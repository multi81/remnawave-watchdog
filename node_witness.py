#!/usr/bin/env python3
"""node-witness: «свидетель» на ноде для сторожа каналов — что нода видела из проверочных соединений.

Сторож и его точки проверки в России открывают серии соединений на порт 443 ноды и помечают их: в первом пакете
(SYN) стоит необычный размер сегмента (MSS) из диапазона MARK. Свидетель слушает сетевой интерфейс и считает
только такие соединения: сколько раз пришёл запрос, сколько раз нода ответила, были ли сбросы. Сторож сравнивает
это со своей стороной и видит, где теряется: по дороге к ноде или на обратном пути.

Что важно:
  - запросы клиентов без метки отбрасываются ещё в ядре (фильтр BPF). Ответы и сбросы самой ноды с порта 443
    (SYN-ACK, RST) фильтр пропускает только от своих адресов ноды и к ним: чужие ответы (сайты, куда ходят
    пользователи выходной ноды) в процесс не попадают. Ответы ноды клиентам фильтр без состояния отличить не может —
    они сверяются только с помеченными соединениями и нигде не сохраняются;
  - адресов в выходном файле нет: только время, метка и счётчики;
  - пакеты разбирает tcpdump, и он сразу после открытия захвата сбрасывает права до пользователя tcpdump (-Z);
  - поддельными помеченными SYN свидетеля не забить: следим не больше чем за MAX_LIVE соединениями, файл не больше
    MAX_BYTES. Что не уместилось, честно помечается: since сдвигается за время потери, и сторож не судит по
    сериям, которые свидетель видел не целиком;
  - ничего не отправляет и не принимает команд: раз в 10 секунд пишет небольшой JSON рядом с маячком ноды
    (то же случайное имя), сторож забирает его сам.
Запуск: node_witness.py <файл> [интерфейс]. Нужны права на захват (CAP_NET_RAW) и tcpdump.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

try:
    import pwd
except ImportError:  # Windows (тесты)
    pwd = None

MARK = (1201, 1260)      # тот же диапазон, что netprobe.MSS_MARK
PORT = 443
LIVE = 14                # секунд следим за соединением: за это время нода успевает повторить ответ до 4 раз
KEEP = 1800              # секунд храним счётчики
MAX_FLOWS = 4000         # сосчитанных соединений в файле
MAX_LIVE = 2000          # одновременно отслеживаемых: сверх — новые помеченные SYN не берём (поддельный поток)
MAX_BYTES = 350000       # предел файла: сторож забирает не больше 400000 байт
WRITE_EVERY = 10
LINE = re.compile(r"^(\d+\.\d+) (?:\S+ +(?:In|Out) +)?IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]+)\]"
                  r"(?:.*?\bmss (\d+))?")
IPV4 = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def build_filter(local=()):
    """Фильтр BPF. Метка стоит первой опцией SYN (так её ставит Linux): вид 0x0204 + размер. Свои адреса известны —
    помеченные SYN только к ним, ответы и сбросы с порта 443 только от них, сбросы на порт 443 только к ним."""
    hosts = sorted(a for a in local if IPV4.fullmatch(a))
    to = " and (" + " or ".join(f"dst host {a}" for a in hosts) + ")" if hosts else ""
    frm = " and (" + " or ".join(f"src host {a}" for a in hosts) + ")" if hosts else ""
    return (f"(tcp dst port {PORT} and tcp[tcpflags] == tcp-syn and tcp[20:2] = 0x0204 and tcp[22:2] >= {MARK[0]} "
            f"and tcp[22:2] <= {MARK[1]}{to}) or (tcp src port {PORT} and tcp[tcpflags] & (tcp-syn|tcp-rst) != 0{frm}) "
            f"or (tcp dst port {PORT} and tcp[tcpflags] & tcp-rst != 0{to})")


FILTER = build_filter()  # без своих адресов (их не удалось узнать) — прежний фильтр


class Flows:
    """Помеченные соединения: live — за которыми ещё следим (ключ — адрес и порт клиента), done — уже сосчитанные.
    cut — до какого времени счётчики неполны (что-то не уместилось в пределы), dropped — сколько SYN не взяли."""

    def __init__(self, local=()):
        self.live, self.done, self.lock, self.since = {}, [], threading.Lock(), time.time()
        self.local = set(local)  # свои адреса: помеченные соединения, которые сервер открывает сам, — не к нему
        self.cut, self.dropped, self.swept = 0.0, 0, 0.0

    def _sweep(self, now):
        """Закрыть соединения, за которыми следить уже не нужно."""
        for key in [k for k, v in self.live.items() if now - v[0] > LIVE]:
            self.done.append(self.live.pop(key))
        self.swept = now

    def _lost(self, ts):
        self.cut = max(self.cut, ts)

    def feed(self, line):
        m = LINE.match(line)
        if not m:
            return
        ts, src, sport, dst, dport, flags, mss = m.groups()
        ts = float(ts)
        with self.lock:
            if flags == "S" and int(dport) == PORT:
                if src in self.local:
                    return  # это сам сервер проверяет другую ноду (на нём стоит сторож) — не входящее соединение
                key = (src, sport)
                cur = self.live.get(key)
                if cur and ts - cur[0] <= LIVE:
                    cur[2] += 1  # повторный запрос того же соединения
                elif mss and MARK[0] <= int(mss) <= MARK[1]:
                    if not cur and len(self.live) >= MAX_LIVE:
                        if ts - self.swept >= 1:  # под потоком — не чаще раза в секунду
                            self._sweep(ts)
                        if len(self.live) >= MAX_LIVE:
                            self.dropped += 1
                            self._lost(ts)
                            return
                    if cur:
                        self.done.append(cur)
                    self.live[key] = [ts, int(mss), 1, 0, 0, 0]  # время, метка, SYN, SYN-ACK, RST от ноды, RST к ноде
                    if len(self.done) > 2 * MAX_FLOWS:  # между записями файла: память не растёт
                        self.done.sort()
                        self._lost(self.done[-MAX_FLOWS - 1][0])
                        self.done = self.done[-MAX_FLOWS:]
                return
            if int(sport) == PORT:  # пакет от ноды
                cur = self.live.get((dst, dport))
                if cur and ts - cur[0] <= LIVE:
                    if flags == "S.":
                        cur[3] += 1
                    elif "R" in flags:
                        cur[4] += 1
            elif int(dport) == PORT and "R" in flags:
                cur = self.live.get((src, sport))
                if cur and ts - cur[0] <= LIVE:
                    cur[5] += 1

    def snapshot(self, now):
        with self.lock:
            self._sweep(now)
            self.done = sorted(f for f in self.done if now - f[0] <= KEEP)
            if len(self.done) > MAX_FLOWS:
                self._lost(self.done[-MAX_FLOWS - 1][0])
                self.done = self.done[-MAX_FLOWS:]
            rows = self.done + list(self.live.values())
            since = int(self.since)
            if self.cut:
                since = max(since, int(self.cut) + 1)  # сторож не верит сериям, начатым до потери (since > t0)
            return {"v": 1, "ts": round(now, 1), "since": since, "keep": KEEP, "dropped": self.dropped,
                    "flows": [[round(f[0], 2)] + f[1:] for f in sorted(rows)]}


def fit(data, limit=MAX_BYTES):
    """JSON снимка не длиннее limit: лишнее — самые старые записи, since сдвигается за последнюю отброшенную."""
    text = json.dumps(data, separators=(",", ":"))
    if len(text) <= limit:
        return text
    rows, over, k = data["flows"], len(text) - limit + 16, 0  # 16 — на удлинение since
    while k < len(rows) and over > 0:
        over -= len(json.dumps(rows[k], separators=(",", ":"))) + 1
        k += 1
    out = dict(data, flows=rows[k:])
    if k:
        out["since"] = max(int(data.get("since", 0)), int(rows[k - 1][0]) + 1)
    return json.dumps(out, separators=(",", ":"))


def write(path, data):
    """Свой временный файл (mkstemp: O_EXCL, неугадываемое имя), права на открытый файл, затем os.replace: подложенная
    в папку сайта ссылка не заставит писать в чужой файл или открыть его всем."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".fw-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), 0o644)
            f.write(fit(data) if isinstance(data, dict) and "flows" in data else json.dumps(data, separators=(",", ":")))
        if not hasattr(os, "fchmod"):  # Windows (тесты)
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def default_iface():
    try:
        out = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"\bdev (\S+)", out)
        return m.group(1) if m else "any"
    except (OSError, subprocess.TimeoutExpired):
        return "any"


def local_addrs():
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))
    except (OSError, subprocess.TimeoutExpired):
        return set()


def drop_user():
    """Кем станет tcpdump после открытия захвата: пользователь tcpdump (из пакета), нет его — nobody.
    Не root — tcpdump права не сбрасывает (и не может), -Z не нужен."""
    if pwd is None or os.geteuid() != 0:
        return None
    for name in ("tcpdump", "nobody"):
        try:
            pwd.getpwnam(name)
            return name
        except KeyError:
            continue
    return None


def tcpdump_cmd(iface, local=()):
    user = drop_user()
    return (["tcpdump", "-l", "-n", "-tt", "-p"] + (["-Z", user] if user else [])
            + ["-i", iface, build_filter(local)])


def main(path, iface=None):
    flows = Flows(local_addrs())

    def writer():
        while True:
            try:
                write(path, flows.snapshot(time.time()))
            except OSError as e:
                print(f"не записал {path}: {e}", file=sys.stderr, flush=True)
            time.sleep(WRITE_EVERY)

    threading.Thread(target=writer, daemon=True).start()
    while True:
        flows.local = local_addrs() or flows.local  # адреса могли смениться — фильтр пересобирается при перезапуске
        cmd = tcpdump_cmd(iface or default_iface(), flows.local)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
        for line in proc.stdout:
            flows.feed(line)
        code = proc.wait()
        err = " ".join((proc.stderr.read() or "").split())[-300:]
        print(f"tcpdump завершился (код {code}): {err}", file=sys.stderr, flush=True)
        time.sleep(5)  # интерфейс пропал и т. п. — запускаем снова


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("нужен путь к выходному файлу")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
