#!/usr/bin/env python3
"""node-witness: «свидетель» на ноде для сторожа каналов — что нода видела из проверочных соединений.

Сторож и его точки проверки в России открывают серии соединений на порт 443 ноды и помечают их: в первом пакете
(SYN) стоит необычный размер сегмента (MSS) из диапазона MARK. Свидетель слушает сетевой интерфейс и считает
только такие соединения: сколько раз пришёл запрос, сколько раз нода ответила, были ли сбросы. Сторож сравнивает
это со своей стороной и видит, где теряется: по дороге к ноде или на обратном пути.

Что важно:
  - соединения клиентов не учитываются и не записываются: без метки пакет отбрасывается ещё в ядре (фильтр BPF),
    а ответы и сбросы ноды сверяются только с помеченными соединениями и нигде не сохраняются;
  - адресов в выходном файле нет: только время, метка и счётчики;
  - ничего не отправляет и не принимает команд: раз в 10 секунд пишет небольшой JSON рядом с маячком ноды
    (то же случайное имя), сторож забирает его сам.
Запуск: node_witness.py <файл> [интерфейс]. Нужны права root (захват пакетов) и tcpdump.
"""
import json
import os
import re
import subprocess
import sys
import threading
import time

MARK = (1201, 1260)      # тот же диапазон, что netprobe.MSS_MARK
PORT = 443
LIVE = 14                # секунд следим за соединением: за это время нода успевает повторить ответ до 4 раз
KEEP = 1800              # секунд храним счётчики
MAX_FLOWS = 4000
WRITE_EVERY = 10
LINE = re.compile(r"^(\d+\.\d+) (?:\S+ +(?:In|Out) +)?IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]+)\]"
                  r"(?:.*?\bmss (\d+))?")
# метка стоит первой опцией SYN (так её ставит Linux): вид 0x0204 + размер
FILTER = (f"(tcp dst port {PORT} and tcp[tcpflags] == tcp-syn and tcp[20:2] = 0x0204 and tcp[22:2] >= {MARK[0]} "
          f"and tcp[22:2] <= {MARK[1]}) or (tcp src port {PORT} and tcp[tcpflags] & (tcp-syn|tcp-rst) != 0) "
          f"or (tcp dst port {PORT} and tcp[tcpflags] & tcp-rst != 0)")


class Flows:
    """Помеченные соединения: live — за которыми ещё следим (ключ — адрес и порт клиента), done — уже сосчитанные."""

    def __init__(self, local=()):
        self.live, self.done, self.lock, self.since = {}, [], threading.Lock(), time.time()
        self.local = set(local)  # свои адреса: помеченные соединения, которые сервер открывает сам, — не к нему

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
                    if cur:
                        self.done.append(cur)
                    self.live[key] = [ts, int(mss), 1, 0, 0, 0]  # время, метка, SYN, SYN-ACK, RST от ноды, RST к ноде
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
            for key in [k for k, v in self.live.items() if now - v[0] > LIVE]:
                self.done.append(self.live.pop(key))
            self.done = [f for f in self.done if now - f[0] <= KEEP][-MAX_FLOWS:]
            rows = self.done + list(self.live.values())
            return {"v": 1, "ts": round(now, 1), "since": int(self.since), "keep": KEEP,
                    "flows": [[round(f[0], 2)] + f[1:] for f in sorted(rows)]}


def write(path, data):
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    os.chmod(path + ".tmp", 0o644)
    os.replace(path + ".tmp", path)


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


def main(path, iface=None):
    flows = Flows(local_addrs())

    def writer():
        while True:
            try:
                write(path, flows.snapshot(time.time()))
            except OSError as e:
                print(f"не записал {path}: {e}", file=sys.stderr)
            time.sleep(WRITE_EVERY)

    threading.Thread(target=writer, daemon=True).start()
    cmd = ["tcpdump", "-l", "-n", "-tt", "-Z", "root", "-i", iface or default_iface(), FILTER]
    while True:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
        for line in proc.stdout:
            flows.feed(line)
        proc.wait()
        time.sleep(5)  # tcpdump завершился (интерфейс пропал и т. п.) — запускаем снова


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("нужен путь к выходному файлу")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
