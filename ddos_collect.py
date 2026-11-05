#!/usr/bin/env python3
"""ddos-collect: сборщик метрик сервера для сторожа каналов (DDoS и нагрузка). Логика сбора — из ddos-agent
(плагин ddos-monitoring к Remnawave, MIT), с правками:
  - трафик и пакеты — только внешний интерфейс (маршрут по умолчанию): ddos-agent суммировал все, кроме lo, и
    считал трафик docker/veth/туннелей по второму разу;
  - добавлены SYN cookies, listen drops/overflows (/proc/net/netstat) — по ним плагин ловил SYN-флуд и переполнение;
  - состояние контейнеров Docker (1.1.0):
    раз в минуту вместе с systemctl — имя, состояние, healthcheck, политика перезапуска, счётчик перезапусков, код
    выхода; читает сокет Docker напрямую (без запуска docker CLI — лимит памяти службы 64M);
  - щит (1.2.0, блокировки только с подтверждением в Telegram): раз в минуту — режим щита, число
    блокировок и до 10 «подозрительных» адресов (кто за 10 минут открывал соединения сверх порога) — чтобы сторож мог
    предложить заблокировать их кнопкой; это единственные адреса в срезе, живут в нём 5 минут;
  - наши клиенты (1.3.0, щит сверяется с адресами настоящих клиентов): раз в минуту
    дочитывает журнал Xray (/var/log/remnanode/access.log, строки accepted … email: — прошедшие проверку подписки),
    держит адреса за сутки в /run/storozh-shield/clients.json (600, только на этом сервере) и в наборе щита clients4/6;
    в срез идёт только их число;
  - других адресов не собирает и не хранит: только счётчики (сколько разных адресов, сколько SYN_RECV и т.п.);
  - ничего не отправляет и не принимает: раз в STEP секунд пишет /run/ddos-collect/state.json (последние KEEP
    срезов), сторож на rf1 забирает файл сам ключом, который умеет только прочитать этот файл.
Без внешних зависимостей (python3 из Ubuntu). Запуск: ddos_collect.py [файл] — служба ddos-collect.service.
"""
import calendar
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse

VERSION = "1.6.0"   # 1.6.0: метка compose и --rm у контейнеров; 1.5.0 (27.10): переполнение буфера карты и сбросы ядра; 1.4.0 (25.10): протоколы и порты из щита
SHIELD_CTL = "/usr/local/sbin/shield-ctl"
SHIELD_TOP = 10
XRAY_LOG = "/var/log/remnanode/access.log"
CLIENTS_FILE = "/run/storozh-shield/clients.json"
CLIENTS_KEEP = 86400        # клиент «наш» сутки после последнего подключения
CLIENTS_MAX = 200000
LOG_FIRST = 16 * 2 ** 20    # при первом запуске — хвост журнала (≈ сутки на ноде), не весь
LOG_CHUNK = 4 * 2 ** 20     # за проход — не больше (ноды по 1 ядру, CPUQuota 5%)
DOCKER_SOCK = "/var/run/docker.sock"
DOCKER_MAX = 40    # контейнеров в срезе, не больше
STEP = 10          # секунд между срезами
KEEP = 30          # срезов в файле (5 минут): сторож забирает раз в минуту и не пропускает короткие всплески
FAILED_EVERY = 60  # секунд между опросами systemctl --failed
OUT = sys.argv[1] if len(sys.argv) > 1 else "/run/ddos-collect/state.json"


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def default_iface():
    for ln in read("/proc/net/route").splitlines()[1:]:
        c = ln.split()
        if len(c) > 2 and c[1] == "00000000":
            return c[0]
    return ""


def overload(iface, sysfs="/sys/class/net", softnet="/proc/net/softnet_stat"):
    """Настоящие признаки перегрузки сети (сообщать только при переполнении буфера карты и сбросах ядра):
    rx_missed_errors — сетевой карте некуда положить пакет; softnet dropped — ядро не успевает разбирать очередь.
    Общий rx_dropped у облачных серверов — в основном фон сети хостера (кадры «не для меня»), его здесь нет."""
    out = {"missed": 0, "softnet": 0}
    try:
        out["missed"] = int(read("%s/%s/statistics/rx_missed_errors" % (sysfs, iface)).strip() or 0)
    except ValueError:
        pass
    for ln in read(softnet).splitlines():
        c = ln.split()
        if len(c) > 1:
            try:
                out["softnet"] += int(c[1], 16)
            except ValueError:
                pass
    return out


def netdev(iface):
    for ln in read("/proc/net/dev").splitlines():
        if ":" in ln and ln.split(":", 1)[0].strip() == iface:
            c = ln.split(":", 1)[1].split()
            # колонки: rx bytes packets errs DROP … | tx bytes packets errs DROP … (ddos-agent брал errs вместо drop)
            return {"rx_b": int(c[0]), "rx_p": int(c[1]), "rx_d": int(c[3]), "tx_b": int(c[8]), "tx_p": int(c[9]),
                    "tx_d": int(c[11])}
    return None


def netstat():
    """TcpExt: SyncookiesSent, ListenDrops, ListenOverflows."""
    out, lines = {}, read("/proc/net/netstat").splitlines()
    for i in range(0, len(lines) - 1, 2):
        head, vals = lines[i].split(), lines[i + 1].split()
        if head and head[0] == "TcpExt:":
            d = dict(zip(head[1:], vals[1:]))
            for k in ("SyncookiesSent", "ListenDrops", "ListenOverflows"):
                out[k] = int(d.get(k, 0))
    return out


def cpu_times():
    for ln in read("/proc/stat").splitlines():
        if ln.startswith("cpu "):
            p = [int(x) for x in ln.split()[1:]]
            return sum(p), p[3] + p[4]
    return 0, 0


def tcp_states():
    syn = est = 0
    uniq = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for ln in read(path).splitlines()[1:]:
            c = ln.split()
            if len(c) < 4:
                continue
            if c[3] == "03":      # SYN_RECV (ddos-agent считал "02" — это SYN_SENT, исходящие соединения)
                syn += 1
            elif c[3] == "01":    # ESTABLISHED
                est += 1
                uniq.add(c[2].rsplit(":", 1)[0])
    return syn, est, len(uniq)


def failed_units():
    try:
        out = subprocess.run(["systemctl", "list-units", "--failed", "--no-legend", "--plain"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [p.split()[0] for p in out.splitlines() if p.split() and not p.split()[0].endswith(".target")][:10]


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


def _docker_get(path, sock, timeout):
    c = _UnixHTTP(sock, timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise OSError("docker %s: HTTP %s" % (path, r.status))
        return json.loads(body)
    finally:
        c.close()


def containers(sock=DOCKER_SOCK, get=None, timeout=10):
    """-> (docker_ok, [контейнеры]) или (None, None), если Docker на сервере нет.
    Контейнер: n имя, s состояние (running/exited/restarting/dead/…), h healthcheck (""/healthy/unhealthy/starting),
    rp политика перезапуска, rc счётчик перезапусков, ex код выхода; cp — проект docker compose (если поднят им),
    ar — True, если запущен с --rm (сам удалится после выхода)."""
    if get is None:
        if not os.path.exists(sock):
            return (False, []) if os.path.exists("/usr/bin/docker") else (None, None)
        get = lambda p: _docker_get(p, sock, timeout)  # noqa: E731
    try:
        lst = get("/containers/json?all=1")
    except (OSError, ValueError, http.client.HTTPException):
        return False, []
    out = []
    for item in (lst or [])[:DOCKER_MAX]:
        try:
            i = get("/containers/%s/json" % urllib.parse.quote(str(item.get("Id", "")), safe=""))
        except (OSError, ValueError, http.client.HTTPException):
            continue   # удалили между запросами
        st, hc = i.get("State") or {}, i.get("HostConfig") or {}
        c = {"n": str(i.get("Name") or "").lstrip("/"), "s": st.get("Status") or "",
             "h": (st.get("Health") or {}).get("Status") or "",
             "rp": (hc.get("RestartPolicy") or {}).get("Name") or "no",
             "rc": int(i.get("RestartCount") or 0), "ex": int(st.get("ExitCode") or 0)}
        cp = ((i.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project")
        if cp:
            c["cp"] = str(cp)[:64]
        if hc.get("AutoRemove"):
            c["ar"] = True
        out.append(c)
    return True, out


def shield(ctl=SHIELD_CTL, run=None):
    """-> {mode, until, blocked, suspects: [[адрес, пакетов сверх порога]], over, dropped} или None (щита нет)."""
    if run is None:
        if not os.path.exists(ctl):
            return None
        try:
            run = lambda: subprocess.run([ctl, "status"], capture_output=True, text=True, timeout=20).stdout  # noqa: E731
        except OSError:
            return None
    try:
        d = json.loads(run() or "null")
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"loaded": False}
    if not isinstance(d, dict) or not d.get("loaded"):
        return {"loaded": False}
    cn = d.get("counters") or {}
    return {"loaded": True, "mode": d.get("mode"), "until": d.get("until", 0), "blocked": len(d.get("blocked") or []),
            "suspects": [x for x in (d.get("suspects") or [])[:SHIELD_TOP] if isinstance(x, list) and len(x) == 2],
            "suspects_total": d.get("suspects_total", 0), "limits": d.get("limits") or {},
            "over": int(cn.get("over_rate", 0)) + int(cn.get("over_conns", 0)),
            "dropped": int(cn.get("dropped_blocked", 0)) + int(cn.get("dropped_shield", 0)),
            "scan": {k: (d.get("scan") or {}).get(k) for k in ("mode", "nets", "updated", "sources", "packets")},
            "proto": d.get("proto") or {}, "ports": [x for x in (d.get("ports") or [])[:5] if isinstance(x, list)]}


def proto_rates(sh, prev, now):
    """Счётчики щита по протоколам (с начала) -> пакетов в секунду за время с прошлого опроса. prev меняется."""
    cur = (sh or {}).get("proto") or {}
    out = {}
    if prev.get("t") and now > prev["t"]:
        for k, v in cur.items():
            if k in prev.get("c", {}) and v >= prev["c"][k]:
                out[k] = round((v - prev["c"][k]) / (now - prev["t"]), 1)
    prev["t"], prev["c"] = now, dict(cur)
    return out


def client_key(addr):
    """Как в shield-ctl: IPv4 как есть, IPv6 — сеть /64. None — не адрес."""
    import ipaddress
    try:
        a = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return None
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network("%s/64" % a, strict=False).network_address)
    return str(a)


def parse_access(line):
    """Строка журнала Xray -> (ts, ключ адреса, пользователь) или None. Только accepted с email (прошёл проверку)."""
    if " accepted " not in line or " email: " not in line:
        return None
    try:
        head, rest = line.split(" from ", 1)
        src = rest.split(" ", 1)[0]
        if src.startswith(("tcp:", "udp:")):
            src = src[4:]
        host = src.rsplit(":", 1)[0]
        user = line.rsplit(" email: ", 1)[1].split()[0]
        ts = calendar.timegm(time.strptime(head[:19], "%Y/%m/%d %H:%M:%S"))   # время журнала Xray — UTC
    except (ValueError, IndexError):
        return None
    k = client_key(host)
    return (ts, k, user[:64]) if k else None


class Clients:
    """Наши клиенты по журналу Xray: дочитывает новые строки, держит сутки."""

    def __init__(self, log=XRAY_LOG, out=CLIENTS_FILE):
        self.log, self.out = log, out
        self.pos, self.ino, self.map, self.dirty = None, None, {}, False
        try:
            d = json.load(open(out, encoding="utf-8"))
            self.map, self.pos, self.ino = d.get("clients", {}), d.get("pos"), d.get("ino")
        except (OSError, ValueError):
            pass

    def read(self, now=None):
        now = now or time.time()
        try:
            st = os.stat(self.log)
        except OSError:
            return False
        if self.ino != st.st_ino or self.pos is None or self.pos > st.st_size:   # новый файл (ротация) или первый запуск
            self.pos = max(st.st_size - LOG_FIRST, 0) if self.ino is None else 0
            self.ino = st.st_ino
        with open(self.log, "rb") as f:
            f.seek(self.pos)
            data = f.read(LOG_CHUNK)
        cut = data.rfind(b"\n") + 1
        self.pos += cut
        before = len(self.map)
        for raw in data[:cut].decode("utf-8", "replace").splitlines():
            r = parse_access(raw)
            if not r:
                continue
            ts, k, user = r
            v = self.map.get(k)
            self.map[k] = [max(int(ts), v[0]) if v else int(ts), user, (v[2] + 1) if v else 1]
        old = [k for k, v in self.map.items() if now - v[0] > CLIENTS_KEEP]
        for k in old:
            del self.map[k]
        if len(self.map) > CLIENTS_MAX:
            for k, _ in sorted(self.map.items(), key=lambda kv: kv[1][0])[:len(self.map) - CLIENTS_MAX]:
                del self.map[k]
        self.dirty = self.dirty or bool(old) or len(self.map) != before
        return True

    def save(self):
        os.makedirs(os.path.dirname(self.out), exist_ok=True)
        tmp = self.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"clients": self.map, "pos": self.pos, "ino": self.ino}, f, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.out)

    def push(self):
        """В набор щита — только когда список изменился (одной транзакцией nft)."""
        if not self.dirty or not os.path.exists(SHIELD_CTL):
            return
        v4 = [k for k in self.map if ":" not in k]
        v6 = [k for k in self.map if ":" in k]
        lines = ["flush set inet storozh_shield clients4", "flush set inet storozh_shield clients6"]
        for name, items in (("clients4", v4), ("clients6", v6)):
            for i in range(0, len(items), 2000):
                lines.append("add element inet storozh_shield %s { %s }" % (name, ", ".join(items[i:i + 2000])))
        try:
            r = subprocess.run(["nft", "-f", "-"], input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=30)
            self.dirty = r.returncode != 0
        except (OSError, subprocess.SubprocessError):
            pass


def static_part(iface, failed, docker=(None, None), sh=None):
    m = {}
    la = read("/proc/loadavg").split()
    if la:
        m["load1"] = float(la[0])
    info = {}
    for ln in read("/proc/meminfo").splitlines():
        if ":" in ln and len(ln.split()) > 1:
            info[ln.split(":", 1)[0]] = int(ln.split()[1])
    if info.get("MemTotal"):
        m["ram_pct"] = round(100.0 * (info["MemTotal"] - info.get("MemAvailable", 0)) / info["MemTotal"], 1)
    if info.get("SwapTotal"):
        m["swap_pct"] = round(100.0 * (info["SwapTotal"] - info.get("SwapFree", 0)) / info["SwapTotal"], 1)
    m["cores"] = max(os.cpu_count() or 1, 1)
    try:
        st = os.statvfs("/")
        m["disk_pct"] = round(100.0 * (st.f_blocks - st.f_bfree) / max(st.f_blocks, 1), 1)
    except OSError:
        pass
    m["syn_recv"], m["established"], m["unique_ips"] = tcp_states()
    ct = read("/proc/sys/net/netfilter/nf_conntrack_count").strip()
    cm = read("/proc/sys/net/netfilter/nf_conntrack_max").strip()
    if ct.isdigit():
        m["conntrack_count"] = int(ct)
    if cm.isdigit():
        m["conntrack_max"] = int(cm)
    m["failed_units"] = failed
    if docker[0] is not None:
        m["docker_ok"], m["containers"] = docker
        m["docker_v"] = 2   # есть cp/ar: сторож отличает временные контейнеры от постоянных
    if sh is not None:
        m["shield"] = sh
    m["iface"] = iface
    return m


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    samples, prev, failed, failed_at, docker, sh = [], None, [], 0.0, (None, None), None
    prev_proto = {}
    cl = Clients() if os.path.exists(XRAY_LOG) else None
    while True:
        t0 = time.time()
        if t0 - failed_at >= FAILED_EVERY:
            if cl:
                try:
                    if cl.read(t0):
                        cl.save()
                        cl.push()
                except OSError:
                    pass
            failed, docker, sh, failed_at = failed_units(), containers(), shield(), t0
            if sh is not None and cl:
                sh["clients"] = len(cl.map)
            if sh is not None and sh.get("loaded"):
                sh["proto_pps"] = proto_rates(sh, prev_proto, t0)
        iface = default_iface()
        nd, ns, (ct, ci) = (netdev(iface) if iface else None), netstat(), cpu_times()
        cur = {"t": time.monotonic(), "nd": nd, "ns": ns, "ct": ct, "ci": ci, "ov": overload(iface) if iface else None}
        m = static_part(iface, failed, docker, sh)
        if prev and prev["nd"] and nd and cur["t"] > prev["t"]:
            dt = cur["t"] - prev["t"]
            m["rx_bps"] = int(max(nd["rx_b"] - prev["nd"]["rx_b"], 0) * 8 / dt)
            m["tx_bps"] = int(max(nd["tx_b"] - prev["nd"]["tx_b"], 0) * 8 / dt)
            m["rx_pps"] = int(max(nd["rx_p"] - prev["nd"]["rx_p"], 0) / dt)
            m["tx_pps"] = int(max(nd["tx_p"] - prev["nd"]["tx_p"], 0) / dt)
            m["rx_drop_ps"] = round(max(nd["rx_d"] - prev["nd"]["rx_d"], 0) / dt, 1)
            m["tx_drop_ps"] = round(max(nd["tx_d"] - prev["nd"]["tx_d"], 0) / dt, 1)
            if cur["ov"] and prev.get("ov"):
                m["nic_missed_ps"] = round(max(cur["ov"]["missed"] - prev["ov"]["missed"], 0) / dt, 1)
                m["softnet_drop_ps"] = round(max(cur["ov"]["softnet"] - prev["ov"]["softnet"], 0) / dt, 1)
            for k, out in (("SyncookiesSent", "syncookies_ps"), ("ListenDrops", "listen_drop_ps"),
                           ("ListenOverflows", "listen_overflow_ps")):
                m[out] = round(max(ns.get(k, 0) - prev["ns"].get(k, 0), 0) / dt, 1)
            if ct > prev["ct"]:
                m["cpu_pct"] = round(100.0 * (1 - (ci - prev["ci"]) / (ct - prev["ct"])), 1)
            m["ts"] = int(t0)
            samples = (samples + [m])[-KEEP:]
            tmp = OUT + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"v": VERSION, "now": int(t0), "step": STEP, "samples": samples}, f, separators=(",", ":"))
            os.chmod(tmp, 0o644)
            os.replace(tmp, OUT)
        prev = cur
        time.sleep(max(STEP - (time.time() - t0), 1))


if __name__ == "__main__":
    main()
