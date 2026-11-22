#!/usr/bin/env python3
"""node-beacon: маячок состояния ноды для сторожа каналов (запуск по таймеру раз в 10 минут, от root).

Пишет в файл (путь — первый аргумент) небольшой JSON: диск, память, ждёт ли сервер перезагрузки, версии ядра и Xray,
включён ли файрвол, сколько было неудачных входов по SSH за сутки и сколько пакетов отбил файрвол (счётчики с момента
загрузки правил — сторож сам считает разницу). Ничего не меняет на сервере и никуда не ходит: файл забирает сторож.
Секретов в файле нет.

С 22.11.2026 ещё:
  tune   — сетевой профиль (BBR, очередь fq, таблица соединений, MPTCP, synflood): сторож пишет, если профиль слетел;
  knocks — кто за сутки стучался в закрытые порты (по журналу ufw, только SYN): адрес, сколько разных портов, сколько
           раз, стучался ли на 80/443/8443. Из этого сторож собирает свой список сканеров «по поведению».
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time


def run(cmd, timeout=20):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def meminfo():
    info = {}
    for line in open("/proc/meminfo"):
        key, value = line.split(":", 1)
        info[key] = int(value.split()[0]) // 1024  # МБ
    return info


def packets(chain, pattern):
    """Сколько пакетов прошло по правилам цепочки, в строке которых есть pattern и действие DROP/REJECT."""
    total = 0
    for line in run(["iptables", "-L", chain, "-v", "-n", "-x"]).splitlines()[2:]:
        parts = line.split()
        if len(parts) > 2 and parts[2] in ("DROP", "REJECT") and pattern in line and parts[0].isdigit():
            total += int(parts[0])
    return total


def policy_drops():
    """Пакеты, которые не подошли ни под одно разрешающее правило: счётчик политики DROP цепочки INPUT."""
    first = run(["iptables", "-L", "INPUT", "-v", "-n", "-x"]).splitlines()[:1]
    m = re.search(r"policy DROP (\d+) packets", first[0]) if first else None
    return int(m.group(1)) if m else None


def sysctl(key):
    try:
        v = open("/proc/sys/" + key.replace(".", "/")).read().strip()
        return int(v) if v.lstrip("-").isdigit() else v
    except OSError:
        return None


def tune():
    """Сетевой профиль ноды как есть (node_tune.sh ставит: bbr, fq, conntrack 100000, mptcp 0, synack 2, fin 15)."""
    dev = (run(["ip", "-o", "route", "show", "default"]).split(" dev ") + [""])[1].split(" ")[0]
    q = run(["tc", "qdisc", "show", "dev", dev]) if dev else ""
    qdisc = "fq" if re.search(r"^qdisc fq ", q, re.M) else (q.split() + ["", "?"])[1] if q else None
    return {"cc": sysctl("net.ipv4.tcp_congestion_control"), "qdisc": qdisc,
            "conntrack_max": sysctl("net.netfilter.nf_conntrack_max"), "mptcp": sysctl("net.mptcp.enabled"),
            "synack": sysctl("net.ipv4.tcp_synack_retries"), "fin_timeout": sysctl("net.ipv4.tcp_fin_timeout")}


KNOCK_PORTS = {80, 443, 8443}   # стук сюда при закрытом порте — почти наверняка сканер (клиенты сюда не ходят мимо правил)
KNOCK_MAX = 400                 # не больше стольких адресов в файле (маячок читается целиком, до 64 КБ)
LINE = re.compile(r"UFW BLOCK.* SRC=([0-9.]+) .*PROTO=TCP .*DPT=(\d+) .*\bSYN\b")


def knock_ts(ln, now):
    """Время строки журнала: ISO (2026-11-22T00:00:05.009+00:00) или классическое «Nov 22 00:00:05» (местное, год текущий)."""
    try:
        if ln[:4].isdigit():
            return dt.datetime.fromisoformat(ln.split()[0]).timestamp()
        t = time.strptime("%d %s" % (time.localtime(now).tm_year, ln[:15]), "%Y %b %d %H:%M:%S")
        return time.mktime(t)
    except (ValueError, IndexError):
        return None



def knocks(lines, now, since=86400):
    """[[адрес, разных портов, стуков, 1 если стучался на 80/443/8443], …] — сначала самые подозрительные."""
    src = {}
    for ln in lines:
        m = LINE.search(ln)
        if not m:
            continue
        ts = knock_ts(ln, now)
        if ts is None or now - ts > since:
            continue
        ip, port = m.group(1), int(m.group(2))
        if ip.startswith(("10.", "192.168.", "127.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip):
            continue
        v = src.setdefault(ip, [set(), 0])
        v[0].add(port)
        v[1] += 1
    out = [[ip, len(p), n, int(bool(p & KNOCK_PORTS))] for ip, (p, n) in src.items()]
    out.sort(key=lambda r: (-r[3], -r[1], -r[2]))
    return out[:KNOCK_MAX]


def ufw_lines():
    out = []
    for f in ("/var/log/ufw.log.1", "/var/log/ufw.log"):
        try:
            with open(f, errors="replace") as fh:
                out += [ln for ln in fh if "UFW BLOCK" in ln]
        except OSError:
            pass
    return out


def collect():
    disk = os.statvfs("/")
    mem = meminfo()
    xray = run(["docker", "exec", "remnanode", "sh", "-c",
                "for b in /usr/local/bin/xray /usr/local/bin/rw-core xray; do $b version 2>/dev/null && break; done"])
    m = re.search(r"Xray (\S+)", xray)
    ssh_fail = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "24 hours ago", "--no-pager", "-q",
                    "-g", "Failed password"], timeout=60)
    conn = [int(open(f"/proc/sys/net/netfilter/nf_conntrack_{k}").read()) if os.path.exists(
        f"/proc/sys/net/netfilter/nf_conntrack_{k}") else None for k in ("count", "max")]
    return {
        "ts": int(time.time()),
        # как в df: занято / (занято + доступно), без учёта резерва файловой системы
        "disk_pct": round(100.0 * (disk.f_blocks - disk.f_bfree) / (disk.f_blocks - disk.f_bfree + disk.f_bavail)),
        "disk_free_mb": disk.f_bavail * disk.f_frsize // 1048576,
        "mem_total_mb": mem.get("MemTotal"), "mem_avail_mb": mem.get("MemAvailable"),
        "swap_used_mb": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
        "load1": round(os.getloadavg()[0], 2),
        "uptime_s": int(float(open("/proc/uptime").read().split()[0])),
        "reboot_required": os.path.exists("/var/run/reboot-required"),
        "kernel": os.uname().release,
        "xray": m.group(1) if m else None,
        "ufw": (run(["ufw", "status"]).split("\n", 1)[0].split(":")[-1].strip() or None),
        "ssh_fail_24h": len([line for line in ssh_fail.splitlines() if "Failed password" in line]),
        "drops": {"policy": policy_drops(), "geo": packets("ufw-before-input", "reshala_geoblock"),
                  "scan": packets("SCANNERS-BLOCK", "SCANNERS"), "crowdsec": packets("CROWDSEC_CHAIN", "match-set")},
        "finwait2": len(run(["ss", "-Htn", "state", "fin-wait-2"]).splitlines()),
        "conntrack": conn,
        "failed_units": [line.split()[0] for line in run(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines() if line.split()],
        "tune": tune(),
        "knocks": knocks(ufw_lines(), time.time()),
    }


if __name__ == "__main__":
    out = sys.argv[1]
    data = collect()
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(out + ".tmp", 0o644)
    os.replace(out + ".tmp", out)
