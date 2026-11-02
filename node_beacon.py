#!/usr/bin/env python3
"""node-beacon: маячок состояния ноды для сторожа каналов (запуск по таймеру раз в 10 минут, от root).

Пишет в файл (путь — первый аргумент) небольшой JSON: диск, память, ждёт ли сервер перезагрузки, версии ядра и Xray,
включён ли файрвол, сколько было неудачных входов по SSH за сутки и сколько пакетов отбил файрвол (счётчики с момента
загрузки правил — сторож сам считает разницу). Ничего не меняет на сервере и никуда не ходит: файл забирает сторож.
Секретов в файле нет.
"""
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
    }


if __name__ == "__main__":
    out = sys.argv[1]
    data = collect()
    with open(out + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(out + ".tmp", 0o644)
    os.replace(out + ".tmp", out)
