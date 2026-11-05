#!/usr/bin/env python3
"""channel-watch: единый список сканеров (в первую очередь сканеров РКН) для щита на всех серверах.

Раз в сутки (таймер channel-watch-scanlists) на rf1:
  1. скачивает списки shadow-netlab/traffic-guard-lists: antiscanner, government_networks, skipa (те же, что у traffic-guard);
  2. проверяет каждый: разобрался, не пустой, не уменьшился больше чем на SHRINK_MAX против прошлой удачной копии —
     иначе берётся прошлая копия (и приходит сообщение);
  3. добавляет свои сети (/etc/channel-watch/scanners-extra.txt), вырезает исключения (scanners-exclude.txt), ваши
     адреса (owner.txt) и все серверы из ddos.json;
  4. рассылает итог на все серверы щита (ключ щита, команда scanners-load) и спрашивает, кто из наших клиентов попал в
     список (scan-clients) — это строка в отчёте сторожа, решение за вами;
  5. пишет итог в /var/lib/channel-watch/scanners/summary.json (для отчёта 3 раза в день).
Сообщение — только когда что-то не так (список не скачался или резко уменьшился, сервер не принял) или в
списке появились новые наши клиенты. Запуск: scanlists.py [--dry] [--only ИМЯ]   (--dry — скачать и проверить, никуда не слать; --only — один сервер)
"""
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time

ETC = "/etc/channel-watch"
DIR = "/var/lib/channel-watch/scanners"
BASE = "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/"
LISTS = {"antiscanner": "сканеры", "government_networks": "государственные сети", "skipa": "СКИПА (РКН)",
         "c24be_gov": "госорганы РФ (C24Be)"}
# списки не из shadow-netlab — свой адрес (C24Be/AS_Network_List, BSD-2, обновляется ежедневно; IPv4 и IPv6)
URLS = {"c24be_gov": "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"}


def list_url(name):
    return URLS.get(name) or BASE + name + ".list"
SHRINK_MAX = 0.3
MIN_PREFIX = {4: 16, 6: 28}


def owner_addrs():
    """Ваши адреса, которые никогда не должны попасть в список сканеров: /etc/channel-watch/owner.txt (адрес или сеть
    в строке, # — комментарий). Серверы из ddos.json добавляются сами."""
    try:
        lines = open(os.path.join(ETC, "owner.txt"), encoding="utf-8").read().splitlines()
    except OSError:
        return []
    return [x for x in (ln.split("#")[0].strip() for ln in lines) if x]


def parse(text):
    """-> (список сетей, число мусорных строк). Слишком широкие — в мусор."""
    nets, bad = [], 0
    for ln in text.splitlines():
        x = ln.split("#")[0].strip()
        if not x:
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            bad += 1
            continue
        if n.prefixlen < MIN_PREFIX[n.version]:
            bad += 1
            continue
        nets.append(n)
    return nets, bad


def fetch(name, routes=(None,)):
    url = list_url(name)
    for proxy in routes:
        cmd = ["curl", "-s", "-f", "-m", "40", url]
        if proxy:
            cmd[1:1] = ["-x", proxy]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=50)
        except (subprocess.TimeoutExpired, OSError):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    return None


def choose(name, text, prev_text):
    """Новая копия или прошлая. -> (текст, сети, заметка или '')."""
    prev_nets = parse(prev_text)[0] if prev_text else []
    if text is None:
        return prev_text or "", prev_nets, "%s: не скачался — взята прошлая копия" % name if prev_text else "%s: не скачался, прошлой копии нет" % name
    nets, bad = parse(text)
    if not nets:
        return prev_text or "", prev_nets, "%s: пустой или не разобрался — взята прошлая копия" % name
    if prev_nets and len(nets) < (1 - SHRINK_MAX) * len(prev_nets):
        return prev_text, prev_nets, "%s: резко уменьшился (%d → %d сетей) — взята прошлая копия" % (name, len(prev_nets), len(nets))
    return text, nets, ""


def own_networks(hosts):
    out = []
    for x in owner_addrs() + [h.get("host", "") for h in hosts]:
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            pass
    return out


def combine(per_list, extra, exclude, own):
    """-> (итоговые сети, сколько вырезано своих/исключений). Пересечения со своими вырезаются из сетей списка."""
    nets = [n for ns in per_list.values() for n in ns] + extra
    cut = 0
    out = []
    for v in (4, 6):
        res = list(ipaddress.collapse_addresses([n for n in nets if n.version == v]))
        for a in [x for x in own + exclude if x.version == v]:
            nxt = []
            for n in res:
                if n.overlaps(a):
                    cut += 1
                    if not a.supernet_of(n):
                        nxt += list(n.address_exclude(a))
                else:
                    nxt.append(n)
            res = nxt
        out += list(ipaddress.collapse_addresses(res))
    return out, cut


def which_list(addr, per_list):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return ""
    names = [LISTS.get(k, k) for k, ns in per_list.items() if any(a in n for n in ns if n.version == a.version)]
    return ", ".join(names) or "свои добавки"


def read(path, default=""):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return default


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


def run(argv, fetcher=None, run_ctl=None, hosts=None, send=None, now=None, base=DIR):
    """Один проход. -> итог (dict). Все внешние вызовы подставляются (тесты)."""
    now = now or time.time()
    dry = "--dry" in argv
    notes, per_list = [], {}
    for name in LISTS:
        prev = read(os.path.join(base, name + ".list"))
        text, nets, note = choose(name, fetcher(name), prev)
        if note:
            notes.append(note)
        if text and not note and not dry:
            write(os.path.join(base, name + ".list"), text)
        per_list[name] = nets
    extra = parse(read(os.path.join(ETC, "scanners-extra.txt")))[0]
    exclude = parse(read(os.path.join(ETC, "scanners-exclude.txt")))[0]
    final, cut = combine(per_list, extra, exclude, own_networks(hosts.values()))
    summary = {"ts": int(now), "nets": len(final), "per_list": {k: len(v) for k, v in per_list.items()},
               "extra": len(extra), "cut": cut, "notes": notes, "hosts": {}, "clients": {}}
    if dry or not final:
        if not final:
            notes.append("итоговый список пуст — не рассылаю")
        return summary
    body = "".join("%s\n" % n for n in final)
    res, th = {}, []
    for h in hosts:
        t = threading.Thread(target=lambda h=h: res.__setitem__(h, run_ctl(h, ["scanners-load"], inp=body)))
        t.start()
        th.append(t)
    for t in th:
        t.join(180)
    for h, r in res.items():
        summary["hosts"][h] = "ok" if (r or {}).get("ok") else "ошибка: %s" % str((r or {}).get("error"))[:80]
    for h in hosts:
        r = run_ctl(h, ["scan-clients"])
        for a, v in ((r or {}).get("clients") or {}).items() if (r or {}).get("ok") else []:
            cur = summary["clients"].get(a)
            if not cur or v.get("last", 0) > cur.get("last", 0):
                summary["clients"][a] = dict(v, node=h, list=which_list(a, per_list))
    prev = json.loads(read(os.path.join(base, "summary.json"), "{}") or "{}")
    new_clients = [a for a in summary["clients"] if a not in (prev.get("clients") or {})]
    failed = [h for h, s in summary["hosts"].items() if s != "ok"]
    write(os.path.join(base, "summary.json"), json.dumps(summary, ensure_ascii=False))
    if send and (notes or failed or new_clients):
        lines = ["🔎 <b>Сканеры: список обновлён с замечаниями</b>" if notes or failed else "🔎 <b>Сканеры: в списке наши клиенты</b>",
                 "Сетей в списке: %d (сканеры %d, гос. сети %d, СКИПА %d, свои %d)" % (
                     len(final), len(per_list.get("antiscanner", [])), len(per_list.get("government_networks", [])),
                     len(per_list.get("skipa", [])), len(extra))]
        lines += ["⚠️ " + n for n in notes]
        if failed:
            lines.append("⚠️ Не приняли список: " + ", ".join("%s (%s)" % (h, summary["hosts"][h]) for h in failed))
        if new_clients:
            lines.append("Новые наши клиенты в списке (%d) — они будут отрезаны, когда сканеры переведут в «отбрасывать»:" % len(new_clients))
            for a in new_clients[:10]:
                v = summary["clients"][a]
                lines.append("• <code>%s</code> — %s, %s, список: %s" % (a, v.get("user", ""), v.get("node", ""), v.get("list", "")))
            lines.append("Оставить в списке или в исключения — решать вам (исключения: /etc/channel-watch/scanners-exclude.txt).")
        send("\n".join(lines))
    return summary


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import probe
    import shieldbot
    hs = shieldbot.hosts()
    if "--only" in argv:   # первый прогон на одном сервере (остальные ещё без команды scanners-load)
        only = argv[argv.index("--only") + 1]
        hs = {k: v for k, v in hs.items() if k == only}
    routes = [None] + [r for r in probe.tg_routes() if r]
    s = run(argv, fetcher=lambda n: fetch(n, routes), run_ctl=lambda h, a, inp=None: shieldbot.run_ctl(h, a, hs, inp),
            hosts=hs, send=None if "--dry" in argv else probe.tg_send)
    print(json.dumps({k: v for k, v in s.items() if k != "clients"}, ensure_ascii=False))
    print("наших клиентов в списке:", len(s["clients"]))
    if "--dry" not in argv:
        probe.log("scanlists: сетей %d, серверов ok %d из %d, замечаний %d, клиентов в списке %d" % (
            s["nets"], sum(1 for v in s["hosts"].values() if v == "ok"), len(s["hosts"]), len(s["notes"]), len(s["clients"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
