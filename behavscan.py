#!/usr/bin/env python3
"""channel-watch: свой список сканеров «по поведению».

Официальные списки (scanlists.py) ловят только известные сети. Остальных сканеров видно по поведению, которого у клиента
не бывает: стук в закрытые порты. Маячок каждой ноды (node_beacon.py, поле knocks) пишет, кто за сутки слал SYN на
закрытые порты (по журналу ufw). Раз в сутки, перед scanlists, этот скрипт на сервере сторожа:
  1. забирает маячки всех нод (nodes.json);
  2. отбирает подозрительных: стучался на 80/443/8443 закрытого порта, или в 3+ разных закрытых порта, или замечен на
     2+ наших серверах;
  3. убирает наши адреса и исключения (те же, что у scanlists: адреса владельца, все серверы из ddos.json,
     /etc/channel-watch/scanners-exclude.txt) и **адреса клиентов**: спрашивает щит каждой ноды (shield-ctl clients —
     кто из адресов подключался к Xray за сутки); адрес, хоть раз оказавшийся клиентом, не берётся 30 дней;
  4. берёт только адреса хостингов/ЦОД (по ip-api.com, кэш 30 дней) — домашние и мобильные сети не трогаем, кроме тех,
     кто простучал 10+ портов: за домашним адресом может сидеть наш клиент;
  5. держит адрес в списке 30 дней после последнего стука; пишет /var/lib/channel-watch/scanners/behavior.list —
     scanlists добавит его к общему списку щита отдельной строкой «по поведению на наших серверах».
Режим тот же, что у остальных списков: пока щит только считает попадания (блокировать — отдельное решение владельца).
Запуск: behavscan.py [--dry]
"""
import ipaddress
import json
import os
import sys
import time
import urllib.request

ETC = "/etc/channel-watch"
DIR = "/var/lib/channel-watch/scanners"
STATE = "/var/lib/channel-watch/behavior.json"
KEEP_DAYS = 30
MIN_PORTS = 3          # столько разных закрытых портов за сутки — сканер
MIN_PORTS_HOME = 10    # домашний/мобильный адрес берём только с таким размахом
MIN_NODES = 2          # замечен на стольких наших серверах — сканер


def aggregate(beacons):
    """{нода: маячок} -> {адрес: {"nodes": set, "ports": макс. разных портов, "hits": сумма, "strong": 0/1}}."""
    agg = {}
    for node, b in beacons.items():
        for row in (b or {}).get("knocks") or []:
            try:
                ip, ports, hits, strong = row[0], int(row[1]), int(row[2]), int(row[3])
                ipaddress.ip_address(ip)
            except (ValueError, TypeError, IndexError):
                continue
            v = agg.setdefault(ip, {"nodes": set(), "ports": 0, "hits": 0, "strong": 0})
            v["nodes"].add(node)
            v["ports"] = max(v["ports"], ports)
            v["hits"] += hits
            v["strong"] = max(v["strong"], strong)
    return agg


def suspicious(v):
    return bool(v["strong"]) or v["ports"] >= MIN_PORTS or len(v["nodes"]) >= MIN_NODES


def is_own(ip, own):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in own if n.version == a.version)


def ip_api(ips):
    """{адрес: {"hosting": bool, "as": str}} по ip-api.com пачками по 100 (без ключа: 15 запросов в минуту)."""
    out = {}
    ips = list(ips)
    for i in range(0, len(ips), 100):
        part = ips[i:i + 100]
        req = urllib.request.Request("http://ip-api.com/batch?fields=query,status,as,hosting",
                                     data=json.dumps(part).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                for x in json.load(r):
                    if x.get("status") == "success":
                        out[x["query"]] = {"hosting": bool(x.get("hosting")), "as": (x.get("as") or "")[:60]}
        except Exception:
            pass   # нет ответа — спросим в следующий раз
        if i + 100 < len(ips):
            time.sleep(5)
    return out


def step(state, beacons, own, now, lookup=ip_api, clients_of=None):
    """Один проход: обновить state (на месте). -> (адреса в списке, новых за проход).
    clients_of(адреса) -> множество тех, кто наш клиент (щиты нод); None — не спрашивать (тесты, нет связи)."""
    ips = state.setdefault("ips", {})
    agg = aggregate(beacons)
    cand = {ip: v for ip, v in agg.items() if suspicious(v) and not is_own(ip, own)}
    asked = list(cand) + [ip for ip, e in ips.items() if e.get("listed") and ip not in cand]
    for ip in (clients_of(asked) if clients_of and asked else set()):
        e = ips.setdefault(ip, {"first": int(now)})
        e.update(client=int(now), listed=False, last=int(now))
    cand = {ip: v for ip, v in cand.items() if now - ips.get(ip, {}).get("client", 0) > KEEP_DAYS * 86400}
    need = [ip for ip in cand if ip not in ips or now - ips[ip].get("looked", 0) > KEEP_DAYS * 86400]
    info = lookup(need) if need else {}
    new = 0
    for ip, v in cand.items():
        e = ips.get(ip)
        if ip in info:
            e = e or {"first": int(now)}
            e.update(info[ip], looked=int(now))
        if e is None:   # сведений нет (ip-api молчит) — подождём следующего прохода
            continue
        if not (e.get("hosting") or v["ports"] >= MIN_PORTS_HOME):
            ips[ip] = dict(e, listed=False, last=int(now))
            continue
        if not e.get("listed"):
            new += 1
        e.update(listed=True, last=int(now), nodes=sorted(v["nodes"]), ports=max(v["ports"], e.get("ports", 0)),
                 hits=e.get("hits", 0) + v["hits"], strong=max(v["strong"], e.get("strong", 0)))
        ips[ip] = e
    for ip in [ip for ip, e in ips.items() if now - e.get("last", 0) > KEEP_DAYS * 86400]:
        del ips[ip]
    for ip, e in ips.items():   # свой адрес или клиент мог попасть в список раньше
        if e.get("listed") and (is_own(ip, own) or now - e.get("client", 0) <= KEEP_DAYS * 86400):
            e["listed"] = False
    state["ts"] = int(now)
    listed = sorted((ip for ip, e in ips.items() if e.get("listed")), key=lambda x: ipaddress.ip_address(x))
    return listed, new


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import nodewatch
    import scanlists
    import shieldbot
    import probe
    nodes = json.load(open(os.path.join(ETC, "nodes.json"), encoding="utf-8"))
    beacons = {n["name"]: nodewatch.fetch_beacon(n["beacon"]) for n in nodes if n.get("beacon")}
    got = sum(1 for b in beacons.values() if b and "knocks" in b)
    own = scanlists.own_networks(shieldbot.hosts().values()) + scanlists.parse(
        scanlists.read(os.path.join(ETC, "scanners-exclude.txt")))[0]
    try:
        state = json.load(open(STATE, encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    hs = shieldbot.hosts()

    def clients_of(addrs):
        found = set()
        for h in hs:
            for i in range(0, len(addrs), 300):
                r = shieldbot.run_ctl(h, ["clients"] + addrs[i:i + 300], hs) or {}
                found |= set((r.get("clients") or {}).keys())
        return found

    listed, new = step(state, beacons, own, time.time(), clients_of=clients_of)
    nclients = sum(1 for e in state["ips"].values() if e.get("client"))
    msg = "behavscan: маячков со стуками %d из %d, в списке %d адресов, новых %d, клиентов отсеяно %d" % (
        got, len(beacons), len(listed), new, nclients)
    print(msg)
    if "--dry" in argv:
        return 0
    with open(STATE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(STATE + ".tmp", STATE)
    scanlists.write(os.path.join(DIR, scanlists.BEHAVIOR + ".list"), "".join("%s/%d\n" % (ip, 128 if ":" in ip else 32) for ip in listed))
    probe.log(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
