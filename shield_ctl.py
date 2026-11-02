#!/usr/bin/env python3
"""shield-ctl: щит от флуда на сервере (своя таблица nft `inet storozh_shield`). Блокировки — только
с подтверждением в Telegram, без автоматики. Сам щит ничего не блокирует: считает, кто открывает слишком много соединений
(«подозрительные», 10 минут), а блокировать адреса и включать резку сверх порога можно только командой — её даёт сторож
на rf1 по кнопке владельца в Telegram (ключ rf1 с command="shield-ctl --ssh").

Таблица не трогает ufw, crowdsec, fail2ban и чужие таблицы nft; снимается одной командой: shield-ctl unload (nft delete table …).
  raw_pre  (prerouting -300) — заблокированные адреса: drop до conntrack;
  pre      (prerouting -150) — новые соединения с внешнего интерфейса: сверх rate/с или больше conns одновременно —
            в «подозрительные» (со счётчиком) и в цепочку enforce: в режиме watch она пустая, в режиме on — drop.
Порог по адресу IPv4 и по сети /64 IPv6. Свои адреса (allow: владелец, наши серверы) и частные сети не считаются никогда.
Prerouting — потому что у панели, sub и бота порты проброшены Docker (их трафик идёт мимо input).
Наши клиенты (1.1.0): сборщик ddos-collect
по журналу Xray (строки accepted … email: — только прошедшие проверку подписки) держит за сутки набор clients4/6 и файл
/run/storozh-shield/clients.json (адрес → пользователь, когда видели, сколько подключений; файл не покидает сервер).
Для клиентов порог в client_factor раз выше (цепочка pre_clients); блокировать клиента — только с явным --clients.
Разбор трафика и калитка (1.3.0):
счётчики пакетов по протоколам (in_tcp/in_udp/in_icmp) и порты новых соединений за 2 минуты (newports) — чтобы в
сообщении об атаке было видно, чем бьют; калитка — на порты gate_tcp/gate_udp пускать только своих (allow) и gate_extra
(например, панель: 443 только своим адресам; 80 открыт для сертификата Let's Encrypt). Пустые списки — выключено.
Сканеры (1.2.0, в первую очередь сканеры РКН): набор scanners4/6
(списки shadow-netlab antiscanner, government_networks, skipa + свои добавки; собирает rf1 раз в сутки, присылает
командой scanners-load, файл /etc/storozh-shield/scanners.txt). raw_pre: попадание — счётчик и учёт источника
(scan_seen, сутки); в режиме scan drop — отбрасывание. Режим по умолчанию count (только считать), drop — включается командой, когда убедились, что ваших клиентов в списке нет.

Команды: load | unload | tick | status | block СЕК [--clients] АДРЕС… | unblock all|АДРЕС… | mode watch |
         mode on ЧАСОВ | clients АДРЕС… (кто из них наш клиент) | scanners-load (список сетей на stdin) |
         scan-mode count|drop | scan-clients (наши клиенты, попавшие в список сканеров)
         --ssh — то же из SSH_ORIGINAL_COMMAND, кроме load/unload/tick (для ключа rf1).
Настройки /etc/storozh-shield/config.json, состояние /var/lib/storozh-shield/state.json (блокировки и режим
переживают перезагрузку). Без внешних зависимостей.
"""
import ipaddress
import json
import os
import subprocess
import sys
import time

VERSION = "1.3.0"
TABLE = "inet storozh_shield"
CONF_FILE = "/etc/storozh-shield/config.json"
STATE_FILE = "/var/lib/storozh-shield/state.json"
LOG_FILE = "/var/log/storozh-shield.log"
CLIENTS_FILE = "/run/storozh-shield/clients.json"
SCANNERS_FILE = "/etc/storozh-shield/scanners.txt"
SCAN_MIN_PREFIX = {4: 16, 6: 28}   # шире — не принимаем (ошибка в списке не должна отрезать полмира)
SCAN_MAX = 100000
DEFAULTS = {"iface": "", "rate": 200, "burst": 400, "conns": 5000, "allow": [], "allow_private": True, "max_block": 50,
            "max_block_sec": 86400, "max_on_hours": 6, "client_factor": 5,
            "gate_tcp": [], "gate_udp": [], "gate_extra": []}
# частные сети — не считать и не блокировать (allow_private: false — только на полигоне, где «чужие» тоже частные)
ALWAYS_ALLOW = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                "::1/128", "fe80::/10", "fc00::/7"]
SUSPECT_TOP = 20


def now():
    return int(time.time())


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def cfg():
    c = dict(DEFAULTS)
    c.update(load_json(CONF_FILE, {}))
    return c


def save_state(st, path=None):
    path = path or STATE_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, path)


def log(line):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + line + "\n")
    except OSError:
        pass


def default_iface():
    try:
        for ln in open("/proc/net/route").read().splitlines()[1:]:
            c = ln.split()
            if len(c) > 2 and c[1] == "00000000":
                return c[0]
    except OSError:
        pass
    return ""


# ---------- адреса ----------
def allow_list(c):
    own = list(c.get("allow") or [])
    return own + (ALWAYS_ALLOW if c.get("allow_private", True) else ["127.0.0.0/8", "::1/128"])


def networks(items):
    out4, out6 = [], []
    for x in items:
        try:
            n = ipaddress.ip_network(str(x).strip(), strict=False)
        except ValueError:
            continue
        (out4 if n.version == 4 else out6).append(n)
    return list(ipaddress.collapse_addresses(out4)), list(ipaddress.collapse_addresses(out6))


def block_key(addr):
    """Адрес для блокировки: IPv4 как есть, IPv6 — сеть /64 (адрес внутри /64 клиент меняет сам). ValueError — не адрес."""
    a = ipaddress.ip_address(str(addr).strip())
    if a.version == 6:
        if a.ipv4_mapped:
            a = a.ipv4_mapped
        else:
            return str(ipaddress.ip_network("%s/64" % a, strict=False).network_address)
    return str(a)


def load_clients(path=None):
    d = load_json(path or CLIENTS_FILE, {})
    return d.get("clients", {}) if isinstance(d, dict) else {}


def check_block(addrs, c, clients=None, with_clients=False):
    """-> (годные ключи, [(адрес, почему нельзя)]). Наших клиентов — только при with_clients."""
    allow4, allow6 = networks(allow_list(c))
    clients = clients if clients is not None else {}
    ok, bad = [], []
    for x in addrs:
        try:
            k = block_key(x)
            a = ipaddress.ip_address(k)
        except ValueError:
            bad.append((x, "не адрес"))
            continue
        if (a.is_private and c.get("allow_private", True)) or a.is_loopback or a.is_multicast or a.is_reserved or a.is_unspecified or a.is_link_local:
            bad.append((x, "частный или служебный"))
        elif any(a in n for n in (allow4 if a.version == 4 else allow6)):
            bad.append((x, "в списке своих"))
        elif k in clients and not with_clients:
            bad.append((x, "наш клиент"))
        elif k not in ok:
            ok.append(k)
    if len(ok) > int(c["max_block"]):
        bad += [(k, "больше %d за раз" % c["max_block"]) for k in ok[c["max_block"]:]]
        ok = ok[:c["max_block"]]
    return ok, bad


# ---------- таблица ----------
def render(c, iface, mode="watch", scan_mode="count"):
    """Текст для nft -f: таблица целиком (пересоздаётся). Блокировки добавляются отдельно (restore)."""
    allow4, allow6 = networks(allow_list(c))
    rate, burst, conns, k = int(c["rate"]), int(c["burst"]), int(c["conns"]), max(int(c.get("client_factor", 5)), 1)
    m6 = "ip6 saddr & ffff:ffff:ffff:ffff::"

    def elems(ns):
        return (" elements = { %s };" % ", ".join(str(n) for n in ns)) if ns else ""
    enforce = "\t\tcounter name dropped_shield drop\n" if mode == "on" else ""
    ports = lambda xs: (" elements = { %s };" % ", ".join(str(int(x)) for x in xs)) if xs else ""   # noqa: E731
    g4, g6 = networks(list(c.get("gate_extra") or []))
    scan_drop = "\t\tcounter name scan_dropped drop\n" if scan_mode == "drop" else ""
    return f"""table {TABLE}
delete table {TABLE}
table {TABLE} {{
	set allow4 {{ type ipv4_addr; flags interval; auto-merge;{elems(allow4)} }}
	set allow6 {{ type ipv6_addr; flags interval; auto-merge;{elems(allow6)} }}
	set blocked4 {{ type ipv4_addr; flags timeout; size 65536; }}
	set blocked6 {{ type ipv6_addr; flags timeout; size 65536; }}
	set flood4 {{ type ipv4_addr; flags dynamic,timeout; timeout 1m; size 65536; }}
	set flood6 {{ type ipv6_addr; flags dynamic,timeout; timeout 1m; size 65536; }}
	set conns4 {{ type ipv4_addr; flags dynamic; size 65536; }}
	set conns6 {{ type ipv6_addr; flags dynamic; size 65536; }}
	set suspects4 {{ type ipv4_addr; flags dynamic,timeout; timeout 10m; size 8192; }}
	set suspects6 {{ type ipv6_addr; flags dynamic,timeout; timeout 10m; size 8192; }}
	set clients4 {{ type ipv4_addr; size 262144; }}
	set clients6 {{ type ipv6_addr; size 65536; }}
	set flood_c4 {{ type ipv4_addr; flags dynamic,timeout; timeout 1m; size 65536; }}
	set flood_c6 {{ type ipv6_addr; flags dynamic,timeout; timeout 1m; size 65536; }}
	set conns_c4 {{ type ipv4_addr; flags dynamic; size 65536; }}
	set conns_c6 {{ type ipv6_addr; flags dynamic; size 65536; }}
	counter over_rate {{ }}
	counter over_conns {{ }}
	counter dropped_blocked {{ }}
	counter dropped_shield {{ }}
	set scanners4 {{ type ipv4_addr; flags interval; size 131072; }}
	set scanners6 {{ type ipv6_addr; flags interval; size 16384; }}
	set scan_seen4 {{ type ipv4_addr; flags dynamic,timeout; timeout 24h; size 65536; }}
	set scan_seen6 {{ type ipv6_addr; flags dynamic,timeout; timeout 24h; size 65536; }}
	counter scan_hits {{ }}
	counter scan_dropped {{ }}
	counter in_tcp {{ }}
	counter in_udp {{ }}
	counter in_icmp {{ }}
	counter gate_dropped {{ }}
	set newports {{ type inet_proto . inet_service; flags dynamic,timeout; timeout 2m; size 4096; }}
	set gate_tcp {{ type inet_service;{ports(c.get("gate_tcp") or [])} }}
	set gate_udp {{ type inet_service;{ports(c.get("gate_udp") or [])} }}
	set gate4 {{ type ipv4_addr; flags interval; auto-merge;{elems(g4)} }}
	set gate6 {{ type ipv6_addr; flags interval; auto-merge;{elems(g6)} }}
	chain raw_pre {{
		type filter hook prerouting priority -300; policy accept;
		iifname != "{iface}" return
		meta l4proto tcp counter name in_tcp
		meta l4proto udp counter name in_udp
		meta l4proto {{ icmp, ipv6-icmp }} counter name in_icmp
		ip saddr @allow4 return
		ip6 saddr @allow6 return
		tcp dport @gate_tcp ip saddr != @gate4 counter name gate_dropped drop
		udp dport @gate_udp ip saddr != @gate4 counter name gate_dropped drop
		tcp dport @gate_tcp ip6 saddr != @gate6 counter name gate_dropped drop
		udp dport @gate_udp ip6 saddr != @gate6 counter name gate_dropped drop
		ip saddr @blocked4 counter name dropped_blocked drop
		{m6} @blocked6 counter name dropped_blocked drop
		ip saddr @scanners4 update @scan_seen4 {{ ip saddr counter }} goto scan
		ip6 saddr @scanners6 update @scan_seen6 {{ ip6 saddr counter }} goto scan
	}}
	chain scan {{
		counter name scan_hits
{scan_drop}	}}
	chain pre {{
		type filter hook prerouting priority -150; policy accept;
		iifname != "{iface}" return
		ct state != new return
		meta l4proto {{ tcp, udp }} update @newports {{ meta l4proto . th dport counter }}
		ip saddr @allow4 return
		ip6 saddr @allow6 return
		ip saddr @clients4 goto pre_clients
		{m6} @clients6 goto pre_clients
		add @flood4 {{ ip saddr limit rate over {rate}/second burst {burst} packets }} update @suspects4 {{ ip saddr counter }} counter name over_rate jump enforce
		add @flood6 {{ {m6} limit rate over {rate}/second burst {burst} packets }} update @suspects6 {{ {m6} counter }} counter name over_rate jump enforce
		add @conns4 {{ ip saddr ct count over {conns} }} update @suspects4 {{ ip saddr counter }} counter name over_conns jump enforce
		add @conns6 {{ {m6} ct count over {conns} }} update @suspects6 {{ {m6} counter }} counter name over_conns jump enforce
	}}
	chain pre_clients {{
		add @flood_c4 {{ ip saddr limit rate over {rate * k}/second burst {burst * k} packets }} update @suspects4 {{ ip saddr counter }} counter name over_rate jump enforce
		add @flood_c6 {{ {m6} limit rate over {rate * k}/second burst {burst * k} packets }} update @suspects6 {{ {m6} counter }} counter name over_rate jump enforce
		add @conns_c4 {{ ip saddr ct count over {conns * k} }} update @suspects4 {{ ip saddr counter }} counter name over_conns jump enforce
		add @conns_c6 {{ {m6} ct count over {conns * k} }} update @suspects6 {{ {m6} counter }} counter name over_conns jump enforce
	}}
	chain enforce {{
{enforce}	}}
}}
"""


def nft(args, inp=None):
    r = subprocess.run(["nft"] + args, input=inp, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("nft %s: %s" % (" ".join(args[:3]), (r.stderr or "").strip()[:300]))
    return r.stdout


def current_mode(st, t=None):
    t = t or now()
    return "on" if st.get("mode") == "on" and int(st.get("until") or 0) > t else "watch"


def live_blocks(st, t=None):
    t = t or now()
    return {k: v for k, v in (st.get("blocks") or {}).items() if int(v) > t}


def add_elements(blocks, t=None):
    t = t or now()
    for fam in (4, 6):
        el = ["%s timeout %ds" % (k, max(int(v) - t, 1)) for k, v in blocks.items()
              if ipaddress.ip_address(k).version == fam]
        if el:
            nft(["add", "element", TABLE, "blocked%d" % fam, "{ %s }" % ", ".join(el)])


def clients_nft(clients):
    """Текст для nft -f: набор клиентов заново, одной транзакцией (пишет и сборщик)."""
    v4 = [k for k in clients if ":" not in k]
    v6 = [k for k in clients if ":" in k]
    out = ["flush set %s clients4" % TABLE, "flush set %s clients6" % TABLE]
    for name, items in (("clients4", v4), ("clients6", v6)):
        for i in range(0, len(items), 2000):
            out.append("add element %s %s { %s }" % (TABLE, name, ", ".join(items[i:i + 2000])))
    return "\n".join(out) + "\n"


# ---------- сканеры ----------
def parse_scanners(text, c):
    """Текст (сеть в строке, # — комментарий) -> (сети v4, сети v6, отброшено [(строка, почему)]). Свои вырезаются."""
    nets, bad = {4: [], 6: []}, []
    for ln in text.splitlines():
        x = ln.split("#")[0].strip()
        if not x:
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            bad.append((x[:60], "не сеть"))
            continue
        if n.prefixlen < SCAN_MIN_PREFIX[n.version]:
            bad.append((x, "слишком широкая (шире /%d)" % SCAN_MIN_PREFIX[n.version]))
            continue
        nets[n.version].append(n)
    allow4, allow6 = networks(allow_list(c))
    out = {}
    for v, allow in ((4, allow4), (6, allow6)):
        res = []
        for n in ipaddress.collapse_addresses(nets[v]):
            parts = [n]
            for a in allow:
                nxt = []
                for p_ in parts:
                    if p_.overlaps(a):
                        if a.supernet_of(p_):
                            bad.append((str(p_), "в списке своих"))
                        else:
                            nxt += list(p_.address_exclude(a))
                            bad.append((str(p_), "вырезаны свои " + str(a)))
                    else:
                        nxt.append(p_)
                parts = nxt
            res += parts
        out[v] = list(ipaddress.collapse_addresses(res))
    if len(out[4]) + len(out[6]) > SCAN_MAX:
        raise ValueError("сетей больше %d" % SCAN_MAX)
    return out[4], out[6], bad


def scanners_nft(v4, v6):
    lines = ["flush set %s scanners4" % TABLE, "flush set %s scanners6" % TABLE]
    for name, items in (("scanners4", v4), ("scanners6", v6)):
        items = [str(n) for n in items]
        for i in range(0, len(items), 2000):
            lines.append("add element %s %s { %s }" % (TABLE, name, ", ".join(items[i:i + 2000])))
    return "\n".join(lines) + "\n"


def cmd_scanners_load(c, text):
    v4, v6, bad = parse_scanners(text, c)
    if not v4 and not v6:
        raise ValueError("пустой список — не загружаю")
    nft(["-f", "-"], scanners_nft(v4, v6))
    os.makedirs(os.path.dirname(SCANNERS_FILE), exist_ok=True)
    tmp = SCANNERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join("%s\n" % n for n in v4 + v6))
    os.replace(tmp, SCANNERS_FILE)
    log("scanners-load: v4 %d, v6 %d, отброшено %d" % (len(v4), len(v6), len(bad)))
    return {"ok": True, "v4": len(v4), "v6": len(v6), "refused": bad[:20], "refused_total": len(bad)}


def scan_mode(st):
    return "drop" if st.get("scan_mode") == "drop" else "count"


def cmd_scan_mode(c, st, mode):
    if mode not in ("count", "drop"):
        raise ValueError("режим сканеров — count или drop")
    st["scan_mode"] = mode
    nft(["flush", "chain", TABLE, "scan"])
    nft(["add", "rule", TABLE, "scan", "counter", "name", "scan_hits"])
    if mode == "drop":
        nft(["add", "rule", TABLE, "scan", "counter", "name", "scan_dropped", "drop"])
    save_state(st)
    log("scan-mode %s" % mode)
    return {"ok": True, "scan_mode": mode}


def load_scanner_nets():
    by_len = {}
    try:
        for ln in open(SCANNERS_FILE, encoding="utf-8"):
            try:
                n = ipaddress.ip_network(ln.strip())
            except ValueError:
                continue
            by_len.setdefault((n.version, n.prefixlen), set()).add(int(n.network_address))
    except OSError:
        pass
    return by_len


def in_scanners(addr, by_len):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    bits = 32 if a.version == 4 else 128
    for (v, plen), nets in by_len.items():
        if v == a.version and (int(a) >> (bits - plen) << (bits - plen)) in nets:
            return True
    return False


def cmd_scan_clients():
    """Наши клиенты (по журналу Xray за сутки), чьи адреса попали в список сканеров."""
    by_len, out = load_scanner_nets(), {}
    for k, v in load_clients().items():
        if in_scanners(k, by_len):
            out[k] = {"user": v[1] if len(v) > 1 else "", "last": v[0], "n": v[2] if len(v) > 2 else 0}
    return {"ok": True, "clients": out}


def cmd_load(c, st):
    iface = c.get("iface") or default_iface()
    if not iface:
        raise RuntimeError("нет внешнего интерфейса")
    st["blocks"] = live_blocks(st)
    mode = current_mode(st)
    if mode == "watch":
        st["mode"], st["until"] = "watch", 0
    nft(["-f", "-"], render(c, iface, mode, scan_mode(st)))
    add_elements(st["blocks"])
    try:
        sc = open(SCANNERS_FILE, encoding="utf-8").read()
        v4, v6, _ = parse_scanners(sc, c)
        nft(["-f", "-"], scanners_nft(v4, v6))
    except OSError:
        pass
    except (ValueError, RuntimeError) as e:
        log("сканеры не загружены: %s" % e)
    cl = load_clients()
    if cl:
        try:
            nft(["-f", "-"], clients_nft(cl))
        except RuntimeError as e:
            log("клиенты не загружены: %s" % e)
    save_state(st)
    return {"ok": True, "iface": iface, "mode": mode, "blocked": len(st["blocks"]), "clients": len(cl)}


def set_mode(c, st, mode, hours=0):
    if mode == "on":
        hours = float(hours)
        if not 0 < hours <= float(c["max_on_hours"]):
            raise ValueError("часов — от 0 до %s" % c["max_on_hours"])
        st["mode"], st["until"] = "on", now() + int(hours * 3600)
        nft(["flush", "chain", TABLE, "enforce"])
        nft(["add", "rule", TABLE, "enforce", "counter", "name", "dropped_shield", "drop"])
    else:
        st["mode"], st["until"] = "watch", 0
        nft(["flush", "chain", TABLE, "enforce"])
    save_state(st)
    log("mode %s %s" % (st["mode"], st["until"]))
    return {"ok": True, "mode": st["mode"], "until": st["until"]}


def cmd_block(c, st, sec, addrs):
    with_clients = "--clients" in addrs
    addrs = [a for a in addrs if a != "--clients"]
    sec = int(sec)
    if not 60 <= sec <= int(c["max_block_sec"]):
        raise ValueError("срок — от 60 до %s секунд" % c["max_block_sec"])
    ok, bad = check_block(addrs, c, load_clients(), with_clients)
    until = now() + sec
    if ok:
        add_elements({k: until for k in ok})
        st.setdefault("blocks", {}).update({k: until for k in ok})
        st["blocks"] = live_blocks(st)
        save_state(st)
        log("block %ds%s %s" % (sec, " (с клиентами)" if with_clients else "", " ".join(ok)))
    return {"ok": True, "blocked": ok, "until": until, "refused": bad}


def cmd_unblock(c, st, addrs):
    blocks = live_blocks(st)
    if addrs == ["all"]:
        keys = list(blocks)
        nft(["flush", "set", TABLE, "blocked4"])
        nft(["flush", "set", TABLE, "blocked6"])
    else:
        keys = []
        for x in addrs:
            try:
                k = block_key(x)
            except ValueError:
                continue
            if k in blocks:
                keys.append(k)
                fam = ipaddress.ip_address(k).version
                nft(["delete", "element", TABLE, "blocked%d" % fam, "{ %s }" % k])
    for k in keys:
        blocks.pop(k, None)
    st["blocks"] = blocks
    save_state(st)
    log("unblock %s" % " ".join(keys))
    return {"ok": True, "unblocked": keys}


def cmd_clients(addrs):
    """Кто из адресов — наш клиент: {адрес: {user, last, n, node}}."""
    cl, out = load_clients(), {}
    for x in addrs:
        try:
            k = block_key(x)
        except ValueError:
            continue
        if k in cl:
            v = cl[k]
            out[x] = {"user": v[1] if len(v) > 1 else "", "last": v[0], "n": v[2] if len(v) > 2 else 0}
    return {"ok": True, "clients": out, "known": len(cl)}


def parse_set(js, name):
    """nft -j list set … -> [(адрес, пакетов)] (у «подозрительных» — счётчик сверх порога)."""
    out = []
    for item in js.get("nftables", []):
        s = item.get("set")
        if not s or s.get("name") != name:
            continue
        for e in s.get("elem", []) or []:
            v = e.get("elem", e) if isinstance(e, dict) else e
            addr = v.get("val") if isinstance(v, dict) else v
            if isinstance(addr, dict) and "concat" in addr:   # порт новых соединений: протокол . порт
                pr, port = (addr["concat"] + [None, None])[:2]
                addr = "%s/%s" % ({6: "tcp", 17: "udp"}.get(pr, pr), port)
            pk = 0
            if isinstance(v, dict):
                pk = int(((v.get("counter") or {}).get("packets")) or 0)
            if isinstance(addr, str):
                out.append((addr, pk))
    return out


def parse_counters(js):
    out = {}
    for item in js.get("nftables", []):
        cn = item.get("counter")
        if cn and cn.get("name"):
            out[cn["name"]] = int(cn.get("packets") or 0)
    return out


def cmd_status(c, st):
    sus = []
    for fam in (4, 6):
        try:
            sus += parse_set(json.loads(nft(["-j", "list", "set", TABLE, "suspects%d" % fam])), "suspects%d" % fam)
        except (RuntimeError, ValueError):
            return {"ok": False, "loaded": False, "v": VERSION}
    try:
        counters = parse_counters(json.loads(nft(["-j", "list", "counters", "table", TABLE])))
    except (RuntimeError, ValueError):
        counters = {}
    sus.sort(key=lambda x: -x[1])
    seen = []
    for fam in (4, 6):
        try:
            seen += parse_set(json.loads(nft(["-j", "list", "set", TABLE, "scan_seen%d" % fam])), "scan_seen%d" % fam)
        except (RuntimeError, ValueError):
            pass
    seen.sort(key=lambda x: -x[1])
    try:
        nports = sorted(parse_set(json.loads(nft(["-j", "list", "set", TABLE, "newports"])), "newports"), key=lambda x: -x[1])
    except (RuntimeError, ValueError):
        nports = []
    try:
        scan_nets = sum(1 for _ in open(SCANNERS_FILE, encoding="utf-8"))
        scan_updated = int(os.path.getmtime(SCANNERS_FILE))
    except OSError:
        scan_nets, scan_updated = 0, 0
    return {"ok": True, "loaded": True, "v": VERSION, "mode": current_mode(st), "until": int(st.get("until") or 0),
            "scan": {"mode": scan_mode(st), "nets": scan_nets, "updated": scan_updated, "sources": len(seen),
                     "packets": sum(p for _, p in seen), "top": [list(x) for x in seen[:10]]},
            "blocked": sorted(live_blocks(st).items()), "suspects": [list(x) for x in sus[:SUSPECT_TOP]],
            "suspects_total": len(sus), "counters": counters, "clients": len(load_clients()),
            "limits": {"rate": int(c["rate"]), "conns": int(c["conns"])},
            "proto": {k: counters.get("in_" + k, 0) for k in ("tcp", "udp", "icmp")},
            "ports": [list(x) for x in nports[:10]],
            "gate": {"tcp": list(c.get("gate_tcp") or []), "udp": list(c.get("gate_udp") or []),
                     "dropped": counters.get("gate_dropped", 0)}}


def cmd_tick(c, st):
    changed = False
    if st.get("mode") == "on" and current_mode(st) == "watch":
        set_mode(c, st, "watch")
        log("mode on истёк — снова наблюдение")
        changed = True
    blocks = live_blocks(st)
    if blocks != (st.get("blocks") or {}):
        st["blocks"] = blocks
        save_state(st)
        changed = True
    return {"ok": True, "changed": changed}


SSH_ALLOWED = ("status", "block", "unblock", "mode", "clients", "scanners-load", "scan-mode", "scan-clients")


def dispatch(argv, c, st):
    if not argv:
        raise ValueError("нет команды")
    cmd, a = argv[0], argv[1:]
    if cmd == "load":
        return cmd_load(c, st)
    if cmd == "unload":
        nft(["delete", "table", TABLE])
        return {"ok": True}
    if cmd == "tick":
        return cmd_tick(c, st)
    if cmd == "status":
        return cmd_status(c, st)
    if cmd == "block" and len(a) >= 2:
        return cmd_block(c, st, a[0], a[1:])
    if cmd == "clients" and a:
        return cmd_clients(a)
    if cmd == "scanners-load" and not a:
        return cmd_scanners_load(c, sys.stdin.read(20 * 2 ** 20))
    if cmd == "scan-mode" and len(a) == 1:
        return cmd_scan_mode(c, st, a[0])
    if cmd == "scan-clients" and not a:
        return cmd_scan_clients()
    if cmd == "unblock" and a:
        return cmd_unblock(c, st, a)
    if cmd == "mode" and a and a[0] == "watch":
        return set_mode(c, st, "watch")
    if cmd == "mode" and len(a) == 2 and a[0] == "on":
        return set_mode(c, st, "on", a[1])
    raise ValueError("не понимаю: %s" % " ".join(argv)[:100])


def ssh_argv(original):
    """SSH_ORIGINAL_COMMAND -> argv; только разрешённые команды, только простые слова (без кавычек и подстановок)."""
    parts = (original or "").split()
    if not parts or parts[0] not in SSH_ALLOWED:
        raise ValueError("команда не разрешена")
    if len(parts) > 60 or any(not all(ch.isalnum() or ch in ".:-_" for ch in p) for p in parts):
        raise ValueError("недопустимые символы")
    return parts


def main(argv):
    c, st = cfg(), load_json(STATE_FILE, {})
    try:
        if argv[:1] == ["--ssh"]:
            argv = ssh_argv(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
            log("ssh: " + " ".join(argv)[:300])
        res = dispatch(argv, c, st)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        res = {"ok": False, "error": str(e)[:300]}
    print(json.dumps(res, ensure_ascii=False))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
