#!/usr/bin/env python3
"""channel-watch: свой список сканеров «по поведению».

Официальные списки (scanlists.py) ловят только известные сети. Остальных сканеров видно по поведению, которого у клиента
не бывает: стук в закрытые порты. Маячок каждой ноды (node_beacon.py, поле knocks) пишет, кто за сутки слал SYN на
закрытые порты (по журналу ufw). Раз в сутки, перед scanlists, этот скрипт на сервере сторожа:
  1. забирает маячки всех нод (nodes.json); с ноды берёт не больше KNOCK_MAX строк, порты только 1…65535, строки не
     того вида пропускает; ::ffff:a.b.c.d — это IPv4; не глобальные и multicast — пропуск (старые маячки пропускают
     100.64/10, 169.254/16); IPv6 — сеть /64 (новый маячок отдаёт её сам, старый — адрес /128);
  2. отбирает подозрительных: стучался на 80/443/8443 закрытого порта, или в 3+ разных закрытых порта, или замечен на
     2+ наших серверах; запоминает по суткам и по нодам (повторный проход заменяет запись только тех нод, чей маячок
     прочитался, а не складывает; новая запись суток ноды — только через NEW_DAY_GAP после прошлой, иначе проходы в
     23:00 и в 04:20 видели бы одни и те же стуки за 24 ч как двое суток);
  3. вносит адрес, только если хотя бы в одних сутках стук был с 2+ разных нод И стук был в 2+ разных сутках (SYN с
     чужим адресом подделывается, одного-двух стуков мало);
  4. убирает наши адреса и исключения (scanlists.own_networks: ваши адреса из owner.txt, серверы ddos.json, хосты nodes.json и
     vantage.json; /etc/channel-watch/scanners-exclude.txt), NEVER_LIST из scanlists (Telegram, Cloudflare, GitHub,
     ip-api, DNS; IPv4 и IPv6) и **адреса клиентов**: каждый проход спрашивает щит каждой ноды обо всех, кто стучал
     сегодня, и обо всех внесённых (shield-ctl clients кусками до 50 адресов — кто подключался к Xray за сутки;
     щиты разных серверов — параллельно, куски одному щиту — по очереди);
     клиент не берётся 30 дней, его адрес сразу забывается, остаётся только солёный хэш (соль — отдельный файл SALT,
     права 600, меняется раз в KEEP_DAYS). Если хоть один щит не ответил, клиенты неизвестны — новых не вносим.
     Свои, исключения и NEVER_LIST для IPv6 — по пересечению сети /64 с ними;
  5. берёт только адреса хостингов/ЦОД (по ip-api.com, кэш 30 дней); мобильные — никогда (за CGNAT сотни людей),
     домашние — только если простучали 10+ портов (с 2+ нод);
  6. держит адрес в списке 30 дней после последнего стука; пишет /var/lib/channel-watch/scanners/behavior.list
     (IPv4 — /32, IPv6 — /64) — scanlists добавит его к общему списку щита отдельной строкой «по поведению на наших
     серверах».
Режим тот же, что у остальных списков: пока щит только считает попадания (блокировать — отдельной командой, когда убедились).
Запуск: behavscan.py [--dry]
"""
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanlists  # noqa: E402

ETC = "/etc/channel-watch"
DIR = "/var/lib/channel-watch/scanners"
STATE = "/var/lib/channel-watch/behavior.json"
SALT = "/var/lib/channel-watch/behavscan.salt"   # соль хэшей клиентов — отдельно от STATE, права 600
KEEP_DAYS = 30
MIN_PORTS = 3          # столько разных закрытых портов за сутки — сканер
MIN_PORTS_HOME = 10    # домашний адрес берём только с таким размахом (и с MIN_NODES нод)
MIN_NODES = 2          # хотя бы в одних сутках замечен на стольких наших серверах; меньше — в список не вносим
MIN_DAYS = 2           # и стук в стольких разных сутках
KNOCK_MAX = 400        # строк knocks с одной ноды (столько отдаёт маячок), лишнее отбрасываем
CLIENTS_CHUNK = 50     # адресов в одной команде clients: щит по ssh принимает не больше 60 слов
CLIENTS_WAIT = 75      # секунд ожидания щита на один кусок (shieldbot.run_ctl ждёт ssh до 60 с)
NEW_DAY_GAP = 23 * 3600   # новая запись суток ноды — не раньше, чем через столько после её прошлой записи (окно маячка 24 ч)


def ip_key(ip):
    """Ключ сортировки адресов обоих семейств: IPv4 и IPv6 напрямую не сравниваются."""
    a = ipaddress.ip_address(ip)
    return a.version, a


def norm_ip(text):
    """Адрес из маячка -> ключ state или None. ::ffff:a.b.c.d — IPv4; не глобальные (частные, 100.64/10, 169.254/16,
    документация) и multicast — None; IPv6 — адрес сети /64 (клиент и сканер меняют адрес внутри /64 сами).
    ValueError — не адрес."""
    a = ipaddress.ip_address(text)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if not a.is_global or a.is_multicast:
        return None
    if a.version == 6:
        return str(ipaddress.ip_network((a, 64), strict=False).network_address)
    return str(a)


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def aggregate(beacons):
    """{нода: маячок} -> {адрес: {"nodes": set, "ports": макс. разных портов, "hits": сумма, "strong": 0/1,
    "per": {нода: {"ports", "hits", "strong"}}}}. Маячку не доверяем: knocks не список — нода пропускается, строка не
    список из адреса и трёх чисел — пропускается строка; весь проход из-за одной ноды не падает. Адрес — ключ
    norm_ip: IPv6 — сеть /64 (стуки адресов одной /64 с ноды складываются), не глобальные — пропуск."""
    agg = {}
    for node, b in beacons.items():
        knocks = b.get("knocks") if isinstance(b, dict) else None
        if not isinstance(knocks, list):
            continue
        for row in knocks[:KNOCK_MAX]:
            if not (isinstance(row, (list, tuple)) and len(row) >= 4 and isinstance(row[0], str)
                    and all(_num(x) for x in row[1:4])):
                continue
            try:
                ip, ports, hits, strong = norm_ip(row[0]), int(row[1]), int(row[2]), int(row[3])
            except (ValueError, OverflowError):
                continue
            if ip is None or not (1 <= ports <= 65535 and hits >= 0 and strong in (0, 1)):
                continue
            v = agg.setdefault(ip, {"nodes": set(), "ports": 0, "hits": 0, "strong": 0, "per": {}})
            v["nodes"].add(node)
            v["ports"] = max(v["ports"], ports)
            v["hits"] += hits
            v["strong"] = max(v["strong"], strong)
            p = v["per"].setdefault(node, {"ports": 0, "hits": 0, "strong": 0})
            p["ports"] = max(p["ports"], ports)
            p["hits"] += hits
            p["strong"] = max(p["strong"], strong)
    return agg


def suspicious(v):
    return bool(v["strong"]) or v["ports"] >= MIN_PORTS or len(v["nodes"]) >= MIN_NODES


def is_own(ip, own):
    """Адрес в своих сетях. IPv6 — по пересечению его сети /64 (ключ в state и строка behavior.list) со своими: сеть
    /64, задевшая наш сервер или NEVER_LIST, в список не идёт."""
    a = ipaddress.ip_address(ip)
    if a.version == 6:
        net = ipaddress.ip_network((a, 64), strict=False)
        return any(net.overlaps(n) for n in own if n.version == 6)
    return any(a in n for n in own if n.version == 4)


def day_of(now):
    """Номер суток по Москве (ключ в state)."""
    return str(int((now + 3 * 3600) // 86400))


def load_salt(now, path=None, save=True):
    """Соль для хэшей клиентов -> (соль, с какого времени). Лежит отдельно от behavior.json (права 600): кто унёс
    только state, хэши не переберёт. Раз в KEEP_DAYS — новая соль; step тогда сбрасывает отметки клиентов (щиты всё
    равно перепроверяют каждый проход). save=False (--dry) — файл не трогаем."""
    path = path or SALT
    try:
        salt, since = open(path, encoding="ascii").read().split()
        since = int(since)
        if len(salt) >= 32 and 0 <= now - since < KEEP_DAYS * 86400:
            return salt, since
    except (OSError, ValueError, UnicodeError):
        pass
    salt, since = secrets.token_hex(16), int(now)
    if save:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write("%s %d\n" % (salt, since))
        os.chmod(path + ".tmp", 0o600)
        os.replace(path + ".tmp", path)
    return salt, since


def client_hash(ip, salt):
    """Отметка «клиент» без самого адреса (README: адреса клиентов не копим)."""
    return hashlib.sha256((salt + str(ipaddress.ip_address(ip))).encode()).hexdigest()


def summary(e):
    """Сводка стуков адреса по всем хранимым суткам; "most" — больше всего разных нод в одних сутках."""
    nodes, rows, most, days = set(), [], 0, 0
    for d in (e.get("days") or {}).values():
        if d:
            days += 1
            nodes.update(d)
            rows += d.values()
            most = max(most, len(d))
    return {"nodes": nodes, "days": days, "most": most, "ports": max([r.get("ports", 0) for r in rows] or [0]),
            "hits": sum(r.get("hits", 0) for r in rows), "strong": max([r.get("strong", 0) for r in rows] or [0])}


def _norm_day(d):
    """Запись суток -> {нода: {"ports", "hits", "strong"}}. Прежний вид {"nodes": [...], "ports", "hits",
    "strong"} делим по нодам (стуки — первой ноде, чтобы сумма не выросла)."""
    if not isinstance(d, dict):
        return {}
    if isinstance(d.get("nodes"), list):
        return {str(n): {"ports": d.get("ports", 0), "hits": d.get("hits", 0) if i == 0 else 0,
                         "strong": d.get("strong", 0)} for i, n in enumerate(d["nodes"])}
    return {str(n): x for n, x in d.items() if isinstance(x, dict)}


def _merge(a, b):
    """Две записи одной сети /64 (старый state хранил IPv6 адресами /128) -> одна: за основу — со свежим стуком,
    записи суток другой добавляются по нодам, которых нет."""
    if b.get("last", 0) > a.get("last", 0):
        a, b = b, a
    for d, day in b["days"].items():
        cur = a["days"].setdefault(d, {})
        for n, x in day.items():
            cur.setdefault(n, x)
    a["first"] = min(a.get("first", a.get("last", 0)), b.get("first", b.get("last", 0)))
    return a


def _migrate(ips, clients, salt):
    """Записи прежнего вида (без суток): клиента — в хэш, адрес забыть; остальных снять со списка — внесены по
    одному стуку, пусть наберут 2 ноды и 2 суток заново. Сутки прежнего вида — по нодам. Ключ — norm_ip:
    ::ffff:a.b.c.d — IPv4, IPv6 — сеть /64 (записи одной /64 сливаются); ключ не адрес или не глобальный, запись не
    словарь, сутки не числом — выкидываются (повреждённый state не роняет проход)."""
    out = {}
    for ip, e in ips.items():
        try:
            key = norm_ip(ip) if isinstance(ip, str) else None
        except ValueError:
            continue
        if key is None or not isinstance(e, dict):
            continue
        if "days" in e:
            days = e["days"] if isinstance(e["days"], dict) else {}
            e["days"] = {d: _norm_day(x) for d, x in days.items() if isinstance(d, str) and d.isdigit()}
        elif e.get("client"):
            if _num(e["client"]):
                h = client_hash(key, salt)
                clients[h] = max(clients.get(h, 0), int(e["client"]))
            continue
        else:
            e["days"] = {day_of(e.get("last", 0)): _norm_day({"nodes": e.get("nodes") or [], "ports": e.get("ports", 0),
                                                              "hits": e.get("hits", 0), "strong": e.get("strong", 0)})}
            e["listed"] = False
        out[key] = _merge(out[key], e) if key in out else e
    ips.clear()
    ips.update(out)


def _last_record(days, node):
    """Последняя запись суток ноды -> (сутки, когда заведена) или (None, None). Запись без ts (старый state) —
    заведена в начале своих суток по Москве."""
    have = [d for d, x in days.items() if node in x]
    if not have:
        return None, None
    d = max(have, key=int)
    ts = days[d][node].get("ts")
    return d, ts if _num(ts) else int(d) * 86400 - 3 * 3600


def ip_api(ips):
    """{адрес: {"hosting": bool, "mobile": bool, "as": str}} по ip-api.com пачками по 100 (без ключа: 15 в минуту)."""
    out = {}
    ips = list(ips)
    for i in range(0, len(ips), 100):
        part = ips[i:i + 100]
        req = urllib.request.Request("http://ip-api.com/batch?fields=query,status,as,hosting,mobile",
                                     data=json.dumps(part).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                for x in json.load(r):
                    if x.get("status") == "success":
                        out[x["query"]] = {"hosting": bool(x.get("hosting")), "mobile": bool(x.get("mobile")),
                                           "as": (x.get("as") or "")[:60]}
        except Exception:
            pass   # нет ответа — спросим в следующий раз
        if i + 100 < len(ips):
            time.sleep(5)
    return out


def step(state, beacons, own, now, lookup=ip_api, clients_of=None, clients_unknown=False, salt=None):
    """Один проход: обновить state (на месте). -> (адреса в списке, новых за проход).
    clients_of(адреса) -> множество тех, кто наш клиент (щиты нод), или (множество, ответили_все); None вместо
    множества — щиты не ответили. clients_of=None — не спрашивать (тесты).
    clients_unknown=True (или неполный ответ щитов) — новых адресов не вносить, внесённые не трогать (кроме исключений).
    salt — (соль, с какого времени) из load_salt; None — прочитать файл SALT."""
    keep = KEEP_DAYS * 86400
    if not isinstance(state.get("ips"), dict):   # повреждённый state — начинаем с пустого, а не падаем каждый проход
        state["ips"] = {}
    ips = state["ips"]
    salt, since = salt or load_salt(now)
    state.pop("salt", None)   # прежняя версия держала соль в state — теперь она в отдельном файле
    if state.get("salt_ts") != since or not isinstance(state.get("clients"), dict):
        state["clients"] = {}   # соль сменилась (старые хэши ни с чем не совпадут) или запись повреждена — сбрасываем
        state["salt_ts"] = since
    clients = state["clients"]   # {хэш адреса: когда последний раз оказался клиентом}
    for h in [h for h, t in clients.items() if not _num(t)]:
        del clients[h]
    _migrate(ips, clients, salt)
    never = scanlists.never_networks()
    today = day_of(now)

    def excluded(ip):
        return is_own(ip, own) or is_own(ip, never)

    def is_client(ip):
        return now - clients.get(client_hash(ip, salt), 0) <= keep

    # 1. стук: заменяем запись только тех нод, что ответили сейчас (второй проход видит те же стуки — не удваиваем;
    #    подтверждение ноды, чей маячок в этот раз не прочитался, не теряем). Маячок отдаёт стуки за 24 ч: новая
    #    запись суток ноды — только через NEW_DAY_GAP после прошлой (её ts), иначе обновляем прошлую — проходы в 23:00
    #    и в 04:20 следующих суток с теми же стуками остаются одними сутками
    for ip, v in aggregate(beacons).items():
        if excluded(ip) or is_client(ip) or not (suspicious(v) or ip in ips):
            continue
        e = ips.setdefault(ip, {"first": int(now)})
        days = e.setdefault("days", {})
        for node, rec in v["per"].items():
            d, ts = _last_record(days, node)
            if d is not None and 0 <= now - ts < NEW_DAY_GAP:   # ts из будущего (часы убегали) — не верим
                days[d][node] = dict(rec, ts=ts)
            else:
                days.setdefault(today, {})[node] = dict(rec, ts=int(now))
        e["last"] = int(now)
    # старые сутки — прочь; адрес без стуков за 30 дней — забыть
    for ip, e in list(ips.items()):
        e["days"] = {d: x for d, x in (e.get("days") or {}).items() if x and int(d) > int(today) - KEEP_DAYS}
        if not e["days"] or now - e.get("last", 0) > keep:
            del ips[ip]
    for h in [h for h, t in clients.items() if now - t > keep]:
        del clients[h]
    # 2. клиенты: спрашиваем обо всех, кто стучал сегодня, и обо всех внесённых (щит помнит клиента только сутки);
    #    найденного — сразу в хэш, его запись с адресом удалить
    asked = sorted((ip for ip, e in ips.items() if today in e["days"] or e.get("listed")), key=ip_key)
    if clients_of and asked:
        r = clients_of(asked)
        found, known = r if isinstance(r, tuple) else (r, r is not None)
        clients_unknown = clients_unknown or not known
        for ip in set(found or ()) & set(asked):
            clients[client_hash(ip, salt)] = int(now)
            ips.pop(ip, None)
    # 3. кто готов к списку: хотя бы в одних сутках 2+ нод и стук в 2+ разных сутках
    ready = {}
    for ip, e in ips.items():
        s = summary(e)
        if excluded(ip) or is_client(ip):
            continue
        if s["most"] >= MIN_NODES and s["days"] >= MIN_DAYS and suspicious(s):
            ready[ip] = s
    # 4. сведения ip-api (кэш 30 дней; в старом кэше нет mobile — спросить заново)
    need = [ip for ip in sorted(ready, key=ip_key) if now - ips[ip].get("looked", 0) > keep or "mobile" not in ips[ip]]
    info = lookup(need) if need else {}
    new = 0
    for ip, s in ready.items():
        e = ips[ip]
        if ip in info:
            e.update(info[ip], looked=int(now))
        e.update(nodes=sorted(s["nodes"]), ports=s["ports"], hits=s["hits"], strong=s["strong"])
        if "mobile" not in e:   # сведений нет (ip-api молчит) — подождём следующего прохода
            continue
        if e.get("mobile") or not (e.get("hosting") or s["ports"] >= MIN_PORTS_HOME):
            e["listed"] = False
            continue
        if not e.get("listed"):
            if clients_unknown:   # при сомнении не вносить
                continue
            new += 1
            e["listed"] = True
    for ip, e in ips.items():   # свой адрес, NEVER_LIST, клиент или не набравший правило мог попасть в список раньше
        if e.get("listed") and (excluded(ip) or is_client(ip) or ip not in ready):
            e["listed"] = False
    state["ts"] = int(now)
    listed = sorted((ip for ip, e in ips.items() if e.get("listed")), key=ip_key)
    return listed, new


def clients_via(hs, run_ctl):
    """clients_of для step: спросить щит каждого сервера кусками по CLIENTS_CHUNK. -> (клиенты, ответили ли все).
    Щиты разных серверов — параллельно, поток на сервер (как shieldbot.lookup_clients): по очереди 10 серверов по
    20 кусков ждали бы друг друга. Куски одному щиту — по очереди; щит отказал или молчит — остальные куски ему не
    шлём (каждый ждал бы таймаут ssh). Поток не закончил за CLIENTS_WAIT на кусок — щит считается не ответившим."""
    def clients_of(addrs):
        addrs = list(addrs)
        found, done, lock = set(), set(), threading.Lock()

        def ask(h):
            try:
                for i in range(0, len(addrs), CLIENTS_CHUNK):
                    r = run_ctl(h, ["clients"] + addrs[i:i + CLIENTS_CHUNK])
                    if not isinstance(r, dict) or r.get("ok") is not True:
                        return   # щит отказал или молчит — это не «клиентов нет»
                    with lock:
                        found.update((r.get("clients") or {}).keys())
                with lock:
                    done.add(h)
            except Exception:
                pass   # сбой опроса — тоже «не ответил»

        th = [threading.Thread(target=ask, args=(h,), daemon=True) for h in hs]
        for t in th:
            t.start()
        until = time.time() + CLIENTS_WAIT * max(1, -(-len(addrs) // CLIENTS_CHUNK))
        for t in th:
            t.join(max(0, until - time.time()))
        with lock:   # нет ни одного щита (ddos.json не прочитался) — тоже «неизвестно»
            return set(found), bool(hs) and all(h in done for h in hs)
    return clients_of


def with_knocks(beacons):
    """Сколько маячков со стуками: пустой knocks (нет ufw.log или rsyslog) — не в счёт."""
    return sum(1 for b in beacons.values() if isinstance(b, dict) and isinstance(b.get("knocks"), list) and b["knocks"])


def load_state(path=None):
    """behavior.json -> dict. Не читается, не JSON или не словарь — начинаем с пустого (ips не словарь чинит step)."""
    try:
        state = json.load(open(path or STATE, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def list_text(listed):
    """Строки behavior.list: IPv4 — /32, IPv6 — /64 (ключ IPv6 в state — уже адрес сети /64)."""
    return "".join("%s/%d\n" % (ip, 64 if ":" in ip else 32) for ip in listed)


def main(argv):
    import nodewatch
    import shieldbot
    import probe
    dry = "--dry" in argv
    nodes = json.load(open(os.path.join(ETC, "nodes.json"), encoding="utf-8"))
    beacons = {n["name"]: nodewatch.fetch_beacon(n["beacon"]) for n in nodes if n.get("beacon")}
    got = with_knocks(beacons)
    hs = shieldbot.hosts()
    unresolved = []
    own = scanlists.own_networks(hs.values(), failed=unresolved) + scanlists.parse(
        scanlists.read(os.path.join(ETC, "scanners-exclude.txt")), wide=True)[0]
    state = load_state()
    asked = {}

    def clients_of(addrs):
        found, known = clients_via(hs, lambda h, a: shieldbot.run_ctl(h, a, hs))(addrs)
        asked["known"] = known
        return found, known

    now = time.time()
    listed, new = step(state, beacons, own, now, clients_of=clients_of, salt=load_salt(now, save=not dry))
    msg = "behavscan: маячков со стуками %d из %d, в списке %d адресов, новых %d, клиентов отсеяно %d" % (
        got, len(beacons), len(listed), new, len(state.get("clients", {})))
    if asked.get("known") is False:
        msg += "; щиты ответили не все — новых не вносил"
    if unresolved:
        msg += "; имён не разрешилось %d" % len(unresolved)
    print(msg)
    if dry:
        return 0
    with open(STATE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(STATE + ".tmp", STATE)
    scanlists.write(os.path.join(DIR, scanlists.BEHAVIOR + ".list"), list_text(listed))
    probe.log(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
