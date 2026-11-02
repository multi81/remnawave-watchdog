"""channel-watch: блокировки глазами сторожа — часть probe.py, вынесенная в отдельный файл.

Логика взята из открытого описания cheburcheck.ru (https://cheburcheck.ru/kb/faq), источники — те же:
1. Списки (probe.py --lists, раз в 6 часов): адреса и домены наших серверов сверяются с реестром РКН
   (antifilter.download, antifilter.network) и с подсетями CDN и хостеров, которые в России душат «после 16–20 КБ»
   (github.com/123jjck/cdn-ip-ranges). Списки скачиваются сюда и сверяются на месте — наши адреса никуда не уходят.
2. Подмена DNS (раз в DNS_EVERY): ответ обычного DNS по UDP сравнивается с ответом по защищённому DNS (DoH).
3. Разбор сбоя канала: нода проверяется напрямую с rf1 и с других российских точек (агенты vantage_agent.py),
   из-за рубежа (через чужой канал) и трассировкой — чтобы отличить блокировку от поломки ноды.
4. Заглушка под внешний сервис с добровольными сканерами в сетях операторов — ВЫКЛЮЧЕНА (см. external_scan).
"""
import concurrent.futures
import html
import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import netprobe
import nodewatch

ETC = "/etc/channel-watch"
LISTS_FILE = "/var/lib/channel-watch/lists.json"
LISTS_DIR = "/var/lib/channel-watch/lists"
LISTS_STALE = 14 * 3600     # списки обновляются раз в 6 часов; старше — сказать в отчёте
DNS_EVERY = 1800            # секунд между проверками подмены DNS
DNS_MIN = 2                 # столько независимых ответов должны разойтись с защищённым DNS, чтобы считать подменой
DEEP_MAX = 3                # за один запуск подробно разбираем не больше стольких каналов
LOSS_FILE = "/var/lib/channel-watch/loss.json"
SIDE_FILE = "/var/lib/channel-watch/side.json"  # профиль точек и гео нод (probe.py --side, свой таймер)
PROFILE_TRIES = 3           # попыток профиля точки за один сбор
VPN_EVERY = 3600            # секунд между обходами плиток через VPN-точки (служба --side)
PROFILE_GAP = 60            # секунд между попытками
# список профиля для самого rf1 — тот же, что DEFAULT_PROFILE у агентов (проверка ZL47 следит, чтобы не разошлись)
PROFILE_LOCAL = {"sites": [["blocked", "rutracker.org"], ["blocked", "www.instagram.com"], ["blocked", "www.facebook.com"],
                           ["control", "www.example.org"], ["control", "ya.ru"]],
                 "loads": [["cloudflare", "https://speed.cloudflare.com/__down?bytes=300000", None],
                           ["ovh", "https://proof.ovh.net/files/1Mb.dat", "0-299999"],
                           ["hetzner", "https://fsn1-speed.hetzner.com/100MB.bin", "0-299999"]]}
LOSS_N = 30                 # соединений в одном фоновом замере: с одной точки на вход одной ноды
LOSS_BAD = 3                # не прошло столько и больше (10 %) — «потери»
LOSS_CONFIRM = 2            # столько замеров подряд нужно, чтобы сказать о потерях и об их конце
LOSS_STALE = 3 * 3600       # замер старше — в отчёт не идёт
DEEP_SERIES = 6             # соединений с каждой точки при разборе сбоя
WITNESS_LAG = 10            # столько после серии нода ещё дописывает счётчики (повторы своих ответов)
WITNESS_WAIT = 16           # дольше этого за один раз счётчиков ноды не ждём
SELF = "rf1"                # так в сообщениях называется сам сервер сторожа
VANTAGE = "vantage.json"    # точки проверки в РФ: [{"name", "url", "token"}]
EXTERNAL = "external.json"  # внешний сервис проверки блокировок: {"enabled": false, ...}

# ключ, откуда, что внутри, hard — тревога сразу / soft — только в сводке за неделю
SOURCES = (
    ("rkn_ip", "https://antifilter.download/list/ip.lst", "ip", "hard"),
    ("rkn_net", "https://antifilter.download/list/subnet.lst", "ip", "hard"),
    ("rkn_ip2", "https://antifilter.network/download/ip.lst", "ip", "hard"),
    ("rkn_net2", "https://antifilter.network/download/subnet.lst", "ip", "hard"),
    ("rkn_dom", "https://antifilter.download/list/domains.lst", "domain", "hard"),
    ("cdn", "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/all/all_plain_ipv4.txt", "ip", "hard"),
)
KIND = {key: (what, level) for key, _, what, level in SOURCES}
LIST_NAMES = {"rkn_ip": "реестр РКН, адреса", "rkn_net": "реестр РКН, подсети", "rkn_ip2": "реестр РКН, адреса",
              "rkn_net2": "реестр РКН, подсети", "rkn_dom": "реестр РКН, домены",
              "cdn": "подсети CDN и хостеров, которые в России душат"}
MAX_LIST = 120 * 1024 * 1024
SITE_LABELS = {"panel": "панель", "sub": "подписка", "cab": "кабинет", "admin": "админка"}
RESOLVERS = (("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Яндекс", "77.88.8.8"), ("Quad9", "9.9.9.9"))
DOH = ("https://dns.google/resolve?name={}&type=A", "https://cloudflare-dns.com/dns-query?name={}&type=A")


def read_etc(name, default):
    try:
        return json.load(open(os.path.join(ETC, name), encoding="utf-8"))
    except (OSError, ValueError):
        return default


# ---------- 1. списки ----------

def fetch(url, dest, socks_port=None):
    """Скачать список в файл; не вышло напрямую — через канал сторожа. True — файл на месте и не пустой."""
    for port in (None, socks_port) if socks_port else (None,):
        cmd = ["curl", "-sL", "-m", "150", "--max-filesize", str(MAX_LIST), "-o", dest + ".tmp", url]
        if port:
            cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{port}"]
        try:
            ok = subprocess.run(cmd, capture_output=True, timeout=170).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            ok = False
        if ok and os.path.exists(dest + ".tmp") and os.path.getsize(dest + ".tmp") > 50:
            os.replace(dest + ".tmp", dest)
            return True
    try:
        os.remove(dest + ".tmp")
    except OSError:
        pass
    return False


def load_nets(path):
    """Список адресов и подсетей IPv4 -> (подсети /24 и мельче по первым трём числам, подсети крупнее, сколько записей)."""
    small, big, n = {}, [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s[0] in "#;":
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            n += 1
            if net.prefixlen >= 24:
                small.setdefault(int(net.network_address) >> 8, []).append(net)
            else:
                big.append(net)
    return small, big, n


def ip_match(index, ip):
    """В какую запись списка попадает адрес: строка с подсетью либо None."""
    small, big, _ = index
    a = ipaddress.ip_address(ip)
    for net in small.get(int(a) >> 8, []) + big:
        if a in net:
            return str(net)
    return None


def scan_domains(path, names, bases):
    """Список доменов (он большой — читаем построчно): ({запись списка: она же}, сколько записей). Совпадение —
    любое наше имя, наш основной домен (тогда закрыты все имена на нём) или любой поддомен основного домена."""
    hits, n = {}, 0
    names = {x.lower() for x in names} | set(bases)
    tails = tuple("." + b for b in bases)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            d = line.strip().strip('"').lower().rstrip(".")
            if not d or "." not in d:
                continue
            n += 1
            if d in names or d.endswith(tails):
                hits[d] = d
    return hits, n


def targets(chans, nodes, site_hosts, bases, resolve=socket.gethostbyname):
    """Что сверяем: {"ips": {адрес: кто это}, "names": {имя: кто это}}. Имена нод — из nodes.json, входы-адреса
    (ретрансляторы) — из каналов, сайты владельца — из списка сайтов."""
    ips, names = {}, {}
    for n in nodes:
        names[n["host"]] = n["name"]
    for h in site_hosts:
        names[h] = SITE_LABELS.get(h.split(".")[0], h.split(".")[0])
    for name, who in list(names.items()):
        try:
            ips.setdefault(resolve(name), who)
        except OSError:
            pass
    for c in chans:
        entry = str(c.get("entry") or "")
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            continue
        ips.setdefault(entry, "вход «" + " ".join(c["name"].replace("🌐", " ").replace("🔄", " ").replace("|", " ").split()) + "»")
    for b in bases:
        names.setdefault(b, b)
    return {"ips": ips, "names": names}


def lists_run(tg, bases, socks_port=None, work=None, sources=SOURCES, fetcher=fetch):
    """Скачать списки и сверить: {"ts", "sources": {ключ: {"ok", "n"}}, "hits": {ключ: {кто: запись списка}}, "targets"}."""
    work = work or LISTS_DIR
    os.makedirs(work, exist_ok=True)
    out = {"ts": int(time.time()), "sources": {}, "hits": {}, "neighbours": {},
           "targets": {"ips": len(tg["ips"]), "names": len(tg["names"])}}
    for key, url, what, _ in sources:
        path = os.path.join(work, key + ".lst")
        ok = fetcher(url, path, socks_port)
        hits, n = {}, 0
        if ok:
            try:
                if what == "ip":
                    index = load_nets(path)
                    n = index[2]
                    for ip, who in tg["ips"].items():
                        m = ip_match(index, ip)
                        if m:
                            hits[f"{who} ({ip})"] = m
                        if key == "rkn_ip":
                            # чужие адреса из реестра в той же подсети /24: нам они не мешают, но показывают,
                            # что подсеть хостера «на заметке»
                            a = ipaddress.ip_address(ip)
                            near = sum(1 for net in index[0].get(int(a) >> 8, []) if a not in net)
                            if near:
                                out["neighbours"][f"{who} ({ip})"] = near
                else:
                    found, n = scan_domains(path, tg["names"], bases)
                    hits = {(f"{tg['names'][d]} ({d})" if tg["names"].get(d, d) != d else d): d for d in found}
            except OSError:
                ok = False
            try:
                os.remove(path)  # списки большие (домены — 32 МБ), на диске ноды их не держим
            except OSError:
                pass
        out["sources"][key] = {"ok": bool(ok and n), "n": n}
        out["hits"][key] = hits
    return out


def lists_step(st, data):
    """Свежая сверка -> состояние сторожа. Возвращает оповещения: кто появился в «жёстких» списках и кто из них ушёл.
    Если список не скачался, прошлые совпадения по нему остаются как были — молчание источника не значит «чисто»."""
    prev = st.get("lists") or {}
    old = prev.get("hits", {})
    merged = {}
    for key in KIND:
        src = data["sources"].get(key, {})
        merged[key] = data["hits"].get(key, {}) if src.get("ok") else old.get(key, {})
    alerts = []
    for key, (_, level) in KIND.items():
        if level != "hard":
            continue
        was, cur = old.get(key, {}), merged[key]
        for who, rec in cur.items():
            if who not in was:
                alerts.append(list_alert(key, who, rec))
        alerts += [f"✅ <b>Больше нет в списке блокировок: {html.escape(who)}</b> — {LIST_NAMES[key]}."
                   for who in was if who not in cur]
    near = data.get("neighbours", {}) if data["sources"].get("rkn_ip", {}).get("ok") else prev.get("neighbours", {})
    st["lists"] = {"ts": data["ts"], "hits": merged, "sources": data["sources"], "targets": data["targets"],
                   "neighbours": near}
    return alerts


def list_alert(key, who, rec):
    head = f"🚫 <b>В списке блокировок: {html.escape(who)}</b>\n{LIST_NAMES[key].capitalize()}: запись {html.escape(rec)}.\n"
    if key == "cdn":
        return head + ("<b>Что это значит:</b> адрес стоит в подсети хостера, соединения с которой в России обрывают "
                       "после 16–20 КБ. Плитка может подключаться, но сайты через неё грузиться не будут — "
                       "сторож покажет это как «душат».")
    if key == "rkn_dom":
        return head + ("<b>Что это значит:</b> домен внесён в реестр — операторы в России обязаны его блокировать. "
                       "Плитки и сайты на этом имени перестанут открываться у пользователей; нужен другой домен.")
    return head + ("<b>Что это значит:</b> адрес внесён в реестр — операторы в России обязаны его блокировать. "
                   "Плитка перестанет подключаться у части или у всех пользователей; готовьте замену адреса.")


def hard_hits(st):
    """[(кто, название списка)] по «жёстким» спискам."""
    hits = (st.get("lists") or {}).get("hits", {})
    return [(who, LIST_NAMES[key]) for key, (_, level) in KIND.items() if level == "hard" for who in hits.get(key, {})]


def near_hits(st):
    """[(кто, сколько)] — рядом с какими нашими адресами (в той же подсети /24) в реестре есть чужие адреса."""
    return sorted(((st.get("lists") or {}).get("neighbours") or {}).items())


# ---------- 2. подмена DNS ----------

def doh(name, socks_port=None):
    """Адреса имени по защищённому DNS (DoH, JSON) — напрямую или через канал сторожа; None — не ответили."""
    found = None
    for tpl in DOH:
        cmd = ["curl", "-s", "-m", "8", "-H", "accept: application/dns-json", tpl.format(urllib.parse.quote(name))]
        if socks_port:
            cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{socks_port}"]
        try:
            data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=12).stdout)
        except (ValueError, subprocess.TimeoutExpired, OSError):
            continue
        if data.get("Status") not in (0, 3):
            continue
        ips = {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}
        found = (found or set()) | ips
    return found


def dns_truth(name, socks_port):
    """Чему верим: всё, что отдал защищённый DNS напрямую и через зарубежный канал; None — спросить не удалось."""
    parts = [x for x in (doh(name), doh(name, socks_port) if socks_port else None) if x is not None]
    return set().union(*parts) if parts else None


def dns_observe(name, agents=()):
    """Что отвечает обычный DNS: {кто: (итог, [адреса])} — системный резолвер rf1, публичные резолверы по UDP,
    и то же самое с точек проверки."""
    seen = {"rf1: системный": netprobe.resolve_system(name)}
    for who, ip in RESOLVERS:
        seen[f"rf1: {who}"] = netprobe.dns_udp(name, ip)
    for a in agents:
        data = agent_get(a, "/dns?name=" + urllib.parse.quote(name), 12)
        if not data:
            continue
        seen[f"{a['name']}: системный"] = tuple(data.get("system") or ("err", []))
        for who, res in (data.get("udp") or {}).items():
            seen[f"{a['name']}: {who}"] = tuple(res)
    return seen


def dns_judge(truth, seen):
    """Кто из наблюдателей отвечает не то, что защищённый DNS: [(кто, что ответил)]."""
    if not truth:
        return []
    odd = []
    for who, (status, ips) in sorted(seen.items()):
        if status == "nx":
            odd.append((who, "такого имени нет"))
        elif status == "ok" and ips and not set(ips) <= truth:
            odd.append((who, ", ".join(ips)))
    return odd


def dns_check(names, socks_port, agents=()):
    """{имя: {"truth": [адреса], "odd": [[кто, что]], "asked": сколько ответов}}; имя без ответа DoH пропускается."""
    out = {}

    def one(name):
        truth = dns_truth(name, socks_port)
        if truth is None:
            return name, None
        seen = dns_observe(name, agents)
        system = {who.split(": ")[0]: st for who, (st, _) in seen.items() if who.endswith(": системный")}
        return name, {"truth": sorted(truth), "odd": [list(x) for x in dns_judge(truth, seen)],
                      "asked": sum(1 for s, _ in seen.values() if s != "err"), "system": system}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for name, res in ex.map(one, names):
            if res is not None:
                out[name] = res
    return out


def dns_points(dns, agents):
    """По проверке DNS: у каких точек свой (системный) DNS не нашёл наши имена — {точка: (не нашёл, всего)}."""
    out = {}
    for point in ["rf1"] + [a["name"] for a in agents]:
        total = failed = 0
        for res in dns.values():
            st = (res.get("system") or {}).get(point)
            if st is None:
                continue
            total += 1
            failed += st != "ok"
        if total:
            out[point] = (failed, total)
    return out


def dns_point_text(point, lvl, failed, total):
    if lvl == "bad":
        return (f"🧭 <b>У точки «{html.escape(point)}» свой DNS не находит наши имена</b>\nНе нашлось {failed} из {total} "
                "(сайты и ноды), а публичный DNS их находит. Проверки с этой точки идут через публичный DNS.\n"
                "<b>Для пользователей:</b> у клиентов с DNS этого провайдера приложение может не найти сервер по имени.")
    return f"✅ <b>У точки «{html.escape(point)}» свой DNS снова находит наши имена</b>"


def dns_alert(name, res, lvl):
    if lvl == "ok":
        return f"✅ <b>DNS снова отвечает верно: {html.escape(name)}</b> — {html.escape(', '.join(res['truth']))}."
    odd = "\n".join(f"• {who}: {what}" for who, what in res["odd"])
    return (f"🧭 <b>Подмена DNS: {html.escape(name)}</b>\nПо защищённому DNS адрес — "
            f"{html.escape(', '.join(res['truth']) or 'нет записи')}, а обычный DNS отвечает иначе:\n{html.escape(odd)}\n"
            "<b>Похоже на:</b> оператор или его DNS подменяет ответ — так блокируют по имени. Если адрес недавно меняли "
            "вы сами, это может быть устаревший ответ и пройдёт само.\n"
            "<b>Для пользователей:</b> у кого DNS оператора — приложение не найдёт сервер по этому имени.")


# ---------- 3. точки проверки и разбор сбоя ----------

def agents_cfg():
    return [a for a in read_etc(VANTAGE, []) if a.get("url") and a.get("token") and a.get("name")]


def add_vantage(text):
    """Добавить точку проверки в vantage.json (probe.py --add-vantage): text — запись, которую печатает
    vantage_install.sh --entry. Точка с тем же названием заменяется. Возвращает названия всех точек."""
    new = json.loads(text)
    if not (isinstance(new, dict) and all(isinstance(new.get(k), str) and new[k] for k in ("name", "url", "token"))):
        raise ValueError("запись точки проверки не того вида: нужны name, url и token")
    path = os.path.join(ETC, VANTAGE)
    items = [a for a in read_etc(VANTAGE, []) if a.get("name") != new["name"]] + [new]
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    os.replace(path + ".tmp", path)
    return [a["name"] for a in items]


def agent_get(agent, path, timeout=20):
    """Запрос к агенту точки проверки; None — не ответил или ответил не тем."""
    try:
        req = urllib.request.Request(agent["url"].rstrip("/") + path, headers={"X-Token": agent["token"]})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(65536).decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # сеть, отказ, не JSON — для сторожа одно и то же: «точка не ответила»
        return None


def agents_health(agents):
    return {a["name"]: bool((agent_get(a, "/health", 8) or {}).get("ok")) for a in agents}


def vpn_points(agents):
    """Точки, где стоит свой клиент Xray (в vantage.json у точки "vpn": true)."""
    return [a for a in agents if a.get("vpn")]


def vpn_sweep(agents, names):
    """Все плитки через каждую VPN-точку, по очереди (одна загрузка за раз): {точка: {плитка: ответ | None}}."""
    out = {}
    for a in vpn_points(agents):
        out[a["name"]] = {n: agent_get(a, "/vpn?name=" + urllib.parse.quote(n), 40) for n in names}
    return out


def vpn_text(r):
    """Ответ /vpn одной фразой."""
    if not r:
        return "точка не ответила"
    if r.get("ok"):
        return f"работает ({r['bytes'] // 1024} КБ за {r['s']} с, {r['mbit']} Мбит/с)"
    if r.get("bytes"):
        return f"не работает: пришло {r['bytes'] // 1024} КБ из 512"
    return "не работает" + (f" (код {r['code']})" if r.get("code") not in (None, "000") else "")


VPN_CONFIRM = 2             # столько обходов подряд плитка не работает через VPN-точку — сообщение


def vpn_step(st, data, chan_ok):
    """Тревоги VPN-точки по очередному обходу. data — {точка: {плитка: ответ /vpn | None}}; chan_ok — {плитка: True,
    если с rf1 она сейчас работает}. Через точку прошло меньше половины плиток — беда у самой точки: плитки не судим,
    о точке — одно сообщение после VPN_CONFIRM таких обходов. Плитка не работает через точку VPN_CONFIRM обходов подряд,
    а с rf1 работает — сообщение (если не работает и с rf1 — об этом уже пишет основной сторож)."""
    vs = st.setdefault("vpn_alert", {})
    msgs = []
    for point, res in sorted(data.items()):
        p = vs.setdefault(point, {"bad_n": 0, "point_alerted": False, "tiles": {}})
        good = [n for n, r in res.items() if r and r.get("ok")]
        pn = html.escape(point)
        if not res or len(good) * 2 < len(res):
            p["bad_n"] += 1
            if p["bad_n"] >= VPN_CONFIRM and not p["point_alerted"]:
                p["point_alerted"] = True
                msgs.append(f"📍 <b>VPN-точка {pn} не проверяет плитки</b>\nДва обхода подряд через неё прошло "
                            f"{len(good)} из {len(res)} плиток — похоже, беда у самой точки (её сеть или клиент Xray), "
                            "а не у плиток. Пока не наладится, плитки по ней не сужу.")
            continue
        if p["point_alerted"]:
            msgs.append(f"✅ <b>VPN-точка {pn} снова проверяет плитки</b>\nЧерез неё прошло {len(good)} из {len(res)}.")
        p["bad_n"], p["point_alerted"] = 0, False
        for tile, r in sorted(res.items()):
            t = p["tiles"].setdefault(tile, {"n": 0, "alerted": False})
            name = html.escape(clean(tile))
            if r and r.get("ok"):
                if t["alerted"]:
                    msgs.append(f"✅ <b>Через VPN с точки {pn} снова работает: {name}</b>")
                t.update(n=0, alerted=False)
                continue
            t["n"] += 1
            if t["n"] >= VPN_CONFIRM and not t["alerted"] and chan_ok.get(tile):
                t["alerted"] = True
                msgs.append(f"🛰 <b>Через VPN с точки {pn} не работает: {name}</b>\n{html.escape(vpn_text(r))} — "
                            f"{VPN_CONFIRM} обхода подряд, а с rf1 плитка работает.\n<b>Похоже на:</b> плитку режут у "
                            "провайдера этой точки — пользователи с таким провайдером могут не подключиться.")
    return msgs


def vpn_line(st):
    """Строка обычного отчёта: сколько плиток работает через VPN с каждой VPN-точки."""
    by = (st.get("vpn_pt") or {}).get("by") or {}
    parts = []
    for point, res in sorted(by.items()):
        ask = {n: r for n, r in res.items() if r is not None}
        if not ask:
            parts.append(f"через VPN с точки {point}: точка не ответила")
            continue
        bad = sorted(clean(n) for n, r in ask.items() if not r.get("ok"))
        parts.append(f"через VPN с точки {point}: работают {len(ask) - len(bad)} из {len(ask)}"
                     + (f" (не работают: {', '.join(bad)})" if bad else ""))
    return "; ".join(parts) or None


def profile_merge(runs):
    """Несколько ответов /profile одной точки → сводный профиль: по каждому сайту — сколько раз ответил с настоящим
    именем и с нейтральным; по каждой загрузке — сколько раз качнулось и средняя (медиана) скорость."""
    sites, loads = {}, {}
    for r in runs:
        for s in r.get("sites", []):
            v = sites.setdefault(s["host"], {"kind": s["kind"], "host": s["host"], "addr": s.get("addr"), "n": 0,
                                             "real_ok": 0, "neutral_ok": 0, "fails": {}})
            v["n"] += 1
            v["addr"] = v["addr"] or s.get("addr")
            v["real_ok"] += s.get("real") == "answer"
            v["neutral_ok"] += s.get("neutral") == "answer"
            if s.get("real") != "answer":
                v["fails"][s.get("real") or "?"] = v["fails"].get(s.get("real") or "?", 0) + 1
        for d in r.get("loads", []):
            v = loads.setdefault(d["name"], {"name": d["name"], "n": 0, "ok": 0, "speeds": []})
            v["n"] += 1
            if d.get("bytes") and d.get("mbit") is not None:
                v["ok"] += 1
                v["speeds"].append(d["mbit"])
    for v in loads.values():
        sp = sorted(v.pop("speeds"))
        v["mbit"] = sp[len(sp) // 2] if sp else None
    return {"sites": list(sites.values()), "loads": list(loads.values()), "tries": len(runs)}


def profile_fetch(agents, tries=PROFILE_TRIES, gap=PROFILE_GAP, local=None):
    """Профиль rf1 и каждой точки: tries попыток через gap секунд, в каждой — все точки разом. {точка: сводный}."""
    local = local or (lambda: netprobe.profile_run(PROFILE_LOCAL["sites"], PROFILE_LOCAL["loads"]))
    runs = {}
    for t in range(tries):
        if t:
            time.sleep(gap)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents) + 1) as ex:
            fut = {a["name"]: ex.submit(agent_get, a, "/profile", 150) for a in agents}
            fut["rf1"] = ex.submit(local)
            for name, f in fut.items():
                try:
                    r = f.result()
                except Exception:  # noqa: BLE001 — одна точка не должна сорвать сбор остальных
                    r = None
                if r and isinstance(r.get("sites"), list):
                    runs.setdefault(name, []).append(r)
    return {name: profile_merge(rs) for name, rs in runs.items()}


def site_cut(s):
    """Сайт режут по имени: с настоящим именем не ответил ни разу, с нейтральным — хотя бы два раза (и не меньше
    половины попыток). Нужны минимум две попытки."""
    return (s["kind"] == "blocked" and s.get("n", 0) >= 2 and s["real_ok"] == 0
            and s["neutral_ok"] >= max(2, (s["n"] + 1) // 2))


def profile_verdict(prof):
    """filtered — хотя бы один заблокированный сайт режут по имени; clear — нет, и сайты отвечали; unknown — не
    определить (сайты не отвечали ни так, ни так, или старый формат с одним замером)."""
    sites = prof.get("sites", [])
    if not sites or any("n" not in s for s in sites):
        return "unknown"
    if any(site_cut(s) for s in sites):
        return "filtered"
    return "clear" if any(s["real_ok"] or s["neutral_ok"] for s in sites) else "unknown"


def profile_text(point, prof):
    """Профиль одной точки одной строкой (журнал, сводка)."""
    verd = {"filtered": "за фильтром — режут по имени", "clear": "фильтра по имени не видно",
            "unknown": "не определить"}[profile_verdict(prof)]
    sites = [s for s in prof.get("sites", []) if "n" in s]
    cut = ", ".join(f"{s['host']} (с именем {s['real_ok']} из {s['n']}, с нейтральным {s['neutral_ok']} из {s['n']})"
                    for s in sites if site_cut(s))
    odd = ", ".join(f"{s['host']} с именем {s['real_ok']} из {s['n']}" for s in sites
                    if s["kind"] == "blocked" and not site_cut(s) and 0 < s["n"] - s["real_ok"])
    loads = ", ".join((f"{d['name']} {d['mbit']}" if d["ok"] else f"{d['name']} не качается")
                      + (f" ({d['ok']} из {d['n']})" if 0 < d["ok"] < d["n"] else "") for d in prof.get("loads", []))
    return (f"{point}: {verd}" + (f": {cut}" if cut else "") + (f"; неровно: {odd}" if odd else "")
            + (f"; загрузка, Мбит/с: {loads}" if loads else "") + f" [попыток {prof.get('tries', 1)}]")


def profiles_line(st):
    """Строка обычного отчёта: сколько точек за фильтром."""
    prof = (st.get("profiles") or {}).get("by") or {}
    if not prof:
        return None
    verd = {p: profile_verdict(pr) for p, pr in prof.items()}
    filt = sorted(p for p, v in verd.items() if v == "filtered")
    clear = sum(v == "clear" for v in verd.values())
    if filt:
        return "ℹ️ за фильтром точки: " + ", ".join(filt)
    return f"точки без фильтра по имени ({clear})" if clear else None


TLS_SHIFT = 30              # метка приветствия TLS точки № i = метка её серии + TLS_SHIFT
DEEP_EXTRA_LIVE = True      # путь от точек, «закрыто ли имя», сброс TLS по свидетелю, ответ VPN-точки — и в сообщения


def tls_mss(i):
    """Метка приветствия TLS с настоящим именем для точки № i (0 — сам сторож)."""
    return point_mss(i) + TLS_SHIFT


def point_mss(i):
    """Метка серии соединений для точки № i (0 — сам сторож): по ней нода отличает серии разных точек."""
    return netprobe.MSS_MARK[0] + 2 * i


def agent_bundle(agent, i, query):
    """Всё, что точка проверки делает при разборе: проверка входа, серия соединений, сравнение имён (с меткой). Если
    вход с точки закрыт — ещё путь до ноды и «закрыто ли имя», параллельно с серией (у агента шесть мест).
    (вход, серия, имена, путь, имя на чужом сервере); старый агент на новое не отвечает — там None."""
    probe = agent_get(agent, "/probe?" + query, 25)
    closed = bool(probe and probe.get("tcp") in ("timeout", "refused"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        f_more = ex.submit(lambda: (agent_get(agent, "/path?" + query, 30),
                                    agent_get(agent, "/sniref?" + query, 30))) if closed else None
        ser = agent_get(agent, f"/series?{query}&n={DEEP_SERIES}&mss={point_mss(i)}", 30)
        if probe and probe.get("tcp") == "timeout" and ser and ser.get("ok"):
            probe = agent_get(agent, "/probe?" + query, 25) or probe  # одиночная проверка попала на потерянное соединение
        cmp_ = agent_get(agent, f"/sni?{query}&mss={tls_mss(i)}", 30)
        path, ref = f_more.result() if f_more else (None, None)
    return probe, ser, cmp_, path, ref


def deep_diag(ch, via, agents, bases):
    """Канал не работает: посмотреть на его вход напрямую с rf1, с других российских точек, из-за рубежа и трассировкой.
    С каждой точки: проверка входа (порт, TLS, 64 КБ), серия из DEEP_SERIES соединений и сравнение имён TLS.
    via — живой зарубежный канал ({"name", "port"}) либо None."""
    host, port = ch.get("entry"), int(ch.get("entry_port") or 443)
    sni = ch.get("sni") or host
    own = str(host).endswith(tuple("." + b for b in bases)) and sni == host
    query = f"host={urllib.parse.quote(str(host))}&port={port}" + ("" if sni == host else f"&sni={urllib.parse.quote(sni)}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents) + 6) as ex:
        f_direct = ex.submit(netprobe.direct_probe, host, port, sni)
        f_series = ex.submit(netprobe.series, host, port, DEEP_SERIES, point_mss(0))
        f_sni = ex.submit(netprobe.sni_compare, host, port, sni, tls_mss(0))
        f_agents = {a["name"]: ex.submit(agent_bundle, a, i + 1, query) for i, a in enumerate(agents)}
        f_abroad = (ex.submit(nodewatch.socks_open, via["port"], host, port, 5, ch.get("security") in ("reality", "tls"))
                    if via else None)
        direct, series, names = f_direct.result(), {SELF: f_series.result()}, {SELF: f_sni.result()}
        if direct["tcp"] == "timeout" and (series[SELF] or {}).get("ok"):
            direct = netprobe.direct_probe(host, port, sni)  # одиночная проверка попала на потерянное соединение
        f_ref = ex.submit(netprobe.name_ref, sni) if direct["tcp"] in ("timeout", "refused") else None
        f_vpn = {a["name"]: ex.submit(agent_get, a, "/vpn?name=" + urllib.parse.quote(ch["name"]), 40)
                 for a in vpn_points(agents)}
        probes, paths, refs = {}, {}, {}
        for name, f in f_agents.items():
            probe, ser, cmp_, path, ref = f.result()
            if probe is None and not own:
                continue  # адрес вне наших доменов этой точке не разрешён — она не «не ответила», её не спрашивали
            probes[name], series[name], names[name] = probe, ser, cmp_
            if path:
                paths[name] = path
            if ref:
                refs[name] = ref
        if f_ref is not None and f_ref.result():
            refs[SELF] = f_ref.result()
        f_trace = ex.submit(netprobe.tcp_trace, direct["addr"], port) if direct["addr"] and direct["tcp"] != "open" else None
        d = {"direct": direct, "agents": probes, "series": series, "sni": names,
             "abroad": f_abroad.result() if f_abroad else None, "via": via["name"] if via else None,
             "trace": f_trace.result() if f_trace else None, "external": external_scan({"host": host, "addr": direct["addr"]}),
             "paths": paths, "refs": refs, "vpn": {n: f.result() for n, f in f_vpn.items()}}
    # что из этих серий видела сама нода (её счётчики лежат рядом с маячком; забираем и через живой чужой канал)
    beacon = next((n.get("beacon") for n in read_etc("nodes.json", []) if n.get("host") == host), None)
    tls = {f"{n}|tls": t for n, t in ((n, tls_ser(c)) for n, c in names.items()) if t}
    d["witness"] = witness_wait(witness_url(beacon), {**series, **tls}, via["port"] if via else None) if port == 443 else {}
    return d


def tls_ser(cmp_):
    """Приветствие TLS с настоящим именем, которое сбросили или закрыли, — как «серия из одного соединения» для
    сверки со свидетелем на ноде; None — сверять нечего (без метки или ответ пришёл)."""
    if not cmp_ or not cmp_.get("mss") or not cmp_.get("t1") or cmp_.get("real") not in ("reset", "closed"):
        return None
    return {"mss": cmp_["mss"], "t0": cmp_["t0"], "t1": cmp_["t1"], "n": 1, "ok": 1, "fail": 1}


# ---------- 3а. потери соединений: фоновый замер с точек и сверка с нодой ----------

def witness_url(beacon):
    """Где нода публикует счётчики помеченных соединений (node_witness.py): рядом с маячком, то же случайное имя."""
    if not beacon:
        return None
    head, _, tail = beacon.rpartition("/")
    if tail.startswith("st-"):
        return f"{head}/fw-{tail[3:]}"
    return f"{head}/flows.json" if tail == "state.json" else None


def fetch_witness(url, socks_port=None):
    """Счётчики ноды: {"ts", "flows": [[время, метка, SYN, SYN-ACK, RST от ноды, RST к ноде], ...]} либо None.
    Напрямую; не вышло и есть живой канал — через него (нода может быть закрыта из России)."""
    if not url:
        return None
    for port in (None, socks_port) if socks_port else (None,):
        cmd = ["curl", "-s", "-m", "10", "--max-filesize", "400000", "-H", "Cache-Control: no-cache", url]
        if port:
            cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{port}"]
        try:
            data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=14).stdout)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("flows"), list) and isinstance(data.get("ts"), (int, float)):
            return data
    return None


def witness_match(wit, ser, slack=20):
    """Что нода видела из серии ser (по метке и времени): {"seen" — сколько соединений дошло, "rep" — на скольких
    нода повторяла ответ (её ответ не дошёл обратно), "rst_out", "rst_in"}; None — сверить нечем."""
    if not wit or not ser or not ser.get("mss") or not ser.get("t1") or wit["ts"] < ser["t1"] + WITNESS_LAG:
        return None  # файл ноды записан раньше, чем нода досчитала эту серию
    if wit.get("since", 0) > ser["t0"]:
        return None  # свидетель на ноде запущен позже начала серии — целиком он её не видел
    rows = [f for f in wit["flows"] if len(f) >= 6 and f[1] == ser["mss"] and ser["t0"] - slack <= f[0] <= ser["t1"] + slack]
    if len(rows) < (ser.get("ok") or 0):
        return None  # нода насчитала меньше соединений, чем прошло успешно, — её счётчики неполны, судить по ним нельзя
    return {"seen": len(rows), "rep": sum(1 for f in rows if f[3] >= 3),
            "rst_out": sum(f[4] for f in rows), "rst_in": sum(f[5] for f in rows)}


def witness_text(ser, w):
    """Сверка серии с нодой одной фразой; None — сказать нечего."""
    if not w or not ser or not (ser.get("fail") or ser.get("refused")):
        return None
    n, seen = ser["n"], w["seen"]
    if ser.get("refused") and not w["rst_out"]:
        return (f"точка получила отказ в соединении ({ser['refused']} из {n}), а нода отказов не отправляла — "
                "соединение сбросил кто-то по дороге")
    if seen == 0:
        return f"до ноды не дошло ни одно из {n} соединений — запросы пропадают по дороге к ноде"
    if n - seen >= max(1, ser["fail"] // 2):
        return f"до ноды дошло {seen} из {n} — запросы теряются по дороге к ноде"
    if w["rep"] and not ser.get("ok"):
        return f"нода получила все {seen} и отвечала, но ни один ответ не дошёл обратно — закрыт обратный путь от ноды"
    if w["rep"]:
        return (f"нода получила все {seen} и ответила на каждое, но на {w['rep']} ответ не дошёл обратно — "
                "теряются ответы ноды на обратном пути")
    if w["rst_out"]:
        return f"нода получила {seen} из {n} и сама сбросила {w['rst_out']} — отказ на самой ноде"
    return f"нода получила {seen} из {n} и ответила — где теряется, по её счётчикам не видно"


def witness_wait(url, series, socks_port=None):
    """Дождаться счётчиков ноды по сериям, где что-то не прошло: {точка: сверка}. Нода пишет их раз в 10 секунд."""
    todo = {n: r for n, r in series.items() if r and r.get("mss") and (r.get("fail") or r.get("refused"))}
    if not url or not todo:
        return {}
    ready, got = max(r["t1"] for r in todo.values()) + WITNESS_LAG, {}
    for _ in range(3):
        delay = ready + 3 - time.time()
        if delay > 0 and WITNESS_WAIT:
            time.sleep(min(delay, WITNESS_WAIT))
        wit = fetch_witness(url, socks_port)
        got = {n: witness_match(wit, r) for n, r in todo.items()}
        if wit is None or all(got.values()):
            break  # нода счётчиков не публикует — либо всё сверено
        ready = time.time() + 6
    return {n: w for n, w in got.items() if w}


def loss_keep(r):
    """Из ответа серии — только то, что нужно хранить."""
    if not r or "n" not in r:
        return None
    return {k: r.get(k) for k in ("n", "ok", "fail", "slow", "refused", "ms", "t0", "t1", "mss", "dns")}


def loss_run(nodes, agents, n=LOSS_N, socks_port=None, local=netprobe.series, remote=None, wait=WITNESS_LAG + 14):
    """Фоновый замер: с сервера сторожа и с каждой точки — по n соединений на вход каждой ноды, затем сверка
    с тем, что видела сама нода. {"ts", "n", "points": [...], "nodes": {нода: {точка: серия | None}}}"""
    remote = remote or (lambda agent, host, mss: agent_get(agent, f"/series?host={urllib.parse.quote(host)}&port=443"
                                                           f"&n={n}&mss={mss}", n * 3 + 15))
    points = [(SELF, None)] + [(a["name"], a) for a in agents]

    def one(i, agent, node):
        mss = point_mss(i)
        return loss_keep(local(node["host"], 443, n, mss) if agent is None else remote(agent, node["host"], mss))

    def per_point(item):
        i, (_, agent) = item
        # с одной точки — по три ноды разом: у агента ограничено число одновременных проверок
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            return list(ex.map(lambda node: one(i, agent, node), nodes))

    out = {node["name"]: {} for node in nodes}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(points)) as ex:
        for (pname, _), rows in zip(points, ex.map(per_point, enumerate(points))):
            for node, r in zip(nodes, rows):
                out[node["name"]][pname] = r
    # сверка с нодой нужна только там, где что-то потерялось; нода пишет счётчики раз в 10 секунд
    lossy_nodes = [node for node in nodes if any(r and (r["fail"] or r["refused"]) for r in out[node["name"]].values())]
    if lossy_nodes and wait:
        time.sleep(wait)
    for node in lossy_nodes:
        wit = fetch_witness(witness_url(node.get("beacon")), socks_port)
        for r in out[node["name"]].values():
            w = witness_match(wit, r) if r and (r["fail"] or r["refused"]) else None
            if w:
                r["wit"] = w
    return {"ts": time.time(), "n": n, "points": [name for name, _ in points], "nodes": out}


def loss_judge(r):
    """Серия одним словом: 'bad' — частичные потери, 'ok' — потерь нет, None — судить не о чем (сервер недоступен
    целиком — это видно по каналу; точка не ответила; потерялось меньше порога)."""
    if not r or not r.get("ok"):
        return None
    if r["fail"] >= LOSS_BAD:
        return "bad"
    return "ok" if r["fail"] == 0 and r["n"] >= 10 else None


def loss_pct(r):
    return round(100.0 * r["fail"] / r["n"]) if r and r.get("n") else 0


def point_view(data, point):
    """Как точка проверила ноды в этом замере: 'blind' — ничего не проверила (не ответила, не нашла ни одного имени,
    ни одного соединения), 'noisy' — потери к большинству нод сразу, 'ok' — иначе."""
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if not rows or all(not r or not r.get("n") or not (r.get("ok") or r.get("fail") or r.get("refused")) for r in rows):
        return "blind"
    if sum(1 for r in rows if loss_judge(r) == "bad") >= max(3, (len(rows) + 1) // 2):
        return "noisy"
    return "ok"


def point_why(data, point):
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if all(not r for r in rows):
        return "точка не отвечает"
    if all(not r or not r.get("n") for r in rows):
        return "ни свой, ни публичный DNS не нашёл ни одного имени ноды"
    return "не открылось ни одного соединения"


def point_alert(kind, point, data, since, now):
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if kind == "blind":
        return (f"📍 <b>Точка «{html.escape(point)}» ничего не проверила</b> — {LOSS_CONFIRM} замера подряд: "
                f"{point_why(data, point)}.\nПока так, её данные в выводах не учитываются.")
    if kind == "noisy":
        bad = sorted(n for n, pts in data["nodes"].items() if loss_judge(pts.get(point)) == "bad")
        return (f"📍 <b>У точки «{html.escape(point)}» проблемы с сетью</b>\nТеряются соединения к {len(bad)} нодам из "
                f"{len(rows)} сразу ({', '.join(n.upper() for n in bad)}), {LOSS_CONFIRM} замера подряд; с других точек "
                "к этим нодам потерь нет или почти нет.\n<b>Похоже на:</b> беду сети этой точки или её провайдера, а не "
                "нод. По нодам отдельных сообщений не шлю, в разборе сбоя эту точку не учитываю.")
    return (f"✅ <b>Точка «{html.escape(point)}» снова в порядке</b>\nБыло с {hmsk(since)} до {hmsk(now)} МСК.")


def hmsk(ts):
    return time.strftime("%H:%M", time.gmtime(ts + 3 * 3600))


def points_step(st, data):
    """Состояние точек по замеру: ok / blind / noisy, с подтверждением LOSS_CONFIRM замеров подряд.
    Возвращает (сообщения, точки, которые сейчас не учитываются)."""
    pt = st.setdefault("loss", {}).setdefault("pt", {})
    msgs = []
    for point in data.get("points", []):
        cur = pt.setdefault(point, {"lvl": "ok", "cand": "ok", "n": 0, "since": 0})
        obs = point_view(data, point)
        if obs == cur["lvl"]:
            cur["cand"], cur["n"] = obs, 0
            continue
        cur["n"] = cur["n"] + 1 if obs == cur["cand"] else 1
        cur["cand"] = obs
        if cur["n"] >= LOSS_CONFIRM:
            was, since = cur["lvl"], cur["since"]
            cur.update(lvl=obs, n=0, since=data["ts"])
            msgs.append(point_alert(obs, point, data, since, data["ts"]) if obs != "ok" or was != "ok" else None)
    for point in [p for p in pt if p not in data.get("points", [])]:
        del pt[point]
    return [m for m in msgs if m], sorted(p for p, v in pt.items() if v["lvl"] != "ok")


def loss_step(st, data):
    """Свежий замер -> сообщения: о точках (ослепла, проблемы с сетью, снова в порядке) и о потерях к нодам, которые
    держатся LOSS_CONFIRM замеров подряд, и об их конце. Пары точки, которая сейчас не в порядке, не судятся."""
    loss = st.setdefault("loss", {})
    lvl = loss.setdefault("lvl", {})
    loss["ts"], loss["n"], loss["last"] = data["ts"], data["n"], data["nodes"]
    msgs, skip = points_step(st, data)
    loss["skip"] = skip
    began, ended = [], []
    for node, pts in sorted(data["nodes"].items()):
        for point, r in pts.items():
            cur = lvl.setdefault(f"{node}|{point}", {"lvl": "ok", "cand": "ok", "n": 0})
            if point in skip:
                cur.update(lvl="ok", cand="ok", n=0)  # беда самой точки: о нодах с неё не судим
                continue
            obs = loss_judge(r)
            if obs is None:
                continue
            if obs == cur["lvl"]:
                cur["cand"], cur["n"] = obs, 0
                continue
            cur["n"] = cur["n"] + 1 if obs == cur["cand"] else 1
            cur["cand"] = obs
            if cur["n"] >= LOSS_CONFIRM:
                cur["lvl"], cur["n"] = obs, 0
                (began if obs == "bad" else ended).append((node, point))
    valid = {f"{node}|{point}" for node, pts in data["nodes"].items() for point in pts}
    for key in [k for k in lvl if k not in valid]:
        del lvl[key]
    return msgs + ([loss_alert(began, data)] if began else []) + ([loss_end(ended, data)] if ended else [])


def loss_group(pairs):
    """Пары (нода, точка) -> {точка: [ноды]} в порядке появления."""
    by_point = {}
    for node, point in pairs:
        by_point.setdefault(point, []).append(node)
    return by_point


def loss_alert(pairs, data):
    """Сообщение о потерях: по абзацу на ноду, что видела сама нода — отдельной строкой."""
    out = ["📉 <b>Потери соединений до нод</b>",
           f"<i>{LOSS_CONFIRM} замера подряд, по {data['n']} соединений на ноду</i>"]
    for point, nodes in loss_group(pairs).items():
        out += ["", f"📍 Откуда: <b>{html.escape(point)}</b>"]
        elsewhere = []
        for node in nodes:
            pts = data["nodes"][node]
            r = pts[point]
            out += ["", f"• <b>{html.escape(node.upper())}</b> — не проходит {r['fail']} из {r['n']} ({loss_pct(r)} %)"]
            note = witness_text(r, r.get("wit"))
            if note:
                out.append("   ↳ " + html.escape(note))
            elsewhere += [f"{node.upper()} — {p}: {v['fail']} из {v['n']}" for p, v in pts.items()
                          if p != point and v and v.get("fail")]
        rest = [p for p in data.get("points", []) if p != point]
        out += ["", html.escape("С других точек к этим нодам: " + ("; ".join(elsewhere) if elsewhere else "потерь нет")
                                + (f" ({', '.join(rest)})" if rest and not elsewhere else ""))]
    out += ["", "<b>Что это значит:</b> у клиентов такого же провайдера часть подключений к этим нодам зависает "
                "на старте. Сами ноды работают."]
    return "\n".join(out)


def loss_end(pairs, data):
    out = ["✅ <b>Потери соединений прошли</b>", f"<i>{LOSS_CONFIRM} замера подряд без потерь</i>"]
    for point, nodes in loss_group(pairs).items():
        out += ["", f"📍 Откуда: <b>{html.escape(point)}</b>",
                html.escape("• " + ", ".join(node.upper() for node in nodes)
                            + f" — проходят все {data['nodes'][nodes[0]][point]['n']} соединений")]
    return "\n".join(out)


def loss_bad(st, now):
    """Пары (нода, точка, процент) с подтверждёнными потерями по свежему замеру."""
    loss = st.get("loss") or {}
    if not loss.get("ts") or now - loss["ts"] > LOSS_STALE:
        return None
    out = []
    for key, v in sorted(loss.get("lvl", {}).items()):
        if v.get("lvl") == "bad":
            node, point = key.split("|", 1)
            out.append((node, point, loss_pct((loss.get("last", {}).get(node) or {}).get(point))))
    return out


def loss_log(data):
    """Замер одной строкой для журнала сторожа."""
    bad = [f"{node} — {point} {r['fail']}/{r['n']}" for node, pts in sorted(data["nodes"].items())
           for point, r in pts.items() if r and r.get("fail")]
    asked = sum(1 for pts in data["nodes"].values() for r in pts.values() if r)
    total = sum(len(pts) for pts in data["nodes"].values())
    return f"потери с точек: серий {asked} из {total}; не прошло: " + ("; ".join(bad) or "нигде")


def deep_many(chans, via_for, agents, bases):
    """Разбор нескольких каналов разом (не больше DEEP_MAX): {имя канала: результат deep_diag}."""
    chans = chans[:DEEP_MAX]
    if not chans:
        return {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(chans)) as ex:
        return dict(zip((c["name"] for c in chans), ex.map(lambda c: deep_diag(c, via_for(c), agents, bases), chans)))


def series_part(ser):
    """Серия соединений одной фразой: «соединений прошло 5 из 6»; None — серии не было или сервер недоступен целиком."""
    if not ser or not ser.get("n") or not ser.get("ok"):
        return None
    return f"соединений прошло {ser['ok']} из {ser['n']}"


def lossy(ser):
    """Часть соединений серии не прошла, а часть прошла — частичные потери."""
    return bool(ser and ser.get("ok") and ser.get("fail"))


def sni_cut(cmp_):
    """С настоящим именем сервер не отвечает, а тот же адрес с другим именем или без имени — отвечает."""
    return bool(cmp_ and cmp_.get("real") in ("silent", "reset", "closed")
                and "answer" in (cmp_.get("neutral"), cmp_.get("none")))


def point_text(r):
    """Одна точка проверки одной фразой."""
    kind = netprobe.probe_class(r)
    if kind == "none":
        return "не ответила"
    if kind == "dns":
        return "имя не находится в DNS"
    if kind == "tcp":
        text = {"refused": "порт закрыт (отказ в соединении)", "timeout": "порт не отвечает"}.get(r["tcp"], "нет соединения")
        return text + (", а порт 80 на том же адресе отвечает" if r.get("alt80") else "")
    if kind == "tls":
        return f"порт открыт ({r['tcp_ms']} мс), TLS не отвечает"
    if kind == "stall":
        return f"соединение есть, но данные встали после {max(1, r['bytes'] // 1024)} КБ"
    if r["end"] == "ok":
        return f"порт открыт ({r['tcp_ms']} мс), TLS отвечает, {r['need'] // 1024} КБ получены"
    return f"порт открыт ({r['tcp_ms']} мс), TLS отвечает" if r["tls"] else f"порт открыт ({r['tcp_ms']} мс)"


def path_text(p):
    """Путь с точки до ноды одной фразой; None — нечего сказать."""
    if not p or not p.get("addr") or "list" not in p:
        return None
    if p.get("reached"):
        return f"доходит до ноды ({p['hops']} шагов)"
    rej = next((h for h in p["list"] if str(h[1]).startswith(("reject", "icmp"))), None)
    if rej:
        return f"узел шага {rej[0]} ({rej[2]}) ответил отказом — путь закрыт на нём"
    if p.get("last"):
        return f"пропадает после шага {p['last'][0]} ({p['last'][1]})"
    return "не ответил ни один шаг"


def name_cut(r):
    """Имя ноды на чужом нейтральном сервере: с ним ответа нет ни разу, а с нейтральным именем там же — есть."""
    return bool(r and r.get("n") and r["name_ok"] == 0 and r["neutral_ok"] >= 1)


def deep_extra(d):
    """Строки разбора из части D (путь от точек, имя на чужом сервере, сброс TLS по свидетелю)."""
    lines = [f"• путь от {name}: {t}" for name, t in sorted((n, path_text(p)) for n, p in (d.get("paths") or {}).items()) if t]
    refs = d.get("refs") or {}
    cut = [n for n, r in refs.items() if name_cut(r)]
    free = [n for n, r in refs.items() if r and r.get("n") and r["name_ok"]]
    if cut:
        lines.append(f"• имя ноды на чужом сервере ({', '.join(cut)}): с нашим именем ответа нет, с нейтральным есть — "
                     "имя в фильтре")
    if free:
        lines.append(f"• имя ноды на чужом сервере ({', '.join(free)}): проходит — закрыт адрес, а не имя")
    for name, r in sorted((d.get("vpn") or {}).items()):
        lines.append(f"• через VPN с точки {name}: {vpn_text(r)}")
    for k, w in sorted((d.get("witness") or {}).items()):
        if k.endswith("|tls") and w:
            if w["rst_out"]:
                lines.append(f"• сброс TLS ({k[:-4]}): его отправила сама нода")
            elif w["seen"]:
                lines.append(f"• сброс TLS ({k[:-4]}): нода сброса не отправляла — соединение оборвали по дороге")
    return lines


def name_note(d):
    """Вывод по имени, когда адрес ноды закрыт; None — проверки имени не было или она разноречива."""
    refs = [r for r in (d.get("refs") or {}).values() if r and r.get("n")]
    if not refs:
        return None
    if all(name_cut(r) for r in refs):
        return "имя ноды тоже в фильтре (проверено на чужом сервере) — новый адрес не поможет, нужно и новое имя"
    if all(r["name_ok"] for r in refs):
        return "имя ноды не в фильтре (на чужом сервере проходит) — закрыт адрес; поможет новый адрес"
    return None


def deep_lines(d, extra=None):
    """Что увидели: строки для сообщения. extra — добавлять ли строки части D (по умолчанию — как DEEP_EXTRA_LIVE)."""
    series, names = d.get("series") or {}, d.get("sni") or {}

    def point(name, r):
        return "; ".join(x for x in (point_text(r), series_part(series.get(name))) if x)
    lines = ["• с rf1 напрямую: " + point(SELF, d["direct"])]
    lines += [f"• {name}: {point(name, r)}" + (" (у точки сейчас своя беда с сетью — в выводе не учитываю)"
                                                 if name in d.get("skip", ()) else "") for name, r in d["agents"].items()]
    for name, w in (d.get("witness") or {}).items():
        note = witness_text(series.get(name), w)
        if note:
            lines.append(f"• сверка с нодой ({name}): {note}")
    cut = [("с rf1" if name == SELF else name) for name, c in names.items() if sni_cut(c)]
    if cut:
        lines.append("• имена TLS на том же адресе (" + ", ".join(cut) + "): с настоящим именем ответа нет, "
                     "с другим именем и без имени сервер отвечает")
    if d["abroad"] is not None:
        lines.append(f"• из-за рубежа (через {d['via']}): " + ("отвечает" if d["abroad"] else "не отвечает"))
    t = d.get("trace")
    if t:
        if t["reached"]:
            lines.append(f"• трассировка с rf1: пакеты доходят до ноды ({t['hops']} шагов)")
        elif t["last"]:
            lines.append(f"• трассировка с rf1: пакеты пропадают после шага {t['last'][0]} ({t['last'][1]})")
        else:
            lines.append("• трассировка с rf1: не ответил ни один шаг")
    ext = d.get("external")
    if ext:
        lines.append(f"• внешняя проверка ({ext.get('service', '?')}): {ext.get('note', 'нет данных')}")
    if DEEP_EXTRA_LIVE if extra is None else extra:
        lines += deep_extra(d)
    return lines


def deep_verdict(d, status):
    """На что похоже — одной фразой. status — состояние канала: DOWN или FREEZE."""
    points = {"rf1": netprobe.probe_class(d["direct"])}
    points.update({name: netprobe.probe_class(r) for name, r in d["agents"].items() if name not in d.get("skip", ())})
    answered = {k: v for k, v in points.items() if v != "none"}
    kinds = set(answered.values())
    n = len(answered)
    filt = d.get("filtered") or []
    seen_filt = [p for p in filt if p in answered]
    where = "с rf1" if n == 1 else f"со всех {n} российских точек" + (f" (из них за фильтром: {len(seen_filt)})" if seen_filt else "")
    abroad = d["abroad"]
    series, names = d.get("series") or {}, d.get("sni") or {}
    part = [f"{n} — {series[n]['ok']} из {series[n]['n']}" for n in series if lossy(series[n])]
    tail = (f"; при этом часть соединений теряется ({', '.join(part)}) — путь от этих точек до ноды неустойчив"
            if part else "")
    cut = [n for n, c in names.items() if sni_cut(c) and points.get(n, "none") not in ("ok", "none")]
    if cut and len(cut) == len(answered):
        return (f"режут по имени сайта: {where} с настоящим именем ноды ответа нет, а тот же адрес с другим именем "
                "отвечает — блокировка по имени (SNI), сам адрес ноды не закрыт")
    if kinds == {"stall"}:
        return (f"данные встают {where} даже при прямом обращении к сайту ноды — душат всю подсеть хостера, "
                "а не только VPN (обрыв «после 16–20 КБ»)")
    if kinds == {"ok"}:
        if status == "FREEZE":
            return (f"напрямую сайт ноды отдаёт данные без обрыва {where}, а через VPN они встают — режут именно "
                    "VPN-соединение (по признакам протокола) либо узкое место на самой ноде")
        return (f"сайт ноды отвечает {where}, а VPN через неё не проходит — дело в Xray на ноде, ключе или профиле, "
                "а не в блокировке адреса") + tail
    if "ok" in kinds:
        bad = ", ".join(k for k, v in answered.items() if v != "ok")
        good = ", ".join(k for k, v in answered.items() if v == "ok")
        if points["rf1"] != "ok" and all(v == "ok" for k, v in answered.items() if k != "rf1"):
            return (f"не отвечает только с rf1, с остальных точек ({good}) нода работает — сбой на стороне rf1 или "
                    "её провайдера; у пользователей, скорее всего, всё в порядке")
        return (f"с части российских точек нода не отвечает ({bad}), с других работает ({good}) — блокировка "
                "у отдельных провайдеров либо неустойчивая сеть") + tail
    # ни с одной российской точки не работает
    if kinds == {"dns"}:
        return (f"имя ноды не находится в DNS {where}" + (", а из-за рубежа нода отвечает — блокировка или подмена "
                "на уровне DNS" if abroad else " — проверьте запись домена у регистратора"))
    alt = [n for n, r in [(SELF, d["direct"])] + list(d["agents"].items()) if r and r.get("alt80")]
    if abroad is True and kinds == {"tcp"} and alt:
        return (f"из-за рубежа нода отвечает, а из России {where} порт 443 молчит, хотя порт 80 на том же адресе "
                "отвечает — закрыт именно порт 443 этого адреса, а не адрес целиком")
    if abroad is True:
        if kinds <= {"tls"}:
            return (f"из-за рубежа нода отвечает, а из России {where} порт открыт, но TLS рвётся — "
                    "блокировка по имени сайта (SNI) или по протоколу")
        wit = [w for k, w in (d.get("witness") or {}).items() if w and not k.endswith("|tls")]
        side = ("" if not wit else "; по счётчикам ноды запросы из России до неё не доходят — закрыт путь к ноде"
                if not any(w["seen"] for w in wit) else
                "; по счётчикам ноды запросы из России доходят и она отвечает — закрыт обратный путь, от ноды в Россию"
                if all(w["seen"] and w["rep"] for w in wit) else "")
        return (f"из-за рубежа нода отвечает, а из России {where} — нет: похоже на блокировку адреса ноды из России"
                + (f" (пакеты пропадают после шага {d['trace']['last'][0]})"
                   if d.get("trace") and not d["trace"]["reached"] and d["trace"]["last"] else "") + side)
    if abroad is False:
        return "нода не отвечает ни из России, ни из-за рубежа — сбой самой ноды или её хостера, а не блокировка"
    return f"нода не отвечает {where}; из-за рубежа проверить было не через что — блокировка это или поломка, не различить"


def deep_text(d, status, extra=()):
    """Блок сообщения: что увидели (плюс строки extra от самого сторожа) и на что похоже."""
    note = name_note(d) if DEEP_EXTRA_LIVE else None
    return ("<b>Откуда проверил</b>\n" + html.escape("\n".join(deep_lines(d) + list(extra)))
            + f"\n\n<b>Похоже на:</b> {html.escape(deep_verdict(d, status))}." + (f"\n{html.escape(note)}." if note else ""))


# ---------- 4. внешний сервис: заглушка ----------

def external_scan(target, cfg=None):
    """ЗАГЛУШКА, выключена. Место под проверку ноды сторонним сервисом, у которого сканеры стоят в сетях настоящих
    операторов (например, «динамическое сканирование» cheburcheck.ru) — этого взгляда сторожу не хватает: все его
    точки в дата-центрах.

    Почему выключено: сервису и его добровольцам пришлось бы сообщить адрес и домен ноды. Включать — только по
    решению владельца: external.json {"enabled": true, "service": "..."}; и до включения нужно дописать сам запрос
    (порядок обращения к сервису не проверялся). Пока запроса нет, функция никуда не ходит ни при каких настройках.
    Возвращает None (выключено) либо {"service", "note"} — строку для сообщения."""
    cfg = read_etc(EXTERNAL, {}) if cfg is None else cfg
    if not cfg.get("enabled"):
        return None
    return {"service": str(cfg.get("service") or "не указан"),
            "note": "включена в настройках, но запрос к сервису не написан — ничего не отправлено"}


# ---------- проверка по запросу (probe.py --blocks) ----------

def clean(name):
    """Имя плитки без украшений."""
    for junk in ("🌐", "🔄", "|"):
        name = name.replace(junk, " ")
    return " ".join(name.split())


def full_check(chans, nodes, site_hosts, bases, state_chans, agents=None):
    """Всё разом, не дожидаясь расписания: свежая сверка со списками, DNS, точки проверки и вход каждого канала
    с каждой точки. {"lists", "dns", "dns_names", "health", "nodes": {канал: deep_diag}, "external"}"""
    agents = agents_cfg() if agents is None else agents
    alive = [c for c in chans if not c.get("expected_exit") and state_chans.get(c["name"], {}).get("status", "OK") == "OK"]
    via_port = alive[0]["port"] if alive else None
    tails = tuple("." + b for b in bases)
    names = list(site_hosts) + [n["host"] for n in nodes if str(n.get("host", "")).endswith(tails)]

    def via_for(c):
        return next(({"name": clean(o["name"]), "port": o["port"]} for o in alive if o.get("entry") != c.get("entry")), None)

    # списки качаются сами по себе; ноды — по три разом и раньше DNS, чтобы не завалить запросами точки проверки
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as side, concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f_lists = side.submit(lists_run, targets(chans, nodes, site_hosts, bases), bases, via_port)
        health = agents_health(agents)
        f_nodes = [(c["name"], ex.submit(deep_diag, c, via_for(c), agents, bases)) for c in chans]
        checked = {name: f.result() for name, f in f_nodes}
        dns = dns_check(names, via_port, agents)
        return {"lists": f_lists.result(), "dns": dns, "dns_names": len(names), "health": health, "nodes": checked,
                "external": bool(read_etc(EXTERNAL, {}).get("enabled"))}


def node_line(name, d):
    """Строка проверки по запросу: вход канала со всех точек одной фразой."""
    points = {SELF: d["direct"]}
    points.update(d["agents"])
    kinds = {p: netprobe.probe_class(r) for p, r in points.items()}
    series = d.get("series") or {}
    part = [f"{p} — прошло {series[p]['ok']} из {series[p]['n']}" for p in points if lossy(series.get(p))]
    answered = {p: k for p, k in kinds.items() if k != "none"}
    silent = [p for p, k in kinds.items() if k == "none"]
    abroad = {True: "из-за рубежа отвечает", False: "из-за рубежа НЕ отвечает", None: "из-за рубежа не проверялось"}[d["abroad"]]
    where = "с rf1" if len(answered) == 1 else f"со всех {len(answered)} российских точек"
    if set(answered.values()) == {"ok"} and d["abroad"] is not False:
        note = f" (точка не ответила: {', '.join(silent)})" if silent else ""
        if part:
            return f"⚠️ {clean(name)} — отвечает {where}, но часть соединений теряется: {'; '.join(part)}; {abroad}{note}"
        return f"✅ {clean(name)} — отвечает {where}, {abroad}{note}"
    bad = "; ".join(f"{p}: {point_text(points[p])}" for p, k in kinds.items() if k != "ok")
    good = ", ".join(p for p, k in answered.items() if k == "ok")
    return (f"⚠️ {clean(name)} — {bad}" + (f"; в порядке: {good}" if good else "")
            + (f"; часть соединений теряется: {'; '.join(part)}" if part else "") + f"; {abroad}")


def check_text(res, when):
    """Сообщение о проверке блокировок по запросу."""
    out = [f"🛡 <b>Проверка блокировок (rf1)</b> · {when}", ""]
    lists = res["lists"]
    src = lists["sources"]
    hard = [(who, rec, LIST_NAMES[key]) for key, (_, level) in KIND.items() if level == "hard"
            for who, rec in lists["hits"].get(key, {}).items()]
    near = sorted(lists.get("neighbours", {}).items())
    failed = [LIST_NAMES[k] for k, v in src.items() if not v["ok"]]
    out.append("<b>Списки</b> <i>(реестр РКН и подсети, которые в России душат)</i>")
    if hard:
        out += [html.escape(f"⚠️ {who} — {name}, запись {rec}") for who, rec, name in hard]
    else:
        out.append(f"✅ наших адресов и доменов в списках нет — сверено адресов: {lists['targets']['ips']}, "
                   f"имён: {lists['targets']['names']}, списков: {sum(1 for v in src.values() if v['ok'])} из {len(src)}")
    if near:
        out.append(html.escape("ℹ️ рядом с нашими адресами в реестре есть чужие (та же подсеть /24, другие клиенты хостера): "
                               + ", ".join(f"{who} — {n}" for who, n in near)
                               + ". Наших адресов в реестре нет, на работу это не влияет."))
    if failed:
        out.append(html.escape("⚠️ не скачались: " + ", ".join(failed)))
    out += ["", "<b>DNS</b> <i>(обычный ответ против защищённого)</i>"]
    odd = {n: r for n, r in res["dns"].items() if r["odd"]}
    for name, r in sorted(odd.items()):
        out.append(html.escape(f"⚠️ {name}: по защищённому DNS {', '.join(r['truth']) or 'нет записи'}; иначе отвечают: "
                               + "; ".join(f"{who} — {what}" for who, what in r["odd"])))
    if not odd:
        out.append(f"✅ подмены нет — имён: {len(res['dns'])}")
    if len(res["dns"]) < res["dns_names"]:
        out.append(f"⚠️ защищённый DNS не ответил по {res['dns_names'] - len(res['dns'])} из {res['dns_names']} имён")
    out += ["", "<b>Входы нод напрямую</b> <i>(порт, TLS и 64 КБ по одному соединению; сам VPN — в обычном отчёте)</i>"]
    out += [html.escape(node_line(name, d)) for name, d in res["nodes"].items()]
    points = ["rf1 ✅"] + [f"{name} {'✅' if ok else '❌'}" for name, ok in res["health"].items()]
    out += ["", "<b>Точки проверки в РФ:</b> " + html.escape(" · ".join(points)),
            "<b>Внешний сервис:</b> " + ("включён в настройках, но запрос к нему не написан — ничего не отправляется"
                                         if res["external"] else "выключен")]
    return "\n".join(out)


# ---------- строки отчёта ----------

def block_line(st, now):
    """Строка обычного отчёта: списки · DNS · точки проверки. Подробно — только о бедах."""
    parts = block_items(st, now)
    return "<b>Блокировки:</b> " + html.escape(" · ".join(parts)) if parts else None


def block_items(st, now):
    """Части строки «Блокировки» по отдельности (без экранирования) — отчёт раскладывает их по пунктам (v12)."""
    parts = []
    lists = st.get("lists") or {}
    if lists.get("ts"):
        hard = hard_hits(st)
        failed = [k for k, v in lists.get("sources", {}).items() if not v.get("ok")]
        tg = lists.get("targets", {})
        if hard:
            parts.append("⚠️ в списках: " + "; ".join(f"{who} — {name}" for who, name in hard))
        else:
            parts.append(f"в списках блокировок наших адресов нет (сверено адресов: {tg.get('ips', 0)}, имён: {tg.get('names', 0)})")
        if now - lists["ts"] > LISTS_STALE:
            parts.append(f"⚠️ списки не обновлялись {int((now - lists['ts']) // 3600)} ч")
        elif failed:
            parts.append(f"не скачалось списков: {len(failed)} из {len(lists['sources'])}")
    dns = st.get("dns") or {}
    if dns.get("names"):
        bad = [n for n, v in (st.get("dns_lvl") or {}).items() if v.get("lvl") == "bad"]
        parts.append("⚠️ подмена DNS: " + ", ".join(sorted(bad)) if bad else f"подмены DNS нет (имён: {dns['names']})")
    van = st.get("vantage") or {}
    if van:
        down = [n for n, ok in van.items() if not ok]
        parts.append("⚠️ точка проверки не отвечает: " + ", ".join(down) if down
                     else f"точек проверки в РФ: {len(van) + 1}")
    skip = (st.get("loss") or {}).get("skip") or []
    if skip:
        why = {"blind": "ничего не проверяет", "noisy": "проблемы с сетью"}
        pt = (st.get("loss") or {}).get("pt") or {}
        parts.append("⚠️ " + "; ".join(f"точка «{p}» — {why.get(pt.get(p, {}).get('lvl'), 'не в порядке')}" for p in skip))
    dbad = sorted(p for p, v in (st.get("dns_pt") or {}).items() if v.get("lvl") == "bad")
    if dbad:
        parts.append("⚠️ свой DNS не находит наших имён: " + ", ".join(dbad))
    pl = profiles_line(st)
    if pl:
        parts.append(pl)
    vl = vpn_line(st)
    if vl:
        parts.append(vl)
    lossy_now = loss_bad(st, now)
    if lossy_now:
        parts.append("⚠️ потери соединений: " + ", ".join(f"{node} — {point} {pct} %" for node, point, pct in lossy_now))
    elif lossy_now is not None:
        parts.append("потерь соединений с точек нет")
    return parts


GEO_SOURCES = ("ipinfo", "ip-api", "ipwho", "geojs", "country.is")  # гео-базы (+cloudflare, +youtube считаем отдельно)


def geo_verdict(row):
    """row — {источник: страна|None, ...}. Множество стран, которые назвали источники (без None)."""
    return {cc for cc in row.values() if cc}


def geo_step(st, data, live):
    """data — {нода: {"flag": CC|None, "row": {база: страна}, "org", "cf": страна Cloudflare, "yt": страна YouTube}}.
    Для каждой ноды и источника помним всё, что он показывал (seen). Новое значение ждёт подтверждения следующим сбором
    (pend); подтвердилось — запоминаем и сообщаем (при live). В пробном режиме (live=False) и для источника, ответившего
    впервые, всё запоминается молча — это исходное состояние."""
    geo = st.setdefault("geo", {})
    seen, pend = geo.setdefault("seen", {}), geo.setdefault("pend", {})
    msgs = []
    for node, cur in sorted(data.items()):
        vals = dict(cur.get("row") or {})
        vals.update(cloudflare=cur.get("cf"), youtube=cur.get("yt"), org=cur.get("org"))
        if not any(vals.values()):
            continue  # канал не ответил — ничего не знаем, ничего не меняем
        s, p = seen.setdefault(node, {}), pend.setdefault(node, {})
        new_ru, moved, org = [], [], None
        for src, v in sorted(vals.items()):
            if not v:
                continue
            known = s.setdefault(src, [])
            if v in known:
                p.pop(src, None)
                continue
            if not live or not known:
                known.append(v)
                p.pop(src, None)
                continue
            if p.get(src) != v:
                p[src] = v  # новое — ждём подтверждения следующим сбором
                continue
            p.pop(src, None)
            was = known[-1]
            known.append(v)
            if src == "org":
                org = (was, v)
            elif v == "RU":
                new_ru.append(src)
            else:
                moved.append(f"{src}: {was}→{v}")
        flag = cur.get("flag")
        if new_ru:
            msgs.append(f"🌍 <b>Нода {html.escape(node)}: Россия в гео</b>\nВпервые показывают Россией: "
                        + html.escape(", ".join(new_ru)) + (f". Флаг плитки — {flag}." if flag else "."))
        if moved:
            msgs.append(f"🌍 <b>Нода {html.escape(node)}: сменилась страна в гео</b>\n" + html.escape("; ".join(moved)))
        if org:
            msgs.append(f"🌍 <b>Нода {html.escape(node)}: сменился владелец сети</b>\n"
                        + html.escape(f"было {org[0]}, стало {org[1]}"))
    geo["by"] = data
    return msgs


def geo_line(node, cur):
    """Строка ноды для недельной таблицы гео. ⚠️ — источники расходятся с флагом плитки или между собой."""
    ccs = geo_verdict(cur.get("row") or {})
    flag = cur.get("flag")
    others = {x for x in (cur.get("cf"), cur.get("yt")) if x}
    odd = len(ccs) > 1 or bool(flag and (ccs | others) - {flag}) or bool(not flag and others - ccs)
    extra = [f"CF {cur['cf']}"] if cur.get("cf") else []
    extra += [f"YT {cur['yt']}"] if cur.get("yt") else []
    return (f"• {clean(node)} ({'флаг ' + flag if flag else 'без флага выхода'}): базы {'/'.join(sorted(ccs)) or '?'}"
            + (", " + ", ".join(extra) if extra else "") + (" ⚠️" if odd else ""))


def geo_week(st):
    """Таблица гео для недельной сводки."""
    geo = (st.get("geo") or {}).get("by") or {}
    if not geo:
        return []
    return ["", "<b>Гео адресов нод</b> <i>(страна по базам, Cloudflare, YouTube; ⚠️ — расходится с флагом плитки)</i>"] \
        + [geo_line(node, cur) for node, cur in sorted(geo.items())]


def week_lines(st):
    """Для сводки за неделю: рядом с какими нашими адресами в реестре есть чужие."""
    near = near_hits(st)
    if not near:
        return []
    return ["", "<b>Чужие адреса в реестре рядом с нашими</b> <i>(та же подсеть /24; наших в реестре нет)</i><b>:</b> "
            + html.escape(", ".join(f"{who} — {n}" for who, n in near))]
