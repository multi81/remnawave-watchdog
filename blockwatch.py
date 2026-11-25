"""channel-watch: блокировки глазами сторожа — часть probe.py, вынесенная в отдельный файл.

Логика взята из открытого описания cheburcheck.ru (https://cheburcheck.ru/kb/faq), источники — те же:
1. Списки (probe.py --lists, раз в 6 часов): адреса и домены наших серверов сверяются с реестром РКН
   (antifilter.download, antifilter.network) и с подсетями CDN и хостеров, которые в России душат «после 16–20 КБ»
   (github.com/123jjck/cdn-ip-ranges). Списки скачиваются сюда и сверяются на месте — наши адреса никуда не уходят.
2. Подмена DNS (раз в DNS_EVERY): ответ обычного DNS сравнивается с ответом по защищённому DNS (DoH). Наши имена —
   только системным DNS rf1 и точек; публичные DNS по UDP — только на чужих именах (подменяют ли ответы по пути).
3. Разбор сбоя канала: нода проверяется напрямую с rf1 и с других российских точек (агенты vantage_agent.py),
   из-за рубежа (через чужой канал) и трассировкой — чтобы отличить блокировку от поломки ноды.
4. Взгляд из домашних сетей России — Globalping (globalping.py, external_scan): когда порт входа ноды не открывается
   (таймаут, отказ) с rf1 или с двух наших точек, его адрес (сверенный с защищённым DNS) и порт (только IP, без имени) проверяются по TCP у добровольных точек
   Globalping в сетях обычных провайдеров (МТС, Билайн, Ростелеком, Дом.ру…) и из Европы. Так видно: закрыто по всей
   России, у части провайдеров или только для дата-центров. Включается в external.json; без него наружу не уходит ничего.
"""
import concurrent.futures
import html
import inspect
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import netprobe
import nodewatch
import rucheck

# Через локальные SOCKS-порты сторожа ходим с паролем из socks.auth (netprobe.curl_socks); метка для
# build_channels.py --socks-auth: этот модуль пароль умеет.
SOCKS_AUTH_READY = True

try:
    import vantage_client  # TLS к точке проверки с закреплённым отпечатком (лежит рядом, ставит install.sh)
except ImportError:  # сторож обновили частично: точки без sha256 работают по HTTP, с sha256 — «не ответила»
    vantage_client = None
try:
    import globalping  # взгляд из домашних сетей России (лежит рядом, ставит install.sh)
except ImportError:  # сторож обновили частично: внешней проверки нет, в сообщении «запрос не написан»
    globalping = None

ETC = "/etc/channel-watch"
LISTS_FILE = "/var/lib/channel-watch/lists.json"
LISTS_DIR = "/var/lib/channel-watch/lists"
LISTS_STALE = 14 * 3600     # списки обновляются раз в 6 часов; старше — сказать в отчёте
DNS_EVERY = 1800            # секунд между проверками подмены DNS
DNS_MIN = 2                 # столько независимых ответов должны разойтись с защищённым DNS, чтобы считать подменой
DEEP_MAX = 3                # за один запуск подробно разбираем не больше стольких каналов
DEEP_TAIL = 4               # разбор со сроком: после срока ещё столько секунд на дописывание (чьи узлы трассировки)
LINGER = False              # разбор обрезан по сроку, а его потоки ещё ждут ответов — probe выйдет, не дожидаясь их
ABROAD_VIAS = 2             # из-за рубежа сверяем не больше чем через столько чужих каналов (разные входы и выходы)
ABROAD_CONTROL = "www.gstatic.com"  # заведомо живой адрес: довозит ли сам обходной канал (тот же, что QUICK_URL у probe)
LOSS_FILE = "/var/lib/channel-watch/loss.json"
SIDE_FILE = "/var/lib/channel-watch/side.json"  # профиль точек и гео нод (probe.py --side, свой таймер)
PROFILE_TRIES = 3           # попыток профиля точки за один сбор
VPN_EVERY = 3600            # секунд между обходами плиток через VPN-точки (служба --side)
VPN_STALE = 3 * VPN_EVERY        # обход через VPN-точки старше — не показывать как данные
PROFILE_STALE = 13 * 3600        # профиль собирается раз в 6 ч: два пропуска и час запаса
OUTSIDE_STALE = 13 * 3600        # взгляд снаружи — раз в 6 ч (probe.SLOW_EVERY)
GEO_STALE = 25 * 3600            # гео — раз в 12 ч
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
WIT_MIN = 3                 # меньше дошедших до ноды соединений — об отказе самой ноды не судим
WITNESS_WAIT = 16           # дольше этого за один раз счётчиков ноды не ждём
SELF = "rf1"                # так в сообщениях называется сам сервер сторожа
VANTAGE = "vantage.json"    # точки проверки в РФ: [{"name", "url", "token"}]
EXTERNAL = "external.json"  # внешний сервис проверки блокировок: {"enabled": true, "service": "globalping"}

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
# публичные DNS по UDP спрашиваем только о чужих именах DNS_REF_NAMES: так видно, подменяют ли ответы по пути, а имена
# наших нод и сайтов открытым текстом к ним не уходят (наши имена — системным DNS и защищённым DoH)
RESOLVERS = (("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1"), ("Яндекс", "77.88.8.8"), ("Quad9", "9.9.9.9"))
DNS_REF_NAMES = ("rutracker.org", "www.facebook.com", "www.example.org")  # те же, что в профиле rf1 (PROFILE_LOCAL)
AGENT_DNS_CAP = "dns_udp0"  # агент в /health ("caps") обещает: /dns?udp=0 — только системный DNS, без публичных
CERT_CHECK = True           # разбор сбоя: сверять сертификат у каналов с обычным TLS (CDN); Reality не сверяем
DOH = ("https://dns.google/resolve?name={}&type=A", "https://cloudflare-dns.com/dns-query?name={}&type=A")


def read_json_file(path, default=None):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return default


def side_age(part, limit, now):
    """Сколько часов данным службы --side, если они старше срока; иначе None. Нет ts или now — срок неизвестен,
    не устарело."""
    ts = (part or {}).get("ts")
    if now and ts and now - ts > limit:
        return int((now - ts) // 3600)
    return None


def read_etc(name, default):
    try:
        return json.load(open(os.path.join(ETC, name), encoding="utf-8"))
    except (OSError, ValueError):
        return default


# ---------- 1. списки ----------

def fetch(url, dest, socks_port=None):
    """Скачать список в файл; не вышло напрямую — через канал сторожа. True — файл на месте и не пустой."""
    for port in (None, socks_port) if socks_port else (None,):
        # -f: страница ошибки сервера (4xx/5xx) — не список
        cmd = ["curl", "-fsL", "-m", "150", "--max-filesize", str(MAX_LIST), "-o", dest + ".tmp", url]
        cfg = ""
        if port:
            proxy, cfg = netprobe.curl_socks(port)  # пароль SOCKS — в конфиге на stdin, не в argv
            cmd[1:1] = proxy
        try:
            ok = subprocess.run(cmd, capture_output=True, timeout=170,
                                **({"input": cfg.encode()} if cfg else {})).returncode == 0
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
    hits, n, junk = {}, 0, 0
    names = {x.lower() for x in names} | set(bases)
    tails = tuple("." + b for b in bases)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            d = line.strip().strip('"')
            if d and any(ch in d for ch in "<>{}= \t"):
                junk += 1  # «/» мусором не считаем: в настоящем списке он бывает
            d = d.lower().rstrip(".")
            if not d or "." not in d:
                continue
            n += 1
            if d in names or d.endswith(tails):
                hits[d] = d
    if junk > max(5, n // 100):
        # страница ошибки или заглушка вместо списка: строки с точкой есть, но это не домены — источник считаем
        # нескачавшимся
        return {}, 0
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
    # когда каждый список скачался удачно в последний раз: по этому отчёт видит источник, который давно не качается
    last = dict(prev.get("last") or {})
    if "last" not in prev and prev.get("ts"):
        # состояние до этой правки: удачно скачанные в прошлый раз считаем скачанными тогда
        for k, v in (prev.get("sources") or {}).items():
            if v.get("ok"):
                last[k] = prev["ts"]
    for k in KIND:
        if data["sources"].get(k, {}).get("ok") or k not in last:
            last[k] = data["ts"]  # не скачался и раньше не знали — смотрим с этого момента
    st["lists"] = {"ts": data["ts"], "hits": merged, "sources": data["sources"], "targets": data["targets"],
                   "neighbours": near, "last": last}
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


def registry_hit(addr, lists):
    """Есть ли адрес в открытом реестре РКН (по последней сверке списков): True / False / None — сверки ещё не было.
    Подсети CDN и хостеров — не реестр, их не считаем."""
    hits = (lists or {}).get("hits")
    if not hits:
        return None
    tail = f"({addr})"
    return any(str(who).endswith(tail) for key, found in hits.items() if key.startswith("rkn") for who in found)


def hard_hits(st):
    """[(кто, название списка)] по «жёстким» спискам."""
    hits = (st.get("lists") or {}).get("hits", {})
    return [(who, LIST_NAMES[key]) for key, (_, level) in KIND.items() if level == "hard" for who in hits.get(key, {})]


def near_hits(st):
    """[(кто, сколько)] — рядом с какими нашими адресами (в той же подсети /24) в реестре есть чужие адреса."""
    return sorted(((st.get("lists") or {}).get("neighbours") or {}).items())


# ---------- 2. подмена DNS ----------

def doh(name, socks_port=None, first=False):
    """Адреса имени по защищённому DNS (DoH, JSON) — напрямую или через канал сторожа; None — не ответили.
    first — хватит первого ответившего сервиса (быстрее, для сверки адреса перед Globalping)."""
    found = None
    for tpl in DOH:
        if first and found is not None:
            break
        cmd = ["curl", "-s", "-m", "8", "-H", "accept: application/dns-json", tpl.format(urllib.parse.quote(name))]
        cfg = ""
        if socks_port:
            proxy, cfg = netprobe.curl_socks(socks_port)
            cmd[1:1] = proxy
        try:
            data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=12,
                                             **({"input": cfg} if cfg else {})).stdout)
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
    """Что отвечает обычный DNS: {кто: (итог, [адреса])}. Наше имя — системный резолвер rf1 и системный DNS точек
    проверки, которые умеют /dns без публичных резолверов; чужое имя из DNS_REF_NAMES — ещё и публичные по UDP."""
    seen = {"rf1: системный": netprobe.resolve_system(name)}
    if name in DNS_REF_NAMES:
        for who, ip in RESOLVERS:
            seen[f"rf1: {who}"] = netprobe.dns_udp(name, ip)
        return seen  # точкам чужие имена не разрешены
    for a in agents:
        if not a.get(AGENT_DNS_CAP):
            continue  # старый агент спросил бы о нашем имени публичные DNS открытым текстом — ему не отдаём
        data = agent_get(a, "/dns?name=" + urllib.parse.quote(name) + "&udp=0", 12)
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


def agent_dns_udp0(agent):
    """Умеет ли агент /dns?udp=0 (только системный DNS): так он пишет в /health, в списке "caps"."""
    caps = (agent_get(agent, "/health", 8) or {}).get("caps")
    return isinstance(caps, list) and AGENT_DNS_CAP in caps


def agents_each(fn, agents):
    """fn(точка) для всех точек разом: [результат] в порядке agents. Недоступная точка (ожидание до таймаута)
    не задерживает остальные — шаг занимает одно ожидание, а не сумму."""
    agents = list(agents)
    if not agents:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(agents))) as ex:
        return list(ex.map(fn, agents))


def dns_level(res):
    """Уровень имени для тревоги «Подмена DNS»: 'bad' — разошлись не меньше DNS_MIN независимых ответов; 'ok' —
    меньше; None — ответивших меньше DNS_MIN, а расхождение есть: для вывода мало, только журнал и state."""
    odd = len(res.get("odd") or [])
    if res.get("asked", 0) < DNS_MIN and odd:
        return None
    return "bad" if odd >= DNS_MIN else "ok"


def dns_path(socks_port):
    """Подменяют ли по пути ответы публичных DNS по UDP — на чужих именах DNS_REF_NAMES: [[кто, имя, что ответил]],
    если хоть на одном имени разошлись не меньше DNS_MIN публичных резолверов; иначе []."""
    out = []
    for name in DNS_REF_NAMES:
        truth = dns_truth(name, socks_port)
        if not truth:
            continue
        public = {who: res for who, res in dns_observe(name).items() if not who.endswith(": системный")}
        odd = dns_judge(truth, public)
        if len(odd) >= DNS_MIN:
            out += [[who, name, what] for who, what in odd]
    return out


def dns_check(names, socks_port, agents=()):
    """{имя: {"truth": [адреса], "odd": [[кто, что]], "asked": сколько ответов, "system": {точка: итог}}}; имя без
    ответа DoH пропускается. Если по пути подменяют ответы публичных DNS (dns_path) — у каждого имени ещё "path"."""
    out = {}
    agents = list(agents)
    agents = [dict(a, **{AGENT_DNS_CAP: cap}) for a, cap in zip(agents, agents_each(agent_dns_udp0, agents))]

    def one(name):
        truth = dns_truth(name, socks_port)
        if truth is None:
            return name, None
        seen = dns_observe(name, agents)
        system = {who.split(": ")[0]: st for who, (st, _) in seen.items() if who.endswith(": системный")}
        return name, {"truth": sorted(truth), "odd": [list(x) for x in dns_judge(truth, seen)],
                      "asked": sum(1 for s, _ in seen.values() if s != "err"), "system": system}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        f_path = ex.submit(dns_path, socks_port)
        for name, res in ex.map(one, names):
            if res is not None:
                out[name] = res
        path = f_path.result()
    if path:
        for res in out.values():
            res["path"] = path
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
            "вы сами, это может быть устаревший ответ и пройдёт само.\n" + dns_path_text(res.get("path")) +
            "<b>Для пользователей:</b> у кого DNS оператора — приложение не найдёт сервер по этому имени.")


def dns_path_text(path):
    """Строка к тревоге о подмене: публичные DNS по UDP отвечают не то и на чужие имена (dns_path)."""
    if not path:
        return ""
    names = sorted({name for _, name, _ in path})
    return (f"<b>По пути:</b> публичные DNS по UDP отвечают не то и на чужие имена ({html.escape(', '.join(names))}) "
            "— ответы подменяют по дороге (ТСПУ).\n")


# ---------- 3. точки проверки и разбор сбоя ----------

def agents_cfg():
    return [a for a in read_etc(VANTAGE, []) if a.get("url") and a.get("token") and a.get("name")]


def add_vantage(text):
    """Добавить точку проверки в vantage.json (probe.py --add-vantage): text — запись, которую печатает
    vantage_install.sh --entry. Точка с тем же названием заменяется. Возвращает названия всех точек."""
    new = json.loads(text)
    if not (isinstance(new, dict) and all(isinstance(new.get(k), str) and new[k] for k in ("name", "url", "token"))):
        raise ValueError("запись точки проверки не того вида: нужны name, url и token")
    if vantage_client is not None:
        vantage_client.check_entry(new)  # sha256, если есть, — настоящий отпечаток, иначе точка молча замолчит
    elif "sha256" in new:
        raise ValueError("в записи точки есть sha256, а рядом со сторожем нет vantage_client.py — "
                         "сначала обновите сторож (install.sh), иначе точка не будет отвечать")
    path = os.path.join(ETC, VANTAGE)
    items = [a for a in read_etc(VANTAGE, []) if a.get("name") != new["name"]] + [new]
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    os.replace(path + ".tmp", path)
    return [a["name"] for a in items]


def agent_get(agent, path, timeout=20):
    """Запрос к агенту точки проверки; None — не ответил или ответил не тем. У точки в vantage.json есть "sha256" —
    только TLS с этим сертификатом (vantage_client), на HTTP не откатываемся: иначе подменивший ответ TLS на пути
    получил бы X-Token и вопросы открытым текстом. Нет "sha256" — по-старому, HTTP."""
    if agent.get("sha256"):
        return vantage_client.agent_get(agent, path, timeout) if vantage_client is not None else None
    try:
        req = urllib.request.Request(agent["url"].rstrip("/") + path, headers={"X-Token": agent["token"]})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(262144).decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # сеть, отказ, не JSON — для сторожа одно и то же: «точка не ответила»
        return None


def agents_health(agents):
    """{точка: на связи ли} — /health всех точек разом, а не по очереди по 8 с."""
    agents = list(agents)
    oks = agents_each(lambda a: bool((agent_get(a, "/health", 8) or {}).get("ok")), agents)
    return {a["name"]: v for a, v in zip(agents, oks)}


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


def vpn_line(st, now=None):
    """Строка обычного отчёта: сколько плиток работает через VPN с каждой VPN-точки. Обход старше VPN_STALE — не данные
    (None; о нём говорит block_items)."""
    if side_age(st.get("vpn_pt"), VPN_STALE, now) is not None:
        return None
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


def profiles_line(st, now=None):
    """Строка обычного отчёта: сколько точек за фильтром. Профиль старше PROFILE_STALE — не данные (None; о нём
    говорит block_items)."""
    if side_age(st.get("profiles"), PROFILE_STALE, now) is not None:
        return None
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


def agent_bundle(agent, i, query, verify=False):
    """Всё, что точка проверки делает при разборе: проверка входа, серия соединений, сравнение имён (с меткой). Если
    вход с точки закрыт — ещё путь до ноды и «закрыто ли имя», параллельно с серией (у агента шесть мест).
    verify — просить сверку сертификата (старый агент параметр не знает и проверяет как раньше).
    (вход, серия, имена, путь, имя на чужом сервере); старый агент на новое не отвечает — там None."""
    probe_q = "/probe?" + query + ("&verify=1" if verify else "")
    probe = agent_get(agent, probe_q, 25)
    closed = bool(probe and probe.get("tcp") in ("timeout", "refused"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        f_more = ex.submit(lambda: (agent_get(agent, "/path?" + query, 30),
                                    agent_get(agent, "/sniref?" + query, 30))) if closed else None
        ser = agent_get(agent, f"/series?{query}&n={DEEP_SERIES}&mss={point_mss(i)}", 30)
        if probe and probe.get("tcp") == "timeout" and ser and ser.get("ok"):
            probe = agent_get(agent, probe_q, 25) or probe  # одиночная проверка попала на потерянное соединение
        cmp_ = agent_get(agent, f"/sni?{query}&mss={tls_mss(i)}", 30)
        path, ref = f_more.result() if f_more else (None, None)
    return probe, ser, cmp_, path, ref


def abroad_vias(cands, ch, exits=None):
    """Через какие чужие каналы смотреть на вход ch из-за рубежа: не больше ABROAD_VIAS, список {"name", "port"}.
    cands — уже отобранные живые каналы без expected_exit, по порядку: {"name" (для показа), "port", "entry",
    "key" (полное имя канала — по нему ищем выход в exits)}. Вход посредника не совпадает со входом ch, входы выбранных
    разные. Выход (exits[полное имя], если известен) не совпадает с выходом ch: иначе посредник, возможно, выходит
    через ту же ноду и стучится к ней же — «не отвечает» будет ложным; выходы выбранных тоже разные. Неизвестный
    выход кандидата не отсекает."""
    exits = exits or {}
    own = exits.get(ch.get("name"))
    out, entries, seen = [], set(), set()
    for c in cands:
        entry, ex = c.get("entry"), exits.get(c.get("key", c.get("name")))
        if entry == ch.get("entry") or entry in entries:
            continue
        if ex and ((own and ex == own) or ex in seen):
            continue
        out.append({"name": c["name"], "port": c["port"]})
        entries.add(entry)
        if ex:
            seen.add(ex)
        if len(out) >= ABROAD_VIAS:
            break
    return out


def abroad_check(vias, host, port, tls=False, sni=None):
    """Отвечает ли вход host:port из-за рубежа — через чужие каналы vias (список {"name", "port"}, первый — основной).
    Сначала цель через vias[0]; ответила — всё (обычный случай, один запрос). Нет — один параллельный шаг: контрольный
    адрес через vias[0] (довозит ли сам канал), цель через vias[1] (если его нет — ещё раз через vias[0]) и контроль
    через vias[1]. К цели — не больше двух запросов: меньше шансов попасть под антискан ноды.
    Подтвердил «не отвечает» тот канал, у которого цель молчит, а контрольный адрес открылся.
    {"ok": True|False|None, "tries": [[имя, цель, контроль|None], ...], "sure": 0|1|2 (сколько каналов подтвердили
    «не отвечает»), "via": имена для показа, "port": порт канала, который точно довозит (для сверки с нодой)}.
    None — проверить не удалось: обходной канал сам не работал."""
    tries = []
    first = vias[0] if vias else None
    try:
        kw = {"sni": sni} if sni else {}

        def target(v):
            return nodewatch.socks_open(v["port"], host, port, 5, tls, **kw)

        def control(v):
            return nodewatch.socks_open(v["port"], ABROAD_CONTROL, 443, 5, True)
        if not vias:
            return {"ok": None, "tries": tries, "sure": 0, "via": None, "port": None}
        a = vias[0]
        if target(a):
            tries.append([a["name"], True, None])
            return {"ok": True, "tries": tries, "sure": 0, "via": a["name"], "port": a["port"]}
        b = vias[1] if len(vias) > 1 else a
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            f_ca = ex.submit(control, a)
            f_tb = ex.submit(target, b)
            f_cb = ex.submit(control, b) if b is not a else None
            ca, tb = bool(f_ca.result()), bool(f_tb.result())
            cb = bool(f_cb.result()) if f_cb else ca
        tries += [[a["name"], False, ca], [b["name"], tb, cb]]
        if tb:
            return {"ok": True, "tries": tries, "sure": 0, "via": b["name"], "port": b["port"]}
        sure = [v for v, c in ((a, ca), (b, cb)) if c]
        sure = [v for i, v in enumerate(sure) if v not in sure[:i]]   # один канал дважды — один подтвердивший
        good = sure[0]["port"] if sure else a["port"]
        if sure:
            return {"ok": False, "tries": tries, "sure": len(sure), "via": " и ".join(v["name"] for v in sure),
                    "port": good}
        names = list(dict.fromkeys(v["name"] for v in (a, b)))
        return {"ok": None, "tries": tries, "sure": 0, "via": " и ".join(names), "port": good}
    except Exception:  # noqa: BLE001 — проверка из-за рубежа не должна сорвать разбор канала
        if not tries and first:
            tries.append([first["name"], None, None])
        # err — сорвалась сама проверка (ошибка в коде или окружении), а не «обходной канал не довёз»
        return {"ok": None, "tries": tries, "sure": 0, "via": first["name"] if first else None,
                "port": first["port"] if first else None, "err": True}


def _until(f, deadline, default=None):
    """Результат f, но не позже deadline (time.monotonic; None — ждать сколько нужно). Не успел — default и отметка
    LINGER: поток ещё работает, и выход процесса его ждать не должен. Ошибка внутри f — как раньше, наружу."""
    global LINGER
    if f is None:
        return default
    if deadline is None:
        return f.result()
    try:
        return f.result(timeout=max(0.0, deadline - time.monotonic()))
    except concurrent.futures.TimeoutError:
        LINGER = True
        return default


def deep_diag(ch, via, agents, bases, deadline=None):
    """Канал не работает: посмотреть на его вход напрямую с rf1, с других российских точек, из-за рубежа и трассировкой.
    С каждой точки: проверка входа (порт, TLS, 64 КБ), серия из DEEP_SERIES соединений и сравнение имён TLS.
    via — живые зарубежные каналы: список {"name", "port"} (из abroad_vias; сверяем через первые ABROAD_VIAS),
    один такой словарь (как раньше) либо None.
    deadline — срок (time.monotonic): что не успело к нему, в разбор не входит — точка, не успевшая ответить, попадает
    в d["late"], из-за рубежа и Globalping остаются None, сверки с нодой нет. Без срока — ждём всё, как раньше."""
    host, port = ch.get("entry"), int(ch.get("entry_port") or 443)
    vias = via if isinstance(via, list) else ([via] if via else [])
    tls_in = ch.get("security") in ("reality", "tls")
    hello = ch.get("sni") if tls_in and ch.get("sni") and ch.get("sni") != host else None   # имя прикрытия Reality
    sni = ch.get("sni") or host
    own = str(host).endswith(tuple("." + b for b in bases)) and sni == host
    query = f"host={urllib.parse.quote(str(host))}&port={port}" + ("" if sni == host else f"&sni={urllib.parse.quote(sni)}")
    verify = CERT_CHECK and ch.get("security") == "tls"   # у Reality сертификат чужой по устройству — не сверяем
    # внешний сервис — в своём потоке-демоне: стартует, как только порт не открылся (с rf1 или с двух точек), идёт
    # параллельно с остальным, а выход процесса его не ждёт
    f_ext, t_ext = None, None

    def ext_start(addrs):
        return daemon_call(ext_job, host, addrs, port), time.monotonic()
    # со сроком пул не ждёт отставших при выходе из разбора (shutdown без ожидания), без срока — как раньше, ждёт всех
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(agents) + 6)
    try:
        f_direct = ex.submit(direct_check, host, port, sni, verify)
        f_series = ex.submit(netprobe.series, host, port, DEEP_SERIES, point_mss(0))
        f_sni = ex.submit(netprobe.sni_compare, host, port, sni, tls_mss(0))
        f_agents = {a["name"]: (ex.submit(agent_bundle, a, i + 1, query, True) if verify
                                else ex.submit(agent_bundle, a, i + 1, query)) for i, a in enumerate(agents)}
        f_abroad = ex.submit(abroad_check, vias[:ABROAD_VIAS], host, port, tls_in, hello) if vias else None
        # прямая проверка с rf1 сама ограничена ~17 с, без неё разбора нет — её ждём всегда
        direct, series, names = f_direct.result(), {SELF: _until(f_series, deadline)}, {SELF: _until(f_sni, deadline)}
        if direct["tcp"] == "timeout" and (series[SELF] or {}).get("ok"):
            direct = direct_check(host, port, sni, verify)  # одиночная проверка попала на потерянное соединение
        if ext_trouble(direct):
            f_ext, t_ext = ext_start([direct.get("addr")])
        f_ref = ex.submit(netprobe.name_ref, sni) if direct["tcp"] in ("timeout", "refused") else None
        f_vpn = {a["name"]: ex.submit(agent_get, a, "/vpn?name=" + urllib.parse.quote(ch["name"]), 40)
                 for a in vpn_points(agents)}
        probes, paths, refs, late = {}, {}, {}, []
        for name, f in f_agents.items():
            got = _until(f, deadline)
            if got is None:
                if own:
                    late.append(name)   # точка не успела к сроку — это не «не ответила»
                    probes[name], series[name], names[name] = None, None, None
                continue
            probe, ser, cmp_, path, ref = got
            if probe is None and not own:
                continue  # адрес вне наших доменов этой точке не разрешён — она не «не ответила», её не спрашивали
            probes[name], series[name], names[name] = probe, ser, cmp_
            if path:
                paths[name] = path
            if ref:
                refs[name] = ref
        own_ref = _until(f_ref, deadline)
        if own_ref:
            refs[SELF] = own_ref
        if f_ext is None and ext_wanted(direct, probes):
            f_ext, t_ext = ext_start([direct.get("addr")] + [p.get("addr") for p in probes.values() if p])
        closed = direct["addr"] and direct["tcp"] != "open"
        f_trace = ex.submit(netprobe.tcp_trace, direct["addr"], port) if closed else None
        f_nb = ex.submit(netprobe.neighbours, direct["addr"]) if closed else None
        d = {"direct": direct, "agents": probes, "series": series, "sni": names,
             "abroad": None, "via": None, "abroad_tries": [], "abroad_sure": 0,
             "trace": _until(f_trace, deadline), "external": None,
             "paths": paths, "refs": refs, "vpn": {n: _until(f, deadline) for n, f in f_vpn.items()},
             "neighbours": _until(f_nb, deadline),
             "registry": registry_hit(direct["addr"], read_json_file(LISTS_FILE)) if closed else None}
        if late:
            d["late"] = late
        ab = _until(f_abroad, deadline)
    finally:
        ex.shutdown(wait=deadline is None, cancel_futures=deadline is not None)
    if ab:
        d.update(abroad=ab["ok"], via=ab["via"], abroad_tries=ab["tries"], abroad_sure=ab["sure"])
        if ab.get("err"):
            d["abroad_err"] = True
    # что из этих серий видела сама нода (её счётчики лежат рядом с маячком; забираем и через живой чужой канал)
    beacon = next((n.get("beacon") for n in read_etc("nodes.json", []) if n.get("host") == host), None)
    tls = {f"{n}|tls": t for n, t in ((n, tls_ser(c)) for n, c in names.items()) if t}
    wit_args = (witness_url(beacon), {**series, **tls}, ab["port"] if ab else None)
    if port != 443:
        d["witness"] = {}
    elif deadline is None:
        d["witness"] = witness_wait(*wit_args)
    else:   # счётчики ноды — в потоке-демоне и не дольше срока: забор файла через канал бывает долгим
        d["witness"] = _until(daemon_call(witness_wait, *wit_args), deadline, {})
    if deadline is None or time.monotonic() < deadline:
        add_hop_info(d, own=netprobe.own_addr(), origins=agent_origins(agents))   # чей последний узел трассировки
    if f_ext is not None:
        end = t_ext + EXT_WAIT if deadline is None else min(t_ext + EXT_WAIT, deadline)
        try:   # ждём не дольше срока от старта (сверка адреса по DoH и весь check Globalping) и не дольше срока разбора
            d["external"] = f_ext.result(timeout=max(0.1, end - time.monotonic()))
        except Exception:  # noqa: BLE001 — внешний сервис не должен сорвать разбор
            d["external"] = None
    return d


def daemon_call(fn, *args):
    """fn(*args) в отдельном потоке-демоне -> Future. В отличие от ThreadPoolExecutor, выход процесса такой поток
    не ждёт: задержавшийся внешний сервис не держит службу до TimeoutStartSec и не съедает её сообщение."""
    fut = concurrent.futures.Future()

    def run():
        if fut.set_running_or_notify_cancel():
            try:
                fut.set_result(fn(*args))
            except BaseException as e:  # noqa: BLE001 — отдаём ожидающему
                fut.set_exception(e)
    threading.Thread(target=run, daemon=True).start()
    return fut


def direct_check(host, port, sni, verify=False):
    """Прямая проверка входа с rf1; со сверкой сертификата, если её просят и netprobe её умеет (старый — как раньше)."""
    if verify:
        try:
            params = inspect.signature(netprobe.direct_probe).parameters
        except (TypeError, ValueError):
            params = {}
        if "verify" in params or any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return netprobe.direct_probe(host, port, sni, verify=True)
    return netprobe.direct_probe(host, port, sni)


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


WITNESS_MAX = 400000  # файл свидетеля больше — не берём (--max-filesize у curl, предел и для TLS)


def witness_pin(url):
    """Отпечаток сертификата для файла свидетеля: поле "sha256" у ноды в nodes.json, чей маячок лежит рядом
    (witness_url(маячок) == url; маячок в режиме --serve отдаёт flows.json тем же сервером и по TLS).
    None — поля нет (по-старому, HTTP); строка — только TLS с этим отпечатком ('' — испорченное поле)."""
    return nodewatch.beacon_pin(url, derive=witness_url)


def fetch_witness(url, socks_port=None, sha256=None):
    """Счётчики ноды: {"ts", "flows": [[время, метка, SYN, SYN-ACK, RST от ноды, RST к ноде], ...]} либо None.
    Напрямую; не вышло и есть живой канал — через него (нода может быть закрыта из России).
    У ноды в nodes.json есть "sha256" (или sha256 передан) — только TLS с этим сертификатом и напрямую, и через канал
    (nodewatch.pinned_get, тот же код, что у маячка), без отката на HTTP: счётчики не видны на пути и не
    подменяются. Нет отпечатка — по-старому, curl по HTTP."""
    if not url:
        return None
    pin = witness_pin(url) if sha256 is None else str(sha256 or "")
    for port in (None, socks_port) if socks_port else (None,):
        try:
            if pin is not None:
                raw = nodewatch.pinned_get(url, pin, 10, WITNESS_MAX, socks_port=port)
                if raw is None:
                    continue
                data = json.loads(raw.decode("utf-8"))
            else:
                cmd = ["curl", "-s", "-m", "10", "--max-filesize", str(WITNESS_MAX), "-H", "Cache-Control: no-cache", url]
                cfg = ""
                if port:
                    proxy, cfg = netprobe.curl_socks(port)
                    cmd[1:1] = proxy
                data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=14,
                                                 **({"input": cfg} if cfg else {})).stdout)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("flows"), list) and isinstance(data.get("ts"), (int, float)):
            return data
    return None


def witness_match(wit, ser, slack=20):
    """Что нода видела из серии ser (по метке и времени): {"seen" — сколько соединений дошло, "rep" — на скольких
    нода повторяла ответ (её ответ не дошёл обратно), "rst_out", "rst_in", "mute" — сколько дошло, а нода не ответила
    ничем}; None — сверить нечем. В старых сверках (loss.json) "mute" нет — читать через w.get("mute")."""
    if not wit or not ser or not ser.get("mss") or not ser.get("t1") or wit["ts"] < ser["t1"] + WITNESS_LAG:
        return None  # файл ноды записан раньше, чем нода досчитала эту серию
    if wit.get("since", 0) > ser["t0"]:
        return None  # свидетель на ноде запущен позже начала серии — целиком он её не видел
    rows = [f for f in wit["flows"] if len(f) >= 6 and f[1] == ser["mss"] and ser["t0"] - slack <= f[0] <= ser["t1"] + slack]
    if len(rows) < (ser.get("ok") or 0):
        return None  # нода насчитала меньше соединений, чем прошло успешно, — её счётчики неполны, судить по ним нельзя
    return {"seen": len(rows), "rep": sum(1 for f in rows if f[3] >= 3),
            "rst_out": sum(f[4] for f in rows), "rst_in": sum(f[5] for f in rows),
            "mute": sum(1 for f in rows if f[3] == 0 and f[4] == 0)}


def witness_refusal(ser, w):
    """Отказывает ли этой серии сама нода, по её счётчикам: 'drop' — дошли все, нода не ответила ни на одно, и отказов
    точке не приходило;
    'reject' — дошли все, нода сама сбросила каждое; 'part' — часть прошла, остальные дошли, но нода на них
    промолчала (лимит соединений или перегрузка); None — нет или судить не по чему."""
    if not w or not ser or w.get("mute") is None or w["rep"] or w["seen"] < WIT_MIN:
        return None
    fail, refused = ser.get("fail") or 0, ser.get("refused") or 0
    if not fail + refused or w["seen"] < ser["n"] - 1:
        return None   # потерь нет, либо часть запросов не дошла — тогда теряется и по дороге
    if not ser.get("ok"):
        # нода молчала, а точке пришёл отказ — отказ прислал кто-то по дороге (свой REJECT нода видит как rst_out)
        if w["mute"] == w["seen"] and not refused:
            return "drop"
        if refused and not fail and w["rst_out"] >= refused and w["mute"] == 0:
            return "reject"
        return None
    if fail and not refused and w["mute"] >= fail:
        return "part"
    return None


def node_refused(d, pts):
    """{точка: 'drop' | 'reject'} — каким точкам из pts (с бедой на уровне TCP), по счётчикам ноды, отказывает сама нода."""
    series, wit = d.get("series") or {}, d.get("witness") or {}
    out = {p: witness_refusal(series.get(p), wit.get(p)) for p in pts}
    return {p: k for p, k in out.items() if k in ("drop", "reject")}


def witness_text(ser, w):
    """Сверка серии с нодой одной фразой; None — сказать нечего."""
    if not w or not ser or not (ser.get("fail") or ser.get("refused")):
        return None
    n, seen = ser["n"], w["seen"]
    kind, k = witness_refusal(ser, w), min(seen, n)   # при двух разборах подряд нода может насчитать больше серии
    if kind == "drop":
        return (f"нода получила все {k}, но не ответила ни на одно — их отбрасывает сама нода "
                "(файрвол, бан адреса или перегрузка)")
    if kind == "reject":
        return f"нода получила все {k} и сама сбросила каждое — отказ на самой ноде"
    if kind == "part":
        return (f"нода получила {k} из {n}, на {w['mute']} не ответила вовсе — часть запросов отбрасывает сама нода "
                "(лимит соединений или перегрузка)")
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
    return f"нода получила {k} из {n} — где теряется, по её счётчикам не видно"


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
    return {k: r.get(k) for k in ("n", "ok", "fail", "slow", "refused", "ms", "t0", "t1", "mss", "dns", "addr")}


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


def loss_shut(r):
    """Серия, в которой не открылось ни одно соединение из первых SERIES_GIVEUP: вход закрыт. Судим по полям
    серии, а не по тому, когда бросает серию агент точки: у агента своя копия netprobe."""
    return bool(r and r.get("n", 0) >= netprobe.SERIES_GIVEUP and not r.get("ok")
                and (r.get("fail") or 0) + (r.get("refused") or 0) == r["n"])


def pair_judge(pts, point):
    """Серия точки к ноде одним словом с оглядкой на сервер сторожа: 'closed' — с точки не открылось ни одно
    соединение, а с сервера сторожа открывается не меньше половины; не открывается и с него — нода недоступна
    целиком, это видно по каналам, тут не судим (None). Иначе — как loss_judge."""
    r = pts.get(point)
    if point != SELF and loss_shut(r):
        ref = pts.get(SELF)
        return "closed" if ref and ref.get("n") and (ref.get("ok") or 0) * 2 >= ref["n"] else None
    return loss_judge(r)


def loss_pct(r):
    return round(100.0 * r["fail"] / r["n"]) if r and r.get("n") else 0


def point_view(data, point):
    """Как точка проверила ноды в этом замере: 'blind' — ничего не проверила (не ответила, не нашла ни одного имени,
    ни одного соединения), 'shut' — к большинству нод не открывается ни одно соединение, а с сервера сторожа они
    открываются, 'noisy' — потери или закрытый вход к большинству нод сразу, 'ok' — иначе."""
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if not rows or all(not r or not r.get("n") or not (r.get("ok") or r.get("fail") or r.get("refused")) for r in rows):
        return "blind"
    judged = [pair_judge(pts, point) for pts in data["nodes"].values()]
    closed, bad, lim = judged.count("closed"), judged.count("bad"), max(3, (len(rows) + 1) // 2)
    if closed >= lim:
        return "shut"
    if bad + closed >= lim:
        return "noisy"
    return "ok"


def point_why(data, point):
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if all(not r for r in rows):
        return "точка не отвечает"
    if all(not r or not r.get("n") for r in rows):
        return "ни свой, ни публичный DNS не нашёл ни одного имени ноды"
    return "не открылось ни одного соединения"


def shut_why(data, point, shut):
    """Почему с точки не открываются ноды shut — по счётчикам нод на её сериях: бан на нодах или блокировка по дороге."""
    rows = [data["nodes"][n].get(point) for n in shut]
    wits = [r.get("wit") for r in rows if r and r.get("wit")]
    if rows and all(witness_refusal(r, r.get("wit")) in ("drop", "reject") for r in rows):
        return ("по счётчикам нод запросы точки доходят, и ноды сами их отклоняют — бан адреса точки на нодах "
                "(антискан, файрвол), а не блокировка")
    if rows and len(wits) == len(rows) and not any(w["seen"] for w in wits):
        return ("по счётчикам нод запросы точки до них не доходят — похоже на блокировку наших адресов у провайдера "
                "этой точки; у его абонентов эти ноды, скорее всего, тоже не открываются")
    return ("блокировка наших адресов у провайдера этой точки либо бан её адреса на нодах — по счётчикам нод "
            "не различить")


def point_alert(kind, point, data, since, now):
    rows = [pts.get(point) for pts in data["nodes"].values()]
    if kind == "blind":
        return (f"📍 <b>Точка «{html.escape(point)}» ничего не проверила</b> — {LOSS_CONFIRM} замера подряд: "
                f"{point_why(data, point)}.\nПока так, её данные в выводах не учитываются.")
    judged = {n: pair_judge(pts, point) for n, pts in sorted(data["nodes"].items())}
    shut = [n for n, k in judged.items() if k == "closed"]
    if kind == "noisy":
        bad = [n for n, k in judged.items() if k == "bad"]
        also = f", к {len(shut)} — не открывается ни одно ({', '.join(n.upper() for n in shut)})" if shut else ""
        return (f"📍 <b>У точки «{html.escape(point)}» проблемы с сетью</b>\nТеряются соединения к {len(bad)} нодам из "
                f"{len(rows)} сразу ({', '.join(n.upper() for n in bad)}){also}, {LOSS_CONFIRM} замера подряд; с других "
                "точек к этим нодам потерь нет или почти нет.\n<b>Похоже на:</b> беду сети этой точки или её провайдера, "
                "а не нод. По нодам отдельных сообщений не шлю, в разборе сбоя эту точку не учитываю.")
    if kind == "shut":
        # так выглядит и блокировка наших адресов у провайдера точки, и бан адреса точки на нодах — различают счётчики нод
        return (f"📍 <b>С точки «{html.escape(point)}» не открываются {len(shut)} нод из {len(rows)}</b>\n"
                f"{', '.join(n.upper() for n in shut)} — ни одного соединения, {LOSS_CONFIRM} замера подряд; с сервера "
                f"сторожа эти ноды открываются.\n<b>Похоже на:</b> {shut_why(data, point, shut)}.\n"
                "По нодам отдельных сообщений не шлю; в разборе сбоя данные точки учитываю.")
    return (f"✅ <b>Точка «{html.escape(point)}» снова в порядке</b>\nБыло с {hmsk(since)} до {hmsk(now)} МСК.")


def hmsk(ts):
    return time.strftime("%H:%M", time.gmtime(ts + 3 * 3600))


def points_step(st, data):
    """Состояние точек по замеру: ok / blind / shut / noisy, с подтверждением LOSS_CONFIRM замеров подряд.
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
    """Свежий замер -> сообщения: о точках (ослепла, не открывает ноды, проблемы с сетью, снова в порядке), о потерях
    к нодам и о закрытом с точки входе ноды, которые держатся LOSS_CONFIRM замеров подряд, и об их конце. Пары точки,
    которая сейчас не в порядке, не судятся."""
    loss = st.setdefault("loss", {})
    lvl = loss.setdefault("lvl", {})
    loss["ts"], loss["n"], loss["last"] = data["ts"], data["n"], data["nodes"]
    msgs, skip = points_step(st, data)
    # в разборе сбоя не учитываем только точки со своей бедой сети (ослепла, потери ко всем). «Не открывает ноды»
    # (shut) — улика: так выглядит и блокировка наших адресов у её провайдера; её пары лишь не судим поодиночке
    pt = loss.get("pt") or {}
    loss["skip"] = [p for p in skip if pt.get(p, {}).get("lvl") != "shut"]
    began, ended, shut_began, shut_ended, absorbed = [], [], [], [], []
    for node, pts in sorted(data["nodes"].items()):
        for point, r in pts.items():
            cur = lvl.setdefault(f"{node}|{point}", {"lvl": "ok", "cand": "ok", "n": 0})
            if point in skip:
                if cur["lvl"] in ("closed", "bad"):
                    absorbed.append((node, point, cur["lvl"]))   # о паре уже сообщали — сказать, куда она делась
                cur.update(lvl="ok", cand="ok", n=0)  # беда самой точки: о нодах с неё не судим
                continue
            obs = pair_judge(pts, point)
            if obs is None:
                if cur["lvl"] == "closed" and point != SELF and loss_shut(r):
                    # с сервера сторожа нода тоже не открывается — она недоступна целиком (это видно по каналам),
                    # «закрыт с одной точки» больше не правда: пару сбрасываем молча
                    cur.update(lvl="ok", cand="ok", n=0)
                continue
            if obs == cur["lvl"]:
                cur["cand"], cur["n"] = obs, 0
                continue
            cur["n"] = cur["n"] + 1 if obs == cur["cand"] else 1
            cur["cand"] = obs
            if cur["n"] >= LOSS_CONFIRM:
                was = cur["lvl"]
                cur["lvl"], cur["n"] = obs, 0
                if obs == "bad":
                    began.append((node, point))   # и из закрытого входа в потери — обычное сообщение о потерях
                elif obs == "closed":
                    shut_began.append((node, point))
                else:
                    (shut_ended if was == "closed" else ended).append((node, point))
    valid = {f"{node}|{point}" for node, pts in data["nodes"].items() for point in pts}
    for key in [k for k in lvl if k not in valid]:
        del lvl[key]
    return (msgs + [absorbed_text(absorbed)] * bool(absorbed)
            + ([loss_alert(began, data)] if began else []) + ([shut_alert(shut_began, data)] if shut_began else [])
            + ([loss_end(ended, data)] if ended else [])
            + ([loss_end(shut_ended, data, title="✅ <b>Вход ноды снова открыт</b>")] if shut_ended else []))


def absorbed_text(items):
    """Пары, о которых уже сообщали (закрытый вход, потери), а теперь у их точки общая беда: [(нода, точка, lvl)]."""
    by = {}
    for node, point, kind in items:
        by.setdefault(point, {"closed": [], "bad": []})[kind].append(node.upper())
    out = []
    for point, k in by.items():
        what = "; ".join(x for x in (("вход закрыт: " + ", ".join(k["closed"])) if k["closed"] else "",
                                     ("потери: " + ", ".join(k["bad"])) if k["bad"] else "") if x)
        out.append(f"ℹ️ <b>Точка «{html.escape(point)}»: ранее сообщал — {html.escape(what)}</b>\nТеперь это часть "
                   "общей беды точки (сообщение о ней — выше или раньше); отдельно эти ноды больше не веду.")
    return "\n\n".join(out)


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
    rows = [data["nodes"][node][point] for node, point in pairs]
    if rows and all(witness_refusal(r, r.get("wit")) == "part" for r in rows):
        out += ["", "<b>Что это значит:</b> нода сама отбрасывает часть подключений с этого адреса — лимит соединений "
                    "или перегрузка на ноде; клиентам мешает, когда их много за одним адресом."]
    else:
        out += ["", "<b>Что это значит:</b> у клиентов такого же провайдера часть подключений к этим нодам зависает "
                    "на старте. Сами ноды работают."]
    return "\n".join(out)


WIT_VAGUE = "где теряется, по её счётчикам не видно"   # общая фраза сверки, когда сказать по сути нечего


def shut_alert(pairs, data):
    """Сообщение о закрытом с точки входе ноды: с точки не открылось ни одно соединение, с сервера сторожа нода
    открывается. По абзацу на ноду: что видела сама нода, другой ли адрес дало имя ноды у точки."""
    by_point = loss_group(pairs)
    out = ["🚪 <b>Вход ноды закрыт с " + ("одной точки" if len(by_point) == 1 else "точек") + "</b>",
           f"<i>{LOSS_CONFIRM} замера подряд: с точки не открылось ни одно соединение</i>"]
    for point, nodes in by_point.items():
        out += ["", f"📍 Откуда: <b>{html.escape(point)}</b>"]
        for node in nodes:
            pts = data["nodes"][node]
            r, ref = pts[point], pts.get(SELF) or {}
            # число попыток — у каждой ноды своё: старый агент серию не бросает и делает все 30
            out += ["", f"• <b>{html.escape(node.upper())}</b> — с точки 0 из {r.get('n')}, с сервера сторожа проходит "
                        f"{ref.get('ok')} из {ref.get('n')}"]
            note = witness_text(r, r.get("wit"))
            if note and not note.endswith(WIT_VAGUE):   # при закрытом входе общая фраза только путает
                out.append("   ↳ " + html.escape(note))
            if r.get("addr") and ref.get("addr") and r["addr"] != ref["addr"]:
                out.append("   ↳ имя ноды у точки дало другой адрес, чем у сервера сторожа")
        for node in nodes:
            pts = data["nodes"][node]
            seen = []
            for p in data.get("points", []):
                v = pts.get(p)
                if p in (point, SELF):
                    continue
                if not v or not v.get("n"):
                    seen.append(f"{p} — нет данных")
                elif loss_shut(v):
                    seen.append(f"{p} — тоже закрыт")
                elif loss_judge(v) == "bad":
                    seen.append(f"{p} — не проходит {v['fail']} из {v['n']}")
                else:
                    seen.append(f"{p} — проходит")
            if seen:
                whom = "этой ноде" if len(nodes) == 1 else node.upper()
                out += ["", html.escape(f"С других точек к {whom}: " + ", ".join(seen))]
    rows = [data["nodes"][node][point] for node, point in pairs]
    if all(witness_refusal(r, r.get("wit")) in ("drop", "reject") for r in rows):
        out += ["", "<b>Что это значит:</b> нода сама не принимает подключения с адреса этой точки (файрвол или бан "
                    "адреса); у остальных клиентов она работает."]
    else:
        out += ["", "<b>Что это значит:</b> клиенты такого же провайдера к " + ("этой ноде" if len(rows) == 1
                    else "этим нодам") + " не подключаются, у остальных " + ("она работает." if len(rows) == 1
                                                                          else "они работают.")]
    return "\n".join(out)


def loss_end(pairs, data, title="✅ <b>Потери соединений прошли</b>"):
    out = [title, f"<i>{LOSS_CONFIRM} замера подряд без потерь</i>"]
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


def loss_shut_now(st, now):
    """Пары (нода, точка) с подтверждённым закрытым входом по свежему замеру; замер устарел — пусто."""
    loss = st.get("loss") or {}
    if not loss.get("ts") or now - loss["ts"] > LOSS_STALE:
        return []
    return [tuple(key.split("|", 1)) for key, v in sorted(loss.get("lvl", {}).items()) if v.get("lvl") == "closed"]


def loss_log_pair(node, point, r):
    if loss_shut(r):
        return f"{node} — {point} закрыт {r.get('ok') or 0}/{r['n']}"
    return f"{node} — {point} {r.get('fail') or 0}/{r['n']}" + (f", сброшено {r['refused']}" if r.get("refused") else "")


def loss_log(data):
    """Замер одной строкой для журнала сторожа."""
    bad = [loss_log_pair(node, point, r) for node, pts in sorted(data["nodes"].items())
           for point, r in pts.items() if r and (r.get("fail") or r.get("refused"))]
    asked = sum(1 for pts in data["nodes"].values() for r in pts.values() if r)
    total = sum(len(pts) for pts in data["nodes"].values())
    return f"потери с точек: серий {asked} из {total}; не прошло: " + ("; ".join(bad) or "нигде")


def deep_many(chans, via_for, agents, bases, deadline=None):
    """Разбор нескольких каналов разом (не больше DEEP_MAX): {имя канала: результат deep_diag}.
    deadline — срок (time.monotonic): разбор каждого канала укладывается в него (см. deep_diag), канал, чей разбор
    не кончился и через DEEP_TAIL после срока, в ответ не входит."""
    chans = chans[:DEEP_MAX]
    if not chans:
        return {}
    if deadline is None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(chans)) as ex:
            return dict(zip((c["name"] for c in chans), ex.map(lambda c: deep_diag(c, via_for(c), agents, bases), chans)))
    # со сроком: каждый канал в своём потоке-демоне, отдаём то, что готово, — по каналу, а не всё или ничего
    futs = {c["name"]: daemon_call(deep_diag, c, via_for(c), agents, bases, deadline) for c in chans}
    out = {}
    for name, f in futs.items():
        try:
            got = _until(f, deadline + DEEP_TAIL)
        except Exception:  # noqa: BLE001 — сорвался разбор одного канала: остальные всё равно отдаём
            continue
        if got is not None:
            out[name] = got
    return out


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


def cert_why(r):
    """Чем не тот сертификат (по netprobe.cert_check) — для текста."""
    cn = str(r.get("cert_cn") or "")[:80]
    if r.get("cert") == "name":
        return f"выдан на другое имя ({cn})" if cn else "выдан на другое имя"
    if r.get("cert") == "expired":
        return "просрочен"
    return "не заверен доверенным центром" + (f" (на имя {cn})" if cn else "")


def cert_verdict(points, results):
    """Вывод «сертификат не тот», если хоть одна точка его видит; None — не тот случай. points — {точка: класс},
    results — {точка: проба}. Точка, где сертификат сверен и он настоящий, — довод против (подмена у части путей)."""
    bad = [p for p, k in points.items() if k == "cert"]
    if not bad:
        return None
    real = [p for p, k in points.items() if k == "ok" and (results.get(p) or {}).get("cert") == "ok"]
    why = cert_why(results[bad[0]])
    if real:
        return (f"с части российских точек ({', '.join(bad)}) отдаётся не тот сертификат — {why}, а с других "
                f"({', '.join(real)}) настоящий: похоже на подмену по пути у отдельных провайдеров")
    where = "с rf1" if bad == [SELF] else f"с точек: {', '.join(bad)}"
    down = [p for p, k in points.items() if k not in ("cert", "ok", "none")]
    return (f"сервер отвечает {where}, но сертификат не тот — {why}: клиенты получат ошибку TLS. Похоже, CDN или фронт "
            "отдаёт свой сертификат вместо нашего (ресурс выключен, кончился срок, сменили настройки) — дело не в Xray "
            "и не в блокировке адреса" + (f"; с {', '.join(down)} нода не отвечает вовсе" if down else ""))


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
    if kind == "cert":
        return f"порт открыт ({r['tcp_ms']} мс), TLS отвечает, но сертификат не тот: {cert_why(r)}"
    if kind == "stall":
        return f"соединение есть, но данные встали после {max(1, r['bytes'] // 1024)} КБ"
    if r["end"] == "ok":
        return f"порт открыт ({r['tcp_ms']} мс), TLS отвечает, {r['need'] // 1024} КБ получены"
    return f"порт открыт ({r['tcp_ms']} мс), TLS отвечает" if r["tls"] else f"порт открыт ({r['tcp_ms']} мс)"


HOP_CACHE = "/var/lib/channel-watch/hops.json"   # кто владеет узлами трассировки: {адрес: {"ts", "info"}}
HOP_TTL = 7 * 86400
HOP_LOOKUP = None                                  # подмена запроса к гео-базе (тесты); None — ipinfo.io
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def hop_lookup(ip, timeout=6):
    """Сеть, страна и город адреса по ipinfo.io: {"org", "country", "city"} или None."""
    try:
        out = subprocess.run(["curl", "-s", "-m", str(timeout), f"https://ipinfo.io/{ip}/json"],
                             capture_output=True, text=True, timeout=timeout + 4).stdout
        d = json.loads(out)
        return d if isinstance(d, dict) and (d.get("org") or d.get("country")) else None
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return None


def hop_info(ip, lookup=None, cache_file=None, now=None):
    """Чей узел: «AS1299 Arelion Sweden AB · SE Stockholm»; частный адрес — «внутренняя сеть хостера»; не узнали — ""."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return ""
    if a.is_private or a.is_loopback or a.is_link_local or (a.version == 4 and a in CGNAT):
        return "внутренняя сеть хостера"
    cache_file, now = cache_file or HOP_CACHE, now or time.time()
    try:
        cache = json.load(open(cache_file, encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    hit = cache.get(str(a))
    if hit and now - hit.get("ts", 0) <= HOP_TTL:
        return hit.get("info", "")
    d = (lookup or HOP_LOOKUP or hop_lookup)(str(a))
    if not d:
        return ""
    where = " ".join(x for x in (d.get("country"), d.get("city")) if x)
    info = " · ".join(x for x in (str(d.get("org") or "").strip(), where) if x)
    cache[str(a)] = {"ts": int(now), "info": info}
    try:
        with open(cache_file + ".tmp", "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.replace(cache_file + ".tmp", cache_file)
    except OSError:
        pass
    return info


def _public(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or (a.version == 4 and a in CGNAT))


def last_owner(t, own, lookup=None, cache_file=None):
    """Чей последний ответивший узел. Внешний — его сеть; внутренний — внешний узел перед ним, а если внешних не было —
    сеть самой точки, откуда идёт проверка (адрес own)."""
    ttl, ip = t["last"][0], t["last"][1]
    if _public(ip):
        return hop_info(ip, lookup, cache_file)
    steps = t.get("seen") or [[r[0], r[2]] for r in t.get("list") or [] if r[2]]
    before = [a for n, a in steps if n < ttl and _public(a)]
    if before:
        info = hop_info(before[-1], lookup, cache_file)
        return f"внутренняя сеть, перед ней — {before[-1]}" + (f" — {info}" if info else "")
    if own and _public(own):
        info = hop_info(own, lookup, cache_file)
        return f"внутренняя сеть хостера, откуда идёт проверка: {own}" + (f" — {info}" if info else "")
    return "внутренняя сеть хостера"


def add_hop_info(d, lookup=None, cache_file=None, own=None, origins=None):
    """Разбор сбоя: к последнему ответившему узлу трассировки (с rf1 и с точек) дописать, чей он. own — внешний адрес
    самого сторожа, origins — {точка: её адрес}: по ним называется сеть, если обрыв во внутренней сети хостера."""
    t = d.get("trace")
    if t and not t.get("reached") and t.get("last"):
        t["last_info"] = last_owner(t, own, lookup, cache_file)
    for name, p in (d.get("paths") or {}).items():
        if p and not p.get("reached") and p.get("last"):
            p["last_info"] = last_owner(p, (origins or {}).get(name), lookup, cache_file)
    return d


def agent_origins(agents):
    """{точка: её адрес} из vantage.json (адрес — хост в url, если это внешний IP)."""
    out = {}
    for a in agents or []:
        host = urllib.parse.urlparse(str(a.get("url") or "")).hostname
        if host and _public(host):
            out[a.get("name")] = host
    return out


def _with_info(addr, info):
    return f"{addr} — {info}" if info else f"{addr}"


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
        return f"пропадает после шага {p['last'][0]} ({_with_info(p['last'][1], p.get('last_info'))})"
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
        if name in d.get("late", ()):
            return "не успела ответить за срок разбора"
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
    ab_line = abroad_line(d)
    if ab_line:
        lines.append(ab_line)
    t = d.get("trace")
    if t:
        if t["reached"]:
            lines.append(f"• трассировка с rf1: пакеты доходят до ноды ({t['hops']} шагов)")
        elif t["last"]:
            lines.append(f"• трассировка с rf1: пакеты пропадают после шага {t['last'][0]} ({_with_info(t['last'][1], t.get('last_info'))})")
        else:
            lines.append("• трассировка с rf1: не ответил ни один шаг")
    ext = d.get("external")
    if ext and ext.get("service") == "Globalping":
        lines.append(f"• абоненты в РФ (Globalping): {ext.get('note') or 'нет данных'}")
    elif ext:
        lines.append(f"• внешняя проверка ({ext.get('service', '?')}): {ext.get('note', 'нет данных')}")
    if DEEP_EXTRA_LIVE if extra is None else extra:
        lines += deep_extra(d)
    return lines


def abroad_line(d):
    """Строка «из-за рубежа» для разбора (None — не проверяли). Попытки — d["abroad_tries"] от abroad_check."""
    ab, tries, via = d.get("abroad"), d.get("abroad_tries") or [], d.get("via")
    if ab is True:
        if len(tries) >= 2 and tries[0][1] is False:
            first, last = tries[0][0], tries[-1][0]
            if first == last:
                return f"• из-за рубежа: через {first} со второй попытки отвечает"
            return f"• из-за рубежа: через {first} не ответила, через {last} отвечает"
        return f"• из-за рубежа (через {via}): отвечает"
    if ab is False:
        # что сверка шла через один канал, говорит вывод («вывод неуверенный») — здесь не повторяем
        return f"• из-за рубежа (через {via}): не отвечает"
    if d.get("abroad_err"):
        return "• из-за рубежа: проверка сорвалась (ошибка в самой проверке)"
    if tries:
        return "• из-за рубежа: проверить не удалось — обходной канал сам не открыл контрольный адрес"
    return None


def deep_verdict(d, status):
    """На что похоже — одной фразой. status — состояние канала: DOWN или FREEZE."""
    points = {"rf1": netprobe.probe_class(d["direct"])}
    points.update({name: netprobe.probe_class(r) for name, r in d["agents"].items() if name not in d.get("skip", ())})
    answered = {k: v for k, v in points.items() if v != "none"}
    cert = cert_verdict(answered, {"rf1": d["direct"], **d["agents"]})
    if cert:
        return cert
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
        bad_kinds = {v for v in answered.values() if v != "ok"}
        # по счётчикам ноды: каким точкам с бедой на уровне TCP отказывает сама нода (tls и обрыв данных так не объяснить)
        ref = node_refused(d, [k for k, v in answered.items() if v == "tcp"])
        if points["rf1"] != "ok" and all(v == "ok" for k, v in answered.items() if k != "rf1"):
            if "rf1" in ref:
                return ("не отвечает только с rf1, а по счётчикам ноды запросы rf1 доходят и она сама их отклоняет — "
                        "нода закрылась от адреса сторожа (бан или антискан на ноде); у пользователей, скорее всего, "
                        "всё в порядке — снять бан") + ext_tail(d, bad_kinds)
            return (f"не отвечает только с rf1, с остальных точек ({good}) нода работает — сбой на стороне rf1 или "
                    "её провайдера; у пользователей, скорее всего, всё в порядке") + ext_tail(d, bad_kinds)
        if ref and len(ref) == sum(1 for v in answered.values() if v != "ok"):
            return (f"с части точек ({bad}) нода не отвечает, с других работает ({good}); по её счётчикам запросы "
                    "доходят, но она сама их отклоняет — бан адресов точек на ноде, а не провайдеры") + ext_tail(d, bad_kinds)
        return (f"с части российских точек нода не отвечает ({bad}), с других работает ({good}) — блокировка "
                "у отдельных провайдеров либо неустойчивая сеть") + tail + (
                    f"; {', '.join(ref)}: нода сама отклоняет их запросы (бан на ноде)" if ref else "") + ext_tail(d, bad_kinds)
    # ни с одной российской точки не работает
    nv = node_refusal_verdict(d, answered, kinds)
    if nv:
        return nv
    gv = ext_verdict(d, kinds, where)
    if gv:
        return gv
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
                   if d.get("trace") and not d["trace"]["reached"] and d["trace"]["last"] else "") + side
                + block_detail(d))
    if abroad is False:
        if d.get("abroad_sure", 2) >= 2:
            return ("нода не отвечает ни из России, ни из-за рубежа — сбой самой ноды или её хостера, а не блокировка"
                    + (f" (через {d['via']})" if d.get("via") else ""))
        return (f"нода не отвечает ни из России, ни из-за рубежа (через {d.get('via')}, второго рабочего канала для "
                "сверки нет) — похоже на сбой самой ноды или её хостера, но вывод неуверенный")
    if d.get("abroad_err"):
        return (f"нода не отвечает {where}; проверка из-за рубежа сорвалась — блокировка это или поломка, "
                "не различить")
    if d.get("abroad_tries"):
        return (f"нода не отвечает {where}; из-за рубежа проверить не удалось — обходной канал сам не работал; "
                "блокировка это или поломка, не различить")
    return f"нода не отвечает {where}; из-за рубежа проверить было не через что — блокировка это или поломка, не различить"


def node_refusal_verdict(d, answered, kinds):
    """Ни с одной российской точки порт не открывается, а по счётчикам ноды запросы доходят и она сама их отклоняет
    (молчит или сбрасывает) — это не блокировка по дороге. Вывод только когда у всех точек беда с портом (tcp), каждая
    сверенная точка отклонена и сверено не меньше двух точек (или все): одна rf1 с баном на ноде не должна заслонить
    настоящую блокировку у остальных. Globalping остаётся в выводе: он говорит, задело ли пользователей; если у
    абонентов тоже закрыто, а отклонена одна точка — называем только бан этой точки, причину беды абонентов нет.
    None — не то."""
    if not answered or not kinds <= {"tcp"}:
        return None
    ref = node_refused(d, list(answered))
    wit = [p for p, w in (d.get("witness") or {}).items() if w and not p.endswith("|tls") and p in answered]
    if not ref or any(p not in ref for p in wit) or not (len(ref) >= 2 or len(ref) == len(answered)):
        return None
    who = "с rf1" if list(ref) == [SELF] else "с точек " + ", ".join(ref)
    how = "сама сбрасывает их" if all(k == "reject" for k in ref.values()) else "не отвечает на них"
    rest = [p for p in answered if p not in ref]
    rest_tail = f" (остальные — {', '.join(rest)} — сверить не удалось)" if rest else ""
    s = ext_summary(d, fresh=True)
    gpc = bool(s) and s["verdict"] in ("closed", "mixed")
    abroad = d.get("abroad")
    unsure = " (из-за рубежа сверено через один канал — вывод неуверенный)" if (
        abroad is False and d.get("abroad_sure", 2) < 2) else ""
    if gpc and abroad is not False and len(ref) < 2:
        # отклонена одна точка (обычно rf1 — антискан на ноде): бан её адреса доказан, а причина беды абонентов — нет,
        # это может быть и настоящая блокировка
        return (f"по счётчикам ноды запросы {who} доходят, но она {how} — адрес проверки забанен на ноде"
                + ext_tail(d) + "; почему не открывается у абонентов, по этим данным не сказать — блокировка или "
                "файрвол ноды") + rest_tail
    if gpc and abroad is not False:
        return (f"по счётчикам ноды запросы {who} доходят, но она {how}; у абонентов домашних провайдеров тоже не "
                "открывается — нода закрыта для России своим файрволом (геоблок, антискан), клиенты из РФ подключиться "
                "не могут") + rest_tail
    if abroad is True:
        return (f"из-за рубежа нода отвечает, а {who} запросы доходят до ноды, и она {how} — это не блокировка: нода "
                "закрылась от адресов проверки (бан, антискан, файрвол на ноде)") + ext_tail(d) + rest_tail
    if abroad is False:
        if all(k == "reject" for k in ref.values()):
            return ("нода сама сбрасывает соединения на порт входа, из-за рубежа тоже не отвечает — Xray на ноде не "
                    "слушает порт или его закрыл файрвол; это не блокировка") + unsure + rest_tail
        return (f"запросы {who} доходят до ноды, но она не отвечает, из-за рубежа тоже — перегрузка или файрвол самой "
                "ноды, а не блокировка") + unsure + rest_tail
    return (f"запросы {who} доходят до ноды, но она {how} — отказывает сама нода (файрвол, бан, перегрузка), а не "
            "блокировка") + ext_tail(d) + rest_tail


def block_detail(d):
    """К выводу «блокировка адреса»: соседи по подсети и открытый реестр РКН."""
    out = ""
    nb = d.get("neighbours")
    if nb and nb.get("checked"):
        if nb.get("open"):
            out += (f"; соседние адреса той же подсети из России открываются ({len(nb['open'])} из {nb['checked']}) "
                    "— закрыт именно адрес ноды")
        else:
            out += "; соседние адреса той же подсети из России тоже не отвечают — возможно, закрыта вся подсеть хостера"
    reg = d.get("registry")
    if reg is True:
        out += "; адрес есть в реестре РКН"
    elif reg is False:
        out += "; в открытом реестре РКН адреса нет — похоже на блокировку на ТСПУ вне реестра"
    return out


def deep_text(d, status, extra=()):
    """Блок сообщения: что увидели (плюс строки extra от самого сторожа) и на что похоже."""
    note = name_note(d) if DEEP_EXTRA_LIVE else None
    return ("<b>Откуда проверил</b>\n" + html.escape("\n".join(deep_lines(d) + list(extra)))
            + f"\n\n<b>Похоже на:</b> {html.escape(deep_verdict(d, status))}." + (f"\n{html.escape(note)}." if note else ""))


# ---------- 4. внешний сервис: Globalping (домашние сети России) ----------

def external_scan(target, cfg=None):
    """Взгляд из домашних сетей России: открывается ли вход ноды у абонентов обычных провайдеров (МТС, Билайн,
    Ростелеком, Дом.ру…) и из Европы — через Globalping (globalping.py). Все наши точки в дата-центрах, этого взгляда
    сторожу не хватало. Зовётся из deep_diag (ext_job) только когда порт входа не открывается с rf1 или с двух точек,
    и только с адресом, совпавшим с защищённым DNS.

    Включается в external.json: {"enabled": true, "service": "globalping"}; необязательно "ru_probes" (точек в РФ,
    по умолчанию 8) и "hour_budget" (проверок в час). Наружу уходят только адрес (IP) и порт входа — имя ноды никогда;
    результаты Globalping открыты по номеру замера. Выключено или нет файла — None, наружу ничего. Другой сервис
    в настройках — запроса к нему нет, тоже ничего не уходит (в сообщении так и сказано).
    target — {"host", "addr", "port"}. Возвращает None либо {"service", "note", ...итог globalping.check}."""
    cfg = read_etc(EXTERNAL, {}) if cfg is None else cfg
    if not isinstance(cfg, dict) or not cfg.get("enabled"):
        return None
    service = str(cfg.get("service") or "не указан")
    if service.lower() != "globalping" or globalping is None:
        return {"service": service, "note": "включена в настройках, но запрос к сервису не написан — ничего не отправлено"}
    addr = (target or {}).get("addr")
    if not addr or not globalping.public_ip(addr):
        return None   # имени наружу не отдаём, а адреса нет — спрашивать не о чем
    try:
        n = max(1, min(int(cfg.get("ru_probes") or globalping.RU_PROBES), 20))
        budget = int(cfg["hour_budget"]) if cfg.get("hour_budget") else None
    except (TypeError, ValueError):
        n, budget = globalping.RU_PROBES, None
    res = globalping.check(addr, int((target or {}).get("port") or 443), n=n, budget=budget)
    if res is None:
        return None
    return dict(res, service="Globalping", note=globalping.text(res))


EXT_DOH_WAIT = 10        # секунд на сверку адреса по защищённому DNS перед Globalping
EXT_WAIT = (globalping.WALL if globalping else 0) + EXT_DOH_WAIT + 2   # дольше от старта внешний сервис не ждём
EXT_FRESH = 300          # итог Globalping старше (из памяти) в вывод не берём — только строкой «что увидели»


def ext_trouble(r):
    """Порт входа с этой точки не открывается (таймаут, отказ): повод спросить внешний сервис. Globalping проверяет
    только рукопожатие TCP — при обрыве TLS, остановке данных или чужом сертификате он ответит «открывается», а адрес
    уйдёт в открытый сервис зря. Не проверялось (none) — тоже не повод."""
    return netprobe.probe_class(r) == "tcp"


def ext_wanted(direct, probes):
    """Спрашивать ли внешний сервис по итогам всех точек (когда с rf1 порт открыт или не проверялся): порт не
    открылся хотя бы с двух точек или со всех ответивших. Одна точка при живом rf1 — скорее её собственная беда."""
    pts = [direct] + [p for p in probes.values() if p]
    bad = [p for p in pts if ext_trouble(p)]
    seen = [p for p in pts if netprobe.probe_class(p) != "none"]
    return bool(bad) and (len(bad) >= 2 or len(bad) == len(seen))


def trusted_addr(host, addrs):
    """Какой адрес можно отдать наружу -> (адрес, None) | (None, почему нет). Адрес с rf1 и с точек — из их обычного
    DNS; при подмене это чужой адрес (заглушка, «яма»), и отдавать его в открытый сервис нельзя: сверяем с защищённым
    DNS. Вход задан самим адресом — сверять нечего."""
    addrs = [a for a in dict.fromkeys(addrs) if a]
    if not addrs:
        return None, None
    try:
        ipaddress.ip_address(str(host))
        return (str(host) if str(host) in addrs else addrs[0]), None
    except ValueError:
        pass
    truth = doh(str(host), first=True)
    if not truth:
        return None, "не спрашивал — защищённый DNS не ответил, а адресу из обычного DNS без сверки не верю"
    good = [a for a in addrs if a in truth]
    if not good:
        return None, ("не спрашивал — адрес входа у наших точек не совпадает с защищённым DNS (похоже на подмену), "
                      "чужой адрес наружу не отдаю")
    return good[0], None


def ext_job(host, addrs, port):
    """В потоке внешнего сервиса: выбрать адрес, которому верим, и спросить. Выключено — ничего, даже DoH."""
    cfg = read_etc(EXTERNAL, {})
    if not isinstance(cfg, dict) or not cfg.get("enabled"):
        return None
    if str(cfg.get("service") or "").lower() != "globalping" or globalping is None:
        return external_scan({"host": host, "addr": next((a for a in addrs if a), None), "port": port}, cfg)
    addr, why = trusted_addr(host, addrs)
    if not addr:
        return {"service": "Globalping", "skipped": "dns", "note": why} if why else None
    return external_scan({"host": host, "addr": addr, "port": port}, cfg)


def ext_summary(d, fresh=False):
    """Итог Globalping из разбора, если он есть и в нём есть ответы домашних точек; иначе None.
    fresh — только для вывода: результат из памяти старше EXT_FRESH не годится (с тех пор нода могла упасть)."""
    ext = d.get("external")
    s = ext.get("summary") if isinstance(ext, dict) else None
    if fresh and s and ext.get("cached") and (ext.get("age") or 0) > EXT_FRESH:
        return None
    return s if s and s.get("verdict") != "nodata" else None


def ext_isps(s, state):
    """Провайдеры: ok — у кого открылось хоть у одной точки; fail — у кого не открылось ни у одной (провайдер, где
    есть и то и другое, в «закрытые» не пишем: это неустойчивая точка, а не блокировка)."""
    return ", ".join(k for k, v in sorted((s.get("isps") or {}).items())
                     if (v["ok"] if state == "ok" else v["fail"] and not v["ok"]))


def ext_verdict(d, kinds, where):
    """Вывод по Globalping, когда ни с одной нашей точки вход не открывается; None — данных нет или они не решают."""
    s = ext_summary(d, fresh=True)
    if not s or not kinds <= {"tcp"}:
        return None   # Globalping проверяет только рукопожатие TCP: про TLS и обрыв данных он ничего не скажет
    answered = s["ru_ok"] + s["ru_fail"]
    gp = f"Globalping: открывается у {s['ru_ok']} из {answered}"
    if s["verdict"] == "open":
        return (f"с наших точек (все в дата-центрах) порт не отвечает {where}, а у абонентов домашних провайдеров "
                f"открывается ({gp}: {ext_isps(s, 'ok')}) — закрыт путь из дата-центров и хостингов, у пользователей, "
                "скорее всего, всё в порядке")
    if s["verdict"] == "mixed":
        return (f"порт не отвечает {where}; у абонентов домашних провайдеров — у части открывается "
                f"({ext_isps(s, 'ok')}), у части нет ({ext_isps(s, 'fail')}) ({gp}) — блокировка у отдельных "
                "провайдеров, а не по всей стране" + block_detail(d))
    hop = (f" (с rf1 пакеты пропадают после шага {d['trace']['last'][0]})"
           if d.get("trace") and not d["trace"]["reached"] and d["trace"]["last"] else "")
    if s["verdict"] == "closed" and s["control"] == "down" and d.get("abroad") is True:
        return (f"порт не отвечает {where} и у абонентов домашних провайдеров ({gp}: {ext_isps(s, 'fail')}); "
                f"через наш зарубежный канал ({d.get('via') or '?'}) нода отвечает, а с точек Globalping в Европе — нет: "
                "источники расходятся, похоже на блокировку из России, но вывод неуверенный" + hop + block_detail(d))
    if s["verdict"] == "closed" and (s["control"] == "up" or d.get("abroad") is True):
        src = ("из Европы (Globalping) открывается" if s["control"] == "up"
               else f"из-за рубежа (через {d.get('via') or '?'}) отвечает")
        return (f"блокировка адреса по всей России: порт не отвечает {where} и у абонентов домашних провайдеров "
                f"({gp}: {ext_isps(s, 'fail')}), а {src}" + hop + block_detail(d))
    if s["verdict"] == "closed" and s["control"] == "down" and d.get("abroad") is not True:
        return ("нода не отвечает ни из России (наши точки и домашние провайдеры), ни из Европы (Globalping) — "
                "сбой самой ноды или её хостера, а не блокировка")
    return None


def ext_tail(d, bad_kinds=("tcp",)):
    """Хвост к выводу «у части точек не открывается»: что видят абоненты домашних провайдеров. bad_kinds — как не
    открылось у наших точек: Globalping видит только порт, поэтому хвост — лишь когда у всех них беда с портом (tcp);
    при обрыве TLS или данных его «открывается» вводило бы в заблуждение."""
    s = ext_summary(d, fresh=True)
    if not s or not set(bad_kinds) <= {"tcp"} or s["verdict"] not in ("open", "mixed", "closed"):
        return ""
    answered = s["ru_ok"] + s["ru_fail"]
    if s["verdict"] == "open":
        return f"; у абонентов домашних провайдеров открывается (Globalping: {s['ru_ok']} из {answered})"
    if s["verdict"] == "mixed":
        return (f"; у абонентов домашних провайдеров — у части открывается ({ext_isps(s, 'ok')}), у части нет "
                f"({ext_isps(s, 'fail')})")
    return f"; у абонентов домашних провайдеров не открывается (Globalping: 0 из {answered})"


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

    cands = [{"name": clean(o["name"]), "port": o["port"], "entry": o.get("entry"), "key": o["name"]} for o in alive]
    exits = {name: (s or {}).get("exit") for name, s in state_chans.items()}

    def via_for(c):
        return abroad_vias(cands, c, exits)

    # списки качаются сами по себе; ноды — по три разом и раньше DNS, чтобы не завалить запросами точки проверки
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as side, concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f_lists = side.submit(lists_run, targets(chans, nodes, site_hosts, bases), bases, via_port)
        health = agents_health(agents)
        f_nodes = [(c["name"], ex.submit(deep_diag, c, via_for(c), agents, bases)) for c in chans]
        checked = {name: f.result() for name, f in f_nodes}
        dns = dns_check(names, via_port, agents)
        ext_cfg = read_etc(EXTERNAL, {})
        ext_on = isinstance(ext_cfg, dict) and bool(ext_cfg.get("enabled"))
        return {"lists": f_lists.result(), "dns": dns, "dns_names": len(names), "health": health, "nodes": checked,
                "external": (str(ext_cfg.get("service") or "не указан") if ext_on else False)}


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
    if d["abroad"] is None and d.get("abroad_tries"):
        abroad = "из-за рубежа проверить не удалось (обходной канал не работал)"
    elif d["abroad"] is False and d.get("abroad_sure", 2) == 1:
        abroad = "из-за рубежа НЕ отвечает (через один канал)"
    s = ext_summary(d)
    if s:
        abroad += f"; абоненты в РФ (Globalping): открывается у {s['ru_ok']} из {s['ru_ok'] + s['ru_fail']}"
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
        weak = dns_level(r) is None
        out.append(html.escape(f"{'ℹ️' if weak else '⚠️'} {name}: по защищённому DNS {', '.join(r['truth']) or 'нет записи'}; "
                               "иначе отвечают: " + "; ".join(f"{who} — {what}" for who, what in r["odd"])
                               + (f" (ответили {r.get('asked', 0)}, для вывода о подмене нужно {DNS_MIN} — пока "
                                  "это не подмена)" if weak else "")))
    if not odd:
        out.append(f"✅ подмены нет — имён: {len(res['dns'])}")
    if len(res["dns"]) < res["dns_names"]:
        out.append(f"⚠️ защищённый DNS не ответил по {res['dns_names'] - len(res['dns'])} из {res['dns_names']} имён")
    out += ["", "<b>Входы нод напрямую</b> <i>(порт, TLS и 64 КБ по одному соединению; сам VPN — в обычном отчёте)</i>"]
    out += [html.escape(node_line(name, d)) for name, d in res["nodes"].items()]
    points = ["rf1 ✅"] + [f"{name} {'✅' if ok else '❌'}" for name, ok in res["health"].items()]
    out += ["", "<b>Точки проверки в РФ:</b> " + html.escape(" · ".join(points)),
            "<b>Внешний сервис:</b> " + html.escape(external_status(res))]
    return "\n".join(out)


def external_status(res):
    """Строка «Внешний сервис» проверки по запросу."""
    ext = res.get("external")
    if not ext:
        return "выключен"
    if not isinstance(ext, str) or ext.lower() != "globalping" or globalping is None:
        return "включён в настройках, но запрос к нему не написан — ничего не отправляется"
    asked = sum(1 for d in (res.get("nodes") or {}).values() if ext_summary(d))
    return ("Globalping (абоненты домашних провайдеров в РФ) — спрашивается только о нодах, вход которых не "
            "открывается с наших точек; уходят только адрес и порт" + (f"; спрошено о нодах: {asked}" if asked else
                                                                     "; в этот раз не понадобился"))


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
        else:
            # сверка идёт, но какой-то список давно не скачивается: зеркала одного списка — одна группа
            srcs, last, groups = lists.get("sources", {}), lists.get("last") or {}, {}
            for k, name in LIST_NAMES.items():
                groups.setdefault(name, []).append(k)
            old = []
            for name, keys in groups.items():
                seen = [last[k] for k in keys if k in last]
                if seen and not any(srcs.get(k, {}).get("ok") for k in keys) and now - max(seen) > LISTS_STALE:
                    old.append(f"{name} — {int((now - max(seen)) // 3600)} ч")
            if old:
                parts.append("⚠️ давно не скачиваются: " + "; ".join(old))
            if failed:
                parts.append(f"не скачалось списков: {len(failed)} из {len(lists['sources'])}")
    parts += rucheck.items(st)
    dns = st.get("dns") or {}
    if dns.get("names"):
        bad = [n for n, v in (st.get("dns_lvl") or {}).items() if v.get("lvl") == "bad"]
        parts.append("⚠️ подмена DNS: " + ", ".join(sorted(bad)) if bad else f"подмены DNS нет (имён: {dns['names']})")
    van = st.get("vantage") or {}
    if van:
        down = [n for n, ok in van.items() if not ok]
        parts.append("⚠️ точка проверки не отвечает: " + ", ".join(down) if down
                     else f"точек проверки в РФ: {len(van) + 1}")
    pt = (st.get("loss") or {}).get("pt") or {}
    # точки не в порядке — и те, что в разборе не учитываются (loss["skip"]), и «не открывает ноды»
    skip = sorted(set((st.get("loss") or {}).get("skip") or []) | {p for p, v in pt.items() if v.get("lvl", "ok") != "ok"})
    if skip:
        why = {"blind": "ничего не проверяет", "noisy": "проблемы с сетью", "shut": "не открывает наши ноды"}
        parts.append("⚠️ " + "; ".join(f"точка «{p}» — {why.get(pt.get(p, {}).get('lvl'), 'не в порядке')}" for p in skip))
    dbad = sorted(p for p, v in (st.get("dns_pt") or {}).items() if v.get("lvl") == "bad")
    if dbad:
        parts.append("⚠️ свой DNS не находит наших имён: " + ", ".join(dbad))
    pl = profiles_line(st, now)
    if pl:
        parts.append(pl)
    vl = vpn_line(st, now)
    if vl:
        parts.append(vl)
    # данные службы --side старше срока — не показываем как данные, говорим одной строкой
    stale = [(h, word) for h, word in ((side_age(st.get("profiles"), PROFILE_STALE, now), "профиль"),
                                       (side_age(st.get("vpn_pt"), VPN_STALE, now), "обход через VPN")) if h is not None]
    if stale:
        parts.append(f"⚠️ данные точек не обновлялись {max(h for h, _ in stale)} ч ("
                     + ", ".join(w for _, w in stale) + ") — служба channel-watch-side")
    lossy_now, shut_now = loss_bad(st, now), loss_shut_now(st, now)
    if shut_now:
        parts.append("⚠️ вход ноды закрыт: " + ", ".join(f"{node} — с точки {point}" for node, point in shut_now))
    if lossy_now:
        parts.append("⚠️ потери соединений: " + ", ".join(f"{node} — {point} {pct} %" for node, point, pct in lossy_now))
    elif lossy_now is not None and not shut_now:
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


def geo_week(st, now=None):
    """Таблица гео для недельной сводки. Гео старше GEO_STALE — с пометкой в заголовке."""
    geo = (st.get("geo") or {}).get("by") or {}
    if not geo:
        return []
    h = side_age(st.get("geo"), GEO_STALE, now)
    old = f" — ⚠️ данные {h} ч назад" if h is not None else ""
    return ["", "<b>Гео адресов нод</b> <i>(страна по базам, Cloudflare, YouTube; ⚠️ — расходится с флагом плитки)</i>"
            + old] + [geo_line(node, cur) for node, cur in sorted(geo.items())]


def week_lines(st):
    """Для сводки за неделю: рядом с какими нашими адресами в реестре есть чужие."""
    near = near_hits(st)
    if not near:
        return []
    return ["", "<b>Чужие адреса в реестре рядом с нашими</b> <i>(та же подсеть /24; наших в реестре нет)</i><b>:</b> "
            + html.escape(", ".join(f"{who} — {n}" for who, n in near))]
