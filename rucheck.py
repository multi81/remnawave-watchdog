"""channel-watch: сверка шаблона подписки с блокировками в России.

1. Список сервисов проверяется прямо с сервера сторожа (из России, мимо VPN) по слоям: обычный DNS против защищённого,
   TCP 443, TLS с именем сайта, HTTP-запрос (451 и страницы-заглушки провайдеров). Вердикт: OK, DNS_BLOCK,
   TCP_TIMEOUT, TCP_RESET, TLS_BLOCK, HTTP_STUB, DOWN (сервис недоступен вообще, не похоже на блокировку).
   Идея разбора по слоям — как у github.com/MayersScott/rkn-block-checker (MIT).
2. Из настоящей подписки сторожа (XRAY_JSON) берутся правила каждой плитки; одинаковые правила — один шаблон. Для
   каждого сервиса считается, куда его отправит шаблон: напрямую, через VPN или в блок (domain/full/regexp/keyword,
   geosite и geoip из geosite.dat/geoip.dat, domainStrategy).
3. Расхождение — сервис по шаблону идёт напрямую, а из России закрыт: у клиентов он не откроется. Шаблоны, где всё по
   умолчанию идёт напрямую (плитки «для заграницы»), не сверяются.
Запуск — вместе со сверкой списков (probe.py --lists, раз в 6 часов); итог забирает обычный проход: тревога о новом
расхождении, сообщение, когда ушло, строка в отчёте.
"""
import concurrent.futures
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time

STATE_FILE = "/var/lib/channel-watch/rucheck.json"
GEO_DIR = "/var/lib/channel-watch/geo"
SERVICES_FILE = "/etc/channel-watch/rucheck.json"      # свои списки: {"services": [...], "local": [...]}
GEO_MAX_AGE = 7 * 86400
SERVICES = (
    "www.youtube.com", "www.instagram.com", "www.facebook.com", "x.com", "web.telegram.org", "discord.com",
    "chatgpt.com", "claude.ai", "www.linkedin.com", "www.tiktok.com", "web.whatsapp.com", "open.spotify.com",
    "www.netflix.com", "github.com", "www.google.com", "ru.wikipedia.org", "www.reddit.com", "www.twitch.tv",
    "soundcloud.com", "proton.me", "signal.org",
)
# российские: проверяем, что с сервера сторожа открываются, но расхождением с шаблоном не считаем — часть из них
# (Госуслуги и др.) не пускает адреса хостингов, а у клиентов дома открывается
LOCAL = ("www.gosuslugi.ru", "www.nalog.gov.ru", "www.sberbank.ru", "vk.com", "ya.ru", "www.mos.ru", "www.ozon.ru",
         "www.wildberries.ru", "max.ru", "rutube.ru")
BLOCKED = ("DNS_BLOCK", "TCP_TIMEOUT", "TCP_RESET", "TLS_BLOCK", "HTTP_STUB")
VERDICT_RU = {"DNS_BLOCK": "подмена DNS", "TCP_TIMEOUT": "порт молчит", "TCP_RESET": "сброс соединения",
              "TLS_BLOCK": "рвут TLS по имени сайта", "HTTP_STUB": "страница-заглушка", "DOWN": "недоступен", "OK": "открыт"}
STUB_MARKERS = ("eais.rkn.gov.ru", "warning.rt.ru", "blocklist.rkn.gov.ru", "доступ к ресурсу ограничен",
                "доступ к запрашиваемому ресурсу ограничен", "ресурс заблокирован", "blocked by roskomnadzor")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"


def blocked(verdict):
    return verdict in BLOCKED


# ---------- геобазы ----------

def _varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def _fields(b):
    i = 0
    while i < len(b):
        key, i = _varint(b, i)
        f, t = key >> 3, key & 7
        if t == 0:
            v, i = _varint(b, i)
        elif t == 2:
            n, i = _varint(b, i)
            v = b[i:i + n]
            i += n
        elif t == 5:
            v, i = b[i:i + 4], i + 4
        elif t == 1:
            v, i = b[i:i + 8], i + 8
        else:
            raise ValueError("неизвестный тип поля %d" % t)
        yield f, v


class Geo:
    """geosite.dat / geoip.dat Xray: категории читаются по запросу и запоминаются. Нет файла — None (не знаем)."""

    def __init__(self, folder=GEO_DIR):
        self.folder, self.sites, self.ips = folder, {}, {}
        self._site_raw = self._ip_raw = None

    def _read(self, name):
        try:
            return open(os.path.join(self.folder, name), "rb").read()
        except OSError:
            return None

    def _site(self, code):
        code = code.lower().split("@")[0]
        if code not in self.sites:
            if self._site_raw is None:
                self._site_raw = self._read("geosite.dat") or b""
            found = None
            for f, entry in _fields(self._site_raw):
                if f != 1:
                    continue
                items, name = [], None
                for g, v in _fields(entry):
                    if g == 1:
                        name = v.decode().lower()
                        if name != code:
                            break
                    elif g == 2:
                        t, val = 0, ""
                        for h, x in _fields(v):
                            if h == 1:
                                t = x
                            elif h == 2:
                                val = x.decode(errors="replace")
                        items.append((t, val.lower()))
                if name == code:
                    found = items
                    break
            self.sites[code] = found
        return self.sites[code]

    def site_match(self, code, host):
        items = self._site(code)
        if items is None:
            return None
        host = host.lower()
        for t, v in items:
            if (t == 2 and (host == v or host.endswith("." + v))) or (t == 3 and host == v) \
                    or (t == 0 and v in host) or (t == 1 and re.search(v, host)):
                return True
        return False

    def ip_match(self, code, ip):
        code = code.lower()
        if code not in self.ips:
            if self._ip_raw is None:
                self._ip_raw = self._read("geoip.dat") or b""
            nets = None
            for f, entry in _fields(self._ip_raw):
                if f != 1:
                    continue
                name, cidrs = None, []
                for g, v in _fields(entry):
                    if g == 1:
                        name = v.decode().lower()
                        if name != code:
                            break
                    elif g == 2:
                        raw, p = b"", 0
                        for h, x in _fields(v):
                            if h == 1:
                                raw = x
                            elif h == 2:
                                p = x
                        try:
                            cidrs.append(ipaddress.ip_network((ipaddress.ip_address(raw), p), strict=False))
                        except ValueError:
                            pass
                if name == code:
                    nets = cidrs
                    break
            self.ips[code] = nets
        nets = self.ips[code]
        if nets is None:
            return None
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets if n.version == a.version)


def refresh_geo(folder=GEO_DIR, now=None):
    """Свежие geosite.dat/geoip.dat из контейнера remnanode на этом же сервере (если он есть); раз в неделю."""
    now = now or time.time()
    os.makedirs(folder, exist_ok=True)
    for name in ("geosite.dat", "geoip.dat"):
        path = os.path.join(folder, name)
        if os.path.exists(path) and now - os.path.getmtime(path) < GEO_MAX_AGE:
            continue
        try:
            data = subprocess.run(["docker", "exec", "remnanode", "cat", "/usr/local/share/xray/" + name],
                                  capture_output=True, timeout=60).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        if len(data) > 1000:
            with open(path + ".tmp", "wb") as f:
                f.write(data)
            os.replace(path + ".tmp", path)


# ---------- маршрут по шаблону ----------

def _kind(cfg, rule):
    """Куда ведёт правило: direct / block / proxy (балансировщик — всегда VPN)."""
    if rule.get("balancerTag"):
        return "proxy"
    proto = {o.get("tag"): o.get("protocol") for o in cfg.get("outbounds", [])}.get(rule.get("outboundTag"))
    return {"freedom": "direct", "blackhole": "block"}.get(proto, "proxy")


def _port_ok(spec):
    if spec in (None, ""):
        return True
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit() and int(a) <= 443 <= int(b):
                return True
        elif part == "443":
            return True
    return False


def _applies(rule):
    """Правило может сработать на TCP 443 от клиента (без привязки к служебному входу, протоколу и т. п.)."""
    net = rule.get("network")
    if net and "tcp" not in str(net):
        return False
    if rule.get("inboundTag") or rule.get("protocol") or rule.get("source") or rule.get("user"):
        return False
    return _port_ok(rule.get("port"))


def _dom_match(d, host, geo):
    d = str(d)
    if d.startswith("domain:"):
        v = d[7:].lower()
        return host == v or host.endswith("." + v)
    if d.startswith("full:"):
        return host == d[5:].lower()
    if d.startswith("regexp:"):
        try:
            return bool(re.search(d[7:], host))
        except re.error:
            return False
    if d.startswith("keyword:"):
        return d[8:].lower() in host
    if d.startswith("geosite:"):
        return bool(geo.site_match(d[8:], host))
    if d.startswith(("ext:", "ext-domain:")):
        return False
    return d.lower() in host


def _ip_match(spec, ips, geo):
    spec = str(spec)
    for ip in ips:
        if spec.startswith("geoip:"):
            code = spec[6:]
            if code.startswith("!"):
                continue
            if geo.ip_match(code, ip):
                return True
        else:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False):
                    return True
            except ValueError:
                continue
    return False


def route(cfg, host, ips, geo):
    """Куда шаблон отправит TCP 443 на host (ips — его адреса): direct / proxy / block."""
    host = host.lower()
    rules = [r for r in (cfg.get("routing") or {}).get("rules", []) if _applies(r)]
    strategy = (cfg.get("routing") or {}).get("domainStrategy", "AsIs")

    def run(with_ip):
        for r in rules:
            doms, rip = r.get("domain"), r.get("ip")
            if doms and not any(_dom_match(d, host, geo) for d in doms):
                continue
            if rip:
                if not with_ip or not _ip_match_any(rip):
                    continue
            if not doms and not rip and not r.get("network") and not r.get("port"):
                continue
            return _kind(cfg, r)
        return None

    def _ip_match_any(rip):
        return any(_ip_match(s, ips, geo) for s in rip)

    got = run(strategy == "IPOnDemand")
    if got is None and strategy == "IPIfNonMatch":
        got = run(True)
    if got is None:
        outs = cfg.get("outbounds") or []
        got = {"freedom": "direct", "blackhole": "block"}.get(outs[0].get("protocol"), "proxy") if outs else "proxy"
    return got


def default_direct(cfg):
    """Всё, что не попало в правила, идёт напрямую — плитка «для заграницы», её с блокировками в РФ не сверяем."""
    return route(cfg, "zz-no-such-host.invalid", ["198.18.0.1"], Geo("/nonexistent")) == "direct"


# ---------- проверка сервиса по слоям ----------

class LiveNet:
    """Сеть по-настоящему; в тестах подменяется."""

    def resolve(self, host):
        try:
            return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
        except OSError:
            return []

    def doh(self, host):
        try:
            out = subprocess.run(["curl", "-s", "-m", "8", "-H", "accept: application/dns-json",
                                  "https://cloudflare-dns.com/dns-query?name=%s&type=A" % host],
                                 capture_output=True, text=True, timeout=12).stdout
            return sorted({a["data"] for a in json.loads(out).get("Answer", []) if a.get("type") == 1})
        except (ValueError, OSError, subprocess.TimeoutExpired):
            return []

    def connect(self, ip, port, timeout):
        try:
            socket.create_connection((ip, port), timeout=timeout).close()
            return "ok"
        except socket.timeout:
            return "timeout"
        except (ConnectionResetError, ConnectionRefusedError):
            return "reset"
        except OSError:
            return "timeout"

    def _tls(self, ip, host, timeout):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # российские сертификаты (Минцифры) — не ошибка
        raw = socket.create_connection((ip, 443), timeout=timeout)
        return ctx.wrap_socket(raw, server_hostname=host)

    def handshake(self, ip, host, timeout):
        try:
            self._tls(ip, host, timeout).close()
            return "ok"
        except socket.timeout:
            return "timeout"
        except (ssl.SSLError, ConnectionResetError, OSError):
            return "reset"

    def get(self, ip, host, timeout):
        try:
            s = self._tls(ip, host, timeout)
            s.settimeout(timeout)
            s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
                       % (host, UA)).encode())
            data = b""
            while len(data) < 65536:
                chunk = s.recv(16384)
                if not chunk:
                    break
                data += chunk
            s.close()
        except OSError:
            return (None, b"")
        m = re.match(rb"HTTP/\d\.\d (\d{3})", data)
        return (int(m.group(1)) if m else None, data)


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved


def probe_service(host, net=None, timeout=6):
    """Проверка с этого сервера по слоям: {"host", "verdict", "sys", "doh", "code"}."""
    net = net or LiveNet()
    sys_ips, doh_ips = net.resolve(host), net.doh(host)
    out = {"host": host, "sys": sys_ips, "doh": doh_ips, "code": None}
    if not sys_ips and not doh_ips:
        return dict(out, verdict="DOWN")
    if doh_ips and (not sys_ips or (not set(sys_ips) & set(doh_ips) and all(_private(a) for a in sys_ips))):
        return dict(out, verdict="DNS_BLOCK")
    # сначала адреса обычного DNS (Госуслуги и др. отдают зарубежному DNS другие адреса, закрытые для России),
    # потом защищённого; до трёх адресов — один молчащий узел CDN ещё не блокировка
    cands = list(dict.fromkeys(sys_ips + doh_ips))[:3]
    ip, tcp = None, "timeout"
    for a in cands:
        tcp = net.connect(a, 443, timeout)
        if tcp == "ok":
            ip = a
            break
    if ip is None:
        return dict(out, verdict="TCP_TIMEOUT" if tcp == "timeout" else "TCP_RESET")
    if net.handshake(ip, host, timeout) != "ok":
        return dict(out, verdict="TLS_BLOCK")
    code, body = net.get(ip, host, timeout)
    out["code"] = code
    low = body[:65536].decode("utf-8", "replace").lower()
    if code == 451 or any(m in low for m in STUB_MARKERS):
        return dict(out, verdict="HTTP_STUB")
    return dict(out, verdict="OK")


# ---------- сверка ----------

def compare(tiles, verdicts, geo, resolve=None):
    """tiles — конфиги подписки (у каждого remarks и routing); verdicts — {host: {"verdict"}}.
    -> {"templates": [{"name", "tiles", "default_direct", "routes": {host: куда}}], "mismatch": [...]}"""
    resolve = resolve or (lambda h: (verdicts.get(h) or {}).get("doh") or [])
    groups = {}
    for c in tiles:
        key = json.dumps((c.get("routing") or {}).get("rules", []), sort_keys=True, ensure_ascii=False)
        g = groups.setdefault(key, {"cfg": c, "tiles": []})
        g["tiles"].append(str(c.get("remarks") or "?").strip())
    templates, mismatch = [], []
    for g in groups.values():
        cfg, name = g["cfg"], g["tiles"][0]
        routes = {h: route(cfg, h, resolve(h), geo) for h in verdicts}
        dd = default_direct(cfg)
        templates.append({"name": name, "tiles": g["tiles"], "default_direct": dd, "routes": routes})
        if dd:
            continue
        for h, v in sorted(verdicts.items()):
            if routes[h] == "direct" and blocked(v.get("verdict")) and not v.get("local"):
                mismatch.append({"template": name, "host": h, "verdict": v["verdict"]})
    return {"templates": templates, "mismatch": mismatch}


def services_list(path=SERVICES_FILE):
    """-> (зарубежные, российские); свой файл заменяет каждый список по отдельности."""
    out = [list(SERVICES), list(LOCAL)]
    try:
        d = json.load(open(path, encoding="utf-8"))
        for i, k in enumerate(("services", "local")):
            if isinstance(d.get(k), list) and d[k]:
                out[i] = [str(x) for x in d[k]]
    except (OSError, ValueError, AttributeError):
        pass
    return out[0], out[1]


def check_all(hosts, net=None):
    """Все сервисы по слоям, 8 разом: {host: ответ probe_service без лишнего}."""
    hosts = list(dict.fromkeys(hosts))
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        return dict(zip(hosts, ex.map(lambda h: probe_service(h, net), hosts)))


def run_live(tiles, geo_dir=GEO_DIR, services=None, net=None, points=(), ask=None):
    """Полный проход: геобазы, сервисы, сверка. -> данные для STATE_FILE.
    points — точки проверки с отметкой "rucheck" (обычный провайдер видит блокировки, дата-центр — не всегда);
    ask(точка, список) -> {host: ответ} | None. Ни одна не ответила — проверяем отсюда и пишем об этом."""
    refresh_geo(geo_dir)
    geo = Geo(geo_dir)
    foreign, local = services or services_list()
    hosts = list(dict.fromkeys(list(foreign) + list(local)))
    verdicts, source, missed = None, None, []
    for p in points:
        got = ask(p, hosts) if ask else None
        if isinstance(got, dict) and got and all(isinstance(v, dict) and v.get("verdict") for v in got.values()):
            verdicts, source = {h: got[h] for h in hosts if h in got}, p["name"]
            break
        missed.append(p["name"])
    if not verdicts:
        verdicts = check_all(hosts, net)
    for h in local:
        if h in verdicts and h not in foreign:
            verdicts[h]["local"] = True
    res = compare(tiles, verdicts, geo)
    return {"ts": int(time.time()), "services": verdicts, "templates": res["templates"], "mismatch": res["mismatch"],
            "geo": bool(geo._read("geosite.dat")), "source": source, "missed": missed}


# ---------- состояние, тревоги, отчёт ----------

def _key(m):
    return "%s|%s" % (m["template"], m["host"])


def step(st, data):
    """Свежая сверка -> st["rucheck"]; тревоги о новых расхождениях и о тех, что ушли."""
    prev = {_key(m): m for m in (st.get("rucheck") or {}).get("mismatch", [])}
    cur = {_key(m): m for m in data.get("mismatch", [])}
    alerts = []
    for k, m in cur.items():
        if k not in prev:
            alerts.append("🚧 <b>Шаблон «%s»: %s идёт напрямую, а из России закрыт</b> (%s)\n"
                          "У клиентов на этой плитке он не откроется. Что сделать: в шаблоне отправить его через VPN."
                          % (html.escape(m["template"]), html.escape(m["host"]),
                             VERDICT_RU.get(m["verdict"], m["verdict"])))
    for k, m in prev.items():
        if k not in cur:
            alerts.append("✅ <b>Шаблон «%s»: %s больше не расходится с блокировками</b>"
                          % (html.escape(m["template"]), html.escape(m["host"])))
    sv = data.get("services") or {}
    st["rucheck"] = {"ts": data.get("ts"), "mismatch": list(cur.values()),
                     "closed": sorted(h for h, v in sv.items() if blocked(v.get("verdict")) and not v.get("local")),
                     "total": sum(1 for v in sv.values() if not v.get("local")),
                     "local_down": sorted(h for h, v in sv.items() if v.get("local") and v.get("verdict") != "OK"),
                     "geo": data.get("geo", True), "source": data.get("source"), "missed": data.get("missed") or []}
    return alerts


def items(st):
    """Части строки «Блокировки» в отчёте."""
    rc = st.get("rucheck") or {}
    if not rc.get("ts"):
        return []
    where = "с точки «%s»" % rc["source"] if rc.get("source") else "с сервера сторожа"
    parts = ["%s закрыто %d из %d зарубежных сервисов%s" % (
        where, len(rc.get("closed", [])), rc.get("total", 0), (": " + ", ".join(rc["closed"][:8])) if rc.get("closed") else "")]
    if rc.get("missed") and not rc.get("source"):
        parts.append("⚠️ точка «%s» не ответила — сервисы проверены с сервера сторожа (дата-центр видит не все блокировки)"
                     % "», «".join(rc["missed"]))
    if rc.get("local_down"):
        parts.append("российские не открылись %s (часто не пускают хостинги): %s" % (where, ", ".join(rc["local_down"][:6])))
    mm = rc.get("mismatch") or []
    parts.append("⚠️ расхождения с шаблоном: " + "; ".join("«%s» — %s" % (m["template"], m["host"]) for m in mm[:6])
                 if mm else "расхождений с шаблоном нет")
    if not rc.get("geo", True):
        parts.append("⚠️ нет geosite.dat — правила geosite в шаблоне не учтены")
    return parts
