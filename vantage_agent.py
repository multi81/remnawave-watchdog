#!/usr/bin/env python3
"""vantage-agent: точка проверки для сторожа каналов — «посмотреть на ноду ещё и отсюда».

Сторож (rf1) видит ноды только из своей сети. Этот агент стоит на другом российском сервере и по запросу сторожа
делает те же прямые проверки: порт, TLS, набирается ли по соединению 64 КБ (обрыв DPI на 16–20 КБ), и что
отвечает здешний DNS. Сам никуда не ходит и ничего не хранит.

Ограничения (чтобы агент нельзя было использовать как прокси или сканер):
  - отвечает только адресам из списка allow и только с верным токеном (заголовок X-Token);
  - проверяет только имена на доменах из списка suffixes (и адреса, перечисленные в hosts — например свои
    ретрансляторы) и только порты из списка ports;
  - адрес сервера узнаёт сам по имени — указать ему произвольный адрес нельзя;
  - не больше MAX_PARALLEL проверок разом и RATE запросов в минуту.
Настройки — /etc/vantage-agent/agent.json: {"token", "allow": [...], "suffixes": [...], "ports": [443], "port": 9109,
  "hosts": [...], "snis": [...]} (hosts и snis необязательны: адреса вне своих доменов и имена TLS для них).
Запросы (ответ — JSON):
  /health
  /probe?host=ИМЯ[&port=443][&sni=ИМЯ]   порт, TLS, набираются ли 64 КБ
  /series?host=ИМЯ[&port][&n=20][&mss=N]  n соединений подряд: сколько прошло (частичные потери)
  /sni?host=ИМЯ[&port][&sni=ИМЯ]          тот же адрес с настоящим именем, с нейтральным и без имени
  /dns?name=ИМЯ
  /services                               популярные сервисы по слоям (DNS, TCP, TLS, заглушка) — для сверки шаблона;
                                          список свой (rucheck.py или "services" в настройках), чужие имена не принимаются
TLS: если есть cert.pem и key.pem (их создаёт vantage_install.sh), на том же порту принимается и TLS — по первому байту
  соединения. Сторож закрепляет сертификат по отпечатку sha256 (vantage_client.py). Обычный HTTP остаётся для старого
  сторожа, пока в настройках не включено "tls_only": true (с 127.0.0.1 HTTP отвечает всегда — для самопроверки).
Настройки и ключ TLS берутся из $CREDENTIALS_DIRECTORY (LoadCredential в юните), если они там есть, иначе из /etc.
"""
import hmac
import ipaddress
import os
import re
import http.server
import json
import socket
import ssl
import sys
import threading
import time
import urllib.parse

import netprobe

CONF = "/etc/vantage-agent/agent.json"
CERT, KEY = "/etc/vantage-agent/cert.pem", "/etc/vantage-agent/key.pem"
VPN_CHANNELS = "/etc/channel-watch/channels.json"  # каналы своего клиента Xray (на VPN-точке; агенту — через LoadCredential)


def vpn_channels():
    """Плитки своего клиента Xray: [{"name", "port", ...}]; None — файла нет (это не VPN-точка или каналы не собраны)."""
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    for path in ((os.path.join(d, "vpn-channels.json"),) if d else ()) + (VPN_CHANNELS,):
        try:
            return json.load(open(path, encoding="utf-8")).get("channels", [])
        except (OSError, ValueError, AttributeError):
            continue
    return None
VERSION = 7         # 5 — VPN-точка: /vpn?name=<плитка> через свой клиент Xray (если в настройках "vpn": true)
                    # 6 — /services: проверка популярных сервисов отсюда (rucheck.py рядом)
                    # 7 — TLS на том же порту, /dns?udp=0, /probe?verify=1; чужие адреса отсекаются до разбора запроса
CAPS = ["dns_udp0", "verify", "tls"]  # что умеет (в /health): по этому списку сторож решает, о чём спрашивать
# список по умолчанию, если в настройках нет profile: заблокированные сайты (приветствие TLS) и зарубежные хостинги
DEFAULT_PROFILE = {"sites": [["blocked", "rutracker.org"], ["blocked", "www.instagram.com"], ["blocked", "www.facebook.com"],
                             ["control", "www.example.org"], ["control", "ya.ru"]],
                   "loads": [["cloudflare", "https://speed.cloudflare.com/__down?bytes=300000", None],
                             ["ovh", "https://proof.ovh.net/files/1Mb.dat", "0-299999"],
                             ["hetzner", "https://fsn1-speed.hetzner.com/100MB.bin", "0-299999"]]}
MAX_PARALLEL = 6
WAIT_SLOT = 10       # секунд ждём свободного места, прежде чем ответить «занят»
RATE = 120
RESOLVERS = {"Google": "8.8.8.8", "Cloudflare": "1.1.1.1", "Яндекс": "77.88.8.8"}
MAX_CONN = 16        # соединений разом (на каждое — поток); сверх — закрываем сразу
HEAD_MAX = 16384     # байт на строку запроса и заголовки вместе
HEAD_TIME = 10       # секунд на весь запрос: досылкой по байту соединение не удержать
TLS_WAIT = 10        # секунд на первый байт и рукопожатие TLS
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")  # метка имени по правилам DNS


def cred_path(name, default):
    """Файл из $CREDENTIALS_DIRECTORY (LoadCredential), если он там есть; иначе — путь по умолчанию."""
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    p = os.path.join(d, name) if d else ""
    return p if p and os.path.isfile(p) else default


def is_local(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def good_label(p):
    """Метка имени: 1–63 символа a-z, 0-9 и «-», дефис не первым и не последним; у xn-- после префикса не пусто."""
    return bool(LABEL_RE.fullmatch(p)) and not (p.startswith("xn--") and not p[4:].strip("-"))


def allowed_name(name, suffixes):
    """Имя на своих доменах: только ASCII, метки по правилам DNS (иначе кодек имён падает на «a..x» и длинной метке,
    а «-» и «xn--» уходили в системный резолвер)."""
    name = (name or "").strip().lower().rstrip(".")
    ok = name and len(name) <= 253 and all(good_label(p) for p in name.split("."))
    return name if ok and any(name == s or name.endswith("." + s) for s in suffixes) else None


def allowed_host(name, cfg):
    """Имя на своих доменах либо адрес, явно перечисленный в настройках (hosts)."""
    return allowed_name(name, cfg["suffixes"]) or next(
        (h for h in cfg.get("hosts", []) if h == (name or "").strip().lower()), None)


def number(text, low, high, default):
    try:
        return max(low, min(high, int(text)))
    except (TypeError, ValueError):
        return default


class HeadReader:
    """Чтение запроса с пределами: не больше cap байт и не дольше чем до deadline на всё вместе
    (заголовки по 64 КБ и досылка по байту не держат память и поток). Тела запросов агент не читает."""

    def __init__(self, sock, orig, cap=HEAD_MAX, wait=HEAD_TIME):
        self.sock, self.orig, self.left, self.deadline, self.buf = sock, orig, cap, time.monotonic() + wait, b""

    def readline(self, limit=-1):
        while True:
            i = self.buf.find(b"\n")
            if i >= 0 or 0 <= limit <= len(self.buf):
                n = i + 1 if i >= 0 else limit
                n = min(n, limit) if limit >= 0 else n
                line, self.buf = self.buf[:n], self.buf[n:]
                return line
            wait = self.deadline - time.monotonic()
            if wait <= 0 or self.left <= 0:
                raise TimeoutError("запрос слишком долгий или большой")  # handle_one_request закроет соединение
            self.sock.settimeout(wait)
            data = self.sock.recv(min(4096, self.left))
            if not data:
                line, self.buf = self.buf, b""
                return line
            self.left -= len(data)
            self.buf += data

    def read(self, n=-1):
        return b""

    def close(self):
        self.orig.close()


class Agent(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = MAX_CONN

    def __init__(self, addr, cfg, tls=None):
        super().__init__(addr, Handler)
        self.cfg, self.tls = cfg, tls
        self.slots = threading.BoundedSemaphore(MAX_PARALLEL)
        self.conns = threading.BoundedSemaphore(MAX_CONN)
        self.lock = threading.Lock()
        self.window = []

    def verify_request(self, request, client_address):
        # чужой адрес — закрыть сразу, до потока и до чтения заголовков; 127.0.0.1 — для самопроверки (ответ 403)
        return client_address[0] in self.cfg["allow"] or is_local(client_address[0])

    def process_request(self, request, client_address):
        if not self.conns.acquire(blocking=False):
            return self.shutdown_request(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.conns.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.conns.release()

    def finish_request(self, request, client_address):
        sock = self.open_tls(request, client_address)
        if sock is None:
            return
        try:
            super().finish_request(sock, client_address)
        finally:
            if sock is not request:
                sock.close()

    def open_tls(self, sock, addr):
        """Один порт на оба вида: первый байт 0x16 — рукопожатие TLS, иначе обычный HTTP (старый сторож).
        None — соединение не принимаем (оборвалось, не то рукопожатие, HTTP при tls_only)."""
        sock.settimeout(TLS_WAIT)
        try:
            first = sock.recv(1, socket.MSG_PEEK)
        except OSError:
            return None
        if not first:
            return None
        if first == b"\x16" and self.tls:
            try:
                return self.tls.wrap_socket(sock, server_side=True)
            except (OSError, ValueError):
                return None
        if self.cfg.get("tls_only") and not is_local(addr[0]):
            return None
        return sock

    def handle_error(self, request, client_address):
        pass  # обрывы и мусор от сети — не в журнал

    def rate_ok(self):
        now = time.time()
        with self.lock:
            self.window = [t for t in self.window if now - t < 60]
            if len(self.window) >= RATE:
                return False
            self.window.append(now)
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    server_version, sys_version = "", ""
    error_message_format, error_content_type = "", "text/plain"  # ошибки разбора — без страницы с подписью
    timeout = 15

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.rfile = HeadReader(self.connection, self.rfile)

    def parse_request(self):
        ok = super().parse_request()
        self.connection.settimeout(self.timeout)  # запрос прочитан — дальше обычный срок на ответ
        return ok

    def send_response(self, code, message=None):
        # без заголовка Server — агента не узнать по подписи
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8") if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8" if body else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv, cfg = self.server, self.server.cfg
        token = (self.headers.get("X-Token") or "").encode()
        if self.client_address[0] not in cfg["allow"] or not hmac.compare_digest(token, cfg["token"].encode()):
            return self.reply(403, None)  # без JSON: снаружи — обычный отказ
        if self.headers.get("Transfer-Encoding") or (self.headers.get("Content-Length") or "0").strip() != "0":
            return self.reply(413, None)  # тел запросов агент не принимает и не читает
        if not srv.rate_ok():
            return self.reply(429, {"error": "rate"})
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        ports = cfg.get("ports", [443])
        if url.path == "/health":
            return self.reply(200, {"ok": True, "ts": int(time.time()), "name": cfg.get("name", ""), "v": VERSION,
                                    "ports": ports, "vpn": bool(cfg.get("vpn")), "caps": CAPS,
                                    "tls": bool(srv.tls), "tls_only": bool(cfg.get("tls_only"))})
        if url.path == "/vpn":
            # проверка плитки через свой клиент Xray — только плитки из своего списка каналов
            chans = vpn_channels() if cfg.get("vpn") else None
            if chans is None:
                return self.reply(400, {"error": "no vpn"})
            if not q.get("name"):
                return self.reply(200, {"names": [c.get("name") for c in chans]})
            ch = next((c for c in chans if c.get("name") == q["name"] and isinstance(c.get("port"), int)), None)
            if not ch:
                return self.reply(404, {"error": "no such tile"})
            if not srv.slots.acquire(timeout=WAIT_SLOT):
                return self.reply(429, {"error": "busy"})
            try:
                return self.reply(200, dict(netprobe.socks_load(ch["port"]), name=ch["name"]))
            finally:
                srv.slots.release()
        if url.path == "/services":
            try:
                import rucheck
            except ImportError:
                return self.reply(400, {"error": "no rucheck"})
            if not srv.slots.acquire(timeout=WAIT_SLOT):
                return self.reply(429, {"error": "busy"})
            try:
                if isinstance(cfg.get("services"), list) and cfg["services"]:
                    hosts = [str(h) for h in cfg["services"]]
                else:
                    foreign, local = rucheck.services_list()
                    hosts = list(foreign) + list(local)
                got = rucheck.check_all(hosts)
                keep = ("verdict", "code", "sys", "doh")
                return self.reply(200, {"services": {h: {k: v.get(k) for k in keep} for h, v in got.items()}})
            finally:
                srv.slots.release()
        if url.path == "/profile":
            if not srv.slots.acquire(timeout=WAIT_SLOT):
                return self.reply(429, {"error": "busy"})
            try:
                prof = cfg.get("profile") or DEFAULT_PROFILE
                return self.reply(200, netprobe.profile_run(prof["sites"], prof["loads"]))
            finally:
                srv.slots.release()
        if url.path == "/dns":
            name = allowed_name(q.get("name") or q.get("host"), cfg["suffixes"])
        else:
            name = allowed_host(q.get("host") or q.get("name"), cfg)
        if url.path not in ("/probe", "/dns", "/series", "/sni", "/path", "/sniref") or not name:
            return self.reply(400, {"error": "bad request"})
        port = number(q.get("port") or 443, 0, 65535, 0)
        if url.path != "/dns" and port not in ports:
            return self.reply(400, {"error": "bad port"})
        # имя TLS — само имя сервера либо одно из разрешённых в настройках (у ретранслятора оно чужое)
        sni = q.get("sni") if q.get("sni") in cfg.get("snis", []) else name
        if not srv.slots.acquire(timeout=WAIT_SLOT):
            return self.reply(429, {"error": "busy"})
        try:
            if url.path == "/dns":
                # udp=0 — только системный DNS: имя своей ноды не уходит открытым текстом к публичным резолверам
                udp = {} if q.get("udp") == "0" else RESOLVERS
                out = {"system": list(netprobe.resolve_system(name)),
                       "udp": {who: list(netprobe.dns_udp(name, ip)) for who, ip in udp.items()}}
            elif url.path == "/series":
                out = netprobe.series(name, port, number(q.get("n"), 1, netprobe.SERIES_MAX, 20),
                                      number(q.get("mss"), *netprobe.MSS_MARK, None))
            elif url.path == "/sni":
                out = netprobe.sni_compare(name, port, sni, number(q.get("mss"), *netprobe.MSS_MARK, None)) or {"addr": None}
            elif url.path == "/path":
                out = netprobe.path_trace(name, port) or {"addr": None, "unsupported": True}
            elif url.path == "/sniref":
                out = netprobe.name_ref(sni)
            else:
                out = probe(name, port, sni, cfg.get("tls", True), q.get("verify") == "1")
            self.reply(200, out)
        except (UnicodeError, ValueError):
            self.reply(400, {"error": "bad name"})  # кодек имён (idna) не принял имя — ответ, а не обрыв с трассировкой
        finally:
            srv.slots.release()

    def do_other(self):
        self.reply(405, None)  # тело не читаем

    do_POST = do_PUT = do_DELETE = do_PATCH = do_other


def probe(name, port, sni, tls, verify):
    """direct_probe; verify — ещё и сверка сертификата (netprobe без verify — проверка без неё)."""
    if verify:
        try:
            return netprobe.direct_probe(name, port, sni=sni, tls=tls, verify=True)
        except TypeError:
            pass
    return netprobe.direct_probe(name, port, sni=sni, tls=tls)


def tls_context(cfg):
    """Контекст TLS из cert.pem и key.pem; None — файлов нет (агент поставлен до TLS: только HTTP)."""
    cert = cred_path("cert.pem", cfg.get("tls_cert", CERT))
    key = cred_path("key.pem", cfg.get("tls_key", KEY))
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def main(conf=None):
    cfg = json.load(open(conf or cred_path("agent.json", CONF), encoding="utf-8"))
    assert len(cfg["token"]) >= 32 and cfg["allow"] and cfg["suffixes"], "в настройках нет токена, списка адресов или доменов"
    tls = tls_context(cfg)
    assert tls or not cfg.get("tls_only"), "в настройках tls_only, а сертификата нет (cert.pem, key.pem)"
    Agent((cfg.get("bind", "0.0.0.0"), int(cfg.get("port", 9109))), cfg, tls).serve_forever()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
