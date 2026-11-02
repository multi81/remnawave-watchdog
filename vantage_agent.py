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
"""
import hmac
import os
import http.server
import json
import sys
import threading
import time
import urllib.parse

import netprobe

CONF = "/etc/vantage-agent/agent.json"
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
VERSION = 5         # 5 — VPN-точка: /vpn?name=<плитка> через свой клиент Xray (если в настройках "vpn": true)
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


def allowed_name(name, suffixes):
    name = (name or "").strip().lower().rstrip(".")
    ok = name and len(name) <= 253 and all(c.isalnum() or c in "-." for c in name)
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


class Agent(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, cfg):
        super().__init__(addr, Handler)
        self.cfg = cfg
        self.slots = threading.BoundedSemaphore(MAX_PARALLEL)
        self.lock = threading.Lock()
        self.window = []

    def rate_ok(self):
        now = time.time()
        with self.lock:
            self.window = [t for t in self.window if now - t < 60]
            if len(self.window) >= RATE:
                return False
            self.window.append(now)
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    server_version, sys_version = "va", ""
    timeout = 15

    def log_message(self, *args):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv, cfg = self.server, self.server.cfg
        token = (self.headers.get("X-Token") or "").encode()
        if self.client_address[0] not in cfg["allow"] or not hmac.compare_digest(token, cfg["token"].encode()):
            return self.reply(403, {"error": "forbidden"})
        if not srv.rate_ok():
            return self.reply(429, {"error": "rate"})
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        ports = cfg.get("ports", [443])
        if url.path == "/health":
            return self.reply(200, {"ok": True, "ts": int(time.time()), "name": cfg.get("name", ""), "v": VERSION,
                                    "ports": ports, "vpn": bool(cfg.get("vpn"))})
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
                out = {"system": list(netprobe.resolve_system(name)),
                       "udp": {who: list(netprobe.dns_udp(name, ip)) for who, ip in RESOLVERS.items()}}
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
                out = netprobe.direct_probe(name, port, sni=sni, tls=cfg.get("tls", True))
            self.reply(200, out)
        finally:
            srv.slots.release()


def main(conf=CONF):
    cfg = json.load(open(conf, encoding="utf-8"))
    assert len(cfg["token"]) >= 32 and cfg["allow"] and cfg["suffixes"], "в настройках нет токена, списка адресов или доменов"
    Agent((cfg.get("bind", "0.0.0.0"), int(cfg.get("port", 9109))), cfg).serve_forever()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else CONF)
