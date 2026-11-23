"""Тесты: токен бота щита не в argv curl; имена наших нод не уходят в публичные DNS по UDP (подмена по пути — на
чужих именах); TLS-проба отличает «сертификат не тот» от «нет связи»; pull() читает кусками со сроком на каждом куске.
Без внешней сети (только 127.0.0.1): PYTHONIOENCODING=utf-8 python test_netprobe_dns.py"""
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blockwatch as bw  # noqa: E402
import netprobe as npb  # noqa: E402
import shieldbot as b  # noqa: E402

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)

ok = 0
skipped = []


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    return s, s.getsockname()[1]


def serve(srv, handler):
    """Каждое соединение — в своей нити; handler(conn)."""
    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=lambda c=c: _safe(handler, c), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def _safe(handler, c):
    try:
        handler(c)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def read_request(c):
    data = b""
    while b"\r\n\r\n" not in data:
        part = c.recv(4096)
        if not part:
            return None
        data += part
    return data


# ===================== токен бота не в argv =====================
class FakeProbe:
    @staticmethod
    def tg_env():
        return "123456:SECRET-TOKEN", "42"

    @staticmethod
    def tg_routes():
        return [None, "socks5h://127.0.0.1:21004"]


calls = []


def fake_run(cmd, input=None, **kw):
    calls.append((list(cmd), input))
    out = "" if len(calls) == 1 else '{"ok": true, "result": []}'   # напрямую не вышло, через канал — ответ
    return subprocess.CompletedProcess(cmd, 0, out, "")


real_probe, real_run = b._probe, b.subprocess.run
b._probe = lambda: FakeProbe
b.subprocess.run = fake_run
try:
    payload = {"chat_id": "42", "text": 'кнопка "да" \\ <b>щит</b>'}
    r = b.tg_call("sendMessage", payload)
finally:
    b._probe, b.subprocess.run = real_probe, real_run
check("Т1 tg_call: ответ Telegram получен со второго маршрута", r == {"ok": True, "result": []} and len(calls) == 2)
check("Т2 токена нет в argv ни на одном маршруте (ps, /proc/*/cmdline)",
      all("SECRET" not in " ".join(cmd) and "api.telegram.org" not in " ".join(cmd) for cmd, _ in calls))
check("Т3 адрес и тело — конфигом curl на stdin (-K -), прокси — как раньше",
      all(cmd[-2:] == ["-K", "-"] for cmd, _ in calls) and calls[1][0][1:3] == ["-x", "socks5h://127.0.0.1:21004"]
      and 'url = "https://api.telegram.org/bot123456:SECRET-TOKEN/sendMessage"' in calls[0][1])
check("Т4 конфиг: кавычки и \\ экранированы, тело одной строкой", b.curl_config("u", '{"a": "x\\"y\\\\z"}')
      == 'url = "u"\ndata-binary = "{\\"a\\": \\"x\\\\\\"y\\\\\\\\z\\"}"\n')

# настоящий curl читает такой конфиг и шлёт тело байт в байт
curl = shutil.which("curl")
if curl:
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got["path"] = self.path
            got["type"] = self.headers.get("Content-Type")
            got["body"] = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *a):
            pass

    hs = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    body = json.dumps({"chat_id": "42", "text": 'кнопка "да" \\ <b>щит</b> & @file'})
    url = "http://127.0.0.1:%d/bot123:SECRET/sendMessage" % hs.server_address[1]
    rr = subprocess.run([curl, "-s", "-m", "10", "--noproxy", "*", "-X", "POST", "-H", "Content-Type: application/json",
                         "-K", "-"], input=b.curl_config(url, body), capture_output=True, text=True, timeout=20)
    hs.shutdown()
    check("Т5 настоящий curl: адрес из конфига, тело дошло без искажений, ответ прочитан",
          got.get("path") == "/bot123:SECRET/sendMessage" and got.get("body") == body.encode()
          and got.get("type") == "application/json" and json.loads(rr.stdout) == {"ok": True})
else:
    skipped.append("Т5 (нет curl)")

# ===================== наши имена — не в публичные DNS =====================
udp_calls, agent_calls = [], []
real_udp, real_sys, real_aget, real_doh = npb.dns_udp, npb.resolve_system, bw.agent_get, bw.doh
SPOOF = {}   # имя -> подменный ответ публичных резолверов


def fake_udp(name, server, port=53, timeout=3):
    udp_calls.append((name, server))
    if name in SPOOF and server in ("8.8.8.8", "77.88.8.8"):
        return "ok", [SPOOF[name]]
    return "ok", ["10.0.0.1"]


AG_NEW = {"name": "Москва", "url": "u1", "token": "t"}
AG_OLD = {"name": "Timeweb", "url": "u2", "token": "t"}


def fake_aget(a, path, timeout=20):
    agent_calls.append((a["name"], path))
    if path == "/health":
        return {"ok": True, "v": 7, "caps": ["dns_udp0"]} if a["url"] == "u1" else {"ok": True, "v": 6}
    if path.startswith("/dns"):
        return {"system": ["ok", ["10.0.0.1"]], "udp": {}}
    return None


npb.dns_udp, npb.resolve_system, bw.agent_get = fake_udp, lambda name: ("ok", ["10.0.0.1"]), fake_aget
bw.doh = lambda name, socks_port=None: {"10.0.0.1"}
try:
    seen = bw.dns_observe("pl1.example.net", [dict(AG_NEW, dns_udp0=True), dict(AG_OLD, dns_udp0=False)])
    check("Д1 наше имя: публичные DNS по UDP не спрашиваем вовсе",
          udp_calls == [] and set(seen) == {"rf1: системный", "Москва: системный"})
    check("Д2 наше имя: новой точке — /dns с udp=0, старой (без caps) имя не отдаём",
          agent_calls == [("Москва", "/dns?name=pl1.example.net&udp=0")])
    agent_calls.clear()
    seen = bw.dns_observe("rutracker.org", [dict(AG_NEW, dns_udp0=True)])
    check("Д3 чужое имя: системный и четыре публичных резолвера по UDP; точкам его не шлём",
          sorted(s for _, s in udp_calls) == sorted(ip for _, ip in bw.RESOLVERS) and agent_calls == []
          and set(seen) == {"rf1: системный"} | {f"rf1: {w}" for w, _ in bw.RESOLVERS})

    udp_calls.clear()
    agent_calls.clear()
    ours = ["panel.example.com", "pl1.example.net"]
    res = bw.dns_check(ours, 21004, [AG_NEW, AG_OLD])
    check("Д4 dns_check: по UDP уходят только чужие имена, наших среди них нет",
          udp_calls and {n for n, _ in udp_calls} <= set(bw.DNS_REF_NAMES) and not {n for n, _ in udp_calls} & set(ours))
    check("Д5 dns_check: возможности точек — по /health; /dns только у новой точки и с udp=0",
          ("Москва", "/health") in agent_calls and ("Timeweb", "/health") in agent_calls
          and not any(n == "Timeweb" and p.startswith("/dns") for n, p in agent_calls)
          and all(p.endswith("&udp=0") for n, p in agent_calls if p.startswith("/dns")))
    check("Д6 вид ответа прежний (probe.py старой версии читает truth/odd/asked/system); подмены нет — без path",
          set(res) == set(ours) and all(set(v) == {"truth", "odd", "asked", "system"} for v in res.values())
          and res["panel.example.com"]["system"] == {"rf1": "ok", "Москва": "ok"})
    pts = bw.dns_points(res, [AG_NEW, AG_OLD])
    check("Д7 dns_points: старая точка без ответа просто не считается", pts == {"rf1": (0, 2), "Москва": (0, 2)})

    SPOOF["rutracker.org"] = "95.167.13.50"
    res = bw.dns_check(ours, 21004, [])
    path = res["panel.example.com"].get("path")
    check("Д8 два публичных резолвера подменяют чужое имя — у каждого нашего имени пометка path",
          path and sorted(w for w, n, _ in path) == ["rf1: Google", "rf1: Яндекс"]
          and all(n == "rutracker.org" for _, n, _ in path) and res["pl1.example.net"]["path"] == path)
    res["panel.example.com"]["odd"] = [["rf1: системный", "6.6.6.6"], ["Москва: системный", "6.6.6.6"]]
    text = bw.dns_alert("panel.example.com", res["panel.example.com"], "bad")
    check("Д9 тревога о подмене говорит и о подмене по пути на чужих именах",
          "<b>По пути:</b>" in text and "rutracker.org" in text and "Подмена DNS: panel.example.com" in text)
    SPOOF.clear()
    SPOOF["www.example.org"] = "6.6.6.6"
    udp_calls.clear()
    real_udp_inner = npb.dns_udp
    npb.dns_udp = lambda name, server, port=53, timeout=3: (udp_calls.append((name, server)) or
                                                          (("ok", ["6.6.6.6"]) if server == "8.8.8.8" else ("ok", ["10.0.0.1"])))
    res = bw.dns_check(ours, 21004, [])
    npb.dns_udp = real_udp_inner
    check("Д10 разошёлся один публичный резолвер — это ещё не подмена по пути (как DNS_MIN для наших имён)",
          all("path" not in v for v in res.values()))
    check("Д11 тревога без path — прежний текст", "По пути" not in bw.dns_alert("panel.example.com", res["panel.example.com"], "bad"))
finally:
    npb.dns_udp, npb.resolve_system, bw.agent_get, bw.doh = real_udp, real_sys, real_aget, real_doh

# ===================== pull() кусками и со сроком =====================


def big_body(c):
    """Content-Length 400 МБ, тело отдаём быстро, пока читают."""
    if read_request(c) is None:
        return
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 400000000\r\n\r\n")
    chunk = b"x" * 65536
    for _ in range(400000000 // 65536):
        c.sendall(chunk)


def trickle(c):
    """Заголовки, потом по байту каждые 0,3 с — бесконечно (раньше read() ждал конца тела без срока)."""
    if read_request(c) is None:
        return
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n")
    for _ in range(200):
        c.sendall(b"y")
        time.sleep(0.3)


def chunked(c):
    """Ответы с Transfer-Encoding: chunked по 5000 байт, соединение держим."""
    while read_request(c) is not None:
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1388\r\n" + b"z" * 5000 + b"\r\n0\r\n\r\n")


srv_big, p_big = listener()
serve(srv_big, big_body)
srv_tr, p_tr = listener()
serve(srv_tr, trickle)
srv_ch, p_ch = listener()
serve(srv_ch, chunked)

tracemalloc.start()
t0 = time.time()
s = socket.create_connection(("127.0.0.1", p_big), timeout=5)
got, end = npb.pull(s, "127.0.0.1", need=64 * 1024, deadline=10)
s.close()
_, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
check("П1 тело 400 МБ: набрали need и остановились, не читая всё (память и время малы)",
      end == "ok" and 64 * 1024 <= got <= 64 * 1024 + 200 + npb.PULL_CHUNK and peak < 4 * 1024 * 1024
      and time.time() - t0 < 5)

out = {}
t0 = time.time()
s = socket.create_connection(("127.0.0.1", p_tr), timeout=5)
th = threading.Thread(target=lambda: out.update(r=npb.pull(s, "127.0.0.1", need=64 * 1024, deadline=2)), daemon=True)
th.start()
th.join(8)
took = time.time() - t0
s.close()
check("П2 медленное тело (байт раз в 0,3 с): срок проверяется на каждом куске — «deadline» за ~2 с, слот не висит",
      out.get("r") and out["r"][1] == "deadline" and 200 < out["r"][0] < 300 and took < 4)

s = socket.create_connection(("127.0.0.1", p_ch), timeout=5)
got, end = npb.pull(s, "127.0.0.1", need=20000, deadline=10)
s.close()
check("П3 chunked-ответы по одному соединению: объём набирается, как раньше", end == "ok" and 20000 <= got <= 21000)

# ===================== сертификат не тот =====================
openssl = shutil.which("openssl")
tmp = tempfile.mkdtemp(prefix="p34net-")


def ossl(*args):
    return subprocess.run([openssl, *args], capture_output=True, text=True, timeout=60,
                          env=dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")).returncode == 0


def make_certs():
    ca_key, ca = os.path.join(tmp, "ca.key"), os.path.join(tmp, "ca.pem")
    key, csr, crt = (os.path.join(tmp, n) for n in ("srv.key", "srv.csr", "srv.pem"))
    ext = os.path.join(tmp, "ext.cnf")
    open(ext, "w").write("subjectAltName=DNS:node.test\nbasicConstraints=CA:FALSE\n")
    okk = (ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca, "-days", "3",
                "-subj", "/CN=Test Root CA")
           and ossl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=node-cn.test")
           and ossl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-out", crt,
                    "-days", "3", "-extfile", ext))
    # без SAN — имя берётся из CN владельца
    key2, crt2 = os.path.join(tmp, "nosan.key"), os.path.join(tmp, "nosan.pem")
    okk = okk and ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key2, "-out", crt2, "-days", "3",
                       "-subj", "/CN=*.yccdn.example.net")
    return okk and (ca, key, crt, key2, crt2)


certs = make_certs() if openssl else None
if certs:
    ca, key, crt, key2, crt2 = certs
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(crt, key)

    def tls_page(c):
        try:
            t = sctx.wrap_socket(c, server_side=True)
        except (ssl.SSLError, OSError):
            return
        with t:
            while read_request(t) is not None:
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n" + b"p" * 4000)

    srv_tls, p_tls = listener()
    serve(srv_tls, tls_page)

    der = ssl.PEM_cert_to_DER_cert(open(crt).read())
    der2 = ssl.PEM_cert_to_DER_cert(open(crt2).read())
    check("С1 cert_cn: имя из SAN; без SAN — CN владельца, а не издателя",
          npb.cert_cn(der) == "node.test" and npb.cert_cn(der2) == "*.yccdn.example.net" and npb.cert_cn(b"\x00") is None)

    npb.CERT_CAFILE = ca
    try:
        r = npb.direct_probe("127.0.0.1", p_tls, sni="node.test", need=10000, verify=True)
        check("С2 свой сертификат на своё имя — cert ok, класс ok, объём набран",
              r["tls"] is True and r["cert"] == "ok" and r["cert_cn"] == "node.test" and r["end"] == "ok"
              and npb.probe_class(r) == "ok")
        r = npb.direct_probe("127.0.0.1", p_tls, sni="cdn.test", need=10000, verify=True)
        check("С3 сертификат на другое имя (как CDN отдал свой) — cert name, класс cert, а не ok и не tls",
              r["tls"] is True and r["cert"] == "name" and r["cert_cn"] == "node.test" and npb.probe_class(r) == "cert")
        r = npb.direct_probe("127.0.0.1", p_tls, sni="cdn.test", need=10000)
        check("С4 без verify — как раньше: сертификат не сверяется, ключа cert нет, класс ok",
              "cert" not in r and "cert_cn" not in r and npb.probe_class(r) == "ok")
    finally:
        npb.CERT_CAFILE = None
    r = npb.direct_probe("127.0.0.1", p_tls, sni="node.test", need=10000, verify=True)
    check("С5 не заверен доверенным центром (системные корни) — cert chain, класс cert", r["cert"] == "chain"
          and npb.probe_class(r) == "cert")
    dead_s, dead_port = listener()
    dead_s.close()
    check("С6 сверка не смогла соединиться — None (не судим), класс по остальному",
          npb.cert_check("127.0.0.1", dead_port, "node.test") is None
          and npb.probe_class(dict(r, cert=None)) == "ok")
else:
    skipped.append("С1–С6 (нет openssl)")

# классы и тексты сторожа
base = {"host": "cdn.example", "addr": "1.2.3.4", "tcp": "open", "tcp_ms": 30, "tls": True, "bytes": 70000,
        "need": 65536, "end": "ok"}
bad = dict(base, cert="name", cert_cn="*.yccdn.cloud.yandex.net")
check("С7 point_text: «сертификат не тот» и на чьё имя", "сертификат не тот: выдан на другое имя (*.yccdn.cloud.yandex.net)"
      in bw.point_text(bad))
check("С8 cert_why: просрочен / не заверен", "просрочен" in bw.cert_why({"cert": "expired"})
      and "не заверен" in bw.cert_why({"cert": "chain", "cert_cn": "x.test"}))
d = {"direct": bad, "agents": {"Москва": dict(base)}, "abroad": True, "series": {}, "sni": {}}
v = bw.deep_verdict(d, "DOWN")
check("С9 rf1 видит чужой сертификат, старая точка не сверяла — вывод «сертификат не тот», не «дело в Xray»",
      "сертификат не тот" in v and "CDN" in v and "дело в Xray на ноде" not in v)
d["agents"]["Москва"] = dict(base, cert="ok", cert_cn="cdn.example")
v = bw.deep_verdict(d, "DOWN")
check("С10 с другой точки сертификат сверен и настоящий — подмена по пути у части провайдеров", "подмену по пути" in v
      and "rf1" in v and "Москва" in v)
d = {"direct": dict(base), "agents": {}, "abroad": True, "series": {}, "sni": {}}
check("С11 без сверки — прежний вывод", "дело в Xray на ноде" in bw.deep_verdict(d, "DOWN"))
check("С12 node_line: точка с чужим сертификатом — в «⚠️»", bw.node_line("CDN", {"direct": bad, "agents": {}, "abroad": True})
      .startswith("⚠️") and "сертификат не тот" in bw.node_line("CDN", {"direct": bad, "agents": {}, "abroad": True}))

# разбор сбоя: сверка только у каналов с обычным TLS; старый netprobe без verify — без неё
asked = {"direct": [], "agent": []}
real_dp, real_aget2 = npb.direct_probe, bw.agent_get
real_parts = (npb.series, npb.sni_compare, npb.tcp_trace, npb.neighbours, npb.name_ref, npb.own_addr, bw.witness_wait,
              bw.add_hop_info)


def dp_new(host, port=443, sni=None, need=npb.NEED, tls=True, deadline=12, verify=False):
    asked["direct"].append((host, sni, verify))
    return dict(base, cert="name", cert_cn="*.cdn.test") if verify else dict(base)


npb.direct_probe = dp_new
bw.agent_get = lambda a, path, timeout=20: asked["agent"].append(path) or None
npb.series = lambda host, port=443, n=20, mss=None, **kw: {"n": n, "ok": n, "fail": 0}
npb.sni_compare = lambda *a, **k: None
npb.tcp_trace = lambda *a, **k: None
npb.own_addr = lambda: None
bw.witness_wait = lambda *a, **k: {}
bw.add_hop_info = lambda *a, **k: None
try:
    ch_tls = {"name": "CDN", "entry": "cdn.example", "entry_port": 443, "sni": "cdn.example", "security": "tls"}
    ch_rl = {"name": "PL", "entry": "pl.example", "entry_port": 443, "sni": "www.google.com", "security": "reality"}
    ag = [{"name": "Москва", "url": "u", "token": "t"}]
    dd = bw.deep_diag(ch_tls, None, ag, ("example",))
    check("С13 канал с TLS: rf1 сверяет сертификат, точке — /probe с verify=1 (остальные запросы без него)",
          asked["direct"] == [("cdn.example", "cdn.example", True)] and dd["direct"]["cert"] == "name"
          and "/probe?host=cdn.example&port=443&verify=1" in asked["agent"]
          and all("verify" not in p for p in asked["agent"] if not p.startswith("/probe")))
    asked["direct"].clear()
    asked["agent"].clear()
    bw.deep_diag(ch_rl, None, ag, ("example",))
    check("С14 Reality: сертификат не сверяем (у него чужой по устройству)",
          asked["direct"] == [("pl.example", "www.google.com", False)] and not any("verify" in p for p in asked["agent"]))
    asked["direct"].clear()
    npb.direct_probe = lambda host, port=443, sni=None, need=npb.NEED, tls=True, deadline=12: (
        asked["direct"].append((host, sni)) or dict(base))
    bw.CERT_CHECK = True
    dd = bw.deep_diag(ch_tls, None, [], ("example",))
    check("С15 старый netprobe без verify — проверка идёт как раньше, без падения", asked["direct"] == [("cdn.example", "cdn.example")]
          and "cert" not in dd["direct"])
    bw.CERT_CHECK = False
    asked["direct"].clear()
    npb.direct_probe = dp_new
    bw.deep_diag(ch_tls, None, [], ("example",))
    check("С16 CERT_CHECK = False — сверку можно выключить", asked["direct"] == [("cdn.example", "cdn.example", False)])
finally:
    bw.CERT_CHECK = True
    npb.direct_probe, bw.agent_get = real_dp, real_aget2
    (npb.series, npb.sni_compare, npb.tcp_trace, npb.neighbours, npb.name_ref, npb.own_addr, bw.witness_wait,
     bw.add_hop_info) = real_parts

shutil.rmtree(tmp, ignore_errors=True)
print("токен, DNS, сертификат, pull: тестов пройдено %d" % ok + (" (пропущено: %s)" % ", ".join(skipped) if skipped else ""))
