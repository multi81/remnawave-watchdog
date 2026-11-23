"""Тесты: порог «Подмена DNS» при малом числе ответивших,
TLS у точек проверки (blockwatch.agent_get по TLS с отпечатком, add_vantage проверяет sha256, install.sh и vantage_update.sh
копируют нужное), бюджет сверки сертификата и «встало у срока» в netprobe, /health точек разом, ожидание файла
свидетеля, отказ --public IPv6 и LC_ALL=C у ufw, подсказка SELF и reset-failed в guard_install.sh, метки имён в
vantage_agent.allowed_name. Без внешней сети: PYTHONIOENCODING=utf-8 python test_tls_dns_installers.py"""
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
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import netprobe  # noqa: E402
import probe  # noqa: E402
import vantage_agent as va  # noqa: E402
import vantage_client as vc  # noqa: E402

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)

ok = 0
skipped = []


def check(name, cond):
    global ok
    print(("OK   " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    ok += 1


def src_of(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


def git_bash():
    if os.name != "nt":
        return shutil.which("bash")
    for p in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if p and os.path.exists(p) and "system32" not in p.lower():
            return p
    return None


BASH = git_bash()
tmp = tempfile.mkdtemp()
T = tmp.replace("\\", "/")


def sh(script, timeout=60):
    shim = 'python3() { "%s" "$@"; }\nexport -f python3\n' % sys.executable.replace("\\", "/")
    r = subprocess.run([BASH, "-c", shim + script], capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# ---------- 2. порог «Подмена DNS»: ответивших меньше DNS_MIN — не тревога ----------
O1, O2 = ["rf1: системный", "6.6.6.6"], ["Москва: системный", "6.6.6.6"]
check("D1 blockwatch.dns_level: одна rf1 с расхождением — None (вывода нет), DNS_MIN расхождений — bad, "
      "расхождений меньше порога при многих ответивших — ok",
      blockwatch.dns_level({"asked": 1, "odd": [O1]}) is None and blockwatch.dns_level({"asked": 2, "odd": [O1, O2]}) == "bad"
      and blockwatch.dns_level({"asked": 4, "odd": [O1]}) == "ok" and blockwatch.dns_level({"asked": 1, "odd": []}) == "ok"
      and blockwatch.DNS_MIN == 2)
check("D2 probe.dns_level — то же (probe работает и со старым blockwatch), порог не снижен: dns_need = DNS_MIN",
      probe.dns_level({"asked": 1, "odd": [O1]}) is None and probe.dns_level({"asked": 2, "odd": [O1, O2]}) == "bad"
      and probe.dns_need({"asked": 1}) == blockwatch.DNS_MIN)
CLEAN = {"sources": {}, "hits": {}, "targets": {"ips": 1, "names": 1}}
res = {"lists": CLEAN, "health": {}, "nodes": {}, "external": False, "dns_names": 2,
       "dns": {"a.example.net": {"truth": ["1.1.1.1"], "odd": [O1], "asked": 1},
               "b.example.net": {"truth": ["1.1.1.1"], "odd": [O1, O2], "asked": 2}}}
text = blockwatch.check_text(res, "сейчас")
la = next(x for x in text.splitlines() if "a.example.net" in x)
lb = next(x for x in text.splitlines() if "b.example.net" in x)
check("D3 проверка по запросу: расхождение при одном ответившем — «ℹ️ … пока это не подмена», "
      "DNS_MIN расхождений — «⚠️» как раньше", la.startswith("ℹ️") and "пока это не подмена" in la
      and lb.startswith("⚠️") and "не подмена" not in lb)


# ---------- 6. /health точек разом ----------
def slow_agent_get(agent, path, timeout=20):
    if path == "/health":
        time.sleep(1.0)  # точка отвечает долго (или не отвечает до таймаута)
        return {"ok": True, "caps": ["dns_udp0"]} if agent["name"] != "Старая" else {"ok": True}
    return {"system": ["ok", ["1.1.1.1"]], "udp": {}}


AG = [{"name": n, "url": "http://x", "token": "t"} for n in ("Москва", "Офис", "Старая", "Дом")]
real = (blockwatch.agent_get, blockwatch.dns_truth, blockwatch.netprobe.resolve_system, blockwatch.dns_path)
blockwatch.agent_get = slow_agent_get
blockwatch.dns_truth = lambda name, port: {"1.1.1.1"}
blockwatch.netprobe.resolve_system = lambda name: ("ok", ["1.1.1.1"])
blockwatch.dns_path = lambda port: []
t0 = time.monotonic()
got = blockwatch.dns_check(["a.example.net"], None, AG)
took = time.monotonic() - t0
check("P1 blockwatch.dns_check: /health четырёх точек по 1 с — разом (~1 с, а не 4), caps верны",
      took < 2.5 and got["a.example.net"]["asked"] == 4
      and set(got["a.example.net"]["system"]) == {"rf1", "Москва", "Офис", "Дом"})
t0 = time.monotonic()
h = blockwatch.agents_health(AG)
check("P2 agents_health — тоже разом, порядок и вид ответа прежние ({точка: на связи})",
      time.monotonic() - t0 < 2.5 and list(h) == [a["name"] for a in AG] and all(v is True for v in h.values()))
t0 = time.monotonic()
caps = probe.agents_caps(AG)
check("P3 probe.agents_caps (своя проверка при старом blockwatch) — разом, в порядке точек",
      time.monotonic() - t0 < 2.5 and caps == [True, True, False, True] and probe.agents_caps([]) == [])
blockwatch.agent_get, blockwatch.dns_truth, blockwatch.netprobe.resolve_system, blockwatch.dns_path = real


# ---------- 3. blockwatch.agent_get по TLS для точек с sha256 ----------
plain_calls = []
real_urlopen = urllib.request.urlopen


def spy_urlopen(req, *a, **k):
    plain_calls.append(req.full_url if hasattr(req, "full_url") else str(req))
    return real_urlopen(req, *a, **k)


urllib.request.urlopen = spy_urlopen
TOKEN = "t" * 40
openssl = shutil.which("openssl")
cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
have_cert = bool(openssl) and subprocess.run(
    [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
     "-days", "30", "-subj", "/CN=vantage-agent", "-keyout", key, "-out", cert], capture_output=True).returncode == 0
if have_cert:
    fp = vc.fingerprint(ssl.PEM_cert_to_DER_cert(open(cert).read()))
    cfg = {"token": TOKEN, "allow": ["127.0.0.1"], "suffixes": ["example.net"], "ports": [443]}
    srv = va.Agent(("127.0.0.1", 0), cfg, va.tls_context({"tls_cert": cert, "tls_key": key}))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % srv.server_address[1]
    ag = {"name": "Москва", "url": url, "token": TOKEN, "sha256": fp}
    got = blockwatch.agent_get(ag, "/health", 8)
    check("K1 точка с sha256: blockwatch.agent_get идёт по TLS с отпечатком — ответ есть, обычный HTTP (urllib) не трогается",
          bool(got) and got.get("tls") is True and plain_calls == [])
    check("K2 чужой отпечаток — None, отката на HTTP нет",
          blockwatch.agent_get(dict(ag, sha256="0" * 64), "/health", 8) is None and plain_calls == [])
    got = blockwatch.agent_get({"name": "Москва", "url": url, "token": TOKEN}, "/health", 8)
    check("K3 точка без sha256 — по-старому HTTP (старая запись в vantage.json работает)",
          bool(got) and got.get("ok") and len(plain_calls) == 1 and plain_calls[0].startswith("http://"))
    saved_vc, blockwatch.vantage_client = blockwatch.vantage_client, None
    n = len(plain_calls)
    check("K4 сторож обновлён частично (нет vantage_client.py): точка с sha256 — «не ответила», на HTTP не идём",
          blockwatch.agent_get(ag, "/health", 8) is None and len(plain_calls) == n)
    blockwatch.vantage_client = saved_vc
    srv.shutdown()
    # /dns с плохими метками у живого агента — 400 (п. 10)
    srv = va.Agent(("127.0.0.1", 0), cfg, None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]

    def code(path):
        try:
            with real_urlopen(urllib.request.Request(base + path, headers={"X-Token": TOKEN}), timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    check("N5 живой агент: /dns?name=-.… и xn--.… — 400 (раньше 200 и вопрос резолверу)",
          code("/dns?name=-.example.net&udp=0") == 400 and code("/dns?name=xn--.example.net&udp=0") == 400
          and code("/dns?name=a-.example.net&udp=0") == 400)
    srv.shutdown()
else:
    skipped.append("K1–K4, N5 (нет openssl)")
urllib.request.urlopen = real_urlopen

blockwatch.ETC = tmp
E = {"name": "Москва", "url": "http://1.2.3.4:9109", "token": TOKEN}
try:
    blockwatch.add_vantage(json.dumps(dict(E, sha256="не отпечаток")))
    bad = False
except ValueError:
    bad = True
names = blockwatch.add_vantage(json.dumps(dict(E, sha256="AB:" * 31 + "AB")))
check("K5 add_vantage вызывает vantage_client.check_entry: испорченный sha256 — отказ, настоящий — принят",
      bad and names == ["Москва"] and json.load(open(os.path.join(tmp, "vantage.json"), encoding="utf-8"))[0]["sha256"])
saved_vc, blockwatch.vantage_client = blockwatch.vantage_client, None
try:
    blockwatch.add_vantage(json.dumps(dict(E, sha256="ab" * 32)))
    refused = False
except ValueError as e:
    refused = "vantage_client.py" in str(e)
check("K6 без vantage_client.py запись с sha256 не вносится (точка молча замолчала бы), без sha256 — вносится",
      refused and blockwatch.add_vantage(json.dumps(E)) == ["Москва"])
blockwatch.vantage_client = saved_vc

inst = src_of("install.sh")
a = inst.index("for f in probe.py")
need_line = inst[a:inst.index("\n", a)]
check("K7 install.sh: vantage_client.py обязателен рядом, проверяется на синтаксис и копируется в /opt/channel-watch",
      "vantage_client.py" in need_line and '"$SRC/vantage_client.py"' in inst[inst.index("import ast"):inst.index("# --- ссылка")]
      and 'install -m 644 "$SRC/vantage_client.py" /opt/channel-watch/' in inst)
vi, vu = src_of("vantage_install.sh"), src_of("vantage_update.sh")
a = vi.index('install -m 644 "$SRC/vantage_agent.py"')
inst_files = sorted(x.split("/")[-1].strip('"') for x in vi[a:vi.index("\n", a)].split() if x.startswith('"$SRC/'))
upd_files = sorted(vu[vu.index('FILES="') + 7:vu.index('"', vu.index('FILES="') + 7)].split())
check("K8 vantage_update.sh копирует тот же набор файлов агента, что vantage_install.sh, и подсказывает про TLS",
      inst_files == upd_files == ["netprobe.py", "vantage_agent.py"] and 'for f in $FILES; do install -m 644' in vu
      and "vantage_install.sh --yes" in vu and 'rucheck.py' in vu)


# ---------- 4. netprobe: бюджет сверки сертификата и «встало у срока» ----------
def silent_server():
    """Принимает TCP и молчит (рукопожатие TLS не идёт)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    conns = []
    threading.Thread(target=lambda: [conns.append(s.accept()) for _ in range(8)], daemon=True).start()
    return s, s.getsockname()[1]


def drip_server():
    """Принимает TCP и шлёт по байту раз в 0,4 с (рукопожатие «идёт», но не кончается)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)

    def run():
        c, _ = s.accept()
        try:
            for _ in range(100):
                c.sendall(b"\x16")
                time.sleep(0.4)
        except OSError:
            pass
    threading.Thread(target=run, daemon=True).start()
    return s, s.getsockname()[1]


s1, p1 = silent_server()
t0 = time.monotonic()
r1 = netprobe.cert_check("127.0.0.1", p1, "node.test", budget=1.5)
d1 = time.monotonic() - t0
s2, p2 = drip_server()
t0 = time.monotonic()
r2 = netprobe.cert_check("127.0.0.1", p2, "node.test", budget=1.5)
d2 = time.monotonic() - t0
check("C1 cert_check с бюджетом: молчащий сервер и рукопожатие по байту — None не позже бюджета (строго, не "
      "по таймауту на каждый байт)", r1 is None and r2 is None and d1 < 2.2 and d2 < 2.2)
check("C2 без бюджета — прежняя подпись и поведение (cert_check(addr, port, name[, timeout]))",
      netprobe.cert_check("127.0.0.1", 1, "node.test") is None)

calls = []
real_pull, real_cc, real_resolve = netprobe.pull, netprobe.cert_check, netprobe.resolve
netprobe.cert_check = lambda addr, port, name, timeout=6, budget=None: calls.append(budget) or "ok"
netprobe.resolve = lambda host, port=443: ("127.0.0.1", "system")


class TLSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
        self.wfile.write(b"x" * 100)

    def log_message(self, *a):
        pass


if have_cert:
    hs = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TLSHandler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert, key)
    hs.socket = sctx.wrap_socket(hs.socket, server_side=True)
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    hp = hs.server_address[1]
    netprobe.pull = lambda sock, hostname, need=netprobe.NEED, deadline=12: (need, "ok")
    r = netprobe.direct_probe("node.test", hp, verify=True)
    check("C3 direct_probe с verify: сверка получает бюджет не больше CERT_BUDGET (4 с)",
          r["cert"] == "ok" and calls and 1 <= calls[-1] <= netprobe.CERT_BUDGET == 4)

    shift = [0.0]
    real_time_mod = netprobe.time

    class Clock:
        sleep = staticmethod(time.sleep)

        @staticmethod
        def time():
            return time.time() + shift[0]

    def slow_pull(sock, hostname, need=netprobe.NEED, deadline=12):
        shift[0] += 5 + 6 + deadline - 0.5  # медленный путь: соединение, TLS и замер съели почти весь худший случай
        return 1000, "deadline"

    netprobe.pull, netprobe.time = slow_pull, Clock
    calls.clear()
    r = netprobe.direct_probe("node.test", hp, verify=True)
    netprobe.time = real_time_mod
    check("C4 от худшего случая пробы без сверки (5 + 6 + deadline) осталось меньше секунды — сверку пропускаем "
          "(cert None, «не судим»): с verify /probe точки не дольше, чем без него, и укладывается в 25 с blockwatch",
          r.get("cert") is None and calls == [] and "cert" in r)
    hs.shutdown()
else:
    skipped.append("C3–C4 (нет openssl)")
netprobe.pull, netprobe.cert_check, netprobe.resolve = real_pull, real_cc, real_resolve


def body_then_silence(first, total):
    """Сервер: ответ с Content-Length total, сразу first байт тела, дальше молчит."""
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(total))
            self.end_headers()
            self.wfile.write(b"y" * first)
            self.wfile.flush()
            time.sleep(6)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


old_stall = netprobe.STALL
netprobe.STALL = 2  # ожидание у срока урезается до остатка: при сроке 1,5 с каждый ожидаемый кусок — до 1,5 с
srv = body_then_silence(3000, 100000)
sock = socket.create_connection(srv.server_address, timeout=5)
got, end = netprobe.pull(sock, "x", need=64 * 1024, deadline=1.5)
sock.close()
srv.shutdown()
check("C5 pull: данные встали, срок вышел, последний кусок давно (дольше STALL·DEADLINE_IDLE_PART) — «timeout», "
      "probe_class — «stall» (раньше «deadline» = «ok»)",
      end == "timeout" and got < 64 * 1024 and netprobe.probe_class(
          {"tcp": "open", "tls": True, "end": end, "bytes": got, "need": 64 * 1024}) == "stall")
netprobe.STALL = old_stall


class Drip(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "100000")
        self.end_headers()
        try:
            for _ in range(40):
                self.wfile.write(b"z")
                self.wfile.flush()
                time.sleep(0.2)
        except OSError:
            pass

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
sock = socket.create_connection(srv.server_address, timeout=5)
got, end = netprobe.pull(sock, "x", need=64 * 1024, deadline=1.5)
sock.close()
srv.shutdown()
check("C6 данные идут, но медленно (кусок раз в 0,2 с) — по-прежнему «deadline», это не «встало»",
      end == "deadline" and 0 < got < 64 * 1024)


# ---------- 5 (тест — в test_probe.py: TG10а) ----------

# ---------- 10. метки имён у агента ----------
suf = ["example.net"]
bad_names = ["-.example.net", "xn--.example.net", "a-.example.net", "-a.example.net", "xn---.example.net",
             "a_b.example.net", "a" * 64 + ".example.net"]
good_names = ["xn--p1ai.example.net", "a--b.example.net", "a.example.net", "9.example.net",
              "a" * 63 + ".example.net", "example.net"]
check("N1 allowed_name: метка по [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?, у xn-- после префикса не пусто",
      all(va.allowed_name(n, suf) is None for n in bad_names) and all(va.allowed_name(n, suf) for n in good_names))


# ---------- 7–9. установщики ----------
wi = src_of("witness_install.sh")
check("W1 witness_install.sh: вместо sleep 4 — ожидание свежего файла до 15 с, при неудаче systemctl status и journalctl",
      "sleep 4" not in wi and "for _ in $(seq 30); do fresh && break; sleep 0.5; done" in wi
      and "systemctl status node-witness.service" in wi and "journalctl -u node-witness.service" in wi)
vsrc = src_of("vantage_install.sh")
check("V1 vantage_install.sh: состояние ufw — LC_ALL=C ufw status (локализованный вывод не ломает правило)",
      "LC_ALL=C ufw status" in vsrc and "\"$(ufw status" not in vsrc)
gsrc = src_of("guard_install.sh")
a = gsrc.index('if [ "$uninstall" -eq 1 ]; then')
unin = gsrc[a:gsrc.index("\nfi\n", a) + 4]
check("G1 guard_install.sh --uninstall: systemctl reset-failed службы и таймера",
      "systemctl reset-failed channel-watch-guard.service channel-watch-guard.timer" in unin)

if BASH:
    # 7: ожидание файла — фрагмент установщика с подставными systemctl/journalctl
    a = wi.index('t0="$(date +%s)"')
    block = wi[a:wi.index("\nfi\n", a) + 4]
    stub = ('systemctl() { echo "systemctl $*"; }\njournalctl() { echo "journalctl $*"; }\n'
            'stat() { command stat "$@"; }\n')
    out_f = T + "/fw-x.json"
    rc, out, err = sh(stub + 'out="%s"\n( sleep 1.2; echo "{}" > "$out" ) &\n' % out_f + block + "\necho DONE")
    check("W2 файл появился через 1,2 с — установщик идёт дальше сразу, без прежнего sleep 4",
          rc == 0 and "DONE" in out)
    os.utime(out_f, (time.time() - 3600, time.time() - 3600))  # прежний файл от прошлой установки
    fast = block.replace("seq 30", "seq 3")
    t0 = time.monotonic()
    rc, out, err = sh(stub + 'out="%s"\n' % out_f + fast + "\necho DONE")
    check("W3 свежего файла нет (старый от прошлой установки не в счёт) — отказ, печатаются status и journalctl",
          rc == 1 and "DONE" not in out and "systemctl status node-witness.service" in out
          and "journalctl -u node-witness.service" in out and "за 15 с" in out)

    # 8: --public IPv6 — отказ и в режиме установки
    a = vsrc.index("valid_addr() {")
    funcs = vsrc[a:vsrc.index("\n}\n", vsrc.index("check_public() {")) + 3]
    rc6, out6, err6 = sh(funcs + 'check_public 2001:db8::5; echo PASSED')
    rc4, out4, _ = sh(funcs + 'check_public 1.2.3.4; check_public home.example.ru; echo PASSED')
    check("V2 check_public: IPv6 — отказ с объяснением (агент слушает IPv4), IPv4 и имя — проходят",
          rc6 != 0 and "PASSED" not in out6 and "IPv4" in err6 and rc4 == 0 and "PASSED" in out4)
    check("V3 --public проверяется через check_public везде: --entry, установка и вопрос мастера",
          vsrc.count("check_public \"$public\"") == 2 and 'check_public "$x"' in vsrc)

    # 9: подсказка SELF
    a = gsrc.index('rc=0; out="$(python3')
    selfc = gsrc[a:gsrc.index("\nfi\n", a) + 4]
    stub = 'systemctl() { :; }\nDIR=/x; ETC=/etc/channel-watch-guard\n'

    def guard_says(line, code):
        g = 'python3() { echo "%s"; return %d; }\n' % (line, code)
        return sh(stub + g + selfc)

    rc, out, _ = guard_says("SELF: пульс не читается, но недоступен и контрольный узел", 1)
    check("G2 самопроверка при SELF: своя подсказка (сеть guard или GUARD_CONTROL), без обещания тревоги",
          rc == 0 and "SELF:" in out and "GUARD_CONTROL" in out and "тревога придёт" not in out)
    rc, out, _ = guard_says("UNREACH: порт открыт, сайт не отвечает", 1)
    check("G3 rf1 и правда недоступен — прежнее предупреждение о тревоге после второй проверки",
          "тревога придёт после второй проверки" in out and "GUARD_CONTROL" not in out)
    rc, out, _ = guard_says("OK: пульс свежий", 0)
    check("G4 всё в порядке — без предупреждений", "внимание" not in out and "OK: пульс свежий" in out)
    rc, out, _ = sh('systemctl() { echo "systemctl $*"; }\nuninstall=1; DIR=%s/g; ETC=%s/ge\n' % (T, T)
                    + unin.replace("rm -rf", "echo rm -rf").replace("exit 0", "true"))
    check("G5 --uninstall выполняет reset-failed после daemon-reload",
          "systemctl reset-failed channel-watch-guard.service channel-watch-guard.timer" in out
          and out.index("daemon-reload") < out.index("reset-failed"))
    names = " ".join('"%s/%s"' % (HERE.replace("\\", "/"), n) for n in
                     ("install.sh", "witness_install.sh", "vantage_install.sh", "vantage_update.sh", "guard_install.sh"))
    check("S1 bash -n пяти изменённых установщиков", sh("for f in %s; do bash -n \"$f\" || exit 1; done" % names)[0] == 0)
else:
    skipped.append("W2–W3, V2–V3, G2–G5, S1 (нет bash)")

for name in ("probe.py", "blockwatch.py", "netprobe.py", "vantage_agent.py", "install.sh", "witness_install.sh",
             "vantage_install.sh", "vantage_update.sh", "guard_install.sh", "test_probe.py"):
    raw = open(os.path.join(HERE, name), "rb").read()
    if b"\r" in raw:
        check("E1 LF без CR: " + name, False)
    raw.decode("utf-8")
check("E1 изменённые файлы — UTF-8, LF", True)

shutil.rmtree(tmp, ignore_errors=True)
print("\nпройдено: %d" % ok + ("; пропущено: " + ", ".join(skipped) if skipped else ""))
