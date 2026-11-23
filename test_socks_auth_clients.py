"""Тесты: пароль SOCKS у всех модулей, свидетель по TLS, роль watch_ro, удаление DDoS-служб.
1. Пароль SOCKS во всех модулях сторожа: nodewatch (socks_connect, site_title, site_face, big_speed), scanlists.fetch
   и shieldbot.tg_call (маршруты probe.tg_routes); метка SOCKS_AUTH_READY; поиск build_channels.socks_not_ready находит
   все модули, которые сами ходят на 127.0.0.1:2100x (и прежние scanlists/shieldbot, которые раньше пропускал);
   --socks-auth в папке сторожа проходит проверку готовности; vpn_point_install.sh передаёт агенту socks.auth.
2. blockwatch.fetch_witness — у ноды с "sha256" в nodes.json flows.json только по TLS с этим отпечатком
   (напрямую и через канал), без отката на HTTP.
3. panel_user_info.sh: готовность роли watch_ro — запросом к тем же пяти таблицам, иначе postgres.
4. install.sh --uninstall: DDoS-службы по одной — убираются те, что есть.
Без внешней сети (только 127.0.0.1). Нужны curl, bash и openssl (без них часть проверок пропускается).
Запуск: PYTHONIOENCODING=utf-8 python test_socks_auth_clients.py"""
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
BEFORE = os.environ.get("OLD_CODE_DIR", "")   # папка с прежней версией модулей — для сравнения (необязательно)
sys.path.insert(0, HERE)
import beacon_serve as bs  # noqa: E402
import blockwatch  # noqa: E402
import build_channels  # noqa: E402
import netprobe  # noqa: E402
import nodewatch  # noqa: E402
import scanlists  # noqa: E402
import shieldbot  # noqa: E402

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
os.environ.pop("CREDENTIALS_DIRECTORY", None)

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def src(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


TMP = tempfile.mkdtemp(prefix="cw-left2-")
AUTH = ("cwtest02cd", "Pw-abcdef0123456789QRS")
netprobe.SOCKS_AUTH_FILE = os.path.join(TMP, "socks.auth")


def auth_on():
    with open(netprobe.SOCKS_AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump({"user": AUTH[0], "pass": AUTH[1]}, f)


def auth_off():
    if os.path.exists(netprobe.SOCKS_AUTH_FILE):
        os.remove(netprobe.SOCKS_AUTH_FILE)


BASH = shutil.which("bash")
if BASH and "system32" in BASH.lower():   # bash из WSL — не тот
    BASH = None
CURL = shutil.which("curl")


class FakeSocks:
    """SOCKS5 как у Xray: auth=None — «без пароля», иначе только логин/пароль. Имена *.test — на 127.0.0.1."""

    def __init__(self, auth=None):
        self.auth, self.seen = auth, []
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(20)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    @staticmethod
    def rx(c, n):
        buf = b""
        while len(buf) < n:
            x = c.recv(n - len(buf))
            if not x:
                raise OSError("закрыто")
            buf += x
        return buf

    def handle(self, c):
        try:
            c.settimeout(10)
            _, n = self.rx(c, 2)
            methods = self.rx(c, n)
            if self.auth:
                if 2 not in methods:
                    c.sendall(b"\x05\xff")
                    self.seen.append(("no-method", bytes(methods)))
                    return
                c.sendall(b"\x05\x02")
                _, ul = self.rx(c, 2)
                user = self.rx(c, ul).decode()
                pw = self.rx(c, self.rx(c, 1)[0]).decode()
                good = (user, pw) == self.auth
                self.seen.append(("auth", good))
                c.sendall(b"\x01\x00" if good else b"\x01\x01")
                if not good:
                    return
            else:
                if 0 not in methods:
                    c.sendall(b"\x05\xff")
                    return
                c.sendall(b"\x05\x00")
                self.seen.append(("noauth", bytes(methods)))
            _, _, _, atyp = self.rx(c, 4)
            if atyp == 1:
                host = socket.inet_ntoa(self.rx(c, 4))
            elif atyp == 3:
                host = self.rx(c, self.rx(c, 1)[0]).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, self.rx(c, 16))
            port = struct.unpack(">H", self.rx(c, 2))[0]
            up = socket.create_connection(("127.0.0.1" if host.endswith(".test") else host, port), timeout=5)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            threading.Thread(target=self.pipe, args=(up, c), daemon=True).start()
            self.pipe(c, up)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    @staticmethod
    def pipe(a, b):
        try:
            while True:
                x = a.recv(65536)
                if not x:
                    break
                b.sendall(x)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


pw_srv, open_srv = FakeSocks(AUTH), FakeSocks(None)
netprobe.SOCKS_PORTS = (pw_srv.port, open_srv.port, 21001)  # в тестах «порты каналов» — порты подставных прокси

# --- маячок ноды (beacon_serve.py) с TLS и HTTP на одном порту: файл свидетеля и простой текст для curl
www = os.path.join(TMP, "www")
os.makedirs(www)
WIT = {"ts": 1763900000, "flows": [[1763900000, 1201, 3, 3, 0, 0]]}
with open(os.path.join(www, "flows.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(WIT, f)
with open(os.path.join(www, "state.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump({"ts": 1763900000}, f)
OPENSSL = shutil.which("openssl")
CERT, KEY, FP = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem"), ""
if OPENSSL:
    r = subprocess.run([OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", KEY, "-out", CERT, "-days", "2", "-subj", "/CN=localhost"],
                       capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV="1"))
    if r.returncode == 0:
        import ssl
        import hashlib
        FP = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(CERT, encoding="ascii").read())).hexdigest()


def serve(tls):
    srv = bs.Server(("127.0.0.1", 0), www, tls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


# ---------- 1. метки и поиск тех, кто ходит через SOCKS сам ----------

for name in ("nodewatch.py", "scanlists.py", "shieldbot.py", "blockwatch.py", "netprobe.py", "probe.py"):
    check("M1 %s: метка SOCKS_AUTH_READY = True на верхнем уровне" % name, build_channels.socks_ready_mark(src(name)))

real_nr = build_channels.socks_not_ready(HERE, dropin=os.path.join(TMP, "нет.conf"))
check("M2 в папке сторожа все модули, что ходят через SOCKS, умеют пароль (список неготовых пуст)", real_nr == [])

ETC = os.path.join(TMP, "etc")
os.makedirs(ETC)
build_channels.ETC = ETC
res = build_channels.make_socks_auth(HERE, dropin=os.path.join(TMP, "нет.conf"))
saved = json.load(open(os.path.join(ETC, "socks.auth"), encoding="utf-8"))
check("M3 --socks-auth в папке сторожа проходит проверку готовности: socks.auth создан",
      res == 0 and build_channels.read_socks_auth() == (saved["user"], saved["pass"]))
os.remove(os.path.join(ETC, "socks.auth"))

# прежние версии модулей (до правки): поиск должен находить их все, в том числе scanlists и shieldbot
if os.path.isdir(BEFORE):
    OLD = os.path.join(TMP, "old")
    os.makedirs(OLD)
    for name in ("nodewatch.py", "scanlists.py", "shieldbot.py", "blockwatch.py", "probe.py", "netprobe.py"):
        if os.path.exists(os.path.join(BEFORE, name)):
            shutil.copy(os.path.join(BEFORE, name), OLD)
    old_nr = build_channels.socks_not_ready(OLD, dropin=os.path.join(TMP, "нет.conf"))
    check("M4 прежние nodewatch, scanlists, shieldbot, blockwatch, probe (без пароля) — все в списке неготовых",
          {"nodewatch.py", "scanlists.py", "shieldbot.py", "blockwatch.py", "probe.py"} <= set(old_nr))
    check("M5 прежние scanlists и shieldbot находятся по вызову tg_routes() и по curl -x",
          "маршруты probe.tg_routes (в них порт канала)" in build_channels.socks_user_signs(
              open(os.path.join(OLD, "scanlists.py"), encoding="utf-8").read())
          and "маршруты probe.tg_routes (в них порт канала)" in build_channels.socks_user_signs(
              open(os.path.join(OLD, "shieldbot.py"), encoding="utf-8").read()))
else:
    print("ПРОПУСК M4-M5: не задана OLD_CODE_DIR (папка с копиями до правки)")

SIB = os.path.join(TMP, "sib")
os.makedirs(SIB)
SAMPLES = {
    "routes.py": "for proxy in probe.tg_routes():\n    pass\n",
    "routes2.py": "rs = [None] + [r for r in probe.tg_routes ( ) if r]\n",
    "listx.py": 'cmd[1:1] = ["-x", proxy]\n',
    "listlong.py": 'cmd += ["--proxy"]\ncmd.append(proxy)\n',
    "iptables.py": 'out = run(["iptables", "-L", "INPUT", "-v", "-n", "-x"])\n',
    "proxyeq.py": 'cmd = ["curl", "--proxy=" + p]\n',
    "socks5h.py": 'url = "socks5h" + "://127.0.0.1:%d" % p\n',
    "hostname.py": 'cmd = ["curl", "--socks5-hostname", addr]\n',
    "env.py": 'os.environ["ALL_PROXY"] = p\n',
    "handler.py": "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': p}))\n",
    "pysocks.py": "import socks\n",
    "port.py": "PORT = 21003\n",
    "base.py": "port = BASE_PORT + i\n",
    "sock.py": 's = socket.create_connection(("127.0.0.1", p))\n',
    "hand.py": 's.sendall(b"\\x05\\x01\\x00")\n',
    "plain.py": 'print("нет SOCKS: curl -s https://example.com")\n',
    "viapb.py": "r = netprobe.socks_load(port)\nproxy, cfg = netprobe.curl_socks(port)\n",
}
for name, text in SAMPLES.items():
    with open(os.path.join(SIB, name), "w", encoding="utf-8") as f:
        f.write(text)
nr = set(build_channels.socks_not_ready(SIB, dropin=os.path.join(TMP, "нет.conf")))
check("M6 найдены все виды «сам ходит через SOCKS» (tg_routes, -x в списке, --proxy=, socks5h строкой, "
      "--socks5-hostname, ALL_PROXY, ProxyHandler, PySocks, порт 2100x, BASE_PORT, сокет и рукопожатие)",
      nr == set(SAMPLES) - {"plain.py", "viapb.py", "iptables.py"})
check("M7 модуль без SOCKS, модуль, что ходит только через netprobe (пароль подставляет он), и iptables -x "
      "в конце списка — не в списке", not {"plain.py", "viapb.py", "iptables.py"} & nr)
with open(os.path.join(SIB, "routes.py"), "a", encoding="utf-8") as f:
    f.write("# SOCKS_AUTH_READY = True\nX = 'SOCKS_AUTH_READY = True'\n")
with open(os.path.join(SIB, "port.py"), "a", encoding="utf-8") as f:
    f.write("def f():\n    SOCKS_AUTH_READY = True\n")
with open(os.path.join(SIB, "base.py"), "a", encoding="utf-8") as f:
    f.write("SOCKS_AUTH_READY = False\n")
with open(os.path.join(SIB, "sock.py"), "a", encoding="utf-8") as f:
    f.write("SOCKS_AUTH_READY = True\n")
nr = set(build_channels.socks_not_ready(SIB, dropin=os.path.join(TMP, "нет.conf")))
check("M8 метка в комментарии, в строке, внутри функции или False — не считается; настоящая — считается",
      {"routes.py", "port.py", "base.py"} <= nr and "sock.py" not in nr)

# vpn_point_install.sh: агенту VPN-точки передаётся socks.auth (LoadCredential) — с запасным «{}»
vpi = src("vpn_point_install.sh") if os.path.exists(os.path.join(HERE, "vpn_point_install.sh")) else None
m = None
if vpi is None:
    print("ПРОПУСК V1-V3: рядом нет vpn_point_install.sh (в открытую версию установщик VPN-точки не входит)")
else:
    m = re.search(r"printf '%s\\n' '\[Service\]'.*?> /etc/systemd/system/vantage-agent\.service\.d/vpn\.conf", vpi, re.S)
    check("V1 vpn_point_install.sh: в drop-in vpn.conf — LoadCredential=socks.auth:/etc/channel-watch/socks.auth",
          m is not None and "'LoadCredential=socks.auth:/etc/channel-watch/socks.auth'" in m.group(0))
if BASH and m:
    dropin = os.path.join(TMP, "vpn.conf")
    cmd = m.group(0).replace("/etc/systemd/system/vantage-agent.service.d/vpn.conf", dropin.replace("\\", "/"))
    r = subprocess.run([BASH, "-c", cmd], capture_output=True, text=True, env=dict(os.environ, MSYS_NO_PATHCONV="1"))
    conf = open(dropin, encoding="utf-8").read()
    check("V2 drop-in, который пишет установщик, проходит проверку готовности --socks-auth на VPN-точке",
          r.returncode == 0 and conf.startswith("[Service]\n")
          and not [x for x in build_channels.socks_not_ready(SIB + "-нет", dropin=dropin, agent_dir=None)
                   if "LoadCredential" in x])
    check("V3 прежняя строка vpn-channels.json на месте, запасное значение socks.auth — «{}»",
          "LoadCredential=vpn-channels.json:/etc/channel-watch/channels.json\n" in conf
          and "SetCredential=socks.auth:{}\n" in conf)
elif vpi is not None:
    print("ПРОПУСК V2-V3: нет bash")
cred = os.path.join(TMP, "cred")
os.makedirs(cred)
with open(os.path.join(cred, "socks.auth"), "w", encoding="utf-8") as f:
    f.write("{}")
os.environ["CREDENTIALS_DIRECTORY"] = cred
auth_off()
check("V4 запасное «{}» (пароль ещё не включён) — netprobe считает «пароля нет», curl как раньше",
      netprobe.socks_auth() is None and netprobe.curl_socks(pw_srv.port)[1] == "")
del os.environ["CREDENTIALS_DIRECTORY"]

# ---------- 2. nodewatch: сокет и три curl ----------

auth_off()
s = nodewatch.socks_connect(open_srv.port, "cw-a.test", pw_srv.port, 5)
check("N1 socks_connect без socks.auth, Xray без пароля — как раньше, соединение есть", s is not None)
s and s.close()
check("N2 socks_connect без socks.auth к Xray с паролем — None (без исключения)",
      nodewatch.socks_connect(pw_srv.port, "cw-a.test", open_srv.port, 5) is None)
auth_on()
n0 = pw_srv.seen.count(("auth", True))
s = nodewatch.socks_connect(pw_srv.port, "cw-a.test", open_srv.port, 5)
check("N3 socks_connect с socks.auth к Xray с паролем — вход по паролю, соединение есть",
      s is not None and pw_srv.seen.count(("auth", True)) == n0 + 1)
s and s.close()
s = nodewatch.socks_connect(open_srv.port, "cw-a.test", pw_srv.port, 5)
check("N4 socks.auth уже есть, Xray ещё без пароля — соединение есть (поэтапная выкладка)", s is not None)
s and s.close()


class R:
    def __init__(self, out="", rc=0):
        self.stdout, self.returncode, self.stderr = out, rc, ""


calls = []


def fake_run(cmd, **kw):
    calls.append((list(cmd), kw))
    if any("size_download" in str(c) for c in cmd):
        return R("%d 2500000" % nodewatch.BIG_BYTES)
    if "-I" in cmd:
        return R("HTTP/1.1 200 OK\r\nstrict-transport-security: max-age=1\r\n")
    if any("redirect_url" in str(c) for c in cmd):
        return R("301 https://site.example/")
    return R("<html><title>Привет</title></html>\n200")


keep_run, keep_tls = nodewatch.subprocess.run, nodewatch.tls_face
nodewatch.subprocess.run = fake_run
nodewatch.tls_face = lambda *a, **k: (None, None)
try:
    for with_auth in (True, False):
        (auth_on if with_auth else auth_off)()
        calls.clear()
        t = nodewatch.site_title(pw_srv.port, "site.example")
        face = nodewatch.site_face(pw_srv.port, "site.example")
        sp = nodewatch.big_speed(pw_srv.port)
        argv = " ".join(" ".join(c) for c, _ in calls)
        proxied = all("-x" in c and c[c.index("-x") + 1] == "socks5h://127.0.0.1:%d" % pw_srv.port for c, _ in calls)
        if with_auth:
            check("N5 site_title, site_face, big_speed с socks.auth: «-K -», логин и пароль на stdin, в argv их нет",
                  len(calls) == 4 and proxied and AUTH[1] not in argv and AUTH[0] not in argv
                  and all(c[c.index("-K") + 1] == "-" and 'proxy-user = "%s:%s"' % AUTH in kw.get("input", "")
                          for c, kw in calls))
            check("N6 ответы разбираются как раньше (заголовок, заглушка, скорость)",
                  t == ("200", "Привет") and face and face["r301"] and face["hsts"] and sp == 20.0)
        else:
            check("N7 без socks.auth — вызов curl прежний: без -K и без stdin",
                  len(calls) == 4 and proxied and all("-K" not in c and "input" not in kw for c, kw in calls)
                  and t == ("200", "Привет") and sp == 20.0)
finally:
    nodewatch.subprocess.run, nodewatch.tls_face = keep_run, keep_tls

# ---------- 3. scanlists.fetch и shieldbot.tg_call: маршруты tg_routes ----------

if CURL:
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"1.2.3.0/24\n5.6.7.8\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    keep_url = scanlists.list_url
    scanlists.list_url = lambda name: "http://cw-list.test:%d/%s.list" % (web.server_address[1], name)
    seen_cmds = []
    real_run = subprocess.run

    def spy(cmd, **kw):
        seen_cmds.append(list(cmd))
        return real_run(cmd, **kw)

    scanlists.subprocess.run = spy
    try:
        auth_on()
        n0 = pw_srv.seen.count(("auth", True))
        text = scanlists.fetch("scanner", (None, "socks5h://127.0.0.1:%d" % pw_srv.port))
        check("S1 scanlists.fetch: напрямую имя не находится, через канал под паролем (настоящий curl) — список получен",
              text == "1.2.3.0/24\n5.6.7.8\n" and pw_srv.seen.count(("auth", True)) == n0 + 1)
        check("S2 пароль SOCKS не в argv curl", all(AUTH[1] not in " ".join(c) for c in seen_cmds)
              and ["-K", "-"] == seen_cmds[-1][3:5])
        text = scanlists.fetch("scanner", (None, "socks5h://127.0.0.1:%d" % open_srv.port))
        check("S3 socks.auth есть, Xray ещё без пароля — список получен", text == "1.2.3.0/24\n5.6.7.8\n")
        auth_off()
        seen_cmds.clear()
        text = scanlists.fetch("scanner", (None, "socks5h://127.0.0.1:%d" % pw_srv.port))
        check("S4 без socks.auth к Xray с паролем — не скачалось (отказ, без исключения), curl без -K",
              text is None and all("-K" not in c for c in seen_cmds))
    finally:
        scanlists.subprocess.run = real_run
        scanlists.list_url = keep_url
else:
    print("ПРОПУСК S1-S4: нет curl")

auth_on()
check("S5 scanlists.proxy_cfg: пароль только для портов каналов, не для моста и не напрямую",
      scanlists.proxy_cfg("socks5h://127.0.0.1:21001") == 'proxy-user = "%s:%s"\n' % AUTH
      and scanlists.proxy_cfg("socks5h://127.0.0.1:10809") == "" and scanlists.proxy_cfg(None) == ""
      and scanlists.proxy_cfg("http://127.0.0.1:21001") == "")


class FakeProbe:
    @staticmethod
    def tg_env():
        return "123:SECRET", "42"

    @staticmethod
    def tg_routes():
        return [None, "socks5h://127.0.0.1:21001", "socks5h://127.0.0.1:10809"]


tg_calls = []


def tg_run(cmd, **kw):
    tg_calls.append((list(cmd), kw))
    return R("")   # пусто — следующий маршрут


keep_probe, keep_srun = shieldbot._probe, shieldbot.subprocess.run
shieldbot._probe = lambda: FakeProbe
shieldbot.subprocess.run = tg_run
try:
    shieldbot.tg_call("sendMessage", {"chat_id": 42, "text": "x"})
    by = {(c[c.index("-x") + 1] if "-x" in c else None): (c, kw) for c, kw in tg_calls}
    pu = 'proxy-user = "%s:%s"' % AUTH
    check("T1 shieldbot: через порт канала — логин и пароль в конфиге на stdin, напрямую и через мост — нет",
          len(tg_calls) == 3 and pu in by["socks5h://127.0.0.1:21001"][1]["input"]
          and pu not in by[None][1]["input"] and pu not in by["socks5h://127.0.0.1:10809"][1]["input"])
    check("T2 shieldbot: ни пароля SOCKS, ни токена в argv; конфиг — через «-K -»",
          all(AUTH[1] not in " ".join(c) and "SECRET" not in " ".join(c) and c[c.index("-K") + 1] == "-"
              for c, _ in tg_calls)
          and all("url = " in kw["input"] for _, kw in tg_calls))
    auth_off()
    tg_calls.clear()
    shieldbot.tg_call("sendMessage", {"chat_id": 42, "text": "x"})
    check("T3 shieldbot без socks.auth — конфиг как раньше (без proxy-user)",
          len(tg_calls) == 3 and all("proxy-user" not in kw["input"] for _, kw in tg_calls))
finally:
    shieldbot._probe, shieldbot.subprocess.run = keep_probe, keep_srun

# ---------- 4. blockwatch.fetch_witness по TLS с отпечатком ----------

NODES = os.path.join(TMP, "nodes.json")
nodewatch.NODES_FILE = NODES


def nodes(*items):
    with open(NODES, "w", encoding="utf-8") as f:
        json.dump(list(items), f)


bw_calls = []
keep_bw_run = blockwatch.subprocess.run


def bw_spy(cmd, **kw):
    bw_calls.append(list(cmd))
    return keep_bw_run(cmd, **kw)


blockwatch.subprocess.run = bw_spy
auth_off()
try:
    if FP:
        tport = serve(bs.tls_context(CERT, KEY))
        beacon = "http://127.0.0.1:%d/state.json" % tport
        wurl = blockwatch.witness_url(beacon)
        nodes({"name": "n0", "host": "198.51.100.1", "beacon": "http://198.51.100.1:9/state.json", "sha256": "x"},
              {"name": "n1", "host": "127.0.0.1", "beacon": beacon, "sha256": FP.upper()})
        check("W1 отпечаток для flows.json берётся у ноды, чей маячок рядом (поле sha256 из nodes.json)",
              blockwatch.witness_pin(wurl) == FP.upper() and blockwatch.witness_pin(beacon) is None)
        bw_calls.clear()
        check("W2 sha256 есть — счётчики по TLS с этим сертификатом, curl по HTTP не вызывается",
              blockwatch.fetch_witness(wurl) == WIT and bw_calls == [])
        nodes({"name": "n1", "host": "127.0.0.1", "beacon": beacon, "sha256": "ab" * 32})
        check("W3 чужой отпечаток — None, на HTTP не откатываемся (маячок отдал бы по HTTP)",
              blockwatch.fetch_witness(wurl) is None and bw_calls == [])
        nodes({"name": "n1", "host": "127.0.0.1", "beacon": beacon, "sha256": "не отпечаток"})
        check("W4 испорченный sha256 — None, без HTTP", blockwatch.fetch_witness(wurl) is None and bw_calls == [])
        check("W5 sha256 передан явно — он и действует", blockwatch.fetch_witness(wurl, sha256=FP) == WIT
              and bw_calls == [])
        hport = serve(None)
        hbeacon = "http://127.0.0.1:%d/state.json" % hport
        nodes({"name": "n1", "host": "127.0.0.1", "beacon": hbeacon, "sha256": FP})
        check("W6 у ноды sha256, а маячок отдаёт только HTTP (старая установка) — None, отката на HTTP нет",
              blockwatch.fetch_witness(blockwatch.witness_url(hbeacon)) is None and bw_calls == [])
        if CURL:
            nodes({"name": "n1", "host": "127.0.0.1", "beacon": beacon})
            check("W7 у ноды нет sha256 — по-старому, curl по HTTP (тот же порт маячка отвечает и HTTP)",
                  blockwatch.fetch_witness(wurl) == WIT and len(bw_calls) == 1 and bw_calls[0][-1] == wurl)
        # через канал: напрямую имя не находится (нода закрыта из России), через SOCKS с паролем — TLS со сверкой
        auth_on()
        vbeacon = "http://cw-node.test:%d/state.json" % tport
        nodes({"name": "n1", "host": "cw-node.test", "beacon": vbeacon, "sha256": FP})
        bw_calls.clear()
        n0 = pw_srv.seen.count(("auth", True))
        check("W8 через канал под паролем — TLS с тем же отпечатком, счётчики получены, без curl",
              blockwatch.fetch_witness(blockwatch.witness_url(vbeacon), pw_srv.port) == WIT and bw_calls == []
              and pw_srv.seen.count(("auth", True)) > n0)
        nodes({"name": "n1", "host": "cw-node.test", "beacon": vbeacon, "sha256": "cd" * 32})
        check("W9 через канал с чужим отпечатком — None, без HTTP",
              blockwatch.fetch_witness(blockwatch.witness_url(vbeacon), pw_srv.port) is None and bw_calls == [])
        big = os.path.join(www, "flows.json")
        keep_big = open(big, encoding="utf-8").read()
        with open(big, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"ts": 1, "flows": [[1, 1201, 0, 0, 0, 0]] * 30000}, f)
        nodes({"name": "n1", "host": "127.0.0.1", "beacon": beacon, "sha256": FP})
        check("W10 файл свидетеля больше предела (%d) — не берём и по TLS" % blockwatch.WITNESS_MAX,
              os.path.getsize(big) > blockwatch.WITNESS_MAX and blockwatch.fetch_witness(wurl) is None)
        with open(big, "w", encoding="utf-8", newline="\n") as f:
            f.write(keep_big)
        s = nodewatch.fetch_beacon(beacon)
        check("W11 маячок state.json той же ноды — тем же кодом по TLS (nodewatch.pinned_get)",
              isinstance(s, dict) and s.get("ts") == 1763900000)
    else:
        print("ПРОПУСК W1-W11: нет openssl")
finally:
    blockwatch.subprocess.run = keep_bw_run
auth_off()

# ---------- 5. panel_user_info.sh: готовность роли — запросом к тем же таблицам ----------

sh = src("panel_user_info.sh")
query = sh.split("<<'SQL'", 1)[1].split("\nSQL", 1)[0]
TABLES = set(re.findall(r"\b(?:from|join)\s+([a-z_]+)\b", query)) - {"lateral"}
mm = re.search(r"^ro_check='([^']*)'", sh, re.M)
check("P1 проверка роли — select 1 из тех же пяти таблиц, что читает запрос, с limit 0 (строк не читает)",
      mm is not None and len(TABLES) == 5 and set(re.findall(r"[a-z_]+", mm.group(1).split(" from ", 1)[1]))
      == TABLES | {"limit"} and mm.group(1).rstrip().endswith("limit 0"))
if BASH:
    work = os.path.join(TMP, "panel")
    fake = os.path.join(work, "bin")
    os.makedirs(fake)
    with open(os.path.join(fake, "docker"), "w", encoding="utf-8", newline="\n") as f:
        f.write('#!/bin/bash\n'
                'printf "%s\\n" "$*" >> "$LOG"\n'
                'case " $* " in\n'
                '  *" -U watch_ro "*" -c "*)\n'
                '    [ "${ROLE:-0}" = 1 ] || { echo "psql: FATAL: role \\"watch_ro\\" does not exist" >&2; exit 2; }\n'
                '    q="${@: -1}"\n'
                '    for t in $TABLES_ALL; do\n'
                '      case " $GRANTED " in *" $t "*) ;; *) case "$q" in *"$t"*)\n'
                '        echo "ERROR: permission denied for table $t" >&2; exit 1;; esac;; esac\n'
                '    done\n'
                '    exit 0;;\n'
                'esac\n'
                'cat > /dev/null\n'
                'echo \'{"users": []}\'\n')

    def prun(role, granted):
        log = os.path.join(work, "log")
        if os.path.exists(log):
            os.remove(log)
        e = dict(os.environ, LOG=log.replace("\\", "/"), ROLE=str(role), SSH_ORIGINAL_COMMAND="user_1",
                 GRANTED=" ".join(granted), TABLES_ALL=" ".join(sorted(TABLES)), FAKE=fake.replace("\\", "/"),
                 SCRIPT=os.path.join(HERE, "panel_user_info.sh").replace("\\", "/"), MSYS_NO_PATHCONV="1")
        r = subprocess.run([BASH, "-c", 'PATH="$(cd "$FAKE" && pwd):$PATH" bash "$SCRIPT"'], capture_output=True,
                           text=True, encoding="utf-8", env=e, timeout=60)
        return r, (open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else [])

    r, c = prun(1, TABLES)
    check("P2 роль с правами на все пять таблиц — запрос под watch_ro",
          r.returncode == 0 and r.stdout == '{"users": []}\n' and len(c) == 2 and "-U watch_ro" in c[1])
    r, c = prun(1, TABLES - {"hwid_user_devices"})
    check("P3 роль есть, но прав на одну таблицу нет (миграция пересоздала таблицу) — запрос под postgres",
          r.returncode == 0 and r.stdout == '{"users": []}\n' and len(c) == 2 and "-U postgres" in c[1])
    r, c = prun(0, TABLES)
    check("P4 роли нет — под postgres, как раньше", r.returncode == 0 and len(c) == 2 and "-U postgres" in c[1])
else:
    print("ПРОПУСК P2-P4: нет bash")

# ---------- 6. install.sh --uninstall: DDoS-службы по одной ----------

ins = src("install.sh")
blk = ins.split("  # 1) DDoS-часть первой", 1)[1].split("\n", 1)[1].split("\n  # 2) щитам на серверах", 1)[0]
check("U1 install.sh: прежней проверки одним ls по общему шаблону больше нет",
      "channel-watch-{ddos,shieldbot,scanlists,behavscan}.*" not in blk and "ddos_units" in blk)
if BASH:
    root = os.path.join(TMP, "sys")

    def urun(present, ddos_sh=False):
        unit_dir = os.path.join(root, "units")
        srcd = os.path.join(root, "src")
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(unit_dir)
        os.makedirs(srcd)
        for u in present:
            open(os.path.join(unit_dir, u), "w").close()
        open(os.path.join(unit_dir, "channel-watch-xray.service"), "w").close()
        open(os.path.join(unit_dir, "other.service"), "w").close()
        if ddos_sh:
            with open(os.path.join(srcd, "install_ddos.sh"), "w", encoding="utf-8", newline="\n") as f:
                f.write('echo "ddos-uninstall $*" >> "$LOG"\n')
        body = blk.replace("/etc/systemd/system", unit_dir.replace("\\", "/"))
        script = ('set -euo pipefail\nSRC="%s"\nexport LOG="%s"\nsystemctl() { echo "systemctl $*" >> "$LOG"; }\n'
                  % (srcd.replace("\\", "/"), os.path.join(root, "log").replace("\\", "/")) + body + "\necho END\n")
        r = subprocess.run([BASH, "-c", script], capture_output=True, text=True, encoding="utf-8",
                           env=dict(os.environ, MSYS_NO_PATHCONV="1"))
        log = os.path.join(root, "log")
        return r, sorted(os.listdir(unit_dir)), (open(log, encoding="utf-8").read().splitlines()
                                                  if os.path.exists(log) else [])

    part = ["channel-watch-ddos.service", "channel-watch-ddos.timer", "channel-watch-shieldbot.service"]
    r, left, log = urun(part)
    check("U2 стоит только часть DDoS (ddos и shieldbot, без scanlists и behavscan) — она убрана целиком",
          r.returncode == 0 and r.stdout.rstrip().endswith("END")
          and left == ["channel-watch-xray.service", "other.service"]
          and {"systemctl disable --now " + u for u in part} <= set(log) and log[-1] == "systemctl daemon-reload")
    check("U3 сначала таймер, потом службы", log.index("systemctl disable --now channel-watch-ddos.timer")
          < log.index("systemctl disable --now channel-watch-ddos.service"))
    full = ["channel-watch-%s" % u for u in ("ddos.service", "ddos.timer", "shieldbot.service", "scanlists.service",
                                             "scanlists.timer", "behavscan.service", "behavscan.timer")]
    r, left, log = urun(full)
    check("U4 стоит вся DDoS-часть — убрана вся, чужие юниты и Xray сторожа на месте (их убирает следующий шаг)",
          r.returncode == 0 and left == ["channel-watch-xray.service", "other.service"]
          and sum(1 for x in log if x.startswith("systemctl disable")) == len(full))
    r, left, log = urun([])
    check("U5 DDoS-части нет — ничего не делается, systemctl не зовётся",
          r.returncode == 0 and log == [] and left == ["channel-watch-xray.service", "other.service"])
    r, left, log = urun(["channel-watch-shieldbot.service"], ddos_sh=True)
    check("U6 есть install_ddos.sh — уборка через него, как раньше (и при одной службе)",
          r.returncode == 0 and log == ["ddos-uninstall --uninstall"])
else:
    print("ПРОПУСК U2-U6: нет bash")

# ---------- 7. файлы: UTF-8, LF ----------

for name in ("nodewatch.py", "scanlists.py", "shieldbot.py", "blockwatch.py", "build_channels.py",
             "vpn_point_install.sh", "panel_user_info.sh", "install.sh", "test_socks_auth_clients.py"):
    if not os.path.exists(os.path.join(HERE, name)):
        continue
    raw = open(os.path.join(HERE, name), "rb").read()
    raw.decode("utf-8")
    check("F %s: UTF-8, без CR, в конце перевод строки" % name, b"\r" not in raw and raw.endswith(b"\n"))

shutil.rmtree(TMP, ignore_errors=True)
print("пароль SOCKS у всех модулей, свидетель по TLS: тестов пройдено %d" % ok)
