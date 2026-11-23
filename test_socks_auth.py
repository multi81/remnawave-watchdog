"""Тесты: пароль на локальных SOCKS-портах сторожа (build_channels.py, netprobe, probe,
blockwatch), вырезание вложенного dialerProxy из подписки, настраиваемый диапазон меток MSS (сторож, агент точки,
свидетель на ноде), запасной DNS только защищённый. Без внешней сети (только 127.0.0.1), нужен curl.
Запуск: PYTHONIOENCODING=utf-8 python test_socks_auth.py"""
import http.server
import importlib.util
import io
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import build_channels  # noqa: E402
import netprobe  # noqa: E402
import node_witness as nw  # noqa: E402
import probe  # noqa: E402
import vantage_agent  # noqa: E402

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


TMP = tempfile.mkdtemp(prefix="cw-left-")
AUTH = ("cwtest01ab", "Pw-0123456789abcdefXYZ")


def write_auth(path, auth=AUTH):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"user": auth[0], "pass": auth[1]}, f)


# ---------- 1. build_channels: пароль на SOCKS, dialerProxy ----------

ETC = os.path.join(TMP, "etc")
os.makedirs(ETC)
build_channels.ETC = ETC


def tile(name, host, extra_stream=None, **top):
    ss = {"network": "xhttp", "security": "reality",
          "realitySettings": {"serverName": host, "publicKey": "k"},
          "sockopt": {"dialerProxy": "evil", "tcpFastOpen": True}}
    ss.update(extra_stream or {})
    ob = {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": host, "port": 443}]},
          "streamSettings": ss, "mux": {"enabled": True}}
    ob.update(top)
    return {"remarks": name, "outbounds": [ob]}


SUB = [tile("A", "a.example", {"xhttpSettings": {"extra": {"downloadSettings": {
    "address": "d.example", "sockopt": {"dialerProxy": "out-0", "mark": 7},
    "list": [{"sockopt": {"dialerProxy": "x"}}]}}}}, proxySettings={"tag": "out-0"}),
       tile("B", "b.example")]


def build(args=()):
    build_channels.load_sub = lambda: json.loads(json.dumps(SUB))
    old_argv = sys.argv
    sys.argv = ["build_channels.py", *args]
    try:
        build_channels.main()
    except SystemExit as e:
        return e.code
    finally:
        sys.argv = old_argv


def xray():
    return json.load(open(os.path.join(ETC, "xray.json"), encoding="utf-8"))


def socks_in(cfg):
    return [i for i in cfg["inbounds"] if i["protocol"] == "socks"]


check("S1 первая сборка без socks.auth — порты без пароля, как раньше (и in-0 тоже)",
      build() == 10 and len(socks_in(xray())) == 3
      and all(i["settings"] == {"udp": False, "auth": "noauth"} for i in socks_in(xray()))
      and not os.path.exists(os.path.join(ETC, "socks.auth")))
text = json.dumps(xray())
check("S2 dialerProxy вырезан на любой глубине (xhttp downloadSettings, списки), proxySettings и mux тоже",
      "dialerProxy" not in text and "proxySettings" not in text and '"mux"' not in text)
ob1 = next(o for o in xray()["outbounds"] if o["tag"] == "out-1")
check("S3 остальное в outbound не тронуто (sockopt.mark, tcpFastOpen, address загрузки)",
      ob1["streamSettings"]["sockopt"] == {"tcpFastOpen": True}
      and ob1["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["address"] == "d.example"
      and ob1["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"] == {"mark": 7})
check("S4 та же подписка — без изменений (код 0)", build() == 0)

# включение: модули рядом не готовы — отказ, файла нет
SIB = os.path.join(TMP, "sib")
os.makedirs(SIB)
shutil.copy(os.path.join(HERE, "build_channels.py"), SIB)
with open(os.path.join(SIB, "nodewatch.py"), "w", encoding="utf-8") as f:
    f.write('s = socket.create_connection(("127.0.0.1", socks_port), timeout=1)\n')
with open(os.path.join(SIB, "old.py"), "w", encoding="utf-8") as f:
    f.write('cmd = ["curl", "-x", f"socks5h://127.0.0.1:{port}"]\n')
with open(os.path.join(SIB, "plain.py"), "w", encoding="utf-8") as f:
    f.write('print("нет SOCKS")\n')
with open(os.path.join(SIB, "test_x.py"), "w", encoding="utf-8") as f:
    f.write('x = "socks5h://127.0.0.1:1"\n')
nr = build_channels.socks_not_ready(SIB, dropin=os.path.join(TMP, "нет.conf"))
check("S5 кто не умеет пароль: модули без метки SOCKS_AUTH_READY (тесты и модули без SOCKS не в счёт)",
      nr == ["nodewatch.py", "old.py"])
res = build_channels.make_socks_auth(SIB, dropin=os.path.join(TMP, "нет.conf"))
check("S6 включение при неготовых модулях — отказ с перечнем, socks.auth не создан",
      isinstance(res, str) and "nodewatch.py" in res and not os.path.exists(os.path.join(ETC, "socks.auth")))
for name in ("nodewatch.py", "old.py"):
    with open(os.path.join(SIB, name), "a", encoding="utf-8") as f:
        f.write("SOCKS_AUTH_READY = True\n")
dropin = os.path.join(TMP, "vpn.conf")
with open(dropin, "w", encoding="utf-8") as f:
    f.write("[Service]\nLoadCredential=vpn-channels.json:/etc/channel-watch/channels.json\n")
res = build_channels.make_socks_auth(SIB, dropin=dropin)
check("S7 VPN-точка: агенту не передан socks.auth (LoadCredential) — отказ",
      isinstance(res, str) and "LoadCredential=socks.auth" in res and not os.path.exists(os.path.join(ETC, "socks.auth")))
with open(dropin, "a", encoding="utf-8") as f:
    f.write("LoadCredential=socks.auth:/etc/channel-watch/socks.auth\n")
check("S8 все готовы — включать можно", build_channels.socks_not_ready(SIB, dropin=dropin) == [])
real_nr = build_channels.socks_not_ready(HERE, dropin=os.path.join(TMP, "нет.conf"))
check("S9 в папке сторожа probe, blockwatch и netprobe помечены как умеющие пароль",
      not {"probe.py", "blockwatch.py", "netprobe.py", "build_channels.py", "vantage_agent.py"} & set(real_nr))
print("     (ещё без пароля в папке сторожа:", ", ".join(real_nr) or "никого", ")")

keep_nr = build_channels.socks_not_ready
build_channels.socks_not_ready = lambda *a, **k: []
rc = build(["--socks-auth"])
auth_path = os.path.join(ETC, "socks.auth")
saved = json.load(open(auth_path, encoding="utf-8"))
ins = socks_in(xray())
check("S10 --socks-auth: файл создан, логин и пароль случайные, все порты (и прямой выход in-0) под паролем, код 10",
      rc == 10 and len(saved["user"]) >= 8 and len(saved["pass"]) >= 24
      and all(i["settings"] == {"udp": False, "auth": "password",
                                "accounts": [{"user": saved["user"], "pass": saved["pass"]}]} for i in ins)
      and any(i["tag"] == "in-0" for i in ins))
if os.name == "posix":
    check("S11 socks.auth — права 600", oct(os.stat(auth_path).st_mode & 0o777) == "0o600")
check("S12 повторный запуск (и с --socks-auth) — файл тот же, конфиг тот же (код 0)",
      build(["--socks-auth"]) == 0 and build() == 0 and json.load(open(auth_path, encoding="utf-8")) == saved)
with open(auth_path, "w", encoding="utf-8") as f:
    f.write("{битый")
check("S13 битый socks.auth — порты без пароля (сторож не ломается), код 10",
      build() == 10 and all(i["settings"]["auth"] == "noauth" for i in socks_in(xray())))
os.remove(auth_path)
build_channels.socks_not_ready = keep_nr

# ---------- 2. netprobe: где взять пароль ----------

netprobe.SOCKS_AUTH_FILE = os.path.join(TMP, "socks.auth")
check("N1 файла нет — без пароля", netprobe.socks_auth() is None)
write_auth(netprobe.SOCKS_AUTH_FILE)
check("N2 файл есть — логин и пароль", netprobe.socks_auth() == AUTH)
cred = os.path.join(TMP, "cred")
os.makedirs(cred)
write_auth(os.path.join(cred, "socks.auth"), ("creduser01", "credpass0123456789ab"))
os.environ["CREDENTIALS_DIRECTORY"] = cred
check("N3 из LoadCredential — раньше /etc (агент VPN-точки не root)", netprobe.socks_auth() == ("creduser01", "credpass0123456789ab"))
os.environ.pop("CREDENTIALS_DIRECTORY")
args, cfg = netprobe.curl_socks(21003)
check("N4 curl: пароль не в argv, а в конфиге на stdin (-K -)",
      args == ["-x", "socks5h://127.0.0.1:21003", "-K", "-"] and AUTH[1] not in " ".join(args)
      and cfg == f'proxy-user = "{AUTH[0]}:{AUTH[1]}"\n')
check("N5 порт не канала сторожа (мост 10809) — логин и пароль туда не уходят",
      netprobe.curl_socks(10809) == (["-x", "socks5h://127.0.0.1:10809"], "")
      and netprobe.curl_proxy_cfg(probe.TG_FALLBACK_PROXY) == ""
      and netprobe.curl_proxy_cfg("socks5h://127.0.0.1:21004") == cfg.replace("21003", "21004")
      and netprobe.curl_proxy_cfg(None) == "")
os.remove(netprobe.SOCKS_AUTH_FILE)
check("N6 файла нет — curl как раньше, без -K", netprobe.curl_socks(21003) == (["-x", "socks5h://127.0.0.1:21003"], ""))


# ---------- 3. настоящий curl и сокеты через SOCKS5 с паролем и без ----------

class FakeSocks:
    """SOCKS5 как у Xray: auth=None — «без пароля», иначе только логин/пароль."""

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
                pl = self.rx(c, 1)[0]
                pw = self.rx(c, pl).decode()
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
            _, cmd, _, atyp = self.rx(c, 4)
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


BODY = b"x" * 4096
WIT = json.dumps({"ts": 1000.0, "flows": []}).encode()


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = WIT if self.path.startswith("/flows") else BODY
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=web.serve_forever, daemon=True).start()
WEB = f"http://127.0.0.1:{web.server_address[1]}/"
WEB_VIA = f"http://cw-web.test:{web.server_address[1]}/"  # имя знает только подставной прокси (как выход ноды)

pw_srv, open_srv = FakeSocks(AUTH), FakeSocks(None)
netprobe.SOCKS_PORTS = (pw_srv.port, open_srv.port)  # в тестах «порты каналов» — порты подставных прокси

if shutil.which("curl"):
    r = netprobe.socks_load(pw_srv.port, url=WEB_VIA, need=len(BODY), timeout=8)
    check("C1 Xray с паролем, а socks.auth не прочитан — загрузка не проходит (порт закрыт посторонним)",
          not r["ok"] and any(x[0] == "no-method" and 2 not in x[1] for x in pw_srv.seen))
    write_auth(netprobe.SOCKS_AUTH_FILE)
    r = netprobe.socks_load(pw_srv.port, url=WEB_VIA, need=len(BODY), timeout=8)
    check("C2 с паролем из socks.auth — загрузка через настоящий curl проходит", r["ok"] and ("auth", True) in pw_srv.seen)
    r = netprobe.socks_load(open_srv.port, url=WEB_VIA, need=len(BODY), timeout=8)
    check("C3 socks.auth уже есть, а Xray ещё со старым конфигом (без пароля) — работает как раньше",
          r["ok"] and open_srv.seen and open_srv.seen[-1][0] == "noauth")
    out, code = probe.curl(pw_srv.port, WEB_VIA, 8, "%{http_code}")
    check("C4 probe.curl через канал под паролем — 200", out == "200")  # код 23 на Windows: нет /dev/null
    n_auth = sum(1 for x in pw_srv.seen if x == ("auth", True))
    wit = blockwatch.fetch_witness(WEB_VIA + "flows.json", pw_srv.port)
    check("C5 blockwatch.fetch_witness: напрямую имя не находится, через канал под паролем — счётчики получены",
          wit == {"ts": 1000.0, "flows": []} and sum(1 for x in pw_srv.seen if x == ("auth", True)) > n_auth)
    dest = os.path.join(TMP, "list.txt")
    check("C6 blockwatch.fetch (списки): напрямую нет, через канал под паролем — файл на месте",
          blockwatch.fetch(WEB_VIA + "list", dest, None) is False
          and blockwatch.fetch(WEB_VIA + "list", dest, pw_srv.port) is True and os.path.getsize(dest) == len(BODY))
else:
    print("SKIP C1–C7: нет curl")
    write_auth(netprobe.SOCKS_AUTH_FILE)


def via_socket(port, auth=None):
    s = netprobe.socks_connect(port, "127.0.0.1", web.server_address[1], 5, auth=auth)
    if not s:
        return None
    s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    data = b""
    while True:
        x = s.recv(65536)
        if not x:
            break
        data += x
    s.close()
    return data


check("K1 сокет через SOCKS с паролем (netprobe.socks_connect) — ответ пришёл", (via_socket(pw_srv.port) or b"").endswith(BODY))
check("K2 сокет к старому Xray без пароля, хотя пароль есть, — тоже работает", (via_socket(open_srv.port) or b"").endswith(BODY))
check("K3 неверный пароль — None, а не исключение", via_socket(pw_srv.port, ("cwtest01ab", "wrong-password-000000")) is None)
os.remove(netprobe.SOCKS_AUTH_FILE)
check("K4 файла нет — сокет к Xray с паролем не открывается, к старому — как раньше",
      via_socket(pw_srv.port) is None and (via_socket(open_srv.port) or b"").endswith(BODY))

# argv и stdin: пароль только на stdin
write_auth(netprobe.SOCKS_AUTH_FILE)
calls = []


class R:
    stdout, returncode = '{"Status": 0, "Answer": []}', 0


def fake_run(cmd, **kw):
    calls.append((cmd, kw))
    return R()


real_run = probe.subprocess.run
probe.subprocess.run = netprobe.subprocess.run = blockwatch.subprocess.run = fake_run
try:
    netprobe.SOCKS_PORTS = range(21000, 21100)
    probe.curl(21002, "https://x.test/", 5, "%{http_code}")
    netprobe.socks_load(21002)
    blockwatch.doh("a.example", 21002)
    blockwatch.fetch_witness("https://w.test/flows.json", 21002)
    probe.tg_post("123:tok", "42", "текст", proxy="socks5h://127.0.0.1:21004")
    probe.tg_post("123:tok", "42", "текст", proxy=probe.TG_FALLBACK_PROXY)
    probe.curl(None, "https://x.test/", 5, "%{http_code}")
finally:
    probe.subprocess.run = real_run
argv_all = " ".join(" ".join(map(str, c)) for c, _ in calls)
via_ch = [c for c in calls if any("127.0.0.1:2100" in str(a) for a in c[0])]
check("A1 пароль SOCKS ни в одном argv curl", AUTH[1] not in argv_all and AUTH[0] not in argv_all)
check("A2 все вызовы через каналы передают логин и пароль на stdin", len(via_ch) >= 4 and all(
    AUTH[1] in (kw.get("input") or "") for c, kw in via_ch if "-x" in c))
tg = [kw.get("input") or "" for c, kw in calls if "sendMessage" in (kw.get("input") or "")]
check("A3 Telegram через свой канал — proxy-user в том же конфиге; через мост 10809 — нет",
      len(tg) == 2 and f'proxy-user = "{AUTH[0]}:{AUTH[1]}"' in tg[0] and "proxy-user" not in tg[1])
check("A4 запрос без канала — без stdin и без -K, как раньше", "input" not in calls[-1][1] and "-K" not in calls[-1][0])
os.remove(netprobe.SOCKS_AUTH_FILE)
calls.clear()
probe.subprocess.run = fake_run
try:
    probe.curl(21002, "https://x.test/", 5, "%{http_code}")
finally:
    probe.subprocess.run = real_run
check("A5 нет socks.auth — вызов curl как раньше (без -K, без stdin)",
      "input" not in calls[0][1] and "-K" not in calls[0][0] and "socks5h://127.0.0.1:21002" in calls[0][0])

# ---------- 4. метки MSS из настроек ----------

check("M1 по умолчанию — прежний диапазон 1201–1260", netprobe.MSS_DEFAULT == (1201, 1260) and nw.MARK_DEFAULT == (1201, 1260))
check("M2 диапазон проверяется: узкий, за пределами, не числа — прежний",
      netprobe.mss_range([1300, 1380]) == (1300, 1380) and netprobe.mss_range([1300, 1320]) == (1201, 1260)
      and netprobe.mss_range([400, 480]) == (1201, 1260) and netprobe.mss_range(["1300", "1380"]) == (1201, 1260)
      and netprobe.mss_range([True, 1380]) == (1201, 1260) and netprobe.mss_range(None) == (1201, 1260)
      and netprobe.mss_range([1300, 1600]) == (1201, 1260))
site = os.path.join(TMP, "site.json")
with open(site, "w", encoding="utf-8") as f:
    json.dump({"mss_mark": [1301, 1360], "other": 1}, f)
check("M3 сторож: диапазон из /etc/channel-watch/site.json; файла нет или битый — прежний",
      netprobe.load_mss_mark(site) == (1301, 1360) and netprobe.load_mss_mark(site + ".нет") == (1201, 1260))
keep_mark = netprobe.MSS_MARK
netprobe.MSS_MARK = netprobe.load_mss_mark(site)
check("M4 метки точек сторожа идут от начала диапазона (серия и приветствие TLS)",
      blockwatch.point_mss(0) == 1301 and blockwatch.point_mss(3) == 1307 and blockwatch.tls_mss(2) == 1335
      and netprobe.series("127.0.0.1", 1, 0, mss=1250)["mss"] is None)
netprobe.MSS_MARK = keep_mark


class FakeAgent:
    def __init__(self, addr, cfg, tls):
        self.cfg = cfg

    def serve_forever(self):
        return None


keep_agent = vantage_agent.Agent
vantage_agent.Agent = FakeAgent
conf = os.path.join(TMP, "agent.json")
base_cfg = {"token": "t" * 40, "allow": ["10.0.0.1"], "suffixes": ["example.ru"],
            "tls_cert": os.path.join(TMP, "нет.pem"), "tls_key": os.path.join(TMP, "нет.key")}
try:
    with open(conf, "w", encoding="utf-8") as f:
        json.dump(dict(base_cfg, mss_mark=[1401, 1460]), f)
    vantage_agent.main(conf)
    agent_mark = netprobe.MSS_MARK
    with open(conf, "w", encoding="utf-8") as f:
        json.dump(base_cfg, f)
    netprobe.MSS_MARK = keep_mark
    vantage_agent.main(conf)
finally:
    vantage_agent.Agent = keep_agent
check("M5 агент точки берёт диапазон из agent.json (\"mss_mark\"); без ключа — как был",
      agent_mark == (1401, 1460) and netprobe.MSS_MARK == keep_mark)

check("M6 свидетель: один диапазон или несколько (на время смены), неверное — прежний",
      nw.mark_ranges([1301, 1360]) == [(1301, 1360)]
      and nw.mark_ranges([[1201, 1260], [1301, 1360]]) == [(1201, 1260), (1301, 1360)]
      and nw.mark_ranges([[1201, 1260], [1301, 1900]]) == [(1201, 1260)]
      and nw.mark_ranges("1201-1260") == [(1201, 1260)] and nw.mark_ranges([]) == [(1201, 1260)])
wsite = os.path.join(TMP, "witness-site.json")
with open(wsite, "w", encoding="utf-8") as f:
    json.dump({"mss_mark": [[1201, 1260], [1301, 1360]]}, f)
check("M7 свидетель: диапазоны из /etc/node-witness/site.json; файла нет — прежний",
      nw.load_marks(wsite) == [(1201, 1260), (1301, 1360)] and nw.load_marks(wsite + ".нет") == [(1201, 1260)])
OLD_DIR = os.environ.get("OLD_CODE_DIR", "")   # папка с прежней версией модулей — для сравнения (необязательно)
before = os.path.join(OLD_DIR, "node_witness.py") if OLD_DIR else ""
if os.path.exists(before):
    spec = importlib.util.spec_from_file_location("nw_before_left", before)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    check("M8 без настроек фильтр BPF слово в слово прежний (выкладка по одной ноде безопасна)",
          nw.FILTER == old.FILTER and nw.build_filter({"203.0.113.80"}) == old.build_filter({"203.0.113.80"}))
keep_marks = nw.MARKS
nw.MARKS = [(1201, 1260), (1301, 1360)]
f2 = nw.build_filter()
fl = nw.Flows()


def syn(ts, sport, mss):
    return f"{ts:.6f} IP 1.2.3.4.{sport} > 203.0.113.80.443: Flags [S], seq 1, win 64240, options [mss {mss},sackOK], length 0"


for i, m in enumerate((1210, 1330, 1290, 1460)):
    fl.feed(syn(100.0 + i, 40000 + i, m))
nw.MARKS = keep_marks
check("M9 два диапазона: каждый в своих скобках в фильтре BPF (and и or там равны по старшинству)",
      "((tcp[22:2] >= 1201 and tcp[22:2] <= 1260) or (tcp[22:2] >= 1301 and tcp[22:2] <= 1360))" in f2)
check("M10 два диапазона: считаются метки из обоих, чужие MSS — нет",
      sorted(v[1] for v in fl.live.values()) == [1210, 1330])

# ---------- 5. запасной DNS — только защищённый ----------

check("D1 по умолчанию запасной DNS — только DoH по адресам IP, ни одного сервера по UDP",
      netprobe.FALLBACK_DNS and all(s.startswith("https://") for s in netprobe.FALLBACK_DNS)
      and all(s.split("/")[2].replace(".", "").isdigit() for s in netprobe.FALLBACK_DNS))
udp_calls, doh_calls = [], []
real_gai, real_udp, real_doh = netprobe.socket.getaddrinfo, netprobe.dns_udp, netprobe.doh_query
netprobe.socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("SERVFAIL"))
netprobe.dns_udp = lambda name, server, port=53, timeout=3: udp_calls.append((name, server)) or ("ok", ["198.51.100.1"])
try:
    netprobe.doh_query = lambda name, url, timeout=4: doh_calls.append((name, url)) or ("ok", ["203.0.113.9"])
    r1 = netprobe.resolve("de1.example.com")
    netprobe.doh_query = lambda name, url, timeout=4: doh_calls.append((name, url)) or ("nx", [])
    n0 = len(doh_calls)
    r2 = netprobe.resolve("нет.example.com")
    n_nx = len(doh_calls) - n0
    netprobe.doh_query = lambda name, url, timeout=4: ("err", [])
    r3 = netprobe.resolve("de1.example.com")
finally:
    netprobe.socket.getaddrinfo, netprobe.dns_udp, netprobe.doh_query = real_gai, real_udp, real_doh
check("D2 свой DNS не нашёл — адрес по DoH, помечено «doh»; по UDP никуда не спрашивали",
      r1 == ("203.0.113.9", "doh") and not udp_calls)
check("D3 DoH сказал «имени нет» — второй сервер не спрашиваем; никто не ответил — «fail», и опять без UDP",
      r2 == (None, "fail") and n_nx == 1 and r3 == (None, "fail") and not udp_calls)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


seen_req = []


def fake_urlopen(answer):
    def f(req, timeout=None):
        seen_req.append((req.full_url, req.get_header("Accept"), timeout))
        if isinstance(answer, Exception):
            raise answer
        return FakeResp(json.dumps(answer).encode())
    return f


real_uo = netprobe.urllib.request.urlopen
try:
    netprobe.urllib.request.urlopen = fake_urlopen({"Status": 0, "Answer": [
        {"type": 5, "data": "x.example."}, {"type": 1, "data": "203.0.113.5"}, {"type": 1, "data": "мусор"},
        {"type": 1, "data": "203.0.113.4"}]})
    q1 = netprobe.doh_query("de1.example.com.", netprobe.FALLBACK_DNS[0])
    netprobe.urllib.request.urlopen = fake_urlopen({"Status": 3})
    q2 = netprobe.doh_query("x.test", netprobe.FALLBACK_DNS[0])
    netprobe.urllib.request.urlopen = fake_urlopen({"Status": 2})
    q3 = netprobe.doh_query("x.test", netprobe.FALLBACK_DNS[0])
    netprobe.urllib.request.urlopen = fake_urlopen(OSError("нет сети"))
    q4 = netprobe.doh_query("x.test", netprobe.FALLBACK_DNS[0])
    netprobe.urllib.request.urlopen = fake_urlopen(["не словарь"])
    q5 = netprobe.doh_query("x.test", netprobe.FALLBACK_DNS[0])
finally:
    netprobe.urllib.request.urlopen = real_uo
check("D4 разбор ответа DoH: только записи A с настоящими адресами; «нет имени», отказ, нет сети, мусор",
      q1 == ("ok", ["203.0.113.4", "203.0.113.5"]) and q2 == ("nx", []) and q3 == ("err", [])
      and q4 == ("err", []) and q5 == ("err", []))
check("D5 запрос DoH: имя в адресе запроса (внутри TLS), ответ JSON, с пределом времени",
      seen_req[0][0] == "https://1.1.1.1/dns-query?name=de1.example.com&type=A"
      and seen_req[0][1] == "application/dns-json" and seen_req[0][2] == netprobe.DOH_TIMEOUT)

shutil.rmtree(TMP, ignore_errors=True)
print(f"все {ok} проверок прошли")
