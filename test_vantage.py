"""Тесты точки проверки: чужие адреса отсекаются до разбора запроса, пределы на запрос и соединения, TLS на том же
порту с закреплённым отпечатком (vantage_client.py) при живом HTTP для старого сторожа, /dns без трассировок,
нейтральные ответы; установщик: --public и частный адрес, правило ufw при смене адреса/порта, read -ra, запрет «%».
Только 127.0.0.1 (и свой адрес в локальной сети, если есть): PYTHONIOENCODING=utf-8 python test_vantage.py"""
import http.client
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
import netprobe  # noqa: E402
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


TOKEN = "t" * 40
tmp = tempfile.mkdtemp()


def lan_ip():
    """Свой адрес не 127.x (для проверки «чужого» адреса без внешней сети); None — нет."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # UDP connect пакетов не шлёт
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None
    finally:
        s.close()


LAN = lan_ip()


def start(cfg_extra=None, tls=None, bind="127.0.0.1"):
    cfg = {"token": TOKEN, "allow": ["127.0.0.1"], "suffixes": ["example.net"], "ports": [443]}
    cfg.update(cfg_extra or {})
    srv = va.Agent((bind, 0), cfg, tls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def raw_get(port, path, headers=None, host="127.0.0.1", method="GET", body=None):
    c = http.client.HTTPConnection(host, port, timeout=10)
    c.request(method, path, body=body, headers=dict({"X-Token": TOKEN}, **(headers or {})))
    r = c.getresponse()
    out = r.status, dict(r.getheaders()), r.read()
    c.close()
    return out


def closed_quickly(sock, limit):
    """Сервер закрыл соединение (b'' или сброс) не позже чем через limit секунд."""
    sock.settimeout(limit)
    t = time.monotonic()
    try:
        while True:
            d = sock.recv(4096)
            if not d:
                return time.monotonic() - t <= limit
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


# --- имена: только ASCII, метки 1–63 ---
suf = ["example.net"]
check("N1 обычное имя проходит", va.allowed_name("PL1.example.net.", suf) == "pl1.example.net")
check("N2 кириллица и полноширинные буквы — нет", va.allowed_name("тест.example.net", suf) is None
      and va.allowed_name("\uff41.example.net", suf) is None and va.allowed_name("x\u00b2.example.net", suf) is None)
check("N3 пустая метка «a..» и метка длиннее 63 — нет", va.allowed_name("a..example.net", suf) is None
      and va.allowed_name("a" * 64 + ".example.net", suf) is None and va.allowed_name("a" * 63 + ".example.net", suf))
check("N4 чужой домен — нет", va.allowed_name("example.net.evil.ru", suf) is None)

# --- чужой адрес отсекается до потока и разбора ---
srv, port = start()
check("A1 verify_request: чужой адрес — нет, свой и 127.0.0.1 — да",
      not srv.verify_request(None, ("203.0.113.5", 1)) and srv.verify_request(None, ("127.0.0.1", 1)))
srv.cfg["allow"] = ["198.51.100.9"]
check("A2 127.0.0.1 не в allow всё равно получает 403 (самопроверка установщиков)", raw_get(port, "/health")[0] == 403)
srv.cfg["allow"] = ["127.0.0.1"]
if LAN:
    srv2, port2 = start(bind="0.0.0.0")
    threads0 = threading.active_count()
    socks = []
    for _ in range(20):
        s = socket.create_connection((LAN, port2), timeout=5)
        try:
            s.sendall(b"GET /health HTTP/1.0\r\n" + b"X-A: " + b"a" * 60000 + b"\r\n")
        except OSError:
            pass
        socks.append(s)
    closed = all(closed_quickly(s, 3) for s in socks)
    check("A3 20 соединений с чужого адреса: закрыты сразу, потоков не прибавилось",
          closed and threading.active_count() <= threads0 + 1)
    for s in socks:
        s.close()
    srv2.shutdown()
    srv2.server_close()
else:
    skipped.append("A3 (нет адреса в локальной сети)")

# предел соединений разом
va.MAX_CONN, keep_max = 3, va.MAX_CONN
srv3, port3 = start()
va.MAX_CONN = keep_max
idle = [socket.create_connection(("127.0.0.1", port3), timeout=5) for _ in range(3)]
time.sleep(0.3)
extra = socket.create_connection(("127.0.0.1", port3), timeout=5)
check("A4 сверх предела соединений — закрыто сразу", closed_quickly(extra, 3))
for s in idle:
    s.close()
time.sleep(0.5)
check("A5 места освободились — снова отвечает", raw_get(port3, "/health")[0] == 200)
srv3.shutdown()
srv3.server_close()

# срок на весь запрос: досылка по байту не держит соединение
va.HeadReader.__init__.__defaults__ = (va.HEAD_MAX, 1.5)
s = socket.create_connection(("127.0.0.1", port), timeout=5)
t0 = time.monotonic()
s.sendall(b"GET /health HTTP/1.0\r\n")
alive = True
try:
    for _ in range(20):
        s.sendall(b"X")
        time.sleep(0.25)
        s.settimeout(0.01)
        try:
            if s.recv(1) == b"":
                alive = False
                break
        except socket.timeout:
            pass
except OSError:
    alive = False
check("A6 запрос по байту — соединение закрыто по сроку (не позже ~2,5 с)", not alive and time.monotonic() - t0 < 3)
s.close()
va.HeadReader.__init__.__defaults__ = (va.HEAD_MAX, va.HEAD_TIME)

# предел объёма заголовков
s = socket.create_connection(("127.0.0.1", port), timeout=5)
try:
    s.sendall(b"GET /health HTTP/1.0\r\n" + (b"X-A: " + b"a" * 1000 + b"\r\n") * 40)
except OSError:
    pass
check("A7 заголовки больше 16 КБ — соединение закрыто, ответа 200 нет", closed_quickly(s, 3))
s.close()

# тела не принимаются, прочие методы — 405
check("A8 Content-Length > 0 — 413", raw_get(port, "/health", {"Content-Length": "5"}, body=b"12345")[0] == 413)
check("A9 POST — 405, тело не читается", raw_get(port, "/health", method="POST", body=b"x" * 100)[0] == 405)

# --- нейтральные ответы ---
st, hd, body = raw_get(port, "/health", {"X-Token": "wrong"})
check("B1 403 без JSON и без подписи Server", st == 403 and body == b"" and "Server" not in hd)
st, hd, body = raw_get(port, "/health")
h = json.loads(body)
check("B2 /health: v 7, caps dns_udp0/verify/tls, tls выключен без сертификата, без Server",
      st == 200 and h["v"] == 7 and {"dns_udp0", "verify", "tls"} <= set(h["caps"]) and h["tls"] is False
      and "Server" not in hd)
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"BREW /x HTTP/1.0\r\n\r\n")
resp = s.recv(4096)
s.close()
check("B3 ошибка разбора — без Server и без страницы с подписью Python",
      b"Server:" not in resp and b"Python" not in resp and b"BaseHTTP" not in resp)

# --- /dns: UnicodeError → 400, udp=0 ---
calls = []
real_rs, real_du, real_dp = netprobe.resolve_system, netprobe.dns_udp, netprobe.direct_probe
netprobe.resolve_system = lambda name: ("ok", ["10.0.0.1"])
netprobe.dns_udp = lambda name, ip: calls.append(ip) or ("ok", ["10.0.0.1"])
check("D1 /dns на «a..» и длинной метке — 400, не обрыв",
      raw_get(port, "/dns?name=a..example.net")[0] == 400
      and raw_get(port, "/dns?name=" + "a" * 70 + ".example.net")[0] == 400)


def boom(name):
    raise UnicodeError("label too long")


netprobe.resolve_system = boom
check("D2 кодек имён упал внутри проверки — 400, служба отвечает дальше",
      raw_get(port, "/dns?name=x.example.net")[0] == 400 and raw_get(port, "/health")[0] == 200)
netprobe.resolve_system = lambda name: ("ok", ["10.0.0.1"])
st, _, body = raw_get(port, "/dns?name=x.example.net&udp=0")
check("D3 /dns?udp=0 — только системный DNS, к публичным не ходили", st == 200 and json.loads(body)["udp"] == {}
      and calls == [])
st, _, body = raw_get(port, "/dns?name=x.example.net")
check("D4 /dns без udp=0 — как раньше, публичные тоже", st == 200 and len(json.loads(body)["udp"]) == 3 and len(calls) == 3)

seen = []


def dp_new(host, port=443, sni=None, need=netprobe.NEED, tls=True, deadline=12, verify=False):
    seen.append(verify)
    return {"addr": "10.0.0.1", "tcp": True}


def dp_old(host, port=443, sni=None, need=netprobe.NEED, tls=True, deadline=12):
    seen.append("old")
    return {"addr": "10.0.0.1", "tcp": True}


netprobe.direct_probe = dp_new
raw_get(port, "/probe?host=x.example.net&port=443&verify=1")
raw_get(port, "/probe?host=x.example.net&port=443")
check("D5 /probe?verify=1 — со сверкой, без него — без", seen == [True, False])
netprobe.direct_probe = dp_old
st, _, _ = raw_get(port, "/probe?host=x.example.net&port=443&verify=1")
check("D6 netprobe без verify — проверка без сверки, не ошибка", st == 200 and seen[-1] == "old")
netprobe.resolve_system, netprobe.dns_udp, netprobe.direct_probe = real_rs, real_du, real_dp
srv.shutdown()
srv.server_close()

# --- настройки из LoadCredential ---
cd = os.path.join(tmp, "creds")
os.makedirs(cd)
os.environ["CREDENTIALS_DIRECTORY"] = cd
open(os.path.join(cd, "vpn-channels.json"), "w").write("{}")
check("C1 в каталоге только плитки VPN (старый юнит + vpn.conf) — настройки из /etc", va.cred_path("agent.json", va.CONF) == va.CONF)
open(os.path.join(cd, "agent.json"), "w").write("{}")
check("C2 agent.json передан через LoadCredential — берётся оттуда",
      va.cred_path("agent.json", va.CONF) == os.path.join(cd, "agent.json"))
del os.environ["CREDENTIALS_DIRECTORY"]
check("C3 без сертификата — без TLS (агент до обновления установщика)",
      va.tls_context({"tls_cert": os.path.join(tmp, "nope.pem"), "tls_key": os.path.join(tmp, "nope.key")}) is None)

# --- TLS на том же порту, отпечаток ---
openssl = shutil.which("openssl")
cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
if openssl and subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                               "-nodes", "-sha256", "-days", "30", "-subj", "/CN=vantage-agent", "-keyout", key,
                               "-out", cert], capture_output=True).returncode == 0:
    fp = vc.fingerprint(ssl.PEM_cert_to_DER_cert(open(cert).read()))
    ctx = va.tls_context({"tls_cert": cert, "tls_key": key})
    hits = []
    srv, port = start(tls=ctx)
    real_rate = srv.rate_ok
    srv.rate_ok = lambda: hits.append(1) or real_rate()
    url = "http://127.0.0.1:%d" % port
    ag = {"name": "Москва", "url": url, "token": TOKEN, "sha256": fp}
    got = vc.agent_get(ag, "/health", 8)
    check("T1 TLS с верным отпечатком — /health отвечает, tls включён", got and got["ok"] and got["tls"] is True)
    check("T2 отпечаток с двоеточиями и заглавными — тот же", vc.agent_get(
        dict(ag, sha256=":".join(fp[i:i + 2] for i in range(0, 64, 2)).upper()), "/health", 8) is not None)
    n = len(hits)
    check("T3 чужой отпечаток — None, запрос с токеном не отправлен", vc.agent_get(dict(ag, sha256="0" * 64), "/health", 8)
          is None and len(hits) == n)
    req = urllib.request.Request(url + "/health", headers={"X-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=8) as r:
        old = json.loads(r.read())
    check("T4 старый сторож (urllib, http://) на том же порту — отвечает как раньше", old["ok"] is True)
    plain = []
    get = vc.wrap(lambda a, p, t=20: plain.append(p) or {"plain": True})
    check("T5 wrap: без sha256 — прежняя функция (HTTP), с sha256 — TLS",
          get({"url": url, "token": TOKEN}, "/health") == {"plain": True} and get(ag, "/health", 8)["tls"] is True
          and plain == ["/health"])
    check("T6 sha256 испорчен — None, на HTTP не откатываемся", get(dict(ag, sha256="xyz"), "/health", 8) is None
          and plain == ["/health"])
    check("T7 /dns по TLS с 400 — None (как прежний agent_get)", vc.agent_get(ag, "/dns?name=a..example.net", 8) is None)
    srv.cfg["tls_only"] = True
    check("T8 tls_only: с 127.0.0.1 HTTP отвечает (самопроверка), TLS работает",
          raw_get(port, "/health")[0] == 200 and vc.agent_get(ag, "/health", 8)["tls_only"] is True)
    srv.shutdown()
    srv.server_close()
    if LAN:
        srv, port = start({"allow": ["127.0.0.1", LAN], "tls_only": True}, tls=ctx, bind="0.0.0.0")
        s = socket.create_connection((LAN, port), timeout=5)
        s.sendall(b"GET /health HTTP/1.0\r\nX-Token: " + TOKEN.encode() + b"\r\n\r\n")
        check("T9 tls_only: обычный HTTP с адреса сторожа — закрыто без ответа", closed_quickly(s, 3))
        s.close()
        check("T10 tls_only: TLS с адреса сторожа — отвечает",
              vc.agent_get(dict(ag, url="http://%s:%d" % (LAN, port)), "/health", 8) is not None)
        srv.shutdown()
        srv.server_close()
    else:
        skipped.append("T9–T10 (нет адреса в локальной сети)")
    s_ = socket.create_connection(("127.0.0.1", start(tls=ctx)[1]), timeout=5)
    s_.sendall(b"\x16\x03\x01\x00\x05hello")
    check("T11 мусор вместо рукопожатия — соединение закрыто", closed_quickly(s_, 12))
    s_.close()
else:
    skipped.append("T1–T11 (нет openssl)")

check("K1 check_entry: верный отпечаток и запись без него проходят", vc.check_entry({"sha256": "a" * 64})
      and vc.check_entry({"name": "x"}) == {"name": "x"})
try:
    vc.check_entry({"sha256": "abc"})
    bad = False
except ValueError:
    bad = True
check("K2 check_entry: испорченный sha256 — ValueError", bad)

# --- установщик (копия строк под Git Bash, с подставными ufw и python3) ---


def git_bash():
    for p in (r"C:\Program Files\Git\bin\bash.exe", shutil.which("bash")):
        if p and os.path.exists(p) and "system32" not in p.lower():
            return p
    return None


BASH = git_bash() if os.name == "nt" else shutil.which("bash")
SRC = open(os.path.join(HERE, "vantage_install.sh"), encoding="utf-8").read()
check("S0 установщик: LF, без SC2046 (ufw delete $(cat …)), DynamicUser и LoadCredential, без nogroup",
      "\r" not in SRC and "$(cat \"$ETC/ufw-rule\")\n" not in SRC and "ufw delete $(" not in SRC
      and "DynamicUser=yes" in SRC and "LoadCredential=agent.json:" in SRC and "nogroup" not in SRC)


def func(name):
    a = SRC.index(name + "() {")
    return SRC[a:SRC.index("\n}\n", a) + 3]


def sh(script, cwd=None):
    shim = 'python3() { "%s" "$@"; }\nexport -f python3\n' % sys.executable.replace("\\", "/")
    r = subprocess.run([BASH, "-c", shim + script], capture_output=True, text=True, encoding="utf-8", cwd=cwd)
    return r.returncode, r.stdout, r.stderr


if BASH:
    t = tmp.replace("\\", "/")
    va_ = func("valid_addr")
    ng = func("not_global")
    rc = [sh(va_ + 'valid_addr "%s" %s' % (a, k))[0] for a, k in
          (("1.2.3.4", "ip"), ("2a01:4f8::5", "ip"), ("fe80::1%eth0", "ip"), ("fe80::1%x y*", "any"),
           ("home.example.ru", "any"), ("home.example.ru", "ip"), ("a b", "any"), ("1.2.3.4;id", "any"))]
    check("S1 valid_addr: IPv4/IPv6 да; зона «%», пробелы, «;» — нет; имя только там, где можно",
          rc == [0, 0, 1, 1, 0, 1, 1, 1])
    rc = [sh(ng + 'not_global ' + a)[0] for a in ("192.168.1.10", "100.64.3.4", "10.1.1.1", "8.8.8.8")]
    check("S2 not_global: частные и CGNAT — да, внешний — нет", rc == [0, 0, 0, 1])

    # --entry: копия с ETC во временной папке
    etc = t + "/etc"
    os.makedirs(etc, exist_ok=True)
    json.dump({"name": "Дом", "port": 9109, "token": TOKEN, "public": "192.168.1.10"},
              open(etc + "/agent.json", "w", encoding="utf-8"), ensure_ascii=False)
    if os.path.exists(cert):
        shutil.copy(cert, etc + "/cert.pem")
    body = SRC.replace("ETC=/etc/vantage-agent", "ETC=" + etc).replace(
        '[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }', ":")
    open(t + "/vi.sh", "w", encoding="utf-8", newline="\n").write(body)
    rc, out, err = sh('bash "%s/vi.sh" --entry' % t)
    e = json.loads(out)
    check("S3 --entry: url прежний http:// (старый сторож), частный адрес — предупреждение в stderr, не в запись",
          rc == 0 and e["url"] == "http://192.168.1.10:9109" and "частный" in err and "--public" in err)
    if os.path.exists(cert):
        check("S4 --entry: sha256 = отпечаток cert.pem", e.get("sha256") == fp)
    rc, out, err = sh('bash "%s/vi.sh" --entry --public 1.2.3.4 --rucheck' % t)
    e = json.loads(out)
    check("S5 --entry --public: внешний адрес в записи, без предупреждения",
          e["url"] == "http://1.2.3.4:9109" and e.get("rucheck") is True and "частный" not in err)
    rc, out, err = sh('bash "%s/vi.sh" --entry --public "fe80::1%%eth0"' % t)
    check("S6 --public с зоной «%» — отказ", rc != 0 and out == "")
    rc, out, err = sh('bash "%s/vi.sh" --entry --public 2a01:4f8::7' % t)
    # агент слушает только IPv4 (0.0.0.0): запись с адресом IPv6 сторожу бесполезна — понятный отказ, а не url
    check("S7 --public с адресом IPv6 — отказ с объяснением (агент слушает IPv4), запись не печатается",
          rc != 0 and out == "" and "IPv6" in err and "IPv4" in err)

    # ufw: удаление по файлу через read -ra, смена адреса/порта
    fake = ('ufw() { echo "ufw $*" >> "%s/ufw.log"; [ "$1" = status ] && echo "Status: active"; return 0; }\n'
            % t)
    ud = func("ufw_delete_saved")
    open(etc + "/ufw-rule", "w").write("allow from 1.2.3.4 to any port * proto tcp $(touch %s/pwned)\n" % t)
    open(t + "/afile", "w").close()
    rc, out, err = sh(fake + 'ETC="%s"\n' % etc + ud + "ufw_delete_saved", cwd=tmp)
    log = open(t + "/ufw.log", encoding="utf-8").read()
    check("S8 ufw delete из файла: слова как есть, без раскрытия «*» и без выполнения $(…)",
          "port * proto" in log and "afile" not in log and not os.path.exists(t + "/pwned"))
    os.remove(t + "/ufw.log")
    block = SRC[SRC.index('rule="allow from $allow'):SRC.index("\nsleep 2\n")]
    open(etc + "/ufw-rule", "w").write("allow from 1.2.3.4 to any port 9109 proto tcp\n")
    rc, out, err = sh(fake + 'ETC="%s"; allow=5.6.7.8; port=9443\n' % etc + ud + block)
    log = open(t + "/ufw.log", encoding="utf-8").read().splitlines()
    check("S9 переустановка с новым --allow/--port: старое правило удалено, новое добавлено, файл обновлён",
          rc == 0 and "ufw delete allow from 1.2.3.4 to any port 9109 proto tcp" in log
          and any(x.startswith("ufw allow from 5.6.7.8 to any port 9443 proto tcp comment") for x in log)
          and open(etc + "/ufw-rule").read().strip() == "allow from 5.6.7.8 to any port 9443 proto tcp")
    os.remove(t + "/ufw.log")
    rc, out, err = sh(fake + 'ETC="%s"; allow=5.6.7.8; port=9443\n' % etc + ud + block)
    log = open(t + "/ufw.log", encoding="utf-8").read()
    check("S10 повтор с теми же адресом и портом — ничего не удаляется", "delete" not in log)
    os.remove(t + "/ufw.log")

    # guard_install.sh: GUARD_CONTROL проверяется
    gsrc = open(os.path.join(HERE, "guard_install.sh"), encoding="utf-8").read()
    a = gsrc.index('case "$GUARD_CONTROL" in')
    gcase = gsrc[a:gsrc.index("\nesac\n", a) + 6]
    res = [sh('GUARD_CONTROL="%s"\n' % v + gcase + 'echo "[$GUARD_CONTROL]"')[1].strip().splitlines()[-1]
           for v in ("api.telegram.org:443", "1.1.1.1:53", "x;id:1", "host", "host:", ":443", "")]
    check("S11 guard_install: GUARD_CONTROL хост:порт — да, мусор и без порта — пусто",
          res == ["[api.telegram.org:443]", "[1.1.1.1:53]", "[]", "[]", "[]", "[]", "[]"])
    check("S12 bash -n установщиков", sh('bash -n "%s/vantage_install.sh" && bash -n "%s/guard_install.sh"'
                                         % (HERE.replace("\\", "/"), HERE.replace("\\", "/")))[0] == 0)
else:
    skipped.append("S1–S12 (нет bash)")

print("\nпройдено: %d" % ok + ("; пропущено: " + ", ".join(skipped) if skipped else ""))
