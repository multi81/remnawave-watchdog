"""Тесты маячка по TLS с отпечатком: свои и чужие до занятия места, общий срок
соединения, место хватает сторожу, --tls-only. Маячок --serve по TLS. beacon_serve.py — HTTP и TLS на одном порту
(по первому байту), только два имени файла, без ссылок и без заголовка Server; nodewatch.fetch_beacon — по TLS со
сверкой отпечатка, если у ноды в nodes.json есть "sha256" (без отката на HTTP), иначе по-старому; beacon_install.sh —
сертификат создаётся один раз, ключ службе через LoadCredential, строка BEACON-SHA256. Сеть — только 127.0.0.1."""
import hashlib
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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import beacon_serve as bs  # noqa: E402
import nodewatch as nwt  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def src_of(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")
work = tempfile.mkdtemp()
www = os.path.join(work, "www")
os.makedirs(www)
STATE = {"ts": 1763900000, "disk_pct": 41, "host": "n1"}
with open(os.path.join(www, "state.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(STATE, f)
with open(os.path.join(www, "flows.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump({"ts": 1763900000, "flows": []}, f)
with open(os.path.join(www, "other.json"), "w", encoding="utf-8", newline="\n") as f:
    f.write("{}")
with open(os.path.join(work, "secret.txt"), "w", encoding="utf-8", newline="\n") as f:
    f.write("SECRET")


def bash(script, env=None):
    e = dict(os.environ)
    e.update(env or {})
    e["MSYS_NO_PATHCONV"] = "1"
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, encoding="utf-8", env=e)


# --- сертификат: тем же куском установщика, что на ноде ---
bi = src_of("beacon_install.sh")
cert_block = bi.split('  if [ ! -s "$ETC/cert.pem" ] || [ ! -s "$ETC/key.pem" ]; then\n', 1)[1].split("\n  fi\n", 1)[0]
fp_line = [ln.strip() for ln in bi.splitlines() if ln.strip().startswith('fp="$(python3 -c')][0]
etc = os.path.join(work, "etc")
os.makedirs(etc)
CERT, KEY, FP = os.path.join(etc, "cert.pem"), os.path.join(etc, "key.pem"), ""
if BASH and OPENSSL:
    epath = etc.replace("\\", "/")
    gen = (f'set -euo pipefail; ETC="{epath}"\nif [ ! -s "$ETC/cert.pem" ] || [ ! -s "$ETC/key.pem" ]; then\n'
           f'{cert_block}\nfi\n' + fp_line.replace("python3", '"$PY"') + '\necho "$fp"')
    py = sys.executable.replace("\\", "/")
    r1 = bash(gen, {"PY": py})
    FP = r1.stdout.strip()
    der = ssl.PEM_cert_to_DER_cert(open(CERT, encoding="ascii").read())
    check("C1 кусок установщика создаёт сертификат и ключ, отпечаток установщика = sha256 от DER",
          r1.returncode == 0 and os.path.getsize(KEY) > 0 and FP == hashlib.sha256(der).hexdigest()
          and not os.path.exists(CERT + ".tmp") and not os.path.exists(KEY + ".tmp"))
    r2 = bash(gen, {"PY": py})
    check("C2 повторная установка (обновление) сертификат не меняет — отпечаток у сторожа остаётся верным",
          r2.returncode == 0 and r2.stdout.strip() == FP)
else:
    print("ПРОПУСК C1-C2 и проверок TLS: нет bash или openssl")


def serve(tls):
    srv = bs.Server(("127.0.0.1", 0), www, tls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def raw_get(port, path, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request(method, path)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        c.close()


def raw_bytes(port, data):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(data)
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return out
            out += chunk
    except OSError:
        return out
    finally:
        s.close()


tls = bs.tls_context(CERT, KEY) if FP else None
srv, port = serve(tls)
url = f"http://127.0.0.1:{port}/state.json"

# --- HTTP, как у прежнего сторожа ---
st, hd, body = raw_get(port, "/state.json")
check("H1 HTTP: /state.json отдаётся, тип JSON, без заголовка Server",
      st == 200 and json.loads(body) == STATE and hd.get("Content-Type") == "application/json"
      and not any(k.lower() == "server" for k in hd) and hd.get("Cache-Control") == "no-store")
st, hd, body = raw_get(port, "/flows.json?x=1")
check("H2 HTTP: /flows.json (свидетель, curl сторожа) отдаётся, хвост ?… не мешает", st == 200 and b'"flows"' in body)
bad = ["/other.json", "/", "/www/state.json", "/../secret.txt", "/%2e%2e/secret.txt", "/state.json/", "/state.json.tmp",
       "/STATE.JSON"]
res = [raw_get(port, p) for p in bad]
check("H3 прочие пути — 404 без тела и без Server (только два имени из одной папки)",
      all(r[0] == 404 and r[2] == b"" and not any(k.lower() == "server" for k in r[1]) for r in res))
st, hd, body = raw_get(port, "/state.json", "HEAD")
check("H4 HEAD: заголовки с длиной, без тела", st == 200 and body == b"" and int(hd["Content-Length"]) > 10)
st, hd, body = raw_get(port, "/state.json", "POST")
check("H5 POST — отказ без подписи сервера", st in (404, 405, 501) and not any(k.lower() == "server" for k in hd))
garbage = raw_bytes(port, b"\x00\x01garbage\r\n\r\n")
check("H6 мусор вместо запроса: короткий ответ без Server и без страницы ошибки",
      b"server:" not in garbage.lower() and b"<" not in garbage)
check("H7 после мусора сервер жив", raw_get(port, "/state.json")[0] == 200)

# файл больше предела и ссылка вместо файла
big = os.path.join(www, "flows.json")
with open(big, "wb") as f:
    f.write(b" " * (bs.MAX_FILE + 1))
check("H8 файл больше MAX_FILE не отдаётся", raw_get(port, "/flows.json")[0] == 404)
os.remove(big)
link_ok = False
try:
    os.symlink(os.path.join(work, "secret.txt"), big)
    link_ok = True
except (OSError, NotImplementedError):
    print("ПРОПУСК H9: здесь нельзя создать ссылку")
if link_ok:
    st, _, body = raw_get(port, "/flows.json")
    check("H9 ссылка вместо файла не читается (O_NOFOLLOW)", st == 404 and b"SECRET" not in body)
    os.remove(big)
check("H10 read_file: нет файла / папка — None", bs.read_file(www, "nope.json") is None and bs.read_file(work, "www") is None)
os.mkdir(big)
check("H11 папка с именем flows.json — 404, сервер жив", raw_get(port, "/flows.json")[0] == 404
      and raw_get(port, "/state.json")[0] == 200)
os.rmdir(big)

# --- nodewatch: без отпечатка — по-старому ---
nodes_file = os.path.join(work, "nodes.json")
nwt.NODES_FILE = nodes_file
with open(nodes_file, "w", encoding="utf-8") as f:
    json.dump([{"name": "n1", "host": "127.0.0.1", "beacon": url}], f)
check("N1 у ноды нет sha256 — beacon_pin None, маячок по HTTP как раньше",
      nwt.beacon_pin(url) is None and nwt.fetch_beacon(url) == STATE)
os.remove(nodes_file)
check("N2 нет nodes.json — по-старому (HTTP)", nwt.beacon_pin(url) is None and nwt.fetch_beacon(url) == STATE)

if FP:
    calls = []
    real_read = bs.read_file
    bs.read_file = lambda folder, name: calls.append(name) or real_read(folder, name)
    check("T1 TLS на том же порту: fetch_beacon с верным отпечатком", nwt.fetch_beacon(url, FP) == STATE)
    check("T2 отпечаток с двоеточиями и в верхнем регистре тоже годится",
          nwt.fetch_beacon(url, ":".join(FP[i:i + 2] for i in range(0, 64, 2)).upper()) == STATE)
    n = len(calls)
    wrong = "0" * 64
    check("T3 чужой отпечаток — None, запрос не отправлен (сертификат сверяется до запроса), на HTTP не откатились",
          nwt.fetch_beacon(url, wrong) is None and len(calls) == n)
    check("T4 испорченный sha256 ('' или не 64 знака) — None, без отката на HTTP",
          nwt.fetch_beacon(url, "") is None and nwt.fetch_beacon(url, "abc") is None and len(calls) == n)
    with open(nodes_file, "w", encoding="utf-8") as f:
        json.dump([{"name": "n0", "beacon": "http://127.0.0.1:1/state.json", "sha256": wrong},
                   {"name": "n1", "host": "127.0.0.1", "beacon": url, "sha256": FP}], f)
    check("T5 sha256 берётся из nodes.json по адресу маячка (вызов probe.py/behavscan.py без изменений)",
          nwt.beacon_pin(url) == FP and nwt.fetch_beacon(url) == STATE)
    with open(nodes_file, "w", encoding="utf-8") as f:
        json.dump([{"name": "n1", "beacon": url, "sha256": wrong}], f)
    check("T6 в nodes.json чужой отпечаток — None (подмена сервера не проходит)", nwt.fetch_beacon(url) is None)
    with open(nodes_file, "w", encoding="utf-8") as f:
        json.dump([{"name": "n1", "beacon": url, "sha256": None}], f)
    check("T7 sha256 есть, но пустой — маячок не читается, на HTTP не откатываемся",
          nwt.beacon_pin(url) == "" and nwt.fetch_beacon(url) is None)
    os.remove(nodes_file)
    bs.read_file = real_read
    # прямой TLS-клиент: без Server в ответе, TLS 1.2+
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5))
    s.sendall(b"GET /state.json HTTP/1.0\r\n\r\n")
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    check("T8 ответ по TLS: 200, тот же JSON, без Server",
          resp.startswith(b"HTTP/1.0 200") and b"server:" not in resp.lower() and resp.endswith(json.dumps(STATE).encode()))
    raw_bytes(port, b"\x16\x03\x01\x00\x05junkjunk")
    check("T9 испорченное рукопожатие TLS не роняет сервер: HTTP и TLS после него работают",
          raw_get(port, "/state.json")[0] == 200 and nwt.fetch_beacon(url, FP) == STATE)
    check("T10 самопроверка установщика check(): верный отпечаток (200, 200), чужой (200, 0), без отпечатка (200, None)",
          bs.check(port, FP) == (200, 200) and bs.check(port, wrong) == (200, 0) and bs.check(port) == (200, None))
    r = subprocess.run([sys.executable, os.path.join(HERE, "beacon_serve.py"), "--check", str(port), FP],
                       capture_output=True, text=True)
    check("T11 beacon_serve.py --check печатает «HTTP 200 TLS 200» и выходит с 0",
          r.returncode == 0 and r.stdout.strip() == "HTTP 200 TLS 200")

    # старый сервер без сертификата (нода ещё не обновлена), а сторож уже с отпечатком — не откатываемся на HTTP
    srv0, port0 = serve(None)
    url0 = f"http://127.0.0.1:{port0}/state.json"
    check("T12 сервер без сертификата: HTTP работает, клиент с отпечатком получает None (без отката)",
          nwt.fetch_beacon(url0) == STATE and nwt.fetch_beacon(url0, FP) is None)
    srv0.shutdown()
    srv0.server_close()
    srv1, port1 = serve(bs.tls_context(CERT, KEY))
    check("T13 перезапуск со старым сертификатом — тот же отпечаток", nwt.fetch_beacon(f"http://127.0.0.1:{port1}/state.json", FP) == STATE)
    srv1.shutdown()
    srv1.server_close()
check("T14 tls_context без файлов — None (только HTTP)", bs.tls_context(os.path.join(work, "no.pem"), KEY) is None
      and bs.tls_context(None, None) is None)
old_cd = os.environ.pop("CREDENTIALS_DIRECTORY", None)
os.environ["CREDENTIALS_DIRECTORY"] = etc
check("T15 файлы TLS берутся из $CREDENTIALS_DIRECTORY (LoadCredential)",
      bs.cred_files() == (os.path.join(etc, "cert.pem"), os.path.join(etc, "key.pem")))
del os.environ["CREDENTIALS_DIRECTORY"]
check("T16 без $CREDENTIALS_DIRECTORY — файлов нет", bs.cred_files() == (None, None))
if old_cd is not None:
    os.environ["CREDENTIALS_DIRECTORY"] = old_cd

# --- свои и чужие, общий срок соединения, места ---
import time  # noqa: E402

srv.shutdown()
srv.server_close()

ip = bs.norm_ip
check("A1 norm_ip: IPv4 внутри IPv6 — как IPv4, зона «%» отрезается, мусор — None",
      ip("::ffff:192.0.2.7") == ip("192.0.2.7") and str(ip("fe80::1%eth0")) == "fe80::1" and ip("x") is None
      and ip("") is None)
nets = bs.parse_allow(["192.0.2.10", "2001:db8::/64"])


class FakeSock:
    def __init__(self, local):
        self.local = local

    def getsockname(self):
        return (self.local, 9108)


def ver(addr, allow=nets, local="198.51.100.5", trust=True):
    s = bs.Server.__new__(bs.Server)
    s.allow, s.trust_local = allow, trust
    return s.verify_request(FakeSock(local), (addr, 40000))


check("A2 verify_request: сторож (--allow) и его сеть IPv6 — свои; чужой адрес — нет",
      ver("192.0.2.10") and ver("2001:db8::5") and ver("::ffff:192.0.2.10") and not ver("192.0.2.11")
      and not ver("2001:db8:1::5") and not ver("203.0.113.9"))
check("A3 127.0.0.0/8, ::1 и адрес самой ноды (канал через эту же ноду) — свои; без trust_local — нет",
      ver("127.0.0.1") and ver("::1") and ver("127.0.0.53") and ver("198.51.100.5")
      and not ver("127.0.0.1", trust=False) and not ver("198.51.100.5", trust=False))
check("A4 IPv4 не сравнивается с сетью IPv6 (::/96 не пускает IPv4), мусор вместо адреса — чужой",
      not ver("0.0.0.5", allow=bs.parse_allow(["::/96"]), trust=False) and not ver("junk") and not ver(""))
check("A5 без --allow (прежний юнит) — отвечаем всем", ver("203.0.113.9", allow=None))
check("A6 parse_args: прежний вид «ПОРТ ПАПКА [--bind]» понимается, --allow можно несколько, --tls-only",
      bs.parse_args(["9108", "/w"]) == (9108, "/w", "0.0.0.0", None, False)
      and bs.parse_args(["9108", "/w", "--bind", "::"])[2] == "::"
      and bs.parse_args(["9108", "/w", "--allow", "192.0.2.10", "--allow", "2001:db8::/64", "--tls-only"])
      == (9108, "/w", "0.0.0.0", nets, True))
bad_args = (["9108"], ["9108", "/w", "--allow"], ["9108", "/w", "--allow", "x.y"], ["9108", "/w", "--zzz"],
            ["9108", "/w", "extra"])
res = []
for a in bad_args:
    try:
        bs.parse_args(a)
        res.append(False)
    except ValueError:
        res.append(True)
check("A7 parse_args: не те параметры (нет папки, --allow без адреса или не адрес, лишнее) — ошибка", all(res))


def serve_allow(**kw):
    s = bs.Server(("127.0.0.1", 0), www, tls, ["127.0.0.1/32"], **kw)
    s.trust_local = False  # на одном ПК: 127.0.0.1 — «сторож», 127.0.0.2 — «чужой»
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, s.server_address[1]


def connect_from(src, p):
    c = socket.socket()
    c.settimeout(5)
    c.bind((src, 0))
    c.connect(("127.0.0.1", p))
    return c


def closed_soon(c, wait=3):
    c.settimeout(wait)
    try:
        return c.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


def get_from(src, p, path="/state.json"):
    c = connect_from(src, p)
    try:
        c.sendall(f"GET {path} HTTP/1.0\r\n\r\n".encode())
        out = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                return out
            out += chunk
    except OSError:
        return out
    finally:
        c.close()


def idle(s, wait=2.0):
    """Места освобождены: поток соединения снимает учёт сразу после закрытия сокета — ждём доли секунды."""
    end = time.monotonic() + wait
    while s.active and time.monotonic() < end:
        time.sleep(0.02)
    return not s.active


sa, pa = serve_allow()
foreign = [connect_from("127.0.0.2", pa) for _ in range(bs.MAX_CONN + 4)]
t0 = time.monotonic()
shut = [closed_soon(c) for c in foreign]
check("S1 чужой адрес: каждое из MAX_CONN+4 молчащих соединений закрыто сразу, без ответа",
      all(shut) and time.monotonic() - t0 < 3)
foreign += [connect_from("127.0.0.2", pa) for _ in range(bs.MAX_CONN + 4)]
time.sleep(0.3)
resp = get_from("127.0.0.1", pa)
check("S2 16+ молчащих посторонних не мешают своему: сторож получает 200, мест у чужих нет",
      resp.startswith(b"HTTP/1.0 200") and resp.endswith(json.dumps(STATE).encode()) and idle(sa))
check("S3 чужой и с запросом получает обрыв без единого байта", get_from("127.0.0.2", pa) == b"")
for c in foreign:
    c.close()

own_silent = [connect_from("127.0.0.1", pa) for _ in range(bs.MAX_CONN + 4)]
time.sleep(0.5)
t0 = time.monotonic()
resp = get_from("127.0.0.1", pa)
check("S4 все места заняты молчащими своими — старейшее обрывается, запрос сторожа получает 200",
      resp.startswith(b"HTTP/1.0 200") and time.monotonic() - t0 < bs.EVICT_WAIT + 2)
check("S5 мест занято не больше MAX_CONN", len(sa.active) <= bs.MAX_CONN)
for c in own_silent:
    c.close()
check("S6 после закрытия места освобождаются", idle(sa) and get_from("127.0.0.1", pa).startswith(b"HTTP/1.0 200"))

# общий срок соединения: подача по байту не продлевает его
sa.deadline = 1.5
drip = connect_from("127.0.0.1", pa)
t0, cut_at, payload = time.monotonic(), None, b"GET /state.json HTTP/1.1\r\nX-Pad: " + b"a" * 200
for b_ in payload:
    try:
        drip.send(bytes([b_]))
    except OSError:
        cut_at = time.monotonic() - t0
        break
    time.sleep(0.25)
    if time.monotonic() - t0 > 6:
        break
if cut_at is None:
    cut_at = time.monotonic() - t0 if closed_soon(drip, 1) else None
drip.close()
check("D1 HTTP по байту раз в 0,25 с: соединение оборвано по общему сроку, а не через READ_WAIT",
      cut_at is not None and 1.0 < cut_at < 4)
silent = connect_from("127.0.0.1", pa)
t0 = time.monotonic()
ok_silent = closed_soon(silent, 5)
check("D2 молчащее своё соединение закрыто по общему сроку (раньше FIRST_WAIT)",
      ok_silent and 1.0 < time.monotonic() - t0 < 4)
silent.close()
if tls:
    hs = connect_from("127.0.0.1", pa)
    hs.sendall(b"\x16\x03\x01\x02\x00\x01")   # начало ClientHello, дальше тишина: висит в рукопожатии TLS
    t0 = time.monotonic()
    ok_hs = closed_soon(hs, 5)
    check("D3 недописанное рукопожатие TLS оборвано по общему сроку", ok_hs and time.monotonic() - t0 < 4)
    hs.close()
sa.deadline = bs.CONN_DEADLINE
time.sleep(0.3)
check("D4 после обрывов места свободны, ответ обычный", idle(sa)
      and get_from("127.0.0.1", pa).startswith(b"HTTP/1.0 200"))
check("D5 общий срок по умолчанию — 15 с, ожидание места после обрыва — короче срока",
      bs.CONN_DEADLINE == 15 and bs.EVICT_WAIT < bs.CONN_DEADLINE)
sa.shutdown()
sa.server_close()

# --tls-only: HTTP закрыт, TLS работает
if FP:
    st_, pt = serve_allow(tls_only=True)
    st_.trust_local = True
    check("L1 --tls-only: HTTP-запрос — обрыв без единого байта", get_from("127.0.0.1", pt) == b"")
    check("L2 --tls-only: маячок по TLS со сверкой отпечатка читается",
          nwt.fetch_beacon(f"http://127.0.0.1:{pt}/state.json", FP) == STATE)
    check("L3 самопроверка: (0, 200); check_ok(--tls-only) — да, обычный режим — нет",
          bs.check(pt, FP) == (0, 200) and bs.check_ok((0, 200), True) and not bs.check_ok((0, 200))
          and not bs.check_ok((200, 200), True) and bs.check_ok((200, 200)) and bs.check_ok((200, None)))
    r = subprocess.run([sys.executable, os.path.join(HERE, "beacon_serve.py"), "--check", str(pt), FP, "--tls-only"],
                       capture_output=True, text=True)
    check("L4 beacon_serve.py --check ПОРТ ОТПЕЧАТОК --tls-only: «HTTP 0 TLS 200», код 0",
          r.returncode == 0 and r.stdout.strip() == "HTTP 0 TLS 200")
    st_.shutdown()
    st_.server_close()
    sb, pb = serve_allow()
    sb.trust_local = True
    r = subprocess.run([sys.executable, os.path.join(HERE, "beacon_serve.py"), "--check", str(pb), FP, "--tls-only"],
                       capture_output=True, text=True, timeout=60)
    check("L5 --check --tls-only на сервере, где HTTP открыт, — код 1 (HTTP должен быть закрыт)",
          r.returncode == 1 and r.stdout.strip() == "HTTP 200 TLS 200")
    sb.shutdown()
    sb.server_close()
old_cd = os.environ.pop("CREDENTIALS_DIRECTORY", None)
err_buf = []
real_print = print


def quiet_print(*a, **k):
    if k.get("file") is sys.stderr:
        err_buf.append(" ".join(map(str, a)))
    else:
        real_print(*a, **k)


bs.print = quiet_print
rc_tls_only = bs.main(["0", www, "--tls-only"])
rc_bad = bs.main(["0"])
del bs.print
if old_cd is not None:
    os.environ["CREDENTIALS_DIRECTORY"] = old_cd
check("L6 --tls-only без сертификата — сервер не запускается (код 1); не те параметры — код 2",
      rc_tls_only == 1 and rc_bad == 2 and any("--tls-only" in e for e in err_buf))

# --- beacon_install.sh ---
serve_blk = bi.split('elif [ "$mode" = serve ]; then', 1)[1].split('\nelse\n', 1)[0]
http_unit = serve_blk.split("cat > /etc/systemd/system/node-beacon-http.service <<UNIT\n", 1)[1].split("\nUNIT\n", 1)[0]
hl = http_unit.splitlines()
check("I1 веб-сервер — beacon_serve.py вместо python3 -m http.server, от nobody",
      "ExecStart=/usr/bin/python3 /opt/node-beacon/beacon_serve.py $port $WWW --allow $allow$tls_arg" in hl
      and "http.server" not in http_unit
      and "User=nobody" in hl and "Group=nogroup" in hl)
for d in ("ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "NoNewPrivileges=yes",
          "CapabilityBoundingSet=$caps", "AmbientCapabilities=$caps", "MemoryMax=64M", "RestrictSUIDSGID=yes",
          "SyslogLevel=warning", "LogLevelMax=warning", "Restart=always"):
    check(f"I2 песочница веб-сервера: {d}", d in hl)
check("I3 права: пусто (все сняты), CAP_NET_BIND_SERVICE — только для порта ниже 1024",
      'caps=""; [ "$port" -ge 1024 ] || caps="CAP_NET_BIND_SERVICE"' in serve_blk)
check("I4 ключ службе — через LoadCredential (systemd 247+), сам ключ 600 root; старее — только HTTP",
      "$creds" in hl and "LoadCredential=cert.pem:$ETC/cert.pem\nLoadCredential=key.pem:$ETC/key.pem" in serve_blk
      and '[ "${sdv:-0}" -ge 247 ]' in serve_blk and 'chmod 600 "$ETC/key.pem"' in serve_blk)
check("I5 сертификат создаётся только если его нет (обновление сохраняет отпечаток), через .tmp",
      'if [ ! -s "$ETC/cert.pem" ] || [ ! -s "$ETC/key.pem" ]; then' in serve_blk
      and '-keyout "$ETC/key.pem.tmp" -out "$ETC/cert.pem.tmp"' in serve_blk and "umask 077" in serve_blk
      and serve_blk.find("cert.pem.tmp") < serve_blk.find("node-beacon-http.service <<UNIT"))
check("I6 нет openssl и не поставился — не падаем (set -e), дальше только HTTP",
      "apt-get install -y -qq openssl; } >/dev/null 2>&1 || true" in serve_blk)
pre = bi.split("install -d -m 755 /opt/node-beacon", 1)[0]
check("I7 нет beacon_serve.py рядом — выход до любых изменений (прежняя установка цела)",
      '[ "$mode" != serve ] || [ -s "$SRC/beacon_serve.py" ] || { echo "рядом нет beacon_serve.py' in pre)
check("I8 beacon_serve.py ставится в /opt/node-beacon; --uninstall убирает /opt/node-beacon и /etc/node-beacon целиком",
      'install -m 755 "$SRC/beacon_serve.py" /opt/node-beacon/beacon_serve.py' in serve_blk
      and 'rm -rf /opt/node-beacon "$ETC" /var/lib/node-beacon' in bi.split('if [ "$mode" = uninstall ]; then', 1)[1])
site = bi.split('if [ "$mode" = site ]; then\n', 1)[1].split('elif [ "$mode" = serve ]', 1)[0]
check("I9 serve→site: сертификат, ключ и beacon_serve.py убираются",
      'rm -f "$ETC/cert.pem" "$ETC/key.pem" /opt/node-beacon/beacon_serve.py' in site)
lines = bi.rstrip().splitlines()
check("I10 в конце BEACON-SHA256 <отпечаток> (только --serve с сертификатом), последней — BEACON <хвост>",
      lines[-1] == 'echo "BEACON $tail"'
      and lines[-2] == 'if [ "$mode" = serve ] && [ -n "$fp" ]; then echo "BEACON-SHA256 $fp"; fi')
tail_blk = bi.split('python3 /opt/node-beacon/beacon_serve.py --check "$port" $fp$tls_arg', 1)
check("I11 самопроверка после записи файла маячка: HTTP и TLS со сверкой; не отвечает — выход 1 с подсказкой",
      len(tail_blk) == 2 and bi.find('[ -s "$out" ] || { echo "маячок не записал') < bi.find("beacon_serve.py --check")
      and "journalctl -u node-beacon-http -n 20" in tail_blk[1].split("\nfi\n", 1)[0]
      and '\\"sha256\\": \\"$fp\\"' in tail_blk[1])
check("I12 fp инициализирован до разбора параметров (set -u в режиме --site-dir)",
      'fp=""' in bi.split("while [ $# -gt 0 ]", 1)[0])
check("I13 шапка установщика: TLS, BEACON-SHA256 и порядок перехода через sha256 в nodes.json",
      all(w in bi.split("set -euo pipefail", 1)[0] for w in ("TLS", "BEACON-SHA256", "nodes.json", "\"sha256\"")))
check("I14 установщик и сервер в LF, без CR", "\r" not in bi and "\r" not in src_of("beacon_serve.py")
      and "\r" not in src_of("nodewatch.py"))
if BASH:
    check("I15 bash -n beacon_install.sh", subprocess.run([BASH, "-n", os.path.join(HERE, "beacon_install.sh")]).returncode == 0)
pre_serve = bi.split('elif [ "$mode" = serve ]; then', 1)[0]
check("I17 --tls-only: ключ разбирается, только вместе с --serve — иначе выход до любых изменений",
      "--tls-only) tls_only=1; shift ;;" in bi and 'tls_only=0' in bi.split("while [ $# -gt 0 ]", 1)[0]
      and '[ "$tls_only" = 0 ] || [ "$mode" = serve ] || { echo "--tls-only — только вместе с --serve"; exit 2; }'
      in pre_serve and pre_serve.find('"$mode" = serve ] || { echo "--tls-only') < pre_serve.find("install -d -m 755"))
no_cert = '[ "$tls_only" = 0 ] || [ -n "$fp" ] || {'
check("I18 --tls-only без сертификата — выход после расчёта отпечатка, но до записи out, beacon_serve.py и юнита",
      serve_blk.find('fp="$(python3 -c') < serve_blk.find(no_cert) < serve_blk.find('echo "$WWW/state.json" > "$ETC/out"')
      < serve_blk.find('install -m 755 "$SRC/beacon_serve.py"') < serve_blk.find("node-beacon-http.service <<UNIT")
      and 'tls_arg=""; [ "$tls_only" = 0 ] || tls_arg=" --tls-only"' in serve_blk)
check("I19 юнит передаёт --allow сторожа (чужих сервер закрывает и без ufw); итог --tls-only — с напоминанием о sha256",
      "--allow $allow$tls_arg" in http_unit and 'if [ "$tls_only" = 1 ]; then' in tail_blk[1]
      and "только TLS, HTTP закрыт" in tail_blk[1] and "сервер маячка отвечает только $allow" in serve_blk)
check("I20 шапка: --tls-only и порядок (последним шагом, после sha256 и нового сторожа), --allow у самого сервера",
      all(w in bi.split("set -euo pipefail", 1)[0] for w in ("[--tls-only]", "--tls-only", "последним шагом",
                                                              "blockwatch.py", "чужие соединения закрывает сразу")))
check("I16 шапка nodewatch: поле sha256 у ноды в nodes.json", '"sha256"' in nwt.__doc__ and "BEACON-SHA256" in nwt.__doc__)

shutil.rmtree(work, ignore_errors=True)
print(f"\nвсе {ok} проверок прошли")
