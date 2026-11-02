"""channel-watch: сетевые пробы без зависимостей — общий код сторожа (rf1) и агента точки проверки (vantage_agent.py).

1. dns_udp — вопрос обычному DNS-серверу по UDP (для сравнения с ответом по защищённому DNS: так ищут подмену).
2. direct_probe — прямая проверка сервера: порт, TLS с нужным именем, и набирается ли по одному соединению NEED байт.
   Сайты-прикрытия маленькие, поэтому объём набирается повторными запросами страницы по одному соединению:
   обрыв «после 16–20 КБ» режет соединение, а не файл.
3. tcp_trace — трассировка TCP SYN до порта (системный traceroute -T): дошли ли пакеты и где оборвались.
"""
import http.client
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")
NEED = 64 * 1024     # столько должно прийти по одному соединению; обрыв DPI случается на 16–20 КБ
STALL = 5            # секунд без единого байта — соединение встало
MAX_REQS = 80        # больше запросов по одному соединению не делаем
SMALL_PAGE = 600     # страница меньше (чужой сайт-прикрытие отвечает переадресацией) — объём не набрать, не судим
SMALL_AFTER = 6      # по стольким ответам решаем, что страница мала


# ---------- DNS по UDP ----------

def dns_build(name, qid):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        q += bytes([len(raw)]) + raw
    return q + b"\x00" + struct.pack(">HH", 1, 1)


def _skip_name(data, pos):
    while True:
        n = data[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + n


def dns_parse(data, qid):
    """Ответ DNS: ('ok', [адреса IPv4]), ('nx', []) — имени нет, ('err', []) — ответ не разобрать или отказ."""
    if len(data) < 12:
        return "err", []
    rid, flags, qd, an = struct.unpack(">HHHH", data[:8])
    if rid != qid or not flags & 0x8000:
        return "err", []
    rcode = flags & 0x000F
    if rcode == 3:
        return "nx", []
    if rcode != 0:
        return "err", []
    pos, ips = 12, []
    try:
        for _ in range(qd):
            pos = _skip_name(data, pos) + 4
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
    except (IndexError, struct.error):
        return "err", []
    return "ok", sorted(set(ips))


def dns_udp(name, server, port=53, timeout=3):
    """Запись A у обычного DNS-сервера по UDP, две попытки: ('ok' | 'nx' | 'err', [адреса])."""
    for _ in (1, 2):
        qid = random.randrange(1, 65535)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(dns_build(name, qid), (server, port))
                data, _ = s.recvfrom(2048)
        except (OSError, UnicodeError):
            continue
        res = dns_parse(data, qid)
        if res[0] != "err":
            return res
    return "err", []


def resolve_system(name):
    """Что отвечает системный резолвер этого сервера: ('ok', [адреса]) | ('nx', []) | ('err', [])."""
    try:
        infos = socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return ("nx", []) if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)) else ("err", [])
    except OSError:
        return "err", []
    return "ok", sorted({i[4][0] for i in infos})


FALLBACK_DNS = ("77.88.8.8", "8.8.8.8")  # запасной DNS, когда свой (системный) имя не нашёл


def resolve(host, port=443):
    """Адрес сервера: своим (системным) DNS, а не нашёл — публичным по UDP. (адрес, чем нашли): «system», адрес
    публичного DNS или «fail»."""
    try:
        return socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0], "system"
    except (OSError, UnicodeError):
        pass
    for srv in FALLBACK_DNS:
        status, ips = dns_udp(host, srv)
        if status == "ok" and ips:
            return ips[0], srv
    return None, "fail"


# ---------- прямая проверка сервера ----------

def pull(sock, hostname, need=NEED, deadline=12):
    """Набрать need байт повторными запросами страницы по одному соединению. Возвращает (сколько пришло, чем кончилось):
    'ok' — набрали; 'timeout' — соединение встало (так выглядит обрыв DPI); 'closed' — сервер закрыл соединение;
    'small' — страница слишком мала, объём не набрать; 'deadline' — данные шли, но не уложились во время."""
    conn = http.client.HTTPConnection(hostname)
    conn.sock, conn.auto_open = sock, 0  # соединение уже открыто нами; заново (и без TLS) не открывать
    got, t_end = 0, time.time() + deadline
    for n in range(MAX_REQS):
        if got >= need:
            return got, "ok"
        if n >= SMALL_AFTER and got < n * SMALL_PAGE:
            return got, "small"
        left = t_end - time.time()
        if left <= 0:
            return got, "deadline"
        try:
            sock.settimeout(min(STALL, left))
            conn.request("GET", "/", headers={"User-Agent": UA, "Accept-Encoding": "identity", "Connection": "keep-alive"})
            r = conn.getresponse()
            got += len(r.read()) + 200  # 200 — примерно заголовки ответа
        except (socket.timeout, TimeoutError):
            return got, "timeout"
        except (http.client.HTTPException, OSError):
            return got, "closed"
    return (got, "ok") if got >= need else (got, "small")


def direct_probe(host, port=443, sni=None, need=NEED, tls=True, deadline=12):
    """Прямая проверка host:port: адрес, порт, TLS с именем sni, объём по одному соединению.
    {"addr", "tcp": open|refused|timeout|error|dns, "tcp_ms", "tls": True|False|None, "bytes", "need", "end"}"""
    res = {"host": host, "addr": None, "tcp": "error", "tcp_ms": None, "tls": None, "bytes": None, "need": need, "end": None}
    res["addr"], res["dns"] = resolve(host, port)
    if not res["addr"]:
        res["tcp"] = "dns"
        return res
    t0 = time.time()
    try:
        sock = socket.create_connection((res["addr"], port), timeout=5)
    except ConnectionRefusedError:
        res["tcp"] = "refused"
        return res
    except (socket.timeout, TimeoutError):
        res["tcp"] = "timeout"
        if port == 443:
            res["alt80"] = other_port(res["addr"])  # порт 443 молчит: отвечает ли тот же адрес на порту 80
        return res
    except OSError:
        return res
    res["tcp"], res["tcp_ms"] = "open", int((time.time() - t0) * 1000)
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(6)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=sni or host)
                res["tls"] = True
            except (ssl.SSLError, OSError, ValueError):
                res["tls"] = False
                return res
        res["bytes"], res["end"] = pull(sock, sni or host, need, deadline)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return res


# ---------- серия соединений и сравнение имён ----------

MSS_MARK = (1201, 1260)   # метка серии: SYN с таким MSS узнаёт помощник на ноде (node_witness.py)
SERIES_MAX = 40
SLOW_SYN = 0.9            # соединение дольше — прошло только со второй посылки SYN (первая через 1 с)
NEUTRAL_SNI = "www.example.org"


def series(host, port=443, n=20, mss=None, timeout=2.5, gap=0.1):
    """n соединений подряд с host:port (только рукопожатие TCP): так видно частичные потери, которые одна
    проверка пропустит. mss — метка серии (MSS в SYN): по ней нода узнаёт эти соединения и считает, что дошло.
    {"addr", "n", "ok", "fail", "slow" (прошло лишь со второй посылки), "refused", "ms", "t0", "t1", "mss"}"""
    res = {"host": host, "addr": None, "n": 0, "ok": 0, "fail": 0, "slow": 0, "refused": 0, "ms": None,
           "t0": time.time(), "t1": None, "mss": mss if mss and MSS_MARK[0] <= mss <= MSS_MARK[1] else None}
    res["addr"], res["dns"] = resolve(host, port)
    if not res["addr"]:
        res["t1"] = time.time()
        return res
    times = []
    for i in range(max(1, min(int(n), SERIES_MAX))):
        if i >= 6 and res["ok"] == 0:
            break  # не прошло ни одно из шести — сервер недоступен целиком, это уже не «частичные потери»
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if res["mss"]:
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, res["mss"])
            except (OSError, AttributeError):
                res["mss"] = None  # здесь метку поставить нельзя (не Linux) — серия идёт без неё
        try:
            s.settimeout(timeout)
            t = time.time()
            s.connect((res["addr"], port))
            took = time.time() - t
            res["ok"] += 1
            times.append(took)
            if took > SLOW_SYN:
                res["slow"] += 1
        except ConnectionRefusedError:
            res["refused"] += 1
        except OSError:
            res["fail"] += 1
        finally:
            s.close()
        res["n"] += 1
        time.sleep(gap)
    times.sort()
    res["ms"] = int(times[len(times) // 2] * 1000) if times else None
    res["t1"] = time.time()
    return res


def can_mark(mss):
    """Метка mss в пределах и ставится на этой системе (Linux) — mss, иначе None."""
    if not mss or not MSS_MARK[0] <= mss <= MSS_MARK[1]:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        return mss
    except (OSError, AttributeError):
        return None
    finally:
        s.close()


def tls_hello(addr, port, name, timeout=5, mss=None):
    """Приветствие TLS с именем name (None — без имени) на addr:port. Что вышло: 'answer' — сервер ответил
    (рукопожатием или отказом TLS), 'silent' — порт открыт, ответа нет, 'reset' — соединение сброшено,
    'closed' — закрыто без ответа, 'tcp' — порт не открылся. mss — метка соединения для свидетеля на ноде."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if mss:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        except (OSError, AttributeError):
            pass  # метку здесь поставить нельзя (не Linux) — приветствие идёт без неё
    try:
        sock.settimeout(4)
        sock.connect((addr, port))
    except OSError:
        sock.close()
        return "tcp"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock.settimeout(timeout)
        try:
            sock = ctx.wrap_socket(sock, server_hostname=name)
            return "answer"
        except ssl.SSLEOFError:
            return "closed"
        except ssl.SSLError:
            return "answer"  # отказ TLS (нет такого имени, не TLS и т. п.) — это тоже ответ сервера
        except (socket.timeout, TimeoutError):
            return "silent"
        except ConnectionResetError:
            return "reset"
        except OSError:
            return "closed"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def sni_compare(host, port=443, sni=None, mss=None):
    """Один адрес, разные имена в приветствии TLS: настоящее, нейтральное и без имени. Если с настоящим сервер
    молчит, а с другим отвечает — режут по имени сайта (SNI), а не по адресу. mss — метка на соединении с настоящим
    именем (по ней свидетель на ноде скажет, отправляла ли нода сброс).
    {"addr", "real", "neutral", "none", "mss", "t0", "t1"} — значения как у tls_hello; None — имя не нашлось в DNS."""
    addr, via = resolve(host, port)
    if not addr:
        return None
    mark = can_mark(mss)
    out = {"addr": addr, "dns": via, "mss": mark, "t0": time.time()}
    threads = []
    for key, name in (("real", sni or host), ("neutral", NEUTRAL_SNI), ("none", None)):
        t = threading.Thread(target=lambda k=key, n=name: out.__setitem__(
            k, tls_hello(addr, port, n, mss=mark if k == "real" else None)), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(12)
    out["t1"] = time.time()
    return {k: out.get(k) for k in ("addr", "dns", "real", "neutral", "none", "mss", "t0", "t1")}


IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
REF_HOST = "www.example.org"  # чужой нейтральный сервер для проверки «закрыто ли имя»


def path_hop(addr, port, ttl, timeout=1.0):
    """Одна посылка SYN с TTL ttl. ('dest'|'refused', addr, мс) — дошла до цели; ('hop'|'reject<код>'|'icmpT/C',
    адрес узла, мс) — ответил узел на пути (из очереди ошибок сокета, без особых прав, Linux); ('silent', None, None)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        s.settimeout(timeout)
        t0 = time.monotonic()
        try:
            s.connect((addr, port))
            return "dest", addr, round((time.monotonic() - t0) * 1000)
        except ConnectionRefusedError:
            return "refused", addr, round((time.monotonic() - t0) * 1000)
        except (socket.timeout, TimeoutError):
            return "silent", None, None
        except OSError:
            ms = round((time.monotonic() - t0) * 1000)
            try:
                _, anc, _, _ = s.recvmsg(256, 512, socket.MSG_ERRQUEUE)
            except (OSError, AttributeError):
                return "silent", None, None
            for lvl, typ, data in anc:
                if lvl == socket.IPPROTO_IP and typ == IP_RECVERR and len(data) >= 24:
                    _, origin, itype, icode = struct.unpack_from("=IBBB", data, 0)
                    who = socket.inet_ntoa(data[20:24])
                    if origin != 2:  # не ICMP
                        return "silent", None, None
                    kind = "hop" if itype == 11 else f"reject{icode}" if itype == 3 else f"icmp{itype}/{icode}"
                    return kind, who, ms
            return "silent", None, None
    finally:
        s.close()


def path_trace(host, port=443, max_ttl=16, timeout=1.0, quiet=3, hop=None):
    """Путь соединения до host:port: SYN с растущим TTL. Останавливается, дойдя до цели, на узле с отказом либо после
    quiet молчащих шагов подряд за последним ответившим. {"addr", "dns", "reached", "hops", "last": [шаг, адрес] | None,
    "list": [[шаг, вид, адрес|None, мс|None], ...]}; None — не Linux (без очереди ошибок сокета так не измерить)."""
    hop = hop or (path_hop if sys.platform.startswith("linux") else None)
    if not hop:
        return None
    addr, via = resolve(host, port)
    if not addr:
        return {"addr": None, "dns": via}
    rows, last, quiet_run = [], None, 0
    for ttl in range(1, max_ttl + 1):
        kind, who, ms = hop(addr, port, ttl, timeout)
        rows.append([ttl, kind, who, ms])
        if kind in ("dest", "refused"):
            return {"addr": addr, "dns": via, "reached": True, "hops": ttl, "last": [ttl, addr], "list": rows}
        if who:
            last, quiet_run = [ttl, who], 0
            if kind != "hop":
                break  # узел ответил отказом — дальше путь закрыт
        else:
            quiet_run += 1
            if last and quiet_run >= quiet:
                break
    return {"addr": addr, "dns": via, "reached": False, "hops": len(rows), "last": last, "list": rows}


def name_ref(name, tries=2, ref=REF_HOST):
    """«Закрыто ли имя»: приветствие TLS с именем name на чужой нейтральный сервер (адрес ref) и с нейтральным именем
    там же, tries раз. {"ref", "n", "name_ok", "neutral_ok", "fails"}; ref не нашёлся — {"ref": None}."""
    addr, _ = resolve(ref)
    if not addr:
        return {"ref": None}
    out = {"ref": addr, "n": tries, "name_ok": 0, "neutral_ok": 0, "fails": {}}
    for _ in range(tries):
        a, b = tls_hello(addr, 443, name, timeout=4), tls_hello(addr, 443, ref, timeout=4)
        out["name_ok"] += a == "answer"
        out["neutral_ok"] += b == "answer"
        if a != "answer":
            out["fails"][a] = out["fails"].get(a, 0) + 1
    return out


def other_port(addr, port=80, timeout=3):
    """Отвечает ли адрес на другом порту: 'open' | 'refused' (сервер ответил отказом — адрес доступен) | None."""
    try:
        socket.create_connection((addr, port), timeout=timeout).close()
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return None


def load_speed(url, rng=None, timeout=12):
    """Скорость загрузки url (curl), Мбит/с и сколько пришло; (None, 0) — не ответил."""
    cmd = ["curl", "-4", "-s", "-m", str(timeout), "-o", os.devnull, "-w", "%{speed_download} %{size_download}"]
    if rng:
        cmd[1:1] = ["-r", rng]
    cmd.append(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 4).stdout.split()
        return round(float(out[0]) * 8 / 1e6, 1), int(out[1])
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None, 0


def profile_run(sites, loads, neutral=NEUTRAL_SNI):
    """Профиль точки по ЗАРАНЕЕ заданному списку (не произвольные цели). Для каждого сайта из sites ([вид, имя]):
    приветствие TLS по его адресу с его именем и, если вид 'blocked', с нейтральным именем. Для каждого хостинга из
    loads ([имя, url, диапазон|null]): скорость загрузки. Возвращает {"sites": [...], "loads": [...]}."""
    out = {"sites": [], "loads": []}
    for kind, host in sites:
        addr, via = resolve(host)
        if not addr:
            out["sites"].append({"kind": kind, "host": host, "addr": None, "real": "dns", "neutral": None})
            continue
        real = tls_hello(addr, 443, host, timeout=6)
        neu = tls_hello(addr, 443, neutral, timeout=6) if kind == "blocked" else None
        out["sites"].append({"kind": kind, "host": host, "addr": addr, "real": real, "neutral": neu})
    for name, url, rng in loads:
        mbit, got = load_speed(url, rng)
        out["loads"].append({"name": name, "mbit": mbit, "bytes": got})
    return out


VPN_URL = "https://speed.cloudflare.com/__down?bytes=524288"  # 512 КБ через плитку
VPN_NEED = 524288


def socks_load(port, url=VPN_URL, need=VPN_NEED, timeout=25):
    """Загрузка url через SOCKS 127.0.0.1:port (свой клиент Xray): {"ok", "code", "bytes", "mbit", "s", "ttfb_ms", "rc"}."""
    cmd = ["curl", "-s", "-m", str(timeout), "-x", f"socks5h://127.0.0.1:{int(port)}", "-o", os.devnull,
           "-w", "%{http_code} %{size_download} %{speed_download} %{time_total} %{time_starttransfer}", url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        code, size, speed, total, ttfb = r.stdout.split()
        size = int(float(size))
        return {"ok": code == "200" and size >= need, "code": code, "bytes": size, "mbit": round(float(speed) * 8 / 1e6, 1),
                "s": round(float(total), 2), "ttfb_ms": int(float(ttfb) * 1000), "rc": r.returncode}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"ok": False, "code": None, "bytes": 0, "mbit": None, "s": None, "ttfb_ms": None, "rc": None}


def probe_class(r):
    """Итог прямой проверки одним словом: ok | stall (встало, не набрав объём) | tls | tcp | dns | none (не проверялось)."""
    if not r:
        return "none"
    if r["tcp"] == "dns":
        return "dns"
    if r["tcp"] != "open":
        return "tcp"
    if r["tls"] is False:
        return "tls"
    if r["end"] == "timeout" and (r["bytes"] or 0) < r["need"]:
        return "stall"
    return "ok"


# ---------- трассировка TCP ----------

def parse_trace(out, addr):
    """Вывод traceroute -n -q 1: {"reached": дошли ли до addr, "hops": сколько шагов прошли, "last": (шаг, адрес)}."""
    last, hops = None, 0
    for line in out.splitlines():
        p = line.split()
        if len(p) < 2 or not p[0].isdigit():
            continue
        hops = int(p[0])
        if p[1] != "*":
            last = (hops, p[1])
            if p[1] == addr:
                return {"reached": True, "hops": hops, "last": last}
    return {"reached": False, "hops": hops, "last": last}


def tcp_trace(addr, port=443, max_hops=16):
    """Трассировка TCP SYN до addr:port системным traceroute (нужны права root); None — трассировать нечем."""
    exe = shutil.which("traceroute")
    if not exe or getattr(os, "geteuid", lambda: 0)() != 0:
        return None
    cmd = [exe, "-4", "-T", "-p", str(port), "-n", "-q", "1", "-w", "1", "-m", str(max_hops), addr]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops + 8).stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
    return parse_trace(out, addr)
