"""channel-watch: сетевые пробы без зависимостей — общий код сторожа (rf1) и агента точки проверки (vantage_agent.py).

1. dns_udp — вопрос обычному DNS-серверу по UDP (для сравнения с ответом по защищённому DNS: так ищут подмену).
2. direct_probe — прямая проверка сервера: порт, TLS с нужным именем, и набирается ли по одному соединению NEED байт.
   Сайты-прикрытия маленькие, поэтому объём набирается повторными запросами страницы по одному соединению:
   обрыв «после 16–20 КБ» режет соединение, а не файл. С verify — ещё сверка сертификата (чужой сертификат ≠ «нет связи»).
3. tcp_trace — трассировка TCP SYN до порта (системный traceroute -T): дошли ли пакеты и где оборвались.
"""
import http.client
import json
import os
import random
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

# Локальный SOCKS сторожа (клиент Xray, build_channels.py) — под паролем, если есть файл socks.auth.
# По этой метке build_channels.py --socks-auth проверяет, что модуль рядом с ним умеет ходить с паролем.
SOCKS_AUTH_READY = True

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")
NEED = 64 * 1024     # столько должно прийти по одному соединению; обрыв DPI случается на 16–20 КБ
STALL = 5            # секунд без единого байта — соединение встало
MAX_REQS = 80        # больше запросов по одному соединению не делаем
SMALL_PAGE = 600     # страница меньше (чужой сайт-прикрытие отвечает переадресацией) — объём не набрать, не судим
SMALL_AFTER = 6      # по стольким ответам решаем, что страница мала
PULL_CHUNK = 16 * 1024  # тело ответа читаем кусками не больше этого
# Срок pull вышел, объём не набран, а соединение перед этим молчало дольше STALL * DEADLINE_IDLE_PART — это «встало»,
# а не «не уложились». Буквально «молчало дольше STALL» к сроку почти не бывает: ожидание у срока урезается до остатка
# (меньше STALL), поэтому порог — половина STALL; молчание дольше STALL им тоже покрыто. Поток, который просто
# медленный, приносит данные чаще и остаётся «deadline».
DEADLINE_IDLE_PART = 0.5  # доля STALL
CERT_BUDGET = 4      # секунд на сверку сертификата (verify) всего: соединение и рукопожатие вместе


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


# Запасной DNS, когда свой (системный) имя не нашёл. Только защищённый (DoH, JSON): имена наших нод открытым UDP
# не уходят. Адреса серверов DoH — IP в сертификате, поэтому их имена тоже не спрашиваются открыто.
# Строка без «https://» — прежний вопрос по UDP к этому серверу; по умолчанию таких нет, оставлено только для
# явной настройки и тестов.
FALLBACK_DNS = ("https://1.1.1.1/dns-query?name={}&type=A", "https://8.8.8.8/resolve?name={}&type=A")
DOH_TIMEOUT = 4


def doh_query(name, url, timeout=DOH_TIMEOUT):
    """Запись A по защищённому DNS (DoH, ответ JSON): ('ok' | 'nx' | 'err', [адреса])."""
    try:
        req = urllib.request.Request(url.format(urllib.parse.quote(name.rstrip("."), safe="")),
                                     headers={"accept": "application/dns-json", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(65536).decode("utf-8"))
    except (OSError, ValueError, UnicodeError, http.client.HTTPException):
        return "err", []
    if not isinstance(data, dict):
        return "err", []
    if data.get("Status") == 3:
        return "nx", []
    if data.get("Status") != 0:
        return "err", []
    ips = []
    for a in data.get("Answer") or []:
        if isinstance(a, dict) and a.get("type") == 1:
            try:
                socket.inet_aton(str(a.get("data")))
            except OSError:
                continue
            ips.append(str(a["data"]))
    return "ok", sorted(set(ips))


def resolve(host, port=443):
    """Адрес сервера: своим (системным) DNS, а не нашёл — защищённым (DoH). (адрес, чем нашли): «system»,
    «doh» или «fail». Запасной сервер по UDP (только явной настройкой FALLBACK_DNS) — его адрес."""
    try:
        return socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0], "system"
    except (OSError, UnicodeError):
        pass
    for srv in FALLBACK_DNS:
        if srv.startswith("https://"):
            status, ips = doh_query(host, srv)
            if status == "ok" and ips:
                return ips[0], "doh"
            if status == "nx":
                break  # защищённый DNS сказал «имени нет» — дальше спрашивать незачем
            continue
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
    t_last = time.time()  # когда последний раз что-то пришло (заголовки ответа или кусок тела)

    def at_deadline():
        # срок вышел, объём не набран: если перед этим соединение молчало дольше STALL * DEADLINE_IDLE_PART — встало
        # («timeout», probe_class — «stall»), а не просто не уложилось; так и старый probe_class поймёт верно
        return got, "timeout" if got < need and time.time() - t_last > STALL * DEADLINE_IDLE_PART else "deadline"

    for n in range(MAX_REQS):
        if got >= need:
            return got, "ok"
        if n >= SMALL_AFTER and got < n * SMALL_PAGE:
            return got, "small"
        left = t_end - time.time()
        if left <= 0:
            return at_deadline()
        try:
            sock.settimeout(min(STALL, left))
            conn.request("GET", "/", headers={"User-Agent": UA, "Accept-Encoding": "identity", "Connection": "keep-alive"})
            r = conn.getresponse()
            got += 200  # примерно заголовки ответа
            t_last = time.time()
            # тело кусками, не больше need - got за раз и без накопления в памяти; срок — на каждом куске
            while got < need:
                left = t_end - time.time()
                if left <= 0:
                    return at_deadline()
                sock.settimeout(min(STALL, left))
                chunk = r.read1(min(PULL_CHUNK, need - got))
                if not chunk:
                    break  # ответ кончился — следующий запрос по тому же соединению
                got += len(chunk)
                t_last = time.time()
        except (socket.timeout, TimeoutError):
            # ожидание урезано сроком — «не уложились» (или «встало», если молчало долго — см. at_deadline)
            return at_deadline() if time.time() >= t_end - 0.05 else (got, "timeout")
        except (http.client.HTTPException, OSError):
            return got, "closed"
    return (got, "ok") if got >= need else (got, "small")


CERT_BAD = ("name", "chain", "expired")   # сертификат не тот: другое имя, не заверен, просрочен
CERT_CAFILE = None                         # свои корневые сертификаты вместо системных (тесты)


def _der_len(der, pos):
    """Длина DER по позиции pos: (длина, где начинается значение)."""
    n = der[pos]
    if n < 0x80:
        return n, pos + 1
    k = n & 0x7F
    return int.from_bytes(der[pos + 1:pos + 1 + k], "big"), pos + 1 + k


def cert_cn(der):
    """На чьё имя сертификат (DER, без проверки): первое имя из SAN, нет SAN — последнее CN (первое — издателя).
    Только для текста сообщения; None — не нашлось."""
    try:
        pos = der.index(b"\x06\x03\x55\x1d\x11") + 5   # subjectAltName
        if der[pos] == 0x01:                            # отметка «критичное»
            pos += 3
        if der[pos] == 0x04:
            _, pos = _der_len(der, pos + 1)
            if der[pos] == 0x30:
                size, pos = _der_len(der, pos + 1)
                end = pos + size
                while pos < end:
                    tag = der[pos]
                    n, pos = _der_len(der, pos + 1)
                    if tag == 0x82:                     # dNSName
                        return der[pos:pos + n].decode("ascii", "replace")
                    pos += n
    except (ValueError, IndexError, TypeError):
        pass
    oid, found, pos = b"\x06\x03\x55\x04\x03", None, 0
    try:
        while True:
            pos = der.index(oid, pos) + len(oid)
            tag, n = der[pos], der[pos + 1]
            if tag in (0x0C, 0x13, 0x16, 0x14) and n < 0x80:  # UTF8String, PrintableString, IA5String, T61String
                found = der[pos + 2:pos + 2 + n].decode("utf-8", "replace")
    except (ValueError, IndexError, TypeError):
        pass
    return found


def _cert_verdict(e):
    code = getattr(e, "verify_code", None)
    return "name" if code == 62 else "expired" if code == 10 else "chain"  # 62 — HOSTNAME_MISMATCH


def cert_check(addr, port, name, timeout=6, budget=None):
    """Рукопожатие TLS с проверкой цепочки и имени name: 'ok' | 'name' (выдан на другое имя) | 'expired' |
    'chain' (не заверен доверенным центром) | None — второе соединение не вышло или не уложилось, судить не о чем.
    budget — не дольше стольких секунд всего (соединение и рукопожатие вместе, строго: сервер, присылающий
    рукопожатие по байту, срок не растянет); без него — как раньше: соединение до 5 с, рукопожатие до timeout."""
    end = time.time() + budget if budget is not None else None
    try:
        sock = socket.create_connection((addr, port), timeout=5 if end is None else max(0.1, min(5, budget)))
    except OSError:
        return None
    try:
        ctx = ssl.create_default_context(cafile=CERT_CAFILE)
        if end is None:
            sock.settimeout(timeout)
            try:
                sock = ctx.wrap_socket(sock, server_hostname=name)
                return "ok"
            except ssl.SSLCertVerificationError as e:
                return _cert_verdict(e)
            except (ssl.SSLError, OSError, ValueError):
                return None
        sock.setblocking(False)
        try:
            sock = ctx.wrap_socket(sock, server_hostname=name, do_handshake_on_connect=False)
        except (ssl.SSLError, OSError, ValueError):
            return None
        while True:
            try:
                sock.do_handshake()
                return "ok"
            except ssl.SSLWantReadError:
                want = ([sock], [])
            except ssl.SSLWantWriteError:
                want = ([], [sock])
            except ssl.SSLCertVerificationError as e:
                return _cert_verdict(e)
            except (ssl.SSLError, OSError, ValueError):
                return None
            left = end - time.time()
            if left <= 0:
                return None  # не уложились в бюджет — не судим
            try:
                ready = select.select(want[0], want[1], [], left)
            except (OSError, ValueError):
                return None
            if not (ready[0] or ready[1]):
                return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def direct_probe(host, port=443, sni=None, need=NEED, tls=True, deadline=12, verify=False):
    """Прямая проверка host:port: адрес, порт, TLS с именем sni, объём по одному соединению.
    {"addr", "tcp": open|refused|timeout|error|dns, "tcp_ms", "tls": True|False|None, "bytes", "need", "end"}.
    verify — после проверки ещё рукопожатие со сверкой сертификата (для каналов с обычным TLS, не Reality):
    "cert": ok|name|chain|expired|None (см. cert_check), "cert_cn" — на чьё имя сертификат, который отдали."""
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
            if verify:
                try:
                    res["cert_cn"] = cert_cn(sock.getpeercert(binary_form=True) or b"")
                except (ssl.SSLError, OSError, ValueError):
                    res["cert_cn"] = None
        res["bytes"], res["end"] = pull(sock, sni or host, need, deadline)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if verify and res["tls"]:
        # отдельным соединением и после замера объёма: сверка не мешает пробе, а чужой сертификат отличим от «нет связи».
        # Бюджет — не больше CERT_BUDGET и только остаток худшего случая пробы без сверки (соединение 5 + TLS 6 +
        # pull deadline): с verify /probe точки не дольше, чем без него, и укладывается в ожидание blockwatch (25 с).
        # Не осталось и секунды (медленный путь съел всё) — сверку пропускаем: None, «не судим».
        left = min(CERT_BUDGET, t0 + 5 + 6 + deadline - time.time())
        res["cert"] = cert_check(res["addr"], port, sni or host, budget=left) if left >= 1 else None
    return res


# ---------- серия соединений и сравнение имён ----------

MSS_DEFAULT = (1201, 1260)  # прежний диапазон меток (он открыт в исходниках — поэтому его можно сменить настройкой)
MSS_WIDTH = 59              # не уже прежнего: метки точек — начало + 2 * № точки, приветствие TLS — ещё + 30
SITE_JSON = "/etc/channel-watch/site.json"  # настройки сторожа: {"mss_mark": [начало, конец]}
# Сменить диапазон на всех: 1) ноды — /etc/node-witness/site.json {"mss_mark": [[1201, 1260], [НОВ, НОВ+59]]}
# (старый и новый сразу), restart node-witness; 2) точки — "mss_mark": [НОВ, НОВ+59] в agent.json, restart
# vantage-agent; сторож — то же в /etc/channel-watch/site.json (читается при каждом запуске probe.py);
# 3) ноды — оставить только новый. Шаг 2 — одним заходом: пока диапазоны сторожа и точки расходятся, точка
# прижимает чужую метку к краю своего диапазона, и серии разных точек на свидетеле могут смешаться.


def mss_range(value, default=MSS_DEFAULT):
    """Диапазон меток из настроек: [начало, конец] — целые, 536 ≤ начало, конец ≤ 1460, ширина от MSS_WIDTH до 200.
    Что-то не так — default (прежний диапазон): сторож работает, как раньше."""
    try:
        lo, hi = value
        if isinstance(lo, bool) or isinstance(hi, bool) or not isinstance(lo, int) or not isinstance(hi, int):
            return default
    except (TypeError, ValueError):
        return default
    if 536 <= lo and hi <= 1460 and MSS_WIDTH <= hi - lo <= 200:
        return lo, hi
    return default


def load_mss_mark(path=SITE_JSON):
    """Диапазон меток из файла настроек (ключ "mss_mark"); файла нет, не читается или ключа нет — прежний."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return MSS_DEFAULT
    return mss_range(data.get("mss_mark")) if isinstance(data, dict) else MSS_DEFAULT


def set_mss_mark(value):
    """Сменить диапазон меток на ходу (агент точки берёт его из своих настроек): итоговый диапазон."""
    global MSS_MARK
    MSS_MARK = mss_range(value, MSS_MARK)
    return MSS_MARK


MSS_MARK = load_mss_mark()  # метка серии: SYN с таким MSS узнаёт помощник на ноде (node_witness.py)
SERIES_MAX = 40
SERIES_GIVEUP = 6         # не прошло ни одно из стольких первых — серию бросаем
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
        if i >= SERIES_GIVEUP and res["ok"] == 0:
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


NEIGHBOUR_LAST = (1, 10, 50, 100, 150, 200, 250)   # какие адреса той же /24 пробуем (плюс соседние ±1)


def _tcp_ok(ip, port, timeout):
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def neighbours(addr, ports=(443, 80), timeout=2, conn=None):
    """Отвечают ли отсюда соседи ноды по подсети /24 (порт 443 или 80): {"checked", "open": [адреса]};
    None — адрес частный или не адрес. Открытые соседи при молчащей ноде — признак, что закрыт именно её адрес."""
    import ipaddress
    try:
        a = ipaddress.ip_address(str(addr))
    except ValueError:
        return None
    if a.version != 4 or a.is_private or a.is_loopback:
        return None
    base, last = int(a) & ~0xFF, int(a) & 0xFF
    picks = sorted({x for x in NEIGHBOUR_LAST + (last - 1, last + 1) if 0 < x < 255 and x != last})
    ips = [str(ipaddress.ip_address(base + x)) for x in picks]
    conn = conn or _tcp_ok

    def one(ip):
        return ip if any(conn(ip, p, timeout) for p in ports) else None
    threads = []
    res = {}
    for ip in ips:
        th = threading.Thread(target=lambda ip=ip: res.__setitem__(ip, one(ip)), daemon=True)
        th.start()
        threads.append(th)
    for th in threads:
        th.join(timeout * len(ports) + 2)
    out = sorted(ip for ip in ips if res.get(ip))
    return {"checked": len(ips), "open": out}


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


# ---------- локальный SOCKS сторожа (клиент Xray из build_channels.py) ----------

SOCKS_AUTH_FILE = "/etc/channel-watch/socks.auth"  # {"user", "pass"}, 600; нет файла — Xray ещё без пароля
SOCKS_PORTS = range(21000, 21100)                  # порты каналов; логин и пароль шлём только на них


def socks_auth():
    """(логин, пароль) локального SOCKS или None. Сначала $CREDENTIALS_DIRECTORY/socks.auth (LoadCredential: агент
    VPN-точки работает не от root), потом /etc/channel-watch/socks.auth. Нет файла — None: ходим без пароля, как
    раньше (старый xray.json без пароля или файл ещё не создан)."""
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    for path in ([os.path.join(d, "socks.auth")] if d else []) + [SOCKS_AUTH_FILE]:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            user, pw = data["user"], data["pass"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if isinstance(user, str) and isinstance(pw, str) and 0 < len(user) < 256 and 0 < len(pw) < 256:
            return user, pw
    return None


def _local_port(port):
    try:
        return int(port) in SOCKS_PORTS
    except (TypeError, ValueError):
        return False


def curl_quote(value):
    """Строка для конфига curl (-K): в кавычках, с экранированием, без переводов строки."""
    value = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def curl_socks_cfg(port):
    """Строки конфига curl (-K -) с логином и паролем для SOCKS 127.0.0.1:port; '' — пароля нет (или порт не наш).
    Логин и пароль — только через stdin: аргументы процесса видны всем пользователям сервера (ps, /proc/*/cmdline)."""
    auth = socks_auth() if _local_port(port) else None
    return f"proxy-user = {curl_quote(auth[0] + ':' + auth[1])}\n" if auth else ""


def curl_socks(port):
    """Для curl через SOCKS 127.0.0.1:port: (аргументы, текст для stdin). Без пароля — (['-x', …], ''),
    с паролем — ещё '-K -', а логин и пароль в тексте для stdin."""
    args = ["-x", f"socks5h://127.0.0.1:{int(port)}"]
    cfg = curl_socks_cfg(port)
    return (args + ["-K", "-"], cfg) if cfg else (args, "")


def curl_proxy_cfg(proxy):
    """То же для адреса прокси строкой (socks5h://127.0.0.1:PORT): строки конфига curl или ''."""
    if not proxy:
        return ""
    p = urllib.parse.urlsplit(str(proxy))
    try:
        port = p.port
    except ValueError:
        return ""
    if p.scheme in ("socks5", "socks5h") and p.hostname == "127.0.0.1" and port:
        return curl_socks_cfg(port)
    return ""


def socks_connect(socks_port, host, port, timeout, auth=None):
    """TCP до host:port через локальный SOCKS 127.0.0.1:socks_port (SOCKS5, имя отдаём прокси). Пароль из socks.auth
    (или auth): предлагаем оба способа — «без пароля» и «логин/пароль», выбирает сервер (старый Xray без пароля
    выберет первый). Сокет либо None — канал не принял."""
    if auth is None and _local_port(socks_port):
        auth = socks_auth()
    try:
        s = socket.create_connection(("127.0.0.1", int(socks_port)), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
        method = _recv_exact(s, 2)
        if not method or method[0] != 5:
            raise OSError("не SOCKS5")
        if method[1] == 2 and auth:
            user, pw = auth[0].encode(), auth[1].encode()
            s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            if _recv_exact(s, 2) != b"\x01\x00":
                raise OSError("логин или пароль не приняты")
        elif method[1] != 0:
            raise OSError("способ входа не подошёл")
        name = host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", int(port)))
        reply = _recv_exact(s, 4)
        if not reply or reply[1] != 0:
            raise OSError("прокси не соединил")
        tail = {1: 4, 4: 16}.get(reply[3])
        if tail is None and reply[3] == 3:
            ln = _recv_exact(s, 1)
            tail = ln[0] if ln else None
        if tail is None or _recv_exact(s, tail + 2) is None:
            raise OSError("ответ прокси не разобрать")
        return s
    except (OSError, UnicodeError, ValueError):
        s.close()
        return None


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def socks_load(port, url=VPN_URL, need=VPN_NEED, timeout=25):
    """Загрузка url через SOCKS 127.0.0.1:port (свой клиент Xray): {"ok", "code", "bytes", "mbit", "s", "ttfb_ms", "rc"}."""
    proxy, cfg = curl_socks(port)
    cmd = ["curl", "-s", "-m", str(timeout), *proxy, "-o", os.devnull,
           "-w", "%{http_code} %{size_download} %{speed_download} %{time_total} %{time_starttransfer}", url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5,
                           **({"input": cfg} if cfg else {}))  # stdin — только когда есть пароль
        code, size, speed, total, ttfb = r.stdout.split()
        size = int(float(size))
        return {"ok": code == "200" and size >= need, "code": code, "bytes": size, "mbit": round(float(speed) * 8 / 1e6, 1),
                "s": round(float(total), 2), "ttfb_ms": int(float(ttfb) * 1000), "rc": r.returncode}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"ok": False, "code": None, "bytes": 0, "mbit": None, "s": None, "ttfb_ms": None, "rc": None}


def probe_class(r):
    """Итог прямой проверки одним словом: ok | cert (TLS отвечает, но сертификат не тот) | stall (встало, не набрав
    объём) | tls | tcp | dns | none (не проверялось). «cert» — только если проба шла со сверкой (verify)."""
    if not r:
        return "none"
    if r["tcp"] == "dns":
        return "dns"
    if r["tcp"] != "open":
        return "tcp"
    if r["tls"] is False:
        return "tls"
    if r.get("cert") in CERT_BAD:
        return "cert"
    if r["end"] == "timeout" and (r["bytes"] or 0) < r["need"]:
        return "stall"
    return "ok"


# ---------- трассировка TCP ----------

def parse_trace(out, addr):
    """Вывод traceroute -n -q 1: {"reached": дошли ли до addr, "hops": сколько шагов прошли, "last": (шаг, адрес),
    "seen": [[шаг, адрес], ...] — все ответившие шаги}."""
    last, hops, seen = None, 0, []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 2 or not p[0].isdigit():
            continue
        hops = int(p[0])
        if p[1] != "*":
            last = (hops, p[1])
            seen.append([hops, p[1]])
            if p[1] == addr:
                return {"reached": True, "hops": hops, "last": last, "seen": seen}
    return {"reached": False, "hops": hops, "last": last, "seen": seen}


def own_addr():
    """Внешний адрес этого сервера по маршруту наружу (src); None — не узнали или адрес частный (за NAT)."""
    import ipaddress
    try:
        out = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout
        a = out.split(" src ", 1)[1].split()[0]
        return a if not ipaddress.ip_address(a).is_private else None
    except (IndexError, ValueError, OSError, subprocess.TimeoutExpired):
        return None


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
