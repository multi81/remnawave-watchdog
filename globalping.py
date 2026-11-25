"""channel-watch: взгляд из домашних сетей России через Globalping (api.globalping.io).

Все наши российские точки стоят в дата-центрах. Когда вход ноды с них не открывается, сторож спрашивает Globalping:
открывается ли тот же АДРЕС и порт (TCP, как «ping по TCP» — только рукопожатие) у его добровольных точек в сетях
обычных провайдеров России (МТС, Билайн, Ростелеком, Дом.ру…), и для сверки — с двух точек в Европе (DE, NL).
Так видно: закрыто по всей России, у части провайдеров или только для дата-центров.

Что уходит наружу: только адрес (IP) и порт входа. Имя ноды, домены, пользователи — никогда. Результаты Globalping
открыты всем, у кого есть номер замера, и хранятся до полугода; адрес, отправленный сюда, считаем опубликованным.

Бережность: результат по адресу живёт CACHE_TTL (повторно не спрашиваем), часовой запас проверок HOUR_BUDGET (сильно
меньше бесплатных 250 в час), ответ 429 — пауза до сброса, сбой сети — None и короткая пауза. Ключ (необязательный) —
/etc/channel-watch/globalping.token (600), уходит только заголовком Authorization к /measurements и нигде не печатается.
Разбор сбоя идёт в нескольких потоках (и probe.py с --blocks могут совпасть): память читается и пишется под замком,
проверки бронируются до обращения, один и тот же адрес из двух потоков спрашивается один раз.
Только стандартная библиотека.
"""
import contextlib
import gzip
import io
import ipaddress
import json
import os
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

try:
    import fcntl   # замок между процессами (на rf1 есть всегда; без него — только между потоками)
except ImportError:
    fcntl = None

# Метка для build_channels.py --socks-auth: через SOCKS этот модуль не ходит вовсе (прокси отключён явно, см. _OPENER),
# пароль к SOCKS ему не нужен, включение пароля его не ломает.
SOCKS_AUTH_READY = True

API = "https://api.globalping.io/v1"
STATE = "/var/lib/channel-watch/globalping.json"
TOKEN_FILE = "/etc/channel-watch/globalping.token"
UA = "channel-watch/1.0"       # без имён и адресов: так просят представляться клиентов
RU_PROBES = 8                  # точек в домашних сетях России на один замер
CONTROL = ("DE", "NL")         # по одной точке в дата-центре этих стран — жив ли адрес вообще
PACKETS = 3                    # соединений с каждой точки
DEADLINE = 40                  # секунд от создания замеров до последнего опроса: точка ждёт ответа до 30 с, плюс запас
PROBES_TIMEOUT = 5             # секунд на список точек (/probes); не пришёл — общий запрос по стране
CREATE_MIN_LEFT = 5            # меньше осталось до срока — новый замер не создаём
EXTRA_MIN_LEFT = 10            # запасной общий запрос и сверку из Европы — только если осталось столько
CONTROL_GRACE = 4              # сверку из Европы опрашиваем хотя бы раз, даже если российский замер съел срок
WALL = PROBES_TIMEOUT + DEADLINE + CONTROL_GRACE + 4   # дольше этого check не идёт (и соседний поток не ждёт)
HTTP_TIMEOUT = 8               # секунд на один запрос к API (и не дальше общего срока)
POLL_GAP = 1.0                 # секунд между опросами замера (API просит не чаще раза в 0,5 с)
CACHE_TTL = 20 * 60            # результат по адресу моложе — берём из памяти, наружу не ходим
SHORT_TTL = 3 * 60             # неполный результат (мало сетей, Европа молчит, замер не доехал) — помним недолго
HOUR_BUDGET = 120              # проверок (точка × замер) в час без ключа; бесплатно 250 в час на адрес сторожа
HOUR_BUDGET_TOKEN = 300        # с ключом (бесплатно 500 в час)
ERR_PAUSE = 300                # после сбоя сети или непонятного ответа — столько не спрашиваем
LIMIT_PAUSE = 600              # ответ 429 без срока — пауза по умолчанию
LIMIT_PAUSE_MAX = 3600
PROBES_TTL = 600               # список точек Globalping (бесплатный запрос) обновляем не чаще
MAX_BODY = 8_000_000           # байт ответа API, больше не читаем
CHUNK = 65536                  # читаем ответ кусками, чтобы срок проверялся и при медленной отдаче
CLOCK_SLACK = 60               # запись «из будущего» дальше этого (часы шагнули назад) — выбрасываем

# настоящие провайдеры доступа в интернет: номер сети (ASN) -> как называть в сообщении
# (сети без имени здесь называются так, как их называет сам Globalping — поле network)
ISP_NAMES = {8359: "МТС", 12389: "Ростелеком", 3216: "Билайн", 8402: "Билайн", 25513: "МГТС",
             51570: "Дом.ру", 41733: "Дом.ру", 39435: "Дом.ру", 42116: "Дом.ру", 52207: "Дом.ру",
             24955: "Уфанет", 8595: "WestCall", 31133: "Мегафон"}
# хостеры, которые Globalping ошибочно считает домашними сетями: их точки в выборку и в вывод не берём
# (номера сетей хостинг-провайдеров, замеченных среди точек Globalping)
HOSTERS = {16262, 9123, 207957, 48282, 216334, 49505, 197695}


# ---------- память: кэш, запас проверок, паузы ----------

_lock = threading.Lock()          # потоки одного процесса
_inflight = {}                    # адрес:порт -> {"ev", "res"}: этот адрес уже спрашивает соседний поток
_inflight_lock = threading.Lock()


@contextlib.contextmanager
def locked(path=None):
    """Замок на память: между потоками — threading.Lock, между процессами — flock на файле рядом.
    Под замком только чтение и запись файла, без обращений к сети."""
    path = path or STATE
    with _lock:
        fd = None
        if fcntl is not None:
            try:
                fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                if fd is not None:
                    os.close(fd)
                fd = None
        try:
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) < 1e12


def clean_state(st, now):
    """Память после чтения: каждое поле проверяется отдельно (испорченное — по умолчанию, остальное живёт),
    записи «из будущего» (часы сдвинули назад) выбрасываются, паузы — не дольше предела."""
    out = {}
    if not isinstance(st, dict):
        return out
    sp = st.get("spent")
    if isinstance(sp, list):
        out["spent"] = [[x[0], x[1]] for x in sp if isinstance(x, list) and len(x) == 2 and _num(x[0]) and _num(x[1])
                        and now - 3600 < x[0] <= now + CLOCK_SLACK]
    if _num(st.get("until")) and st["until"] > now:
        out["until"] = min(st["until"], now + LIMIT_PAUSE_MAX)
        out["until_why"] = st.get("until_why") if st.get("until_why") in ("limit", "error") else "limit"
    al = st.get("api_left")
    if isinstance(al, dict) and _num(al.get("remaining")) and _num(al.get("until")) and al["until"] > now:
        out["api_left"] = {"remaining": al["remaining"], "until": min(al["until"], now + 3600)}
    cache = st.get("cache")
    if isinstance(cache, dict):
        out["cache"] = {k: v for k, v in cache.items() if isinstance(k, str) and isinstance(v, dict)
                        and _num(v.get("ts")) and now - 24 * 3600 < v["ts"] <= now + CLOCK_SLACK
                        and isinstance(v.get("res"), dict)}
    pr = st.get("probes")
    if isinstance(pr, dict) and _num(pr.get("ts")) and pr["ts"] <= now + CLOCK_SLACK and isinstance(pr.get("list"), list):
        out["probes"] = {"ts": pr["ts"], "list": [p for p in pr["list"] if isinstance(p, dict)]}
    return out


def load_state(path=None, now=None):
    try:
        with open(path or STATE, encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        return {}
    return clean_state(st, time.time() if now is None else now)


def save_state(st, path=None):
    """Записать память: свой временный файл у каждого потока и процесса, права 600 (там адреса входов нод)."""
    path = path or STATE
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def spent_last_hour(st, now):
    """Сколько проверок потрачено за последний час (по своей записи; поправки после брони бывают и меньше нуля)."""
    return sum(n for ts, n in st.get("spent", []) if now - ts < 3600)


def note_spent(st, now, n):
    st["spent"] = [[ts, k] for ts, k in st.get("spent", []) if now - ts < 3600] + [[now, n]]


def budget_wait(st, now, need, budget):
    """Хватает ли запаса на need проверок: None — хватает; иначе время, когда освободится достаточно
    (по самым старым записям часа и по сроку сброса у API)."""
    at = None
    used = spent_last_hour(st, now)
    if used + need > budget:
        at = now + 3600
        for ts, n in sorted(x for x in st.get("spent", []) if now - x[0] < 3600):
            used -= n
            if used + need <= budget:
                at = ts + 3600
                break
    al = st.get("api_left") or {}
    if now < al.get("until", 0) and al.get("remaining", need) < need:
        at = max(at or 0, al["until"])
    return at


def pause(st, now, seconds, why):
    """Не ходить в API seconds секунд (why — для сообщения: limit | error)."""
    st["until"] = now + max(1, min(int(seconds), LIMIT_PAUSE_MAX))
    st["until_why"] = why


def cached(st, key, now):
    rec = (st.get("cache") or {}).get(key)
    if not isinstance(rec, dict) or not isinstance(rec.get("res"), dict) or not _num(rec.get("ts")):
        return None
    ttl = min(rec.get("ttl", CACHE_TTL), CACHE_TTL) if _num(rec.get("ttl")) else CACHE_TTL
    if -CLOCK_SLACK <= now - rec["ts"] < ttl:   # чуть «из будущего» — соседний поток начал на миг позже
        return dict(rec["res"], cached=True, age=max(0, int(now - rec["ts"])))
    return None


def remember(st, key, now, res, ttl=CACHE_TTL):
    cache = {k: v for k, v in (st.get("cache") or {}).items()
             if isinstance(v, dict) and _num(v.get("ts")) and -CLOCK_SLACK <= now - v["ts"] < 24 * 3600}
    cache[key] = {"ts": now, "ttl": ttl, "res": res}
    st["cache"] = cache


def read_token(path=None):
    """Ключ Globalping из файла или None. Содержимое никуда, кроме заголовка, не идёт."""
    try:
        with open(path or TOKEN_FILE, encoding="utf-8") as f:
            tok = f.read().strip()
    except (OSError, ValueError):   # нет файла, нет прав, не UTF-8
        return None
    return tok if tok and len(tok) < 200 and all(33 <= ord(c) < 127 for c in tok) else None


def public_ip(addr):
    """Адрес годится к отправке: настоящий IP (не имя) и не частный/служебный."""
    try:
        a = ipaddress.ip_address(str(addr))
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
                or a.is_unspecified)


# ---------- обращения к API ----------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Переадресацию не выполняем: urllib понёс бы заголовок Authorization на чужой хост (и с https на http).
    Ответ 3xx остаётся ответом с этим кодом — для нас это сбой."""

    def redirect_request(self, *a, **k):
        return None


# прокси из окружения (https_proxy и т. п.) не берём: к Globalping — только напрямую с rf1
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _read(r, limit, deadline, clock):
    """Тело ответа кусками, не больше limit байт и не дольше deadline (медленная отдача не держит поток)."""
    read1 = getattr(r, "read1", None) or r.read
    out = bytearray()
    while len(out) < limit:
        if deadline is not None and clock() > deadline:
            raise TimeoutError("срок вышел")
        part = read1(min(CHUNK, limit - len(out)))
        if not part:
            break
        out += part
    return bytes(out)


def http(method, url, body=None, token=None, timeout=HTTP_TIMEOUT, deadline=None, clock=time.monotonic):
    """Один запрос к API -> (код, заголовки в нижнем регистре, разобранный JSON или None); сбой сети или срок — None.
    deadline (по clock) ограничивает весь запрос вместе с чтением ответа."""
    if deadline is not None:
        left = deadline - clock()
        if left <= 0.2:
            return None
        timeout = min(timeout, left)
    headers = {"User-Agent": UA, "Accept": "application/json", "Accept-Encoding": "gzip"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            if not str(r.geturl()).startswith(API + "/"):
                return None   # ответил не наш адрес API
            # список всех точек (/probes) без сжатия — пара мегабайт; больше не берём
            return r.status, _headers(r.headers), _json(_read(r, MAX_BODY, deadline, clock), r.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = _read(e, 200_000, deadline, clock)
        except (OSError, ValueError, AttributeError):
            raw = b""
        return e.code, _headers(e.headers), _json(raw, e.headers)
    except (OSError, ValueError):   # нет сети, таймаут, TLS, кривой адрес, срок вышел
        return None


def _headers(h):
    return {k.lower(): v for k, v in (h.items() if h else [])}


def _json(raw, h):
    try:
        if h and "gzip" in str(h.get("Content-Encoding", "")).lower():
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:   # с пределом: распакованное — не больше 4 × MAX_BODY
                raw = g.read(4 * MAX_BODY)
        return json.loads(raw.decode("utf-8")) if raw else None
    except (OSError, ValueError, EOFError):
        return None


def _int(v, default=None):
    try:
        return int(float(v))
    except (TypeError, ValueError, OverflowError):
        return default


def _text(v, n):
    """Строка из ответа API (имя сети, город) для сообщения: без переводов строк, управляющих и «невидимых»
    символов (U+202E и т. п. переставляют текст), пробелы схлопнуты, не длиннее n."""
    s = "".join(c if c.isprintable() and unicodedata.category(c) != "Cf" else " " for c in str(v or ""))
    return " ".join(s.split())[:n]


# ---------- выбор точек ----------

def residential(probe):
    """Точка в домашней сети России: страна RU, метка eyeball-network, сеть не из списка хостеров."""
    return (probe.get("country") == "RU" and "eyeball-network" in (probe.get("tags") or [])
            and _int(probe.get("asn")) not in HOSTERS)


def ru_locations(probes, n=RU_PROBES):
    """Из списка точек (/v1/probes) — места для замера: по ASN, сначала известные провайдеры, разные сети по кругу.
    Пусто — список не пришёл или в нём нет домашних точек (тогда — общий запрос по стране)."""
    per = {}
    for p in probes or []:
        loc = p.get("location") or p
        if isinstance(loc, dict) and residential({**loc, "tags": p.get("tags") or loc.get("tags")}):
            asn = _int(loc.get("asn"))
            if asn:
                per[asn] = per.get(asn, 0) + 1
    order = sorted(per, key=lambda a: (a not in ISP_NAMES, -per[a], a))
    take = {}
    while sum(take.values()) < n and any(take.get(a, 0) < per[a] for a in order):
        for a in order:
            if sum(take.values()) < n and take.get(a, 0) < per[a]:
                take[a] = take.get(a, 0) + 1
    return [{"country": "RU", "asn": a, "tags": ["eyeball-network"], "limit": k} for a, k in take.items()]


def fallback_locations(n=RU_PROBES):
    return [{"country": "RU", "tags": ["eyeball-network"], "limit": n}]


def control_locations():
    return [{"country": c, "tags": ["datacenter-network"], "limit": 1} for c in CONTROL]


def get_probes(pc, now, clock=time.monotonic):
    """Список точек онлайн (бесплатно, без предела, без ключа) -> (список | None, что запомнить | None).
    pc — запомненный список; моложе PROBES_TTL — берём его. На запрос — свой короткий срок PROBES_TIMEOUT."""
    pc = pc or {}
    if 0 <= now - pc.get("ts", 0) < PROBES_TTL and isinstance(pc.get("list"), list):
        return pc["list"], None
    r = http("GET", API + "/probes", timeout=PROBES_TIMEOUT, deadline=clock() + PROBES_TIMEOUT, clock=clock)
    if not r or r[0] != 200 or not isinstance(r[2], list):
        return None, None
    slim = [{"location": {k: (p.get("location") or {}).get(k) for k in ("country", "asn", "network", "city")},
             "tags": p.get("tags") or []} for p in r[2] if isinstance(p, dict)
            and isinstance(p.get("location"), dict) and p["location"].get("country") == "RU"]
    return slim, {"ts": now, "list": slim}


def body(addr, port, locations):
    """Тело замера: ping по TCP на адрес и порт. Только IP — имя сюда не попадает никогда."""
    return {"type": "ping", "target": str(addr), "locations": locations,
            "measurementOptions": {"protocol": "TCP", "port": int(port), "packets": PACKETS}}


# ---------- замер ----------

def _mid(v):
    """Номер замера от API: короткий, только латиница и цифры; иное — не номер."""
    return v if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9]{4,64}", v) else None


def create(b, token, deadline=None, clock=time.monotonic):
    """Создать замер -> ("ok", id, заголовки) | ("limit", пауза в секундах, заголовки) | ("noprobes", ...) |
    ("error", None, {})."""
    if deadline is not None and deadline - clock() < CREATE_MIN_LEFT:
        return "error", None, {}
    r = http("POST", API + "/measurements", b, token, deadline=deadline, clock=clock)
    if not r:
        return "error", None, {}
    code, hdr, data = r
    if code in (200, 202) and isinstance(data, dict) and _mid(data.get("id")):
        return "ok", data["id"], hdr
    err = ((data or {}).get("error") or {}).get("type") if isinstance(data, dict) else None
    if code == 429:
        return "limit", _int(hdr.get("retry-after")) or _int(hdr.get("x-ratelimit-reset")) or LIMIT_PAUSE, hdr
    if code == 422 and err == "no_probes_found":
        return "noprobes", None, hdr
    return "error", None, hdr


def poll(mid, token, deadline, sleep=time.sleep, clock=time.monotonic):
    """Ждать окончания замера до deadline (по clock) -> ответ замера; к сроку не закончился — последний полученный
    ответ (status «in-progress», готовые точки в нём уже есть) либо None, если ответа не было ни одного.
    Номер замера подставляем в свой адрес API (заголовку Location не доверяем); 429 — ждём Retry-After, если укладываемся."""
    url = API + "/measurements/" + urllib.parse.quote(mid, safe="")
    last = None
    while True:
        if deadline - clock() <= POLL_GAP:
            return last
        sleep(POLL_GAP)
        r = http("GET", url, token=token, deadline=deadline, clock=clock)
        if not r:
            return last
        code, hdr, data = r
        if code == 429:
            wait = _int(hdr.get("retry-after"), 2)
            if clock() + wait >= deadline:
                return last
            sleep(max(0, wait - POLL_GAP))
            continue
        if code != 200 or not isinstance(data, dict):
            return last
        if data.get("status") != "in-progress":
            return data
        last = data


def probe_state(item):
    """Одна точка замера -> ok (хоть одно соединение прошло) | fail (ни одного) | nodata (точка не смогла).
    Сначала по счётчикам: соединения пробовались и ни одно не прошло — fail, какой бы ни был статус (полностью
    закрытую цель Globalping может пометить «failed»). Статус failed с причиной target — тоже fail. Точка ещё
    работает, offline, сбой у неё самой (resolver, internal), нет счётчиков — nodata."""
    res = item.get("result") if isinstance(item, dict) else None
    if not isinstance(res, dict):
        return "nodata"
    status, src = res.get("status"), res.get("failureSource")
    if status in ("in-progress", "offline") or src in ("resolver", "internal"):
        return "nodata"
    stats = res.get("stats") if isinstance(res.get("stats"), dict) else {}
    total, rcv = _int(stats.get("total")), _int(stats.get("rcv"))
    if total and total > 0 and rcv is not None:
        return "ok" if rcv > 0 else "fail"
    if status == "failed" and src == "target":
        return "fail"
    return "nodata"


def isp_name(probe):
    asn = _int(probe.get("asn"))
    if asn in ISP_NAMES:
        return ISP_NAMES[asn]
    net = _text(probe.get("network"), 24)
    return (net if net else f"AS{asn}") if asn or net else "?"


def rows(data, keep=None):
    """Ответ замера -> [{"isp", "asn", "city", "country", "state", "rtt"}]; keep — какие точки брать."""
    out = []
    results = data.get("results") if isinstance(data, dict) else None
    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue
        probe = item.get("probe") if isinstance(item.get("probe"), dict) else {}
        if keep and not keep(probe):
            continue
        res = item.get("result") if isinstance(item.get("result"), dict) else {}
        stats = res.get("stats") if isinstance(res.get("stats"), dict) else {}
        avg = stats.get("avg")
        out.append({"isp": isp_name(probe), "asn": _int(probe.get("asn")), "city": _text(probe.get("city"), 40),
                    "country": _text(probe.get("country"), 4) or None, "state": probe_state(item),
                    "rtt": round(avg) if _num(avg) else None})
    return out


def summary(ru, ctrl):
    """Итог: сколько домашних точек открыли адрес, какие провайдеры, что видно из Европы.
    verdict: open (открыто; у провайдеров с отказом есть и успехи — неустойчивая точка, не блокировка)
    | closed (ни у кого, и сетей с отказом не меньше двух) | mixed (у кого-то открыто, а у какого-то провайдера
    закрыто на всех его точках) | few (мало данных: для open и mixed нужно две сети или три ответа) | nodata.
    control: up | down | None (нет данных)."""
    ok = [r for r in ru if r["state"] == "ok"]
    bad = [r for r in ru if r["state"] == "fail"]
    isps = {}
    for r in ok + bad:
        s = isps.setdefault(r["isp"], {"ok": 0, "fail": 0})
        s[r["state"]] += 1
    asns = {r["asn"] for r in ok + bad if r.get("asn") is not None}
    blocked = [k for k, v in isps.items() if v["fail"] and not v["ok"]]
    if not ok and not bad:
        verdict = "nodata"
    elif not ok:
        verdict = "closed" if len({r["asn"] for r in bad if r.get("asn") is not None}) >= 2 else "few"
    elif len(asns) < 2 and len(ok) + len(bad) < 3:
        verdict = "few"
    else:
        verdict = "mixed" if blocked else "open"
    c_ok = sum(r["state"] == "ok" for r in ctrl)
    c_bad = sum(r["state"] == "fail" for r in ctrl)
    control = "up" if c_ok else "down" if c_bad else None
    return {"ru_ok": len(ok), "ru_fail": len(bad), "ru_nodata": len(ru) - len(ok) - len(bad), "isps": isps,
            "verdict": verdict, "control": control}


def measure(addr, port, ru_locs, token, sleep=time.sleep, clock=time.monotonic):
    """Два замера (домашние сети РФ и Европа) -> {"ru", "control", "spent", "hdr", "control_limit"} |
    {"limit": секунды} | None (сбой). Европа — отдельным замером, чтобы не смешивалась с российскими местами;
    оба создаются сразу, потом ждём. Срок DEADLINE считается от создания первого замера."""
    deadline = clock() + DEADLINE
    n = sum(x["limit"] for x in ru_locs)
    st_ru = create(body(addr, port, ru_locs), token, deadline, clock)
    if (st_ru[0] == "noprobes" and ru_locs != fallback_locations(n)    # точка из списка успела уйти — общий запрос
            and deadline - clock() >= EXTRA_MIN_LEFT):
        st_ru = create(body(addr, port, fallback_locations(n)), token, deadline, clock)
    if st_ru[0] == "limit":
        return {"limit": st_ru[1]}
    if st_ru[0] != "ok":
        return None
    spent = _int(st_ru[2].get("x-request-cost"), n)
    st_c = (create(body(addr, port, control_locations()), token, deadline, clock)
            if deadline - clock() >= EXTRA_MIN_LEFT else ("error", None, {}))
    if st_c[0] == "ok":
        spent += _int(st_c[2].get("x-request-cost"), len(CONTROL))
    ru = poll(st_ru[1], token, deadline, sleep, clock)
    # Европа шла одновременно с Россией и обычно уже готова: опросить хотя бы раз, даже если срок съеден
    ctrl = (poll(st_c[1], token, max(deadline, clock() + POLL_GAP + CONTROL_GRACE), sleep, clock)
            if st_c[0] == "ok" else None)
    # остаток у API — из более позднего ответа (сверка создавалась второй), если в нём он есть
    hdr = st_c[2] if "x-ratelimit-remaining" in st_c[2] else st_ru[2]
    return {"ru": ru, "control": ctrl, "spent": spent, "hdr": hdr,
            "control_limit": st_c[1] if st_c[0] == "limit" else None}


def check(addr, port=443, n=RU_PROBES, budget=None, state_path=None, token_path=None, now=None,
          sleep=time.sleep, clock=time.monotonic):
    """Открывается ли addr:port у абонентов домашних сетей России и из Европы.
    -> {"service", "addr", "port", "ru": [...], "control": [...], "summary": {...}, "ts"} (cached/age — из памяти,
       partial — замер к сроку закончился не у всех точек)
    | {"skipped": "budget"|"limit"|"error", "until"} — не спрашивали, чтобы не превысить пределы
    | None — адрес не годится, сбой сети или API ответил непонятно. Исключений наружу не бросает."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not public_ip(addr) or not 0 < port < 65536:
        return None
    try:
        return _check(addr, port, n, budget, state_path, token_path, now, sleep, clock)
    except Exception:  # noqa: BLE001 — внешний сервис не должен ронять разбор сбоя
        try:   # и не должен спрашивать снова на каждом разборе, если сломан стабильно
            t = time.time() if now is None else now
            with locked(state_path):
                st = load_state(state_path, t)
                pause(st, t, ERR_PAUSE, "error")
                save_state(st, state_path)
        except Exception:  # noqa: BLE001
            pass
        return None


def _check(addr, port, n, budget, state_path, token_path, now, sleep, clock):
    key = f"{addr}:{port}"
    with _inflight_lock:
        slot = _inflight.get(key)
        lead = slot is None
        if lead:
            slot = _inflight[key] = {"ev": threading.Event(), "res": None}
    if not lead:   # этот адрес уже спрашивает соседний поток (два канала на одном входе) — ждём его итог
        if not slot["ev"].wait(WALL):
            return None
        res = slot["res"]
        return dict(res) if isinstance(res, dict) else None
    try:
        slot["res"] = _lead(addr, port, key, n, budget, state_path, token_path, now, sleep, clock)
        return slot["res"]
    finally:
        with _inflight_lock:
            _inflight.pop(key, None)
        slot["ev"].set()


def _lead(addr, port, key, n, budget, state_path, token_path, now, sleep, clock):
    now = time.time() if now is None else now
    token = read_token(token_path)
    budget = budget or (HOUR_BUDGET_TOKEN if token else HOUR_BUDGET)
    need = n + len(CONTROL)
    with locked(state_path):
        st = load_state(state_path, now)
        hit = cached(st, key, now)
        if hit:
            return hit
        if "until" in st:
            return {"skipped": st["until_why"], "until": st["until"]}
        wait = budget_wait(st, now, need, budget)
        if wait:
            return {"skipped": "budget", "until": wait}
        note_spent(st, now, need)       # бронь до обращения: соседние потоки и процессы видят её сразу
        save_state(st, state_path)
        pc = st.get("probes")
    probes, new_pc = get_probes(pc, now, clock)
    locs = ru_locations(probes, n) or fallback_locations(n)
    try:
        got = measure(addr, port, locs, token, sleep, clock)
    except Exception:  # noqa: BLE001 — сколько ушло, неизвестно: бронь остаётся
        got = False
    with locked(state_path):
        st = load_state(state_path, now)   # перечитать: соседи могли записать своё, пока мы ждали API
        if new_pc:
            st["probes"] = new_pc
        try:
            res = _finish(st, key, now, got, need, addr, port)
        except Exception:  # noqa: BLE001 — API прислал что-то не то: пауза, бронь остаётся
            pause(st, now, ERR_PAUSE, "error")
            res = None
        save_state(st, state_path)
    return res


def _finish(st, key, now, got, need, addr, port):
    """Разобрать замер и записать в память (st под замком) -> итог check."""
    if got is False or got is None:   # сбой; бронь остаётся (замер мог успеть начаться)
        pause(st, now, ERR_PAUSE, "error")
        return None
    if "limit" in got:                # 429: ничего не потрачено
        note_spent(st, now, -need)
        pause(st, now, got["limit"], "limit")
        return {"skipped": "limit", "until": st["until"]}
    if _int(got.get("spent"), need) != need:
        note_spent(st, now, _int(got.get("spent"), need) - need)   # поправка брони по X-Request-Cost
    hdr = got.get("hdr") or {}
    rem, reset = _int(hdr.get("x-ratelimit-remaining")), _int(hdr.get("x-ratelimit-reset"))
    if rem is not None and reset:
        st["api_left"] = {"remaining": rem, "until": now + min(reset, 3600)}
    if got.get("control_limit"):      # сверке ответили 429 — российский итог берём, но дальше ждём сброса
        pause(st, now, got["control_limit"], "limit")
    ru_data, ctrl_data = got.get("ru"), got.get("control")
    if not isinstance(ru_data, dict):
        pause(st, now, ERR_PAUSE, "error")
        return None
    ru = rows(ru_data, residential)
    ctrl = rows(ctrl_data, lambda p: p.get("country") != "RU")
    s = summary(ru, ctrl)
    partial = ru_data.get("status") == "in-progress"
    if partial and s["verdict"] == "nodata":   # к сроку не закончила ни одна точка — как сбой
        pause(st, now, ERR_PAUSE, "error")
        return None
    res = {"service": "Globalping", "addr": str(addr), "port": int(port), "ru": ru, "control": ctrl,
           "summary": s, "ts": int(now)}
    if partial:
        res["partial"] = True
    if s["verdict"] != "nodata":      # «никто не ответил» не помним: сбой у точек — спросим в следующий раз
        full = not partial and s["verdict"] != "few" and s["control"] is not None
        remember(st, key, now, res, CACHE_TTL if full else SHORT_TTL)
    return res


# ---------- текст ----------

def isp_part(name, s):
    if not s["fail"]:
        return f"{name} ✅"
    if not s["ok"]:
        return f"{name} ❌"
    return f"{name} ✅{s['ok']} ❌{s['fail']}"


def text(res):
    """Одна строка для сообщения (без «• »); None — показывать нечего."""
    if not res:
        return None
    if res.get("skipped"):
        return {"budget": "не спрашивал — часовой запас проверок исчерпан",
                "limit": "не спрашивал — сервис просил подождать (предел запросов)",
                "error": "не спрашивал — недавно не ответил, пауза"}.get(res["skipped"], "не спрашивал")
    s = res.get("summary") or {}
    answered = s.get("ru_ok", 0) + s.get("ru_fail", 0)
    if not answered:
        head = "домашние точки в России не дали ответа"
    else:
        isps = ", ".join(isp_part(k, v) for k, v in sorted((s.get("isps") or {}).items(),
                                                            key=lambda kv: (-kv[1]["ok"] - kv[1]["fail"], kv[0])))
        head = f"открывается у {s['ru_ok']} из {answered} — {isps}"
    if s.get("ru_nodata"):
        head += f" (не смогли проверить: {s['ru_nodata']}" + (", замер не успел закончиться" if res.get("partial")
                                                              else "") + ")"
    ctrl = {"up": "из Европы открывается", "down": "из Европы тоже не открывается",
            None: "из Европы нет данных"}[s.get("control")]
    age = f" [замер {max(1, res.get('age', 0) // 60)} мин назад]" if res.get("cached") else ""
    return f"{head}; {ctrl}{age}"
