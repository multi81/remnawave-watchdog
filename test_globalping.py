"""Тесты Globalping (globalping.py и blockwatch.external_scan): что уходит наружу (только IP и порт, домашние сети РФ
и две точки в Европе), ожидание замера, разбор точек по провайдерам, память на 20 минут, часовой запас, 429 и
Retry-After, сбой сети -> None, ключ только заголовком, выключено — ничего не отправлено; выводы разбора сбоя.
Настоящий API не трогаем: вместо него — свой сервер на 127.0.0.1. PYTHONIOENCODING=utf-8 python test_globalping.py"""
import gzip
import json
import os
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import globalping as gp  # noqa: E402
import blockwatch  # noqa: E402
import netprobe  # noqa: E402

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)

ok = 0


def check(name, cond):
    global ok
    print(("OK   " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    ok += 1


tmp = tempfile.mkdtemp()
ADDR = "1.2.3.4"          # вымышленный адрес входа (нужен публичный: globalping не шлёт служебные и документационные адреса)
TOKEN = "gp-test-token-0123456789"


def probe(asn, network, city, country="RU", tags=("eyeball-network",)):
    return {"continent": "EU", "country": country, "city": city, "asn": asn, "network": network,
            "tags": list(tags), "resolvers": ["private"]}


def item(p, rcv, total=3, status="finished"):
    st = {"min": 10, "avg": 12.4, "max": 15, "total": total, "rcv": rcv, "drop": total - rcv,
          "loss": round(100 * (total - rcv) / total) if total else 0}
    return {"probe": p, "result": {"status": status, "stats": st if status == "finished" else None}}


PROBES = [  # список точек онлайн (/v1/probes): домашние, хостер с меткой «домашняя», дата-центр
    {"location": {"country": "RU", "asn": 8359, "network": "MTS PJSC", "city": "Moscow"}, "tags": ["eyeball-network"]},
    {"location": {"country": "RU", "asn": 3216, "network": "PJSC Vimpelcom", "city": "Moscow"}, "tags": ["eyeball-network"]},
    {"location": {"country": "RU", "asn": 51570, "network": "JSC ER-Telecom Holding", "city": "Kazan"}, "tags": ["eyeball-network"]},
    {"location": {"country": "RU", "asn": 51570, "network": "JSC ER-Telecom Holding", "city": "Perm"}, "tags": ["eyeball-network"]},
    {"location": {"country": "RU", "asn": 9123, "network": "Timeweb", "city": "Moscow"}, "tags": ["eyeball-network"]},
    {"location": {"country": "RU", "asn": 49505, "network": "Selectel", "city": "St Petersburg"}, "tags": ["datacenter-network"]},
    {"location": {"country": "DE", "asn": 24940, "network": "Hetzner", "city": "Falkenstein"}, "tags": ["datacenter-network"]},
]
RU_RESULTS = [item(probe(8359, "MTS PJSC", "Moscow"), 3), item(probe(3216, "PJSC Vimpelcom", "Moscow"), 0),
              item(probe(51570, "JSC ER-Telecom Holding", "Kazan"), 3),
              item(probe(51570, "JSC ER-Telecom Holding", "Perm"), 0),
              item(probe(9123, "Timeweb", "Moscow"), 3),                       # хостер — в вывод не идёт
              item(probe(12389, "Rostelecom", "Samara"), 0, status="failed")]  # точка не смогла — нет данных
CTRL_RESULTS = [item(probe(24940, "Hetzner", "Falkenstein", "DE", ("datacenter-network",)), 3),
                item(probe(60781, "Leaseweb", "Amsterdam", "NL", ("datacenter-network",)), 3)]


class World:
    """Что отвечает поддельный API и что к нему пришло."""

    def reset(self):
        self.reqs = []            # (метод, путь, заголовки, тело)
        self.create = []          # очередь ответов на создание: (код, заголовки, тело) — пусто => обычный ответ
        self.polls_left = {}      # id -> сколько раз ответить «in-progress»
        self.poll429 = 0          # столько первых опросов — 429 с Retry-After
        self.ru, self.ctrl = RU_RESULTS, CTRL_RESULTS
        self.n = 0
        self.partial = {}         # id -> готовые точки в ответе «in-progress»
        self.post_delay = 0       # задержка ответа на создание (чтобы потоки пересеклись)
        self.redirect = None      # адрес, куда отвечать 302 на создание


W = World()
W.reset()
N_LOCK = threading.Lock()


class Api(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, data, headers=None, gz=False):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if gz:
            raw = gzip.compress(raw)
            self.send_header("Content-Encoding", "gzip")
        for k, v in (headers or {}).items():
            self.send_header(k, str(v))
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        W.reqs.append(("GET", self.path, dict(self.headers), None))
        if self.path == "/v1/probes":
            return self.send(200, PROBES, gz="gzip" in str(self.headers.get("Accept-Encoding")))
        if self.path.startswith("/v1/measurements/"):
            mid = self.path.rsplit("/", 1)[1]
            if W.poll429 > 0:
                W.poll429 -= 1
                return self.send(429, {"error": {"type": "too_many_requests", "message": "slow down"}}, {"Retry-After": 1})
            if W.polls_left.get(mid, 0) > 0:
                W.polls_left[mid] -= 1
                return self.send(200, {"id": mid, "status": "in-progress", "results": W.partial.get(mid, [])})
            res = W.ctrl if mid.startswith("c") else W.ru
            return self.send(200, {"id": mid, "type": "ping", "status": "finished", "results": res})
        self.send(404, {"error": {"type": "not_found"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        W.reqs.append(("POST", self.path, dict(self.headers), body))
        if W.redirect:
            return self.send(302, {}, {"Location": W.redirect})
        if W.create:
            entry = W.create.pop(0)
            if entry is not None:   # None — обычный ответ
                code, hdr, data = entry
                return self.send(code, data, hdr)
        time.sleep(W.post_delay)
        with N_LOCK:
            W.n += 1
        ctrl = all(loc.get("country") != "RU" for loc in body.get("locations", []))
        mid = ("c" if ctrl else "r") + "id%d" % W.n
        cost = sum(loc.get("limit", 1) for loc in body.get("locations", []))
        self.send(202, {"id": mid, "probesCount": cost},
                  {"Location": "https://elsewhere.invalid/v1/measurements/" + mid, "X-Request-Cost": cost,
                   "X-RateLimit-Remaining": 200, "X-RateLimit-Reset": 3000})


srv = ThreadingHTTPServer(("127.0.0.1", 0), Api)
threading.Thread(target=srv.serve_forever, daemon=True).start()
gp.API = "http://127.0.0.1:%d/v1" % srv.server_address[1]
gp.POLL_GAP = 0.05
gp.STATE = os.path.join(tmp, "globalping.json")
gp.TOKEN_FILE = os.path.join(tmp, "globalping.token")
blockwatch.ETC = tmp


def fresh():
    W.reset()
    for f in (gp.STATE, gp.TOKEN_FILE):
        if os.path.exists(f):
            os.remove(f)


def posts():
    return [r for r in W.reqs if r[0] == "POST"]


# ---------- 1. что уходит наружу ----------
fresh()
res = gp.check(ADDR, 443)
ru_body, c_body = posts()[0][3], posts()[1][3]
check("G1 замер — ping по TCP на адрес и порт входа; цель — только IP",
      ru_body["type"] == "ping" and ru_body["target"] == ADDR and c_body["target"] == ADDR
      and ru_body["measurementOptions"] == {"protocol": "TCP", "port": 443, "packets": gp.PACKETS})
check("G2 места в России (список точек пришёл сжатым gzip) — домашние сети по ASN (хостер с меткой «домашняя» и дата-центр отсеяны), до 8 точек",
      all(loc["country"] == "RU" and loc["tags"] == ["eyeball-network"] for loc in ru_body["locations"])
      and sorted((loc["asn"], loc["limit"]) for loc in ru_body["locations"]) == [(3216, 1), (8359, 1), (51570, 2)])
check("G3 сверка — отдельным замером из Европы (DE и NL, по одной точке)",
      c_body["locations"] == [{"country": "DE", "tags": ["datacenter-network"], "limit": 1},
                              {"country": "NL", "tags": ["datacenter-network"], "limit": 1}])
everything = json.dumps([r[1:] for r in W.reqs if r[3] is not None] + [r[1] for r in W.reqs], ensure_ascii=False)
check("G4 ни имени, ни домена в запросах; номер замера подставлен в свой адрес API, а не из Location",
      "example.net" not in everything and "elsewhere.invalid" not in everything
      and any(r[1].startswith("/v1/measurements/rid") for r in W.reqs if r[0] == "GET"))
ua = posts()[0][2].get("User-Agent")
check("G5 представляемся общим именем, без ключа заголовка Authorization нет",
      ua == gp.UA and "Authorization" not in posts()[0][2])

# ---------- 2. разбор точек ----------
s = res["summary"]
check("G6 точки по провайдерам: МТС открыто, Билайн закрыто, Дом.ру одна да, одна нет; хостер выкинут, «failed» — нет данных",
      s["ru_ok"] == 2 and s["ru_fail"] == 2 and s["ru_nodata"] == 1 and s["verdict"] == "mixed"
      and s["isps"] == {"МТС": {"ok": 1, "fail": 0}, "Билайн": {"ok": 0, "fail": 1}, "Дом.ру": {"ok": 1, "fail": 1}}
      and s["control"] == "up" and all(r["isp"] != "Timeweb" for r in res["ru"]))
check("G7 строка для сообщения",
      gp.text(res) == "открывается у 2 из 4 — Дом.ру ✅1 ❌1, Билайн ❌, МТС ✅ (не смогли проверить: 1); из Европы открывается")
check("G8 итог: все закрыты в двух сетях — closed; одна сеть — мало данных; все открыты — open; Европа молчит — down",
      gp.summary([{"isp": "a", "asn": 1, "state": "fail"}, {"isp": "b", "asn": 2, "state": "fail"}], [])["verdict"] == "closed"
      and gp.summary([{"isp": "a", "asn": 1, "state": "fail"}], [])["verdict"] == "few"
      and gp.summary([{"isp": "a", "asn": 1, "state": "ok"}, {"isp": "b", "asn": 2, "state": "ok"}],
                     [{"isp": "x", "asn": 9, "state": "fail"}]) ==
      {"ru_ok": 2, "ru_fail": 0, "ru_nodata": 0, "isps": {"a": {"ok": 1, "fail": 0}, "b": {"ok": 1, "fail": 0}},
       "verdict": "open", "control": "down"}
      and gp.summary([], [])["verdict"] == "nodata")


def R(isp, asn, st):
    return {"isp": isp, "asn": asn, "state": st}


check("G8a open и mixed — только при двух сетях или трёх ответах; один успех из одной сети — мало данных",
      gp.summary([R("a", 1, "ok")], [])["verdict"] == "few"
      and gp.summary([R("a", 1, "ok"), R("a", 1, "ok"), R("a", 1, "ok")], [])["verdict"] == "open")
check("G8b mixed — только если у провайдера закрыто на всех его точках; у кого и да и нет — неустойчивая точка",
      gp.summary([R("a", 1, "ok"), R("a", 1, "fail"), R("b", 2, "ok")], [])["verdict"] == "open"
      and gp.summary([R("a", 1, "ok"), R("b", 2, "fail")], [])["verdict"] == "mixed"
      and blockwatch.ext_isps(gp.summary([R("a", 1, "ok"), R("a", 1, "fail"), R("b", 2, "fail")], []), "fail") == "b")
check("G8c сеть без номера (None) за отдельную сеть не считается",
      gp.summary([R("a", None, "fail"), R("b", 2, "fail")], [])["verdict"] == "few")

# ---------- 3. память и запас ----------
n_before = len(W.reqs)
again = gp.check(ADDR, 443)
check("G9 тот же адрес моложе 20 минут — из памяти, наружу ничего",
      len(W.reqs) == n_before and again["cached"] is True and again["summary"] == s)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G10 в памяти — потраченные проверки и остаток от API", gp.spent_last_hour(st, time.time()) == 6
      and st["api_left"]["remaining"] == 200)
old = gp.check(ADDR, 443, now=time.time() + gp.CACHE_TTL + 5)
check("G11 старше 20 минут — спрашиваем заново", old and not old.get("cached") and len(posts()) == 4)
fresh()
skip = gp.check(ADDR, 443, budget=5)
check("G12 часовой запас меньше нужного (8 + 2) — не спрашиваем, ни одного запроса",
      skip == {"skipped": "budget", "until": skip["until"]} and W.reqs == []
      and gp.text(skip) == "не спрашивал — часовой запас проверок исчерпан")
fresh()
json.dump({"spent": [[time.time() - 100, 115]]}, open(gp.STATE, "w"))
check("G13 запас за последний час почти потрачен — не спрашиваем", gp.check(ADDR, 443)["skipped"] == "budget" and not posts())
fresh()
json.dump({"api_left": {"remaining": 4, "until": time.time() + 600}}, open(gp.STATE, "w"))
check("G14 API сказал, что осталось меньше нужного — ждём сброса", gp.check(ADDR, 443)["skipped"] == "budget" and not posts())

# ---------- 4. 429 и Retry-After ----------
fresh()
W.create = [(429, {"X-RateLimit-Reset": 120, "X-RateLimit-Remaining": 0},
             {"error": {"type": "rate_limit_exceeded", "message": "exceeds"}})]
lim = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G15 429 при создании — пауза на X-RateLimit-Reset, итог «предел»",
      lim["skipped"] == "limit" and 100 < st["until"] - time.time() <= 121 and st["until_why"] == "limit")
n_before = len(W.reqs)
check("G16 во время паузы — ни одного запроса", gp.check("5.6.7.8", 443)["skipped"] == "limit" and len(W.reqs) == n_before)
fresh()
W.poll429 = 1
t0 = time.monotonic()
got = gp.check(ADDR, 443)
check("G17 429 при опросе — ждём Retry-After и получаем итог",
      got and got["summary"]["ru_ok"] == 2 and time.monotonic() - t0 >= 0.9)
fresh()
W.create = [(422, {}, {"error": {"type": "no_probes_found", "message": "No matching IPv4 probes available."}})]
got = gp.check(ADDR, 443)
check("G18 422 «нет таких точек» — повтор общим запросом по стране",
      got and posts()[1][3]["locations"] == [{"country": "RU", "tags": ["eyeball-network"], "limit": 4}])

# ---------- 5. ожидание замера ----------
fresh()
W.polls_left = {"rid1": 2}
got = gp.check(ADDR, 443)
check("G19 замер «in-progress» — опрашиваем, пока не закончится",
      got and sum(1 for r in W.reqs if r[1] == "/v1/measurements/rid1") == 3)
fresh()
W.polls_left = {"rid1": 10 ** 6}
saved = (gp.DEADLINE, gp.CREATE_MIN_LEFT, gp.EXTRA_MIN_LEFT, gp.CONTROL_GRACE)
gp.DEADLINE, gp.CREATE_MIN_LEFT, gp.EXTRA_MIN_LEFT, gp.CONTROL_GRACE = 1.0, 0, 0, 0
t0 = time.monotonic()
got = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G20 к сроку не закончила ни одна точка — None, без зависания, короткая пауза",
      got is None and time.monotonic() - t0 < 4 and st["until_why"] == "error")
fresh()
W.polls_left = {"rid1": 10 ** 6}   # медленный случай — порт закрыт, часть точек ещё ждёт своих соединений
W.partial = {"rid1": [item(probe(8359, "MTS PJSC", "Moscow"), 0), item(probe(3216, "PJSC Vimpelcom", "Moscow"), 0),
                      {"probe": probe(51570, "JSC ER-Telecom Holding", "Kazan"),
                       "result": {"status": "in-progress", "stats": {"total": 1, "rcv": 0}}}]}
got = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G20a к сроку готова часть точек (rcv=0) — итог по готовым, идущие — нет данных, без паузы, помним недолго",
      got and got.get("partial") and got["summary"]["verdict"] == "closed" and got["summary"]["ru_fail"] == 2
      and got["summary"]["ru_nodata"] == 1 and "until" not in st
      and st["cache"][ADDR + ":443"]["ttl"] == gp.SHORT_TTL and "замер не успел закончиться" in gp.text(got))
gp.DEADLINE, gp.CREATE_MIN_LEFT, gp.EXTRA_MIN_LEFT, gp.CONTROL_GRACE = saved
check("G20b срок — около 40 с от создания замера; разбор сбоя ждёт весь check с запасом",
      gp.DEADLINE >= 35 and gp.WALL >= gp.DEADLINE + gp.PROBES_TIMEOUT and blockwatch.EXT_WAIT > gp.WALL)

# ---------- 6. сбои сети ----------
fresh()
dead = socket.socket()
dead.bind(("127.0.0.1", 0))
port_dead = dead.getsockname()[1]
dead.close()
real_api, gp.API = gp.API, "http://127.0.0.1:%d/v1" % port_dead
got = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G21 API недоступен — None, пауза ERR_PAUSE (не долбим каждый цикл)",
      got is None and st["until_why"] == "error" and gp.check(ADDR, 443)["skipped"] == "error")
gp.API = real_api
fresh()
W.create = [(500, {}, "oops")]
check("G22 непонятный ответ — None", gp.check(ADDR, 443) is None)
fresh()
real_http = gp.http
gp.http = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("неожиданное"))
check("G23 любое исключение внутри — None, наружу не летит, и пауза (не долбить сломанным каждый разбор)",
      gp.check(ADDR, 443) is None and json.load(open(gp.STATE, encoding="utf-8"))["until_why"] == "error")
gp.http = real_http
fresh()
check("G24 имя вместо адреса и частные адреса не отправляются",
      gp.check("de1.example.net", 443) is None and gp.check("10.0.0.1", 443) is None
      and gp.check("127.0.0.1", 443) is None and not os.path.exists(gp.STATE))

# ---------- 7. ключ ----------
fresh()
with open(gp.TOKEN_FILE, "w") as f:
    f.write(TOKEN + "\n")
gp.check(ADDR, 443)
auth = {r[2].get("Authorization") for r in W.reqs if r[1] != "/v1/probes"}
check("G25 ключ из файла уходит заголовком Bearer к /measurements (на /probes — нет) и не попадает в память",
      auth == {"Bearer " + TOKEN} and TOKEN not in open(gp.STATE, encoding="utf-8").read()
      and all("Authorization" not in r[2] for r in W.reqs if r[1] == "/v1/probes"))
check("G26 с ключом запас больше", gp.HOUR_BUDGET_TOKEN > gp.HOUR_BUDGET and gp.HOUR_BUDGET + 2 * 10 < 250)
with open(gp.TOKEN_FILE, "w") as f:
    f.write("bad token\nс пробелом")
check("G27 испорченный файл ключа — без ключа", gp.read_token() is None)

# ---------- 8. blockwatch.external_scan: настройки ----------
fresh()
ext_path = os.path.join(tmp, blockwatch.EXTERNAL)
TARGET = {"host": "de1.example.net", "addr": ADDR, "port": 443}
check("G28 нет external.json или enabled=false — None, ни одного запроса",
      blockwatch.external_scan(TARGET) is None
      and blockwatch.external_scan(TARGET, {"enabled": False, "service": "globalping"}) is None and W.reqs == [])
other = blockwatch.external_scan(TARGET, {"enabled": True, "service": "cheburcheck"})
check("G29 другой сервис — запроса к нему нет, ничего не отправлено",
      other == {"service": "cheburcheck", "note": "включена в настройках, но запрос к сервису не написан — ничего не отправлено"}
      and W.reqs == [])
json.dump({"enabled": True, "service": "globalping", "ru_probes": 3}, open(ext_path, "w", encoding="utf-8"))
ext = blockwatch.external_scan(TARGET)
check("G30 включено — спрашивает Globalping, число точек из настроек, имя хоста не уходит",
      ext["service"] == "Globalping" and ext["note"].startswith("открывается у 2 из 4")
      and sum(loc["limit"] for loc in posts()[0][3]["locations"]) == 3 and "example.net" not in json.dumps([r[3] for r in posts()]))
check("G31 нет адреса — не спрашивает (имя наружу не отдаём)",
      blockwatch.external_scan({"host": "de1.example.net", "addr": None}) is None)


# ---------- 9. выводы разбора сбоя ----------
def pt(tcp="open", tls=True, got=65536, end="ok"):
    up = tcp == "open"
    return {"host": "h", "addr": ADDR, "tcp": tcp, "tcp_ms": 40 if up else None, "tls": tls if up else None,
            "bytes": got if up and tls else None, "need": 65536, "end": end if up and tls else None}


def ext_of(ru_states, ctrl_states):
    ru = [{"isp": isp, "asn": asn, "city": "", "country": "RU", "state": st, "rtt": None} for isp, asn, st in ru_states]
    ctrl = [{"isp": "Hetzner", "asn": 24940, "city": "", "country": "DE", "state": st, "rtt": None} for st in ctrl_states]
    res = {"service": "Globalping", "addr": ADDR, "port": 443, "ru": ru, "control": ctrl, "summary": gp.summary(ru, ctrl)}
    return dict(res, note=gp.text(res))


def dd(direct, agents=None, abroad=None, external=None, trace=None):
    return {"direct": direct, "agents": agents or {}, "abroad": abroad, "via": "NL1", "trace": trace, "external": external}


DEAD, FINE, NOTLS = pt("timeout"), pt(), pt(tls=False)
OPEN = ext_of([("МТС", 8359, "ok"), ("Билайн", 3216, "ok"), ("Дом.ру", 51570, "ok")], ["ok", "ok"])
CLOSED = ext_of([("МТС", 8359, "fail"), ("Билайн", 3216, "fail"), ("Дом.ру", 51570, "fail")], ["ok", "ok"])
MIXED = ext_of([("МТС", 8359, "ok"), ("Билайн", 3216, "fail")], ["ok"])
DOWN = ext_of([("МТС", 8359, "fail"), ("Билайн", 3216, "fail")], ["fail", "fail"])
v = blockwatch.deep_verdict
two = {"СПб": DEAD, "Офис": DEAD}
check("G32 наши точки молчат, у абонентов открыто — путь из дата-центров, пользователи в порядке",
      "закрыт путь из дата-центров и хостингов, у пользователей, скорее всего, всё в порядке" in v(dd(DEAD, two, True, OPEN), "DOWN")
      and "Globalping: открывается у 3 из 3" in v(dd(DEAD, two, True, OPEN), "DOWN"))
txt = v(dd(DEAD, two, None, CLOSED, {"reached": False, "hops": 9, "last": (7, "198.51.100.62")}), "DOWN")
check("G33 закрыто у всех домашних провайдеров, из Европы открыто — блокировка по всей России (даже без своего канала)",
      txt.startswith("блокировка адреса по всей России") and "из Европы (Globalping) открывается" in txt
      and "после шага 7" in txt)
CLOSED_NOCTL = ext_of([("МТС", 8359, "fail"), ("Билайн", 3216, "fail")], [])
CLOSED_CTLDOWN = ext_of([("МТС", 8359, "fail"), ("Билайн", 3216, "fail")], ["fail"])
check("G33a Европа Globalping молчит, а наш зарубежный канал видит — источник назван верно; спорят — так и сказано",
      "а из-за рубежа (через NL1) отвечает" in v(dd(DEAD, two, True, CLOSED_NOCTL), "DOWN")
      and "из Европы" not in v(dd(DEAD, two, True, CLOSED_NOCTL), "DOWN")
      and "источники расходятся" in v(dd(DEAD, two, True, CLOSED_CTLDOWN), "DOWN")
      and not v(dd(DEAD, two, True, CLOSED_CTLDOWN), "DOWN").startswith("блокировка адреса по всей России"))
OLD_OPEN = dict(OPEN, cached=True, age=15 * 60)
check("G33b результат из памяти старше 5 минут в вывод не идёт (нода могла упасть с тех пор), строкой — показан",
      v(dd(DEAD, two, True, OLD_OPEN), "DOWN") == v(dd(DEAD, two, True, None), "DOWN")
      and "[замер 15 мин назад]" in gp.text(OLD_OPEN))
check("G34 у части провайдеров открыто — блокировка у отдельных провайдеров, с названиями",
      "у части открывается (МТС), у части нет (Билайн)" in v(dd(DEAD, two, True, MIXED), "DOWN")
      and "не по всей стране" in v(dd(DEAD, two, True, MIXED), "DOWN"))
check("G35 закрыто везде и из Европы тоже — поломка ноды, а не блокировка",
      "сбой самой ноды или её хостера" in v(dd(DEAD, two, None, DOWN), "DOWN"))
check("G36 TLS рвётся — Globalping (только TCP) вывод не меняет",
      v(dd(NOTLS, {"СПб": NOTLS}, True, OPEN), "DOWN") == v(dd(NOTLS, {"СПб": NOTLS}, True, None), "DOWN"))
check("G37 часть наших точек не видит — к выводу хвост про абонентов",
      v(dd(FINE, {"СПб": DEAD}, True, MIXED), "DOWN").endswith("у части открывается (МТС), у части нет (Билайн)")
      and "у абонентов домашних провайдеров открывается (Globalping: 3 из 3)" in v(dd(DEAD, {"СПб": FINE}, True, OPEN), "DOWN"))
check("G37a у наших точек рвётся TLS, а не порт — хвоста «у абонентов открывается» нет",
      "Globalping" not in v(dd(FINE, {"СПб": NOTLS}, True, OPEN), "DOWN")
      and "Globalping" not in v(dd(NOTLS, {"СПб": FINE}, True, OPEN), "DOWN"))
check("G38 без данных Globalping вывод прежний",
      "похоже на блокировку адреса ноды из России" in v(dd(DEAD, two, True, None), "DOWN")
      and v(dd(DEAD, two, True, {"skipped": "budget", "service": "Globalping", "note": "x"}), "DOWN")
      == v(dd(DEAD, two, True, None), "DOWN"))
lines = blockwatch.deep_lines(dd(DEAD, {}, True, MIXED), extra=False)
check("G39 строка разбора: «абоненты в РФ (Globalping)» по провайдерам и Европа",
      lines[-1] == "• абоненты в РФ (Globalping): открывается у 1 из 2 — Билайн ❌, МТС ✅; из Европы открывается")
lines = blockwatch.deep_lines(dd(DEAD, {}, True, dict(gp.check("9.9.9.9", 443, budget=1), service="Globalping",
                                                         note="не спрашивал — часовой запас проверок исчерпан")), extra=False)
check("G40 не спросили из-за запаса — так и сказано", lines[-1].endswith("часовой запас проверок исчерпан"))
check("G41 строка проверки по запросу: у ноды с бедой — что видят абоненты",
      "абоненты в РФ (Globalping): открывается у 1 из 2" in blockwatch.node_line("pl1", dd(DEAD, {}, True, MIXED)))

# ---------- 10. deep_diag: зовёт только при беде и параллельно ----------
calls = []


def fake_ext(target, cfg=None):
    calls.append(dict(target))
    time.sleep(0.6)
    return OPEN


real = (blockwatch.external_scan, netprobe.direct_probe, netprobe.series, netprobe.sni_compare, netprobe.name_ref,
        netprobe.tcp_trace, netprobe.neighbours, netprobe.own_addr, blockwatch.agent_get, blockwatch.registry_hit,
        blockwatch.witness_wait, blockwatch.doh)
world = {"direct": FINE, "agent": FINE}
truth = {ADDR}
doh_calls = []
blockwatch.doh = lambda name, socks_port=None, first=False: doh_calls.append(name) or truth
blockwatch.external_scan = fake_ext
netprobe.direct_probe = lambda host, port=443, sni=None, **kw: dict(world["direct"])
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: {"n": n, "ok": n, "fail": 0}
netprobe.sni_compare = lambda *a, **k: None
netprobe.name_ref = lambda *a, **k: None
netprobe.tcp_trace = lambda addr, port=443, max_hops=16: time.sleep(0.6) or {"reached": True, "hops": 5, "last": (5, addr)}
netprobe.neighbours = lambda addr, **k: None
netprobe.own_addr = lambda: None
blockwatch.agent_get = lambda a, path, timeout=20: dict(world["agent"]) if path.startswith("/probe") else None
blockwatch.registry_hit = lambda addr, lists: None
blockwatch.witness_wait = lambda url, series, port=None: {}
CH = {"name": "pl1", "entry": "pl1.example.net", "entry_port": 443, "security": "reality", "sni": "pl1.example.net"}
AG = [{"name": "СПб", "url": "http://x", "token": "t"}]
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
check("G42 вход открыт отовсюду (беда в самом VPN) — Globalping не зовётся", calls == [] and d["external"] is None)
world["agent"] = DEAD
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
check("G43 порт закрыт только с одной точки, а с rf1 открыт — не зовётся (скорее беда самой точки)",
      calls == [] and d["external"] is None)
AG2 = AG + [{"name": "Офис", "url": "http://y", "token": "t"}]
d = blockwatch.deep_diag(CH, None, AG2, ("example.net",))
check("G43a порт закрыт с двух точек — зовётся, с адресом (сверен с защищённым DNS) и портом",
      calls == [{"host": CH["entry"], "addr": ADDR, "port": 443}] and d["external"] is OPEN
      and doh_calls == [CH["entry"]])
calls.clear()
world["direct"], world["agent"] = NOTLS, NOTLS
d = blockwatch.deep_diag(CH, None, AG2, ("example.net",))
check("G43b рвётся TLS, порт открыт — Globalping (только TCP) не зовётся, адрес наружу не уходит",
      calls == [] and d["external"] is None)
world["direct"], world["agent"] = DEAD, DEAD
truth = {"9.9.9.9"}
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
check("G43c адрес с наших точек не совпал с защищённым DNS (подмена) — не спрашивает, так и сказано",
      calls == [] and d["external"]["skipped"] == "dns" and "подмену" in d["external"]["note"]
      and "не совпадает с защищённым DNS" in blockwatch.deep_lines(d, extra=False)[-1])
truth = None
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
check("G43d защищённый DNS не ответил — тоже не спрашивает", calls == [] and d["external"]["skipped"] == "dns")
truth = {ADDR}
calls.clear()
world["direct"], world["agent"] = DEAD, DEAD
t0 = time.monotonic()
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
took = time.monotonic() - t0
check("G44 закрыт с rf1 — зовётся сразу и идёт параллельно с трассировкой (не 0,6 + 0,6 с)",
      len(calls) == 1 and d["external"] is OPEN and took < 1.1)
blockwatch.external_scan = lambda target, cfg=None: (_ for _ in ()).throw(RuntimeError("сбой"))
d = blockwatch.deep_diag(CH, None, AG, ("example.net",))
check("G45 исключение внешнего сервиса разбор не срывает", d["external"] is None and d["trace"]["reached"])
(blockwatch.external_scan, netprobe.direct_probe, netprobe.series, netprobe.sni_compare, netprobe.name_ref,
 netprobe.tcp_trace, netprobe.neighbours, netprobe.own_addr, blockwatch.agent_get, blockwatch.registry_hit,
 blockwatch.witness_wait, blockwatch.doh) = real

# ---------- 11. проверка по запросу: строка «Внешний сервис» ----------
res_fc = {"external": "globalping", "nodes": {"pl1": dd(DEAD, {}, True, MIXED), "nl1": dd(FINE, {}, True)}}
check("G46 «Внешний сервис» — Globalping, о скольких нодах спрошено; выключен — «выключен»",
      blockwatch.external_status(res_fc).startswith("Globalping (абоненты домашних провайдеров в РФ)")
      and blockwatch.external_status(res_fc).endswith("спрошено о нодах: 1")
      and blockwatch.external_status({"external": False}) == "выключен"
      and "запрос к нему не написан" in blockwatch.external_status({"external": True})
      and "запрос к нему не написан" in blockwatch.external_status({"external": "cheburcheck"}))
check("G47 пример настроек: включён Globalping, сказано про публичность результатов",
      json.load(open(os.path.join(HERE, "examples", "external.example.json"), encoding="utf-8"))["service"] == "globalping"
      and "открыты всем" in open(os.path.join(HERE, "examples", "external.example.json"), encoding="utf-8").read())
inst = open(os.path.join(HERE, "install.sh"), encoding="utf-8").read()
check("G48 install.sh ставит globalping.py и не создаёт файл ключа",
      'vantage_client.py globalping.py; do' in inst and 'install -m 644 "$SRC/globalping.py" /opt/channel-watch/' in inst
      and "globalping.token" not in inst)

# ---------- 12. потоки, сроки, переадресация, испорченная память ----------
fresh()
W.post_delay = 0.3
out = []
ths = [threading.Thread(target=lambda: out.append(gp.check(ADDR, 443))) for _ in range(3)]
for t in ths:
    t.start()
for t in ths:
    t.join()
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G49 три потока на один адрес — один замер (и одна сверка), итог у всех, запас посчитан один раз",
      len(posts()) == 2 and len(out) == 3 and all(r and r["summary"]["ru_ok"] == 2 for r in out)
      and gp.spent_last_hour(st, time.time()) == 6)
fresh()
W.post_delay = 0.2
addrs = ["1.2.3.4", "5.6.7.8", "8.8.4.4"]
ths = [threading.Thread(target=gp.check, args=(a, 443)) for a in addrs]
for t in ths:
    t.start()
for t in ths:
    t.join()
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G50 три потока на разные адреса — память цела, все три в кэше, запас = сумме, временных файлов не осталось",
      gp.spent_last_hour(st, time.time()) == 18 and sorted(st["cache"]) == sorted(a + ":443" for a in addrs)
      and not [f for f in os.listdir(tmp) if f.endswith(".tmp")])
W.post_delay = 0
fresh()
json.dump({"spent": [[time.time() - 3000, 100], [time.time() - 100, 15]]}, open(gp.STATE, "w"))
sk = gp.check(ADDR, 443)
check("G51 запас исчерпан — «until» по самой старой записи часа, а не «через час»",
      sk["skipped"] == "budget" and abs(sk["until"] - (time.time() - 3000 + 3600)) < 5)
fresh()
fut = time.time() + 10 * 3600
json.dump({"until": fut, "until_why": "error"}, open(gp.STATE, "w"))
sk = gp.check(ADDR, 443)
check("G52 пауза «из будущего» (часы шагнули назад) — не дольше предела", sk["skipped"] == "error"
      and sk["until"] <= time.time() + gp.LIMIT_PAUSE_MAX + 1 and not posts())
json.dump({"spent": [[fut, 500]], "api_left": [1, 2],
           "cache": {ADDR + ":443": {"ts": fut, "res": {"summary": {}}}, "bad": "x"}}, open(gp.STATE, "w"))
got = gp.check(ADDR, 443)
check("G52a траты и кэш «из будущего», кривые поля — выброшены, проверка работает, а не молчит",
      got and not got.get("cached") and got["summary"]["ru_ok"] == 2)
json.dump({"until": "скоро", "spent": "много", "cache": []}, open(gp.STATE, "w"))
check("G52b кривые типы полей — не исключение и не вечная тишина", gp.check("5.6.7.8", 443)["summary"]["ru_ok"] == 2)
P = probe(8359, "MTS PJSC", "Moscow")
check("G53 точка: счётчики первыми; failed с причиной target — закрыто; offline, resolver, internal — нет данных",
      gp.probe_state({"probe": P, "result": {"status": "failed", "stats": {"total": 3, "rcv": 0}}}) == "fail"
      and gp.probe_state({"probe": P, "result": {"status": "failed", "failureSource": "target"}}) == "fail"
      and gp.probe_state({"probe": P, "result": {"status": "offline", "stats": {"total": 3, "rcv": 0}}}) == "nodata"
      and gp.probe_state({"probe": P, "result": {"status": "failed", "failureSource": "internal",
                                                   "stats": {"total": 3, "rcv": 0}}}) == "nodata"
      and gp.probe_state({"probe": P, "result": {"status": "failed", "failureSource": "resolver"}}) == "nodata"
      and gp.probe_state({"probe": P, "result": {"status": "finished", "stats": {"total": "3", "rcv": "x"}}}) == "nodata"
      and gp.probe_state("мусор") == "nodata")
fresh()
W.ru = [item(probe(8359, "MTS", "Moscow"), 0, status="offline"), item(probe(3216, "B", "Moscow"), 0, status="failed")]
got = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G54 никто из домашних точек не ответил — итог есть, но в память не идёт (спросим в следующий раз)",
      got and got["summary"]["verdict"] == "nodata" and ADDR + ":443" not in (st.get("cache") or {}))
fresh()
W.create = [None, (429, {"Retry-After": 200}, {"error": {"type": "too_many_requests"}})]
got = gp.check(ADDR, 443)
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G55 сверке ответили 429 — российский итог есть, а дальше пауза до сброса; Европа без данных — помним недолго",
      got and got["summary"]["ru_ok"] == 2 and got["summary"]["control"] is None and st["until_why"] == "limit"
      and 150 < st["until"] - time.time() <= 201 and st["cache"][ADDR + ":443"]["ttl"] == gp.SHORT_TTL)
fresh()
real_rows = gp.rows
gp.rows = lambda *a, **k: (_ for _ in ()).throw(TypeError("ответ другого вида"))
got = gp.check(ADDR, 443)
gp.rows = real_rows
st = json.load(open(gp.STATE, encoding="utf-8"))
check("G56 ответ не разобрался после замера — потраченное записано, пауза, следующий разбор не тратит заново",
      got is None and gp.spent_last_hour(st, time.time()) == 6 and st["until_why"] == "error"
      and gp.check(ADDR, 443)["skipped"] == "error")


class Trap(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        Trap.seen.append(dict(self.headers))
        self.send_response(202)
        self.end_headers()

    do_GET = do_POST


trap = ThreadingHTTPServer(("127.0.0.1", 0), Trap)
threading.Thread(target=trap.serve_forever, daemon=True).start()
fresh()
with open(gp.TOKEN_FILE, "w") as f:
    f.write(TOKEN)
W.redirect = "http://127.0.0.1:%d/v1/measurements" % trap.server_address[1]
got = gp.check(ADDR, 443)
check("G57 302 на чужой адрес — не идём туда (ключ не уходит), это сбой", got is None and Trap.seen == []
      and json.load(open(gp.STATE, encoding="utf-8"))["until_why"] == "error")
trap.shutdown()
fresh()
W.create = [(202, {}, {"id": "ид12345678"})]
check("G58 номер замера не латиницей — не номер, сбой", gp.check(ADDR, 443) is None)
check("G59 имя сети из API — без переводов строк и «невидимых» символов, не длиннее 24",
      gp.isp_name({"asn": 1, "network": "Evil\n🚫 Блокировка\u202eабв" + "x" * 40}) == ("Evil 🚫 Блокировка абв" + "x" * 40)[:24]
      and "\n" not in gp.isp_name({"asn": 1, "network": "a\r\nb"}))
fresh()
os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = "http://127.0.0.1:%d" % port_dead
got = gp.check(ADDR, 443)
os.environ.pop("HTTP_PROXY")
os.environ.pop("http_proxy", None)
check("G60 прокси из окружения не берём — к API только напрямую", got and got["summary"]["ru_ok"] == 2)


def slow_server():
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)

    def run():
        c, _ = ls.accept()
        c.recv(65536)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
        try:
            for _ in range(100):
                c.sendall(b" ")
                time.sleep(0.3)
        except OSError:
            pass
        c.close()
    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


sp = slow_server()
real_api, gp.API = gp.API, "http://127.0.0.1:%d/v1" % sp
t0 = time.monotonic()
r = gp.http("GET", gp.API + "/measurements/abcdefgh", deadline=time.monotonic() + 1.0)
gp.API = real_api
check("G61 медленная отдача тела не держит запрос дольше срока", r is None and time.monotonic() - t0 < 2.5)

srv.shutdown()
print("\nпройдено: %d" % ok)
