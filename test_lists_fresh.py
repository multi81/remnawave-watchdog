"""Тесты свежести списков блокировок и данных службы --side (blockwatch.py, probe.py): curl -f, заглушка вместо списка
доменов, «когда скачан удачно» по каждому списку, строка «давно не скачиваются», сроки у профиля точек, обхода через
VPN, взгляда снаружи и гео. Без сети, кроме 127.0.0.1; время и Telegram подменены.
Запуск: PYTHONIOENCODING=utf-8 python test_lists_fresh.py"""
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import probe  # noqa: E402
import rucheck  # noqa: E402

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
H = 3600
T = 1_800_000_000

# ---------- fetch: curl -f ----------
NGINX = ("<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n"
         "<hr><center>nginx/1.18.0</center>\n</body>\n</html>\n")


class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code, body = (502, NGINX) if self.path.startswith("/bad") else (200, "a.example.test\n" * 20)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_address[1]}"
if shutil.which("curl"):
    dest = os.path.join(tmp, "f.lst")
    bad = blockwatch.fetch(url + "/bad", dest)
    good = blockwatch.fetch(url + "/good", dest)
    check("L1 curl -f: страница ошибки 502 (больше 50 байт) — не скачано; ответ 200 — скачано",
          bad is False and good is True and open(dest, encoding="utf-8").read().startswith("a.example.test"))
else:
    print("ПРОПУСК L1: нет curl")
srv.shutdown()

# ---------- scan_domains: заглушка вместо списка ----------
def write(name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return p


hits, n = blockwatch.scan_domains(write("nginx.lst", NGINX), ["node.example.test"], ["example.test"])
check("X2а заглушка nginx (одна строка с точкой «nginx/1.18.0») — n=0, список не принят", (hits, n) == ({}, 0))
cf = "<!DOCTYPE html>\n<html lang=\"en-US\">\n<head><title>Just a moment...</title>\n<meta charset=\"UTF-8\">\n" \
     "<script src=\"/cdn-cgi/x.js\"></script>\n</head>\n<body>\n<div class=\"main\">cloudflare.com</div>\n</body>\n</html>\n"
check("X2а заглушка Cloudflare — n=0", blockwatch.scan_domains(write("cf.lst", cf), [], ["example.test"]) == ({}, 0))
good_list = "".join(f'"site{i}.example.org"\n' for i in range(19)) + '"node.example.test"\n<\n'
hits, n = blockwatch.scan_domains(write("dom.lst", good_list), ["node.example.test"], ["example.test"])
check("X2а 20 доменов в кавычках и одна строка «<» — список принят, совпадение найдено",
      n == 20 and hits == {"node.example.test": "node.example.test"})
slash = "".join(f"site{i}.example.org/path\n" for i in range(30))
check("X2а «/» мусором не считается",
      blockwatch.scan_domains(write("slash.lst", slash), [], ["example.test"])[1] == 30)
big = "".join(f"s{i}.example.org\n" for i in range(1000)) + "bad line.x\n" * 9
check("X2а немного мусора в большом списке (9 при 1009 строках, предел max(5, n//100)=10) — список принят",
      blockwatch.scan_domains(write("big.lst", big), [], ["example.test"])[1] == 1009)

# ---------- lists_run + lists_step: HTML вместо доменов не даёт ложного «✅» ----------
TG = {"ips": {"192.0.2.10": "нода"}, "names": {"node.example.test": "нода"}}
BASES = ["example.test"]
mode = {"dom": NGINX}


def fake_fetch(url_, path, port=None):
    key = os.path.basename(path)[:-4]
    text = mode["dom"] if key == "rkn_dom" else "198.51.100.0/24\n203.0.113.5\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return True


data = blockwatch.lists_run(TG, BASES, work=os.path.join(tmp, "w"), fetcher=fake_fetch)
check("X4а HTML вместо списка доменов — sources.rkn_dom.ok=False", data["sources"]["rkn_dom"]["ok"] is False
      and data["sources"]["rkn_ip"]["ok"] is True)
st = {"lists": {"ts": data["ts"] - 6 * H, "hits": {"rkn_dom": {"нода (node.example.test)": "node.example.test"}},
                "sources": {k: {"ok": True, "n": 5} for k in blockwatch.KIND}, "targets": {}}}
alerts = blockwatch.lists_step(st, data)
check("X4а следом lists_step: «✅ Больше нет» не уходит, прошлое совпадение по доменам остаётся",
      not any("Больше нет" in a for a in alerts) and "нода (node.example.test)" in st["lists"]["hits"]["rkn_dom"])

# ---------- lists_step: «когда скачан удачно» ----------
def src(failed=()):
    return {k: {"ok": k not in failed, "n": 0 if k in failed else 5} for k in blockwatch.KIND}


def lists_data(ts, failed=()):
    return {"ts": ts, "sources": src(failed), "hits": {k: {} for k in blockwatch.KIND}, "neighbours": {},
            "targets": {"ips": 1, "names": 1}}


st = {"lists": {"ts": T, "hits": {}, "sources": src(), "targets": {}}}  # состояние до правки: без "last"
blockwatch.lists_step(st, lists_data(T + 1, failed=("rkn_dom",)))
last = st["lists"]["last"]
check("X7в старое состояние без last: не скачавшийся rkn_dom — с прошлой удачной сверки, остальные — сейчас",
      last["rkn_dom"] == T and last["rkn_ip"] == T + 1 and set(last) == set(blockwatch.KIND))
blockwatch.lists_step(st, lists_data(T + 6 * H, failed=("rkn_dom",)))
check("X7в следующая неудача — last.rkn_dom не сдвигается", st["lists"]["last"]["rkn_dom"] == T
      and st["lists"]["last"]["cdn"] == T + 6 * H)
st = {"lists": {"ts": T, "hits": {}, "sources": src(("cdn",)), "targets": {}}}
blockwatch.lists_step(st, lists_data(T + 1, failed=("cdn",)))
check("X7в не качался и раньше, last не было — «смотрим с этого момента»", st["lists"]["last"]["cdn"] == T + 1)
st = {}
blockwatch.lists_step(st, lists_data(T, failed=("rkn_net",)))
check("X7в первая сверка без прошлого состояния — last у всех ключей", st["lists"]["last"]["rkn_net"] == T
      and st["lists"]["last"]["rkn_ip"] == T)

# ---------- block_items: «давно не скачиваются» ----------
now = T + 30 * H
srcs = src(("rkn_dom", "rkn_ip"))
lists = {"ts": now - H, "hits": {}, "sources": srcs, "targets": {"ips": 1, "names": 1},
         "last": dict({k: now - H for k in blockwatch.KIND}, rkn_dom=now - 20 * H, rkn_ip=now - 25 * H)}
parts = blockwatch.block_items({"lists": lists}, now)
txt = " · ".join(parts)
check("X15а давно не скачивается домены — 20 ч; «не скачалось списков» тоже есть; «списки не обновлялись» нет",
      "⚠️ давно не скачиваются: реестр РКН, домены — 20 ч" in txt and "не скачалось списков: 2 из 6" in txt
      and "списки не обновлялись" not in txt)
check("X15а зеркала: rkn_ip старый и не ok, но rkn_ip2 ok — строки о реестре адресов нет", "адреса" not in txt)
lists2 = dict(lists, sources=src(("rkn_dom", "cdn")), last=dict(lists["last"], cdn=now - 31 * H))
txt = " · ".join(blockwatch.block_items({"lists": lists2}, now))
check("X15а две группы — одна строка, порядок как в LIST_NAMES, часы целые",
      "⚠️ давно не скачиваются: реестр РКН, домены — 20 ч; подсети CDN и хостеров, которые в России душат — 31 ч" in txt)
lists3 = dict(lists, ts=now - 15 * H)
txt = " · ".join(blockwatch.block_items({"lists": lists3}, now))
check("X15а сверка сама остановилась — только «списки не обновлялись», без «давно не скачиваются»",
      "⚠️ списки не обновлялись 15 ч" in txt and "давно не скачиваются" not in txt and "не скачалось" not in txt)
lists4 = {k: v for k, v in lists.items() if k != "last"}
txt = " · ".join(blockwatch.block_items({"lists": lists4}, now))
check("X15а состояние без last — строки нет, «не скачалось списков» как раньше",
      "давно не скачиваются" not in txt and "не скачалось списков: 2 из 6" in txt)
lists5 = dict(lists, last=dict(lists["last"], rkn_dom=now - 10 * H))
check("X15а не скачивается меньше срока — строки нет",
      "давно не скачиваются" not in " · ".join(blockwatch.block_items({"lists": lists5}, now)))

# ---------- side_age ----------
check("S1 side_age: старше срока — часы; моложе, без ts, без now — None",
      blockwatch.side_age({"ts": T}, 13 * H, T + 14 * H) == 14 and blockwatch.side_age({"ts": T}, 13 * H, T + 12 * H) is None
      and blockwatch.side_age({}, 13 * H, T) is None and blockwatch.side_age({"ts": 0}, 13 * H, T) is None
      and blockwatch.side_age(None, 13 * H, T) is None and blockwatch.side_age({"ts": T}, 13 * H, None) is None)

# ---------- профиль и обход через VPN в строке «Блокировки» ----------
def prun(real, neutral):
    return {"sites": [{"kind": "blocked", "host": "blocked.example.test", "addr": "192.0.2.1", "real": real,
                       "neutral": neutral},
                      {"kind": "control", "host": "ok.example.test", "addr": "192.0.2.2", "real": "answer", "neutral": None}],
            "loads": []}


PF_FILT = blockwatch.profile_merge([prun("silent", "answer")] * 3)
check("подготовка: профиль «за фильтром»", blockwatch.profile_verdict(PF_FILT) == "filtered")
VPN = {"Офис": {"🇳🇱NL 3": {"ok": True, "bytes": 524288, "s": 0.6, "mbit": 7.0}}}
now = T + 100 * H
txt = " · ".join(blockwatch.block_items({"profiles": {"ts": now - 14 * H, "by": {"Офис": PF_FILT}}}, now))
check("ZL51а профиль на 14 ч старше — «за фильтром точки» нет, есть «данные точек не обновлялись 14 ч (профиль)»",
      "за фильтром точки" not in txt and "⚠️ данные точек не обновлялись 14 ч (профиль) — служба channel-watch-side" in txt)
txt = " · ".join(blockwatch.block_items({"profiles": {"by": {"Офис": PF_FILT}}}, now))
check("ZL51а профиль без ts — строка-данные, без «0 ч» и огромных часов",
      "ℹ️ за фильтром точки: Офис" in txt and "не обновлялись" not in txt)
txt = " · ".join(blockwatch.block_items({"profiles": {"ts": now - H, "by": {"Офис": PF_FILT}}}, now))
check("ZL51а свежий профиль — строка-данные", "ℹ️ за фильтром точки: Офис" in txt and "не обновлялись" not in txt)
check("ZL51а старые вызовы без now — как раньше",
      blockwatch.profiles_line({"profiles": {"ts": 1, "by": {"Офис": PF_FILT}}}) == "ℹ️ за фильтром точки: Офис"
      and blockwatch.vpn_line({"vpn_pt": {"ts": 1, "by": VPN}}) == "через VPN с точки Офис: работают 1 из 1")
txt = " · ".join(blockwatch.block_items({"vpn_pt": {"ts": now - 4 * H, "by": VPN}}, now))
check("ZL64б обход через VPN на 4 ч старше — не данные, «(обход через VPN)»",
      "через VPN с точки" not in txt and "⚠️ данные точек не обновлялись 4 ч (обход через VPN)" in txt)
txt = " · ".join(blockwatch.block_items({"vpn_pt": {"ts": now - 2 * H, "by": VPN}}, now))
check("ZL64б свежий обход — строка-данные", "через VPN с точки Офис: работают 1 из 1" in txt and "не обновлялись" not in txt)
txt = " · ".join(blockwatch.block_items({"profiles": {"ts": now - 14 * H, "by": {"Офис": PF_FILT}},
                                          "vpn_pt": {"ts": now - 20 * H, "by": VPN}}, now))
check("ZL64б устарели оба — одна строка по самой старой части",
      txt.count("не обновлялись") == 1 and "⚠️ данные точек не обновлялись 20 ч (профиль, обход через VPN)" in txt)

# ---------- гео в недельной сводке ----------
G = {"🇩🇪 DE": {"flag": "DE", "row": {"ipinfo": "DE"}, "org": "H", "cf": "DE", "yt": "DE"}}
head_old = blockwatch.geo_week({"geo": {"ts": T, "by": G}}, T + 26 * H)[1]
head_new = blockwatch.geo_week({"geo": {"ts": T, "by": G}}, T + 2 * H)[1]
head_none = blockwatch.geo_week({"geo": {"ts": T, "by": G}})[1]
check("Гео: старый ts — пометка в заголовке; свежий и без now — без пометки",
      head_old.endswith(" — ⚠️ данные 26 ч назад") and "⚠️ данные" not in head_new and "⚠️ данные" not in head_none)

# ---------- probe: взгляд снаружи ----------
OUT = {"🇩🇪 DE": {"open": [443], "site": ["200", "Сайт"]}}
now = T + 50 * H
line = probe.outside_report({"outside": OUT, "outside_ts": now - 14 * H, "nodes": {"🇩🇪 DE": {}}}, now)
check("V3а снимок на 14 ч старше — «данные не обновлялись», без «лишних открытых портов нет»",
      "Снаружи:</b> ⚠️ данные не обновлялись 14 ч" in line and "лишних открытых портов нет" not in line)
line = probe.outside_report({"outside": OUT, "outside_ts": 0, "nodes": {"🇩🇪 DE": {}}}, now)
check("V3а outside_ts=0 — срок неизвестен, обычная строка", "лишних открытых портов нет" in line and "не обновлялись" not in line)
line = probe.outside_report({"outside": OUT, "outside_ts": now - H, "nodes": {"🇩🇪 DE": {}}}, now)
check("V3а свежий снимок — обычная строка", "лишних открытых портов нет" in line)
check("V3а снимка нет — строки нет", probe.outside_report({"outside": {}, "outside_ts": now - 30 * H, "nodes": {}}, now) is None)

# ---------- probe.main: очистка обхода VPN и устаревший профиль в разборе ----------
probe.ETC = blockwatch.ETC = tmp
probe.STATE = os.path.join(tmp, "state.json")
probe.LOG = os.path.join(tmp, "log.txt")
probe.HISTORY = os.path.join(tmp, "history.json")
probe.SPEED_FILE = os.path.join(tmp, "speed.json")
blockwatch.LISTS_FILE = os.path.join(tmp, "lists.json")
blockwatch.LOSS_FILE = os.path.join(tmp, "loss.json")
blockwatch.SIDE_FILE = os.path.join(tmp, "side.json")
blockwatch.HOP_CACHE = os.path.join(tmp, "hops.json")
blockwatch.HOP_LOOKUP = lambda ip: {"org": "AS64500 Тестовая сеть", "country": "XX", "city": "Город"}
blockwatch.netprobe.neighbours = lambda addr, **kw: None
blockwatch.dns_check = lambda names, port, agents=(): {}
blockwatch.agents_health = lambda agents: {}
rucheck.STATE_FILE = os.path.join(tmp, "rucheck.json")
probe.dns_check = lambda names, port, agents=(): {}
probe.weekly_text = lambda st, hist, now: None

CHANS = [{"name": n, "port": 22001 + i, "entry": f"{n.lower()}.example.test", "entry_port": 443,
          "sni": f"{n.lower()}.example.test", "security": "reality", "expected_exit": None}
         for i, n in enumerate(("A", "B", "C", "D"))]
clock = {"t": float(T)}
alive = {}
sent = []
probe.quick = lambda port: (True, 0, 0.05, 0.25) if alive.get(port, True) else (False, 28, 0.0, 0.0)
probe.deep = lambda port: (524288, 0.6, 800_000.0, "192.0.2.1")
probe.confirm_speed = lambda port: (4194304, 0.6, 7_000_000.0)
probe.services = lambda port: {"Telegram": "302", "YouTube": "204", "Instagram": "200", "ChatGPT": "401"}
probe.check_site = lambda name: "200"
probe.site_cross = lambda name, via: None
probe.cert_info = lambda host, port=443, sni=None: {"exp": T + 60 * 86400, "life": 89}
probe.domain_expiry = lambda d: T + 200 * 86400
probe.diagnose = lambda ch: {"ping": False, "tcp": "timeout", "tcp_ms": None, "tls": None}
probe.tg_send = lambda text: sent.append(text) or "ok"
probe.time.time = lambda: clock["t"]
probe.STAGGER = 0
probe.SUMMARY_HOURS_UTC = (0,)
today = probe.dt.datetime.now(probe.dt.timezone.utc).strftime("%Y-%m-%d") + " 00"
DEAD = {"host": "h", "addr": "192.0.2.10", "tcp": "timeout", "tcp_ms": None, "tls": None, "bytes": None,
        "need": 65536, "end": None}
blockwatch.deep_many = lambda chans, via_for, agents, bases, deadline=None: {
    c["name"]: {"direct": DEAD, "agents": {}, "abroad": True, "via": "D", "trace": None, "external": None}
    for c in chans[:blockwatch.DEEP_MAX]}
seen_deeps = []
_deep_within = probe.deep_within


def spy_deep_within(*a, **kw):
    res = _deep_within(*a, **kw)
    seen_deeps.append(res)
    return res


probe.deep_within = spy_deep_within


def load():
    return json.load(open(probe.STATE, encoding="utf-8"))


def save(s):
    json.dump(s, open(probe.STATE, "w", encoding="utf-8"))


def step(minutes=2):
    clock["t"] += minutes * 60
    probe.main()


def fresh():
    for f in (probe.STATE, probe.HISTORY, probe.LOG, blockwatch.SIDE_FILE):
        if os.path.exists(f):
            os.remove(f)
    json.dump({"baseline_port": 22000, "channels": CHANS}, open(os.path.join(tmp, "channels.json"), "w", encoding="utf-8"))
    alive.clear()
    probe.main()
    s0 = load()
    s0["last_summary"] = today
    save(s0)
    sent.clear()
    seen_deeps.clear()


def side(obj):
    json.dump(obj, open(blockwatch.SIDE_FILE, "w", encoding="utf-8"))


def report():
    return probe.report_text(load(), clock["t"])


# VPN-точек нет (vantage.json нет), старый обход в состоянии и в файле службы — очищается, предупреждения нет
fresh()
old = clock["t"] - 5 * H
side({"vpn": {"ts": old, "by": VPN}})
s = load()
s["vpn_pt"] = {"ts": old, "by": VPN}
save(s)
step()
check("ZL64б VPN-точек нет: старый обход очищается, строки о старых данных нет",
      load()["vpn_pt"] == {} and "обход через VPN" not in report() and "через VPN с точки" not in report())
step()
check("ZL64б и на следующем проходе старый обход из файла службы не возвращается", load()["vpn_pt"] == {})
# свежий последний обход доживает свой срок (как ZL64а в test_probe.py)
side({"vpn": {"ts": clock["t"] + 1, "by": VPN}})
step()
check("ZL64б свежий обход при отсутствии VPN-точек ещё показывается", "через VPN с точки Офис: работают 1 из 1" in report())

# устаревший профиль «за фильтром» в разбор (d["filtered"]) не попадает, свежий — попадает
for age, want in ((14 * H, []), (H, ["Офис"])):
    fresh()
    side({"profiles": {"ts": clock["t"] - age, "by": {"Офис": PF_FILT}}})
    alive[22001] = False
    for _ in range(6):
        step()
    got = [d.get("filtered") for res in seen_deeps for d in res.values()]
    check(f"ZL64в профиль {age // H} ч назад — d[\"filtered\"] = {want}", got and all(g == want for g in got))

# отчёт: устаревший взгляд снаружи — в «Требует внимания»
fresh()
s = load()
s["outside"], s["outside_ts"] = OUT, clock["t"] - 14 * H
rep = probe.report_text(s, clock["t"])
check("V3а в полном отчёте — «Снаружи:</b> ⚠️ данные не обновлялись»",
      "Снаружи:</b> ⚠️ данные не обновлялись 14 ч" in rep and "лишних открытых портов нет" not in rep)

print(f"\nпроверок пройдено: {ok}")
