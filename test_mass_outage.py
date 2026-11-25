"""Тесты общего сбоя многих каналов сразу (probe.py): перепроверка с 2–3 точек через представителей, одно сводное
сообщение, откладывание на проход при расхождении, общее напоминание, возврат, срок разбора, старое состояние.
Без сети: проверки каналов, разбор (blockwatch.deep_many), время и Telegram подменены.
Запуск: PYTHONIOENCODING=utf-8 python test_mass_outage.py"""
import json
import os
import sys
import tempfile
import time as _time

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

# четыре канала; у A и B общий вход — представители должны быть с разными входами
CHANS = [{"name": "A 🌐", "port": 22001, "entry": "ab.example", "entry_port": 443, "sni": "ab.example",
          "security": "reality", "expected_exit": None},
         {"name": "B", "port": 22002, "entry": "ab.example", "entry_port": 443, "sni": "x.example",
          "security": "reality", "expected_exit": None},
         {"name": "C", "port": 22003, "entry": "c.example", "entry_port": 443, "sni": "c.example",
          "security": "reality", "expected_exit": None},
         {"name": "D", "port": 22004, "entry": "d.example", "entry_port": 443, "sni": "d.example",
          "security": "reality", "expected_exit": None}]
A, B, C, D = (c["name"] for c in CHANS)
PORT = {c["name"]: c["port"] for c in CHANS}

BASE = 1_800_000_000.0
clock = {"t": BASE}
world = {"alive": {}, "deep": {}}
sent = []
OK_DEEP = (524288, 0.6, 800_000.0, "1.1.1.1")
FREEZE_DEEP = (20000, 20.0, 1000.0, "1.1.1.1")
DIAG_DEAD = {"ping": False, "tcp": "timeout", "tcp_ms": None, "tls": None}

probe.quick = lambda port: (True, 0, 0.05, 0.25) if world["alive"].get(port, True) else (False, 28, 0.0, 0.0)
probe.deep = lambda port: world["deep"].get(port, OK_DEEP)
probe.confirm_speed = lambda port: (4194304, 0.6, 7_000_000.0)
probe.services = lambda port: {"Telegram": "302", "YouTube": "204", "Instagram": "200", "ChatGPT": "401"}
probe.check_site = lambda name: "200"
probe.site_cross = lambda name, via: None
probe.cert_info = lambda host, port=443, sni=None: {"exp": BASE + 60 * 86400, "life": 89}
probe.domain_expiry = lambda d: BASE + 200 * 86400
probe.diagnose = lambda ch: DIAG_DEAD
probe.tg_send = lambda text: sent.append(text) or "ok"
probe.time.time = lambda: clock["t"]
probe.STAGGER = 0
probe.SUMMARY_HOURS_UTC = (0,)
today = probe.dt.datetime.now(probe.dt.timezone.utc).strftime("%Y-%m-%d") + " 00"


# разбор сбоя: по умолчанию — «из-за рубежа отвечает, из России нет» (блокировка адреса)
def pt(tcp="open", tls=True, got=65536, end="ok"):
    up = tcp == "open"
    return {"host": "h", "addr": "192.0.2.10", "tcp": tcp, "tcp_ms": 40 if up else None, "tls": tls if up else None,
            "bytes": got if up and tls else None, "need": 65536, "end": end if up and tls else None}


def dd(direct, agents=None, abroad=None):
    return {"direct": direct, "agents": agents or {}, "abroad": abroad, "via": "D", "trace": None, "external": None}


DEAD, FINE = pt("timeout"), pt()
D_BLOCK = dd(DEAD, {"Москва": DEAD, "Timeweb": DEAD}, True)
D_DOWN = dd(DEAD, {"Москва": DEAD, "Timeweb": DEAD}, False)
D_FINE = dd(FINE, {"Москва": FINE, "Timeweb": FINE}, True)
deep_calls = []
deep_ans = {"default": D_BLOCK}


def fake_deep_many(chans, via_for, agents, bases, deadline=None):
    deep_calls.append([c["name"] for c in chans])
    if deep_ans.get("sleep"):
        _time.sleep(deep_ans["sleep"])
    return {c["name"]: deep_ans.get(c["name"], deep_ans["default"]) for c in chans[:blockwatch.DEEP_MAX]}


blockwatch.deep_many = fake_deep_many


def load():
    return json.load(open(probe.STATE, encoding="utf-8"))


def ch_state(name):
    return load()["channels"][name]


def step(minutes=2):
    clock["t"] += minutes * 60
    before = len(sent)
    probe.main()
    return sent[before:]


def steps(n):
    out = []
    for _ in range(n):
        out += step()
    return out


def fresh():
    for f in (probe.STATE, probe.HISTORY, probe.LOG):
        if os.path.exists(f):
            os.remove(f)
    json.dump({"baseline_port": 22000, "channels": CHANS}, open(os.path.join(tmp, "channels.json"), "w", encoding="utf-8"))
    world["alive"], world["deep"] = {}, {}
    deep_ans.clear()
    deep_ans["default"] = D_BLOCK
    probe.main()
    s0 = load()
    s0["last_summary"] = today
    json.dump(s0, open(probe.STATE, "w", encoding="utf-8"))
    sent.clear()
    deep_calls.clear()


def down(*names, alive=False):
    for n in names:
        world["alive"][PORT[n]] = alive


# ---------- юнит: pick_reps ----------
items = [(CHANS[0], "DOWN"), (CHANS[1], "DOWN"), (CHANS[2], "DOWN")]
reps = probe.pick_reps(items, [])
check("PR1 представители — с разными входами (A и B делят вход — второй берётся C)",
      [c["name"] for c in reps] == [A, C])
reserve = {"name": "Резерв", "port": 22007, "entry": "ru.example", "expected_exit": "203.0.113.9"}
reps = probe.pick_reps([(reserve, "DOWN"), (CHANS[2], "DOWN")], [])
check("PR2 канал с expected_exit («Резерв») в представители не идёт, пока есть другие",
      [c["name"] for c in reps] == [C])
check("PR3 только канал с expected_exit — берём его (лучше, чем ничего)",
      [c["name"] for c in probe.pick_reps([(reserve, "DOWN")], [])] == ["Резерв"])
reps = probe.pick_reps([(CHANS[0], "DOWN"), (CHANS[2], "DOWN"), (CHANS[3], "FREEZE")], [])
check("PR4 есть и «недоступен», и «душат» — по одному на каждое состояние",
      [c["name"] for c in reps] == [A, D])
# вход C делит живой канал (результаты прохода): C уходит в конец очереди
live_c = dict(CHANS[2], name="C2")
reps = probe.pick_reps(items, [(live_c, True, 0, 0, 0, None, None, None, False)])
check("PR5 вход, который делит живой канал, — в представители в последнюю очередь",
      [c["name"] for c in reps] == [A, C] and [c["name"] for c in probe.pick_reps(
          [(CHANS[2], "DOWN"), (CHANS[3], "DOWN")], [(live_c, True, 0, 0, 0, None, None, None, False)], n=1)] == [D])

# ---------- юнит: mass_text ----------
evil = "Злой <b>&"
txt = probe.mass_text("new", 4, BASE, BASE - 600, bad=[(evil, "DOWN"), ("X", "FREEZE")], earlier=["X"],
                      verdict="похоже <i>", rep=(evil, ["• с rf1 напрямую: <порт>"]))
check("MT1 имена, строки разбора и вывод экранируются",
      "Злой &lt;b&gt;&amp;" in txt and "&lt;порт&gt;" in txt and "похоже &lt;i&gt;" in txt and "<b>&" not in txt
      and "Ещё раньше перестал работать: X." in txt and "🔴 не отвечает: Злой" in txt and "🧊" not in txt)
many = [(f"🇩🇪 Germany {i} 🌐 |🔄", "DOWN" if i % 3 else "FREEZE") for i in range(20)]
rep_lines = ["• с rf1 напрямую: порт не отвечает"] + [f"• точка {i}: порт не отвечает; соединений прошло 0 из 6"
                                                      for i in range(8)]
long_v = "\n".join(f"• Germany {i}: " + "нода не отвечает ни из России, ни из-за рубежа " * 2 for i in range(2))
for kind in ("new", "remind"):
    t = probe.TG_HEAD + probe.mass_text(kind, 20, BASE, BASE - 3600, bad=many, verdict=long_v, rep=(many[0][0], rep_lines))
    check(f"MT2 {kind}: 20 каналов — сообщение короче TG_LIMIT ({probe.tg_len(t)})",
          probe.tg_len(t) < probe.TG_LIMIT and "Germany 19" in t and "|" not in t.split("Похоже")[0].replace("</b>", ""))
t = probe.mass_text("back", 4, BASE, BASE - 3600, back=[A], still=[B, C], until=BASE)
check("MT3 вернулся один из трёх — «Снова работает: A … Ещё не работают: B, C»",
      "Снова работает: A</b>" in t and "Ещё не работают: B, C." in t and "1 из" not in t)
t = probe.mass_text("more", 4, BASE, BASE - 3600, bad=[(A, "DOWN")] * 4, more=[D], more_since=BASE - 120)
check("MT4 «ещё и» — сколько всего не работает и с какого времени общий сбой",
      "Не отвечает ещё и: D</b>" in t and "Всего не работают 4 из 4" in t and "Похоже" not in t)

# ---------- XM8: mass_verdict ----------
st_of = {A: "DOWN", C: "DOWN", D: "FREEZE"}
reps = [CHANS[0], CHANS[2]]
v = probe.mass_verdict({A: D_FINE, C: D_FINE}, reps, st_of.get)
check("XM8a входы открыты отовсюду, VPN не проходит на всех представителях — причина у сторожа или панели",
      "общая причина у сторожа или панели" in v and "не блокировка адресов" in v)
v = probe.mass_verdict({A: D_BLOCK, C: D_BLOCK}, reps, st_of.get)
check("XM8b одинаковые выводы сливаются в один с припиской",
      "блокировку адреса ноды из России" in v and "(одинаково для A и C)" in v and "\n" not in v)
v = probe.mass_verdict({A: D_BLOCK, C: D_DOWN}, reps, st_of.get)
check("XM8c разные выводы — строками по каналу",
      v.startswith("• A: ") and "\n• C: " in v and "сбой самой ноды" in v)
check("XM8d разбора нет — запасная фраза", probe.mass_verdict({}, reps, st_of.get) == probe.MASS_FALLBACK)
v = probe.mass_verdict({A: D_FINE, D: D_FINE}, [CHANS[0], CHANS[3]], st_of.get)
check("XM8e среди представителей есть «душат» — особого вывода «у сторожа» нет, выводы по каждому",
      "у сторожа или панели" not in v and "• A: " in v and "• D: " in v)
skipped = dd(FINE, {"Москва": FINE, "Timeweb": DEAD}, True)
skipped["skip"] = ["Timeweb"]
check("XM8f точка с собственной бедой сети (skip) не мешает выводу «у сторожа»",
      "у сторожа или панели" in probe.mass_verdict({A: skipped}, [CHANS[0]], st_of.get))

# ---------- XM1: три канала падают разом — одно сообщение, представители с разными входами ----------
fresh()
down(A, B, C)
out = steps(2)
check("XM1 одно сообщение «Не работают сразу 3 канала из 4», без одиночных тревог",
      len(out) == 1 and "Не работают сразу 3 канала из 4" in out[0] and "Недоступен:" not in out[0]
      and "🔴 не отвечают: A, B, C" in out[0])
check("XM1a разбор вызван один раз, представители — A и C (разные входы)", deep_calls == [[A, C]])
check("XM1b в сообщении «Откуда проверил» первого представителя и общий вывод",
      "<b>Откуда проверил</b> (вход канала A)" in out[0] and "(одинаково для A и C)" in out[0]
      and "Для пользователей:" in out[0])
mass = {n: ch_state(n)["mass"] for n in (A, B, C, D)}
check("XM1c у трёх каналов отмечен общий сбой с одного времени, у D — нет",
      mass[A] == mass[B] == mass[C] > 0 and mass[D] == 0 and load()["mass_hold"] == [])
check("XM1d дальше тихо", steps(3) == [])

# ---------- XM3: через час — одно «продолжается» со свежим разбором ----------
deep_calls.clear()
out = steps(30)
check("XM3 через час одно «продолжается», без одиночных «Всё ещё»",
      len(out) == 1 and "Сбой сразу у многих каналов продолжается: не работают 3 из 4" in out[0]
      and "Всё ещё" not in out[0] and "свежая проверка" in out[0])
check("XM3a разбор вызван заново, last_remind у всех одинаковый",
      len(deep_calls) == 1 and len({ch_state(n)["last_remind"] for n in (A, B, C)}) == 1)

# ---------- XM4: в идущий общий сбой добавился D ----------
down(D)
out = steps(2)
check("XM4 «Не отвечает ещё и: D», одним сообщением", len(out) == 1 and "Не отвечает ещё и: D" in out[0]
      and "Всего не работают 4 из 4" in out[0] and "Недоступен" not in out[0])
check("XM4a D попал в общий сбой с его началом", ch_state(D)["mass"] == ch_state(A)["mass"])
out = steps(31)
check("XM4b следующее напоминание общее: 4 из 4", len(out) == 1 and "не работают 4 из 4" in out[0]
      and "Всё ещё" not in out[0])

# ---------- XM5: все вернулись разом — одно «все» ----------
world["alive"] = {}
out = steps(2)
check("XM5 все вернулись — одно «Снова работают все 4 канала»",
      len(out) == 1 and "Снова работают все 4 канала" in out[0] and "Не работали с" in out[0]
      and all(ch_state(n)["mass"] == 0 for n in (A, B, C, D)))

# возврат вразнобой: A вернулся на проход раньше B и C — всё равно одно сообщение
fresh()
down(A, B, C)
steps(2)
down(A, alive=True)
out = step()
down(B, C, alive=True)
out += step()
check("XM5a A вернулся раньше: в этом проходе ждём B и C (сообщения нет, A отложен)",
      out == [] and [h["name"] for h in load()["mass_hold"]] == [A])
out = step()
check("XM5b следующим проходом одно «Снова работают все 3 канала»",
      len(out) == 1 and "Снова работают все 3 канала" in out[0] and load()["mass_hold"] == []
      and all(ch_state(n)["mass"] == 0 for n in (A, B, C)))

# частичный возврат: вернулись A и B, C лежит — «2 из 3 … Ещё не работает: C», дальше C живёт сам по себе
fresh()
down(A, B, C)
steps(2)
down(A, B, alive=True)
out = steps(2)
check("XM5c вернулись 2 из 3 — «Снова работают 2 из 3 … Ещё не работает: C»",
      len(out) == 1 and "Снова работают 2 из 3" in out[0] and "Ещё не работает: C." in out[0])
check("XM5d в общем сбое остался один канал — сбой закрыт, у C mass == 0", ch_state(C)["mass"] == 0)
deep_calls.clear()
out = steps(31)
check("XM5e у оставшегося C — одиночное «Всё ещё недоступен» с разбором, а не «продолжается … 1 из 4»",
      len(out) == 1 and "Всё ещё недоступен: C" in out[0] and "продолжается" not in out[0]
      and "Откуда проверил" in out[0] and deep_calls == [[C]])
world["alive"] = {}
out = steps(2)
check("XM5f C вернулся — обычное «Снова работает: C»", len(out) == 1 and "Снова работает: C" in out[0]
      and "общего сбоя" not in out[0])

# ---------- XM2: A подтвердился на проход раньше B и C ----------
fresh()
down(A)
check("XM2 первый провал A — тихо", step() == [])
down(B, C)
out = step()
check("XM2a A подтвердился, B и C ещё нет — сообщений нет, A отложен",
      out == [] and [h["name"] for h in load()["mass_hold"]] == [A] and deep_calls == [])
down(D)  # D только начал падать: второй раз уже не откладываем
out = step()
check("XM2b следующим проходом — одно сводное сообщение, отложенное ушло, второй раз не откладываем",
      len(out) == 1 and "Не работают сразу 3 канала из 4" in out[0] and "A, B, C" in out[0]
      and load()["mass_hold"] == [])
out = step()
check("XM2c D подтвердился позже — «ещё и: D»", len(out) == 1 and "Не отвечает ещё и: D" in out[0])
world["alive"] = {}
steps(3)

# ---------- XM6: массовое «душат» ----------
fresh()
for n in (A, B, C):
    world["deep"][PORT[n]] = FREEZE_DEEP
out = steps(12)
check("XM6 душат сразу три канала — одно сообщение со строкой 🧊",
      len(out) == 1 and "Не работают сразу 3 канала из 4" in out[0] and "🧊 душат (соединение есть, данные встают): A, B, C"
      in out[0] and "🔴 не отвеча" not in out[0] and "Душат:" not in out[0])
world["deep"] = {}
out = steps(12)
check("XM6a вернулись — одно сообщение", len(out) == 1 and "Снова работают все 3 канала" in out[0])

# ---------- XM7: смешанное «недоступен» и «душат» ----------
fresh()
world["deep"][PORT[C]] = FREEZE_DEEP
out = []
for _ in range(8):
    out += step()
    if ch_state(C)["cand"] == "FREEZE":
        break
down(A, D)
out += step()
check("XM7 C подтвердил «душат», A и D ещё нет — ждём", out == [] and [h["name"] for h in load()["mass_hold"]] == [C])
deep_calls.clear()
out = step()
check("XM7a одно сообщение с обеими строками: 🔴 A, D и 🧊 C",
      len(out) == 1 and "🔴 не отвечают: A, D" in out[0] and "🧊 душат (соединение есть, данные встают): C" in out[0])
# вход A делит живой B — из «недоступных» представитель D
check("XM7b представители — по одному на «недоступен» и «душат»", deep_calls == [[D, C]])
world["alive"], world["deep"] = {}, {}
steps(12)

# ---------- XM9: разбор не успел за срок ----------
fresh()
deep_ans["sleep"] = 5
# срок разбора — от предела службы: оставляем на разбор ~1,5 с при пороге «не начинать» в 1 с
saved = probe.SERVICE_LIMIT, probe.DEEP_MIN, probe.DEEP_GRACE
probe.SERVICE_LIMIT, probe.DEEP_MIN, probe.DEEP_GRACE = probe.SEND_RESERVE + 1.5, 1, 0
down(A, B, C)
step()
t0 = _time.monotonic()
out = step()
spent = _time.monotonic() - t0
st9 = load()
probe.SERVICE_LIMIT, probe.DEEP_MIN, probe.DEEP_GRACE = saved
deep_ans.pop("sleep")
blockwatch.LINGER = False
check(f"XM9 разбор завис — сообщение ушло через ~1 с ({spent:.1f} с) с запасной фразой",
      len(out) == 1 and probe.MASS_FALLBACK in out[0] and spent < 4)
check("XM9a state.json записан сразу после прохода: общий сбой отмечен, очередь пуста",
      st9["channels"][A]["mass"] > 0 and st9["unsent"] == []
      and "разбор не успел за срок" in open(probe.LOG, encoding="utf-8").read())
world["alive"] = {}
steps(3)

# ---------- XM9b: на разбор времени уже не осталось — не начинаем ----------
fresh()
probe.SERVICE_LIMIT, probe.DEEP_MIN = probe.SEND_RESERVE + 0.5, 1
down(A, B, C)
step()
deep_calls.clear()
out = step()
probe.SERVICE_LIMIT, probe.DEEP_MIN = saved[0], saved[1]
log9 = open(probe.LOG, encoding="utf-8").read()
check("XM9b проверки съели срок — разбор не запускается (ни запросов к точкам, ни Globalping), сообщение уходит",
      deep_calls == [] and len(out) == 1 and probe.MASS_FALLBACK in out[0] and "не начинаю" in log9
      and "проверки заняли" in log9)
world["alive"] = {}
steps(3)

# ---------- XM9c: в общем сбое ни один канал не жив — первым делом сеть rf1 ----------
fresh()
deep_ans["default"] = dd(DEAD, {"Москва": None, "Timeweb": None}, None)
down(A, B, C, D)
step()
out = step()
check("XM9c всё легло и с rf1 никуда не достучаться — «сбой сети самой rf1», а не беда нод",
      len(out) == 1 and "сбой сети самой rf1" in out[0] and "не различить" not in out[0])
probe.SERVICE_LIMIT, probe.DEEP_MIN = probe.SEND_RESERVE + 0.5, 1
world["alive"] = {}
steps(3)
fresh()
down(A, B, C, D)
step()
out = step()
probe.SERVICE_LIMIT, probe.DEEP_MIN = saved[0], saved[1]
check("XM9d разбора нет, а не жив ни один канал — запасная фраза называет первой сеть rf1",
      len(out) == 1 and probe.MASS_FALLBACK_RF1 in out[0])
world["alive"] = {}
steps(3)

# ---------- XM10: старое состояние без mass и mass_hold ----------
fresh()
old = load()
old.pop("mass_hold", None)
for s in old["channels"].values():
    s.pop("mass", None)
json.dump(old, open(probe.STATE, "w", encoding="utf-8"))
down(A, B, C)
out = steps(2)
check("XM10 старое состояние читается, общий сбой работает",
      len(out) == 1 and "Не работают сразу 3 канала из 4" in out[0] and load()["mass_hold"] == [])
# лежали ещё при старой версии (флагов нет): напоминание — общее, с него начинается общий сбой
old = load()
for s in old["channels"].values():
    s["mass"] = 0
    s["last_remind"] = clock["t"] - 3600
old.pop("mass_hold")
json.dump(old, open(probe.STATE, "w", encoding="utf-8"))
out = step()
check("XM10a без флагов, но лежит большинство — одно общее напоминание, флаги проставлены",
      len(out) == 1 and "продолжается: не работают 3 из 4" in out[0] and ch_state(B)["mass"] > 0)
world["alive"] = {}
steps(3)

# ---------- XM11: общий сбой кончился — одиночная поломка приходит обычной тревогой ----------
deep_calls.clear()
down(D)
out = steps(2)
check("XM11 после общего сбоя D лёг один — «Недоступен: D» с разбором, а не «ещё и»",
      len(out) == 1 and "Недоступен: D" in out[0] and "ещё и" not in out[0] and "Откуда проверил" in out[0]
      and deep_calls == [[D]] and ch_state(D)["mass"] == 0)
world["alive"] = {}
steps(3)

# ---------- XM12: при общем сбое состояние сохраняется до отправки (дубль, а не тишина) ----------
fresh()
seen = {}


def tg_peek(text):
    seen["unsent"] = load().get("unsent")
    sent.append(text)
    return "ok"


probe.tg_send = tg_peek
down(A, B, C)
out = steps(2)
probe.tg_send = lambda text: sent.append(text) or "ok"
check("XM12 к моменту отправки тревога уже лежит в очереди на диске",
      len(out) == 1 and seen.get("unsent") and "Не работают сразу" in seen["unsent"][0][0])

# ---------- XM15: предел прохода совпадает с TimeoutStartSec службы ----------
unit = open(os.path.join(HERE, "install.sh"), encoding="utf-8").read().split("channel-watch.service <<'UNIT'", 1)[1]
limit = int(unit.split("TimeoutStartSec=", 1)[1].split()[0])
check(f"XM15 SERVICE_LIMIT ({probe.SERVICE_LIMIT}) = TimeoutStartSec службы channel-watch ({limit}), запас на разбор "
      f"не меньше DEEP_MIN", probe.SERVICE_LIMIT == limit
      and probe.SERVICE_LIMIT - probe.SEND_RESERVE - 30 >= probe.DEEP_MIN)

# ---------- MT5: тексты «ещё и» по состоянию и «оба канала» ----------
t = probe.mass_text("more", 4, BASE, BASE - 3600, bad=[(A, "DOWN"), (B, "DOWN"), (D, "FREEZE")], more=[D],
                    more_since=BASE - 120)
t2 = probe.mass_text("more", 4, BASE, BASE - 3600, bad=[(A, "DOWN"), (C, "DOWN"), (D, "FREEZE")], more=[C, D])
t3 = probe.mass_text("back", 4, BASE, BASE - 3600, back=[A, B], still=[], until=BASE)
check("MT5 присоединился канал в «душат» — «Душат ещё и», вперемешку — «Не работают ещё и»; вернулись два — «оба»",
      "🧊 <b>Душат ещё и: D</b>" in t and "Не отвечает" not in t and "Не работают ещё и: C, D</b>" in t2
      and "Снова работают оба канала</b>" in t3 and "все 2" not in t3)

# ---------- XM8g: юнит rf1_blind ----------
blind = dd(DEAD, {"Москва": None, "Timeweb": None})
check("XM8g всё легло, точки не ответили — «сбой сети самой rf1»; кто-то жив — обычные выводы",
      probe.mass_verdict({A: blind, C: blind}, reps, st_of.get, live=False) == probe.RF1_BLIND
      and probe.mass_verdict({A: blind, C: blind}, reps, st_of.get, live=True) != probe.RF1_BLIND
      and probe.mass_verdict({A: dict(blind, late=["Москва", "Timeweb"]), C: blind}, reps, st_of.get,
                             live=False) != probe.RF1_BLIND
      and probe.mass_verdict({A: D_BLOCK, C: blind}, reps, st_of.get, live=False) != probe.RF1_BLIND)

# ---------- XM13: напоминание о раньше легшем канале в проходе, где начался общий сбой — одно сообщение ----------
fresh()
down(A)
out = steps(2)
check("XM13 сначала одиночная тревога о A", len(out) == 1 and "Недоступен" in out[0])
steps(28)
down(B, C)
out = steps(2)
check("XM13a общий сбой начался в проходе напоминания о A — одно сообщение «сразу», без «продолжается»",
      len(out) == 1 and "Не работают сразу 3 канала из 4" in out[0] and "продолжается" not in out[0]
      and "Ещё раньше перестал работать: A" in out[0])
a_since = ch_state(A)["since"]
world["alive"] = {}
out = steps(3)
back = [m for m in out if "Снова работают" in m]
check("XM13b вернулись все — начало сбоя по самому раннему каналу (A), а не по началу общего сбоя",
      len(back) == 1 and f"Не работали с {probe.hm(a_since)}" in back[0])

# ---------- XM14: отложенная тревога смешанной серии не теряет строку о серии ----------
fresh()
st14 = load()
c14 = st14["channels"][C]
c14.update(status="FREEZE", since=clock["t"] - 360, cand="FREEZE", streak=0, quality="FREEZE",
           quality_detail="за 20 с пришло 19 КБ из 512", detail="за 20 с пришло 19 КБ из 512", last_remind=clock["t"])
st14["mass_hold"] = [{"name": C, "status": "FREEZE", "was": "OK", "was_since": clock["t"] - 3600, "mixed": "DOWN"}]
json.dump(st14, open(probe.STATE, "w", encoding="utf-8"))
world["deep"][PORT[C]] = FREEZE_DEEP
out = step()
check("XM14 отложенная тревога смешанной серии вышла одиночной — со строкой «Проверки подряд: недоступен, потом душат»",
      len(out) == 1 and "Душат" in out[0] and "Проверки подряд: недоступен, потом душат" in out[0])
st14 = load()
st14["channels"][C].update(status="DOWN")
st14["mass_hold"] = [{"name": C, "status": "FREEZE", "was": "OK", "was_since": clock["t"] - 3600}]
json.dump(st14, open(probe.STATE, "w", encoding="utf-8"))
step()
check("XM14a состояние сменилось — снятие отложенной тревоги видно в журнале",
      "отложенная тревога (FREEZE) снята" in open(probe.LOG, encoding="utf-8").read())
world["alive"], world["deep"] = {}, {}
steps(6)

print(f"общий сбой каналов: тестов пройдено {ok}")
