"""Тесты замера потерь: вход ноды закрыт с одной точки целиком (ни одного соединения из первых SERIES_GIVEUP),
а с сервера сторожа нода открывается. Одно сообщение на фактах, точка, у которой закрыто большинство нод, — беда
точки; отчёт, журнал, совместимость со старым состоянием и файлами замера без адреса.
Сеть — только 127.0.0.1: PYTHONIOENCODING=utf-8 python test_loss_shut.py"""
import copy
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import netprobe  # noqa: E402

ok = 0


def check(cond, name):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def ser(fail, n=30, ok_=None, refused=0, **kw):
    return dict({"n": n, "ok": n - fail - refused if ok_ is None else ok_, "fail": fail, "slow": 0, "refused": refused,
                 "ms": 40, "t0": 1000.0, "t1": 1010.0, "mss": 1203}, **kw)


def sh(fail=6, refused=0, **kw):
    """Закрытая серия: ни одно из шести не открылось."""
    return ser(fail, n=6, ok_=0, refused=refused, **kw)


def wit(seen=0, rep=0, rst_out=0, mute=0):
    w = {"seen": seen, "rep": rep, "rst_out": rst_out, "rst_in": 0}
    if mute is not None:
        w["mute"] = mute
    return w


def lines_ok(msg):
    return max(len(x) for x in msg.split("\n")) < 190


# --- 1. константа и сама серия ---
check(netprobe.SERIES_GIVEUP == 6, "SERIES_GIVEUP — шесть первых соединений, как раньше")
s = socket.socket()
s.bind(("127.0.0.1", 0))
free = s.getsockname()[1]
s.close()   # порт свободен — никто не слушает: отказ (или молчание) на каждое соединение
r = netprobe.series("127.0.0.1", free, 20, timeout=2.5, gap=0)
kept = blockwatch.loss_keep(r)
check(r["n"] == netprobe.SERIES_GIVEUP and r["ok"] == 0 and blockwatch.loss_shut(r)
      and kept["addr"] == "127.0.0.1" and blockwatch.loss_shut(kept),
      "серия к закрытому порту бросается после шести, хранится с адресом и читается как «вход закрыт»")
old = {k: v for k, v in sh().items()}
check(blockwatch.loss_keep(old)["addr"] is None and blockwatch.loss_keep(None) is None,
      "серия без адреса (старый агент) хранится как раньше, addr пустой")

# --- ZL8а. loss_shut и pair_judge ---
SELF = blockwatch.SELF
ls, pj, lj = blockwatch.loss_shut, blockwatch.pair_judge, blockwatch.loss_judge
check(ls(sh(6)) and ls(sh(3, 3)) and ls(sh(0, 6)) and not ls(dict(sh(), n=0)) and not ls(None)
      and not ls(ser(5, n=6)) and not ls(ser(6, n=5, ok_=0)) and not ls(ser(4, n=6, ok_=0)),
      "ZL8а loss_shut: 6 из 6 не прошло, 3+3 сброса, 6 сбросов — закрыт; n=0, ok=1, мало соединений — нет")
check(pj({SELF: ser(0), "Офис": sh(6)}, "Офис") == "closed" and pj({SELF: ser(0), "Офис": sh(3, 3)}, "Офис") == "closed"
      and pj({SELF: ser(0), "Офис": sh(0, 6)}, "Офис") == "closed"
      and pj({SELF: sh(6), "Офис": sh(6)}, "Офис") is None and pj({"Офис": sh(6)}, "Офис") is None
      and pj({SELF: None, "Офис": sh(6)}, "Офис") is None
      and pj({SELF: ser(16, ok_=14), "Офис": sh(6)}, "Офис") is None
      and pj({SELF: ser(15), "Офис": sh(6)}, "Офис") == "closed"
      and pj({SELF: sh(6)}, SELF) is None and pj({SELF: sh(6), "Офис": ser(0)}, SELF) is None,
      "ZL8а pair_judge: с точки закрыто, с rf1 открывается хотя бы половина — closed; rf1 тоже закрыт или его нет — None; "
      "сама rf1 — никогда не closed")
check(all(pj({SELF: ser(0), "Офис": x}, "Офис") == lj(x) for x in (ser(3), ser(0), ser(1), None, ser(0, n=4), ser(5, n=6))),
      "ZL8а прочие серии — как loss_judge")

# --- ZL13а. Офис -> de7 закрыт, rf1 30/30 ---
PTS = [SELF, "Москва", "Офис"]


def data(ts, office, rf1=None, moscow=None):
    return {"ts": ts, "n": 30, "points": PTS,
            "nodes": {"de7": {SELF: rf1 or ser(0), "Москва": moscow or ser(0), "Офис": office},
                      "nl2": {SELF: ser(0), "Москва": ser(0), "Офис": ser(0)}}}


st = {}
closed = lambda: sh(6, wit=wit(seen=0))
a1 = blockwatch.loss_step(st, data(100, closed()))
a2 = blockwatch.loss_step(st, data(200, closed()))
a3 = blockwatch.loss_step(st, data(300, closed()))
L = a2[0].split("\n") if len(a2) == 1 else []
check(a1 == [] and len(a2) == 1 and L[0] == "🚪 <b>Вход ноды закрыт с одной точки</b>"
      and "с точки не открылось ни одно соединение" in L[1] and "📍 Откуда: <b>Офис</b>" in L
      and "• <b>DE7</b> — с точки 0 из 6, с сервера сторожа проходит 30 из 30" in L
      and any(x.startswith("   ↳ до ноды не дошло ни одно из 6") for x in L)
      and "С других точек к этой ноде: Москва — проходит" in L and "📉" not in a2[0] and "NL2" not in a2[0]
      and "клиенты такого же провайдера к этой ноде не подключаются" in a2[0]
      and a3 == [] and lines_ok(a2[0]) and st["loss"]["lvl"]["de7|Офис"]["lvl"] == "closed"
      and st["loss"]["pt"]["Офис"]["lvl"] == "ok",
      "ZL13а вход ноды закрыт с точки два замера подряд — одно сообщение на фактах, без «потерь»; дальше не повторяем")

# --- ZL13б. что видела нода, другой адрес ---
def one(office, rf1=None, moscow=None):
    d = data(100, office, rf1, moscow)
    return blockwatch.shut_alert([("de7", "Офис")], d)


m_rej = one(sh(0, 6, wit=wit(seen=6, rst_out=6, mute=0)))
m_path = one(sh(0, 6, wit=wit(seen=6, rst_out=0, mute=None)))
m_vague = one(sh(6, wit=wit(seen=6, rep=0, rst_out=0, mute=None)))
m_drop = one(sh(6, wit=wit(seen=6, mute=6)))
m_addr = one(sh(6, addr="198.51.100.7"), rf1=ser(0, addr="203.0.113.9"), moscow=sh(6))
m_same = one(sh(6, addr="203.0.113.9"), rf1=ser(0, addr="203.0.113.9"))
check("сама сбросила" in m_rej and "сбросил кто-то по дороге" in m_path
      and "где теряется" not in m_vague and "↳" not in m_vague
      and "отбрасывает сама нода" in m_drop and "нода сама не принимает подключения" in m_drop
      and "↳ имя ноды у точки дало другой адрес, чем у сервера сторожа" in m_addr
      and "198.51.100.7" not in m_addr and "203.0.113.9" not in m_addr
      and "Москва — тоже закрыт" in m_addr and "другой адрес" not in m_same
      and all(lines_ok(m) for m in (m_rej, m_path, m_vague, m_drop, m_addr)),
      "ZL13б сверка с нодой: сбросила сама / сбросил кто-то по дороге / общая фраза не выводится; другой адрес — фактом, "
      "без самих адресов")

# --- ZL13в. rf1 тоже 0/6 — нода недоступна целиком, тут не судим ---
st_c = {}
c = [blockwatch.loss_step(st_c, data(t, sh(6), rf1=sh(6))) for t in (100, 200, 300)]
check(c == [[], [], []] and st_c["loss"]["lvl"]["de7|Офис"]["lvl"] == "ok" and st_c["loss"]["pt"]["Офис"]["lvl"] == "ok",
      "ZL13в с сервера сторожа нода тоже не открывается — молчим (это видно по каналам)")

# --- ZL13г. выход из закрытия ---
st_e = copy.deepcopy(st)
e1 = blockwatch.loss_step(st_e, data(400, ser(0)))
e2 = blockwatch.loss_step(st_e, data(500, ser(0)))
check(e1 == [] and len(e2) == 1 and e2[0].startswith("✅ <b>Вход ноды снова открыт</b>")
      and "• DE7 — проходят все 30 соединений" in e2[0] and "Потери соединений прошли" not in e2[0]
      and st_e["loss"]["lvl"]["de7|Офис"]["lvl"] == "ok",
      "ZL13г два чистых замера после закрытого входа — «Вход ноды снова открыт»")
st_f = copy.deepcopy(st)
f1 = blockwatch.loss_step(st_f, data(400, ser(4)))
f2 = blockwatch.loss_step(st_f, data(500, ser(4)))
check(f1 == [] and len(f2) == 1 and f2[0].startswith("📉 <b>Потери соединений до нод</b>")
      and st_f["loss"]["lvl"]["de7|Офис"]["lvl"] == "bad",
      "ZL13г из закрытого входа в частичные потери — обычное сообщение о потерях")
check(blockwatch.loss_end([("de7", "Офис")], data(1, ser(0))).startswith("✅ <b>Потери соединений прошли</b>"),
      "заголовок loss_end по умолчанию прежний")

# --- ZL15а. отчёт ---
bl = blockwatch.block_line
line = bl(st, 350)
check("⚠️ вход ноды закрыт: de7 — с точки Офис" in line and "потерь соединений с точек нет" not in line
      and "вход ноды закрыт" not in (bl(st, 300 + blockwatch.LOSS_STALE + 1) or "")
      and blockwatch.loss_shut_now(st, 300 + blockwatch.LOSS_STALE + 1) == []
      and blockwatch.loss_shut_now(st, 350) == [("de7", "Офис")]
      and "потерь соединений с точек нет" in bl(st_e, 550),
      "ZL15а в отчёте — где закрыт вход; «потерь нет» только когда нет ни потерь, ни закрытых; замер устарел — не упоминаем")

# --- ZL35б. с точки закрыто большинство нод — беда точки ---
NODES5 = ["de1", "de7", "nl1", "nl2", "pl1"]


def dz(ts, office):
    return {"ts": ts, "n": 30, "points": PTS,
            "nodes": {n: {SELF: ser(0), "Москва": ser(0), "Офис": office(n)} for n in NODES5}}


st_p = {}
b1 = blockwatch.loss_step(st_p, dz(100, lambda n: sh(6)))
b2 = blockwatch.loss_step(st_p, dz(200, lambda n: sh(6)))
b3 = blockwatch.loss_step(st_p, dz(300, lambda n: sh(6)))
check(b1 == [] and len(b2) == 1 and "С точки «Офис» не открываются 5 нод из 5" in b2[0]
      and "DE1, DE7, NL1, NL2, PL1 — ни одного соединения" in b2[0] and "Похоже на:</b> блокировка наших адресов" in b2[0]
      and "в разборе сбоя данные точки учитываю" in b2[0]
      and "🚪" not in b2[0] and b3 == [] and st_p["loss"]["skip"] == [] and st_p["loss"]["pt"]["Офис"]["lvl"] == "shut"
      and all(v["lvl"] == "ok" for k, v in st_p["loss"]["lvl"].items() if k.endswith("|Офис"))
      and "точка «Офис» — не открывает наши ноды" in bl(st_p, 350),
      "ZL35б все ноды закрыты с точки — одно сообщение о точке, по нодам не шлём, её пары не судим, строка в отчёте; "
      "в разборе сбоя точка учитывается (так выглядит и блокировка у её провайдера)")
b4 = blockwatch.loss_step(st_p, dz(400, lambda n: ser(0)))
b5 = blockwatch.loss_step(st_p, dz(500, lambda n: ser(0)))
check(b4 == [] and len(b5) == 1 and "Точка «Офис» снова в порядке" in b5[0] and st_p["loss"]["skip"] == [],
      "ZL35б точка снова открывает ноды — «снова в порядке»")

# --- ZL35в. закрытые и потери вместе — проблемы с сетью, текст называет и те, и другие ---
mix = {"de1": sh(6), "de7": ser(4), "nl1": sh(6), "nl2": ser(0), "pl1": ser(0)}
d_mix = dz(100, lambda n: mix[n])
check(blockwatch.point_view(d_mix, "Офис") == "noisy", "ZL35в 2 закрыты + 1 с потерями из 5 — noisy")
st_m = {}
blockwatch.loss_step(st_m, d_mix)
g2 = blockwatch.loss_step(st_m, dz(200, lambda n: mix[n]))
check(len(g2) == 1 and "проблемы с сетью" in g2[0] and "к 1 нодам из 5 сразу (DE7)" in g2[0]
      and "к 2 — не открывается ни одно (DE1, NL1)" in g2[0],
      "ZL35в в сообщении — и нода с потерями, и закрытые: число и список не расходятся")
check(blockwatch.point_view(dz(1, lambda n: ser(4) if n in ("de1", "de7", "nl1") else ser(0)), "Офис") == "noisy"
      and blockwatch.point_view(dz(1, lambda n: sh(6) if n in ("de1", "de7") else ser(0)), "Офис") == "ok"
      and blockwatch.point_view(dz(1, lambda n: None), "Офис") == "blind",
      "point_view: одни потери к большинству — по-прежнему noisy; две закрытые из пяти — ok; ничего — blind")

# --- ZL16а. журнал ---
d_log = {"ts": 1, "n": 30, "points": PTS,
         "nodes": {"de7": {SELF: ser(0), "Москва": ser(0, refused=3), "Офис": sh(6)},
                   "nl2": {SELF: ser(4), "Москва": ser(0), "Офис": ser(0)}}}
log = blockwatch.loss_log(d_log)
check("de7 — Офис закрыт 0/6" in log and "de7 — Москва 0/30, сброшено 3" in log and "nl2 — rf1 4/30" in log
      and "сброшено" not in log.split("nl2")[1],
      "ZL16а журнал: закрытый вход — «закрыт 0/6», серия со сбросами видна, сбросы названы")

# --- совместимость ---
st_old = {"loss": {"ts": 50, "n": 30, "lvl": {"de7|Офис": {"lvl": "bad", "cand": "bad", "n": 0},
                                               "nl2|Офис": {"lvl": "ok", "cand": "ok", "n": 0}},
                   "pt": {"Офис": {"lvl": "noisy", "cand": "noisy", "n": 0, "since": 10}}, "skip": ["Офис"]}}
d_old = data(100, ser(4))
for pts in d_old["nodes"].values():
    for r in pts.values():
        r.pop("addr", None)
try:
    o1 = blockwatch.loss_step(st_old, d_old)
    o2 = blockwatch.loss_step(st_old, data(200, ser(4)))
    good = isinstance(o1, list) and any("снова в порядке" in m for m in o2)
except Exception as e:  # noqa: BLE001
    good = False
    print(repr(e))
check(good, "старое состояние без closed/shut и данные без addr проходят loss_step")

# --- ZL40. «не открывает ноды»: причина по счётчикам нод ---
d_ban = dz(100, lambda n: sh(6, wit=wit(seen=6, mute=6)))
d_way = dz(100, lambda n: sh(6, wit=wit(seen=0)))
d_unk = dz(100, lambda n: sh(6))
check("бан адреса точки на нодах" in blockwatch.shut_why(d_ban, "Офис", NODES5)
      and "блокировку наших адресов у провайдера" in blockwatch.shut_why(d_way, "Офис", NODES5)
      and "не различить" in blockwatch.shut_why(d_unk, "Офис", NODES5),
      "ZL40 нода получила и молчит — бан на нодах; не дошло ни одно — блокировка у провайдера точки; счётчиков нет — "
      "не различить")

# --- ZL41. закрытый вход, а потом у точки общая беда — пара не пропадает молча ---
st_a = {}
blockwatch.loss_step(st_a, data(100, sh(6, wit=wit(seen=0))))
blockwatch.loss_step(st_a, data(200, sh(6, wit=wit(seen=0))))
mix5 = {"de1": sh(6), "de7": ser(4), "nl1": sh(6), "nl2": ser(4), "pl1": ser(0)}
# точка становится noisy (нод теперь пять: de7 — из прежнего замера)
blockwatch.loss_step(st_a, dz(300, lambda n: mix5[n]))
a4 = blockwatch.loss_step(st_a, dz(400, lambda n: mix5[n]))
check(st_a["loss"]["pt"]["Офис"]["lvl"] == "noisy" and any("ранее сообщал — вход закрыт: DE7" in m for m in a4)
      and st_a["loss"]["lvl"]["de7|Офис"]["lvl"] == "ok" and st_a["loss"]["skip"] == ["Офис"],
      "ZL41 закрытый вход DE7 растворился в беде точки — об этом одна строка, пара сброшена")

# --- ZL42. закрытый вход, а потом нода не открывается и с rf1 — «закрыт с одной точки» больше не держим ---
st_c = {}
blockwatch.loss_step(st_c, data(100, sh(6)))
blockwatch.loss_step(st_c, data(200, sh(6)))
c3 = blockwatch.loss_step(st_c, data(300, sh(6), rf1=sh(6)))
check(st_c["loss"]["lvl"]["de7|Офис"]["lvl"] == "ok" and c3 == [] and blockwatch.loss_shut_now(st_c, 350) == [],
      "ZL42 нода недоступна целиком (и с rf1) — закрытая пара сброшена молча, в отчёте не висит")

# --- ZL43. заголовок о закрытом входе без общего числа: у каждой ноды своё ---
d_two = {"ts": 1, "n": 30, "points": PTS,
         "nodes": {"de7": {SELF: ser(0), "Москва": ser(0), "Офис": sh(6)},
                   "nl2": {SELF: ser(0), "Москва": ser(0), "Офис": ser(30, n=30, ok_=0)}}}
t2 = blockwatch.shut_alert([("de7", "Офис"), ("nl2", "Офис")], d_two)
check("ни одно из" not in t2.split("\n")[1] and "DE7</b> — с точки 0 из 6" in t2 and "NL2</b> — с точки 0 из 30" in t2,
      "ZL43 число попыток — у каждой ноды, а не одно на всех в заголовке")

print(f"\nвсё прошло: {ok}")
