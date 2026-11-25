"""Тесты: отказ самой ноды по счётчикам свидетеля. «Нода получила SYN и промолчала» (mute) и «нода сама сбросила» —
в тексте сверки, в выводе разбора сбоя («это не блокировка», «бан адресов точек», «закрылась от адреса сторожа»)
и в сообщении о потерях (часть подключений отбрасывает сама нода). Старые сверки без "mute" — прежнее поведение.
Без сети: PYTHONIOENCODING=utf-8 python test_witness_refusal.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def ser(ok_=0, fail=6, refused=0, n=6):
    return {"n": n, "ok": ok_, "fail": fail, "slow": 0, "refused": refused, "ms": 40,
            "t0": 1000.0, "t1": 1005.0, "mss": 1201}


def wit(seen=6, rep=0, rst_out=0, mute=None):
    w = {"seen": seen, "rep": rep, "rst_out": rst_out, "rst_in": 0}
    if mute is not None:
        w["mute"] = mute
    return w


def pt(tcp="open", tls=True):
    up = tcp == "open"
    return {"host": "h", "addr": "192.0.2.10", "tcp": tcp, "tcp_ms": 40 if up else None, "tls": tls if up else None,
            "bytes": 65536 if up and tls else None, "need": 65536, "end": "ok" if up and tls else None}


DEAD, FINE, NOTLS = pt("timeout"), pt(), pt(tls=False)
DROP, REJ = wit(mute=6), wit(rst_out=6, mute=0)
S_FAIL, S_REF = ser(), ser(fail=0, refused=6)


def dd(direct, agents, abroad=None, series=None, witness=None, external=None, registry=None):
    return {"direct": direct, "agents": agents, "abroad": abroad, "via": "NL1", "trace": None, "external": external,
            "series": series or {}, "sni": {}, "witness": witness or {}, "registry": registry, "neighbours": None}


def gp(verdict, ru_ok, ru_fail, control="up"):
    isps = {"МТС": {"ok": 1 if ru_ok else 0, "fail": 0 if ru_ok else 1}}
    return {"service": "Globalping", "note": "—",
            "summary": {"ru_ok": ru_ok, "ru_fail": ru_fail, "ru_nodata": 0, "isps": isps, "verdict": verdict,
                        "control": control}}


wt, wr, v = blockwatch.witness_text, blockwatch.witness_refusal, blockwatch.deep_verdict

# --- сверка серии ---
rows = [[1001.0 + i, 1201, 2, 0, 0, 0] for i in range(4)] + [[1002.0 + i, 1201, 1, 1, 0, 0] for i in range(2)]
m = blockwatch.witness_match({"ts": 1030.0, "flows": rows + [[1001.0, 1203, 1, 0, 0, 0]]}, ser(ok_=2, fail=4))
check("WR1 сверка считает, сколько дошло, а нода не ответила ничем (mute)",
      m == {"seen": 6, "rep": 0, "rst_out": 0, "rst_in": 0, "mute": 4})
t2 = wt(S_FAIL, DROP)
check("WR2 дошли все, нода молчит — отбрасывает сама нода; «и ответила» больше не пишем",
      wr(S_FAIL, DROP) == "drop" and "отбрасывает сама нода" in t2 and "и ответила" not in t2
      and "и ответила" not in wt(ser(ok_=3, fail=3), wit(mute=0)))
t3 = wt(S_REF, DROP)
SER3R = {"rf1": S_REF, "Москва": S_REF, "Офис": S_REF}
v3 = blockwatch.node_refusal_verdict(dd(DEAD, {"Москва": DEAD, "Офис": DEAD}, None, SER3R,
                                        {"rf1": DROP, "Москва": DROP, "Офис": DROP}),
                                     {"rf1": "tcp", "Москва": "tcp", "Офис": "tcp"}, {"tcp"})
check("WR3 точке пришёл отказ, а нода молчала (свой отказ нода видит как rst_out) — отказ прислал кто-то по дороге; "
      "вывода «отказывает сама нода» нет",
      wr(S_REF, DROP) is None and "сбросил кто-то по дороге" in t3 and "файрвол самой ноды" not in t3 and v3 is None)
check("WR4 дошли все, нода сама сбросила каждое — отказ на самой ноде",
      wr(S_REF, REJ) == "reject" and "сама сбросила каждое" in wt(S_REF, REJ))
t5 = wt(ser(ok_=4, fail=2), wit(mute=2))
check("WR5 часть прошла, на остальные нода промолчала — лимит соединений или перегрузка",
      wr(ser(ok_=4, fail=2), wit(mute=2)) == "part" and "лимит соединений или перегрузка" in t5 and "на 2 не ответила" in t5)
check("WR6 старая сверка без mute — прежнее «сбросил кто-то по дороге»",
      wr(S_REF, wit()) is None and "сбросил кто-то по дороге" in wt(S_REF, wit()))
check("WR7 до ноды дошло меньше WIT_MIN — об отказе ноды не судим",
      wr(ser(fail=2, n=2), wit(seen=2, mute=2)) is None and blockwatch.WIT_MIN == 3)
check("WR8 дошло 4 из 6 — запросы теряются по дороге, отказ ноды не выдумываем",
      wr(ser(ok_=2, fail=4), wit(seen=4, mute=2)) is None
      and "теряются по дороге" in wt(ser(ok_=2, fail=4), wit(seen=4, mute=2)))
check("WR17 нода насчитала 12 при серии из 6 — в тексте «все 6»",
      "все 6" in wt(S_FAIL, wit(seen=12, mute=12)) and "12" not in wt(S_FAIL, wit(seen=12, mute=12)))

# --- вывод разбора: ни с одной российской точки ---
AG = {"Москва": DEAD, "Офис": DEAD}
SER3 = {"rf1": S_FAIL, "Москва": S_FAIL, "Офис": S_FAIL}
t9 = v(dd(DEAD, AG, True, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}, registry=False), "DOWN")
check("WR9 из-за рубежа отвечает, нода молчит всем точкам — это не блокировка; про реестр и блокировку адреса ни слова",
      "это не блокировка" in t9 and "реестр" not in t9 and "блокировку адреса" not in t9 and "с точек rf1, Москва, Офис" in t9)
W6 = wit(rep=6, mute=0)
t10 = v(dd(DEAD, AG, True, SER3, {"rf1": W6, "Москва": W6, "Офис": W6}), "DOWN")
check("WR10 нода отвечала, ответы не вернулись — как раньше «закрыт обратный путь»",
      "закрыт обратный путь" in t10 and "не блокировка" not in t10)
t13a = v(dd(DEAD, AG, False, {k: S_REF for k in SER3}, {"rf1": REJ, "Москва": REJ, "Офис": REJ}), "DOWN")
t13b = v(dd(DEAD, AG, False, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}), "DOWN")
check("WR13 из-за рубежа тоже не отвечает: сбрасывает сама — Xray не слушает порт; молчит — перегрузка или файрвол",
      "не слушает порт" in t13a and "перегрузка или файрвол" in t13b)
t14 = v(dd(DEAD, AG, True, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}, gp("open", 6, 0)), "DOWN")
check("WR14 Globalping открывается, нода молчит нашим точкам — вывод о ноде с хвостом про абонентов",
      "закрылась от адресов проверки" in t14 and "у абонентов домашних провайдеров открывается" in t14)
t14b = v(dd(DEAD, AG, True, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}, gp("closed", 0, 6)), "DOWN")
check("WR14b Globalping закрыт, из-за рубежа отвечает — нода закрыта для России своим файрволом, клиенты из РФ не могут",
      "закрыта для России своим файрволом" in t14b and "клиенты из РФ подключиться не могут" in t14b
      and "это не блокировка" not in t14b)
t16 = v(dd(DEAD, AG, True, SER3, {"rf1": DROP}), "DOWN")
check("WR16 сверена одна rf1 из трёх точек — прежний вывод про блокировку",
      "блокировку адреса ноды из России" in t16 and "не блокировка" not in t16)
t16b = v(dd(DEAD, AG, True, SER3, {"rf1": DROP, "Москва": DROP}), "DOWN")
check("WR16b сверены две из трёх и обе отклонены — вывод о ноде с оговоркой про несверенную точку",
      "это не блокировка" in t16b and "остальные — Офис — сверить не удалось" in t16b)
t16c = v(dd(DEAD, AG, True, SER3, {"rf1": DROP, "Москва": DROP, "Офис": wit(seen=0, mute=0)}), "DOWN")
check("WR16c у одной точки запросы до ноды не дошли — о ноде не судим, прежний вывод",
      "блокировку адреса ноды из России" in t16c and "не блокировка" not in t16c)
t18 = v(dd(DEAD, {"Москва": NOTLS, "Офис": DEAD}, True, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}), "DOWN")
check("WR18 у одной из точек обрыв TLS — счётчики SYN этого не объясняют, вывода о ноде нет",
      "не блокировка" not in t18 and "отклоняет" not in t18 and "закрылась" not in t18)
t19 = v(dd(DEAD, AG, None, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP}), "DOWN")
check("WR19 из-за рубежа проверить не через что — отказывает сама нода, а не блокировка",
      "отказывает сама нода" in t19)

t20 = v(dd(DEAD, {}, True, {"rf1": S_FAIL}, {"rf1": DROP}, gp("closed", 0, 6)), "DOWN")
t20b = v(dd(DEAD, {"Москва": None}, None, {"rf1": S_FAIL}, {"rf1": DROP}, gp("mixed", 3, 3)), "DOWN")
check("WR20 ответила одна rf1, нода её банит, у абонентов тоже закрыто — называем бан rf1, причину для абонентов нет",
      "адрес проверки забанен на ноде" in t20 and "закрыта для России своим файрволом" not in t20
      and "у абонентов домашних провайдеров не открывается (Globalping: 0 из 6)" in t20
      and "по этим данным не сказать" in t20
      and "адрес проверки забанен на ноде" in t20b and "закрыта для России" not in t20b)
d21 = dd(DEAD, AG, False, SER3, {"rf1": DROP, "Москва": DROP, "Офис": DROP})
t21 = v(dict(d21, abroad_sure=1), "DOWN")
t21b = v(dict(d21, abroad_sure=2), "DOWN")
check("WR21 из-за рубежа сверено через один канал — вывод о ноде с оговоркой «неуверенный», через два — без неё",
      "перегрузка или файрвол" in t21 and "неуверенный" in t21 and "неуверенный" not in t21b)

# --- вывод разбора: с части точек работает ---
t11 = v(dd(DEAD, {"Москва": FINE, "Офис": FINE}, None, {"rf1": S_FAIL}, {"rf1": DROP}), "DOWN")
t11b = v(dd(DEAD, {"Москва": FINE, "Офис": FINE}, None, {"rf1": S_FAIL}), "DOWN")
check("WR11 не отвечает только с rf1, нода молчит ей — закрылась от адреса сторожа; без свидетеля — как раньше",
      "закрылась от адреса сторожа" in t11 and "сбой на стороне rf1" in t11b and "сторожа" not in t11b)
SER2 = {"rf1": ser(ok_=6, fail=0), "Москва": S_REF, "Офис": S_REF}
t12 = v(dd(FINE, AG, None, SER2, {"Москва": REJ, "Офис": REJ}), "DOWN")
t12b = v(dd(FINE, AG, None, SER2, {"Москва": REJ}), "DOWN")
check("WR12 нода сама сбрасывает части точек — бан адресов точек; отклонена только часть — прежний вывод с хвостом",
      "бан адресов точек" in t12 and "у отдельных провайдеров" not in t12
      and "у отдельных провайдеров" in t12b and "; Москва: нода сама отклоняет их запросы (бан на ноде)" in t12b)

# --- сообщение о потерях ---
W30 = {"seen": 30, "rep": 0, "rst_out": 0, "rst_in": 0}


def ldata(w):
    s = dict(ser(ok_=26, fail=4, n=30), wit=w)
    return {"ts": 100, "n": 30, "points": ["rf1", "Офис"], "nodes": {"n1": {"rf1": ser(ok_=30, fail=0, n=30), "Офис": s}}}


a_part = blockwatch.loss_alert([("n1", "Офис")], ldata(dict(W30, mute=4)))
a_norm = blockwatch.loss_alert([("n1", "Офис")], ldata(dict(W30, mute=0)))
a_old = blockwatch.loss_alert([("n1", "Офис")], ldata(dict(W30, rep=4)))
check("WR15 нода промолчала на потерянные — «отбрасывает часть подключений»; обычные потери — «Сами ноды работают.»",
      "нода сама отбрасывает часть подключений" in a_part and "Сами ноды работают." not in a_part
      and "Сами ноды работают." in a_norm and "Сами ноды работают." in a_old)

print(f"\nвсё в порядке: {ok} проверок")
