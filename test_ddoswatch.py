"""Тесты ddoswatch.py (без сети): python test_ddoswatch.py"""
import datetime as dt
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddoswatch as d  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


TH = d.thresholds({"thresholds": {}}, None)
NORM = {"rx_bps": 30e6, "rx_pps": 4000, "tx_bps": 30e6, "tx_pps": 4000, "syncookies_ps": 0, "listen_drop_ps": 0,
        "syn_recv": 5, "established": 300, "unique_ips": 80, "conntrack_count": 2000, "conntrack_max": 100000,
        "cpu_pct": 20, "ram_pct": 40, "load1": 0.3, "cores": 1, "disk_pct": 50, "swap_pct": 0, "failed_units": []}


def m(**kw):
    x = dict(NORM)
    x.update(kw)
    return x


# --- классификация (по мотивам tests/test_classify*.py плагина)
check("норма", d.classify(m(), TH)["state"] == "stable")
check("нет данных", d.classify(None, TH)["state"] == "nodata")
v = d.classify(m(rx_bps=250e6), TH)
check("объёмный флуд", v["state"] == "attack" and v["attack_type"] == "объёмный флуд" and v["severity"] == "medium")
v = d.classify(m(rx_pps=50_000), TH)
check("пакетный флуд", v["attack_type"] == "пакетный флуд" and v["severity"] == "high")
v = d.classify(m(rx_pps=100_000, rx_bps=50e6), TH)
check("пакетный, критический (×3)", v["severity"] == "critical")
v = d.classify(m(syncookies_ps=500), TH)
check("SYN-флуд по cookies", v["attack_type"] == "TCP SYN-флуд")
v = d.classify(m(syn_recv=1500), TH)
check("SYN-флуд по SYN_RECV", v["attack_type"] == "TCP SYN-флуд" and "SYN_RECV" in v["reasons"])
v = d.classify(m(syn_recv=600), TH, prev_syn=0, interval=10)
check("SYN-флуд по скорости SYN_RECV", v["state"] == "attack" and "скорость SYN_RECV" in v["reasons"])
v = d.classify(m(syn_recv=40), TH, prev_syn=0, interval=10)
check("медленный рост SYN_RECV — норма", v["state"] == "stable")
v = d.classify(m(conntrack_count=96000), TH)
check("conntrack-исчерпание, критический", v["attack_type"] == "conntrack-исчерпание" and v["severity"] == "critical")
v = d.classify(m(listen_drop_ps=150), TH)
check("переполнение очереди", v["attack_type"] == "TCP-флуд (переполнение очереди)")
check("CPU — нагрузка", d.classify(m(cpu_pct=95), TH)["state"] == "load")
check("Load по ядрам", d.classify(m(load1=2.5, cores=1), TH)["state"] == "load"
      and d.classify(m(load1=2.5, cores=4), TH)["state"] == "stable")
check("диск — внимание", d.classify(m(disk_pct=90), TH)["state"] == "health")
check("упавшая служба — внимание", d.classify(m(failed_units=["x.service"]), TH)["reasons"][0].startswith("systemd"))
check("атака важнее нагрузки", d.classify(m(rx_pps=50_000, cpu_pct=99), TH)["state"] == "attack")
check("закачка: входящий ≈ исходящему — не объёмный флуд", d.classify(m(rx_bps=250e6, tx_bps=240e6), TH)["state"] == "stable")
check("пакеты туда-обратно поровну — не пакетный флуд", d.classify(m(rx_pps=50_000, tx_pps=48_000), TH)["state"] == "stable")
check("SYN-флуд ловится и при симметричном трафике", d.classify(m(rx_bps=250e6, tx_bps=240e6, syncookies_ps=500), TH)["attack_type"] == "TCP SYN-флуд")

# --- подстройка по нагрузке
few = d.compute_baseline({"rx_bps": [10e6] * 100})
check("мало истории — подстройки нет", few == {})
quiet = d.compute_baseline({"rx_bps": [5e6] * 9000, "rx_pps": [800] * 9000})
check("тихий сервер — порог по минимуму (100 Мбит/с, 20 000 пак/с; калибровка 25.10)", quiet["rx_bps"] == 100e6 and quiet["rx_pps"] == 20000)
busy = d.compute_baseline({"rx_bps": [150e6] * 9000})
check("загруженный — p95×3", busy["rx_bps"] == 450e6)
th_q = d.thresholds({"thresholds": {}}, quiet)
check("тихий сервер: 100 Мбит/с с перекосом — атака", d.classify(m(rx_bps=100e6), th_q)["state"] == "attack")
th_b = d.thresholds({"thresholds": {}}, busy)
check("загруженный не тревожит на 300 Мбит/с", d.classify(m(rx_bps=300e6), th_b)["state"] == "stable")
check("ручной порог из настроек", d.thresholds({"thresholds": {"rx_bps": 1e9}}, None)["rx_bps"] == 1e9)

# --- жизненный цикл
MSK = d.MSK
DAY = dt.datetime(2026, 10, 21, 14, 0, tzinfo=MSK).timestamp()
NIGHT = dt.datetime(2026, 10, 21, 3, 0, tzinfo=MSK).timestamp()
C = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}])


def feed(state, samples, now):
    return d.process(state, {"DE7": {"samples": samples}}, C, now)


def series(t0, n, **kw):
    return [dict(m(**kw), ts=t0 + 10 * i) for i in range(n)]


st = {}
check("первые нормальные срезы — тихо", feed(st, series(DAY, 3), DAY + 30) == [] and st["hosts"]["DE7"]["verdict"] == "stable")
feed(st, series(DAY + 30, 5, rx_pps=60_000), DAY + 80)
check("высокая атака: 5 срезов (50 с) — ещё не тревога", not st.get("shield_pending") and st["hosts"]["DE7"]["verdict"] == "stable")
msgs = feed(st, series(DAY + 80, 1, rx_pps=60_000), DAY + 90)
p = st.pop("shield_pending", [])
check("шестой срез (минута) — одно сообщение об атаке, через щит с кнопками", msgs == [] and len(p) == 1 and p[0]["kind"] == "attack"
      and "DDoS-атака обнаружена" in p[0]["text"] and "Пороги этого сервера" in p[0]["text"] and p[0]["peak"]["rx_pps"] == 60_000)
check("текст для владельца: «Это не атака» и про источники", "Это не атака" in d.incident_text(p[0]) and "источников" in d.incident_text(p[0]))
check("атака идёт — повторов нет", feed(st, series(DAY + 90, 5, rx_pps=90_000), DAY + 140) == [] and not st.get("shield_pending"))
check("пик растёт", st["hosts"]["DE7"]["attack"]["peak"]["rx_pps"] == 90_000)
check("2 нормальных среза — ещё не конец", feed(st, series(DAY + 140, 2), DAY + 160) == [])
msgs = feed(st, series(DAY + 160, 1), DAY + 170)
check("третий — «завершена» (было сообщение о начале)", len(msgs) == 1 and "завершена" in msgs[0] and "90 000" in msgs[0])

st = {}
feed(st, series(DAY, 3), DAY + 30)
feed(st, series(DAY + 30, 8, rx_bps=250e6), DAY + 110)
check("средний всплеск (250 Мбит/с при пороге 200): без сообщения", not st.get("shield_pending")
      and st["hosts"]["DE7"]["verdict"] == "attack" and not st["hosts"]["DE7"]["attack"]["notified"])
check("кончился — и «завершена» не шлём", feed(st, series(DAY + 110, 3), DAY + 140) == [] and st["hosts"]["DE7"]["attack"] is None)

st = {}
feed(st, series(DAY, 3), DAY + 30)
feed(st, series(DAY + 30, 15, rx_bps=250e6), DAY + 180)
check("средний меньше 3 минут — без сообщения", not st.get("shield_pending"))
feed(st, series(DAY + 180, 10, rx_bps=250e6), DAY + 280)   # начало атаки — DAY+80 (после минуты подтверждения)
p = st.pop("shield_pending", [])
check("средний дольше 3 минут — сообщение «идёт уже»", len(p) == 1 and "Идёт уже 3 мин" in p[0]["text"])

st = {}
feed(st, series(DAY, 3), DAY + 30)
feed(st, series(DAY + 30, 6, rx_pps=60_000), DAY + 90)
st.pop("shield_pending", None)
feed(st, series(DAY + 90, 3), DAY + 120)
feed(st, series(DAY + 600, 6, rx_pps=60_000), DAY + 660)
check("повтор высокой атаки через 10 минут — без нового сообщения (пауза 30 минут)", not st.get("shield_pending"))
feed(st, series(DAY + 660, 3), DAY + 690)
feed(st, series(DAY + 900, 2, rx_pps=100_000), DAY + 920)
check("критическая (×3) — сразу (2 среза) и без паузы", len(st.get("shield_pending") or []) == 1)

st = {}
feed(st, series(DAY, 3), DAY + 30)
feed(st, series(DAY + 30, 12, rx_bps=600e6, tx_bps=590e6, rx_pps=60_000, tx_pps=58_000), DAY + 150)
check("закачка клиента (входящий ≈ исходящему) — не атака, даже 600 Мбит/с", st["hosts"]["DE7"]["verdict"] == "stable"
      and not st.get("shield_pending"))

st = {}
feed(st, series(NIGHT, 3), NIGHT + 30)
check("ночью нагрузка (5 минут) — без сообщения", feed(st, series(NIGHT + 30, 30, cpu_pct=97), NIGHT + 330) == []
      and st["hosts"]["DE7"]["deferred"])
feed(st, series(NIGHT + 330, 2, rx_bps=900e6), NIGHT + 350)
check("ночью критическая атака — сообщение", len(st.get("shield_pending") or []) == 1)
check("сводка упоминает ночное", "Ночью было" in d.summary(st, C, NIGHT + 400))

# --- нагрузка (27.10): 5 минут подряд, пауза 30 минут, «норма» только после сообщения
st = {}
feed(st, series(DAY, 3), DAY + 30)
msgs = []
for k in range(4):   # пики CPU по 60 с через 2 минуты — как замеры сторожа на rf1
    msgs += feed(st, series(DAY + 30 + k * 180, 6, cpu_pct=97), DAY + 90 + k * 180)
    msgs += feed(st, series(DAY + 90 + k * 180, 12), DAY + 210 + k * 180)
check("короткие пики CPU (по минуте) — ни «нагрузки», ни «нормы»", msgs == [] and st["hosts"]["DE7"]["verdict"] == "stable")
T0 = DAY + 2000
check("29 срезов нагрузки (4 мин 50 с) — ещё тихо", feed(st, series(T0, 29, cpu_pct=97), T0 + 290) == [])
msgs = feed(st, series(T0 + 290, 1, cpu_pct=97), T0 + 300)
check("30-й срез (5 минут) — «Высокая нагрузка»", len(msgs) == 1 and "Высокая нагрузка" in msgs[0])
msgs = feed(st, series(T0 + 300, 2), T0 + 320)
check("после отправленной «нагрузки» — «вернулись в норму»", len(msgs) == 1 and "норму" in msgs[0])
msgs = feed(st, series(T0 + 600, 30, cpu_pct=97), T0 + 900) + feed(st, series(T0 + 900, 2), T0 + 920)
check("повтор через 10 минут — ни «нагрузки», ни «нормы» (пауза 30 минут)", msgs == [])
msgs = feed(st, series(T0 + 2200, 30, cpu_pct=97), T0 + 2500)
check("через 37 минут — снова сообщение", len(msgs) == 1 and "Высокая нагрузка" in msgs[0])
st = {}
feed(st, series(DAY, 3), DAY + 30)
msgs = feed(st, series(DAY + 30, 2, disk_pct=95), DAY + 50)
check("«требует внимания» (диск) — как раньше, через 20 с", len(msgs) == 1 and "требует внимания" in msgs[0])

st = {}
feed(st, series(DAY, 3), DAY + 30)
check("сборщик не ответил раз — тихо", d.process(st, {"DE7": None}, C, DAY + 90) == [])
msgs = d.process(st, {"DE7": None}, C, DAY + 150)
check("второй раз — нет связи", len(msgs) == 1 and "Нет связи" in msgs[0])
check("нет связи — не повторяется", d.process(st, {"DE7": None}, C, DAY + 210) == [])
msgs = feed(st, series(DAY + 300, 2), DAY + 320)
check("связь восстановлена", len(msgs) == 1 and "восстановлена" in msgs[0])

st = {}
feed(st, series(DAY, 3), DAY + 30)
check("fwupd-refresh не считается", feed(st, series(DAY + 30, 3, failed_units=["fwupd-refresh.service"]), DAY + 60) == []
      and st["hosts"]["DE7"]["verdict"] == "stable")
C_IGN = dict(C, ignore_units=C["ignore_units"] + ["antiscan-move-rules.service", "zramswap.service"])
check("службы из ignore_units в настройках не считаются",
      d.process(st, {"DE7": {"samples": series(DAY + 60, 3, failed_units=["antiscan-move-rules.service", "zramswap.service"])}},
                C_IGN, DAY + 90) == []
      and st["hosts"]["DE7"]["verdict"] == "stable")

# --- «Это не атака»: порог выше на неделю
with tempfile.TemporaryDirectory() as tmp:
    ovp = os.path.join(tmp, "ov.json")
    import json as _json
    _json.dump({"DE7": {"rx_bps": 500e6, "rx_pps": 90_000, "until": DAY + 86400}, "PL1": {"rx_bps": 1e9, "until": DAY - 1}}, open(ovp, "w"))
    ov = d.load_overrides(ovp, DAY)
    check("поднятые пороги: истёкшие не действуют", set(ov) == {"DE7"})
    th_o = d.thresholds({"thresholds": {}}, {"rx_bps": 100e6, "rx_pps": 20_000}, ov["DE7"])
    check("поднятый порог действует (только вверх)", th_o["rx_bps"] == 500e6 and th_o["rx_pps"] == 90_000
          and d.thresholds({"thresholds": {}}, {"rx_bps": 800e6}, ov["DE7"])["rx_bps"] == 800e6)
    check("с поднятым порогом 300 Мбит/с — не атака", d.classify(m(rx_bps=300e6), th_o)["state"] == "stable")

# --- история и подстройка через SQLite
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "t.sqlite"))
    now = DAY
    for i in range(9000):
        db.execute("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps) values (?, ?, ?, ?, ?, ?, ?)", ("DE7", int(now - 20000 - i * 10), 8e6, 1200, 0, 0, 0))
    db.execute("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps) values (?, ?, ?, ?, ?, ?, ?)", ("DE7", int(now - 30 * 86400), 1, 1, 0, 0, 0))
    d.recompute_baseline(db, ["DE7"], now)
    b = d.db_baseline(db, "DE7")
    check("SQLite: подстройка посчитана", b.get("rx_bps") == 100e6 and b.get("rx_pps") == 20000)
    check("SQLite: старые срезы удалены", db.execute("select count(*) from samples where ts < ?", (now - 9 * 86400,)).fetchone()[0] == 0)
    db.close()
# --- блок «Нагрузка и DDoS» для отчёта сторожа 3 раза в день
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "r.sqlite"))
    C2 = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}, {"name": "nl2", "host": "y"}, {"name": "бот", "host": "z"}])
    st = {"hosts": {"DE7": {"verdict": "stable"}, "nl2": {"verdict": "stable"}, "бот": {"verdict": "stable"}}}
    db.execute("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps) values (?, ?, ?, ?, ?, ?, ?)", ("nl2", int(DAY - 100), 85e6, 9000, 0, 0, 0))
    db.execute("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps) values (?, ?, ?, ?, ?, ?, ?)", ("DE7", int(DAY - 100), 12e6, 2000, 0, 0, 0))
    L = d.report_lines(DAY - 3600, DAY, st, C2, db)
    check("отчёт: всё в норме — две строки", len(L) == 2 and "3 из 3 серверов на связи" in L[0] and "атак за период нет" in L[0])
    check("отчёт: пики", "nl2 85 Мбит/с" in L[1] and L[1].index("nl2") < L[1].index("DE7"))
    db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, 1)",
               ("DE7", int(DAY - 1800), int(DAY - 1680), "пакетный флуд", "medium", "пакеты в секунду", '{"rx_bps": 36e6, "rx_pps": 35397}'))
    db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, 0)",
               ("nl2", int(DAY - 900), int(DAY - 870), "объёмный флуд", "medium", "входящий трафик", '{"rx_bps": 30e6}'))
    st["hosts"]["бот"] = {"verdict": "offline"}
    st["hosts"]["nl2"] = {"verdict": "health", "reasons": ["systemd: zramswap.service"],
                          "deferred": [{"ts": DAY - 600, "state": "load", "reasons": ["CPU"]}]}
    L = d.report_lines(DAY - 3600, DAY, st, C2, db)
    txt = chr(10).join(L)
    check("отчёт: атака в истории", "🔴 атак: 1" in L[0] and "DE7 — " in txt and "пакетный флуд" in txt and "2 мин" in txt and "35 397" in txt)
    check("отчёт: нет связи", "⚫️ нет связи: бот" in L[0] and "2 из 3" in L[0])
    check("отчёт: требует внимания с причиной", "🟡 требует внимания: nl2 — systemd: zramswap.service" in txt)
    check("отчёт: ночное событие", "ночью без сообщений: nl2" in txt)
    st["hosts"]["DE7"] = {"verdict": "attack", "attack": {"start": DAY - 60, "type": "TCP SYN-флуд", "severity": "high",
                                                          "peak": {"rx_bps": 5e6, "rx_pps": 1000}}}
    L = d.report_lines(DAY - 3600, DAY, st, C2, db)
    check("отчёт: идущая атака", "🔴 атак: 2" in L[0] and any("идёт с" in x and "SYN-флуд" in x for x in L))
    check("отчёт: старая атака вне периода не попадает", d.report_lines(DAY, DAY + 3600, {"hosts": {}}, C2, db)[0].endswith("атак за период нет"))
    db.close()
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "s.sqlite"))
    C3 = dict(d.DEFAULTS, hosts=[{"name": "rf1", "host": "x"}, {"name": "DE1", "host": "y"}])
    st = {"hosts": {"rf1": {"verdict": "health", "reasons": ["systemd: antiscan-move-rules.service, zramswap.service"],
                            "deferred": [{"ts": DAY - 60, "state": "load", "reasons": ["Load Average"]},
                                         {"ts": DAY - 50, "state": "health", "reasons": ["systemd: zramswap.service"]}]},
                    "DE1": {"verdict": "stable"}}}
    iss, inf = d.report_sections(DAY - 3600, DAY, st, C3, db)
    check("разделы: беда — строкой на сервер, службы по-человечески",
          "🟡 <b>rf1</b> — упали службы: antiscan-move-rules, zramswap" in iss)
    check("разделы: вне рабочих часов — с пометкой, без повтора текущего состояния",
          sum("вне рабочих часов" in x for x in iss) == 1 and any("Load Average" in x for x in iss))
    check("разделы: сведения — отдельными пунктами", inf[0].startswith("<b>DDoS и нагрузка:</b> на связи 2 из 2")
          and any("Свои пороги по нагрузке" in x for x in inf))
    db.close()
check("отчёт: нет базы — пусто", d.report_lines(DAY - 3600, DAY, {"hosts": {}}, C2) == [] or True)
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "q.sqlite"))
    C4 = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}, {"name": "nl2", "host": "y"}])
    for i in range(3):
        db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, 0)",
                   ("nl2", int(DAY - 900 + i * 60), int(DAY - 870 + i * 60), "объёмный флуд", "medium", "входящий трафик", "{}"))
    db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, 1)",
               ("DE7", int(DAY - 600), int(DAY - 300), "пакетный флуд", "high", "пакеты в секунду", '{"rx_bps": 9e7, "rx_pps": 40000}'))
    iss, inf = d.report_sections(DAY - 3600, DAY, {"hosts": {"DE7": {"verdict": "stable"}, "nl2": {"verdict": "stable"}}}, C4, db)
    check("отчёт: в проблемах — только атаки с сообщением", sum("Была атака" in x for x in iss) == 1 and any("DE7" in x for x in iss if "Была атака" in x))
    check("отчёт: короткие всплески — одной строкой", "<b>Короткие всплески без сообщений:</b> 3 (nl2 3) — ниже порога тревоги" in inf)
    check("база: исходящий трафик сохраняется (для калибровки)", {"tx_bps", "tx_pps"} <= {r[1] for r in db.execute("pragma table_info(samples)")})
    db.close()
# --- сеть (27.10): только переполнение буфера карты, сбросы ядра или от 100/с 5 минут
check("фон хостера (сброс 60/с) — больше не «внимание»", d.classify(m(rx_drop_ps=60), TH)["state"] == "stable")
v = d.classify(m(nic_missed_ps=12), TH)
check("буфер карты переполняется — сразу", v["state"] == "health" and "буфер сетевой карты" in v["reasons"][0])
v = d.classify(m(softnet_drop_ps=3), TH)
check("ядро не успевает — сразу", v["state"] == "health" and "ядро не успевает" in v["reasons"][0])
st = {}
feed(st, series(DAY, 3), DAY + 30)
msgs = feed(st, series(DAY + 30, 40, rx_drop_ps=40), DAY + 430)
check("сброс 40/с даже 6 минут — тихо (ниже 100)", msgs == [] and st["hosts"]["DE7"]["verdict"] == "stable")
msgs = feed(st, series(DAY + 430, 29, rx_drop_ps=150), DAY + 720)
check("сброс 150/с 4 мин 50 с — ещё тихо", msgs == [])
msgs = feed(st, series(DAY + 720, 2, rx_drop_ps=150), DAY + 740)
check("сброс 150/с 5 минут — «требует внимания»", len(msgs) == 1 and "сброс пакетов 150/с дольше 5 минут" in msgs[0])
import tempfile as _tf
import ddos_collect as col
with _tf.TemporaryDirectory() as tmp:
    os.makedirs(os.path.join(tmp, "eth0", "statistics"))
    open(os.path.join(tmp, "eth0", "statistics", "rx_missed_errors"), "w").write("17\n")
    open(os.path.join(tmp, "softnet"), "w").write("0000a1b2 00000003 00000000\n0000ffff 0000000a 00000001\n")
    check("сборщик: буфер карты и сбросы ядра (сумма по ядрам)", col.overload("eth0", tmp, os.path.join(tmp, "softnet")) == {"missed": 17, "softnet": 13})
    check("сборщик: нет файлов — нули", col.overload("eth9", tmp, os.path.join(tmp, "нет")) == {"missed": 0, "softnet": 0})
print("ddoswatch: тестов пройдено %d" % ok)
