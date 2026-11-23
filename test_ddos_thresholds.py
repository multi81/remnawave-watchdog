"""Тесты: пороги не учатся на атаках и растут с пределом; симметричный флуд (излишек rx − tx, рост против нормы, ICMP,
канал заполнен); экранирование текстов в сообщениях; совместимость с базой и порогами прежней версии.
Без сети: PYTHONIOENCODING=utf-8 python test_ddos_thresholds.py"""
import datetime as dt
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddoswatch as d  # noqa: E402
d.IPINFO_LOOKUP = lambda ips: {}
d.SCAN_DIR = "/nonexistent"

ok = 0


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


DAY = dt.datetime(2026, 10, 21, 14, 0, tzinfo=d.MSK).timestamp()
NORM = {"rx_bps": 30e6, "rx_pps": 4000, "tx_bps": 30e6, "tx_pps": 4000, "syncookies_ps": 0, "listen_drop_ps": 0,
        "syn_recv": 5, "established": 300, "unique_ips": 80, "conntrack_count": 2000, "conntrack_max": 100000,
        "cpu_pct": 20, "ram_pct": 40, "load1": 0.3, "cores": 1, "disk_pct": 50, "swap_pct": 0, "failed_units": []}


def m(**kw):
    x = dict(NORM)
    x.update(kw)
    return x


TH = d.thresholds({"thresholds": {}}, None)
INS = ("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps, tx_bps, tx_pps, susp)"
       " values (?, ?, ?, ?, 0, 0, 0, ?, ?, ?)")


def fill(db, host, t_end, n, rx, tx, pps=4000, txp=4000, susp=None, step=10):
    db.executemany(INS, [(host, int(t_end - i * step), rx, pps, tx, txp, susp) for i in range(n)])


# ---------- пороги не учатся на атаках ----------
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "a.sqlite"))
    now = DAY
    fill(db, "DE7", now - 1, 50000, 30e6, 30e6)                               # обычная неделя, rx ≈ tx
    d.recompute_baseline(db, ["DE7"], now)
    base0 = d.db_baseline(db, "DE7")["rx_bps"]
    check("чистая история: порог по минимуму", base0 == 100e6)
    # 9 часов атаки (вердикт «атака» — susp) по 900 Мбит/с — p95 этого не видит
    fill(db, "DE7", now - 500001, 3240, 900e6, 30e6, pps=200_000, susp=1)
    d.recompute_baseline(db, ["DE7"], now + 3600)
    b = d.db_baseline(db, "DE7")
    check("атака (срезы с пометкой) не поднимает порог", b["rx_bps"] == base0 and b["rx_pps"] == 20000)
    check("атака не поднимает и норму роста", b["rx_bps_sym"] == 300e6 and b["rx_pps_sym"] == 60000)
    db.close()

with tempfile.TemporaryDirectory() as tmp:   # доказательство из замечания: 9 ч в неделю чуть ниже порога, 3 недели
    db = d.db_open(os.path.join(tmp, "b.sqlite"))
    t, seen = DAY, []
    for week in range(3):
        db.execute("delete from samples")
        fill(db, "DE7", t - 1, 50000, 20e6, 20e6)
        th_now = d.thresholds({}, d.db_baseline(db, "DE7"))["rx_bps"]
        fill(db, "DE7", t - 500001, 3240, th_now * 0.95, th_now * 0.95 / 4)   # перекос, тревоги нет (ниже порога)
        d.recompute_baseline(db, ["DE7"], t)
        seen.append(d.db_baseline(db, "DE7")["rx_bps"])
        t += 7 * 86400
    check("нагрузка с перекосом ниже порога: порог не растёт 100 → 285 → 812", seen == [100e6] * 3)
    db.close()

with tempfile.TemporaryDirectory() as tmp:   # старые строки (без susp) — по записанным атакам
    db = d.db_open(os.path.join(tmp, "c.sqlite"))
    fill(db, "DE7", DAY - 1, 50000, 30e6, 30e6)
    fill(db, "DE7", DAY - 100006, 6000, 900e6, 900e6, pps=300_000, txp=300_000)   # симметричный флуд, без пометки
    db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, 1)",
               ("DE7", int(DAY - 100006 - 59990), int(DAY - 100006), "объёмный флуд", "high", "", "{}"))
    d.recompute_baseline(db, ["DE7"], DAY)
    b = d.db_baseline(db, "DE7")
    check("срезы внутри записанной атаки (старые строки) — не в базу", b["rx_bps_sym"] == 300e6 and b["rx_bps"] == 100e6)
    db.close()

rows = [(t, 1e6 * t, 10, 0, 0, 0, 1e6 * t, 10, None) for t in range(1, 200)]
cv = d.clean_values(rows, [(100, 120), (110, 115), (150, 160), (155, 190)])   # пересекающиеся и вложенные отрезки
kept = sorted(int(x / 1e6) for x in cv["rx_bps"])
check("отрезки атак сливаются: вне них всё, внутри (с минутой до начала) ничего",
      kept == [t for t in range(1, 200) if not (40 <= t <= 120 or 90 <= t <= 190)])
check("новые строки (susp = 0) отрезками не режутся — пометка точнее",
      len(d.clean_values([(110, 1e6, 10, 0, 0, 0, 1e6, 10, 0)], [(100, 120)])["rx_bps"]) == 1)
q = d.compute_baseline(d.clean_values([(t, 5e6, 800, 0, 0, 0, 1e6, 200, 0) for t in range(9000)]))
check("тихий фон с перекосом — в базе (порог по минимуму, как прежде)", q["rx_bps"] == 100e6 and q["rx_pps"] == 20000)
import time as _t  # noqa: E402
rows = [(t * 10, 30e6, 4000, 0, 0, 0, 30e6, 4000, None) for t in range(60480)]
t0 = _t.time()
d.clean_values(rows, [(i * 1200, i * 1200 + 60) for i in range(500)])
check("неделя срезов и 500 атак — разбор быстрый", _t.time() - t0 < 5)

with tempfile.TemporaryDirectory() as tmp:   # предел роста: ×1,5 за сутки, ×2 за неделю
    db = d.db_open(os.path.join(tmp, "g.sqlite"))
    fill(db, "DE7", DAY - 1, 50000, 100e6, 100e6, pps=10000, txp=10000)
    d.recompute_baseline(db, ["DE7"], DAY)
    b0 = d.db_baseline(db, "DE7")["rx_bps"]
    check("исходный порог p95×3", b0 == 300e6)
    db.execute("delete from samples")
    fill(db, "DE7", DAY + 3600, 50000, 1e9, 1e9, pps=100000, txp=100000)    # трафик вырос вдесятеро (честно)
    d.recompute_baseline(db, ["DE7"], DAY + 3600)
    b1 = d.db_baseline(db, "DE7")["rx_bps"]
    d.recompute_baseline(db, ["DE7"], DAY + 7200)
    b2 = d.db_baseline(db, "DE7")["rx_bps"]
    check("за сутки не больше ×1,5 и повторный пересчёт в те же сутки не добавляет", b1 == b0 * 1.5 and b2 == b1)
    d.recompute_baseline(db, ["DE7"], DAY + 86400 + 3600)
    b3 = d.db_baseline(db, "DE7")["rx_bps"]
    check("следующие сутки — снова до ×1,5, но не больше ×2 за неделю", b3 == b0 * 2)
    for k in range(2, 7):
        d.recompute_baseline(db, ["DE7"], DAY + k * 86400 + 3600)
    check("неделя не кончилась — выше ×2 не растёт", d.db_baseline(db, "DE7")["rx_bps"] == b0 * 2)
    db.execute("delete from samples")
    fill(db, "DE7", DAY + 7 * 86400 + 7200, 50000, 1e9, 1e9, pps=100000, txp=100000)
    d.recompute_baseline(db, ["DE7"], DAY + 7 * 86400 + 7200)
    check("новая неделя — дальше рост с тем же пределом", d.db_baseline(db, "DE7")["rx_bps"] == b0 * 2 * 1.5)
    db.execute("delete from samples")
    fill(db, "DE7", DAY + 7 * 86400 + 10800, 50000, 10e6, 10e6)
    d.recompute_baseline(db, ["DE7"], DAY + 7 * 86400 + 10800)
    check("снижение — без предела", d.db_baseline(db, "DE7")["rx_bps"] == 100e6)
    db.close()

with tempfile.TemporaryDirectory() as tmp:   # долгая атака: чистых срезов мало — прежний порог, не статический
    db = d.db_open(os.path.join(tmp, "l.sqlite"))
    fill(db, "DE7", DAY - 1, 50000, 100e6, 100e6, pps=10000, txp=10000)
    d.recompute_baseline(db, ["DE7"], DAY)
    db.execute("update samples set susp = 1 where ts > ?", (DAY - 450000,))
    d.recompute_baseline(db, ["DE7"], DAY + 3600)
    check("чистых срезов мало — порог прежний", d.db_baseline(db, "DE7")["rx_bps"] == 300e6)
    db.close()

# потолок от скорости канала
C_L = dict(d.DEFAULTS, link_mbps=1000, hosts=[{"name": "DE7", "host": "x"}, {"name": "nl2", "host": "y", "link_mbps": 10000}])
check("скорость канала: у сервера своя, иначе общая", d.link_bps(C_L, C_L["hosts"][0]) == 1e9
      and d.link_bps(C_L, C_L["hosts"][1]) == 1e10 and d.link_bps(d.DEFAULTS, {"name": "x"}) == 0)
th_l = d.thresholds(C_L, {"rx_bps": 5e9, "rx_bps_sym": 9e9, "rx_excess_bps": 3e9}, None, 1e9)
check("порог объёма не выше 80% канала", th_l["rx_bps"] == 800e6 and th_l["rx_bps_sym"] == 800e6
      and th_l["rx_excess_bps"] == 800e6 and th_l["link_full_bps"] == 900e6)
check("без скорости канала — потолка нет", d.thresholds({}, {"rx_bps": 5e9})["rx_bps"] == 5e9)

# срезы атаки помечаются при записи
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "p.sqlite"))
    C = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}])
    st = {}
    ser = [dict(m(), ts=DAY + 10 * i) for i in range(3)] + [dict(m(rx_pps=60_000), ts=DAY + 30 + 10 * i) for i in range(10)] \
        + [dict(m(), ts=DAY + 130 + 10 * i) for i in range(5)]
    d.process(st, {"DE7": {"samples": ser}}, C, DAY + 200, db)
    rows = dict(db.execute("select ts, susp from samples where host = 'DE7'").fetchall())
    check("запись: обычные срезы чистые", rows[int(DAY)] == 0 and rows[int(DAY + 170)] == 0)
    check("запись: подтверждение, атака и спад — с пометкой", all(rows[int(DAY + 30 + 10 * i)] == 1 for i in range(10))
          and rows[int(DAY + 130)] == 1 and rows[int(DAY + 140)] == 1)
    db.close()

# ---------- совместимость с базой и порогами прежней версии ----------
with tempfile.TemporaryDirectory() as tmp:
    p = os.path.join(tmp, "old.sqlite")
    old = sqlite3.connect(p)
    old.execute("create table samples (host text, ts integer, rx_bps real, rx_pps real, syncookies_ps real,"
                " listen_drop_ps real, rx_drop_ps real, tx_bps real, tx_pps real, primary key (host, ts))")
    old.execute("create table attacks (id integer primary key, host text, start integer, end integer, type text, severity text,"
                " reasons text, peak text, notified integer default 0)")
    old.execute("create table baseline (host text, metric text, value real, computed integer, primary key (host, metric))")
    old.executemany("insert into samples values (?, ?, ?, ?, 0, 0, 0, ?, ?)",
                    [("DE7", int(DAY - 1 - 10 * i), 150e6, 15000, 150e6, 15000) for i in range(9000)])
    old.execute("insert into baseline values ('DE7', 'rx_bps', 2e9, ?)", (int(DAY - 3600),))   # раздутый прежний порог
    old.commit()
    old.close()
    db = d.db_open(p)
    check("совместимость: база прежней версии дополняется (susp, baseline_cap)",
          "susp" in [r[1] for r in db.execute("pragma table_info(samples)")]
          and db.execute("select count(*) from sqlite_master where name = 'baseline_cap'").fetchone()[0] == 1)
    d.recompute_baseline(db, ["DE7"], DAY)
    b = d.db_baseline(db, "DE7")
    check("совместимость: раздутый прежний порог снижается по чистым срезам", b["rx_bps"] == 450e6)
    db.execute("insert into baseline values (?, ?, ?, ?)", ("PL1", "rx_bps", 1e8, int(DAY)))   # так пишет прежняя версия
    db.execute("insert into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps) values (?, ?, ?, ?, ?, ?, ?)",
               ("PL1", int(DAY), 1, 1, 0, 0, 0))
    check("совместимость: прежняя версия по-прежнему пишет в базу (откат)", d.db_baseline(db, "PL1") == {"rx_bps": 1e8})
    db.close()
th_old = d.thresholds({}, {"rx_bps": 600e6, "rx_pps": 100_000})
check("совместимость: прежняя база (только rx_bps/rx_pps) — норма роста из неё, излишек по ней",
      th_old["rx_bps_sym"] == 800e6 and th_old["rx_pps_sym"] == 200_000
      and th_old["rx_excess_bps"] == 600e6 and th_old["rx_excess_pps"] == 100_000)
check("совместимость: прежний набор порогов (без новых ключей) — classify не падает",
      d.classify(m(rx_bps=950e6, tx_bps=950e6), dict(d.STATIC))["state"] in ("stable", "attack")
      and d.classify(m(), {k: v for k, v in d.STATIC.items() if k not in ("rx_bps_sym", "rx_pps_sym", "icmp_pps")})["state"] == "stable")
check("совместимость: из ddos.json задаются и новые пороги", d.thresholds({"thresholds": {"icmp_pps": 900}}, None)["icmp_pps"] == 900)

# ---------- симметричный флуд ----------
v = d.classify(m(rx_bps=900e6, tx_bps=900e6, rx_pps=1_500_000, tx_pps=1_500_000), TH)
check("пинг-флуд 900 Мбит/с с ответами (без истории) — атака", v["state"] == "attack"
      and "входящий выше нормы" in v["reasons"] and "пакеты выше нормы" in v["reasons"] and v["severity"] == "critical")
v = d.classify(m(rx_bps=950e6, tx_bps=500e6, rx_pps=120_000, tx_pps=60_000), TH)
check("флуд 450 Мбит/с поверх 500 своих — атака по излишку", v["state"] == "attack"
      and "входящий сверх исходящего" in v["reasons"])
busy = d.compute_baseline(d.clean_values([(DAY - i, 500e6, 50_000, 0, 0, 0, 495e6, 49_500, None) for i in range(9000)]))
th_b = d.thresholds({}, busy)
check("загруженная нода: свои нормы", busy["rx_bps"] == 1.5e9 and busy["rx_excess_bps"] == 150e6
      and busy["rx_bps_sym"] == 2e9 and busy["rx_pps_sym"] == 200_000)
check("загруженная нода: обычный симметричный трафик — норма", d.classify(m(rx_bps=520e6, tx_bps=510e6, rx_pps=52_000,
                                                                               tx_pps=51_000), th_b)["state"] == "stable")
v = d.classify(m(rx_bps=950e6, tx_bps=500e6, rx_pps=70_000, tx_pps=50_000), th_b)
check("загруженная нода: флуд 450 поверх 500 — атака (раньше stable)", v["state"] == "attack"
      and v["reasons"] == ["входящий сверх исходящего"] and v["attack_type"] == "объёмный флуд")
v = d.classify(m(rx_bps=900e6, tx_bps=900e6, rx_pps=900_000, tx_pps=900_000), th_b)
check("загруженная нода: пинг-флуд с ответами — пакетный флуд против нормы", v["state"] == "attack"
      and v["attack_type"] == "пакетный флуд" and "пакеты выше нормы" in v["reasons"])
quiet = d.compute_baseline(d.clean_values([(DAY - i, 50e6, 6000, 0, 0, 0, 50e6, 6000, None) for i in range(9000)]))
v = d.classify(m(rx_bps=400e6, tx_bps=400e6, rx_pps=40_000, tx_pps=40_000), d.thresholds({}, quiet))
check("тихая нода: 400 Мбит/с туда-обратно — выше нормы (×8)", v["state"] == "attack" and "входящий выше нормы" in v["reasons"])
v = d.classify(m(shield={"proto_pps": {"tcp": 4000, "icmp": 20_000}}), TH)
check("ICMP из щита — «ICMP-флуд»", v["state"] == "attack" and v["attack_type"] == "ICMP-флуд" and v["reasons"] == ["ICMP"])
check("ICMP фон — норма", d.classify(m(shield={"proto_pps": {"icmp": 30}}), TH)["state"] == "stable")
check("щит без proto_pps или не словарь — норма", d.classify(m(shield={"proto_pps": None}), TH)["state"] == "stable"
      and d.classify(m(shield="x"), TH)["state"] == "stable")
th_lk = d.thresholds({}, {"rx_bps_sym": 9e9, "rx_bps": 9e9}, None, 1e9)
v = d.classify(m(rx_bps=950e6, tx_bps=950e6, rx_pps=80_000, tx_pps=80_000), th_lk)
check("канал заполнен — тревога при любом перекосе", v["state"] == "attack" and "канал заполнен" in v["reasons"])
check("без скорости канала — этого признака нет",
      d.classify(m(rx_bps=950e6, tx_bps=950e6, rx_pps=80_000, tx_pps=80_000), d.thresholds({}, {"rx_bps_sym": 9e9, "rx_bps": 9e9}))["state"] == "stable")
th_ov = d.thresholds({}, busy, {"rx_bps": 1.5e9, "rx_pps": 1.5e6, "until": DAY + 1}, 1e9)
check("«Это не атака» поднимает и новые пороги", d.classify(m(rx_bps=950e6, tx_bps=500e6, rx_pps=900_000, tx_pps=900_000,
                                                                 shield={"proto_pps": {"icmp": 50_000}}), th_ov)["state"] == "stable")
check("прежние признаки не изменились: закачка и поровну пакеты — норма",
      d.classify(m(rx_bps=250e6, tx_bps=240e6), TH)["state"] == "stable"
      and d.classify(m(rx_pps=50_000, tx_pps=48_000), TH)["state"] == "stable")

# ---------- экранирование текстов в сообщениях ----------
pl = d.proto_line({"shield": {"proto_pps": {"<i>x</i>": 5}}})
check("экранирование: протокол из щита", "<i>" not in pl and "&lt;i&gt;x" in pl)
st = {"hosts": {"DE7": {"verdict": "stable", "deferred": [{"ts": DAY, "state": "docker", "reasons": ["a <b>b</b> & c"]}]}}}
s = d.summary(st, dict(d.DEFAULTS, hosts=[{"name": "DE7"}]), DAY + 60)
check("экранирование: сводка, ночные события", "a &lt;b&gt;b&lt;/b&gt; &amp; c" in s and "<b>b</b>" not in s)
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "r.sqlite"))
    L = d.report_lines(DAY - 3600, DAY + 60, st, dict(d.DEFAULTS, hosts=[{"name": "DE7"}]), db)
    t = "\n".join(L)
    check("экранирование: отчёт, ночные события", "a &lt;b&gt;b&lt;/b&gt; &amp; c" in t and "<b>b</b>" not in t)
    db.close()
t = d.text_change("DE7", "stable", {"state": "health", "reasons": ["systemd: <x>.service"]}, m(), DAY)
check("экранирование: имена упавших служб с сервера", "&lt;x&gt;.service" in t and "<x>" not in t)

print("пороги DDoS и симметричный флуд: тестов пройдено %d" % ok)
