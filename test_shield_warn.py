"""Тесты: предупреждения щита в /shield, в срезе сборщика и у сторожа; клиент по журналу Xray — только accepted
сразу после адреса. Без сети: PYTHONIOENCODING=utf-8 python test_shield_warn.py"""
import datetime as dt
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402
import shieldbot as b  # noqa: E402
d.IPINFO_LOOKUP = lambda ips: {}   # без сети: сведения об адресах не запрашиваем
d.SCAN_DIR = "/nonexistent"

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


MSK = d.MSK
DAY = dt.datetime(2026, 11, 23, 14, 0, tzinfo=MSK).timestamp()
NIGHT = dt.datetime(2026, 11, 23, 3, 0, tzinfo=MSK).timestamp()

# --- shieldbot: /shield (status_text)
KERNEL = "в ядре щит режет, а по state watch"
TICK = "таймер tick не работает (inactive)"
st_on0 = {"ok": True, "mode": "on", "until": 0, "tick": "active", "warn": [KERNEL]}
t = b.status_text({"de3": st_on0}, DAY)
check("Б1 on без срока — «срок неизвестен», не время 03:00", "включён, срок неизвестен" in t and "до 03:00" not in t)
check("Б2 предупреждение щита — строкой под сервером", "⚠️ " + KERNEL in t)
until = int(DAY + 7200)
t = b.status_text({"de3": {"ok": True, "mode": "on", "until": until, "tick": "active", "warn": []}}, DAY)
check("Б3 on со сроком — время, без предупреждений", "включён до %s" % b.msk(until).strftime("%H:%M") in t and "⚠️" not in t)
t = b.status_text({"de3": {"ok": True, "mode": "watch", "until": 0, "tick": "inactive", "warn": []}}, DAY)
check("Б4 таймер tick не active, warn пуст — показан таймер", "наблюдение" in t and "таймер снятия режима (tick): inactive" in t)
t = b.status_text({"de3": {"ok": True, "mode": "watch", "until": 0, "tick": "inactive", "warn": [TICK]}}, DAY)
check("Б5 таймер уже в warn — второй раз не повторяется", t.count("таймер") == 1 and TICK in t)
t = b.status_text({"de3": {"ok": True, "mode": "watch", "until": 0}}, DAY)
check("Б6 старый щит без tick и warn — как раньше", "• <b>de3</b> — наблюдение" in t and "⚠️" not in t)
t = b.status_text({"de3": {"ok": True, "mode": "watch", "until": 0, "tick": "active", "warn": ["<b>x</b> & y"]}}, DAY)
check("Б7 текст предупреждения экранируется", "&lt;b&gt;x&lt;/b&gt; &amp; y" in t)
t = b.result_text("de3", "on2", {"ok": True, "until": 0}, DAY)
check("Б8 итог кнопки «щит на 2 ч» с until=0 — не 03:00", "до 14:00" in t and "03:00" not in t)

# --- сборщик: warn, tick, v, table_v и время опроса в срезе
STATUS = {"ok": True, "loaded": True, "v": "1.4.0", "mode": "on", "until": 0, "tick": "inactive",
          "warn": [TICK, KERNEL] + ["лишнее %d" % i for i in range(10)] + ["x" * 500], "counters": {},
          "suspects": [], "blocked": [], "table_v": "1.4.0"}
sh = col.shield(run=lambda: json.dumps(STATUS), now=DAY)
check("С1 warn и tick передаются, warn не больше 5", sh["warn"][:2] == [TICK, KERNEL] and len(sh["warn"]) == col.SHIELD_WARN_MAX
      and sh["tick"] == "inactive")
check("С2 версия щита и таблицы, время опроса", sh["v"] == "1.4.0" and sh["table_v"] == "1.4.0" and sh["at"] == int(DAY))
long_ = dict(STATUS, warn=["x" * 500])
check("С3 длинное предупреждение обрезается", len(col.shield(run=lambda: json.dumps(long_), now=DAY)["warn"][0]) == col.SHIELD_WARN_LEN)
old = {k: v for k, v in STATUS.items() if k not in ("tick", "warn", "table_v")}
sh_old = col.shield(run=lambda: json.dumps(old), now=DAY)
check("С4 щит 1.3 без warn/tick — пустой список и None, без ошибки", sh_old["warn"] == [] and sh_old["tick"] is None
      and sh_old["table_v"] is None)
check("С5 warn не список — пусто", col.shield(run=lambda: json.dumps(dict(STATUS, warn="строка")), now=DAY)["warn"] == [])
check("С6 щит не загружен — как раньше", col.shield(run=lambda: json.dumps({"ok": False, "loaded": False})) == {"loaded": False})

# --- сборщик: строка журнала Xray — клиент только при accepted сразу после адреса
ACC = "2026/11/22 10:00:00.123 from 94.25.1.2:5747 accepted tcp:www.google.com:443 [STEAL >> DIRECT] email: user_42"
REJ = ("2026/11/22 10:00:01.456 from 5.6.7.8:1 rejected  proxy/vless/encoding: bad request from 1.1.1.1:2 accepted "
       "tcp:x:443 [a >> b] email: user_666")
REJ2 = "2026/11/22 10:00:02 from tcp:5.6.7.8:3 rejected  common/drain: accepted email: user_777 drained"
r = col.parse_access(ACC)
check("Ж1 accepted с email — клиент", r is not None and r[1:] == ("94.25.1.2", "user_42"))
check("Ж2 rejected, в причине « accepted » и « email: » — не клиент", col.parse_access(REJ) is None)
check("Ж3 rejected с « accepted email: » в причине — не клиент", col.parse_access(REJ2) is None)
check("Ж4 accepted не сразу после адреса — не клиент",
      col.parse_access("2026/11/22 10:00:03 from 5.6.7.8:4 x accepted tcp:x:443 email: user_1") is None)
check("Ж5 accepted без email — не клиент",
      col.parse_access("2026/11/22 10:00:04 from 5.6.7.8:5 accepted tcp:x:443 [api >> api]") is None)
check("Ж6 accepted с пустым email — не клиент",
      col.parse_access("2026/11/22 10:00:05 from 5.6.7.8:6 accepted tcp:x:443 [a >> b] email: ") is None)
check("Ж7 «acceptedX» — не слово accepted",
      col.parse_access("2026/11/22 10:00:06 from 5.6.7.8:7 acceptedX tcp:x:443 email: user_2") is None)
check("Ж8 IPv6 с tcp: — сеть /64",
      col.parse_access("2026/11/22 10:00:07 from tcp:[2a00:1fa0:4:5:6:7:8:9]:1 accepted tcp:x:443 [a >> b] email: u")[1:]
      == ("2a00:1fa0:4:5::", "u"))
with tempfile.TemporaryDirectory() as tmp:
    lg, out = os.path.join(tmp, "access.log"), os.path.join(tmp, "clients.json")
    open(lg, "w", encoding="utf-8").write(REJ + "\n" + REJ2 + "\n" + ACC + "\n")
    cl = col.Clients(lg, out)
    cl.read(dt.datetime(2026, 11, 22, 10, 1, tzinfo=dt.timezone.utc).timestamp())
    check("Ж9 по файлу журнала: клиент только из accepted", set(cl.map) == {"94.25.1.2"})

# --- сторож: предупреждения и тревога
C = dict(d.DEFAULTS, hosts=[{"name": "node-k", "host": "x"}])
NORM = {"rx_bps": 30e6, "rx_pps": 4000, "tx_bps": 30e6, "tx_pps": 4000, "syncookies_ps": 0, "listen_drop_ps": 0,
        "syn_recv": 5, "established": 300, "unique_ips": 80, "conntrack_count": 2000, "conntrack_max": 100000,
        "cpu_pct": 20, "ram_pct": 40, "load1": 0.3, "cores": 1, "disk_pct": 50, "swap_pct": 0, "failed_units": []}


def shd(at, warn, tick="active", mode="watch"):
    return {"loaded": True, "mode": mode, "until": 0, "blocked": 0, "suspects": [], "suspects_total": 0,
            "warn": warn, "tick": tick, "v": "1.4.0", "table_v": None, "at": int(at)}


def feed(state, t0, sh, n=6):
    """Минута срезов по 10 с — все с одним и тем же опросом щита, как у сборщика."""
    samples = [dict(NORM, ts=t0 + 10 * i, shield=sh) for i in range(n)]
    return d.process(state, {"node-k": {"samples": samples}}, C, t0 + 10 * n)


def alarms(msgs):
    return [x for x in msgs if "Щит, node-k" in x]


st = {}
check("Т1 без предупреждений — тихо", alarms(feed(st, DAY, shd(DAY, []))) == [])
m1 = feed(st, DAY + 60, shd(DAY + 60, [KERNEL], mode="on"))
check("Т2 ядро режет при watch — первый опрос: ещё не тревога", alarms(m1) == []
      and st["hosts"]["node-k"]["shield"]["warn"] == [KERNEL])
m2 = feed(st, DAY + 120, shd(DAY + 120, [KERNEL], mode="on"))
a = alarms(m2)
check("Т3 второй опрос подряд — тревога", len(a) == 1 and "неладно" in a[0] and "в ядре щит режет" in a[0] and "/unblock" in a[0])
check("Т4 держится дальше — без повторов", alarms(feed(st, DAY + 180, shd(DAY + 180, [KERNEL], mode="on"))) == [])
a = alarms(feed(st, DAY + 240, shd(DAY + 240, [])))
check("Т5 прошло — «снова в порядке»", len(a) == 1 and "снова в порядке" in a[0] and "совпадают" in a[0])

st = {}
feed(st, DAY, shd(DAY, [KERNEL], mode="on"))
samples = [dict(NORM, ts=DAY + 60 + 10 * i, shield=shd(DAY, [KERNEL], mode="on")) for i in range(6)]
check("Т6 тот же опрос щита в новых срезах — не второй подряд",
      alarms(d.process(st, {"node-k": {"samples": samples}}, C, DAY + 120)) == [])
feed(st, DAY + 120, shd(DAY + 120, []))
check("Т7 перерыв — счёт заново", alarms(feed(st, DAY + 180, shd(DAY + 180, [KERNEL], mode="on"))) == [])

st = {}
feed(st, DAY, shd(DAY, [TICK], tick="inactive"))
a = alarms(feed(st, DAY + 60, shd(DAY + 60, [TICK], tick="inactive")))
check("Т8 таймер tick не работает 2 опроса — тревога днём", len(a) == 1 and "таймер снятия режима (tick) не работает" in a[0])

st = {}
feed(st, NIGHT, shd(NIGHT, [TICK], tick="inactive"))
m = feed(st, NIGHT + 60, shd(NIGHT + 60, [TICK], tick="inactive"))
check("Т9 таймер ночью — без сообщения, в отложенные",
      alarms(m) == [] and any("tick" in r for x in st["hosts"]["node-k"].get("deferred", []) for r in x["reasons"]))
st = {}
feed(st, NIGHT, shd(NIGHT, [KERNEL], mode="on"))
check("Т10 ядро режет ночью — тревога сразу", len(alarms(feed(st, NIGHT + 60, shd(NIGHT + 60, [KERNEL], mode="on")))) == 1)

st = {}
feed(st, DAY, shd(DAY, ["on истёк, таймер не работает — снят сейчас"], tick="failed"))
check("Т11 «on истёк, таймер не работает» тоже беда таймера",
      len(alarms(feed(st, DAY + 60, shd(DAY + 60, [], tick="failed")))) == 1)
st = {}
feed(st, DAY, shd(DAY, ["в allow не адреса: host.example"]))
check("Т12 прочие предупреждения — без тревоги", alarms(feed(st, DAY + 60, shd(DAY + 60, ["в allow не адреса: host.example"]))) == [])

# --- отчёт: строка-предупреждение
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "r.sqlite"))
    rst = {"hosts": {"node-k": {"verdict": "stable", "shield": {"warn": [KERNEL, "в allow не адреса: a<b"]}},
                     "node-c": {"verdict": "stable", "shield": {"warn": []}},
                     "bot": {"verdict": "offline", "shield": {"warn": [TICK]}}}}
    C2 = dict(d.DEFAULTS, hosts=[{"name": n, "host": "x"} for n in ("node-k", "node-c", "bot")])
    iss, inf = d.report_sections(DAY - 3600, DAY, rst, C2, db)
    w = [x for x in iss if x.startswith("🛡 <b>Щит,")]
    check("О1 в проблемах отчёта — строка по серверу с warn, текст экранирован",
          w == ["🛡 <b>Щит, node-k:</b> " + KERNEL + "; в allow не адреса: a&lt;b"])
    L = d.report_lines(DAY - 3600, DAY, rst, C2, db)
    check("О2 и в блоке «Нагрузка и DDoS»", any(x.startswith("🛡 <b>Щит, node-k:</b>") for x in L)
          and not any("Щит, bot" in x for x in L))
    db.close()
st = {"hosts": {"node-k": {"shield": {"warn": [KERNEL], "alarm": ["kernel"], "alarm_run": {"kernel": 3}}}}}
d.shield_pass(st["hosts"]["node-k"], "node-k", {"ts": DAY, "shield": {"loaded": False}}, C, st)
check("О3 щит не загружен — прежние предупреждения забыты", st["hosts"]["node-k"]["shield"]["warn"] == []
      and st["hosts"]["node-k"]["shield"]["alarm"] == [])
print("предупреждения щита и журнал Xray: тестов пройдено %d" % ok)
