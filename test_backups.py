"""Тесты слежки за бэкапами (ddos_collect.backups + ddoswatch.backup_*), без сети: python test_backups.py"""
import calendar
import json
import os
import sys
import tempfile
import time

# Журналы бэкапов пишутся по местному времени серверов (МСК), а сообщения — по МСК: часовой пояс машины, где идут
# тесты, не должен влиять. Местное время в тесте — МСК (UTC+3, без перехода на летнее с 2014 г.): на Linux — через TZ,
# а time.mktime подменяем всегда (на Windows TZ на лету не сменить).
os.environ["TZ"] = "MSK-3"
if hasattr(time, "tzset"):
    time.tzset()
time.mktime = lambda t: calendar.timegm(t) - 3 * 3600

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402
d.IPINFO_LOOKUP = lambda ips: {}   # без сети: сведения об адресах не запрашиваем
d.SCAN_DIR = "/nonexistent"

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


def lt(s):
    return int(time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S")))


tmp = tempfile.mkdtemp()
log1, log2, log3 = (os.path.join(tmp, n) for n in ("panel.log", "bot.log", "sub.log"))
open(log1, "w", encoding="utf-8").write(
    "[2026-11-13 15:20:01] [INFO] start\n[2026-11-13 15:20:09] [INFO] DONE v1.0.0 size=1.1M hash=f0... db=1.1M\n"
    "[*] DONE v1.0.0 size=1.1M\n[2026-11-13 18:20:02] [INFO] start\n"
    "[2026-11-13 18:20:09] [INFO] DONE v1.0.0 size=1.2M hash=aa... db=1.2M\n")
open(log2, "w", encoding="utf-8").write(
    "[2026-11-13 15:30:07] [INFO] DONE v1.0.0 archive=a.tar.gz size=1281KB\n"
    "[2026-11-13 18:30:01] [ERR] pg_dump подозрительно мал: 12 байт\n")
open(log3, "w", encoding="utf-8").write("[2026-11-13T18:30:05] FAILURE on line 77 rc=1\n")
conf = os.path.join(tmp, "backups.json")
json.dump([{"name": "панель", "log": log1}, {"name": "бот", "log": log2}, {"name": "sub", "log": log3},
           {"name": "нет", "log": os.path.join(tmp, "nope.log")}], open(conf, "w", encoding="utf-8"), ensure_ascii=False)
bk = {b["name"]: b for b in col.backups(conf)}
check("B1 удачная копия — последняя строка DONE со временем; строка без времени не в счёт",
      bk["панель"]["ok_ts"] == lt("2026-11-13 18:20:09") and "size=1.2M" in bk["панель"]["ok"] and not bk["панель"]["err_ts"])
check("B2 ошибка после удачной — видна обе", bk["бот"]["ok_ts"] == lt("2026-11-13 15:30:07")
      and bk["бот"]["err_ts"] == lt("2026-11-13 18:30:01") and "pg_dump" in bk["бот"]["err"])
check("B3 FAILURE со временем через T; журнала нет — missing", bk["sub"]["err_ts"] == lt("2026-11-13 18:30:05")
      and not bk["sub"]["ok_ts"] and bk["нет"].get("missing"))
check("B4 нет настроек — бэкапы не смотрим", col.backups(os.path.join(tmp, "нет.json")) is None)
if not hasattr(os, "statvfs"):   # Windows: у сборщика (Linux) берётся место на диске — здесь его нет
    def _nostat(path):
        raise OSError("нет statvfs")
    os.statvfs = _nostat
col.tcp_states = lambda: (0, 0, 0)
m = col.static_part(None, [], bk=list(bk.values()))
check("B5 бэкапы в срезе сборщика", len(m["backups"]) == 4 and "backups" not in col.static_part(None, []))

now = lt("2026-11-13 19:00:00")
pr = d.backup_problems(list(bk.values()), now, 7)
check("B6 что не так: ошибка после удачной, нет удачных, нет журнала; свежая — в порядке",
      set(pr) == {"бот", "sub", "нет"} and "с ошибкой" in pr["бот"] and "нет ни одной" in pr["sub"] and "нет журнала" in pr["нет"])
old = d.backup_problems([bk["панель"]], lt("2026-11-14 03:00:00"), 7)
check("B7 удачной копии нет дольше срока — тревога с временем", "назад" in old.get("панель", "") and "13.11" in old["панель"])

e, c = {}, {"backup_max_hours": 7}
s = {"ts": now, "backups": [bk["панель"], bk["бот"]]}
check("B8 первый проход — без сообщения (подтверждение)", d.backup_pass(e, "бот", s, c) == [])
m2 = d.backup_pass(e, "бот", s, c)
check("B9 второй проход — одно сообщение о беде", len(m2) == 1 and "Бэкап не в порядке" in m2[0] and "pg_dump" in m2[0])
check("B10 пока беда та же — молчим", d.backup_pass(e, "бот", s, c) == [])
fixed = dict(bk["бот"], ok_ts=lt("2026-11-13 21:30:07"), ok="DONE size=1282KB")
m3 = d.backup_pass(e, "бот", {"ts": lt("2026-11-13 21:31:00"), "backups": [bk["панель"], fixed]}, c)
check("B11 копия снова прошла — сообщение о норме", len(m3) == 1 and "снова в порядке" in m3[0] and "21:30" in m3[0])
check("B12 старый сборщик без бэкапов — молчим", d.backup_pass({}, "x", {"ts": now}, c) == [])
iss, inf = d.backup_lines({"бот": e}, now)
check("B13 отчёт: последняя копия каждого бэкапа и размер", iss == [] and "панель — 13.11 18:20 (1.2M)" in inf[0]
      and "бот — 13.11 21:30 (1282KB)" in inf[0])
e2 = {}
for _ in range(2):
    d.backup_pass(e2, "sub", {"ts": now, "backups": [bk["sub"]]}, c)
iss2, _ = d.backup_lines({"sub": e2}, now)
check("B14 отчёт: беда — в проблемах", len(iss2) == 1 and "sub" in iss2[0] and "нет ни одной" in iss2[0])
print("бэкапы: тестов пройдено %d" % ok)
