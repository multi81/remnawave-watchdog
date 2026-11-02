"""Тесты слежения за контейнерами Docker (ddos_collect.containers + ddoswatch.docker_*), без сети: python test_dockerwatch.py"""
import datetime as dt
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


# --- сборщик: ответы Docker API
API = {
    "/containers/json?all=1": [{"Id": "a1"}, {"Id": "b2"}, {"Id": "gone"}],
    "/containers/a1/json": {"Name": "/remnanode", "RestartCount": 2,
                            "State": {"Status": "running", "ExitCode": 0},
                            "HostConfig": {"RestartPolicy": {"Name": "always"}}},
    "/containers/b2/json": {"Name": "/remnawave-db", "RestartCount": 0,
                            "State": {"Status": "exited", "ExitCode": 137, "Health": {"Status": "unhealthy"}},
                            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}}},
}


def get(p):
    if p not in API:
        raise OSError("404")
    return API[p]


okd, cts = col.containers(get=get)
check("сборщик: Docker отвечает, удалённый между запросами пропущен", okd is True and len(cts) == 2)
check("сборщик: поля контейнера", cts[0] == {"n": "remnanode", "s": "running", "h": "", "rp": "always", "rc": 2, "ex": 0})
check("сборщик: healthcheck и код выхода", cts[1]["h"] == "unhealthy" and cts[1]["ex"] == 137 and cts[1]["rp"] == "unless-stopped")


def bad(p):
    raise OSError("connection refused")


check("сборщик: Docker не отвечает", col.containers(get=bad) == (False, []))
with tempfile.TemporaryDirectory() as tmp:
    r = col.containers(sock=os.path.join(tmp, "no.sock"))
    check("сборщик: нет сокета — нет Docker или он лежит", r in ((None, None), (False, [])))
if not hasattr(os, "statvfs"):   # Windows: сборщик живёт на Linux, диск здесь не важен
    os.statvfs = lambda p: (_ for _ in ()).throw(OSError("нет statvfs"))
m = col.static_part("eth0", [], (True, cts))
check("сборщик: в срезе docker_ok и containers", m["docker_ok"] is True and m["containers"] == cts)
check("сборщик: без Docker — полей нет (старый формат)", "containers" not in col.static_part("eth0", [], (None, None)))

# --- сторож: жизненный цикл
MSK = d.MSK
DAY = dt.datetime(2026, 10, 22, 14, 0, tzinfo=MSK).timestamp()
NIGHT = dt.datetime(2026, 10, 22, 3, 0, tzinfo=MSK).timestamp()
C = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}])
NORM = {"rx_bps": 30e6, "rx_pps": 4000, "cpu_pct": 20, "ram_pct": 40, "load1": 0.3, "cores": 1, "disk_pct": 50,
        "swap_pct": 0, "failed_units": [], "conntrack_max": 100000, "conntrack_count": 100}


def ct(n, s="running", rp="always", rc=0, ex=0, h=""):
    return {"n": n, "s": s, "rp": rp, "rc": rc, "ex": ex, "h": h}


GOOD = [ct("remnanode"), ct("caddy-selfsteal", rp="unless-stopped"), ct("remnawave-node-agent", rp="unless-stopped"),
        ct("remnanode-old-20261021", s="exited", rp="no")]


def run(st, t, cts, docker_ok=True, c=C, **kw):
    s = dict(NORM, ts=t, docker_ok=docker_ok, containers=cts, **kw)
    return d.process(st, {"DE7": {"samples": [s]}}, c, t + 5)


def repl(cts, n, **kw):
    return [dict(x, **kw) if x["n"] == n else x for x in cts]


st = {}
check("всё работает — тихо", run(st, DAY, GOOD) == [] and run(st, DAY + 60, GOOD) == [])
check("старая копия с restart=no в exited — не тревога", not st["hosts"]["DE7"]["docker"]["active"])
down = repl(GOOD, "remnanode", s="exited", ex=137)
check("остановился — первый проход тихо", run(st, DAY + 120, down) == [])
msgs = run(st, DAY + 180, down)
check("второй проход — тревога с именем и кодом", len(msgs) == 1 and "🐳" in msgs[0] and "remnanode" in msgs[0]
      and "<b>VPN на ноде (remnanode)</b> — остановлен (убит из-за нехватки памяти или вручную, код 137)" in msgs[0]
      and "⚠️ клиенты этой ноды без VPN" in msgs[0] and "DE7" in msgs[0] and "внесу в исключения" in msgs[0])
SAMPLE_DOWN = msgs[0]
check("пока лежит — не повторяется", run(st, DAY + 240, down) == [])
check("вердикт сервера не тронут", st["hosts"]["DE7"]["verdict"] == "stable")
msgs = run(st, DAY + 300, GOOD)
check("поднялся — «снова работают»", len(msgs) == 1 and "снова работают" in msgs[0] and "VPN на ноде (remnanode)</b> — работает" in msgs[0]
      and "⚠️" not in msgs[0])
SAMPLE_UP = msgs[0]

# упал на один проход и сразу поднялся (перезапуск при обновлении) — тихо
st = {}
run(st, DAY, GOOD)
run(st, DAY + 60, repl(GOOD, "remnanode", s="restarting"))
check("кратковременный restarting — тихо", run(st, DAY + 120, GOOD) == [] and not st["hosts"]["DE7"]["docker"]["active"])

# тревога в тот же проход, что и «Swap 95%» — не теряется
st = {}
run(st, DAY, GOOD)
run(st, DAY + 60, down, swap_pct=95)
msgs = run(st, DAY + 120, down, swap_pct=95)
check("контейнер не теряется за другим состоянием сервера", any("remnanode" in x and "🐳" in x for x in msgs))

# Docker не отвечает
st = {}
run(st, DAY, GOOD)
run(st, DAY + 60, [], docker_ok=False)
msgs = run(st, DAY + 120, [], docker_ok=False)
check("Docker не отвечает — тревога", len(msgs) == 1 and "Docker не отвечает" in msgs[0])
check("Docker вернулся — снова работают", "снова работают" in run(st, DAY + 180, GOOD)[0])

# unhealthy, dead
st = {}
run(st, DAY, GOOD)
uh = repl(GOOD, "caddy-selfsteal", h="unhealthy")
run(st, DAY + 60, uh)
check("unhealthy — тревога", "unhealthy" in run(st, DAY + 120, uh)[0])
st = {}
run(st, DAY, GOOD)
dead = repl(GOOD, "caddy-selfsteal", s="dead")
run(st, DAY + 60, dead)
check("dead — тревога", "dead" in run(st, DAY + 120, dead)[0])

# пропал (docker rm / compose down)
st = {}
run(st, DAY, GOOD)
nogo = [x for x in GOOD if x["n"] != "caddy-selfsteal"]
run(st, DAY + 60, nogo)
check("пропал — тревога", "пропал" in run(st, DAY + 120, nogo)[0])
st["hosts"]["DE7"]["docker"]["known"]["caddy-selfsteal"] = DAY - d.DOCKER_FORGET - 10
run(st, DAY + 180, nogo)
check("через 3 суток пропавший забыт", "caddy-selfsteal" not in st["hosts"]["DE7"]["docker"]["known"])

# остановлен нарочно с restart=no, но раньше работал — тревога; в исключениях — тихо
st = {}
k = [ct("blog", rp="no")]
run(st, DAY, k)
stopped = [ct("blog", s="exited", rp="no")]
run(st, DAY + 60, stopped)
check("работал и остановлен (restart=no) — тревога", "blog" in run(st, DAY + 120, stopped)[0])
st = {}
Ci = dict(C, ignore_containers=["blog"])
run(st, DAY, k, c=Ci)
run(st, DAY + 60, stopped, c=Ci)
check("в ignore_containers — тихо", run(st, DAY + 120, stopped, c=Ci) == [])

# перезапуски по кругу: 3 за час; плановый раз в 6 ч с кодом 0 — тихо
st = {}
for i, rc in enumerate([0, 1, 2, 3, 3]):
    out = run(st, DAY + 60 * i, repl(GOOD, "remnawave-node-agent", rc=rc, ex=1))
check("3 перезапуска за час — тревога", "перезапускается по кругу: 3 раза за час" in
      st["hosts"]["DE7"]["docker"]["active"].get("remnawave-node-agent", ""))
check("склонение: 1 раз, 3 раза, 5 раз, 12 раз, 22 раза", [d.times_ru(k) for k in (1, 3, 5, 12, 22)]
      == ["1 раз", "3 раза", "5 раз", "12 раз", "22 раза"])
st = {}
run(st, DAY, GOOD)
out = run(st, DAY + 60, repl(GOOD, "remnawave-node-agent", rc=1, ex=0))
check("плановый перезапуск агента (код 0) — тихо", out == [] and not st["hosts"]["DE7"]["docker"]["active"])
st = {}
run(st, DAY, GOOD)
out = run(st, DAY + 60, repl(GOOD, "remnanode", rc=1, ex=2))
check("перезапуск после сбоя — разовое сообщение", len(out) == 1 and "упал и поднялся сам" in out[0]
      and "упал (завершился с ошибкой, код 2) и перезапустился сам" in out[0] and "⚠️" not in out[0])
SAMPLE_EVENT = out[0]
check("разовое — не висит в проблемах", run(st, DAY + 120, repl(GOOD, "remnanode", rc=1, ex=2)) == []
      and not st["hosts"]["DE7"]["docker"]["active"])
st = {}
run(st, DAY, repl(GOOD, "remnanode", rc=5))
check("контейнер пересоздан (счёт сбросился) — тихо", run(st, DAY + 60, repl(GOOD, "remnanode", rc=0)) == [])

# ночь: критичный — сообщение, остальное — в отчёт
st = {}
run(st, NIGHT, GOOD)
run(st, NIGHT + 60, down)
check("ночью remnanode — сообщение", len(run(st, NIGHT + 120, down)) == 1)
st = {}
run(st, NIGHT, GOOD)
cd = repl(GOOD, "caddy-selfsteal", s="exited")
run(st, NIGHT + 60, cd)
check("ночью caddy-selfsteal — без сообщения, в отложенные", run(st, NIGHT + 120, cd) == []
      and any(x["state"] == "docker" for x in st["hosts"]["DE7"]["deferred"]))
check("ночью восстановился некритичный — тихо", run(st, NIGHT + 180, GOOD) == [])

# старый сборщик без полей Docker — молчим, памяти нет
st = {}
d.process(st, {"DE7": {"samples": [dict(NORM, ts=DAY)]}}, C, DAY + 5)
check("старый сборщик — без контейнеров", "docker" not in st["hosts"]["DE7"])

# --- отчёт 3 раза в день и сводка
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "r.sqlite"))
    C3 = dict(d.DEFAULTS, hosts=[{"name": "rf1", "host": "x"}, {"name": "DE1", "host": "y"}])
    st = {"hosts": {"rf1": {"verdict": "stable", "docker": {"active": {"remnanode": "остановлен (убит, код 137)"}, "running": 2},
                            "deferred": [{"ts": DAY - 60, "state": "docker", "keys": ["remnanode"],
                                          "reasons": ["VPN на ноде (remnanode) — остановлен (убит, код 137)"]},
                                         {"ts": DAY - 50, "state": "docker", "keys": ["caddy-selfsteal"],
                                          "reasons": ["сайт-маскировка (caddy-selfsteal) — остановлен"]}]},
                    "DE1": {"verdict": "stable", "docker": {"active": {}, "running": 3}}}}
    iss, inf = d.report_sections(DAY - 3600, DAY, st, C3, db)
    check("разделы: беда с контейнером — строкой, понятно", "🐳 <b>rf1</b> — VPN на ноде (remnanode): остановлен (убит, код 137)" in iss)
    SAMPLE_REPORT = [x for x in iss + inf if "🐳" in x or "Контейнеры" in x or "caddy" in x]
    check("разделы: ночное, которое ещё лежит, не повторяется; поднявшееся — с пометкой",
          sum("вне рабочих часов" in x for x in iss) == 1 and any("caddy-selfsteal" in x and "вне рабочих" in x for x in iss))
    check("разделы: сведения о контейнерах", "<b>Контейнеры Docker:</b> работают 5 на 2 серверах · проблемы на 1" in inf)
    L = d.report_lines(DAY - 3600, DAY, st, C3, db)
    check("старый блок отчёта тоже видит", any("🐳" in x for x in L))
    check("сводка видит", "🐳" in d.summary(st, C3, DAY))
    st2 = {"hosts": {"rf1": {"verdict": "stable"}}}
    check("разделы: без данных Docker — строки нет", not any("Контейнеры" in x for x in d.report_sections(DAY - 3600, DAY, st2, C3, db)[1]))
    db.close()
old = {"hosts": {"rf1": {"verdict": "stable", "docker": {"active": {"remnanode": "x"}},
                         "deferred": [{"ts": DAY - 60, "state": "docker", "reasons": ["старая запись без keys"]}]}}}
with tempfile.TemporaryDirectory() as tmp:
    db = d.db_open(os.path.join(tmp, "o.sqlite"))
    check("ночная запись без keys не теряется", any("старая запись без keys" in x for x in d.report_sections(DAY - 3600, DAY, old, C3, db)[0]))
    db.close()
if "--show" in sys.argv:
    for t in (SAMPLE_DOWN, SAMPLE_EVENT, SAMPLE_UP):
        print("-" * 40 + "\n" + t)
    print("-" * 40 + "\nотчёт:\n" + "\n".join(SAMPLE_REPORT))
print("dockerwatch: тестов пройдено %d" % ok)
