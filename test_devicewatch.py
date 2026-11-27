"""Тесты devicewatch.py и panel_devices.sh (без сети и серверов): python test_devicewatch.py
Имена и номера — выдуманные."""
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import devicewatch as d

HERE = os.path.dirname(os.path.abspath(__file__))
MSK = d.MSK
WORK = dt.datetime(2026, 11, 27, 14, 0, tzinfo=MSK).timestamp()
MORNING = dt.datetime(2026, 11, 27, 11, 7, tzinfo=MSK).timestamp()
NIGHT = dt.datetime(2026, 11, 27, 3, 0, tzinfo=MSK).timestamp()
C = dict(d.DEFAULTS, host="10.0.0.1", skip_prefixes=["own_fake_"])
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


def src(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


def over(i, user, lim, n, status="ACTIVE", tg=None, common=False):
    return {"id": i, "username": user, "tg": tg, "status": status, "limit": lim, "limit_common": common,
            "devices": n, "active30": n, "last_seen": int(WORK) - 600}


def nh(i, user, fams, n=0, lim=3, common=False):
    return {"id": i, "username": user, "tg": None, "limit": lim, "limit_common": common, "devices": n,
            "ua_families": fams, "last_request": int(WORK) - 300}


DATA = {"over": [over(1, "test_alpha", 3, 5, tg=111), over(2, "test_beta", 2, 3), over(3, "test_null", None, 9),
                 over(4, "test_zero", 0, 9), over(5, "test_ok", 5, 5), over(6, "own_fake_abc", 1, 4),
                 over(7, "watchdog", 1, 4), over(8, "test_off", 1, 4, status="DISABLED")],
        "nohwid": [nh(10, "test_gamma", ["v2rayNG", "Happ"], 1, 3), nh(11, "watchdog", ["xray"]),
                   nh(12, "test_delta", []), nh(13, "test_eps", ["Nimbo"]), nh(14, "test_zero2", ["INCY"], 0, 0),
                   nh(15, "test_null2", ["INCY"], 0, None), nh(16, "test_999", ["INCY"], 0, 999, True),
                   nh(17, "test_full", ["Happ"], 2, 2), nh(18, "test_common", ["INCY"], 0, 5, True)],
        "other": [{"fam": "Mozilla", "users": 4, "requests": 9}, {"fam": "?", "users": 1, "requests": 2}],
        "ts": int(WORK)}

# ---------- форма ответа ----------
check("parse: хороший ответ", d.parse(DATA) is DATA)
check("parse: без списка — None", d.parse({"over": []}) is None and d.parse(None) is None and d.parse([1]) is None)
check("parse: ошибка скрипта — None", d.parse({"error": "no arguments accepted"}) is None)

# ---------- разбор ----------
cur = d.classify(DATA, C)
check("превышение: 5 из 3 и 3 из 2", set(cur["over"]) == {"1", "2"})
check("лимит NULL (общий) — не в счёт", "3" not in cur["over"])
check("лимит 0 (без ограничения) — не в счёт", "4" not in cur["over"])
check("ровно лимит — не превышение", "5" not in cur["over"])
check("владелец (префикс) и служебный пропущены", "6" not in cur["over"] and "7" not in cur["over"])
check("неактивная подписка пропущена", "8" not in cur["over"])
check("без HWID: программы по алфавиту", cur["nohwid"]["10"]["families"] == ["Happ", "v2rayNG"])
check("без HWID: служебный пользователь сторожа (xray) пропущен", "11" not in cur["nohwid"])
check("без HWID: пустой список программ — не в счёт", "12" not in cur["nohwid"])
check("без HWID: лимит 0, NULL и 999 (без ограничения) — не в счёт",
      not {"14", "15", "16"} & set(cur["nohwid"]))
check("без HWID: устройств столько, сколько разрешено, — «упёрся в лимит?»", cur["nohwid"]["17"]["at_limit"]
      and not cur["nohwid"]["10"]["at_limit"])
check("прочие запросы — только счёт", cur["other"] == {"Mozilla": [4, 9], "?": [1, 2]})
check("parse: other не список — None", d.parse({"over": [], "nohwid": [], "other": 1}) is None)
check("в записях нет адресов", not IP_RE.search(json.dumps(cur)))

# ---------- настройки ----------
with tempfile.TemporaryDirectory() as t:
    json.dump({"skip_users": ["svc_one"], "skip_prefixes": ["own_"], "our_ips": ["1.2.3.4"]},
              open(os.path.join(t, "banme.json"), "w", encoding="utf-8"))
    json.dump({"host": "10.9.9.9", "port": 2222}, open(os.path.join(t, "panel_users.json"), "w", encoding="utf-8"))
    c1 = d.cfg(t)
    check("свои списки — из banme.json", c1["skip_users"] == ["svc_one"] and c1["skip_prefixes"] == ["own_"])
    check("сервер — из panel_users.json, ключ свой (новый)", c1["host"] == "10.9.9.9" and c1["port"] == 2222
          and c1["key"].endswith("panel_devices_ed25519") and c1["known_hosts"].endswith("panel_known_hosts"))
    check("по умолчанию: сводка в 11, сразу — выключено, включено", c1["summary_hour"] == 11
          and c1["alert_new_over"] is False and c1["enabled"] is True)
    json.dump({"skip_users": ["svc_two"], "alert_new_over": True, "enabled": False},
              open(os.path.join(t, "devices.json"), "w", encoding="utf-8"))
    c2 = d.cfg(t)
    check("devices.json поверх, списки пропуска добавляются", c2["skip_users"] == ["svc_one", "svc_two"]
          and c2["skip_prefixes"] == ["own_"] and c2["alert_new_over"] and not c2["enabled"])
    check("банме-адреса в настройки устройств не попадают", "our_ips" not in c2)
    check("свои из devices.json пропускаются", "x" not in d.classify(
        {"over": [over("x", "svc_two", 1, 5)], "nohwid": []}, c2)["over"])
    # состояние banme: только счёт адресов
    json.dump({"day": [{"ts": 1, "user": "test_eps", "score": 50, "strong": True, "foreign": 3, "dropped": 0},
                       {"ts": 2, "user": "test_eps", "score": 40, "strong": False, "foreign": 1, "dropped": 1}]},
              open(os.path.join(t, "banme_state.json"), "w", encoding="utf-8"))
    simul = d.banme_simul(os.path.join(t, "banme_state.json"))
    check("banme: наибольшее число чужих адресов и сильные", simul == {"test_eps": (3, 1)})
    check("banme: нет файла — пусто", d.banme_simul(os.path.join(t, "nope.json")) == {})

# ---------- получение: ssh без слов ----------
calls = []


def fake_run(out, rc=0):
    def f(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, out, "")
    return f


check("fetch: ответ прочитан", d.fetch(C, fake_run(json.dumps(DATA))) == DATA)
cmd = calls[-1]
check("fetch: новый ключ, строгая проверка хоста, без слов после адреса", cmd[-1] == "root@10.0.0.1"
      and "panel_devices_ed25519" in cmd[cmd.index("-i") + 1] and "StrictHostKeyChecking=yes" in cmd and "-T" in cmd)
check("fetch: мусор — None", d.fetch(C, fake_run("not json")) is None)
check("fetch: ошибка ssh — None", d.fetch(C, fake_run(json.dumps(DATA), 255)) is None)
check("fetch: нет адреса панели — None, ssh не зовётся", d.fetch(dict(C, host=""), fake_run("{}")) is None
      and len(calls) == 3)

# ---------- новое / изменилось ----------
prev = {"over": {"1": {"devices": 4, "limit": 3}, "9": {"devices": 2, "limit": 1}},
        "nohwid": {"10": {"families": ["Happ"]}, "13": {"families": ["Nimbo"]}}}
check("сравнивать не с чем — без отметок", d.mark("over", "1", cur["over"]["1"], None) == "")
check("было 4 — изменилось", d.mark("over", "1", cur["over"]["1"], prev) == "изменилось (было 4)")
check("не было — новое", d.mark("over", "2", cur["over"]["2"], prev) == "новое")
check("программы изменились", d.mark("nohwid", "10", cur["nohwid"]["10"], prev) == "изменилось (было Happ)")
check("то же — без отметки", d.mark("nohwid", "13", cur["nohwid"]["13"], prev) == "")

# ---------- сводка ----------
s = d.summary(cur, prev, C, WORK, {"test_eps": (3, 1)})
check("сводка: оба списка с числами", "Больше устройств, чем лимит: 2" in s and "без HWID (лимит на них не действует): 4" in s)
check("сводка: 5 из 3, tg", "<b>test_alpha</b> · tg 111 — 5 из 3" in s)
check("сводка: новое и изменилось", "test_beta" in s and "— новое" in s and "изменилось (было 4)" in s)
check("сводка: программы и общий лимит", "Happ, v2rayNG" in s and "лимит 3;" in s and "лимит 5 (общий)" in s)
check("сводка: упёрся в лимит", s.count("упёрся в лимит?") == 1 and "<b>test_full</b>" in s)
check("сводка: прочие запросы без пользователей", "Mozilla — польз. 4, запросов 9" in s and "(пусто) — польз. 1" in s)
check("сводка: banme — счёт адресов", "banme: до 3 чужих адресов одновременно, сильных 1" in s)
check("сводка: итог по программам", "Программы без HWID:" in s and "Nimbo 1" in s)
check("сводка: ушедшее превышение", "Превышение ушло: 1" in s)
check("сводка: адресов нет", not IP_RE.search(s))
check("сводка: только наблюдение", "ничего не блокируется" in s)
check("первая сводка — пометка", "Первая сводка" in d.summary(cur, None, C, WORK))
evil = d.classify({"over": [over(1, "<b>x</b>&", 1, 3)], "nohwid": []}, C)
check("имя экранируется", "&lt;b&gt;x&lt;/b&gt;&amp;" in d.summary(evil, None, C, WORK))
many = d.classify({"over": [over(i, "test_%02d" % i, 1, 3) for i in range(40)], "nohwid": []}, C)
check("длинный список обрезан", "… и ещё 15" in d.summary(many, None, C, WORK))
check("пустые списки — «нет»", d.summary({"over": {}, "nohwid": {}}, None, C, WORK).count("\nнет") == 2)

# ---------- сразу (по умолчанию выключено) ----------
st = {"prev": {"over": {}}}
check("сразу: выключено по умолчанию", d.alerts(st, cur, C, WORK) == [])
CA = dict(C, alert_new_over=True)
st0 = {}
check("сразу: до первой сводки молчим, текущее запомнено", d.alerts(st0, cur, CA, WORK) == []
      and st0["alerted"] == {"1": 5, "2": 3})
a = d.alerts(st, cur, CA, WORK)
check("сразу: только превышение больше чем на одно (5 из 3), не 3 из 2", len(a) == 1 and "test_alpha" in a[0]
      and "test_beta" not in a[0])
check("сразу: повтор не шлётся", d.alerts(st, cur, CA, WORK + 3600) == [])
cur2 = json.loads(json.dumps(cur))
cur2["over"]["1"]["devices"] = 6
check("сразу: стало больше — снова", len(d.alerts(st, cur2, CA, WORK + 7200)) == 1)
check("сразу: ночью тихо", d.alerts({"prev": {"over": {}}}, cur, CA, NIGHT) == [])
check("сразу: было во вчерашней сводке — не шлётся", d.alerts({"prev": {"over": {"1": {"devices": 5}}}}, cur, CA, WORK) == [])
check("сразу: адресов нет", not IP_RE.search(a[0]))

# ---------- проход целиком ----------
sent = []


def send(text):
    sent.append(text)
    return "ok"


st = {}
d.run([], C, st, None, WORK, send)
d.run([], C, st, None, WORK, send)
check("сбой чтения: считается, без сообщения", st["fetch_fail"] == 2 and sent == [])
d.run([], C, st, None, WORK, send)
check("сбой чтения: на третий раз в рабочие часы — сообщение", len(sent) == 1 and "не читаются" in sent[0])
d.run([], C, st, None, WORK + 3600, send)
check("сбой чтения: повтор не шлётся", len(sent) == 1)
sent.clear()
st = {}
for k in range(3):
    d.run([], C, st, None, NIGHT + k * 3600, send)
check("сбой чтения: третий ночью — тихо", sent == [] and st["fetch_fail"] == 3)
d.run([], C, st, None, WORK, send)
check("сбой чтения: утром, при сбоях дальше, — сообщение", len(sent) == 1 and "не читаются" in sent[0])
d.run([], C, st, DATA, WORK + 3600, send)
check("сбой чтения: снова читается — одно сообщение, счётчик сброшен", len(sent) == 3 and "снова читаются" in sent[1]
      and sum("снова читаются" in x for x in sent) == 1
      and st["fetch_fail"] == 0 and not st["fetch_alerted"])
sent.clear()
st = {}
d.run([], C, st, DATA, NIGHT, send)
check("ночью до сводки — тихо, данные запомнены", sent == [] and st["cur"]["over"] and st["summary_day"] == "2026-11-26")
d.run([], C, st, DATA, MORNING, send)
check("в 11 — одна сводка, первая", len(sent) == 1 and "Первая сводка" in sent[0] and st["summary_day"] == "2026-11-27"
      and st["prev"] == st["cur"])
d.run([], C, st, DATA, MORNING + 3600, send)
check("в тот же день вторая не шлётся", len(sent) == 1)
data2 = json.loads(json.dumps(DATA))
data2["over"].append(over(20, "test_new", 1, 2))
d.run([], C, st, data2, MORNING + 86400, send)
check("назавтра — новое отмечено", len(sent) == 2 and "test_new" in sent[1] and "— новое" in sent[1])
d.run(["--summary"], C, st, data2, MORNING + 86400 + 60, send)
check("--summary: сводка сейчас, день и «вчера» не сдвигаются", len(sent) == 3 and st["summary_day"] == "2026-11-28")
st = {}
d.run([], C, st, DATA, WORK, send)
check("первый проход после 11 — сводка завтра, не сейчас", len(sent) == 3 and st["summary_day"] == "2026-11-27")
d.run([], C, st, DATA, NIGHT + 86400, send)
check("первый проход после 11: ночью тоже тихо", len(sent) == 3)
d.run([], C, st, DATA, MORNING + 86400, send)
check("первый проход после 11: сводка назавтра в 11", len(sent) == 4 and st["summary_day"] == "2026-11-28")
EVENING = dt.datetime(2026, 11, 27, 20, 7, tzinfo=MSK).timestamp()
st = {"summary_day": "2026-11-26"}
d.run([], C, st, DATA, EVENING, send)
check("после work_to сводку не шлём (догонит завтра утром)", len(sent) == 4 and st["summary_day"] == "2026-11-26")
for res, day in (("bad", "2026-11-27"), ("fail", "2026-11-26")):
    st = {"summary_day": "2026-11-26"}
    d.run([], C, st, DATA, MORNING, lambda t, r=res: r)
    check("сводка: ответ Telegram «%s» — день %s" % (res, "отмечен" if res == "bad" else "не отмечен"),
          st["summary_day"] == day)
st2 = {"cur": cur, "cur_ts": WORK - 7 * 3600}
d.run(["--summary"], C, st2, None, WORK, send)
check("старые данные — пометка в сводке", "Свежих данных из панели нет" in sent[-1])
check("ни в одном сообщении нет адресов", not any(IP_RE.search(x) for x in sent))

# ---------- скрипт панели: статически ----------
P = src("panel_devices.sh")
check("panel_devices.sh: LF, #!/bin/bash", "\r" not in P and P.startswith("#!/bin/bash\n"))
check("panel_devices.sh: отказ на любые слова", 'if [ -n "${SSH_ORIGINAL_COMMAND:-}" ] || [ "$#" -gt 0 ]; then' in P)
check("panel_devices.sh: только чтение и предел времени", "default_transaction_read_only=on" in P
      and "statement_timeout=15000" in P)
check("panel_devices.sh: роль watch_ro, как watch-user-info", "-U watch_ro" in P and 'psql -U "$db_user"' in P)
check("panel_devices.sh: только активные, не больше 200 в списке", "from users u where u.status = 'ACTIVE'" in P
      and P.count("limit 200") == 2 and "limit 10" in P)
check("panel_devices.sh: NULL — общий запасной лимит, 0 — не превышение", "FALLBACK_LIMIT=999" in P
      and "coalesce(u.hwid_device_limit, :fallback)" in P and "l.eff > 0 and dev.devices > l.eff" in P)
check("panel_devices.sh: без HWID — только подписки с действующим лимитом", "l.eff between 1 and 998" in P)
check("panel_devices.sh: семейства без учёта регистра, белый список VPN-программ", "lower(substring(" in P
      and "when 'incy' then 'INCY'" in P and "when 'happ' then 'Happ'" in P and "r.fam is null" in P)
check("panel_devices.sh: совпадение по времени — соединением, не подзапросом на каждую строку", "exists" not in P
      and "interval '120 seconds'" in P)
check("panel_devices.sh: адресы клиентов не выбираются", "request_ip" not in P and "ip" not in re.findall(r"as (\w+)", P))
check("panel_devices.sh: только таблицы роли watch_ro", set(re.findall(r"\b(?:from|join)\s+(\w+)", P))
      <= {"users", "hwid_user_devices", "user_subscription_request_history", "dev", "fam", "req", "ov", "nh", "oth",
          "lim", "dt", "lateral", "now"})
check("panel_devices.sh: без записи в базу", not re.search(r"\b(insert|update|delete|drop|alter|create|grant)\b",
                                                          P.split("<<'SQL'", 1)[1], re.I))

BASH = shutil.which("bash")


def posix(p):
    p = p.replace("\\", "/")
    return ("/" + p[0].lower() + p[2:]) if re.match(r"^[A-Za-z]:/", p) else p


if BASH:
    check("bash -n panel_devices.sh", subprocess.run([BASH, "-n", posix(os.path.join(HERE, "panel_devices.sh"))]).returncode == 0)
    with tempfile.TemporaryDirectory() as t:
        fake = os.path.join(t, "docker")
        with open(fake, "w", encoding="utf-8", newline="\n") as f:
            f.write('#!/bin/bash\necho "ARGS $*" >> "$FAKE_LOG"\n'
                    'if [ "$2" = "-i" ]; then cat > "$FAKE_LOG.sql"; echo \'{"over": [], "nohwid": [], "ts": 1}\'; fi\n'
                    'exit 0\n')
        os.chmod(fake, 0o755)
        log = posix(os.path.join(t, "log"))

        def panel(orig, *args):
            env = dict(os.environ, FAKE_LOG=log, FAKE_DIR=posix(t))
            env.pop("SSH_ORIGINAL_COMMAND", None)
            if orig is not None:
                env["SSH_ORIGINAL_COMMAND"] = orig
            r = subprocess.run([BASH, "-c", 'PATH="$FAKE_DIR:$PATH"; exec bash "$0" "$@"',
                                posix(os.path.join(HERE, "panel_devices.sh"))] + list(args),
                               env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)
            return r.returncode, r.stdout

        for bad in ("violations", "x; id", "$(id)", "a b"):
            rc, out = panel(bad)
            check("panel: слово «%s» — отказ, база не читается" % bad, rc == 1 and "no arguments" in out
                  and not os.path.exists(os.path.join(t, "log")))
        rc, out = panel(None, "x")
        check("panel: аргумент запуска — отказ", rc == 1 and not os.path.exists(os.path.join(t, "log")))
        rc, out = panel(None)
        lg = open(os.path.join(t, "log"), encoding="utf-8").read() if os.path.exists(os.path.join(t, "log")) else ""
        check("panel: без слов — JSON из базы", rc == 0 and json.loads(out) == {"over": [], "nohwid": [], "ts": 1})
        check("panel: проверка роли watch_ro, затем запрос под ней и только на чтение",
              "-U watch_ro -d postgres -At -v ON_ERROR_STOP=1 -c select 1 from" in lg
              and "default_transaction_read_only=on" in lg and lg.strip().splitlines()[-1].count("-U watch_ro") == 1
              and "-v fallback=999" in lg)
        sql = open(os.path.join(t, "log.sql"), encoding="utf-8").read()
        check("panel: в базу ушёл запрос json_build_object", "json_build_object" in sql and "'over'" in sql)
else:
    print("bash не найден — проверки скрипта панели запуском пропущены")

for f in ("devicewatch.py", "test_devicewatch.py"):
    check("%s: LF" % f, "\r" not in src(f))
print("devicewatch: тестов пройдено %d" % ok)
