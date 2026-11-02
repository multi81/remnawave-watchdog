"""Проверка логики guard.py без сети: подменяем чтение пульса, время и отправку в Telegram.

Запуск: python test_guard.py
"""
import datetime as dt
import json
import os
import tempfile

import guard

tmp = tempfile.mkdtemp()
guard.ENV = os.path.join(tmp, "guard.env")
guard.STATE = os.path.join(tmp, "state.json")
guard.LOG = os.path.join(tmp, "log.txt")
open(guard.ENV, "w", encoding="utf-8").write(
    "# настройки\nHEARTBEAT_URL=https://rf1.example/hb.json\nTG_TOKEN='t'\nTG_CHAT=1\nGUARD_NAME=watch2\n")

# 04.10.2026 13:00 UTC = 16:00 МСК; отчёты в 06, 12 и 18 UTC
BASE = dt.datetime(2026, 10, 4, 13, 0, tzinfo=dt.timezone.utc).timestamp()
clock = {"t": BASE}
world = {"kind": "ok", "age": 40, "summary": "2026-10-04 12", "unsent": 0, "offline": False, "port": False}
sent = []
tg = {"up": True}


def fake_fetch(url):
    if world["kind"] != "ok":
        return world["kind"], None
    return "ok", {"ts": clock["t"] - world["age"], "summary": world["summary"], "hours": [6, 12, 18],
                  "unsent": world["unsent"], "offline": world["offline"]}


def fake_tg(env, text):
    if not tg["up"]:
        return "fail"
    sent.append(text)
    return "ok"


guard.fetch = fake_fetch
guard.port_open = lambda url: world["port"]
guard.tg_send = fake_tg
guard.time.time = lambda: clock["t"]


def step(minutes=5):
    clock["t"] += minutes * 60
    before = len(sent)
    guard.main()
    return sent[before:]


def state():
    return json.load(open(guard.STATE, encoding="utf-8"))


def check(cond, what):
    print(("OK   " if cond else "FAIL ") + what)
    if not cond:
        raise SystemExit(1)


check(guard.read_env() == {"HEARTBEAT_URL": "https://rf1.example/hb.json", "TG_TOKEN": "t", "TG_CHAT": "1", "GUARD_NAME": "watch2"},
      "0 настройки читаются: комментарии пропущены, кавычки сняты")

# A. всё в порядке — тихо
check(step() == [] and step() == [] and state()["status"] == "OK", "A1 пульс свежий, отчёт ушёл — тихо")

# B. rf1 не отвечает: тревога после второй проверки подряд, напоминание раз в 3 часа, возврат с длительностью
world["kind"] = "unreach"
check(step() == [], "B1 один раз пульс не прочитался — тревоги ещё нет")
out = step()
check(len(out) == 1 and "Сторож за сторожем (watch2)" in out[0] and "rf1 не отвечает" in out[0] and "сервер не отвечает совсем" in out[0],
      "B2 второй раз подряд — тревога «rf1 не отвечает»")
check("С 16:15 МСК" in out[0] and "никто не сообщит" in out[0], "B3 в тревоге — с какого времени и чем это грозит")
out = []
for _ in range(37):
    out += step()
check(len(out) == 1 and "уже 3 ч" in out[0] and out[0].count("rf1 не отвечает") == 1, "B4 напоминание раз в 3 часа")
world["kind"] = "ok"
world["summary"] = "2026-10-04 18"
check(step() == [], "B5 пульс снова читается — ждём подтверждения")
out = step()
check(len(out) == 1 and "снова в порядке" in out[0] and "Перерыв 3 ч 15 мин" in out[0] and "rf1 не отвечал" in out[0],
      "B6 подтверждено — «снова в порядке» с длительностью")

# C. сервер отвечает, а пульс не читается: порт открыт / файла нет / сторож встал
world["kind"], world["port"] = "unreach", True
out = step() + step()
check(len(out) == 1 and "порт сайта на rf1 открыт, но сайт не отвечает" in out[0], "C1 порт открыт, сайт молчит — так и сказано")
world["kind"] = "nofile"
out = step() + step()
check(len(out) == 1 and "Сторож каналов на rf1 не работает" in out[0] and "файла пульса на нём нет" in out[0], "C2 сервер отвечает, файла пульса нет")
world["kind"], world["age"] = "ok", 1500
out = step() + step()
check(out == [] and "не запускался 25 мин" in state()["detail"], "C3 то же состояние с другой причиной — без повторной тревоги, причина обновлена")
world["age"] = 40
out = step() + step()
check(len(out) == 1 and "снова в порядке" in out[0] and "сторож не запускался" in out[0], "C4 сторож снова запускается")
world["age"] = 550
check(step() + step() + step() == [], "C5 пульс до 10 минут — не тревога (сторож мог пропустить пару запусков)")
world["age"] = 40

# D. сторож работает, но оповещения не уходят / у rf1 нет интернета
world["unsent"] = 3
out = step() + step()
check(len(out) == 1 and "не может отправить сообщения" in out[0] and "неотправленных оповещений: 3" in out[0] and "придут, когда" in out[0],
      "D1 на rf1 копится очередь — тревога")
world["unsent"] = 0
step(), step()
world["offline"] = True
out = step() + step()
check(len(out) == 1 and "нет выхода в интернет" in out[0], "D2 у rf1 нет выхода в интернет — тревога")
world["offline"] = False
step(), step()

# E. отчёт не ушёл: ждём 25 минут после часа отчёта
sent.clear()
clock["t"] = dt.datetime(2026, 10, 5, 6, 0, tzinfo=dt.timezone.utc).timestamp()
check(step(10) + step(10) == [], "E1 09:20 МСК, отчёта за 09:00 ещё нет — рано тревожиться")
out = step(5) + step(5)
check(len(out) == 1 and "отчёт в 09:00 МСК не ушёл" in out[0], "E2 через 25 минут после часа отчёта — тревога")
world["summary"] = "2026-10-05 06"
out = step() + step()
check(len(out) == 1 and "снова в порядке" in out[0], "E3 отчёт ушёл — «снова в порядке»")
check(guard.overdue_report({"hours": [6, 12, 18], "summary": "2026-10-04 18"}, dt.datetime(2026, 10, 5, 3, 0, tzinfo=dt.timezone.utc).timestamp()) is None,
      "E4 ночью ждём только вчерашний вечерний отчёт")
check(guard.overdue_report({"hours": [6, 12, 18], "summary": "2026-10-04 12"}, dt.datetime(2026, 10, 5, 3, 0, tzinfo=dt.timezone.utc).timestamp()) == 18,
      "E5 вчерашний вечерний не ушёл — виден и ночью")
check(guard.overdue_report({"summary": ""}, clock["t"]) is None, "E6 в пульсе нет часов отчёта — не тревожимся")

# F. Telegram недоступен с этого сервера — сообщение не теряется
sent.clear()
tg["up"] = False
world["kind"], world["port"] = "unreach", False
check(step() + step() == [] and len(state()["unsent"]) == 1, "F1 Telegram недоступен — тревога в очереди")
tg["up"] = True
out = step()
check(len(out) == 1 and "rf1 не отвечает" in out[0] and state()["unsent"] == [], "F2 связь вернулась — тревога ушла")

print("\n--- пример тревоги ---\n" + out[0])
print("\nвсе проверки пройдены")
