"""Проверка логики probe.py, blockwatch.py, netprobe.py, vantage_agent.py и build_channels.py без сети: подменяем проверки, время и отправку в Telegram.

Запуск: python test_probe.py
"""
import json
import os
import re
import tempfile

# свои сайты для тестов — как в site.example.json, плюс четвёртый сайт и исключение для взгляда «снаружи»
_SITE = os.path.join(tempfile.mkdtemp(), "site.json")
json.dump({"sites": [{"name": "панель", "url": "https://panel.example.com/api/auth/status"},
                     {"name": "кабинет", "url": "https://cab.example.com/"},
                     {"name": "админка", "url": "https://admin.example.com/api/v2/health", "key": "admin",
                      "impact": "это админка защиты от злоупотреблений, на VPN у пользователей не влияет."}],
           "site_hosts": ["panel.example.com", "sub.example.com", "cab.example.com", "admin.example.com"],
           "domains": ["example.com", "example.net"], "no_vantage": ["fi1.example.net"]},
          open(_SITE, "w", encoding="utf-8"), ensure_ascii=False)
os.environ["CHANNEL_WATCH_SITE"] = _SITE
import blockwatch  # noqa: E402
import build_channels  # noqa: E402
import probe  # noqa: E402

tmp = tempfile.mkdtemp()
probe.ETC = tmp
probe.STATE = os.path.join(tmp, "state.json")
probe.LOG = os.path.join(tmp, "log.txt")
probe.HISTORY = os.path.join(tmp, "history.json")
# проверки блокировок в общих сценариях молчат (сети нет); сами они проверяются в разделах U и X
blockwatch.ETC = tmp
blockwatch.LISTS_FILE = os.path.join(tmp, "lists.json")
real_dns_check, real_deep_many, real_health = blockwatch.dns_check, blockwatch.deep_many, blockwatch.agents_health
blockwatch.dns_check = lambda names, port, agents=(): {}
blockwatch.deep_many = lambda chans, via_for, agents, bases: {}
blockwatch.agents_health = lambda agents: {}
# сводку за неделю в общих сценариях не шлём (проверяется отдельно, в разделе W)
real_weekly, probe.weekly_text = probe.weekly_text, lambda st, hist, now: None

POLAND = "🇵🇱 Poland  🌐 |🔄"
SUB = probe.SUB_NAME
CHANS = [{"name": POLAND, "port": 21004, "entry": "pl1.example.net", "entry_port": 443,
          "sni": "pl1.example.net", "security": "reality", "expected_exit": None},
         {"name": "NL1", "port": 21003, "entry": "nl1.example", "entry_port": 443, "sni": "dl.google.com",
          "security": "reality", "expected_exit": None},
         {"name": "Резерв", "port": 21007, "entry": "rf1.example", "entry_port": 443, "sni": "x",
          "security": "reality", "expected_exit": "9.9.9.9"}]
json.dump({"baseline_port": 21000, "channels": CHANS}, open(os.path.join(tmp, "channels.json"), "w", encoding="utf-8"))

BASE = 1_800_000_000.0
DAY = 86400
clock = {"t": BASE}
world = {"alive": {}, "deep": {}, "diag": {}, "svc": {}, "sites": {}, "cross": {}, "certs": {}, "domains": {}, "lat": {},
         "confirm": {}}
sent = []
deep_calls, svc_calls, cert_calls = [], [], []

OK_DEEP = (524288, 0.6, 800_000.0, "1.1.1.1")
DIAG_DEAD = {"ping": False, "tcp": "timeout", "tcp_ms": None, "tls": None}
OK_SVC = {"Telegram": "302", "YouTube": "204", "Instagram": "200", "ChatGPT": "401"}
CERT_EXP = {"sub.example.com": BASE + 40 * DAY}  # остальные — BASE + 60 дней


def fake_quick(port):
    # задержка 50 мс, соединение 0.25 с — если для порта не задано иное
    return (True, 0) + world["lat"].get(port, (0.05, 0.25)) if world["alive"].get(port, True) else (False, 28, 0.0, 0.0)


def fake_deep(port):
    deep_calls.append((clock["t"], port))
    return world["deep"].get(port, OK_DEEP if port != 21007 else (524288, 0.6, 800_000.0, "9.9.9.9"))


def fake_services(port):
    svc_calls.append((clock["t"], port))
    return dict(world["svc"].get(port, OK_SVC))


def fake_cert(host, port=443, sni=None):
    cert_calls.append(sni)
    return dict(world["certs"].get(sni, {"exp": CERT_EXP.get(sni, BASE + 60 * DAY), "life": 89}))


probe.quick = fake_quick
probe.deep = fake_deep
confirm_calls = []
FAST_CONFIRM = (4194304, 0.6, 7_000_000.0)  # закачка побольше по умолчанию — быстрая


def fake_confirm(port):
    confirm_calls.append((clock["t"], port))
    return world["confirm"].get(port, FAST_CONFIRM)


probe.confirm_speed = fake_confirm
probe.services = fake_services
site_calls = []


def fake_site(name):
    site_calls.append((clock["t"], name))
    return world["sites"].get(name, "200")


probe.check_site = fake_site
# сайт через зарубежную ноду: по умолчанию тоже не отвечает
probe.site_cross = lambda name, via: (probe.compact(via["name"]), world["cross"].get(name, "000")) if via else None
probe.cert_info = fake_cert
probe.domain_expiry = lambda d: world["domains"].get(d, BASE + 200 * DAY)
probe.diagnose = lambda ch: world["diag"].get(ch["port"], DIAG_DEAD)
tg = {"up": True}


def fake_tg(text):
    if not tg["up"]:
        return "fail"
    sent.append(text)
    return "ok"


probe.tg_send = fake_tg
probe.time.time = lambda: clock["t"]
probe.STAGGER = 0  # в тестах каналы не ждут друг друга
# отчёт в этих сценариях не шлём: помечаем, что за текущий час из списка он уже был
probe.SUMMARY_HOURS_UTC = (0,)
today = probe.dt.datetime.now(probe.dt.timezone.utc).strftime("%Y-%m-%d") + " 00"


def step(minutes=2):
    clock["t"] += minutes * 60
    before = len(sent)
    probe.main()
    return sent[before:]


def load():
    return json.load(open(probe.STATE, encoding="utf-8"))


def state(name=POLAND):
    return load()["channels"][name]


def report(sub=None, changes=()):
    """Текст отчёта по накопленному на эту минуту (как probe.py --show)."""
    return probe.report_text(probe.init_state(load(), clock["t"]), clock["t"], sub, changes)


def days(ts):
    return int((ts - clock["t"]) // DAY)


def check(cond, what):
    print(("OK   " if cond else "FAIL ") + what)
    if not cond:
        raise SystemExit(1)


# первый запуск: всё работает, сводку глушим
probe.main()
st = load()
st["last_summary"] = today
json.dump(st, open(probe.STATE, "w", encoding="utf-8"))
sent.clear()

# A. как с Poland: два провала подряд -> тревога с причиной; потом два успеха -> «снова работает» с длительностью
world["alive"][21004] = False
check(step() == [], "A1 один провал — тревоги ещё нет")
out = step()
check(len(out) == 1 and "Недоступен: 🇵🇱 Poland 🌐 |🔄" in out[0], "A2 второй провал подряд — тревога «недоступен»")
check("Что проверил" in out[0] and "не пингуется" in out[0] and "Похоже на" in out[0], "A3 в тревоге есть проверки и причина")
check("остальные каналы: работают" in out[0], "A4 в тревоге сказано, что остальные каналы работают")
world["alive"][21004] = True
n = len(deep_calls)
check(step() == [] and len(deep_calls) > n, "A5 первый успех — тревоги нет, но закачка сделана сразу (не ждём 10 минут)")
out = step()
check(len(out) == 1 and "Снова работает" in out[0] and "Был недоступен 4 мин" in out[0], "A6 второй успех — «снова работает», сбой 4 мин")
check(state()["status"] == "OK" and state()["inc"] == 1 and state()["bad_sec"] == 240, "A7 состояние OK, сбой учтён для сводки")
for _ in range(3):
    check(step() == [], "A8 дальше тихо")

# B. разовый провал не считается
world["alive"][21003] = False
check(step() == [], "B1 разовый провал NL1 — тихо")
world["alive"][21003] = True
check(step() == [] and step() == [], "B2 после разового провала тревог нет")

# C. медленно: порог 5 Мбит/с, и судим по закачке 4 МБ — на 512 КБ скорость упирается в разгон соединения
SLOW_QUICK = (524288, 9.0, 58_000.0, "1.1.1.1")       # быстрая закачка: 0,5 Мбит/с
SLOW_BIG = (1_160_000, 20.0, 58_000.0)                # закачка 4 МБ за 20 с не дошла: те же 0,5 Мбит/с
world["deep"][21004], world["confirm"][21004] = SLOW_QUICK, SLOW_BIG
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "Медленно" in out[0] and "0.5 Мбит/с на закачке 4 МБ (порог — 5 Мбит/с)" in out[0],
      "C1 «медленно» подтверждено закачкой побольше и отправлено один раз; подтверждение — следующей же проверкой")
world["deep"].pop(21004), world["confirm"].pop(21004)
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "Снова работает" in out[0] and "Работал медленно" in out[0], "C2 возврат скорости — «снова работает»")
world["deep"][21004] = SLOW_QUICK                     # на 512 КБ мало, а закачка 4 МБ идёт быстро
n = len(confirm_calls)
out = []
for _ in range(8):
    out += step()
check(out == [] and len(confirm_calls) > n and all(p == 21004 for _, p in confirm_calls[n:]),
      "C3 на 512 КБ мало, а на 4 МБ скорость в порядке — не тревога; перепроверяется только этот канал")
world["confirm"][21004] = (4194304, 8.4, 500_000.0)   # 4 МБ дошли, но на 4 Мбит/с — ниже порога
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "Медленно" in out[0] and "4.0 Мбит/с на закачке 4 МБ" in out[0], "C4 закачка 4 МБ дошла, но медленнее 5 Мбит/с — «медленно»")
world["confirm"][21004] = (0, 20.0, 0.0)               # сама перепроверка не пошла вовсе
out = []
for _ in range(8):
    out += step()
check(any("Снова работает" in x for x in out), "C5 перепроверка не дала ни байта — это её разовый сбой, «медленно» по ней не держим")
world["deep"].pop(21004), world["confirm"].pop(21004)
stc = load()
stc["channels"][POLAND]["base"]["spd"] = 4.7           # обычная скорость этого канала на 512 КБ — 4,7 Мбит/с
json.dump(stc, open(probe.STATE, "w", encoding="utf-8"))
world["deep"][21004] = (524288, 1.0, 500_000.0, "1.1.1.1")  # 4,0 Мбит/с: меньше порога, но обычное для канала
n = len(confirm_calls)
for _ in range(8):
    step()
check(len(confirm_calls) == n, "C6 меньше 5 Мбит/с на 512 КБ, но это обычная скорость канала — закачку побольше зря не гоняем")
world["deep"][21004] = (524288, 2.0, 250_000.0, "1.1.1.1")  # 2,0 Мбит/с: заметно ниже обычного
for _ in range(6):
    step()
check(len(confirm_calls) > n, "C7 заметно ниже обычного для канала — перепроверяем закачкой побольше")
check(probe.classify(CHANS[0], (300_000, 20.0, 15_000.0, "1.1.1.1"))[0] == "SLOW"
      and "512 КБ не докачались за 20 с" in probe.classify(CHANS[0], (300_000, 20.0, 15_000.0, "1.1.1.1"))[1],
      "C8 даже 512 КБ не докачались — «медленно» без перепроверки")
world["deep"].pop(21004)
stc = load()
stc["channels"][POLAND]["base"].pop("spd")
json.dump(stc, open(probe.STATE, "w", encoding="utf-8"))
for _ in range(6):
    step()
sent.clear()

# D. «душат» и «не тот выход»
world["deep"][21004] = (20_000, 20.0, 1000.0, "")
out = step(10) + step()
check(any("Душат" in m and "пришло 19 КБ из 512" in m for m in out), "D1 «душат» с цифрами")
check("🧊 🇵🇱 Poland — душат уже" in report(), "D2 в отчёте канал с бедой — отдельной строкой со значком")
world["deep"].pop(21004)
world["deep"][21007] = (524288, 0.6, 800_000.0, "5.5.5.5")
out = []
for _ in range(7):
    out += step()
check(any("Не тот выход: Резерв" in m and "выход 5.5.5.5, ожидался 9.9.9.9" in m for m in out), "D3 «не тот выход»")
world["deep"].pop(21007)
for _ in range(7):
    step()

# E. долгий сбой: напоминание раз в час, причина — «порт открыт, VPN не проходит»
sent.clear()
world["alive"][21004] = False
world["diag"][21004] = {"ping": True, "tcp": "open", "tcp_ms": 67, "tls": True}
out = []
for _ in range(34):
    out += step()
check(sum("Недоступен" in m for m in out) == 1, "E1 одна тревога о сбое")
check("порт 443: открыт (67 мс)" in out[0] and "TLS на порту: отвечает" in out[0] and "VPN-соединение не проходит" in out[0], "E2 причина: сервер и порт живы, VPN не проходит")
check(sum("Всё ещё недоступен" in m for m in out) == 1, "E3 одно напоминание за час с небольшим")
text = report()
_ln = text.split("\n"); _ci = next(i for i, l in enumerate(_ln) if "Каналы: работают" in l)
check("Каналы: работают 2 из 3" in text and _ln[_ci + 1].startswith("🔴 🇵🇱 Poland — недоступен уже 1 ч")
      and "Требует внимания" in text and "не работают 1 из 3" in text,
      "E4 в отчёте неработающий канал стоит первым, в шапке — сколько работает")

# F. отказали сразу все каналы (контрольный без VPN жив) — причина «сбой сети», а не одна нода
world["alive"][21003] = False
world["alive"][21007] = False
out = step() + step()
check(any("Недоступен: NL1" in m and "несколько каналов" in m for m in out), "F1 при массовом сбое причина — сеть")
world["alive"] = {}
for _ in range(3):
    step()

# H. Telegram недоступен в момент тревоги — оповещение уходит позже, не теряется
sent.clear()
tg["up"] = False
world["alive"][21003] = False
check(step() + step() == [], "H1 Telegram недоступен — ничего не ушло")
check(len(load()["unsent"]) == 1, "H2 тревога лежит в очереди")
tg["up"] = True
out = step()
check(len(out) == 1 and "Недоступен: NL1" in out[0], "H3 связь вернулась — тревога из очереди ушла")
world["alive"] = {}
for _ in range(3):
    step()

# I. у самой rf1 пропал интернет: тревог по каналам нет, после возврата — одно сообщение
sent.clear()
world["alive"][21000] = False
check(step() + step() + step() == [], "I1 rf1 без интернета — каналы не проверяются, тревог нет")
world["alive"].pop(21000)
out = step()
check(len(out) == 1 and "У самой rf1 не было интернета 6 мин" in out[0], "I2 после возврата — сообщение о перерыве")
check(step() == [], "I3 дальше тихо")

# J. сервисы через ноды: раз в полчаса, не в одном запуске с закачкой; в отчёте — только то, что не открывается
svc_calls.clear()
for _ in range(20):
    step()
check(all(1 <= sum(p == port for _, p in svc_calls) <= 2 for port in (21003, 21004, 21007)),
      "J1 сервисы проверяются раз в полчаса, а не каждый запуск")
check(not set(svc_calls) & set(deep_calls), "J2 проверка сервисов и закачка не попадают в один запуск")
check("Сервисы через ноды:</b> Telegram, YouTube, Instagram, ChatGPT — везде ✅" in report(), "J3 всё открывается — одна строка")
world["svc"][21004] = dict(OK_SVC, ChatGPT="403")
step(30), step()
text = report()
check("Сервисы через ноды:</b> Telegram, YouTube, Instagram — везде ✅" in text
      and "❌ ChatGPT не открывается: 🇵🇱 Poland (отказ: адрес или регион закрыт)" in text, "J4 ChatGPT закрыт на одной ноде — названы сервис, нода и причина")
world["svc"].pop(21004)
step(30), step()
text = report()
check("⚠️ ChatGPT — были сбои: 🇵🇱 Poland (1 из " in text and "не открывается" not in text, "J5 сбой прошёл — в отчёте «были сбои», а не «не открывается»")

# K. сайты владельца и страница подписки: тревога сразу, а не только в отчёте
ALL_OK = "Сайты:</b> панель ✅ · подписка ✅ · кабинет ✅ · админка ✅"
check(ALL_OK in report(), "K1 сайты в порядке — одна строка, подписка среди них")
sent.clear()
world["sites"]["панель"] = "000"
check(step(10) == [] and "панель ⚠️ 1 разовый сбой" in report(), "K2 один провал панели — тревоги нет, в отчёте разовый сбой")
out = step()
check(len(out) == 1 and "Не отвечает: панель" in out[0] and "нет соединения" in out[0], "K3 второй провал подряд (через 2 минуты, а не через 10) — тревога")
check("ни с rf1, ни через зарубежную ноду (🇵🇱 Poland)" in out[0] and "Для пользователей:</b> VPN у подключённых работает" in out[0],
      "K4 в тревоге: через зарубежную ноду тоже не отвечает, и что это значит для пользователей")
check("панель ❌ не отвечает 2 мин" in report(), "K5 в отчёте — сколько сайт уже не отвечает")
n = len(site_calls)
step()
check([name for _, name in site_calls[n:]] == ["панель"], "K6 лежащий сайт проверяется каждый запуск, остальные — по расписанию")
out = []
for _ in range(31):
    out += step()
check(len(out) == 1 and "Всё ещё не отвечает: панель" in out[0] and "уже 1 ч" in out[0], "K7 напоминание раз в час")
world["sites"].pop("панель")
check(step() == [], "K8 первый ответ после сбоя — ещё тихо")
out = step()
check(len(out) == 1 and "Снова отвечает: панель" in out[0] and "Перерыв 1 ч 08 мин" in out[0], "K9 второй ответ — «снова отвечает» с длительностью")
check("панель ⚠️ 1 сбой, 1 ч 08 мин" in report() and "кабинет ✅" in report(), "K10 в отчёте за период остался сбой с длительностью")
world["sites"]["кабинет"] = "000"
world["cross"]["кабинет"] = "200"
out = step(10) + step()
check(len(out) == 1 and "через зарубежную ноду (🇵🇱 Poland) сервер отвечает, а с rf1 — нет" in out[0], "K11 с rf1 не открывается, из-за границы открывается — так и сказано")
world["sites"]["кабинет"] = "502"
world["sites"]["админка"] = "403"
out = step(10) + step()
check(len(out) == 1 and "Не отвечает: админка" in out[0] and "отвечает кодом 403" in out[0] and "списка разрешённых" in out[0]
      and "кабинет" not in out[0], "K12 отказ 403 — подсказка про список разрешённых адресов; про лежащий кабинет повторно не пишем")
world["sites"] = {SUB: "502"}
out = step(30) + step() + step()
check(any("Не отвечает: подписка" in m and "отвечает кодом 502" in m and "страница подписки или панель" in m for m in out),
      "K13 подписка не отдаётся — тревога с причиной")
check("".join(out).count("Снова отвечает") == 2, "K14 кабинет и админка вернулись — по сообщению на каждый")
world["sites"] = {}
out = step() + step()
check(len(out) == 1 and "Снова отвечает: подписка" in out[0], "K15 подписка вернулась")
world["alive"][21004] = world["alive"][21003] = False
world["sites"]["панель"] = "000"
out = step(10) + step()
check(any("Не отвечает: панель" in m and "проверить сейчас не через что" in m for m in out), "K16 зарубежные ноды сами лежат — через «Резерв» (вход на rf1) сайт не проверяем")
world["alive"], world["sites"], world["cross"] = {}, {}, {}
for _ in range(4):
    step()
n = len(site_calls)
for _ in range(30):
    step()
names = [name for _, name in site_calls[n:]]
check(names.count("панель") == 6 and names.count(SUB) == 2, "K17 в покое: сайты раз в 10 минут, подписка раз в полчаса")
sent.clear()

# L. сертификаты и домены: раз в 6 часов; в отчёте — только беды и ближайший срок
check(cert_calls.count("pl1.example.net") == 1 + int((clock["t"] - BASE) // probe.SLOW_EVERY)
      and "dl.google.com" not in cert_calls and len(set(cert_calls)) == 5,
      "L1 сертификаты проверяются раз в 6 часов: 4 сайта и нода со своим доменом, чужой SNI не трогаем")
check(f"Сертификаты:</b> все 5 в порядке, ближайший срок — sub, {days(BASE + 40 * DAY)} дн." in report(), "L2 сертификаты в порядке — одна строка с ближайшим сроком")
check(f"Домены:</b> example.com — {days(BASE + 200 * DAY)} дн. · example.net — {days(BASE + 200 * DAY)} дн." in report(), "L3 сроки доменов")
soon = clock["t"] + 5.5 * DAY
world["certs"]["pl1.example.net"] = {"exp": soon, "life": 89}
world["certs"]["admin.example.com"] = {"err": "срок истёк"}
world["certs"]["cab.example.com"] = {"err": probe.NO_LINK}
world["domains"]["example.net"] = clock["t"] + 10 * DAY
world["domains"]["example.com"] = None
out = step(6 * 60) + step()
text = report()
check("❌ admin — срок истёк" in text and f"⚠️ pl1 — {days(soon)} дн." in text and "остальные 3 в порядке" in text,
      "L4 истёкший и скоро истекающий сертификаты названы, остальные — числом")
check("cab" not in text.split("Сертификаты:")[1].split("\n")[0], "L5 до сервера не достучались — прошлый срок сохранён, ложной тревоги нет")
check(f"⚠️ example.net — {days(world['domains']['example.net'])} дн." in text and "example.com — не удалось" not in text,
      "L6 домен истекает скоро — ⚠️; RDAP не ответил — остаётся прошлый срок")
check(len(out) == 1 and "Регистрация домена кончается: example.net" in out[0] and "осталось 9 дн." in out[0] and "Сертификат" not in out[0],
      "L8 домен скоро кончится — тревога сразу; по сертификатам ждём подтверждения")
out = step()
check(len(out) == 1 and "Сертификат скоро истечёт: pl1" in out[0] and "сайт-прикрытие ноды" in out[0]
      and "Сертификат не в порядке: admin</b> — срок истёк" in out[0] and "cab" not in out[0],
      "L9 сертификаты: подтверждено следующим запуском — тревога по истекающему и по истёкшему")
check(step() + step(6 * 60) + step() + step() == [], "L10 повторно о том же не пишем")
world["certs"], world["domains"] = {}, {}
out = step(6 * 60) + step() + step()
check("все 5 в порядке" in report(), "L7 после продления — снова одна строка")
check("Сертификат в порядке: pl1" in "".join(out)
      and "Сертификат в порядке: admin" in "".join(out) and "Домен продлён: example.net" in "".join(out),
      "L11 продлили — сообщения «в порядке»")
world["certs"]["sub.example.com"] = {"err": "выдан на другое имя"}
step(6 * 60), step()
world["certs"] = {}
check(step() + step() == [], "L12 разовая ошибка проверки сертификата не подтвердилась — тревоги нет")

# M. задержка и время соединения: в отчёте — медиана, разовый выброс её не портит; долгое соединение помечается
world["lat"][21003] = (0.06, 0.9)
step()
check(state("NL1")["lat"][-1] == 60 and state("NL1")["conn"][-1] == 900, "M0 замеры задержки и соединения копятся в состоянии")
world["lat"] = {}
line = probe.channel_line("NL1", dict(state("NL1"), lat=[60] * 5, conn=[900] * 5), clock["t"])
check(" · 60 мс · " in line and line.endswith("⚠️ соединение 0.9 с"), "M1 канал долго соединяется — пометка в его строке")
line = probe.channel_line(POLAND, dict(state(), lat=[50, 50, 500, 50, 50], conn=[250, 250, 2000, 250, 250]), clock["t"])
check(" · 50 мс · " in line and "соединение" not in line, "M2 разовый выброс не меняет задержку и не даёт пометки")

# N. подписка: число плиток, изменения, недоступность
ok_sub = {"ok": True, "ts": clock["t"] - 600, "tiles": 14, "error": ""}
text = report(ok_sub, [])
check(re.search(r"Сайты:</b> панель .+ · подписка .+ · кабинет .+ · админка ", text) and "Подписка:</b> 14 плиток, без изменений" in text,
      "N1 сайты идут в одном порядке; плитки подписки на месте, изменений нет")
text = report(ok_sub, [{"ts": 1, "added": ["🇸🇪 Sweden 🌐| 🔄"], "removed": []}, {"ts": 2, "added": [], "removed": ["🇫🇷 Paris <b>"]}])
check("14 плиток, ➕ 🇸🇪 Sweden; ➖ 🇫🇷 Paris &lt;b&gt;" in text, "N2 появившиеся и пропавшие плитки")
text = report({"ok": False, "ts": clock["t"] - 600, "tiles": 14, "error": "ответ 502"}, [])
check("Подписка:</b> ❌ не загрузилась в " in text and "(ответ 502)" in text, "N3 при сборке каналов подписка не загрузилась — ❌ и причина")
check("14 плиток, без изменений · ❔ плитки давно не сверялись" in report(dict(ok_sub, ts=clock["t"] - 14 * 3600), []), "N4 плитки давно не сверялись — так и сказано")
check("Подписка:</b> ещё не проверялась" in report(), "N5 данных о подписке ещё нет")

# G. полный отчёт по расписанию
json.dump(dict(ok_sub, ts=clock["t"]), open(os.path.join(tmp, "sub_status.json"), "w", encoding="utf-8"))
json.dump([{"ts": 1, "added": ["Новая"], "removed": []}], open(os.path.join(tmp, "sub_changes.json"), "w", encoding="utf-8"))
st = load()
st["last_summary"] = ""
json.dump(st, open(probe.STATE, "w", encoding="utf-8"))
out = step()
summ = [m for m in out if "Отчёт сторожа" in m]
check(len(summ) == 1 and "Каналы: работают 3 из 3" in summ[0], "G1 отчёт отправлен, в шапке — сколько каналов работает")
line = next(l for l in summ[0].split("\n") if "Poland" in l and not l.startswith("• "))   # строка канала, не пункт «Требует внимания»
check(line.startswith("✅ 🇵🇱 Poland — ") and "Мбит/с · 50 мс · " in line and "%" in line and "сбо" in line, "G2 строка канала: скорость · задержка · доступность (сбои)")
check("У самой rf1 не было интернета 6 мин" in summ[0], "G3 в отчёте указан перерыв у самой rf1")
check(len(summ[0].split("\n")) <= len(CHANS) + 26 and len(summ[0]) < 2500,   # v12: разделы с заголовками — строк больше
      "G4 отчёт компактный: строка на канал и по строке на остальное")
check("14 плиток, ➕ Новая" in summ[0] and not os.path.exists(os.path.join(tmp, "sub_changes.json")), "G5 изменения подписки показаны и после отчёта сброшены")
s = state()
check(s["inc"] == 0 and s["checks"] == 0 and s["lat"] == [] and s["conn"] == [] and s["svc_fail"] == {} and load()["sites"]["панель"]["fails"] == 0,
      "G6 счётчики обнулены после отчёта")
check(step() == [], "G7 второй раз за тот же час отчёт не шлётся")

# Q. пинг и время соединения: рост против обычного — тревога, возврат — «в норме»
for _ in range(7 * 30):
    step()
sent.clear()
check(state()["base"] == {"lat": 50, "conn": 250, "spd": 6.4},
      "Q1 обычные значения посчитаны по почасовой истории: пинг, время соединения и скорость на 512 КБ")
world["lat"][21004] = (0.12, 0.25)
out = []
for _ in range(9):
    out += step()
check(out == [], "Q2 пинг вырос, но меньше 20 минут (медиана выше порога ещё не три прохода подряд) — ещё тихо")
out = step()
check(len(out) == 1 and "Вырос пинг: 🇵🇱 Poland" in out[0] and "120 мс, обычно 50 мс (в 2.4 раза больше)" in out[0]
      and "изменился маршрут" in out[0], "Q3 больше половины замеров за полчаса высокие — тревога с цифрами и причиной")
check("⚠️ пинг выше обычного (50 мс)" in next(l for l in report().split(chr(10)) if "Poland" in l), "Q4 в отчёте у канала пометка")
out = []
for _ in range(20):
    out += step()
check(out == [], "Q5 пока держится — повторно не пишем")
world["lat"] = {}
out = []
for _ in range(16):
    out += step()
check(len(out) == 1 and "Пинг в норме: 🇵🇱 Poland" in out[0] and "Повышение длилось" in out[0] and "Сейчас 50 мс" in out[0],
      "Q6 вернулся — «в норме» с длительностью")
world["lat"][21003] = (0.05, 0.9)
out = []
for _ in range(12):
    out += step()
check(len(out) == 1 and "Дольше устанавливается соединение: NL1" in out[0] and "0.90 с, обычно 0.25 с" in out[0]
      and "IPv6" in out[0], "Q7 выросло время соединения — своя тревога")
check("⚠️ соединение 0.90 с (обычно 0.25 с)" in next(l for l in report().split(chr(10)) if "NL1" in l), "Q8 пометка времени соединения в отчёте")
world["lat"] = {}
for _ in range(16):
    step()
world["lat"] = {21003: (0.3, 0.25), 21004: (0.3, 0.25), 21007: (0.3, 0.25)}
out = []
for _ in range(12):
    out += step()
check("".join(out).count("Вырос пинг") == 3 and "".join(out).count("сразу у 3 каналов") == 3,
      "Q9 пинг вырос у всех сразу — причина «сеть», а не одна нода")
world["lat"] = {}
for _ in range(16):
    step()
sent.clear()
world["lat"][21004] = (0.085, 0.25)
world["lat"][21003] = (0.058, 0.45)
out = []
for _ in range(20):
    out += step()
check(out == [], "Q10 рост меньше порога (в 1.6 раза и на 40 мс; для соединения — на 250 мс) — не тревога")
world["lat"] = {21004: (0.12, 0.25)}
for _ in range(6):
    step()
world["alive"][21004] = False
step(), step()
world["alive"], world["lat"] = {}, {}
out = []
for _ in range(12):
    out += step()
check(not any("пинг" in m.lower() for m in out) and state()["q_lat"]["st"] == "OK",
      "Q11 канал падал — замеры до падения не считаются, ложной тревоги о пинге нет")
sent.clear()
world["lat"][21003] = (0.05, 0.9)
out = []
for _ in range(5 * 48):
    out += step(30)
check(len(out) == 2 and "Дольше устанавливается соединение: NL1" in out[0]
      and "Время соединения держится на новом уровне: NL1" in out[1] and "раньше было 0.25 с" in out[1],
      "Q12 рост держится несколько дней — одно сообщение «новый уровень», дальше это обычное значение")
check(state("NL1")["base"]["conn"] == 900 and state("NL1")["q_conn"]["st"] == "OK", "Q13 обычное значение подтянулось")
world["lat"] = {}
for _ in range(5 * 48):
    step(30)
sent.clear()

# QF. Пинг, который скачет между двумя маршрутами (W-15): подтверждение и одно «скачет»
R = probe.LAT_GROW  # порог при обычных 50 мс — 90 мс, середина — 70 мс
qq = {"st": "OK", "since": 0, "base": 0}
e1 = [probe.quality_step(qq, v, 50, R, t) for v, t in ((120, 0), (120, 120), (50, 240), (120, 360), (120, 480))]
e2 = probe.quality_step(qq, 120, 50, R, 600)
e3 = [probe.quality_step(qq, v, 50, R, t) for v, t in ((50, 720), (50, 1000), (100, 1100), (50, 1200), (50, 1700))]
e4 = probe.quality_step(qq, 50, 50, R, 1800)
check(e1 == [None] * 5 and e2 == "up" and qq["st"] == "OK" if False else
      (e1 == [None] * 5 and e2 == "up" and e3 == [None] * 5 and e4 == "down" and qq["st"] == "OK"),
      "QF1 «вырос» — три прохода подряд выше порога (провал сбрасывает счёт); «в норме» — 10 минут ниже середины "
      "(всплеск сбрасывает отсчёт)")
qf = {}
f = [probe.quality_flap(qf, ev, t) for ev, t in (("up", 0), ("down", 900), ("up", 1800), ("down", 2400), ("up", 3000))]
check(f == ["up", "down", "flap", None, None] and qf["flap"] == 1800
      and not probe.quality_calm(qf, 3000 + 3599) and probe.quality_calm(qf, 3000 + 3600)
      and probe.quality_flap({"flips": [0, 900]}, "up", 4000) == "up",
      "QF2 третья смена за час — одно «скачет», дальше молчим; час без смен — «успокоился»; смены реже — как обычно")
qa = {"st": "HIGH", "since": 0, "base": 50, "flap": 1800, "flips": [0, 900, 1800]}
t_flap = probe.quality_alert({"name": "🇳🇱NL 3 🌐 |🔄"}, "lat", "flap", qa, 120, [], 10, 1800, [50] * 8 + [150] * 8)
qa["st"] = "OK"
t_calm = probe.quality_alert({"name": "🇳🇱NL 3 🌐 |🔄"}, "lat", "calm", qa, 52, [], 10, 9000)
check("〰️ <b>Пинг скачет: 🇳🇱NL 3" in t_flap and "За час 3 раза" in t_flap and "около 50 мс и около 150 мс" in t_flap
      and "(обычно 50 мс)" in t_flap and "двумя маршрутами" in t_flap
      and "✅ <b>Пинг успокоился: 🇳🇱NL 3" in t_calm and "Сейчас 52 мс — в норме" in t_calm,
      "QF3 тексты «скачет» (два уровня и обычное) и «успокоился» (что сейчас)")
# QF4. Сквозь сторож: маршрут меняется туда-обратно каждые 8 минут три часа подряд
sent.clear()
out = []
for i in range(90):
    world["lat"] = {21004: (0.15, 0.25)} if (i // 4) % 2 else {}
    out += step()
pl = [m for m in out if "Poland" in m]
flap_line = next((l for l in report().split(chr(10)) if "Poland" in l), "")
check(len(pl) <= 4 and sum("Вырос пинг" in m for m in pl) <= 2 and sum("скачет" in m for m in pl) <= 1,
      f"QF4 маршрут скачет три часа: сообщений о Poland — {len(pl)} (было бы по одному на каждую смену)")
world["lat"] = {}
for _ in range(40):
    out += step()
check(sum("успокоился" in m for m in out if "Poland" in m) == (1 if any("скачет" in m for m in pl) else 0)
      and not state()["q_lat"].get("flap"),
      "QF5 час без смен после «скачет» — одно «успокоился», метка снята")
sent.clear()

# Y. почасовая история
hist = json.load(open(probe.HISTORY, encoding="utf-8"))
rows = hist["channels"][POLAND]
check(set(rows[-1]) == {"h", "checks", "fails", "bad", "inc", "spd", "spd_n", "big", "big_n", "lat", "conn"} and rows[-1]["lat"] == 50
      and all(a["h"] < b["h"] for a, b in zip(rows, rows[1:])), "Y1 в истории — запись на час: проверки, провалы, простой, сбои, скорость, пинг")
check(len(rows) <= probe.HIST_KEEP and sum(b["inc"] for b in rows) >= 1 and sum(b["bad"] for b in rows) >= 120,
      "Y2 сбои и простой попадают в историю; хранится не больше двух недель с запасом")
check(set(hist["sites"]) == set(probe.SITE_ORDER) and set(hist["sites"]["панель"][-1]) == {"h", "n", "fails", "bad", "inc"},
      "Y3 сайты тоже в истории")

# W. сводка за неделю
HOUR = 3600
end = probe.week_span(clock["t"])[1]


def week_hist(days, **over):
    """История: по записи на час за days суток до текущего часа; over — что отличается у этой недели."""
    return [dict({"h": end - (i + 1) * HOUR, "checks": 30, "fails": 0, "bad": 0, "inc": 0, "spd": 6.0, "spd_n": 6,
                  "lat": 50, "conn": 250}, **over) for i in range(days * 24)][::-1]


def older(rows):
    """Те же записи неделей раньше."""
    return [dict(b, h=b["h"] - probe.WEEK) for b in rows]


poland = week_hist(7)
for b in poland[10:20]:
    b.update(fails=30, bad=3600)
poland[10]["inc"] = 1
hist = {"channels": {POLAND: older(week_hist(7)) + poland,
                     "NL1": older(week_hist(7)) + week_hist(7, lat=120, spd=3.0),
                     "Резерв": older(week_hist(7)) + week_hist(7)},
        "sites": {name: [{"h": end - (i + 1) * HOUR, "n": 6, "fails": 0, "bad": 0, "inc": 0} for i in range(168)]
                  for name in probe.SITE_ORDER}}
hist["sites"]["панель"][5].update(fails=3, bad=720, inc=1)
wtext = real_weekly(load(), hist, clock["t"])
lines = wtext.split(chr(10))
check(lines[0].startswith("🗓 <b>Сводка сторожа за неделю</b> · ") and "История ведётся" not in wtext, "W1 шапка: неделя целиком")
check(lines[3].startswith("🔴 🇵🇱 Poland — 94.0% · 1 сбой, 10 ч 00 мин · 6.0 Мбит/с · 50 мс"), "W2 канал со сбоями — первым, с доступностью и простоем")
check("✅ NL1 — 100% · без сбоев · 3.0 Мбит/с · 120 мс" in wtext and "✅ Резерв — 100% · без сбоев · 6.0 Мбит/с · 50 мс" in wtext, "W3 остальные каналы")
check("Сайты:</b> панель — 1 сбой, 12 мин; остальные без сбоев" in wtext, "W4 сайты: названы только те, где были сбои")
check("Скорость и пинг</b> <i>(к прошлой неделе)</i><b>:</b> NL1 — пинг 50 → 120 мс, скорость 6.0 → 3.0 Мбит/с" in wtext
      and "Poland —" not in wtext.split("Скорость и пинг")[1], "W5 что изменилось к прошлой неделе — только заметное")
short_hist = {"channels": {POLAND: week_hist(3), "NL1": week_hist(1, lat=50) + [], "Резерв": week_hist(3)}, "sites": {}}
for b in short_hist["channels"]["Резерв"][36:]:
    b["lat"] = 90
wtext = real_weekly(load(), short_hist, clock["t"])
check("История ведётся с " in wtext and "сводка — за 3 д 0 ч" in wtext and "Сайты" not in wtext, "W6 истории меньше недели — так и сказано; по сайтам данных нет — строки нет")
check("к прошлой неделе" not in wtext and "Резерв — пинг 50 → 90 мс" in wtext, "W7 прошлой недели нет — сравнение начала периода с концом")
check(real_weekly(load(), {"channels": {}, "sites": {}}, clock["t"]) is None, "W8 истории нет — сводки нет")
check("без заметных изменений" in real_weekly(load(), {"channels": {POLAND: week_hist(3)}, "sites": {}}, clock["t"]), "W9 ничего не менялось — так и сказано")

# расписание: понедельник, один раз на неделю; Telegram недоступен — повтор
probe.weekly_text = real_weekly
monday = (int(clock["t"] // probe.WEEK) + 1) * probe.WEEK + 4 * 86400  # эпоха началась в четверг: +4 суток — понедельник 00:00 UTC
check(probe.dt.datetime.fromtimestamp(monday, probe.dt.timezone.utc).weekday() == 0, "W10 (проверка самой проверки) это понедельник")
st = load()
st["last_weekly"] = probe.week_key(monday - 600)
json.dump(st, open(probe.STATE, "w", encoding="utf-8"))
clock["t"] = monday - 600 - 120
check(step() == [], "W11 воскресенье вечером — сводки нет")
tg["up"] = False
clock["t"] = monday + 300
check(step() == [] and load()["last_weekly"] != probe.week_key(clock["t"]), "W12 понедельник, Telegram недоступен — сводка не потеряна")
tg["up"] = True
out = step()
check(len(out) == 1 and "Сводка сторожа за неделю" in out[0] and "Poland" in out[0], "W13 связь вернулась — сводка ушла")
check(step() == [] and step(60 * 24) == [], "W14 второй раз за ту же неделю не шлётся")
weekly_sample = out[0]
probe.weekly_text = lambda st, hist, now: None

# S. build_channels.py: статус подписки и изменения плиток
build_channels.ETC = tmp2 = tempfile.mkdtemp()


def tile(name, host=None):
    obs = [] if not host else [{"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": host, "port": 443}]},
                                "streamSettings": {"network": "tcp", "security": "reality",
                                                   "realitySettings": {"serverName": host, "publicKey": "k"}}}]
    return {"remarks": name, "outbounds": obs}


def build(tiles):
    def load_sub():
        if tiles is None:
            raise OSError("нет сети")
        return tiles
    build_channels.load_sub = load_sub
    try:
        build_channels.main()
    except SystemExit as e:
        return e.code


def built(name):
    path = os.path.join(tmp2, name)
    return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else None


check(build([tile("A", "a.example"), tile("AUTO")]) == 10 and built("sub_status.json")["tiles"] == 2
      and built("sub_status.json")["ok"] and built("sub_changes.json") is None, "S1 первая сборка: статус записан, изменений нет")
check(build([tile("A", "a.example"), tile("AUTO")]) == 0 and built("sub_changes.json") is None, "S2 та же подписка — без изменений")
check(build([tile("A", "a.example"), tile("B", "b.example")]) == 10
      and built("sub_changes.json")[0]["added"] == ["B"] and built("sub_changes.json")[0]["removed"] == ["AUTO"], "S3 плитка появилась и плитка пропала — записано")
rc = build(None)
check(rc not in (0, 10) and built("sub_status.json")["ok"] is False and built("sub_status.json")["tiles"] == 2
      and len(built("channels.json")["channels"]) == 2, "S4 подписка не загрузилась — статус «нет», каналы остаются прежними")

# T. check_sub: настоящая загрузка подписки (здесь — с локального сервера) и её разбор
import http.server
import threading


class SubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body, code = {"/ok": (b'[{"remarks": "A"}]', 200), "/empty": (b"[]", 200), "/html": (b"<html>", 200)}.get(
            self.path, (b"Bad Gateway", 502))
        agents.append(self.headers.get("User-Agent"))  # до ответа: иначе проверка может опередить запись
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


agents = []
srv = http.server.HTTPServer(("127.0.0.1", 0), SubHandler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
real_sleep, probe.time.sleep = probe.time.sleep, lambda s: None


def sub_code(path, port=srv.server_address[1]):
    open(os.path.join(tmp, "sub.url"), "w", encoding="utf-8").write(f"http://127.0.0.1:{port}{path}\n")
    return probe.check_sub()


check(sub_code("/ok") == "200" and agents == [probe.SUB_UA], "T1 подписка пришла — 200, с первой попытки, клиент назван как у сборки каналов")
check(sub_code("/missing") == "502" and len(agents) == 3, "T2 страница отдала 502 — код ответа, после второй попытки")
check(sub_code("/html") == probe.BAD_FORMAT and sub_code("/empty") == probe.BAD_FORMAT, "T3 ответ 200, но не подписка (не JSON или пустой список)")
srv.shutdown()
srv.server_close()
check(sub_code("/ok") == "000", "T4 сервер не отвечает — «нет соединения»")
os.remove(os.path.join(tmp, "sub.url"))
check(probe.check_sub() == "000", "T5 нет файла с адресом подписки — не падаем")
probe.time.sleep = real_sleep

# P. пульс для внешнего сторожа
probe.HEARTBEAT = os.path.join(tmp, "heartbeat.path")
pulse = os.path.join(tmp, "pulse.json")
probe.beat()
check(not os.path.exists(pulse), "P1 файла с путём нет — пульс не пишется")
open(probe.HEARTBEAT, "w", encoding="utf-8").write(pulse + "\n")
probe.beat()
beat = json.load(open(pulse, encoding="utf-8"))
check({k: beat[k] for k in ("ts", "summary", "hours", "unsent", "offline")}
      == {"ts": int(clock["t"]), "summary": load()["last_summary"], "hours": [0], "unsent": 0, "offline": False}
      and beat["nodes"] == {} and beat["sites"]["panel"] == "OK" and beat["sites"]["sub"] == "OK",
      "P2 в пульсе: время запуска, последний отчёт, часы отчётов, очередь неотправленного, состояние сайтов")

# V. серверы (маячки нод), взгляд снаружи, закачка побольше
nw = probe.nodewatch
probe.SPEED_FILE = os.path.join(tmp, "speed.json")
json.dump([{"name": "de1", "host": "de1.example.net", "beacon": "u-de1", "site": True},
           {"name": "srv1", "host": "srv1.example.net", "beacon": "u-srv1"}],
          open(os.path.join(tmp, "nodes.json"), "w", encoding="utf-8"))
world["beacon"], world["outside"], view_calls = {}, {}, []


def beacon(**over):
    return dict({"ts": clock["t"], "disk_pct": 60, "disk_free_mb": 3500, "mem_total_mb": 1967, "mem_avail_mb": 900,
                 "swap_used_mb": 0, "reboot_required": False, "kernel": "6.8.0-142-generic", "xray": "26.7.28",
                 "ufw": "active", "ssh_fail_24h": 0, "drops": {"policy": 1000, "geo": 0, "scan": 0, "crowdsec": 0}}, **over)


def fake_view(nodes, vantage_for):
    view_calls.append([(n["name"], vantage_for(n)) for n in nodes])
    return {n["name"]: json.loads(json.dumps(world["outside"].get(n["name"], {"open": [443], "site": None})))
            for n in nodes if vantage_for(n) is not None}


nw.fetch_beacon = lambda url: world["beacon"][url]() if url in world["beacon"] else None
nw.outside_view = fake_view
side_default = blockwatch.SIDE_FILE
blockwatch.SIDE_FILE = os.path.join(tmp, "side.json")


def outside_now():
    """Как служба --side: собрать «взгляд снаружи», положить в файл; следующий проход сторожа его забирает."""
    side_ = probe.load_json(blockwatch.SIDE_FILE)
    side_["outside"] = probe.outside_collect(json.load(open(os.path.join(tmp, "nodes.json"), encoding="utf-8")),
                                             json.load(open(os.path.join(tmp, "channels.json"), encoding="utf-8"))["channels"],
                                             load())
    json.dump(side_, open(blockwatch.SIDE_FILE, "w", encoding="utf-8"))
    return step()
world["beacon"] = {"u-de1": lambda: beacon(), "u-srv1": lambda: beacon(xray="26.3.27", reboot_required=True)}
world["outside"] = {"de1": {"open": [80, 443], "site": ["200", "Германия"]}, "srv1": {"open": [443], "site": None}}
sent.clear()
out = step(10) + step() + step(6 * 60) + outside_now()
check(out == [] and "Серверы:</b> все 2 в порядке" in report(), "V1 маячки читаются, всё в порядке — одна строка в отчёте, тревог нет")
check(view_calls and view_calls[-1] == [("de1", 21004), ("srv1", 21004)],
      "V2 снаружи смотрим через чужую ноду (канал Poland), а не через «Резерв» и не через саму ноду")
check("Снаружи:</b> лишних открытых портов нет (2 из 2 нод), сайты-прикрытия отвечают (1)" in report(), "V3 первый снимок «снаружи» — без тревог, строка в отчёте")
world["beacon"]["u-de1"] = lambda: beacon(disk_pct=90, disk_free_mb=800)
out = step(10)
check(out == [] and "⚠️ de1 — диск 90%" in report(), "V4 диск 90% — сразу в отчёте, тревога ждёт подтверждения")
out = step(10)
check(len(out) == 1 and "Заканчивается диск: de1" in out[0] and "занято 90%, свободно 800 МБ" in out[0], "V5 подтвердилось — тревога о диске")
world["beacon"]["u-de1"] = lambda: beacon(ufw="inactive")
out = step(10) + step(10)
check(len(out) == 1 and "Диск в порядке: de1" in out[0] and "de1 — файрвол выключен" in report(), "V6 диск вернулся; выключенный файрвол виден в отчёте")
world["beacon"]["u-de1"] = lambda: None
for _ in range(4):
    step(10)
check("de1 — не отдаёт состояние" in report() and "srv1" not in report().split("Серверы:")[1].split(chr(10))[0], "V7 маячок перестал читаться — так и сказано, вторая нода в порядке")
world["beacon"]["u-de1"] = lambda: beacon(drops={"policy": 1000 + int(clock["t"] - BASE) // 10, "geo": 5, "scan": 0, "crowdsec": 0})
step(10), step(10), step(10)
day = load()["nodes"]["de1"]["days"][-1]
check(day["drops"] > 0 and day["disk"] == 60, "V8 отбитые пакеты копятся по суткам как разница счётчиков")
world["outside"]["de1"] = {"open": [80, 443, 2222], "site": ["200", "Германия"]}
out = step(6 * 60) + outside_now()
check(len(out) == 1 and "Снаружи изменилось: de1" in out[0] and "порт 2222 (управление нодой) открыт для всех" in out[0], "V9 открылся порт управления — тревога")
check("⚠️ de1 — порт 2222 (управление нодой)" in report() and step(6 * 60) + outside_now() == [], "V10 дальше — в отчёте, без повторных тревог")
world["outside"]["de1"] = {"open": [80, 443], "site": ["200", "Германия"]}
out = step(6 * 60) + outside_now()
check(len(out) == 1 and "порт 2222 перестал отвечать" in out[0], "V11 порт закрыли — сообщение")
flip = {"n": 0}


def flaky_view(nodes, vantage_for):
    flip["n"] += 1
    extra = [22] if flip["n"] == 1 else []
    return {n["name"]: {"open": sorted([443] + ([80] if n["name"] == "de1" else []) + extra),
                        "site": ["200", "Германия"] if n["name"] == "de1" else None} for n in nodes}


nw.outside_view = flaky_view
check(step(6 * 60) + outside_now() == [], "V12 порт показался открытым один раз, перепроверка не подтвердила — тревоги нет")
nw.outside_view = fake_view
os.remove(blockwatch.SIDE_FILE)
blockwatch.SIDE_FILE = side_default
check(nw.outside_changes("x", None, {"open": [22, 443], "site": ["502", ""]}) == ["порт 22 (SSH) открыт для всех", "сайт-прикрытие не отвечает (код 502)"]
      and nw.outside_changes("x", None, {"open": [80, 443], "site": ["200", "T"]}) == [], "V13 первый же снимок: открытый SSH и мёртвый сайт — сразу в тревогу, остальное молча")
check(nw.outside_changes("x", {"open": [443], "site": ["200", "А"]}, {"open": [443], "site": ["200", "Б"]}) == ["сайт-прикрытие: было «А» (200), стало «Б» (200)"],
      "V14 сменился сайт-прикрытие — сообщение")
json.dump({"ts": clock["t"] + 60, "channels": {POLAND: 38.4, "NL1": None}}, open(probe.SPEED_FILE, "w", encoding="utf-8"))
step()
check(state()["big"] == 38.4 and state()["hr"]["big_n"] == 1 and " — 38 Мбит/с · " in probe.channel_line(POLAND, state(), clock["t"]),
      "V15 закачка 10 МБ перед отчётом попадает в строку канала и в историю")
check(" — 38 Мбит/с" not in probe.channel_line(POLAND, state(), clock["t"] + 4 * 3600), "V16 устаревший замер в отчёт не идёт")
world["beacon"]["u-de1"] = lambda: beacon(disk_pct=88, mem_avail_mb=60)
step(10)
st7 = load()
st7["nodes"]["de1"]["days"] = [{"d": "2027-01-%02d" % d, "drops": 9000 if d < 20 else 30000, "disk": 60, "mem": 900} for d in range(10, 31)]
st7["nodes"]["srv1"]["days"] = [{"d": "2027-01-%02d" % d, "drops": 1500, "disk": 60, "mem": 900} for d in range(10, 31)]
block = nw.servers_block(st7["nodes"], clock["t"])
check(any(l.startswith("⚠️ de1 — 88% · 60 МБ · 26.7.28 · свободной памяти 60 МБ") for l in block)
      and any(l.startswith("✅ srv1 — 60% · 900 МБ · 26.3.27 · ждёт перезагрузки, Xray старее, чем на других") for l in block),
      "V17 недельная сводка: строка на сервер — диск, память, версия Xray и пометки")
scan = nw.scan_block(st7["nodes"], "2027-01-20", "2027-01-27")
check(len(scan) == 2 and "de1 30 тыс. · srv1 1.5 тыс." in scan[1] and "de1 — в 3.3 раза больше прошлой недели" in scan[1] and "srv1 —" not in scan[1],
      "V18 счётчик сканирования: в сутки по нодам и где выросло вдвое и больше")
check(nw.fmt_k(950) == "950" and nw.fmt_k(4321) == "4.3 тыс." and nw.fmt_k(26492) == "26 тыс.", "V19 числа в счётчике читаемые")

# настоящая проверка порта через SOCKS5 — на локальном прокси и локальных «серверах»
import socket
import socketserver


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-test" + bytes([13, 10]))


class Silent(socketserver.BaseRequestHandler):  # отвечает только на запрос, как веб-сервер
    def handle(self):
        if self.request.recv(100):
            self.request.sendall(b"HTTP/1.0 400 Bad Request" + bytes([13, 10, 13, 10]))


class Socks(socketserver.BaseRequestHandler):  # как клиент Xray: «соединено» отвечает сразу, цель набирает потом
    def handle(self):
        try:
            self.relay()
        except OSError:
            pass

    def relay(self):
        c = self.request
        c.recv(3), c.sendall(bytes([5, 0]))
        head = c.recv(5)
        host = c.recv(head[4])
        port = int.from_bytes(c.recv(2), "big")
        c.sendall(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        try:
            up = socket.create_connection((host.decode(), port), timeout=2)
        except OSError:
            return
        up.settimeout(0.3)
        c.settimeout(0.3)
        for _ in range(12):
            for a, b in ((up, c), (c, up)):
                try:
                    data = a.recv(4096)
                    if not data:
                        return
                    b.sendall(data)
                except socket.timeout:
                    pass


servers = [socketserver.ThreadingTCPServer(("127.0.0.1", 0), h) for h in (Banner, Silent, Socks)]
for sv in servers:
    sv.daemon_threads = True
    threading.Thread(target=sv.serve_forever, daemon=True).start()
ports = [sv.server_address[1] for sv in servers]
dead = socket.socket()
dead.bind(("127.0.0.1", 0))
dead_port = dead.getsockname()[1]
dead.close()
check(nw.socks_open(ports[2], "127.0.0.1", ports[0], timeout=3) is True, "V20 порт с приветствием (как SSH) — открыт")
check(nw.socks_open(ports[2], "127.0.0.1", ports[1], timeout=3) is True, "V21 порт, отвечающий только на запрос, — открыт")
check(nw.socks_open(ports[2], "127.0.0.1", dead_port, timeout=3) is False, "V22 закрытый порт — закрыт, хотя прокси и сказал «соединено»")
check(nw.socks_open(dead_port, "127.0.0.1", ports[0], timeout=2) is False, "V23 сам канал не работает — не «открыт»")


class TlsOnly(socketserver.BaseRequestHandler):  # как вход Reality с чужим сайтом: на простой запрос молчит и закрывает
    def handle(self):
        try:
            first = self.request.recv(1)
            if first == bytes([22]):                       # начало приветствия TLS
                self.request.recv(4096)
                self.request.sendall(bytes([21, 3, 3, 0, 2, 2, 40]))   # отказ TLS (alert handshake_failure)
        except OSError:
            pass


tls_srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TlsOnly)
tls_srv.daemon_threads = True
threading.Thread(target=tls_srv.serve_forever, daemon=True).start()
nw.TLS_PORTS = (tls_srv.server_address[1],)
check(nw.socks_open(ports[2], "127.0.0.1", tls_srv.server_address[1], timeout=3) is True, "V24 порт, отвечающий только на приветствие TLS, — открыт")
nw.TLS_PORTS = ()
check(nw.socks_open(ports[2], "127.0.0.1", tls_srv.server_address[1], timeout=3) is False, "V25 без приветствия TLS такой порт выглядит закрытым — поэтому для 443 оно и нужно")
check(nw.socks_open(ports[2], "127.0.0.1", tls_srv.server_address[1], timeout=3, tls=True) is True,
      "V26 вход VPN на нестандартном порту: когда известно, что там TLS, здороваемся по TLS и видим, что порт отвечает")
tls_srv.shutdown()
for sv in servers:
    sv.shutdown()

# Z. сверка со вторым сторожем: в пульсе — состояние каждой ноды и сайта
probe.socket.gethostbyname = lambda h: {"de1.example.net": "1.1.1.1", "srv1.example.net": "9.9.9.9"}[h]
world["alive"], world["deep"] = {}, {}
for _ in range(8):
    step(10)
probe.beat()
beat = json.load(open(pulse, encoding="utf-8"))
check(set(beat["nodes"]) == {"de1.example.net", "srv1.example.net"}
      and beat["nodes"]["de1.example.net"]["status"] == "OK" and beat["nodes"]["srv1.example.net"]["status"] == "OK",
      "Z1 канал относится к ноде, на которой он выходит (по адресу выхода), — так находятся ноды за ретрансляторами")
world["alive"][21003] = False
step(), step()
probe.beat()
beat = json.load(open(pulse, encoding="utf-8"))
check(beat["nodes"]["de1.example.net"]["status"] == "DOWN" and beat["nodes"]["srv1.example.net"]["status"] == "OK",
      "Z2 у ноды несколько каналов — в пульсе худшее состояние")
world["alive"] = {}
world["sites"]["панель"] = "000"
step(10), step()
probe.beat()
check(json.load(open(pulse, encoding="utf-8"))["sites"] == {"panel": "DOWN", "sub": "OK", "cabinet": "OK", "admin": "OK"},
      "Z3 состояние сайтов в пульсе — под именами, которые понимает второй сторож")
world["sites"] = {}

# ====== версия 8: блокировки (netprobe, vantage_agent, blockwatch) ======
import struct
import time as real_time

import netprobe
import vantage_agent
real_name_ref = netprobe.name_ref
netprobe.name_ref = lambda name, tries=2, ref=None: None  # в разборе — без сети; сама проверка — ZL54
netprobe.FALLBACK_DNS = ()  # в тестах наружу не ходим: запасной DNS выключен (проверяется отдельно, ZL34)

# U. сетевые пробы и агент точки проверки — на локальных заглушках
DNS_ZONE = {"ok.test": ["1.2.3.4", "5.6.7.8"], "one.test": ["9.9.9.9"]}


class FakeDns(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        qid = struct.unpack(">H", data[:2])[0]
        labels, pos = [], 12
        while data[pos]:
            labels.append(data[pos + 1:pos + 1 + data[pos]].decode())
            pos += 1 + data[pos]
        name, question = ".".join(labels), data[12:pos + 5]
        if name == "silent.test":
            return
        if name == "wrongid.test":
            qid ^= 1
        ips = DNS_ZONE.get(name)
        flags = 0x8180 if ips is not None else 0x8183
        out = struct.pack(">HHHHHH", qid, flags, 1, len(ips or []), 0, 0) + question
        for ip in ips or []:
            out += struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
        sock.sendto(out, self.client_address)


dns_srv = socketserver.ThreadingUDPServer(("127.0.0.1", 0), FakeDns)
threading.Thread(target=dns_srv.serve_forever, daemon=True).start()
dns_port = dns_srv.server_address[1]
check(netprobe.dns_udp("ok.test", "127.0.0.1", dns_port, timeout=2) == ("ok", ["1.2.3.4", "5.6.7.8"]),
      "U1 вопрос DNS по UDP: адреса из ответа разобраны")
check(netprobe.dns_udp("nope.test", "127.0.0.1", dns_port, timeout=2) == ("nx", []), "U2 имени нет — так и сказано, это не ошибка связи")
check(netprobe.dns_udp("silent.test", "127.0.0.1", dns_port, timeout=0.3) == ("err", [])
      and netprobe.dns_udp("wrongid.test", "127.0.0.1", dns_port, timeout=0.3) == ("err", [])
      and netprobe.dns_parse(b"abc", 1) == ("err", []),
      "U3 молчание, чужой номер ответа и мусор — «не удалось спросить», а не «имени нет»")

PAGE = b"x" * 3000


class Page(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    stall_after = None   # после стольких ответов по одному соединению перестать отвечать (обрыв DPI)

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.n = getattr(self, "n", 0) + 1
        if self.stall_after and self.n > self.stall_after:
            real_time.sleep(2.5)
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)


class Stall(Page):
    stall_after = 5


class Tiny(Page):  # как чужой сайт-прикрытие: на запрос — короткая переадресация
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "https://example.com/")
        self.send_header("Content-Length", "0")
        self.end_headers()


class OneShot(Page):
    protocol_version = "HTTP/1.0"  # закрывает соединение после каждого ответа


def serve(handler):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    s.daemon_threads = True
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]


p_page, p_stall, p_once, p_tiny = serve(Page), serve(Stall), serve(OneShot), serve(Tiny)
netprobe.STALL = 1
r = netprobe.direct_probe("127.0.0.1", p_page, need=20000, tls=False)
check(r["tcp"] == "open" and r["end"] == "ok" and r["bytes"] >= 20000 and netprobe.probe_class(r) == "ok",
      "U4 объём набирается повторными запросами по одному соединению — «в порядке»")
r = netprobe.direct_probe("127.0.0.1", p_stall, need=60000, tls=False)
check(r["end"] == "timeout" and 15000 <= r["bytes"] <= 17000 and netprobe.probe_class(r) == "stall",
      "U5 соединение встало после ~16 КБ — «встало» (так выглядит обрыв DPI), объём до обрыва посчитан")
r = netprobe.direct_probe("127.0.0.1", p_once, need=20000, tls=False)
check(r["end"] == "closed" and netprobe.probe_class(r) == "ok",
      "U6 сервер сам закрывает соединение — объём не набрать, но это не «встало»")
r = netprobe.direct_probe("127.0.0.1", p_tiny, need=60000, tls=False)
check(r["end"] == "small" and r["bytes"] == 1200 and netprobe.probe_class(r) == "ok",
      "U6а страница слишком мала (чужой сайт-прикрытие) — объём не набрать, бросаем после шести ответов и не судим")
r = netprobe.direct_probe("127.0.0.1", dead_port, tls=False)
check(r["tcp"] == "refused" and netprobe.probe_class(r) == "tcp" and netprobe.probe_class(None) == "none"
      and netprobe.probe_class(netprobe.direct_probe("no-such-name.invalid", 443)) == "dns",
      "U7 закрытый порт, имя не находится, точка не ответила — три разных итога")
TRACE_OK = """traceroute to 9.9.9.9 (9.9.9.9), 16 hops max, 60 byte packets
 1  *
 2  100.88.255.254  1.034 ms
 3  62.115.196.193  32.564 ms
 4  9.9.9.9  53.151 ms
"""
TRACE_CUT = """traceroute to 9.9.9.9 (9.9.9.9), 16 hops max, 60 byte packets
 1  100.88.255.254  1.034 ms
 2  62.115.196.193  32.564 ms
 3  *
 4  *
"""
check(netprobe.parse_trace(TRACE_OK, "9.9.9.9") == {"reached": True, "hops": 4, "last": (4, "9.9.9.9")}
      and netprobe.parse_trace(TRACE_CUT, "9.9.9.9") == {"reached": False, "hops": 4, "last": (2, "62.115.196.193")}
      and netprobe.parse_trace("", "9.9.9.9") == {"reached": False, "hops": 0, "last": None},
      "U8 трассировка: дошли или нет и после какого шага пропали пакеты")

TOKEN = "t" * 40
agent_cfg = {"token": TOKEN, "allow": ["127.0.0.1"], "suffixes": ["localhost"], "ports": [p_page], "tls": False, "name": "тест"}
agent = vantage_agent.Agent(("127.0.0.1", 0), agent_cfg)
threading.Thread(target=agent.serve_forever, daemon=True).start()
A = {"name": "Москва", "url": f"http://127.0.0.1:{agent.server_address[1]}", "token": TOKEN}
check(blockwatch.agent_get(A, "/health") == {"ok": True, "ts": int(real_time.time()), "name": "тест"}
      or blockwatch.agent_get(A, "/health")["ok"] is True, "U9 агент отвечает сторожу с верным токеном")
check(blockwatch.agent_get(dict(A, token="x" * 40), "/health") is None, "U10 неверный токен — отказ")
r = blockwatch.agent_get(A, f"/probe?host=localhost&port={p_page}")
check(r and r["tcp"] == "open" and r["addr"] == "127.0.0.1" and r["end"] in ("ok", "deadline") and netprobe.probe_class(r) == "ok",
      "U11 агент сам находит адрес по имени и делает ту же прямую проверку")
check(blockwatch.agent_get(A, f"/probe?host=example.com&port={p_page}") is None
      and blockwatch.agent_get(A, f"/probe?host=localhost.evil.com&port={p_page}") is None
      and blockwatch.agent_get(A, f"/probe?host=localhost&port={p_stall}") is None
      and blockwatch.agent_get(A, "/probe?host=127.0.0.1") is None,
      "U12 агент проверяет только наши домены и разрешённые порты — чужое имя, адрес цифрами и другой порт отвергнуты")
agent.cfg = dict(agent_cfg, allow=["10.0.0.1"])
check(blockwatch.agent_get(A, "/health") is None, "U13 запрос с адреса не из списка — отказ даже с верным токеном")
agent.cfg = agent_cfg
check(real_health([A, dict(A, name="Нет", url=f"http://127.0.0.1:{dead_port}")]) == {"Москва": True, "Нет": False},
      "U14 опрос точек проверки: кто на связи")
real_udp = netprobe.dns_udp
netprobe.dns_udp = lambda name, server, port=53, timeout=3: ("ok", ["127.0.0.1"])  # наружу в тестах не ходим
d = blockwatch.agent_get(A, "/dns?name=localhost")
netprobe.dns_udp = real_udp
check(d and d["system"][0] == "ok" and "127.0.0.1" in d["system"][1] and set(d["udp"]) == set(vantage_agent.RESOLVERS)
      and d["udp"]["Google"] == ["ok", ["127.0.0.1"]],
      "U15 агент отдаёт, что отвечает его DNS: системный резолвер и публичные по UDP")
agent.shutdown()

# X. блокировки: списки, подмена DNS, разбор сбоя, заглушка внешнего сервиса
lst = os.path.join(tmp, "nets.lst")
open(lst, "w", encoding="utf-8").write("# комментарий\n1.2.3.0/24\n10.0.0.0/8\n5.6.7.8\n2001:db8::/32\nмусор\n104.21.47.4/30\n")
idx = blockwatch.load_nets(lst)
check(idx[2] == 4 and blockwatch.ip_match(idx, "1.2.3.4") == "1.2.3.0/24" and blockwatch.ip_match(idx, "10.9.9.9") == "10.0.0.0/8"
      and blockwatch.ip_match(idx, "5.6.7.8") == "5.6.7.8/32" and blockwatch.ip_match(idx, "104.21.47.6") == "104.21.47.4/30"
      and blockwatch.ip_match(idx, "9.9.9.9") is None and blockwatch.ip_match(idx, "5.6.7.9") is None,
      "X1 адрес ищется в списке и как отдельный, и внутри подсети; IPv6 и мусор пропускаются")
dom = os.path.join(tmp, "dom.lst")
open(dom, "w", encoding="utf-8").write('"sub.example.com"\nother.com\nx.example.net\nexample.com.evil.com\nnotexample.com\n')
found, n = blockwatch.scan_domains(dom, {"sub.example.com": "подписка", "de1.example.net": "de1"}, ("example.com", "example.net"))
check(n == 5 and set(found) == {"sub.example.com", "x.example.net"},
      "X2 домены: находится наше имя и любой поддомен наших доменов; похожие чужие имена — нет")
TG_NODES = [{"name": "de1", "host": "de1.example.net"}, {"name": "pl1", "host": "pl1.example.net"}]
TG_CHANS = [{"name": "srv1📶 ANTI_BLOCK", "entry": "93.188.46.133"}, {"name": POLAND, "entry": "pl1.example.net"}]
ADDR = {"de1.example.net": "93.186.39.68", "pl1.example.net": "93.185.33.11", "sub.example.com": "93.188.74.31"}


def fake_resolve(name):
    if name not in ADDR:
        raise OSError("нет такого имени")
    return ADDR[name]


tgt = blockwatch.targets(TG_CHANS, TG_NODES, ("sub.example.com", "panel.example.com"), ("example.com", "example.net"), fake_resolve)
check(tgt["ips"] == {"93.186.39.68": "de1", "93.185.33.11": "pl1", "93.188.74.31": "подписка",
                     "93.188.46.133": "вход «srv1📶 ANTI_BLOCK»"}
      and tgt["names"]["panel.example.com"] == "панель" and tgt["names"]["example.com"] == "example.com",
      "X3 что сверяем: ноды, сайты владельца, входы-ретрансляторы (по адресу) и сами домены; имя без адреса не мешает")
FILES = {"u-ip": "9.9.9.9\n93.186.39.68\n93.185.33.154\n93.185.33.200\n", "u-dom": "x.example.net\nfoo.com\n",
         "u-cdn": "1.0.0.0/8\n"}
SRC = (("rkn_ip", "u-ip", "ip", "hard"), ("rkn_dom", "u-dom", "domain", "hard"),
       ("cdn", "u-cdn", "ip", "hard"), ("rkn_net", "u-fail", "ip", "hard"))


def fake_fetch(url, dest, socks_port=None):
    if url not in FILES:
        return False
    open(dest, "w", encoding="utf-8").write(FILES[url])
    return True


res = blockwatch.lists_run(tgt, ("example.com", "example.net"), work=os.path.join(tmp, "lists"), sources=SRC, fetcher=fake_fetch)
check(res["hits"]["rkn_ip"] == {"de1 (93.186.39.68)": "93.186.39.68/32"} and res["neighbours"] == {"pl1 (93.185.33.11)": 2}
      and res["hits"]["rkn_dom"] == {"x.example.net": "x.example.net"} and res["hits"]["cdn"] == {}
      and res["sources"]["rkn_ip"] == {"ok": True, "n": 4} and res["sources"]["rkn_net"] == {"ok": False, "n": 0}
      and res["targets"] == {"ips": 4, "names": 6} and os.listdir(os.path.join(tmp, "lists")) == [],
      "X4 сверка: совпадения по каждому списку и чужие адреса реестра рядом с нашими (свой адрес соседом не считается); "
      "нескачавшийся список помечен, скачанные файлы на диске не остаются")


def lists_data(ts, hits=None, failed=(), near=None):
    return {"ts": ts, "sources": {k: {"ok": k not in failed, "n": 0 if k in failed else 10} for k in blockwatch.KIND},
            "hits": dict({k: {} for k in blockwatch.KIND}, **(hits or {})), "targets": {"ips": 17, "names": 17},
            "neighbours": near or {}}


stl = {}
HIT = {"rkn_ip": {"de1 (93.186.39.68)": "93.186.39.68/32"}}
NEAR = {"pl1 (93.185.33.11)": 2}
out = blockwatch.lists_step(stl, lists_data(1, HIT, near=NEAR))
check(len(out) == 1 and "В списке блокировок: de1 (93.186.39.68)" in out[0] and "обязаны его блокировать" in out[0],
      "X5 адрес ноды в реестре — тревога сразу; чужие адреса реестра по соседству — без тревоги")
check(blockwatch.lists_step(stl, lists_data(2, HIT, near=NEAR)) == [] and blockwatch.near_hits(stl) == [("pl1 (93.185.33.11)", 2)],
      "X6 то же самое в следующей сверке — молчим")
check(blockwatch.lists_step(stl, lists_data(3, {}, failed=("rkn_ip",))) == []
      and blockwatch.hard_hits(stl) == [("de1 (93.186.39.68)", "реестр РКН, адреса")]
      and blockwatch.near_hits(stl) == [("pl1 (93.185.33.11)", 2)],
      "X7 список не скачался — прошлое совпадение и соседи остаются, «ушёл из списка» не говорим")
out = blockwatch.lists_step(stl, lists_data(4, {"cdn": {"de7 (1.2.3.4)": "1.0.0.0/8"}}))
check(len(out) == 2 and any("Больше нет в списке блокировок: de1" in x for x in out)
      and any("В списке блокировок: de7" in x and "16–20 КБ" in x for x in out) and blockwatch.near_hits(stl) == [],
      "X8 ушёл из реестра — сообщение; попал в подсеть, которую душат, — тревога со своим объяснением")
out = blockwatch.lists_step({}, lists_data(1, {"rkn_dom": {"подписка (sub.example.com)": "sub.example.com"}}))
check(len(out) == 1 and "нужен другой домен" in out[0], "X9 домен в реестре — своё объяснение")

# списки в работе сторожа: файл сверки забирается обычным запуском


def fresh():
    """Чистое состояние и исходные три канала."""
    for f in (probe.STATE, probe.HISTORY, blockwatch.LISTS_FILE, os.path.join(tmp, "nodes.json")):
        if os.path.exists(f):
            os.remove(f)
    json.dump({"baseline_port": 21000, "channels": CHANS}, open(os.path.join(tmp, "channels.json"), "w", encoding="utf-8"))
    for k in world:
        world[k] = {}
    probe.SUMMARY_HOURS_UTC = (0,)
    probe.weekly_text = lambda st, hist, now: None
    sent.clear()
    probe.main()
    s0 = load()
    s0["last_summary"] = today
    json.dump(s0, open(probe.STATE, "w", encoding="utf-8"))
    sent.clear()


fresh()
check("Блокировки" not in report(), "X10 пока ничего не проверялось — строки о блокировках в отчёте нет")
json.dump(lists_data(clock["t"], HIT, near=NEAR), open(blockwatch.LISTS_FILE, "w", encoding="utf-8"))
out = step()
check(len(out) == 1 and "В списке блокировок: de1" in out[0] and step() == [],
      "X11 свежая сверка забирается один раз: тревога о попадании в реестр уходит сразу и не повторяется")
text = report()
check("<b>Блокировки:</b> ⚠️ в списках: de1 (93.186.39.68) — реестр РКН, адреса" in text, "X12 в отчёте — кто и в каком списке")
check(any("Чужие адреса в реестре рядом с нашими" in x and "pl1 (93.185.33.11) — 2" in x
          for x in blockwatch.week_lines(probe.init_state(load(), clock["t"]))) and "pl1" not in text,
      "X13 чужие адреса реестра по соседству — только в сводке за неделю, в обычном отчёте их нет")
json.dump(lists_data(clock["t"] + 1, {}, failed=("cdn",)), open(blockwatch.LISTS_FILE, "w", encoding="utf-8"))
out = step()
text = report()
check(len(out) == 1 and "Больше нет в списке блокировок: de1" in out[0]
      and "в списках блокировок наших адресов нет (сверено адресов: 17, имён: 17)" in text   # v12: по пункту на строку
      and "• не скачалось списков: 1 из 6" in text,
      "X14 ушёл из списка — сообщение; в отчёте «наших адресов нет» и сколько списков не скачалось")
clock["t"] += 15 * 3600 + 60
check("⚠️ списки не обновлялись 15 ч" in report(), "X15 сверка давно не обновлялась — пометка в отчёте")

# подмена DNS
check(blockwatch.dns_judge({"1.1.1.1"}, {"a": ("ok", ["1.1.1.1"]), "b": ("ok", ["6.6.6.6"]), "c": ("nx", []), "d": ("err", []),
                                         "e": ("ok", [])}) == [("b", "6.6.6.6"), ("c", "такого имени нет")]
      and blockwatch.dns_judge(None, {"a": ("ok", ["6.6.6.6"])}) == [] and blockwatch.dns_judge(set(), {"a": ("nx", [])}) == [],
      "X16 подозрителен другой адрес или «имени нет»; ошибка связи и пустой ответ — нет; без защищённого DNS не судим")
real_doh, real_observe = blockwatch.doh, blockwatch.dns_observe
blockwatch.doh = lambda name, socks_port=None: None if name == "dead.test" else ({"1.1.1.1"} if socks_port else {"2.2.2.2"})
blockwatch.dns_observe = lambda name, agents=(): {"rf1: Google": ("ok", ["2.2.2.2"]), "rf1: Яндекс": ("ok", ["7.7.7.7"]),
                                                  "rf1: Quad9": ("err", [])}
res = real_dns_check(["a.test", "dead.test"], 21003)
check(res == {"a.test": {"truth": ["1.1.1.1", "2.2.2.2"], "odd": [["rf1: Яндекс", "7.7.7.7"]], "asked": 2, "system": {}}},
      "X17 верим всему, что отдал защищённый DNS напрямую и через зарубежный канал; имя без его ответа пропускается")
blockwatch.doh, blockwatch.dns_observe = real_doh, real_observe

fresh()
dns_calls, world_dns = [], {}


def fake_dns(names, port, agents=()):
    dns_calls.append((clock["t"], list(names), port))
    return {n: dict(world_dns.get(n, {"truth": ["93.188.74.31"], "odd": [], "asked": 5})) for n in names}


def until_dns(times=1):
    """Шагать, пока не пройдёт столько проверок DNS; вернуть всё, что ушло в Telegram."""
    got, n = [], len(dns_calls)
    for _ in range(200):
        if len(dns_calls) >= n + times:
            return got
        got += step()
    raise SystemExit("проверка DNS не запускается")


blockwatch.dns_check = fake_dns
out = until_dns()
check(out == [] and dns_calls[-1][1] == list(probe.SITE_HOSTS) and dns_calls[-1][2] == 21004
      and "подмены DNS нет (имён: 4)" in report(),
      "X18 DNS проверяется в запуске без закачки, через работающий зарубежный канал; в отчёте — «подмены нет»")
world_dns["sub.example.com"] = {"truth": ["93.188.74.31"], "odd": [["rf1: Google", "1.2.3.4"]], "asked": 5}
t0 = clock["t"]
check(until_dns(2) == [], "X19 разошёлся один ответ из пяти — это ещё не подмена")
check(clock["t"] - t0 >= 2 * blockwatch.DNS_EVERY - 600, "X20 без расхождений DNS проверяется раз в полчаса, не чаще")
world_dns["sub.example.com"] = {"truth": ["93.188.74.31"], "odd": [["rf1: Google", "1.2.3.4"], ["Москва: системный", "1.2.3.4"]], "asked": 5}
t0 = clock["t"]
out = until_dns(1)
out2 = until_dns(1)
check(out == [] and len(out2) == 1 and "Подмена DNS: sub.example.com" in out2[0] and "93.188.74.31" in out2[0]
      and "• Москва: системный: 1.2.3.4" in out2[0] and clock["t"] - t0 <= blockwatch.DNS_EVERY + 1200,
      "X21 два независимых ответа расходятся — тревога после перепроверки, и перепроверка идёт сразу, не через полчаса")
check("⚠️ подмена DNS: sub.example.com" in report() and until_dns(2) == [], "X22 в отчёте — какое имя подменяют; тревога не повторяется")
world_dns.clear()
out = until_dns(2)
check(len(out) == 1 and "DNS снова отвечает верно: sub.example.com" in out[0] and "подмены DNS нет" in report(),
      "X23 ответы снова совпадают — сообщение о возврате")
blockwatch.dns_check = lambda names, port, agents=(): {}


# разбор сбоя: на что похоже
def pt(tcp="open", tls=True, got=65536, end="ok"):
    up = tcp == "open"
    return {"host": "h", "addr": "9.9.9.9", "tcp": tcp, "tcp_ms": 40 if up else None, "tls": tls if up else None,
            "bytes": got if up and tls else None, "need": 65536, "end": end if up and tls else None}


def dd(direct, agents=None, abroad=None, trace=None):
    return {"direct": direct, "agents": agents or {}, "abroad": abroad, "via": "NL1", "trace": trace, "external": None}


DEAD, FINE, CUT, NOTLS = pt("timeout"), pt(), pt(got=16400, end="timeout"), pt(tls=False)
two = lambda a, b=None: {"Москва": a, "Timeweb": a if b is None else b}
v = blockwatch.deep_verdict
check("блокировку адреса ноды из России" in v(dd(DEAD, two(DEAD), True, {"reached": False, "hops": 9, "last": (7, "62.1.1.1")}), "DOWN")
      and "после шага 7" in v(dd(DEAD, two(DEAD), True, {"reached": False, "hops": 9, "last": (7, "62.1.1.1")}), "DOWN")
      and "со всех 3 российских точек" in v(dd(DEAD, two(DEAD), True), "DOWN"),
      "X24 из-за рубежа жива, из России не отвечает ниоткуда — блокировка адреса, с шагом, где пропадают пакеты")
check("сбой самой ноды или её хостера" in v(dd(DEAD, two(DEAD), False), "DOWN"), "X25 не отвечает ни из России, ни из-за рубежа — поломка, не блокировка")
check("душат всю подсеть хостера" in v(dd(CUT, two(CUT), True), "FREEZE"), "X26 данные встают и при прямом обращении к сайту — душат подсеть хостера")
check("режут именно VPN-соединение" in v(dd(FINE, two(FINE), True), "FREEZE")
      and "дело в Xray на ноде, ключе или профиле" in v(dd(FINE, two(FINE), True), "DOWN"),
      "X27 сайт ноды отовсюду отвечает, а VPN нет — не блокировка адреса: режут протокол либо дело в самой ноде")
check("не отвечает только с rf1" in v(dd(DEAD, two(FINE), True), "DOWN")
      and "с части российских точек" in v(dd(FINE, two(DEAD, FINE), True), "DOWN"),
      "X28 не отвечает только с rf1 — сбой у rf1; с части точек — блокировка у отдельных провайдеров")
check("блокировка по имени сайта (SNI)" in v(dd(NOTLS, two(NOTLS), True), "DOWN")
      and "на уровне DNS" in v(dd(pt("dns"), two(pt("dns")), True), "DOWN"),
      "X29 порт открыт, а TLS рвётся — блокировка по имени; имя не находится в DNS — блокировка на уровне DNS")
check("с rf1;" in v(dd(DEAD, two(None), None), "DOWN") and "не различить" in v(dd(DEAD, two(None), None), "DOWN"),
      "X30 точки не ответили и из-за рубежа проверить не через что — честно: не различить")
lines = blockwatch.deep_lines(dd(CUT, {"Москва": FINE, "Timeweb": None}, True, {"reached": True, "hops": 11, "last": (11, "9.9.9.9")}))
check(lines == ["• с rf1 напрямую: соединение есть, но данные встали после 16 КБ",
                "• Москва: порт открыт (40 мс), TLS отвечает, 64 КБ получены", "• Timeweb: не ответила",
                "• из-за рубежа (через NL1): отвечает", "• трассировка с rf1: пакеты доходят до ноды (11 шагов)"],
      "X31 строки «откуда проверил»: по строке на точку")

# настоящая связка deep_many: кого и о чём спрашиваем
asked = {"direct": [], "agent": [], "abroad": [], "trace": [], "series": [], "sni": []}
real_probe, real_aget, real_sopen, real_trace = netprobe.direct_probe, blockwatch.agent_get, nw.socks_open, netprobe.tcp_trace
real_series, real_cmp = netprobe.series, netprobe.sni_compare
netprobe.direct_probe = lambda host, port=443, sni=None, **kw: asked["direct"].append((host, port, sni)) or dict(pt("timeout"), addr="9.9.9.9")
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: asked["series"].append((host, port, n, mss)) or {"n": n, "ok": 0, "fail": n}
netprobe.sni_compare = lambda host, port=443, sni=None, mss=None: asked["sni"].append((host, port, sni)) or None


def fake_aget(a, path, timeout=20):
    asked["agent"].append((a["name"], path))
    if "example.net" not in path:
        return None  # чужой адрес агенту не разрешён — он отвечает отказом
    return pt("timeout") if path.startswith("/probe") else {"n": 6, "ok": 0, "fail": 6} if path.startswith("/series") else None


blockwatch.agent_get = fake_aget
nw.socks_open = lambda via, host, port, timeout=5, tls=False: asked["abroad"].append((via, host, port, tls)) or True
netprobe.tcp_trace = lambda addr, port=443, max_hops=16: asked["trace"].append((addr, port)) or {"reached": False, "hops": 9, "last": (7, "62.1.1.1")}
got = real_deep_many(CHANS, lambda c: {"name": "NL1", "port": 21003} if c["port"] != 21003 else None,
                     [{"name": "Москва", "url": "u", "token": "t"}], probe.DOMAINS)
check(set(got) == {POLAND, "NL1", "Резерв"} and sorted(asked["direct"]) == [("nl1.example", 443, "dl.google.com"),
                                                                             ("pl1.example.net", 443, "pl1.example.net"),
                                                                             ("rf1.example", 443, "x")]
      and sorted(asked["abroad"]) == [(21003, "pl1.example.net", 443, True), (21003, "rf1.example", 443, True)]
      and len(asked["trace"]) == 3 and got["NL1"]["abroad"] is None and got[POLAND]["abroad"] is True
      and got[POLAND]["external"] is None,
      "X32 разбор: прямая проверка — каждому; из-за рубежа — через чужой канал; трассировка, когда порт не отвечает")
check(sorted(p for _, p in asked["agent"] if "pl1" in p) == ["/path?host=pl1.example.net&port=443",
                                                             "/probe?host=pl1.example.net&port=443",
                                                             "/series?host=pl1.example.net&port=443&n=6&mss=1203",
                                                             "/sni?host=pl1.example.net&port=443&mss=1233",
                                                             "/sniref?host=pl1.example.net&port=443"]
      and ("Москва", "/probe?host=nl1.example&port=443&sni=dl.google.com") in asked["agent"]
      and set(got[POLAND]["agents"]) == {"Москва"} and got["NL1"]["agents"] == {} and got["Резерв"]["agents"] == {}
      and sorted(asked["series"]) == [("nl1.example", 443, 6, 1201), ("pl1.example.net", 443, 6, 1201), ("rf1.example", 443, 6, 1201)]
      and set(got[POLAND]["series"]) == {"rf1", "Москва"} and set(got["NL1"]["series"]) == {"rf1"}
      and ("nl1.example", 443, "dl.google.com") in asked["sni"],
      "X32a точку спрашиваем о входе, серии и именах; о чужом адресе она молчит — её нет в разборе (а не «не ответила»)")
# одиночная проверка попала на потерянное соединение, а серия с той же точки проходит — перепроверяем
asked["direct"].clear()
asked["agent"].clear()
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: {"n": n, "ok": n - 1, "fail": 1}
flip = {"n": 0}


def flaky_probe(host, port=443, sni=None, **kw):
    flip["n"] += 1
    return dict(pt("timeout"), addr="9.9.9.9") if flip["n"] == 1 else dict(pt(), addr="9.9.9.9")


netprobe.direct_probe = flaky_probe
seq = {"n": 0}


def flaky_aget(a, path, timeout=20):
    asked["agent"].append((a["name"], path))
    if path.startswith("/series"):
        return {"n": 6, "ok": 5, "fail": 1}
    if path.startswith("/probe"):
        seq["n"] += 1
        return pt("timeout") if seq["n"] == 1 else pt()
    return None


blockwatch.agent_get = flaky_aget
one = blockwatch.deep_diag(CHANS[0], None, [{"name": "Москва", "url": "u", "token": "t"}], probe.DOMAINS)
check(flip["n"] == 2 and one["direct"]["tcp"] == "open" and one["agents"]["Москва"]["tcp"] == "open"
      and [p for _, p in asked["agent"]].count("/probe?host=pl1.example.net&port=443") == 2,
      "X32b «порт не отвечает» с одной попытки, а серия проходит — вход перепроверяется (и на rf1, и на точке)")
netprobe.series, netprobe.sni_compare = real_series, real_cmp
blockwatch.DEEP_MAX = 2
check(len(real_deep_many(CHANS, lambda c: None, [], probe.DOMAINS)) == 2, "X33 за один запуск разбираем не больше DEEP_MAX каналов")
blockwatch.DEEP_MAX = 3
netprobe.direct_probe, blockwatch.agent_get, nw.socks_open, netprobe.tcp_trace = real_probe, real_aget, real_sopen, real_trace

# разбор сбоя в сообщениях сторожа
fresh()
deep_calls2 = []
D_BLOCK = dd(DEAD, two(DEAD), True, {"reached": False, "hops": 9, "last": (7, "62.1.1.1")})


def fake_deep_many(chans, via_for, agents, bases):
    deep_calls2.append([(c["name"], via_for(c)) for c in chans])
    return {c["name"]: D_BLOCK for c in chans}


blockwatch.deep_many = fake_deep_many
world["alive"][21004] = False
step()
out = step()
check(len(out) == 1 and "Недоступен: 🇵🇱 Poland" in out[0] and "<b>Откуда проверил</b>" in out[0]
      and "• Москва: порт не отвечает" in out[0] and "• из-за рубежа (через NL1): отвечает" in out[0]
      and "• остальные каналы: работают" in out[0] and "блокировку адреса ноды из России" in out[0]
      and "Что проверил" not in out[0] and "Для пользователей" in out[0],
      "X34 канал лёг — в тревоге разбор с нескольких точек и вывод из него")
check(deep_calls2 == [[(POLAND, {"name": "NL1", "port": 21003})]], "X35 из-за рубежа смотрим через живой чужой канал (не «Резерв»: у него выход в РФ)")
got = []
for _ in range(32):
    got += step()
check(len(got) == 1 and "Всё ещё недоступен" in got[0] and "<b>Откуда проверил</b>" in got[0] and len(deep_calls2) == 2,
      "X36 в напоминании через час — свежий разбор")
world["alive"] = {21004: False, 21003: False, 21007: False}
n_before = len(deep_calls2)
step()
out = step()
check(len(deep_calls2) == n_before and any("Недоступен: NL1" in x and "Что проверил" in x and "Откуда проверил" not in x for x in out),
      "X37 лежит сразу большинство каналов — дело не в одной ноде, подробный разбор не запускается")
fresh()
world["deep"][21004] = (20000, 20.0, 1000.0, "1.1.1.1")
D_CUT = dd(CUT, two(CUT), True)
blockwatch.deep_many = lambda chans, via_for, agents, bases: {c["name"]: D_CUT for c in chans}
got = []
for _ in range(12):
    got += step()
check(len(got) == 1 and "Душат: 🇵🇱 Poland" in got[0] and "<b>Откуда проверил</b>" in got[0]
      and "душат всю подсеть хостера" in got[0] and "Так выглядит удушение DPI" not in got[0],
      "X38 канал душат — в тревоге тот же разбор: душат подсеть хостера или только VPN")
world["deep"] = {}
blockwatch.deep_many = lambda chans, via_for, agents, bases: {}

# точки проверки в отчёте
fresh()
json.dump([A, {"name": "Нет", "url": "http://x", "token": "t"}, {"name": "без токена", "url": "http://x"}],
          open(os.path.join(tmp, "vantage.json"), "w", encoding="utf-8"))
check([a["name"] for a in blockwatch.agents_cfg()] == ["Москва", "Нет"], "X39 точки проверки берутся из vantage.json; запись без токена пропускается")
blockwatch.agents_health = lambda agents: {a["name"]: a["name"] != "Нет" for a in agents}
for _ in range(4):
    step()
check("⚠️ точка проверки не отвечает: Нет" in report(), "X40 точка проверки молчит — пометка в отчёте")
blockwatch.agents_health = lambda agents: {a["name"]: True for a in agents}
stv = load()
stv["slow_last"] = 0
json.dump(stv, open(probe.STATE, "w", encoding="utf-8"))
for _ in range(4):
    step()
check("точек проверки в РФ: 3" in report(), "X41 все на связи — в отчёте сколько точек смотрит на ноды (rf1 и агенты)")
os.remove(os.path.join(tmp, "vantage.json"))
blockwatch.agents_health = lambda agents: {}

# проверка блокировок по запросу (probe.py --blocks)
CLEAN = {"ts": 1, "sources": {k: {"ok": True, "n": 10} for k in blockwatch.KIND}, "hits": {k: {} for k in blockwatch.KIND},
         "targets": {"ips": 17, "names": 17}, "neighbours": {}}
res_ok = {"lists": CLEAN, "dns": {"sub.example.com": {"truth": ["1.1.1.1"], "odd": [], "asked": 5}}, "dns_names": 1,
          "health": {"Москва": True, "Timeweb": True},
          "nodes": {POLAND: dd(FINE, two(FINE), True), "srv1📶 ANTI_BLOCK": dd(pt(got=1200, end="small"), {}, True)},
          "external": False}
text = blockwatch.check_text(res_ok, "07.10 16:00 МСК")
check("✅ наших адресов и доменов в списках нет — сверено адресов: 17, имён: 17, списков: 6 из 6" in text
      and "✅ подмены нет — имён: 1" in text
      and "✅ 🇵🇱 Poland — отвечает со всех 3 российских точек, из-за рубежа отвечает" in text
      and "✅ srv1📶 ANTI_BLOCK — отвечает с rf1, из-за рубежа отвечает" in text
      and "rf1 ✅ · Москва ✅ · Timeweb ✅" in text and "<b>Внешний сервис:</b> выключен" in text and "⚠️" not in text,
      "X45 проверка по запросу, всё чисто: списки, DNS, вход каждой ноды со всех точек, сами точки, внешний сервис выключен")
bad_lists = dict(CLEAN, sources=dict(CLEAN["sources"], cdn={"ok": False, "n": 0}),
                 hits=dict(CLEAN["hits"], rkn_ip={"de1 (93.186.39.68)": "93.186.39.68/32"}),
                 neighbours={"pl1 (93.185.33.11)": 2, "rf1 (93.187.140.234)": 1})
res_bad = {"lists": bad_lists, "dns": {"sub.example.com": {"truth": ["1.1.1.1"], "odd": [["rf1: Google", "6.6.6.6"]], "asked": 5}},
           "dns_names": 3, "health": {"Москва": True, "Timeweb": False},
           "nodes": {POLAND: dd(CUT, {"Москва": FINE, "Timeweb": None}, True), "NL1": dd(DEAD, {}, False)}, "external": True}
text = blockwatch.check_text(res_bad, "07.10 16:00 МСК")
check("⚠️ de1 (93.186.39.68) — реестр РКН, адреса, запись 93.186.39.68/32" in text
      and ("ℹ️ рядом с нашими адресами в реестре есть чужие (та же подсеть /24, другие клиенты хостера): "
           "pl1 (93.185.33.11) — 2, rf1 (93.187.140.234) — 1. Наших адресов в реестре нет, на работу это не влияет.") in text
      and "⚠️ не скачались: подсети CDN и хостеров, которые в России душат" in text
      and "⚠️ sub.example.com: по защищённому DNS 1.1.1.1; иначе отвечают: rf1: Google — 6.6.6.6" in text
      and "⚠️ защищённый DNS не ответил по 2 из 3 имён" in text
      and ("⚠️ 🇵🇱 Poland — rf1: соединение есть, но данные встали после 16 КБ; Timeweb: не ответила; "
           "в порядке: Москва; из-за рубежа отвечает") in text
      and "⚠️ NL1 — rf1: порт не отвечает; из-за рубежа НЕ отвечает" in text and "Timeweb ❌" in text
      and "запрос к нему не написан" in text,
      "X46 проверка по запросу с бедами: кто в каком списке, какое имя подменяют, какая нода с какой точки не отвечает")
real_parts = (blockwatch.lists_run, blockwatch.dns_check, blockwatch.deep_diag, blockwatch.targets)
seen_fc = {"via": {}}
blockwatch.targets = lambda *a, **k: {"ips": {}, "names": {}}
blockwatch.lists_run = lambda tg, bases, port=None, **kw: seen_fc.update(lists_port=port) or CLEAN
blockwatch.dns_check = lambda names, port, agents=(): seen_fc.update(dns=(list(names), port)) or {}
blockwatch.deep_diag = lambda c, via, agents, bases: seen_fc["via"].update({c["name"]: via}) or dd(FINE, {}, True)
blockwatch.agents_health = lambda agents: {"Москва": True}
res = blockwatch.full_check(CHANS, [{"name": "pl1", "host": "pl1.example.net"}], probe.SITE_HOSTS, probe.DOMAINS,
                            {POLAND: {"status": "DOWN"}, "NL1": {"status": "OK"}, "Резерв": {"status": "OK"}}, agents=[])
check(set(res["nodes"]) == {POLAND, "NL1", "Резерв"} and res["dns_names"] == 5 and seen_fc["dns"][1] == 21003
      and seen_fc["lists_port"] == 21003 and seen_fc["via"][POLAND] == {"name": "NL1", "port": 21003}
      and seen_fc["via"]["NL1"] is None and res["health"] == {"Москва": True} and res["external"] is False,
      "X47 проверка по запросу: защищённый DNS и «из-за рубежа» — через канал, который сейчас работает и не выходит в РФ")
blockwatch.lists_run, blockwatch.dns_check, blockwatch.deep_diag, blockwatch.targets = real_parts
blockwatch.dns_check = lambda names, port, agents=(): {}
blockwatch.agents_health = lambda agents: {}

vpath = os.path.join(tmp, "vantage.json")
check(blockwatch.add_vantage(json.dumps({"name": "Москва", "url": "http://a:9109", "token": "t1"})) == ["Москва"]
      and blockwatch.add_vantage(json.dumps({"name": "Питер", "url": "http://b:9109", "token": "t2"})) == ["Москва", "Питер"]
      and blockwatch.add_vantage(json.dumps({"name": "Москва", "url": "http://c:9109", "token": "t3"})) == ["Питер", "Москва"]
      and [a["url"] for a in blockwatch.agents_cfg()] == ["http://b:9109", "http://c:9109"],
      "X48 точка проверки добавляется в vantage.json; точка с тем же названием заменяется, а не двоится")
try:
    blockwatch.add_vantage(json.dumps({"name": "без токена", "url": "http://x"}))
    refused = False
except ValueError:
    refused = True
check(refused and len(blockwatch.agents_cfg()) == 2, "X49 запись без токена не принимается, список не портится")
os.remove(vpath)

# Telegram: напрямую, затем через свой рабочий канал, затем запасной мост
fresh()
check(probe.tg_routes() == [None, "socks5h://127.0.0.1:21004", probe.TG_FALLBACK_PROXY],
      "X50 в Telegram шлём напрямую, а если не вышло — через свой рабочий канал с зарубежным выходом")
world["alive"] = {21004: False, 21003: False}
step(), step()
check(probe.tg_routes() == [None, probe.TG_FALLBACK_PROXY],
      "X51 зарубежные каналы лежат («Резерв» выходит в РФ — не годится) — остаются прямой путь и запасной мост")
world["alive"] = {}
step(), step()
sent.clear()

# заглушка внешнего сервиса: выключена и никуда не ходит
real_conn, real_urlopen = socket.create_connection, blockwatch.urllib.request.urlopen
touched = []
socket.create_connection = lambda *a, **k: touched.append(a) or (_ for _ in ()).throw(OSError("сеть в этом тесте запрещена"))
blockwatch.urllib.request.urlopen = lambda *a, **k: touched.append(a) or (_ for _ in ()).throw(OSError("сеть в этом тесте запрещена"))
check(blockwatch.external_scan({"host": "de1.example.net", "addr": "93.186.39.68"}) is None
      and blockwatch.external_scan({"host": "x"}, {"enabled": False, "service": "cheburcheck"}) is None,
      "X42 внешний сервис: настроек нет или выключен — ничего не делает")
json.dump({"enabled": True, "service": "cheburcheck"}, open(os.path.join(tmp, "external.json"), "w", encoding="utf-8"))
ext = blockwatch.external_scan({"host": "de1.example.net", "addr": "93.186.39.68"})
check(ext == {"service": "cheburcheck", "note": "включена в настройках, но запрос к сервису не написан — ничего не отправлено"}
      and touched == [],
      "X43 даже если включить в настройках — запроса нет: наружу не уходит ничего, в сообщении так и сказано")
check("• внешняя проверка (cheburcheck): включена в настройках" in blockwatch.deep_lines(dict(D_BLOCK, external=ext))[-1],
      "X44 строка о внешней проверке появляется в разборе только когда она включена")
os.remove(os.path.join(tmp, "external.json"))
socket.create_connection, blockwatch.urllib.request.urlopen = real_conn, real_urlopen

# ZL. серии соединений, сравнение имён TLS, фоновый замер потерь, сверка с нодой
class Silent(socketserver.BaseRequestHandler):
    def handle(self):
        real_time.sleep(3)


class Closer(socketserver.BaseRequestHandler):
    def handle(self):
        pass


def tcp_server(handler):
    srv_ = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv_.daemon_threads = True
    threading.Thread(target=srv_.serve_forever, daemon=True).start()
    return srv_.server_address[1]


p_silent, p_closer = tcp_server(Silent), tcp_server(Closer)
r = netprobe.series("localhost", p_page, 5, gap=0)
check(r["addr"] == "127.0.0.1" and (r["n"], r["ok"], r["fail"], r["refused"]) == (5, 5, 0, 0) and r["ms"] is not None
      and r["t1"] >= r["t0"] and r["mss"] is None,
      "ZL1 серия соединений: сколько прошло, сколько нет, время")
r = netprobe.series("127.0.0.1", dead_port, 20, gap=0)
check((r["n"], r["ok"], r["refused"]) == (6, 0, 6) and netprobe.series("no-such-name.invalid", 443, 3)["addr"] is None,
      "ZL2 не прошло ни одно из шести — серия обрывается: сервер недоступен целиком, это не «частичные потери»")
MARK = netprobe.series("127.0.0.1", p_page, 1, mss=1213, gap=0)["mss"] == 1213  # умеет ли система ставить метку
check(netprobe.series("127.0.0.1", p_page, 2, mss=1213, gap=0)["mss"] == (1213 if MARK else None)
      and netprobe.series("127.0.0.1", p_page, 2, mss=5000, gap=0)["mss"] is None
      and netprobe.series("127.0.0.1", p_page, 2, mss=1213, gap=0)["ok"] == 2,
      "ZL3 метка серии — только из своего диапазона; с меткой соединения проходят так же")
check(netprobe.tls_hello("127.0.0.1", p_page, "x.example") == "answer"
      and netprobe.tls_hello("127.0.0.1", p_silent, "x.example", timeout=1) == "silent"
      and netprobe.tls_hello("127.0.0.1", p_closer, None, timeout=2) in ("closed", "reset")
      and netprobe.tls_hello("127.0.0.1", dead_port, None) == "tcp",
      "ZL4 приветствие TLS: сервер ответил (хоть отказом) / молчит / закрыл соединение / порт не открылся")
c = netprobe.sni_compare("localhost", p_page)
sc = blockwatch.sni_cut
check({k: c[k] for k in ("addr", "dns", "real", "neutral", "none")} == {"addr": "127.0.0.1", "dns": "system", "real": "answer", "neutral": "answer", "none": "answer"} and c["mss"] is None
      and netprobe.sni_compare("no-such-name.invalid") is None
      and sc({"real": "silent", "neutral": "answer", "none": "silent"}) and sc({"real": "reset", "neutral": "silent", "none": "answer"})
      and not sc(c) and not sc({"real": "silent", "neutral": "silent", "none": "silent"}) and not sc(None)
      and not sc({"real": "tcp", "neutral": "tcp", "none": "tcp"}),
      "ZL5 сравнение имён: с настоящим молчит, с другим отвечает — режут по имени; молчит со всеми — нет")

agent_cfg2 = {"token": TOKEN, "allow": ["127.0.0.1"], "suffixes": ["localhost"], "ports": [p_page, p_silent], "tls": False,
              "name": "тест", "hosts": ["127.0.0.1"], "snis": ["dl.google.com"]}
agent2 = vantage_agent.Agent(("127.0.0.1", 0), agent_cfg2)
threading.Thread(target=agent2.serve_forever, daemon=True).start()
A2 = {"name": "Офис", "url": f"http://127.0.0.1:{agent2.server_address[1]}", "token": TOKEN}
h = blockwatch.agent_get(A2, "/health")
r = blockwatch.agent_get(A2, f"/series?host=localhost&port={p_page}&n=4&mss=1213")
check(h["v"] == 5 and h["ports"] == [p_page, p_silent] and (r["n"], r["ok"], r["mss"]) == (4, 4, 1213 if MARK else None)
      and blockwatch.agent_get(A2, f"/series?host=localhost&port={p_page}&n=999&mss=9999")["mss"] == (1260 if MARK else None)
      and blockwatch.agent_get(A2, f"/series?host=localhost&port={dead_port}") is None,
      "ZL6 агент: серия соединений по запросу; число и метка — в своих пределах; чужой порт — отказ")
real_hello = netprobe.tls_hello
seen_sni = []
netprobe.tls_hello = lambda addr, port, name, timeout=5, mss=None: seen_sni.append(name) or "answer"
blockwatch.agent_get(A2, f"/sni?host=127.0.0.1&port={p_page}&sni=dl.google.com")
blockwatch.agent_get(A2, f"/sni?host=127.0.0.1&port={p_page}&sni=evil.example")
netprobe.tls_hello = real_hello
check(blockwatch.agent_get(A2, f"/probe?host=127.0.0.1&port={p_page}")["tcp"] == "open"
      and blockwatch.agent_get(A2, f"/probe?host=10.0.0.1&port={p_page}") is None
      and blockwatch.agent_get(A2, f"/sni?host=localhost&port={p_page}")["real"] == "answer"
      and seen_sni.count("dl.google.com") == 1 and "evil.example" not in seen_sni and seen_sni.count("127.0.0.1") == 1,
      "ZL7 агент: адрес из списка hosts разрешён, прочие — нет; чужое имя TLS — только из списка snis")
agent2.shutdown()

lj = blockwatch.loss_judge
ser = lambda fail, n=30, ok=None, **kw: dict({"n": n, "ok": n - fail if ok is None else ok, "fail": fail, "slow": 0, "refused": 0,
                                               "ms": 40, "t0": 1000.0, "t1": 1010.0, "mss": 1203}, **kw)
check(lj(ser(3)) == "bad" and lj(ser(0)) == "ok" and lj(ser(1)) is None and lj(ser(2)) is None and lj(None) is None
      and lj(ser(6, n=6, ok=0)) is None and lj(ser(0, n=4)) is None,
      "ZL8 замер одним словом: 3 из 30 и больше — потери; ноль — чисто; один-два — не судим; сервер недоступен целиком — не судим")
wu = blockwatch.witness_url
check(wu("https://de7.example.net/st-abc123.json") == "https://de7.example.net/fw-abc123.json"
      and wu("http://1.2.3.4:9108/state.json") == "http://1.2.3.4:9108/flows.json" and wu(None) is None and wu("https://x/other.json") is None,
      "ZL9 счётчики ноды лежат рядом с маячком под тем же случайным именем")
flows = [[1001.0 + i * 0.2, 1203, 1, 1, 0, 0] for i in range(27)] + [[1007.0 + i, 1203, 3, 5, 0, 0] for i in range(3)]
wit = {"ts": 1030.0, "flows": flows + [[1002.0, 1205, 1, 1, 0, 0], [500.0, 1203, 1, 1, 0, 0]]}
wm, wt = blockwatch.witness_match, blockwatch.witness_text
m = wm(wit, ser(3))
check(m == {"seen": 30, "rep": 3, "rst_out": 0, "rst_in": 0} and "ответ не дошёл обратно" in wt(ser(3), m)
      and wm(dict(wit, ts=1005.0), ser(3)) is None and wm(None, ser(3)) is None and wm(wit, ser(3, mss=None)) is None,
      "ZL10 сверка с нодой: все запросы дошли, нода отвечала, ответы не вернулись — потери на обратном пути; чужие метки и старые записи не в счёт")
m2 = wm({"ts": 1030.0, "flows": flows[:27]}, ser(3))
check(m2["seen"] == 27 and "теряются по дороге к ноде" in wt(ser(3), m2) and wt(ser(0), m) is None and wt(ser(3), None) is None,
      "ZL11 до ноды дошло меньше, чем послано, — потери по дороге к ноде; без потерь и без счётчиков — молчим")

L_NODES = [{"name": "de7", "host": "de7.example.net", "beacon": "https://de7.example.net/st-a.json"},
           {"name": "nl2", "host": "nl2.example.net", "beacon": "https://nl2.example.net/st-b.json"}]
L_AGENTS = [{"name": "Москва", "url": "u", "token": "t"}, {"name": "Офис", "url": "u2", "token": "t"}]
asked_loss, fetched = [], []
real_fw = blockwatch.fetch_witness
blockwatch.fetch_witness = lambda url, socks_port=None: fetched.append((url, socks_port)) or {"ts": 2000.0, "flows": [[f[0], 1205] + f[2:] for f in flows]}
res = blockwatch.loss_run(
    L_NODES, L_AGENTS, n=30, socks_port=21003, wait=0,
    local=lambda host, port, n, mss: asked_loss.append(("rf1", host, mss)) or ser(0, mss=mss),
    remote=lambda agent, host, mss: asked_loss.append((agent["name"], host, mss))
    or (ser(3, mss=mss) if (agent["name"], host) == ("Офис", "de7.example.net") else None if agent["name"] == "Москва" and "nl2" in host else ser(0, mss=mss)))
blockwatch.fetch_witness = real_fw
check(res["points"] == ["rf1", "Москва", "Офис"] and set(res["nodes"]) == {"de7", "nl2"}
      and sorted(asked_loss) == sorted([(p, h, m_) for p, m_ in (("rf1", 1201), ("Москва", 1203), ("Офис", 1205))
                                        for h in ("de7.example.net", "nl2.example.net")])
      and res["nodes"]["de7"]["Офис"]["fail"] == 3 and res["nodes"]["de7"]["Офис"]["wit"]["seen"] == 30
      and "wit" not in res["nodes"]["de7"]["rf1"] and res["nodes"]["nl2"]["Москва"] is None
      and fetched == [("https://de7.example.net/fw-a.json", 21003)],
      "ZL12 замер: каждая точка — каждую ноду, у каждой точки своя метка; у ноды спрашиваем счётчики только там, где что-то потерялось")

st_l = {}
data = lambda ts, office: {"ts": ts, "n": 30, "points": ["rf1", "Офис"],
                           "nodes": {"de7": {"rf1": ser(0), "Офис": office}, "nl2": {"rf1": ser(0), "Офис": ser(0)}}}
a1 = blockwatch.loss_step(st_l, data(100, ser(4, wit={"seen": 30, "rep": 4, "rst_out": 0, "rst_in": 0})))
a2 = blockwatch.loss_step(st_l, data(200, ser(4, wit={"seen": 30, "rep": 4, "rst_out": 0, "rst_in": 0})))
a3 = blockwatch.loss_step(st_l, data(300, ser(5)))
L2 = a2[0].split("\n") if a2 else []
check(a1 == [] and len(a2) == 1 and L2[0] == "📉 <b>Потери соединений до нод</b>" and "📍 Откуда: <b>Офис</b>" in L2
      and "• <b>DE7</b> — не проходит 4 из 30 (13 %)" in L2 and any(x.startswith("   ↳ нода получила все 30") for x in L2)
      and "С других точек к этим нодам: потерь нет (rf1)" in L2 and "NL4" not in a2[0] and a3 == []
      and L2.count("") >= 4 and max(len(x) for x in L2) < 190,
      "ZL13 потери держатся два замера подряд — одно сообщение, читаемое: откуда, по ноде на абзац, что видела нода — отдельной строкой; дальше не повторяем")
a4 = blockwatch.loss_step(st_l, data(400, ser(1)))
a5 = blockwatch.loss_step(st_l, data(500, ser(0)))
a6 = blockwatch.loss_step(st_l, data(600, ser(0)))
check(a4 == [] and a5 == [] and len(a6) == 1 and "Потери соединений прошли" in a6[0]
      and "📍 Откуда: <b>Офис</b>" in a6[0] and "• DE7 — проходят все 30 соединений" in a6[0]
      and st_l["loss"]["lvl"]["de7|Офис"]["lvl"] == "ok",
      "ZL14 один-два потерянных — ещё не «прошло»; чисто два замера подряд — сообщение, что потери прошли")
blockwatch.loss_step(st_l, data(700, ser(4)))
blockwatch.loss_step(st_l, data(800, ser(4)))
bl = blockwatch.block_line
check("⚠️ потери соединений: de7 — Офис 13 %" in bl(st_l, 900)
      and "потери" not in (bl(st_l, 800 + blockwatch.LOSS_STALE + 1) or "")
      and "потерь соединений с точек нет" in bl({"loss": {"ts": 100, "lvl": {}, "last": {}}}, 200),
      "ZL15 в обычном отчёте: где сейчас потери; чисто — так и сказано; замер устарел — не упоминаем")

okk = pt()
d1 = dict(dd(okk, {"Офис": okk}, True), series={"rf1": ser(0, n=6), "Офис": ser(1, n=6)}, sni={})
lines = blockwatch.deep_lines(d1)
check("соединений прошло 6 из 6" in lines[0] and "соединений прошло 5 из 6" in lines[1]
      and "часть соединений теряется (Офис — 5 из 6)" in v(d1, "DOWN"),
      "ZL16 в разборе у каждой точки — сколько соединений прошло; частичные потери названы в выводе")
cut_cmp = {"addr": "9.9.9.9", "real": "silent", "neutral": "answer", "none": "answer"}
d2 = dict(dd(NOTLS, {"Офис": NOTLS}, True), series={}, sni={"rf1": cut_cmp, "Офис": cut_cmp})
d3 = dict(dd(NOTLS, {"Офис": NOTLS}, True), series={}, sni={"rf1": cut_cmp, "Офис": dict(cut_cmp, neutral="silent", none="silent")})
check("режут по имени сайта" in v(d2, "DOWN") and any("имена TLS на том же адресе (с rf1, Офис)" in x for x in blockwatch.deep_lines(d2))
      and "режут по имени сайта" not in v(d3, "DOWN") and "блокировка по имени сайта (SNI) или по протоколу" in v(d3, "DOWN"),
      "ZL17 с настоящим именем ответа нет, с другим — есть, и так со всех точек — блокировка по имени; не со всех — прежний осторожный вывод")
d4 = dict(dd(dict(DEAD, alt80="open"), {"Офис": dict(DEAD, alt80="refused")}, True), series={}, sni={})
check("закрыт именно порт 443" in v(d4, "DOWN") and "а порт 80 на том же адресе отвечает" in blockwatch.deep_lines(d4)[0]
      and "закрыт именно порт 443" not in v(dd(DEAD, {"Офис": DEAD}, True), "DOWN"),
      "ZL18 порт 443 молчит, а порт 80 на том же адресе отвечает — закрыт порт, а не адрес")
nl = blockwatch.node_line
check(nl(POLAND, d1).startswith("⚠️") and "часть соединений теряется: Офис — прошло 5 из 6" in nl(POLAND, d1)
      and nl(POLAND, dict(d1, series={})).startswith("✅"),
      "ZL19 в проверке по запросу нода с частичными потерями помечена, без потерь — как раньше")

W0 = {"seen": 0, "rep": 0, "rst_out": 0, "rst_in": 0}
check("не дошло ни одно из 6" in wt(ser(6, n=6, ok=0), W0)
      and "закрыт обратный путь от ноды" in wt(ser(6, n=6, ok=0), dict(W0, seen=6, rep=6))
      and "сбросил кто-то по дороге" in wt(ser(0, n=6, ok=0, refused=6), dict(W0, seen=6))
      and "отказ на самой ноде" in wt(ser(2, n=6), dict(W0, seen=6, rst_out=2))
      and wt(ser(0, n=6, ok=0, refused=6), dict(W0, seen=6, rst_out=6)) is not None,
      "ZL21 сверка: запросы не дошли / ответы не вернулись / отказ пришёл не от ноды / отказала сама нода")
# сверка в разборе сбоя: счётчики ноды забираются через живой чужой канал
json.dump([{"name": "pl1", "host": "pl1.example.net", "beacon": "https://pl1.example.net/st-zz.json"}],
          open(os.path.join(tmp, "nodes.json"), "w", encoding="utf-8"))
blockwatch.WITNESS_WAIT = 0
real_probe2, real_aget2, real_series2, real_cmp2, real_sopen2, real_trace2 = (
    netprobe.direct_probe, blockwatch.agent_get, netprobe.series, netprobe.sni_compare, nw.socks_open, netprobe.tcp_trace)
netprobe.direct_probe = lambda host, port=443, sni=None, **kw: dict(pt("timeout"), addr="9.9.9.9")
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: ser(n, n=n, ok=0, mss=mss, t0=clock["t"] - 30, t1=clock["t"] - 20)
netprobe.sni_compare = lambda host, port=443, sni=None, mss=None: None
netprobe.tcp_trace = lambda addr, port=443, max_hops=16: None
nw.socks_open = lambda via, host, port, timeout=5, tls=False: True
blockwatch.agent_get = lambda a, path, timeout=20: (pt("timeout") if path.startswith("/probe") else
                                                    ser(6, n=6, ok=0, mss=1203, t0=clock["t"] - 30, t1=clock["t"] - 20)
                                                    if path.startswith("/series") else None)
wit_calls = []
blockwatch.fetch_witness = lambda url, socks_port=None: wit_calls.append((url, socks_port)) or {
    "ts": clock["t"], "flows": [[clock["t"] - 25, m_, 3, 5, 0, 0] for m_ in (1201, 1203) for _ in range(6)]}
dw = blockwatch.deep_diag(CHANS[0], {"name": "NL1", "port": 21003}, [{"name": "Москва", "url": "u", "token": "t"}], probe.DOMAINS)
check(wit_calls == [("https://pl1.example.net/fw-zz.json", 21003)] and set(dw["witness"]) == {"rf1", "Москва"}
      and dw["witness"]["Москва"] == {"seen": 6, "rep": 6, "rst_out": 0, "rst_in": 0}
      and any("сверка с нодой (Москва): нода получила все 6 и отвечала, но ни один ответ не дошёл обратно" in x for x in blockwatch.deep_lines(dw))
      and "закрыт обратный путь, от ноды в Россию" in v(dw, "DOWN"),
      "ZL22 разбор: счётчики ноды — через чужой канал; запросы дошли, ответы нет — в выводе «закрыт обратный путь»")
blockwatch.fetch_witness = lambda url, socks_port=None: {"ts": clock["t"], "flows": []}
dw0 = blockwatch.deep_diag(CHANS[0], {"name": "NL1", "port": 21003}, [], probe.DOMAINS)
blockwatch.fetch_witness = lambda url, socks_port=None: None
dwn = blockwatch.deep_diag(CHANS[0], {"name": "NL1", "port": 21003}, [], probe.DOMAINS)
check("запросы из России до неё не доходят — закрыт путь к ноде" in v(dw0, "DOWN") and dwn["witness"] == {}
      and "счётчикам ноды" not in v(dwn, "DOWN") and "блокировку адреса ноды из России" in v(dwn, "DOWN"),
      "ZL23 нода не видела ни одного запроса — закрыт путь к ноде; счётчиков нет — прежний вывод без догадок")
(netprobe.direct_probe, blockwatch.agent_get, netprobe.series, netprobe.sni_compare, nw.socks_open, netprobe.tcp_trace) = (
    real_probe2, real_aget2, real_series2, real_cmp2, real_sopen2, real_trace2)
blockwatch.fetch_witness = real_fw
os.remove(os.path.join(tmp, "nodes.json"))

import node_witness
fl = node_witness.Flows()
T = 1000.0
for line in (
    f"{T:.6f} IP 79.1.1.1.40001 > 93.185.1.1.443: Flags [S], seq 1, win 64240, options [mss 1213,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0",
    f"{T + 0.01:.6f} IP 93.185.1.1.443 > 79.1.1.1.40001: Flags [S.], seq 9, ack 2, win 65160, options [mss 1460], length 0",
    f"{T + 0.2:.6f} IP 79.1.1.1.40002 > 93.185.1.1.443: Flags [S], seq 5, win 64240, options [mss 1213,sackOK], length 0",
    f"{T + 0.21:.6f} IP 93.185.1.1.443 > 79.1.1.1.40002: Flags [S.], seq 9, ack 6, win 65160, options [mss 1460], length 0",
    f"{T + 1.2:.6f} IP 79.1.1.1.40002 > 93.185.1.1.443: Flags [S], seq 5, win 64240, options [mss 1213,sackOK], length 0",
    f"{T + 1.21:.6f} IP 93.185.1.1.443 > 79.1.1.1.40002: Flags [S.], seq 9, ack 6, win 65160, options [mss 1460], length 0",
    f"{T + 3.2:.6f} IP 93.185.1.1.443 > 79.1.1.1.40002: Flags [S.], seq 9, ack 6, win 65160, options [mss 1460], length 0",
    f"{T + 0.5:.6f} IP 5.5.5.5.50000 > 93.185.1.1.443: Flags [S], seq 7, win 64240, options [mss 1460,sackOK], length 0",
    f"{T + 0.51:.6f} IP 93.185.1.1.443 > 5.5.5.5.50000: Flags [S.], seq 1, ack 8, win 65160, options [mss 1460], length 0",
    f"{T + 0.6:.6f} IP 93.185.1.1.443 > 5.5.5.5.50001: Flags [R.], seq 1, ack 8, win 0, length 0",
    f"{T + 0.7:.6f} eth0  In  IP 79.1.1.1.40003 > 93.185.1.1.443: Flags [S], seq 5, win 64240, options [mss 1217,sackOK], length 0",
    f"{T + 0.71:.6f} eth0  Out IP 93.185.1.1.443 > 79.1.1.1.40003: Flags [R.], seq 0, ack 6, win 0, length 0",
    f"{T + 0.9:.6f} IP 79.1.1.1.40001 > 93.185.1.1.443: Flags [R], seq 2, win 0, length 0",
    "мусор",
):
    fl.feed(line)
snap = fl.snapshot(T + 5)
rows = snap["flows"]
check(len(rows) == 3 and rows[0] == [T, 1213, 1, 1, 0, 1] and rows[1] == [T + 0.2, 1213, 2, 3, 0, 0] and rows[2] == [T + 0.7, 1217, 1, 0, 1, 0]
      and "79.1.1.1" not in json.dumps(snap) and "5.5.5.5" not in json.dumps(snap) and snap["ts"] == T + 5,
      "ZL24 свидетель: считает только помеченные соединения (запросы, ответы, сбросы), клиентские не попадают; адресов в файле нет")
fl.feed(f"{T + 40:.6f} IP 79.1.1.1.40001 > 93.185.1.1.443: Flags [S], seq 77, win 64240, options [mss 1213,sackOK], length 0")
fl.feed(f"{T + 20:.6f} IP 93.185.1.1.443 > 79.1.1.1.40002: Flags [S.], seq 9, ack 6, win 65160, options [mss 1460], length 0")
late = fl.snapshot(T + 41)["flows"]
old_gone = fl.snapshot(T + 41 + node_witness.KEEP)["flows"]
check(len(late) == 4 and late[1] == [T + 0.2, 1213, 2, 3, 0, 0] and late[-1] == [T + 40, 1213, 1, 0, 0, 0] and old_gone == []
      and wm({"ts": T + 30, "flows": rows}, ser(1, n=2, mss=1213, t0=T - 1, t1=T + 2)) == {"seen": 2, "rep": 1, "rst_out": 0, "rst_in": 1},
      "ZL25 свидетель: тот же порт через полминуты — новое соединение; поздний пакет в старое не идёт; записи старше получаса уходят; сторож сверяет по метке")

check(wm({"ts": 1030.0, "since": 1005.0, "flows": flows}, ser(3)) is None
      and wm({"ts": 1030.0, "since": 900.0, "flows": flows}, ser(3))["seen"] == 30
      and wm({"ts": 1030.0, "flows": flows[:20]}, ser(3)) is None and wm({"ts": 1030.0, "flows": []}, ser(4)) is None
      and wm({"ts": 1030.0, "flows": []}, ser(6, n=6, ok=0)) == W0,
      "ZL26 свидетель запущен позже серии или насчитал меньше, чем прошло успешно, — его счётчикам не верим; «не дошло ничего» — только когда и у точки не прошло ничего")

fl2 = node_witness.Flows(local={"93.187.140.234"})
fl2.feed(f"{T:.6f} IP 93.187.140.234.50001 > 93.185.1.1.443: Flags [S], seq 1, win 64240, options [mss 1201,sackOK], length 0")
fl2.feed(f"{T:.6f} IP 79.1.1.1.40001 > 93.187.140.234.443: Flags [S], seq 1, win 64240, options [mss 1207,sackOK], length 0")
check([f[1] for f in fl2.snapshot(T + 1)["flows"]] == [1207],
      "ZL27 свидетель на сервере сторожа: собственные исходящие проверки других нод за входящие не считает")

two_pts = {"ts": 900, "n": 30, "points": ["rf1", "Москва", "Офис"],
           "nodes": {"de7": {"rf1": ser(0), "Москва": ser(1), "Офис": ser(6)}, "fi1": {"rf1": ser(0), "Москва": ser(0), "Офис": ser(4)},
                     "pl1": {"rf1": ser(0), "Москва": ser(5), "Офис": ser(0)}}}
txt = blockwatch.loss_alert([("de7", "Офис"), ("fi1", "Офис"), ("pl1", "Москва")], two_pts)
check(txt.count("📍 Откуда:") == 2 and txt.index("<b>DE7</b>") < txt.index("<b>FI1</b>") < txt.index("📍 Откуда: <b>Москва</b>") < txt.index("<b>PL1</b>")
      and "С других точек к этим нодам: DE7 — Москва: 1 из 30" in txt and "С других точек к этим нодам: потерь нет (rf1, Офис)" in txt
      and txt.endswith("Сами ноды работают."),
      "ZL28 несколько нод и точек в одном сообщении: сгруппировано по точке, у каждой свои ноды и своя строка про остальные точки")

# замер попадает в сообщения сторожа: свежий файл забирается один раз
fresh()
blockwatch.LOSS_FILE = os.path.join(tmp, "loss.json")
put = lambda fail: json.dump(dict(data(clock["t"] + 1, ser(fail)), ts=clock["t"] + 1), open(blockwatch.LOSS_FILE, "w", encoding="utf-8"))
put(4)
s1 = step()
put(4)
s2 = step()
s3 = step()
put(4)
s4 = step()
check(s1 == [] and len(s2) == 1 and "Потери соединений до нод" in s2[0] and s3 == [] and s4 == []
      and load()["loss"]["lvl"]["de7|Офис"]["lvl"] == "bad" and "потери соединений: de7 — Офис" in report(),
      "ZL20 сторож: потери подтверждены вторым замером — одно сообщение; тот же файл дважды не читается; в отчёте — строка")
os.remove(blockwatch.LOSS_FILE)

# ZL51. Профиль и гео приходят из файла службы --side; забираются один раз; гео в пробном режиме — без тревог
fresh()
blockwatch.SIDE_FILE = os.path.join(tmp, "side.json")
PF51 = blockwatch.profile_merge([{"sites": [{"kind": "blocked", "host": "rutracker.org", "addr": "1.2.3.4", "real": "silent",
                                             "neutral": "answer"}], "loads": []}] * 3)
G51 = {"🇩🇪 DE": {"flag": "DE", "row": {"ipinfo": "DE"}, "org": "H", "cf": "DE", "yt": "RU"}}
json.dump({"profiles": {"ts": clock["t"] + 1, "by": {"Офис": PF51}}, "geo": {"ts": clock["t"] + 1, "data": G51}},
          open(blockwatch.SIDE_FILE, "w", encoding="utf-8"))
a51 = step()
st51 = load()
a51b = step()
check(a51 == [] and a51b == [] and st51["profiles"]["by"]["Офис"]["tries"] == 3 and st51["geo"]["by"] == G51
      and st51["geo"]["seen"]["🇩🇪 DE"]["youtube"] == ["RU"] and "за фильтром точки: Офис" in report()
      and load()["geo"]["ts"] == st51["geo"]["ts"],
      "ZL51 основной проход забирает профиль и гео из файла службы один раз; гео первой недели — исходное, без тревог")
os.remove(blockwatch.SIDE_FILE)

# ZL29–ZL33. «Медленно» сразу у многих каналов (v9.1)
R = lambda ch, want, deep_res=OK_DEEP: (ch, True, 0, 0.05, 0.25, deep_res, None, None, want)
confirm_calls.clear()
res, ctrl = probe.confirm_step([R(CHANS[0], True), R(CHANS[1], False), R(CHANS[2], True)], 3)
check(ctrl is None and [p for _, p in confirm_calls] == [21004, 21007] and len(res[0][5]) == 5 and len(res[1][5]) == 4,
      "ZL29 мало у двух каналов из трёх — перепроверяем только их, по очереди, без замера напрямую")
confirm_calls.clear()
res, ctrl = probe.confirm_step([R(c, True) for c in CHANS], 3)
check(ctrl == FAST_CONFIRM and [p for _, p in confirm_calls] == [None, 21004, 21003, 21007] and all(len(r[5]) == 5 for r in res),
      "ZL29а мало у всех сразу — сперва та же закачка напрямую с rf1, потом каналы по одному")
confirm_calls.clear()
world["confirm"][None] = (1_000_000, 20.0, 50_000.0)
res, ctrl = probe.confirm_step([R(c, True) for c in CHANS], 3)
check([p for _, p in confirm_calls] == [None] and all(len(r[5]) == 4 for r in res) and ctrl[2] == 50_000.0,
      "ZL29б напрямую тоже медленно — тормозит сам rf1: каналы не перепроверяем")
world["confirm"].pop(None)
probe.CONFIRM_BUDGET, confirm_calls[:] = -1, []
res, _ = probe.confirm_step([R(CHANS[0], True), R(CHANS[1], False)], 3)
probe.CONFIRM_BUDGET = 90
check(confirm_calls == [] and res[0][5] is None and res[1][5] == OK_DEEP,
      "ZL29в время на перепроверки вышло — замер канала в этот раз не меняем (держим прежний)")

fresh()
SLOW_R = (524288, 9.0, 58_000.0, "9.9.9.9")
for c in CHANS:
    world["deep"][c["port"]] = SLOW_R if c["port"] == 21007 else SLOW_QUICK
    world["confirm"][c["port"]] = SLOW_BIG
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "Медленно сразу у 3 каналов из 3" in out[0] and "Poland 0.5" in out[0] and "NL1 0.5" in out[0]
      and "Резерв 0.5" in out[0] and "Напрямую с rf1 без VPN в тот же момент: 56.0 Мбит/с" in out[0]
      and "общую причину на стороне rf1" in out[0] and all(state(c["name"])["status"] == "SLOW" for c in CHANS),
      "ZL30 медленно сразу у всех каналов — одно сообщение со скоростями всех и замером напрямую")
out = []
for _ in range(31):
    out += step()
check(len(out) == 1 and "Всё ещё медленно у 3 каналов" in out[0] and "уже 1 ч" in out[0],
      "ZL31 через час — одно напоминание на всех, а не по каналу")
for c in CHANS:
    world["deep"].pop(c["port"])
    world["confirm"].pop(c["port"])
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "Скорость вернулась сразу у 3 каналов" in out[0] and "Медленно было с" in out[0],
      "ZL32 скорость вернулась сразу у всех — одно сообщение")

fresh()
world["confirm"][None] = (1_000_000, 20.0, 50_000.0)
for c in CHANS:
    world["deep"][c["port"]] = SLOW_R if c["port"] == 21007 else SLOW_QUICK
    world["confirm"][c["port"]] = SLOW_BIG
out = []
for _ in range(11):  # подтверждение — двумя плановыми замерами подряд, они раз в 10 минут
    out += step()
check(len(out) == 1 and "Медленно у самого rf1, а не у нод" in out[0] and "rf1 качает всего 0.4 Мбит/с" in out[0]
      and all(state(c["name"])["status"] == "OK" for c in CHANS) and not any("Медленно сразу" in x for x in out),
      "ZL33 напрямую с rf1 тоже медленно — каналы не помечаются, одно сообщение «медленно у самого rf1»")
world["confirm"].pop(None)
for c in CHANS:
    world["deep"].pop(c["port"])
    world["confirm"].pop(c["port"])
out = []
for _ in range(8):
    out += step()
check(len(out) == 1 and "rf1 снова качает нормально" in out[0] and load()["watch_slow"]["alerted"] is False,
      "ZL33а rf1 снова в порядке — одно сообщение, состояние сброшено")

# ZL34–ZL38. Часть A v10: слепая точка, запасной DNS, беда сети точки, DNS точки
real_gai, real_udp2 = netprobe.socket.getaddrinfo, netprobe.dns_udp
netprobe.FALLBACK_DNS = ("77.88.8.8", "8.8.8.8")
netprobe.socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("SERVFAIL"))
netprobe.dns_udp = lambda name, server, port=53, timeout=3: ("ok", ["203.0.113.7"]) if server == "8.8.8.8" else ("err", [])
r1 = netprobe.resolve("de7.example.net")
netprobe.dns_udp = lambda name, server, port=53, timeout=3: ("err", [])
r2 = netprobe.resolve("de7.example.net")
s2 = netprobe.series("de7.example.net", 443, 3)
netprobe.socket.getaddrinfo, netprobe.dns_udp, netprobe.FALLBACK_DNS = real_gai, real_udp2, ()
check(r1 == ("203.0.113.7", "8.8.8.8") and r2 == (None, "fail") and s2["addr"] is None and s2["dns"] == "fail" and s2["n"] == 0
      and netprobe.resolve("localhost") == ("127.0.0.1", "system"),
      "ZL34 свой DNS не нашёл имя — адрес берётся у публичного, и это помечено; не нашёл никто — так и сказано")

NODES5 = ["de1", "de7", "nl1", "nl2", "pl1"]
dz = lambda ts, office, moscow=None: {"ts": ts, "n": 30, "points": ["rf1", "Москва", "Офис"],
                                       "nodes": {n: {"rf1": ser(0), "Москва": moscow(n) if moscow else ser(0), "Офис": office(n)}
                                                 for n in NODES5}}
st_p = {}
blind = lambda n: None
b1 = blockwatch.loss_step(st_p, dz(100, lambda n: ser(4)))
b2 = blockwatch.loss_step(st_p, dz(200, lambda n: ser(4)))
check(len(b2) == 1 and "У точки «Офис» проблемы с сетью" in b2[0] and "5 нодам из 5" in b2[0] and "Потери соединений" not in b2[0]
      and st_p["loss"]["skip"] == ["Офис"] and all(v["lvl"] == "ok" for k, v in st_p["loss"]["lvl"].items() if k.endswith("|Офис")),
      "ZL35 точка теряет связь к большинству нод — одно сообщение о беде точки, по нодам не шлём, её пары не судим")
nb = lambda n: ser(0) if n != "de7" else ser(5)
b3 = blockwatch.loss_step(st_p, dz(300, nb))
b4 = blockwatch.loss_step(st_p, dz(400, nb))
check(b3 == [] and len(b4) == 1 and "Точка «Офис» снова в порядке" in b4[0] and st_p["loss"]["skip"] == []
      and st_p["loss"]["lvl"]["de7|Офис"]["cand"] == "bad",
      "ZL35а точка снова в порядке — сообщение; дальше её пары судятся как обычно (de7 — уже кандидат в потери)")
st_b = {}
c1 = blockwatch.loss_step(st_b, dz(100, blind))
c2 = blockwatch.loss_step(st_b, dz(200, lambda n: dict(ser(0), n=0, ok=0, addr=None, dns="fail")))
check(len(c2) == 1 and "Точка «Офис» ничего не проверила" in c2[0] and "ни свой, ни публичный DNS" in c2[0]
      and "Офис" in st_b["loss"]["skip"] and "точка «Офис» — ничего не проверяет" in blockwatch.block_line(st_b, 250),
      "ZL36 точка ничего не проверила два замера подряд — сообщение с причиной, строка в отчёте, её данные не учитываются")
check(blockwatch.loss_step(st_b, dz(300, blind)) == [] and st_b["loss"]["pt"]["Офис"]["lvl"] == "blind",
      "ZL36а пока точка слепа — повторных сообщений нет")

dns_res = {"a.example.com": {"system": {"rf1": "ok", "Офис": "err"}}, "b.example.net": {"system": {"rf1": "ok", "Офис": "err"}},
           "c.example.net": {"system": {"rf1": "ok", "Офис": "ok"}}}
check(blockwatch.dns_points(dns_res, [{"name": "Офис"}]) == {"rf1": (0, 3), "Офис": (2, 3)}
      and "свой DNS не находит наши имена" in blockwatch.dns_point_text("Офис", "bad", 2, 3)
      and "снова находит" in blockwatch.dns_point_text("Офис", "ok", 0, 3),
      "ZL37 по проверке DNS видно, у какой точки свой DNS не находит наши имена")
fresh()
real_dns_check_fake = blockwatch.dns_check
blockwatch.dns_check = lambda names, port, agents=(): {n: {"truth": ["1.1.1.1"], "odd": [], "asked": 3,
                                                          "system": {"rf1": "ok", "Москва": "err"}} for n in names}
blockwatch.agents_cfg = lambda: [{"name": "Москва", "url": "u", "token": "t"}]
out = []
for _ in range(40):
    out += step()
dns_msgs = [x for x in out if "свой DNS не находит" in x]
blockwatch.dns_check = lambda names, port, agents=(): {n: {"truth": ["1.1.1.1"], "odd": [], "asked": 3,
                                                          "system": {"rf1": "ok", "Москва": "ok"}} for n in names}
out2 = []
for _ in range(40):
    out2 += step()
blockwatch.dns_check = real_dns_check_fake
blockwatch.agents_cfg = lambda: []
check(len(dns_msgs) == 1 and "«Москва»" in dns_msgs[0] and len([x for x in out2 if "снова находит наши имена" in x]) == 1,
      "ZL37а сторож: свой DNS точки не находит наши имена две проверки подряд — одно сообщение; снова находит — одно")

okk2 = pt()
d5 = dict(dd(okk2, {"Офис": DEAD, "Москва": okk2}, True), series={}, sni={}, skip=["Офис"])
check("со всех 2 российских точек" in v(d5, "DOWN") and "с части российских точек" not in v(d5, "DOWN")
      and any("в выводе не учитываю" in x for x in blockwatch.deep_lines(d5)),
      "ZL38 разбор сбоя: точку с собственной бедой сети показываем, но в выводе не учитываем")

# ZL39–ZL41. Профиль точки (v10.1: три попытки, сводка)
def prun(real, neutral, cf=40.0, cf_bytes=300000):
    """Один ответ /profile: rutracker с настоящим именем real, с нейтральным neutral; ya.ru отвечает."""
    return {"sites": [{"kind": "blocked", "host": "rutracker.org", "addr": "1.2.3.4", "real": real, "neutral": neutral},
                      {"kind": "control", "host": "ya.ru", "addr": "9.9.9.9", "real": "answer", "neutral": None}],
            "loads": [{"name": "cloudflare", "mbit": cf, "bytes": cf_bytes}, {"name": "hetzner", "mbit": 0.0, "bytes": 0}]}


PF_FILT = blockwatch.profile_merge([prun("silent", "answer"), prun("reset", "answer"), prun("silent", "answer", 20.0)])
PF_ONCE = blockwatch.profile_merge([prun("silent", "answer"), prun("answer", "answer"), prun("answer", "answer")])
PF_ONE = blockwatch.profile_merge([prun("silent", "answer")])
PF_DEAD = blockwatch.profile_merge([{"sites": [{"kind": "blocked", "host": "r.org", "addr": None, "real": "dns", "neutral": None}, {"kind": "control", "host": "ya.ru", "addr": "9.9.9.9", "real": "tcp", "neutral": None}], "loads": []}] * 2)
pv = blockwatch.profile_verdict
t_filt = blockwatch.profile_text("Офис", PF_FILT)
t_once = blockwatch.profile_text("Москва", PF_ONCE)
check(pv(PF_FILT) == "filtered" and pv(PF_ONCE) == "clear" and pv(PF_ONE) == "clear"
      and pv({"sites": [{"kind": "blocked", "host": "x", "real": "silent", "neutral": "answer"}]}) == "unknown"
      and PF_FILT["sites"][0]["fails"] == {"silent": 2, "reset": 1}
      and "за фильтром — режут по имени: rutracker.org (с именем 0 из 3, с нейтральным 3 из 3)" in t_filt
      and "cloudflare 40.0" in t_filt and "hetzner не качается" in t_filt and "[попыток 3]" in t_filt
      and "фильтра по имени не видно; неровно: rutracker.org с именем 2 из 3" in t_once,
      "ZL39 профиль: «режут по имени» — только если с именем ни разу из трёх, с нейтральным отвечает; один промах — "
      "«неровно», не фильтр; один замер — не вывод; старый формат — «не определить»")
check(pv(PF_DEAD) == "unknown" and blockwatch.profile_merge([prun("silent", "answer", 10.0), prun("silent", "answer", 30.0),
                                                              prun("silent", "answer", 20.0)])["loads"][0]["mbit"] == 20.0,
      "ZL39а ничего не ответило — «не определить»; скорость — медиана попыток")
st_pf = {"profiles": {"ts": 1000, "by": {"Офис": PF_FILT, "Москва": PF_ONCE}}}
check("ℹ️ за фильтром точки: Офис" in blockwatch.block_line(st_pf, 1100)
      and blockwatch.profiles_line({"profiles": {"ts": 1, "by": {"Москва": PF_ONCE, "Офис": PF_DEAD}}}) == "точки без фильтра по имени (1)"
      and blockwatch.profiles_line({"profiles": {"ts": 1, "by": {"Офис": PF_DEAD}}}) is None,
      "ZL40 в отчёте — какие точки за фильтром; если никто — так и сказано")
okk3 = pt()
dpf = dict(dd(okk3, {"Офис": okk3, "Москва": okk3}, True), series={}, sni={}, filtered=["Офис"])
check("из них за фильтром: 1" in v(dpf, "DOWN"),
      "ZL41 в разборе сбоя рядом с «отвечает со всех точек» — сколько из них за фильтром")
# ZL47. Список профиля у rf1 и у агентов один и тот же
check(blockwatch.PROFILE_LOCAL == vantage_agent.DEFAULT_PROFILE,
      "ZL47 список профиля rf1 (blockwatch.PROFILE_LOCAL) совпадает со списком агентов (DEFAULT_PROFILE)")
# ZL48. Сбор профиля: попытки, rf1 сам, точка без ответа и упавшая проверка не срывают сбор
calls = []
real_ag = blockwatch.agent_get


def fake_ag(a, path, timeout=20):
    calls.append((a["name"], path))
    return None if a["name"] == "Молчит" else prun("silent", "answer")


blockwatch.agent_get = fake_ag
n_local = []


def bad_local():
    n_local.append(1)
    if len(n_local) == 2:
        raise RuntimeError("сбой")
    return prun("answer", "answer")


by48 = blockwatch.profile_fetch([{"name": "Офис"}, {"name": "Молчит"}], tries=3, gap=0, local=bad_local)
blockwatch.agent_get = real_ag
check(sorted(by48) == ["rf1", "Офис"] and by48["Офис"]["tries"] == 3 and by48["rf1"]["tries"] == 2
      and pv(by48["Офис"]) == "filtered" and pv(by48["rf1"]) == "clear"
      and calls.count(("Офис", "/profile")) == 3 and len(n_local) == 3,
      "ZL48 сбор профиля: три попытки на каждую точку и сам rf1; молчащая точка пропускается, сбой одной попытки — не помеха")

# агент: /profile по своему списку (произвольную цель не принимает)
real_profile_run = netprobe.profile_run
netprobe.profile_run = lambda sites, loads, neutral=netprobe.NEUTRAL_SNI: {"sites": [["got", len(sites)]], "loads": [["got", len(loads)]]}
agent3 = vantage_agent.Agent(("127.0.0.1", 0), dict(agent_cfg, profile={"sites": [["blocked", "x.test"]], "loads": [["cf", "u", None]]}))
import threading as _th
_th.Thread(target=agent3.serve_forever, daemon=True).start()
A3 = {"name": "П", "url": f"http://127.0.0.1:{agent3.server_address[1]}", "token": TOKEN}
r = blockwatch.agent_get(A3, "/profile", 10)
bad = blockwatch.agent_get(dict(A3, token="z" * 40), "/profile", 10)
agent3.shutdown()
netprobe.profile_run = real_profile_run
check(r == {"sites": [["got", 1]], "loads": [["got", 1]]} and bad is None,
      "ZL42 агент отдаёт профиль по своему списку из настроек и только с верным токеном")

# ZL43–ZL45. Гео-паспорт нод (v10.1: всё виденное — не новое; новое — после подтверждения)
G1 = {"🇫🇮 FI": {"flag": "FI", "row": {"ipinfo": "FI", "geojs": "US"}, "org": "VPSPay", "cf": "FI", "yt": "FI"},
      "🇩🇪 DE": {"flag": "DE", "row": {"ipinfo": "DE", "ip-api": "DE"}, "org": "Hoster", "cf": "DE", "yt": "DE"}}
G_FLAP = {"🇫🇮 FI": dict(G1["🇫🇮 FI"], yt="NL"), "🇩🇪 DE": G1["🇩🇪 DE"]}
st_g = {}
m0 = blockwatch.geo_step(st_g, G1, live=False) + blockwatch.geo_step(st_g, G_FLAP, live=False)
check(m0 == [] and st_g["geo"]["by"] == G_FLAP and st_g["geo"]["seen"]["🇫🇮 FI"]["youtube"] == ["FI", "NL"],
      "ZL43 пробный режим — молча копим всё, что показывали источники (YouTube то FI, то NL — оба исходные)")
G2 = {"🇫🇮 FI": dict(G1["🇫🇮 FI"], yt="RU"), "🇩🇪 DE": dict(G1["🇩🇪 DE"], row={"ipinfo": "RU", "ip-api": "DE"}, org="OtherOrg")}
m1 = blockwatch.geo_step(st_g, G2, live=True)
m1b = blockwatch.geo_step(st_g, G2, live=True)
m1c = blockwatch.geo_step(st_g, G_FLAP, live=True) + blockwatch.geo_step(st_g, G2, live=True)
check(m1 == [] and any("Нода 🇫🇮 FI: Россия в гео" in x and "youtube" in x for x in m1b)
      and any("Нода 🇩🇪 DE: Россия в гео" in x and "ipinfo" in x for x in m1b)
      and any("сменился владелец сети" in x and "было Hoster, стало OtherOrg" in x for x in m1b) and m1c == [],
      "ZL44 новое (Россия у источника, другой владелец сети) — сообщение только когда подтвердил следующий сбор; "
      "уже виденное снова — без повторов")
G3 = {"🇩🇪 DE": dict(G1["🇩🇪 DE"], row={"ipinfo": "NL", "ip-api": "DE"})}
st_g2 = {}
blockwatch.geo_step(st_g2, {"🇩🇪 DE": G1["🇩🇪 DE"]}, live=False)
m2 = blockwatch.geo_step(st_g2, G3, live=True)
m2b = blockwatch.geo_step(st_g2, {"🇩🇪 DE": G1["🇩🇪 DE"]}, live=True) + blockwatch.geo_step(st_g2, G3, live=True)
m2c = blockwatch.geo_step(st_g2, G3, live=True)
check(m2 == [] and m2b == [] and any("сменилась страна в гео" in x and "ipinfo: DE→NL" in x for x in m2c),
      "ZL45 страна сменилась — после подтверждения; мелькнула один раз и вернулась — молчим")
m2d = blockwatch.geo_step(st_g2, {"🇩🇪 DE": {"flag": "DE", "row": {}, "org": None, "cf": None, "yt": None}}, live=True)
check(m2d == [] and st_g2["geo"]["pend"]["🇩🇪 DE"] == {},
      "ZL45б канал не ответил (пусто) — ничего не меняем и не сообщаем")
wk = "\n".join(blockwatch.geo_week({"geo": {"by": G1}}))
check("Гео адресов нод" in wk and "базы FI/US" in wk and "YT FI" in wk and "⚠️" in wk and "• 🇩🇪 DE (флаг DE): базы DE, CF DE, YT DE\n" in wk + "\n",
      "ZL45а в недельной сводке — таблица гео с пометкой расхождений")
# ZL49. Строка гео: плитка без флага выхода (ретранслятор, без эмодзи) — сверяем источники между собой
l_ok = blockwatch.geo_line("Резерв", {"flag": None, "row": {"ipinfo": "NL"}, "org": None, "cf": "NL", "yt": None})
l_odd = blockwatch.geo_line("Резерв", {"flag": None, "row": {"ipinfo": "NL"}, "org": None, "cf": "NL", "yt": "RU"})
check("без флага выхода" in l_ok and "⚠️" not in l_ok and l_odd.endswith("⚠️"),
      "ZL49 плитка без флага выхода: согласные источники — без пометки, YouTube «Россия» — с пометкой")

real_curl = probe.curl
GEO_BODY = {probe.EXIT_URL: "203.0.113.9",
            "https://ipinfo.io/203.0.113.9/json": '{"country":"de","org":"AS1 Hoster"}',
            "http://ip-api.com/json/203.0.113.9?fields=countryCode,as": '{"countryCode":"DE","as":"AS1 Hoster"}',
            "https://ipwho.is/203.0.113.9": '{"country_code":"DE"}',
            "https://get.geojs.io/v1/ip/geo.json?ip=203.0.113.9": '[{"country_code":"DE","organization_name":"Hoster"}]',
            "https://api.country.is/203.0.113.9": '["not","a","dict"]',
            "https://www.cloudflare.com/cdn-cgi/trace": "ip=203.0.113.9\nloc=DE\ncolo=FRA\n"}


def geo_curl(port, url, timeout, fmt, body=False, ua=None, limit=None):
    if "youtube.com" in url:
        return ('window.ytcfg={"INNERTUBE_CONTEXT_GL":"DE"};', 0)
    return (GEO_BODY.get(url, ""), 0)


probe.curl = geo_curl
name, g = probe.geo_one({"name": "🇩🇪 DE", "port": 21001})
name_r, g_r = probe.geo_one({"name": "🇷🇺 Резерв · вход через РФ", "port": 21008, "expected_exit": "203.0.113.9"})
probe.curl = real_curl
check(g_r["flag"] is None and g_r["row"]["ipinfo"] == "DE",
      "ZL50 у ретранслятора (задан ожидаемый выход) флаг плитки — страна входа: с выходом не сравниваем")
check(name == "🇩🇪 DE" and g["flag"] == "DE" and {k: g["row"][k] for k in ("ipinfo", "ip-api", "ipwho", "geojs")} == {"ipinfo": "DE", "ip-api": "DE", "ipwho": "DE", "geojs": "DE"} and g["row"]["country.is"] is None
      and g["org"] == "AS1 Hoster" and g["cf"] == "DE" and g["yt"] == "DE",
      "ZL46 geo_one разбирает объект и массив (geojs), владельца сети, Cloudflare и YouTube; мусорный ответ пропускает")

# ZL52–ZL59. Путь до ноды с точек, «закрыто ли имя», метка на приветствии TLS (v10, часть D)
import socket as _so
import sys as _sys
SEQ = {1: ("hop", "10.0.0.1", 1), 2: ("silent", None, None), 3: ("hop", "10.0.0.3", 5)}
p_lost = netprobe.path_trace("127.0.0.1", 443, hop=lambda a, pt_, t, to: SEQ.get(t, ("silent", None, None)))
p_ok = netprobe.path_trace("127.0.0.1", 443, hop=lambda a, pt_, t, to: ("hop", "10.0.0.1", 1) if t == 1 else ("dest", a, 9))
p_rej = netprobe.path_trace("127.0.0.1", 443, hop=lambda a, pt_, t, to: ("hop", "10.0.0.1", 1) if t == 1 else ("reject13", "10.0.0.2", 3))
p_none = netprobe.path_trace("127.0.0.1", 443, max_ttl=5, hop=lambda a, pt_, t, to: ("silent", None, None))
ptx = blockwatch.path_text
check(p_lost["reached"] is False and p_lost["last"] == [3, "10.0.0.3"] and p_lost["hops"] == 6
      and ptx(p_lost) == "пропадает после шага 3 (10.0.0.3)"
      and p_ok["reached"] and p_ok["hops"] == 2 and ptx(p_ok) == "доходит до ноды (2 шагов)"
      and p_rej["hops"] == 2 and ptx(p_rej) == "узел шага 2 (10.0.0.2) ответил отказом — путь закрыт на нём"
      and p_none["hops"] == 5 and p_none["last"] is None and ptx(p_none) == "не ответил ни один шаг"
      and ptx({"addr": None, "dns": "fail"}) is None and ptx(None) is None,
      "ZL52 путь: дошёл / пропадает после последнего ответившего узла (три шага тишины — стоп) / узел ответил отказом / "
      "никто не ответил")
ls52 = _so.socket()
ls52.bind(("127.0.0.1", 0))
ls52.listen(4)
p_real = netprobe.path_trace("127.0.0.1", ls52.getsockname()[1], max_ttl=4)
ls52.close()
check(p_real is None if not _sys.platform.startswith("linux") else (p_real["reached"] and p_real["hops"] == 1),
      "ZL53 путь по-настоящему (Linux, без особых прав): до своего порта — с первого шага; не Linux — не меряем")
real_th = netprobe.tls_hello
netprobe.tls_hello = lambda addr, port, name, timeout=5, mss=None: "answer" if name == "localhost" else "silent"
r_cut = real_name_ref("de7.example.net", tries=2, ref="localhost")
netprobe.tls_hello = lambda addr, port, name, timeout=5, mss=None: "answer"
r_free = real_name_ref("de7.example.net", tries=2, ref="localhost")
netprobe.tls_hello = real_th
nn = blockwatch.name_note
check(r_cut == {"ref": "127.0.0.1", "n": 2, "name_ok": 0, "neutral_ok": 2, "fails": {"silent": 2}}
      and blockwatch.name_cut(r_cut) and not blockwatch.name_cut(r_free) and r_free["name_ok"] == 2
      and "новый адрес не поможет" in nn({"refs": {"rf1": r_cut, "Офис": r_cut}})
      and "поможет новый адрес" in nn({"refs": {"rf1": r_free}}) and nn({"refs": {"rf1": r_cut, "Офис": r_free}}) is None
      and nn({}) is None,
      "ZL54 «закрыто ли имя»: на чужом сервере с нашим именем молчит, с нейтральным отвечает — имя в фильтре; "
      "проходит — закрыт только адрес; точки расходятся — вывода нет")
c55 = netprobe.sni_compare("localhost", p_page, mss=1231)
check(c55["mss"] == (1231 if MARK else None) and c55["t1"] >= c55["t0"] and c55["real"] == "answer"
      and netprobe.sni_compare("localhost", p_page, mss=99)["mss"] is None,
      "ZL55 сравнение имён: приветствие с настоящим именем идёт с меткой (где система умеет), время записано")
real_pt, real_nr, real_sc = netprobe.path_trace, netprobe.name_ref, netprobe.sni_compare
netprobe.path_trace = lambda host, port=443, **kw: {"asked": [host, port]}
netprobe.name_ref = lambda name, tries=2, ref=None: {"asked": name}
netprobe.sni_compare = lambda host, port=443, sni=None, mss=None: {"addr": "1", "mss": mss}
agent4 = vantage_agent.Agent(("127.0.0.1", 0), agent_cfg)
_th.Thread(target=agent4.serve_forever, daemon=True).start()
A4 = {"name": "П4", "url": f"http://127.0.0.1:{agent4.server_address[1]}", "token": TOKEN}
g4 = lambda path: blockwatch.agent_get(A4, path, 10)
r56 = (g4(f"/path?host=localhost&port={p_page}"), g4(f"/sniref?host=localhost&port={p_page}"),
       g4(f"/sni?host=localhost&port={p_page}&mss=1233"), g4(f"/sni?host=localhost&port={p_page}&mss=9999"),
       g4(f"/path?host=evil.example&port={p_page}"), g4("/path?host=localhost&port=22"), g4("/health")["v"])
agent4.shutdown()
netprobe.path_trace, netprobe.name_ref, netprobe.sni_compare = real_pt, real_nr, real_sc
check(r56 == ({"asked": ["localhost", p_page]}, {"asked": "localhost"}, {"addr": "1", "mss": 1233}, {"addr": "1", "mss": 1260},
              None, None, 5),
      "ZL56 агент 4: путь и «закрыто ли имя» — только до разрешённого имени и порта; метка сравнения имён — в пределах")
d57 = dict(dd(pt("timeout"), {"Офис": pt("timeout")}, True), series={}, sni={}, paths={"Офис": p_lost},
           refs={"rf1": r_cut, "Офис": r_cut}, witness={"Офис|tls": {"seen": 1, "rep": 0, "rst_out": 0, "rst_in": 0},
                                                       "rf1|tls": {"seen": 1, "rep": 0, "rst_out": 1, "rst_in": 0}})
live57 = blockwatch.DEEP_EXTRA_LIVE
blockwatch.DEEP_EXTRA_LIVE = False
plain, full = blockwatch.deep_lines(d57), blockwatch.deep_lines(d57, extra=True)
txt_shadow = blockwatch.deep_text(d57, "DOWN")
blockwatch.DEEP_EXTRA_LIVE = True
txt_live = blockwatch.deep_text(d57, "DOWN")
blockwatch.DEEP_EXTRA_LIVE = live57
check(not any("путь от" in x for x in plain) and "• путь от Офис: пропадает после шага 3 (10.0.0.3)" in full
      and any("имя ноды на чужом сервере (rf1, Офис): с нашим именем ответа нет" in x for x in full)
      and "• сброс TLS (Офис): нода сброса не отправляла — соединение оборвали по дороге" in full
      and "• сброс TLS (rf1): его отправила сама нода" in full
      and "новый адрес не поможет" not in txt_shadow and "путь от" not in txt_shadow
      and "новый адрес не поможет" in txt_live and "путь от Офис" in txt_live
      and "блокировку адреса ноды из России" in v(d57, "DOWN"),
      "ZL57 пробный режим: путь, имя и сброс TLS — в журнале (extra), в сообщении нет; включили — есть; "
      "сверка TLS не путается со сверкой серий в выводе")
c58 = {"addr": "1", "real": "reset", "neutral": "answer", "none": "answer", "mss": 1233, "t0": 1000.0, "t1": 1002.0}
t58 = blockwatch.tls_ser(c58)
check(t58 == {"mss": 1233, "t0": 1000.0, "t1": 1002.0, "n": 1, "ok": 1, "fail": 1}
      and blockwatch.witness_match({"ts": 1100, "flows": [[1001, 1233, 1, 1, 0, 0], [1001, 1203, 1, 1, 0, 0]]}, t58)
      == {"seen": 1, "rep": 0, "rst_out": 0, "rst_in": 0}
      and blockwatch.tls_ser(dict(c58, real="answer")) is None and blockwatch.tls_ser(dict(c58, mss=None)) is None
      and blockwatch.tls_mss(0) == 1231 and blockwatch.tls_mss(1) == 1233,
      "ZL58 сброшенное приветствие TLS с меткой сверяется со свидетелем как серия из одного соединения")
# ZL59. Разбор целиком: путь и имя спрашиваются у точки с закрытым входом; сброс TLS сверяется по метке
json.dump([{"name": "pl1", "host": "pl1.example.net", "beacon": "https://pl1.example.net/st-zz.json"}],
          open(os.path.join(tmp, "nodes.json"), "w", encoding="utf-8"))
keep59 = (netprobe.direct_probe, blockwatch.agent_get, netprobe.series, netprobe.sni_compare, nw.socks_open,
          netprobe.tcp_trace, netprobe.name_ref, blockwatch.fetch_witness)
t59 = clock["t"]
netprobe.direct_probe = lambda host, port=443, sni=None, **kw: dict(pt("timeout"), addr="9.9.9.9")
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: ser(n, n=n, ok=0, mss=mss, t0=t59 - 30, t1=t59 - 20)
netprobe.sni_compare = lambda host, port=443, sni=None, mss=None: {"addr": "9.9.9.9", "real": "reset", "neutral": "answer",
                                                                   "none": "answer", "mss": mss, "t0": t59 - 30, "t1": t59 - 20}
netprobe.tcp_trace = lambda addr, port=443, max_hops=16: None
netprobe.name_ref = lambda name, tries=2, ref=None: r_cut
nw.socks_open = lambda via, host, port, timeout=5, tls=False: True
blockwatch.agent_get = lambda a, path, timeout=20: (
    pt("timeout") if path.startswith("/probe") else ser(6, n=6, ok=0, mss=1203, t0=t59 - 30, t1=t59 - 20)
    if path.startswith("/series") else p_lost if path.startswith("/path") else r_cut if path.startswith("/sniref")
    else {"addr": "9.9.9.9", "real": "reset", "neutral": "answer", "none": "answer", "mss": 1233, "t0": t59 - 30, "t1": t59 - 20}
    if path.startswith("/sni?") else None)
blockwatch.fetch_witness = lambda url, socks_port=None: {
    "ts": t59, "flows": [[t59 - 25, 1231, 1, 1, 1, 0], [t59 - 25, 1233, 1, 1, 0, 0]]}
d59 = blockwatch.deep_diag(CHANS[0], {"name": "NL1", "port": 21003}, [{"name": "Москва", "url": "u", "token": "t"}], probe.DOMAINS)
(netprobe.direct_probe, blockwatch.agent_get, netprobe.series, netprobe.sni_compare, nw.socks_open,
 netprobe.tcp_trace, netprobe.name_ref, blockwatch.fetch_witness) = keep59
os.remove(os.path.join(tmp, "nodes.json"))
f59 = blockwatch.deep_lines(d59, extra=True)
check(d59["paths"] == {"Москва": p_lost} and set(d59["refs"]) == {"rf1", "Москва"}
      and d59["witness"]["Москва|tls"]["rst_out"] == 0 and d59["witness"]["rf1|tls"]["rst_out"] == 1
      and "• путь от Москва: пропадает после шага 3 (10.0.0.3)" in f59
      and "• сброс TLS (Москва): нода сброса не отправляла — соединение оборвали по дороге" in f59
      and "новый адрес не поможет" in blockwatch.name_note(d59),
      "ZL59 разбор целиком: у точки с закрытым входом — путь и имя на чужом сервере; сброс TLS сверен по метке с нодой")

# ZL60–ZL64. VPN-точка: проверка плиток через свой клиент Xray на офисной машине (v10, часть E)
class FakeRun:
    def __init__(self, out, rc=0):
        self.stdout, self.returncode = out, rc


real_sub = netprobe.subprocess
calls60 = []


class FakeSub:
    TimeoutExpired = real_sub.TimeoutExpired

    @staticmethod
    def run(cmd, **kw):
        calls60.append(cmd)
        return FakeRun("200 524288 1000000.0 0.52 0.11") if "21003" in " ".join(cmd) else FakeRun("000 0 0.000 25.0 0.0", 28)


netprobe.subprocess = FakeSub
ok60, bad60 = netprobe.socks_load(21003), netprobe.socks_load(21004)
netprobe.subprocess = real_sub
check(ok60 == {"ok": True, "code": "200", "bytes": 524288, "mbit": 8.0, "s": 0.52, "ttfb_ms": 110, "rc": 0}
      and bad60["ok"] is False and bad60["bytes"] == 0 and "socks5h://127.0.0.1:21003" in calls60[0],
      "ZL60 загрузка 512 КБ через SOCKS своего Xray: пришло всё — работает; ничего — не работает")
vfile = os.path.join(tmp, "vpn-channels.json")
json.dump({"channels": [{"name": "🇳🇱NL 3", "port": 21003}, {"name": "Poland", "port": 21004}]}, open(vfile, "w", encoding="utf-8"))
real_vc, real_sl = vantage_agent.VPN_CHANNELS, netprobe.socks_load
vantage_agent.VPN_CHANNELS = vfile
netprobe.socks_load = lambda port, *a, **kw: {"ok": port == 21003, "bytes": 524288 if port == 21003 else 0, "port": port}
agent5 = vantage_agent.Agent(("127.0.0.1", 0), dict(agent_cfg, vpn=True))
agent6 = vantage_agent.Agent(("127.0.0.1", 0), agent_cfg)
for a_ in (agent5, agent6):
    _th.Thread(target=a_.serve_forever, daemon=True).start()
A5 = {"name": "Офис", "url": f"http://127.0.0.1:{agent5.server_address[1]}", "token": TOKEN, "vpn": True}
A6 = {"name": "Москва", "url": f"http://127.0.0.1:{agent6.server_address[1]}", "token": TOKEN}
import urllib.parse as _up
r61 = (blockwatch.agent_get(A5, "/vpn"), blockwatch.agent_get(A5, "/vpn?name=" + _up.quote("🇳🇱NL 3")),
       blockwatch.agent_get(A5, "/vpn?name=evil"), blockwatch.agent_get(A6, "/vpn?name=Poland"),
       blockwatch.agent_get(A5, "/health")["vpn"], blockwatch.agent_get(A6, "/health")["vpn"])
sweep = blockwatch.vpn_sweep([A5, A6], ["🇳🇱NL 3", "Poland", "нет такой"])
agent5.shutdown()
agent6.shutdown()
check(r61 == ({"names": ["🇳🇱NL 3", "Poland"]}, {"ok": True, "bytes": 524288, "port": 21003, "name": "🇳🇱NL 3"}, None, None, True, False),
      "ZL61 агент VPN-точки: только плитки своего списка (чужое имя — отказ); точка без своего Xray на /vpn не отвечает")
check(set(sweep) == {"Офис"} and sweep["Офис"]["Poland"]["ok"] is False and sweep["Офис"]["нет такой"] is None,
      "ZL62 обход: все плитки через каждую VPN-точку; остальные точки не спрашиваются")
vantage_agent.VPN_CHANNELS, netprobe.socks_load = real_vc, real_sl
vt = blockwatch.vpn_text
check(vt({"ok": True, "bytes": 524288, "s": 0.52, "mbit": 8.0}) == "работает (512 КБ за 0.52 с, 8.0 Мбит/с)"
      and vt({"ok": False, "bytes": 20480, "code": "200"}) == "не работает: пришло 20 КБ из 512"
      and vt({"ok": False, "bytes": 0, "code": "000"}) == "не работает" and vt(None) == "точка не ответила"
      and blockwatch.vpn_line({"vpn_pt": {"ts": 1, "by": {"Офис": {"🇳🇱NL 3": {"ok": True}, "🇵🇱 Poland": {"ok": False}, "x": None}}}})
      == "через VPN с точки Офис: работают 1 из 2 (не работают: 🇵🇱 Poland)"
      and blockwatch.vpn_line({}) is None,
      "ZL63 строки VPN-точки: работает / не работает / сколько плиток работает в отчёте")
d64 = dict(dd(pt("timeout"), {}, True), series={}, sni={}, vpn={"Офис": {"ok": True, "bytes": 524288, "s": 0.6, "mbit": 7.0}})
live64 = blockwatch.DEEP_EXTRA_LIVE
blockwatch.DEEP_EXTRA_LIVE = False
shadow64 = blockwatch.deep_lines(d64)
blockwatch.DEEP_EXTRA_LIVE = live64
check("• через VPN с точки Офис: работает (512 КБ за 0.6 с, 7.0 Мбит/с)" in blockwatch.deep_lines(d64, extra=True)
      and not any("через VPN" in x for x in shadow64),
      "ZL64 разбор сбоя: что видит VPN-точка через эту плитку — в журнале (пробный режим), в сообщении пока нет")
# основной проход забирает обход из файла службы --side
fresh()
blockwatch.SIDE_FILE = os.path.join(tmp, "side.json")
t64 = clock["t"] + 1
json.dump({"vpn": {"ts": t64, "by": {"Офис": {CHANS[0]["name"]: {"ok": False, "bytes": 0}}}}},
          open(blockwatch.SIDE_FILE, "w", encoding="utf-8"))
a64 = step()
check(a64 == [] and "через VPN с точки Офис: работают 0 из 1" in report() and load()["vpn_pt"]["ts"] == t64,
      "ZL64а обход VPN-точки приходит из файла службы: строка в отчёте, тревог нет (пробный режим)")
os.remove(blockwatch.SIDE_FILE)

# ZL65–ZL68. Заглушка ноды глазами постороннего (статья vpn-hub: 301 на порту 80, TLS 1.2/1.3, HSTS, свой сертификат)
GOOD = {"r301": True, "tls12": True, "tls13": True, "hsts": True, "cert": True}
was65 = {"open": [443], "site": ["200", "Сайт"], "face": GOOD}
cur65 = {"open": [443], "site": ["200", "Сайт"], "face": dict(GOOD, hsts=False, cert=False)}
ch65 = nw.outside_changes("de7", was65, cur65)
first65 = nw.outside_changes("de7", {"open": [443], "site": ["200", "Сайт"]}, cur65)
check(ch65 == ["у заглушки пропал HSTS", "на адресе ноды чужой или недействительный сертификат"] and first65 == []
      and nw.outside_changes("de7", cur65, was65) == [],
      "ZL65 заглушка: тревога только о том, что было и пропало; первый взгляд и улучшение — без тревоги")
line_bad = nw.outside_line({"de7": cur65, "nl2": was65}, 11)
line_ok = nw.outside_line({"de7": was65, "nl2": was65, "srv1": {"open": [443], "site": None}}, 11)
check("de7 — заглушка: нет HSTS, нет свой сертификат" in line_bad and "nl2" not in line_bad
      and "у заглушек 301, TLS 1.2 и 1.3, HSTS, свой сертификат (2)" in line_ok
      and nw.face_missing(dict(GOOD, r301=False)) == "нет редиректа 301 на порту 80" and nw.face_missing(None) == "",
      "ZL66 в отчёте — у каких нод заглушке чего не хватает; всё в порядке — так и сказано")


class FakeRun65:
    def __init__(self, out):
        self.stdout = out


calls66 = []


def fake_run66(cmd, **kw):
    calls66.append(cmd)
    if "-I" in cmd:
        return FakeRun65("HTTP/2 200\r\nstrict-transport-security: max-age=31536000\r\ncontent-type: text/html\r\n")
    return FakeRun65(world66["http"])


real_run66, real_tf66 = nw.subprocess.run, nw.tls_face
nw.subprocess.run = fake_run66
nw.tls_face = lambda port, host, ver, timeout=8: (True, True) if ver == nw.ssl.TLSVersion.TLSv1_3 else (True, False)
world66 = {"http": "301 https://de7.example/"}
f1 = nw.site_face(21001, "de7.example")
world66["http"] = "308 https://de7.example/"
f2 = nw.site_face(21001, "de7.example")
world66["http"] = "200 "
f3 = nw.site_face(21001, "de7.example")
nw.tls_face = lambda port, host, ver, timeout=8: (None, None)
world66["http"] = "000 "
nw.subprocess.run = lambda cmd, **kw: FakeRun65("")
f4 = nw.site_face(21001, "de7.example")
nw.subprocess.run, nw.tls_face = real_run66, real_tf66
check(f1 == GOOD and f2["r301"] is False and f3["r301"] is False and f4 is None
      and any("socks5h://127.0.0.1:21001" in " ".join(c) for c in calls66),
      "ZL67 разбор заглушки: 301 на https — да, 308 и 200 — нет; HSTS по заголовку; сертификат годен хоть в одной версии; "
      "канал не ответил ничем — нет данных (не «всё пропало»)")
# ZL68. tls_face: настоящий TLS-сервер с самоподписанным сертификатом — версия есть, сертификат «чужой»
import ssl as _ssl
import socket as _sock
real_sc68 = nw.socks_connect
try:
    import subprocess as _sp
    _tmpd = tempfile.mkdtemp()
    _sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=other.example",
             "-keyout", os.path.join(_tmpd, "k.pem"), "-out", os.path.join(_tmpd, "c.pem")], capture_output=True, timeout=60)
    _ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    _ctx.load_cert_chain(os.path.join(_tmpd, "c.pem"), os.path.join(_tmpd, "k.pem"))
    _ls = _sock.socket()
    _ls.bind(("127.0.0.1", 0))
    _ls.listen(4)

    def _serve():
        for _ in range(2):
            c, _a = _ls.accept()
            try:
                _ctx.wrap_socket(c, server_side=True).close()
            except (OSError, _ssl.SSLError):
                c.close()

    _th.Thread(target=_serve, daemon=True).start()
    nw.socks_connect = lambda port, host, p, timeout: _sock.create_connection(("127.0.0.1", _ls.getsockname()[1]), timeout=timeout)
    r68 = (nw.tls_face(1, "de7.example", _ssl.TLSVersion.TLSv1_3), nw.tls_face(1, "de7.example", _ssl.TLSVersion.TLSv1_2))
    nw.socks_connect = lambda port, host, p, timeout: (_ for _ in ()).throw(ConnectionRefusedError())
    r68b = nw.tls_face(1, "de7.example", _ssl.TLSVersion.TLSv1_3)
    ok68 = r68 == ((True, False), (True, False)) and r68b == (None, None)
except FileNotFoundError:
    ok68 = True  # нет openssl на этом компьютере — пропускаем
finally:
    nw.socks_connect = real_sc68
check(ok68, "ZL68 tls_face: сервер отвечает версией, но сертификат не на это имя — «чужой сертификат»; канал не соединил — нет данных")

# ZL69–ZL72. Тревоги VPN-точки (v10, часть H)
check(blockwatch.DEEP_EXTRA_LIVE is True and probe.GEO_SHADOW == 86400,
      "ZL69 после пробной ночи: строки разбора идут в сообщения, гео — пробный режим только первые сутки")
OKR, BAD = {"ok": True, "bytes": 524288, "s": 0.5, "mbit": 8.0}, {"ok": False, "bytes": 0, "code": "000"}
T3 = ["DE1", "NL1", "Poland", "DE7"]


def sweep(**bad):
    return {"Офис": {t: (bad[t] if t in bad else OKR) for t in T3}}


st69, ok_all = {}, {t: True for t in T3}
m1 = blockwatch.vpn_step(st69, sweep(Poland=BAD), ok_all)
m2 = blockwatch.vpn_step(st69, sweep(Poland=BAD), ok_all)
m3 = blockwatch.vpn_step(st69, sweep(Poland=BAD), ok_all)
m4 = blockwatch.vpn_step(st69, sweep(), ok_all)
check(m1 == [] and len(m2) == 1 and "Через VPN с точки Офис не работает: Poland" in m2[0] and "с rf1 плитка работает" in m2[0]
      and m3 == [] and len(m4) == 1 and "снова работает: Poland" in m4[0],
      "ZL70 плитка не работает через VPN-точку два обхода подряд, а с rf1 работает — одно сообщение; вернулась — «снова работает»")
st70 = {}
alt = [blockwatch.vpn_step(st70, sweep(**({"DE7": BAD} if i % 2 else {"Poland": BAD})), ok_all) for i in range(6)]
st70b = {}
both = [blockwatch.vpn_step(st70b, sweep(Poland=BAD), dict(ok_all, Poland=False)) for _ in range(3)]
check(all(m == [] for m in alt) and all(m == [] for m in both),
      "ZL71 разовые сбои разных плиток (как в пробную ночь) — тишина; не работает и с rf1 — пишет основной сторож, не VPN-точка")
st71 = {}
dead = {"Офис": {t: None for t in T3}}
p1 = blockwatch.vpn_step(st71, dead, ok_all)
p2 = blockwatch.vpn_step(st71, sweep(DE1=BAD, NL1=BAD, Poland=BAD), ok_all)
p3 = blockwatch.vpn_step(st71, dead, ok_all)
p4 = blockwatch.vpn_step(st71, sweep(), ok_all)
check(p1 == [] and len(p2) == 1 and "VPN-точка Офис не проверяет плитки" in p2[0] and "прошло 1 из 4" in p2[0] and p3 == []
      and len(p4) == 1 and "снова проверяет плитки" in p4[0] and st71["vpn_alert"]["Офис"]["tiles"].get("Poland", {}).get("n", 0) == 0,
      "ZL72 у самой VPN-точки беда (прошло меньше половины) — плитки не судим, о точке одно сообщение после двух обходов; наладилась — сообщение")

import io
# ZL73–ZL74. «Взгляд снаружи» (v11.1)
src_nw = io.open(os.path.join(os.path.dirname(os.path.abspath(nw.__file__)), "nodewatch.py"), encoding="utf-8").read()
check(nw.TLS_CLOSED == (2222, 4443, 8443, 10443, 2053, 9108) and "socks_open, via, node[\"host\"], port, 5, port in TLS_CLOSED" in src_nw,
      "ZL73 закрытые порты, кроме SSH, «снаружи» проверяются и приветствием TLS (порт ноды 2222 молчит на простое подключение)")
n74 = len(view_calls)
out74 = step(6 * 60) + step()
check(len(view_calls) == n74,
      "ZL74 основной проход «снаружи» сам не смотрит (раньше 16.10 он из-за этого не укладывался в 110 с) — это делает служба --side")

print("\n--- пример сводки за неделю ---\n" + weekly_sample)
print("\n--- пример отчёта ---\n" + summ[0])
print("\n--- отчёт, когда подписка не загрузилась ---\n" + text)
print("\nвсе проверки пройдены")
