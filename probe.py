#!/usr/bin/env python3
"""channel-watch: проверка каналов VPN изнутри РФ (запуск по таймеру раз в 2 минуты).

Через каждый канал (SOCKS-порт локального клиента Xray, см. build_channels.py):
  - каждый запуск: короткий запрос generate_204 — «жив / не жив» (две попытки), заодно задержка
    и время установки соединения;
  - раз в DEEP_EVERY секунд, а также пока новое состояние канала не подтверждено: закачка DEEP_BYTES —
    скорость и «замирание» (типичный DPI: соединение есть, а данные встают), плюс IP выхода; если скорость
    меньше SLOW_MBIT и заметно ниже обычной для канала — перепроверка закачкой CONFIRM_BYTES: «медленно» — это
    меньше SLOW_MBIT уже на ней (на DEEP_BYTES скорость упирается в разгон соединения и настоящей не показывает);
  - раз в SERVICES_EVERY секунд: открываются ли через канал Telegram, YouTube, Instagram, ChatGPT.
Напрямую с rf1: ваши сайты (site.json: панель, кабинет …) — раз в DEEP_EVERY; страница подписки
(настоящая загрузка подписки сторожа) — раз в SUB_EVERY; пока сайт не отвечает — каждый запуск;
сроки сертификатов (сайты и ноды) и регистрации доменов — раз в SLOW_EVERY.
Если канал не отвечает, сторож сам проверяет, что именно сломано (пинг, порт, TLS), и пишет вероятную причину;
если не отвечает сайт — смотрит, отвечает ли он через зарубежную ноду.
Блокировки (blockwatch.py, логика и источники — как у cheburcheck.ru):
  - когда канал подтверждённо лёг или его душат, вход канала проверяется напрямую с rf1, с других российских точек
    (агенты vantage_agent.py, список — vantage.json), из-за рубежа и трассировкой — в сообщении видно, блокировка
    это или поломка ноды;
  - раз в DNS_EVERY — не подменяет ли обычный DNS адреса наших сайтов и нод (сравнение с защищённым DNS);
  - раз в 6 часов (probe.py --lists, свой таймер) — нет ли наших адресов и доменов в реестре РКН и в подсетях,
    которые в России душат; о попадании в список — сразу.
Оповещения в Telegram:
  - смена состояния канала или сайта — после CONFIRM проверок подряд (и поломка, и возврат в норму, с длительностью сбоя);
  - напоминание раз в REMIND_EVERY, пока канал или сайт не работает;
  - сертификат или домен скоро истекает, истёк, продлён — сразу, как это стало видно;
  - у канала вырос пинг или время соединения против обычного для него (медиана за полчаса против медианы
    часовых значений за неделю) — сообщение о росте и о возврате;
  - полный отчёт в часы из SUMMARY_HOURS_UTC: каналы, сервисы, сайты, сертификаты, домены, подписка;
  - сводка за неделю — по понедельникам с первым отчётом дня: доступность, сбои, скорость и пинг по каналам,
    сбои сайтов, что изменилось. Берётся из почасовой истории (HISTORY), которая пишется раз в час.
Токен — из /etc/bridge-watch/guard.env.
Пульс для внешнего сторожа (guard.py на другом сервере): после каждого запуска — файл, путь к которому
записан в /etc/channel-watch/heartbeat.path; нет этого файла — пульс не пишется.
Вручную: probe.py --show — напечатать отчёт; probe.py --report — напечатать и отправить (статистика не сбрасывается);
probe.py --week — напечатать сводку за неделю; probe.py --week-report — напечатать и отправить;
probe.py --blocks — проверить блокировки сейчас (списки, DNS, вход каждой ноды со всех точек) и напечатать;
probe.py --blocks-report — то же и отправить; probe.py --lists — только сверка со списками (её запускает таймер).
"""
import concurrent.futures
import datetime as dt
import html
import http.client
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import blockwatch
import nodewatch

ETC = "/etc/channel-watch"
SPEED_FILE = "/var/lib/channel-watch/speed.json"  # замеры probe.py --speed (закачка побольше перед отчётом)
SITE_FILE = os.environ.get("CHANNEL_WATCH_SITE") or os.path.join(ETC, "site.json")  # сайты, домены, исключения (образец — site.example.json)


def _site_cfg():
    try:
        return json.load(open(SITE_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


SITE_CFG = _site_cfg()
# ноды, чей выход есть в ваших списках разрешённых адресов (SSH и т. п.) — «снаружи» через них не посмотришь
NO_VANTAGE = tuple(SITE_CFG.get("no_vantage", ()))
STATE = "/var/lib/channel-watch/state.json"
LOG = "/var/log/channel-watch.log"
TG_ENV = "/etc/bridge-watch/guard.env"
QUICK_URL = "https://www.gstatic.com/generate_204"
DEEP_BYTES = 512 * 1024
DEEP_URL = f"https://speed.cloudflare.com/__down?bytes={DEEP_BYTES}"
EXIT_URL = "https://api.ipify.org"
HEARTBEAT = os.path.join(ETC, "heartbeat.path")  # в файле — куда писать пульс для внешнего сторожа
DEEP_EVERY = 600          # секунд между плановыми закачками и проверками сайтов
SERVICES_EVERY = 1800     # секунд между проверками сервисов через канал
SUB_EVERY = 1800          # секунд между загрузками подписки сторожа (проверка страницы подписки)
SLOW_EVERY = 21600        # секунд между проверками сертификатов и доменов
PROFILE_EVERY = 21600     # секунд между сбором профиля точек (за фильтром или нет)
GEO_EVERY = 43200         # секунд между сборами гео-паспорта нод (новое подтверждается следующим сбором)
GEO_SHADOW = 86400        # первые сутки гео — пробный режим: журнал и таблица, тревог нет
FLAG_CC = {"🇩🇪": "DE", "🇳🇱": "NL", "🇵🇱": "PL", "🇪🇪": "EE", "🇫🇮": "FI", "🇷🇺": "RU", "🇪🇸": "ES", "🇬🇧": "GB", "🇺🇸": "US"}
GEO_DBS = (("ipinfo", "https://ipinfo.io/{ip}/json", "country", "org"),
           ("ip-api", "http://ip-api.com/json/{ip}?fields=countryCode,as", "countryCode", "as"),
           ("ipwho", "https://ipwho.is/{ip}", "country_code", None),
           ("geojs", "https://get.geojs.io/v1/ip/geo.json?ip={ip}", "country_code", "organization_name"),
           ("country.is", "https://api.country.is/{ip}", "country", None))
CONFIRM = 2               # сколько проверок подряд нужно, чтобы сменить состояние
FREEZE_BYTES = 64 * 1024  # получили меньше за всё время закачки — «замирание» (DPI)
SLOW_MBIT = 5             # порог «медленно», Мбит/с — судим по закачке побольше (CONFIRM_BYTES), а не по 512 КБ
SLOW_BPS = SLOW_MBIT * 1e6 / 8
SLOW_PART = 0.6           # закачкой побольше перепроверяем, только если быстрая дала ещё и меньше такой доли обычного
# на 512 КБ скорость упирается в разгон соединения: у исправных каналов там 5–12 Мбит/с при настоящих 20–140,
# поэтому «меньше 5 Мбит/с» на 512 КБ ничего не значит — нужна закачка, на которой соединение успевает разогнаться
CONFIRM_BYTES = 4 * 1024 * 1024
CONFIRM_URL = f"https://speed.cloudflare.com/__down?bytes={CONFIRM_BYTES}"
CONFIRM_BUDGET = 90       # секунд на перепроверки закачкой побольше за один запуск: они идут по очереди
REMIND_EVERY = 3600       # напоминать, пока канал не работает
STAGGER = 0.3             # секунд между стартами проверок соседних каналов
PERIOD_KEEP = 720         # сколько замеров задержки хранить на канал (сутки проверок)
CONN_WARN_MS = 700        # соединение через канал устанавливается дольше — пометить в отчёте
HISTORY = "/var/lib/channel-watch/history.json"  # почасовая история каналов и сайтов: «обычные» значения и сводка за неделю
HIST_KEEP = 15 * 24       # часовых записей на канал: неделя сводки, неделя для сравнения и запас
QUAL_WINDOW = 15          # о пинге и времени соединения судим по медиане стольких последних замеров (полчаса)
QUAL_MIN = 10             # замеров в окне меньше — не судим
BASE_HOURS = 7 * 24       # «обычно» — медиана часовых медиан за столько часов
BASE_MIN_HOURS = 6        # истории меньше — о росте не судим
LAT_GROW = (1.6, 40)      # пинг вырос: в столько раз и на столько мс больше обычного (нужно и то, и другое)
CONN_GROW = (1.6, 250)    # время соединения — так же
QUAL_UP_N = 3             # «вырос» — медиана выше порога столько проходов подряд (~6 мин)
QUAL_DOWN_SEC = 600       # «в норме» — медиана ниже середины между обычным и порогом не меньше стольких секунд
QUAL_FLAP_N = 3           # столько смен «вырос/в норме» за QUAL_FLAP_SEC — канал «скачет»: одно сообщение и тишина
QUAL_FLAP_SEC = 3600
QUAL_CALM_SEC = 3600      # «скачет» кончается, когда столько времени не было ни одной смены
WEEKLY_WEEKDAY = 0        # сводка за неделю — в понедельник (0), в первый час из SUMMARY_HOURS_UTC
WEEK = 7 * 86400
SUMMARY_HOURS_UTC = (6, 12, 18)  # часы полного отчёта по UTC = 09:00, 15:00 и 21:00 МСК
CERT_WARN_PART = 0.22     # сертификат продлевается, когда остаётся треть срока; осталось меньше 22% — продление не сработало
DOMAIN_WARN_DAYS = 30
SUB_STALE = 13 * 3600     # подписку загружает build_channels.py трижды в сутки; старше — «давно не проверялась»
MSK = dt.timezone(dt.timedelta(hours=3))
TG_FALLBACK_PROXY = "socks5h://127.0.0.1:10809"  # запасной путь к api.telegram.org (локальный клиент Xray через зарубежную ноду)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")

# сервис, адрес, коды ответа «открывается» (ChatGPT: 401 — пускает, 403 — адрес или регион закрыт)
SERVICES = (("Telegram", "https://api.telegram.org/", ("302", "200", "301")),
            ("YouTube", "https://www.youtube.com/generate_204", ("204", "200")),
            ("Instagram", "https://www.instagram.com/", ("200", "301", "302")),
            ("ChatGPT", "https://api.openai.com/v1/models", ("401", "200")))
SVC_MAX_BYTES = 32768     # ответ целиком не нужен (страница Instagram — 640 КБ), хватает кода ответа
# ваши сайты (site.json: "sites": [{"name", "url", "key", "impact"}]); страница подписки проверяется настоящей
# загрузкой подписки сторожа (check_sub): на несуществующую подписку она отвечает 502, «пустым» адресом её не проверить
SITES = tuple((x["name"], x["url"]) for x in SITE_CFG.get("sites", ())) or (
    ("панель", "https://panel.example.com/api/auth/status"),
    ("кабинет", "https://cab.example.com/"))
SUB_NAME = "подписка"
SUB_UA = "Happ/4.6.0/Linux/channel-watch"  # как у build_channels.py: такому клиенту панель отдаёт XRAY_JSON
SITE_ORDER = tuple(n for n, _ in SITES[:1]) + (SUB_NAME,) + tuple(n for n, _ in SITES[1:])  # порядок в отчёте
SITE_IMPACT = {
    "панель": "VPN у подключённых работает (ноды держат последние настройки), но подписки не обновляются, "
              "а бот и кабинет не могут выдавать и продлевать доступ.",
    SUB_NAME: "приложения не могут обновить список серверов, новые пользователи не могут добавить подписку. "
              "Уже настроенный VPN работает.",
    "кабинет": "кабинет не открывается; через этот же адрес бот получает уведомления об оплате.",
}
SITE_IMPACT.update({x["name"]: x["impact"] for x in SITE_CFG.get("sites", ()) if x.get("impact")})
# имена ваших сайтов (сертификаты, подмена DNS) и домены (срок регистрации, реестр)
SITE_HOSTS = tuple(SITE_CFG.get("site_hosts", ())) or ("panel.example.com", "sub.example.com", "cab.example.com")
DOMAINS = tuple(SITE_CFG.get("domains", ())) or ("example.com", "example.net")
NO_LINK = "не удалось проверить"
BAD_FORMAT = "формат"     # ответ 200, но пришла не подписка

ICONS = {"OK": "✅", "SLOW": "🐢", "FREEZE": "🧊", "DOWN": "🔴", "WRONG_EXIT": "🔀"}
LABELS = {"OK": "✅ работает", "SLOW": "🐢 медленно", "FREEZE": "🧊 душат (замирает)",
          "DOWN": "🔴 недоступен", "WRONG_EXIT": "🔀 не тот выход"}
WAS = {"DOWN": "Был недоступен", "SLOW": "Работал медленно", "FREEZE": "Его душили", "WRONG_EXIT": "Выход был не тот"}
STILL = {"DOWN": "недоступен", "SLOW": "медленно", "FREEZE": "душат", "WRONG_EXIT": "не тот выход"}
# статистика между отчётами — обнуляется после каждого отчёта
PERIOD = (("inc", 0), ("bad_sec", 0), ("checks", 0), ("fails", 0), ("spd_sum", 0.0), ("spd_n", 0),
          ("spd_min", 0.0), ("svc_n", 0))
PERIOD_LISTS = ("lat", "conn")  # замеры задержки и времени соединения за период, мс — в отчёте их медианы
DEFAULTS = (("status", "OK"), ("cand", "OK"), ("streak", 0), ("detail", ""), ("quality", "OK"),
            ("quality_detail", ""), ("last_remind", 0), ("svc_ts", 0)) + PERIOD
# сайт: n, fails, inc, bad_sec — статистика между отчётами; ts — когда проверяли в последний раз
SITE_DEFAULTS = (("ok", True), ("n", 0), ("fails", 0), ("inc", 0), ("bad_sec", 0), ("status", "OK"), ("cand", "OK"),
                 ("streak", 0), ("code", "200"), ("last_remind", 0), ("ts", 0))
# что растёт: заголовок тревоги, как назвать в остальных сообщениях, правило роста
QUAL = {"lat": ("Вырос пинг", "Пинг", LAT_GROW),
        "conn": ("Дольше устанавливается соединение", "Время соединения", CONN_GROW)}
Q_EVENT = {"up": "вырос", "down": "вернулся к обычному", "norm": "держится, принят за обычный",
           "flap": "скачет — одно сообщение, дальше молчу", "calm": "успокоился", None: "сменился (скачет — не пишу)"}


def curl(port, url, timeout, fmt, body=False, ua=None, limit=None):
    cmd = ["curl", "-s", "-m", str(timeout), "-w", fmt]
    if port:
        cmd += ["-x", f"socks5h://127.0.0.1:{port}"]
    if ua:
        cmd += ["-A", ua]
    if limit:
        cmd += ["--max-filesize", str(limit)]
    if not body:
        cmd += ["-o", "/dev/null"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", 28


def quick(port):
    """Короткий запрос; вторая попытка через 2 с, чтобы разовая потеря пакета не считалась сбоем.

    Возвращает: жив ли канал, код curl и два времени в секундах —
    задержку (один обмен «запрос — ответ» по уже установленному соединению, близко к пингу через канал)
    и время соединения (от начала до первого байта ответа: туннель, DNS на ноде, TLS с сайтом)."""
    code = 0
    for attempt in (1, 2):
        out, code = curl(port, QUICK_URL, 8, "%{http_code} %{time_pretransfer} %{time_starttransfer}")
        parts = (out.split() + ["000", "0", "0"])[:3]
        if parts[0] in ("204", "200"):
            pre, start = float(parts[1]), float(parts[2])
            return True, 0, max(0.0, start - pre), start
        if attempt == 1:
            time.sleep(2)
    return False, code, 0.0, 0.0


def deep(port):
    out, _ = curl(port, DEEP_URL, 20, "%{size_download} %{time_total} %{speed_download}")
    parts = (out.split() + ["0", "0", "0"])[:3]
    size, total, speed = int(float(parts[0])), float(parts[1]), float(parts[2])
    ip = curl(port, EXIT_URL, 10, "", body=True)[0][:45]
    return size, total, speed, ip


def confirm_speed(port):
    """Закачка побольше, когда быстрая показала мало: (сколько пришло, за сколько секунд, байт в секунду)."""
    out, _ = curl(port, CONFIRM_URL, 20, "%{size_download} %{time_total} %{speed_download}")
    parts = (out.split() + ["0", "0", "0"])[:3]
    return int(float(parts[0])), float(parts[1]), float(parts[2])


def control_speed():
    """Та же закачка побольше напрямую с rf1, без VPN: медленно и она — тормозит сам rf1, а не ноды."""
    return confirm_speed(None)


def crowd(total):
    """Столько каналов сразу — это уже не беда отдельных нод, а общая причина (как и для «недоступен»)."""
    return max(3, (total + 1) // 2)


def confirm_step(results, total):
    """Перепроверить закачкой побольше каналы, где быстрая закачка дала мало, — по очереди и не дольше CONFIRM_BUDGET.
    Когда таких много сразу, сначала та же закачка напрямую с rf1: медленно и она — каналы не перепроверяем (по одной
    быстрой закачке «медленно» не ставится, см. classify). Возвращает (результаты, замер напрямую или None)."""
    wants = [i for i, r in enumerate(results) if r[8]]
    ctrl = control_speed() if len(wants) >= crowd(total) else None
    out = [list(r) for r in results]
    if ctrl is not None and ctrl[2] < SLOW_BPS:
        return [tuple(r) for r in out], ctrl
    t_end = time.time() + CONFIRM_BUDGET
    for i in wants:
        if time.time() > t_end:
            out[i][5] = None  # не успели за отведённое время — держим прежний замер канала
            continue
        out[i][5] = tuple(out[i][5]) + (confirm_speed(out[i][0]["port"]),)
    return [tuple(r) for r in out], ctrl


def mbit_of(detail):
    """«0.7 Мбит/с на закачке 4 МБ» -> «0.7»."""
    head = (detail or "").split(" Мбит/с")[0]
    return head if head.replace(".", "", 1).isdigit() else "?"


def crowd_text(kind, items, total, now, ctrl=None):
    """Одно сообщение вместо многих: kind — new (стало медленно), back (снова в порядке), remind (всё ещё медленно);
    items — [(канал, состояние канала, прежнее состояние, прежнее «с»)]."""
    names = ", ".join(html.escape(compact(ch["name"])) for ch, _, _, _ in items)
    if kind == "new":
        since = min(s["since"] for _, s, _, _ in items)
        speeds = ", ".join(f"{html.escape(compact(ch['name']))} {mbit_of(s['detail'])}" for ch, s, _, _ in items)
        text = (f"🐢 <b>Медленно сразу у {len(items)} каналов из {total}</b>\nС {hm(since)} МСК на закачке "
                f"{CONFIRM_BYTES // 1048576} МБ, Мбит/с: {speeds} (порог — {SLOW_MBIT}).")
        if ctrl is not None:
            text += f"\nНапрямую с rf1 без VPN в тот же момент: {ctrl[2] * 8 / 1e6:.1f} Мбит/с."
        return text + ("\n<b>Похоже на:</b> общую причину на стороне rf1 или его провайдера (так много нод сразу "
                       "не тормозит), а не поломку самих нод.")
    if kind == "back":
        since = min(was_since for _, _, _, was_since in items)
        return (f"✅ <b>Скорость вернулась сразу у {len(items)} каналов</b>: {names}.\n"
                f"Медленно было с {hm(since)} до {hm(now)} МСК.")
    since = min(s["since"] for _, s, _, _ in items)
    return (f"⏳ <b>Всё ещё медленно у {len(items)} каналов</b>: {names} — уже {dur(now - since)} "
            f"(с {hm(since)} МСК).")


def watch_slow_text(slow, total, ctrl, since, now):
    if slow:
        return (f"🐢 <b>Медленно у самого rf1, а не у нод</b>\nС {hm(since)} МСК у {slow} каналов из {total} быстрая "
                f"закачка ниже порога, и напрямую без VPN rf1 качает всего {ctrl[2] * 8 / 1e6:.1f} Мбит/с "
                f"(порог — {SLOW_MBIT}). Сторож меряет скорость с rf1, поэтому, пока так, каналы медленными не помечаю.\n"
                "<b>Для пользователей:</b> медленно у тех, кто входит через rf1 (плитка «Резерв»); "
                "на остальных плитках это не сказывается.")
    return f"✅ <b>rf1 снова качает нормально</b>\nМедленно было с {hm(since)} до {hm(now)} МСК ({dur(now - since)})."


def need_confirm(deep_res, usual, slow_now):
    """Перепроверять ли скорость закачкой побольше. Да — если быстрая закачка дошла, но дала меньше порога и заметно
    меньше обычного для этого канала (usual, Мбит/с; None — обычное ещё не накоплено). Канал уже считается
    медленным (slow_now) — перепроверяем всегда: возврат в норму судим по той же мерке, что и поломку."""
    size, _, speed = deep_res[:3]
    if size < DEEP_BYTES or speed >= SLOW_BPS:
        return False
    return slow_now or usual is None or speed * 8 / 1e6 < usual * SLOW_PART


def http_code(port, url, ok, timeout):
    """Код ответа; при неудаче — вторая попытка, чтобы разовый сбой не попадал в отчёт."""
    code = "000"
    for attempt in (1, 2):
        code = curl(port, url, timeout, "%{http_code}", ua=UA, limit=SVC_MAX_BYTES)[0] or "000"
        if code in ok:
            break
        if attempt == 1:
            time.sleep(1)
    return code


def services(port):
    """Открываются ли сервисы через канал: {название: код ответа}."""
    return {name: http_code(port, url, ok, 6) for name, url, ok in SERVICES}


def sub_url():
    return open(os.path.join(ETC, "sub.url"), encoding="utf-8").read().strip()


def check_sub():
    """Страница подписки: настоящая загрузка подписки сторожа. '200' — пришла подписка,
    '000' — нет соединения, BAD_FORMAT — ответ есть, но это не подписка, иначе — код ответа."""
    code = "000"
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(sub_url(), headers={"User-Agent": SUB_UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode("utf-8"))
            code = "200" if isinstance(data, list) and data else BAD_FORMAT
        except urllib.error.HTTPError as e:
            code = str(e.code)
        except ValueError:
            code = BAD_FORMAT
        except (OSError, http.client.HTTPException):
            code = "000"
        if code == "200":
            break
        if attempt == 1:
            time.sleep(2)
    return code


def check_site(name):
    """Сайт владельца, напрямую с rf1: код ответа ('200' — в порядке, '000' — нет соединения)."""
    return check_sub() if name == SUB_NAME else http_code(None, dict(SITES)[name], ("200",), 8)


def site_cross(name, via):
    """Сайт не отвечает с rf1: отвечает ли его сервер через зарубежную ноду.
    Возвращает (название ноды, код ответа); None — проверить не через что."""
    if not via:
        return None
    try:
        # адрес подписки сторожа — секрет, в командную строку curl он попадать не должен: хватит ответа сервера
        url = f"https://{urllib.parse.urlsplit(sub_url()).hostname}/" if name == SUB_NAME else dict(SITES)[name]
    except OSError:
        return None
    return compact(via["name"]), curl(via["port"], url, 8, "%{http_code}", ua=UA, limit=SVC_MAX_BYTES)[0] or "000"


def site_detail(code):
    return {"000": "нет соединения", BAD_FORMAT: "ответ пришёл, но это не подписка"}.get(code, f"отвечает кодом {code}")


def site_reason(name, code, cross):
    if code == "000":
        if not cross:
            return "сервер не отвечает на запросы с rf1; из-за границы проверить сейчас не через что"
        if cross[1] == "000":
            return (f"сервер не отвечает ни с rf1, ни через зарубежную ноду ({cross[0]}) — выключен, завис "
                    "или у хостера пропала сеть")
        return (f"через зарубежную ноду ({cross[0]}) сервер отвечает, а с rf1 — нет: блокировка или сбой связи "
                "между РФ и сервером")
    if code == "403":
        return "веб-сервер жив, но отказал rf1 в доступе — возможно, адрес rf1 пропал из списка разрешённых"
    if name == SUB_NAME:
        return ("сервер подписки жив, но подписку не отдаёт — не работает сама страница подписки или панель, "
                "у которой она берёт данные")
    if code.startswith("5"):
        return "веб-сервер жив, а приложение за ним не отвечает — упал или перезапускается контейнер"
    return "сайт отвечает не так, как обычно"


def site_alert(name, v, was_since, cross):
    if v["status"] == "OK":
        return (f"✅ <b>Снова отвечает: {name}</b>\nПерерыв {dur(v['since'] - was_since)} "
                f"(с {hm(was_since)} до {hm(v['since'])} МСК).")
    return (f"🔴 <b>Не отвечает: {name}</b>\nС {hm(v['since'])} МСК: {site_detail(v['code'])}.\n"
            f"<b>Похоже на:</b> {html.escape(site_reason(name, v['code'], cross))}.\n"
            f"<b>Для пользователей:</b> {SITE_IMPACT[name]}")


def site_remind(name, v, cross, now):
    return (f"⏳ <b>Всё ещё не отвечает: {name}</b> — уже {dur(now - v['since'])} (с {hm(v['since'])} МСК).\n"
            f"Сейчас: {site_detail(v['code'])}. <b>Похоже на:</b> {html.escape(site_reason(name, v['code'], cross))}.")


def level_step(store, name, lvl, confirm):
    """Уровень срока (ok / soon / bad) меняется после confirm наблюдений подряд.
    Возвращает прежний уровень, если он сменился, иначе None."""
    s = store.setdefault(name, {"lvl": "ok", "cand": "ok", "n": 0})
    if lvl == s["lvl"]:
        s["cand"], s["n"] = lvl, 0
        return None
    s["n"] = s["n"] + 1 if s["cand"] == lvl else 1
    s["cand"] = lvl
    if s["n"] < confirm:
        return None
    was, s["lvl"], s["n"] = s["lvl"], lvl, 0
    return was


def cert_level(v, now):
    """ok / soon / bad; None — до сервера ещё ни разу не достучались, судить не о чем."""
    if "err" in v:
        return None if v["err"] == NO_LINK else "bad"
    days = (v["exp"] - now) / 86400
    return "bad" if days < 0 else "soon" if days < max(3, v["life"] * CERT_WARN_PART) else "ok"


def cert_alert(name, v, lvl, now, node):
    """Сертификат сайта или ноды сменил уровень; node — это сайт-прикрытие ноды, а не сайт владельца."""
    days = int((v["exp"] - now) // 86400) if "exp" in v else None
    if lvl == "ok":
        return f"✅ <b>Сертификат в порядке: {name}</b> — действует ещё {days} дн."
    effect = ("Это сайт-прикрытие ноды: VPN работает, но маскировка становится заметной." if node
              else "Приложения и браузеры перестанут открывать сайт.")
    if lvl == "soon":
        return (f"⚠️ <b>Сертификат скоро истечёт: {name}</b> — осталось {days} дн.\n"
                f"Обычно он продлевается сам заранее — похоже, продление не сработало. Когда истечёт: {effect}")
    return f"❌ <b>Сертификат не в порядке: {name}</b> — {html.escape(v.get('err') or 'срок истёк')}.\n{effect}"


def domain_alert(domain, exp, lvl, now):
    until = f"{dt.datetime.fromtimestamp(exp, MSK):%d.%m.%Y}"
    if lvl == "ok":
        return f"✅ <b>Домен продлён: {domain}</b> — до {until}."
    if lvl == "soon":
        return (f"⚠️ <b>Регистрация домена кончается: {domain}</b> — до {until}, осталось "
                f"{int((exp - now) // 86400)} дн.\nПродлить у регистратора: на этом домене сайты и входы нод.")
    return f"❌ <b>Регистрация домена истекла: {domain}</b> — {until}. Сайты и входы нод на этом домене перестанут открываться."


def cert_info(host, port=443, sni=None):
    """Сертификат сервера: {'exp': когда истекает, 'life': на сколько дней выдан} либо {'err': что не так}."""
    try:
        with socket.create_connection((host, int(port)), timeout=6) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=sni or host) as tls:
                cert = tls.getpeercert()
        end, start = ssl.cert_time_to_seconds(cert["notAfter"]), ssl.cert_time_to_seconds(cert["notBefore"])
        return {"exp": end, "life": int((end - start) // 86400)}
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or "не прошёл проверку"
        for mark, text in (("expired", "срок истёк"), ("Hostname mismatch", "выдан на другое имя"),
                           ("self-signed", "самоподписанный"), ("self signed", "самоподписанный")):
            if mark in msg:
                msg = text
        return {"err": msg}
    except (OSError, ValueError, KeyError):
        return {"err": NO_LINK}


def cert_targets(chans):
    """Чьи сертификаты проверять: сайты владельца и ноды, у которых прикрытием служит собственный домен."""
    targets = {h.split(".")[0]: (h, 443, h) for h in SITE_HOSTS}
    for c in chans:
        sni = c.get("sni") or ""
        if sni.endswith(tuple("." + d for d in DOMAINS)):
            targets[sni.split(".")[0]] = (c["entry"], c.get("entry_port") or 443, sni)
    return targets


def domain_expiry(domain):
    """Когда кончается регистрация домена (RDAP), секунды с эпохи; None — узнать не удалось."""
    for proxy in (None, TG_FALLBACK_PROXY):
        cmd = ["curl", "-sL", "-m", "12", f"https://rdap.org/domain/{domain}"]
        if proxy:
            cmd[1:1] = ["-x", proxy]
        try:
            data = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout)
            for e in data.get("events", []):
                if e.get("eventAction") == "expiration":
                    return dt.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00")).timestamp()
        except (ValueError, KeyError, AttributeError, subprocess.TimeoutExpired):
            continue
    return None


def classify(ch, deep_res):
    """deep_res — (сколько пришло, секунд, байт/с, адрес выхода) и, если скорость перепроверялась, пятым —
    результат закачки побольше (confirm_speed)."""
    size, total, speed, ip = deep_res[:4]
    confirm = deep_res[4] if len(deep_res) > 4 else None
    if size < FREEZE_BYTES:
        return "FREEZE", f"за {total:.0f} с пришло {size // 1024} КБ из {DEEP_BYTES // 1024}"
    if ch.get("expected_exit") and ip and ip != ch["expected_exit"]:
        return "WRONG_EXIT", f"выход {ip}, ожидался {ch['expected_exit']}"
    if size < DEEP_BYTES:
        return "SLOW", f"{speed * 8 / 1e6:.1f} Мбит/с: {DEEP_BYTES // 1024} КБ не докачались за {total:.0f} с"
    # закачка побольше совсем не пошла (меньше FREEZE_BYTES) — разовый сбой самой перепроверки, по ней не судим
    if confirm and confirm[0] >= FREEZE_BYTES and (confirm[0] < CONFIRM_BYTES or confirm[2] < SLOW_BPS):
        return "SLOW", f"{confirm[2] * 8 / 1e6:.1f} Мбит/с на закачке {CONFIRM_BYTES // 1048576} МБ"
    return "OK", f"{speed * 8 / 1e6:.1f} Мбит/с, выход {ip or '?'}"


def diagnose(ch):
    """Канал не отвечает: что именно сломано — сервер, порт или только VPN поверх них."""
    host, port = ch.get("entry"), int(ch.get("entry_port") or 443)
    d = {"ping": False, "tcp": "error", "tcp_ms": None, "tls": None}
    try:
        d["ping"] = subprocess.run(["ping", "-c", "2", "-W", "2", "-q", host],
                                   capture_output=True, timeout=8).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        pass
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except ConnectionRefusedError:
        d["tcp"] = "refused"
    except TimeoutError:
        d["tcp"] = "timeout"
    except OSError:
        d["tcp"] = "error"
    else:
        d["tcp"], d["tcp_ms"] = "open", int((time.time() - t0) * 1000)
        try:
            if ch.get("security") in ("reality", "tls"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock.settimeout(6)
                with ctx.wrap_socket(sock, server_hostname=ch.get("sni") or host):
                    d["tls"] = True
        except (ssl.SSLError, OSError, ValueError):
            d["tls"] = False
        finally:
            sock.close()
    return d


def diag_lines(ch, d, bad_now):
    tcp = {"open": f"открыт ({d['tcp_ms']} мс)", "refused": "закрыт (отказ в соединении)",
           "timeout": "не отвечает (таймаут)"}.get(d["tcp"], "ошибка соединения")
    lines = [f"• сервер {ch.get('entry')}: {'пингуется' if d['ping'] else 'не пингуется'}",
             f"• порт {ch.get('entry_port') or 443}: {tcp}"]
    if d["tls"] is not None:
        lines.append(f"• TLS на порту: {'отвечает' if d['tls'] else 'не отвечает'}")
    lines.append(others_line(ch, bad_now))
    return lines


def others_line(ch, bad_now):
    others = [short(n) for n in bad_now if n != ch["name"]]
    return "• остальные каналы: " + ("работают" if not others else f"не отвечают ещё {len(others)} — " + ", ".join(others))


def reason(d, bad_now, total):
    if len(bad_now) >= max(3, (total + 1) // 2):
        return ("не отвечает сразу несколько каналов — похоже на сбой сети в РФ или у самой rf1, "
                "а не на поломку одной ноды")
    if d["tcp"] == "open":
        if d["tls"] is False:
            return ("порт открыт, но TLS не отвечает — Xray на ноде завис, либо соединение рвут по пути "
                    "(так выглядит блокировка DPI)")
        return ("сервер и порт отвечают, а VPN-соединение не проходит — нода перезапускается или получила "
                "от панели новый конфиг, не знает служебного пользователя, либо протокол режет DPI")
    if d["tcp"] == "refused":
        return "сервер включён, но порт VPN закрыт — на ноде не запущен Xray (контейнер remnanode)"
    if d["ping"]:
        return "сервер пингуется, но порт VPN не отвечает — файрвол на ноде или блокировка порта по пути из РФ"
    return ("сервер не отвечает совсем — выключен, перезагружается, пропала сеть у хостера, "
            "либо его адрес блокируют из РФ")


def short(name):
    return " ".join(name.split())


def compact(name):
    """Имя плитки без украшений (🌐, 🔄, |) — для отчёта."""
    for junk in ("🌐", "🔄", "|"):
        name = name.replace(junk, " ")
    return " ".join(name.split())


def plural(n, one, few, many):
    """1 канал, 2 канала, 5 каналов."""
    n10, n100 = n % 10, n % 100
    word = one if n10 == 1 and n100 != 11 else few if 2 <= n10 <= 4 and not 12 <= n100 <= 14 else many
    return f"{n} {word}"


def hm(ts):
    return dt.datetime.fromtimestamp(ts, MSK).strftime("%H:%M")


def dm(ts):
    return dt.datetime.fromtimestamp(ts, MSK).strftime("%d.%m")


def dur(seconds):
    m = max(1, int(round(seconds / 60)))
    if m < 60:
        return f"{m} мин"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} ч {m:02d} мин"
    d, h = divmod(h, 24)
    return f"{d} д {h} ч"


def alert_text(ch, s, was, was_since, diag, bad_now, total, deep=None):
    """deep — разбор сбоя с нескольких точек (blockwatch.deep_diag); есть он — вывод берётся из него."""
    name, st, since = html.escape(short(ch["name"])), s["status"], hm(s["since"])
    if st == "OK":
        text = (f"✅ <b>Снова работает: {name}</b>\n{WAS[was]} {dur(s['since'] - was_since)} "
                f"(с {hm(was_since)} до {since} МСК).")
        return text + (f"\nСейчас: {html.escape(s['detail'])}." if s["detail"] else "")
    if st == "DOWN":
        text = f"🔴 <b>Недоступен: {name}</b>\nНе отвечает с {since} МСК."
        if deep:
            text += "\n\n" + blockwatch.deep_text(deep, st, [others_line(ch, bad_now)])
        elif diag:
            text += ("\n\n<b>Что проверил</b>\n" + html.escape("\n".join(diag_lines(ch, diag, bad_now)))
                     + f"\n\n<b>Похоже на:</b> {html.escape(reason(diag, bad_now, total))}.")
        text += ("\n<b>Для пользователей:</b> эта плитка не подключается; "
                 "балансиры AUTO и AUTO_LTE недоступные ноды обходят сами.")
    elif st == "FREEZE":
        text = (f"🧊 <b>Душат: {name}</b>\nС {since} МСК соединение устанавливается, но данные встают: "
                f"{html.escape(s['detail'])}."
                + ("\n\n" + blockwatch.deep_text(deep, st) + "\n" if deep else " Так выглядит удушение DPI.\n")
                + "<b>Для пользователей:</b> подключение есть, а сайты и видео не грузятся.")
    elif st == "SLOW":
        text = (f"🐢 <b>Медленно: {name}</b>\nС {since} МСК скорость {html.escape(s['detail'])} "
                f"(порог — {SLOW_MBIT} Мбит/с).")
    else:
        text = (f"🔀 <b>Не тот выход: {name}</b>\nС {since} МСК {html.escape(s['detail'])}. "
                "Трафик выходит не через тот сервер, что задуман.")
    return text + (f"\n<i>До этого: {LABELS[was]}.</i>" if was != "OK" else "")


def remind_text(ch, s, diag, bad_now, total, now, deep=None):
    text = (f"⏳ <b>Всё ещё {STILL[s['status']]}: {html.escape(short(ch['name']))}</b> — уже "
            f"{dur(now - s['since'])} (с {hm(s['since'])} МСК).")
    if deep and s["status"] in ("DOWN", "FREEZE"):
        if s["status"] == "FREEZE" and s["detail"]:
            text += f"\nСейчас: {html.escape(s['detail'])}."
        text += "\n" + blockwatch.deep_text(deep, s["status"], [others_line(ch, bad_now)] if s["status"] == "DOWN" else [])
    elif s["status"] == "DOWN" and diag:
        text += ("\n" + html.escape("\n".join(diag_lines(ch, diag, bad_now)))
                 + f"\n<b>Похоже на:</b> {html.escape(reason(diag, bad_now, total))}.")
    elif s["detail"]:
        text += f"\nСейчас: {html.escape(s['detail'])}."
    return text


def geo_one(ch):
    """Гео выхода одной ноды через её канал: {"flag", "row": {база: страна}, "org", "cf": страна Cloudflare, "yt"}."""
    port = ch["port"]
    # у ретранслятора (ожидаемый выход задан) флаг плитки — страна входа, не выхода
    flag = None if ch.get("expected_exit") else next((FLAG_CC[g] for g in FLAG_CC if g in ch["name"]), None)
    ip = curl(port, EXIT_URL, 10, "", body=True)[0].strip()[:45]
    row, org = {}, None
    import ipaddress as _ip
    try:
        _ip.ip_address(ip)
    except ValueError:
        return ch["name"], {"flag": flag, "row": {}, "org": None, "cf": None, "yt": None}
    for name, url, cc_key, org_key in GEO_DBS:
        body = curl(port, url.format(ip=ip), 12, "", body=True)[0]
        try:
            d = json.loads(body)
        except ValueError:
            continue
        if isinstance(d, list):  # geojs с ?ip= отвечает массивом из одного объекта
            d = d[0] if d and isinstance(d[0], dict) else {}
        if not isinstance(d, dict):
            continue
        cc = d.get(cc_key)
        row[name] = cc.upper() if isinstance(cc, str) and len(cc) == 2 else None
        if org_key and not org and d.get(org_key):
            org = str(d.get(org_key))[:60]
    trace = dict(x.split("=", 1) for x in curl(port, "https://www.cloudflare.com/cdn-cgi/trace", 10, "", body=True)[0].splitlines() if "=" in x)
    yt = curl(port, "https://www.youtube.com/", 12, "", body=True, ua=UA)[0]
    import re as _re
    m = _re.search(r'"(?:INNERTUBE_CONTEXT_)?GL":"([A-Z]{2})"', yt)
    return ch["name"], {"flag": flag, "row": row, "org": org, "cf": trace.get("loc"), "yt": m.group(1) if m else None}


def geo_collect(chans):
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(chans))) as ex:
        return dict(ex.map(geo_one, chans))


def outside_collect(nodes, cfg, state):
    """Взгляд снаружи для службы --side: каждую ноду — через живой чужой канал (не «Резерв», не через неё саму);
    у кого снимок разошёлся с принятым сторожем (state["outside"]) — сразу перепроверить.
    {"ts", "seen": {нода: снимок}, "again": {нода: снимок перепроверки | None}}"""
    live = [c for c in cfg if state.get("channels", {}).get(c["name"], {}).get("status") == "OK"
            and not c.get("expected_exit") and str(c.get("entry", "")).endswith(tuple("." + d for d in DOMAINS))
            and c["entry"] not in NO_VANTAGE]

    def vantage_for(node):
        return next((c["port"] for c in live if c["entry"] != node["host"]), None)
    seen = nodewatch.outside_view(nodes, vantage_for)
    again = {}
    for node in nodes:
        name = node["name"]
        if name in seen and nodewatch.outside_changes(name, state.get("outside", {}).get(name), seen[name]):
            again[name] = nodewatch.outside_view([node], vantage_for).get(name)
    return {"ts": time.time(), "seen": seen, "again": again}


def tg_env():
    env = {}
    try:
        for line in open(TG_ENV, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env.get("BW_TG_TOKEN"), env.get("BW_TG_CHAT")


def tg_routes():
    """Через что слать в Telegram: напрямую; не вышло — через свой же рабочий канал с зарубежным выходом
    (так сторож не зависит от того, виден ли Telegram с его сервера); последним — запасной мост, если он есть."""
    routes = [None]
    state = load_state().get("channels", {})
    port = next((c["port"] for c in read_json("channels.json", {}).get("channels", [])
                 if not c.get("expected_exit") and state.get(c["name"], {}).get("status", "OK") == "OK"), None)
    if port:
        routes.append(f"socks5h://127.0.0.1:{port}")
    return routes + [TG_FALLBACK_PROXY]


def tg_send(text):
    """'ok' — доставлено; 'bad' — Telegram отверг само сообщение (повторять бесполезно); 'fail' — нет связи."""
    token, chat = tg_env()
    if not token or not chat:
        return "fail"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    result = "fail"
    for proxy in tg_routes():
        cmd = ["curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", url,
               "--data-urlencode", f"chat_id={chat}", "--data-urlencode", f"text={text}",
               "-d", "parse_mode=HTML", "-d", "disable_web_page_preview=true"]
        if proxy:
            cmd[1:1] = ["-x", proxy]
        try:
            code = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
        except subprocess.TimeoutExpired:
            continue
        if code == "200":
            return "ok"
        if code == "400":
            result = "bad"
    return result


def log(line):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%dT%H:%M:%SZ} {line}\n")


def read_json(name, default):
    """Файл от build_channels.py (состояние подписки, изменения в ней)."""
    try:
        return json.load(open(os.path.join(ETC, name), encoding="utf-8"))
    except (OSError, ValueError):
        return default


def load_json(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def load_state():
    return load_json(STATE)


def new_hour():
    """Счётчики канала за текущий час — в конце часа уходят в историю (close_hour)."""
    return {"checks": 0, "fails": 0, "bad": 0, "inc": 0, "spd_sum": 0.0, "spd_n": 0, "big_sum": 0.0, "big_n": 0,
            "lat": [], "conn": []}


def init_channel(s, now):
    for k, v in DEFAULTS + (("since", now), ("cand_since", now)):
        s.setdefault(k, v)
    s.setdefault("svc", {})
    s.setdefault("svc_fail", {})
    for k in PERIOD_LISTS + ("win_lat", "win_conn"):
        s.setdefault(k, [])
    s.setdefault("base", {})  # обычные пинг и время соединения, мс — пересчитываются раз в час по истории
    for kind in QUAL:
        s.setdefault("q_" + kind, {"st": "OK", "since": 0, "base": 0})
    s.setdefault("hr", new_hour())
    return s


def week_key(ts):
    year, week, _ = dt.datetime.fromtimestamp(ts, dt.timezone.utc).isocalendar()
    return f"{year}-W{week:02d}"


def init_state(st, now):
    """Недостающие поля состояния — при первом запуске и после обновления сторожа."""
    for k, v in (("channels", {}), ("last_deep", 0), ("last_summary", ""), ("summary_since", now),
                 ("offline_sec", 0), ("slow_last", 0), ("sites", {}), ("certs", {}), ("domains", {}),
                 ("cert_lvl", {}), ("dom_lvl", {}), ("recheck", False), ("hour", 0), ("last_run", 0),
                 ("last_weekly", week_key(now)), ("nodes", {}), ("outside", {}), ("outside_ts", 0), ("disk_lvl", {}), ("speed_ts", 0),
                 ("lists", {}), ("dns", {}), ("dns_lvl", {}), ("dns_last", 0), ("dns_recheck", False), ("vantage", {}),
                 ("loss", {}), ("watch_slow", {"since": 0, "n": 0, "alerted": False}), ("dns_pt", {}),
                 ("profiles", {}), ("geo", {}), ("vpn_pt", {}), ("vpn_alert", {})):
        st.setdefault(k, v)
    for s in st["channels"].values():
        init_channel(s, now)
    for name in SITE_ORDER:
        site = st["sites"].setdefault(name, {})
        for k, v in SITE_DEFAULTS + (("since", now), ("cand_since", now)):
            site.setdefault(k, v)
        site.setdefault("hr", {"n": 0, "fails": 0, "bad": 0, "inc": 0})
    return st


def load_history():
    try:
        hist = json.load(open(HISTORY, encoding="utf-8"))
    except (OSError, ValueError):
        hist = {}
    hist.setdefault("channels", {})
    hist.setdefault("sites", {})
    return hist


def save_history(hist):
    with open(HISTORY + ".tmp", "w", encoding="utf-8") as f:
        json.dump(hist, f, ensure_ascii=False)
    os.replace(HISTORY + ".tmp", HISTORY)


def baseline(buckets, kind, now):
    """Обычное значение пинга или времени соединения: медиана часовых медиан за BASE_HOURS; None — истории мало."""
    values = [b[kind] for b in buckets if b.get(kind) is not None and b["h"] >= now - BASE_HOURS * 3600]
    return statistics.median(values) if len(values) >= BASE_MIN_HOURS else None


def close_hour(st, hist, hour):
    """Час кончился: накопленное за него — в историю, счётчики часа — заново, обычные значения — пересчитать."""
    for name, s in st["channels"].items():
        hr = s["hr"]
        if hr["checks"]:
            hist["channels"].setdefault(name, []).append({
                "h": hour, "checks": hr["checks"], "fails": hr["fails"], "bad": round(hr["bad"]), "inc": hr["inc"],
                "spd": round(hr["spd_sum"] / hr["spd_n"], 2) if hr["spd_n"] else None, "spd_n": hr["spd_n"],
                "big": round(hr["big_sum"] / hr["big_n"], 1) if hr.get("big_n") else None, "big_n": hr.get("big_n", 0),
                "lat": round(statistics.median(hr["lat"])) if hr["lat"] else None,
                "conn": round(statistics.median(hr["conn"])) if hr["conn"] else None})
        s["hr"] = new_hour()
        s["base"] = {kind: baseline(hist["channels"].get(name, []), kind, hour + 3600) for kind in QUAL}
        s["base"]["spd"] = baseline(hist["channels"].get(name, []), "spd", hour + 3600)  # обычная скорость на 512 КБ
    for name, v in st["sites"].items():
        hr = v["hr"]
        if hr["n"] or hr["bad"]:
            hist["sites"].setdefault(name, []).append(
                {"h": hour, "n": hr["n"], "fails": hr["fails"], "bad": round(hr["bad"]), "inc": hr["inc"]})
        v["hr"] = {"n": 0, "fails": 0, "bad": 0, "inc": 0}
    for group in (hist["channels"], hist["sites"]):
        for buckets in group.values():
            del buckets[:-HIST_KEEP]


def q_fmt(kind, value):
    return f"{value:.0f} мс" if kind == "lat" else f"{value / 1000:.2f} с"


def q_limit(base, rule):
    return max(base * rule[0], base + rule[1])


def quality_step(q, value, base, rule, now):
    """Пинг или время соединения против обычного. Возвращает 'up' — вырос (медиана выше порога QUAL_UP_N проходов
    подряд), 'down' — вернулся к прежнему, 'norm' — так и держится, а обычное значение за это время подтянулось к нему
    (оба — не раньше, чем через QUAL_DOWN_SEC ниже середины); None — без перемен."""
    if q["st"] == "OK":
        if base is not None and value >= q_limit(base, rule):
            q["n_up"] = q.get("n_up", 0) + 1
            if q["n_up"] >= QUAL_UP_N:
                q.update(st="HIGH", since=now, base=base, n_up=0, low=0)
                return "up"
        else:
            q["n_up"] = 0
        return None
    # возврат — ниже середины между обычным и порогом, чтобы на самой границе не дёргаться туда-сюда
    old_mid = (q["base"] + q_limit(q["base"], rule)) / 2
    new_mid = (base + q_limit(base, rule)) / 2 if base is not None else None
    if value < old_mid or (new_mid is not None and value < new_mid):
        q["low"] = q.get("low") or now
        if now - q["low"] >= QUAL_DOWN_SEC:
            q.update(st="OK", low=0, n_up=0)
            return "down" if value < old_mid else "norm"
    else:
        q["low"] = 0
    return None


def quality_flap(q, event, now):
    """Смена состояния (up/down/norm) → что сообщать: само событие; 'flap' — канал скачет (третья смена за час,
    одно сообщение); None — уже скачет, молчим."""
    q["flips"] = [t for t in q.get("flips", []) if now - t < QUAL_FLAP_SEC] + [now]
    if q.get("flap"):
        return None
    if len(q["flips"]) >= QUAL_FLAP_N:
        q["flap"] = now
        return "flap"
    return event


def quality_calm(q, now):
    """Канал скакал, а теперь QUAL_CALM_SEC без единой смены — пора сказать «успокоился»."""
    return bool(q.get("flap")) and now - max(q.get("flips") or [q["flap"]]) >= QUAL_CALM_SEC


def q_levels(win):
    """Два уровня скачущего значения: нижняя и верхняя четверть последних замеров."""
    v = sorted(win)
    return v[len(v) // 4], v[(3 * len(v)) // 4]


def quality_alert(ch, kind, event, q, value, high, total, now, win=()):
    name = html.escape(short(ch["name"]))
    title, noun, _ = QUAL[kind]
    if event == "flap":
        lo, hi = q_levels(win) if len(win) >= 4 else (value, value)
        return (f"〰️ <b>{noun} скачет: {name}</b>\nЗа час {len(q['flips'])} раза то выше обычного, то в норме: "
                f"около {q_fmt(kind, lo)} и около {q_fmt(kind, hi)} (обычно {q_fmt(kind, q['base'])}).\n"
                "<b>Похоже на:</b> трафик до ноды ходит двумя маршрутами попеременно.\n"
                "<b>Для пользователей:</b> канал работает, временами медленнее. Пока не успокоится, об этом больше не пишу.")
    if event == "calm":
        now_txt = ("в норме" if q["st"] == "OK" else f"держится выше обычного (обычно {q_fmt(kind, q['base'])})")
        return (f"✅ <b>{noun} успокоился: {name}</b>\nСкакал с {hm(q['flap'])} до {hm(now)} МСК; "
                f"последний час без скачков. Сейчас {q_fmt(kind, value)} — {now_txt}.")
    if event == "up":
        if len(high) >= max(3, (total + 1) // 2):
            why = (f"так сразу у {plural(len(high), 'канала', 'каналов', 'каналов')} — похоже на сеть в РФ "
                   "или у самой rf1, а не на одну ноду")
        elif kind == "lat":
            why = "изменился маршрут между РФ и нодой, перегружен канал у хостера либо сама нода"
        else:
            why = ("нода дольше открывает соединения с сайтами — перегрузка, медленный DNS или неработающий IPv6 "
                   "на ноде (так было на NL1)")
        return (f"🐌 <b>{title}: {name}</b>\nПоследние полчаса — {q_fmt(kind, value)}, обычно {q_fmt(kind, q['base'])} "
                f"(в {value / q['base']:.1f} раза больше).\n<b>Похоже на:</b> {why}.\n"
                "<b>Для пользователей:</b> канал работает, но сайты через него открываются медленнее.")
    if event == "down":
        return (f"✅ <b>{noun} в норме: {name}</b>\nПовышение длилось {dur(now - q['since'])} "
                f"(с {hm(q['since'])} до {hm(now)} МСК). Сейчас {q_fmt(kind, value)}.")
    return (f"ℹ️ <b>{noun} держится на новом уровне: {name}</b>\n{q_fmt(kind, value)} уже {dur(now - q['since'])} "
            f"(раньше было {q_fmt(kind, q['base'])}). Дальше считаю это обычным значением.")


def main():
    cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    now = time.time()
    st = init_state(load_state(), now)

    if not quick(cfg["baseline_port"])[0]:
        log("контрольный канал без VPN не работает — у rf1 нет интернета, проверку пропускаю")
        st.setdefault("offline_since", now)
        save_state(st)
        return
    alerts = []
    if st.get("offline_since"):
        # интернет у самой rf1 вернулся: каналы всё это время никто не проверял — сказать об этом
        gap = now - st["offline_since"]
        st["offline_sec"] += gap
        alerts.append(f"ℹ️ <b>У самой rf1 не было интернета {dur(gap)}</b> (с {hm(st['offline_since'])} до {hm(now)} МСК).\n"
                      "Каналы в это время не проверялись.")
        del st["offline_since"]
    chans = cfg["channels"]
    # порядок — как в подписке; каналы, которых в ней больше нет, из состояния уходят
    st["channels"] = {c["name"]: init_channel(st["channels"].get(c["name"], {}), now) for c in chans}
    hour = int(now // 3600) * 3600
    if st["hour"] and st["hour"] != hour:
        hist = load_history()
        close_hour(st, hist, st["hour"])
        save_history(hist)
    st["hour"] = hour
    # сколько прошло с прошлого запуска — столько времени канал или сайт пробыл в нынешнем состоянии
    elapsed = min(max(now - st["last_run"], 0), 300) if st["last_run"] else 120
    node_cfg = read_json("nodes.json", [])  # ноды: имя, адрес, откуда брать маячок состояния
    st["nodes"] = {n["name"]: st["nodes"].get(n["name"], {}) for n in node_cfg}
    due = now - st["last_deep"] >= DEEP_EVERY
    # не в одном запуске с закачкой; recheck — сертификат сменил уровень, подтверждаем следующим же запуском
    do_slow = not due and (now - st["slow_last"] >= SLOW_EVERY or st["recheck"])
    # подмена DNS — в запуске без закачки и без сертификатов; расхождение подтверждаем следующим же запуском
    do_dns = not due and not do_slow and (now - st["dns_last"] >= blockwatch.DNS_EVERY or st["dns_recheck"])
    agents = blockwatch.agents_cfg()  # другие российские точки проверки
    dns_names = list(SITE_HOSTS) + [n["host"] for n in node_cfg if str(n.get("host", "")).endswith(tuple("." + d for d in DOMAINS))]
    # зарубежный канал, который в прошлый раз работал: через него спрашиваем защищённый DNS
    ok_port = next((c["port"] for c in chans if not c.get("expected_exit") and st["channels"][c["name"]]["status"] == "OK"), None)
    sites = st["sites"]
    # сайт с неподтверждённой сменой состояния или лежащий — проверяем каждый запуск, не дожидаясь срока
    site_due = [name for name in SITE_ORDER
                if sites[name]["cand"] != sites[name]["status"] or sites[name]["status"] != "OK"
                or (now - sites[name]["ts"] >= SUB_EVERY if name == SUB_NAME else due)]

    def run(ch):
        s = st["channels"][ch["name"]]
        time.sleep(STAGGER * chans.index(ch))  # каналы стартуют по очереди: замеры задержки не мешают друг другу
        alive, code, lat, conn = quick(ch["port"])
        deep_res = diag = svc = None
        want = False
        if not alive:
            diag = diagnose(ch)
        elif due or s["cand"] != s["status"] or s["status"] == "DOWN":
            deep_res = deep(ch["port"])  # плановая закачка либо подтверждение нового состояния
            # мало — перепроверим закачкой побольше, но после всех каналов и по очереди (confirm_step)
            want = need_confirm(deep_res, s["base"].get("spd"), "SLOW" in (s["status"], s["cand"]))
        elif now - s["svc_ts"] >= SERVICES_EVERY:
            svc = services(ch["port"])   # в запуске без закачки, чтобы не растягивать его
        return ch, alive, code, lat, conn, deep_res, diag, svc, want

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(chans) + 16) as ex:
        f_chans = [ex.submit(run, c) for c in chans]
        f_sites = {name: ex.submit(check_site, name) for name in site_due}
        f_beacons = {n["name"]: ex.submit(nodewatch.fetch_beacon, n["beacon"]) for n in node_cfg if n.get("beacon")} if due else {}
        f_certs = {k: ex.submit(cert_info, *v) for k, v in cert_targets(chans).items()} if do_slow else {}
        f_domains = {d: ex.submit(domain_expiry, d) for d in DOMAINS} if do_slow else {}
        f_dns = ex.submit(blockwatch.dns_check, dns_names, ok_port, agents) if do_dns else None
        f_van = ex.submit(blockwatch.agents_health, agents) if do_slow and agents else None
        results = [f.result() for f in f_chans]
        site_codes = {name: f.result() for name, f in f_sites.items()}
        beacons = {name: f.result() for name, f in f_beacons.items()}
        if do_slow:
            old = st["certs"]
            st["certs"] = {}
            for name, f in f_certs.items():
                res = f.result()
                # до сервера не достучались — оставляем прошлый срок: о самом сервере скажет строка канала или сайта
                st["certs"][name] = old[name] if res.get("err") == NO_LINK and "exp" in old.get(name, {}) else res
            for d, f in f_domains.items():
                exp = f.result()
                if exp:
                    st["domains"][d] = exp
            st["slow_last"] = now
            log("сертификаты: " + ", ".join(
                f"{k} {v['err'] if 'err' in v else str(int((v['exp'] - now) // 86400)) + ' дн.'}"
                for k, v in sorted(st["certs"].items()))
                + "; домены: " + ", ".join(f"{d} {int((exp - now) // 86400)} дн." for d, exp in st["domains"].items()))
    if due:
        st["last_deep"] = now
    bad_now = [r[0]["name"] for r in results if not r[1]]
    # перепроверка закачкой побольше — по очереди; много сразу — сперва напрямую с rf1 (не он ли сам тормозит)
    results, ctrl = confirm_step(results, len(chans))
    if ctrl is not None:
        log(f"медленно сразу у {sum(1 for r in results if r[8])} каналов; напрямую без VPN — {ctrl[2] * 8 / 1e6:.1f} Мбит/с")
    r4 = st["watch_slow"]
    if ctrl is not None and ctrl[2] < SLOW_BPS:
        r4["since"], r4["n"] = r4["since"] or now, r4["n"] + 1
        if r4["n"] >= CONFIRM and not r4["alerted"]:
            r4["alerted"] = True
            alerts.append(watch_slow_text(sum(1 for r in results if r[8]), len(chans), ctrl, r4["since"], now))
    elif any(r[5] is not None for r in results):  # в этом запуске мерили — и rf1 в порядке
        if r4["alerted"]:
            alerts.append(watch_slow_text(0, len(chans), ctrl, r4["since"], now))
        r4.update(since=0, n=0, alerted=False)
    if f_van is not None:
        st["vantage"] = f_van.result()
    elif not agents:
        st["vantage"] = {}
    # профиль точек и гео нод собирает probe.py --side (свой таймер); здесь — забрать свежее один раз
    side = load_json(blockwatch.SIDE_FILE)
    sp = side.get("profiles") or {}
    if sp.get("ts", 0) > (st["profiles"].get("ts") or 0):
        st["profiles"] = sp  # пробный режим: только журнал, строка отчёта и пометка в разборе, тревог нет
        for point, pr in sorted(sp.get("by", {}).items()):
            log("профиль " + blockwatch.profile_text(point, pr))
    sv = side.get("vpn") or {}
    if sv.get("ts", 0) > (st["vpn_pt"].get("ts") or 0):
        st["vpn_pt"] = sv
        alerts += blockwatch.vpn_step(st, sv.get("by", {}),
                                      {n: c.get("status") == "OK" for n, c in st["channels"].items()})
        for point, res in sorted(sv.get("by", {}).items()):
            log(f"через VPN с точки {point}: " + "; ".join(f"{compact(n)} — {blockwatch.vpn_text(r)}" for n, r in res.items()))
    sg = side.get("geo") or {}
    if sg.get("ts", 0) > (st["geo"].get("ts") or 0):
        data = sg.get("data") or {}
        live = bool(st["geo"].get("by")) and now - st["geo"].get("first", now) >= GEO_SHADOW
        st["geo"].setdefault("first", now)
        alerts += blockwatch.geo_step(st, data, live)
        st["geo"]["ts"] = sg["ts"]
        for node, cur in sorted(data.items()):
            log(f"гео {compact(node)}: базы {'/'.join(sorted(blockwatch.geo_verdict(cur['row']))) or '?'}, "
                f"CF {cur.get('cf') or '-'}, YT {cur.get('yt') or '-'}, флаг {cur.get('flag') or '?'}")

    # подмена DNS: обычный DNS отвечает не то, что защищённый, — после CONFIRM проверок подряд
    if f_dns is not None:
        dns = f_dns.result()
        st["dns_last"] = now
        st["dns"] = {"ts": now, "names": len(dns)}
        st["dns_lvl"] = {k: v for k, v in st["dns_lvl"].items() if k in dns_names}
        for name, res in sorted(dns.items()):
            lvl = "bad" if len(res["odd"]) >= blockwatch.DNS_MIN else "ok"
            if level_step(st["dns_lvl"], name, lvl, CONFIRM):
                alerts.append(blockwatch.dns_alert(name, res, lvl))
            if res["odd"]:
                log(f"DNS {name}: по защищённому {', '.join(res['truth'])}; расходятся: "
                    + "; ".join(f"{who} — {what}" for who, what in res["odd"]))
        # свой DNS точки не находит наши имена (SERVFAIL, пусто) — событие точки, а не подмена отдельного имени
        for point, (failed, total) in blockwatch.dns_points(dns, agents).items():
            plvl = "bad" if failed >= max(2, (total + 1) // 2) else "ok"
            if level_step(st["dns_pt"], point, plvl, CONFIRM):
                alerts.append(blockwatch.dns_point_text(point, plvl, failed, total))
            if failed:
                log(f"DNS точки {point}: своим DNS не нашлось {failed} из {total} имён")
        st["dns_recheck"] = any(s["cand"] != s["lvl"] for s in st["dns_lvl"].values())
        log(f"DNS: проверено имён {len(dns)} из {len(dns_names)}, расхождений "
            f"{sum(1 for r in dns.values() if r['odd'])}")

    # списки блокировок: свежую сверку (probe.py --lists) забираем один раз; о попадании в список — сразу
    fresh = load_json(blockwatch.LISTS_FILE)
    if fresh.get("ts", 0) > st["lists"].get("ts", 0):
        found = blockwatch.lists_step(st, fresh)
        alerts += found
        log("списки блокировок: " + (", ".join(f"{who} — {name}" for who, name in blockwatch.hard_hits(st)) or "наших адресов нет")
            + f"; источников скачано {sum(1 for v in fresh['sources'].values() if v['ok'])} из {len(fresh['sources'])}")

    # потери соединений с точек: свежий замер (probe.py --loss, раз в час) забираем один раз
    fresh = load_json(blockwatch.LOSS_FILE)
    if fresh.get("ts", 0) > st["loss"].get("ts", 0):
        alerts += blockwatch.loss_step(st, fresh)
        log(blockwatch.loss_log(fresh))

    # сайты: поломка и возврат подтверждаются следующим же запуском; пока сайт лежит — напоминание раз в час
    via = next((r[0] for r in results if r[1] and not r[0].get("expected_exit")), None)  # живая зарубежная нода
    for name, code in site_codes.items():
        v, obs = sites[name], "OK" if code == "200" else "DOWN"
        v["ok"], v["code"], v["ts"] = obs == "OK", code, now
        v["n"], v["fails"] = v["n"] + 1, v["fails"] + (obs != "OK")
        v["hr"]["n"], v["hr"]["fails"] = v["hr"]["n"] + 1, v["hr"]["fails"] + (obs != "OK")
        if obs != "OK":
            log(f"сайт «{name}» не ответил: {site_detail(code)}")
        if obs == v["status"]:
            v["cand"], v["streak"] = obs, 0
        else:
            if v["cand"] == obs:
                v["streak"] += 1
            else:
                v["cand"], v["streak"], v["cand_since"] = obs, 1, now
            if v["streak"] >= CONFIRM:
                was_since = v["since"]
                v["status"], v["since"], v["streak"], v["last_remind"] = obs, v["cand_since"], 0, now
                if obs == "OK":
                    v["bad_sec"] += max(0, v["since"] - was_since)
                else:
                    v["inc"], v["hr"]["inc"] = v["inc"] + 1, v["hr"]["inc"] + 1
                cross = site_cross(name, via) if code == "000" else None
                alerts.append(site_alert(name, v, was_since, cross))
                log(f"сайт «{name}»: состояние {obs}" + (f", через {cross[0]} — код {cross[1]}" if cross else ""))
        if v["status"] == "DOWN" and obs == "DOWN" and now - v["last_remind"] >= REMIND_EVERY:
            v["last_remind"] = now
            alerts.append(site_remind(name, v, site_cross(name, via) if code == "000" else None, now))
    for v in sites.values():
        if v["status"] != "OK":
            v["hr"]["bad"] += elapsed

    # серверы: маячки нод — диск, память, файрвол, счётчики отбитых пакетов; о кончающемся диске — сразу
    for name, data in beacons.items():
        nodewatch.take_beacon(st["nodes"][name], data, now)
        lvl = nodewatch.disk_level(st["nodes"][name])
        if data is not None and lvl and level_step(st["disk_lvl"], name, lvl, CONFIRM):
            alerts.append(nodewatch.disk_alert(name, st["nodes"][name], lvl))

    # взгляд снаружи: что у каждой ноды видит посторонний — смотрит служба --side (раз в 6 ч, через чужую ноду,
    # изменение перепроверяет там же); здесь — забрать свежий снимок один раз и сообщить о подтверждённом
    so = side.get("outside") or {}
    if node_cfg and so.get("ts", 0) > st["outside_ts"]:
        st["outside_ts"] = so["ts"]
        seen, again_all = so.get("seen") or {}, so.get("again") or {}
        for node in node_cfg:
            name = node["name"]
            if name not in seen:
                continue
            changes = nodewatch.outside_changes(name, st["outside"].get(name), seen[name])
            if changes:
                again = again_all.get(name)
                if again is None:
                    continue  # не перепроверено (не через что или сравнивали с другим снимком) — снимок не трогаем
                changes = [c for c in changes if c in nodewatch.outside_changes(name, st["outside"].get(name), again)]
                seen[name] = again
            if changes:
                alerts.append(f"🔎 <b>Снаружи изменилось: {html.escape(name)}</b>\n"
                              + html.escape("\n".join("• " + c for c in changes)))
                log(f"снаружи {name}: " + "; ".join(changes))
            st["outside"][name] = seen[name]
        st["outside"] = {k: v for k, v in st["outside"].items() if k in st["nodes"]}

    # сертификаты и домены: о смене уровня (скоро истечёт, истёк, продлён) — сразу, а не только в отчёте
    if do_slow:
        own = {h.split(".")[0] for h in SITE_HOSTS}
        st["cert_lvl"] = {k: v for k, v in st["cert_lvl"].items() if k in st["certs"]}
        for name, v in sorted(st["certs"].items()):
            lvl = cert_level(v, now)
            if lvl and level_step(st["cert_lvl"], name, lvl, CONFIRM):
                alerts.append(cert_alert(name, v, lvl, now, name not in own))
        st["recheck"] = any(s["cand"] != s["lvl"] for s in st["cert_lvl"].values())
        for d, exp in st["domains"].items():
            lvl = "bad" if exp < now else "soon" if exp - now < DOMAIN_WARN_DAYS * 86400 else "ok"
            if level_step(st["dom_lvl"], d, lvl, 1):
                alerts.append(domain_alert(d, exp, lvl, now))

    # свежие замеры закачки побольше (probe.py --speed, за 5 минут до отчёта) — в состояние каналов и в историю
    sp = load_json(SPEED_FILE)
    if sp.get("ts", 0) > st["speed_ts"]:
        st["speed_ts"] = sp["ts"]
        for name, mbit in sp.get("channels", {}).items():
            s = st["channels"].get(name)
            if s is not None:
                s["big"], s["big_ts"] = mbit, sp["ts"]
                if mbit:
                    s["hr"]["big_sum"], s["hr"]["big_n"] = s["hr"].get("big_sum", 0.0) + mbit, s["hr"].get("big_n", 0) + 1

    q_events = []
    deferred = []  # сообщения о каналах дописываются после разбора сбоя: (место в alerts, вид, канал, параметры)
    for ch, alive, code, lat, conn, deep_res, diag, svc, _ in results:
        s = st["channels"][ch["name"]]
        hr = s["hr"]
        # статистика для отчёта (за период) и для истории (за час): доступность, задержка и скорость
        s["checks"], hr["checks"] = s["checks"] + 1, hr["checks"] + 1
        if not alive:
            s["fails"], hr["fails"] = s["fails"] + 1, hr["fails"] + 1
            s["win_lat"], s["win_conn"] = [], []  # канал лежал — прежние замеры о нынешнем отклике не говорят
        else:
            for kind, ms in (("lat", round(lat * 1000)), ("conn", round(conn * 1000))):
                s[kind] = (s[kind] + [ms])[-PERIOD_KEEP:]
                s["win_" + kind] = (s["win_" + kind] + [ms])[-QUAL_WINDOW:]
                hr[kind].append(ms)
            if deep_res is not None and deep_res[3]:
                s["exit"] = deep_res[3]  # с какого адреса канал выходит в интернет — по нему узнаём ноду за ретранслятором
            if deep_res is not None and deep_res[0] >= DEEP_BYTES:
                mbit = deep_res[2] * 8 / 1e6
                s["spd_sum"], s["spd_n"] = s["spd_sum"] + mbit, s["spd_n"] + 1
                s["spd_min"] = mbit if not s["spd_min"] else min(s["spd_min"], mbit)
                hr["spd_sum"], hr["spd_n"] = hr["spd_sum"] + mbit, hr["spd_n"] + 1
        if svc is not None:
            s["svc"], s["svc_ts"], s["svc_n"] = svc, now, s["svc_n"] + 1
            failed = [name for name, _, ok in SERVICES if svc.get(name) not in ok]
            for name in failed:
                s["svc_fail"][name] = s["svc_fail"].get(name, 0) + 1
            log(f"{short(ch['name'])}: сервисы — " + ("все открываются" if not failed else "НЕ открываются: "
                + ", ".join(f"{name} ({svc.get(name)})" for name in failed)))
        if not alive:
            tcp = {"open": "порт открыт", "refused": "порт закрыт", "timeout": "порт молчит"}.get(diag["tcp"], "нет связи")
            obs, detail = "DOWN", f"не отвечает ({'пинг есть' if diag['ping'] else 'пинга нет'}, {tcp}, curl {code})"
        elif deep_res is not None:
            obs, detail = classify(ch, deep_res)
            s["quality"], s["quality_detail"] = obs, detail
        else:
            obs, detail = s["quality"], s["quality_detail"]  # между закачками держим последний замер
        if obs == s["status"]:
            s["cand"], s["streak"], s["detail"] = obs, 0, detail
        else:
            if s["cand"] == obs:
                s["streak"] += 1
            else:
                s["cand"], s["streak"], s["cand_since"] = obs, 1, now
            if s["streak"] >= CONFIRM:
                was, was_since = s["status"], s["since"]
                s["status"], s["since"], s["detail"], s["streak"] = obs, s["cand_since"], detail, 0
                s["last_remind"] = now
                if was == "OK":
                    s["inc"], hr["inc"] = s["inc"] + 1, hr["inc"] + 1
                else:
                    s["bad_sec"] += max(0, s["since"] - was_since)
                alerts.append(None)
                deferred.append((len(alerts) - 1, "alert", ch, (s, was, was_since, diag)))
        if s["status"] != "OK" and obs == s["status"] and now - s["last_remind"] >= REMIND_EVERY:
            s["last_remind"] = now
            alerts.append(None)
            deferred.append((len(alerts) - 1, "remind", ch, (s, diag)))
        if s["status"] != "OK":
            hr["bad"] += elapsed
        elif alive:
            # пинг и время соединения: рост против обычного — по медиане последних замеров, чтобы выброс не считался
            for kind, (_, _, rule) in QUAL.items():
                if len(s["win_" + kind]) >= QUAL_MIN:
                    value = statistics.median(s["win_" + kind])
                    event = quality_step(s["q_" + kind], value, s["base"].get(kind), rule, now)
                    if event:
                        q_events.append((ch, kind, event, value))
                    elif quality_calm(s["q_" + kind], now):
                        q_events.append((ch, kind, "calm", value))
        note = "" if not alive or deep_res is not None else " (прошлый замер)"
        log(f"{short(ch['name'])}: {'жив' if alive else 'НЕТ'} | вижу {obs} | состояние {s['status']} | {detail}{note}")
    # разбор сбоя: вход канала — напрямую с rf1, с других российских точек, из-за рубежа и трассировкой.
    # Когда лежит сразу много каналов, дело не в одной ноде — тогда не разбираем.
    many = len(bad_now) >= max(3, (len(chans) + 1) // 2)
    todo = [ch for _, _, ch, _ in deferred if st["channels"][ch["name"]]["status"] in ("DOWN", "FREEZE")]

    def via_for(ch):
        return next(({"name": compact(r[0]["name"]), "port": r[0]["port"]} for r in results
                     if r[1] and not r[0].get("expected_exit") and r[0].get("entry") != ch.get("entry")), None)
    deeps = blockwatch.deep_many(todo, via_for, agents, DOMAINS) if todo and not many else {}
    # «медленно», «снова работает» после «медленно» и «всё ещё медленно» сразу у многих каналов — одним сообщением
    groups = {"new": [], "back": [], "remind": []}
    for d in deferred:
        idx, what, ch, args = d
        s = st["channels"][ch["name"]]
        if what == "alert" and s["status"] == "SLOW":
            groups["new"].append(d)
        elif what == "alert" and s["status"] == "OK" and args[1] == "SLOW":
            groups["back"].append(d)
        elif what == "remind" and s["status"] == "SLOW":
            groups["remind"].append(d)
    for kind, items in groups.items():
        if len(items) >= crowd(len(chans)):
            alerts[items[0][0]] = crowd_text(kind, [(ch, st["channels"][ch["name"]], args[1] if what == "alert" else None,
                                                     args[2] if what == "alert" else None)
                                                    for _, what, ch, args in items], len(chans), now, ctrl)
            for idx, _, _, _ in items[1:]:
                alerts[idx] = ""
            deferred = [d for d in deferred if d not in items]
            log(f"одним сообщением ({kind}): " + ", ".join(short(ch["name"]) for _, _, ch, _ in items))
    filt = sorted(p for p, pr in ((st.get("profiles") or {}).get("by") or {}).items()
                  if blockwatch.profile_verdict(pr) == "filtered")
    for d in deeps.values():
        d["skip"] = st["loss"].get("skip", [])  # точки с собственной бедой сети в выводе не учитываются
        d["filtered"] = filt
    for idx, what, ch, args in deferred:
        deep_d = deeps.get(ch["name"])
        if what == "alert":
            s, was, was_since, diag = args
            alerts[idx] = alert_text(ch, s, was, was_since, diag, bad_now, len(chans), deep_d)
        else:
            s, diag = args
            alerts[idx] = remind_text(ch, s, diag, bad_now, len(chans), now, deep_d)
        if deep_d:
            note = blockwatch.name_note(deep_d)
            log(f"{short(ch['name'])}: разбор — " + "; ".join(x.lstrip("• ") for x in blockwatch.deep_lines(deep_d, extra=True))
                + " => " + blockwatch.deep_verdict(deep_d, st["channels"][ch["name"]]["status"]) + (f" | {note}" if note else ""))
    for ch, kind, event, value in q_events:
        s = st["channels"][ch["name"]]
        q = s["q_" + kind]
        if event == "calm":
            say = "calm"
        else:
            say = quality_flap(q, event, now)
        high = [n for n, c in st["channels"].items() if c["q_" + kind]["st"] == "HIGH"]
        if say:
            alerts.append(quality_alert(ch, kind, say, q, value, high, len(chans), now, s["win_" + kind]))
        if say == "calm":
            q.update(flap=0, flips=[])
        log(f"{short(ch['name'])}: {QUAL[kind][1].lower()} — {Q_EVENT[event if say == event else say]}: "
            f"сейчас {q_fmt(kind, value)}, обычно {q_fmt(kind, q['base'])}")

    # очередь: если Telegram сейчас недоступен, оповещение не теряется, а уходит при следующей проверке
    alerts = [a for a in alerts if a]  # сообщения, влитые в общее, пустые
    queue = st.setdefault("unsent", [])
    for i in range(0, len(alerts), 4):
        queue.append("🛰 <b>Сторож каналов (rf1)</b>\n\n" + "\n\n".join(alerts[i:i + 4]))
    del queue[:-20]
    while queue:
        sent = tg_send(queue[0])
        if sent == "fail":
            log(f"оповещение НЕ ушло в Telegram (нет связи), в очереди {len(queue)} — повторю при следующей проверке")
            break
        queue.pop(0)
        log("оповещение отправлено в Telegram" if sent == "ok" else "Telegram отверг оповещение — пропускаю")

    # полный отчёт — в часы из SUMMARY_HOURS_UTC, один раз на каждый час из списка
    utc = dt.datetime.now(dt.timezone.utc)
    slot = max((h for h in SUMMARY_HOURS_UTC if utc.hour >= h), default=None)
    key = f"{utc:%Y-%m-%d} {slot:02d}" if slot is not None else None
    if key and st["last_summary"] != key:
        if tg_send(report_text(st, now, read_json("sub_status.json", {}), read_json("sub_changes.json", []))) == "ok":
            log("полный отчёт отправлен в Telegram")
            st["last_summary"] = key
            st["summary_since"], st["offline_sec"] = now, 0
            for s in st["channels"].values():
                s.update(dict(PERIOD), inc=0 if s["status"] == "OK" else 1, svc_fail={}, lat=[], conn=[])
            for site in st["sites"].values():
                site.update(n=0, fails=0, inc=0 if site["status"] == "OK" else 1, bad_sec=0)
            try:
                os.remove(os.path.join(ETC, "sub_changes.json"))  # изменения в подписке показаны — начинаем копить заново
            except OSError:
                pass

    # сводка за неделю — в понедельник с первым отчётом дня, один раз на неделю; не ушла — повтор при следующей проверке
    day = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    first = min(SUMMARY_HOURS_UTC, default=None)
    if first is not None and st["last_weekly"] != week_key(now) and (day.weekday(), day.hour) >= (WEEKLY_WEEKDAY, first):
        text = weekly_text(st, load_history(), now)
        if text is None or tg_send(text) == "ok":
            st["last_weekly"] = week_key(now)
            log("сводка за неделю отправлена в Telegram" if text else "сводка за неделю: истории ещё нет")

    st["last_run"] = now
    save_state(st)


def channel_line(name, s, now):
    """Строка отчёта на канал: скорость · задержка · доступность за период."""
    name = html.escape(compact(name))
    up = "100%" if not s["fails"] else f"{100.0 * (s['checks'] - s['fails']) / s['checks']:.1f}%"
    if s["status"] != "OK":
        line = f"{ICONS[s['status']]} {name} — {STILL[s['status']]} уже {dur(now - s['since'])}"
        if s["status"] != "DOWN" and s["detail"]:
            line += f" ({html.escape(s['detail'])})"
        return line + (f" · доступность {up}" if s["checks"] else "")
    parts = []
    if s.get("big") and now - s.get("big_ts", 0) < nodewatch.BIG_FRESH:
        parts.append(f"{s['big']:.0f} Мбит/с")  # закачка 10 МБ перед отчётом — ближе к настоящей скорости
    elif s["spd_n"]:
        parts.append(f"{s['spd_sum'] / s['spd_n']:.1f} Мбит/с")
    if s["lat"]:
        parts.append(f"{statistics.median(s['lat']):.0f} мс")
    if s["checks"]:
        parts.append(up)
    line = f"✅ {name}" + (" — " + " · ".join(parts) if parts else "")
    if s["inc"]:
        line += f" ({plural(s['inc'], 'сбой', 'сбоя', 'сбоев')}" + (f", {dur(s['bad_sec'])})" if s["bad_sec"] else ")")
    if s["q_lat"].get("flap") or s["q_conn"].get("flap"):
        line += " · 〰️ " + " и ".join(n for n, k in (("пинг", "q_lat"), ("время соединения", "q_conn")) if s[k].get("flap")) + " скачет"
    elif s["q_lat"]["st"] == "HIGH":
        line += f" · ⚠️ пинг выше обычного ({q_fmt('lat', s['q_lat']['base'])})"
    if s["q_conn"]["st"] == "HIGH" and s["win_conn"]:
        line += (f" · ⚠️ соединение {q_fmt('conn', statistics.median(s['win_conn']))} "
                 f"(обычно {q_fmt('conn', s['q_conn']['base'])})")
    elif s["conn"] and statistics.median(s["conn"]) >= CONN_WARN_MS:
        line += f" · ⚠️ соединение {statistics.median(s['conn']) / 1000:.1f} с"  # обычно 0.2–0.5 с
    return line


def span_stats(buckets, t0, t1):
    """Итог по часовым записям истории за промежуток [t0, t1); None — записей нет."""
    bs = [b for b in buckets if t0 <= b["h"] < t1]
    if not bs:
        return None
    spd_n = sum(b.get("spd_n") or 0 for b in bs)
    big_n = sum(b.get("big_n") or 0 for b in bs)
    lats = [b["lat"] for b in bs if b.get("lat") is not None]
    return {"hours": len(bs), "from": min(b["h"] for b in bs),
            "big": sum(b["big"] * b["big_n"] for b in bs if b.get("big") is not None) / big_n if big_n else None,
            "checks": sum(b.get("checks", b.get("n", 0)) for b in bs), "fails": sum(b["fails"] for b in bs),
            "bad": sum(b["bad"] for b in bs), "inc": sum(b["inc"] for b in bs), "spd_n": spd_n,
            "spd": sum(b["spd"] * b["spd_n"] for b in bs if b.get("spd") is not None) / spd_n if spd_n else None,
            "lat": statistics.median(lats) if lats else None}


def week_line(name, cur):
    """Строка сводки за неделю на канал: доступность · сбои · скорость · пинг."""
    up = 100.0 * (cur["checks"] - cur["fails"]) / cur["checks"] if cur["checks"] else 100.0
    parts = ["100%" if not cur["fails"] else f"{min(up, 99.9):.1f}%",
             "без сбоев" if not cur["inc"] else plural(cur["inc"], "сбой", "сбоя", "сбоев")
             + (f", {dur(cur['bad'])}" if cur["bad"] else "")]
    if cur.get("big") is not None:
        parts.append(f"{cur['big']:.0f} Мбит/с")
    elif cur["spd"] is not None:
        parts.append(f"{cur['spd']:.1f} Мбит/с")
    if cur["lat"] is not None:
        parts.append(f"{cur['lat']:.0f} мс")
    icon = "🔴" if up < 99 else "⚠️" if cur["inc"] else "✅"
    return f"{icon} {html.escape(compact(name))} — " + " · ".join(parts)


def week_changes(name, a, b):
    """Что заметно изменилось у канала от промежутка a к промежутку b: скорость (на четверть), пинг (на четверть и 15 мс)."""
    out = []
    if a["lat"] and b["lat"] and abs(b["lat"] - a["lat"]) >= max(15, a["lat"] * 0.25):
        out.append(f"пинг {a['lat']:.0f} → {b['lat']:.0f} мс")
    if a["spd"] and b["spd"] and min(a["spd_n"], b["spd_n"]) >= 10 and abs(b["spd"] - a["spd"]) >= a["spd"] * 0.25:
        out.append(f"скорость {a['spd']:.1f} → {b['spd']:.1f} Мбит/с")
    return f"{compact(name)} — " + ", ".join(out) if out else None


def week_span(now):
    """Семь полных суток по московскому времени до последней полуночи: (начало, конец). В понедельник это прошлая неделя."""
    shift = MSK.utcoffset(None).total_seconds()
    end = int((now + shift) // 86400) * 86400 - int(shift)
    return end - WEEK, end


def weekly_text(st, hist, now):
    """Сводка за семь полных суток по почасовой истории; None — истории ещё нет."""
    start, end = week_span(now)
    rows = [(name, span_stats(hist["channels"].get(name, []), start, end)) for name in st["channels"]]
    rows = [(name, cur) for name, cur in rows if cur]
    if not rows:
        return None
    since = min(cur["from"] for _, cur in rows)
    out = [f"🗓 <b>Сводка сторожа за неделю</b> · {dm(start)}–{dm(end - 1)}"]
    if since - start > 12 * 3600:
        out.append(f"<i>История ведётся с {dm(since)}, сводка — за {dur(end - since)}.</i>")
    out += ["", "<b>Каналы</b> <i>(доступность · сбои · скорость · пинг)</i>"]
    rows.sort(key=lambda r: ((r[1]["checks"] - r[1]["fails"]) / max(1, r[1]["checks"]), -r[1]["bad"]))
    out += [week_line(name, cur) for name, cur in rows]

    # сайты: только те, у кого были сбои
    sites = [(name, span_stats(hist["sites"].get(name, []), start, end)) for name in SITE_ORDER]
    sites = [(name, cur) for name, cur in sites if cur]
    if sites:
        bad = [f"{name} — {plural(cur['inc'], 'сбой', 'сбоя', 'сбоев')}" + (f", {dur(cur['bad'])}" if cur["bad"] else "")
               for name, cur in sites if cur["inc"]]
        first = min(cur["from"] for _, cur in sites)
        out += ["", "<b>Сайты" + (f" (с {dm(first)})" if first - since > 12 * 3600 else "") + ":</b> "
                + ("; ".join(bad) + ("; остальные без сбоев" if len(bad) < len(sites) else "") if bad else "все без сбоев")]

    # серверы, счётчик сканирования и взгляд снаружи
    iso = lambda ts: f"{dt.datetime.fromtimestamp(ts, MSK):%Y-%m-%d}"
    out += nodewatch.servers_block(st["nodes"], now)
    out += nodewatch.scan_block(st["nodes"], iso(start), iso(end))
    seen = nodewatch.outside_line(st["outside"], len(st["nodes"]))
    if seen:
        out += ["", seen]
    out += blockwatch.geo_week(st)
    out += blockwatch.week_lines(st)

    # как менялись скорость и пинг: к прошлой неделе, а пока её нет — от первой половины этой недели ко второй
    prev = {name: span_stats(hist["channels"].get(name, []), start - WEEK, start) for name, _ in rows}
    if any(p and p["hours"] >= 24 for p in prev.values()):
        label, pairs = "к прошлой неделе", [(name, prev[name], cur) for name, cur in rows if prev[name]]
    elif end - since >= 2 * 86400:
        mid = since + (end - since) // 2 // 3600 * 3600
        label = f"с {dm(since)} к {dm(end - 1)}"
        pairs = [(name, span_stats(hist["channels"][name], since, mid), span_stats(hist["channels"][name], mid, end))
                 for name, _ in rows]
    else:
        label, pairs = "", []
    if label:
        changes = [c for c in (week_changes(name, a, b) for name, a, b in pairs if a and b) if c]
        out += ["", f"<b>Скорость и пинг</b> <i>({label})</i><b>:</b> "
                + (html.escape("; ".join(changes)) if changes else "без заметных изменений")]
    return "\n".join(out)


def site_cell(name, v, now):
    """Сайт в строке отчёта: сейчас и что было за период."""
    if v["status"] != "OK":
        return f"{name} ❌ не отвечает {dur(now - v['since'])}"
    if v["inc"]:
        return f"{name} ⚠️ {plural(v['inc'], 'сбой', 'сбоя', 'сбоев')}" + (f", {dur(v['bad_sec'])}" if v["bad_sec"] else "")
    if v["fails"]:
        return f"{name} ⚠️ {plural(v['fails'], 'разовый сбой', 'разовых сбоя', 'разовых сбоев')}"
    return f"{name} ✅"


def services_lines(chans):
    """Сервисы через ноды: одной строкой, если всё открывается; иначе — что и через какую ноду не открывается."""
    checked = [(compact(n), s) for n, s in chans.items() if s.get("svc") and s["status"] != "DOWN"]
    if not checked:
        return ["<b>Сервисы через ноды:</b> ещё не проверялись"]
    note = {"000": "нет соединения", "403": "отказ: адрес или регион закрыт", "429": "сервис ограничивает адрес ноды"}
    good, lines = [], []
    for svc, _, ok in SERVICES:
        down = [f"{n} ({note.get(s['svc'][svc], 'код ' + s['svc'][svc])})" for n, s in checked
                if s["svc"].get(svc, ok[0]) not in ok]
        flaky = [f"{n} ({s['svc_fail'][svc]} из {s['svc_n']} проверок)" for n, s in checked
                 if s["svc_fail"].get(svc) and s["svc"].get(svc, ok[0]) in ok]
        if down:
            lines.append(html.escape(f"❌ {svc} не открывается: " + ", ".join(down)))
        if flaky:
            lines.append(html.escape(f"⚠️ {svc} — были сбои: " + ", ".join(flaky)))
        if not down and not flaky:
            good.append(svc)
    return ["<b>Сервисы через ноды:</b>" + (" " + ", ".join(good) + " — везде ✅" if good else "")] + lines


def _is_issue(line):
    return "⚠️" in line or "❌" in line


def report_text(st, now, sub=None, changes=()):
    """Полный отчёт (v12): вверху «Требует внимания» — только если есть беды, дальше разделы по пункту на строку:
    каналы, сервисы и сайты, серверы (маячки, снаружи, DDoS и нагрузка), блокировки, сроки и подписка."""
    chans = st["channels"]
    bad = sum(s["status"] != "OK" for s in chans.values())
    attention = []

    channels = [f"📡 <b>Каналы: работают {len(chans) - bad} из {len(chans)}</b> <i>(скорость · задержка · доступность)</i>"]
    channels += [channel_line(n, s, now) for n, s in sorted(chans.items(), key=lambda kv: kv[1]["status"] == "OK")]
    if bad:
        attention.append(f"❌ <b>Каналы:</b> не работают {bad} из {len(chans)} — список в разделе «Каналы»")
    if st.get("offline_sec"):
        channels.append(f"ℹ️ У самой rf1 не было интернета {dur(st['offline_sec'])} — каналы в это время не проверялись")

    # сервисы и сайты
    services = []
    svc = services_lines(chans)
    if svc[0].rstrip().endswith("</b>"):          # «Сервисы через ноды:» без общего «везде ✅» — только беды
        services.append(svc[0] + " есть сбои — см. «Требует внимания»")
    else:
        services.append(svc[0])
    attention += svc[1:]
    sub = sub or {}
    sites = [site_cell(name, v, now) for name, v in ((n, st["sites"][n]) for n in SITE_ORDER) if v["ts"] or v["n"]]
    sites_line = "<b>Сайты:</b> " + (" · ".join(sites) if sites else "ещё не проверялись")
    (attention if _is_issue(sites_line) else services).append(sites_line)

    # серверы: маячки, взгляд снаружи, DDoS и нагрузка
    servers = []
    for line in (nodewatch.servers_line(st["nodes"], now), nodewatch.outside_line(st["outside"], len(st["nodes"]))):
        if not line:
            continue
        if _is_issue(line):
            attention.append(line)
        elif "; у заглушек " in line:     # «Снаружи»: порты и заглушки — двумя пунктами
            ports, faces = line.split("; у заглушек ", 1)
            servers += [ports, "<b>Заглушки:</b> " + faces]
        else:
            servers.append(line)
    try:
        import ddoswatch
        d_issues, d_info = ddoswatch.report_sections(st["summary_since"], now)
        attention += d_issues
        servers += d_info
    except Exception as e:  # noqa: BLE001 — сбой блока отчёт не ломает
        log("отчёт: блок DDoS не собран: %s" % e)

    # блокировки — по пункту на строку
    blocks = []
    for part in blockwatch.block_items(st, now):
        line = html.escape(part)
        if _is_issue(part):
            attention.append("<b>Блокировки:</b> " + line)
        else:
            blocks.append(line)

    # сроки: сертификаты, домены, подписка
    terms = []
    certs = {k: (v, int((v["exp"] - now) // 86400) if "exp" in v else None)
             for k, v in sorted(st["certs"].items())}
    if not certs:
        terms.append("<b>Сертификаты:</b> ещё не проверялись")
    else:
        broken = [f"❌ {k} — {v['err'] if 'err' in v else 'срок истёк'}" for k, (v, days) in certs.items()
                  if "err" in v or days < 0]
        soon = [f"⚠️ {k} — {days} дн." for k, (v, days) in certs.items()
                if "exp" in v and 0 <= days < max(3, v["life"] * CERT_WARN_PART)]
        fine = {k: days for k, (v, days) in certs.items() if "exp" in v and days >= max(3, v["life"] * CERT_WARN_PART)}
        if broken or soon:
            attention.append("<b>Сертификаты:</b> " + html.escape("; ".join(broken + soon))
                             + (f"; остальные {len(fine)} в порядке" if fine else ""))
        else:
            k = min(fine, key=fine.get)
            terms.append(f"<b>Сертификаты:</b> все {len(fine)} в порядке, ближайший срок — {k}, {fine[k]} дн.")
    doms = []
    for d in DOMAINS:
        days = int((st["domains"][d] - now) // 86400) if d in st["domains"] else None
        doms.append(f"{d} — не удалось узнать" if days is None
                    else f"{'⚠️ ' if days < DOMAIN_WARN_DAYS else ''}{d} — {days} дн.")
    dom_line = "<b>Домены:</b> " + " · ".join(doms)
    (attention if _is_issue(dom_line) else terms).append(dom_line)
    if not sub:
        terms.append("<b>Подписка:</b> ещё не проверялась")
    elif not sub.get("ok"):
        attention.append(f"<b>Подписка:</b> ❌ не загрузилась в {hm(sub.get('ts', now))} МСК"
                         + (f" ({html.escape(str(sub['error']))})" if sub.get("error") else ""))
    else:
        added = [compact(t) for c in changes for t in c.get("added", [])]
        removed = [compact(t) for c in changes for t in c.get("removed", [])]
        diff = "; ".join(p for p in ("➕ " + ", ".join(added) if added else "",
                                     "➖ " + ", ".join(removed) if removed else "") if p)
        terms.append(f"<b>Подписка:</b> {plural(sub.get('tiles', 0), 'плитка', 'плитки', 'плиток')}, "
                     + (html.escape(diff) if diff else "без изменений")
                     + (" · ❔ плитки давно не сверялись" if now - sub.get("ts", 0) > SUB_STALE else ""))

    def section(title, items):
        return ["", title] + ["• " + x for x in items] if items else []

    out = [f"🛰 <b>Отчёт сторожа (rf1)</b> · {dt.datetime.fromtimestamp(now, MSK):%d.%m %H:%M} МСК · "
           f"за {dur(now - st['summary_since'])}"]
    out += section("⚠️ <b>Требует внимания</b>", attention) if attention else ["", "✅ <b>Всё в порядке</b> — проблем нет"]
    out += [""] + channels
    out += section("🌐 <b>Сервисы и сайты</b>", services)
    out += section("🖥 <b>Серверы</b>", servers)
    out += section("🚧 <b>Блокировки</b>", blocks)
    out += section("📅 <b>Сроки</b>", terms)
    return "\n".join(out)


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(tmp, STATE)


SITE_KEYS = {"панель": "panel", SUB_NAME: "sub", "кабинет": "cabinet"}  # имена сайтов в пульсе
SITE_KEYS.update({x["name"]: x["key"] for x in SITE_CFG.get("sites", ()) if x.get("key")})
BAD_ORDER = ("OK", "SLOW", "WRONG_EXIT", "FREEZE", "DOWN")  # если у ноды несколько каналов — берём худшее состояние


def node_states(st):
    """Состояние каждой ноды глазами сторожа — для сверки со вторым сторожем (на другом сервере): {адрес ноды: {status, since}}.
    Канал относится к ноде, если входит прямо на неё; канал через ретранслятор — к ноде, на которой он выходит."""
    cfg = read_json("channels.json", {}).get("channels", [])
    nodes = read_json("nodes.json", [])
    by_ip = {}
    for n in nodes:
        try:
            by_ip[socket.gethostbyname(n["host"])] = n["host"]
        except OSError:
            pass
    hosts = {n["host"] for n in nodes}
    out = {}
    for c in cfg:
        s = st.get("channels", {}).get(c["name"])
        if not s:
            continue
        host = c.get("entry") if c.get("entry") in hosts else by_ip.get(s.get("exit"))
        if not host:
            continue
        cur = out.get(host)
        if cur is None or BAD_ORDER.index(s["status"]) > BAD_ORDER.index(cur["status"]):
            out[host] = {"status": s["status"], "since": int(s.get("since", 0))}
    return out


def beat():
    """Пульс для внешних сторожей: когда был последний запуск, ушёл ли отчёт, не копятся ли неотправленные оповещения,
    и что сторож думает о каждой ноде и сайте (по этому второй сторож решает, слать ли своё сообщение).
    Пишется после каждого запуска, который дошёл до конца."""
    try:
        path = open(HEARTBEAT, encoding="utf-8").read().strip()
    except OSError:
        return
    st = load_state()
    data = {"ts": int(time.time()), "summary": st.get("last_summary", ""), "hours": list(SUMMARY_HOURS_UTC),
            "unsent": len(st.get("unsent", [])), "offline": "offline_since" in st,
            "nodes": node_states(st), "sites": {SITE_KEYS[n]: v.get("status", "OK") for n, v in st.get("sites", {}).items()
                                                if n in SITE_KEYS and v.get("ts")}}
    try:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(path + ".tmp", 0o644)
        os.replace(path + ".tmp", path)
    except OSError as e:
        log(f"пульс не записан: {e}")


if __name__ == "__main__":
    if "--show" in sys.argv or "--report" in sys.argv:
        # отчёт по накопленному на эту минуту; статистика периода не сбрасывается
        text = report_text(init_state(load_state(), time.time()), time.time(),
                           read_json("sub_status.json", {}), read_json("sub_changes.json", []))
        print(text)
        if "--report" in sys.argv:
            print("\nотправка в Telegram:", tg_send(text))
    elif "--speed" in sys.argv:
        # закачка побольше через каждый канал, по очереди; результат забирает очередной обычный запуск
        channels = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))["channels"]
        result = nodewatch.speed_run(channels)
        with open(SPEED_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        os.replace(SPEED_FILE + ".tmp", SPEED_FILE)
        print("; ".join(f"{compact(n)}: {v if v is not None else 'не докачалось'}" for n, v in result["channels"].items()))
    elif "--lists" in sys.argv:
        # сверка наших адресов и доменов со списками блокировок; результат забирает очередной обычный запуск
        cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))
        state = load_state().get("channels", {})
        via = next((c["port"] for c in cfg["channels"] if not c.get("expected_exit")
                    and state.get(c["name"], {}).get("status") == "OK"), None)
        tg = blockwatch.targets(cfg["channels"], read_json("nodes.json", []), SITE_HOSTS, DOMAINS)
        result = blockwatch.lists_run(tg, DOMAINS, via)
        with open(blockwatch.LISTS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        os.replace(blockwatch.LISTS_FILE + ".tmp", blockwatch.LISTS_FILE)
        print(f"сверено адресов {len(tg['ips'])}, имён {len(tg['names'])}")
        for key, src in result["sources"].items():
            hits = result["hits"][key]
            print(f"  {blockwatch.LIST_NAMES[key]} ({key}): " + (f"записей {src['n']}; наших: "
                  + (", ".join(f"{who} в {rec}" for who, rec in hits.items()) or "нет") if src["ok"] else "НЕ СКАЧАЛСЯ"))
        print("  чужие адреса реестра в той же подсети /24, что наши: "
              + (", ".join(f"{who} — {n}" for who, n in sorted(result["neighbours"].items())) or "нет"))
    elif "--loss" in sys.argv:
        # фоновый замер потерь: серия соединений на вход каждой ноды с rf1 и с каждой точки; результат забирает
        # очередной обычный запуск
        cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))
        state = load_state().get("channels", {})
        via = next((c["port"] for c in cfg["channels"] if not c.get("expected_exit")
                    and state.get(c["name"], {}).get("status") == "OK"), None)
        own = tuple("." + d for d in DOMAINS)
        result = blockwatch.loss_run([n for n in read_json("nodes.json", []) if str(n.get("host", "")).endswith(own)],
                                     blockwatch.agents_cfg(), socks_port=via)
        with open(blockwatch.LOSS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        os.replace(blockwatch.LOSS_FILE + ".tmp", blockwatch.LOSS_FILE)
        print(blockwatch.loss_log(result))
        for node, pts in sorted(result["nodes"].items()):
            print(f"  {node}: " + "; ".join(
                f"{point} — " + ("нет ответа" if not r else f"не прошло {r['fail']} из {r['n']}"
                                 + (f" ({blockwatch.witness_text(r, r['wit'])})" if r.get("wit") and r["fail"] else ""))
                for point, r in pts.items()))
    elif "--side" in sys.argv:
        # профиль точек (раз в 6 ч) и гео нод (раз в 12 ч) — долгие сборы вне основного прохода; таймер раз в час
        # запускает, а делается только то, что подошло по сроку (--force — всё сразу)
        force = "--force" in sys.argv
        side = load_json(blockwatch.SIDE_FILE)

        def save_side():
            with open(blockwatch.SIDE_FILE + ".tmp", "w", encoding="utf-8") as f:
                json.dump(side, f, ensure_ascii=False)
            os.replace(blockwatch.SIDE_FILE + ".tmp", blockwatch.SIDE_FILE)

        if force or time.time() - (side.get("profiles") or {}).get("ts", 0) >= PROFILE_EVERY - 600:
            by = blockwatch.profile_fetch(blockwatch.agents_cfg())
            side["profiles"] = {"ts": time.time(), "by": by}
            save_side()
            for point, pr in sorted(by.items()):
                print("профиль " + blockwatch.profile_text(point, pr))
        agents = blockwatch.agents_cfg()
        if blockwatch.vpn_points(agents) and (force or time.time() - (side.get("vpn") or {}).get("ts", 0)
                                              >= blockwatch.VPN_EVERY - 600):
            names = [c["name"] for c in json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))["channels"]]
            side["vpn"] = {"ts": time.time(), "by": blockwatch.vpn_sweep(agents, names)}
            save_side()
            for point, res in sorted(side["vpn"]["by"].items()):
                for n, r in res.items():
                    print(f"через VPN с точки {point}: {n} — {blockwatch.vpn_text(r)}")
        if force or time.time() - (side.get("outside") or {}).get("ts", 0) >= SLOW_EVERY - 600:
            cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))["channels"]
            side["outside"] = outside_collect(read_json("nodes.json", []), cfg, load_state())
            save_side()
            seen, again = side["outside"]["seen"], side["outside"]["again"]
            for name, v in sorted(seen.items()):
                print(f"снаружи {name}: открыты {v['open']}" + (f"; заглушка: {nodewatch.face_missing(v.get('face')) or 'всё на месте'}"
                                                             if v.get("face") else "") + (" (перепроверено)" if name in again else ""))
        if force or time.time() - (side.get("geo") or {}).get("ts", 0) >= GEO_EVERY - 600:
            cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))
            data = geo_collect(cfg["channels"])
            side["geo"] = {"ts": time.time(), "data": data}
            save_side()
            for node, cur in sorted(data.items()):
                print(blockwatch.geo_line(node, cur))
    elif "--add-vantage" in sys.argv:
        # новая точка проверки: запись приходит со стандартного ввода (vantage_install.sh --entry | … --add-vantage)
        names = blockwatch.add_vantage(sys.stdin.read())
        print("точки проверки:", ", ".join(names))
        print("на связи:", blockwatch.agents_health(blockwatch.agents_cfg()))
    elif "--blocks" in sys.argv or "--blocks-report" in sys.argv:
        # проверка блокировок по запросу: списки, DNS, точки проверки и вход каждой ноды с каждой точки
        cfg = json.load(open(os.path.join(ETC, "channels.json"), encoding="utf-8"))
        res = blockwatch.full_check(cfg["channels"], read_json("nodes.json", []), SITE_HOSTS, DOMAINS,
                                    load_state().get("channels", {}))
        with open(blockwatch.LISTS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(res["lists"], f, ensure_ascii=False)  # свежую сверку заберёт и обычный запуск
        os.replace(blockwatch.LISTS_FILE + ".tmp", blockwatch.LISTS_FILE)
        text = blockwatch.check_text(res, f"{dt.datetime.fromtimestamp(time.time(), MSK):%d.%m %H:%M} МСК")
        print(text)
        if "--blocks-report" in sys.argv:
            print("\nотправка в Telegram:", tg_send(text))
    elif "--week" in sys.argv or "--week-report" in sys.argv:
        # сводка за последние семь суток по накопленной истории
        text = weekly_text(init_state(load_state(), time.time()), load_history(), time.time())
        print(text or "истории ещё нет")
        if text and "--week-report" in sys.argv:
            print("\nотправка в Telegram:", tg_send(text))
    else:
        main()
        beat()
