#!/usr/bin/env python3
"""channel-watch-guard: сторож за сторожем каналов (запуск по таймеру раз в 5 минут, на другом сервере).

Читает пульс, который сторож каналов на rf1 пишет после каждого запуска (probe.py, beat()), и сообщает в Telegram,
если:
  - rf1 не отвечает — пульс не читается;
  - сервер отвечает, но сторож давно не запускался (или файла пульса нет);
  - сторож работает, но у rf1 нет выхода в интернет — каналы не проверяются;
  - сторож работает, но не может отправить сообщения: копится очередь либо не ушёл отчёт.
Смена состояния — после CONFIRM проверок подряд; напоминание раз в REMIND_EVERY; возврат в норму — с длительностью.
Настройки — /etc/channel-watch-guard/guard.env: HEARTBEAT_URL, TG_TOKEN, TG_CHAT, по желанию GUARD_NAME.
Вручную: guard.py --show — что видно сейчас; guard.py --test — то же и пробное сообщение в Telegram.
"""
import datetime as dt
import html
import http.client
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ENV = "/etc/channel-watch-guard/guard.env"
STATE = "/var/lib/channel-watch-guard/state.json"
LOG = "/var/log/channel-watch-guard.log"
STALE = 600               # пульс старше — сторож не запускается (он идёт каждые 2 минуты)
REPORT_GRACE = 1500       # отчёт должен уйти не позже чем через столько секунд после своего часа
CONFIRM = 2               # сколько проверок подряд нужно, чтобы сменить состояние
REMIND_EVERY = 3 * 3600   # напоминать, пока сторож не в порядке
MSK = dt.timezone(dt.timedelta(hours=3))
UA = "channel-watch-guard"

TITLES = {"UNREACH": "🔴 <b>rf1 не отвечает — сторож каналов недоступен</b>",
          "STALE": "🟠 <b>Сторож каналов на rf1 не работает</b>",
          "BLIND": "🟠 <b>У rf1 нет выхода в интернет — каналы не проверяются</b>",
          "MUTED": "🟠 <b>Сторож каналов не может отправить сообщения</b>"}
EFFECT = {"UNREACH": "Пока так, о сбоях каналов и сайтов никто не сообщит.",
          "STALE": "Пока так, о сбоях каналов и сайтов никто не сообщит.",
          "BLIND": "Пока так, о сбоях каналов никто не сообщит; сам сторож работает.",
          "MUTED": "Тревоги копятся на rf1 и придут, когда оттуда снова будет доступен Telegram."}
WAS = {"UNREACH": "rf1 не отвечал", "STALE": "сторож не запускался", "BLIND": "у rf1 не было интернета",
       "MUTED": "сторож не мог отправить сообщения"}


def read_env():
    env = {}
    try:
        for line in open(ENV, encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


def fetch(url):
    """Пульс сторожа: ('ok', пульс) | ('nofile', None) — сервер ответил, но это не пульс | ('unreach', None)."""
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read(65536)
        except urllib.error.HTTPError:
            return "nofile", None
        except (OSError, http.client.HTTPException):
            if attempt == 1:
                time.sleep(5)
            continue
        try:
            hb = json.loads(raw.decode("utf-8"))
        except ValueError:
            return "nofile", None  # файла нет — сайт на rf1 отдаёт вместо него свою главную страницу
        return ("ok", hb) if isinstance(hb, dict) and isinstance(hb.get("ts"), (int, float)) else ("nofile", None)
    return "unreach", None


def port_open(url):
    """Отвечает ли сам сервер (TCP на порт сайта), когда пульс прочитать не удалось."""
    u = urllib.parse.urlsplit(url)
    try:
        socket.create_connection((u.hostname, u.port or 443), timeout=6).close()
        return True
    except OSError:
        return False


def hm(ts):
    return dt.datetime.fromtimestamp(ts, MSK).strftime("%H:%M")


def dur(seconds):
    m = max(1, int(round(seconds / 60)))
    if m < 60:
        return f"{m} мин"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h} ч {m:02d} мин"
    d, h = divmod(h, 24)
    return f"{d} д {h} ч"


def overdue_report(hb, now):
    """Час отчёта (UTC), который уже должен был уйти, но не ушёл; None — отчёты идут вовремя."""
    hours = [h for h in hb.get("hours", []) if isinstance(h, int)]
    if not hours:
        return None
    limit = dt.datetime.fromtimestamp(now - REPORT_GRACE, dt.timezone.utc)
    slots = [(day, h) for day in (limit.date(), limit.date() - dt.timedelta(days=1)) for h in hours
             if dt.datetime(day.year, day.month, day.day, h, tzinfo=dt.timezone.utc) <= limit]
    day, hour = max(slots)
    return hour if str(hb.get("summary", "")) < f"{day:%Y-%m-%d} {hour:02d}" else None


def observe(kind, hb, now, alive):
    """Что видно сейчас: (состояние, подробность). alive — отвечает ли порт сайта на rf1 (при 'unreach')."""
    if kind == "unreach":
        return "UNREACH", ("порт сайта на rf1 открыт, но сайт не отвечает — на rf1 не работает сайт-прикрытие (caddy) "
                           "или вход VPN" if alive else "сервер не отвечает совсем — выключен, перезагружается "
                           "либо у хостера пропала сеть")
    if kind == "nofile":
        return "STALE", "сервер отвечает, но файла пульса на нём нет"
    age = now - hb["ts"]
    if age > STALE:
        return "STALE", f"сервер отвечает, но сторож не запускался {dur(age)} (последний раз в {hm(hb['ts'])} МСК)"
    if hb.get("offline"):
        return "BLIND", "сторож запускается, но контрольный запрос без VPN с rf1 не проходит"
    if hb.get("unsent"):
        return "MUTED", f"в очереди на rf1 неотправленных оповещений: {hb['unsent']} — похоже, с rf1 недоступен Telegram"
    hour = overdue_report(hb, now)
    if hour is not None:
        return "MUTED", f"отчёт в {(hour + 3) % 24:02d}:00 МСК не ушёл — похоже, с rf1 недоступен Telegram"
    return "OK", f"последний запуск {int(age)} с назад, отчёт «{hb.get('summary', '')}» UTC"


def alert_text(s, was, was_since):
    if s["status"] == "OK":
        return (f"✅ <b>Сторож каналов снова в порядке</b>\nПерерыв {dur(s['since'] - was_since)} "
                f"(с {hm(was_since)} до {hm(s['since'])} МСК): {WAS[was]}.")
    return f"{TITLES[s['status']]}\nС {hm(s['since'])} МСК: {html.escape(s['detail'])}.\n{EFFECT[s['status']]}"


def remind_text(s, now):
    return (f"⏳ {TITLES[s['status']]} — уже {dur(now - s['since'])} (с {hm(s['since'])} МСК).\n"
            f"Сейчас: {html.escape(s['detail'])}.")


def tg_send(env, text):
    """'ok' — доставлено; 'bad' — Telegram отверг само сообщение (повторять бесполезно); 'fail' — нет связи."""
    if not env.get("TG_TOKEN") or not env.get("TG_CHAT"):
        return "fail"
    data = urllib.parse.urlencode({"chat_id": env["TG_CHAT"], "text": text, "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    try:
        with urllib.request.urlopen(f"https://api.telegram.org/bot{env['TG_TOKEN']}/sendMessage", data=data, timeout=20):
            return "ok"
    except urllib.error.HTTPError as e:
        return "bad" if e.code == 400 else "fail"
    except (OSError, http.client.HTTPException):
        return "fail"


def log(line):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%dT%H:%M:%SZ} {line}\n")


def load_state(now):
    try:
        st = json.load(open(STATE, encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    for k, v in (("status", "OK"), ("cand", "OK"), ("streak", 0), ("detail", ""), ("since", now),
                 ("cand_since", now), ("last_remind", 0), ("unsent", [])):
        st.setdefault(k, v)
    return st


def save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    os.replace(STATE + ".tmp", STATE)


def look(env, now):
    kind, hb = fetch(env.get("HEARTBEAT_URL", ""))
    return observe(kind, hb, now, kind == "unreach" and port_open(env.get("HEARTBEAT_URL", "")))


def main():
    env, now = read_env(), time.time()
    name = env.get("GUARD_NAME") or socket.gethostname()
    s = load_state(now)
    obs, detail = look(env, now)
    alerts = []
    if obs == s["status"]:
        s["cand"], s["streak"], s["detail"] = obs, 0, detail
    else:
        if s["cand"] == obs:
            s["streak"] += 1
        else:
            s["cand"], s["streak"], s["cand_since"] = obs, 1, now
        if s["streak"] >= CONFIRM:
            was, was_since = s["status"], s["since"]
            s["status"], s["since"], s["detail"], s["streak"], s["last_remind"] = obs, s["cand_since"], detail, 0, now
            alerts.append(alert_text(s, was, was_since))
    if s["status"] != "OK" and obs == s["status"] and now - s["last_remind"] >= REMIND_EVERY:
        s["last_remind"] = now
        alerts.append(remind_text(s, now))
    log(f"вижу {obs} | состояние {s['status']} | {detail}")

    # очередь: если Telegram отсюда сейчас недоступен, сообщение уйдёт при следующей проверке
    queue = s["unsent"]
    queue += [f"🛡 <b>Сторож за сторожем ({html.escape(name)})</b>\n\n{a}" for a in alerts]
    del queue[:-10]
    while queue:
        sent = tg_send(env, queue[0])
        if sent == "fail":
            log(f"сообщение НЕ ушло в Telegram (нет связи), в очереди {len(queue)} — повторю при следующей проверке")
            break
        queue.pop(0)
        log("сообщение отправлено в Telegram" if sent == "ok" else "Telegram отверг сообщение — пропускаю")
    save_state(s)


if __name__ == "__main__":
    if "--show" in sys.argv or "--test" in sys.argv:
        env = read_env()
        obs, detail = look(env, time.time())
        print(f"{obs}: {detail}")
        if "--test" in sys.argv:
            name = html.escape(env.get("GUARD_NAME") or socket.gethostname())
            print("отправка в Telegram:", tg_send(env, f"🛡 <b>Сторож за сторожем ({name})</b>\n\nПроверка связи. "
                                                       f"Сейчас вижу: {html.escape(detail)}."))
        sys.exit(0 if obs == "OK" else 1)
    main()
