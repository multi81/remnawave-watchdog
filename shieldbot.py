#!/usr/bin/env python3
"""channel-watch: кнопки щита в Telegram (ваш бот). Блокировки — только с подтверждением, без
автоматики. Сторож (ddoswatch) предлагает — эта служба выполняет только то, что владелец нажал:
  * предложение = сообщение с кнопками; кнопка одноразовая и живёт OFFER_TTL; нажатие принимается только от того, кому
    сторож пишет (BW_TG_CHAT — личный чат владельца, проверяется и чат, и отправитель);
  * выполнение — на сервере по SSH отдельным ключом /etc/channel-watch/shield_ed25519, который на сервере умеет только
    `shield-ctl --ssh` (status, block, unblock, mode); адреса из списка своих и частные там отказываются ещё раз;
  * команды в чате: /shield — что где заблокировано и включено, /unblock — снять блокировки (тоже кнопкой);
  * сверка с нашими клиентами: перед предложением ноды отвечают, кто из подозрительных — наш клиент
    (по журналу Xray за сутки); «Заблокировать» берёт только чужих, наших — отдельная кнопка «всех» с предупреждением.
Работает постоянно (служба channel-watch-shieldbot): читает обновления бота длинным опросом. Без внешних зависимостей.
Запуск: shieldbot.py           — служба
        shieldbot.py --status  — то же, что /shield, в консоль
"""
import datetime as dt
import html
import json
import os
import secrets
import subprocess
import sys
import threading
import time

try:
    import fcntl
except ImportError:   # Windows (тесты на ПК) — без блокировки файла
    fcntl = None

ETC = "/etc/channel-watch"
OFFERS_FILE = "/var/lib/channel-watch/shield_offers.json"
BOT_STATE = "/var/lib/channel-watch/shieldbot.json"
KEY = ETC + "/shield_ed25519"
KNOWN = ETC + "/shield_known_hosts"
OFFER_TTL = 12 * 3600       # кнопка живёт 12 ч: ночное предложение должно дожить до утра
RECHECK_AFTER = 1800        # нажали позже 30 мин — сначала перепроверить, шумят ли адреса сейчас
INCIDENT_WINDOW = 3600      # повтор по тому же серверу в течение часа — правим прежнее сообщение, не шлём новое
FOLLOWUP_AFTER = 600        # итог блокировки — через 10 минут
OVERRIDE_DAYS = 7           # «Это не атака» — порог сервера выше на неделю
DDOS_STATE = "/var/lib/channel-watch/ddos_state.json"
OVERRIDES_FILE = "/var/lib/channel-watch/ddos_overrides.json"
MSK = dt.timezone(dt.timedelta(hours=3))
ACTIONS = {"b1": ("block", 3600, "заблокированы на 1 час"), "b24": ("block", 86400, "заблокированы на сутки"),
           "b1a": ("block_all", 3600, "заблокированы на 1 час, вместе с нашими клиентами"),
           "na": ("not_attack", 0, "это не атака"), "y": ("confirm", 0, "подтверждено"),
           "on2": ("on", 2, "щит включён на 2 часа"), "ua": ("unblock", 0, "блокировки сняты"),
           "no": ("none", 0, "оставлено как есть")}


def msk(ts):
    return dt.datetime.fromtimestamp(ts, MSK)


def cnt(v):
    return "{:,}".format(int(v)).replace(",", " ")


# ---------- Telegram ----------
def _probe():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import probe
    return probe


def tg_call(method, payload, timeout=20):
    """-> ответ Telegram (dict) или None. Маршруты — как у сторожа (напрямую, через свой канал, мост)."""
    probe = _probe()
    token, _ = probe.tg_env()
    if not token:
        return None
    url = "https://api.telegram.org/bot%s/%s" % (token, method)
    for proxy in probe.tg_routes():
        cmd = ["curl", "-s", "-m", str(timeout), "-X", "POST", "-H", "Content-Type: application/json", "-d", "@-", url]
        if proxy:
            cmd[1:1] = ["-x", proxy]
        try:
            r = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout + 5)
            d = json.loads(r.stdout or "null")
        except (subprocess.TimeoutExpired, ValueError, OSError):
            continue
        if isinstance(d, dict):
            return d
    return None


def owner_chat():
    return str(_probe().tg_env()[1] or "")


# ---------- предложения ----------
class Offers:
    """Файл предложений с блокировкой (пишут ddoswatch и эта служба)."""

    def __init__(self, path=OFFERS_FILE):
        self.path = path

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.f = open(self.path + ".lock", "w")
        if fcntl:
            fcntl.flock(self.f, fcntl.LOCK_EX)
        try:
            self.data = json.load(open(self.path, encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        return self.data

    def __exit__(self, *a):
        offers = {k: v for k, v in self.data.items() if not k.startswith("_")}
        t = max([v.get("created", 0) for v in offers.values()] or [0])   # от самой свежей записи, не от часов (тесты, сбитые часы)
        for k in [k for k, v in offers.items() if t - v.get("created", 0) > 2 * 86400]:
            del self.data[k]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False)
        os.replace(tmp, self.path)
        if fcntl:
            fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


ALLOWED = {"block": {"b1", "b24", "b1a", "on2", "no"}, "attack": {"b1", "b24", "b1a", "on2", "na", "no"},
           "unblock": {"ua", "no"}, "confirm": {"y", "no"}}


def keyboard(oid, kind, host="", n_ips=0, n_clients=0):
    if kind == "confirm":
        return {"inline_keyboard": [[{"text": "✅ Да, заблокировать", "callback_data": "sh:%s:y" % oid},
                                     {"text": "Нет", "callback_data": "sh:%s:no" % oid}]]}
    if kind == "unblock":
        return {"inline_keyboard": [[{"text": "🔓 Снять все блокировки: %s" % host, "callback_data": "sh:%s:ua" % oid}],
                                    [{"text": "Отмена", "callback_data": "sh:%s:no" % oid}]]}
    rows = []
    if n_ips > n_clients:
        what = "чужих" if n_clients else ""
        rows.append([{"text": ("🛡 Заблокировать %s на 1 ч" % what).replace("  ", " "), "callback_data": "sh:%s:b1" % oid},
                     {"text": "🛡 На сутки", "callback_data": "sh:%s:b24" % oid}])
    rows.append([{"text": "🛡 Включить щит на 2 ч", "callback_data": "sh:%s:on2" % oid}])
    if n_clients:
        rows.append([{"text": "⚠️ Всех на 1 ч, и наших клиентов (%d)" % n_clients, "callback_data": "sh:%s:b1a" % oid}])
    if kind == "attack":
        rows.append([{"text": "Это не атака (поднять порог)", "callback_data": "sh:%s:na" % oid}])
    rows.append([{"text": "Не трогать", "callback_data": "sh:%s:no" % oid}])
    return {"inline_keyboard": rows}


def new_offer(host, kind, ips, now=None, offers_path=OFFERS_FILE, clients=None, extra=None):
    oid = secrets.token_hex(5)
    with Offers(offers_path) as d:
        d[oid] = dict({"host": host, "kind": kind, "ips": list(ips), "clients": list(clients or []),
                       "created": int(now or time.time()), "used": False}, **(extra or {}))
    return oid


def send_incident(host, kind, ips, text, tg=tg_call, chat=None, offers_path=OFFERS_FILE, now=None, clients=None, peak=None):
    """Одно сообщение на случай: если по этому серверу за последний час уже было — правим его (текст и кнопки),
    прежние кнопки гасим. -> id предложения или None."""
    now = now or time.time()
    chat = chat or owner_chat()
    clients = [a for a in (clients or []) if a in ips]
    with Offers(offers_path) as d:
        prev = (d.get("_msgs") or {}).get(host)
    if prev and now - prev.get("first", 0) < INCIDENT_WINDOW and prev.get("mid"):
        oid = new_offer(host, kind, ips, now=now, offers_path=offers_path, clients=clients, extra={"peak": peak or {}})
        r = tg("editMessageText", {"chat_id": chat, "message_id": prev["mid"], "parse_mode": "HTML",
                                   "disable_web_page_preview": True,
                                   "text": text + "\n\n<i>Обновлено %s МСК. Кнопки действуют 12 часов.</i>" % msk(now).strftime("%H:%M"),
                                   "reply_markup": keyboard(oid, kind, host, len(ips), len(clients))})
        if (r or {}).get("ok"):
            with Offers(offers_path) as d:
                if prev.get("oid") in d and not d[prev["oid"]].get("used"):
                    d[prev["oid"]].update(used=True, act="replaced", used_at=int(now))
                d.setdefault("_msgs", {})[host] = dict(prev, oid=oid, ts=int(now))
                d[oid]["message_id"] = prev["mid"]
            return oid
        with Offers(offers_path) as d:   # не вышло (сообщение удалено и т.п.) — новое
            d.pop(oid, None)
    oid = send_offer(host, kind, ips, text, tg=tg, chat=chat, offers_path=offers_path, now=now, clients=clients,
                     extra={"peak": peak or {}})
    if oid:
        with Offers(offers_path) as d:
            d.setdefault("_msgs", {})[host] = {"mid": d[oid].get("message_id"), "oid": oid, "first": int(now), "ts": int(now)}
    return oid


def send_offer(host, kind, ips, text, tg=tg_call, chat=None, offers_path=OFFERS_FILE, now=None, clients=None, extra=None):
    """Предложение с кнопками владельцу. -> id или None (не отправилось). clients — кто из ips наш клиент."""
    clients = [a for a in (clients or []) if a in ips]
    oid = new_offer(host, kind, ips, now=now, offers_path=offers_path, clients=clients, extra=extra)
    r = tg("sendMessage", {"chat_id": chat or owner_chat(), "text": text + "\n\n<i>Кнопки действуют 12 часов.</i>",
                           "parse_mode": "HTML", "disable_web_page_preview": True,
                           "reply_markup": keyboard(oid, kind, host, len(ips), len(clients))})
    if not (r or {}).get("ok"):
        return None
    with Offers(offers_path) as d:
        if oid in d:
            d[oid]["message_id"] = r["result"]["message_id"]
    return oid


# ---------- выполнение на сервере ----------
def hosts():
    try:
        return {h["name"]: h for h in json.load(open(os.path.join(ETC, "ddos.json"), encoding="utf-8"))["hosts"]}
    except (OSError, ValueError, KeyError):
        return {}


def run_ctl(host, args, hs=None, inp=None):
    """shield-ctl на сервере (через ключ щита). inp — на stdin (список сканеров). -> dict ответа или {"ok": False, …}."""
    h = (hs or hosts()).get(host)
    if not h:
        return {"ok": False, "error": "нет такого сервера в ddos.json"}
    cmd = ["ssh", "-i", KEY, "-p", str(h.get("port", 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + KNOWN, "root@" + h["host"]] + [str(a) for a in args]
    try:
        r = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=120 if inp else 60)
        return json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {"ok": False, "error": "нет ответа (код %d)" % r.returncode}
    except (subprocess.TimeoutExpired, ValueError, OSError, IndexError) as e:
        return {"ok": False, "error": "сервер не ответил: %s" % str(e)[:100]}


def lookup_clients(ips, hs=None, run=None):
    """Спросить все серверы со щитом, кто из адресов — наш клиент. -> {адрес: {user, last, n, node}} (самое свежее)."""
    run = run or run_ctl
    hs = hs or hosts()
    out, th, lock, answered = {}, [], threading.Lock(), []

    def ask(name):
        r = run(name, ["clients"] + list(ips), hs)
        if (r or {}).get("ok"):
            answered.append(name)
        for a, v in ((r or {}).get("clients") or {}).items() if (r or {}).get("ok") else []:
            with lock:
                if a not in out or v.get("last", 0) > out[a].get("last", 0):
                    out[a] = dict(v, node=name)
    for name in hs:
        t = threading.Thread(target=ask, args=(name,))
        t.start()
        th.append(t)
    for t in th:
        t.join(70)
    return out if answered else None   # None — никто не ответил, сверки нет


def result_text(host, act, res, now):
    if act == "na":
        if not res.get("ok"):
            return "⚠️ <b>Щит, %s:</b> %s" % (html.escape(host), html.escape(str(res.get("error"))))
        return ("✅ <b>%s:</b> понял, это не атака. Порог тревоги поднят до %.0f Мбит/с и %s пак/с до %s — такой трафик "
                "больше не тревожит; если будет сильнее — сообщу." % (html.escape(host), res["rx_bps"] / 1e6,
                                                                      cnt(res["rx_pps"]), msk(res["until"]).strftime("%d.%m")))
    what = ACTIONS[act][2]
    if not res.get("ok"):
        return "⚠️ <b>Щит, %s:</b> не вышло — %s" % (html.escape(host), html.escape(str(res.get("error"))))
    if act in ("b1", "b24", "b1a"):
        n = len(res.get("blocked") or [])
        word = "адрес" if n % 10 == 1 and n % 100 != 11 else "адреса" if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else "адресов"
        what = what.replace("заблокированы", "заблокирован") if word == "адрес" else what
        lines = ["✅ <b>Щит, %s:</b> %d %s %s, до %s МСК" % (html.escape(host), n, word, what,
                                                                  msk(res.get("until", now)).strftime("%d.%m %H:%M"))]
        if res.get("refused"):
            lines.append("Не тронуты: " + ", ".join("%s (%s)" % (html.escape(a), html.escape(w)) for a, w in res["refused"]))
        lines.append("Снять раньше — /unblock")
        return "\n".join(lines)
    if act == "on2":
        return ("✅ <b>Щит, %s:</b> %s — до %s МСК режется всё сверх порога с одного адреса; потом сам вернётся в "
                "наблюдение. Выключить раньше — /unblock" % (html.escape(host), what, msk(res.get("until", now)).strftime("%H:%M")))
    if act == "ua":
        return "✅ <b>Щит, %s:</b> %s (%d), щит в режиме наблюдения" % (html.escape(host), what, len(res.get("unblocked") or []))
    return "Щит, %s: %s" % (html.escape(host), what)


def attack_now(host, path=None):
    try:
        return (json.load(open(path or DDOS_STATE, encoding="utf-8")).get("hosts", {}).get(host) or {}).get("verdict") == "attack"
    except (OSError, ValueError):
        return False


def raise_threshold(host, peak, now, path=None):
    """«Это не атака»: порог сервера = пик ×1,5 на неделю (только вверх). -> что поставили или ошибка."""
    rx, pps = float(peak.get("rx_bps") or 0), float(peak.get("rx_pps") or 0)
    if rx <= 0 and pps <= 0:
        return {"ok": False, "error": "в сообщении нет пика трафика — порог не поднять"}
    path = path or OVERRIDES_FILE
    try:
        d = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    cur = d.get(host) or {}
    v = {"rx_bps": max(rx * 1.5, float(cur.get("rx_bps") or 0)), "rx_pps": max(pps * 1.5, float(cur.get("rx_pps") or 0)),
         "until": int(now + OVERRIDE_DAYS * 86400), "set": int(now)}
    d[host] = v
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(path + ".tmp", path)
    return dict(v, ok=True)


def execute(offer, act, run=run_ctl):
    host, kind = offer["host"], ACTIONS[act][0]
    if kind == "confirm":
        return execute(dict(offer, kind=offer.get("for_kind", "block")), offer["act"], run)
    if kind == "block":
        ips = [a for a in offer.get("ips") or [] if a not in (offer.get("clients") or [])]
        if not ips:
            return {"ok": False, "error": "чужих адресов нет — все подозрительные наши клиенты"}
        return run(host, ["block", ACTIONS[act][1]] + ips)
    if kind == "block_all":
        if not offer.get("ips"):
            return {"ok": False, "error": "в предложении нет адресов"}
        return run(host, ["block", ACTIONS[act][1], "--clients"] + offer["ips"])
    if kind == "on":
        return run(host, ["mode", "on", ACTIONS[act][1]])
    if kind == "unblock":
        r1 = run(host, ["unblock", "all"])
        r2 = run(host, ["mode", "watch"])
        return r1 if not r1.get("ok") else r2 if not r2.get("ok") else r1
    return {"ok": True}


# ---------- обработка обновлений ----------
def status_text(statuses, now):
    lines = ["🛡 <b>Щит: состояние</b> (%s МСК)" % msk(now).strftime("%d.%m %H:%M")]
    for host, s in sorted(statuses.items()):
        if not s.get("ok"):
            lines.append("• %s — %s" % (html.escape(host), "щит не стоит" if s.get("loaded") is False else
                                        "не ответил: " + html.escape(str(s.get("error"))[:80])))
            continue
        mode = "включён до %s" % msk(s["until"]).strftime("%H:%M") if s.get("mode") == "on" else "наблюдение"
        part = "• <b>%s</b> — %s" % (html.escape(host), mode)
        if s.get("blocked"):
            part += " · заблокировано %d" % len(s["blocked"])
        if s.get("suspects"):
            part += " · подозрительных %d (больше всех %s — %s лишних)" % (
                s.get("suspects_total", len(s["suspects"])), html.escape(s["suspects"][0][0]), cnt(s["suspects"][0][1]))
        lines.append(part)
    return "\n".join(lines)


def all_status(hs=None, run=run_ctl):
    hs = hs or hosts()
    out, th = {}, []
    for name in hs:
        t = threading.Thread(target=lambda n=name: out.__setitem__(n, run(n, ["status"], hs)))
        t.start()
        th.append(t)
    for t in th:
        t.join(70)
    return out


def handle(upd, chat, tg=tg_call, run=run_ctl, status=all_status, now=None, offers_path=OFFERS_FILE):
    """Одно обновление Telegram. -> что сделано (строка для журнала) или None."""
    now = now or time.time()
    cq = upd.get("callback_query")
    if cq:
        frm = str((cq.get("from") or {}).get("id"))
        cchat = str(((cq.get("message") or {}).get("chat") or {}).get("id"))
        parts = str(cq.get("data") or "").split(":")
        if frm != chat or cchat != chat:
            tg("answerCallbackQuery", {"callback_query_id": cq["id"], "text": "Нет доступа"})
            return "кнопка от чужого (%s) — отказ" % frm
        if len(parts) != 3 or parts[0] != "sh" or parts[2] not in ACTIONS:
            tg("answerCallbackQuery", {"callback_query_id": cq["id"], "text": "Не понимаю кнопку"})
            return "непонятная кнопка"
        oid, act = parts[1], parts[2]
        with Offers(offers_path) as d:
            o = d.get(oid) if not oid.startswith("_") else None
            bad = ("кнопка не найдена" if not o else
                   "это сообщение уже обновлено — нажмите кнопку в новом" if o.get("act") == "replaced" else
                   "уже выполнено" if o.get("used") else
                   "кнопка устарела (больше 12 часов)" if now - o.get("created", 0) > OFFER_TTL else
                   "эта кнопка не для этого предложения" if act not in ALLOWED.get(o.get("kind"), set()) else "")
            if not bad:
                o["used"], o["act_done"], o["used_at"] = True, act, int(now)
                o = dict(o)
        mid = (cq.get("message") or {}).get("message_id")
        if bad:
            tg("answerCallbackQuery", {"callback_query_id": cq["id"], "text": bad, "show_alert": True})
            if mid:
                tg("editMessageReplyMarkup", {"chat_id": chat, "message_id": mid, "reply_markup": {"inline_keyboard": []}})
            return "кнопка %s: %s" % (act, bad)
        tg("answerCallbackQuery", {"callback_query_id": cq["id"], "text": "Выполняю…" if act != "no" else "Хорошо"})
        if mid:
            tg("editMessageReplyMarkup", {"chat_id": chat, "message_id": mid, "reply_markup": {"inline_keyboard": []}})
        if act in ("b1", "b24", "b1a") and now - o.get("created", now) > RECHECK_AFTER:
            st = run(o["host"], ["status"])
            noisy = {a for a, _ in (st.get("suspects") or [])} if st.get("ok") else set(o["ips"])
            if not (noisy & set(o["ips"])) and not attack_now(o["host"]):
                cid = new_offer(o["host"], "confirm", o["ips"], now=now, offers_path=offers_path, clients=o.get("clients"),
                                extra={"act": act, "for_kind": o.get("kind"), "peak": o.get("peak") or {}})
                tg("sendMessage", {"chat_id": chat, "parse_mode": "HTML", "reply_to_message_id": mid,
                                   "text": "⏳ <b>%s:</b> предложение от %s МСК — эти адреса сейчас уже не шумят, атаки на сервере нет. "
                                           "Всё равно заблокировать?" % (html.escape(o["host"]), msk(o["created"]).strftime("%H:%M")),
                                   "reply_markup": keyboard(cid, "confirm")})
                return "кнопка %s %s: перепроверка — уже тихо, спросила подтверждение" % (act, o["host"])
        if act == "na":
            res = raise_threshold(o["host"], o.get("peak") or {}, now)
        else:
            base = None
            eff = o.get("act") if act == "y" else act
            if eff in ("b1", "b24", "b1a"):
                st0 = run(o["host"], ["status"])
                base = (st0.get("counters") or {}).get("dropped_blocked", 0) if st0.get("ok") else None
            res = execute(o, act, run)
            if res.get("ok") and eff in ("b1", "b24", "b1a") and res.get("blocked"):
                with Offers(offers_path) as d:
                    d.setdefault("_follow", []).append({"host": o["host"], "at": int(now + FOLLOWUP_AFTER), "base": base,
                                                        "n": len(res["blocked"]), "mid": mid, "ts": int(now)})
            act = eff if act == "y" else act
        tg("sendMessage", {"chat_id": chat, "text": result_text(o["host"], act, res, now), "parse_mode": "HTML",
                           "reply_to_message_id": mid} if mid else
           {"chat_id": chat, "text": result_text(o["host"], act, res, now), "parse_mode": "HTML"})
        return "кнопка %s %s: %s" % (act, o["host"], "ok" if res.get("ok") else res.get("error"))
    msg = upd.get("message") or {}
    if str((msg.get("chat") or {}).get("id")) != chat or str((msg.get("from") or {}).get("id")) != chat:
        return None
    text = (msg.get("text") or "").strip().split("@")[0]
    if text == "/shield":
        tg("sendMessage", {"chat_id": chat, "text": status_text(status(), now), "parse_mode": "HTML"})
        return "/shield"
    if text == "/unblock":
        st = status()
        targets = [h for h, s in st.items() if s.get("ok") and (s.get("blocked") or s.get("mode") == "on")]
        if not targets:
            tg("sendMessage", {"chat_id": chat, "text": "🛡 Блокировок нет, щит везде в режиме наблюдения."})
        for h in targets:
            s = st[h]
            send_offer(h, "unblock", [], "🔓 <b>%s</b>: заблокировано %d%s. Снять всё и вернуть щит в наблюдение?" % (
                html.escape(h), len(s.get("blocked") or []), ", щит включён" if s.get("mode") == "on" else ""),
                tg=tg, chat=chat, offers_path=offers_path, now=now)
        return "/unblock: %d" % len(targets)
    return None


def process_followups(chat, tg=tg_call, run=run_ctl, now=None, offers_path=OFFERS_FILE, state_path=None):
    """Итоги блокировок, которым пора (через 10 минут): сколько отрезано и идёт ли атака. -> сколько отправлено."""
    now = now or time.time()
    with Offers(offers_path) as d:
        due = [f for f in d.get("_follow", []) if f["at"] <= now]
        d["_follow"] = [f for f in d.get("_follow", []) if f["at"] > now]
    for f in due:
        st = run(f["host"], ["status"])
        if st.get("ok") and f.get("base") is not None:
            cut = max(int((st.get("counters") or {}).get("dropped_blocked", 0)) - int(f["base"]), 0)
            part = "отрезано %s пакетов от %d адресов" % (cnt(cut), f["n"])
        else:
            part = "сколько отрезано — сервер не ответил"
        tail = ("атака на сервере ещё идёт — можно включить щит на 2 ч (/shield)" if attack_now(f["host"], state_path)
                else "атаки на сервере сейчас нет")
        tg("sendMessage", dict({"chat_id": chat, "parse_mode": "HTML",
                                "text": "📋 <b>Итог блокировки, %s</b> (через 10 минут): %s; %s." % (html.escape(f["host"]), part, tail)},
                               **({"reply_to_message_id": f["mid"]} if f.get("mid") else {})))
    return len(due)


def main(argv):
    probe = _probe()
    chat = owner_chat()
    if "--status" in argv:
        print(status_text(all_status(), time.time()))
        return 0
    if not chat:
        print("нет BW_TG_CHAT")
        return 1
    try:
        offset = json.load(open(BOT_STATE)).get("offset", 0)
    except (OSError, ValueError):
        offset = 0
    tg_call("setMyCommands", {"commands": [{"command": "shield", "description": "Щит: что заблокировано"},
                                           {"command": "unblock", "description": "Щит: снять блокировки"}]})
    while True:
        r = tg_call("getUpdates", {"offset": offset, "timeout": 50, "allowed_updates": ["message", "callback_query"]},
                    timeout=60)
        if not (r or {}).get("ok"):
            time.sleep(10)
            continue
        for upd in r.get("result", []):
            offset = max(offset, upd["update_id"] + 1)
            try:
                what = handle(upd, chat)
            except Exception as e:  # служба не должна падать от одного кривого обновления
                what = "ошибка: %s" % str(e)[:200]
            if what:
                probe.log("shield: " + what)
        with open(BOT_STATE + ".tmp", "w") as f:
            json.dump({"offset": offset}, f)
        os.replace(BOT_STATE + ".tmp", BOT_STATE)
        try:
            n = process_followups(chat)
            if n:
                probe.log("shield: итогов блокировки отправлено %d" % n)
        except Exception as e:  # итог не должен ронять службу
            probe.log("shield: итог блокировки — ошибка %s" % str(e)[:200])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
