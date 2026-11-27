"""channel-watch: превышение лимита устройств и подписки без HWID — только наблюдение, раз в день сводка.

Владелец 27.11: «давай клиенты сначала сделаем слежение превышения на сторож, пока только мониторинг».
Ничего не блокирует и в панели не меняет.

Откуда данные: раз в час (таймер channel-watch-devices) сторож заходит на сервер панели отдельным ключом
/etc/channel-watch/panel_devices_ed25519, который умеет только запустить /usr/local/sbin/watch-devices (чтение базы
панели, без слов): активные подписки, у которых устройств больше лимита, и подписки с действующим лимитом, которые за
7 дней брали из VPN-программ без HWID (им панель 3.4.11 отдаёт подписку целиком, лимит на них не действует).
Чего не видно: второй экземпляр той же программы без HWID (INCY на компьютере при INCY с HWID на телефоне) и
программа без HWID, обновляющая подписку в ту же минуту, что и программа с HWID (подробно — в шапке panel_devices.sh).

Как читаем (настройки — /etc/channel-watch/devices.json, необязателен):
  * свои — пропускаем: служебные пользователи и подписки владельца, списки skip_users / skip_prefixes из banme.json;
    те же списки в devices.json ДОБАВЛЯЮТСЯ к ним (не заменяют);
  * превышение — устройств больше лимита (свой лимит или общий запасной панели; 0 — без ограничения, не в счёт);
  * без HWID — названия программ (INCY, Happ, v2rayNG …); если устройств уже столько, сколько разрешено, строка
    помечена «упёрся в лимит?»: возможно, панель просто не записала новое устройство, а программа HWID шлёт;
  * прочие запросы (браузер, превью Telegram, curl …) — только счёт, без пользователей;
  * сводка — раз в день с summary_hour до work_to МСК: оба списка, «новое» и «изменилось» — по сравнению с прошлой
    сводкой; у подписок без HWID — сколько чужих адресов одновременно видел banme за сутки (если есть его состояние);
    первая — в ближайшее окно (поставили после 11 — назавтра); не успели до work_to — назавтра;
  * сразу — только если alert_new_over (по умолчанию выключено): новое превышение больше чем на одно устройство,
    в рабочие часы work_from–work_to МСК, по каждой подписке один раз (снова — если устройств стало больше);
    до первой сводки — молчим (всё текущее считается известным).
Адресов клиентов в сообщениях нет. Состояние — /var/lib/channel-watch/devices_state.json.
Запуск: devicewatch.py [--dry] (напечатать вместо отправки, состояние не менять) | --summary (сводка сейчас).
"""
import datetime as dt
import html
import json
import os
import subprocess
import sys
import time

ETC = "/etc/channel-watch"
STATE_FILE = "/var/lib/channel-watch/devices_state.json"
BANME_STATE = "/var/lib/channel-watch/banme_state.json"
MSK = dt.timezone(dt.timedelta(hours=3))
DEFAULTS = {
    "enabled": True, "host": "", "port": 22,
    "key": ETC + "/panel_devices_ed25519", "known_hosts": ETC + "/panel_known_hosts",
    "summary_hour": 11, "work_from": 11, "work_to": 19,
    "alert_new_over": False, "fail_alert_runs": 3, "max_lines": 25,
    "skip_users": ["watchdog", "bridge2", "Bridge_user", "elsinor-probe", "hwid-canary"],
    "skip_prefixes": [],   # подписки владельца — в banme.json (там они уже заданы)
}
LISTS = ("skip_users", "skip_prefixes")
UNLIMITED = 999   # лимит 999 и больше — практически без ограничения (так стоит общий запасной лимит панели)


def _load(path):
    try:
        d = json.load(open(path, encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def cfg(etc=ETC):
    """Свои списки — из banme.json (одно место для владельца и служебных), сервер — из panel_users.json,
    поверх всего — devices.json (его списки пропуска добавляются к спискам banme.json)."""
    c = dict(DEFAULTS)
    banme = _load(os.path.join(etc, "banme.json"))
    for k in LISTS + ("work_from", "work_to"):
        if k in banme:
            c[k] = banme[k]
    pu = _load(os.path.join(etc, "panel_users.json"))
    if pu.get("host"):
        c["host"], c["port"] = pu["host"], pu.get("port", 22)
        if pu.get("known_hosts"):
            c["known_hosts"] = pu["known_hosts"]
    own = _load(os.path.join(etc, "devices.json"))
    for k in LISTS:
        extra = own.pop(k, None)
        if isinstance(extra, list):
            c[k] = list(c[k]) + [x for x in extra if x not in c[k]]
    c.update(own)
    return c


def fetch(c, run=subprocess.run):
    if not c.get("host"):
        return None
    cmd = ["ssh", "-T", "-i", c["key"], "-p", str(c["port"]), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + c["known_hosts"], "root@" + c["host"]]
    try:
        r = run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        data = json.loads(r.stdout.strip() or "null") if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None
    return parse(data)


def parse(data):
    """Проверка формы ответа watch-devices; плохое — None."""
    if not isinstance(data, dict) or not isinstance(data.get("over"), list) or not isinstance(data.get("nohwid"), list):
        return None
    if not isinstance(data.get("other", []), list):
        return None
    return data


def is_own_user(c, name):
    name = name or ""
    return name in c["skip_users"] or any(name.startswith(p) for p in c["skip_prefixes"])


def _int(x, default=0):
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def classify(data, c):
    """-> {"over": {id: запись}, "nohwid": {id: запись}, "other": {программа: [пользователей, запросов]}}
    без своих и без лишнего (адресов в записях нет). Лимит — уже действующий (свой или общий запасной панели)."""
    over, nohwid, other = {}, {}, {}
    for u in data.get("over") or []:
        if not isinstance(u, dict) or is_own_user(c, u.get("username")):
            continue
        lim, n = u.get("limit"), _int(u.get("devices"))
        if lim is None or _int(lim) <= 0 or n <= _int(lim):
            continue   # 0 — без ограничения
        if u.get("status") not in (None, "ACTIVE"):
            continue
        over[str(u.get("id"))] = {"username": u.get("username") or "?", "tg": u.get("tg"), "limit": _int(lim),
                                  "common": bool(u.get("limit_common")), "devices": n,
                                  "active30": _int(u.get("active30")), "last_seen": u.get("last_seen")}
    for u in data.get("nohwid") or []:
        if not isinstance(u, dict) or is_own_user(c, u.get("username")):
            continue
        lim = _int(u.get("limit"), -1)
        if not 0 < lim < UNLIMITED:
            continue   # без ограничения или практически без — лимит и так не действует
        fams = sorted({str(f)[:24] for f in (u.get("ua_families") or []) if f})
        if not fams:
            continue
        n = _int(u.get("devices"))
        nohwid[str(u.get("id"))] = {"username": u.get("username") or "?", "tg": u.get("tg"), "limit": lim,
                                    "common": bool(u.get("limit_common")), "devices": n, "families": fams,
                                    "at_limit": n >= lim, "last_request": u.get("last_request")}
    for x in data.get("other") or []:
        if isinstance(x, dict) and x.get("fam"):
            other[str(x["fam"])[:24]] = [_int(x.get("users")), _int(x.get("requests"))]
    return {"over": over, "nohwid": nohwid, "other": other}


def banme_simul(path=BANME_STATE):
    """{username: (наибольшее число чужих адресов в одном нарушении за сутки, сильных нарушений)} из состояния banmewatch.
    Сами адреса там не хранятся — только счёт."""
    out = {}
    for d in _load(path).get("day") or []:
        if not isinstance(d, dict) or not d.get("user"):
            continue
        m, s = out.get(d["user"], (0, 0))
        out[d["user"]] = (max(m, _int(d.get("foreign"))), s + (1 if d.get("strong") else 0))
    return out


def mark(kind, uid, cur, prev):
    """'' | 'новое' | 'изменилось (было …)' — по сравнению с прошлой сводкой. prev None — сравнивать не с чем."""
    if prev is None:
        return ""
    old = (prev.get(kind) or {}).get(uid)
    if old is None:
        return "новое"
    if kind == "over" and old.get("devices") != cur["devices"]:
        return "изменилось (было %s)" % old.get("devices")
    if kind == "over" and old.get("limit") != cur["limit"]:
        return "изменилось (лимит был %s)" % old.get("limit")
    if kind == "nohwid" and old.get("families") != cur["families"]:
        return "изменилось (было %s)" % (", ".join(old.get("families") or []) or "—")
    return ""


def _who(x):
    tg = (" · tg %s" % html.escape(str(x["tg"]))) if x.get("tg") else ""
    return "<b>%s</b>%s" % (html.escape(str(x["username"])), tg)


def _date(ts):
    try:
        return dt.datetime.fromtimestamp(int(ts), MSK).strftime("%d.%m %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return "—"


def summary(cur, prev, c, now, simul=None, stale=False):
    simul = simul or {}
    head = "📱 <b>Сторож · устройства: сводка</b> (только наблюдение, ничего не блокируется)"
    lines = [head]
    if stale:
        lines.append("⚠️ Свежих данных из панели нет — ниже последнее прочитанное.")
    if prev is None:
        lines.append("Первая сводка — сравнивать не с чем, «новое» появится со следующей.")
    n = c["max_lines"]
    over = sorted(cur["over"].items(), key=lambda kv: (-(kv[1]["devices"] - kv[1]["limit"]), kv[1]["username"]))
    lines.append("\n<b>Больше устройств, чем лимит: %d</b>" % len(over))
    for uid, x in over[:n]:
        m = mark("over", uid, x, prev)
        lines.append("• %s — %d из %d%s (за 30 дней активны %d, последнее %s)%s"
                     % (_who(x), x["devices"], x["limit"], " (общий)" if x.get("common") else "", x["active30"],
                        _date(x["last_seen"]), (" — " + m) if m else ""))
    if len(over) > n:
        lines.append("… и ещё %d" % (len(over) - n))
    if not over:
        lines.append("нет")
    nh = sorted(cur["nohwid"].items(), key=lambda kv: (-_int(kv[1]["last_request"]), kv[1]["username"]))
    lines.append("\n<b>Берут подписку без HWID (лимит на них не действует): %d</b>" % len(nh))
    for uid, x in nh[:n]:
        m = mark("nohwid", uid, x, prev)
        lim = "%s%s" % (x["limit"], " (общий)" if x.get("common") else "")
        b = simul.get(x["username"])
        bm = ("; banme: до %d чужих адресов одновременно, сильных %d" % tuple(b)) if b and b[0] else ""
        at = "; упёрся в лимит? (возможно, панель не записала новое устройство)" if x.get("at_limit") else ""
        lines.append("• %s — %s; устройств %d, лимит %s; запрос %s%s%s%s"
                     % (_who(x), html.escape(", ".join(x["families"])), x["devices"], lim, _date(x["last_request"]),
                        at, bm, (" — " + m) if m else ""))
    if len(nh) > n:
        lines.append("… и ещё %d" % (len(nh) - n))
    if not nh:
        lines.append("нет")
    fams = {}
    for _, x in nh:
        for f in x["families"]:
            fams[f] = fams.get(f, 0) + 1
    if fams:
        lines.append("Программы без HWID: " + ", ".join("%s %d" % (html.escape(f), k)
                                                       for f, k in sorted(fams.items(), key=lambda kv: -kv[1])))
    other = sorted((cur.get("other") or {}).items(), key=lambda kv: (-kv[1][0], kv[0]))
    if other:
        lines.append("Прочие запросы подписки за 7 дней (не VPN-программы, в списки не входят): "
                     + ", ".join("%s — польз. %d, запросов %d" % (html.escape("(пусто)" if f == "?" else f), u, r)
                                 for f, (u, r) in other))
    if prev is not None:
        gone = [u for u in (prev.get("over") or {}) if u not in cur["over"]]
        if gone:
            lines.append("Превышение ушло: %d" % len(gone))
    return "\n".join(lines)


def msk(ts):
    return dt.datetime.fromtimestamp(ts, MSK)


def in_work(c, now):
    return c["work_from"] <= msk(now).hour < c["work_to"]


def alerts(state, cur, c, now):
    """Сразу — только новое превышение больше чем на одно устройство, в рабочие часы, если включено."""
    if not c.get("alert_new_over") or not in_work(c, now):
        return []
    sent = state.setdefault("alerted", {})
    if state.get("prev") is None:
        # до первой сводки сравнивать не с чем: всё текущее считаем известным, иначе уйдёт пачка «новых»
        for uid, x in cur["over"].items():
            sent[uid] = max(sent.get(uid, 0), x["devices"])
        return []
    known = state["prev"].get("over") or {}
    out = []
    for uid, x in sorted(cur["over"].items()):
        if x["devices"] <= x["limit"] + 1:
            continue
        if uid in known and known[uid].get("devices", 0) >= x["devices"]:
            continue   # было уже во вчерашней сводке и не выросло
        if sent.get(uid, 0) >= x["devices"]:
            continue
        sent[uid] = x["devices"]
        out.append("📱 <b>Сторож · устройства: новое превышение</b>\n%s — %d устройств при лимите %d "
                   "(за 30 дней активны %d). Только наблюдение, ничего не блокируется."
                   % (_who(x), x["devices"], x["limit"], x["active30"]))
    for uid in [u for u in sent if u not in cur["over"]]:
        del sent[uid]
    return out


def load_state(path=STATE_FILE):
    return _load(path)


def save_state(state, path=STATE_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, path)


def run(argv, c, state, data, now, send, log=lambda line: None, simul=None):
    """Один проход: -> state (изменённый). data — ответ watch-devices или None."""
    today = msk(now).strftime("%Y-%m-%d")
    hour = msk(now).hour
    if "summary_day" not in state:
        # первый проход: поставили до summary_hour — сводка сегодня, позже — завтра утром (не ночью)
        state["summary_day"] = today if hour >= c["summary_hour"] else msk(now - 86400).strftime("%Y-%m-%d")
    if data is None:
        state["fetch_fail"] = state.get("fetch_fail", 0) + 1
        log("devices: не прочитались данные панели (%d подряд)" % state["fetch_fail"])
        if state["fetch_fail"] >= c["fail_alert_runs"] and in_work(c, now) and not state.get("fetch_alerted"):
            res = send("⚠️ Сторож · устройства: %d раз подряд не читаются данные панели (watch-devices) — проверить "
                       "ключ и сервер панели." % state["fetch_fail"])
            if res in ("ok", "bad"):
                state["fetch_alerted"] = True
    else:
        if state.get("fetch_alerted"):
            send("✅ Сторож · устройства: данные панели снова читаются.")
        state["fetch_fail"], state["fetch_alerted"] = 0, False
        state["cur"] = classify(data, c)
        state["cur_ts"] = now
        for text in alerts(state, state["cur"], c, now):
            res = send(text)
            log("devices: тревога %s" % ("отправлена" if res == "ok" else "НЕ отправлена (%s)" % res))
    forced = "--summary" in argv
    due = c["summary_hour"] <= hour < c["work_to"] and state.get("summary_day") != today
    if (forced or due) and state.get("cur") is not None:
        stale = now - state.get("cur_ts", 0) > 6 * 3600
        res = send(summary(state["cur"], state.get("prev"), c, now, simul, stale))
        log("devices: сводка %s" % {"ok": "отправлена",
                                    "bad": "отвергнута Telegram (часть могла уйти), повторять не будем"}
            .get(res, "НЕ отправлена (%s), повтор через час" % res))
        if res in ("ok", "bad") and not forced:   # 'bad' — окончательный ответ, повтор дал бы дубли
            state["summary_day"] = today
            state["prev"] = state["cur"]
    return state


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import probe  # tg_send и общий журнал сторожа
    c = cfg()
    if not c.get("enabled", True):
        return 0
    dry = "--dry" in argv
    send = (lambda text: print("[не отправлено, --dry]\n" + text) or "ok") if dry else probe.tg_send
    log = print if dry else probe.log
    state = load_state()
    run(argv, c, state, fetch(c), time.time(), send, log, banme_simul())
    if not dry:
        save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
