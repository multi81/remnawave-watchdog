"""channel-watch: DDoS и нагрузка серверов (VPN-ноды, панель, бот, подписка).

Логика выросла из плагина ddos-monitoring к Remnawave (poller.py, notify.py, MIT): подстройка порогов по обычной
нагрузке каждого сервера, классификация атак, сообщения в Telegram.

Откуда данные: на каждом сервере служба ddos-collect пишет /run/ddos-collect/state.json (последние 30 срезов по 10 с).
Раз в минуту (таймер channel-watch-ddos) сторож забирает файлы со всех серверов параллельно — ключом, который умеет
только прочитать этот файл (authorized_keys: from=rf1,command="cat …",restrict).

Что изменено против плагина:
  * подстройка по нагрузке работает для всех серверов и в обе стороны: порог = max(p95 за 7 дней × формула, минимум);
    пока истории меньше BASELINE_MIN_SAMPLES — статические пороги плагина. В плагине было max(статический, baseline) —
    порог только рос, и для серверов с ddos-agent baseline не применялся вовсе; в базу идут только чистые срезы
    (без атак и перекоса), рост порога — не больше ×1,5 за сутки и ×2 за неделю, потолок — от "link_mbps";
  * симметричный флуд (нода отвечает тем же): излишек rx − tx, рост против нормы, ICMP из щита, канал заполнен;
  * трафик/пакеты проверяются для всех (в плагине для серверов с агентом смотрелись только tcp/udp/icmp_bytes,
    которых агент не присылал, — объёмный и пакетный флуд там не ловился);
  * «пакетный флуд» — когда превышены пакеты; иначе «объёмный» (в плагине условие было истинно при любом rx_pps);
  * SYN_RECV считается правильно (сборщик), SYN-флуд по SYN cookies / listen drops / SYN_RECV / скорости SYN_RECV;
  * атаки и «нет связи» — сразу в любое время; нагрузка и «требует внимания» — в рабочие часы (ночью — в сводку);
    сводка — раз в день в summary_hour МСК (в плагине — каждый час).
Состояние — /var/lib/channel-watch/ddos_state.json, история — /var/lib/channel-watch/ddos.sqlite (срезы 8 дней,
атаки 90 дней). Запуск: ddoswatch.py [--dry] | --summary | --status.
"""
import bisect
import datetime as dt
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time

ETC = "/etc/channel-watch"
STATE_FILE = "/var/lib/channel-watch/ddos_state.json"
DB_FILE = "/var/lib/channel-watch/ddos.sqlite"
MSK = dt.timezone(dt.timedelta(hours=3))

# Пороги плагина (poller.DEFAULT_THRESHOLDS, v0.7.44+)
STATIC = {
    "rx_bps": 200_000_000.0, "rx_pps": 30_000.0, "syncookies_ps": 200.0, "listen_drop_ps": 100.0,
    "conntrack_ratio": 0.75, "rx_drop_ps": 50.0, "cpu_percent": 90.0, "memory_percent": 90.0,
    "load_per_cpu": 2.0, "disk_percent": 85.0, "swap_percent": 90.0,
    # симметричный флуд (нода отвечает тем же объёмом — перекоса нет): излишек входящего над исходящим, рост против
    # нормы и ICMP. Пока своей нормы нет: излишек — как rx_bps/rx_pps, рост — эти запасные (берутся и из ddos.json)
    "rx_bps_sym": 800_000_000.0, "rx_pps_sym": 150_000.0, "icmp_pps": 5000.0,
}
EXCESS = {"rx_excess_bps": "rx_bps", "rx_excess_pps": "rx_pps"}   # излишек без своей нормы — порог основной метрики
# Подстройка (poller._DEFAULT_EXPRESSIONS / _DEFAULT_MIN): порог = max(p95 ∘ формула, минимум)
BASELINE = {
    # калибровка: нижние границы плагина 20 Мбит/с и 5000 пак/с у VPN-нод — это обычная закачка клиента
    # (на бою было ~50 ложных «атак» в сутки, две трети короче минуты)
    "rx_bps": (lambda v: v * 3, 100_000_000.0),
    "rx_pps": (lambda v: v * 2, 20_000.0),
    "syncookies_ps": (lambda v: v + 5, 10.0),
    "listen_drop_ps": (lambda v: v + 3, 5.0),
    "rx_drop_ps": (lambda v: v + 3, 5.0),
    # излишек rx − tx (без перекоса) и весь входящий против нормы — учатся только на чистых срезах
    "rx_excess_bps": (lambda v: v * 3, 150_000_000.0),
    "rx_excess_pps": (lambda v: v * 3, 30_000.0),
    "rx_bps_sym": (lambda v: v * 4, 300_000_000.0),
    "rx_pps_sym": (lambda v: v * 4, 60_000.0),
}
# Рост порога (прежде p95 учился на самих атаках и рос без предела): не больше ×1,5 за сутки и ×2 за неделю.
# Потолок от скорости канала: "link_mbps" сервера (или общий) в ddos.json — пороги объёма не выше 80% канала,
# входящий от 90% канала — тревога при любом перекосе
BASELINE_GROWTH_DAY, BASELINE_GROWTH_WEEK = 1.5, 2.0
LINK_CAP_SHARE, LINK_FULL_SHARE = 0.8, 0.9
SUSPECT_PAD = 60                # срезы за минуту до записанной атаки — тоже не в базу (подтверждение)
# перекос ниже этого не поднимет порог выше минимума (100 Мбит/с = 33×3, 20 000 пак/с = 10 000×2) — тихий фон в базе
ASYM_LEARN_MIN = {"rx_bps": 33_000_000.0, "rx_pps": 10_000.0}
BASELINE_DAYS = 7
BASELINE_MIN_SAMPLES = 8640     # сутки срезов по 10 с — раньше подстройку не включаем
BASELINE_EVERY = 3600
SYN_RECV_LIMIT = 1000           # poller.AGENT_SYN_RECV_LIMIT
SYN_RATE = 50.0                 # poller.DEFAULT_SYN_RATE_THRESHOLD, SYN_RECV/с
ATTACK_CONFIRM, RECOVERY_CONFIRM, OFFLINE_CONFIRM = 6, 3, 2   # атака — минута подряд (в плагине 2 среза = 20 с)
ATTACK_CONFIRM_STRONG = 2       # критическая (втрое выше порога) — как раньше, 20 с
ASYM = 2.0                      # объёмный/пакетный флуд — только если входящего хотя бы вдвое больше исходящего:
                                # VPN-нода пересылает клиенту то же, что получила (TX/RX 0,96–1,07 на всех нодах при замере)
ATTACK_MSG_COOLDOWN = 1800      # сообщение об атаке по серверу — не чаще раза в 30 минут (критическая — всегда)
ATTACK_LONG = 180               # средняя атака — сообщение, только если длится дольше 3 минут
OVERRIDES_FILE = "/var/lib/channel-watch/ddos_overrides.json"   # пороги, поднятые кнопкой «Это не атака»
ALERT_COOLDOWN = 300
# Нагрузка: 5 минут подряд и пауза 30 минут. Если у сторожевого сервера одно ядро, его же замеры скорости дают пики CPU
# на 20–60 с — без выдержки это десятки сообщений «нагрузка / норма» в сутки
LOAD_CONFIRM = 30           # срезов подряд (30 × 10 с = 5 минут)
LOAD_COOLDOWN = 1800        # сообщение о нагрузке по серверу — не чаще раза в 30 минут
# Сеть: сообщать только при переполнении буфера карты, сбросах ядра или от 100 сбросов в секунду 5 минут подряд.
# Общий rx_dropped у облачных серверов — фон сети хостера (бывает ~2 000 пак/с служебных кадров соседей, 2–4 сброса/с)
NIC_MISSED_MIN = 1.0        # переполнение буфера сетевой карты, пакетов/с — сразу
SOFTNET_MIN = 1.0           # сбросы в очереди ядра, пакетов/с — сразу
DROP_MIN = 100.0            # общий сброс, пакетов/с — не ниже этого …
DROP_CONFIRM = 30           # … и 5 минут подряд (30 срезов)
STALE_AFTER = 120               # срез старше — нет телеметрии
KEEP_SAMPLES_DAYS, KEEP_ATTACKS_DAYS = 8, 90
DEFAULTS = {"key": ETC + "/ddos_ed25519", "known_hosts": ETC + "/ddos_known_hosts", "hosts": [],
            "work_from": 11, "work_to": 19, "summary_hour": 11, "thresholds": {},
            # упавшие службы, которые не считаем проблемой (обновление прошивок, новости motd, плановые apt)
            "ignore_units": ["fwupd-refresh.service", "motd-news.service", "apt-daily.service",
                             "apt-daily-upgrade.service", "update-notifier-download.service"],
            # контейнеры, остановленные нарочно (не тревожить)
            "ignore_containers": [],
            # важные контейнеры без политики перезапуска и не из docker compose — следить, как за постоянными
            "permanent_containers": [],
            # без них не работает VPN, панель, бот или подписка — о них и ночью
            "critical_containers": ["remnanode", "remnawave", "remnawave-db", "remnawave-redis", "caddy",
                                    "remnawave_bot", "remnawave_bot_db", "remnawave_bot_redis",
                                    "remnawave-subscription-page"]}
# Контейнеры Docker: отдельно от вердикта сервера, чтобы упавший контейнер не терялся за «Swap 95%»
DOCKER_CONFIRM = 2          # проходов подряд (проход — раз в минуту), прежде чем тревожить
BACKUP_MAX_HOURS = 26       # удачной копии нет дольше — тревога (свой срок: "backup_max_hours" в ddos.json)
RESTARTS_HOUR = 3           # перезапусков за час — «по кругу» (плановый перезапуск раз в несколько часов — это не он)
DOCKER_FORGET = 3 * 86400   # пропавший контейнер забываем через 3 суток
# Щит — только с подтверждением в Telegram, никакой автоматики: сторож только предлагает, блокирует — кнопка (shieldbot)
SHIELD_OFFER_MIN = 1000     # лишних соединений за 10 минут у самого «громкого» адреса — предложить и без атаки
SHIELD_OFFER_EVERY = 3600   # не чаще раза в час на сервер (атака — своё предложение сразу)
SHIELD_OFFER_IPS = 10
SHIELD_ALARM_CONFIRM = 2    # опросов щита подряд (раз в минуту) с той же бедой, прежде чем тревожить
SHIELD_ALARM_RU = {"tick": "таймер снятия режима (tick) не работает — истёкший «щит включён» снимается только при "
                           "опросе щита сборщиком",
                   "kernel": "в ядре щит режет, а по его записям — наблюдение: режется без срока и без нажатия кнопки. "
                             "Снять — /unblock"}
SHIELD_ALARM_OK_RU = {"tick": "таймер tick работает", "kernel": "ядро и записи щита снова совпадают"}
HOST_INFO = {}              # {имя сервера: (адрес, пометка)} — из ddos.json, для строки «Сервер» в сообщениях
IPINFO_CACHE = "/var/lib/channel-watch/ipinfo.json"   # сведения об адресах-источниках: {адрес: {"ts", ...}}
IPINFO_TTL = 7 * 86400
IPINFO_LOOKUP = None        # подмена запроса (тесты); None — ip-api.com (пакетом), запасной — ipinfo.io
SCAN_DIR = "/var/lib/channel-watch/scanners"

STATE_TITLE = {   # notify.STATE_TITLE
    "attack": "🚨 <b>DDoS-атака обнаружена</b>",
    "load": "🟠 <b>Высокая нагрузка без признаков DDoS</b>",
    "health": "🟡 <b>Состояние сервера требует внимания</b>",
    "offline": "⚫️ <b>Нет связи с мониторингом</b>",
}
SEVERITY_RU = {"critical": "КРИТИЧЕСКИЙ", "high": "ВЫСОКИЙ", "medium": "СРЕДНИЙ"}
SEV_ORDER = {"normal": 0, "warning": 1, "medium": 2, "high": 3, "critical": 4}


def cfg():
    c = dict(DEFAULTS)
    try:
        c.update(json.load(open(os.path.join(ETC, "ddos.json"), encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return c


def num(v, d=0.0):
    try:
        f = float(v)
        return f if f == f else d
    except (TypeError, ValueError):
        return d


# ---------- пороги ----------
def thresholds(c, baseline, override=None, link_bps=0.0):
    th = dict(STATIC)
    th.update({k: float(v) for k, v in (c.get("thresholds") or {}).items() if k in STATIC})
    base = {k: v for k, v in (baseline or {}).items() if k in BASELINE}
    th.update(base)
    for k, src in EXCESS.items():
        th.setdefault(k, th[src])
    # прежняя база (только rx_bps = p95×3, rx_pps = p95×2) — норма для роста из неё, пока своей нет
    if "rx_bps_sym" not in base and "rx_bps" in base:
        th["rx_bps_sym"] = max(th["rx_bps_sym"], base["rx_bps"] * 4 / 3)
    if "rx_pps_sym" not in base and "rx_pps" in base:
        th["rx_pps_sym"] = max(th["rx_pps_sym"], base["rx_pps"] * 2)
    link = num(link_bps)
    th["link_full_bps"] = link * LINK_FULL_SHARE if link > 0 else 0.0
    if link > 0:
        for k in ("rx_bps", "rx_excess_bps", "rx_bps_sym"):
            th[k] = min(th[k], link * LINK_CAP_SHARE)
    if override:   # поднято кнопкой «Это не атака» — только вверх (пик входящего ×1,5 — и для новых признаков)
        for k, src in (("rx_bps", "rx_bps"), ("rx_excess_bps", "rx_bps"), ("rx_bps_sym", "rx_bps"),
                       ("link_full_bps", "rx_bps"), ("rx_pps", "rx_pps"), ("rx_excess_pps", "rx_pps"),
                       ("rx_pps_sym", "rx_pps"), ("icmp_pps", "rx_pps")):
            if k == "link_full_bps" and not th[k]:
                continue
            if num(override.get(src)) > th[k]:
                th[k] = num(override[src])
    return th


def load_overrides(path=None, now=None):
    now = now or time.time()
    try:
        d = json.load(open(path or OVERRIDES_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {h: v for h, v in d.items() if isinstance(v, dict) and num(v.get("until")) > now}


def compute_baseline(values):
    """values: {metric: [числа]} -> {metric: порог} (только где хватает истории)."""
    out = {}
    for k, (expr, floor) in BASELINE.items():
        vs = sorted(num(x) for x in values.get(k, []))
        if len(vs) < BASELINE_MIN_SAMPLES:
            continue
        p95 = vs[max(0, int(round(0.95 * (len(vs) - 1))))]
        out[k] = max(expr(p95), floor)
    return out


# ---------- вердикт по одному срезу ----------
def classify(m, th, prev_syn=None, interval=0.0):
    """-> {state: attack|load|health|stable|nodata, attack_type, severity, reasons}"""
    if not m:
        return {"state": "nodata", "attack_type": "", "severity": "normal", "reasons": []}
    rx_bps, rx_pps = num(m.get("rx_bps")), num(m.get("rx_pps"))
    # объём и пакеты считаем атакой только при перекосе (входящего вдвое больше исходящего): закачка клиента — симметрична
    rx_eff = rx_bps if rx_bps >= ASYM * num(m.get("tx_bps")) else 0.0
    pps_eff = rx_pps if rx_pps >= ASYM * num(m.get("tx_pps")) else 0.0
    # перекоса нет, а лишнее есть: флуд поверх трафика клиентов (излишек rx − tx), пинг-флуд с ответами (рост против
    # нормы, ICMP), канал заполнен. Порогов нет в старом th (чужой вызов) — признак молчит
    rx_exc, pps_exc = max(rx_bps - num(m.get("tx_bps")), 0.0), max(rx_pps - num(m.get("tx_pps")), 0.0)
    sh = m.get("shield") if isinstance(m.get("shield"), dict) else {}
    icmp = num((sh.get("proto_pps") if isinstance(sh.get("proto_pps"), dict) else {}).get("icmp"))
    syncookies, ldrop = num(m.get("syncookies_ps")), num(m.get("listen_drop_ps")) + num(m.get("listen_overflow_ps"))
    ct, ctmax = num(m.get("conntrack_count")), num(m.get("conntrack_max"))
    ct_ratio = ct / ctmax if ctmax > 0 else 0.0
    syn = int(num(m.get("syn_recv")))

    def r(v, t):
        return v / t if t > 0 else 0.0
    checks = {"входящий трафик": r(rx_eff, th["rx_bps"]), "пакеты в секунду": r(pps_eff, th["rx_pps"]),
              "SYN cookies": r(syncookies, th["syncookies_ps"]), "listen drop": r(ldrop, th["listen_drop_ps"]),
              "conntrack": r(ct_ratio, th["conntrack_ratio"]), "SYN_RECV": r(syn, SYN_RECV_LIMIT),
              "входящий сверх исходящего": r(rx_exc, th.get("rx_excess_bps", 0)),
              "пакеты сверх исходящих": r(pps_exc, th.get("rx_excess_pps", 0)),
              "входящий выше нормы": r(rx_bps, th.get("rx_bps_sym", 0)),
              "пакеты выше нормы": r(rx_pps, th.get("rx_pps_sym", 0)),
              "ICMP": r(icmp, th.get("icmp_pps", 0)),
              "канал заполнен": r(rx_bps, th.get("link_full_bps", 0))}
    syn_rate = (syn - prev_syn) / interval if prev_syn is not None and interval > 0 and syn > prev_syn else 0.0
    checks["скорость SYN_RECV"] = r(syn_rate, SYN_RATE)
    reasons = [k for k, v in checks.items() if v >= 1.0]
    peak = max(checks.values(), default=0.0)
    if reasons:
        if checks["SYN cookies"] >= 1 or checks["SYN_RECV"] >= 1 or checks["скорость SYN_RECV"] >= 1 \
                or (syncookies >= th["syncookies_ps"] * 0.5 and syncookies >= ldrop):
            atype = "TCP SYN-флуд"
        elif ct_ratio >= 0.9:
            atype = "conntrack-исчерпание"
        elif checks["listen drop"] >= 1:
            atype = "TCP-флуд (переполнение очереди)"
        elif checks["ICMP"] >= 1:
            atype = "ICMP-флуд"
        elif checks["пакеты в секунду"] >= 1 or checks["пакеты сверх исходящих"] >= 1 or checks["пакеты выше нормы"] >= 1:
            atype = "пакетный флуд"
        else:
            atype = "объёмный флуд"
        sev = "critical" if peak >= 3.0 or ct_ratio >= 0.95 else "high" if peak >= 1.5 else "medium"
        return {"state": "attack", "attack_type": atype, "severity": sev, "reasons": reasons}
    cores = max(int(num(m.get("cores"), 1)) or 1, 1)
    load = [n for n, ok in (("CPU", num(m.get("cpu_pct")) >= th["cpu_percent"]),
                            ("RAM", num(m.get("ram_pct")) >= th["memory_percent"]),
                            ("Load Average", num(m.get("load1")) >= cores * th["load_per_cpu"])) if ok]
    if load:
        return {"state": "load", "attack_type": "", "severity": "warning", "reasons": load}
    health = []
    if m.get("failed_units"):
        health.append("systemd: " + ", ".join(str(u) for u in m["failed_units"][:5]))
    if num(m.get("swap_pct")) >= th["swap_percent"]:
        health.append("Swap %.0f%%" % num(m.get("swap_pct")))
    if num(m.get("disk_pct")) >= th["disk_percent"]:
        health.append("Диск %.0f%%" % num(m.get("disk_pct")))
    if num(m.get("nic_missed_ps")) >= NIC_MISSED_MIN:
        health.append("Сеть: буфер сетевой карты переполняется (%s пак/с)" % cnt(m.get("nic_missed_ps")))
    if num(m.get("softnet_drop_ps")) >= SOFTNET_MIN:
        health.append("Сеть: ядро не успевает разбирать пакеты (%s пак/с)" % cnt(m.get("softnet_drop_ps")))
    if m.get("drop_sustained"):
        health.append("Сеть: сброс пакетов %s/с дольше 5 минут" % cnt(max(num(m.get("rx_drop_ps")), num(m.get("tx_drop_ps")))))
    if health:
        return {"state": "health", "attack_type": "", "severity": "warning", "reasons": health}
    return {"state": "stable", "attack_type": "", "severity": "normal", "reasons": []}


# ---------- тексты (notify.py) ----------
def msk(ts):
    return dt.datetime.fromtimestamp(ts, MSK)


def mbit(v):
    x = num(v) / 1e6
    return "%.0f" % x if x >= 10 else "%.1f" % x


def cnt(v):
    return "{:,}".format(int(num(v))).replace(",", " ")


def dur(s):
    s = int(s)
    return "%d ч %d мин" % (s // 3600, s % 3600 // 60) if s >= 3600 else "%d мин %d с" % (s // 60, s % 60) if s >= 60 else "%d с" % s


def metric_lines(m):
    if not m:
        return []
    out = ["📥 RX: %s Мбит/с · %s пак/с" % (mbit(m.get("rx_bps")), cnt(m.get("rx_pps"))),
           "📤 TX: %s Мбит/с · %s пак/с" % (mbit(m.get("tx_bps")), cnt(m.get("tx_pps")))]
    if m.get("syncookies_ps") or m.get("listen_drop_ps"):
        out.append("🛡 SYN cookies: %s/с · listen drop: %s/с" % (cnt(m.get("syncookies_ps")), cnt(num(m.get("listen_drop_ps")) + num(m.get("listen_overflow_ps")))))
    out.append("🔗 Соединения: SYN_RECV %s · EST %s · адресов %s" % (cnt(m.get("syn_recv")), cnt(m.get("established")), cnt(m.get("unique_ips"))))
    if num(m.get("conntrack_max")):
        out.append("🧱 Conntrack: %s / %s (%.1f%%)" % (cnt(m.get("conntrack_count")), cnt(m.get("conntrack_max")),
                                                       100 * num(m.get("conntrack_count")) / num(m.get("conntrack_max"))))
    out.append("⚙️ CPU %.0f%% · RAM %.0f%% · Load %.1f (ядер %d) · диск %.0f%%" % (
        num(m.get("cpu_pct")), num(m.get("ram_pct")), num(m.get("load1")), int(num(m.get("cores"), 1)), num(m.get("disk_pct"))))
    return out


def server_label(name):
    """«бот · 203.0.113.5 · бот Bedolaga» — имя, адрес и пометка из ddos.json (что есть)."""
    addr, note = HOST_INFO.get(name) or (None, None)
    return " · ".join(html.escape(str(x)) for x in (name, addr, note) if x)


def text_change(name, prev, cur, m, now, attack=None, th=None):
    head = ["🖥 <b>Сервер:</b> %s" % server_label(name), "🕒 %s МСК" % msk(now).strftime("%d.%m %H:%M:%S")]
    st = cur["state"]
    if st == "attack":
        lines = head + ["💥 <b>Тип:</b> %s" % cur["attack_type"], "🔴 <b>Уровень:</b> %s" % SEVERITY_RU.get(cur["severity"], "?"),
                        "📌 <b>Сработало:</b> %s" % html.escape(", ".join(cur["reasons"])), ""] + metric_lines(m)
        if th:
            lines.append("📏 Пороги этого сервера: RX %s Мбит/с · %s пак/с" % (mbit(th["rx_bps"]), cnt(th["rx_pps"])))
        return STATE_TITLE["attack"] + "\n\n" + "\n".join(lines)
    if st in ("load", "health"):
        return STATE_TITLE[st] + "\n\n" + "\n".join(head + ["📌 <b>Сработало:</b> %s" % html.escape(", ".join(cur["reasons"])), ""]
                                                     + metric_lines(m))
    if st == "offline":
        return STATE_TITLE["offline"] + "\n\n" + "\n".join(head + ["🧩 Причина: %s" % html.escape(cur.get("error") or "нет телеметрии")])
    # stable после другого состояния
    if prev == "attack" and attack:
        return "🟢 <b>DDoS-атака завершена</b>\n\n" + "\n".join(head + [
            "⏱ <b>Продолжительность:</b> %s" % dur(now - attack["start"]),
            "📈 <b>Пиковый RX:</b> %s Мбит/с" % mbit(attack["peak"].get("rx_bps")),
            "📦 <b>Пиковый PPS:</b> %s пак/с" % cnt(attack["peak"].get("rx_pps")), "", "🟢 Показатели вернулись в норму."])
    if prev == "offline":
        return "🟢 <b>Связь с мониторингом восстановлена</b>\n\n" + "\n".join(head)
    return "🟢 <b>Показатели вернулись в норму</b>\n\n" + "\n".join(head)


# ---------- история ----------
def db_open(path=DB_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    db = sqlite3.connect(path, timeout=30)
    db.execute("create table if not exists samples (host text, ts integer, rx_bps real, rx_pps real, syncookies_ps real,"
               " listen_drop_ps real, rx_drop_ps real, primary key (host, ts))")
    db.execute("create table if not exists attacks (id integer primary key, host text, start integer, end integer,"
               " type text, severity text, reasons text, peak text)")
    db.execute("create table if not exists baseline (host text, metric text, value real, computed integer,"
               " primary key (host, metric))")
    # опорные значения для предела роста — отдельной таблицей: прежняя версия пишет в baseline 4 значения без имён
    db.execute("create table if not exists baseline_cap (host text, metric text, day_value real, day_ts integer,"
               " week_value real, week_ts integer, primary key (host, metric))")
    # susp = 1: срез во время атаки или её подтверждения — в базу порогов не идёт (у старых строк null — чистый)
    for table, col, typ in (("samples", "tx_bps", "real"), ("samples", "tx_pps", "real"), ("attacks", "notified", "integer default 0"),
                            ("samples", "susp", "integer")):
        if col not in [r[1] for r in db.execute("pragma table_info(%s)" % table)]:
            db.execute("alter table %s add column %s %s" % (table, col, typ))
    return db


def db_baseline(db, host):
    return {m: v for m, v in db.execute("select metric, value from baseline where host = ?", (host,))}


def clean_values(rows, attacks=()):
    """Срезы -> {метрика: [числа]} для базы порогов. rows: (ts, rx_bps, rx_pps, syncookies, listen_drop, rx_drop,
    tx_bps, tx_pps, susp). Не берём: срезы атак и их подтверждения (susp; для старых строк — по записанным атакам),
    для объёма и пакетов — заметные срезы с перекосом (rx ≥ ASYM·tx): иначе порог учится на самих атаках."""
    vals = {k: [] for k in BASELINE}
    spans = []   # слитые отрезки атак по началу — поиск делением пополам (атак за неделю бывают сотни)
    for a, b in sorted((num(a) - SUSPECT_PAD, num(b)) for a, b in attacks):
        if spans and a <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], b)
        else:
            spans.append([a, b])
    starts = [a for a, _ in spans]
    for ts, rx, pps, sc, ld, rd, tx, txp, susp in rows:
        if susp:
            continue
        if susp is None and spans:   # строка прежней версии — пометки нет, смотрим записанные атаки
            i = bisect.bisect_right(starts, num(ts)) - 1
            if i >= 0 and num(ts) <= spans[i][1]:
                continue
        for k, v in (("syncookies_ps", sc), ("listen_drop_ps", ld), ("rx_drop_ps", rd)):
            if v is not None:
                vals[k].append(v)
        for k, raw, out, sym, exc in (("rx_bps", rx, tx, "rx_bps_sym", "rx_excess_bps"),
                                      ("rx_pps", pps, txp, "rx_pps_sym", "rx_excess_pps")):
            if raw is None or (out is not None and num(raw) >= ASYM * num(out) and num(raw) >= ASYM_LEARN_MIN[k]):
                continue
            vals[k].append(raw)
            vals[sym].append(raw)
            if out is not None:   # излишек — только где исходящий известен
                vals[exc].append(max(num(raw) - num(out), 0.0))
    return vals


def cap_growth(new, prev, ref, now):
    """Предел роста порога. ref = [day_value, day_ts, week_value, week_ts] (меняется) -> новый порог.
    Опора суток/недели — порог в начале окна; снижается без ограничений."""
    if prev is None:
        ref[:] = [new, now, new, now]
        return new
    for i, span in ((0, 86400), (2, 7 * 86400)):
        if ref[i] is None or ref[i + 1] is None or now - ref[i + 1] >= span:
            ref[i], ref[i + 1] = prev, now
    out = min(new, ref[0] * BASELINE_GROWTH_DAY, ref[2] * BASELINE_GROWTH_WEEK)
    return max(out, min(new, prev))   # не ниже прежнего, если новый не ниже: предел только на рост


def recompute_baseline(db, hosts, now):
    since = now - BASELINE_DAYS * 86400
    for h in hosts:
        rows = list(db.execute("select ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps, tx_bps, tx_pps, susp"
                               " from samples where host = ? and ts > ?", (h, since)))
        attacks = list(db.execute("select start, end from attacks where host = ? and end > ?", (h, since)))
        vals = clean_values(rows, attacks)
        prev = db_baseline(db, h)
        refs = {m: list(r) for m, *r in db.execute("select metric, day_value, day_ts, week_value, week_ts from baseline_cap"
                                                    " where host = ?", (h,))}
        new = compute_baseline(vals)
        if len(rows) >= BASELINE_MIN_SAMPLES:   # история есть, но чистых срезов мало (долгая атака) — прежний порог
            for k in BASELINE:
                if k not in new and k in prev:
                    new[k] = prev[k]
        db.execute("delete from baseline where host = ?", (h,))
        db.execute("delete from baseline_cap where host = ?", (h,))
        for k, v in new.items():
            ref = refs.get(k) or [None] * 4
            v = cap_growth(v, prev.get(k), ref, int(now))
            db.execute("insert into baseline values (?, ?, ?, ?)", (h, k, v, int(now)))
            db.execute("insert into baseline_cap values (?, ?, ?, ?, ?, ?)", (h, k, *ref))
    db.execute("delete from samples where ts < ?", (now - KEEP_SAMPLES_DAYS * 86400,))
    db.execute("delete from attacks where start < ?", (now - KEEP_ATTACKS_DAYS * 86400,))
    db.commit()


# ---------- сбор ----------
def fetch(c, h):
    cmd = ["ssh", "-i", c["key"], "-p", str(h.get("port", 22)), "-o", "BatchMode=yes", "-o", "ConnectTimeout=12",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + c["known_hosts"], "root@" + h["host"], "state"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        d = json.loads(r.stdout or "null") if r.returncode == 0 else None
    except (subprocess.TimeoutExpired, ValueError, OSError):
        d = None
    return d if isinstance(d, dict) and isinstance(d.get("samples"), list) else None


def fetch_all(c):
    out, threads = {}, []
    for h in c["hosts"]:
        t = threading.Thread(target=lambda h=h: out.__setitem__(h["name"], fetch(c, h)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(60)
    return out


# ---------- жизненный цикл (poller._apply_verdict / _handle_offline) ----------
def in_work(c, now):
    return c["work_from"] <= msk(now).hour < c["work_to"]


def new_entry():
    return {"verdict": "unknown", "cand": "", "cand_n": 0, "last_ts": 0, "last_syn": None, "last_alert": 0,
            "attack": None, "deferred": [], "last_m": None}


def proto_line(m):
    """Чем бьют: пакеты в секунду по протоколам за последнюю минуту и порты новых соединений (из щита)."""
    sh = (m or {}).get("shield") or {}
    pp = {k: num(v) for k, v in (sh.get("proto_pps") or {}).items() if num(v) > 0}
    if not pp:
        return ""
    names = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
    line = "📦 <b>Протоколы</b> (за минуту): " + " · ".join("%s %s пак/с" % (html.escape(str(names.get(k, k))), cnt(v))
                                                           for k, v in sorted(pp.items(), key=lambda kv: -kv[1]))
    ports = [x for x in (sh.get("ports") or []) if isinstance(x, list) and len(x) == 2][:3]
    if ports:
        line += "\n🎯 <b>Больше всего новых соединений:</b> " + ", ".join("%s (%s)" % (html.escape(str(p)), cnt(n)) for p, n in ports)
    return line


def maybe_notify(e, name, m, ts, th):
    """Идущая атака: пора ли сообщать. Сообщение (с кнопками щита) кладётся в e["incident"] — его заберёт process."""
    a = e.get("attack")
    if not a or a.get("notified"):
        return
    sev, long_ = a.get("severity"), ts - a["start"] >= ATTACK_LONG
    cool = ts - e.get("last_attack_msg", 0) >= ATTACK_MSG_COOLDOWN
    if not (sev == "critical" or ((sev == "high" or long_) and cool)):
        return
    a["notified"], e["last_attack_msg"] = True, ts
    v = {"state": "attack", "attack_type": a.get("type"), "severity": sev, "reasons": a.get("reasons") or []}
    text = text_change(name, "stable", v, m, ts, th=th)
    pl = proto_line(m)
    if pl:
        text += "\n" + pl
        a["peak"]["proto"] = (m.get("shield") or {}).get("proto_pps")
        a["peak"]["ports"] = (m.get("shield") or {}).get("ports")
    if long_:
        text += "\n⏱ Идёт уже %s (с %s МСК)" % (dur(ts - a["start"]), msk(a["start"]).strftime("%H:%M"))
    e["incident"] = {"text": text, "ts": ts, "peak": dict(a.get("peak") or {}),
                     "attack": {k: a.get(k) for k in ("type", "severity", "start")}}


def apply(e, name, v, m, ts, c, th, db=None):
    """Один срез. -> текст сообщения или None. e — состояние сервера (меняется). Сообщение о начале атаки —
    через e["incident"] (одно сообщение с кнопками щита), не текстом отсюда."""
    st = v["state"]
    if e["attack"] and st == "attack":   # пик и тяжесть идущей атаки
        pk = e["attack"]["peak"]
        for k in ("rx_bps", "rx_pps", "syncookies_ps", "syn_recv"):
            pk[k] = max(num(pk.get(k)), num(m.get(k)))
        if SEV_ORDER[v["severity"]] > SEV_ORDER[e["attack"]["severity"]]:
            e["attack"]["severity"] = v["severity"]
        maybe_notify(e, name, m, ts, th)
    if st == e["verdict"]:
        e["cand"], e["cand_n"] = "", 0
        return None
    need = ((ATTACK_CONFIRM_STRONG if v["severity"] == "critical" else ATTACK_CONFIRM) if st == "attack" else
            RECOVERY_CONFIRM if e["verdict"] == "attack" else LOAD_CONFIRM if st == "load" else 2)
    e["cand_n"] = e["cand_n"] + 1 if e["cand"] == st else 1
    e["cand"] = st
    if e["cand_n"] < need:
        return None
    prev, e["verdict"], e["cand"], e["cand_n"] = e["verdict"], st, "", 0
    msg = None
    if st == "attack":
        e["attack"] = {"start": ts, "type": v["attack_type"], "severity": v["severity"], "reasons": v["reasons"],
                       "peak": {k: num(m.get(k)) for k in ("rx_bps", "rx_pps", "syncookies_ps", "syn_recv")},
                       "notified": False}
        maybe_notify(e, name, m, ts, th)
        return None
    elif prev == "attack":
        a = e["attack"] or {"start": ts, "peak": {}}
        msg = text_change(name, prev, v, m, ts, attack=a) if a.get("notified") else None   # «завершена» — только после «началась»
        if db is not None:
            db.execute("insert into attacks (host, start, end, type, severity, reasons, peak, notified) values (?, ?, ?, ?, ?, ?, ?, ?)",
                       (name, int(a["start"]), int(ts), a.get("type"), a.get("severity"), ", ".join(a.get("reasons") or []),
                        json.dumps(a.get("peak")), 1 if a.get("notified") else 0))
        e["attack"] = None
        e.pop("incident", None)
        if msg is None:
            return None
    elif prev == "unknown" and st == "stable":
        return None
    elif st in ("load", "health"):
        e["state_notified"] = False
        if not in_work(c, ts):
            e["deferred"].append({"ts": ts, "state": st, "reasons": v["reasons"]})
            return None
        if st == "load":
            if ts - e.get("last_load_alert", 0) < LOAD_COOLDOWN:
                return None
            e["last_load_alert"] = ts
        elif ts - e["last_alert"] < ALERT_COOLDOWN:
            return None
        msg = text_change(name, prev, v, m, ts)
        e["state_notified"] = True
    elif prev in ("load", "health") and (not in_work(c, ts) or not e.get("state_notified")):
        e["state_notified"] = False
        return None   # «вернулись в норму» — только если о нагрузке/внимании было сообщение
    else:
        msg = text_change(name, prev, v, m, ts)
        e["state_notified"] = False
    e["last_alert"] = ts
    return msg


def offline(e, name, now, error):
    """Нет свежих срезов. -> текст или None (подтверждение OFFLINE_CONFIRM проходами)."""
    if e["verdict"] == "offline":
        return None
    e["cand_n"] = e["cand_n"] + 1 if e["cand"] == "offline" else 1
    e["cand"] = "offline"
    if e["cand_n"] < OFFLINE_CONFIRM:
        return None
    prev, e["verdict"], e["cand"], e["cand_n"] = e["verdict"], "offline", "", 0
    e["attack"] = None
    if prev == "unknown":
        return None
    e["last_alert"] = now
    return text_change(name, prev, {"state": "offline", "error": error}, None, now)


# ---------- контейнеры Docker ----------
# В сводке и тревогах — по-человечески: что за контейнер, что случилось, чем грозит
CT_RU = {"remnanode": "VPN на ноде", "caddy-selfsteal": "сайт-маскировка", "selfsteal-caddy": "сайт-маскировка",
         "remnawave-node-agent": "агент мониторинга ноды", "remnawave": "панель Remnawave", "remnawave-db": "база панели",
         "remnawave-redis": "кэш панели", "caddy": "веб-вход сервера (панель или подписка)",
         "remnawave_bot": "бот Бедолага", "remnawave_bot_db": "база бота", "remnawave_bot_redis": "кэш бота",
         "cabinet_frontend": "кабинет бота", "remnawave-subscription-page": "страница подписки",
         "awg-panel": "панель Amnezia", "awg-caddy": "веб-вход панели Amnezia",
         "docker": "Docker"}
CT_IMPACT = {"remnanode": "клиенты этой ноды без VPN", "remnawave": "панель не работает, новые подписки не выдаются",
             "remnawave-db": "панель не работает", "remnawave-redis": "панель может не работать",
             "caddy": "панель или подписка недоступны снаружи", "remnawave_bot": "бот не отвечает, оплаты не проходят",
             "remnawave_bot_db": "бот не работает", "remnawave_bot_redis": "бот может не работать",
             "remnawave-subscription-page": "клиенты не получают подписку", "docker": "все контейнеры сервера под вопросом"}
EXIT_RU = {1: "завершился с ошибкой", 2: "завершился с ошибкой", 125: "Docker не смог его запустить",
           126: "не запускается программа", 127: "не найдена программа", 137: "убит из-за нехватки памяти или вручную",
           139: "аварийно упал", 143: "остановлен командой"}


def ct_label(n):
    ru = CT_RU.get(n) or ("старая копия ноды" if n.startswith("remnanode-old") else "")
    return "%s (%s)" % (ru, n) if ru and n != "docker" else ru or n


def exit_ru(ex):
    return "%s, код %d" % (EXIT_RU[ex], ex) if ex in EXIT_RU else "код выхода %d" % ex


def times_ru(k):
    return "%d %s" % (k, "раз" if k % 10 in (0, 1, 5, 6, 7, 8, 9) or 11 <= k % 100 <= 14 else "раза")


PERMANENT_RP = ("always", "unless-stopped", "on-failure")
TEMP_LOG_KEEP = 2 * 86400


def is_temp(ct, perm):
    """Временный контейнер: без политики перезапуска, не из docker compose, не назван важным (critical/permanent)."""
    return (ct.get("rp") or "no") not in PERMANENT_RP and not ct.get("cp") and str(ct.get("n") or "") not in perm


def temp_track(dk, n, ct, now, seen_temp):
    """Временный контейнер: без тревог, в отдельный журнал — когда завершился (если видели его работающим)."""
    temp, log = dk.setdefault("temp", {}), dk.setdefault("temp_log", [])
    seen_temp.add(n)
    st, ex = ct.get("s") or "", int(num(ct.get("ex")))
    if st == "running":
        temp[n] = {"ts": now, "run": True}
    elif temp.get(n, {}).get("run"):
        log.append({"n": n, "ts": now, "how": "завершился, код %d" % ex if ex else "завершился без ошибок"})
        temp[n] = {"ts": now, "run": False}
    else:
        temp.setdefault(n, {"ts": now, "run": False})


def docker_problems(dk, s, now, ign, perm=None):
    """Один срез сборщика -> ({ключ: что не так}, [разовые события]). dk — память по серверу (меняется).
    perm — имена важных контейнеров; задан только для нового сборщика (docker_v=2): тогда временные идут отдельно."""
    if s.get("docker_ok") is False:
        return {"docker": "Docker не отвечает"}, []
    probs, events, seen, seen_temp = {}, [], set(), set()
    known, rcs = dk.setdefault("known", {}), dk.setdefault("rc", {})
    for ct in s.get("containers") or []:
        n = str(ct.get("n") or "")
        if not n or n in ign:
            continue
        if perm is not None and is_temp(ct, perm):
            temp_track(dk, n, ct, now, seen_temp)
            continue
        seen.add(n)
        st, rp, ex, rc = ct.get("s") or "", ct.get("rp") or "no", int(num(ct.get("ex"))), int(num(ct.get("rc")))
        if st == "restarting":
            probs[n] = "перезапускается по кругу" + (" (%s)" % exit_ru(ex) if ex else "")
        elif st == "dead":
            probs[n] = "сломан, Docker не может его ни запустить, ни удалить (dead)"
        elif st == "running":
            known[n] = now
            if ct.get("h") == "unhealthy":
                probs[n] = "запущен, но не проходит свою проверку здоровья (unhealthy)"
        elif rp in ("always", "unless-stopped", "on-failure") or n in known:
            probs[n] = "остановлен" + (" (%s)" % exit_ru(ex) if ex else "")
        hist = [p for p in rcs.get(n, []) if now - p[0] <= 3600]
        last = rcs[n][-1][1] if rcs.get(n) else None
        if last is not None and rc < last:   # контейнер пересоздан — счёт заново
            hist, last = [], None
        hist.append([now, rc])
        rcs[n] = hist
        if hist[-1][1] - hist[0][1] >= RESTARTS_HOUR and n not in probs:
            probs[n] = "перезапускается по кругу: %s за час" % times_ru(hist[-1][1] - hist[0][1])
        elif last is not None and rc > last and ex != 0 and st == "running":
            events.append((n, "упал (%s) и перезапустился сам — сейчас работает" % exit_ru(ex)))
    for n in list(rcs):
        if n not in seen:
            del rcs[n]
    if perm is not None:
        for n, v in list(dk.get("temp", {}).items()):
            if n not in seen_temp:
                if v.get("run"):
                    dk.setdefault("temp_log", []).append({"n": n, "ts": now, "how": "удалён"})
                del dk["temp"][n]
        dk["temp_log"] = [x for x in dk.get("temp_log", []) if now - x["ts"] <= TEMP_LOG_KEEP]
    for n, t in list(known.items()):
        if n in seen or n in ign:
            continue
        if now - t > DOCKER_FORGET:
            del known[n]
        else:
            probs[n] = "пропал — контейнер удалён и не создан заново"
    return probs, events


def docker_text(name, title, items, ts, impact=False):
    lines = []
    for k, t in items:
        lines.append("• <b>%s</b> — %s" % (html.escape(ct_label(k)), html.escape(t)))
        if k in CT_IMPACT and impact:
            lines.append("   ⚠️ %s" % CT_IMPACT[k])
    return "%s\n\n🖥 <b>Сервер:</b> %s · 🕒 %s МСК\n\n%s" % (title, html.escape(name), msk(ts).strftime("%d.%m %H:%M"),
                                                          "\n".join(lines))


def docker_pass(e, name, s, c):
    """Последний свежий срез сервера -> сообщения о контейнерах. Старый сборщик (без containers) — молчим."""
    if "containers" not in s and "docker_ok" not in s:
        return []
    ts = s["ts"]
    dk = e.setdefault("docker", {})
    crit = set(c.get("critical_containers") or []) | {"docker"}
    perm = (crit | set(c.get("permanent_containers") or [])) if num(s.get("docker_v")) >= 2 else None
    probs, events = docker_problems(dk, s, ts, set(c.get("ignore_containers") or []), perm)
    cand, active = dk.setdefault("cand", {}), dk.setdefault("active", {})
    newly = []
    for k, t in probs.items():
        cand[k] = cand.get(k, 0) + 1
        if k in active:
            active[k] = t
        elif cand[k] >= DOCKER_CONFIRM:
            active[k] = t
            newly.append((k, t))
    for k in list(cand):
        if k not in probs:
            del cand[k]
    gone = [(k, active.pop(k)) for k in list(active) if k not in probs]
    dk["running"] = sum(1 for ct in s.get("containers") or [] if ct.get("s") == "running")
    work, msgs = in_work(c, ts), []
    hint = "\n\nЕсли его остановили нарочно — добавьте его имя в ignore_containers в /etc/channel-watch/ddos.json, и тревоги о нём не будет."
    for items, title, extra in ((newly, "🐳 <b>Контейнеры: требуют внимания</b>", hint),
                                (events, "🐳 <b>Контейнер упал и поднялся сам</b>", "")):
        if not items:
            continue
        if work or any(k in crit for k, _ in items):
            msgs.append(docker_text(name, title, items, ts, impact=items is newly) + extra)
        else:
            e.setdefault("deferred", []).append({"ts": ts, "state": "docker",
                                                  "keys": [k for k, _ in items],
                                                  "reasons": ["%s — %s" % (ct_label(k), t) for k, t in items]})
    if gone and (work or any(k in crit for k, _ in gone)):
        msgs.append(docker_text(name, "🟢 <b>Контейнеры снова работают</b>", [(k, "работает") for k, _ in gone], ts))
    return msgs


# ---------- бэкапы ----------
def backup_problems(bks, now, max_h):
    """{имя бэкапа: что не так} по срезу сборщика."""
    out = {}
    for b in bks or []:
        n = str(b.get("name") or "?")
        if b.get("missing"):
            out[n] = "нет журнала бэкапа"
        elif not b.get("ok_ts"):
            out[n] = "в журнале нет ни одной удачной копии" + (": " + b["err"] if b.get("err") else "")
        elif b.get("err_ts") and b["err_ts"] > b["ok_ts"]:
            out[n] = "последняя попытка с ошибкой (%s): %s" % (msk(b["err_ts"]).strftime("%d.%m %H:%M"), b.get("err") or "?")
        elif now - b["ok_ts"] > max_h * 3600:
            out[n] = "последняя удачная копия %s — %s назад" % (msk(b["ok_ts"]).strftime("%d.%m %H:%M"), dur(now - b["ok_ts"]))
    return out


def backup_pass(e, name, s, c):
    """Бэкапы сервера по последнему срезу -> сообщения. Сборщик без бэкапов — молчим."""
    if "backups" not in s:
        return []
    bk = e.setdefault("backup", {})
    probs = backup_problems(s["backups"], s["ts"], num(c.get("backup_max_hours"), BACKUP_MAX_HOURS))
    cand, active = bk.setdefault("cand", {}), bk.setdefault("active", {})
    newly = []
    for k, t in probs.items():
        cand[k] = cand.get(k, 0) + 1
        if k in active:
            active[k] = t
        elif cand[k] >= DOCKER_CONFIRM:
            active[k] = t
            newly.append((k, t))
    for k in list(cand):
        if k not in probs:
            del cand[k]
    gone = [k for k in list(active) if k not in probs]
    for k in gone:
        active.pop(k)
    bk["last"] = [{k: b.get(k) for k in ("name", "ok_ts", "ok")} for b in s["backups"]]
    head = "\n\n🖥 <b>Сервер:</b> %s · 🕒 %s МСК\n\n" % (html.escape(name), msk(s["ts"]).strftime("%d.%m %H:%M"))
    msgs = []
    if newly:
        msgs.append("💾 <b>Бэкап не в порядке</b>" + head + "\n".join(
            "• <b>%s</b> — %s" % (html.escape(k), html.escape(t)) for k, t in newly)
            + "\n\nПока бэкап не идёт, при поломке сервера данные с последней копии потеряются.")
    if gone:
        last = {b["name"]: b for b in bk["last"]}
        msgs.append("🟢 <b>Бэкап снова в порядке</b>" + head + "\n".join(
            "• <b>%s</b> — копия %s" % (html.escape(k), msk(last[k]["ok_ts"]).strftime("%d.%m %H:%M") if last.get(k, {}).get("ok_ts") else "есть")
            for k in gone))
    return msgs


def backup_lines(hosts, now):
    """(проблемы, сведения) для отчёта."""
    iss, rows = [], []
    for n, e in hosts.items():
        bk = e.get("backup") or {}
        for k, t in (bk.get("active") or {}).items():
            iss.append("💾 <b>Бэкап %s (%s)</b> — %s" % (html.escape(k), html.escape(n), html.escape(t)))
        for b in bk.get("last") or []:
            if b.get("ok_ts"):
                size = re.search(r"size=(\S+)", b.get("ok") or "")
                rows.append("%s — %s%s" % (html.escape(b["name"]), msk(b["ok_ts"]).strftime("%d.%m %H:%M"),
                                           " (%s)" % html.escape(size.group(1)) if size else ""))
    info = ["<b>Бэкапы, последняя удачная копия:</b> " + ", ".join(rows)] if rows else []
    return iss, info


# ---------- щит ----------
def ago_ru(ts, now):
    m = int(max(now - ts, 0) // 60)
    return "только что" if m < 2 else "%d мин назад" % m if m < 60 else "%d ч назад" % (m // 60)


def _ipapi_batch(ips, timeout=8):
    """ip-api.com, пакет до 100 адресов: {адрес: {...}}. Бесплатно, без ключа (только http)."""
    body = json.dumps([{"query": a, "fields": "status,query,countryCode,city,isp,org,as,mobile,proxy,hosting"} for a in ips[:100]])
    try:
        r = subprocess.run(["curl", "-s", "-m", str(timeout), "-X", "POST", "-H", "Content-Type: application/json",
                            "-d", "@-", "http://ip-api.com/batch"], input=body, capture_output=True, text=True,
                           timeout=timeout + 5)
        return {x["query"]: x for x in json.loads(r.stdout or "[]") if isinstance(x, dict) and x.get("status") == "success"}
    except (OSError, ValueError, subprocess.TimeoutExpired, KeyError, TypeError):
        return {}


def ip_lookup(ips):
    """{адрес: {"as", "net", "country", "city", "mobile", "proxy", "hosting"}} — ip-api.com, кого не нашёл — ipinfo.io."""
    if IPINFO_LOOKUP:
        return IPINFO_LOOKUP(ips)
    out = {}
    for a, x in _ipapi_batch(list(ips)).items():
        out[a] = {"as": (x.get("as") or "").split(" ")[0], "net": x.get("org") or x.get("isp") or "",
                  "country": x.get("countryCode") or "", "city": x.get("city") or "",
                  "mobile": bool(x.get("mobile")), "proxy": bool(x.get("proxy")), "hosting": bool(x.get("hosting"))}
    rest = [a for a in ips if a not in out]
    if rest:
        try:
            import blockwatch
            for a in rest[:5]:
                r = blockwatch.hop_lookup(a, timeout=4)
                if r:
                    org = r.get("org") or ""
                    out[a] = {"as": org.split(" ")[0] if org.startswith("AS") else "", "net": org.split(" ", 1)[-1],
                              "country": r.get("country") or "", "city": r.get("city") or ""}
        except Exception:  # запасной источник не обязателен
            pass
    return out


def ip_details(ips, now=None, cache_file=None):
    """Сведения об адресах с кешем на неделю: {адрес: {...}}. Сеть недоступна — что есть в кеше."""
    now = now or time.time()
    path = cache_file or IPINFO_CACHE
    try:
        cache = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    need = [a for a in ips if a not in cache or now - cache[a].get("ts", 0) > IPINFO_TTL]
    if need:
        for a, v in ip_lookup(need).items():
            cache[a] = dict(v, ts=int(now))
        cache = {a: v for a, v in cache.items() if now - v.get("ts", 0) <= IPINFO_TTL}
        try:
            with open(path + ".tmp", "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False)
            os.replace(path + ".tmp", path)
        except OSError:
            pass
    return {a: cache[a] for a in ips if a in cache}


def scan_membership(ips, folder=None):
    """{адрес: «сканеры, СКИПА (РКН)»} — в каких списках сканеров адрес (по скачанным спискам сторожа)."""
    try:
        import scanlists
        per = {}
        for name in list(scanlists.LISTS) + [getattr(scanlists, "BEHAVIOR", "behavior")]:
            try:
                per[name] = scanlists.parse(open(os.path.join(folder or SCAN_DIR, name + ".list"), encoding="utf-8").read())[0]
            except OSError:
                continue
        out = {}
        for a in ips:
            w = scanlists.which_list(a, per)
            if w and w != "свои добавки":
                out[a] = w
        return out
    except Exception:  # списков нет — не беда
        return {}


def ip_line(info, scan=""):
    """Строка под адресом: «AS12389 Rostelecom · RU Moscow · мобильная сеть · в списке сканеров: …»."""
    parts = []
    if info:
        net = " ".join(x for x in (info.get("as"), info.get("net")) if x)
        if net:
            parts.append(net[:60])
        place = " ".join(x for x in (info.get("country"), info.get("city")) if x)
        if place:
            parts.append(place)
        tags = [t for k, t in (("mobile", "мобильная сеть — за адресом может быть много людей"), ("hosting", "хостинг / дата-центр"),
                               ("proxy", "прокси или VPN")) if info.get(k)]
        parts += tags
    if scan:
        parts.append("в списке сканеров: " + scan)
    return ("   " + html.escape(" · ".join(parts))) if parts else ""


def ports_line(sh):
    ports = [x for x in (sh.get("ports") or []) if isinstance(x, list) and len(x) == 2][:3]
    return ("🎯 <b>Куда бьют:</b> " + ", ".join("%s (%s)" % (html.escape(str(p)), cnt(n)) for p, n in ports)) if ports else ""


def suspects_block(sh, ts, clients=None):
    """Источники для сообщения об атаке: кто больше всех сверх порога, с пометкой наш/не наш."""
    lim = (sh.get("limits") or {}).get("rate", 200)
    lines = ["🛡 <b>Больше всех сверх порога</b> (%d новых соединений в секунду с адреса) за 10 минут:" % lim]
    shown = [a for a, _ in sh["suspects"][:SHIELD_OFFER_IPS]]
    info, scan = ip_details(shown), scan_membership(shown)
    for a, p in sh["suspects"][:SHIELD_OFFER_IPS]:
        v = (clients or {}).get(a)
        mark = ("✅ наш клиент (%s, %s, %s)" % (html.escape(str(v.get("user", ""))[:28]), html.escape(str(v.get("node", ""))),
                                               ago_ru(v.get("last", ts), ts)) if v else
                "❓ не клиент" if clients is not None else "сверка с клиентами не удалась")
        lines.append("• <code>%s</code> — %s лишних — %s" % (html.escape(a), cnt(p), mark))
        extra = ip_line(info.get(a), scan.get(a, ""))
        if extra:
            lines.append(extra)
    pl = ports_line(sh)
    if pl:
        lines.append(pl)
    return "\n".join(lines)


def incident_text(o, clients=None):
    """Сообщение об атаке с источниками (или без них) — одно на случай."""
    text = o["text"]
    if o.get("ips") and o.get("sh"):
        text += "\n\n" + suspects_block(o["sh"], o["ts"], clients)
        ours = [a for a in o["ips"] if a in (clients or {})]
        if clients is not None:
            text += "\nНаших клиентов среди них: %d из %d." % (len(ours), len(o["ips"]))
    else:
        text += ("\n\n🛡 Щит пока не назвал отдельных источников (никто не превысил порог соединений с адреса). "
                 "Можно включить щит на 2 ч — он режет лишнее со всех адресов.")
    return text + "\n\nЕсли это обычный трафик (обновления, закачки) — «Это не атака»: порог этого сервера поднимется на неделю."


def shield_offer_text(name, sh, ts, attack=None, clients=None):
    """clients — {адрес: {user, last, node}} из shieldbot.lookup_clients (None — сверка не удалась)."""
    lim = (sh.get("limits") or {}).get("rate", 200)
    head = ("🚨 <b>Щит: %s — атака, можно отрезать источники</b>" % html.escape(name) if attack else
            "🛡 <b>Щит: %s — кто-то открывает слишком много соединений</b>" % html.escape(name))
    lines = [head, "🖥 <b>Сервер:</b> %s" % server_label(name),
             "🕒 %s МСК · сейчас щит %s" % (msk(ts).strftime("%d.%m %H:%M"),
                                          "включён" if sh.get("mode") == "on" else "в режиме наблюдения (ничего не режется)")]
    if attack:
        lines.append("💥 %s, уровень %s" % (attack.get("type"), SEVERITY_RU.get(attack.get("severity"), "?").lower()))
    pl = ports_line(sh)
    if pl:
        lines.append(pl)
    lines += ["", "Больше всех сверх порога (%d новых соединений в секунду с адреса) за 10 минут:" % lim]
    shown0 = [a for a, _ in sh["suspects"][:SHIELD_OFFER_IPS]]
    info, scan = ip_details(shown0), scan_membership(shown0)
    for a, p in sh["suspects"][:SHIELD_OFFER_IPS]:
        v = (clients or {}).get(a)
        mark = ("✅ наш клиент (%s, %s, %s)" % (html.escape(str(v.get("user", ""))[:28]), html.escape(str(v.get("node", ""))),
                                               ago_ru(v.get("last", ts), ts)) if v else
                "❓ не клиент" if clients is not None else "сверка с клиентами не удалась")
        lines.append("• <code>%s</code> — %s лишних — %s" % (html.escape(a), cnt(p), mark))
        extra = ip_line(info.get(a), scan.get(a, ""))
        if extra:
            lines.append(extra)
    if sh.get("suspects_total", 0) > SHIELD_OFFER_IPS:
        lines.append("… и ещё %d" % (sh["suspects_total"] - SHIELD_OFFER_IPS))
    shown = [a for a, _ in sh["suspects"][:SHIELD_OFFER_IPS]]
    ours = [a for a in shown if a in (clients or {})]
    lines.append("")
    if clients is not None:
        lines.append("Наших клиентов среди них: %d из %d (сверка по журналам Xray нод за сутки)." % (len(ours), len(shown)))
    lines += ["«Заблокировать» — только чужие адреса целиком; «Включить щит» — резать лишнее со всех адресов, у наших "
              "клиентов порог в 5 раз выше.",
              "⚠️ За одним адресом бывают сотни клиентов мобильного оператора. Наших блокировать — только отдельной кнопкой."]
    return "\n".join(lines)


def shield_alarm_keys(sh):
    """Беды щита, о которых тревожить: tick — таймер снятия режима не работает; kernel — ядро режет, а по state watch."""
    warn = [str(w) for w in (sh.get("warn") if isinstance(sh.get("warn"), list) else [])]
    keys = set()
    tick = sh.get("tick")
    if (tick and tick not in ("active", "unknown")) or any(
            w.startswith("таймер tick не работает") or "таймер не работает" in w for w in warn):
        keys.add("tick")
    if any(w.startswith("в ядре щит режет") for w in warn):
        keys.add("kernel")
    return keys


def shield_warn_text(name, title, keys, warn, ts):
    lines = [title, "🖥 <b>Сервер:</b> %s · 🕒 %s МСК" % (server_label(name), msk(ts).strftime("%d.%m %H:%M")), ""]
    lines += ["• " + SHIELD_ALARM_RU[k] for k in keys]
    if warn:
        lines.append("Щит сообщает: " + html.escape("; ".join(warn)))
    return "\n".join(lines)


def shield_warn_pass(e, name, sh, ts, c):
    """Предупреждения щита (warn, tick) из среза: запомнить для отчёта; тревога — если «таймер tick не работает» или
    «ядро режет, а по state watch» держится SHIELD_ALARM_CONFIRM опросов щита подряд. Срезы раз в 10 с несут один и
    тот же опрос (раз в минуту, поле at) — считаются опросы, а не срезы. Ядро режет — сразу в любое время (могут
    резаться клиенты), таймер — в рабочие часы, ночью в отчёт. -> список сообщений."""
    es = e.setdefault("shield", {})
    warn = [str(w)[:200] for w in (sh.get("warn") if isinstance(sh.get("warn"), list) else [])][:5]
    es.update({"warn": warn, "tick": sh.get("tick"), "v": sh.get("v"), "table_v": sh.get("table_v")})
    at = int(num(sh.get("at"))) or int(ts)
    if at == es.get("warn_at"):
        return []
    es["warn_at"] = at
    keys = shield_alarm_keys(sh)
    run = es.setdefault("alarm_run", {})
    for k in keys:
        run[k] = run.get(k, 0) + 1
    for k in list(run):
        if k not in keys:
            del run[k]
    active = es.setdefault("alarm", [])
    newly = [k for k in sorted(keys) if run[k] >= SHIELD_ALARM_CONFIRM and k not in active]
    gone = [k for k in active if k not in keys]
    es["alarm"] = [k for k in active if k in keys] + newly
    work, msgs = in_work(c, ts), []
    if newly:
        if work or "kernel" in newly:
            msgs.append(shield_warn_text(name, "⚠️ <b>Щит, %s: неладно</b>" % html.escape(name), newly, warn, ts))
        else:
            e.setdefault("deferred", []).append({"ts": ts, "state": "shield", "reasons": [
                "щит: " + SHIELD_ALARM_RU[k] for k in newly]})
    if gone and (work or "kernel" in gone):
        msgs.append("🟢 <b>Щит, %s: снова в порядке</b> — %s" % (
            html.escape(name), "; ".join(SHIELD_ALARM_OK_RU[k] for k in gone)))
    return msgs


def shield_warn_lines(hosts):
    """Строки-предупреждения щита для отчёта: по серверу, если щит в последнем опросе что-то сообщил (warn)."""
    out = []
    for n, e in sorted(hosts.items()):
        es = e.get("shield") or {}
        if es.get("warn") and e.get("verdict") != "offline":
            out.append("🛡 <b>Щит, %s:</b> %s" % (html.escape(n), html.escape("; ".join(es["warn"]))))
    return out


def shield_pass(e, name, s, c, state):
    """Последний срез: предложение кнопок в state["shield_pending"] (отправляет main через shieldbot) и сообщение,
    когда щит сам вернулся в наблюдение. -> список обычных сообщений."""
    sh = s.get("shield")
    if not isinstance(sh, dict) or not sh.get("loaded"):
        if isinstance(e.get("shield"), dict):   # щита нет или не загружен — его прежние предупреждения уже не о чем
            e["shield"].update({"warn": [], "alarm_run": {}, "alarm": []})
        return []
    ts, msgs = s["ts"], []
    es = e.setdefault("shield", {})
    if es.get("mode") == "on" and sh.get("mode") == "watch" and es.get("until"):   # on без срока — о нём своя тревога
        msgs.append("🛡 <b>Щит, %s:</b> время вышло — снова режим наблюдения, ничего не режется." % html.escape(name))
    es.update({"mode": sh.get("mode"), "until": sh.get("until", 0), "blocked": sh.get("blocked", 0),
               "suspects": sh.get("suspects_total", 0), "top": (sh.get("suspects") or [[None, 0]])[0],
               "scan": sh.get("scan") or {}})
    msgs += shield_warn_pass(e, name, sh, ts, c)
    sus = sh.get("suspects") or []
    if not sus:
        return msgs
    if e.get("verdict") == "attack" or e.get("cand") == "attack":
        return msgs   # идёт (или подтверждается) атака — источники придут в её сообщении
    attack = None
    top = int(num(sus[0][1]))
    if top >= SHIELD_OFFER_MIN and ts - es.get("offer_at", 0) >= SHIELD_OFFER_EVERY:
        if not in_work(c, ts):
            if ts - es.get("offer_at", 0) >= SHIELD_OFFER_EVERY:
                es["offer_at"] = ts
                e.setdefault("deferred", []).append({"ts": ts, "state": "shield", "reasons": [
                    "щит: подозрительных %d, больше всех %s — %s лишних" % (sh.get("suspects_total", len(sus)), sus[0][0], cnt(top))]})
            return msgs
        es["offer_at"] = ts
        state.setdefault("shield_pending", []).append({
            "kind": "suspects", "host": name, "ips": [a for a, _ in sus[:SHIELD_OFFER_IPS]], "sh": sh, "ts": ts,
            "attack": attack, "peak": {k: num(s.get(k)) for k in ("rx_bps", "rx_pps")}})
    return msgs


def shield_info(hosts):
    sh = [(n, e["shield"]) for n, e in hosts.items() if e.get("shield")]
    if not sh:
        return None
    on = [n for n, x in sh if x.get("mode") == "on"]
    blocked = sum(int(x.get("blocked") or 0) for _, x in sh)
    sus = [(n, x) for n, x in sh if x.get("suspects")]
    out = "<b>Щит:</b> стоит на %d серверах · %s · заблокировано адресов: %d" % (
        len(sh), ("включён на: " + ", ".join(html.escape(n) for n in on)) if on else "везде наблюдение", blocked)
    if sus:
        out += " · подозрительные сейчас: " + ", ".join("%s (%d)" % (html.escape(n), x["suspects"]) for n, x in sus)
    return out


SCAN_SUMMARY = "/var/lib/channel-watch/scanners/summary.json"


def plural(k, one, few, many):
    k = abs(int(k))
    w = one if k % 10 == 1 and k % 100 != 11 else few if 2 <= k % 10 <= 4 and not 12 <= k % 100 <= 14 else many
    return "%s %s" % (cnt(k), w)


def scan_lines(hosts, summary_path=None):
    """Сканеры для отчёта: (проблемы, сведения). Сведения — сколько стучались за сутки и куда больше всего."""
    sc = [(n, (e.get("shield") or {}).get("scan") or {}) for n, e in hosts.items()]
    sc = [(n, x) for n, x in sc if x.get("nets")]
    try:
        sm = json.load(open(summary_path or SCAN_SUMMARY, encoding="utf-8"))
    except (OSError, ValueError):
        sm = {}
    issues, info = [], []
    if not sc and not sm:
        return issues, info
    drop = [n for n, x in sc if x.get("mode") == "drop"]
    total = sum(int(x.get("packets") or 0) for _, x in sc)
    srcs = sum(int(x.get("sources") or 0) for _, x in sc)
    top = sorted(((n, int(x.get("packets") or 0)) for n, x in sc), key=lambda t: -t[1])[:3]
    if sm.get("sent") is False:   # scanlists не разослал итог (предел, пустой) — щиты на прошлом, число сетей не их
        what = "новый список не разослан, на щитах прошлый"
    else:
        what = "список %s%s" % (
            plural(sm.get("nets") or max([int(x.get("nets") or 0) for _, x in sc] or [0]), "сеть", "сети", "сетей"),
            (" от " + msk(sm["ts"]).strftime("%d.%m %H:%M")) if sm.get("ts") else "")
    line = "<b>Сканеры (РКН и др.):</b> %s · %s · за сутки стучались %s с %s" % (
        what,
        ("отбрасываем на: " + ", ".join(html.escape(n) for n in drop)) if drop else "пока только считаем",
        plural(total, "раз", "раза", "раз"), plural(srcs, "адреса", "адресов", "адресов"))
    if total and top:
        line += " · больше всего: " + ", ".join("%s (%s)" % (html.escape(n), cnt(p)) for n, p in top if p)
    info.append(line)
    if sm.get("notes"):
        issues.append("🔎 <b>Список сканеров:</b> " + html.escape("; ".join(sm["notes"])))
    hs = sm.get("hosts") or {}
    bad = [h for h, v in hs.items() if not str(v).startswith("ok")]   # «ok, отвергнуто N» — принят, но не весь
    part = [h for h, v in hs.items() if str(v).startswith("ok") and str(v) != "ok"]
    if bad:
        issues.append("🔎 <b>Список сканеров не приняли:</b> " + ", ".join(html.escape(h) for h in bad))
    if part:
        issues.append("🔎 <b>Список сканеров приняли не всё:</b> " + ", ".join(
            "%s (%s)" % (html.escape(h), html.escape(str(hs[h]))) for h in part))
    cl = sm.get("clients") or {}
    if cl:
        import scanlists
        issues.append("🔎 <b>В списке сканеров наши клиенты: %d</b>\n" % len(cl)
                      + "\n".join("• " + html.escape(scanlists.client_text(a, v)) for a, v in list(cl.items())[:5])
                      + ("\n…и ещё %d" % (len(cl) - 5) if len(cl) > 5 else "")
                      + "\nОтрежутся, когда сканеры начнут отбрасываться; оставить или в исключения "
                        "(/etc/channel-watch/scanners-exclude.txt) — решать вам")
    return issues, info


def docker_issue(n, e):
    act = (e.get("docker") or {}).get("active") or {}
    if not act:
        return None
    return "🐳 <b>%s</b> — %s" % (html.escape(n), html.escape("; ".join("%s: %s" % (ct_label(k), t) for k, t in act.items())))


def link_bps(c, h):
    """Скорость канала сервера, бит/с: "link_mbps" у сервера в ddos.json, иначе общий; 0 — не задана."""
    v = num((h or {}).get("link_mbps")) or num(c.get("link_mbps"))
    return v * 1e6 if v > 0 else 0.0


def process(state, data, c, now, db=None):
    """-> список текстов. data: {имя: ответ сборщика или None}."""
    msgs = []
    hosts = state.setdefault("hosts", {})
    overrides = load_overrides()
    HOST_INFO.clear()
    HOST_INFO.update({h["name"]: (h.get("host"), h.get("note")) for h in c.get("hosts", []) if h.get("name")})
    for h in c["hosts"]:
        name = h["name"]
        e = hosts.setdefault(name, new_entry())
        d = data.get(name)
        fresh = [s for s in (d or {}).get("samples", []) if num(s.get("ts")) > e["last_ts"]]
        if not d or not fresh and now - e["last_ts"] > STALE_AFTER:
            t = offline(e, name, now, "сборщик не отвечает" if not d else "нет свежих срезов")
            if t:
                msgs.append(t)
            continue
        th = thresholds(c, db_baseline(db, name) if db is not None else state.get("baseline", {}).get(name), overrides.get(name),
                        link_bps(c, h))
        ign = set(c.get("ignore_units") or [])
        for s in sorted(fresh, key=lambda s: s["ts"]):
            s["failed_units"] = [u for u in (s.get("failed_units") or []) if u not in ign]
            interval = s["ts"] - e["last_ts"] if e["last_ts"] else 0
            drop = max(num(s.get("rx_drop_ps")), num(s.get("tx_drop_ps")))
            e["drop_run"] = e.get("drop_run", 0) + 1 if drop >= max(th["rx_drop_ps"], DROP_MIN) else 0
            s["drop_sustained"] = e["drop_run"] >= DROP_CONFIRM
            v = classify(s, th, e["last_syn"], interval)
            t = apply(e, name, v, s, s["ts"], c, th, db)
            if t:
                msgs.append(t)
            if v["state"] == e["verdict"]:
                e["reasons"] = v["reasons"]
            e["last_ts"], e["last_syn"], e["last_m"] = s["ts"], int(num(s.get("syn_recv"))), s
            if db is not None:   # срез атаки, её подтверждения или спада — в базу порогов не пойдёт
                susp = 1 if v["state"] == "attack" or e["verdict"] == "attack" or e["cand"] == "attack" else 0
                db.execute("insert or ignore into samples (host, ts, rx_bps, rx_pps, syncookies_ps, listen_drop_ps, rx_drop_ps,"
                           " tx_bps, tx_pps, susp) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (name, int(s["ts"]), s.get("rx_bps"), s.get("rx_pps"), s.get("syncookies_ps"),
                            num(s.get("listen_drop_ps")) + num(s.get("listen_overflow_ps")), s.get("rx_drop_ps"),
                            s.get("tx_bps"), s.get("tx_pps"), susp))
        if fresh:
            last = max(fresh, key=lambda s: s["ts"])
            msgs += docker_pass(e, name, last, c)
            msgs += backup_pass(e, name, last, c)
            msgs += shield_pass(e, name, last, c, state)
            inc = e.pop("incident", None)
            if inc:   # атака: одно сообщение с источниками и кнопками щита
                sh = last.get("shield") if isinstance(last.get("shield"), dict) and last["shield"].get("loaded") else None
                state.setdefault("shield_pending", []).append(dict(inc, kind="attack", host=name, sh=sh,
                                                                   ips=[a for a, _ in ((sh or {}).get("suspects") or [])[:SHIELD_OFFER_IPS]]))
    return msgs


def summary(state, c, now, db=None):
    lines = ["📊 <b>Сторож · DDoS и нагрузка: сводка</b> (%s МСК)" % msk(now).strftime("%d.%m %H:%M")]
    hosts = state.get("hosts", {})
    attacks = []
    if db is not None:
        attacks = list(db.execute("select host, start, end, type, severity from attacks where start > ? order by start",
                                  (now - 86400,)))
    lines.append("Атак за сутки: %d" % len(attacks))
    for hst, s, e_, ty, sev in attacks[:10]:
        lines.append("• %s — %s, %s, %s (%s)" % (html.escape(hst), msk(s).strftime("%d.%m %H:%M"), ty,
                                                SEVERITY_RU.get(sev, sev), dur(e_ - s)))
    bad = [(n, e) for n, e in hosts.items() if e.get("verdict") not in ("stable", "unknown")]
    lines.append("Сейчас не в норме: %s" % (", ".join("%s (%s)" % (html.escape(n), e["verdict"]) for n, e in bad) or "нет"))
    lines += [x for x in (docker_issue(n, e) for n, e in hosts.items()) if x]
    deferred = [(n, d) for n, e in hosts.items() for d in e.get("deferred", [])]
    if deferred:
        lines.append("Ночью было (без сообщений): " + "; ".join(
            "%s %s — %s" % (html.escape(n), msk(d["ts"]).strftime("%H:%M"), html.escape(", ".join(d["reasons"])))
            for n, d in deferred[:10]))
    lines.append("Серверов под наблюдением: %d" % len(c["hosts"]))
    return "\n".join(lines)


def report_lines(since, now, state=None, c=None, db=None):
    """Блок «Нагрузка и DDoS» для отчёта сторожа (probe.report_text) за период since..now. Только чтение."""
    c = c or cfg()
    state = state if state is not None else load_state()
    own_db = db is None
    if own_db:
        if not os.path.exists(DB_FILE):
            return []
        db = sqlite3.connect("file:%s?mode=ro" % DB_FILE, uri=True, timeout=10)
    try:
        hosts = state.get("hosts", {})
        names = [h["name"] for h in c.get("hosts", [])] or list(hosts)
        if not names:
            return []
        off = [n for n in names if hosts.get(n, {}).get("verdict") == "offline"]
        attacks = list(db.execute("select host, start, end, type, severity, peak from attacks where end >= ? and notified = 1"
                                  " order by start", (int(since),)))
        live = [(n, e["attack"]) for n, e in hosts.items() if e.get("verdict") == "attack" and e.get("attack")]
        head = "<b>Нагрузка и DDoS:</b> %d из %d серверов на связи" % (len(names) - len(off), len(names))
        if off:
            head += " · ⚫️ нет связи: " + ", ".join(html.escape(n) for n in off)
        n_att = len(attacks) + len(live)
        head += " · атак за период нет" if not n_att else " · 🔴 атак: %d" % n_att
        out = [head]
        for n, a in live:
            out.append("🔴 %s — идёт с %s: %s, %s, пик %s Мбит/с · %s пак/с" % (
                html.escape(n), msk(a["start"]).strftime("%H:%M"), a.get("type"), SEVERITY_RU.get(a.get("severity"), "?").lower(),
                mbit(a["peak"].get("rx_bps")), cnt(a["peak"].get("rx_pps"))))
        for hst, st_, en, ty, sev, pk in attacks[-5:]:
            pk = json.loads(pk or "{}")
            out.append("🔴 %s — %s, %s, %s, %s, пик %s Мбит/с · %s пак/с" % (
                html.escape(hst), msk(st_).strftime("%d.%m %H:%M"), ty, SEVERITY_RU.get(sev, sev).lower(), dur(en - st_),
                mbit(pk.get("rx_bps")), cnt(pk.get("rx_pps"))))
        for state_name, icon, label in (("load", "🟠", "высокая нагрузка"), ("health", "🟡", "требует внимания")):
            bad = [(n, e) for n, e in hosts.items() if e.get("verdict") == state_name]
            if bad:
                reasons = sorted({r for _, e in bad for r in (e.get("reasons") or [])})
                out.append("%s %s: %s%s" % (icon, label, ", ".join(html.escape(n) for n, _ in bad),
                                            (" — " + html.escape("; ".join(reasons))) if reasons else ""))
        out += [x for x in (docker_issue(n, e) for n, e in hosts.items()) if x]
        out += shield_warn_lines(hosts)
        night =[(n, d) for n, e in hosts.items() for d in e.get("deferred", []) if d["ts"] >= since]
        if night:
            out.append("ночью без сообщений: " + "; ".join("%s %s — %s" % (html.escape(n), msk(d["ts"]).strftime("%H:%M"),
                                                                             html.escape(", ".join(d["reasons"])))
                                                            for n, d in night[:5]))
        peaks = list(db.execute("select host, max(rx_bps) m from samples where ts >= ? group by host order by m desc limit 3",
                                (int(since),)))
        tail = []
        if peaks:
            tail.append("пик входящего: " + ", ".join("%s %s Мбит/с" % (html.escape(h), mbit(m)) for h, m in peaks))
        nb = db.execute("select count(distinct host) from baseline").fetchone()[0]
        tail.append("пороги по нагрузке: у %d из %d" % (nb, len(names)))
        out.append(" · ".join(tail))
        return out
    except sqlite3.Error:
        return []
    finally:
        if own_db:
            db.close()


def _reason_ru(r):
    """«systemd: a.service, b.service» -> «упали службы: a, b»; остальное как есть."""
    if r.startswith("systemd: "):
        return "упали службы: " + ", ".join(u.strip().replace(".service", "") for u in r[9:].split(","))
    return r


def report_sections(since, now, state=None, c=None, db=None):
    """Для отчёта сторожа v12: (проблемы, сведения) — по строке на пункт, проблемы по серверам. Только чтение."""
    c = c or cfg()
    state = state if state is not None else load_state()
    own_db = db is None
    if own_db:
        if not os.path.exists(DB_FILE):
            return [], []
        db = sqlite3.connect("file:%s?mode=ro" % DB_FILE, uri=True, timeout=10)
    try:
        hosts = state.get("hosts", {})
        names = [h["name"] for h in c.get("hosts", [])] or list(hosts)
        if not names:
            return [], []
        issues, info = [], []
        off = [n for n in names if hosts.get(n, {}).get("verdict") == "offline"]
        if off:
            issues.append("⚫️ <b>Нет связи со сборщиком:</b> " + ", ".join(html.escape(n) for n in off))
        for n, e in hosts.items():
            a = e.get("attack") if e.get("verdict") == "attack" else None
            if a:
                issues.append("🔴 <b>Атака идёт: %s</b> — с %s, %s, %s, пик %s Мбит/с · %s пак/с" % (
                    html.escape(n), msk(a["start"]).strftime("%H:%M"), a.get("type"),
                    SEVERITY_RU.get(a.get("severity"), "?").lower(), mbit(a["peak"].get("rx_bps")), cnt(a["peak"].get("rx_pps"))))
        attacks = list(db.execute("select host, start, end, type, severity, peak from attacks where end >= ? and notified = 1"
                                  " order by start", (int(since),)))
        quiet = list(db.execute("select host, count(*) from attacks where end >= ? and notified = 0 group by host"
                                " order by count(*) desc", (int(since),)))
        for hst, st_, en, ty, sev, pk in attacks[-5:]:
            pk = json.loads(pk or "{}")
            issues.append("🔴 <b>Была атака: %s</b> — %s, %s, %s, %s, пик %s Мбит/с · %s пак/с" % (
                html.escape(hst), msk(st_).strftime("%d.%m %H:%M"), ty, SEVERITY_RU.get(sev, sev).lower(),
                dur(en - st_), mbit(pk.get("rx_bps")), cnt(pk.get("rx_pps"))))
        for n, e in hosts.items():
            if e.get("verdict") in ("load", "health"):
                icon = "🟠" if e["verdict"] == "load" else "🟡"
                what = "высокая нагрузка" if e["verdict"] == "load" else "требует внимания"
                rs = "; ".join(_reason_ru(r) for r in (e.get("reasons") or []))
                if e["verdict"] == "load":
                    issues.append("%s <b>%s</b> — высокая нагрузка%s" % (icon, html.escape(n), (": " + html.escape(rs)) if rs else ""))
                else:
                    issues.append("%s <b>%s</b> — %s" % (icon, html.escape(n), html.escape(rs) if rs else what))
        issues += [x for x in (docker_issue(n, e) for n, e in hosts.items()) if x]
        seen = set()
        for n, e in hosts.items():
            act = (e.get("docker") or {}).get("active") or {}
            for d in e.get("deferred", []):
                key = (n, d["state"], tuple(d["reasons"]))
                if d["ts"] < since or key in seen or (e.get("verdict") == d["state"]) \
                        or (d["state"] == "docker" and d.get("keys") and all(k in act for k in d["keys"])):
                    continue   # уже сказано выше (то же состояние сейчас) или повтор
                seen.add(key)
                issues.append("🌙 %s — в %s (вне рабочих часов, без сообщения): %s" % (
                    html.escape(n), msk(d["ts"]).strftime("%H:%M"), html.escape("; ".join(_reason_ru(r) for r in d["reasons"]))))
        n_att = len(attacks) + sum(1 for e in hosts.values() if e.get("verdict") == "attack")
        info.append("<b>DDoS и нагрузка:</b> на связи %d из %d серверов · %s" % (
            len(names) - len(off), len(names), "атак за период нет" if not n_att else "атак: %d" % n_att))
        if quiet:
            info.append("<b>Короткие всплески без сообщений:</b> %d (%s) — ниже порога тревоги" % (
                sum(n for _, n in quiet), ", ".join("%s %d" % (html.escape(h), n) for h, n in quiet[:5])))
        ov = load_overrides()
        if ov:
            info.append("<b>Пороги подняты вами:</b> " + ", ".join("%s — %s Мбит/с до %s" % (
                html.escape(h), mbit(v.get("rx_bps")), msk(v["until"]).strftime("%d.%m")) for h, v in ov.items()))
        peaks = list(db.execute("select host, max(rx_bps) m from samples where ts >= ? group by host order by m desc limit 3",
                                (int(since),)))
        if peaks:
            info.append("<b>Пик входящего:</b> " + ", ".join("%s — %s Мбит/с" % (html.escape(h), mbit(m)) for h, m in peaks))
        nb = db.execute("select count(distinct host) from baseline").fetchone()[0]
        info.append("<b>Свои пороги по нагрузке:</b> у %d из %d серверов%s" % (
            nb, len(names), " (появятся после суток истории)" if nb == 0 else ""))
        dks = [e["docker"] for e in hosts.values() if e.get("docker")]
        if dks:
            bad_n = sum(1 for x in dks if x.get("active"))
            info.append("<b>Контейнеры Docker:</b> работают %d на %d серверах · %s" % (
                sum(int(x.get("running") or 0) for x in dks), len(dks),
                "проблем нет" if not bad_n else "проблемы на %d" % bad_n))
            tl = [(h, x) for h, e in hosts.items() for x in (e.get("docker") or {}).get("temp_log", []) if x["ts"] >= since]
            if tl:
                info.append("<b>Временные контейнеры</b> (без тревог): %d за период · %s" % (len(tl), ", ".join(
                    "%s на %s — %s" % (html.escape(x["n"]), html.escape(h), html.escape(x["how"])) for h, x in tl[-5:])))
        si = shield_info(hosts)
        if si:
            info.append(si)
        issues += shield_warn_lines(hosts)
        b_iss, b_inf = backup_lines(hosts, now)
        issues += b_iss
        info += b_inf
        s_iss, s_inf = scan_lines(hosts)
        issues += s_iss
        info += s_inf
        return issues, info
    except sqlite3.Error:
        return [], []
    finally:
        if own_db:
            db.close()


def load_state():
    try:
        return json.load(open(STATE_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def main(argv):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import probe  # tg_send и общий журнал сторожа
    c, now, dry = cfg(), time.time(), "--dry" in argv
    state = load_state()
    db = db_open()
    send = (lambda t: print("[не отправлено, --dry]\n" + t) or "ok") if dry else probe.tg_send
    if "--status" in argv:
        for n, e in state.get("hosts", {}).items():
            print("%-24s %-8s последний срез %s, порог RX %s" % (n, e.get("verdict"), msk(e.get("last_ts") or 0).strftime("%H:%M:%S"),
                                                               mbit(thresholds(c, db_baseline(db, n), None, link_bps(
                                                                   c, next((h for h in c["hosts"] if h.get("name") == n), None)))["rx_bps"])))
        return 0
    data = fetch_all(c)
    for t in process(state, data, c, now, db):
        res = send(t)
        if not dry:   # заголовок — в журнал (25.10: для калибровки надо знать, что именно ушло)
            title = re.sub(r"<[^>]+>", "", t.split("\n", 1)[0]).strip()[:80]
            srv = re.search(r"Сервер:</b> ([^\n·<]+)", t)
            probe.log("ddos: сообщение %s: %s%s" % ("отправлено" if res == "ok" else "НЕ отправлено (%s)" % res, title,
                                                    " — " + srv.group(1).strip() if srv else ""))
    HOST_INFO.update({h["name"]: (h.get("host"), h.get("note")) for h in c.get("hosts", []) if h.get("name")})
    for o in state.pop("shield_pending", []):   # атака или подозрительные — одно сообщение с кнопками (выполняет shieldbot)
        import shieldbot
        cl = None
        if o.get("ips"):
            try:
                cl = shieldbot.lookup_clients(o["ips"])
            except Exception:  # сверка не удалась — сообщение всё равно нужно, с пометкой
                cl = None
        attack_kind = o.get("kind") == "attack"
        text = incident_text(o, cl) if attack_kind else shield_offer_text(o["host"], o["sh"], o["ts"], o.get("attack"), cl)
        if dry:
            print("[не отправлено, --dry, кнопки щита]\n" + text)
            continue
        oid = shieldbot.send_incident(o["host"], "attack" if attack_kind else "block", o.get("ips") or [], text,
                                      clients=list(cl or {}), peak=o.get("peak"))
        if not oid and attack_kind:   # без кнопок, но об атаке сказать надо
            send(text)
        probe.log("ddos: %s %s %s" % ("атака" if attack_kind else "щит, предложение", o["host"],
                                      "отправлено " + oid if oid else "НЕ отправлено с кнопками"))
    if now - state.get("baseline_at", 0) >= BASELINE_EVERY:
        recompute_baseline(db, [h["name"] for h in c["hosts"]], now)
        state["baseline_at"] = now
    # своей сводки нет — блок «Нагрузка и DDoS» в отчёте сторожа 3 раза в день (report_lines);
    # --summary — показать/отправить его сейчас. Ночные события держим двое суток для отчёта.
    if "--summary" in argv:
        send("\n".join(report_lines(now - 86400, now, state, c, db)))
    for e in state.get("hosts", {}).values():
        e["deferred"] = [d for d in e.get("deferred", []) if now - d["ts"] <= 2 * 86400]
    if not dry:
        db.commit()
        save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
