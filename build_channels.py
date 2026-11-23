#!/usr/bin/env python3
"""channel-watch: собрать каналы для проверки из подписки служебного пользователя.

Берёт XRAY_JSON-подписку (URL в /etc/channel-watch/sub.url), вытаскивает outbound
каждой плитки с собственной нодой/ретранслятором (тег "proxy"), убирает дубли
и пишет:
  /etc/channel-watch/xray.json     — клиент Xray: по SOCKS-порту на канал
  /etc/channel-watch/channels.json — список каналов для probe.py
Заодно — для отчёта сторожа (probe.py):
  sub_status.json  — загрузилась ли подписка (это и есть проверка страницы подписки), когда, сколько плиток
  tiles.json       — названия всех плиток подписки
  sub_changes.json — какие плитки появились и пропали с прошлого отчёта (probe.py удаляет файл после отчёта)
Код выхода 0 — без изменений, 10 — конфиг изменился (нужен рестарт xray), 1 — подписка не загрузилась.

SOCKS-порты 127.0.0.1:21000-21099 (и прямой выход in-0) — под паролем, если есть /etc/channel-watch/socks.auth
({"user", "pass"}, 600): иначе любой процесс на сервере выходит в сеть через ноды. Файл создаётся один раз ключом
--socks-auth (случайные логин и пароль), дальше просто читается. Нет файла — порты без пароля, как раньше.
Включить: python3 build_channels.py --socks-auth; systemctl restart channel-watch-xray (или код выхода 10 —
перезапуск сделает служба пересборки). Выключить: удалить socks.auth и так же пересобрать.
"""
import glob
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.request

ETC = "/etc/channel-watch"
BASE_PORT = 21000
UA = "Happ/4.6.0/Linux/channel-watch"
# ожидаемый выход для каналов, где он не совпадает с адресом входа (каскад, мост):
# /etc/channel-watch/expected_exit.json — {"вход канала": "адрес выхода"}
try:
    EXPECTED_EXIT = json.load(open(os.path.join(ETC, "expected_exit.json"), encoding="utf-8"))
except (OSError, ValueError):
    EXPECTED_EXIT = {}


def load_sub():
    url = open(os.path.join(ETC, "sub.url"), encoding="utf-8").read().strip()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("подписка пришла не в формате XRAY_JSON (ожидался массив конфигов)")
    return data


def read_json(name, default):
    try:
        return json.load(open(os.path.join(ETC, name), encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write(name, text):
    tmp = os.path.join(ETC, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(ETC, name))


def write_json(name, obj):
    write(name, json.dumps(obj, ensure_ascii=False, indent=1))


def socks_auth_path():
    return os.path.join(ETC, "socks.auth")


def read_socks_auth():
    """(логин, пароль) из socks.auth или None (файла нет или он битый — порты без пароля, как раньше)."""
    try:
        data = json.load(open(socks_auth_path(), encoding="utf-8"))
        user, pw = data["user"], data["pass"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if isinstance(user, str) and isinstance(pw, str) and re.fullmatch(r"[A-Za-z0-9_-]{8,128}", user) \
            and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", pw):
        return user, pw
    return None


def socks_settings():
    """Настройки входа SOCKS для xray.json: с паролем, если есть socks.auth, иначе без пароля."""
    auth = read_socks_auth()
    if not auth:
        return {"udp": False, "auth": "noauth"}
    return {"udp": False, "auth": "password", "accounts": [{"user": auth[0], "pass": auth[1]}]}


# Модуль рядом, который сам ходит через локальные SOCKS-порты, должен уметь пароль — иначе включать нельзя.
# «Сам ходит» — любой из признаков ниже (с запасом: лишний признак значит только, что модуль надо посмотреть и
# поставить метку). Модуль, который лишь зовёт netprobe.socks_load / curl_socks / socks_connect, сюда не попадает:
# пароль подставляет netprobe.
SOCKS_USER_SIGNS = (
    (r"socks[45][ah]?://", "адрес прокси socks…://"),
    (r"\btg_routes\s*\(", "маршруты probe.tg_routes (в них порт канала)"),
    (r"\\x05\\x0[0-3]", "рукопожатие SOCKS5 в сокете"),
    (r"\(\s*[\"']127\.0\.0\.1[\"']\s*,", "сокет на 127.0.0.1"),
    (r"[\"']socks5h?[\"']", "схема socks5 строкой"),
    (r"[\"'](?:-x|--proxy|--preproxy|--socks[45][\w-]*)[\"']\s*[,+]", "прокси в аргументах curl"),
    # в конце списка — только длинные ключи: «-x"]» бывает у iptables -L -v -n -x (node_beacon), это не прокси
    (r"[\"'](?:--proxy|--preproxy|--socks[45][\w-]*)[\"']\s*[\])]", "прокси в аргументах curl"),
    (r"[\"']--(?:proxy|preproxy|socks[45][\w-]*)=", "прокси в аргументах curl"),
    (r"\b(?:ALL|all|HTTPS?|https?)_(?:PROXY|proxy)\b", "прокси из окружения"),
    (r"\bProxyHandler\b|^\s*(?:import|from)\s+socks\b", "прокси в urllib или PySocks"),
    (r"\bBASE_PORT\b|\bbaseline_port\b|\b21[01]\d\d\b", "порты каналов 21000-21099"),
)
SOCKS_USER = re.compile("|".join(f"(?:{p})" for p, _ in SOCKS_USER_SIGNS), re.M)
SOCKS_READY = re.compile(r"^SOCKS_AUTH_READY\s*=\s*True\b", re.M)
VPN_POINT_DROPIN = "/etc/systemd/system/vantage-agent.service.d/vpn.conf"
VPN_POINT_AGENT_DIR = "/opt/vantage-agent"  # на VPN-точке агент (netprobe, vantage_agent) лежит не рядом с этим файлом


def socks_ready_mark(text):
    """Метка SOCKS_AUTH_READY = True — присваивание на верхнем уровне модуля (не в строке и не в комментарии)."""
    import ast
    if not SOCKS_READY.search(text):
        return False
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SOCKS_AUTH_READY"
                                                for t in node.targets):
            return isinstance(node.value, ast.Constant) and node.value.value is True
    return False


def socks_user_signs(text):
    """Какие признаки «сам ходит через SOCKS» есть в тексте модуля (пустой список — не ходит)."""
    return sorted({why for p, why in SOCKS_USER_SIGNS if re.search(p, text, re.M)})


def socks_not_ready(here=None, dropin=VPN_POINT_DROPIN, agent_dir=VPN_POINT_AGENT_DIR):
    """Кто ещё не умеет ходить через SOCKS с паролем: модули рядом с этим файлом (на VPN-точке — ещё и в папке
    агента) с признаком SOCKS_USER_SIGNS без метки SOCKS_AUTH_READY, нечитаемые модули и агент VPN-точки, которому
    socks.auth не передан (LoadCredential). Пустой список — включать можно."""
    here = here or os.path.dirname(os.path.abspath(__file__))
    dirs = [here]
    if agent_dir and os.path.exists(dropin) and os.path.isdir(agent_dir) \
            and os.path.realpath(agent_dir) != os.path.realpath(here):
        dirs.append(agent_dir)
    bad = []
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.py"))):
            name = os.path.basename(path)
            if name.startswith("test_") or name == os.path.basename(__file__):
                continue
            shown = name if d == here else path
            try:
                with open(path, "rb") as f:
                    text = f.read().decode("utf-8", errors="replace")
            except OSError:
                bad.append(shown + " (не читается — не проверить)")
                continue
            if SOCKS_USER.search(text) and not socks_ready_mark(text):
                bad.append(shown)
    try:
        conf = open(dropin, encoding="utf-8", errors="replace").read()
        # строка настройки, а не упоминание в комментарии
        if not re.search(r"^\s*LoadCredential\s*=\s*socks\.auth:/\S+", conf, re.M):
            bad.append(dropin + " (агенту VPN-точки нужен LoadCredential=socks.auth:" + socks_auth_path() + ")")
    except OSError:
        pass
    return bad


def make_socks_auth(here=None, dropin=VPN_POINT_DROPIN):
    """Создать socks.auth один раз (600, случайные логин и пароль). Уже есть — не трогать. Код: 0 — файл на месте,
    иначе текст отказа."""
    if read_socks_auth():
        return 0
    bad = socks_not_ready(here, dropin)
    if bad:
        return "пароль на SOCKS не включён: ещё не умеют ходить с паролем — " + ", ".join(bad)
    data = {"user": "cw" + secrets.token_hex(6), "pass": secrets.token_urlsafe(24)}
    tmp = socks_auth_path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, socks_auth_path())
    return 0


def strip_dialer(obj):
    """Убрать dialerProxy на любой глубине (sockopt у xhttp downloadSettings и т. п.) и цепочку proxySettings:
    из подписки берётся один outbound, и он не должен уводить соединения через что-то ещё."""
    if isinstance(obj, dict):
        obj.pop("dialerProxy", None)
        for v in obj.values():
            strip_dialer(v)
    elif isinstance(obj, list):
        for v in obj:
            strip_dialer(v)
    return obj


def channel_key(ob):
    vnext = ob.get("settings", {}).get("vnext", [{}])[0]
    ss = ob.get("streamSettings", {})
    sec = ss.get("realitySettings") or ss.get("tlsSettings") or {}
    return (vnext.get("address"), vnext.get("port"), ss.get("network"),
            sec.get("serverName"), sec.get("publicKey"))


def main():
    if "--socks-auth" in sys.argv[1:]:
        res = make_socks_auth()
        if res:
            raise SystemExit(res)
    now = int(time.time())
    old_tiles = read_json("tiles.json", None)
    try:
        sub = load_sub()
    except Exception as e:  # сеть, ответ не 200, не JSON — в отчёте это «подписка не загрузилась»
        reason = getattr(e, "reason", None) or (f"ответ {e.code}" if hasattr(e, "code") else type(e).__name__)
        write_json("sub_status.json", {"ok": False, "ts": now, "tiles": len(old_tiles or []),
                                       "error": str(reason)[:80]})
        raise SystemExit(f"подписка не загрузилась: {reason}")

    # плитки подписки: сколько их и что изменилось — для отчёта
    tiles = [cfg.get("remarks") or "?" for cfg in sub]
    if old_tiles is not None and sorted(old_tiles) != sorted(tiles):
        changes = read_json("sub_changes.json", [])
        changes.append({"ts": now, "added": [t for t in tiles if t not in old_tiles],
                        "removed": [t for t in old_tiles if t not in tiles]})
        write_json("sub_changes.json", changes[-20:])
    write_json("tiles.json", tiles)
    write_json("sub_status.json", {"ok": True, "ts": now, "tiles": len(tiles), "error": ""})

    channels, outbounds, inbounds, rules, seen = [], [], [], [], set()
    socks = socks_settings()
    for cfg in sub:
        remark = cfg.get("remarks") or "?"
        proxy = next((o for o in cfg.get("outbounds", []) if o.get("tag") == "proxy"), None)
        if not proxy or proxy.get("protocol") != "vless":
            continue  # виртуальные плитки балансиров и прочее — их ноды проверяются своими плитками
        key = channel_key(proxy)
        if key in seen:
            continue  # та же нода/вход под другим названием (например, две плитки rf1)
        seen.add(key)
        i = len(channels) + 1
        ob = json.loads(json.dumps(proxy))
        ob["tag"] = f"out-{i}"
        ob.pop("mux", None)
        ob.pop("proxySettings", None)
        strip_dialer(ob)
        outbounds.append(ob)
        inbounds.append({"tag": f"in-{i}", "listen": "127.0.0.1", "port": BASE_PORT + i,
                         "protocol": "socks", "settings": json.loads(json.dumps(socks))})
        rules.append({"type": "field", "inboundTag": [f"in-{i}"], "outboundTag": f"out-{i}"})
        # entry/entry_port/sni/security нужны probe.py, чтобы при сбое проверить сервер напрямую
        channels.append({"name": remark, "port": BASE_PORT + i, "entry": key[0], "entry_port": key[1],
                         "sni": key[3], "security": proxy.get("streamSettings", {}).get("security"),
                         "expected_exit": EXPECTED_EXIT.get(key[0])})
    if not channels:
        raise SystemExit("в подписке не нашлось ни одного канала")
    # контрольный канал без VPN: если он не работает, значит, проблема у самой rf1
    inbounds.append({"tag": "in-0", "listen": "127.0.0.1", "port": BASE_PORT,
                     "protocol": "socks", "settings": json.loads(json.dumps(socks))})
    outbounds.append({"tag": "out-0", "protocol": "freedom"})
    rules.insert(0, {"type": "field", "inboundTag": ["in-0"], "outboundTag": "out-0"})
    xray = {"log": {"loglevel": "warning", "access": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}

    new = json.dumps(xray, ensure_ascii=False, indent=1)
    path = os.path.join(ETC, "xray.json")
    old = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    write("xray.json", new)
    write_json("channels.json", {"baseline_port": BASE_PORT, "channels": channels})
    print(f"плиток в подписке: {len(tiles)}; каналов: {len(channels)} — " + ", ".join(c["name"] for c in channels))
    sys.exit(10 if hashlib.sha256(old.encode()).digest() != hashlib.sha256(new.encode()).digest() else 0)


if __name__ == "__main__":
    main()
