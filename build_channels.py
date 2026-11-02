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
"""
import hashlib
import json
import os
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


def channel_key(ob):
    vnext = ob.get("settings", {}).get("vnext", [{}])[0]
    ss = ob.get("streamSettings", {})
    sec = ss.get("realitySettings") or ss.get("tlsSettings") or {}
    return (vnext.get("address"), vnext.get("port"), ss.get("network"),
            sec.get("serverName"), sec.get("publicKey"))


def main():
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
        ob.get("streamSettings", {}).get("sockopt", {}).pop("dialerProxy", None)
        outbounds.append(ob)
        inbounds.append({"tag": f"in-{i}", "listen": "127.0.0.1", "port": BASE_PORT + i,
                         "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}})
        rules.append({"type": "field", "inboundTag": [f"in-{i}"], "outboundTag": f"out-{i}"})
        # entry/entry_port/sni/security нужны probe.py, чтобы при сбое проверить сервер напрямую
        channels.append({"name": remark, "port": BASE_PORT + i, "entry": key[0], "entry_port": key[1],
                         "sni": key[3], "security": proxy.get("streamSettings", {}).get("security"),
                         "expected_exit": EXPECTED_EXIT.get(key[0])})
    if not channels:
        raise SystemExit("в подписке не нашлось ни одного канала")
    # контрольный канал без VPN: если он не работает, значит, проблема у самой rf1
    inbounds.append({"tag": "in-0", "listen": "127.0.0.1", "port": BASE_PORT,
                     "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}})
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
