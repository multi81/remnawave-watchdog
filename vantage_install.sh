#!/usr/bin/env bash
# vantage_install.sh — точка проверки для сторожа каналов (vantage_agent.py): ещё один российский сервер,
# с которого сторож смотрит на ноды, когда канал не работает. Система — Ubuntu 24.04 / 26.04.
#
#   bash vantage_install.sh                       мастер: спросит адрес сторожа, порт и название точки
#   bash vantage_install.sh --allow IP --yes      без вопросов (IP — адрес сервера, где стоит сторож)
#        --port N        порт агента (по умолчанию 9109)
#        --name ИМЯ      как называть точку в сообщениях сторожа (по умолчанию имя сервера)
#        --suffix a,b    домены, имена на которых агенту разрешено проверять (обязательно)
#        --ports a,b     порты, которые агенту разрешено проверять (по умолчанию 443)
#        --hosts a,b     адреса вне своих доменов, которые тоже можно проверять (например свои ретрансляторы)
#        --snis a,b      имена TLS, с которыми можно обращаться к таким адресам (у ретранслятора имя чужое)
#   bash vantage_install.sh --entry               напечатать запись для vantage.json сторожа (в ней токен: не на экран,
#                                                 а конвейером на сервер сторожа)
#   bash vantage_install.sh --uninstall           убрать
#
# Что ставит: /opt/vantage-agent (два файла), настройки /etc/vantage-agent/agent.json (токен создаётся здесь же),
# службу vantage-agent от пользователя nobody. В ufw порт открывается только адресу сторожа.
# Агент отвечает только сторожу (адрес и токен), проверяет только имена на разрешённых доменах и только порт 443.
# Повторный запуск безопасен: файлы и служба обновляются, токен остаётся прежним.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/vantage-agent; ETC=/etc/vantage-agent; UNIT=/etc/systemd/system/vantage-agent.service
allow="" port=9109 name="" suffix="" yes=0 mode=install ports="" hosts="" snis=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow) allow="${2:?после --allow нужен адрес сторожа}"; shift 2 ;;
    --port) port="${2:?после --port нужен номер}"; shift 2 ;;
    --name) name="${2:?после --name нужно название}"; shift 2 ;;
    --suffix) suffix="${2:?после --suffix нужны домены через запятую}"; shift 2 ;;
    --ports) ports="${2:?после --ports нужны порты через запятую}"; shift 2 ;;
    --hosts) hosts="${2:?после --hosts нужны адреса через запятую}"; shift 2 ;;
    --snis) snis="${2:?после --snis нужны имена через запятую}"; shift 2 ;;
    --yes) yes=1; shift ;;
    --entry) mode=entry; shift ;;
    --uninstall) mode=uninstall; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "$mode" = entry ]; then
  python3 - "$ETC/agent.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
e = {"name": c["name"], "url": "http://%s:%d" % (c["public"], c["port"]), "token": c["token"]}
if c.get("vpn"):
    e["vpn"] = True  # VPN-точка (агент с собственным клиентом Xray): сторож будет проверять через неё плитки
print(json.dumps(e, ensure_ascii=False))
PY
  exit 0
fi

if [ "$mode" = uninstall ]; then
  systemctl disable --now vantage-agent.service 2>/dev/null || true
  if [ -s "$ETC/ufw-rule" ] && command -v ufw >/dev/null; then ufw delete $(cat "$ETC/ufw-rule") >/dev/null 2>&1 || true; fi
  rm -rf "$DIR" "$ETC" "$UNIT"
  systemctl daemon-reload
  echo "точка проверки убрана"; exit 0
fi
[ -n "$suffix" ] || { echo "укажите --suffix: ваши домены через запятую (на других именах агент проверять не будет)"; exit 2; }

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "внимание: рассчитано на Ubuntu 24.04 / 26.04, здесь ${PRETTY_NAME:-неизвестная система}" ;;
esac
for f in vantage_agent.py netprobe.py; do [ -s "$SRC/$f" ] || { echo "рядом со скриптом нет $f"; exit 1; }; done
command -v python3 >/dev/null || { apt-get update -qq; apt-get install -y -qq python3; }

if [ -z "$allow" ]; then
  [ "$yes" -eq 0 ] || { echo "нужен адрес сервера сторожа: --allow IP"; exit 1; }
  read -r -p "Адрес сервера, где стоит сторож (ему одному агент будет отвечать): " allow
fi
python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$allow" 2>/dev/null || { echo "«$allow» — не адрес"; exit 1; }
if [ "$yes" -eq 0 ]; then
  read -r -p "Порт агента [$port]: " x; port="${x:-$port}"
  read -r -p "Как называть эту точку в сообщениях сторожа [$(hostname)]: " x; name="${x:-$name}"
fi
name="${name:-$(hostname)}"
case "$port" in ''|*[!0-9]*) echo "порт должен быть числом"; exit 1 ;; esac
if ss -Hltn "( sport = :$port )" | grep -q . && ! systemctl is-active --quiet vantage-agent.service; then
  echo "порт $port уже занят другой программой — укажите свободный: --port N"; exit 1
fi
public="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | cut -d' ' -f2)"
[ -n "$public" ] || { echo "не удалось узнать свой адрес"; exit 1; }

install -d -m 755 "$DIR"
install -d -m 750 -g nogroup "$ETC"
install -m 644 "$SRC/vantage_agent.py" "$SRC/netprobe.py" "$DIR/"
python3 - "$ETC/agent.json" "$allow" "$port" "$name" "$suffix" "$public" "$ports" "$hosts" "$snis" <<'PY'
import json, os, secrets, sys
path, allow, port, name, suffix, public, ports, hosts, snis = sys.argv[1:10]
items = lambda text: [x.strip().lower() for x in text.split(",") if x.strip()]
try:
    cfg = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    cfg = {}
cfg.setdefault("token", secrets.token_urlsafe(32))
cfg.update(allow=[allow], port=int(port), name=name, public=public, suffixes=items(suffix))
# порты, адреса и имена TLS: заданные сейчас — заменяют прежние; не заданные — остаются как были
cfg["ports"] = [int(x) for x in items(ports)] if ports else cfg.get("ports", [443])
for key, text in (("hosts", hosts), ("snis", snis)):
    if text:
        cfg[key] = items(text)
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=1)
os.chmod(path + ".tmp", 0o640)
os.replace(path + ".tmp", path)
PY
chgrp nogroup "$ETC/agent.json"

cat > "$UNIT" <<'EOF'
[Unit]
Description=vantage-agent: точка проверки для сторожа каналов (отвечает только сторожу)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/vantage-agent/vantage_agent.py
User=nobody
Group=nogroup
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
MemoryMax=64M
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vantage-agent.service >/dev/null 2>&1
systemctl restart vantage-agent.service

fw="файрвол ufw не включён — порт $port открыт всем (агент всё равно отвечает только сторожу с токеном)"
if command -v ufw >/dev/null && [ "$(ufw status | awk 'NR==1{print $2}')" = active ]; then
  rule="allow from $allow to any port $port proto tcp"
  echo "$rule" > "$ETC/ufw-rule"
  ufw $rule comment 'vantage-agent: watchdog only' >/dev/null
  fw="в ufw порт $port открыт только для $allow"
fi

sleep 2
code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health" || true)"
echo "== $(hostname): служба $(systemctl is-active vantage-agent.service), слушает $public:$port; $fw"
echo "   самопроверка: чужой запрос без токена получил ответ $code (должно быть 403)"
echo "   запись для сторожа: bash $0 --entry  (в ней токен — передавать конвейером, не выводить на экран)"
[ "$code" = 403 ] || { echo "   агент отвечает не так, как должен: journalctl -u vantage-agent -n 20"; exit 1; }
