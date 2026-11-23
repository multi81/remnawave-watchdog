#!/usr/bin/env bash
# witness_install.sh [--uninstall] — «свидетель» на ноде для сторожа каналов (node_witness.py).
# Считает только помеченные проверочные соединения сторожа и его точек (метка — MSS в первом пакете) и раз в 10 секунд
# пишет небольшой JSON без адресов рядом с маячком ноды (то же случайное имя, начало fw- вместо st-; у нод без своего
# сайта — flows.json рядом со state.json). Сторож забирает файл сам; портов свидетель не открывает и команд не принимает.
# Нужен уже установленный маячок (beacon_install.sh) и tcpdump (если его нет — ставится из пакетов Ubuntu).
# Настройки Xray, файрвола, веб-сервера и маячка не трогает. Рядом должен лежать node_witness.py.
# После смены режима маячка (--site-dir ↔ --serve) запустить ещё раз: файл свидетеля переедет за файлом маячка.
# Откат: bash witness_install.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/node-witness; UNIT=/etc/systemd/system/node-witness.service; ETC=/etc/node-witness
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

# убрать файл свидетеля и его временные файлы (.fw-*.tmp — новые, $out.tmp — от прежних версий)
rm_out() {
  [ -n "${1:-}" ] || return 0
  rm -f -- "$1" "$1.tmp" "$(dirname "$1")"/.fw-*.tmp
}

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now node-witness.service 2>/dev/null || true
  if [ -s "$ETC/out" ]; then rm_out "$(cat "$ETC/out")"; fi
  rm -rf "$APP" "$ETC" "$UNIT"
  systemctl daemon-reload
  systemctl reset-failed node-witness.service 2>/dev/null || true
  echo "свидетель убран (tcpdump, если ставился, оставлен)"; exit 0
fi

[ -s "$SRC/node_witness.py" ] || { echo "рядом нет node_witness.py"; exit 1; }
[ -s /etc/node-beacon/out ] || { echo "на ноде нет маячка (/etc/node-beacon/out) — сначала beacon_install.sh"; exit 1; }
beacon="$(cat /etc/node-beacon/out)"; dir="$(dirname "$beacon")"; base="$(basename "$beacon")"
case "$base" in
  st-*.json) out="$dir/fw-${base#st-}" ;;
  state.json) out="$dir/flows.json" ;;
  *) echo "не понимаю имя файла маячка: $base"; exit 1 ;;
esac
[ -d "$dir" ] || { echo "нет папки $dir"; exit 1; }
case "$dir" in /*) ;; *) echo "путь папки маячка должен быть абсолютным: $dir"; exit 1 ;; esac
# путь идёт в юнит в кавычках; ", \ и % (спецификаторы systemd) там поняли бы не так
case "$dir" in
  *\"*|*'\'*|*%*|*$'\n'*) echo "в пути папки $dir есть \", \\ или % — укажите маячку другую папку"; exit 1 ;;
esac
if ! command -v tcpdump >/dev/null; then
  echo "tcpdump не найден — ставлю из пакетов"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump >/dev/null
fi
# маячок переехал (смена режима) — прежний файл свидетеля убрать
if [ -s "$ETC/out" ] && [ "$(cat "$ETC/out")" != "$out" ]; then
  systemctl stop node-witness.service 2>/dev/null || true
  rm_out "$(cat "$ETC/out")"
fi
install -d -m 755 "$APP"; install -d -m 700 "$ETC"
install -m 755 "$SRC/node_witness.py" "$APP/node_witness.py"
echo "$out" > "$ETC/out"
case "$dir" in   # папка сайта в /home или /root: ProtectHome=yes спрятал бы её целиком
  /home/*|/root/*|/run/user/*) ph=read-only ;;
  *) ph=yes ;;
esac
# Песочница. Работает от root, но без его полномочий: из возможностей только захват (CAP_NET_RAW, CAP_NET_ADMIN),
# смена пользователя для tcpdump (CAP_SETUID, CAP_SETGID — разбирает пакеты он уже от пользователя tcpdump) и, если
# папка сайта не root-а, запись в неё (CAP_DAC_OVERRIDE). Отдельного пользователя для самого свидетеля нет: ему нужно
# писать в папку сайта, а её владельца и права установщик не меняет. Писать можно только в эту папку.
caps="CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID"
perm="$(stat -c '%u %A' "$dir")"
case "$perm" in 0\ ??w*) ;; *) caps="$caps CAP_DAC_OVERRIDE" ;; esac
cat > "$UNIT" <<EOF
[Unit]
Description=node-witness: что нода видела из проверочных соединений сторожа каналов (только помеченные, без адресов)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 "$APP/node_witness.py" "$out"
Restart=always
RestartSec=10
Nice=10
MemoryMax=64M
CPUQuota=15%
CapabilityBoundingSet=$caps
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths="$dir"
ProtectHome=$ph
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
# сообщения в stderr (не записал, tcpdump упал, трассировки) — уровнем warning, иначе LogLevelMax их отбросит
SyslogLevel=warning
LogLevelMax=warning

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable node-witness.service >/dev/null 2>&1
t0="$(date +%s)"
systemctl restart node-witness.service
# первая запись после перезапуска — 1–2 с, на загруженной ноде (CPUQuota) дольше: ждём свежий файл (записан после
# перезапуска, прежний от прошлой установки не в счёт) до 15 с, а не наугад
fresh() { [ -s "$out" ] && [ "$(stat -c %Y "$out" 2>/dev/null || echo 0)" -ge "$t0" ]; }
for _ in $(seq 30); do fresh && break; sleep 0.5; done
if ! fresh; then
  echo "свидетель не записал файл $out за 15 с"
  # журнал юнита бывает пуст: LogLevelMax=warning глушит и сообщения systemd о нём — поэтому и status
  systemctl status node-witness.service --no-pager -l 2>&1 | head -n 20 || true
  journalctl -u node-witness.service -n 20 --no-pager || true
  exit 1
fi
python3 - "$out" <<'PY'
import json, sys, time
d = json.load(open(sys.argv[1]))
print("   файл пишется: возраст %.0f с, записей %d" % (time.time() - d["ts"], len(d["flows"])))
PY
tu="$(ps -o user= -C tcpdump 2>/dev/null | sort -u | tr '\n' ' ')"
echo "== $(hostname): свидетель $(systemctl is-active node-witness.service), tcpdump $(pgrep -c -f 'tcpdump.*tcp-syn' || true) шт. (от ${tu:-?}), память $(systemctl show node-witness.service -p MemoryCurrent --value | awk '{printf "%.0f МБ", $1/1048576}')"
echo "WITNESS /$(basename "$out")"
