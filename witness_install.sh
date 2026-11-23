#!/usr/bin/env bash
# witness_install.sh [--uninstall] — «свидетель» на ноде для сторожа каналов (node_witness.py).
# Считает только помеченные проверочные соединения сторожа и его точек (метка — MSS в первом пакете) и раз в 10 секунд
# пишет небольшой JSON без адресов рядом с маячком ноды (то же случайное имя, начало fw- вместо st-; у нод без своего
# сайта — flows.json рядом со state.json). Сторож забирает файл сам; портов свидетель не открывает и команд не принимает.
# Нужен уже установленный маячок (beacon_install.sh) и tcpdump (если его нет — ставится из пакетов Ubuntu).
# Настройки Xray, файрвола, веб-сервера и маячка не трогает. Рядом должен лежать node_witness.py.
# После смены режима маячка (--site-dir ↔ --serve) запустить ещё раз: файл свидетеля переедет за файлом маячка.
# Работает от своего системного пользователя node-witness (без входа и домашней папки) с одной возможностью —
# захват пакетов (CAP_NET_RAW). Писать в папку файла маячка ему разрешает ACL только на эту папку (setfacl, пакет acl;
# нет — ставится из пакетов Ubuntu): владелец и права папки для остальных не меняются. Файловая система без ACL —
# прежняя схема (root с узкими возможностями) и предупреждение. Повторный запуск поверх прежней установки (от root):
# файл, имя и путь те же. Если права папки сбросил chmod (выкладка сайта, повторный beacon_install.sh), свидетель
# через 30 с отказов записи перезапускается, и служба перед стартом возвращает ACL сама.
# Откат: bash witness_install.sh --uninstall (служба, файл, ACL с папки и пользователь node-witness убираются)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/node-witness; UNIT=/etc/systemd/system/node-witness.service; ETC=/etc/node-witness
WUSER=node-witness
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

# убрать файл свидетеля и его временные файлы (.fw-*.tmp — новые, $out.tmp — от прежних версий)
rm_out() {
  [ -n "${1:-}" ] || return 0
  rm -f -- "$1" "$1.tmp" "$(dirname "$1")"/.fw-*.tmp
}

# снять ACL свидетеля с папки. setfacl -x оставляет запись mask; если других именованных записей нет и mask равна
# правам группы (на права она уже не влияет), убирается и она — папка возвращается к виду до установки
acl_off() {
  [ -n "${1:-}" ] && [ -d "$1" ] && command -v setfacl >/dev/null || return 0
  getfacl -cp -- "$1" 2>/dev/null | grep -q "^user:$WUSER:" || return 0
  setfacl -P -x "u:$WUSER" -- "$1" || return 0
  local acl
  acl="$(getfacl -cp -- "$1" 2>/dev/null | grep -v '^$')" || return 0
  if ! printf '%s\n' "$acl" | grep -Evq '^(user::|group::|other::|mask::)' \
     && [ "$(printf '%s\n' "$acl" | sed -n 's/^mask:://p')" = "$(printf '%s\n' "$acl" | sed -n 's/^group:://p')" ]; then
    setfacl -P -b -- "$1" || true
  fi
}

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now node-witness.service 2>/dev/null || true
  if [ -s "$ETC/out" ]; then rm_out "$(cat "$ETC/out")"; acl_off "$(dirname "$(cat "$ETC/out")")"; fi
  if [ -s "$ETC/acl" ]; then acl_off "$(cat "$ETC/acl")"; fi
  rm -rf "$APP" "$ETC" "$UNIT"
  systemctl daemon-reload
  systemctl reset-failed node-witness.service 2>/dev/null || true
  if id -u "$WUSER" >/dev/null 2>&1; then userdel "$WUSER" 2>/dev/null || true; fi
  if getent group "$WUSER" >/dev/null; then groupdel "$WUSER" 2>/dev/null || true; fi
  echo "свидетель убран: служба, файл, ACL папки и пользователь $WUSER (tcpdump и acl, если ставились, оставлены)"; exit 0
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
# и ACL с прежней папки снять
if [ -s "$ETC/acl" ] && [ "$(cat "$ETC/acl")" != "$dir" ]; then
  systemctl stop node-witness.service 2>/dev/null || true
  acl_off "$(cat "$ETC/acl")"; rm -f "$ETC/acl"
fi
# свой пользователь: системный, без входа и домашней папки
if ! id -u "$WUSER" >/dev/null 2>&1; then
  if getent group "$WUSER" >/dev/null; then g=(-g "$WUSER"); else g=(--user-group); fi
  useradd --system "${g[@]}" --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$WUSER"
fi
if ! command -v setfacl >/dev/null; then
  echo "setfacl не найден — ставлю пакет acl"
  # NEEDRESTART_SUSPEND — без простыни needrestart о службах; не поставился — ниже откат на прежнюю схему
  if ! NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acl >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acl 2>&1 | tail -n 2 || true
  fi
fi
# папки НАД папкой файла — только root и без записи для группы и прочих: иначе их хозяин может подменить папку файла
# ссылкой, и root (установщик, ExecStartPre при каждом старте) поставил бы ACL на чужую папку
safe_parents() {
  local d; d="$(dirname "$1")"
  while :; do
    [ "$(stat -c '%u' "$d")" = 0 ] || return 1
    case "$(stat -c '%A' "$d")" in ?????w????|????????w?) return 1 ;; esac
    [ "$d" = / ] && return 0
    d="$(dirname "$d")"
  done
}
# право записи — ACL только на папку файла и только для своего пользователя; проверка — запись от его имени
asuser=0
if command -v setfacl >/dev/null && [ ! -L "$dir" ] && safe_parents "$dir" \
   && setfacl -P -m "u:$WUSER:rwx" -- "$dir" 2>/dev/null \
   && runuser -u "$WUSER" -- test -w "$dir" -a -x "$dir" 2>/dev/null; then
  asuser=1
else
  acl_off "$dir"
  echo "ВНИМАНИЕ: не удалось дать пользователю $WUSER запись в $dir через ACL (нет setfacl, папка над ней не"
  echo "   root-а или открыта на запись другим, файловая система"
  echo "   без ACL или к папке нет прохода) — свидетель остаётся на прежней схеме: root с узкими возможностями"
fi
install -d -m 755 "$APP"
if [ "$asuser" = 1 ]; then
  # site.json (диапазон меток) свидетель читает сам: папка настроек — группе node-witness, новые файлы — её же (g+s)
  install -d -m 2750 -o root -g "$WUSER" "$ETC"
  if [ -f "$ETC/site.json" ]; then chgrp "$WUSER" "$ETC/site.json"; chmod 640 "$ETC/site.json"; fi
  echo "$dir" > "$ETC/acl"
  owner="$WUSER"
else
  install -d -m 700 -o root -g root "$ETC"; chmod g-s "$ETC"   # g+s от обычной схемы chmod/install сами не снимают
  rm -f "$ETC/acl"
  owner=root
fi
install -m 755 "$SRC/node_witness.py" "$APP/node_witness.py"
echo "$out" > "$ETC/out"
# файл от прежней установки — новому владельцу (замена в папке с липким битом иначе не пройдёт); ссылку не трогаем
if [ -f "$out" ] && [ ! -L "$out" ]; then chown -h "$owner:" "$out"; fi   # 0644 свидетель ставит сам через 10 с
case "$dir" in   # папка сайта в /home или /root: ProtectHome=yes спрятал бы её целиком
  /home/*|/root/*|/run/user/*) ph=read-only ;;
  *) ph=yes ;;
esac
# Песочница. Обычно — от пользователя node-witness с одной возможностью CAP_NET_RAW: её наследует tcpdump (захват
# с -p, CAP_NET_ADMIN не нужен — проверено на стенде), -Z ему не нужен — он и так не root. Перед запуском
# («-+»: от root вне песочницы, ошибка не мешает старту) ACL на папку ставится заново. Писать можно только в эту папку.
# Прежняя схема (ACL не вышло): от root, но без его полномочий — захват (CAP_NET_RAW, CAP_NET_ADMIN), смена
# пользователя для tcpdump (CAP_SETUID, CAP_SETGID, -Z tcpdump) и, если папка сайта не root-а, CAP_DAC_OVERRIDE.
if [ "$asuser" = 1 ]; then
  caps="CAP_NET_RAW"; amb="CAP_NET_RAW"
  run_as="User=$WUSER
Group=$WUSER
ExecStartPre=-+$(command -v setfacl) -P -m u:$WUSER:rwx \"$dir\""
else
  caps="CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID"; amb="CAP_NET_RAW CAP_NET_ADMIN"
  run_as="# без User=: ACL на папку поставить не удалось — от root с узкими возможностями"
  perm="$(stat -c '%u %A' "$dir")"
  case "$perm" in 0\ ??w*) ;; *) caps="$caps CAP_DAC_OVERRIDE" ;; esac
fi
cat > "$UNIT" <<EOF
[Unit]
Description=node-witness: что нода видела из проверочных соединений сторожа каналов (только помеченные, без адресов)
After=network-online.target
Wants=network-online.target

[Service]
$run_as
ExecStart=/usr/bin/python3 "$APP/node_witness.py" "$out"
UMask=0022
Restart=always
RestartSec=10
Nice=10
MemoryMax=64M
CPUQuota=15%
CapabilityBoundingSet=$caps
AmbientCapabilities=$amb
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths="$dir"
ProtectHome=$ph
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
PrivateIPC=yes
InaccessiblePaths=-/dev/shm -/run/lock -/run/screen -/run/cloud-init
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
# tcpdump свидетель запускает чуть позже первой записи файла — подождать до 5 с; нет его — «?», а не обрыв (pipefail)
for _ in $(seq 10); do pgrep -f 'tcpdump.*tcp-syn' >/dev/null && break; sleep 0.5; done
tu="$( (ps -o user:32= -C tcpdump 2>/dev/null || true) | sort -u | tr '\n' ' ')"
wu="$(ps -o user:32= -p "$(systemctl show node-witness.service -p MainPID --value)" 2>/dev/null || true)"
echo "== $(hostname): свидетель $(systemctl is-active node-witness.service) (от ${wu:-?}), tcpdump $(pgrep -c -f 'tcpdump.*tcp-syn' || true) шт. (от ${tu:-?}), память $(systemctl show node-witness.service -p MemoryCurrent --value | awk '{printf "%.0f МБ", $1/1048576}')"
echo "WITNESS /$(basename "$out")"
