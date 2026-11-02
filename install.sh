#!/usr/bin/env bash
# install.sh — установка сторожа каналов (версия 11) с нуля. Ставится на сервер в РФ: каналы он проверяет «изнутри».
# Система — Ubuntu 24.04 / 26.04. Запускать из папки с файлами сторожа.
#
#   bash install.sh             мастер: спросит то, чего не хватает
#   bash install.sh --yes       без вопросов (ссылка подписки и настройки Telegram уже лежат на местах)
#   bash install.sh --xray ПУТЬ взять бинарник Xray из файла (по умолчанию копируется из контейнера remnanode)
#   bash install.sh --no-start  всё поставить, но таймеры не включать и первую проверку не запускать
#   bash install.sh --uninstall убрать сторож
#
# Что нужно заранее:
#   - служебный пользователь в панели Remnawave (создать в веб-интерфейсе: все сквады, без срока и лимита трафика)
#     и его ссылка подписки;
#   - токен Telegram-бота и номер чата, куда писать.
# Входящих портов сторож не открывает: сам ходит наружу, файрвол трогать не нужно.
# Повторный запуск безопасен: обновляет скрипты и службы, состояние и настройки не трогает.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/channel-watch
TG_ENV=/etc/bridge-watch/guard.env   # отсюда сторож читает BW_TG_TOKEN и BW_TG_CHAT
yes=0 start=1 xray_src="" uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) yes=1; shift ;;
    --no-start) start=0; shift ;;
    --xray) xray_src="${2:?после --xray нужен путь к бинарнику}"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "$uninstall" -eq 1 ]; then
  systemctl disable --now channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer \
    channel-watch-loss.timer channel-watch-side.timer channel-watch-xray.service 2>/dev/null || true
  rm -rf /opt/channel-watch "$ETC" /var/lib/channel-watch /etc/logrotate.d/channel-watch /var/log/channel-watch.log*
  rm -f /etc/systemd/system/channel-watch.service /etc/systemd/system/channel-watch.timer \
        /etc/systemd/system/channel-watch-build.service /etc/systemd/system/channel-watch-build.timer \
        /etc/systemd/system/channel-watch-speed.service /etc/systemd/system/channel-watch-speed.timer \
        /etc/systemd/system/channel-watch-lists.service /etc/systemd/system/channel-watch-lists.timer \
        /etc/systemd/system/channel-watch-loss.service /etc/systemd/system/channel-watch-loss.timer \
        /etc/systemd/system/channel-watch-side.service /etc/systemd/system/channel-watch-side.timer \
        /etc/systemd/system/channel-watch-xray.service
  systemctl daemon-reload
  echo "сторож убран. Не тронуты: $TG_ENV (настройки Telegram) и служебный пользователь в панели — его удалить вручную."
  exit 0
fi

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "внимание: рассчитано на Ubuntu 24.04 / 26.04, здесь ${PRETTY_NAME:-неизвестная система}" ;;
esac
for f in probe.py nodewatch.py blockwatch.py netprobe.py build_channels.py; do
  [ -s "$SRC/$f" ] || { echo "рядом со скриптом нет $f"; exit 1; }
done
missing=""
for bin in python3 curl ping traceroute; do command -v "$bin" >/dev/null || missing="$missing $bin"; done
if [ -n "$missing" ]; then
  echo "ставлю недостающее:$missing"
  apt-get update -qq
  apt-get install -y -qq python3 curl iputils-ping traceroute
fi
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' \
  "$SRC/probe.py" "$SRC/nodewatch.py" "$SRC/blockwatch.py" "$SRC/netprobe.py" "$SRC/build_channels.py"

# --- ссылка подписки служебного пользователя ---
install -d -m 700 "$ETC"
if [ ! -s "$ETC/sub.url" ]; then
  [ "$yes" -eq 0 ] || { echo "нет $ETC/sub.url (ссылка подписки служебного пользователя) — положите её туда или запустите без --yes"; exit 1; }
  read -r -s -p "Ссылка подписки служебного пользователя (не показывается): " sub; echo
  case "$sub" in https://*) ;; *) echo "ссылка должна начинаться с https://"; exit 1 ;; esac
  ( umask 077; printf '%s\n' "$sub" > "$ETC/sub.url" )
fi
chmod 600 "$ETC/sub.url"

# --- Telegram ---
if ! grep -qs '^BW_TG_TOKEN=' "$TG_ENV" || ! grep -qs '^BW_TG_CHAT=' "$TG_ENV"; then
  [ "$yes" -eq 0 ] || { echo "в $TG_ENV нет BW_TG_TOKEN / BW_TG_CHAT — впишите или запустите без --yes"; exit 1; }
  read -r -s -p "Токен Telegram-бота (не показывается): " token; echo
  read -r -p "Номер чата Telegram, куда писать: " chat
  [ -n "$token" ] && [ -n "$chat" ] || { echo "нужны и токен, и чат"; exit 1; }
  install -d -m 700 "$(dirname "$TG_ENV")"
  ( umask 077; printf 'BW_TG_TOKEN=%s\nBW_TG_CHAT=%s\n' "$token" "$chat" >> "$TG_ENV" )
fi
chmod 600 "$TG_ENV"

# --- файлы ---
install -d -m 755 /opt/channel-watch /var/lib/channel-watch
install -m 755 "$SRC/probe.py" "$SRC/nodewatch.py" "$SRC/blockwatch.py" "$SRC/netprobe.py" "$SRC/build_channels.py" /opt/channel-watch/

# клиент Xray: тот же бинарник, что у ноды (ничего не скачиваем), либо указанный файл
if [ -n "$xray_src" ]; then
  install -m 755 "$xray_src" /opt/channel-watch/xray
elif [ ! -x /opt/channel-watch/xray ]; then
  docker cp remnanode:/usr/local/bin/xray /opt/channel-watch/xray 2>/dev/null \
    || { echo "не нашёл Xray: контейнера remnanode нет. Укажите бинарник: bash install.sh --xray /путь/к/xray"; exit 1; }
  chmod 755 /opt/channel-watch/xray
fi
echo "xray: $(/opt/channel-watch/xray version | head -n 1)"

# --- каналы из подписки ---
rc=0; python3 /opt/channel-watch/build_channels.py || rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 10 ] || { echo "список каналов из подписки не собрался (rc=$rc): проверьте ссылку в $ETC/sub.url"; exit 1; }
/opt/channel-watch/xray run -test -c "$ETC/xray.json" | tail -n 1

# --- службы ---
cat > /etc/systemd/system/channel-watch-xray.service <<'UNIT'
[Unit]
Description=channel-watch: клиент Xray для проверки каналов (SOCKS 127.0.0.1:21000-21099)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/channel-watch/xray run -c /etc/channel-watch/xray.json
Restart=always
RestartSec=5
Nice=10
MemoryMax=96M

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/channel-watch.service <<'UNIT'
[Unit]
Description=channel-watch: проверка каналов VPN (оповещения в Telegram)
After=channel-watch-xray.service
Requires=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py
Nice=10
TimeoutStartSec=110
UNIT

cat > /etc/systemd/system/channel-watch.timer <<'UNIT'
[Unit]
Description=channel-watch: каждые 2 минуты

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
AccuracySec=10s

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-build.service <<'UNIT'
[Unit]
Description=channel-watch: пересборка списка каналов из подписки

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'rc=0; /usr/bin/python3 /opt/channel-watch/build_channels.py || rc=$?; [ "$rc" -eq 10 ] && systemctl restart channel-watch-xray.service; [ "$rc" -eq 0 ] || [ "$rc" -eq 10 ]'
UNIT

cat > /etc/systemd/system/channel-watch-build.timer <<'UNIT'
[Unit]
Description=channel-watch: пересборка каналов и проверка подписки — за 10 минут до каждого отчёта

[Timer]
OnCalendar=*-*-* 05,11,17:50:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-speed.service <<'UNIT'
[Unit]
Description=channel-watch: закачка 10 МБ через каждый канал (скорость для отчёта)
After=channel-watch-xray.service
Requires=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --speed
Nice=10
TimeoutStartSec=600
UNIT

cat > /etc/systemd/system/channel-watch-speed.timer <<'UNIT'
[Unit]
Description=channel-watch: закачка побольше — за 5 минут до каждого отчёта

[Timer]
OnCalendar=*-*-* 05,11,17:55:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-lists.service <<'UNIT'
[Unit]
Description=channel-watch: сверка наших адресов и доменов со списками блокировок
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --lists
Nice=15
MemoryMax=256M
TimeoutStartSec=900
UNIT

cat > /etc/systemd/system/channel-watch-lists.timer <<'UNIT'
[Unit]
Description=channel-watch: списки блокировок — раз в 6 часов

[Timer]
OnCalendar=*-*-* 02,08,14,20:40:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-loss.service <<'UNIT'
[Unit]
Description=channel-watch: фоновый замер потерь соединений с российских точек до входов нод
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --loss
Nice=15
MemoryMax=128M
TimeoutStartSec=600
UNIT

cat > /etc/systemd/system/channel-watch-loss.timer <<'UNIT'
[Unit]
Description=channel-watch: замер потерь с точек — раз в час

[Timer]
OnCalendar=*-*-* *:25:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-side.service <<'UNIT'
[Unit]
Description=channel-watch: профиль точек проверки и гео адресов нод (долгие сборы вне основного прохода)
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --side
Nice=15
MemoryMax=256M
TimeoutStartSec=1200
UNIT

cat > /etc/systemd/system/channel-watch-side.timer <<'UNIT'
[Unit]
Description=channel-watch: профиль точек и гео нод — проверка сроков раз в час

[Timer]
OnCalendar=*-*-* *:45:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/logrotate.d/channel-watch <<'ROT'
/var/log/channel-watch.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
ROT

systemctl daemon-reload
if [ "$start" -eq 0 ]; then
  echo "== поставлено без запуска. Включить: systemctl enable --now channel-watch-xray.service channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer channel-watch-loss.timer channel-watch-side.timer"
  exit 0
fi
systemctl enable --now channel-watch-xray.service >/dev/null 2>&1
sleep 2
systemctl enable --now channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer \
  channel-watch-loss.timer channel-watch-side.timer >/dev/null 2>&1

# --- самопроверка: первый запуск (он же шлёт первый отчёт в Telegram) ---
echo "== самопроверка: первый запуск"
rc=0; systemctl start channel-watch.service || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "первый запуск завершился с ошибкой:"; journalctl -u channel-watch.service -n 20 --no-pager; exit 1
fi
python3 /opt/channel-watch/probe.py --show | sed -n '1,14p'
echo
echo "== готово: клиент Xray $(systemctl is-active channel-watch-xray.service), таймер $(systemctl is-active channel-watch.timer)"
echo "   отправка в Telegram: $(grep -c 'отправлен в Telegram' /var/log/channel-watch.log 2>/dev/null || echo 0) сообщений в журнале — проверьте, что отчёт пришёл"
echo "   дальше по желанию: маячки и свидетель на нодах (beacon_install.sh, witness_install.sh), сторож за сторожем
   (guard_install.sh), точки проверки (vantage_install.sh); DDoS, щит и сканеры — install_ddos.sh. См. README.md"
