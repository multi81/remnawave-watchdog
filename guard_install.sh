#!/usr/bin/env bash
# guard_install.sh — установка «сторожа за сторожем» (channel-watch-guard) на сервер, отличный от rf1.
# Рядом должен лежать guard.py. Система — Ubuntu 24.04 / 26.04. Входящих портов не открывает: сам ходит наружу
# (читает пульс с rf1 и пишет в Telegram), файрвол трогать не нужно.
#
#   bash guard_install.sh                  — мастер с вопросами
#   bash guard_install.sh --env FILE --yes — без вопросов; FILE — строки KEY=VALUE, «-» — читать со стандартного ввода
#   bash guard_install.sh --uninstall      — убрать
#
# Ключи: HEARTBEAT_URL — адрес файла пульса на rf1; TG_TOKEN и TG_CHAT — бот и чат для сообщений
# (понимает и имена BW_TG_TOKEN / BW_TG_CHAT, как в /etc/bridge-watch/guard.env на rf1); GUARD_NAME — как
# подписывать сообщения (по умолчанию имя сервера). Секреты аргументами не передаются: их видно в списке процессов.
# Откат: bash guard_install.sh --uninstall
set -euo pipefail

DIR=/opt/channel-watch-guard
ETC=/etc/channel-watch-guard
SRC="$(cd "$(dirname "$0")" && pwd)"
env_file="" yes=0 uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --env) env_file="${2:?после --env нужен файл или -}"; shift 2 ;;
    --yes) yes=1; shift ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "$uninstall" -eq 1 ]; then
  systemctl disable --now channel-watch-guard.timer 2>/dev/null || true
  rm -rf "$DIR" "$ETC" /var/lib/channel-watch-guard /var/log/channel-watch-guard.log* \
         /etc/systemd/system/channel-watch-guard.service /etc/systemd/system/channel-watch-guard.timer \
         /etc/logrotate.d/channel-watch-guard
  systemctl daemon-reload
  echo "сторож за сторожем убран"
  exit 0
fi

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "внимание: рассчитано на Ubuntu 24.04 / 26.04, здесь ${PRETTY_NAME:-неизвестная система}" ;;
esac
[ -s "$SRC/guard.py" ] || { echo "рядом со скриптом нет guard.py"; exit 1; }
command -v python3 >/dev/null || { echo "ставлю python3"; apt-get update -qq && apt-get install -y -qq python3; }
python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$SRC/guard.py"

# значения: из файла или стандартного ввода, недостающие — вопросами
HEARTBEAT_URL="" TG_TOKEN="" TG_CHAT="" GUARD_NAME=""
if [ -n "$env_file" ]; then
  [ "$env_file" = "-" ] && env_file=/dev/stdin
  while IFS= read -r line || [ -n "$line" ]; do
    key="${line%%=*}" val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    case "$key" in
      HEARTBEAT_URL) HEARTBEAT_URL="$val" ;;
      TG_TOKEN|BW_TG_TOKEN) TG_TOKEN="$val" ;;
      TG_CHAT|BW_TG_CHAT) TG_CHAT="$val" ;;
      GUARD_NAME) GUARD_NAME="$val" ;;
    esac
  done < "$env_file"
fi
if [ "$yes" -eq 0 ]; then
  [ -n "$HEARTBEAT_URL" ] || read -r -p "Адрес файла пульса на rf1 (https://…): " HEARTBEAT_URL
  [ -n "$TG_TOKEN" ] || { read -r -s -p "Токен Telegram-бота (не показывается): " TG_TOKEN; echo; }
  [ -n "$TG_CHAT" ] || read -r -p "Номер чата Telegram, куда писать: " TG_CHAT
  [ -n "$GUARD_NAME" ] || { read -r -p "Как подписывать сообщения [$(hostname)]: " GUARD_NAME; }
fi
GUARD_NAME="${GUARD_NAME:-$(hostname)}"
[ -n "$HEARTBEAT_URL" ] && [ -n "$TG_TOKEN" ] && [ -n "$TG_CHAT" ] || { echo "не хватает HEARTBEAT_URL, TG_TOKEN или TG_CHAT"; exit 1; }
case "$HEARTBEAT_URL" in https://*) ;; *) echo "адрес пульса должен начинаться с https://"; exit 1 ;; esac

install -d -m 755 "$DIR" /var/lib/channel-watch-guard
install -d -m 700 "$ETC"
install -m 755 "$SRC/guard.py" "$DIR/guard.py"
umask 077
printf 'HEARTBEAT_URL=%s\nTG_TOKEN=%s\nTG_CHAT=%s\nGUARD_NAME=%s\n' "$HEARTBEAT_URL" "$TG_TOKEN" "$TG_CHAT" "$GUARD_NAME" > "$ETC/guard.env"
umask 022

cat > /etc/systemd/system/channel-watch-guard.service <<'UNIT'
[Unit]
Description=channel-watch-guard: сторож за сторожем каналов (читает пульс с rf1)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch-guard/guard.py
Nice=10
TimeoutStartSec=120
UNIT

cat > /etc/systemd/system/channel-watch-guard.timer <<'UNIT'
[Unit]
Description=channel-watch-guard: каждые 5 минут

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=15s

[Install]
WantedBy=timers.target
UNIT

cat > /etc/logrotate.d/channel-watch-guard <<'ROT'
/var/log/channel-watch-guard.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
ROT

# самопроверка: пульс читается, Telegram принимает сообщение — и только потом таймер
echo "== самопроверка"
rc=0; python3 "$DIR/guard.py" --test || rc=$?
systemctl daemon-reload
systemctl enable --now channel-watch-guard.timer >/dev/null 2>&1
[ "$rc" -eq 0 ] || echo "внимание: сейчас сторож каналов не в порядке (см. строку выше) — таймер включён, тревога придёт после второй проверки"
echo "== готово: таймер $(systemctl is-active channel-watch-guard.timer); настройки $ETC/guard.env (600); журнал /var/log/channel-watch-guard.log"
echo "== вручную: python3 $DIR/guard.py --show"
