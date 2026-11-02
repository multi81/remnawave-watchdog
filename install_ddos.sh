#!/usr/bin/env bash
# install_ddos.sh — DDoS, нагрузка, щит с кнопками и сканеры на сторожевом сервере. Ставить ПОСЛЕ install.sh
# (сообщения в Telegram идут через probe.py, тот же бот и чат). Ubuntu 24.04 / 26.04. Запускать из папки с файлами.
#
#   bash install_ddos.sh                         ключи, службы и таймеры; список серверов — /etc/channel-watch/ddos.json
#   bash install_ddos.sh add ИМЯ АДРЕС [ПОРТ]    добавить сервер в ddos.json и запомнить ключ его SSH (после того как
#                                                на нём выполнен server_install.sh) и проверить, что сторож его читает
#   bash install_ddos.sh keys                    напечатать строку для server_install.sh (адрес сторожа и два ключа)
#   bash install_ddos.sh --uninstall             убрать службы и таймеры (ключи и настройки остаются)
#
# Как устроено: на каждом сервере служба ddos-collect пишет срезы в /run/ddos-collect/state.json, сторож раз в минуту
# забирает файл ключом, который на сервере умеет только прочитать этот файл; щит (shield-ctl) только считает, а
# блокирует и включает резку — по кнопке в Telegram, отдельным ключом, который умеет только команды shield-ctl.
# Входящих портов сторож не открывает.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/channel-watch
OPT=/opt/channel-watch
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

keys() {
  local ip
  ip=$(curl -4 -s -m 10 https://api.ipify.org || true)
  echo "bash server_install.sh --watch ${ip:-АДРЕС_СТОРОЖА} \\"
  echo "  --ddos-key '$(cat $ETC/ddos_ed25519.pub)' \\"
  echo "  --shield-key '$(cat $ETC/shield_ed25519.pub)' \\"
  echo "  --allow 'ВАШИ_АДРЕСА_ЧЕРЕЗ_ПРОБЕЛ'"
}

case "${1:-}" in
  --uninstall)
    systemctl disable --now channel-watch-ddos.timer channel-watch-shieldbot.service channel-watch-scanlists.timer 2>/dev/null || true
    rm -f /etc/systemd/system/channel-watch-ddos.{service,timer} /etc/systemd/system/channel-watch-shieldbot.service \
          /etc/systemd/system/channel-watch-scanlists.{service,timer}
    systemctl daemon-reload
    echo "службы DDoS, щита и сканеров убраны; ключи и $ETC/ddos.json остались"; exit 0 ;;
  keys) keys; exit 0 ;;
  add)
    name="${2:?имя сервера}"; host="${3:?адрес сервера}"; port="${4:-22}"
    python3 - "$ETC/ddos.json" "$name" "$host" "$port" <<'PY'
import json, sys
path, name, host, port = sys.argv[1:5]
c = json.load(open(path, encoding="utf-8"))
c["hosts"] = [h for h in c.get("hosts", []) if h.get("name") != name] + [{"name": name, "host": host, "port": int(port)}]
json.dump(c, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
PY
    # ключ сервера: один раз при добавлении (сверьте отпечаток с консолью хостера, если сомневаетесь)
    for kh in ddos_known_hosts shield_known_hosts; do
      ssh-keygen -R "$host" -f "$ETC/$kh" >/dev/null 2>&1 || true
      [ "$port" = 22 ] || ssh-keygen -R "[$host]:$port" -f "$ETC/$kh" >/dev/null 2>&1 || true
      ssh-keyscan -T 10 -t ed25519 -p "$port" "$host" 2>/dev/null >> "$ETC/$kh"
    done
    rm -f "$ETC"/*_known_hosts.old
    echo "отпечаток ключа $name: $(ssh-keygen -lf "$ETC/ddos_known_hosts" | grep -F "$host" | awk '{print $2}' | tail -1)"
    ssh -i "$ETC/ddos_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$ETC/ddos_known_hosts" root@"$host" x \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print("сборщик читается, срезов:", len(d["samples"]))'
    ssh -i "$ETC/shield_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$ETC/shield_known_hosts" root@"$host" status \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print("щит:", d.get("mode"), "· таблица", d.get("loaded"))'
    exit 0 ;;
  "") ;;
  *) echo "не понимаю: $1 (см. шапку скрипта)"; exit 2 ;;
esac

[ -s "$OPT/probe.py" ] || { echo "сначала install.sh: через probe.py уходят сообщения в Telegram"; exit 1; }
for f in ddoswatch.py shieldbot.py scanlists.py; do [ -s "$SRC/$f" ] || { echo "рядом нет $f"; exit 1; }; done
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' \
  "$SRC/ddoswatch.py" "$SRC/shieldbot.py" "$SRC/scanlists.py"
install -m 755 "$SRC/ddoswatch.py" "$SRC/shieldbot.py" "$SRC/scanlists.py" "$OPT/"

for k in ddos shield; do
  [ -f "$ETC/${k}_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C "channel-watch-$k" -f "$ETC/${k}_ed25519"
  chmod 600 "$ETC/${k}_ed25519"; touch "$ETC/${k}_known_hosts"; chmod 644 "$ETC/${k}_known_hosts"
done
# work_from/work_to — часы по МСК, когда предложения щита приходят сразу (ночью — строкой в утреннем отчёте)
[ -s "$ETC/ddos.json" ] || printf '{"hosts": [], "work_from": 9, "work_to": 21, "summary_hour": 9, "thresholds": {}}\n' > "$ETC/ddos.json"
touch "$ETC/scanners-extra.txt" "$ETC/scanners-exclude.txt" "$ETC/owner.txt"

cat > /etc/systemd/system/channel-watch-ddos.service <<'UNIT'
[Unit]
Description=channel-watch: DDoS и нагрузка серверов

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/ddoswatch.py
TimeoutStartSec=90
UNIT
cat > /etc/systemd/system/channel-watch-ddos.timer <<'UNIT'
[Unit]
Description=channel-watch: DDoS и нагрузка раз в минуту

[Timer]
OnBootSec=3min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/channel-watch-shieldbot.service <<'UNIT'
[Unit]
Description=channel-watch: кнопки щита в Telegram (выполняет только нажатое)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/channel-watch/shieldbot.py
Restart=always
RestartSec=10
Nice=10
MemoryMax=96M

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/channel-watch-scanlists.service <<'UNIT'
[Unit]
Description=channel-watch: единый список сканеров для щита

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/scanlists.py
Nice=15
TimeoutStartSec=600
UNIT
cat > /etc/systemd/system/channel-watch-scanlists.timer <<'UNIT'
[Unit]
Description=channel-watch: список сканеров раз в сутки

[Timer]
OnCalendar=*-*-* 01:30:00 UTC
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now channel-watch-ddos.timer channel-watch-shieldbot.service channel-watch-scanlists.timer >/dev/null 2>&1

echo "== готово: DDoS $(systemctl is-active channel-watch-ddos.timer), кнопки $(systemctl is-active channel-watch-shieldbot.service), сканеры $(systemctl is-active channel-watch-scanlists.timer)"
echo "   ваши адреса (никогда не блокировать и не считать сканерами) — по одному в строке в $ETC/owner.txt"
echo "   на каждом сервере выполните server_install.sh (рядом ddos_collect.py и shield_ctl.py):"
keys | sed 's/^/     /'
echo "   потом здесь: bash install_ddos.sh add ИМЯ АДРЕС [ПОРТ_SSH]"
