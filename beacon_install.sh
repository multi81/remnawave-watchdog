#!/usr/bin/env bash
# beacon_install.sh --site-dir ПАПКА | --serve ПОРТ --allow АДРЕС | --uninstall
# Маячок состояния ноды для сторожа каналов (в недельную сводку — диск, память, версии; счётчик сканирования). Рядом должен лежать node_beacon.py. Раз в 10 минут пишет небольшой JSON без секретов.
#   --site-dir ПАПКА        нода со своим сайтом-прикрытием: файл со случайным именем кладётся в папку сайта, сторож
#                           забирает его по https; портов и настроек веб-сервера не трогает;
#   --serve ПОРТ --allow IP нода без своего сайта: файл отдаёт крошечный веб-сервер на ПОРТу (от пользователя nobody),
#                           в ufw порт открыт только адресу сторожа (IP).
# В конце печатает одну строку «BEACON <хвост адреса>» — её забирает сторож.
# Откат: bash beacon_install.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/node-beacon
WWW=/var/lib/node-beacon/www
mode="" dir="" port="" allow=""
while [ $# -gt 0 ]; do
  case "$1" in
    --site-dir) mode=site; dir="$2"; shift 2 ;;
    --serve) mode=serve; port="$2"; shift 2 ;;
    --allow) allow="$2"; shift 2 ;;
    --uninstall) mode=uninstall; shift ;;
    *) echo "не понимаю параметр $1"; exit 2 ;;
  esac
done

if [ "$mode" = uninstall ]; then
  systemctl disable --now node-beacon.timer node-beacon-http.service 2>/dev/null || true
  if [ -s "$ETC/out" ]; then rm -f "$(cat "$ETC/out")" "$(cat "$ETC/out").tmp"; fi
  if [ -s "$ETC/ufw-rule" ]; then sh -c "ufw delete $(cat "$ETC/ufw-rule")" >/dev/null 2>&1 || true; fi
  rm -rf /opt/node-beacon "$ETC" /var/lib/node-beacon
  rm -f /etc/systemd/system/node-beacon.service /etc/systemd/system/node-beacon.timer /etc/systemd/system/node-beacon-http.service
  systemctl daemon-reload
  echo "маячок убран"; exit 0
fi

[ -s "$SRC/node_beacon.py" ] || { echo "рядом нет node_beacon.py"; exit 1; }
install -d -m 755 /opt/node-beacon
install -d -m 700 "$ETC"
install -m 755 "$SRC/node_beacon.py" /opt/node-beacon/node_beacon.py

if [ "$mode" = site ]; then
  [ -d "$dir" ] || { echo "нет папки сайта $dir"; exit 1; }
  [ -s "$ETC/out" ] || echo "$dir/st-$(openssl rand -hex 12).json" > "$ETC/out"
  tail="/$(basename "$(cat "$ETC/out")")"
elif [ "$mode" = serve ]; then
  [ -n "$port" ] && [ -n "$allow" ] || { echo "нужны --serve ПОРТ и --allow АДРЕС"; exit 1; }
  install -d -m 755 /var/lib/node-beacon "$WWW"
  echo "$WWW/state.json" > "$ETC/out"
  cat > /etc/systemd/system/node-beacon-http.service <<UNIT
[Unit]
Description=node-beacon: отдаёт файл состояния ноды сторожу каналов (порт $port открыт в ufw только его адресу)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -m http.server $port --bind 0.0.0.0 --directory $WWW
User=nobody
Group=nogroup
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
LogLevelMax=warning
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  rule="allow from $allow to any port $port proto tcp"
  echo "$rule" > "$ETC/ufw-rule"
  ufw $rule comment 'node-beacon: watchdog only' >/dev/null
  tail=":$port/state.json"
else
  echo "укажите --site-dir или --serve"; exit 2
fi

cat > /etc/systemd/system/node-beacon.service <<'UNIT'
[Unit]
Description=node-beacon: записать состояние ноды для сторожа каналов

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/node-beacon-run
Nice=10
TimeoutStartSec=120
LogLevelMax=warning
UNIT
cat > /usr/local/sbin/node-beacon-run <<'SH'
#!/bin/sh
# куда писать — в /etc/node-beacon/out
exec /usr/bin/python3 /opt/node-beacon/node_beacon.py "$(cat /etc/node-beacon/out)"
SH
chmod 755 /usr/local/sbin/node-beacon-run
cat > /etc/systemd/system/node-beacon.timer <<'UNIT'
[Unit]
Description=node-beacon: каждые 10 минут

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
AccuracySec=30s

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
if [ "$mode" = serve ]; then systemctl enable --now node-beacon-http.service >/dev/null 2>&1; fi
systemctl enable --now node-beacon.timer >/dev/null 2>&1
systemctl start node-beacon.service
out="$(cat "$ETC/out")"
[ -s "$out" ] || { echo "маячок не записал файл $out"; journalctl -u node-beacon.service -n 8 --no-pager; exit 1; }
python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); print("   " + sys.argv[2] + ": диск", str(d["disk_pct"]) + "%, свободно памяти", d["mem_avail_mb"], "МБ, Xray", d["xray"], "| ufw", d["ufw"], "| отбито:", d["drops"], "| ssh-подбор за сутки:", d["ssh_fail_24h"])' "$out" "$(hostname)" >&2
echo "BEACON $tail"
