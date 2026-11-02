#!/usr/bin/env bash
# witness_install.sh [--uninstall] — «свидетель» на ноде для сторожа каналов (node_witness.py).
# Считает только помеченные проверочные соединения сторожа и его точек (метка — MSS в первом пакете) и раз в 10 секунд
# пишет небольшой JSON без адресов рядом с маячком ноды (то же случайное имя, начало fw- вместо st-; у нод без своего
# сайта — flows.json рядом со state.json). Сторож забирает файл сам; портов свидетель не открывает и команд не принимает.
# Нужен уже установленный маячок (beacon_install.sh) и tcpdump (если его нет — ставится из пакетов Ubuntu).
# Настройки Xray, файрвола, веб-сервера и маячка не трогает. Рядом должен лежать node_witness.py.
# Откат: bash witness_install.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/node-witness; UNIT=/etc/systemd/system/node-witness.service; ETC=/etc/node-witness
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now node-witness.service 2>/dev/null || true
  if [ -s "$ETC/out" ]; then rm -f "$(cat "$ETC/out")" "$(cat "$ETC/out").tmp"; fi
  rm -rf "$APP" "$ETC" "$UNIT"
  systemctl daemon-reload
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
if ! command -v tcpdump >/dev/null; then
  echo "tcpdump не найден — ставлю из пакетов"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpdump >/dev/null
fi
install -d -m 755 "$APP"; install -d -m 700 "$ETC"
install -m 755 "$SRC/node_witness.py" "$APP/node_witness.py"
echo "$out" > "$ETC/out"
cat > "$UNIT" <<EOF
[Unit]
Description=node-witness: что нода видела из проверочных соединений сторожа каналов (только помеченные, без адресов)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 $APP/node_witness.py $out
Restart=always
RestartSec=10
Nice=10
MemoryMax=64M
CPUQuota=15%
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$dir
ProtectHome=yes
PrivateTmp=yes
LogLevelMax=warning

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable node-witness.service >/dev/null 2>&1
systemctl restart node-witness.service
sleep 4
[ -s "$out" ] || { echo "свидетель не записал файл $out"; journalctl -u node-witness.service -n 8 --no-pager; exit 1; }
python3 - "$out" <<'PY'
import json, sys, time
d = json.load(open(sys.argv[1]))
print("   файл пишется: возраст %.0f с, записей %d" % (time.time() - d["ts"], len(d["flows"])))
PY
echo "== $(hostname): свидетель $(systemctl is-active node-witness.service), tcpdump $(pgrep -c -f 'tcpdump.*tcp-syn' || echo 0) шт., память $(systemctl show node-witness.service -p MemoryCurrent --value | awk '{printf "%.0f МБ", $1/1048576}')"
echo "WITNESS /$(basename "$out")"
