#!/usr/bin/env bash
# vantage_update.sh — обновить точку проверки (vantage-agent) до версии из архива (версия — VERSION в vantage_agent.py).
# Рядом должны лежать vantage_agent.py и netprobe.py (и по желанию rucheck.py) — те же файлы, что ставит
# vantage_install.sh. Запускать от root на точке.
# Обновляются только файлы агента: юнит, права и сертификат TLS не трогаются. Новый агент со старым юнитом работает
# по HTTP, как раньше; TLS (версия 7+) появляется после bash vantage_install.sh --yes (прежние настройки сохранятся).
#   bash vantage_update.sh [--ports 443,9443] [--hosts a,b] [--snis x,y]
# Токен, адрес сторожа, порт агента и остальные настройки не меняются (кроме явно переданных параметров).
# Прежние файлы и настройки при каждом запуске копируются в /opt/vantage-agent/prev-<время UTC>/.
# Откат: D=/opt/vantage-agent/prev-<время>; cp $D/vantage_agent.py $D/netprobe.py /opt/vantage-agent/ \
#        && cat $D/agent.json > /etc/vantage-agent/agent.json && systemctl restart vantage-agent
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/vantage-agent; CONF=/etc/vantage-agent/agent.json
ports="" hosts="" snis=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ports) ports="$2"; shift 2 ;;
    --hosts) hosts="$2"; shift 2 ;;
    --snis) snis="$2"; shift 2 ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }
[ -s "$CONF" ] && [ -s "$DIR/vantage_agent.py" ] || { echo "агент здесь не установлен (сначала vantage_install.sh)"; exit 1; }
# файлы агента — тот же набор, что копирует vantage_install.sh (новый файл добавлять в оба установщика)
FILES="vantage_agent.py netprobe.py"
for f in $FILES; do [ -s "$SRC/$f" ] || { echo "рядом со скриптом нет $f"; exit 1; }; done
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read()) for f in sys.argv[1:]]' $(for f in $FILES; do echo "$SRC/$f"; done)
B="$DIR/prev-$(date -u +%Y%m%d-%H%M%S)"
install -d -m 700 "$B"
for f in $FILES; do [ ! -f "$DIR/$f" ] || cp -a "$DIR/$f" "$B/"; done
cp -a "$CONF" "$B/agent.json"; chmod 600 "$B/agent.json"
for f in $FILES; do install -m 644 "$SRC/$f" "$DIR/"; done
# проверка сервисов для сверки шаблона (/services) — если rucheck.py лежит рядом
if [ -s "$SRC/rucheck.py" ]; then
  [ -f "$DIR/rucheck.py" ] && cp -a "$DIR/rucheck.py" "$B/"
  python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$SRC/rucheck.py"
  install -m 644 "$SRC/rucheck.py" "$DIR/"
fi
if [ -n "$ports$hosts$snis" ]; then
  python3 - "$CONF" "$ports" "$hosts" "$snis" <<'PY'
import json, sys
path, ports, hosts, snis = sys.argv[1:5]
items = lambda text: [x.strip().lower() for x in text.split(",") if x.strip()]
cfg = json.load(open(path, encoding="utf-8"))
if ports:
    cfg["ports"] = [int(x) for x in items(ports)]
for key, text in (("hosts", hosts), ("snis", snis)):
    if text:
        cfg[key] = items(text)
with open(path, "r+", encoding="utf-8") as f:  # тот же файл — права и группа не меняются
    f.seek(0)
    json.dump(cfg, f, ensure_ascii=False, indent=1)
    f.truncate()
print("   настройки: порты %s; адреса вне доменов %s; имена TLS %s" % (cfg.get("ports"), cfg.get("hosts", []), cfg.get("snis", [])))
PY
fi
systemctl restart vantage-agent.service
sleep 2
port="$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); print(c["port"])' "$CONF")"
code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health" || true)"
ver="$(python3 -c 'import re,sys; print(re.search(r"^VERSION = (\d+)", open(sys.argv[1], encoding="utf-8").read(), re.M).group(1))' "$DIR/vantage_agent.py")"
echo "== $(hostname): агент версии $ver, служба $(systemctl is-active vantage-agent.service); запрос без токена — ответ $code (должно быть 403)"
echo "   прежние файлы: $B"
[ "$code" = 403 ] || { echo "   агент отвечает не так, как должен: journalctl -u vantage-agent -n 20"; exit 1; }
if [ ! -s /etc/vantage-agent/cert.pem ] || ! grep -qs '^LoadCredential=cert.pem' /etc/systemd/system/vantage-agent.service; then
  echo "   TLS на точке не включён (нет сертификата или юнит старый): bash vantage_install.sh --yes — прежние настройки сохранятся"
fi
