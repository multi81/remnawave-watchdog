#!/usr/bin/env bash
# server_install.sh — сервер под присмотром сторожа: сборщик метрик (ddos-collect) и щит (shield-ctl) в режиме
# НАБЛЮДЕНИЯ — ничего не режет и не блокирует, пока вы не нажмёте кнопку в Telegram. Ubuntu 24.04 / 26.04, root.
# Рядом должны лежать ddos_collect.py и shield_ctl.py. Готовую команду печатает на сторожевом сервере
# `bash install_ddos.sh keys`:
#
#   bash server_install.sh --watch АДРЕС_СТОРОЖА --ddos-key 'ssh-ed25519 …' --shield-key 'ssh-ed25519 …' \
#        [--allow 'адрес адрес …'] [--iface eth0]
#   bash server_install.sh --uninstall
#
# Что ставится:
#   /usr/local/sbin/ddos-collect + ddos-collect.service (Nice 10, CPUQuota 5%, MemoryMax 64M) — только счётчики,
#     адресов не хранит (кроме «подозрительных» на 5 минут и ваших клиентов по журналу Xray — файл не покидает сервер);
#   /usr/local/sbin/shield-ctl + storozh-shield.service — своя таблица nft `inet storozh_shield`, ufw, crowdsec,
#     fail2ban и чужие таблицы не трогает; снимается одной командой: systemctl disable --now storozh-shield;
#   две строки в /root/.ssh/authorized_keys, обе только с адреса сторожа: одна умеет лишь прочитать срезы,
#     другая — лишь команды shield-ctl (status, block, unblock, mode). Копия прежнего файла — authorized_keys.before.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
B=/root/storozh-before
watch="" ddos_key="" shield_key="" allow="" iface="" uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --watch) watch="${2:?адрес сторожа}"; shift 2 ;;
    --ddos-key) ddos_key="${2:?ключ ddos}"; shift 2 ;;
    --shield-key) shield_key="${2:?ключ щита}"; shift 2 ;;
    --allow) allow="${2:-}"; shift 2 ;;
    --iface) iface="${2:?интерфейс}"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "$uninstall" -eq 1 ]; then
  systemctl disable --now storozh-shield storozh-shield-tick.timer ddos-collect 2>/dev/null || true
  rm -f /etc/systemd/system/storozh-shield.service /etc/systemd/system/storozh-shield-tick.{service,timer} \
        /etc/systemd/system/ddos-collect.service /usr/local/sbin/shield-ctl /usr/local/sbin/ddos-collect
  rm -rf /etc/storozh-shield /var/lib/storozh-shield
  sed -i '/channel-watch-ddos\|channel-watch-shield/d' /root/.ssh/authorized_keys
  systemctl daemon-reload
  echo "сборщик и щит убраны, строки ключей сторожа удалены"; exit 0
fi

[ -n "$watch" ] && [ -n "$ddos_key" ] && [ -n "$shield_key" ] || { echo "нужны --watch, --ddos-key и --shield-key (см. шапку)"; exit 2; }
for f in ddos_collect.py shield_ctl.py; do [ -s "$SRC/$f" ] || { echo "рядом нет $f"; exit 1; }; done
command -v python3 >/dev/null || { echo "нет python3"; exit 1; }
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y -qq nftables; }
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' "$SRC/ddos_collect.py" "$SRC/shield_ctl.py"

install -d -m 700 "$B"
[ -f "$B/authorized_keys.before" ] || cp -a /root/.ssh/authorized_keys "$B/authorized_keys.before" 2>/dev/null || true
nft list ruleset > "$B/ruleset.before" 2>/dev/null || true

# --- щит: наблюдение ---
install -m 755 "$SRC/shield_ctl.py" /usr/local/sbin/shield-ctl
install -d -m 755 /etc/storozh-shield
if [ ! -s /etc/storozh-shield/config.json ]; then
  python3 - "$watch" "$allow" "$iface" <<'PY'
import json, sys
watch, allow, iface = sys.argv[1:4]
cfg = {"rate": 200, "burst": 400, "conns": 5000, "allow": sorted(set([watch] + allow.split()))}
if iface:
    cfg["iface"] = iface
json.dump(cfg, open("/etc/storozh-shield/config.json", "w", encoding="utf-8"), indent=1)
PY
fi
cat > /etc/systemd/system/storozh-shield.service <<'UNIT'
[Unit]
Description=storozh-shield: щит от флуда (таблица nft inet storozh_shield); блокирует только по кнопке
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/shield-ctl load
ExecStop=/usr/local/sbin/shield-ctl unload

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/storozh-shield-tick.service <<'UNIT'
[Unit]
Description=storozh-shield: срок включённого щита и блокировок

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shield-ctl tick
UNIT
cat > /etc/systemd/system/storozh-shield-tick.timer <<'UNIT'
[Unit]
Description=storozh-shield: раз в минуту

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT

# --- сборщик ---
install -m 755 "$SRC/ddos_collect.py" /usr/local/sbin/ddos-collect
cat > /etc/systemd/system/ddos-collect.service <<'UNIT'
[Unit]
Description=ddos-collect: метрики сервера для сторожа (DDoS и нагрузка), только счётчики
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/sbin/ddos-collect /run/ddos-collect/state.json
Restart=always
RestartSec=5
Nice=10
CPUQuota=5%
MemoryMax=64M
RuntimeDirectory=ddos-collect
RuntimeDirectoryPreserve=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now storozh-shield storozh-shield-tick.timer ddos-collect >/dev/null 2>&1

# --- ключи сторожа: только с его адреса и только одна команда ---
install -d -m 700 /root/.ssh; touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys
add_key() {  # add_key МЕТКА КОМАНДА КЛЮЧ
  grep -qF "$1" /root/.ssh/authorized_keys && { echo "строка $1 уже есть"; return; }
  set -- "$1" "$2" $3
  printf 'from="%s",command="%s",restrict %s %s %s\n' "$watch" "$2" "$3" "$4" "$1" >> /root/.ssh/authorized_keys
  echo "строка $1 добавлена"
}
add_key channel-watch-ddos "cat /run/ddos-collect/state.json" "$ddos_key"
add_key channel-watch-shield "/usr/local/sbin/shield-ctl --ssh" "$shield_key"

sleep 25
echo "== сборщик $(systemctl is-active ddos-collect), срезы $([ -s /run/ddos-collect/state.json ] && echo пишутся || echo 'ещё нет'), щит: $(/usr/local/sbin/shield-ctl status | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("mode"), "· таблица", d.get("loaded"))')"
echo "   теперь на сторожевом сервере: bash install_ddos.sh add ИМЯ $(curl -4 -s -m 8 https://api.ipify.org || echo АДРЕС) [ПОРТ_SSH]"
echo "   откат: bash server_install.sh --uninstall (прежние authorized_keys и правила nft — в $B)"
