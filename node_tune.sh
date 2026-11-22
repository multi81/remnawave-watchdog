#!/usr/bin/env bash
# node_tune.sh — сетевой профиль VPN-ноды (Ubuntu 24.04/26.04). Один скрипт вместо прежних tune.sh и tune_align.sh.
# Маячок ноды (node_beacon.py) раз в 10 минут сообщает сторожу, на месте ли профиль; если слетел (переустановка системы,
# обновление ядра, ручная правка) — сторож пишет об этом в отчёте.
#
#   node_tune.sh [--buffer БАЙТ] [--swap МБ] [--journal 200M] [--check]
#     --buffer  потолок TCP-буфера (по умолчанию 16777216 = 16 МБ; на 1 ГБ памяти разумно 8388608)
#     --swap    создать /swapfile этого размера, если swap нет совсем (по умолчанию не создаётся)
#     --journal ограничить журнал systemd
#     --check   ничего не менять, только показать, что отличается от профиля
#
# Что ставит (каждое — отдельный файл, ничего чужого не переписывается):
#   /etc/sysctl.d/99-vpn-optimize.conf  BBR + fq, буферы, очереди, keepalive, таблица соединений 100000 и её таймауты;
#   /etc/sysctl.d/99-vpn-synflood.conf  быстрее отпускать недооткрытые и закрытые соединения;
#   /etc/sysctl.d/99-no-mptcp.conf      MPTCP выключен (CVE-2026-98432: удалённый root через MPTCP-слушатель;
#                                       программы на Go 1.24+ включают MPTCP сами);
#   /etc/modules-load.d/vpn-node.conf   tcp_bbr и nf_conntrack при загрузке (иначе sysctl таблицы не применяется);
#   /etc/modprobe.d/nf_conntrack.conf   хэш таблицы соединений 32768 (только увеличивается);
#   очередь основной сетевой карты fq_codel → fq (нужна BBR) — сразу и после каждой загрузки (служба vpn-node-fq).
# Откат: удалить перечисленные файлы, systemctl disable --now vpn-node-fq; перезагрузка.
set -euo pipefail
BUF=16777216 SWAP_MB=0 JCAP="" CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --buffer) BUF=$2; shift ;;
    --swap) SWAP_MB=$2; shift ;;
    --journal) JCAP=$2; shift ;;
    --check) CHECK=1 ;;
    *) echo "не понимаю параметр $1"; exit 2 ;;
  esac
  shift
done
IF=$(ip -o route show default | awk '{print $5; exit}')
qdisc() { tc qdisc show dev "$IF" 2>/dev/null | grep -q '^qdisc fq ' && echo fq || tc qdisc show dev "$IF" root | awk 'NR==1{print $2}'; }
show() {
  echo "$(hostname): cc=$(sysctl -n net.ipv4.tcp_congestion_control) очередь($IF)=$(qdisc)" \
       "conntrack_max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo нет)" \
       "mptcp=$(sysctl -n net.mptcp.enabled 2>/dev/null || echo нет) synack=$(sysctl -n net.ipv4.tcp_synack_retries)" \
       "fin_timeout=$(sysctl -n net.ipv4.tcp_fin_timeout) буфер=$(sysctl -n net.core.rmem_max)"
}
if [ "$CHECK" = 1 ]; then
  show
  [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = bbr ] || echo "  ✗ не BBR"
  [ "$(qdisc)" = fq ] || echo "  ✗ очередь не fq"
  [ "$(sysctl -n net.mptcp.enabled 2>/dev/null || echo 0)" = 0 ] || echo "  ✗ MPTCP включён"
  [ "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)" -ge 65536 ] || echo "  ✗ мала таблица соединений"
  exit 0
fi
B=/root/node-tune-backup/$(date +%Y%m%d-%H%M%S); install -d -m 700 "$B"
sysctl -a 2>/dev/null > "$B/sysctl-before.txt" || true
cp -p /etc/sysctl.d/99-vpn-*.conf /etc/sysctl.d/99-no-mptcp.conf "$B/" 2>/dev/null || true
echo "до:    $(show)"

printf 'tcp_bbr\nnf_conntrack\n' > /etc/modules-load.d/vpn-node.conf
modprobe tcp_bbr; modprobe nf_conntrack
if [ "$(sysctl -n net.netfilter.nf_conntrack_buckets)" -lt 32768 ]; then
  echo 'options nf_conntrack hashsize=32768' > /etc/modprobe.d/nf_conntrack.conf
  echo 32768 > /sys/module/nf_conntrack/parameters/hashsize
fi

cat > /etc/sysctl.d/99-vpn-optimize.conf <<CONF
# Сетевой профиль VPN-ноды (node_tune.sh).
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = $BUF
net.core.wmem_max = $BUF
net.ipv4.tcp_rmem = 4096 87380 $BUF
net.ipv4.tcp_wmem = 4096 65536 $BUF
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.netfilter.nf_conntrack_max = 100000
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
vm.swappiness = 10
vm.vfs_cache_pressure = 50
CONF
cat > /etc/sysctl.d/99-vpn-synflood.conf <<'CONF'
# VPN-нода: устойчивость к наплыву недооткрытых соединений (node_tune.sh).
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
CONF
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-no-mptcp.conf
for f in 99-vpn-optimize 99-vpn-synflood 99-no-mptcp; do
  sysctl -q -p /etc/sysctl.d/$f.conf 2>>"$B/sysctl-apply.log" || echo "  (часть строк $f не применилась — $B/sysctl-apply.log)"
done

# очередь: сейчас и после каждой загрузки (default_qdisc действует не на все карты, поднятые раньше sysctl)
cat > /etc/systemd/system/vpn-node-fq.service <<'UNIT'
[Unit]
Description=VPN node: fq queue on the default-route interface (for BBR)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'IF=$(ip -o route show default | awk "{print \$5; exit}"); tc qdisc show dev "$IF" root | grep -q "^qdisc fq_codel" && tc qdisc replace dev "$IF" root fq || true'
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now vpn-node-fq.service >/dev/null 2>&1 || true

if [ "$SWAP_MB" != 0 ] && [ "$(free -m | awk 'NR==3{print $2}')" = 0 ] && [ ! -e /swapfile ]; then
  fallocate -l "${SWAP_MB}M" /swapfile; chmod 600 /swapfile; mkswap /swapfile >/dev/null; swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
if [ -n "$JCAP" ]; then
  install -d /etc/systemd/journald.conf.d
  printf '[Journal]\nSystemMaxUse=%s\n' "$JCAP" > /etc/systemd/journald.conf.d/00-size.conf
  systemctl restart systemd-journald; journalctl --vacuum-size="$JCAP" >/dev/null 2>&1 || true
fi
echo "после: $(show)"
echo "копия «до»: $B"
