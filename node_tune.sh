#!/usr/bin/env bash
# node_tune.sh — сетевой профиль VPN-ноды (Ubuntu 24.04/26.04). Один скрипт вместо прежних tune.sh и tune_align.sh.
# Маячок ноды (node_beacon.py) раз в 10 минут сообщает сторожу, на месте ли профиль; если слетел (переустановка системы,
# обновление ядра, ручная правка) — сторож пишет об этом в отчёте.
#
#   node_tune.sh [--buffer БАЙТ] [--swap МБ] [--journal 200M] [--check]
#     --buffer  потолок TCP-буфера (по умолчанию 16777216 = 16 МБ; на 1 ГБ памяти разумно 8388608)
#     --swap    создать /swapfile этого размера, если swap нет совсем (по умолчанию не создаётся)
#     --journal ограничить журнал systemd
#     --check   ничего не менять, только показать, что отличается от профиля. Можно не от root, но тогда неполно:
#               MPTCP-слушателей ss без root видит только при модуле mptcp_diag и без владельцев, а контейнеры
#               со своей сетью не проверяются вовсе (об этом печатается «?»)
#
# Что ставит (каждое — отдельный файл; прежние версии файлов уходят в копию «до» /root/node-tune-backup/ДАТА/):
#   /etc/sysctl.d/99-vpn-optimize.conf  BBR + fq, буферы, очереди, keepalive, таблица соединений не меньше 100000
#                                       (больше — остаётся как было или как ставило ядро) и её таймауты;
#   /etc/sysctl.d/99-vpn-synflood.conf  быстрее отпускать недооткрытые и закрытые соединения;
#   /etc/sysctl.d/99-zz-no-mptcp.conf   MPTCP выключен (CVE-2026-98432: удалённый root через MPTCP-слушатель;
#                                       программы на Go 1.24+ включают MPTCP сами). Имя «zz» — чтобы читался после
#                                       99-sysctl.conf (= /etc/sysctl.conf). Прежний 99-no-mptcp.conf убирается,
#                                       если в нём нет чужих строк (иначе остаётся, чужие строки называются);
#   /etc/modules-load.d/vpn-node.conf   tcp_bbr и nf_conntrack при загрузке (иначе sysctl таблицы не применяется);
#   /etc/modprobe.d/nf_conntrack.conf   хэш таблицы соединений 32768 (только увеличивается);
#   очередь основной сетевой карты fq_codel → fq (нужна BBR) — сразу и после каждой загрузки (служба vpn-node-fq).
#     У многоочередной карты (корневая mq) с дочерними не fq корень пересоздаётся той же mq: дочерние берут
#     default_qdisc=fq.
# sysctl 0 запрещает MPTCP только новым сокетам: уже открытые слушатели живут до перезапуска владельца, а у контейнера
# со своей сетью (не host) MPTCP в его сети включён по умолчанию. Если после настройки слушатели остались, скрипт
# называет владельцев, что перезапустить, и выходит с кодом 3.
# Откат: взять самую раннюю копию «до», сделанную этой версией (/root/node-tune-backup/ДАТА с файлом README.txt; в
# копиях прежних версий файлы лежат плоско, а в копиях следующих прогонов — уже наши). Удалить 99-zz-no-mptcp.conf и
# 99-vpn-*.conf, вернуть из копии всё, что в ней есть (с полными путями, относительно /); если в ней нет
# vpn-node-fq.service — systemctl disable --now vpn-node-fq и удалить юнит; перезагрузка (иначе sysctl, таблица
# соединений и MPTCP останутся как сейчас).
# Выкладка по флоту: код 3 ожидаем на нодах, где Xray (Go 1.24+) уже слушает MPTCP, — это не сбой установки. Названный
# перезапуск (обычно docker restart remnanode) обрывает сессии клиентов: делать вручную в тихое время, потом --check.
set -euo pipefail
BUF=16777216 SWAP_MB=0 JCAP="" CHECK=0
ARGS=("$@")   # для подсказки «нужен root» — разбор ниже съедает $@
# себя в подсказках — полным путём через bash: при запуске «bash node_tune.sh» голое имя без ./ и бита x не сработает
SELF=$(readlink -f "$0" 2>/dev/null) || SELF=$0; SELF=$(printf '%q' "${SELF:-$0}")
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
if [ "$CHECK" = 0 ] && [ "$(id -u)" != 0 ]; then
  a=""; [ ${#ARGS[@]} = 0 ] || a=$(printf ' %q' "${ARGS[@]}")
  echo "нужен root: sudo bash $SELF$a (без root можно только bash $SELF --check)"; exit 1
fi
IF=$(ip -o route show default | awk '{print $5; exit}')
root_qdisc() { tc qdisc show dev "$IF" root 2>/dev/null | awk 'NR==1{print $2}'; }
# дочерние очереди mq: только строки с parent, без ingress/clsact (их ставят фильтры tc, это не очереди отправки)
mq_kids() { tc qdisc show dev "$IF" 2>/dev/null | awk '/ parent / && $2 !~ /^(mq|ingress|clsact)$/ {print $2}' | sort -u | paste -sd, -; }
# пересоздать корневую mq: дочерние создаются заново с default_qdisc, корень остаётся mq. Ручка — не как у текущей:
# replace той же mq без ручки (или с той же) поверх mq с ненулевой ручкой ядро считает «изменением» и молча ничего не
# делает (проверено на стенде); у mq по умолчанию ручка 0:, там сработало бы и без неё.
mq_renew() {
  local h=1
  if [ "$(tc qdisc show dev "$IF" root 2>/dev/null | awk 'NR==1{print $3}')" = 1: ]; then h=2; fi
  tc qdisc replace dev "$IF" root handle "$h": mq
}
qdisc() {   # корневая очередь; mq с дочерними fq — fq, иначе mq/дочерние (mq/fq_codel); fq под другим корнем — fq
  local r kids
  r=$(root_qdisc)
  if [ "$r" = mq ]; then
    kids=$(mq_kids)
    if [ "$kids" = fq ]; then echo fq; else echo "mq/${kids:-?}"; fi
  elif [ "$r" != fq ] && tc qdisc show dev "$IF" 2>/dev/null | grep -q '^qdisc fq '; then
    echo fq
  else
    echo "$r"
  fi
}

# MPTCP-слушатели, по строке ss на сокет. $1 — доп. ключ ss (p — с владельцами), дальше — чем запускать ss (nsenter
# в сеть контейнера). Основной способ — TCP-подпоток слушателя с пометкой tcp-ulp-mptcp (ss -ti): ss -M без модуля
# mptcp_diag (в Ubuntu он в linux-modules-extra, на облачных образах его нет) молча отдаёт пусто. Пометку ULP ядро
# показывает только root. Коды: 0 — ответ верный (пусто — слушателей нет); 2 — ss не сработал; 3 — без root и без
# mptcp_diag не проверить; 124 — ss не ответил вовремя (timeout).
# модуль mptcp_diag есть: загружен (/sys/module) или встроен в ядро (=y — каталога в /sys/module может не быть)
mptcp_diag_here() {
  [ -d /sys/module/mptcp_diag ] || grep -qsE '(^|/)mptcp_diag\.ko$' "/lib/modules/$(uname -r)/modules.builtin"
}
mptcp_ss() {
  local f=$1 o rc; shift
  o=$("$@" ss -H -tlni"$f" 2>/dev/null) || { rc=$?; [ "$rc" = 124 ] && return 124; return 2; }
  o=$(printf '%s\n' "$o" | awk '/^[ \t]/ { if (/tcp-ulp-mptcp/ && p != "") print p; p = ""; next } { p = $0 }')
  if [ -z "$o" ]; then
    o=$("$@" ss -H -lMn"$f" 2>/dev/null | grep -v '^[[:space:]]*$' || true)
    if [ -z "$o" ] && [ "$(id -u)" != 0 ] && ! mptcp_diag_here; then return 3; fi
  fi
  [ -z "$o" ] || printf '%s\n' "$o"
}
mptcp_ls() { mptcp_ss p; }   # в сети хоста, с владельцами (их ss -p показывает только root)
mptcp_n() {
  local l; l=$(mptcp_ls) || { echo "?"; return 0; }
  if [ -n "$l" ]; then printf '%s\n' "$l" | wc -l | tr -d ' '; else echo 0; fi
}
# владельцы из строк ss -p, по одному на строку: «что_перезапустить<TAB>кто»; «?<TAB>текст» — не удалось узнать
mptcp_owners() {
  local name pid cg cid c unit rc dk=1
  printf '%s\n' "$1" | { grep -o '("[^"]*",pid=[0-9]*' || true; } | sed 's/^("\([^"]*\)",pid=\([0-9]*\)$/\2\t\1/' |
  while IFS=$'\t' read -r pid name; do   # pid первым и через табуляцию: в имени процесса бывают пробелы
    cg=$(cat "/proc/$pid/cgroup" 2>/dev/null || true)
    cid=$(printf '%s\n' "$cg" | { grep -oE '[0-9a-f]{64}' || true; } | head -n1)
    c=""
    if [ -n "$cid" ] && command -v docker >/dev/null 2>&1; then
      # docker не ответил — только «?»: запасное «перезапустить этот процесс» увело бы от docker restart
      if [ "$dk" = 0 ]; then printf '?\tdocker не ответил — контейнер процесса %s (pid %s) не назван\n' "$name" "$pid"; continue; fi
      c=$(timeout 10 docker inspect -f '{{.Name}}' "$cid" 2>/dev/null) || {
        rc=$?; c=""
        if [ "$rc" = 124 ]; then dk=0; printf '?\tdocker не ответил — контейнер процесса %s (pid %s) не назван\n' "$name" "$pid"; continue; fi
      }
      c=${c#/}
    fi
    unit=$(printf '%s\n' "$cg" | { grep -oE '[^/]+\.service$' || true; } | head -n1)
    if [ -n "$c" ]; then printf 'docker restart %s\t%s (контейнер %s)\n' "$c" "$name" "$c"
    elif [ -n "$unit" ]; then printf 'systemctl restart %s\t%s (служба %s)\n' "$unit" "$name" "$unit"
    else printf 'перезапустить этот процесс\t%s (pid %s)\n' "$name" "$pid"
    fi
  done | sort -u
}
# контейнеры со своей сетью, где кто-то слушает MPTCP: «имя число» (из сети хоста ss их не видит); строка «? …» —
# проверить не удалось. Нужен root (nsenter). docker и nsenter — с пределом времени: зависший dockerd не вешает скрипт.
mptcp_containers() {
  command -v docker >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1 || return 0
  local ids id info name mode pid l rc
  ids=$(timeout 10 docker ps -q 2>/dev/null) || { rc=$?; [ "$rc" != 124 ] || echo "? docker не ответил — контейнеры со своей сетью не проверены"; return 0; }
  for id in $ids; do
    info=$(timeout 10 docker inspect -f '{{.Name}} {{.HostConfig.NetworkMode}} {{.State.Pid}}' "$id" 2>/dev/null) || {
      rc=$?; if [ "$rc" = 124 ]; then echo "? docker не ответил — контейнеры со своей сетью проверены не все"; return 0; fi; continue; }
    read -r name mode pid <<<"$info"
    case "$mode" in host|container:*|"") continue ;; esac
    l=$(mptcp_ss "" timeout 5 nsenter -t "$pid" -n) || {
      rc=$?
      if [ "$rc" = 124 ]; then echo "? ${name#/}: ss в сети контейнера не ответил"
      else echo "? ${name#/}: сеть контейнера не проверить"; fi
      continue
    }
    if [ -n "$l" ]; then echo "${name#/} $(printf '%s\n' "$l" | wc -l | tr -d ' ')"; fi
  done
  return 0
}
# «слушателя»/«слушателей» после числа
sl() { if [ $(($1 % 10)) = 1 ] && [ $(($1 % 100)) != 11 ]; then echo "слушателя"; else echo "слушателей"; fi; }
# итог по MPTCP: код 1 — слушатели остались (с подсказкой, кого перезапустить); «?» — что проверить не удалось
mptcp_report() {
  local l rc=0 own ct nu
  l=$(mptcp_ls) || rc=$?
  case "$rc" in
    0) ;;
    3) echo "  ? MPTCP-слушателей без root не проверить (ss видит их только от root или с модулем mptcp_diag)"; l="" ;;
    *) echo "  ? MPTCP-слушателей не проверить: ss не сработал"; l="" ;;
  esac
  ct=""
  if [ "$(id -u)" = 0 ]; then
    ct=$(mptcp_containers)
  elif command -v docker >/dev/null 2>&1; then
    echo "  ? контейнеры со своей сетью не проверены (нужен root)"
  fi
  if [ -n "$ct" ]; then
    printf '%s\n' "$ct" | { grep '^? ' || true; } | sed 's/^/  /'
    ct=$(printf '%s\n' "$ct" | { grep -v '^? ' || true; })
  fi
  [ -z "$l" ] && [ -z "$ct" ] && return 0
  if [ -n "$l" ]; then
    echo "  ✗ MPTCP-слушателей в сети хоста: $(printf '%s\n' "$l" | wc -l | tr -d ' ') — sysctl 0 их не гасит, нужен перезапуск владельцев:"
    own=$(mptcp_owners "$l")
    if [ -n "$own" ]; then
      printf '%s\n' "$own" | while IFS=$'\t' read -r cmd who; do
        if [ "$cmd" = "?" ]; then echo "      ? $who"; else echo "      $who:  $cmd"; fi
      done
    fi
    nu=$(printf '%s\n' "$l" | grep -vc 'users:((' || true)
    if [ "$nu" -gt 0 ]; then
      echo "      у $nu $(sl "$nu") владелец не определён (адреса: $(printf '%s\n' "$l" | grep -v 'users:((' | awk '{print $4}' | paste -sd' ' -))"
      if [ "$(id -u)" != 0 ]; then echo "      владельцев ss показывает только root; обычно это Xray в remnanode: docker restart remnanode"; fi
    fi
  fi
  if [ -n "$ct" ]; then
    echo "  ✗ контейнеры со своей сетью слушают MPTCP (в их сети он включён, простой restart не поможет):"
    printf '%s\n' "$ct" | while read -r c k; do echo "      $c: слушателей $k"; done
    echo "      в compose у службы: sysctls: [net.mptcp.enabled=0], затем docker compose up -d"
  fi
  return 1
}
show() {
  echo "$(hostname): cc=$(sysctl -n net.ipv4.tcp_congestion_control) очередь($IF)=$(qdisc)" \
       "conntrack_max=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo нет)" \
       "mptcp=$(sysctl -n net.mptcp.enabled 2>/dev/null || echo нет) mptcp_слушателей=$(mptcp_n)" \
       "synack=$(sysctl -n net.ipv4.tcp_synack_retries)" \
       "fin_timeout=$(sysctl -n net.ipv4.tcp_fin_timeout) буфер=$(sysctl -n net.core.rmem_max)"
}
if [ "$CHECK" = 1 ]; then
  show
  [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = bbr ] || echo "  ✗ не BBR"
  case "$(qdisc)" in
    fq) ;;
    mq/*) echo "  ✗ очередь $(qdisc): дочерние очереди многоочередной карты не fq — sudo bash $SELF пересоздаст корень mq" \
               "(дочерние возьмут default_qdisc=fq)" ;;
    *) echo "  ✗ очередь не fq" ;;
  esac
  [ "$(sysctl -n net.mptcp.enabled 2>/dev/null || echo 0)" = 0 ] || echo "  ✗ MPTCP включён"
  mptcp_report || true
  [ "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)" -ge 65536 ] || echo "  ✗ мала таблица соединений"
  exit 0
fi
B=/root/node-tune-backup/$(date +%Y%m%d-%H%M%S); install -d -m 700 "$B"
sysctl -a 2>/dev/null > "$B/sysctl-before.txt" || true
echo "node_tune.sh: копия «до» с полными путями (etc/… — как /etc/…); откат — см. шапку node_tune.sh" > "$B/README.txt"
for f in /etc/sysctl.d/99-vpn-*.conf /etc/sysctl.d/99-no-mptcp.conf /etc/sysctl.d/99-zz-no-mptcp.conf \
         /etc/modules-load.d/vpn-node.conf /etc/modprobe.d/nf_conntrack.conf \
         /etc/systemd/journald.conf.d/00-size.conf /etc/systemd/system/vpn-node-fq.service; do
  if [ -e "$f" ]; then cp -p --parents "$f" "$B/"; fi
done
echo "до:    $(show)"

printf 'tcp_bbr\nnf_conntrack\n' > /etc/modules-load.d/vpn-node.conf
modprobe tcp_bbr; modprobe nf_conntrack
if [ "$(sysctl -n net.netfilter.nf_conntrack_buckets)" -lt 32768 ]; then
  echo 'options nf_conntrack hashsize=32768' > /etc/modprobe.d/nf_conntrack.conf
  echo 32768 > /sys/module/nf_conntrack/parameters/hashsize
fi
# Таблицу соединений только увеличиваем: CT = максимум из 100000, текущего значения, числа корзин хэша и значения из
# самой ранней копии «до». Текущего мало: прежняя версия скрипта на всём флоте записала 100000 безусловно, и там, где
# ядро ставило больше, сейчас уже 100000. В ядрах 5.15+ по умолчанию nf_conntrack_max = nf_conntrack_buckets (на машине
# больше 4 ГБ — 262144; hashsize=32768 мы там не пишем, корзины остаются ядерные), а самая ранняя копия «до» хранит
# значение до первого прогона (если nf_conntrack тогда уже был загружен).
CT=100000
first=""; for f in /root/node-tune-backup/*/sysctl-before.txt; do if [ -f "$f" ]; then first=$f; break; fi; done
for v in "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || true)" \
         "$(sysctl -n net.netfilter.nf_conntrack_buckets 2>/dev/null || true)" \
         "$([ -z "$first" ] || sed -n 's/^net\.netfilter\.nf_conntrack_max = \([0-9][0-9]*\)$/\1/p' "$first" | head -n1)"; do
  case "$v" in ''|*[!0-9]*) continue ;; esac
  if [ "$v" -gt "$CT" ]; then CT=$v; fi
done

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
net.netfilter.nf_conntrack_max = $CT
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
echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/99-zz-no-mptcp.conf
# прежнее имя читалось раньше 99-sysctl.conf; убираем (копия уже в «до»), если в нём нет ничего, кроме пустых строк,
# комментариев (# и ;) и net.mptcp.enabled = 0; иначе оставляем и называем чужие строки
OLD=/etc/sysctl.d/99-no-mptcp.conf
if [ -f "$OLD" ]; then
  alien=$(grep -nvE '^[[:space:]]*([#;].*)?$|^[[:space:]]*-?net[./]mptcp[./]enabled[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$OLD" |
          tr -d '\r' || true)
  if [ -z "$alien" ]; then
    rm -f "$OLD"; echo "убран прежний $OLD (копия в $B)"
  else
    echo "  ! $OLD оставлен: в нём чужие строки (MPTCP теперь в 99-zz-no-mptcp.conf; их перенесите сами и удалите файл):"
    printf '%s\n' "$alien" | sed 's/^\([0-9]*\):/      стр. \1: /'
  fi
fi
for f in 99-vpn-optimize 99-vpn-synflood 99-zz-no-mptcp; do
  sysctl -q -p /etc/sysctl.d/$f.conf 2>>"$B/sysctl-apply.log" || echo "  (часть строк $f не применилась — $B/sysctl-apply.log)"
done

# очередь: сейчас и после каждой загрузки (default_qdisc действует не на все карты, поднятые раньше sysctl).
# Корневую fq_codel меняем на fq. У mq (многоочередная карта) с дочерними не fq пересоздаём корень той же mq: дочерние
# создаются заново с default_qdisc=fq, корень остаётся mq. Прочие корни (htb, cake и т. п. — чужая настройка) не трогаем.
cat > /etc/systemd/system/vpn-node-fq.service <<'UNIT'
[Unit]
Description=VPN node: fq queue on the default-route interface (for BBR)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'IF=$(ip -o route show default | awk "{print \$5; exit}"); [ -n "$IF" ] || exit 0; R=$(tc qdisc show dev "$IF" root | awk "NR==1{print \$2}"); if [ "$R" = fq_codel ]; then tc qdisc replace dev "$IF" root fq; elif [ "$R" = mq ] && tc qdisc show dev "$IF" | grep " parent " | grep -vqE "^qdisc (mq|fq|ingress|clsact) "; then H=1; tc qdisc show dev "$IF" root | grep -q "^qdisc mq 1: " && H=2; tc qdisc replace dev "$IF" root handle $H: mq; fi; true'
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now vpn-node-fq.service >/dev/null 2>&1 || true
Q=$(qdisc)
case "$Q" in
  mq/*)   # служба уже должна была это сделать; повторяем на случай, если она не запустилась
    mq_renew 2>>"$B/sysctl-apply.log" || true
    if [ "$(qdisc)" = fq ]; then echo "очередь $IF: корневая mq пересоздана, дочерние ${Q#mq/} → fq"
    else echo "  ! очередь $IF: $(qdisc) — дочерние не стали fq (default_qdisc=$(sysctl -n net.core.default_qdisc)), см. $B/sysctl-apply.log"; fi ;;
esac

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
if ! mptcp_report; then
  echo "ИТОГ: профиль поставлен, но MPTCP ещё слушает — перезапустите названное выше и проверьте: bash $SELF --check"
  exit 3
fi
