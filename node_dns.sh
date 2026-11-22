#!/usr/bin/env bash
# node_dns.sh — свой кэширующий DNS-резолвер ноды (Unbound), рядом с node_tune.sh. Ubuntu 24.04/26.04.
#
# Зачем: нода сама находит адреса сайтов для трафика клиентов (Xray спрашивает систему). Без своего резолвера эти
# запросы уходят к DNS провайдера или 1.1.1.1; свой Unbound спрашивает корневые серверы сам, держит кэш (на рабочей
# ноде 96% ответов из кэша) и проверяет подписи DNSSEC. Телефоны клиентов его не видят: он слушает только 127.0.0.1.
# Российские сайты не страдают: в шаблонах подписки они идут напрямую с устройства, а адреса, которые находит Unbound,
# совпадают с ответами 1.1.1.1.
#
#   node_dns.sh install | status | rollback        [FALLBACK=1.1.1.1 — запасной DNS]
#
# Что ставит:
#   /etc/unbound/unbound.conf.d/storozh.conf      Unbound только на 127.0.0.1, кэш 32+64 МБ, prefetch, serve-expired,
#                                                 подробная статистика (маячок следит за кэшем и очередью);
#   /etc/systemd/resolved.conf.d/storozh-unbound.conf   systemd-resolved спрашивает Unbound первым, запасной — FALLBACK;
#   storozh-unbound-return.timer                  раз в 10 минут: если resolved ушёл на запасной, а Unbound отвечает —
#                                                 вернуть; каждое переключение — строка в /var/log/storozh-unbound.log.
# Откат: node_dns.sh rollback (resolved снова на DNS провайдера, Unbound выключен).
# Установка сама откатывается, если Unbound не смог найти адрес ya.ru: так бывает у хостеров, которые закрывают
# российские сервисы вместе с их DNS-серверами (рекурсия до Яндекса не доходит) — там лучше оставить DNS провайдера.
set -euo pipefail
FALLBACK=${FALLBACK:-1.1.1.1}
B=/root/node-dns-backup; install -d -m 700 "$B"
IF=$(ip -o route get 1.1.1.1 | grep -o "dev [^ ]*" | cut -d" " -f2)

probe() {   # ответ Unbound на запрос A имени $1: rcode (0 — норма) или «нет ответа»
  python3 - "$1" <<'PY'
import socket, struct, random, sys
name = sys.argv[1]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + b"".join(
    bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
try:
    s.sendto(q, ("127.0.0.1", 53)); r = s.recv(1500); print(r[3] & 15)
except OSError:
    print("нет ответа")
PY
}

case "${1:-}" in
  install)
    resolvectl status > "$B/resolvectl-before.txt" 2>&1 || true
    ss -lunH | awk '{print $4}' | grep -qE '^127\.0\.0\.1:53$' && ! systemctl is-active -q unbound && {
      echo "127.0.0.1:53 уже занят чем-то другим — не ставлю"; exit 1; }
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q unbound >/dev/null
    systemctl mask --now unbound-resolvconf.service >/dev/null 2>&1 || true
    cat > /etc/unbound/unbound.conf.d/storozh.conf <<'CONF'
# node_dns.sh: свой кэширующий резолвер ноды. Только для самой ноды (127.0.0.1), спрашивает корневые серверы сам.
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    do-ip6: yes
    prefer-ip6: no
    num-threads: 1
    msg-cache-size: 32m
    rrset-cache-size: 64m
    num-queries-per-thread: 4096
    outgoing-range: 8192
    prefetch: yes
    serve-expired: yes
    serve-expired-ttl: 3600
    qname-minimisation: yes
    hide-identity: yes
    hide-version: yes
    extended-statistics: yes
CONF
    # управление (unbound-control) пакет Ubuntu включает сам: unbound.conf.d/remote-control.conf
    unbound-checkconf >/dev/null
    systemctl enable unbound >/dev/null 2>&1; systemctl restart unbound; sleep 2
    ok=0; for i in 1 2 3; do [ "$(probe ya.ru)" = 0 ] && { ok=1; break; }; sleep 3; done   # холодный кэш: первый ответ бывает долгим
    [ "$ok" = 1 ] || { echo "Unbound не отвечает — откат"; "$0" rollback; exit 1; }
    install -d /etc/systemd/resolved.conf.d
    # пустое DNS= сбрасывает список из основного resolved.conf (хостеры часто прописывают там свои), иначе Unbound встанет последним
    printf '[Resolve]\n# node_dns.sh: свой резолвер первым, %s — запасной\nDNS=\nDNS=127.0.0.1 %s\nDomains=~.\n' "$FALLBACK" "$FALLBACK" \
      > /etc/systemd/resolved.conf.d/storozh-unbound.conf
    systemctl restart systemd-resolved; sleep 1
    resolvectl default-route "$IF" false || true
    cat > /usr/local/sbin/storozh-unbound-return <<'SH'
#!/usr/bin/env bash
# node_dns.sh: держать систему на своём Unbound. Каждое переключение — строка в /var/log/storozh-unbound.log.
set -u
LOG=/var/log/storozh-unbound.log
IF=$(ip -o route get 1.1.1.1 | grep -o "dev [^ ]*" | cut -d" " -f2)
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
ok() { python3 -c '
import socket, struct, random, sys
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + b"\x02ya\x02ru\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, ("127.0.0.1", 53)); r = s.recv(512); sys.exit(0 if (r[3] & 15) == 0 else 1)
except OSError:
    sys.exit(1)'; }
current() { resolvectl status 2>/dev/null | awk '/Current DNS Server/{print $4; exit}'; }
if resolvectl status "$IF" 2>/dev/null | grep -q "+DefaultRoute"; then
  resolvectl default-route "$IF" false && echo "$(now) DNS сетевой карты $IF снова был маршрутом по умолчанию — выключен" >> "$LOG"
fi
cur=$(current)
if [ "$cur" != "127.0.0.1" ]; then
  if ok; then
    systemctl restart systemd-resolved; sleep 1; resolvectl default-route "$IF" false
    echo "$(now) resolved был на ${cur:-?} — вернула на Unbound (сейчас $(current))" >> "$LOG"
  else
    echo "$(now) resolved на ${cur:-?}, Unbound не отвечает — оставлен запасной" >> "$LOG"
  fi
fi
SH
    chmod 755 /usr/local/sbin/storozh-unbound-return
    cat > /etc/systemd/system/storozh-unbound-return.service <<'UNIT'
[Unit]
Description=storozh: держать систему на своём Unbound (возврат с запасного DNS)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/storozh-unbound-return
UNIT
    cat > /etc/systemd/system/storozh-unbound-return.timer <<'UNIT'
[Unit]
Description=storozh: проверка своего DNS раз в 10 минут
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
UNIT
    cat > /etc/logrotate.d/storozh-unbound <<'L'
/var/log/storozh-unbound.log {
    monthly
    rotate 3
    compress
    missingok
    notifempty
}
L
    systemctl daemon-reload; systemctl enable --now storozh-unbound-return.timer >/dev/null 2>&1
    "$0" status ;;
  status)
    echo "unbound: $(systemctl is-active unbound) · система спрашивает: $(resolvectl status | awk '/Current DNS Server/{print $4; exit}')" \
         "· ya.ru: rcode $(probe ya.ru) · ozon.ru: rcode $(probe ozon.ru)" \
         "· переключений на запасной за сутки: $(awk -v d="$(date -u -d '-24 hours' +%Y-%m-%dT%H:%M)" '$1>=d' /var/log/storozh-unbound.log 2>/dev/null | wc -l)"
    unbound-control stats_noreset 2>/dev/null | grep -E '^total\.num\.(queries|cachehits)=|^total\.requestlist\.exceeded=|^mem\.cache\.(rrset|message)=' | tr '\n' ' '; echo ;;
  rollback)
    systemctl disable --now storozh-unbound-return.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/storozh-unbound-return.{service,timer} /usr/local/sbin/storozh-unbound-return; systemctl daemon-reload
    rm -f /etc/systemd/resolved.conf.d/storozh-unbound.conf
    resolvectl default-route "$IF" true || true
    systemctl restart systemd-resolved
    systemctl disable --now unbound >/dev/null 2>&1 || true
    [ -e /etc/unbound/unbound.conf.d/storozh.conf ] && mv /etc/unbound/unbound.conf.d/storozh.conf "$B/storozh.conf.rolled-back"
    echo "откат: resolved — $(resolvectl status | awk '/DNS Servers/{print $3, $4; exit}'), unbound — $(systemctl is-active unbound)" ;;
  *) echo "node_dns.sh install | status | rollback"; exit 2 ;;
esac
