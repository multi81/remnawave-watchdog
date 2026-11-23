#!/usr/bin/env bash
# node_dns.sh — свой кэширующий DNS-резолвер ноды (Unbound), рядом с node_tune.sh. Ubuntu 24.04/26.04.
#
# Зачем: нода сама находит адреса сайтов для трафика клиентов (Xray спрашивает систему). Без своего резолвера эти
# запросы уходят к DNS провайдера или 1.1.1.1; свой Unbound спрашивает корневые серверы сам, держит кэш (на рабочей
# ноде 96% ответов из кэша) и проверяет подписи DNSSEC. Телефоны клиентов его не видят: он слушает только 127.0.0.1.
# Российские сайты не страдают: в шаблонах подписки они идут напрямую с устройства, а адреса, которые находит Unbound,
# совпадают с ответами 1.1.1.1.
#
#   bash node_dns.sh install | status | rollback   [FALLBACK="адрес …" — запасной DNS, каждый адрес проверяется;
#                                                   по умолчанию DNS системы до установки (глобальные и у сетевой
#                                                   карты; если снимок снят после прежней установки — только у карты),
#                                                   если их нет — 1.1.1.1. Нужен маршрут IPv4 наружу: по нему ищется
#                                                   сетевая карта]
#
# Что ставит:
#   /etc/unbound/unbound.conf.d/storozh.conf      Unbound только на 127.0.0.1, кэш 32+64 МБ, prefetch, serve-expired,
#                                                 подробная статистика (маячок следит за кэшем и очередью);
#   /etc/systemd/resolved.conf.d/storozh-unbound.conf   systemd-resolved на своём Unbound. Два вида:
#                                                 полный — запасной FALLBACK отвечает: DNS=127.0.0.1 FALLBACK и
#                                                 Domains=~., default-route у карты снят: Unbound спрашивается первым,
#                                                 запасной — если Unbound не ответил, DNS провайдера не спрашивается;
#                                                 мягкий — запасной не ответил: DNS=127.0.0.1 и DNS карты, без Domains=~.,
#                                                 default-route как до установки: resolved спрашивает Unbound и DNS
#                                                 карты параллельно, отвечает быстрейший (часть ответов — от DNS
#                                                 провайдера, мимо кэша и DNSSEC Unbound; DNS карты — если у карты и в
#                                                 снимке «до» их нет, из DNS= в /etc/systemd/resolved.conf и его .conf.d);
#   storozh-unbound-return.timer                  раз в 10 минут (3 попытки, случайное имя под ya.ru — его нет в кэше,
#                                                 serve-expired не замаскирует отказ): запасной ожил/умер — drop-in
#                                                 полный/мягкий; resolved ушёл с Unbound, а Unbound отвечает — вернуть;
#                                                 не отвечают ни Unbound, ни запасной — снять drop-in и вернуть DNS
#                                                 провайдера (drop-in вернётся, когда Unbound ответит);
#                                                 каждое переключение — строка в /var/log/storozh-unbound.log.
# Как было до установки: /root/node-dns-backup/resolvectl-before.txt и before.env (пишутся один раз, повторная
# установка их не трогает; при неверном FALLBACK не пишутся); запасной этой установки — dns.env. Откат: node_dns.sh
# rollback — resolved снова на DNS провайдера, default-route как был, Unbound выключен (если он работал до нас —
# остаётся, только без storozh.conf), автозапуск Unbound как был, маска unbound-resolvconf снята, если её ставили мы;
# before.env удаляется, снимок уходит в resolvectl-before.txt.rolled-back-ДАТА — следующая установка снимет «до» заново.
# Установка сама откатывается, если Unbound не смог найти адрес ya.ru: так бывает у хостеров, которые закрывают
# российские сервисы вместе с их DNS-серверами (рекурсия до Яндекса не доходит) — там лучше оставить DNS провайдера.
# Повторная установка новой версии на ноде с прежней: если проба ya.ru не пройдёт, это тот же автооткат — нода уйдёт
# с Unbound на DNS провайдера. Это нормально; выкатывать по одной ноде и смотреть вывод.
set -euo pipefail
FALLBACK=${FALLBACK:-}
B=/root/node-dns-backup; install -d -m 700 "$B"
# сетевая карта маршрута наружу; нет маршрута IPv4 — пусто (install не ставит, rollback не трогает default-route)
IF=$(ip -o route get 1.1.1.1 2>/dev/null | grep -o "dev [^ ]*" | cut -d" " -f2) || IF=
UCONF=/etc/unbound/unbound.conf.d/storozh.conf
RCONF=/etc/systemd/resolved.conf.d/storozh-unbound.conf
ROFF=$B/storozh-unbound.conf.off   # drop-in, снятый таймером, когда не отвечали ни Unbound, ни запасной
RET=/usr/local/sbin/storozh-unbound-return
NOW=$B/resolvectl-now.txt          # свежий `resolvectl status` для разбора (rv читает файл, не аргумент)

probe() {   # ответ DNS-сервера $2 (по умолчанию свой Unbound) на запрос A имени $1: rcode (0 — норма) или «нет ответа»
  python3 - "$1" "${2:-127.0.0.1}" <<'PY'
import socket, struct, random, sys
name, srv = sys.argv[1], sys.argv[2]
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + b"".join(
    bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
try:
    s.sendto(q, (srv, 53)); r = s.recv(1500); print(r[3] & 15)
except OSError:
    print("нет ответа")
PY
}

rv() {   # dns ФАЙЛ  — DNS из `resolvectl status` (файл): глобальные и у $IF, до трёх; если в Global есть свой 127.x/::1
         #             (снимок после прежней установки), Global не берём целиком — только DNS сетевой карты;
         # link ФАЙЛ — только DNS у $IF;  route ФАЙЛ [legacy] — default-route у $IF (true/false, пусто — не понять;
         #             legacy: снимку после прежней установки не верить);  check "АДРЕС …" — годные адреса из списка;
         # conf ФАЙЛ… — DNS= из секции [Resolve] файлов resolved.conf по порядку (пустое DNS= сбрасывает список).
         # Не годятся: loopback, 0.0.0.0/::, multicast, 240/4 с 255.255.255.255, адреса с %, IPv6 link-local, мусор;
         # ::ffff:a.b.c.d проверяется и выдаётся как a.b.c.d; IPv4 169.254/16 годится (DNS облаков на адресе метаданных).
  python3 - "$IF" "$@" <<'PY'
import ipaddress, re, sys
ifc, mode, arg = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
legacy = len(sys.argv) > 4 and sys.argv[4] == "legacy"

def addr(t, plain=False):   # ip_address из записи 1.1.1.1, 1.1.1.1#sni, 1.1.1.1:53, [::1]:53; None — не адрес
    a = t
    if not plain:
        a = a.split("#")[0]
        if a.startswith("["):
            a = a[1:].split("]")[0]
        elif a.count(":") == 1:
            a = a.split(":")[0]
    if "%" in a:
        return None
    try:
        return ipaddress.ip_address(a)
    except ValueError:
        return None

def v4(ip):   # ::ffff:a.b.c.d — это IPv4 a.b.c.d (Python 3.12 не считает ::ffff:127.0.0.1 loopback'ом)
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped is not None else ip

def good(ip):
    ip = v4(ip)
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or (ip.version == 4 and ip.is_reserved)
                or (ip.version == 6 and ip.is_link_local))

def uniq(xs):
    out = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out

if mode == "check":
    out = []
    for t in arg.split():
        ip = addr(t, plain=True)
        if ip is None or not good(ip):
            print("FALLBACK: %r — не адрес DNS-сервера, пропускаю" % t, file=sys.stderr)
        else:
            out.append(str(v4(ip)))
    print(" ".join(uniq(out)))
    sys.exit()
if mode == "conf":
    out = []
    for fn in sys.argv[3:]:
        try:
            lines = open(fn, errors="replace").read().splitlines()
        except OSError:
            continue
        sec = ""
        for ln in lines:
            s = ln.strip()
            if not s or s[0] in "#;":
                continue
            if s.startswith("["):
                sec = s; continue
            k, eq, v = s.partition("=")
            if sec != "[Resolve]" or not eq or k.strip() != "DNS":
                continue
            if not v.strip():
                out = []; continue
            for t in v.split():
                ip = addr(t)
                if ip is not None and good(ip):
                    out.append(str(v4(ip)))
    print(" ".join(uniq(out)[:3]))
    sys.exit()
try:
    text = open(arg, errors="replace").read()
except OSError:
    text = ""
sec = key = None; g, i = [], []; route = ""; loop = False
for ln in text.splitlines():
    if not ln.strip():
        key = None; continue
    if re.match(r"(Global|Link \d+ \()", ln):   # подписи выровнены вправо: «Current DNS Server:» тоже с начала строки
        sec = "g" if ln.startswith("Global") else ("i" if re.match(r"Link \d+ \(%s\)" % re.escape(ifc), ln) else None)
        key = None; continue
    m = re.match(r"\s*([A-Za-z][A-Za-z .]*?):(?:\s+(.*))?$", ln)
    if m:
        key, rest = m.group(1), m.group(2) or ""
    else:
        rest = ln   # продолжение списка адресов
    if sec == "i" and key == "Protocols":
        route = "true" if "+DefaultRoute" in rest.split() else ("false" if "-DefaultRoute" in rest.split() else route)
    if sec == "i" and key == "DefaultRoute setting":
        route = "true" if rest.strip() == "yes" else "false"
    if sec and key == "DNS Servers":
        for t in rest.split():
            ip = addr(t)
            if ip is None:
                continue
            if v4(ip).is_loopback and sec == "g":
                loop = True
            if good(ip):
                (g if sec == "g" else i).append(str(v4(ip)))
if mode == "dns":
    print(" ".join(uniq(i if loop else g + i)[:3]))
elif mode == "link":
    print(" ".join(uniq(i)[:3]))
else:
    print("" if legacy and loop else route)
PY
}

before() { sed -n "s/^$1=//p" "$B/before.env" 2>/dev/null | head -n1 || true; }   # значение из before.env

before_env() {   # как было до первой установки: Unbound (работал, автозапуск), default-route у $IF, маска
                 # unbound-resolvconf. Один раз.
  [ -s "$B/before.env" ] && return 0
  local was=no en=no mask=no dr
  if [ -e "$UCONF" ] || [ -e "$RCONF" ]; then
    # стоит прежняя версия node_dns.sh: Unbound и маска — наши, default-route уже сняли мы — берём из снимка «до»
    mask=yes
    dr=$(rv route "$B/resolvectl-before.txt" legacy) || dr=
  else
    systemctl is-active -q unbound && was=yes
    en=$(systemctl is-enabled unbound 2>/dev/null || true); en=${en%%[[:space:]]*}
    [ "$(systemctl is-enabled unbound-resolvconf.service 2>/dev/null || true)" = masked ] || mask=yes
    resolvectl status > "$NOW" 2>&1 || true
    dr=$(rv route "$NOW") || dr=
  fi
  printf 'UNBOUND_WAS_ACTIVE=%s\nUNBOUND_WAS_ENABLED=%s\nDEFAULT_ROUTE=%s\nMASKED_BY_US=%s\n' \
    "$was" "${en:-no}" "${dr:-true}" "$mask" > "$B/before.env"
}

do_install() {
  ss -lunH | awk '{print $4}' | grep -qE '^127\.0\.0\.1:53$' && ! systemctl is-active -q unbound && {
    echo "127.0.0.1:53 уже занят чем-то другим — не ставлю"; exit 1; }
  [ -n "$IF" ] || { echo "нет маршрута IPv4 наружу (ip route get 1.1.1.1) — не понять сетевую карту, не ставлю"; exit 1; }
  # FALLBACK из окружения — до снимков «до»: при неверном ничего не записано, следующая установка снимет состояние сама
  if [ -n "$FALLBACK" ]; then
    FALLBACK=$(rv check "$FALLBACK") || FALLBACK=
    [ -n "$FALLBACK" ] || { echo "FALLBACK: ни одного годного адреса — нужны адреса DNS-серверов через пробел" \
                                 "(не 127.x, ::1, 0.0.0.0, ::, 255.255.255.255, не с %)"; exit 2; }
  fi
  [ -s "$B/resolvectl-before.txt" ] || resolvectl status > "$B/resolvectl-before.txt" 2>&1 || true
  before_env
  if [ -z "$FALLBACK" ]; then
    FALLBACK=$(rv dns "$B/resolvectl-before.txt") || FALLBACK=; FALLBACK=${FALLBACK:-1.1.1.1}
  fi
  local ip6=no fbs fb_ok=0 a mode sysdns f rcfs
  # без глобального IPv6 и маршрута по нему Unbound только теряет время на AAAA-адреса серверов имён
  [ -n "$(ip -6 -o addr show scope global 2>/dev/null)" ] && [ -n "$(ip -6 route show default 2>/dev/null)" ] && ip6=yes
  DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null || echo "apt-get update с ошибкой — ставлю из того, что есть"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q unbound >/dev/null
  systemctl mask --now unbound-resolvconf.service >/dev/null 2>&1 || true
  cat > "$UCONF" <<CONF
# node_dns.sh: свой кэширующий резолвер ноды. Только для самой ноды (127.0.0.1), спрашивает корневые серверы сам.
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    do-ip6: $ip6
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
  ok=0; for _ in 1 2 3; do [ "$(probe ya.ru)" = 0 ] && { ok=1; break; }; sleep 3; done   # холодный кэш: первый ответ бывает долгим
  [ "$ok" = 1 ] || { echo "Unbound не отвечает — откат"; do_rollback; exit 1; }
  read -ra fbs <<< "$FALLBACK"
  for a in "${fbs[@]}"; do [ "$(probe ya.ru "$a")" = 0 ] && { fb_ok=1; break; }; done
  # DNS карты на случай мягкого drop-in, если у карты сейчас их нет: живые, иначе DNS системы из снимка «до», иначе
  # DNS= из resolved.conf и его .conf.d (хостеры прописывают туда; пустое DNS= нашего drop-in их прячет), кроме нашего
  resolvectl status > "$NOW" 2>&1 || true
  sysdns=$(rv link "$NOW") || sysdns=
  [ -n "$sysdns" ] || { sysdns=$(rv dns "$B/resolvectl-before.txt") || sysdns=; }
  if [ -z "$sysdns" ]; then
    rcfs=(/etc/systemd/resolved.conf)
    for f in /etc/systemd/resolved.conf.d/*.conf; do
      if [ -f "$f" ] && [ "$f" != "$RCONF" ]; then rcfs+=("$f"); fi
    done
    sysdns=$(rv conf "${rcfs[@]}") || sysdns=
  fi
  printf 'FALLBACK=%s\nSYSTEM_DNS=%s\n' "$FALLBACK" "$sysdns" > "$B/dns.env"
  cat > "$RET" <<'SH'
#!/usr/bin/env bash
# node_dns.sh: держать систему на своём Unbound. Каждое переключение — строка в /var/log/storozh-unbound.log.
#   storozh-unbound-return                   проверка (таймер раз в 10 минут)
#   storozh-unbound-return conf full|soft    только записать drop-in (так его пишет и node_dns.sh install)
# full — запасной отвечает: DNS=127.0.0.1 FALLBACK и Domains=~., default-route у карты снят (Unbound первым);
# soft — запасной не отвечает: DNS=127.0.0.1 и DNS карты без Domains=~., default-route как до установки — resolved
#        спрашивает Unbound и DNS карты параллельно, отвечает быстрейший. Если молчат и Unbound, и запасной —
#        drop-in снимается совсем (до ответа Unbound).
set -u
LOG=/var/log/storozh-unbound.log
CONF=/etc/systemd/resolved.conf.d/storozh-unbound.conf
B=/root/node-dns-backup
OFF=$B/storozh-unbound.conf.off   # drop-in, снятый, когда не отвечали ни Unbound, ни запасной
env_() { sed -n "s/^$1=//p" "$2" 2>/dev/null | head -n1; }
FB=$(env_ FALLBACK "$B/dns.env")
IF=$(ip -o route get 1.1.1.1 2>/dev/null | grep -o "dev [^ ]*" | cut -d" " -f2)
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
py() { python3 - "$@" <<'PY'
import ipaddress, random, socket, struct, sys
if sys.argv[1] == "alive":
    # жива ли рекурсия у сервера: 3 попытки, каждый раз случайное имя под ya.ru (ya.ru без DNSSEC — aggressive-nsec
    # не выдумает ответ из кэша, а имени нет в кэше — serve-expired не отдаст старое). NOERROR/NXDOMAIN — жива;
    # таймаут, SERVFAIL, REFUSED — нет.
    srv = sys.argv[2]
    for _ in range(3):
        lab = ("storozh%08x" % random.getrandbits(32)).encode()
        q = struct.pack(">HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0) + bytes([len(lab)]) + lab \
            + b"\x02ya\x02ru\x00" + struct.pack(">HH", 1, 1)
        s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
        try:
            s.sendto(q, (srv, 53)); r = s.recv(1500)
            if r[:2] == q[:2] and r[2] & 0x80 and r[3] & 15 in (0, 3):
                sys.exit(0)
        except OSError:
            pass
        finally:
            s.close()
    sys.exit(1)
out = []   # link: годные адреса из вывода `resolvectl dns IF` ($2; stdin занят самим скриптом), как в node_dns.sh rv
for t in sys.argv[2].split("): ", 1)[-1].split():
    a = t.split("#")[0]
    a = a[1:].split("]")[0] if a.startswith("[") else (a.split(":")[0] if a.count(":") == 1 else a)
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        continue
    if ip.version == 6 and ip.ipv4_mapped is not None:   # ::ffff:a.b.c.d — это IPv4 a.b.c.d
        ip = ip.ipv4_mapped
    if "%" in a or ip.is_loopback or ip.is_unspecified or ip.is_multicast or (ip.version == 4 and ip.is_reserved) \
            or (ip.version == 6 and ip.is_link_local):
        continue
    if str(ip) not in out:
        out.append(str(ip))
print(" ".join(out[:3]))
PY
}
alive() { py alive "$1"; }
fb_alive() { local a; for a in $FB; do alive "$a" && return 0; done; return 1; }
card() { local c; c=$(py link "$(resolvectl dns "$IF" 2>/dev/null)"); echo "${c:-$(env_ SYSTEM_DNS "$B/dns.env")}"; }
write_conf() {   # $1: full | soft; пустое DNS= сбрасывает список из основного resolved.conf (хостеры часто прописывают
                 # там свои), иначе Unbound встанет последним
  if [ "$1" = full ]; then
    printf '[Resolve]\n# node_dns.sh: свой резолвер первым, %s — запасной\nDNS=\nDNS=127.0.0.1 %s\nDomains=~.\n' "$FB" "$FB"
  else
    local c; c=$(card)
    printf '[Resolve]\n# node_dns.sh: запасной %s не отвечает — без Domains=~.: resolved спрашивает свой резолвер и DNS карты параллельно, отвечает быстрейший\nDNS=\nDNS=127.0.0.1 %s\n' \
      "${FB:-?}" "$c"
  fi > "$CONF.tmp" && mv -f "$CONF.tmp" "$CONF"
}
route() {   # default-route у карты: full — снят, soft — как до установки
  local dr=false
  [ "$1" = full ] || { dr=$(env_ DEFAULT_ROUTE "$B/before.env"); dr=${dr:-true}; }
  resolvectl default-route "$IF" "$dr"
}
current() {   # сразу после перезапуска resolved сервер ещё не выбран — сначала один запрос
  resolvectl query -t A ya.ru >/dev/null 2>&1; resolvectl status 2>/dev/null | awk '/Current DNS Server/{print $4; exit}'; }
kind() { if grep -q '^Domains=~\.' "$CONF" 2>/dev/null; then echo full; else echo soft; fi; }
if [ "${1:-}" = conf ]; then
  [ -n "$IF" ] || { echo "нет маршрута наружу — не понять сетевую карту"; exit 1; }
  install -d /etc/systemd/resolved.conf.d; write_conf "${2:-full}"; exit
fi
[ -n "$IF" ] || exit 0   # нет маршрута — проверять нечего
u=0; alive 127.0.0.1 && u=1
f=0; fb_alive && f=1
m=soft; [ "$f" = 1 ] && m=full
if [ ! -e "$CONF" ]; then
  [ -e "$OFF" ] || exit 0   # drop-in сняли не мы (откат, руками) — не вмешиваться
  if [ "$u" = 1 ]; then
    write_conf "$m" && rm -f "$OFF"
    systemctl restart systemd-resolved; sleep 1; route "$m"
    echo "$(now) Unbound снова отвечает — drop-in возвращён ($m), вернула на Unbound (сейчас $(current))" >> "$LOG"
  fi
  exit 0
fi
if [ "$u" = 0 ] && [ "$f" = 0 ]; then
  mv -f "$CONF" "$OFF"
  systemctl restart systemd-resolved; sleep 1; route soft
  echo "$(now) не отвечают ни Unbound, ни запасной ${FB:-?} — drop-in снят, DNS провайдера у $IF возвращён (сейчас $(current))" >> "$LOG"
  exit 0
fi
k=$(kind)
if [ "$k" != "$m" ]; then   # запасной ожил или умер — drop-in под это (Domains=~. только пока запасной отвечает)
  write_conf "$m"; systemctl restart systemd-resolved; sleep 1; route "$m"
  if [ "$m" = full ]; then
    echo "$(now) запасной ${FB:-?} отвечает — drop-in полный, DNS провайдера у $IF снят (сейчас $(current))" >> "$LOG"
  else
    echo "$(now) запасной ${FB:-?} не отвечает — drop-in мягкий: без Domains=~., спрашиваются и DNS карты $IF (сейчас $(current))" >> "$LOG"
  fi
elif [ "$m" = full ] && resolvectl status "$IF" 2>/dev/null | grep -q "+DefaultRoute"; then
  resolvectl default-route "$IF" false && echo "$(now) DNS сетевой карты $IF снова был маршрутом по умолчанию — выключен" >> "$LOG"
fi
cur=$(current)
if [ "$cur" != "127.0.0.1" ]; then
  if [ "$u" = 1 ]; then
    systemctl restart systemd-resolved; sleep 1; route "$m"
    echo "$(now) resolved был на ${cur:-?} — вернула на Unbound (сейчас $(current))" >> "$LOG"
  else
    echo "$(now) resolved на ${cur:-?}, Unbound не отвечает — оставлен запасной" >> "$LOG"
  fi
fi
SH
  chmod 755 "$RET"
  mode=soft; [ "$fb_ok" = 1 ] && mode=full
  "$RET" conf "$mode"
  rm -f "$ROFF"
  systemctl restart systemd-resolved; sleep 1
  if [ "$mode" = full ]; then
    resolvectl default-route "$IF" false || true
    echo "запасной DNS ($FALLBACK) отвечает — drop-in полный, DNS провайдера у $IF снят (default-route false)"
  else
    resolvectl default-route "$IF" "$(before DEFAULT_ROUTE)" || true
    echo "запасной DNS ($FALLBACK) не отвечает — drop-in мягкий: без Domains=~., DNS=127.0.0.1 $(sed -n 's/^DNS=127\.0\.0\.1 *//p' "$RCONF");" \
         "resolved спрашивает Unbound и DNS карты $IF параллельно, default-route у $IF как до установки ($(before DEFAULT_ROUTE)); таймер сделает полный, когда запасной ответит"
  fi
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
  do_status
}

do_status() {
  resolvectl query -t A ya.ru >/dev/null 2>&1 || true   # сразу после перезапуска resolved ещё не выбрал сервер
  echo "unbound: $(systemctl is-active unbound) · система спрашивает: $(resolvectl status | awk '/Current DNS Server/{print $4; exit}')" \
       "· ya.ru: rcode $(probe ya.ru) · ozon.ru: rcode $(probe ozon.ru)" \
       "· строк в журнале переключений за сутки: $(awk -v d="$(date -u -d '-24 hours' +%Y-%m-%dT%H:%M)" '$1>=d' /var/log/storozh-unbound.log 2>/dev/null | wc -l)"
  if [ -e "$ROFF" ]; then
    echo "drop-in снят таймером (не отвечали ни Unbound, ни запасной): система на DNS провайдера, вернётся сама, когда Unbound ответит"
  elif [ -e "$RCONF" ]; then
    if grep -q '^Domains=~\.' "$RCONF"; then
      echo "drop-in полный: $(grep '^DNS=.' "$RCONF"), Domains=~. — DNS провайдера не спрашивается"
    else
      echo "drop-in мягкий (запасной не отвечал): $(grep '^DNS=.' "$RCONF"), без Domains=~. — спрашиваются и DNS карты $IF"
    fi
  fi
  unbound-control stats_noreset 2>/dev/null | grep -E '^total\.num\.(queries|cachehits)=|^total\.requestlist\.exceeded=|^mem\.cache\.(rrset|message)=' | tr '\n' ' ' || true; echo
}

do_rollback() {   # каждый шаг сам по себе: ошибка одного — сообщение, остальные выполняются
  before_env || echo "откат: before.env не записан — беру значения по умолчанию"   # прежняя версия его не писала
  local was en dr mask
  was=$(before UNBOUND_WAS_ACTIVE); en=$(before UNBOUND_WAS_ENABLED); dr=$(before DEFAULT_ROUTE); mask=$(before MASKED_BY_US)
  systemctl disable --now storozh-unbound-return.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/storozh-unbound-return.{service,timer} "$RET" || echo "откат: таймер не удалён"
  systemctl daemon-reload || echo "откат: daemon-reload с ошибкой"
  rm -f "$RCONF" "$RCONF.tmp" "$ROFF" "$B/dns.env" || echo "откат: drop-in не удалён"
  # default-route и до, и после перезапуска: не встанет resolved — карта всё равно спрашивается
  if [ -n "$IF" ]; then
    resolvectl default-route "$IF" "${dr:-true}" || echo "откат: default-route до перезапуска resolved не поставлен"
  else
    echo "откат: нет маршрута IPv4 наружу — сетевую карту не понять, default-route не трогаю (верните сами: resolvectl default-route КАРТА ${dr:-true})"
  fi
  systemctl restart systemd-resolved || echo "откат: systemd-resolved не перезапустился"
  sleep 1
  if [ -n "$IF" ]; then
    resolvectl default-route "$IF" "${dr:-true}" || echo "откат: default-route после перезапуска resolved не поставлен"
  fi
  if [ -e "$UCONF" ]; then mv -f "$UCONF" "$B/storozh.conf.rolled-back" || echo "откат: storozh.conf не убран"; fi
  if [ "$mask" = yes ]; then
    systemctl unmask unbound-resolvconf.service >/dev/null 2>&1 || echo "откат: маска unbound-resolvconf не снята"
  fi
  if [ "$was" = yes ]; then   # Unbound работал до нас — оставить, только без storozh.conf
    systemctl try-restart unbound >/dev/null 2>&1 || echo "откат: Unbound не перезапустился"
  else
    systemctl stop unbound >/dev/null 2>&1 || true
  fi
  if [ "$en" != enabled ]; then   # автозапуск как был: до нас не был включён — выключить (без --now)
    systemctl disable unbound >/dev/null 2>&1 || true
  fi
  # система снова «как было»: следующая установка снимет состояние заново (снимок «до» — в сторону, не стирать)
  rm -f "$B/before.env" "$NOW"
  if [ -e "$B/resolvectl-before.txt" ]; then
    mv -f "$B/resolvectl-before.txt" "$B/resolvectl-before.txt.rolled-back-$(date +%Y%m%d-%H%M%S)" ||
      echo "откат: resolvectl-before.txt не убран — следующая установка возьмёт из него запасной по умолчанию"
  fi
  echo "откат: resolved — $(resolvectl status | awk '/DNS Servers/{print $3, $4; exit}'), unbound — $(systemctl is-active unbound)," \
       "автозапуск — $(systemctl is-enabled unbound 2>/dev/null || true)"
}

case "${1:-}" in
  install) do_install ;;
  status) do_status ;;
  rollback) do_rollback ;;
  *) echo "node_dns.sh install | status | rollback"; exit 2 ;;
esac
