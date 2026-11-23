#!/usr/bin/env bash
# beacon_install.sh --site-dir ПАПКА | --serve ПОРТ --allow АДРЕС [--tls-only] [--home-ro] | --uninstall
# Маячок состояния ноды для сторожа каналов (в недельную сводку — диск, память,
# версии; счётчик сканирования). Рядом должен лежать node_beacon.py. Раз в 10 минут пишет небольшой JSON без секретов.
#   --site-dir ПАПКА        нода со своим сайтом-прикрытием: файл со случайным именем кладётся в папку сайта, сторож
#                           забирает его по https; портов и настроек веб-сервера не трогает;
#   --serve ПОРТ --allow IP нода без своего сайта: файл отдаёт крошечный веб-сервер beacon_serve.py на ПОРТу (от
#                           пользователя nobody, рядом должен лежать beacon_serve.py), в ufw порт открыт только адресу
#                           сторожа (IP). ufw выключен — правило не ставится, порт открыт всем (установщик об этом пишет).
#                           На том же порту и HTTP, и TLS: сертификат самоподписанный, создаётся при первой
#                           установке и потом не меняется; его отпечаток печатается строкой «BEACON-SHA256 <отпечаток>».
#                           Порядок перехода без простоя: обновить ноду этим установщиком (путь и порт прежние, сторож
#                           ходит по HTTP как раньше) → у ноды в /etc/channel-watch/nodes.json сторожа добавить
#                           "sha256": "<отпечаток>" — сторож перейдёт на TLS и будет сверять сертификат.
#                           Сам сервер тоже отвечает только адресу сторожа (--allow), а также 127.0.0.1 и адресу самой
#                           ноды; чужие соединения закрывает сразу, места не занимают — и при выключенном ufw.
#   --tls-only              вместе с --serve: HTTP закрыт, только TLS. Включать последним шагом, когда у ноды в
#                           nodes.json уже есть "sha256" и сторож с новым nodewatch.py и blockwatch.py забирает по TLS
#                           и маячок, и flows.json свидетеля. Без сертификата (нет openssl или systemd старше 247)
#                           установщик с --tls-only сервер и юнит не трогает и выходит с ошибкой. Повтор без ключа —
#                           снова HTTP и TLS.
#   --home-ro               ProtectHome=read-only вместо yes: на ноде со своим docker context в
#                           /root/.docker — иначе docker CLI его не видит и поля xray, mptcp_listeners_ct будут None.
# Повторный запуск с другим режимом, папкой, --allow или --port убирает прежний файл, веб-сервер и правило ufw.
# В конце печатает строку «BEACON <хвост адреса>» — её забирает сторож; в режиме --serve перед ней — «BEACON-SHA256 …».
# Откат: bash beacon_install.sh --uninstall
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "нужен root (sudo bash $0 …)"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/node-beacon
WWW=/var/lib/node-beacon/www
mode="" dir="" port="" allow="" home_ro=0 fp="" tls_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --site-dir) mode=site; dir="$2"; shift 2 ;;
    --serve) mode=serve; port="$2"; shift 2 ;;
    --allow) allow="$2"; shift 2 ;;
    --uninstall) mode=uninstall; shift ;;
    --home-ro) home_ro=1; shift ;;
    --tls-only) tls_only=1; shift ;;
    *) echo "не понимаю параметр $1"; exit 2 ;;
  esac
done

# правило ufw из файла: словами, без раскрытия шаблонов и без sh -c
ufw_delete_saved() {
  [ -s "$ETC/ufw-rule" ] && command -v ufw >/dev/null || return 0
  local r
  read -ra r < "$ETC/ufw-rule"
  [ "${r[0]:-}" = allow ] && ufw delete "${r[@]}" >/dev/null 2>&1 || true
}
# прежний файл маячка и его временные файлы
rm_out() {
  [ -n "${1:-}" ] || return 0
  rm -f -- "$1" "$1.tmp" "$(dirname "$1")"/.beacon-*.tmp
}

if [ "$mode" = uninstall ]; then
  systemctl disable --now node-beacon.timer node-beacon-http.service 2>/dev/null || true
  systemctl stop node-beacon.service 2>/dev/null || true
  if [ -s "$ETC/out" ]; then
    out="$(cat "$ETC/out")"
    # .beacon-*.tmp — временные файлы маячка, если его прервали между записью и переименованием
    rm -f -- "$out" "$out.tmp" "$(dirname "$out")"/.beacon-*.tmp
  fi
  ufw_delete_saved
  rm -rf /opt/node-beacon "$ETC" /var/lib/node-beacon
  rm -f /etc/systemd/system/node-beacon.service /etc/systemd/system/node-beacon.timer /etc/systemd/system/node-beacon-http.service \
        /usr/local/sbin/node-beacon-run
  systemctl daemon-reload
  # память о прежних сбоях юнитов: без неё systemctl --failed ещё показывал бы убранный маячок
  systemctl reset-failed node-beacon.timer node-beacon.service node-beacon-http.service 2>/dev/null || true
  echo "маячок убран"; exit 0
fi

[ "$tls_only" = 0 ] || [ "$mode" = serve ] || { echo "--tls-only — только вместе с --serve"; exit 2; }
[ -s "$SRC/node_beacon.py" ] || { echo "рядом нет node_beacon.py"; exit 1; }
# до любых изменений: без сервера маячка прежняя установка остаётся как есть
[ "$mode" != serve ] || [ -s "$SRC/beacon_serve.py" ] || { echo "рядом нет beacon_serve.py (нужен для --serve)"; exit 1; }
install -d -m 755 /opt/node-beacon
install -d -m 700 "$ETC"
install -m 755 "$SRC/node_beacon.py" /opt/node-beacon/node_beacon.py
prev=""; [ ! -s "$ETC/out" ] || prev="$(cat "$ETC/out")"

if [ "$mode" = site ]; then
  [ -d "$dir" ] || { echo "нет папки сайта $dir"; exit 1; }
  dir="$(cd "$dir" && pwd -P)"   # абсолютный путь: он же пойдёт в ReadWritePaths юнита
  case "$(basename "$prev")" in   # то же случайное имя — адрес файла у сторожа не меняется
    st-*.json) name="$(basename "$prev")" ;;
    *) name="st-$(openssl rand -hex 12).json" ;;
  esac
  echo "$dir/$name" > "$ETC/out"
  tail="/$name"
  # был режим --serve: веб-сервер маячка и его правило ufw больше не нужны
  if [ -f /etc/systemd/system/node-beacon-http.service ]; then
    systemctl disable --now node-beacon-http.service 2>/dev/null || true
    rm -f /etc/systemd/system/node-beacon-http.service
    systemctl reset-failed node-beacon-http.service 2>/dev/null || true
  fi
  ufw_delete_saved; rm -f "$ETC/ufw-rule"
  rm -f "$ETC/cert.pem" "$ETC/key.pem" /opt/node-beacon/beacon_serve.py   # сертификат был только для --serve
elif [ "$mode" = serve ]; then
  [ -n "$port" ] && [ -n "$allow" ] || { echo "нужны --serve ПОРТ и --allow АДРЕС"; exit 1; }
  case "$port" in ''|*[!0-9]*) echo "порт — только цифры: $port"; exit 1 ;; esac
  port=$((10#$port))
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "порт вне 1-65535: $port"; exit 1; }
  # адрес или сеть сторожа: без «%» (зона IPv6), пробелов и прочего, что ufw поймёт не так; /0 — открыть всем — нельзя
  python3 -c '
import ipaddress, re, sys
a = sys.argv[1]
if not re.fullmatch(r"[0-9A-Fa-f.:]{2,45}(/[0-9]{1,3})?", a):
    sys.exit(1)
n = ipaddress.ip_network(a, strict=False)
sys.exit(1 if n.prefixlen == 0 else 0)
' "$allow" 2>/dev/null || { echo "«$allow» — не адрес (нужен IP или сеть без зоны «%» и пробелов, не /0)"; exit 1; }
  # сертификат TLS: самоподписанный, создаётся один раз — при обновлении отпечаток у сторожа остаётся верным
  if [ ! -s "$ETC/cert.pem" ] || [ ! -s "$ETC/key.pem" ]; then
    command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq openssl; } >/dev/null 2>&1 || true
    if ( umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
           -subj "/CN=localhost" -keyout "$ETC/key.pem.tmp" -out "$ETC/cert.pem.tmp" ) >/dev/null 2>&1; then
      mv -f "$ETC/key.pem.tmp" "$ETC/key.pem"; mv -f "$ETC/cert.pem.tmp" "$ETC/cert.pem"
    fi
    rm -f "$ETC/key.pem.tmp" "$ETC/cert.pem.tmp"
  fi
  # ключ читает только root; службе от nobody его передаёт systemd (LoadCredential, systemd 247+). Иначе — только HTTP
  creds="" fp=""
  sdv="$(systemctl --version 2>/dev/null | awk 'NR==1{print $2+0}')"
  if [ -s "$ETC/cert.pem" ] && [ -s "$ETC/key.pem" ] && [ "${sdv:-0}" -ge 247 ]; then
    chmod 600 "$ETC/key.pem"; chmod 644 "$ETC/cert.pem"; chown root:root "$ETC/key.pem" "$ETC/cert.pem"
    creds="LoadCredential=cert.pem:$ETC/cert.pem
LoadCredential=key.pem:$ETC/key.pem"
    fp="$(python3 -c 'import hashlib, ssl, sys; print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1], encoding="ascii").read())).hexdigest())' "$ETC/cert.pem")"
  fi
  # --tls-only без сертификата — служба бы не запустилась: выходим до записи out, сервера и юнита (прежнее цело)
  [ "$tls_only" = 0 ] || [ -n "$fp" ] || {
    echo "--tls-only: сертификата нет (openssl не поставился или systemd старше 247) — сервер маячка и юнит прежние"; exit 1; }
  tls_arg=""; [ "$tls_only" = 0 ] || tls_arg=" --tls-only"
  install -d -m 755 /var/lib/node-beacon "$WWW"
  echo "$WWW/state.json" > "$ETC/out"
  install -m 755 "$SRC/beacon_serve.py" /opt/node-beacon/beacon_serve.py
  # порт ниже 1024 пользователь nobody занять не может — только это право, остальные убраны
  caps=""; [ "$port" -ge 1024 ] || caps="CAP_NET_BIND_SERVICE"
  cat > /etc/systemd/system/node-beacon-http.service <<UNIT
[Unit]
Description=node-beacon: отдаёт файл состояния ноды сторожу каналов (порт $port открыт в ufw только его адресу)
After=network-online.target

[Service]
# --allow: чужие адреса сервер закрывает сразу после accept (и при выключенном ufw), места они не занимают
ExecStart=/usr/bin/python3 /opt/node-beacon/beacon_serve.py $port $WWW --allow $allow$tls_arg
User=nobody
Group=nogroup
$creds
CapabilityBoundingSet=$caps
AmbientCapabilities=$caps
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=64M
SyslogLevel=warning
LogLevelMax=warning
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  rule="allow from $allow to any port $port proto tcp"
  fw="ufw не включён — порт $port открыт всем, но сервер маячка отвечает только $allow (прочих закрывает сразу); лучше закройте порт и своим файрволом"
  if command -v ufw >/dev/null; then
    # прежнее правило (другой адрес сторожа или порт) — убрать, иначе оно останется навсегда
    if [ -s "$ETC/ufw-rule" ] && [ "$(cat "$ETC/ufw-rule")" != "$rule" ]; then ufw_delete_saved; rm -f "$ETC/ufw-rule"; fi
    if [ "$(LC_ALL=C ufw status | awk 'NR==1{print $2}')" = active ]; then
      echo "$rule" > "$ETC/ufw-rule"
      read -ra r <<< "$rule"
      ufw "${r[@]}" comment 'node-beacon: watchdog only' >/dev/null
      fw="в ufw порт $port открыт только для $allow"
    fi
  fi
  tail=":$port/state.json"
else
  echo "укажите --site-dir или --serve"; exit 2
fi
# файл маячка переехал (другой режим или папка) — прежний убрать
moved=0
if [ -n "$prev" ] && [ "$prev" != "$(cat "$ETC/out")" ]; then
  rm_out "$prev"; moved=1
fi
if [ "$mode" = site ]; then rmdir "$WWW" /var/lib/node-beacon 2>/dev/null || true; fi   # пустые после --serve

# песочница юнита маячка: писать можно только в папку выходного файла. Работает от root — нужно для iptables,
# ufw status, ss, unbound-control, docker и nsenter (nsenter требует CAP_SYS_ADMIN, поэтому CapabilityBoundingSet не
# сужаем). ProtectKernelModules не ставим: первый ss -M просит ядро подгрузить mptcp_diag. ProtectKernelTunables
# оставляет /proc/sys и /sys для чтения — маячок их только читает. Замки ufw и iptables (legacy) в /run создаются до
# запуска («+» — вне песочницы) и открыты на запись по одному файлу, остальной /run только для чтения.
outdir="$(dirname "$(cat "$ETC/out")")"
case "$outdir" in
  /*) ;;
  *) echo "путь выходного файла должен быть абсолютным: $outdir"; exit 1 ;;
esac
case "$outdir" in
  *[[:space:]]*|*%*|*\"*|*\'*|*'\'*) echo "в пути папки $outdir пробел или %, \", ', \\ — укажите другую папку"; exit 1 ;;
esac
if [ "$mode" = serve ]; then rw=/var/lib/node-beacon; else rw="$outdir"; fi
case "$outdir" in   # папка сайта в /home или /root: ProtectHome=yes спрятал бы её целиком
  /home/*|/root/*|/run/user/*) ph=read-only ;;
  *) ph=yes ;;
esac
[ "$home_ro" = 0 ] || ph=read-only   # --home-ro: свой docker context в /root/.docker
cat > /etc/systemd/system/node-beacon.service <<UNIT
[Unit]
Description=node-beacon: записать состояние ноды для сторожа каналов

[Service]
Type=oneshot
ExecStartPre=+/usr/bin/touch /run/ufw.lock /run/xtables.lock
ExecStart=/usr/local/sbin/node-beacon-run
Nice=10
TimeoutStartSec=120
# сообщения в stderr (трассировки) — уровнем warning, иначе LogLevelMax их отбросит
SyslogLevel=warning
LogLevelMax=warning
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$rw -/run/ufw.lock -/run/xtables.lock
ProtectHome=$ph
PrivateTmp=yes
ProtectKernelTunables=yes
RestrictSUIDSGID=yes
LockPersonality=yes
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
if [ "$mode" = serve ]; then
  systemctl enable node-beacon-http.service >/dev/null 2>&1
  systemctl restart node-beacon-http.service   # новый порт — сразу
fi
systemctl enable --now node-beacon.timer >/dev/null 2>&1
systemctl start node-beacon.service
out="$(cat "$ETC/out")"
[ -s "$out" ] || { echo "маячок не записал файл $out"; journalctl -u node-beacon.service -n 8 --no-pager; exit 1; }
python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); print("   " + sys.argv[2] + ": диск", str(d["disk_pct"]) + "%, свободно памяти", d["mem_avail_mb"], "МБ, Xray", d["xray"], "| ufw", d["ufw"], "| отбито:", d["drops"], "| ssh-подбор за сутки:", d["ssh_fail_24h"])' "$out" "$(hostname)" >&2
if [ "$mode" = serve ]; then
  echo "   $fw" >&2
  # самопроверка с самой ноды: HTTP (прежний сторож) и TLS со сверкой отпечатка (новый)
  chk="$(python3 /opt/node-beacon/beacon_serve.py --check "$port" $fp$tls_arg 2>&1)" || {
    echo "   веб-сервер маячка не отвечает как надо ($chk): journalctl -u node-beacon-http -n 20" >&2; exit 1; }
  if [ "$tls_only" = 1 ]; then
    echo "   на порту $port только TLS, HTTP закрыт ($chk). У ноды в nodes.json сторожа должно быть \"sha256\": \"$fp\" — без него сторож маячок не прочитает" >&2
  elif [ -n "$fp" ]; then
    echo "   на порту $port и HTTP, и TLS ($chk). У ноды в nodes.json сторожа добавьте \"sha256\": \"$fp\" — сторож перейдёт на TLS" >&2
  else
    echo "   сертификата нет (openssl или systemd старше 247) — только HTTP ($chk)" >&2
  fi
fi
if [ "$moved" = 1 ] && [ -s /etc/node-witness/out ]; then
  echo "   свидетель пишет в прежнюю папку — запустите witness_install.sh ещё раз" >&2
fi
if [ "$mode" = serve ] && [ -n "$fp" ]; then echo "BEACON-SHA256 $fp"; fi
echo "BEACON $tail"
