#!/usr/bin/env bash
# install.sh — установка сторожа каналов (версия 11) с нуля. Ставится на сервер в РФ: каналы он проверяет «изнутри».
# Система — Ubuntu 24.04 / 26.04. Запускать из папки с файлами сторожа.
#
#   bash install.sh             мастер: спросит то, чего не хватает
#   bash install.sh --yes       без вопросов (ссылка подписки и настройки Telegram уже лежат на местах)
#   bash install.sh --xray ПУТЬ взять бинарник Xray из файла (по умолчанию копируется из контейнера remnanode)
#   bash install.sh --no-start  всё поставить, но таймеры не включать и первую проверку не запускать
#   bash install.sh --uninstall убрать сторож (сначала DDoS-часть и щиты серверов — в наблюдение; если не все
#                               щиты ответили, ключ щита остаётся; --uninstall --force — удалить и его)
#
# Что нужно заранее:
#   - служебный пользователь в панели Remnawave (создать в веб-интерфейсе: все сквады, без срока и лимита трафика)
#     и его ссылка подписки;
#   - токен Telegram-бота и номер чата, куда писать.
# Входящих портов сторож не открывает: сам ходит наружу, файрвол трогать не нужно.
# Повторный запуск безопасен: обновляет скрипты и службы, состояние и настройки не трогает; Xray заменяет, только если
# в источнике (контейнер remnanode) версия новее, а с --xray ПУТЬ — всегда.
# Службы работают в песочнице systemd: писать можно только в /etc/channel-watch, /var/lib/channel-watch, /var/log и
# папки пульса из heartbeat.path / heartbeat-full.path. Путь пульса поменяли — снова bash install.sh.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/channel-watch
TG_ENV=/etc/bridge-watch/guard.env   # отсюда сторож читает BW_TG_TOKEN и BW_TG_CHAT
yes=0 start=1 xray_src="" uninstall=0 force=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) yes=1; shift ;;
    --no-start) start=0; shift ;;
    --xray) xray_src="${2:?после --xray нужен путь к бинарнику}"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    --force) force=1; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

if [ "$uninstall" -eq 1 ]; then
  # 1) DDoS-часть первой: без /opt и /etc/channel-watch её таймеры и кнопки начали бы падать
  #    Каждую службу — по отдельности: стоит любая часть (например, только ddos и shieldbot) — убирается то, что есть
  #    (прежний ls по общему шаблону при одной недостающей службе давал ошибку, и DDoS-часть оставалась целиком).
  ddos_units=()
  for u in ddos.timer scanlists.timer behavscan.timer \
           ddos.service shieldbot.service scanlists.service behavscan.service; do
    if [ -e "/etc/systemd/system/channel-watch-$u" ] || [ -L "/etc/systemd/system/channel-watch-$u" ]; then
      ddos_units+=("channel-watch-$u")   # битая ссылка на юнит — тоже убрать
    fi
  done
  if [ "${#ddos_units[@]}" -gt 0 ]; then
    if [ -s "$SRC/install_ddos.sh" ]; then
      bash "$SRC/install_ddos.sh" --uninstall
    else
      echo "== DDoS-часть: ${ddos_units[*]}"
      for u in "${ddos_units[@]}"; do   # сначала таймеры, потом службы — таймер не перезапустит снятую службу
        systemctl disable --now "$u" 2>/dev/null || true
      done
      for u in "${ddos_units[@]}"; do rm -f "/etc/systemd/system/$u"; done
      systemctl daemon-reload
    fi
  fi
  # 2) щитам на серверах из ddos.json — наблюдение (scan-mode count, mode watch), пока есть чем: потом ключа щита не
  #    будет и переключать их станет нечем. Не все ответили — ключ щита и ddos.json остаются (без --force).
  keep_shield=0
  if [ -s "$ETC/shield_ed25519" ] && [ -s "$ETC/ddos.json" ]; then
    echo "== щиты на серверах → наблюдение:"
    if ! python3 - "$ETC" <<'PY'
import concurrent.futures, json, subprocess, sys
etc = sys.argv[1]
try:
    hs = [h for h in json.load(open(etc + "/ddos.json", encoding="utf-8")).get("hosts", [])
          if isinstance(h, dict) and h.get("name") and h.get("host")]
except (OSError, ValueError, AttributeError) as e:
    print("   ddos.json не читается: %s" % e)
    sys.exit(1)


def ctl(h, args):
    """shield-ctl на сервере — та же команда, что у кнопок щита (shieldbot.run_ctl): ключ щита, свой known_hosts."""
    cmd = ["ssh", "-i", etc + "/shield_ed25519", "-p", str(h.get("port", 22)), "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=" + etc + "/shield_known_hosts", "root@" + str(h["host"])] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = r.stdout.strip()
        return json.loads(out.splitlines()[-1]) if out else {"ok": False, "error": "нет ответа (код %d)" % r.returncode}
    except (subprocess.TimeoutExpired, ValueError, OSError, IndexError) as e:
        return {"ok": False, "error": "сервер не ответил: %s" % str(e)[:100]}


def calm(h):
    s = ctl(h, ["scan-mode", "count"])
    # щит старше 1.2 сканеров не знает — и резать по ним не может
    s_ok = s.get("ok") or any(w in str(s.get("error", "")) for w in ("не разрешена", "не понимаю"))
    m = ctl(h, ["mode", "watch"])
    if s_ok and m.get("ok"):
        return True, "наблюдение, сканеры — только счёт"
    return False, "НЕ ПЕРЕКЛЮЧЁН: " + "; ".join(str(r.get("error", "?"))[:120] for r in (s, m) if not r.get("ok"))


if not hs:
    print("   серверов в ddos.json нет")
    sys.exit(0)
with concurrent.futures.ThreadPoolExecutor(8) as ex:
    res = list(ex.map(calm, hs))
for h, (ok, text) in zip(hs, res):
    print("   %s: %s" % (h["name"], text))
sys.exit(0 if all(ok for ok, _ in res) else 1)
PY
    then
      if [ "$force" -eq 1 ]; then
        echo "внимание: не все щиты переключены, ключ щита удаляю по --force — на этих серверах переключать вручную:"
        echo "   shield-ctl mode watch; shield-ctl scan-mode count"
      else
        keep_shield=1
      fi
    fi
  fi
  # 3) сторож целиком
  systemctl disable --now channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer \
    channel-watch-loss.timer channel-watch-side.timer channel-watch-xray.service 2>/dev/null || true
  rm -rf /opt/channel-watch /var/lib/channel-watch /etc/logrotate.d/channel-watch /var/log/channel-watch.log*
  if [ "$keep_shield" -eq 1 ]; then
    find "$ETC" -mindepth 1 -maxdepth 1 ! -name shield_ed25519 ! -name shield_ed25519.pub ! -name shield_known_hosts \
      ! -name ddos.json -exec rm -rf {} +
  else
    rm -rf "$ETC"
  fi
  rm -f /etc/systemd/system/channel-watch.service /etc/systemd/system/channel-watch.timer \
        /etc/systemd/system/channel-watch-build.service /etc/systemd/system/channel-watch-build.timer \
        /etc/systemd/system/channel-watch-speed.service /etc/systemd/system/channel-watch-speed.timer \
        /etc/systemd/system/channel-watch-lists.service /etc/systemd/system/channel-watch-lists.timer \
        /etc/systemd/system/channel-watch-loss.service /etc/systemd/system/channel-watch-loss.timer \
        /etc/systemd/system/channel-watch-side.service /etc/systemd/system/channel-watch-side.timer \
        /etc/systemd/system/channel-watch-xray.service
  # drop-in песочницы от sandbox_dropins.sh — вместе со службами (только свои, по первой строке)
  for f in /etc/systemd/system/channel-watch*.service.d/50-sandbox.conf; do
    { [ -f "$f" ] && head -n 1 "$f" | grep -qF '# channel-watch: песочница systemd (sandbox_dropins.sh'; } || continue
    rm -f "$f"; rmdir "${f%/*}" 2>/dev/null || true
  done
  systemctl daemon-reload
  echo "сторож убран. Не тронуты: $TG_ENV (настройки Telegram) и служебный пользователь в панели — его удалить вручную."
  if [ "$keep_shield" -eq 1 ]; then
    echo "ВНИМАНИЕ: не все щиты переведены в наблюдение (см. выше). Ключ щита и список серверов оставлены в $ETC."
    echo "   Когда серверы будут доступны — снова bash install.sh --uninstall; удалить и ключ — --uninstall --force"
    echo "   (тогда переключать на самих серверах: shield-ctl mode watch; shield-ctl scan-mode count)."
    exit 1
  fi
  exit 0
fi

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "внимание: рассчитано на Ubuntu 24.04 / 26.04, здесь ${PRETTY_NAME:-неизвестная система}" ;;
esac
# vantage_client.py — TLS к точкам проверки с закреплённым отпечатком (blockwatch.agent_get для точек с "sha256")
for f in probe.py nodewatch.py blockwatch.py netprobe.py rucheck.py build_channels.py vantage_client.py; do
  [ -s "$SRC/$f" ] || { echo "рядом со скриптом нет $f"; exit 1; }
done
missing=""
for bin in python3 curl ping traceroute; do command -v "$bin" >/dev/null || missing="$missing $bin"; done
if [ -n "$missing" ]; then
  echo "ставлю недостающее:$missing"
  apt-get update -qq
  apt-get install -y -qq python3 curl iputils-ping traceroute
fi
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' \
  "$SRC/probe.py" "$SRC/nodewatch.py" "$SRC/blockwatch.py" "$SRC/netprobe.py" "$SRC/rucheck.py" "$SRC/build_channels.py" \
  "$SRC/vantage_client.py"

# --- ссылка подписки служебного пользователя ---
install -d -m 700 "$ETC"
if [ ! -s "$ETC/sub.url" ]; then
  [ "$yes" -eq 0 ] || { echo "нет $ETC/sub.url (ссылка подписки служебного пользователя) — положите её туда или запустите без --yes"; exit 1; }
  read -r -s -p "Ссылка подписки служебного пользователя (не показывается): " sub; echo
  case "$sub" in https://*) ;; *) echo "ссылка должна начинаться с https://"; exit 1 ;; esac
  ( umask 077; printf '%s\n' "$sub" > "$ETC/sub.url" )
fi
chmod 600 "$ETC/sub.url"

# --- Telegram ---
need_token=0 need_chat=0
grep -qs '^BW_TG_TOKEN=' "$TG_ENV" || need_token=1
grep -qs '^BW_TG_CHAT=' "$TG_ENV" || need_chat=1
if [ "$need_token$need_chat" != 00 ]; then   # спрашивается и дописывается только недостающее
  [ "$yes" -eq 0 ] || { echo "в $TG_ENV нет BW_TG_TOKEN / BW_TG_CHAT — впишите или запустите без --yes"; exit 1; }
  token="" chat=""
  if [ "$need_token" -eq 1 ]; then
    read -r -s -p "Токен Telegram-бота (не показывается): " token; echo
    [ -n "$token" ] || { echo "нужен токен"; exit 1; }
  fi
  if [ "$need_chat" -eq 1 ]; then
    read -r -p "Номер чата Telegram, куда писать: " chat
    [ -n "$chat" ] || { echo "нужен номер чата"; exit 1; }
  fi
  install -d -m 700 "$(dirname "$TG_ENV")"
  ( umask 077
    # файл без перевода строки в конце: новая строка иначе склеится с последней
    [ ! -s "$TG_ENV" ] || [ -z "$(tail -c 1 "$TG_ENV")" ] || echo >> "$TG_ENV"
    [ "$need_token" -eq 0 ] || printf 'BW_TG_TOKEN=%s\n' "$token" >> "$TG_ENV"
    [ "$need_chat" -eq 0 ] || printf 'BW_TG_CHAT=%s\n' "$chat" >> "$TG_ENV" )
fi
chmod 600 "$TG_ENV"

# --- файлы ---
install -d -m 755 /opt/channel-watch /var/lib/channel-watch
# кнопки щита (shieldbot, из install_ddos.sh) шлют в Telegram через probe.py: новый probe.py — перезапустить их
probe_changed=0; cmp -s "$SRC/probe.py" /opt/channel-watch/probe.py || probe_changed=1
install -m 755 "$SRC/probe.py" "$SRC/nodewatch.py" "$SRC/blockwatch.py" "$SRC/netprobe.py" "$SRC/rucheck.py" "$SRC/build_channels.py" /opt/channel-watch/
install -m 644 "$SRC/vantage_client.py" /opt/channel-watch/
# байт-код заранее: в песочнице /opt только для чтения, без него каждый запуск компилировал бы заново
python3 -m compileall -q /opt/channel-watch >/dev/null 2>&1 || true

if [ "$probe_changed" -eq 1 ]; then systemctl try-restart channel-watch-shieldbot.service 2>/dev/null || true; fi

# клиент Xray: тот же бинарник, что у ноды (ничего не скачиваем), либо указанный файл. Уже стоит — заменяется, только
# если в контейнере версия новее; --xray ПУТЬ — всегда (файл указан явно). Замена через mv: работающий Xray не мешает.
xver() { "$1" version 2>/dev/null | awk 'NR==1{print $2}'; }
newer() { [ -n "$1" ] && [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]; }
xray_new=0 cand="" tmpx=""
if [ -n "$xray_src" ]; then
  cand="$xray_src"
else
  tmpx="$(mktemp /opt/channel-watch/.xray-XXXXXX)"
  if docker cp remnanode:/usr/local/bin/xray "$tmpx" 2>/dev/null; then chmod 755 "$tmpx"; cand="$tmpx"; fi
fi
if [ -z "$cand" ]; then
  rm -f "$tmpx"
  [ -x /opt/channel-watch/xray ] || { echo "не нашёл Xray: контейнера remnanode нет. Укажите бинарник: bash install.sh --xray /путь/к/xray"; exit 1; }
  echo "xray: контейнера remnanode нет — оставлен прежний"
elif [ -n "$xray_src" ] || [ ! -x /opt/channel-watch/xray ] || newer "$(xver "$cand")" "$(xver /opt/channel-watch/xray)"; then
  [ ! -x /opt/channel-watch/xray ] || echo "xray: $(xver /opt/channel-watch/xray) → $(xver "$cand")"
  install -m 755 "$cand" /opt/channel-watch/.xray.new
  mv -f /opt/channel-watch/.xray.new /opt/channel-watch/xray
  xray_new=1
fi
rm -f "$tmpx"
echo "xray: $(/opt/channel-watch/xray version | head -n 1)"

# --- каналы из подписки ---
rc=0; python3 /opt/channel-watch/build_channels.py || rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 10 ] || { echo "список каналов из подписки не собрался (rc=$rc): проверьте ссылку в $ETC/sub.url"; exit 1; }
/opt/channel-watch/xray run -test -c "$ETC/xray.json" | tail -n 1

# --- службы ---
# Песочница Python-служб (дописывается в конец [Service]). Они остаются от root: читают sub.url и guard.env (600 root),
# ходят в docker (rucheck: docker exec remnanode), трассируют TCP SYN (traceroute -T, нужен raw-сокет), а их файлы
# в /etc и /var/lib/channel-watch делят со службами DDoS-части, которые тоже от root. Зато писать можно только в свои
# папки, /var/log (журнал и его ротация) и папки пульса; /home и /root только для чтения (свой docker context); /run
# тоже (ProtectSystem=strict его не закрывает), сокеты docker и D-Bus при этом работают. Те же настройки на работающем
# стороже без переустановки кладёт sandbox_dropins.sh.
hb_rw=""
for f in "$ETC/heartbeat.path" "$ETC/heartbeat-full.path"; do
  [ -s "$f" ] || continue
  d="$(dirname "$(head -n 1 "$f")")"
  case "$d" in
    *[[:space:]]*|*%*|*\"*|*\'*|*'\'*|[!/]*) echo "внимание: путь пульса в $f не абсолютный или с пробелом, %, кавычкой, \\ — песочница запись туда не пустит" ;;
    *) hb_rw="$hb_rw -$d" ;;
  esac
done
py_sandbox() {   # $1 — дополнительные папки для записи
  cat <<EOF
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log${1:-}
ReadOnlyPaths=/run
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
EOF
}
xray_unit_was="$(cat /etc/systemd/system/channel-watch-xray.service 2>/dev/null || true)"
# Xray — от временного пользователя (DynamicUser) без полномочий: xray.json (600 root) ему отдаёт systemd копией
# (LoadCredential). systemd старше 250 (не Ubuntu 24.04+) — по-старому, от root, но с той же песочницей.
if [ "$(systemctl --version | awk 'NR==1{print $2+0}')" -ge 250 ]; then
  xexec='/opt/channel-watch/xray run -c ${CREDENTIALS_DIRECTORY}/xray.json'
  xuser='LoadCredential=xray.json:/etc/channel-watch/xray.json
DynamicUser=yes
CapabilityBoundingSet=
AmbientCapabilities='
else
  xexec='/opt/channel-watch/xray run -c /etc/channel-watch/xray.json'
  xuser='CapabilityBoundingSet='
fi
cat > /etc/systemd/system/channel-watch-xray.service <<UNIT
[Unit]
Description=channel-watch: клиент Xray для проверки каналов (SOCKS 127.0.0.1:21000-21099)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$xexec
$xuser
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
Restart=always
RestartSec=5
Nice=10
MemoryMax=96M

[Install]
WantedBy=multi-user.target
UNIT
# sockopt.mark (SO_MARK) требует CAP_NET_ADMIN — у Xray в песочнице его нет, такой канал не соединится
if grep -q '"mark"' "$ETC/xray.json" 2>/dev/null; then
  echo "внимание: в $ETC/xray.json есть sockopt.mark — Xray в песочнице его поставить не сможет, канал будет недоступен"
fi

cat > /etc/systemd/system/channel-watch.service <<'UNIT'
[Unit]
Description=channel-watch: проверка каналов VPN (оповещения в Telegram)
After=channel-watch-xray.service
Requires=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py
Nice=10
TimeoutStartSec=110
UNIT
py_sandbox "$hb_rw" >> /etc/systemd/system/channel-watch.service

cat > /etc/systemd/system/channel-watch.timer <<'UNIT'
[Unit]
Description=channel-watch: каждые 2 минуты

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
AccuracySec=10s

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-build.service <<'UNIT'
[Unit]
Description=channel-watch: пересборка списка каналов из подписки

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'rc=0; /usr/bin/python3 /opt/channel-watch/build_channels.py || rc=$?; [ "$rc" -eq 10 ] && systemctl restart channel-watch-xray.service; [ "$rc" -eq 0 ] || [ "$rc" -eq 10 ]'
UNIT
py_sandbox >> /etc/systemd/system/channel-watch-build.service

cat > /etc/systemd/system/channel-watch-build.timer <<'UNIT'
[Unit]
Description=channel-watch: пересборка каналов и проверка подписки — за 10 минут до каждого отчёта

[Timer]
OnCalendar=*-*-* 05,11,17:50:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-speed.service <<'UNIT'
[Unit]
Description=channel-watch: закачка 10 МБ через каждый канал (скорость для отчёта)
After=channel-watch-xray.service
Requires=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --speed
Nice=10
TimeoutStartSec=600
UNIT
py_sandbox >> /etc/systemd/system/channel-watch-speed.service

cat > /etc/systemd/system/channel-watch-speed.timer <<'UNIT'
[Unit]
Description=channel-watch: закачка побольше — за 5 минут до каждого отчёта

[Timer]
OnCalendar=*-*-* 05,11,17:55:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-lists.service <<'UNIT'
[Unit]
Description=channel-watch: сверка наших адресов и доменов со списками блокировок
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --lists
Nice=15
MemoryMax=256M
TimeoutStartSec=900
UNIT
py_sandbox >> /etc/systemd/system/channel-watch-lists.service

cat > /etc/systemd/system/channel-watch-lists.timer <<'UNIT'
[Unit]
Description=channel-watch: списки блокировок — раз в 6 часов

[Timer]
OnCalendar=*-*-* 02,08,14,20:40:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-loss.service <<'UNIT'
[Unit]
Description=channel-watch: фоновый замер потерь соединений с российских точек до входов нод
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --loss
Nice=15
MemoryMax=128M
TimeoutStartSec=600
UNIT
py_sandbox >> /etc/systemd/system/channel-watch-loss.service

cat > /etc/systemd/system/channel-watch-loss.timer <<'UNIT'
[Unit]
Description=channel-watch: замер потерь с точек — раз в час

[Timer]
OnCalendar=*-*-* *:25:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/channel-watch-side.service <<'UNIT'
[Unit]
Description=channel-watch: профиль точек проверки и гео адресов нод (долгие сборы вне основного прохода)
After=channel-watch-xray.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/probe.py --side
Nice=15
MemoryMax=256M
TimeoutStartSec=1200
UNIT
py_sandbox >> /etc/systemd/system/channel-watch-side.service

cat > /etc/systemd/system/channel-watch-side.timer <<'UNIT'
[Unit]
Description=channel-watch: профиль точек и гео нод — проверка сроков раз в час

[Timer]
OnCalendar=*-*-* *:45:00 UTC
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat > /etc/logrotate.d/channel-watch <<'ROT'
/var/log/channel-watch.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
ROT

systemctl daemon-reload
# новый бинарник или юнит Xray (песочница) — перезапустить работающий; остальные службы — oneshot, новое со следующего запуска
if [ "$xray_new" -eq 1 ] || [ "$xray_unit_was" != "$(cat /etc/systemd/system/channel-watch-xray.service)" ]; then
  systemctl try-restart channel-watch-xray.service 2>/dev/null || true
fi
if [ "$start" -eq 0 ]; then
  echo "== поставлено без запуска. Включить: systemctl enable --now channel-watch-xray.service channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer channel-watch-loss.timer channel-watch-side.timer"
  exit 0
fi
systemctl enable --now channel-watch-xray.service >/dev/null 2>&1
sleep 2
systemctl enable --now channel-watch.timer channel-watch-build.timer channel-watch-speed.timer channel-watch-lists.timer \
  channel-watch-loss.timer channel-watch-side.timer >/dev/null 2>&1

# --- самопроверка: первый запуск (он же шлёт первый отчёт в Telegram) ---
echo "== самопроверка: первый запуск"
rc=0; systemctl start channel-watch.service || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "первый запуск завершился с ошибкой:"; journalctl -u channel-watch.service -n 20 --no-pager; exit 1
fi
python3 /opt/channel-watch/probe.py --show | sed -n '1,14p'
echo
echo "== готово: клиент Xray $(systemctl is-active channel-watch-xray.service), таймер $(systemctl is-active channel-watch.timer)"
echo "   отправка в Telegram: $(grep -c 'отправлен в Telegram' /var/log/channel-watch.log 2>/dev/null || echo 0) сообщений в журнале — проверьте, что отчёт пришёл"
echo "   дальше по желанию: маячки и свидетель на нодах (beacon_install.sh, witness_install.sh), сторож за сторожем
   (guard_install.sh), точки проверки (vantage_install.sh); DDoS, щит и сканеры — install_ddos.sh. См. README.md"
