#!/usr/bin/env bash
# sandbox_dropins.sh — песочница systemd для служб сторожа на уже работающем сервере.
# install.sh пишет песочницу прямо в юниты, но на работающем стороже её дала бы только полная переустановка. Этот скрипт
# кладёт те же настройки отдельными файлами /etc/systemd/system/<служба>.service.d/50-sandbox.conf: юниты, скрипты,
# состояние и настройки не трогаются, откат — удалить эти файлы.
#
#   bash sandbox_dropins.sh                     положить drop-in, daemon-reload, пробный запуск каждой службы;
#                                               хоть одна не прошла — все drop-in убираются (как было), код 1
#   bash sandbox_dropins.sh --skip-test UNIT[,UNIT]  не запускать пробно эти службы (можно коротко: side,lists)
#   bash sandbox_dropins.sh --no-test           без пробного запуска разовых служб (Xray и кнопки щита перезапускаются
#                                               и проверяются всегда: песочница у них — только с перезапуска)
#   bash sandbox_dropins.sh --dry               показать, какие службы и с какими настройками, ничего не менять
#   bash sandbox_dropins.sh --rollback          убрать drop-in этого скрипта, daemon-reload, перезапустить Xray и кнопки щита
#
# Пробный запуск — обычный проход службы (тот же, что по таймеру): главная проверка может прислать тревогу, если она
# назрела; --speed качает по 10 МБ через каналы; --lists и --side идут до 15–20 минут. Служба, которая падала и до
# песочницы (Result до запуска показан в отчёте), откатит всё — её можно исключить --skip-test и разобрать отдельно.
# Повторный запуск безопасен: файлы перезаписываются. Путь пульса (heartbeat.path / heartbeat-full.path) поменяли —
# запустить снова, иначе probe.py не сможет писать пульс в новую папку.
#
# Что ужесточается — см. py_sandbox и xray_sandbox ниже; почему Python-службы остаются от root — там же.
set -euo pipefail
UNIT_DIR="${CW_UNIT_DIR:-/etc/systemd/system}"   # CW_* — только для тестов
ETC="${CW_ETC:-/etc/channel-watch}"
SYSTEMCTL="${CW_SYSTEMCTL:-systemctl}"
JOURNALCTL="${CW_JOURNALCTL:-journalctl}"
PAUSE="${CW_PAUSE:-3}"            # секунд между проверками долгоживущих служб после перезапуска
DROPIN=50-sandbox.conf
MARK="# channel-watch: песочница systemd (sandbox_dropins.sh)"

# службы сторожа и их вид. Список install.sh (Xray и шесть разовых) и DDoS-часть с тем же сервером и теми же папками:
# ключи ssh и known_hosts у ddoswatch, shieldbot, scanlists лежат в /etc/channel-watch,
# состояние — в /var/lib/channel-watch. Чужие channel-watch-*.service (guard — на другом сервере, свои папки) пропускаются.
XRAY=channel-watch-xray.service
LONG_PY="channel-watch-shieldbot.service"
ONESHOT="channel-watch-build.service channel-watch.service channel-watch-speed.service channel-watch-lists.service
channel-watch-loss.service channel-watch-side.service channel-watch-ddos.service channel-watch-scanlists.service
channel-watch-behavscan.service"
HB_UNIT=channel-watch.service     # пульс пишет только главная проверка (как в install.sh)

mode=apply test=1 skip=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) mode=rollback; shift ;;
    --dry) mode=dry; shift ;;
    --no-test) test=0; shift ;;
    --skip-test) skip="$skip,${2:?после --skip-test нужен список служб}"; shift 2 ;;
    -h|--help) awk 'NR > 1 && /^#/ {sub(/^# ?/, ""); print; next} NR > 1 {exit}' "$0"; exit 0 ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ -n "${CW_UNIT_DIR:-}" ] || [ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

skipped() {   # $1 — служба; в --skip-test можно полностью, без .service и без channel-watch- (lists, side, …)
  local b="${1%.service}"
  case ",$skip," in *",$1,"*|*",$b,"*|*",${b#channel-watch-},"*) return 0 ;; esac
  return 1
}

# --- что пишется ---
# Python-службы: тот же набор, что py_sandbox в install.sh (сверяет test_sandbox.py). Пишут только в свои
# папки, /var/log (журнал и его ротация) и папки пульса; /usr, /boot, /etc (кроме своей), /opt — только чтение; /home и
# /root — только чтение (docker context, ~/.ssh/config); свой /tmp; ядро (sysctl, модули, cgroup) не меняют; новые
# полномочия (setuid) не получают и setuid-файлы не создают.
# От root остаются, потому что: читают sub.url и /etc/bridge-watch/guard.env (600 root); ходят в docker (rucheck:
# docker exec remnanode — это и так равно root); traceroute -T и ping нужны raw-сокеты; ssh-ключи серверов (600 root) в
# /etc/channel-watch; файлы в /etc и /var/lib/channel-watch общие у всех служб; channel-watch-build перезапускает Xray
# через systemctl. /run только для чтения (ProtectSystem=strict его не закрывает): сокеты docker и D-Bus от этого
# работают — connect не пишет в файловую систему; папка пульса внутри /run осталась бы доступной на запись.
# Граница не жёсткая: процесс от root с сокетом docker и D-Bus при желании выйдет из песочницы (docker run, systemd-run).
# Она закрывает другое — ошибку в коде или в пути, которая писала бы мимо своих папок, в /usr, /opt, /etc, ядро. /dev/shm
# остаётся на запись: PrivateDevices у Python-служб нет ни в install.sh, ни здесь (на стенде проверено без него).
hb_rw() {
  local f d out=""
  for f in "$ETC/heartbeat.path" "$ETC/heartbeat-full.path"; do
    [ -s "$f" ] || continue
    d="$(dirname "$(head -n 1 "$f")")"
    case "$d" in
      *[[:space:]]*|*%*|*\"*|*\'*|*'\'*|[!/]*)
        echo "внимание: путь пульса в $f не абсолютный или с пробелом, %, кавычкой, \\ — песочница запись туда не пустит" >&2 ;;
      *) case " $out " in *" -$d "*) ;; *) out="$out -$d" ;; esac ;;
    esac
  done
  printf '%s' "$out"
}
py_sandbox() {   # $1 — дополнительные папки для записи (с «-»: нет папки — не ошибка)
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
# Xray: как в install.sh — от временного пользователя (DynamicUser) без полномочий, xray.json (600 root) systemd отдаёт ему
# копией (LoadCredential); писать никуда не может, /home и /root не видит, сокеты только IP, UNIX и netlink.
# systemd старше 250 — от root, но с той же песочницей и без полномочий (CapabilityBoundingSet пустой).
xray_sandbox() {
  local v
  v="$("$SYSTEMCTL" --version | awk 'NR==1{print $2+0}')"
  if [ "${v:-0}" -ge 250 ]; then
    cat <<'EOF'
ExecStart=
ExecStart=/opt/channel-watch/xray run -c ${CREDENTIALS_DIRECTORY}/xray.json
LoadCredential=xray.json:/etc/channel-watch/xray.json
DynamicUser=yes
CapabilityBoundingSet=
AmbientCapabilities=
EOF
  else
    echo 'CapabilityBoundingSet='
  fi
  cat <<'EOF'
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
EOF
}
dropin_text() {   # $1 — служба
  echo "$MARK"
  echo "# Убрать: bash sandbox_dropins.sh --rollback (или удалить этот файл и systemctl daemon-reload)."
  echo "[Service]"
  case "$1" in
    "$XRAY") xray_sandbox ;;
    "$HB_UNIT") py_sandbox "$(hb_rw)" ;;
    *) py_sandbox ;;
  esac
}

# --- какие службы есть на этом сервере ---
present=""
for u in $XRAY $LONG_PY $ONESHOT; do
  [ -f "$UNIT_DIR/$u" ] && present="$present $u"
done
for f in "$UNIT_DIR"/channel-watch*.service; do
  [ -f "$f" ] || continue
  u="${f##*/}"
  case " $XRAY $LONG_PY $(echo $ONESHOT) " in *" $u "*) ;; *) echo "пропускаю $u: не знаю её папок — песочница не для неё" ;; esac
done
ours() {   # первая строка — наша метка; прежняя метка — с пометкой после запятой: «(sandbox_dropins.sh, …)»
  local l
  [ -f "$1" ] || return 1
  l=$(head -n 1 "$1")
  [ "$l" = "$MARK" ] && return 0
  case "$l" in "${MARK%)}, "*")") return 0 ;; esac
  return 1
}

restart_long() {   # перезапустить работающие долгоживущие службы (их новая песочница или её снятие — только с перезапуска)
  local u
  for u in $XRAY $LONG_PY; do
    case " $present " in *" $u "*) "$SYSTEMCTL" try-restart "$u" 2>/dev/null || true ;; esac
  done
}

rollback() {   # убрать все наши drop-in; чужие файлы не трогаем
  local u f n=0
  for f in "$UNIT_DIR"/channel-watch*.service.d/"$DROPIN"; do
    ours "$f" || continue
    rm -f "$f"; n=$((n + 1))
    rmdir "${f%/*}" 2>/dev/null || true
  done
  "$SYSTEMCTL" daemon-reload
  restart_long
  for u in $XRAY $LONG_PY; do
    case " $present " in
      *" $u "*) echo "   $u: $("$SYSTEMCTL" show -p ActiveState --value "$u" 2>/dev/null || echo '?')" ;;
    esac
  done
  echo "== откат: убрано drop-in: $n"
}

if [ "$mode" = rollback ]; then
  rollback
  exit 0
fi
[ -n "$present" ] || { echo "служб сторожа в $UNIT_DIR нет — нечего делать"; exit 1; }

# чужой 50-sandbox.conf не перезаписываем — ничего не меняя, выходим
for u in $present; do
  f="$UNIT_DIR/$u.d/$DROPIN"
  if [ -e "$f" ] && ! ours "$f"; then
    echo "в $f уже лежит чужой файл — не трогаю ничего; разберите его и запустите снова"; exit 2
  fi
done
if grep -q '"mark"' "$ETC/xray.json" 2>/dev/null; then
  echo "внимание: в $ETC/xray.json есть sockopt.mark — Xray в песочнице его поставить не сможет, канал будет недоступен"
fi

if [ "$mode" = dry ]; then
  for u in $present; do
    echo "== $UNIT_DIR/$u.d/$DROPIN"; dropin_text "$u"
  done
  exit 0
fi

# --- положить ---
declare -A before
for u in $present; do
  before[$u]="$("$SYSTEMCTL" show -p Result --value "$u" 2>/dev/null || echo '?')"
done
trap 'echo; echo "== прервано — откатываю"; rollback; exit 130' INT TERM HUP
for u in $present; do
  install -d -m 755 "$UNIT_DIR/$u.d"
  dropin_text "$u" > "$UNIT_DIR/$u.d/.$DROPIN.new"
  chmod 644 "$UNIT_DIR/$u.d/.$DROPIN.new"
  mv -f "$UNIT_DIR/$u.d/.$DROPIN.new" "$UNIT_DIR/$u.d/$DROPIN"
done
"$SYSTEMCTL" daemon-reload

fail=""
fail_unit() {   # $1 — служба, $2 — причина
  fail="$1"
  echo "   НЕ ПРОШЛА: $1 — $2"
  "$JOURNALCTL" -u "$1" -n 25 --no-pager 2>/dev/null | sed 's/^/      /' || true
}
# systemd принял настройки: ProtectSystem=strict у каждой службы
for u in $present; do
  ps="$("$SYSTEMCTL" show -p ProtectSystem --value "$u" 2>/dev/null || true)"
  [ "$ps" = strict ] || { fail_unit "$u" "systemd не применил drop-in (ProtectSystem=$ps)"; break; }
done

wait_idle() {   # дождаться конца прохода, начатого ещё без песочницы (до 25 минут)
  local i st
  for i in $(seq 1 750); do
    st="$("$SYSTEMCTL" show -p ActiveState --value "$1" 2>/dev/null || true)"
    case "$st" in activating|deactivating|reloading) sleep 2 ;; *) return 0 ;; esac
  done
  return 1
}
check_long() {   # долгоживущая: работала — перезапуск и две проверки, что жива и не перезапускается по кругу
  local u="$1" st pid1 pid2
  st="$("$SYSTEMCTL" show -p ActiveState --value "$u" 2>/dev/null || true)"
  if [ "$st" != active ]; then
    echo "   $u: не работала ($st) — без пробы, песочница со следующего запуска"; return 0
  fi
  # Xray не перезапускать посреди главной проверки: каналы на эти секунды пропали бы
  [ "$u" != "$XRAY" ] || wait_idle "$HB_UNIT" || true
  "$SYSTEMCTL" restart "$u" || { fail_unit "$u" "не перезапустилась"; return 1; }
  sleep "$PAUSE"
  pid1="$("$SYSTEMCTL" show -p MainPID --value "$u" || true)"
  sleep "$PAUSE"
  pid2="$("$SYSTEMCTL" show -p MainPID --value "$u" || true)"
  st="$("$SYSTEMCTL" show -p ActiveState --value "$u" || true)"
  if [ "$st" != active ] || [ "${pid1:-0}" = 0 ] || [ "$pid1" != "$pid2" ]; then
    fail_unit "$u" "после перезапуска не держится (состояние $st, PID $pid1 → $pid2)"; return 1
  fi
  echo "   $u: работает в песочнице (PID $pid2)"
}
check_oneshot() {
  local u="$1" rc=0 res
  wait_idle "$u" || { fail_unit "$u" "прежний проход не закончился за 25 минут"; return 1; }
  echo "   $u: пробный запуск (Result до песочницы: ${before[$u]})"
  "$SYSTEMCTL" start "$u" || rc=$?
  res="$("$SYSTEMCTL" show -p Result --value "$u" 2>/dev/null || true)"
  if [ "$rc" -ne 0 ] || [ "$res" != success ]; then
    fail_unit "$u" "код $rc, Result=$res"; return 1
  fi
  echo "   $u: Result=success"
}

# долгоживущие получают песочницу только с перезапуска — их перезапуск и проверка идут и при --no-test
if [ -z "$fail" ]; then
  echo "== пробный запуск служб в песочнице"
  for u in $XRAY $LONG_PY $ONESHOT; do
    case " $present " in *" $u "*) ;; *) continue ;; esac
    case " $XRAY $LONG_PY " in
      *" $u "*)
        if skipped "$u"; then echo "   $u: пропущена (--skip-test) — песочница с ближайшего перезапуска"; continue; fi
        check_long "$u" || break ;;
      *)
        if [ "$test" -eq 0 ]; then continue; fi
        if skipped "$u"; then echo "   $u: пропущена (--skip-test)"; continue; fi
        check_oneshot "$u" || break ;;
    esac
  done
fi
trap - INT TERM HUP

if [ -n "$fail" ]; then
  echo "== $fail не прошла — снимаю песочницу со всех служб"
  rollback
  exit 1
fi
echo "== песочница стоит:$(for u in $present; do printf ' %s' "${u%.service}"; done)"
[ "$test" -eq 1 ] || echo "   разовые службы пробно не запускались (--no-test): проверьте их после ближайших проходов таймеров"
echo "   снять: bash $0 --rollback"
