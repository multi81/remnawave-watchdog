#!/usr/bin/env bash
# install_ddos.sh — DDoS, нагрузка, щит с кнопками и сканеры на сторожевом сервере. Ставить ПОСЛЕ install.sh
# (сообщения в Telegram идут через probe.py, тот же бот и чат). Ubuntu 24.04 / 26.04. Запускать из папки с файлами.
#
#   bash install_ddos.sh                         ключи, службы и таймеры; список серверов — /etc/channel-watch/ddos.json
#   bash install_ddos.sh add ИМЯ АДРЕС [ПОРТ] [--rekey]
#                                                проверить, что сторож читает сервер (после того как на нём выполнен
#                                                server_install.sh), запомнить ключ его SSH и добавить в ddos.json;
#                                                сменившийся ключ SSH сервера принимается только с --rekey
#   bash install_ddos.sh keys                    напечатать строку для server_install.sh (адрес сторожа и два ключа)
#   bash install_ddos.sh --uninstall             убрать службы и таймеры (ключи и настройки остаются)
#
# Повторный запуск — обновление: новые скрипты; кнопки щита (служба shieldbot) и изменённые таймеры перезапускаются.
#
# Как устроено: на каждом сервере служба ddos-collect пишет срезы в /run/ddos-collect/state.json, сторож раз в минуту
# забирает файл ключом, который на сервере умеет только прочитать этот файл; щит (shield-ctl) только считает, а
# блокирует и включает резку — по кнопке в Telegram, отдельным ключом, который умеет только команды shield-ctl.
# Входящих портов сторож не открывает.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
ETC=/etc/channel-watch
OPT=/opt/channel-watch
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

keys() {
  local ip own
  ip=$(curl -4 -fsS -m 10 https://api.ipify.org 2>/dev/null || true)
  python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$ip" 2>/dev/null || ip=""
  # ваши адреса из owner.txt (по одному в строке, # — комментарий) — в allow щита; мусор пропускается
  own=$(python3 - "$ETC/owner.txt" <<'PY'
import ipaddress, sys
out = []
try:
    for ln in open(sys.argv[1], encoding="utf-8"):
        w = ln.split("#")[0].split()
        try:
            n = ipaddress.ip_network(w[0], strict=False) if w and "%" not in w[0] else None
        except ValueError:
            n = None
        if n is not None:
            out.append(str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n))
except OSError:
    pass
print(" ".join(dict.fromkeys(out)))
PY
)
  echo "bash server_install.sh --watch ${ip:-АДРЕС_СТОРОЖА} \\"
  echo "  --ddos-key '$(cat $ETC/ddos_ed25519.pub)' \\"
  if [ -n "$own" ]; then
    echo "  --shield-key '$(cat $ETC/shield_ed25519.pub)' \\"
    echo "  --allow '$own'"
  else
    echo "  --shield-key '$(cat $ETC/shield_ed25519.pub)'"
    echo "  (ваши адреса не записаны в $ETC/owner.txt — допишите их туда или добавьте к команде --allow 'адрес адрес')"
  fi
}

case "${1:-}" in
  --uninstall)
    systemctl disable --now channel-watch-ddos.timer channel-watch-shieldbot.service channel-watch-scanlists.timer channel-watch-behavscan.timer 2>/dev/null || true
    rm -f /etc/systemd/system/channel-watch-ddos.{service,timer} /etc/systemd/system/channel-watch-shieldbot.service \
          /etc/systemd/system/channel-watch-scanlists.{service,timer} /etc/systemd/system/channel-watch-behavscan.{service,timer}
    systemctl daemon-reload
    echo "службы DDoS, щита и сканеров убраны; ключи и $ETC/ddos.json остались"
    echo "   щиты на серверах остались в своём режиме; вернуть всем наблюдение и снять сторож целиком — bash install.sh --uninstall"
    exit 0 ;;
  keys) keys; exit 0 ;;
  add)
    shift; rekey=0; args=()
    for a in "$@"; do case "$a" in --rekey) rekey=1 ;; *) args+=("$a") ;; esac; done
    name="${args[0]:-}"; host="${args[1]:-}"; port="${args[2]:-22}"
    [[ "$name" =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || { echo "имя сервера: латиница, цифры, _ . - (до 40 знаков)"; exit 2; }
    [[ "$host" =~ ^[A-Za-z0-9.:-]{1,253}$ ]] || { echo "адрес сервера: IP или имя хоста"; exit 2; }
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "порт SSH: число 1-65535"; exit 2; }
    for f in ddos.json ddos_ed25519 shield_ed25519; do
      [ -s "$ETC/$f" ] || { echo "нет $ETC/$f — сначала bash install_ddos.sh"; exit 1; }
    done
    # ключ SSH сервера: первый раз запоминается (сверьте отпечаток с консолью хостера, если сомневаетесь); сменившийся
    # ключ молча не принимается — только с --rekey (переустановили сервер — да; иначе это может быть подмена)
    kh_name="$host"; [ "$port" = 22 ] || kh_name="[$host]:$port"
    scanned=$(ssh-keyscan -T 10 -t ed25519 -p "$port" "$host" 2>/dev/null | awk '!/^#/ && $2 == "ssh-ed25519" {print $2, $3; exit}' || true)
    [ -n "$scanned" ] || { echo "ключ SSH сервера $host:$port не получен — сервер недоступен или нет ключа ed25519"; exit 1; }
    fp=$(printf '%s %s\n' "$kh_name" "$scanned" | ssh-keygen -lf - | awk '{print $2}')
    trust=()
    for kh in ddos_known_hosts shield_known_hosts; do
      touch "$ETC/$kh"
      known=$(ssh-keygen -F "$kh_name" -f "$ETC/$kh" 2>/dev/null | awk '!/^#/ && $2 == "ssh-ed25519" {print $2, $3}' || true)
      if [ -z "$known" ]; then trust+=("$kh")
      elif printf '%s\n' "$known" | grep -qxF "$scanned"; then :
      elif [ "$rekey" -eq 1 ]; then trust+=("$kh")
      else
        echo "ВНИМАНИЕ: ключ SSH сервера $kh_name изменился (новый отпечаток $fp), в $ETC/$kh — прежний."
        echo "  Если сервер переустановлен — сверьте отпечаток с консолью хостера и повторите с --rekey."
        echo "  Если нет — это может быть подмена по пути: ничего не меняю."
        exit 1
      fi
    done
    # связь не подтвердится — ключ не запоминаем (undo возвращает known_hosts как были)
    undo() { local kh; for kh in "${trust[@]}"; do [ ! -f "$ETC/$kh.add" ] || mv -f "$ETC/$kh.add" "$ETC/$kh"; done; }
    for kh in "${trust[@]}"; do
      cp -p "$ETC/$kh" "$ETC/$kh.add"
      ssh-keygen -R "$kh_name" -f "$ETC/$kh" >/dev/null 2>&1 || true
      printf '%s %s\n' "$kh_name" "$scanned" >> "$ETC/$kh"
    done
    rm -f "$ETC"/*_known_hosts.old
    if [ "${#trust[@]}" -gt 0 ] && [ "$rekey" -eq 1 ]; then echo "ключ SSH $name принимается заново (--rekey): $fp"
    elif [ "${#trust[@]}" -gt 0 ]; then echo "ключ SSH $name новый: $fp (сверьте с консолью хостера, если сомневаетесь)"
    else echo "ключ SSH $name прежний: $fp"; fi
    # связь: ddos.json меняется только после того, как оба ключа сработали
    out=$(ssh -i "$ETC/ddos_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes \
          -o UserKnownHostsFile="$ETC/ddos_known_hosts" root@"$host" x) \
      && printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("сборщик читается, срезов:", len(d["samples"]))' \
      || { echo "сборщик на $host не читается${out:+ (${out:0:200})} — выполнен ли там server_install.sh? В ddos.json не добавлен, ключ SSH не запомнен."; undo; exit 1; }
    out=$(ssh -i "$ETC/shield_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes \
          -o UserKnownHostsFile="$ETC/shield_known_hosts" root@"$host" status) \
      && printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ok"), d; print("щит:", d.get("mode"), "· таблица", d.get("loaded"))' \
      || { echo "щит на $host не отвечает${out:+ (${out:0:200})}. В ddos.json не добавлен, ключ SSH не запомнен."; undo; exit 1; }
    rm -f "$ETC"/*_known_hosts.add
    python3 - "$ETC/ddos.json" "$name" "$host" "$port" <<'PY'
import json, os, shutil, sys
path, name, host, port = sys.argv[1:5]
c = json.load(open(path, encoding="utf-8"))
was = [h for h in c.get("hosts", []) if h.get("name") == name]
c["hosts"] = [h for h in c.get("hosts", []) if h.get("name") != name] + [{"name": name, "host": host, "port": int(port)}]
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(c, f, ensure_ascii=False, indent=1)
    f.write("\n")
shutil.copymode(path, tmp)
os.replace(tmp, path)
print("%s в ddos.json %s" % (name, "обновлён" if was else "добавлен"))
PY
    exit 0 ;;
  "") ;;
  *) echo "не понимаю: $1 (см. шапку скрипта)"; exit 2 ;;
esac

[ -s "$OPT/probe.py" ] || { echo "сначала install.sh: через probe.py уходят сообщения в Telegram"; exit 1; }
for f in ddoswatch.py shieldbot.py scanlists.py behavscan.py; do [ -s "$SRC/$f" ] || { echo "рядом нет $f"; exit 1; }; done
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' \
  "$SRC/ddoswatch.py" "$SRC/shieldbot.py" "$SRC/scanlists.py" "$SRC/behavscan.py"
# повторный запуск — обновление: ставится только изменённое; что изменилось у работающего — перезапускается ниже
first=0; [ -f /etc/systemd/system/channel-watch-shieldbot.service ] || first=1
ch_bot=0 ch_timers=""
for f in ddoswatch.py shieldbot.py scanlists.py behavscan.py; do
  if ! cmp -s "$SRC/$f" "$OPT/$f"; then
    install -m 755 "$SRC/$f" "$OPT/"
    if [ "$f" = shieldbot.py ]; then ch_bot=1; fi
  fi
done
unit() {  # unit ИМЯ <<текст — 0: юнит новый или изменён, 1: такой же
  local tmp; tmp=$(mktemp)
  cat > "$tmp"
  if [ -f "/etc/systemd/system/$1" ] && cmp -s "$tmp" "/etc/systemd/system/$1"; then rm -f "$tmp"; return 1; fi
  install -m 644 "$tmp" "/etc/systemd/system/$1" || { rm -f "$tmp"; echo "не смог записать юнит $1"; exit 1; }
  rm -f "$tmp"
}

for k in ddos shield; do
  [ -f "$ETC/${k}_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C "channel-watch-$k" -f "$ETC/${k}_ed25519"
  chmod 600 "$ETC/${k}_ed25519"; touch "$ETC/${k}_known_hosts"; chmod 644 "$ETC/${k}_known_hosts"
done
# work_from/work_to — часы по МСК, когда предложения щита приходят сразу (ночью — строкой в утреннем отчёте)
[ -s "$ETC/ddos.json" ] || printf '{"hosts": [], "work_from": 9, "work_to": 21, "summary_hour": 9, "thresholds": {}}\n' > "$ETC/ddos.json"
touch "$ETC/scanners-extra.txt" "$ETC/scanners-exclude.txt" "$ETC/owner.txt"

unit channel-watch-ddos.service <<'UNIT' || true
[Unit]
Description=channel-watch: DDoS и нагрузка серверов

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/ddoswatch.py
TimeoutStartSec=90
UNIT
unit channel-watch-ddos.timer <<'UNIT' && ch_timers="$ch_timers channel-watch-ddos.timer"
[Unit]
Description=channel-watch: DDoS и нагрузка раз в минуту

[Timer]
OnBootSec=3min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
UNIT
unit channel-watch-shieldbot.service <<'UNIT' && ch_bot=1
[Unit]
Description=channel-watch: кнопки щита в Telegram (выполняет только нажатое)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/channel-watch/shieldbot.py
Restart=always
RestartSec=10
Nice=10
MemoryMax=96M

[Install]
WantedBy=multi-user.target
UNIT
unit channel-watch-scanlists.service <<'UNIT' || true
[Unit]
Description=channel-watch: единый список сканеров для щита

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/scanlists.py
Nice=15
TimeoutStartSec=600
UNIT
unit channel-watch-scanlists.timer <<'UNIT' && ch_timers="$ch_timers channel-watch-scanlists.timer"
[Unit]
Description=channel-watch: список сканеров раз в сутки

[Timer]
OnCalendar=*-*-* 01:30:00 UTC
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
unit channel-watch-behavscan.service <<'UNIT' || true
[Unit]
Description=channel-watch: свой список сканеров по поведению (стуки в закрытые порты ваших серверов)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/channel-watch/behavscan.py
Nice=15
TimeoutStartSec=600
UNIT
unit channel-watch-behavscan.timer <<'UNIT' && ch_timers="$ch_timers channel-watch-behavscan.timer"
[Unit]
Description=channel-watch: свой список сканеров раз в сутки, перед общим списком

[Timer]
OnCalendar=*-*-* 01:20:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable channel-watch-ddos.timer channel-watch-shieldbot.service channel-watch-scanlists.timer channel-watch-behavscan.timer >/dev/null 2>&1
# разовые службы (ddoswatch, scanlists, behavscan) следующий раз сами запустятся с новым кодом; кнопки работают
# постоянно — их перезапустить, если изменились; таймеры — если изменились или стоят
for t in channel-watch-ddos.timer channel-watch-scanlists.timer channel-watch-behavscan.timer; do
  if ! systemctl is-active -q "$t" || [[ " $ch_timers " == *" $t "* ]]; then
    systemctl restart "$t"; [ "$first" -eq 1 ] || echo "   $t: перезапущен"
  fi
done
if ! systemctl is-active -q channel-watch-shieldbot.service || [ "$ch_bot" -eq 1 ]; then
  systemctl restart channel-watch-shieldbot.service; [ "$first" -eq 1 ] || echo "   кнопки щита (shieldbot): перезапущены с новым кодом"
elif [ "$first" -eq 0 ] && [ -z "$ch_timers" ]; then
  echo "   код кнопок и таймеры не изменились, службы не перезапускались"
fi

echo "== готово: DDoS $(systemctl is-active channel-watch-ddos.timer), кнопки $(systemctl is-active channel-watch-shieldbot.service), сканеры $(systemctl is-active channel-watch-scanlists.timer)"
echo "   ваши адреса (никогда не блокировать и не считать сканерами) — по одному в строке в $ETC/owner.txt"
echo "   на каждом сервере выполните server_install.sh (рядом ddos_collect.py и shield_ctl.py):"
keys | sed 's/^/     /'
echo "   потом здесь: bash install_ddos.sh add ИМЯ АДРЕС [ПОРТ_SSH]"
