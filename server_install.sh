#!/usr/bin/env bash
# server_install.sh — сервер под присмотром сторожа: сборщик метрик (ddos-collect) и щит (shield-ctl) в режиме
# НАБЛЮДЕНИЯ — ничего не режет и не блокирует, пока вы не нажмёте кнопку в Telegram. Ubuntu 24.04 / 26.04, root.
# Рядом должны лежать ddos_collect.py и shield_ctl.py. Готовую команду печатает на сторожевом сервере
# `bash install_ddos.sh keys`:
#
#   bash server_install.sh --watch АДРЕС_СТОРОЖА --ddos-key 'ssh-ed25519 …' --shield-key 'ssh-ed25519 …' \
#        [--allow 'адрес адрес …'] [--iface eth0]
#   bash server_install.sh                 повторно — обновление: новый код, перезапуск изменённого
#   bash server_install.sh --uninstall
#
# Что ставится:
#   /usr/local/sbin/ddos-collect + ddos-collect.service (Nice 10, CPUQuota 5%, MemoryMax 64M) — только счётчики,
#     адресов не хранит (кроме «подозрительных» на 5 минут и ваших клиентов по журналу Xray — файл не покидает сервер);
#   /usr/local/sbin/shield-ctl + storozh-shield.service — своя таблица nft `inet storozh_shield`, ufw, crowdsec,
#     fail2ban и чужие таблицы не трогает; снимается одной командой: systemctl disable --now storozh-shield;
#   две строки в /root/.ssh/authorized_keys, обе только с адреса сторожа: одна умеет лишь прочитать срезы,
#     другая — лишь команды shield-ctl (status, block, unblock, mode). Копия прежнего файла — authorized_keys.before.
#
# «Свои» для щита (allow: не считать и не блокировать): адрес сторожа, адреса самого сервера (публичные с интерфейса
# маршрута по умолчанию или --iface и внешний, каким его видит интернет) и --allow (адреса или сети через пробел или
# запятую). Публичные адреса прочих интерфейсов (туннели, мосты) только печатаются подсказкой: ваши — добавьте в
# --allow. Внешний адрес не получен (api.ipify.org не ответил) — остаётся прежний. Мусор в --allow — ошибка,
# установка останавливается (раньше молча пропадал).
#
# Повторный запуск — обновление: ставит новые shield-ctl и ddos-collect и перезапускает то, что изменилось. Таблица
# щита пересобирается атомарно (shield-ctl load): режим, блокировки, клиенты и списки сканеров сохраняются. Ключи и
# адрес сторожа можно не повторять — берутся из прежней установки. Новый --watch, ключ или --allow заменяют
# прежние (копии authorized_keys и config.json — в /root/storozh-before).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
B=/root/storozh-before
AK=/root/.ssh/authorized_keys
CONF=/etc/storozh-shield/config.json
TS=$(date +%Y%m%d-%H%M%S)
watch="" ddos_key="" shield_key="" allow="" allow_given=0 iface="" uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --watch) watch="${2:?адрес сторожа}"; shift 2 ;;
    --ddos-key) ddos_key="${2:?ключ ddos}"; shift 2 ;;
    --shield-key) shield_key="${2:?ключ щита}"; shift 2 ;;
    --allow) allow="$allow ${2:-}"; allow_given=1; shift 2 ;;
    --iface) iface="${2:?интерфейс}"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }
install -d -m 700 "$B"

if [ "$uninstall" -eq 1 ]; then
  systemctl disable --now storozh-shield storozh-shield-tick.timer ddos-collect 2>/dev/null || true
  rm -f /etc/systemd/system/storozh-shield.service /etc/systemd/system/storozh-shield-tick.{service,timer} \
        /etc/systemd/system/ddos-collect.service /usr/local/sbin/shield-ctl /usr/local/sbin/ddos-collect \
        /etc/logrotate.d/storozh-shield /var/log/storozh-shield.log*
  rm -rf /etc/storozh-shield /var/lib/storozh-shield /run/storozh-shield
  # по подстроке: и строки с меткой без хвоста, и прежние вида channel-watch-ddos@имя
  if [ -f "$AK" ] && grep -q 'channel-watch-ddos\|channel-watch-shield' "$AK"; then
    cp -a "$AK" "$B/authorized_keys.$TS"
    sed -i '/channel-watch-ddos\|channel-watch-shield/d' "$AK"
  fi
  systemctl daemon-reload
  echo "сборщик и щит убраны, строки ключей сторожа удалены (копии прежних файлов — в $B)"; exit 0
fi

# --- прежняя установка: строки ключей и адрес сторожа берутся из неё, если не заданы заново ---
# метка — последнее поле строки; прежние версии писали её с хвостом (channel-watch-ddos@имя) — такие строки тоже наши
label_re() { printf '[[:space:]]%s(@[^[:space:]]*)?$' "$1"; }
line_of() { [ -f "$AK" ] && grep -E "$(label_re "$1")" "$AK" | tail -n 1 || true; }
old_ddos=$(line_of channel-watch-ddos)
old_shield=$(line_of channel-watch-shield)
old_watch=$(printf '%s\n' "$old_shield" | sed -nE 's/^from="([^"]*)".*/\1/p')
[ -n "$watch" ] || watch=$old_watch
[ -n "$watch" ] || { echo "нужен --watch АДРЕС_СТОРОЖА (см. шапку)"; exit 2; }
[ -n "$ddos_key" ] || [ -n "$old_ddos" ] || { echo "нужен --ddos-key (см. шапку)"; exit 2; }
[ -n "$shield_key" ] || [ -n "$old_shield" ] || { echo "нужен --shield-key (см. шапку)"; exit 2; }
for k in "$ddos_key" "$shield_key"; do
  [ -z "$k" ] || [[ "$k" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\ [A-Za-z0-9+/]+=*(\ [A-Za-z0-9@._-]*)?$ ]] \
    || { echo "ключ не похож на открытый ключ SSH (ожидается «ssh-ed25519 AAAA… имя»): ${k:0:40}…"; exit 2; }
done
for f in ddos_collect.py shield_ctl.py; do [ -s "$SRC/$f" ] || { echo "рядом нет $f"; exit 1; }; done
command -v python3 >/dev/null || { echo "нет python3"; exit 1; }
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y -qq nftables; }
python3 -c 'import ast, sys; [ast.parse(open(f, encoding="utf-8").read(), f) for f in sys.argv[1:]]' "$SRC/ddos_collect.py" "$SRC/shield_ctl.py"
[ -z "$iface" ] || [[ "$iface" =~ ^[A-Za-z0-9_.:@-]{1,15}$ ]] || { echo "--iface: недопустимое имя интерфейса"; exit 2; }

# адрес сторожа: только адреса (from= в authorized_keys и allow щита); имя разрешается в адреса один раз здесь
watch_ips=$(python3 - "$watch" <<'PY'
import ipaddress, socket, sys
out = []
for x in sys.argv[1].replace(",", " ").split():
    try:
        out.append(str(ipaddress.ip_address(x)) if "%" not in x else "")
    except ValueError:
        try:
            out += sorted({ai[4][0] for ai in socket.getaddrinfo(x, None, proto=socket.IPPROTO_TCP)})
        except OSError:
            sys.exit("--watch: не адрес и не разрешается в адрес: %s" % x)
out = [a for a in dict.fromkeys(out) if a and "%" not in a]
if not out:
    sys.exit("--watch: нет ни одного адреса")
print(",".join(out))
PY
)

# внешний адрес сервера (за NAT провайдера он не виден на интерфейсах); не получен — ниже остаётся прежний
pub=$(curl -4 -fsS -m 8 https://api.ipify.org 2>/dev/null || true)
python3 -c 'import ipaddress, sys; a = ipaddress.ip_address(sys.argv[1]); sys.exit(0 if a.version == 4 and a.is_global else 1)' \
  "$pub" 2>/dev/null || pub=""

[ -f "$B/authorized_keys.before" ] || cp -a "$AK" "$B/authorized_keys.before" 2>/dev/null || true
# правила до ПЕРВОЙ установки: при повторных запусках не перезаписываются (там уже была бы таблица щита)
[ -s "$B/ruleset.before" ] || nft list ruleset > "$B/ruleset.before" 2>/dev/null || true

# --- настройки щита: allow = свои адреса; прочие ключи config.json (пороги, iface, правленные вручную) сохраняются ---
install -d -m 755 /etc/storozh-shield
conf_changed=$(python3 - "$CONF" "$watch_ips" "$allow" "$allow_given" "$pub" "$iface" "$B/config.json.$TS" "$old_watch" <<'PY'
import ipaddress, json, os, shutil, subprocess, sys
conf, watch_raw, allow_raw, allow_given, pub, iface, backup, old_watch_raw = sys.argv[1:9]
# служебные поля установщика: щит их не читает, их правка — не повод пересобирать таблицу
BOOK = ("allow_installer", "allow_extra", "allow_self", "allow_public")


def say(msg):
    print(msg, file=sys.stderr)


def norm(x):
    """адрес или сеть -> строка (адрес без /32, сеть по границе); мусор или шире /8 (IPv6 — /32) -> ValueError"""
    n = ipaddress.ip_network(x.strip(), strict=False)
    if "%" in x or n.prefixlen < (8 if n.version == 4 else 32):
        raise ValueError(x)
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def order(x):
    n = ipaddress.ip_network(x, strict=False)
    return n.version, n


old = {}
if os.path.exists(conf):
    try:
        old = json.load(open(conf, encoding="utf-8"))
    except ValueError:
        sys.exit("не читается %s — исправьте или удалите его и запустите снова" % conf)
extra, bad = [], []
for x in allow_raw.replace(",", " ").split():
    try:
        extra.append(norm(x))
    except ValueError:
        bad.append(x)
if bad:
    sys.exit("--allow: не адрес и не сеть: %s (адреса через пробел или запятую, сети вида 203.0.113.0/24, "
             "не шире /8, для IPv6 — /32)" % ", ".join(bad))


def clean(items):
    out = []
    for x in items:
        try:
            out.append(norm(str(x).strip(" ,;")))
        except ValueError:
            say("   в прежнем allow не адрес: %r — убран (щит его и так не понимал)" % x)
    return out


watch = [norm(x) for x in watch_raw.split(",") if x]


def ip_json(*args):
    try:
        out = subprocess.run(["ip", "-j"] + list(args), capture_output=True, text=True, timeout=10).stdout
        return json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


# адреса самого сервера с интерфейсов: только с интерфейса маршрута по умолчанию (IPv4 и IPv6) или с --iface
# (iface из config.json); публичные адреса прочих интерфейсов (туннели, мосты, тестовые veth) — только подсказкой
ifs = {iface or old.get("iface") or ""} - {""}
if not ifs:
    for fam in ("-4", "-6"):
        for r in ip_json(fam, "route", "show", "default"):
            ifs.update(h["dev"] for h in [r] + list(r.get("nexthops") or []) if h.get("dev"))
own, other = [], []
for link in ip_json("addr", "show", "scope", "global"):
    for a in link.get("addr_info") or []:
        try:
            if ipaddress.ip_address(a.get("local", "")).is_global:
                (own if link.get("ifname") in ifs else other).append((link.get("ifname"), norm(a["local"])))
        except ValueError:
            pass
own = [x for _, x in own]
if not ifs:
    # маршрута по умолчанию нет (сеть ещё не поднялась) — прежние адреса сервера не выбрасываются
    own = list(old.get("allow_self") or [])
    say("   маршрута по умолчанию нет и --iface не задан — адреса сервера в своих прежние: %s" % (" ".join(own) or "нет"))

# внешний адрес: api.ipify.org не ответил — остаётся прежний (разовый сбой не меняет allow и не пересобирает таблицу)
if pub:
    public = [norm(pub)]
else:
    public = list(old.get("allow_public") or [])
    say("   внешний адрес не получен (api.ipify.org) — %s" % (
        "оставлен прежний: " + " ".join(public) if public else "в свои не добавлен, повторите установку позже"))

if "allow_installer" in old:
    # добавленное в allow не установщиком (вручную) остаётся; без --allow — прежние --allow
    manual = clean(x for x in old.get("allow") or [] if x not in old["allow_installer"])
    if allow_given != "1":
        extra = list(old.get("allow_extra") or [])
else:
    # установщик до 1.3 своё не помечал, а его allow — это прежние --watch и --allow: сменившийся --watch уходит,
    # прежние --allow без нового --allow остаются (дальше — как --allow), новый --allow их заменяет
    manual = []
    if allow_given != "1":
        gone_watch = set(clean(x for x in old_watch_raw.split(",") if x))
        extra = [x for x in clean(old.get("allow") or []) if x not in gone_watch and x not in watch]
auto = sorted(set(watch + own + public + extra), key=order)
cfg = dict(old) if old else {"rate": 200, "burst": 400, "conns": 5000}
cfg["allow"] = sorted(set(manual + auto), key=order)
cfg["allow_installer"] = auto
cfg["allow_extra"] = extra
cfg["allow_self"] = sorted(set(own), key=order)
cfg["allow_public"] = public
if iface:
    cfg["iface"] = iface
hint = [(i, x) for i, x in other if x not in cfg["allow"]]
if hint:
    say("   публичные адреса других интерфейсов в свои не добавлены: %s — если это ваши, добавьте --allow '%s'" % (
        ", ".join("%s %s" % ix for ix in hint), " ".join(dict.fromkeys(x for _, x in hint))))
if cfg == old:
    print("0")
    sys.exit(0)
changed = any(cfg.get(k) != old.get(k) for k in set(cfg) | set(old) if k not in BOOK)
was = set(old.get("allow") or [])
add, gone = [x for x in cfg["allow"] if x not in was], sorted(was - set(cfg["allow"]), key=str)
if old:
    shutil.copy2(conf, backup)
    if changed:
        say("   config.json изменён (копия прежнего — %s)%s%s" % (
            backup, "; allow + " + " ".join(add) if add else "", "; allow − " + " ".join(gone) if gone else ""))
tmp = conf + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=1)
    f.write("\n")
os.replace(tmp, conf)
print("1" if changed else "0")
PY
)
echo "   свои для щита: $(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["allow"]))' "$CONF")"

# --- файлы и юниты: ставятся, только если отличаются; что изменилось — перезапускается ниже ---
first=0; [ -f /etc/systemd/system/storozh-shield.service ] || first=1
ch_shield=$conf_changed ch_tick=0 ch_collect=0
put() {  # put ИСТОЧНИК ЦЕЛЬ — 0: поставлен новый, 1: такой же уже стоит
  if [ -f "$2" ] && cmp -s "$1" "$2"; then return 1; fi
  install -m 755 "$1" "$2" || { echo "не смог поставить $2"; exit 1; }
}
unit() {  # unit ИМЯ <<текст — 0: юнит новый или изменён, 1: такой же
  local tmp; tmp=$(mktemp)
  cat > "$tmp"
  if [ -f "/etc/systemd/system/$1" ] && cmp -s "$tmp" "/etc/systemd/system/$1"; then rm -f "$tmp"; return 1; fi
  install -m 644 "$tmp" "/etc/systemd/system/$1" || { rm -f "$tmp"; echo "не смог записать юнит $1"; exit 1; }
  rm -f "$tmp"
}

# --- щит: наблюдение ---
put "$SRC/shield_ctl.py" /usr/local/sbin/shield-ctl && ch_shield=1
# сеть при загрузке: без iface в config.json щит берёт интерфейс маршрута IPv4 по умолчанию — ждём его (не дольше
# минуты); при сбое load — повтор через 30 с без предела числа попыток (StartLimitIntervalSec=0). С пределом служба
# после серии сбоев (сеть поднялась через четверть часа, config.json правили руками) застревала бы в failed до ручного
# запуска, и блокировки с режимом on из state не вернулись бы; попытка — один короткий запуск shield-ctl, 30 с между
# ними не нагружают ни сервер, ни журнал. reload = shield-ctl load (таблица пересоздаётся атомарно, режим, блоки и
# списки — из state)
unit storozh-shield.service <<'UNIT' && ch_shield=1
[Unit]
Description=storozh-shield: щит от флуда (таблица nft inet storozh_shield); блокирует только по кнопке
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/bin/sh -c 'grep -q "iface.: *.[[:alnum:]]" /etc/storozh-shield/config.json 2>/dev/null && exit 0; n=0; until ip -4 route show default | grep -q . || [ "$$n" -ge 30 ]; do n=$$((n+1)); sleep 2; done'
ExecStart=/usr/local/sbin/shield-ctl load
ExecReload=/usr/local/sbin/shield-ctl load
ExecStop=/usr/local/sbin/shield-ctl unload
Restart=on-failure
RestartSec=30
TimeoutStartSec=150

[Install]
WantedBy=multi-user.target
UNIT
unit storozh-shield-tick.service <<'UNIT' && ch_tick=1
[Unit]
Description=storozh-shield: срок включённого щита и блокировок

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shield-ctl tick
UNIT
unit storozh-shield-tick.timer <<'UNIT' && ch_tick=1
[Unit]
Description=storozh-shield: раз в минуту

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
UNIT
cat > /etc/logrotate.d/storozh-shield <<'ROT'
/var/log/storozh-shield.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
ROT

# --- сборщик ---
put "$SRC/ddos_collect.py" /usr/local/sbin/ddos-collect && ch_collect=1
unit ddos-collect.service <<'UNIT' && ch_collect=1
[Unit]
Description=ddos-collect: метрики сервера для сторожа (DDoS и нагрузка), только счётчики
Wants=network-online.target
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
systemctl enable storozh-shield storozh-shield-tick.timer ddos-collect >/dev/null 2>&1

# --- запуск и обновление: работающее с новым кодом или настройками — перезапустить ---
if ! systemctl is-active -q storozh-shield; then
  systemctl reset-failed storozh-shield 2>/dev/null || true
  systemctl start storozh-shield || echo "внимание: щит не загрузился — journalctl -u storozh-shield"
  [ "$first" -eq 1 ] || echo "   щит: запущен"
elif [ "$ch_shield" -eq 1 ]; then
  systemctl reload storozh-shield && echo "   щит: таблица пересобрана новым кодом/настройками (shield-ctl load)" \
    || echo "внимание: shield-ctl load не прошёл, работает прежняя таблица — journalctl -u storozh-shield"
fi
if ! systemctl is-active -q storozh-shield-tick.timer || [ "$ch_tick" -eq 1 ]; then
  systemctl restart storozh-shield-tick.timer; [ "$first" -eq 1 ] || echo "   таймер щита: перезапущен"
fi
if ! systemctl is-active -q ddos-collect || [ "$ch_collect" -eq 1 ]; then
  systemctl restart ddos-collect; [ "$first" -eq 1 ] || echo "   сборщик: перезапущен с новым кодом"
else
  ch_collect=0
fi
[ "$first" -eq 1 ] || [ "$ch_shield$ch_tick$ch_collect" != 000 ] || echo "   код и настройки не изменились, службы не перезапускались"

# --- ключи сторожа: только с его адреса и только одна команда; новый адрес или ключ заменяет строку ---
install -d -m 700 /root/.ssh; touch "$AK"; chmod 600 "$AK"
ak_saved=0
set_key() {  # set_key МЕТКА КОМАНДА КЛЮЧ (пустой ключ — прежний из строки с этой меткой)
  local label=$1 cmd=$2 key=$3 re old new tag
  re=$(label_re "$label")
  old=$(line_of "$label")
  if [ -n "$key" ]; then key=$(printf '%s\n' "$key" | awk '{print $1, $2}')
  else key=$(printf '%s\n' "$old" | sed -nE 's/^.*restrict ([^ ]+ [^ ]+) .*$/\1/p'); fi
  [ -n "$key" ] || { echo "не нашёл ключ в прежней строке $label — задайте ключ заново"; exit 2; }
  # метка прежней строки (в том числе с хвостом) сохраняется: иначе каждый повтор менял бы файл без нужды
  tag=$label; [ -z "$old" ] || tag=$(printf '%s\n' "$old" | awk '{print $NF}')
  new=$(printf 'from="%s",command="%s",restrict %s %s' "$watch_ips" "$cmd" "$key" "$tag")
  if [ "$old" = "$new" ] && [ "$(grep -cE "$re" "$AK")" -eq 1 ]; then echo "   строка $tag без изменений"; return; fi
  if [ "$ak_saved" -eq 0 ] && [ -s "$AK" ]; then cp -a "$AK" "$B/authorized_keys.$TS"; ak_saved=1; fi
  { grep -vE "$re" "$AK" || true; printf '%s\n' "$new"; } > "$AK.tmp"
  chmod 600 "$AK.tmp"; mv -f "$AK.tmp" "$AK"
  if [ -n "$old" ]; then echo "   строка $tag заменена (копия прежнего файла — $B/authorized_keys.$TS)"
  else echo "   строка $tag добавлена"; fi
}
set_key channel-watch-ddos "cat /run/ddos-collect/state.json" "$ddos_key"
set_key channel-watch-shield "/usr/local/sbin/shield-ctl --ssh" "$shield_key"

[ "$ch_collect" -eq 0 ] || sleep 25
echo "== сборщик $(systemctl is-active ddos-collect), срезы $([ -s /run/ddos-collect/state.json ] && echo пишутся || echo 'ещё нет'), щит: $(/usr/local/sbin/shield-ctl status | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("mode"), "· таблица", d.get("loaded"), "· версия", d.get("v"))')"
[ "$first" -eq 0 ] || echo "   теперь на сторожевом сервере: bash install_ddos.sh add ИМЯ ${pub:-АДРЕС} [ПОРТ_SSH]"
echo "   откат: bash server_install.sh --uninstall (прежние authorized_keys и правила nft — в $B)"
