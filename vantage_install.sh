#!/usr/bin/env bash
# vantage_install.sh — точка проверки для сторожа каналов (vantage_agent.py): ещё один российский сервер,
# с которого сторож смотрит на ноды, когда канал не работает. Система — Ubuntu 24.04 / 26.04.
#
#   bash vantage_install.sh                       мастер: спросит адрес сторожа, порт и название точки
#   bash vantage_install.sh --allow IP --yes      без вопросов (IP — адрес сервера, где стоит сторож)
#        --port N        порт агента (по умолчанию 9109)
#        --name ИМЯ      как называть точку в сообщениях сторожа (по умолчанию имя сервера)
#        --suffix a,b    домены, имена на которых агенту разрешено проверять (обязательно)
#        --ports a,b     порты, которые агенту разрешено проверять (по умолчанию 443)
#        --hosts a,b     адреса вне своих доменов, которые тоже можно проверять (например свои ретрансляторы)
#        --snis a,b      имена TLS, с которыми можно обращаться к таким адресам (у ретранслятора имя чужое)
#        --public АДРЕС  внешний адрес или имя точки, по которому до неё дойдёт сторож (точка за NAT: дома, в офисе —
#                        адрес роутера, на котором порт агента проброшен на эту машину); только IPv4 или имя с
#                        записью A — агент слушает IPv4
#        --tls-only      больше не отвечать сторожу по обычному HTTP, только TLS (включать, когда сторож
#                        уже ходит по TLS: в его vantage.json у точки есть "sha256"); --http-also — вернуть HTTP
#   bash vantage_install.sh --entry [--rucheck] [--public АДРЕС]   напечатать запись для vantage.json сторожа
#                                                 (в ней токен: не на экран, а конвейером на сервер сторожа)
#        --rucheck       точка проверяет сервисы для сверки шаблона (лучше точка у обычного провайдера, не в дата-центре)
#   bash vantage_install.sh --uninstall           убрать
#
# Что ставит: /opt/vantage-agent (агент и проверки), настройки /etc/vantage-agent/agent.json (токен создаётся здесь же,
# читает только root), сертификат TLS /etc/vantage-agent/cert.pem и key.pem (самоподписанный, создаётся здесь же),
# службу vantage-agent от временного пользователя (DynamicUser): настройки и ключ она получает через LoadCredential.
# В ufw порт открывается только адресу сторожа.
# Агент отвечает только сторожу (адрес и токен), проверяет только имена на разрешённых доменах и только порт 443.
# TLS и HTTP — на одном порту: старый сторож ходит по HTTP, новый (vantage_client.py) — по TLS со сверкой отпечатка.
# Порядок перехода: обновить точку → внести запись заново (--entry … --add-vantage, в ней "sha256") → --tls-only.
# Повторный запуск безопасен: файлы и служба обновляются, токен, сертификат и прежние настройки остаются.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/vantage-agent; ETC=/etc/vantage-agent; UNIT=/etc/systemd/system/vantage-agent.service
allow="" allow_given=0 port="" name="" suffix="" yes=0 mode=install ports="" hosts="" snis="" public="" tls_only=""
while [ $# -gt 0 ]; do
  case "$1" in
    --allow) allow="${2:?после --allow нужен адрес сторожа}"; allow_given=1; shift 2 ;;
    --port) port="${2:?после --port нужен номер}"; shift 2 ;;
    --name) name="${2:?после --name нужно название}"; shift 2 ;;
    --suffix) suffix="${2:?после --suffix нужны домены через запятую}"; shift 2 ;;
    --ports) ports="${2:?после --ports нужны порты через запятую}"; shift 2 ;;
    --hosts) hosts="${2:?после --hosts нужны адреса через запятую}"; shift 2 ;;
    --snis) snis="${2:?после --snis нужны имена через запятую}"; shift 2 ;;
    --public) public="${2:?после --public нужен внешний адрес}"; shift 2 ;;
    --tls-only) tls_only=1; shift ;;
    --http-also) tls_only=0; shift ;;
    --yes) yes=1; shift ;;
    --entry) mode=entry; shift ;;
    --rucheck) rucheck=1; shift ;;
    --uninstall) mode=uninstall; shift ;;
    *) echo "не понимаю параметр: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "нужны права root"; exit 1; }

# адрес или имя без пробелов, «%» (зона IPv6) и прочего, что ufw и URL поймут не так
valid_addr() {
  python3 -c '
import ipaddress, re, sys
a = sys.argv[1]
if "%" in a or not re.fullmatch(r"[0-9A-Za-z.:-]{1,253}", a):
    sys.exit(1)
try:
    ipaddress.ip_address(a)
except ValueError:
    if sys.argv[2] == "ip" or not re.fullmatch(r"([0-9a-z]([0-9a-z-]{0,61}[0-9a-z])?\.)+[a-z]{2,63}", a.lower()):
        sys.exit(1)
' "$1" "$2"
}
# адрес для записи сторожа: агент слушает только IPv4 (0.0.0.0), до адреса IPv6 сторож не достучится
check_public() {
  valid_addr "$1" any || { echo "«$1» — не адрес и не имя" >&2; exit 1; }
  case "$1" in
    *:*) echo "«$1» — адрес IPv6, а агент слушает только IPv4: укажите внешний адрес IPv4 или имя с записью A" >&2
         exit 1 ;;
  esac
}
# адрес не из интернета: частный, CGNAT 100.64/10, локальный
not_global() { python3 -c 'import ipaddress, sys; sys.exit(0 if not ipaddress.ip_address(sys.argv[1]).is_global else 1)' "$1" 2>/dev/null; }

if [ "$mode" = entry ]; then
  if [ -n "$public" ]; then check_public "$public"; fi
  python3 - "$ETC/agent.json" "${rucheck:-0}" "$public" "$ETC/cert.pem" <<'PY'
import hashlib, ipaddress, json, ssl, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
public = sys.argv[3] or c["public"]
e = {"name": c["name"], "url": "http://%s:%d" % ("[%s]" % public if ":" in public else public, c["port"]),
     "token": c["token"]}
# url остаётся http:// — старый сторож ходит как раньше; новый по "sha256" идёт на тот же порт по TLS
try:
    e["sha256"] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[4], encoding="ascii").read())).hexdigest()
except (OSError, ValueError):
    pass
if c.get("vpn"):
    e["vpn"] = True  # VPN-точка (агент с собственным клиентом Xray): сторож будет проверять через неё плитки
if sys.argv[2] == "1":
    e["rucheck"] = True  # сервисы для сверки шаблона с блокировками проверяются с этой точки
try:
    private = not ipaddress.ip_address(public).is_global
except ValueError:
    private = False
if private:
    print("внимание: адрес точки %s — частный (точка за NAT), сторож до него не дойдёт. Пробросьте порт %d на "
          "роутере и укажите внешний адрес: --public АДРЕС" % (public, c["port"]), file=sys.stderr)
print(json.dumps(e, ensure_ascii=False))
PY
  exit 0
fi

# правило ufw из файла: словами, без раскрытия шаблонов и без sh -c
ufw_delete_saved() {
  [ -s "$ETC/ufw-rule" ] && command -v ufw >/dev/null || return 0
  local r
  read -ra r < "$ETC/ufw-rule"
  [ "${r[0]:-}" = allow ] && ufw delete "${r[@]}" >/dev/null 2>&1 || true
}

if [ "$mode" = uninstall ]; then
  systemctl disable --now vantage-agent.service 2>/dev/null || true
  ufw_delete_saved
  rm -rf "$DIR" "$ETC" "$UNIT"
  systemctl daemon-reload
  echo "точка проверки убрана"; exit 0
fi

. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "внимание: рассчитано на Ubuntu 24.04 / 26.04, здесь ${PRETTY_NAME:-неизвестная система}" ;;
esac
for f in vantage_agent.py netprobe.py; do [ -s "$SRC/$f" ] || { echo "рядом со скриптом нет $f"; exit 1; }; done
command -v python3 >/dev/null || { apt-get update -qq; apt-get install -y -qq python3; }

# при повторной установке не заданное сейчас берётся из прежних настроек
if [ -s "$ETC/agent.json" ]; then
  while IFS=$'\t' read -r k v; do
    case "$k" in
      allow) [ -n "$allow" ] || allow="$v" ;;
      port) [ -n "$port" ] || port="$v" ;;
      name) [ -n "$name" ] || name="$v" ;;
      suffixes) [ -n "$suffix" ] || suffix="$v" ;;
      public_ext) [ -n "$public" ] || public="$v" ;;
    esac
  done < <(python3 - "$ETC/agent.json" <<'PY'
import json, sys
try:
    c = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    c = {}
for k, v in (("allow", (c.get("allow") or [""])[0]), ("port", c.get("port", "")), ("name", c.get("name", "")),
             ("suffixes", ",".join(c.get("suffixes") or [])), ("public_ext", c.get("public_ext", ""))):
    v = str(v)
    if v and "\t" not in v and "\n" not in v:
        print("%s\t%s" % (k, v))
PY
)
fi
port="${port:-9109}"
# домены — свои, обязательно; при повторной установке берутся из прежних настроек
[ -n "$suffix" ] || { echo "укажите --suffix: ваши домены через запятую (на других именах агент проверять не будет)"; exit 2; }

if [ -z "$allow" ]; then
  [ "$yes" -eq 0 ] || { echo "нужен адрес сервера сторожа: --allow IP"; exit 1; }
  read -r -p "Адрес сервера, где стоит сторож (ему одному агент будет отвечать): " allow
fi
valid_addr "$allow" ip || { echo "«$allow» — не адрес (нужен IP без зоны «%» и пробелов)"; exit 1; }
if [ "$yes" -eq 0 ]; then
  read -r -p "Порт агента [$port]: " x; port="${x:-$port}"
  read -r -p "Как называть эту точку в сообщениях сторожа [${name:-$(hostname)}]: " x; name="${x:-$name}"
fi
name="${name:-$(hostname)}"
case "$port" in ''|*[!0-9]*) echo "порт должен быть числом"; exit 1 ;; esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "порт должен быть от 1 до 65535"; exit 1; }
if ss -Hltn "( sport = :$port )" | grep -q . && ! systemctl is-active --quiet vantage-agent.service; then
  echo "порт $port уже занят другой программой — укажите свободный: --port N"; exit 1
fi
local_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | cut -d' ' -f2)"
[ -n "$local_ip" ] || { echo "не удалось узнать свой адрес"; exit 1; }
if [ -n "$public" ]; then
  check_public "$public"
elif not_global "$local_ip"; then
  # точка за NAT: сторож дойдёт только до внешнего адреса роутера с пробросом порта
  echo "внимание: адрес этой машины $local_ip — частный (точка за NAT). Сторож дойдёт до неё, только если на роутере"
  echo "  порт $port проброшен сюда, а в записи для сторожа стоит внешний адрес роутера."
  if [ "$yes" -eq 0 ]; then
    read -r -p "Внешний адрес или имя, где проброшен порт $port (Enter — оставить $local_ip): " x
    if [ -n "$x" ]; then check_public "$x"; public="$x"; fi
  else
    echo "  укажите его: --public АДРЕС (сейчас в записи для сторожа будет $local_ip)"
  fi
fi

install -d -m 755 "$DIR"
install -d -m 700 -o root -g root "$ETC"
install -m 644 "$SRC/vantage_agent.py" "$SRC/netprobe.py" "$DIR/"
# проверка сервисов для сверки шаблона (/services) — если rucheck.py лежит рядом
if [ -s "$SRC/rucheck.py" ]; then install -m 644 "$SRC/rucheck.py" "$DIR/"; fi

# сертификат TLS: самоподписанный, создаётся один раз; сторож закрепит его по отпечатку sha256
if [ ! -s "$ETC/cert.pem" ] || [ ! -s "$ETC/key.pem" ]; then
  command -v openssl >/dev/null || { apt-get update -qq; apt-get install -y -qq openssl; }
  ( umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
      -subj "/CN=vantage-agent" -keyout "$ETC/key.pem.tmp" -out "$ETC/cert.pem.tmp" >/dev/null 2>&1 ) \
    && mv -f "$ETC/key.pem.tmp" "$ETC/key.pem" && mv -f "$ETC/cert.pem.tmp" "$ETC/cert.pem" \
    || { rm -f "$ETC/key.pem.tmp" "$ETC/cert.pem.tmp"; echo "внимание: сертификат TLS не создан — агент будет только по HTTP"; }
fi
tls=0; [ -s "$ETC/cert.pem" ] && [ -s "$ETC/key.pem" ] && tls=1
[ "$tls_only" != 1 ] || [ "$tls" = 1 ] || { echo "--tls-only без сертификата нельзя"; exit 1; }
[ "$tls" = 0 ] || { chmod 600 "$ETC/key.pem"; chmod 644 "$ETC/cert.pem"; }

python3 - "$ETC/agent.json" "$allow" "$port" "$name" "$suffix" "$local_ip" "$ports" "$hosts" "$snis" "$public" "$tls_only" "$allow_given" <<'PY'
import json, os, secrets, sys
path, allow, port, name, suffix, local_ip, ports, hosts, snis, public, tls_only, allow_given = sys.argv[1:13]
items = lambda text: [x.strip().lower() for x in text.split(",") if x.strip()]
try:
    cfg = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError):
    cfg = {}
cfg.setdefault("token", secrets.token_urlsafe(32))
# --allow заменяет список; без него прежний список остаётся целиком (переезд сторожа: старый и новый адрес)
old = [x for x in (cfg.get("allow") or []) if isinstance(x, str) and x]
allow_list = [allow] if allow_given == "1" or not old else [allow] + [x for x in old if x != allow]
cfg.update(allow=allow_list, port=int(port), name=name, public=public or local_ip, suffixes=items(suffix))
if public:
    cfg["public_ext"] = public  # задан вручную (--public): при повторной установке не заменяется найденным
# порты, адреса и имена TLS: заданные сейчас — заменяют прежние; не заданные — остаются как были
cfg["ports"] = [int(x) for x in items(ports)] if ports else cfg.get("ports", [443])
for key, text in (("hosts", hosts), ("snis", snis)):
    if text:
        cfg[key] = items(text)
if tls_only:
    cfg["tls_only"] = tls_only == "1"
fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=1)
os.chmod(path + ".tmp", 0o600)
os.replace(path + ".tmp", path)
PY
chown root:root "$ETC/agent.json"
public="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["public"])' "$ETC/agent.json")"

# настройки и ключ — только root; службе их передаёт systemd (LoadCredential), её пользователь временный
creds="LoadCredential=agent.json:$ETC/agent.json"
[ "$tls" = 0 ] || creds="$creds
LoadCredential=cert.pem:$ETC/cert.pem
LoadCredential=key.pem:$ETC/key.pem"
cat > "$UNIT" <<EOF
[Unit]
Description=vantage-agent: точка проверки для сторожа каналов (отвечает только сторожу)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/vantage-agent/vantage_agent.py
DynamicUser=yes
$creds
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
MemoryMax=64M
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vantage-agent.service >/dev/null 2>&1
systemctl restart vantage-agent.service

fw="файрвол ufw не включён — порт $port открыт всем (чужим адресам агент обрывает соединение, не читая запрос)"
rule="allow from $allow to any port $port proto tcp"
if command -v ufw >/dev/null; then
  # прежнее правило (другой адрес сторожа или порт) — убрать, иначе оно останется навсегда
  if [ -s "$ETC/ufw-rule" ] && [ "$(cat "$ETC/ufw-rule")" != "$rule" ]; then ufw_delete_saved; rm -f "$ETC/ufw-rule"; fi
  if [ "$(LC_ALL=C ufw status | awk 'NR==1{print $2}')" = active ]; then  # без перевода: «Status: active»
    echo "$rule" > "$ETC/ufw-rule"
    read -ra r <<< "$rule"
    ufw "${r[@]}" comment 'vantage-agent: watchdog only' >/dev/null
    fw="в ufw порт $port открыт только для $allow"
  fi
fi

sleep 2
code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health" || true)"
tcode="-"; fp=""
if [ "$tls" = 1 ]; then
  tcode="$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$port/health" || true)"
  fp="$(openssl x509 -in "$ETC/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')"
fi
mode_txt="HTTP и TLS"; [ "$tls" = 1 ] || mode_txt="только HTTP"
[ "$(python3 -c 'import json, sys; print(int(bool(json.load(open(sys.argv[1])).get("tls_only"))))' "$ETC/agent.json")" = 0 ] \
  || mode_txt="только TLS (HTTP — лишь с 127.0.0.1)"
echo "== $(hostname): служба $(systemctl is-active vantage-agent.service), слушает $public:$port ($mode_txt); $fw"
echo "   самопроверка: чужой запрос без токена получил ответ $code по HTTP, $tcode по TLS (должно быть 403)"
[ -z "$fp" ] || echo "   отпечаток сертификата sha256: $fp"
echo "   запись для сторожа: bash $0 --entry  (в ней токен — передавать конвейером, не выводить на экран)"
[ "$code" = 403 ] || { echo "   агент отвечает не так, как должен: journalctl -u vantage-agent -n 20"; exit 1; }
[ "$tls" = 0 ] || [ "$tcode" = 403 ] || { echo "   TLS не отвечает: journalctl -u vantage-agent -n 20"; exit 1; }
