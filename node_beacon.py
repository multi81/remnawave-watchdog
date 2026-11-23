#!/usr/bin/env python3
"""node-beacon: маячок состояния ноды для сторожа каналов (запуск по таймеру раз в 10 минут, от root).

Пишет в файл (путь — первый аргумент) небольшой JSON: диск, память, ждёт ли сервер перезагрузки, версии ядра и Xray,
включён ли файрвол, сколько было неудачных входов по SSH за сутки и сколько пакетов отбил файрвол (счётчики с момента
загрузки правил — сторож сам считает разницу). Ничего не меняет на сервере и никуда не ходит: файл забирает сторож.
Секретов в файле нет.

С 22.11.2026 ещё:
  tune   — сетевой профиль (BBR, очередь fq, таблица соединений, MPTCP и его живые слушатели в сети хоста
           и в контейнерах со своей сетью, synflood): сторож пишет,
           если профиль слетел;
  dns    — свой резолвер Unbound (node_dns.sh): работает ли, на нём ли система, кэш, очередь, уходы на запасной;
           с 23.11 и режим «запасной на каждый запрос» (mode="per-query"): current — реальный путь запросов программ
           по /etc/resolv.conf, а не сервер systemd-resolved; nameservers, resolv_foreign, resolv_card, xray_resolv;
  knocks — кто за сутки стучался в закрытые порты (по журналу ufw, только SYN): адрес, сколько разных портов, сколько
           раз, стучался ли на 80/443/8443. Из этого сторож собирает свой список сканеров «по поведению».

Песочница юнита (beacon_install.sh) ставит ProtectHome=yes: на ноде, где docker настроен своим context в /root/.docker
(docker context use), docker CLI его не увидит, и поля xray и mptcp_listeners_ct будут None. Там ставить маячок с ключом
--home-ro (ProtectHome=read-only).
"""
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time


def proc(cmd, timeout=20):
    """(код возврата, stdout, stderr); не запустилась или не уложилась во время — (None, "", "")."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return None, "", ""


def run(cmd, timeout=20):
    return proc(cmd, timeout)[1]


def have(cmd):
    return shutil.which(cmd) is not None


def meminfo():
    info = {}
    for line in open("/proc/meminfo"):
        key, value = line.split(":", 1)
        info[key] = int(value.split()[0]) // 1024  # МБ
    return info


def packets(chain, pattern):
    """Сколько пакетов прошло по правилам цепочки, в строке которых есть pattern и действие DROP/REJECT."""
    total = 0
    for line in run(["iptables", "-L", chain, "-v", "-n", "-x"]).splitlines()[2:]:
        parts = line.split()
        if len(parts) > 2 and parts[2] in ("DROP", "REJECT") and pattern in line and parts[0].isdigit():
            total += int(parts[0])
    return total


def policy_drops():
    """Пакеты, которые не подошли ни под одно разрешающее правило: счётчик политики DROP цепочки INPUT."""
    first = run(["iptables", "-L", "INPUT", "-v", "-n", "-x"]).splitlines()[:1]
    m = re.search(r"policy DROP (\d+) packets", first[0]) if first else None
    return int(m.group(1)) if m else None


def sysctl(key):
    try:
        v = open("/proc/sys/" + key.replace(".", "/")).read().strip()
        return int(v) if v.lstrip("-").isdigit() else v
    except OSError:
        return None


PROC_MPTCP = "/proc/sys/net/mptcp"   # нет — ядро без MPTCP
SYS_MODULE = "/sys/module"
MODULES = "/lib/modules"


def mptcp_diag():
    """Есть ли в ядре mptcp_diag. Без него ss -M молча отдаёт пустой список с кодом 0 (ошибку ENOENT от netlink ss не
    печатает) — ложный ноль. Модуль сами не грузим: первый ss -M просит ядро подгрузить его само, поэтому проверять
    после ss. Модуль загружен — есть /sys/module/mptcp_diag; встроен в ядро — строка в modules.builtin."""
    if os.path.isdir(os.path.join(SYS_MODULE, "mptcp_diag")):
        return True
    try:
        with open(os.path.join(MODULES, os.uname().release, "modules.builtin")) as f:
            return any(ln.strip().endswith("/mptcp_diag.ko") for ln in f)
    except (OSError, AttributeError):
        return False


def is_root():
    geteuid = getattr(os, "geteuid", None)   # на Windows (тесты) его нет
    return geteuid is not None and geteuid() == 0


def ulp_mptcp(out):
    """Сколько слушателей в выводе ss -H -tlni помечены tcp-ulp-mptcp: строка сокета, под ней строка сведений
    (с отступом) — как awk в mptcp_ss из node_tune.sh."""
    n, sock = 0, False
    for ln in out.splitlines():
        if ln[:1] in (" ", "\t"):
            if sock and "tcp-ulp-mptcp" in ln:
                n += 1
            sock = False
        else:
            sock = bool(ln.strip())
    return n


def ss_mptcp(prefix=(), timeout=20):
    """Сколько сокетов слушают MPTCP (prefix — например, nsenter в сеть контейнера), как mptcp_ss в node_tune.sh.
    Основной способ — TCP-подпоток слушателя с пометкой tcp-ulp-mptcp (ss -H -tlni): её ядро показывает root и без
    модуля mptcp_diag (в Ubuntu он в linux-modules-extra, на облачных образах его нет). Пометок нет — запасной ss -H
    -lMn: без mptcp_diag он молча отдаёт пусто с кодом 0, поэтому его пусто верно только при mptcp_diag. None — ни тот,
    ни другой не дал надёжного ответа: таймаут, ss нет или ошибка, пусто не от root и без mptcp_diag."""
    rc, out, _ = proc(list(prefix) + ["ss", "-H", "-tlni"], timeout)
    if rc is None:
        return None   # ss не ответил вовремя (или его нет) — второй раз не ждём
    n = ulp_mptcp(out) if rc == 0 else 0
    if n:
        return n
    rc2, out2, err2 = proc(list(prefix) + ["ss", "-H", "-lMn"], timeout)
    m = len([ln for ln in out2.splitlines() if ln.strip()]) if rc2 == 0 else 0
    if m:
        return m
    if rc == 0 and is_root():
        return 0   # пометку ULP root видит всегда: пусто — слушателей нет
    if rc2 == 0 and not err2.strip() and mptcp_diag():
        return 0
    return None


def mptcp_listeners():
    """Сколько сокетов слушают MPTCP в сети хоста. sysctl 0 запрещает только новые: старые слушатели (Xray на Go 1.24+
    включает MPTCP сам) живут до перезапуска владельца. Считаем при любом net.mptcp.enabled. None — не узнать."""
    if not os.path.isdir(PROC_MPTCP):
        return None
    return ss_mptcp()


CT_MAX_S = 30   # на обход контейнеров не больше стольких секунд (юнит маячка ждёт 120)


def mptcp_listeners_ct():
    """MPTCP-слушатели в контейнерах со своей сетью (как node_tune.sh: docker ps → не host → nsenter -n и ss_mptcp; из
    сети хоста ss их не видит, а в их сети net.mptcp.enabled свой, обычно 1). {имя: N}, только ненулевые; None — docker
    нет или не узнать."""
    if not have("docker") or not os.path.isdir(PROC_MPTCP):
        return None
    rc, ids, _ = proc(["docker", "ps", "-q"], timeout=10)
    if rc != 0:
        return None
    ids = ids.split()
    if not ids:
        return {}
    if not have("nsenter"):
        return None
    _, info, _ = proc(["docker", "inspect", "-f", "{{.Name}} {{.HostConfig.NetworkMode}} {{.State.Pid}}"] + ids,
                      timeout=10)   # контейнер мог исчезнуть после ps — код не 0, остальные строки годятся
    out, start = {}, time.monotonic()
    for line in info.splitlines():
        f = line.split()
        if len(f) != 3 or f[1] == "host" or f[1].startswith("container:") or not f[2].isdigit() or f[2] == "0":
            continue
        if time.monotonic() - start > CT_MAX_S:
            break
        k = ss_mptcp(["nsenter", "-t", f[2], "-n"], timeout=5)
        if k:
            out[f[0].lstrip("/")[:64]] = k
    return out


def tune():
    """Сетевой профиль ноды как есть (node_tune.sh ставит: bbr, fq, conntrack 100000, mptcp 0, synack 2, fin 15)."""
    dev = (run(["ip", "-o", "route", "show", "default"]).split(" dev ") + [""])[1].split(" ")[0]
    q = run(["tc", "qdisc", "show", "dev", dev]) if dev else ""
    qdisc = "fq" if re.search(r"^qdisc fq ", q, re.M) else (q.split() + ["", "?"])[1] if q else None
    return {"cc": sysctl("net.ipv4.tcp_congestion_control"), "qdisc": qdisc,
            "conntrack_max": sysctl("net.netfilter.nf_conntrack_max"), "mptcp": sysctl("net.mptcp.enabled"),
            "synack": sysctl("net.ipv4.tcp_synack_retries"), "fin_timeout": sysctl("net.ipv4.tcp_fin_timeout"),
            "mptcp_listeners": mptcp_listeners(), "mptcp_listeners_ct": mptcp_listeners_ct()}


KNOCK_PORTS = {80, 443, 8443}   # стук сюда при закрытом порте — почти наверняка сканер (клиенты сюда не ходят мимо правил)
KNOCK_MAX = 400                 # не больше стольких адресов в файле (маячок читается целиком, до 64 КБ)
KNOCK_MAX6 = 100                # из них строк IPv6 (/64) не больше — чтобы IPv6 не вытеснил IPv4
LINE_MAX = 1024                 # строка iptables LOG короче; длиннее — чужое сообщение в журнале, не разбираем
UFW_TAG = "[UFW BLOCK] "
UFW_KEYS = ("SRC", "DST", "PROTO", "DPT", "RES", "URGP")   # поля строки iptables LOG, которые нужны (каждое — один раз)
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def ufw_kernel(ln):
    """Строка ядра от ufw: «… kernel: … [UFW BLOCK] …». Остальное в журнале (logger, чужие службы) — не наше."""
    i = ln.find(UFW_TAG)
    return i > 0 and 0 <= ln.find(" kernel: ") < i


def ufw_syn(ln):
    """(адрес, порт назначения) из строки iptables LOG, если это TCP SYN без ACK; иначе None. Один проход по полям
    ключ=значение (split, без регулярки — время линейное и на поддельной строке). Флаги TCP — слова без «=» между
    RES=0x.. и URGP=; SYN-ACK — ответы на чужие запросы (отражение), не стук. Поле дважды — строка чужая, пропуск."""
    if len(ln) > LINE_MAX or not ufw_kernel(ln):
        return None
    f, flags, in_flags = {}, [], False
    for w in ln[ln.find(UFW_TAG) + len(UFW_TAG):].split():
        k, eq, v = w.partition("=")
        if not eq:
            if in_flags:
                flags.append(w)
            continue
        if k in UFW_KEYS:
            if k in f:
                return None
            f[k] = v
        if k == "RES":
            in_flags = True
        elif k == "URGP":
            break
    if "URGP" not in f or not f.get("RES", "").startswith("0x") or f.get("PROTO") != "TCP" or not f.get("SRC"):
        return None
    dpt = f.get("DPT", "")
    if not (dpt.isdigit() and len(dpt) <= 5) or "SYN" not in flags or "ACK" in flags:
        return None
    return f["SRC"], int(dpt)


def knock_ts(ln, now):
    """Время строки журнала: ISO (2026-11-22T00:00:05.009+00:00) или классическое «Nov 22 00:00:05» (местное, год текущий;
    1 января строки «Dec 31» из ufw.log.1 оказались бы в будущем — тогда год прошлый)."""
    try:
        if ln[:4].isdigit():
            return dt.datetime.fromisoformat(ln.split()[0]).timestamp()
        year = time.localtime(now).tm_year
        ts = time.mktime(time.strptime("%d %s" % (year, ln[:15]), "%Y %b %d %H:%M:%S"))
        if ts > now + 86400:
            ts = time.mktime(time.strptime("%d %s" % (year - 1, ln[:15]), "%Y %b %d %H:%M:%S"))
        return ts
    except (ValueError, IndexError, OverflowError):
        return None


def public_ip(s):
    """Адрес в коротком виде, если он публичный; частные, 100.64/10, 169.254/16, петля, мультикаст, мусор — None.
    ::ffff:a.b.c.d и 64:ff9b::a.b.c.d (NAT64) — это IPv4: приводим к нему и проверяем уже его."""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 6:
        if a.ipv4_mapped:
            a = a.ipv4_mapped
        elif a in NAT64:
            a = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
    return str(a) if a.is_global and not a.is_multicast else None


def knock_key(ip):
    """IPv4 как есть, IPv6 — первый адрес его /64 (так же блокирует щит: адрес внутри /64 сканер меняет сам)."""
    if ":" not in ip:
        return ip
    return str(ipaddress.ip_network(ip + "/64", strict=False).network_address)


def knocks(lines, now, since=86400):
    """[[адрес, разных портов, стуков, 1 если стучался на 80/443/8443], …] — сначала самые подозрительные. IPv6 — строка на
    /64 (её первый адрес, порты и стуки всей /64 вместе), таких строк не больше KNOCK_MAX6."""
    src = {}
    for ln in lines:
        m = ufw_syn(ln)
        if m is None:
            continue
        ts = knock_ts(ln, now)
        if ts is None or now - ts > since:
            continue
        ip, port = public_ip(m[0]), m[1]
        if ip is None:
            continue
        v = src.setdefault(knock_key(ip), [set(), 0])
        v[0].add(port)
        v[1] += 1
    out = [[ip, len(p), n, int(bool(p & KNOCK_PORTS))] for ip, (p, n) in src.items()]
    out.sort(key=lambda r: (-r[3], -r[1], -r[2]))
    res, n6 = [], 0
    for r in out:
        if ":" in r[0]:
            if n6 >= KNOCK_MAX6:
                continue
            n6 += 1
        res.append(r)
        if len(res) >= KNOCK_MAX:
            break
    return res


UCONF = "/etc/unbound/unbound.conf.d/storozh.conf"
RESOLV = "/etc/resolv.conf"
DNS_BAK = "/root/node-dns-backup"            # dns.env и флаги таймера; под ProtectHome=yes маячку не видна
DNS_LOG = "/var/log/storozh-unbound.log"
RMARK = "# storozh-per-query: этим файлом управляет node_dns.sh"   # первая строка своего resolv.conf (как в node_dns.sh)
LOG_FRESH = 1800   # «Unbound не отвечает» таймер пишет каждый прогон (10 мин), пока не ответит: старше 30 мин — уже не так


def nameservers(text):
    return [ln.split()[1] for ln in text.splitlines() if ln.split()[:1] == ["nameserver"] and len(ln.split()) > 1]


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def unbound_answers(srv="127.0.0.1", timeout=2):
    """Отвечает ли Unbound на 127.0.0.1:53 (запрос localhost — своя зона Unbound, наружу не ходит). Как glibc с
    timeout:2: молчит или отказал (REFUSED, SERVFAIL) — программы уходят на запасной."""
    import random
    import socket
    import struct
    q = struct.pack(">HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0) + b"\x09localhost\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (srv, 53))
        r = s.recv(1500)
        return r[:2] == q[:2] and bool(r[2] & 0x80) and r[3] & 15 in (0, 3)
    except OSError:
        return False
    finally:
        s.close()


def pq_log_state(lines, now):
    """Что таймер в режиме per-query написал последним (когда /root маячку не виден): (Unbound не отвечает,
    адреса DNS карт за 127.0.0.1 или None)."""
    down, card = False, None
    for ln in lines:
        if "Unbound не отвечает (3 попытки)" in ln:
            try:
                down = now - dt.datetime.strptime(ln[:19], "%Y-%m-%dT%H:%M:%S").replace(
                    tzinfo=dt.timezone.utc).timestamp() <= LOG_FRESH
            except ValueError:
                down = False
        elif "вернула запросы на Unbound" in ln:
            down = False
        if "за 127.0.0.1 поставлены DNS карты " in ln:
            card = ln.split("поставлены DNS карты ", 1)[1].split(" (", 1)[0].split()
        elif "(DNS карты убраны)" in ln:
            card = None
    return down, card


def docker_resolv():
    """Первый nameserver в копии resolv.conf контейнера remnanode (её Docker пишет при старте контейнера; Xray в сети
    хоста ходит по ней, а не по /etc/resolv.conf хоста) и сеть контейнера. Без docker exec: путь — docker inspect,
    файл читается с диска. Нет контейнера — (None, None)."""
    code, out, _ = proc(["docker", "inspect", "-f", "{{.ResolvConfPath}}|{{.HostConfig.NetworkMode}}|{{.State.Running}}",
                         "remnanode"])
    if code != 0 or out.count("|") < 2:
        return None, None
    path, net, running = out.strip().split("|", 2)
    if running != "true":
        return None, None   # контейнер стоит — Xray не работает, его копия ни о чём не говорит
    text = read_text(path) if path else None
    ns = nameservers(text) if text is not None else []
    return (ns[0] if ns else None), (net or None)


def dns(now=None):
    """Свой резолвер Unbound (node_dns.sh): работает ли, на нём ли система, кэш, очередь, уходы на запасной. Нет — None.

    Режим «запасной на каждый запрос» (node_dns.sh install --per-query): программы идут не в systemd-resolved, а по
    /etc/resolv.conf (127.0.0.1 первым, за ним запасные) — current тогда реальный путь запросов: 127.0.0.1, пока Unbound
    отвечает; не отвечает (флаг таймера unbound-down, его строка в журнале или сам не ответил на запрос) — первый
    запасной. resolved — сервер systemd-resolved (для сведения: в этом режиме им почти никто не пользуется).
    resolv_foreign — /etc/resolv.conf не свой (подменили до прогона таймера); resolv_replaced_24h — сколько раз за сутки
    таймер находил его подменённым; resolv_card — за 127.0.0.1 стоят DNS карты (молчали Unbound и запасные);
    xray_resolv — первый nameserver в копии resolv.conf контейнера remnanode.
    Песочница маячка (ProtectHome=yes) прячет /root: dns.env и флаги не видны — режим тогда по метке файла, «Unbound
    не отвечает» и DNS карты — по журналу таймера; подменённый файл без метки там не отличить от обычного режима."""
    if not os.path.exists(UCONF):
        return None
    now = time.time() if now is None else now
    st = {}
    for line in run(["unbound-control", "stats_noreset"]).splitlines():
        k, _, v = line.partition("=")
        try:
            st[k] = float(v)
        except ValueError:
            pass
    conf = read_text(UCONF) or ""

    def size_mb(key, default):
        m = re.search(r"^\s*%s:\s*(\d+)([kmg]?)" % key, conf, re.M | re.I)
        if not m:
            return default
        return int(m.group(1)) * {"": 1 / 1048576, "k": 1 / 1024, "m": 1, "g": 1024}[m.group(2).lower()]

    m = re.search(r"Current DNS Server:\s*(\S+)", run(["resolvectl", "status"]))
    resolved = m.group(1) if m else None
    since = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(now - 86400))
    log = read_text(DNS_LOG)
    lines = log.splitlines() if log is not None else []
    fb = sum(1 for ln in lines if ln[:16] >= since and "вернула" in ln)
    g = lambda k: int(st[k]) if k in st else None
    active = run(["systemctl", "is-active", "unbound"]).strip() == "active"
    out = {"active": active, "current": resolved,
           "queries": g("total.num.queries"), "hits": g("total.num.cachehits"), "exceeded": g("total.requestlist.exceeded"),
           "servfail": g("num.answer.rcode.SERVFAIL"), "uptime": g("time.up"),
           "rrset_mb": round(st.get("mem.cache.rrset", 0) / 1048576, 1), "rrset_max_mb": size_mb("rrset-cache-size", 4),
           "msg_mb": round(st.get("mem.cache.message", 0) / 1048576, 1), "msg_max_mb": size_mb("msg-cache-size", 4),
           "fallback_24h": fb}

    # режим: dns.env (PER_QUERY=yes), а если /root не виден (ProtectHome=yes) — метка первой строки /etc/resolv.conf
    bak = os.path.isdir(DNS_BAK) and os.access(DNS_BAK, os.R_OK | os.X_OK)
    env = read_text(os.path.join(DNS_BAK, "dns.env")) if bak else None
    pq_env = None if env is None else (re.search(r"^PER_QUERY=yes\s*$", env, re.M) is not None)
    rtext = read_text(RESOLV)
    ours = not os.path.islink(RESOLV) and rtext is not None and rtext.split("\n", 1)[0].rstrip("\r") == RMARK
    mode_file = (read_text("/etc/node-dns.mode") or "").strip() == "per-query"   # виден и из песочницы
    if pq_env is None and mode_file:
        pq_env = True
    if not (pq_env or (pq_env is None and ours)):
        return out   # обычный режим — поля как раньше
    # в этом режиме программы resolved не спрашивают: его прежние «уходы» («resolved был на … — вернула») к делу не
    # относятся — считаем только настоящие возвраты после отказа Unbound
    out["fallback_24h"] = sum(1 for ln in lines if ln[:16] >= since and "вернула" in ln and "resolved был на" not in ln)
    ns = nameservers(rtext or "")
    if bak and env is not None:
        down = os.path.exists(os.path.join(DNS_BAK, "unbound-down"))
        card = (read_text(os.path.join(DNS_BAK, "resolv-card")) or "").split() or None
    else:
        down, card = pq_log_state(lines, now)
        if card and ns[1:] != card:
            card = None   # строка в журнале старая: в файле уже не DNS карты
    alive = active and not down and unbound_answers()
    if ours and ns:
        spare = [a for a in ns if a != "127.0.0.1"]
        current = ns[0] if (ns[0] != "127.0.0.1" or alive) else (spare[0] if spare else None)
    else:
        current = ns[0] if ns else None   # чужой файл: запросы идут туда, что в нём первым
    # подмену таймер исправляет за 10 мин — маячок её застаёт редко; строки таймера видны и из песочницы
    replaced = sum(1 for ln in lines if ln[:16] >= since and "/etc/resolv.conf был подменён" in ln)
    out.update({"mode": "per-query", "current": current, "resolved": resolved, "nameservers": ns,
                "unbound_ok": alive, "resolv_foreign": not ours, "resolv_card": card, "resolv_replaced_24h": replaced})
    xr, net = docker_resolv()
    if xr is not None or net is not None:
        out["xray_resolv"] = xr
        out["xray_net"] = net
    return out


UFW_LOGS = ("/var/log/ufw.log.1", "/var/log/ufw.log")


def ufw_lines(paths=UFW_LOGS):
    out = []
    for f in paths:
        try:
            with open(f, errors="replace") as fh:
                out += [ln for ln in fh if ufw_kernel(ln)]   # только строки ядра
        except OSError:
            pass
    return out


def collect():
    disk = os.statvfs("/")
    mem = meminfo()
    xray = run(["docker", "exec", "remnanode", "sh", "-c",
                "for b in /usr/local/bin/xray /usr/local/bin/rw-core xray; do $b version 2>/dev/null && break; done"])
    m = re.search(r"Xray (\S+)", xray)
    ssh_fail = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "24 hours ago", "--no-pager", "-q",
                    "-g", "Failed password"], timeout=60)
    conn = [int(open(f"/proc/sys/net/netfilter/nf_conntrack_{k}").read()) if os.path.exists(
        f"/proc/sys/net/netfilter/nf_conntrack_{k}") else None for k in ("count", "max")]
    return {
        "ts": int(time.time()),
        # как в df: занято / (занято + доступно), без учёта резерва файловой системы
        "disk_pct": round(100.0 * (disk.f_blocks - disk.f_bfree) / (disk.f_blocks - disk.f_bfree + disk.f_bavail)),
        "disk_free_mb": disk.f_bavail * disk.f_frsize // 1048576,
        "mem_total_mb": mem.get("MemTotal"), "mem_avail_mb": mem.get("MemAvailable"),
        "swap_used_mb": mem.get("SwapTotal", 0) - mem.get("SwapFree", 0),
        "load1": round(os.getloadavg()[0], 2),
        "uptime_s": int(float(open("/proc/uptime").read().split()[0])),
        "reboot_required": os.path.exists("/var/run/reboot-required"),
        "kernel": os.uname().release,
        "xray": m.group(1) if m else None,
        "ufw": (run(["ufw", "status"]).split("\n", 1)[0].split(":")[-1].strip() or None),
        "ssh_fail_24h": len([line for line in ssh_fail.splitlines() if "Failed password" in line]),
        "drops": {"policy": policy_drops(), "geo": packets("ufw-before-input", "reshala_geoblock"),
                  "scan": packets("SCANNERS-BLOCK", "SCANNERS"), "crowdsec": packets("CROWDSEC_CHAIN", "match-set")},
        "finwait2": len(run(["ss", "-Htn", "state", "fin-wait-2"]).splitlines()),
        "conntrack": conn,
        "failed_units": [line.split()[0] for line in run(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines() if line.split()],
        "tune": tune(),
        "knocks": knocks(ufw_lines(), time.time()),
        "dns": dns(),
    }


def write_state(out, data):
    """Записать JSON через свой временный файл: mkstemp создаёт его сам (O_EXCL, чужая ссылка с тем же именем не
    подойдёт), права ставятся по дескриптору, не по имени. Папка сайта может быть доступна на запись не только root."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(out)), prefix=".beacon-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(data, f)
        os.replace(tmp, out)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    write_state(sys.argv[1], collect())
