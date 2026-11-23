"""Тесты: маячок ноды и пометки сторожа. Разбор ufw.log (только SYN без ACK,
IPv6, длинные и «злые» строки), частные адреса через ipaddress (мультикаст, ::ffff:, 64:ff9b::), IPv6 по /64 и не больше
100 строк, год в классическом syslog, MPTCP (слушатели хоста и контейнеров, ложный ноль без mptcp_diag), запись
файла маячка и песочница юнита в beacon_install.sh. Ещё: MPTCP основным способом ss -tlni + tcp-ulp-mptcp
(блок U), ufw.log — только строки ядра и разбор полей без регулярки (блок N), reset-failed при --uninstall и ключ
--home-ro (S7–S9). Без сети."""
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import node_beacon as nb  # noqa: E402
import nodewatch as nw  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


def ufw(src, dpt, flags="SYN", stamp="2026-11-22T10:00:00.000000+00:00", v6=False):
    """Строка ufw.log как её пишет iptables LOG (ISO-время rsyslog или классическое «Nov 22 10:00:00»)."""
    ip = ("LEN=80 TC=0 HOPLIMIT=57 FLOWLBL=0" if v6 else "LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF")
    return (f"{stamp} node1 kernel: [123.456] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:aa:bb:cc:52:54:00:dd:ee:ff:08:00 "
            f"SRC={src} DST=198.51.100.7 {ip} PROTO=TCP SPT=44321 DPT={dpt} WINDOW=64240 RES=0x00 {flags} URGP=0\n")


NOW = 1795341600.0   # 2026-11-22T10:00:00Z; строки ниже — за 10 минут до этого
ISO = "2026-11-22T09:50:00.000000+00:00"

# --- только SYN без ACK ---
r = nb.knocks([ufw("45.83.64.5", 22, stamp=ISO), ufw("45.83.64.5", 443, stamp=ISO)], NOW)
check("K1 чистый SYN считается", r == [["45.83.64.5", 2, 2, 1]])
refl = [ufw("104.16.1.1", p, flags="ACK SYN", stamp=ISO) for p in (31337, 40000, 52000, 61000)]
check("K2 SYN-ACK (отражение) не считается", nb.knocks(refl, NOW) == [])
other = [ufw("45.83.64.6", 22, flags=f, stamp=ISO) for f in ("ACK", "RST", "ACK FIN", "ACK PSH", "ACK RST")]
check("K3 ACK/RST/FIN без SYN не считаются", nb.knocks(other, NOW) == [])
check("K4 SYN с ECN-флагами считается",
      nb.knocks([ufw("45.83.64.7", 8443, flags="CWR ECE SYN", stamp=ISO)], NOW) == [["45.83.64.7", 1, 1, 1]])
check("K5 строка без флагов (UDP-подобная) не ломает разбор", nb.knocks(["UFW BLOCK SRC=45.83.64.8 PROTO=TCP DPT=1\n"], NOW) == [])

# --- IPv6 ---
full = "2001:0db8:0000:0000:0000:0000:0000:0001"   # iptables LOG пишет адрес полностью; для проверки нужен публичный
pub6 = "2a00:1450:4001:0820:0000:0000:0000:200e"
r = nb.knocks([ufw(pub6, 22, stamp=ISO, v6=True), ufw(pub6, 23, stamp=ISO, v6=True)], NOW)
check("K6 IPv6 считается, пишется коротко (первый адрес /64)", r == [["2a00:1450:4001:820::", 2, 2, 0]])
check("K7 IPv6 SYN-ACK не считается", nb.knocks([ufw(pub6, 22, flags="ACK SYN", stamp=ISO, v6=True)], NOW) == [])
check("K8 документационный 2001:db8:: — не публичный", nb.knocks([ufw(full, 22, stamp=ISO, v6=True)], NOW) == [])

# --- частные адреса через ipaddress ---
for ip in ("10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "127.0.0.1", "100.64.0.1", "100.127.255.254",
           "169.254.10.10", "0.0.0.0", "203.0.113.5", "fd00:0000:0000:0000:0000:0000:0000:0001", "fe80:0000:0000:0000:0000:0000:0000:0001",
           "0000:0000:0000:0000:0000:0000:0000:0001"):
    check(f"P1 {ip} не учитывается", nb.knocks([ufw(ip, 22, stamp=ISO, v6=":" in ip)], NOW) == [])
check("P2 172.32.x (не частный) учитывается", nb.knocks([ufw("172.32.0.1", 22, stamp=ISO)], NOW) == [["172.32.0.1", 1, 1, 0]])
check("P3 мусор вместо адреса — пропуск", nb.public_ip("1.2.3") is None and nb.public_ip("::::") is None)
check("P4 публичный адрес — как есть", nb.public_ip("8.8.8.8") == "8.8.8.8")

# --- классический syslog и Новый год ---
jan1 = time.mktime((2027, 1, 1, 0, 10, 0, 0, 0, -1))      # местное 1 января 00:10
ts = nb.knock_ts("Dec 31 23:50:00 node1 kernel: x", jan1)
check("Y1 «Dec 31» первого января — прошлый год", ts is not None and 0 < jan1 - ts <= 1200 + 3600)
r = nb.knocks([ufw("45.83.64.9", 22, stamp="Dec 31 23:50:00"), ufw("45.83.64.10", 22, stamp="Dec 30 10:00:00")], jan1)
check("Y2 за сутки — только вчерашнее, позавчерашнее отброшено", r == [["45.83.64.9", 1, 1, 0]])
nov = time.mktime((2026, 11, 22, 12, 0, 0, 0, 0, -1))
ts = nb.knock_ts("Nov 22 11:00:00 node1 kernel: x", nov)
check("Y3 обычный день — год текущий", ts is not None and abs(nov - ts - 3600) <= 3600)
ts = nb.knock_ts("Nov 22 13:00:00 node1 kernel: x", nov)
check("Y4 часы ноды чуть впереди (меньше суток) — год не трогаем", ts is not None and abs(ts - nov - 3600) <= 3600)
check("Y5 мусор во времени — None", nb.knock_ts("Xyz 99 99:99:99 node1", nov) is None)

# --- tune(), mptcp_listeners и ложный ноль ---
SS3 = (0, "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\nLISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n", "")
SS0 = (0, "", "")
# ss -H -tlni от root на стенде (Ubuntu 24.04, 6.8.0-147, без mptcp_diag): MPTCP-слушатель python socket(..., 262)
TLNI = "LISTEN 0      8          127.0.0.1:47031 0.0.0.0:*\n\t bbr cwnd:10 tcp-ulp-mptcp\n"
TLNI6 = "LISTEN 0      8              [::1]:47032    [::]:*\n\t bbr cwnd:10 tcp-ulp-mptcp\n"
TLNI_NONE = ("LISTEN 0      4096         0.0.0.0:22    0.0.0.0:*\n\t cubic cwnd:10\n"
             "LISTEN 0      4096   127.0.0.53%lo:53    0.0.0.0:*\n\t bbr cwnd:10  \n")
TMP = tempfile.mkdtemp(prefix="beacon-test-")
os.makedirs(os.path.join(TMP, "mptcp"))
os.makedirs(os.path.join(TMP, "mod", "mptcp_diag"))
os.makedirs(os.path.join(TMP, "nomod"))
os.makedirs(os.path.join(TMP, "lib", "6.8.0-test"))
with open(os.path.join(TMP, "lib", "6.8.0-test", "modules.builtin"), "w") as f:
    f.write("kernel/net/ipv4/tcp_bbr.ko\nkernel/net/mptcp/mptcp_diag.ko\n")


def fake_proc(ss=SS3, ps=(0, "", ""), inspect="", ns=None, calls=None, tlni=SS0):
    """Подставной proc: ss хоста (ss — ответ ss -lMn, tlni — ss -tlni), docker ps/inspect, nsenter по pid
    (ns = {pid: (код, вывод, stderr)} — один ответ на оба ss, или {pid: {"tlni": …, "lMn": …}})."""
    def proc(cmd, timeout=20):
        if calls is not None:
            calls.append((list(cmd), timeout))
        if cmd[:1] == ["ss"]:
            return tlni if "-tlni" in cmd else ss
        if cmd[:1] == ["nsenter"]:
            r = (ns or {}).get(cmd[2], (1, "", "нет такого процесса"))
            return r.get("tlni" if "-tlni" in cmd else "lMn", SS0) if isinstance(r, dict) else r
        if cmd[:2] == ["docker", "ps"]:
            return ps
        if cmd[:2] == ["docker", "inspect"]:
            return (0, inspect, "")
        if cmd[:2] == ["ip", "-o"]:
            return (0, "default via 198.51.100.1 dev eth0 proto static\n", "")
        if cmd[0] == "tc":
            return (0, "qdisc fq 8001: root refcnt 2 limit 10000p\n", "")
        return (0, "", "")
    return proc


saved = {k: getattr(nb, k) for k in ("proc", "have", "PROC_MPTCP", "SYS_MODULE", "MODULES", "sysctl", "is_root")}
had_uname = hasattr(os, "uname")
real_uname = getattr(os, "uname", None)
try:
    nb.PROC_MPTCP, nb.SYS_MODULE, nb.MODULES = os.path.join(TMP, "mptcp"), os.path.join(TMP, "mod"), os.path.join(TMP, "lib")
    nb.have = lambda c: False   # docker нет
    nb.is_root = lambda: False  # ниже M* и C* — запасной способ ss -lMn (пометок ULP нет); от root — блок U
    nb.proc = fake_proc(SS3)
    t = nb.tune()
    check("M1 три MPTCP-слушателя", t["mptcp_listeners"] == 3 and t["qdisc"] == "fq")
    nb.proc = fake_proc(SS0)
    check("M2 слушателей нет, mptcp_diag есть — 0", nb.tune()["mptcp_listeners"] == 0)
    nb.proc = fake_proc((1, "", "ss: invalid option -- 'M'"))
    check("M3 ss не умеет -M (код не 0) — None", nb.tune()["mptcp_listeners"] is None)
    nb.proc = fake_proc((None, "", ""))
    check("M4 таймаут или ss нет — None", nb.tune()["mptcp_listeners"] is None)
    nb.proc = fake_proc((0, "", "RTNETLINK answers: Invalid argument\n"))
    check("M4b пусто и сообщение ss в stderr — None, не 0", nb.tune()["mptcp_listeners"] is None)
    nb.SYS_MODULE = os.path.join(TMP, "nomod")
    nb.proc = fake_proc(SS0)
    check("M4c пусто, mptcp_diag не загружен и не встроен — None (ложный ноль)", nb.tune()["mptcp_listeners"] is None)
    nb.proc = fake_proc(SS3)
    check("M4d слушатели видны — значит, mptcp_diag работает", nb.tune()["mptcp_listeners"] == 3)
    os.uname = lambda: type("U", (), {"release": "6.8.0-test"})()
    nb.proc = fake_proc(SS0)
    check("M4e mptcp_diag встроен в ядро (modules.builtin) — честный 0", nb.tune()["mptcp_listeners"] == 0)
    nb.SYS_MODULE = os.path.join(TMP, "mod")
    calls = []
    nb.PROC_MPTCP = os.path.join(TMP, "нет")
    nb.proc = fake_proc(SS3, calls=calls)
    check("M4f нет /proc/sys/net/mptcp — None, ss не зовём", nb.tune()["mptcp_listeners"] is None
          and not [c for c, _ in calls if c[:1] == ["ss"]])
    nb.PROC_MPTCP = os.path.join(TMP, "mptcp")
    nb.sysctl = lambda k: 1 if k == "net.mptcp.enabled" else saved["sysctl"](k)
    t = nb.tune()
    check("M4g net.mptcp.enabled=1 — слушателей считаем как есть", t["mptcp"] == 1 and t["mptcp_listeners"] == 3)
    nb.sysctl = saved["sysctl"]

    # --- MPTCP в контейнерах со своей сетью ---
    calls = []
    nb.proc = fake_proc(SS3, calls=calls)
    check("C1 docker нет — None, docker не зовём", nb.tune()["mptcp_listeners_ct"] is None
          and not [c for c, _ in calls if c[:1] in (["docker"], ["nsenter"])])
    nb.have = lambda c: True
    nb.proc = fake_proc(SS3, ps=(1, "", "Cannot connect to the Docker daemon"))
    check("C2 docker не отвечает — None", nb.mptcp_listeners_ct() is None)
    nb.proc = fake_proc(SS3, ps=(0, "\n", ""))
    check("C3 контейнеров нет — {}", nb.mptcp_listeners_ct() == {})
    INSPECT = ("/caddy default 101\n/remnanode host 102\n/side container:abcdef 103\n/web mynet 104\n"
               "/gone bridge 0\n/bad bridge 105\n/zz bridge 106\n")
    NS = {"101": (0, "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\n", ""), "104": SS0,
          "105": (1, "", "nsenter: cannot open /proc/105/ns/net"), "106": (0, "LISTEN 0 1 0.0.0.0:80 0.0.0.0:*\n", ""),
          "102": SS3, "103": SS3}
    calls = []
    nb.proc = fake_proc(SS3, ps=(0, "a1\nb2\nc3\nd4\ne5\nf6\ng7\n", ""), inspect=INSPECT, ns=NS, calls=calls)
    t = nb.tune()
    check("C4 только контейнеры со своей сетью и только ненулевые", t["mptcp_listeners_ct"] == {"caddy": 2, "zz": 1})
    ns_calls = [c for c in calls if c[0][:1] == ["nsenter"]]
    check("C5 nsenter -t PID -n ss -H -tlni (потом запасной -lMn), без host, container: и pid 0",
          sorted(set(c[0][2] for c in ns_calls)) == ["101", "104", "105", "106"]
          and ns_calls[0][0] == ["nsenter", "-t", ns_calls[0][0][2], "-n", "ss", "-H", "-tlni"]
          and ns_calls[1][0] == ["nsenter", "-t", ns_calls[0][0][2], "-n", "ss", "-H", "-lMn"])
    check("C6 таймауты: docker 10 с, nsenter 5 с",
          all(tm == 10 for c, tm in calls if c[:1] == ["docker"]) and all(tm == 5 for _, tm in ns_calls)
          and len([c for c, _ in calls if c[:1] == ["docker"]]) == 2)
    nb.have = lambda c: c != "nsenter"
    check("C7 nsenter нет — None", nb.mptcp_listeners_ct() is None)
    nb.have = lambda c: True
    nb.SYS_MODULE = os.path.join(TMP, "nomod")
    os.uname = lambda: type("U", (), {"release": "нет-такого"})()
    check("C8 mptcp_diag нет — контейнеры всё равно проверяются (видимые слушатели — честное число)",
          nb.mptcp_listeners_ct() == {"caddy": 2, "zz": 1})

    # --- MPTCP: основной способ — ss -H -tlni и пометка tcp-ulp-mptcp, как mptcp_ss в node_tune.sh ---
    nb.have = lambda c: False
    nb.SYS_MODULE = os.path.join(TMP, "nomod")
    os.uname = lambda: type("U", (), {"release": "нет-такого"})()   # mptcp_diag нет ни загруженного, ни встроенного
    check("U1 разбор вывода ss -tlni стенда (Ubuntu 24.04, iproute2 6.1): один слушатель с пометкой",
          nb.ulp_mptcp(TLNI) == 1)
    check("U1b пометка без строки сокета над ней, в самой строке сокета и пустая строка — не считаются",
          nb.ulp_mptcp("\ttcp-ulp-mptcp\nLISTEN 0 1 0.0.0.0:1 0.0.0.0:* tcp-ulp-mptcp\n\n\t bbr tcp-ulp-mptcp\n") == 0
          and nb.ulp_mptcp("") == 0)
    check("U1c два слушателя (IPv4 и IPv6) с пометкой — 2", nb.ulp_mptcp(TLNI + TLNI6) == 2)
    nb.is_root = lambda: True
    calls = []
    nb.proc = fake_proc(SS0, tlni=(0, TLNI, ""), calls=calls)
    t = nb.tune()
    check("U2 root, живой слушатель, ss -lMn пусто, mptcp_diag нет — честная 1, не None", t["mptcp_listeners"] == 1)
    check("U2b сначала ss -H -tlni; нашлись пометки — запасной ss -lMn не нужен",
          [c for c, _ in calls if c[:1] == ["ss"]] == [["ss", "-H", "-tlni"]])
    nb.proc = fake_proc(SS0, tlni=(0, TLNI_NONE, ""))
    check("U3 root, пометок нет, ss -lMn пусто, mptcp_diag нет — честный 0 (root видит пометку всегда)",
          nb.mptcp_listeners() == 0)
    nb.is_root = lambda: False
    check("U4 не root, пометок нет, mptcp_diag нет — None (не проверить)", nb.mptcp_listeners() is None)
    nb.is_root = lambda: True
    calls = []
    nb.proc = fake_proc(SS3, tlni=(None, "", ""), calls=calls)
    check("U5 ss -tlni не ответил вовремя — None, второй раз не ждём",
          nb.mptcp_listeners() is None and [c for c, _ in calls if c[:1] == ["ss"]] == [["ss", "-H", "-tlni"]])
    nb.proc = fake_proc(SS3, tlni=(1, "", "ss: ошибка"))
    check("U6 ss -tlni с ошибкой — запасной ss -lMn: видимые слушатели — честное число", nb.mptcp_listeners() == 3)
    nb.proc = fake_proc(SS0, tlni=(1, "", "ss: ошибка"))
    check("U6b ss -tlni с ошибкой, ss -lMn пусто без mptcp_diag — None (даже от root)", nb.mptcp_listeners() is None)
    nb.SYS_MODULE = os.path.join(TMP, "mod")
    check("U6c ss -tlni с ошибкой, ss -lMn пусто, mptcp_diag есть — 0", nb.mptcp_listeners() == 0)
    nb.SYS_MODULE = os.path.join(TMP, "nomod")
    nb.proc = fake_proc((1, "", ""), tlni=(0, TLNI_NONE, ""))
    check("U6d root, пометок нет, ss -lMn не умеет -M — всё равно честный 0 по ss -tlni", nb.mptcp_listeners() == 0)
    nb.have = lambda c: True
    calls = []
    NSU = {"101": {"tlni": (0, TLNI + TLNI6, ""), "lMn": SS0}, "104": {"tlni": (0, TLNI_NONE, ""), "lMn": SS0},
           "106": {"tlni": (124, "", ""), "lMn": SS0}}
    nb.proc = fake_proc(SS0, ps=(0, "a1\nd4\ng7\n", ""), inspect="/caddy default 101\n/web mynet 104\n/zz bridge 106\n",
                        ns=NSU, calls=calls, tlni=(0, TLNI, ""))
    t = nb.tune()
    check("U7 контейнеры без mptcp_diag: слушатели по пометке ULP через nsenter, хост тоже",
          t["mptcp_listeners_ct"] == {"caddy": 2} and t["mptcp_listeners"] == 1)
    ns_calls = [c for c, _ in calls if c[:1] == ["nsenter"]]
    check("U7b nsenter -t PID -n ss -H -tlni; запасной -lMn только там, где пометок нет",
          ["nsenter", "-t", "101", "-n", "ss", "-H", "-tlni"] in ns_calls
          and ["nsenter", "-t", "101", "-n", "ss", "-H", "-lMn"] not in ns_calls
          and ["nsenter", "-t", "104", "-n", "ss", "-H", "-lMn"] in ns_calls)
    check("U8 is_root без os.geteuid (Windows) — не root", saved["is_root"]() is (os.name == "posix" and os.geteuid() == 0))
finally:
    for k, v in saved.items():
        setattr(nb, k, v)
    if had_uname:
        os.uname = real_uname
    elif hasattr(os, "uname"):
        del os.uname

BASE = {"cc": "bbr", "qdisc": "fq", "conntrack_max": 100000, "mptcp": 0}
check("M5 sysctl 0, слушатели живы — пометка",
      nw.tune_flags(dict(BASE, mptcp_listeners=2)) == ["MPTCP-слушателей 2 (нужен перезапуск служб)"])
check("M6 слушателей нет — молчим", nw.tune_flags(dict(BASE, mptcp_listeners=0)) == [])
check("M7 старый маячок без поля — молчим", nw.tune_flags(BASE) == [])
check("M8 ss не умеет -M (None) — молчим", nw.tune_flags(dict(BASE, mptcp_listeners=None)) == [])
check("M9 MPTCP включён и слушает — обе пометки", nw.tune_flags(dict(BASE, mptcp=1, mptcp_listeners=1)) ==
      ["MPTCP включён", "MPTCP-слушателей 1 (нужен перезапуск служб)"])
check("M10 мусор в поле — молчим", nw.tune_flags(dict(BASE, mptcp_listeners="3")) == []
      and nw.tune_flags(dict(BASE, mptcp_listeners=True)) == [])

CT = "(перезапустить контейнер или net.mptcp.enabled=0 в sysctls)"
check("M11 MPTCP в контейнере — пометка с именем",
      nw.tune_flags(dict(BASE, mptcp_listeners=0, mptcp_listeners_ct={"caddy": 2})) == [f"MPTCP в контейнере caddy: 2 {CT}"])
check("M12 хост и контейнеры — по пометке, контейнеры по имени",
      nw.tune_flags(dict(BASE, mptcp_listeners=1, mptcp_listeners_ct={"zz": 1, "caddy": 3})) ==
      ["MPTCP-слушателей 1 (нужен перезапуск служб)", f"MPTCP в контейнере caddy: 3 {CT}", f"MPTCP в контейнере zz: 1 {CT}"])
check("M13 docker нет (None), пусто, мусор — молчим",
      nw.tune_flags(dict(BASE, mptcp_listeners_ct=None)) == [] and nw.tune_flags(dict(BASE, mptcp_listeners_ct={})) == []
      and nw.tune_flags(dict(BASE, mptcp_listeners_ct=["caddy"])) == []
      and nw.tune_flags(dict(BASE, mptcp_listeners_ct={"a": 0, "b": True, "c": "3", "d": -1})) == [])

# --- регулярка ufw.log: длинные и «злые» строки ---
seg = "SRC=45.83.64.1 DST=198.51.100.7 PROTO=TCP SPT=1 DPT=443 RES=0x00 SYN "
evil = ["[UFW BLOCK] " + seg * 15 + "X",
        ("[UFW BLOCK] " + seg) * 13,
        "[UFW BLOCK] " + "SRC=45.83.64.1 DST=2 " * 40 + "PROTO=TCP SPT=1 DPT=2 " * 8,
        "[UFW BLOCK] " + "a " * 500,
        "UFW BLOCK] SRC= " * 60]
KPFX = ISO + " node1 kernel: "   # с пометкой ядра — злые строки доходят до разбора полей
evil += [KPFX + e for e in evil]
for i, e in enumerate(evil):
    e = e[:nb.LINE_MAX]
    t0 = time.perf_counter()
    r = nb.knocks([e], NOW)
    check(f"R1.{i} злая строка {len(e)} символов — быстро и без совпадения", r == [] and time.perf_counter() - t0 < 0.1)
t0 = time.perf_counter()
r = nb.knocks([("[UFW BLOCK] " + seg) * 300 + "URGP=0\n"], NOW)
check("R2 строка длиннее 1024 — пропуск, быстро", r == [] and time.perf_counter() - t0 < 0.1)
pad = ufw("45.83.64.11", 22, stamp=ISO).replace("OUT= ", "OUT= " + "X=" + "y" * 900 + " ")
check("R3 настоящая строка, раздутая за 1024, — пропуск", len(pad) > nb.LINE_MAX and nb.knocks([pad], NOW) == [])
real = ("2026-11-22T09:50:00.123456+00:00 node1 kernel: [UFW BLOCK] IN=ens3 OUT= MAC=fa:16:3e:00:00:01:fa:16:3e:00:00:02:08:00 "
        "SRC=45.83.64.12 DST=198.51.100.7 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 PROTO=TCP SPT=40000 DPT=8443 "
        "WINDOW=1024 RES=0x00 SYN URGP=0 \n")
check("R4 обычная строка ядра (без DF) разбирается", nb.knocks([real], NOW) == [["45.83.64.12", 1, 1, 1]])
check("R5 SYN-ACK и IPv6 по-прежнему: K2, K6 выше; ACK в середине флагов — не стук",
      nb.knocks([ufw("45.83.64.13", 22, flags="ACK PSH SYN", stamp=ISO)], NOW) == [])

# --- ufw.log: только строки ядра, разбор одним проходом по полям, без регулярки ---
good = ufw("45.83.64.20", 443, stamp=ISO)
check("N1 строка ядра — стук", nb.ufw_syn(good) == ("45.83.64.20", 443) and nb.knocks([good], NOW) == [["45.83.64.20", 1, 1, 1]])
forged = good.replace(" kernel: ", " root: ")   # logger -t root "[UFW BLOCK] …" — попадает в ufw.log, но не от ядра
check("N2 не от ядра (logger) — не стук", nb.knocks([forged], NOW) == [] and not nb.ufw_kernel(forged))
late = ISO + " node1 sshd[1]: x [UFW BLOCK] IN=eth0 kernel: " + good.split("[UFW BLOCK] ", 1)[1]
check("N3 «kernel:» после [UFW BLOCK] — не строка ядра", nb.knocks([late], NOW) == [] and not nb.ufw_kernel(late))
check("N4 поле дважды (SRC) — строка чужая, пропуск",
      nb.knocks([good.replace("DST=", "SRC=45.83.64.21 DST=")], NOW) == [])
check("N5 OPT (…) после URGP= не мешает",
      nb.knocks([good.replace("URGP=0", "URGP=0 OPT (020405B40402080A)")], NOW) == [["45.83.64.20", 1, 1, 1]])
check("N6 порт мусорный или слишком длинный — пропуск", nb.ufw_syn(good.replace("DPT=443", "DPT=4x3")) is None
      and nb.ufw_syn(good.replace("DPT=443", "DPT=1234567")) is None and nb.ufw_syn(good.replace("DPT=443 ", "")) is None)
check("N7 UDP и строка без URGP= — не стук", nb.ufw_syn(good.replace("PROTO=TCP", "PROTO=UDP")) is None
      and nb.ufw_syn(good.replace(" URGP=0", "")) is None)
check("N8 флаги до RES= (DF) флагами TCP не считаются", nb.ufw_syn(good.replace("DF ", "DF SYN ").replace(" SYN URGP", " URGP")) is None)
check("N9 разбор без регулярки: LINE больше нет", not hasattr(nb, "LINE"))
long_ok = KPFX + "[UFW BLOCK] " + "A=b " * 220 + "SRC=45.83.64.22 DST=1 PROTO=TCP SPT=1 DPT=22 RES=0x00 SYN URGP=0"
t0 = time.perf_counter()
for _ in range(1000):
    r = nb.knocks([long_ok], NOW)
check("N10 1000 строк по ~1000 символов (220 полей) — быстро, время линейное",
      len(long_ok) <= nb.LINE_MAX and r == [["45.83.64.22", 1, 1, 0]] and time.perf_counter() - t0 < 2)
with tempfile.TemporaryDirectory() as d:
    log1, log0 = os.path.join(d, "ufw.log.1"), os.path.join(d, "ufw.log")
    with open(log1, "w", encoding="utf-8") as f:
        f.write(good + forged)
    with open(log0, "w", encoding="utf-8") as f:
        f.write(late + "мусор\n" + good.replace("45.83.64.20", "45.83.64.23"))
    got = nb.ufw_lines((log1, log0, os.path.join(d, "нет")))
    check("N11 ufw_lines: только строки ядра, оба файла, отсутствующий — пропуск",
          got == [good, good.replace("45.83.64.20", "45.83.64.23")])

# --- IPv6: строка на /64 и не больше KNOCK_MAX6 ---
a1, a2 = "2a00:1450:4001:0820:0000:0000:0000:200e", "2a00:1450:4001:0820:dead:beef:0000:0001"
r = nb.knocks([ufw(a1, 22, stamp=ISO, v6=True), ufw(a2, 443, stamp=ISO, v6=True), ufw(a2, 22, stamp=ISO, v6=True)], NOW)
check("V1 два адреса одной /64 — одна строка (первый адрес /64), порты и стуки вместе", r == [["2a00:1450:4001:820::", 2, 3, 1]])
r = nb.knocks([ufw(a1, 22, stamp=ISO, v6=True), ufw("2a00:1450:4001:0821:0000:0000:0000:0001", 22, stamp=ISO, v6=True)], NOW)
check("V2 разные /64 — разные строки", sorted(x[0] for x in r) == ["2a00:1450:4001:820::", "2a00:1450:4001:821::"])
lines = []
for i in range(150):   # 150 сетей /64 стучат на три порта, включая 443 — подозрительнее любого IPv4 ниже
    for p in (443, 22, 23):
        lines.append(ufw("2a01:4f8:%x:%x:0000:0000:0000:0001" % (i // 256 + 1, i % 256), p, stamp=ISO, v6=True))
for i in range(350):
    lines.append(ufw("45.83.%d.%d" % (65 + i // 250, i % 250 + 1), 443, stamp=ISO))
r = nb.knocks(lines, NOW)
n6 = len([x for x in r if ":" in x[0]])
check("V3 IPv6 не больше 100 строк, IPv4 не вытеснен", len(r) == 400 and n6 == nb.KNOCK_MAX6 == 100 and len(r) - n6 == 300)
check("V4 порядок сохранён: сначала самые подозрительные", r[0][1] == 3 and r[-1][1] == 1)
lines = [ufw("2a01:4f8:1:%x:0000:0000:0000:0001" % i, p, stamp=ISO, v6=True) for i in range(500) for p in (443, 22)]
lines += [ufw("45.83.70.%d" % i, 25, stamp=ISO) for i in range(1, 11)]
r = nb.knocks(lines, NOW)
check("V5 500 сетей IPv6 против 10 тихих IPv4 — все IPv4 на месте", len([x for x in r if ":" not in x[0]]) == 10 and len(r) == 110)

# --- public_ip: мультикаст, v4-mapped, NAT64 ---
check("I1 мультикаст IPv4 и IPv6 — нет", nb.public_ip("224.0.0.5") is None and nb.public_ip("239.1.2.3") is None
      and nb.public_ip("ff0e::1") is None)
check("I2 ::ffff:a.b.c.d — это IPv4", nb.public_ip("::ffff:45.83.64.5") == "45.83.64.5"
      and nb.public_ip("0000:0000:0000:0000:0000:ffff:2d53:4005") == "45.83.64.5")
check("I3 ::ffff: с частным IPv4 — нет", nb.public_ip("::ffff:10.0.0.1") is None and nb.public_ip("::ffff:127.0.0.1") is None)
check("I4 64:ff9b:: — по встроенному IPv4", nb.public_ip("64:ff9b::a00:1") is None and nb.public_ip("64:ff9b::c0a8:101") is None
      and nb.public_ip("64:ff9b::2d53:4005") == "45.83.64.5")
r = nb.knocks([ufw("0000:0000:0000:0000:0000:ffff:2d53:4005", 22, stamp=ISO, v6=True),
               ufw("0064:ff9b:0000:0000:0000:0000:2d53:4005", 23, stamp=ISO, v6=True),
               ufw("ff02:0000:0000:0000:0000:0000:0000:0001", 22, stamp=ISO, v6=True)], NOW)
check("I5 в knocks: обе записи IPv4 сливаются в одну, мультикаст отброшен", r == [["45.83.64.5", 2, 2, 0]])

# --- beacon_install.sh: песочница юнита, root, --uninstall ---
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon_install.sh"), encoding="utf-8", newline="").read()
check("S0 установщик в LF", "\r" not in src)
unit = src.split("cat > /etc/systemd/system/node-beacon.service <<UNIT\n", 1)[1].split("\nUNIT\n", 1)[0]
for d in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=$rw ", "ProtectHome=$ph", "PrivateTmp=yes",
          "ProtectKernelTunables=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes"):
    check(f"S1 в юните маячка {d}", d in unit.splitlines() or any(ln.startswith(d) for ln in unit.splitlines()))
check("S2 без ProtectKernelModules (mptcp_diag) и CapabilityBoundingSet (nsenter)",
      "ProtectKernelModules" not in unit and "CapabilityBoundingSet" not in unit and "ProtectKernelModules=yes" not in src)
check("S3 ReadWritePaths: папка файла, в режиме --serve /var/lib/node-beacon",
      'if [ "$mode" = serve ]; then rw=/var/lib/node-beacon; else rw="$outdir"; fi' in src)
check("S4 проверка на root до разбора параметров",
      0 <= src.find('[ "$(id -u)" = 0 ]') < src.find("while [ $# -gt 0 ]"))
un = src.split('if [ "$mode" = uninstall ]; then', 1)[1].split("\nfi\n", 1)[0]
check("S5 --uninstall убирает node-beacon-run и .beacon-*.tmp рядом с файлом",
      "/usr/local/sbin/node-beacon-run" in un and '"$(dirname "$out")"/.beacon-*.tmp' in un)
tail_un = un.split("systemctl daemon-reload", 1)[-1]
check("S7 --uninstall в конце: reset-failed трёх юнитов, ошибки не валят",
      "systemctl reset-failed node-beacon.timer node-beacon.service node-beacon-http.service 2>/dev/null || true" in tail_un
      and tail_un.find("reset-failed") < tail_un.find('echo "маячок убран"'))
check("S8 шапка node_beacon.py: свой docker context в /root/.docker → xray и mptcp_listeners_ct None, ProtectHome=read-only",
      all(w in " ".join(nb.__doc__.split()) for w in ("/root/.docker", "xray", "mptcp_listeners_ct", "None",
                                                      "ProtectHome=read-only", "--home-ro")))
check("S9 ключ --home-ro: разбирается и ставит ProtectHome=read-only до записи юнита",
      "--home-ro) home_ro=1; shift ;;" in src and "home_ro=0" in src.split("while [ $# -gt 0 ]", 1)[0]
      and 0 < src.find('[ "$home_ro" = 0 ] || ph=read-only') < src.find("cat > /etc/systemd/system/node-beacon.service")
      and src.find("  *) ph=yes ;;") < src.find('[ "$home_ro" = 0 ] || ph=read-only')
      and "--home-ro" in src.splitlines()[1])
if os.name == "posix":
    import subprocess
    check("S6 bash -n beacon_install.sh", subprocess.run(["bash", "-n", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                                      "beacon_install.sh")]).returncode == 0)

# --- запись файла маячка ---
modes = []
real_fchmod = getattr(os, "fchmod", None)


def spy_fchmod(fd, mode):
    modes.append(mode)
    if real_fchmod:
        real_fchmod(fd, mode)


os.fchmod = spy_fchmod   # на Windows os.fchmod нет — подменяем, на Linux заодно проверяем вызов
try:
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "st-node1.json")
        with open(out + ".tmp", "w") as f:   # старое имя временного файла — не трогаем, не используем
            f.write("CHUZHOE")
        nb.write_state(out, {"ts": 1, "x": "я"})
        check("W1 JSON записан", json.load(open(out, encoding="utf-8")) == {"ts": 1, "x": "я"})
        check("W2 права ставятся по дескриптору, 0644", modes == [0o644])
        check("W3 файл по старому имени .tmp не тронут", open(out + ".tmp").read() == "CHUZHOE")
        check("W4 своих временных файлов не осталось", sorted(os.listdir(d)) == ["st-node1.json", "st-node1.json.tmp"])
        if os.name == "posix":
            check("W5 файл маячка 0644", os.stat(out).st_mode & 0o777 == 0o644)
        try:
            nb.write_state(out, {"bad": object()})
            check("W6 несериализуемое — исключение", False)
        except TypeError:
            pass
        check("W6 при ошибке старый файл цел, временный убран",
              json.load(open(out, encoding="utf-8")) == {"ts": 1, "x": "я"}
              and sorted(os.listdir(d)) == ["st-node1.json", "st-node1.json.tmp"])
        # ссылка на чужой файл под любым именем в папке не помогает: mkstemp сам создаёт новый файл (O_EXCL)
        victim = os.path.join(d, "victim")
        with open(victim, "w") as f:
            f.write("SECRET")
        os.chmod(victim, 0o600)
        try:
            os.remove(out + ".tmp")
            os.symlink(victim, out + ".tmp")
            linked = True
        except (OSError, NotImplementedError):
            linked = False   # Windows без прав на ссылки — пропускаем
        if linked:
            nb.write_state(out, {"ts": 2})
            check("W7 файл за ссылкой не затёрт", open(victim).read() == "SECRET")
            if os.name == "posix":
                check("W7b права файла за ссылкой не тронуты", os.stat(victim).st_mode & 0o777 == 0o600)
            check("W7c маячок записан", json.load(open(out, encoding="utf-8")) == {"ts": 2})
        else:
            print("ПРОПУСК W7, W7b, W7c: ссылку создать нельзя (Windows без прав) — прогнать на Linux")
        if os.name != "posix":
            print("ПРОПУСК W5, W7b: права файлов проверяются только на Linux")
finally:
    if real_fchmod:
        os.fchmod = real_fchmod
    else:
        del os.fchmod

shutil.rmtree(TMP, ignore_errors=True)
print(f"OK {ok}")
