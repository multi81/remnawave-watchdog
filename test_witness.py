"""Тесты: свидетель ноды и установщики. Свидетель (фильтр BPF по своим адресам, tcpdump без
-Z root, песочница юнита, предел отслеживаемых соединений и размера файла, честный since, запись файла
свидетеля через mkstemp), beacon_install.sh (ufw только включённый, удаление правила без sh -c, проверка
адреса и порта, смена правила), переход serve↔site, install.sh (песочница служб, Xray от DynamicUser) и
обновление Xray при повторной установке, мелочи (SyslogLevel при LogLevelMax, пути в кавычках). Без сети."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import node_witness as nw  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def syn(ts, src, sport, mss=1213, dst="198.51.100.1"):
    return f"{ts:.6f} IP {src}.{sport} > {dst}.443: Flags [S], seq 1, win 64240, options [mss {mss},sackOK], length 0"


def src_of(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


BASH = shutil.which("bash")


def bash(script, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, encoding="utf-8", env=e)


# --- фильтр BPF ---
f0 = nw.build_filter()
OLD_DIR = os.environ.get("OLD_CODE_DIR", "")   # папка с прежней версией модулей — для сравнения (необязательно)
before = os.path.join(OLD_DIR, "node_witness.py") if OLD_DIR else ""
if os.path.exists(before):
    spec = importlib.util.spec_from_file_location("nw_before", before)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    check("W1 без своих адресов фильтр прежний (свидетель работает, даже если ip не ответил)", f0 == old.FILTER == nw.FILTER)
f1 = nw.build_filter({"198.51.100.1", "10.0.0.5", "мусор", "fe80::1"})
syn_b, src_b, rst_b = f1.split(") or (")
check("W2 фильтр: помеченные SYN и сбросы на 443 — только к своим адресам, ответы с 443 — только от своих",
      "(dst host 10.0.0.5 or dst host 198.51.100.1)" in syn_b and "(src host 10.0.0.5 or src host 198.51.100.1)" in src_b
      and "(dst host 10.0.0.5 or dst host 198.51.100.1)" in rst_b and "tcp src port 443" in src_b
      and "мусор" not in f1 and "fe80" not in f1 and "tcp[22:2] >= 1201" in syn_b)

real_du = nw.drop_user
nw.drop_user = lambda: "tcpdump"
c1 = nw.tcpdump_cmd("eth0", {"198.51.100.1"})
nw.drop_user = lambda: None
c2 = nw.tcpdump_cmd("eth0", ())
nw.drop_user = real_du
check("W3 tcpdump: права сбрасывает до tcpdump (-Z tcpdump, не root), без неразборчивого режима (-p)",
      c1[c1.index("-Z") + 1] == "tcpdump" and "-p" in c1 and "root" not in c1 and c1[-1] == nw.build_filter({"198.51.100.1"})
      and "-Z" not in c2 and c2[c2.index("-i") + 1] == "eth0")
check("W4 в коде свидетеля нет -Z root", '"-Z", "root"' not in src_of("node_witness.py"))
if os.name != "posix":
    check("W5 drop_user на Windows (тесты) — None", nw.drop_user() is None)

# --- поддельные помеченные SYN ---
T = 1000.0
fl = nw.Flows(local={"198.51.100.1"})
fl.since = T - 100
for i in range(nw.MAX_LIVE + 3000):
    fl.feed(syn(T + i * 0.0002, f"79.{i // 60000 % 250}.{i // 250 % 240}.{i % 250 + 1}", 40000 + i % 20000))
check("W6 поток поддельных SYN: следим не больше чем за MAX_LIVE, лишние сосчитаны как отброшенные",
      len(fl.live) == nw.MAX_LIVE and fl.dropped == 3000 and fl.cut > T)
snap = fl.snapshot(T + 2)
check("W7 после потери since сдвинут за её время: сторож (старый и новый) не судит по серии, начатой до потери",
      snap["since"] > fl.cut and snap["dropped"] == 3000
      and blockwatch.witness_match(dict(snap, ts=T + 40), {"mss": 1213, "t0": T - 5, "t1": T + 5, "ok": 0, "n": 6}) is None)
fl.feed(syn(T + 30, "80.1.1.1", 41000))
s2 = fl.snapshot(T + 31)
check("W8 поток кончился: через LIVE новые помеченные соединения снова принимаются",
      len(fl.live) == 1 and s2["flows"][-1][:3] == [T + 30, 1213, 1] and fl.dropped == 3000)
wm = blockwatch.witness_match(dict(s2, ts=T + 50), {"mss": 1213, "t0": T + 29, "t1": T + 31, "ok": 1, "n": 1})
check("W9 серия после потери сверяется как обычно", wm is not None and wm["seen"] == 1)

fl3 = nw.Flows()
for i in range(3 * nw.MAX_FLOWS):   # долгий поток: соединения успевают закрываться, done не растёт без предела
    fl3.feed(syn(T + i * 0.02, f"81.{i // 62500 % 250}.{i // 250 % 250}.{i % 250 + 1}", 30000 + i % 30000))
check("W10 между записями файла сосчитанных не больше 2×MAX_FLOWS (память под потоком ограничена)",
      len(fl3.done) <= 2 * nw.MAX_FLOWS and len(fl3.live) <= nw.MAX_LIVE)
s3 = fl3.snapshot(T + 3 * nw.MAX_FLOWS * 0.02 + 1)
check("W11 в снимке не больше MAX_FLOWS + MAX_LIVE записей, обрезанное честно отмечено в since",
      len(s3["flows"]) <= nw.MAX_FLOWS + nw.MAX_LIVE and s3["since"] > s3["flows"][0][0] - 1 and fl3.cut > 0)

# --- размер файла ---
big = {"v": 1, "ts": 1795341600.0, "since": 1795340000, "keep": nw.KEEP, "dropped": 0,
       "flows": [[1795340000.12 + i, 1260, 99, 99, 99999, 99999] for i in range(nw.MAX_FLOWS + nw.MAX_LIVE)]}
text = nw.fit(big)
check("W12 даже снимок наибольшего размера с большими счётчиками меньше 400000 байт (предел curl у сторожа)",
      len(text.encode()) <= nw.MAX_BYTES < 400000)
huge = dict(big, flows=big["flows"] * 4)
huge["flows"] = sorted(huge["flows"])
t2 = nw.fit(huge)
d2 = json.loads(t2)
check("W13 больше предела — отбрасываются самые старые, since за последней отброшенной, свежие на месте",
      len(t2) <= nw.MAX_BYTES and d2["flows"][-1] == huge["flows"][-1] and len(d2["flows"]) < len(huge["flows"])
      and d2["since"] > huge["flows"][len(huge["flows"]) - len(d2["flows"]) - 1][0]
      and d2["since"] <= d2["flows"][0][0] + 1)
small = {"v": 1, "ts": 1.0, "since": 0, "keep": 1800, "flows": [[1.0, 1213, 1, 1, 0, 0]]}
check("W14 обычный снимок не меняется; поля старого формата на месте (старый сторож читает)",
      nw.fit(small) == json.dumps(small, separators=(",", ":"))
      and {"v", "ts", "since", "keep", "flows"} <= set(snap) and all(len(r) == 6 for r in snap["flows"]))

# --- запись файла ---
tmp = tempfile.mkdtemp()
try:
    out = os.path.join(tmp, "fw-abc.json")
    victim = os.path.join(tmp, "victim")
    with open(victim, "w") as f:
        f.write("SECRET")
    if os.name == "posix":
        os.chmod(victim, 0o600)
        os.symlink(victim, out + ".tmp")   # ловушка под прежнее предсказуемое имя
    else:
        with open(out + ".tmp", "w") as f:
            f.write("SECRET")
    nw.write(out, small)
    left = [n for n in os.listdir(tmp) if n.startswith(".fw-")]
    check("W15 запись: свой временный файл (mkstemp), предсказуемое $out.tmp не трогается, лишних файлов нет",
          json.load(open(out)) == small and open(victim).read() == "SECRET" and left == []
          and (os.name != "posix" or (os.stat(out).st_mode & 0o777 == 0o644 and os.stat(victim).st_mode & 0o777 == 0o600)))
    real_replace = nw.os.replace

    def boom(a, b):
        raise OSError("нет места")
    nw.os.replace = boom
    try:
        nw.write(out, dict(small, ts=2.0))
        raised = False
    except OSError:
        raised = True
    finally:
        nw.os.replace = real_replace
    check("W16 сбой записи: временный файл убран, прежний файл цел",
          raised and json.load(open(out)) == small and [n for n in os.listdir(tmp) if n.startswith(".fw-")] == [])
    if os.name == "posix":
        os.remove(out)
        os.symlink(victim, out)   # ссылка на месте самого файла: заменяется ссылка, не жертва
        nw.write(out, small)
        check("W17 ссылка на месте файла заменяется, файл-жертва цел", not os.path.islink(out) and open(victim).read() == "SECRET")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# --- witness_install.sh ---
wi = src_of("witness_install.sh")
unit = wi.split('cat > "$UNIT" <<EOF\n', 1)[1].split("\nEOF\n", 1)[0]
ul = unit.splitlines()
check("X1 установщик свидетеля в LF", "\r" not in wi and "\r" not in src_of("node_witness.py"))
check("X2 пути в юните в кавычках (пробелы), \", \\ и % в пути папки отвергаются до записи юнита",
      'ExecStart=/usr/bin/python3 "$APP/node_witness.py" "$out"' in ul and 'ReadWritePaths="$dir"' in ul
      and 0 < wi.find('*\\"*|*\'\\\'*|*%*') < wi.find('cat > "$UNIT"'))
check("X3 песочница свидетеля: только нужные возможности, без root-полномочий, запись только в папку",
      "CapabilityBoundingSet=$caps" in ul and "AmbientCapabilities=$amb" in ul   # от node-witness — test_witness_user.py
      and 'caps="CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID"' in wi and 'caps="$caps CAP_DAC_OVERRIDE"' in wi
      and all(d in ul for d in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "ProtectHome=$ph",
                                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET",
                                "ProtectKernelModules=yes", "RestrictSUIDSGID=yes")))
check("X4 SyslogLevel=warning стоит вместе с LogLevelMax=warning (трассировки и «не записал» не теряются)",
      "SyslogLevel=warning" in ul and "LogLevelMax=warning" in ul)
check("X5 --uninstall и переезд убирают .fw-*.tmp и прежний файл; reset-failed",
      '"$(dirname "$1")"/.fw-*.tmp' in wi and "systemctl reset-failed node-witness.service" in wi
      and 'rm_out "$(cat "$ETC/out")"' in wi.split('if [ "${1:-}" = "--uninstall" ]', 1)[1].split("\nfi\n", 1)[0]
      and '[ "$(cat "$ETC/out")" != "$out" ]' in wi)

# --- beacon_install.sh ---
bi = src_of("beacon_install.sh")
check("B1 нет sh -c с правилом ufw: удаление словами из файла (read -ra) и ufw delete \"${r[@]}\"",
      'sh -c "ufw' not in bi and 'read -ra r < "$ETC/ufw-rule"' in bi and 'ufw delete "${r[@]}"' in bi
      and "ufw_delete_saved" in bi.split('if [ "$mode" = uninstall ]; then', 1)[1].split("\nfi\n", 1)[0])
serve = bi.split('elif [ "$mode" = serve ]; then', 1)[1].split('\nelse\n', 1)[0]
check("B2 --serve: правило ufw только при включённом ufw, прежнее (другой адрес или порт) сначала удаляется",
      "LC_ALL=C ufw status" in serve and serve.find('!= "$rule" ]; then ufw_delete_saved') < serve.find("= active ]")
      and serve.find("= active ]") < serve.find('ufw "${r[@]}" comment')
      and "ufw $rule" not in serve and "открыт всем" in serve)
check("B3 --serve: порт — только цифры и 1-65535, проверка до записи юнита",
      "*[!0-9]*) echo \"порт — только цифры" in serve and "port=$((10#$port))" in serve
      and serve.find("*[!0-9]*)") < serve.find("node-beacon-http.service <<UNIT"))
code = serve.split("python3 -c '\n", 1)[1].split("\n' \"$allow\"", 1)[0]


def allow_ok(a):
    return subprocess.run([sys.executable, "-c", code, a], capture_output=True).returncode == 0


check("B4 --allow через ipaddress: адрес или сеть; внедрение, зона %, пробелы и /0 отвергаются",
      all(allow_ok(a) for a in ("203.0.113.7", "198.51.100.0/24", "2001:db8::5", "2001:db8::/48"))
      and not any(allow_ok(a) for a in ("203.0.113.7; touch /x", "$(id)", "fe80::1%eth0", "1.2.3.4 to any port 22",
                                        "0.0.0.0/0", "::/0", "", "999.1.1.1", "example.com")))
site = bi.split('if [ "$mode" = site ]; then\n', 1)[1].split('elif [ "$mode" = serve ]', 1)[0]
check("B5 serve→site: веб-сервер маячка и правило ufw убираются, случайное имя сохраняется (адрес у сторожа тот же)",
      "systemctl disable --now node-beacon-http.service" in site and "ufw_delete_saved; rm -f \"$ETC/ufw-rule\"" in site
      and "st-*.json) name=\"$(basename \"$prev\")\"" in site and '[ -s "$ETC/out" ] ||' not in site)
check("B6 смена режима или папки: прежний файл маячка убирается, пустой www после --serve тоже; подсказка про свидетеля",
      'if [ -n "$prev" ] && [ "$prev" != "$(cat "$ETC/out")" ]; then' in bi and 'rm_out "$prev"; moved=1' in bi
      and 'rmdir "$WWW" /var/lib/node-beacon' in bi and "witness_install.sh ещё раз" in bi
      and bi.rstrip().splitlines()[-1] == 'echo "BEACON $tail"')
check("B7 --serve: служба веб-сервера перезапускается (новый порт сразу), SyslogLevel=warning у маячка",
      "systemctl restart node-beacon-http.service" in bi
      and "SyslogLevel=warning\nLogLevelMax=warning" in bi.split("node-beacon.service <<UNIT", 1)[1].split("\nUNIT\n", 1)[0])
check("B8 установщик маячка в LF", "\r" not in bi)

if BASH:
    for name in ("beacon_install.sh", "witness_install.sh", "install.sh"):
        check(f"B9 bash -n {name}", subprocess.run([BASH, "-n", os.path.join(HERE, name)]).returncode == 0)
    fn = bi.split("ufw_delete_saved() {\n", 1)[1].split("\n}\n", 1)[0]
    work = tempfile.mkdtemp()
    try:
        wpath = work.replace("\\", "/")
        os.makedirs(os.path.join(work, "bin"))
        with open(os.path.join(work, "bin", "ufw"), "w", newline="\n") as f:
            f.write('#!/bin/sh\nfor a in "$@"; do printf "[%s]" "$a"; done >> "$LOG"; echo >> "$LOG"\n')
        os.chmod(os.path.join(work, "bin", "ufw"), 0o755)
        with open(os.path.join(work, "ufw-rule"), "w", newline="\n") as f:
            f.write("allow from 203.0.113.7$(touch PWNED) to any port 8080 proto tcp\n")
        r = bash(f'set -euo pipefail; ETC="{wpath}"; ufw_delete_saved() {{\n{fn}\n}}\ncd "{wpath}"; ufw_delete_saved',
                 env={"PATH": f"{wpath}/bin:" + os.environ.get("PATH", ""), "LOG": f"{wpath}/log"})
        log = open(os.path.join(work, "log"), encoding="utf-8").read() if os.path.exists(os.path.join(work, "log")) else ""
        check("B10 удаление правила подставным ufw: аргументы словами, подстановка $(…) не выполняется",
              r.returncode == 0 and not os.path.exists(os.path.join(work, "PWNED"))
              and log.strip() == "[delete][allow][from][203.0.113.7$(touch][PWNED)][to][any][port][8080][proto][tcp]")
    finally:
        shutil.rmtree(work, ignore_errors=True)

# --- install.sh ---
ins = src_of("install.sh")
check("I1 install.sh в LF", "\r" not in ins)
for name in ("channel-watch", "channel-watch-build", "channel-watch-speed", "channel-watch-lists", "channel-watch-loss",
             "channel-watch-side"):
    after = ins.split(f"cat > /etc/systemd/system/{name}.service <<'UNIT'\n", 1)[1].split("\nUNIT\n", 1)[1]
    check(f"I2 песочница дописывается в {name}.service",
          after.startswith("py_sandbox") and after.split("\n", 1)[0].endswith(f">> /etc/systemd/system/{name}.service"))
box = ins.split("py_sandbox() {", 1)[1].split("\n}\n", 1)[0]
check("I3 песочница Python-служб: запись только в свои папки, /var/log и папки пульса; /home только чтение",
      "ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log${1:-}" in box
      and all(d in box for d in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes"))
      and 'py_sandbox "$hb_rw" >> /etc/systemd/system/channel-watch.service' in ins
      and 'hb_rw="$hb_rw -$d"' in ins and '"$ETC/heartbeat.path" "$ETC/heartbeat-full.path"' in ins)
xu = ins.split("cat > /etc/systemd/system/channel-watch-xray.service <<UNIT\n", 1)[1].split("\nUNIT\n", 1)[0]
check("I4 Xray от DynamicUser без возможностей, конфиг через LoadCredential; старый systemd — запасной путь от root",
      "LoadCredential=xray.json:/etc/channel-watch/xray.json\nDynamicUser=yes" in ins
      and "xray run -c ${CREDENTIALS_DIRECTORY}/xray.json'" in ins and "ExecStart=$xexec" in xu and "$xuser" in xu
      and "-ge 250 ]" in ins and "xray run -c /etc/channel-watch/xray.json'" in ins
      and all(d in xu for d in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "MemoryMax=96M")))
check("I5 юнит или бинарник Xray изменились — работающий Xray перезапускается",
      'systemctl try-restart channel-watch-xray.service' in ins.split("systemctl daemon-reload\n# новый бинарник", 1)[1]
      and 'xray_unit_was="$(cat /etc/systemd/system/channel-watch-xray.service' in ins)
check("I6 байт-код заранее (в песочнице /opt только чтение)", "python3 -m compileall -q /opt/channel-watch" in ins)
xb = ins.split("xver() {", 1)[1].split("\nfi\nrm -f \"$tmpx\"", 1)[0]
check("I7 Xray: из контейнера — только если новее; --xray — всегда; замена через mv",
      'newer "$(xver "$cand")" "$(xver /opt/channel-watch/xray)"' in xb and '[ -n "$xray_src" ] ||' in xb
      and "mv -f /opt/channel-watch/.xray.new /opt/channel-watch/xray" in xb and "оставлен прежний" in xb)
if BASH:
    nf = [ln for ln in ins.splitlines() if ln.startswith("newer() {")][0]

    def newer(a, b):
        return bash(f"{nf}\nnewer '{a}' '{b}'").returncode == 0

    check("I8 сравнение версий Xray: 25.10.15 новее 25.9.1, не новее себя и старших; неизвестная установленная — замена",
          newer("25.10.15", "25.9.1") and not newer("25.9.1", "25.10.15") and not newer("25.9.1", "25.9.1")
          and newer("1.8.24", "") and not newer("", "25.9.1") and newer("26.1.0", "25.12.31"))
    r0 = bash("set -euo pipefail\npy_sandbox() {" + box + "\n}\npy_sandbox; echo ==; py_sandbox ' -/srv/hb'")
    a0, a1 = (r0.stdout.split("==\n") + [""])[:2]
    check("I9 py_sandbox под set -u: без папок пульса и с ними (на стенде без ${1:-} установка падала)",
          r0.returncode == 0 and "ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log\n" in a0
          and "ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log -/srv/hb\n" in a1)

print(f"\nвсе {ok} проверок прошли")
