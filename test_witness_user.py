"""Тесты: свидетель не от root. Отдельный пользователь node-witness, одна
возможность CAP_NET_RAW, запись в папку файла через ACL только для него (снимается при --uninstall), откат на прежнюю
схему (root с узкими возможностями), если ACL нельзя; tcpdump без -Z; самовосстановление ACL после chmod папки;
site.json читается группой node-witness. Без сети: фрагменты установщика — в bash с подставными командами."""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import node_witness as nw  # noqa: E402

ok = 0
skipped = []


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    print("OK  ", name)
    ok += 1


def src_of(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


BASH = shutil.which("bash")


def bash(script, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, encoding="utf-8", env=e)


def between(text, start, end, keep_end=False):
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b + (len(end) if keep_end else 0)]


wi = src_of("witness_install.sh")
unin = between(wi, 'if [ "${1:-}" = "--uninstall" ]; then', "\nfi\n")
inst = wi[len(wi.split('[ -s "$SRC/node_witness.py" ]', 1)[0]):]

# --- установщик: порядок и состав (по тексту) ---
check("N1 пользователь системный, без входа и домашней папки, создаётся только если его нет",
      'if ! id -u "$WUSER" >/dev/null 2>&1; then' in inst and "useradd --system" in inst
      and "--no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin" in inst and "WUSER=node-witness" in wi)
check("N2 ACL: только своему пользователю, только на папку файла (без -R и без default), проверка записью от его имени",
      'setfacl -P -m "u:$WUSER:rwx" -- "$dir"' in inst and 'safe_parents "$dir"' in inst and '[ ! -L "$dir" ]' in inst and 'runuser -u "$WUSER" -- test -w "$dir" -a -x "$dir"' in inst
      and " -R " not in wi and "-d -m" not in wi.replace("install -d -m", "") and "chmod -R" not in wi
      and "chown -R" not in wi)
check("N3 setfacl нет — пакет acl из apt; ACL не вышел — откат на прежнюю схему с понятным сообщением",
      "apt-get install -y -qq acl" in inst and inst.find("apt-get install -y -qq acl") < inst.find('setfacl -P -m "u:$WUSER')
      and "ВНИМАНИЕ: не удалось дать пользователю $WUSER запись" in inst and "прежней схеме" in inst
      and inst.find("useradd --system") < inst.find('setfacl -P -m "u:$WUSER'))
check("N4 владелец и права самой папки не меняются (ни chown, ни chmod на $dir)",
      'chown -h "$owner:" "$out"' in inst
      and not any(f'{c} "$dir"' in wi or f"{c} -- \"$dir\"" in wi for c in ("chown", "chmod", "chgrp")))
check("N5 --uninstall: служба стоп → файл → ACL (по out и по сохранённой папке) → настройки → пользователь и группа",
      unin.index("systemctl disable --now") < unin.index("rm_out") < unin.index('acl_off "$(dirname "$(cat "$ETC/out")")"')
      < unin.index('acl_off "$(cat "$ETC/acl")"') < unin.index('rm -rf "$APP" "$ETC" "$UNIT"')
      < unin.index('userdel "$WUSER"') < unin.index('groupdel "$WUSER"'))
check("N6 маячок переехал — ACL с прежней папки снимается; повторный запуск идемпотентен (useradd/ACL только если нет)",
      '[ "$(cat "$ETC/acl")" != "$dir" ]' in inst and 'acl_off "$(cat "$ETC/acl")"; rm -f "$ETC/acl"' in inst
      and 'echo "$dir" > "$ETC/acl"' in inst)
check("N7 переход с прежней установки: файл тот же, владелец — новый (chown -h, не по ссылке); 0644 ставит сам свидетель",
      'if [ -f "$out" ] && [ ! -L "$out" ]; then chown -h "$owner:" "$out"; fi' in inst
      and inst.index('chown -h "$owner:"') < inst.index("systemctl restart node-witness.service"))
check("N8 site.json читает сам свидетель: папка настроек root:node-witness 2750, файл 640; в прежней схеме — 700",
      'install -d -m 2750 -o root -g "$WUSER" "$ETC"' in inst and 'chgrp "$WUSER" "$ETC/site.json"; chmod 640' in inst
      and 'install -d -m 700 -o root -g root "$ETC"' in inst)

check("N33 setfacl не идёт по ссылке (-P) — и в установщике, и в ExecStartPre, и при снятии; папки над папкой файла проверяются",
      "setfacl -P -x" in wi and "setfacl -P -b" in wi and "-P -m u:$WUSER:rwx" in wi and "safe_parents()" in wi
      and "?????w????|????????w?" in wi)
check("N34 общие tmpfs хоста службе недоступны, передача прежнего файла без перехода по ссылке",
      "PrivateIPC=yes" in wi and "InaccessiblePaths=-/dev/shm -/run/lock" in wi and 'chown -h "$owner:" "$out"' in wi
      and 'chmod 644 "$out"' not in wi)


# --- юнит: собрать фрагментом установщика в обоих режимах ---
if BASH:
    work = tempfile.mkdtemp()
    try:
        wp = work.replace("\\", "/")
        os.makedirs(os.path.join(work, "bin"))
        for name, body in (("setfacl", "exit 0"), ("stat", 'echo "$STAT_OUT"')):
            with open(os.path.join(work, "bin", name), "w", newline="\n") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(os.path.join(work, "bin", name), 0o755)
        frag = between(wi, 'case "$dir" in   # папка сайта', "\nEOF\n", keep_end=True)

        def unit(asuser, d="/var/www/test/site", stat_out="0 drwxr-xr-x"):
            r = bash(f'set -euo pipefail\nWUSER=node-witness; APP=/opt/node-witness; UNIT="{wp}/u.service"\n'
                     f'dir="{d}"; out="{d}/fw-abc.json"; asuser={asuser}\n{frag}\ncat "$UNIT"',
                     env={"PATH": f"{wp}/bin:" + os.environ.get("PATH", ""), "STAT_OUT": stat_out})
            return r.returncode, r.stdout

        rc1, u1 = unit(1)
        l1 = u1.splitlines()
        pre = [x for x in l1 if x.startswith("ExecStartPre=")]
        check("U1 обычный режим: User=node-witness, только CAP_NET_RAW (и в Ambient, и в Bounding), без SETUID/DAC",
              rc1 == 0 and "User=node-witness" in l1 and "Group=node-witness" in l1
              and "CapabilityBoundingSet=CAP_NET_RAW" in l1 and "AmbientCapabilities=CAP_NET_RAW" in l1
              and "CAP_SETUID" not in u1 and "CAP_DAC_OVERRIDE" not in u1 and "CAP_NET_ADMIN" not in u1)
        check("U2 перед стартом ACL ставится заново от root вне песочницы, ошибка не мешает старту («-+»)",
              len(pre) == 1 and pre[0].startswith("ExecStartPre=-+") and pre[0].endswith('setfacl -P -m u:node-witness:rwx '
                                                                                        '"/var/www/test/site"'))
        check("U3 песочница: запись только в папку, NoNewPrivileges, ProtectSystem=strict, AF_PACKET для tcpdump и т. д.",
              all(x in l1 for x in ('ReadWritePaths="/var/www/test/site"', "NoNewPrivileges=yes", "ProtectSystem=strict",
                                    "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
                                    "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
                                    "ProtectProc=invisible", "RestrictSUIDSGID=yes", "UMask=0022", "MemoryMax=64M",
                                    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET",
                                    'ExecStart=/usr/bin/python3 "/opt/node-witness/node_witness.py" '
                                    '"/var/www/test/site/fw-abc.json"')))
        rc2, u2 = unit(0, stat_out="33 drwxr-xr-x")
        l2 = u2.splitlines()
        check("U4 прежняя схема (ACL нельзя): без User=, захват + смена пользователя для tcpdump, папка не root-а — "
              "DAC_OVERRIDE, без ExecStartPre",
              rc2 == 0 and not any(x.startswith(("User=", "ExecStartPre=")) for x in l2)
              and "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE" in l2
              and "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in l2 and "NoNewPrivileges=yes" in l2)
        rc3, u3 = unit(0, stat_out="0 drwxr-xr-x")
        check("U5 прежняя схема, папка root-а с записью для него — без DAC_OVERRIDE",
              rc3 == 0 and "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID" in u3.splitlines())
        rc4, u4 = unit(1, d="/home/site/www")
        check("U6 папка в /home — ProtectHome=read-only (иначе папка была бы скрыта)",
              rc4 == 0 and "ProtectHome=read-only" in u4.splitlines() and "User=node-witness" in u4.splitlines())

        # --- acl_off с подставными getfacl/setfacl ---
        fn = between(wi, "acl_off() {", "\n}\n", keep_end=True)
        with open(os.path.join(work, "bin", "getfacl"), "w", newline="\n") as f:
            f.write('#!/bin/sh\ncat "$ACL"\n')
        with open(os.path.join(work, "bin", "setfacl"), "w", newline="\n") as f:
            # -P (не идти по ссылке) обязателен: без него заглушка помечает вызов NO-P, и проверки ниже падают
            f.write('#!/bin/sh\nif [ "$1" = -P ]; then shift; else set -- NO-P "$@"; fi\necho "$*" >> "$LOG"\n'
                    'case "$1" in -x) grep -v "^user:node-witness:" "$ACL" | sed "s/^mask::rwx/mask::$MASK_AFTER/" > "$ACL.n"'
                    ' && mv "$ACL.n" "$ACL" ;; esac\n')
        for n in ("getfacl", "setfacl"):
            os.chmod(os.path.join(work, "bin", n), 0o755)
        os.makedirs(os.path.join(work, "site"))

        def acl_off(acl, mask_after="r-x"):
            with open(os.path.join(work, "acl"), "w", newline="\n") as f:
                f.write(acl)
            log = os.path.join(work, "log")
            if os.path.exists(log):
                os.remove(log)
            r = bash(f'set -euo pipefail\nWUSER=node-witness\n{fn}\nacl_off "{wp}/site"; echo DONE',
                     env={"PATH": f"{wp}/bin:" + os.environ.get("PATH", ""), "ACL": f"{wp}/acl", "LOG": f"{wp}/log",
                          "MASK_AFTER": mask_after})
            calls = open(log, encoding="utf-8").read().split("\n") if os.path.exists(log) else []
            return r.returncode == 0 and "DONE" in r.stdout, [c.split(" -- ")[0] for c in calls if c]

        base = "user::rwx\ngroup::r-x\nother::r-x\n"
        okr, calls = acl_off("user::rwx\nuser:node-witness:rwx\ngroup::r-x\nmask::rwx\nother::r-x\n\n")
        check("A1 только наш ACL: setfacl -x, затем -b (оставшаяся mask равна правам группы) — папка как до установки",
              okr and calls == ["-x u:node-witness", "-b"])
        okr, calls = acl_off("user::rwx\nuser:node-witness:rwx\nuser:www-data:r-x\ngroup::r-x\nmask::rwx\nother::r-x\n")
        check("A2 есть чужие записи ACL — снимается только наша, остальное не трогается",
              okr and calls == ["-x u:node-witness"])
        okr, calls = acl_off(base)
        check("A3 нашей записи нет — setfacl не вызывается", okr and calls == [])
        okr, calls = acl_off("user::rwx\nuser:node-witness:rwx\ngroup::rwx\nmask::rwx\nother::r-x\n", mask_after="r-x")
        check("A4 mask после снятия не равна правам группы — -b не делается (иначе группа получила бы больше)",
              okr and calls == ["-x u:node-witness"])
        r = bash(f'set -euo pipefail\nWUSER=node-witness\n{fn}\nacl_off ""; acl_off "{wp}/нет-папки"; echo DONE',
                 env={"PATH": f"{wp}/bin:" + os.environ.get("PATH", ""), "ACL": f"{wp}/acl", "LOG": f"{wp}/log"})
        check("A5 пустой путь и нет папки — тихо ничего", r.returncode == 0 and "DONE" in r.stdout)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    check("B1 bash -n witness_install.sh", subprocess.run([BASH, "-n", os.path.join(HERE, "witness_install.sh")]).returncode == 0)
else:
    skipped.append("U1–U6, A1–A5, B1 (нет bash)")

# --- свидетель: tcpdump без -Z, если не root ---
real_root, real_pwd = nw.is_root, nw.pwd


class FakePwd:
    @staticmethod
    def getpwnam(name):
        if name != "tcpdump":
            raise KeyError(name)
        return object()


try:
    nw.pwd = FakePwd
    nw.is_root = lambda: False
    c_user = nw.tcpdump_cmd("eth0", {"10.0.0.5"})
    nw.is_root = lambda: True
    c_root = nw.tcpdump_cmd("eth0", {"10.0.0.5"})
finally:
    nw.is_root, nw.pwd = real_root, real_pwd
check("T1 свидетель не от root — tcpdump без -Z (захват по унаследованной CAP_NET_RAW); от root — -Z tcpdump",
      "-Z" not in c_user and c_user[-1] == nw.build_filter({"10.0.0.5"}) and "-p" in c_user
      and c_root[c_root.index("-Z") + 1] == "tcpdump")
check("T2 фильтр и пределы не изменились",
      nw.MAX_LIVE == 2000 and nw.MAX_FLOWS == 4000 and nw.MAX_BYTES == 350000 and nw.WRITE_EVERY == 10
      and "tcp[20:2] = 0x0204" in nw.FILTER)


# --- write_loop: отказ записи → выход на перезапуск (ACL вернёт служба) ---
class Stop(Exception):
    pass


def run_loop(errors, root=False, limit=10):
    """errors — что бросает write на каждом шаге (None — запись прошла). Возвращает (код выхода или None, шагов)."""
    seq = list(errors)
    steps = {"n": 0}
    real_write, real_root2 = nw.write, nw.is_root

    def fake_write(path, data):
        e = seq.pop(0) if seq else None
        if e:
            raise e

    def fake_sleep(_):
        steps["n"] += 1
        if steps["n"] >= limit:
            raise Stop()

    code = {"c": None}

    def fake_quit(c):
        code["c"] = c
        raise Stop()

    nw.write, nw.is_root = fake_write, (lambda: root)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            nw.write_loop("/x/fw-a.json", nw.Flows(), sleep=fake_sleep, quit=fake_quit)
    except Stop:
        pass
    finally:
        nw.write, nw.is_root = real_write, real_root2
    return code["c"], steps["n"]


P = PermissionError(13, "Permission denied")
c, n = run_loop([P, P, P])
check("L1 три отказа записи подряд (≈30 с) — выход с кодом 75, systemd перезапустит и вернёт ACL",
      c == 75 and n == 2 and nw.DENIED_EXIT == 3)
c, n = run_loop([P, P, None, P, P, None, P, P])
check("L2 отказы вперемежку с удачными записями — не выходит", c is None and n == 10)
c, n = run_loop([P] * 12, root=True)
check("L3 свидетель от root (прежняя схема) — перезапуск не поможет, не выходит, только сообщения", c is None and n == 10)
c, n = run_loop([OSError(28, "No space left")] * 12)
check("L4 другие ошибки записи (нет места) — не выходит", c is None and n == 10)

# --- site.json не читается — предупреждение, а не молчание ---
real_open = nw.__dict__.get("open")


def deny(*a, **k):
    raise PermissionError(13, "Permission denied", a[0])


err = io.StringIO()
nw.open = deny
try:
    with contextlib.redirect_stderr(err):
        got = nw.load_marks("/etc/node-witness/site.json")
finally:
    if real_open is None:
        del nw.open
    else:
        nw.open = real_open
check("S1 site.json есть, но не читается — прежний диапазон и предупреждение в журнал (про группу node-witness)",
      got == [nw.MARK_DEFAULT] and "не прочитал /etc/node-witness/site.json" in err.getvalue()
      and "node-witness" in err.getvalue())
err2 = io.StringIO()
with contextlib.redirect_stderr(err2):
    got2 = nw.load_marks(os.path.join(HERE, "нет-такого-site.json"))
check("S2 файла нет — прежний диапазон молча (как раньше)", got2 == [nw.MARK_DEFAULT] and err2.getvalue() == "")

for name in ("witness_install.sh", "node_witness.py", "test_witness_user.py", "test_witness.py"):
    raw = open(os.path.join(HERE, name), "rb").read()
    raw.decode("utf-8")
    check(f"E1 UTF-8, LF без CR: {name}", b"\r" not in raw)

print(f"\nвсе {ok} проверок прошли" + ("; пропущено: " + ", ".join(skipped) if skipped else ""))
