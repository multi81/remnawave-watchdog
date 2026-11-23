"""Тесты песочницы systemd на работающем стороже: sandbox_dropins.sh кладёт песочницу systemd отдельными файлами
<служба>.service.d/50-sandbox.conf — те же настройки, что пишет install.sh (сверяется по тексту обоих), с папками пульса
только у главной проверки; пробный запуск каждой службы после daemon-reload; сбой любой — откат всех drop-in (и при
прерывании); --rollback, --dry, --no-test, --skip-test; чужой 50-sandbox.conf не трогается. systemctl и journalctl —
заглушки (bash), папки — временные; root и настоящий systemd не нужны. Проверка на живом systemd — на стенде."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ok = 0


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
SCRIPT = os.path.join(HERE, "sandbox_dropins.sh").replace("\\", "/")
INSTALL = src_of("install.sh")
DROP = src_of("sandbox_dropins.sh")

PY_UNITS = ["channel-watch.service", "channel-watch-build.service", "channel-watch-speed.service",
            "channel-watch-lists.service", "channel-watch-loss.service", "channel-watch-side.service"]
DDOS_UNITS = ["channel-watch-ddos.service", "channel-watch-scanlists.service", "channel-watch-behavscan.service"]
XRAY = "channel-watch-xray.service"
SHIELD = "channel-watch-shieldbot.service"
LONG = [XRAY, SHIELD]

# заглушка systemctl: состояние — файлы в $FAKE; журнал вызовов — $FAKE/log (с пометкой, был ли drop-in в момент вызова)
FAKE_SYSTEMCTL = r'''#!/usr/bin/env bash
F="$FAKE"; D="$CW_UNIT_DIR"
has() { [ -f "$D/$1.d/50-sandbox.conf" ] && echo dropin || echo bare; }
case "$1" in
  --version) echo "systemd ${FAKE_SD:-255} (fake)"; exit 0 ;;
  daemon-reload) echo "daemon-reload" >> "$F/log"; exit 0 ;;
  show)
    p="$3"; u="$5"
    case "$p" in
      ProtectSystem)
        if [ -f "$F/noapply" ]; then echo no
        elif grep -qs '^ProtectSystem=strict$' "$D/$u.d/50-sandbox.conf"; then echo strict; else echo no; fi ;;
      Result) cat "$F/result.$u" 2>/dev/null || echo success ;;
      ActiveState)
        if [ -s "$F/busy.$u" ]; then n=$(cat "$F/busy.$u"); echo $((n - 1)) > "$F/busy.$u"
          [ "$n" -le 0 ] && rm -f "$F/busy.$u"; echo activating; exit 0; fi
        if [ -f "$F/state.$u" ]; then cat "$F/state.$u"; exit 0; fi
        case "$u" in channel-watch-xray.service|channel-watch-shieldbot.service) echo active ;; *) echo inactive ;; esac ;;
      MainPID)
        if [ -f "$F/flap.$u" ]; then n=$(cat "$F/flap.$u"); echo $((n + 1)) > "$F/flap.$u"; echo "$n"
        else echo 4242; fi ;;
    esac
    exit 0 ;;
  start)
    echo "start $2 $(has "$2")" >> "$F/log"
    if [ -f "$F/interrupt.$2" ]; then kill -TERM "$PPID"; exit 0; fi
    if [ -f "$F/fail.$2" ]; then echo exit-code > "$F/result.$2"; exit 1; fi
    echo success > "$F/result.$2"; exit 0 ;;
  restart|try-restart) echo "$1 $2 $(has "$2")" >> "$F/log"; exit 0 ;;
esac
echo "fake systemctl: $*" >> "$F/log"
'''
FAKE_JOURNALCTL = '#!/usr/bin/env bash\necho "journal of $2"\n'


class Env:
    def __init__(self, units=PY_UNITS + DDOS_UNITS + LONG, extra=(), hb=("/srv/p1/hb.json", "/srv/p2/full.json")):
        self.root = tempfile.mkdtemp()
        self.unit = os.path.join(self.root, "units")
        self.etc = os.path.join(self.root, "etc")
        self.fake = os.path.join(self.root, "fake")
        for d in (self.unit, self.etc, self.fake):
            os.makedirs(d)
        for u in list(units) + list(extra):
            self.write(os.path.join(self.unit, u), "[Service]\nExecStart=/bin/true\n")
        if hb:
            self.write(os.path.join(self.etc, "heartbeat.path"), hb[0] + "\n")
            if len(hb) > 1:
                self.write(os.path.join(self.etc, "heartbeat-full.path"), hb[1] + "\n")
        self.sc = os.path.join(self.root, "systemctl")
        self.jc = os.path.join(self.root, "journalctl")
        self.write(self.sc, FAKE_SYSTEMCTL)
        self.write(self.jc, FAKE_JOURNALCTL)

    @staticmethod
    def write(path, text):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def flag(self, name, text=""):
        self.write(os.path.join(self.fake, name), text)

    def p(self, path):
        return path.replace("\\", "/")

    def run(self, *args, sd=255):
        e = dict(os.environ)
        e.update({"CW_UNIT_DIR": self.p(self.unit), "CW_ETC": self.p(self.etc), "CW_SYSTEMCTL": self.p(self.sc),
                  "CW_JOURNALCTL": self.p(self.jc), "CW_PAUSE": "0", "FAKE": self.p(self.fake), "FAKE_SD": str(sd),
                  "MSYS_NO_PATHCONV": "1"})
        r = subprocess.run([BASH, SCRIPT] + list(args), capture_output=True, text=True, encoding="utf-8", env=e)
        return r.returncode, r.stdout + r.stderr

    def dropin(self, u):
        path = os.path.join(self.unit, u + ".d", "50-sandbox.conf")
        return open(path, encoding="utf-8", newline="").read() if os.path.exists(path) else None

    def log(self):
        path = os.path.join(self.fake, "log")
        return open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []


def directives(text):
    return [line for line in text.splitlines() if re.match(r"^[A-Z][A-Za-z]+=", line)]


# ---------- 1. те же настройки, что в install.sh ----------
def heredoc(src, start):
    i = src.index(start)
    j = src.index("<<EOF\n", i) + len("<<EOF\n")
    return src[j:src.index("\nEOF\n", j)]


py_inst = heredoc(INSTALL, "py_sandbox() {")
py_drop = heredoc(DROP, "py_sandbox() {")
check("песочница Python-служб в sandbox_dropins.sh слово в слово как в install.sh", py_inst == py_drop)
check("в ней NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, свои папки и /run только для чтения",
      all(x in py_drop for x in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=read-only",
                                 "PrivateTmp=yes", "ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log",
                                 "ReadOnlyPaths=/run")))
xray_unit = INSTALL[INSTALL.index("cat > /etc/systemd/system/channel-watch-xray.service"):]
xray_unit = xray_unit[:xray_unit.index("\nUNIT\n")]
xuser = INSTALL[INSTALL.index("xuser='"):INSTALL.index("cat > /etc/systemd/system/channel-watch-xray.service")]
xray_inst = set(directives(xray_unit)) | set(directives(xuser.replace("xuser='", "").replace("'", "")))
xd = DROP[DROP.index("xray_sandbox() {"):DROP.index("dropin_text() {")]
sandbox_keys = {"NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables",
                "ProtectKernelModules", "ProtectControlGroups", "ProtectClock", "ProtectHostname", "RestrictNamespaces",
                "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality", "SystemCallArchitectures",
                "RestrictAddressFamilies", "DynamicUser", "LoadCredential", "CapabilityBoundingSet", "AmbientCapabilities"}
inst_sb = {d for d in xray_inst if d.split("=", 1)[0] in sandbox_keys}
drop_sb = {d for d in directives(xd) if d.split("=", 1)[0] in sandbox_keys}
check("песочница Xray в sandbox_dropins.sh та же, что в install.sh (DynamicUser, LoadCredential и прочее)",
      inst_sb == drop_sb and "DynamicUser=yes" in drop_sb)
check("ExecStart Xray в drop-in тот же, что в install.sh для systemd 250+",
      "ExecStart=/opt/channel-watch/xray run -c ${CREDENTIALS_DIRECTORY}/xray.json" in xd
      and "xexec='/opt/channel-watch/xray run -c ${CREDENTIALS_DIRECTORY}/xray.json'" in INSTALL)
inst_units = set(re.findall(r"cat > /etc/systemd/system/(channel-watch[\w-]*\.service)", INSTALL))
check("все службы, которые ставит install.sh, есть в списке sandbox_dropins.sh",
      inst_units and all(u in DROP for u in inst_units) and inst_units == set(PY_UNITS) | {XRAY})
check("и службы DDoS-части из --uninstall install.sh (ddos, shieldbot, scanlists, behavscan)",
      all(u in DROP for u in ("channel-watch-ddos.service", SHIELD, "channel-watch-scanlists.service",
                              "channel-watch-behavscan.service")))
check("sandbox_dropins.sh: LF, без CR, начинается с #!", "\r" not in DROP and DROP.startswith("#!/usr/bin/env bash\n"))
check("install.sh: LF, без CR", "\r" not in INSTALL)
check("bash -n sandbox_dropins.sh", subprocess.run([BASH, "-n", SCRIPT]).returncode == 0)

# ---------- 2. обычный проход ----------
env = Env(extra=["channel-watch-guard.service"])
rc, out = env.run()
check("всё прошло — код 0, «песочница стоит»", rc == 0 and "песочница стоит" in out)
for u in PY_UNITS + DDOS_UNITS + LONG:
    d = env.dropin(u)
    if d is None or not d.startswith("# channel-watch: песочница systemd") or "\r" in d:
        check("drop-in у %s" % u, False)
check("drop-in у всех %d известных служб, с пометкой, LF" % len(PY_UNITS + DDOS_UNITS + LONG), True)
check("чужая channel-watch-guard.service пропущена (свои папки, другой сервер)",
      env.dropin("channel-watch-guard.service") is None and "пропускаю channel-watch-guard.service" in out)
main = env.dropin("channel-watch.service")
check("главной проверке — папки пульса из heartbeat.path и heartbeat-full.path (с «-»)",
      "ReadWritePaths=/etc/channel-watch /var/lib/channel-watch /var/log -/srv/p1 -/srv/p2\n" in main)
check("остальным Python-службам — без папок пульса, тот же набор, что в install.sh",
      env.dropin("channel-watch-lists.service").split("[Service]\n", 1)[1] == py_inst.replace("${1:-}", "") + "\n"
      and env.dropin("channel-watch-ddos.service").split("[Service]\n", 1)[1] == py_inst.replace("${1:-}", "") + "\n")
xr = env.dropin(XRAY)
check("Xray на systemd 255: ExecStart= сброшен, DynamicUser, LoadCredential, без полномочий",
      "ExecStart=\nExecStart=/opt/channel-watch/xray run -c ${CREDENTIALS_DIRECTORY}/xray.json\n" in xr
      and "DynamicUser=yes" in xr and "LoadCredential=xray.json:/etc/channel-watch/xray.json" in xr
      and "CapabilityBoundingSet=\n" in xr and "ReadWritePaths" not in xr)
check("кнопкам щита — песочница Python-служб (не Xray)", "DynamicUser" not in env.dropin(SHIELD)
      and "ProtectHome=read-only" in env.dropin(SHIELD))
lg = env.log()
starts = [x.split()[1] for x in lg if x.startswith("start ")]
check("daemon-reload до первого пробного запуска", lg.index("daemon-reload") < min(
    i for i, x in enumerate(lg) if x.startswith(("start ", "restart "))))
check("пробно запущены все разовые службы, каждая уже с drop-in",
      sorted(starts) == sorted(PY_UNITS + DDOS_UNITS)
      and all(x.endswith(" dropin") for x in lg if x.startswith("start ")))
check("пересборка каналов раньше главной проверки, Xray и кнопки щита перезапущены с drop-in",
      starts.index("channel-watch-build.service") < starts.index("channel-watch.service")
      and "restart %s dropin" % XRAY in lg and "restart %s dropin" % SHIELD in lg)
check("в отчёте — Result до песочницы", "Result до песочницы: success" in out)

# повторный запуск: те же файлы
before = {u: env.dropin(u) for u in PY_UNITS + LONG}
rc2, _ = env.run("--no-test")
check("повторный запуск безопасен: файлы те же, код 0", rc2 == 0 and all(env.dropin(u) == before[u] for u in before))

# ---------- 3. systemd старше 250, путь пульса с пробелом ----------
env = Env(hb=("/srv/my pulse/hb.json",))
rc, out = env.run("--dry", sd=249)
check("--dry ничего не пишет", rc == 0 and env.dropin(XRAY) is None and not env.log()
      and "== " in out and "50-sandbox.conf" in out)
check("systemd 249: Xray от root, без DynamicUser и без сброса ExecStart, но без полномочий",
      "DynamicUser" not in out and "ExecStart=" not in out and "CapabilityBoundingSet=" in out)
check("путь пульса с пробелом — предупреждение, в ReadWritePaths не попадает",
      "путь пульса" in out and "my pulse" not in out.split("предупреждение")[0].split("ReadWritePaths")[-1]
      and "-/srv/my" not in out)

# ---------- 4. сбой — откат всех ----------
env = Env()
env.flag("fail.channel-watch-lists.service")
rc, out = env.run()
lg = env.log()
check("служба не прошла — код 1, причина и журнал в выводе",
      rc == 1 and "НЕ ПРОШЛА: channel-watch-lists.service" in out and "journal of channel-watch-lists.service" in out)
check("откат: drop-in нет ни у одной службы, папки .d убраны",
      all(env.dropin(u) is None for u in PY_UNITS + DDOS_UNITS + LONG)
      and not any(n.endswith(".d") for n in os.listdir(env.unit)))
last_reload = len(lg) - 1 - lg[::-1].index("daemon-reload")
check("после отката daemon-reload и перезапуск Xray и кнопок щита уже без drop-in",
      "try-restart %s bare" % XRAY in lg[last_reload:] and "try-restart %s bare" % SHIELD in lg[last_reload:])
check("службы после упавшей пробно не запускались",
      not any(x.startswith("start channel-watch-loss.service") for x in lg))

# ---------- 5. --skip-test ----------
env = Env()
rc, out = env.run("--skip-test", "lists,channel-watch-side.service", "--skip-test", "channel-watch-ddos")
starts = [x.split()[1] for x in env.log() if x.startswith("start ")]
check("--skip-test: коротко, полностью и без .service; можно несколько раз",
      rc == 0 and "channel-watch-lists.service" not in starts and "channel-watch-side.service" not in starts
      and "channel-watch-ddos.service" not in starts and "channel-watch.service" in starts)
check("пропущенные тоже получают drop-in", env.dropin("channel-watch-lists.service") is not None)

# ---------- 6. чужой 50-sandbox.conf ----------
env = Env()
os.makedirs(os.path.join(env.unit, "channel-watch-speed.service.d"))
alien = os.path.join(env.unit, "channel-watch-speed.service.d", "50-sandbox.conf")
env.write(alien, "[Service]\nNice=5\n")
rc, out = env.run()
check("чужой 50-sandbox.conf: код 2, ничего не записано и не перезапущено",
      rc == 2 and "чужой файл" in out and env.dropin(XRAY) is None and not env.log()
      and open(alien, encoding="utf-8").read() == "[Service]\nNice=5\n")

# ---------- 7. --rollback не трогает чужое ----------
env = Env()
env.run("--no-test")
other = os.path.join(env.unit, "channel-watch.service.d", "10-other.conf")
env.write(other, "[Service]\nNice=3\n")
rc, out = env.run("--rollback")
check("--rollback: наши drop-in убраны, код 0", rc == 0 and all(env.dropin(u) is None for u in PY_UNITS + LONG)
      and "убрано drop-in: %d" % len(PY_UNITS + DDOS_UNITS + LONG) in out)
check("--rollback: чужой файл в той же папке и сама папка на месте", os.path.exists(other))
check("--rollback: daemon-reload и перезапуск Xray", "daemon-reload" in env.log()[-3:] or
      "try-restart %s bare" % XRAY in env.log())
rc, out = env.run("--rollback")
check("--rollback второй раз — без ошибок, убрано 0", rc == 0 and "убрано drop-in: 0" in out)

# ---------- 7а. прежняя метка (с пометкой после запятой) — тоже наша ----------
env = Env()
env.run("--no-test")
p = os.path.join(env.unit, XRAY + ".d", "50-sandbox.conf")
first, rest = open(p, encoding="utf-8").read().split("\n", 1)
env.write(p, first[:-1] + ", пометка)\n" + rest)
rc, out = env.run("--rollback")
check("--rollback: drop-in с прежней меткой «(sandbox_dropins.sh, …)» тоже убран", rc == 0 and env.dropin(XRAY) is None)

# ---------- 8. --no-test ----------
env = Env()
rc, out = env.run("--no-test")
lg = env.log()
check("--no-test: разовые не запускаются, Xray и кнопки щита перезапущены с drop-in",
      rc == 0 and not any(x.startswith("start ") for x in lg) and "restart %s dropin" % XRAY in lg
      and "restart %s dropin" % SHIELD in lg and "разовые службы пробно не запускались" in out)

# ---------- 9. долгоживущие: не работала, перезапуск по кругу ----------
env = Env()
env.flag("state.%s" % SHIELD, "inactive")
rc, out = env.run("--no-test")
check("кнопки щита не работали — не запускаются, проба не валит",
      rc == 0 and not any(SHIELD in x for x in env.log() if x.startswith("restart")) and "не работала" in out)
env = Env()
env.flag("flap.%s" % XRAY, "500")
rc, out = env.run()
check("Xray после перезапуска не держится (PID меняется) — откат всех, разовые не запускались",
      rc == 1 and "не держится" in out and env.dropin("channel-watch.service") is None
      and not any(x.startswith("start ") for x in env.log()))

# ---------- 10. systemd не применил ----------
env = Env()
env.flag("noapply")
rc, out = env.run()
check("ProtectSystem не strict после daemon-reload — откат, пробы не было",
      rc == 1 and "не применил" in out and env.dropin(XRAY) is None
      and not any(x.startswith(("start ", "restart ")) for x in env.log()))

# ---------- 11. проход, начатый до песочницы, дожидается ----------
env = Env(units=["channel-watch-build.service"])
env.flag("busy.channel-watch-build.service", "1")
rc, out = env.run()
check("служба была в работе — сначала дождались, потом пробный запуск", rc == 0
      and [x for x in env.log() if x.startswith("start ")] == ["start channel-watch-build.service dropin"]
      and not os.path.exists(os.path.join(env.fake, "busy.channel-watch-build.service")))

# ---------- 12. прерывание во время пробы ----------
env = Env()
env.flag("interrupt.channel-watch-speed.service")
rc, out = env.run()
check("прервали во время пробы — откат всех drop-in, код 130",
      rc == 130 and "прервано" in out and all(env.dropin(u) is None for u in PY_UNITS + DDOS_UNITS + LONG))

# ---------- 13а. install.sh --uninstall убирает и drop-in песочницы ----------
m = re.search(r"\n(  for f in /etc/systemd/system/channel-watch\*\.service\.d/50-sandbox\.conf; do\n.*?\n  done)\n",
              INSTALL, re.S)
check("в install.sh --uninstall есть уборка drop-in песочницы", m is not None
      and INSTALL.index("--uninstall) uninstall=1") < m.start() < INSTALL.index('echo "сторож убран.'))
env = Env()
env.run("--no-test")
other = os.path.join(env.unit, "channel-watch-lists.service.d", "10-other.conf")
env.write(other, "[Service]\nNice=3\n")
alien_dir = os.path.join(env.unit, "channel-watch-loss.service.d")
os.remove(os.path.join(alien_dir, "50-sandbox.conf"))
env.write(os.path.join(alien_dir, "50-sandbox.conf"), "[Service]\nNice=4\n")
snippet = m.group(1).replace("/etc/systemd/system", env.p(env.unit))
r = subprocess.run([BASH, "-c", "set -euo pipefail\n" + snippet], capture_output=True, text=True, encoding="utf-8")
check("уборка из --uninstall: наши drop-in и пустые папки убраны, чужие файлы на месте",
      r.returncode == 0 and env.dropin("channel-watch.service") is None and env.dropin(XRAY) is None
      and not os.path.exists(os.path.join(env.unit, "channel-watch.service.d"))
      and os.path.exists(other) and env.dropin("channel-watch-loss.service") == "[Service]\nNice=4\n")

# ---------- 13. служб нет ----------
env = Env(units=[])
rc, out = env.run()
check("служб сторожа нет — код 1, ничего не делается", rc == 1 and "нечего делать" in out and not env.log())

print("\nвсего проверок: %d — все прошли" % ok)
