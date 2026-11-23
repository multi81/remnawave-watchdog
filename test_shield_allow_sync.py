"""Тесты: allow-sync щита — свои от сторожа отдельным набором. Без сети и без nft: python test_shield_allow_sync.py
1) сторож шлёт в allow-sync только то, что установщик щита и так кладёт в allow (ваши адреса из owner.txt,
   ddos.json) и свой адрес, без нод nodes.json и точек vantage.json (адрес выхода ноды — трафик клиентов VPN);
2) щит принимает сети не шире /24 (IPv4) и /64 (IPv6);
3) блокировки адресов, ставших своими, снимаются той же транзакцией nft и из state, ответ говорит об этом."""
import contextlib
import io
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shield_ctl as s  # noqa: E402
import scanlists as sl  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


class Nft:
    """Подставной nft: kernel — элементы blocked4/6 в ядре; table=False — таблицы нет; fail_f — nft -f падает."""
    def __init__(self, kernel=None, table=True, fail_f=False):
        self.kernel, self.table, self.fail_f = dict(kernel or {}), table, fail_f
        self.calls, self.inputs = [], []

    def __call__(self, args, inp=None):
        self.calls.append(list(args))
        self.inputs.append(inp)
        if not self.table:
            raise RuntimeError("nft %s: Error: No such file or directory" % " ".join(args[:3]))
        if args[:1] == ["-f"] and self.fail_f:
            raise RuntimeError("nft -f -: Error: Could not process rule")
        if args[:3] == ["-j", "list", "set"]:
            name = args[-1]
            elem = [{"elem": {"val": k, "timeout": 600, "expires": 500}} for k in self.kernel.get(name, [])]
            return json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": name, "elem": elem}}]})
        return ""

    def f_inputs(self):
        return [i for a, i in zip(self.calls, self.inputs) if a[:1] == ["-f"]]


def no_dns(h, p):
    raise OSError("без сети")


C = dict(s.DEFAULTS, allow=["93.187.140.234"])

# --- 2) ширина своих: не шире /24 и /64
check("A1 ALLOW_MIN_PREFIX = {4: 24, 6: 64}", s.ALLOW_MIN_PREFIX == {4: 24, 6: 64})
nets_, bad_ = s.parse_allow_sync("10.0.0.0/16\n2001:db8::/32\n")
check("A2 10.0.0.0/16 и 2001:db8::/32 — отказ (шире /24 и /64)", nets_ == []
      and dict(bad_) == {"10.0.0.0/16": "слишком широкая (шире /24)", "2001:db8::/32": "слишком широкая (шире /64)"})
nets_, bad_ = s.parse_allow_sync("203.0.113.0/24\n198.51.100.128/25\n2001:db8:1:2::/64\n2001:db8:1:3::5\n"
                                 "198.51.0.0/23\n2001:db8:1::/63\n")
check("A3 ровно /24 и /64 и уже — приняты; /23 и /63 — отказ", nets_ == [
    "198.51.100.128/25", "203.0.113.0/24", "2001:db8:1:2::/64", "2001:db8:1:3::5/128"]
      and [x for x, _ in bad_] == ["198.51.0.0/23", "2001:db8:1::/63"])

real = {k: getattr(s, k) for k in ("nft", "STATE_FILE", "LOG_FILE", "ALLOW_SYNC_FILE", "CONF_FILE", "CLIENTS_FILE",
                                   "SCANNERS_FILE", "lock", "unlock", "tick_timer_state")}
real_stdin = sys.stdin
with tempfile.TemporaryDirectory() as tmp:
    s.STATE_FILE, s.LOG_FILE = os.path.join(tmp, "st.json"), os.path.join(tmp, "log")
    s.ALLOW_SYNC_FILE, s.CONF_FILE = os.path.join(tmp, "allow-sync.txt"), os.path.join(tmp, "config.json")
    s.CLIENTS_FILE, s.SCANNERS_FILE = os.path.join(tmp, "cl.json"), os.path.join(tmp, "sc.txt")
    s.tick_timer_state = lambda: "active"
    s.nft = Nft()
    try:
        s.cmd_allow_sync(dict(C), "10.0.0.0/16\n2001:db8::/32\n", {})
        check("A4 список только из широких сетей — отказ, файл не записан, ядро не тронуто", False)
    except ValueError as e:
        check("A4 список только из широких сетей — отказ, файл не записан, ядро не тронуто",
              "пустой" in str(e) and not os.path.exists(s.ALLOW_SYNC_FILE) and s.nft.f_inputs() == [])

    # --- 3) блокировки своих снимаются той же транзакцией
    t = int(time.time())
    st = {"blocks": {"93.184.216.34": t + 600, "198.51.100.7": t + 600, "2001:db8:5:6::": t + 600,
                     "93.184.216.40": t - 5}, "mode": "watch"}
    s.nft = Nft(kernel={"blocked4": ["93.184.216.34", "93.184.216.35", "198.51.100.7"], "blocked6": ["2001:db8:5:6::"]})
    r = s.cmd_allow_sync(dict(C), "93.184.216.34\n93.184.216.35\n2001:db8:5:6::77\n", st)
    fi = s.nft.f_inputs()
    check("A5 ответ: сняты блокировки своих — из state и только из ядра, IPv6 по /64",
          r["ok"] and set(r["unblocked"]) == {"93.184.216.34", "93.184.216.35", "2001:db8:5:6::"}
          and len(r["unblocked"]) == 3)
    check("A6 одна транзакция nft -f: allow4/6 заново и снятие блокировок вместе",
          len(fi) == 1 and fi[0].startswith("flush set %s allow4\nflush set %s allow6\n" % (s.TABLE, s.TABLE))
          and "delete element %s blocked4 { 93.184.216.34 }" % s.TABLE in fi[0]
          and "delete element %s blocked4 { 93.184.216.35 }" % s.TABLE in fi[0]
          and "delete element %s blocked6 { 2001:db8:5:6:: }" % s.TABLE in fi[0]
          and "198.51.100.7" not in fi[0])
    lines = fi[0].splitlines()
    check("A7 перед каждым delete — add того же элемента (отсутствующий в ядре не роняет транзакцию)",
          all(lines[i - 1] == ln.replace("delete element", "add element").replace(" }", " timeout 1s }")
              for i, ln in enumerate(lines) if ln.startswith("delete element")))
    st_file = json.load(open(s.STATE_FILE, encoding="utf-8"))
    check("A8 state: свои убраны, чужая блокировка осталась, истёкшая вычищена; mode не тронут",
          st_file["blocks"] == {"198.51.100.7": t + 600} and st["blocks"] == st_file["blocks"]
          and st_file["mode"] == "watch")
    check("A9 в журнале щита — какие блокировки сняты", "сняты блокировки своих" in open(s.LOG_FILE, encoding="utf-8").read())

    # без своих среди блокировок — ни delete, ни записи state
    os.remove(s.STATE_FILE)
    st = {"blocks": {"198.51.100.7": t + 600}}
    s.nft = Nft(kernel={"blocked4": ["198.51.100.7"]})
    r = s.cmd_allow_sync(dict(C), "93.184.216.34\n", st)
    check("A10 своих среди блокировок нет — unblocked пустой, delete нет, state не переписан",
          r["unblocked"] == [] and "blocked" not in s.nft.f_inputs()[0] and not os.path.exists(s.STATE_FILE))

    # таблицы нет: ядро не трогаем, но state чистим (load иначе вернул бы блокировку своего в blocked4)
    st = {"blocks": {"93.184.216.34": t + 600, "198.51.100.7": t + 600}}
    s.nft = Nft(table=False)
    r = s.cmd_allow_sync(dict(C), "93.184.216.34\n", st)
    check("A11 таблицы нет — applied=false, nft -f не вызывался, блокировка своего убрана из state",
          r["applied"] is False and r["unblocked"] == ["93.184.216.34"] and s.nft.f_inputs() == []
          and json.load(open(s.STATE_FILE, encoding="utf-8"))["blocks"] == {"198.51.100.7": t + 600})

    # nft не принял — ни файл, ни state не меняются
    before_file = open(s.ALLOW_SYNC_FILE, encoding="utf-8").read()
    st = {"blocks": {"93.184.216.50": t + 600}}
    s.save_state(st)
    s.nft = Nft(kernel={"blocked4": ["93.184.216.50"]}, fail_f=True)
    try:
        s.cmd_allow_sync(dict(C), "93.184.216.50\n", st)
        check("A12 nft -f упал — ошибка, файл и state прежние", False)
    except RuntimeError:
        check("A12 nft -f упал — ошибка, файл и state прежние",
              open(s.ALLOW_SYNC_FILE, encoding="utf-8").read() == before_file
              and json.load(open(s.STATE_FILE, encoding="utf-8"))["blocks"] == {"93.184.216.50": t + 600}
              and st["blocks"] == {"93.184.216.50": t + 600})

    # через main: state читается и пишется под блокировкой, ответ с unblocked
    s.save_state({"blocks": {"93.184.216.60": t + 600, "198.51.100.7": t + 600}})
    s.lock, s.unlock = (lambda *a, **k: None), (lambda fd: None)
    sys.stdin = io.StringIO("93.184.216.60\n")
    s.nft = Nft(kernel={"blocked4": ["93.184.216.60", "198.51.100.7"]})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = s.main(["allow-sync"])
    out = json.loads(buf.getvalue())
    check("A13 main allow-sync: ответ с unblocked, state на диске без своего",
          rc == 0 and out["unblocked"] == ["93.184.216.60"]
          and json.load(open(s.STATE_FILE, encoding="utf-8"))["blocks"] == {"198.51.100.7": t + 600})
    s.save_state({"blocks": {"93.184.216.61": t + 600}})
    st = json.load(open(s.STATE_FILE, encoding="utf-8"))
    s.nft = Nft()
    r = s.dispatch(["allow-sync"], dict(C), st, "93.184.216.61\n")
    check("A14 dispatch передаёт state в allow-sync", r["unblocked"] == ["93.184.216.61"] and st["blocks"] == {})
for k, v in real.items():
    setattr(s, k, v)
sys.stdin = real_stdin

# own_blocked: правила те же, что у отказа блокировать
c6 = dict(s.DEFAULTS, allow=[], allow_sync=["2a01:4f8:1:2::5/128", "2a01:4f8:9::/64", "93.184.216.0/24"])
check("A15 own_blocked: /64 со своим адресом внутри и своя /64 — свои; соседняя /64 и чужой IPv4 — нет; мусор пропущен",
      s.own_blocked(["2a01:4f8:1:2::", "2a01:4f8:9::", "2a01:4f8:1:3::", "93.184.216.9", "93.187.140.1", "мусор",
                     "93.184.216.9"], c6) == ["2a01:4f8:1:2::", "2a01:4f8:9::", "93.184.216.9"])
check("A16 own_blocked согласован с check_block: что нельзя заблокировать как своё, то и снимается",
      all((k in s.own_blocked([k], c6)) == (dict(s.check_block([k], c6)[1]).get(k) == "в списке своих")
          for k in ("2a01:4f8:1:2::", "2a01:4f8:9::", "2a01:4f8:1:3::", "93.184.216.9", "93.187.140.1")))

# --- 1) сторож: только ваши адреса (owner.txt), ddos.json и свой адрес
HS = {"DE7": {"host": "198.51.100.107"}, "NL1": {"host": "198.51.100.47"}, "NM": {"host": "shield.example"}}


def fake_dns(h, p):
    if h == "shield.example":
        return [(2, 1, 6, "", ("198.51.100.99", 0))]
    raise OSError("нет такого")


with tempfile.TemporaryDirectory() as tmp:
    real_etc = sl.ETC
    sl.ETC = tmp
    json.dump([{"name": "n1", "host": "192.0.2.10"}, {"name": "n2", "host": "node.example"}],
              open(os.path.join(tmp, "nodes.json"), "w", encoding="utf-8"))
    json.dump([{"url": "https://192.0.2.20:9109"}], open(os.path.join(tmp, "vantage.json"), "w", encoding="utf-8"))
    with open(os.path.join(tmp, "owner.txt"), "w", encoding="utf-8") as f:
        f.write("# ваши адреса\n93.184.89.45\n\n2001:db8:77::1  # дом\n")
    sync = {str(n) for n in sl.sync_networks(HS.values(), ["203.0.113.50", "2a01:4f8:c0c:1::5"], fake_dns)}
    installer = {"93.184.89.45/32", "2001:db8:77::1/128"} | {"198.51.100.107/32", "198.51.100.47/32", "198.51.100.99/32"}
    check("A17 sync_networks: ваши адреса (owner.txt, как у установщика), ddos.json (имена "
          "разрешены) и свой адрес; nodes.json и vantage.json — нет",
          sync == installer | {"203.0.113.50/32", "2a01:4f8:c0c:1::5/128"})
    check("A18 адреса владельца — из owner.txt (комментарии и пустые строки пропускаются), как у установщика щита",
          sl.owner_addrs() == ["93.184.89.45", "2001:db8:77::1"])
    body_ok = "".join("%s\n" % n for n in sl.sync_networks(HS.values(), ["203.0.113.50"], fake_dns))
    check("A19 новый щит принимает список сторожа целиком, без отказов", s.parse_allow_sync(body_ok)[1] == []
          and len(s.parse_allow_sync(body_ok)[0]) == len(body_ok.splitlines()))

    loads, syncs = {}, {}

    def ctl(h, args, inp=None):
        if args == ["scanners-load"]:
            loads[h] = inp
            return {"ok": True, "v4": 1}
        if args == ["allow-sync"]:
            syncs[h] = inp
            return {"ok": True, "n": len(inp.splitlines()), "applied": True, "refused_total": 0,
                    "unblocked": ["198.51.100.107"] if h == "DE7" else []}
        return {"ok": True, "clients": {}}
    sm = sl.run([], fetcher=lambda n: "192.0.2.0/24\n" if n == "skipa" else "37.0.113.0/24\n", run_ctl=ctl,
                hosts={k: v for k, v in HS.items() if k != "NM"}, send=None, now=1000, base=tmp, resolve=no_dns,
                self_addrs=["203.0.113.50"])
    body = set((syncs.get("DE7") or "").splitlines())
    check("A20 run: в allow-sync нет нод и точек (192.0.2.10, 192.0.2.20), есть ваши адреса, ddos.json и свой адрес",
          body and not body & {"192.0.2.10/32", "192.0.2.20/32"}
          and {"93.184.89.45/32", "198.51.100.107/32", "198.51.100.47/32", "203.0.113.50/32"} <= body)
    check("A21 run: из списка сканеров ноды и точки по-прежнему вырезаются (это не allow, а «не резать своих»)",
          "192.0.2.0/24" not in loads["DE7"] and "192.0.2.10" not in loads["DE7"] and "192.0.2.20" not in loads["DE7"]
          and "192.0.2.11/32" in loads["DE7"])
    check("A22 summary: снятые блокировки своих видны по серверу",
          sm["allow_sync"]["DE7"] == "ok, своих %d, сняты блокировки своих: 1" % len(body)
          and sm["allow_sync"]["NL1"].startswith("ok, своих") and "сняты" not in sm["allow_sync"]["NL1"])
    sl.ETC = real_etc
check("A23 ответ щита прежней версии (без unblocked) — как раньше", sl.allow_status(
    {"ok": True, "n": 5, "applied": True, "refused_total": 0}) == "ok, своих 5")
print("allow-sync щита: тестов пройдено %d" % ok)
