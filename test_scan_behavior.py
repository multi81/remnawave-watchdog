"""Тесты списка сканеров «по поведению» (behavscan) и списков сканеров (scanlists): стук с нескольких нод и в разные
сутки, клиенты и свои, рост и уменьшение списков, дробление широких сетей; блоки П1–П10 и Р1–Р9.
Без сети: python test_scan_behavior.py"""
import io
import ipaddress
import json
import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behavscan as bs  # noqa: E402
import ddoswatch  # noqa: E402
import scanlists as sl  # noqa: E402
import shield_ctl  # noqa: E402

ok = 0
TMP = tempfile.mkdtemp()
bs.SALT = os.path.join(TMP, "behavscan.salt")   # соль — во временный файл, не в /var/lib


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


NOW = 1_800_000_000
DAY = 86400
N = ipaddress.ip_network
own = [N("192.0.2.10/32")]
HOST = {"hosting": True, "mobile": False, "as": "AS64500 Scan"}


def info_all(d=None):
    """lookup: всем — хостинг (или что задано в d по адресу)."""
    calls = []

    def lookup(ips):
        calls.append(sorted(ips))
        return {i: (d or {}).get(i, HOST) for i in ips}
    lookup.calls = calls
    return lookup


def kn(*rows_by_node):
    """kn(("A", [строки]), ("B", [строки])) -> маячки."""
    return {node: {"ts": NOW, "knocks": rows} for node, rows in rows_by_node}


# ---------------- клиенты кусками по 50, молчащий щит = «неизвестно» ----------------
sent = []


def ctl_ok(h, args):
    sent.append((h, args))
    return {"ok": True, "clients": {}, "known": 0}


addrs = ["37.0.113.%d" % i for i in range(1, 121)]
found, known = bs.clients_via({"node-k": {}, "node-j": {}}, ctl_ok)(addrs)
lens = [len(a) - 1 for h, a in sent]
check("Н4-1 куски не больше 50 адресов, каждый щит спрошен обо всех", max(lens) <= 50 and sorted(lens) == [20, 20, 50, 50, 50, 50]
      and known is True and found == set())
check("Н4-2 кусок из 50 адресов щит по ssh принимает", all(shield_ctl.ssh_argv(" ".join(a)) == a for h, a in sent))


def ctl_one_bad(h, args):
    return {"ok": True, "clients": {"37.0.113.5": {}}} if h == "node-k" else {"ok": False, "error": "недопустимые символы"}


found, known = bs.clients_via({"node-k": {}, "node-j": {}}, ctl_one_bad)(addrs[:10])
check("Н4-3 один щит ответил не ok — клиенты неизвестны, но найденные у других учтены", known is False and found == {"37.0.113.5"})
found, known = bs.clients_via({"node-k": {}}, lambda h, a: None)(addrs[:10])
check("Н4-4 щит не ответил — неизвестно (а не «клиентов нет»)", known is False)
check("Н4-5 щитов нет вовсе — неизвестно", bs.clients_via({}, ctl_ok)(addrs[:3])[1] is False)

B2 = kn(("A", [["37.0.113.7", 1, 3, 1], ["37.0.113.8", 1, 3, 1]]), ("B", [["37.0.113.7", 1, 1, 1], ["37.0.113.8", 1, 1, 1]]))
st = {}
bs.step(st, B2, own, NOW, info_all(), clients_of=lambda ips: (set(), False))
l1, n1 = bs.step(st, B2, own, NOW + DAY, info_all(), clients_of=lambda ips: (set(), False))
check("Н4-6 щиты ответили не все — новых не вносим", l1 == [] and n1 == 0 and "37.0.113.7" in st["ips"])
l2, n2 = bs.step(st, B2, own, NOW + DAY + 60, info_all(), clients_of=lambda ips: None)
check("Н4-7 clients_of вернул None — тоже не вносим", l2 == [] and n2 == 0)
l3, n3 = bs.step(st, B2, own, NOW + DAY + 120, info_all(), clients_of=lambda ips: set())
check("Н4-8 щиты ответили — вносим", l3 == ["37.0.113.7", "37.0.113.8"] and n3 == 2)
l4, n4 = bs.step(st, B2, own, NOW + DAY + 180, info_all(), clients_unknown=True)
check("Н4-9 признак «клиенты неизвестны»: внесённые не трогаем", l4 == l3 and n4 == 0)
l5, _ = bs.step(st, B2, own + [N("37.0.113.8/32")], NOW + DAY + 240, info_all(), clients_unknown=True)
check("Н4-10 при неизвестных клиентах исключения всё равно работают", l5 == ["37.0.113.7"])
l6, _ = bs.step(st, B2, own, NOW + DAY + 300, info_all(), clients_of=lambda ips: ({"37.0.113.7"} & set(ips), False))
check("Н4-11 неполный ответ: найденный клиент всё равно выпадает", "37.0.113.7" not in l6)

# ---------------- 2 ноды и 2 суток; NEVER_LIST ----------------
spoof = kn(("A", [["77.18.0.1", 1, 1, 1]]))
st = {}
lk = info_all()
for d in range(5):
    lst, _ = bs.step(st, spoof, own, NOW + d * DAY, lk)
check("Н2-1 стук с одной ноды (поддельный SYN) хоть каждый день — не вносим", lst == [] and lk.calls == [])
st = {}
both = kn(("A", [["77.18.0.2", 1, 1, 1]]), ("B", [["77.18.0.2", 1, 1, 1]]))
l1, _ = bs.step(st, both, own, NOW, lk)
check("Н2-2 две ноды за одни сутки — не вносим", l1 == [])
check("Н2-3 пока не внесён — в state сутки и ноды", sorted(list(st["ips"]["77.18.0.2"]["days"].values())[0]) == ["A", "B"]
      and not st["ips"]["77.18.0.2"].get("listed"))
l2, _ = bs.step(st, both, own, NOW + 3 * 3600, lk)
check("Н2-4 второй проход в те же сутки — всё ещё одни сутки", l2 == [] and len(st["ips"]["77.18.0.2"]["days"]) == 1)
l3, _ = bs.step(st, kn(("A", [["77.18.0.2", 1, 1, 1]])), own, NOW + DAY, lk)
check("Н2-5 2 ноды и 2 суток (в сумме) — вносим", l3 == ["77.18.0.2"])
st = {}
day2 = kn(("A", [["77.18.0.3", 1, 1, 1]]))
bs.step(st, day2, own, NOW, lk)
l4, _ = bs.step(st, kn(("A", [["77.18.0.3", 2, 1, 1]])), own, NOW + DAY, lk)
check("Н2-6 2 суток, но одна нода — не вносим", l4 == [])

never_ips = ["149.154.167.220", "91.108.56.1", "104.16.1.1", "172.67.1.1", "140.82.112.3", "185.199.108.153",
             "208.95.112.1", "1.1.1.1", "8.8.8.8", "77.88.8.8", "9.9.9.9", "208.67.222.222"]
bad = kn(("A", [[ip, 20, 50, 1] for ip in never_ips]), ("B", [[ip, 20, 50, 1] for ip in never_ips]))
st = {}
lk = info_all()
bs.step(st, bad, own, NOW, lk)
l5, _ = bs.step(st, bad, own, NOW + DAY, lk)
check("Н2-7 Telegram, Cloudflare, GitHub, ip-api, публичные DNS не вносятся и не запоминаются",
      l5 == [] and st["ips"] == {} and lk.calls == [])
st["ips"]["149.154.167.220"] = {"first": NOW, "last": NOW + DAY, "listed": True, "looked": NOW, "mobile": False,
                                "hosting": True, "days": {bs.day_of(NOW + DAY): {"nodes": ["A", "B"], "ports": 1}}}
l6, _ = bs.step(st, {}, own, NOW + DAY + 60, lk)
check("Н2-8 попавший раньше адрес из NEVER_LIST снимается", l6 == [])
NEED = ["149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
        "91.108.56.0/22", "95.161.64.0/20", "185.76.151.0/24", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22", "143.55.64.0/20", "208.95.112.0/24", "1.1.1.1/32",
        "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32", "149.112.112.112/32", "77.88.8.8/32", "77.88.8.1/32",
        "208.67.222.222/32", "208.67.220.220/32"]
check("Н2-9 NEVER_LIST: все нужные сети на месте и разбираются", set(NEED) <= {str(n) for n in sl.never_networks()})

# ---------------- mobile, не-хостинги, проверка строк маячка ----------------
real_urlopen = bs.urllib.request.urlopen
seen_url = []


def fake_urlopen(req, timeout=None):
    seen_url.append(req.full_url)
    return io.BytesIO(json.dumps([{"query": "77.18.1.1", "status": "success", "hosting": False, "mobile": True,
                                   "as": "AS64600 Mobile"}]).encode())


bs.urllib.request.urlopen = fake_urlopen
try:
    got = bs.ip_api(["77.18.1.1"])
finally:
    bs.urllib.request.urlopen = real_urlopen
check("Н11-1 у ip-api запрашивается mobile", "mobile" in seen_url[0].split("fields=")[1].split(",")
      and got["77.18.1.1"]["mobile"] is True)
MOB = {"77.18.1.1": {"hosting": True, "mobile": True, "as": "AS64600 Mobile"}}
mob = kn(("A", [["77.18.1.1", 30, 99, 1]]), ("B", [["77.18.1.1", 30, 99, 1]]))
st = {}
bs.step(st, mob, own, NOW, info_all(MOB))
l1, _ = bs.step(st, mob, own, NOW + DAY, info_all(MOB))
check("Н11-2 мобильный не вносится никогда (даже 30 портов и «хостинг»)", l1 == [] and st["ips"]["77.18.1.1"]["listed"] is False)
HOME = {"77.18.2.%d" % i: {"hosting": False, "mobile": False, "as": "AS64700 ISP"} for i in range(1, 4)}
home = kn(("A", [["77.18.2.1", 10, 10, 0], ["77.18.2.2", 9, 9, 0], ["77.18.2.3", 15, 15, 0]]),
          ("B", [["77.18.2.1", 2, 2, 0], ["77.18.2.2", 9, 9, 0]]))
st = {}
bs.step(st, home, own, NOW, info_all(HOME))
l2, _ = bs.step(st, home, own, NOW + DAY, info_all(HOME))
check("Н11-3 домашний: 10+ портов и 2 ноды — да; 9 портов — нет; 15 портов с одной ноды — нет", l2 == ["77.18.2.1"])
rows = [["77.18.3.1", 70000, 1, 1], ["77.18.3.2", 0, 1, 1], ["77.18.3.3", 5, -1, 1], ["77.18.3.4", 5, 1, 7],
        ["77.18.3.5", 65535, 1, 1]]
agg = bs.aggregate({"A": {"knocks": rows}})
check("Н11-4 порты 1…65535, стуки не отрицательные, признак 0/1", set(agg) == {"77.18.3.5"})
many = [["11.%d.%d.1" % (i // 250, i % 250), 1, 1, 1] for i in range(500)]
agg = bs.aggregate({"A": {"knocks": many}})
check("Н11-5 с одной ноды не больше 400 строк, лишнее отброшено", len(agg) == bs.KNOCK_MAX == 400
      and "11.1.149.1" in agg and "11.1.150.1" not in agg)
st = {"ips": {"77.18.4.1": {"first": NOW, "last": NOW, "looked": NOW, "hosting": True, "as": "x", "listed": False,
                             "days": {bs.day_of(NOW): {"nodes": ["A", "B"], "ports": 1, "hits": 1, "strong": 1}}}}}
lk = info_all()
l3, _ = bs.step(st, kn(("A", [["77.18.4.1", 1, 1, 1]])), own, NOW + DAY, lk)
check("Н11-6 в старом кэше нет mobile — спрашиваем ip-api заново", lk.calls == [["77.18.4.1"]] and l3 == ["77.18.4.1"])

# ---------------- свои — хосты nodes.json и vantage.json ----------------
resolved = []


def resolve(name, port):
    resolved.append(name)
    if name == "nl1.example.net":
        return [(socket.AF_INET, 1, 6, "", ("77.18.5.1", 0)), (socket.AF_INET6, 1, 6, "", ("2001:db8::5", 0, 0, 0))]
    if name == "va.example.net":
        return [(socket.AF_INET, 1, 6, "", ("77.18.5.2", 0))]
    raise socket.gaierror("нет такого имени")


FILES = {"nodes.json": [{"name": "nl1", "host": "nl1.example.net"}, {"name": "de1", "host": "77.18.5.3"},
                        {"name": "x", "host": "gone.example.net"}, {"name": "y"}],
         "vantage.json": [{"name": "msk", "url": "http://77.18.5.4:9109", "token": "секрет"},
                          {"name": "spb", "url": "http://va.example.net:9109/"}, {"name": "z", "url": "мусор"}]}
oh = sl.own_hosts(resolve=resolve, load=lambda n: FILES.get(n, []))
check("Н13-1 адреса и имена нод и точек — свои, неразрешимое молча пропущено",
      {str(n) for n in oh} == {"77.18.5.1/32", "2001:db8::5/128", "77.18.5.3/32", "77.18.5.4/32", "77.18.5.2/32"})
check("Н13-2 адреса в файлах не разрешаются через DNS", "77.18.5.3" not in resolved and "77.18.5.4" not in resolved)
with tempfile.TemporaryDirectory() as tmp:
    for n, v in FILES.items():
        json.dump(v, open(os.path.join(tmp, n), "w", encoding="utf-8"))
    oh2 = sl.own_hosts(etc=tmp, resolve=resolve)
    check("Н13-3 читает настоящие файлы", {str(n) for n in oh2} == {str(n) for n in oh})
    empty = tempfile.mkdtemp(dir=tmp)
    check("Н13-4 файлов нет — пусто, без ошибок", sl.own_hosts(etc=empty, resolve=resolve) == [])
nodeknock = kn(("A", [["77.18.5.1", 10, 10, 1]]), ("B", [["77.18.5.1", 10, 10, 1]]))
st = {}
bs.step(st, nodeknock, own + oh, NOW, info_all())
l1, _ = bs.step(st, nodeknock, own + oh, NOW + DAY, info_all())
check("Н13-5 сторож стучит с ноды по портам — нода в список не попадает", l1 == [] and st["ips"] == {})

# ---------------- мелочи behavscan ----------------
check("М1 маячок с пустым knocks — не «со стуками»",
      bs.with_knocks({"a": {"ts": 1, "knocks": []}, "b": {"ts": 1}, "c": None, "d": {"ts": 1, "knocks": [["1.2.3.4", 1, 1, 1]]}}) == 1)
hit = kn(("A", [["77.18.6.1", 1, 5, 1]]), ("B", [["77.18.6.1", 1, 2, 1]]))
st = {}
lk = info_all()
bs.step(st, hit, own, NOW, lk)
bs.step(st, hit, own, NOW + DAY, lk)
h1 = st["ips"]["77.18.6.1"]["hits"]
bs.step(st, hit, own, NOW + DAY + 3600, lk)
check("М2 hits: два прохода за сутки не удваивают, за разные сутки складываются", h1 == 14 and st["ips"]["77.18.6.1"]["hits"] == 14)
st = {}
bs.SALT = os.path.join(TMP, "m.salt")
two = kn(("A", [["77.18.7.1", 1, 1, 1], ["77.18.7.2", 1, 1, 1]]), ("B", [["77.18.7.1", 1, 1, 1], ["77.18.7.2", 1, 1, 1]]))
bs.step(st, two, own, NOW, lk)
l1, _ = bs.step(st, two, own, NOW + DAY, lk, clients_of=lambda ips: {"77.18.7.1"} & set(ips))
salt = bs.load_salt(NOW + DAY)[0]
dump = json.dumps(st)
check("М3 адрес клиента в state не хранится, только солёный хэш", "77.18.7.1" not in dump and len(st["clients"]) == 1
      and bs.client_hash("77.18.7.1", salt) in st["clients"] and l1 == ["77.18.7.2"])
check("М4 соль создаётся один раз и хранится (в своём файле); хэш зависит от соли", "salt" not in st
      and bs.load_salt(NOW + 2 * DAY)[0] == salt and len(salt) >= 16
      and bs.client_hash("77.18.7.1", salt) != bs.client_hash("77.18.7.1", salt + "x"))
l2, _ = bs.step(st, two, own, NOW + 2 * DAY, lk, clients_of=lambda ips: set())
check("М5 исключение клиента работает как раньше: 30 дней не берём", l2 == ["77.18.7.2"] and "77.18.7.1" not in st["ips"])
old = {"ips": {"77.18.8.1": {"first": NOW, "client": NOW, "listed": False, "last": NOW},
               "77.18.8.2": {"first": NOW, "last": NOW, "listed": True, "nodes": ["A"], "ports": 1, "hits": 1, "strong": 1}}}
l3, _ = bs.step(old, {}, own, NOW + 60, lk)
check("М6 старый state: клиент переведён в хэш, внесённый по одному стуку снят", "77.18.8.1" not in json.dumps(old)
      and bs.client_hash("77.18.8.1", bs.load_salt(NOW + 60)[0]) in old["clients"] and l3 == [])

# ---------------- рост списков, NEVER_LIST в combine, общий предел, IPv6 /32 ----------------
prev = "".join("9.9.%d.0/24\n" % i for i in range(100))
t, nets, note = sl.choose("skipa", prev + "".join("9.8.%d.0/24\n" % i for i in range(51)), prev)
check("Н3-1 сетей больше чем в 1,5 раза — прошлая копия с заметкой", t == prev and len(nets) == 100 and "резко вырос" in note)
t, nets, note = sl.choose("skipa", "".join("%d.9.0.0/16\n" % i for i in range(1, 101)), prev)
check("Н3-2 сетей столько же, а адресов в 256 раз больше — прошлая копия", t == prev and "резко вырос" in note)
t, nets, note = sl.choose("skipa", prev + "".join("9.8.%d.0/24\n" % i for i in range(40)), prev)
check("Н3-3 рост в 1,4 раза — принимаем", note == "" and len(nets) == 140)
p6 = "2a00:1::/48\n" * 1 + "9.9.9.0/24\n" * 3
t, nets, note = sl.choose("x", "2a00:1::/48\n2a00:2::/32\n2a00:3::/32\n9.9.9.0/24\n9.9.9.0/24\n", p6)
check("Н3-4 охват IPv6 вырос сильно — тоже прошлая копия", t == p6 and "резко вырос" in note)
L = {"a": [N("149.154.160.0/20"), N("104.16.0.0/16"), N("1.1.1.0/24"), N("37.0.113.0/24")]}
fin, cut = sl.combine(L, [], [], [])
check("Н3-5 combine вычитает NEVER_LIST", [str(n) for n in fin if n.overlaps(N("1.1.1.0/24"))] != []
      and not any(n.overlaps(N(x)) for n in fin for x in ("149.154.160.0/20", "104.16.0.0/16", "1.1.1.1/32"))
      and sl.volume([n for n in fin if n.overlaps(N("1.1.1.0/24"))]) == 255 and N("37.0.113.0/24") in fin and cut == 3)
check("Н3-6 IPv6 шире /32 не принимаем, /32 — да", sl.parse("2a00::/31\n2a00:1::/32\n")[1] == 1 and sl.MIN_PREFIX[6] == 32)
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    big = "".join("%d.%d.0.0/16\n" % (11 + i // 200, i % 200) for i in range(31))   # 31 × 65 536 > 2 000 000
    loads = []
    sm = sl.run([], fetcher=lambda n: big if n == "skipa" else "37.0.113.0/24\n",
                run_ctl=lambda h, a, inp=None: loads.append(h) or {"ok": True}, hosts={"node-k": {"host": "198.51.100.1"}},
                send=None, now=NOW, base=tmp)
    check("Н3-7 итог больше предела адресов IPv4 — не рассылаем, заметка", loads == [] and sm["addrs4"] > sl.ADDR4_MAX
          and any("больше предела" in x for x in sm["notes"]))
LISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "2026-10-22-scanners", "lists")
if os.path.isdir(LISTS_DIR):
    per = {n: sl.parse(open(os.path.join(LISTS_DIR, n + ".list"), encoding="utf-8").read())[0] for n in sl.LISTS}
    fin, _ = sl.combine(per, [], [], sl.own_networks([]))
    v4 = sl.volume(fin, 4)
    check("Н3-8 настоящие списки укладываются в предел с запасом ~в 3 раза", 0 < v4 * 2 < sl.ADDR4_MAX < v4 * 4)
    v6 = sl.v6_32(fin)
    check("П3-0 настоящие списки: IPv6 в пределе ADDR6_MAX с запасом ~в 3 раза", 0 < v6 * 2 < sl.ADDR6_MAX < v6 * 4)

# ---------------- дробление шире MIN_PREFIX, refused_total ----------------
fin, _ = sl.combine({"a": [N("31.0.0.0/16"), N("31.1.0.0/16")], "b": [N("2a00::/32"), N("2a00:1::/32")]}, [], [], [])
check("Н14-1 склеенное шире /16 и /32 раздроблено обратно", sorted(str(n) for n in fin) == ["2a00:1::/32", "2a00::/32", "31.0.0.0/16", "31.1.0.0/16"])
fin, _ = sl.combine({"a": [N("31.%d.0.0/16" % i) for i in range(8)]}, [], [N("31.3.0.0/24")], [])
check("Н14-2 после вычитания тоже не шире /16", all(n.prefixlen >= 16 for n in fin)
      and sl.volume(fin) == 8 * 65536 - 256)
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    msgs = []

    def ctl(h, args, inp=None):
        if args == ["scanners-load"]:
            return {"ok": True, "v4": 3, "refused_total": 3} if h == "node-k" else {"ok": False, "error": "<b>нет</b> & связи"}
        return {"ok": True, "clients": {}}
    sm = sl.run([], fetcher=lambda n: "37.0.113.0/24\n", run_ctl=ctl, hosts={"node-k": {"host": "198.51.100.1"},
                "node-j": {"host": "198.51.100.2"}}, send=msgs.append, now=NOW, base=tmp)
    check("Н14-3 отвергнутое щитом видно в сводке", sm["hosts"]["node-k"] == "ok, отвергнуто 3"
          and sm["hosts"]["node-j"].startswith("ошибка"))
    check("Н14-4 в сообщении — кто принял не всё", len(msgs) == 1 and "Приняли не всё: node-k (ok, отвергнуто 3)" in msgs[0])
    check("М7 текст ошибки сервера экранирован", "&lt;b&gt;нет&lt;/b&gt; &amp; связи" in msgs[0] and "<b>нет</b>" not in msgs[0])

# ---------------- мелочи scanlists ----------------
check("М8 исключения разбираются любой ширины", sl.parse("85.140.0.0/14\n", wide=True) == ([N("85.140.0.0/14")], 0)
      and sl.parse("85.140.0.0/14\n")[1] == 1)
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    open(os.path.join(tmp, "scanners-exclude.txt"), "w", encoding="utf-8").write("85.140.0.0/14  # провайдер\n")
    sm = sl.run(["--dry"], fetcher=lambda n: "85.141.7.0/24\n37.0.113.0/24\n", run_ctl=None, hosts={}, send=None,
                now=NOW, base=tmp)
    check("М9 широкое исключение вырезает сеть из списка", sm["nets"] == 1)
check("М10 докстринг: 5 списков и свой «по поведению»", "5 списков" in sl.__doc__ and "по поведению" in sl.__doc__
      and len(sl.LISTS) == 5 and "пять внешних" in sl.__doc__ and "три списка" not in sl.__doc__)
# ================= П1–П10: IPv6, рассылка, клиенты, сутки по нодам, соль, свои, рост списков =================
bs.SALT = os.path.join(TMP, "p.salt")

# ---------------- П1: смесь IPv4 и IPv6 не роняет step ----------------
mix = kn(("A", [["45.83.64.7", 1, 1, 1], ["2a01:4f8::7", 1, 1, 1]]), ("B", [["2a01:4f8::7", 1, 1, 1], ["45.83.64.7", 1, 1, 1]]))
st = {}
asked_mix = []
bs.step(st, mix, own, NOW, info_all(), clients_of=lambda ips: asked_mix.append(list(ips)) or set())
l1, n1 = bs.step(st, mix, own, NOW + DAY, info_all(), clients_of=lambda ips: asked_mix.append(list(ips)) or set())
check("П1-1 смесь IPv4 и IPv6: вносятся оба (IPv6 — сетью /64), сортировка (семейство, адрес)",
      l1 == ["45.83.64.7", "2a01:4f8::"] and n1 == 2 and asked_mix[0] == ["45.83.64.7", "2a01:4f8::"])
check("П1-2 ключ сортировки", sorted(["2a01::1", "9.9.9.9", "1.2.3.4", "::1"], key=bs.ip_key) == ["1.2.3.4", "9.9.9.9", "::1", "2a01::1"])

# ---------------- П2: NEVER_LIST с IPv6 ----------------
NEED6 = ["2001:67c:4e8::/48", "2001:b28:f23c::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2a0a:f280::/32",
         "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
         "2c0f:f248::/32", "2a0a:a440::/29", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111",
         "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff",
         "2620:119:35::35", "2620:119:53::53"]
check("П2-1 NEVER_LIST: все IPv6-диапазоны на месте", {str(N(x)) for x in NEED6} <= {str(n) for n in sl.never_networks()})
never6 = ["2001:67c:4e8::1", "2001:b28:f23d::5", "2a0a:f280::1", "2606:4700::6810:1", "2a06:98c0:3600::103",
          "2a0a:a440::1", "2001:4860:4860::8888", "2a02:6b8::feed:ff", "2620:fe::fe"]
bad6 = kn(("A", [[ip, 20, 50, 1] for ip in never6 + ["2a01:4f8::9"]]), ("B", [[ip, 20, 50, 1] for ip in never6 + ["2a01:4f8::9"]]))
st = {}
lk = info_all()
bs.step(st, bad6, own, NOW, lk)
l2, _ = bs.step(st, bad6, own, NOW + DAY, lk)
check("П2-2 behavscan: IPv6 Telegram, Cloudflare, GitHub, DNS не вносятся и не запоминаются; чужой IPv6 — да",
      l2 == ["2a01:4f8::"] and set(st["ips"]) == {"2a01:4f8::"} and lk.calls == [["2a01:4f8::"]])
own_mix = [N("192.0.2.0/24"), N("2001:db8::/32")]
check("П2-3 is_own для обоих семейств", bs.is_own("192.0.2.5", own_mix) and bs.is_own("2001:db8::5", own_mix)
      and not bs.is_own("2001:db9::5", own_mix) and not bs.is_own("198.51.100.1", own_mix))
fin, cut = sl.combine({"x": [N("2001:67c::/32"), N("2606:4700::/32"), N("2a01:4f8::/32"), N("104.16.0.0/16")]}, [], [], [])
check("П2-4 combine вычитает NEVER_LIST и в IPv6", not any(n.overlaps(m) for n in fin for m in sl.never_networks())
      and N("2a01:4f8::/32") in fin and not any(n.overlaps(N("2606:4700::/32")) for n in fin)
      and sl.volume([n for n in fin if n.overlaps(N("2001:67c::/32"))], 6) == 2 ** 96 - 2 ** 80 and cut == 3)

# ---------------- П3: не разослали — всё равно summary.json и сообщение ----------------
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    big = "".join("%d.%d.0.0/16\n" % (11 + i // 200, i % 200) for i in range(31))   # 31 × 65 536 > 2 000 000
    loads, msgs = [], []
    ctl_rec = lambda h, a, inp=None: loads.append((h, a)) or {"ok": True, "clients": {}}  # noqa: E731
    open(os.path.join(tmp, "summary.json"), "w", encoding="utf-8").write(json.dumps(
        {"clients": {"11.0.0.5": {"user": "u1", "list": "СКИПА (РКН)"}}}))
    sm = sl.run([], fetcher=lambda n: big if n == "skipa" else "37.0.113.0/24\n", run_ctl=ctl_rec,
                hosts={"node-k": {"host": "198.51.100.1"}}, send=msgs.append, now=NOW, base=tmp)
    saved = json.load(open(os.path.join(tmp, "summary.json"), encoding="utf-8"))
    check("П3-1 больше ADDR4_MAX: щитам не шлём, summary.json с заметкой, сообщение ушло", loads == []
          and saved["sent"] is False and any("больше предела" in x for x in saved["notes"]) and len(msgs) == 1
          and "не разослан" in msgs[0] and "больше предела 2000000" in msgs[0] and "прошлом списке" in msgs[0])
    check("П3-2 копии списков «прошлыми» не сохраняются, клиенты прошлой сводки остаются",
          not os.path.exists(os.path.join(tmp, "skipa.list")) and "11.0.0.5" in saved["clients"])
    msgs.clear()
    sm = sl.run([], fetcher=lambda n: "1.1.1.1/32\n8.8.8.8/32\n", run_ctl=ctl_rec, hosts={"node-k": {"host": "198.51.100.1"}},
                send=msgs.append, now=NOW + 1, base=tmp)
    saved = json.load(open(os.path.join(tmp, "summary.json"), encoding="utf-8"))
    check("П3-3 пустой итог: не шлём щитам, но сводка и сообщение есть", loads == [] and sm["nets"] == 0
          and saved["ts"] == NOW + 1 and any("пуст" in x for x in saved["notes"]) and len(msgs) == 1 and "пуст" in msgs[0])
    msgs.clear()
    v6many = "".join("2a0%d:%x::/32\n" % (1 + i // 100, i % 100 + 1) for i in range(sl.ADDR6_MAX + 1))
    sm = sl.run([], fetcher=lambda n: v6many if n == "c24be_gov" else "37.0.113.0/24\n", run_ctl=ctl_rec,
                hosts={"node-k": {"host": "198.51.100.1"}}, send=msgs.append, now=NOW + 2, base=tmp)
    check("П3-4 IPv6 больше ADDR6_MAX (в сетях /32) — не рассылаем, сообщение", loads == [] and sm["addrs6_32"] > sl.ADDR6_MAX
          and any("IPv6" in x and "больше предела" in x for x in sm["notes"]) and len(msgs) == 1)
    msgs.clear()
    os.remove(os.path.join(tmp, "summary.json"))
    sm = sl.run(["--dry"], fetcher=lambda n: big if n == "skipa" else "37.0.113.0/24\n", run_ctl=ctl_rec,
                hosts={"node-k": {"host": "198.51.100.1"}}, send=msgs.append, now=NOW + 3, base=tmp)
    check("П3-5 --dry: заметка в итоге, но ни сводки, ни сообщения", msgs == [] and any("больше предела" in x for x in sm["notes"])
          and not os.path.exists(os.path.join(tmp, "summary.json")))

# ---------------- П4: ddoswatch — «ok, отвергнуто N» не «не приняли» ----------------
with tempfile.TemporaryDirectory() as tmp:
    p = os.path.join(tmp, "summary.json")
    json.dump({"ts": NOW, "nets": 10, "notes": [], "hosts": {"node-k": "ok, отвергнуто 3", "node-j": "ошибка: timeout", "FI1": "ok"},
               "clients": {}}, open(p, "w", encoding="utf-8"))
    iss, _ = ddoswatch.scan_lines({"node-k": {"shield": {"scan": {"nets": 10}}}}, p)
    nopr = [x for x in iss if "не приняли" in x]
    part = [x for x in iss if "приняли не всё" in x]
    check("П4-1 «не приняли» — только сервер с ошибкой", len(nopr) == 1 and "node-j" in nopr[0] and "node-k" not in nopr[0]
          and "FI1" not in nopr[0])
    check("П4-2 «ok, отвергнуто N» — отдельной строкой «приняли не всё»", len(part) == 1
          and "node-k (ok, отвергнуто 3)" in part[0] and "node-j" not in part[0])
    json.dump({"ts": NOW, "nets": 10, "notes": [], "hosts": {"node-k": "ok"}, "clients": {}}, open(p, "w", encoding="utf-8"))
    check("П4-3 все ok — ни одной строки о приёме", not any("приняли" in x for x in ddoswatch.scan_lines({}, p)[0]))

# ---------------- П5: клиенты — каждый проход обо всех со стуком за сегодня ----------------
X = "45.10.20.30"
seen = []


def shields(answer):
    def clients_of(ips):
        seen.append(list(ips))
        return set(answer) & set(ips)
    return clients_of


st = {}
xb = kn(("A", [[X, 1, 1, 1]]), ("B", [[X, 1, 1, 1]]))
l1, _ = bs.step(st, xb, own, NOW, info_all(), clients_of=shields({X}))
l2, _ = bs.step(st, kn(("A", [[X, 1, 1, 1]])), own, NOW + DAY, info_all(), clients_of=shields(set()))
check("П5-1 клиент в первые сутки, во вторые щит его уже не помнит — не вносим (как раньше)",
      seen[0] == [X] and l1 == [] and l2 == [] and X not in json.dumps(st))
st, seen[:] = {}, []
one = kn(("A", [["77.18.9.9", 1, 1, 1], ["77.18.9.10", 1, 1, 1]]))
bs.step(st, one, own, NOW, info_all(), clients_of=shields({"77.18.9.9"}))
check("П5-2 стучал с одной ноды — щиты всё равно спрошены; клиент сразу в хэш, адреса в state нет",
      seen == [["77.18.9.9", "77.18.9.10"]] and "77.18.9.9" not in json.dumps(st) and "77.18.9.10" in st["ips"]
      and bs.client_hash("77.18.9.9", bs.load_salt(NOW)[0]) in st["clients"])
st, seen[:] = {}, []
two = kn(("A", [["77.18.9.20", 1, 1, 1]]), ("B", [["77.18.9.20", 1, 1, 1]]))
bs.step(st, two, own, NOW, info_all(), clients_of=shields(set()))
bs.step(st, two, own, NOW + DAY, info_all(), clients_of=shields(set()))
l3, _ = bs.step(st, {}, own, NOW + DAY + 3600, info_all(), clients_of=shields({"77.18.9.20"}))
check("П5-3 внесённый без стука сегодня тоже спрашивается; клиент выпадает", seen[-1] == ["77.18.9.20"] and l3 == []
      and "77.18.9.20" not in st["ips"])
calls = {}


def ctl_dead(h, args):
    calls[h] = calls.get(h, 0) + 1
    return None if h == "dead" else {"ok": True, "clients": {}}


found, known = bs.clients_via({"dead": {}, "ok1": {}}, ctl_dead)(["77.18.%d.%d" % (i // 250, i % 250) for i in range(1000)])
check("П5-4 щит отказал — остальные куски ему не шлём, клиенты неизвестны", calls == {"dead": 1, "ok1": 20} and known is False)
st = {}
bs.step(st, two, own, NOW, info_all(), clients_of=lambda ips: (set(), False))
l4, n4 = bs.step(st, two, own, NOW + DAY, info_all(), clients_of=lambda ips: (set(), False))
check("П5-5 клиенты неизвестны — новых не вносим (правило сохранено)", l4 == [] and n4 == 0)

# ---------------- П6: мусор в маячке не роняет проход ----------------
junk = {"A": {"ts": 1, "knocks": {"1.2.3.4": [1]}},
        "B": {"ts": 1, "knocks": [{"a": 1}, "строка", ["77.18.10.1", "5", 1, 1], [5, 1, 1, 1], ["77.18.10.2", 1, 1],
                                  ["77.18.10.3", True, 1, 1], ["77.18.10.4", float("inf"), 1, 1], None, 7,
                                  ["77.18.10.5", 2, 3, 1], ("77.18.10.6", 1.0, 2, 0)]},
        "C": {"ts": 1, "knocks": 5}, "D": "мусор", "E": [1, 2], "F": None, "G": {"ts": 1, "knocks": "1.2.3.4"}}
agg = bs.aggregate(junk)
check("П6-1 aggregate: словарь, число, строка вместо списка, кривые строки — пропуск", set(agg) == {"77.18.10.5", "77.18.10.6"}
      and agg["77.18.10.5"]["per"] == {"B": {"ports": 2, "hits": 3, "strong": 1}})
st = {}
try:
    bs.step(st, junk, own, NOW, info_all())
    l5, _ = bs.step(st, dict(junk, H={"knocks": [["77.18.10.5", 2, 3, 1]]}), own, NOW + DAY, info_all())
    crashed = False
except Exception:
    crashed = True
check("П6-2 step с мусорным маячком не падает", not crashed and "77.18.10.5" in st["ips"])
check("П6-3 with_knocks не падает на мусоре и считает только списки", bs.with_knocks(junk) == 1)

# ---------------- П7: 2 ноды в одних сутках И 2 суток; сутки по нодам ----------------
st = {}
lk = info_all()
bs.step(st, kn(("A", [["77.18.11.1", 1, 1, 1]])), own, NOW, lk)
bs.step(st, kn(("B", [["77.18.11.1", 1, 1, 1]])), own, NOW + DAY, lk)
l1, _ = bs.step(st, kn(("A", [["77.18.11.1", 1, 1, 1]])), own, NOW + 2 * DAY, lk)
check("П7-1 поддельные SYN: A в одни сутки, B в другие — не вносим", l1 == [] and lk.calls == [])
st = {}
pair = kn(("A", [["77.18.11.2", 1, 4, 1]]), ("B", [["77.18.11.2", 1, 2, 1]]))
bs.step(st, pair, own, NOW, lk)
bs.step(st, {"A": {"ts": NOW, "knocks": [["77.18.11.2", 1, 5, 1]]}, "B": None}, own, NOW + 3 * 3600, lk)
d0 = {n: {k: x for k, x in r.items() if k != "ts"} for n, r in st["ips"]["77.18.11.2"]["days"][bs.day_of(NOW)].items()}
check("П7-2 второй проход за сутки: молчащая нода сохраняет подтверждение, ответившая — заменена",
      d0 == {"A": {"ports": 1, "hits": 5, "strong": 1}, "B": {"ports": 1, "hits": 2, "strong": 1}})
l2, _ = bs.step(st, kn(("A", [["77.18.11.2", 1, 1, 1]])), own, NOW + DAY, lk)
check("П7-3 2 ноды в первых сутках + стук во вторых — вносим", l2 == ["77.18.11.2"] and st["ips"]["77.18.11.2"]["hits"] == 8)
d = bs.day_of(NOW)
st = {"salt": "старая", "clients": {"abc": NOW}, "ips": {
    "77.18.11.3": {"first": NOW, "last": NOW, "days": {d: {"nodes": ["A", "B"], "ports": 2, "hits": 4, "strong": 1}}},
    "77.18.11.4": {"first": NOW, "last": NOW + DAY, "listed": True, "looked": NOW, "hosting": True, "mobile": False,
                    "days": {d: {"nodes": ["A"], "ports": 1, "hits": 1, "strong": 1},
                             bs.day_of(NOW + DAY): {"nodes": ["B"], "ports": 1, "hits": 1, "strong": 1}}}}}
l3, _ = bs.step(st, kn(("A", [["77.18.11.3", 1, 1, 1]])), own, NOW + DAY + 60, lk)
check("П7-4 state прежней версии: сутки разложены по нодам, стуки не удвоены",
      st["ips"]["77.18.11.3"]["days"][d] == {"A": {"ports": 2, "hits": 4, "strong": 1}, "B": {"ports": 2, "hits": 0, "strong": 1}}
      and "77.18.11.3" in l3)
check("П7-5 внесённый по старому правилу (A и B в разные сутки) снят", "77.18.11.4" not in l3
      and st["ips"]["77.18.11.4"]["listed"] is False)
old = {"ips": {"77.18.11.5": {"first": NOW, "last": NOW, "listed": True, "nodes": ["A", "B"], "ports": 3, "hits": 6,
                               "strong": 0}}}
bs.step(old, {}, own, NOW + 60, lk)
check("П7-6 боевой state старого вида: сутки по нодам, снят со списка",
      old["ips"]["77.18.11.5"]["days"] == {d: {"A": {"ports": 3, "hits": 6, "strong": 0}, "B": {"ports": 3, "hits": 0, "strong": 0}}}
      and old["ips"]["77.18.11.5"]["listed"] is False)

# ---------------- П8: соль — отдельный файл 600, смена раз в KEEP_DAYS ----------------
sp = os.path.join(TMP, "salt8", "behavscan.salt")
s1, t1 = bs.load_salt(NOW, sp)
check("П8-1 соль создаётся в своём файле", os.path.exists(sp) and len(s1) == 32 and t1 == NOW
      and bs.load_salt(NOW + (bs.KEEP_DAYS - 1) * DAY, sp) == (s1, NOW))
if os.name == "posix":
    check("П8-2 права файла соли 600", os.stat(sp).st_mode & 0o777 == 0o600)
s2, t2 = bs.load_salt(NOW + bs.KEEP_DAYS * DAY, sp)
check("П8-3 через KEEP_DAYS — новая соль", s2 != s1 and t2 == NOW + bs.KEEP_DAYS * DAY)
check("П8-4 --dry (save=False): файл не создаётся", bs.load_salt(NOW, os.path.join(TMP, "нет", "x.salt"), save=False)[0]
      and not os.path.exists(os.path.join(TMP, "нет")))
bs.SALT = os.path.join(TMP, "salt8b", "behavscan.salt")
st = {}
cl = kn(("A", [["77.18.12.1", 1, 1, 1]]))
bs.step(st, cl, own, NOW, info_all(), clients_of=lambda ips: set(ips))
check("П8-5 соли нет в behavior.json, отметка клиента есть", len(st["clients"]) == 1 and "salt" not in st
      and bs.load_salt(NOW)[0] not in json.dumps(st))
bs.step(st, {}, own, NOW + bs.KEEP_DAYS * DAY, info_all())
check("П8-6 соль сменилась — отметки клиентов сброшены", st["clients"] == {} and st["salt_ts"] == NOW + bs.KEEP_DAYS * DAY)
st = {"salt": "старая", "clients": {"abc": NOW}, "ips": {}}
bs.step(st, {}, own, NOW + bs.KEEP_DAYS * DAY + 60, info_all())
check("П8-7 соль прежней версии из state убрана, её хэши сброшены", "salt" not in st and st["clients"] == {})

# ---------------- П9: own_hosts в scanlists; ddos.json — имена разрешаются ----------------
check("П9-1 own_hosts живёт в scanlists, behavscan своего не держит", hasattr(sl, "own_hosts") and not hasattr(bs, "own_hosts"))
failed = []
on = sl.own_networks([{"host": "nl1.example.net"}, {"host": "198.51.100.9"}, {"host": "gone.example.net"}, {}],
                     resolve=resolve, load=lambda n: FILES.get(n, []), failed=failed)
son = {str(n) for n in on}
check("П9-2 own_networks: имена из ddos.json разрешены, хосты nodes.json и vantage.json добавлены",
      {"77.18.5.1/32", "2001:db8::5/128", "198.51.100.9/32", "77.18.5.3/32", "77.18.5.4/32", "77.18.5.2/32"} <= son
      and {str(N(x)) for x in sl.owner_addrs()} <= son)
check("П9-3 неразрешённые имена — в счётчик (без повторов)", failed == ["gone.example.net"])
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    json.dump(FILES["nodes.json"], open(os.path.join(tmp, "nodes.json"), "w", encoding="utf-8"))
    loads9, msgs9 = [], []
    sm = sl.run([], fetcher=lambda n: "77.18.5.0/24\n" if n == "skipa" else "37.0.113.0/24\n",
                run_ctl=lambda h, a, inp=None: loads9.append(inp) or ({"ok": False, "error": "x"} if h == "node-j"
                                                                    else {"ok": True, "clients": {}}),
                hosts={"node-k": {"host": "nl1.example.net"}, "node-j": {"host": "dead.example.net"}}, send=msgs9.append, now=NOW,
                base=tmp, resolve=resolve)
    check("П9-4 run: нода по имени вырезана из списка, «имён не разрешилось» в summary и сообщении",
          sm["unresolved"] == 2 and "77.18.5.0/24" not in loads9[0] and "77.18.5.128/25" in loads9[0]
          and "77.18.5.1/32" not in loads9[0] and "77.18.5.2/32" in loads9[0]
          and len(msgs9) == 1 and "не разрешилось: 2" in msgs9[0])

# ---------------- П10: рост — порог, семейство с нуля, --accept ----------------
small = "".join("5.5.%d.0/24\n" % i for i in range(10))   # ~2,5 тыс. адресов, как skipa
t, nets, note = sl.choose("skipa", small + "6.6.0.0/22\n", small)
check("П10-1 мелкая добавка к маленькому списку (+/22) — не «резко вырос»", note == "" and len(nets) == 11)
t, nets, note = sl.choose("skipa", small + "6.6.0.0/16\n7.7.0.0/16\n", small)
check("П10-2 прибавилось больше 65 536 и больше 1,5 раза — «резко вырос»", t == small and "резко вырос" in note)
t, nets, note = sl.choose("skipa", small + "6.6.0.0/16\n", small)
check("П10-3 прибавилось ровно 65 536 — ещё не рост", note == "")
p6only = "".join("2a00:%x::/48\n" % i for i in range(1, 11))
t, nets, note = sl.choose("x", p6only + "".join("%d.1.0.0/16\n" % i for i in range(31, 35)), p6only)
check("П10-4 IPv4 в прошлой копии не было, а пришло больше порога — «резко вырос»", t == p6only and "резко вырос" in note)
p4only = "".join("9.9.%d.0/24\n" % i for i in range(100))
t, nets, note = sl.choose("x", p4only + "2a00:1::/32\n2a00:2::/32\n", p4only)
check("П10-5 IPv6 с нуля больше одной /32 — «резко вырос»; одна /32 — нет", "резко вырос" in note
      and sl.choose("x", p4only + "2a00:1::/32\n", p4only)[2] == "")
t, nets, note = sl.choose("skipa", small + "6.6.0.0/16\n7.7.0.0/16\n", small)
check("П10-6 в заметке — как принять, командой целиком", "python3 /opt/channel-watch/scanlists.py --accept skipa" in note)
t, nets, note = sl.choose("skipa", small + "6.6.0.0/16\n7.7.0.0/16\n", small, accept=True)
check("П10-7 accept=True — новая копия вопреки росту", note == "" and len(nets) == 12)
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    for n in sl.LISTS:
        open(os.path.join(tmp, n + ".list"), "w", encoding="utf-8").write(small)
    grown = small + "6.6.0.0/16\n7.7.0.0/16\n"
    ctl10 = lambda h, a, inp=None: {"ok": True, "clients": {}}  # noqa: E731
    sm = sl.run([], fetcher=lambda n: grown if n == "skipa" else small, run_ctl=ctl10, hosts={}, send=None, now=NOW, base=tmp)
    check("П10-8 без --accept: прошлая копия осталась", any("skipa: резко вырос" in x for x in sm["notes"])
          and open(os.path.join(tmp, "skipa.list"), encoding="utf-8").read() == small)
    sm = sl.run(["--accept", "skipa", "--accept", "нет_такого"], fetcher=lambda n: grown if n == "skipa" else small,
                run_ctl=ctl10, hosts={}, send=None, now=NOW, base=tmp)
    check("П10-9 --accept skipa: новая копия принята и сохранена; неизвестное имя — заметка",
          not any("резко вырос" in x for x in sm["notes"]) and sm["per_list"]["skipa"] == 12
          and open(os.path.join(tmp, "skipa.list"), encoding="utf-8").read() == grown
          and any("--accept нет_такого: такого списка нет" in x for x in sm["notes"]))

# ================= Р1–Р9: щиты параллельно, IPv6 /64, двойной счёт суток, повреждённый state, --accept ====
import threading  # noqa: E402

bs.SALT = os.path.join(TMP, "r.salt")

# ---------------- Р1: щиты параллельно, внутри сервера куски по очереди ----------------
gate = threading.Barrier(2, timeout=5)
order = {}


def ctl_par(h, args):
    order.setdefault(h, []).append(args[1])
    if len(order[h]) == 1:
        gate.wait()   # оба щита должны оказаться здесь одновременно — иначе BrokenBarrierError через 5 с
    if h == "bad" and len(order[h]) == 2:
        return {"ok": False, "error": "нет связи"}
    return {"ok": True, "clients": {args[1]: {}}}


r_addrs = ["45.20.%d.%d" % (i // 250, i % 250) for i in range(120)]
found, known = bs.clients_via({"good": {}, "bad": {}}, ctl_par)(r_addrs)
check("Р1-1 щиты двух серверов спрошены одновременно (поток на сервер)", not gate.broken
      and order["good"] == [r_addrs[0], r_addrs[50], r_addrs[100]])
check("Р1-2 внутри сервера куски по очереди; после отказа остальные куски ему не шлём; итог «неизвестно»",
      order["bad"] == [r_addrs[0], r_addrs[50]] and known is False
      and found == {r_addrs[0], r_addrs[50], r_addrs[100]})
gate = threading.Barrier(2, timeout=5)
order = {}
found, known = bs.clients_via({"good": {}, "good2": {}}, ctl_par)(r_addrs[:10])
check("Р1-3 все щиты ответили — known=True, найденные у всех вместе", known is True and found == {r_addrs[0]})
found, known = bs.clients_via({"x": {}}, lambda h, a: 1 / 0)(r_addrs[:3])
check("Р1-4 опрос щита упал исключением — «неизвестно», проход не падает", known is False and found == set())

# ---------------- Р2: ::ffff:a.b.c.d — IPv4; не глобальные и multicast — пропуск ----------------
rows = [["::ffff:45.30.0.1", 1, 2, 1], ["100.64.1.1", 5, 5, 1], ["169.254.3.3", 5, 5, 1], ["10.0.0.1", 5, 5, 1],
        ["224.0.0.5", 5, 5, 1], ["ff02::1", 5, 5, 1], ["::ffff:100.64.0.1", 5, 5, 1], ["fe80::1", 5, 5, 1],
        ["192.168.1.1", 5, 5, 1], ["127.0.0.1", 5, 5, 1], ["45.30.0.1", 3, 1, 0]]
agg = bs.aggregate({"A": {"knocks": rows}})
check("Р2-1 ::ffff:a.b.c.d сведён к IPv4 и сложен с ним; 100.64/10, 169.254/16, частные, multicast — пропуск",
      set(agg) == {"45.30.0.1"} and agg["45.30.0.1"]["hits"] == 3 and agg["45.30.0.1"]["ports"] == 3)
check("Р2-2 norm_ip", bs.norm_ip("::ffff:45.30.0.1") == "45.30.0.1" and bs.norm_ip("100.64.0.1") is None
      and bs.norm_ip("239.1.1.1") is None and bs.norm_ip("2a01:4f8:1:2::77") == "2a01:4f8:1:2::")

# ---------------- Р3: NEVER_LIST — Telegram 91.105.192.0/23, GitHub 2606:50c0::/32 ----------------
check("Р3-1 NEVER_LIST: новые сети на месте", {"91.105.192.0/23", "2606:50c0::/32"} <= {str(n) for n in sl.never_networks()})
tg_gh = kn(("A", [["91.105.192.5", 20, 50, 1], ["2606:50c0:8000::154", 20, 50, 1]]),
           ("B", [["91.105.193.9", 20, 50, 1], ["2606:50c0:8001::154", 20, 50, 1]]))
st = {}
lk = info_all()
bs.step(st, tg_gh, own, NOW, lk)
l1, _ = bs.step(st, tg_gh, own, NOW + DAY, lk)
check("Р3-2 behavscan: Telegram и raw.githubusercontent.com не вносятся и не запоминаются", l1 == [] and st["ips"] == {}
      and lk.calls == [])
fin, cut = sl.combine({"x": [N("91.105.192.0/24"), N("2606:50c0::/32"), N("2a01:4f8::/32")]}, [], [], [])
check("Р3-3 combine вырезает их из итога", [str(n) for n in fin] == ["2a01:4f8::/32"] and cut == 2)

# ---------------- Р4: IPv6 — сеть /64; свои и NEVER_LIST по пересечению /64 ----------------
v6 = kn(("A", [["2a01:4f8:1:2::77", 1, 2, 1], ["2a01:4f8:1:2::78", 2, 3, 1], ["2a01:4f8:1:2::", 1, 1, 1]]),
        ("B", [["2a01:4f8:1:2::99", 1, 1, 1]]))
agg = bs.aggregate(v6)
check("Р4-1 адреса одной /64 (старый маячок) и адрес сети /64 (новый) — один ключ", list(agg) == ["2a01:4f8:1:2::"]
      and agg["2a01:4f8:1:2::"]["per"]["A"] == {"ports": 2, "hits": 6, "strong": 1} and agg["2a01:4f8:1:2::"]["nodes"] == {"A", "B"})
check("Р4-2 behavior.list: IPv4 — /32, IPv6 — /64", bs.list_text(["45.83.64.7", "2a01:4f8:1:2::"])
      == "45.83.64.7/32\n2a01:4f8:1:2::/64\n" and sl.parse(bs.list_text(["2a01:4f8:1:2::"])) == ([N("2a01:4f8:1:2::/64")], 0))
own6 = [N("2a01:4f8:1:2::5/128")]
check("Р4-3 is_own для IPv6 — по пересечению /64 со своими", bs.is_own("2a01:4f8:1:2::", own6)
      and bs.is_own("2a01:4f8:1:2::abcd", own6) and not bs.is_own("2a01:4f8:1:3::", own6))
st = {}
lk = info_all()
near = kn(("A", [["2a01:4f8:1:2::99", 5, 5, 1], ["2620:fe::1234", 5, 5, 1]]),
          ("B", [["2a01:4f8:1:2::98", 5, 5, 1], ["2620:fe::1235", 5, 5, 1]]))
bs.step(st, near, own6, NOW, lk)
l1, _ = bs.step(st, near, own6, NOW + DAY, lk)
check("Р4-4 /64 с нашим сервером или с DNS из NEVER_LIST (/128) — не вносим", l1 == [] and st["ips"] == {})
shield_cl = {shield_ctl.block_key("2a01:4f8:1:2::77"): [NOW, "u7", 3]}
real_load_clients = shield_ctl.load_clients
shield_ctl.load_clients = lambda path=None: shield_cl
try:
    ans = shield_ctl.cmd_clients(["2a01:4f8:1:2::", "2a01:4f8:1:3::"])
    st = {}
    v6b = kn(("A", [["2a01:4f8:1:2::77", 1, 2, 1], ["2a01:4f8:1:3::1", 1, 1, 1]]),
             ("B", [["2a01:4f8:1:2::78", 1, 1, 1], ["2a01:4f8:1:3::2", 1, 1, 1]]))
    via = bs.clients_via({"node-k": {}}, lambda h, a: shield_ctl.cmd_clients(a[1:]))
    bs.step(st, v6b, own, NOW, info_all(), clients_of=via)
    l2, _ = bs.step(st, v6b, own, NOW + DAY, info_all(), clients_of=via)
finally:
    shield_ctl.load_clients = real_load_clients
check("Р4-5 щит узнаёт клиента по адресу сети /64 (shield_ctl сам приводит к /64)", list(ans["clients"]) == ["2a01:4f8:1:2::"])
check("Р4-6 клиент по /64 не вносится, его адреса в state нет; соседняя /64 — вносится", l2 == ["2a01:4f8:1:3::"]
      and "2a01:4f8:1:2" not in json.dumps(st))
old6 = {"ips": {"2a01:4f8:9:9::7": {"first": NOW - DAY, "last": NOW - DAY, "listed": True, "looked": NOW, "hosting": True,
                                    "mobile": False, "days": {bs.day_of(NOW - DAY): {"A": {"ports": 1, "hits": 1, "strong": 1}}}},
                "2a01:4f8:9:9::8": {"first": NOW - 2 * DAY, "last": NOW, "days": {bs.day_of(NOW): {"B": {"ports": 2, "hits": 2, "strong": 1}}}},
                "::ffff:45.40.0.1": {"first": NOW, "last": NOW, "days": {bs.day_of(NOW): {"A": {"ports": 1, "hits": 1, "strong": 1}}}}}}
bs.step(old6, {}, own, NOW + 60, info_all())
e6 = old6["ips"].get("2a01:4f8:9:9::")
check("Р4-7 старый state: адреса /128 одной /64 слиты в одну запись, ::ffff: — в IPv4", set(old6["ips"]) == {"2a01:4f8:9:9::", "45.40.0.1"}
      and e6["first"] == NOW - 2 * DAY and set(e6["days"]) == {bs.day_of(NOW - DAY), bs.day_of(NOW)})

# ---------------- Р5: двойной счёт суток — проходы в 23:00 и в 04:20 ----------------
T23 = int(bs.day_of(NOW)) * DAY - 3 * 3600 + 23 * 3600   # 23:00 по Москве
check("Р5-0 время прохода посчитано верно", bs.day_of(T23) == bs.day_of(NOW) and bs.day_of(T23 + 3600) != bs.day_of(NOW))
pair = kn(("A", [["45.50.0.1", 1, 4, 1]]), ("B", [["45.50.0.1", 1, 2, 1]]))
st = {}
lk = info_all()
bs.step(st, pair, own, T23, lk)
l1, _ = bs.step(st, pair, own, T23 + 5 * 3600 + 20 * 60, lk)   # 04:20 следующих суток, те же стуки за 24 ч
e = st["ips"]["45.50.0.1"]
check("Р5-1 23:00 и 04:20 следующих суток с теми же стуками — одни сутки, не вносим", l1 == [] and len(e["days"]) == 1
      and e["days"][bs.day_of(T23)]["A"]["ts"] == T23)
l2, _ = bs.step(st, kn(("A", [["45.50.0.1", 1, 9, 1]])), own, T23 + 7 * 3600, lk)
check("Р5-2 проход до 23 ч обновляет прошлую запись ноды (стуки заменены, не сложены)", l2 == [] and len(e["days"]) == 1
      and e["days"][bs.day_of(T23)]["A"]["hits"] == 9 and bs.summary(e)["hits"] == 11)
l3, _ = bs.step(st, kn(("A", [["45.50.0.1", 1, 1, 1]])), own, T23 + DAY + 5 * 3600 + 20 * 60, lk)   # 04:20 через сутки
check("Р5-3 через 23+ ч — новые сутки; 2 ноды и 2 суток — вносим", l3 == ["45.50.0.1"] and len(e["days"]) == 2)
st = {}
bs.step(st, pair, own, NOW, lk)
bs.step(st, pair, own, NOW + 22 * 3600, lk)
check("Р5-4 22 ч спустя (уже другие сутки) — всё ещё одна запись", len(st["ips"]["45.50.0.1"]["days"]) == 1)
bs.step(st, pair, own, NOW + 23 * 3600, lk)
check("Р5-5 ровно 23 ч — новая запись суток", len(st["ips"]["45.50.0.1"]["days"]) == 2)
st = {}
bs.step(st, pair, own, NOW + 3 * DAY, lk)   # часы убегали на 3 суток вперёд
bs.step(st, pair, own, NOW + DAY, lk)      # вернулись
check("Р5-6 запись из будущего не держит новые сутки", len(st["ips"]["45.50.0.1"]["days"]) == 2)

# ---------------- Р6: предел числа сетей IPv6 в итоге scanlists ----------------
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    many6 = "".join("2a01:4f8:%x:%x::/64\n" % (i // 30000, (i % 30000) * 2) for i in range(sl.ADDR6_NETS_MAX + 1))
    open(os.path.join(tmp, sl.BEHAVIOR + ".list"), "w", encoding="utf-8").write(many6)
    loads6, msgs6 = [], []
    sm = sl.run([], fetcher=lambda n: "45.60.0.0/24\n", run_ctl=lambda h, a, inp=None: loads6.append(h) or {"ok": True},
                hosts={"node-k": {"host": "45.61.0.1"}}, send=msgs6.append, now=NOW, base=tmp)
    check("Р6-1 сетей IPv6 больше ADDR6_NETS_MAX — не рассылаем, заметка и сообщение", sl.ADDR6_NETS_MAX == 10000
          and loads6 == [] and sm["sent"] is False and sm["addrs6_32"] <= sl.ADDR6_MAX
          and any("10001 сетей IPv6, больше предела 10000" in x for x in sm["notes"]) and len(msgs6) == 1)
    open(os.path.join(tmp, sl.BEHAVIOR + ".list"), "w", encoding="utf-8").write("".join(many6.splitlines(True)[:sl.ADDR6_NETS_MAX]))
    sm = sl.run(["--dry"], fetcher=lambda n: "45.60.0.0/24\n", run_ctl=None, hosts={}, send=None, now=NOW, base=tmp)
    check("Р6-2 ровно ADDR6_NETS_MAX — ещё можно", not any("сетей IPv6" in x for x in sm["notes"]))

# ---------------- Р7: ddoswatch — список не разослан ----------------
with tempfile.TemporaryDirectory() as tmp:
    p = os.path.join(tmp, "summary.json")
    json.dump({"ts": NOW, "nets": 12345, "sent": False, "notes": ["в итоге 10001 сетей IPv6, больше предела 10000 — не рассылаю"],
               "hosts": {}, "clients": {}}, open(p, "w", encoding="utf-8"))
    iss, inf = ddoswatch.scan_lines({"node-k": {"shield": {"scan": {"nets": 10}}}}, p)
    check("Р7-1 sent=False — «новый список не разослан, на щитах прошлый» вместо «список N сетей от …»",
          "новый список не разослан, на щитах прошлый" in inf[0] and "12" not in inf[0].split("·")[0]
          and " от " not in inf[0].split("·")[0] and any("больше предела" in x for x in iss))
    json.dump({"ts": NOW, "nets": 10, "notes": [], "hosts": {}, "clients": {}}, open(p, "w", encoding="utf-8"))
    iss, inf = ddoswatch.scan_lines({"node-k": {"shield": {"scan": {"nets": 10}}}}, p)
    check("Р7-2 разослан — как раньше: «список N сетей от …»", "список 10 сетей от " in inf[0] and "не разослан" not in inf[0])

# ---------------- Р8: повреждённый state ----------------
for i, text in enumerate(["[1, 2]", "{не json", '"строка"', "null"]):
    pth = os.path.join(TMP, "state%d.json" % i)
    open(pth, "w", encoding="utf-8").write(text)
    check("Р8-1.%d load_state: не словарь или не JSON — пустой" % i, bs.load_state(pth) == {})
check("Р8-2 load_state: файла нет — пустой", bs.load_state(os.path.join(TMP, "нет.json")) == {})
st = {"ips": [1, 2], "clients": "мусор"}
bs.step(st, kn(("A", [["45.70.0.1", 1, 1, 1]])), own, NOW, info_all())
check("Р8-3 ips и clients не словари — начинаем с пустых, проход идёт", set(st["ips"]) == {"45.70.0.1"} and st["clients"] == {})
good = {"first": NOW, "last": NOW, "days": {bs.day_of(NOW): {"A": {"ports": 1, "hits": 1, "strong": 1}}, "abc": {"A": {}}}}
st = {"clients": {"h1": NOW, "h2": "мусор"}, "salt_ts": bs.load_salt(NOW)[1],
      "ips": {"мусор": dict(good), "45.70.0.0/24": dict(good), "10.0.0.1": dict(good), "": dict(good),
              "45.70.0.2": dict(good), "45.70.0.3": "не словарь", "45.70.0.4": {"first": NOW, "last": NOW, "days": [1]}}}
try:
    bs.step(st, {}, own, NOW + 60, info_all())
    crashed = False
except Exception:
    crashed = True
check("Р8-4 _migrate: ключи не адреса, сети, не глобальные, сутки не числом — выкинуты, проход не падает",
      not crashed and set(st["ips"]) == {"45.70.0.2"} and list(st["ips"]["45.70.0.2"]["days"]) == [bs.day_of(NOW)]
      and st["clients"] == {"h1": NOW})

# ---------------- Р9: --accept снимает и «резко уменьшился» ----------------
big_prev = "".join("9.7.%d.0/24\n" % i for i in range(100))
shrunk = "".join("9.7.%d.0/24\n" % i for i in range(50))
t, nets, note = sl.choose("skipa", shrunk, big_prev)
check("Р9-1 «резко уменьшился» — прошлая копия, в заметке команда принять", t == big_prev and "резко уменьшился" in note
      and "python3 /opt/channel-watch/scanlists.py --accept skipa" in note)
t, nets, note = sl.choose("skipa", shrunk, big_prev, accept=True)
check("Р9-2 accept=True — уменьшенная копия принята", t == shrunk and note == "" and len(nets) == 50)
with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    for n in sl.LISTS:
        open(os.path.join(tmp, n + ".list"), "w", encoding="utf-8").write(big_prev)
    ctl9 = lambda h, a, inp=None: {"ok": True, "clients": {}}  # noqa: E731
    sm = sl.run(["--accept", "skipa"], fetcher=lambda n: shrunk if n == "skipa" else big_prev, run_ctl=ctl9, hosts={},
                send=None, now=NOW, base=tmp)
    check("Р9-3 run --accept: уменьшенная копия сохранена «прошлой»", sm["notes"] == [] and sm["per_list"]["skipa"] == 50
          and open(os.path.join(tmp, "skipa.list"), encoding="utf-8").read() == shrunk)
check("Р9-4 докстринг: --accept и про уменьшение", "«резко вырос» или «резко уменьшился»" in sl.__doc__)
print("сканеры «по поведению» и списки сканеров: тестов пройдено %d" % ok)
