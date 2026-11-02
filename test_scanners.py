"""Тесты единой защиты от сканеров (shield_ctl, scanlists, ddoswatch.scan_lines) без сети: python test_scanners.py"""
import datetime as dt
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402
import scanlists as sl  # noqa: E402
import shield_ctl as s  # noqa: E402

ok = 0
LISTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lists")  # по желанию: скачанные списки — проверка на настоящих данных


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


C = dict(s.DEFAULTS, allow=["93.184.89.45", "93.187.140.234"])

# --- таблица
t = s.render(C, "eth0")
check("наборы сканеров и учёт источников", "set scanners4" in t and "set scanners6" in t and "set scan_seen4" in t)
check("сканеры — в raw_pre, после своих и блокировок", t.index("ip saddr @allow4 return") < t.index("@scanners4") and
      t.index("@blocked4") < t.index("@scanners4") and t.index("@scanners4") < t.index("chain pre {"))
check("по умолчанию только считаем", "chain scan {\n\t\tcounter name scan_hits\n\t}" in t)
check("режим drop — отбрасываем", "counter name scan_dropped drop" in s.render(C, "eth0", "watch", "drop").split("chain scan")[1])

# --- разбор списка на сервере
txt = "# комментарий\n1.2.3.0/24\n1.2.3.0/25\n10.0.0.0/8\n5.0.0.0/8\nмусор\n93.184.89.0/24\n2a00:1::/32\n2a00::/16\n"
v4, v6, bad = s.parse_scanners(txt, C)
check("пересечения слиты, частные вырезаны", "1.2.3.0/24" in [str(x) for x in v4] and not any(str(x).startswith("10.") for x in v4))
check("шире /16 и /28 — отказ", ("5.0.0.0/8", "слишком широкая (шире /16)") in bad and ("2a00::/16", "слишком широкая (шире /28)") in bad)
check("мусор — отказ", ("мусор", "не сеть") in bad)
check("адрес владельца вырезан из сети, остальное осталось", not any(x.overlaps(s.ipaddress.ip_network("93.184.89.45/32")) for x in v4)
      and sum(x.num_addresses for x in v4 if x.overlaps(s.ipaddress.ip_network("93.184.89.0/24"))) == 255)
check("IPv6 принят", [str(x) for x in v6] == ["2a00:1::/32"])
tx = s.scanners_nft(v4, v6)
check("загрузка одной транзакцией заново", tx.startswith("flush set inet storozh_shield scanners4\nflush set inet storozh_shield scanners6\n")
      and "add element inet storozh_shield scanners6 { 2a00:1::/32 }" in tx)

if os.path.isdir(LISTS_DIR):
    real = "".join(open(os.path.join(LISTS_DIR, n + ".list"), encoding="utf-8").read() for n in sl.LISTS)
    rv4, rv6, rbad = s.parse_scanners(real, C)
    check("настоящие списки: тысячи сетей, без отказов по ширине", 2000 < len(rv4) < 10000 and len(rv6) >= 20
          and not [b for b in rbad if "широкая" in b[1]])
    check("настоящие списки: в набор nft — кусками по 2000", s.scanners_nft(rv4, rv6).count("add element") >= 2)

calls = []
s.nft = lambda args, inp=None: calls.append((args, inp)) or ""
with tempfile.TemporaryDirectory() as tmp:
    s.SCANNERS_FILE = os.path.join(tmp, "scanners.txt")
    s.STATE_FILE = os.path.join(tmp, "st.json")
    s.LOG_FILE = os.path.join(tmp, "log")
    s.CLIENTS_FILE = os.path.join(tmp, "clients.json")
    r = s.cmd_scanners_load(C, "1.2.3.0/24\n2a00:1::/32\n")
    check("scanners-load: загружено и сохранено (переживёт перезагрузку)", r["v4"] == 1 and r["v6"] == 1
          and open(s.SCANNERS_FILE).read() == "1.2.3.0/24\n2a00:1::/32\n" and calls[-1][0] == ["-f", "-"])
    try:
        s.cmd_scanners_load(C, "# пусто\n")
        check("пустой список не загружается", False)
    except ValueError:
        check("пустой список не загружается", True)
    st = {}
    calls.clear()
    s.cmd_scan_mode(C, st, "drop")
    check("scan-mode drop", st["scan_mode"] == "drop" and (["add", "rule", s.TABLE, "scan", "counter", "name", "scan_dropped", "drop"], None) in calls)
    s.cmd_scan_mode(C, st, "count")
    check("scan-mode count — без drop", st["scan_mode"] == "count" and calls[-1][0][-1] == "scan_hits")
    json.dump({"clients": {"1.2.3.77": [100, "user_gov", 4], "8.8.8.8": [100, "user_ok", 1], "2a00:1:5:6::": [100, "u6", 1]}},
              open(s.CLIENTS_FILE, "w"))
    r = s.cmd_scan_clients()
    check("scan-clients: наши клиенты, попавшие в список", set(r["clients"]) == {"1.2.3.77", "2a00:1:5:6::"}
          and r["clients"]["1.2.3.77"]["user"] == "user_gov")
    check("ssh: команды сканеров разрешены", s.ssh_argv("scanners-load") == ["scanners-load"] and s.ssh_argv("scan-mode drop")
          and s.ssh_argv("scan-clients"))

# --- сборщик списков на rf1
check("разбор: широкие и мусор отброшены", sl.parse("1.2.3.0/24\nx\n5.0.0.0/8\n")[1] == 2)
prev = "1.1.1.0/24\n" * 1 + "".join("9.9.%d.0/24\n" % i for i in range(100))
txt_, nets, note = sl.choose("skipa", None, prev)
check("не скачался — прошлая копия", txt_ == prev and len(nets) == 101 and "прошлая копия" in note)
txt_, nets, note = sl.choose("skipa", "9.9.1.0/24\n", prev)
check("резко уменьшился — прошлая копия", txt_ == prev and "резко уменьшился (101 → 1" in note)
txt_, nets, note = sl.choose("skipa", prev + "7.7.7.0/24\n", prev)
check("нормальное обновление", note == "" and len(nets) == 102)
check("первый раз и не скачался — честно", sl.choose("skipa", None, "")[2] == "skipa: не скачался, прошлой копии нет")
own = sl.own_networks([{"host": "93.185.179.107"}])
fin, cut = sl.combine({"a": [sl.ipaddress.ip_network("93.185.179.0/24")]}, [], [], own)
check("наш сервер вырезан из сети списка", cut == 1 and not any(n.overlaps(own[-1]) for n in fin) and sum(n.num_addresses for n in fin) == 255)
fin, cut = sl.combine({"a": [sl.ipaddress.ip_network("1.2.3.0/24")]}, [], [sl.ipaddress.ip_network("1.2.3.0/24")], [])
check("исключение владельца убирает сеть целиком", fin == [])

with tempfile.TemporaryDirectory() as tmp:
    sl.ETC = tmp
    open(os.path.join(tmp, "scanners-extra.txt"), "w", encoding="utf-8").write("203.0.113.0/24  # свои добавки\n")
    LST = {"antiscanner": "1.2.3.0/24\n", "government_networks": "4.4.0.0/20\n2a00:1::/32\n", "skipa": "5.5.5.0/24\n"}
    loads, sent = {}, []
    HOSTS = {"DE7": {"host": "93.185.179.107"}, "NL1": {"host": "93.185.34.47"}}

    def ctl(h, args, inp=None):
        if args == ["scanners-load"]:
            loads[h] = inp
            return {"ok": True} if h == "DE7" else {"ok": False, "error": "timeout"}
        if args == ["scan-clients"]:
            return {"ok": True, "clients": {"4.4.1.9": {"user": "user_gov", "last": 50, "n": 2}}} if h == "DE7" else {"ok": False}
        return {"ok": False}
    sm = sl.run([], fetcher=lambda n: LST[n], run_ctl=ctl, hosts=HOSTS, send=sent.append, now=1000, base=tmp)
    check("собрано из трёх списков и своих добавок", sm["nets"] == 5 and sm["per_list"] == {"antiscanner": 1, "government_networks": 2, "skipa": 1}
          and sm["extra"] == 1)
    check("разослано на все серверы одинаково", set(loads) == {"DE7", "NL1"} and loads["DE7"] == loads["NL1"] and "203.0.113.0/24" in loads["DE7"])
    check("кто не принял — видно", sm["hosts"] == {"DE7": "ok", "NL1": "ошибка: timeout"})
    check("наш клиент в списке — с указанием, в каком", sm["clients"]["4.4.1.9"]["list"] == "государственные сети"
          and sm["clients"]["4.4.1.9"]["node"] == "DE7")
    check("сообщение владельцу: не принял сервер и клиент в списке", len(sent) == 1 and "NL1" in sent[0] and "user_gov" in sent[0]
          and "исключения" in sent[0])
    check("итог сохранён для отчёта", json.load(open(os.path.join(tmp, "summary.json")))["nets"] == 5)
    sent.clear()

    def ctl_ok(h, args, inp=None):
        return ctl("DE7", args, inp)
    sl.run([], fetcher=lambda n: LST[n], run_ctl=ctl_ok, hosts=HOSTS, send=sent.append, now=2000, base=tmp)
    check("всё приняли, клиент уже известен — молчим", sent == [])
    sm = sl.run(["--dry"], fetcher=lambda n: None, run_ctl=None, hosts=HOSTS, send=sent.append, now=3000, base=tmp)
    check("--dry: ничего не шлёт; не скачалось — прошлые копии", sent == [] and sm["nets"] == 5 and len(sm["notes"]) == 3)

# --- отчёт
DAY = dt.datetime(2026, 10, 22, 14, 0, tzinfo=d.MSK).timestamp()
hosts = {"DE7": {"shield": {"scan": {"mode": "count", "nets": 2600, "sources": 40, "packets": 900}}},
         "NL1": {"shield": {"scan": {"mode": "drop", "nets": 2600, "sources": 5, "packets": 3100}}},
         "бот": {"shield": {"scan": {}}}}
with tempfile.TemporaryDirectory() as tmp:
    p = os.path.join(tmp, "summary.json")
    json.dump({"ts": DAY, "nets": 2600, "notes": ["skipa: не скачался — взята прошлая копия"], "hosts": {"DE7": "ok", "NL1": "ok"},
               "clients": {"4.4.1.9": {"user": "user_gov", "list": "государственные сети"}}}, open(p, "w"))
    iss, inf = d.scan_lines(hosts, p)
    check("отчёт: сколько стучались и куда больше всего", inf and "список 2 600 сетей от 22.10 14:00" in inf[0] and d.plural(2444, "сеть", "сети", "сетей") == "2 444 сети"
          and d.plural(22, "раз", "раза", "раз") == "22 раза" and d.plural(11, "сеть", "сети", "сетей") == "11 сетей"
          and "отбрасываем на: NL1" in inf[0] and "стучались 4 000 раз с 45 адресов" in inf[0] and inf[0].index("NL1 (3 100)") < inf[0].index("DE7 (900)"))
    check("отчёт: замечание по списку и клиенты в нём", any("не скачался" in x for x in iss)
          and any("наши клиенты: 1" in x and "user_gov (государственные сети)" in x for x in iss))
    check("отчёт: нет данных — нет строк", d.scan_lines({}, os.path.join(tmp, "нет.json")) == ([], []))

# --- сборщик метрик передаёт счёт сканеров
stj = json.dumps({"ok": True, "loaded": True, "mode": "watch", "blocked": [], "suspects": [], "counters": {},
                  "scan": {"mode": "count", "nets": 2600, "updated": 5, "sources": 3, "packets": 77, "top": [["1.2.3.4", 70]]}})
sh = col.shield(run=lambda: stj)
check("срез: счёт сканеров без адресов", sh["scan"] == {"mode": "count", "nets": 2600, "updated": 5, "sources": 3, "packets": 77})
print("сканеры: тестов пройдено %d" % ok)
