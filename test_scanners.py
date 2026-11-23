"""Тесты единой защиты от сканеров (shield_ctl, scanlists, ddoswatch.scan_lines) без сети: python test_scanners.py"""
import datetime as dt
import json
import os
import re
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
RAW, PRE = t.split("chain raw_pre {")[1].split("chain scan {")[0], t.split("chain pre {")[1].split("chain pre_clients {")[0]
check("сканеры — не в raw_pre (до conntrack), а в pre: после ct state, своих и клиентов, до порогов",
      "@scanners" not in RAW and "@blocked4" in RAW and PRE.index("ct state != new return") < PRE.index("ip saddr @allow4 return")
      < PRE.index("ip saddr @clients4 goto pre_clients") < PRE.index("ip saddr @scanners4 update") < PRE.index("add @flood4")
      and PRE.index("ip6 saddr & ffff:ffff:ffff:ffff:: @clients6 goto pre_clients") < PRE.index("ip6 saddr @scanners6 update"))
check("jump scan (не goto): в count сканер проходит и проверку порогов", "jump scan" in PRE and "goto scan" not in t)
check("клиент из списка сканеров — свой счётчик scan_clients, раньше goto pre_clients",
      "counter scan_clients { }" in t and PRE.index("ip saddr @clients4 ip saddr @scanners4 counter name scan_clients")
      < PRE.index("ip saddr @clients4 goto pre_clients"))
check("по умолчанию только считаем", "chain scan {\n\t\tcounter name scan_hits\n\t}" in t)
check("режим drop — отбрасываем", "counter name scan_dropped drop" in s.render(C, "eth0", "watch", "drop").split("chain scan")[1])



# --- проход пакета IPv4 по цепочкам (упрощённо, по тексту render)
def run_chain(tab, name, pkt, cnt):
    body = tab.split("\tchain %s {\n" % name)[1].split("\n\t}")[0]
    for ln in body.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(("type ", "iifname", "meta l4proto")) or "ip6 " in ln:   # только IPv4
            continue
        conds = [pkt.get("ct", "new") != "new"] if "ct state != new" in ln else []
        conds += [pkt.get("ct", "new") == "invalid"] if "ct state invalid" in ln else []
        conds += [pkt.get(key, False) != ("!= " + tok in ln) for tok, key in (
            ("@allow4", "allow"), ("@clients4", "client"), ("@scanners4", "scanner"), ("@blocked4", "blocked")) if tok in ln]
        conds += [False] if "@gate_" in ln else []
        conds += [pkt.get("flood", False)] if any(x in ln for x in ("add @flood4", "add @conns4", "add @flood_c4", "add @conns_c4")) else []
        if not all(conds):
            continue
        cnt += re.findall(r"counter name (\w+)", ln)
        if ln == "drop" or ln.endswith(" drop"):
            return "drop"
        m = re.search(r"(jump|goto) (\w+)$", ln)
        if m:
            if run_chain(tab, m.group(2), pkt, cnt) == "drop":
                return "drop"
            if m.group(1) == "goto":
                return "end"
            continue
        if ln.endswith("return"):
            return "end"
    return "end"


def walk(pkt, mode="watch", scan="drop"):
    tab, cnt = s.render(C, "eth0", mode, scan), []
    for ch in ("raw_pre", "pre"):
        if run_chain(tab, ch, pkt, cnt) == "drop":
            return "drop", cnt
    return "accept", cnt


check("drop: ответ сканера на наше исходящее соединение (established) проходит и не считается",
      walk({"scanner": True, "ct": "established"}) == ("accept", []))
check("drop: related (ICMP об ошибке на наше соединение) тоже проходит", walk({"scanner": True, "ct": "related"})[0] == "accept")
check("drop: новое входящее от сканера — отброшено со счётчиками", walk({"scanner": True}) == ("drop", ["scan_hits", "scan_dropped"]))
check("count: новое от сканера — счёт и пропуск", walk({"scanner": True}, scan="count") == ("accept", ["scan_hits"]))
check("drop: наш клиент из списка сканеров — не режется, не попадание, только scan_clients",
      walk({"scanner": True, "client": True}) == ("accept", ["scan_clients"]))
check("count: клиент из списка — тоже не попадание", walk({"scanner": True, "client": True}, scan="count") == ("accept", ["scan_clients"]))
check("свои (allow) из списка — мимо всего", walk({"scanner": True, "allow": True}) == ("accept", []))
check("count + щит on: сканер сверх порога режется щитом (jump scan вернулся к порогам)",
      walk({"scanner": True, "flood": True}, mode="on", scan="count") == ("drop", ["scan_hits", "over_rate", "dropped_shield"]))
check("щит on: сверх порога режутся только новые, установленные соединения — нет",
      walk({"flood": True}, mode="on")[0] == "drop" and walk({"flood": True, "ct": "established"}, mode="on") == ("accept", []))
check("заблокированный по кнопке режется целиком, и ответы тоже (до conntrack)",
      walk({"blocked": True, "ct": "established"}) == ("drop", ["dropped_blocked"]))
check("обычный адрес — проходит", walk({}) == ("accept", []))

# --- ct invalid от сканеров (FIN/NULL/XMAS, непрошеный SYN-ACK): режутся в drop, считаются в count
INV4 = "ct state invalid ip saddr @scanners4 ip saddr != @allow4 ip saddr != @clients4 update @scan_seen4 { ip saddr counter } jump scan"
INV6 = ("ct state invalid ip6 saddr @scanners6 ip6 saddr != @allow6 ip6 saddr & ffff:ffff:ffff:ffff:: != @clients6 "
        "update @scan_seen6 { ip6 saddr counter } jump scan")
for sm_ in ("count", "drop"):
    P_ = s.render(C, "eth0", "watch", sm_).split("chain pre {")[1].split("chain pre_clients {")[0]
    check("invalid (%s): отдельные правила v4/v6 в pre, до `ct state != new return`, после iifname" % sm_,
          INV4 in P_ and INV6 in P_ and P_.index('iifname != "eth0" return') < P_.index(INV4) < P_.index(INV6)
          < P_.index("ct state != new return") < P_.index("ip saddr @scanners4 update"))
    check("invalid (%s): правило только про invalid — established/related в pre нигде не перечислены" % sm_,
          [ln.strip() for ln in P_.splitlines() if "ct state" in ln] == [INV4, INV6, "ct state != new return"]
          and "established" not in P_ and "related" not in P_)
check("invalid: режим берётся из цепочки scan (её же меняет scan-mode) — pre одинаковая в count и drop",
      s.render(C, "eth0", "watch", "count").split("chain pre {")[1] == s.render(C, "eth0", "watch", "drop").split("chain pre {")[1])
check("drop: invalid от сканера отброшен, считается в scan_dropped (и scan_hits)",
      walk({"scanner": True, "ct": "invalid"}) == ("drop", ["scan_hits", "scan_dropped"]))
check("count: invalid от сканера — только scan_hits, проходит", walk({"scanner": True, "ct": "invalid"}, scan="count")
      == ("accept", ["scan_hits"]))
check("drop: established и related от сканера по-прежнему проходят и не считаются",
      walk({"scanner": True, "ct": "established"}) == ("accept", []) and walk({"scanner": True, "ct": "related"}) == ("accept", []))
check("drop: invalid от нашего клиента из списка сканеров — не трогаем", walk({"scanner": True, "client": True, "ct": "invalid"})
      == ("accept", []))
check("drop: invalid не от сканера — не наше дело, проходит", walk({"ct": "invalid"}) == ("accept", []))

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
    # --- обновление на бою — state и файлы прежней версии (1.3.0) читаются, всё восстанавливается в новой таблице
    json.dump({"mode": "watch", "until": 0, "blocks": {"9.9.9.9": s.now() + 3000, "2a03:1:2:3::": s.now() + 600,
                                                        "7.7.7.7": s.now() - 5}, "scan_mode": "drop"}, open(s.STATE_FILE, "w"))
    open(s.SCANNERS_FILE, "w").write("1.2.3.0/24\n2a00:1::/32\n")
    calls.clear()
    st_old = json.load(open(s.STATE_FILE))
    r = s.cmd_load(dict(C, iface="eth0"), st_old)
    tab = calls[0][1]
    st_new = json.load(open(s.STATE_FILE))
    check("load со state прежней версии: таблица новая (сканеры в pre), режим сканеров drop сохранён",
          r["ok"] and "jump scan" in tab and "counter name scan_dropped drop" in tab.split("chain scan {")[1].split("}")[0]
          and st_new["scan_mode"] == "drop")
    check("load: живые блоки вернулись в ядро, истёкший убран", any(a[:4] == ["add", "element", s.TABLE, "blocked4"]
          and "9.9.9.9 timeout" in a[4] for a, _ in calls) and any("2a03:1:2:3:: timeout" in a[-1] for a, _ in calls if a[0] == "add")
          and set(st_new["blocks"]) == {"9.9.9.9", "2a03:1:2:3::"})
    check("load: список сканеров и клиенты загружены из файлов", any(i and "scanners4 { 1.2.3.0/24 }" in i for _, i in calls)
          and any(i and "clients4 { 1.2.3.77, 8.8.8.8 }" in i or i and "clients4 { 8.8.8.8, 1.2.3.77 }" in i for _, i in calls)
          and r["clients"] == 3)
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
    LST = {"antiscanner": "1.2.3.0/24\n", "government_networks": "4.4.0.0/20\n2a00:1::/32\n", "skipa": "5.5.5.0/24\n",
           "c24be_gov": "7.7.7.0/24\n4.4.1.0/24\n", "antiscanner_sngvy": "# Shodan\n8.8.0.0/24\n7.7.7.0/24\n"}
    loads, sent = {}, []
    HOSTS = {"DE7": {"host": "93.185.179.107"}, "NL1": {"host": "93.185.34.47"}}

    def ctl(h, args, inp=None):
        if args == ["scanners-load"]:
            loads[h] = inp
            return {"ok": True} if h == "DE7" else {"ok": False, "error": "timeout"}
        if args == ["scan-clients"]:
            return {"ok": True, "clients": {"4.4.1.9": {"user": "user_gov", "last": 50, "n": 2}}} if h == "DE7" else {"ok": False}
        return {"ok": False}
    asked_users = []
    USERS = {"user_gov": {"username": "user_gov", "status": "ACTIVE", "expire": 1900000000, "tg": 123456,
                          "desc": "Bot user: Иван Петров @ivan_p", "node": "DE7", "online": 1000, "devices": 2,
                          "traffic_gb": 12.5, "ua": "Happ/4.6.0/ios"}}
    sm = sl.run([], fetcher=lambda n: LST[n], run_ctl=ctl, hosts=HOSTS, send=sent.append, now=1000, base=tmp,
                users=lambda names: asked_users.append(list(names)) or USERS)
    check("собрано из четырёх списков и своих добавок (пересечения слиты)", sm["nets"] == 7
          and sm["per_list"] == {"antiscanner": 1, "government_networks": 2, "skipa": 1, "c24be_gov": 2,
                                 "antiscanner_sngvy": 2} and sm["extra"] == 1)
    check("разослано на все серверы одинаково", set(loads) == {"DE7", "NL1"} and loads["DE7"] == loads["NL1"] and "203.0.113.0/24" in loads["DE7"])
    check("кто не принял — видно", sm["hosts"] == {"DE7": "ok", "NL1": "ошибка: timeout"})
    check("наш клиент в списке — с указанием, в каких", sm["clients"]["4.4.1.9"]["list"] == "государственные сети, госорганы РФ (C24Be)"
          and sm["clients"]["4.4.1.9"]["node"] == "DE7")
    check("сообщение владельцу: не принял сервер и клиент в списке", len(sent) == 1 and "NL1" in sent[0] and "user_gov" in sent[0]
          and "исключения" in sent[0])
    ct = sl.client_text("4.4.1.9", sm["clients"]["4.4.1.9"], now=1000)
    check("кто клиент: ник и имя из панели, TG, подписка, где был, устройства", asked_users == [["user_gov"]]
          and all(x in ct for x in ("user_gov", "@ivan_p", "Иван Петров", "TG 123456", "подписка активна до", "DE7",
                                    "устройств: 2", "12.5 ГБ", "Happ/4.6.0/ios", "4.4.1.9", "госорганы"))
          and "@ivan_p" in sent[0])
    ct0 = sl.client_text("4.4.1.9", {"user": "u1", "node": "NL1", "list": "сканеры"})
    check("панели нет — имя из журнала, нода и список", ct0 == "u1; адрес 4.4.1.9; список: сканеры; нода: NL1")
    ct1 = sl.client_text("4.4.1.9", {"user": "150", "list": "сканеры", "info": {"id": "150", "username": "ivan_vpn", "status": "ACTIVE"}})
    check("в журнале Xray номер — показываем имя из панели и номер", ct1.startswith("ivan_vpn (№150); адрес 4.4.1.9"))
    check("в панель — только допустимые имена, без настроек — ничего не спрашиваем",
          sl.panel_users(["x;rm", "ok"], conf={}) == {} and sl.panel_users(["a b"], conf={"host": "h"}) == {})
    check("итог сохранён для отчёта", json.load(open(os.path.join(tmp, "summary.json"), encoding="utf-8"))["nets"] == 7)
    sent.clear()

    def ctl_ok(h, args, inp=None):
        return ctl("DE7", args, inp)
    sl.run([], fetcher=lambda n: LST[n], run_ctl=ctl_ok, hosts=HOSTS, send=sent.append, now=2000, base=tmp)
    check("всё приняли, клиент уже известен — молчим", sent == [])
    sm = sl.run(["--dry"], fetcher=lambda n: None, run_ctl=None, hosts=HOSTS, send=sent.append, now=3000, base=tmp)
    check("--dry: ничего не шлёт; не скачалось — прошлые копии", sent == [] and sm["nets"] == 7 and len(sm["notes"]) == 5)
check("адреса списков: shadow-netlab и C24Be (госорганы, обновляется ежедневно)",
      sl.list_url("skipa").endswith("/traffic-guard-lists/refs/heads/main/public/skipa.list")
      and sl.list_url("c24be_gov") == "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist.txt"
      and sl.LISTS["c24be_gov"] == "госорганы РФ (C24Be)"
      and sl.list_url("antiscanner_sngvy") == "https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
      and sl.LISTS["antiscanner_sngvy"] == "сканеры и парсеры подписок (AntiScanner)")

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
          and any("наши клиенты: 1" in x and "user_gov; адрес 4.4.1.9; список: государственные сети" in x for x in iss))
    check("отчёт: нет данных — нет строк", d.scan_lines({}, os.path.join(tmp, "нет.json")) == ([], []))

# --- сборщик метрик передаёт счёт сканеров
stj = json.dumps({"ok": True, "loaded": True, "mode": "watch", "blocked": [], "suspects": [], "counters": {},
                  "scan": {"mode": "count", "nets": 2600, "updated": 5, "sources": 3, "packets": 77, "top": [["1.2.3.4", 70]]}})
sh = col.shield(run=lambda: stj)
check("срез: счёт сканеров без адресов", sh["scan"] == {"mode": "count", "nets": 2600, "updated": 5, "sources": 3, "packets": 77})
print("сканеры: тестов пройдено %d" % ok)
