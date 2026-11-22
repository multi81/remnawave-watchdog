"""Тесты: свой список сканеров по поведению (behavscan), пометки о профиле тюнинга (nodewatch), имя списка в
scanlists. Без сети."""
import ipaddress
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behavscan as bs  # noqa: E402
import nodewatch as nw  # noqa: E402
import scanlists as sl  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


NOW = 1_800_000_000
own = [ipaddress.ip_network("192.0.2.10/32")]
beacons = {
    "node-a": {"knocks": [["203.0.113.1", 1, 5, 1],      # стук на 443 закрытого — сканер
                        ["203.0.113.2", 1, 1, 0],      # один порт, один сервер — не сканер
                        ["203.0.113.3", 4, 9, 0],      # 4 разных порта — сканер
                        ["192.0.2.10", 9, 9, 1],       # наш адрес — никогда
                        ["198.51.100.5", 12, 40, 0],   # домашний, но 12 портов — берём
                        ["198.51.100.6", 1, 1, 1],     # домашний, стук на 443 — не берём (может быть клиент)
                        ["bad", 1, 1, 1]]},
    "node-b": {"knocks": [["203.0.113.4", 1, 1, 0]]},
    "node-c": {"knocks": [["203.0.113.4", 1, 2, 0]]},      # 203.0.113.4: два сервера — сканер
    "node-d": None,
}
agg = bs.aggregate(beacons)
check("A1 сводка по адресам и серверам", agg["203.0.113.4"]["nodes"] == {"node-b", "node-c"} and agg["203.0.113.4"]["hits"] == 3
      and "bad" not in agg)
check("A2 признаки", bs.suspicious(agg["203.0.113.1"]) and not bs.suspicious(agg["203.0.113.2"])
      and bs.suspicious(agg["203.0.113.3"]) and bs.suspicious(agg["203.0.113.4"]))
asked = []
INFO = {"203.0.113.1": {"hosting": True, "as": "AS64500 Scan"}, "203.0.113.3": {"hosting": True, "as": "AS64500 Scan"},
        "203.0.113.4": {"hosting": True, "as": "AS64501 Cloud"}, "198.51.100.5": {"hosting": False, "as": "AS64510 ISP"},
        "198.51.100.6": {"hosting": False, "as": "AS64510 ISP"}}


def lookup(ips):
    asked.append(sorted(ips))
    return {i: INFO[i] for i in ips if i in INFO}


st = {}
listed, new = bs.step(st, beacons, own, NOW, lookup)
check("S1 в списке хостинги и размашистый домашний", listed == ["198.51.100.5", "203.0.113.1", "203.0.113.3", "203.0.113.4"]
      and new == 4)
check("S2 свой адрес и одиночный стук не спрашиваем", "192.0.2.10" not in asked[0] and "203.0.113.2" not in asked[0])
check("S3 домашний с одним стуком запомнен, но не в списке", st["ips"]["198.51.100.6"]["listed"] is False)
listed2, new2 = bs.step(st, beacons, own, NOW + 3600, lookup)
check("S4 повторный проход: сведения из кэша, новых нет", len(asked) == 1 and new2 == 0 and listed2 == listed)
check("S5 стуки копятся", st["ips"]["203.0.113.1"]["hits"] == 10)
listed3, _ = bs.step(st, {}, own, NOW + 31 * 86400, lookup)
check("S6 через 30 дней без стуков — из списка", listed3 == [] and st["ips"] == {})
st2 = {}
bs.step(st2, beacons, own, NOW, lambda ips: {})
check("S7 ip-api молчит — никого не берём вслепую", not any(e.get("listed") for e in st2.get("ips", {}).values()))
st3 = {}
bs.step(st3, beacons, own, NOW, lookup)
own2 = own + [ipaddress.ip_network("203.0.113.1/32")]
l4, _ = bs.step(st3, beacons, own2, NOW + 60, lookup)
check("S8 добавили в исключения — пропал из списка", "203.0.113.1" not in l4)

check("T1 профиль в порядке — без пометок", nw.tune_flags({"cc": "bbr", "qdisc": "fq", "conntrack_max": 100000, "mptcp": 0}) == [])
f = nw.tune_flags({"cc": "cubic", "qdisc": "fq_codel", "conntrack_max": 8192, "mptcp": 1})
check("T2 слетевший профиль — четыре пометки", f == ["TCP cubic, не BBR", "очередь fq_codel, не fq", "MPTCP включён",
                                                    "таблица соединений 8192"])
check("T2b cake тоже годится", nw.tune_flags({"cc": "bbr", "qdisc": "cake", "conntrack_max": 100000, "mptcp": 0}) == [])
check("T3 старый маячок без профиля — молчим", nw.tune_flags(None) == [])
node = {"data": {"ts": NOW, "disk_pct": 10, "mem_avail_mb": 900, "ufw": "active", "tune": {"cc": "cubic"}}, "ok_ts": NOW}
check("T4 пометка в отчёте о сервере", nw.node_flags(node, NOW) == ["TCP cubic, не BBR"])

per = {"skipa": [ipaddress.ip_network("203.0.113.0/24")], sl.BEHAVIOR: [ipaddress.ip_network("198.51.100.5/32")]}
check("L1 имя своего списка", sl.which_list("198.51.100.5", per) == "по поведению на наших серверах")
d = tempfile.mkdtemp()
open(os.path.join(d, sl.BEHAVIOR + ".list"), "w").write("198.51.100.5/32\n")
s = sl.run(["--dry"], fetcher=lambda n: None, run_ctl=None, hosts={}, send=None, now=NOW, base=d)
check("L2 scanlists подхватывает свой список", s["per_list"].get(sl.BEHAVIOR) == 1)
print("сканеры по поведению, профиль: тестов пройдено %d" % ok)
