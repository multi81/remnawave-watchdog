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
bs.SALT = os.path.join(tempfile.mkdtemp(), "behavscan.salt")   # соль — во временный файл, не в /var/lib


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


NOW = 1_800_000_000
DAY = 86400
own = [ipaddress.ip_network("37.0.2.10/32")]
beacons = {
    "node-a": {"knocks": [["37.0.113.1", 1, 5, 1],      # стук на 443 закрытого — сканер
                        ["37.0.113.2", 1, 1, 0],      # один порт, один сервер — не сканер
                        ["37.0.113.3", 4, 9, 0],      # 4 разных порта — сканер
                        ["37.0.2.10", 9, 9, 1],       # наш адрес — никогда
                        ["37.51.100.5", 12, 40, 0],   # домашний, но 12 портов — берём
                        ["37.51.100.6", 1, 1, 1],     # домашний, стук на 443 — не берём (может быть клиент)
                        ["bad", 1, 1, 1]]},
    "node-b": {"knocks": [["37.0.113.4", 1, 1, 0],
                       # вторая нода видит тех же: без 2 нод в список не вносим
                       ["37.0.113.1", 1, 1, 1], ["37.0.113.3", 3, 3, 0], ["37.0.2.10", 1, 1, 0],
                       ["37.51.100.5", 11, 11, 0], ["37.51.100.6", 1, 1, 1]]},
    "node-c": {"knocks": [["37.0.113.4", 1, 2, 0]]},      # 37.0.113.4: два сервера — сканер
    "node-d": None,
}
agg = bs.aggregate(beacons)
check("A1 сводка по адресам и серверам", agg["37.0.113.4"]["nodes"] == {"node-b", "node-c"} and agg["37.0.113.4"]["hits"] == 3
      and "bad" not in agg)
check("A2 признаки", bs.suspicious(agg["37.0.113.1"]) and not bs.suspicious(agg["37.0.113.2"])
      and bs.suspicious(agg["37.0.113.3"]) and bs.suspicious(agg["37.0.113.4"]))
asked = []
INFO = {"37.0.113.1": {"hosting": True, "mobile": False, "as": "AS64500 Scan"},
        "37.0.113.3": {"hosting": True, "mobile": False, "as": "AS64500 Scan"},
        "37.0.113.4": {"hosting": True, "mobile": False, "as": "AS64501 Cloud"},
        "37.51.100.5": {"hosting": False, "mobile": False, "as": "AS64510 ISP"},
        "37.51.100.6": {"hosting": False, "mobile": False, "as": "AS64510 ISP"}}


def lookup(ips):
    asked.append(sorted(ips))
    return {i: INFO[i] for i in ips if i in INFO}


def two_days(st_, t, lk=lookup, **kw):
    """Те же стуки двое суток подряд (правило «2 ноды и 2 суток»). -> итог второго прохода."""
    bs.step(st_, beacons, own, t, lk, **kw)
    return bs.step(st_, beacons, own, t + DAY, lk, **kw)


st = {}
l0, n0 = bs.step(st, beacons, own, NOW, lookup)
check("S0 первые сутки — никого: нужны 2 суток", l0 == [] and n0 == 0 and asked == [])
listed, new = bs.step(st, beacons, own, NOW + DAY, lookup)
check("S1 вторые сутки: в списке хостинги и размашистый домашний",
      listed == ["37.0.113.1", "37.0.113.3", "37.0.113.4", "37.51.100.5"] and new == 4)
check("S2 свой адрес и одиночный стук не спрашиваем", "37.0.2.10" not in asked[0] and "37.0.113.2" not in asked[0]
      and "37.0.113.2" not in st["ips"])
check("S3 домашний с одним стуком запомнен, но не в списке", st["ips"]["37.51.100.6"]["listed"] is False)
listed2, new2 = bs.step(st, beacons, own, NOW + DAY + 3600, lookup)
check("S4 повторный проход: сведения из кэша, новых нет", len(asked) == 1 and new2 == 0 and listed2 == listed)
check("S5 стуки копятся по суткам, второй проход за те же сутки не удваивает", st["ips"]["37.0.113.1"]["hits"] == 12)
listed3, _ = bs.step(st, {}, own, NOW + 32 * DAY, lookup)
check("S6 через 30 дней без стуков — из списка", listed3 == [] and st["ips"] == {})
st2 = {}
two_days(st2, NOW, lambda ips: {})
check("S7 ip-api молчит — никого не берём вслепую", not any(e.get("listed") for e in st2.get("ips", {}).values()))
st3 = {}
two_days(st3, NOW)
own2 = own + [ipaddress.ip_network("37.0.113.1/32")]
l4, _ = bs.step(st3, beacons, own2, NOW + DAY + 60, lookup)
check("S8 добавили в исключения — пропал из списка", "37.0.113.1" not in l4 and "37.0.113.3" in l4)

st5 = {}
two_days(st5, NOW)
l5, _ = bs.step(st5, beacons, own, NOW + DAY + 60, lookup, clients_of=lambda ips: {"37.0.113.3"} & set(ips))
check("C1 клиент выпадает из списка", "37.0.113.3" not in l5 and "37.0.113.3" not in st5["ips"]
      and st5["clients"][bs.client_hash("37.0.113.3", bs.load_salt(NOW + DAY + 60)[0])] == NOW + DAY + 60)
l6, _ = bs.step(st5, beacons, own, NOW + 2 * DAY, lookup, clients_of=lambda ips: set())
check("C2 бывший клиент не возвращается 30 дней", "37.0.113.3" not in l6)
l7, _ = two_days(st5, NOW + 32 * DAY, clients_of=lambda ips: set())
check("C3 через 30 дней без подключений — снова может попасть", "37.0.113.3" in l7)
st6 = {}
l8, _ = two_days(st6, NOW, clients_of=lambda ips: {"37.0.113.1"} & set(ips))
check("C4 клиент не попадает с первого прохода", "37.0.113.1" not in l8 and "37.0.113.3" in l8)

check("T1 профиль в порядке — без пометок", nw.tune_flags({"cc": "bbr", "qdisc": "fq", "conntrack_max": 100000, "mptcp": 0}) == [])
f = nw.tune_flags({"cc": "cubic", "qdisc": "fq_codel", "conntrack_max": 8192, "mptcp": 1})
check("T2 слетевший профиль — четыре пометки", f == ["TCP cubic, не BBR", "очередь fq_codel, не fq", "MPTCP включён",
                                                    "таблица соединений 8192"])
check("T2b cake тоже годится", nw.tune_flags({"cc": "bbr", "qdisc": "cake", "conntrack_max": 100000, "mptcp": 0}) == [])
check("T3 старый маячок без профиля — молчим", nw.tune_flags(None) == [])
node = {"data": {"ts": NOW, "disk_pct": 10, "mem_avail_mb": 900, "ufw": "active", "tune": {"cc": "cubic"}}, "ok_ts": NOW}
check("T4 пометка в отчёте о сервере", nw.node_flags(node, NOW) == ["TCP cubic, не BBR"])

D = {"active": True, "current": "127.0.0.1", "queries": 755000, "hits": 727000, "exceeded": 81, "rrset_mb": 20.0,
     "rrset_max_mb": 64, "msg_mb": 10.0, "msg_max_mb": 32, "fallback_24h": 2}
check("D1 резолвер в порядке — без пометок", nw.dns_flags(D) == [])
check("D1b после перезапуска мелкие числа — без пометки", nw.dns_flags(dict(D, queries=1868, exceeded=3)) == [])
check("D2 не ставили — молчим", nw.dns_flags(None) == [])
check("D3 не работает", nw.dns_flags(dict(D, active=False)) == ["свой DNS не работает (система на запасном)"])
f = nw.dns_flags(dict(D, current="1.1.1.1", fallback_24h=30, exceeded=5000, rrset_mb=63.5))
SLOW = ("DNS отвечает медленно: 5000 ответов искались дольше 1,9 с (18 % из 28000 поисков мимо кэша; "
        "клиенты в это время ждут 2 с и идут на запасной)")
check("D4 запасной, частые уходы, медленные ответы, кэш", f == ["DNS сейчас на запасном 1.1.1.1",
                                                               "DNS уходил на запасной 30 раз за сутки", SLOW,
                                                               "кэш DNS записей заполнен (63.5 из 64 МБ)"])
check("D5 обычные медленные ответы (7 % поисков мимо кэша) — без пометки", nw.dns_flags(dict(D, exceeded=2000)) == [])
check("D6 как на живой ноде (1127 из ~21800 мимо кэша, 5 %) — без пометки",
      nw.dns_flags(dict(D, queries=284564, hits=284564 - 21806, exceeded=1127)) == [])
check("D7 сразу после перезапуска (20 из 987 мимо кэша) — молчим", nw.dns_flags(dict(D, queries=30716, hits=29729, exceeded=20)) == [])
check("D8 нет поля hits (старый маячок) — не делим на ноль, без ложной пометки",
      nw.dns_flags({k: v for k, v in D.items() if k != "hits"}) == [])

per = {"skipa": [ipaddress.ip_network("37.0.113.0/24")], sl.BEHAVIOR: [ipaddress.ip_network("37.51.100.5/32")]}
check("L1 имя своего списка", sl.which_list("37.51.100.5", per) == "по поведению на наших серверах")
d = tempfile.mkdtemp()
open(os.path.join(d, sl.BEHAVIOR + ".list"), "w").write("37.51.100.5/32\n")
s = sl.run(["--dry"], fetcher=lambda n: None, run_ctl=None, hosts={}, send=None, now=NOW, base=d)
check("L2 scanlists подхватывает свой список", s["per_list"].get(sl.BEHAVIOR) == 1)
print("сканеры по поведению, профиль: тестов пройдено %d" % ok)
