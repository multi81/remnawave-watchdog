"""Тесты проверки «из-за рубежа» через два разных канала (blockwatch.abroad_check, abroad_vias, abroad_line, тексты
deep_verdict и node_line, связка с deep_diag) и имени в приветствии TLS у nodewatch.socks_open.
Без сети, кроме 127.0.0.1: PYTHONIOENCODING=utf-8 python test_abroad.py"""
import os
import socket
import socketserver
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import blockwatch  # noqa: E402
import netprobe  # noqa: E402
import nodewatch  # noqa: E402

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)

ok = 0


def check(name, cond):
    global ok
    print(("OK   " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)
    ok += 1


CTRL = blockwatch.ABROAD_CONTROL
NL1, PL = {"name": "NL1", "port": 21003}, {"name": "Poland", "port": 21004}
real_sopen = nodewatch.socks_open


def world(target, control):
    """Заглушка socks_open: target/control — {порт канала: ответ}; все вызовы — в calls."""
    calls = []

    def fake(port, host, p, timeout=5, tls=False, sni=None):
        calls.append((port, host, p, tls, sni))
        return (control if host == CTRL else target).get(port, False)
    nodewatch.socks_open = fake
    return calls


def to_target(calls):
    return [c for c in calls if c[1] != CTRL]


# AB1 цель ответила через первый канал — один запрос, без контроля
calls = world({21003: True}, {})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
check("AB1 первый канал довёз — ok True, один запрос, без контроля и без второго канала",
      r["ok"] is True and r["via"] == "NL1" and r["port"] == 21003 and r["sure"] == 0 and len(calls) == 1
      and r["tries"] == [["NL1", True, None]]
      and blockwatch.abroad_line({"abroad": True, "via": r["via"], "abroad_tries": r["tries"]})
      == "• из-за рубежа (через NL1): отвечает")

DEAD = {"host": "h", "addr": "9.9.9.9", "tcp": "timeout", "tcp_ms": None, "tls": None, "bytes": None, "need": 65536,
        "end": None}
# AB2 оба канала подтвердили «не отвечает»
calls = world({}, {21003: True, 21004: True})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
d = {"direct": DEAD, "agents": {}, "abroad": r["ok"], "via": r["via"], "abroad_tries": r["tries"],
     "abroad_sure": r["sure"], "trace": None, "external": None}
check("AB2 два разных канала подтвердили — ok False, sure 2, оба в выводе",
      r["ok"] is False and r["sure"] == 2 and r["via"] == "NL1 и Poland" and len(to_target(calls)) == 2
      and blockwatch.abroad_line(d) == "• из-за рубежа (через NL1 и Poland): не отвечает"
      and "сбой самой ноды или её хостера, а не блокировка (через NL1 и Poland)" in blockwatch.deep_verdict(d, "DOWN"))

# AB3 первый молчит, второй отвечает
calls = world({21004: True}, {21003: True, 21004: True})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
d3 = {"abroad": r["ok"], "via": r["via"], "abroad_tries": r["tries"]}
check("AB3 через первый канал не ответила, через второй отвечает — ok True и честная строка",
      r["ok"] is True and r["via"] == "Poland" and r["port"] == 21004
      and blockwatch.abroad_line(d3) == "• из-за рубежа: через NL1 не ответила, через Poland отвечает")

# AB4 обходные каналы сами не работают
calls = world({}, {})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
d4 = dict(d, abroad=r["ok"], via=r["via"], abroad_tries=r["tries"], abroad_sure=r["sure"])
v4 = blockwatch.deep_verdict(d4, "DOWN")
check("AB4 контроль не прошёл ни через один канал — None, «не различить», без «сбой самой ноды»",
      r["ok"] is None and r["port"] == 21003 and "не различить" in v4 and "проверить не удалось" in v4
      and "сбой самой ноды" not in v4
      and "проверить не удалось" in blockwatch.abroad_line(d4)
      and "из-за рубежа проверить не удалось (обходной канал не работал)" in blockwatch.node_line("X", d4))

# AB5 канал один
calls = world({}, {21003: True})
r = blockwatch.abroad_check([NL1], "n.example", 443, True)
d5 = dict(d, abroad=r["ok"], via=r["via"], abroad_tries=r["tries"], abroad_sure=r["sure"])
check("AB5 канал один: цель дважды молчит, контроль жив — sure 1, «неуверенный»",
      r["ok"] is False and r["sure"] == 1 and len(to_target(calls)) == 2
      and "неуверенный" in blockwatch.deep_verdict(d5, "DOWN")
      and blockwatch.abroad_line(d5) == "• из-за рубежа (через NL1): не отвечает"
      and "из-за рубежа НЕ отвечает (через один канал)" in blockwatch.node_line("X", d5))
calls = world({}, {})
r = blockwatch.abroad_check([NL1], "n.example", 443, True)
check("AB5a канал один и контроль мёртв — None", r["ok"] is None and r["sure"] == 0)
calls = world({}, {21003: True})
calls_n = []


def second_ok(port, host, p, timeout=5, tls=False, sni=None):
    calls_n.append(host)
    return host == CTRL or calls_n.count("n.example") == 2


nodewatch.socks_open = second_ok
r = blockwatch.abroad_check([NL1], "n.example", 443, True)
check("AB5b канал один, со второй попытки ответила — ok True, строка «со второй попытки»",
      r["ok"] is True and blockwatch.abroad_line({"abroad": True, "via": r["via"], "abroad_tries": r["tries"]})
      == "• из-за рубежа: через NL1 со второй попытки отвечает")

# AB6 у второго канала мёртв контроль
calls = world({}, {21003: True})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
d6 = dict(d, abroad=r["ok"], via=r["via"], abroad_tries=r["tries"], abroad_sure=r["sure"])
check("AB6 второй канал сам не довозит — sure 1, ровно 2 запроса к цели, порт для сверки — первого",
      r["ok"] is False and r["sure"] == 1 and r["via"] == "NL1" and r["port"] == 21003 and len(to_target(calls)) == 2
      and blockwatch.abroad_line(d6) == "• из-за рубежа (через NL1): не отвечает"
      and "второго рабочего канала для сверки нет" in blockwatch.deep_verdict(d6, "DOWN"))
calls = world({}, {21004: True})
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
check("AB6a у первого мёртв контроль, второй подтвердил — порт для сверки второго",
      r["ok"] is False and r["sure"] == 1 and r["via"] == "Poland" and r["port"] == 21004)


# AB7 исключение внутри socks_open
def boom(*a, **k):
    raise RuntimeError("сломалось")


nodewatch.socks_open = boom
r = blockwatch.abroad_check([NL1, PL], "n.example", 443, True)
check("AB7 ошибка в socks_open — ok None, разбор не падает", r["ok"] is None and r["port"] == 21003 and r["tries"])

# AB8 связка с deep_diag
FINE = {"host": "h", "addr": "9.9.9.9", "tcp": "open", "tcp_ms": 40, "tls": True, "bytes": 65536, "need": 65536,
        "end": "ok"}
real = (netprobe.direct_probe, netprobe.series, netprobe.sni_compare, netprobe.name_ref, netprobe.tcp_trace,
        netprobe.neighbours, netprobe.own_addr, blockwatch.agent_get, blockwatch.registry_hit, blockwatch.witness_wait,
        blockwatch.add_hop_info, blockwatch.read_etc)
netprobe.direct_probe = lambda host, port=443, sni=None, **kw: dict(FINE)
netprobe.series = lambda host, port=443, n=20, mss=None, **kw: {"n": n, "ok": n, "fail": 0}
netprobe.sni_compare = lambda *a, **k: None
netprobe.name_ref = lambda *a, **k: None
netprobe.tcp_trace = lambda *a, **k: None
netprobe.neighbours = lambda *a, **k: None
netprobe.own_addr = lambda: None
blockwatch.agent_get = lambda *a, **k: None
blockwatch.registry_hit = lambda *a, **k: None
wit = []
blockwatch.witness_wait = lambda url, series, port=None: wit.append(port) or {}
blockwatch.add_hop_info = lambda *a, **k: None
blockwatch.read_etc = lambda name, default=None: default
try:
    RL = {"name": "R", "entry": "r.example", "entry_port": 443, "security": "reality", "sni": "www.cover.example"}
    VL = {"name": "V", "entry": "v.example", "entry_port": 443, "security": "none", "sni": "www.cover.example"}
    calls = world({21003: True}, {})
    dd = blockwatch.deep_diag(RL, NL1, [], ("example",))
    one = dd["abroad"] is True and dd["via"] == "NL1" and calls == [(21003, "r.example", 443, True, "www.cover.example")]
    calls = world({21003: True}, {})
    dd = blockwatch.deep_diag(VL, [NL1, PL], [], ("example",))
    lst = dd["abroad"] is True and calls == [(21003, "v.example", 443, False, None)]
    dd = blockwatch.deep_diag(VL, None, [], ("example",))
    none = dd["abroad"] is None and dd["via"] is None and dd["abroad_tries"] == [] and dd["abroad_sure"] == 0
    check("AB8 deep_diag принимает словарь, список и None; для Reality уходит имя прикрытия, без TLS — без имени",
          one and lst and none)
    wit.clear()
    calls = world({}, {21004: True})
    dd = blockwatch.deep_diag(RL, [NL1, PL], [], ("example",))
    check("AB8a сверка с нодой — через канал, у которого прошёл контроль",
          wit == [21004] and dd["abroad"] is False and dd["abroad_sure"] == 1)
    nodewatch.socks_open = boom
    dd = blockwatch.deep_diag(RL, [NL1, PL], [], ("example",))
    check("AB7a ошибка в socks_open — deep_diag не падает, abroad None", dd["abroad"] is None and dd["direct"]["tcp"] == "open")
    dd["direct"] = dict(DEAD)
    check("AB7b ошибка внутри проверки — «проверка сорвалась», а не «обходной канал не открыл контрольный адрес»",
          dd.get("abroad_err") is True and "проверка сорвалась" in blockwatch.abroad_line(dd)
          and "контрольный адрес" not in blockwatch.abroad_line(dd)
          and "проверка из-за рубежа сорвалась" in blockwatch.deep_verdict(dd, "DOWN")
          and "обходной канал сам не работал" not in blockwatch.deep_verdict(dd, "DOWN"))

    # AB10 разбор со сроком: точка, из-за рубежа и счётчики ноды висят дольше срока — отдаём то, что успели
    import time as _t

    def slow(*a, **k):
        _t.sleep(3)
        return None

    def slow_open(*a, **k):
        _t.sleep(3)
        return False
    blockwatch.agent_get = slow
    nodewatch.socks_open = slow_open
    blockwatch.witness_wait = lambda url, series, port=None: _t.sleep(3) or {}
    OWN = {"name": "O", "entry": "o.example", "entry_port": 443, "security": "reality", "sni": "o.example"}
    AG = [{"name": "Москва", "url": "http://127.0.0.1:9", "token": "t"}]
    blockwatch.LINGER = False
    t0 = _t.monotonic()
    dd = blockwatch.deep_diag(OWN, [NL1, PL], AG, ("example",), deadline=_t.monotonic() + 1.0)
    took = _t.monotonic() - t0
    check(f"AB10 срок 1 с — разбор вернулся вовремя ({took:.1f} с): rf1 есть, точка «не успела», из-за рубежа нет",
          took < 2.0 and dd["direct"]["tcp"] == "open" and dd.get("late") == ["Москва"] and dd["abroad"] is None
          and dd["witness"] == {} and blockwatch.LINGER
          and "• Москва: не успела ответить за срок разбора" in blockwatch.deep_lines(dd))
    # AB10a deep_many со сроком: каждый канал отдельно — зависший канал не отнимает готовый
    real_dd = blockwatch.deep_diag

    def fake_dd(ch, via, agents, bases, deadline=None):
        if ch["name"] == "Hang":
            _t.sleep(5)
        return {"name": ch["name"]}
    blockwatch.deep_diag = fake_dd
    blockwatch.LINGER = False
    t0 = _t.monotonic()
    got = blockwatch.deep_many([{"name": "Fast"}, {"name": "Hang"}], lambda c: None, [], ("example",),
                               deadline=_t.monotonic() + 0.5)
    took = _t.monotonic() - t0
    blockwatch.deep_diag = real_dd
    check(f"AB10a deep_many со сроком — готовый канал отдан, зависший нет ({took:.1f} с)",
          list(got) == ["Fast"] and took < 0.5 + blockwatch.DEEP_TAIL + 1 and blockwatch.LINGER)
    blockwatch.LINGER = False
finally:
    (netprobe.direct_probe, netprobe.series, netprobe.sni_compare, netprobe.name_ref, netprobe.tcp_trace,
     netprobe.neighbours, netprobe.own_addr, blockwatch.agent_get, blockwatch.registry_hit, blockwatch.witness_wait,
     blockwatch.add_hop_info, blockwatch.read_etc) = real
    nodewatch.socks_open = real_sopen

# AB9 выбор каналов
CH = {"name": "Bad", "entry": "bad.example"}
C = [{"name": "A", "key": "A full", "port": 1, "entry": "bad.example"},     # тот же вход, что у ch
     {"name": "B", "key": "B full", "port": 2, "entry": "b.example"},
     {"name": "B2", "key": "B2 full", "port": 3, "entry": "b.example"},     # тот же вход, что у B
     {"name": "Cc", "key": "C full", "port": 4, "entry": "c.example"},      # выход как у ch
     {"name": "D", "key": "D full", "port": 5, "entry": "d.example"},       # выход как у B
     {"name": "E", "key": "E full", "port": 6, "entry": "e.example"}]       # выход неизвестен
ex = {"Bad": "1.0.0.1", "B full": "198.51.100.2", "C full": "1.0.0.1", "D full": "198.51.100.2"}
check("AB9 разные входы и выходы; выход как у ch и повтор выхода пропускаются; неизвестный выход не мешает",
      blockwatch.abroad_vias(C, CH, ex) == [{"name": "B", "port": 2}, {"name": "E", "port": 6}]
      and blockwatch.abroad_vias(C, CH) == [{"name": "B", "port": 2}, {"name": "Cc", "port": 4}]
      and blockwatch.abroad_vias([], CH, ex) == []
      and blockwatch.abroad_vias(C[:1], CH, ex) == [])
check("AB9a старые тексты: словарь без abroad_sure даёт прежний вывод",
      "сбой самой ноды или её хостера, а не блокировка" in blockwatch.deep_verdict(
          {"direct": DEAD, "agents": {}, "abroad": False, "via": "NL1", "trace": None, "external": None}, "DOWN")
      and "проверить было не через что" in blockwatch.deep_verdict(
          {"direct": DEAD, "agents": {}, "abroad": None, "via": None, "trace": None, "external": None}, "DOWN"))


# SN1 имя в приветствии TLS: локальный SOCKS5 и «сервер», который смотрит в приветствие
class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        c.settimeout(3)
        try:
            g = c.recv(2)
            c.recv(g[1])
            c.sendall(bytes([5, 0]))
            head = c.recv(4)
            if head[3] == 3:
                host = c.recv(c.recv(1)[0]).decode()
            else:
                host = socket.inet_ntoa(c.recv(4))
            port = int.from_bytes(c.recv(2), "big")
            c.sendall(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
            up = socket.create_connection((host, port), timeout=2)
        except (OSError, IndexError):
            return
        up.settimeout(0.3)
        c.settimeout(0.3)
        for _ in range(20):
            for a, b in ((up, c), (c, up)):
                try:
                    data = a.recv(4096)
                    if not data:
                        return
                    b.sendall(data)
                except socket.timeout:
                    pass
                except OSError:
                    return


hellos = []


class TlsLook(socketserver.BaseRequestHandler):  # на простой запрос молчит; приветствие TLS запоминает и отказывает
    def handle(self):
        try:
            self.request.settimeout(4)
            first = self.request.recv(1)
            if first == bytes([22]):
                hellos.append(self.request.recv(4096))
                self.request.sendall(bytes([21, 3, 3, 0, 2, 2, 40]))
        except OSError:
            pass


srv = [socketserver.ThreadingTCPServer(("127.0.0.1", 0), h) for h in (Socks, TlsLook)]
for s in srv:
    s.daemon_threads = True
    threading.Thread(target=s.serve_forever, daemon=True).start()
sp, tp = srv[0].server_address[1], srv[1].server_address[1]
r1 = nodewatch.socks_open(sp, "127.0.0.1", tp, timeout=3, tls=True, sni="x.example")
got1 = list(hellos)
hellos.clear()
r2 = nodewatch.socks_open(sp, "127.0.0.1", tp, timeout=3, tls=True)
check("SN1 socks_open с sni: в приветствии TLS — это имя; без sni (адрес) имени нет",
      r1 is True and r2 is True and got1 and b"x.example" in got1[0] and hellos and b"x.example" not in hellos[0])
for s in srv:
    s.shutdown()

print(f"\nвсе проверки пройдены: {ok}")
