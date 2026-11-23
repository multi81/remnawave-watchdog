"""Тесты щита без сети и без nft: python test_shield.py"""
import datetime as dt
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402
d.IPINFO_LOOKUP = lambda ips: {}   # без сети: сведения об адресах не запрашиваем
d.SCAN_DIR = "/nonexistent"
import shield_ctl as s  # noqa: E402
NFT_REAL = s.nft   # настоящий вызов nft (ниже его подменяют)
import shieldbot as b  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    assert cond, name
    ok += 1


C = dict(s.DEFAULTS, allow=["93.184.89.45", "93.187.140.234", "2a01:4f8::/32"])

# --- shield-ctl: адреса
check("IPv6 блокируется сетью /64", s.block_key("2a03:1:2:3:4:5:6:7") == "2a03:1:2:3::")
check("IPv4 в IPv6 — как IPv4", s.block_key("::ffff:8.8.8.8") == "8.8.8.8")
good, bad = s.check_block(["8.8.8.8", "93.184.89.45", "10.1.1.1", "мусор", "8.8.8.8", "2a01:4f8:1::5", "1.1.1.1"], C)
check("блокировать можно чужих; свои, частные и мусор — отказ; повтор — один раз",
      good == ["8.8.8.8", "1.1.1.1"] and dict(bad) == {"93.184.89.45": "в списке своих", "10.1.1.1": "частный или служебный",
                                                         "мусор": "не адрес", "2a01:4f8:1::5": "в списке своих"})
many = ["8.8.%d.%d" % (i // 250, i % 250 + 1) for i in range(60)]
g2, b2 = s.check_block(many, C)
check("не больше 50 за раз", len(g2) == 50 and len(b2) == 10)
check("полигон: allow_private=false — частные можно", s.check_block(["192.168.77.128"], dict(C, allow_private=False))[0] == ["192.168.77.128"])

# --- shield-ctl: таблица
t = s.render(C, "eth0")
check("таблица: своя, пересоздаётся", t.startswith("table inet storozh_shield\ndelete table inet storozh_shield\n"))
check("таблица: только внешний интерфейс, prerouting", 'iifname != "eth0" return' in t and "hook prerouting priority -300" in t
      and "hook prerouting priority -150" in t)
check("таблица: свои и частные в allow", "93.184.89.45" in t and "10.0.0.0/8" in t and "2a01:4f8::/32" in t)
check("таблица: пороги", "limit rate over 200/second burst 400 packets" in t and "ct count over 5000" in t)
check("наблюдение: enforce пустая", "chain enforce {\n\t}" in t)
check("щит включён: enforce режет", "counter name dropped_shield drop" in s.render(C, "eth0", "on").split("chain enforce")[1])
check("IPv6 — по /64", "ip6 saddr & ffff:ffff:ffff:ffff:: @blocked6" in t)

# --- shield-ctl: команды по SSH
check("ssh: status", s.ssh_argv("status") == ["status"])
check("ssh: block", s.ssh_argv("block 3600 1.2.3.4 2a03:1::") == ["block", "3600", "1.2.3.4", "2a03:1::"])
for bad_cmd in ("load", "unload", "status; rm -rf /", "block 60 $(id)", "tick", "", "mode on `x`"):
    try:
        s.ssh_argv(bad_cmd)
        check("ssh: отказ «%s»" % bad_cmd, False)
    except ValueError:
        check("ssh: отказ «%s»" % bad_cmd, True)

# --- shield-ctl: состояние с подставным nft
calls = []
s.nft = lambda args, inp=None: calls.append(args) or ""
with tempfile.TemporaryDirectory() as tmp:
    s.STATE_FILE = os.path.join(tmp, "st.json")
    s.LOG_FILE = os.path.join(tmp, "log")
    st = {}
    r = s.cmd_block(C, st, 3600, ["8.8.8.8", "93.184.89.45"])
    check("block: добавлено в nft с таймаутом", r["blocked"] == ["8.8.8.8"] and any("blocked4" in a and "timeout 3600s" in a[-1] or
                                                                                      "timeout 3599s" in a[-1] for a in calls))
    check("block: в состоянии (переживёт перезагрузку)", "8.8.8.8" in json.load(open(s.STATE_FILE))["blocks"])
    try:
        s.cmd_block(C, st, 10 ** 6, ["8.8.4.4"])
        check("block: срок больше суток — отказ", False)
    except ValueError:
        check("block: срок больше суток — отказ", True)
    s.set_mode(C, st, "on", 2)
    check("mode on: до +2 ч", st["mode"] == "on" and st["until"] > s.now() + 7000)
    try:
        s.set_mode(C, st, "on", 100)
        check("mode on: больше 6 ч — отказ", False)
    except ValueError:
        check("mode on: больше 6 ч — отказ", True)
    st["until"] = s.now() - 1
    check("tick: срок вышел — наблюдение", s.cmd_tick(C, st)["changed"] and st["mode"] == "watch")
    st["blocks"]["9.9.9.9"] = s.now() - 5
    s.cmd_tick(C, st)
    check("tick: истёкшие блокировки убраны из состояния", "9.9.9.9" not in st["blocks"])
    calls.clear()
    check("unblock all", s.cmd_unblock(C, st, ["all"])["unblocked"] == ["8.8.8.8"] and ["flush", "set", s.TABLE, "blocked4"] in calls)

# --- разбор вывода nft -j (как на полигоне)
js = {"nftables": [{"metainfo": {}}, {"set": {"name": "suspects4", "elem": [
    {"elem": {"val": "192.168.77.128", "timeout": 600, "expires": 590, "counter": {"packets": 207, "bytes": 1}}},
    {"elem": {"val": "1.2.3.4", "counter": {"packets": 5, "bytes": 1}}}]}}]}
check("разбор подозрительных со счётчиком", s.parse_set(js, "suspects4") == [("192.168.77.128", 207), ("1.2.3.4", 5)])
check("разбор счётчиков", s.parse_counters({"nftables": [{"counter": {"name": "over_rate", "packets": 9}}]}) == {"over_rate": 9})

# --- сборщик
st_json = json.dumps({"ok": True, "loaded": True, "mode": "watch", "until": 0, "blocked": [["8.8.8.8", 1]],
                      "suspects": [["1.2.3.4", 900], ["5.6.7.8", 300]], "suspects_total": 2,
                      "counters": {"over_rate": 1000, "over_conns": 200, "dropped_blocked": 7, "dropped_shield": 0},
                      "limits": {"rate": 200, "conns": 5000}})
sh = col.shield(run=lambda: st_json)
check("сборщик: щит в срезе", sh["loaded"] and sh["blocked"] == 1 and sh["suspects"][0] == ["1.2.3.4", 900]
      and sh["over"] == 1200 and sh["dropped"] == 7)
check("сборщик: щита нет — None", col.shield(ctl="/нет/такого") is None)
check("сборщик: таблица не загружена", col.shield(run=lambda: '{"ok": false, "loaded": false}') == {"loaded": False})

# --- сторож: когда предлагать
MSK = d.MSK
DAY = dt.datetime(2026, 10, 22, 14, 0, tzinfo=MSK).timestamp()
NIGHT = dt.datetime(2026, 10, 22, 3, 0, tzinfo=MSK).timestamp()
CW = dict(d.DEFAULTS, hosts=[{"name": "DE7", "host": "x"}])
NORM = {"rx_bps": 30e6, "rx_pps": 4000, "cpu_pct": 20, "ram_pct": 40, "load1": 0.3, "cores": 1, "disk_pct": 50,
        "swap_pct": 0, "failed_units": [], "conntrack_max": 100000, "conntrack_count": 100}


def feed(state, t, shield, **kw):
    return d.process(state, {"DE7": {"samples": [dict(NORM, ts=t, shield=shield, **kw)]}}, CW, t + 5)


SH0 = {"loaded": True, "mode": "watch", "until": 0, "blocked": 0, "suspects": [], "suspects_total": 0, "limits": {"rate": 200}}
SH1 = dict(SH0, suspects=[["1.2.3.4", 5000], ["5.6.7.8", 1200]], suspects_total=2)
SHs = dict(SH0, suspects=[["1.2.3.4", 300]], suspects_total=1)
def TXT(o, cl=None):
    return d.shield_offer_text(o["host"], o["sh"], o["ts"], o.get("attack"), cl)


st = {}
feed(st, DAY, SH0)
check("нет подозрительных — тихо", not st.get("shield_pending"))
feed(st, DAY + 60, SHs)
check("мало лишних (300) — не предлагать", not st.get("shield_pending"))
feed(st, DAY + 120, SH1)
p = st.get("shield_pending") or []
check("много лишних днём — предложение с адресами", len(p) == 1 and p[0]["ips"] == ["1.2.3.4", "5.6.7.8"]
      and "1.2.3.4</code> — 5 000 лишних" in TXT(p[0]) and "сотни клиентов" in TXT(p[0]))
st["shield_pending"] = []
feed(st, DAY + 180, SH1)
check("не чаще раза в час", not st["shield_pending"])
feed(st, DAY + 120 + 3601, SH1)
check("через час — снова", len(st["shield_pending"]) == 1)
st = {}
feed(st, NIGHT, SH0)
feed(st, NIGHT + 60, SH1)
check("ночью без атаки — без кнопок, в отчёт", not st.get("shield_pending")
      and any(x["state"] == "shield" for x in st["hosts"]["DE7"]["deferred"]))
st = {}
feed(st, NIGHT, SH0)
feed(st, NIGHT + 10, SHs, rx_pps=90_000)
feed(st, NIGHT + 20, SHs, rx_pps=90_000)
p = st.get("shield_pending") or []
check("ночью атака — предложение сразу, даже при малом числе лишних", len(p) == 1 and "атака" in TXT(p[0]))
st["shield_pending"] = []
feed(st, NIGHT + 30, SHs, rx_pps=90_000)
check("та же атака — второй раз не предлагать", not st["shield_pending"])
st = {}
feed(st, DAY, dict(SH0, mode="on", until=DAY + 100))
msgs = feed(st, DAY + 200, SH0)
check("щит сам вернулся в наблюдение — сообщение", any("снова режим наблюдения" in m for m in msgs))
check("сводка: строка щита", "<b>Щит:</b> стоит на 1 серверах · везде наблюдение · заблокировано адресов: 0"
      in (d.shield_info(st["hosts"]) or ""))

# --- кнопки
CHAT = "555"


class TG:
    def __init__(self):
        self.calls = []

    def __call__(self, method, payload, timeout=20):
        self.calls.append((method, payload))
        return {"ok": True, "result": {"message_id": 77}}


with tempfile.TemporaryDirectory() as tmp:
    OF = os.path.join(tmp, "offers.json")
    tg = TG()
    oid = b.send_offer("DE7", "block", ["1.2.3.4", "5.6.7.8"], "текст", tg=tg, chat=CHAT, offers_path=OF, now=DAY)
    kb = tg.calls[0][1]["reply_markup"]["inline_keyboard"]
    check("предложение: кнопки 1 ч / сутки / щит / не трогать", oid and [x["callback_data"] for row in kb for x in row]
          == ["sh:%s:b1" % oid, "sh:%s:b24" % oid, "sh:%s:on2" % oid, "sh:%s:no" % oid])
    runs = []

    def run(host, args, hs=None):
        if args == ["status"]:   # бот спрашивает статус для итога через 10 минут — в журнал вызовов не пишем
            return {"ok": True, "counters": {"dropped_blocked": 100}, "suspects": [["1.2.3.4", 50]]}
        runs.append((host, args))
        if args[0] == "block":
            return {"ok": True, "blocked": args[2:], "until": DAY + 3600, "refused": []}
        return {"ok": True, "mode": "on", "until": DAY + 7200, "unblocked": ["1.2.3.4"]}

    def press(data, frm=CHAT, chat=CHAT, now=DAY + 60):
        return b.handle({"callback_query": {"id": "q", "from": {"id": int(frm)}, "data": data,
                                            "message": {"message_id": 77, "chat": {"id": int(chat)}}}},
                        CHAT, tg=tg, run=run, now=now, offers_path=OF)

    r = press("sh:%s:b1" % oid, frm="999", now=DAY)
    check("чужой нажал — отказ, ничего не выполнено", "чужого" in r and not runs)
    r = press("sh:%s:b1" % oid, now=DAY)
    check("владелец нажал «1 ч» — block 3600 этих адресов", runs == [("DE7", ["block", 3600, "1.2.3.4", "5.6.7.8"])])
    check("ответ: сделано, до какого времени, как снять", any(m == "sendMessage" and "2 адреса заблокированы на 1 час" in p["text"]
                                                              and "/unblock" in p["text"] for m, p in tg.calls))
    check("кнопки убраны после нажатия", any(m == "editMessageReplyMarkup" for m, _ in tg.calls))
    runs.clear()
    r = press("sh:%s:b24" % oid, now=DAY)
    check("вторая кнопка того же предложения — не выполняется", "уже выполнено" in r and not runs)
    oid2 = b.send_offer("DE7", "block", ["1.2.3.4"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY)
    r = press("sh:%s:on2" % oid2, now=DAY + b.OFFER_TTL + 600)
    check("кнопка старше 12 часов — не выполняется", "устарела" in r and not runs)
    oid3 = b.send_offer("DE7", "block", ["1.2.3.4"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY)
    press("sh:%s:on2" % oid3)
    check("«включить щит» — mode on 2", runs == [("DE7", ["mode", "on", 2])])
    runs.clear()
    oid4 = b.send_offer("DE7", "block", ["1.2.3.4"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY)
    press("sh:%s:no" % oid4)
    check("«не трогать» — ничего на сервере", not runs)
    r = press("sh:%s:ua" % b.send_offer("DE7", "block", ["1.2.3.4"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY))
    check("кнопка снятия к предложению блокировки — отказ", "не для этого" in r and not runs)
    check("подделанная кнопка — отказ", "непонятная" in press("sh:x:rm") and not runs)

    def status():
        return {"DE7": {"ok": True, "mode": "on", "until": DAY + 3600, "blocked": [["1.2.3.4", 1]],
                        "suspects": [["5.6.7.8", 99]], "suspects_total": 1},
                "PL1": {"ok": True, "mode": "watch", "blocked": [], "suspects": []},
                "ee1": {"ok": False, "error": "timeout"}}
    tg.calls.clear()

    def msg(text, frm=CHAT):
        return b.handle({"message": {"chat": {"id": int(CHAT)}, "from": {"id": int(frm)}, "text": text}}, CHAT, tg=tg,
                        run=run, status=status, now=DAY, offers_path=OF)
    msg("/shield")
    txt = tg.calls[-1][1]["text"]
    check("/shield: по каждому серверу понятно", "<b>DE7</b> — включён до" in txt and "заблокировано 1" in txt
          and "<b>PL1</b> — наблюдение" in txt and "ee1 — не ответил" in txt)
    msg("/unblock")
    kb = tg.calls[-1][1]["reply_markup"]["inline_keyboard"]
    check("/unblock: кнопка только для сервера с блокировками", len([c for c in tg.calls if c[0] == "sendMessage"]) == 2
          and kb[0][0]["text"] == "🔓 Снять все блокировки: DE7")
    oid5 = kb[0][0]["callback_data"].split(":")[1]
    runs.clear()
    press("sh:%s:ua" % oid5)
    check("снять — unblock all и режим наблюдения", runs == [("DE7", ["unblock", "all"]), ("DE7", ["mode", "watch"])])
    check("команда от чужого — молчим", msg("/shield", frm="999") is None)
# ===== сверка с нашими клиентами =====
# --- shield-ctl
t = s.render(C, "eth0")
check("клиенты: свои наборы и цепочка с порогом ×5", "set clients4" in t and "goto pre_clients" in t
      and "limit rate over 1000/second burst 2000 packets" in t and "ct count over 25000" in t)
check("клиенты: проверка клиентов раньше общего порога", t.index("goto pre_clients") < t.index("add @flood4"))
CL = {"8.8.8.8": [1000, "user_42", 5], "2a03:1:2:3::": [1000, "user_9", 1]}
g, bd = s.check_block(["8.8.8.8", "1.1.1.1", "2a03:1:2:3:4::9"], C, CL)
check("клиента без --clients не блокировать", g == ["1.1.1.1"] and ("8.8.8.8", "наш клиент") in bd
      and ("2a03:1:2:3:4::9", "наш клиент") in bd)
check("с --clients — можно", s.check_block(["8.8.8.8"], C, CL, True)[0] == ["8.8.8.8"])
with tempfile.TemporaryDirectory() as tmp:
    s.CLIENTS_FILE = os.path.join(tmp, "clients.json")
    s.STATE_FILE = os.path.join(tmp, "st.json")
    json.dump({"clients": CL}, open(s.CLIENTS_FILE, "w"))
    r = s.cmd_block(C, {}, 3600, ["8.8.8.8", "1.1.1.1"])
    check("block: клиент отклонён по списку сервера", r["blocked"] == ["1.1.1.1"] and ["8.8.8.8", "наш клиент"] in [list(x) for x in r["refused"]])
    r = s.cmd_block(C, {}, 3600, ["--clients", "8.8.8.8"])
    check("block --clients: заблокирован", r["blocked"] == ["8.8.8.8"])
    r = s.cmd_clients(["8.8.8.8", "9.9.9.9", "2a03:1:2:3::77"])
    check("clients: кто наш, с пользователем", set(r["clients"]) == {"8.8.8.8", "2a03:1:2:3::77"}
          and r["clients"]["8.8.8.8"]["user"] == "user_42" and r["known"] == 2)
    check("ssh: clients разрешена, --clients проходит", s.ssh_argv("clients 1.2.3.4") == ["clients", "1.2.3.4"]
          and s.ssh_argv("block 3600 --clients 1.2.3.4")[2] == "--clients")
    tx = s.clients_nft(CL)
    check("набор клиентов — одной транзакцией заново", tx.startswith("flush set inet storozh_shield clients4\nflush set inet storozh_shield clients6\n")
          and "add element inet storozh_shield clients4 { 8.8.8.8 }" in tx and "clients6 { 2a03:1:2:3:: }" in tx)

# --- сборщик: журнал Xray
L1 = "2026/10/22 15:56:29.283494 from 94.25.1.2:5747 accepted tcp:www.google.com:443 [STEAL-DE7 >> DIRECT] email: user_42"
L2 = "2026/10/22 15:56:30.1 from tcp:[2a00:1fa0:4:5:6:7:8:9]:1234 accepted tcp:x:443 [VLESS >> DIRECT] email: user_9"
L3 = "2026/10/22 15:56:31.2 from 5.6.7.8:1 rejected  proxy/vless/encoding: invalid request user id"
L4 = "2026/10/22 15:56:32.2 from 5.6.7.8:1 accepted tcp:x:443 [api >> api]"
r1 = col.parse_access(L1)
check("журнал: accepted с email — клиент (время UTC)", r1[1:] == ("94.25.1.2", "user_42")
      and r1[0] == dt.datetime(2026, 10, 22, 15, 56, 29, tzinfo=dt.timezone.utc).timestamp())
check("журнал: IPv6 в скобках и с tcp: — сеть /64", col.parse_access(L2)[1] == "2a00:1fa0:4:5::")
check("журнал: отказ проверки и строки без email — не клиенты", col.parse_access(L3) is None and col.parse_access(L4) is None)
with tempfile.TemporaryDirectory() as tmp:
    lg, out = os.path.join(tmp, "access.log"), os.path.join(tmp, "clients.json")
    T0 = dt.datetime(2026, 10, 22, 15, 57, tzinfo=dt.timezone.utc).timestamp()
    open(lg, "w").write(L1 + "\n" + L3 + "\n" + L2 + "\n" + "2026/10/22 15:56:33.0 from 94.25.1.2:9 acc")
    c1 = col.Clients(lg, out)
    c1.read(T0)
    check("журнал: прочитаны два клиента, недописанная строка — потом", set(c1.map) == {"94.25.1.2", "2a00:1fa0:4:5::"}
          and c1.map["94.25.1.2"][2] == 1)
    open(lg, "a").write("epted tcp:x:443 [a >> b] email: user_42\n")
    c1.read(T0)
    check("журнал: дочитан конец строки — счётчик подключений вырос", c1.map["94.25.1.2"][2] == 2)
    c1.save()
    c2 = col.Clients(lg, out)
    check("перезапуск сборщика — продолжает с того же места", c2.pos == c1.pos and c2.map == c1.map)
    c2.read(T0 + 2 * 86400)
    check("через сутки без подключений — уже не клиент", c2.map == {})
    os.rename(lg, lg + ".1")
    open(lg, "w").write(L1 + "\n")
    c2.read(T0)
    check("ротация журнала — новый файл с начала", set(c2.map) == {"94.25.1.2"})
    big = os.path.join(tmp, "big.log")
    open(big, "w").write(("x" * 99 + "\n") * 200000 + L1 + "\n")
    c3 = col.Clients(big, os.path.join(tmp, "c3.json"))
    c3.read(T0)
    size = os.path.getsize(big)
    check("первый запуск — с хвоста журнала (16 МБ), за проход не больше 4 МБ",
          size - col.LOG_FIRST < c3.pos <= size - col.LOG_FIRST + col.LOG_CHUNK and size > col.LOG_FIRST)
    for _ in range(5):
        c3.read(T0)
    check("за несколько проходов дочитан до конца", c3.pos == size and "94.25.1.2" in c3.map)

# --- сторож: пометки в предложении
o = {"host": "DE7", "sh": SH1, "ts": DAY, "attack": None}
txt = TXT(o, {"1.2.3.4": {"user": "user_100000001", "last": DAY - 600, "node": "DE7"}})
check("предложение: наш клиент помечен, с пользователем, нодой и временем",
      "1.2.3.4</code> — 5 000 лишних — ✅ наш клиент (user_100000001, DE7, 10 мин назад)" in txt
      and "5.6.7.8</code> — 1 200 лишних — ❓ не клиент" in txt and "Наших клиентов среди них: 1 из 2" in txt)
check("предложение: сверка не удалась — так и сказано", "сверка с клиентами не удалась" in TXT(o, None))

# --- кнопки и выполнение
kb = b.keyboard("x", "block", "DE7", 2, 1)["inline_keyboard"]
check("кнопки при смеси: «чужих», щит, «всех и наших (1)», не трогать",
      [r[0]["callback_data"] for r in kb] == ["sh:x:b1", "sh:x:on2", "sh:x:b1a", "sh:x:no"]
      and kb[0][0]["text"] == "🛡 Заблокировать чужих на 1 ч" and "наших клиентов (1)" in kb[2][0]["text"])
kb = b.keyboard("x", "block", "DE7", 2, 2)["inline_keyboard"]
check("кнопки, когда все наши: блокировки чужих нет", [r[0]["callback_data"] for r in kb] == ["sh:x:on2", "sh:x:b1a", "sh:x:no"])
check("кнопки без наших — как раньше", b.keyboard("x", "block", "DE7", 2, 0)["inline_keyboard"][0][0]["text"] == "🛡 Заблокировать на 1 ч")
runs = []


def run2(host, args, hs=None):
    runs.append((host, args))
    return {"ok": True, "blocked": [a for a in args[2:] if a != "--clients"], "until": DAY + 3600, "refused": []}


offer = {"host": "DE7", "ips": ["1.2.3.4", "5.6.7.8"], "clients": ["1.2.3.4"]}
b.execute(offer, "b1", run2)
check("«чужих» — наш клиент не попадает в блокировку", runs[-1] == ("DE7", ["block", 3600, "5.6.7.8"]))
b.execute(offer, "b1a", run2)
check("«всех» — с --clients", runs[-1] == ("DE7", ["block", 3600, "--clients", "1.2.3.4", "5.6.7.8"]))
r = b.execute({"host": "DE7", "ips": ["1.2.3.4"], "clients": ["1.2.3.4"]}, "b24", run2)
check("все наши, а нажали «чужих» — ничего не блокируем", not r["ok"] and "наши клиенты" in r["error"])


def ask(host, args, hs=None):
    if host == "DE7":
        return {"ok": True, "clients": {"1.2.3.4": {"user": "u1", "last": 100, "n": 3}}}
    if host == "NL1":
        return {"ok": True, "clients": {"1.2.3.4": {"user": "u1", "last": 500, "n": 1}}}
    return {"ok": False, "error": "timeout"}


HS = {"DE7": {}, "NL1": {}, "ee1": {}}
lc = b.lookup_clients(["1.2.3.4", "5.6.7.8"], HS, ask)
check("сверка по всем нодам — самое свежее", lc == {"1.2.3.4": {"user": "u1", "last": 500, "n": 1, "node": "NL1"}})
check("сверка: никто не ответил — None, не «чужие»", b.lookup_clients(["1.2.3.4"], HS, lambda *a: {"ok": False}) is None)
with tempfile.TemporaryDirectory() as tmp:
    OF = os.path.join(tmp, "o.json")
    tg = TG()
    oid = b.send_offer("DE7", "block", ["1.2.3.4", "5.6.7.8"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY,
                       clients=["1.2.3.4", "9.9.9.9"])
    check("предложение помнит, кто наш (только из этих адресов)", json.load(open(OF))[oid]["clients"] == ["1.2.3.4"])
# ===== улучшения 25.10: одно сообщение на случай, 12 ч с перепроверкой, «Это не атака», итог через 10 минут =====
with tempfile.TemporaryDirectory() as tmp:
    OF = os.path.join(tmp, "inc.json")
    b.DDOS_STATE = os.path.join(tmp, "ddos_state.json")
    b.OVERRIDES_FILE = os.path.join(tmp, "ov.json")
    json.dump({"hosts": {"DE7": {"verdict": "stable"}, "ee1": {"verdict": "attack"}}}, open(b.DDOS_STATE, "w"))
    tg = TG()
    o1 = b.send_incident("DE7", "attack", ["1.2.3.4"], "атака 1", tg=tg, chat=CHAT, offers_path=OF, now=DAY,
                         peak={"rx_bps": 120e6, "rx_pps": 30000})
    kb = tg.calls[-1][1]["reply_markup"]["inline_keyboard"]
    check("сообщение об атаке: блок, щит, «Это не атака», не трогать", tg.calls[-1][0] == "sendMessage"
          and [r[0]["callback_data"] for r in kb] == ["sh:%s:b1" % o1, "sh:%s:on2" % o1, "sh:%s:na" % o1, "sh:%s:no" % o1]
          and "12 часов" in tg.calls[-1][1]["text"])
    o2 = b.send_incident("DE7", "attack", ["1.2.3.4", "5.6.7.8"], "атака 1, обновлено", tg=tg, chat=CHAT, offers_path=OF,
                         now=DAY + 600, peak={"rx_bps": 150e6, "rx_pps": 40000})
    check("повтор в течение часа — правим прежнее сообщение, не шлём новое", tg.calls[-1][0] == "editMessageText"
          and tg.calls[-1][1]["message_id"] == 77 and "Обновлено" in tg.calls[-1][1]["text"]
          and sum(1 for c in tg.calls if c[0] == "sendMessage") == 1)
    runs = []

    def run3(host, args, hs=None):
        if args == ["status"]:
            return {"ok": True, "counters": {"dropped_blocked": 1000 + 250 * len(runs)}, "suspects": []}
        runs.append((host, args))
        return {"ok": True, "blocked": [a for a in args[2:] if a != "--clients"], "until": DAY + 7200, "refused": []}

    def press3(data, now):
        return b.handle({"callback_query": {"id": "q", "from": {"id": int(CHAT)}, "data": data,
                                            "message": {"message_id": 77, "chat": {"id": int(CHAT)}}}},
                        CHAT, tg=tg, run=run3, now=now, offers_path=OF)
    r = press3("sh:%s:b1" % o1, DAY + 700)
    check("кнопка заменённого сообщения — не выполняется", "обновлено" in r and not runs)
    r = press3("sh:%s:b1" % o2, DAY + 600 + 5 * 3600)
    check("нажато через 5 ч, адреса уже не шумят — переспрашивает, не блокирует", "перепроверка" in r and not runs
          and "Всё равно заблокировать?" in tg.calls[-1][1]["text"])
    cid = tg.calls[-1][1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"].split(":")[1]
    press3("sh:%s:y" % cid, DAY + 600 + 5 * 3600 + 30)
    check("«Да, заблокировать» — блокирует то, что предлагалось", runs == [("DE7", ["block", 3600, "1.2.3.4", "5.6.7.8"])])
    check("итог через 10 минут — запланирован", len(json.load(open(OF))["_follow"]) == 1)
    T = DAY + 600 + 5 * 3600 + 30
    check("итог: раньше 10 минут — не шлём", b.process_followups(CHAT, tg=tg, run=run3, now=T + 300, offers_path=OF) == 0)
    n = b.process_followups(CHAT, tg=tg, run=run3, now=T + 601, offers_path=OF)
    check("итог через 10 минут: сколько отрезано и есть ли атака", n == 1 and "Итог блокировки, DE7" in tg.calls[-1][1]["text"]
          and "отрезано 250 пакетов от 2 адресов" in tg.calls[-1][1]["text"] and "атаки на сервере сейчас нет" in tg.calls[-1][1]["text"])
    check("итог — один раз", b.process_followups(CHAT, tg=tg, run=run3, now=T + 900, offers_path=OF) == 0)
    o3 = b.send_incident("ee1", "attack", ["9.9.9.9"], "атака ee1", tg=tg, chat=CHAT, offers_path=OF, now=DAY,
                         peak={"rx_bps": 200e6, "rx_pps": 35744})
    runs.clear()
    press3("sh:%s:b1" % o3, DAY + 3 * 3600)
    check("нажато поздно, но атака ещё идёт — блокирует без переспроса", runs == [("ee1", ["block", 3600, "9.9.9.9"])])
    o4 = b.send_incident("PL1", "attack", [], "атака PL1", tg=tg, chat=CHAT, offers_path=OF, now=DAY,
                         peak={"rx_bps": 120e6, "rx_pps": 25000})
    kb = tg.calls[-1][1]["reply_markup"]["inline_keyboard"]
    check("без названных источников — только щит, «Это не атака», не трогать", [r[0]["callback_data"].split(":")[2] for r in kb] == ["on2", "na", "no"])
    press3("sh:%s:na" % o4, DAY + 100)
    ov = json.load(open(b.OVERRIDES_FILE))
    check("«Это не атака»: порог PL1 = пик ×1,5 на неделю", ov["PL1"]["rx_bps"] == 180e6 and ov["PL1"]["rx_pps"] == 37500
          and ov["PL1"]["until"] == int(DAY + 100 + 7 * 86400))
    check("ответ понятный", "понял, это не атака" in tg.calls[-1][1]["text"] and "180 Мбит/с" in tg.calls[-1][1]["text"])
    o5 = b.send_offer("DE7", "block", ["1.2.3.4"], "т", tg=tg, chat=CHAT, offers_path=OF, now=DAY + 200)
    check("«Это не атака» у предложения без атаки — не принимается", "не для этого" in press3("sh:%s:na" % o5, DAY + 210))
# ===== 25.10: разбор трафика по протоколам/портам и калитка =====
t = s.render(dict(C, gate_tcp=[443], gate_udp=[443], gate_extra=["93.194.30.81"]), "eth0")
check("калитка: порты и свой список", "set gate_tcp { type inet_service; elements = { 443 }; }" in t
      and "93.194.30.81/32" in t.split("set gate4")[1].split("}")[0])
check("калитка — после своих (свои проходят), до блокировок", t.index("ip saddr @allow4 return") < t.index("tcp dport @gate_tcp ip saddr != @gate4")
      < t.index("@blocked4"))
check("калитка и для IPv6", "tcp dport @gate_tcp ip6 saddr != @gate6 counter name gate_dropped drop" in t)
t0 = s.render(C, "eth0")
check("без настройки калитка пустая (ни под что не подходит)", "set gate_tcp { type inet_service; }" in t0)
check("счётчики протоколов — до своих (считаем всё)", t0.index("counter name in_udp") < t0.index("ip saddr @allow4 return"))
check("порты новых соединений", "update @newports { meta l4proto . th dport counter }" in t0)
js = {"nftables": [{"set": {"name": "newports", "elem": [{"elem": {"val": {"concat": ["udp", 443]}, "counter": {"packets": 9000}}},
                                                          {"elem": {"val": {"concat": [6, 22]}, "counter": {"packets": 4}}}]}}]}
check("разбор портов: протокол/порт", s.parse_set(js, "newports") == [("udp/443", 9000), ("tcp/22", 4)])
prev = {}
check("сборщик: первый опрос — скоростей ещё нет", col.proto_rates({"proto": {"tcp": 100, "udp": 50}}, prev, 1000) == {})
check("сборщик: пакеты в секунду по протоколам", col.proto_rates({"proto": {"tcp": 700, "udp": 6050}}, prev, 1060) == {"tcp": 10.0, "udp": 100.0})
check("сборщик: счётчик сбросился (перезагрузка таблицы) — без мусора", col.proto_rates({"proto": {"tcp": 5, "udp": 9000}}, prev, 1120) == {"udp": 49.2})
m_ = {"shield": {"proto_pps": {"udp": 85000, "tcp": 3000, "icmp": 0}, "ports": [["udp/443", 51000], ["tcp/443", 900]]}}
pl = d.proto_line(m_)
check("сообщение: чем бьют — протоколы и порты", "UDP 85 000 пак/с · TCP 3 000 пак/с" in pl and "udp/443 (51 000)" in pl and "ICMP" not in pl)
check("без данных щита — строки нет", d.proto_line({}) == "")


# ===== 1.4.0: =====
class FakeNft:
    """Подставной nft: помнит, режет ли enforce; table=False — таблицы нет (все вызовы падают)."""
    def __init__(self, enforce=False, table=True, fail_flush=False):
        self.enforce, self.table, self.fail_flush, self.calls, self.inputs = enforce, table, fail_flush, [], []

    def __call__(self, args, inp=None):
        self.calls.append(args)
        self.inputs.append(inp)
        if not self.table or (self.fail_flush and args[:1] == ["flush"]):
            raise RuntimeError("nft %s: No such file or directory" % " ".join(args[:3]))
        if args[:2] == ["flush", "chain"] and args[-1] == "enforce":
            self.enforce = False
        if args[:2] == ["add", "rule"] and args[3] == "enforce" and args[-1] == "drop":
            self.enforce = True
        if args[:3] == ["list", "chain", s.TABLE]:
            return "table inet storozh_shield {\n\tchain enforce {\n%s\t}\n}\n" % (
                "\t\tcounter name \"dropped_shield\" drop\n" if self.enforce else "")
        if args[:3] == ["-j", "list", "counters"]:   # таблица текущей версии: с отметкой table_v_…
            return json.dumps({"nftables": [{"counter": {"name": s.table_v_name(), "packets": 0}}]})
        if args[:1] == ["-j"]:
            return '{"nftables": []}'
        return ""


# --- allow через запятую и с запятой в конце не пропадает молча
CA = dict(s.DEFAULTS, allow=["93.184.216.34,", "1.2.3.4, 5.6.7.8", "nl1.example.net"])
check("allow «a,» и «a, b» — адреса свои, блокировать нельзя",
      s.check_block(["93.184.216.34", "1.2.3.4", "5.6.7.8"], CA)[0] == [] and "93.184.216.34" in s.render(CA, "eth0"))
check("мусор в allow виден (имя вместо адреса)", s.allow_bad(CA) == ["nl1.example.net"] and s.allow_bad(C) == [])

# --- IPv6 — отказ, если своя сеть пересекается с блокируемой /64
C6 = dict(s.DEFAULTS, allow=["2a01:4f8:1:2::5", "2a02:9:9::/48", "2a03:7:7:7:1::/80"])
g6, b6 = s.check_block(["2a01:4f8:1:2::77", "2a01:4f8:1:2:aaaa::1", "2a01:4f8:1:3::1", "2a02:9:9:5::1", "2a03:7:7:7::9"], C6)
check("соседний адрес в /64 своего (SLAAC) — отказ; своя /48 и /80 внутри /64 — отказ; другая /64 — можно",
      g6 == ["2a01:4f8:1:3::"] and [x for x, why in b6 if why == "в списке своих"]
      == ["2a01:4f8:1:2::77", "2a01:4f8:1:2:aaaa::1", "2a02:9:9:5::1", "2a03:7:7:7::9"])
check("IPv4 — как раньше, по адресу", s.check_block(["93.184.89.46"], C)[0] == ["93.184.89.46"])

real_nft, real_timer = s.nft, s.tick_timer_state
with tempfile.TemporaryDirectory() as tmp:
    s.STATE_FILE, s.LOG_FILE = os.path.join(tmp, "st.json"), os.path.join(tmp, "log")
    s.CLIENTS_FILE, s.SCANNERS_FILE = os.path.join(tmp, "cl.json"), os.path.join(tmp, "sc.txt")
    s.CONF_FILE = os.path.join(tmp, "config.json")

    # --- истёкший on снимает любая команда, status говорит правду
    s.nft, s.tick_timer_state = FakeNft(enforce=True), lambda: "inactive"
    st = {"mode": "on", "until": s.now() - 30, "blocks": {}}
    r = s.dispatch(["status"], C, st)
    check("status: on истёк, таймер стоит — снят сейчас, режим watch, так и сказано",
          r["mode"] == "watch" and not s.nft.enforce and r["tick"] == "inactive"
          and "on истёк, таймер не работает — снят сейчас" in r["warn"]
          and json.load(open(s.STATE_FILE))["mode"] == "watch" and ["flush", "chain", s.TABLE, "enforce"] in s.nft.calls)
    s.nft = FakeNft(enforce=True)
    st = {"mode": "on", "until": s.now() - 30}
    s.dispatch(["clients", "8.8.8.8"], C, st)
    check("clients: истёкший on тоже снимается", st["mode"] == "watch" and not s.nft.enforce)
    s.nft = FakeNft(enforce=True)
    st = {"mode": "on", "until": s.now() + 3600}
    r = s.dispatch(["status"], C, st)
    check("срок не вышел — режет дальше, предупреждение только про таймер", r["mode"] == "on" and s.nft.enforce
          and r["warn"] == ["таймер tick не работает (inactive)"])
    s.tick_timer_state = lambda: "active"
    s.nft = FakeNft(enforce=True)
    r = s.dispatch(["status"], C, {"mode": "watch", "until": 0})
    check("ядро режет, а по state наблюдение — status показывает on и почему", r["mode"] == "on"
          and r["warn"] == ["в ядре щит режет, а по state watch"])
    s.nft = FakeNft(enforce=True, fail_flush=True)
    st = {"mode": "on", "until": s.now() - 30}
    r = s.dispatch(["status"], C, st)
    check("снять не удалось — status не врёт: on и ошибка", r["mode"] == "on" and st["mode"] == "on"
          and any("снять не удалось" in w for w in r["warn"]))
    s.nft = FakeNft(table=False)
    st = {"mode": "on", "until": s.now() - 30}
    r = s.dispatch(["status"], C, st)
    check("таблицы нет — в state правда (watch), status: не загружен", st["mode"] == "watch" and r["loaded"] is False)
    s.nft = FakeNft(enforce=True)
    st = {"mode": "on", "until": s.now() - 30}
    check("tick снимает истёкший on, как раньше", s.cmd_tick(C, st)["changed"] and st["mode"] == "watch" and not s.nft.enforce)
    s.nft = FakeNft()
    st = {"mode": "on", "until": s.now() - 30}
    r = s.cmd_load(dict(C, iface="eth0"), st)
    check("load: истёкший on — таблица в наблюдении", r["mode"] == "watch" and st["mode"] == "watch"
          and "chain enforce {\n\t}" in s.nft.inputs[0])
    check("таймер спросить нельзя (не Linux) — unknown, без ложной тревоги", real_timer() in ("unknown", "active", "inactive")
          and s.cmd_status(C, {}, False, "")["warn"] == [])
    s.nft = FakeNft(enforce=True)
    r = s.dispatch(["status"], CA, {"mode": "on", "until": s.now() + 600})
    check("status: мусор в allow — в предупреждениях", any("nl1.example.net" in w for w in r["warn"]))

    # --- unblock: в state нет, а в ядре есть; повтор адреса; в state есть, в ядре уже нет
    s.nft = FakeNft()
    st = {"blocks": {}}
    r = s.cmd_unblock(C, st, ["9.9.9.9", "9.9.9.9"])
    check("unblock: блок вне state снят в ядре, повтор — один delete", r["unblocked"] == ["9.9.9.9"]
          and sum(1 for a in s.nft.calls if a[0] == "delete") == 1)

    class NoElem(FakeNft):
        def __call__(self, args, inp=None):
            if args[0] == "delete":
                raise RuntimeError("nft delete element: No such file or directory")
            return FakeNft.__call__(self, args, inp)
    s.nft = NoElem()
    st = {"blocks": {"8.8.8.8": s.now() + 100}}
    r = s.cmd_unblock(C, st, ["8.8.8.8", "7.7.7.7"])
    check("unblock: в ядре элемента уже нет — из state убран, без ошибки; чужой адрес не выдуман",
          r["unblocked"] == ["8.8.8.8"] and st["blocks"] == {})

    # --- блокировка на всё время команды
    held = set()

    def flock(fd, op):
        if op & 4 and "busy" in held:
            raise BlockingIOError(11, "Resource temporarily unavailable")
    lk = os.path.join(tmp, "lock", "shield.lock")
    fd = s.lock(lk, wait=1, flock=flock)
    check("блокировка взята, файл создан", isinstance(fd, int) and os.path.exists(lk))
    os.close(fd)
    held.add("busy")
    t0 = s.time.monotonic()
    try:
        s.lock(lk, wait=0.5, flock=flock)
        check("занято дольше срока — понятная ошибка", False)
    except s.Busy as e:
        check("занято дольше срока — понятная ошибка", "занят другой командой" in str(e) and s.time.monotonic() - t0 >= 0.5)
    n = [0]

    def flock2(fd, op):
        n[0] += 1
        if n[0] < 3:
            raise BlockingIOError(11, "busy")
    fd = s.lock(lk, wait=5, flock=flock2)
    check("соседняя команда закончила — ждём и берём", isinstance(fd, int) and n[0] == 3)
    os.close(fd)

    def flock_bad(fd, op):
        raise OSError(9, "Bad file descriptor")
    try:
        s.lock(lk, wait=5, flock=flock_bad)
        check("другая ошибка flock — не ждём, сразу наружу", False)
    except OSError as e:
        check("другая ошибка flock — не ждём, сразу наружу", e.errno == 9 and not isinstance(e, s.Busy))

    # main: state читается только после блокировки — запись соседа, сделанная пока ждали, не теряется
    s.nft = FakeNft()
    json.dump({"blocks": {}}, open(s.STATE_FILE, "w"))
    order = []

    def lock_wait(*a, **k):
        order.append("lock")
        json.dump({"blocks": {"9.9.9.9": s.now() + 3000}, "mode": "on", "until": s.now() + 3000}, open(s.STATE_FILE, "w"))
        fd_ = os.open(os.path.join(tmp, "l2"), os.O_RDWR | os.O_CREAT)
        order.append(fd_)
        return fd_
    real_lock = s.lock
    s.lock = lock_wait
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = s.main(["block", "3600", "8.8.8.8"])
    stj = json.load(open(s.STATE_FILE))
    check("main: блок соседа (записан, пока ждали) и режим on сохранены рядом с новым",
          rc == 0 and set(stj["blocks"]) == {"9.9.9.9", "8.8.8.8"} and stj["mode"] == "on")
    try:
        os.fstat(order[1])
        closed = False
    except OSError:
        closed = True
    check("main: блокировка снята после команды", closed)

    def lock_busy(*a, **k):
        raise s.Busy("щит занят другой командой дольше 30 с — повторите позже")
    s.lock = lock_busy
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = s.main(["block", "3600", "1.1.1.1"])
    out = json.loads(buf.getvalue())
    check("main: занято — ok false, понятная ошибка, state не тронут", rc == 1 and "занят" in out["error"]
          and "1.1.1.1" not in json.load(open(s.STATE_FILE))["blocks"])
    s.lock = real_lock
    check("на Windows (нет fcntl) блокировка — пустая", s.fcntl is not None or s.lock(lk) is None)
    if s.fcntl is not None:   # Linux: настоящий flock — второй вызов ждёт и получает Busy, после снятия — берёт
        fd1 = s.lock(lk, wait=1)
        try:
            s.lock(lk, wait=0.3)
            check("настоящий flock: занято — Busy", False)
        except s.Busy:
            check("настоящий flock: занято — Busy", True)
        os.close(fd1)
        fd2 = s.lock(lk, wait=1)
        check("настоящий flock: снята — берётся", isinstance(fd2, int))
        os.close(fd2)
s.nft, s.tick_timer_state = real_nft, real_timer

# ===== партия 2: stdin до блокировки, status без долгой блокировки, «таблицы нет» ≠ сбой nft, table_v =====
import contextlib  # noqa: E402
import io  # noqa: E402


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = s.main(argv)
    return rc, json.loads(buf.getvalue())


class Stdin:
    """Подставной stdin: отмечает в order, когда его читали."""
    def __init__(self, order, text):
        self.order, self.text = order, text

    def read(self, n=-1):
        self.order.append(("stdin", n))
        return self.text


real_lock, real_unlock, real_stdin = s.lock, s.unlock, sys.stdin
with tempfile.TemporaryDirectory() as tmp:
    s.STATE_FILE, s.LOG_FILE = os.path.join(tmp, "st.json"), os.path.join(tmp, "log")
    s.CLIENTS_FILE, s.SCANNERS_FILE = os.path.join(tmp, "cl.json"), os.path.join(tmp, "sc.txt")
    s.tick_timer_state = lambda: "active"
    order = []

    def lock_rec(*a, **k):
        order.append("lock")
        return os.open(os.path.join(tmp, "lk"), os.O_RDWR | os.O_CREAT)

    def unlock_rec(fd):
        if fd is not None:
            order.append("unlock")
            os.close(fd)

    class OrderNft(FakeNft):
        def __call__(self, args, inp=None):
            order.append(("nft",) + tuple(args[:3]))
            return FakeNft.__call__(self, args, inp)
    s.lock, s.unlock = lock_rec, unlock_rec

    # 1) scanners-load: stdin читается ДО блокировки, под ней — разбор, nft и запись файла
    s.nft = OrderNft()
    sys.stdin = Stdin(order, "1.2.3.0/24\n2a00:1::/32\n")
    rc, out = run_main(["scanners-load"])
    nft_f = [i for i, x in enumerate(order) if x == ("nft", "-f", "-")]
    check("scanners-load: stdin прочитан до блокировки, с пределом размера; nft под блокировкой; файл записан",
          rc == 0 and out["v4"] == 1 and order[0] == ("stdin", s.STDIN_MAX) and order.index("lock") == 1
          and nft_f and order.index("lock") < nft_f[0] < order.index("unlock")
          and open(s.SCANNERS_FILE, encoding="utf-8").read() == "1.2.3.0/24\n2a00:1::/32\n")
    order.clear()
    os.environ["SSH_ORIGINAL_COMMAND"] = "scanners-load"
    rc, out = run_main(["--ssh"])
    check("scanners-load по SSH: тоже stdin до блокировки", rc == 0 and order[0] == ("stdin", s.STDIN_MAX)
          and order.index("lock") == 1)
    del os.environ["SSH_ORIGINAL_COMMAND"]
    order.clear()
    rc, out = run_main(["block", "3600", "8.8.8.8"])
    check("прочие команды stdin не читают", rc == 0 and not any(isinstance(x, tuple) and x[0] == "stdin" for x in order))
    try:
        s.dispatch(["scanners-load"], C, {})
        check("dispatch scanners-load без списка — отказ, stdin под блокировкой не читается", False)
    except ValueError as e:
        check("dispatch scanners-load без списка — отказ, stdin под блокировкой не читается", "не передан" in str(e))
    sys.stdin = Stdin(order, "")   # status и прочие не должны его трогать

    # 2) status: под блокировкой только снятие истёкшего on (и запись state), nft list и сбор сведений — без неё
    json.dump({"mode": "on", "until": s.now() - 30, "blocks": {}}, open(s.STATE_FILE, "w"))
    s.nft = OrderNft(enforce=True)
    order.clear()
    rc, out = run_main(["status"])
    un = order.index("unlock")
    flush = order.index(("nft", "flush", "chain", s.TABLE))
    lists = [i for i, x in enumerate(order) if isinstance(x, tuple) and x[0] == "nft" and "list" in x]
    check("status: истёкший on снят под блокировкой, state записан",
          rc == 0 and order[0] == "lock" and flush < un and out["mode"] == "watch"
          and json.load(open(s.STATE_FILE))["mode"] == "watch" and "on истёк — снят сейчас" in out["warn"])
    check("status: все nft list — после снятия блокировки", lists and min(lists) > un and order.count("unlock") == 1)
    order.clear()
    rc, out = run_main(["status"])
    check("status: on не истёк — блокировка только на чтение state, nft под ней не зовётся",
          rc == 0 and order[:2] == ["lock", "unlock"] and all(x not in ("lock", "unlock") for x in order[2:])
          and not any(isinstance(x, tuple) and x[0] == "stdin" for x in order))
    order.clear()
    rc, out = run_main(["mode", "on", "1"])
    check("прочие команды (mode) держат блокировку всё время: nft — между lock и unlock",
          rc == 0 and order[0] == "lock" and order[-1] == "unlock"
          and all(isinstance(x, tuple) for x in order[1:-1]) and len(order) > 2)

    # 4) expire_on: «таблицы нет» отличается от прочих сбоев nft
    s.lock, s.unlock = real_lock, real_unlock
    calls_ts = []

    def nft_ts(err):
        def f(args, inp=None):
            calls_ts.append(args)
            if err:
                raise RuntimeError(err)
            return ""
        return f
    s.nft = nft_ts(None)
    check("table_state: есть — True, спрашивает nft -t list table (без элементов наборов)",
          s.table_state() is True and calls_ts[-1] == ["-t", "list", "table", s.TABLE])
    s.nft = nft_ts("nft -t list table: Error: No such file or directory; did you mean table ‘x’ in family ip?")
    check("table_state: «No such file or directory» — таблицы нет", s.table_state() is False)
    s.nft = nft_ts("nft -t list table: нет ответа 30 с")
    check("table_state: иной сбой nft — неизвестно (None)", s.table_state() is None)

    class Flaky(FakeNft):
        """Таблица есть, но nft сбоит: снять не вышло, и list table — не «No such file»."""
        def __call__(self, args, inp=None):
            self.calls.append(args)
            if args[:1] in (["flush"], ["-t"]):
                raise RuntimeError("nft %s: нет ответа 30 с" % " ".join(args[:3]))
            return FakeNft.__call__(self, args, inp)
    s.nft = Flaky(enforce=True)
    json.dump({"mode": "on", "until": s.now() - 30}, open(s.STATE_FILE, "w"))
    st = {"mode": "on", "until": s.now() - 30}
    r = s.dispatch(["status"], C, st)
    check("expire_on: прочий сбой nft — state не тронут (on), ошибка в status.warn",
          st["mode"] == "on" and json.load(open(s.STATE_FILE))["mode"] == "on" and r["mode"] == "on"
          and any("снять не удалось" in w and "нет ответа" in w for w in r["warn"])
          and ["-t", "list", "table", s.TABLE] in s.nft.calls)
    class Flaky2(Flaky):
        """Сбоит и nft list chain (раньше по нему решали, что таблицы нет)."""
        def __call__(self, args, inp=None):
            if args[:2] == ["list", "chain"]:
                raise RuntimeError("nft list chain inet: нет ответа 30 с")
            return Flaky.__call__(self, args, inp)
    s.nft = Flaky2(enforce=True)
    json.dump({"mode": "on", "until": s.now() - 30}, open(s.STATE_FILE, "w"))
    st = {"mode": "on", "until": s.now() - 30}
    r = s.dispatch(["status"], C, st)
    check("expire_on: сбоит и list chain — всё равно не «таблицы нет»: state on, ошибка в warn",
          st["mode"] == "on" and json.load(open(s.STATE_FILE))["mode"] == "on"
          and any("снять не удалось" in w for w in r["warn"]))
    s.nft = FakeNft(table=False)
    st = {"mode": "on", "until": s.now() - 30}
    s.dispatch(["clients", "8.8.8.8"], C, st)
    check("expire_on: таблицы нет (No such file or directory) — state watch, как раньше",
          st["mode"] == "watch" and json.load(open(s.STATE_FILE))["mode"] == "watch")
    real_run = s.subprocess.run

    def run_timeout(*a, **k):
        raise s.subprocess.TimeoutExpired(a[0], 30)
    s.subprocess.run = run_timeout
    try:
        NFT_REAL(["list", "chain", s.TABLE, "enforce"])
        check("nft: таймаут — RuntimeError (обычный сбой nft, команда не падает мимо обработчиков)", False)
    except RuntimeError as e:
        check("nft: таймаут — RuntimeError (обычный сбой nft, команда не падает мимо обработчиков)", "нет ответа" in str(e))
    finally:
        s.subprocess.run = real_run

    # 5) table_v: версия таблицы в ядре по счётчику-отметке
    t5 = s.render(C, "eth0")
    check("render: счётчик-отметка версии таблицы", "counter %s { }" % s.table_v_name() in t5
          and s.table_v_name() == "table_v_" + s.VERSION.replace(".", "_"))
    s.nft = FakeNft()
    r = s.cmd_status(C, {}, False, "")
    check("status: table_v — версия таблицы в ядре, совпадает с кодом; отметки нет среди счётчиков; без предупреждения",
          r["table_v"] == s.VERSION and r["v"] == s.VERSION and not any(k.startswith("table_v_") for k in r["counters"])
          and r["warn"] == [])

    class OldTable(FakeNft):
        def __call__(self, args, inp=None):
            if args[:3] == ["-j", "list", "counters"]:   # таблица прежней версии: отметки нет
                return json.dumps({"nftables": [{"counter": {"name": "scan_hits", "packets": 7}}]})
            return FakeNft.__call__(self, args, inp)
    s.nft = OldTable()
    r = s.cmd_status(C, {}, False, "")
    check("status: таблица старой версии (без отметки) — table_v пусто и предупреждение «не пересоздана»",
          r["table_v"] == "" and r["counters"] == {"scan_hits": 7}
          and any("не пересоздана" in w and "без отметки версии" in w for w in r["warn"]))

    class NewerTable(FakeNft):
        def __call__(self, args, inp=None):
            if args[:3] == ["-j", "list", "counters"]:
                return json.dumps({"nftables": [{"counter": {"name": s.table_v_name("1.3.9"), "packets": 0}}]})
            return FakeNft.__call__(self, args, inp)
    s.nft = NewerTable()
    r = s.cmd_status(C, {}, False, "")
    check("status: таблица другой версии — table_v её номер и предупреждение", r["table_v"] == "1.3.9"
          and any("таблица в ядре 1.3.9" in w for w in r["warn"]))

    class NoCounters(FakeNft):
        def __call__(self, args, inp=None):
            if args[:3] == ["-j", "list", "counters"]:
                raise RuntimeError("nft -j list counters: нет ответа 30 с")
            return FakeNft.__call__(self, args, inp)
    s.nft = NoCounters()
    r = s.cmd_status(C, {}, False, "")
    check("status: счётчики не прочитались — table_v неизвестна (None), ложной тревоги нет",
          r["table_v"] is None and r["warn"] == [])
sys.stdin = real_stdin
s.lock, s.unlock = real_lock, real_unlock
s.nft, s.tick_timer_state = real_nft, real_timer
print("щит: тестов пройдено %d" % ok)
