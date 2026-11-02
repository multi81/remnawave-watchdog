"""Тесты щита без сети и без nft: python test_shield.py"""
import datetime as dt
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddos_collect as col  # noqa: E402
import ddoswatch as d  # noqa: E402
import shield_ctl as s  # noqa: E402
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
check("полигон: allow_private=false — частные можно", s.check_block(["172.16.0.128"], dict(C, allow_private=False))[0] == ["172.16.0.128"])

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
    {"elem": {"val": "172.16.0.128", "timeout": 600, "expires": 590, "counter": {"packets": 207, "bytes": 1}}},
    {"elem": {"val": "1.2.3.4", "counter": {"packets": 5, "bytes": 1}}}]}}]}
check("разбор подозрительных со счётчиком", s.parse_set(js, "suspects4") == [("172.16.0.128", 207), ("1.2.3.4", 5)])
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
CL = {"8.8.8.8": [1000, "user_380", 5], "2a03:1:2:3::": [1000, "user_9", 1]}
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
          and r["clients"]["8.8.8.8"]["user"] == "user_380" and r["known"] == 2)
    check("ssh: clients разрешена, --clients проходит", s.ssh_argv("clients 1.2.3.4") == ["clients", "1.2.3.4"]
          and s.ssh_argv("block 3600 --clients 1.2.3.4")[2] == "--clients")
    tx = s.clients_nft(CL)
    check("набор клиентов — одной транзакцией заново", tx.startswith("flush set inet storozh_shield clients4\nflush set inet storozh_shield clients6\n")
          and "add element inet storozh_shield clients4 { 8.8.8.8 }" in tx and "clients6 { 2a03:1:2:3:: }" in tx)

# --- сборщик: журнал Xray
L1 = "2026/10/22 15:56:29.283494 from 94.25.1.2:5747 accepted tcp:www.google.com:443 [STEAL-DE7 >> DIRECT] email: user_380"
L2 = "2026/10/22 15:56:30.1 from tcp:[2a00:1fa0:4:5:6:7:8:9]:1234 accepted tcp:x:443 [VLESS >> DIRECT] email: user_9"
L3 = "2026/10/22 15:56:31.2 from 5.6.7.8:1 rejected  proxy/vless/encoding: invalid request user id"
L4 = "2026/10/22 15:56:32.2 from 5.6.7.8:1 accepted tcp:x:443 [api >> api]"
r1 = col.parse_access(L1)
check("журнал: accepted с email — клиент (время UTC)", r1[1:] == ("94.25.1.2", "user_380")
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
    open(lg, "a").write("epted tcp:x:443 [a >> b] email: user_380\n")
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
txt = TXT(o, {"1.2.3.4": {"user": "user_380424819", "last": DAY - 600, "node": "DE7"}})
check("предложение: наш клиент помечен, с пользователем, нодой и временем",
      "1.2.3.4</code> — 5 000 лишних — ✅ наш клиент (user_380424819, DE7, 10 мин назад)" in txt
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
print("щит: тестов пройдено %d" % ok)
