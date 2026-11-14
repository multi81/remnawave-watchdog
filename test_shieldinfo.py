"""Тесты: сообщение щита — сервер и адрес, куда бьют, сведения об адресах; бот кнопок — чужой опрос. Без сети."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ddoswatch as d  # noqa: E402
import shieldbot as b  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


tmp = tempfile.mkdtemp()
d.IPINFO_CACHE = os.path.join(tmp, "ipinfo.json")
asked = []
FAKE = {"5.6.7.8": {"as": "AS12389", "net": "Rostelecom", "country": "RU", "city": "Moscow", "mobile": True},
        "9.9.1.5": {"as": "AS14061", "net": "DigitalOcean", "country": "NL", "city": "Amsterdam", "hosting": True}}
d.IPINFO_LOOKUP = lambda ips: asked.append(list(ips)) or {a: FAKE[a] for a in ips if a in FAKE}
sd = os.path.join(tmp, "scan")
os.makedirs(sd)
open(os.path.join(sd, "skipa.list"), "w").write("9.9.1.0/24\n")
d.SCAN_DIR = sd

d.HOST_INFO.update({"бот": ("203.0.113.5", "бот подписок")})
check("S1 сервер: имя, адрес и пометка", d.server_label("бот") == "бот · 203.0.113.5 · бот подписок"
      and d.server_label("nl1") == "nl1")
info = d.ip_details(["5.6.7.8", "9.9.1.5", "1.1.1.1"], now=1000)
check("S2 сведения об адресах; кого не нашли — нет", set(info) == {"5.6.7.8", "9.9.1.5"} and asked == [["5.6.7.8", "9.9.1.5", "1.1.1.1"]])
d.ip_details(["5.6.7.8"], now=2000)
check("S3 кеш на неделю — повторно не спрашиваем", len(asked) == 1)
d.ip_details(["5.6.7.8"], now=1000 + d.IPINFO_TTL + 1)
check("S4 через неделю — спрашиваем снова", len(asked) == 2)
check("S5 списки сканеров", d.scan_membership(["9.9.1.5", "5.6.7.8"]) == {"9.9.1.5": "СКИПА (РКН)"})
ln = d.ip_line(FAKE["5.6.7.8"])
check("S6 строка об адресе: сеть, место, мобильная сеть", "AS12389 Rostelecom" in ln and "RU Moscow" in ln and "мобильная сеть" in ln)
check("S7 хостинг и сканеры", "хостинг" in d.ip_line(FAKE["9.9.1.5"], "СКИПА (РКН)") and "в списке сканеров: СКИПА" in d.ip_line({}, "СКИПА (РКН)")
      and d.ip_line(None) == "")
sh = {"limits": {"rate": 200}, "mode": "watch", "suspects": [["5.6.7.8", 900], ["9.9.1.5", 400]], "suspects_total": 2,
      "ports": [["tcp/443", 21362], ["tcp/22", 98]]}
t = d.shield_offer_text("бот", sh, 1000, clients={})
check("S8 предложение щита: строка сервера с адресом, куда бьют, сведения под каждым адресом",
      "🖥 <b>Сервер:</b> бот · 203.0.113.5 · бот подписок" in t and "tcp/443 (21 362)" in t
      and "Rostelecom" in t and "DigitalOcean" in t and "в списке сканеров: СКИПА (РКН)" in t)
blk = d.suspects_block(sh, 1000, clients={})
check("S9 сообщение об атаке: те же сведения и порты", "Rostelecom" in blk and "Куда бьют" in blk)

st = {}
r409 = {"ok": False, "error_code": 409, "description": "Conflict: terminated by other getUpdates request"}
check("S10 первый конфликт — молчим", b.conflict_step(st, r409, 100) is None)
check("S11 конфликт меньше 10 минут — молчим", b.conflict_step(st, r409, 100 + 500) is None)
m = b.conflict_step(st, r409, 100 + 601)
check("S12 конфликт 10 минут — сообщение с подсказкой", m and "Кнопки щита могут не срабатывать" in m and "BotFather" in m)
check("S13 повтор не чаще раза в 6 часов", b.conflict_step(st, r409, 100 + 700) is None)
check("S14 опрос снова удачный — «снова доходят»", "снова доходят" in (b.conflict_step(st, {"ok": True, "result": []}, 800) or "")
      and st == {})
check("S15 удачный опрос без тревоги — без сообщения", b.conflict_step({}, {"ok": True}, 900) is None
      and b.conflict_step({"since": 1}, {"ok": True}, 900) is None)
print("щит, сведения: тестов пройдено %d" % ok)
