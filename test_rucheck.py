"""Тесты сверки шаблона с блокировками в России (rucheck.py), без сети: python test_rucheck.py"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rucheck as rc  # noqa: E402

ok = 0


def check(cond, what):
    global ok
    assert cond, what
    ok += 1


# --- геобазы: минимальные geosite.dat / geoip.dat в формате protobuf
def vint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def fld(num, data):
    return vint(num << 3 | 2) + vint(len(data)) + data


def dom(t, v):
    return vint(1 << 3 | 0) + vint(t) + fld(2, v.encode())


site = fld(1, fld(1, b"YOUTUBE") + fld(2, dom(2, "youtube.com")) + fld(2, dom(2, "googlevideo.com"))) \
    + fld(1, fld(1, b"CATEGORY-RU") + fld(2, dom(2, "vk.com")) + fld(2, dom(3, "ya.ru")) + fld(2, dom(1, r"\.gov\.ru$"))) \
    + fld(1, fld(1, b"OTHER") + fld(2, dom(0, "zzz")))
cidr = lambda ip, p: fld(1, bytes(int(x) for x in ip.split("."))) + vint(2 << 3 | 0) + vint(p)
geoip = fld(1, fld(1, b"RU") + fld(2, cidr("5.255.0.0", 16))) + fld(1, fld(1, b"PRIVATE") + fld(2, cidr("10.0.0.0", 8)))
tmp = tempfile.mkdtemp()
open(os.path.join(tmp, "geosite.dat"), "wb").write(site)
open(os.path.join(tmp, "geoip.dat"), "wb").write(geoip)
geo = rc.Geo(tmp)
check(geo.site_match("youtube", "www.youtube.com") and geo.site_match("youtube", "googlevideo.com")
      and not geo.site_match("youtube", "notyoutube.com") and geo.site_match("category-ru", "ya.ru")
      and not geo.site_match("category-ru", "www.ya.ru") and geo.site_match("category-ru", "www.nalog.gov.ru")
      and geo.site_match("other", "abzzzc.com") and geo.site_match("nope", "x.com") is None,
      "R1 geosite: domain (с поддоменами), full, regexp, keyword; неизвестная категория — None")
check(geo.ip_match("ru", "5.255.255.70") and not geo.ip_match("ru", "8.8.8.8") and geo.ip_match("private", "10.1.2.3")
      and geo.ip_match("cn", "1.1.1.1") is None, "R2 geoip: адрес в категории; неизвестная — None")
check(rc.Geo(os.path.join(tmp, "нет")).site_match("youtube", "youtube.com") is None, "R3 геобаз нет — None, без ошибки")

# --- маршрут по правилам шаблона
cfg = {"outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"},
                     {"tag": "block", "protocol": "blackhole"}],
       "routing": {"domainStrategy": "IPIfNonMatch", "balancers": [{"tag": "SMART"}], "rules": [
           {"type": "field", "inboundTag": ["dns-in"], "outboundTag": "direct"},
           {"type": "field", "port": "443", "network": "udp", "domain": ["domain:youtube.com"], "outboundTag": "block"},
           {"type": "field", "domain": ["geosite:category-ru", "regexp:\\.su$"], "outboundTag": "direct"},
           {"type": "field", "domain": ["domain:instagram.com", "full:x.com"], "balancerTag": "SMART"},
           {"type": "field", "domain": ["wechat"], "outboundTag": "direct"},
           {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
           {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}]}}
R = lambda h, ips=(): rc.route(cfg, h, list(ips), geo)
check(R("vk.com") == "direct" and R("www.nalog.gov.ru") == "direct" and R("site.su") == "direct",
      "R4 geosite и regexp → напрямую")
check(R("www.youtube.com") == "proxy", "R5 правило UDP 443 к TCP-проверке не относится — дальше, в общий VPN")
check(R("www.instagram.com") == "proxy" and R("x.com") == "proxy" and R("api.x.com") == "proxy",
      "R6 балансировщик — через VPN; full только точное имя (поддомен — общим правилом)")
check(R("web.wechat.com") == "direct", "R7 строка без приставки — подстрока (keyword)")
# как в Xray: при IPIfNonMatch сначала все правила без адресов; общее правило «network» в конце срабатывает раньше
# правила по адресу — поэтому для проверки адресов шаблон без общего правила
noall = dict(cfg, routing=dict(cfg["routing"], rules=cfg["routing"]["rules"][:-1]))
R2 = lambda h, ips=(): rc.route(noall, h, list(ips), geo)
check(R2("yandex.example", ["5.255.255.70"]) == "direct" and R2("foreign.example", ["8.8.8.8"]) == "proxy"
      and R("yandex.example", ["5.255.255.70"]) == "proxy",
      "R8 IPIfNonMatch: домен не совпал — правило по адресу (geoip:ru) срабатывает по адресам; общее правило — раньше")
asis = dict(noall, routing=dict(noall["routing"], domainStrategy="AsIs"))
check(rc.route(asis, "yandex.example", ["5.255.255.70"], geo) == "proxy", "R9 AsIs: правила по адресам к доменам не применяются")
blk = {"outbounds": cfg["outbounds"], "routing": {"rules": [{"type": "field", "domain": ["domain:bad.com"], "outboundTag": "block"}]}}
check(rc.route(blk, "a.bad.com", [], geo) == "block" and rc.route(blk, "ok.com", [], geo) == "proxy",
      "R10 блок; ни одно правило не подошло — первый выход (как в Xray)")
check(rc.route(dict(cfg, routing=dict(cfg["routing"], rules=[{"type": "field", "domain": ["geosite:nope"],
                                                              "outboundTag": "direct"}])), "x.com", [], geo) == "proxy",
      "R11 неизвестная категория geosite не совпадает")

# --- проверка сервиса по слоям (подмена сети)
class Net:
    def __init__(self, sys_ips=("1.1.1.1",), doh=("1.1.1.1",), tcp="ok", tls="ok", http=(200, b"<html>hi</html>")):
        self.sys_ips, self.doh_ips, self.tcp, self.tls, self.http = list(sys_ips), list(doh), tcp, tls, http

    def resolve(self, host):
        return self.sys_ips

    def doh(self, host):
        return self.doh_ips

    def connect(self, ip, port, timeout):
        return self.tcp

    def handshake(self, ip, host, timeout):
        return self.tls

    def get(self, ip, host, timeout):
        return self.http


V = lambda **kw: rc.probe_service("svc.example", net=Net(**kw))["verdict"]
check(V() == "OK" and V(http=(403, b"forbidden")) == "OK", "R12 открылся (любой код, кроме заглушки) — OK")
check(V(sys_ips=()) == "DNS_BLOCK" and V(sys_ips=("127.0.0.1",), doh=("1.1.1.1",)) == "DNS_BLOCK",
      "R13 обычный DNS молчит или отдаёт частный адрес, защищённый — настоящий: подмена DNS")
check(V(sys_ips=("2.2.2.2",), doh=("1.1.1.1",)) == "OK", "R14 разные публичные адреса (CDN) — не подмена")
check(V(tcp="timeout") == "TCP_TIMEOUT" and V(tcp="reset") == "TCP_RESET", "R15 TCP: молчит / сброс")
check(V(tls="reset") == "TLS_BLOCK" and V(tls="timeout") == "TLS_BLOCK", "R16 TCP есть, TLS рвётся — блокировка по имени (DPI)")
check(V(http=(451, b"")) == "HTTP_STUB"
      and V(http=(200, "<p>Доступ к ресурсу ограничен на основании Федерального закона</p>".encode())) == "HTTP_STUB"
      and V(http=(302, b"Location: http://warning.rt.ru/?id=1")) == "HTTP_STUB", "R17 451 и страницы-заглушки")
check(V(sys_ips=(), doh=()) == "DOWN", "R18 имени нет ни в одном DNS — не блокировка, сервис недоступен")
class Net2(Net):
    def connect(self, ip, port, timeout):
        self.tried = getattr(self, "tried", []) + [ip]
        return "ok" if ip == "2.2.2.2" else "timeout"


n2 = Net2(sys_ips=("3.3.3.3", "2.2.2.2"), doh=("4.4.4.4",))
check(rc.probe_service("svc.example", net=n2)["verdict"] == "OK" and n2.tried == ["3.3.3.3", "2.2.2.2"],
      "R27 сначала адреса обычного DNS; один молчащий адрес — пробуем следующий")
n3 = Net2(sys_ips=("3.3.3.3",), doh=("4.4.4.4", "5.5.5.5", "6.6.6.6"))
check(rc.probe_service("svc.example", net=n3)["verdict"] == "TCP_TIMEOUT" and n3.tried == ["3.3.3.3", "4.4.4.4", "5.5.5.5"],
      "R28 не больше трёх адресов; все молчат — TCP_TIMEOUT")
check(rc.blocked("TLS_BLOCK") and rc.blocked("HTTP_STUB") and not rc.blocked("OK") and not rc.blocked("DOWN"),
      "R19 что считаем блокировкой")

# --- сверка: шаблоны × сервисы
tiles = [dict(cfg, remarks="🇪🇺 AUTO"), dict(cfg, remarks="🇩🇪 DE2"),
         dict(cfg, remarks="🌍 Я за границей", routing=dict(cfg["routing"], rules=[{"type": "field", "network": "tcp,udp",
                                                                                      "outboundTag": "direct"}]))]
verd = {"www.instagram.com": {"verdict": "TLS_BLOCK"}, "vk.com": {"verdict": "OK"}, "web.wechat.com": {"verdict": "TCP_TIMEOUT"}}
res = rc.compare(tiles, verd, geo, resolve=lambda h: [])
check([t["tiles"] for t in res["templates"]] == [["🇪🇺 AUTO", "🇩🇪 DE2"], ["🌍 Я за границей"]],
      "R20 одинаковые правила — один шаблон, плитки списком")
check(res["mismatch"] == [{"template": "🇪🇺 AUTO", "host": "web.wechat.com", "verdict": "TCP_TIMEOUT"}],
      "R21 расхождение: напрямую, а из России закрыт; «Я за границей» (всё напрямую) — не расхождение: это плитка для заграницы")
# --- состояние, тревоги и отчёт
st = {}
data = {"ts": 100, "services": verd, "templates": res["templates"], "mismatch": res["mismatch"]}
a1 = rc.step(st, data)
check(len(a1) == 1 and "web.wechat.com" in a1[0] and "напрямую" in a1[0] and "🇪🇺 AUTO" in a1[0], "R22 новое расхождение — тревога")
check(rc.step(st, dict(data, ts=200)) == [], "R23 то же расхождение — без повтора")
a3 = rc.step(st, dict(data, ts=300, mismatch=[]))
check(len(a3) == 1 and "web.wechat.com" in a3[0] and "✅" in a3[0], "R24 расхождение ушло — сообщение о норме")
parts = rc.items(st)
check(any("закрыто 2 из 3 зарубежных" in p for p in parts) and any("расхождений с шаблоном нет" in p for p in parts),
      "R25 строка отчёта: сколько сервисов закрыто и есть ли расхождения")
check(rc.items({}) == [], "R26 сверки ещё не было — строк нет")
vl = dict(verd, **{"www.gosuslugi.ru": {"verdict": "TCP_TIMEOUT", "local": True}})
cfg_ru = dict(cfg, remarks="🇪🇺 AUTO")
check(rc.compare([cfg_ru], {"www.gosuslugi.ru": vl["www.gosuslugi.ru"]}, geo, resolve=lambda h: [])["mismatch"] == [],
      "R29 российский сервис (часто не пускает хостинги) — не расхождение")
st2 = {}
rc.step(st2, {"ts": 1, "services": vl, "mismatch": []})
p2 = rc.items(st2)
check(any("закрыто 2 из 3 зарубежных" in p for p in p2) and any("российские не открылись" in p and "gosuslugi" in p for p in p2),
      "R30 российские — отдельной строкой, в счёт зарубежных не входят")
d = tempfile.mkdtemp()
open(os.path.join(d, "s.json"), "w").write('{"local": ["a.ru"]}')
fr, lo = rc.services_list(os.path.join(d, "s.json"))
check(lo == ["a.ru"] and fr == list(rc.SERVICES) and rc.services_list(os.path.join(d, "нет")) == (list(rc.SERVICES), list(rc.LOCAL)),
      "R31 свой файл заменяет списки по отдельности; файла нет — по умолчанию")
# --- проверка с точки у обычного провайдера, сервер сторожа — запасной
asked = []
office = {"name": "Точка Б", "url": "x", "token": "t", "rucheck": True}
good = lambda a, hosts: asked.append(a["name"]) or {h: {"verdict": "TCP_TIMEOUT" if h == "x.com" else "OK"} for h in hosts}
r1 = rc.run_live([], geo_dir=tmp, services=(["x.com"], ["vk.com"]), net=Net(), points=[office], ask=good)
check(r1["source"] == "Точка Б" and r1["services"]["x.com"]["verdict"] == "TCP_TIMEOUT" and r1["services"]["vk.com"]["local"]
      and asked == ["Точка Б"], "R32 сервисы проверяются с точки, российские отмечаются")
r2 = rc.run_live([], geo_dir=tmp, services=(["x.com"], []), net=Net(), points=[office], ask=lambda a, h: None)
check(r2["source"] is None and r2["missed"] == ["Точка Б"] and r2["services"]["x.com"]["verdict"] == "OK",
      "R33 точка не ответила — проверка с сервера сторожа")
st3 = {}
rc.step(st3, r2)
check(any("не ответила" in p for p in rc.items(st3)) and any(p.startswith("с сервера сторожа") for p in rc.items(st3)),
      "R34 в отчёте видно, откуда проверено и что точка молчит")
st4 = {}
rc.step(st4, r1)
check(any(p.startswith("с точки «Точка Б» закрыто 1 из 1") for p in rc.items(st4)), "R35 в отчёте — точка, с которой проверено")
print("rucheck: тестов пройдено %d" % ok)
