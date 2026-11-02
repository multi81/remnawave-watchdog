"""channel-watch: серверы глазами сторожа — часть probe.py, вынесенная в отдельный файл.

1. Маячки нод (node_beacon.py на каждой ноде): диск, память, версии, файрвол, счётчики отбитых пакетов.
2. Взгляд снаружи: какие порты ноды отвечают постороннему и жив ли её сайт-прикрытие. Смотрим через чужую ноду
   (канал сторожа с выходом на другом сервере, которого нет ни в одном списке разрешённых адресов), а не с rf1:
   rf1 сама в списках SSH, с неё «закрытый» порт выглядит открытым.
3. Закачка побольше перед отчётом (probe.py --speed) — скорость ближе к настоящей, чем на 512 КБ.
Список нод и адреса маячков — /etc/channel-watch/nodes.json: [{"name", "host", "beacon"}].
"""
import concurrent.futures
import datetime as dt
import html
import json
import socket
import ssl
import statistics
import struct
import subprocess
import time
import urllib.request

BEACON_STALE = 1800        # маячок старше — «не отдаёт состояние»
DISK_WARN, DISK_BAD = 85, 93   # % занятого диска: предупредить / тревога
MEM_WARN_MB = 80           # свободной памяти меньше — пометить
PORTS = (22, 2200, 80, 443, 2222, 4443, 8443, 10443, 2053, 9108)   # что пробуем снаружи
# эти порты посторонний видеть не должен: SSH, управление нодой, внутренние входы веб-сервера и Xray, мост, маячок
MUST_BE_CLOSED = (22, 2200, 2222, 4443, 8443, 10443, 2053, 9108)
# эти, если молчат на простое подключение, проверяем ещё и приветствием TLS (порт ноды 2222 молчит, пока не поздороваешься)
TLS_CLOSED = tuple(p for p in MUST_BE_CLOSED if p not in (22, 2200))
PORT_NAMES = {22: "SSH", 2200: "SSH", 2222: "управление нодой", 4443: "вход Xray без шифрования",
              8443: "внутренний порт сайта", 10443: "внутренний порт сайта", 2053: "мост", 9108: "маячок"}
BIG_BYTES = 10 * 1024 * 1024
BIG_URL = f"https://speed.cloudflare.com/__down?bytes={BIG_BYTES}"
BIG_FRESH = 3 * 3600       # замер «большой» скорости старше — в отчёт не идёт
DAYS_KEEP = 15


def fetch_beacon(url):
    """Маячок ноды: словарь либо None, если не достучались или пришло не то."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "channel-watch", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read(65536).decode("utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("ts"), (int, float)) else None
    except Exception:  # сеть, сертификат, не JSON — для отчёта это одно и то же: «маячок не читается»
        return None


def take_beacon(node, data, now):
    """Положить свежий маячок в состояние ноды и досчитать суточные счётчики отбитых пакетов."""
    node["tried"] = now
    if data is None:
        return
    prev = node.get("data") or {}
    day = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
    days = node.setdefault("days", [])
    if not days or days[-1]["d"] != day:
        days.append({"d": day, "drops": 0})
        del days[:-DAYS_KEEP]
    for key, cur in (data.get("drops") or {}).items():
        old = (prev.get("drops") or {}).get(key)
        if isinstance(cur, int) and isinstance(old, int):
            days[-1]["drops"] += cur - old if cur >= old else cur  # счётчик обнулился (перезагрузка, ufw reload)
    days[-1].update(disk=data.get("disk_pct"), mem=data.get("mem_avail_mb"))
    node["data"], node["ok_ts"] = data, now


def node_flags(node, now):
    """Что не так с сервером: список коротких пометок (пустой — всё в порядке)."""
    d = node.get("data")
    if not d or now - node.get("ok_ts", 0) > BEACON_STALE or now - d["ts"] > BEACON_STALE:
        return ["не отдаёт состояние" + (f" {max(1, int((now - node['ok_ts']) // 60))} мин" if node.get("ok_ts") else "")]
    flags = []
    if (d.get("disk_pct") or 0) >= DISK_WARN:
        flags.append(f"диск {d['disk_pct']}%")
    if d.get("mem_avail_mb") is not None and d["mem_avail_mb"] < MEM_WARN_MB:
        flags.append(f"свободной памяти {d['mem_avail_mb']} МБ")
    if d.get("ufw") and d["ufw"] != "active":
        flags.append("файрвол выключен")
    return flags


def disk_level(node):
    d = node.get("data") or {}
    pct = d.get("disk_pct")
    return None if pct is None else "bad" if pct >= DISK_BAD else "soon" if pct >= DISK_WARN else "ok"


def disk_alert(name, node, lvl):
    d = node["data"]
    if lvl == "ok":
        return f"✅ <b>Диск в порядке: {name}</b> — занято {d['disk_pct']}%, свободно {d['disk_free_mb']} МБ."
    return (f"{'❌' if lvl == 'bad' else '⚠️'} <b>Заканчивается диск: {name}</b> — занято {d['disk_pct']}%, "
            f"свободно {d['disk_free_mb']} МБ.\nКогда место кончится, нода перестанет писать журналы и может остановиться.")


def servers_line(nodes, now):
    """Строка обычного отчёта: одной фразой, если всё в порядке; иначе — что и где."""
    if not nodes:
        return None
    bad = [f"{name} — {', '.join(flags)}" for name, flags in ((n, node_flags(v, now)) for n, v in nodes.items()) if flags]
    return "<b>Серверы:</b> " + (html.escape("⚠️ " + "; ".join(bad)) if bad else f"все {len(nodes)} в порядке")


def servers_block(nodes, now):
    """Блок недельной сводки: строка на сервер — диск · свободно памяти · Xray, плюс пометки."""
    if not nodes:
        return []
    out = ["", "<b>Серверы</b> <i>(диск · свободно памяти · Xray)</i>"]
    versions = [v["data"].get("xray") for v in nodes.values() if v.get("data") and v["data"].get("xray")]
    newest = max(versions, key=lambda s: [int(x) for x in s.split(".") if x.isdigit()]) if versions else None
    for name, v in nodes.items():
        d, flags = v.get("data"), node_flags(v, now)
        if not d or flags[:1] and flags[0].startswith("не отдаёт"):
            out.append(f"⚠️ {name} — {flags[0]}")
            continue
        notes = [f for f in flags if not f.startswith("диск")]
        if d.get("reboot_required"):
            notes.append("ждёт перезагрузки")
        if d.get("xray") and newest and d["xray"] != newest:
            notes.append("Xray старее, чем на других")
        mark = "⚠️" if flags else "✅"
        out.append(html.escape(f"{mark} {name} — {d['disk_pct']}% · {d['mem_avail_mb']} МБ · {d.get('xray') or '?'}"
                               + (" · " + ", ".join(notes) if notes else "")))
    return out


def fmt_k(n):
    return f"{n / 1000:.0f} тыс." if n >= 10000 else f"{n / 1000:.1f} тыс." if n >= 1000 else str(int(n))


def scan_block(nodes, start_day, end_day):
    """Счётчик сканирования за неделю: сколько пакетов в сутки отбил файрвол на каждой ноде и где это выросло."""
    rows = []
    for name, v in nodes.items():
        days = [x for x in v.get("days", []) if start_day <= x["d"] < end_day and x.get("drops")]
        prev = [x["drops"] for x in v.get("days", []) if x["d"] < start_day and x.get("drops")]
        if days:
            rows.append((name, statistics.mean(x["drops"] for x in days), max(x["drops"] for x in days),
                         statistics.mean(prev) if len(prev) >= 3 else None))
    if not rows:
        return []
    rows.sort(key=lambda r: -r[1])
    line = " · ".join(f"{name} {fmt_k(avg)}" for name, avg, _, _ in rows)
    grown = [f"{name} — в {avg / was:.1f} раза больше прошлой недели" for name, avg, _, was in rows if was and avg >= was * 2]
    return ["", "<b>Сканирование</b> <i>(пакетов в сутки отбил файрвол)</i><b>:</b> " + html.escape(line)
            + (html.escape(". ⚠️ " + "; ".join(grown)) if grown else "")]


# ---------- взгляд снаружи ----------

TLS_PORTS = (443,)  # здесь, если на простой запрос молчат, пробуем ещё и поздороваться по TLS


def socks_connect(socks_port, host, port, timeout):
    """Соединение с host:port через SOCKS-порт канала сторожа; None — канал не принял."""
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        name = host.encode()
        if s.recv(2) == b"\x05\x00":
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
            reply = s.recv(10)
            if len(reply) >= 2 and reply[1] == 0:
                return s
    except (OSError, socket.timeout):
        pass
    s.close()
    return None


def socks_open(socks_port, host, port, timeout=5, tls=False):
    """Отвечает ли порт host:port постороннему. Идём через SOCKS-порт канала сторожа (выход — чужая нода).
    tls=True — про порт известно, что на нём TLS (вход VPN на нестандартном порту): здороваемся по TLS и там.
    Клиент Xray подтверждает соединение сразу, не дожидаясь цели, поэтому «открыт» — только если от цели пришли
    данные: приветствие, ответ на запрос или ответ на приветствие TLS."""
    try:
        s = socks_connect(socks_port, host, port, timeout)
        if s is None:
            return False
        with s:
            try:
                s.settimeout(2)
                if s.recv(1):          # SSH и подобные здороваются сами
                    return True
                return False           # закрыли без единого байта
            except socket.timeout:
                pass
            s.settimeout(timeout)
            # молчит — спросим как по HTTP; веб-сервер на TLS-порту ответит отказом, это тоже ответ
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                if s.recv(1):
                    return True
            except socket.timeout:
                pass
        if port not in TLS_PORTS and not tls:
            return False
        # вход Reality с чужим сайтом-прикрытием на простой запрос молчит — здороваемся по TLS
        s = socks_connect(socks_port, host, port, timeout)
        if s is None:
            return False
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
        except ssl.SSLEOFError:
            return False               # закрыли, ничего не ответив
        except ssl.SSLError:
            return True                # ответили, пусть и отказом
        finally:
            s.close()
    except (OSError, socket.timeout):
        return False


def site_title(socks_port, host):
    """Сайт-прикрытие глазами постороннего: (код ответа, заголовок страницы)."""
    cmd = ["curl", "-s", "-m", "10", "-x", f"socks5h://127.0.0.1:{socks_port}", "-w", "\n%{http_code}", f"https://{host}/"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except subprocess.TimeoutExpired:
        return "000", ""
    body, _, code = out.rpartition("\n")
    start = body.find("<title>")
    return code.strip() or "000", body[start + 7:body.find("<", start + 7)].strip()[:80] if start >= 0 else ""


FACE = {"r301": "порт 80 отвечает редиректом 301 на https", "tls12": "TLS 1.2", "tls13": "TLS 1.3",
        "hsts": "HSTS", "cert": "свой сертификат"}
FACE_LOST = {"r301": "порт 80 больше не отвечает редиректом 301 на https", "tls12": "заглушка перестала отвечать по TLS 1.2",
             "tls13": "заглушка перестала отвечать по TLS 1.3", "hsts": "у заглушки пропал HSTS",
             "cert": "на адресе ноды чужой или недействительный сертификат"}


def tls_face(socks_port, host, version, timeout=8):
    """Приветствие TLS только версии version с проверкой сертификата на имя host, через чужой канал.
    (ответила ли этой версией, сертификат годен для имени) — (None, None), если канал не соединил."""
    try:
        s = socks_connect(socks_port, host, 443, timeout)
    except OSError:
        return None, None
    if s is None:
        return None, None
    ctx = ssl.create_default_context()
    ctx.minimum_version = ctx.maximum_version = version
    try:
        with ctx.wrap_socket(s, server_hostname=host):
            return True, True
    except ssl.SSLCertVerificationError:
        return True, False          # этой версией ответили, но сертификат не на это имя или недействителен
    except (ssl.SSLError, OSError):
        return False, None
    finally:
        s.close()


def site_face(socks_port, host):
    """Заглушка глазами постороннего: {"r301", "tls12", "tls13", "hsts", "cert"} — True/False; None — канал подвёл."""
    def curl(*args):
        try:
            return subprocess.run(["curl", "-s", "-m", "10", "-x", f"socks5h://127.0.0.1:{socks_port}", *args],
                                  capture_output=True, text=True, timeout=15).stdout
        except subprocess.TimeoutExpired:
            return ""
    code, _, to = curl("-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", f"http://{host}/").partition(" ")
    head = curl("-I", f"https://{host}/").lower()
    t12, c12 = tls_face(socks_port, host, ssl.TLSVersion.TLSv1_2)
    t13, c13 = tls_face(socks_port, host, ssl.TLSVersion.TLSv1_3)
    if t12 is None and t13 is None and not code.strip("0") and not head:
        return None
    return {"r301": code == "301" and to.startswith(f"https://{host}"), "tls12": bool(t12), "tls13": bool(t13),
            "hsts": "\nstrict-transport-security:" in "\n" + head, "cert": bool(c12 or c13)}


def face_missing(face):
    """Чего у заглушки нет — по-русски, через запятую; пусто — всё на месте."""
    return ", ".join(("нет " if k != "r301" else "") + (FACE[k] if k != "r301" else "нет редиректа 301 на порту 80")
                     for k in FACE if face and face.get(k) is False)


def outside_view(nodes, vantage_for):
    """{нода: {"open": [порты], "site": [код, заголовок]}}; vantage_for(нода) -> SOCKS-порт чужого канала или None."""
    jobs, result = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for node in nodes:
            via = vantage_for(node)
            if via is None:
                continue
            result[node["name"]] = {"open": [], "site": None}
            for port in PORTS:
                jobs[ex.submit(socks_open, via, node["host"], port, 5, port in TLS_CLOSED)] = (node["name"], port)
            if node.get("site"):
                jobs[ex.submit(site_title, via, node["host"])] = (node["name"], "site")
                jobs[ex.submit(site_face, via, node["host"])] = (node["name"], "face")
        for fut, (name, what) in jobs.items():
            res = fut.result()
            if what == "site":
                result[name]["site"] = list(res)
            elif what == "face":
                if res is not None:
                    result[name]["face"] = res
            elif res:
                result[name]["open"].append(what)
    for v in result.values():
        v["open"].sort()
    return result


def outside_changes(name, was, cur):
    """Что изменилось в том, как ноду видно снаружи: список фраз. was — прошлый снимок (None — первый раз)."""
    out = []
    was_open = set((was or {}).get("open", []))
    for port in cur["open"]:
        if port in MUST_BE_CLOSED and (was is None or port not in was_open):
            out.append(f"порт {port} ({PORT_NAMES[port]}) открыт для всех")
        elif was is not None and port not in was_open:
            out.append(f"открылся порт {port}")
    if was is not None:
        out += [f"порт {port} перестал отвечать" for port in sorted(was_open - set(cur["open"]))]
        if was.get("site") and cur.get("site") and was["site"] != cur["site"]:
            out.append(f"сайт-прикрытие: было «{was['site'][1]}» ({was['site'][0]}), стало «{cur['site'][1]}» ({cur['site'][0]})")
    if cur.get("site") and cur["site"][0] != "200" and not any("сайт" in x for x in out) and was is None:
        out.append(f"сайт-прикрытие не отвечает (код {cur['site'][0]})")
    # заглушка (статья vpn-hub): сообщаем только о том, что было и пропало; первый взгляд — без тревоги, только в отчёт
    old_face, new_face = (was or {}).get("face"), cur.get("face")
    if old_face and new_face:
        out += [FACE_LOST[k] for k in FACE if old_face.get(k) and new_face.get(k) is False]
    return out


def outside_line(outside, nodes_total):
    """Строка отчёта и недельной сводки о взгляде снаружи."""
    if not outside:
        return None
    bad = [f"{name} — порт {p} ({PORT_NAMES[p]})" for name, v in outside.items() for p in v["open"] if p in MUST_BE_CLOSED]
    bad += [f"{name} — сайт не отвечает ({v['site'][0]})" for name, v in outside.items() if v.get("site") and v["site"][0] != "200"]
    bad += [f"{name} — заглушка: {face_missing(v['face'])}" for name, v in outside.items() if face_missing(v.get("face"))]
    sites = sum(1 for v in outside.values() if v.get("site"))
    faces = sum(1 for v in outside.values() if v.get("face"))
    return "<b>Снаружи:</b> " + (html.escape("⚠️ " + "; ".join(bad)) if bad else
                                 f"лишних открытых портов нет ({len(outside)} из {nodes_total} нод), сайты-прикрытия отвечают ({sites})"
                                 + (f"; у заглушек 301, TLS 1.2 и 1.3, HSTS, свой сертификат ({faces})" if faces else ""))


# ---------- закачка побольше ----------

def big_speed(port, max_time=45):
    """Скорость закачки BIG_BYTES через канал, Мбит/с; None — не докачалось."""
    cmd = ["curl", "-s", "-m", str(max_time), "-o", "/dev/null", "-x", f"socks5h://127.0.0.1:{port}",
           "-w", "%{size_download} %{speed_download}", BIG_URL]
    try:
        size, speed = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time + 5).stdout.split()
    except (ValueError, subprocess.TimeoutExpired):
        return None
    return round(float(speed) * 8 / 1e6, 1) if int(float(size)) >= BIG_BYTES else None


def speed_run(channels):
    """Каналы по очереди (не разом — иначе меряем не канал, а процессор rf1): {"ts", "channels": {имя: Мбит/с}}."""
    return {"ts": int(time.time()), "channels": {c["name"]: big_speed(c["port"]) for c in channels}}
