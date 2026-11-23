#!/usr/bin/env python3
"""beacon_serve: отдаёт сторожу файл состояния ноды — замена `python3 -m http.server` для beacon_install.sh --serve.

Что отдаёт: только GET и HEAD двух имён из одной папки — state.json (маячок) и flows.json (свидетель, node_witness.py
кладёт его рядом). Файл открывается без перехода по ссылкам, только обычный файл и не больше MAX_FILE. Всё прочее — 404
без тела. Заголовки нейтральные: нет Server, нет подписи в ответах на ошибки.

TLS и HTTP на одном порту: первый байт соединения 0x16 — рукопожатие TLS, иначе обычный HTTP. HTTP остаётся для
прежнего сторожа (у ноды в его nodes.json ещё нет "sha256") и для счётчиков свидетеля, которые сторож берёт curl-ом.
Новый сторож (nodewatch.fetch_beacon) для ноды с "sha256" ходит только по TLS и сверяет сертификат по отпечатку.
Сертификат самоподписанный, его создаёт beacon_install.sh; ключ читает только root, службе (пользователь nobody) его
передаёт systemd через LoadCredential — файлы берутся из $CREDENTIALS_DIRECTORY. Нет их — только HTTP.
--tls-only — HTTP закрыт: соединение без рукопожатия TLS сразу закрывается. Включать, когда у ноды в nodes.json
сторожа уже есть "sha256" и сторож забирает по TLS и маячок, и flows.json. С --tls-only без сертификата не запускается.

Свои и чужие: --allow СЕТЬ (можно несколько) — отвечаем только этим адресам, а также
127.0.0.0/8, ::1 и адресу самой ноды (самопроверка установщика и путь сторожа через канал этой же ноды). Адрес
проверяется сразу после accept, до занятия места среди MAX_CONN, чужое соединение тут же закрывается — молчащие
посторонние места не занимают. Без --allow отвечаем всем, как прежний python3 -m http.server.
У каждого соединения общий срок CONN_DEADLINE от accept до конца ответа: по истечении сокет обрывается, даже если
байты подаются по одному (FIRST_WAIT и READ_WAIT действуют на каждое чтение, их так можно обойти, общий срок — нет).
Все места заняты своими — обрывается самое старое соединение: настоящий запрос сторожа длится доли секунды.

Запуск:  beacon_serve.py ПОРТ ПАПКА [--bind АДРЕС] [--allow СЕТЬ]... [--tls-only]
Самопроверка установщика:  beacon_serve.py --check ПОРТ [ОТПЕЧАТОК] [--tls-only] — печатает «HTTP <код> TLS <код>»
(TLS — с 127.0.0.1 со сверкой отпечатка; «-» — без отпечатка не проверяли, «0» — нет ответа или чужой сертификат;
с --tls-only успех — «HTTP 0 TLS 200»: HTTP должен быть закрыт).
"""
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import os
import socket
import ssl
import stat
import sys
import threading
import time

NAMES = ("state.json", "flows.json")
MAX_FILE = 1 << 20     # маячок — единицы КБ, свидетель — до 400 КБ (столько читает сторож)
MAX_CONN = 16          # одновременных соединений своих; чужие места не занимают
FIRST_WAIT = 10        # секунд на первый байт и рукопожатие TLS (на каждое чтение)
READ_WAIT = 10         # секунд на строку запроса и заголовки (на каждое чтение)
CONN_DEADLINE = 15     # секунд на всё соединение: от accept до конца ответа
EVICT_WAIT = 2         # секунд ждать, пока оборванное старое соединение освободит место


def read_file(folder, name):
    """Содержимое файла или None: не обычный файл, ссылка, слишком большой, нет файла."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(os.path.join(folder, name), flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:  # папка, канал, устройство — не отдаём
            return None
        data = b""
        while len(data) <= MAX_FILE:
            chunk = os.read(fd, MAX_FILE + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    return data if len(data) <= MAX_FILE else None


class Handler(http.server.BaseHTTPRequestHandler):
    timeout = READ_WAIT
    error_message_format, error_content_type = "", "text/plain"

    def send_response(self, code, message=None):
        # как в http.server, но без заголовка Server
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        try:
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError:
            pass

    def log_message(self, *args):
        pass  # кто и что спрашивал — не в журнал

    def do_GET(self):
        self.reply(True)

    def do_HEAD(self):
        self.reply(False)

    def reply(self, body):
        path = self.path.split("?", 1)[0]
        name = path[1:] if path.startswith("/") else ""
        data = read_file(self.server.folder, name) if name in NAMES else None
        if data is None:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(data)


def norm_ip(addr):
    """Адрес клиента как ipaddress: без зоны «%…», IPv4 внутри IPv6 (::ffff:a.b.c.d) — как IPv4. None — не адрес."""
    try:
        ip = ipaddress.ip_address(str(addr).split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def parse_allow(items):
    """Сети из --allow; ValueError — не адрес."""
    return [ipaddress.ip_network(a.strip(), strict=False) for a in items]


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False   # потоки соединений заводим сами (process_request), их учёт — в self.active
    request_queue_size = 128  # очередь accept: наплыв чужих (их закрываем сразу) не должен отказывать сторожу

    def __init__(self, addr, folder, tls=None, allow=None, tls_only=False):
        if ":" in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, Handler)
        self.folder, self.tls, self.tls_only = folder, tls, tls_only
        # None — отвечаем всем (без --allow, как раньше); строки — разбираем как в --allow
        self.allow = None if allow is None else [n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                                                 else parse_allow([n])[0] for n in allow]
        self.trust_local = True    # 127.0.0.0/8, ::1 и адрес самой ноды — свои (тесты на одном ПК это выключают)
        self.deadline = CONN_DEADLINE
        self.cv = threading.Condition()
        self.active = {}           # дубль сокета соединения -> [время accept, живой сокет (после TLS — обёртка)]

    def verify_request(self, request, client_address):
        """Свой ли адрес — сразу после accept, до занятия места; False — socketserver тут же закрывает соединение."""
        if self.allow is None:
            return True
        ip = norm_ip(client_address[0] if client_address else "")
        if ip is None:
            return False
        if self.trust_local:
            if ip.is_loopback:
                return True
            try:
                if ip == norm_ip(request.getsockname()[0]):  # с самой ноды на её же адрес (канал через эту ноду)
                    return True
            except OSError:
                return False
        return any(ip.version == n.version and ip in n for n in self.allow)

    def process_request(self, request, client_address):
        try:
            guard = request.dup()  # тот же сокет ядра: им обрываем по сроку, что бы ни стало с самим объектом
        except OSError:
            return self.shutdown_request(request)
        with self.cv:
            if len(self.active) >= MAX_CONN:
                # все места у своих: обрываем самое старое (запрос сторожа — доли секунды, старое — значит, молчит)
                self._cut(min(self.active, key=lambda g: self.active[g][0]))
                if not self.cv.wait_for(lambda: len(self.active) < MAX_CONN, EVICT_WAIT):
                    guard.close()
                    return self.shutdown_request(request)
            self.active[guard] = [time.monotonic(), request]
        timer = threading.Timer(self.deadline, self.expire, (guard,))
        timer.daemon = True
        try:
            timer.start()
            threading.Thread(target=self.conn_thread, args=(request, client_address, guard, timer), daemon=True).start()
        except Exception:  # поток не завёлся — соединение закрываем, место освобождаем
            self.release(guard, timer)
            self.shutdown_request(request)

    def conn_thread(self, request, client_address, guard, timer):
        try:
            self.finish_request(request, client_address, guard)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self.release(guard, timer)

    def release(self, guard, timer):
        timer.cancel()
        with self.cv:
            self.active.pop(guard, None)
            guard.close()
            self.cv.notify_all()

    def expire(self, guard):
        """Срок соединения истёк — оборвать, где бы ни ждал поток (первый байт, рукопожатие, заголовки, отправка)."""
        with self.cv:
            if guard in self.active:
                self._cut(guard)

    def _cut(self, guard):
        # вызывается под self.cv. В Linux shutdown дубля будит поток в recv/send того же сокета ядра. В Windows
        # (тесты на ПК) не будит — там закрываем и живой сокет, и дубль: поток просыпается, когда закрыты оба
        try:
            guard.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if os.name == "nt":
            try:
                self.active[guard][1].close()
            except (OSError, KeyError):
                pass
            guard.close()

    def _live(self, guard, sock):
        with self.cv:
            if guard in self.active:
                self.active[guard][1] = sock

    def finish_request(self, request, client_address, guard=None):
        sock = self.open_tls(request, guard)
        if sock is None:
            return
        try:
            super().finish_request(sock, client_address)
        finally:
            if sock is not request:
                sock.close()

    def open_tls(self, sock, guard=None):
        """Первый байт 0x16 — рукопожатие TLS (если есть сертификат), иначе обычный HTTP (с --tls-only — закрыть).
        None — оборвалось или не годится."""
        sock.settimeout(FIRST_WAIT)
        try:
            first = sock.recv(1, socket.MSG_PEEK)
        except OSError:
            return None
        if not first:
            return None
        if first == b"\x16" and self.tls:
            try:
                tls = self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            except (OSError, ValueError):
                return None
            if guard is not None:
                self._live(guard, tls)  # исходный объект отдан обёртке — обрывать по сроку теперь её
            try:
                tls.do_handshake()
            except (OSError, ValueError):
                tls.close()
                return None
            return tls
        if self.tls_only:
            return None  # HTTP закрыт: ни строки ответа, ни подписи
        return sock

    def handle_error(self, request, client_address):
        pass  # обрывы и мусор от сети — не в журнал


def tls_context(cert, key):
    """Контекст TLS или None — файлов нет (установка без сертификата: только HTTP)."""
    if not (cert and key and os.path.isfile(cert) and os.path.isfile(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def cred_files():
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    if not d:
        return None, None
    return os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")


def check(port, fp="", host="127.0.0.1", timeout=5):
    """Самопроверка: (код по HTTP, код по TLS со сверкой отпечатка). 0 — не ответил, None — TLS не проверяли."""
    def ask(sock):
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock
        try:
            conn.request("GET", "/state.json", headers={"Connection": "close"})
            r = conn.getresponse()
            r.read(MAX_FILE)
            return r.status
        finally:
            conn.close()

    try:
        code_http = ask(socket.create_connection((host, port), timeout=timeout))
    except (OSError, http.client.HTTPException):
        code_http = 0
    if not fp:
        return code_http, None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # доверяем ровно одному сертификату — по отпечатку
    try:
        tls = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout))
    except (OSError, ValueError):
        return code_http, 0
    if not hmac.compare_digest(hashlib.sha256(tls.getpeercert(binary_form=True) or b"").hexdigest(), fp.lower()):
        tls.close()
        return code_http, 0
    try:
        return code_http, ask(tls)
    except (OSError, http.client.HTTPException):
        return code_http, 0


def check_ok(res, tls_only=False):
    """Итог самопроверки: обычный режим — HTTP 200 (и TLS 200, если проверяли); --tls-only — HTTP закрыт, TLS 200."""
    if tls_only:
        return res[0] == 0 and res[1] == 200
    return res[0] == 200 and res[1] in (None, 200)


def parse_args(argv):
    """(порт, папка, адрес, сети --allow или None, tls_only); ValueError — параметры не те."""
    pos, bind, allow, tls_only, i = [], "0.0.0.0", None, False, 0
    while i < len(argv):
        a = argv[i]
        if a in ("--bind", "--allow"):
            if i + 1 >= len(argv):
                raise ValueError(f"после {a} нужен адрес")
            if a == "--bind":
                bind = argv[i + 1]
            else:
                allow = (allow or []) + parse_allow([argv[i + 1]])
            i += 2
            continue
        if a == "--tls-only":
            tls_only = True
        elif a.startswith("--"):
            raise ValueError(f"не понимаю параметр {a}")
        else:
            pos.append(a)
        i += 1
    if len(pos) != 2:
        raise ValueError("нужны ПОРТ и ПАПКА")
    return int(pos[0]), pos[1], bind, allow, tls_only


def main(argv):
    if argv[:1] == ["--check"]:
        tls_only = "--tls-only" in argv
        rest = [a for a in argv[1:] if a != "--tls-only"]
        port, fp = int(rest[0]), (rest[1] if len(rest) > 1 else "")
        for _ in range(10):  # служба могла только что перезапуститься
            res = check(port, fp)
            if check_ok(res, tls_only):
                break
            time.sleep(0.5)
        print(f"HTTP {res[0]} TLS {'-' if res[1] is None else res[1]}")
        return 0 if check_ok(res, tls_only) else 1
    try:
        port, folder, bind, allow, tls_only = parse_args(argv)
    except ValueError as e:
        print(f"{e}\nbeacon_serve.py ПОРТ ПАПКА [--bind АДРЕС] [--allow СЕТЬ]... [--tls-only]", file=sys.stderr)
        return 2
    tls = tls_context(*cred_files())
    if tls is None and tls_only:
        print("--tls-only, а сертификата нет — не запускаюсь", file=sys.stderr)
        return 1
    if tls is None:
        print("сертификата нет — только HTTP", file=sys.stderr)
    Server((bind, port), folder, tls, allow, tls_only).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
