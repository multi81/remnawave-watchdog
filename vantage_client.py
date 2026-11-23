"""vantage_client: запросы сторожа к точке проверки по TLS с закреплённым сертификатом.

Агент (vantage_agent.py, версия 7+) на том же порту принимает и TLS: сертификат самоподписанный, его создаёт
vantage_install.sh, а отпечаток sha256 печатает vantage_install.sh --entry в поле "sha256" записи vantage.json.
Правило: у точки в vantage.json есть "sha256" — только TLS и только с этим сертификатом, на HTTP не откатываемся;
нет "sha256" — по-старому, HTTP (старая точка или запись, внесённая до TLS). Сертификат сверяется до отправки
запроса: X-Token, имена нод и ответы не видны на пути и не подменяются.

Подключён в blockwatch.py: agent_get (единственная точка, через которую сторож ходит к точкам) для точки с "sha256"
вызывает vantage_client.agent_get, add_vantage проверяет запись через check_entry. Файл лежит рядом с blockwatch.py
в /opt/channel-watch, его копирует install.sh. wrap() — для внешнего подключения к старому blockwatch.
"""
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import urllib.parse

MAX_BODY = 262144  # как у прежнего agent_get


def norm_fp(text):
    """Отпечаток в виде 64 шестнадцатеричных знаков (двоеточия и регистр — как угодно); '' — не отпечаток."""
    fp = re.sub(r"[\s:]", "", str(text or "")).lower()
    return fp if re.fullmatch(r"[0-9a-f]{64}", fp) else ""


def fingerprint(der):
    return hashlib.sha256(der).hexdigest()


def check_entry(entry):
    """Для add_vantage: поле sha256, если оно есть, — настоящий отпечаток (иначе точка молча перестала бы отвечать)."""
    if "sha256" in entry and not norm_fp(entry["sha256"]):
        raise ValueError("в записи точки sha256 — не отпечаток (нужно 64 шестнадцатеричных знака)")
    return entry


def _addr(url):
    u = urllib.parse.urlsplit(url)
    return u.hostname, u.port or (443 if u.scheme == "https" else 80)


def open_pinned(agent, timeout):
    """Соединение TLS с точкой, сертификат сверен с agent["sha256"]; None — не тот сертификат или нет связи."""
    pin = norm_fp(agent.get("sha256"))
    host, port = _addr(agent.get("url", ""))
    if not pin or not host:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # цепочку не проверяем: доверяем ровно одному сертификату — по отпечатку
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw)
    except (OSError, ValueError):
        raw.close()
        return None
    der = tls.getpeercert(binary_form=True) or b""
    if not hmac.compare_digest(fingerprint(der), pin):
        tls.close()
        return None
    return tls


def agent_get(agent, path, timeout=20):
    """Как blockwatch.agent_get, но по TLS с закреплённым отпечатком; None — не ответила или ответила не тем."""
    tls = conn = None
    try:
        tls = open_pinned(agent, timeout)
        if tls is None:
            return None
        host, port = _addr(agent["url"])
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = tls
        conn.request("GET", path, headers={"X-Token": agent["token"], "Connection": "close"})
        r = conn.getresponse()
        if r.status != 200:
            return None
        data = json.loads(r.read(MAX_BODY).decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # сеть, отказ, не JSON — для сторожа одно и то же: «точка не ответила»
        return None
    finally:
        for c in (conn, tls):
            if c is not None:
                try:
                    c.close()
                except OSError:
                    pass


def wrap(plain_get):
    """agent_get для сторожа: точки с отпечатком — по TLS (без отката на HTTP), остальные — прежней функцией."""
    def get(agent, path, timeout=20):
        if agent.get("sha256"):
            return agent_get(agent, path, timeout)
        return plain_get(agent, path, timeout)
    return get
