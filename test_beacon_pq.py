"""Тесты: маячок и сторож в режиме node_dns.sh «запасной на каждый запрос» (install --per-query). Пути маячка —
во временную папку, команды (unbound-control, resolvectl, systemctl, docker) и запрос к Unbound подменены. Без сети."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import node_beacon as nb  # noqa: E402
import nodewatch as nw  # noqa: E402

ok = 0


def check(name, cond):
    global ok
    if not cond:
        print("FAIL", name)
        sys.exit(1)
    ok += 1


NOW = 1_800_000_000
MARK = nb.RMARK
OLD_KEYS = {"active", "current", "queries", "hits", "exceeded", "servfail", "uptime", "rrset_mb", "rrset_max_mb",
            "msg_mb", "msg_max_mb", "fallback_24h"}


def ts(sec_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - sec_ago))


def pq_resolv(*spares):
    return "\n".join([MARK, "# комментарий", "nameserver 127.0.0.1"] + ["nameserver " + a for a in spares]
                     + ["options timeout:2 attempts:1 edns0 trust-ad", "search example"]) + "\n"


def setup(resolv, env=None, flags=(), card=None, log="", active=True, resolved="1.1.1.1", answers=True,
          docker=None, bak=True):
    """Стенд маячка во временной папке. env — текст dns.env (None — файла нет), bak=False — /root не виден."""
    d = tempfile.mkdtemp()
    nb.UCONF = os.path.join(d, "storozh.conf")
    open(nb.UCONF, "w", encoding="utf-8").write("server:\n    rrset-cache-size: 64m\n    msg-cache-size: 32m\n")
    nb.RESOLV = os.path.join(d, "resolv.conf")
    open(nb.RESOLV, "w", encoding="utf-8", newline="\n").write(resolv)
    nb.DNS_BAK = os.path.join(d, "node-dns-backup")
    if bak:
        os.mkdir(nb.DNS_BAK)
        if env is not None:
            open(os.path.join(nb.DNS_BAK, "dns.env"), "w", encoding="utf-8").write(env)
        for f in flags:
            open(os.path.join(nb.DNS_BAK, f), "w").close()
        if card:
            open(os.path.join(nb.DNS_BAK, "resolv-card"), "w").write(card + "\n")
    nb.DNS_LOG = os.path.join(d, "storozh-unbound.log")
    open(nb.DNS_LOG, "w", encoding="utf-8").write(log)

    def run(cmd, timeout=20):
        if cmd[0] == "unbound-control":
            return "total.num.queries=1000\ntotal.num.cachehits=900\nmem.cache.rrset=1048576\n"
        if cmd[0] == "resolvectl":
            return "Global\n  Current DNS Server: %s\n" % resolved if resolved else "Global\n"
        if cmd[0] == "systemctl":
            return "active\n" if active else "inactive\n"
        return ""

    def proc(cmd, timeout=20):
        if cmd[:2] == ["docker", "inspect"] and docker is not None:
            path = os.path.join(d, "container-resolv.conf")
            open(path, "w", encoding="utf-8").write("".join("nameserver %s\n" % a for a in docker[0]))
            return 0, "%s|%s|%s\n" % (path, docker[1], docker[2] if len(docker) > 2 else "true"), ""
        return 1, "", "Error: No such object: remnanode"

    nb.run, nb.proc = run, proc
    nb.unbound_answers = lambda srv="127.0.0.1", timeout=2: answers
    return nb.dns(now=NOW)


ENV_PQ = "FALLBACK=8.8.8.8\nSYSTEM_DNS=10.0.0.1\nPER_QUERY=yes\nRESOLV_NS=8.8.8.8 9.9.9.9\nRESOLV_SEARCH=\n"
ENV_REG = "FALLBACK=8.8.8.8\nSYSTEM_DNS=10.0.0.1\n"

# --- обычный режим: поля и значения как раньше
x = setup("nameserver 127.0.0.53\noptions edns0 trust-ad\n", env=ENV_REG, resolved="127.0.0.1",
          log=ts(3600) + " resolved был на 1.1.1.1 — вернула на Unbound (сейчас 127.0.0.1)\n")
check("R1 обычный режим — только прежние поля", set(x) == OLD_KEYS)
check("R2 обычный режим — current от resolved, уходы считаются", x["current"] == "127.0.0.1" and x["fallback_24h"] == 1)
check("R3 обычный режим — кэш из storozh.conf", x["rrset_max_mb"] == 64 and x["msg_max_mb"] == 32 and x["rrset_mb"] == 1.0)
x = setup("nameserver 127.0.0.53\n", env=ENV_REG, resolved="1.1.1.1")
check("R4 обычный режим на запасном — пометка как раньше", nw.dns_flags(x) == ["DNS сейчас на запасном 1.1.1.1"])
x = setup(pq_resolv("8.8.8.8"), env=ENV_REG)
check("R5 dns.env без PER_QUERY, а файл с меткой — обычный режим (dns.env главнее)", set(x) == OLD_KEYS)
x = setup("nameserver 127.0.0.53\n", bak=False, docker=(["127.0.0.53"], "host"))
check("R6 /root не виден, файл не наш — обычный режим, без docker", set(x) == OLD_KEYS)
os.remove(nb.UCONF)
check("R7 Unbound не ставили — None", nb.dns(now=NOW) is None)

# --- per-query, Unbound жив
x = setup(pq_resolv("8.8.8.8", "9.9.9.9"), env=ENV_PQ, resolved="1.1.1.1")
check("P1 режим per-query", x["mode"] == "per-query")
check("P2 current — 127.0.0.1, resolved — для сведения", x["current"] == "127.0.0.1" and x["resolved"] == "1.1.1.1")
check("P3 nameservers из файла", x["nameservers"] == ["127.0.0.1", "8.8.8.8", "9.9.9.9"])
check("P4 файл свой, DNS карт нет, Unbound отвечает", x["resolv_foreign"] is False and x["resolv_card"] is None
      and x["unbound_ok"] is True)
check("P5 resolved на 1.1.1.1 — ложной пометки нет", nw.dns_flags(x) == [])
check("P6 прежние поля на месте", OLD_KEYS <= set(x))
check("P7 нет remnanode — нет полей xray", "xray_resolv" not in x and "xray_net" not in x)

# --- per-query, Unbound не отвечает
x = setup(pq_resolv("8.8.8.8", "9.9.9.9"), env=ENV_PQ, flags=("unbound-down",), resolved="127.0.0.1")
check("P8 флаг unbound-down — current первый запасной", x["current"] == "8.8.8.8" and x["unbound_ok"] is False)
check("P9 пометка «на запасном»", nw.dns_flags(x) == ["DNS сейчас на запасном 8.8.8.8"])
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, answers=False)
check("P10 сам не ответил на запрос — current запасной", x["current"] == "8.8.8.8")
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, active=False)
check("P11 служба остановлена — current запасной, пометка «не работает»", x["current"] == "8.8.8.8"
      and nw.dns_flags(x) == ["свой DNS не работает (система на запасном)"])
check("P11b в файле только 127.0.0.1 — current None",
      setup(MARK + "\nnameserver 127.0.0.1\n", env=ENV_PQ, answers=False)["current"] is None)

# --- /root не виден маячку (ProtectHome=yes): режим по метке, состояние — по журналу таймера
x = setup(pq_resolv("8.8.8.8"), bak=False)
check("H1 режим по метке первой строки", x["mode"] == "per-query" and x["current"] == "127.0.0.1")
down = ts(300) + " Unbound не отвечает (3 попытки), перезапуск не помог — остаётся первым в /etc/resolv.conf\n"
x = setup(pq_resolv("8.8.8.8"), bak=False, log=down)
check("H2 свежая строка «не отвечает» — current запасной", x["current"] == "8.8.8.8")
x = setup(pq_resolv("8.8.8.8"), bak=False, log=ts(7200) + down[20:])
check("H3 строка старше 30 мин — не верить, current 127.0.0.1", x["current"] == "127.0.0.1")
x = setup(pq_resolv("8.8.8.8"), bak=False, log=down + ts(60) + " Unbound снова отвечает — вернула запросы на Unbound\n")
check("H4 после «вернула» — снова 127.0.0.1, уход посчитан", x["current"] == "127.0.0.1" and x["fallback_24h"] == 1)
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, log=down)
check("H5 /root виден — верим флагу, не журналу", x["current"] == "127.0.0.1")

# --- DNS карты за 127.0.0.1 (resolv-card)
x = setup(pq_resolv("10.0.0.1"), env=ENV_PQ, card="10.0.0.1", flags=("unbound-down",))
check("C1 флаг resolv-card — адреса карт", x["resolv_card"] == ["10.0.0.1"] and x["current"] == "10.0.0.1")
check("C2 пометки: запасной и DNS карты", nw.dns_flags(x) == ["DNS сейчас на запасном 10.0.0.1",
                                                            "запасные DNS молчали — за Unbound стоят DNS карты 10.0.0.1"])
cardlog = ts(900) + " не отвечают ни Unbound, ни запасные 8.8.8.8 — в /etc/resolv.conf за 127.0.0.1 поставлены DNS карты " \
    "10.0.0.1 10.0.0.2 (запасные вернутся, когда ответят)\n"
x = setup(pq_resolv("10.0.0.1", "10.0.0.2"), bak=False, log=cardlog)
check("C3 /root не виден — DNS карты по журналу", x["resolv_card"] == ["10.0.0.1", "10.0.0.2"])
x = setup(pq_resolv("8.8.8.8"), bak=False, log=cardlog)
check("C4 в файле уже запасные — строка журнала старая", x["resolv_card"] is None)
x = setup(pq_resolv("8.8.8.8"), bak=False, log=cardlog + ts(60) + " запасные 8.8.8.8 снова отвечают — в /etc/resolv.conf "
          "за 127.0.0.1 снова они (DNS карты убраны)\n")
check("C5 карты убраны — None", x["resolv_card"] is None)

# --- /etc/resolv.conf подменён
x = setup("nameserver 1.1.1.1\nnameserver 8.8.4.4\n", env=ENV_PQ)
check("F1 подмена — флаг, current первый в чужом файле", x["mode"] == "per-query" and x["resolv_foreign"] is True
      and x["current"] == "1.1.1.1" and x["nameservers"] == ["1.1.1.1", "8.8.4.4"])
check("F2 пометки: подменён и на запасном", nw.dns_flags(x) == ["/etc/resolv.conf подменён (nameserver 1.1.1.1 8.8.4.4)",
                                                             "DNS сейчас на запасном 1.1.1.1"])
x = setup("nameserver 127.0.0.1\n", env=ENV_PQ)
check("F3 чужой файл, но на Unbound — только «подменён»", nw.dns_flags(x) == ["/etc/resolv.conf подменён (nameserver 127.0.0.1)"])
repl = ts(3000) + " /etc/resolv.conf был подменён (чужой файл, nameserver: 1.1.1.1 ) — поставлен свой: nameserver 127.0.0.1 8.8.8.8\n"
x = setup(pq_resolv("8.8.8.8"), bak=False, log=ts(90000) + repl[20:] + repl + repl)
check("F4 подмены за сутки по журналу (и из песочницы)", x["resolv_replaced_24h"] == 2 and x["resolv_foreign"] is False)
check("F5 пометка о подменах", nw.dns_flags(x) == ["/etc/resolv.conf подменяли 2 раз за сутки (таймер вернул свой)"])
x = setup("nameserver 1.1.1.1\n", env=ENV_PQ, log=repl)
check("F6 подменён сейчас — одна пометка о подмене, не две",
      nw.dns_flags(x) == ["/etc/resolv.conf подменён (nameserver 1.1.1.1)", "DNS сейчас на запасном 1.1.1.1"])

# --- копия resolv.conf контейнера remnanode
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, docker=(["127.0.0.1", "8.8.8.8"], "host"))
check("X1 копия новая — xray_resolv 127.0.0.1, пометок нет", x["xray_resolv"] == "127.0.0.1" and x["xray_net"] == "host"
      and nw.dns_flags(x) == [])
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, docker=(["127.0.0.53"], "host"))
check("X2 копия старая — пометка", x["xray_resolv"] == "127.0.0.53" and nw.dns_flags(x) == [
    "Xray ходит через systemd-resolved, а не по своему resolv.conf (копия в контейнере старая, nameserver 127.0.0.53; обновить копию или перезапустить remnanode)"])
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, docker=(["127.0.0.53"], "host", "false"))
check("X5 контейнер остановлен — копию resolv.conf не смотрим, пометки «через resolved» нет",
      x.get("xray_resolv") is None and not any("resolved" in f for f in nw.dns_flags(x)))
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, docker=(["8.8.8.8"], "bridge"))
check("X3 контейнер не в сети хоста — своя пометка",
      nw.dns_flags(x) == ["Xray ходит не по своему resolv.conf (контейнер не в сети хоста, nameserver 8.8.8.8)"])
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, docker=([], "host"))
check("X4 в копии нет nameserver — поле None, пометки нет", x["xray_resolv"] is None and nw.dns_flags(x) == [])

# --- счётчик уходов в режиме per-query: прежние «уходы» resolved не считаются, настоящие возвраты — считаются
old = "".join(ts(3600 * k) + " resolved был на 1.1.1.1 — вернула на Unbound (сейчас 127.0.0.1)\n" for k in (1, 2, 3))
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, log=old)
check("F1 per-query: прежние переключения resolved в счётчик не идут", x["fallback_24h"] == 0
      and not any("уходил" in f for f in nw.dns_flags(x)))
x = setup(pq_resolv("8.8.8.8"), env=ENV_PQ, log=old + ts(600) + " Unbound снова отвечает — вернула запросы на Unbound\n")
check("F2 per-query: настоящий возврат после отказа Unbound считается", x["fallback_24h"] == 1)
x = setup("nameserver 127.0.0.53\n", log=old)
check("F3 обычный режим: счёт как раньше", x["fallback_24h"] == 3)

# --- сторож: старые маячки и прочие пометки
D = {"active": True, "current": "127.0.0.1", "queries": 755000, "hits": 727000, "exceeded": 81, "rrset_mb": 20.0,
     "rrset_max_mb": 64, "msg_mb": 10.0, "msg_max_mb": 32, "fallback_24h": 2}
check("W1 старый маячок без mode — как раньше", nw.dns_flags(dict(D, current="1.1.1.1")) == ["DNS сейчас на запасном 1.1.1.1"])
check("W2 старый маячок: поля per-query без mode не читаются",
      nw.dns_flags(dict(D, resolv_foreign=True, xray_resolv="127.0.0.53", resolv_card=["1.2.3.4"])) == [])
P = dict(D, mode="per-query", current="127.0.0.1", resolved="1.1.1.1", nameservers=["127.0.0.1", "8.8.8.8"],
         resolv_foreign=False, resolv_card=None, unbound_ok=True)
check("W3 per-query: частые уходы — как раньше", nw.dns_flags(dict(P, fallback_24h=30)) == ["DNS уходил на запасной 30 раз за сутки"])
check("W4 per-query: медленные ответы и кэш — как раньше", nw.dns_flags(dict(P, exceeded=5000, rrset_mb=63.5)) == [
    "DNS отвечает медленно: 5000 ответов искались дольше 1,9 с (18 % из 28000 поисков мимо кэша; клиенты в это время ждут 2 с "
    "и идут на запасной)", "кэш DNS записей заполнен (63.5 из 64 МБ)"])
node = {"data": {"ts": NOW, "disk_pct": 10, "mem_avail_mb": 900, "ufw": "active", "dns": P}, "ok_ts": NOW}
check("W5 в отчёте о сервере — без ложной пометки", nw.node_flags(node, NOW) == [])

# --- разбор журнала
check("L1 пустой журнал", nb.pq_log_state([], NOW) == (False, None))
check("L2 битая дата — не «не отвечает»", nb.pq_log_state(["xx Unbound не отвечает (3 попытки)"], NOW) == (False, None))
check("L3 nameservers без адреса пропускаются", nb.nameservers("nameserver\nnameserver 1.2.3.4\n# nameserver 5.6.7.8\n")
      == ["1.2.3.4"])
print("маячок и сторож, DNS per-query: тестов пройдено %d" % ok)
