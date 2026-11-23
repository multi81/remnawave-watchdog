"""Тесты роли базы только на чтение для сведений о пользователе (panel_ro_role.sql и panel_user_info.sh).
Без панели и без Docker: docker подменяется скриптом. python test_panel_ro.py"""
import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ok = 0


def check(name, cond):
    global ok
    assert cond, name
    print("OK  ", name)
    ok += 1


def src(name):
    return open(os.path.join(HERE, name), encoding="utf-8", newline="").read()


sh, sql = src("panel_user_info.sh"), src("panel_ro_role.sql")
check("файлы в UTF-8 и LF, без CR", "\r" not in sh and "\r" not in sql)

# --- SQL: права ровно на те таблицы, что читает скрипт
query = sh.split("<<'SQL'", 1)[1].split("\nSQL", 1)[0]
read_tables = set(re.findall(r"\b(?:from|join)\s+([a-z_]+)\b", query)) - {"lateral"}
m = re.search(r"GRANT SELECT ON TABLE ([a-z_, ]+) TO watch_ro;", sql)
granted = {x.strip() for x in m.group(1).split(",")} if m else set()
check("скрипт читает пять таблиц", read_tables == {"users", "user_traffic", "nodes", "hwid_user_devices",
                                                   "user_subscription_request_history"})
check("SELECT выдан ровно на таблицы, которые читает скрипт", granted == read_tables)
body = "\n".join(ln for ln in sql.splitlines() if not ln.lstrip().startswith("--"))
check("роль создаётся только если её нет (повторный запуск не падает)",
      re.search(r"IF NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = 'watch_ro'\) THEN\s+CREATE ROLE watch_ro LOGIN;",
                body) is not None and body.count("CREATE ROLE") == 1)
check("без пароля, не суперпользователь, без создания баз и ролей",
      "PASSWORD NULL" in body and "NOSUPERUSER" in body and "NOCREATEDB" in body and "NOCREATEROLE" in body
      and re.search(r"PASSWORD\s+'", body) is None)
check("прав на запись нет: только CONNECT, USAGE и SELECT",
      re.search(r"\b(INSERT|UPDATE|DELETE|TRUNCATE|ALL PRIVILEGES|GRANT ALL)\b", body) is None
      and sorted(set(re.findall(r"GRANT (\w+)", body))) == ["CONNECT", "SELECT", "USAGE"])
check("одной транзакцией, с остановкой на первой ошибке", "BEGIN;" in body and body.rstrip().endswith("COMMIT;")
      and "ON_ERROR_STOP" in body)
check("по умолчанию у роли — только чтение", "ALTER ROLE watch_ro SET default_transaction_read_only = on;" in body)
check("в шапке — как применить", "docker exec -i remnawave-db psql -U postgres -d postgres" in sql)

# --- скрипт: watch_ro, если роль есть, иначе postgres (docker — подставной)
BASH = shutil.which("bash")
if BASH and "system32" not in BASH.lower():   # bash из WSL в System32 — не тот
    work = tempfile.mkdtemp()
    fake = os.path.join(work, "bin")
    os.makedirs(fake)
    with open(os.path.join(fake, "docker"), "w", encoding="utf-8", newline="\n") as f:
        f.write('#!/bin/bash\n'
                'printf "%s\\n" "$*" >> "$LOG"\n'
                'case " $* " in\n'
                '  *" -U watch_ro "*"select 1"*)\n'
                '    [ "${ROLE:-0}" = 1 ] && { echo 1; exit 0; }\n'
                '    echo "psql: FATAL: role \\"watch_ro\\" does not exist" >&2; exit 2;;\n'
                'esac\n'
                'cat > "$LOG.stdin"\n'
                'echo \'{"users": []}\'\n')
    os.chmod(os.path.join(fake, "docker"), 0o755)

    def run(role, names="user_1 42"):
        log = os.path.join(work, "log%s" % role)
        for p in (log, log + ".stdin"):
            if os.path.exists(p):
                os.remove(p)
        e = dict(os.environ, LOG=log.replace("\\", "/"), ROLE=str(role), SSH_ORIGINAL_COMMAND=names,
                 FAKE=fake.replace("\\", "/"), SCRIPT=os.path.join(HERE, "panel_user_info.sh").replace("\\", "/"),
                 MSYS_NO_PATHCONV="1")
        r = subprocess.run([BASH, "-c", 'PATH="$(cd "$FAKE" && pwd):$PATH" bash "$SCRIPT"'], capture_output=True,
                           text=True, encoding="utf-8", env=e, timeout=60)
        calls = open(log, encoding="utf-8").read().splitlines() if os.path.exists(log) else []
        stdin = open(log + ".stdin", encoding="utf-8").read() if os.path.exists(log + ".stdin") else ""
        return r, calls, stdin

    r, calls, stdin = run(0)
    check("роли нет — запрос, как раньше, под postgres; ответ — одна строка JSON",
          r.returncode == 0 and r.stdout == '{"users": []}\n' and len(calls) == 2
          and "-U watch_ro" in calls[0] and "-U postgres" in calls[1] and "select json_build_object" in stdin)
    r, calls, stdin = run(1)
    check("роль есть — запрос под watch_ro; вывод проверки в ответ не попадает",
          r.returncode == 0 and r.stdout == '{"users": []}\n' and len(calls) == 2
          and "-U watch_ro" in calls[1] and "-U postgres" not in " ".join(calls)
          and "default_transaction_read_only=on" in calls[1])
    check("проверка роли — фиксированный select 1, без имён из команды и без postgres",
          "select 1" in calls[0] and "user_1" not in calls[0] and "-U postgres" not in calls[0])
    r, calls, _ = run(1, "*")
    check("шаблон в команде не раскрывается, docker не зовётся", r.stdout.strip() == '{"error": "bad name"}'
          and calls == [])
    shutil.rmtree(work, ignore_errors=True)
else:
    print("ПРОПУСК проверок скрипта: нет bash")
print("роль базы только на чтение: тестов пройдено %d" % ok)
