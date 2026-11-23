-- Роль базы панели Remnawave только на чтение для скрипта сведений о пользователе (panel_user_info.sh,
-- на сервере панели /usr/local/sbin/watch-user-info). Отдельная роль базы только на
-- SELECT вместо postgres.
--
-- Что делает:
--   роль watch_ro: LOGIN без пароля, не суперпользователь, без прав создавать базы и роли;
--   вход — только изнутри контейнера remnawave-db (docker exec … psql: локальный сокет, по умолчанию образа postgres
--   «local all all trust»); снаружи контейнера (сеть Docker, проброшенный порт) — scram-sha-256, а пароля у роли нет;
--   CONNECT на текущую базу, USAGE на схему public, SELECT только на пять таблиц, которые читает скрипт:
--   users, user_traffic, nodes, hwid_user_devices, user_subscription_request_history;
--   по умолчанию у роли транзакции только на чтение и statement_timeout 15 с (скрипт задаёт их и сам).
-- Повторный запуск безопасен: роль есть — не создаётся заново, права выдаются повторно без ошибки.
-- Всё одной транзакцией: при ошибке (например, в новой версии панели таблица переименована) не меняется ничего.
--
-- Как применить (на сервере панели, под root):
--   docker exec -i remnawave-db psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f - < panel_ro_role.sql
-- или через файл в контейнере:
--   docker cp panel_ro_role.sql remnawave-db:/tmp/panel_ro_role.sql
--   docker exec remnawave-db psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /tmp/panel_ro_role.sql
--   docker exec remnawave-db rm -f /tmp/panel_ro_role.sql
-- Проверка: docker exec remnawave-db psql -U watch_ro -d postgres -At -c 'select count(*) from users'
--   (число — роль работает; запись должна падать: … -c 'delete from users where false' → permission denied).
-- После этого watch-user-info сам переходит на watch_ro (проверяет входом под ней), ставить заново не нужно.
-- Откат: docker exec -i remnawave-db psql -U postgres -d postgres -c 'DROP OWNED BY watch_ro; DROP ROLE watch_ro'
--   (скрипт снова пойдёт под postgres, как раньше).
-- Замечание: в Postgres до 15 у PUBLIC есть CREATE на схему public; там от создания своих таблиц держит только
-- транзакция только на чтение. Права PUBLIC здесь не трогаются: это настройка базы панели, не наша.

\set ON_ERROR_STOP on
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'watch_ro') THEN
    CREATE ROLE watch_ro LOGIN;
  END IF;
END
$$;

ALTER ROLE watch_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD NULL;
ALTER ROLE watch_ro SET default_transaction_read_only = on;
ALTER ROLE watch_ro SET statement_timeout = '15s';

DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO watch_ro', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO watch_ro;
GRANT SELECT ON TABLE users, user_traffic, nodes, hwid_user_devices, user_subscription_request_history TO watch_ro;

COMMIT;
