#!/bin/bash
# Сторож: превышение лимита устройств и подписки без HWID — ТОЛЬКО ЧТЕНИЕ базы панели Remnawave (Postgres в контейнере
# remnawave-db). Владелец 27.11: «давай клиенты сначала сделаем слежение превышения на сторож, пока только мониторинг».
# Ставится на сервер панели: install -m 755 panel_devices.sh /usr/local/sbin/watch-devices и вызывается только своим
# ключом сторожа (отдельным от watch-user-info):
#   from="<адрес сторожа>",command="/usr/local/sbin/watch-devices",restrict ... в /root/.ssh/authorized_keys
# Слов не принимает: любое слово в команде ssh (SSH_ORIGINAL_COMMAND) — отказ, база не читается.
#
# Лимит подписки: свой (users.hwid_device_limit) или, если он NULL, общий запасной из панели — FALLBACK_LIMIT ниже
# (сейчас в панели 999). Поменяли общий лимит в панели — поменять и здесь, иначе превышения у подписок с NULL не видны.
# 0 — без ограничения; 999 и больше — практически без ограничения. Такие подписки не в счёт.
#
# Печатает одну строку JSON, только АКТИВНЫЕ подписки, не больше 200 строк в каждом списке:
#   {"over":   [{id, username, tg, status, limit, limit_common, devices, active30, last_seen}] — устройств больше лимита;
#    "nohwid": [{id, username, tg, limit, limit_common, devices, ua_families, last_request}] — только подписки с
#              действующим лимитом (1–998): за 7 дней были запросы подписки из VPN-программы (белый список ниже), а ни
#              один запрос этой программы за 30 дней не стоит ближе 120 с к появлению или обновлению какого-либо
#              устройства этого пользователя (панель обновляет устройство при каждом запросе с HWID), или устройств нет
#              совсем. Панель 3.4.11 программам без x-hwid отдаёт подписку целиком, лимит на них не действует.
#              Не ловит: второй экземпляр той же программы без HWID (например, INCY на Linux при INCY с HWID на
#              телефоне) и программу без HWID, которая обновляет подписку в ту же минуту, что и программа с HWID.
#              Ложное «без HWID» возможно у подписки, упёршейся в лимит (новое устройство панель не записала) —
#              сторож помечает такие строки сам (устройств ≥ лимита);
#    "other":  [{fam, users, requests}] — запросы за 7 дней не из VPN-программ (браузер, превью Telegram, curl,
#              пустая строка клиента и т. п.), только счёт, без пользователей, не больше 10 строк;
#    "ts": время базы}
# Время — секунды UTC. Адресов клиентов в выдаче нет. Ничего не пишет.
# Роль базы — как в watch-user-info: watch_ro (panel_ro_role.sql), если готова (проверка входом под ней и пробным
# запросом к тем же таблицам, строк не читает); нет роли — postgres. Транзакция в любом случае только на чтение,
# statement_timeout 15 с.
set -euo pipefail
set -f
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ] || [ "$#" -gt 0 ]; then
  echo '{"error": "no arguments accepted"}'
  exit 1
fi
FALLBACK_LIMIT=999
db_user=postgres
ro_check='select 1 from users, hwid_user_devices, user_subscription_request_history limit 0'
if timeout 10 docker exec remnawave-db psql -U watch_ro -d postgres -At -v ON_ERROR_STOP=1 -c "$ro_check" \
     </dev/null >/dev/null 2>&1; then
  db_user=watch_ro
fi
docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=15000' remnawave-db \
  psql -U "$db_user" -d postgres -At -v ON_ERROR_STOP=1 -v fallback="$FALLBACK_LIMIT" <<'SQL'
with lim as (
  select u.id, u.username, u.telegram_id as tg, u.status,
         coalesce(u.hwid_device_limit, :fallback) as eff, u.hwid_device_limit is null as common
  from users u where u.status = 'ACTIVE'
),
dev as (
  select d.user_id, count(*) as devices,
         count(*) filter (where d.updated_at > now() - interval '30 days') as active30,
         max(d.updated_at) as last_seen
  from hwid_user_devices d group by d.user_id
),
ov as (
  select l.id::text as id, l.username, l.tg, l.status, l.eff as "limit", l.common as limit_common,
         dev.devices, dev.active30,
         extract(epoch from (dev.last_seen at time zone 'UTC'))::bigint as last_seen
  from lim l join dev on dev.user_id = l.id
  where l.eff > 0 and dev.devices > l.eff
  order by dev.devices - l.eff desc, l.username
  limit 200
),
req as (
  select h.user_id, h.request_at, t.tok,
         case t.tok
           when 'incy' then 'INCY' when 'happ' then 'Happ' when 'v2rayng' then 'v2rayNG' when 'v2rayn' then 'v2rayN'
           when 'v2raytun' then 'v2raytun' when 'nimbo' then 'Nimbo' when 'streisand' then 'Streisand'
           when 'hiddify' then 'Hiddify' when 'hiddifynext' then 'Hiddify' when 'v2box' then 'V2Box'
           when 'foxray' then 'FoXray' when 'shadowrocket' then 'Shadowrocket' when 'karing' then 'Karing'
           when 'nekobox' then 'NekoBox' when 'nekoray' then 'NekoBox' when 'sing-box' then 'sing-box'
           when 'clash' then 'Clash' when 'clash-verge' then 'Clash' when 'clashmeta' then 'Clash'
           when 'mihomo' then 'Clash' when 'flclash' then 'Clash' when 'xray' then 'xray'
         end as fam
  from user_subscription_request_history h join lim l on l.id = h.user_id
  cross join lateral (select lower(substring(h.user_agent from '^[A-Za-z][A-Za-z0-9._-]*')) as tok) t
  where h.request_at > now() - interval '30 days'
),
dt as (
  select d.user_id, d.updated_at as t from hwid_user_devices d
  union all
  select d.user_id, d.created_at from hwid_user_devices d
),
fam as (
  select r.user_id, r.fam, max(r.request_at) as last_req, bool_or(dt.user_id is not null) as has_dev
  from req r join lim l on l.id = r.user_id and l.eff between 1 and 998
  left join dt on dt.user_id = r.user_id
       and dt.t between r.request_at - interval '120 seconds' and r.request_at + interval '120 seconds'
  where r.fam is not null
    and r.user_id in (select q.user_id from req q where q.request_at > now() - interval '7 days')
  group by r.user_id, r.fam
),
nh as (
  select l.id::text as id, l.username, l.tg, l.eff as "limit", l.common as limit_common,
         coalesce(dev.devices, 0) as devices,
         json_agg(f.fam order by f.fam) as ua_families,
         extract(epoch from (max(f.last_req) at time zone 'UTC'))::bigint as last_request
  from fam f join lim l on l.id = f.user_id left join dev on dev.user_id = l.id
  where not f.has_dev and f.last_req > now() - interval '7 days'
  group by l.id, l.username, l.tg, l.eff, l.common, dev.devices
  order by max(f.last_req) desc
  limit 200
),
oth as (
  select coalesce(left(r.tok, 24), '?') as fam, count(distinct r.user_id) as users, count(*) as requests
  from req r
  where r.fam is null and r.request_at > now() - interval '7 days'
  group by 1
  order by 2 desc, 1
  limit 10
)
select json_build_object(
  'over', coalesce((select json_agg(o) from ov o), '[]'::json),
  'nohwid', coalesce((select json_agg(n) from nh n), '[]'::json),
  'other', coalesce((select json_agg(x) from oth x), '[]'::json),
  'ts', extract(epoch from now())::bigint);
SQL
