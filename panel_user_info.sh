#!/bin/bash
# Сторож: кто из ваших клиентов попал в список сканеров — ТОЛЬКО ЧТЕНИЕ базы панели Remnawave (Postgres в контейнере remnawave-db).
# Ставится на сервер панели: install -m 755 panel_user_info.sh /usr/local/sbin/watch-user-info и вызывается только ключом сторожа:
#   from="<адрес сторожа>",command="/usr/local/sbin/watch-user-info",restrict ... в /root/.ssh/authorized_keys
# Имена пользователей или номера (id — так клиент записан в журнале Xray) — в команде ssh через пробел (SSH_ORIGINAL_COMMAND), не больше 20, только [A-Za-z0-9_.@-].
# Печатает одну строку JSON: {"users": [{id, username, status, expire, created, tg, desc, tag, online, node, traffic_gb,
#   devices, ua}]}; время — секунды UTC. Ничего не пишет.
# Рекомендация: вместо postgres — отдельная роль базы только на чтение, например
#   create role watch_ro login; grant select on users, user_traffic, nodes, hwid_user_devices,
#   user_subscription_request_history to watch_ro;   и ниже psql -U watch_ro
# (транзакция и так только на чтение, но роль без прав на запись — второй замок).
set -euo pipefail
set -f   # SSH_ORIGINAL_COMMAND режется на слова без раскрытия шаблонов (* не превращается в имена файлов)
names=()
for n in ${SSH_ORIGINAL_COMMAND:-}; do
  [[ "$n" =~ ^[A-Za-z0-9_.@-]{1,64}$ ]] || { echo '{"error": "bad name"}'; exit 1; }
  names+=("$n")
done
[ "${#names[@]}" -ge 1 ] && [ "${#names[@]}" -le 20 ] || { echo '{"error": "need 1-20 names"}'; exit 1; }
list=$(IFS=,; echo "${names[*]}")
docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=15000' remnawave-db \
  psql -U postgres -d postgres -At -v ON_ERROR_STOP=1 -v names="$list" <<'SQL'
select json_build_object('users', coalesce(json_agg(t order by t.username), '[]'::json)) from (
  select u.id::text as id, u.username, u.status,
         extract(epoch from (u.expire_at at time zone 'UTC'))::bigint as expire,
         extract(epoch from (u.created_at at time zone 'UTC'))::bigint as created,
         u.telegram_id as tg, left(u.description, 160) as desc, u.tag,
         extract(epoch from (tr.online_at at time zone 'UTC'))::bigint as online,
         n.name as node,
         round(coalesce(tr.lifetime_used_traffic_bytes, 0) / 1e9, 1) as traffic_gb,
         (select count(*) from hwid_user_devices d where d.user_id = u.id) as devices,
         left(h.user_agent, 80) as ua
  from users u
  left join user_traffic tr on tr.id = u.id
  left join nodes n on n.uuid = tr.last_connected_node_uuid
  left join lateral (select user_agent from user_subscription_request_history
                     where user_id = u.id order by request_at desc limit 1) h on true
  where u.username = any(string_to_array(:'names', ',')) or u.id::text = any(string_to_array(:'names', ','))
) t;
SQL
