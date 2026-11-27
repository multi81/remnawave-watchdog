<div align="center">

# 🛡 Remnawave Watchdog

[Русский](README.md) | **English**

**A watchdog for a VPN service built on Remnawave.**
It looks at your VPN the way a client inside Russia sees it and tells you in Telegram what broke, why, and what it means for your users.

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Ubuntu 24.04 / 26.04](https://img.shields.io/badge/ubuntu-24.04%20%7C%2026.04-orange)
![Remnawave + Xray](https://img.shields.io/badge/Remnawave-Xray-7b5cff)
![No dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

[Features](#-features) · [Telegram messages](#-what-it-looks-like-in-telegram) · [Installation](#-installation) · [Configuration](#%EF%B8%8F-configuration) · [Security](#-security)

</div>

---

Regular monitoring tells you "the server is up". That is no comfort to a client whose ISP is throttling the connection
and whose subscription won't load. The watchdog sits **inside the Russian network** and every two minutes walks the
same path your clients do: through every entry (tile) of the subscription, to the same sites and services.

- 🇷🇺 **A view from inside Russia:** sees blocking, connection freezes (DPI) and DNS spoofing that are invisible from abroad.
- 🧠 **Explains, not just alarms:** is it blocking or a broken node, an attack or just clients downloading a lot?
- 🤝 **Never acts on its own:** blocking addresses or cutting traffic happens only when you press a button in Telegram.
- 🪶 **Lightweight:** Python 3 and stock Ubuntu utilities, no packages or databases; 1 CPU core and 1 GB of RAM are enough; opens no inbound ports.


## ✨ Features

### 📡 Channels — every 2 minutes
Fetches a service subscription from Remnawave, starts a local Xray client and checks **every tile**:

| Check | What you see |
|---|---|
| Is the channel alive | ✅ working · 🔴 unreachable — with two attempts and confirmation, no false alarms |
| Speed | 🐢 slow — measured on a download long enough for the connection to ramp up |
| Freezing | 🧊 throttled — the connection is up but data stalls (typical DPI at 16–20 KB) |
| Exit | 🔀 wrong exit — for cascades, the expected exit address is verified |
| Ping and connect time | growth compared with what is normal for this channel (30-minute median vs. the week) |
| Services through the channel | Telegram, YouTube, Instagram, ChatGPT |

If every channel is slow at once, the watchdog says so: the problem is its own server, not the nodes.

- **A mass outage — one message.** If many channels go down or get throttled at once, the watchdog diagnoses 2
  representative channels from 2–3 vantage points and sends a single summary: what is down, what is throttled, what it
  looks like, then one shared reminder and one shared recovery notice. If no channel works and rf1 can reach neither the
  vantage points nor the node entry addresses, it says exactly that: the problem is rf1's own network, not the nodes.
- **A flapping channel — no avalanche.** "Unreachable" and "throttled" alternating count as one problem. When ping or
  connect time keeps rising and falling back (a third change within an hour), you get one "flapping" message and then
  silence until "settled down".
- A watchdog run is capped at 170 seconds (the service timeout): outage analysis doesn't start when time is short, and
  alerts are saved before sending, so an interrupted send goes out on the next run.

### 🚧 Blocking
- When a channel goes down, the watchdog works out the cause itself: ping, port, TLS, a cutoff at 16–20 KB, a view
  from other Russian vantage points and from abroad, traceroute.
- **The node refusing vs. blocking on the way.** The witness counters on the node show whether the probe's SYN
  arrived: the node received it and stayed silent or reset the connection itself — that is not blocking but the node
  banning the vantage point (or watchdog) addresses; it never arrived — it is being cut somewhere along the path.
- **From abroad — through two different channels** with a control site (`www.gstatic.com`): "not responding" counts
  only if the control address opened through that same channel. The node itself gets no more than two requests, so as
  not to trigger its anti-scan protection.
- **A view from Russian home networks (Globalping, optional).** Your own vantage points usually sit in data centers.
  When a node entry won't open from rf1 or from a vantage point, the watchdog asks [Globalping](https://globalping.io)
  whether the same address and port open over TCP for subscribers of ordinary ISPs (MTS, Beeline, Rostelecom,
  Dom.ru…) and, for comparison, from two points in Europe. You can see whether it is closed across all of Russia, at some
  ISPs, or only for data centers. More in [Configuration](#%EF%B8%8F-configuration).
- **An entry fully closed from one vantage point.** Background loss measurement: if not a single connection from a
  vantage point got through while the node opens from rf1, you get one fact-based message; a vantage point that has most
  nodes closed is a problem with the vantage point itself.
- Every 6 hours it checks your addresses and domains against public blocklists and shows your neighbors in the
  registry. List freshness is based on the last **successful** download of each list: if one hasn't downloaded for a
  long time, there is a line in the report, and a stale copy is never passed off as fresh.
- Checks whether ordinary DNS spoofs the addresses of your sites and nodes: the system DNS of the watchdog server and
  of the vantage points against secure DoH. Your names are never sent to public DNS over plain UDP — those are asked
  only about other people's names.
- Tracks the country and network of node addresses across five geo databases: it will notice if "Germany" suddenly
  became "USA".
- **Checks the subscription template against blocking.** Every 6 hours it tests popular services directly from Russia
  layer by layer (DNS, TCP, TLS, block page) and parses the rules of every subscription tile (domain/full/regexp,
  geosite and geoip from the node's `geosite.dat`/`geoip.dat`, `domainStrategy`). If the template routes a service
  directly but it is blocked from Russia, you get an alert: clients on that tile won't be able to open it. Tiles that
  route everything directly ("for use abroad") are not checked; Russian services are only noted (some of them reject
  hosting addresses). Services are best checked from a vantage point at an ordinary ISP (`"rucheck": true` in
  `vantage.json`): a data center often doesn't cut what home connections get cut; if it doesn't respond, the check runs
  from the watchdog itself with a note in the report. A vantage point running agent 8 also reports "throttled" (data
  stalls mid-response, and after how many KB); a new "throttled" alerts from the second consecutive run. The idea of
  layered checks comes from [rkn-block-checker](https://github.com/MayersScott/rkn-block-checker).

### 🌐 Sites, subscription, certificates
- Panel, user portal and your other sites — directly from Russia; the subscription page — by **actually downloading**
  the subscription.
- Certificate and domain registration expiry: warns in advance and tells you when it has been renewed.
- Subscription changes: which tiles appeared, disappeared or changed.

### 💥 DDoS and load — every minute
- Each server runs a lightweight collector (5% CPU, 64 MB): traffic and packets on the external interface, SYN flood,
  queue overflows, CPU, memory, disk, swap, failed services.
- **Thresholds adapt automatically** to each server's normal load (weekly p95).
- A VPN node that is simply serving a lot of client traffic is **not treated** as under attack: the watchdog compares
  inbound and outbound traffic.
- Attack type (SYN flood, UDP, ICMP, volumetric, packet-rate), severity, protocols and targeted ports.
- Docker containers: what went down, why (by exit code), what it means for clients; restart loops.
- 💾 **Backups** of the panel, the bot, the subscription page — anything that writes a log: the collector on the server
  reads the log, and the watchdog tells you when there hasn't been a successful backup for too long or the last attempt
  failed, and again when everything is fine. The report shows the time and size of the latest copy of each backup.
- **Permanent and temporary containers are handled separately.** Permanent ones (with a restart policy, from docker
  compose, or named in `critical_containers` / `permanent_containers`) are covered by alerts. Temporary ones (a one-off
  `docker run`) raise no alerts: when they exit or are removed, it is a line in the report.

### 🛡 Flood shield — with buttons in Telegram
- Its own nftables table, which by default **only counts** who opens too many new connections.
- On an attack or a suspicious address you get **one message** with the sources and buttons.
- Knows your clients (from the Xray log) and marks them: hundreds of people can sit behind one mobile carrier address.
- Blocks and an enabled shield **lift themselves** on a timer. The "Это не атака" ("Not an attack") button raises the
  server's threshold for a week.
- Gate: panel ports can be opened to your own addresses only.
- Chat commands: `/shield` — what is blocked where, `/unblock` — lift everything.

### 🔭 Scanners
- A combined list of scanner networks is re-downloaded once a day and distributed to all servers. Sources:
  | List | Contents |
  |---|---|
  | `government_networks` ([shadow-netlab](https://github.com/shadow-netlab/traffic-guard-lists)) | government networks |
  | `skipa` (shadow-netlab) | SKIPA — Roskomnadzor scanners |
  | `antiscanner` (shadow-netlab) | internet scanners |
  | `c24be_gov` ([C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List)) | Russian government agency networks, IPv4 and IPv6 |
  | `antiscanner_sngvy` ([sngvy/AntiScanner](https://github.com/sngvy/AntiScanner)) | scanners and subscription harvesters |
  | `scanners-extra.txt` | your own additions |
  | `behavior` (our own, `behavscan.py`) | who knocked on closed ports of your servers — scanners that aren't in anyone else's lists |
- Each list is validated: downloaded, parsed, didn't shrink sharply; otherwise the previous copy is used and you get a
  message.
- By default hits are **only counted**; dropping is enabled by a separate command once you are sure none of your
  clients are on the list. Your own addresses and servers are always removed from the list.

### 📊 Reports
- A full report three times a day: channels, services, sites, certificates, domains, subscription, servers.
- A weekly summary on Mondays: availability, outages, speed and ping per channel.
- 🐕 **A watchdog for the watchdog** (`guard.py`) on another server: if the watchdog itself goes down or loses
  connectivity, you get a message too.

## 🆕 What's new

**27.11.2026 — device monitoring** (`devicewatch.py`, `panel_devices.sh`, tests — `test_devicewatch.py`). Monitoring
only, nothing is changed in the panel. Once an hour the watchdog reads the panel database through a separate
`watch-devices` command (read-only, `watch_ro` role, its own key with `from=`, `command=`, `restrict`; any extra words in
the command are refused) and once a day sends a summary: subscriptions with more devices than their HWID limit, and
limited subscriptions fetched by an app that does not send HWID (the panel serves them the subscription without applying
the limit). New/changed items are marked, own subscriptions are skipped via `skip_users` / `skip_prefixes`, client
addresses never appear in messages. Settings — `/etc/channel-watch/devices.json` (`summary_hour`, `alert_new_over` — off
by default).

**25.11.2026 — more precise outage analysis and a view from home networks** (watchdog, vantage agent 8,
`globalping.py`; tests — `test_globalping.py`, `test_witness_refusal.py`, `test_abroad.py`, `test_mass_outage.py`,
`test_loss_shut.py`, `test_lists_fresh.py`, `test_rucheck.py`)
- 🏠 **Globalping — a view from Russian home networks**, optional (`globalping.py`, `/etc/channel-watch/external.json`,
  sample — `examples/external.example.json`). Queried only when a node entry already fails to open from rf1 or from a
  vantage point: a TCP handshake to the same address and port from 8 probes on ordinary ISP networks plus one each in
  DE and NL. Only the entry's IP address and port leave your servers — never the node name, domains or users.
  Globalping results are public to anyone with the measurement ID and are kept for up to six months: treat any address
  you send as published. Gentle on the API: a per-address answer is cached for 20 minutes, the budget is 120 checks per
  hour (free tier: 250), with an optional key `/etc/channel-watch/globalping.token` (600) — 300 (free tier: 500); a 429
  response pauses until the limit resets. To disable — `"enabled": false` or delete the file: then nothing is sent out.
- 🚪 **A ban on the node vs. blocking on the way:** based on the witness counters, the analysis says "это не
  блокировка" ("this is not blocking") — the node received the SYN and stayed silent or reset the connection itself
  (banned the vantage point addresses, closed itself off from the watchdog's address); the loss message says "часть
  подключений отбрасывает сама нода" ("the node itself drops some connections").
- 🌍 **From abroad — two channels and a control site:** "not responding" is confirmed only by a channel through which
  the control address opened; if none got through — "проверить не удалось" ("couldn't check"), not a false block.
- 〰️ **A flapping channel** — one "flapping" message and one "settled down"; "unreachable" and "throttled" alternating
  count as one problem.
- 📣 **A mass outage of many channels** — one summary analyzing 2 representatives from 2–3 vantage points, one shared
  reminder and recovery notice; a separate verdict "rf1's own network is down" when it can reach neither the vantage
  points nor the entries.
- 🧊 **"Throttled" in the template check:** vantage agent 8 reports after how many KB data stalls; the alert fires from
  the second consecutive run.
- 📋 **Blocklist freshness** — based on the last successful download of each list (curl -f; a placeholder page instead
  of a list doesn't count); a list that hasn't downloaded for a long time gets a line in the report.
- 🚫 **An entry fully closed from one vantage point** — one message; a vantage point with most nodes closed is a problem
  with the vantage point.
- 🩺 **Node DNS:** instead of "queue overflowing" — "DNS отвечает медленно" ("DNS is responding slowly") (share of
  answers slower than 1.9 s among cache-miss lookups), with no noise right after a restart.
- ⏱ A watchdog run lasts no longer than 170 s (`TimeoutStartSec`), leaving headroom for sending to Telegram.
- Upgrade: watchdog — `bash install.sh --yes`; vantage points — `bash vantage_update.sh` (agent 8). Globalping is
  optional: `cp examples/external.example.json /etc/channel-watch/external.json`.

**23.11.2026 — the node's own DNS: fallback on every query** (`node_dns.sh install --per-query`) — against
systemd-resolved "sticking" to the fallback DNS while Unbound is healthy; the timer no longer restarts Unbound because of
a single slow recursion (only if it failed to answer twice in a row or the service died), and rollback waits for a
running check to finish.

**23.11.2026 — security and reliability, part 4** (watchdog, beacon, witness, vantage point, shield; tests —
`test_socks_auth*.py`, `test_beacon_serve.py`, `test_witness_user.py`, `test_sandbox.py`, `test_shield_allow_sync.py`,
`test_panel_ro.py`, `test_shield.py`)
- 🔐 **Password on the local SOCKS ports** of the watchdog and the VPN vantage point: `build_channels.py --socks-auth`
  creates `/etc/channel-watch/socks.auth` (600) once, with a random username and password — otherwise any process on
  the server could reach the network through your nodes. The password never appears in arguments: curl gets it via
  standard input (`-K -`), Xray from its own config. All modules support both modes, and `--socks-auth` first checks
  that every module alongside it supports the password — so it switches on with no downtime. Without the file the ports
  have no password, as before.
- ✂️ **`dialerProxy` from the subscription is stripped at any depth** (including `sockopt` inside transport settings),
  not only at the top level: the watchdog's channel won't go through someone else's chain.
- 🏷 **MSS marks are configurable:** `"mss_mark": [start, end]` in the watchdog's `/etc/channel-watch/site.json`, in the
  vantage point's `agent.json` and in the witness's `/etc/node-witness/site.json`. During a changeover the witness
  accepts several ranges at once (`[[old], [new]]`). Without the setting — the previous range.
- 🧭 **Fallback DNS — DoH by IP only** (`1.1.1.1`, `8.8.8.8`): if the system DNS fails to resolve a node entry name, the
  name no longer goes out over plain UDP to public resolvers.
- 📡 **Beacon `--serve` — its own server `beacon_serve.py`:** HTTP and TLS on one port, a self-signed certificate; the
  installer prints its fingerprint as a `BEACON-SHA256` line; put it as `"sha256"` for the node in `nodes.json` and the
  watchdog switches to TLS and verifies the certificate. `--tls-only` closes HTTP. The watchdog also fetches the
  witness's `flows.json` over TLS. Connections from unknown addresses are dropped before they take up resources, and
  every connection has an overall deadline.
- 🛡 **Shield, allow-sync:** once a day the watchdog sends the shields its own addresses — your addresses
  (`owner.txt`), the `ddos.json` servers and its own external address; networks no wider than /24 and /64. The shield
  keeps them separately (`allow-sync.txt`), honors them everywhere allow applies, and lifts blocks from addresses that
  have become trusted. An old shield doesn't know the command — there is a note in the report.
- 🗄 **A read-only role for the panel database** (`panel_ro_role.sql`): `SELECT` on five tables, read-only
  transactions. `watch-user-info` switches to it automatically when it exists; otherwise it works as before.
- 🧱 **systemd sandbox for an already running watchdog** (`sandbox_dropins.sh`): the same settings `install.sh` writes,
  as separate drop-ins without reinstalling, with a test start of the services and rollback on failure; `--dry` — show,
  `--rollback` — remove.
- Upgrade: watchdog — `bash install.sh --yes`, then `python3 /opt/channel-watch/build_channels.py --socks-auth` and
  `systemctl restart channel-watch-xray`; nodes — `beacon_install.sh` again with the same parameters (with
  `beacon_serve.py` alongside), the fingerprint goes into `nodes.json`, and once everything works — `--tls-only`;
  shields — the new `shield_ctl.py` (or re-run `server_install.sh`).

**23.11.2026 — security and reliability, part 3: secrets, vantage point, witness, DDoS thresholds** (watchdog,
vantage agent 7, installers; tests — `test_ddos_thresholds.py`, `test_netprobe_dns.py`, `test_vantage.py`,
`test_witness.py`, `test_tls_dns_installers.py`, `test_probe.py`, `test_guard.py`)
- 🔑 **Secrets don't show up in the process list:** curl gets the bot token and message text via standard input
  (`-K -`) rather than as arguments — both in the watchdog and in the shield buttons.
- 📨 **Telegram doesn't lose a batch of alerts:** a long batch is sent one alert at a time right away; a batch Telegram
  rejected is resent one by one — only the bad one is lost (its beginning goes to the log); a rejected full report is
  not retried every 2 minutes.
- 💓 **A short heartbeat:** `heartbeat.path` holds only the start time, the last report, the queue and whether there is
  internet, with no list of nodes (the file sits in the site folder). The full heartbeat with nodes and sites is written
  only if a path is set in `heartbeat-full.path`; the same path in both files means one full file, as before. Writes go
  through a private temp file (`mkstemp`): a planted symlink can't redirect the write into someone else's file.
- 🧭 **Your node names don't go out over plain DNS to public resolvers.** Your names are checked with the system DNS of
  the watchdog server and vantage points against secure DoH; public DNS over UDP is asked only about neutral third-party
  names — that is enough to see whether answers are spoofed on the way. The "Подмена DNS" ("DNS spoofing") alert fires
  only on 2 independent mismatches; a single mismatch goes to the log.
- 🔐 **The TLS probe verifies the certificate where the diagnosis needs it:** for channels with regular TLS (CDN), outage
  analysis tells "wrong certificate" apart from "no connectivity"; for Reality the certificate isn't verified. Reading
  the response (`pull`) is done in chunks, with a deadline on each chunk and a size limit.
- 💥 **DDoS thresholds don't learn from attacks:** only clean samples go into the baseline (no attacks, their
  confirmation or traffic skew); a threshold may grow by no more than ×1.5 per day and ×2 per week, capped by the link
  speed (`link_mbps` in `ddos.json`). A symmetric flood (the node answers with the same volume) is caught without skew:
  inbound excess over outbound, growth against the norm, ICMP, a saturated link.
- 📍 **Vantage point (agent 7):** TLS on the same port with a pinned fingerprint (`"sha256"` in `vantage.json`, printed
  by `vantage_install.sh --entry`); connections from unknown addresses are dropped before the request is read;
  responses carry no server signature; strict name validation per DNS rules; the service runs as a temporary user
  (DynamicUser), settings and key are readable only by root; `--public ADDRESS` for a vantage point behind NAT.
  Reinstalling keeps the `allow` list (unless `--allow` is given) and removes the old ufw rule when the address or port
  changes.
- 🐕 **Watchdog for the watchdog:** before reporting "сторож недоступен" ("watchdog unreachable"), guard checks a
  control host (`api.telegram.org:443`, key `GUARD_CONTROL`) — if guard itself has no network, there is no alert; a
  malformed heartbeat doesn't crash it.
- 👁 **Witness on the node:** tcpdump parses packets as a separate user, the filter covers only marked connections to
  your own addresses, memory and file size are capped, writes go through a private temp file; the service runs in a
  systemd sandbox.
- 📡 **Beacon `--serve`:** the ufw rule is added only if ufw is enabled (otherwise the installer warns that the port is
  open to everyone); the rule is removed without `sh -c`; the watchdog address and port are validated.
- 🧱 **systemd sandbox for the watchdog services** (`install.sh`): Xray runs as a temporary user with no privileges,
  Python services write only to their own directories, `/var/log` and the heartbeat directory. What couldn't be
  tightened: the Python services still run as root — they read `sub.url` and `guard.env`, talk to docker and trace TCP
  SYN.
- 🧪 Tests don't depend on the machine's time zone or on proxies in the environment.
- Upgrade: watchdog — `bash install.sh --yes`; vantage points — `bash vantage_install.sh --yes`, then re-register
  (`--entry … | … --add-vantage`; the entry will now contain `"sha256"`) and, once everything works, `--tls-only`; on
  nodes — `beacon_install.sh` again with the same parameters, then `witness_install.sh`.

**23.11.2026 — security and reliability, part 2: shield** (`shield-ctl` 1.4.0, `ddos-collect` 1.8.0, installers;
tests — `test_shield.py`, `test_scanners.py`, `test_shield_warn.py`)
- 🛡 **Dropping scanners is now safe.** The rule sits after conntrack: only new inbound connections from listed
  addresses are cut (plus ct invalid packets — FIN/NULL/XMAS scans, unsolicited SYN-ACK), while replies to the server's
  own outbound connections (Telegram, GitHub, sites for clients), your addresses and your clients are never cut. Note: in
  "count" mode the hit counter now counts only new connections — the numbers are noticeably lower than before.
- 🔒 **Shield commands don't interfere with each other:** a lock is held for the duration of a command (previously a
  block pressed while a timed unblock was running could vanish from the state); the scanner list is read before taking
  the lock.
- **IPv6:** the shield refuses to block a /64 if it overlaps your addresses (not only if it matches them).
- **Honest status:** an "enabled" mode whose time has run out is cleared by any command; `status` and `/shield` show
  whether the kernel is actually dropping, whether the unblock timer is alive, and the table version in the kernel
  (`table_v`); if something is wrong two polls in a row, you get an alert. "Срок неизвестен" ("expiry unknown") instead
  of a made-up time.
- **Clients from the Xray log** — only lines where `accepted` directly follows the address (a rejection line with that
  word in the reason no longer makes the address a "client").
- **Installers:** re-running `server_install.sh` applies the update (restarts only what changed, takes parameters from
  the previous install); the shield service waits for the network and restarts on failure; the shield's own addresses
  are the watchdog address, the server's addresses and `--allow`; `install.sh --uninstall` first switches the shields to
  observe mode; `install_ddos.sh add` won't silently trust a changed server key (`--rekey`); the shield log is rotated.
- Upgrading running servers: new `shield_ctl.py` → `/usr/local/sbin/shield-ctl`, `systemctl restart
  storozh-shield` (mode, blocks, clients and scanner lists are preserved), or re-run `server_install.sh`.

**23.11.2026 — security and reliability, part 1** (the "behavior" list, scanner lists, beacon, `node_dns.sh`,
`node_tune.sh`; a test for every fix, `test_scan_behavior.py`, `test_beacon.py`)
- 🔎 **The "behavior" list (`behavscan.py`) is now hard to poison:**
  - an address is added only if within one day it knocked on at least 2 servers and the knocking recurred on another
    day; the same knock isn't counted twice if a run happened before and after midnight;
  - mobile addresses are never added, residential ones only with 10+ ports and knocks on 2+ servers;
  - a "never add" list (`scanlists.NEVER_LIST`): Telegram, Cloudflare, GitHub, ip-api networks, public DNS — IPv4 and
    IPv6; they are also stripped from third-party lists;
  - matching against your clients didn't always work (the shield rejected requests with more than 60 addresses, and the
    rejection was read as "no clients"): now it goes in chunks of 50, shields are polled in parallel, and if even one
    doesn't answer, no new addresses are added this time;
  - "ours" now also includes servers from nodes.json and vantage.json (names are resolved to addresses); IPv6 — by /64;
  - beacon lines aren't taken on faith: ports, numbers, public addresses only; a faulty beacon doesn't crash the run.
- 📋 **Third-party scanner lists (`scanlists.py`):** if a list grows more than 1.5× (by networks or addresses), the
  previous copy is used and you get a message with the command to accept it (`scanlists.py --accept NAME`); an overall
  size limit on the result (IPv4 and IPv6); IPv6 wider than /32 is rejected; merged ranges wider than /16 are split
  rather than silently rejected by the shield; how many networks the shield didn't accept is shown in the message;
  exclusions (`scanners-exclude.txt`) of any width. If the result wasn't distributed, you find out (previously — only
  in the log).
- 📡 **Beacon:** counts only SYN without ACK (previously SYN-ACK replies too), sees IPv6 (one line per /64, at most 100
  lines), filters out private and reserved addresses; the ufw log is parsed in linear time and only kernel lines are
  used; reports the number of MPTCP listeners, including in containers with their own network — the watchdog marks
  what to restart; the file is written without following symlinks, the beacon service runs in a systemd sandbox.
  Upgrade: run `beacon_install.sh` again with the same parameters (the file path doesn't change).
- 🧭 **`node_dns.sh`:** auto-rollback and `status` work when run via `bash`; by default the fallback is the DNS the
  server had before installation, and it is tested — if it doesn't answer, the ISP's DNS is not disabled; rollback
  restores "as it was" (a pre-existing Unbound, autostart, default-route, mask); the timer checks live recursion (a
  random name, 3 attempts), not an answer from cache. Reinstalling on a server with the previous version upgrades it
  cleanly (if the probe fails, the server goes back to the ISP's DNS — that's expected).
- ⚙️ **`node_tune.sh`:** MPTCP is disabled by the file `99-zz-no-mptcp.conf` (read after `99-sysctl.conf`); after
  applying, MPTCP listeners are counted (sysctl 0 doesn't close already open ones) — the script names what to restart
  and exits with code 3; the connection table only grows (no less than 100000 and no less than the kernel value); the
  modprobe and journald files are backed up before being overwritten; a multiqueue (mq) qdisc gets fq children right
  away; root check.

**22.11.2026 v.2**
- 🧭 **The node's own DNS resolver — `node_dns.sh`.** Unbound on 127.0.0.1 only: the node resolves sites for client
  traffic itself without handing these queries to the ISP's DNS or 1.1.1.1; caching (96% of answers from cache on a
  production node), DNSSEC validation. systemd-resolved asks it first, with 1.1.1.1 as fallback; a timer every 10
  minutes switches the system back from the fallback and logs every switch to `/var/log/storozh-unbound.log`. Client
  phones don't see the resolver. If the hoster put its own DNS servers into the main `resolved.conf`, that list is
  cleared so Unbound comes first.
- 🚫 **ExpressHost (AS197574) by default blocks major Russian services from its servers** — Yandex, VK, Mail.ru, Ozon,
  Gosuslugi, banks, and with them their DNS servers (a toggle in the hoster's panel: "Сеть → Доступ к RU-сервисам",
  "Network → Access to RU services"). Other Russian sites open. What follows from this:
  - your own resolver won't come up there — recursion can't reach Yandex's DNS, so `node_dns.sh install` checks
    whether Unbound resolves ya.ru and rolls itself back on failure: such nodes keep the ISP's DNS;
  - anything the subscription template sends through the VPN rather than directly won't reach these services via such
    a node. Russian services in templates should go directly from the device (`geosite:category-ru`,
    `*.ru`/`*.рф`/`*.su`, `geoip:ru`; in whitelist mode — at least the listed services themselves and VK networks for
    MAX). The restriction itself is useful: Russian services don't see the node's address as a "user from Russia", so
    we don't recommend lifting it.
- 🩺 **The watchdog monitors the resolver.** The beacon reports whether Unbound is running, whether the system is using
  it, how many times a day it fell back, whether the queue overflows, whether the cache is full — a note in the
  "Серверы" ("Servers") line of the report.
- 👥 Our own scanner list doesn't pick up client addresses: the collector asks every node's shield who connected to Xray.

**22.11.2026**
- 🔭 **Our own "behavior" scanner list.** Official lists know only well-known networks, but there are far more scanners
  (on a test node, only a fifth of the addresses that knocked in a day were in the official lists). A client never
  knocks on closed ports — a scanner does it constantly. Each node's beacon takes from the ufw log who sent SYN to
  closed ports over the day; once a day `behavscan.py` on the watchdog gathers suspects from all nodes: knocking on a
  closed 80/443/8443, 3+ different closed ports, or 2+ of your servers. Only hosting and data center addresses are taken
  (ip-api.com, cached for 30 days) — residential and mobile networks, where a client might be, only with 10+ ports.
  Your addresses and `scanners-exclude.txt` are never included, **nor are your clients**: the collector asks every
  node's shield which addresses connected to Xray during the day, and such an address isn't taken for 30 days. An
  address stays on the list for 30 days after its last knock. The list joins the shield's combined list as the line
  "по поведению на наших серверах" ("by behavior on our servers") and, like the others, is **only counted** by default.
  The more closed ports and nodes with a closed 443 (for example, a node behind a relay entry), the better the trap.
- ⚙️ **Node tuning in the repository — `node_tune.sh`.** One script instead of the old ones: BBR + fq, buffers, queues,
  keepalive, a 100000-entry connection table and its hash, SYN flood protection, **MPTCP disabled** (CVE-2026-98432:
  remote root via an MPTCP listener, and programs built with Go 1.24+, including Xray, enable MPTCP on their own), fq
  queueing persisting across reboots. `node_tune.sh --check` only shows the differences.
- 🩺 **The watchdog checks that the profile hasn't been reset.** The beacon reports the network profile; if a node
  isn't on BBR, the qdisc isn't fq (cake is fine too), MPTCP is enabled or the connection table is too small — a note in
  the "Серверы" ("Servers") line of the report.

**14.11.2026**
- 🛡 **Clearer shield messages.** A line "🖥 Сервер: name · address · note" ("Server"), "🎯 Куда бьют" ("Targets",
  ports), and under each source address — its network (AS), country and city, tags "мобильная сеть" ("mobile
  network"), "хостинг" ("hosting"), "прокси или VPN" ("proxy or VPN") (free: ip-api.com, fallback — ipinfo.io; cached
  for a week) and which scanner lists the address is on.
- 🔘 **If shield buttons don't get through** — Telegram replies that someone else is polling this bot (a second copy of
  the watchdog with the same token): after 10 minutes you get a message with a hint, and another one once everything is
  back to normal.

**13.11.2026**
- 💾 **Backup monitoring.** The collector (version 1.7.0) reads backup logs listed in `/etc/ddos-collect/backups.json`;
  the watchdog alerts if there has been no successful copy for longer than `backup_max_hours` or the last attempt
  failed; the report shows the latest copy and its size. No new keys or access to the backup storage are needed.
- 👤 **Which clients ended up on the scanner list.** The report and message show the Telegram username and name,
  Telegram ID, subscription (active until…), last node and date, devices, traffic, app. The data comes from the panel via
  a read-only script (`panel_user_info.sh`) using a key that can do nothing but run it; no more than 20 clients at a
  time.
- 🧭 **Checking the subscription template against blocking** (`rucheck.py`). Every 6 hours popular services are tested
  from Russia layer by layer (DNS, TCP, TLS, block page), and the rules of every subscription tile are evaluated the way
  Xray does it (domain/full/regexp, geosite/geoip, `domainStrategy`). If the template routes a service directly but it
  is blocked from Russia, you get an alert. Identical rules count as one template; "everything direct" tiles aren't
  checked.
- 📍 Services for the template check are tested by **a vantage point at an ordinary ISP** (`"rucheck": true` in
  `vantage.json`): a data center often doesn't cut what home connections get cut. If the vantage point doesn't respond,
  the watchdog checks itself and a note appears in the report. The vantage agent is updated to version 6 (`/services`
  request, only its own list of services).
- 🔭 A fifth scanner list: [sngvy/AntiScanner](https://github.com/sngvy/AntiScanner) — scanners and subscription
  harvesters (count-only by default).
- 🧱 **An address blocked outside the registry.** If a node doesn't respond from Russia but works from abroad, the
  watchdog checks neighboring addresses in the same /24 and the open Roskomnadzor registry. The analysis says whether
  just the node's address or the whole subnet is closed, and whether the address is in the registry.
- 🗺 **Traceroute names the last hop**: address, network (AS), country and city. If the trace stops at an internal
  address (10.x, 100.64.x), it shows whose network that is: the external hop before it or the vantage point's own
  network.

**05.11.2026**
- 🐳 Containers: temporary ones (a one-off `docker run`) are counted separately from permanent services. Permanent ones
  (with a restart policy, from docker compose) are covered by alerts; temporary ones raise no alerts, just a line in the
  report. Settings — `permanent_containers` and `ignore_containers` in `ddos.json`; the alert includes a hint on how to
  add a container to the exclusions.
- 🔭 A fourth scanner list: [C24Be/AS_Network_List](https://github.com/C24Be/AS_Network_List) — Russian government
  agency networks (IPv4 and IPv6), updated daily like the others.

**02.11.2026** — first public release.

## 💬 What it looks like in Telegram

Messages are in Russian; an English gloss follows each example.

<table>
<tr><td>

🧊 **Душат: 🇩🇪 DE1**<br>
С 14:02 МСК соединение устанавливается, но данные встают: получено 18 КБ из 512 КБ.<br>
Вход с российских точек: обрыв на 16–20 КБ — похоже на блокировку, а не на поломку ноды.

<sub>Throttled: DE1. Since 14:02 MSK the connection is established but data stalls: 18 KB of 512 KB received. Entry
from Russian vantage points: cutoff at 16–20 KB — looks like blocking, not a broken node.</sub>

</td><td>

✅ **Снова работает: 🇩🇪 DE1**<br>
Его душили 47 мин (14:02–14:49 МСК).

<sub>Working again: DE1. It was throttled for 47 min (14:02–14:49 MSK).</sub>

</td></tr>
<tr><td>

🚨 **Щит: nl1 — атака, можно отрезать источники**<br>
💥 Тип: SYN-флуд · 🔴 Уровень: высокий<br>
Больше всех сверх порога за 10 минут:<br>
❓ 203.0.113.7 — 41 000 лишних<br>
✅ наш клиент — 198.51.100.4<br>
<br>
`[ Заблокировать чужих на 1 ч ]`<br>
`[ Включить щит на 2 ч ]` `[ Это не атака ]`

<sub>Shield: nl1 — attack, sources can be cut off. Type: SYN flood · Severity: high. Most over the threshold in 10
minutes: 203.0.113.7 — 41,000 excess; our client — 198.51.100.4. Buttons: Block outsiders for 1 h · Enable shield for
2 h · Not an attack.</sub>

</td><td>

🟡 **Состояние сервера требует внимания**<br>
🖥 Сервер: панель<br>
Контейнер remnawave-db упал: код 137 — убит из-за нехватки памяти или вручную.<br>
Чем грозит: панель не работает, новые подписки не выдаются.

<sub>Server needs attention. Server: panel. Container remnawave-db went down: code 137 — killed by out-of-memory or
manually. Impact: the panel is down, no new subscriptions are issued.</sub>

</td></tr>
</table>

<sub>The examples show the message format; addresses are illustrative.</sub>

## 🧩 How it works

```
 Telegram ◄──┐
             │
 ┌───────────┴─ watchdog server in Russia ───────┐
 │ probe.py      channels, sites, blocking       │
 │ ddoswatch.py  DDoS, load, containers          │
 │ shieldbot.py  shield buttons                  │
 │ scanlists.py  scanner list                    │
 │ rucheck.py    subscription template vs. blocks│
 └──────┬────────────────────────┬───────────────┘
        │ SOCKS via Xray         │ SSH: key with command=…
        ▼                        ▼
 ┌─────────────┐   ┌──────────────────────────────┐
 │  VPN nodes  │   │ your servers                 │
 │ as a client │   │ ddos-collect: read-only      │
 └─────────────┘   │ shield-ctl: shield commands  │
                   └──────────────────────────────┘
```

The watchdog makes all connections outward itself. On your servers it needs two lines in `authorized_keys`: both are
accepted only from the watchdog's address, and each can run exactly one command.

## 🚀 Installation

**Requirements:**
- a Remnawave panel and Xray nodes;
- a server in Russia for the watchdog: Ubuntu 24.04 or 26.04, root. The most convenient option is one of your Russian
  nodes: then Xray and the geo databases (`geosite.dat`, `geoip.dat`) are taken from the `remnanode` container and
  nothing needs to be downloaded;
- a Telegram bot (token from @BotFather) and the chat ID to post to;
- a service user in the panel: all squads, no expiry and no traffic limit. You'll need its subscription link in step 1.

Clone the repository onto the watchdog server and run all commands from its directory:

```bash
git clone https://github.com/multi81/remnawave-watchdog.git && cd remnawave-watchdog
```

### Step 1. Channel watchdog

```bash
bash install.sh
```

It asks for the service user's subscription link and the bot credentials (input is hidden), installs services and
timers, and sends the first report to Telegram. Non-interactive: `bash install.sh --yes`, if the link is already in
`/etc/channel-watch/sub.url` and the bot in `/etc/bridge-watch/guard.env`. If the server has no `remnanode`, point to
Xray with `--xray /path/to/xray` and put the geo databases in `/var/lib/channel-watch/geo/` (without them the template
check can't evaluate geosite rules and will say so in the report).

### Step 2. Your sites and domains

```bash
cp examples/site.example.json /etc/channel-watch/site.json && nano /etc/channel-watch/site.json
cp examples/owner.example.txt /etc/channel-watch/owner.txt && nano /etc/channel-watch/owner.txt
```

`site.json` — which sites to check and which domains are yours; `owner.txt` — your own addresses: the shield never
blocks them or counts them as scanners.

### Step 3. DDoS, shield, scanners

```bash
bash install_ddos.sh
```

At the end it prints a ready-made command for step 4 (it contains keys — don't publish it).

### Step 4. On each of your servers

Copy `server_install.sh`, `ddos_collect.py`, `shield_ctl.py` to the server and run the command from step 3
(`АДРЕС_СТОРОЖА` is the watchdog's address, `ваши адреса` — your addresses):

```bash
bash server_install.sh --watch АДРЕС_СТОРОЖА --ddos-key '…' --shield-key '…' --allow 'ваши адреса'
```

The shield will treat as its own: the watchdog's address, `--allow`, the server's addresses on the default-route
interface (or on `--iface`) and its external address. Public addresses on other interfaces (tunnels, bridges) are only
printed by the installer: if they are yours, add them to `--allow`.

Node network profile (BBR, fq, connection table, MPTCP off) — optional, in the same session:

```bash
sudo bash node_tune.sh       # or --check: only show what differs
```

The connection table is at least 100000; if the server had more (set by hand, the kernel default, or in the earliest
"before" backup in `/root/node-tune-backup/`), the larger value stays. Exit codes: 0 — everything applied; 1 — root
required; 2 — unknown parameter; **3 — profile applied, but MPTCP is still listening**: sysctl 0 forbids MPTCP only for
new sockets. The script names what to restart (`docker restart NAME`, `systemctl restart SERVICE` or a process).
Containers with their own network (not host) need more than a restart: add `sysctls: [net.mptcp.enabled=0]` in compose
and run `docker compose up -d`. Restarting remnanode drops client sessions — do it at a quiet time, then run
`sudo bash node_tune.sh --check`.

The node's own DNS resolver (Unbound) — optional:

```bash
bash node_dns.sh install      # status — current state, rollback — remove
```

If the beacon shows frequent "fallbacks" while Unbound is healthy: systemd-resolved tunes its timeout to the speed of
the local Unbound and on a cache miss (recursion 0.3–1.5 s) switches to the fallback for a long time. In that case use
`bash node_dns.sh install --per-query`: `/etc/resolv.conf` becomes a regular file (Unbound first, fallbacks after it,
`timeout:2`), every query from programs goes to Unbound first and only to the fallback if Unbound stays silent; there is
nothing to get stuck on, and DNS never drops out even for a moment. Docker gives containers on the host network
(remnanode) a copy of the file at startup — after switching, restart them or refresh the copy in place: `cat
/etc/resolv.conf > $(docker inspect -f '{{.ResolvConfPath}}' remnanode)`. To leave this mode — `install --regular`, to
remove everything — `rollback`.

### Step 5. Connect the server to the watchdog

Back on the watchdog — the server's name, address and SSH port:

```bash
bash install_ddos.sh add nl1 203.0.113.10 22
```

Steps 4 and 5 are repeated for each server. If the server's SSH key has changed, `add` refuses and shows the
fingerprint. Reinstalled the server? Compare the fingerprint with the hoster's console and repeat with `--rekey`.

### Optional

**A vantage point in another Russian network** — a second view of the nodes when a channel is down, and service checks
for the template check. Best is a machine at an ordinary ISP (home, office): a data center often doesn't cut what your
clients get cut. On the vantage machine (with `vantage_agent.py`, `netprobe.py`, `rucheck.py` alongside;
`АДРЕС_СТОРОЖА` is the watchdog's address, `ваш-домен.ru` your domain):

```bash
bash vantage_install.sh --allow АДРЕС_СТОРОЖА --suffix ваш-домен.ru
```

Then hand the vantage point's entry to the watchdog — through a pipe, so the token never appears on screen. `--rucheck`
means services for the template check are tested from this vantage point:

```bash
bash vantage_install.sh --entry --rucheck | ssh root@АДРЕС_СТОРОЖА python3 /opt/channel-watch/probe.py --add-vantage
```

The agent answers only the watchdog (address and token), checks only names on your domains and its own list of
services. The watchdog and the vantage point talk TLS on the agent port (9109 by default): the certificate is
self-signed, and the watchdog pins it by the `"sha256"` fingerprint from the entry (printed by `--entry`); a vantage
point without `"sha256"` is polled over HTTP, as before. Once the entry with `"sha256"` is in place, plain HTTP on the
vantage point can be turned off: `bash vantage_install.sh --tls-only`. A vantage point behind NAT (home, office):
forward the agent port on the router and specify the external address — `--public ADDRESS` (both at install time and
with `--entry`). To update only the agent files without touching the unit and settings: `bash vantage_update.sh`.

**Beacons on nodes** — disk, memory, versions in the weekly summary. On the node (with `node_beacon.py` alongside):
`bash beacon_install.sh --site-dir SITE_DIR` (a node with a cover website) or
`bash beacon_install.sh --serve PORT --allow WATCHDOG_ADDRESS` (no website; `beacon_serve.py` must be alongside too).
With `--serve` the port is opened in ufw only to the watchdog's address; if ufw is disabled, no rule is added — the
installer will say so, but the beacon server itself still answers only the watchdog (and the node itself). The `--serve`
port speaks both HTTP and TLS: the installer prints the certificate fingerprint as a `BEACON-SHA256 …` line — put it for
the node in `/etc/channel-watch/nodes.json` (`"sha256": "…"`), and the watchdog will fetch the beacon and the witness
file only over TLS with verification. Once that works, close HTTP: run `beacon_install.sh` again with the same
parameters plus `--tls-only`.

**Witness on the node** — counts only the marked probe connections of the watchdog and its vantage points and writes a
small file without addresses next to the beacon; opens no ports. On a node with a beacon (with `node_witness.py`
alongside): `bash witness_install.sh`. tcpdump parses packets as a separate user, and the service runs in a systemd
sandbox.

**Which clients ended up on the scanner list** — Telegram username and name, subscription, node, devices and app instead
of a bare number from the Xray log. The watchdog needs read-only access to the panel, and only to this data
(`АДРЕС_СТОРОЖА` — watchdog address, `АДРЕС_ПАНЕЛИ` — panel server address):

```bash
# on the watchdog: a dedicated key
ssh-keygen -q -t ed25519 -N '' -C channel-watch-users -f /etc/channel-watch/panel_users_ed25519
cat /etc/channel-watch/panel_users_ed25519.pub
# on the panel server: a read-only database script and a key that can only run it, and only from the watchdog's address
install -m 755 panel_user_info.sh /usr/local/sbin/watch-user-info
echo 'from="АДРЕС_СТОРОЖА",command="/usr/local/sbin/watch-user-info",restrict ssh-ed25519 AAAA… channel-watch-users' >> /root/.ssh/authorized_keys
# back on the watchdog: the panel server's host key and the panel address
ssh-keyscan -t ed25519 АДРЕС_ПАНЕЛИ > /etc/channel-watch/panel_known_hosts
echo '{"host": "АДРЕС_ПАНЕЛИ"}' > /etc/channel-watch/panel_users.json
```

Without these files everything works as before: the report shows the name from the Xray log, the node and the list. To
have the script read the database not as `postgres` but through a dedicated read-only role, apply `panel_ro_role.sql`
on the panel server (instructions at the top of the file); `watch-user-info` will switch to it on its own.

**Watchdog for the watchdog** — on any other server (with `guard.py` alongside): `bash guard_install.sh`. It notifies
you if the watchdog itself goes down or disappears. It reads the watchdog's heartbeat: write the file path inside the
site folder to `/etc/channel-watch/heartbeat.path` (use a random name, e.g. `hb-$(openssl rand -hex 12).json`) and run
`bash install.sh --yes` again — the service sandbox needs to know this folder. The heartbeat contains only the start
time, the last report, the queue of unsent messages and whether the server has internet, with no list of nodes. The
full heartbeat (plus the state of every node and site) — only if a second watchdog needs it: put its path in
`/etc/channel-watch/heartbeat-full.path`, also with a random name. If the heartbeat can't be read, guard first checks a
control host (`api.telegram.org:443`, or your own — `GUARD_CONTROL=host:port`): if that is unreachable too, it is
guard's own network failing and there is no alert.

### Upgrading

```bash
cd remnawave-watchdog && git pull
bash install.sh --yes          # watchdog: scripts and services are updated, settings and history are kept
bash install_ddos.sh           # DDoS, shield, scanners
```

On the servers — `bash server_install.sh` again; parameters don't need to be repeated: the watchdog address, keys and
`--allow` are taken from the previous install, and new values replace the old ones. Only what changed is restarted: new
shield code or settings — the table is rebuilt in place (mode, blocks and scanner lists are kept), a new collector — its
service. On vantage points — `bash vantage_install.sh` (the token, certificate and previous settings, including the
list of watchdog addresses, are kept). What changed — see [What's new](#-whats-new).

The password on the watchdog's SOCKS ports is enabled once: `python3 /opt/channel-watch/build_channels.py --socks-auth`,
then `systemctl restart channel-watch-xray` (to disable — delete `/etc/channel-watch/socks.auth` and rebuild the same
way). The systemd sandbox on a running watchdog without reinstalling is applied by `bash sandbox_dropins.sh` (`--dry` —
only show, `--rollback` — remove). Beacons on nodes — `beacon_install.sh` again with the same parameters.

### Uninstalling

```bash
bash install.sh --uninstall           # on the watchdog: everything, including the DDoS part
bash server_install.sh --uninstall    # on each server
bash vantage_install.sh --uninstall   # on vantage points
```

`install.sh --uninstall` removes the DDoS part itself and switches the shields on all servers to observe mode (scanners
— count only). If some server didn't respond, the shield key and the server list are kept so that a repeated
`--uninstall` can deliver the command; `--uninstall --force` removes them too, and you switch unreachable servers
manually. To remove only the DDoS part and keep the channel watchdog: `bash install_ddos.sh --uninstall` (shields stay
in their current mode).

## ⚙️ Configuration

<details>
<summary><b>Configuration files</b></summary>

| File | Contents |
|---|---|
| `/etc/channel-watch/sub.url` | service subscription link (600) |
| `/etc/bridge-watch/guard.env` | `BW_TG_TOKEN`, `BW_TG_CHAT` — bot and chat (600) |
| `/etc/channel-watch/site.json` | your sites, domains, exclusions, MSS mark range (`mss_mark`) — sample in `examples/` |
| `/etc/channel-watch/socks.auth` | username and password for the watchdog's SOCKS ports (600), created by `build_channels.py --socks-auth`; no file — no password |
| `/etc/channel-watch/ddos.json` | monitored servers, working hours, custom thresholds (`thresholds`), containers: `ignore_containers` (don't watch), `permanent_containers` (watch as permanent); `note` for a server — a label in messages ("панель Remnawave", "Remnawave panel"); `backup_max_hours` — how many hours without a successful backup before an alert (default 26; for backups every 3 h set 7) |
| `/etc/ddos-collect/backups.json` (on the server) | which backups to watch: `[{"name": "панель", "log": "/var/log/panel-backup.log"}]`; a successful backup is a log line with a timestamp `[ГГГГ-ММ-ДД ЧЧ:ММ:СС]` (`[YYYY-MM-DD HH:MM:SS]`) and the word `DONE`, an error — `[ERR]`, `FAILURE` or `ERROR` (your own patterns — as regular expressions `ok`, `err`) |
| `/etc/channel-watch/owner.txt` | your own addresses: never blocked and never counted as scanners |
| `/etc/channel-watch/scanners-extra.txt`, `scanners-exclude.txt` | additions to and exclusions from the scanner list |
| `/etc/channel-watch/expected_exit.json` | expected exit for cascades: `{"вход": "адрес выхода"}` (`{"entry": "exit address"}`) |
| `/etc/channel-watch/nodes.json` | node beacons (`beacon_install.sh`); `"sha256"` for a node — fetch the beacon only over TLS with this fingerprint |
| `/etc/channel-watch/panel_users.json` | read-only panel access — which clients are on the scanner list: `{"host", "port", "key", "known_hosts"}` (defaults: port 22, `panel_users_ed25519`, `panel_known_hosts`) |
| `/etc/channel-watch/rucheck.json` | your own service lists for the template check: `{"services": [...], "local": [...]}` |
| `/etc/channel-watch/vantage.json` | vantage points (`probe.py --add-vantage`); a vantage point with `"rucheck": true` tests services for the template check — preferably at an ordinary ISP: a data center doesn't see all blocking |
| `/etc/channel-watch/external.json` | view from Russian home networks via Globalping: `{"enabled": true, "service": "globalping", "ru_probes": 8}` — sample in `examples/`; no file or `"enabled": false` — disabled, nothing is sent out |
| `/etc/channel-watch/globalping.token` | optional Globalping key (600): more checks per hour; sent only as a header to the API |
| `/etc/storozh-shield/config.json` | on the server: shield thresholds (`rate`, `burst`, `conns`), your own addresses (`allow`), the port gate; addresses synced from the watchdog are kept separately in `allow-sync.txt` next to it |

</details>

<details>
<summary><b>Thresholds</b></summary>

The values in the code are a reasonable starting point, not the truth. Watch for a week in observe mode (`/shield` in
the chat, reports), then tune to your setup: attack thresholds — in `ddos.json` → `thresholds`, the shield — in
`config.json` on the server.

</details>

<details>
<summary><b>Manual commands</b></summary>

```bash
python3 /opt/channel-watch/probe.py --show          # report now (without sending)
python3 /opt/channel-watch/probe.py --blocks        # check blocking now
python3 /opt/channel-watch/probe.py --week          # weekly summary
python3 /opt/channel-watch/ddoswatch.py --status    # servers and thresholds
python3 /opt/channel-watch/shieldbot.py --status    # what is blocked and where the shield is on
python3 /opt/channel-watch/scanlists.py --dry       # download and validate scanner lists, send nothing
```

</details>

## 🔒 Security

- **Never blocks on its own.** The shield only counts; blocking and cutting happen on a button press, buttons are
  single-use and accepted only from your chat.
- **Restricted keys.** On the servers the watchdog's key works only from its address and can do one thing: read a
  snapshot or run a shield command. The shield refuses, once more on the server itself, to block your own and private
  addresses.
- **Leaves other rules alone.** The shield has its own nftables table; ufw, fail2ban, crowdsec and other tables stay as
  they were. It is removed with one command.
- **Secrets are not in arguments.** curl gets the bot token and message text via standard input (`-K -`): they are not
  visible in `ps` or `/proc/*/cmdline`. The installers don't take secrets as arguments either.
- **Local SOCKS ports are password-protected.** After `build_channels.py --socks-auth` the watchdog's (and VPN vantage
  point's) channel ports accept only the username and password from `socks.auth` (600): another process on the server
  can't reach the network through your nodes. The modules pass the password to curl via standard input, not as
  arguments.
- **systemd sandbox.** The watchdog's Xray runs as a temporary unprivileged user (DynamicUser), and systemd hands it the
  config. The watchdog's Python services write only to their own directories, `/var/log` and the heartbeat directory;
  `/home` and `/root` are read-only. To be honest: they still run as root — they read `sub.url` and `guard.env` (600
  root), talk to docker and trace TCP SYN (`traceroute -T`). On an already running watchdog the same is applied without
  reinstalling by `sandbox_dropins.sh`. The vantage agent runs as a temporary user, and its settings and TLS key are
  readable only by root; the witness on a node keeps only the privileges to capture packets and write to the site
  folder, and tcpdump parses packets as a separate user.
- **The vantage point and the beacon don't talk too much.** Connections from unknown addresses are dropped before the
  request is read; responses carry no server signature; names only on your domains and per DNS rules; the watchdog talks
  to the vantage point and to the `--serve` beacon over TLS with a pinned fingerprint (`"sha256"`), and HTTP can be
  closed (`--tls-only`).
- **Narrow trust for the shield.** allow-sync accepts from the watchdog only addresses and networks no wider than /24
  and /64; node addresses are not added to the trusted list (VPN clients go through them). The watchdog can read client
  information from the panel database with a read-only role (`panel_ro_role.sql`).
- **A heartbeat without the node list.** The file for guard sits in the site folder and is therefore short; the full
  one goes only to a separate path.
- **Doesn't hoard addresses.** The collector keeps only counters; "suspicious" entries live for 5 minutes, your clients'
  addresses for a day and only on the server itself. The "behavior" list on the watchdog
  (`/var/lib/channel-watch/behavior.json`) stores addresses that knocked on closed ports (per day and server, with
  ip-api details) for up to 30 days after the last knock. An address the shields identified as a client is deleted
  immediately — only sha256(salt + address) with a date remains, for up to 30 days; the salt is stored separately
  (`behavscan.salt`, mode 600) and rotated every 30 days. To be honest: anyone who reads both files can recover such
  IPv4 addresses by brute force; and a client the shields didn't recognize this time (connected more than a day ago) is
  stored the same as any other knocking address.

<details>
<summary><b>Where the watchdog connects</b></summary>

Only outward, and only where a check needs it: `api.telegram.org` (messages); `ip-api.com`, `ipinfo.io` (source address
details in shield messages); through the channels — `gstatic.com`, `speed.cloudflare.com`, `api.ipify.org`, Telegram,
YouTube, Instagram, OpenAI (service availability); your sites and `rdap.org` (domain expiry);
`antifilter.download`/`antifilter.network` (blocklists); `dns.google`, `cloudflare-dns.com` (DNS cross-check over
secure DoH, through a foreign channel, or directly if there is none); public DNS 8.8.8.8, 1.1.1.1, 77.88.8.8, 9.9.9.9
over UDP — only about third-party names (`rutracker.org`, `www.facebook.com`, `www.example.org`); your names are never
sent there in plain text (if the system DNS fails to resolve a node entry name, the probe asks the fallback DoH by IP —
`https://1.1.1.1`, `https://8.8.8.8`); node beacons and witnesses (files on their sites or the `--serve` port, over TLS
with a pinned fingerprint); vantage points (agent port, TLS with a pinned fingerprint); geo databases `ipinfo.io`,
`ip-api.com`, `ipwho.is`, `geojs.io`, `country.is`; `raw.githubusercontent.com`, `gist.githubusercontent.com` (scanner
lists); the template check — directly from the server to popular services (list in `rucheck.py`) and
`cloudflare-dns.com`. The view from Russian home networks via Globalping (`api.globalping.io`, `globalping.py`) — only
if enabled in `external.json` (sample — `examples/external.example.json`) and only when a node entry already fails to
open from rf1 or from a vantage point: only the entry's IP address and port are sent, without names or domains;
Globalping measurement results are public to anyone with the measurement ID. No file or `"enabled": false` — nothing is
sent there.

</details>

## 🧪 Tests

No network and no root needed, on any machine with Python 3.10+:

```bash
for t in test_*.py; do python3 $t | tail -1; done
```

## 📄 License

[MIT](LICENSE). The DDoS part's logic grew out of the ddos-monitoring plugin for Remnawave (MIT).
