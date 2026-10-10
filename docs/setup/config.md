# config.yaml

One file says everything lanowl does. A new install has a short one, written by lanowl at its
first start, and the dashboard's gear changes it: [Settings](../using/settings.md) shows every
section as a form, from `config.example.yaml`, and keeps the file's comments. Or copy
`config.example.yaml` to `config/config.yaml` and edit it: the essentials come first, and
every optional feature starts switched off.

- **No secrets here.** Logins, tokens and lanowl's ssh key live in
  [`secrets.yaml`](secrets.md), so this file can be shared or kept in git.
- **Relative paths** (the database, the log, the outbox) land in `/state`, the container's
  volume.
- **Four settings can come from the environment** instead, so one file serves several
  machines: `LANOWL_MODEL_URL` (`model.url`), `LANOWL_HOST_IP` (`observer.host_ip`),
  `LANOWL_WEB_PORT` (`web.port`) and `TZ` (`timezone`). The environment wins.
- **Changes need a restart** (`docker compose restart lanowl`), except `secrets.yaml`, which
  is read again when it changes.
- `lanowl --check` reads this file the way a start does, and says what is wrong.

The values below are the example's. Where leaving a key out gives something different, the
last section says so.

## network

```yaml
network:
  description: |
    A home LAN 192.168.88.0/24 behind a MikroTik router (192.168.88.1), one fibre line to the
    internet. IoT devices share the main LAN on purpose. Guests use their own Wi-Fi.
```

A few sentences about your network, in your own words. Every prompt the model reads includes
them, marked as context, not instructions. Say what no inventory says: the links, the sites,
what runs where, what matters, and what you chose on purpose (so the owl does not report it).

## timezone

```yaml
timezone: "Europe/Berlin"
```

Sunrise and sunset, the morning jobs and the router's log timestamps are read in it. The
first-run setup writes it from your browser. `TZ` in the environment wins; neither set, UTC.

## model

The local model: where Ollama is, which model, and how it speaks.
See [The model](model.md).

## telegram

```yaml
telegram:
  chat_id: ""                     # your chat with the bot
  outbox_file: "tg_outbox.json"   # what could not be sent during an outage
  chat:
    enabled: true                 # answer questions and /commands
    allowed_chat_ids: []          # only these chats are answered (empty: chat_id)
    poll_timeout_s: 50
    answer_max_wall_s: 600        # the longest an answer may take
    max_iters: 16                 # the most tool calls in one answer
```

`telegram.chat.allowed_user_ids` lists who may press Approve and Reject; needed only when the
chat is a group. See [Telegram](../getting-started/telegram.md).

## web

```yaml
web:
  enabled: true
  host: "0.0.0.0"
  port: 80                        # or LANOWL_WEB_PORT
  allowed_hosts: []
  password_hash: ""
  login: true
```

The dashboard. It is closed until you log in with its password: `password_hash`, written by
the dashboard's first page (after the setup code) or made by `lanowl --hash-password`, or,
when that is empty, the one set with `/password` on Telegram. With neither, it asks for the
setup code. `login: false` switches the login off, for a
dashboard behind a login of your own. More: [Logging in](../using/dashboard.md#logging-in).

It answers on any address of the host. By default it accepts requests only
when the browser reached it by an IP address: that is what stops a hostile web page from
borrowing a DNS name that points at your network (DNS rebinding). To open it by name
(`lanowl.lan`, or behind a reverse proxy), list the names in `allowed_hosts`.

## cadence

```yaml
cadence:
  sweep_interval_s: 60            # every device probed once a minute
  debounce_fails: 2               # misses in a row before a device is down
  recovery_oks: 1                 # answers in a row before it is up again
  llm_mode: "interval"            # the owl's audit: "interval" or "times"
  llm_interval_s: 3600
  llm_times: ["08:00", "13:00", "20:00"]
  llm_on_incident: true           # a new critical: the owl diagnoses it at once
  llm_incident_cooldown_s: 600
  llm_max_wall_s: 900             # an audit is abandoned after this
  digest_when_ok: false           # no digest when there is nothing to say
```

The sweep and the model run on separate clocks: an audit never delays a sweep. With
`llm_mode: times`, the audit runs at the listed times instead of every `llm_interval_s`.
A device can carry its own `debounce_fails` in the inventory (a site behind a tunnel wants
more patience).

## alerts

```yaml
alerts:
  recovery_confirm_s: 900         # clear this long before "RECOVERED"
  cooldown_s: 3600                # the same problem stays quiet this long after it recovers
  renotify_after_s: 0             # re-page a problem that never clears (0 = never)
  digest_repeat_s: 86400          # re-state a still-open problem once a day
  notify_recovery: true
  recovery_min_severity: "info"
```

How these decide what reaches you: [How alerts work](../using/alerts.md).

## probes

```yaml
probes:
  concurrency: 32
  icmp_timeout_ms: 1500
  tcp_timeout_ms: 1500
  http_timeout_ms: 4000
  snmp_timeout_s: 2
  snmp_community: "public"
```

Defaults for every check. A check in the inventory can carry its own `timeout_ms` (and
`count` for ping), for a device on weak Wi-Fi.

## wan

```yaml
wan:
  targets: ["8.8.8.8", "208.67.222.222", "1.0.0.1"]
  watch:
    enabled: true
    interval_s: 15                # its own ping loop, faster than the sweep
    fail_checks: 2
    ok_checks: 1
    min_outage_s: 90              # shorter blackouts are counted, not paged
    state_messages: true
    log_interval_s: 60
    flap_hold_s: 60
    flap_severity: "critical"
    log_down_match: ""
    log_up_match: ""
    routine: []
    log_triage: {enabled: true, cooldown_s: 900, timeout_s: 90, max_lines: 40,
                 notify_severities: ["critical", "warning"]}
  path:
    route_comment: ""
    main: "main link"
    backup: "backup link"
```

The internet is up when any of `targets` answers. Pick neutral public addresses from
different providers. The watcher's loop runs every 15 seconds: a blackout is confirmed in
about 30 seconds, and one shorter than `min_outage_s` is counted in the digest instead of
paging you.

`path`, `log_down_match`, `log_up_match`, `routine` and `standby` are for a second internet
line and a MikroTik's log: [A backup internet line](backup-line.md). `log_triage` lets the
owl read router-log lines that no rule explains.

## mikrotik

The main router's REST address, its read-only login, and the kept API connection.
See [Your router](mikrotik.md).

## discovery

```yaml
discovery:
  notify_new_devices: true        # a Telegram line when a never-seen device joins
  notify_address_changes: true    # ...when DHCP moves a watched device
  new_window_h: 24                # "new" on the dashboard for this long
  guest_nets: []                  # e.g. ["192.168.89.0/24"]: marked as guests
  ignore_macs: []
  ignore_ips: []
```

What the router's DHCP holds and nobody watches (needs a MikroTik). A watched device that
DHCP moves to another address is followed by its MAC (`mac:` in the inventory, or learned
from the lease). `ignore_macs` does by hand what the dashboard's **Known** button does.

## sites

```yaml
sites:
  dhcp_every_min: 30
  scan: {enabled: true, at: "05:00", seconds: 30}
  list:
    - {key: home, name: "Home", nets: ["192.168.88.0/24"]}
```

The networks lanowl looks after. `home` is the main one. See [Remote sites](sites.md).

## site

```yaml
site:
  lat: 48.0                       # rough is fine
  lon: 11.0
  sun_margin_min: 60
  day_margin_min: 45
  offline_grace_min: 30
```

Where the network is, for sunrise and sunset: a device with `expect_offline: sun` (solar
gear) is asleep from sunset to sunrise, widened by `sun_margin_min`; one with
`expect_offline: day` (a dusk-to-dawn light) the other way round, by `day_margin_min`. One
that dozes off a little early, or wakes late, stays asleep for `offline_grace_min` before it
counts as down. Without `lat` and `lon`, `expect_offline` does nothing.

## observer

```yaml
observer:
  enabled: true
  host_ip: ""                     # or LANOWL_HOST_IP; empty: the address it reaches the internet from
  gateway_ip: ""                  # default: the router in mikrotik.dhcp_source
  min_down_pct: 60
  min_groups: 3
```

lanowl's own host. Everything is probed from one machine, so if that machine loses the
network, every device looks down. When the gateway is unreachable, at least `min_down_pct`
of the devices are down, and they span at least `min_groups` groups, lanowl sends one alert
saying it has probably lost the network itself, instead of forty.

## mqtt

```yaml
mqtt:
  host: ""                        # empty: MQTT off
  port: 1883
  tls: false
  credentials: "mqtt"             # its login in secrets.yaml, if the broker wants one
  base_topic: "lanowl"
  subscribe: []                   # e.g. ["shellies/#"]: last values the owl can read
```

See [MQTT topics](../reference/mqtt.md).

## weekly

```yaml
weekly: {enabled: true, day: "sun", time: "10:00"}
```

The week in review: the numbers, and the owl's note on top. The first one waits until lanowl
has watched for six days (`/week` asks for one at any time).

## state and logging

```yaml
state:
  db_path: "lanowl_state.sqlite"
  history_days: 30
logging:
  level: "INFO"
  file: "lanowl.log"
```

Both under `/state`. With `logging.file` set, `docker logs` stays empty: read the file
instead. See [Logs and lanowl's own state](../running/state.md).

## The optional features

Each is off until you switch it on, and each acts only on the devices whose `manage` list
names it ([Devices](inventory.md)). `lanowl --check` shows the plan.

| Section | What it does | Where it is explained |
|---|---|---|
| `profiles` | Device kinds of your own (default: `config/profiles/`) | [Profiles](profiles.md) |
| `access` | Where `secrets.yaml` is, known hosts, Home Assistant's address | [Secrets](secrets.md) |
| `actions` | What the owl may propose, and you approve | [Actions](../using/actions.md) |
| `devwatch` | Every device's Ethernet ports and its own log, hourly (on in the example) | [Device kinds](../reference/kinds.md#every-hour-its-ports-and-its-log) |
| `hostlog` | Linux auth logs, every two minutes, by lanowl's key | [Security](../using/security.md) |
| `updates`, `cves` | Waiting updates every morning, a monthly scan | [Security](../using/security.md) |
| `exposure` | The owl's daily review of what each machine exposes | [Security](../using/security.md) |
| `drift`, `configwatch` | The owl's looks at what is slowly changing, and at config changes | [Security](../using/security.md) |
| `fixes`, `scorecard` | A written fix for each finding; each diagnosis graded afterwards | [Asking the owl](../using/asking.md) |
| `backups` | Monthly backups of your machines onto a disk of yours | [Security](../using/security.md) |
| `shell` | The owl's sandboxed shell | [The model](model.md) |

## Leaving a key out

A key left out of the file takes lanowl's own default. For most keys that is the example's
value. These differ:

| Key | Left out |
|---|---|
| `web.enabled` | `false`: no dashboard |
| `web.port` | `8088` |
| `telegram.chat.enabled` | `false`: questions and commands are not read |
| `weekly.enabled` | `false` |
| `discovery.notify_new_devices` | `false` |
| `model.num_ctx` | `16384` |
| `model.keep_alive` | `0`: the model is unloaded after each call |
| `model.request_timeout_s` | `240` |
| `model.max_tool_iters` | `6` |
| `cadence.llm_max_wall_s` | `600` |
| `telegram.chat.answer_max_wall_s` | `420` |
| `probes.icmp_timeout_ms` | `1000` |
| `fixes.enabled`, `scorecard.enabled` | `true` |
