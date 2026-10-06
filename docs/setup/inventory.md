# Devices: inventory.yaml

Every device lanowl watches is described once, in `config/inventory.yaml`: how it is
watched, how much it matters, and what lanowl may do with it besides watching. An address that
is not in the inventory is never probed, and the model's tools refuse it too.

The dashboard writes it too: the first-run setup picks devices from your router's DHCP list,
and Settings → Devices adds and changes them one by one ([Settings](../using/settings.md)).

```yaml
groups:
  network: {majority_down_critical: true}
  cameras: {majority_down_critical: true}
  servers: {majority_down_critical: false}

devices:
  - ip: 192.168.88.10
    name: "Home server"
    group: servers
    criticality: critical
    kind: linux
    credentials: server
    manage: [logs, updates, upgrade, reboot, restart, config, security, backup]
    restart: {units: [mosquitto]}
    checks:
      - {type: icmp}
      - {type: tcp, port: 22}
      - {type: tcp, port: 1883, name: "MQTT"}
```

Watching needs only `ip`, `name` and `checks`. Everything from `kind` down is optional.

## Watching

| Field | What it does |
|---|---|
| `ip` | The address lanowl probes. |
| `name` | What every message and the dashboard call it. You can rename a device on the dashboard too; the inventory's name is kept underneath. |
| `group` | Devices that share fate: a switch's cameras, the servers. Groups decide what counts as one incident. |
| `criticality` | How much it matters: `critical`, `high`, `warning`, `low` or `info`. See below. |
| `checks` | How it is watched. A device is up while any of its checks answers. Default: one ping. |
| `mac` | Its MAC address. A device that DHCP moves to another address is followed. |
| `depends_on` | The address of what it is reached through, or `wan`. When that is down, this one is not a second alert: the parent's names it. |
| `expect_offline` | `sun`: off at night by design (solar gear). `day`: off in daylight (a dusk-to-dawn light). Needs `site.lat` and `site.lon`. |
| `debounce_fails` | Misses in a row before it is down, for this device alone (default `cadence.debounce_fails`, 2). A site behind a tunnel wants 5. |
| `role` | `ap`: rebooting it holds the alerts of the devices on its Wi-Fi. `wan-gateway`: never rebooted while the internet runs through it. Anything else is a label on the device's sheet. |
| `note` | A line shown on the device's sheet. |

### Criticality

| Criticality | When it goes down |
|---|---|
| `critical` | A 🔴 alert at once, and a 🟢 when it is back. |
| `high` | Reported in the next digest, once. |
| `warning` | Reported in the next digest, once. |
| `low`, `info` | Mentioned once in the next digest. Never makes the network "degraded". |

A device that answers but whose named service check fails (`degraded`) is a `warning`. More in
[How alerts work](../using/alerts.md).

### Checks

| Check | What it asks | Options |
|---|---|---|
| `{type: icmp}` | A ping. | `timeout_ms`, `count` |
| `{type: tcp, port: 22}` | Does the port accept a connection? | `port`, `timeout_ms`, `name` |
| `{type: http, port: 80}` | Does `/` on that port answer? Any reply below 500 counts, a login page included. HTTPS on ports 443 and 8443. | `port`, `timeout_ms`, `name` |
| `{type: snmp}` | An SNMP read of its uptime. A failed SNMP read never makes a device degraded. | `community` |
| `{type: arp}` | The router ARP-pings it: is it on the wire? For gear that ignores ping and listens on no port. Needs the MikroTik API and the `test` policy. | `iface` (default `bridge-lan`), `count` |
| `{type: link, iface: ether5}` | Is the router port it hangs off up? The fastest honest signal for a device on its own port. Needs a MikroTik. | `iface` |
| `{type: lease}` | Does it hold a DHCP lease on the router? Slow: a lease outlives the device by hours. The last resort. Needs `mac`. | |

A check with a `name` is a **service**: it gets its own line on the dashboard, and when it
fails while the device answers, the device is "degraded" rather than down.

A device on weak Wi-Fi is better given patience than taken out of monitoring: more time and
more pings, `{type: icmp, timeout_ms: 2500, count: 3}`, turn a 30% loss into an answer.

### Groups

```yaml
groups:
  cameras: {majority_down_critical: true}
```

With `majority_down_critical`, more than half of a group going dark at once is one 🔴 alert
about the group ("suspect a single upstream cause"), not one message per device. Devices
explained by a `depends_on` parent do not count towards the majority.

### depends_on

```yaml
  - ip: 192.168.88.21
    name: "Cam Front door"
    depends_on: 192.168.88.2      # the PoE switch
```

When the PoE switch is down, its cameras are still drawn down on the dashboard, but they
are not alerts of their own: the switch's alert says "dark with it: Cam Front door, …". A
device behind the internet (a VPS) takes `depends_on: wan`. Chains work: a remote site's
camera depends on the site's router, which depends on the VPS that carries the tunnel.

## Managing

What lanowl may do with a device besides watching it, each only where its kind can, and only
with a login in [`secrets.yaml`](secrets.md):

```yaml
    kind: linux                   # what it is
    credentials: server           # its login, by name, in secrets.yaml
    manage: [updates, reboot, restart, backup]
    restart: {units: [mosquitto]}
```

| Feature | What lanowl does | Switched on by |
|---|---|---|
| `logs` | Reads its auth log for security events (Linux, by key) | `hostlog.enabled` |
| `updates` | Checks its updates every morning | `updates.enabled` |
| `upgrade` | May propose installing them | `actions.enabled` |
| `reboot` | May propose a reboot | `actions.enabled` |
| `restart` | May propose restarting one of its listed services | `actions.enabled` |
| `config` | Tells what changed in its configuration | `configwatch.enabled` |
| `security` | Reviews what it exposes, every day | `exposure.enabled` |
| `backup` | Backs it up, monthly and before updates | `backups.enabled` |

Anything that changes a device is only ever a proposal that you approve. Which kind can do
what: [Device kinds and features](../reference/kinds.md). A kind lanowl does not know is a
YAML file of your own: [Device kinds of your own](profiles.md).

### Feature options

A feature's options sit under its own name on the device:

```yaml
    restart: {units: [mosquitto, jellyfin]}     # what it may restart, and nothing else
    backup:  {paths: [etc, home]}               # what a backup by password takes
    reboot:  {risk: "the cameras record to it", hold_min: 10, also_hold: [192.168.88.21]}
    upgrade: {risk: "the internet is down while it installs", hold_min: 12, also_hold: [wan]}
    logs:    {public: true, about: "the VPN hub on the internet", trusted: ["10.8.0.0/24"]}
```

| Option | Meaning |
|---|---|
| `restart.units` | The systemd units it may restart. Nothing else can be restarted. |
| `backup.paths` | What a Linux machine's backup copies. Required over a password login; over lanowl's key a default list of configuration paths is used. |
| `reboot.risk`, `upgrade.risk` | A line shown with the proposal: what you lose while it runs. |
| `hold_min` | How long its alerts are held while it restarts (default 5 minutes). |
| `also_hold` | Other addresses held with it, or `wan` for the internet. |
| `reboot.ha_button` | Reboot it by pressing a Home Assistant button entity, such as its smart plug's. |
| `logs.public` | It is on the internet: the scanners' constant knocking is filtered out. |
| `logs.about` | A sentence for the owl about what this machine is. |
| `logs.trusted` | Networks a login may come from without being news. |

A reboot through a Home Assistant button works for any device, but it still needs a `kind`
(`generic` is enough), `manage: [reboot]`, and Home Assistant's address and token
(`access.ha_url`, `tokens.homeassistant`):

```yaml
  - ip: 192.168.88.23
    name: "Cam Garage"
    kind: generic
    manage: [reboot]
    reboot: {ha_button: button.garage_cam_plug_restart}
    checks: [{type: icmp}]
```

## Devices you add from the dashboard

Once lanowl reads a router's DHCP, the dashboard lists the devices on each site's network
that nobody watches. **Watch** writes one into this file, with its MAC so lanowl follows it
when DHCP moves it, and pings it at once. **Known** marks one as belonging there. Settings →
Devices adds any device by hand, and asks for its login right there: a user and a password,
or lanowl's ssh key.

## Checking it

`lanowl --check` reads this file the way a start does and lists, per device, each feature as
✓ on, ○ switched off in config.yaml, or ✗ cannot, with the reason. A change of `kind`,
`manage` or login type takes a restart; a changed password does not.
