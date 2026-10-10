# Device kinds and features

A device's `kind` says what it is; its `manage` list says what lanowl may do with it besides
watching. A feature works only where the kind can do it, with the login it needs, and with
its switch on in `config.yaml`. `lanowl --check` shows the result per device.

## What each kind can do

| kind | logs | updates | upgrade | reboot | restart | config | security | backup |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `mikrotik` | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | ✓ |
| `openwrt` | ✓ | ✓ | | ✓ | | | ✓ | |
| `linux` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `esxi` | ✓ | ✓ | | | | | ✓ | ✓ |
| `unifi` | ✓ | ✓ | | ✓ | | | | |
| `homeassistant` | | ✓ | | ✓ | | | | ✓ |
| `reolink` | | | | ✓ | | | | |
| `shelly` | | | | ✓ | | | | ✓ |
| `generic` | | | | | | | | |
| a profile | | ✓ | | ✓ | | ✓ | ✓ | ✓ |

Any kind, `generic` included, can be rebooted through a Home Assistant button:
`manage: [reboot]` with `reboot: {ha_button: button.<entity>}`.

## How each kind is reached

| kind | Login | How |
|---|---|---|
| `mikrotik` | A password | ssh with RouterOS commands. Updates are compared with MikroTik's own release list, and a release whose changelog mentions a security fix is flagged. An upgrade downloads the package, then reboots to install it. Backups are an `/export` plus a binary backup, copied off and deleted from the router. |
| `openwrt` | A password | ssh. Reads its release, board, uptime and Wi-Fi clients. There is no feed of the latest release per board, so the owl's review judges its age. |
| `linux` | lanowl's key, or a password | ssh. Updates from `apt`, a pending reboot and what asked for it; upgrades with `apt`; restarts only the units listed in `restart.units`. A user other than root needs sudo. |
| `esxi` | A password | ssh. Its version, its exposure, and backups of the host's configuration bundle and every VM's settings. |
| `unifi` | A password | ssh. Read only: a UniFi device is updated from your UniFi app. |
| `homeassistant` | `access.ha_url` and `tokens.homeassistant` | Home Assistant's API for updates and restarts. Its backups also need an ssh login with a password: lanowl makes a full backup, copies it across, and deletes it on Home Assistant. Home Assistant's own automatic backups are never touched. |
| `reolink` | A password | The camera's own web API. |
| `shelly` | None | The Shelly's own HTTP API. A reboot restarts its controller; relays never switch. lanowl refuses one whose relay would come back off. |
| a profile | lanowl's key, or a password | ssh, with your commands ([Profiles](profiles.md)). |

## What the owl can read

In your own questions (Telegram, or the dashboard's Ask tab), the owl can read a device
itself, logged in with the login lanowl has for it: a device with a `kind` below and its
`credentials:` (Home Assistant: its token). No `manage` is needed. Each read is one fixed,
read-only command: the owl picks the read, never the command. Every read is listed under the
answer.

| kind | Reads |
|---|---|
| `mikrotik` | `system` (model, version, uptime, CPU, memory) · `ports` (each port's link state and link-downs; each ethernet port's negotiated rate and duplex, and what the other end offers) · `log` · `clients` (the Wi-Fi clients in every Wi-Fi menu, `wifi`, `wireless` or `wifiwave2`, and the MAC addresses on each bridge port) |
| `openwrt` | `system` · `ports` (link, speed, duplex; the switch ports on a device with a switch chip) · `log` (logread) · `clients` (Wi-Fi clients, ARP table) |
| `linux` | `system` (OS, uptime, memory, disks, failed services) · `ports` · `log` (the journal: through sudo when the login is not root, else what the login itself may read) |
| `esxi` | `system` · `ports` (each NIC's link, speed, duplex, error and drop counters) · `log` (vobd.log) · `vmkernel` · `vms` (every VM and whether it is on) |
| `unifi` | `system` · `ports` · `log` · `clients` |
| `homeassistant` | `system` · `log` · `unavailable` (every entity that is unavailable, and since when) |
| `reolink` | `system` (model, firmware; an NVR's disks) · `sessions` (who is connected) · `channels` (an NVR's cameras online) |
| a profile | Its operations, except `reboot` and `backup` |

## What each feature does

| Feature | What lanowl does | Switch in config.yaml |
|---|---|---|
| `logs` | Reads its own log every hour, with one login: the routine is dropped (Wi-Fi clients, DHCP, lanowl's own logins), and the owl says something only when it is not normal — a power cut, a link that flaps, a disk error, a login that does not fit. A Linux machine by lanowl's key: its auth log every two minutes too (failed-login bursts, logins from unknown places, connection floods; `hostlog.enabled`). | `devwatch.enabled` |
| `updates` | Checks its updates every morning. A security update waiting two days, or a reboot pending three, gets one message. | `updates.enabled` |
| `upgrade` | May propose installing them. With backups on for that machine, it is backed up first, and a failed backup stops the update. | `actions.enabled` |
| `reboot` | May propose a reboot. Its alerts, and those of the devices on its Wi-Fi or listed in `also_hold`, are held while it restarts. | `actions.enabled` |
| `restart` | May propose restarting one of `restart.units`, and nothing else. | `actions.enabled` |
| `config` | Every morning, compares its configuration with the day before; the owl says what each change does and how risky it is. | `configwatch.enabled` |
| `security` | The owl reviews what it exposes, every morning. | `exposure.enabled` |
| `backup` | Backs it up monthly, and before every update. | `backups.enabled` |

Everything that changes a device is a proposal you approve: [Actions and approvals](../using/actions.md).

## Every hour: its ports, and its log

With `devwatch.enabled`, every `mikrotik`, `openwrt`, `linux`, `esxi` and `unifi` device with a
login is read once an hour, with one login (never more often: a device writes each login in its
own log). The main router is never logged in to: its ports are read every minute over its
connection, and its log is always read.

- **Its ports**, with no `manage` needed: each physical Ethernet port's negotiated speed and
  duplex. A port that comes up slower than it usually runs (1 Gbps → 100 Mbps, or half duplex)
  is read again a minute later and, still slower, you get one message: the numbers, and on a
  MikroTik what the other end offers. Back to its usual speed: one more. A port that does it
  twice in a week has a device behind it that changes the link by itself (a computer going to
  sleep drops it to 10/100): you are told so once, then it is left quiet. Its sheet still shows
  it, and **Mute** there stops its messages.
- **Its log**, with `manage: [logs]`: the lines written since the last read.

| kind | Its ports | Its log |
|---|---|---|
| `mikrotik` | `/interface ethernet monitor` | `/log` (in memory: it starts again empty after a restart) |
| `openwrt` | `/sys/class/net` | `logread` |
| `linux` | `/sys/class/net` | The journal: every service's errors and the kernel's lines (links, disks); the auth lines too when lanowl's key does not read them every two minutes. Through sudo when the login needs it. |
| `esxi` | `esxcli network nic list` | `vobd.log` (links, storage, hardware, logins) and `vmkwarning.log` |
| `unifi` | `/sys/class/net` | `/var/log/messages` |

The routine never reaches the owl: Wi-Fi clients joining and leaving, DHCP, ESXi's second copy of
each event, a logout, and lanowl's own logins (by the address the device saw them come from). What
is left is marked when lanowl recognises it — `[link]`, `[reboot]`, `[storage]`, `[hardware]`,
`[memory]`, `[login]`, `[failed-login]`, `[config]` — and the owl reads it with what lanowl knows
about the device: its ports, what lanowl itself did to it in that hour, and the internet at the
time. Normal gets no message. For the first `quiet_days` (7) nothing is sent: what the owl would
have said is on the Timeline and under **Log checks**, so you can read it first.
