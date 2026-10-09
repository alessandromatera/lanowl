# Device kinds and features

A device's `kind` says what it is; its `manage` list says what lanowl may do with it besides
watching. A feature works only where the kind can do it, with the login it needs, and with
its switch on in `config.yaml`. `lanowl --check` shows the result per device.

## What each kind can do

| kind | logs | updates | upgrade | reboot | restart | config | security | backup |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `mikrotik` | | ✓ | ✓ | ✓ | | ✓ | ✓ | ✓ |
| `openwrt` | | ✓ | | ✓ | | | ✓ | |
| `linux` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `esxi` | | ✓ | | | | | ✓ | ✓ |
| `unifi` | | ✓ | | ✓ | | | | |
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
| `logs` | Reads its auth log for security events: failed-login bursts, logins from unknown places, connection floods. The owl reads lines no rule explains. | `hostlog.enabled` |
| `updates` | Checks its updates every morning. A security update waiting two days, or a reboot pending three, gets one message. | `updates.enabled` |
| `upgrade` | May propose installing them. With backups on for that machine, it is backed up first, and a failed backup stops the update. | `actions.enabled` |
| `reboot` | May propose a reboot. Its alerts, and those of the devices on its Wi-Fi or listed in `also_hold`, are held while it restarts. | `actions.enabled` |
| `restart` | May propose restarting one of `restart.units`, and nothing else. | `actions.enabled` |
| `config` | Every morning, compares its configuration with the day before; the owl says what each change does and how risky it is. | `configwatch.enabled` |
| `security` | The owl reviews what it exposes, every morning. | `exposure.enabled` |
| `backup` | Backs it up monthly, and before every update. | `backups.enabled` |

Everything that changes a device is a proposal you approve: [Actions and approvals](../using/actions.md).
