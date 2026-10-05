# Actions and approvals

A monitor that can only look can say what is wrong but never settle it. So the owl may
**propose** a change, and you **approve** it, on Telegram with a button or on the dashboard
with your PIN. Nothing changes by itself, and the model never writes a command: it names an
action from a fixed catalog and a device, and lanowl builds the command.

## The catalog

| Action | What runs | On which devices |
|---|---|---|
| Reboot the device | Its kind's own way: RouterOS `/system reboot`, `reboot` over ssh, a camera's API, Home Assistant, a button entity | `manage: [reboot]` |
| Restart a service | `systemctl restart <unit>` | `manage: [restart]`, only a unit in its `restart.units` |
| Update the system | `apt-get upgrade --with-new-pkgs`, non-interactive, config files kept | `manage: [upgrade]`, Linux |
| Update RouterOS | Download the package, then reboot to install it | `manage: [upgrade]`, MikroTik |
| Reboot the Shelly | Its own reboot endpoint. The relays never switch. | `kind: shelly` |
| Scan the open ports | `nmap -sT` (no raw sockets) | Main LAN devices, except denied groups |
| Identify the services | `nmap -sV` on 1 to 10 ports | Main LAN devices, except denied groups |

```yaml
actions:
  enabled: true
  mode: "shadow"            # "shadow": record what WOULD run; "live": it runs
  catalog:
    nmap_scan: {deny_groups: ["security"]}
    nmap_service: {deny_groups: ["security", "iot"]}
    reboot: {hold_min: 5}
```

Start in **shadow** mode: proposals arrive and you answer them, but an approval only records
what would have run. When you trust what it proposes, switch to `live`.

Actions need a [dashboard PIN](dashboard.md#the-pin): until one is set they stay off, and
lanowl says so on Telegram when it starts. Send `/pin` to the bot, or set
`actions.pin_sha256` in `config.yaml`.

## The rules every proposal passes

Before you are asked:

- The device is in the inventory, and the action is allowed on it (its `manage` list, its
  kind, the catalog's deny lists).
- Never lanowl's own machine. Scans only on the main LAN.
- Not too many: at most `max_pending` waiting at once (3) and `max_per_day` a day (20). An
  action that already ran on the device is not proposed again for 30 minutes (an hour for an
  update).
- The hourly audit proposes the same thing at most once a day (`repeat_after_h`), answered
  or not.
- **A read-only check of the device itself**: is it still worth doing, and is it safe? A
  Shelly whose relay would come back off after a reboot is refused, because a pump or a heater
  may be wired that way. A device with `role: wan-gateway` is not rebooted while the internet
  runs through it. A service lanowl's login may not restart is refused in live mode.

A refused proposal never reaches you; it is kept, with why, and the owl is told.

## Approving

The proposal shows what will run, the owl's reason, the result of its check, and its risk:

```text
🛠 Reboot the device — Cam Garage (192.168.88.23)
Home Assistant: button.press button.garage_cam_plug_restart
Why (model): dark since 13:35 while the other four cameras answer; its plug can power-cycle it
Checked: through Home Assistant's button.garage_cam_plug_restart
⏳ Waiting for you until 14:28 · approving runs it
[ ✅ Approve ] [ ✖️ Reject ]
```

When you approve, the check runs again (the network may have moved on), then the action,
one at a time, and the same message is edited with what happened. A proposal nobody answers
expires after `expire_min` minutes (15). An action approved on the dashboard is announced on
Telegram: something that changed the network is never silent there.

During a reboot, the device's alerts are held, with those of the devices on its Wi-Fi
(`role: ap`) and any in `also_hold`, until it is back or `hold_min` runs out. An update is
preceded by a backup when backups are on for that machine, and a failed backup stops it.

## Asking for one yourself

`/reboot ap porch` or `/upgrade home server` on Telegram, or **Reboot** and **Update** in a
device's sheet on the dashboard. Your own request passes the same rules and the same check,
and still waits for your button or your PIN, so a typo never reboots the wrong thing. It does
not count against the daily limit.

## Investigation sessions

To look further than its read-only tools, the owl runs diagnostics from a catalog of its own
(`mtr`, DNS, TLS, captures, checks from the router, another LAN host or the VPS). In your
questions they run at once: asking is the approval. The hourly audit, which nobody asked, may
run a few passive ones by itself; for more, it asks you to open a **session**, a proposal
like any other, listing the checks it wants. Approve it and the owl has `session.minutes` and
`session.max_checks` to look, then reports back. **End** closes it early.

```yaml
actions:
  session: {minutes: 15, max_checks: 10, audit_checks: 3, max_per_day: 8}
  checks:
    lan_subnets: ["192.168.88.0/24"]
    home_server: "192.168.88.10"     # another LAN host to look from (by lanowl's key)
    vps: "203.0.113.10"              # a public server to look from
```

Changes stay proposals, session or not.

## The record

Every proposal, refused ones included, is kept with what you decided and what happened: the
Ask tab's **Proposed and run**, the Timeline's **Actions**, and the owl's own records, so
"what did you restart last week?" has an answer.
