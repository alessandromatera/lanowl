# The first hour

What happens after `docker compose up -d`, and what is worth tuning in the first days.

## Right away

- **The first sweep** runs within a minute: every device in the inventory is probed, and the
  dashboard fills. A device is shown down only after two missed sweeps in a row
  (`cadence.debounce_fails`), so a single lost ping never turns anything red.
- **The internet** gets its own loop: the addresses in `wan.targets` are pinged every 15
  seconds. The dashboard's Internet card fills as the record grows.
- **The owl's first audit** (with a model) runs at the first sweep, then every hour
  (`cadence.llm_interval_s`). It sends a digest only if it has something new to say; on a
  healthy network you hear nothing.

## With a MikroTik

- **The router's DHCP** is read every five minutes (`mikrotik.discovery_interval_s`). The
  first read is a baseline: what is already on your network is not announced as new.
- Under each site, the dashboard lists the devices on its DHCP that nobody watches, with two
  buttons. **Watch** writes one into `inventory.yaml` and pings it at once; **Known** marks
  it as belonging there, so it no longer counts as unknown. The family's phones are Known;
  the printer is worth a Watch.

## In the morning

With the update check on (`updates.enabled`), lanowl reads every managed machine's waiting
updates at 06:30 (`updates.at`), then the owl reviews what each machine exposes
(`exposure.enabled`). If lanowl starts after that time, the first check runs at once. Only
what is new and matters reaches Telegram; everything is on the Security tab.

The weekly review arrives on Sundays at 10:00 (`weekly`).

## Tuning in the first days

The first days show what is noise on your network. Most of it is settled on the device's page
(Settings → Devices), or in `inventory.yaml` by hand:

| You see | Change |
|---|---|
| A page for something that can wait until morning | Lower its `criticality`: `high` and `warning` ride the next digest, `low` and `info` are told once and never page |
| Solar gear "down" every night, a dusk-to-dawn light every day | `expect_offline: sun` or `day` |
| A plug on weak Wi-Fi going down and up | Give its check more patience: `{type: icmp, timeout_ms: 2500, count: 3}` |
| Five cameras, five messages, when their switch restarts | `depends_on: <the switch's address>` on each camera, or `majority_down_critical: true` on their group |
| Everything at a remote site paging when its tunnel drops | `depends_on` the tunnel's endpoint, and a larger `debounce_fails` for it |
| A device you switch off on purpose (the TV, holiday gear) | Pause it: `/pause tv` on Telegram, or its sheet on the dashboard |
| A diagnosis that misses something only you know | Tell the owl: `/remember the NAS sleeps from 01:00 to 07:00` |

Every one of these is explained in [Devices](../setup/inventory.md) and
[How alerts work](../using/alerts.md).
