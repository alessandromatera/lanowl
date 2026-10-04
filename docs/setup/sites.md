# Remote sites

lanowl can look after more than one network: your home, and the places you reach over a VPN,
such as a cabin, an office or your parents' house. Each is a **site**, with its own devices
on the dashboard, its own DHCP list, and its own checks.

```yaml
sites:
  dhcp_every_min: 30
  scan: {enabled: true, at: "05:00", seconds: 30}
  list:
    - {key: home, name: "Home", nets: ["192.168.88.0/24"]}
    - {key: cabin, name: "Cabin", nets: ["10.8.0.9/32", "192.168.70.0/24"],
       router: "10.8.0.9", kind: routeros, criticality: info}
```

| Key | What it is |
|---|---|
| `key`, `name` | An id, and what the dashboard calls it. `home` is the main site; it is added if you leave it out. |
| `nets` | The networks that belong to it. A device belongs to the first site whose network holds its address; the rest are home's. |
| `router` | The site's router, an address in the inventory. lanowl logs into it to read its DHCP. |
| `kind` | `routeros` (MikroTik) or `openwrt`. Taken from the router's inventory entry when left out. |
| `criticality` | What a device you watch there gets by default: `info` for a remote site, `low` for home. |

## The site's router

Put the router in the inventory, reached through what carries the tunnel, with its login:

```yaml
  - ip: 203.0.113.10
    name: "VPS"
    group: vpn
    criticality: warning
    depends_on: wan
    checks: [{type: tcp, port: 22}]       # many VPSs drop ping

  - ip: 10.8.0.9
    name: "Cabin router"
    group: vpn
    criticality: info
    depends_on: 203.0.113.10              # the VPN hub carries its tunnel
    debounce_fails: 5                     # a tunnel re-keys after a failover
    kind: mikrotik
    credentials: routers
    checks: [{type: icmp}]
```

The `depends_on` chain matters: when the VPS or your own internet is down, the cabin is not
a second alert, it is named in the first one. `debounce_fails: 5` keeps a tunnel that takes a
minute to come back from paging you.

## What lanowl does with a site

- **Its DHCP**, read every `dhcp_every_min` minutes: the dashboard lists what is on the
  site's network, by name and maker, with **Watch** and **Known** for each device. A
  watched device is pinged from then on, behind the site's router, at the site's
  criticality, and followed by its MAC when DHCP moves it. By default only the router itself
  is watched.
- **Fixed addresses**: devices that hold no lease are found in the router's ARP table, read
  with the DHCP, and once a month by asking the router who is on each network (RouterOS's
  `ip-scan`, or a ping sweep on OpenWrt). Never a port scan. On `scan.day` (the same day as
  the monthly vulnerability scan) at `scan.at`, or with **Scan now**.
- **Checks from the router**, when the owl needs them: a ping from inside the site, its DHCP,
  and a speed test of its internet line. The speed test runs only when you ask: it is their
  bandwidth.
- **New devices**: one never seen on the site's network before is marked new for a day
  (`discovery.new_window_h`). What was there the first time a site was read is not new.

Nothing here writes to a router: lanowl only prints, pings and scans.
