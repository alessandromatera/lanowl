# A backup internet line

Most networks have one line, and the internet is simply up or down. With a second line (a
MikroTik with dual WAN: fibre plus LTE, say), lanowl tells three states apart:

| State | What it means | What you get |
|---|---|---|
| **Online** | The main link carries the traffic | Nothing |
| **On backup** | The router failed over: the internet works, over the backup | One 🔴 alert, and one 🟢 when the main link is back |
| **Down** | Nothing answers from the internet at all | Past 90 seconds (`wan.watch.min_outage_s`), one 🔴 alert, delivered when the line is back. Shorter ones are counted as blips in the digest. |

Pings alone cannot tell the first two apart: they answer over either link. The router's route
table can, so lanowl needs a MikroTik ([Your router](mikrotik.md)).

## Name the main route

On the router, give the main link's default route a comment:

```
/ip route set [find dst-address=0.0.0.0/0 gateway=<the fibre's gateway>] comment=main
```

and tell lanowl, with the names you use for your links:

```yaml
wan:
  path:
    route_comment: "main"     # the comment on the MAIN default route
    main: "fibre"             # what every message calls each link
    backup: "LTE"
```

While that route is active, lanowl is online on the main link. When it is not, it is on the
backup. Without `route_comment`, there is one line, and nothing speaks of a backup.

| Key | Default | What it does |
|---|---|---|
| `severity` | `critical` | Being on the backup pages you. `warning`: the next digest instead. |
| `interval_s` | `300` | How often the route is read by REST (with the API, every ping round) |
| `main_probe`, `backup_probe` | | An address the router sends only over that link, typically its failover's own health probes. Lets the owl test each link on its own (`link_test`). |
| `backup_standby` | `false` | The backup switches its uplink on only when the router chooses it (an LTE or radio link): silence from it while the main link works is normal. |

## The failover's own log lines

A failover script logs when it takes the main link out and puts it back. Give lanowl those
lines, and it reads the moment of each switch from the router's log rather than from its own
pings, which are up to 15 seconds late:

```yaml
wan:
  watch:
    log_down_match: "WAN-FAILOVER: main down"   # part of the line your script logs
    log_up_match: "WAN-FAILOVER: main up"
    routine: []                                  # other lines that are just failover chatter
```

Both or neither: without them no link changes are read from the log. The owl reads any
other odd line in the router's log (`log_triage`), so add to `routine` what is normal on your
router.

A failover that is already over by the time lanowl's pings would notice (the log shows the
main link dropping and coming back within seconds) is still reported, as one alert of
`flap_severity` saying how long it lasted and how many times it happened in 24 hours. The
incident is held open for `flap_hold_s` after it, so a burst of flaps is one incident.

## A standby backup router

When the backup is a router of its own (a MikroTik on LTE whose netwatch turns its uplink on
when the main router goes quiet), lanowl can read it while the main link is down: is its
uplink on, how strong its signal is, and whether the internet comes through it.

```yaml
wan:
  standby: {ip: "192.168.88.7", iface: "lte1", probe: "1.1.1.1", every_s: 30, grace_s: 120}
```

It is read only while the main link is down, never otherwise, with its login from
`secrets.yaml`. What it saw is kept with the outage, for the owl and for you.

## Where it broke

Every blip and outage keeps its evidence: the rounds that failed, whether the router itself
and the provider's first hop answered, the router's own pings (its netwatch), and its log
around the moment. On the dashboard, tap an event on the Internet card: lanowl says where it
most likely broke (lanowl's own link, your line, or further out at the provider), and
**Ask about it** hands the same evidence to the owl.
