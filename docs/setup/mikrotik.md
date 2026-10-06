# Your router (MikroTik)

With a MikroTik as the main router, lanowl reads it, and nothing more:

- **DHCP leases**: new devices, a watched device that DHCP moved, what nobody watches.
- **Routes**: which internet link carries the traffic ([A backup internet line](backup-line.md)).
- **ARP and the ports' link state**: for gear that does not answer ping (`arp` and `link` checks).
- **The log**: the failover's own lines, logins, and anything odd for the owl to read.

Everything else works without it: leave `mikrotik.dhcp_source` empty. With another router,
watch it like any device; an OpenWrt router can still be managed (`kind: openwrt`).

## A read-only user

On the router, create a user that can read and nothing more, allowed only from lanowl's host
(here `192.168.88.5`; older RouterOS calls a service's `available-from` `address`):

```
/user group add name=lanowl-ro policy=read,test,sniff,api,rest-api
/user add name=lanowl group=lanowl-ro address=192.168.88.5/32 password="a long one"
/ip service set www available-from=192.168.88.5/32
```

`test` and `sniff` let the owl ping, traceroute and capture from the router when you ask it to
look into something, and let `arp` checks work; leave them out and it simply cannot.

lanowl watches its own group: a change to it that grants more than `mikrotik.lanowl_policy`
is reported like any other configuration change.

Then give lanowl the router's address, that user and its password: in the first-run setup's
router step (or Settings → Add from the router's list), where **Try the router** checks them.
The setup writes them into the files. By hand instead, in `config.yaml`:

```yaml
mikrotik:
  dhcp_source: "http://192.168.88.1"   # the router's REST address
  credentials: "router-read"           # the login's name in secrets.yaml
```

and in `secrets.yaml`:

```yaml
logins:
  router-read: {user: lanowl, password: "a long one"}
```

If the router refuses the login, lanowl says so once, with what to check (the password, and
the user's `address=`), and does not try again for 15 minutes or until `secrets.yaml`
changes: every refused try is a `login failure` line in the router's log.

## One kept connection instead of polling (recommended)

Over REST, every read is a login, and the router's log fills with them. The API over TLS keeps
one connection open instead. RouterOS will not self-sign a server certificate ("CA not
found"), so a small local CA signs it:

```
/certificate add name=lanowl-ca common-name=lanowl-ca key-usage=key-cert-sign,crl-sign days-valid=3650
/certificate sign lanowl-ca
/certificate add name=lanowl-api common-name=192.168.88.1 subject-alt-name=IP:192.168.88.1 days-valid=3650
/certificate sign lanowl-api ca=lanowl-ca
/ip service set api-ssl certificate=lanowl-api available-from=192.168.88.5/32 disabled=no
```

```yaml
mikrotik:
  api:
    enabled: true
    port: 8729
    fingerprint: ""            # filled in below
```

The certificate is self-signed, so lanowl trusts it by its fingerprint. On the first
connection the log says `router API: pin this certificate: mikrotik.api.fingerprint: …`. Put
that value in `config.yaml` and restart. Until then the link is encrypted but not
authenticated, and the dashboard's Services list says "certificate not pinned".

When the API is down, lanowl falls back to REST for every read, and the Services list shows
it.

## The other settings

| Key | Default | What it does |
|---|---|---|
| `verify_tls` | `false` | Verify the REST endpoint's certificate (for `https://` in `dhcp_source`) |
| `discovery_interval_s` | `300` | How often the DHCP leases are read |
| `interface_interval_s` | `60` | How often the port table is read, when a `link` check needs it |
| `lanowl_group` | `lanowl-ro` | The router group of lanowl's user, watched for changes |
| `lanowl_policy` | `[read, test, sniff, api, rest-api]` | What you granted it on purpose |
| `api.heartbeat_s` | `30` | How often the kept connection is checked |
| `api.timeout_s` | `10` | How long a read may take |

## What lanowl never does on the router

It never writes. Its user's group has no `write` policy, so it could not if it tried. A
RouterOS update or a reboot, when you approve one, runs over ssh with a separate login of its
own, named on the router's inventory entry (`credentials:`), and only from the fixed list of
actions.
