# What you need

lanowl runs in Docker on a machine that stays on. Everything else is optional, and each
part you add gives it more to work with.

## The machine

Docker with Compose 2.24 or later (January 2024: `docker compose version` says).

**Linux with Docker is the recommended setup.** The container runs with host networking, so
lanowl sees the network exactly as the host does: `mtr` and `traceroute` see every hop, and
ARP and packet captures see the real wire. A small always-on box is enough: a mini PC, a NUC,
a home server, a VM on your hypervisor.

**Docker Desktop on a Mac or Windows works too**, behind Docker's own NAT. Watching devices,
alerts and the dashboard work the same; the model's per-hop diagnostics then see only the
target, not the hops in between. Two things look different there: every browser reaches lanowl
from Docker's own address (192.168.65.1 on a Mac), so History and Telegram's lines name that
instead of the browser's; and the address lanowl finds for itself is Docker's internal one, so
set this machine's real one in Settings (`observer.host_ip`).

Give the machine a **fixed address** on your LAN (a DHCP reservation is fine). lanowl uses it
to tell its own outage from the network's: if this machine drops off the network, you get one
message saying so, not forty saying everything is down.

**Allow unprivileged ping** on a Linux host. Debian ships it closed, and then every device
reads DOWN:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-ping.conf
```

The second line keeps it across reboots.

## Optional, and what each adds

| What | What it adds | Without it |
|---|---|---|
| A Telegram bot | Alerts, digests, the weekly review, questions, Approve buttons | The dashboard only; nothing reaches your phone |
| A model on [Ollama](https://ollama.com) | The owl: diagnoses, answers, the security review, proposed fixes | Detection, alerts, digests and the dashboard all work |
| A MikroTik as the main router | DHCP leases, new devices, which internet link is in use, the router's log | Every device is still watched by ping, TCP, HTTP, SNMP |
| Logins to your machines | Updates, backups, reboots, config changes, the security review | They are watched, not managed |
| An MQTT broker | Results published for Home Assistant or anything else | Nothing is missing from lanowl itself |

## The model's hardware

Any Ollama model with tool calling works. A larger model reasons better: a 27–35B model on a
machine with 32–64 GB of memory is comfortable. The model can run on another machine than
lanowl (a desktop with a GPU, a Mac with Apple silicon); lanowl calls it over HTTP. See
[The model](../setup/model.md).

## Without Docker

lanowl is a Python package (3.11 or newer): `pip install .` from the repository gives you the
`lanowl` command. The Docker image adds what the model's diagnostics run (`mtr`,
`traceroute`, `dig`, `nmap`, `tcpdump`, `fping`, `arping`, `snmpget`, `ssh`); install those
yourself to get the same. Docker is the supported way.

Next: [Quick start](quick-start.md).
