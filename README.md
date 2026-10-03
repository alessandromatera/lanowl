# lanowl 🦉

**A watchful, read-only caretaker for home and small-office networks.**

lanowl checks every device on your network once a minute and tells you about a problem **once
per incident**, not once per blip. It knows the difference between "the main line failed
over" and "there is no internet at all". It looks after more than one site: your home, and
the routers you reach over a VPN.

On top of that deterministic monitor sits a **local model, the owl**. It diagnoses what broke,
answers your questions about the network, reviews its security every morning, and proposes
fixes. It **changes nothing by itself**: a change runs only when you press a button.

> **Status: pre-alpha.** lanowl comes out of a monitor that has run a real home network
> (MikroTik, OpenWrt, Linux servers, Shelly, cameras, a VPS hub, two remote sites) since
> August 2026. It is being turned into something anyone can install, and is not ready yet.

## What it does

- **Detection that does not depend on the model.** Ping, TCP, HTTP, SNMP, the router's ARP
  table, a router port's link state: debounced, grouped (a dead switch is one message, not
  twelve), with devices that sleep by design (solar gear at night) never paging.
- **One message per incident.** A flapping line pages once and then says "unstable for 3h ·
  5 outages" when it settles. Recoveries say when, and for how long.
- **The internet, properly.** A fast ping loop (15 s), the router's own log and route table:
  `ok`, `down`, and, with a backup link, `on backup`. Every blip keeps its evidence, so
  "where did it break?" has an answer: your line, the provider, or lanowl's own view.
- **The owl.** Read-only tools, a fixed catalog of diagnostics (mtr, DNS, TLS, scans, packet
  headers, the router's own ping) and a sandboxed shell with no keys in it. It diagnoses
  incidents, answers questions on Telegram and the dashboard, remembers what you tell it,
  reviews security daily, and grades its own past diagnoses.
- **Propose → approve → run.** Reboots, updates, service restarts and scans are proposals with
  a button; the model fills typed slots in a fixed catalog and never writes a command.
- **Its own dashboard**, made for a phone, that works when the internet does not.
- **Sites.** Remote routers over WireGuard: their DHCP, their devices, checks from them.

## Quick start (Docker)

```bash
git clone https://github.com/alessandromatera/lanowl && cd lanowl
mkdir config
cp config.example.yaml config/config.yaml        # then edit: network, Telegram, the router
cp inventory.example.yaml config/inventory.yaml  # the devices to watch
cp secrets.example.yaml config/secrets.yaml && chmod 600 config/secrets.yaml
cp docker/env.example docker/.env                # this host's address, the model's URL, TZ
docker compose -f docker/compose.yaml up -d
```

Then open `http://<this host>/`. On Linux, allow unprivileged ping first
(`sysctl -w net.ipv4.ping_group_range="0 2147483647"`), or every device reads DOWN.

What lanowl will do with each device, and why not:

```bash
docker compose -f docker/compose.yaml run --rm lanowl lanowl --check
```

A dry run, one sweep printed and nothing sent:

```bash
docker compose -f docker/compose.yaml run --rm lanowl python -m lanowl.main --once --no-llm --no-mqtt --no-telegram
```

## Configure

Three files, all under `config/`:

| file | what | shared? |
|---|---|---|
| `config.yaml` | everything lanowl does, with every optional feature off | yes |
| `inventory.yaml` | the devices: how each is watched, and what lanowl does with it | yes |
| `secrets.yaml` | device logins, by name; mode 600, mounted read-only | **never** |
| `profiles/` | device kinds of your own (optional) | yes |

Two settings shape how the owl thinks:

- **`network.description`**: a few sentences about your network, in your own words: the
  links, the sites, what runs where, what you chose on purpose. Every prompt gets it.
- **`ollama.persona`**: `owl` (the default), or `""` for plain prose. The owl's voice is
  calm and brief and never changes a severity; its words carry 🦉, the monitor's keep 🔴🟡🟢.

**A backup internet link** is optional. Without `wan.path.route_comment` lanowl assumes one
line, and nothing speaks of failover. With it (a MikroTik dual-WAN), name your links
(`wan.path.main` / `backup`) and every message uses those names.

## Devices

Each device is described once, in the inventory. Watching it needs only an address and its
checks. What lanowl does with it besides is set on the device too:

```yaml
- ip: 192.168.88.1
  name: Router
  kind: mikrotik                 # what it is
  credentials: routers           # its login, by name, in secrets.yaml
  manage: [updates, upgrade, reboot, config, security, backup]
```

| feature | what lanowl does |
|---|---|
| `logs` | reads its auth log for security events |
| `updates` | checks its updates every morning |
| `upgrade` | may propose installing them |
| `reboot` | may propose a reboot |
| `restart` | may propose restarting one of its listed services |
| `config` | tells what changed in its configuration |
| `security` | reviews what it exposes, every day |
| `backup` | backs it up, monthly and before updates |

Built-in kinds and what each can do:

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

Any device can be rebooted through a Home Assistant button (a smart plug):
`reboot: {ha_button: button.nvr_plug_restart}`. A feature's options sit under its name:
`restart: {units: [mosquitto]}`, `backup: {paths: [etc, home]}`,
`reboot: {risk: "...", hold_min: 10}`, `logs: {public: true, about: "..."}`.

**Logins** (`secrets.yaml`) are a user with a password, lanowl's ssh key (`key: true`), or both
(the key logs in, the password is what sudo asks for). A user other than root needs sudo for
what reads or changes the system.

**A kind of your own** is a profile: `config/profiles/<kind>.yaml`, a command per operation
and a fixed parser for what it prints, never code. lanowl ships `macos` as one; copy it:

```yaml
kind: macos
ops:
  version:  {cmd: "sw_vers -productName; sw_vers -productVersion", parse: lines}
  updates:  {cmd: "softwareupdate --list 2>&1", parse: {regex: '^\* Label: (?P<pkg>.+)$'}}
  uptime:   {cmd: "sysctl -n kern.boottime", parse: boottime}
  reboot:   {cmd: "shutdown -r now", sudo: true, back_s: 600}
  config:   {cmd: "scutil --get ComputerName; pmset -g custom"}
  security: {cmd: "fdesetup status; csrutil status; spctl --status"}
```

Operations: `version`, `updates`, `uptime`, `reboot`, `config`, `security`, `backup`.
Parsers: `text`, `lines`, `first_line`, `seconds`, `proc_uptime`, `boottime`, `{regex: ...}`.

## The model

Any [Ollama](https://ollama.com) model with tool calling. A larger model reasons better: a
27–35B model on a 32–64 GB machine is comfortable. Without a model everything still works:
detection, alerts, digests, the dashboard. The switch on the dashboard (or `/model off`)
puts the owl to sleep.

## Safety

- Read-only unless you press a button; actions are a fixed catalog, validated before they run.
- The model never sees a password; logins reach ssh through `SSH_ASKPASS`, never argv.
- The model's shells are sandboxes beside lanowl, with no key, no config and no state; their
  walls are proven before the tool is offered.
- The dashboard accepts only JSON POSTs and IP-literal `Host` headers.

## License

Apache-2.0. See [LICENSE](LICENSE).
