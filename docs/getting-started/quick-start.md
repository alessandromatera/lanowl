# Quick start

From nothing to a dashboard of your own network in about ten minutes: three files to fill
in, one command to check what lanowl will do, one to start it.

## 1. Get lanowl and copy the three files

Everything lanowl reads lives in one `config` folder, mounted read-only into the container.

```bash
git clone https://github.com/alessandromatera/lanowl && cd lanowl
mkdir config
cp config.example.yaml config/config.yaml
cp inventory.example.yaml config/inventory.yaml
cp secrets.example.yaml config/secrets.yaml && chmod 600 config/secrets.yaml
ssh-keygen -t ed25519 -N '' -C lanowl -f config/id_ed25519
cp docker/env.example docker/.env
```

| File | What goes in it | Share it? |
|---|---|---|
| `config/config.yaml` | Everything lanowl does. Every optional feature starts switched off. | Yes |
| `config/inventory.yaml` | The devices: how each is watched, and what lanowl may do with it. | Yes |
| `config/secrets.yaml` | Every secret: device logins, the Telegram token, lanowl's ssh key. | Never |
| `config/id_ed25519` | lanowl's own ssh key, for the machines it logs in to by key. | Never |

## 2. Describe your network

Open `config/config.yaml` and start with `network.description`: a few sentences in your own
words. Every prompt the model reads begins with them, so say what no inventory can: the
links, the sites, what runs where, what you chose on purpose.

```yaml
network:
  description: |
    A family home: LAN 192.168.88.0/24 behind a MikroTik router (192.168.88.1).
    Fibre is the main link; an LTE router takes over when it fails.
    The cameras hang off a PoE switch.
```

Then the Telegram chat lanowl writes to (how to find its id: [Telegram](telegram.md)):

```yaml
telegram:
  chat_id: "100000001"
```

The bot's token is a secret, so it goes in `config/secrets.yaml`:

```yaml
tokens:
  telegram: "123456:ABC..."
```

## 3. List a few devices

Start small in `config/inventory.yaml`: the router, a server, whatever you would want to hear
about at night. You can add the rest later; once lanowl reads your router's DHCP, the
dashboard lists every device nobody watches, with a **Watch** button.

```yaml
groups:
  network: {majority_down_critical: true}
  home:    {majority_down_critical: false}

devices:
  - ip: 192.168.88.1
    name: "Router"
    group: network
    criticality: critical        # pages at once
    checks: [{type: icmp}, {type: http, port: 80}]

  - ip: 192.168.88.50
    name: "Solar inverter"
    group: home
    criticality: warning
    expect_offline: sun          # dark at night by design: never an alert
    checks: [{type: icmp}]
```

What each field means, and every kind of check: [Devices](../setup/inventory.md).

## 4. Tell Docker where it runs

`docker/.env` holds what differs between machines:

```bash
LANOWL_HOST_IP=192.168.88.5                  # this machine's address on the LAN
LANOWL_MODEL_URL=http://192.168.88.6:11434   # where Ollama runs (leave it without a model)
LANOWL_WEB_PORT=80                           # the dashboard
TZ=Europe/Berlin                             # sunrise, sunset and the router's log
```

On a Linux host, allow unprivileged ping first, or every device reads DOWN:
`sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` ([why](requirements.md)).

## 5. Check the plan

Before anything runs, ask lanowl what it will do with each device, and why not. Nothing is
probed and nothing is sent.

```bash
docker compose -f docker/compose.yaml run --rm lanowl lanowl --check
```

The first run builds the image, which takes a few minutes. The demo house answers:

```text
27 device(s) watched, 15 managed, 0 problem(s). Profiles: macos. ✓ on · ○ switched off in config.yaml · ✗ cannot

Router (192.168.88.1) · mikrotik · login: password
  ✓ updates   checks its updates every morning
  ✓ upgrade   may propose installing them
  ✓ reboot    may propose a reboot
  ✓ config    tells what changed in its configuration
  ✓ security  reviews what it exposes, every day
  ✓ backup    backs it up, monthly and before updates

Home server (192.168.88.10) · linux · login: key
  ○ logs      reads its auth log for security events — off: hostlog.enabled in config.yaml
  ✓ updates   checks its updates every morning
  ✓ upgrade   may propose installing them
  ✓ reboot    may propose a reboot
  ✓ restart   may propose restarting a listed service
  ✓ config    tells what changed in its configuration
  ✓ security  reviews what it exposes, every day
  ✓ backup    backs it up, monthly and before updates
  …

Secrets: /config/secrets.yaml · 9 login(s), 2 token(s), mode 600
  ✓ Telegram token  from secrets.yaml
  ✓ Home Assistant  from secrets.yaml
  ✓ router login    lanowl, from secrets.yaml login router-read
  ○ MQTT login      not used: no mqtt.host
  ✓ ssh key         id_ed25519, from secrets.yaml

Model: ollama · qwen3:30b at http://192.168.88.6:11434

Shell: off
```

A **✗** says what is wrong and how to fix it, for example:

```text
  ✗ ssh key         others can read id_ed25519, and ssh refuses such a key: chmod 600 id_ed25519
```

`--check` exits with 1 when anything is wrong, so a script can stop a deploy on it.

## 6. A dry run

One sweep, printed, with nothing sent anywhere:

```bash
docker compose -f docker/compose.yaml run --rm lanowl \
  python -m lanowl.main --once --no-llm --no-mqtt --no-telegram
```

Every device is listed as `UP`, `DOWN`, `ZZZ` (asleep on schedule) or `PAUS` (paused), with
its latency and any check that failed.

## 7. Start it

```bash
docker compose -f docker/compose.yaml up -d
```

Open `http://<this machine>/`. The first sweep is done within a minute. Send `/start` to your
bot: it answers with what it can do.

Next: [Telegram](telegram.md), then [The first hour](first-hour.md).
