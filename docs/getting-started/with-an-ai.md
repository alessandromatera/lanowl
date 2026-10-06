# Set it up with an AI assistant

lanowl is configured in plain YAML, which an AI assistant (Claude, ChatGPT, Gemini, or any
other) writes well. You describe your network in your own words; it writes `config.yaml` and
`inventory.yaml`; `lanowl --check` tells you both what is wrong, and you go round until it is
clean. This page is what to give the assistant, what to ask, and what never to paste.

## What to give it

The assistant needs three things: the example files, the documentation, and your network.

- **The example files**, which carry every key with a comment:
  [`config.example.yaml`](https://raw.githubusercontent.com/alessandromatera/lanowl/main/config.example.yaml),
  [`inventory.example.yaml`](https://raw.githubusercontent.com/alessandromatera/lanowl/main/inventory.example.yaml),
  [`secrets.example.yaml`](https://raw.githubusercontent.com/alessandromatera/lanowl/main/secrets.example.yaml).
  An assistant that can open links reads them itself; otherwise paste them.
- **The documentation**, at [lanowl.com/docs](https://lanowl.com/docs/): above all
  [Devices](../setup/inventory.md), [config.yaml](../setup/config.md) and
  [Device kinds and features](../reference/kinds.md).
- **Your network**: the router, what runs where, every device you care about with its address,
  what it is and how much it matters, what sleeps or is switched off on purpose, and how you
  reach lanowl's host and the model.

## What never to give it

**No secret, ever.** Not a password, not the Telegram token, not a key, not your real
`secrets.yaml`. The assistant never needs one: the inventory names each login
(`credentials: routers`), and you set the login itself on the dashboard (Settings → Secrets,
Add a login) or in `secrets.yaml` on your own machine. Ask the assistant for the list of
logins to create, and fill them in yourself.

Addresses, device names and MAC addresses are your call: they say a lot about your home to
whoever runs the assistant. A local model on your own Ollama is an option for this too.

## The first configuration

Copy this, fill in the part about your network, and send it:

```text
I want to set up lanowl, a self-hosted AI network monitor, for my home network.
Its documentation is at https://lanowl.com/docs/ and its example files are:
https://raw.githubusercontent.com/alessandromatera/lanowl/main/config.example.yaml
https://raw.githubusercontent.com/alessandromatera/lanowl/main/inventory.example.yaml
https://raw.githubusercontent.com/alessandromatera/lanowl/main/secrets.example.yaml
(If you cannot open links, say so and I will paste them.)

Write my config/config.yaml and config/inventory.yaml. Start from the examples, keep their
keys and comments, and change only what my network needs.

My network:
- Router: <model> at <address>, LAN <network>, <one internet line / fibre + LTE backup>.
- lanowl runs on <machine> at <address>, in Docker.
- The model: Ollama on <machine> at <address>, model <name>  (or: no model yet).
- Telegram chat id: <number>  (the bot token I keep to myself).
- Devices (name, address, what it is, how much it matters):
  <one per line>
- What sleeps by design (solar at night, a dusk-to-dawn light): <...>
- What is often off on purpose (the TV, a printer): <...>
- What sits behind what (cameras on a PoE switch, a site behind a VPN): <...>
- What should wake me at night: <...>

Rules:
- Every device once in inventory.yaml, with checks that suit it: icmp for most, tcp for a
  service's port, http for a web interface. A named check (name: "MQTT") is a service.
- criticality: critical only for what should wake me; high or warning for what can wait for
  the next digest; low or info for things that are often off.
- expect_offline for what sleeps by design; depends_on for what is reached through another
  device; group devices that share fate, with majority_down_critical where a group going
  dark together means one cause.
- kind and manage only with the built-in kinds (mikrotik, openwrt, linux, esxi, unifi,
  homeassistant, reolink, shelly, generic), and only the features each kind supports, as the
  docs' table says. If a device needs a kind of its own, tell me instead of inventing one.
- Logins only by name in credentials:. Never write a password, token or key.
- Leave every optional feature in config.yaml off unless I asked for it.
- Ask me before guessing anything you are not sure of.

At the end, list the logins and tokens I must put in secrets.yaml, and remind me to run
lanowl --check.
```

## Fixing what `--check` says

Run the check and give the assistant its output. It never contains a secret: it says where
each one comes from, not its value.

```bash
docker compose -f docker/compose.yaml run --rm lanowl lanowl --check
```

```text
lanowl --check says this about the files you wrote. Fix them, change nothing else, and
explain each change in one line:

<paste the output>
```

Go round until it shows no ✗. Then a dry run (`--once --no-llm --no-mqtt --no-telegram`, see
[Quick start](quick-start.md)) shows every device answering, or not.

## Adding the devices your router knows

Once lanowl reads your router, the dashboard lists every device on its DHCP that nobody
watches. Or take the router's own list (on a MikroTik: `/ip dhcp-server lease print terse`)
and pick what to watch:

```text
Here are devices from my router's DHCP list. Add the ones I marked with * to my
inventory.yaml, in the same style as the devices already there, with a name I will
recognise, the right group, criticality and checks, and mac: so lanowl follows them when
DHCP moves them. Ask me what each unknown one is rather than guessing.

<paste the lines, with a * on the ones to add>
```

## The router's read-only user

The commands in [Your router](../setup/mikrotik.md) assume lanowl at `192.168.88.5`. An
assistant adapts them in a moment:

```text
Adapt lanowl's MikroTik setup (https://lanowl.com/docs/setup/mikrotik/) to my router:
RouterOS <version>, lanowl's host at <address>, the router at <address>. Give me the
commands for the read-only user and for the API over TLS, in order, and tell me what each
one does before I paste it. Use "<PASSWORD>" where the password goes.
```

## A kind of your own

For a device lanowl does not know (a NAS, a firewall appliance), a profile is a YAML file of
commands, never code ([Device kinds of your own](../setup/profiles.md)):

```text
Write a lanowl profile for my <device and system, e.g. Synology DSM 7.2>, reached over ssh.
Follow https://lanowl.com/docs/reference/profiles/ and the shipped example
https://raw.githubusercontent.com/alessandromatera/lanowl/main/src/lanowl/profiles/macos.yaml
Every command must only read, except reboot. For each one, tell me how to try it over ssh
first and what its output should look like, so I can check the parser before I use it.
```

Try each command on the device yourself before you trust it: the assistant cannot see your
device's real output.

## Your network in your own words

`network.description` is the paragraph every prompt the owl reads begins with. An assistant
can draft it from your notes:

```text
From these notes, write the network.description for lanowl's config.yaml: three to six plain
sentences on the links, the sites, what runs where, what matters, and what I chose on
purpose. No marketing, no lists.

<your notes>
```

## With a coding assistant in the repository

A coding assistant that works in a folder (Claude Code, Codex, Gemini CLI, Cursor) can read
the docs and examples itself, write the files, and run `--check` for you. Open it in the
cloned `lanowl` folder and give it the first prompt above, with one more rule:

```text
Do not open config/secrets.yaml or any key: I fill those in myself.
```

Create `config/secrets.yaml` only after it is done, or keep the example's placeholders in it
until then.

## Trust, but check

The assistant writes YAML that looks right; lanowl decides whether it is. Read what it
changed, run `lanowl --check`, and start with actions off (`actions.enabled: false`) or in
shadow mode, so nothing changes on your network while you learn what the configuration does.
