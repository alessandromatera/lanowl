# Quick start

From nothing to a dashboard of your own network in about ten minutes, without opening a file:
three commands, then the page.

## 1. Start it

```bash
git clone https://github.com/alessandromatera/lanowl && cd lanowl
docker compose -f docker/compose.yaml up -d
docker exec lanowl lanowl --setup-code
```

The first start builds the image, which takes a few minutes. Then lanowl finds the `config`
folder empty and writes what it needs there:

| File | What goes in it | Share it? |
|---|---|---|
| `config/config.yaml` | Everything lanowl does: at first, the dashboard, the internet watch, Telegram's questions and the week in review. Every optional feature starts switched off. | Yes |
| `config/inventory.yaml` | The devices: how each is watched, and what lanowl may do with it. Empty until the setup. | Yes |
| `config/secrets.yaml` | Every secret: device logins, the Telegram token. Empty until the setup. | Never |
| `config/id_ed25519` | lanowl's own ssh key, for the machines it logs in to by key. | Never |

Each one is mode 600 and belongs to you (the owner of the folder), with no example address
in it. The dashboard fills them; you can still edit them by hand.

On a Linux host, allow unprivileged ping, or every device reads DOWN:
`sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` ([why](requirements.md)).

## 2. Open the dashboard

Open `http://<this machine>:8088/`. Until it has a password, anyone on your network could
open it, so it first asks for the code the third command printed. Then choose the dashboard's
password, and check the time zone: it comes from your browser, and sunrise, sunset and the
router's log times are read in it.

## 3. Your router

lanowl reads your router's DHCP list to find your devices. Type its address
(`http://192.168.88.1`), and the user and password lanowl logs in with: a read-only user is
enough ([making one on a MikroTik](../setup/mikrotik.md)). **Try the router** logs in and
counts the addresses on its DHCP list. Nothing is written yet.

The password goes into `secrets.yaml` at the last step and is never shown again, on this page
or any other. It crosses your network once, in plain HTTP unless lanowl sits behind an HTTPS
proxy, as the dashboard password does.

Not a MikroTik? lanowl reads DHCP only from RouterOS. **Sweep the network instead** pings every
address of the main network once and lists who answered.

## 4. Your devices

Pick what to watch from the list. Each gets a name, a group, a criticality and a ping check.
A kind guessed from the maker (a MikroTik, a Shelly, a Reolink) is marked as a guess.

With a kind, a device asks for its login right there: the user and the password lanowl logs
in with, and then lanowl can check its updates, back it up and reboot it when you approve.
Leave them empty and it is only watched. Instead of a password, a Linux machine can use
lanowl's own ssh key: the page gives the one line to run on it, ready to copy. Or pick a login
that is there already, to share one between devices.

## 5. Telegram

Telegram is where lanowl writes: alerts, the morning digest, the Approve buttons, its answers.
In Telegram, send `/newbot` to **@BotFather**: it answers with a token. Paste it and **Check
the token**: lanowl asks Telegram which bot it is and shows its name. Then send `/start` to
your bot from the phone you want the alerts on; the chat appears on the page within seconds.
**Use this chat** sets it, and the bot says hello there.

Optional: **Skip** it and the dashboard works alone. Settings → Secrets sets the token later
([Telegram](telegram.md)).

## 6. Write

The last step lists what it will write into each file, in words and never a password or a
token, and checks the new files with `lanowl --check`'s rules: anything wrong is said there. **Write and restart** writes all
three and restarts lanowl, which starts watching. The first sweep is done within a minute.
Send `/start` to your bot: it answers with what it can do.

Next, in Settings (the gear): **The model**, where Ollama runs for the owl's answers
([The model](../setup/model.md)), and the features you want, each off until you switch it on.

## Check the plan

What lanowl does with each device, and why not, from the same files a start reads. Nothing is
probed and nothing is sent:

```bash
docker exec lanowl lanowl --check
```

```text
3 device(s) watched, 2 managed, 0 problem(s). ✓ on · ○ switched off in config.yaml · ✗ cannot

Router (192.168.88.1) · mikrotik · login: password
  ✓ updates   checks its updates every morning
  ○ backup    backs it up, monthly and before updates — off: backups.enabled in config.yaml
  …

Secrets: /config/secrets.yaml · 3 login(s), 1 token(s), mode 600
  ✓ Telegram token  from secrets.yaml
  ✓ router login    lanowl, from secrets.yaml login router-read
  ✓ ssh key         /config/id_ed25519, from secrets.yaml
```

A **✗** says what is wrong and how to fix it. `--check` exits with 1 when anything is wrong,
so a script can stop a deploy on it.

## Rather write the files yourself

Everything above can be a file you write instead, or one an AI assistant writes from a
description of your network ([Set it up with an AI assistant](with-an-ai.md)). Copy the
examples into `config/` before the first start, and lanowl writes nothing of its own:

```bash
cp config.example.yaml config/config.yaml        # every key, with what it does
cp inventory.example.yaml config/inventory.yaml  # the devices
cp secrets.example.yaml config/secrets.yaml && chmod 600 config/secrets.yaml
ssh-keygen -t ed25519 -N '' -C lanowl -f config/id_ed25519
```

The examples are a demo house on 192.168.88.0/24: replace their addresses and their
`change-me` passwords before the first start. What each file holds: [config.yaml](../setup/config.md),
[Devices](../setup/inventory.md), [Secrets](../setup/secrets.md).

`docker/.env` is optional: it sets the few things that win over `config.yaml` (this host's
address, the model's URL, the dashboard's port, `TZ`), and Settings then shows them locked
([The environment](../reference/environment.md)).

Next: [Telegram](telegram.md), then [The first hour](first-hour.md).
