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

lanowl reads your router's DHCP list to find your devices. Its address is filled in already:
lanowl's gateway, marked "found", or a guess at your network's `.1`, marked as a guess. Change it
if it is wrong; `192.168.88.1` is enough, without `http://`. Then the user and password lanowl
logs in with: a read-only user is enough. No such user yet? **Make one: 2 lines to paste on the
router** shows the two RouterOS lines, with lanowl's address in them and a Copy button
([more on a MikroTik](../setup/mikrotik.md)). **Try the router** logs in and counts the
addresses on its DHCP list, and says so if that user may also change the router (a read-only
one is safer). Nothing is written yet.

The password goes into `secrets.yaml` at the last step and is never shown again, on this page
or any other. It crosses your network once, in plain HTTP unless lanowl sits behind an HTTPS
proxy, as the dashboard password does.

Not a MikroTik, or no router login? **Next, without the router** finds your devices without
it, with the ping and the probe below. Your network is the main site's if Settings → Sites
names one, else the `/24` your router's address is on, else lanowl's own `/24`.

## 4. Find my devices

**Next: find my devices** takes about half a minute and changes nothing anywhere. It looks in
three places, then asks each device a question:

- the router's DHCP list;
- its ARP table: the devices with a fixed address (switches, access points, cameras, servers),
  which hold no lease;
- one ping to every address of your network;
- then a few ports on each device it found, once (22, 80, 443, 554, 631, 1883, 8006, 8123,
  8291, 9000, 11434): what answers tells what it is. Port 8291 is a MikroTik, 8123 Home
  Assistant, 9000 with 554 a Reolink, `/shelly` a Shelly, LuCI an OpenWrt, ssh's greeting a
  Linux machine. Only addresses of your home network are asked, and the answers are kept for
  an hour, so a reload asks nothing again.

The page says what it looked at and how many each source gave. Then the devices, grouped
(Router and Wi-Fi, Servers, Cameras, Smart home, Other, Don't know yet, Phones), each with its
address, where it was seen (DHCP, ARP, ping), whether it is here now, and **why** lanowl thinks
it is what it says ("port 8123 answers like Home Assistant"). What it recognised is ticked;
phones, tablets, laptops and what it does not know are listed but not ticked. A device lanowl
already watches is marked so. **Add a device by address** asks one more the same way.

Each ticked one gets a name (its DHCP name, a Shelly's own, else what it is and its number), a
group, how much it matters, in words (*Message me at once, day or night* · *In the next digest,
as a serious problem* · *In the next digest* · *Mentioned in the digest, never a problem* ·
*Just noted, never a problem*), a kind, and its login:

- **A user and a password**, the usual user filled in (`admin` on a MikroTik or a Reolink, `root`
  on OpenWrt), **Show** to read back what you typed, and **Try**: one login the way lanowl will
  log in, and the device's own answer, word for word ("Permission denied (publickey,password)."),
  or what it is ("RLN8-410 · v3.3.0"). Nothing is written by a Try. Leave the password empty and
  the device is only watched.
- **The same login as** another device you typed one for: nine cameras, one password typed once.
- **lanowl's own ssh key**, for a Linux machine or a kind of your own: the page gives the one line
  to run on it. Other kinds log in with a password only.
- **Home Assistant** takes a token, not a password: the page says where to make one (your
  profile → Security → Long-lived access tokens) and links there. Its address is filled in for
  you.
- **A Shelly** needs no login: lanowl talks to it the way its own app does. Its Try reads what it
  is. One with a password set on it can only be watched.

The router itself is always watched, with **the same login as above** chosen once that login
worked: if it may do more than read, lanowl can check its updates and back it up too.

## 5. Telegram

Telegram is where lanowl writes: alerts, the morning digest, the Approve buttons, its answers.
In Telegram, send `/newbot` to **@BotFather**: it answers with a token. Paste it and **Check
the token**: lanowl asks Telegram which bot it is and shows its name. Then send `/start` to
your bot from the phone you want the alerts on; the chat appears on the page within seconds.
**Use this chat** sets it, and the bot says hello there.

Optional: **Skip** it and the dashboard works alone. Settings → Secrets sets the token later
([Telegram](telegram.md)).

## 6. Write

The last step asks what lanowl does with the devices it can log in to, each a switch, in
words: check their updates each morning, review what each exposes, tell what changed in their
settings (all three on), and reboot or update one when you approve (off). Each applies where the
device's kind can do it. Then it lists what it will write into each file, in words and never a
password or a token, and checks the new files with `lanowl --check`'s rules: anything wrong is
said there. **Write and restart** writes all three, at once, and restarts lanowl, which starts
watching. A grey bar says the first sweep is under
way; it is done within a minute. Telegram gets one line saying what was set up. Send `/start`
to your bot: it answers with what it can do.

Next, in Settings (the gear): **The model**, where Ollama runs for the owl's answers
([The model](../setup/model.md)). Until then the owl is off: lanowl asks no model, checks for
none and warns about none, and the owl's card on Now says where to set it. Settings opens on
the essentials (the model, Telegram, sites, updates, security, backups, approvals, the shell);
every other key of `config.yaml` is under **Every setting**. A switch that is not in your file
shows lanowl's own default for it, not the example's.

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
