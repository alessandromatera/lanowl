# Settings

The gear in the dashboard's header opens Settings: `config.yaml`, `inventory.yaml` and
`secrets.yaml`, changed from the browser. They stay your files. A save edits them where they
are, keeps every comment and every line you did not touch, and runs from the next restart of
lanowl (secrets.yaml at once).

Secrets are write-only: a password or a token goes in from the page and never comes back out
([Secrets](#secrets)).

## What it shows

Every section of `config.yaml`, under the file's own headings: your network, the model,
Telegram, the dashboard, and so on, then the optional features with their switch. The forms
are built from `config.example.yaml`: its values say each setting's type (a switch, a
number, a list, text), its comments are the help under each field.

Each field says where its value comes from:

- **config.yaml**: it is in your file.
- **not in your file**: lanowl uses its built-in default. The example file's value is shown as
  a hint. It is not always the default: the example is a starting point. Type a value and it
  goes into your file, with the example's comment beside it.
- **the environment**: set by a variable in `docker/.env` (`LANOWL_MODEL_URL`,
  `LANOWL_HOST_IP`, `LANOWL_WEB_PORT`, `TZ`), which wins over the file. The field is locked:
  change it there.

`observer.host_ip` left empty says the address lanowl found for its own machine (the one it
reaches the internet from). `timezone` is the first-run setup's, from your browser.

Paths inside the container (the database, the log, the sandbox sockets) sit under
**Advanced** in their section. The dashboard password has a button of its own, **Change the
password**; it is never shown, and a new one logs every browser out, yours too.

**Secrets** lists `secrets.yaml` by name, and sets what goes in it ([Secrets](#secrets)).

## Saving

Change what you want; a bar at the bottom counts the changes. **Review** shows what the save
would do before it does anything:

1. What changes, in words: "model.name qwen3:30b → qwen3:32b", "NVR (192.168.88.20) added".
   The file itself is not shown; the save keeps its comments and order.
2. `lanowl --check`'s rules, run on the new file. A problem the file does not have now (a login
   name `secrets.yaml` lacks, a feature a device's kind cannot do) stops the save and says
   what it is; otherwise nothing is said.
3. **Save** writes it. A logged-in browser is not asked the password again: the login is
   the guard, so keep the dashboard's sessions to devices you hold
   ([Logging in](dashboard.md#logging-in)).

Then:

- the file as it was is kept, in lanowl's state (`settings-versions`, the last 30 of each
  file);
- Telegram gets one line: which file, from which address, what changed (the first three
  changes, and how many more). It goes to the chat lanowl runs with, so a save that points
  `telegram.chat_id` somewhere else is still heard where you are;
- nothing runs differently yet. Settings says "Saved, not running yet" and the gear has a
  blue dot until lanowl restarts.

A save is refused when the file changed after the page read it (look at it again and save),
when the environment sets the value, when the file is read-only for lanowl (see
[the compose file](#the-files-and-the-container)), or when the file was replaced on the host
(restart the container first).

## Secrets

**Settings → Secrets** lists every login by name, with its user, how lanowl logs in (a
password or its ssh key) and what uses it; the tokens (Telegram's, Home Assistant's); and
lanowl's ssh key. A name the inventory or `config.yaml` uses that the file lacks is marked
missing.

- **Set** and **Replace** open a sheet: the user, a password or lanowl's key, and for a
  password the new one (left empty, the one there is kept). A token is pasted.
- **Add a login**: a name, then the same. Pick it on a device in Settings → Devices.
- **Remove** is refused while a device or `config.yaml` still names the login, and says which.
- **Public key**: lanowl's own, with the line that adds it to a machine's `authorized_keys`.

The changes say
"login routers: password replaced", never a value; Telegram gets one line
naming the login or token, and History keeps the file as it was (mode 600). lanowl reads the
new file at once: no restart. A token set in the environment (`LANOWL_TG_TOKEN`) says so and
is changed there.

## Restart to apply

**Restart** (in the "Saved, not running yet" banner, or under lanowl at the bottom of
Settings) restarts lanowl: the same process starts over and reads both files again. The
dashboard is back in a few seconds; nothing is watched for that long. It needs no password: it
only applies what a save already confirmed. Telegram is not told.

Nothing is lost: open incidents and what Telegram was already told about them, paused devices,
names, the model's switch, logins (nobody is logged out), proposals waiting for you, the
login's lock, the history and the Timeline. The one thing it stops is an answer the owl is
writing at that moment: the sheet says so when there is one, and you ask again once lanowl is
back. It waits while an action, a backup or a device's reboot is running, and says which.

## History and undo

**History** lists every save from the dashboard, the newest first: when, which file, what
changed, from which address, and whether the file had been edited on the host before it.
**Undo** puts a file back as it was before the latest save; older ones say **Restore**, and
the sheet lists everything that goes back with it. An undo is a save like any other: the
changes, the confirm, a line on Telegram, then Restart.

## Devices

**Settings → Devices** lists `inventory.yaml`'s devices by group. Tap one to change it, or
**Add a device**:

- **Watching**: name, address, MAC (lanowl follows it when DHCP moves it), group,
  criticality, checks, what it depends on, whether it is off at night or by day, a role and a
  note.
- **Managing**: its kind; its login, asked on its page: its own (a user and a password, or
  lanowl's ssh key; the password never shown again, left empty to keep it), one shared with
  other devices, or none; and only the features its kind can do. A feature switched off in
  `config.yaml` says so. A service it may restart is listed under it.

A save that sets the device's own login writes `secrets.yaml` too: the sheet lists both files'
changes.

Anything else a device has in the file is kept as it is. **Remove from inventory.yaml** takes
it out, through the same sheet and confirm.

**Watch**, on the Devices tab's list of what a site's DHCP sees, writes the device into
`inventory.yaml` (the same sheet), and lanowl pings it at once: it is on the page when the
sheet closes, with no restart. Devices watched this way before Settings existed lived only in lanowl's state; Settings
→ Devices offers to **Move** them into the file in one save.

## Sites

A site is another network lanowl looks after, such as an office or a cabin reached over a VPN:
its chip next to **All sites**, its devices, and its router's DHCP list with **Watch** and
**Known** ([Remote sites](../setup/sites.md)).

**Make it a site**, on the page of a router in the inventory (kind `mikrotik` or `openwrt`,
not on the main network): on its dashboard sheet under Manage, and in Settings → Devices.
It opens the site's page, filled in from the router:

- **Name**: the router's group, when it has one of its own; or its name.
- **Networks**: the router's `/24`. Add what else is on that side, comma-separated, and for a
  router reached over a VPN the address lanowl reaches it at (`10.8.0.9/32`). The most specific
  network wins, so a site's `/24` can sit inside the main site's `192.168.0.0/16`.
- **Router**: that router. lanowl reads its DHCP list every `sites.dhcp_every_min` minutes,
  over ssh with the router's login; a router with no login yet says so.
- **Criticality**: for the devices you Watch from its DHCP list; `info` by default (never pages).

**Review** shows the change in words, **Save** writes it into `sites.list` in `config.yaml`, and
it runs from the next restart.

**Settings → Sites** lists every site, the main one first: its networks and its router, with
**Edit** and **Remove**, and **Add a site**. The main site's name and networks can change; it has
no router of its own (that is `mikrotik.dhcp_source`) and is never removed. Removing a site
leaves its devices in `inventory.yaml`; from the restart they belong to whichever site's
networks hold them, the main one by default. What a site's entry has beyond these fields stays
as it is.

What is refused, and why, before anything is saved: a network another site has already, a
network holding the main router, a router that is not in the inventory, is not a mikrotik or an
openwrt, is the main router, is another site's router, or is not on the site's networks.

## The first-run setup

A new install opens on it: after the [setup code and the password](dashboard.md#logging-in),
and whenever `inventory.yaml` has no devices or still has the example's seven. It is always in
Settings, as **Add from the router's list**.

1. **Welcome**: the setup code, the dashboard's password, and the time zone, from your browser.
2. **The router**: its address, and the user and password lanowl reads it with (the login's
   name in `secrets.yaml`, `router-read`, is under Advanced). **Try the router** logs in with
   what you typed and counts the addresses on its DHCP list; nothing is written yet.
   [Making the read-only user on a MikroTik](../setup/mikrotik.md).
3. **Your devices**: the router's DHCP list with names, makers, static or dynamic, and who is
   here now. Pick what to watch; for each, a name, a group, a criticality and a kind. A kind
   guessed from the maker (a Shelly, a Reolink, a MikroTik) is marked as a guess. With a kind,
   its login, typed right there: a user and a password (or lanowl's ssh key, with the line to
   add on the device), named after the device in `secrets.yaml`; or a login that is there
   already; or none. The router itself is always watched.
4. **Telegram**: the bot's token, checked with Telegram; then `/start` to the bot, and **Use
   this chat** ([Telegram](../getting-started/telegram.md)). Optional.
5. **Write**: what goes into the three files, in words, never a value: `secrets.yaml` (the
   logins and the token), `inventory.yaml` (the example's devices out, its comments kept; a
   dynamic address gets its MAC), `config.yaml` (the router, the chat, the time zone). Then
   lanowl restarts and watches them.


Not a MikroTik? lanowl reads DHCP only from RouterOS. **Sweep the network instead** pings
every address of the main network once (`sites.list`, the site keyed `home`) and lists who
answered, with the makers from lanowl's machine's ARP table, and no names.

**Not now** keeps it closed for a day.

## The model's shell

Its sandboxes are two containers of their own, started apart from lanowl. Settings → The
model's shell gives the command, with lanowl's own address filled in:

```bash
LANOWL_HOST_IP=192.168.88.5 docker compose -f docker/compose.yaml --profile shell up -d
```

## The files and the container

The compose file mounts the config folder read-write, so lanowl can write its files there:

```yaml
    volumes:
      - ../config:/config
```

On a first start with no `config.yaml`, lanowl writes it, `inventory.yaml`, `secrets.yaml` and
its ssh key (each mode 600, owned by the folder's owner). Then the dashboard edits them where
they are, and you can still edit them by hand, with any editor: lanowl reads them again.

A compose file from before mounts the folder read-only (`../config:/config:ro`), with
`config.yaml` and `inventory.yaml` read-write on their own. It keeps working, but
`secrets.yaml` stays read-only: Settings says so, and the setup shows the lines to add by hand.
To set secrets from the page, mount the folder read-write as above
([Upgrading](../running/upgrading.md)).
