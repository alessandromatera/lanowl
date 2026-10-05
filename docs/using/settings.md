# Settings

The gear in the dashboard's header opens Settings: `config.yaml` and `inventory.yaml`,
changed from the browser. They stay your files. A save edits them where they are, keeps every
comment and every line you did not touch, and runs from the next restart of lanowl.

Secrets are not here. `secrets.yaml` stays a file you edit on lanowl's machine; Settings only
says which logins and tokens are set and which are missing, never a value.

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
  `LANOWL_HOST_IP`, `LANOWL_WEB_PORT`), which wins over the file. The field is locked: change
  it there.

Paths inside the container (the database, the log, the sandbox sockets) sit under
**Advanced** in their section. The dashboard password has a button of its own, **Change the
password**; it is never shown, and a new one logs every browser out, yours too.

**Secrets** lists `secrets.yaml` by name: each login (password or key) and what uses it, the
tokens, lanowl's ssh key. A name the inventory or `config.yaml` uses that the file lacks is
marked missing, with the lines to add.

## Saving

Change what you want; a bar at the bottom counts the changes. **Review** shows what the save
would do before it does anything:

1. The diff of the file, old to new, with its comments and order kept.
2. `lanowl --check`'s rules, run on the new file. A problem the file does not have now (a login
   name `secrets.yaml` lacks, a feature a device's kind cannot do) stops the save and says
   what it is.
3. **Save** writes it. When this browser has not typed the password in the last ten minutes,
   the sheet asks for it first: a browser stays logged in for a month, and whoever holds your
   phone may not be you. Wrong ones count toward the login's lock (five in a row, 15
   minutes).

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

## Restart to apply

**Restart** (in the "Saved, not running yet" banner, or under lanowl at the bottom of
Settings) restarts lanowl: the same process starts over and reads both files again. The
dashboard is back in a few seconds; nothing is watched for that long. It needs no password: it
only applies what a save already confirmed. Telegram is not told.

Kept across it: open incidents and what Telegram was already told about them, paused devices,
names, the model's switch, logins (nobody is logged out), proposals waiting for you, the
login's lock, the history and the Timeline. Cut by it: an answer the owl is writing. It waits
while an action, a backup or a device's reboot is running, and says which.

## History and undo

**History** lists every save from the dashboard, the newest first: when, which file, what
changed, from which address, and whether the file had been edited on the host before it.
**Undo** puts a file back as it was before the latest save; older ones say **Restore**, and
the diff shows everything that goes back with it. An undo is a save like any other: the diff,
the confirm, a line on Telegram, then Restart.

## Devices

**Settings → Devices** lists `inventory.yaml`'s devices by group. Tap one to change it, or
**Add a device**:

- **Watching**: name, address, MAC (lanowl follows it when DHCP moves it), group,
  criticality, checks, what it depends on, whether it is off at night or by day, a role and a
  note.
- **Managing**: its kind, its login by name (from `secrets.yaml`; set or missing, never a
  value), and only the features its kind can do. A feature switched off in `config.yaml`
  says so. A service it may restart is listed under it.

Anything else a device has in the file is kept as it is. **Remove from inventory.yaml** takes
it out, through the same diff and confirm.

**Watch**, on the Devices tab's list of what a site's DHCP sees, writes the device into
`inventory.yaml` (the same sheet), and lanowl pings it from the next sweep, before any
restart. Devices watched this way before Settings existed lived only in lanowl's state; Settings
→ Devices offers to **Move** them into the file in one save.

## The first-run setup

A new install opens on it: after the [setup code and the password](dashboard.md#logging-in),
and whenever `inventory.yaml` has no devices or still has the example's seven. It is always in
Settings, as **Add from the router's list**.

1. **The router**: its address (`mikrotik.dhcp_source`) and the name of its read-only login
   (`mikrotik.credentials`). The login itself is read from `secrets.yaml`: when it is missing,
   the page shows the lines to add, and lanowl reads the file again by itself. **Try the
   router** logs in and counts the addresses on its DHCP list. [Making the read-only user on a
   MikroTik](../setup/mikrotik.md).
2. **Your devices**: the router's DHCP list with names, makers, static or dynamic, and who is
   here now. Pick what to watch; for each, a name, a group, a criticality and a kind. A kind
   guessed from the maker (a Shelly, a Reolink, a MikroTik) is marked as a guess. The router
   itself is always watched.
3. **Write**: the new `inventory.yaml` (the example's devices out, its comments kept), and the
   router in `config.yaml` if you changed it. Dynamic addresses get their MAC. Then Restart.

Not a MikroTik? lanowl reads DHCP only from RouterOS. **Sweep the network instead** pings
every address of the main network once (`sites.list`, the site keyed `home`) and lists who
answered, with the makers from lanowl's machine's ARP table, and no names.

**Not now** keeps it closed for a day.

## The files and the container

The compose file mounts the config folder read-only, and `config.yaml` and `inventory.yaml`
read-write on top of it, each on its own:

```yaml
    volumes:
      - ../config:/config:ro
      - {type: bind, source: ../config/config.yaml, target: /config/config.yaml, bind: {create_host_path: false}}
      - {type: bind, source: ../config/inventory.yaml, target: /config/inventory.yaml, bind: {create_host_path: false}}
```

Both files must exist before the first start: compose stops with an error instead of making a
folder in their place. lanowl writes them in place, never by renaming a new file over them,
which a single-file mount does not allow.

You can still edit them by hand. One catch: an editor that saves by writing a new file and
renaming it over the old one (vim does by default; so does `rsync`) drops the container's
read-write mount of that file. lanowl then reads your new file, but cannot write it: Settings
says so, and saves wait until the container is restarted (`docker compose restart lanowl`;
Restart to apply is not enough, it does not mount anything again). Editors that write in place
(nano, most others) have no such catch.
