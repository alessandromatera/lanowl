# The dashboard

lanowl serves its own dashboard, at `http://<lanowl's host>/` (port `web.port`). It needs no
internet and loads nothing from anywhere else, so it works precisely when the internet does
not. It is made for a phone first: add it to your home screen and it opens like an app. On a
computer the tabs sit in a sidebar, with lanowl's own vitals under them (last sweep, last
audit, how long it has been running).

**Search** (⌘K, or the magnifier on a phone) finds devices by name or address, jumps to a tab,
or sends what you typed to the owl as a question.

It is closed until you log in: see [Logging in](#logging-in). The **gear** in the header opens
[Settings](settings.md): config.yaml, your devices, and the first-run setup.

![The Now tab](../img/home-wide.png)

## Now

What needs you, first.

- **The headline** says the state of the network in one line: "Cam Garage is down", "All
  quiet", and how many devices answer, the internet, and each site.
- **The incident card**, when there is one: the problem, its severity, since when, and its
  trail: when it stopped answering, what Telegram was told, the owl's diagnosis, a proposal
  waiting for you. **Open** shows the device; **Ask about it** starts a question with its
  facts.
- **Groups**: one tile per group, with what is down and what went down this week.
- **Needs you**: proposals waiting for your approval, updates that have waited too long,
  devices on a network for the first time, the security findings that matter. Each with its
  buttons.
- **Internet**: online, on the backup line, or down, through which link, the targets' answers,
  drops and blips in 24 hours, and seven days as a bar. Tap an event to see where it broke.
- **Sites**: each site with its devices answering and its unnamed devices.
- **The owl's assessment**: its last audit in a sentence, a box for a follow-up question, and
  **Audit now** (the digest goes to Telegram too).
- **The model also looks**: what it found slowly getting worse over the week.
- **Last 24 hours**: a lane per device that had anything to show.

![An internet blip and its evidence](../img/wan-wide.png)

## Devices

Every watched device, grouped, with its state now, its latency over 24 hours and seven days
of answers. Filter by site, by what is down, by what went down this week, by what is asleep,
or sort the least stable first. Under the list: each site's DHCP devices that nobody watches,
with **Watch** and **Known**, and every named service. **Watch** writes the device into
`inventory.yaml` (after a sheet that names the change) and pings it at once: it is on the page
when the sheet closes, no restart needed. **Known** only stops it counting as unknown.

Tap a device for its sheet:

- **Overview**: down since when, the share of answers in 24 hours and seven days, its
  outages, a latency chart with lost probes, seven days of ups and downs.
- **Manage**: pause its monitoring (Telegram is told), and the actions its kind allows,
  such as Reboot or Update, each confirmed in a sheet that says what runs.
- **Details**: its checks, its kind, its login type, and what lanowl may do with it and why
  not.
- The pencil renames it. The inventory's name stays underneath.

![A device's sheet](../img/sheet-wide.png)

## Timeline

Seven days in one stream: outages grouped into incidents, the internet, security events,
actions, every Telegram message, new devices and the log checks. On top, seven days at a
glance, a lane per device that went down, with moments when several went down together
shaded. Filter by kind; switch on the devices asleep on schedule or paused to see them too.

![The Timeline](../img/log-wide.png)

## Security

What could let someone in, and whether every machine is patched and backed up.

- **The model's review**: this morning's summary, **Check now** (updates, then the review),
  and **Deep scan** (the monthly vulnerability scan, now).
- **To decide**: what matters, first.
- **Worth fixing, not urgent**: the rest. **Fix** shows the owl's written fix for you to
  apply yourself; **Dismiss** takes it off the list until it changes (with a note, if you
  like).
- **Machines**: per machine, its updates, its last backup, its review, the deep scan and
  how long it has been up, with **Update** or **Reboot** where they apply.
- **What changed**: configuration changes since yesterday, with the owl's reading of each.
  **Compare now** runs it.
- **Logins and logs**: what the auth logs showed, until you mark an event handled ("It was
  me" or "Fixed").
- **Backups**: where they go, when the next run is, and **Back up everything now**.

![The Security tab](../img/sec-wide.png)

More: [Updates, backups and the security review](security.md).

## Ask the owl

A conversation with the model, with the same tools as the Telegram bot. You watch it work:
its thinking, each check as it runs, and the answer as it is written. **Stop** stops it;
**Ask again** retries; follow-ups remember the conversation. Earlier conversations are kept
across restarts, so one started on the phone can go on at the computer.

Beside it, the model's side:

- **Local model**: the switch that puts the owl to sleep and wakes it, the model's name, when
  it audits, and when it last did.
- **Memory**: the notes it keeps. Add, edit or forget them.
- **Proposed and run**: everything it proposed, what you decided, and what happened.
- **Track record**: each diagnosis, checked with hindsight once the problem was over.
- **The model's shell**: every command it ran in its sandbox.

![Ask the owl](../img/ask-wide.png)

More: [Asking the owl](asking.md).

## Logging in

The dashboard has one password, and no user name. Until it has one, it asks for a **setup
code** and then the password. The code proves you can reach lanowl's machine, not just the
page; lanowl makes it at its first start and prints it on request:

```bash
docker exec lanowl lanowl --setup-code
```

The code works once. The password's hash goes into `config.yaml` (`web.password_hash`), and
the dashboard opens on the [first-run setup](settings.md#the-first-run-setup). The other ways
to set a password:

- **Telegram:** send `/password` to the bot, then the password (8 characters or more). The
  bot deletes your message as soon as it has read it and keeps only a hash. `/password`
  again changes it.
- **config.yaml:** make a hash, and put the line it prints under `web:`, then restart lanowl.

```bash
docker compose -f docker/compose.yaml run --rm lanowl lanowl --hash-password
```

```yaml
web:
  password_hash: "scrypt$32768$8$1$…"
```

A password in `config.yaml` wins: `/password` then only points to it. `lanowl --check` says
where the password comes from, or that there is none.

A browser stays logged in for 30 days after its last visit, across restarts and upgrades of
lanowl. **Log out** and **Log out everywhere** are in the Ask tab, under lanowl. A new
password, from either place, logs every browser out.

Five wrong passwords in a row lock the login for 15 minutes, for every browser, and Telegram
is told once, with the address the last try came from. `/password` sets a new one and lifts
the lock. A good login sends nothing.

The login is a cookie, so the password crosses your network only when you log in. Over plain
HTTP anyone who can watch your LAN's traffic could read it then; put lanowl behind a reverse
proxy with HTTPS if that matters to you (and list its name in `web.allowed_hosts`).

`web.login: false` switches the login off, for a dashboard that already sits behind a login of
your own (Authelia, Authentik, Tailscale). `--check` says so while it is off.

## Approving

Anything on the dashboard that changes something (approving a proposal, a reboot, an update)
opens a sheet that says what runs, on which device, and the risk; your tap on its button is
the approval. Reject, End and Cancel need no sheet: they can only stop something. There is no
PIN: the page is behind its login.

## Who can reach it

Only a browser logged in with the password. Keep it on your LAN all the same. It accepts only
JSON requests and IP-address host names, which stops another web page from driving it through
your browser. Pausing a device is told on Telegram, and so is every save in Settings.
