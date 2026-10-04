# The dashboard

lanowl serves its own dashboard, at `http://<lanowl's host>/` (port `web.port`). It needs no
internet and loads nothing from anywhere else, so it works precisely when the internet does
not. It is made for a phone first: add it to your home screen and it opens like an app. On a
computer the tabs sit in a sidebar, with lanowl's own vitals under them (last sweep, last
audit, how long it has been running).

**Search** (⌘K, or the magnifier on a phone) finds devices by name or address, jumps to a tab,
or sends what you typed to the owl as a question.

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
with **Watch** and **Known**, and every named service.

Tap a device for its sheet:

- **Overview**: down since when, the share of answers in 24 hours and seven days, its
  outages, a latency chart with lost probes, seven days of ups and downs.
- **Manage**: pause its monitoring (Telegram is told), and the actions its kind allows,
  such as Reboot or Update, each asking for your PIN.
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

## The PIN

Anything on the dashboard that changes something (approving a proposal, a reboot, an update)
asks for your PIN once per device and browser. Set it in `config.yaml` as a SHA-256 hash of
`lanowl-pin:` followed by the PIN, so the digits themselves never sit in the file:

```bash
printf 'lanowl-pin:%s' 1234 | sha256sum      # on a Mac: shasum -a 256
```

```yaml
actions:
  pin_sha256: "…"
```

Without a PIN, the dashboard cannot approve anything; Telegram's buttons still can. Five
wrong tries in a row (`actions.pin_max_failures`) lock dashboard approvals for
`actions.pin_lockout_min` minutes (30 in the example), and Telegram is told.

## Who can reach it

The dashboard has no login yet (it is on the [roadmap](../reference/roadmap.md)), so keep it
on your LAN. It accepts only JSON requests and IP-address host names, which stops another web
page from driving it through your browser. Reading is open to anyone on the LAN; pausing a
device is told on Telegram; approving anything needs the PIN.
