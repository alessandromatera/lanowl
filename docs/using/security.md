# Updates, backups and the security review

Every morning, lanowl checks what is waiting to be updated, the owl reviews what each machine
exposes, and the configurations are compared with yesterday's. Once a month the machines are
backed up and scanned for known vulnerabilities. Only what is new and matters reaches
Telegram, once; everything is on the Security tab and in `/security`.

Each part works on the devices whose `manage` list names it ([Devices](../setup/inventory.md)),
with its switch on in `config.yaml`.

## Updates

```yaml
updates:
  enabled: true
  at: "06:30"
  scan: {enabled: true, day: 1, at: "04:00", top_ports: 1000, deny_groups: ["security", "iot"]}
```

At `at` every day, lanowl reads each machine's waiting updates, read only: `apt` on Linux,
RouterOS against MikroTik's own latest release (and whether the versions in between were
security releases), Home Assistant's update list (which covers its add-ons and the firmware it
knows), ESXi's version, OpenWrt's and UniFi's release, your profiles' `updates`. It also
notices an insecure service newly open (telnet, ftp).

**What pages, once:** a reboot pending for more than 3 days, a security update still not
installed after 2 days, a security release or a serious vulnerability for something
installed, a newly opened telnet or ftp. Everything else waits on the Security tab.

Installing is an action you approve: **Update** on the machine's row, `/upgrade` on Telegram,
or the owl's proposal.

### The monthly vulnerability scan

On `scan.day` at `scan.at` (or **Deep scan** now), the main LAN's devices are scanned for
service versions with nmap's `vulners` script, outside the denied groups. A version scan
matches many CVEs that are not real (Debian and Ubuntu fix flaws without changing the version
a service announces), so each match is checked against fixed sources: the exact package
installed, asked of OSV.dev (the distributions' own security data), or NVD's record of the
CVE. What is still affected goes to the owl with the machine's own facts: does the flaw's
condition hold here? Only one that applies, with CVSS 7 or more, pages. What leaves your
network for this is package names, versions and CVE ids, never an address or a name.

## The security review

```yaml
exposure:
  enabled: true
  page_from: "2026-11-01"          # watch what it finds for a while before it pages
  outside_scan: {top_ports: 1000, max_rate: 20}
  public_names: []                 # your own host names, looked at from outside
```

After the update check, lanowl reads, read only, what decides how exposed each machine is: who
may log in and how, what listens, the firewall, which management services answer and from
where, UPnP, an open resolver, the firmware's age. It never reads a password, a key, a Wi-Fi
passphrase or a password hash. It also looks from outside: your public server is scanned from
here, and your home's public address from that server, but only if that address is really your
router's (behind a provider's shared NAT, nothing inbound can reach you anyway).

The owl reads it all and names each problem with one of a fixed set of checks (ssh accepts
passwords, a management service exposed, a firmware out of support, and so on), so the same
problem keeps the same name every day. That is what lets you **Dismiss** it once, with a note.
A dismissal lasts until you undo it, or until the problem has been gone for three reviews.

Pages start from `page_from` (watch what it finds for a couple of weeks first), and then
only for a new critical finding, once.

**Fix** shows the owl's written fix for that machine: the exact steps, in an order that cannot
lock you out, how to check it, and how to undo it. Nothing runs.

## What changed

```yaml
configwatch: {enabled: true}
```

Every morning after the update check (or **Compare now**), each machine's configuration is
compared with yesterday's: a MikroTik's `/export`, a Linux machine's effective sshd settings,
accounts, sudo rules, keys, crontabs, services, listening ports, firewall and VPN peers. The
owl says what each change does and how risky it is, knowing what you ran on the machine in
between. A change in a part that decides who gets in, that the owl did not explain, is listed
anyway. The first comparison is the baseline. Nothing pages: a high or critical change rides
the next digest and stays in What matters until you mark it handled ("It was me").

## Slowly changing

```yaml
drift: {enabled: true, at: "07:30"}
```

Once a day the owl reads a week of the sweep's own numbers, per device and per day, and names
what is slowly getting worse: a device that drops every night at 02:00, a line that flaps a
little more each week. Latency alone is never a finding, nor something already over. Only a
high one rides a digest; the rest is on Now and in the weekly review.

## Logins and logs

```yaml
hostlog:
  enabled: true
```

For Linux machines with `manage: [logs]` (by lanowl's key), lanowl reads the auth log every two
minutes: ssh logins, failed passwords, invalid users, sudo, and kernel warnings. A burst of
failed logins, a login from an address you do not trust (`logs.trusted`), or a flood of
connections is an alert at once, without waiting for the model; the owl reads the lines no rule
explains. lanowl's own logins are recognised by user and address, so they are never mistaken
for someone else. The router's log is read the same way.

Each security event stays in What matters until you mark it **handled**.

## Backups

```yaml
backups:
  enabled: true
  day: 1
  at: "03:00"
  keep: 6
  keep_before_days: 90
  store: {host: "192.168.88.11", path: "/srv/lanowl-backups"}
  self: {daily: 7}
```

On day `day` of every month, every machine with `manage: [backup]` is backed up onto
`store`: a Linux machine lanowl reaches by its key, on a disk of its own (not the datastore of
the VMs it backs up). The last `keep` are kept per machine, and one is taken before every
update (kept `keep_before_days`). How each kind is backed up: [Device kinds](../reference/kinds.md).

lanowl also backs **itself** up daily (`self.daily` kept): its database (history, memory,
actions, conversations, dismissals, pauses), its secrets, and the config it runs with.

> **Not encrypted.** The backups hold your network's passwords and keys in the clear. Keep the
> store's path as private as `secrets.yaml`.

One message when a monthly run had a failure, or when a machine has had no good backup for two
months. **Back up everything now** on the Security tab, `/backups` on Telegram.

### Setting it up from the dashboard

Backups start switched off, like every optional feature: until then a device's page shows
`backup` with "switched off in config.yaml", and `lanowl --check` says
`○ backup … off: backups.enabled in config.yaml`. Three steps:

1. **The store.** In Settings → Devices, open the Linux machine with the disk (or add it):
   kind `linux`, its login "its own login: lanowl's ssh key", and the user. Run the line the
   page gives on that machine, as that user.
2. **Settings → Backups**: switch it on, `store.host` that machine's address, `store.path` a
   folder on it that only you can read.
3. **Restart** (the banner offers it). Each machine with `backup` ticked on its page is then
   backed up monthly, and **Back up everything now** is on the Security tab.
