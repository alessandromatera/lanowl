# Device kinds of your own

lanowl knows a handful of kinds (MikroTik, OpenWrt, Linux, ESXi, UniFi, Home Assistant,
Reolink, Shelly). For anything else that you reach over ssh, write a **profile**: a YAML file
with a command per operation and a fixed parser for what it prints. A profile is never code:
lanowl runs the command you wrote and reads the output with one of a few parsers.

lanowl ships one, for a Mac, and it is the example to copy.

## Where profiles live

`config/profiles/<kind>.yaml`, beside `config.yaml` (or the folder `profiles.dir` names).
Then write `kind: <kind>` on the device:

```yaml
  - ip: 192.168.88.70
    name: "Studio Mac"
    group: servers
    criticality: high
    kind: macos
    credentials: mac
    manage: [updates, reboot, config, security]
    checks: [{type: icmp}]
```

A profile of yours with the same kind as a shipped one replaces it. A built-in kind's name
cannot be reused.

## The shipped profile, line by line

```yaml
kind: macos
about: "an Apple Mac, reached over ssh"
ops:
  version:
    cmd: "sw_vers -productName; sw_vers -productVersion"
    parse: lines                       # the first line is the system, the second its release
  updates:
    cmd: "softwareupdate --list 2>&1"
    parse: {regex: '^\* Label: (?P<pkg>.+)$'}
    timeout_s: 240                     # it asks Apple's servers
  uptime:
    cmd: "sysctl -n kern.boottime"
    parse: boottime
  reboot:
    cmd: "shutdown -r now"
    sudo: true
    back_s: 600
  config:
    cmd: >-
      echo '# name'; scutil --get ComputerName; scutil --get LocalHostName;
      echo '# network services'; networksetup -listallnetworkservices;
      echo '# power'; pmset -g custom; true
  security:
    cmd: >-
      echo '# FileVault'; fdesetup status;
      echo '# System Integrity Protection'; csrutil status;
      echo '# Gatekeeper'; spctl --status; true
```

(The shipped file's `config` and `security` read more; this is abridged.)

- **`version`** prints two lines; `lines` gives them as a list, and lanowl takes the first as
  the system and the second as its release.
- **`updates`** prints one `* Label: …` line per waiting update; the regex's named group
  `pkg` becomes each update's name (add a `version` group if the output has one).
- **`uptime`** tells lanowl when it booted, so a reboot can be seen to have happened.
- **`reboot`** runs as root (`sudo: true`: the login's password goes to sudo on standard
  input), and lanowl waits up to `back_s` seconds for it to answer again.
- **`config`** and **`security`** print text. lanowl compares `config` from one day to the
  next and tells you what changed; the owl reads `security` in its morning review. Headings
  like `# power` help both.

## What the operations give

Each operation unlocks a feature you can then list in `manage:` on the device:

| Operations | Feature |
|---|---|
| `updates` (and `version`) | `updates`: its waiting updates, every morning. Reported, never paged. |
| `reboot` (and `uptime`) | `reboot`: the owl may propose one; you approve. |
| `config` | `config`: what changed in its configuration. |
| `security` | `security`: the owl's daily review of what it exposes. |
| `backup` | `backup`: its output saved as a file with the monthly backups. |

`upgrade` (installing updates) and `restart` (a service) are not available to profiles yet;
they are for built-in kinds only.

Every option, parser and result: [Profiles: operations and parsers](../reference/profiles.md).

## Testing a profile

`lanowl --check` loads every profile and says what is wrong in one, in words ("updates: bad
regex: …", "unknown operation 'install'"). Once a device uses it, run the update check from
the dashboard's Security tab: the device's row shows what was read, or why it could not be.
