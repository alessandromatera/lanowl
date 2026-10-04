# Profiles: operations and parsers

The full format of a profile, `config/profiles/<kind>.yaml`. A guide with a worked example:
[Device kinds of your own](../setup/profiles.md).

```yaml
kind: mykind            # lowercase letters, digits, - and _ ; not a built-in kind's name
about: "one line on what it is"
ops:
  <operation>:
    cmd: "..."          # required: what runs on the device, over ssh
    parse: lines        # how its output is read (default depends on the operation)
    sudo: false         # run it as root, the login's password going to sudo
    timeout_s: 60       # 1 to 3600
    ok_rc: [0]          # exit codes that count as success
```

An operation may also be written as a plain string, which is its `cmd`.

## Operations

| Operation | What it reads or does | Default parser | Extra keys |
|---|---|---|---|
| `version` | The system and its release | `lines` | |
| `updates` | One entry per waiting update | `lines` | |
| `uptime` | Seconds since boot | `proc_uptime` | |
| `reboot` | Reboots it (run detached, so lanowl gets an answer first) | `text` | `back_s` (default 300): how long it may take to answer again |
| `config` | Its configuration, compared day to day | `text` | `ignore`: regexes of lines left out of the comparison |
| `security` | What decides how exposed it is, for the owl's review | `text` | |
| `backup` | Output saved as a backup file | `text` | `file`: the file's name (default `<kind>-backup.txt`) |

At least one operation is required. Unknown operations or keys are refused, with the reason.

## Parsers

| Parser | Result |
|---|---|
| `text` | The whole output, trimmed |
| `lines` | Every non-empty line, trimmed |
| `first_line` | The first non-empty line |
| `seconds` | The first number in the output |
| `proc_uptime` | The first number, as `/proc/uptime` prints it |
| `boottime` | Seconds since a boot time: `{ sec = 1696300000, … }` (macOS) or an epoch |
| `{regex: '...'}` | One entry per match, multiline. Named groups become fields (`pkg`, `version`); without names, the first group or the whole match. |

For `updates`, each entry's `pkg` (or its first field) is the update's name, and `version`,
when present, its version. For `version`, the first entry is the system and the second its
release (or the `os` and `release` named groups of a regex).

## Logins

A profile runs over ssh with the device's login from `secrets.yaml`: by lanowl's key when
the login has `key: true`, else with its password. An operation with `sudo: true` runs as
root: directly when the login is root, else through sudo with the login's password on
standard input.
