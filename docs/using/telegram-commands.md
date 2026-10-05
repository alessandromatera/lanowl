# Telegram commands

Send `/help` to the bot for this list. Anything that is not a command is a question for the
owl ([Asking the owl](asking.md)). Commands answer at once and involve no model, except where
the table says.

| Command | What it does |
|---|---|
| `/status` | The network right now: health, devices answering, the internet, what is open. Instant. |
| `/audit` | A full audit by the owl, and its digest, now: the dashboard's **Audit now**. (`/check` works too.) |
| `/security` | What matters, from every check, by severity: the Security tab's list. |
| `/updates` | What is waiting to be updated, pending reboots, known vulnerabilities, from the last morning check. |
| `/backups` | Each machine's last backup on the store, and the next run. |
| `/sites` | Every site: devices up, the ones down by name, unknown devices on its network. |
| `/week` | The weekly review, now. Uses the owl for its note. |
| `/reboot <device>` | Propose a reboot of one device. The proposal, with its Approve button, is the answer. |
| `/upgrade <machine>` | Propose updating a Linux machine (apt) or a MikroTik (RouterOS). Approve to run it. |
| `/pause <device>` | Stop watching a device you switched off on purpose. Several at once: `/pause tv, boiler`. |
| `/resume <device>` | Watch it again. `/resume all` ends every pause. |
| `/paused` | What is paused, since when, and whether it answers. |
| `/memory` | The notes the owl keeps. |
| `/remember <text>` | Add a note, as written. |
| `/forget <number>` | Delete a note. Several: `/forget 3, 5`. |
| `/model` | Whether the owl is on. `/model off` puts it to sleep (no diagnoses, answers or reviews; alerts and digests go on); `/model on` wakes it. |
| `/new` | Start a new conversation. The bot otherwise keeps the last few questions for 6 hours. |
| `/pin` | Set the [dashboard's PIN](dashboard.md#the-pin), when `config.yaml` has none. The bot asks for the digits and deletes your message at once. |
| `/password` | Set the [dashboard's password](dashboard.md#logging-in), when `config.yaml` has none. The bot asks for it and deletes your message at once. A new one logs every browser out and lifts a lock. |

## Naming a device

Commands that take a device accept any part of its name or its address: `/pause tv`,
`/reboot ap porch`, `/reboot 192.168.88.3`. When several devices match, the bot lists them
and asks which. `/resume` looks among the paused devices first, so `/resume shelly` finds the
one paused Shelly, not eleven.

## The buttons

Proposals arrive with **✅ Approve** and **✖️ Reject**. Pressing one is the decision: an
approved action is checked against the device again, then runs (or, in shadow mode, is only
recorded), and the same message is edited with what happened. A proposal nobody answers
expires after `actions.expire_min` minutes and its buttons go away. Only the people in
`telegram.chat.allowed_user_ids` (by default, the owner of the private chat) can press them.
