# How alerts work

lanowl's promise is one message per incident, not one per blip. This page is how it keeps it:
what counts as down, what reaches your phone at once, what waits for a digest, and what never
reaches you at all.

## Down is decided by code

Every minute (`cadence.sweep_interval_s`), every device in the inventory is probed. A device
is **down** after two misses in a row (`cadence.debounce_fails`), and up again at the first
answer. The internet has its own loop every 15 seconds. The model takes no part in any of
this: switch it off and detection is exactly the same.

A device is **not** an incident when its silence is explained:

| Why | How lanowl knows |
|---|---|
| Asleep on schedule | `expect_offline: sun` or `day`, with a grace period at the edges |
| Paused by you | `/pause` or its sheet on the dashboard ([Pausing a device](pausing.md)) |
| Rebooting on your say-so | An approved reboot holds its alerts until it is back |
| Behind something that is down | `depends_on`: the parent's alert names it instead |
| lanowl itself lost the network | The router and most of the network are unreachable at once: one alert says so |

## Two doors: now, or in the digest

Each problem has a severity, from the device's `criticality`:

| Severity | From | Door |
|---|---|---|
| 🔴 critical | `criticality: critical`; a group's majority dark; no internet; on the backup line | **At once**, one message per incident |
| 🟠 high | `criticality: high` | **The next digest**, once |
| 🟡 warning | `criticality: warning`; a named service failing on a device that answers | **The next digest**, once |
| ⚪ info | `criticality: low` or `info` | **The next digest**, once. Never makes the network "degraded". |

Everything raised in the same minute leaves as one message.

### An alert, as it arrives

```text
🔴 CRITICAL 07:13:00
Home Assistant (192.168.88.12)
unreachable (icmp, Home Assistant)

🦉 Likely cause (model, 07:13): Went quiet at 07:12 right after installing 2026.10.1;
nothing else dropped. The update's own restart.
→ Nothing to do: it should answer again within ten minutes.
```

The 🦉 part is not a second message. On a new critical incident the owl investigates at once
(`cadence.llm_on_incident`), and its diagnosis is **edited into the alert you already have**,
which does not notify you again. Internet incidents are explained by lanowl's own evidence
instead, so they never wait for the model.

### The recovery

```text
🟢 RECOVERED
Group 'cameras' is back online
back at 02:19:00 · unstable for 5m · 2 outages
```

A recovery is sent only after the problem has stayed away for 15 minutes
(`alerts.recovery_confirm_s`), and it says when it really came back. A device that drops,
returns and drops again inside that window is **one incident**: the recovery counts the
outages instead of each one paging you.

After a recovery, the same problem stays quiet for an hour (`alerts.cooldown_s`): a new
occurrence is folded into the count. If it is still down when the hour is over, it pages
once more, so a real problem cannot go silent.

### The digest

The digest is sent by the owl's hourly audit (`cadence.llm_interval_s`), and **only when
there is something new to say**:

- a problem that is not critical opened since the last digest and is still open;
- the owl's scheduled looks found something new (a configuration change, something slowly
  getting worse);
- once a day, a problem that is still open (`alerts.digest_repeat_s`), so it is not forgotten.

```text
⚪ lanowl digest — DEGRADED
26/27 up · WAN OK
🦉 Cam Garage needs a look; everything else answers as usual.
🟠 Cam Garage (192.168.88.23): unreachable (icmp) — since 13:35:00
   ↳ Stopped answering at 13:35; the four other cameras on the same PoE switch answer, so
     not the switch. Its DHCP lease is still bound: it lost power or hung. → Power-cycle it
     with its smart plug; if it stays dark, check the cable at the garage end.
```

A healthy network gets no digest (`cadence.digest_when_ok: false`). A problem you were told
about in a digest gets a 🟢 line when it goes away (`alerts.notify_recovery`,
`alerts.recovery_min_severity`); one that opened and healed between two digests was never
mentioned, so its recovery is not news either.

Without a model, digests still go out: the monitor's own report, without the 🦉 lines.

## The internet

| What happened | What you get |
|---|---|
| A blip shorter than 90 seconds (`wan.watch.min_outage_s`) | Nothing at the time. The digest counts it ("1 brief drop in 24h, longest 45s"), and the dashboard says where it broke. |
| No internet for longer | One 🔴 alert, queued and delivered when the line is back, then a recovery with how long it lasted. |
| On the backup line | One 🔴 alert and one 🟢 when the main link is back ([A backup internet line](../setup/backup-line.md)). |

## What never reaches you

- A single missed ping.
- A device asleep on schedule, paused, or rebooting because you approved it.
- Twelve cameras behind one switch: that is one incident.
- Latency alone, a recovery of something you were never told about, a problem already over by
  the next digest.
- "All is well".

## Tuning

| Key | Default | Turn it when |
|---|---|---|
| `cadence.debounce_fails` | 2 | Flaky gear pages on a single bad minute: raise it, or per device |
| `alerts.recovery_confirm_s` | 900 | You want recoveries sooner (and more flaps as separate incidents) |
| `alerts.cooldown_s` | 3600 | A problem that comes back pages too soon, or too late |
| `alerts.renotify_after_s` | 0 | You want a reminder page while a critical problem stays open |
| `alerts.digest_repeat_s` | 86400 | The daily reminder of an open problem is too often (0: never) |
| `alerts.recovery_min_severity` | info | You want "back online" lines only from `warning` up, say |
