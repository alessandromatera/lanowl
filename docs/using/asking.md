# Asking the owl

Ask lanowl anything about your network, in your own words: on Telegram (any message that is
not a command) or in the dashboard's **Ask the owl** tab. The owl answers from the network's
data and lanowl's own records, and runs the diagnostics the question needs.

> **Why did the internet drop on Friday?**
>
> 🦉 The fibre failed on Friday 19:41 and the router moved the traffic to LTE within a minute;
> the fibre was back at 19:47, six minutes in all. Nothing answered from the internet for 45
> seconds while LTE came up; after that every device kept working.

Good questions are the ones you would ask someone who had watched the network all week:

- "Why did the internet drop last night?"
- "How has the boiler been this week?"
- "Who joined the guest Wi-Fi today?"
- "Is the VPS being attacked?"
- "What did you send me on Sunday, and why no digest this morning?"
- "Show me the exact log of the home server around 03:00."

## How it answers

It looks first, then answers: a device's history, the internet's evidence, the router's log,
a machine's log, MQTT values, and everything lanowl keeps (every message it sent you and why
a digest was held back, the update check, the security review, the backups, earlier
conversations). For more it runs diagnostics from a fixed catalog: `mtr`, DNS, TLS, a scan,
a packet capture, a check from the router, from another LAN host or from your VPS. Asking is
the approval: they run at once, and each is listed under the answer (🔧 on Telegram). Anything
that would change something is only proposed, with a button
([Actions and approvals](actions.md)).

An answer takes a minute or two. The model does one thing at a time: a question asked while
the hourly audit is thinking waits for it, and says so.

**On the dashboard** you watch it work: its thinking, each check as it runs, and the answer as
it is written. **Stop** stops it at once, **Ask again** retries, and **Copy** copies the
answer. Conversations are kept across restarts.

**On Telegram** a chat is a conversation too: a question carries the last few exchanges, so
"and yesterday?" works. `/new` starts over; six hours of silence does too.

## Memory

The owl keeps notes that outlive a conversation: what only you know.

- "Remember that the NAS sleeps from 01:00 to 07:00."
- "The office's public address is 198.51.100.7."
- "Forget the note about the old printer."

Notes are **written** only in your own conversations, when you say so or when it learns
something worth keeping. Every change is printed under the answer by lanowl itself, so a note
cannot be added unseen. They are **read** by every model run: questions, the audit, the weekly
review, the log checks. A note is context, never a rule: it can change how the owl reads a
log, never what is watched or what pages.

You can also edit them directly: `/memory`, `/remember`, `/forget` on Telegram, or the Memory
list on the Ask tab.

## Its track record

How far can the owl be trusted? Each cause it gives for a problem is checked once the
problem is over: the owl is asked again, with hindsight and the evidence, whether the cause
it named is what really happened: right, partly, wrong, or can't tell. Your own verdict, one
tap on the dashboard, beats its grade. The totals are on the Ask tab and in the weekly review
(`scorecard`).

## Written fixes

For each finding of the morning security review, the owl writes the exact fix for that
machine: what to type, where, in which order so you cannot lock yourself out, how to check it
worked, and how to undo it. Nothing runs: you read it on the Security tab (**Fix**), copy it,
and apply it yourself, or not (`fixes`).

## Over MQTT

A question published on `lanowl/ask` is answered on `lanowl/answer`, for an automation that
wants the owl's view ([MQTT topics](../reference/mqtt.md)).
