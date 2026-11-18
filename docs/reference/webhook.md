# Webhook

Besides Telegram (and MQTT, where every message is also published), lanowl can send every
alert as one HTTP POST of JSON to an address of your own: an Apprise server, ntfy, n8n, Home
Assistant, a gateway to Matrix or Slack. It works with Telegram not set up.

## Switch it on

```yaml
webhook:
  enabled: true
  format: "generic"           # generic, apprise, ntfy, or template
```

The address goes in [`secrets.yaml`](../setup/secrets.md), not here, because it often carries
a key (a path or a query a stranger could post with):

```yaml
tokens:
  webhook_url: "https://hooks.example.org/lanowl/…"
  webhook: "…"                # a bearer token, only if the receiver wants one
```

Or in the environment: `LANOWL_WEBHOOK_URL` and `LANOWL_WEBHOOK_TOKEN` (each also as `_FILE`).
Settings → Secrets sets and replaces both from the dashboard, as it does the Telegram token.
They are read again at every message, so a new one needs no restart; the settings in
`config.yaml` do. Set the address first: `lanowl --check`, and so Settings, calls a webhook
that is on with no address a problem.

**Settings → Webhook** has a **Send test notification** button and a line that says what the
last delivery did ("Delivered 14:03 · 0 waiting", "Failing since 14:03: HTTP 502 · 4 waiting ·
next try 14:05", "Not set: no address in secrets.yaml"). The test sends one message straight
away, with the settings and secrets as saved, whether the webhook is on or not, so you can try it
before you switch it on. `lanowl --check` shows one line, "Webhook: on · generic · to
hooks.example.org", and sends nothing.

The address and the token are never in the log, Telegram, MQTT, the dashboard or what the
owl reads. The log names the receiver's host and nothing more of the address.

## What it sends, and when

It gets what Telegram gets, no more: the same incidents (one message per incident, a recovery
when it is over), the same digests, the same opt-ins: a new device still needs
`discovery.notify_new_devices`. `--no-telegram` mutes it too. `events` and `min_severity` can
only narrow that down. The dashboard says where each message went: on the Timeline, under
Messages, it reads Telegram, Webhook, both, or Not sent.

One POST per Telegram message. A message about several devices is one POST: each device has a
line in its `message` ("NAS (192.168.10.5): unreachable (icmp)") and an entry in its `incidents`.

`events` picks the kinds of message:

| Kind | What | On by default |
|---|---|:-:|
| `down` | A device or service down, and the reminder that it still is | ✓ |
| `recovery` | It is back. A problem only the digest had named is told back only with `digest` on too: otherwise the webhook never heard of it | ✓ |
| `wan` | The internet: no internet, back, on the backup line | ✓ |
| `security` | The security review, a login from an unknown address, failed logins, a connection flood, a locked dashboard login, the owl's shell not isolated | ✓ |
| `new_device` | A device never seen on the network | ✓ |
| `logs` | A host's or a device's own log, the router's log, a port slower or back | ✓ |
| `diagnosis` | The owl's diagnosis of an incident (below) | ✓ |
| `proposal` | An action the owl or the audit proposes, waiting for your yes. A POST has no buttons, so you answer it on the dashboard | ✓ |
| `digest` | The digest and the week in review | |
| `maintenance` | Updates, backups, lanowl's own updates, an action you approved on the dashboard, a muted port | |
| `other` | Pause and resume, the owl switched on or off, a Settings change, the dashboard's setup, an address change, the dashboard closed until a password is set | |

`min_severity` (`info`, `warning`, `high`, `critical`; default `info`) drops what is less bad
than that. A recovery counts as `info`, and so does a proposal: above `info`, proposals are left
out too. A diagnosis has its incident's severity.

## The generic body

```json
{
  "sender": "lanowl",
  "title": "NAS offline",
  "message": "NAS (192.168.10.5)\nunreachable (icmp)",
  "severity": "critical",
  "event_id": "5c0f6d0a9e4b4f5c8a1d2b7e3f9a6c41",
  "event_type": "device_down",
  "category": "down",
  "timestamp": "2026-11-17T14:02:27+01:00",
  "incident_id": "9b1e4c7a2d6f3e80",
  "device": {"name": "NAS", "ip": "192.168.10.5", "mac": "AA:BB:CC:00:00:05"},
  "incidents": [
    {"incident_id": "9b1e4c7a2d6f3e80", "event_type": "device_down", "severity": "critical",
     "device": {"name": "NAS", "ip": "192.168.10.5"}}
  ]
}
```

| Field | What |
|---|---|
| `title`, `message` | Plain text: Telegram's formatting is gone, its lines are kept. The title is the first line without its emoji and time; for a device, "NAS offline", "NAS still offline", "NAS back online", "3 devices offline". |
| `severity` | `critical`, `high`, `medium`, `low` or `info` (the table below). |
| `event_id` | Unique to the message, and the same on every retry: a receiver can drop a duplicate by it. |
| `event_type` | `device_down`, `device_still_down`, `device_up`, `wan_down`, `wan_up`, `wan_warning`, `log_alert`, `security_alert`, `new_device`, `diagnosis`, `digest`, `weekly`, `maintenance`, `proposal`, `notice`, `test`. |
| `category` | The kind of message, as `events` names it. |
| `timestamp` | When it happened, ISO 8601 with the offset, not when it was delivered. |
| `incident_id` | Only when the message is about exactly one incident. An alert and its recovery have the same one. |
| `device` | Only when the message is about exactly one device: `name`, `ip`, and `mac` when lanowl knows it. |
| `incidents` | Every incident the message covers: its `incident_id`, `event_type`, `severity` and `device`. |
| `in_reply_to` | Only on a diagnosis: the `event_id` of the message it follows. |

A field the message does not have is left out, not `null`.

### Severity

| lanowl | generic | apprise `type` | ntfy `priority` |
|---|---|---|:-:|
| critical | `critical` | `failure` | 5 |
| high | `high` | `failure` | 4 |
| warning | `medium` | `warning` | 3 |
| info | `low` | `info` | 2 |
| recovery | `info` | `success` | 3 |

### The owl's diagnosis

Telegram gets the owl's diagnosis of a new critical incident a few minutes later, edited into
the alert. A POST cannot be edited, so the webhook gets a second one: `event_type: "diagnosis"`,
the same `incident_id` (or `incidents`), and `in_reply_to`, the `event_id` of the message that
announced it. One follow-up for each message that announced an incident. It needs no Telegram,
and is not sent for an incident the webhook was not told about (filtered out, or announced
before lanowl last started).

## The other formats

**`apprise`**, for an Apprise server's JSON notification:

```json
{"version": "1.0", "title": "NAS offline", "message": "NAS (192.168.10.5)\nunreachable (icmp)",
 "type": "failure", "sender": "lanowl"}
```

**`ntfy`**: the address is the one you would open, `https://ntfy.example.org/lanowl`. lanowl
posts to the server's root with the topic in the body, as ntfy's JSON publish wants:

```json
{"topic": "lanowl", "title": "NAS offline", "message": "NAS (192.168.10.5)\nunreachable (icmp)",
 "priority": 5, "tags": ["rotating_light"]}
```

The tags are `rotating_light` (critical), `warning` (high, warning), `information_source`
(info) and `white_check_mark` (recovery). A token in `tokens.webhook` is sent as
`Authorization: Bearer …`, which is how ntfy takes its access tokens.

**`template`**: your own JSON, for a receiver none of the others fits. Every string value
may hold `{name}` placeholders:

```yaml
webhook:
  format: "template"
  template:
    text: "{title}: {message}"
    severity: "{severity}"
    devices: "{incidents}"
```

| Name | What |
|---|---|
| `title`, `message` | As above |
| `severity` | lanowl's own word: `critical`, `high`, `warning`, `info` or `recovery` |
| `event_id`, `event_type`, `category`, `timestamp` | As above |
| `incident_id`, `in_reply_to` | As above; empty when there is none |
| `device`, `ip`, `mac` | The one device the message is about; empty otherwise |
| `incidents` | The list of incidents |

A value that is only a placeholder takes the value as it is, so `"{incidents}"` is the list.
Inside a longer string a list is written as JSON. A name lanowl does not know is left as written.
Only `{name}` is filled in: nothing else in a string is read as anything.

## Headers

`Content-Type: application/json` and `User-Agent: lanowl/<version>`, then what `headers` adds
(for a header that is not secret), then `Authorization: Bearer …` if `tokens.webhook` is set.
`verify_tls: false` is for a gateway with a self-signed certificate.

## When the receiver does not answer

Each message is tried up to three times, two seconds and then four apart, each with 10 seconds
to answer. A message that still has not been taken waits at the head of its queue and is tried
again every minute; the ones behind it wait too, so they arrive in order.

| Answer | What lanowl does |
|---|---|
| 2xx | Delivered. |
| 408, 429, 5xx, no answer, no connection | Tried again. |
| Any other 4xx | The receiver refused that message: dropped, with a line in the log and in the status. |
| A redirect | Not followed: it would carry the token to another host. Dropped like a refusal. |

The queue is a file (`webhook.queue_file`, in `/state`): what waited survives a restart. A
message older than 24 hours is dropped, and at most 200 are kept, the oldest first to go. Nothing
waits for the internet: unlike Telegram, the receiver is often on your own network, so a message
goes out during an outage. Nothing on the sweep, Telegram or MQTT ever waits for the receiver
either.
