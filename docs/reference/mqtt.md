# MQTT topics

MQTT is optional. With a broker, lanowl publishes its results for Home Assistant, Node-RED or
anything else, takes two commands, and keeps the last values of topics you choose so the owl
can read them.

```yaml
mqtt:
  host: "192.168.88.10"
  port: 1883
  tls: false
  credentials: "mqtt"          # its login in secrets.yaml, if the broker wants one
  base_topic: "lanowl"
  subscribe: ["shellies/#"]    # the last values the owl may read
```

## What lanowl publishes

All under `base_topic` (`lanowl` here), as JSON.

| Topic | Retained | What |
|---|:-:|---|
| `lanowl/status` | ✓ | The report after every sweep: overall health, counts, the internet, issues, every device with its state and latency, the named services. |
| `lanowl/report` | ✓ | The same, after each audit by the owl, with its assessment. |
| `lanowl/heartbeat` | ✓ | After every sweep: its time, the process id, how many sweeps, uptime, the sweep interval and the number of devices. |
| `lanowl/logbook` | ✓ | Every device's confirmed downs and ups, for a history panel. |
| `lanowl/discovery` | ✓ | What the router's DHCP holds and nobody watches, and what is new. |
| `lanowl/critical` | | Every alert as sent to Telegram: `{"text", "ts"}`. |
| `lanowl/digest` | | Every digest and other message: `{"text", "ts"}`. |
| `lanowl/answer` | ✓ | The answer to a question asked on `lanowl/ask`: `{"q", "a", "ts"}`. |

## What lanowl listens to

| Topic | What it does |
|---|---|
| `lanowl/cmd` | Any message: an audit now, as **Audit now** on the dashboard. |
| `lanowl/ask` | A question for the owl, as plain text or `{"q": "..."}`. The answer goes to `lanowl/answer`. |
| what `subscribe` lists | The last values are kept for the owl's `mqtt_last` tool, for example your Shellies' power readings. |

## A watchdog for lanowl itself

lanowl cannot report its own death. A supervisor restarts a process that crashes, but a process
that is merely stuck looks exactly like a quiet network. `lanowl/heartbeat` is retained for
exactly this: something on another machine (a Home Assistant automation, a cron job on your
NAS) can alert you when its `ts` stops moving.
