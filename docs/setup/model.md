# The model

The owl is a local language model, run by [Ollama](https://ollama.com) on a machine of
yours. It explains incidents, answers your questions, reviews security every morning and
proposes fixes. It never decides whether something is down: that is lanowl's own code, and it
works the same with the model switched off.

## Setting it up

Until `config.yaml` has a `model:` section (or `LANOWL_MODEL_URL` gives one), there is no model:
the owl is off. lanowl asks nothing, checks no model server and warns about none; the alerts,
the digests and the dashboard work as always, and the owl's card on Now says where to set one.
A new install starts this way.

1. Install Ollama on the machine with the most memory or the best GPU (it can be another
   machine than lanowl's).
2. Pull a model with tool calling, for example `ollama pull qwen3.8:27b`, the one lanowl is
   tested with.
3. Make Ollama listen on the network if it is on another machine (`OLLAMA_HOST=0.0.0.0`),
   and point lanowl at it:

```yaml
model:
  provider: ollama
  url: "http://192.168.88.6:11434"    # or LANOWL_MODEL_URL in docker/.env
  name: "qwen3:30b"
  think: true
  num_ctx: 32768
  keep_alive: "10m"
  request_timeout_s: 300
  max_tool_iters: 10
  temperature: 0.2
  persona: "owl"
```

| Key | What it does |
|---|---|
| `url`, `name` | Where Ollama is, and which model. `LANOWL_MODEL_URL` wins over `url`. |
| `think` | Let a thinking model reason before it answers. |
| `num_ctx` | The context window. Every tool result stays in the prompt, so give it room: past it, Ollama silently drops the start of the prompt, and lanowl's log warns when an audit came within 10% of it. |
| `keep_alive` | How long the model stays loaded after a call. `0` frees the memory at once. |
| `request_timeout_s` | The longest one call may take. |
| `max_tool_iters` | The most tool calls in one audit. |
| `persona` | The voice of its prose: `owl`, or `""` for plain prose. |

**Which model.** Any Ollama model with tool calling works. A larger model reasons better; a
27–35B model on a machine with 32–64 GB of memory is comfortable.

**Tested with `qwen3.8:27b`**, and it works well: lanowl is developed against a real home
network with it (the Apple-silicon build `qwen3.8:27b-mlx`, about 18 GB, with `think: true`
and `num_ctx: 131072`).

Only Ollama is supported for now; cloud models are on the [roadmap](../reference/roadmap.md).

## The owl's voice

With `persona: owl`, the model writes the way a calm night watcher speaks: brief, precise,
with times and numbers. It never changes a severity or invents a fact, and its words are
marked 🦉 wherever they appear, so you can always tell the model's words from the monitor's
measurements, which keep their 🔴🟡🟢.

What makes its answers good is `network.description` in `config.yaml`: a few sentences about
your network that every prompt includes. Say what no inventory says.

## What it can do

**Look**, with read-only tools: the history of every device, the internet's history and
evidence, the router's log and tables, a machine's log, MQTT values, ping, TCP and HTTP to an
inventory device, and everything lanowl has kept: what it sent you, the update check, the
security review, the backups, earlier conversations. An address outside your inventory is
refused.

**Read a device itself**, in your questions: the speed a port really linked at, its own log,
its Wi-Fi clients. lanowl logs in with the device's own login, the one it uses for updates and
backups, and runs one fixed read-only command per read; the owl picks the read, never the
command. What each kind offers: [Device kinds](../reference/kinds.md#what-the-owl-can-read).

**Run diagnostics**, from a fixed catalog: `mtr`, `traceroute`, DNS and TLS checks, a port
scan, the router's own ping, a packet capture, each internet link on its own, a check from
another LAN host or from your VPS. When you ask a question, the ones it needs run at once and
are listed under its answer. The hourly audit, which nobody asked, may run a few passive ones
by itself (`actions.session.audit_checks`); for anything more, or anything active like a scan,
it asks you to open an investigation session, with a button.

**Propose changes**, from another fixed catalog, that run only when you approve:
[Actions and approvals](../using/actions.md).

**Remember** what you tell it ("remember that the NAS sleeps at night"), in notes you can
read, edit and delete on the dashboard or with `/memory`.

## Its shell, in a sandbox

For questions a fixed tool cannot answer, the owl can get a shell: one bash command at a
time, in a container of its own beside lanowl.

```bash
docker compose -f docker/compose.yaml --profile shell up -d
```

```yaml
shell:
  enabled: true
  canary_lan: "192.168.88.10:22"     # a LAN service that always answers a handshake
  audit: {enabled: true}             # the hourly audit's own, offline sandbox
```

The sandbox has no key, no config and no state of lanowl's. It reaches the internet, and the
LAN only for handshakes and scans. It cannot reach lanowl's dashboard. Its walls are
**proven** before the tool is offered: from inside, a handshake to `canary_lan` must succeed
(the network is there), the HTTP request after it must get nothing, and lanowl's dashboard must
not answer at all. Anything else switches the shell off, and you are told once.
The proof runs at start, every morning with the security review, and whenever the sandbox
restarts.

The hourly audit gets a second sandbox with no internet and no DNS at all, and at most a few
commands per audit. Every command, with who asked and what came back, is listed under the
answer and on the dashboard.

## Switching it off

`/model off` on Telegram, or the switch on the dashboard's Ask tab, puts the owl to sleep:
no diagnoses, answers or reviews, and Ollama is told to free its memory. Alerts, digests and
the dashboard go on. `/model on` wakes it.
