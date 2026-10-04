# FAQ

### Is it free?

Yes. lanowl is open source under the AGPL-3.0 license. There is no paid tier, no account and
no telemetry.

### What leaves my network?

Only what each feature needs, to the place it needs it:

- **Telegram**: the messages you receive, sent to Telegram's API.
- **The internet check**: pings to `wan.targets`.
- **The update check**: MikroTik's release list; and, for the monthly vulnerability check,
  package names, versions and CVE ids to OSV.dev and NVD, never an address or a name.
- **The security review**: a port scan of your own public server, from your network, and of
  your home's public address from that server; one HTTPS request to each of your own
  `public_names`.
- **A speed test** from a remote site's router, only when you ask for one.
- **The owl's diagnostics**, when a question or an approved session needs them: `mtr`, DNS
  lookups, `whois`, TLS checks, towards the hosts in question. Its sandboxed shell, when you
  switch it on, has the internet too.

The model runs on your own Ollama. Nothing goes to the lanowl project: it has no servers.

### Do I need a GPU?

No. Without a model everything works except the owl's words: detection, alerts, digests and
the dashboard. For the owl, any Ollama model with tool calling; a 27–35B model on a machine
with 32–64 GB of memory is comfortable.

### Can I use ChatGPT or Claude instead of a local model?

Not yet: only Ollama. Cloud models (OpenAI-compatible APIs and Anthropic's) are on the
[roadmap](../reference/roadmap.md), with a check of what would leave the network.

### Do I need a MikroTik?

No. With one, lanowl reads its DHCP, routes, ARP table and log: new devices, which internet
link is in use, failovers. With any other router, every device is still watched by ping, TCP,
HTTP or SNMP.

### Will it change anything on my network?

Only what you approve, with a button on Telegram or your PIN on the dashboard. Actions are
off until you switch them on, and can run in shadow mode, which only records what would have
run. The model never writes a command: it picks an action from a fixed list.

### Is it a Home Assistant add-on?

No, on purpose. lanowl watches Home Assistant too, so it must not go down with it. It runs
beside it, can reboot or back up Home Assistant, and publishes its results to MQTT.
Discovery into Home Assistant is on the roadmap.

### How many devices can it watch?

It has watched a real network of about sixty devices across three sites, with a sweep a
minute. Probes run in parallel (`probes.concurrency`).

### Can it run without Docker?

Yes: it is a Python package (`pip install .`, Python 3.11 or newer). The image adds the tools
the owl's diagnostics use (`mtr`, `nmap`, `tcpdump` and others); without them, those checks are
not available. Docker is the supported way.

### Why an owl?

It watches at night, sees in the dark, and is supposed to be wise: it tells you *why*. Its
words are marked 🦉, so you can always tell the model's opinion from the monitor's
measurements, which keep their 🔴🟡🟢.

### Is it ready?

It is pre-alpha. lanowl comes out of a monitor that has looked after a real home network since
August 2026: MikroTik, OpenWrt, Linux servers, Shellies, cameras, a VPS and two remote sites.
Expect rough edges, and tell us about them on GitHub.
