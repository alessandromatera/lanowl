# Logs and lanowl's own state

## The log

```yaml
logging:
  level: "INFO"
  file: "lanowl.log"
```

The log is a file in the `/state` volume, rotated at 5 MB, three old ones kept. With a file
set, `docker logs` stays empty: read the file.

```bash
docker exec lanowl tail -f /state/lanowl.log
```

It logs changes, not repetition: a device going down and up, an alert sent or held, an audit
and what became of its digest, a proposal and its outcome. The owl can read it too ("what did
lanowl log about the router this morning?").

`level: DEBUG` for a while when something needs explaining; `--log-level` overrides it for one
run.

## What is in /state

| File | What |
|---|---|
| `lanowl_state.sqlite` | Everything lanowl remembers: every device's samples (`state.history_days`, 30 days), every down and up, the internet's evidence, what Telegram was told, and the records: the alert gate, pauses, the model's switch, its memory, proposals and actions, conversations, the update check, the security review, dismissals, Known and Watched devices, backups. |
| `lanowl.log` | The log, and its rotated copies. |
| `tg_outbox.json` | Messages waiting for the internet. |
| `known_hosts_devices` | The ssh host keys of your devices. |

The compose file keeps `/state` in the `lanowl-state` volume, and ssh's own files in
`lanowl-ssh`.

## Backing lanowl up

With backups on, lanowl backs itself up every day (`backups.self.daily` kept): a consistent
copy of its database, taken while it runs, its secrets, its known hosts and the config it runs
with, onto your backup store. To move lanowl to another machine, put the config folder and the
database back, and it carries on where it was.

## History

Samples older than `state.history_days` are pruned every hour. The dashboard shows seven days;
the owl can read the whole history you keep.
