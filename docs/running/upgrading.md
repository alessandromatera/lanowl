# Upgrading

lanowl is built from the repository, so upgrading is pulling it and rebuilding the image.
Everything it knows lives in the `/state` volume and your `config` folder, so nothing is lost.

```bash
cd lanowl
git pull
docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml run --rm lanowl lanowl --check
docker compose -f docker/compose.yaml up -d
```

With the sandboxed shell, add `--profile shell` to the `build` and `up` commands.

## Before restarting

Run `lanowl --check` on the new image first. When a setting was renamed or moved, it says
so with a ✗ and what to write instead (for example, an old `ollama:` section is now `model:`,
with `name:` for the model), and exits with 1, so a script can stop there.

The test suite rides in the image too:

```bash
docker compose -f docker/compose.yaml run --rm lanowl python /app/tests/run_all.py
```

## Settings on the dashboard

[Settings](../using/settings.md) writes `config.yaml` and `inventory.yaml`, so the compose
file now mounts those two read-write, each on its own, over the read-only config folder. If
you keep a compose file of your own, add the two lines under `volumes:` (paths as in yours):

```yaml
      - {type: bind, source: ../config/config.yaml, target: /config/config.yaml, bind: {create_host_path: false}}
      - {type: bind, source: ../config/inventory.yaml, target: /config/inventory.yaml, bind: {create_host_path: false}}
```

Without them everything works as before, and Settings says the files are read-only.

There is no dashboard PIN any more: approving on the dashboard is a confirm, behind its
login. `--check` names any `actions.pin_sha256`, `pin_max_failures` or `pin_lockout_min`
still in your `config.yaml`; they do nothing now, so take them out of the file. Devices you
watched with the dashboard's **Watch** button lived in lanowl's state: Settings → Devices
offers to move them into `inventory.yaml`.

## What a restart keeps

A restart picks every device up where the last run left it: an outage already under way keeps
its start time, an incident you were already told about is not announced again, and the
digest does not repeat itself. Messages that could not be sent are still in the outbox and go
out when they can. Paused devices stay paused, the model's switch keeps its position,
proposals still waiting for you keep their buttons until they expire, browsers stay logged in,
and a locked login stays locked.

lanowl is pre-alpha: read the commit log before upgrading, and keep `backups.self` on, so its
own state can be put back.
