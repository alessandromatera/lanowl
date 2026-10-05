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

## What a restart keeps

A restart picks every device up where the last run left it: an outage already under way keeps
its start time, an incident you were already told about is not announced again, and the
digest does not repeat itself. Messages that could not be sent are still in the outbox and go
out when they can. Paused devices stay paused, the model's switch keeps its position, and
proposals still waiting for you keep their buttons until they expire.

lanowl is pre-alpha: read the commit log before upgrading, and keep `backups.self` on, so its
own state can be put back.
