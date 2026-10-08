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

## The config folder, read-write

lanowl writes its own files into an empty config folder at a first start, and the dashboard
sets secrets too, so the compose file mounts the folder read-write, in one line, instead of
read-only with `config.yaml` and `inventory.yaml` read-write on their own:

```yaml
    env_file: [{path: .env, required: false}]    # optional now
    volumes:
      - ../config:/config
```

If you keep a compose file of your own, make the same change (paths as in yours). Until you
do, everything works as before: Settings still writes `config.yaml` and `inventory.yaml`, and
says `secrets.yaml` is read-only. `required: false` needs Docker Compose 2.24 or later
([What you need](../getting-started/requirements.md)); with an older one, keep `env_file:
.env` and the file.

The model's two shells (its sandboxes) now take `LANOWL_HOST_IP` from `docker/.env` or the command line
(Settings → The model's shell gives the line); `docker/.env` keeps working as it was.

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
