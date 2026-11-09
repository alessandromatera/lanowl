# Upgrading

Upgrading is pulling the new release: the repository (for the compose file and the examples)
and the image. Everything lanowl knows lives in the `/state` volume and your `config` folder,
so nothing is lost.

```bash
cd lanowl
git pull
docker compose -f docker/compose.yaml pull
docker compose -f docker/compose.yaml run --rm lanowl lanowl --check
docker compose -f docker/compose.yaml up -d
```

With the sandboxed shell, add `--profile shell` to the `pull` and `up` commands, and
`LANOWL_HOST_IP=<this machine's address>` before `up` unless `docker/.env` sets it. The releases
and what changed are on [GitHub](https://github.com/alessandromatera/lanowl/releases);
`lanowl --version` says which one you run.

To run the code you checked out instead of the release (`main` between releases, or your own
change), replace `pull` with `build`.

A compose file of your own, copied before the images were published, still names local
images (`lanowl:latest`, `lanowl-sandbox:latest`): `pull` then fetches nothing and the old
image keeps running. Name the published ones, `ghcr.io/alessandromatera/lanowl:latest` and
`ghcr.io/alessandromatera/lanowl-sandbox:latest`, or keep using `build`.

## The updater (optional)

Settings → lanowl's version and updates can update lanowl for you. That needs one more
container, the updater, which you start yourself:

```bash
docker compose -f docker/compose.yaml --profile updater up -d
```

The risk, in one sentence: the updater holds Docker's socket, which is root on the machine, so
it is a container of its own, from the same image, with no network, a read-only disk and no
capabilities; lanowl itself never gets the socket and can only tell the updater "update".

What an update does, fixed in the updater's code and not chosen by lanowl: it takes only the
containers of its own compose project that are lanowl, `sandbox` or `sandbox-offline` and are
running; pulls each one's own image (a lanowl built on the machine, with no registry in its
name, is refused: update it where it was built); stops there when the images are the same;
else replaces the sandboxes first and lanowl last, each new container made from the old one's
own configuration. The old ones are kept, renamed `-previous`, until the new lanowl has run for
3 minutes without restarting and its dashboard answers. Then they are removed. If it does not,
the new ones are removed, the old ones come back, and Telegram quotes the new container's last
log lines. What happened is in `/run/updater/last.json`, and on Settings.

Without the updater, update by hand as above (`pull`, `up -d`), or `pip install -U lanowl` and a
restart for a pip install.

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

lanowl is pre-alpha: read the release notes before upgrading, and keep `backups.self` on, so its
own state can be put back.
