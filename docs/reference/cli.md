# Command line

The container runs `python -m lanowl.main`, which is lanowl itself: every loop, the
dashboard and the Telegram bot. The same program takes a few options, run with
`docker compose -f docker/compose.yaml run --rm lanowl <command>`.

| Command | What it does |
|---|---|
| `lanowl --check` | Reads the config, the inventory, the profiles and the secrets the way a start does, and says what lanowl will do with each device and why not, where each secret comes from, which model it will ask, and whether the sandboxed shell is ready. Probes nothing and sends nothing. Exits with 1 when something is wrong. |
| `lanowl --once` | One sweep and one audit by the owl, printed, then exits. Like a real sweep it may send an alert: add `--no-telegram` to stay quiet. |
| `lanowl --once --no-llm --no-mqtt --no-telegram` | A dry run: one sweep printed, nothing sent anywhere. |
| `lanowl` | Runs for good (the container's command). |

| Option | What it does |
|---|---|
| `--config PATH` | The config file. Default: `LANOWL_CONFIG`, else `config.yaml` where it runs. |
| `--inventory PATH` | The inventory. Default: `LANOWL_INVENTORY`, else `inventory.yaml`. |
| `--no-llm` | No model for this run, whatever the switch says. |
| `--no-mqtt` | Do not connect to the broker. |
| `--no-telegram` | Never send to Telegram (rehearsals). |
| `--log-level LEVEL` | `DEBUG`, `INFO`, `WARNING`. |

A one-off run (`--once`) never writes lanowl's record of what you were told, so a rehearsal
next to a running lanowl cannot confuse it.

## The test suite

The tests ride in the image, so a deploy can be gated on them:

```bash
docker compose -f docker/compose.yaml run --rm lanowl python /app/tests/run_all.py
```
