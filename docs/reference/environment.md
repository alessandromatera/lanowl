# Environment variables

The environment holds what differs between machines running the same `config.yaml`, and,
optionally, lanowl's own secrets. With Docker, put them in `docker/.env`. A variable wins over
the file.

## Deployment

| Variable | Instead of | What |
|---|---|---|
| `LANOWL_HOST_IP` | `observer.host_ip` | This machine's address on the LAN. lanowl tells its own outage from the network's by it, and recognises its own ssh logins in your logs. |
| `LANOWL_MODEL_URL` | `model.url` | Where Ollama runs. |
| `LANOWL_WEB_PORT` | `web.port` | The dashboard's port. |
| `LANOWL_CONFIG` | `--config` | The config file (the image sets `/config/config.yaml`). |
| `LANOWL_INVENTORY` | `--inventory` | The inventory (the image sets `/config/inventory.yaml`). |
| `TZ` | | Your time zone. Not optional in practice: sunrise and sunset, the morning jobs and the router's log timestamps read local time. |

## Secrets

Each also as `<NAME>_FILE`, the path of a file holding the value, which is how Docker secrets
arrive (`/run/secrets/<name>`). The first found wins: the variable, then its `_FILE`, then
`secrets.yaml`.

| Variable | Instead of |
|---|---|
| `LANOWL_TG_TOKEN` | `tokens.telegram` |
| `LANOWL_HA_TOKEN` | `tokens.homeassistant` |
| `LANOWL_MIKROTIK_USER`, `LANOWL_MIKROTIK_PASS` | The router's read-only login (`mikrotik.credentials`) |
| `LANOWL_MQTT_USER`, `LANOWL_MQTT_PASS` | The broker's login (`mqtt.credentials`) |
| `LANOWL_SSH_KEY` | `ssh_key` (a path; no `_FILE` twin) |

Device logins come from `secrets.yaml` only. `lanowl --check` says where each secret comes
from, never its value.
