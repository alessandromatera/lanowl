# lanowl documentation

lanowl watches every device on your network, tells you once per incident, and has a local
model explain what broke. These pages cover installing it, setting it up for your own
network, and living with it. They describe what lanowl does today; what is planned is on the
[roadmap](reference/roadmap.md).

> **Let an AI assistant write your configuration.** You do not need to learn lanowl's YAML.
> Describe your network to Claude, ChatGPT, Gemini or any assistant, point it at the example
> files, and it writes `config.yaml` and `inventory.yaml` for you; `lanowl --check` tells you
> both what to fix. Your passwords never leave your machine.
> [How, and the prompt to copy](getting-started/with-an-ai.md).

The screenshots and messages come from a made-up house played through lanowl's own code
([`demo/`](../demo/)): a family home behind a MikroTik with fibre and an LTE backup, and a
cabin reached over WireGuard. None of it is a real network.

## Getting started

- [What you need](getting-started/requirements.md)
- [Quick start](getting-started/quick-start.md)
- [Set it up with an AI assistant](getting-started/with-an-ai.md)
- [Telegram](getting-started/telegram.md)
- [The first hour](getting-started/first-hour.md)

## Setting it up

- [config.yaml](setup/config.md)
- [Devices: inventory.yaml](setup/inventory.md)
- [Secrets and logins](setup/secrets.md)
- [Your router (MikroTik)](setup/mikrotik.md)
- [A backup internet line](setup/backup-line.md)
- [Remote sites](setup/sites.md)
- [Device kinds of your own](setup/profiles.md)
- [The model](setup/model.md)

## Using it

- [How alerts work](using/alerts.md)
- [The dashboard](using/dashboard.md)
- [Settings: config, devices, the first-run setup](using/settings.md)
- [Telegram commands](using/telegram-commands.md)
- [Asking the owl](using/asking.md)
- [Actions and approvals](using/actions.md)
- [Updates, backups and the security review](using/security.md)
- [Pausing a device](using/pausing.md)

## Running it

- [Upgrading](running/upgrading.md)
- [Logs and lanowl's own state](running/state.md)
- [Troubleshooting](running/troubleshooting.md)
- [FAQ](running/faq.md)

## Reference

- [Device kinds and features](reference/kinds.md)
- [Profiles: operations and parsers](reference/profiles.md)
- [Command line](reference/cli.md)
- [Environment variables](reference/environment.md)
- [MQTT topics](reference/mqtt.md)
- [The security model](reference/security-model.md)
- [Roadmap](reference/roadmap.md)
