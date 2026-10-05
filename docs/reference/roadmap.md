# Roadmap

What is agreed and not built yet, roughly in order. lanowl is pre-alpha: the order can change,
and nothing here is promised by a date.

- **Cloud models**, besides Ollama: OpenAI-compatible APIs and Anthropic's, with a check of what
  would leave the network (never a login; addresses and names only as you allow).
- **ntfy** as a second alert channel beside Telegram.
- **Home Assistant**: every watched device and the internet's state as entities through MQTT
  discovery, without a custom integration, and an add-on for Home Assistant OS users.
- **A Settings tab** on the dashboard: `config.yaml` as forms, each field saying where its
  value comes from.
- **Profiles that can install and restart**: `upgrade` and `restart` operations for device
  kinds of your own.
- **Releases**: a multi-architecture image on GitHub's registry and packages on PyPI, so
  installing needs no build.

Ideas, requests and bugs are welcome as
[GitHub issues](https://github.com/alessandromatera/lanowl/issues).
