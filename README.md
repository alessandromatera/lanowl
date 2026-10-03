# lanowl

A watchful, read-only caretaker for home and small-office networks.

lanowl checks every device on your network every minute and tells you about a problem once per incident, not once per blip. It knows the difference between "the main line failed over" and "there is no internet at all". It looks after more than one site: your house, and the routers you reach over a VPN.

A local model, or a cloud one if you choose, can diagnose a problem, answer questions about the network and propose a fix. Nothing on a device changes until you approve it.

Device kinds are modules:
- **Built-in:** MikroTik, OpenWrt, Linux machines, and plain ping/http.
- **Your own:** write a YAML file, or a Python package for devices with an API.

Credentials live in one file of your own and never reach the model.

**Status:** early. It is being extracted from a private deployment that has run since August 2026, and it is not ready to install yet.

## License

Apache-2.0. See [LICENSE](LICENSE).
