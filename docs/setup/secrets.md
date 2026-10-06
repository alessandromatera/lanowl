# Secrets and logins

Every secret lanowl holds is in one file, `config/secrets.yaml`, so that `config.yaml` and
`inventory.yaml` can be shared or kept in git without one. lanowl writes it at its first start
(mode 600, no login, no token yet) and the dashboard fills it; you can also edit it by hand.
lanowl reads it again whenever it changes: a new password or token needs no restart (a
password that becomes a key does).

## From the dashboard

Write-only: a password or a token goes in from the page, and no page shows it again.

- **The first-run setup** takes the router's login, a login for each device you give one, and
  the Telegram token, and writes them at its last step.
- **Settings → Secrets** lists every login and token by name: set or missing, the login's
  user, what uses it. **Set**, **Replace** and **Add a login** open a sheet with the fields;
  a login is a user with a password, or with lanowl's ssh key. **Remove** is refused while a
  device or `config.yaml` still names the login, and says which.

Each save, from a logged-in browser, says what changes
by name ("login routers: password replaced"), Telegram gets one line naming the login or token,
and the file as it was is kept in lanowl's state (mode 600, the last 30 versions): History can
put it back. A value set in the environment (`LANOWL_TG_TOKEN`, below) is not changed from
the page: it says where it comes from.

Those kept versions hold the secrets too: whoever backs up lanowl's state volume backs them up.

The page sends a typed password to lanowl once, over the dashboard's connection: plain HTTP
unless lanowl sits behind an HTTPS proxy, as the dashboard password does.

## The file

```yaml
logins:                          # named logins; several devices may share one
  routers:     {user: admin, password: "a long one"}
  server:      {user: root, key: true}                      # lanowl's own ssh key
  nas:         {user: admin, key: true, password: "..."}    # the key logs in, sudo takes the password
  router-read: {user: lanowl, password: "..."}              # the router's read-only user

devices:                         # address -> login, for devices that do not name theirs
  192.168.88.30: server

tokens:
  telegram: "123456:ABC..."      # from @BotFather
  homeassistant: "eyJ..."        # a long-lived access token (your HA profile → Security)

ssh_key: /config/id_ed25519      # lanowl's own key, for every `key: true` login
```

## Logins

A login is a user with one of:

| | How lanowl logs in |
|---|---|
| `password: "..."` | ssh with a password. Routers, cameras, most appliances. |
| `key: true` | ssh with lanowl's own key (`ssh_key`). Or `key: /path/to/key` for another one. |
| `key: true` and `password` | The key logs in; the password is what sudo asks for. |

A device names its login in the inventory (`credentials: routers`), or the `devices:` map
here does it by address. The inventory's wins.

A user other than root needs sudo for what reads or changes the system. With a password,
sudo takes it. With a key alone, it needs a `NOPASSWD` rule; for restarting a service, a rule
for exactly `systemctl restart <unit>` is enough.

### lanowl's key

lanowl makes its own key at its first start (`config/id_ed25519`, mode 600) and names it in
`secrets.yaml` (`ssh_key`). Settings → Secrets → **Public key** shows its public half with the
line to add on a machine, ready to copy:

```bash
mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA… lanowl' >> ~/.ssh/authorized_keys
```

Run it as the user lanowl logs in as, on each machine whose login has `key: true`. With files
of your own instead, make the key yourself:

```bash
ssh-keygen -t ed25519 -N '' -C lanowl -f config/id_ed25519
```

Give the private key mode 600: ssh refuses a key others can read, and `lanowl --check` says so.

### lanowl's own logins

Two logins are lanowl's own rather than a device's, and `config.yaml` names them:

| Login | Named by | What for |
|---|---|---|
| The router's read-only user | `mikrotik.credentials` (default `router-read`) | DHCP, routes, the log, the API ([Your router](mikrotik.md)) |
| The MQTT broker's user | `mqtt.credentials` (default `mqtt`) | Only if the broker wants one |

## From the environment

lanowl's own secrets can come from the environment instead of the file, for a deployment
that keeps them elsewhere. The first found wins: the variable, then the file its `_FILE`
twin names (which is how Docker secrets arrive, in `/run/secrets/`), then `secrets.yaml`.

| Variable | Instead of |
|---|---|
| `LANOWL_TG_TOKEN` | `tokens.telegram` |
| `LANOWL_HA_TOKEN` | `tokens.homeassistant` |
| `LANOWL_MIKROTIK_USER`, `LANOWL_MIKROTIK_PASS` | The router's read-only login |
| `LANOWL_MQTT_USER`, `LANOWL_MQTT_PASS` | The broker's login |
| `LANOWL_SSH_KEY` | `ssh_key` (a path; no `_FILE` twin) |

Device logins come from the file only.

## Where a password goes, and where it never goes

- ssh reads it through `SSH_ASKPASS`: a script readable only by lanowl that prints a variable
  set for that one ssh process. Never on the command line, where anyone on the machine could
  read it, and never in a log line.
- sudo reads it on standard input, inside the encrypted connection.
- A camera's web API gets it in the body of its own login call, and nowhere else.
- It never comes back out: not to a proposal, a message, the dashboard or the model. What a
  command prints is scrubbed of it before anything else sees it.

lanowl tries a password once per connection, because some systems (ESXi) lock an account
after a few failures, and it never offers its key to a password login.

## Host keys

A device's host key is trusted the first time lanowl connects and remembered on the state
volume. A device that makes a new host key at every boot is listed in
`access.hostkey_any`. Old devices (RouterOS 6, OpenWrt's dropbear) offer only older key types;
lanowl accepts those as a fallback, never in preference to modern ones.

## Checking

`lanowl --check` lists where each secret comes from (the file, a variable, a `_FILE`), what is
missing for a feature you switched on, and whether the file or the key can be read by others.
It never prints a value.
