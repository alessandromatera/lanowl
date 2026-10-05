# Troubleshooting

Start with `lanowl --check`, then the log (`docker exec lanowl tail -100 /state/lanowl.log`).
Most problems are named in one or the other, with what to do.

## Every device reads DOWN

The host does not allow unprivileged ping (Debian ships it closed):

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee /etc/sysctl.d/60-ping.conf
```

If everything went down at once on a lanowl that was working, read the alert: when the router
is unreachable too, lanowl says it has probably lost the network itself. Check its own cable,
Wi-Fi or VM network first.

## The dashboard does not open

- Is it on? `web.enabled: true`, and the port: `web.port`, or `LANOWL_WEB_PORT` in
  `docker/.env`. Without either, the port is 8088.
- Is lanowl running? `docker compose -f docker/compose.yaml ps`, then the log.
- **"use the address, not a name" (HTTP 421):** you opened it by a host name. Open it by IP
  address, or list the name in `web.allowed_hosts`.
- **"Set a password first":** the dashboard has no password yet. Send `/password` to the bot,
  or set `web.password_hash` ([Logging in](../using/dashboard.md#logging-in)).
- **You forgot the password:** `/password` on Telegram sets a new one. If yours is in
  `config.yaml`, make a new hash with `lanowl --hash-password` and restart lanowl.
- **"Login locked":** five wrong passwords in a row. Wait 15 minutes, or set a new password
  with `/password`, which lifts the lock.

## Nothing arrives on Telegram

- `lanowl --check` shows whether the token is found and `telegram.chat_id` is set.
- Did you send `/start` to the bot from your account? A bot cannot write to a chat that never
  started it.
- "another client is polling this bot" in the log: something else reads this bot's updates
  (a browser tab on `getUpdates`, another lanowl). Questions and buttons need lanowl to be the
  only reader; alerts still go out.
- No internet: alerts wait in the outbox and arrive, marked delayed, when it is back.

## The router refuses the login

The log says "refused the login 'lanowl' (HTTP 401)" once, with what to check: the password in
`secrets.yaml`, and on the router the user's `address=`, which must include lanowl's host.
lanowl does not try again for 15 minutes, or until `secrets.yaml` changes, because every
refused try is a "login failure" line in the router's log.

## The owl does not answer

- The Services list on the Devices tab has a row for the model server: "not answering",
  or "qwen3:30b not installed" (`ollama pull` it).
- Ollama on another machine must listen on the network (`OLLAMA_HOST=0.0.0.0`), and
  `model.url` or `LANOWL_MODEL_URL` must point at it.
- Answers that stop half-way, or audits "abandoned after 900s": a slow model for the timeouts
  (`model.request_timeout_s`, `cadence.llm_max_wall_s`). A log line saying the context peak was
  within 10% of `num_ctx` means the model was reading a truncated prompt: raise `num_ctx`.
- Is it switched off? `/model` says.

## A device flaps

Weak Wi-Fi, usually. Give its check more patience instead of removing it:
`{type: icmp, timeout_ms: 2500, count: 3}`, or a higher `debounce_fails` on the device. A
device that sleeps by design wants `expect_offline`. One you switched off wants `/pause`.

## ssh problems

- **"others can read id_ed25519":** `chmod 600 config/id_ed25519`.
- **A device's host key changed** (after a reinstall): delete its line from
  `known_hosts_devices` in the state volume. One that makes a new key at every boot goes in
  `access.hostkey_any`.
- **"needs a login with lanowl's ssh key":** the feature needs `key: true` on that login, and
  `config/id_ed25519.pub` in the device's `authorized_keys`.

## The sandboxed shell is off

The owl's shell is offered only while its walls are proven. The log and the Ask tab's "The
model's shell" say which test failed: the LAN handshake to `shell.canary_lan` (pick a service
that always answers, such as a server's ssh port), or something the sandbox reached that it
must not. Is the sandbox running? `docker compose -f docker/compose.yaml --profile shell up -d`.

## Times are wrong

Set `TZ` in `docker/.env`. Sunrise and sunset, the morning jobs, the weekly review and the
router's log timestamps all read local time.

## Still stuck

Ask the owl: it can read lanowl's own log and records. Or open an issue on GitHub with the
`--check` output and the relevant log lines (they never contain a password or a token).
