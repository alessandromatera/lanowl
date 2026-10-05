# The security model

A tool that watches a network gets close to everything on it: it holds logins to your
routers and servers, and it runs a language model that reads text strangers wrote (a device's
DHCP name, a failed login's user name, a log line). lanowl is built so that this closeness
cannot turn into damage on its own. This page is how.

## The model is not trusted

The owl is useful, and treated as if anything it reads could steer it.

- **It can look, not touch.** Its tools are read-only. An address that is not in your
  inventory is refused, whatever the model asks.
- **It never writes a command.** A change is an action from a fixed catalog, which the model
  fills with a device and a reason. lanowl builds the command from validated data: nmap runs
  without a shell, a service restart takes a unit from that device's allow-list, a Shelly
  reboot is one request to its own endpoint. The model's words are only ever shown.
- **Every change waits for a person.** A proposal is checked against the rules and the device
  itself before you see it, and again when you approve. Approval is a Telegram button from an
  allowed user, or the dashboard with your PIN.
- **It never sees a password.** Logins reach ssh through `SSH_ASKPASS` and sudo through
  standard input, and command output is scrubbed of them.
- **Its shell is a sandbox.** A separate container with no key, no config and no state of
  lanowl's, reaching the LAN only for handshakes and scans and never lanowl's dashboard. Its
  walls are proven from inside before the tool is offered, and every morning. The hourly
  audit's sandbox has no internet and no DNS at all.
- **Its memory is written in your conversations only.** Never by the audit or a log check,
  the runs that read strangers' text with nobody watching, and every note it saves is printed
  under its answer by lanowl itself.
- **Detection does not depend on it.** What is down, what pages and what is told are decided by
  code. A model that says nonsense can make a bad diagnosis; it cannot hide an outage.

## Secrets

- One file, `secrets.yaml`, mode 600, mounted read-only. `config.yaml` and `inventory.yaml`
  hold none and can be shared.
- `lanowl --check` reports where each secret comes from, never its value, and refuses a file
  or a key that others can read.
- The router is read with a user whose group can only read; lanowl reports any change to that
  group that grants more than you gave it on purpose.

## The dashboard

The dashboard is closed until you log in, and it relies on these:

- One password, kept as a scrypt hash: in `config.yaml`, or set with `/password` on Telegram,
  whose message is deleted. Without one the page shows only how to set one.
- A login is a random token in an HttpOnly cookie, of which lanowl keeps only a hash. It
  lasts 30 days after the last visit. A new password, or Log out everywhere, ends every one.
- Five wrong passwords lock the login for 15 minutes and tell you on Telegram, with the
  address the last try came from.
- It accepts only JSON for anything that does something, so another web page cannot submit a
  form to it (a cross-origin JSON request needs a permission it never grants).
- It answers only requests that reached it by IP address or by a name you listed, which
  defeats DNS rebinding.
- It cannot be framed by another site.
- Approving anything needs the PIN; five wrong ones lock dashboard approvals and tell you on
  Telegram.
- Pausing a device, the one thing it changes without the PIN, is announced on Telegram, so
  nobody on the LAN can quietly stop lanowl watching the alarm.

## Telegram

The bot answers only the chats you allow, ignores everyone else (logged, never answered), and
acts on a button only when it comes from an allowed person in an allowed chat.

## What is not protected

- **Backups are not encrypted.** They hold your network's passwords and keys. Keep the
  store's path as private as `secrets.yaml`.
- **The dashboard's password over plain HTTP.** It crosses your LAN unencrypted when you log
  in. Put lanowl behind a reverse proxy with HTTPS if anyone you do not trust can watch your
  network's traffic.
- **A host that is already compromised.** If someone is root on lanowl's own machine, they
  have its secrets.
