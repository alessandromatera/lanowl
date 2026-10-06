"""Every secret lanowl holds, in one file: secrets.yaml.

The owner's device logins, the tokens of the services lanowl talks to, the logins it reads
them with, and where its own ssh key is — outside the config and the inventory, so those two
can be shared or versioned without a secret in them. Mount it read-only (mode 600). It is read
again whenever it changes, so an updated password or token needs no restart.

    logins:                       # named logins; several devices may share one
      routers:  {user: admin, password: "..."}
      server:   {user: root, key: true}                 # lanowl's own ssh key
      nas:      {user: admin, key: true, password: "..."}   # the key logs in, sudo takes the password
      router-read: {user: lanowl, password: "..."}      # the router's read-only user (mikrotik.credentials)
    devices:                      # address -> login name
      192.168.10.32: routers
    tokens:
      telegram: "..."
      homeassistant: "..."
    ssh_key: /config/id_ed25519   # lanowl's own key, for every `key: true` login

A device in the inventory may name its login itself (`credentials: routers`); that wins over
the `devices:` map.

lanowl's own secrets (a token, the router's or the broker's login) may come from the
environment instead; the first found wins: the variable (LANOWL_TG_TOKEN), then the file its
_FILE twin names (LANOWL_TG_TOKEN_FILE: how Docker secrets arrive, /run/secrets/<name>), then
secrets.yaml. Device logins come from the file only.

Where a password may go, and where it never goes:
  - ssh reads it from SSH_ASKPASS: a 0700 script that prints an environment variable set for
    that one ssh process. Never argv (anyone on the box can read argv), never a log line.
  - sudo reads it on stdin (`sudo -S`), inside the encrypted channel.
  - HTTP sends it in the body of the device's own login call (Reolink), and nowhere else.
  - never into a proposal, a message, the dashboard, or the model's context: callers get
    back (rc, stdout, stderr) and this module scrubs the password out of both streams.

One password prompt per connection (NumberOfPasswordPrompts=1): some systems (ESXi) lock an
account after a few failures, and ssh would otherwise try three times per connection.
lanowl's own key is never offered to these devices (PubkeyAuthentication=no): a refused key
counts as a failure too.

Host keys: trusted on first use, in their own known_hosts on the state volume. A device that
makes a new host key at every boot (/var/lib on tmpfs) is listed in `access.hostkey_any`.
Old devices (RouterOS 6, dropbear on OpenWrt) offer only ssh-rsa host keys and sha1 key
exchange, so those are ALLOWED as extras (+), never preferred over modern ones.
"""
from __future__ import annotations

import contextlib
import logging
import os
import stat
import tempfile
from typing import NamedTuple, Optional

from .checks import _exec

log = logging.getLogger("lanowl.access")

LEGACY = ["-o", "HostKeyAlgorithms=+ssh-rsa",
          "-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"]


class Login(NamedTuple):
    user: str
    password: str
    key: str = ""        # "": no key; "default": lanowl's own (`ssh_key`); or a path

    def __repr__(self) -> str:          # a log line or a traceback must never print it
        return f"Login(user={self.user!r}, password=***, key={self.key!r})"


def parse(text: str) -> dict:
    """{"logins": {name: Login}, "devices": {address: login name}, "tokens": {service: token},
    "ssh_key": path} from secrets.yaml's text. A login with neither a password nor a key is
    dropped: it could log in to nothing. So is a blank token."""
    import yaml
    raw = yaml.safe_load(text) or {}
    if not isinstance(raw, dict):
        raise ValueError("secrets.yaml must be a mapping")
    logins = {}
    for name, v in (raw.get("logins") or {}).items():
        if not isinstance(v, dict):
            continue
        key = v.get("key")
        key = "default" if key is True else str(key or "") if key is not False else ""
        if v.get("password") or key:
            logins[str(name)] = Login(str(v.get("user") or ""), str(v.get("password") or ""), key)
    devices = {str(ip): str(n) for ip, n in (raw.get("devices") or {}).items() if n}
    tokens = {str(k): str(v).strip() for k, v in (raw.get("tokens") or {}).items()
              if v is not None and str(v).strip()}
    return {"logins": logins, "devices": devices, "tokens": tokens,
            "ssh_key": str(raw.get("ssh_key") or "")}


def _empty() -> dict:
    return {"logins": {}, "devices": {}, "tokens": {}, "ssh_key": ""}


class SecretsFile:
    """secrets.yaml, read again whenever it changes. One per path (`shared`): the watchers,
    the alerts and the actions all read the same file, and see an edit at the same moment."""

    def __init__(self, path: str):
        self.path = path
        self._data: dict = _empty()
        self._mtime = None
        self.error = ""                     # why it could not be read (`lanowl --check`)

    def data(self) -> dict:
        try:
            m = os.stat(self.path).st_mtime
        except OSError:
            if self._mtime is not None:
                log.warning("access: %s is gone — no logins, no tokens", self.path)
            self._data, self._mtime, self.error = _empty(), None, ""
            return self._data
        if m == self._mtime:
            return self._data
        self.error = ""
        try:
            with open(self.path, encoding="utf-8") as f:
                self._data = parse(f.read())
            nd = len(self._data["devices"])
            log.info("access: %d login(s), %d token(s)%s read from %s",
                     len(self._data["logins"]), len(self._data["tokens"]),
                     f", {nd} device(s) by address" if nd else "", self.path)
        except (OSError, ValueError) as e:
            self.error = f"unreadable: {e}"
            log.warning("access: %s %s", self.path, self.error)
            self._data = _empty()
        except Exception as e:              # a YAML error must not take the monitor down
            self.error = f"not valid YAML: {type(e).__name__}"
            log.warning("access: %s is %s", self.path, self.error)
            self._data = _empty()
        self._mtime = m                     # a broken file is not re-read until it changes
        return self._data


_FILES: dict = {}


class _Planned(SecretsFile):
    """A secrets.yaml text that is not a file yet: what `--check`'s rules read while Settings
    weighs a save (overlay)."""

    def __init__(self, path: str, text: str):
        super().__init__(path)
        try:
            self._data = parse(text)
        except Exception as e:
            self._data, self.error = _empty(), f"not valid YAML: {type(e).__name__}"

    def data(self) -> dict:
        return self._data


@contextlib.contextmanager
def overlay(cfg: dict, text: str):
    """`cfg` reads `text` as its secrets.yaml for the duration (cfg is a copy the caller made)."""
    real = secrets_path(cfg)
    fake = real + "#planned"
    _FILES[fake] = _Planned(fake, text)
    ac = cfg.get("access") if isinstance(cfg.get("access"), dict) else {}
    cfg["access"] = {**ac, "secrets_file": fake}
    try:
        yield
    finally:
        _FILES.pop(fake, None)
        cfg["access"] = {**ac, "secrets_file": real}


def reread(cfg: dict):
    """secrets.yaml was just written: read it again at the next use, whatever its mtime says."""
    f = _FILES.get(secrets_path(cfg))
    if f is not None:
        f._mtime = None


def secrets_path(cfg: dict) -> str:
    """`access.secrets_file`; load_config puts it beside config.yaml when it is not set."""
    return str(((cfg or {}).get("access") or {}).get("secrets_file") or "secrets.yaml")


def shared(cfg: dict) -> SecretsFile:
    p = secrets_path(cfg)
    if p not in _FILES:
        _FILES[p] = SecretsFile(p)
    return _FILES[p]


# --- lanowl's own secrets -----------------------------------------------------------------
# a token's name in secrets.yaml -> its environment variable
TOKENS = {"telegram": "LANOWL_TG_TOKEN", "homeassistant": "LANOWL_HA_TOKEN"}
# a config.yaml section that logs in -> (user variable, password variable, login name when the
# section names none in `credentials:`)
SERVICES = {"mikrotik": ("LANOWL_MIKROTIK_USER", "LANOWL_MIKROTIK_PASS", "router-read"),
            "mqtt": ("LANOWL_MQTT_USER", "LANOWL_MQTT_PASS", "mqtt")}
KEY_ENV = "LANOWL_SSH_KEY"          # lanowl's own ssh key file, over secrets.yaml's `ssh_key`
_warned: set = set()


def _from_env(var: str) -> tuple:
    """(value, where) from the environment: the variable, else the file its _FILE twin names.
    ("", "") = neither."""
    v = os.environ.get(var, "").strip()
    if v:
        return v, var
    fp = os.environ.get(var + "_FILE", "")
    if fp:
        try:
            with open(fp, encoding="utf-8") as f:
                v = f.read().strip()
            if v:
                return v, var + "_FILE"
        except OSError as e:
            if fp not in _warned:           # read on every use: say it once
                _warned.add(fp)
                log.warning("access: %s_FILE names %s, unreadable: %s", var, fp, e.strerror)
    return "", ""


def token_from(cfg: dict, name: str) -> tuple:
    """(token, where) of a service in TOKENS; ("", "") = none anywhere."""
    v, where = _from_env(TOKENS[name])
    if v:
        return v, where
    v = shared(cfg).data()["tokens"].get(name, "")
    return (v, "secrets.yaml") if v else ("", "")


def token(cfg: dict, name: str) -> str:
    return token_from(cfg, name)[0]


def service_login_name(cfg: dict, section: str) -> str:
    return str(((cfg or {}).get(section) or {}).get("credentials") or SERVICES[section][2])


def service_login_from(cfg: dict, section: str) -> tuple:
    """(Login, where) lanowl itself logs in to a service with: `mikrotik`, the router's
    read-only user for its API and REST; `mqtt`, the broker. The login the section names in
    `credentials:`; the user and the password may each come from the environment instead.
    Login("", "") = none."""
    uvar, pvar, _ = SERVICES[section]
    name = service_login_name(cfg, section)
    lg = shared(cfg).data()["logins"].get(name)
    (u, uw), (p, pw) = _from_env(uvar), _from_env(pvar)
    user, pas = u or (lg.user if lg else ""), p or (lg.password if lg else "")
    mine = f"secrets.yaml login {name}"
    where = list(dict.fromkeys(w for w in (uw or (mine if user else ""), pw or (mine if pas else ""))
                               if w))
    return Login(user, pas), " + ".join(where)


def service_login(cfg: dict, section: str) -> Login:
    return service_login_from(cfg, section)[0]


def ssh_key(cfg: dict) -> str:
    """lanowl's own ssh key file: LANOWL_SSH_KEY, else secrets.yaml's `ssh_key`. "" = ssh's
    own default (~/.ssh/id_*)."""
    return os.environ.get(KEY_ENV, "").strip() or shared(cfg).data()["ssh_key"]


class Access:
    def __init__(self, cfg: dict, inventory=None):
        c = cfg.get("access") or {}
        self.file = shared(cfg)
        self.path = self.file.path
        self.hostkey_any = {str(x) for x in (c.get("hostkey_any") or [])}
        self.known_hosts = str(c.get("known_hosts") or "known_hosts_devices")
        self.inventory = inventory
        self._askpass: Optional[str] = None

    @property
    def _data(self) -> dict:
        return self.file.data()

    def login_name(self, ip: str) -> str:
        d = self.inventory.get(ip) if self.inventory is not None else None
        named = str((d.attrs.get("credentials") if d is not None else "") or "")
        return named or self._data["devices"].get(ip, "")

    def login(self, ip: str) -> Optional[Login]:
        return self._data["logins"].get(self.login_name(ip))

    def has(self, ip: str) -> bool:
        """A login with a password: what ssh-with-a-password, sudo and HTTP logins need."""
        lg = self.login(ip)
        return lg is not None and bool(lg.password)

    def by_key(self, ip: str) -> bool:
        """Its login is lanowl's ssh key (kinds.py routes it through the key's shared
        connection, hostlog.py)."""
        lg = self.login(ip)
        return lg is not None and bool(lg.key)

    # --- ssh with a password ---------------------------------------------------
    def _askpass_path(self) -> str:
        if self._askpass is None or not os.path.exists(self._askpass):
            d = tempfile.mkdtemp(prefix="lanowl-askpass-")
            p = os.path.join(d, "askpass")
            with open(p, "w") as f:
                f.write('#!/bin/sh\nprintf \'%s\\n\' "$LANOWL_ASKPASS_PW"\n')
            os.chmod(p, stat.S_IRWXU)
            self._askpass = p
        return self._askpass

    def ssh_argv(self, ip: str, user: str, remote: str, tty: bool = False) -> list:
        any_key = ip in self.hostkey_any
        return (["ssh", "-T" if not tty else "-tt",
                 "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1",
                 "-o", "PubkeyAuthentication=no",
                 "-o", "PreferredAuthentications=keyboard-interactive,password",
                 "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5",
                 "-o", "ServerAliveCountMax=3", "-o", "LogLevel=ERROR",
                 "-o", "StrictHostKeyChecking=" + ("no" if any_key else "accept-new"),
                 "-o", "UserKnownHostsFile=" + ("/dev/null" if any_key else self.known_hosts)]
                + LEGACY + ["-l", user, ip, "--", remote])

    def _env(self, lg: Login) -> dict:
        return dict(os.environ, SSH_ASKPASS=self._askpass_path(), SSH_ASKPASS_REQUIRE="force",
                    DISPLAY=os.environ.get("DISPLAY", ":0"), LANOWL_ASKPASS_PW=lg.password)

    def command(self, ip: str, remote: str, user_suffix: str = "") -> Optional[tuple]:
        """(argv, env, login) of an ssh command NOT run yet — for streaming its output into
        another process (backups.py). None = no login for it."""
        lg = self.login(ip)
        if lg is None or not lg.user or not lg.password:
            return None
        return self.ssh_argv(ip, lg.user + user_suffix, remote), self._env(lg), lg

    async def scp_get(self, ip: str, remote_path: str, local_path: str,
                      timeout_s: float = 60) -> tuple:
        """Copy one file from the device (scp over the SFTP protocol, the password through
        SSH_ASKPASS). (rc, err)."""
        lg = self.login(ip)
        if lg is None or not lg.user:
            return None, f"no login for {ip} in secrets.yaml"
        if not lg.password:
            return None, f"{ip}'s login is lanowl's ssh key, and this needs a password"
        any_key = ip in self.hostkey_any
        argv = (["scp", "-q", "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1",
                 "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=8",
                 "-o", "StrictHostKeyChecking=" + ("no" if any_key else "accept-new"),
                 "-o", "UserKnownHostsFile=" + ("/dev/null" if any_key else self.known_hosts)]
                + LEGACY + [f"{lg.user}@{ip}:{remote_path}", local_path])
        rc, _, err = await _exec(argv, timeout_s, env=self._env(lg))
        return rc, self.scrub(err, lg)

    async def ssh(self, ip: str, remote: str, stdin: Optional[bytes] = None,
                  timeout_s: float = 20, user_suffix: str = "", tty: bool = False,
                  sudo_pw: bool = False, raw: bool = False) -> tuple:
        """(rc, out, err) of `remote` on `ip`, logged in with its login from secrets.yaml;
        rc None = did not run (no login, ssh missing, timed out). `sudo_pw`: the password is
        written on stdin first, for a `sudo -S` in `remote`. `user_suffix`: RouterOS login
        flags."""
        lg = self.login(ip)
        if lg is None:
            return None, "", f"no login for {ip} in secrets.yaml"
        if not lg.user:
            return None, "", f"secrets.yaml has a password but no user for {ip}"
        if not lg.password:
            return None, "", f"{ip}'s login is lanowl's ssh key, and this needs a password"
        if sudo_pw:
            stdin = lg.password.encode() + b"\n" + (stdin or b"")
        rc, out, err = await _exec(self.ssh_argv(ip, lg.user + user_suffix, remote, tty),
                                   timeout_s, stdin=stdin, env=self._env(lg))
        # raw: a backup's content (a RouterOS export) is kept byte for byte — it is written
        # to the backup disk, never logged or shown
        return rc, out if raw else self.scrub(out, lg), self.scrub(err, lg)

    @staticmethod
    def scrub(text: str, lg: Login) -> str:
        """A device may echo what it was sent (a tty does): the password never comes back out."""
        return text.replace(lg.password, "***") if lg.password and text else text


# --- `lanowl --check` ------------------------------------------------------------------------
def _public_key(path: str) -> str:
    """The public half of a key file: its .pub, else derived (no passphrase asked)."""
    try:
        with open(path + ".pub", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        pass
    import subprocess
    try:
        r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", path], capture_output=True,
                           text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _open_to_others(path: str) -> bool:
    try:
        return bool(stat.S_IMODE(os.stat(path).st_mode) & 0o077)
    except OSError:
        return False


def report(cfg: dict, inv=None) -> tuple:
    """(text, problems): where every secret lanowl uses comes from, and what is missing —
    never a value. ✓ found · ○ not used · ✗ missing or wrong."""
    from .model import router_host
    f = shared(cfg)
    d = f.data()
    lines, bad = [], 0

    def row(mark: str, what: str, text: str):
        nonlocal bad
        bad += mark == "✗"
        lines.append(f"  {mark} {what:<15} {text}")

    if os.path.exists(f.path):
        mode = stat.S_IMODE(os.stat(f.path).st_mode)
        lines.append(f"Secrets: {f.path} · {len(d['logins'])} login(s), {len(d['tokens'])} "
                     f"token(s), mode {mode:o}")
    else:
        lines.append(f"Secrets: {f.path} · not found")
    if f.error:
        row("✗", "secrets.yaml", f.error)
    if _open_to_others(f.path) and not f.path.startswith("/run/secrets/"):
        row("✗", "secrets.yaml", f"others can read it: chmod 600 {f.path}")

    for name, what, need, why in (
            ("telegram", "Telegram token", (cfg.get("telegram") or {}).get("chat_id"), "telegram.chat_id"),
            ("homeassistant", "Home Assistant", (cfg.get("access") or {}).get("ha_url"), "access.ha_url")):
        _, where = token_from(cfg, name)
        if where:
            row("✓", what, f"from {where}")
        elif need:
            row("✗", what, f"{why} is set and there is no token: `tokens: {{{name}: ...}}` in "
                           f"secrets.yaml, or {TOKENS[name]}")
        else:
            row("○", what, f"not used: no {why}")

    lg, where = service_login_from(cfg, "mikrotik")
    name, host = service_login_name(cfg, "mikrotik"), router_host(cfg)
    if lg.user and lg.password:
        row("✓", "router login", f"{lg.user}, from {where}")
    elif host:
        row("✗", "router login", f"the router ({host}) is read with the login {name!r}: add it to "
                                 "secrets.yaml (a read-only user), or blank mikrotik.dhcp_source "
                                 "if the router is not a MikroTik")
    else:
        row("○", "router login", "not used: no router in mikrotik.dhcp_source")

    lg, where = service_login_from(cfg, "mqtt")
    named = (cfg.get("mqtt") or {}).get("credentials")
    if not (cfg.get("mqtt") or {}).get("host"):
        row("○", "MQTT login", "not used: no mqtt.host")
    elif lg.user:
        row("✓", "MQTT login", f"{lg.user}, from {where}")
    elif named:
        row("✗", "MQTT login", f"mqtt.credentials names {named!r}, which secrets.yaml does not have")
    else:
        row("○", "MQTT login", "none: the broker is used without one")

    key = ssh_key(cfg)
    src = KEY_ENV if os.environ.get(KEY_ENV, "").strip() else "secrets.yaml"
    wants = (any(x.key == "default" for x in d["logins"].values())
             or (cfg.get("hostlog") or {}).get("enabled"))
    if key and not os.path.exists(key):
        row("✗", "ssh key", f"{key} (from {src}) does not exist")
    elif key and _open_to_others(key):
        row("✗", "ssh key", f"others can read {key}, and ssh refuses such a key: chmod 600 {key}")
    elif key:
        row("✓", "ssh key", f"{key}, from {src}")
        pub = _public_key(key)
        if pub:
            lines.append(f"{'':20}its public half, for each key login's authorized_keys:")
            lines.append(f"{'':20}{pub}")
    elif wants:
        import glob
        own = sorted(x for x in glob.glob(os.path.expanduser("~/.ssh/id_*")) if not x.endswith(".pub"))
        if own:
            row("✓", "ssh key", f"ssh's own {own[0]} (no ssh_key in secrets.yaml)")
        else:
            row("✗", "ssh key", "a login uses lanowl's key (`key: true`) and there is none: "
                                "`ssh-keygen -t ed25519 -N '' -f config/id_ed25519`, then "
                                "`ssh_key: /config/id_ed25519` in secrets.yaml")
    else:
        row("○", "ssh key", "not used: no login with `key: true`")

    for n, x in d["logins"].items():
        if x.key not in ("", "default") and not os.path.exists(x.key):
            row("✗", "ssh key", f"login {n!r}: its key {x.key} does not exist")
    have = d["logins"]
    for dev in (inv.devices if inv is not None else []):
        n = str(dev.attrs.get("credentials") or "")
        if n and n not in have:
            row("✗", "login", f"{dev.name} ({dev.ip}) names {n!r}, which secrets.yaml does not "
                              "have (or has with neither a password nor a key)")
    for ip, n in d["devices"].items():
        if n not in have:
            row("✗", "login", f"devices: {ip} names {n!r}, which secrets.yaml does not have")
    return "\n".join(lines), bad
