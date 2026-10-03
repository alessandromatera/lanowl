"""Logging in to the network's devices with the owner's own logins, kept in secrets.yaml.

One file holds every login, outside the config and the inventory, so those two can be shared
or versioned without a secret in them. Mount it read-only (mode 600). It is read again
whenever it changes, so an updated password needs no restart.

    logins:                       # named logins; several devices may share one
      routers:  {user: admin, password: "..."}
      server:   {user: root, key: true}                 # lanowl's own ssh key
      nas:      {user: admin, key: true, password: "..."}   # the key logs in, sudo takes the password
    devices:                      # address -> login name
      192.168.10.32: routers

A device in the inventory may name its login itself (`credentials: routers`); that wins over
the `devices:` map.

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
    key: str = ""        # "": no key; "default": lanowl's own (hostlog.ssh.identity); or a path

    def __repr__(self) -> str:          # a log line or a traceback must never print it
        return f"Login(user={self.user!r}, password=***, key={self.key!r})"


def parse(text: str) -> dict:
    """{"logins": {name: Login}, "devices": {address: login name}} from secrets.yaml's text.
    A login with neither a password nor a key is dropped: it could log in to nothing."""
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
    return {"logins": logins, "devices": devices}


class Access:
    def __init__(self, cfg: dict, inventory=None):
        c = cfg.get("access") or {}
        self.path = str(c.get("secrets_file") or "secrets.yaml")
        self.hostkey_any = {str(x) for x in (c.get("hostkey_any") or [])}
        self.known_hosts = str(c.get("known_hosts") or "known_hosts_devices")
        self.inventory = inventory
        self._data: dict = {"logins": {}, "devices": {}}
        self._mtime = None
        self._askpass: Optional[str] = None

    # --- the file -------------------------------------------------------------
    def _load(self):
        try:
            m = os.stat(self.path).st_mtime
        except OSError:
            if self._mtime is not None:
                log.warning("access: %s is gone — no device logins", self.path)
            self._data, self._mtime = {"logins": {}, "devices": {}}, None
            return
        if m == self._mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                self._data = parse(f.read())
            self._mtime = m
            log.info("access: %d login(s) for %d device(s) read from %s",
                     len(self._data["logins"]), len(self._data["devices"]), self.path)
        except (OSError, ValueError) as e:
            log.warning("access: %s unreadable: %s", self.path, e)
            self._data = {"logins": {}, "devices": {}}
        except Exception as e:              # a YAML error must not take the monitor down
            log.warning("access: %s is not valid YAML: %s", self.path, type(e).__name__)
            self._data = {"logins": {}, "devices": {}}

    def login_name(self, ip: str) -> str:
        d = self.inventory.get(ip) if self.inventory is not None else None
        named = str((d.attrs.get("credentials") if d is not None else "") or "")
        return named or self._data["devices"].get(ip, "")

    def login(self, ip: str) -> Optional[Login]:
        self._load()
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
