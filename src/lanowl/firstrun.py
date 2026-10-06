"""A new install with nothing in its config folder: lanowl writes its own files.

`docker compose up -d` on a fresh checkout mounts the repository's empty `config` folder,
read-write. When config.yaml is not there, lanowl writes what a start needs into that folder,
and nothing that is only an example:

  config.yaml     the dashboard on, Telegram's questions on, the internet watched, new devices
                  told, the week in review, the log file: what the example switches on,
                  without the example's addresses
  inventory.yaml  no devices: the first-run setup on the dashboard picks them
  secrets.yaml    no logins and no tokens yet; where lanowl's ssh key is
  id_ed25519      lanowl's own ssh key, and its .pub — made once, never shown

Each file is mode 600 and belongs to whoever owns the folder (the one who cloned the repo), so
it can still be edited by hand. A file that is there is never touched, and an install that has
config.yaml gets nothing at all. A folder lanowl cannot write (a compose file that mounts it
read-only) gets nothing either: the start then stops on the missing file, as it always did.

Two values a start finds for itself when nothing sets them:
  - observer.host_ip: the address this machine uses to reach the internet (a UDP socket is
    pointed at a documentation address to read it; no packet is sent);
  - the time zone: `timezone:` in config.yaml, unless TZ in the environment says otherwise.
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from typing import Optional

log = logging.getLogger("lanowl.firstrun")

KEY = "id_ed25519"
# TZ that lanowl set itself from config.yaml (not the environment): it survives Restart to
# apply (os.execv keeps the environment), and must not then pass for the environment's own
TZ_MARK = "LANOWL_TZ_FROM"

CONFIG = """\
# lanowl's settings. lanowl wrote this file at its first start, with only what a start needs:
# change it in Settings on the dashboard (the gear), or here. Every key, and what it does:
# config.example.yaml. Secrets never go in this file: they are in secrets.yaml, beside it.

web:
  enabled: true

telegram:
  chat:
    enabled: true                   # answer questions and /commands

wan:
  targets: ["8.8.8.8", "208.67.222.222", "1.0.0.1"]   # neutral public addresses: "is there internet?"

discovery:
  notify_new_devices: true          # a device nobody has seen before: one line on Telegram

weekly: {enabled: true, day: "sun", time: "10:00"}

logging:
  file: "lanowl.log"                # in lanowl's state: docker exec lanowl tail /state/lanowl.log
"""

INVENTORY = """\
# The devices lanowl watches. The first-run setup on the dashboard fills this list from your
# router's DHCP list; change them in Settings → Devices, or here. Every field, and what it
# does: inventory.example.yaml.

devices: []
"""

SECRETS = """\
# lanowl's secrets: device logins, tokens, its own ssh key. The dashboard sets them (the
# first-run setup, Settings → Secrets) and never shows one again; or edit this file by hand.
# Keep it mode 600. The format: secrets.example.yaml.

logins:
tokens:
ssh_key: "{key}"{pad}# lanowl's own ssh key, made at its first start
"""

created: list = []          # what the last prepare() wrote, for the start's log


def _owner(folder: str) -> tuple:
    try:
        st = os.stat(folder)
        return st.st_uid, st.st_gid
    except OSError:
        return -1, -1


def _give(path: str, uid: int, gid: int):
    if uid < 0:
        return
    try:
        os.chown(path, uid, gid)
    except OSError:                  # not root, or a file system without owners: fine
        pass


def _new(path: str, text: str, uid: int, gid: int) -> bool:
    """Write a file that is not there; never one that is (O_EXCL)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)            # whatever the umask said
    _give(path, uid, gid)
    return True


def make_key(path: str, uid: int = -1, gid: int = -1) -> str:
    """lanowl's own ssh key at `path` (and `path`.pub); "" when made, else why not."""
    if os.path.exists(path):
        return ""
    try:
        r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lanowl", "-f", path],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return f"ssh-keygen did not run: {e}"
    if r.returncode != 0:
        return f"ssh-keygen failed: {(r.stderr or r.stdout).strip()[:200]}"
    os.chmod(path, 0o600)
    _give(path, uid, gid)
    if os.path.exists(path + ".pub"):
        os.chmod(path + ".pub", 0o644)
        _give(path + ".pub", uid, gid)
    return ""


def prepare(cfg_path: str, inv_path: str, secrets_path: Optional[str] = None) -> list:
    """A fresh install (no config.yaml): its files, written. The names written; [] when
    config.yaml is there, or the folder cannot be written."""
    global created
    created = []
    cfg_path = os.path.abspath(cfg_path)
    if os.path.exists(cfg_path):
        return created
    folder = os.path.dirname(cfg_path)
    if not os.path.isdir(folder) or not os.access(folder, os.W_OK):
        return created
    uid, gid = _owner(folder)
    key = os.path.join(folder, KEY)
    secrets_path = os.path.abspath(secrets_path or os.path.join(folder, "secrets.yaml"))
    texts = [(cfg_path, CONFIG), (os.path.abspath(inv_path), INVENTORY),
             (secrets_path, SECRETS.format(key=key, pad=" " * max(1, 28 - len(key))))]
    for path, text in texts:
        if os.path.isdir(os.path.dirname(path)) and _new(path, text, uid, gid):
            created.append(os.path.basename(path))
    if os.path.basename(secrets_path) in created:
        why = make_key(key, uid, gid)
        if why:
            created.append(f"no ssh key ({why})")
        else:
            created.append(KEY)
    return created


# --- what a start finds for itself -------------------------------------------------------------
def find_host_ip() -> str:
    """The address this machine reaches the internet from: the source address the kernel
    picks for a public destination. connect() on a UDP socket sends nothing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))          # TEST-NET-1: routed by the default route, never answered
        ip = s.getsockname()[0]
        return "" if ip.startswith(("0.", "127.")) else ip
    except OSError:
        return ""
    finally:
        s.close()


def fill_host_ip(cfg: dict) -> str:
    """observer.host_ip when nothing set it (config.yaml, LANOWL_HOST_IP): found, and marked
    as found (Settings says so)."""
    ob = cfg.get("observer") if isinstance(cfg.get("observer"), dict) else {}
    if str(ob.get("host_ip") or "").strip():
        return ""
    ip = find_host_ip()
    if ip:
        cfg["observer"] = {**ob, "host_ip": ip}
        cfg["_host_ip_found"] = ip
    return ip


def env_tz() -> str:
    """TZ as the environment set it; "" when lanowl set it itself, from config.yaml."""
    return "" if os.environ.get(TZ_MARK) == "config" else os.environ.get("TZ", "").strip()


def valid_tz(name: str) -> bool:
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(name)
        return True
    except Exception:
        return False


def apply_timezone(cfg: dict) -> str:
    """config.yaml's `timezone:` for this process (and what it starts), unless TZ in the
    environment wins. What it did: "env", "config", "" (none), or "bad"."""
    if env_tz():
        return "env"
    want = str(cfg.get("timezone") or "").strip()
    if want and valid_tz(want):
        os.environ["TZ"], os.environ[TZ_MARK] = want, "config"
        out = "config"
    else:
        if os.environ.get(TZ_MARK) == "config":       # a restart that took it out of the file
            os.environ.pop("TZ", None)
            os.environ.pop(TZ_MARK, None)
        out = "bad" if want else ""
    try:
        time.tzset()
    except AttributeError:          # not on Windows
        pass
    return out
