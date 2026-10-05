"""The dashboard's login: one password, and each browser remembered for 30 days.

The dashboard shows the whole network and can ask the model anything, so it is closed until
it has a password, on by default. Where the password comes from, like the actions PIN:

  - config.yaml's `web.password_hash` wins (`lanowl --hash-password` makes one);
  - otherwise the one set with /password on Telegram: the message is deleted at once and only
    the hash is kept, in the `login` record;
  - with neither, the page says how to set one and shows nothing else.

`web.login: false` switches it off, for a page that already sits behind a login of its own
(a reverse proxy with Authelia or Authentik, Tailscale). --check says so while it is off.

A login is a random token in an HttpOnly cookie; only its SHA-256 is kept, in the record, so
a restart or an upgrade logs nobody out. A browser stays in for SESSION_DAYS after its last
visit. A new password, from either place, logs every browser out.

Five wrong passwords in a row lock the login for 15 minutes, for every browser (the PIN's
rule), and Telegram hears it once, with the address the last try came from. /password lifts
the lock. A good login, a log out and a session that runs out send nothing.

The hash is scrypt from Python's standard library: `scrypt$n$r$p$salt$hash`, base64.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Optional

log = logging.getLogger("lanowl.login")

RECORD = "login"
COOKIE = "lanowl_session"
SESSION_DAYS = 30
SESSION_S = SESSION_DAYS * 86400
MIN_LEN = 8
MAX_LEN = 256
MAX_FAILS = 5
LOCK_S = 15 * 60
MAX_SESSIONS = 50          # browsers remembered at once; the oldest goes first
SEEN_SAVE_S = 3600         # a visit renews a login; written down at most once an hour
WAIT_S = 300               # after /password, the next message is the password
N, R, P = 2 ** 15, 8, 1    # ~40-100 ms per try, 32 MB
_HASH = re.compile(r"^scrypt\$(\d+)\$(\d+)\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$")


def hash_password(pw: str, salt: Optional[bytes] = None) -> str:
    """What `web.password_hash` holds."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=N, r=R, p=P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def valid_hash(s: str) -> bool:
    m = _HASH.match(str(s or "").strip())
    if not m:
        return False
    n, r, p = (int(x) for x in m.groups()[:3])
    # a power of two, and nothing a typo could turn into minutes of work per try
    return 2 ** 10 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 4


def verify(pw: str, stored: str) -> bool:
    m = _HASH.match(str(stored or "").strip())
    if not m or not valid_hash(stored):
        return False
    n, r, p = (int(x) for x in m.groups()[:3])
    try:
        salt, want = base64.b64decode(m.group(4)), base64.b64decode(m.group(5))
        got = hashlib.scrypt(str(pw).encode(), salt=salt, n=n, r=r, p=p,
                             maxmem=256 * 1024 * 1024, dklen=len(want))
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(got, want)


def _tok(token: str) -> str:
    return hashlib.sha256(str(token).encode()).hexdigest()


def _hm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


class Login:
    def __init__(self, auditor):
        self.a = auditor
        w = auditor.cfg.get("web") or {}
        self.on = bool(w.get("login", True))
        self.cfg_raw = str(w.get("password_hash") or "").strip()
        self.cfg_hash = self.cfg_raw if valid_hash(self.cfg_raw) else ""
        self.tg_hash = ""                      # set with /password on Telegram: in the record
        self.sessions: dict = {}               # sha256(token) -> {"made", "seen"}
        self._saved_seen: dict = {}            # sha256(token) -> the "seen" last written
        self._fails: list = []
        self._locked_until = 0.0
        self.waiting: dict = {}                # chat_id -> when /password asked for it
        self._restore()

    # --- what is set --------------------------------------------------------
    @property
    def hash(self) -> str:
        """config.yaml's when it has one (even a broken one: then nothing opens), else /password's."""
        return self.cfg_hash if self.cfg_raw else self.tg_hash

    @property
    def source(self) -> str:
        if not self.hash:
            return ""
        return "config.yaml" if self.cfg_raw else "Telegram"

    @property
    def needed(self) -> bool:
        """On, and nothing to log in with: the page is closed until a password is set."""
        return self.on and not self.hash

    def locked(self, now: Optional[float] = None) -> float:
        """When the lock ends, or 0."""
        now = now or time.time()
        return self._locked_until if now < self._locked_until else 0.0

    def view(self) -> dict:
        return {"on": self.on, "source": self.source, "days": SESSION_DAYS}

    # --- browsers -------------------------------------------------------------
    def check(self, token: str, now: Optional[float] = None) -> bool:
        """A request's cookie: a login this lanowl handed out, used in the last 30 days.
        A visit renews it."""
        if not token or not self.hash:
            return False
        now = now or time.time()
        k = _tok(token)
        s = self.sessions.get(k)
        if s is None:
            return False
        if now - float(s.get("seen") or 0) > SESSION_S:
            self.sessions.pop(k, None)
            self._save()
            return False
        s["seen"] = now
        if now - self._saved_seen.get(k, 0.0) > SEEN_SAVE_S:
            self._save()
        return True

    def attempt(self, ok: bool, ip: str = "", now: Optional[float] = None) -> dict:
        """The answer to a password typed on the page, once `verify` has said whether it
        matched (it runs in a thread: scrypt is slow on purpose). {"ok", "why", "token",
        "left", "until"}."""
        now = now or time.time()
        if not self.hash:
            return {"ok": False, "why": "none"}
        if self.locked(now):
            return {"ok": False, "why": "locked", "until": self._locked_until}
        if ok:
            self._fails = []
            token = secrets.token_urlsafe(32)
            self.sessions[_tok(token)] = {"made": now, "seen": now}
            self._save()
            log.info("dashboard login from %s", ip or "?")
            return {"ok": True, "token": token}
        self._fails = [t for t in self._fails if now - t < LOCK_S] + [now]
        log.warning("dashboard: wrong password from %s (%d in a row)", ip or "?", len(self._fails))
        if len(self._fails) >= MAX_FAILS:
            self._fails = []
            self._locked_until = now + LOCK_S
            chat = self._chat()
            self.a._emit_telegram("digest", (
                f"🔒 <b>Dashboard login locked until {_hm(self._locked_until)}</b>\n"
                f"{MAX_FAILS} wrong passwords in a row"
                + (f", the last from {ip}" if ip else "") + "."
                + (" /password sets a new one and lifts the lock." if chat and not self.cfg_raw else "")))
            return {"ok": False, "why": "locked", "until": self._locked_until}
        return {"ok": False, "why": "wrong", "left": MAX_FAILS - len(self._fails)}

    def logout(self, token: str, everywhere: bool = False):
        if everywhere:
            n = len(self.sessions)
            self.sessions = {}
            log.warning("dashboard: every browser logged out (%d)", n)
        else:
            self.sessions.pop(_tok(token or ""), None)
        self._save()

    # --- Telegram -------------------------------------------------------------
    def _telegram(self) -> bool:
        """Whether lanowl can tell anyone on Telegram: a chat and the bot's token."""
        from .sinks import resolve_tg_token
        try:
            return bool((self.a.cfg.get("telegram") or {}).get("chat_id")) and bool(resolve_tg_token(self.a.cfg))
        except Exception:
            return False

    def _chat(self) -> bool:
        """Whether /password can reach lanowl: Telegram, with its commands answered."""
        return self._telegram() and bool(((self.a.cfg.get("telegram") or {}).get("chat") or {}).get("enabled"))

    def needed_text(self, chat: bool) -> str:
        """The Telegram message at a start while the page has no password."""
        lines = ["🔑 <b>The dashboard is closed until you set a password</b>"]
        if self.cfg_raw:
            lines.append("config.yaml's <code>web.password_hash</code> is not a password hash, "
                         "so nothing opens it: make one with <code>lanowl --hash-password</code>.")
        elif chat:
            lines.append("Send /password, then the password: I delete your message and keep only "
                         "its hash. Or set <code>web.password_hash</code> in config.yaml "
                         "(<code>lanowl --hash-password</code>).")
        else:
            lines.append("Set <code>web.password_hash</code> in config.yaml: "
                         "<code>lanowl --hash-password</code> makes it.")
        return "\n".join(lines)

    def ask_text(self) -> Optional[str]:
        """/password with nothing after it: the refusal, or None when it may ask."""
        if not self.on:
            return "🔑 The dashboard's login is switched off (<code>web.login: false</code>)."
        if self.cfg_raw:
            return ("🔑 The dashboard password is set in config.yaml (<code>web.password_hash</code>) "
                    "— change it there." if self.cfg_hash else
                    "🔑 config.yaml has <code>web.password_hash</code>, and it is not a password "
                    "hash: fix it there (<code>lanowl --hash-password</code>), or empty it to set "
                    "the password here.")
        return None

    def set_password(self, pw: str, now: Optional[float] = None, hashed: str = "") -> dict:
        """/password on Telegram. Only its hash is kept (`hashed`: made already, in a
        thread). A new password logs every browser out and lifts a lock. {"ok", "text"}."""
        refused = self.ask_text()
        if refused:
            return {"ok": False, "text": refused}
        pw = str(pw or "")
        if len(pw) < MIN_LEN or len(pw) > MAX_LEN:
            return {"ok": False, "text": f"🔑 A password has {MIN_LEN} characters or more. "
                                         "Nothing changed: /password to try again."}
        was = bool(self.tg_hash)
        self.tg_hash = hashed if valid_hash(hashed) else hash_password(pw)
        self.sessions = {}
        lifted = bool(self.locked(now))
        self._fails, self._locked_until = [], 0.0
        self._save()
        log.warning("dashboard password %s on Telegram", "changed" if was else "set")
        if not was:
            return {"ok": True, "text": f"🔑 Dashboard password set. Every browser stays logged in "
                                        f"for {SESSION_DAYS} days after its last visit."}
        return {"ok": True, "text": "🔑 Dashboard password changed. Every browser was logged out"
                                    + (", and the lock is lifted." if lifted else ".")}

    # --- persistence ------------------------------------------------------------
    def _restore(self):
        try:
            rec = self.a.state.load_record(RECORD) or {}
        except Exception:
            log.warning("login: record unreadable, starting empty", exc_info=True)
            return
        h = str(rec.get("password") or "")
        self.tg_hash = h if valid_hash(h) else ""
        # logins handed out under another password (config.yaml's changed while lanowl was
        # stopped) are not this password's
        if rec.get("under") != _tok(self.hash):
            return
        now = time.time()
        self.sessions = {str(k): v for k, v in (rec.get("sessions") or {}).items()
                         if isinstance(v, dict) and now - float(v.get("seen") or 0) <= SESSION_S}
        self._saved_seen = {k: float(v.get("seen") or 0) for k, v in self.sessions.items()}

    def _save(self):
        now = time.time()
        live = sorted(((k, v) for k, v in self.sessions.items()
                       if now - float(v.get("seen") or 0) <= SESSION_S),
                      key=lambda kv: -float(kv[1].get("seen") or 0))[:MAX_SESSIONS]
        self.sessions = dict(live)
        try:
            self.a.state.save_record(RECORD, {"password": self.tg_hash, "under": _tok(self.hash),
                                              "sessions": self.sessions})
            self._saved_seen = {k: float(v.get("seen") or 0) for k, v in self.sessions.items()}
        except Exception as e:
            log.warning("login: record not saved: %s", e)


# --- `lanowl --check` ------------------------------------------------------------------
def _in_state(cfg: dict) -> bool:
    """Whether /password set one: read from the state's record (--check is a process of its own)."""
    import json
    import os
    import sqlite3
    path = (cfg.get("state") or {}).get("db_path", "lanowl_state.sqlite")
    if not os.path.exists(path):
        return False
    try:
        con = sqlite3.connect(path, timeout=5)
        try:
            row = con.execute("SELECT value FROM records WHERE name=?", (RECORD,)).fetchone()
        finally:
            con.close()
        return bool(row) and valid_hash(str(json.loads(row[0]).get("password") or ""))
    except Exception:
        return False


def report(cfg: dict) -> tuple:
    """(text, problems): the dashboard's login. Never a value."""
    w = cfg.get("web") or {}
    if not w.get("enabled"):
        return "Dashboard: off (web.enabled)", 0
    head = "Dashboard: on"
    chat = bool(((cfg.get("telegram") or {}).get("chat") or {}).get("enabled"))
    if not w.get("login", True):
        return (f"{head}\n  ○ {'login':<15} off (web.login: false): anyone who reaches the "
                "address can use the dashboard. Keep it only behind a login of your own."), 0
    raw = str(w.get("password_hash") or "").strip()
    if valid_hash(raw):
        mark, text = "✓", "password from config.yaml"
    elif raw:
        mark, text = "✗", ("web.password_hash is not a password hash, so the dashboard stays "
                           "closed: make one with lanowl --hash-password")
    elif _in_state(cfg):
        mark, text = "✓", "password set on Telegram (/password)"
    else:
        mark, text = "✗", ("no password, so the dashboard stays closed: "
                           + ("send /password to the bot on Telegram, or set " if chat else "set ")
                           + "web.password_hash in config.yaml (lanowl --hash-password)")
    return f"{head}\n  {mark} {'login':<15} {text}", int(mark == "✗")
