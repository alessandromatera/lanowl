"""lanowl's own releases: is there a newer one, and (with the helper) updating to it.

Two halves, and only the first one is lanowl's business:

  - The check. Once a day, and on Settings → lanowl's Check now, lanowl asks GitHub for the
    latest FULL release (that endpoint never returns a draft or a pre-release, which is what
    is wanted) and keeps what it said: version, date, link, a few lines of notes. A failed
    check keeps the last good answer and the error beside it; it is never an alert. The
    request carries lanowl's version in its User-Agent and nothing else. `self_update.check:
    false` switches it off: then there is no request at all, not even on the button.
  - Telling the owner. One line in the next digest, once per new version, pointing to
    Settings. Never a page, never a second time for the same version.

Updating is done by `updater.py`, a separate, optional container that is the ONLY one holding
Docker's socket. lanowl never gets that socket: it can only write one word, "update", to the
helper's own socket (`/run/updater/updater.sock`), and the helper decides everything else. So
this file has no Docker in it. `self_update.auto: true` is that one word, sent once per version,
at `self_update.at`, when a newer release is known and the helper answers.

After an update the new lanowl says so once on Telegram (the normal channel, not a page): "lanowl
updated: 0.2.0 → 0.2.1", or that it was put back and why. The helper writes what happened to
`/run/updater/last.json`; lanowl also remembers the version it ran last, so an update made by
hand (`docker compose pull && up -d`, `pip install -U`) is told the same way.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Optional

from . import __version__
from .report import _html
from .reviews import today_at

log = logging.getLogger("lanowl.selfupdate")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

RECORD = "selfupdate"
RELEASES = "https://api.github.com/repos/alessandromatera/lanowl/releases/latest"
RELEASE_PAGE = "https://github.com/alessandromatera/lanowl/releases"
TIMEOUT_S = 15
EVERY_S = 86400                    # a good answer is asked again after a day...
RETRY_S = 3600                     # ...a failed one after an hour
UPDATER_SOCK = "/run/updater/updater.sock"
LAST_FILE = "/run/updater/last.json"
AUTO_WINDOW_S = 2 * 3600           # an automatic update starts within two hours of `at`, never in the afternoon
STALE_RUN_S = 3600                 # a helper job "running" for longer than this died with it
NOTES_LINES = 6
NOTES_CHARS = 700
COMMANDS = {
    "docker": "docker compose -f docker/compose.yaml pull && docker compose -f docker/compose.yaml up -d",
    "pip": "pip install -U lanowl",
    "updater": "docker compose -f docker/compose.yaml --profile updater up -d",
}


# --- versions -------------------------------------------------------------------------------
_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[.-]?(dev|a|b|rc)\.?(\d*))?$")
_PRE = {"dev": 0, "a": 1, "b": 2, "rc": 3}


def parse_version(s) -> Optional[tuple]:
    """'0.2.1' -> (0, 2, 1, 9, 0); '0.2.1.dev0' -> (0, 2, 1, 0, 0). A development, alpha, beta
    or release candidate sorts before the release it leads to and after the one before:
    0.2.0 < 0.2.1.dev0 < 0.2.1rc1 < 0.2.1. None for anything else."""
    m = _VER.match(str(s or "").strip())
    if not m:
        return None
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), _PRE[pre] if pre else 9, int(m.group(5) or 0))


def is_dev(s) -> bool:
    v = parse_version(s)
    return bool(v and v[3] != 9)


def compare(running, latest) -> str:
    """How the running version stands against the latest release:
    "behind" (a newer release is out), "current", "ahead" (newer than the latest release: a
    development build, or a release GitHub does not list yet) or "unknown"."""
    a, b = parse_version(running), parse_version(latest)
    if a is None or b is None:
        return "unknown"
    return "behind" if a < b else "current" if a == b else "ahead"


def stand_words(running, latest) -> str:
    """The relation in words, as Settings says it ("" when there is no answer yet)."""
    if not latest:
        return ""
    rel = compare(running, latest)
    if rel == "behind":
        return f"lanowl {latest} is out"
    if rel == "current":
        return "you run the latest release"
    if rel == "ahead":
        return ("a development build, newer than the latest release" if is_dev(running)
                else "newer than the latest release")
    return "the version could not be compared"


# --- GitHub ---------------------------------------------------------------------------------
def _plain(s: str) -> str:
    """Markdown's [text](link), **bold** and `code` as their plain text."""
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"(\*\*|__)(.+?)\1", r"\2", s)
    return re.sub(r"`([^`]*)`", r"\1", s)


def notes_short(body, lines: int = NOTES_LINES, chars: int = NOTES_CHARS) -> str:
    """The release notes' first paragraphs and points, as plain lines: GitHub's wrapped lines
    joined again, headings and rules left out, markdown shown as its text, a point as "• …"."""
    items, cur = [], ""
    for ln in str(body or "").replace("\r", "").split("\n"):
        s = ln.strip()
        if not s or set(s) <= set("-=*_ ") or s.startswith("#"):
            if cur:
                items.append(cur)
            cur = ""
            continue
        m = re.match(r"^(?:[-*+]|\d+[.)])\s+(.*)$", s)
        if m:
            if cur:
                items.append(cur)
            cur = "• " + m.group(1)
        else:
            cur = f"{cur} {s}" if cur else s
    if cur:
        items.append(cur)
    text = "\n".join(_plain(x) for x in items[:lines])
    return text if len(text) <= chars else text[:chars].rsplit(" ", 1)[0].rstrip(",;:") + "…"


def parse_release(obj) -> tuple:
    """(release, error) from GitHub's /releases/latest JSON. The link must be github.com's: the
    page puts it in a href, so nothing else is kept."""
    if not isinstance(obj, dict):
        return None, "GitHub's answer was not a release"
    tag = str(obj.get("tag_name") or "")
    ver = tag[1:] if tag[:1] in ("v", "V") else tag
    if parse_version(ver) is None:
        return None, f"the latest release's tag ({tag[:40]!r}) is not a version"
    if obj.get("draft") or obj.get("prerelease"):
        return None, "GitHub listed a draft or a pre-release as the latest release"
    url = str(obj.get("html_url") or "")
    if not url.startswith("https://github.com/"):
        url = RELEASE_PAGE
    return {"tag": tag, "version": ver, "published": str(obj.get("published_at") or "")[:10],
            "url": url, "notes": notes_short(obj.get("body"))}, ""


async def http_get_json(url: str, headers: dict, timeout: float) -> tuple:
    """(status, parsed JSON or None). The one place a request leaves; the tests replace it."""
    if aiohttp is None:  # pragma: no cover
        raise RuntimeError("aiohttp is not installed")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
        async with s.get(url, headers=headers) as r:
            try:
                data = await r.json(content_type=None)
            except Exception:
                data = None
            return r.status, data


# --- the helper's socket ----------------------------------------------------------------------
async def updater_call(op: str, timeout: float = 5.0, path: str = "") -> dict:
    """One word to the updater, one JSON line back. {"ok": False, "error"} when it is not there.
    Only "status" and "update" exist: the helper refuses anything else, and this sends nothing
    but the word."""
    path = path or UPDATER_SOCK
    if not os.path.exists(path):
        return {"ok": False, "absent": True, "error": "the updater is not running"}
    try:
        async def one():
            r, w = await asyncio.open_unix_connection(path, limit=1 << 16)
            try:
                w.write((json.dumps({"op": op}) + "\n").encode())
                await w.drain()
                return await r.readline()
            finally:
                w.close()
        line = await asyncio.wait_for(one(), timeout)
        out = json.loads(line.decode("utf-8", "replace") or "null")
        return out if isinstance(out, dict) else {"ok": False, "error": "the updater's answer was not understood"}
    except Exception as e:
        return {"ok": False, "error": f"the updater did not answer ({type(e).__name__})"}


def in_container() -> bool:
    return os.path.exists("/.dockerenv")


def read_last(path: str = "") -> dict:
    """What the helper last did (last.json); {} when it never did, or the file is not readable."""
    try:
        with open(path or LAST_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# --- the record and the clock ------------------------------------------------------------------
class SelfUpdate:
    ICON = "⬆️"

    def __init__(self, auditor):
        self.a = auditor
        c = (auditor.cfg.get("self_update") or {}) if isinstance(auditor.cfg.get("self_update"), dict) else {}
        self.check_on = bool(c.get("check", True))
        self.auto = bool(c.get("auto", False))
        self.at = str(c.get("at") or "04:00")
        if not re.match(r"^\d{1,2}:\d{2}$", self.at) or int(self.at.split(":")[0]) > 23 or int(self.at.split(":")[1]) > 59:
            self.at = "04:00"
        self.version = __version__
        self._task: Optional[asyncio.Task] = None
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("selfupdate: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k, dflt in (("latest", None), ("checked", 0.0), ("ok_at", 0.0), ("error", ""), ("told", ""),
                        ("auto_tried", ""), ("last_run", ""), ("announced", 0.0), ("auto_error", "")):
            self.rec.setdefault(k, dflt)

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("selfupdate: record not saved: %s", e)

    # --- the check -------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def due(self, now: float) -> bool:
        if not self.check_on or self.running:
            return False
        wait = RETRY_S if self.rec.get("error") else EVERY_S
        return now - float(self.rec.get("checked") or 0) >= wait

    async def check(self, now: Optional[float] = None) -> dict:
        """Ask GitHub. Returns view(); a failure is kept beside the last good answer. Switched
        off, it asks nothing."""
        if not self.check_on:
            return {**self.view(), "error": "the check is switched off (self_update.check)"}
        now = time.time() if now is None else now
        self.rec["checked"] = now          # claimed now: a slow answer is not asked twice
        try:
            status, data = await http_get_json(
                RELEASES, {"Accept": "application/vnd.github+json", "User-Agent": f"lanowl/{__version__}"},
                TIMEOUT_S)
            if status != 200:
                rel, err = None, (f"GitHub said {status}"
                                  + (f": {str(data.get('message'))[:120]}" if isinstance(data, dict) and data.get("message") else ""))
            else:
                rel, err = parse_release(data)
        except Exception as e:
            rel, err = None, f"GitHub could not be reached ({type(e).__name__})"
        if rel:
            self.rec.update(latest=rel, error="", ok_at=now)
        else:
            self.rec["error"] = err
            log.info("selfupdate: the check failed: %s", err)
        self._save()
        return self.view()

    def start_check(self):
        if not self.running:
            self._task = asyncio.ensure_future(self._guarded())

    async def _guarded(self):
        try:
            await self.check()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("selfupdate: the check failed")

    # --- what is known -----------------------------------------------------------------------
    def latest_version(self) -> str:
        return str((self.rec.get("latest") or {}).get("version") or "")

    def newer(self) -> bool:
        return compare(self.version, self.latest_version()) == "behind"

    def view(self) -> dict:
        lat = self.rec.get("latest") or None
        return {"version": self.version, "dev": is_dev(self.version), "check": self.check_on, "auto": self.auto,
                "at": self.at, "latest": lat, "stand": compare(self.version, self.latest_version()) if lat else "",
                "words": stand_words(self.version, self.latest_version()),
                "checked": self.rec.get("checked") or 0, "ok_at": self.rec.get("ok_at") or 0,
                "error": self.rec.get("error") or "", "checking": self.running,
                "auto_error": self.rec.get("auto_error") or "", "container": in_container(),
                "last": self.outcome(), "commands": COMMANDS, "releases": RELEASE_PAGE}

    # --- the digest -------------------------------------------------------------------------
    def digest_news(self) -> list:
        """One line, for a release not yet mentioned in a digest. HTML, like the other lines."""
        if not self.check_on or not self.newer() or self.rec.get("told") == self.latest_version():
            return []
        v = self.latest_version()
        return [f"{self.ICON} <b>lanowl {_html(v)} is out</b> (this one is {_html(self.version)}) — "
                "Settings → lanowl has what is new and how to update"]

    def digest_told(self):
        v = self.latest_version()
        if v and self.newer() and self.rec.get("told") != v:
            self.rec["told"] = v
            self._save()

    # --- automatic update ---------------------------------------------------------------------
    def auto_due(self, now: float) -> bool:
        """Once per version, within two hours after `at`, when a newer full release is known."""
        if not (self.auto and self.check_on and self.newer()):
            return False
        v = self.latest_version()
        if self.rec.get("auto_tried") == v:
            return False
        at = today_at(self.at, now)
        return at <= now < at + AUTO_WINDOW_S and not self.a.restart_blockers(now)

    async def update_now(self, by: str = "") -> dict:
        """Say the word to the updater. {"ok", "error"?}. Nothing is chosen here: not an image, not a
        container."""
        if not self.newer():
            return {"ok": False, "error": "there is no newer release known: Check now first"}
        r = await updater_call("update")
        if r.get("ok"):
            who = f" (asked from {_html(by)})" if by else ""
            self._tell(f"{self.ICON} <b>lanowl is updating</b> to {_html(self.latest_version())}{who}: it restarts "
                       "in a minute; the old one comes back if the new one does not answer in 3 minutes")
        return r

    def start_auto(self, now: float):
        v = self.latest_version()
        self.rec["auto_tried"] = v           # once per version, whatever comes of it
        self._save()

        async def go():
            r = await updater_call("update")
            self.rec["auto_error"] = "" if r.get("ok") else str(r.get("error") or "the updater refused")[:300]
            self._save()
            if r.get("ok"):
                self._tell(f"{self.ICON} <b>lanowl is updating by itself</b> to {_html(v)} ({_html(self.at)}): "
                           "it restarts in a minute; the old one comes back if the new one does not answer in 3 minutes")
        asyncio.ensure_future(go())

    # --- the clock ---------------------------------------------------------------------------
    def tick(self, now: float):
        """Once a sweep: the check when it is due, the automatic update at its hour, and the
        helper's news when it has some."""
        try:
            if self.due(now):
                self.start_check()
            if self.auto_due(now):
                self.start_auto(now)
            self.announce_outcome(now)
        except Exception:
            log.exception("selfupdate: tick failed")

    # --- after an update ----------------------------------------------------------------------
    def outcome(self) -> dict:
        """What the helper last did, as the page shows it ({} for never, or a job still running)."""
        d = read_last(LAST_FILE)
        return d if d.get("state") in ("ok", "rolled_back", "failed", "nothing") else {}

    def at_start(self, now: Optional[float] = None):
        """Called once when lanowl starts: a different version from the one that ran last, or an
        outcome the helper wrote that was not told yet, is said once."""
        now = time.time() if now is None else now
        ran = str(self.rec.get("last_run") or "")
        self.rec["last_run"] = self.version
        if not self.announce_outcome(now, started=True) and ran and ran != self.version \
                and not self._job_running(now):
            # an update made by hand: the same words, from the versions alone
            if compare(ran, self.version) == "behind":
                self._tell(f"{self.ICON} <b>lanowl updated</b>: {_html(ran)} → {_html(self.version)}")
            else:
                self._tell(f"{self.ICON} <b>lanowl changed version</b>: {_html(ran)} → {_html(self.version)}")
        self._save()

    @staticmethod
    def _job_running(now: float) -> bool:
        d = read_last(LAST_FILE)
        return d.get("state") == "running" and now - float(d.get("started") or 0) < STALE_RUN_S

    def announce_outcome(self, now: float, started: bool = False) -> bool:
        """Tell the helper's last finished outcome once (keyed by when it finished). True when one
        was told."""
        d = read_last(LAST_FILE)
        fin = float(d.get("finished") or 0)
        if d.get("state") not in ("ok", "rolled_back", "failed") or fin <= float(self.rec.get("announced") or 0):
            return False
        self.rec["announced"] = fin
        self._save()
        frm, to = str(d.get("from") or ""), str(d.get("to") or "")
        if d.get("state") == "ok":
            self._tell(f"{self.ICON} <b>lanowl updated</b>: {_html(frm)} → {_html(to)}" if frm and to
                       else f"{self.ICON} <b>lanowl updated</b> to the latest image")
        elif d.get("state") == "rolled_back":
            why = str(d.get("reason") or "")[:700]
            self._tell(f"↩️ <b>lanowl update rolled back</b>: the old one runs again"
                       + (f" ({_html(frm)})" if frm else "") + ("\nthe new one's last log lines:\n<pre>"
                                                              + _html(why) + "</pre>" if why else ""))
        else:
            self._tell(f"{self.ICON} <b>lanowl update did not start</b>: {_html(str(d.get('reason') or '')[:300])}")
        return True

    def _tell(self, text: str):
        try:
            self.a._emit_telegram("digest", text)
        except Exception:
            log.warning("selfupdate: the Telegram line was not sent", exc_info=True)
