"""The webhook: every alert, also as one HTTP POST of JSON to an address of your own.

A third way out beside Telegram and MQTT, for what listens on neither: Apprise, ntfy, n8n, a
gateway to Matrix or Slack, Home Assistant. It gets exactly what Telegram gets — the same
gate, the same opt-ins — and `webhook.events` / `webhook.min_severity` can only narrow that
down, never add to it. It works with Telegram not set up at all.

How a message gets here: main._emit_telegram hands over the finished Telegram text and, where it
knows them, what the message is about (`event`); `say` turns that into one event, tests it
against the filter and appends it to a queue file. A worker task of its own does the HTTP.
Nothing on the sweep, the Telegram or the MQTT path ever awaits it.

  - One POST per Telegram message. A message that covers several incidents lists each in
    `incidents`.
  - Not parked while the internet is down, as the Telegram outbox is: the receiver is often on the
    LAN (a gateway, Home Assistant), and a message sent into a blackout is exactly what it needs.
  - The owl's diagnosis arrives minutes after the alert. Telegram edits it into the message;
    a POST cannot, so it follows as a second event (`event_type: diagnosis`) that names the
    first in `in_reply_to`.
  - The address and the token are secrets (access.py, read at every use): never in the log,
    Telegram, MQTT, the dashboard or the model. The queue file holds events, never either.
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import html as _html
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from . import __version__, access
from .alerts import RECOVERED, STILL

log = logging.getLogger("lanowl.webhook")

# what `webhook.events` may hold: the kinds of message, as the owner thinks of them
CATEGORIES = ("down", "recovery", "wan", "logs", "security", "new_device", "diagnosis", "proposal",
              "digest", "maintenance", "other")
# on by default: what is news now, and what waits for the owner's yes (a POST has no buttons, so
# a webhook-only owner would otherwise never hear that a proposal waits); the digests, the
# housekeeping and the rest are opt-in
DEFAULT_EVENTS = ("down", "recovery", "wan", "security", "new_device", "logs", "diagnosis",
                  "proposal")
FORMATS = ("generic", "apprise", "ntfy", "template")
# lanowl's own severities, low to high; a recovery counts as info when the filter compares
RANK = {"recovery": 0, "info": 0, "warning": 1, "high": 2, "critical": 3}
MIN_SEVERITIES = ("info", "warning", "high", "critical")

# One POST: 10 s in all, up to 3 tries 2 s then 4 s apart (a route flip that ate the first is
# over a second later); then the message at the head waits and is tried again every minute.
TIMEOUT_S = 10.0
GAPS = (2.0, 4.0)
HEAD_WAIT_S = 60.0
# What cannot be delivered is kept a day and at most this many, the oldest dropped first: an
# alert that arrives tomorrow is noise, and a receiver that is gone must not fill the disk.
MAX_AGE_S = 24 * 3600
MAX_ITEMS = 200
# a message is cut here: a digest can be long, and the queue file holds 200 of them
MAX_TEXT = 16000
SAID_N = 160

# the severity each preset sends (the table in docs/reference/webhook.md)
GENERIC_SEV = {"critical": "critical", "high": "high", "warning": "medium", "info": "low",
               "recovery": "info"}
APPRISE_TYPE = {"critical": "failure", "high": "failure", "warning": "warning", "info": "info",
                "recovery": "success"}
NTFY_PRIORITY = {"critical": 5, "high": 4, "warning": 3, "info": 2, "recovery": 3}
NTFY_TAG = {"critical": "rotating_light", "high": "warning", "warning": "warning",
            "info": "information_source", "recovery": "white_check_mark"}

# a message's first character says how bad it is (report._EMOJI and the watchers' own)
_EMOJI_SEVERITY = (("🔴", "critical"), ("🚨", "critical"), ("🟠", "high"), ("🟡", "warning"),
                   ("⚪", "info"), ("🟢", "recovery"), ("✅", "recovery"))
# the door a message left by, when nothing else says how bad it is
_CHANNEL_SEVERITY = {"critical": "critical", "digest": "info"}
# what an event is called when its caller named only the category
_TYPES = {"down": "device_down", "recovery": "device_up", "logs": "log_alert",
          "security": "security_alert", "new_device": "new_device", "diagnosis": "diagnosis",
          "proposal": "proposal", "digest": "digest", "maintenance": "maintenance"}

_TAG = re.compile(r"</?[A-Za-z][^<>]*>")
_TIME = re.compile(r"\s*(?<![\w:])\d{1,2}:\d{2}(?::\d{2})?(?![\w:])")
_HOLDER = re.compile(r"\{(\w+)\}")
# the host-log watcher's heads that are about who got in, not about what a log said (hostlog.py)
_SECURITY_HEAD = re.compile(r"^\W*(LOGIN THROUGH|LOGIN FROM|FAILED LOGINS|CONNECTION FLOOD)\b")


# --- from Telegram's HTML to words --------------------------------------------------------
def plain(text) -> str:
    """Telegram's HTML as plain text: tags gone, entities decoded, lines kept, runs of blank
    lines folded into one. Tags first, entities after: a model's `&lt;b&gt;` is the text
    "<b>", not a tag."""
    t = _html.unescape(_TAG.sub("", str(text or ""))).replace("\r", "")
    out, blank = [], False
    for ln in t.split("\n"):
        ln = ln.rstrip()
        if ln.strip():
            out.append(ln)
            blank = False
        elif out and not blank:
            out.append("")
            blank = True
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)[:MAX_TEXT]


def emoji_severity(text: str) -> str:
    """The severity a message's leading emoji says, or "" when it names none."""
    t = text.lstrip()
    return next((s for e, s in _EMOJI_SEVERITY if t.startswith(e)), "")


def _title_of(line: str) -> str:
    """A message's first line as a title: the leading emoji and the time stamps off (the
    event carries its own `timestamp`), what is left of the separators trimmed."""
    t = re.sub(r"^[^\w]+", "", line)
    t = _TIME.sub("", t)
    t = re.sub(r"\s{2,}", " ", t).strip(" —-:·")
    return t if len(t) <= 150 else t[:149].rstrip() + "…"


def split_text(text: str) -> tuple:
    """(title, message) of a message's plain text: the first line, and the lines after it.
    A one-line message has nothing after its title: the message is the title again, because
    a receiver that takes a title takes a body, and some refuse one without the other."""
    lines = plain(text).split("\n")
    title = _title_of(lines[0]) if lines else ""
    title = title or "lanowl"
    message = "\n".join(lines[1:]).strip("\n")
    return title, message or title


def iso(ts: float) -> str:
    """ISO 8601 with the offset, in the time zone lanowl runs in."""
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def severity_name(s) -> str:
    s = str(s or "").lower()
    return s if s in ("critical", "high", "warning", "info", "recovery") else "info"


def incident_id(episode) -> str:
    """One incident's id, the same for its alert and its recovery: from the gate's episode,
    which is what lets one message announce several and one recovery close them."""
    return hashlib.sha1(f"{episode.key}|{int(episode.started)}".encode()).hexdigest()[:16]


# --- what the gate said, as an event ----------------------------------------------------------
def gate_event(events: list) -> dict:
    """The description of ONE message format_alerts made from these gate events (all raised, or
    all recovered): its category, type, severity, title and the incidents it covers. What
    `_emit_telegram` takes as `event`.

    The text of a gate message is a head line ("CRITICAL 14:02:27") the Telegram reader
    wants and a webhook does not: the title says what happened to whom."""
    rows, keys = [], []
    for e in events:
        i = e.issue
        if e.kind == RECOVERED:
            et, sev = "device_up", "recovery"
        else:
            et, sev = ("device_still_down" if e.kind == STILL else "device_down"), severity_name(i.get("severity"))
        dev = {"name": str(i.get("device") or ""), "ip": str(i.get("ip") or "")}
        iid = incident_id(e.episode)
        rows.append({"incident_id": iid, "event_type": et, "severity": sev, "device": dev})
        keys.append({"key": e.episode.key, "incident_id": iid})
    recovered = bool(events) and all(e.kind == RECOVERED for e in events)
    every_down = all((e.issue.get("kind") or "down") == "down" for e in events)
    n = len(events)
    if n == 1:
        e, name = events[0], rows[0]["device"]["name"]
        if recovered:
            title = f"{name} back online" if every_down else f"{name} recovered"
        elif every_down:
            title = f"{name} still offline" if e.kind == STILL else f"{name} offline"
        else:
            title = f"{name}: {e.issue.get('detail') or 'a problem'}"
    elif recovered:
        title = f"{n} devices back online" if every_down else f"{n} issues recovered"
    else:
        still = all(e.kind == STILL for e in events)
        title = (f"{n} devices {'still ' if still else ''}offline" if every_down else f"{n} issues")
    if recovered:
        sev, et = "recovery", "device_up"
    else:
        sev = max((r["severity"] for r in rows), key=lambda s: RANK[s], default="critical")
        et = "device_still_down" if all(r["event_type"] == "device_still_down" for r in rows) else "device_down"
    return {"category": "recovery" if recovered else "down", "type": et, "severity": sev,
            "title": title, "incidents": rows, "keys": keys}


# --- the presets ----------------------------------------------------------------------------------
def _context(ev: dict) -> dict:
    """What a template may name: every field of the event, "" or [] when it has none, so a
    placeholder is never a null."""
    dev = ev.get("device") or {}
    return {"sender": "lanowl", "title": ev["title"], "message": ev["message"],
            "severity": ev["severity"], "event_id": ev["event_id"], "event_type": ev["event_type"],
            "category": ev["category"], "timestamp": ev["timestamp"],
            "incident_id": ev.get("incident_id") or "", "device": dev.get("name") or "",
            "ip": dev.get("ip") or "", "mac": dev.get("mac") or "",
            "incidents": copy.deepcopy(ev.get("incidents") or []),
            "in_reply_to": ev.get("in_reply_to") or ""}


def _as_text(v) -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return str(v)


def fill(node, ctx: dict, depth: int = 0):
    """The owner's template, with {name} placeholders filled in every string value.

    Matched with a regex and nothing else — never str.format: text from the owner's file must
    not reach format-spec evaluation ("{title.__class__}", "{0}"). A string that is exactly one
    placeholder takes the value as it is, so "{incidents}" becomes the list. A name lanowl does
    not know stays as written."""
    if depth > 20:
        raise ValueError("webhook.template is nested too deep")
    if isinstance(node, str):
        m = _HOLDER.fullmatch(node)
        if m and m.group(1) in ctx:
            return copy.deepcopy(ctx[m.group(1)])
        return _HOLDER.sub(lambda m: _as_text(ctx[m.group(1)]) if m.group(1) in ctx else m.group(0), node)
    if isinstance(node, dict):
        return {k: fill(v, ctx, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [fill(v, ctx, depth + 1) for v in node]
    return node


def generic_body(ev: dict) -> dict:
    body = {"sender": "lanowl", "title": ev["title"], "message": ev["message"],
            "severity": GENERIC_SEV[ev["severity"]], "event_id": ev["event_id"],
            "event_type": ev["event_type"], "category": ev["category"], "timestamp": ev["timestamp"]}
    for k in ("incident_id", "device", "incidents", "in_reply_to"):
        if ev.get(k):
            body[k] = ev[k]
    return body


def render(ev: dict, wcfg: dict, url: str) -> tuple:
    """(url, body) for one event in the configured format. ValueError says what the owner got
    wrong (a format that does not exist, an empty template, an ntfy address with no topic)."""
    fmt = str(wcfg.get("format") or "generic").strip().lower()
    sev = ev["severity"]
    if fmt == "generic":
        return url, generic_body(ev)
    if fmt == "apprise":
        return url, {"version": "1.0", "title": ev["title"], "message": ev["message"],
                     "type": APPRISE_TYPE[sev], "sender": "lanowl"}
    if fmt == "ntfy":
        # ntfy's JSON publish goes to the server's root with the topic in the body; the
        # address the owner gives is the one they would open, https://host[/path]/<topic>
        p = urlsplit(url)
        root, _, topic = p.path.rstrip("/").rpartition("/")
        if not topic:
            raise ValueError("an ntfy address ends with the topic: https://host/<topic>")
        return (urlunsplit((p.scheme, p.netloc, root + "/", p.query, "")),
                {"topic": unquote(topic), "title": ev["title"], "message": ev["message"],
                 "priority": NTFY_PRIORITY[sev], "tags": [NTFY_TAG[sev]]})
    if fmt == "template":
        tpl = wcfg.get("template")
        if not isinstance(tpl, (dict, list)) or not tpl:
            raise ValueError("webhook.format is template, and webhook.template is empty")
        return url, fill(tpl, _context(ev))
    raise ValueError(f"webhook.format {fmt!r} is not one of {', '.join(FORMATS)}")


def _headers(wcfg: dict, token: str) -> dict:
    """Content-Type, User-Agent, the owner's own headers, then the bearer token (which wins
    over an Authorization header of theirs: the token is the setting made for it)."""
    h: dict = {}

    def put(name: str, value: str):
        for k in [k for k in h if k.lower() == name.lower()]:
            del h[k]
        h[name] = value

    put("Content-Type", "application/json")
    put("User-Agent", f"lanowl/{__version__}")
    extra = wcfg.get("headers")
    for k, v in (extra.items() if isinstance(extra, dict) else ()):
        k, v = str(k), str(v)
        if re.search(r"[\x00-\x1f\x7f]", k + v) or not k.strip():
            raise ValueError("a header in webhook.headers has a line break or no name")
        put(k, v)
    if token:
        if re.search(r"[\x00-\x20\x7f]", token):
            raise ValueError("the bearer token has a space or a line break in it")
        put("Authorization", f"Bearer {token}")
    return h


def _hide(url: str, token: str) -> list:
    """Every piece of the address and the token a receiver might echo back in an error:
    the whole address, what follows the host (a key often rides in the path), each long path
    segment and query value, the token. Longest first, so a piece never half-hides a bigger one."""
    bits = {url, token}
    try:
        p = urlsplit(url)
        bits.add(url.split("://", 1)[-1])
        tail = p.path + ("?" + p.query if p.query else "")
        if len(tail) > 1:
            bits.add(tail)
        bits |= {s for seg in p.path.split("/") for s in (seg, unquote(seg)) if len(s) >= 6}
        bits |= {v for _, v in parse_qsl(p.query) if len(v) >= 6}
        bits |= {x for x in (p.username, p.password) if x}
    except ValueError:
        pass
    return sorted((b for b in bits if b and len(b) >= 4), key=len, reverse=True)


def _mask(text: str, hide: list, n: int = SAID_N) -> str:
    """A receiver's words as a line: the secrets out, blanks folded, at most `n` characters."""
    t = " ".join(str(text or "").split())
    for b in hide:
        t = t.replace(b, "***")
    return t if len(t) <= n else t[:n - 1].rstrip() + "…"


def _host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


# --- the channel -----------------------------------------------------------------------------------
class Webhook:
    """The queue, the worker and the settings of the webhook channel.

    `episode_of(key)`: when the incident for that key began, 0.0 when none is open (main) —
    how a WAN message's "back" finds the incident it closes. `mac_of(ip)`: a device's MAC from
    the inventory, when one is known."""

    def __init__(self, cfg: dict, episode_of: Optional[Callable] = None,
                 mac_of: Optional[Callable] = None):
        self.cfg = cfg
        self._episode_of = episode_of or (lambda key: 0.0)
        self._mac_of = mac_of
        self.timeout_s, self.gaps, self.head_wait_s = TIMEOUT_S, GAPS, HEAD_WAIT_S
        self.max_age_s, self.max_items = MAX_AGE_S, MAX_ITEMS
        self._lock = threading.Lock()          # enqueue may be called from another thread
        self._items: list = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._wake: Optional[asyncio.Event] = None
        self._stopped = False
        # status(): what the dashboard says. All memory: a restart starts the story over.
        self.last_ok_ts = 0.0
        self.last_error = ""
        self.last_error_ts = 0.0
        self.failing_since = 0.0
        self.next_try_ts = 0.0
        # key -> {"event_id", "incident_id", "ts", "answered"}: which POST announced which
        # incident, for the diagnosis that follows it (the Telegram side keeps _alert_msgs)
        self._announced: dict = {}
        # a WAN message's incident: key -> {"id", "start"} (see _wan_incident)
        self._open: dict = {}
        self._no_address_said = 0.0
        self._load()

    # --- settings, read at every use -----------------------------------------------------------
    def _wcfg(self) -> dict:
        w = self.cfg.get("webhook")
        return w if isinstance(w, dict) else {}

    @property
    def enabled(self) -> bool:
        return bool(self._wcfg().get("enabled"))

    def url(self) -> str:
        return access.token(self.cfg, "webhook_url")

    def token(self) -> str:
        return access.token(self.cfg, "webhook")

    def _path(self) -> str:
        return os.path.expanduser(str(self._wcfg().get("queue_file") or "webhook_queue.json"))

    def events(self) -> set:
        e = self._wcfg().get("events")
        if not isinstance(e, (list, tuple)):
            e = DEFAULT_EVENTS
        return {str(x).strip().lower() for x in e}

    def wanted(self, ev: dict) -> bool:
        """The owner's filter: the kind of message is on the list and it is bad enough. A
        recovery counts as info; a diagnosis carries its incident's severity already."""
        floor = str(self._wcfg().get("min_severity") or "info").strip().lower()
        return (ev["category"] in self.events()
                and RANK[ev["severity"]] >= RANK.get(floor, 0))

    # --- an event, from what main hands over ------------------------------------------------------
    def compose(self, channel: str, text: str, key: str = "", event: Optional[dict] = None,
                now: Optional[float] = None) -> dict:
        """The event for one Telegram message. `event` is what the caller knows: category,
        type, severity (anything left out is read from the text and the door it left by),
        and for a gate message its title and incidents."""
        now = time.time() if now is None else now
        info = dict(event or {})
        category = info.get("category") if info.get("category") in CATEGORIES else "other"
        body = plain(text)
        head = body.split("\n", 1)[0]
        # the WAN watcher's own router-log findings are log news, not the internet's
        if category == "wan" and re.match(r"^\W*ROUTER LOG\b", head):
            category = "logs"
        # ...and a host log's logins and connection floods are security news: an owner who keeps
        # only `security` still hears that someone logged in from an unknown address
        if category == "logs" and _SECURITY_HEAD.match(head):
            category = "security"
        sev = (info.get("severity") and severity_name(info["severity"])) or emoji_severity(body) \
            or _CHANNEL_SEVERITY.get(channel, "info")
        title, message = split_text(text)
        if info.get("title"):
            title = str(info["title"])
        etype = info.get("type") or self._type_of(category, sev)
        ev = {"event_id": uuid.uuid4().hex, "event_type": etype, "category": category,
              "severity": sev, "title": title, "message": message, "timestamp": iso(now)}
        rows = info.get("incidents") or []
        if rows:
            ev["incidents"] = rows
            if len(rows) == 1:
                ev["incident_id"] = rows[0]["incident_id"]
                ev["device"] = self._with_mac(rows[0]["device"])
        elif category == "wan" and key:
            iid = self._wan_incident(key, sev == "recovery")
            ev["incident_id"] = iid
            ev["incidents"] = [{"incident_id": iid, "event_type": etype, "severity": sev}]
        elif info.get("device"):
            ev["device"] = info["device"]
        return ev

    def _with_mac(self, dev: dict) -> dict:
        """The device as one message names it alone: its MAC too, when the inventory has one."""
        mac = str(self._mac_of(dev["ip"]) or "") if self._mac_of and dev.get("ip") else ""
        return {**dev, "mac": mac} if mac else dict(dev)

    @staticmethod
    def _type_of(category: str, sev: str) -> str:
        if category == "wan":
            return "wan_up" if sev == "recovery" else "wan_down" if sev in ("critical", "high") else "wan_warning"
        return _TYPES.get(category, "notice")

    def _wan_incident(self, key: str, recovery: bool) -> str:
        """The id of the WAN incident a message belongs to. The watcher says only "this key";
        its episode (the gate's, which outlives the flaps) is the incident. Opened with the
        first message about an episode, kept for the "back" messages, dropped with the
        last, which the gate has already closed. An episode that began later is a new incident,
        even when no recovery ever closed the old id (the watcher skips one it judges redundant)."""
        start = float(self._episode_of(key) or 0.0)
        rec = self._open.get(key)
        if rec is not None and start and rec["start"] and start != rec["start"]:
            rec = None
        if rec is None:
            iid = (hashlib.sha1(f"{key}|{int(start)}".encode()).hexdigest()[:16] if start
                   else uuid.uuid4().hex[:16])
            rec = self._open[key] = {"id": iid, "start": start}
        elif start and not rec["start"]:
            rec["start"] = start
        if recovery and not start:
            self._open.pop(key, None)
        while len(self._open) > 100:           # a key that never closed: forget the oldest
            del self._open[next(iter(self._open))]
        return rec["id"]

    # --- handing a message in -----------------------------------------------------------------------
    def say(self, channel: str, text: str, key: str = "", event: Optional[dict] = None,
            now: Optional[float] = None) -> Optional[dict]:
        """Queue the webhook's copy of one Telegram message, if the owner wants it. Instant,
        and it never raises into the caller. Returns the event queued, else None."""
        if not self.enabled:
            return None
        if not self.url():
            if time.time() - self._no_address_said > 600:
                self._no_address_said = time.time()
                log.warning("webhook: switched on, but there is no address (tokens.webhook_url in "
                            "secrets.yaml, or LANOWL_WEBHOOK_URL): nothing is sent")
            return None
        info = dict(event or {})
        keys = info.pop("keys", None) or []
        # A message that closes what another kind announced ("follows": the recovery of a problem
        # only a digest named): with that kind filtered out, the receiver never heard of it, and
        # "recovered" would be news of nothing.
        follows = info.pop("follows", None)
        if follows and follows not in self.events():
            return None
        ev = self.compose(channel, text, key, info, now)
        if not self.wanted(ev):
            return None
        self.enqueue(ev, now)
        if ev["category"] == "down":
            self._announce(keys, ev["event_id"], now)
        return ev

    def _announce(self, keys: list, event_id: str, now: Optional[float]):
        now = time.time() if now is None else now
        for k in keys:
            self._announced[k["key"]] = {"event_id": event_id, "incident_id": k["incident_id"],
                                         "ts": now, "answered": False}
        # two days is far longer than a triage takes, as on the Telegram side
        for k in [k for k, v in self._announced.items() if now - v["ts"] > 2 * 86400]:
            del self._announced[k]
        while len(self._announced) > 500:
            del self._announced[next(iter(self._announced))]

    def diagnose(self, issues: dict, note_for: Callable, now: Optional[float] = None) -> int:
        """The owl's diagnosis, as a follow-up to the POST that announced each incident: one
        follow-up per announcing POST (Telegram edits one message once), naming it in
        `in_reply_to` and carrying the same incident ids. `issues` is {key: issue};
        `note_for(issues)` is the Telegram note for a group of them. An incident the webhook
        never announced (filtered out, or before this start) has nothing to reply to.
        Returns how many were queued."""
        if not self.enabled or not self.url():
            return 0
        groups: dict = {}
        for key, issue in issues.items():
            rec = self._announced.get(key)
            if rec is not None and not rec["answered"]:
                groups.setdefault(rec["event_id"], []).append((issue, rec))
        n = 0
        for event_id, rows in groups.items():
            for _, rec in rows:
                rec["answered"] = True
            text = plain(note_for([i for i, _ in rows]))
            if not text:
                continue
            sev = max((severity_name(i.get("severity")) for i, _ in rows), key=lambda s: RANK[s])
            devs = [{"name": str(i.get("device") or ""), "ip": str(i.get("ip") or "")} for i, _ in rows]
            ev = {"event_id": uuid.uuid4().hex, "event_type": "diagnosis", "category": "diagnosis",
                  "severity": sev,
                  "title": f"Diagnosis: {devs[0]['name']}" if len(rows) == 1 else f"Diagnosis: {len(rows)} issues",
                  "message": text, "timestamp": iso(time.time() if now is None else now),
                  "in_reply_to": event_id,
                  "incidents": [{"incident_id": rec["incident_id"], "event_type": "diagnosis",
                                 "severity": sev, "device": d} for (_, rec), d in zip(rows, devs)]}
            if len(rows) == 1:
                ev["incident_id"] = rows[0][1]["incident_id"]
                ev["device"] = self._with_mac(devs[0])
            if self.wanted(ev):
                self.enqueue(ev, now)
                n += 1
        return n

    # --- the queue -----------------------------------------------------------------------------------------
    def _load(self):
        try:
            with open(self._path(), encoding="utf-8") as f:
                items = json.load(f)
            self._items = [it for it in items if isinstance(it, dict) and isinstance(it.get("event"), dict)
                           and it["event"].get("event_id") and isinstance(it.get("ts"), (int, float))][-MAX_ITEMS:]
            if self._items:
                log.info("webhook: %d message(s) waiting from a previous run", len(self._items))
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("webhook: queue not read: %s", type(e).__name__)

    def _save(self):
        try:
            tmp = self._path() + ".tmp"
            with open(tmp, "w", encoding="utf-8", errors="replace") as f:   # as post(): never unsaved
                json.dump(self._items, f, ensure_ascii=False)
            os.replace(tmp, self._path())          # whole or not at all, as the Telegram outbox
        except Exception as e:
            log.warning("webhook: queue not saved: %s", e)

    @property
    def pending(self) -> int:
        return len(self._items)

    def enqueue(self, ev: dict, now: Optional[float] = None):
        """Append and wake the worker. Synchronous and instant: a file write, never HTTP."""
        with self._lock:
            self._items.append({"ts": time.time() if now is None else now, "event": ev})
            over = len(self._items) - self.max_items
            if over > 0:
                del self._items[:over]
                log.warning("webhook: %d waiting, the limit is %d: the oldest %d dropped",
                            len(self._items), self.max_items, over)
            self._save()
        self._poke()

    def _poke(self):
        loop, ev = self._loop, self._wake
        if loop is None or ev is None:
            return
        with contextlib.suppress(RuntimeError):    # the loop has closed: nothing to wake
            loop.call_soon_threadsafe(ev.set)

    def _expire(self, now: float):
        with self._lock:
            keep = [it for it in self._items if now - it["ts"] <= self.max_age_s]
            if len(keep) != len(self._items):
                log.warning("webhook: %d message(s) older than %d h dropped, never delivered",
                            len(self._items) - len(keep), self.max_age_s // 3600)
                self._items = keep
                self._save()

    def _pop(self):
        with self._lock:
            if self._items:
                self._items.pop(0)
                self._save()

    # --- the worker ------------------------------------------------------------------------------------------
    async def run(self):
        """Deliver, in order, for as long as lanowl runs. Its own task: a receiver that hangs
        costs this loop a wait and nothing else."""
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        while not self._stopped:
            try:
                delay = await self.turn()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # the type only: an exception raised while the address is in hand may quote it
                log.error("webhook: the delivery loop failed (%s); trying again", type(e).__name__)
                delay = self.head_wait_s
            self._wake.clear()
            if delay is None:
                # idle: until something is queued, and now and then to age the queue
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), 60)
            else:
                # behind a failing head: what arrives meanwhile queues up behind it, in order
                await asyncio.sleep(delay)

    def stop(self):
        self._stopped = True
        self._poke()

    async def turn(self) -> Optional[float]:
        """Deliver from the head until the queue is empty (None) or the head cannot be
        delivered (seconds until it is tried again). A failing head holds the rest: order is
        the point of a queue."""
        while True:
            now = time.time()
            self._expire(now)
            if not self.enabled:
                # switched off: nothing is sent, and what waits would be stale when it is switched on
                with self._lock:
                    if self._items:
                        log.info("webhook: switched off, %d waiting message(s) dropped", len(self._items))
                        self._items = []
                        self._save()
                self.failing_since = self.next_try_ts = 0.0
                return None
            if not self._items:
                self.failing_since = self.next_try_ts = 0.0
                return None
            head = self._items[0]
            outcome = await self._round(head["event"])
            if outcome != "failed":
                self.next_try_ts = 0.0
                continue
            self.next_try_ts = time.time() + self.head_wait_s
            return self.head_wait_s

    async def _round(self, ev: dict) -> str:
        """One message: up to three tries. "sent", "dropped" (the receiver refused it for good)
        or "failed" (still undelivered: it stays at the head)."""
        host = _host(self.url())
        for n in range(1, len(self.gaps) + 2):
            r = await self.post(ev)
            if r["kind"] == "ok":
                self.last_ok_ts, self.failing_since = time.time(), 0.0
                self._pop()
                return "sent"
            self.last_error, self.last_error_ts = r["why"], time.time()
            if r["kind"] == "rejected":
                log.error("webhook: %s refused a message for good, dropped (%s)", host or "the receiver", r["why"])
                self.failing_since = 0.0
                self._pop()
                return "dropped"
            self.failing_since = self.failing_since or self.last_error_ts
            log.warning("webhook: %s did not take a message (%s; try %d of %d)", host or "the receiver",
                        r["why"], n, len(self.gaps) + 1)
            if n <= len(self.gaps):
                await asyncio.sleep(self.gaps[n - 1])
        return "failed"

    async def post(self, ev: dict, said_n: int = SAID_N) -> dict:
        """One POST of one event, as the settings say. {"kind": "ok" | "transient" | "rejected",
        "status", "why", "said"}: transient is worth trying again (a timeout, a refused
        connection, 408, 429, 5xx), rejected is not (any other 4xx, a redirect, a setting that
        cannot be rendered)."""
        wcfg = self._wcfg()
        url, token = self.url(), self.token()
        hide = _hide(url, token)

        def out(kind: str, why: str, status=None, said: str = "") -> dict:
            return {"kind": kind, "status": status, "why": why, "said": said}

        if not url:
            return out("transient", "no address: tokens.webhook_url in secrets.yaml, or LANOWL_WEBHOOK_URL")
        try:
            parts = urlsplit(url)
            ok_url = parts.scheme in ("http", "https") and bool(parts.hostname)
        except ValueError:
            ok_url = False
        if not ok_url:
            return out("rejected", "the address is not an http:// or https:// one")
        try:
            target, body = render(ev, wcfg, url)
            headers = _headers(wcfg, token)
            # "replace": a lone surrogate (a device's JSON can carry one) is a "?", not a message
            # refused for good
            data = json.dumps(body, ensure_ascii=False).encode("utf-8", "replace")
        except (ValueError, TypeError) as e:
            return out("rejected", _mask(str(e), hide))
        import aiohttp
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout_s)) as s:
                # never a redirect: it would carry the token to whatever host the answer names
                async with s.post(target, data=data, headers=headers, allow_redirects=False,
                                  ssl=False if wcfg.get("verify_tls") is False else True) as r:
                    status = r.status
                    raw = await r.content.read(2048)
        except asyncio.TimeoutError:
            return out("transient", f"no answer within {self.timeout_s:g} s")
        except aiohttp.InvalidURL:
            return out("rejected", "the address is not valid")
        except aiohttp.ClientConnectorCertificateError:
            return out("transient", "the TLS certificate was not accepted (webhook.verify_tls: false "
                                    "for a self-signed one)")
        except aiohttp.ClientConnectorError:
            return out("transient", "could not connect")
        except (aiohttp.ClientError, OSError) as e:
            return out("transient", f"the connection failed ({type(e).__name__})")
        except ValueError:
            return out("rejected", "the request could not be made (a header or the address)")
        said = _mask(raw.decode("utf-8", "replace"), hide, said_n)
        if 200 <= status < 300:
            return out("ok", f"HTTP {status}", status, said)
        if 300 <= status < 400:
            return out("rejected", f"HTTP {status}: redirected, not followed", status, said)
        if status in (408, 429) or status >= 500:
            return out("transient", f"HTTP {status}" + (f": {said}" if said else ""), status, said)
        return out("rejected", f"HTTP {status}" + (f": {said}" if said else ""), status, said)

    # --- for the dashboard ---------------------------------------------------------------------------------------
    def status(self) -> dict:
        return {"enabled": self.enabled, "url_set": bool(self.url()), "pending": len(self._items),
                "last_ok_ts": self.last_ok_ts, "last_error": self.last_error,
                "last_error_ts": self.last_error_ts, "failing_since": self.failing_since,
                "next_try_ts": self.next_try_ts}

    async def test(self) -> dict:
        """One POST now, not queued: Settings' "Send test notification". It uses the settings
        as saved and works while the channel is off, so it can be tried before it is switched on.
        {"ok", "status", "said"}: what the receiver answered, its words masked, at most 200."""
        if not self.url():
            return {"ok": False, "status": None,
                    "said": "No address: set tokens.webhook_url in secrets.yaml (Settings → Secrets), "
                            "or LANOWL_WEBHOOK_URL."}
        ev = {"event_id": uuid.uuid4().hex, "event_type": "test", "category": "other",
              "severity": "info", "title": "lanowl test",
              "message": "If you can read this, lanowl's webhook works.", "timestamp": iso(time.time())}
        r = await self.post(ev, said_n=200)
        # a failed test says why, in words; a delivered one says what the receiver answered
        said = r["said"] if r["kind"] == "ok" else (r["why"] if len(r["why"]) <= 200 else r["why"][:199] + "…")
        return {"ok": r["kind"] == "ok", "status": r["status"], "said": said}


def report(cfg: dict) -> tuple:
    """(text, problems) for `lanowl --check`: off, or on with its format and the receiver's host
    name (never the address). Sends nothing."""
    w = cfg.get("webhook") if isinstance(cfg.get("webhook"), dict) else {}
    if not w.get("enabled"):
        return "Webhook: off (webhook.enabled)", 0
    fmt = str(w.get("format") or "generic").strip().lower()
    url = access.token(cfg, "webhook_url")
    host = _host(url)
    where = f"to {host}" if host else ("an address that is not http(s)" if url else "no address yet")
    lines, bad = [f"Webhook: on · {fmt} · {where}"], 0

    def row(what: str, text: str):
        nonlocal bad
        bad += 1
        lines.append(f"  ✗ {what:<15} {text}")

    if fmt not in FORMATS:
        row("webhook.format", f"{fmt!r} is not one of {', '.join(FORMATS)}")
    elif fmt == "template" and not (isinstance(w.get("template"), (dict, list)) and w.get("template")):
        row("webhook.template", "format is template, and the template is empty")
    ev = w.get("events")
    if ev is not None and not isinstance(ev, list):
        row("webhook.events", "is a list of kinds of message")
    else:
        odd = [str(x) for x in (ev or []) if str(x).strip().lower() not in CATEGORIES]
        if odd:
            row("webhook.events", f"{', '.join(odd)}: not a kind of message ({', '.join(CATEGORIES)})")
    floor = str(w.get("min_severity") or "info").strip().lower()
    if floor not in MIN_SEVERITIES:
        row("webhook.min_severity", f"{floor!r} is not one of {', '.join(MIN_SEVERITIES)}")
    return "\n".join(lines), bad
