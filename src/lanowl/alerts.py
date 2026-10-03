"""Alert gating: one Telegram message per incident, not one per sweep.

The sweep re-derives the whole issue list every 60s, so the raw signal is "these
issues exist right now". Turning that into messages naively — alert when a key
appears, recover when it disappears — pages once per *edge*, and an internet line can flap
daily: a single evening of a flapping line can produce eighteen messages (three down/up
cycles x three correlated issues x two edges each).

This module collapses edges into *episodes*. An episode opens when an issue first
appears and stays open across flaps; it only closes after the issue has been
continuously clear for `recovery_confirm_s`. Inside one episode the user hears at
most one alert and one recovery, and for `cooldown_s` after it closes the same key
stays quiet — a re-fire in that window is folded into the flap count instead of
paging again. If it is still down when the cooldown ends, it pages once more, so a
real problem that never healed cannot go silent forever.

Everything raised in the same sweep is returned together so the caller can send it
as ONE message: the WAN dying takes the camera group and the network group with it,
and that is one event to a human, not three.

Pure logic, no I/O — the caller formats and sends. Time is injectable for tests.
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Optional

log = logging.getLogger("lanowl.alerts")

# event kinds returned by AlertGate.update()
NEW = "new"            # first time this incident is announced
STILL = "still"        # it came back / never left and the cooldown expired
RECOVERED = "recovered"

# After a restart the detectors need a sweep or two to see again what the last process saw.
# An incident that looks clear during that catch-up and then reappears never flapped.
RESUME_GRACE_S = 300.0


@dataclass
class Episode:
    """One incident for one issue key, spanning any number of flaps."""
    key: str
    issue: dict
    started: float             # when the incident began (see _open)
    last_seen: float
    clear_since: float = 0.0   # 0 while the issue is present; else when it went away
    closed_at: float = 0.0     # 0 while open; else when the recovery was confirmed
    notified_at: float = 0.0   # last time we said anything about this key
    announced: bool = False    # the user currently believes this issue is open
    pending: bool = True       # an occurrence is waiting to be announced
    silent_until: float = 0.0  # ...but not before this instant (cooldown)
    flaps: int = 0             # re-fires folded into this episode

    def duration(self, now: float) -> float:
        return max(0.0, (self.clear_since or now) - self.started)


def _open(key: str, issue: dict, now: float) -> Episode:
    """A new episode, dated from the issue's own `since` when it has one.

    The gate first sees a `down` issue on the sweep that confirmed it, which is
    `debounce_fails` sweeps after the device actually stopped answering — a minute on the
    LAN, five for a site behind the tunnel. The issue carries the first miss as `since`
    (report.build_report), and that is when the incident began: "down for 6m" and "since
    14:02:27" should both count from there. The gate's own clock is the fallback for
    anything that cannot date itself (a degraded service, a group majority). A later
    flap never moves `started` — the freshest issue's `since` is the latest drop, but the
    episode is the whole incident, dated from the first."""
    since = float(issue.get("since") or 0)
    return Episode(key, issue, started=min(now, since) if since else now, last_seen=now)


@dataclass
class AlertEvent:
    kind: str            # NEW | STILL | RECOVERED
    issue: dict
    episode: Episode
    flaps: int = 0
    duration_s: float = 0.0


@dataclass
class AlertGate:
    """Feed it the current critical issues each sweep; get back what to actually say."""

    recovery_confirm_s: float = 900.0   # stay clear this long before announcing recovery
    cooldown_s: float = 3600.0          # after that, same key stays quiet this long
    renotify_after_s: float = 0.0       # 0 = never re-ping while an issue stays open
    _eps: dict = field(default_factory=dict)
    _resumed_at: float = 0.0            # when restore() took over a previous process's record

    @classmethod
    def from_config(cls, cfg: dict) -> "AlertGate":
        a = (cfg or {}).get("alerts", {}) or {}
        return cls(
            recovery_confirm_s=float(a.get("recovery_confirm_s", 900)),
            cooldown_s=float(a.get("cooldown_s", 3600)),
            renotify_after_s=float(a.get("renotify_after_s", 0)),
        )

    # --- main entry point --------------------------------------------------
    def update(self, current: dict, now: Optional[float] = None) -> list[AlertEvent]:
        """current: {issue_key: issue_dict} for every critical issue in this sweep."""
        now = time.time() if now is None else now
        events: list[AlertEvent] = []
        events += self._handle_active(current, now)
        events += self._handle_cleared(current, now)
        self._prune(now)
        return events

    def _handle_active(self, current: dict, now: float) -> list[AlertEvent]:
        events = []
        for key, issue in current.items():
            ep = self._eps.get(key)
            if ep is None:
                ep = self._eps[key] = _open(key, issue, now)
            elif ep.closed_at:
                if now - ep.closed_at >= self.cooldown_s:
                    # the previous episode is old news: this is a genuinely new incident
                    ep = self._eps[key] = _open(key, issue, now)
                else:
                    # re-fire inside the cooldown: same incident, reopened. Worth a word,
                    # but not before the quiet window is over — if it heals first, the
                    # user never needed to know (see _handle_cleared, which drops pending).
                    ep.silent_until = ep.closed_at + self.cooldown_s
                    ep.closed_at = 0.0
                    ep.clear_since = 0.0
                    ep.flaps += 1
                    ep.pending = True
            elif ep.clear_since:
                # came back before the recovery was confirmed -> the episode never ended.
                # Not a flap if it only looked clear while a restarted process caught up.
                if not (self._resumed_at and
                        self._resumed_at <= ep.clear_since < self._resumed_at + RESUME_GRACE_S):
                    ep.flaps += 1
                ep.clear_since = 0.0
            ep.issue = issue          # keep the freshest detail text
            ep.last_seen = now

            if ep.pending and now >= ep.silent_until:
                ep.pending = False
                ep.announced = True
                ep.notified_at = now
                kind = STILL if ep.flaps else NEW
                events.append(AlertEvent(kind, issue, ep, ep.flaps, ep.duration(now)))
                if kind == STILL:
                    log.warning("re-alerting %s after cooldown (%d flap(s) folded)", key, ep.flaps)
            elif ep.pending:
                log.debug("alert suppressed (cooldown %.0fs left): %s",
                          ep.silent_until - now, key)
            elif ep.announced and self.renotify_after_s and \
                    (now - ep.notified_at) >= self.renotify_after_s:
                ep.notified_at = now
                events.append(AlertEvent(STILL, issue, ep, ep.flaps, ep.duration(now)))
        return events

    def _handle_cleared(self, current: dict, now: float) -> list[AlertEvent]:
        events = []
        for key, ep in self._eps.items():
            if key in current or ep.closed_at:
                continue
            if not ep.clear_since:
                ep.clear_since = now
                continue
            if now - ep.clear_since < self.recovery_confirm_s:
                continue
            ep.closed_at = now
            duration = ep.duration(now)
            # A re-fire that healed before its cooldown expired was never announced —
            # so there is nothing to announce as fixed either. Drop it silently.
            ep.pending = False
            if ep.announced:
                ep.announced = False
                ep.notified_at = now
                events.append(AlertEvent(RECOVERED, ep.issue, ep, ep.flaps, duration))
            ep.flaps = 0
        return events

    def forget(self, match) -> list[str]:
        """Drop every episode whose issue `match(issue)` accepts — no recovery, no cooldown.

        For a device the owner has just paused (pause.py): its incident did not end,
        it stopped being one. Letting it close the normal way would send "back online" for a
        TV that is off on purpose, fifteen minutes after being told to stop watching it. If
        the device is resumed and still down, the next sweep opens a fresh episode, which is
        exactly the message that is owed then."""
        keys = [k for k, e in self._eps.items() if match(e.issue)]
        for k in keys:
            del self._eps[k]
        return keys

    def rekey(self, fn) -> int:
        """Rename keys: a device renamed on the dashboard (names.py). Each episode
        carries on under its new key, its issue under the new name: no recovery, no new
        alert. `fn(key)` is the key it becomes (the key itself when untouched)."""
        n, eps = 0, {}
        for k, e in self._eps.items():
            k2 = fn(k)
            if k2 != k:
                n += 1
                e.key = k2
                e.issue = {**e.issue, "device": k2.split(":", 3)[-1]}
            eps[k2] = e
        self._eps = eps
        return n

    def _prune(self, now: float):
        horizon = self.cooldown_s + self.recovery_confirm_s + 3600
        for key in [k for k, e in self._eps.items()
                    if e.closed_at and (now - e.closed_at) > horizon]:
            del self._eps[key]

    # --- across restarts ---------------------------------------------------
    def dump(self) -> dict:
        """Every episode as plain JSON-safe data, for restore() in the next process."""
        return {key: asdict(ep) for key, ep in self._eps.items()}

    def restore(self, data: Optional[dict], now: Optional[float] = None) -> int:
        """Take back a previous process's episodes; returns how many.

        The gate is the record of what the user has been told. Kept only in memory, every
        restart would forget it and the first sweep would announce every open incident as
        NEW again: a device that had been down for hours, and paged already, paged again
        after each restart. Restored, an open incident stays announced, its recovery is
        still owed, and a cooldown keeps running across the restart."""
        now = time.time() if now is None else now
        known = {f.name for f in fields(Episode)}
        n = 0
        for key, raw in (data or {}).items():
            try:
                self._eps[key] = Episode(**{k: v for k, v in raw.items() if k in known})
                n += 1
            except (TypeError, AttributeError):
                log.warning("dropping an unreadable episode from the saved record: %s", key)
        self._resumed_at = now
        self._prune(now)
        return n

    # --- introspection (dashboard / tests) ---------------------------------
    def episode_start(self, key: str) -> float:
        """When the currently-open episode for `key` began; 0.0 if none is open.

        Lets a caller scope its own evidence to the incident the gate is tracking —
        the WAN watcher uses it to report the outage seconds the router recorded
        *during this episode* rather than every flap it still remembers."""
        ep = self._eps.get(key)
        return 0.0 if (ep is None or ep.closed_at) else ep.started

    def episode_flaps(self, key: str) -> int:
        """Re-fires folded into the currently-open episode for `key`; 0 if none is open.

        With `episode_start`, this is what lets the digest describe an incident the way
        the alert does — 'unstable since 14:02 · 3 outages' rather than a start time that
        quietly pretends the device has been down continuously."""
        ep = self._eps.get(key)
        return 0 if (ep is None or ep.closed_at) else ep.flaps

    def silenced(self, key: str, now: Optional[float] = None) -> bool:
        """Is this key inside a quiet window right now?

        For a caller that sends its own extra message about an incident this gate is
        tracking (the WAN watcher says "there is no internet at all" alongside the
        incident alert). The cooldown is a property of the *incident*, not of one
        message: anything else said about it has to respect the same window, or a
        flapping line pages through a cooldown that is no longer a cooldown."""
        ep = self._eps.get(key)
        now = time.time() if now is None else now
        return bool(ep and not ep.closed_at and ep.silent_until and now < ep.silent_until)

    def open_keys(self) -> list[str]:
        return [k for k, e in self._eps.items() if not e.closed_at]

    def announced_keys(self) -> list[str]:
        return [k for k, e in self._eps.items() if e.announced]
