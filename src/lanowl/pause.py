"""Devices the owner has switched off on purpose: paused, not down.

A device switched off for a holiday, or unplugged for a while, should not page. Deleting it
from the inventory loses the way back, and an `expect_offline` schedule is for gear that
sleeps every day, not for a holiday. So it can be paused.

A paused device is still probed and recorded, so the logbook stays true. Nothing reports it,
though — no issue, no alert, no digest line, no model finding, no share of a group majority.
The dashboard shows it as Paused.

A pause ends only by hand: /resume on Telegram, or the switch on the dashboard. Manual stop,
manual start: a device coming back never decides for the owner that it is watched again. The
digests and the weekly review list every pause, which is what keeps one from being
forgotten.

What the owner was told matters as much as what is true (see alerts.py): pausing closes the
device's open incident without a "back online" — it is off on purpose, not fixed — and every
pause and resume is said on Telegram. The dashboard has no login, and a pause nobody hears
about would be the quietest way to blind the monitor to the alarm or the cameras.

Pure bookkeeping, no I/O: the Auditor persists `dump()` in the SQLite `records` table and
writes each pause and resume to `events`, which is where `intervals()` reads history from.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

log = logging.getLogger("lanowl.pause")

EVENT_KINDS = ("pause", "resume")


class Pauses:
    def __init__(self):
        # ip -> {"ts": paused at, "by": dashboard|telegram, "name"}
        self._p: dict[str, dict] = {}

    # --- the record ---------------------------------------------------------
    def dump(self) -> dict:
        return {ip: dict(e) for ip, e in self._p.items()}

    def restore(self, data: Optional[dict], known: Optional[dict] = None) -> int:
        """Take back the saved pauses. `known` is {ip: name} for the inventory as loaded.

        A pause is keyed by the address the device had when it was paused, which may be a
        DHCP address the inventory does not list (Inventory.rebind moved it there). Such a
        pause follows the device's name back to its configured address, and discovery
        carries it forward again with rename(). One whose device has left the inventory is
        dropped: a pause must never outlive the thing it was about."""
        self._p = {}
        by_name: dict[str, list] = {}
        for ip, name in (known or {}).items():
            by_name.setdefault(str(name).casefold(), []).append(ip)
        for ip, e in (data or {}).items():
            if not isinstance(e, dict) or not e.get("ts"):
                continue
            if known is not None and ip not in known:
                same = by_name.get(str(e.get("name") or "").casefold(), [])
                if len(same) != 1 or same[0] in (data or {}):
                    log.info("dropping the pause of %s: no longer in the inventory", ip)
                    continue
                ip = same[0]
            self._p[ip] = {"ts": float(e["ts"]), "by": str(e.get("by") or ""),
                           "name": str(e.get("name") or ip)}
        return len(self._p)

    # --- reading ------------------------------------------------------------
    def is_paused(self, ip: str) -> bool:
        return ip in self._p

    def get(self, ip: str) -> Optional[dict]:
        return self._p.get(ip)

    def ips(self) -> set:
        return set(self._p)

    def entries(self) -> list[dict]:
        """Every pause, oldest first, each with its ip."""
        return sorted(({"ip": ip, **e} for ip, e in self._p.items()), key=lambda e: e["ts"])

    # --- changing -----------------------------------------------------------
    def pause(self, ip: str, name: str, by: str, now: Optional[float] = None) -> Optional[dict]:
        """Pause `ip`; None if it already was."""
        if ip in self._p:
            return None
        self._p[ip] = {"ts": time.time() if now is None else now, "by": by, "name": name}
        return {"ip": ip, **self._p[ip]}

    def resume(self, ip: str) -> Optional[dict]:
        e = self._p.pop(ip, None)
        return {"ip": ip, **e} if e else None

    def renamed(self, ip: str, name: str) -> None:
        """The device was given a new name (names.py): a restore finds its pause by
        the name it has now."""
        if ip in self._p:
            self._p[ip]["name"] = name

    def rename(self, old_ip: str, new_ip: str):
        """DHCP moved the device (Inventory.rebind): the pause goes with it."""
        if old_ip in self._p and new_ip not in self._p:
            self._p[new_ip] = self._p.pop(old_ip)


# --- history ------------------------------------------------------------------
def event_detail(ip: str, name: str, by: str) -> str:
    return json.dumps({"ip": ip, "name": name, "by": by}, ensure_ascii=False)


def intervals(events: list, current: Optional[dict] = None,
              now: Optional[float] = None) -> dict[str, list]:
    """{ip: [(start, end), ...]} — every pause in `events` (the pause/resume rows of the
    events table, any order), plus the ones still running (`current`: Pauses.dump()).

    A resume whose pause is older than the rows read started before anyone can say: it is
    taken as open from the beginning. A pause still running ends at `now`."""
    now = time.time() if now is None else now
    current = current or {}
    out: dict[str, list] = {}
    opened: dict[str, float] = {}
    for ev in sorted(events or [], key=lambda e: e["ts"]):
        if ev.get("kind") not in EVENT_KINDS:
            continue
        try:
            ip = json.loads(ev.get("detail") or "{}").get("ip")
        except ValueError:
            continue
        if not ip:
            continue
        if ev["kind"] == "pause":
            opened.setdefault(ip, ev["ts"])
        else:
            out.setdefault(ip, []).append((opened.pop(ip, 0.0), ev["ts"]))
    for ip, start in opened.items():
        # a pause with no resume on record: still running, or its record was lost with the
        # device (restore() drops it) — then nothing is known after it began
        out.setdefault(ip, []).append((start, now if ip in current else start))
    for ip, e in current.items():
        if not any(b >= now for _, b in out.get(ip, [])):
            out.setdefault(ip, []).append((float(e["ts"]), now))
    return out


def paused_at(iv: dict, ip: str, ts: float) -> bool:
    return any(a <= ts <= b for a, b in iv.get(ip, ()))


def overlaps(iv: dict, ip: str, a: float, b: float) -> bool:
    """Did any pause of `ip` touch the span a..b? An outage the owner paused part-way
    through was, by their word, the device being off on purpose."""
    return any(pa <= b and a <= pb for pa, pb in iv.get(ip, ()))


def find_devices(devices, query: str) -> list:
    """The devices `query` names: an exact address, an exact name, or every device whose
    name holds all its words ("tv" -> the TV; "shelly lamp" -> one Shelly among several)."""
    q = " ".join(str(query or "").split())
    if not q:
        return []
    exact_ip = [d for d in devices if d.ip == q]
    if exact_ip:
        return exact_ip
    cf = q.casefold()
    exact = [d for d in devices if d.name.casefold() == cf]
    if exact:
        return exact
    words = cf.split()
    return [d for d in devices if all(w in d.name.casefold() for w in words)]
