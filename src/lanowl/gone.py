"""A machine lanowl no longer watches takes its LIVE state with it.

Taking a device out of the inventory — or out of what a feature does for it (`manage`) — is
applied by a restart. Each feature keeps rows per machine in its own record (what it read, its
findings, what the owner dismissed). A row of a machine the feature no longer works from would
go on showing on the Security tab and in the model's records, and nothing would ever refresh or
remove it. So each feature drops what belongs to an address it no longer works from: at the
start (Lanowl.resume_alerts) and after each of its runs, one INFO line when something went.

History is not live state and stays: the samples, transitions, events and sightings, the
Timeline, past alerts and actions, the owl's fixes, the scorecard, the save history.
"""
from __future__ import annotations

from .report import plural


def managed(inv, feature: str) -> set:
    """The addresses whose inventory entry names `feature` in its `manage`, as the owner wrote
    it — planned at this start or not. A login missing at a start (a typo in secrets.yaml, a
    login renamed) leaves the feature without the device until it is fixed; it must not cost what
    the feature learned about it (the owner's dismissals, a configuration's baseline)."""
    out = set()
    for d in (getattr(inv, "devices", None) or []):
        m = d.attrs.get("manage") or []
        m = [m] if isinstance(m, str) else m if isinstance(m, (list, tuple)) else []
        if feature in {str(x).strip().lower() for x in m}:
            out.add(d.ip)
    return out


def drop_rows(rows: dict, watched) -> list:
    """Remove from `rows` (keyed by address) every key not in `watched`; the keys removed."""
    gone = [k for k in rows if k not in watched]
    for k in gone:
        del rows[k]
    return gone


def say(log, module: str, gone, done: str = "checked"):
    """"updates: 1 machine no longer checked, its rows dropped: 192.168.10.5" — nothing when
    nothing went."""
    gone = sorted(set(gone))
    if gone:
        log.info("%s: %s no longer %s, %s rows dropped: %s", module, plural(len(gone), "machine"),
                 done, "its" if len(gone) == 1 else "their", ", ".join(gone))
