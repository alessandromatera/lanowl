"""The logbook: every device that went down or came back, from lanowl's own history.

    python -m lanowl.logbook                          # the last 7 days, newest first
    python -m lanowl.logbook --days 14 --ip 10.8.0.9
    docker exec lanowl python -m lanowl.logbook

The same list is published retained on `<base_topic>/logbook` whenever a device changes
state. Where the event log shows only what was announced, this is every confirmed down and
up, announced or not, kept in SQLite for `state.history_days`.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

from .model import load_config, load_inventory
from .pause import intervals, overlaps
from .report import human_duration, label
from .state import StateStore
from .sweep import offline_by_design, offline_mode_ips


def entries(state: StateStore, inv, cfg: dict, now: float, days: float = 7.0,
            ip=None, limit: int = 200, paused: Optional[dict] = None,
            paused_now=()) -> list[dict]:
    """StateStore.logbook(), with each row named, scheduled sleep marked `by_design` and a
    device switched off on purpose marked `paused`.

    `paused` is {ip: [(start, end)]} (pause.intervals); an outage any pause touched is the
    owner's doing, both its `down` and its `up`. `paused_now` are the devices paused right
    now, whose still-open outage is theirs whenever it began.

    The name comes from the inventory as it is now, falling back to the one recorded with
    the transition for a device that has since left it."""
    scheduled = offline_mode_ips(inv)
    rows = state.logbook(now - days * 86400, ip=ip, limit=limit)
    paused = paused or {}
    ends, running = {}, {}           # id(down entry) -> when its `up` came
    for e in reversed(rows):         # oldest first: each `up` closes the `down` before it
        if e["kind"] == "down":
            running[e["ip"]] = e
        elif e["ip"] in running:
            ends[id(running.pop(e["ip"]))] = e["ts"]
    for e in rows:
        if e["kind"] == "up":
            a, b = e["ts"] - (e.get("down_for") or 0), e["ts"]
        else:
            a, b = e["ts"], (now if e.get("open") else ends.get(id(e), e["ts"]))
        e["paused"] = overlaps(paused, e["ip"], a, b) or \
            bool(e["kind"] == "down" and e.get("open") and e["ip"] in paused_now)
        dev = inv.get(e["ip"])
        e["name"] = dev.name if dev else e["name"]
        e["label"] = label(e["name"], e["ip"])
        mode = scheduled.get(e["ip"])
        e["by_design"] = bool(mode) and offline_by_design(cfg, mode, e["ts"])
        if e.get("down_for") is not None:
            e["down_for_text"] = human_duration(e["down_for"])
    return rows


def payload(state: StateStore, inv, cfg: dict, now: float, days: float = 7.0,
            paused: Optional[dict] = None, paused_now=()) -> dict:
    return {"ts": now, "days": days,
            "entries": entries(state, inv, cfg, now, days, paused=paused, paused_now=paused_now)}


def main():
    ap = argparse.ArgumentParser(description="Every device down and up, newest first")
    ap.add_argument("--days", type=float, default=7.0)
    ap.add_argument("--ip", default=None, help="only this device")
    ap.add_argument("--config", default=None)
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--db", default=None, help="sqlite file (default: state.db_path)")
    args = ap.parse_args()

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = load_config(args.config or os.path.join(here, "config.yaml"))
    inv = load_inventory(args.inventory or os.path.join(here, "inventory.yaml"))
    db = args.db or cfg.get("state", {}).get("db_path", "lanowl_state.sqlite")
    if not os.path.exists(db):      # StateStore would quietly create an empty one
        sys.exit(f"no history at {os.path.abspath(db)} — run from lanowl's state "
                 f"directory, or pass --db")
    state = StateStore(db)
    state.keep = inv.owns          # as lanowl reads it; --ip still shows any address
    now = time.time()
    rec = state.load_record("paused") or {}
    iv = intervals([e for k in ("pause", "resume") for e in state.events(0, kind=k, limit=5000)],
                   rec, now)
    for e in entries(state, inv, cfg, now, args.days, ip=args.ip, limit=100_000,
                     paused=iv, paused_now=set(rec)):
        when = time.strftime("%a %d/%m %H:%M:%S", time.localtime(e["ts"]))
        if e["kind"] == "down":
            what, note = "DOWN", (f"still down, {human_duration(now - e['ts'])}"
                                  if e.get("open") else "")
        else:
            what, note = "up  ", (f"after {e['down_for_text']} down"
                                  if e.get("down_for_text") else "")
        sched = "  (paused)" if e["paused"] else "  (on schedule)" if e["by_design"] else ""
        print(f"{when}  {what}  {e['label']}{sched}" + (f"  — {note}" if note else ""))
    state.close()


if __name__ == "__main__":
    main()
