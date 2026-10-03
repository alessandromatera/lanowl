"""The Timeline: seven days as one stream, for the dashboard (GET /api/timeline).

Ups & downs, what Telegram was told, the log checks, the new devices and the action history
are five places to look for one story. When the internet blacks out a minute after a router
update the owner approved, the two belong side by side.

Outages are grouped into INCIDENTS the way the alert gate groups them: what the gate raised
together is one problem and one message. Every Telegram message records the issue keys it
announced (main._emit_telegram), and outages announced by one message are one incident. For
devices that never page, outages that start within
GROUP_S of each other are one incident — the gate raises those in the same sweep. Asleep on
schedule and paused are grouped apart: they are nobody's problem, and never merged with one.

Each incident and each internet outage carries what happened around it: the Telegram messages
about it, an internet outage at the same moment, and an action on the network that ran just
before (a likely cause, said as "after", never as "because").

`assemble()` is pure (tested in tests/test_timeline.py); `build()` gathers its inputs.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .model import wan_links
from .wanexplain import merge

GROUP_S = 180.0       # outages that start this close together are one incident
CAUSE_S = 600.0       # an action on the network this long before may be what did it
WAN_NEAR_S = 180.0    # an internet outage this close to an incident's start is part of it
RAN = ("done", "failed", "running")       # approved and not run (skipped, cancelled) did nothing


def _first_line(text: str) -> str:
    import re
    t = re.sub(r"<[^>]+>", "", str(text or "")).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return t.strip().split("\n")[0][:200]


def _key_ip(key: str) -> str:
    """An issue key is kind:ip:group:device (main.Auditor._key); only `down` keys name an
    outage the logbook knows."""
    parts = str(key).split(":")
    return parts[1] if len(parts) >= 4 and parts[0] == "down" else ""


def outages(rows: list, now: float, since: float) -> list:
    """Logbook entries (logbook.entries, newest first) -> one interval per outage: an `up`
    carries how long it was down, an open `down` runs until now."""
    out = []
    for e in rows:
        if e.get("kind") == "up":
            # an `up` whose `down` is older than the record: down since before the window
            a = e["ts"] - e["down_for"] if e.get("down_for") is not None else since
            b, op = e["ts"], False
        elif e.get("kind") == "down" and e.get("open"):
            a, b, op = e["ts"], now, True
        else:
            continue
        if b < since:
            continue
        out.append({"ip": e["ip"], "name": e.get("name") or e["ip"], "a": max(a, since), "b": b, "open": op,
                    "cat": "paused" if e.get("paused") else "sched" if e.get("by_design") else "down"})
    return sorted(out, key=lambda o: o["a"])


def _cause(actions: list, t: float, ips: set, network: set) -> Optional[dict]:
    """The action that ran on one of these devices, or on the network in front of them, in
    the CAUSE_S before `t` — the latest one."""
    best = None
    for p in actions:
        if p.get("status") not in RAN or not p.get("ip"):
            continue
        ran = p.get("started_ts") or p.get("decided_ts") or p.get("ts") or 0
        if not (t - CAUSE_S <= ran <= t + 60):
            continue
        if p["ip"] in ips or p["ip"] in network:
            if best is None or ran > best["ts"]:
                best = {"id": p.get("id"), "title": p.get("title"), "label": p.get("label"),
                        "ts": ran, "status": p.get("status")}
    return best


def assemble(rows: list, wan: list, telegram: list, actions: list, seclog: dict, seen: list,
             findings: list, groups: dict, now: float, days: float = 7.0,
             wan_since: Optional[float] = None, renames: tuple = (), why=None) -> dict:
    """rows: logbook entries; wan: [{ts, kind, s}]; telegram: [{ts, channel, text, keys?}];
    actions: public proposals; seclog: SecLog.view(); seen: Sites.seen(); findings: the log
    checks' verdicts; groups: {ip: inventory group}; why: {ts, kind, s} -> the code's reading
    of a WAN event ({where, short}, wanexplain.py). Returns {items, lanes, since, now}."""
    since = now - days * 86400
    outs = outages(rows, now, since)
    network = {ip for ip, g in groups.items() if g == "network"}

    # --- incidents: union-find over outages ----------------------------------
    parent = list(range(len(outs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        if outs[i]["cat"] == outs[j]["cat"]:
            parent[find(i)] = find(j)

    for i in range(len(outs)):                       # started together
        for j in range(i + 1, len(outs)):
            if outs[j]["a"] - outs[i]["a"] > GROUP_S:
                break
            union(i, j)
    for m in telegram:                               # announced together
        ips = {_key_ip(k) for k in m.get("keys") or []} - {""}
        if len(ips) < 2:
            continue
        hit = [i for i, o in enumerate(outs) if o["ip"] in ips and o["a"] - 900 <= m["ts"] <= o["b"] + 60]
        for i in hit[1:]:
            union(hit[0], i)
    clusters: dict = {}
    for i, o in enumerate(outs):
        clusters.setdefault(find(i), []).append(o)

    # WAN events: one per moment (a short one logged as a blip AND a blackout is the
    # blip — wanexplain.merge)
    wev = [e for e in merge(wan) if e["ts"] >= since]

    items = []
    for ms in clusters.values():
        a, b = min(o["a"] for o in ms), max(o["b"] for o in ms)
        ips, names = {o["ip"] for o in ms}, [o["name"] for o in ms]
        cat = ms[0]["cat"]
        told = []
        if cat == "down":
            for m in telegram:
                if not (a - 60 <= m["ts"] <= b + 1500):
                    continue
                keys = {_key_ip(k) for k in m.get("keys") or []} - {""}
                if (keys & ips) or (not keys and any(n and n in m.get("text", "") for n in names)):
                    told.append({"ts": m["ts"], "channel": m.get("channel"), "text": _first_line(m.get("text"))})
        items.append({"type": "incident", "ts": a, "a": a, "b": b, "cat": cat,
                      "open": any(o["open"] for o in ms),
                      "members": sorted(({"ip": o["ip"], "name": o["name"], "a": o["a"], "b": o["b"],
                                          "open": o["open"]} for o in ms), key=lambda o: o["a"]),
                      "told": told[:4],
                      "wan": [w for w in wev if abs(w["ts"] - a) <= WAN_NEAR_S] if cat == "down" else [],
                      "cause": _cause(actions, a, ips, network) if cat == "down" else None})
    for w in wev:
        v = why(w) if why is not None else None
        items.append({"type": "wan", **w, "cause": _cause(actions, w["ts"], set(), network),
                      **({"where": v["where"], "why": v["short"]} if v else {})})
    for m in telegram:
        if m["ts"] >= since:
            items.append({"type": "telegram", "ts": m["ts"], "channel": m.get("channel"),
                          "text": _first_line(m.get("text")), "full": str(m.get("text") or "")[:1500]})
    for x in (seclog.get("open") or []) + (seclog.get("handled") or []):
        if (x.get("ts") or 0) >= since:
            items.append({"type": "security", "ts": x["ts"], "id": x.get("id"), "title": x.get("title"),
                          "sev": x.get("sev"), "ip": x.get("ip"), "source": x.get("source"),
                          "handled": x.get("handled"), "count": x.get("count") or 1})
    refused: dict = {}
    for p in actions:
        if (p.get("ts") or 0) < since:
            continue
        if p.get("status") == "refused" and not p.get("owner"):
            day = time.strftime("%Y-%m-%d", time.localtime(p["ts"]))
            refused.setdefault(day, []).append(p)
            continue
        items.append({"type": "action", "ts": p.get("done_ts") or p.get("decided_ts") or p["ts"],
                      "asked": p["ts"], "id": p.get("id"), "action": p.get("action"),
                      "title": p.get("title"), "label": p.get("label"), "ip": p.get("ip"),
                      "status": p.get("status"), "via": p.get("via"), "owner": bool(p.get("owner")),
                      "words": p.get("words")})
    for day, ps in refused.items():
        items.append({"type": "refused", "ts": max(p["ts"] for p in ps), "n": len(ps),
                      "ids": [p.get("id") for p in ps]})
    for r in seen:
        if (r.get("first_seen") or 0) >= since and not r.get("before"):
            items.append({"type": "new_device", "ts": r["first_seen"], "site": r.get("site"),
                          "site_name": r.get("site_name"), "ip": r.get("ip"), "mac": r.get("mac"),
                          "name": r.get("name") or r.get("host") or "", "vendor": r.get("vendor") or "",
                          "guest": bool(r.get("guest")), "status": r.get("status") or ""})
    # A log check that found nothing wrong, while the internet was out, says nothing ("a
    # device joined the guest Wi-Fi — unrelated to the outage", written 30 s after it was
    # back, is noise on the outage's line). Kept when it found a problem.
    dark = [(w["ts"], w["ts"] + w["s"] + 300) for w in wev if w["kind"] in ("blackout", "main-outage")]
    for f in findings:
        if not f.get("problem") and any(a <= (f.get("ts") or 0) <= b for a, b in dark):
            continue
        if (f.get("ts") or 0) >= since:
            items.append({"type": "check", "ts": f["ts"], "source": f.get("source"),
                          "problem": bool(f.get("problem")), "severity": f.get("severity"),
                          "kind": f.get("kind"), "summary": f.get("summary"), "detail": f.get("detail")})
    for r in renames:                                # the owner's names (names.py)
        if (r.get("ts") or 0) >= since:
            items.append({"type": "rename", "ts": r["ts"], "ip": r.get("ip") or "", "site": r.get("site") or "",
                          "mac": r.get("mac") or "", "from": r.get("from") or "", "to": r.get("to") or ""})
    items.sort(key=lambda x: x["ts"], reverse=True)

    lanes: dict = {}
    for o in outs:
        ln = lanes.setdefault(o["ip"], {"name": o["name"], "group": groups.get(o["ip"], ""), "segs": []})
        ln["segs"].append([o["a"], o["b"], o["cat"]])
    return {"now": now, "since": since, "wan_since": wan_since, "items": items, "lanes": lanes}


def build(a, now: Optional[float] = None, days: float = 7.0) -> dict:
    """The stream from what lanowl holds: its SQLite history and its records."""
    from . import logbook, wanexplain
    now = now or time.time()
    since = now - days * 86400
    rows = logbook.entries(a.state, a.inv, a.cfg, now, days, limit=5000,
                           paused=a._pause_intervals(now), paused_now=a.pauses.ips())
    wan = [{"ts": e["ts"], "kind": k, "s": e["value"]}
           for k in ("main-outage", "blackout", "blip") for e in a.state.events(since, kind=k, limit=2000)]
    tg, fs = [], []
    for e in a.state.events(since, kind="telegram", limit=2000):
        try:
            d = json.loads(e.get("detail") or "{}")
        except ValueError:
            d = {}
        tg.append({"ts": e["ts"], "channel": d.get("channel"), "text": d.get("text") or "", "keys": d.get("keys") or []})
    for e in a.state.events(since, kind="finding", limit=2000):
        try:
            fs.append({"ts": e["ts"], **json.loads(e.get("detail") or "{}")})
        except ValueError:
            continue
    acts = [a.actions.public(p) for p in a.actions.items if (p.get("ts") or 0) >= since]
    renames = []
    for e in a.state.events(since, kind="rename", limit=500):
        try:
            renames.append({"ts": e["ts"], **json.loads(e.get("detail") or "{}")})
        except ValueError:
            continue
    try:
        seen = a.sites.seen()
    except Exception:
        seen = []
    groups = {d.ip: d.group for d in a.inv.devices}
    try:
        wan_since = a.state.first_event_ts()
    except Exception:
        wan_since = None
    evs = wanexplain.evidence(a.state, since - 60)
    ants = wanexplain.standby_events(a.state, since - 60)
    moms = merge(wan)
    nw = getattr(getattr(a, "wanwatch", None), "netwatch", None)
    links = wan_links(a.cfg)
    why = lambda w: wanexplain.verdict(w, wanexplain.find(evs, w["ts"]), nw,   # noqa: E731
                                       wanexplain.context_for(w, moms, evs, ants), links=links)
    return assemble(rows, wan, tg, acts, a.seclog.view(now), seen, fs, groups, now, days, wan_since,
                    renames, why=why)
