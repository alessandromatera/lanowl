"""What happened to the internet at one moment — from what lanowl kept.

A blip on the Timeline ("Internet blackout — 29s") is worth clicking only if it can say where
it broke. Several short blackouts in a row may turn out to be lanowl's own view of the internet
dropping while the network kept it — the router's own pings never failing once — and nothing
but evidence kept per event can tell the two apart.

So the WAN watcher keeps, for every blip and blackout (wanwatch.py, `wan-evidence` events):
each failed round, whether the router and the line's first hop answered in it, the router's
netwatch counters as it started and ~75 s after it ended, and the router's log around it.
This module turns that into the code's reading — where it broke, in one line for the Timeline
and a few for the drawer — with no model involved. The model's reading is one button away
(the drawer's "Ask the owl about this"), and gets the same facts (`brief`).

For an event with no evidence of its own, the router's counters as read now still answer one
question: if none of its pings has failed since before the event, the network had internet.

Every sentence names the links as the owner does (`links`: model.wan_links); with one internet
line only, nothing here speaks of a backup or a failover.

`merge`: one entry per moment, so every reader counts alike.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Optional

from .model import on_main_lan, wan_links
from .report import human_duration

WAN_KINDS = ("main-outage", "blackout", "blip")
RANK = {"blackout": 0, "main-outage": 1, "blip": 2}
MOMENT_S = 2.0          # events of one moment: the ping loop writes a blip and its twin together
EVIDENCE_S = 5.0        # an evidence row belongs to the event that started within this

_NAMES = {"blackout": "Internet blackout", "main-outage": "The {Main} went down", "blip": "Internet blip"}

# where it broke -> the Timeline's line ({main}/{backup}: the links' names)
_SHORT = {
    "main": "the {main} dropped",
    "main-covered": "the {main} dropped; the {backup} carried the traffic",
    "main-dark": "the {main} dropped and the {backup} did not carry the traffic",
    "standby-off": "the {main} dropped and the {backup} never switched its uplink on",
    "standby-nolink": "the {main} dropped; the {backup}'s uplink came on but never connected",
    "standby-dead": "the {main} dropped; the {backup} was connected but no internet came through it",
    "lanowl": "lanowl's own link dropped, not the network's internet",
    "lanowl-path": "the network kept its internet — only lanowl's view of it dropped",
    "isp-link": "the provider's side: the {main}'s first hop stopped answering",
    "isp-beyond": "further into the provider's network: the {main}'s first hop kept answering",
    "home": "the router lost the internet too",
    "unknown": "not enough was kept to say where",
}


def _names(links: Optional[dict]) -> dict:
    L = links or wan_links({})
    return {"main": L["main"], "backup": L["backup"], "Main": L["main"][:1].upper() + L["main"][1:]}


def short(where: str, links: Optional[dict] = None) -> str:
    return _SHORT.get(where, where).format(**_names(links))


def name_of(kind: str, links: Optional[dict] = None) -> str:
    return _NAMES.get(kind, kind).format(**_names(links))


# What a STANDBY backup link did while the main one was down (`wan.standby`: a device that
# switches its uplink on only when the router stops answering it on the main link — so off
# with the main link up is fine, and lanowl reads it only while the main link is down,
# wanwatch._standby_tick). Then: still off after the grace is the failover failing; on and
# connected with no internet through it is a blackout with a reason.
STANDBY_TROUBLE = ("standby-off", "standby-nolink", "standby-dead")
STANDBY_GRACE_S = 120.0


def standby_story(reads: list, down_at: Optional[float], grace_s: float = STANDBY_GRACE_S,
                  links: Optional[dict] = None) -> Optional[dict]:
    """The standby link's reads during one outage of the main link ({ts, on, link, signal, net,
    err}, oldest first) -> {where, line}: what it did, in one sentence. None while nothing is
    definite yet — not read, or still off inside its grace."""
    n = _names(links)
    B = n["backup"][:1].upper() + n["backup"][1:]
    rs = [r for r in reads or [] if r.get("on") is not None]
    if not rs:
        errs = [r for r in reads or [] if r.get("err")]
        return ({"where": "unknown", "line": f"The {n['backup']} could not be read ({errs[-1]['err']})."}
                if errs else None)
    down_at = down_at or rs[0]["ts"]
    on = [r for r in rs if r["on"]]
    if not on:
        last = rs[-1]
        if last["ts"] - down_at < grace_s:
            return None
        return {"where": "standby-off", "line": (
            f"The {n['backup']} never switched its uplink on: still off at {_hm(last['ts'])}, "
            f"{human_duration(last['ts'] - down_at)} after the router took the {n['main']} out — "
            "the failover had nothing to fail over to.")}
    late = on[0]["ts"] - down_at
    came = (f"The {n['backup']} switched its uplink on by {_hm(on[0]['ts'])}"
            + (f" — {human_duration(late)} after the {n['main']} went, later than it should" if late > grace_s else ""))
    good = [r for r in on if r.get("net")]
    if good:
        return {"where": "standby-ok", "line": f"{came}, and the internet came through it from {_hm(good[0]['ts'])}."}
    linked = [r for r in on if r.get("link")]
    if linked:
        sig = linked[-1].get("signal")
        return {"where": "standby-dead", "line": (
            f"{came} and connected to the provider" + (f" ({sig} dBm)" if sig is not None else "")
            + ", but no internet came through it.")}
    if any(r.get("link") is False for r in on):
        return {"where": "standby-nolink", "line": f"{came}, but it never connected to the provider's access point."}
    return {"where": "unknown", "line": f"{came}; whether it connected could not be read."}


# The router's log lines that are an outage's side effects, not its story: in a long outage
# they are dozens of WireGuard retries and DHCP renewals, and the minutes that matter — the
# link dropping and the failover acting — are at its start and its end, never its middle.
# (topic, words): both must be in the line.
NOISE = (("wireguard", "did not complete"), ("wireguard", "retrying"), ("dhcp", "assigned "),
         ("wireless", "connected"), ("", "Download from"))
LOG_BEFORE, LOG_AFTER, LOG_LINES = 120.0, 180.0, 40


def is_noise(r: dict) -> bool:
    t, m = str(r.get("topics") or ""), str(r.get("message") or "")
    return any(tp in t and w in m for tp, w in NOISE)


def pick_log(rows: list, start: float, end: float, cap: int = LOG_LINES) -> list:
    """The router's log lines that tell an outage's story ([{ts, topics, message[, n, last]}]):
    the minutes around its start and around its end — a long one's middle is the tunnels
    retrying — its side effects dropped, a line that repeats kept once with its count."""
    head_b = start + LOG_AFTER
    out, seen = [], {}
    for r in sorted(rows or [], key=lambda r: r["ts"]):
        head = start - LOG_BEFORE <= r["ts"] <= head_b
        if is_noise(r) or not (head or end - LOG_BEFORE <= r["ts"] <= end + 60):
            continue
        k = (head, r.get("topics"), re.sub(r"\d+", "#", str(r.get("message") or ""))[:120])
        o = seen.get(k)
        if o is not None:
            o["n"] = o.get("n", 1) + r.get("n", 1)
            o["last"] = r.get("last", r["ts"])
            continue
        seen[k] = o = dict(r)
        out.append(o)
    if len(out) > cap:
        head = [r for r in out if r["ts"] <= head_b]
        tail = [r for r in out if r["ts"] > head_b]
        nt = min(len(tail), cap // 2)
        out = head[:cap - nt] + (tail[-nt:] if nt else [])
    return out


def merge(rows: list) -> list:
    """Raw WAN event rows ({ts, kind, value}) -> one {ts, kind, s} per moment, oldest first.

    A 'blackout' with a 'blip' at the same instant is the blip (a blackout under the paging
    floor may be recorded as that pair). Otherwise the worst kind wins."""
    rows = sorted((r for r in rows if r.get("kind") in RANK), key=lambda r: r["ts"])
    groups: list = []
    for r in rows:
        if groups and r["ts"] - groups[-1][0]["ts"] < MOMENT_S:
            groups[-1].append(r)
        else:
            groups.append([r])
    out = []
    for g in groups:
        kinds = {r["kind"] for r in g}
        if {"blackout", "blip"} <= kinds:
            kinds.discard("blackout")
        k = min(kinds, key=lambda x: RANK[x])
        r = next(x for x in g if x["kind"] == k)
        out.append({"ts": r["ts"], "kind": k, "s": float(r.get("value", r.get("s")) or 0)})
    return out


def moments(state, since: float) -> list:
    rows = []
    for k in WAN_KINDS:
        rows += state.events(since, kind=k, limit=2000)
    return merge(rows)


def evidence(state, since: float) -> dict:
    """{start ts: evidence dict} for the evidence rows since `since`."""
    out = {}
    for e in state.events(since, kind="wan-evidence", limit=2000):
        try:
            out[e["ts"]] = json.loads(e["detail"] or "{}")
        except ValueError:
            continue
    return out


def standby_events(state, since: float) -> dict:
    """{main-down ts: {down_at, up_at, reads}} — the standby link's reads of each main outage."""
    out = {}
    for e in state.events(since, kind="wan-standby", limit=2000):
        try:
            out[e["ts"]] = json.loads(e["detail"] or "{}")
        except ValueError:
            continue
    return out


def context_for(event: dict, moms: list, evs: dict, ants: dict) -> dict:
    """What a main-link outage's own row cannot know: how much of it the network had NO
    internet (the blackouts inside it), and what the standby link did — {dark_s, standby:
    {down_at, reads}}."""
    a, b = event["ts"], event["ts"] + float(event.get("s") or 0)
    dark = 0.0
    if event.get("kind") == "main-outage":
        dark = sum(max(0.0, min(b, m["ts"] + m["s"]) - max(a, m["ts"]))
                   for m in moms if m["kind"] in ("blackout", "blip"))
    ant = next((x for t, x in sorted(ants.items()) if a - 180 <= t <= b + 30), None)
    if ant is None:
        for m in moms:
            ev = find(evs, m["ts"]) if m["ts"] <= b and m["ts"] + m["s"] >= a else None
            if ev and ev.get("standby"):
                ant = ev["standby"]
                break
    return {"dark_s": dark, "standby": ant}


def find(evs: dict, ts: float) -> Optional[dict]:
    hit = min(evs, key=lambda t: abs(t - ts), default=None)
    return evs[hit] if hit is not None and abs(hit - ts) <= EVIDENCE_S else None


def _router_ts(s: str) -> Optional[float]:
    """A netwatch `since` ("2026-09-27 00:57:07", the router's local time) as a timestamp."""
    try:
        return time.mktime(time.strptime(str(s).strip(), "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def _internet(host: str) -> bool:
    """A netwatch check of the internet — not one of a LAN box (a backup link's own device)."""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def nw_delta(ev: dict) -> Optional[dict]:
    """The router's own pings while it happened: tests run and failed between the two reads,
    over the checks that were up when it began. None if either read is missing."""
    a, b = ev.get("nw_before"), ev.get("nw_after")
    if not isinstance(a, dict) or not isinstance(b, dict):
        return None
    tests = failed = 0
    hosts = []
    for h, x in a.items():
        y = b.get(h)
        if y is None or x.get("status") != "up" or not _internet(h):
            continue
        dt, df = y["done"] - x["done"], y["failed"] - x["failed"]
        if dt < 0:              # the router restarted its checks in between
            continue
        tests += dt
        failed += max(0, df)
        hosts.append(h)
    return {"tests": tests, "failed": failed, "hosts": hosts} if hosts else None


def nw_since_clean(netwatch: Optional[dict], ts: float) -> Optional[dict]:
    """For an event with no evidence of its own: the router's ping checks that are up now,
    have never failed, and were already running at `ts`. {hosts, since} or None."""
    hosts, since = [], None
    for h, x in (netwatch or {}).items():
        s = _router_ts(x.get("since"))
        if x.get("status") == "up" and x.get("failed") == 0 and s is not None and s < ts - 60 \
                and _internet(h):
            hosts.append(h)
            since = max(since or 0, s)
    return {"hosts": hosts, "since": since} if hosts else None


def _hm(ts: Optional[float]) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "?"


def _dm(ts: Optional[float]) -> str:
    return time.strftime("%d/%m %H:%M", time.localtime(ts)) if ts else "?"


def _hosts(hs: list) -> str:
    return ", ".join(hs[:4]) + ("…" if len(hs) > 4 else "")


def length(event: dict, ev: Optional[dict]) -> dict:
    """How long, honestly: pings every `interval_s` only bound it. n failed rounds in a row
    mean the internet was gone for at least (n-1) intervals and at most (n+1)."""
    s, iv = float(event.get("s") or 0), float((ev or {}).get("interval_s") or 15)
    if event.get("kind") == "main-outage":
        return {"s": s, "text": human_duration(s), "how": "timed by the router's own log"}
    n = int((ev or {}).get("rounds_n") or max(1, round(s / iv)))
    lo, hi = max(1.0, (n - 1) * iv), (n + 1) * iv
    return {"s": s, "text": "~" + human_duration(round(s)), "lo": lo, "hi": hi,
            "how": f"{n} round{'s' if n != 1 else ''} of pings {iv:g} s apart got no answer: "
                   f"it lasted between ~{human_duration(lo)} and ~{human_duration(hi)}"}


def verdict(event: dict, ev: Optional[dict], netwatch: Optional[dict] = None,
            ctx: Optional[dict] = None, links: Optional[dict] = None) -> dict:
    """The code's reading of one event: {where, short, lines}. No model. `ctx` (context_for)
    is what else happened at that moment: the blackouts inside a main-link outage, the standby
    link. `links`: model.wan_links, for the names."""
    L = links or wan_links({})
    n = _names(L)
    main, backup = n["main"], n["backup"]
    kind = event.get("kind")
    lines: list = []
    ctx = ctx or {}
    sb = ctx.get("standby") or (ev or {}).get("standby") or {}
    story = standby_story(sb.get("reads"), sb.get("down_at"), links=L) if sb else None

    def done(where):
        return {"where": where, "short": short(where, L), "lines": lines}

    if kind == "main-outage":
        # Not "the backup carried it" by default: the router's own pings may have failed all
        # along, and then nothing did.
        s = float(event.get("s") or 0)
        dark = float(ctx.get("dark_s") or 0)
        lines.append(f"The router logged the {main} down and back up (its own timing).")
        if story and story["where"] in STANDBY_TROUBLE:
            where = story["where"]
        elif s and dark >= 0.8 * s:
            where = "main-dark"
            lines.append(f"Nothing carried the traffic in between: lanowl's pings got no answer "
                         f"for {human_duration(dark)} of it.")
        else:
            where = "main-covered"
            if dark:
                lines.append(f"Nothing answered for {human_duration(dark)}, until the {backup} took over.")
        if story:
            lines.append(story["line"])
        elif where == "main-covered" and not dark:
            lines.append(f"Its failover moved the network onto the {backup} in between.")
        return done(where)
    if ev is None:
        clean = nw_since_clean(netwatch, event["ts"])
        if clean:
            lines += [f"The router's own pings to {_hosts(clean['hosts'])} — every 20 s — have not failed "
                      f"once since {_dm(clean['since'])}, which covers this moment: the network had internet.",
                      "No evidence was kept for this one, so whether lanowl's own link or its "
                      "traffic through the router dropped can no longer be told."]
            return done("lanowl-path")
        lines.append("No evidence was kept for this one, and the router's counters have been "
                     "reset since: nothing left says where it broke.")
        return done("unknown")

    rounds = ev.get("rounds") or []
    hops = ev.get("hops") or {}
    router_ip, isp_ip = hops.get("router", "the router"), hops.get("isp")
    r_known = [r for r in rounds if "router" in r]
    router_fail = bool(r_known) and all(r["router"] is False for r in r_known)
    i_known = [r for r in rounds if "isp" in r]
    isp_fail = bool(i_known) and all(r["isp"] is False for r in i_known)
    isp_ok = any(r.get("isp") is True for r in i_known)
    nw = nw_delta(ev)
    # the longest a round of pings waits: `pings` per target (1 before they were recorded),
    # each up to the timeout, 0.25 s apart (probes.ping)
    pings = int(ev.get("pings") or 1)
    tmo = pings * float(ev.get("timeout_ms") or 1500) / 1000 + (pings - 1) * 0.25
    slow = max((float(r.get("took") or 0) for r in rounds), default=0)

    if ev.get("main"):
        f = ev["main"][0]
        where = "main"
        lines.append(f"The router logged the {main} down at {_hm(f['down'])} and back up at {_hm(f['up'])}.")
        if story and story["where"] in STANDBY_TROUBLE:
            where = story["where"]
            lines.append(story["line"])
        elif story:
            lines.append(story["line"])
        elif nw is not None and nw["tests"] >= 10 and nw["failed"] >= 0.9 * nw["tests"]:
            where = "main-dark"
            lines.append(f"The {backup} did not carry it either: the router's own pings failed "
                         f"{nw['failed']} of {nw['tests']} times while it lasted.")
        else:
            lines.append(f"Nothing answered until the failover moved the network onto the {backup}, "
                         f"or the {main} came back.")
    elif router_fail:
        where = "lanowl"
        lines.append(f"The router ({router_ip}) did not answer lanowl either: it was lanowl's own "
                     "connection that dropped — its host, the host's network, or the cable and "
                     "switch between it and the router.")
    elif nw is not None and nw["tests"] > 0 and nw["failed"] == 0:
        where = "lanowl-path"
        lines.append(f"The network kept its internet: the router's own pings to {_hosts(nw['hosts'])} "
                     f"ran {nw['tests']} test(s) in that time and none failed.")
        if any(r.get("router") is True for r in r_known):
            lines.append("The router answered lanowl all along, so it is not lanowl's "
                         "cable either: only lanowl's own traffic out through the router was "
                         "lost for a moment.")
    elif nw is not None and nw["failed"] > 0:
        if isp_fail:
            where = "isp-link"
            lines.append(f"The {main}'s first hop ({isp_ip}, the provider's gateway) stopped "
                         f"answering: the break was on the {main} or at the provider's "
                         "nearest equipment.")
        elif isp_ok:
            where = "isp-beyond"
            lines.append(f"The {main}'s first hop ({isp_ip}) kept answering, so the line itself "
                         "stayed up: the break was further into the provider's network.")
        else:
            where = "home"
            lines.append("The router lost the internet too.")
        lines.append(f"The router's own pings failed {nw['failed']} of {nw['tests']} time(s) in "
                     "that span" + (f", not long enough for its failover to switch to the {backup}."
                                    if L["failover"] else "."))
    elif isp_fail:
        where = "isp-link"
        lines.append(f"The router answered, the {main}'s first hop ({isp_ip}) did not: the break "
                     f"was on the {main} or at the provider's nearest equipment. (The router's "
                     "own pings cannot confirm the network lost it too.)")
    elif isp_ok:
        where = "isp-beyond"
        lines.append(f"The router and the {main}'s first hop ({isp_ip}) both answered: the break "
                     "was further into the provider's network. (The router's own pings cannot "
                     "confirm the network lost it too.)")
    else:
        where = "unknown"
        lines.append("The evidence kept does not say where it broke.")

    if nw is not None and nw["tests"] == 0:
        lines.append("The router's own pings did not run while it lasted (they run every 20 s), "
                     "so they cannot say whether the network had internet.")
    if router_fail and nw is not None and nw["tests"] > 0:
        lines.append(f"Meanwhile the router's own pings ran {nw['tests']} test(s) and "
                     + ("none failed: the network had internet all along."
                        if nw["failed"] == 0 else f"{nw['failed']} failed: the network lost it too."))
    if slow > tmo + 2:
        lines.append(f"lanowl itself was slow: a round of pings took {slow:.1f} s where "
                     f"{tmo:g} s is the most it waits — its host may have stalled.")
    if (ev.get("path") or {}).get("on_backup"):
        lines.append(f"The network was already on the {backup} when it began.")
    return done(where)


def _sweep(a, t0: float, t1: float) -> Optional[dict]:
    """What lanowl's own sweep saw inside the window: the LAN, and what it reaches over
    the internet (the VPS, the tunnels). One sweep a minute, so often none."""
    try:
        rows = a.state.conn.execute(
            "SELECT ts, ip, up, latency FROM samples WHERE ts BETWEEN ? AND ?", (t0, t1)).fetchall()
    except Exception:
        return None
    if not rows:
        return None
    lan = [r for r in rows if on_main_lan(a.cfg, str(r["ip"]))]
    far = [r for r in rows if not on_main_lan(a.cfg, str(r["ip"]))]
    name = lambda ip: (a.inv.get(ip).name if a.inv.get(ip) is not None else ip)   # noqa: E731
    return {"ts": rows[0]["ts"], "lan_up": sum(1 for r in lan if r["up"]), "lan": len(lan),
            "far": [{"ip": r["ip"], "name": name(r["ip"]), "up": bool(r["up"]),
                     "ms": round(r["latency"]) if r["latency"] is not None else None} for r in far][:6]}


def explain(a, ts: float) -> Optional[dict]:
    """Everything the drawer shows about the WAN event at `ts` (within a couple of seconds)."""
    evs = moments(a.state, ts - 60)
    event = next((e for e in evs if abs(e["ts"] - ts) < MOMENT_S), None)
    if event is None:
        return None
    evs_all = evidence(a.state, ts - 86400)
    ev = find(evs_all, event["ts"])
    ww = getattr(a, "wanwatch", None)
    L = wan_links(a.cfg)
    ctx = context_for(event, moments(a.state, ts - 86400), evs_all, standby_events(a.state, ts - 86400))
    v = verdict(event, ev, getattr(ww, "netwatch", None), ctx, links=L)
    ln = length(event, ev)
    end = event["ts"] + event["s"]
    out = {"ts": event["ts"], "end": end, "kind": event["kind"],
           "title": f"{name_of(event['kind'], L)} — {ln['text']}",
           "length": ln, "verdict": v, "paged": event["kind"] == "blackout",
           "floor_s": float(((a.cfg.get("wan") or {}).get("watch") or {}).get("min_outage_s", 90))}
    if ev is not None:
        out["evidence"] = {k: ev.get(k) for k in ("targets", "hops", "rounds", "rounds_n", "interval_s",
                                                  "timeout_ms", "pings", "path", "main")}
        nw = nw_delta(ev)
        if nw is not None:
            out["evidence"]["router_pings"] = nw
    # The router's log around its start and its end (pick_log). Read again from the router's
    # log as lanowl holds it now when that still goes back far enough, else what was kept.
    raw, first = None, None
    if ww is not None and ww.log_rows:
        lines, first = ww._log_window(event["ts"] - LOG_BEFORE, end + 60)
        if first is not None and first <= event["ts"] - LOG_BEFORE:
            raw = lines
    if raw is None and ev is not None:
        raw, first = ev.get("log") or [], ev.get("log_from")
    out["log"] = pick_log(raw or [], event["ts"], end)
    out["log_from"] = first
    if first and first > event["ts"] - 60:
        out["log_note"] = (f"The router's log only goes back to {_dm(first)} — "
                           "what it said at the time is gone.")
    elif not out["log"] and raw:
        out["log_note"] = ("Only side effects in the router's log around it — tunnels retrying, "
                           "leases renewed, Wi-Fi clients — nothing about the internet link"
                           + (" or the failover." if L["failover"] else "."))
    elif not out["log"]:
        out["log_note"] = ("The router's log has nothing in those minutes"
                           + (f": no {L['main']} drop, no failover." if L["failover"] else "."))
    sw = _sweep(a, event["ts"] - 5, end - 0.5)      # inside it: the first good round ends it
    if sw:
        out["sweep"] = sw
    if not ev and event["kind"] != "main-outage":
        nwc = nw_since_clean(getattr(ww, "netwatch", None), event["ts"])
        if nwc:
            out["router_pings_now"] = nwc
    out["brief"] = brief(out, L)
    return out


def brief(x: dict, links: Optional[dict] = None) -> str:
    """The facts for the model, in words — what the drawer shows, nothing more."""
    L = links or wan_links({})
    lines = [f"WAN EVENT: {x['title']} — {time.strftime('%A %d/%m %H:%M:%S', time.localtime(x['ts']))}"
             f" to {_hm(x['end'])}.",
             f"How long: {x['length']['how']}.",
             ("It paged (it passed the paging floor)." if x.get("paged") else
              f"It did not page: under the {x['floor_s']:g} s paging floor"
              + (f", or a {L['main']} drop the failover covered." if L["failover"] else ".")),
             f"The monitor's own reading (code, not a model): {x['verdict']['short']}.",
             *[f"- {s}" for s in x["verdict"]["lines"]]]
    e = x.get("evidence")
    if e:
        n = int(e.get("pings") or 1)
        lines.append(f"Pinged every {e.get('interval_s'):g} s, {n} ping{'s' if n > 1 else ''} each "
                     f"(any reply = up): {', '.join(e.get('targets') or [])}; "
                     f"in a failed round also the router and the {L['main']}'s first hop "
                     f"({json.dumps(e.get('hops'))}).")
        for r in e.get("rounds") or []:
            lines.append(f"  failed round {_hm(r['ts'])}: took {r.get('took')} s; router "
                         f"{'answered' if r.get('router') else 'no answer' if 'router' in r else 'not asked'}"
                         + (f"; {L['main']} first hop {'answered' if r.get('isp') else 'no answer'}"
                            if "isp" in r else ""))
        if e.get("router_pings"):
            rp = e["router_pings"]
            lines.append(f"The router's own pings (netwatch) in that span: {rp['tests']} test(s), "
                         f"{rp['failed']} failed, to {', '.join(rp['hosts'])}.")
    if x.get("router_pings_now"):
        rp = x["router_pings_now"]
        lines.append(f"The router's own pings to {', '.join(rp['hosts'])} have not failed since "
                     f"{_dm(rp['since'])}.")
    sw = x.get("sweep")
    if sw:
        lines.append(f"lanowl's sweep at {_hm(sw['ts'])}: {sw['lan_up']} of {sw['lan']} LAN "
                     "devices answered; over the internet: "
                     + (", ".join(f"{f['name']} {'answered ' + str(f['ms']) + ' ms' if f['up'] else 'no answer'}"
                                  for f in sw["far"]) or "nothing asked") + ".")
    if x.get("log"):
        lines.append("The router's log around it:")
        lines += [f"  {_hm(r['ts'])} [{r.get('topics', '')}] {r['message']}"
                  + (f" (×{r['n']}, the last at {_hm(r.get('last'))})" if r.get("n", 1) > 1 else "")
                  for r in x["log"][:30]]
    if x.get("log_note"):
        lines.append(x["log_note"])
    return "\n".join(lines)
