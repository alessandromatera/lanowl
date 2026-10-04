"""The weekly review: a week of history, counted by the monitor and narrated by the model.

Every other message lanowl sends is about the last minute or the last hour; the digest's
"Quietly getting worse" looks back 24 h at most. Yet the questions worth asking about a home
network are weekly ones: is the internet line having a bad week or a bad evening, which
device keeps falling off, did anything new join, did the log checks find anything. The SQLite
history holds the answers, and the router's log holds about a week and a half of link
failovers. This reads them once a week.

Same split as everywhere else: the numbers are computed here, deterministically, and are
printed in the message whether or not the model answers. The model only writes the note on
top — which of those numbers deserve the owner's attention, and why.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from . import wanexplain
from .model import wan_links
from .pause import overlaps
from .report import _html, format_model_off, format_paused, human_duration, label
from .sweep import offline_mode_ips

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


FIRST_WEEK_S = 6 * 86400   # the first review waits for (nearly) a week of watching


def is_due(cfg: dict, now: float, last_sent: float, since: float = 0.0) -> bool:
    """Is this the configured weekday, past the configured time, and not yet sent today?
    And has lanowl watched for most of a week (`since`: when it began)? A first start on
    the review's day would otherwise review a week it never saw."""
    w = cfg.get("weekly") or {}
    if not w.get("enabled", False):
        return False
    lt = time.localtime(now)
    day = str(w.get("day", "sun")).lower()[:3]
    if day not in _DAYS or lt.tm_wday != _DAYS.index(day):
        return False
    hh, mm = (int(x) for x in str(w.get("time", "10:00")).split(":"))
    slot = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hh, mm, 0, 0, 0, -1))
    return now >= slot and last_sent < slot and slot - since >= FIRST_WEEK_S


def _random_mac(mac: str) -> bool:
    """Locally administered = a phone or tablet using a private, rotating address."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _channel(detail: str) -> str:
    """A telegram event's channel: JSON with the text, or (older rows) the whole detail."""
    if str(detail).startswith("{"):
        try:
            return str(json.loads(detail).get("channel") or "")
        except ValueError:
            return ""
    return str(detail)


def compute_facts(state, inv, wanwatch=None, hostlog=None, discovery: Optional[dict] = None,
                  now: Optional[float] = None, days: int = 7, paused: Optional[dict] = None,
                  paused_now: Optional[list] = None) -> dict:
    """`paused`: {ip: [(start, end)]} (pause.intervals). A device paused at any point this
    week is left out of the uptime league — a holiday is not downtime — and the ones still
    paused are listed, so a pause gets a weekly reminder even when nothing else is said.
    `paused_now`: the report's `paused` list."""
    now = now or time.time()
    start, prev = now - days * 86400, now - 2 * days * 86400
    scheduled = offline_mode_ips(inv)
    watched = {d.ip: d for d in inv.devices
               if d.criticality in ("critical", "high", "warning") and d.ip not in scheduled
               and not overlaps(paused or {}, d.ip, start, now)}

    cur = state.week_stats(start, now)
    last = state.week_stats(prev, start)
    rows = []
    for ip, d in watched.items():
        s = cur.get(ip)
        if not s or s.get("uptime_pct") is None:
            continue
        p = last.get(ip) or {}
        rows.append({"device": label(d.name, ip), "uptime_pct": s["uptime_pct"],
                     "outages": s["transitions"] // 2 + s["transitions"] % 2,
                     "latency_ms": s["latency_ms"],
                     "last_week_uptime_pct": p.get("uptime_pct"),
                     "last_week_outages": (p.get("transitions", 0) // 2
                                           + p.get("transitions", 0) % 2) if p else None})
    worst = sorted([r for r in rows if r["uptime_pct"] < 99.5], key=lambda r: r["uptime_pct"])
    flappy = sorted([r for r in rows if r["outages"] >= 3], key=lambda r: -r["outages"])

    facts: dict = {
        "period": f"{time.strftime('%d/%m', time.localtime(start))} – "
                  f"{time.strftime('%d/%m', time.localtime(now))}",
        "devices": {"watched": len(rows),
                    "at_or_above_99_5_pct": sum(1 for r in rows if r["uptime_pct"] >= 99.5),
                    "worst_uptime": worst[:5], "most_outages": flappy[:5]},
    }
    if paused_now:
        facts["paused_by_owner"] = [
            {"device": label(p.get("name"), p.get("ip")), "ip": p.get("ip"),
             "name": p.get("name"), "ts": p.get("ts"), "up": p.get("up"),
             "since": time.strftime("%d/%m %H:%M", time.localtime(p["ts"]))}
            for p in paused_now]
    try:
        deg = state.degrading(now)
        names = {d.ip: d.name for d in inv.devices}
        facts["devices"]["degrading_last_24h"] = [
            {"device": label(names.get(r["ip"], ""), r["ip"]), "why": r["why"]} for r in deg[:5]]
    except Exception:
        pass

    # --- the internet
    wan: dict = {}
    # the main link's own drops only with a failover the router's log reports (wan.watch)
    L = wan_links(getattr(wanwatch, "cfg", None) or {})
    if wanwatch is not None and L["failover"] and getattr(wanwatch, "_edge_patterns", lambda: ("", ""))()[0]:
        wan["main_name"] = L["main"]
        outs = wanwatch.outages_from_log()
        this = [(s, e) for s, e in outs if s.timestamp() >= start]
        before = [(s, e) for s, e in outs if prev <= s.timestamp() < start]
        secs = [(e - s).total_seconds() for s, e in this]
        covers = wanwatch.log_rows[0][0].timestamp() if wanwatch.log_rows else now
        wan["main_drops"] = len(this)
        wan["main_down_total"] = human_duration(sum(secs)) if secs else "0s"
        wan["main_longest"] = human_duration(max(secs)) if secs else None
        per_day: dict = {}
        for s, _ in this:
            k = s.strftime("%a %d/%m")
            per_day[k] = per_day.get(k, 0) + 1
        wan["main_drops_per_day"] = per_day
        wan["last_week_main_drops"] = len(before)
        wan["last_week_complete"] = covers <= prev
    ev = state.events(start)
    # one per moment: a short one recorded as a blip AND a blackout is the blip
    wm = wanexplain.merge([e for e in ev if e["kind"] in wanexplain.WAN_KINDS])
    black = [e for e in wm if e["kind"] == "blackout"]
    blips = [e for e in wm if e["kind"] == "blip"]
    wan["no_internet_at_all"] = {"times": len(black),
                                 "total": human_duration(sum(e["s"] for e in black))}
    wan["short_blips_not_paged"] = len(blips)
    first = state.first_event_ts()
    wan["blackouts_tracked_since"] = (time.strftime("%d/%m", time.localtime(first))
                                      if first and first > start else None)
    facts["internet"] = wan

    # --- what the checks said, and what was sent
    finds = []
    for e in ev:
        if e["kind"] == "finding":
            try:
                finds.append(json.loads(e["detail"]))
            except ValueError:
                pass
    facts["log_checks"] = {"triaged": len(finds),
                           "problems": [f.get("summary") for f in finds if f.get("problem")][:6]}
    sent = [_channel(e["detail"]) for e in ev if e["kind"] == "telegram"]
    facts["messages_sent"] = {"alerts": sent.count("critical"), "digests": sent.count("digest")}
    if first and first > start:
        facts["messages_sent"]["counted_since"] = time.strftime("%d/%m", time.localtime(first))

    # --- the network's membership
    new = state.new_macs(start)
    facts["new_on_network"] = {
        "count": len(new),
        "with_random_mac": sum(1 for n in new if _random_mac(n.get("mac", ""))),
        "others": [f"{n.get('host') or '(no name)'} {n.get('ip')} {n.get('mac')}"
                   + (f" at {n['site']}" if n.get("site") not in (None, "home") else "")
                   + (" (fixed address)" if n.get("how") in ("arp", "scan") else "")
                   for n in new if not _random_mac(n.get("mac", ""))][:6],
    }
    if discovery:
        facts["new_on_network"]["unknown_in_dhcp_now"] = discovery.get("unknown_count")

    # --- the public box
    if hostlog is not None:
        for h in getattr(hostlog, "hosts", []):
            if h.public:
                facts.setdefault("public_hosts", []).append(
                    {"host": f"{h.name} ({h.ip})", "last_24h": hostlog.noise_24h(h)})
    return facts


def format_weekly(facts: dict, narrative: Optional[str]) -> str:
    """The message. The numbers are always there; the model's note is on top when it wrote one."""
    lines = [f"📅 <b>Week in review</b> · {facts.get('period', '')}"]
    if narrative:
        lines += ["🦉 " + _html(narrative.strip()), ""]      # the model's note: the owl's mark
    lines.append("<b>Numbers</b>")
    w = facts.get("internet") or {}
    if "main_drops" in w:
        lw = w.get("last_week_main_drops")
        cmp_ = (f" (last week: {lw}{'' if w.get('last_week_complete') else '+, log incomplete'})"
                if lw is not None else "")
        longest = f", longest {w['main_longest']}" if w.get("main_longest") else ""
        name = str(w.get("main_name") or "Main link")
        lines.append(f"🌐 {name[:1].upper() + name[1:]}: {w['main_drops']} drop(s), {w['main_down_total']} down"
                     f"{longest}{cmp_}")
    nia = w.get("no_internet_at_all") or {}
    since = f" (tracked since {w['blackouts_tracked_since']})" if w.get("blackouts_tracked_since") else ""
    lines.append(f"🔴 No internet at all: "
                 + (f"{nia.get('times')}×, {nia.get('total')}" if nia.get("times") else "never")
                 + since)
    d = facts.get("devices") or {}
    if d.get("watched"):
        worst = (d.get("worst_uptime") or [None])[0]
        tail = (f"; worst {worst['device']} {worst['uptime_pct']}% · {worst['outages']} outage(s)"
                if worst else "")
        lines.append(f"📟 Devices: {d['at_or_above_99_5_pct']}/{d['watched']} at ≥99.5%{tail}")
    if facts.get("paused_by_owner"):
        lines.append(format_paused(facts["paused_by_owner"]))
    if facts.get("model_off"):
        lines.append(format_model_off(facts["model_off"]))
    m = facts.get("messages_sent") or {}
    if m:
        cs = f" (since {m['counted_since']})" if m.get("counted_since") else ""
        lines.append(f"✉️ Sent: {m.get('alerts', 0)} alert(s), {m.get('digests', 0)} digest(s){cs}")
    n = facts.get("new_on_network") or {}
    if n.get("count"):
        lines.append(f"🆕 New on the network: {n['count']}"
                     + (f" ({n['with_random_mac']} phones/tablets with a random MAC)"
                        if n.get("with_random_mac") else ""))
    lc = facts.get("log_checks") or {}
    if lc.get("triaged"):
        lines.append(f"🔎 Log checks: {lc['triaged']} batch(es) read, "
                     f"{len(lc.get('problems') or [])} worth reporting")
    for h in facts.get("public_hosts") or []:
        nz = h.get("last_24h") or {}
        if nz.get("attempts"):
            lines.append(f"🛡️ {h['host']}: {nz['attempts']:,} failed passwords from "
                         f"{nz['sources']} addresses in 24h")
    se = facts.get("security_events") or {}                       # seclog.py
    if se.get("raised_this_week") or se.get("still_open"):
        lines.append(f"🛡️ Security events from the logs: {se.get('raised_this_week', 0)} this week"
                     + (f", {len(se['still_open'])} still open on the Security tab"
                        if se.get("still_open") else ", all handled"))
    lines += [_html(x) for x in facts.get("updates") or []]      # updates.py
    for b in facts.get("by_hand") or []:                          # Actions.by_hand
        lines.append(_html(f"🔁 By hand, again and again: {b['action']}"
                           + (f" — {b['device']}" if b.get("device") else "")
                           + f", {b['n']}× in 30 days. A standing order could do it for you: ask."))
    return "\n".join(lines)
