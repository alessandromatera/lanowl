"""Deterministic issue/severity model + message formatting.

The deterministic report is always correct and always available; the LLM audit is
merged in when present but can never remove a deterministic critical.
"""
from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .model import Inventory, model_cfg, model_name, router_host
from .sweep import OLLAMA_KEY, Snapshot

# device criticality -> issue severity when that device is down
_SEV = {"critical": "critical", "high": "high", "warning": "warning", "low": "info", "info": "info"}
_SEV_RANK = {"critical": 3, "high": 2, "warning": 1, "info": 0}
_EMOJI = {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "⚪", "ok": "🟢"}


@dataclass
class Issue:
    device: str
    ip: str
    group: str
    severity: str
    detail: str
    kind: str = "down"    # down | degraded | wan | wan-path | group
    since: float = 0.0    # when it started, if the source knows; 0 = only the gate knows


def _worst(sevs: list) -> str:
    return max(sevs, key=lambda s: _SEV_RANK.get(s, 0)) if sevs else "info"


def wan_state(wan_ok: bool, wan_path: Optional[dict]) -> str:
    """The internet in one word: ok | backup | down.

    Three states, because that is how people on the network experience it — the main link
    is carrying traffic, the backup link is, or nothing is. Pings alone cannot tell the first
    two apart (they succeed over either link), which is what the route poll is for; with one
    internet line there are only ok and down.

    This is the sweep's own answer, on its 60s clock. `wan.watch` computes the same three
    states four times faster and its verdict overrides this one in the published report;
    this stays correct when the watcher is disabled."""
    if not wan_ok:
        return "down"
    return "backup" if (wan_path or {}).get("on_backup") else "ok"


def observer_failure(cfg: dict, snapshot: Snapshot, down_ips: set, counts: dict):
    """Is the most likely explanation that THIS MACHINE fell off the network?

    Everything here is probed from one machine (`observer.host_ip`), so lanowl cannot tell
    "the network went dark" from "I went dark" by looking at devices alone — both produce a
    screen full of red. The tell is the shape of the failure: not a device or a group, but
    most of the LAN at once *including the gateway*. Nothing downstream of the router can
    take out half the network and leave the router pingable; if the router is unreachable too, the shortest path
    from here to it is the first suspect.

    Returns the Issue to raise instead of the storm, or None.

    This is deliberately conservative — it must never explain away a real power cut, so it
    needs the gateway to be gone AND the failure to span groups that share no other
    infrastructure. A cut to one switch takes out its own devices, not five groups at once."""
    o = (cfg or {}).get("observer") or {}
    if not o.get("enabled", True):
        return None
    gw = o.get("gateway_ip") or router_host(cfg)
    if not gw or gw not in down_ips:
        return None                      # the router answers: the network is there, so are we
    # what is being watched: a paused device's silence says nothing about this host
    total = counts.get("total", 0) - counts.get("paused", 0)
    down = counts.get("down", 0)
    if total <= 0 or (100.0 * down / total) < float(o.get("min_down_pct", 60)):
        return None
    groups = {d.group for d in snapshot.devices
              if d.ip in down_ips and not d.excused}
    if len(groups) < int(o.get("min_groups", 3)):
        return None
    host = o.get("host_ip") or "this host"
    return Issue("lanowl's host", host, "servers", "critical",
                 f"{down}/{total} devices unreachable across {len(groups)} groups, the "
                 f"gateway ({gw}) among them — lanowl's own host ({host}) has most "
                 f"likely lost the network. Check its link before assuming the whole network is dark.",
                 kind="observer")


def shadowed_ips(snapshot: Snapshot, down_ips: set) -> dict:
    """{ip: parent} for every down device that is down BECAUSE of something upstream.

    A device may declare `depends_on: <ip>` (or `depends_on: wan`) in the inventory: the
    thing it is reached through. Remote sites behind a VPN hub are the case in point — their
    routers are only visible through the main router's tunnel to the hub, so when the main
    link drops, or the hub reboots, or the tunnel is re-keying after a failover, all of them
    vanish at once. Reporting each of them is the camera storm again: four alerts that all
    mean one thing, and three of them point at the wrong place.

    Only the IMMEDIATE parent matters: if it answers, the path to it works, so nothing above
    it can be what took the child out. The parent counts as down on its raw probe, not just
    its confirmed status — the two debounce on their own clocks, and a child that confirmed
    one sweep before its parent must not slip out as an issue of its own for that sweep.
    `wan` is the sweep's own verdict (which the WAN watcher already overrides).

    Only a down device is ever shadowed; a remote site that answers is judged on its own.
    The parent's issue stands, and names what went dark with it."""
    parents = {d.ip: str(d.attrs.get("depends_on") or "") for d in snapshot.devices
               if (d.attrs or {}).get("depends_on")}
    if not parents:
        return {}
    raw_up = {d.ip: d.up for d in snapshot.devices}
    out: dict[str, str] = {}
    for d in snapshot.devices:
        if d.ip not in down_ips or d.excused or d.ip not in parents:
            continue
        parent = parents[d.ip]
        if parent == "wan":
            if not snapshot.wan_ok:
                out[d.ip] = "wan"
        elif parent in down_ips or raw_up.get(parent) is False:
            out[d.ip] = parent
    return out


def build_report(snapshot: Snapshot, inv: Inventory, down_ips: set,
                 cfg: Optional[dict] = None, down_since: Optional[dict] = None) -> dict:
    """down_ips = confirmed-down IPs from the StatusTracker (debounced).
    down_since = {ip: ts} for those — the first missed sweep, which is `debounce_fails`
    sweeps before the one that confirmed it. Carried on the issue as `since` so every
    message about the outage can say WHEN, not just that."""
    issues: list[Issue] = []
    down_since = down_since or {}
    shadow = shadowed_ips(snapshot, down_ips)

    # 1) WAN
    if not snapshot.wan_ok and snapshot.wan:
        issues.append(Issue("Internet / WAN", "-", "wan", "critical",
                            f"No WAN reachability ({snapshot.wan})", kind="wan"))

    # 1b) WAN path: pings succeed over either link, so a clean failover would otherwise
    #     look like "internet fine, nothing happened". Severity from wan.path.severity
    #     (critical = immediate Telegram + recovery message when back on the main link).
    wp = snapshot.wan_path or {}
    if wp.get("on_backup"):
        issues.append(Issue("Internet / WAN path", "-", "wan", wp.get("severity", "critical"),
                            f"running on the BACKUP link '{wp.get('link')}' — {wp.get('detail')}",
                            kind="wan-path"))

    # 2) confirmed-down devices. EVERY device that goes down is reported, at the severity
    #    its criticality earns — low/info gear (the TV, the robot vacuum) becomes an
    #    `info` issue. That is deliberately not the same as "not a problem": an info issue
    #    never pages and never makes the network 'degraded' (see `overall` below), but it
    #    is reported once, in the next digest, because a vacuum being off is something the
    #    owner wants to know about even though it is not a network fault.
    #    The once-only part is the alert gate's job, not this function's.
    #    expected_down (PV gear at night) is 'asleep', not down — never an issue; nor is
    #    a device the owner paused (pause.py).
    #    A device down only because what it is reached through is down (`depends_on`)
    #    is not its own issue: its parent's issue names it instead.
    names = {d.ip: d.name for d in snapshot.devices}

    def _behind(ip: str, seen=None) -> list:
        """Everything shadowed by `ip`, and by those in turn — the whole subtree, so the
        VPS's issue names the sites behind its tunnel, not just the tunnel."""
        seen = set() if seen is None else seen
        out = []
        for child, parent in shadow.items():
            if parent == ip and child not in seen:
                seen.add(child)
                out.append(names.get(child, child))
                out.extend(_behind(child, seen))
        return out

    for d in snapshot.devices:
        if d.ip in down_ips and not d.excused and d.ip not in shadow:
            detail = f"unreachable ({', '.join(d.failed_services()) or 'icmp'})"
            behind = _behind(d.ip)
            if behind:
                detail += f" — dark with it: {', '.join(sorted(behind))}"
            issues.append(Issue(d.name, d.ip, d.group, _SEV.get(d.criticality, "info"),
                                detail, kind="down", since=down_since.get(d.ip, 0.0)))

    # 3) degraded (device up but a declared service is failing). SNMP is enrichment-only,
    #    so a failing snmp probe never counts as 'degraded'.
    for d in snapshot.devices:
        failed = [f for f in d.failed_services() if not f.startswith("snmp")]
        if d.ip not in down_ips and d.up and failed and not d.excused \
                and d.ip not in shadow:
            issues.append(Issue(d.name, d.ip, d.group, "warning",
                                f"service degraded: {', '.join(failed)}", kind="degraded"))

    # 3b) the model server: a service of lanowl's own host, not an inventory device
    #     (see Auditor._probe_ollama). Without it every audit quietly falls back to the
    #     deterministic report, and this is the one thing that says so. Debounced like a
    #     device — main keeps it in the tracker under OLLAMA_KEY, so down_ips has it once
    #     it is confirmed. When the model's host is an inventory device of its own and THAT
    #     is down, its issue already says the model is unreachable — a second one for the
    #     same box would be two messages, one incident.
    if snapshot.ollama is not None and OLLAMA_KEY in down_ips \
            and _ollama_ip(cfg) not in down_ips:
        issues.append(Issue("Ollama", _ollama_ip(cfg), "services", "warning",
                            f"{snapshot.ollama.detail} — audits fall back to the "
                            f"deterministic report", kind="degraded",
                            since=down_since.get(OLLAMA_KEY, 0.0)))

    # 4) group-majority escalation (e.g. whole camera range dark => upstream cause)
    #    Shadowed devices do not count towards a majority: they are already explained.
    counts = group_counts(snapshot, down_ips)
    shadowed_in = {}
    for d in snapshot.devices:
        if d.ip in shadow:
            shadowed_in[d.group] = shadowed_in.get(d.group, 0) + 1
    for g, c in counts.items():
        meta = inv.groups.get(g, {})
        own_down = c["down"] - shadowed_in.get(g, 0)
        # a majority of what is WATCHED: five cameras paused for the holiday leave four,
        # and all four going dark is still the whole range
        watched = c["total"] - c.get("paused", 0)
        if meta.get("majority_down_critical") and watched >= 2 and own_down * 2 > watched:
            issues.append(Issue(f"Group '{g}'", "-", g, "critical",
                                f"{c['down']}/{c['total']} in group down — suspect a single upstream cause",
                                kind="group"))

    # 5) ...unless the whole picture says the observer is what broke. One honest issue then
    #    replaces the storm: 40 "unreachable" alerts that all mean "lanowl's host lost its network"
    #    are 40 chances to look in the wrong place, and they arrive as one Telegram burst at
    #    whatever hour it happens. The devices themselves stay in `devices` below, so the
    #    dashboard still shows exactly what could not be reached.
    obs = observer_failure(cfg, snapshot, down_ips, totals(snapshot, down_ips))
    if obs:
        issues = [i for i in issues if i.kind not in ("down", "group", "degraded")] + [obs]

    # Health reflects the NETWORK, not the household. An `info` issue (the TV is off) is
    # reported but must never turn the network 'degraded' — that verdict drives the
    # dashboard colour and, historically, an hourly digest.
    overall = "ok"
    if any(i.severity == "critical" for i in issues):
        overall = "critical"
    elif any(_SEV_RANK.get(i.severity, 0) >= _SEV_RANK["warning"] for i in issues):
        overall = "degraded"

    return {
        "ts": snapshot.ts,
        "overall_health": overall,
        "wan_ok": snapshot.wan_ok,
        "wan_path": snapshot.wan_path,
        # ok | backup | down — what the dashboard box is coloured by. Overwritten in
        # main.py with the WAN watcher's faster answer when the watcher is running.
        "wan_state": wan_state(snapshot.wan_ok, snapshot.wan_path),
        "counts": totals(snapshot, down_ips),
        "groups": counts,
        # down devices explained by something upstream (`depends_on`): {ip: parent ip|"wan"}.
        # Still shown down in `devices` — the dashboard tells the truth; only the *issue* is
        # folded into the parent's.
        "shadowed": shadow,
        "issues": [i.__dict__ for i in sorted(issues, key=lambda x: -_SEV_RANK.get(x.severity, 0))],
        "devices": [{"ip": d.ip, "name": d.name, "group": d.group,
                     # criticality travels with the device so merge_llm can tell an issue
                     # the severity model would raise from one it deliberately mutes
                     "criticality": d.criticality,
                     "up": (d.ip not in down_ips) and d.up,
                     "asleep": (d.ip in down_ips or not d.up) and d.expected_down
                               and not d.paused,
                     # paused whether or not it answers: the owner said not to watch it
                     "paused": d.paused,
                     # rebooting (reboot.py): drawn as such, counted as asleep
                     "held": d.held and (d.ip in down_ips or not d.up),
                     "latency_ms": round(d.latency_ms, 1) if d.latency_ms else None}
                    for d in snapshot.devices],
        # Named service checks (e.g. Node-RED / Mosquitto / Samba on a home server),
        # so the dashboard can show per-service state rather than just host up/down.
        "services": [
            {"host": d.name, "ip": d.ip, "name": c.name, "ok": c.ok,
             "port": c.port, "detail": c.detail}
            for d in snapshot.devices for c in d.checks if c.name
        ] + ([] if snapshot.ollama is None else [
            {"host": f"Model server · {model_name(cfg)}",
             "ip": _ollama_ip(cfg), "name": snapshot.ollama.name, "ok": snapshot.ollama.ok,
             "port": snapshot.ollama.port, "detail": snapshot.ollama.detail}])
          + _router_api_row(snapshot, cfg),
    }


def _router_api_row(snapshot: Snapshot, cfg: Optional[dict]) -> list:
    """How lanowl is reading the router: its kept api-ssl connection, or REST.

    Shown, never alerted: REST still answers every read when the API is down — the cost is
    the router log filling with our logins again, which is worth seeing, not a page."""
    st = getattr(snapshot, "router_api", None)
    if not st:
        return []
    api = ((cfg or {}).get("mikrotik") or {}).get("api") or {}
    if st.get("up"):
        detail = "since " + time.strftime("%H:%M", time.localtime(st.get("since") or 0))
        if not st.get("pinned"):
            detail += " · certificate not pinned"
    else:
        detail = f"reading over REST — {st.get('error') or 'not connected'}"
    return [{"host": "lanowl → router (api-ssl)", "ip": api.get("host") or router_host(cfg),
             "name": "Router API", "ok": bool(st.get("up")), "port": api.get("port", 8729),
             "detail": detail}]


def _ollama_ip(cfg: Optional[dict]) -> str:
    """The model server's address, so its issue is labelled like any device's: the host in
    `model.url`, unless that is this machine under another name — loopback, or the
    container's alias for the Mac it runs on — which is `observer.host_ip`."""
    host = urlsplit(str(model_cfg(cfg).get("url") or "")).hostname or ""
    if host in ("", "127.0.0.1", "localhost", "::1", "host.docker.internal"):
        return ((cfg or {}).get("observer") or {}).get("host_ip", "")
    return host


def totals(snapshot: Snapshot, down_ips: set) -> dict:
    """`paused` counts every paused device, answering or not; `up`, `down` and `asleep`
    count the rest, so the four add up to `total`."""
    total = len(snapshot.devices)
    paused = sum(1 for d in snapshot.devices if d.paused)
    dark = [d for d in snapshot.devices if (d.ip in down_ips or not d.up) and not d.paused]
    asleep = sum(1 for d in dark if d.expected_down)
    down = len(dark) - asleep
    return {"total": total, "up": total - down - asleep - paused, "down": down,
            "asleep": asleep, "paused": paused}


def group_counts(snapshot: Snapshot, down_ips: set) -> dict:
    out: dict[str, dict] = {}
    for d in snapshot.devices:
        c = out.setdefault(d.group, {"total": 0, "down": 0, "up": 0, "asleep": 0, "paused": 0})
        c["total"] += 1
        if d.paused:
            c["paused"] += 1     # nor may a device the owner switched off on purpose
        elif d.ip in down_ips or not d.up:
            # asleep must not count as down: it would poison majority-down escalation
            c["asleep" if d.expected_down else "down"] += 1
        else:
            c["up"] += 1
    return out


def _muted_labels(report: dict) -> set:
    """Names and IPs of down devices the deterministic model will never call an issue.

    Two kinds, both deliberate policy in build_report:
      - **asleep** — PV gear at night, the porch light by day (`expect_offline`);
      - **low/info criticality** — the TV, the robot vacuum, a sleeping laptop. Step 2
        only raises an issue for `warning` and above, precisely so that ordinary gear
        being switched off is not a network problem.
    ...and a third that is the owner's word rather than policy: **paused** (pause.py),
    answering or not.

    The model is told to ignore both, and mostly does, but a local model slips — and a
    single hallucinated "TV unreachable" issue is enough to escalate a healthy report to
    'degraded' and push a digest to Telegram. That is how a TV being off became an hourly
    message. Anything the deterministic model muted, the LLM may describe but may not
    escalate on."""
    out = set()
    for d in report.get("devices", []):
        if d.get("paused"):
            out |= {str(d.get("ip", "")).lower(), str(d.get("name", "")).lower()}
            continue
        if d.get("up"):
            continue
        sev = _SEV.get(d.get("criticality", "info"), "info")
        if d.get("asleep") or _SEV_RANK.get(sev, 0) < _SEV_RANK["warning"]:
            out |= {str(d.get("ip", "")).lower(), str(d.get("name", "")).lower()}
    # 1-2 character labels would match almost any sentence
    return {x for x in out if len(x) >= 3}


def _about_muted(issue: dict, labels: set) -> bool:
    text = f"{issue.get('device', '')} {issue.get('root_cause', '')}".lower()
    return any(l in text for l in labels)


# an IPv4 address; a sentence's full stop after it is not part of it
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")


def name_addresses(text: str, idx) -> str:
    """Put the device's name in front of every bare inventory address in free text.

    label() fixes an issue's `device` field, but the model's prose is the other place a bare
    address reaches a human ("Remote device 10.9.0.10 recovered ~36 min ago"). An address
    whose name already appears in the text is
    left alone, and so is one nobody has a name for — same rule as label()."""
    if not text:
        return text
    by_ip = idx[0]
    folded = text.casefold()

    def one(m):
        ip = m.group(0)
        name = by_ip.get(ip)
        if not name or name.casefold() in folded:
            return ip
        if text[m.start() - 1:m.start()] == "(" and text[m.end():m.end() + 1] == ")":
            return f"{name}, {ip}"          # "(10.9.0.10)" -> "(Name, 10.9.0.10)"
        return f"{name} ({ip})"
    return _IPV4.sub(one, text)


def merge_llm(report: dict, llm: Optional[dict]) -> dict:
    """Attach the LLM audit. Overall health = worst of deterministic vs LLM.

    Muted devices are filtered out first (see _muted_labels): an escalation above the
    deterministic verdict has to be backed by an issue about a device the severity model
    would itself have flagged. With nothing left to point at, the deterministic report
    stands — the LLM's prose is kept, its verdict is not."""
    report = dict(report)
    if llm:
        llm = dict(llm)
        labels = _muted_labels(report)
        issues = [i for i in (llm.get("issues") or []) if not _about_muted(i, labels)]
        dropped = len(llm.get("issues") or []) - len(issues)
        # The prompt asks for the name and the address; a model under load still returns
        # one bare address now and then, and that lands in front of a human. Normalise
        # here rather than trusting the instruction — done AFTER the mute filter, which
        # matches on the model's own wording.
        idx = _label_index(report)
        for i in issues:
            i["device"] = label(i.get("device"), i.get("ip"), idx)
            for field_ in ("root_cause", "evidence", "recommendation"):
                if isinstance(i.get(field_), str):
                    i[field_] = name_addresses(i[field_], idx)
        # ...and the prose, which is what the dashboard's assessment box actually shows
        if isinstance(llm.get("summary"), str):
            llm["summary"] = name_addresses(llm["summary"], idx)
        llm["issues"] = issues
        if dropped:
            llm["muted_issues_dropped"] = dropped
        report["llm"] = llm

        order = {"ok": 0, "degraded": 1, "critical": 2}
        llm_health = llm.get("overall_health", "ok")
        det_health = report["overall_health"]
        escalating = order.get(llm_health, 0) > order.get(det_health, 0)
        if escalating and not issues:
            # nothing awake to justify it (dropped, or the model never named anything)
            report["summary"] = _auto_summary(report)
            return report
        report["summary"] = llm.get("summary", "")
        report["summary_by_model"] = bool(report["summary"])
        report["overall_health"] = llm_health if escalating else det_health
    else:
        report["llm"] = None
        report.setdefault("summary", _auto_summary(report))
    return report


def _auto_summary(report: dict) -> str:
    c = report["counts"]
    wp = report.get("wan_path") or {}
    backup = f" Internet is on the BACKUP link '{wp.get('link')}'." if wp.get("on_backup") else ""
    if report["overall_health"] == "ok":
        quiet = [f"{c['asleep']} asleep as expected" if c.get("asleep") else "",
                 f"{c['paused']} paused" if c.get("paused") else ""]
        quiet = ", ".join(q for q in quiet if q)
        return f"All good — {c['up']}/{c['total']} devices up{f' ({quiet})' if quiet else ''}, WAN OK."
    crit = [i for i in report["issues"] if i["severity"] == "critical"]
    head = f"{c['down']}/{c['total']} devices down." + backup
    if crit:
        idx = _label_index(report)
        head += " Critical: " + "; ".join(
            label(i.get("device"), i.get("ip"), idx) for i in crit[:4])
    return head


# --- Telegram/text formatting ----------------------------------------------
def _label_index(src) -> tuple:
    """{ip: name} and {name: ip} for everything in this sweep.

    Takes a report dict or a Snapshot, so every formatter can build it from whatever it
    already has in hand."""
    if isinstance(src, dict):
        pairs = [(str(d.get("ip") or ""), str(d.get("name") or ""))
                 for d in src.get("devices", [])]
    else:
        pairs = [(str(d.ip), str(d.name)) for d in getattr(src, "devices", [])]
    by_ip, by_name = {}, {}
    for ip, name in pairs:
        if ip:
            by_ip[ip] = name
        if name:
            by_name.setdefault(name.casefold(), ip)
    return by_ip, by_name


def label(device: str = "", ip: str = "", idx=None) -> str:
    """'Nome (192.168.10.x)' — how a device is written everywhere a human reads it.

    A name alone is ambiguous when there are four Shellys; an address alone means walking
    to the inventory to find out what broke, at the exact moment nobody wants to. Both,
    always, so a phone at 3am tells you the whole thing.

    Only the first kind of caller arrives holding both halves:
      - the deterministic issues, which carry name and ip already;
      - the LLM's issues, whose `device` is whatever the model chose to write;
      - the trend records, which are keyed by ip and never had a name at all.
    So each half is looked up from the other when it is missing, which is also what makes
    the output identical no matter which of the three produced it.

    What this will NOT do is invent a name. A DHCP stranger stays a bare address — that is
    the most specific thing anyone knows about it — and a label that never had an address
    of its own ('Internet / WAN', "Group 'cameras'") is returned untouched."""
    by_ip, by_name = idx if idx else ({}, {})
    dev, ip = (device or "").strip(), (ip or "").strip()
    if ip in ("", "-"):                    # ...the model likes putting it in `device`
        ip = by_name.get(dev.casefold(), "") or (dev if dev in by_ip else "")
    if not dev or dev == ip:               # a trend record, or an address used as a name
        dev = by_ip.get(ip, "")
    if dev and ip and ip != "-" and f"({ip})" not in dev:
        return f"{dev} ({ip})"
    return dev or ip or "?"


def format_critical(device_name: str, ip: str, detail: str, snapshot: Snapshot) -> str:
    when = time.strftime("%H:%M:%S", time.localtime(snapshot.ts))
    who = label(device_name, ip, _label_index(snapshot))
    return f"{_EMOJI['critical']} <b>CRITICAL</b> {when}\n{who}\n{detail}"


def format_recovery(device_name: str, ip: str, kind: str = "down", idx=None) -> str:
    if kind in ("wan-path", "wan-link"):
        return f"{_EMOJI['ok']} RECOVERED\nInternet is back on the MAIN link"
    return f"{_EMOJI['ok']} RECOVERED\n{label(device_name, ip, idx)} is back online"


def human_duration(seconds: float) -> str:
    s = int(max(0, seconds))
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    h, m = divmod(s // 60, 60)
    return f"{h}h{m:02d}m" if m else f"{h}h"


def _span(seconds: float, flaps: int, tense: str) -> str:
    """Downtime phrasing that stays honest about flapping.

    With flaps the elapsed span is NOT continuous downtime — it covers the up periods
    in between — so it is described as instability plus the outage count, never as
    'down for 76m' when the line was actually up for half of it."""
    dur = human_duration(seconds)
    if flaps:
        return f"unstable for {dur} · {flaps + 1} outages"
    return f"{tense} {dur}"


def _measured_span(event, tense: str) -> str:
    """How long it was actually broken, preferring a duration the source measured itself.

    An episode's elapsed time is only a proxy for downtime, and for the WAN link it is a
    poor one: a completed flap is held 'present' for `flap_hold_s` after the line is
    already back, so the episode always outlives the outage. When the issue carries an
    `outage_s` (the WAN watcher fills it in from the timestamps of the router's own link
    down/up lines) that measurement wins — a 57s failover reads as 57s, not as the 60s or
    75s of hold window."""
    i = event.issue
    if i.get("outage_s") is None:
        return _span(event.duration_s, event.flaps, tense)
    dur = human_duration(float(i["outage_s"]))
    n = int(i.get("outages", 1))
    return f"{n} outages, {dur} down in total" if n > 1 else f"{tense} {dur}"


def _restored_clock(event) -> str:
    """The wall-clock instant the issue actually cleared, or "" if it cannot be known.

    A recovery message is never prompt: the gate holds it for `recovery_confirm_s` (15
    minutes) of continuous quiet before it believes the problem is over, and anything
    raised during an internet outage waits in the outbox on top of that. "It's back" with
    no time on it therefore tells you the least useful part of the story. `restored_at` is
    the source's own measurement when it has one (the WAN watcher fills it in from the
    router's link-up line); otherwise the episode's `clear_since` — the first moment the
    issue stopped being present — which is exactly the instant asked about."""
    ts = event.issue.get("restored_at") or getattr(event.episode, "clear_since", 0.0)
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""


def _recovery_span(event, tense: str) -> str:
    at = _restored_clock(event)
    span = _measured_span(event, tense)
    return f"back at {at} · {span}" if at else span


def _blackout_note(issue: dict) -> str:
    """Was the network ever left with NO internet during this incident?

    Running on the backup link and having nothing at all are different experiences, and the
    closing message is the one place they can be told apart after the fact — by then the
    dashboard box is green again and the only record of the red minutes is this line."""
    n = int(issue.get("blackouts") or 0)
    if not n:
        return ""
    total = float(issue.get("blackout_s") or 0)
    dur = f", {human_duration(total)} in total" if total else ""
    return (f"\n<i>🔴 no internet at all for part of it: "
            f"{n} blackout(s){dur}</i>")


def format_alerts(events: list, snapshot: Snapshot) -> list:
    """One message per sweep, not one per issue.

    A single root cause (the internet line dropping) raises the WAN issue and every group it
    takes down in the same cycle. Sent one by one that is a burst of near-identical
    pages; grouped, it reads as the one event it actually is. Alerts and recoveries
    stay separate messages so a burst of red is never buried under a green line.

    events: AlertEvent list from AlertGate.update(). Returns [] when there is nothing
    to say."""
    from .alerts import NEW, RECOVERED, STILL

    when = time.strftime("%H:%M:%S", time.localtime(snapshot.ts))
    idx = _label_index(snapshot)
    out = []

    raised = [e for e in events if e.kind in (NEW, STILL)]
    if raised:
        if len(raised) == 1:
            e = raised[0]
            i = e.issue
            head = "CRITICAL" if e.kind == NEW else "STILL CRITICAL"
            age = f"\n<i>{_span(e.duration_s, e.flaps, 'down for')}</i>" \
                if e.kind == STILL else ""
            out.append(f"{_EMOJI['critical']} <b>{head}</b> {when}\n"
                       f"{label(i.get('device'), i.get('ip'), idx)}\n{i['detail']}{age}")
        else:
            lines = [f"{_EMOJI['critical']} <b>CRITICAL</b> {when} — {len(raised)} issues",
                     "<i>one event, probably one cause</i>"]
            for e in raised:
                i = e.issue
                lines.append(f"• <b>{label(i.get('device'), i.get('ip'), idx)}</b>: "
                             f"{i['detail']}")
            out.append("\n".join(lines))

    healed = [e for e in events if e.kind == RECOVERED]
    if healed:
        if len(healed) == 1:
            e = healed[0]
            i = e.issue
            base = format_recovery(i["device"], i.get("ip", ""),
                                   kind=i.get("kind", "down"), idx=idx)
            extra = _blackout_note(i)
            out.append(f"{base}\n<i>{_recovery_span(e, 'was down')}</i>{extra}")
        else:
            lines = [f"{_EMOJI['ok']} <b>RECOVERED</b> {when} — {len(healed)} issues"]
            for e in healed:
                i = e.issue
                lines.append(f"• {label(i.get('device'), i.get('ip'), idx)}: "
                             f"{_recovery_span(e, 'back after')}")
            out.append("\n".join(lines))

    return out


def digest_fingerprint(report: dict) -> str:
    """Identity of a digest's *content*, so an unchanged one isn't re-sent every hour.

    Health plus the set of open issues — deliberately not the counts or the LLM prose,
    which drift by a device or a word while nothing has actually changed."""
    keys = sorted(f"{i.get('kind')}:{i.get('ip')}:{i.get('device')}:{i.get('severity')}"
                  for i in report.get("issues", []))
    return f"{report.get('overall_health')}|{report.get('wan_ok')}|" + ";".join(keys)


def _clock(ts: float, now: float) -> str:
    """HH:MM:SS, with the day in front once it is no longer today's."""
    t = time.localtime(ts)
    fmt = "%H:%M:%S" if t[:3] == time.localtime(now)[:3] else "%d/%m %H:%M:%S"
    return time.strftime(fmt, t)


def _since_note(issue: dict, now: float) -> str:
    """' — since 14:02:27', or ' — unstable since 14:02:27 · 3 outages' for a flapper.

    A digest is late by design. It is written at the next audit, up to an hour after the
    device dropped, and the daily re-state a day or more after that; the critical page
    carries the sweep's clock in its header, but nothing that leaves by the digest door
    ever said when. Yet *when* is the first question on reading "unreachable" — it is
    what places the vacuum next to the power flicker or the boiler next to the firmware
    update. So every line names the instant. `since` is whatever the sender knows best:
    the first missed sweep for a `down` issue, the gate's episode start otherwise (main.py
    stamps both, preferring the episode so a flapper is dated from its first drop). The
    day appears once it is no longer today's, which the daily reminder needs."""
    ts = float(issue.get("since") or 0)
    if not ts:
        return ""
    flaps = int(issue.get("flaps") or 0)
    at = _clock(ts, now)
    if flaps:
        return f" — <i>unstable since {at} · {flaps + 1} outages</i>"
    return f" — <i>since {at}</i>"


def _html(s) -> str:
    """Model text going into a Telegram HTML message. A stray '<' in its prose used to be
    the one thing that could make Telegram refuse a digest outright."""
    return html.escape(str(s or ""), quote=False)


def _short(s, n: int = 170) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def match_diagnosis(issue: dict, llm_issues: list) -> Optional[dict]:
    """The model's issue about the same thing as this deterministic one, if it wrote one.

    By address first — merge_llm has already put 'Name (ip)' on every model issue — then by
    name, for the issues that have no address of their own (a group, the WAN)."""
    ip = str(issue.get("ip") or "")
    if ip and ip != "-":
        for d in llm_issues:
            if str(d.get("ip") or "") == ip or f"({ip})" in str(d.get("device") or ""):
                return d
        return None      # it has an address: a name match would be about another device
    name = str(issue.get("device") or "").casefold()
    if name:
        for d in llm_issues:
            if name in str(d.get("device") or "").casefold():
                return d
    return None


def _diag_line(d: dict) -> str:
    cause, rec = _short(d.get("root_cause")), _short(d.get("recommendation"), 120)
    if not cause and not rec:
        return ""
    return ("   ↳ " + (f"<i>{_html(cause)}</i>" if cause else "")
            + (f" → {_html(rec)}" if rec else ""))


def ran_lines(ran: list, limit: int = 12) -> list:
    """What the model ran by itself, one line each: 🔧 and the check (or the command), ✗ for one
    that failed. The same under a Telegram answer, a digest and an incident's alert, so a
    diagnosis always says what it was based on."""
    out = [f"{'🔧' if r.get('ok') else '✗'} {_html(r.get('label') or r.get('command') or '')}"
           for r in (ran or [])[:limit]]
    if len(ran or []) > limit:
        out.append(f"…and {len(ran) - limit} more")
    return out


def format_diagnosis_note(issues: list, llm: Optional[dict], at: Optional[float] = None,
                          ran: Optional[list] = None) -> str:
    """The note, with what the model checked by itself to reach it (`ran`) under it."""
    note = _diagnosis(issues, llm, at)
    if note and ran:
        note += "\n" + "\n".join(ran_lines(ran, 6))
    return note


def _diagnosis(issues: list, llm: Optional[dict], at: Optional[float] = None) -> str:
    """What an incident triage adds to its alert — edited INTO that message, never a second one.

    The triage that runs on every new critical writes a root cause, the evidence and a
    recommendation; without this the phone gets the alert and never the why. Marked as the
    model's, with its own time, because it is an opinion that arrived later than the fact
    above it."""
    if not llm:
        return ""
    when = time.strftime("%H:%M", time.localtime(at or time.time()))
    rows = [(i, d) for i in issues for d in [match_diagnosis(i, llm.get("issues") or [])] if d]
    if not rows:
        s = _short(llm.get("summary"), 300)
        return f"\n\n🦉 <i>model, {when}:</i> {_html(s)}" if s else ""
    if len(rows) == 1:
        _, d = rows[0]
        out = f"\n\n🦉 <b>Likely cause</b> <i>(model, {when})</i>: {_html(_short(d.get('root_cause')))}"
        if d.get("recommendation"):
            out += f"\n→ {_html(_short(d['recommendation'], 140))}"
        return out
    lines = ["", "", f"🦉 <b>Likely causes</b> <i>(model, {when})</i>"]
    for i, d in rows[:6]:
        lines.append(f"• {label(i.get('device'), i.get('ip'))}: {_html(_short(d.get('root_cause'), 120))}")
    return "\n".join(lines)


def format_digest(report: dict, now: Optional[float] = None,
                  title: str = "lanowl digest") -> str:
    now = time.time() if now is None else now
    e = _EMOJI.get(report["overall_health"], "⚪")
    c = report["counts"]
    asleep = f" · {c['asleep']} asleep" if c.get("asleep") else ""
    asleep += f" · {c['paused']} paused" if c.get("paused") else ""
    wp = report.get("wan_path") or {}
    state = report.get("wan_state") or wan_state(report["wan_ok"], wp)
    # The three states read as three different sentences. "OK via <backup>" would be the one
    # wording that manages to be both true and misleading.
    wan = {"ok": "OK", "down": "DOWN — no internet at all",
           "backup": f"on the BACKUP link '{wp.get('link') or 'backup'}'"}.get(state, "OK")
    idx = _label_index(report)
    lines = [f"{e} <b>{title}</b> — {report['overall_health'].upper()}",
             f"{c['up']}/{c['total']} up{asleep} · WAN {wan}"]
    if report.get("summary"):
        # the model's summary carries the owl's mark; the monitor's own does not
        lines.append(("🦉 " if report.get("summary_by_model") else "") + _html(report["summary"]))
    # Every open issue is listed, info included — the ⚪ lines are how "the vacuum is off"
    # reaches you. The gate upstream guarantees a given issue only reaches a digest once,
    # so listing them here cannot become a repeating message.
    #
    # Under each one, the model's cause and suggestion when it wrote one: every audit
    # returns a root_cause and a recommendation per issue.
    llm_issues = list(((report.get("llm") or {}).get("issues")) or [])
    used = set()
    issues = report["issues"]
    shown, rest = issues[:10], issues[10:]
    for i in shown:
        lines.append(f"{_EMOJI.get(i['severity'], '•')} "
                     f"{label(i.get('device'), i.get('ip'), idx)}: {i['detail']}"
                     f"{_since_note(i, now)}")
        d = match_diagnosis(i, llm_issues) if i.get("severity") != "info" else None
        if d:
            used.add(id(d))
            dl = _diag_line(d)
            if dl:
                lines.append(dl)
    if rest:
        lines.append(f"…and {len(rest)} more (see dashboard)")

    # What the model found that no rule raised. Only what it rated warning or worse, and
    # only a few: merge_llm has already dropped anything about muted (asleep / low) gear.
    extra = [d for d in llm_issues if id(d) not in used
             and d.get("severity") in ("critical", "high", "warning")][:3]
    if extra:
        lines.append("🦉 <b>The model also noticed</b>")
        for d in extra:
            lines.append(f"• {label(d.get('device'), d.get('ip'), idx)}: "
                         f"{_html(_short(d.get('root_cause'), 140))}"
                         + (f" → {_html(_short(d.get('recommendation'), 100))}"
                            if d.get("recommendation") else ""))

    # Brief internet drops under the paging floor. Not "covered by the backup": a short drop
    # may never reach the failover at all, with the router's own pings never failing
    # (wanexplain.py says where each one broke). The count is how you notice a bad week
    # rather than a bad minute.
    ww = report.get("wan_watch") or {}
    if ww.get("blips_24h"):
        longest = ww.get("longest_blip_s")
        lines.append(f"🔵 Internet: {ww['blips_24h']} brief drop(s) in 24h"
                     + (f", longest {human_duration(longest)}" if longest else "")
                     + " — under the paging floor, not alerted; the dashboard's Internet "
                       "card says where each one broke")

    # Things that still work but are getting worse. This is the only part of the digest
    # that looks BACKWARDS rather than at the current sweep, and it is the part that would
    # have caught the lifting pumps before they started crying wolf.
    trends = report.get("trends") or []
    if trends:
        lines.append("📉 <b>Quietly getting worse</b>")
        for t in trends[:5]:
            lines.append(f"• {label(t.get('device'), t.get('ip'), idx)}: {t['why']}")

    # What the model's own scheduled looks found since the last digest (reviews.py):
    # slowly changing, what changed in the configurations. Each
    # item rides ONE digest; the lines are already HTML, escaped where they were written.
    for sec in report.get("review_news") or []:
        lines.append(f"{sec.get('icon') or '•'} <b>{_html(sec.get('title') or '')}</b> "
                     "<i>(the model's look — the dashboard has the rest)</i>")
        lines += list(sec.get("lines") or [])[:5]
        if len(sec.get("lines") or []) > 5:
            lines.append(f"…and {len(sec['lines']) - 5} more on the dashboard")

    # Every digest names what is paused, because a pause is silence by design and the one
    # way it goes wrong is being forgotten (pause.py).
    paused = report.get("paused") or []
    if paused:
        lines.append(format_paused(paused, now))
    # the same for the local model switched off (Auditor.set_model): silence by choice
    if report.get("model_off"):
        lines.append(format_model_off(report["model_off"], now))
    # what the audit looked at by itself (passive checks, its offline shell),
    # listed like the 🔧 lines under a Telegram answer
    ran = report.get("checks_ran") or []
    if ran:
        lines.append("<i>The audit looked for itself:</i>")
        lines += ran_lines(ran, 8)
    return "\n".join(lines)


def format_model_off(m: dict, now: Optional[float] = None) -> str:
    """'🦉 The owl is asleep since 29/09 14:02 (local model off) — …', while the owner has it off."""
    now = time.time() if now is None else now
    return (f"🦉 <b>The owl is asleep</b> since {_clock(m.get('since') or now, now)} (local model off) — no diagnoses, "
            f"answers or reviews until you switch it on (/model on)")


def format_paused(paused: list, now: Optional[float] = None) -> str:
    """'⏸ Paused, not watched: TV (192.168.10.36) since 20/09 14:02, off; …'"""
    now = time.time() if now is None else now
    bits = [f"{_html(label(p.get('name'), p.get('ip')))} since {_clock(p['ts'], now)}"
            + ("" if p.get("up") is None else (", answering" if p["up"] else ", off"))
            for p in paused[:8]]
    more = f" …and {len(paused) - 8} more" if len(paused) > 8 else ""
    return "⏸ <b>Paused, not watched</b>: " + "; ".join(bits) + more
