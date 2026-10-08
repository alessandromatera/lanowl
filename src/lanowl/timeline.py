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

`assemble()` is pure (unit-tested); `build()` gathers its inputs.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Optional

from .configwatch import change_id
from .model import wan_links
from .wanexplain import merge

GROUP_S = 180.0       # outages that start this close together are one incident
CAUSE_S = 600.0       # an action on the network this long before may be what did it
WAN_NEAR_S = 180.0    # an internet outage this close to an incident's start is part of it
RAN = ("done", "failed", "running")       # approved and not run (skipped, cancelled) did nothing
STORY_S = 86400.0     # a log check or config change that names a new device within a day is its story
TOLD_S = 120.0        # a digest leaves within this of the audit that wrote it
_CIDR = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})(?![\d])")
# a device's name too common to say that a line is about it ("MikroTik", "iPhone")
_GENERIC = {"mikrotik", "iphone", "ipad", "android", "espressif", "raspberrypi", "unknown",
            "localhost", "router", "laptop", "desktop", "galaxy", "routerboard"}


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


def _ip_rx(ip: str):
    """This address and not a longer one (.11 is not .117)."""
    return re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d])")


def _words(x: dict) -> str:
    """What a log check or a config change says, to look for a device's address or name in."""
    if x["type"] == "check":
        return " ".join([str(x.get("summary") or ""), str(x.get("detail") or "")] + list(x.get("log") or []))
    return " ".join([str(x.get("what") or ""), str(x.get("why") or "")] + list(x.get("lines") or []))


def _holds(net: str, ip: str) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def stories(news: list, others: list, lan: tuple = ()) -> dict:
    """A new device's story: the log checks and config changes of the day after it joined that
    NAME it (its address, its MAC, its name when that is not a common word), then the ones that
    share a network those name (a route to 192.168.77.0/24 that names it, and the VPN peer for
    the same 192.168.77.0/24 elsewhere). Its own LAN never links anything: every line there
    would. {new device id: [(item, why)]}, oldest first. Only words are compared: two devices
    are never merged here (the owner, 10-08: the owl decides what is one box)."""
    out = {}
    for d in news:
        t0 = d["ts"]
        near = [x for x in others if t0 - 600 <= x["ts"] <= t0 + STORY_S]
        if not near:
            continue
        seeds = []
        if d.get("ip"):
            seeds.append((_ip_rx(d["ip"]), d["ip"]))
        if d.get("mac"):
            seeds.append((re.compile(re.escape(d["mac"]), re.I), d["mac"].upper()))
        nm = str(d.get("name") or "")
        if len(nm) >= 6 and nm.lower() not in _GENERIC and not nm.lower().startswith(("a phone", "private")):
            seeds.append((re.compile(r"(?<![\w])" + re.escape(nm) + r"(?![\w])", re.I), nm))
        linked, nets = [], set()
        for x in near:
            t = _words(x)
            hit = next((w for rx, w in seeds if rx.search(t)), None)
            if hit:
                linked.append((x, f"names {hit}"))
                nets |= set(_CIDR.findall(t))
        nets = {n for n in nets if not _holds(n, d.get("ip")) and n not in lan
                and int(n.split("/")[1]) >= 16 and not n.endswith("/32")}
        for x in near:
            if any(x is y for y, _ in linked):
                continue
            hit = next((n for n in sorted(nets) if n in _words(x)), None)
            if hit:
                linked.append((x, f"same network {hit}"))
        if linked:
            out[d["id"]] = sorted(linked, key=lambda v: v[0]["ts"])
    return out


def owl_items(audits: list, telegram: list, since: float) -> list:
    """The hourly audit's verdicts, one row each time it CHANGES — its health, or the devices
    it names as issues — or sends a digest; the rest repeat the hour before. Each carries the
    digest it sent."""
    out, prev = [], None
    for a in sorted(audits, key=lambda x: x["ts"]):
        if a.get("health") is None and not a.get("summary"):
            continue                              # the model gave nothing: the monitor's report stood
        key = (a.get("health"), tuple(sorted(str(i.get("device") or "") for i in a.get("issues") or [])))
        sent = str(a.get("digest") or "").startswith("sent")
        changed = key != prev
        prev = key
        if a["ts"] < since or not (changed or sent):
            continue
        told = [m for m in telegram if m.get("channel") == "digest" and abs(m["ts"] - a["ts"]) <= TOLD_S
                and "digest" in _first_line(m.get("text")).lower()]
        out.append({"type": "owl", "ts": a["ts"], "health": a.get("health"), "summary": a.get("summary") or "",
                    "issues": [{"device": i.get("device"), "severity": i.get("severity"),
                                "cause": i.get("cause") or i.get("root_cause")} for i in a.get("issues") or []],
                    "changed": changed, "digest": a.get("digest") or "",
                    "told": [{"ts": m["ts"], "channel": m.get("channel"), "text": _first_line(m.get("text")),
                              "_m": m} for m in told]})
    return out


def owl_words(d: dict, audits: list) -> dict:
    """What the owl said about one new device: the last sentence of its summaries naming it,
    and how many audits raised it as an issue."""
    rxs = [_ip_rx(d["ip"])] if d.get("ip") else []
    nm = str(d.get("name") or "")
    if len(nm) >= 6 and nm.lower() not in _GENERIC:
        rxs.append(re.compile(re.escape(nm), re.I))
    said, raised, at = "", 0, None
    for a in sorted(audits, key=lambda x: x["ts"]):
        if a["ts"] < d["ts"]:
            continue
        if any(rx.search(str(i.get("device") or "")) for i in a.get("issues") or [] for rx in rxs):
            raised += 1
        for sent in re.split(r"(?<=[.!?])\s+", str(a.get("summary") or "")):
            if any(rx.search(sent) for rx in rxs):
                said, at = sent.strip(), a["ts"]
    return {k: v for k, v in (("said", said), ("said_ts", at), ("raised", raised)) if v}


def assemble(rows: list, wan: list, telegram: list, actions: list, seclog: dict, seen: list,
             findings: list, groups: dict, now: float, days: float = 7.0,
             wan_since: Optional[float] = None, renames: tuple = (), why=None,
             audits: tuple = (), configs: tuple = (), lan: tuple = ()) -> dict:
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
    attached: set = set()        # the messages shown under the event they are about
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
                    attached.add(id(m))
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
    # what the owl said, each time its verdict changed or it sent a digest
    for o in owl_items(list(audits), telegram, since):
        for t in o["told"]:
            attached.add(id(t.pop("_m")))
        items.append(o)
    refused: dict = {}
    for p in actions:
        if (p.get("ts") or 0) < since:
            continue
        if p.get("status") == "refused" and not p.get("owner"):
            day = time.strftime("%Y-%m-%d", time.localtime(p["ts"]))
            refused.setdefault(day, []).append(p)
            continue
        at = p.get("done_ts") or p.get("decided_ts") or p["ts"]
        rx = re.compile(r"#%s(?!\d)" % p.get("id"))
        told = [m for m in telegram if p.get("id") is not None and p["ts"] - 60 <= m["ts"] <= at + 3600
                and rx.search(m.get("text", ""))]
        attached.update(id(m) for m in told)
        items.append({"type": "action", "ts": at,
                      "asked": p["ts"], "id": p.get("id"), "action": p.get("action"),
                      "title": p.get("title"), "label": p.get("label"), "ip": p.get("ip"),
                      "status": p.get("status"), "via": p.get("via"), "owner": bool(p.get("owner")),
                      "words": p.get("words"), "decided_from": p.get("decided_from"),
                      "told": [{"ts": m["ts"], "channel": m.get("channel"), "text": _first_line(m.get("text")),
                                "full": str(m.get("text") or "")[:1500]} for m in told]})
    for day, ps in refused.items():
        items.append({"type": "refused", "ts": max(p["ts"] for p in ps), "n": len(ps),
                      "ids": [p.get("id") for p in ps]})
    # the configurations' changes (configwatch.py), and what the logs said: the stories' parts
    sids = {c.get("sid") for c in configs if c.get("sid")}
    for x in (seclog.get("open") or []) + (seclog.get("handled") or []):
        if (x.get("ts") or 0) >= since and x.get("id") not in sids:
            told = [m for m in telegram if abs(m["ts"] - (x.get("ts") or 0)) <= 900 and x.get("title")
                    and str(x["title"])[:40] in m.get("text", "")]
            attached.update(id(m) for m in told)
            items.append({"type": "security", "ts": x["ts"], "id": x.get("id"), "title": x.get("title"),
                          "sev": x.get("sev"), "ip": x.get("ip"), "source": x.get("source"),
                          "handled": x.get("handled"), "count": x.get("count") or 1,
                          "told": [{"ts": m["ts"], "channel": m.get("channel"), "text": _first_line(m.get("text"))}
                                   for m in told]})
    handled = {x.get("id"): x.get("handled") for x in (seclog.get("handled") or [])}
    others = []
    for c in configs:
        if (c.get("ts") or 0) >= since:
            others.append({"type": "config", "id": change_id(c), "ts": c["ts"],
                           "ip": c.get("ip"), "name": c.get("name"), "risk": c.get("risk"),
                           "what": c.get("what"), "why": c.get("why"), "lines": list(c.get("lines") or [])[:12],
                           "sid": c.get("sid"), "handled": c.get("handled") or handled.get(c.get("sid")),
                           "by": c.get("by")})
    for f in findings:
        if (f.get("ts") or 0) >= since:
            others.append({"type": "check", "id": f"chk:{f['ts']:.3f}", "ts": f["ts"], "source": f.get("source"),
                           "problem": bool(f.get("problem")), "severity": f.get("severity"),
                           "kind": f.get("kind"), "summary": f.get("summary"), "detail": f.get("detail"),
                           "log": list(f.get("log") or [])})
    news = []
    for r in seen:
        if (r.get("first_seen") or 0) >= since and not r.get("before"):
            mac = str(r.get("mac") or "")
            told = [m for m in telegram if mac and mac.lower() in m.get("text", "").lower()]
            attached.update(id(m) for m in told)
            news.append({"type": "new_device", "id": f"new:{r.get('site') or 'home'}:{mac.upper()}",
                         "ts": r["first_seen"], "site": r.get("site"),
                         "site_name": r.get("site_name"), "ip": r.get("ip"), "mac": mac,
                         "name": r.get("name") or r.get("host") or "", "vendor": r.get("vendor") or "",
                         "guest": bool(r.get("guest")), "status": r.get("status") or "",
                         # when the router or lanowl last HEARD from it — not when a table last listed it
                         "last": r.get("heard"), "here": bool(r.get("here")),
                         "told": [{"ts": m["ts"], "channel": m.get("channel"), "text": _first_line(m.get("text")),
                                   "full": str(m.get("text") or "")[:1500]} for m in told]})
    st = stories(news, others, tuple(lan))
    for d in news:
        d["owl"] = owl_words(d, list(audits))
        d["story"] = [{"id": x["id"], "type": x["type"], "ts": x["ts"], "why": why_,
                       "text": x.get("summary") if x["type"] == "check" else x.get("what"),
                       "where": x.get("source") if x["type"] == "check" else x.get("name"),
                       "level": (x.get("severity") if x.get("problem") else "fine") if x["type"] == "check"
                       else x.get("risk"), "sid": x.get("sid"), "handled": bool(x.get("handled"))}
                      for x, why_ in st.get(d["id"], [])]
        for x, why_ in st.get(d["id"], []):
            x.setdefault("part_of", {"id": d["id"], "ts": d["ts"], "name": d["name"] or d["ip"], "why": why_})
    items += news + others
    for m in telegram:
        if m["ts"] >= since:
            items.append({"type": "telegram", "ts": m["ts"], "channel": m.get("channel"),
                          "text": _first_line(m.get("text")), "full": str(m.get("text") or "")[:1500],
                          **({"attached": True} if id(m) in attached else {})})
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
    audits = []
    for e in a.state.events(since - 86400, kind="audit", limit=1000):
        try:
            audits.append({"ts": e["ts"], **json.loads(e.get("detail") or "{}")})
        except ValueError:
            continue
    cw = getattr(a, "configwatch", None)
    configs = list((cw.rec.get("changes") if cw is not None else None) or [])
    try:
        lan = tuple(str(n) for n in a.sites._lan(a.sites.get("home")))
    except Exception:
        lan = ()
    out = assemble(rows, wan, tg, acts, a.seclog.view(now), seen, fs, groups, now, days, wan_since,
                   renames, why=why, audits=audits, configs=configs, lan=lan)
    a.stories = story_index(out["items"], now)
    return out


def story_index(items: list, now: float) -> dict:
    """What each config change and security item is part of, for the cards that show them on
    Now and Security ("part of the access point you set up Tue 15:40"): {"cfg": {sid or id: part},
    "dev": {MAC: the new device's story, the owl's words, its messages}, "ts"}."""
    cfg, dev = {}, {}
    for x in items:
        if x["type"] == "new_device" and (x.get("story") or now - x["ts"] < 3 * 86400):
            # keyed by MAC: Now and Devices find a new device's verdict and message by it
            dev[str(x.get("mac") or "").lower()] = {
                "id": x["id"], "name": x.get("name") or x.get("ip"), "ip": x.get("ip"), "ts": x["ts"],
                "n": len(x.get("story") or []), "owl": x.get("owl") or {},
                "told": [t["ts"] for t in x.get("told") or []]}
        if x["type"] == "config" and x.get("part_of"):
            for k in (x.get("sid"), x["id"]):
                if k:
                    cfg[k] = x["part_of"]
    return {"cfg": cfg, "dev": dev, "ts": now}
