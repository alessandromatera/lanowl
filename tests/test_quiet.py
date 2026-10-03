"""Telegram quiet-policy tests: run with `python -m tests.test_quiet`.

The rule these pin down is the one that matters to a human holding the phone: a critical
edge (the internet line dropping) pages immediately, every incident — and a switched-off TV never
pages at all, no matter how many hours it stays off or how the LLM narrates it.

Regression under test: the deterministic report OK hour after hour, yet a digest each hour,
because the LLM escalated ok -> degraded citing the TV and the robot vacuum (both `info`
criticality, which build_report never raises).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.report import _muted_labels, digest_fingerprint, merge_llm

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def base_report(**kw):
    """A healthy deterministic report with the TV + vacuum off."""
    r = {
        "ts": 0, "overall_health": "ok", "wan_ok": True, "wan_path": None,
        "counts": {"total": 53, "up": 50, "down": 0, "asleep": 1},
        "groups": {}, "issues": [],
        "devices": [
            {"ip": "192.168.10.36", "name": "TV Lounge LG OLED", "group": "media",
             "criticality": "info", "up": False, "asleep": False, "latency_ms": None},
            {"ip": "192.168.10.115", "name": "Robot vacuum", "group": "iot",
             "criticality": "info", "up": False, "asleep": False, "latency_ms": None},
            {"ip": "192.168.10.120", "name": "Solar inverter", "group": "energy",
             "criticality": "high", "up": False, "asleep": True, "latency_ms": None},
            {"ip": "192.168.10.1", "name": "Router RB5009 MikroTik", "group": "network",
             "criticality": "critical", "up": True, "asleep": False, "latency_ms": 29},
        ],
        "services": [],
    }
    r.update(kw)
    return r


def test_muted_labels():
    print("devices the severity model mutes are identified")
    labels = _muted_labels(base_report())
    check("tv lounge lg oled" in labels, "the info-criticality TV is muted")
    check("192.168.10.36" in labels, "by IP as well as name")
    check("solar inverter" in labels, "asleep PV gear is still muted (old behaviour kept)")
    check(not any("router" in l for l in labels), "an UP critical device is not muted")
    check(all(len(l) >= 3 for l in labels), "no 1-2 char labels that would match any text")


def test_llm_cannot_escalate_on_a_switched_off_tv():
    print("the LLM cannot turn a healthy network 'degraded' over the TV")
    llm = {"overall_health": "degraded",
           "summary": "Two devices are unreachable: TV Lounge and Robot vacuum.",
           "issues": [{"device": "TV Lounge LG OLED", "severity": "warning",
                       "root_cause": "unreachable on the LAN"},
                      {"device": "Robot vacuum", "severity": "warning",
                       "root_cause": "not answering ICMP"}]}
    out = merge_llm(base_report(), llm)
    check(out["overall_health"] == "ok", f"verdict stays ok (got {out['overall_health']})")
    check(out["llm"]["issues"] == [], "both muted issues were dropped")
    check(out["llm"].get("muted_issues_dropped") == 2, "and the drop is recorded")
    check(not out["issues"], "no deterministic issue was invented")


def test_llm_can_still_escalate_on_something_real():
    print("but it CAN escalate about a device that really matters")
    llm = {"overall_health": "degraded",
           "summary": "The Intercom is unreachable.",
           "issues": [{"device": "Door intercom", "severity": "warning",
                       "root_cause": "no answer on port 80"}]}
    rep = base_report()
    rep["devices"].append({"ip": "192.168.10.37", "name": "Door intercom",
                           "group": "security", "criticality": "high", "up": False,
                           "asleep": False, "latency_ms": None})
    out = merge_llm(rep, llm)
    check(out["overall_health"] == "degraded", "escalation is allowed through")
    check(len(out["llm"]["issues"]) == 1, "the real issue survives the filter")


def test_deterministic_criticals_are_never_touched():
    print("a deterministic critical always stands, whatever the LLM says")
    rep = base_report(overall_health="critical", issues=[
        {"device": "Internet / WAN", "ip": "-", "group": "wan", "severity": "critical",
         "detail": "No WAN reachability", "kind": "wan"}])
    out = merge_llm(rep, {"overall_health": "ok", "summary": "all fine", "issues": []})
    check(out["overall_health"] == "critical", "the LLM cannot downgrade it")
    check(len(out["issues"]) == 1, "and cannot remove the issue")


def test_digest_fingerprint_ignores_prose():
    print("digest identity is the issue set, not the wording")
    a = base_report(overall_health="degraded", issues=[
        {"device": "Intercom", "ip": "192.168.10.37", "group": "security",
         "severity": "warning", "detail": "unreachable (icmp)", "kind": "down"}])
    b = dict(a, summary="totally different prose from a different audit")
    check(digest_fingerprint(a) == digest_fingerprint(b),
          "same issues + different summary = same digest, so it is not re-sent")
    c = dict(a, issues=a["issues"] + [
        {"device": "NVR", "ip": "192.168.10.60", "group": "cameras",
         "severity": "warning", "detail": "unreachable", "kind": "down"}])
    check(digest_fingerprint(a) != digest_fingerprint(c),
          "a new issue changes it, so that digest IS sent")


def test_minor_device_is_reported_once_then_silent():
    """The vacuum going off IS news — exactly once. Then nothing until it happens again."""
    print("a low/info device off is reported once, then never repeated")
    from lanowl.alerts import NEW, RECOVERED, STILL, AlertGate

    VAC = {"device": "Robot vacuum", "ip": "192.168.10.115", "group": "iot",
           "severity": "info", "detail": "unreachable (icmp)", "kind": "down"}
    # Model production faithfully: the gate is updated by the SWEEP every 60s, while the
    # digest decision runs on the hourly LLM cadence and consumes whatever news accrued.
    g, t = AlertGate(), 0.0
    digests, news, recoveries = 0, False, 0

    def run(hours, issues):
        """Advance `hours` of 60s sweeps with `issues` standing, checking digests hourly."""
        nonlocal digests, news, recoveries
        for m in range(int(hours * 60)):
            now = t + run.minute * 60
            run.minute += 1
            ev = g.update(issues, now)
            for e in ev:
                if e.issue.get("severity") == "critical":
                    continue
                if e.kind in (NEW, STILL):
                    news = True
                elif e.kind == RECOVERED:
                    recoveries += 1
            if run.minute % 60 == 0 and news:      # the hourly audit sends the digest
                digests += 1
                news = False
    run.minute = 0

    run(1, {})                                     # baseline, vacuum on
    check(digests == 0, "nothing to say while everything is fine")
    run(1, {"vac": VAC})                           # goes off
    check(digests == 1, f"one digest when it goes off (got {digests})")
    run(11, {"vac": VAC})                          # stays off for 11 more hours
    check(digests == 1, f"still exactly one after 11 more hours (got {digests})")
    run(2, {})                                     # comes back on
    check(digests == 1, "coming back on does not send a digest of its own")
    check(recoveries == 1, f"the episode closed cleanly (got {recoveries})")
    run(2, {"vac": VAC})                           # a genuinely new outage, hours later
    check(digests == 2, f"a NEW outage later is worth one more (got {digests})")


def test_recovery_never_triggers_a_digest():
    """Regression: a digest fired because the robot vacuum came back half an hour
    earlier. The news test passed while production ORed in `fp != last_fp`, which also
    changes when an issue LEAVES the set. News must be per-key and open-at-digest-time."""
    print("a recovery, and a self-healed blip, never trigger a digest")
    from lanowl.alerts import NEW, RECOVERED, STILL, AlertGate

    CAM = {"device": "Camera Front door", "ip": "192.168.10.71", "group": "cameras",
           "severity": "warning", "detail": "service degraded: tcp/554", "kind": "degraded"}
    VAC = {"device": "Robot vacuum", "ip": "192.168.10.115", "group": "iot",
           "severity": "info", "detail": "unreachable (icmp)", "kind": "down"}

    g, t = AlertGate(), 0.0
    news, digests, minute = set(), 0, 0

    def run(hours, issues):
        """60s sweeps + an hourly digest decision, exactly as main.py wires it."""
        nonlocal digests, minute
        for _ in range(int(hours * 60)):
            now = t + minute * 60
            minute += 1
            for e in g.update(issues, now):
                if e.issue.get("severity") == "critical":
                    continue
                if e.kind in (NEW, STILL):
                    news.add(e.episode.key)
                elif e.kind == RECOVERED:
                    news.discard(e.episode.key)
            if minute % 60 == 0:
                pending = news & set(issues)      # unreported AND still open
                if pending:
                    digests += 1
                    news.clear()

    run(1, {"vac": VAC})                 # vacuum off -> reported at the hour
    check(digests == 1, f"the vacuum being off is reported once (got {digests})")
    run(3, {"vac": VAC})
    check(digests == 1, "and not again while it stays off")
    run(2, {})                           # comes back on
    check(digests == 1, f"its recovery sends nothing (got {digests})")

    # the 02:00 cameras: degraded, healed 17 minutes later, between two audits
    before = digests
    for m in range(17):
        g.update({"cam": CAM}, t + (minute + m) * 60)
        for e in g.update({"cam": CAM}, t + (minute + m) * 60):
            if e.kind in (NEW, STILL):
                news.add(e.episode.key)
    minute += 17
    run(2, {})                           # healed before the next audit
    check(digests == before, f"a blip that healed between audits is never sent (got {digests-before} extra)")


def test_a_reported_problem_gets_a_recovery_message():
    """A device the owner was told has a problem gets a message when it works again.
    Criticals always did; everything that left by the digest door must too — not have its key
    dropped from _digest_news, leaving the owner's last word on the boiler 'unreachable'."""
    print("a problem the user was TOLD about reports itself fixed")
    from lanowl.alerts import NEW, RECOVERED, STILL, AlertGate

    BOILER = {"device": "Boiler", "ip": "192.168.10.117", "group": "home",
              "severity": "high", "detail": "unreachable (icmp)", "kind": "down"}
    CAM = {"device": "Camera Front door", "ip": "192.168.10.71", "group": "cameras",
           "severity": "warning", "detail": "service degraded: tcp/554", "kind": "degraded"}

    g = AlertGate()
    news, told, minute = set(), set(), 0
    digests, recoveries = 0, []

    def run(hours, issues):
        """main.py's wiring: _diff_criticals every 60s, a digest decision every hour."""
        nonlocal digests, minute
        for _ in range(int(hours * 60)):
            now = minute * 60
            minute += 1
            events = [e for e in g.update(issues, now)
                      if e.issue.get("severity") != "critical"]
            # recovery messages go out for keys a digest actually carried
            for e in events:
                if e.kind == RECOVERED and e.episode.key in told:
                    recoveries.append(e.issue["device"])
            for e in events:
                if e.kind in (NEW, STILL):
                    news.add(e.episode.key)
                elif e.kind == RECOVERED:
                    news.discard(e.episode.key)
                    told.discard(e.episode.key)
            if minute % 60 == 0 and (news & set(issues)):
                digests += 1
                news.clear()
                told.update(issues)        # every key this digest named, now 'told'

    run(1, {"boiler": BOILER})
    check(digests == 1, f"the boiler outage is reported once (got {digests})")
    check(recoveries == [], "nothing recovered yet")
    run(2, {})                            # boiler comes back
    check(recoveries == ["Boiler"], f"and its return is reported (got {recoveries})")
    check(digests == 1, "as its own message, NOT as a whole new digest")

    # the flip side, unchanged: something never mentioned stays unmentioned
    before = len(recoveries)
    for m in range(17):
        for e in g.update({"cam": CAM}, (minute + m) * 60):
            if e.kind in (NEW, STILL):
                news.add(e.episode.key)
    minute += 17
    run(2, {})
    check(len(recoveries) == before,
          f"a blip no digest ever carried recovers silently (got {len(recoveries)-before} extra)")


def test_minor_device_never_pages_and_never_degrades():
    print("...and it still never pages, nor turns the network 'degraded'")
    rep = base_report()
    rep["issues"] = [{"device": "Robot vacuum", "ip": "192.168.10.115", "group": "iot",
                      "severity": "info", "detail": "unreachable (icmp)", "kind": "down"}]
    crit = [i for i in rep["issues"] if i["severity"] == "critical"]
    check(crit == [], "no critical issue -> nothing reaches the immediate Telegram path")
    check(rep["overall_health"] == "ok", "health stays ok, so the dashboard stays green")


def test_build_report_severities():
    """The real build_report: every down device reported, at its earned severity."""
    print("build_report grades rather than mutes")
    import os as _os, sys as _sys
    live = "/srv/lanowl"
    if not _os.path.isdir(live):
        print("  --   live inventory not present, skipped"); return
    _sys.path.insert(0, live)
    from lanowl.model import load_inventory
    from lanowl.report import build_report
    from lanowl.sweep import Snapshot, DeviceStatus
    inv = load_inventory(_os.path.join(live, "inventory.yaml"))
    by_ip = {d.ip: d for d in inv.devices}
    down = {"192.168.10.115", "192.168.10.37"}    # vacuum (info) + Intercom (high)
    devs = [DeviceStatus(ip=d.ip, name=d.name, group=d.group, criticality=d.criticality,
                         up=(d.ip not in down), reachable=(d.ip not in down),
                         latency_ms=None if d.ip in down else 9.0)
            for d in inv.devices]
    rep = build_report(Snapshot(ts=0, devices=devs, wan={"8.8.8.8": True}, wan_ok=True),
                       inv, down)
    sev = {i["ip"]: i["severity"] for i in rep["issues"]}
    check(sev.get("192.168.10.115") == "info", f"vacuum -> info (got {sev.get('192.168.10.115')})")
    check(sev.get("192.168.10.37") == "high", f"Intercom -> high (got {sev.get('192.168.10.37')})")
    check(rep["overall_health"] == "degraded", "a high issue does degrade the network")

    rep2 = build_report(Snapshot(ts=0, devices=[d for d in devs if d.ip != "192.168.10.37"],
                                 wan={"8.8.8.8": True}, wan_ok=True),
                        inv, {"192.168.10.115"})
    check(rep2["overall_health"] == "ok",
          f"but the vacuum alone leaves it ok (got {rep2['overall_health']})")
    check(len(rep2["issues"]) == 1, "while still being reported as an issue")


def test_observer_failure_collapses_the_storm():
    """When lanowl's own host loses the LAN, that is ONE problem — not fifty."""
    print("a mass outage including the gateway is reported as an observer failure")
    from lanowl.report import build_report
    from lanowl.sweep import Snapshot, DeviceStatus

    class _Inv:
        groups = {}

    def dev(ip, group, crit="warning", up=True):
        return DeviceStatus(ip=ip, name=f"dev {ip}", group=group, criticality=crit,
                            up=up, reachable=up, latency_ms=None if not up else 5.0)

    cfg = {"observer": {"enabled": True, "gateway_ip": "192.168.10.1",
                        "host_ip": "192.168.10.103", "min_down_pct": 60, "min_groups": 3}}
    groups = ["network", "cameras", "energy", "home", "servers"]
    devs = [dev(f"192.168.10.{10 + i}", groups[i % 5]) for i in range(20)]
    devs.append(dev("192.168.10.1", "network", "critical"))

    # 1) the whole LAN, gateway included -> one issue about lanowl's own host
    all_down = {d.ip for d in devs}
    for d in devs:
        d.up = d.reachable = False
    rep = build_report(Snapshot(ts=0, devices=devs, wan={"8.8.8.8": False}, wan_ok=False),
                       _Inv(), all_down, cfg)
    kinds = [i["kind"] for i in rep["issues"]]
    check(kinds.count("observer") == 1, f"exactly one observer issue (kinds={set(kinds)})")
    check("down" not in kinds, "the individual unreachable alerts are collapsed into it")
    check(len(rep["devices"]) == 21,
          "but every device is still on the dashboard, shown as it really is")
    obs = next(i for i in rep["issues"] if i["kind"] == "observer")
    check("lost the network" in obs["detail"], f"and it says where to look: {obs['detail'][:60]}…")
    check(rep["wan_ok"] is False, "the WAN issue is untouched — that one is real either way")

    # 2) the same devices down WITHOUT the gateway is a real outage, reported normally
    for d in devs:
        d.up = d.reachable = (d.ip == "192.168.10.1")
    rep2 = build_report(Snapshot(ts=0, devices=devs, wan={"8.8.8.8": True}, wan_ok=True),
                        _Inv(), all_down - {"192.168.10.1"}, cfg)
    kinds2 = [i["kind"] for i in rep2["issues"]]
    check("observer" not in kinds2,
          "a router that still answers rules the observer out — something else is wrong")
    check(kinds2.count("down") == 20, f"so all 20 are reported ({kinds2.count('down')})")


def test_model_host_down_is_one_issue():
    """The model's host is an inventory device: that host dark is ONE issue, not two."""
    print("the Ollama issue folds into its host's while that host is down")
    from lanowl.report import build_report
    from lanowl.sweep import Snapshot, DeviceStatus, CheckResult, OLLAMA_KEY

    class _Inv:
        groups = {}

    cfg = {"ollama": {"url": "http://192.168.10.103:11434"},
           "observer": {"host_ip": "192.168.10.95"}}
    mac = DeviceStatus(ip="192.168.10.103", name="Model server", group="servers",
                       criticality="warning", up=False, reachable=False, latency_ms=None)
    snap = Snapshot(ts=0, devices=[mac], wan={"8.8.8.8": True}, wan_ok=True,
                    ollama=CheckResult(type="ollama", ok=False, detail="no answer"))
    rep = build_report(snap, _Inv(), {"192.168.10.103", OLLAMA_KEY}, cfg)
    names = [i["device"] for i in rep["issues"] if i["ip"] == "192.168.10.103"]
    check(names == ["Model server"], f"only the host's issue while it is down (got {names})")

    mac.up = mac.reachable = True
    rep2 = build_report(snap, _Inv(), {OLLAMA_KEY}, cfg)
    names2 = [i["device"] for i in rep2["issues"] if i["ip"] == "192.168.10.103"]
    check(names2 == ["Ollama"], f"host up, model gone -> the Ollama issue (got {names2})")


def test_criticals_page_on_the_same_sweep():
    """No gate rule may add latency to a critical the user has not yet heard about."""
    print("a critical pages on the very sweep it is confirmed — zero added delay")
    from lanowl.alerts import NEW, AlertGate

    FIBER = {"device": "Internet / WAN path", "ip": "-", "group": "wan",
             "severity": "critical", "detail": "running on the BACKUP link 'antenna'",
             "kind": "wan-path"}
    TV_ISH = {"device": "Intercom", "ip": "192.168.10.37", "group": "security",
              "severity": "warning", "detail": "unreachable", "kind": "down"}

    g, t = AlertGate(), 1000.0
    ev = g.update({"fiber": FIBER}, t)
    check(len(ev) == 1 and ev[0].kind == NEW, "fires in the same update() call, not the next")
    check(ev[0].episode.silent_until == 0.0, "a first-time critical has no quiet window at all")

    # a long-standing muted issue must not delay an unrelated new critical
    g2, t2 = AlertGate(), 0.0
    g2.update({"warn": TV_ISH}, t2)                       # opens a non-critical episode
    for i in range(1, 200):                               # 3+ hours pass
        g2.update({"warn": TV_ISH}, t2 + i * 60)
    ev = g2.update({"warn": TV_ISH, "fiber": FIBER}, t2 + 200 * 60)
    check([e.kind for e in ev] == [NEW] and ev[0].issue["kind"] == "wan-path",
          "a new critical is unaffected by another issue sitting in the gate")

    # and while the SAME key is in its post-recovery cooldown, a *different* critical
    # is still immediate
    g3, t3 = AlertGate(), 0.0
    g3.update({"fiber": FIBER}, t3)
    g3.update({}, t3 + 60)
    g3.update({}, t3 + 1000)                              # fiber recovered -> cooldown starts
    OTHER = dict(FIBER, device="NVR", ip="192.168.10.60", kind="down")
    ev = g3.update({"nvr": OTHER}, t3 + 1200)
    check(len(ev) == 1 and ev[0].kind == NEW, "a different critical pages during that cooldown")


def test_digest_says_when_a_device_went_down():
    """lanowl says when a device went down even in a digest. The critical page always
    carried the sweep's clock in its header; a digest line must not say only 'unreachable',
    an hour or a day after the fact.

    Run the real chain — tracker, build_report, gate, digest — on an injected clock, and
    read the message the way the phone will."""
    print("a digest line names WHEN the device went down")
    import time as _time
    from lanowl.alerts import AlertGate
    from lanowl.model import Device, Inventory
    from lanowl.report import build_report, format_digest
    from lanowl.state import StatusTracker
    from lanowl.sweep import DeviceStatus, Snapshot

    VAC = "192.168.10.115"
    inv = Inventory(devices=[Device(VAC, "Robot vacuum", "iot", "info", [{"type": "icmp"}])],
                    groups={})
    tracker, gate = StatusTracker(debounce_fails=2, recovery_oks=1), AlertGate()
    # the clock: today at 14:00:00 local, so the note has no date in front of it
    lt = _time.localtime()
    day0 = _time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 14, 0, 0, 0, 0, -1))
    hhmm = lambda ts: _time.strftime("%H:%M:%S", _time.localtime(ts))

    def key(i):
        return f"{i['kind']}:{i['ip']}:{i['group']}:{i['device']}"

    def sweep(ts, up):
        """One production sweep: debounce, report, gate — main.py in miniature."""
        tracker.update(VAC, up, ts)
        down = set(tracker.down_ips())
        snap = Snapshot(ts=ts, devices=[DeviceStatus(ip=VAC, name="Robot vacuum", group="iot",
                                                     criticality="info", up=up, reachable=up,
                                                     latency_ms=None)],
                        wan={"8.8.8.8": True}, wan_ok=True)
        rep = build_report(snap, inv, down,
                           down_since={ip: tracker.down_since(ip) for ip in down})
        gate.update({key(i): i for i in rep["issues"]}, ts)
        return rep

    def digest(rep, now):
        """_send_digest's dating, then the formatter."""
        for i in rep["issues"]:
            started = gate.episode_start(key(i))
            if started:
                i["since"], i["flaps"] = started, gate.episode_flaps(key(i))
        return format_digest(dict(rep, summary="", counts=rep["counts"]), now)

    sweep(day0, True)                          # 14:00 answers
    rep = sweep(day0 + 60, False)              # 14:01 first miss — a blip so far
    check(rep["issues"] == [], "one miss is not an issue yet")
    rep = sweep(day0 + 120, False)             # 14:02 confirmed down
    check([i["kind"] for i in rep["issues"]] == ["down"], "the second miss confirms it")
    check(rep["issues"][0]["since"] == day0 + 60,
          "the issue is dated from the FIRST miss, not the sweep that confirmed it")
    msg = digest(rep, day0 + 3600)             # the hourly audit, at 15:00
    check(f"unreachable (icmp) — <i>since {hhmm(day0 + 60)}</i>" in msg,
          f"the digest line says since 14:01:00, no date — it is still today "
          f"(got {msg.splitlines()[-1]!r})")

    # the daily reminder, two days on: the day goes in front, or 14:01 is a lie
    later = day0 + 2 * 86400 + 3600
    msg = digest(rep, later)
    stamp = _time.strftime("%d/%m %H:%M:%S", _time.localtime(day0 + 60))
    check(f"since {stamp}" in msg, f"two days later it says 'since {stamp}' (got {msg.splitlines()[-1]!r})")

    # a flapper: back at 14:10, gone again at 14:40. One incident, dated from the first
    # drop — and described as unstable, since 'down since 14:01' would claim a continuity
    # the device never had.
    sweep(day0 + 600, True)
    for m in (40, 41):
        rep = sweep(day0 + m * 60, False)
    check(rep["issues"][0]["since"] == day0 + 40 * 60,
          "build_report's own `since` is the latest drop (14:40)...")
    msg = digest(rep, day0 + 3600)
    check(f"unstable since {hhmm(day0 + 60)} · 2 outages" in msg,
          f"...but the digest dates the incident from 14:01 and counts the outages "
          f"(got {msg.splitlines()[-1]!r})")

    # an issue nobody can date says nothing rather than something wrong
    undated = {"device": "Group 'cameras'", "ip": "-", "group": "cameras", "severity": "critical",
               "detail": "7/10 in group down", "kind": "group"}
    msg = format_digest(dict(rep, issues=[undated], summary="", overall_health="critical"), day0)
    check("since" not in msg, "no `since` -> no note at all")


def test_tracker_remembers_the_first_miss():
    print("the tracker dates an outage from the first miss, per device")
    from lanowl.state import StatusTracker
    t = StatusTracker(debounce_fails=2, recovery_oks=1)
    LAN, SITE = "192.168.10.34", "10.8.0.16"
    check(t.down_since(LAN) == 0.0, "nothing known: 0")
    t.update(LAN, True, 0)
    t.update(LAN, False, 60)
    check(t.down_since(LAN) == 0.0, "one miss: still up, so nothing to date")
    t.update(LAN, False, 120)
    check(t.down_since(LAN) == 60, "confirmed on the second miss, dated from the first")
    t.update(LAN, False, 180)
    check(t.down_since(LAN) == 60, "and it stays put while the misses continue")
    t.update(LAN, True, 240)
    check(t.down_since(LAN) == 0.0, "back up: nothing to date any more")
    # a site with its own five-sweep debounce is where the difference is worth having
    for i in range(5):
        t.update(SITE, False, i * 60, debounce_fails=5)
    check(t.since(SITE) == 240 and t.down_since(SITE) == 0,
          "confirmed at 240 but down since 0 — four minutes the old clock would have hidden")


if __name__ == "__main__":
    for fn in [test_muted_labels, test_llm_cannot_escalate_on_a_switched_off_tv,
               test_llm_can_still_escalate_on_something_real,
               test_deterministic_criticals_are_never_touched,
               test_digest_fingerprint_ignores_prose,
               test_minor_device_is_reported_once_then_silent,
               test_recovery_never_triggers_a_digest,
               test_a_reported_problem_gets_a_recovery_message,
               test_minor_device_never_pages_and_never_degrades,
               test_build_report_severities, test_observer_failure_collapses_the_storm,
               test_model_host_down_is_one_issue,
               test_criticals_page_on_the_same_sweep,
               test_digest_says_when_a_device_went_down,
               test_tracker_remembers_the_first_miss]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all quiet-policy tests passed")
