"""Timeline tests: run with `python -m tests.test_timeline`.

What these pin down (the dashboard's Timeline, timeline.py): outages
that went down together are one incident, as the alert gate made them one message; scheduled
sleep is never merged into a real outage; the internet's blackout, which the WAN watcher also
logs as a blip, is one event; and two blackouts show next to the RouterOS updates approved a
minute before them.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.timeline import assemble

_fails = []
NOW = 1_790_600_000.0
H = 3600.0


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def up(ip, name, ts, down_for, by_design=False, paused=False):
    return {"ts": ts, "ip": ip, "kind": "up", "name": name, "down_for": down_for,
            "by_design": by_design, "paused": paused}


def down(ip, name, ts, open_=False, by_design=False):
    return {"ts": ts, "ip": ip, "kind": "down", "name": name, "open": open_, "by_design": by_design, "paused": False}


GROUPS = {"192.168.10.1": "network", "192.168.10.32": "network", "192.168.10.117": "home",
          "192.168.10.118": "home", "192.168.10.58": "energy", "10.8.0.16": "vpn"}


def run(rows=(), wan=(), tg=(), actions=(), seclog=None, seen=(), findings=()):
    return assemble(sorted(rows, key=lambda e: -e["ts"]), list(wan), list(tg), list(actions),
                    seclog or {}, list(seen), list(findings), GROUPS, NOW)


def incidents(r):
    return [x for x in r["items"] if x["type"] == "incident"]


def test_together_is_one_incident():
    t = NOW - 10 * H
    r = run(rows=[down("192.168.10.32", "AP-Porch", t), up("192.168.10.32", "AP-Porch", t + 120, 120),
                  down("192.168.10.117", "Boiler", t + 60), up("192.168.10.117", "Boiler", t + 180, 120),
                  down("192.168.10.118", "Garage door", t + 1200), up("192.168.10.118", "Garage door", t + 1320, 120)])
    inc = incidents(r)
    check(len(inc) == 2, f"AP-Porch and Boiler a minute apart, the garage door 20 min later: 2 incidents ({len(inc)})")
    both = [x for x in inc if len(x["members"]) == 2]
    check(len(both) == 1 and {m["name"] for m in both[0]["members"]} == {"AP-Porch", "Boiler"}, "the first one has both devices")
    check(both and both[0]["a"] == t and both[0]["b"] == t + 180, "it runs from the first drop to the last recovery")


def test_sleep_is_never_merged():
    t = NOW - 5 * H
    r = run(rows=[down("192.168.10.58", "Shelly porch", t, by_design=True), up("192.168.10.58", "Shelly porch", t + 3 * H, 3 * H, by_design=True),
                  down("192.168.10.118", "Garage door", t + 30), up("192.168.10.118", "Garage door", t + 150, 120)])
    inc = incidents(r)
    check(len(inc) == 2 and {x["cat"] for x in inc} == {"sched", "down"}, "a scheduled sleep at the same minute stays apart")


def test_one_message_is_one_incident():
    t = NOW - 8 * H
    keys = ["down:10.8.0.16:vpn:Lake router", "down:192.168.10.118:home:Garage door"]
    r = run(rows=[down("10.8.0.16", "Lake router", t), up("10.8.0.16", "Lake router", t + 2400, 2400),
                  down("192.168.10.118", "Garage door", t + 290), up("192.168.10.118", "Garage door", t + 400, 110)],
            tg=[{"ts": t + 300, "channel": "critical", "text": "🔴 <b>2 devices down</b>\nGran router · Garage door", "keys": keys}])
    inc = incidents(r)
    check(len(inc) == 1 and len(inc[0]["members"]) == 2, "announced in one message 5 min apart: one incident")
    check(inc and inc[0]["told"] and inc[0]["told"][0]["text"] == "🔴 2 devices down", "it carries the message, first line, no markup")


def test_the_text_names_it_when_no_keys():
    t = NOW - 30 * H
    r = run(rows=[down("10.8.0.16", "Lake router", t), up("10.8.0.16", "Lake router", t + 1800, 1800)],
            tg=[{"ts": t + 120, "channel": "critical", "text": "🔴 Lake router (10.8.0.16) is down"},
                {"ts": t + 130, "channel": "critical", "text": "🔴 Boiler is down"}])
    inc = incidents(r)
    check(len(inc[0]["told"]) == 1, "an older message without keys: matched by the device's name only")


def test_blackout_after_the_router_update():
    t = NOW - 35 * H
    acts = [{"id": 45, "title": "Update RouterOS", "label": "Router hAP (192.168.10.1)", "ip": "192.168.10.1",
             "status": "done", "ts": t - 200, "decided_ts": t - 90, "started_ts": t - 60, "done_ts": t + 30, "owner": True}]
    r = run(wan=[{"ts": t, "kind": "blackout", "s": 29.0}, {"ts": t, "kind": "blip", "s": 29.0}], actions=acts)
    w = [x for x in r["items"] if x["type"] == "wan"]
    # a blip under the paging floor recorded as both never paged: a blip
    check(len(w) == 1 and w[0]["kind"] == "blip", "a blackout also logged as a blip: one event, the blip")
    check(w and (w[0]["cause"] or {}).get("id") == 45, "the RouterOS update a minute before is named with it")
    far = run(wan=[{"ts": t + 3 * H, "kind": "blackout", "s": 20.0}], actions=acts)
    check([x for x in far["items"] if x["type"] == "wan"][0]["cause"] is None, "three hours later: nothing named")


def test_the_incident_names_the_action_on_its_device():
    t = NOW - 12 * H
    acts = [{"id": 37, "title": "Reboot the Shelly", "label": "Shelly porch", "ip": "192.168.10.58",
             "status": "done", "ts": t - 100, "started_ts": t - 30}]
    r = run(rows=[down("192.168.10.58", "Shelly porch", t), up("192.168.10.58", "Shelly porch", t + 90, 90)], actions=acts)
    check((incidents(r)[0]["cause"] or {}).get("id") == 37, "a reboot of that very device, just before: named")
    skipped = [{**acts[0], "status": "skipped"}]
    r = run(rows=[down("192.168.10.58", "Shelly porch", t), up("192.168.10.58", "Shelly porch", t + 90, 90)], actions=skipped)
    check(incidents(r)[0]["cause"] is None, "approved but never run (skipped): not named")


def test_open_outage():
    t = NOW - 600
    r = run(rows=[down("10.8.0.16", "Lake router", t, open_=True)])
    inc = incidents(r)
    check(inc and inc[0]["open"] and inc[0]["b"] == NOW, "still down: open, running until now")
    check(r["lanes"]["10.8.0.16"]["segs"] == [[t, NOW, "down"]], "and its lane says so")


def test_refusals_fold_and_new_devices():
    t = NOW - 20 * H
    acts = [{"id": i, "title": "Reboot the Shelly", "ip": "192.168.10.64", "status": "refused", "ts": t + i, "owner": False} for i in range(5)]
    acts.append({"id": 9, "title": "Update the system", "ip": "192.168.10.35", "status": "refused", "ts": t + 50, "owner": True})
    seen = [{"first_seen": t, "site": "home", "ip": "192.168.10.122", "mac": "aa", "before": False},
            {"first_seen": t, "site": "home", "ip": "192.168.10.48", "mac": "bb", "before": True}]
    r = run(actions=acts, seen=seen)
    ref = [x for x in r["items"] if x["type"] == "refused"]
    check(len(ref) == 1 and ref[0]["n"] == 5, "the model's refused requests: one line for the day")
    check(any(x["type"] == "action" and x["id"] == 9 for x in r["items"]), "the owner's own refused request stays itself")
    nd = [x for x in r["items"] if x["type"] == "new_device"]
    check(len(nd) == 1 and nd[0]["ip"] == "192.168.10.122", "a device there before the first look is never new")


def test_log_checks_with_nothing_to_say_during_an_outage():
    # a long outage's log rows that found nothing say nothing relevant on its line
    t = NOW - 30 * H
    fs = [{"ts": t + 600, "source": "router log", "problem": False, "severity": "info",
           "summary": "A device joined the guest Wi-Fi — unrelated to the outage"},
          {"ts": t + 9000, "source": "router log", "problem": False, "severity": "info",
           "summary": "Failover script re-enabling the fiber route — still no internet"},
          {"ts": t + 1200, "source": "host log VPS", "problem": True, "severity": "warning",
           "summary": "the L2TP tunnel flapping"},
          {"ts": t - 7200, "source": "router log", "problem": False, "severity": "info", "summary": "routine"}]
    r = run(wan=[{"ts": t, "kind": "blackout", "s": 8962.0}, {"ts": t + 22, "kind": "main-outage", "s": 8940.0}],
            findings=fs)
    got = [x["summary"] for x in r["items"] if x["type"] == "check"]
    check(got == ["the L2TP tunnel flapping", "routine"],
          f"inside the outage only a check that found a problem stays; outside it, as before ({got})")


if __name__ == "__main__":
    for fn in [test_log_checks_with_nothing_to_say_during_an_outage, test_together_is_one_incident, test_sleep_is_never_merged, test_one_message_is_one_incident,
               test_the_text_names_it_when_no_keys, test_blackout_after_the_router_update,
               test_the_incident_names_the_action_on_its_device, test_open_outage,
               test_refusals_fold_and_new_devices]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all timeline tests passed")
