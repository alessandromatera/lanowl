"""Where an internet event broke: run with `python -m tests.test_wanexplain`.

A blackout on the Timeline should be one click from what happened. Pinned down here:

  1. one event per moment: a short one recorded as a blip AND a blackout is the blip;
  2. the code's reading (wanexplain.py) from each kind of evidence — lanowl's
     own link, the network kept its internet, the fiber's first hop, further in, the fiber;
  3. an event from before the evidence existed: the router's counters as they are now;
  4. the watcher keeps the evidence of a run (the rounds, the hops, the router's pings
     before and after) and records a blip only once;
  5. explain() puts it together for the drawer and the model's brief;
  6. the router's log around an outage's start and end, its side effects dropped, a repeated
     line kept once;
  7. what a standby backup link did — read only while the main link is down — and a main-link
     outage never said to be "carried by the backup" when the network had nothing: a long
     outage, replayed.
"""
from __future__ import annotations

import asyncio
import datetime
import functools
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import probes, wanexplain, wanwatch
from lanowl.state import StateStore
from lanowl.wanwatch import WanWatcher

LINKS = {"failover": True, "main": "fiber", "backup": "antenna", "main_probe": "9.9.9.9",
         "backup_probe": "1.1.1.1", "standby": True}
verdict_ = functools.partial(wanexplain.verdict, links=LINKS)
story_ = functools.partial(wanexplain.standby_story, links=LINKS)

_fails = []


def check(cond, msg):
    print(f"  {'ok  ' if cond else 'FAIL'} {msg}")
    if not cond:
        _fails.append(msg)


CFG = {
    "wan": {"targets": ["8.8.8.8", "208.67.222.222", "1.0.0.1"],
            "watch": {"enabled": True, "interval_s": 15, "fail_checks": 2, "ok_checks": 1,
                      "min_outage_s": 90, "log_interval_s": 60},
            "path": {"interval_s": 300, "route_comment": "Fiber", "main": "fiber", "backup": "antenna"}},
    "mikrotik": {"dhcp_source": "http://192.168.10.1", "user": "lanowl", "password": "p"},
    "probes": {"icmp_timeout_ms": 1500},
    "alerts": {"recovery_confirm_s": 900, "cooldown_s": 3600},
}
T = 1790731181.9          # a night-time blip


def nw(failed=0, done=100, status="up"):
    out = {h: {"done": done, "failed": failed, "status": status, "since": "2026-09-27 00:57:07"}
           for h in ("9.9.9.9", "8.8.8.8", "1.0.0.1")}
    # the antenna's own box, on the LAN side: not a ping of the internet, never counted
    out["192.168.20.1"] = {"done": done, "failed": failed + 7, "status": "up", "since": "2026-09-27 00:57:06"}
    return out


def ev(rounds, before=None, after=None, fiber=(), took=1.5):
    return {"kind": "blip", "start": T, "end": T + 28.5, "s": 28.5, "interval_s": 15, "timeout_ms": 1500,
            "targets": CFG["wan"]["targets"], "hops": {"router": "192.168.10.1", "isp": "100.64.0.1"},
            "rounds": [{"ts": T + 15 * i, "took": took, **r} for i, r in enumerate(rounds)],
            "rounds_n": len(rounds), "path": {"link": "fiber", "on_backup": False},
            "nw_before": before, "nw_after": after, "main": list(fiber)}


BLIP = {"ts": T, "kind": "blip", "s": 28.5}


def test_merge():
    print("\n-- one event per moment --")
    m = wanexplain.merge([{"ts": T, "kind": "blackout", "value": 28.5}, {"ts": T, "kind": "blip", "value": 28.5}])
    check(len(m) == 1 and m[0]["kind"] == "blip", "a blackout with its blip twin is the blip (never paged)")
    m = wanexplain.merge([{"ts": T, "kind": "blackout", "value": 300}])
    check(m[0]["kind"] == "blackout" and m[0]["s"] == 300, "a blackout on its own stays one")
    m = wanexplain.merge([{"ts": T, "kind": "main-outage", "value": 60}, {"ts": T + 30, "kind": "blip", "s": 20}])
    check([x["kind"] for x in m] == ["main-outage", "blip"], "two moments stay two, oldest first; `s` read too")


def test_verdicts():
    print("\n-- the code's reading --")
    v = verdict_(BLIP, ev([{"router": False, "isp": False}] * 2, nw(0, 100), nw(0, 102)))
    check(v["where"] == "lanowl", "the router did not answer lanowl: its own link")
    check(any("none failed" in x for x in v["lines"]), "and the router's own pings say the network had internet")

    v = verdict_(BLIP, ev([{"router": True, "isp": False}] * 2, nw(0, 100), nw(0, 103)))
    check(v["where"] == "lanowl-path", "router answered, its own pings ran and never failed: only lanowl's view")
    check("kept its internet" in v["short"], f"said as such on the Timeline ({v['short']})")

    v = verdict_(BLIP, ev([{"router": True, "isp": False}] * 2, nw(4, 100), nw(6, 103)))
    check(v["where"] == "isp-link", "the router's pings failed too and the first hop was silent: the fiber side")
    v = verdict_(BLIP, ev([{"router": True, "isp": True}] * 2, nw(4, 100), nw(6, 103)))
    check(v["where"] == "isp-beyond", "the first hop kept answering: further into the provider")
    v = verdict_(BLIP, ev([{"router": True, "isp": True}] * 2, nw(0, 100), nw(0, 100)))
    check(v["where"] == "isp-beyond", "no router test ran in the window: the hops alone say further in")
    check(any("did not run" in x for x in v["lines"]), "and it says the router's pings did not run meanwhile")
    v = verdict_(BLIP, ev([{"router": True}] * 2, nw(), nw(0, 102), fiber=[{"down": T - 5, "up": T + 40}]))
    check(v["where"] == "main", "a Fiber DOWN/UP pair around it: the main link")
    v = verdict_(BLIP, ev([{"router": True, "isp": True}] * 2, None, None, took=9.0))
    check(any("stalled" in x for x in v["lines"]), "a round that took 9 s: lanowl's VM itself was slow")
    v = verdict_({"ts": T, "kind": "main-outage", "s": 57}, None)
    check(v["where"] == "main-covered", "a fiber drop is the router's own record: the antenna carried it")


def test_old_events():
    print("\n-- from before the evidence --")
    v = verdict_(BLIP, None, nw(0, 14491))
    check(v["where"] == "lanowl-path", "the router's pings clean since before it: the network had internet")
    check(any("27/09" in x for x in v["lines"]), "naming since when")
    check(not any("192.168.20.1" in x for x in v["lines"]), "the antenna's LAN-side check is not an internet ping")
    v = verdict_({"ts": time.mktime((2026, 9, 26, 12, 0, 0, 0, 0, -1)), "kind": "blip", "s": 28},
                           None, nw(0, 14491))
    check(v["where"] == "unknown", "an event before the counters began: nothing to say")
    v = verdict_(BLIP, None, nw(3, 14491))
    check(v["where"] == "unknown", "counters that did fail at some point cannot vouch for this moment")


def test_length():
    print("\n-- how long, honestly --")
    ln = wanexplain.length(BLIP, ev([{}] * 2))
    check(ln["lo"] == 15 and ln["hi"] == 45, f"two failed rounds 15 s apart: 15–45 s ({ln['lo']}–{ln['hi']})")
    check(ln["text"].startswith("~"), "shown as approximate")


def stub_ping(up_targets: bool, router: bool = True, isp: bool = False):
    async def _p(ip, timeout_ms=1000, count=2):
        ok = router if ip == "192.168.10.1" else isp if ip == "100.64.0.1" else up_targets
        return probes.ProbeResult(ok, 1.0 if ok else None, "icmp")
    probes.ping = _p


def stub_router(counters: list):
    """REST reads: the netwatch counters in turn, an empty log."""
    async def _r(base, path, user, pw, verify=False, timeout_ms=5000):
        if "netwatch" in path:
            c = counters.pop(0) if counters else {}
            return probes.ProbeResult(True, None, "mikrotik", {"json": [
                {"host": h, "done-tests": str(x["done"]), "failed-tests": str(x["failed"]),
                 "status": x["status"], "since": x["since"]} for h, x in c.items()]})
        return probes.ProbeResult(True, None, "mikrotik", {"json": []})
    probes.mikrotik_rest = _r


def at(now, fn):
    real = wanwatch.time.time
    wanwatch.time.time = lambda: now
    try:
        return fn()
    finally:
        wanwatch.time.time = real


def test_watcher_keeps_the_evidence():
    print("\n-- the watcher keeps a run's evidence --")
    events = []
    w = WanWatcher(CFG, lambda text, key="": None, on_event=lambda *a: events.append(a))
    w._isp_gw = "100.64.0.1"
    stub_router([nw(0, 100), nw(0, 104)])

    async def run():
        stub_ping(False, router=True, isp=False)
        at(T, lambda: None)
        wanwatch.time.time = lambda: T
        await w._ping_round()
        await asyncio.sleep(0.05)              # the netwatch read, in its own task
        wanwatch.time.time = lambda: T + 15
        await w._ping_round()
        w._emit()
        stub_ping(True)
        wanwatch.time.time = lambda: T + 28.5
        await w._ping_round()
        w._emit()
        wanwatch.time.time = lambda: T + 28.5 + 80
        await w._finish_evidence(T + 28.5 + 80)
    real = wanwatch.time.time
    try:
        asyncio.run(run())
    finally:
        wanwatch.time.time = real
    kinds = [e[0] for e in events]
    check(kinds.count("blip") == 1, f"the blip is recorded once ({kinds})")
    check("blackout" not in kinds, "and no longer as a blackout too")
    evr = [e for e in events if e[0] == "wan-evidence"]
    check(len(evr) == 1, "its evidence follows once the router had its say")
    if evr:
        e = json.loads(evr[0][2])
        check(e["rounds_n"] == 2 and all(r.get("router") is True and r.get("isp") is False for r in e["rounds"]),
              "both failed rounds, with the router answering and the first hop not")
        check(e["nw_before"] and e["nw_after"] and e["nw_after"]["8.8.8.8"]["done"] == 104,
              "the router's counters before and after")
        v = verdict_({"ts": e["start"], "kind": "blip", "s": e["s"]}, e)
        check(v["where"] == "lanowl-path", f"read as: the network kept its internet ({v['where']})")


def test_a_paged_blackout_is_still_one():
    print("\n-- a blackout past the paging floor is recorded as a blackout --")
    events = []
    w = WanWatcher(CFG, lambda text, key="": None, on_event=lambda *a: events.append(a))
    stub_router([])

    async def run():
        stub_ping(False, router=True, isp=False)
        for i in range(8):                     # 0 .. 105 s
            wanwatch.time.time = lambda i=i: T + 15 * i
            await w._ping_round()
            w._emit()
        stub_ping(True)
        wanwatch.time.time = lambda: T + 120
        await w._ping_round()
        w._emit()
    real = wanwatch.time.time
    try:
        asyncio.run(run())
    finally:
        wanwatch.time.time = real
    kinds = [e[0] for e in events]
    check(kinds.count("blackout") == 1 and "blip" not in kinds, f"one blackout, no blip ({kinds})")
    check(len(w._pending_ev) == 1 and w._pending_ev[0]["ev"]["kind"] == "blackout"
          and w._pending_ev[0]["ev"]["rounds_n"] == 8, "its evidence waits as a blackout of 8 rounds")


def test_explain():
    print("\n-- explain(): the drawer and the model's brief --")
    with tempfile.TemporaryDirectory() as d:
        st = StateStore(os.path.join(d, "s.sqlite"))
        st.record_event("blip", 28.5, "", T)
        st.record_event("blackout", 28.5, "", T)
        st.record_event("wan-evidence", 28.5, json.dumps(ev([{"router": True, "isp": True}] * 2,
                                                              nw(0, 100), nw(0, 104))), T)

        class Inv:
            def get(self, ip):
                return None

        class A:
            pass
        a = A()
        a.state, a.cfg, a.inv = st, CFG, Inv()
        a.wanwatch = WanWatcher(CFG, lambda text, key="": None)
        x = wanexplain.explain(a, T + 0.5)
        check(x is not None and x["kind"] == "blip", "found by its time, as a blip")
        check(x and x["verdict"]["where"] == "lanowl-path", "with the code's reading")
        check(x and x["title"].startswith("Internet blip — ~"), f"titled honestly ({x and x['title']})")
        check(x and "none failed" in x["brief"] and "failed round" in x["brief"],
              "the brief carries the facts the drawer shows")
        check(x and not x["paged"], "and says it did not page")
        check(wanexplain.explain(a, T + 500) is None, "an instant with no event: nothing")


def lg(ts, msg, topics="script,info"):
    return {"ts": ts, "topics": topics, "message": msg}


# 10-01: the fiber gone 11:20:19 → 13:49:19, nothing through the antenna; the router's log full
# of WireGuard retrying — what its drawer showed, from 12:31 to 12:37
D0 = time.mktime((2026, 10, 1, 11, 19, 57, 0, 0, -1))
F0, F1 = D0 + 22, D0 + 22 + 8940
LOG_1001 = ([lg(F0, "Fiber DOWN - health IP disabled"),
             lg(F0 + 1, "route 0.0.0.0/0 changed by scheduler:main-failover", "system,info"),
             lg(F0 + 2, "address 10.8.0.2/24 changed by scheduler:main-failover", "system,info"),
             lg(F0 + 30, "admin logged in from 192.168.10.110 via web", "system,info,account")]
            + [lg(F0 + 600 + 5 * i, "wg0: [peer1] x=: Handshake for peer did not complete after 5 seconds, "
                  "retrying (try 2)", "wireguard,info") for i in range(1500)]
            + [lg(F0 + 4000, "bridge deassigned 192.168.10.137 for 68:A4", "dhcp,info"),
               lg(F0 + 4100, "D0:53:49:8E:EA:06@wlan2: connected, signal strength -78", "wireless,info"),
               lg(F1 - 20, "route 0.0.0.0/0 changed by scheduler:main-failover", "system,info"),
               lg(F1 - 10, "route 0.0.0.0/0 changed by scheduler:main-failover", "system,info"),
               lg(F1, "Fiber UP - health IP enabled")])


def test_outage_logs():
    print("\n-- the router's log around an outage: its start and end, not its middle --")
    x = wanexplain.pick_log(LOG_1001, D0, F1)
    msgs = [r["message"] for r in x]
    check(msgs[0].startswith("Fiber DOWN") and msgs[-1].startswith("Fiber UP"), "the fiber going and coming back")
    check(any("scheduler:main-failover" in m for m in msgs), "the failover script acting")
    check(not any("Handshake" in m or "deassigned" in m or "connected, signal" in m for m in msgs),
          "no WireGuard retries, no leases, no Wi-Fi clients")
    tail = [r for r in x if r["ts"] > F0 + 600 and "main-failover" in r["message"]]
    check(len(tail) == 1 and tail[0].get("n") == 2 and tail[0]["last"] == F1 - 10,
          "the failover's two route changes at the end: one line, ×2, with the last one's time")
    check(len(x) <= wanexplain.LOG_LINES and len(wanexplain.pick_log(LOG_1001 * 1, D0, D0 + 60)) <= 40,
          "at most 40 lines")


def test_standby():
    print("\n-- what the antenna did, while the fiber was down --")
    r = lambda t, on, link=None, sig=None, net=None: {"ts": T + t, "on": on, "link": link, "signal": sig,   # noqa: E731
                                                       "net": net, "err": ""}
    st = story_
    check(st([r(30, False)], T) is None, "Wi-Fi still off inside its 2 minutes: nothing to say yet")
    a = st([r(30, False), r(150, False)], T)
    check(a["where"] == "standby-off" and "never switched its uplink on" in a["line"],
          f"still off after them: the failover has nothing to fail over to ({a['line']})")
    a = st([r(30, False), r(60, True, True, -67, False), r(90, True, True, -68, False)], T)
    check(a["where"] == "standby-dead" and "-68 dBm" in a["line"], f"on, connected, no internet ({a['line']})")
    a = st([r(60, True, False, None, False)], T)
    check(a["where"] == "standby-nolink", "on, never connected to the provider")
    a = st([r(30, False), r(60, True, True, -66, True)], T)
    check(a["where"] == "standby-ok" and "came through it" in a["line"], "on, and the internet through it: fine")
    a = st([{"ts": T + 30, "on": None, "err": "no login"}], T)
    check(a["where"] == "unknown" and "no login" in a["line"], "could not be read: said, not guessed")

    fo = {"ts": F0, "kind": "main-outage", "s": 8940.0}
    v = verdict_(fo, None, None, {"dark_s": 8940.0})
    check(v["where"] == "main-dark" and "did not carry" in v["short"],
          "a fiber outage the network spent with no internet is not 'the antenna carried the traffic'")
    v = verdict_(fo, None, None, {"dark_s": 40.0})
    check(v["where"] == "main-covered" and any("40s" in x for x in v["lines"]),
          f"the usual: a gap, then the antenna took over ({v['lines']})")
    v = verdict_(fo, None, None, {"dark_s": 8940.0, "standby": {"down_at": F0, "reads": [
        {"ts": F0 + 30, "on": False}, {"ts": F0 + 200, "on": False}]}})
    check(v["where"] == "standby-off", "with the antenna read: why it did not carry it")
    b = {"ts": D0, "kind": "blackout", "s": 8962.0}
    e = ev([{"router": True, "isp": False}] * 2, nw(0, 100), nw(1494, 1607), fiber=[{"down": F0, "up": F1}])
    v = verdict_(b, e)
    check(v["where"] == "main-dark" and any("4482 of 4521" in x for x in v["lines"]),   # 3 hosts × 1507
          f"10-01's blackout: the router's own pings say the antenna carried nothing either ({v['lines']})")


def test_explain_1001():
    print("\n-- 10-01 replayed: the drawer --")
    with tempfile.TemporaryDirectory() as d:
        st = StateStore(os.path.join(d, "s.sqlite"))
        st.record_event("blackout", 8962.0, "", D0)
        st.record_event("main-outage", 8940.0, "", F0)
        e = ev([{"router": True, "isp": False}] * 2, nw(0, 100), nw(1494, 1607), fiber=[{"down": F0, "up": F1}])
        e.update(start=D0, end=D0 + 8962, s=8962.0, kind="blackout",
                 log=[r for r in LOG_1001 if F0 + 3600 <= r["ts"] <= F0 + 3800][:40], log_from=D0 - 3 * 86400)
        st.record_event("wan-evidence", 8962.0, json.dumps(e), D0)

        class Inv:
            def get(self, ip):
                return None

        class A:
            pass
        a = A()
        a.state, a.cfg, a.inv = st, CFG, Inv()
        a.wanwatch = WanWatcher(CFG, lambda text, key="": None)
        x = wanexplain.explain(a, F0)
        check(x and x["verdict"]["where"] == "main-dark", f"the fiber's row: nothing carried it ({x and x['verdict']})")
        x = wanexplain.explain(a, D0)
        check(x and x["log"] == [] and "side effects" in (x.get("log_note") or ""),
              f"the lines kept at the time were all WireGuard: said so, not shown ({x and x.get('log_note')})")
        a.wanwatch.log_rows = [(datetime.datetime.fromtimestamp(r["ts"]), {"topics": r["topics"], "message": r["message"]})
                               for r in [lg(D0 - 3 * 86400, "first line")] + LOG_1001]
        x = wanexplain.explain(a, D0)
        msgs = [r["message"] for r in x["log"]]
        check(msgs and msgs[0].startswith("Fiber DOWN") and msgs[-1].startswith("Fiber UP"),
              "read again from the router's log, which still goes back that far: its start and its end")
        check("Fiber DOWN" in x["brief"] and "Handshake" not in x["brief"], "and the model's brief says the same")


if __name__ == "__main__":
    for t in (test_merge, test_verdicts, test_old_events, test_length, test_watcher_keeps_the_evidence,
              test_a_paged_blackout_is_still_one, test_explain, test_outage_logs, test_standby, test_explain_1001):
        t()
    print(f"\n{'all wanexplain tests passed' if not _fails else f'{len(_fails)} FAILED'}")
    sys.exit(1 if _fails else 0)
