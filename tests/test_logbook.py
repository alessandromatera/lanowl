"""Logbook + restart tests: run with `python -m tests.test_logbook`.

What these pin down: a remote router goes dark at 19:48 and lanowl restarts twice that
evening. A restart must not re-date the outage to itself (a recovery reading "down 30280s",
counted from the second restart), nor write another `down` for it; and the history and the
model's words carry names, so a twelve-hour outage is never called "brief" about a bare
"10.9.0.10".
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.prompts import build_user_context
from lanowl.report import _label_index, merge_llm, name_addresses
from lanowl.state import StateStore, StatusTracker, Transition

_fails = []

IP, NAME = "10.9.0.10", "Acme mikrotik router"


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def sweep(store, tracker, up, ts, fails=None):
    """One sweep of one device, recorded the way Auditor.sweep_cycle records it.

    Never at ts 0: record_sample reads a zero timestamp as 'now'."""
    t = tracker.update(IP, up, ts, debounce_fails=fails)
    store.record_sample(IP, up, 10.0 if up else None, {}, ts=ts)
    if t:
        t.detail = NAME
        store.record_transition(t)
    store.commit()
    return t


def restart(store, now, **kw):
    tracker = StatusTracker(**kw)
    for ip, st in store.resume([IP], now=now).items():
        tracker.restore(ip, **st)
    return tracker


def test_a_restart_keeps_the_outage_date():
    print("an outage that began before a restart keeps its start")
    store = StateStore(":memory:")
    old = StatusTracker(debounce_fails=2)
    for m in range(1, 10):
        sweep(store, old, True, m * 60)
    for m in range(10, 20):                        # dark from minute 10
        sweep(store, old, False, m * 60)
    check(old.down_since(IP) == 600, "the first process dates it from the first miss")

    new = restart(store, 22 * 60, debounce_fails=2)
    check(new.status(IP) is False, "the next process knows it is down before it sweeps")
    check(new.down_since(IP) == 600, "...and since when")
    check(sweep(store, new, False, 22 * 60) is None, "its first sweep writes no second `down`")
    check(new.down_since(IP) == 600, "nor moves the start")
    t = sweep(store, new, True, 30 * 60)
    check(t is not None and t.kind == "up", "the recovery is still an `up`")
    downs = [r for r in store.recent_transitions(0, ip=IP) if r["kind"] == "down"]
    check(len(downs) == 1 and downs[0]["ts"] == 600,
          "one `down` in the history, dated at the first miss")
    book = store.logbook()
    check(book[0].get("down_for") == 20 * 60, "the logbook says it was down 20 minutes")


def test_a_half_counted_debounce_carries_over():
    print("misses counted before a restart still count after it")
    store = StateStore(":memory:")
    old = StatusTracker()
    for m in range(1, 5):
        sweep(store, old, True, m * 60, fails=5)
    for m in (5, 6, 7):
        sweep(store, old, False, m * 60, fails=5)
    check(old.status(IP) is True, "three misses of five: not down yet")
    new = restart(store, 8 * 60)
    sweep(store, new, False, 8 * 60, fails=5)
    t = sweep(store, new, False, 9 * 60, fails=5)
    check(t is not None and t.kind == "down", "the fifth miss confirms it, across the restart")
    check(t is not None and t.at == 300, "dated from the first miss, before the restart")


def test_resume_distrusts_a_long_gap():
    print("after a long silence the history is not trusted")
    store = StateStore(":memory:")
    old = StatusTracker()
    for m in range(1, 4):
        sweep(store, old, False, m * 60)
    check(store.resume([IP], now=3 * 60 + 7200) == {}, "two hours later: start fresh")
    check(IP in store.resume([IP], now=4 * 60), "a minute later: carry on")


def test_resume_ignores_a_down_it_answered_after():
    print("a `down` with an answer after it and no `up` is not resumed as down")
    store = StateStore(":memory:")
    store.record_transition(Transition(IP, "down", 100, NAME))
    store.record_sample(IP, True, 10.0, {}, ts=500)     # it answered; an old restart missed it
    store.commit()
    check(IP not in store.resume([IP], now=560), "nothing to resume: it is simply up")


def test_logbook_folds_the_restart_duplicates():
    print("the logbook folds a restart's repeated `down` into its outage (the Acme night)")
    store = StateStore(":memory:")
    h = 3600
    for m in range(19 * 60 + 48, 31 * 60 + 40, 5):      # nothing answered all night
        store.record_sample(IP, False, None, {}, ts=m * 60)
    for ts, kind in ((19 * h + 48 * 60, "down"), (21 * h + 44 * 60, "down"),
                     (23 * h + 19 * 60, "down"), (31 * h + 40 * 60, "up")):
        store.record_transition(Transition(IP, kind, ts, NAME))
    store.commit()
    book = store.logbook()
    check([e["kind"] for e in book] == ["up", "down"], "one outage: an up and a down, newest first")
    check(book[0]["down_for"] == 11 * h + 52 * 60, "down 11h52m, counted from the FIRST `down`")
    check(book[1]["open"] is False, "and the `down` is closed")
    check(book[0]["name"] == NAME, "every row carries the name it was recorded with")


def test_logbook_closes_an_outage_nobody_saw_end():
    print("a device that came back while lanowl was away is not down forever")
    store = StateStore(":memory:")
    store.record_transition(Transition(IP, "down", 100, NAME))
    store.record_sample(IP, True, 10.0, {}, ts=500)      # answered, but no `up` was written
    store.record_transition(Transition(IP, "down", 900, NAME))
    store.commit()
    book = store.logbook()
    check([(e["kind"], e["ts"]) for e in book] == [("down", 900), ("up", 500), ("down", 100)],
          "down, up at the answer, down again")
    check(book[1]["down_for"] == 400, "the first outage closes at the answer")
    check(book[0]["open"] is True, "the second is still running")
    check([e["ts"] for e in store.logbook(since_ts=600)] == [900],
          "the time window is applied after pairing")


def test_logbook_ends_an_outage_where_probing_stopped():
    print("an address nobody probes any more is not down forever (a camera taken out while down)")
    old, new, cam = "192.168.108.244", "192.168.108.243", "Camera Lake"
    store = StateStore(":memory:")
    store.record_transition(Transition(old, "down", 100, cam))
    for ts in (160, 220, 280):                            # still down when it left the inventory
        store.record_sample(old, False, None, {}, ts=ts)
    store.record_transition(Transition(new, "down", 150, cam))
    store.record_sample(new, False, None, {}, ts=300)
    store.commit()
    check(all(e.get("open") for e in store.logbook() if e["kind"] == "down"),
          "without an inventory to ask, both stay open")
    store.probed = lambda ip: ip == new
    book = store.logbook()
    ups = [e for e in book if e["kind"] == "up"]
    check([(e["ip"], e["ts"], e["down_for"]) for e in ups] == [(old, 280, 180)],
          "the old address closes at its last probe")
    check(next(e for e in book if e["ip"] == new)["open"] is True,
          "the address still probed stays down until it answers")
    check(store.logbook(ip=old)[0]["kind"] == "up", "asked for by address, the same")


def test_bare_addresses_get_their_names():
    print("the model's prose names every address it left bare")
    report = {
        "overall_health": "ok", "counts": {"total": 2, "up": 2, "down": 0}, "issues": [],
        "devices": [
            {"ip": IP, "name": NAME, "group": "vpn", "criticality": "info",
             "up": True, "asleep": False},
            {"ip": "192.168.10.1", "name": "Router RB5009 MikroTik", "group": "network",
             "criticality": "critical", "up": True, "asleep": False},
        ],
    }
    llm = {"overall_health": "ok", "issues": [],
           "summary": "Remote device 10.9.0.10 recovered ~36 min ago after a brief outage "
                      "at the remote site — no action needed locally."}
    out = merge_llm(report, llm)
    check(f"device {NAME} (10.9.0.10) recovered" in out["summary"],
          "the dashboard's sentence names the router")
    idx = _label_index(report)
    named = f"{NAME} (10.9.0.10) is back."
    check(name_addresses(named, idx) == named, "an address already named is left alone")
    check(name_addresses("the site (10.9.0.10) is back", idx)
          == f"the site ({NAME}, 10.9.0.10) is back", "no brackets inside brackets")
    check(name_addresses("it ends at 10.9.0.10.", idx) == f"it ends at {NAME} (10.9.0.10).",
          "a full stop is not part of the address")
    check(name_addresses("192.168.10.17 is not the router", idx)
          == "192.168.10.17 is not the router", "192.168.10.17 is not 192.168.10.1")
    check(name_addresses("192.168.10.250 is new", idx) == "192.168.10.250 is new",
          "a stranger stays an address")


def test_the_model_sees_names_and_durations():
    print("the audit's history names each device and says how long it was down")
    snap = {"ts": 1000 * 60, "wan_ok": True, "wan": {},
            "devices": [{"ip": IP, "name": NAME, "group": "vpn", "up": True}]}
    ctx = build_user_context(snap, [], [{"ts": 964 * 60, "ip": IP, "kind": "up",
                                         "down_for": 712 * 60}], {}, {})
    check(f"{NAME} ({IP})" in ctx, "named")
    check('"down_min": 712' in ctx, "with how long it had been down — not 'brief'")


def test_a_record_survives_the_process():
    print("a saved record is there for the next process, and an unchanged one is not rewritten")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "state.sqlite")
        a = StateStore(path)
        a.save_record("alerts", {"told": ["x"], "n": 1})
        ts = lambda s: s.conn.execute("SELECT ts FROM records WHERE name='alerts'").fetchone()["ts"]
        first = ts(a)
        a.save_record("alerts", {"n": 1, "told": ["x"]})
        check(ts(a) == first, "the same content is not written again")
        a.close()
        b = StateStore(path)
        check(b.load_record("alerts") == {"told": ["x"], "n": 1}, "the next process reads it back")
        check(b.load_record("nothing") is None, "a record never saved is None")
        b.close()


def test_what_the_user_was_told_survives_a_restart():
    print("the alert record — gate, digest bookkeeping, WAN incident — outlives the process")
    from lanowl.alerts import NEW, AlertGate
    from lanowl.main import Auditor
    from lanowl.wanwatch import WAN_KEY, WanWatcher
    store = StateStore(":memory:")
    PUMP = {"device": "Shelly pump", "ip": "192.168.10.57", "group": "energy",
             "severity": "critical", "detail": "unreachable (icmp, http/80)", "kind": "down"}
    BACKUP = {"device": "Internet / WAN", "ip": "-", "group": "wan",
              "severity": "critical", "detail": "on the backup link", "kind": "wan-path"}

    def process():
        """An Auditor holding only what the alert record touches: no network, no loop."""
        a = Auditor.__new__(Auditor)
        a.state, a.gate = store, AlertGate()
        a._told, a._digest_news = set(), set()
        a._last_digest_fp, a._last_digest_sent, a._persist_alerts = "", 0.0, False
        a.wanwatch = WanWatcher({}, lambda text, key="": None)
        return a

    first = process()
    first.resume_alerts(now=1000)
    check([e.kind for e in first.gate.update({"pump": PUMP}, 1000)] == [NEW],
          "the first process pages Shelly pump")
    first._told, first._digest_news, first._last_digest_sent = {"cam"}, {"tv"}, 900.0
    first.wanwatch._gate.update({WAN_KEY: BACKUP}, 1000)
    first.wanwatch._ep_outages = 2
    first._save_alert_record()
    first.wanwatch._save_record()

    rehearsal = process()                  # `--once` never resumes, so it never saves
    rehearsal.gate.update({"pump": PUMP}, 1050)
    rehearsal._save_alert_record()

    after = process()
    after.resume_alerts(now=1100)
    check(after.gate.update({"pump": PUMP}, 1160) == [], "the restart does not page it again")
    check(after._told == {"cam"} and after._digest_news == {"tv"}
          and after._last_digest_sent == 900.0,
          "the digest bookkeeping is back (and the rehearsal did not overwrite it)")
    check(after.wanwatch._gate.update({WAN_KEY: BACKUP}, 1160) == []
          and after.wanwatch._ep_outages == 2,
          "the WAN watcher keeps its incident and its outage count")


def test_a_device_out_of_the_inventory_leaves_the_history():
    print("\n-- a device taken out of the inventory leaves the logbook, the context and the tools --")
    import tempfile
    from lanowl.model import Device, Inventory
    moved = Device("192.168.10.160", "TV", attrs={})
    inv = Inventory(devices=[Device("192.168.10.117", "Boiler"), moved])
    inv.rebind(moved, "192.168.10.170")            # DHCP moved it: .160 is its configured address
    with tempfile.TemporaryDirectory() as d:
        st = StateStore(os.path.join(d, "s.sqlite"))
        rows = [(100, "192.168.10.103", "down", "Model server"), (220, "192.168.10.103", "up", "Model server"),
                (300, "192.168.10.117", "down", "Boiler"), (360, "192.168.10.117", "up", ""),
                (400, "192.168.10.160", "down", "TV"), (460, "192.168.10.160", "up", ""),
                (500, "192.168.10.150", "down", "TV"), (560, "192.168.10.150", "up", "")]
        for ts, ip, kind, name in rows:
            st.record_transition(Transition(ip=ip, kind=kind, at=ts, detail=name))
        t0, now = 1_000_000, 1_000_000 + 7 * 86400
        for ip in ("192.168.10.103", "192.168.10.117"):      # both fine for six days, then lossy
            for ts in range(t0, now, 300):
                up = ts < now - 86400 or (ts // 300) % 2 == 0
                st.record_sample(ip, up, 5.0 if up else None, {}, ts=ts)
        st.commit()
        everything = {e["ip"] for e in st.logbook()}
        worse_all = {r["ip"] for r in st.degrading(now)}
        st.keep = inv.owns
        worse = {r["ip"] for r in st.degrading(now)}
        book = {e["ip"] for e in st.logbook()}
        recent = {r["ip"] for r in st.recent_transitions(0)}
        flaps = set(st.flap_counts(0))
        only = st.logbook(ip="192.168.10.103")
        st.close()
    check("192.168.10.103" in everything, "the rows are still in the database (nothing deleted)")
    check(book == {"192.168.10.117", "192.168.10.160", "192.168.10.150"},
          f"the logbook drops the retired Model server, keeps a device DHCP moved, by address or name ({sorted(book)})")
    check("192.168.10.103" not in recent and "192.168.10.103" not in flaps,
          "the model's history tool and the audit's flap counts leave it out too")
    check(len(only) == 2, "asked for by address, its history is still there")
    check(worse_all == {"192.168.10.103", "192.168.10.117"} and worse == {"192.168.10.117"},
          f"'getting worse' names only monitored devices ({sorted(worse_all)} -> {sorted(worse)})")
    check(inv.owns("192.168.10.170") and inv.owns("192.168.10.160") and not inv.owns("192.168.10.103"),
          "owns: the current address and the configured one, not a retired device")


if __name__ == "__main__":
    for fn in [test_a_record_survives_the_process,
               test_what_the_user_was_told_survives_a_restart,
               test_a_restart_keeps_the_outage_date,
               test_a_half_counted_debounce_carries_over,
               test_resume_distrusts_a_long_gap,
               test_resume_ignores_a_down_it_answered_after,
               test_logbook_folds_the_restart_duplicates,
               test_logbook_closes_an_outage_nobody_saw_end,
               test_logbook_ends_an_outage_where_probing_stopped,
               test_bare_addresses_get_their_names,
               test_the_model_sees_names_and_durations,
               test_a_device_out_of_the_inventory_leaves_the_history]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all logbook tests passed")
