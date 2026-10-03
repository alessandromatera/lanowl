"""Security-event record tests: run with `python -m tests.test_seclog`.

What is pinned down (seclog.py):
  1. an event stays open until the owner marks it handled — never by time, never by a restart;
  2. a repeat of an open event counts on its row; after it was handled, a repeat is a new row;
  3. handled: a week under Handled with the owner's words, then only in the record;
  4. the model's read of a rule's lines is attached, and only raises the row's severity.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.seclog import SecLog

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


class FakeState:
    def __init__(self):
        self.recs = {}

    def save_record(self, name, obj):
        self.recs[name] = json.dumps(obj)

    def load_record(self, name):
        return json.loads(self.recs[name]) if name in self.recs else None


def add(sl, **kw):
    base = dict(source="host log VM HomeHub", ip="192.168.10.113", sev="critical",
                title="40 failed logins from 192.168.10.103 in 10 min", detail="Connection closed by invalid user drill",
                by="rule", key="hostlog-burst:192.168.10.113:192.168.10.103")
    return sl.add(**{**base, **kw})


def test_open_until_handled_and_through_a_restart():
    print("\n-- open until the owner says so, restart or not --")
    st = FakeState()
    sl = SecLog(st)
    i = add(sl, ts=time.time() - 40 * 86400)
    sl2 = SecLog(st)                                   # a restart reads the record back
    v = sl2.view()
    check([x["id"] for x in v["open"]] == [i], "still open 40 days later, after a restart")
    check(sl2.handle("nope")["ok"] is False, "an unknown id is refused")
    r = sl2.handle(i, "me", "  testing   the burst rule ")
    v = SecLog(st).view()
    check(r["ok"] and v["open"] == [] and len(v["handled"]) == 1, "handled: out of open, into Handled")
    h = v["handled"][0]["handled"]
    check(h["pick"] == "me" and h["note"] == "testing the burst rule", "with the pick and the note, tidied")
    check(SecLog.owner_words(v["handled"][0]) == "It was me — testing the burst rule", "said as the owner said it")
    check(sl2.unhandle(i)["ok"] and len(sl2.view()["open"]) == 1, "Undo puts it back")
    check(sl2.unhandle(i)["ok"] is False, "an open one cannot be un-handled")
    check(sl2.handle(i, "bogus")["ok"] and sl2.view()["handled"][0]["handled"]["pick"] == "",
          "an unknown pick is dropped, the handling kept")


def test_repeats_count_on_the_open_row():
    print("\n-- one incident, one row --")
    sl = SecLog(FakeState())
    i = add(sl)
    j = add(sl, title="41 failed logins from 192.168.10.103 in 10 min", paged=False)
    v = sl.view()["open"]
    check(i == j and len(v) == 1 and v[0]["count"] == 2 and v[0]["title"].startswith("41"),
          "the same key while open: counted, the newest words kept")
    check(v[0]["paged"] is True, "paged once is paged")
    k = add(sl, key="")
    check(k != i and len(sl.view()["open"]) == 2, "no key: always its own row")
    sl.handle(i, "fixed")
    m = add(sl)
    check(m != i and len(sl.view()["open"]) == 2, "after it was handled, the same key is a new row")


def test_handled_leaves_the_list_after_a_week():
    print("\n-- Handled shows a week; open rows are never pruned --")
    sl = SecLog(FakeState())
    i = add(sl)
    sl.handle(i, "me")
    sl.rec["items"][0]["handled"]["ts"] = time.time() - 8 * 86400
    check(sl.view()["handled"] == [], "handled 8 days ago: off the list")
    check(len(sl.since(time.time() - 86400)) == 1, "...but still in the record")
    old = add(sl, key="x", ts=time.time() - 200 * 86400)
    it = sl._get(i)
    it["ts"] = it["last"] = time.time() - 100 * 86400
    sl._save()
    ids = [x["id"] for x in sl.rec["items"]]
    check(old in ids and i not in ids, "a handled row goes after 90 days; an open one never")


def test_the_models_read_is_attached():
    print("\n-- the model's read of a rule's lines --")
    sl = SecLog(FakeState())
    i = add(sl, sev="warning", key="hostlog-login:192.168.10.113:127.0.0.1")
    check(sl.attach(i, "warning", "password login through the tunnel", "x" * 1400), "attached")
    it = sl.view()["open"][0]
    check(it["model"]["summary"] == "password login through the tunnel" and len(it["model"]["detail"]) == 1400,
          "its words, whole")
    check(it["sev"] == "warning", "the same severity leaves the row as it was")
    sl.attach(i, "critical", "and a new user", "")
    check(sl.view()["open"][0]["sev"] == "critical", "worse raises it")
    check(sl.attach("nope", "info", "", "") is False, "an unknown id: nothing")


def test_the_first_start_carries_the_tabs_problems_over():
    print("\n-- the first start: the last 24 h of security problems, once --")
    st = FakeState()
    ev = lambda ts, **f: {"ts": ts, "kind": "finding", "detail": json.dumps(f)}
    now = time.time()
    events = [ev(now - 3600, source="host log VM HomeHub", problem=True, kind="security", severity="warning",
                 summary="Password login for pi through the tunnel", detail="x" * 400),
              ev(now - 7200, source="host log VPS", problem=False, kind="security", severity="info", summary="fine"),
              ev(now - 7300, source="router log", problem=True, kind="health", severity="warning", summary="flap"),
              ev(now - 9000, source="router log", problem=True, severity="critical", summary="old default: health"),
              ev(now - 9100, source="host log VPS", problem=True, severity="warning", summary="old default: security")]
    ips = {"host log VM HomeHub": "192.168.10.113", "host log VPS": "203.0.113.10"}
    sl = SecLog(st)
    check(sl.seed(events, lambda s: ips.get(s, "")) == 2, "two carried over: security, a problem, not info")
    v = sl.view()["open"]
    check([x["ip"] for x in v] == ["192.168.10.113", "203.0.113.10"] and v[0]["by"] == "model"
          and len(v[0]["detail"]) == 400, "with their machine, newest first, whole")
    check(SecLog(st).seed(events, lambda s: "") == 0, "and only ever once")


def test_weekly():
    print("\n-- the weekly review's facts --")
    sl = SecLog(FakeState())
    a = add(sl)
    add(sl, key="k2", title="pi logged in through ssh.example.com", sev="warning")
    sl.handle(a, "me", "my own test")
    w = sl.weekly()
    check(w["raised_this_week"] == 2 and len(w["still_open"]) == 1 and "ssh.example.com" in w["still_open"][0],
          "how many, and which are still open")
    check(w["handled_this_week"] == [{"event": "40 failed logins from 192.168.10.103 in 10 min",
                                      "owner_said": "It was me — my own test"}], "and what the owner said")


if __name__ == "__main__":
    for fn in [test_open_until_handled_and_through_a_restart,
               test_repeats_count_on_the_open_row,
               test_handled_leaves_the_list_after_a_week,
               test_the_models_read_is_attached,
               test_the_first_start_carries_the_tabs_problems_over,
               test_weekly]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all security-event tests passed")
