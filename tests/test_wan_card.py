"""The dashboard's Internet card: run with `python -m tests.test_wan_card`.

What these pin down: the card is told when the internet's record begins, whatever the week
held. With fewer than three events the explanation of the last ones looked three back and
failed, and the start was never read: the whole week was drawn as "no record". One or two
blips a week is the usual case.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.state import StateStore
from lanowl.web import wan_moments

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _lanowl(blips: int):
    st = StateStore(os.path.join(tempfile.mkdtemp(), "state.sqlite"))
    now = time.time()
    st.record_event("telegram", None, "{}", now - 6 * 86400)      # the record began then
    for i in range(blips):
        st.record_event("blip", 45.0, "", now - (i + 1) * 86400)
    st.commit()
    return SimpleNamespace(state=st, cfg={}, wanwatch=SimpleNamespace(netwatch=None)), now


def test_few_events():
    for n in (0, 1, 2, 3, 5):
        a, now = _lanowl(n)
        events, since = wan_moments(a, now)
        check(len(events) == n, f"{n} blip(s): {n} event(s) on the card")
        check(since is not None and abs(since - (now - 6 * 86400)) < 1,
              f"{n} blip(s): the record's start is known (not a week of 'no record')")
        check(all("where" in e for e in events[-3:]), f"{n} blip(s): the last ones say where they broke")


if __name__ == "__main__":
    test_few_events()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all wan card tests passed")
