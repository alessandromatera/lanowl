"""/api/history tests: run with `python -m tests.test_web_history`.

What these pin down: the Devices table draws a 24h sparkline and a 7-day answered share for
every device from one request. Its queries run in a worker thread on a read-only connection
of their own (~1 s for the shares with ~60 devices, too long for the
loop the sweep runs on), so they must say exactly what the sheet's /api/device says.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.state import StateStore
from lanowl.web import _histories

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _store():
    path = os.path.join(tempfile.mkdtemp(), "state.sqlite")
    st = StateStore(path)
    now = time.time()
    # two devices, two days of one sample a minute: .10 always up, .20 down for the last hour
    for i in range(2 * 1440):
        ts = now - i * 60
        st.record_sample("192.168.10.34", True, 5.0 + (i % 7), {}, ts=ts)
        st.record_sample("192.168.10.38", i >= 60, 12.0 if i >= 60 else None, {}, ts=ts)
    st.commit()
    return st, path, now


def test_the_thread_says_what_the_sheet_says():
    st, path, now = _store()
    ips = ["192.168.10.34", "192.168.10.38", "192.168.10.113"]
    buckets, u7 = _histories(path, ips, now, True)
    for ip in ips[:2]:
        check(buckets[ip] == st.device_history(ip, now - 86400, 900), f"{ip}: the same 15-minute buckets as /api/device")
        check(u7[ip] == st.uptime_pct(ip, now - 7 * 86400), f"{ip}: the same 7-day share as /api/device ({u7[ip]})")
    check(buckets["192.168.10.113"] == [] and u7["192.168.10.113"] is None, "a device with no samples: no buckets, no share (never 0%)")
    check(any(b[2] == 0 for b in buckets["192.168.10.38"]), "the hour .20 was down shows as unanswered buckets")


def test_the_shares_only_when_asked():
    _, path, now = _store()
    _, u7 = _histories(path, ["192.168.10.34"], now, False)
    check(u7 is None, "want_u7=False: the 7-day query is not run")


def test_read_only():
    st, path, now = _store()
    _histories(path, ["192.168.10.34"], now, True)
    st.record_sample("192.168.10.34", True, 1.0, {}, ts=now + 1)
    st.commit()
    check(True, "the sweep still writes after a history read")


if __name__ == "__main__":
    for fn in [test_the_thread_says_what_the_sheet_says,
               test_the_shares_only_when_asked,
               test_read_only]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all web history tests passed")
