"""WAN watcher tests: run with `python -m tests.test_wanwatch`.

No network and no router — the ping probe and the REST call are both stubbed, so a night
of a flapping line is a handful of calls. What is being pinned down:

  1. a 57s outage IS detected (the whole reason this module exists — the 60s sweep with
     debounce 2 needs ~120s and misses every failover that short);
  2. an outage that starts AND ends between two log polls is still detected, because the
     evidence sits in the router's buffer rather than in the instantaneous route state;
  3. a flapping line still pages ONCE, per the rule in alerts.py;
  4. a restart does not replay yesterday's flaps out of the log buffer;
  5. the router-log triage stays quiet for routine chatter, asks the model about novel
     lines, and never blocks the ping clock.
"""
from __future__ import annotations

import asyncio
import datetime
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import probes, wanwatch
from lanowl.wanwatch import Flap, WanWatcher

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


CFG = {
    "wan": {
        "targets": ["8.8.8.8", "208.67.222.222", "1.0.0.1"],
        "watch": {"enabled": True, "interval_s": 15, "fail_checks": 2, "ok_checks": 1,
                  "log_interval_s": 60, "log_down_match": "Fiber DOWN",
                  "log_up_match": "Fiber UP", "flap_hold_s": 60,
                  "flap_severity": "critical",
                  "log_triage": {"enabled": True, "cooldown_s": 0, "timeout_s": 5,
                                 "max_lines": 40,
                                 "notify_severities": ["critical", "warning"]}},
        "path": {"interval_s": 300, "route_comment": "Fiber", "main": "fiber", "backup": "antenna"},
    },
    # the username matters: lanowl's own REST logins are filtered by it (see
    # WanWatcher._routine_patterns), so the fixtures below use the real one
    "mikrotik": {"dhcp_source": "http://router", "user": "lanowl", "password": "p"},
    "probes": {"icmp_timeout_ms": 1500},
    "alerts": {"recovery_confirm_s": 900, "cooldown_s": 3600},
}


def watcher(alerts, agent=None, cfg=None, llm_busy=None):
    # on_alert is (text, key="") — the key is what the outbox uses to notice that a queued
    # message's incident has already healed. The tests only care about the text.
    w = WanWatcher(cfg or CFG, lambda text, key="": alerts.append(text),
                   agent=agent, llm_busy=llm_busy)
    # pretend we primed at the start of the day: both watermarks set, nothing replayed
    w._watermark = w._triage_mark = datetime.datetime(2026, 8, 17, 0, 0, 0)
    return w


def _hhmmss(ts):
    """The wall-clock string the messages are expected to carry."""
    return time.strftime("%H:%M:%S", time.localtime(ts))


def row(t, msg, topics="script,info"):
    return {"time": t, "message": msg, "topics": topics, ".id": "*1"}


def stub_ping(up: bool):
    async def _p(ip, timeout_ms=1000, count=2):
        return probes.ProbeResult(up, 1.0 if up else None, "icmp")
    probes.ping = _p


def stub_log(rows):
    async def _r(base, path, user, pw, verify=False, timeout_ms=5000):
        return probes.ProbeResult(True, None, "mikrotik", {"json": rows})
    probes.mikrotik_rest = _r


# --- 1. the ping half -------------------------------------------------------
def test_blackout_confirms_in_two_rounds():
    print("\ntest: a total blackout is confirmed after fail_checks rounds (~30s, not ~120s)")
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()

    w._ping_at(now)
    check(w.blackout is False, "one bad round is a blip, not an outage")
    w._ping_at(now + 15)
    check(w.blackout is True, "two bad rounds (30s at interval_s=15) confirm the blackout")

    # Detection and paging are deliberately different clocks: it is KNOWN at 30s, and it is
    # worth telling a human at min_outage_s, once the failover has visibly failed to cover it.
    w._emit_at(now + 30)
    check(len(alerts) == 0, "30s in, the antenna may still save it — nothing sent yet")
    w._emit_at(now + 95)
    check(len(alerts) == 1, f"past min_outage_s it pages ({len(alerts)} message(s))")
    check("CRITICAL" in alerts[0], "and it is a critical")

    w._emit_at(now + 110); w._emit_at(now + 125)
    check(len(alerts) == 1, "still one message after further ticks — not one per tick")

    stub_ping(True)
    w._ping_at(now + 140)
    check(w.blackout is False, "one good round clears it (ok_checks=1)")


def test_short_blackout_is_counted_not_paged():
    print("\ntest: a blackout the failover absorbs is counted, never paged")
    # 44s with no WAN: the alert cannot leave the network (no internet), sits in the outbox,
    # and is delivered seconds AFTER the line is already back — then a 'RECOVERED, down 14s'
    # 15 minutes later. Two buzzes for an outage over before the first one landed.
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()

    w._ping_at(now); w._ping_at(now + 15); w._ping_at(now + 30)
    w._emit_at(now + 30)
    check(w.blackout is True, "still detected — this is not about hiding it")
    check(len(alerts) == 0, "but nothing is sent while it is this short")

    stub_ping(True)
    w._ping_at(now + 44)
    w._emit_at(now + 44)
    check(w.blackout is False, "it cleared after 44s")
    check(len(alerts) == 0, f"and never paged ({len(alerts)} message(s))")
    check(w.blip_count_24h() == 1, f"counted as a blip ({w.blip_count_24h()})")
    check(w.snapshot_state()["longest_blip_s"] == 44,
          f"with its real length for the digest ({w.snapshot_state()['longest_blip_s']}s)")

    # ...and no phantom recovery a quarter of an hour later, because no episode ever opened
    w._emit_at(now + 44 + 900)
    check(len(alerts) == 0, "no recovery message either — there was nothing to recover from")


def test_57s_outage_would_be_caught():
    print("\ntest: the 57s outage that the 60s sweep structurally cannot see")
    alerts = []
    w = watcher(alerts)
    stub_log([])
    # 57s at interval_s=15 is 3 full rounds of failure
    stub_ping(False)
    for _ in range(3):
        asyncio.run(w._ping_round())
    check(w.blackout is True, "confirmed inside the 57s window")
    stub_ping(True)
    asyncio.run(w._ping_round())
    check(w.blackout is False, "and cleared as soon as it comes back")


# --- 2. the router-log half -------------------------------------------------
def test_flap_between_polls_is_detected():
    print("\ntest: an outage that starts AND ends between two log polls is still seen")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([row("2026-08-17 21:04:36", "Fiber DOWN - health IP disabled"),
              row("2026-08-17 21:05:33", "Fiber UP - health IP enabled")])
    asyncio.run(w._scan_log())
    check(len(w.flaps) == 1, f"flap recovered from the log buffer ({len(w.flaps)} found)")
    check(round(w.flaps[0].seconds) == 57, f"duration is the router's, not ours ({w.flaps[0].seconds:.0f}s)")
    w._emit()
    check(len(alerts) == 1, "and it pages")
    check("57s" in alerts[0], "message states how long the link was on the backup")


def test_same_lines_are_not_counted_twice():
    print("\ntest: re-reading the same buffer does not re-report the same flap")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    rows = [row("2026-08-17 21:04:36", "Fiber DOWN - health IP disabled"),
            row("2026-08-17 21:05:33", "Fiber UP - health IP enabled")]
    stub_log(rows)
    asyncio.run(w._scan_log())
    asyncio.run(w._scan_log())
    asyncio.run(w._scan_log())
    check(len(w.flaps) == 1, f"still one flap after three polls ({len(w.flaps)})")


def test_priming_skips_history():
    print("\ntest: a restart does not replay the buffer as fresh alerts")
    alerts = []
    w = WanWatcher(CFG, alerts.append)
    stub_ping(True)
    stub_log([row("2026-08-17 12:35:34", "Fiber DOWN - health IP disabled"),
              row("2026-08-17 12:37:31", "Fiber UP - health IP enabled"),
              row("2026-08-17 23:47:37", "Fiber DOWN - health IP disabled"),
              row("2026-08-17 23:48:34", "Fiber UP - health IP enabled")])
    asyncio.run(w._scan_log(prime=True))
    check(len(w.flaps) == 0, f"yesterday's flaps are not re-announced ({len(w.flaps)})")
    check(w._watermark is not None, "watermark adopted from the router's own clock")
    w._emit()
    check(len(alerts) == 0, "and nothing is sent")


def test_sustained_outage_left_to_wan_path():
    print("\ntest: a long failover is not re-raised from the log (the route poll had it)")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([row("2026-08-17 03:00:00", "Fiber DOWN - health IP disabled"),
              row("2026-08-17 03:20:00", "Fiber UP - health IP enabled")])   # 1200s > 300s
    asyncio.run(w._scan_log())
    check(w._last_flap_at == 0, "20-minute outage does not hold an incident open here")
    # It IS counted, though. Dropping the number along with the hold is what made a
    # 24-minute outage get reported as a 4-minute one — see the regression test below.
    check(w._ep_outages == 1 and round(w._ep_outage_s) == 1200,
          f"the outage is counted for the episode total ({w._ep_outage_s:.0f}s)")
    w._emit()
    check(len(alerts) == 0, "and its 'Fiber UP' does not reopen the incident afterwards")
    check(w._ep_outages == 0,
          "with no episode to belong to, the count is dropped rather than left to "
          "contaminate the next incident")


# --- 2b. the two detectors are ONE incident ---------------------------------
def test_failover_seen_by_both_detectors_pages_once():
    print("\ntest: a failover both detectors see is ONE alert and ONE recovery")
    # The route poll catches the backup link AND the log scan recovers the completed flap a
    # minute later. In separate gates that is four Telegram messages (two alerts + two
    # recoveries).
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    now = 1_000_000.0

    w.set_path({"link": "antenna", "on_backup": True,
                "detail": "route 'Fiber' disabled by failover"})
    w._emit_at(now)
    check(len(alerts) == 1, f"the route poll pages once ({len(alerts)})")
    check("BACKUP" in alerts[0], "naming the backup link it is running on")

    # ...and 57s later the fiber is back, which the route poll sees first
    now += 57
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now)
    # ...then the log scan finds the same event and records it as a completed flap
    now += 12
    w._record_flap(Flap(datetime.datetime(2026, 8, 20, 12, 57, 2),
                        datetime.datetime(2026, 8, 20, 12, 57, 59)))
    w._last_flap_at = now
    w._emit_at(now)
    check(len(alerts) == 1, f"the log scan does NOT page a second time ({len(alerts)})")

    now += 120        # the flap hold expires
    w._emit_at(now)
    now += 900        # recovery_confirm_s of quiet
    w._emit_at(now)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"exactly one recovery message ({len(recovery)})")
    check(len(alerts) == 2, f"two messages in total for the whole event ({len(alerts)})")


def test_blackout_and_backup_link_are_one_incident():
    print("\ntest: no-internet and on-the-backup-link are ONE incident, not two")
    # One failover, seen as two incidents, sends FOUR messages: a blackout critical, a
    # backup-link critical 40 s later (two different device names for the same event), then
    # their two separate recoveries.
    alerts = []
    w = watcher(alerts)
    stub_log([])
    now = time.time()

    stub_ping(False)
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 95)
    check(len(alerts) == 1, f"the blackout opens the incident ({len(alerts)})")

    # ...and the route poll reports the backup link while that is still open
    stub_ping(True)
    w._ping_at(now + 110)
    w.set_path({"link": "antenna", "on_backup": True,
                "detail": "route 'Fiber' disabled by failover"})
    w._emit_at(now + 110)
    crit = [a for a in alerts if "CRITICAL" in a]
    check(len(crit) == 1, f"the backup link does NOT open a second incident ({len(crit)})")
    # It IS worth saying that the network has internet again, at the instant it does — the
    # user was told there was none, and the incident will not close for 15 minutes.
    check(len(alerts) == 2 and "INTERNET IS BACK" in alerts[1],
          f"the end of the blackout is announced: {alerts[-1]!r}")

    # the fiber comes back 237s in
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 237)
    check(len(alerts) == 3 and "BACK ON THE MAIN LINK" in alerts[2],
          f"and so is the return to the fiber: {alerts[-1]!r}")

    w._emit_at(now + 237 + 900)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"exactly one recovery ({len(recovery)})")
    check("MAIN link" in recovery[0],
          f"worded by what was true last — the link came back: {recovery[0]!r}")
    check("1 blackout(s)" in recovery[0],
          f"and the recovery records that part of it was a total outage: {recovery[0]!r}")
    check(len([a for a in alerts if "CRITICAL" in a]) == 1,
          "one red message for the whole event, whatever the greens say")


def test_long_outage_counts_toward_the_episode_total():
    print("\ntest: a long outage inside an episode is in the reported downtime")
    # "RECOVERED (down 237s)" for an episode the router itself timed at 237s + 1197s: the long
    # half dropped because _record_flap returned before the accounting, a 24-minute outage
    # reaching the phone as a 4-minute one.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([])
    now = time.time()

    w._record_flap(Flap(datetime.datetime(2026, 8, 22, 11, 48, 23),
                        datetime.datetime(2026, 8, 22, 11, 52, 20)))       # 237s, short
    w._last_flap_at = now
    w._emit_at(now)
    check(len(alerts) == 1, "the flap opens the incident")

    # the line drops again and stays down for 1197s — the route poll holds the episode open
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now + 1020)
    w._record_flap(Flap(datetime.datetime(2026, 8, 22, 12, 5, 23),
                        datetime.datetime(2026, 8, 22, 12, 25, 20)))       # 1197s, sustained
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 2220)
    w._emit_at(now + 2220 + 900)

    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"one recovery for the whole episode ({len(recovery)})")
    check("2 outages" in recovery[0], f"both outages counted: {recovery[0]!r}")
    check("23m" in recovery[0], f"and the real 1434s of downtime is reported: {recovery[0]!r}")


def test_recovery_reports_the_routers_own_duration():
    print("\ntest: the recovery reports the router's 57s, not the flap_hold window")
    # This is the "durata" bug: the flap is held 'present' for flap_hold_s AFTER it ended,
    # so the episode outlives the outage and the recovery claimed 60s / 75s for 57s.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    now = 1_000_000.0
    w._record_flap(Flap(datetime.datetime(2026, 8, 20, 20, 14, 5),
                        datetime.datetime(2026, 8, 20, 20, 15, 2)))     # 57s
    w._last_flap_at = now
    w._emit_at(now)
    now += 120                # the flap hold expires: the gate starts its recovery clock
    w._emit_at(now)
    now += 900                # ...and recovery_confirm_s of quiet closes the episode
    w._emit_at(now)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"one recovery ({len(recovery)})")
    check("57s" in recovery[0], f"stating the outage the router timed: {recovery[0]!r}")
    check("60s" not in recovery[0] and "75s" not in recovery[0],
          "and not the hold window that used to be reported instead")


def test_sustained_backup_reports_elapsed_time():
    print("\ntest: a sustained failover still reports its real elapsed downtime")
    # No flap is ever recorded for these (the log pair is >= path.interval_s), so there is
    # no router-measured number — and here the episode's own elapsed time IS the downtime.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    now = 1_000_000.0
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now)
    now += 3600                                   # an hour on the antenna
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now)
    now += 900
    w._emit_at(now)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"one recovery ({len(recovery)})")
    check("60m" in recovery[0], f"reporting the hour it was really down: {recovery[0]!r}")


def test_flapping_evening_pages_once():
    print("\ntest: five flaps in an evening = one page, then a recovery with the count")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    base = datetime.datetime(2026, 8, 17, 20, 0, 0)
    now = 1_000_000.0
    for i in range(5):
        w._record_flap(Flap(base + datetime.timedelta(minutes=30 * i),
                            base + datetime.timedelta(minutes=30 * i, seconds=57)))
        w._last_flap_at = now
        w._emit_at(now)          # the flap is 'present'
        now += 120
        w._emit_at(now)          # ...and 60s later it is not
        now += 1500
    check(len(alerts) == 1, f"one alert for the whole evening ({len(alerts)})")
    # 15 min of quiet closes the episode
    now += 1000
    w._emit_at(now)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"one recovery message ({len(recovery)})")
    check("outages" in recovery[0], f"which reports the flap count: {recovery[0]!r}")


# --- 2c. the three states ---------------------------------------------------
def test_three_states_track_what_is_actually_true():
    print("\ntest: ok / backup / down follow the two level detectors, immediately")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([])
    now = time.time()
    w._emit_at(now)
    check(w.state == "ok", f"green while everything answers over the fiber ({w.state})")

    stub_ping(False)
    w._ping_at(now + 15); w._ping_at(now + 30)
    w._emit_at(now + 30)
    check(w.state == "down", f"red as soon as the blackout is confirmed ({w.state})")
    # The paging floor is about what is worth a human's attention; the box shows the truth
    # at 30s, long before min_outage_s has any opinion.
    check(len(alerts) == 0, "and the screen is red before anything has been sent")

    stub_ping(True)
    w._ping_at(now + 60)
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now + 60)
    check(w.state == "backup", f"yellow once the antenna carries the traffic ({w.state})")

    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 300)
    check(w.state == "ok", f"green again when the route is back on the fiber ({w.state})")
    snap = w.snapshot_state()
    check(snap["state"] == "ok" and snap["link"] == "fiber",
          f"and the dashboard is handed both facts ({snap['state']}, {snap['link']})")


def test_a_completed_flap_does_not_colour_the_box():
    print("\ntest: the flap hold keeps the incident open without lying about the state")
    # `flap_hold_s` turns a completed flap into a 60s 'level' so the gate has something to
    # hold an episode open with. That is a gating device, not a fact about the internet:
    # by the time the log line is read the line is already back.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    now = 1_000_000.0
    w._record_flap(Flap(datetime.datetime(2026, 8, 20, 20, 14, 5),
                        datetime.datetime(2026, 8, 20, 20, 15, 2)))
    w._last_flap_at = now
    w._emit_at(now)
    check(len(alerts) == 1, "the flap still pages")
    check(w.state == "ok", f"but the box stays green — the line came back 60s ago ({w.state})")


def test_total_blackout_is_its_own_message():
    print("\ntest: losing the antenna too is a separate message, not a longer incident")
    # The failover works and the network is on the antenna — one page, as always. Then the
    # antenna dies as well and there is no internet AT ALL, which is a different thing to
    # be told and used to be invisible: the incident was already open, so nothing was sent.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([])
    now = time.time()

    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now)
    check(len(alerts) == 1 and "BACKUP" in alerts[0], "the failover pages once, as before")

    stub_ping(False)
    w._ping_at(now + 60); w._ping_at(now + 75)
    w._emit_at(now + 75)
    check(len(alerts) == 1, "nothing yet — the floor still applies to the ping detector")
    w._emit_at(now + 180)
    check(len(alerts) == 2, f"past the floor, the blackout gets its own message ({len(alerts)})")
    check("NO INTERNET AT ALL" in alerts[1], f"saying exactly that: {alerts[1]!r}")
    check(_hhmmss(now + 60) in alerts[1],
          f"and when it started, not when it was noticed: {alerts[1]!r}")

    # ...and once. A second tick inside the same incident is not a second announcement.
    w._emit_at(now + 240)
    check(len(alerts) == 2, f"still two after another tick ({len(alerts)})")


def test_the_moment_the_internet_returns_is_reported():
    print("\ntest: 'it came back at 23:19:41' — the exact time, however late the message is")
    # The whole point of the timestamps: this message cannot be delivered while it is
    # relevant. The blackout alert sits in the outbox until there is a route out, and the
    # incident's own recovery waits 15 minutes to be believed.
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()

    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 95)
    check(len(alerts) == 1 and "NO INTERNET" in alerts[0], "no internet at all, announced")

    stub_ping(True)
    w._ping_at(now + 200)
    w._emit_at(now + 200)
    check(len(alerts) == 2, f"the return is announced at once ({len(alerts)})")
    back = alerts[1]
    check("INTERNET IS BACK" in back, f"as its own message: {back!r}")
    check(_hhmmss(now + 200) in back,
          f"stating the instant it came back, not when this was sent: {back!r}")
    check("3m" in back, f"and how long the network had nothing: {back!r}")

    # ...and the incident closes silently a quarter of an hour later. Nothing was on the
    # antenna and nothing came back to the main link: the message above already said the
    # only thing a recovery could say, at the instant it was true rather than 15 minutes
    # after the fact.
    w._emit_at(now + 200 + 900)
    check(len(alerts) == 2, f"no second, later message repeating it ({len(alerts)})")
    check(not [a for a in alerts if "RECOVERED" in a], "the incident closes quietly")


def test_the_router_timestamp_wins_over_our_own():
    print("\ntest: 'back at' prefers the router's own Fiber UP second to our 15s ping grid")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    up = datetime.datetime.now().replace(microsecond=0) - datetime.timedelta(seconds=30)
    down = up - datetime.timedelta(seconds=57)
    now = time.time()
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now)
    w._record_flap(Flap(down, up))
    w._last_flap_at = now + 30
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 30)         # the route is back; the flap hold still holds the episode
    w._emit_at(now + 120)        # ...it expires, and the gate starts its recovery clock
    w._emit_at(now + 120 + 900)
    recovery = [a for a in alerts if "RECOVERED" in a][0]
    check(f"back at {up.strftime('%H:%M:%S')}" in recovery,
          f"the router's second, not ours: {recovery!r}")


def test_a_blip_stays_silent_in_every_state():
    print("\ntest: a sub-floor blackout announces neither its start nor its end")
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 30)
    check(w.state == "down", "the state still tells the truth")
    stub_ping(True)
    w._ping_at(now + 44)
    w._emit_at(now + 44)
    check(w.state == "ok", "and back again 44s later")
    check(len(alerts) == 0, f"with nothing sent in either direction ({len(alerts)})")
    w._emit_at(now + 44 + 900)
    check(len(alerts) == 0, "no late 'it's back' for something never announced")


def test_back_over_standby_then_back_on_main_are_both_announced():
    print("\ntest: 'it works again (antenna)' and 'back on the fiber' are two messages")
    # 45 minutes with nothing, the internet returns over the BACKUP, and the main link takes
    # over 31s later. Both edges are
    # news after three quarters of an hour of silence — the first because it means the network
    # can work again, the second because it means the line is properly back. Batching them
    # into one settled message was tried and rejected: waiting to name the final link costs
    # the user the moment they were actually waiting for.
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()

    w._ping_at(now); w._ping_at(now + 15)
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now + 100)
    check(len(alerts) == 1 and "NO INTERNET AT ALL" in alerts[0],
          f"the blackout is announced: {alerts[0][:40]!r}")

    back = now + 2757
    stub_ping(True)
    w._ping_at(back)
    w._emit_at(back)
    check(len(alerts) == 2, f"the internet coming back is announced at once ({len(alerts)})")
    msg = alerts[1]
    check("INTERNET IS BACK" in msg and _hhmmss(back) in msg,
          f"with the instant it returned: {msg!r}")
    # It does NOT name the link. The route poll runs on the sweep's clock, so at this
    # instant its answer predates the recovery — on the real event it still said 'antenna'
    # while the fiber had already been carrying traffic for seven seconds.
    check("antenna" not in msg and "fiber is still down" not in msg,
          f"claiming nothing about a link it cannot know yet: {msg!r}")
    check("told when the fiber is carrying it" in msg,
          f"but promising the message that follows: {msg!r}")

    # ...31 seconds later the fiber is carrying traffic again
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(back + 31)
    check(len(alerts) == 3, f"which is its own message, right after ({len(alerts)})")
    msg = alerts[2]
    check("BACK ON THE MAIN LINK" in msg and "fiber" in msg, f"naming the link: {msg!r}")
    check(_hhmmss(back + 31) in msg, f"at the instant it happened: {msg!r}")

    # ...and neither repeats on later ticks
    w._emit_at(back + 60); w._emit_at(back + 120)
    check(len(alerts) == 3, f"no repeats ({len(alerts)})")


def test_straight_from_blackout_to_main_is_one_message():
    print("\ntest: when the fiber itself comes back, there is no second message to send")
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._set_path_at(now - 60,
                   {"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 100)
    stub_ping(True)
    w._ping_at(now + 300)
    # the route poll confirms the fiber AFTER the recovery, so the link is known already
    w._set_path_at(now + 300,
                   {"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 300)
    check(len(alerts) == 2, f"the blackout and its end ({len(alerts)})")
    check("back on the main link" in alerts[1],
          f"the 'back' message already names the fiber: {alerts[1]!r}")
    w._emit_at(now + 400)
    check(len(alerts) == 2, f"so nothing follows it ({len(alerts)})")


def test_a_clean_failover_does_not_get_the_extra_messages():
    print("\ntest: a failover nobody felt still costs exactly two messages")
    # The daily fiber flap. The network never lost internet, so there is nothing to announce
    # coming back from — the incident alert and its recovery are the whole story, and the
    # 'back on the main link' message would be a third buzz for a non-event.
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([])
    now = time.time()
    w.set_path({"link": "antenna", "on_backup": True, "detail": "route 'Fiber' disabled"})
    w._emit_at(now)
    check(len(alerts) == 1, "the failover pages once")
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now + 57)
    check(len(alerts) == 1, f"no extra message when it returns ({len(alerts)})")
    w._emit_at(now + 57 + 900)
    check(len(alerts) == 2, f"just the incident's own recovery ({len(alerts)})")
    check("RECOVERED" in alerts[1], f"which is the one that carries the totals: {alerts[1]!r}")


def test_a_blackout_that_resumes_is_counted_not_re_announced():
    print("\ntest: a line flapping in and out of a blackout still pages once")
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 100)
    check(len(alerts) == 1, "the blackout is announced")

    stub_ping(True)                       # 20s of internet...
    w._ping_at(now + 200)
    w._emit_at(now + 200)
    check(len(alerts) == 2, "and its end is announced, because it really was back")
    stub_ping(False)                      # ...and it is gone again
    w._ping_at(now + 220); w._ping_at(now + 235)
    w._emit_at(now + 330)
    check(len(alerts) == 2, f"the second blackout does NOT re-announce ({len(alerts)})")
    check(w.state == "down", f"though the state is honest about it ({w.state})")
    check(w._ep_blackouts == 2, f"and both are counted ({w._ep_blackouts})")

    stub_ping(True)
    w._ping_at(now + 400)
    w._emit_at(now + 400)
    check(len(alerts) == 2, f"nor does its end ({len(alerts)})")
    w._emit_at(now + 400 + 900)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, "the incident closes once")
    check("2 blackout" in recovery[0] or "2 outages" in recovery[0],
          f"reporting both blackouts: {recovery[0]!r}")


def test_the_blackout_message_respects_the_cooldown():
    print("\ntest: a second blackout inside the gate's quiet window does not page around it")
    # The trap in adding any message outside the gate: the cooldown belongs to the INCIDENT,
    # not to one message. A line dropping every twenty minutes all evening would otherwise
    # page every time through a cooldown that is no longer a cooldown.
    alerts = []
    w = watcher(alerts)
    stub_log([])
    now = time.time()

    stub_ping(False)
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 95)
    check(len(alerts) == 1, "the first blackout pages")
    stub_ping(True)
    w._ping_at(now + 300)
    w._emit_at(now + 300)                      # "INTERNET IS BACK"
    w._emit_at(now + 300 + 900)                # ...and the episode closes
    said = len(alerts)

    # 20 minutes later — well inside cooldown_s — the line goes dark again for 3 minutes
    t2 = now + 300 + 900 + 1200
    stub_ping(False)
    w._ping_at(t2); w._ping_at(t2 + 15)
    w._emit_at(t2 + 100)
    check(len(alerts) == said, f"the second one is folded into the incident ({len(alerts)})")
    check(w._ep_blackouts == 1, f"but counted for the closing message ({w._ep_blackouts})")
    stub_ping(True)
    w._ping_at(t2 + 200)
    w._emit_at(t2 + 200)
    check(len(alerts) == said,
          f"and its end is not announced either — nobody was told it started ({len(alerts)})")


def test_state_messages_can_be_turned_off():
    print("\ntest: state_messages=false leaves the old one-incident behaviour untouched")
    import copy
    cfg = copy.deepcopy(CFG)
    cfg["wan"]["watch"]["state_messages"] = False
    alerts = []
    w = watcher(alerts, cfg=cfg)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 95)
    check(len(alerts) == 1, "the incident still pages")
    stub_ping(True)
    w._ping_at(now + 200)
    w._emit_at(now + 200)
    check(len(alerts) == 1, f"but the return is left to the recovery ({len(alerts)})")
    w._emit_at(now + 200 + 900)
    recovery = [a for a in alerts if "RECOVERED" in a]
    check(len(recovery) == 1, f"...which still arrives, 15 min later ({len(recovery)})")
    check("back at" in recovery[0],
          f"with the exact instant on it either way: {recovery[0]!r}")


# --- 3. router-log LLM triage ----------------------------------------------
class FakeAgent:
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = []

    async def ask_json(self, system, user, timeout_s=None):
        self.calls.append(user)
        return self.verdict


def test_triage_ignores_routine_chatter():
    print("\ntest: triage stays quiet for the router's normal background hum")
    alerts = []
    ag = FakeAgent({"problem": True, "severity": "critical", "summary": "x", "detail": ""})
    w = watcher(alerts, agent=ag)
    stub_ping(True)
    stub_log([row("2026-08-17 21:00:00", "user lanowl logged in from 192.168.10.103 via rest-api", "system,info,account"),
              row("2026-08-17 21:00:01", "Download from 192.168.10.113 FINISHED", "fetch,info"),
              row("2026-08-17 21:04:36", "Fiber DOWN - health IP disabled"),
              row("2026-08-17 21:05:33", "Fiber UP - health IP enabled"),
              row("2026-08-17 21:05:34", "route 0.0.0.0/0 changed by netwatch", "system,info")])
    asyncio.run(w._scan_log())
    check(len(ag.calls) == 0, f"model not consulted for known-boring lines ({len(ag.calls)} call(s))")


def test_our_own_logins_are_noise_but_other_peoples_are_not():
    print("\ntest: lanowl's own REST logins are filtered BY USERNAME, not by 'login'")
    alerts = []
    ag = FakeAgent({"problem": False, "severity": "info", "summary": "", "detail": ""})
    w = watcher(alerts, agent=ag)
    stub_ping(True)
    # exactly the form RouterOS writes for our own reads — 222 of the last 1000 lines
    stub_log([row("2026-08-17 21:10:00",
                  "user lanowl logged in from 192.168.10.103 via rest-api",
                  "system,info,account")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == 0, f"our own polling is not an event ({len(ag.calls)} call(s))")

    w._watermark = w._triage_mark = datetime.datetime(2026, 8, 17, 0, 0, 0)
    stub_log([row("2026-08-17 21:12:00",
                  "user admin logged in from 203.0.113.9 via winbox",
                  "system,info,account")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == 1, "but somebody ELSE logging in is absolutely an event")
    check("admin" in ag.calls[0], "and the model is shown that line")


def test_triage_reports_a_real_problem():
    print("\ntest: a novel line reaches the model, and a 'problem' verdict pages")
    alerts = []
    ag = FakeAgent({"problem": True, "severity": "critical",
                    "summary": "Repeated SSH login failures",
                    "detail": "12 failed logins for user admin from 203.0.113.9."})
    w = watcher(alerts, agent=ag)
    stub_ping(True)
    stub_log([row("2026-08-17 21:00:00", "user lanowl logged in from 192.168.10.103 via rest-api", "system,info,account"),
              row("2026-08-17 21:10:00", "login failure for user admin from 203.0.113.9 via ssh",
                  "system,error,critical")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))            # let the detached triage task run
    check(len(ag.calls) == 1, f"model consulted once ({len(ag.calls)})")
    check("login failure" in ag.calls[0], "and it was given the offending line")
    check("logged in from" not in ag.calls[0], "with the routine noise stripped out")
    check(len(alerts) == 1, f"the verdict pages ({len(alerts)})")
    check("ROUTER LOG" in alerts[0] and "SSH login failures" in alerts[0],
          f"message reads sensibly: {alerts[0]!r}")


def test_triage_is_told_the_internet_was_down():
    print("\ntest: the model is told about the outage that explains the lines")
    # WireGuard failing 7 handshakes in the middle of a 45-minute TOTAL blackout must not be
    # reported as a tunnel fault to go and investigate, queued in the outbox behind the very
    # outage that caused it.
    # The model could not have known: the router logs nothing about its own dead uplink,
    # so the fact that explains those lines is not in the lines.
    alerts = []
    agent = FakeAgent({"problem": False, "severity": "info",
                       "summary": "symptom of the WAN outage"})
    w = watcher(alerts, agent=agent)
    stub_ping(False)
    now = time.time()
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 100)                       # state is DOWN, blackout announced
    alerts.clear()

    stub_log([row("2026-08-24 15:11:02", "wireguard: peer1 handshake did not complete"),
              row("2026-08-24 15:24:41", "wireguard: peer1 handshake did not complete")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))               # let the detached triage task run
    check(len(agent.calls) == 1, f"the model was asked ({len(agent.calls)})")
    prompt = agent.calls[0]
    check("NO internet at all" in prompt,
          f"and told the network had nothing: {prompt.splitlines()[0][:90]!r}")
    check(prompt.index("WHAT WAS HAPPENING") < prompt.index("wireguard"),
          "with the context BEFORE the evidence, not after it")
    check(len(alerts) == 0, "a 'symptom' verdict pages nobody")


def test_triage_context_says_when_the_outage_ended():
    print("\ntest: after the line is back, the note dates the outage rather than dropping it")
    # Lines are triaged minutes after the fact — the cooldown, a busy model, the scan
    # cadence — so the window has usually closed by the time the model sees them. The note
    # has to say WHEN, or the model cannot tell a symptom from a fault that outlived it.
    alerts = []
    w = watcher(alerts)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 100)
    stub_ping(True)
    w._ping_at(now + 600)
    w._emit_at(now + 600)

    note = _at(w, now + 900, lambda: w._wan_context(now + 900))
    check("NO internet at all from" in note, f"the outage is dated: {note!r}")
    check(_hhmmss(now) in note and _hhmmss(now + 600) in note,
          f"with both ends of the window: {note!r}")
    check("working again now" in note,
          f"and the model is told it is over, so a lingering fault is still a fault: {note!r}")

    # ...and once it is old news the note goes away rather than excusing everything forever
    stale = _at(w, now + 600 + 7300, lambda: w._wan_context(now + 600 + 7300))
    check("NO internet" not in stale,
          f"a two-hour-old outage no longer explains anything: {stale!r}")


def test_triage_says_nothing_when_the_wan_is_fine():
    print("\ntest: no note at all when there is nothing to explain")
    alerts = []
    w = watcher(alerts)
    stub_ping(True)
    stub_log([])
    now = time.time()
    w._ping_at(now)
    w.set_path({"link": "fiber", "on_backup": False, "detail": "route 'Fiber' active"})
    w._emit_at(now)
    check(_at(w, now, lambda: w._wan_context(now)) == "",
          "a healthy connection adds nothing to the prompt")


def test_triage_no_problem_stays_silent():
    print("\ntest: a 'no problem' verdict is logged, never sent")
    alerts = []
    ag = FakeAgent({"problem": False, "severity": "info", "summary": "routine", "detail": ""})
    w = watcher(alerts, agent=ag)
    stub_ping(True)
    stub_log([row("2026-08-17 21:10:00", "dhcp alert on bridge: unknown server", "dhcp,warning")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == 1, "model was asked")
    check(len(alerts) == 0, f"and said nothing to the user ({len(alerts)})")


def test_triage_does_not_repeat_itself():
    print("\ntest: a recurring condition is triaged once, not once per line")
    alerts = []
    ag = FakeAgent({"problem": True, "severity": "warning", "summary": "s", "detail": ""})
    w = watcher(alerts, agent=ag)
    stub_ping(True)
    stub_log([row("2026-08-17 21:10:00", "login failure for user admin from 203.0.113.9", "system,error")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    first = len(ag.calls)
    # same condition, different attacker IP and timestamp -> same 'shape'
    w._watermark = w._triage_mark = datetime.datetime(2026, 8, 17, 0, 0, 0)
    stub_log([row("2026-08-17 21:11:00", "login failure for user admin from 198.51.100.4", "system,error")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == first, f"the second attempt does not re-ask ({len(ag.calls)} total)")
    check(len(alerts) == 1, f"and does not re-page ({len(alerts)})")


def test_triage_defers_to_a_running_audit_without_losing_lines():
    print("\ntest: triage stands aside for the hourly audit — and picks the lines up later")
    alerts = []
    ag = FakeAgent({"problem": True, "severity": "warning",
                    "summary": "Interface ether5 flapping", "detail": "d"})
    busy = {"v": True}
    w = watcher(alerts, agent=ag, llm_busy=lambda: busy["v"])
    stub_ping(True)
    stub_log([row("2026-08-17 21:10:00", "interface ether5 link down", "interface,info")])

    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == 0, "nothing sent to a model that is already loaded up")

    busy["v"] = False                     # the audit finishes; same lines still in the buffer
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(len(ag.calls) == 1, f"the deferred line IS triaged on the next scan ({len(ag.calls)})")
    check("ether5" in ag.calls[0], "and it is the line that was deferred, not a fresh one")
    check(len(alerts) == 1, "so the finding still reaches the user")


def test_triage_failure_is_harmless():
    print("\ntest: a model that errors or hangs cannot break the watcher")
    alerts = []

    class Broken:
        async def ask_json(self, *a, **kw):
            raise RuntimeError("ollama is down")

    w = watcher(alerts, agent=Broken())
    stub_ping(True)
    stub_log([row("2026-08-17 21:10:00", "some novel thing happened", "system,error")])
    asyncio.run(w._scan_log())
    asyncio.run(asyncio.sleep(0))
    check(True, "scan completed without raising")
    check(len(alerts) == 0, "and nothing was sent")


# --- test harness helper ----------------------------------------------------
def _at(self, now, fn):
    """Run `fn` with an injected clock, so the tests don't have to sleep for real."""
    real = wanwatch.time.time
    wanwatch.time.time = lambda: now
    try:
        return fn()
    finally:
        wanwatch.time.time = real


def _emit_at(self, now):
    return _at(self, now, self._emit)


def _ping_at(self, now):
    """One ping round on the injected clock — the outage floor is measured from the first
    failed round, so a test that wants to cross it has to control that clock too."""
    return _at(self, now, lambda: asyncio.run(self._ping_round()))


def _set_path_at(self, now, wp):
    """A route-poll answer that ARRIVES at `now`.

    The clock matters: the 'internet is back' message will only name a link when the route
    answer is newer than the recovery itself: the poll can still report the backup seconds
    after the main link has taken over."""
    return _at(self, now, lambda: self.set_path(wp))


WanWatcher._emit_at = _emit_at
WanWatcher._ping_at = _ping_at
WanWatcher._set_path_at = _set_path_at


def test_the_owners_own_grant_to_the_auditor_is_not_news():
    print("\n-- the owner giving lanowl's router user its chosen rights is not a finding --")
    from lanowl.wanwatch import owner_granted
    POL = ["read", "test", "sniff", "api", "rest-api"]
    real = ('user group lanowl-ro changed by macintosh-intel-mac-os-x-10-15-7/web:admin@192.168.10.140 '
            '(/user group set lanowl-ro comment="Auditor: read-only REST, no reboot/sniff/sensitive" '
            'name=lanowl-ro policy=read,test,sniff,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,'
            '!write,!policy,!winbox,!password,!web,!sensitive,!romon skin=default)')
    check(owner_granted(real, "lanowl-ro", POL),
          "the owner adding test + sniff to lanowl's group is the owner's doing, not news")
    check(owner_granted(real.replace("read,test,sniff,", "read,"), "lanowl-ro", POL),
          "taking rights away is fine too")
    check(not owner_granted(real.replace("read,test,sniff,", "read,write,test,sniff,"), "lanowl-ro", POL),
          "a grant of WRITE still goes to the model")
    check(not owner_granted(real.replace(",!sensitive,", ",sensitive,"), "lanowl-ro", POL),
          "so does sensitive (it would expose passwords to the REST user)")
    check(not owner_granted(real.replace("lanowl-ro", "full"), "lanowl-ro", POL),
          "another group's change still goes to the model")
    check(not owner_granted('user group lanowl-ro changed by x (/user group set lanowl-ro '
                            'comment="policy=read" policy=read,write,api)', "lanowl-ro", POL),
          "a comment that says policy= cannot hide the real one (the last policy= wins)")
    check(not owner_granted("user lanowl changed by admin (/user set lanowl address=0.0.0.0/0)",
                            "lanowl-ro", POL),
          "a change to lanowl USER (e.g. where it may log in from) is not covered")


# --- a standby backup link (wan.standby) ------------------------------------------
ACFG = {**CFG, "wan": {**CFG["wan"], "standby": {"ip": "192.168.20.1", "iface": "wlan1", "probe": "1.1.1.1",
                                                 "every_s": 30, "grace_s": 120}}}


class FakeAntenna:
    """The antenna over ssh: its wlan1 on or off, connected or not."""
    def __init__(self, on=False, signal=None):
        self.on, self.signal, self.calls = on, signal, []

    async def ssh(self, ip, remote, **kw):
        self.calls.append((ip, remote))
        if remote.startswith("/interface print"):
            return 0, f"0 {'R' if self.on else 'X'} name=wlan1 default-name=wlan1 type=wlan mtu=1500\n", ""
        if "registration-table" in remote:
            return 0, (f" 0 interface=wlan1 radio-name=\"AP\" signal-strength={self.signal}@6Mbps\n"
                       if self.signal is not None else ""), ""
        return 1, "", "unexpected"


def test_the_standby_is_read_only_while_the_main_is_down():
    print("\ntest: the antenna is standby by design — read only while the router has the fiber down")
    alerts = []
    w = watcher(alerts, cfg=ACFG)
    ant = FakeAntenna(on=True, signal=-67)
    w._access = ant
    stub_ping(False)          # 1.1.1.1, through the antenna, does not answer either

    async def go():
        now = time.time()
        w._standby_tick(now)
        await asyncio.sleep(0)
        out = {"up": list(ant.calls)}
        w._pending_down = datetime.datetime.fromtimestamp(now - 40)       # the router's `Fiber DOWN`
        w._standby_tick(now)
        await w._sb_task
        out["down"] = list(ant.calls)
        w._standby_tick(now + 10)
        await asyncio.sleep(0)
        out["again"] = len(ant.calls)
        out["read"] = dict(w.standby)
        out["snap"] = w.snapshot_state()["standby"]
        w._pending_down = None
        w._standby_tick(now + 60)
        out["after"] = (w._sb_down_at, w._sb_last and len(w._sb_last["reads"]))
        return out
    out = asyncio.run(go())
    check(out["up"] == [], "fiber up: the antenna is not asked anything (Wi-Fi off — or on — is fine)")
    check(len(out["down"]) == 2 and out["down"][0][0] == "192.168.20.1", "fiber down: its Wi-Fi and its link are read")
    check(out["again"] == 2, "not again within every_s")
    r = out["read"]
    check(r["on"] is True and r["link"] is True and r["signal"] == -67 and r["net"] is False,
          f"Wi-Fi on, connected at -67 dBm, no internet through it ({r})")
    check(out["snap"] and out["snap"]["on"] is True, "the dashboard sees it while the fiber is down")
    check(out["after"] == (0.0, 1), "fiber back: reads stop; the outage's reads are kept for its messages")


def test_the_blackout_says_why_the_standby_did_not_take_over():
    print("\ntest: 'no internet at all' says the antenna never switched its Wi-Fi on")
    alerts = []
    w = watcher(alerts, cfg=ACFG)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._sb_down_at = now - 10
    w._sb_reads = [{"ts": now + 20, "on": False, "link": None, "signal": None, "net": None, "err": ""}]
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 30)
    w._sb_reads.append({"ts": now + 150, "on": False, "link": None, "signal": None, "net": None, "err": ""})
    w._emit_at(now + 150)
    check(len(alerts) == 1 and "NO INTERNET" in alerts[0], f"one message ({len(alerts)})")
    check("never switched its uplink on" in alerts[0], f"with the reason, once past the grace: {alerts[0]!r}")
    stub_ping(True)
    w._ping_at(now + 300)
    w._emit_at(now + 300)
    check(len(alerts) == 2 and "INTERNET IS BACK" in alerts[1] and "never switched its uplink on" in alerts[1],
          f"and the return says what the antenna did meanwhile: {alerts[-1]!r}")


def test_inside_its_grace_the_standby_is_not_blamed():
    print("\ntest: Wi-Fi still off one minute in is the antenna getting ready, not a fault")
    alerts = []
    w = watcher(alerts, cfg=ACFG)
    stub_ping(False)
    stub_log([])
    now = time.time()
    w._sb_down_at = now
    w._sb_reads = [{"ts": now + 60, "on": False, "link": None, "signal": None, "net": None, "err": ""}]
    w._ping_at(now); w._ping_at(now + 15)
    w._emit_at(now + 95)
    check(len(alerts) == 1 and "Wi-Fi" not in alerts[0], f"nothing said about it yet: {alerts[0]!r}")


if __name__ == "__main__":
    for fn in [test_the_standby_is_read_only_while_the_main_is_down,
               test_the_blackout_says_why_the_standby_did_not_take_over,
               test_inside_its_grace_the_standby_is_not_blamed,
               test_the_owners_own_grant_to_the_auditor_is_not_news, test_blackout_confirms_in_two_rounds, test_short_blackout_is_counted_not_paged,
               test_57s_outage_would_be_caught,
               test_flap_between_polls_is_detected, test_same_lines_are_not_counted_twice,
               test_priming_skips_history, test_sustained_outage_left_to_wan_path,
               test_failover_seen_by_both_detectors_pages_once,
               test_blackout_and_backup_link_are_one_incident,
               test_long_outage_counts_toward_the_episode_total,
               test_recovery_reports_the_routers_own_duration,
               test_sustained_backup_reports_elapsed_time,
               test_flapping_evening_pages_once,
               test_three_states_track_what_is_actually_true,
               test_a_completed_flap_does_not_colour_the_box,
               test_total_blackout_is_its_own_message,
               test_the_moment_the_internet_returns_is_reported,
               test_the_router_timestamp_wins_over_our_own,
               test_a_blip_stays_silent_in_every_state,
               test_back_over_standby_then_back_on_main_are_both_announced,
               test_straight_from_blackout_to_main_is_one_message,
               test_a_clean_failover_does_not_get_the_extra_messages,
               test_a_blackout_that_resumes_is_counted_not_re_announced,
               test_the_blackout_message_respects_the_cooldown,
               test_state_messages_can_be_turned_off,
               test_triage_ignores_routine_chatter,
               test_our_own_logins_are_noise_but_other_peoples_are_not,
               test_triage_reports_a_real_problem,
               test_triage_is_told_the_internet_was_down,
               test_triage_context_says_when_the_outage_ended,
               test_triage_says_nothing_when_the_wan_is_fine,
               test_triage_no_problem_stays_silent, test_triage_does_not_repeat_itself,
               test_triage_defers_to_a_running_audit_without_losing_lines,
               test_triage_failure_is_harmless]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all WAN-watcher tests passed")
