"""Alert-gate state machine tests: run with `python -m tests.test_alerts`.

Pure logic, no network — the clock is injected, so a two-hour flapping outage is a
handful of calls. The rule being pinned down: the user hears about an incident once,
and never stops hearing about one that is genuinely still broken.
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.alerts import NEW, RECOVERED, STILL, AlertGate

WAN = {"device": "Internet / WAN", "ip": "-", "group": "wan",
       "severity": "critical", "detail": "No WAN reachability", "kind": "wan"}
CAM = {"device": "Group 'cameras'", "ip": "-", "group": "cameras",
       "severity": "critical", "detail": "7/10 down", "kind": "group"}

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


def kinds(events):
    return [e.kind for e in events]


def gate(**kw):
    return AlertGate(recovery_confirm_s=kw.get("recovery_confirm_s", 900),
                     cooldown_s=kw.get("cooldown_s", 3600),
                     renotify_after_s=kw.get("renotify_after_s", 0))


def test_single_incident_alerts_once():
    print("a steady outage alerts once and recovers once")
    g, t = gate(), 1000.0
    check(kinds(g.update({"wan": WAN}, t)) == [NEW], "first sweep alerts")
    for i in range(1, 40):                       # 40 min still down: silence
        check(g.update({"wan": WAN}, t + i * 60) == [], f"sweep {i} stays quiet") if i == 39 else \
            g.update({"wan": WAN}, t + i * 60)
    ev = g.update({}, t + 40 * 60)               # clears
    check(ev == [], "recovery is held, not fired on the first clear sweep")
    ev = g.update({}, t + 40 * 60 + 899)
    check(ev == [], "still held one second before the confirm window")
    ev = g.update({}, t + 40 * 60 + 900)
    check(kinds(ev) == [RECOVERED], "recovery fires once the window passes")
    check(round(ev[0].duration_s) == 2400, f"duration is the outage, not the wait ({ev[0].duration_s})")


def test_flapping_is_one_incident():
    """A flapping evening: down/up/down/up/down/up in ~55 min."""
    print("a flapping line is one incident, not three")
    g, t = gate(), 0.0
    msgs = []
    for cycle in range(3):
        base = t + cycle * 2400                  # a fresh drop every 40 min
        msgs += g.update({"wan": WAN}, base)
        msgs += g.update({}, base + 300)         # back after 5 min
        msgs += g.update({}, base + 600)
    msgs += g.update({}, t + 3 * 2400 + 1000)    # long enough to confirm recovery
    check(kinds(msgs) == [NEW, RECOVERED], f"two messages total, got {kinds(msgs)}")
    rec = [m for m in msgs if m.kind == RECOVERED][0]
    check(rec.flaps == 2, f"the recovery reports the 2 folded flaps (got {rec.flaps})")


def test_refire_after_recovery_is_quiet_then_escalates():
    print("a re-fire after recovery is quiet — until it proves it is real")
    g, t = gate(), 0.0
    g.update({"wan": WAN}, t)                    # NEW
    g.update({}, t + 60)
    ev = g.update({}, t + 60 + 900)              # RECOVERED at t+960
    check(kinds(ev) == [RECOVERED], "recovered")
    ev = g.update({"wan": WAN}, t + 1200)        # re-fires inside the cooldown
    check(ev == [], "re-fire inside the cooldown says nothing")
    ev = g.update({"wan": WAN}, t + 3000)
    check(ev == [], "still nothing halfway through the cooldown")
    ev = g.update({"wan": WAN}, t + 960 + 3600)  # cooldown expires, still down
    check(kinds(ev) == [STILL], f"a problem that outlasts the cooldown pages again ({kinds(ev)})")
    check(ev[0].flaps == 1, "and says it flapped")


def test_refire_that_heals_stays_silent():
    print("a re-fire that heals inside the cooldown is never mentioned")
    g, t = gate(), 0.0
    g.update({"wan": WAN}, t)
    g.update({}, t + 60)
    g.update({}, t + 1000)                       # RECOVERED
    g.update({"wan": WAN}, t + 1200)             # blip inside the cooldown
    ev = g.update({}, t + 1260)
    check(ev == [], "no alert for the blip")
    ev = g.update({}, t + 1260 + 900)
    check(ev == [], f"and no second recovery for it either ({kinds(ev)})")


def test_new_incident_after_cooldown():
    print("a genuinely new outage, hours later, is a new incident")
    g, t = gate(), 0.0
    g.update({"wan": WAN}, t)
    g.update({}, t + 60)
    g.update({}, t + 1000)                       # RECOVERED at t+1000
    ev = g.update({"wan": WAN}, t + 1000 + 3600) # cooldown over
    check(kinds(ev) == [NEW], f"pages as new ({kinds(ev)})")
    check(ev[0].flaps == 0, "with a clean flap count")


def test_correlated_issues_batch():
    print("issues raised in the same sweep come out together")
    g, t = gate(), 0.0
    ev = g.update({"wan": WAN, "cam": CAM}, t)
    check(len(ev) == 2 and set(kinds(ev)) == {NEW}, "both raised in one update() call")
    ev = g.update({}, t + 60)
    ev = g.update({}, t + 60 + 900)
    check(len(ev) == 2 and set(kinds(ev)) == {RECOVERED}, "both recover together")


def test_renotify_heartbeat():
    print("renotify_after_s re-pings an issue that never clears")
    g, t = gate(renotify_after_s=3600), 0.0
    check(kinds(g.update({"wan": WAN}, t)) == [NEW], "initial alert")
    check(g.update({"wan": WAN}, t + 1800) == [], "quiet at 30 min")
    check(kinds(g.update({"wan": WAN}, t + 3600)) == [STILL], "heartbeat at 60 min")
    check(g.update({"wan": WAN}, t + 5000) == [], "quiet again after it")
    ev = g.update({"wan": WAN}, t + 7200)
    check(kinds(ev) == [STILL], "and again at 120 min")
    check(round(ev[0].duration_s) == 7200, "reporting the full elapsed downtime")


def test_cooldown_zero_is_legacy_behaviour():
    print("cooldown_s=0 restores alert-on-every-re-fire")
    g, t = gate(cooldown_s=0, recovery_confirm_s=0), 0.0
    check(kinds(g.update({"wan": WAN}, t)) == [NEW], "alert")
    check(kinds(g.update({}, t + 60)) == [], "clear sweep arms the recovery")
    check(kinds(g.update({}, t + 120)) == [RECOVERED], "recovery next sweep")
    check(kinds(g.update({"wan": WAN}, t + 180)) == [NEW], "re-fire pages immediately")


def test_outbox_says_when_a_delayed_alert_already_healed():
    print("\ntest: a queued alert whose incident is over says so on delivery")
    # An alert raised during a blackout cannot leave the network, so by the time Telegram is
    # reachable the news is always late — and sometimes it is also over: delivered seconds
    # after the line came back, in the present tense, it must say it has already recovered.
    import asyncio
    import tempfile

    from lanowl import sinks

    sent = []

    async def fake_send(cfg, text, **kw):   # ids=, chat_id=: see telegram_direct
        sent.append(text)
        return True

    real, sinks.telegram_direct = sinks.telegram_direct, fake_send
    try:
        with tempfile.TemporaryDirectory() as d:
            ob = sinks.TelegramOutbox(os.path.join(d, "outbox.json"))
            ob.add("🔴 CRITICAL — no internet", key="wan-incident:-:wan:Internet / WAN")
            ob.add("🔴 CRITICAL — boiler unreachable", key="down:192.168.10.59:home:Boiler")
            # the WAN healed while the messages were stuck; the boiler is still down
            asyncio.run(ob.flush({}, {"down:192.168.10.59:home:Boiler"}))

            check(len(sent) == 2, f"both queued messages are still delivered ({len(sent)})")
            check("already recovered" in sent[0],
                  f"the healed one is marked as over: {sent[0]!r}")
            check("already recovered" not in sent[1],
                  f"the one still broken is not: {sent[1]!r}")
            check(ob.pending == 0, "and the queue is empty afterwards")
    finally:
        sinks.telegram_direct = real


class _FakeResponse:
    def __init__(self, status, body=""):
        self.status, self._body = status, body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """Scripted Bot API: each entry is an HTTP status, a body, or an exception to raise."""
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def post(self, url, json=None):
        self.calls.append(dict(json))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        status, body = step if isinstance(step, tuple) else (step, "")
        return _FakeResponse(status, body)


def test_direct_sender_retries_the_route_flip():
    print("\ntest: the direct sender survives what killed Node-RED's — and knows when to stop")
    import asyncio

    from lanowl import sinks

    # no sleeping in tests
    real_sleep, sinks.asyncio.sleep = sinks.asyncio.sleep, _no_sleep
    try:
        # the WAN flip: the request in flight gets no answer; the retry a moment later does
        s = _FakeSession([asyncio.TimeoutError(), 200])
        ok = asyncio.run(sinks._send_part(s, "u", "c", "🔴 fiber down"))
        check(ok is True and len(s.calls) == 2, "a timeout is retried and the retry delivers")

        # a dead path: every attempt fails -> False, so the caller queues it
        s = _FakeSession([asyncio.TimeoutError()] * sinks.TG_ATTEMPTS)
        ok = asyncio.run(sinks._send_part(s, "u", "c", "x"))
        check(ok is False and len(s.calls) == sinks.TG_ATTEMPTS,
              f"gives up after {sinks.TG_ATTEMPTS} attempts and reports failure")

        # bad markup: Telegram refuses the HTML, the same text goes out plain
        s = _FakeSession([(400, "Bad Request: can't parse entities"), 200])
        ok = asyncio.run(sinks._send_part(s, "u", "c", "<b>unbalanced"))
        check(ok is True and "parse_mode" in s.calls[0] and "parse_mode" not in s.calls[1],
              "rejected HTML is resent as plain text")

        # ...and if Telegram still refuses, the message is rejected, not retried forever
        s = _FakeSession([(400, "Bad Request: chat not found"), (400, "Bad Request: chat not found")])
        try:
            asyncio.run(sinks._send_part(s, "u", "c", "x"))
            check(False, "a second 400 raises TelegramRejected")
        except sinks.TelegramRejected:
            check(True, "a second 400 raises TelegramRejected")

        # a 5xx is the path, not the message: retried, then given up on
        s = _FakeSession([(502, "bad gateway"), (502, "bad gateway"), 200])
        ok = asyncio.run(sinks._send_part(s, "u", "c", "x"))
        check(ok is True and len(s.calls) == 3, "a 5xx is retried")
    finally:
        sinks.asyncio.sleep = real_sleep

    # a digest longer than Telegram allows is cut on line boundaries
    long = "\n".join(f"line {i:04d} " + "x" * 60 for i in range(100))
    parts = sinks._split(long, limit=1000)
    check(all(len(p) <= 1000 for p in parts) and "".join(p.replace("\n", "") for p in parts)
          == long.replace("\n", ""), f"long text splits into {len(parts)} parts, nothing lost")
    check(all(not p.startswith("\n") and not p.endswith("\n") for p in parts),
          "every part starts and ends on a whole line")
    check(sinks._split("short") == ["short"], "short text is untouched")


async def _no_sleep(_s):
    return None


def test_outbox_drops_what_telegram_rejects():
    print("\ntest: a message Telegram will never accept does not block the queue behind it")
    import asyncio
    import tempfile

    from lanowl import sinks

    sent = []

    async def fake_send(cfg, text, **kw):   # ids=, chat_id=: see telegram_direct
        if "poison" in text:
            raise sinks.TelegramRejected("HTTP 400: can't parse entities")
        sent.append(text)
        return True

    real, sinks.telegram_direct = sinks.telegram_direct, fake_send
    try:
        with tempfile.TemporaryDirectory() as d:
            ob = sinks.TelegramOutbox(os.path.join(d, "outbox.json"))
            ob.add("poison <b>", key="k1")
            ob.add("🔴 CRITICAL — router unreachable", key="k2")
            n = asyncio.run(ob.flush({}, {"k2"}))
            check(n == 1 and len(sent) == 1 and "router" in sent[0],
                  "the poisoned message is dropped and the one behind it is delivered")
            check(ob.pending == 0, "the queue is empty afterwards")
    finally:
        sinks.telegram_direct = real


def test_pruning():
    print("closed episodes are eventually forgotten")
    g, t = gate(), 0.0
    g.update({"wan": WAN}, t)
    g.update({}, t + 60)
    g.update({}, t + 1000)
    check(len(g._eps) == 1, "kept while the cooldown could still apply")
    g.update({}, t + 1000 + 3600 + 900 + 3601)
    check(len(g._eps) == 0, "dropped once it can no longer affect anything")


def _reborn(g, now, **kw):
    """The same gate as the next process sees it: dumped, through JSON, restored."""
    import json
    g2 = gate(**kw)
    g2.restore(json.loads(json.dumps(g.dump())), now)
    return g2


def test_restart_does_not_repage():
    print("a restart does not re-announce an incident the user was already told about")
    g, t = gate(), 1000.0
    check(kinds(g.update({"cam": CAM}, t)) == [NEW], "paged once")
    g2 = _reborn(g, t + 600)
    check(g2.update({"cam": CAM}, t + 660) == [], "the next process stays quiet about it")
    g2.update({}, t + 720)
    ev = g2.update({}, t + 720 + 900)
    check(kinds(ev) == [RECOVERED], "...and still owes the recovery")
    check(bool(ev) and ev[0].duration_s == 720, "timed from the start before the restart")
    check(gate().restore(None, t) == 0 and gate().restore({"k": {"nope": 1}}, t) == 0,
          "a missing or unreadable record restores nothing")


def test_restart_keeps_the_cooldown():
    print("a cooldown keeps running across a restart")
    g, t = gate(), 1000.0
    g.update({"wan": WAN}, t)
    g.update({}, t + 60)
    check(kinds(g.update({}, t + 60 + 900)) == [RECOVERED], "recovered before the restart")
    g2 = _reborn(g, t + 1000)
    check(g2.update({"wan": WAN}, t + 1100) == [], "a re-fire inside the cooldown stays quiet")
    check(kinds(g2.update({"wan": WAN}, t + 960 + 3600)) == [STILL],
          "still down when the cooldown ends: it pages once more")


def test_restart_catch_up_is_not_a_flap():
    print("looking clear while a restarted process catches up is not a flap")
    g, t = gate(), 1000.0
    g.update({"cam": CAM}, t)
    g2 = _reborn(g, t + 600)
    g2.update({}, t + 660)                  # the first sweep has not seen it again yet
    g2.update({"cam": CAM}, t + 720)
    check(g2.episode_flaps("cam") == 0, "no flap for the catch-up")
    g2.update({}, t + 600 + 400)            # a real drop, after the grace
    g2.update({"cam": CAM}, t + 600 + 460)
    check(g2.episode_flaps("cam") == 1, "a real one later still counts")


if __name__ == "__main__":
    for fn in [test_single_incident_alerts_once, test_flapping_is_one_incident,
               test_refire_after_recovery_is_quiet_then_escalates,
               test_refire_that_heals_stays_silent, test_new_incident_after_cooldown,
               test_correlated_issues_batch, test_renotify_heartbeat,
               test_cooldown_zero_is_legacy_behaviour,
               test_outbox_says_when_a_delayed_alert_already_healed,
               test_direct_sender_retries_the_route_flip,
               test_outbox_drops_what_telegram_rejects, test_pruning,
               test_restart_does_not_repage, test_restart_keeps_the_cooldown,
               test_restart_catch_up_is_not_a_flap]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all alert-gate tests passed")
