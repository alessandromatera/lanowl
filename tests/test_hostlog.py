"""Host-log watcher tests: run with `python -m tests.test_hostlog`.

No network and no server — the ssh call is stubbed, so a night of somebody guessing
passwords is a handful of dict lookups. What is being pinned down:

  1. a restart does not replay days of journal out of the box's history;
  2. the routine hum (cron twice a minute, logind bookkeeping, samba churn) never
     reaches the model, and neither does the watcher's OWN ssh poll — but the same
     account logging in from anywhere else does;
  3. a burst of failed logins pages WITHOUT the model, once per source, per the rule in
     alerts.py;
  4. the triage stays quiet for the ordinary, speaks for the real, and never blocks the
     poll clock or queues behind the hourly audit;
  5. an unreachable host is a status, not an alert.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.hostlog import HostLogWatcher

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


CFG = {
    "hostlog": {
        "enabled": True, "interval_s": 120,
        "ssh": {"binary": "ssh", "connect_timeout_s": 8, "command_timeout_s": 25},
        # the user matters: our own poll is filtered by user AND source address
        # (see HostLogWatcher._is_ours), so the fixtures below use the real pair
        "hosts": [{"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi"}],
        "burst": {"enabled": True, "window_s": 600, "fail_attempts": 8, "repeat_s": 3600},
        "connections": {"enabled": True, "max_established": 600, "confirm_polls": 2,
                        "repeat_s": 3600},
        "triage": {"enabled": True, "cooldown_s": 0, "timeout_s": 5, "fetch_lines": 400,
                   "max_lines": 40, "notify_severities": ["critical", "warning"]},
    },
    # the address lanowl polls FROM; our own logins wear it
    "observer": {"host_ip": "192.168.10.103"},
}

CURSOR = "s=18ff;i=1;b=58ac;m=66;t=65a;x=19"

# --- fixtures ----------------------------------------------------------------
ROUTINE = [
    "2026-09-03T14:05:01+02:00 homehub CRON[12465]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
    "2026-09-03T14:05:01+02:00 homehub CRON[12465]: pam_unix(cron:session): session closed for user root",
    "2026-09-03T14:05:12+02:00 homehub systemd-logind[907]: New session 894 of user pi.",
    "2026-09-03T14:05:19+02:00 homehub systemd-logind[907]: Removed session 894.",
    "2026-09-03T14:06:02+02:00 homehub smbd: pam_unix(samba:session): session opened for user samba(uid=1001) by (uid=0)",
]
# the watcher's own ssh poll, exactly as it lands in the journal it is reading
OUR_POLL = [
    "2026-09-03T14:07:11+02:00 homehub sshd[122471]: Accepted publickey for pi from 192.168.10.103 port 59498 ssh2: ED25519 SHA256:8k",
    "2026-09-03T14:07:11+02:00 homehub sshd[122471]: pam_unix(sshd:session): session opened for user pi(uid=1000) by pi(uid=0)",
]


def out(lines, cursor=CURSOR, conns=118, peers=32, entries=True):
    """What the remote command prints: journal lines, cursor, then the census."""
    body = "\n".join(lines) if entries else "-- No entries --"
    return f"{body}\n-- cursor: {cursor}\n--- conns ---\n{conns}\n{peers}\n"


class FakeAgent:
    """Stands in for LlmAgent. Records what it was asked; answers what it was told to."""

    def __init__(self, verdict=None, delay=0.0):
        self.verdict, self.delay = verdict, delay
        self.asks = []

    async def ask_json(self, system, user_context, timeout_s=None):
        self.asks.append(user_context)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.verdict


class FakeState:
    """The two calls SecLog makes of the StateStore."""
    def __init__(self):
        self.recs = {}

    def save_record(self, name, obj):
        self.recs[name] = __import__("json").loads(__import__("json").dumps(obj))

    def load_record(self, name):
        return self.recs.get(name)


def watcher(alerts, agent=None, cfg=None, llm_busy=None, wan=None, seclog=None, access=None):
    # on_alert is (text, key="") — the same sink the WAN watcher uses, so these findings
    # inherit the outbox and the direct-Telegram fallback
    return HostLogWatcher(cfg or CFG, lambda t, key="": alerts.append((t, key)),
                          agent=agent, llm_busy=llm_busy, wan_context=wan, seclog=seclog,
                          access_check=access)


def access_says(result):
    """A stand-in for Exposure._name_check: what one HTTPS GET from outside got."""
    calls = []

    async def check(name):
        calls.append(name)
        if isinstance(result, Exception):
            raise result
        return {"name": name, **result}
    check.calls = calls
    return check


def drive(w, responses):
    """Run one _poll per canned ssh response, priming on the first."""
    seq = list(responses)

    async def fake_ssh(h, remote):
        return seq.pop(0) if seq else None

    w._ssh = fake_ssh          # bound-method replacement: (host, remote) -> str | None

    async def go():
        h = w.hosts[0]
        first = True
        while seq:
            await w._poll(h, prime=first)
            first = False
        # let any detached triage task finish
        if w._triage_task is not None:
            await asyncio.gather(w._triage_task, return_exceptions=True)
    asyncio.run(go())
    return w


# --- tests -------------------------------------------------------------------
def test_priming_skips_history():
    print("\n-- a restart does not replay the box's journal --")
    a, ag = [], FakeAgent({"problem": True, "severity": "critical", "summary": "old news"})
    w = drive(watcher(a, agent=ag), [out(["2026-08-30T03:14:00+02:00 homehub sshd[1]: Failed password for root from 8.8.8.8 port 1 ssh2"])])
    check(w.hosts[0].cursor == CURSOR, "the cursor is adopted from the first read")
    check(ag.asks == [], "nothing from before the watcher started is triaged")
    check(a == [], "and nothing is paged")


def test_routine_chatter_is_not_triaged():
    print("\n-- cron, logind and samba churn never reach the model --")
    a, ag = [], FakeAgent({"problem": False})
    drive(watcher(a, agent=ag), [out([]), out(ROUTINE)])
    check(ag.asks == [], "a poll of pure background hum asks nothing")
    check(a == [], "and says nothing")


def test_our_own_poll_is_noise_but_others_are_not():
    print("\n-- our own ssh poll is filtered by user AND address, never by user alone --")
    a, ag = [], FakeAgent({"problem": False})
    drive(watcher(a, agent=ag), [out([]), out(OUR_POLL)])
    check(ag.asks == [], "the watcher's own login is not a finding")

    a2, ag2 = [], FakeAgent({"problem": False})
    intruder = ["2026-09-03T03:14:00+02:00 homehub sshd[9]: Accepted publickey for pi "
                "from 203.0.113.9 port 40001 ssh2: ED25519 SHA256:zz"]
    drive(watcher(a2, agent=ag2), [out([]), out(intruder)])
    check(len(ag2.asks) == 1 and "203.0.113.9" in ag2.asks[0],
          "the same account from another address IS offered to the model")


def test_burst_pages_without_the_model():
    print("\n-- a run of failed logins pages on a rule, not on a verdict --")
    a = []
    attack = [f"2026-09-03T03:1{i}:00+02:00 homehub sshd[{100+i}]: "
              f"Failed password for root from 203.0.113.9 port {40000+i} ssh2"
              for i in range(9)]
    drive(watcher(a, agent=None), [out([]), out(attack)])       # agent=None: no LLM at all
    check(len(a) == 1, f"one alert for nine attempts from one source (got {len(a)})")
    check("203.0.113.9" in a[0][0] and "FAILED LOGINS" in a[0][0],
          "it names the source address")
    check("root" in a[0][0], "...and the account being guessed")
    check(a[0][1] == "hostlog-burst:192.168.10.113:203.0.113.9", "keyed per source for the outbox")


def test_burst_does_not_add_up_across_sources():
    print("\n-- one mistyped password here and a scan there are not one incident --")
    a = []
    mixed = ([f"2026-09-03T03:10:0{i}+02:00 homehub sshd[{i}]: Failed password for pi "
              f"from 192.168.10.55 port {41000+i} ssh2" for i in range(5)]
             + [f"2026-09-03T03:11:0{i}+02:00 homehub sshd[{20+i}]: Failed password for "
                f"root from 203.0.113.9 port {42000+i} ssh2" for i in range(5)])
    drive(watcher(a, agent=None), [out([]), out(mixed)])
    check(a == [], "five plus five from two addresses is under the per-source floor")


def test_a_hammering_scanner_still_costs_one_message():
    print("\n-- an evening of hammering is one message, not one per poll --")
    a = []
    rounds = []
    for r in range(3):
        rounds.append(out([f"2026-09-03T03:{20+r}:0{i}+02:00 homehub sshd[{r*10+i}]: "
                           f"Invalid user admin from 203.0.113.9 port {43000+i}"
                           for i in range(9)]))
    drive(watcher(a, agent=None), [out([])] + rounds)
    check(len(a) == 1, f"repeat_s holds the second and third burst (got {len(a)})")


def test_triage_reports_a_real_problem():
    print("\n-- the model's verdict becomes a message --")
    a = []
    ag = FakeAgent({"problem": True, "severity": "critical",
                    "summary": "root logged in from an unknown address",
                    "detail": "Check ~/.ssh/authorized_keys on the host."})
    odd = ["2026-09-03T03:14:00+02:00 homehub sudo: pi : TTY=pts/1 ; PWD=/home/pi ; "
           "USER=root ; COMMAND=/usr/sbin/useradd -m backdoor"]
    drive(watcher(a, agent=ag), [out([]), out(odd)])
    check(len(a) == 1, "one alert")
    check("HOST LOG" in a[0][0] and "root logged in" in a[0][0], "carries the summary")
    check("authorized_keys" in a[0][0], "...and the detail")
    check("VM HomeHub" in a[0][0], "...and says which host")


def test_triage_no_problem_stays_silent():
    print("\n-- 'problem: false' is logged, never sent --")
    a, ag = [], FakeAgent({"problem": False, "summary": "the owner logged in"})
    odd = ["2026-09-03T09:00:00+02:00 homehub sshd[7]: Accepted password for pi from 192.168.10.55 port 5 ssh2"]
    drive(watcher(a, agent=ag), [out([]), out(odd)])
    check(len(ag.asks) == 1, "the model was asked")
    check(a == [], "and nothing was sent")


def test_info_verdicts_are_not_sent():
    print("\n-- an 'info' finding stays on the dashboard --")
    a, ag = [], FakeAgent({"problem": True, "severity": "info", "summary": "a service restarted"})
    odd = ["2026-09-03T09:00:00+02:00 homehub sshd[7]: Server listening on 0.0.0.0 port 22."]
    drive(watcher(a, agent=ag), [out([]), out(odd)])
    check(a == [], "notify_severities keeps 'info' quiet")


def test_the_same_condition_does_not_repeat():
    print("\n-- a shape that has had its say is not triaged again --")
    a, ag = [], FakeAgent({"problem": True, "severity": "warning", "summary": "odd sudo"})
    line = ("2026-09-03T0{}:14:00+02:00 homehub sudo: pi : TTY=pts/1 ; PWD=/home/pi ; "
            "USER=root ; COMMAND=/usr/bin/id")
    drive(watcher(a, agent=ag), [out([]), out([line.format(3)]), out([line.format(4)])])
    check(len(ag.asks) == 1, f"asked once, not twice (got {len(ag.asks)})")
    check(len(a) == 1, "and paged once")


def test_triage_defers_to_a_running_audit():
    print("\n-- the hourly audit keeps the model; the poll clock does not wait --")
    a, ag = [], FakeAgent({"problem": True, "severity": "critical", "summary": "x"})
    odd = ["2026-09-03T03:14:00+02:00 homehub sshd[7]: Accepted password for pi from 203.0.113.9 port 5 ssh2"]
    w = drive(watcher(a, agent=ag, llm_busy=lambda: True), [out([]), out(odd)])
    check(ag.asks == [], "nothing is queued behind the audit")
    check(a == [], "and nothing is sent")
    check(w.hosts[0].cursor == CURSOR, "the poll finished anyway")


def test_burst_fires_even_while_the_model_is_busy():
    print("\n-- the rule is the safety net the model is not --")
    a = []
    attack = [f"2026-09-03T03:1{i}:00+02:00 homehub sshd[{i}]: Failed password for root "
              f"from 203.0.113.9 port {40000+i} ssh2" for i in range(9)]
    drive(watcher(a, agent=FakeAgent(None), llm_busy=lambda: True), [out([]), out(attack)])
    check(len(a) == 1, "a brute force pages while the audit holds the model")


def test_connection_ceiling_needs_two_polls():
    print("\n-- a spike is not an incident; a sustained flood is --")
    a = []
    drive(watcher(a, agent=None), [out([]), out([], conns=900, peers=700)])
    check(a == [], "one poll over the ceiling says nothing")
    a2 = []
    drive(watcher(a2, agent=None),
          [out([]), out([], conns=900, peers=700), out([], conns=950, peers=740)])
    check(len(a2) == 1 and "950" in a2[0][0], "two in a row is reported once, with the count")

    a3 = []
    drive(watcher(a3, agent=None),
          [out([]), out([], conns=900, peers=700), out([], conns=118, peers=32),
           out([], conns=900, peers=700)])
    check(a3 == [], "a poll back under the ceiling resets the confirmation")


def test_quiet_polls_are_not_new_lines():
    print("\n-- '-- No entries --' is not a log entry --")
    a, ag = [], FakeAgent({"problem": True, "severity": "critical", "summary": "x"})
    drive(watcher(a, agent=ag), [out([]), out([], entries=False), out([], entries=False)])
    check(ag.asks == [], "a quiet poll asks nothing")
    check(a == [], "and pages nothing")


def test_an_unreachable_host_is_a_status_not_an_alert():
    print("\n-- ssh failing is for the dashboard; the device sweep already pages --")
    a = []
    w = watcher(a, agent=None)

    async def dead_ssh(h, remote):
        h.ok, h.last_error = False, "ssh: connect to host 192.168.10.113 port 22: No route to host"
        return None
    w._ssh = dead_ssh
    asyncio.run(w._poll(w.hosts[0], prime=True))
    asyncio.run(w._poll(w.hosts[0]))
    check(a == [], "no alert of its own — the host being down is the sweep's story")
    snap = w.snapshot_state()
    check(snap["hosts"][0]["ok"] is False and "No route" in snap["hosts"][0]["error"],
          "but the dashboard says why")


def test_the_wan_context_reaches_the_prompt():
    print("\n-- an outage explains the failures it caused --")
    a, ag = [], FakeAgent({"problem": False})
    odd = ["2026-09-03T15:14:00+02:00 homehub sshd[7]: error: kex_exchange_identification: "
           "Connection closed by remote host"]
    drive(watcher(a, agent=ag, wan=lambda: "The network had NO internet at all from 15:11 to 15:24."),
          [out([]), out(odd)])
    check(len(ag.asks) == 1 and "NO internet at all" in ag.asks[0],
          "the model is told what the internet was doing")
    check("CONNECTION CENSUS" in ag.asks[0], "...and how many sockets the host holds")


def test_a_login_through_the_tunnel_pages():
    """A Cloudflare Tunnel routes ssh.example.com to the host's sshd, which sees those logins
    from 127.0.0.1 — the internet, not the host itself."""
    print("\n-- a login through the Cloudflare Tunnel (127.0.0.1) pages; the LAN does not --")
    cfg = {**CFG, "hostlog": {**CFG["hostlog"], "hosts": [
        {"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi", "tunnel_from": ["127.0.0.1"]}]}}
    tunnel = ["2026-09-27T03:14:00+02:00 homehub sshd[9]: Accepted password for pi "
              "from 127.0.0.1 port 40001 ssh2"]
    lan = ["2026-09-27T03:15:00+02:00 homehub sshd[10]: Accepted password for pi "
           "from 192.168.10.70 port 40002 ssh2"]
    a = []
    drive(watcher(a, agent=FakeAgent({"problem": False}), cfg=cfg), [out([]), out(tunnel), out(tunnel + lan)])
    check(len(a) == 1 and "Cloudflare Tunnel" in a[0][0] and "from the INTERNET" in a[0][0]
          and "change pi's password" in a[0][0] and a[0][1] == "hostlog-login:192.168.10.113:127.0.0.1",
          "one page, saying it came from the internet, and whose password to change")
    a2 = []
    drive(watcher(a2, agent=FakeAgent({"problem": False})), [out([]), out(tunnel)])
    check(a2 == [], "without tunnel_from a non-public host pages nothing, as before")
    check("arrive from 127.0.0.1 and come from the INTERNET" in " ".join(__import__("lanowl.hostlog", fromlist=["x"]).DEFAULT_ABOUT.split()),
          "the default host description says a tunnel's 127.0.0.1 is the internet")


TUNNEL_CFG = {**CFG, "hostlog": {**CFG["hostlog"], "hosts": [
    {"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi", "tunnel_from": ["127.0.0.1"],
     "tunnel_names": ["ssh.example.com"]}]}}
TUNNEL_LOGIN = ["2026-09-28T10:48:40+02:00 homehub sshd[9]: Accepted password for pi "
                "from 127.0.0.1 port 48110 ssh2"]
TUNNEL_CLOSED = ["2026-09-28T10:48:52+02:00 homehub sshd[11]: Connection closed by "
                 "authenticating user pi 127.0.0.1 port 48122 [preauth]"]


def test_a_login_past_cloudflare_access_is_yellow():
    """With Cloudflare Access in front of ssh.example.com, a login through it pages 🟡 once a
    day, saying so — checked from outside at that moment."""
    print("\n-- a tunnel login past Cloudflare Access: 🟡, and on the Security tab --")
    from lanowl.seclog import SecLog
    a, sl, acc = [], SecLog(FakeState()), access_says({"https": 302, "access_login": True})
    drive(watcher(a, agent=FakeAgent({"problem": False}), cfg=TUNNEL_CFG, seclog=sl, access=acc),
          [out([]), out(TUNNEL_LOGIN)])
    check(len(a) == 1 and "🟡" in a[0][0] and "CLOUDFLARE ACCESS" in a[0][0]
          and "ssh.example.com" in a[0][0] and "checked just now" in a[0][0],
          "one yellow page naming the name and that Access was checked")
    check(acc.calls == ["ssh.example.com"], "Access was checked from outside, once")
    it = sl.view()["open"]
    check(len(it) == 1 and it[0]["sev"] == "warning" and it[0]["by"] == "rule"
          and it[0]["ip"] == "192.168.10.113" and "Accepted password for pi" in it[0]["detail"],
          "and it is an open warning on the Security tab, with the log line")


def test_a_login_without_access_is_still_red():
    print("\n-- no Access in front (or not checkable): the 🔴 it always was --")
    from lanowl.seclog import SecLog
    a, sl = [], SecLog(FakeState())
    drive(watcher(a, agent=FakeAgent({"problem": False}), cfg=TUNNEL_CFG, seclog=sl,
                  access=access_says({"https": 200, "access_login": False})), [out([]), out(TUNNEL_LOGIN)])
    check(len(a) == 1 and "🔴" in a[0][0] and "NOT in front" in a[0][0] and "from the INTERNET" in a[0][0],
          "red, and it says Access is not in front")
    check(sl.view()["open"][0]["sev"] == "critical", "a critical item")
    a2 = []
    drive(watcher(a2, agent=FakeAgent({"problem": False}), cfg=TUNNEL_CFG,
                  access=access_says(TimeoutError("no answer"))), [out([]), out(TUNNEL_LOGIN)])
    check(len(a2) == 1 and "🔴" in a2[0][0] and "NOT in front" not in a2[0][0],
          "a check that got no answer is red too, without claiming what it could not see")


def test_a_second_login_the_same_day_is_counted_not_paged():
    print("\n-- once a day on Telegram; every login still counted on the open row --")
    from lanowl.seclog import SecLog
    a, sl = [], SecLog(FakeState())
    again = [TUNNEL_LOGIN[0].replace("48110", "48200")]
    drive(watcher(a, agent=FakeAgent({"problem": False}), cfg=TUNNEL_CFG, seclog=sl,
                  access=access_says({"https": 302, "access_login": True})),
          [out([]), out(TUNNEL_LOGIN), out(again)])
    it = sl.view()["open"]
    check(len(a) == 1, f"one message (got {len(a)})")
    check(len(it) == 1 and it[0]["count"] == 2 and it[0]["paged"] is True, "one row, counting 2")
    sl.handle(it[0]["id"], "me")
    w = watcher(a, agent=FakeAgent({"problem": False}), cfg=TUNNEL_CFG, seclog=sl,
                access=access_says({"https": 302, "access_login": True}))
    w.hosts[0].logins_told["127.0.0.1"] = time.time()
    drive(w, [out([]), out(again)])
    v = sl.view()
    check(len(a) == 1 and len(v["open"]) == 1 and v["open"][0]["paged"] is False
          and len(v["handled"]) == 1,
          "after the owner handled it, the next login is a new row — not paged, and saying so")


def test_one_login_one_message():
    """One login, one message: not the rule's 🔴 and the model's 🟡 about the same line, seconds apart."""
    print("\n-- the model's read of lines a rule paged for goes on the rule's row --")
    from lanowl.seclog import SecLog
    long = "sshd accepted a password authentication for pi through the tunnel. " * 8
    a, sl = [], SecLog(FakeState())
    ag = FakeAgent({"problem": True, "kind": "security", "severity": "warning",
                    "summary": "Password login for pi through the tunnel", "detail": long})
    w = drive(watcher(a, agent=ag, cfg=TUNNEL_CFG, seclog=sl,
                      access=access_says({"https": 302, "access_login": True})),
              [out([]), out(TUNNEL_LOGIN + TUNNEL_CLOSED)])
    it = sl.view()["open"]
    check(len(ag.asks) == 1, "the model was still asked")
    check(len(a) == 1 and "CLOUDFLARE ACCESS" in a[0][0], f"ONE message, the rule's (got {len(a)})")
    check(len(it) == 1 and it[0]["model"] and it[0]["model"]["summary"].startswith("Password login"),
          "the model's words are on the rule's row")
    check(it[0]["model"]["detail"] == long.strip() and w.findings[-1]["detail"].strip() == long.strip(),
          "whole, not cut at 300 characters")
    a2, sl2 = [], SecLog(FakeState())
    ag2 = FakeAgent({"problem": True, "kind": "security", "severity": "critical",
                     "summary": "a login and then a new user", "detail": "useradd right after"})
    drive(watcher(a2, agent=ag2, cfg=TUNNEL_CFG, seclog=sl2,
                  access=access_says({"https": 302, "access_login": True})), [out([]), out(TUNNEL_LOGIN)])
    check(len(a2) == 2 and "HOST LOG" in a2[1][0] and sl2.view()["open"][0]["sev"] == "critical",
          "a verdict WORSE than the rule's page is sent as well, and the row turns critical")


def test_the_burst_is_on_the_security_tab():
    print("\n-- a burst of failed logins: a critical row, the model's read attached --")
    from lanowl.seclog import SecLog
    a, sl = [], SecLog(FakeState())
    ag = FakeAgent({"problem": True, "kind": "security", "severity": "warning", "summary": "guessing drill"})
    fails = [f"2026-09-28T10:1{i % 10}:00+02:00 homehub sshd[{i}]: Connection closed by invalid "
             f"user drill 192.168.10.103 port {40000 + i} [preauth]" for i in range(10)]
    drive(watcher(a, agent=ag, seclog=sl), [out([]), out(fails)])
    it = sl.view()["open"]
    check(len(a) == 1 and "FAILED LOGINS" in a[0][0], f"one page (got {len(a)})")
    check(len(it) == 1 and it[0]["sev"] == "critical" and "10 failed logins from 192.168.10.103" in it[0]["title"]
          and "drill" in it[0]["title"], "a critical row: how many, from where, which user")
    check(it[0]["model"] is not None, "the model's read is on it, not a second message")


def test_the_models_own_find_is_a_row_health_is_not():
    print("\n-- the model's security find is a row; a health problem stays in Log checks --")
    from lanowl.seclog import SecLog
    odd = ["2026-09-03T03:14:00+02:00 homehub sudo: pi : TTY=pts/1 ; PWD=/home/pi ; "
           "USER=root ; COMMAND=/usr/sbin/useradd -m backdoor"]
    a, sl = [], SecLog(FakeState())
    drive(watcher(a, agent=FakeAgent({"problem": True, "kind": "security", "severity": "critical",
                                      "summary": "a user was added", "detail": "useradd backdoor"}),
                  seclog=sl), [out([]), out(odd)])
    it = sl.view()["open"]
    check(len(a) == 1 and len(it) == 1 and it[0]["by"] == "model" and it[0]["sev"] == "critical",
          "paged, and a critical row by the model")
    a2, sl2 = [], SecLog(FakeState())
    drive(watcher(a2, agent=FakeAgent({"problem": True, "kind": "health", "severity": "warning",
                                       "summary": "disk errors"}), seclog=sl2), [out([]), out(odd)])
    check(len(a2) == 1 and sl2.view()["open"] == [], "a health problem pages but is not a security row")


def test_the_auditors_own_sudo_is_said():
    print("\n-- lanowl's own sudo is told to the triage, with its time --")
    a, ag = [], FakeAgent({"problem": False})
    w = watcher(a, agent=ag)
    now = time.time()
    w.note_own("192.168.10.113", now - 30, now - 10, "its daily security review (a read-only script, via sudo)")
    w.note_own("192.168.10.1", now - 30, now - 10, "not watched: ignored")
    sudo = ["2026-09-27T06:35:00+02:00 homehub sudo[5]: pi : PWD=/home/pi ; USER=root ; COMMAND=/usr/bin/sh -c x"]
    drive(w, [out([]), out(sudo)])
    check(len(ag.asks) == 1 and "THE AUDITOR ITSELF" in ag.asks[0] and "security review" in ag.asks[0]
          and "anything else is not" in ag.asks[0], "the triage is told when and what, and still judges")
    w.hosts[0].own_runs = [(now - 9000, now - 8000, "old")]
    check("THE AUDITOR ITSELF" not in w._context(w.hosts[0]), "a run two hours old is not mentioned")


def test_disabled_does_nothing():
    print("\n-- the whole thing is one switch --")
    cfg = {**CFG, "hostlog": {**CFG["hostlog"], "enabled": False}}
    w = watcher([], agent=None, cfg=cfg)
    check(w.enabled is False, "hostlog.enabled=false disables it")
    asyncio.run(w.run())
    check(True, "and run() returns immediately")


if __name__ == "__main__":
    for fn in [test_priming_skips_history,
               test_routine_chatter_is_not_triaged,
               test_our_own_poll_is_noise_but_others_are_not,
               test_burst_pages_without_the_model,
               test_burst_does_not_add_up_across_sources,
               test_a_hammering_scanner_still_costs_one_message,
               test_triage_reports_a_real_problem,
               test_triage_no_problem_stays_silent,
               test_info_verdicts_are_not_sent,
               test_the_same_condition_does_not_repeat,
               test_triage_defers_to_a_running_audit,
               test_burst_fires_even_while_the_model_is_busy,
               test_connection_ceiling_needs_two_polls,
               test_quiet_polls_are_not_new_lines,
               test_an_unreachable_host_is_a_status_not_an_alert,
               test_the_wan_context_reaches_the_prompt,
               test_a_login_through_the_tunnel_pages,
               test_a_login_past_cloudflare_access_is_yellow,
               test_a_login_without_access_is_still_red,
               test_a_second_login_the_same_day_is_counted_not_paged,
               test_one_login_one_message,
               test_the_burst_is_on_the_security_tab,
               test_the_models_own_find_is_a_row_health_is_not,
               test_the_auditors_own_sudo_is_said,
               test_disabled_does_nothing]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all host-log tests passed")
