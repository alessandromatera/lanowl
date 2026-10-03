"""The model's own looks, its fixes and its track record: `python -m tests.test_reviews`.

No network, no model, no Telegram — ssh and the model are fakes. Pinned down here:

  1. a look runs daily at its time or every N hours, never twice, never in the first ten
     minutes after a start (the every-N ones);
  2. findings are held to the rules: a known check (else "other"), no "critical" (they never
     page), an anchor the facts know, one per key — the worst;
  3. a dismissal holds until undone or the problem is gone three runs in a row;
  4. drift: a week of samples per device and per day, the hours its misses fall in, devices
     asleep by design marked, paused ones left out; the model's findings keyed by device — and
     only meaningful ones: no latency alone, nothing better, nothing "info", and
     what it names must hold in the device's own numbers;
  5. configurations: the first look is the baseline; a change is the model's words held to the
     diff (a quote not in it is dropped, "none" where access lives becomes "low"), and a change
     where access is decided that the model left out is listed anyway; a risky one is a security
     event; no model = the rule alone; lanowl's own sudo is told to the log triage;
     nftables' counters and an interface the router's own netwatch toggles are not changes,
     nor is a snapshot kept before the cleaner learned that; an unusable answer is asked again;
  6. the digest: what is new rides ONE digest — even on a healthy network — and never twice;
     Slowly changing's only when "high";
  7. fixes: written for the morning review's open findings, not again for the same words;
     nothing to write with the model off;
  8. the scorecard: one claim per problem episode, closed an hour after nobody raises it,
     graded half an hour later; the owner's word beats the grader's;
  9. the records tool reads all of it.

"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import configwatch as C
from lanowl import scorecard as SC
from lanowl.report import format_digest
from lanowl.reviews import today_at
from tests.test_reboot import _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _run(go):
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))


def _report(issues=None):
    return {"overall_health": "ok" if not issues else "warning", "issues": issues or [],
            "counts": {"up": 9, "total": 9}, "wan_ok": True, "wan_state": "ok"}


# --- 1. when ----------------------------------------------------------------------------------
def test_due():
    print("\n-- 1. daily at its time, or every N hours; never twice --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        r = a.drift
        r.enabled, r.at = True, "07:15"
        at = today_at("07:15", time.time())
        out["before"] = r.due(at - 60)
        out["after"] = r.due(at + 60)
        r.rec["last"] = at + 30
        out["done"] = r.due(at + 600)
        h = a.drift                 # the every-N-hours shape
        h.rec["last"], h.every_s = 0.0, 6 * 3600
        a._started = time.time()
        out["fresh_start"] = h.due(time.time())
        a._started = time.time() - 3600
        out["every"] = h.due(time.time())
        h.rec["last"] = time.time() - 3600
        out["recent"] = h.due(time.time())
        cw = a.configwatch
        cw.enabled = True
        a.updates.enabled, a.updates.at = True, "06:30"
        t = today_at("06:30", time.time()) + 3600
        a.updates.rec["last_done"] = t - 86400
        out["cw_before_updates"] = cw.due(t)
        a.updates.rec["last_done"] = t - 1800
        out["cw_after_updates"] = cw.due(t)
    _run(go)
    check(not out["before"] and out["after"] and not out["done"], "daily: after its time, once")
    check(not out["fresh_start"] and out["every"] and not out["recent"],
          "every N hours: not in the first ten minutes after a start, not again within N hours")
    check(not out["cw_before_updates"] and out["cw_after_updates"],
          "the configuration look waits for the morning's update check, like the security review")


# --- 2-3. findings, dismissals ------------------------------------------------------------------
def test_findings_rules_and_dismissals():
    print("\n-- 2-3. findings held to the rules; dismissals --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        r = a.drift
        r.enabled = True
        facts = {"ips": {"192.168.10.57", "192.168.10.32"}}
        fs = r.normalise([
            {"ip": "192.168.10.57", "check": "losing_probes", "severity": "critical", "title": "pump worse"},
            {"ip": "192.168.10.57", "check": "losing_probes", "severity": "info", "title": "dup"},
            {"ip": "192.168.10.32", "check": "made_up", "severity": "loud", "title": "odd"},
            {"ip": "8.8.8.8", "check": "slower", "severity": "warning", "title": "not ours"},
            {"ip": "wan", "check": "internet", "severity": "warning", "title": "fiber worse"},
            "junk"], facts)
        out["keys"] = [f["key"] for f in fs]
        out["sev"] = {f["key"]: f["severity"] for f in fs}
        out["names"] = {f["key"]: (f.get("name"), f.get("ip")) for f in fs}
        r.keep(fs, "a week", "")
        out["news1"] = [k for k, _ in r.news()]
        r.mark_told([k for k, _ in r.news()])
        out["news2"] = r.news()
        out["dis"] = r.dismiss("drift:192.168.10.57:losing_probes", "pump moved")
        out["open"] = [f["key"] for f in r.open_findings()]
        for _ in range(2):
            r.keep([f for f in fs if f["anchor"] != "192.168.10.57"], "", "")
        out["held"] = "drift:192.168.10.57:losing_probes" in r.rec["dismissed"]
        r.keep([f for f in fs if f["anchor"] != "192.168.10.57"], "", "")
        out["forgotten"] = "drift:192.168.10.57:losing_probes" not in r.rec["dismissed"]
        r.keep(fs, "", "")
        out["news_back"] = [k for k, _ in r.news()]
        out["weekly"] = r.weekly_lines()
    _run(go)
    check(out["keys"] == ["drift:192.168.10.57:losing_probes", "drift:192.168.10.32:other", "drift:wan:internet"],
          f"one per key, the worst; unknown check -> other; a stranger dropped; the internet as 'wan' ({out['keys']})")
    check(out["sev"]["drift:192.168.10.57:losing_probes"] == "high" and out["sev"]["drift:192.168.10.32:other"] == "warning",
          "never 'critical' (these never page); an unknown severity -> warning")
    check(out["names"]["drift:192.168.10.57:losing_probes"] == ("Shelly pump", "192.168.10.57")
          and out["names"]["drift:wan:internet"][0] == "The internet", "each finding names its device")
    check(out["news1"] == ["drift:192.168.10.57:losing_probes"] and out["news2"] == [],
          "news once, and only the 'high' one: a told finding is not news again")
    check(out["dis"]["ok"] and "drift:192.168.10.57:losing_probes" not in out["open"], "a dismissed one leaves the open list")
    check(out["held"] and out["forgotten"], "a dismissal outlives two runs without it, is forgotten after three")
    check("drift:192.168.10.57:losing_probes" in out["news_back"], "gone and back: news again")
    check(out["weekly"] and "Slowly changing" in out["weekly"][0], "a line for the weekly review")


# --- 4. drift -----------------------------------------------------------------------------------
def test_drift_reads_the_week():
    print("\n-- 4. drift: the week per device and per day --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        r = a.drift
        r.enabled = True
        now = time.time()
        start = today_at("00:00", now) - 7 * 86400
        rows = []
        for day in range(8):
            for k in range(0, 1440, 10):            # every 10 minutes
                ts = start + day * 86400 + k * 60
                if ts > now:
                    break
                # the pump: always between 02:00 and 04:00 — a little at first, all of it lately
                hour = time.localtime(ts).tm_hour
                up = 0 if (hour == 2 and k % 30 == 0) or (day >= 5 and hour in (2, 3)) else 1
                rows.append((ts, "192.168.10.57", up, 40.0 + day * 10, None))
                rows.append((ts, "192.168.10.32", 1, 5.0, None))
                rows.append((ts, "192.168.10.46", 1, 9.0, None))
        a.state.conn.executemany("INSERT INTO samples(ts, ip, up, latency, services) VALUES (?,?,?,?,?)", rows)
        a.state.conn.execute("INSERT INTO transitions(ts, ip, kind, detail) VALUES (?,?,?,?)",
                             (start + 3 * 86400 + 7200, "192.168.10.57", "down", "Shelly pump"))
        a.state.commit()
        a.inv.get("192.168.10.32").attrs["expect_offline"] = "sun"
        a._emit_telegram = lambda *x, **k: None
        a.set_paused("192.168.10.46", True, "dashboard")
        seen = []

        async def ask_json(system, ctx, timeout_s=None):
            seen.append(ctx)
            return {"summary": "The pump is slipping, the AP slower, the cleaner better.", "findings": [
                {"ip": "192.168.10.57", "check": "time_of_day", "severity": "high", "title": "pump drops at 02:00",
                 "evidence": "missed 0 → 2.4%"},
                {"ip": "192.168.10.32", "check": "slower", "severity": "warning", "title": "AP latency doubling"},
                {"ip": "192.168.10.32", "check": "losing_probes", "severity": "warning", "title": "AP losing probes"},
                {"ip": "192.168.10.57", "check": "other", "severity": "info", "title": "pump fine otherwise"},
                {"ip": "192.168.10.32", "check": "better", "severity": "info", "title": "AP recovered"}]}
        a.agent.ask_json = ask_json
        out["fs"] = await r.run("test")
        out["summary"] = r.rec["summary"]
        out["ctx"] = seen[0] if seen else ""
        a._model_off = {"since": now, "by": "dashboard"}
        seen.clear()
        await r.run("test")
        out["off"] = (seen, r.rec["error"], [f["key"] for f in r.rec["findings"]])
    _run(go)
    ctx = out["ctx"]
    check("Shelly pump (192.168.10.57)" in ctx and "probes missed %:" in ctx and "latency mean ms:" in ctx,
          "each device, per day: probes missed, latency")
    check("02h" in ctx.split("Shelly pump")[1].split("\n\n")[0], "the hours its misses fall in")
    check("asleep by design: at night" in ctx, "a device asleep by design is marked")
    check("Shelly kitchen-table (192.168.10.46)" not in ctx and "Paused by the owner" in ctx,
          "a paused device is left out, and said to be")
    check("went down: " in ctx and "THE INTERNET, per day:" in ctx, "outages per day, the internet per day")
    check([f["key"] for f in out["fs"]] == ["drift:192.168.10.57:time_of_day"],
          "the model's finding, keyed by device — latency alone, 'better', 'info' and a finding its "
          "device's own numbers do not bear out are dropped")
    check(out["summary"] == "pump drops at 02:00", f"the summary: what stood, not the model's sentence about the rest ({out['summary']!r})")
    from lanowl.drift import Drift as D
    st = {"miss": [0.1, 0.2, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6], "down": [0] * 8, "svc": [0] * 8}
    check(not D.holds({"anchor": "1"}, {"stats": {"1": st}}), "0.1% → 0.6%: under 2% now — noise")
    st = {"miss": [1.0, 1.2, 0.9, 1.1, 1.5, 2.0, 2.5, 2.4], "down": [0] * 8, "svc": [0] * 8}
    check(not D.holds({"anchor": "1"}, {"stats": {"1": st}}), "1% → 2.5%: not three times its start")
    st = {"miss": [0.3, 0.2, 0.4, 0.3, 1.0, 2.5, 4.0, 3.1], "down": [0] * 8, "svc": [0] * 8}
    check(D.holds({"anchor": "1"}, {"stats": {"1": st}}), "0.3% → 4%: failing now, ten times its start")
    st = {"miss": [0.0] * 8, "down": [0, 0, 0, 0, 0, 1, 1, 2], "svc": [0] * 8}
    check(D.holds({"anchor": "1"}, {"stats": {"1": st}}), "down 3 times in two days, never before")
    check(D.holds({"anchor": "wan"}, {"internet_n": [0, 1, 0, 1, 0, 2, 2, 1]})
          and not D.holds({"anchor": "wan"}, {"internet_n": [2, 2, 1, 2, 0, 1, 1, 1]})
          and not D.holds({"anchor": "wan"}, {"internet_n": [None] * 5 + [2, 2, 1]}),
          "the internet: more drops in three days than in the four before; unknown is not zero")
    seen, err, keys = out["off"]
    check(seen == [] and "switched off" in err and keys == ["drift:192.168.10.57:time_of_day"],
          "model off: nothing asked, the last findings kept, and why")


# --- 6. configurations ------------------------------------------------------------------------------
EXPORT1 = """# 2026-10-01 06:30:00 by RouterOS 7.20
# software id = ABCD-1234
#
/interface bridge add name=bridge
/ip firewall filter add action=accept chain=input connection-state=established
/ip firewall filter add action=drop chain=input in-interface=ether1
/ip dhcp-server lease add address=192.168.10.59 mac-address=AA:BB:CC:00:00:01
/system identity set name=Router
"""
EXPORT2 = EXPORT1.replace("# 2026-10-01 06:30:00", "# 2026-10-02 06:30:00") \
    .replace("/ip firewall filter add action=drop chain=input in-interface=ether1\n",
             "/ip firewall filter add action=accept chain=input dst-port=8291 protocol=tcp\n"
             "/ip firewall filter add action=drop chain=input in-interface=ether1\n") \
    .replace("/system identity set name=Router", "/system identity set name=Home") \
    + "/user add group=full name=guest\n"
LINUX1 = "== sshd (effective settings)\npasswordauthentication no\n== crontabs\nroot: 0 3 * * * /backup.sh\n"
LINUX2 = "== sshd (effective settings)\npasswordauthentication yes\n== crontabs\nroot: 0 3 * * * /backup.sh\n"


ANTENNA_ON = """/interface wireless set [ find default-name=wlan1 ] band=5ghz-a/n disabled=no frequency=5640 ssid=RadioISP_46
/interface wireless set [ find default-name=wlan2 ] disabled=no ssid=other
/tool netwatch add comment="Connect to wlan1 if ADSL is down" disabled=no down-script="/interface wireless enable wlan1" host=192.168.88.1 interval=10s timeout=1s type=simple up-script="/interface wireless disable wlan1"
"""
NFT1 = "== firewall\n\t\tiifname \"tailscale0\" counter packets 333466 bytes 24171985 accept\n"
NFT2 = "== firewall\n\t\tiifname \"tailscale0\" counter packets 972586 bytes 59933497 accept\n"


def test_config_noise():
    print("\n-- 6c. a snapshot kept before the cleaner knew is cleaned again; an unusable answer is asked twice --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        cw = a.configwatch
        cw.enabled = True
        cw.machines = [{"ip": "192.168.20.1", "via": "routeros"}, {"ip": "192.168.10.113", "via": "sudo"}]
        # this morning's snapshots, from before the counters and the toggle were known
        cw.rec["snap"] = {"192.168.20.1": {"text": ANTENNA_ON.strip(), "ts": 1.0, "kind": "routeros"},
                          "192.168.10.113": {"text": NFT1.strip(), "ts": 1.0, "kind": "linux"}}
        texts = {"192.168.20.1": ANTENNA_ON.replace(" disabled=no frequency", " frequency"), "192.168.10.113": NFT2}

        async def ssh(ip, remote, **kw):
            if remote == "/system resource print":
                return 0, "  version: 7.20 (stable)\n", ""
            return 0, texts[ip], ""
        a.access.ssh = ssh
        a.hostlog.note_own = lambda *x: None
        asked = []

        async def ask_json(system, ctx, timeout_s=None):
            asked.append(ctx)
            return None
        a.agent.ask_json = ask_json
        out["quiet"] = await cw.run("test")
        out["asked_quiet"] = len(asked)
        texts["192.168.10.113"] = NFT2 + "\t\ttcp dport 22 accept\n"
        out["real"] = await cw.run("test")
        out["asked"] = len(asked)
    _run(go)
    check(out["quiet"] == [] and out["asked_quiet"] == 0,
          "yesterday's snapshot with its counters and its Wi-Fi state, today's without: nothing changed")
    check(len(out["real"]) == 1 and out["real"][0]["by"] == "rule" and out["asked"] == 2,
          "a real firewall change: the model asked twice when its answer was unusable, then the rule's reading")


def test_config_changes():
    print("\n-- 6. what changed in the configurations --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        cw = a.configwatch
        cw.enabled = True
        cw.machines = [{"ip": "192.168.20.1", "via": "routeros"}, {"ip": "192.168.10.113", "via": "sudo"}]
        texts = {"192.168.20.1": EXPORT1, "192.168.10.113": LINUX1}
        calls = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            calls.append((ip, remote, sudo_pw))
            if remote == "/system resource print":
                return 0, "  version: 7.20 (stable)\n", ""
            return 0, texts[ip], ""
        a.access.ssh = ssh
        own = []
        a.hostlog.note_own = lambda ip, s, e, what: own.append((ip, what))
        asked = []

        async def nothing(system, ctx, timeout_s=None):
            asked.append(ctx)
            return None
        a.agent.ask_json = nothing
        out["first"] = await cw.run("test")
        out["first_asked"] = list(asked)
        out["calls"] = list(calls)
        out["own"] = list(own)
        texts.update({"192.168.20.1": EXPORT2, "192.168.10.113": LINUX2})

        async def judge(system, ctx, timeout_s=None):
            asked.append(ctx)
            return {"summary": "winbox opened, a user added.", "changes": [
                {"ip": "192.168.20.1", "what": "winbox (8291) accepted from anywhere", "risk": "critical",
                 "why": "management open", "lines": ["+/ip firewall filter add action=accept chain=input dst-port=8291 protocol=tcp"]},
                {"ip": "192.168.20.1", "what": "renamed", "risk": "none",
                 "lines": ["-/system identity set name=Router", "/system identity set name=Home"]},
                {"ip": "192.168.20.1", "what": "invented", "risk": "low", "lines": ["+/ip service set telnet disabled=no"]},
                {"ip": "192.168.10.113", "what": "a reorder", "risk": "none",
                 "lines": ["-passwordauthentication no", "+passwordauthentication yes"]},
                {"ip": "10.9.9.9", "what": "a stranger", "risk": "high", "lines": []}]}
        a.agent.ask_json = judge
        new = await cw.run("test")
        out["new"] = new
        out["ctx"] = asked[-1]
        out["seclog"] = [x["title"] for x in a.seclog.view()["open"]]
        out["news"] = [k for k, _ in cw.news()]
        cw.mark_told([k for k, _ in cw.news()])
        out["news2"] = cw.news()
        # no model: the rule alone
        texts["192.168.20.1"] = EXPORT2 + "/ip service set winbox address=0.0.0.0/0\n"
        a._model_off = {"since": time.time(), "by": "dashboard"}
        out["nomodel"] = await cw.run("test")
        out["view"] = cw.view()
    _run(go)
    check(out["first"] == [] and out["first_asked"] == [], "the first look is the baseline: nothing to say, nothing asked")
    check(any(c[1] == "/export terse" for c in out["calls"]) and
          any(c[0] == "192.168.10.113" and c[1].startswith("sudo -S") and c[2] for c in out["calls"]),
          "RouterOS: export terse (secrets hidden); the homehub: its login + sudo")
    check(("192.168.10.113", next(w for i, w in out["own"] if i == "192.168.10.113")) in out["own"]
          and "configuration snapshot" in out["own"][0][1], "its own sudo is told to the host-log triage")
    check("2026-10-02" not in out["ctx"] and "software id" not in out["ctx"], "the export's comment header never compares")
    by = {(c["ip"], c["what"]): c for c in out["new"]}
    w = by.get(("192.168.20.1", "winbox (8291) accepted from anywhere"))
    check(w is not None and w["risk"] == "critical" and w["lines"] and w["by"] == "model", "the model's words, its risk, its lines")
    check(by.get(("192.168.20.1", "invented"), {}).get("lines") == [], "a quoted line not in the diff is dropped")
    re_ = by.get(("192.168.10.113", "a reorder"))
    check(re_ is not None and re_["risk"] == "low", "'none' where access is decided becomes 'low'")
    check(not any(c["ip"] == "10.9.9.9" for c in out["new"]), "a machine that did not change is not taken from the model")
    ru = [c for c in out["new"] if c["by"] == "rule"]
    check(len(ru) == 1 and "/user" in ru[0]["sections"] and ru[0]["risk"] == "high" and "+/user add group=full name=guest" in ru[0]["lines"],
          f"a change where access lives that the model left out is listed by the rule ({[(c['what'], c['sections']) for c in ru]})")
    check(any("winbox" in t for t in out["seclog"]) and any("/user" in t for t in out["seclog"])
          and not any("renamed" in t for t in out["seclog"]), "risky ones are security events (Handled); a rename is not")
    check(len(out["news"]) == 2 and out["news2"] == [], "high and critical ride one digest, once")
    nm = out["nomodel"]
    check(len(nm) == 1 and nm[0]["by"] == "rule" and nm[0]["risk"] == "high" and "/ip service" in nm[0]["sections"],
          "no model: the rule's reading alone")
    v = out["view"]
    check(v["changes"][0]["ts"] >= v["changes"][-1]["ts"] and {m["ip"] for m in v["machines"]} == {"192.168.20.1", "192.168.10.113"},
          "the view: newest first, each machine read")


def test_clean_and_sections():
    print("\n-- 6b. exports compare cleanly; sections --")
    e = C.clean_export(EXPORT1 + "\n\n/ppp secret add name=x password=hunter2\n")
    check(not any(x.startswith("#") for x in e.splitlines()) and "hunter2" not in e,
          "no comment header, nothing password-shaped")
    check(C.section_of("/ip firewall filter add action=drop chain=input", "routeros") == "/ip firewall filter"
          and C.section_of("/system identity set name=x", "routeros") == "/system identity",
          "a RouterOS line's section is its own path")
    t = C.clean_export(ANTENNA_ON)
    check("disabled=" not in t.splitlines()[0] and "disabled=no" in t.splitlines()[1]
          and "disabled=no down-script" in t, "the antenna's wlan1, which its own netwatch switches, has no "
          "disabled= to compare; wlan2's and the netwatch's own stay")
    check(C.clean_export(ANTENNA_ON) == C.clean_export(ANTENNA_ON.replace(" disabled=no frequency", " frequency")),
          "its Wi-Fi on one morning and off the next is not a change")
    check(C.clean_linux(NFT1) == C.clean_linux(NFT2) and "counter accept" in C.clean_linux(NFT1),
          "nftables' packet counters are not a change; the rule still is")
    check(C.risky("/ip firewall filter", "routeros") and C.risky("/user", "routeros")
          and not C.risky("/ip dhcp-server lease", "routeros") and not C.risky("/user-manager", "routeros"),
          "risky RouterOS sections — by path, not by prefix of a word")
    d = C.diff(LINUX1, LINUX2, "linux")
    check(d == [("-", "passwordauthentication no", "sshd (effective settings)"),
                ("+", "passwordauthentication yes", "sshd (effective settings)")], f"a Linux line's section is its header ({d})")


# --- 7. the digest ---------------------------------------------------------------------------------
def test_digest_carries_news_once():
    print("\n-- 7. the digest: news once, even on a healthy network --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        sent = []
        a._emit_telegram = lambda ch, text, **kw: sent.append((ch, text))
        r = a.drift
        r.enabled = True
        r.keep(r.normalise([{"ip": "192.168.10.32", "check": "losing_probes", "severity": "warning",
                             "title": "the AP misses a little more"}], {"ips": {"192.168.10.32"}}), "", "")
        a._last_report = _report()
        out["d0"] = a._maybe_send_digest(_report(), "scheduled")
        r.keep(r.normalise([{"ip": "192.168.10.57", "check": "losing_probes", "severity": "high",
                             "title": "the pump misses more every day", "evidence": "0.4 → 6 %"}],
                            {"ips": {"192.168.10.57"}}), "", "")
        out["d1"] = a._maybe_send_digest(_report(), "scheduled")
        out["d2"] = a._maybe_send_digest(_report(), "scheduled")
        out["sent"] = sent
        out["trend_ips"] = a.drift.ips()
    _run(go)
    check(out["d0"].startswith("held back"), f"Slowly changing's 'warning' sends nothing ({out['d0']!r})")
    check(out["d1"].startswith("sent: 1 new from the model's reviews") and out["d2"].startswith("held back"),
          f"healthy network, new finding: one digest, then nothing ({out['d1']!r}, {out['d2']!r})")
    text = out["sent"][0][1] if out["sent"] else ""
    check("Slowly changing" in text and "the pump misses more every day" in text and "Shelly pump" in text,
          "the digest says it, with the device's name and address")
    check(out["trend_ips"] == {"192.168.10.57"}, "the thresholds' own trend line steps aside for the model's")
    t = format_digest({**_report(), "review_news": [{"title": "What changed", "icon": "🛠️",
                                                     "lines": [f"• x{i}" for i in range(7)]}]})
    check("…and 2 more on the dashboard" in t, "at most five lines per look in a digest")


# --- 8. fixes ----------------------------------------------------------------------------------------
def test_fixes():
    print("\n-- 8. fixes: written out, never run --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        x = a.exposure
        x.rec["findings"] = [
            {"key": "exp:203.0.113.10:ssh_password_login", "ip": "203.0.113.10", "check": "ssh_password_login",
             "severity": "high", "name": "VPS", "title": "ssh accepts passwords", "evidence": "passwordauthentication yes",
             "fix": "keys only"},
            {"key": "exp:192.168.10.35:other", "ip": "192.168.10.35", "check": "other", "severity": "info",
             "name": "AirPrint", "title": "minor", "evidence": "x", "fix": ""},
            {"key": "exp:192.168.10.113:upnp", "ip": "192.168.10.113", "check": "upnp", "severity": "warning",
             "name": "HS", "title": "upnp", "evidence": "y", "fix": ""}]
        x.rec["dismissed"] = {"exp:192.168.10.113:upnp": {"ts": 1, "note": "", "missed": 0}}
        x.rec["facts"] = {"203.0.113.10": {"ok": True, "text": "Ubuntu 24.04.1 LTS\npasswordauthentication yes"}}
        seen = []

        async def ask_json(system, ctx, timeout_s=None):
            seen.append((system, ctx))
            return {"summary": "keys only on the VPS", "steps": [
                {"where": "VPS, root shell", "do": "prove a key login first", "commands": "ssh -o PubkeyAuthentication=yes root@203.0.113.10 true"},
                {"where": "VPS", "do": "turn passwords off", "commands": "echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-keys.conf\nsystemctl reload ssh"},
                "junk"], "undo": "rm /etc/ssh/sshd_config.d/10-keys.conf; systemctl reload ssh",
                "check": "sshd -T | grep passwordauthentication", "careful": "keep this session open"}
        a.agent.ask_json = ask_json
        a.fixes.after_review()
        await a.fixes._task
        out["seen"] = list(seen)
        out["items"] = dict(a.fixes.rec["items"])
        seen.clear()
        a.fixes.after_review()                 # the same words: nothing to write again
        await asyncio.sleep(0)
        out["again"] = list(seen)
        x.rec["findings"][0]["evidence"] = "passwordauthentication yes; permitrootlogin yes"
        out["stale"] = a.fixes.view()["items"]["exp:203.0.113.10:ssh_password_login"]["stale"]
        a._model_off = {"since": time.time(), "by": "dashboard"}
        out["off"] = a.fixes.start("exp:203.0.113.10:ssh_password_login")
        out["nokey"] = a.fixes.start("exp:1.2.3.4:none")
    _run(go)
    check(len(out["seen"]) == 1 and "Ubuntu 24.04.1" in out["seen"][0][1] and "NEVER LOCK THEM OUT" in out["seen"][0][0],
          "written for the open finding worth fixing, with its machine's own facts and the never-lock-out rule")
    it = out["items"].get("exp:203.0.113.10:ssh_password_login") or {}
    fx = it.get("fix") or {}
    check(it.get("status") == "ready" and len(fx.get("steps") or []) == 2 and fx.get("undo"),
          "stored: steps (junk dropped), undo, check")
    check(set(out["items"]) == {"exp:203.0.113.10:ssh_password_login"},
          "not for an 'info' finding, nor a dismissed one")
    check(out["again"] == [] and out["stale"], "not written again for the same words; marked stale when they change")
    check(not out["off"]["ok"] and "switched off" in out["off"]["error"] and not out["nokey"]["ok"],
          "the model off, or no such finding: nothing to write")


# --- 9. the scorecard ---------------------------------------------------------------------------------
def test_scorecard():
    print("\n-- 9. the scorecard: one claim per episode, graded with hindsight, the owner's word wins --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        s = a.scorecard
        t = time.time() - 5 * 3600
        lake = {"ip": "10.8.0.16", "device": "Lake router (10.8.0.16)", "severity": "warning",
                 "root_cause": "fault at Lake's power or ISP", "recommendation": "check power"}
        det = _report([{"ip": "10.8.0.16", "device": "Lake router", "kind": "down", "severity": "warning"}])
        s.note_audit({"issues": [lake, {"ip": "192.168.10.46", "severity": "info", "root_cause": "off"}]}, det, now=t)
        s.note_audit({"issues": [lake]}, det, now=t + 3600)
        s.note_audit({"issues": [{**lake, "root_cause": "its Wi-Fi uplink is stuck"}]}, det, now=t + 7200)
        out["claims"] = [dict(c) for c in s.rec["claims"]]
        s.note_audit({"issues": []}, det, now=t + 3 * 3600)          # the monitor still sees it
        out["still"] = s.rec["claims"][0]["open"]
        s.note_audit({"issues": []}, _report(), now=t + 3.5 * 3600)
        s.note_audit({"issues": []}, _report(), now=t + 4.6 * 3600)
        c = s.rec["claims"][0]
        out["closed"] = (c["open"], c["closed"])
        out["due_early"] = s.due_claim(c["closed"] + 600)
        out["due"] = s.due_claim(c["closed"] + SC.SETTLE_S + 1)
        a.state.record_transition(type("T", (), {"at": t - 60, "ip": "10.8.0.16", "kind": "down", "detail": "Lake router"})())
        a.state.commit()
        seen = []

        async def run_audit(system, ctx):
            seen.append(ctx)
            return {"verdict": "partly", "why": "the router was up, its uplink was not", "evidence": "watchdog log"}
        a.agent.run_audit = run_audit
        g = await s.grade(c["id"])
        out["grade"], out["ctx"] = g, seen[0]
        out["owner"] = s.owner_says(c["id"], "wrong", "it was the Wi-Fi uplink")
        out["final"] = s.final(c)
        out["totals"] = s.totals()
        out["bad"] = s.owner_says(c["id"], "maybe")

        async def nonsense(system, ctx):
            return {"verdict": "probably"}
        a.agent.run_audit = nonsense
        s.note_audit({"issues": [{**lake, "ip": "192.168.10.32", "device": "AP"}]}, _report(), now=t)
        c2 = next(x for x in s.rec["claims"] if x["ip"] == "192.168.10.32")
        await s.grade(c2["id"])
        out["failed"] = (c2.get("grade"), c2.get("grading_failed"))
        out["weekly"] = s.weekly_lines()
        out["records"] = a.records.call({"topic": "scorecard", "hours": 48})
    _run(go)
    cl = out["claims"]
    check(len(cl) == 1 and cl[0]["seen"] == 3 and cl[0]["kind"] == "down",
          "one claim per episode: re-stated hourly, an 'info' one not a claim; its kind from the monitor's issue")
    check(cl[0]["first"]["cause"] == "fault at Lake's power or ISP" and cl[0]["last"]["cause"] == "its Wi-Fi uplink is stuck",
          "its first words kept, and its last when it changed its mind")
    check(out["still"], "still open while the monitor sees the problem, even if the model stopped naming it")
    op, closed = out["closed"]
    check(not op and closed, "closed an hour after nobody raised it")
    check(out["due_early"] is None and out["due"] is not None, "graded half an hour after it closed, not before")
    check(out["grade"]["verdict"] == "partly" and "fault at Lake's power or ISP" in out["ctx"]
          and "its Wi-Fi uplink is stuck" in out["ctx"] and "ITS UPS AND DOWNS" in out["ctx"],
          "the grader reads what it said and what happened")
    check(out["owner"]["ok"] and out["final"] == "wrong", "the owner's word beats the grader's")
    t_ = out["totals"]["all"]
    check(t_["graded"] == 1 and t_["wrong"] == 1 and t_["owner_disagreed"] == 1 and "down" in out["totals"],
          "totals, by kind, with the owner's disagreements")
    check(not out["bad"]["ok"], "only right, partly, wrong or clear")
    check(out["failed"] == (None, 1), "a grade that is not one of the four is no grade")
    check(out["weekly"] and "1 wrong" in out["weekly"][0] and "you corrected 1" in out["weekly"][0], "a line for the weekly review")
    check("Lake router" in json.dumps(out["records"]), "Ask reads it")


# --- 10. the records ------------------------------------------------------------------------------------
def test_records_topics():
    print("\n-- 10. the records tool reads every look --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        for t in ("slow_changes", "config_changes", "fixes", "scorecard"):
            out[t] = a.records.call({"topic": t})
    _run(go)
    for t, r in out.items():
        check("records" in r and "error" not in r, f"topic {t}")


if __name__ == "__main__":
    os.environ.setdefault("TZ", "Europe/Berlin")
    time.tzset()
    test_due()
    test_findings_rules_and_dismissals()
    test_drift_reads_the_week()
    test_config_changes()
    test_clean_and_sections()
    test_config_noise()
    test_digest_carries_news_once()
    test_fixes()
    test_scorecard()
    test_records_topics()
    print(f"\n{'FAILED: ' + str(len(_fails)) if _fails else 'all passed'}")
    sys.exit(1 if _fails else 0)
