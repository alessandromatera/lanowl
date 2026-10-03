"""lanowl's own records, for the model: run with `python -m tests.test_records`.

No network, no model, no Telegram. Pinned down here (records.py):

  1. one tool, offered to every model turn with tools, dispatched by the executor;
  2. security: what matters, what the owner dismissed with their reason, UNKNOWN before the
     first check — and the one-line summary every question carries;
  3. updates: every package (name, new and installed version, security, held back), what
     asked for a pending reboot; a machine outside the check says what the check covers;
  4. device: the dashboard's whole sheet, its updates, paused or not — and never a login;
  5. actions: who asked (the owner or the model, and where), what became of it, why refused;
  6. telegram: every message with its text — the ones recorded before the text was kept
     are matched to the in-memory log, or say the text is gone;
  7. log checks: the verdicts that found NOTHING are there too, with the window's counts;
  8. audits: each verdict and what became of its digest (the digest decides in words);
     before the first record, UNKNOWN;
  9. lanowl's log: filtered by time, level and words, a traceback kept with its line,
     tokens and passwords scrubbed, and where the file starts;
 10. conversations from the dashboard and Telegram, searchable;
 11. the weekly review counts sends in both event formats; apt's installed version is read;
 12. a huge answer is cut, and says how to ask for less;
 13. a log verdict is labelled security or health (the model's word, or the source's
     default), and the page gets each machine's package list.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import records as RC
from lanowl import updates as U
from lanowl import weekly
from tests.test_reboot import PW, _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _run(go):
    """An Auditor needs a running loop: every test's body is `go(d)`, in its own directory."""
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))


async def _rec(a, **args):
    """The tool through the executor, as the model calls it; the JSON decoded."""
    r = await a.executor.call("lanowl_records", args)
    res = r.get("result") or {}
    return json.loads(res["records"]) if "records" in res else res


def _updates(a, now):
    u = a.updates
    u.enabled = True
    u.rec["last_done"] = now - 600
    u.rec["hosts"]["192.168.10.113"] = {
        "kind": "linux", "name": "VM HomeHub", "os": "Ubuntu 24.04.5 LTS", "ts": now - 600,
        "reboot_since": now - 5 * 86400, "reboot_pkgs": ["linux-image-6.8.0-142-generic"],
        "lists_ts": now - 3600,
        "updates": [{"pkg": "openssl", "version": "3.0.13-0ubuntu3.6", "from": "3.0.13-0ubuntu3.5",
                     "security": True},
                    {"pkg": "apparmor", "version": "4.0.1", "security": False, "phased": True}]}
    u.rec["hosts"]["192.168.20.1"] = {
        "kind": "routeros", "name": "Uplink MikroTik", "ts": now - 600, "installed": "6.49.12",
        "latest": "6.49.22", "channel": "long-term", "security_releases": ["6.49.19"],
        "fw": "6.49.12", "fw_new": "6.49.12"}
    u.rec["first_seen"]["192.168.10.113"] = {"openssl": now - 4 * 86400}
    u.rec["ports"] = {"192.168.10.57": [23]}


# --- 1. the tool ----------------------------------------------------------------------------
def test_offered_and_dispatched():
    print("\n-- one tool, offered to every model turn with tools --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        names = lambda: [t["function"]["name"] for t in a.executor.tool_specs()]  # noqa: E731
        out["outside"] = names()
        with a.actions.source("audit"):
            out["audit"] = names()
        out["spec"] = next(t for t in a.executor.tool_specs()
                           if t["function"]["name"] == "lanowl_records")
        out["bad"] = await a.executor.call("lanowl_records", {"topic": "passwords"})
    _run(go)
    check("lanowl_records" in out["outside"] and "lanowl_records" in out["audit"],
          "offered outside a proposing turn and in the audit")
    desc = out["spec"]["function"]["description"]
    check(all(k in desc for k in RC.TOPICS) and "never say you do not know" in desc,
          "every topic is spelt out in the description")
    err = out["bad"]["result"]["error"]
    check("unknown topic" in err and "security" in err, "an unknown topic says which exist")


# --- 2. security --------------------------------------------------------------------------
def test_security():
    print("\n-- security: what matters, what was dismissed and why, UNKNOWN before the check --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        a.updates.enabled = True
        out["never"] = await _rec(a, topic="security")
        out["line_never"] = a.records.security_line()
        _updates(a, time.time())
        out["dis"] = a.updates.dismiss("port:192.168.10.57:23", "the pump's Shelly cannot turn telnet off")
        out["sec"] = await _rec(a, topic="security")
        out["line"] = a.records.security_line()
    _run(go)
    check("UNKNOWN" in str(out["never"]["updates"]) and "not run yet" in out["line_never"],
          "before the first check: UNKNOWN, not 'nothing'")
    s = out["sec"]
    check(any("openssl" in x for x in s["what_matters"]) and any("reboot" in x for x in s["what_matters"]),
          f"what matters: the security update and the reboot ({s['what_matters']})")
    dis = s["dismissed_by_the_owner"]
    check(out["dis"].get("ok") and len(dis) == 1
          and dis[0]["his_reason"] == "the pump's Shelly cannot turn telnet off",
          f"the dismissed finding with the owner's reason ({dis})")
    check(any(x["machine"] == "VM HomeHub (192.168.10.113)" and x.get("reboot_pending_since")
              for x in s["machines"]), "each machine named and addressed, with its pending reboot")
    ln = out["line"]
    check(ln.startswith("SECURITY (checked") and "openssl" in ln and "1 finding(s) dismissed" in ln
          and "lanowl_records" in ln, f"the one line every question carries: {ln!r}")


# --- 3. updates -----------------------------------------------------------------------------
def test_updates():
    print("\n-- updates: every package, and what asked for the reboot --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _updates(a, time.time())
        out["one"] = await _rec(a, topic="updates", ip="192.168.10.113")
        out["all"] = await _rec(a, topic="updates")
        out["none"] = await _rec(a, topic="updates", ip="192.168.10.32")
    _run(go)
    one = out["one"]
    pk = {p["package"]: p for p in one["packages_waiting"]}
    check(pk["openssl"] == {"package": "openssl", "new_version": "3.0.13-0ubuntu3.6",
                            "installed": "3.0.13-0ubuntu3.5", "security": True},
          f"a package with both versions and its security flag ({pk['openssl']})")
    check(pk["apparmor"].get("held_back_by_ubuntu") is True, "a phased one is said held back")
    check(one["reboot_asked_by"] == ["linux-image-6.8.0-142-generic"] and one["reboot_pending_since"],
          "the pending reboot, since when and what asked for it")
    ros = next(x for x in out["all"]["machines"] if x["kind"] == "routeros")
    check(ros["routeros_installed"] == "6.49.12" and ros["latest"] == "6.49.22"
          and ros["security_releases_in_between"] == ["6.49.19"],
          "RouterOS: installed, latest, the security releases in between")
    check("not in the update check" in out["none"] and "VM HomeHub" in out["none"],
          "a machine outside the check says what the check covers")


# --- 4. device ----------------------------------------------------------------------------------
def test_device_never_a_login():
    print("\n-- device: the whole sheet, its updates, paused — and never a login --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _updates(a, time.time())
        a.pauses.pause("192.168.10.113", "VM HomeHub", "the owner on the dashboard")
        out["d"] = await _rec(a, topic="device", ip="192.168.10.113")
        out["ap"] = await _rec(a, topic="device", ip="192.168.10.32")
        out["nope"] = await _rec(a, topic="device", ip="192.168.10.250")
        out["missing"] = await _rec(a, topic="device")
    _run(go)
    dv = out["d"]
    check(dv["name"] == "VM HomeHub" and dv["updates"]["packages_waiting"]
          and dv["paused"]["by"] == "the owner on the dashboard", "the sheet, its updates, its pause")
    blob = json.dumps(out, ensure_ascii=False)
    check(PW not in blob and "ant$1" not in blob and "WIFI: x" not in blob,
          "no password and no logins.tsv note anywhere")
    check(out["ap"]["login_known"] is True and "reboot" in out["ap"], "only whether a login is known")
    check("not in the inventory" in json.dumps(out["nope"]) and "needs ip" in json.dumps(out["missing"]),
          "an unknown address, and a missing one, are said so")


# --- 5. actions --------------------------------------------------------------------------------
def test_actions():
    print("\n-- actions: who asked, what became of it, why refused --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        a.actions.items += [
            {"id": 1, "action": "reboot", "ip": "192.168.10.32", "name": "AP-Porch", "via": "dashboard",
             "owner": True, "status": "done", "ts": now - 3600, "done_ts": now - 3500, "args": {},
             "decided_by": "dashboard", "decided_ts": now - 3590,
             "outcome": {"ran": True, "result": "back after 62 s"}},
            {"id": 2, "action": "shelly_reboot", "ip": "192.168.10.57", "name": "Shelly pump",
             "via": "audit", "status": "refused", "ts": now - 1800, "args": {},
             "reason": "answers ping, not HTTP", "refused": "unsafe: relay 0 would come back OFF"},
            {"id": 3, "action": "nmap_scan", "ip": "192.168.10.113", "name": "VM HomeHub",
             "via": "telegram", "status": "rejected", "ts": now - 5 * 86400, "args": {},
             "decided_by": "telegram", "decided_ts": now - 5 * 86400 + 60}]
        out["r"] = await _rec(a, topic="actions")
        out["one"] = await _rec(a, topic="actions", ip="192.168.10.57")
        out["old"] = await _rec(a, topic="actions", hours=24 * 7)
    _run(go)
    acts = {x["id"]: x for x in out["r"]["actions"]}
    check(set(acts) == {1, 2}, "the window: 48 hours by default")
    check(acts[1]["asked_by"] == "the owner, on dashboard" and acts[1]["result"] == "back after 62 s"
          and acts[1]["device"] == "AP-Porch (192.168.10.32)",
          "the owner's press, its result, the device named and addressed")
    check(acts[2]["asked_by"] == "the model, in the hourly audit"
          and acts[2]["refused_because"].startswith("unsafe"), "the model's proposal and why it was refused")
    check([x["id"] for x in out["one"]["actions"]] == [2], "one device's actions")
    check(any(x["id"] == 3 for x in out["old"]["actions"]) and out["old"]["record_starts"],
          "a longer window, and where the record starts")


# --- 6. telegram ------------------------------------------------------------------------------
def test_telegram():
    print("\n-- telegram: every message with its text --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        a.state.record_event("telegram", None, "critical", now - 7200)            # old format
        a._sent_log.append({"ts": now - 7200, "channel": "critical", "text": "🔴 <b>NVR</b> down"})
        a.state.record_event("telegram", None, "digest", now - 9000)              # old, text gone
        a._on_event("telegram", None, json.dumps({"channel": "digest",
                                                  "text": "📋 Weekly review: quiet"}), now - 60)
        out["r"] = await _rec(a, topic="telegram")
        out["s"] = await _rec(a, topic="telegram", search="weekly|nothing-else")
    _run(go)
    msgs = out["r"]["messages"]
    texts = [x["text"] for x in msgs]
    check(texts[0] == "📋 Weekly review: quiet" and msgs[0]["channel"] == "digest",
          "the newest first, with its text and channel")
    check("🔴 NVR down" in texts, "an old-format row gets its text back from the in-memory log, tags removed")
    check("(its text was not kept)" in texts, "...or says the text is gone")
    check(len(out["s"]["messages"]) == 1, "search, with '|' alternatives")


# --- 7. log checks ------------------------------------------------------------------------------
def test_log_checks():
    print("\n-- log checks: the verdicts that found nothing are there too --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        for i, (prob, summ) in enumerate([(False, "Acme tunnel re-established"),
                                          (True, "root login from 45.1.2.3"),
                                          (False, "cron noise")]):
            a.state.record_event("finding", None, json.dumps(
                {"source": "host log VPS", "lines": 1, "problem": prob,
                 "severity": "critical" if prob else "info", "summary": summ}), now - 600 * (i + 1))
        out["r"] = await _rec(a, topic="log_checks")
        out["s"] = await _rec(a, topic="log_checks", search="acme")
    _run(go)
    r, s = out["r"], out["s"]
    check(len(r["verdicts"]) == 3 and r["in_window"] == {"total": 3, "problems": 1},
          "all three verdicts, and the counts of the window")
    check(r["verdicts"][0]["problem"] is False, "a 'nothing' verdict is a record too")
    check(len(s["verdicts"]) == 1 and s["in_window"]["total"] == 3, "search narrows the list, not the counts")


# --- 8. audits -----------------------------------------------------------------------------------
def test_audits_and_the_digest_decision():
    print("\n-- audits: each verdict and what became of its digest --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        out["empty"] = await _rec(a, topic="audits")
        healthy = {"overall_health": "ok", "issues": [], "summary": "all fine"}
        sick = {"overall_health": "degraded", "summary": "NVR down",
                "issues": [{"device": "NVR", "ip": "192.168.10.31", "severity": "critical",
                            "kind": "device", "group": "cameras"}]}
        a._send_digest = lambda rep, now, why: None
        out["d_healthy"] = a._maybe_send_digest(healthy, "scheduled")
        out["d_forced"] = a._maybe_send_digest(healthy, "check-now")
        a._digest_news = {a._key(sick["issues"][0])}
        out["d_new"] = a._maybe_send_digest(sick, "scheduled")
        a._digest_news = set()
        a._last_digest_sent = time.time()
        out["d_old"] = a._maybe_send_digest(sick, "scheduled")
        a._record_audit({"overall_health": "degraded", "summary": "NVR down",
                         "issues": [{"device": "NVR", "ip": "192.168.10.31", "severity": "critical",
                                     "root_cause": "PoE port lost power", "recommendation": "check"}]},
                        "scheduled", out["d_old"], 88.4)
        a._record_audit(None, "incident", "no digest: an incident's triage", 600)
        out["r"] = await _rec(a, topic="audits")
    _run(go)
    check("UNKNOWN before" in out["empty"]["note"], "no record yet: UNKNOWN, and where else to look")
    check(out["d_healthy"].startswith("held back: all healthy") and out["d_forced"].startswith("sent:")
          and out["d_new"] == "sent: 1 new issue(s)" and out["d_old"].startswith("held back: nothing new"),
          f"the digest says what it decided ({out['d_healthy']!r}, {out['d_old']!r})")
    au = out["r"]["audits"]
    check(len(au) == 2 and au[1]["digest"].startswith("held back: nothing new")
          and au[1]["issues"][0]["device"] == "NVR (192.168.10.31)"
          and au[1]["issues"][0]["cause"] == "PoE port lost power" and au[1]["secs"] == 88,
          "the verdict, its issues named and addressed, its digest decision")
    check("no assessment" in au[0]["result"], "an audit the model did not finish is recorded too")


# --- 9. lanowl's own log ---------------------------------------------------------------------
def test_auditor_log():
    print("\n-- lanowl's log: filtered, a traceback kept, secrets scrubbed --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        path = os.path.join(d, "lanowl.log")
        stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + ",123"  # noqa: E731
        with open(path, "w") as f:
            f.write(f"{stamp(now - 3 * 86400)} INFO auditor: Auditor started\n"
                    f"{stamp(now - 7200)} INFO auditor: all healthy — scheduled digest suppressed (no Telegram)\n"
                    f"{stamp(now - 3600)} ERROR auditor.sinks: send failed https://api.telegram.org/bot"
                    "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawx/sendMessage password=hunter2\n"
                    "Traceback (most recent call last):\n  File \"x.py\", line 1\n"
                    f"{stamp(now - 60)} WARNING auditor.hostlog: host-log: 203.0.113.10 read failed\n")
        a.cfg["logging"] = {"file": path}
        out["r"] = await _rec(a, topic="auditor_log")
        out["w"] = await _rec(a, topic="auditor_log", level="WARNING")
        out["s"] = await _rec(a, topic="auditor_log", search="suppressed")
        out["long"] = await _rec(a, topic="auditor_log", hours=24 * 30)
        a.cfg["logging"] = {"file": os.path.join(d, "gone.log")}
        out["gone"] = await _rec(a, topic="auditor_log")
    _run(go)
    r = out["r"]
    blob = json.dumps(r, ensure_ascii=False)
    check(len(r["lines"]) == 3 and "Auditor started" not in blob, "the window: 48 hours by default")
    check("AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawx" not in blob and "hunter2" not in blob
          and "<telegram token>" in blob and "password=***" in blob,
          "the bot token and a password scrubbed")
    check("Traceback" in r["lines"][1], "a traceback stays with its line")
    w = out["w"]["lines"]
    check(len(w) == 2 and all(("ERROR" in x or "WARNING" in x) for x in w),
          "level=WARNING: warnings and errors only")
    check(len(out["s"]["lines"]) == 1 and "digest suppressed" in out["s"]["lines"][0], "search")
    check("UNKNOWN before" in out["long"].get("note", ""), "a window older than the file says where it starts")
    check("cannot read" in json.dumps(out["gone"]), "a missing file is said so")
    check(RC.scrub("GET https://admin:s3cret@192.168.10.1/rest") == "GET https://***:***@192.168.10.1/rest",
          "a login in a URL scrubbed too")


# --- 10. conversations --------------------------------------------------------------------------
def test_conversations():
    print("\n-- conversations, from the dashboard and Telegram --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        a.dashboard.chats._convs["c1"] = {"id": "c1", "created": now - 900, "updated": now - 800, "turns": [
            {"id": "t1", "q": "why is the boiler slow?", "a": "weak Wi-Fi", "status": "done",
             "done_ts": now - 800},
            {"id": "t2", "q": "and now?", "status": "pending"}]}
        a.chat._tg["100000001"] = {"turns": [{"q": "is the VPS ok?", "a": "yes", "ts": now - 300}]}
        out["r"] = await _rec(a, topic="conversations")
        out["s"] = await _rec(a, topic="conversations", search="boiler")
    _run(go)
    ex = out["r"]["exchanges"]
    check([x["where"] for x in ex] == ["telegram", "dashboard"] and ex[1]["a"] == "weak Wi-Fi",
          "both places, newest first, the unanswered question left out")
    check(len(out["s"]["exchanges"]) == 1 and out["s"]["exchanges"][0]["q"].startswith("why"), "search")


# --- 11. weekly and apt ------------------------------------------------------------------------
def test_weekly_and_apt():
    print("\n-- the weekly review reads both event formats; apt's installed version --")
    check(weekly._channel("critical") == "critical"
          and weekly._channel(json.dumps({"channel": "digest", "text": "x"})) == "digest"
          and weekly._channel("{broken") == "", "old detail, new JSON detail, a broken one")
    f = U.parse_linux("UPG=openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 "
                      "[upgradable from: 3.0.13-0ubuntu3.5]\nUPG=vim/noble 2:9.1 amd64\n")
    check(f["updates"][0]["from"] == "3.0.13-0ubuntu3.5" and "from" not in f["updates"][1],
          "the installed version when apt says it")


# --- 13. step 3: the label on log verdicts, the package list on the page --------------------------
def test_verdict_kind_and_packages():
    print("\n-- a log verdict is about security or health; the page gets the package list --")
    from lanowl.wanwatch import verdict_kind
    check(verdict_kind({"kind": "security"}, "health") == "security"
          and verdict_kind({"kind": "Health "}, "security") == "health"
          and verdict_kind({}, "health") == "health" and verdict_kind({"kind": "odd"}, "security") == "security",
          "the model's word, or the source's default")
    check(RC.finding_kind({"source": "host log VPS"}) == "security"
          and RC.finding_kind({"source": "router log"}) == "health"
          and RC.finding_kind({"source": "router log", "kind": "security"}) == "security",
          "an old verdict without a label: a host's auth log is security, the router's health")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _updates(a, time.time())
        out["v"] = {h["ip"]: h for h in a.updates.view()["hosts"]}
    _run(go)
    h = out["v"]["192.168.10.113"]
    check(h["packages"][0] == {"pkg": "openssl", "to": "3.0.13-0ubuntu3.6", "from": "3.0.13-0ubuntu3.5",
                               "security": True, "phased": False}
          and h["packages"][1]["phased"] is True and h["reboot_pkgs"] == ["linux-image-6.8.0-142-generic"],
          "each machine's packages and what asked for the reboot, for the device sheet")
    check(out["v"]["192.168.20.1"]["security_releases"] == ["6.49.19"], "RouterOS: the security releases too")


# --- 12. size --------------------------------------------------------------------------------------
def test_cut():
    print("\n-- a huge answer is cut, and says how to ask for less --")
    s = RC._clip({"x": "y" * (RC.MAX_CHARS * 2)})
    check(len(s) < RC.MAX_CHARS + 200 and s.endswith("or an ip]"), "cut, with the way out")


if __name__ == "__main__":
    for fn in [test_offered_and_dispatched, test_security, test_updates, test_device_never_a_login,
               test_actions, test_telegram, test_log_checks, test_audits_and_the_digest_decision,
               test_auditor_log, test_conversations, test_weekly_and_apt, test_verdict_kind_and_packages,
               test_cut]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
