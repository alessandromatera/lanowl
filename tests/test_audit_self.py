"""The audit looks for itself: run with `python -m tests.test_audit_self`.

No network, no model, no sandbox — fakes throughout. Pinned down here:

  1. in the hourly audit a PASSIVE check runs at once, `session.audit_checks` an audit, then it
     is refused; an ACTIVE one (a scan, a capture, the speed test) still asks for a session —
     and only while an incident is open; run_check says which is which;
  2. the audit's prompt says so, and lists the whole actions catalog;
  3. the audit's shell is the OFFLINE sandbox, offered in the audit only (the owner's shell in
     questions only), its commands counted apart; its canary also proves the internet and
     every resolver unreachable — one that answers is a breach, said once on Telegram;
  4. the walls are proven when lanowl starts, then at most daily from the sweep; the
     security review proves them too; `ready` proves them again when the sandbox restarted
     (its start marker changed) and not otherwise;
  5. what the audit ran by itself is listed under its digest and kept in its record — and, for
     an incident, under the diagnosis edited into that incident's alert.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import prompts as P
from lanowl import shell as SH
from lanowl.report import format_digest
from tests import test_checks as TC
from tests.test_shell import ISOLATED, _sandbox

_fails = []
OFFLINE_OK = ISOLATED + "NET-000\nDNS-CLOSED\nRDNS-CLOSED\nMARK boot-1 4242\n"


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


# --- 1. passive checks in the audit ---------------------------------------------------------------
def test_passive_checks_run_in_the_audit():
    print("\n-- the audit runs passive checks itself; active ones still ask --")
    out = {}
    ex = TC._Exec({"curl": (0, "203.0.113.7\n", "")}).install()
    try:
        async def go(d):
            a = TC._auditor(d)
            ac = a.actions
            ac.audit_checks = 2
            ran = []
            with ac.source("audit", ran=ran):
                out["spec"] = ac.check_spec()["function"]["description"]
                out["r1"] = await ac.run_check({"check": "public_ip"})
                out["r2"] = await ac.run_check({"check": "ping", "target": "9.9.9.9"})
                out["r3"] = await ac.run_check({"check": "public_ip"})
                out["active"] = await ac.run_check({"check": "speed_test", "reason": "slow?"})
            out["ran"], out["items"] = ran, list(ac.items)
            with ac.source("telegram"):
                out["question"] = await ac.run_check({"check": "public_ip", "reason": "q"})
        with tempfile.TemporaryDirectory() as d:
            TC.run(go(d))
    finally:
        ex.restore()
    check("PASSIVE checks run at once" in out["spec"] and "public_ip" in out["spec"]
          and "speed_test" not in out["spec"].split("PASSIVE")[1].split(".")[0],
          "run_check tells the audit which checks it runs itself")
    check(out["r1"].get("ok") is not None and "left" in out["r1"] and "ran" in out["r1"],
          "a passive check runs at once and returns its output")
    check("refused" in out["r3"] and "this audit has used its 2 checks" in out["r3"]["refused"],
          "at most session.audit_checks an audit")
    check("refused" in out["active"] and "incident" in out["active"]["refused"],
          "an active one still asks for a session — refused on a healthy network")
    check([r["check"] for r in out["ran"]] == ["public_ip", "ping"] and all(r["kind"] == "check" for r in out["ran"]),
          "the checks it ran are listed for the digest")
    check(not any(p.get("action") == "investigate" and p.get("status") == "pending" for p in out["items"]),
          "no session request is left waiting for the owner")
    check("NOT RUN" in out["question"].get("status", ""),
          "a question that is not the owner's own still asks for a session, as before")


# --- 2. the prompt ---------------------------------------------------------------------------------
def test_audit_prompt():
    print("\n-- the audit's prompt: its own checks, the whole catalog --")
    s = " ".join(P.with_actions(P.system_prompt(), "audit", True).split())
    check("RUN AT ONCE" in s and "Never on a healthy network" in s and "INVESTIGATION SESSION" in s,
          "passive checks at once, never 'to confirm'; the rest asks")
    check(all(x in s for x in ("reboot", "apt_upgrade", "routeros_upgrade", "shelly_reboot")),
          "the prompt names every action the tool offers")
    check("OFFLINE" in P.with_shell_offline("") and "no DNS" in P.with_shell_offline(""),
          "the audit's shell rules say offline, no DNS")


# --- 3-4. the audit's offline shell, and when the walls are proven -----------------------------------
def _cfg(d):
    return {"shell": {"enabled": True, "socket": os.path.join(d, "owner.sock"), "timeout_s": 60,
                      "timeout_max_s": 300, "output_max_chars": 400, "max_per_answer": 5,
                      "canary_lan": "192.168.10.103:11434",
                      "audit": {"enabled": True, "socket": os.path.join(d, "offline.sock"),
                                "max_per_audit": 2}},
            "observer": {"host_ip": "192.168.10.95"},
            "mikrotik": {"dhcp_source": "http://192.168.10.1"}}


def test_offline_shell_and_when_it_is_proven():
    print("\n-- the audit's offline shell; proven at start, daily, and when the sandbox restarts --")
    out = {"tg": []}
    from tests.test_llm_more import _auditor

    async def go(d):
        _, a = _auditor(d, _cfg(d))
        a._emit_telegram = lambda ch, text, **kw: out["tg"].append((ch, text))
        reply = {"canary": OFFLINE_OK, "mark": "boot-1 4242"}
        seen = []

        def answer(cmd, timeout):
            if "HANDSHAKE" in cmd:
                return {"rc": 0, "out": reply["canary"], "secs": 3}
            if cmd.startswith("cat /proc/sys/kernel/random/boot_id"):
                return {"rc": 0, "out": reply["mark"].replace(" ", "\n") + "\n", "secs": 0.01}
            return {"rc": 0, "out": f"ran: {cmd}\n", "secs": 0.1}
        srv = await _sandbox(a.shell_audit.sock, answer, seen)
        sh = a.shell_audit
        try:
            out["spec_outside"] = [t["function"]["name"] for t in a.executor.tool_specs()]
            st = await sh.canary()
            out["canary_cmd"], out["ok"] = seen[-1]["cmd"], dict(st)
            # the sweep's tick: nothing more within the day
            n = len(seen)
            sh.tick(time.time() + 3600)
            await asyncio.sleep(0.05)
            out["tick_hour"] = len(seen) - n
            sh.tick(time.time() + 90000)
            await asyncio.sleep(0.2)
            out["tick_day"] = len(seen) - n
            # ready(): same sandbox -> no new proof; restarted -> proven again
            n = len(seen)
            out["ready_same"] = await sh.ready()
            out["same_calls"] = [s["cmd"][:20] for s in seen[n:]]
            reply["mark"] = "boot-1 9999"
            reply["canary"] = OFFLINE_OK.replace("4242", "9999")
            n = len(seen)
            out["ready_new"] = await sh.ready()
            out["new_calls"] = sum(1 for s in seen[n:] if "HANDSHAKE" in s["cmd"])
            # in the audit's turn: the offline shell, 2 commands, counted apart
            ran = []
            with sh.turn("audit", "scheduled", ran):
                specs = a.executor.tool_specs()
                out["spec_audit"] = next((t for t in specs if t["function"]["name"] == "shell"), None)
                out["c1"] = await a.executor.call("shell", {"command": "fping -c1 192.168.10.31"})
                out["c2"] = await a.executor.call("shell", {"command": "ip route"})
                out["c3"] = await a.executor.call("shell", {"command": "true"})
            out["ran"] = ran
            out["log"] = a.state.load_record("shell_audit") if a._persist_alerts else None
            # the internet answers: a breach
            reply["canary"] = ISOLATED + "NET-200\nDNS-CLOSED\nRDNS-CLOSED\nMARK boot-1 9999\n"
            out["leak"] = dict(await sh.canary())
            reply["canary"] = ISOLATED + "NET-000\nDNS-CLOSED\nRDNS-OPEN\nMARK boot-1 9999\n"
            out["dns"] = dict(await sh.canary())
        finally:
            srv.close()
            await srv.wait_closed()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("shell" not in out["spec_outside"], "outside a turn, no shell is offered")
    c = out["canary_cmd"]
    check("http://1.1.1.1/" in c and "@192.168.10.1" in c and "dig" in c and "MARK" in c,
          "the offline canary tries the internet, Docker's resolver and the router's, and reads the marker")
    check(out["ok"]["ok"] is True and "offline" in out["ok"]["why"] and out["ok"]["marker"] == "boot-1 4242",
          "no internet, no DNS: proven offline, with the sandbox's marker")
    check(out["tick_hour"] == 0 and out["tick_day"] == 1, "the sweep proves it again only after a day")
    check(out["ready_same"] is True and out["same_calls"] == ["cat /proc/sys/kernel"],
          "same sandbox: only its marker is read, nothing proven again")
    check(out["ready_new"] is True and out["new_calls"] == 1, "a restarted sandbox is proven again first")
    spec = out["spec_audit"]
    check(spec is not None and "OFFLINE" in spec["function"]["description"],
          "in the audit's turn the shell is the offline one")
    check(out["c1"]["result"]["exit_code"] == 0 and "refused" in out["c3"]["result"]
          and "this audit has used its 2 commands" in out["c3"]["result"]["refused"],
          "max_per_audit commands, then refused")
    check([r["label"] for r in out["ran"]] == ["$ fping -c1 192.168.10.31", "$ ip route"],
          "its commands join the audit's list")
    check(out["leak"]["ok"] is False and "NOT ISOLATED" in out["leak"]["why"] and "internet 200" in out["leak"]["why"],
          "the internet answering is a breach")
    check(out["dns"]["ok"] is False and "DNS answers" in out["dns"]["why"], "...and so is a resolver answering")
    tg = [t for t in out["tg"] if t[0] == "critical"]
    check(len(tg) == 1 and "The audit's offline shell NOT isolated" in tg[0][1], "said on Telegram once, named")


# --- 5. under the digest ---------------------------------------------------------------------
def test_digest_lists_what_it_ran():
    print("\n-- what the audit ran by itself is under its digest --")
    rep = {"overall_health": "degraded", "counts": {"up": 1, "total": 2, "down": 1}, "wan_ok": True,
           "issues": [], "devices": [],
           "checks_ran": [{"label": "public IP", "ok": True}, {"label": "<ping> 9.9.9.9", "ok": False}]}
    t = format_digest(rep)
    check("The audit looked for itself" in t and "🔧 public IP" in t and "✗ &lt;ping&gt; 9.9.9.9" in t,
          f"🔧 per check, ✗ for a failed one, escaped ({t[-120:]!r})")
    rep.pop("checks_ran")
    check("looked for itself" not in format_digest(rep), "nothing when it ran nothing")
    from lanowl.report import format_diagnosis_note
    issue = {"device": "NVR", "ip": "192.168.10.31", "kind": "device"}
    llm = {"issues": [{"device": "NVR", "ip": "192.168.10.31", "root_cause": "PoE port lost power",
                       "recommendation": "check the switch port"}]}
    ran = [{"label": "ping 192.168.10.31 · from here", "ok": False}, {"label": "router port ether3", "ok": True}]
    note = format_diagnosis_note([issue], llm, at=0, ran=ran)
    check("🦉 <b>Likely cause</b>" in note and note.endswith("✗ ping 192.168.10.31 · from here\n🔧 router port ether3"),
          f"the incident's alert: the cause, then what the model checked to find it ({note[-80:]!r})")
    check("🔧" not in format_diagnosis_note([issue], llm, at=0), "no checks run, no lines")


if __name__ == "__main__":
    for fn in [test_passive_checks_run_in_the_audit, test_audit_prompt,
               test_offline_shell_and_when_it_is_proven, test_digest_lists_what_it_ran]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
