"""The model's daily security review: run with `python -m tests.test_exposure`.

No network, no model, no Telegram — ssh, nmap, the router and the model are fakes. Pinned down
here (exposure.py):

  1. it runs once a day, after the morning's update check has finished — never before it;
  2. each kind of machine is read its own way: root over the host-log key, the listed login
     with sudo -S, RouterOS in groups (one unknown command costs its group, not the rest);
     what comes back is scrubbed; a machine that cannot be read says so;
  3. the network is scanned from the VPS ONLY when its public address is on the router — behind
     the provider's NAT it is not (the provider's box is not ours); the VPS is scanned from here;
  4. the model's findings are held to the rules: a machine it was shown, a check from the list
     (else "other"), a known severity, one finding per machine + check (the worst kept);
  5. no usable review keeps yesterday's findings and says why;
  6. the owner dismisses one; it stays out until undone, or until the problem is gone;
  7. nothing pages before `page_from`; then a NEW critical one pages once, and again only if
     it went away and came back;
  8. the log checks and the review see only the memory notes the owner asked for;
  9. the port list and nmap's output are read right; the records tool and the weekly line.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import exposure as E
from lanowl import memory as M
from tests.test_reboot import _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _run(go):
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))


HOSTS = [{"ip": "203.0.113.10", "via": "key"}, {"ip": "192.168.10.113", "via": "sudo"},
         {"ip": "192.168.20.1", "via": "routeros"}, {"ip": "10.8.0.16", "via": "openwrt"}]


def _setup(a, page_from="2099-01-01"):
    x = a.exposure
    x.enabled, x.hosts, x.page_from = True, [dict(h) for h in HOSTS], page_from
    calls = {"ssh": [], "key": [], "nmap": []}

    async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
        calls["ssh"].append((ip, remote, sudo_pw, user_suffix))
        if ip == "10.8.0.16":
            return None, "", "ssh: connect to host 10.8.0.16 port 22: No route to host"
        if user_suffix == "+ct":
            if remote.startswith("/ip upnp"):
                return 0, "bad command name upnp (line 1 column 5)", ""
            return 0, f"{remote.split(';')[0]}\n  enabled: yes\n  password=hunter2\n", ""
        return 0, "== sshd (effective settings)\npasswordauthentication yes\npermitrootlogin yes\n", ""
    a.access.ssh = ssh

    async def key(ip, remote, timeout_s=20):
        calls["key"].append((ip, remote))
        return 0, "== sshd (effective settings)\npasswordauthentication yes\n== firewall\n-P INPUT ACCEPT\n", ""
    a.actions._ssh_run = key

    async def fake_exec(argv, timeout_s):
        calls["nmap"].append(argv)
        return 0, ('<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/>'
                   '<service name="ssh"/></port><port protocol="tcp" portid="80"><state state="closed"/>'
                   '</port></ports></host></nmaprun>'), ""
    E._exec = fake_exec
    return x, calls


# --- 1. when --------------------------------------------------------------------------------
def test_due():
    print("\n-- once a day, after the morning's update check --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        x, _ = _setup(a)
        u = a.updates
        u.enabled, u.at = True, "06:30"
        at = u._today_at("06:30", time.time())
        now = at + 3600
        u.rec["last_done"] = at - 86400
        out["before_check"] = x.due(now)
        u.rec["last_done"] = at + 120
        out["after_check"] = x.due(now)
        x.rec["last"] = at + 200
        out["done_today"] = x.due(now)
        x.enabled = False
        x.rec["last"] = 0
        out["off"] = x.due(now)
    _run(go)
    check(not out["before_check"] and out["after_check"], "only once today's update check has finished")
    check(not out["done_today"] and not out["off"], "once a day, and never when switched off")


# --- 2-5. a run ------------------------------------------------------------------------------
def test_run_reads_scans_and_holds_the_model_to_the_rules():
    print("\n-- a run: each machine its own way, the scans, the model held to the rules --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        x, calls = _setup(a)
        vps = next(h for h in a.hostlog.hosts if h.public) if a.hostlog.hosts else None
        out["hostlog"] = vps is not None
        x._house_public = lambda: "198.51.100.7"

        async def router_addrs():      # ZeroTier's and the tunnel's private addresses too
            return {"192.168.10.1", "10.147.17.60", "10.8.0.4", "100.70.1.2"}
        x._router_addrs = router_addrs
        seen = []

        async def ask_json(system, ctx, timeout_s=None):
            seen.append((system, ctx))
            return {"summary": "The VPS takes root passwords from the internet.", "findings": [
                {"ip": "203.0.113.10", "check": "ssh_password_login", "severity": "high",
                 "title": "ssh accepts passwords", "evidence": "passwordauthentication yes", "fix": "keys only"},
                {"ip": "203.0.113.10", "check": "ssh_password_login", "severity": "critical",
                 "title": "root password login from the internet", "evidence": "permitrootlogin yes", "fix": "x"},
                {"ip": "203.0.113.10", "check": "made_up_check", "severity": "sky-high", "title": "odd"},
                {"ip": "8.8.8.8", "check": "no_firewall", "severity": "critical", "title": "not ours"},
                "not a dict"]}
        a.agent.ask_json = ask_json
        started = []
        a.cves.start = lambda reason: started.append(reason) or True
        out["findings"] = await x.run("test")
        out["cve_none"] = list(started)              # no scan matches yet: nothing to check
        a.updates.rec["scan"] = {"done": 1.0, "found": {"192.168.10.35": [{"id": "CVE-2024-1", "cvss": 9.0}]}}
        out["calls"] = {k: list(v) for k, v in calls.items()}      # the first run's only
        out["seen"], out["rec"] = seen, x.rec

        async def no_answer(system, ctx, timeout_s=None):
            return None
        a.agent.ask_json = no_answer
        await x.run("test")
        out["after_none"] = (list(x.rec["findings"]), x.rec["error"])
        out["cve_after"] = list(started)
    _run(go)
    c = out["calls"]
    sudo = [s for s in c["ssh"] if s[0] == "192.168.10.113"]
    check(sudo and sudo[0][1].startswith("sudo -S -p '' sh -c ") and sudo[0][2] is True,
          "the homehub: its listed login, sudo -S with its password")
    check([k[0] for k in c["key"]].count("203.0.113.10") >= 1 and c["key"][0][1].startswith("sh -c "),
          "the VPS: root over the host-log key")
    ros = [s for s in c["ssh"] if s[0] == "192.168.20.1"]
    check(len(ros) == len(E.ROUTEROS) and all(s[3] == "+ct" for s in ros), "RouterOS: one ssh per group, +ct")
    f = out["rec"]["facts"]
    check(f["192.168.20.1"]["ok"] and "bad command" in f["192.168.20.1"]["text"]
          and "/ip service print detail" in f["192.168.20.1"]["text"],
          "an unknown RouterOS command costs its group, the rest is kept")
    check("hunter2" not in json.dumps(f), "what comes back is scrubbed")
    check(not f["10.8.0.16"]["ok"] and "No route to host" in f["10.8.0.16"]["error"],
          "a machine that cannot be read says why")
    ctx = out["seen"][0][1]
    check("COULD NOT BE READ: ssh: connect to host 10.8.0.16" in ctx, "...and the model is told so")
    o = out["rec"]["outside"]
    check(o["vps"]["open"] == [{"port": 22, "service": "ssh"}] and "--max-rate" in c["nmap"][0]
          and c["nmap"][0][-1] == "203.0.113.10", "the VPS scanned from here, rate-limited, open ports read")
    check(o["home"]["scanned"] is False and "provider's NAT" in o["home"]["note"]
          and "100.70.1.2" in o["home"]["note"] and "10.147" not in o["home"]["note"],
          "the network behind the provider's NAT: not scanned, and why — the fiber's address, not ZeroTier's")
    fs = out["findings"]
    check([x["key"] for x in fs] == ["exp:203.0.113.10:ssh_password_login", "exp:203.0.113.10:other"],
          f"one per machine + check, a check off the list is 'other', a stranger dropped ({[x['key'] for x in fs]})")
    check(fs[0]["severity"] == "critical" and "ssh accepts passwords" in fs[0]["title"]
          and fs[1]["severity"] == "warning", "the worst severity kept, the other title folded in; unknown -> warning")
    check(out["cve_none"] == [] and out["cve_after"] == ["after the security review"],
          "the scan's CVE matches are checked again after each review — when there are any")
    kept, err = out["after_none"]
    check(len(kept) == 2 and "no usable review" in err, "no usable review: yesterday's findings kept, and why")


def test_house_scanned_only_when_it_is_ours():
    print("\n-- the network is scanned from the VPS only when its address is the router's --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        x, calls = _setup(a)
        x._house_public = lambda: "81.1.2.3"

        async def router_addrs():
            return {"81.1.2.3", "192.168.10.1"}
        x._router_addrs = router_addrs
        real = E.top_ports
        E.top_ports = lambda n=1000, path="": [22, 80, 443]
        try:
            out["o"] = await x._outside()
        finally:
            E.top_ports = real
        out["cmds"] = [k[1] for k in calls["key"]]
    _run(go)
    h = out["o"]["home"]
    check(h.get("scanned_from") == "203.0.113.10" and h.get("ports_tried") == 1000,
          "a public address on the router: scanned from the VPS")
    check(any("xargs -P 20" in c and "nc -z -w 2 81.1.2.3" in c for c in out["cmds"]), "with nc, 20 at a time")


def test_tunnel_names_and_own_sudo():
    print("\n-- the tunnel's routes are read, the owner's names looked at, the own sudo said --")
    check("cloudflare tunnel" in E.LINUX and "<hidden>" in E.LINUX and "/config" in E.LINUX,
          "a Linux machine running a Cloudflare Tunnel: its routes read, its token never")
    check("CLOUDFLARE TUNNEL" in E.SYSTEM and "127.0.0.1" in E.SYSTEM and "cloudflareaccess.com" in E.SYSTEM,
          "the model is told a tunnel route is a door from the internet")
    out = {"notes": []}

    async def go(d):
        m, a = _auditor(d)
        x, calls = _setup(a)
        x.names = ["ssh.example.com", "webhook.example.com"]

        async def name_check(n):
            return {"name": n, "https": 200, "access_login": False}
        x._name_check = name_check
        x._house_public = lambda: ""
        a.hostlog.note_own = lambda ip, t0, t1, what: out["notes"].append((ip, what))
        out["o"] = await x._outside()
        for h in x.hosts:
            await x._facts(h)
    _run(go)
    check([n["name"] for n in out["o"]["public_names"]] == ["ssh.example.com", "webhook.example.com"],
          "the owner's names are looked at from outside")
    ips = [n[0] for n in out["notes"]]
    check(ips == ["203.0.113.10", "192.168.10.113"] and "via sudo" in out["notes"][1][1]
          and "as root" in out["notes"][0][1], "its own root/sudo runs are told to the host-log triage")


# --- 6-7. the owner, and paging -------------------------------------------------------------------
def test_dismiss_and_paging():
    print("\n-- dismissed until undone or gone; nothing pages before page_from, then once --")
    out = {"sent": []}
    finding = {"ip": "203.0.113.10", "check": "ssh_root_login", "severity": "critical",
               "title": "root logs in by password", "evidence": "permitrootlogin yes", "fix": "keys"}

    async def go(d):
        m, a = _auditor(d)
        x, _ = _setup(a)
        x._house_public = lambda: ""
        a._emit_telegram = lambda kind, text: out["sent"].append((kind, text))
        answer = {"findings": [finding]}

        async def ask_json(system, ctx, timeout_s=None):
            out.setdefault("ctx", []).append(ctx)
            return answer
        a.agent.ask_json = ask_json
        await x.run("t")                                   # the trial: nothing sent
        out["trial"] = len(out["sent"])
        x.page_from = "2000-01-01"
        await x.run("t")
        await x.run("t")                                   # the same one again: silent
        out["paged"] = len(out["sent"])
        key = "exp:203.0.113.10:ssh_root_login"
        out["dis"] = x.dismiss(key, "keys only next month")
        out["dis_bad"] = x.dismiss("exp:1.2.3.4:x")
        await x.run("t")
        out["ctx_dis"] = out["ctx"][-1]
        out["view"] = x.view()
        answer["findings"] = []                            # the problem is gone...
        await x.run("t")
        out["kept_after_one"] = key in x.rec["dismissed"]  # ...or the model left it out once
        await x.run("t")
        await x.run("t")
        out["forgotten"] = key not in x.rec["dismissed"] and key not in x.rec["announced"]
        out["ahead"] = x.dismiss("exp:10.8.0.16:end_of_life", "replacing it, not now")
        out["bad_key"] = x.dismiss("exp:10.8.0.16:made_up")
        answer["findings"] = [finding]                     # ...and back
        await x.run("t")
        out["again"] = len(out["sent"])
        out["undo_missing"] = x.undismiss(key)
    _run(go)
    check(out["trial"] == 0, "before page_from nothing goes to Telegram")
    check(out["paged"] == 1 and out["sent"][0][0] == "critical" and "VPS (203.0.113.10)" in out["sent"][0][1],
          "then a new critical pages once, named and addressed")
    check(out["dis"]["ok"] and not out["dis_bad"]["ok"], "the owner dismisses one of the review's findings")
    check("exp:203.0.113.10:ssh_root_login — keys only next month" in out["ctx_dis"],
          "the model is told what was dismissed, with the reason")
    v = out["view"]["findings"][0]
    check(v["dismissed"]["note"] == "keys only next month", "the view carries the dismissal")
    check(out["kept_after_one"], "one review without it does not forget a dismissal")
    check(out["forgotten"], "three in a row: the problem is gone — dismissal and announcement forgotten")
    check(out["ahead"]["ok"] and not out["bad_key"]["ok"], "a decision by key, ahead of the review; not a made-up check")
    check("Still report each one that still holds" in out["ctx_dis"], "the model is told to keep reporting a dismissed one")
    check(out["again"] == 2, "...so if it comes back, it pages again")
    check(not out["undo_missing"]["ok"], "undoing what is not dismissed says so")


# --- 8. memory ----------------------------------------------------------------------------------
def test_memory_asked_only():
    print("\n-- the unwatched verdicts see only the notes the owner asked for --")
    with tempfile.TemporaryDirectory() as d:
        async def go():
            m, a = _auditor(d)
            mem = a.memory
            mem.notes = [
                {"id": 1, "text": "Acme comes from Starlink", "ts": 1, "upd": 1, "by": "model", "q": "Remember that"},
                {"id": 2, "text": "the VPS logins at 3am are fine", "ts": 1, "upd": 1, "by": "model",
                 "q": "why was there a login at 3am?"},
                {"id": 3, "text": "the NVR reboots on Sundays", "ts": 1, "upd": 1, "by": "owner"},
                {"id": 4, "text": "washer", "ts": 1, "upd": 1, "by": "model", "q": "non avvisarmi per la lavatrice"}]
            return mem.block(), mem.block(asked_only=True)
        full, asked = asyncio.run(go())
    check("#2" in full and "#2" not in asked, "a note the model saved unasked stays out of the verdicts")
    check(all(f"#{i}" in asked for i in (1, 3, 4)), "the owner's own, a 'remember that', a 'non avvisarmi'")
    check(M.asked({"by": "model", "q": "ricordati che il frigo è nuovo"}), "Italian too")


# --- 9. parsing, records, weekly ---------------------------------------------------------------------
def test_parsing_records_weekly():
    print("\n-- the port list, nmap's output, the records tool, the weekly line --")
    with tempfile.NamedTemporaryFile("w", suffix=".services", delete=False) as fh:
        fh.write("# comment\nssh\t22/tcp\t0.18\nhttp\t80/tcp\t0.48\ndomain\t53/udp\t0.2\nfoo\t9/tcp\t0.001\n")
        path = fh.name
    check(E.top_ports(2, path) == [22, 80], "the most used TCP ports, from nmap's own file")
    os.unlink(path)
    check(E.parse_open("<x") == [], "broken XML: nothing, no crash")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        x, _ = _setup(a)
        x.rec.update(last_done=time.time(), reviewed=time.time(), summary="exposed a bit",
                     facts={"203.0.113.10": {"name": "VPS", "kind": "key", "ok": True, "text": "== sshd\npasswordauthentication yes"}},
                     findings=[{"key": "exp:203.0.113.10:ssh_password_login", "ip": "203.0.113.10", "name": "VPS",
                                "check": "ssh_password_login", "severity": "critical", "title": "passwords accepted",
                                "evidence": "passwordauthentication yes", "fix": "keys only"}])
        r = await a.executor.call("lanowl_records", {"topic": "exposure"})
        out["rec"] = json.loads(r["result"]["records"])
        out["weekly"] = x.weekly_lines()
        a.updates.enabled = True
        a.updates.rec["last_done"] = time.time()
        out["line"] = a.records.security_line()
    _run(go)
    r = out["rec"]
    check(r["findings"][0]["check"] == "ssh_password_login" and "passwordauthentication yes" in r["facts"]["203.0.113.10"]["facts"]
          and "not before 2099-01-01" in r["pages_telegram"], "the records tool: findings, the facts, the trial")
    check(out["weekly"][0].startswith("🔎 Security review: 1 finding(s), the worst critical: VPS (203.0.113.10)"),
          "one line in the weekly review")
    check("the model's security review" in out["line"] and "passwords accepted" in out["line"],
          "and the question's SECURITY line says it too")


if __name__ == "__main__":
    for fn in [test_due, test_run_reads_scans_and_holds_the_model_to_the_rules,
               test_house_scanned_only_when_it_is_ours, test_tunnel_names_and_own_sudo,
               test_dismiss_and_paging,
               test_memory_asked_only, test_parsing_records_weekly]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
