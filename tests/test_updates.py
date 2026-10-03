"""Updates, pending reboots, known vulnerabilities: run with `python -m tests.test_updates`.

No network, no host — ssh, Home Assistant, MikroTik's site, nmap and Telegram are fakes.
Pinned down here (updates.py):

  1. what each host says is read right: apt's list (security apart), the reboot flag and
     since when, RouterOS installed/channel/firmware, the versions between two RouterOS
     releases, nmap's vulners output;
  2. the four rules that page — reboot pending > 3 days, security update not installed after
     2 days, a RouterOS security release or a CVSS >= 7 CVE, telnet/ftp open — and nothing
     else does;
  3. ONE message per run, only for what is new: the same finding tomorrow is silent, one that
     went away and came back pages again;
  4. it runs once a day at `at`, the scan on its day of the month;
  5. /updates and the weekly review say it too;
  6. the owner dismisses what matters, one by one: out of it and silent until something NEW
     shows up for it (a new CVE/version, security package, pending reboot, RouterOS release);
     an insecure port until undone; the reason goes to the weekly review.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import updates as U
from tests.test_reboot import DEVICES, _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


DAY = 86400
UBUNTU = ("OS=Ubuntu 24.04.5 LTS\nKERNEL=6.8.0-139-generic\nUPTIME=1209600.5\n"
          "REBOOT={rb}\nRPKG=linux-image-6.8.0-142-generic\nRPKG=linux-base\nLISTS=1790000000\n"
          "UPG=openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]\n"
          "UPG=vim/noble-updates 2:9.1.0016-1ubuntu7.9 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.8]\n")
DEBIAN = ("OS=Debian GNU/Linux 12 (bookworm)\nKERNEL=6.1.0-53-amd64\nUPTIME=86441.40\nLISTS=1790000000\n"
          "UPG=libc6/stable-security 2.36-9+deb12u14 amd64 [upgradable from: 2.36-9+deb12u13]\n")
ROS6 = ("          channel: long-term\n installed-version: 6.49.12\n\n"
        "       routerboard: yes\n             model: SXT Lite5\n  current-firmware: 6.49.12\n"
        "  upgrade-firmware: 6.49.12\n")
ROS7 = ("        channel: stable\ninstalled-version: 7.24.4\n\n       routerboard: yes\n"
        "        model: C53UiG+5HPaxD2HPaxD\ncurrent-firmware: 7.23.1\nupgrade-firmware: 7.24.4\n")
NMAP = """<?xml version="1.0"?><nmaprun><host><address addr="192.168.10.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="Dropbear sshd" version="2022.83"/>
<script id="vulners" output="..."><table key="cpe:/a:matt_johnston:dropbear_ssh_server:2022.83">
<table><elem key="id">CVE-2025-47203</elem><elem key="cvss">8.1</elem><elem key="type">cve</elem><elem key="is_exploit">false</elem></table>
<table><elem key="id">CVE-2023-48795</elem><elem key="cvss">5.9</elem><elem key="type">cve</elem><elem key="is_exploit">true</elem></table>
<table><elem key="id">PACKETSTORM:1</elem><elem key="cvss">9.8</elem><elem key="type">packetstorm</elem><elem key="is_exploit">true</elem></table>
</table></script></port></ports></host>
<host><address addr="192.168.10.113" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>"""


def test_parsing():
    print("\n-- what the hosts say, read right --")
    now = time.time()
    f = U.parse_linux(UBUNTU.format(rb=int(now - 5 * DAY)))
    check(f["os"] == "Ubuntu 24.04.5 LTS" and f["uptime"] == 1209600.5, "OS and uptime")
    check(abs(f["reboot_since"] - (now - 5 * DAY)) < 2 and f["reboot_pkgs"] == ["linux-image-6.8.0-142-generic", "linux-base"],
          "the reboot flag, since when, and what asked for it")
    check([(u["pkg"], u["security"]) for u in f["updates"]] == [("openssl", True), ("vim", False)],
          "apt's list, a security update told apart (noble-security)")
    d = U.parse_linux(DEBIAN)
    check("reboot_since" not in d and d["updates"][0]["security"], "Debian: stable-security counts as security")
    r = U.parse_routeros(ROS6)
    check(r == {"channel": "long-term", "installed": "6.49.12", "board": "SXT Lite5", "fw": "6.49.12", "fw_new": "6.49.12"},
          f"RouterOS 6: channel, version, board, firmware ({r})")
    check(U.parse_routeros(ROS7)["fw_new"] == "7.24.4", "RouterOS 7: a firmware upgrade waiting")
    check(U.between("6.49.12", "6.49.22") == [f"6.49.{z}" for z in range(13, 23)],
          "the releases in between, same line")
    check(U.between("6.49.21", "6.49.22") == ["6.49.22"] and U.between("7.24.4", "7.24.4") == [],
          "one step; none when current")
    check(U.between("7.23.1", "7.24.2") == ["7.24", "7.24.1", "7.24.2"], "across a minor: the new line's own")
    v = U.parse_vulners(NMAP)
    check(list(v) == ["192.168.10.8"] and [x["id"] for x in v["192.168.10.8"]] == ["PACKETSTORM:1", "CVE-2025-47203"],
          "vulners: CVSS >= 7 only, worst first; a host with nothing is not listed")
    check(v["192.168.10.8"][1]["product"] == "Dropbear sshd 2022.83" and U.parse_vulners("junk") == {},
          "the software it is in; junk is nothing")


class _Fake:
    """Every host, as the fakes will answer it."""
    def __init__(self, a, now):
        self.a, self.now = a, now
        self.linux = {"203.0.113.10": UBUNTU.format(rb=int(now - 5 * DAY)),
                      "192.168.10.113": UBUNTU.format(rb=int(now - 1 * DAY)).replace("REBOOT", "XREBOOT")}
        self.ros = {"192.168.20.1": ROS6, "192.168.10.32": ROS6.replace("6.49.12", "6.49.21")}
        self.ports = {("192.168.10.32", 23)}
        self.sent = []
        self.fetched = []

    def install(self):
        a, fk = self.a, self

        async def ssh_run(ip, remote, timeout_s=20, root=False):
            return (0, fk.linux[ip], "") if ip in fk.linux else (None, "", "no")
        a.actions._ssh_run = ssh_run

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            if ip in fk.ros:
                return 0, fk.ros[ip], ""
            if ip == "192.168.10.111":
                return 0, "VMware ESXi 8.0.3 build-24677879\nVMware ESXi 8.0 Update 3\n7514128167969\n", ""
            return 255, "", f"ssh: connect to host {ip} port 22: No route to host"
        a.access.ssh = ssh

        async def ha(method, path, body=None, timeout_s=10):
            if path == "/api/states":
                return 200, [{"entity_id": "update.home_assistant_core_update", "state": "on",
                              "attributes": {"title": "Home Assistant Core", "installed_version": "2026.8.3",
                                             "latest_version": "2026.9.3"}},
                             {"entity_id": "update.nvr_firmware", "state": "off", "attributes": {}}]
            return 200, {"version": "2026.8.3"}
        a.actions.reboot._ha = ha

        async def fetch(url):
            fk.fetched.append(url)
            if url.endswith("NEWEST6.long-term"):
                return "6.49.22 1789563951"
            if url.endswith("/6.49.21/CHANGELOG"):
                return "What's new in 6.49.21:\nThis is an important security update."
            return "What's new:\n*) system - improve stability;"
        a.updates._fetch = fetch

        class _P:
            def __init__(self, ok):
                self.ok = ok

        async def tcp(ip, port, timeout_ms=1500):
            return _P((ip, port) in fk.ports)
        U.probes.tcp_check = tcp
        a._emit_telegram = lambda ch, text, **kw: fk.sent.append(text)
        return self


def _cfg_hosts(a):
    u = a.updates
    u.enabled = True
    u.hosts = [{"ip": "203.0.113.10", "via": "key"}, {"ip": "192.168.10.113", "via": "key"},
               {"ip": "192.168.10.95", "via": "password", "name": "VM monitor"},
               {"ip": "192.168.10.111", "via": "esxi"},
               {"ip": "192.168.20.1", "via": "routeros"}, {"ip": "192.168.10.32", "via": "routeros"},
               {"ip": "192.168.10.104", "via": "homeassistant"}]


def test_the_daily_check():
    print("\n-- the daily check: four rules page, once; the rest is for the dashboard --")
    out = {}
    real_tcp = U.probes.tcp_check

    async def go(d):
        m, a = _auditor(d)
        _cfg_hosts(a)
        fk = _Fake(a, time.time()).install()
        out["f1"] = await a.updates.run("test")
        out["sent1"] = list(fk.sent)
        out["fetched"] = list(fk.fetched)
        out["f2"] = await a.updates.run("test")
        out["sent2"] = len(fk.sent)
        fk.ports.clear()
        await a.updates.run("test")
        fk.ports.add(("192.168.10.32", 23))
        await a.updates.run("test")
        out["sent3"] = fk.sent[len(out["sent1"]):]
        # the security update seen three days ago now pages
        a.updates.rec["first_seen"]["192.168.10.113"]["openssl"] = time.time() - 3 * DAY
        await a.updates.run("test")
        out["sent4"] = fk.sent[-1]
        out["view"] = a.updates.view()
        out["weekly"] = a.updates.weekly_lines()
        out["tg"] = a.chat.updates_text()
    try:
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        U.probes.tcp_check = real_tcp
    f = {x["key"]: x for x in out["f1"]}
    check(f["reboot:203.0.113.10"]["page"] and "reboot pending for 5 days" in f["reboot:203.0.113.10"]["text"]
          and "linux-image-6.8.0-142-generic" in f["reboot:203.0.113.10"]["text"],
          "VPS: a reboot pending 5 days pages, naming what asked for it")
    check("reboot:192.168.10.113" not in f, "no flag, no reboot finding")
    check(not f["secupd:203.0.113.10"]["page"], "a security update seen today does not page yet")
    check(not f["upd:203.0.113.10"]["page"], "ordinary updates never page")
    check(f["ros:192.168.20.1:6.49.22"]["page"] and "6.49.21 was a security release" in f["ros:192.168.20.1:6.49.22"]["text"],
          "the antenna on 6.49.12: behind a security release — pages")
    check(not f["ros:192.168.10.32:6.49.22"]["page"], "an AP one plain release behind: dashboard only")
    check(f["port:192.168.10.32:23"]["page"], "telnet open pages")
    check(not f["ha:update.home_assistant_core_update"]["page"] and "update.nvr_firmware" not in str(f),
          "Home Assistant's waiting updates: dashboard only; ones not waiting are not listed")
    check(f["err:192.168.10.95"]["text"].startswith("VM monitor (192.168.10.95): not checked")
          and not f["err:192.168.10.95"]["page"], "a host that cannot be read says so, by name, without paging")
    check(len(out["sent1"]) == 1 and out["sent1"][0].count("\n• ") == 3,
          "ONE message for the three findings that matter")
    check(sum("6.49.21/CHANGELOG" in u for u in out["fetched"]) == 1 and
          sum("CHANGELOG" in u for u in out["fetched"]) == 10,
          "each changelog fetched once, and cached for the next host")
    check(out["sent2"] == 1, "the next day, the same findings: silence")
    check(len(out["sent3"]) == 1 and "telnet" in out["sent3"][0] and "reboot" not in out["sent3"][0],
          "telnet closed, then open again: it pages again — alone")
    check("1 security update(s) not installed for 3 days" in out["sent4"], "a security update 3 days old pages")
    v = out["view"]
    check(v["findings"][0]["page"] and any(h["name"] == "ESXi hypervisor" or h["ip"] == "192.168.10.111" for h in v["hosts"]),
          "the dashboard: what matters first, then each machine")
    check(out["weekly"] and "thing(s) waiting" in out["weekly"][0], f"the weekly review's line: {out['weekly']}")
    check("❗" in out["tg"] and "Updates &amp; security" in out["tg"], "/updates: the list, what matters marked")


def test_when():
    print("\n-- once a day at `at`; the scan on its day --")
    with tempfile.TemporaryDirectory() as d:
        async def go():
            m, a = _auditor(d)
            u = a.updates
            u.enabled, u.at = True, "06:30"
            lt = time.localtime()
            base = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 6, 0, 0, 0, 0, -1))
            r = [u.due(base), u.due(base + 3600)]
            u.rec["last"] = base + 3600
            r.append(u.due(base + 7200))
            u.scan_day = lt.tm_mday
            r += [u.scan_due(base - 4 * 3600), u.scan_due(base)]
            u.scan_day = lt.tm_mday % 28 + 1
            r.append(u.scan_due(base))
            return r
        r = asyncio.run(go())
    check(r[:3] == [False, True, False], "before 06:30 no; after it yes; once it ran, no more today")
    check(r[3:] == [False, True, False], "the scan: its day after 04:00 only")


def test_the_scan():
    print("\n-- the monthly scan: nmap -sV + vulners, one message for what is new --")
    out = {}
    real = U._exec

    async def go(d):
        m, a = _auditor(d)
        sent = []
        a._emit_telegram = lambda ch, text, **kw: sent.append(text)
        xml = [NMAP]

        # the check of each match (cves.py): NVD and the model faked — no network
        async def nvd(cid):
            return {"desc": "a flaw", "cvss": 8.1, "vector": "", "ts": time.time(), "ranges": [
                {"cpe": "cpe:2.3:a:matt_johnston:dropbear_ssh_server:*:*:*:*:*:*:*:*", "ee": "2025.88"}]}
        a.cves._nvd = nvd

        async def model(*args, **kw):
            return None
        a.agent.ask_json = model

        async def fake(argv, timeout_s, stdin=None, env=None):
            out.setdefault("argv", []).append(argv)
            return 0, xml[0], ""
        U._exec = fake
        await a.updates.scan("test")
        await a.updates.scan("test")
        xml[0] = NMAP.replace("CVE-2025-47203", "CVE-2026-11111")
        await a.updates.scan("test")
        out["sent"] = sent
        out["view"] = a.updates.view()["scan"]
    try:
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        U._exec = real
    argv = out["argv"][0]
    check(argv[:2] == ["nmap", "-sT"] and "vulners" in argv and "mincvss=7" in argv,
          "nmap -sT -sV with vulners, CVSS 7 and up")
    check("192.168.10.32" in argv and "192.168.10.103" not in argv,
          "the network's devices, never lanowl's own host")
    check(len(out["sent"]) == 2 and "Monthly vulnerability scan" in out["sent"][0]
          and "Dropbear sshd 2022.83" in out["sent"][0] and "applies" in out["sent"][0]
          and "read by the model" in out["sent"][0],
          "one message per scan with something that applies; a repeat is silent; a new CVE pages")
    v = out["view"]["found"]["192.168.10.8"]
    check([x["verdict"] for x in v["vulns"]] == ["applies"] and v["refs"] == 1,
          "the CVE checked (NVD's versions include it), the PACKETSTORM id listed as a reference")
    check(out["view"]["found"]["192.168.10.8"]["count"] == 2, "the dashboard lists it per device")


def test_install_updates():
    print("\n-- installing them: a proposal, the button, systemd-run, what is left --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        a.cfg["actions"]["catalog"]["apt_upgrade"] = {"hosts": {
            "203.0.113.10": {"via": "key", "risk": "tunnels may drop"},
            "192.168.10.113": {"via": "password"}}}
        ran = []
        state = {"203.0.113.10": UBUNTU.format(rb=int(time.time())),
                 "192.168.10.113": UBUNTU.format(rb=0).replace("REBOOT", "XREBOOT")}

        async def ssh_run(ip, remote, timeout_s=20, root=False):
            ran.append(("key", ip, remote, False))
            if remote.startswith("systemd-run"):
                state[ip] = state[ip].split("UPG=")[0]          # everything installed
                return 0, "RC=0\n", ""
            return 0, state[ip], ""
        a.actions._ssh_run = ssh_run

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            ran.append(("pw", ip, remote, sudo_pw))
            if "systemd-run" in remote:
                return 0, "RC=100\n", ""
            return 0, state[ip], ""
        a.access.ssh = ssh
        a.updates.start = lambda reason: out.setdefault("refreshed", reason)
        ac = a.actions
        out["no"] = await ac.ask("apt_upgrade", "192.168.10.35", "telegram")
        out["vps"] = await ac.ask("apt_upgrade", "203.0.113.10", "dashboard")
        p = ac.items[-1]
        out["p"] = dict(p)
        chk = await ac._check(p)
        out["res"] = await ac._run(p, chk)
        p.update(status="rejected", decided_ts=time.time(), decided_by="dashboard")
        out["empty"] = await ac.ask("apt_upgrade", "203.0.113.10", "dashboard")
        p2 = {"ip": "192.168.10.113", "action": "apt_upgrade", "name": "VM HomeHub"}
        chk2 = await ac._check(p2)
        out["res2"] = await ac._run(p2, chk2)
        out["ran"] = ran
        out["spec"] = ac.spec()["function"]["description"]
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("only on: 203.0.113.10, 192.168.10.113" in out["no"].get("refused", ""),
          "only the hosts configured for it")
    p = out["p"]
    check(out["vps"].get("proposal") and p["check"] == "2 update(s) waiting (1 security)"
          and p["risk"] == ["tunnels may drop"], "the VPS: proposed, with what is waiting and the risk")
    up = [r for r in out["ran"] if "systemd-run" in r[2]]
    check(up[0][0] == "key" and "--with-new-pkgs upgrade" in up[0][2] and "NEEDRESTART_MODE=l" in up[0][2]
          and "force-confold" in up[0][2], "apt-get under systemd-run, config kept, needrestart only lists")
    r = out["res"]
    check(r["ok"] and r["result"].startswith("2 package(s) updated;") and "reboot is now pending" in r["result"],
          f"the result: what was installed, what is left, a reboot now pending ({r.get('result')})")
    check(out["refreshed"] == "after an upgrade", "the Updates card refreshes at once")
    check("nothing to update" in out["empty"].get("refused", ""), "nothing waiting: refused")
    check(up[1][0] == "pw" and up[1][3] and up[1][2].startswith("sudo -S -p '' sh -c '"),
          ".99: through sudo, with the list's password on its stdin")
    check(not out["res2"]["ok"] and "apt-get failed (exit 100)" in out["res2"]["error"], "a failed apt-get says so")
    check("apt_upgrade" in out["spec"] and "203.0.113.10" in out["spec"], "the model knows where it may propose it")


def test_routeros_update():
    print("\n-- RouterOS: check, download (nothing changes if it fails), reboot, version back --")
    out = {}
    real = (U.ROS_POLL_S,)

    async def go(d):
        m, a = _auditor(d)
        U.ROS_POLL_S = 0
        a.cfg["actions"]["catalog"]["routeros_upgrade"] = {"hosts": {
            "192.168.10.32": {"risk": "Wi-Fi off"}, "192.168.20.1": {}}}
        st = {"inst": "6.49.21", "latest": "6.49.22", "status": "New version is available",
              "download": "Downloaded, please reboot router to upgrade it", "fw": "6.49.22", "fw_new": "6.49.22"}
        cmds = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            cmds.append(remote)
            if remote == "/system resource print":
                return 0, "uptime: 3w\n version: 6.49.21\n board-name: wAP R ac\n", ""
            if remote.startswith("/interface wireless"):
                return 0, "", ""
            if remote.endswith("download"):
                st["status"] = st["download"]
                return 0, "", ""
            if remote == "/system routerboard print":
                return 0, f"routerboard: yes\n current-firmware: {st['fw']}\n upgrade-firmware: {st['fw_new']}\n", ""
            if remote == "/system routerboard upgrade":
                out.setdefault("fw_flash", []).append(stdin)
                st["flashed"] = True
                return 0, "", ""
            if remote.startswith("/system package update print"):
                return 0, (f"channel: stable\n installed-version: {st['inst']}\n"
                           f" latest-version: {st['latest']}\n status: {st['status']}\n"), ""
            return 0, "", ""
        a.access.ssh = ssh

        async def reboot_run(ip, name, chk, via="", back_s=0, hold_s=0):
            out["reboot_args"] = (via, back_s, hold_s)
            out["reboots"] = out.get("reboots", 0) + 1
            st["inst"] = st["latest"]
            if st.pop("flashed", False):
                st["fw"] = st["fw_new"]
            return {"ok": True, "ran": True, "result": "rebooted — answering again after 95 s (up 60 s)"}
        a.actions.reboot.run = reboot_run
        a.updates.start = lambda reason: None
        ac = a.actions
        out["router"] = await ac.ask("routeros_upgrade", "192.168.10.113", "telegram")
        a._last_report = {"wan_state": "backup"}
        out["antenna"] = await ac.ask("routeros_upgrade", "192.168.20.1", "telegram")
        a._last_report = {"wan_state": "ok"}
        out["ap"] = await ac.ask("routeros_upgrade", "192.168.10.32", "dashboard")
        p = ac.items[-1]
        out["p"] = dict(p)
        chk = await ac._check(p)
        st["download"] = "ERROR: not enough disk space"
        out["fail"] = await ac._run(p, chk)
        st["download"], st["status"] = "Downloaded, please reboot router to upgrade it", "New version is available"
        out["ok"] = await ac._run(p, chk)
        p.update(status="rejected", decided_ts=time.time(), decided_by="dashboard")
        # the morning's row still says 6.49.21 and a security release behind: the press's check
        # brings it up to date
        a.updates.rec["hosts"]["192.168.10.32"] = {"kind": "routeros", "name": "AP-Porch", "installed": "6.49.21",
                                                 "latest": "6.49.22", "security_releases": ["6.49.22"],
                                                 "fw": "6.49.21", "fw_new": "6.49.21", "ts": time.time() - 4 * 3600}
        out["latest"] = await ac.ask("routeros_upgrade", "192.168.10.32", "dashboard")
        out["ros_row"] = next(h for h in a.updates.view()["hosts"] if h["ip"] == "192.168.10.32")
        # firmware only: RouterOS current, the RouterBOARD not — one flash, one reboot
        st.update(fw="6.45.9", fw_new="6.49.22")
        out["reboots"] = 0
        chk2 = await ac._check({"action": "routeros_upgrade", "ip": "192.168.10.32", "name": "AP-Porch"})
        out["fw_check"] = chk2
        out["fw_only"] = await ac._run({"action": "routeros_upgrade", "ip": "192.168.10.32", "name": "AP-Porch"}, chk2)
        out["fw_reboots"] = out["reboots"]
        # both: RouterOS behind and the firmware after it — two reboots
        st.update(inst="6.49.21", latest="6.49.22", status="New version is available", fw="6.45.9", fw_new="6.49.22")
        out["reboots"] = 0
        chk3 = await ac._check({"action": "routeros_upgrade", "ip": "192.168.10.32", "name": "AP-Porch"})
        out["both"] = await ac._run({"action": "routeros_upgrade", "ip": "192.168.10.32", "name": "AP-Porch"}, chk3)
        out["both_reboots"] = out["reboots"]
        out["cmds"] = cmds
    try:
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        (U.ROS_POLL_S,) = real
    check("only on: 192.168.10.32, 192.168.20.1" in out["router"].get("refused", ""),
          "only the MikroTiks configured for it (the main router is not)")
    check("internet is on the Uplink" in out["antenna"].get("refused", ""),
          "never the antenna while the network runs on it")
    p = out["p"]
    check(out["ap"].get("proposal") and p["check"].startswith("RouterOS 6.49.21 → 6.49.22, then its firmware (one more reboot); wAP R ac")
          and p["risk"] == ["Wi-Fi off"], f"proposed with what it will install ({p.get('check')})")
    check("/system package update check-for-updates once" in out["cmds"], "the check asks MikroTik first")
    f = out["fail"]
    check(not f["ok"] and not f["ran"] and "nothing was installed" in f["error"] and "not enough disk space" in f["error"],
          f"a download that fails: nothing changed, and why ({f.get('error')})")
    ok = out["ok"]
    check(ok["ok"] and ok["result"].startswith("RouterOS 6.49.21 → 6.49.22; answering again after 95 s"),
          f"downloaded, rebooted, the new version read back ({ok.get('result')})")
    check(out["reboot_args"] == ("routeros", U.ROS_BACK_S, 600.0),
          "the reboot is the Reboot button's, with room for the install (8 min back, 10 min hold)")
    rr = out["ros_row"]
    check(not rr["ros_behind"] and rr["security"] == 0 and rr["updates"] == 0 and rr["fw"] == "6.49.22"
          and rr["os"] == "RouterOS 6.49.22", "the press's check brings the MikroTik's row up to date too")
    check("already on the latest RouterOS (6.49.22) and its firmware is current" in out["latest"].get("refused", ""),
          "already on the latest, firmware current: refused")
    check(out["fw_check"]["ok"] and out["fw_check"]["note"].startswith("RouterBOARD firmware 6.45.9 → 6.49.22 (one reboot)"),
          "firmware only: offered, with what it will flash")
    fo = out["fw_only"]
    check(fo["ok"] and fo["result"].startswith("firmware 6.45.9 → 6.49.22; answering again") and out["fw_reboots"] == 1
          and out["fw_flash"][0] == b"y\n",
          f"firmware only: /system routerboard upgrade (+ the 'y'), one reboot, version read back ({fo.get('result')})")
    b = out["both"]
    check(b["ok"] and b["result"].startswith("RouterOS 6.49.21 → 6.49.22; firmware 6.45.9 → 6.49.22;") and out["both_reboots"] == 2,
          f"both: RouterOS, then the firmware — two reboots ({b.get('result')})")


def test_installed_by_itself():
    print("\n-- installed by itself since the check: the press says so, and the row is brought up to date --")
    out = {}
    # the morning check lists openssl + libssl3t64; unattended-upgrades installs them half an hour
    # later; Update must bring the row up to date, not say "nothing to update" all day
    fresh = UBUNTU.format(rb=0).replace("REBOOT", "XREBOOT")
    fresh = "\n".join(x for x in fresh.splitlines() if not x.startswith("UPG=")) + "\n"
    # the VPS keeps UTC: its 06:59 is lanowl's local time of that instant
    inst = time.mktime(time.strptime(time.strftime("%Y-%m-%d") + " 08:59:44", "%Y-%m-%d %H:%M:%S"))
    hist = ("Start-Date: " + time.strftime("%Y-%m-%d  %H:%M:%S", time.gmtime(inst))
            + "\nCommandline: /usr/bin/unattended-upgrade\nTZ=+0000\n")

    async def go(d):
        a = _auditor(d)[1]
        a.cfg["actions"]["catalog"]["apt_upgrade"] = {"hosts": {"203.0.113.10": {"via": "key"}}}
        a.updates.rec["hosts"]["203.0.113.10"] = {"kind": "linux", "name": "VPS", "via": "key", "ts": time.time() - 4 * 3600,
                                                  **U.parse_linux(UBUNTU.format(rb=0).replace("REBOOT", "XREBOOT"))}
        out["before"] = next(h for h in a.updates.view()["hosts"] if h["ip"] == "203.0.113.10")["security"]
        cmds = []

        async def ssh_run(ip, remote, timeout_s=20, root=False):
            cmds.append(remote)
            return 0, (hist if "history.log" in remote else fresh), ""
        a.actions._ssh_run = ssh_run
        out["r"] = await a.actions.ask("apt_upgrade", "203.0.113.10", "dashboard")
        out["after"] = next(h for h in a.updates.view()["hosts"] if h["ip"] == "203.0.113.10")
        out["name"] = a.updates.rec["hosts"]["203.0.113.10"].get("name")
        out["secupd"] = [f for f in a.updates.findings() if f["key"] == "secupd:203.0.113.10"]
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = out["r"].get("refused", "")
    check(out["before"] == 1 and "nothing to update" in r and "openssl" in r and "installed afterwards, at 08:59, by" in r
          and "unattended-upgrades" in r, f"the press: installed by itself, when (in lanowl's time, not the machine's UTC) and by what ({r})")
    check(out["after"]["security"] == 0 and out["after"]["updates"] == 0 and not out["secupd"] and out["name"] == "VPS",
          "the row brought up to date at once, its name kept")


def test_phased_and_presses():
    print("\n-- Ubuntu's phased updates are not offered; the owner's presses: no cooldown, one at a time --")
    out = {}
    phased_state = UBUNTU.format(rb=0).replace("REBOOT", "XREBOOT") + "PHASED=  apparmor libapparmor1\n"
    phased_state = phased_state.replace("UPG=openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]\n", "")
    phased_state = phased_state.replace("UPG=vim/", "UPG=apparmor/") + "UPG=libapparmor1/noble-updates 4.0.1 amd64 [upgradable from: 4.0.0]\n"
    f = U.parse_linux(phased_state)
    out["parsed"] = [(u["pkg"], u["phased"]) for u in f["updates"]]

    async def go(d):
        a = _auditor(d)[1]
        a.cfg["actions"]["catalog"]["apt_upgrade"] = {"hosts": {"203.0.113.10": {"via": "key"}}}

        async def ssh_run(ip, remote, timeout_s=20, root=False):
            return 0, phased_state, ""
        a.actions._ssh_run = ssh_run
        out["only_phased"] = await a.actions.ask("apt_upgrade", "203.0.113.10", "dashboard")
        a.updates.rec["hosts"]["203.0.113.10"] = {"kind": "linux", **f, "name": "VPS"}
        out["finding"] = [x["text"] for x in a.updates.findings() if x["key"] == "upd:203.0.113.10"]
        out["view"] = next(h for h in a.updates.view()["hosts"] if h["ip"] == "203.0.113.10")
        # one running on the machine: a second press is refused, and says why
        a.actions.items.append({"id": 90, "action": "reboot", "ip": "203.0.113.10", "status": "running", "ts": time.time()})
        out["busy"] = await a.actions.ask("apt_upgrade", "203.0.113.10", "dashboard")
        # ...and no cooldown for the owner: an update that ran ten minutes ago does not block
        a.actions.items[-1].update(status="done", done_ts=time.time() - 600, outcome={"ran": True},
                                   action="apt_upgrade")
        a.actions.reboot  # noqa
        out["cool"] = a.actions._limits({"action": "apt_upgrade", "ip": "203.0.113.10", "via": "dashboard", "owner": True}, time.time())
        out["cool_model"] = a.actions._limits({"action": "apt_upgrade", "ip": "203.0.113.10", "via": "telegram"}, time.time())
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["parsed"] == [("apparmor", True), ("libapparmor1", True)], "held back by phasing: read from apt-get -s")
    check("held back by Ubuntu's phased rollout, they install by themselves" in out["only_phased"].get("refused", ""),
          "only phased ones waiting: no update offered, and why")
    check(out["finding"] and "held back by Ubuntu's phased rollout" in out["finding"][0], "the list says so too")
    check(out["view"]["updates"] == 0 and out["view"]["phased"] == 2, "the row: nothing to update, 2 held back")
    check("is running on it right now" in out["busy"].get("refused", ""), "a press while one runs there: refused, with why")
    check(out["cool"] == "" and "not again for 60 min" in out["cool_model"],
          "the cooldown binds the model's proposals, never the owner's own press")


def test_unconfirmed():
    print("\n-- the scan: backported builds and major-only versions are unconfirmed, never paged --")
    out = {}

    async def go(d):
        a, u = _auditor(d)[1], None
        u = a.updates
        u.rec["hosts"] = {"192.168.10.113": {"kind": "linux"}, "192.168.10.111": {"kind": "esxi"}}
        mk = lambda prod, ver, cid="CVE-2024-1", cvss=9.8: {"port": 22, "product": prod, "version": ver, "id": cid, "cvss": cvss, "exploit": False}
        out["deb"] = u.unconfirmed("192.168.10.35", mk("OpenSSH 9.2p1 Debian 2+deb12u7", "9.2p1 Debian 2+deb12u7"))
        out["apt"] = u.unconfirmed("192.168.10.113", mk("OpenSSH 9.6p1", "9.6p1"))
        out["samba"] = u.unconfirmed("192.168.10.31", mk("Samba smbd 4", "4"))
        out["gsoap"] = u.unconfirmed("192.168.10.31", mk("gSOAP 2.8", "2.8"))
        out["old_record"] = u.unconfirmed("192.168.10.31", {"product": "Samba smbd 4"})
        out["real"] = u.unconfirmed("192.168.10.103", mk("OpenSSH 10.3", "10.3"))
        out["esxi"] = u.unconfirmed("192.168.10.111", mk("OpenSSH 9.8", "9.8"))
        u.rec["scan"]["found"] = {"192.168.10.31": [mk("gSOAP 2.8", "2.8", "CVE-2017-9765", 8.1)],
                                  "192.168.10.103": [mk("OpenSSH 10.3", "10.3", "CVE-2026-60002", 9.4),
                                                   mk("OpenSSH 10.3 Debian", "10.3 Debian", "CVE-2026-1", 7.5)]}
        out["f"] = {f["ip"]: f for f in u.findings() if f["key"].startswith("cve:")}
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("backported" in out["deb"], "a Debian build: unconfirmed (fixes are backported)")
    check("apt" in out["apt"], "a machine the daily check reads through apt: unconfirmed")
    check("major version" in out["samba"] and "major version" in out["gsoap"] and "major version" in out["old_record"],
          "'Samba smbd 4', gSOAP '2.8' (records from before this, too): unconfirmed")
    check(out["real"] == "", "OpenSSH 10.3 matching a <10.4 CVE: a real version match")
    check("VMware" in out["esxi"], "ESXi's sshd (VMware's build, '9.8' for 9.8p1): unconfirmed")
    # before the check of cves.py has run on a scan, the rule above stands
    f = out["f"]
    check(not f["192.168.10.31"]["page"] and "none of its 1 CVE match" in f["192.168.10.31"]["text"]
          and "1 can't be judged" in f["192.168.10.31"]["text"], "only unclear: listed, never paged")
    check(f["192.168.10.103"]["page"] and "1 known vulnerability ≥ CVSS 7 applies" in f["192.168.10.103"]["text"]
          and "not checked yet" in f["192.168.10.103"]["text"], "a real version match pages until checked")


def test_apt_watch():
    print("\n-- a running apt upgrade: its latest line from the machine's journal, for the page --")
    out = {}
    real = U.APT_WATCH_S

    async def go(d):
        m, a = _auditor(d)
        a.cfg["actions"]["catalog"]["apt_upgrade"] = {"hosts": {"192.168.10.113": {"via": "password"}}}
        calls = []
        answers = [(0, "N=3\nSetting up libssl3:amd64 (3.0.13-0ubuntu3.6) ...\n", ""),
                   (None, "", "timed out")]

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            calls.append((remote, sudo_pw))
            return answers.pop(0) if answers else (None, "", "timed out")
        a.access.ssh = ssh
        p = {"id": 9, "status": "running", "action": "apt_upgrade", "ip": "192.168.10.113"}
        a.actions._cur = p
        U.APT_WATCH_S = 0.01
        t = asyncio.ensure_future(a.updates._apt_watch("192.168.10.113", 1790000000.0, 8))
        for _ in range(400):
            await asyncio.sleep(0.005)
            if (p.get("detail") or {}).get("n"):
                break
        out["first"] = dict(p.get("detail") or {})
        for _ in range(400):
            await asyncio.sleep(0.005)
            if (p.get("detail") or {}).get("error"):
                break
        out["second"] = dict(p.get("detail") or {})
        t.cancel()
        out["calls"] = calls
    try:
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        U.APT_WATCH_S = real
    f = out["first"]
    check(f.get("text") == "Setting up libssl3:amd64 (3.0.13-0ubuntu3.6) ..." and f.get("n") == 3
          and f.get("of") == 8, f"the latest line and how many are set up: {f}")
    s2 = out["second"]
    check(s2.get("error") == "no answer from it right now" and s2.get("text") == f.get("text"),
          "no answer: said so, the last line kept")
    cmd, sudo = out["calls"][0]
    check(sudo and "journalctl -u" in cmd and "lanowl-apt-upgrade-*" in cmd
          and "--since @1789999995" in cmd, "read from the upgrade unit's own journal, as root")


def test_dismiss():
    print("\n-- the owner dismisses what matters: gone from it, silent, until something new --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        now = time.time()
        u = a.updates
        u.enabled = True
        u.rec["last_done"] = now
        u.rec["hosts"]["192.168.10.113"] = {
            "kind": "linux", "name": "VM HomeHub", "reboot_since": now - 5 * 86400,
            "reboot_pkgs": ["linux-image"], "lists_ts": now,
            "updates": [{"pkg": "openssl", "security": True}, {"pkg": "vim", "security": False}]}
        u.rec["first_seen"]["192.168.10.113"] = {"openssl": now - 4 * 86400}
        u.rec["ports"] = {"192.168.10.34": [23]}
        ssh_cve = {"id": "CVE-2026-60002", "cvss": 9.4, "product": "OpenSSH 10.3", "version": "10.3",
                   "port": 22}
        u.rec["scan"]["found"] = {"192.168.10.103": [dict(ssh_cve)]}
        sent = []
        a._emit_telegram = lambda kind, text: sent.append(text)
        keys = lambda: sorted(f["key"] for f in u.findings() if f["page"])
        out["before"] = keys()
        # a non-urgent one too (the Security tab is one list, Dismiss on every row)
        out["upd"] = u.dismiss("upd:192.168.10.113", "it can wait")
        out["upd_marked"] = any(f["key"] == "upd:192.168.10.113" and f.get("dismissed") for f in u.findings())
        u.undismiss("upd:192.168.10.113")
        out["no_such"] = u.dismiss("port:192.168.10.34:21")
        for k, note in (("cve:192.168.10.103", "patched by the next macOS"),
                        ("port:192.168.10.34:23", "the alarm panel cannot turn telnet off"),
                        ("reboot:192.168.10.113", "")):
            out.setdefault("ok", []).append(u.dismiss(k, note)["ok"])
        out["after"] = keys()
        fs = u.findings()
        out["dis"] = {f["key"]: f.get("dismissed") for f in fs if f.get("dismissed")}
        out["view_fp"] = any("fp" in f for f in u.view()["findings"])
        out["weekly"] = u.weekly_lines()[0]
        out["tg"] = a.chat.updates_text()
        await u._announce(fs)
        out["sent1"] = list(sent)
        out["announced"] = list(u.rec["announced"])
        out["undo"] = u.undismiss("reboot:192.168.10.113")
        await u._announce(u.findings())
        out["sent2"] = sent[len(out["sent1"]):]
        # the same scan again: still dismissed
        u._prune_dismissed(u.findings())
        out["same_scan"] = "cve:192.168.10.103" in u.rec["dismissed"]
        # the port closes, then opens again: still dismissed, until undone
        u.rec["ports"] = {}
        u._prune_dismissed(u.findings())
        u.rec["ports"] = {"192.168.10.34": [23]}
        out["port_back"] = "port:192.168.10.34:23" in keys()
        # a new CVE on the Mac: back in what matters, the dismissal lifted
        u.rec["scan"]["found"] = {"192.168.10.103": [dict(ssh_cve), {**ssh_cve, "id": "CVE-2026-61111"}]}
        out["new_cve"] = "cve:192.168.10.103" in keys()
        u._prune_dismissed(u.findings())
        out["lifted"] = "cve:192.168.10.103" not in u.rec["dismissed"]
        # a host that could not be read keeps its dismissals; a new pending reboot lifts one
        u.dismiss("reboot:192.168.10.113")
        u.rec["hosts"]["192.168.10.113"]["error"] = "ssh timed out"
        u._prune_dismissed(u.findings())
        out["kept_on_error"] = "reboot:192.168.10.113" in u.rec["dismissed"]
        del u.rec["hosts"]["192.168.10.113"]["error"]
        u.rec["hosts"]["192.168.10.113"]["reboot_since"] = now - 4 * 86400
        out["new_reboot"] = "reboot:192.168.10.113" in keys()
        # it survives a restart
        u._save()
        out["reloaded"] = sorted(U.Updates(a).rec["dismissed"])
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["before"] == ["cve:192.168.10.103", "port:192.168.10.34:23", "reboot:192.168.10.113",
                            "secupd:192.168.10.113"], f"four things matter: {out['before']}")
    check(out["upd"]["ok"] and out["upd_marked"] and not out["no_such"]["ok"],
          "anything in the list can be dismissed — the not urgent too — but only what is there")
    check(out["ok"] == [True] * 3 and out["after"] == ["secupd:192.168.10.113"],
          "dismissed: out of what matters, the rest stays")
    check(out["dis"]["port:192.168.10.34:23"]["note"] == "the alarm panel cannot turn telnet off"
          and out["dis"]["cve:192.168.10.103"]["ts"], "with when, and the owner's reason")
    check(not out["view_fp"], "the page gets no fingerprints")
    check("☑️" in out["tg"] and "dismissed: the alarm panel cannot turn telnet off" in out["tg"],
          "/updates says what was dismissed, and why")
    check("3 dismissed by the owner as known" in out["weekly"]
          and "owner: the alarm panel cannot turn telnet off" in out["weekly"],
          "the weekly review (the model) knows, with the reason")
    check(len(out["sent1"]) == 1 and "security update" in out["sent1"][0]
          and "telnet" not in out["sent1"][0] and "reboot pending" not in out["sent1"][0],
          "Telegram pages only what is not dismissed")
    check(out["undo"]["ok"] and out["sent2"] == [], "undone: back in what matters, but not paged again")
    check(out["same_scan"], "the same scan again: still dismissed")
    check(not out["port_back"], "a port closed and reopened stays dismissed, until undone")
    check(out["new_cve"] and out["lifted"], "a new CVE on the device: back, the dismissal lifted")
    check(out["kept_on_error"], "a host that could not be read keeps its dismissals")
    check(out["new_reboot"], "a new pending reboot comes back")
    check("port:192.168.10.34:23" in out["reloaded"], "dismissals survive a restart")


if __name__ == "__main__":
    for fn in [test_parsing, test_the_daily_check, test_when, test_the_scan, test_install_updates,
               test_routeros_update, test_installed_by_itself, test_phased_and_presses, test_unconfirmed, test_apt_watch,
               test_dismiss]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
