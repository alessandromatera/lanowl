"""New devices on the network's DHCP, and every device ever seen: `python -m tests.test_new_devices`.

A guest network's clients are on the same DHCP and are checked for new devices too, and every
device ever seen is remembered — a friend who comes back after months is recognised. No
router, no model: the leases are a fake, the audit's verdict is written here. Pinned down:

  1. the guest Wi-Fi's clients are marked `guest`;
  2. every MAC is remembered for good: new = never seen before; a friend back after 100 days
     is "here since" the first visit, not new;
  3. the hourly audit gets the new ones apart and first (the 12-by-address cap cannot hide
     them), every unknown device with its first-seen date;
  4. an issue the audit raises about a new device sends ONE message — none for a device that
     is not new, none twice, not even after a restart;
  5. the dashboard's DHCP rows say new / here since / guest; the log of every device ever seen
     is newest first, with what each is now; Ask can search it;
  6. a device with a fixed address — in the router's ARP table, no lease, or found by the
     monthly scan, on every site — is listed and can be new; what was there at the first look is not new; Lake's
     site keeps its own record, its ARP table and its monthly scan too; both routers' tables
     and RouterOS's ip-scan are read right;
  7. an address with no lease that is only a STALE entry in the router's table (a phone gone,
     its lease over — 10-05, at Lake's) is said as that, never as a fixed address.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import discovery as DI
from lanowl import sites as SI
from lanowl.model import Inventory
from lanowl.prompts import build_user_context
from lanowl.sites import HOUSE
from tests.test_actions import _auditor

_fails = []

CFG = {"discovery": {"guest_nets": ["192.168.180.0/24"], "new_window_h": 24,
                     "ignore_macs": ["AA:00:00:00:00:09"]},
       "sites": {"list": [{"key": "home", "name": "Home", "nets": ["192.168.10.0/24", "192.168.180.0/24"]}]}}

FRIEND = "B8:27:EB:11:22:33"        # a friend's laptop, last here three months ago
PI = "DC:A6:32:44:55:66"            # a Raspberry Pi nobody added, on the LAN tonight
PHONE = "8E:B3:7D:55:09:C8"         # a guest's phone, private address, on the guest Wi-Fi
DISH = "AA:00:00:00:00:09"          # the dishwasher, in ignore_macs
SWITCH = "00:0C:42:AA:BB:01"        # a switch with a fixed address, there since forever
ROGUE = "00:0C:42:AA:BB:02"         # a fixed address set tonight

LAKE = {"sites": {"list": [
    {"key": "home", "name": "Home", "nets": ["192.168.10.0/24", "192.168.180.0/24"]},
    {"key": "lake", "name": "Lake", "nets": ["10.8.0.16/32", "192.168.108.0/24"], "router": "10.8.0.16",
     "kind": "openwrt", "criticality": "warning"}]}}
PROC_ARP = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.108.101    0x1         0x2         aa:bb:cc:00:00:01     *        br-lan\n"
            "192.168.108.2      0x1         0x2         aa:bb:cc:00:00:05     *        br-lan\n"
            "192.168.108.77     0x1         0x0         00:00:00:00:00:00     *        br-lan\n")


def lease(ip, mac, host=""):
    return {"address": ip, "mac-address": mac, "host-name": host, "status": "bound", "dynamic": "true"}


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _run(go):
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))


def test_guest_marked():
    print("\n-- the guest Wi-Fi's clients are marked --")
    d = DI.compute([lease("192.168.180.12", PHONE), lease("192.168.10.150", PI)], Inventory(devices=[]), CFG)
    g = {x["ip"]: x["guest"] for x in d["unknown"]}
    check(g == {"192.168.180.12": True, "192.168.10.150": False}, "192.168.180.x is the guest Wi-Fi, the LAN is not")
    check(DI.guest_nets({"discovery": {"guest_nets": ["nonsense"]}}) == [], "a bad network is ignored, not fatal")


def arp(ip, mac, status="reachable"):
    return {"address": ip, "mac-address": mac, "status": status, "interface": "bridge-lan", "complete": "true"}


def test_remembered_and_told():
    print("\n-- remembered for good; new = never seen; one message per new device --")
    out = {}

    async def go(d):
        m, a = _auditor(d, CFG)
        sent = []
        a._emit_telegram = lambda ch, text, *x, **k: sent.append((ch, text))
        now = time.time()
        # the friend's first visit, 100 days ago — and lanowl has a baseline since
        a.state.mark_seen([{"ip": "192.168.10.160", "mac": FRIEND, "host": "Marcos-Laptop"},
                           {"ip": "192.168.10.137", "mac": DISH, "host": ""}], now - 100 * 86400)
        a.state.mark_seen([{"ip": "192.168.10.160", "mac": FRIEND, "host": "Marcos-Laptop"}], now - 90 * 86400)
        leases = [lease("192.168.10.160", FRIEND, "Marcos-Laptop"), lease("192.168.10.150", PI),
                  lease("192.168.180.12", PHONE), lease("192.168.10.137", DISH)]

        async def fetch_leases(cfg):
            return leases

        arps = [[arp("192.168.10.2", SWITCH), arp("192.168.10.66", "00:0C:42:AA:BB:99", "failed")]]

        async def fetch_arp(cfg):
            return arps[-1]
        real = DI.fetch_leases, DI.fetch_arp
        DI.fetch_leases, DI.fetch_arp = fetch_leases, fetch_arp
        try:
            a._last_discovery = 0
            await a.run_discovery(now)                # the fixed addresses' first look: the switch
            out["switch_first"] = [x.get("how") for x in a._discovery["unknown"] if x["mac"] == SWITCH]
            out["switch_new"] = SWITCH in [x["mac"] for x in a._discovery["recent_new"]]
            arps.append(arps[-1] + [arp("192.168.10.201", ROGUE)])
            a._last_discovery = 0
            await a.run_discovery(now + 60)           # a fixed address set tonight
        finally:
            DI.fetch_leases, DI.fetch_arp = real
        disc = a._discovery
        out["recent"] = [x["mac"] for x in disc["recent_new"]]
        out["friend_first"] = next(x["first_seen"] for x in disc["unknown"] if x["mac"] == FRIEND)
        out["first_ts"] = now - 100 * 86400
        ctx = build_user_context({"devices": [], "ts": now}, [], [], {}, {}, discovery=disc,
                                 new_devices=a.sites.recent_new())
        out["ctx"] = ctx
        rows = {r["mac"]: r for r in a.sites.rows(HOUSE)[0]}
        out["rows"] = rows

        # the audit's verdict: an issue on the Pi (new) and on the friend (not new); the
        # guest's phone only in the summary
        llm = {"overall_health": "ok", "summary": "A guest phone joined the guest Wi-Fi.",
               "issues": [{"device": "Raspberry Pi", "ip": "192.168.10.150", "severity": "info",
                           "root_cause": "a single-board computer nobody added, on the LAN at night",
                           "recommendation": "check who plugged it in; mark it Known or Watch it"},
                          {"device": "Marcos-Laptop", "ip": "192.168.10.160", "severity": "info",
                           "root_cause": "x", "recommendation": "y"}]}
        a._tell_new_devices(llm)
        a._tell_new_devices(llm)                     # the next hourly audit says it again
        out["sent"] = list(sent)
        # a restart: the new process has been told too
        m2, a2 = _auditor(d, CFG)
        sent2 = []
        a2._emit_telegram = lambda ch, text, *x, **k: sent2.append(text)
        a2._discovery = disc
        a2._tell_new_devices(llm)
        out["sent_after_restart"] = sent2

        # the log of everything ever seen, and Ask
        a._mac_index = DI.build_mac_index(leases)
        out["seen"] = a.sites.seen()
        r = await a.executor.call("lanowl_records", {"topic": "devices_seen", "search": FRIEND.lower()[:8]})
        res = (r or {}).get("result") or {}
        out["ask"] = json.loads(res["records"]) if "records" in res else res

    _run(go)
    check(out["switch_first"] == ["arp"] and not out["switch_new"],
          "a fixed address at the first look is listed, and not new (the switch)")
    check(sorted(out["recent"]) == sorted([PI, PHONE, ROGUE]),
          "the Pi, the guest's phone and tonight's fixed address are new; the friend back after 90 days is not")
    check(abs(out["friend_first"] - out["first_ts"]) < 1, "the friend is 'here since' the first visit, 100 days ago")
    ctx = out["ctx"]
    new_line = next((ln for ln in ctx.splitlines() if ln.startswith("NEW_DEVICES")), "")
    unk_line = next((ln for ln in ctx.splitlines() if ln.startswith("UNKNOWN_DHCP_DEVICES")), "")
    check(PI in new_line and PHONE in new_line and FRIEND not in new_line,
          "the audit gets the new ones apart")
    check(ctx.index("NEW_DEVICES") < ctx.index("UNKNOWN_DHCP_DEVICES"), "...and first")
    check('"fixed_address": true' in new_line and ROGUE in new_line, "the model is told it took no DHCP lease")
    fday = time.strftime("%Y-%m-%d", time.localtime(out["first_ts"]))
    check(FRIEND in unk_line and fday in unk_line, "every unknown device carries its first-seen date")
    check('"guest": true' in new_line, "the guest Wi-Fi is marked for the model")
    rows = out["rows"]
    check(rows[PI.lower()]["new"] and not rows[FRIEND.lower()]["new"], "DHCP rows: the Pi is new, the friend is not")
    check(rows[PHONE.lower()]["guest"] and not rows[PI.lower()]["guest"], "DHCP rows: the guest Wi-Fi is marked")
    check(len(out["sent"]) == 1 and PI in out["sent"][0][1] and "192.168.10.150" in out["sent"][0][1],
          "ONE message, for the new device the audit raised — none for the friend, none twice")
    check("never seen here before" in out["sent"][0][1], "...saying it was never here before")
    check(out["sent_after_restart"] == [], "not again after a restart")
    seen = out["seen"]
    check([r["mac"] for r in seen][-1] in (FRIEND.lower(), DISH.lower()) and len(seen) == 6,
          "the log holds every device ever seen, fixed addresses too, newest first")
    check(next(r for r in seen if r["mac"] == ROGUE.lower())["fixed"], "...marked fixed address")
    s = {r["mac"]: r for r in seen}
    check(s[DISH.lower()]["status"] == "known" and s[PI.lower()]["status"] == "", "what each is now: known or nobody's")
    check(all(r["here"] for r in seen), "here now: every one holds a lease or is in the ARP table")
    ask = out["ask"]
    devs = (ask or {}).get("devices") or []
    check(len(devs) == 1 and devs[0]["mac"] == FRIEND.lower() and devs[0].get("first_seen"),
          "Ask finds the friend, with the first visit")


def test_gran():
    print("\n-- Lake's site: its own record, its ARP table, its monthly scan --")
    out = {}
    leases = ["1790546704 aa:bb:cc:00:00:01 192.168.108.101 A26-di-Rosette *\n"]
    procs = [PROC_ARP]

    async def go(d):
        m, a = _auditor(d, LAKE)
        calls = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            calls.append(remote)
            if "dhcp.leases" in remote:
                return 0, leases[-1], ""
            if remote.startswith("n=0; for a in"):             # the scan: then its ARP table
                return 0, procs[-1] + "192.168.108.9      0x1         0x2         aa:bb:cc:00:00:09     *        br-lan\n", ""
            if "/proc/net/arp" in remote:
                return 0, procs[-1], ""
            return None, "", "no route"
        a.access.ssh = ssh
        s = a.sites
        await s.read_all()                            # the first look: nothing new
        out["first"] = {r["mac"]: (r["how"], r["new"]) for r in s.rows("lake")[0]}
        leases.append(leases[-1] + "1790546800 aa:bb:cc:00:00:03 192.168.108.103 * *\n")
        procs.append(PROC_ARP + "192.168.108.3      0x1         0x2         aa:bb:cc:00:00:06     *        br-lan\n")
        await s.read_all()
        rows = {r["mac"]: r for r in s.rows("lake")[0]}
        out["second"] = {m_: (r["how"], r["new"]) for m_, r in rows.items()}
        out["recent"] = [(x["site"], x["mac"], x.get("how")) for x in s.recent_new()]
        r = s.start_scan("test")
        out["again"] = s.start_scan("test")          # one at a time
        await s._scan_task
        out["scan_ok"] = r.get("ok")
        out["scan_cmd"] = next((c for c in calls if c.startswith("n=0; for a in")), "")
        out["scan_rec"] = s.rec["scan"].get("lake")
        out["after_scan"] = {r["mac"]: (r["how"], r["new"]) for r in s.rows("lake")[0]}
        out["seen"] = [(r["site_name"], r["mac"], r["fixed"]) for r in s.seen() if r["site"] == "lake"]
        # her router has `ip`: the table with each entry's state, 00:05 not heard from lately
        procs.append("192.168.108.101 dev br-lan lladdr aa:bb:cc:00:00:01 REACHABLE\n"
                     "192.168.108.2 dev br-lan lladdr aa:bb:cc:00:00:05 STALE\n"
                     "192.168.108.3 dev br-lan lladdr aa:bb:cc:00:00:06 router DELAY\n"
                     "192.168.108.77 dev br-lan  FAILED\n")
        await s.read_all()
        out["stale"] = {r["mac"]: (r["how"], bool(r.get("stale"))) for r in s.rows("lake")[0]}
        # a year on: the scan just run must come before the day probed (a fixed date would go
        # stale the morning its scan was already done)
        y = time.localtime().tm_year + 1
        out["due"] = [s.scan_due(time.mktime((y, 10, s.scan_day, 4, 0, 0, 0, 0, -1))),
                      s.scan_due(time.mktime((y, 10, s.scan_day, 5, 30, 0, 0, 0, -1))),
                      s.scan_due(time.mktime((y, 10, s.scan_day + 1, 5, 30, 0, 0, 0, -1)))]

    _run(go)
    check(out["first"] == {"aa:bb:cc:00:00:01": ("dhcp", False), "aa:bb:cc:00:00:05": ("arp", False)},
          "the first look lists the lease and the fixed address (the incomplete entry left out), none new")
    sec = out["second"]
    check(sec.get("aa:bb:cc:00:00:03") == ("dhcp", True) and sec.get("aa:bb:cc:00:00:06") == ("arp", True)
          and sec.get("aa:bb:cc:00:00:05") == ("arp", False), "then a new lease and a new fixed address are new")
    check(sorted(out["recent"]) == [("lake", "AA:BB:CC:00:00:03", "dhcp"), ("lake", "AA:BB:CC:00:00:06", "arp")],
          "...and go to the audit, as Lake's")
    check(out["scan_ok"] and "192.168.108.1 " in out["scan_cmd"] and "192.168.108.254;" in out["scan_cmd"]
          and "ping -c1 -W1" in out["scan_cmd"], "the scan pings every address of 192.168.108.0/24, from her router")
    check(any(r["mac"] == "aa:bb:cc:00:00:09" for r in (out["scan_rec"] or {}).get("rows") or []),
          "a silent device the scan found is kept")
    check(out["after_scan"].get("aa:bb:cc:00:00:09") == ("scan", False),
          "...listed as found by the scan, and not new: the first scan is a first look too")
    check(("Lake", "aa:bb:cc:00:00:06", True) in out["seen"], "the log of every device holds Lake's, fixed ones marked")
    check(out["stale"].get("aa:bb:cc:00:00:05") == ("arp", True) and out["stale"].get("aa:bb:cc:00:00:06") == ("arp", False)
          and "aa:bb:cc:00:00:01" not in {m_ for m_, v in out["stale"].items() if v[1]},
          f"read with `ip neigh`: the stale entry is marked stale, the live ones are not ({out['stale']})")
    check(out["due"] == [False, True, False], f"monthly, on the day, after the hour ({out['due']})")
    check(out["again"].get("ok") is False, "one scan at a time")


def test_parsers():
    print("\n-- the routers' tables --")
    r = SI.parse_routeros_arp('0 D address=192.168.0.5 mac-address=11:22:33:44:55:66 interface=bridge status=reachable\n'
                              '1 D address=192.168.0.9 interface=bridge status=failed\n')
    check(r == [{"ip": "192.168.0.5", "mac": "11:22:33:44:55:66", "iface": "bridge"}], "RouterOS ARP, the failed entry left out")
    r = SI.parse_routeros_arp('0 D address=192.168.0.6 mac-address=11:22:33:44:55:67 interface=bridge status=stale\n'
                              '1 D address=192.168.0.7 mac-address=11:22:33:44:55:70 interface=bridge status=failed\n')
    check(len(r) == 1 and r[0].get("stale") is True,
          "RouterOS ARP: a stale entry is marked stale; a failed one is left out even with its MAC kept")
    n = SI.parse_ip_neigh("192.168.0.5 dev br-lan lladdr 11:22:33:44:55:66 REACHABLE\n"
                          "192.168.0.6 dev br-lan lladdr 11:22:33:44:55:67 STALE\n"
                          "192.168.0.1 dev wlan0 lladdr 11:22:33:44:55:68 router DELAY\n"
                          "192.168.0.9 dev br-lan  FAILED\n"
                          "fe80::1 dev br-lan lladdr 11:22:33:44:55:69 router STALE\n")
    check(n == [{"ip": "192.168.0.5", "mac": "11:22:33:44:55:66", "iface": "br-lan"},
                {"ip": "192.168.0.6", "mac": "11:22:33:44:55:67", "iface": "br-lan", "stale": True},
                {"ip": "192.168.0.1", "mac": "11:22:33:44:55:68", "iface": "wlan0"}],
          f"OpenWrt's `ip neigh`: IPv4 with a MAC, the stale one marked, failed and IPv6 left out ({n})")
    check(SI.parse_ip_neigh(PROC_ARP) == [], "...and /proc/net/arp is not mistaken for it (read by its own parser)")
    scan = ("Columns: ADDRESS, MAC-ADDRESS, TIME, DNS\n  ADDRESS      MAC-ADDRESS        TIME  DNS\n"
            "  192.168.0.1  4C:5E:0C:11:22:33  1ms   router.lan\n  192.168.0.20 11:22:33:44:55:77  3ms\n")
    check(SI.parse_pairs(scan) == [{"ip": "192.168.0.1", "mac": "4c:5e:0c:11:22:33"},
                                   {"ip": "192.168.0.20", "mac": "11:22:33:44:55:77"}], "RouterOS ip-scan's table")
    check([x["mac"] for x in SI.parse_proc_arp(PROC_ARP)] == ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:05"],
          "OpenWrt's /proc/net/arp, the incomplete entry left out")
    st = DI.static_from_arp([arp("192.168.10.2", SWITCH), arp("192.168.10.150", PI), arp("10.9.9.9", ROGUE),
                             arp("192.168.10.8", "00:0C:42:AA:BB:03", "failed")],
                            [lease("192.168.10.150", PI)], DI.guest_nets({"discovery": {"guest_nets": ["192.168.10.0/24"]}}))
    check([x["mac"] for x in st] == [SWITCH], "fixed = in ARP, on the network, no lease, not failed")
    st = DI.static_from_arp([arp("192.168.10.2", SWITCH, "stale")], [], DI.guest_nets({"discovery": {"guest_nets": ["192.168.10.0/24"]}}))
    check(st and st[0].get("stale") is True, "the main router's stale entry is marked stale")
    d = DI.compute([], Inventory([], {}), {}, static=st)
    check(d["unknown"] and d["unknown"][0].get("stale") is True, "...and stays marked in the unknown devices")


if __name__ == "__main__":
    for t in (test_guest_marked, test_remembered_and_told, test_gran, test_parsers):
        t()
    print("\nFAILED:\n  " + "\n  ".join(_fails) if _fails else "\nall ok")
    sys.exit(1 if _fails else 0)
