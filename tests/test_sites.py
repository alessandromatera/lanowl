"""The sites — the main one, a VPS, remote ones: run with `python -m tests.test_sites`.

No network, no router — ssh is a fake that answers the way an OpenWrt and a RouterOS router
do. Pinned down here (sites.py):

  1. a device's site is where its address falls; the main site by default;
  2. both routers' DHCP is read right (OpenWrt's leases file, RouterOS's terse print);
  3. the owner watches a device from a site's DHCP: it joins the inventory (ping, behind the
     site's router, at the site's criticality), survives a restart, follows its MAC, and
     stops when unwatched; one not on the DHCP list, or already watched, is refused;
  4. checks from a site's router: a ping (both dialects), its DHCP, a speed test timed on the
     router (to the second on RouterOS); site_ping and site_dhcp are PASSIVE, the speed test
     is not; a wrong site is refused; the tools reach every site's network, not only the main one;
  5. the dashboard's view: each site's devices up, the down ones named, the DHCP rows marked;
  6. the update check reads OpenWrt and UniFi machines: release, uptime, Wi-Fi clients.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import sites as SI
from lanowl import updates as U
from lanowl.checks import PASSIVE, CheckError
from tests.test_actions import _auditor

_fails = []

SITES = {"sites": {"dhcp_every_min": 30, "list": [
    {"key": "home", "name": "Home", "nets": ["192.168.10.0/24", "192.168.20.0/24"]},
    {"key": "vps", "name": "VPS", "nets": ["203.0.113.10/32", "10.8.0.1/32"]},
    {"key": "lake", "name": "Lake", "nets": ["10.8.0.16/32", "192.168.108.0/24"], "router": "10.8.0.16",
     "kind": "openwrt", "criticality": "warning"},
    {"key": "acme", "name": "Acme", "nets": ["10.9.0.0/24", "192.168.0.0/24"], "router": "10.9.0.10",
     "kind": "routeros", "criticality": "info"}]}}

OPENWRT_LEASES = ("1790546704 aa:bb:cc:00:00:01 192.168.108.101 A26-di-Rosette 01:aa:bb:cc:00:00:01\n"
                  "1790546697 aa:bb:cc:00:00:02 192.168.108.102 * *\n")
ROS_LEASES = ('0 address=192.168.0.20 mac-address=11:22:33:44:55:66 server=dhcp1 status=bound '
              'active-address=192.168.0.20 active-mac-address=11:22:33:44:55:66 host-name="PC-Office"\n'
              '1 D address=192.168.0.31 mac-address=11:22:33:44:55:77 status=waiting\n')
ROS_PING = ("  SEQ HOST SIZE TTL TIME STATUS\n    0 8.8.8.8 56 117 36ms\n"
            "    sent=3 received=3 packet-loss=0% min-rtt=31ms avg-rtt=34ms max-rtt=36ms\n")
BB_PING = ("--- 8.8.8.8 ping statistics ---\n3 packets transmitted, 3 packets received, 0% packet loss\n"
           "round-trip min/avg/max = 31.072/32.033/33.664 ms\n")
ROS_FETCH = ("      status: downloading\n  downloaded: 845KiB\n    duration: 1s\n\n"
             "      status: finished\n  downloaded: 10240KiB\n       total: 10240KiB\n    duration: 4s\n")


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _run(go):
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))


def _fake_ssh(a, answers, calls):
    async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
        calls.append((ip, remote, user_suffix))
        for (want_ip, needle), ans in answers.items():
            if ip == want_ip and needle in remote:
                return ans
        return None, "", "no route"
    a.access.ssh = ssh


def test_where_and_leases():
    print("\n-- where a device is; both routers' DHCP read right --")
    out = {}

    async def go(d):
        m, a = _auditor(d, SITES)
        s = a.sites
        out["of"] = [s.of(x) for x in ("192.168.10.31", "192.168.20.1", "203.0.113.10", "10.8.0.1",
                                        "10.8.0.16", "192.168.108.50", "10.9.0.10", "192.168.0.7", "8.8.8.8", "x")]
        out["remote"] = [x["key"] for x in s.remote()]
    _run(go)
    check(out["of"] == ["home", "home", "vps", "vps", "lake", "lake", "acme", "acme", "home", "home"],
          f"by address, the network by default ({out['of']})")
    check(out["remote"] == ["lake", "acme"], "the sites with a router lanowl logs into")
    o = SI.parse_openwrt_leases(OPENWRT_LEASES)
    check(o == [{"mac": "aa:bb:cc:00:00:01", "ip": "192.168.108.101", "name": "A26-di-Rosette", "expires": 1790546704},
                {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.108.102", "name": "", "expires": 1790546697}],
          "OpenWrt: MAC, address, name ('*' = none)")
    r = SI.parse_routeros_leases(ROS_LEASES)
    check([(x["ip"], x["mac"], x["name"]) for x in r] == [("192.168.0.20", "11:22:33:44:55:66", "PC-Office"),
                                                          ("192.168.0.31", "11:22:33:44:55:77", "")],
          "RouterOS: the active address when there is one, the name when given")


def test_watch_follow_unwatch():
    print("\n-- the owner watches a device from a site's DHCP --")
    out = {}

    async def go(d):
        m, a = _auditor(d, SITES)
        a._persist_alerts = True
        calls = []
        _fake_ssh(a, {("10.8.0.16", "dhcp.leases"): (0, OPENWRT_LEASES, "")}, calls)
        s = a.sites
        s.rec["read"] = 0
        s.tick(time.time())
        await asyncio.sleep(0.05)
        out["read"] = [r["ip"] for r in s.rec["leases"]["lake"]["rows"]]
        out["no_row"] = s.watch("lake", "de:ad:be:ef:00:00")
        out["w"] = s.watch("lake", "aa:bb:cc:00:00:01", "Tablet Lake")
        out["again"] = s.watch("lake", "aa:bb:cc:00:00:01")
        # a device on a network of the site's that is not routed here (Acme's 192.168.180.x)
        s.rec["leases"]["acme"] = {"ts": time.time(), "rows": [
            {"mac": "24:ce:33:19:2e:d8", "ip": "192.168.180.245", "name": ""}]}
        out["unrouted"] = s.watch("acme", "24:ce:33:19:2e:d8")
        dev = a.inv.get("192.168.108.101")
        out["dev"] = (dev.name, dev.group, dev.criticality, dev.checks, dev.attrs.get("depends_on"), dev.attrs.get("site"))
        out["listed"] = {x["key"]: x["watched"] for x in s.view({})["sites"]}
        # a restart: a new Sites puts it back into the inventory
        a.inv.remove("192.168.108.101")
        SI.Sites(a)
        out["restored"] = a.inv.get("192.168.108.101") is not None
        # DHCP moved it
        s._follow(s.get("lake"), [{"mac": "aa:bb:cc:00:00:01", "ip": "192.168.108.140", "name": "x"}])
        out["moved"] = (a.inv.get("192.168.108.140") is not None, a.inv.get("192.168.108.101") is None,
                        "192.168.108.140" in s.rec["watch"])
        out["un"] = s.unwatch("192.168.108.140")
        out["gone"] = a.inv.get("192.168.108.140") is None
        out["un2"] = s.unwatch("192.168.108.140")
        out["view"] = s.view({"devices": [{"ip": "10.8.0.16", "name": "Lake router", "up": False},
                                          {"ip": "192.168.10.31", "name": "NVR", "up": True},
                                          {"ip": "203.0.113.10", "name": "VPS", "up": True}]})
    _run(go)
    check(out["read"] == ["192.168.108.101", "192.168.108.102"], "the site's DHCP is read on the sweep's tick")
    check(not out["no_row"]["ok"] and "not on the site's list" in out["no_row"]["error"], "only a device on its list")
    check(out["w"]["ok"] and out["w"]["name"] == "Tablet Lake" and not out["again"]["ok"], "watched once, not twice")
    check(not out["unrouted"]["ok"] and "not routed" in out["unrouted"]["error"],
          "a device on a network the tunnels do not carry is refused (it would ping a house guest)")
    check(out["dev"] == ("Tablet Lake", "remote", "warning", [{"type": "icmp"}], "10.8.0.16", "lake"),
          f"pinged, behind the site's router, at the site's criticality ({out['dev']})")
    check(out["listed"]["lake"] == [{"ip": "192.168.108.101", "name": "Tablet Lake", "mac": "aa:bb:cc:00:00:01"}]
          and out["listed"]["acme"] == [], "each site lists what it watches — the sheet's Stop watching")
    check(out["restored"], "it survives a restart")
    check(out["moved"] == (True, True, True), "DHCP moved it: it follows its MAC")
    check(out["un"]["ok"] and out["gone"] and not out["un2"]["ok"], "unwatched: out of the inventory")
    v = {x["key"]: x for x in out["view"]["sites"]}
    check(v["lake"]["down"] == ["Lake router"] and v["home"]["up"] == 1 and v["vps"]["total"] == 1,
          "each site's devices up, the down ones named")
    rows = v["lake"]["dhcp"]["rows"]
    check(len(rows) == 2 and all(r["routed"] and not r["known"] for r in rows),
          "the DHCP rows nobody watches, routed or not, known or not")


def test_site_checks():
    print("\n-- checks from a site's router --")
    out = {}

    async def go(d):
        m, a = _auditor(d, SITES)
        calls = []
        _fake_ssh(a, {("10.9.0.10", "/ping"): (0, ROS_PING, ""),
                      ("10.8.0.16", "ping -c"): (0, BB_PING, ""),
                      ("10.9.0.10", "/tool fetch"): (0, ROS_FETCH, ""),
                      ("10.8.0.16", "wget -q -O /dev/null"): (0, "RC=0 START=100.00 END=102.50\n", ""),
                      ("10.9.0.10", "lease print"): (0, ROS_LEASES, "")}, calls)
        C = a.actions.checks
        run = lambda name, **k: C.plan(name, k)   # noqa: E731
        out["ros_ping"] = await C.run(await run("site_ping", site="acme", target="8.8.8.8", count=3))
        out["bb_ping"] = await C.run(await run("site_ping", site="lake", target="8.8.8.8"))
        out["ros_speed"] = await C.run(await run("site_speed_test", site="acme"))
        out["bb_speed"] = await C.run(await run("site_speed_test", site="lake"))
        out["dhcp"] = await C.run(await run("site_dhcp", site="acme"))
        out["calls"] = calls
        try:
            await run("site_ping", site="mars", target="8.8.8.8")
            out["bad"] = None
        except CheckError as e:
            out["bad"] = str(e)
        out["cmd"] = (await run("site_ping", site="lake", target="192.168.108.1", count=2))["command"]
        out["sweep_remote"] = await run("ping_sweep", subnet="192.168.108.0/24")
    _run(go)
    check(out["ros_ping"]["ok"] and "3/3 answered, 0% loss, avg 34ms" in out["ros_ping"]["summary"]
          and "Acme's router" in out["ros_ping"]["summary"], f"RouterOS ping read ({out['ros_ping']['summary']})")
    check(out["bb_ping"]["ok"] and "3/3 answered" in out["bb_ping"]["summary"] and "avg 32ms" in out["bb_ping"]["summary"],
          f"busybox ping read ({out['bb_ping']['summary']})")
    check(out["ros_speed"]["ok"] and "about 21 Mbit/s" in out["ros_speed"]["summary"] and "to the second" in out["ros_speed"]["summary"],
          f"RouterOS: 10 MB in the LAST duration, said to the second ({out['ros_speed']['summary']})")
    check(out["bb_speed"]["ok"] and "33.6 Mbit/s" in out["bb_speed"]["summary"],
          f"OpenWrt: timed on the router ({out['bb_speed']['summary']})")
    ros_calls = [c for c in out["calls"] if c[0] == "10.9.0.10"]
    check(all(c[2] == "+ct" for c in ros_calls) and any("keep-result=no" in c[1] for c in ros_calls)
          and any("-O /dev/null" in c[1] for c in out["calls"]), "nothing is written to either router")
    check(out["dhcp"]["ok"] and "2 device(s) on Acme's DHCP" in out["dhcp"]["summary"]
          and "PC-Office" in out["dhcp"]["output"], "its DHCP, now")
    check(out["bad"] and "lake, acme" in out["bad"], "a wrong site is refused, and the right ones named")
    check(out["cmd"] == "lake's router: ping 192.168.108.1 ×2", f"the command as the owner reads it ({out['cmd']})")
    check(out["sweep_remote"]["args"]["subnet"] == "192.168.108.0/24", "the tools reach Lake's network too, not only the network")
    check({"site_ping", "site_dhcp"} <= PASSIVE and "site_speed_test" not in PASSIVE,
          "a ping and the DHCP are passive; the speed test (their bandwidth) is not")


def test_updates_openwrt_unifi():
    print("\n-- the update check reads OpenWrt and UniFi machines --")
    o = U.parse_openwrt("DISTRIB_DESCRIPTION='OpenWrt 23.05.0 r23497-6637af95aa'\nMODEL=GL.iNet GL-AR150\n"
                        "UPTIME=86441.40\nWIFI=phy0-ap0 6\nWIFI=phy1-ap0 2\n")
    check(o == {"os": "OpenWrt 23.05.0 r23497-6637af95aa (GL.iNet GL-AR150)", "uptime": 86441.4,
                "clients": 8, "radios": 2}, f"release, board, uptime, clients over all radios ({o})")
    n = U.parse_openwrt("DISTRIB_DESCRIPTION='LEDE Reboot 17.01.7 r4030-6028f00df0'\nMODEL=TP-Link TL-MR3420 v1\nUPTIME=12\n")
    check(n["clients"] is None and n["os"].startswith("LEDE Reboot 17.01.7"), "no iwinfo: clients unknown, not zero")
    u = U.parse_unifi("Model:       U7-Lite\nVersion:     8.6.11.18870\nUptime:      7614223 seconds\n")
    check(u == {"os": "UniFi U7-Lite 8.6.11.18870", "uptime": 7614223.0}, "UniFi: model, version, uptime")
    f = U.parse_unifi("ETCVERSION=BZ2.8.6.11\nBOARD=U7-Lite\nUPTIME=7614223.12\n")
    check(f == {"os": "UniFi U7-Lite BZ2.8.6.11", "uptime": 7614223.12}, "without mca-cli-op: its version file")
    check("mca-cli-op info" in U.UNIFI and "info;" not in U.UNIFI, "not the interactive-only `info`")
    out = {}

    async def go(d):
        m, a = _auditor(d, SITES)
        _fake_ssh(a, {("192.168.10.8", "openwrt_release"): (0, "DISTRIB_DESCRIPTION='OpenWrt 23.05.0'\nWIFI=phy0-ap0 6\n", ""),
                      ("192.168.10.136", "mca-cli-op"): (0, "Model: U7-Lite\nVersion: 8.6.11\n", "")}, [])
        out["ow"] = await a.updates._host({"ip": "192.168.10.8", "via": "openwrt"})
        out["uf"] = await a.updates._host({"ip": "192.168.10.136", "via": "unifi"})
        out["no"] = await a.updates._host({"ip": "192.168.10.200", "via": "unifi"})
    _run(go)
    check(out["ow"]["kind"] == "openwrt" and out["ow"]["clients"] == 6, "an OpenWrt machine in the check")
    check(out["uf"]["kind"] == "unifi" and out["uf"]["os"] == "UniFi U7-Lite 8.6.11", "the U7 in the check")
    check("cannot read it" in out["no"]["error"], "one that does not answer says so")


def test_by_hand_in_the_weekly():
    print("\n-- what the owner keeps doing by hand, in the weekly review --")
    from lanowl import weekly
    out = {}

    async def go(d):
        m, a = _auditor(d, SITES)
        now = time.time()
        a.actions.items += [{"id": 900 + i, "action": "shelly_reboot", "ip": "192.168.10.57", "name": "Shelly pump",
                             "owner": True, "status": "done", "ts": now - i * 86400, "done_ts": now - i * 86400}
                            for i in range(4)]
        a.actions.items += [{"id": 950, "action": "reboot", "ip": "192.168.10.31", "name": "NVR", "owner": True,
                             "status": "done", "ts": now, "done_ts": now},
                            {"id": 951, "action": "shelly_reboot", "ip": "192.168.10.57", "name": "Shelly pump",
                             "status": "done", "ts": now, "done_ts": now},             # the model's: not counted
                            {"id": 952, "action": "shelly_reboot", "ip": "192.168.10.57", "name": "Shelly pump",
                             "owner": True, "status": "done", "ts": now - 40 * 86400, "done_ts": now - 40 * 86400}]
        out["b"] = a.actions.by_hand(now)
    _run(go)
    check(out["b"] == [{"action": "Reboot the Shelly", "device": "Shelly pump (192.168.10.57)", "n": 4}],
          f"the owner's own, the same thing on the same device, 3+ times in 30 days ({out['b']})")
    t = weekly.format_weekly({"by_hand": out["b"]}, None)
    check("🔁 By hand, again and again: Reboot the Shelly — Shelly pump (192.168.10.57), 4× in 30 days" in t
          and "standing order" in t, "one line in the weekly review, offering a standing order")


def test_uniform_dhcp_known_and_the_house():
    """Every site's DHCP the same — the main site's too — with
    Watch and Known; Known replaces editing discovery.ignore_macs by hand."""
    print("\n-- every site's DHCP the same: the network's too, Watch and Known --")
    from lanowl import discovery as DI
    out = {}

    async def go(d):
        cfg = {**SITES, "discovery": {"ignore_macs": ["AA:AA:AA:AA:AA:01"]}}
        m, a = _auditor(d, cfg)
        a._persist_alerts = True
        leases = [{"status": "bound", "address": "192.168.10.201", "mac-address": "AA:AA:AA:AA:AA:01", "host-name": "phone-ale"},
                  {"status": "bound", "address": "192.168.10.202", "mac-address": "AA:AA:AA:AA:AA:02", "host-name": "laptop"},
                  {"status": "bound", "address": "192.168.10.203", "mac-address": "AA:AA:AA:AA:AA:03", "host-name": ""},
                  {"status": "bound", "address": "192.168.10.31", "mac-address": "AA:AA:AA:AA:AA:04", "host-name": "nvr"}]
        a._discovery = DI.compute(leases, a.inv, a.cfg, known_macs=a.sites.known_macs("home"))
        s = a.sites
        rows, read, err = s.rows("home")
        out["rows"] = [(r["ip"], r["known"], r["known_by"]) for r in rows]
        out["k"] = s.know("home", "aa:aa:aa:aa:aa:02")
        out["now"] = (a._discovery["unknown_count"], [x["ip"] for x in a._discovery["ignored"]])
        # the next DHCP read keeps it known
        a._discovery = DI.compute(leases, a.inv, a.cfg, known_macs=s.known_macs("home"))
        out["next"] = a._discovery["unknown_count"]
        out["undo_config"] = s.know("home", "aa:aa:aa:aa:aa:01", False)
        out["undo"] = s.know("home", "aa:aa:aa:aa:aa:02", False)
        out["after_undo"] = a._discovery["unknown_count"]
        out["w"] = s.watch("home", "aa:aa:aa:aa:aa:03", "Printer")
        dev = a.inv.get("192.168.10.203")
        out["dev"] = (dev.group, dev.criticality, dev.attrs.get("depends_on")) if dev else None
        v = {x["key"]: x for x in s.view({})["sites"]}
        out["house_dhcp"] = v["home"].get("dhcp", {}).get("unknown")
        out["vps_dhcp"] = "dhcp" in v["vps"]
        out["sec"] = a.chat.security_text()
        out["sites"] = a.chat.sites_text()
    _run(go)
    check(out["rows"] == [("192.168.10.201", True, "config"), ("192.168.10.202", False, ""), ("192.168.10.203", False, "")],
          f"the network's rows: not the inventory's, the config's known marked as such ({out['rows']})")
    check(out["k"]["ok"] and out["now"][0] == 1 and "192.168.10.202" in out["now"][1] and out["next"] == 1,
          "Known: out of the unknown count at once, and at the next DHCP read")
    check(not out["undo_config"]["ok"] and out["undo"]["ok"] and out["after_undo"] == 2,
          "Undo for a Known of yours; the config's stay the config's")
    check(out["w"]["ok"] and out["dev"] == ("watched", "low", None), "a house device watched: low, behind nothing")
    check(out["house_dhcp"] == 1 and not out["vps_dhcp"], "each site with a DHCP says how many nobody knows")
    check(out["sec"].startswith("🛡 <b>Security</b>") and "Worth fixing" in out["sec"] and "nobody knows" not in out["sec"].split("Worth")[0],
          "/security: what matters first; unknown devices are not urgent")
    check("<b>Home</b>" in out["sites"] and "1 unknown on its network" in out["sites"], "/sites: each site, its unknown")


def test_one_check_now():
    print("\n-- one Check now: the update check goes on into the model's review --")
    out = {"started": []}

    async def go(d):
        m, a = _auditor(d, SITES)
        a.updates.enabled, a.updates.hosts = True, []
        a.exposure.enabled = True
        a.exposure.start = lambda why: out["started"].append(why) or True

        async def none():
            return {}
        a.updates._insecure_ports = none
        await a.updates.run("dashboard")
        await a.updates.run("scheduled")
    _run(go)
    check(out["started"] == ["check now"], "the owner's Check now starts the review; the morning's is started by its own clock")


def test_vendor():
    print("\n-- who made it, from the MAC — offline --")
    from lanowl import oui
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write("# comment\nB827EB Raspberry Pi Foundation\n000C29 VMware\n70B3D5123 Some MA-S Maker\n")
        path = fh.name
    oui._table = None
    try:
        check(oui.vendor("b8:27:eb:12:34:56", path) == "Raspberry Pi Foundation", "a maker by its prefix")
        check(oui.vendor("70-B3-D5-12-3F-00", path) == "Some MA-S Maker", "the longest block first, any spelling")
        check(oui.vendor("8e:b3:7d:55:09:c8", path) == oui.PRIVATE, "a randomized address says so")
        check(oui.vendor("01:00:5e:00:00:01", path) == "" and oui.vendor("", path) == "", "multicast or nothing: no answer")
        check(oui.vendor("00:11:22:33:44:55", path) == "", "unknown: empty, not a guess")
    finally:
        oui._table = None
        os.unlink(path)


if __name__ == "__main__":
    for fn in [test_where_and_leases, test_watch_follow_unwatch, test_site_checks, test_updates_openwrt_unifi,
               test_by_hand_in_the_weekly, test_uniform_dhcp_known_and_the_house, test_one_check_now,
               test_vendor]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
