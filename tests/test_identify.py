"""Find my devices and Try (identify.py, trylogin.py, the setup's routes): `python -m tests.test_identify`.

No network: the probe's answers and the devices' answers are fakes.
Pinned down here:

  1. what a device is, from what answers: Winbox is a MikroTik, 8123 Home Assistant, /shelly a
     Shelly, LuCI an OpenWrt, a Reolink's maker, RTSP a camera, ssh's greeting a Linux machine, a
     VMware card with OpenSSH a virtual machine (never an ESXi host), a private MAC a phone —
     each with the reason said, a group and how much it matters;
  2. its name: the DHCP name, a Shelly's own, a useful page title, else what it is and its
     last number; a maker as people say it ("Reolink", not "Reolink Innovation Limited");
  3. only a home network's addresses are probed or tried; a probe is kept an hour;
  4. a router's own networks for "Make it a site": its LAN and its address, not the tunnel's;
  5. Try never shows a password: what comes back is scrubbed.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import identify as I
from lanowl import trylogin as T
from lanowl.oui import PRIVATE
from lanowl.settingsweb import router_nets, site_nets_guess

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def test_identify():
    print("\n-- what a device is, from what answers --")
    cases = [
        ({"ip": "192.168.88.1", "vendor": "Routerboard.com"}, {"open": [22, 80, 8291], "ssh": "SSH-2.0-ROSSSH"},
         ("mikrotik", "network", "port 8291 answers (Winbox)")),
        ({"ip": "192.168.88.12", "vendor": "Raspberry Pi Trading"}, {"open": [22, 8123]},
         ("homeassistant", "servers", "port 8123 answers like Home Assistant")),
        ({"ip": "192.168.88.40", "vendor": "Espressif"}, {"open": [80], "shelly": {"name": "Pump", "app": "Pro1", "gen": "2"}},
         ("shelly", "iot", "/shelly says Pro1")),
        ({"ip": "192.168.88.4", "vendor": "GL Technologies (Hong Kong)"}, {"open": [22, 80], "title": "LuCI"},
         ("openwrt", "network", "its web page is LuCI")),
        ({"ip": "192.168.88.30", "vendor": "Reolink Innovation Limited"}, {"open": [80, 554, 9000]},
         ("reolink", "cameras", "port 9000 answers like a Reolink")),
        ({"ip": "192.168.88.33", "vendor": "Hikvision"}, {"open": [554]}, ("", "cameras", "port 554 answers (RTSP video)")),
        ({"ip": "192.168.88.34", "vendor": ""}, {"open": [80, 554, 9000]}, ("reolink", "cameras", "port 9000 answers like a Reolink")),
        ({"ip": "192.168.88.11", "vendor": ""}, {"open": [22], "ssh": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"},
         ("linux", "servers", "ssh says SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")),
        ({"ip": "192.168.88.93", "vendor": "VMware"}, {"open": [22], "ssh": "SSH-2.0-OpenSSH_9.6"},
         ("linux", "servers", "VMware network card, ssh says SSH-2.0-OpenSSH_9.6")),
        ({"ip": "192.168.88.50", "vendor": "HP"}, {"open": [631]}, ("", "misc", "IPP printing on port 631")),
        ({"ip": "192.168.88.101", "vendor": PRIVATE}, {"open": []}, ("", "phones", "a private MAC: it hides its own")),
        ({"ip": "192.168.88.103", "vendor": "Apple"}, {"open": []}, ("", "phones", "Apple, no open port")),
        ({"ip": "192.168.88.60", "vendor": "Espressif"}, {"open": []},
         ("", "unknown", "answers nothing but ping: give it a name, or leave it")),
    ]
    for row, probe, (kind, group, why) in cases:
        r = I.identify(row, probe)
        check((r["kind"], r["group"], r["why"]) == (kind, group, why),
              f"{row['ip']} ({row['vendor'] or 'no maker'}): kind {r['kind'] or '-'}, {r['group']}, \"{r['why']}\"")
    vm = I.identify({"ip": "192.168.88.93", "vendor": "VMware"}, {"open": [22], "ssh": "SSH-2.0-OpenSSH_9.6"})
    check(vm["kind"] != "esxi", "a VMware network card is a virtual machine's: never guessed an ESXi host")
    esxi = I.identify({"ip": "192.168.88.8", "vendor": "Supermicro"}, {"open": [22, 443], "title": "VMware ESXi"})
    check(esxi["kind"] == "esxi", "an ESXi host says so on its own page")
    check(I.identify({"ip": "192.168.88.101", "vendor": PRIVATE}, {"open": []})["phone"], "a phone is marked: listed, not ticked")
    print("\n-- its name --")
    check(I.identify({"ip": "192.168.88.40", "vendor": "Espressif", "name": ""}, {"open": [80], "shelly": {"name": "Pump", "app": "Pro1"}})["name"] == "Pump",
          "a Shelly's own name")
    check(I.identify({"ip": "192.168.88.9", "vendor": "", "name": "nas"}, {"open": [22], "ssh": "SSH-2.0-OpenSSH_9 Debian"})["name"] == "nas",
          "the DHCP name first")
    check(I.identify({"ip": "192.168.88.30", "vendor": "Reolink Innovation Limited"}, {"open": [9000]})["name"] == "Reolink 30",
          "else what it is and its last number")
    check(I.identify({"ip": "192.168.88.7", "vendor": ""}, {"open": [80], "title": "Login"})["name"] == "Login 7",
          "a page called Login is no name")
    check(I.short_vendor("Reolink Innovation Limited") == "Reolink" and I.short_vendor("GL Technologies (Hong Kong)") == "GL"
          and I.short_vendor("Espressif Inc.") == "Espressif" and I.short_vendor(PRIVATE) == PRIVATE,
          "a maker as people say it")


def test_probe_rules():
    print("\n-- only a home network's addresses; a probe is kept an hour --")
    out = {}

    async def go():
        calls = []
        real = I._port

        async def port(ip, p, sem):
            calls.append((ip, p))
            return None
        I._port = port
        try:
            out["public"] = await I.probe("203.0.113.5", now=1000)
            out["lan"] = await I.probe("192.168.88.77", now=1000)
            n = len(calls)
            out["first"] = sorted(p for ip, p in calls if ip == "192.168.88.77")
            out["again"] = await I.probe("192.168.88.77", now=1000 + 600)
            out["kept"] = len(calls) == n
            await I.probe("192.168.88.77", now=1000 + 3700)
            out["expired"] = len(calls) > n
            out["calls"] = calls
        finally:
            I._port = real
    asyncio.run(go())
    check(out["public"].get("skipped") and not any(c[0] == "203.0.113.5" for c in out["calls"]), "a public address is never probed")
    check(out["lan"]["open"] == [] and out["first"] == sorted(I.PORTS),
          "a home address: the few ports, each once")
    check(out["kept"] and out["expired"], "asked again within the hour: kept; after it: asked again")
    check(not T.allowed("8.8.8.8") and T.allowed("10.1.2.3") and not T.allowed("127.0.0.1"), "Try: a home network's addresses only")


def test_router_nets():
    print("\n-- a router's own networks, for Make it a site --")
    ros = ("0   address=10.8.0.9/24 network=10.8.0.0 interface=wg0\n"
           "1   address=192.168.70.1/24 network=192.168.70.0 interface=bridge\n"
           "2 D address=100.64.1.5/30 network=100.64.1.4 interface=pppoe-out1\n")
    check(router_nets("10.8.0.9", ros) == ["192.168.70.0/24", "10.8.0.9/32"],
          "RouterOS: its LAN and its own address — not the tunnel's /24, not the provider's")
    owrt = "1: lo    inet 127.0.0.1/8 scope host lo\n2: br-lan    inet 192.168.70.1/24 brd 192.168.70.255\n5: wg0    inet 10.8.0.16/24 scope global wg0\n"
    check(router_nets("10.8.0.16", owrt) == ["192.168.70.0/24", "10.8.0.16/32"], "OpenWrt's `ip addr` the same way")
    check(router_nets("10.8.0.9", "") == [], "nothing read: nothing made up")
    check(site_nets_guess({"sites": {"list": [{"key": "home", "nets": ["192.168.88.0/24"]}]}}, "10.8.0.9") == ["10.8.0.9/32"]
          and site_nets_guess({"mikrotik": {"dhcp_source": "http://192.168.88.1"}}, "192.168.88.3") == ["192.168.88.0/24"],
          "without its list: only its own address when it is far, its /24 on lanowl's side")


def test_try_scrub():
    print("\n-- Try never gives a password back --")
    check(T._scrub("Permission denied for p4ss-w0rd!", "p4ss-w0rd!") == "Permission denied for ••••", "scrubbed")
    check(T._last("Warning: added host key\nPermission denied (publickey,password).\n") == "Permission denied (publickey,password).",
          "the device's last line, as it said it")
    r = asyncio.run(T.try_login(None, "reolink", "192.168.88.30", "admin", ""))
    check(not r["ok"] and r["said"] == "type its user and password first", "nothing typed: nothing sent")
    r = asyncio.run(T.try_login(None, "linux", "203.0.113.5", "root", "x"))
    check(not r["ok"] and "home network" in r["said"], "a public address is never tried")


if __name__ == "__main__":
    for fn in (test_identify, test_probe_rules, test_router_nets, test_try_scrub):
        fn()
    print(f"\n{len(_fails)} FAILED" if _fails else "\nall passed")
    sys.exit(1 if _fails else 0)
