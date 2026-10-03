"""Remote-site tests (`depends_on` + per-device debounce): run with `python -m tests.test_remote`.

The sites behind a VPS's WireGuard tunnel — a family member's router, an office's — are
reached lanowl -> main router -> VPS -> peer, so every one of them goes dark whenever the main
link flaps, the VPS reboots, or the tunnel is re-keying on the new link after a failover. The rule pinned down
here is the rule for anything that pages: ONE message per incident. A parent that is
down explains its children; the children are named on its issue and never raise their own.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.model import Device, Inventory
from lanowl.prompts import build_user_context
from lanowl.report import build_report, shadowed_ips
from lanowl.state import StatusTracker
from lanowl.sweep import CheckResult, DeviceStatus, Snapshot

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


VPS, TUN, LAKE, OFFICE, LAN = "203.0.113.10", "10.8.0.1", "10.8.0.16", "10.9.0.10", "192.168.10.34"


def inventory(groups=None) -> Inventory:
    """The real chain: wan -> VPS -> tunnel -> {Lake, Acme}, plus one LAN device."""
    return Inventory(devices=[
        Device(VPS, "VPS", "vpn", "info", [{"type": "tcp", "port": 22, "name": "SSH"}],
               attrs={"depends_on": "wan", "debounce_fails": 5}),
        Device(TUN, "WireGuard tunnel to the VPS", "vpn", "info", [{"type": "icmp"}],
               attrs={"depends_on": VPS, "debounce_fails": 5}),
        Device(LAKE, "Lake router", "vpn", "info", [{"type": "icmp"}],
               attrs={"depends_on": TUN, "debounce_fails": 5}),
        Device(OFFICE, "Acme mikrotik router", "vpn", "info", [{"type": "icmp"}],
               attrs={"depends_on": TUN, "debounce_fails": 5}),
        Device(LAN, "Alarm", "security", "critical", [{"type": "icmp"}]),
    ], groups=groups or {"vpn": {"majority_down_critical": False}})


def snapshot(inv: Inventory, raw_down: set, wan_ok=True, failed: dict = None) -> Snapshot:
    """A sweep in which `raw_down` did not answer; `failed` = {ip: [check labels]} for
    devices that are up but with a service missing."""
    failed = failed or {}
    devs = []
    for d in inv.devices:
        up = d.ip not in raw_down
        checks = [CheckResult("icmp", up)]
        for label in failed.get(d.ip, []):
            checks.append(CheckResult("http", False, 80, name=label))
        devs.append(DeviceStatus(ip=d.ip, name=d.name, group=d.group,
                                 criticality=d.criticality, up=up, reachable=up,
                                 latency_ms=90.0 if up else None, checks=checks,
                                 attrs=d.attrs))
    return Snapshot(ts=0, devices=devs, wan={"8.8.8.8": wan_ok}, wan_ok=wan_ok)


def downs(rep) -> dict:
    return {i["ip"]: i for i in rep["issues"] if i["kind"] == "down"}


def test_per_device_debounce():
    print("a remote site needs its own number of missed sweeps, the LAN keeps the default")
    t = StatusTracker(debounce_fails=2, recovery_oks=1)
    check(t.update(LAN, False, 0) is None, "LAN: first miss is a blip")
    check(t.update(LAN, False, 60).kind == "down", "LAN: second miss confirms (global 2)")
    for i in range(4):
        check(t.update(LAKE, False, i * 60, debounce_fails=5) is None,
              f"remote: miss {i + 1} of 5 is still nothing")
    tr = t.update(LAKE, False, 240, debounce_fails=5)
    check(tr is not None and tr.kind == "down", "remote: the fifth miss confirms")
    check(t.update(LAKE, True, 300, debounce_fails=5).kind == "up",
          "recovery is unchanged (one good sweep)")
    # a two-minute failover re-key never becomes an outage
    t2 = StatusTracker(2, 1)
    for i in range(3):
        t2.update(LAKE, False, i * 60, debounce_fails=5)
    check(t2.update(LAKE, True, 180, debounce_fails=5) is None and t2.status(LAKE) is not False,
          "three missed sweeps then back: no transition at all")
    check(t2.update(LAN, False, 0, debounce_fails=None) is None
          and t2.update(LAN, False, 60, debounce_fails=None).kind == "down",
          "None means 'use the global threshold'")


def test_wan_down_explains_everything_remote():
    print("no internet: the WAN issue is the only word about the remote sites")
    inv = inventory()
    remote = {VPS, TUN, LAKE, OFFICE}
    rep = build_report(snapshot(inv, remote, wan_ok=False), inv, remote)
    kinds = [i["kind"] for i in rep["issues"]]
    check("wan" in kinds, "the WAN issue is raised")
    check(downs(rep) == {}, f"and not one remote device is its own issue ({list(downs(rep))})")
    check(rep["shadowed"] == {VPS: "wan", TUN: VPS, LAKE: TUN, OFFICE: TUN},
          f"the report says who explains whom ({rep['shadowed']})")
    check(all(not d["up"] for d in rep["devices"] if d["ip"] in remote),
          "the dashboard still shows them down — the truth is not hidden, only the alert")


def test_vps_down_is_one_issue_naming_the_sites():
    print("the VPS reboots: one issue, and it names everything behind it")
    inv = inventory()
    remote = {VPS, TUN, LAKE, OFFICE}
    rep = build_report(snapshot(inv, remote, wan_ok=True), inv, remote)
    d = downs(rep)
    check(set(d) == {VPS}, f"exactly one down issue, the VPS ({set(d)})")
    check(d[VPS]["severity"] == "info", "at the VPS's own severity: info, by choice")
    for name in ("WireGuard tunnel to the VPS", "Lake router", "Acme mikrotik router"):
        check(name in d[VPS]["detail"], f"…and it names '{name}'")
    check(rep["overall_health"] == "ok",
          "the whole overlay dark is news, not a fault of THIS network")


def test_tunnel_down_with_vps_up():
    print("VPS answers, tunnel dark: OUR tunnel is the issue, the sites ride on it")
    inv = inventory()
    dark = {TUN, LAKE, OFFICE}
    rep = build_report(snapshot(inv, dark, wan_ok=True), inv, dark)
    d = downs(rep)
    check(set(d) == {TUN}, f"only the tunnel is raised ({set(d)})")
    check(d[TUN]["severity"] == "info", "as info: a digest line, never a page")
    check("Lake router" in d[TUN]["detail"] and "Acme" in d[TUN]["detail"],
          "with both sites named on it")


def test_one_site_down_is_its_own_issue():
    print("tunnel up, Lake dark: that IS her site, reported on its own")
    inv = inventory()
    rep = build_report(snapshot(inv, {LAKE}, wan_ok=True), inv, {LAKE})
    d = downs(rep)
    check(set(d) == {LAKE}, f"Lake's router is the issue ({set(d)})")
    check("dark with it" not in d[LAKE]["detail"], "nothing hangs off it")
    check(rep["shadowed"] == {}, "nothing is shadowed")


def test_parent_raw_down_before_it_confirms():
    print("debounce order: a child must not slip out the sweep before its parent confirms")
    inv = inventory()
    # the VPS missed this sweep (raw) but is not yet confirmed; the tunnel already is
    snap = snapshot(inv, {VPS, TUN}, wan_ok=True)
    rep = build_report(snap, inv, {TUN})
    check(downs(rep) == {}, f"no issue at all this sweep ({list(downs(rep))})")
    check(rep["shadowed"] == {TUN: VPS}, "the tunnel is already filed under the VPS")


def test_up_child_is_never_shadowed():
    print("a device that answers is judged on its own, whatever its parent does")
    inv = inventory()
    # the VPS's public sshd died but the tunnel still works: the sites are fine and say so
    rep = build_report(snapshot(inv, {VPS}, wan_ok=True), inv, {VPS})
    d = downs(rep)
    check(set(d) == {VPS}, "the VPS is the issue")
    check("dark with it" not in d[VPS]["detail"], "and nothing is listed as dark with it")
    # a remote site that is UP but degraded is reported normally
    rep2 = build_report(snapshot(inv, set(), wan_ok=True, failed={OFFICE: ["http/80"]}),
                        inv, set())
    deg = [i for i in rep2["issues"] if i["kind"] == "degraded"]
    check(len(deg) == 1 and deg[0]["ip"] == OFFICE, "Acme's http going away is a degraded issue")


def test_shadowed_do_not_make_a_majority():
    print("a shadowed device does not count towards a group-majority escalation")
    inv = inventory(groups={"vpn": {"majority_down_critical": True}})
    dark = {TUN, LAKE, OFFICE}          # 3/4 of the group, but two of them are explained
    rep = build_report(snapshot(inv, dark, wan_ok=True), inv, dark)
    check(not any(i["kind"] == "group" for i in rep["issues"]),
          "tunnel + its two sites is not a majority of independent failures")
    # …whereas three sites failing on their own would be
    inv2 = Inventory(devices=[Device(f"10.8.0.{i}", f"site {i}", "vpn", "high",
                                     [{"type": "icmp"}]) for i in (16, 7, 8)],
                     groups={"vpn": {"majority_down_critical": True}})
    dark2 = {"10.8.0.16", "10.8.0.7"}
    rep2 = build_report(snapshot(inv2, dark2, wan_ok=True), inv2, dark2)
    check(any(i["kind"] == "group" for i in rep2["issues"]),
          "independent sites dark together still escalate")


def test_context_tells_the_model():
    print("the model is told which down devices are only a consequence")
    inv = inventory()
    dark = {TUN, LAKE, OFFICE}
    snap = snapshot(inv, dark, wan_ok=True)
    rep = build_report(snap, inv, dark)
    ctx = build_user_context(snap.to_dict(), snap.anomalies(), [], {}, inv.groups,
                             shadowed=rep["shadowed"])
    check("SHADOWED" in ctx, "there is a SHADOWED line")
    check("Lake router (10.8.0.16) behind WireGuard tunnel to the VPS (10.8.0.1)" in ctx,
          "naming the site and what it is behind")
    ctx2 = build_user_context(snap.to_dict(), snap.anomalies(), [], {}, inv.groups,
                              shadowed={})
    check("SHADOWED" not in ctx2, "and no such line when nothing is shadowed")


def test_no_depends_on_is_a_no_op():
    print("an inventory without depends_on behaves exactly as before")
    inv = Inventory(devices=[Device(LAN, "Alarm", "security", "critical", [{"type": "icmp"}])])
    check(shadowed_ips(snapshot(inv, {LAN}, wan_ok=False), {LAN}) == {},
          "nothing is ever shadowed")


if __name__ == "__main__":
    for fn in [test_per_device_debounce, test_wan_down_explains_everything_remote,
               test_vps_down_is_one_issue_naming_the_sites, test_tunnel_down_with_vps_up,
               test_one_site_down_is_its_own_issue, test_parent_raw_down_before_it_confirms,
               test_up_child_is_never_shadowed, test_shadowed_do_not_make_a_majority,
               test_context_tells_the_model, test_no_depends_on_is_a_no_op]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all remote-site tests passed")
