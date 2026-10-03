"""Renaming tests: run with `python -m tests.test_names`.

What these pin down (names.py): a name given on the dashboard sticks and can go back to
the inventory's; the device's history still belongs to it under its old name; and a device renamed
in the middle of an outage is not announced again — neither as new under its new name, nor as
recovered under its old one — nor loses the alert waiting in the outbox, nor its pause.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.alerts import NEW, RECOVERED, AlertGate
from lanowl.model import Device, Inventory
from lanowl.names import Names, clean, mac_key
from lanowl.pause import Pauses
from lanowl.sinks import TelegramOutbox

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def inv():
    return Inventory(devices=[
        Device("192.168.10.118", "Garage door", "home", "warning"),
        Device("192.168.108.243", "Lake", "remote", "warning",
               attrs={"watched": True, "mac": "aa:bb:cc:dd:ee:ff", "site": "lake"}),
    ])


def key(dev):     # main.Auditor._key
    return f"down:{dev.ip}:{dev.group}:{dev.name}"


def issue(dev, t):
    return {"device": dev.name, "ip": dev.ip, "group": dev.group, "severity": "critical",
            "kind": "down", "detail": "no answer", "since": t}


def rekey(ip, old, new):   # main.Auditor._rekey's mapping
    def nk(k):
        p = str(k).split(":", 3)
        return f"{p[0]}:{ip}:{p[2]}:{new}" if len(p) == 4 and p[1] == ip and p[3] == old else k
    return nk


def test_clean():
    check(clean("  Gate\n  garage \t") == "Gate garage", "one line, spaces collapsed")
    check(clean("\x1b[31mX") == "[31mX", "control characters dropped")
    check(len(clean("x" * 200)) == 60, "at most 60 characters")


def test_names_stick_and_go_back():
    iv, n = inv(), Names()
    g = iv.get("192.168.10.118")
    n.set(g, "Gate garage")
    n.apply(iv)
    check(g.name == "Gate garage" and g.attrs["listed_name"] == "Garage door", "renamed, the list's name kept")
    check(iv.owns("192.168.10.250", "Garage door") and iv.owns("192.168.10.250", "Gate garage"),
          "its history, recorded at another address under either name, is still its own")
    check(n.apply(iv) == [], "applying again changes nothing")
    again = Names(n.dump())
    iv2 = inv()
    again.apply(iv2)
    check(iv2.get("192.168.10.118").name == "Gate garage", "kept across a restart (the record)")
    again.set(iv2.get("192.168.10.118"), "")
    again.apply(iv2)
    check(iv2.get("192.168.10.118").name == "Garage door", "\"\" goes back to the list's name")


def test_by_mac_for_what_is_watched_from_a_site():
    iv, n = inv(), Names()
    lake = iv.get("192.168.108.243")
    check(Names.key(lake) == ("mac", "lake|aa:bb:cc:dd:ee:ff"), "a device watched from a site is named by site and MAC")
    n.set_key("mac", mac_key("lake", "AA:BB:CC:DD:EE:FF"), "Lake's tablet")
    n.apply(iv)
    check(lake.name == "Lake's tablet", "a name given on its DHCP row carries to the watched device")
    check(n.for_mac("lake", "aa:bb:cc:dd:ee:ff") == "Lake's tablet", "and the row shows it")


def test_an_open_incident_carries_over():
    iv, t = inv(), 1_790_000_000.0
    g = iv.get("192.168.10.118")
    gate = AlertGate(recovery_confirm_s=900, cooldown_s=3600)
    ev = gate.update({key(g): issue(g, t)}, t)
    check([e.kind for e in ev] == [NEW], "down: announced once")
    old = g.name
    iv.rename(g, "Gate garage")
    moved = gate.rekey(rekey(g.ip, old, g.name))
    check(moved == 1, "its episode moves to the new key")
    ev = gate.update({key(g): issue(g, t)}, t + 60)
    check(ev == [], "the next sweep, under the new name: no new alert, no recovery of the old one")
    gate.update({}, t + 120)
    ev = gate.update({}, t + 120 + 900)
    check([e.kind for e in ev] == [RECOVERED] and ev[0].issue["device"] == "Gate garage",
          "when it comes back: one recovery, under the new name")


def test_the_outbox_keeps_its_incident():
    path = os.path.join(tempfile.mkdtemp(), "outbox.json")
    ob = TelegramOutbox(path)
    ob.add("🔴 Garage door down", "down:192.168.10.118:home:Garage door")
    ob.rekey(rekey("192.168.10.118", "Garage door", "Gate garage"))
    it = TelegramOutbox(path)._items[0]
    check(it["key"] == "down:192.168.10.118:home:Gate garage" and it["keys"] == [it["key"]],
          "a queued alert is re-keyed, and saved so")


def test_a_pause_follows_the_new_name():
    ps = Pauses()
    ps.restore({"192.168.10.230": {"ts": 1.0, "by": "dashboard", "name": "Garage door"}})
    ps.renamed("192.168.10.230", "Gate garage")
    back = Pauses()
    back.restore(ps.dump(), known={"192.168.10.118": "Gate garage"})
    check(back.is_paused("192.168.10.118"), "paused at a DHCP address, renamed: the restore still finds it by name")


def test_the_auditors_rename():
    """Auditor.rename and _rekey themselves, on a stand-in holding only what they touch."""
    import json
    from lanowl.main import Auditor
    from lanowl.state import StateStore

    class A:
        rename, _rekey = Auditor.rename, Auditor._rekey

    a, t = A(), 1_790_000_000.0
    a.inv, a.names, a.pauses = inv(), Names(), Pauses()
    a.state = StateStore(os.path.join(tempfile.mkdtemp(), "s.sqlite"))
    a.gate = AlertGate(recovery_confirm_s=900, cooldown_s=3600)
    a.outbox = TelegramOutbox(os.path.join(tempfile.mkdtemp(), "o.json"))
    a._told, a._digest_news, a._alert_msgs, a._incident_issues = set(), set(), {}, {}
    a.executor = type("E", (), {"snapshot": None})()
    saved = []
    a._save_alert_record = lambda: saved.append("alerts")
    a._save_pauses = lambda: saved.append("pauses")
    a._publish_logbook = lambda now: None
    a._on_event = lambda kind, v, detail, ts=None: a.state.record_event(kind, v, detail, ts)
    g = a.inv.get("192.168.10.118")
    k0 = key(g)
    a.gate.update({k0: issue(g, t)}, t)
    a._told.add(k0)
    a._alert_msgs[k0] = {"id": 7}
    r = a.rename(ip=g.ip, name="  Gate   garage ")
    k1 = key(g)
    check(r["ok"] and r["changed"] and g.name == "Gate garage", "renamed, the name cleaned")
    check(a.gate.open_keys() == [k1] and a._told == {k1} and list(a._alert_msgs) == [k1],
          "the gate, what the digests told and the sent alert all under the new key")
    check(a.names.dump()["ips"] == {"192.168.10.118": "Gate garage"} and a.state.load_record("names") == a.names.dump(),
          "kept in the record")
    ev = a.state.events(0, kind="rename")
    check(len(ev) == 1 and json.loads(ev[0]["detail"])["to"] == "Gate garage", "a rename event, for the Timeline")
    r = a.rename(ip=g.ip, name="")
    check(r["ok"] and g.name == "Garage door" and a.names.dump()["ips"] == {}, "\"\" goes back to the list's name")
    r = a.rename(site="lake", mac="AA:BB:CC:DD:EE:FF", name="Tablet")
    check(r["ok"] and a.inv.get("192.168.108.243").name == "Tablet", "a MAC's name reaches the device watched with it")
    r = a.rename(site="home", mac="11:22:33:44:55:66", name="Ilenia's laptop")
    check(r["ok"] and a.names.for_mac("home", "11:22:33:44:55:66") == "Ilenia's laptop", "a device nobody watches can be named")
    check(not a.rename(ip="192.168.10.250", name="x")["ok"], "an address lanowl does not watch: refused")


if __name__ == "__main__":
    for fn in [test_clean, test_names_stick_and_go_back, test_by_mac_for_what_is_watched_from_a_site,
               test_an_open_incident_carries_over, test_the_outbox_keeps_its_incident,
               test_a_pause_follows_the_new_name, test_the_auditors_rename]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all naming tests passed")
