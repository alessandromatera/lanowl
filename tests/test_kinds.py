"""Device kinds and profiles: run with `python -m tests.test_kinds`.

  1. secrets.yaml logins: a password, lanowl's key, or both; a login with neither is dropped;
  2. every built-in kind maps each feature it can do to the way its module reaches it, and a
     linux device's way follows its login;
  3. what cannot be done is a problem in words, never a crash: an unknown kind or feature, a
     feature the kind lacks, a missing login, a restart without units, logs without a key;
  4. `apply` fills every feature's list from the inventory, ignores config.yaml's old lists with
     a warning, and gives every key login its connection (its log read only with `logs`);
  5. a profile: parsed and validated, its parsers, its operations run by key or by password
     with sudo, its reboot detached;
  6. the app wired from the plan: updates, reboots, restarts, Shellies, the log watcher, and a
     profile's updates reported without paging;
  7. `lanowl --check` says it all in words, and fails when something is wrong.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import yaml  # noqa: E402

from lanowl import access as X  # noqa: E402
from lanowl import kinds as K  # noqa: E402
from lanowl.model import Device, Inventory  # noqa: E402

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


SECRETS = """
logins:
  routers:    {user: admin, password: "r0uter-pw"}
  server-key: {user: root, key: true}
  nas:        {user: admin, password: "nas-pw"}
  store-key:  {user: admin, key: true, password: "st-pw"}
  cams:       {user: admin, password: "cam-pw"}
  ha-ssh:     {user: root, password: "ha-pw"}
  mac-key:    {user: admin, key: /config/id_mac}
  esxi:       {user: root, password: "esx-pw"}
  vps-key:    {user: root, key: true}
  nothing:    {user: x}
  box:        {user: admin, password: "box-pw"}
"""

INVENTORY = {"devices": [
    {"ip": "192.168.88.1", "name": "Router", "kind": "mikrotik", "credentials": "routers",
     "manage": ["updates", "upgrade", "reboot", "config", "security", "backup"],
     "reboot": {"risk": "every Wi-Fi drops"}},
    {"ip": "192.168.88.2", "name": "AP", "kind": "openwrt", "credentials": "routers",
     "manage": ["updates", "reboot", "security"]},
    {"ip": "192.168.88.10", "name": "Server", "kind": "linux", "credentials": "server-key",
     "manage": ["logs", "updates", "upgrade", "reboot", "restart", "config", "security", "backup"],
     "restart": {"units": ["mosquitto"]}, "logs": {"about": "the home server", "public": False}},
    {"ip": "192.168.88.11", "name": "NAS", "kind": "linux", "credentials": "nas",
     "manage": ["updates", "config", "security", "backup", "logs", "restart"],
     "backup": {"paths": ["etc"]}},
    {"ip": "192.168.88.12", "name": "Store", "kind": "linux", "credentials": "store-key",
     "manage": ["backup"]},
    {"ip": "192.168.88.20", "name": "Camera", "kind": "reolink", "credentials": "cams",
     "manage": ["reboot"]},
    {"ip": "192.168.88.30", "name": "Home Assistant", "kind": "homeassistant",
     "credentials": "ha-ssh", "manage": ["updates", "reboot", "backup"]},
    {"ip": "192.168.88.40", "name": "Kitchen relay", "kind": "shelly", "manage": ["reboot", "backup"]},
    {"ip": "192.168.88.41", "name": "Pump relay", "kind": "shelly", "manage": ["backup"]},
    {"ip": "192.168.88.50", "name": "Mac", "kind": "macos", "credentials": "mac-key",
     "manage": ["updates", "reboot", "config", "security", "backup"]},
    {"ip": "192.168.88.51", "name": "Box", "kind": "busybox", "credentials": "box",
     "manage": ["config", "reboot"]},
    {"ip": "192.168.88.60", "name": "ESXi", "kind": "esxi", "credentials": "esxi",
     "manage": ["updates", "reboot"]},
    {"ip": "192.168.88.70", "name": "Old NVR", "kind": "generic", "manage": ["reboot"],
     "reboot": {"ha_button": "button.nvr_plug_restart"}},
    {"ip": "192.168.88.80", "name": "Toaster", "kind": "toaster", "manage": ["updates"]},
    {"ip": "192.168.88.81", "name": "No kind", "manage": ["updates"]},
    {"ip": "192.168.88.82", "name": "Typo", "kind": "linux", "credentials": "server-key",
     "manage": ["updatez"]},
    {"ip": "192.168.88.90", "name": "Printer"},
    {"ip": "203.0.113.10", "name": "VPS", "credentials": "vps-key"},
]}

BUSYBOX = """
kind: busybox
about: a small box with a shell
ops:
  config: {cmd: "cat /etc/box.conf", sudo: true, ignore: ['^# generated']}
  uptime: {cmd: "cat /proc/uptime"}
  reboot: {cmd: "reboot", sudo: true, back_s: 120}
"""


def _files(d: str) -> dict:
    sec = os.path.join(d, "secrets.yaml")
    with open(sec, "w") as f:
        f.write(SECRETS)
    prof = os.path.join(d, "profiles")
    os.makedirs(prof)
    with open(os.path.join(prof, "busybox.yaml"), "w") as f:
        f.write(BUSYBOX)
    with open(os.path.join(prof, "broken.yaml"), "w") as f:
        f.write("kind: linux\nops: {config: {cmd: x}}\n")
    cfg = {"access": {"secrets_file": sec, "known_hosts": os.path.join(d, "kh"),
                      "ha_url": "http://192.168.88.30:8123"},
           "profiles": {"dir": prof},
           "observer": {"host_ip": "192.168.88.99"},
           "updates": {"enabled": True, "hosts": [{"ip": "192.0.2.1", "via": "key"}]},
           "exposure": {"enabled": True},
           "configwatch": {"enabled": False},
           "hostlog": {"enabled": True},
           "backups": {"enabled": True, "store": {"host": "192.168.88.12"}, "self": {"daily": 5}},
           "actions": {"enabled": True, "mode": "shadow",
                       "catalog": {"restart_service": {"host": "192.0.2.2", "units": ["y"]},
                                   "vps_restart": {"host": "192.0.2.3"}, "shelly_reboot": {}}}}
    return cfg


def _inv() -> Inventory:
    devs = []
    for d in INVENTORY["devices"]:
        attrs = {k: v for k, v in d.items() if k not in ("ip", "name")}
        devs.append(Device(d["ip"], d["name"], attrs=attrs))
    return Inventory(devices=devs)


def _load(d):
    cfg = _files(d)
    inv = _inv()
    acc = X.Access(cfg, inv)
    return cfg, inv, acc, K.Kinds.load(cfg, inv, acc)


# --- 1. logins ----------------------------------------------------------------------------------
def test_logins():
    print("\n-- secrets.yaml: a password, lanowl's key, or both --")
    lg = X.parse(SECRETS)["logins"]
    check(lg["routers"].password == "r0uter-pw" and lg["routers"].key == "", "a password login")
    check(lg["server-key"].key == "default" and lg["server-key"].password == "",
          "`key: true`: lanowl's own key")
    check(lg["mac-key"].key == "/config/id_mac", "a key file of its own")
    check(lg["store-key"].key == "default" and lg["store-key"].password == "st-pw",
          "both: the key logs in, the password is sudo's")
    check("nothing" not in lg, "a login with neither is dropped")
    check("st-pw" not in repr(lg["store-key"]), "a login never prints its password")
    with tempfile.TemporaryDirectory() as d:
        cfg = _files(d)
        acc = X.Access(cfg, _inv())
        check(acc.has("192.168.88.1") and not acc.by_key("192.168.88.1"), "has(): a password")
        check(acc.by_key("192.168.88.10") and not acc.has("192.168.88.10"),
              "by_key(): lanowl's key, and has() is false without a password")
        rc, _, err = asyncio.run(acc.ssh("192.168.88.10", "true"))
        check(rc is None and "needs a password" in err,
              "a password ssh to a key-only login refuses, and says why")


# --- 2-3. the plan --------------------------------------------------------------------------------
def test_plan():
    print("\n-- every kind, every feature: the way in, or why not --")
    with tempfile.TemporaryDirectory() as d:
        cfg, inv, acc, k = _load(d)
    P = {p.ip: p for p in k.plans}
    f = lambda ip: P[ip].features  # noqa: E731
    check(f("192.168.88.1") == {x: "routeros" for x in
                                ("updates", "upgrade", "reboot", "config", "security", "backup")},
          "mikrotik: RouterOS over ssh for all six")
    check(f("192.168.88.2") == {"updates": "openwrt", "reboot": "ssh", "security": "openwrt"},
          "openwrt: its own reads, a reboot over ssh")
    check(f("192.168.88.10") == {"logs": "key", "updates": "key", "upgrade": "key",
                                 "reboot": "ssh_key", "restart": "key", "config": "key",
                                 "security": "key", "backup": "vps"},
          "linux by key: every feature over the key")
    check(f("192.168.88.11") == {"updates": "password", "config": "sudo", "security": "sudo",
                                 "backup": "files"},
          "linux by password: sudo for root's reads, a backup of its listed paths")
    nas = " ".join(P["192.168.88.11"].problems)
    check("logs needs a login with lanowl's ssh key" in nas, "logs without a key: said why")
    check("restart needs the services it may restart" in nas, "restart without units: said why")
    check(f("192.168.88.12") == {"backup": "store"} and P["192.168.88.12"].login == "key+password",
          "the backup store backs itself up where it is")
    check(f("192.168.88.20") == {"reboot": "reolink"}, "reolink: its own API")
    check(f("192.168.88.30") == {"updates": "homeassistant", "reboot": "homeassistant",
                                 "backup": "homeassistant"}, "homeassistant: its API, ssh for backups")
    check(f("192.168.88.40") == {"reboot": "shelly", "backup": "shellies"}
          and f("192.168.88.41") == {"backup": "shellies"}, "shelly: its controller, its settings")
    check(f("192.168.88.50") == {"updates": "profile", "reboot": "profile", "config": "profile",
                                 "security": "profile"}, "a shipped profile (macos)")
    check(any("no `backup` operation" in w for w in P["192.168.88.50"].problems),
          "a profile without the operation: said which")
    check(f("192.168.88.51") == {"config": "profile", "reboot": "profile"},
          "the owner's own profile (profiles/busybox.yaml)")
    check(f("192.168.88.60") == {"updates": "esxi"}
          and any("cannot do reboot" in w and "it can:" in w for w in P["192.168.88.60"].problems),
          "a feature the kind lacks: refused, with what it can do")
    check(f("192.168.88.70") == {"reboot": "ha_button"}, "any device: a reboot by an HA button")
    check(any("unknown kind 'toaster'" in w for w in P["192.168.88.80"].problems),
          "an unknown kind: said, with the built-in ones")
    check(P["192.168.88.81"].problems == ["`manage` needs a `kind`"], "manage without a kind")
    check(any("unknown feature 'updatez'" in w for w in P["192.168.88.82"].problems), "a typo")
    check("192.168.88.90" not in P and "203.0.113.10" not in P, "only watched: no plan")
    check(P["192.168.88.1"].off == {"config": "configwatch.enabled"} and "config" in f("192.168.88.1"),
          "a feature switched off in config.yaml: noted, not a problem")
    check(any("broken.yaml" in w and "built in" in w for w in k.problems),
          "a profile that takes a built-in kind's name: refused")
    with tempfile.TemporaryDirectory() as d:
        cfg = _files(d)
        cfg["access"]["ha_url"] = ""
        k2 = K.Kinds.load(cfg, _inv(), X.Access(cfg, _inv()))
    ha = {p.ip: p for p in k2.plans}["192.168.88.30"]
    check("updates" not in ha.features and "backup" in ha.features
          and any("needs access.ha_url" in w for w in ha.problems),
          "Home Assistant's API without its address: the API features refused, ssh ones kept")


# --- 4. apply -------------------------------------------------------------------------------------
def test_apply():
    print("\n-- the lists every feature reads, from the inventory --")
    with tempfile.TemporaryDirectory() as d:
        cfg, inv, acc, k = _load(d)
    ips = lambda rows: sorted(r["ip"] for r in rows)  # noqa: E731
    check(ips(cfg["updates"]["hosts"]) == ["192.168.88.1", "192.168.88.10", "192.168.88.11",
                                           "192.168.88.2", "192.168.88.30", "192.168.88.50",
                                           "192.168.88.60"], "updates: the managed ones only")
    check(any("updates.hosts is ignored" in w for w in k.problems)
          and any("restart_service.host is ignored" in w for w in k.problems)
          and any("vps_restart.host is ignored" in w for w in k.problems),
          "config.yaml's old lists: ignored, and said so")
    hl = {h["ip"]: h for h in cfg["hostlog"]["hosts"]}
    check(sorted(hl) == ["192.168.88.10", "192.168.88.12", "192.168.88.50", "192.168.88.82",
                         "203.0.113.10"], "every key login gets its connection, managed or not")
    check(hl["192.168.88.10"]["watch"] and hl["192.168.88.10"]["about"] == "the home server"
          and not hl["203.0.113.10"]["watch"] and not hl["192.168.88.12"]["watch"],
          "its log is read only with `logs`, with its options")
    check(hl["192.168.88.50"]["identity"] == "/config/id_mac" and hl["192.168.88.50"]["user"] == "admin"
          and hl["192.168.88.10"]["identity"] == "", "its own key file, or lanowl's")
    bk = {m["ip"]: m for m in cfg["backups"]["machines"]}
    check(bk["192.168.88.11"]["paths"] == ["etc"] and bk["192.168.88.12"]["via"] == "store",
          "backups: options carried, the store")
    check(bk["shellies"]["devices"] == ["192.168.88.40", "192.168.88.41"],
          "the Shellies: one backup of the listed ones")
    check(bk["lanowl"]["daily"] == 5, "lanowl itself, daily (backups.self)")
    cat = cfg["actions"]["catalog"]
    rb = cat["reboot"]["devices"]
    check(rb["192.168.88.1"] == {"via": "routeros", "risk": "every Wi-Fi drops"}
          and rb["192.168.88.70"] == {"via": "ha_button", "entity": "button.nvr_plug_restart"}
          and rb["192.168.88.51"]["back_s"] == 120, "reboots: risk, the HA button, a profile's wait")
    check(cat["shelly_reboot"]["devices"] == ["192.168.88.40"], "only the Shelly with `reboot`")
    check(cat["apt_upgrade"]["hosts"] == {"192.168.88.10": {"via": "key"}}
          and cat["routeros_upgrade"]["hosts"] == {"192.168.88.1": {}}, "upgrades")
    check(cat["restart_service"] == {"hosts": {"192.168.88.10": {"via": "key", "units": ["mosquitto"]}}}
          and "vps_restart" not in cat, "restarts: per device, the old shapes gone")


# --- 5. profiles ----------------------------------------------------------------------------------
def test_profiles():
    print("\n-- a profile: commands and fixed parsers, never code --")
    mac = K.parse_profile(open(os.path.join(K.SHIPPED, "macos.yaml")).read())
    check(set(mac.ops) == {"version", "updates", "uptime", "reboot", "config", "security"}
          and mac.ops["reboot"]["sudo"] and mac.ops["reboot"]["back_s"] == 600,
          "the shipped macos profile reads")
    for bad, why in (("kind: Bad Name\nops: {config: x}", "kind"),
                     ("kind: x\nops: {format: {cmd: x}}", "unknown operation"),
                     ("kind: x\nops: {config: {cmd: x, run_as: root}}", "unknown key"),
                     ("kind: x\nops: {config: {cmd: x, parse: eval}}", "parse"),
                     ("kind: x\nops: {config: {cmd: x, parse: {regex: '('}}}", "bad regex"),
                     ("kind: x\nops: {backup: {cmd: x, file: ../etc/passwd}}", "plain file name"),
                     ("kind: x\nops: {}", "no operations"),
                     ("kind: x\nscript: rm -rf /\nops: {config: x}", "unknown key")):
        try:
            K.parse_profile(bad)
            check(False, f"refused: {why}")
        except ValueError as e:
            check(why in str(e), f"refused: {why} — {e}")
    po = K.parse_output
    check(po({"parse": "text"}, " a\nb \n") == "a\nb", "text")
    check(po({"parse": "lines"}, "a\n\n b\n") == ["a", "b"], "lines")
    check(po({"parse": "first_line"}, "\n x \ny") == "x", "first_line")
    check(po({"parse": "proc_uptime"}, "12345.67 999.1\n") == 12345.67, "proc_uptime")
    bt = po({"parse": "boottime"}, f"{{ sec = {int(time.time()) - 100}, usec = 0 }} Mon Oct  1")
    check(99 <= bt <= 102, "boottime: seconds since the boot")
    check(po({"parse": {"regex": r"^\* Label: (?P<pkg>.+)$"}}, "x\n* Label: A-1\n* Label: B-2\n")
          == [{"pkg": "A-1"}, {"pkg": "B-2"}], "regex: named groups, one row per match")
    check(po({"parse": "text", "ignore": [__import__("re").compile("^# gen")]},
             "# generated 10:01\nport=22") == "port=22", "config: ignored lines left out")
    try:
        po({"parse": "seconds"}, "soon")
        check(False, "a number that is not one: refused")
    except ValueError:
        check(True, "a number that is not one: refused")
    check(K.update_items([{"pkg": "A", "version": "2"}, {"value": "B"}]) ==
          [{"pkg": "A", "version": "2"}, {"pkg": "B"}] and K.version_fields(["macOS", "15.1"]) ==
          {"os": "macOS", "release": "15.1"}, "updates and version, from any parser's shape")

    class _Acc:
        def __init__(self):
            self.calls = []

        def login(self, ip):
            return {"192.168.88.50": X.Login("admin", "", "default"),
                    "192.168.88.51": X.Login("admin", "box-pw")}.get(ip)

        def by_key(self, ip):
            return ip == "192.168.88.50"

        async def ssh(self, ip, cmd, sudo_pw=False, timeout_s=20):
            self.calls.append(("pw", ip, cmd, sudo_pw))
            if "REBOOTING" in cmd:
                return 0, "REBOOTING\n", ""
            return (1, "", "boom") if "fail" in cmd else (0, "# generated now\nmode=on\n", "")

    class _Act:
        def __init__(self):
            self.calls = []

        async def _ssh_run(self, ip, cmd, timeout_s=20, root=False):
            self.calls.append(("key", ip, cmd, root))
            return 0, "macOS\n15.1\n", ""

    class _A:
        access, actions = _Acc(), _Act()

    with tempfile.TemporaryDirectory() as d:
        cfg, inv, acc, k = _load(d)
    a = _A()
    ok, v = asyncio.run(k.run(a, "192.168.88.50", "version"))
    check(ok and v == ["macOS", "15.1"] and a.actions.calls[-1][0] == "key"
          and a.actions.calls[-1][3] is False, "by key: over the key's connection, not as root")
    ok, v = asyncio.run(k.run(a, "192.168.88.51", "config"))
    c = a.access.calls[-1]
    check(ok and v == "mode=on" and c[2].startswith("sudo -S -p '' sh -c ") and c[3] is True,
          "by password with sudo: sudo -S, the password on stdin, ignored lines gone")
    k.profiles["busybox"].ops["config"]["cmd"] = "fail"
    ok, v = asyncio.run(k.run(a, "192.168.88.51", "config"))
    check(not ok and v == "boom", "a failing command: not ok, its own words")
    sent, _ = asyncio.run(k.send_reboot(a, "192.168.88.51"))
    c = a.access.calls[-1]
    check(sent and "( sleep 2; reboot ) </dev/null >/dev/null 2>&1 & echo REBOOTING" in c[2]
          and c[3] is True, "the reboot: detached, as root, answered before it goes")


# --- 6. the app, wired from the plan ------------------------------------------------------------
def test_wired():
    print("\n-- the app, from the inventory alone --")
    from lanowl import main as m
    from lanowl.agent import LlmAgent
    from lanowl.state import StateStore, StatusTracker
    from lanowl.sinks import MqttBridge
    from lanowl.tools import ToolExecutor
    out = {}

    async def go(d):
        cfg, inv, acc, k = _load(d)
        cfg.update({"telegram": {"via": "direct", "chat_id": "1",
                                 "outbox_file": os.path.join(d, "o.json")}})
        st = StateStore(os.path.join(d, "s.sqlite"))
        mq = MqttBridge(cfg)
        ex = ToolExecutor(cfg, inv, mq, st)
        a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex), kinds=k)
        out["updates"] = {h["ip"]: h["via"] for h in a.updates.hosts}
        out["reboot"] = (a.actions.reboot.can("192.168.88.50"), a.actions.reboot.via("192.168.88.50"),
                         a.actions.reboot.can("192.168.88.60"))
        out["restart"] = a.actions._restartable()
        out["shelly"] = (a.actions._shelly_ok(inv.get("192.168.88.40")),
                         a.actions._shelly_ok(inv.get("192.168.88.41")))
        out["watched"] = [h.ip for h in a.hostlog.watched]
        out["key_hosts"] = sorted(h.ip for h in a.hostlog.hosts)
        out["enabled"] = a.hostlog.enabled

        async def fake_run(_a, ip, op):
            return (True, ["macOS", "15.1"]) if op == "version" else \
                (True, [{"pkg": "macOS 15.2-24C101"}, {"pkg": "Safari 18.2"}])
        k.run = fake_run
        h = next(x for x in a.updates.hosts if x["ip"] == "192.168.88.50")
        r = await a.updates._host(h)
        out["read"] = r
        a.updates.rec["hosts"]["192.168.88.50"] = {**r, "name": "Mac", "ts": time.time()}
        out["findings"] = [f for f in a.updates.findings() if f["ip"] == "192.168.88.50"]
        st.close()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["updates"]["192.168.88.50"] == "profile" and out["updates"]["192.168.88.10"] == "key",
          "updates: each device by its own way")
    check(out["reboot"] == (True, "profile", False), "reboots: the managed ones, a profile's included")
    check(out["restart"] == {"192.168.88.10": ["mosquitto"]}, "restarts: the listed units")
    check(out["shelly"] == (True, False), "a Shelly restarts only with `reboot`")
    check(out["watched"] == ["192.168.88.10"] and len(out["key_hosts"]) == 5 and out["enabled"],
          "the log watcher reads only `logs` hosts; the key reaches all five")
    r = out["read"]
    check(r.get("profile") and r["kind"] == "macos" and r["os"] == "macOS"
          and [u["pkg"] for u in r["updates"]] == ["macOS 15.2-24C101", "Safari 18.2"],
          "a profile's version and updates, read")
    fs = out["findings"]
    check(len(fs) == 1 and not fs[0]["page"] and "2 update(s) waiting" in fs[0]["text"]
          and "Mac (192.168.88.50)" in fs[0]["text"], "reported with its name and address, never paged")


# --- 7. lanowl --check ------------------------------------------------------------------------------
def test_check():
    print("\n-- lanowl --check --")
    from lanowl import main as m
    with tempfile.TemporaryDirectory() as d:
        cfg = _files(d)
        cp, ip = os.path.join(d, "config.yaml"), os.path.join(d, "inventory.yaml")
        with open(cp, "w") as f:
            yaml.safe_dump(cfg, f)
        with open(ip, "w") as f:
            yaml.safe_dump(INVENTORY, f)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m._check(argparse.Namespace(config=cp, inventory=ip))
        text = buf.getvalue()
        with open(ip, "w") as f:
            yaml.safe_dump({"devices": [INVENTORY["devices"][0]]}, f)
        cfg.pop("updates")
        cfg["actions"]["catalog"] = {}
        os.remove(os.path.join(d, "profiles", "broken.yaml"))
        with open(cp, "w") as f:
            yaml.safe_dump(cfg, f)
        with contextlib.redirect_stdout(io.StringIO()):
            rc_ok = m._check(argparse.Namespace(config=cp, inventory=ip))
    check(rc == 1 and rc_ok == 0, "fails when something is wrong, passes when nothing is")
    check("Router (192.168.88.1) · mikrotik · login: password" in text
          and "✓ upgrade   may propose installing them" in text, "each device: kind, login, what it does")
    check("✗ unknown kind 'toaster'" in text
          and "○ config    tells what changed in its configuration — off: configwatch.enabled" in text,
          "problems and switched-off features, in words")
    check("r0uter-pw" not in text and "st-pw" not in text, "no password in it")


if __name__ == "__main__":
    test_logins()
    test_plan()
    test_apply()
    test_profiles()
    test_wired()
    test_check()
    print(f"\n{len(_fails)} FAILED" if _fails else "\nall passed")
    sys.exit(1 if _fails else 0)
