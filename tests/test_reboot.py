"""Rebooting devices with the owner's own logins: run with `python -m tests.test_reboot`.

No network, no device, no Telegram — ssh, ping and the senders are fakes.
Pinned down here (access.py + reboot.py):

  1. secrets.yaml: named logins, found by the device's own `credentials:` or the address map,
     read again when it changes; a password never reaches argv, a repr or the output;
  2. the allow-list decides: listed devices only, the VPS included, never lanowl's own
     machine; a Shelly keeps its own shelly_reboot;
  3. asked by the owner: /reboot answers with the proposal and its buttons, the dashboard's
     Reboot button proposes and then needs the confirm like any approval;
  4. the check: a login that works, sudo for a non-root user, never the backup link's router
     while the network's internet runs on it;
  5. a reboot holds the device's alerts (and its Wi-Fi clients') — shown as rebooting, never
     an issue — sends the command, watches it go down and come back, and ends the hold
     soon after; one that never went down did not reboot, and says so.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import access as X
from lanowl import actions as A
from lanowl import reboot as R
from lanowl.agent import LlmAgent
from lanowl.model import Device, Inventory
from lanowl.state import StateStore, StatusTracker
from lanowl.sweep import DeviceStatus, Snapshot
from lanowl.tools import ToolExecutor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


PW = "Sec$ret&Pass1"
LIST = ("logins:\n"
        "  antenna: {user: admin, password: 'ant$1'}\n"
        "  porch-ap: {user: admin, password: '" + PW + "'}\n"
        "  printer: {user: printer, password: 'pr$1'}\n"
        "  esxi: {user: root, password: 'esx$1'}\n"
        "  empty: {user: nobody}\n"
        "devices:\n"
        "  192.168.20.1: antenna\n"
        "  192.168.10.32: porch-ap\n"
        "  192.168.10.35: printer\n"
        "  192.168.10.7: empty\n"
        "  192.168.10.111: esxi\n"
        "  192.168.10.98: printer\n")

DEVICES = [
    Device("192.168.20.1", "Uplink MikroTik", "network", "critical", attrs={"role": "wan-gateway"}),
    Device("192.168.10.32", "AP-Porch", "network", "high", attrs={"role": "ap"}),
    Device("192.168.10.35", "Pi print server", "services", "low"),
    Device("192.168.10.57", "Shelly pump", "energy", "critical"),
    Device("192.168.10.46", "Shelly kitchen-table", "energy", "low"),
    Device("192.168.10.103", "Model server", "servers", "critical"),
    Device("192.168.10.113", "VM HomeHub", "servers", "critical"),
    Device("203.0.113.10", "VPS", "vpn", "critical"),
    Device("10.8.0.16", "Lake router", "vpn", "warning"),
]


def _auditor(d, mode="shadow"):
    from lanowl import main as m
    from lanowl.sinks import MqttBridge
    creds = os.path.join(d, "secrets.yaml")
    with open(creds, "w") as f:
        f.write(LIST)
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0},
           "observer": {"host_ip": "192.168.10.103"},
           "access": {"secrets_file": creds, "known_hosts": os.path.join(d, "kh")},
           "actions": {"enabled": True, "mode": mode, "expire_min": 15, "max_pending": 10,
                       "max_per_day": 20, "repeat_after_h": 24,
                       "catalog": {"shelly_reboot": {}, "reboot": {"hold_min": 5, "devices": {
                           "192.168.20.1": {"via": "routeros"},
                           "192.168.10.32": {"via": "routeros", "risk": "its Wi-Fi drops"},
                           "192.168.10.35": {"via": "ssh"},
                           "192.168.10.103": {"via": "ssh"},
                           "203.0.113.10": {"via": "ssh_key", "also_hold": ["10.8.0.16"]},
                           "192.168.10.66": {"via": "telnet"}}}}}}
    inv = Inventory(devices=[Device(x.ip, x.name, x.group, x.criticality, attrs=dict(x.attrs))
                             for x in DEVICES])
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
    a.resume_alerts()
    return m, a


class _Tg:
    def __init__(self):
        self.sent, self.edits = [], []

    def install(self):
        self.real = (A.telegram_direct, A.telegram_edit)

        async def send(cfg, text, ids=None, chat_id="", extra=None):
            self.sent.append({"text": text, "extra": extra or {}})
            if ids is not None:
                ids.append(900 + len(self.sent))
            return True

        async def edit(cfg, mid, text, reply_markup=None):
            self.edits.append({"mid": mid, "text": text, "markup": reply_markup})
            return True
        A.telegram_direct, A.telegram_edit = send, edit
        return self

    def restore(self):
        A.telegram_direct, A.telegram_edit = self.real


async def _settle(n=5):
    for _ in range(n):
        await asyncio.sleep(0)


def _run(coro_fn):
    with tempfile.TemporaryDirectory() as d:
        return asyncio.run(coro_fn(d))


# --- 1. the list, and the secret ------------------------------------------------------
def test_the_list_and_the_secret():
    print("\n-- secrets.yaml: named logins, the password never shown --")
    rows = X.parse(LIST)
    check(rows["logins"]["porch-ap"][:2] == ("admin", PW) and rows["devices"]["192.168.10.32"] == "porch-ap",
          "a named login, and the address that uses it")
    check("empty" not in rows["logins"], "a login without a password is dropped")
    out = {}

    async def go(d):
        p = os.path.join(d, "l.txt")
        with open(p, "w") as f:
            f.write(LIST)
        inv = Inventory(devices=[Device("192.168.10.98", "Spare box", "servers", "low",
                                        attrs={"credentials": "esxi"})])
        ac = X.Access({"access": {"secrets_file": p, "known_hosts": os.path.join(d, "kh"),
                                  "hostkey_any": ["192.168.20.1"]}}, inv)
        out["lg"] = ac.login("192.168.10.32")
        out["esx"] = ac.login("192.168.10.111")
        out["override"] = ac.login("192.168.10.98")
        out["none"] = (ac.login("192.168.10.57"), ac.login("192.168.10.200"))
        seen = []
        real = X._exec

        async def fake(argv, timeout_s, stdin=None, env=None):
            seen.append({"argv": list(argv), "stdin": stdin, "env": dict(env or {})})
            return 0, f"you said {PW}\n", ""
        X._exec = fake
        try:
            out["r"] = await ac.ssh("192.168.10.32", "/system resource print", user_suffix="+ct")
            out["r2"] = await ac.ssh("192.168.10.35", "sudo -S true", sudo_pw=True)
            out["r3"] = await ac.ssh("192.168.20.1", "x")
            out["nolog"] = await ac.ssh("192.168.10.57", "x")
        finally:
            X._exec = real
        out["seen"] = seen
        with open(p, "w") as f:
            f.write(LIST.replace(PW, "Changed1"))
        os.utime(p, (time.time() + 5, time.time() + 5))
        out["after"] = ac.login("192.168.10.32")
    _run(go)
    lg = out["lg"]
    check(lg.password == PW and PW not in repr(lg) and "***" in repr(lg),
          "a Login never prints its password (repr)")
    check(tuple(out["esx"] or ())[:2] == ("root", "esx$1"), "an address mapped to a named login gets it")
    check(tuple(out["override"] or ())[:2] == ("root", "esx$1"), "a device's own credentials: wins over the address map")
    check(out["none"] == (None, None), "no password, or no login named: no login")
    s = out["seen"]
    check(all(PW not in " ".join(x["argv"]) for x in s), "the password is never in argv")
    check(s[0]["env"].get("LANOWL_ASKPASS_PW") == PW and s[0]["env"].get("SSH_ASKPASS_REQUIRE") == "force",
          "ssh gets it from SSH_ASKPASS, through its own environment")
    check("admin+ct" in s[0]["argv"] and "NumberOfPasswordPrompts=1" in s[0]["argv"]
          and "PubkeyAuthentication=no" in s[0]["argv"],
          "RouterOS flags on the user; one password try; lanowl's key is never offered")
    check(s[1]["stdin"] == b"pr$1\n", "sudo -S reads the password on stdin")
    check("StrictHostKeyChecking=no" in s[2]["argv"] and "StrictHostKeyChecking=accept-new" in s[0]["argv"],
          "host keys trusted on first use, except where configured (the intercom)")
    check(PW not in out["r"][1] and "***" in out["r"][1], "a device echoing the password: scrubbed")
    check(out["nolog"][0] is None and "no login" in out["nolog"][2] and len(s) == 3,
          "no login: ssh is not even started")
    check(out["after"].password == "Changed1", "the list is read again when it changes")


# --- 2. the rules -----------------------------------------------------------------------
def test_rules_and_owner_requests():
    print("\n-- the allow-list decides; the owner asks by /reboot or the dashboard --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        calls = []

        async def chk(ip, name):
            calls.append(ip)
            return {"ok": True, "note": "RouterOS 6.49, up 3 days", "risk": ["its Wi-Fi drops"]}
        a.actions.reboot.check = chk
        tg = _Tg().install()
        try:
            ac = a.actions
            out["unknown_kind"] = "192.168.10.66" in ac.reboot.devices
            with ac.source("telegram"):
                out["ap"] = await ac.propose({"action": "reboot", "ip": "192.168.10.32",
                                              "reason": "Wi-Fi flapping"})
                out["tv"] = await ac.propose({"action": "reboot", "ip": "192.168.10.113", "reason": "x"})
                out["mac"] = await ac.propose({"action": "reboot", "ip": "192.168.10.103", "reason": "x"})
                out["vps"] = await ac.propose({"action": "reboot", "ip": "203.0.113.10", "reason": "x"})
            await _settle()
            out["shelly_action"] = None
            real = ac._shelly_check

            async def shelly_ok(p):
                return {"ok": True, "note": "relay OFF, comes back the same"}
            ac._shelly_check = shelly_ok
            out["shelly"] = await ac.ask("reboot", "192.168.10.46", "dashboard")
            out["shelly_action"] = ac.items[-1]["action"]
            ac._shelly_check = real
            n0 = len(tg.sent)
            out["dash"] = await ac.ask("reboot", "192.168.10.35", "dashboard")
            await _settle()
            out["dash_sent"] = len(tg.sent) - n0
            out["again"] = await a.chat.reboot_command("ap-porch")
            a.actions.items[0].update(status="rejected", decided_ts=time.time(), decided_by="telegram")
            out["reply"] = await a.chat.reboot_command("porch")
            await _settle()
            out["tg_msg"] = tg.sent[-1]
            out["list"] = await a.chat.reboot_command("")
            out["shellies"] = await a.chat.reboot_command("shelly")
            out["notmine"] = await a.chat.reboot_command("homehub")
            out["spec"] = ac.spec()["function"]["description"]
            out["rebootable"] = ac.view()["rebootable"]
            out["calls"] = calls
            out["items"] = [dict(p) for p in ac.items]
        finally:
            tg.restore()
    _run(go)
    check(not out["unknown_kind"], "a device with no known way to reboot is left out of the list")
    check(out["ap"].get("proposal") and out["items"][0]["command"] == "ssh 192.168.10.32: /system reboot",
          "a listed AP: proposed, with the command it will run (no password in it)")
    check("not a device lanowl can reboot" in out["tv"].get("refused", ""),
          "a device not on the list: refused, and the list is named")
    check("lanowl's own machine" in out["mac"].get("refused", ""), "never lanowl's own machine")
    check(out["vps"].get("proposal"), "the VPS may be rebooted (it is on the list), though not on the LAN")
    check(out["shelly"].get("proposal") and out["shelly_action"] == "shelly_reboot",
          "a Shelly is rebooted by shelly_reboot, whose check protects its relays")
    check(out["dash"].get("proposal") and out["dash_sent"] == 0,
          "the dashboard's Reboot proposes without a Telegram message (the confirm follows at once)")
    check(out["reply"] == "" and "You asked for it" in out["tg_msg"]["text"]
          and "Asked by you on Telegram" in out["tg_msg"]["text"]
          and out["tg_msg"]["extra"].get("reply_markup", {}).get("inline_keyboard"),
          "/reboot porch: the answer IS the proposal, with its buttons")
    check("already waiting for you (#1)" in out["again"],
          "/reboot of a device whose reboot is already waiting: pointed at its buttons")
    check("AP-Porch" in out["list"] and "Pi print server" in out["list"] and "VM HomeHub" not in out["list"],
          "/reboot alone lists what can be rebooted")
    check("matches 2 devices" in out["shellies"], "an ambiguous name asks which")
    check("not a device I can reboot" in out["notmine"], "a device off the list is refused by name")
    check("AP-Porch 192.168.10.32" in out["spec"] and "reboot" in out["spec"],
          "the model's tool names the devices it may propose a reboot for")
    check("192.168.10.32" in out["rebootable"] and "192.168.10.57" in out["rebootable"]
          and "192.168.10.113" not in out["rebootable"], "the page offers Reboot on the list and the Shellies")


# --- 3. the check ------------------------------------------------------------------------
def test_the_check():
    print("\n-- the check: a login that works, sudo, never the antenna while on it --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        rb = a.actions.reboot
        a._mac_index = {"02:00:5E:10:00:08": "192.168.10.57", "02:00:5E:10:00:11": "192.168.10.200"}
        answers = {}

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            out.setdefault("ssh", []).append((ip, remote, sudo_pw))
            return answers[(ip, remote.split()[0])]
        a.access.ssh = ssh
        answers[("192.168.10.32", "/system")] = (0, "uptime: 3w1d19h29m50s\n version: 6.49.21 (long-term)\n"
                                                  "board-name: wAP R ac\n", "")
        answers[("192.168.10.32", "/interface")] = (0, " 0 interface=wlan mac-address=02:00:5E:10:00:08\n"
                                                     " 1 interface=wlan mac-address=02:00:5E:10:00:11\n", "")
        out["ap"] = await rb.check("192.168.10.32", "AP-Porch")
        answers[("192.168.10.35", "cat")] = (0, "857255.61 3412162.58\n1000\n", "")
        out["nosudo"] = await rb.check("192.168.10.35", "Airprint")
        answers[("192.168.10.35", "cat")] = (0, "857255.61 3412162.58\n1000\nSUDO_OK\n", "")
        out["sudo"] = await rb.check("192.168.10.35", "Airprint")
        answers[("192.168.20.1", "/system")] = (0, "uptime: 1d2h\n", "")
        a._last_report = {"wan_state": "backup"}
        out["standby_backup"] = await rb.check("192.168.20.1", "Uplink")
        a._last_report = {"wan_state": "ok"}
        out["standby_ok"] = await rb.check("192.168.20.1", "Uplink")
        answers[("192.168.10.32", "/system")] = (255, "", "admin@192.168.10.32: Permission denied (password).")
        out["denied"] = await rb.check("192.168.10.32", "AP-Porch")

        async def vps(ip, remote, timeout_s=20, root=False):
            return 0, "1209600.5 1.0\n", ""
        a.actions._ssh_run = vps
        out["vps"] = await rb.check("203.0.113.10", "VPS")
    _run(go)
    ap = out["ap"]
    check(ap["ok"] and ap["uptime"] == 3 * 604800 + 86400 + 19 * 3600 + 29 * 60 + 50
          and ap["note"].startswith("wAP R ac 6.49.21 (long-term), up 22 days"),
          f"RouterOS: model, version and uptime read ({ap['note']})")
    check(ap["clients"] == ["192.168.10.57"] and "1 more device(s) on its Wi-Fi" in ap["note"],
          "its Wi-Fi clients that the inventory watches are held too (the rest are not ours)")
    check(ap["risk"] == ["its Wi-Fi drops"], "the configured risk goes on the approval message")
    check(not out["nosudo"]["ok"] and "sudo refused" in out["nosudo"]["note"],
          "a non-root login whose sudo refuses the password cannot reboot")
    check(out["sudo"]["ok"] and out["sudo"]["uid"] == "1000" and "via sudo" in out["sudo"]["note"]
          and any(x[0] == "192.168.10.35" and x[2] for x in out["ssh"]),
          "with sudo it can — the password handed to sudo on stdin")
    check(not out["standby_backup"]["ok"] and "internet is on the Uplink" in out["standby_backup"]["note"],
          "never the antenna while the network's internet runs on it")
    check(out["standby_ok"]["ok"], "...and fine while the fiber carries it")
    check(not out["denied"]["ok"] and "Permission denied" in out["denied"]["note"],
          "a refused login says so")
    check(out["vps"]["ok"] and out["vps"]["clients"] == ["10.8.0.16"] and "behind it" in out["vps"]["note"],
          "the VPS: over lanowl's key; the tunnels behind it are held too (also_hold)")


# --- 4. the hold ---------------------------------------------------------------------------
def test_the_hold():
    print("\n-- while it reboots: 'rebooting', never an issue; after the hold, reported --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        forgot = []
        real_forget = a._forget_incidents
        a._forget_incidents = lambda ip: (forgot.append(ip), real_forget(ip))
        now = time.time()
        for _ in range(3):
            a.tracker.update("192.168.10.32", False, now=now)

        def snap():
            return Snapshot(ts=time.time(), devices=[
                DeviceStatus(x.ip, x.name, x.group, x.criticality, up=x.ip != "192.168.10.32",
                             reachable=x.ip != "192.168.10.32", latency_ms=1.0 if x.ip != "192.168.10.32" else None,
                             attrs=dict(x.attrs)) for x in DEVICES])
        a.hold(["192.168.10.32"], now + 300, "reboot of AP-Porch")
        a.hold(["192.168.10.32"], now + 250, "again")
        r = a._make_report(snap())
        out["held_dev"] = next(x for x in r["devices"] if x["ip"] == "192.168.10.32")
        out["held_issues"] = [i for i in r["issues"] if i.get("ip") == "192.168.10.32"]
        out["held_counts"] = r["counts"]
        out["forgot"] = list(forgot)
        a.hold(["192.168.10.32"], 0)
        out["until"] = a.held_until("192.168.10.32")
        r = a._make_report(snap())
        out["after_issues"] = [i for i in r["issues"] if i.get("ip") == "192.168.10.32"]
        a.hold(["192.168.10.35"], now - 1)
        out["past"] = a.held_until("192.168.10.35")
        # the main router restarting: the WAN watcher's messages are held, others are not
        passed = []
        a._wan_alert = lambda text, key="": passed.append(text)
        a.hold(["wan"], now + 300, "reboot of the router")
        a._wanwatch_alert("🔴 NO INTERNET AT ALL 13:00", "k")
        out["wan_held"] = list(passed)
        a.hold(["wan"], 0)
        a._wanwatch_alert("🔴 NO INTERNET AT ALL 13:10", "k")
        out["wan_after"] = list(passed)
    _run(go)
    check(out["held_dev"]["held"] and out["held_dev"]["asleep"] and not out["held_dev"]["up"],
          "a held device that is down is drawn as rebooting (and counted as asleep)")
    check(out["held_issues"] == [] and out["held_counts"]["down"] == 0, "it is no issue, and not 'down'")
    check(out["forgot"] == ["192.168.10.32"],
          "its open incident is closed quietly ONCE, when the hold starts (no false 'back online')")
    check(out["until"] == 0 and out["after_issues"] and out["after_issues"][0]["kind"] == "down",
          "once the hold ends, a device still down is an issue again, as usual")
    check(out["past"] == 0, "a hold in the past is no hold")
    check(out["wan_held"] == [] and out["wan_after"] == ["🔴 NO INTERNET AT ALL 13:10"],
          "the router restarting holds the WAN watcher's messages ('wan'); after, they flow again")


# --- 5. the reboot itself ---------------------------------------------------------------------
def test_the_reboot():
    print("\n-- the reboot: sent, down, back, uptime; one that never went down failed --")
    out = {}
    real = (R.probes.ping, R.POLL_S, R.DOWN_WAIT_S)

    async def go(d):
        m, a = _auditor(d, mode="live")
        rb = a.actions.reboot
        sent, pings, ups = [], [], []

        class _P:
            def __init__(self, ok):
                self.ok = ok

        async def ping(ip, timeout_ms=1000, count=2):
            return _P(pings.pop(0) if pings else True)
        R.probes.ping = ping
        R.POLL_S, R.DOWN_WAIT_S = 0, 1

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False):
            if remote == "/system reboot":
                sent.append((ip, stdin))
                out["held_during"] = (a.held_until("192.168.10.32"), a.held_until("192.168.10.57"))
                return 255, "", "Connection to 192.168.10.32 closed by remote host."
            if remote.startswith("/system resource"):
                return 0, f"uptime: {ups.pop(0) if ups else '40s'}\n", ""
            if remote.startswith("( sleep 2") or remote.startswith("sudo -S"):
                sent.append((ip, remote, sudo_pw))
                return 0, "REBOOTING\n", ""
            return 0, "", ""
        a.access.ssh = ssh

        async def sleep0(s):
            await asyncio.sleep(0)
        R.asyncio = type("_a", (), {"sleep": staticmethod(sleep0)})
        try:
            t0 = time.time()
            pings[:] = [False, False, True]
            out["ok"] = await rb.run("192.168.10.32", "AP-Porch", {"clients": ["192.168.10.57"]})
            out["after"] = (a.held_until("192.168.10.32"), t0)
            pings[:] = [True] * 50
            ups[:] = ["3w1d"]
            out["never"] = await rb.run("192.168.10.32", "AP-Porch", {"clients": []})
            out["released"] = a.held_until("192.168.10.32")
            pings[:] = [False, True]
            out["root"] = await rb.run("192.168.10.35", "Airprint", {"uid": "0"})
            pings[:] = [False, True]
            out["sudo"] = await rb.run("192.168.10.35", "Airprint", {"uid": "1000"})
            out["sent"] = sent
            # end to end: the owner asks on Telegram, approves, it runs — one at a time
            tg = _Tg().install()
            try:
                async def chk(ip, name):
                    return {"ok": True, "note": "up 3 weeks", "clients": []}
                rb.check = chk
                pings[:] = [False, True]
                a.updates.hosts = [{"ip": "192.168.10.32", "via": "routeros"}]
                a.updates.start = lambda reason: out.setdefault("recheck", reason)
                await a.chat.reboot_command("porch")
                await _settle()
                p = a.actions.items[-1]
                out["toast"] = await a.chat.on_callback(f"ax:a:{p['id']}:{p['nonce']}")
                for _ in range(40):
                    await _settle()
                out["p"] = dict(p)
                out["edits"] = list(tg.edits)
            finally:
                tg.restore()
        finally:
            R.asyncio = asyncio
    try:
        _run(go)
    finally:
        R.probes.ping, R.POLL_S, R.DOWN_WAIT_S = real
    ok = out["ok"]
    check(ok["ok"] and ok["result"].startswith("rebooted — answering again after") and "(up 40 s)" in ok["result"],
          f"sent, went down, came back, uptime proves it: {ok.get('result')}")
    check(out["sent"][0] == ("192.168.10.32", b"y\n"), "RouterOS: /system reboot, with the 'y' its console may ask for")
    check(out["held_during"][0] > time.time() and out["held_during"][1] > time.time(),
          "the AP and its Wi-Fi client were held BEFORE the command went")
    check(0 < out["after"][0] <= time.time() + R.AFTER_BACK_S + 1,
          "back: the hold ends two minutes later, not at the full five")
    nv = out["never"]
    check(not nv["ok"] and nv["ran"] and "did not reboot" in nv["error"] and "up 22 days" in nv["error"],
          f"never went down, and a long uptime: it did not reboot ({nv.get('error')})")
    check(out["released"] == 0, "...and its hold ends at once")
    ssh12 = [x for x in out["sent"] if x[0] == "192.168.10.35"]
    check(out["root"]["ok"] and ssh12[0][1].startswith("( sleep 2; reboot )") and not ssh12[0][2],
          "root: a detached reboot, so the command returns before the link goes")
    check(out["sudo"]["ok"] and ssh12[1][1].startswith("sudo -S -p ''") and ssh12[1][2],
          "not root: through sudo, the password on its stdin")
    p = out["p"]
    check(p["status"] == "done" and p["outcome"]["result"].startswith("rebooted"),
          f"end to end from /reboot: approved on Telegram, run, done ({p['outcome'].get('result')})")
    check("running it now" in out["toast"] and "✅ <b>Done</b>" in out["edits"][-1]["text"],
          "the button says it runs; the message ends with the result")
    check(out.get("recheck") == "after a reboot",
          "a machine the update check reads is read again at once: its 'reboot pending' goes")


if __name__ == "__main__":
    for fn in [test_the_list_and_the_secret, test_rules_and_owner_requests, test_the_check,
               test_the_hold, test_the_reboot]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
