"""Proposed actions, and the raw host log: run with `python -m tests.test_actions`.

No network, no model, no Telegram — the read-only checks and the senders are fakes.
Pinned down here (actions.py):

  1. the rules: inventory only, the main LAN only, never lanowl itself, per-action
     deny lists, the service allow-list, only a Shelly is a Shelly;
  2. the tool is offered only while a turn may propose (questions, the audit) — never to
     the weekly review, the log triages or an MQTT question;
  3. a question's proposal is one Telegram message with Approve/Reject; the button needs
     the proposal's nonce; approving checks again and records a DRY RUN — nothing runs;
  4. limits: one pending copy, max pending, and the audit may not re-propose for a day;
  5. unanswered proposals expire and lose their buttons;
  6. the audit's proposals ride on the incident's own alert (no second message), and the
     diagnosis edit keeps their buttons; otherwise one silent message per audit;
  7. the dashboard: Reject freely, Approve with the PIN; five wrong ones lock it and say so;
  8. a Shelly whose relay would change on a restart is refused (a contactor that powers on OFF);
  9. the record survives a restart; a button from anyone but the owner does nothing;
 10. host_log: the model's words reach the remote shell quoted, never as shell;
 11. LIVE: an approved action really runs — nmap without a shell, a service restart only with
     a NOPASSWD rule for exactly it, a Shelly reboot that waits for the Shelly and checks its
     relays — one at a time, then a cooldown; a dashboard approval is said on Telegram;
 12. one approved while another runs is QUEUED, in the order approved, says so on the page
     and on Telegram, and can be cancelled until its turn; a restart never runs it;
 13. a running one says its step, a long step's latest word and when it gives up (the page).
"""
from __future__ import annotations

import asyncio
import os
import shlex
import sys
import tempfile
import time

# the expected local times below are Central European: the test sets that zone itself, so it
# passes the same in a UTC container and on a laptop anywhere
os.environ["TZ"] = "Europe/Berlin"
time.tzset()

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import actions as A
from lanowl.agent import LlmAgent
from lanowl.model import Device, Inventory
from lanowl.state import StateStore, StatusTracker
from lanowl.tools import TOOL_SPECS, ToolExecutor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


DEVICES = [
    Device("192.168.10.31", "NVR", group="cameras", criticality="critical"),
    Device("192.168.10.34", "Alarm", group="security", criticality="critical"),
    Device("192.168.10.57", "Shelly pump", group="energy", criticality="critical"),
    Device("192.168.10.61", "Shelly battery_charger_contactor", group="energy", criticality="high"),
    Device("192.168.10.30", "ESP sensore", group="iot", criticality="low"),
    Device("192.168.10.103", "Model server", group="servers", criticality="critical"),
    Device("192.168.10.113", "VM HomeHub", group="servers", criticality="critical"),
    Device("10.8.0.2", "Router Lake", group="vpn", criticality="warning",
           attrs={"depends_on": "203.0.113.10"}),
]

ACTIONS_CFG = {"actions": {
    "enabled": True, "mode": "shadow", "expire_min": 15, "max_pending": 3, "max_per_day": 20,
    "repeat_after_h": 24, "pin_sha256": A.pin_hash("2389"),
    "catalog": {"nmap_scan": {"deny_groups": ["security"]},
                "nmap_service": {"deny_groups": ["security", "iot"]},
                "restart_service": {"hosts": {"192.168.10.113": {
                    "via": "key", "units": ["nodered", "mosquitto"]}}},
                "shelly_reboot": {}}}}


def _auditor(d, cfg_extra=None):
    from lanowl import main as m
    from lanowl.sinks import MqttBridge
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0},
           "observer": {"host_ip": "192.168.10.103"}, **ACTIONS_CFG, **(cfg_extra or {})}
    inv = Inventory(devices=[Device(x.ip, x.name, x.group, x.criticality, attrs=dict(x.attrs))
                             for x in DEVICES])
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
    a.resume_alerts()
    return m, a


class _Tg:
    """Fake Telegram for actions.py: what was sent, and every edit."""

    def __init__(self):
        self.sent, self.edits = [], []

    def install(self):
        self.real = (A.telegram_direct, A.telegram_edit)

        async def send(cfg, text, ids=None, chat_id="", extra=None):
            self.sent.append({"text": text, "extra": extra or {}})
            if ids is not None:
                ids.append(500 + len(self.sent))
            return True

        async def edit(cfg, mid, text, reply_markup=None):
            self.edits.append({"mid": mid, "text": text, "markup": reply_markup})
            return True
        A.telegram_direct, A.telegram_edit = send, edit
        return self

    def restore(self):
        A.telegram_direct, A.telegram_edit = self.real


def _fake_checks(a, ok=True, note="answering (2 ms)"):
    calls = []

    async def chk(p):
        calls.append((p["action"], p["ip"]))
        return {"ok": ok, "note": note}
    a.actions._check = chk
    return calls


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)


# --- 1. the rules -------------------------------------------------------------------
def test_rules():
    print("\n-- the rules --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _fake_checks(a)
        tg = _Tg().install()
        try:
            ac = a.actions
            out["outside"] = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.31",
                                               "reason": "x"})
            with ac.source("telegram"):
                P = lambda **k: ac.propose({"reason": "why", **k})       # noqa: E731
                out["unknown"] = await P(action="rm_rf", ip="192.168.10.31")
                out["noinv"] = await P(action="nmap_scan", ip="192.168.10.200")
                out["remote"] = await P(action="nmap_scan", ip="10.8.0.2")
                out["self"] = await P(action="nmap_scan", ip="192.168.10.103")
                out["alarm"] = await P(action="nmap_scan", ip="192.168.10.34")
                out["iot"] = await P(action="nmap_service", ip="192.168.10.30", ports=[80])
                out["noports"] = await P(action="nmap_service", ip="192.168.10.31")
                out["manyports"] = await P(action="nmap_service", ip="192.168.10.31",
                                           ports=list(range(1, 12)))
                out["badhost"] = await P(action="restart_service", ip="192.168.10.31",
                                         service="nodered")
                out["badunit"] = await P(action="restart_service", ip="192.168.10.113",
                                         service="sshd; reboot")
                out["notshelly"] = await P(action="shelly_reboot", ip="192.168.10.31")
                out["svc"] = await P(action="restart_service", ip="192.168.10.113",
                                     service="nodered.service")
                out["nmap"] = await P(action="nmap_service", ip="192.168.10.31",
                                      ports=[554, "80", 80])
                await _settle()
            out["items"] = list(ac.items)
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("error" in out["outside"], "outside a turn that may propose, nothing can be proposed")
    for k, why in [("unknown", "an action outside the catalog"),
                   ("noinv", "a device not in the inventory"),
                   ("remote", "a remote device behind the VPN"),
                   ("self", "lanowl's own machine"),
                   ("alarm", "nmap on the alarm (security group)"),
                   ("iot", "a version probe on cheap IoT"),
                   ("noports", "nmap_service without ports"),
                   ("manyports", "nmap_service with 11 ports"),
                   ("badhost", "restart_service on a device with no services listed"),
                   ("badunit", "a service not on the list (or a shell trick)"),
                   ("notshelly", "shelly_reboot on something that is not a Shelly")]:
        check("refused" in out[k], f"refused: {why} — {out[k].get('refused', out[k])}")
    check(out["svc"].get("proposal") and out["nmap"].get("proposal"), "valid ones are proposed")
    svc = next(p for p in out["items"] if p["action"] == "restart_service" and p["status"] == "pending")
    nm = next(p for p in out["items"] if p["action"] == "nmap_service" and p["status"] == "pending")
    check(svc["command"] == "systemctl restart nodered.service on VM HomeHub",
          "the command is built by the code, from the allow-list")
    check(nm["command"] == "nmap -sT -sV -Pn -p 80,554 192.168.10.31" and nm["args"]["ports"] == [80, 554],
          "ports are numbers, deduplicated and sorted")
    check(sum(p["status"] == "refused" for p in out["items"]) == 11,
          "every refusal is kept in the record, for reading back what the model tried")


def test_tool_offered_only_in_a_turn():
    print("\n-- the tool is offered only while a turn may propose --")
    with tempfile.TemporaryDirectory() as d:
        async def go():
            m, a = _auditor(d)
            names = lambda: [t["function"]["name"] for t in a.executor.tool_specs()]  # noqa: E731
            outside = names()
            with a.actions.source("audit"):
                inside = names()
            a.actions.switched_on = False
            with a.actions.source("telegram"):
                off = names()
            a.actions.switched_on, a.actions.pin_cfg_raw = True, ""
            with a.actions.source("telegram"):
                nopin = names()
            return outside, inside, off, nopin
        outside, inside, off, nopin = asyncio.run(go())
    check("propose_action" not in outside
          and set(outside) == {t["function"]["name"] for t in TOOL_SPECS} | {"lanowl_records", "cve_lookup"},
          "not offered to the weekly review / triages / MQTT (the read-only tools and the "
          "auditor's own records are)")
    check("propose_action" in inside and "host_log" in inside, "offered to the audit, with host_log")
    check("propose_action" not in off, "actions.enabled=false takes it away entirely")
    check("propose_action" not in nopin and "run_check" not in nopin,
          "switched on but no PIN anywhere: off as well")


# --- 3. a question's proposal, the buttons, the dry run -----------------------------------
def test_question_proposal_and_telegram_button():
    print("\n-- a question proposes; the owner approves on Telegram; nothing runs --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        calls = _fake_checks(a)
        tg = _Tg().install()
        try:
            with a.actions.source("telegram"):
                r = await a.executor.call("propose_action", {
                    "action": "nmap_scan", "ip": "192.168.10.31", "reason": "RTSP stopped"})
            await _settle()
            out["result"] = r["result"]
            out["sent"] = list(tg.sent)
            p = a.actions.items[-1]
            out["bad"] = await a.chat.on_callback(f"ax:a:{p['id']}:deadbeef")
            out["after_bad"] = p["status"]
            out["ok"] = await a.chat.on_callback(f"ax:a:{p['id']}:{p['nonce']}")
            await _settle()
            out["p"] = dict(p)
            out["again"] = await a.chat.on_callback(f"ax:r:{p['id']}:{p['nonce']}")
            out["edits"] = list(tg.edits)
            out["calls"] = list(calls)
            out["ctx"] = a.actions.context()
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = out["result"]
    check(r.get("proposal") and "DRY RUN" in r.get("mode", ""), "the model is told: proposed, dry run")
    check(len(out["sent"]) == 1, "one Telegram message for the proposal")
    msg = out["sent"][0]
    kb = (msg["extra"].get("reply_markup") or {}).get("inline_keyboard") or []
    check(len(kb) == 1 and len(kb[0]) == 2 and kb[0][0]["callback_data"].startswith("ax:a:"),
          "with an Approve and a Reject button")
    check("nmap -sT -Pn --top-ports 100 -T4 192.168.10.31" in msg["text"] and "NVR (192.168.10.31)" in msg["text"]
          and "RTSP stopped" in msg["text"] and "dry run" in msg["text"],
          "saying what would run, on what, why (the model's words), and that it is a dry run")
    check(msg["extra"].get("disable_notification") is False, "a question's proposal notifies")
    check("Unknown" in out["bad"] and out["after_bad"] == "pending", "a button without the nonce does nothing")
    check("approved" in out["ok"] and out["p"]["status"] == "done", "Approve -> done")
    o = out["p"]["outcome"]
    check(o.get("dry_run") is True and o.get("would_run") == "nmap -sT -Pn --top-ports 100 -T4 192.168.10.31",
          "the outcome is a dry run: what WOULD have run")
    check(out["calls"] == [("nmap_scan", "192.168.10.31")] * 2, "checked when proposed, and again when approved")
    e = out["edits"][-1]
    check(e["mid"] == 501 and e["markup"] == {"inline_keyboard": []}
          and "dry run, nothing was executed" in e["text"],
          "the message is edited: buttons gone, 'dry run, nothing was executed'")
    check("already" in out["again"], "a second press changes nothing")
    check(out["ctx"] and "DRY RUN" in out["ctx"][-1], "the model's next turn sees what became of it")


def test_limits_and_expiry():
    print("\n-- limits, and proposals nobody answered --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _fake_checks(a)
        tg = _Tg().install()
        try:
            ac = a.actions
            with ac.source("dashboard"):
                one = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.31", "reason": "a"})
                dup = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.31", "reason": "b"})
                await ac.propose({"action": "nmap_scan", "ip": "192.168.10.113", "reason": "c"})
                await ac.propose({"action": "shelly_reboot", "ip": "192.168.10.57", "reason": "d"})
                full = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.61", "reason": "e"})
            await _settle()
            out.update(one=one, dup=dup, full=full)
            ac.tick(time.time() + 16 * 60)
            await _settle()
            out["expired"] = [p["status"] for p in ac.items if p["status"] != "refused"]
            out["edits"] = list(tg.edits)
            # the audit may not re-propose what the owner already saw today; a question may
            with ac.source("audit"):
                out["audit_again"] = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.31",
                                                       "reason": "f"})
            with ac.source("telegram"):
                out["asked_again"] = await ac.propose({"action": "nmap_scan", "ip": "192.168.10.31",
                                                       "reason": "g"})
            await _settle()
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["dup"].get("proposal") == out["one"]["proposal"] and "already" in out["dup"]["status"],
          "the same proposal twice is the same proposal")
    check("refused" in out["full"] and "waiting" in out["full"]["refused"], "no more than 3 waiting")
    check(out["expired"] == ["expired"] * 3, "15 minutes unanswered -> expired")
    check(len(out["edits"]) == 3 and all(e["markup"] == {"inline_keyboard": []}
                                         and "Expired" in e["text"] for e in out["edits"]),
          "each expired message loses its buttons and says so")
    check("refused" in out["audit_again"] and "not again today" in out["audit_again"]["refused"],
          "the audit does not re-propose the same thing within a day")
    check(out["asked_again"].get("proposal"), "the owner asking again is always heard")


def test_owner_presses_are_not_capped():
    """The caps are the model's: a day of the owner's own updates must not fill them and get
    their presses the next morning refused."""
    print("\n-- the owner's own presses neither hit the caps nor use them up --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _fake_checks(a)
        tg = _Tg().install()
        try:
            ac, now = a.actions, time.time()
            # a busy day of the owner's own: 20 done
            ac.items += [{"id": 900 + i, "action": "nmap_scan", "ip": "192.168.10.31", "via": "dashboard",
                          "owner": True, "status": "done", "ts": now - 3600, "args": {}} for i in range(20)]
            with ac.source("telegram"):
                out["model_after_owner_day"] = await ac.propose(
                    {"action": "nmap_scan", "ip": "192.168.10.113", "reason": "a"})
            # the model's own 20 (the one above included): the model is capped, the owner is not
            ac.items += [{"id": 950 + i, "action": "nmap_scan", "ip": "192.168.10.31", "via": "telegram",
                          "status": "done", "ts": now - 3600, "args": {}} for i in range(19)]
            with ac.source("telegram"):
                out["model_capped"] = await ac.propose(
                    {"action": "nmap_scan", "ip": "192.168.10.61", "reason": "b"})
            out["owner"] = await ac.ask("nmap_scan", "192.168.10.61", "dashboard")
            # three of the model's waiting: the owner's press still goes through
            for x in ac.items:
                if x.get("status") == "done" and not x.get("owner"):
                    x["ts"] = now - 2 * 86400
            with ac.source("telegram"):
                for ip in ("192.168.10.31", "192.168.10.113", "192.168.10.57"):
                    await ac.propose({"action": "nmap_scan" if ip != "192.168.10.57" else "shelly_reboot",
                                      "ip": ip, "reason": "c"})
            out["owner_while_3_wait"] = await ac.ask("nmap_scan", "192.168.10.30", "dashboard")
            await _settle()
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["model_after_owner_day"].get("proposal"),
          "the owner's own day of presses does not use up the model's 20")
    check("refused" in out["model_capped"] and "a day" in out["model_capped"]["refused"],
          "the model's own 20 still cap the model")
    check(out["owner"].get("proposal"), "...but not the owner's press")
    check(out["owner_while_3_wait"].get("proposal"),
          "three of the model's proposals waiting do not block the owner's press")


def test_pin_sources():
    """The PIN is required: config.yaml's, or — when that is empty — the one set with /pin on
    Telegram (only its hash, in the record). Without either, actions stay off."""
    print("\n-- the dashboard PIN: config.yaml, else /pin; none = actions off --")
    out = {}

    async def go(d):
        m, a = _auditor(d, {"state": {"db_path": os.path.join(d, "s.sqlite")}})
        ac = a.actions
        _fake_checks(a)
        ac.pin_cfg_raw = ac.pin_cfg = ""                   # config.yaml without one
        out["off"] = (ac.enabled, ac.needs_pin, ac.view()["needs_pin"])
        out["ask_off"] = await ac.ask("nmap_scan", "192.168.10.61", "dashboard")
        out["short"] = ac.set_pin("12")
        out["letters"] = ac.set_pin("12ab")
        out["set"] = ac.set_pin("4321")
        out["on"] = (ac.enabled, ac.needs_pin, ac.check_pin("4321"), ac.check_pin("2389"))
        out["changed"] = ac.set_pin("5678")
        # it outlives a restart: a fresh Actions reads it back from the record
        b = A.Actions(a)
        b.pin_cfg_raw = b.pin_cfg = ""
        out["restored"] = (b.enabled, b.check_pin("5678")[0])
        out["report_tg"] = A.report({**a.cfg, "actions": {**a.cfg["actions"], "pin_sha256": ""}})
        # config.yaml wins, and /pin will not touch it
        out["cfg_wins"] = (b.__class__(a).check_pin("2389")[0], b.__class__(a).set_pin("1111"))
        # the digits themselves in pin_sha256: no PIN, and --check says why
        c = A.Actions(a)
        c.pin_cfg_raw, c.pin_cfg = "1234", ""
        out["raw"] = (c.enabled, c.needs_pin, c.set_pin("1111"))

    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["off"] == (False, True, True), "config.yaml has none: actions off, and the page is told")
    check("/pin" in out["ask_off"].get("refused", ""), "an owner's press then says how to set it")
    check(not out["short"]["ok"] and not out["letters"]["ok"], "a PIN is 4 to 12 digits")
    check(out["set"]["ok"] and "actions are on" in out["set"]["text"]
          and out["on"][0] and not out["on"][1] and out["on"][2][0] and not out["on"][3][0],
          "/pin sets it: actions on, that PIN approves, another does not")
    check(out["changed"]["ok"] and "changed" in out["changed"]["text"], "/pin again changes it")
    check(out["restored"] == (True, True), "kept (as a hash) across a restart")
    check(out["report_tg"][1] == 0 and "set on Telegram" in out["report_tg"][0],
          "--check finds it in the state: ✓")
    check(out["cfg_wins"][0] and not out["cfg_wins"][1]["ok"]
          and "config.yaml" in out["cfg_wins"][1]["text"],
          "config.yaml's PIN wins, and /pin points there")
    check(out["raw"][:2] == (False, True) and not out["raw"][2]["ok"],
          "pin_sha256 holding the digits themselves is no PIN; fix it in config.yaml")


def test_pin_report():
    print("\n-- --check: actions on need a PIN --")
    base = {"telegram": {"chat": {"enabled": True}}, "state": {"db_path": "/nonexistent/x.sqlite"}}
    off = A.report({**base, "actions": {"enabled": False}})
    good = A.report({**base, "actions": {"enabled": True, "pin_sha256": A.pin_hash("2389")}})
    raw = A.report({**base, "actions": {"enabled": True, "pin_sha256": "2389"}})
    none = A.report({**base, "actions": {"enabled": True}})
    nochat = A.report({"actions": {"enabled": True}, "state": base["state"]})
    check(off[1] == 0 and "off" in off[0], "actions off: nothing needed")
    check(good[1] == 0 and "✓ dashboard PIN" in good[0] and "from config.yaml" in good[0], "config.yaml's: ✓")
    check(raw[1] == 1 and "not a SHA-256" in raw[0] and "2389" not in raw[0],
          "the digits in pin_sha256: ✗, without repeating them")
    check(none[1] == 1 and "/pin" in none[0] and "--hash-pin" in none[0], "none: ✗, both ways named")
    check(nochat[1] == 1 and "/pin" not in nochat[0], "no Telegram chat: only config.yaml")


def test_pin_on_telegram():
    print("\n-- /pin on Telegram: the digits are deleted --")
    out = {"replies": [], "calls": []}
    from lanowl import chat as C

    async def go(d):
        m, a = _auditor(d)
        a.actions.pin_cfg_raw = a.actions.pin_cfg = ""
        real = C.telegram_call

        async def call(cfg, method, payload, timeout_s=15):
            out["calls"].append((method, payload))
            return {"ok": method != "deleteMessage" or payload["message_id"] != 99}

        async def reply(chat_id, text):
            out["replies"].append(text)
        C.telegram_call = call
        a.chat._reply = reply
        try:
            await a.chat.on_telegram("/pin", "100000001", 7)
            await a.chat.on_telegram("4321", "100000001", 8)
            out["on"] = a.actions.enabled and a.actions.check_pin("4321")[0]
            await a.chat.on_telegram("/pin@lanowl_example_bot 5678", "100000001", 99)
            out["changed"] = a.actions.check_pin("5678")[0]
            # after /pin, anything that is not digits is not taken as the PIN
            await a.chat.on_telegram("/pin", "100000001", 10)
            await a.chat.on_telegram("/status", "100000001", 11)
            await a.chat.on_telegram("1111", "100000001", 12)
            out["kept"] = a.actions.check_pin("5678")[0] and not a.actions.check_pin("1111")[0]
        finally:
            C.telegram_call = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r, calls = out["replies"], out["calls"]
    deleted = [p["message_id"] for meth, p in calls if meth == "deleteMessage"]
    check("4 to 12 digits" in r[0], "/pin asks for the digits")
    check(8 in deleted and out["on"] and "actions are on" in r[1], "the PIN message is deleted; actions are on")
    check(out["changed"] and 99 in deleted and "delete it yourself" in r[2],
          "/pin 5678 in one go works too; a message it could not delete is said")
    check(out["kept"] and 12 not in deleted, "a command cancels the wait: later digits are a question")


# --- 6. the audit ---------------------------------------------------------------------
def test_audit_rides_on_the_incident_alert():
    print("\n-- the audit's proposals ride on the incident's own alert --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _fake_checks(a)
        tg = _Tg().install()
        try:
            key = "down:192.168.10.57:energy:Shelly pump"
            a._alert_msgs[key] = {"id": 77, "text": "🔴 <b>Shelly pump</b> is down", "ts": time.time()}
            a._open_incident_keys = lambda: {key}
            with a.actions.source("audit"):
                await a.actions.propose({"action": "shelly_reboot", "ip": "192.168.10.57",
                                         "reason": "answers ping, HTTP dead"})
                await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.31",
                                         "reason": "odd"})
            await _settle()
            out["before_flush"] = (len(tg.sent), len(tg.edits))
            await a.actions.flush_audit()
            await _settle()
            out["sent"], out["edits"] = list(tg.sent), list(tg.edits)
            # the diagnosis arrives afterwards: the buttons must survive that edit
            out["decorated"] = a.actions.decorate(77, "🔴 <b>Shelly pump</b> is down\n🦉 cause")
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["before_flush"] == (0, 0), "nothing goes out while the audit is still running")
    e = [x for x in out["edits"] if x["mid"] == 77]
    check(len(e) == 1 and e[0]["text"].startswith("🔴 <b>Shelly pump</b> is down")
          and "Reboot the Shelly" in e[0]["text"] and e[0]["markup"]["inline_keyboard"],
          "the pump's proposal is EDITED into its alert, with buttons — no second message")
    check("⚠️" in e[0]["text"] and "CRITICAL" in e[0]["text"], "a critical device carries the warning")
    check(len(out["sent"]) == 1 and "The audit proposes" in out["sent"][0]["text"]
          and "NVR" in out["sent"][0]["text"]
          and out["sent"][0]["extra"].get("disable_notification") is True,
          "one with no incident goes in one SILENT message")
    text, markup = out["decorated"]
    check("🦉 cause" in text and "Reboot the Shelly" in text and markup["inline_keyboard"],
          "the diagnosis edit keeps the proposal and its buttons")


# --- 7. the dashboard ---------------------------------------------------------------------
def test_dashboard_pin():
    print("\n-- the dashboard: Reject freely, Approve with the PIN --")
    import aiohttp
    out = {}

    async def go(d):
        m, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0, "login": False}})
        _fake_checks(a)
        tg = _Tg().install()
        emitted = []
        a._emit_telegram = lambda ch, text, **k: emitted.append(text)
        try:
            with a.actions.source("dashboard"):
                for ip in ("192.168.10.31", "192.168.10.113", "192.168.10.57"):
                    await a.actions.propose({"action": "nmap_scan", "ip": ip, "reason": "r"})
            ids = [p["id"] for p in a.actions.items if p["status"] == "pending"]
            await a.dashboard.start()
            base = f"http://127.0.0.1:{a.dashboard._runner.addresses[0][1]}"
            async with aiohttp.ClientSession() as s:
                async def post(body, ctype="application/json"):
                    import json
                    async with s.post(base + "/api/action", data=json.dumps(body),
                                      headers={"Content-Type": ctype}) as r:
                        return r.status, await r.json(content_type=None) if r.status != 415 else None
                out["form"] = await post({"id": ids[0], "approve": True, "pin": "2389"}, "text/plain")
                out["nopin"] = await post({"id": ids[0], "approve": True})
                out["wrong"] = await post({"id": ids[0], "approve": True, "pin": "1234"})
                out["right"] = await post({"id": ids[0], "approve": True, "pin": "2389"})
                out["reject"] = await post({"id": ids[1], "approve": False})
                for _ in range(5):
                    out["lock"] = await post({"id": ids[2], "approve": True, "pin": "0000"})
                out["locked_right"] = await post({"id": ids[2], "approve": True, "pin": "2389"})
                async with s.get(base + "/api/state") as r:
                    out["state"] = (await r.json())["actions"]
            await _settle()
            await a.dashboard.stop()
            out["emitted"] = emitted
            out["p0"] = a.actions._get(ids[0])["status"]
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["form"][0] == 415, "a non-JSON POST is refused")
    check(out["nopin"][0] == 403 and out["wrong"][0] == 403 and out["wrong"][1]["pin"] == "wrong",
          "no PIN / a wrong PIN: refused")
    check(out["right"][0] == 200 and out["p0"] == "done", "the right PIN approves (dry run)")
    check(out["reject"][0] == 200 and out["reject"][1]["status"] == "rejected", "Reject needs no PIN")
    check(out["lock"][1]["pin"] == "locked" and out["locked_right"][1]["pin"] == "locked",
          "5 wrong in a row lock it — even the right PIN waits")
    check(len(out["emitted"]) == 1 and "locked" in out["emitted"][0], "and Telegram is told, once")
    st = out["state"]
    check(st["enabled"] and st["mode"] == "shadow" and st["pin"] and st["locked_until"]
          and len(st["pending"]) == 1 and len(st["recent"]) == 2,
          "the state carries pending, history and the lock for the page")


# --- 8. the Shelly check ------------------------------------------------------------------
def test_shelly_safety():
    print("\n-- a Shelly whose relay would change on a restart is refused --")
    pages = {
        # a contactor: gen 3, output ON, powers on OFF
        "http://192.168.10.61/shelly": {"gen": 3, "model": "S3SW-001P8EU"},
        "http://192.168.10.61/rpc/Shelly.GetConfig": {"switch:0": {"initial_state": "off"}},
        "http://192.168.10.61/rpc/Shelly.GetStatus": {"switch:0": {"output": True}},
        # a pump: gen 1, default 'last'
        "http://192.168.10.57/shelly": {"type": "SHSW-1"},
        "http://192.168.10.57/settings": {"relays": [{"default_state": "last"}]},
        "http://192.168.10.57/status": {"relays": [{"ison": True}]},
        # a gen-1 that follows its wall switch, and a roller
        "http://192.168.10.31/shelly": {"type": "SHSW-25"},
        "http://192.168.10.31/settings": {"relays": [{"default_state": "switch"}]},
        "http://192.168.10.31/status": {"relays": [{"ison": False}]},
        "http://192.168.10.113/shelly": {"type": "SHSW-25"},
        "http://192.168.10.113/settings": {"mode": "roller"},
        "http://192.168.10.113/status": {},
    }
    real = A._get_json

    async def fake(url, timeout_s=4.0):
        return pages.get(url)
    A._get_json = fake
    res = {}
    try:
        with tempfile.TemporaryDirectory() as d:
            async def go():
                m, a = _auditor(d)
                for ip in ("192.168.10.61", "192.168.10.57", "192.168.10.31", "192.168.10.113",
                           "192.168.10.30"):
                    p = {"ip": ip, "name": ip}
                    res[ip] = (await a.actions._shelly_check(p), p.get("command"))
            asyncio.run(go())
    finally:
        A._get_json = real
    r52 = res["192.168.10.61"][0]
    check(not r52["ok"] and "would come back OFF" in r52["note"],
          f"the battery contactor is refused: {r52['note']}")
    r44, cmd44 = res["192.168.10.57"]
    check(r44["ok"] and "comes back the same" in r44["note"] and cmd44 == "GET http://192.168.10.57/reboot",
          "the pump ('last') may be proposed, with the gen-1 command")
    check(res["192.168.10.61"][1] == "GET http://192.168.10.61/rpc/Shelly.Reboot", "gen 2+ command")
    check(not res["192.168.10.31"][0]["ok"] and "cannot be told" in res["192.168.10.31"][0]["note"],
          "a relay that follows a wall switch: unknown, so refused")
    check(not res["192.168.10.113"][0]["ok"] and "roller" in res["192.168.10.113"][0]["note"], "a roller: refused")
    check(not res["192.168.10.30"][0]["ok"], "no answer as a Shelly: refused")
    check(A._after_reboot(2, "restore_last", False) is False and A._after_reboot(1, "on", False) is True
          and A._after_reboot(2, "match_input", True) is None, "the power-on rules")


# --- 9. restart, and who may press ---------------------------------------------------------
def test_record_and_foreign_button():
    print("\n-- the record survives a restart; only the owner's buttons count --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        _fake_checks(a)
        tg = _Tg().install()
        try:
            with a.actions.source("telegram"):
                await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.31", "reason": "r"})
                await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.113", "reason": "r"})
            await _settle()
            a.actions.items[-1]["status"] = "running"      # died mid-check
            a.actions._save()
            b = A.Actions(a)
            out["restored"] = [(p["id"], p["status"]) for p in b.items]
            out["next"] = b._next
            out["msgs"] = sorted(b.msgs)
        finally:
            tg.restore()

        # the poller: a button from a stranger, and from the owner
        from lanowl import sinks
        answered, called = [], []

        async def fake_call(cfg, method, payload, timeout_s=0):
            answered.append((method, payload.get("text")))
            return {"ok": True}

        async def on_cb(data):
            called.append(data)
            return "fine"
        real = sinks.telegram_call
        sinks.telegram_call = fake_call
        try:
            poller = sinks.TelegramPoller({"telegram": {"chat_id": "100000001",
                                                        "chat": {"enabled": True}}},
                                          on_message=None, on_callback=on_cb)
            await poller._button({"id": "1", "data": "ax:a:1:x", "from": {"id": 555},
                                  "message": {"chat": {"id": 100000001}}})
            await poller._button({"id": "2", "data": "ax:a:1:x", "from": {"id": 100000001},
                                  "message": {"chat": {"id": 100000001}}})
        finally:
            sinks.telegram_call = real
        out["answered"], out["called"] = answered, called
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["restored"] == [(1, "pending"), (2, "failed")] and out["next"] == 3,
          "restored after a restart; one caught mid-run is 'failed — unknown', never re-run")
    check(out["msgs"] == ["501", "502"], "and which Telegram message carries which")
    check(out["called"] == ["ax:a:1:x"], "a stranger's button is not acted on; the owner's is")
    check([t for _, t in out["answered"]] == ["Not allowed.", "fine"],
          "both are answered, so no button spins forever")


# --- 10. host_log ------------------------------------------------------------------------
def test_host_log_quotes_the_models_words():
    print("\n-- host_log: the raw journal, the model's words never as shell --")
    from lanowl.hostlog import HostLogWatcher
    cfg = {"observer": {"host_ip": "192.168.10.103"},
           "hostlog": {"enabled": True, "hosts": [
               {"name": "VPS", "ip": "203.0.113.10", "user": "root", "public": True},
               {"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi"}]}}
    hl = HostLogWatcher(cfg, on_alert=lambda *a, **k: None)
    seen = []

    class _P:
        returncode = 0

        async def communicate(self):
            return (b"2026-09-24T14:59:01+0200 vps xl2tpd[812]: Connection 7 closed\n"
                    b"2026-09-24T15:00:02+0200 vps sshd[9]: Accepted publickey for root from "
                    b"192.168.10.103 port 5 ssh2\n", b"")

    async def fake_exec(*argv, **kw):
        seen.append(argv)
        return _P()
    real = asyncio.create_subprocess_exec
    asyncio.create_subprocess_exec = fake_exec
    try:
        async def go():
            evil = "x'; rm -rf / #"
            r1 = await hl.read_log("203.0.113.10", hours=6, search=evil, limit=10)
            r2 = await hl.read_log("203.0.113.10", unit="ssh; reboot")
            r3 = await hl.read_log("192.168.10.59")
            r4 = await hl.read_log("192.168.10.113", unit="nodered", noise=True, hours=999)
            return r1, r2, r3, r4
        r1, r2, r3, r4 = asyncio.run(go())
    finally:
        asyncio.create_subprocess_exec = real
    remote1 = seen[0][-1]
    check(shlex.quote("x'; rm -rf / #") in remote1 and "grep -F -i -e" in remote1,
          "the search reaches the remote shell quoted, as a fixed string")
    check("--since=-360min" in remote1 and "tail -n 30" in remote1 and "grep -Ev" in remote1
          and "N[(]DPD" in remote1,
          "the window and limit are numbers; a public host's scanner hum and keepalives are filtered")
    check(r1["lines"] == ["2026-09-24T14:59:01+02:00 vps xl2tpd[812]: Connection 7 closed"],
          "the lines come back exactly, in the network's time — minus lanowl's own login")
    from lanowl.hostlog import _local_ts
    check(_local_ts("2026-09-24T13:13:21+00:00 ubuntu sshd[1]: x") == "2026-09-24T15:13:21+02:00 ubuntu sshd[1]: x"
          and _local_ts("no timestamp here") == "no timestamp here",
          "a UTC line is shown in local time, the same instant")
    check("error" in r2 and len(seen) == 2, "a unit that is not a unit name never reaches ssh")
    check("error" in r3 and "VPS" in r3["error"], "only hosts whose log is read; it says which")
    remote4 = seen[1][-1]
    check("-u nodered" in remote4 and "grep -Ev" not in remote4 and "--since=-4320min" in remote4,
          "the home server by unit, no noise filter there, the window capped at 72h")


def test_prompts():
    print("\n-- the prompts --")
    from lanowl import prompts as P
    a = P.with_actions(P.system_prompt(""), "audit")
    q = P.with_actions(P.QA_SYSTEM_CHAT, "qa")
    check("no such tool exists" not in a and "at most ONE proposal" in a and "DRY RUN" in a,
          "the audit: 'no such tool' swapped for the ACTIONS section")
    check("say so if asked to" not in q and "catalog covers" in q, "the questions likewise")
    check("host_log" in P.QA_SYSTEM and "QUOTE the lines exactly" in P.QA_SYSTEM,
          "asked for a log, the model quotes it")
    ctx = P.build_qa_context("q", {}, proposals=["#1 nmap_scan on NVR: rejected"])
    check("RECENT PROPOSALS" in ctx and "#1 nmap_scan" in ctx, "its recent proposals are in the context")
    # a sweep's report has llm None; the audit is handed over apart and still reaches the model
    ctx = P.build_qa_context("q", {"llm": None}, audit={
        "summary": "One real issue: the Garage door.", "issues": [
            {"device": "Garage door (192.168.10.118)", "severity": "warning",
             "root_cause": "8 Wi-Fi drops in 24h", "recommendation": "a closer AP"}]},
        audit_at=1790000000.0)
    check("LAST AUDIT at " in ctx and "One real issue: the Garage door." in ctx
          and "8 Wi-Fi drops in 24h" in ctx and "a closer AP" in ctx,
          "a follow-up sees the last audit and its findings, whatever the last sweep says")


# --- 11. live -------------------------------------------------------------------------------
NMAP_XML = """<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="9999"><state state="closed"/><service name="abyss"/></port>
</ports></host></nmaprun>"""


def _live(d, extra=None):
    m, a = _auditor(d, extra)
    a.actions.mode = A.LIVE
    return m, a


def test_live_nmap():
    print("\n-- live: an approved scan runs nmap, without a shell, and reports --")
    out = {}
    real = A._exec

    async def fake_exec(argv, timeout_s):
        out.setdefault("argv", []).append(list(argv))
        return 0, NMAP_XML, ""
    A._exec = fake_exec
    try:
        async def go(d):
            m, a = _live(d)
            _fake_checks(a)
            tg = _Tg().install()
            try:
                with a.actions.source("telegram"):
                    r = await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.113",
                                                 "reason": "what does it expose"})
                await _settle()
                out["told"] = r
                p = a.actions.items[-1]
                out["toast"] = await a.chat.on_callback(f"ax:a:{p['id']}:{p['nonce']}")
                for _ in range(20):
                    await _settle()
                out["p"] = dict(p)
                out["edits"] = list(tg.edits)
                out["ctx"] = a.actions.context()
            finally:
                tg.restore()
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        A._exec = real
    check("LIVE" in out["told"]["mode"], "the model is told it is live")
    check("running it now" in out["toast"], "the button says it is running")
    check(out["argv"] == [["nmap", "-sT", "-Pn", "--top-ports", "100", "-T4", "192.168.10.113", "-oX", "-"]],
          "nmap is exec'd as an argument list, from the catalog")
    o = out["p"]["outcome"]
    check(out["p"]["status"] == "done" and o["ran"] and
          o["result"] == "2 open of the top 100 TCP ports: 22 ssh, 80 http",
          f"done, with what it found: {o.get('result')}")
    check(o["lines"] == ["22/tcp open ssh — OpenSSH 9.6p1", "80/tcp open http"], "and the port lines")
    check(len(out["edits"]) == 2 and "running" in out["edits"][0]["text"]
          and out["edits"][0]["markup"] == {"inline_keyboard": []}
          and "✅ <b>Done</b>" in out["edits"][1]["text"] and "22/tcp open ssh" in out["edits"][1]["text"],
          "the message: buttons gone at once ('running…'), then the result")
    check("RUN: 2 open" in out["ctx"][-1], "the model's next turn knows what the scan found")
    ports = A.parse_nmap_xml(NMAP_XML)
    check([x["state"] for x in ports] == ["open", "open", "closed"] and A.parse_nmap_xml("junk") is None,
          "nmap XML parsed; anything else is not")


def test_live_restart_service():
    print("\n-- live: a service restart needs a NOPASSWD rule for exactly it --")
    out = {}

    async def go(d):
        m, a = _live(d)
        tg = _Tg().install()
        calls = []
        allowed = {"n": "0"}

        async def fake_login_run(ip, remote, timeout_s=20, sudo_pw=False):
            calls.append(remote)
            if "sudo -n -l" in remote:
                return 0, "active\n" + ("ALLOWED" if allowed["n"] == "1" else "REFUSED") + "\n", ""
            return 0, "rc=0\nactive\n", ""
        a.actions._login_run = fake_login_run
        try:
            with a.actions.source("telegram"):
                out["no_rule"] = await a.actions.propose({"action": "restart_service",
                                                          "ip": "192.168.10.113",
                                                          "service": "nodered", "reason": "r"})
                allowed["n"] = "1"
                out["ok"] = await a.actions.propose({"action": "restart_service",
                                                     "ip": "192.168.10.113",
                                                     "service": "nodered", "reason": "r"})
            await _settle()
            p = a.actions.items[-1]
            a.actions.decide(p["id"], True, "dashboard")
            emitted = []
            a._emit_telegram = lambda ch, text, **k: emitted.append(text)
            for _ in range(20):
                await _settle()
            out["p"] = dict(p)
            out["emitted"] = emitted
            out["calls"] = calls
            with a.actions.source("telegram"):
                out["again"] = await a.actions.propose({"action": "restart_service",
                                                        "ip": "192.168.10.113",
                                                        "service": "nodered", "reason": "r"})
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("refused" in out["no_rule"] and "no sudo for it" in out["no_rule"]["refused"],
          "without the sudoers rule it is refused, and says why")
    check(out["ok"].get("proposal"), "with it, proposed")
    run = [c for c in out["calls"] if "systemctl restart" in c and "sudo -n -l" not in c]
    check(len(run) == 1 and run[0].startswith("sudo -n /usr/bin/systemctl restart nodered.service;"),
          "runs `sudo -n systemctl restart <allow-listed unit>` — never a prompt")
    check(out["p"]["status"] == "done" and "restarted — active" in out["p"]["outcome"]["result"],
          "done: restarted and active again")
    check(len(out["emitted"]) == 1 and "Approved on the dashboard" in out["emitted"][0],
          "approved on the dashboard -> said on Telegram")
    check("refused" in out["again"] and "already ran" in out["again"]["refused"],
          "30 minutes before the same restart can be proposed again")


def test_live_shelly_reboot():
    print("\n-- live: a Shelly reboot waits for it and checks its relays --")
    state = {"on": True, "rebooted": 0, "after": True}

    async def fake_json(url, timeout_s=4.0):
        if url.endswith("/shelly"):
            return {"type": "SHSW-1"}
        if url.endswith("/settings"):
            return {"relays": [{"default_state": "last"}]}
        if url.endswith("/status"):
            return {"relays": [{"ison": state["on"] if not state["rebooted"] else state["after"]}]}
        return None

    async def fake_get(url, timeout_s=6.0):
        state["rebooted"] += 1
        state["url"] = url
        return 200
    real = (A._get_json, A._http_get, A.SHELLY_FIRST_S, A.SHELLY_POLL_S)
    A._get_json, A._http_get, A.SHELLY_FIRST_S, A.SHELLY_POLL_S = fake_json, fake_get, 0, 0
    res = {}
    try:
        async def go(d, after):
            state.update(rebooted=0, after=after)
            m, a = _live(d)
            tg = _Tg().install()
            try:
                with a.actions.source("dashboard"):
                    await a.actions.propose({"action": "shelly_reboot", "ip": "192.168.10.57",
                                             "reason": "HTTP dead"})
                p = a.actions.items[-1]
                a._emit_telegram = lambda *x, **k: None
                a.actions.decide(p["id"], True, "telegram")
                for _ in range(40):
                    await _settle()
                return dict(p)
            finally:
                tg.restore()
        with tempfile.TemporaryDirectory() as d:
            res["same"] = asyncio.run(go(d, True))
        with tempfile.TemporaryDirectory() as d:
            res["changed"] = asyncio.run(go(d, False))
    finally:
        A._get_json, A._http_get, A.SHELLY_FIRST_S, A.SHELLY_POLL_S = real
    s, c = res["same"], res["changed"]
    check(state["url"] == "http://192.168.10.57/reboot", "the gen-1 reboot endpoint, once")
    check(s["status"] == "done" and "relay 0 ON as before" in s["outcome"]["result"],
          f"done: back, relays as before — {s['outcome'].get('result')}")
    check(c["status"] == "failed" and "relay 0 was ON, is now OFF" in c["outcome"]["error"],
          "a relay that came back different is a FAILURE, said loudly")


def test_live_timeout_and_prompts():
    print("\n-- live: a hung action is reported as unknown; the prompts say live --")
    out = {}
    real_t = dict(A.RUN_TIMEOUT_S)

    async def go(d):
        m, a = _live(d)
        _fake_checks(a)
        tg = _Tg().install()

        async def hang(p, chk):
            await asyncio.sleep(5)
        a.actions._run = hang
        A.RUN_TIMEOUT_S["nmap_scan"] = 0.05
        try:
            with a.actions.source("telegram"):
                await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.31", "reason": "r"})
            p = a.actions.items[-1]
            a.actions.decide(p["id"], True, "telegram")
            await asyncio.sleep(0.3)
            out["p"] = dict(p)
        finally:
            tg.restore()
    try:
        with tempfile.TemporaryDirectory() as d:
            asyncio.run(go(d))
    finally:
        A.RUN_TIMEOUT_S.clear()
        A.RUN_TIMEOUT_S.update(real_t)
    check(out["p"]["status"] == "failed" and "unknown" in out["p"]["outcome"]["error"],
          "no answer in time -> failed, outcome unknown")
    from lanowl import prompts as P
    live = P.with_actions(P.QA_SYSTEM, "qa", live=True)
    dry = P.with_actions(P.QA_SYSTEM, "qa", live=False)
    check("LIVE" in live and "DRY RUN" not in live and "DRY RUN" in dry,
          "the prompt says live when it is, dry run when it is not")


def test_live_queue():
    print("\n-- live: approved while another runs -> queued in order, cancellable, said so --")
    out = {}

    async def go(d):
        m, a = _live(d)
        _fake_checks(a)
        tg = _Tg().install()
        gate, ran = asyncio.Event(), []

        async def run(p, chk):
            ran.append(p["id"])
            if len(ran) == 1:
                await gate.wait()                  # the first one takes its time
            return {"ok": True, "ran": True, "result": "fine"}
        a.actions._run = run
        try:
            ids = []
            for ip in ("192.168.10.31", "192.168.10.113", "192.168.10.30"):
                with a.actions.source("telegram"):
                    await a.actions.propose({"action": "nmap_scan", "ip": ip, "reason": "r"})
                ids.append(a.actions.items[-1]["id"])
            await _settle()
            r1 = a.actions.decide(ids[0], True, "telegram")
            await _settle()
            r2 = a.actions.decide(ids[1], True, "dashboard")
            r3 = a.actions.decide(ids[2], True, "dashboard")
            await _settle()
            p1, p2, p3 = (a.actions._get(i) for i in ids)
            out["r"] = (r1, r2, r3)
            out["q"] = (p1.get("queued"), p2.get("queued"), p3.get("queued"))
            out["pub"] = [a.actions.public(x) for x in (p1, p2, p3)]
            out["mk"] = a.actions._compose({"pids": [ids[1]], "key": "", "head": "", "base": ""})
            out["no_stop"] = a.actions.cancel(ids[0], "dashboard")
            out["toast"] = await a.actions.on_callback(f"ax:c:{ids[2]}:{p3['nonce']}")
            out["moved"] = a.actions.public(p2)
            gate.set()
            for _ in range(30):
                await _settle()
            out["ran"], out["ids"] = list(ran), ids
            out["st"] = [a.actions._get(i)["status"] for i in ids]
            out["p2"] = dict(p2)
            out["edits"] = list(tg.edits)
            out["ctx"] = a.actions.context()
            # a restart with one still waiting its turn: it never started, and says so
            p2.update(status="running", queued=True)
            a.actions._save()
            out["restored"] = A.Actions(a)._get(ids[1])
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    ids = out["ids"]
    check(out["q"] == (None, True, True) and "running it now" in out["r"][0]["text"]
          and out["r"][1]["queued"] and "queued behind #1" in out["r"][1]["text"],
          "the first runs; the two approved while it runs are queued, and told so")
    check(not out["pub"][0]["queued"] and out["pub"][1]["queue"].startswith("behind #1 (")
          and out["pub"][2]["queue"].endswith(" and 1 more"),
          f"the page gets the line: {out['pub'][2]['queue']!r}")
    check(out["mk"][1] == {"inline_keyboard": [[{"text": "✖️ Cancel", "callback_data":
                                                 f"ax:c:{ids[1]}:{out['p2']['nonce']}"}]]}
          and "⏸" in out["mk"][0] and "queued behind #1" in out["mk"][0],
          "its Telegram message says queued, with a Cancel button")
    check(not out["no_stop"]["ok"] and "cannot be stopped halfway" in out["no_stop"]["error"],
          "one already running cannot be cancelled")
    check("cancelled — nothing was done" in out["toast"] and not out["moved"]["queue"].endswith("more"),
          "a queued one is cancelled from its button; the one behind moves up")
    check(out["ran"] == [ids[0], ids[1]] and out["st"] == ["done", "done", "cancelled"],
          f"they run in the order approved, the cancelled one never: {out['st']}")
    check(out["p2"].get("started_ts") and "queued" not in out["p2"],
          "at its turn it is no longer queued, and has a start time")
    check(any("queued behind" in e["text"] for e in out["edits"])
          and any("✖️ Cancelled on Telegram" in e["text"] for e in out["edits"]),
          "Telegram: queued, then cancelled — on the messages themselves")
    check(any("cancelled on Telegram" in c and "nothing was done" in c for c in out["ctx"]),
          "the model's next turn knows it was cancelled")
    r = out["restored"]
    check(r["status"] == "skipped" and r["outcome"]["ran"] is False
          and "before its turn" in r["outcome"]["check"],
          "a restart with one queued: skipped, never run — not 'failed, unknown'")


def test_live_steps():
    print("\n-- live: a running action says its step, a long step's latest word, when it gives up --")
    out = {}

    async def go(d):
        m, a = _live(d)
        _fake_checks(a)
        tg = _Tg().install()
        gate = asyncio.Event()

        async def run(p, chk):
            a.actions.step("installing the updates")
            a.actions.progress(text="Setting up libssl3 (3.0.17) ...", n=3, of=10)
            await gate.wait()
            return {"ok": True, "ran": True, "result": "fine"}
        a.actions._run = run
        try:
            with a.actions.source("telegram"):
                await a.actions.propose({"action": "nmap_scan", "ip": "192.168.10.31", "reason": "r"})
            p = a.actions.items[-1]
            a.actions.decide(p["id"], True, "telegram")
            for _ in range(10):
                await _settle()
            out["mid"] = a.actions.public(p)
            a.actions.progress(error="no answer from it right now")
            out["err"] = dict(a.actions.public(p)["detail"])
            gate.set()
            for _ in range(20):
                await _settle()
            a.actions.step("after the end")            # nothing is running: ignored
            out["end"] = a.actions.public(p)
            out["cur"] = a.actions._cur
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    mid = out["mid"]
    check([x["step"] for x in mid["trail"]] == ["checking it again", "running", "installing the updates"]
          and all(x["ts"] for x in mid["trail"]), f"its steps, each with its time: {[x['step'] for x in mid['trail']]}")
    check(mid["detail"]["text"].startswith("Setting up libssl3") and mid["detail"]["n"] == 3
          and mid["detail"]["of"] == 10, "and the step's own latest word")
    check(mid["started_ts"] and mid["deadline"] and
          abs(mid["deadline"] - mid["started_ts"] - A.RUN_TIMEOUT_S["nmap_scan"]) < 5,
          "when it started, and when it gives up")
    check(out["err"]["error"] == "no answer from it right now" and out["err"]["text"].startswith("Setting up"),
          "a machine that does not answer is said so; its last good word is kept")
    e = out["end"]
    check(e["status"] == "done" and e["detail"] is None and len(e["trail"]) == 3 and out["cur"] is None,
          "done: the live word goes, the steps it took stay; a step after the end changes nothing")


if __name__ == "__main__":
    for fn in [test_rules, test_tool_offered_only_in_a_turn,
               test_question_proposal_and_telegram_button, test_limits_and_expiry,
               test_owner_presses_are_not_capped, test_pin_sources, test_pin_report,
               test_pin_on_telegram,
               test_audit_rides_on_the_incident_alert, test_dashboard_pin, test_shelly_safety,
               test_record_and_foreign_button, test_host_log_quotes_the_models_words,
               test_prompts, test_live_nmap, test_live_restart_service, test_live_shelly_reboot,
               test_live_timeout_and_prompts, test_live_queue, test_live_steps]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
