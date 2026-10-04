"""The local model's switch: run with `python -m tests.test_model_switch`.

No network, no model, no Telegram — the agent's calls are fakes and so is the sender.
Pinned down here (Auditor.set_model):

  1. while off, the agent asks Ollama nothing, whoever calls; switched off mid-call, the call
     returns None (a model that failed) — while a Stop or a timeout still unwinds as before;
  2. switching off stops the audit in flight, whose digest still goes out, and the dashboard's
     pending answers; it is said on Telegram from the dashboard; it survives a restart;
  3. off: the digest still goes (scheduled and Audit now), says the model is off, and no model
     call is made; the Ollama check is not probed and its open incident closes quietly;
  4. the log triages stand down while off, and the router's does not replay the hours off;
  5. /model, /model off, /model on; a question while off says so; POST /api/model.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import weekly
from lanowl.agent import LlmAgent
from lanowl.model import Device, Inventory
from lanowl.report import format_digest
from lanowl.state import StateStore, StatusTracker
from lanowl.sweep import CheckResult, DeviceStatus, Snapshot
from lanowl.tools import ToolExecutor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


DEVICES = [
    Device("192.168.10.117", "Boiler", group="home", criticality="critical"),
    Device("192.168.10.36", "TV Lounge", group="media", criticality="info"),
]


def _auditor(d, cfg_extra=None, persist=True):
    from lanowl import main as m
    from lanowl.sinks import MqttBridge
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0},
           "observer": {"host_ip": "192.168.10.103"},
           "model": {"url": "http://127.0.0.1:9", "name": "test-model"}, **(cfg_extra or {})}
    inv = Inventory(devices=[Device(x.ip, x.name, x.group, x.criticality) for x in DEVICES])
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
    if persist:
        a.resume_alerts()
    return m, a


def _sweep(a, ts=None):
    ts = ts or time.time()
    snap = Snapshot(ts=ts, devices=[
        DeviceStatus(ip=x.ip, name=x.name, group=x.group, criticality=x.criticality, up=True,
                     reachable=True, latency_ms=2.0, checks=[CheckResult("icmp", True)])
        for x in a.inv.devices], wan={"1.1.1.1": True})
    a.executor.snapshot = snap
    return snap, a._make_report(snap)


def _fake_telegram(m, sent):
    async def fake_send(cfg, text, ids=None, **kw):
        sent.append(text)
        if ids is not None:
            ids.append(900 + len(sent))
        return True
    m.telegram_direct = fake_send


# --- 1. the agent -----------------------------------------------------------------------
def test_agent_guard():
    print("\n-- the agent: off asks nothing; a cut call returns None; a Stop still stops --")
    out = {}

    async def go():
        ag = LlmAgent({"model": {"url": "http://127.0.0.1:9"}}, None)
        called = []

        async def fake_text(*a, **kw):
            called.append(1)
            await asyncio.sleep(3600)
            return "never"
        ag._ask_text = fake_text

        ag.off = True
        out["off"] = await ag.ask_text("s", "q")
        out["off_called"] = len(called)
        ag.off = False

        t = asyncio.ensure_future(ag.ask_text("s", "q"))
        await asyncio.sleep(0.01)
        out["n"] = ag.cut()
        out["cut"] = await t
        out["left"] = len(ag._calls) + len(ag._cut)

        t = asyncio.ensure_future(ag.ask_text("s", "q"))       # the owner's Stop
        await asyncio.sleep(0.01)
        t.cancel()
        try:
            await t
            out["stop"] = "returned"
        except asyncio.CancelledError:
            out["stop"] = "cancelled"

        try:                                                   # the answer's wall clock
            await asyncio.wait_for(ag.ask_text("s", "q"), timeout=0.02)
            out["timeout"] = "returned"
        except asyncio.TimeoutError:
            out["timeout"] = "timeout"
        out["unload_fails_quietly"] = await ag.unload() is False   # nothing on :9
    asyncio.run(go())
    check(out["off"] is None and out["off_called"] == 0, "off: None, and the model is never called")
    check(out["n"] == 1 and out["cut"] is None and out["left"] == 0,
          "switched off mid-call: that call returns None, nothing left behind")
    check(out["stop"] == "cancelled", "a Stop still cancels the caller")
    check(out["timeout"] == "timeout", "a timeout is still a timeout")
    check(out["unload_fails_quietly"], "an unload Ollama does not answer fails quietly")


# --- 2. the switch ------------------------------------------------------------------------
def test_switch_off_mid_audit():
    print("\n-- switching off stops the audit, whose digest still goes; told on Telegram --")
    sent, out = [], {}

    async def go(d):
        m, a = _auditor(d)
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            snap, rep = _sweep(a)
            started = asyncio.Event()

            async def slow_audit(system, ctx):
                started.set()
                await asyncio.sleep(3600)
            a.agent._run_audit = slow_audit
            unloads = []

            async def fake_unload():
                unloads.append(1)
                return True
            a.agent.unload = fake_unload
            audit = asyncio.ensure_future(
                a.run_llm_audit(snap, rep, send_digest=True, reason="check-now"))
            await asyncio.wait_for(started.wait(), 2)
            r = a.set_model(False, "dashboard")
            await asyncio.wait_for(audit, 2)
            for _ in range(5):
                await asyncio.sleep(0)
            out.update(r=r, sent=list(sent), unloads=len(unloads), busy=a._llm_busy,
                       on=a.model_view()["on"], rec=a.state.load_record("model"),
                       events=a.state.events(0, kind="model"))
            out["again"] = a.set_model(False, "telegram")
        finally:
            m.telegram_direct = real
        # a restart: read back off, the agent off with it
        m2, b = _auditor(d)
        out["restart"] = (b.no_llm, b.agent.off, b.model_view()["by"])
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["r"]["ok"] and out["r"]["changed"], "switched off")
    check(any("The owl is asleep" in s and "from the dashboard" in s for s in out["sent"]),
          "said on Telegram, from the dashboard")
    check(any("What it was doing has been stopped" in s for s in out["sent"]),
          "...and that the audit was stopped")
    check(any("lanowl digest" in s for s in out["sent"]),
          "the stopped audit's digest (Audit now) still went out")
    check(out["unloads"] == 1, "the model is unloaded from Ollama")
    check(not out["busy"], "the model lock is free")
    check(not out["on"] and out["rec"].get("off") and out["rec"].get("by") == "dashboard",
          "kept in the records")
    check(len(out["events"]) == 1 and out["events"][0]["value"] == 0, "and in the events")
    check(out["again"]["ok"] and not out["again"]["changed"], "switching off twice changes nothing")
    check(out["restart"] == (True, True, "dashboard"), "a restart keeps it off")


def test_off_digests_without_the_model():
    print("\n-- off: the digest still goes, says so, and nothing asks the model --")
    sent, out = [], {}

    async def go(d):
        m, a = _auditor(d)
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            calls = []

            async def spy(*x, **kw):
                calls.append(1)
                return None
            a.agent._run_audit = a.agent._ask_text = a.agent._ask_json = spy

            async def fake_unload():
                return True
            a.agent.unload = fake_unload
            a.set_model(False, "telegram")
            await asyncio.sleep(0)
            out["told"] = list(sent)                    # from Telegram: the reply, not a send
            snap, rep = _sweep(a)
            out["probe"] = await a._probe_ollama()
            await a.run_llm_audit(snap, rep, send_digest=True, reason="check-now")
            await a.run_llm_audit(snap, rep, send_digest=False, reason="incident")
            await asyncio.sleep(0)
            out["sent"] = list(sent)
            out["weekly"] = await a.run_weekly("requested")
            out["calls"] = len(calls)
            out["audit_ev"] = a.state.events(0, kind="audit")
            r = a.set_model(True, "telegram")
            out["on"] = (r["changed"], a.no_llm, a.agent.off, "model_off" in a._last_report)
            for _ in range(5):                          # the weekly's send, to the fake
                await asyncio.sleep(0)
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(not out["told"], "switched from Telegram: no separate message (the reply is it)")
    check(out["probe"] is None, "the Ollama check is not probed")
    dig = [s for s in out["sent"] if "lanowl digest" in s]
    check(len(dig) == 1 and "The owl is asleep" in dig[0] and "/model on" in dig[0],
          "Audit now sends the digest, which says the model is off")
    check("The owl is asleep" in out["weekly"], "the weekly review says so too")
    check(out["calls"] == 0, "not one model call")
    check(out["audit_ev"] and "switched off" in out["audit_ev"][-1]["detail"],
          "the record says why there was no assessment")
    check(out["on"] == (True, False, False, False), "and back on")


def test_ollama_incident_closes_quietly():
    print("\n-- an open Ollama incident closes without a 'back online' --")
    sent, out = [], {}

    async def go(d):
        m, a = _auditor(d)
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            snap = type("S", (), {"ts": time.time(), "devices": []})()
            issue = {"kind": "degraded", "ip": "192.168.10.103", "group": "services",
                     "device": "Ollama", "severity": "warning", "detail": "refused"}
            a._diff_criticals({"issues": [issue]}, snap)
            out["open_before"] = set(a.gate.open_keys())

            async def fake_unload():
                return True
            a.agent.unload = fake_unload
            a.set_model(False, "telegram")
            out["open_after"] = set(a.gate.open_keys())
            sent.clear()
            a._diff_criticals({"issues": []}, snap)
            await asyncio.sleep(0)
            out["sent"] = list(sent)
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["open_before"] and not out["open_after"], "its incident is closed")
    check(not out["sent"], "...without a recovery message")


# --- 4. the log triages -------------------------------------------------------------------
def test_triages_stand_down():
    print("\n-- the log triages stand down while off; the router's does not replay --")
    from lanowl.hostlog import HostLogWatcher
    from lanowl.wanwatch import WanWatcher
    on = {"v": False}
    started = []
    w = WanWatcher({}, lambda *x, **k: None, agent=object(), model_on=lambda: on["v"])
    w._triage_mark = 100.0
    w._consider_triage([(200.0, {"message": "x"})])
    check(w._triage_mark is None and w._triage_task is None,
          "router log: nothing started, and its watermark let go")
    h = HostLogWatcher({}, lambda *x, **k: None, agent=object(), model_on=lambda: on["v"])
    h._consider_triage(type("H", (), {"last_triage": 0, "_shapes": set()})(), ["a line"])
    check(h._triage_task is None, "host log: nothing started")
    on["v"] = True
    w._consider_triage([(300.0, {"message": "x"})])
    check(w._triage_mark == 300.0 and w._triage_task is None,
          "back on: it adopts the buffer as it is, no replay of the hours off")


# --- 5. Telegram, the dashboard -----------------------------------------------------------
def test_telegram():
    print("\n-- /model, /model off, /model on; a question while off --")
    replies = []

    async def go(d):
        m, a = _auditor(d)

        async def reply(chat, text):
            replies.append(text)
        a.chat._reply = reply

        async def fake_unload():
            return True
        a.agent.unload = fake_unload
        a._last_report = {"overall_health": "ok", "counts": {"up": 2, "total": 2, "down": 0},
                          "wan_ok": True, "wan_state": "ok", "issues": [], "summary": "All good"}
        for t in ("/model", "/model off", "/model", "why is the boiler slow?", "/audit",
                  "/model on", "/help"):
            await a.chat.on_telegram(t, "100000001")
            await asyncio.sleep(0)
        for t in list(a.chat._tasks):
            await t
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = replies
    check("<b>on</b>" in r[0] and "test-model" in r[0], "/model says it is on, and which")
    check("The owl is asleep" in r[1], "/model off switches it off")
    check("<b>off</b>" in r[2] and "/model on" in r[2], "/model then says off, and how back")
    q = [x for x in r if "can't answer" in x]
    check(q and "Right now" in q[0], "a question while off says so, with what is certain")
    check(any("without it" in x for x in r), "/audit while off: the digest, without the model")
    check(any("The owl is awake" in x for x in r), "/model on")
    check("/model on | off" in r[-1], "/help lists it")


def test_dashboard():
    print("\n-- the dashboard: POST /api/model, the state, Ask while off --")
    import aiohttp
    out, sent = {}, []

    async def go(d):
        m, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0}})
        real = m.telegram_direct
        _fake_telegram(m, sent)

        async def fake_unload():
            return True
        a.agent.unload = fake_unload
        try:
            _sweep(a)
            await a.dashboard.start()
            base = f"http://127.0.0.1:{a.dashboard._runner.addresses[0][1]}"
            # an answer waiting for the model when it is switched off
            async with a.model_turn():
                async with aiohttp.ClientSession() as s:
                    async with s.post(base + "/api/ask", json={"q": "hello?"}) as r:
                        out["asked"] = await r.json()
                    await asyncio.sleep(0.05)
                    async with s.post(base + "/api/model", json={"on": "no"}) as r:
                        out["bad"] = r.status
                    async with s.post(base + "/api/model", json={"on": False}) as r:
                        out["off"] = (r.status, await r.json())
            await asyncio.sleep(0.05)
            async with aiohttp.ClientSession() as s:
                async with s.get(base + f"/api/chat?c={out['asked']['c']}") as r:
                    j = await r.json()
                    out["turn"] = j["conv"]["turns"][-1]
                    out["chat_model"] = j["model"]
                async with s.get(base + "/api/state") as r:
                    out["state"] = await r.json()
                async with s.post(base + "/api/ask", json={"q": "and now?"}) as r:
                    out["ask_off"] = (r.status, await r.json())
                async with s.post(base + "/api/model", json={"on": True}) as r:
                    out["on"] = (r.status, await r.json())
            await asyncio.sleep(0)
            await a.dashboard.stop()
            out["sent"] = list(sent)
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["bad"] == 400, "a sloppy body is refused")
    check(out["off"][0] == 200 and out["off"][1]["changed"], "switched off from the page")
    check(out["turn"]["status"] == "stopped" and "switched off" in out["turn"].get("error", ""),
          "the waiting answer ends: stopped, the model was switched off")
    ms = out["state"]["model_switch"]
    check(ms["on"] is False and ms["by"] == "dashboard" and ms["since"], "the state says off, since, by")
    check(out["chat_model"]["off"] and not out["chat_model"]["cli"], "Ask knows it is the switch")
    check(out["ask_off"][0] == 503 and "switched off" in out["ask_off"][1]["error"],
          "a question while off is refused, saying why")
    check(out["on"][0] == 200 and out["on"][1]["changed"], "back on from the page")
    check(len([s for s in out["sent"] if "local model o" in s]) == 2, "both said on Telegram")


def test_no_llm_wins():
    print("\n-- --no-llm: the switch cannot turn it on --")
    with tempfile.TemporaryDirectory() as d:
        from lanowl import main as m
        from lanowl.sinks import MqttBridge
        cfg = {"telegram": {"outbox_file": os.path.join(d, "o.json")}}
        inv = Inventory(devices=list(DEVICES))
        st = StateStore(os.path.join(d, "s.sqlite"))
        ex = ToolExecutor(cfg, inv, MqttBridge(cfg), st)

        async def go():
            a = m.Auditor(cfg, inv, MqttBridge(cfg), st, StatusTracker(), ex, LlmAgent(cfg, ex),
                          no_llm=True)
            return a.set_model(True, "dashboard"), a.model_view()
        r, v = asyncio.run(go())
        st.close()
    check(not r["ok"] and "--no-llm" in r["text"], "refused, saying why")
    check(v["cli"] and not v["on"], "the page is told it is the flag")


def test_formats():
    print("\n-- the reminder line in the digest and the weekly --")
    now = time.time()
    rep = {"overall_health": "ok", "wan_ok": True, "wan_state": "ok", "issues": [],
           "counts": {"total": 2, "up": 2, "down": 0}, "summary": "All good",
           "model_off": {"since": now - 60, "by": "dashboard"}}
    check("🦉 <b>The owl is asleep</b> since" in format_digest(rep, now), "the digest")
    check("The owl is asleep" not in format_digest({**rep, "model_off": None}, now), "only while off")
    check("The owl is asleep" in weekly.format_weekly({"model_off": {"since": now}}, None),
          "the weekly")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"\n{'FAILED: ' + str(len(_fails)) if _fails else 'all passed'}")
    sys.exit(1 if _fails else 0)
