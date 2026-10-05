"""Pausing a device: run with `python -m tests.test_pause`.

No network, no model, no Telegram — sweeps are built by hand and the sender is a fake.
Pinned down here (pause.py):

  1. a paused device is never an issue, never down in the counts, never part of a group
     majority, and never something the model may escalate on;
  2. pausing closes its open incident WITHOUT a "back online", and every pause and resume
     made on the dashboard is said on Telegram;
  3. a pause ends only by hand (/resume or the switch) — never because the device came back
     online (manual stop, manual start);
  4. resuming a device that is still down reports it at once;
  5. a pause survives a restart, follows a DHCP move, and is dropped with its device;
  6. /pause, /resume and /paused on Telegram; POST /api/pause on the dashboard;
  7. the logbook, the digest and the weekly review all say "paused", not "down".
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import logbook, weekly
from lanowl.agent import LlmAgent
from lanowl.model import Device, Inventory
from lanowl.pause import Pauses, find_devices, intervals, overlaps, paused_at
from lanowl.report import _muted_labels, build_report, format_digest
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
    Device("192.168.10.36", "TV Lounge LG OLED", group="media", criticality="info"),
    Device("192.168.10.57", "Shelly pump", group="energy", criticality="critical"),
    Device("192.168.10.46", "Shelly kitchen-table", group="energy", criticality="low"),
    Device("192.168.10.103", "Model server", group="servers", criticality="critical"),
]


def _status(dev: Device, up: bool) -> DeviceStatus:
    return DeviceStatus(ip=dev.ip, name=dev.name, group=dev.group,
                        criticality=dev.criticality, up=up, reachable=up,
                        latency_ms=2.0 if up else None,
                        checks=[CheckResult("icmp", up)], attrs=dev.attrs)


# --- 1. the pure parts ------------------------------------------------------------
def test_a_record_from_the_auto_resume_days_loads():
    print("\n-- an older pause record (with auto-resume fields) still loads --")
    q = Pauses()
    n = q.restore({"192.168.10.36": {"ts": 5, "by": "telegram", "name": "TV",
                                    "seen_down": True, "up_since": 99.0}},
                  known={"192.168.10.36": "TV"})
    check(n == 1 and q.is_paused("192.168.10.36"), "the pause comes back")
    check(q.get("192.168.10.36") == {"ts": 5.0, "by": "telegram", "name": "TV"},
          "...without the fields nothing reads any more")


def test_restore_rename_and_drop():
    print("\n-- the record: survives, follows a DHCP move, dies with its device --")
    p = Pauses()
    p.pause("192.168.10.150", "TV", "dashboard", now=5)     # a DHCP address, rebound
    p.pause("192.168.10.77", "Gone", "dashboard", now=6)
    p.pause("192.168.10.117", "Boiler", "telegram", now=7)
    q = Pauses()
    n = q.restore(json.loads(json.dumps(p.dump())),
                  known={"192.168.10.36": "TV", "192.168.10.117": "Boiler"})
    check(n == 2 and q.is_paused("192.168.10.117"), "a known device's pause comes back")
    check(q.is_paused("192.168.10.36") and not q.is_paused("192.168.10.150"),
          "one keyed by a DHCP address follows the name to the configured address")
    check(not q.is_paused("192.168.10.77"), "one for a device no longer in the inventory is dropped")
    q.rename("192.168.10.36", "192.168.10.151")
    check(q.is_paused("192.168.10.151") and not q.is_paused("192.168.10.36"),
          "discovery's rebind carries it along")


def test_intervals():
    print("\n-- history: when was a device paused? --")
    ev = lambda ts, kind, ip: {"ts": ts, "kind": kind, "detail": json.dumps({"ip": ip})}
    rows = [ev(100, "pause", "a"), ev(200, "resume", "a"), ev(300, "pause", "a"),
            ev(150, "resume", "b"), ev(50, "blip", "a")]
    iv = intervals(rows, current={"a": {"ts": 300}, "c": {"ts": 10}}, now=1000)
    check(iv["a"] == [(100, 200), (300, 1000)], f"closed and running pauses ({iv.get('a')})")
    check(iv["b"] == [(0.0, 150)], "a resume whose pause is older than the rows: open from the start")
    check(iv["c"] == [(10, 1000)], "a running pause with no event on record still counts")
    check(paused_at(iv, "a", 250) is False and paused_at(iv, "a", 350), "paused_at")
    check(overlaps(iv, "a", 180, 250) and not overlaps(iv, "a", 210, 290), "overlaps")


def test_find_devices():
    print("\n-- naming a device on Telegram --")
    inv = Inventory(devices=list(DEVICES))
    check([d.ip for d in find_devices(inv.devices, "tv")] == ["192.168.10.36"], "tv -> the LG")
    check(len(find_devices(inv.devices, "shelly")) == 2, "shelly -> ambiguous")
    check([d.name for d in find_devices(inv.devices, "shelly pump")] == ["Shelly pump"],
          "every word must match")
    check([d.name for d in find_devices(inv.devices, "192.168.10.117")] == ["Boiler"], "by address")
    check(find_devices(inv.devices, "  ") == [], "nothing for nothing")


def test_the_report_leaves_a_paused_device_alone():
    print("\n-- a paused device is not an issue, not down, not a majority --")
    cams = [Device(f"192.168.10.{80 + i}", f"Cam {i}", group="cameras", criticality="warning")
            for i in range(5)]
    inv = Inventory(devices=cams + DEVICES[:1], groups={"cameras": {"majority_down_critical": True}})
    st = [_status(d, False) for d in cams] + [_status(DEVICES[0], True)]
    for d in st[:3]:
        d.paused = True                                 # three cameras off for the holiday
    snap = Snapshot(ts=time.time(), devices=st, wan={"1.1.1.1": True})
    down = {d.ip for d in st if not d.up}
    r = build_report(snap, inv, down, {})
    check(not [i for i in r["issues"] if i["ip"] in {c.ip for c in cams[:3]}],
          "no issue for a paused device")
    check(r["counts"]["paused"] == 3 and r["counts"]["down"] == 2 and r["counts"]["up"] == 1
          and sum(r["counts"][k] for k in ("up", "down", "asleep", "paused")) == 6,
          f"counts add up, paused apart from down ({r['counts']})")
    grp = [i for i in r["issues"] if i["kind"] == "group"]
    check(len(grp) == 1, "the two watched cameras both dark is still the whole (watched) range")
    for d in st[3:5]:
        d.paused = True
    r = build_report(snap, inv, down, {})
    check(r["overall_health"] == "ok" and not r["issues"], "everything dark is paused: all good")
    check(all(d["paused"] and not d["asleep"] for d in r["devices"] if d["group"] == "cameras"),
          "the device list says paused, not asleep")
    labels = _muted_labels(r)
    check("cam 0" in labels and "192.168.10.80" in labels, "the model may not escalate on it")
    st[5].paused = True
    check("boiler" in _muted_labels(build_report(snap, inv, down, {})),
          "...even while it answers")


# --- 2. lanowl ---------------------------------------------------------------
def _auditor(d, cfg_extra=None):
    from lanowl import main as m
    from lanowl.sinks import MqttBridge
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0},
           "observer": {"host_ip": "192.168.10.103"}, **(cfg_extra or {})}
    inv = Inventory(devices=[Device(x.ip, x.name, x.group, x.criticality) for x in DEVICES])
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
    a.resume_alerts()          # loop mode: the record is read and written
    return m, a


def _sweep(a, down: set, ts: float):
    """sweep_cycle without the network: the same steps, in the same order."""
    snap = Snapshot(ts=ts, devices=[_status(d, d.ip not in down) for d in a.inv.devices],
                    wan={"1.1.1.1": True})
    for d in snap.devices:
        t = a.tracker.update(d.ip, d.up, now=ts)
        a.state.record_sample(d.ip, d.up, d.latency_ms, {}, ts=ts)
        if t:
            t.detail = d.name
            a.state.record_transition(t)
    a.state.commit()
    a.executor.snapshot = snap
    rep = a._make_report(snap)
    a._diff_criticals(rep, snap)
    return rep


def _fake_telegram(m, sent):
    async def fake_send(cfg, text, ids=None, **kw):
        sent.append(text)
        if ids is not None:
            ids.append(900 + len(sent))
        return True
    m.telegram_direct = fake_send


def test_pause_closes_the_incident_quietly():
    print("\n-- pausing: the open alert closes without a 'back online'; resuming a dead one pages --")
    sent, out = [], {}

    async def go(d):
        m, a = _auditor(d)
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            t = time.time() - 3600
            for i in range(3):                              # boiler dies
                _sweep(a, {"192.168.10.117"}, t + 60 * i)
            await asyncio.sleep(0)
            out["alerted"] = [s for s in sent if "CRITICAL" in s]
            sent.clear()
            r = a.set_paused("192.168.10.117", True, "dashboard")
            await asyncio.sleep(0)
            out["result"] = r
            out["notice"] = list(sent)
            out["open"] = a.gate.open_keys()
            out["report"] = a._last_report
            sent.clear()
            for i in range(3, 8):                           # still off, then another sweep
                _sweep(a, {"192.168.10.117"}, t + 60 * i)
            await asyncio.sleep(0)
            out["quiet"] = list(sent)
            r = a.set_paused("192.168.10.117", False, "dashboard")
            await asyncio.sleep(0)
            out["resume"] = (r, list(sent))
            sent.clear()
            _sweep(a, {"192.168.10.117"}, t + 60 * 9)
            await asyncio.sleep(0)
            out["repaged"] = list(sent)
            out["mac"] = a.set_paused("192.168.10.103", True, "dashboard")
            out["again"] = a.set_paused("192.168.10.57", True, "telegram")
            out["twice"] = a.set_paused("192.168.10.57", True, "telegram")
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(len(out["alerted"]) == 1, "the dead boiler paged once")
    check(out["result"]["ok"] and out["result"]["changed"], "the pause is accepted")
    check(len(out["notice"]) == 1 and "Monitoring paused" in out["notice"][0]
          and "from the dashboard" in out["notice"][0] and "critical device" in out["notice"][0],
          f"a pause from the dashboard is said on Telegram, flagged critical ({out['notice']})")
    check(not out["open"], "its incident is closed")
    rep = out["report"]
    check(not rep["issues"] and rep["counts"]["paused"] == 1
          and rep["paused"][0]["ip"] == "192.168.10.117",
          "the dashboard's report shows it paused at once, not a sweep later")
    check(not out["quiet"], f"no 'back online', no re-alert while paused ({out['quiet']})")
    r, msgs = out["resume"]
    check(r["changed"] and msgs and "Monitoring resumed" in msgs[-1]
          and "still unreachable" in msgs[-1], "resuming a dead device says it is still down")
    check(len(out["repaged"]) == 1 and "CRITICAL" in out["repaged"][0],
          "...and the next sweep reports it like any fresh outage")
    check(not out["mac"]["ok"] and "is lanowl itself" in out["mac"]["text"],
          "lanowl's own host cannot be paused")
    check(out["again"]["changed"] and not out["twice"]["changed"], "pausing twice is harmless")


def test_holiday_round_trip():
    print("\n-- the holiday: pause the TV while it is on, switch off, come home, switch on --")
    sent, out = [], {}

    async def go(d):
        m, a = _auditor(d)
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            t = time.time() - 86400
            _sweep(a, set(), t)
            a.set_paused("192.168.10.36", True, "telegram", now=t + 1)
            await asyncio.sleep(0)
            out["telegram_pause"] = list(sent)          # a Telegram pause is its own reply
            for i in range(1, 30):                      # still on for half an hour
                _sweep(a, set(), t + 60 * i)
            out["still_paused"] = a.pauses.is_paused("192.168.10.36")
            for i in range(30, 300):                    # off for the holiday
                _sweep(a, {"192.168.10.36"}, t + 60 * i)
            out["news"] = set(a._digest_news)
            out["issues"] = a._last_report["issues"]
            for i in range(300, 420):                   # back on, for two hours
                _sweep(a, set(), t + 60 * i)
            await asyncio.sleep(0)
            out["still_paused_back"] = a.pauses.is_paused("192.168.10.36")
            out["quiet_back"] = list(sent)
            a.set_paused("192.168.10.36", False, "dashboard", now=t + 60 * 420)   # by hand
            await asyncio.sleep(0)
            out["resumed"] = not a.pauses.is_paused("192.168.10.36")
            out["msgs"] = list(sent)
            now = t + 60 * 421
            out["log"] = logbook.entries(a.state, a.inv, a.cfg, now,
                                         paused=a._pause_intervals(now),
                                         paused_now=a.pauses.ips())
            out["hist"] = a._llm_history(now - 6 * 3600)
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(not out["telegram_pause"], "pausing from Telegram sends nothing extra (the reply is the notice)")
    check(out["still_paused"], "answering after the pause did not end it")
    check(not out["news"] and not out["issues"], "switched off: no issue, nothing for the digest")
    check(out["still_paused_back"], "back online for two hours: still paused — only a hand ends it")
    check(not out["quiet_back"], f"...and nothing was said about it coming back ({out['quiet_back']})")
    check(out["resumed"], "the switch turned back on: watched again")
    check(len(out["msgs"]) == 1 and "Monitoring resumed" in out["msgs"][0]
          and "TV Lounge" in out["msgs"][0], f"one message says so ({out['msgs']})")
    tv = [e for e in out["log"] if e["ip"] == "192.168.10.36"]
    check(len(tv) == 2 and all(e["paused"] for e in tv),
          f"the logbook marks the holiday outage as paused ({tv})")
    trans, flaps = out["hist"]
    check(not [x for x in trans if x["ip"] == "192.168.10.36"],
          "and the model's history leaves it out")


def test_record_survives_a_restart():
    print("\n-- a restart keeps the pause --")
    with tempfile.TemporaryDirectory() as d:
        async def one():
            m, a = _auditor(d)
            a.set_paused("192.168.10.36", True, "telegram")

        async def two():
            m, a = _auditor(d)
            return a.pauses.entries(), a._pause_intervals(time.time())
        asyncio.run(one())
        es, iv = asyncio.run(two())
    check([e["ip"] for e in es] == ["192.168.10.36"] and es[0]["by"] == "telegram",
          "the pause is read back by the next process")
    check("192.168.10.36" in iv, "and its history is in the events table")


def test_telegram_commands():
    print("\n-- /pause, /resume, /paused --")
    out = {}

    async def go(d):
        m, a = _auditor(d)
        for i in range(2):                  # two misses: the boiler is confirmed down
            _sweep(a, {"192.168.10.117"}, time.time() - 60 + 60 * i)
        c = a.chat
        out["none"] = c.pause_command("/paused", "")
        out["usage"] = c.pause_command("/pause", "")
        out["two"] = c.pause_command("/pause", "tv, boiler")
        out["amb"] = c.pause_command("/pause", "shelly")
        out["miss"] = c.pause_command("/pause", "fridge")
        out["list"] = c.pause_command("/paused", "")
        out["one"] = c.pause_command("/resume", "tv")
        out["all"] = c.pause_command("/resume", "all")
        out["left"] = a.pauses.entries()
        replies = []

        async def reply(chat, text):
            replies.append(text)
        c._reply = reply
        await c.on_telegram("/pause@lanowl_example_bot TV", "100000001")
        await c.on_telegram("/help", "100000001")
        out["replies"] = replies
        out["after"] = a.pauses.ips()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("Nothing is paused" in out["none"], "/paused with nothing paused")
    check("Say which" in out["usage"], "/pause alone explains itself")
    check(out["two"].count("Monitoring paused") == 2, "two devices at once, comma-separated")
    check("TV Lounge LG OLED (192.168.10.36)" in out["two"], "each named with its address")
    check("matches 2 devices" in out["amb"] and "Shelly pump" in out["amb"],
          "an ambiguous name asks which, listing them")
    check("No device matches" in out["miss"], "an unknown name says so")
    check("Paused</b> (2)" in out["list"] and "off" in out["list"] and "answering" in out["list"],
          f"/paused lists them, off or answering ({out['list']})")
    check("Monitoring resumed" in out["one"], "/resume tv")
    check("Monitoring resumed" in out["all"] and "still unreachable" in out["all"] and not out["left"],
          "/resume all ends every pause, and says the boiler is still down")
    check(out["replies"] and "Monitoring paused" in out["replies"][0]
          and out["after"] == {"192.168.10.36"}, "the bot's @name and any case are fine")
    check("/pause" in out["replies"][1], "/help lists the new commands")


def test_dashboard_switch():
    print("\n-- the dashboard switch: POST /api/pause --")
    import aiohttp
    out, sent = {}, []

    async def go(d):
        m, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0, "login": False}})
        real = m.telegram_direct
        _fake_telegram(m, sent)
        try:
            _sweep(a, set(), time.time())
            await a.dashboard.start()
            base = f"http://127.0.0.1:{a.dashboard._runner.addresses[0][1]}"
            async with aiohttp.ClientSession() as s:
                async with s.post(base + "/api/pause", data='{"ip":"192.168.10.36","paused":true}',
                                  headers={"Content-Type": "text/plain"}) as r:
                    out["form"] = r.status
                async with s.post(base + "/api/pause", json={"ip": "10.9.9.9", "paused": True}) as r:
                    out["unknown"] = r.status
                async with s.post(base + "/api/pause", json={"ip": "192.168.10.36", "paused": "yes"}) as r:
                    out["notbool"] = r.status
                async with s.post(base + "/api/pause", json={"ip": "192.168.10.103", "paused": True}) as r:
                    out["mac"] = (r.status, await r.json())
                async with s.post(base + "/api/pause", json={"ip": "192.168.10.36", "paused": True}) as r:
                    out["pause"] = (r.status, await r.json())
                async with s.get(base + "/api/state") as r:
                    out["state"] = await r.json()
                async with s.post(base + "/api/pause", json={"ip": "192.168.10.36", "paused": False}) as r:
                    out["resume"] = (r.status, await r.json())
            await asyncio.sleep(0)
            await a.dashboard.stop()
            out["sent"] = list(sent)
        finally:
            m.telegram_direct = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["form"] == 415, "a non-JSON POST is refused, as for every POST")
    check(out["unknown"] == 400 and out["notbool"] == 400, "unknown device / sloppy body refused")
    check(out["mac"][0] == 409 and not out["mac"][1]["ok"], "lanowl's host cannot be paused")
    check(out["pause"][0] == 200 and out["pause"][1]["changed"], "a pause is accepted")
    st = out["state"]
    tv = [x for x in st["devices"] if x["ip"] == "192.168.10.36"]
    check(tv and tv[0]["paused"] and st["paused"] and st["paused"][0]["ip"] == "192.168.10.36"
          and st["pause"]["self_ip"] == "192.168.10.103",
          "the state shows it paused, with what the sheet needs to explain it")
    check(out["resume"][0] == 200 and out["resume"][1]["changed"], "and resumed")
    check(len(out["sent"]) == 2 and "Monitoring paused" in out["sent"][0]
          and "Monitoring resumed" in out["sent"][1], "both said on Telegram")


def test_digest_and_weekly_name_it():
    print("\n-- the digest and the weekly review list what is paused --")
    now = time.time()
    rep = {"overall_health": "ok", "wan_ok": True, "wan_state": "ok", "issues": [],
           "counts": {"total": 5, "up": 4, "down": 0, "asleep": 0, "paused": 1},
           "devices": [], "summary": "All good",
           "paused": [{"ip": "192.168.10.36", "name": "TV <LG>", "ts": now - 3600, "up": False}]}
    txt = format_digest(rep, now)
    check("4/5 up · 1 paused" in txt, "the count line says paused")
    check("Paused, not watched" in txt and "TV &lt;LG&gt; (192.168.10.36)" in txt
          and ", off" in txt, "the device is named, escaped, off")
    with tempfile.TemporaryDirectory() as d:
        st = StateStore(os.path.join(d, "s.sqlite"))
        inv = Inventory(devices=list(DEVICES))
        f = weekly.compute_facts(st, inv, now=now, paused={"192.168.10.117": [(now - 100, now)]},
                                 paused_now=rep["paused"])
        st.close()
    check("paused_by_owner" in f and "Paused, not watched" in weekly.format_weekly(f, None),
          "the weekly review reminds of it")


if __name__ == "__main__":
    for fn in [test_a_record_from_the_auto_resume_days_loads, test_restore_rename_and_drop,
               test_intervals, test_find_devices, test_the_report_leaves_a_paused_device_alone,
               test_pause_closes_the_incident_quietly, test_holiday_round_trip,
               test_record_survives_a_restart, test_telegram_commands, test_dashboard_switch,
               test_digest_and_weekly_name_it]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
