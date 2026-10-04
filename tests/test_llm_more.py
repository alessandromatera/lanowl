"""What the model does beyond the hourly summary: run with `python -m tests.test_llm_more`.

No network, no model, no Telegram — every one of them is a fake. Pinned down here:

  1. the agent always keeps its last turn for the answer, and counts its own tool calls
     (not a counter that is never reset);
  2. the model's cause and suggestion reach the digest, escaped, under the right issue —
     and never under the switched-off TV;
  3. an incident's diagnosis is EDITED into the alert that announced it, never sent as a
     second message; one still waiting in the outbox leaves with it;
  4. the router's log turns into evidence: a device that rejoined with four others is a
     shared event, and .10 is not .100;
  5. the VPS: scanner noise is counted not triaged, the burst rule is off, our own session
     is ours, and a login that succeeds from a stranger pages once;
  6. the weekly review is due exactly once, and its numbers go out even without the model;
  7. the chat answers only its owner, and /status never waits for the model.
"""
from __future__ import annotations

import asyncio
import logging
import datetime
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import sinks, weekly
from lanowl.agent import LlmAgent
from lanowl.hostlog import HostLogWatcher
from lanowl.model import Device, Inventory
from lanowl.report import format_diagnosis_note, format_digest, match_diagnosis
from lanowl.state import StateStore
from lanowl.tools import ToolExecutor

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


# --- 1. the agent loop --------------------------------------------------------------
class _Exec:
    def __init__(self):
        self.calls = 0

    async def call(self, name, args):
        self.calls += 1
        return {"tool": name, "result": {"ok": True}}


def test_json_with_line_breaks_in_strings():
    """A fix's commands come "one per line", and the model writes those line breaks as they are,
    inside the JSON string: strict JSON threw every such answer away (seen on a real network:
    two fixes lost in a row, "no JSON in its answer")."""
    print("\n-- a model's JSON with raw line breaks inside a string --")
    from lanowl.agent import extract_json
    raw = '{"summary": "Turn off password logins",\n "steps": [{"where": "VPS", "commands": "sed -i x /etc/ssh/sshd_config\nsystemctl reload ssh"}]}'
    v = extract_json(raw)
    check(v is not None and v["steps"][0]["commands"] == "sed -i x /etc/ssh/sshd_config\nsystemctl reload ssh",
          "read, the line break kept in the value")
    check(extract_json("Here it is:\n```json\n" + raw + "\n```") == v, "...also fenced, after a sentence")
    check(extract_json("no json here") is None and extract_json('["a list"]') is None, "still None when there is none")


def test_json_slips_mended_and_asked_again():
    """A security review came back unreadable even with line breaks accepted: shell commands
    carry backslashes that are no JSON escape (sed's `\\(`), and a list can end in a comma.
    Those two are mended; anything else is asked again once, with what the parser said."""
    print("\n-- a model's JSON slips: mended, or asked again with the parser's words --")
    from lanowl.agent import extract_json
    check(extract_json(r'''{"fix": "sed -i 's/\(Permit\).*/\1 no/' f; grep -E '\s+'"}''')["fix"]
          == r"sed -i 's/\(Permit\).*/\1 no/' f; grep -E '\s+'", "a backslash that is no JSON escape: kept as written")
    check(extract_json('{"a": [1, 2,], "b": {"c": 3,},}') == {"a": [1, 2], "b": {"c": 3}}, "trailing commas")
    check(extract_json('{"q": "x \\"y\\" z", "n": "a\\nb"}') == {"q": 'x "y" z', "n": "a\nb"},
          "valid escapes untouched")

    ag = LlmAgent({"model": {}}, _Exec())
    seen, answers = [], ['{"verdict": "fine", "why": "he said "ok" here"}', '{"verdict": "fine"}']

    async def chat(session, messages, use_tools):
        seen.append([dict(m) for m in messages])
        return {"message": {"content": answers[len(seen) - 1]}}
    ag._chat = chat
    import lanowl.agent as A
    v = asyncio.run(ag.ask_json("system", "is it fine?"))
    check(v == {"verdict": "fine"} and len(seen) == 2, "unreadable: asked once more, and the second answer used")
    check("Expecting ',' delimiter" in seen[1][-1]["content"] and seen[1][-2]["role"] == "assistant",
          "...told exactly what the parser said about its first answer")
    seen.clear()
    answers[1] = "still not json"
    logged = []
    h = logging.Handler()
    h.emit = lambda rec: logged.append(rec.getMessage())
    logging.getLogger("lanowl.agent").addHandler(h)
    try:
        v = asyncio.run(ag.ask_json("system", "is it fine?"))
    finally:
        logging.getLogger("lanowl.agent").removeHandler(h)
    check(v is None and len(seen) == 2 and any("Expecting ',' delimiter" in m and "twice" in m for m in logged),
          "unreadable twice: None, and the log says why")


def test_agent_keeps_its_last_turn_for_the_answer():
    print("\n-- the model that keeps investigating still answers --")
    ag = LlmAgent({"model": {"max_tool_iters": 4}}, _Exec())
    seen = []

    async def chat(session, messages, use_tools):
        seen.append(use_tools)
        if use_tools:     # a model that would call tools forever if allowed
            return {"message": {"role": "assistant", "content": "",
                                "tool_calls": [{"function": {"name": "ping_host",
                                                             "arguments": {"ip": "1.2.3.4"}}}]}}
        return {"message": {"role": "assistant",
                            "content": '{"overall_health": "ok", "summary": "fine", "issues": []}'}}
    ag._chat = chat
    out = asyncio.run(ag.run_audit("sys", "ctx"))
    check(out is not None and out.get("summary") == "fine",
          "an answer comes back instead of 'hit max tool iterations'")
    check(seen == [True, True, True, False], f"last of 4 turns is asked without tools ({seen})")
    check(ag.last_tool_calls == 3, f"tool calls are counted per run ({ag.last_tool_calls})")
    asyncio.run(ag.run_audit("sys", "ctx"))
    check(ag.last_tool_calls == 3, "...and reset for the next one, not accumulated")

    async def chat_text(session, messages, use_tools):
        return {"message": {"role": "assistant", "content": "  The boiler dropped at 14:02.  "}}
    ag._chat = chat_text
    check(asyncio.run(ag.ask_text("sys", "q")) == "The boiler dropped at 14:02.",
          "a question gets plain text back")


# --- 2. the digest shows the diagnosis ------------------------------------------------
def _report(issues, llm_issues, devices=None):
    return {"overall_health": "degraded", "counts": {"up": 50, "total": 53, "down": 3},
            "wan_ok": True, "wan_state": "ok", "issues": issues, "summary": "3 down <all>",
            "devices": devices or [], "llm": {"summary": "x", "issues": llm_issues}}


def test_digest_carries_the_diagnosis():
    print("\n-- the model's cause reaches the phone, under the right line --")
    issues = [
        {"device": "Boiler", "ip": "192.168.10.117", "severity": "high", "detail": "unreachable (icmp)"},
        {"device": "TV", "ip": "192.168.10.140", "severity": "info", "detail": "unreachable (icmp)"},
    ]
    llm_issues = [
        {"device": "Boiler (192.168.10.117)", "ip": "192.168.10.117", "severity": "high",
         "root_cause": "dropped with 4 others at 14:02 <AP>", "recommendation": "check AP kitchen"},
        {"device": "TV (192.168.10.140)", "ip": "192.168.10.140", "severity": "info",
         "root_cause": "switched off", "recommendation": "none"},
        {"device": "Shelly garage (192.168.10.60)", "ip": "192.168.10.60", "severity": "warning",
         "root_cause": "rejoined DHCP 9 times in 24h", "recommendation": "move it closer to an AP"},
    ]
    txt = format_digest(_report(issues, llm_issues), now=time.time())
    lines = txt.splitlines()
    i = next(n for n, l in enumerate(lines) if "Boiler" in l and "unreachable" in l)
    check("dropped with 4 others" in lines[i + 1] and "check AP kitchen" in lines[i + 1],
          "the cause and suggestion sit directly under the boiler")
    check("&lt;AP&gt;" in txt and "<AP>" not in txt, "model text is HTML-escaped")
    check("&lt;all&gt;" in txt, "...and so is the summary")
    check("switched off" not in txt, "the TV (info) gets no diagnosis line")
    check("also noticed" in txt and "Shelly garage" in txt and "9 times" in txt,
          "what the model found that no rule raised is listed separately")


def test_diagnosis_note():
    print("\n-- the note edited into an alert --")
    issue = {"device": "Boiler", "ip": "192.168.10.117"}
    llm = {"summary": "one AP restarted", "issues": [
        {"device": "Boiler (192.168.10.117)", "ip": "192.168.10.117",
         "root_cause": "AP restart", "recommendation": "check AP"}]}
    n = format_diagnosis_note([issue], llm, at=0)
    check(n.startswith("\n\n🦉") and "AP restart" in n and "→ check AP" in n and "model" in n,
          f"one issue: cause + suggestion, marked as the model's: {n!r}")
    two = format_diagnosis_note([issue, {"device": "Group 'cameras'", "ip": "-"}],
                                {"summary": "s", "issues": llm["issues"] + [
                                    {"device": "Group 'cameras' (switch)", "ip": "-",
                                     "root_cause": "PoE switch"}]}, at=0)
    check("Likely causes" in two and "PoE switch" in two and "AP restart" in two,
          "a batched alert gets one line per incident, matched by name when there is no address")
    none = format_diagnosis_note([{"device": "X", "ip": "192.168.10.33"}], llm, at=0)
    check("one AP restarted" in none, "no matching issue -> the model's summary instead")
    check(format_diagnosis_note([issue], None) == "", "no audit -> nothing is added")
    check(match_diagnosis({"device": "Boiler", "ip": "192.168.10.34"}, llm["issues"]) is None,
          ".10 does not match an issue about .106")


# --- 3. telegram: ids, edits, the outbox ---------------------------------------------
class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Session:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def post(self, url, json=None):
        self.calls.append(json)
        return _Resp(*self.replies.pop(0))


def test_message_ids_and_the_outbox():
    print("\n-- an alert remembers its message id; a queued one takes its diagnosis along --")
    s = _Session([(200, json.dumps({"ok": True, "result": {"message_id": 4711}}))])
    ids = []
    ok = asyncio.run(sinks._send_part(s, "u", "c", "🔴 x", ids=ids))
    check(ok is True and ids == [4711], f"the delivered message's id is kept ({ids})")

    with tempfile.TemporaryDirectory() as d:
        ob = sinks.TelegramOutbox(os.path.join(d, "o.json"))
        ob.add("🔴 CRITICAL 2 issues", key="", keys=["k1", "k2"])
        ob.add("🔴 CRITICAL other", key="k3")
        check(ob.annotate("k2", "\n\n🦉 AP restart"), "a queued batched alert is found by any key")
        check(not ob.annotate("nope", "x"), "an unknown key finds nothing")
        got = []
        real = sinks.telegram_direct

        async def fake(cfg, text, ids=None, **kw):
            ids.append(99)
            return True
        sinks.telegram_direct = fake
        try:
            asyncio.run(ob.flush({}, set(), on_sent=lambda keys, mid, text: got.append((keys, mid, text))))
        finally:
            sinks.telegram_direct = real
        check(len(got) == 2 and got[0][0] == ["k1", "k2"] and got[0][1] == 99,
              "flush reports which keys each delivered message covered")
        check("🦉 AP restart" in got[0][2] and "🦉" not in got[1][2],
              "the note left with the right message only")


# --- 4. the router's log as evidence ---------------------------------------------------
class _WW:
    def __init__(self, rows):
        self.log_rows = rows
        self.findings = [{"ts": time.time() - 60, "source": "router log", "problem": False,
                          "severity": "info", "summary": "guest Wi-Fi churn"}]


def _row(ts, msg):
    return (datetime.datetime.fromtimestamp(ts), {"message": msg, "topics": "dhcp,info"})


def test_router_log_evidence():
    print("\n-- the router's own log explains a drop --")
    now = time.time()
    t = now - 3600
    rows = [
        _row(t, "bridge deassigned 192.168.10.117 for 02:00:5E:10:00:08 boiler"),
        _row(t, "bridge assigned 192.168.10.117 for 02:00:5E:10:00:08 boiler"),
        _row(t + 1, "bridge assigned 192.168.10.145 for 02:00:5E:10:00:0E temp_inside"),
        _row(t + 1, "bridge assigned 192.168.10.116 for 02:00:5E:10:00:11 temp_ext"),
        _row(t + 2, "bridge assigned 192.168.10.131 for 02:00:5E:10:00:0F ESP_A1B2C3"),
        _row(t + 500, "bridge assigned 192.168.10.114 for 02:00:5E:10:00:07 esp32"),
    ]
    inv = Inventory(devices=[Device("192.168.10.117", "Boiler", attrs={"mac": "02:00:5E:10:00:08"}),
                             Device("192.168.10.34", "Shelly lamp"),
                             Device("192.168.10.145", "Thermometer inside")])
    with tempfile.TemporaryDirectory() as d:
        ex = ToolExecutor({}, inv, None, StateStore(os.path.join(d, "s.sqlite")))
        ex.wanwatch = _WW(rows)
        ev = ex._router_evidence("192.168.10.117", "02:00:5E:10:00:08")
        tog = (ev.get("rejoined_with_others") or [{}])[0]
        check(ev["dhcp_rejoins"] == 1 and tog.get("count") == 3,
              f"it rejoined once, with three others ({tog})")
        check("Thermometer inside" in tog.get("with", []), "others are named from the inventory")
        ten = ex._router_evidence("192.168.10.34", "")
        check(ten["lines_24h"] == 0, ".10 does not match lines about .100 or .106")
        f = asyncio.run(ex.call("log_findings", {"hours": 1}))
        check(f["result"] and f["result"][0]["summary"] == "guest Wi-Fi churn",
              "log_findings returns what the triage concluded")


def test_internet_questions():
    """2026-09-25 12:17, "test internet connectivity": the model pinged 9.9.9.9 and 1.1.1.1,
    was refused as "not in inventory", and said it could not ping them; and with the router's
    log three hours old (restarted for an upgrade) it said "no fiber outages in 3 days"."""
    print("\n-- 'test internet connectivity' --")
    from lanowl import probes
    now = time.time()
    cfg = {"wan": {"targets": ["8.8.8.8", "208.67.222.222", "1.0.0.1"],
                   "path": {"route_comment": "Fiber", "main": "fiber", "backup": "antenna",
                     "main_probe": "9.9.9.9", "backup_probe": "1.1.1.1", "backup_standby": True}}}
    inv = Inventory(devices=[Device("192.168.10.117", "Boiler")])
    answers = {"9.9.9.9": True, "1.1.1.1": False}

    async def fake_ping(ip, timeout_ms=1000, count=2):
        return probes.ProbeResult(answers.get(ip, True), 12.0 if answers.get(ip, True) else None,
                                  "icmp")

    ww = type("W", (), {})()
    ww.path = {"link": "fiber", "on_backup": False}
    ww.outages_from_log = lambda: []
    ww.snapshot_state = lambda: {"flaps_24h": 0}
    real = probes.ping
    probes.ping = fake_ping
    try:
        with tempfile.TemporaryDirectory() as d:
            ex = ToolExecutor(cfg, inv, None, StateStore(os.path.join(d, "s.sqlite")))
            ex.wanwatch = ww
            desc = next(t for t in ex.tool_specs() if t["function"]["name"] == "ping_host")[
                "function"]["parameters"]["properties"]["ip"]["description"]
            check("8.8.8.8" in desc and "9.9.9.9" in desc and "STANDBY" in desc,
                  "ping_host names the addresses it takes")
            call = lambda n, a: asyncio.run(ex.call(n, a))                  # noqa: E731
            fib = call("ping_host", {"ip": "9.9.9.9"}).get("result") or {}
            check(fib.get("ok") and fib.get("link") == "fiber"
                  and "the fiber itself answers" in fib.get("meaning", ""),
                  f"9.9.9.9 is the fiber's own test ({fib.get('meaning')})")
            ant = call("ping_host", {"ip": "1.1.1.1"}).get("result") or {}
            check(ant.get("link") == "antenna" and "standby" in ant.get("meaning", ""),
                  f"1.1.1.1 silent while on the fiber is standby ({ant.get('meaning')})")
            ww.path = {"link": "antenna", "on_backup": True}
            ant = call("ping_host", {"ip": "1.1.1.1"}).get("result") or {}
            check("failing too" in ant.get("meaning", ""),
                  "...but silent while ON the antenna is a fault")
            ww.path = {"link": "fiber", "on_backup": False}
            tcp = call("tcp_check", {"ip": "9.9.9.9", "port": 53})
            check("refused" in tcp.get("error", "") and "8.8.8.8" in tcp["error"]
                  and "9.9.9.9" not in tcp["error"].split("takes are")[-1],
                  f"other tools still refuse it, and say what they take ({tcp.get('error')})")
            other = call("ping_host", {"ip": "4.4.4.4"})
            check("9.9.9.9 (fiber only)" in other.get("error", ""),
                  f"a refused ping names the per-link addresses ({other.get('error')})")

            ww.log_rows = [_row(now - 3 * 3600, "router rebooted")]
            h = call("wan_history", {"days": 3})["result"]
            check("UNKNOWN before" in h.get("note", "") and "none since" in h["note"]
                  and "flaps_24h" in h["note"],
                  f"a log shorter than the question says so ({h.get('note')})")
            h7 = call("wan_history", {"days": 7})["result"]
            check("never 'none in 7 days'" in h7.get("note", ""), "...in the days asked")
            ww.log_rows = [_row(now - 10 * 86400, "start")]
            h = call("wan_history", {"days": 3})["result"]
            check("note" not in h and h["main_outages"] == [],
                  "a log that covers the window: no note, and none is none")
            ww.log_rows = [_row(now - 3 * 86400, "start")]
            h = call("wan_history", {"days": 7})["result"]
            check("UNKNOWN before" in h.get("note", "") and "flaps_24h" not in h["note"],
                  "a log older than a day leaves flaps_24h alone")
    finally:
        probes.ping = real


# --- 5. the VPS ---------------------------------------------------------------------------
VPS_CFG = {
    "hostlog": {
        "enabled": True, "interval_s": 120,
        "hosts": [{"name": "VPS", "ip": "203.0.113.10", "user": "root", "public": True,
                   "trusted": ["10.8.0.0/24"], "about": "the VPN hub"}],
        "burst": {"enabled": True, "window_s": 600, "fail_attempts": 3, "repeat_s": 3600},
        "connections": {"enabled": True, "max_established": 600, "confirm_polls": 2},
        "triage": {"enabled": True, "cooldown_s": 0, "timeout_s": 5, "max_lines": 40},
    },
    "observer": {"host_ip": "192.168.10.103"},
}
CUR = "s=1;i=2"


def _vps_out(lines, noise="--- noise 120 40 1.2.3.4 5.6.7.8 198.51.100.7", me="198.51.100.7"):
    return "\n".join([f"--- self {me}"] + lines + [f"-- cursor: {CUR}", noise,
                      "--- conns ---", "3", "2"])


class _Agent:
    def __init__(self):
        self.asks = []

    async def ask_json(self, system, user_context, timeout_s=None):
        self.asks.append((system, user_context))
        return {"problem": False, "summary": "fine"}


def test_vps_is_watched_without_the_noise():
    print("\n-- the VPS: scanners counted, a stranger's login paged --")
    alerts, ag = [], _Agent()
    w = HostLogWatcher(VPS_CFG, lambda t, key="": alerts.append((t, key)), agent=ag)
    h = w.hosts[0]
    check(h.public and not h.burst, "a public host has the burst rule off by default")
    h.cursor = CUR
    cmd = w._remote_cmd(h)
    check("awk" in cmd and "--- noise" in cmd and "SSH_CLIENT" in cmd and "-n 20000" in cmd,
          "its journal is filtered and counted on the box")
    seq = [_vps_out([]), _vps_out([
        "2026-09-24T08:00:32+00:00 ubuntu sshd[1]: Accepted publickey for root from 198.51.100.7 port 3599 ssh2: ED25519 SHA256:x",
        "2026-09-24T08:01:00+00:00 ubuntu sshd[2]: Accepted publickey for root from 10.8.0.5 port 1 ssh2: RSA SHA256:y",
        "2026-09-24T08:02:00+00:00 ubuntu sshd[3]: Accepted password for root from 198.51.100.16 port 2 ssh2",
        "2026-09-24T08:03:00+00:00 ubuntu sshd[4]: Accepted password for root from 198.51.100.16 port 3 ssh2",
    ])]

    async def fake_ssh(h_, remote):
        return seq.pop(0) if seq else None
    w._ssh = fake_ssh

    async def go():
        await w._poll(h, prime=True)
        await w._poll(h)
        if w._triage_task is not None:
            await asyncio.gather(w._triage_task, return_exceptions=True)
    asyncio.run(go())
    check(h.self_addrs == {"198.51.100.7"}, "it learns where it sees us from")
    logins = [a for a in alerts if a[1].startswith("hostlog-login:")]
    check(len(logins) == 1 and "198.51.100.16" in logins[0][0] and "password" in logins[0][0],
          f"one page for the stranger, none for the network or a VPN peer ({len(logins)})")
    nz = w.noise_24h(h)
    check({k: nz[k] for k in ("lines", "attempts", "sources")} == {"lines": 120, "attempts": 40,
                                                                  "sources": 2}
          and nz["since"] and nz["since"] <= time.time(),
          f"scanner noise is counted, our own probe is not a scanner ({nz})")
    check(ag.asks and "the VPN hub" in ag.asks[0][0], "the model is told what this host is")
    check(ag.asks and "198.51.100.7 port 3599" not in ag.asks[0][1],
          "our own session is not offered to the model")
    check(ag.asks and "SCANNER NOISE" in ag.asks[0][1], "...but the noise count is")
    snap = w.snapshot_state()["hosts"][0]
    check(snap.get("public") and snap.get("noise_24h", {}).get("attempts") == 40,
          "the dashboard sees the count")


def test_lan_host_command_unchanged():
    print("\n-- a host without `public` is read as a LAN host --")
    cfg = {**VPS_CFG, "hostlog": {**VPS_CFG["hostlog"], "hosts": [
        {"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi"}]}}
    w = HostLogWatcher(cfg, lambda *a, **k: None)
    h = w.hosts[0]
    h.cursor = CUR
    cmd = w._remote_cmd(h)
    check("awk" not in cmd.split(";")[0] and "SSH_CLIENT" not in cmd and h.burst,
          "no filter, no self line, burst rule on")


# --- 6. the weekly review -----------------------------------------------------------------
def test_weekly_is_due_once():
    print("\n-- the weekly review: once, on the day, after the time --")
    cfg = {"weekly": {"enabled": True, "day": "sun", "time": "10:00"}}
    sun_0959 = time.mktime((2026, 9, 27, 9, 59, 0, 0, 0, -1))
    sun_1001 = sun_0959 + 120
    check(not weekly.is_due(cfg, sun_0959, 0), "not before the time")
    check(weekly.is_due(cfg, sun_1001, 0), "due after it")
    check(not weekly.is_due(cfg, sun_1001 + 3600, sun_1001), "not twice the same Sunday")
    check(not weekly.is_due(cfg, sun_1001 + 86400, sun_1001), "not on Monday")
    check(weekly.is_due(cfg, sun_1001 + 7 * 86400, sun_1001), "and again next Sunday")
    check(not weekly.is_due({"weekly": {"enabled": False}}, sun_1001, 0), "off is off")
    check(not weekly.is_due(cfg, sun_1001, 0, since=sun_0959 - 3600),
          "not on a first start that same morning: a week it never watched")
    check(not weekly.is_due(cfg, sun_1001 + 7 * 86400, 0, since=sun_0959 + 3 * 86400),
          "nor after three days of watching")
    check(weekly.is_due(cfg, sun_1001 + 7 * 86400, 0, since=sun_0959 - 3600),
          "but the next Sunday, a week later")


def test_weekly_numbers_without_the_model():
    print("\n-- the week's numbers go out even if the model does not answer --")
    now = time.time()
    with tempfile.TemporaryDirectory() as d:
        st = StateStore(os.path.join(d, "s.sqlite"))
        for k in range(200):
            st.record_sample("192.168.10.117", k % 20 != 0, 5.0, {}, ts=now - 3 * 86400 + k * 60)
        st.record_event("blackout", 125, "", now - 86400)
        st.record_event("telegram", None, "critical", now - 3600)
        st.record_event("finding", None, json.dumps({"problem": True, "summary": "odd login"}),
                        now - 7200)
        st.commit()
        inv = Inventory(devices=[Device("192.168.10.117", "Boiler", criticality="high")])
        ww = type("W", (), {})()
        ww.log_rows = [_row(now - 10 * 86400, "start")]
        ww.outages_from_log = lambda: [
            (datetime.datetime.fromtimestamp(now - 2 * 86400),
             datetime.datetime.fromtimestamp(now - 2 * 86400 + 240)),
            (datetime.datetime.fromtimestamp(now - 9 * 86400),
             datetime.datetime.fromtimestamp(now - 9 * 86400 + 60))]
        single = weekly.compute_facts(st, inv, ww, None, {"unknown_count": 2}, now)
        ww.cfg = {"wan": {"path": {"route_comment": "Fiber", "main": "fiber", "backup": "antenna"}}}
        ww._edge_patterns = lambda: ("Fiber DOWN", "Fiber UP")
        facts = weekly.compute_facts(st, inv, ww, None, {"unknown_count": 2}, now)
        txt = weekly.format_weekly(facts, None)
    check("main_drops" not in single["internet"] and "🌐" not in weekly.format_weekly(single, None),
          "one internet line: no link row, only whether there was internet")
    check(facts["internet"]["main_drops"] == 1 and facts["internet"]["last_week_main_drops"] == 1,
          "with failover: the main link's drops this week and last, from the router's log")
    check("🌐 Fiber: 1 drop(s)" in txt, "named as the owner calls it")
    check("Boiler (192.168.10.117)" in txt and "95.0%" in txt, f"the worst device is named: {txt!r}")
    check("No internet at all: 1×, 2m" in txt, "the blackout is counted")
    check("1 alert(s)" in txt and "1 worth reporting" in txt, "messages and log checks too")
    check("Week in review" in txt and "🦉" not in txt, "a plain numbers message without the model")


# --- 7. the chat --------------------------------------------------------------------------
def test_poller_answers_only_its_owner():
    print("\n-- the bot listens to its owner and nobody else --")
    got = []

    async def on_msg(text, chat):
        got.append((text, chat))
    cfg = {"telegram": {"chat_id": "100000001", "chat": {"enabled": True}}}
    p = sinks.TelegramPoller(cfg, on_msg, persist=lambda o: saved.append(o))
    saved = []
    replies = [{"ok": True, "result": [
        {"update_id": 10, "message": {"chat": {"id": 100000001}, "text": "/status"}},
        {"update_id": 11, "message": {"chat": {"id": 5555}, "from": {"username": "x"}, "text": "hi"}},
        {"update_id": 12, "message": {"chat": {"id": 100000001}, "text": "why?"}},
    ]}]
    real_call, real_tok = sinks.telegram_call, sinks.resolve_tg_token

    async def fake_call(cfg_, method, payload, timeout_s=15):
        if replies:
            return replies.pop(0)
        p.stop()
        return {"ok": True, "result": []}
    sinks.telegram_call, sinks.resolve_tg_token = fake_call, (lambda c: "t")
    try:
        asyncio.run(p.run())
    finally:
        sinks.telegram_call, sinks.resolve_tg_token = real_call, real_tok
    check(got == [("/status", "100000001"), ("why?", "100000001")],
          f"the stranger is ignored, the owner's two messages arrive in order ({got})")
    check(p.offset == 13 and saved and saved[-1] == 13, "the position survives a restart")


def _auditor(d, cfg_extra=None):
    """A real Auditor with nothing real behind it: no MQTT, a scratch database."""
    from lanowl import main as m
    from lanowl.sinks import MqttBridge
    from lanowl.state import StatusTracker
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0}, **(cfg_extra or {})}
    inv = Inventory(devices=[Device("192.168.10.117", "Boiler", group="home",
                                    criticality="critical")])
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    return m, m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))


def test_incident_diagnosis_is_edited_in():
    print("\n-- the triage's diagnosis is edited into its alert: one message, not two --")
    issue = {"kind": "down", "ip": "192.168.10.117", "group": "home", "device": "Boiler",
             "severity": "critical", "detail": "unreachable (icmp)"}
    llm = {"summary": "s", "issues": [{"device": "Boiler (192.168.10.117)", "ip": "192.168.10.117",
                                       "root_cause": "AP restart at 14:02",
                                       "recommendation": "check the AP"}]}
    sent, edits = [], []

    async def fake_send(cfg, text, ids=None, **kw):
        sent.append(text)
        if ids is not None:
            ids.append(500 + len(sent))
        return True

    async def fake_edit(cfg, mid, text):
        edits.append((mid, text))
        return True

    async def go(d, offline):
        m, a = _auditor(d)
        real = (m.telegram_direct, m.telegram_edit)
        m.telegram_direct, m.telegram_edit = fake_send, fake_edit
        try:
            a._wan_raw_ok = not offline
            snap = type("S", (), {"ts": time.time(), "devices": []})()
            incident = a._diff_criticals({"issues": [issue]}, snap)
            await asyncio.sleep(0)               # let the send task run
            await asyncio.sleep(0)
            await a._annotate_incident(dict(a._incident_issues), llm)
            return a, incident
        finally:
            m.telegram_direct, m.telegram_edit = real

    with tempfile.TemporaryDirectory() as d:
        a, incident = asyncio.run(go(d, offline=False))
    check(incident and len(sent) == 1, "one alert was sent and it asks for a triage")
    check(len(edits) == 1 and edits[0][0] == 501 and "AP restart" in edits[0][1]
          and edits[0][1].startswith(sent[0]),
          "the diagnosis is edited into THAT message, which keeps its original text")
    check(len(sent) == 1, "...and no second message was sent")

    sent.clear()
    edits.clear()
    with tempfile.TemporaryDirectory() as d:
        a, _ = asyncio.run(go(d, offline=True))
        queued = a.outbox._items
    check(not sent and not edits and len(queued) == 1 and "AP restart" in queued[0]["text"],
          "with no internet the alert waits in the outbox and the diagnosis waits with it")


def test_status_needs_no_model():
    print("\n-- /status answers from the last sweep, instantly --")
    replies = []

    async def go(d):
        _, a = _auditor(d)
        a._last_report = {"overall_health": "ok", "counts": {"up": 3, "total": 3, "down": 0},
                          "wan_ok": True, "wan_state": "ok", "issues": [], "summary": "All good"}

        async def reply(chat, text):
            replies.append(text)
        a.chat._reply = reply
        await a.chat.on_telegram("/status", "100000001")
        await a.chat.on_telegram("/help", "100000001")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(replies and "Right now" in replies[0] and "3/3 up" in replies[0], "status is the report")
    check(len(replies) == 2 and "/week" in replies[1], "help lists the commands")


def test_web_dashboard():
    print("\n-- lanowl's own dashboard: reads, Check now, Ask — and nothing from elsewhere --")
    import aiohttp
    out = {}

    async def go(d):
        _, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0}})
        a._last_report = {"ts": time.time(), "overall_health": "degraded",
                          "counts": {"up": 1, "total": 2, "down": 1},
                          "issues": [{"kind": "down", "device": "Boiler", "ip": "192.168.10.117",
                                      "severity": "high", "detail": "unreachable"}],
                          "devices": [{"ip": "192.168.10.117", "name": "Boiler", "group": "home",
                                       "up": False}]}
        a._last_llm_report = {"overall_health": "degraded", "llm": {"summary": "AP blip",
                              "issues": [{"device": "Boiler (192.168.10.117)", "ip": "192.168.10.117",
                                          "severity": "high", "root_cause": "AP restart",
                                          "recommendation": "check AP"}]}}
        a._last_llm_at = time.time() - 60
        checks = []
        a.request_check = lambda: checks.append(1)

        async def fake_answer(q, on_wait=None, **kw):
            return f"answer to {q}"
        a.chat.answer = fake_answer
        await a.dashboard.start()
        port = a.dashboard._runner.addresses[0][1]
        base = f"http://127.0.0.1:{port}"
        async with aiohttp.ClientSession() as s:
            async with s.get(base + "/") as r:
                out["index"] = (r.status, "<title>lanowl</title>" in await r.text())
            async with s.get(base + "/api/state") as r:
                out["state"] = await r.json()
            async with s.get(base + "/api/state", headers={"Host": "evil.example:8088"}) as r:
                out["rebind"] = r.status
            async with s.post(base + "/api/check", data="x",
                              headers={"Content-Type": "text/plain"}) as r:
                out["form"] = r.status
            async with s.post(base + "/api/check", json={}) as r:
                out["check"] = r.status
            async with s.post(base + "/api/ask", json={"q": "  why is the boiler down?  "}) as r:
                out["ask"] = await r.json()
            await asyncio.sleep(0.05)
            async with s.get(base + f"/api/chat?c={out['ask'].get('c')}") as r:
                out["after"] = (await r.json())["conv"]["turns"]
            async with s.get(base + "/api/history") as r:
                out["hist1"] = sorted((await r.json())["devices"])
            a._last_report["devices"].append({"ip": "192.168.10.122", "name": "Tablet", "up": False})
            async with s.get(base + "/api/history") as r:        # a device just watched
                h2 = await r.json()
                out["hist2"] = (sorted(h2["devices"]), h2["devices"].get("192.168.10.122"))
        out["checks"] = len(checks)
        await a.dashboard.stop()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    st = out["state"]
    check(out["index"] == (200, True), "the page is served")
    check(st["issues"][0]["diag"] == {"cause": "AP restart", "rec": "check AP"},
          "the issue carries the model's diagnosis")
    check(st["llm"]["summary"] == "AP blip" and st["llm"]["fresh"], "and the assessment is there")
    check(out["rebind"] == 421, "a request under a borrowed name is refused (DNS rebinding)")
    check(out["form"] == 415, "a non-JSON POST — what a page elsewhere could send — is refused")
    check(out["check"] == 200 and out["checks"] == 1, "Check now starts an audit")
    check(out["hist1"] == ["192.168.10.117"] and out["hist2"][0] == ["192.168.10.117", "192.168.10.122"]
          and out["hist2"][1] == {"b": [], "u7": None, "f7": None},
          "the histories follow a device watched a moment ago, with no record of it (not a minute late)")
    check(out["ask"].get("ok") and out["after"] and out["after"][0]["status"] == "done"
          and out["after"][0]["a"] == "answer to why is the boiler down?",
          f"a question is answered and shows up in its conversation ({out['after']})")


if __name__ == "__main__":
    for fn in [test_json_slips_mended_and_asked_again, test_json_with_line_breaks_in_strings, test_web_dashboard,
               test_incident_diagnosis_is_edited_in, test_status_needs_no_model,
               test_agent_keeps_its_last_turn_for_the_answer,
               test_digest_carries_the_diagnosis, test_diagnosis_note,
               test_message_ids_and_the_outbox, test_router_log_evidence,
               test_internet_questions,
               test_vps_is_watched_without_the_noise, test_lan_host_command_unchanged,
               test_weekly_is_due_once, test_weekly_numbers_without_the_model,
               test_poller_answers_only_its_owner]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all model-extension tests passed")
