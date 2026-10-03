"""The model's shell, lanowl's side: run with `python -m tests.test_shell`.

No sandbox, no model — a fake sandbox on a unix socket in a scratch directory, speaking the
same one-JSON-line protocol as docker/sandbox/server.py. Pinned down here (shell.py):

  1. the canary: isolated only when the LAN handshake works, the GET after it gets nothing and
     the dashboard does not answer; a sandbox that reaches either is NOT isolated — said on
     Telegram once, and once when it is over; no control, no socket: off, quietly;
  2. `shell` is offered in the owner's question only, and only while isolated — never in the
     audit, over MQTT, or with the canary failing;
  3. a command: exit code and output (head and tail when long), killed at its time limit, at
     most max_per_answer per answer, every one kept in the record with who asked;
  4. a Telegram answer lists the commands under it; the dashboard shows each as `$ command`;
  5. the socket path must BE a socket (a planted file or link is refused).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import shell as SH
from tests.test_llm_more import _auditor

_fails = []
ISOLATED = "HANDSHAKE-OK\nGET-000\nSELF-000\nVM-CLOSED\n"


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


async def _sandbox(path, answer, seen):
    """A fake sandbox: `answer(cmd, timeout)` gives the reply dict."""
    async def handle(reader, writer):
        req = json.loads(await reader.readline())
        seen.append(req)
        writer.write(json.dumps(answer(req["cmd"], req["timeout"])).encode() + b"\n")
        await writer.drain()
        writer.close()
    return await asyncio.start_unix_server(handle, path=path)


def _cfg(d):
    return {"shell": {"enabled": True, "socket": os.path.join(d, "exec.sock"), "timeout_s": 60,
                      "timeout_max_s": 300, "output_max_chars": 200, "max_per_answer": 2,
                      "canary_lan": "192.168.10.103:11434"},
            "observer": {"host_ip": "192.168.10.95"}}


def test_canary():
    print("\n-- the canary: isolated, not isolated, not proven, not there --")
    out = {"tg": []}

    async def go(d):
        _, a = _auditor(d, _cfg(d))
        a._emit_telegram = lambda ch, text, **kw: out["tg"].append((ch, text))
        reply = {"out": ISOLATED}
        seen = []
        srv = await _sandbox(a.shell.sock, lambda c, t: {"rc": 0, "secs": 8.0, **reply}, seen)
        try:
            out["ok"] = dict(await a.shell.canary())
            out["cmd"] = seen[0]["cmd"]
            reply["out"] = "HANDSHAKE-OK\nGET-200\nSELF-000\nVM-CLOSED\n"
            out["breach"] = dict(await a.shell.canary())
            out["breach2"] = dict(await a.shell.canary())
            out["tg_after_breach"] = list(out["tg"])
            reply["out"] = "HANDSHAKE-OK\nGET-000\nSELF-200\nVM-CLOSED\n"
            out["self"] = dict(await a.shell.canary())
            reply["out"] = "HANDSHAKE-OK\nGET-000\nSELF-000\nVM-OPEN\n"
            out["vm"] = dict(await a.shell.canary())
            reply["out"] = ISOLATED
            out["back"] = dict(await a.shell.canary())
            reply["out"] = "HANDSHAKE-FAIL\nGET-000\nSELF-000\nVM-CLOSED\n"
            out["noctl"] = dict(await a.shell.canary())
        finally:
            srv.close()
            await srv.wait_closed()
        os.unlink(a.shell.sock)
        out["gone"] = dict(await a.shell.canary())
        with open(a.shell.sock, "w") as f:
            f.write("not a socket")
        out["planted"] = await a.shell._exec("id", 5)
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["ok"]["ok"] is True and "isolated" in out["ok"]["why"], "handshake yes, GET nothing, dashboard nothing: isolated")
    check("nc -z -w3 192.168.10.103 11434" in out["cmd"] and "http://192.168.10.95:" in out["cmd"]
          and "nc -z -w3 192.168.10.95 22" in out["cmd"],
          f"it tries the LAN control and lanowl's own dashboard ({out['cmd']})")
    check(out["breach"]["ok"] is False and "NOT ISOLATED" in out["breach"]["why"],
          "a GET that comes back: NOT isolated, the tool is off")
    check(len(out["tg_after_breach"]) == 1 and out["tg_after_breach"][0][0] == "critical"
          and "NOT isolated" in out["tg_after_breach"][0][1],
          "said on Telegram — once, not at every check")
    check(out["self"]["ok"] is False and "NOT ISOLATED" in out["self"]["why"],
          "reaching the dashboard is a breach too")
    check(out["vm"]["ok"] is False and "ssh port OPEN" in out["vm"]["why"],
          "a handshake to the VM itself is a breach: the whole host is walled off")
    check(out["back"]["ok"] is True and len(out["tg"]) == 2 and "isolated again" in out["tg"][1][1],
          "and one message when it holds again")
    check(out["noctl"]["ok"] is False and "not proven" in out["noctl"]["why"] and len(out["tg"]) == 2,
          "no handshake to the control: not proven, off — quietly (the LAN or the control host is down)")
    check(out["gone"]["ok"] is False and "not running" in out["gone"]["why"], "no socket: off")
    check("not a socket" in out["planted"].get("error", ""), "a plain file where the socket should be is refused")


def test_the_tool():
    print("\n-- the tool: only in the owner's question, only while isolated --")
    out = {}

    def answer(cmd, timeout):
        if cmd.startswith("nc -z"):
            return {"rc": 0, "out": ISOLATED, "secs": 8}
        if cmd == "sleep 999":
            return {"rc": -9, "out": "partial", "secs": timeout, "timed_out": True}
        if cmd == "big":
            return {"rc": 0, "out": "A" * 300 + "THE END", "secs": 0.1, "truncated": False}
        return {"rc": 0, "out": f"ran: {cmd}\n", "secs": 0.2}

    async def go(d):
        _, a = _auditor(d, _cfg(d))
        a._persist_alerts = True
        seen = []
        srv = await _sandbox(a.shell.sock, answer, seen)
        try:
            out["before"] = await a.executor.call("shell", {"command": "id"})
            await a.shell.canary()
            with a.actions.source("audit"):
                out["audit"] = [t["function"]["name"] for t in a.executor.tool_specs()]
            ran = []
            with a.shell.turn("telegram", "is the fiber ok?", ran):
                out["specs"] = [t["function"]["name"] for t in a.executor.tool_specs()]
                out["r1"] = await a.executor.call("shell", {"command": "mtr -r -c 3 9.9.9.9",
                                                            "timeout_s": 9999})
                out["r2"] = await a.executor.call("shell", {"command": "sleep 999", "timeout_s": 5})
                out["r3"] = await a.executor.call("shell", {"command": "id"})
            out["ran"], out["seen"] = ran, list(seen)
            with a.shell.turn("dashboard", "q"):
                out["big"] = (await a.executor.call("shell", {"command": "big"}))["result"]
                out["empty"] = (await a.executor.call("shell", {"command": "  "}))["result"]
            out["outside"] = await a.executor.call("shell", {"command": "id"})
            out["record"] = a.state.load_record(SH.RECORD)
            out["view"] = a.shell.view()

            # through Chat.answer
            async def ask_text(system, ctx, **kw):
                out["system"] = system
                out["tools"] = [t["function"]["name"] for t in a.executor.tool_specs()]
                await a.executor.call("shell", {"command": "dig +short example.com"})
                return "It resolves."
            a.agent.ask_text = ask_text
            out["tg"] = await a.chat.answer("does example.com resolve?", history=[],
                                            source={"via": "telegram", "chat_id": "100000001"})
            out["on_system"], out["on_tools"] = out["system"], out["tools"]
            out["mqtt_tools"] = None

            async def ask_mqtt(system, ctx, **kw):
                out["mqtt_tools"] = [t["function"]["name"] for t in a.executor.tool_specs()]
                return "x"
            a.agent.ask_text = ask_mqtt
            await a.chat.answer("over mqtt")
            a.shell.state["ok"] = False
            a.agent.ask_text = ask_text
            out["off_system"] = None
            await a.chat.answer("q", history=[], source={"via": "dashboard", "conv": "c"})
            out["off_system"], out["off_tools"] = out["system"], out["tools"]
        finally:
            srv.close()
            await srv.wait_closed()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("error" in out["before"]["result"] or "error" in out["before"],
          "before the canary has passed, nothing runs")
    check("shell" not in out["audit"], "the audit is never offered the shell")
    check("shell" in out["specs"], "the owner's question is, once the canary passed")
    r1 = out["r1"]["result"]
    check(r1["exit_code"] == 0 and r1["output"] == "ran: mtr -r -c 3 9.9.9.9\n"
          and out["seen"][1]["timeout"] == 300, "a command runs; the time limit is held to timeout_max_s")
    check("killed after 5s" in out["r2"]["result"]["note"] and out["r2"]["result"]["output"] == "partial",
          "a command past its limit is killed, and what it printed is kept")
    check("refused" in out["r3"]["result"] and len(out["seen"]) == 3,
          "max_per_answer commands, then refused — nothing sent to the sandbox")
    big = out["big"]
    check(big["output"].startswith("AAA") and big["output"].endswith("THE END") and "cut" in big["output"]
          and "filter it" in big["note"], "a long output keeps its head AND its tail, and says to filter")
    check("error" in out["empty"], "an empty command is refused")
    check("error" in out["outside"]["result"], "outside a question, it refuses")
    rec = out["record"]["log"]
    check([x["cmd"] for x in rec] == ["mtr -r -c 3 9.9.9.9", "sleep 999", "big"]
          and rec[0]["via"] == "telegram" and rec[0]["q"] == "is the fiber ok?" and rec[1]["timed_out"],
          "every command is kept, with who asked and what came of it")
    check([r["label"] for r in out["ran"]] == ["$ mtr -r -c 3 9.9.9.9", "$ sleep 999"]
          and out["ran"][1]["ok"] is False, "each joins the answer's list, a killed one as failed")
    check(out["view"]["ok"] and out["view"]["recent"][0]["cmd"] == "big", "the dashboard gets the state and the newest first")
    check("SHELL — `shell` runs a bash command" in out["on_system"] and "shell" in out["on_tools"],
          "a question while isolated gets the tool and its rules")
    check(out["tg"] == "It resolves.\n\n🔧 $ dig +short example.com",
          f"a Telegram answer lists the command under it ({out['tg']!r})")
    check(out["mqtt_tools"] is not None and "shell" not in out["mqtt_tools"], "an MQTT question gets no shell")
    check("SHELL —" not in out["off_system"] and "shell" not in out["off_tools"],
          "with the canary failing: neither the tool nor its rules")
    from lanowl.conversations import describe_tool
    check(describe_tool("shell", {"command": "mtr  -r\n9.9.9.9"}, None) == "$ mtr -r 9.9.9.9",
          "the dashboard shows the command itself")


def test_clip():
    print("\n-- clipping --")
    t = "H" * 100 + "T" * 100
    c = SH.clip(t, 50)
    check(c.startswith("H" * 35) and c.endswith("T" * 15) and "150 characters cut" in c,
          f"70% head, 30% tail, and how much went ({c!r})")
    check(SH.clip("short", 50) == "short", "short output untouched")


if __name__ == "__main__":
    for fn in [test_canary, test_the_tool, test_clip]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all shell tests passed")
