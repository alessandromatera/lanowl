"""The dashboard's Ask tab as a conversation: run with `python -m tests.test_ask`.

No network, no model, no Telegram — a fake Ollama on a local port, a fake answerer, a
scratch database. Pinned down here (conversations.py):

  1. the agent can stream: thinking, text and each tool call reach the caller as they come,
     and the audit's own requests stay unstreamed;
  2. stopping an answer closes the stream to Ollama (which is what stops the generation)
     and hands the model back;
  3. a follow-up is shown the earlier questions and answers; the first question of a chat
     already gets the dashboard's prompt (Telegram's conversation: tests/test_memory.py);
  4. Stop keeps what was written so far; Retry asks the last question again — and a Retry
     straight after a Stop is not marked stopped by the run it replaced;
  5. one question at a time per conversation, a short queue overall, New chat and Delete;
  6. conversations survive a restart, and an answer the restart interrupted says so;
  7. every check the model makes is shown in words, devices as NAME (address);
  8. the HTTP side: GET /api/chat, POST /api/ask|ask/stop|ask/retry|chat/delete, JSON only.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import conversations as cv
from lanowl.agent import LlmAgent
from lanowl.model import Device, Inventory
from lanowl.prompts import QA_SYSTEM, QA_SYSTEM_CHAT
from tests.test_llm_more import _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


class _Exec:
    def __init__(self):
        self.calls = []

    async def call(self, name, args):
        self.calls.append((name, args))
        return {"tool": name, "result": {"ok": True}}


async def _ollama(chunks_for, delay=0.0, seen=None):
    """A fake Ollama /api/chat. `chunks_for(n, body)` gives the chunks of the n-th request."""
    from aiohttp import web
    seen = seen if seen is not None else {}
    seen.setdefault("bodies", [])

    async def chat(request):
        body = await request.json()
        seen["bodies"].append(body)
        chunks = chunks_for(len(seen["bodies"]), body)
        if not body.get("stream"):
            msg = {"role": "assistant", "content": "".join(c.get("content", "") for c in chunks)}
            return web.json_response({"message": msg, "done": True, "prompt_eval_count": 7})
        resp = web.StreamResponse(headers={"Content-Type": "application/x-ndjson"})
        await resp.prepare(request)
        try:
            for c in chunks:
                await resp.write((json.dumps({"message": {"role": "assistant", **c},
                                              "done": False}) + "\n").encode())
                if delay:
                    await asyncio.sleep(delay)
            await resp.write((json.dumps({"message": {"role": "assistant", "content": ""},
                                          "done": True, "prompt_eval_count": 42}) + "\n").encode())
        except (ConnectionResetError, asyncio.CancelledError):
            seen["disconnected"] = True       # the client went away mid-answer
        return resp

    app = web.Application()
    app.router.add_post("/api/chat", chat)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, f"http://127.0.0.1:{runner.addresses[0][1]}", seen


# --- 1. streaming ------------------------------------------------------------------------
def test_agent_streams():
    print("\n-- the agent streams: thinking, text, checks — the audit does not --")
    rounds = {1: [{"thinking": "the boiler, "}, {"thinking": "let me look"},
                  {"content": "Let me check."},
                  {"content": "", "tool_calls": [{"function": {"name": "device_stats",
                                                               "arguments": {"ip": "192.168.10.117"}}}]}],
              2: [{"thinking": "all fine"}, {"content": "The boiler "}, {"content": "is fine."}]}
    events, out = [], {}

    async def go():
        runner, url, seen = await _ollama(lambda n, b: rounds.get(n, rounds[2]))
        ex = _Exec()
        ag = LlmAgent({"model": {"url": url, "max_tool_iters": 4}}, ex)
        hist = [{"role": "user", "content": "q1"}, {"role": "assistant", "content": "a1"}]
        out["text"] = await ag.ask_text("sys", "ctx", history=hist,
                                        on_event=lambda *e: events.append(e))
        out["calls"], out["peak"] = ex.calls, ag.last_ctx_peak
        out["bodies"] = list(seen["bodies"])
        seen["bodies"].clear()
        out["audit"] = await ag.run_audit("sys", "ctx")
        out["audit_stream"] = [b.get("stream") for b in seen["bodies"]]
        await runner.cleanup()
    asyncio.run(go())
    check(out["text"] == "The boiler is fine.", f"the answer is the last round's text ({out['text']!r})")
    kinds = [e[0] for e in events]
    check(kinds[:3] == ["thinking", "thinking", "content"] and ("tool", "device_stats",
          {"ip": "192.168.10.117"}) in events, f"thinking, text and the check arrive as they happen ({kinds})")
    check(kinds.index("tool") < kinds.index("content", kinds.index("tool")),
          "the check is announced before the text that follows it")
    check(out["calls"] == [("device_stats", {"ip": "192.168.10.117"})], "the tool really ran")
    b = out["bodies"][0]
    check(all(x.get("stream") for x in out["bodies"]), "the question's requests are streamed")
    check(b["messages"][0]["content"].startswith("sys\n\n")
          and [m["content"] for m in b["messages"][1:4]] == ["q1", "a1", "ctx"],
          "the conversation sits between the system prompt (and its voice) and the new question")
    check(out["bodies"][1]["messages"][-2].get("tool_calls"),
          "the tool call goes back to the model in the next round, as before")
    check(out["peak"] == 42, "the prompt size still comes from the last chunk")
    check(out["audit_stream"] and not any(out["audit_stream"]),
          f"the audit's own requests are not streamed ({out['audit_stream']})")


def test_stop_closes_the_stream():
    print("\n-- Stop closes the stream to Ollama: that is what stops the model --")
    out = {}

    async def go():
        endless = [{"content": "word "}] * 400
        runner, url, seen = await _ollama(lambda n, b: endless, delay=0.02)
        ag = LlmAgent({"model": {"url": url}}, _Exec())
        got = []
        task = asyncio.ensure_future(ag.ask_text("sys", "ctx", on_event=lambda *e: got.append(e)))
        while len(got) < 5:
            await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            out["cancelled"] = True
        for _ in range(100):
            if seen.get("disconnected"):
                break
            await asyncio.sleep(0.02)
        out["disconnected"] = bool(seen.get("disconnected"))
        await runner.cleanup()
    asyncio.run(go())
    check(out.get("cancelled"), "the answer is cancelled, not swallowed into a None")
    check(out["disconnected"], "and the server sees the client go away")


# --- 2. conversations ----------------------------------------------------------------------
def _fake(a, gate=None, record=None):
    """A stand-in for Chat.answer: records what it was given, optionally waits on `gate`."""
    record = record if record is not None else []

    async def answer(q, on_wait=None, history=None, on_event=None, source=None, session=None):
        record.append({"q": q, "history": history, "source": source})
        if on_event:
            on_event("start")
            on_event("tool", "router_log", {"search": "fiber", "hours": 24})
            on_event("content", "partial ")
        if gate is not None:
            await gate.wait()
        return f"answer to {q}"
    a.chat.answer = answer
    return record


def test_follow_ups_carry_the_conversation():
    print("\n-- a follow-up is shown what was asked and answered before --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        seen = _fake(a)
        ch = cv.Conversations(a)
        r1, s1 = ch.ask(None, "  why did the fiber drop?  ")
        await asyncio.sleep(0.01)
        r2, s2 = ch.ask(r1["c"], "and yesterday?")
        await asyncio.sleep(0.01)
        r3, _ = ch.ask("", "something else")
        await asyncio.sleep(0.01)
        out.update(r1=r1, s1=s1, r2=r2, s2=s2, r3=r3, seen=seen, view=ch.view(r1["c"]),
                   recent=ch.recent())
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    s = out["seen"]
    check(out["s1"] == 200 and out["r1"]["ok"] and out["r1"]["c"], "a question starts a conversation")
    check(s[0]["q"] == "why did the fiber drop?" and s[0]["history"] == [],
          "the first question has no history — but a list, so it gets the dashboard's prompt")
    check(s[1]["history"] == [{"role": "user", "content": "why did the fiber drop?"},
                              {"role": "assistant", "content": "answer to why did the fiber drop?"}],
          f"the follow-up carries the first question and its answer ({s[1]['history']})")
    check((s[0]["source"] or {}).get("via") == "dashboard" and callable(s[0]["source"].get("on_proposed")),
          "a dashboard question may propose, and its proposals are tied to its turn")
    check(out["r2"]["c"] == out["r1"]["c"] and out["r3"]["c"] != out["r1"]["c"],
          "a follow-up stays in the conversation; no conversation id starts a new one")
    t = out["view"]["turns"]
    check(len(t) == 2 and all(x["status"] == "done" for x in t), "both answered, in order")
    check(t[0]["steps"][0]["text"] == "Searching the router log for “fiber”, last 24h",
          f"each check the model made is kept, in words ({t[0]['steps']})")
    check("draft" not in t[0] and "think" not in t[0], "a finished answer carries no live fields")
    check([r["title"] for r in out["recent"]] == ["something else", "why did the fiber drop?"],
          "Recent lists the newest conversation first, titled by its first question")


def test_stop_retry_and_the_queue():
    print("\n-- Stop keeps what was written, Retry asks again, one at a time --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        gate = asyncio.Event()
        seen = _fake(a, gate)
        ch = cv.Conversations(a)
        r1, _ = ch.ask(None, "slow question")
        await asyncio.sleep(0.01)
        v = ch.view(r1["c"])["turns"][0]
        out["live"] = (v["status"], v["phase"], v["draft"], len(v["steps"]))
        out["busy"] = ch.ask(r1["c"], "follow-up while answering")
        out["stop"] = ch.stop(r1["c"], v["id"])
        out["after_stop"] = dict(ch.view(r1["c"])["turns"][0])
        # Retry at once, while the stopped run is still unwinding its cancellation
        out["retry"] = ch.retry(r1["c"], v["id"])
        await asyncio.sleep(0.01)
        out["retrying"] = ch.view(r1["c"])["turns"][0]["status"]
        gate.set()
        await asyncio.sleep(0.01)
        out["retried"] = ch.view(r1["c"])["turns"][0]
        out["not_last"] = ch.ask(r1["c"], "second")
        await asyncio.sleep(0.01)
        out["retry_old"] = ch.retry(r1["c"], v["id"])
        gate.clear()
        for i in range(cv.MAX_PENDING):
            ch.ask(None, f"queued {i}")
        out["full"] = ch.ask(None, "one too many")
        out["empty"] = ch.ask(None, "   ")
        gate.set()
        await asyncio.sleep(0.01)
        out["seen"] = seen
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["live"] == ("pending", "writing", "partial ", 1),
          f"while it works, the page sees the phase, the draft and the checks ({out['live']})")
    check(out["busy"][1] == 409, "a second question in the same chat waits for the first")
    a = out["after_stop"]
    check(out["stop"][1] == 200 and a["status"] == "stopped" and a["a"] == "partial",
          f"Stop is immediate and keeps what was written ({a['status']}, {a.get('a')!r})")
    check(out["retry"][1] == 200 and out["retrying"] == "pending",
          f"Retry straight after Stop runs — the old run does not mark it stopped ({out['retrying']})")
    r = out["retried"]
    check(r["status"] == "done" and r["a"] == "answer to slow question" and r["attempt"] == 2,
          f"and it is answered ({r['status']}, attempt {r.get('attempt')})")
    check(out["not_last"][1] == 200 and out["retry_old"][1] == 409,
          "only the last answer can be asked again")
    check(out["full"][1] == 429, "the queue is short: a question beyond it is refused, not lost")
    check(out["empty"][1] == 400, "an empty question is refused")


def test_stop_hands_the_model_back():
    print("\n-- a stopped answer frees the model at once --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        started = asyncio.Event()

        async def ask_text(system, ctx, history=None, on_event=None, **kw):
            out["system"] = system
            started.set()
            await asyncio.sleep(60)                 # a model that would think for a minute
        a.agent.ask_text = ask_text
        ch = cv.Conversations(a)
        r, _ = ch.ask(None, "long one")
        await asyncio.wait_for(started.wait(), 2)
        out["held"] = a._llm_lock.locked()
        ch.stop(r["c"], r["t"])
        await asyncio.sleep(0.01)
        out["freed"] = not a._llm_lock.locked()
        out["status"] = ch.view(r["c"])["turns"][0]["status"]

        async def plain(system, ctx, **kw):
            out["tg_system"], out["tg_kw"] = system, kw
            return "ok"
        a.agent.ask_text = plain
        await a.chat.answer("from telegram")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["held"] and out["freed"], "the model was held while answering and is free after Stop")
    check(out["status"] == "stopped", "the answer reads as stopped")
    check(out["system"].startswith(QA_SYSTEM_CHAT) and "update_memory" in out["system"],
          "the dashboard asks with the conversation prompt, and may write the memory")
    check(out["tg_system"] == QA_SYSTEM and out["tg_kw"].get("history") is None
          and out["tg_kw"].get("on_event") is None,
          "a question with no source (MQTT) is one question with its own prompt, unstreamed, "
          "no memory tools")


def test_new_chat_delete_and_restart():
    print("\n-- New chat, Delete, and conversations that outlive a restart --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        gate = asyncio.Event()
        _fake(a, gate)
        ch = cv.Conversations(a)
        gate.set()
        r1, _ = ch.ask(None, "kept")
        await asyncio.sleep(0.01)
        r2, _ = ch.ask(None, "deleted")
        await asyncio.sleep(0.01)
        out["del"] = ch.delete(r2["c"])
        out["del_again"] = ch.delete(r2["c"])
        gate.clear()
        r3, _ = ch.ask(None, "interrupted by a restart")
        await asyncio.sleep(0.01)
        # the process dies here: a new store reads what the old one saved
        ch2 = cv.Conversations(a)
        out["ids"] = {x["id"] for x in ch2.recent()}
        out["r"] = (r1["c"], r2["c"], r3["c"])
        out["kept"] = ch2.view(r1["c"])["turns"][0]
        out["interrupted"] = ch2.view(r3["c"])["turns"][0]
        out["follow"] = ch2.ask(r1["c"], "follow-up after the restart")
        gate.set()
        await asyncio.sleep(0.01)
        for i in range(cv.MAX_CONVS + 3):
            ch2.ask(None, f"filler {i}")
            await asyncio.sleep(0)
        await asyncio.sleep(0.01)
        out["n"] = len(ch2.recent())
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    k, d_, i = out["r"]
    check(out["del"][1] == 200 and out["del_again"][1] == 404, "a conversation can be deleted, once")
    check(k in out["ids"] and d_ not in out["ids"] and i in out["ids"],
          "after a restart the conversations are back, the deleted one is not")
    check(out["kept"]["status"] == "done" and out["kept"]["a"] == "answer to kept",
          "with their answers")
    x = out["interrupted"]
    check(x["status"] == "failed" and "restarted" in x.get("error", ""),
          f"an answer the restart cut off says so, instead of hanging forever ({x['status']})")
    check(out["follow"][1] == 200 and out["follow"][0]["c"] == k,
          "and a restored conversation takes follow-ups")
    check(out["n"] == cv.MAX_CONVS, f"Recent keeps the newest {cv.MAX_CONVS} ({out['n']})")


def test_checks_in_words():
    print("\n-- each check the model makes, in words --")
    inv = Inventory(devices=[Device("192.168.10.117", "Boiler")])
    d = cv.describe_tool
    check(d("device_stats", {"ip": "192.168.10.117", "days": 7}, inv)
          == "How Boiler (192.168.10.117) has been, last 7 days", "a device is NAME (address)")
    check(d("ping_host", {"ip": "192.168.10.250"}, inv) == "Pinging 192.168.10.250",
          "a stranger stays a bare address — no invented name")
    check(d("history_query", {"hours": 72}, inv) == "Ups and downs, last 3 days", "hours read as days")
    check(d("wan_history", {"days": "x"}, inv) == "Internet history, last 24h",
          "a nonsense argument from the model does not break the line")
    check(d("router_log", {"search": "a" * 200}, inv).count("a") <= 62, "long arguments are cut")


# --- 3. over HTTP ------------------------------------------------------------------------
def test_http():
    print("\n-- the Ask endpoints: conversation, stop, retry, delete — JSON only --")
    import aiohttp
    out = {}

    async def go(d):
        _, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0}})
        gate = asyncio.Event()
        _fake(a, gate)
        await a.dashboard.start()
        base = f"http://127.0.0.1:{a.dashboard._runner.addresses[0][1]}"
        async with aiohttp.ClientSession() as s:
            async with s.post(base + "/api/ask", json={"q": "is the VPS ok?"}) as r:
                out["ask"] = await r.json()
            c, t = out["ask"]["c"], out["ask"]["t"]
            await asyncio.sleep(0.01)
            async with s.get(base + f"/api/chat?c={c}") as r:
                out["live"] = await r.json()
            async with s.post(base + "/api/ask/stop", json={"c": c, "t": t}) as r:
                out["stop"] = (r.status, await r.json())
            async with s.post(base + "/api/ask/retry", json={"c": c, "t": t}) as r:
                out["retry"] = r.status
            gate.set()
            await asyncio.sleep(0.02)
            async with s.get(base + f"/api/chat?c={c}") as r:
                out["done"] = await r.json()
            async with s.get(base + "/api/chat?c=nope") as r:
                out["unknown"] = await r.json()
            async with s.post(base + "/api/ask/stop", data="c=x",
                              headers={"Content-Type": "application/x-www-form-urlencoded"}) as r:
                out["form"] = r.status
            async with s.post(base + "/api/chat/delete", json={"c": c}) as r:
                out["delete"] = r.status
            async with s.get(base + "/api/state") as r:
                out["state"] = await r.json()
        await a.dashboard.stop()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    lv = out["live"]["conv"]["turns"][0]
    check(out["ask"]["ok"] and lv["status"] == "pending" and lv["draft"] == "partial ",
          "GET /api/chat shows the answer being written")
    check(out["live"]["recent"][0]["pending"] and "busy" in out["live"]["model"],
          "with the Recent list and what the model is doing")
    check(out["stop"] == (200, {"ok": True, "status": "stopped"}), "POST /api/ask/stop stops it")
    check(out["retry"] == 200 and out["done"]["conv"]["turns"][0]["a"] == "answer to is the VPS ok?",
          "POST /api/ask/retry asks again and it is answered")
    check(out["unknown"]["conv"] is None, "an unknown conversation is simply none — the page starts fresh")
    check(out["form"] == 415, "a form POST to the new endpoints is refused like the others")
    check(out["delete"] == 200, "POST /api/chat/delete removes it")
    check("answers" not in out["state"], "questions no longer ride along in /api/state")


if __name__ == "__main__":
    for fn in [test_agent_streams, test_stop_closes_the_stream,
               test_follow_ups_carry_the_conversation, test_stop_retry_and_the_queue,
               test_stop_hands_the_model_back, test_new_chat_delete_and_restart,
               test_checks_in_words, test_http]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all Ask tests passed")
