"""The model's memory, and Telegram as a conversation: run with `python -m tests.test_memory`.

No network, no model, no Telegram — a fake answerer that calls the tools the way the model
would, a scratch database. Pinned down here (memory.py):

  1. remember / change / forget, from the model's tools: saved, rewritten, deleted, kept
     across a restart — and a --once rehearsal writes nothing;
  2. the memory's tools exist only in the owner's own question (Telegram, dashboard): not in
     the audit, not over MQTT, not in an investigation session's turn;
  3. every change is printed under the answer by the code, whatever the model wrote — and
     the model's own imitation of that line is dropped, from its answer and its history;
  4. every model run reads the notes: they end the system prompt of an audit, a question,
     the weekly review and a log triage;
  5. /memory, /remember, /forget on Telegram;
  6. a Telegram chat is a conversation: the last few exchanges ride along, /new and a long
     silence start over, and it survives a restart;
  7. the dashboard: the notes in /api/state, POST /api/memory add | edit | delete.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import chat as C
from lanowl import memory as M
from lanowl.prompts import QA_SYSTEM, QA_SYSTEM_TELEGRAM
from tests.test_llm_more import _auditor

_fails = []
ACME = "The Acme office's public IPs are 198.51.100.20 and 198.51.100.21."


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _model(a, script, seen):
    """A stand-in for LlmAgent.ask_text that calls tools like the model: `script(n)` gives the
    n-th question's tool calls and answer. Records the system prompt, history and the tools
    offered."""
    n = {"i": 0}

    async def ask_text(system, ctx, history=None, on_event=None, **kw):
        n["i"] += 1
        calls, answer = script(n["i"])
        seen.append({"system": a.agent._with_memory(system), "history": history,
                     "tools": [t["function"]["name"] for t in a.executor.tool_specs()],
                     "results": [await a.executor.call(name, args) for name, args in calls]})
        return answer
    a.agent.ask_text = ask_text


def test_remember_change_forget():
    print("\n-- remember, change, forget: the owner's example, over three conversations --")
    out = {}

    def script(i):
        return {1: ([("remember", {"text": ACME})], "Saved."),
                2: ([("update_memory", {"id": 1, "text": "The Acme office's public IP is "
                                                         "198.51.100.99 (changed on 25/09)."})],
                    "Updated."),
                3: ([("forget_memory", {"id": 1})], "")}[i]

    async def go(d):
        _, a = _auditor(d)
        a._persist_alerts = True
        seen = []
        _model(a, script, seen)
        src = {"via": "telegram", "chat_id": "100000001"}
        out["a1"] = await a.chat.answer("those are Acme's public IPs, memorize it",
                                        history=[], source={**src, "question": "memorize it"})
        out["notes1"] = a.memory.view()
        out["a2"] = await a.chat.answer("Acme changed IP, it's 198.51.100.99 now",
                                        history=[], source={**src, "question": "changed"})
        out["notes2"] = a.memory.view()
        out["a3"] = await a.chat.answer("forget about Acme's IP", history=[],
                                        source={**src, "question": "forget"})
        out["notes3"] = a.memory.view()
        out["seen"] = seen
        out["after"] = a.executor.tool_specs()

        # kept across a restart
        a.memory.add("The boiler is switched off every summer.", by="owner", via="telegram")
        _, b = _auditor(d)
        out["restored"] = b.memory.view()
        out["next"] = b.memory.add("x", by="owner", via="telegram")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    n1, n2 = out["notes1"], out["notes2"]
    check(len(n1) == 1 and n1[0]["id"] == 1 and n1[0]["text"] == ACME
          and n1[0]["by"] == "model" and n1[0]["via"] == "telegram" and n1[0]["q"] == "memorize it",
          f"remember: saved as #1, with who and during which question ({n1})")
    check(out["a1"] == f"Saved.\n\n💾 Remembered #1: {ACME}",
          f"...and the note itself is printed under the answer ({out['a1']!r})")
    check(len(n2) == 1 and n2[0]["text"].startswith("The Acme office's public IP is 198.51.100.99"),
          "update_memory rewrites #1")
    check(out["a2"].endswith("✏️ Changed #1: The Acme office's public IP is 198.51.100.99 "
                             "(changed on 25/09)."), "...and says so under the answer")
    check(out["notes3"] == [] and out["a3"].startswith("🗑 Forgot #1:"),
          f"forget_memory deletes it — printed even when the model wrote nothing ({out['a3']!r})")
    s = out["seen"]
    check(all({"remember", "update_memory", "forget_memory"} <= set(x["tools"]) for x in s),
          "the three tools are offered in the owner's questions")
    check("#1 (" in s[1]["system"] and ACME in s[1]["system"],
          "the next conversation's prompt carries the note, with its number")
    check(s[0]["system"].startswith(QA_SYSTEM_TELEGRAM) and "MEMORY — remember" in s[0]["system"],
          "a Telegram question gets the conversation prompt and the memory's rules")
    check(not any(t["function"]["name"] == "remember" for t in out["after"]),
          "...and the tools are gone once the answer is done")
    check([x["text"] for x in out["restored"]] == ["The boiler is switched off every summer."]
          and out["next"]["id"] == 3, "the notes and their numbering survive a restart")


def test_the_footer_is_the_codes():
    print("\n-- only the code prints a change: the model's imitation is dropped, history too --")
    out = {}

    def script(i):
        return {1: ([("remember", {"text": "note one"})], "Fatto.\n\n💾 Remembered #1: note one"),
                2: ([("update_memory", {"id": 1, "text": "note two"})],
                    "Fatto: nota #1 aggiornata.\n\n💾 Updated #1: note two")}[i]

    async def go(d):
        _, a = _auditor(d)
        seen = []
        _model(a, script, seen)
        src = {"via": "telegram", "chat_id": "100000001"}
        out["a1"] = await a.chat.answer("remember note one", history=[], source=src)
        a.chat._tg_keep("100000001", "remember note one", out["a1"])
        out["a2"] = await a.chat.answer("it is note two now",
                                        history=a.chat._tg_history("100000001"), source=src)
        out["seen"] = seen
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["a1"] == "Fatto.\n\n💾 Remembered #1: note one",
          f"the model's copy of the line is dropped, the code's printed once ({out['a1']!r})")
    check(out["a2"] == "Fatto: nota #1 aggiornata.\n\n✏️ Changed #1: note two",
          f"...also when it invents its own wording for it ({out['a2']!r})")
    check(out["seen"][1]["history"][1]["content"] == "Fatto.",
          "the earlier answer is shown to the model without the line, so it has nothing to copy")
    from lanowl.conversations import describe_tool
    check([describe_tool(n, a, None) for n, a in (("remember", {"text": "Acme IPs"}),
                                                  ("update_memory", {"id": 3}),
                                                  ("forget_memory", {"id": 3}))]
          == ["Remembering “Acme IPs”", "Changing note #3", "Forgetting note #3"],
          "the dashboard shows each memory step in words")


def test_rules():
    print("\n-- where memory can be written, and what it refuses --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        m = a.memory
        out["outside"] = await a.executor.call("remember", {"text": "x"})
        out["audit_tools"] = []

        async def run_audit(system, ctx):
            out["audit_tools"] = [t["function"]["name"] for t in a.executor.tool_specs()]
            out["audit_system"] = a.agent._with_memory(system)
            return {"overall_health": "ok", "summary": "fine", "issues": []}
        m.add(ACME, by="owner", via="dashboard")
        with a.actions.source("audit"):
            await run_audit("AUDIT PROMPT", "")
        seen = []
        _model(a, lambda i: ([("remember", {"text": "from mqtt"})], "ok"), seen)
        out["mqtt"] = await a.chat.answer("a question over MQTT")
        out["session"] = await a.chat.answer("brief", source={"via": "telegram"},
                                             session={"id": 9})
        out["seen"] = seen
        out["dup"] = m.add(ACME.upper(), by="owner", via="telegram")
        out["empty"] = m.add("   \n ", by="owner", via="telegram")
        out["long"] = m.add("y" * 900, by="owner", via="telegram")
        for i in range(M.MAX_NOTES):
            m.add(f"note {i}", by="owner", via="telegram")
        out["full"] = m.add("one too many", by="owner", via="telegram")
        out["count"] = len(m.notes)
        out["noedit"] = m.edit(999, "z", by="owner", via="telegram")
        out["nofile"] = a.state.load_record(M.RECORD)
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check("error" in out["outside"], "outside a conversation the tool refuses")
    check(not {"remember", "update_memory", "forget_memory"} & set(out["audit_tools"]),
          f"the hourly audit is not offered the memory's tools ({out['audit_tools']})")
    check(ACME in out["audit_system"], "...but reads the notes")
    check(out["seen"][0]["tools"] == out["seen"][1]["tools"]
          and "remember" not in out["seen"][0]["tools"]
          and "error" in out["seen"][0]["results"][0] and "error" in out["seen"][1]["results"][0],
          "an MQTT question and an investigation session's turn cannot write it either")
    check(out["mqtt"] == "ok", "...and nothing is printed under their answers")
    check(not out["dup"]["ok"] and "already note #1" in out["dup"]["error"],
          "the same note twice is refused, whatever the case")
    check(not out["empty"]["ok"], "an empty note is refused")
    check(out["long"]["ok"] and out["count"] == M.MAX_NOTES
          and not out["full"]["ok"] and "full" in out["full"]["error"],
          f"a long note is cut to {M.MAX_CHARS}; past {M.MAX_NOTES} notes it says to update or forget one")
    check(not out["noedit"]["ok"], "an unknown number is refused")
    check(out["nofile"] is None, "a --once rehearsal (the smoke run) writes nothing")


def test_every_run_reads_it():
    print("\n-- every model run reads the notes: audit, question, weekly, log triage --")
    out = {}
    a_voice = ["", ""]

    async def go(d):
        _, a = _auditor(d)
        a.memory.add(ACME, by="owner", via="dashboard")
        bodies = []

        async def fake_chat(session, messages, use_tools):
            bodies.append(messages[0]["content"])
            return {"message": {"role": "assistant", "content": '{"problem": false}'}}
        a.agent._chat = fake_chat
        await a.agent.ask_json("TRIAGE PROMPT", "lines")
        await a.agent.run_audit("AUDIT PROMPT", "ctx")
        await a.agent.ask_text("WEEKLY PROMPT", "facts", tools=False)
        out["bodies"] = bodies
        a.memory.notes.clear()
        out["none"] = a.agent._with_memory("PROMPT")
        a_voice[:] = [a.agent.network, a.agent.voice]
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    b = out["bodies"]
    check(len(b) == 3 and all(ACME in x for x in b),
          "a log triage, the audit and the weekly review all carry the note")
    check(all(x.split("\n\n")[0] in ("TRIAGE PROMPT", "AUDIT PROMPT", "WEEKLY PROMPT") for x in b),
          "at the END of the system prompt, so its prefix does not change")
    check(out["none"] == "\n\n".join(x for x in ("PROMPT", a_voice[0], a_voice[1]) if x)
          and "MEMORY" not in out["none"], "no notes, no block: the prompt, the network, the voice")
    check(a_voice[1].startswith("\nVOICE — you are the owl"), "the owl's voice by default")


def test_telegram_commands():
    print("\n-- /memory, /remember, /forget --")
    replies = []

    async def go(d):
        _, a = _auditor(d)

        async def reply(chat, text):
            replies.append(text)
        a.chat._reply = reply
        for t in ("/memory", "/remember " + ACME, "/remember", "/memory", "/forget",
                  "/forget #1, 7", "/memory"):
            await a.chat.on_telegram(t, "100000001")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = replies
    check("Nothing remembered yet" in r[0], "an empty memory says how to add to it")
    check(r[1] == "💾 Remembered #1.", "/remember saves it as written")
    check("Say what" in r[2], "/remember with nothing asks for the text")
    check("#1</b> The Acme" in r[3] and "you, " in r[3], "/memory lists it, as the owner's")
    check("Say which" in r[4] and "#1</b>" in r[4], "/forget with no number shows the list")
    check("🗑 Forgot #1." in r[5] and "no note #7" in r[5], "/forget takes several, and says which were not there")
    check("Nothing remembered yet" in r[6], "...and it is gone")


def test_telegram_is_a_conversation():
    print("\n-- a Telegram chat is a conversation: follow-ups, /new, a long silence, a restart --")
    out = {}

    async def go(d):
        _, a = _auditor(d)
        a._persist_alerts = True
        seen = []
        _model(a, lambda i: ([], f"answer {i}"), seen)
        replies = []

        async def reply(chat, text):
            replies.append(text)
        a.chat._reply = reply

        async def ask(q):
            await a.chat._answer_telegram(q, "100000001")
        await ask("why did the fiber drop?")
        await ask("and yesterday?")
        _, b = _auditor(d)                     # a restart in between
        b.agent.ask_text = a.agent.ask_text
        b.chat._reply = reply
        await b.chat._answer_telegram("and the day before?", "100000001")
        await b.chat.on_telegram("/new", "100000001")
        await b.chat._answer_telegram("something else", "100000001")
        c = b.chat._tg["100000001"]["turns"]
        c[-1]["ts"] = time.time() - C.TG_IDLE_S - 60      # six hours of silence
        out["idle"] = b.chat._tg_history("100000001")
        for i in range(C.TG_TURNS + 3):
            b.chat._tg_keep("100000001", f"q{i}", f"a{i}")
        out["kept"] = len(b.chat._tg["100000001"]["turns"])
        out["seen"], out["replies"] = seen, replies
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    s = out["seen"]
    check(s[0]["history"] == [] and s[0]["system"].startswith(QA_SYSTEM_TELEGRAM),
          "the first question has no history — but the conversation's prompt")
    check(s[1]["history"] == [{"role": "user", "content": "why did the fiber drop?"},
                              {"role": "assistant", "content": "answer 1"}],
          "the follow-up carries the first question and its answer")
    check(len(s[2]["history"]) == 4, "...and it survives a restart")
    check("New conversation" in out["replies"][3] and s[3]["history"] == [],
          "/new starts over")
    check(out["idle"] == [], "so does a question after six hours of silence")
    check(out["kept"] == C.TG_TURNS, f"only the last {C.TG_TURNS} exchanges are kept")
    check(QA_SYSTEM != QA_SYSTEM_TELEGRAM and "stands alone" not in QA_SYSTEM_TELEGRAM,
          "the Telegram prompt no longer says each question stands alone")


def test_dashboard():
    print("\n-- the dashboard: the notes, and add / edit / delete --")
    import aiohttp
    out = {}

    async def go(d):
        _, a = _auditor(d, {"web": {"enabled": True, "host": "127.0.0.1", "port": 0, "login": False}})
        a._last_report = {"ts": time.time(), "devices": []}
        await a.dashboard.start()
        port = a.dashboard._runner.addresses[0][1]
        base = f"http://127.0.0.1:{port}"
        async with aiohttp.ClientSession() as s:
            async def post(body):
                async with s.post(base + "/api/memory", json=body) as r:
                    return r.status, await r.json()
            out["add"] = await post({"op": "add", "text": ACME})
            out["edit"] = await post({"op": "edit", "id": 1, "text": "Acme: 198.51.100.99"})
            async with s.get(base + "/api/state") as r:
                out["state"] = (await r.json())["memory"]
            out["del"] = await post({"op": "delete", "id": 1})
            out["again"] = await post({"op": "delete", "id": 1})
            out["bad"] = await post({"op": "drop"})
            async with s.post(base + "/api/memory", data="x",
                              headers={"Content-Type": "text/plain"}) as r:
                out["form"] = r.status
        await a.dashboard.stop()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["add"][0] == 200 and out["add"][1]["id"] == 1 and "change" not in out["add"][1],
          "POST add saves it")
    check(out["state"] == [{**out["state"][0], "text": "Acme: 198.51.100.99", "by": "owner",
                            "via": "dashboard"}], f"/api/state carries it, edited ({out['state']})")
    check(out["del"][0] == 200 and out["again"][0] == 409, "delete removes it; twice is a 409")
    check(out["bad"][0] == 400 and out["form"] == 415, "an unknown op and a form POST are refused")


if __name__ == "__main__":
    for fn in [test_remember_change_forget, test_the_footer_is_the_codes, test_rules, test_every_run_reads_it,
               test_telegram_commands, test_telegram_is_a_conversation, test_dashboard]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all memory tests passed")
