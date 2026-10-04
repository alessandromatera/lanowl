"""The thinking, read-only tool-calling agent (Ollama /api/chat).

Bounded and fail-safe: capped tool iterations, per-request timeout, one JSON-repair
retry, and any failure returns None so the caller falls back to the deterministic
report. The LLM never gates detection or alerts — it only enriches them.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional

from .model import model_cfg, model_name
from .prompts import DEFAULT_PERSONA, network_block, persona_block
from .tools import TOOL_SPECS, ToolExecutor

log = logging.getLogger("lanowl.agent")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    m = _FENCE.search(text)
    if m:
        text = m.group(1)
    text = text.strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    # last resort: outermost braces
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            obj = json.loads(text[start:end + 1])
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


class LlmAgent:
    def __init__(self, cfg: dict, executor: ToolExecutor):
        o = model_cfg(cfg)
        self.url = str(o.get("url") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model_name(cfg)
        self.think = bool(o.get("think", True))
        self.keep_alive = o.get("keep_alive", 0)
        self.timeout_s = o.get("request_timeout_s", 240)
        self.max_iters = o.get("max_tool_iters", 6)
        self.options = {"num_ctx": o.get("num_ctx", 16384),
                        "temperature": o.get("temperature", 0.2)}
        # added to every system prompt (_with_memory): the owner's words about the network,
        # and the voice ("owl" unless config.yaml says otherwise; "" for none)
        self.network = network_block(cfg)
        self.voice = persona_block(o.get("persona", DEFAULT_PERSONA))
        self.executor = executor
        # Largest prompt (in tokens) any single call of the LAST audit sent, per Ollama's
        # own prompt_eval_count. Every tool result is appended to the conversation, so the
        # prompt grows with each iteration, and past num_ctx Ollama truncates from the
        # FRONT — silently, and the front is the system prompt with the JSON schema in it.
        # An audit that then "loops without answering" looks like a model problem and is
        # a context problem. This number is how you tell the two apart.
        self.last_ctx_peak = 0
        # Tool calls made by the LAST run — not `executor.calls`, a counter that is never
        # reset, so "tool calls=122" can be an audit that made one.
        self.last_tool_calls = 0
        # memory.py, wired by the orchestrator: its notes end EVERY system prompt this
        # agent sends — audit, questions, weekly review, log triages. None = no memory.
        self.memory = None
        # The owner's switch (Auditor.set_model). While off, every call returns
        # None at once and Ollama is asked nothing, whichever caller forgot to check; `cut()`
        # makes the calls in flight return None too. None is a model that failed, and every
        # caller already carries on without one.
        self.off = False
        self._calls: set = set()
        self._cut: set = set()

    async def _guard(self, coro):
        """Run one call where the switch can reach it."""
        if self.off:
            coro.close()
            return None
        t = asyncio.ensure_future(coro)
        self._calls.add(t)
        try:
            return await t
        except asyncio.CancelledError:
            # cut by the switch — not the caller being cancelled (a Stop, a timeout), which
            # must still unwind as a cancellation
            me = asyncio.current_task()
            if t in self._cut and not (me is not None and me.cancelling()):
                return None
            raise
        finally:
            self._calls.discard(t)
            self._cut.discard(t)

    def cut(self) -> int:
        """Stop every call in flight: the switch going off. Closing the request is what makes
        Ollama stop generating. Returns how many were stopped."""
        n = 0
        for t in list(self._calls):
            if not t.done():
                self._cut.add(t)
                t.cancel()
                n += 1
        return n

    async def unload(self) -> bool:
        """Drop the model from Ollama's memory now (keep_alive 0) rather than after
        `keep_alive` — the switch going off: a large model can hold tens of GB for an hour."""
        if aiohttp is None:
            return False
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                async with s.post(f"{self.url}/api/generate",
                                  json={"model": self.model, "keep_alive": 0}) as resp:
                    resp.raise_for_status()
                    await resp.read()
            return True
        except Exception as e:
            log.warning("model not unloaded (%s: %s)", type(e).__name__, e or "no message")
            return False

    def _with_memory(self, system: str, asked_only: bool = False) -> str:
        """`system`, then the owner's description of the network and the persona's voice
        (both fixed by config), then the memory's notes. The notes go LAST, so the prompt's
        prefix — and the model server's cached work on it — stays the same when a note
        changes. `asked_only`: the owner's notes only (Memory.block)."""
        system = "\n\n".join(x for x in (system, self.network, self.voice) if x)
        try:
            block = self.memory.block(asked_only) if self.memory is not None else ""
        except Exception:
            log.warning("memory unreadable — prompt sent without it", exc_info=True)
            block = ""
        return f"{system}\n\n{block}" if block else system

    def _tools(self) -> list:
        """The executor decides what is on offer this turn (`propose_action` only while a
        turn may propose); anything without that notion gets the read-only set."""
        specs = getattr(self.executor, "tool_specs", None)
        return specs() if callable(specs) else TOOL_SPECS

    async def _chat(self, session, messages: list, use_tools: bool) -> dict:
        body = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.keep_alive,   # shared box: release the model after the call
            "options": self.options,
        }
        if self.think:
            body["think"] = True
        if use_tools:
            body["tools"] = self._tools()
        async with session.post(f"{self.url}/api/chat", json=body) as resp:
            resp.raise_for_status()
            data = await resp.json()
        used = int(data.get("prompt_eval_count") or 0)
        if used > self.last_ctx_peak:
            self.last_ctx_peak = used
        return data

    async def _chat_stream(self, session, messages: list, use_tools: bool, on_delta) -> dict:
        """`_chat`, streamed: the same request and the same reply, but every piece of thinking
        and text is handed to `on_delta(kind, text)` as it is generated.

        Only the dashboard's Ask uses this. An answer takes minutes, and a page that shows the
        model reasoning and writing is one you can tell is working — and stop, because closing
        a stream is what makes Ollama stop generating. The audit keeps `_chat`: nobody watches
        it. Ollama sends a tool call whole, in one chunk, and the prompt count on the last."""
        body = {"model": self.model, "messages": messages, "stream": True,
                "keep_alive": self.keep_alive, "options": self.options}
        if self.think:
            body["think"] = True
        if use_tools:
            body["tools"] = self._tools()
        content, thinking, tool_calls, last = [], [], [], {}
        async with session.post(f"{self.url}/api/chat", json=body) as resp:
            resp.raise_for_status()
            async for raw in resp.content:
                raw = raw.strip()
                if not raw:
                    continue
                last = json.loads(raw)
                if last.get("error"):
                    raise RuntimeError(str(last["error"]))
                m = last.get("message") or {}
                if m.get("thinking"):
                    thinking.append(m["thinking"])
                    on_delta("thinking", m["thinking"])
                if m.get("content"):
                    content.append(m["content"])
                    on_delta("content", m["content"])
                tool_calls += m.get("tool_calls") or []
        used = int(last.get("prompt_eval_count") or 0)
        if used > self.last_ctx_peak:
            self.last_ctx_peak = used
        msg = {"role": "assistant", "content": "".join(content), "thinking": "".join(thinking)}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return {"message": msg, "prompt_eval_count": used}

    @staticmethod
    def _parse_args(raw) -> dict:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except Exception:
                return {}
        return {}

    async def ask_json(self, system: str, user_context: str,
                       timeout_s: Optional[float] = None) -> Optional[dict]:
        return await self._guard(self._ask_json(system, user_context, timeout_s))

    async def _ask_json(self, system: str, user_context: str,
                        timeout_s: Optional[float] = None) -> Optional[dict]:
        """One-shot, no tools, JSON back — or None.

        The full `run_audit` loop is the wrong shape for small verdict questions like
        "is anything in this log worth waking someone for": it grants tools, allows
        `max_tool_iters` round trips and has run for 569s. This is a single call with its
        own (shorter) timeout, so a caller on a fast clock can await it without inheriting
        the audit's worst case. Same fail-safe contract: any problem returns None."""
        if aiohttp is None:
            return None
        # a verdict nobody watches: only the notes the owner asked for (Memory.block)
        messages = [{"role": "system", "content": self._with_memory(system, asked_only=True)},
                    {"role": "user", "content": user_context}]
        timeout = aiohttp.ClientTimeout(total=timeout_s or self.timeout_s)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                data = await self._chat(session, messages, use_tools=False)
                text = (data.get("message", {}) or {}).get("content", "") or ""
                v = extract_json(text)
                if v is None:
                    # what it said instead, so "no usable answer" can be read
                    log.warning("LLM ask_json: no JSON in its answer (%d chars): %r", len(text), text[:300])
                return v
        except Exception as e:
            log.warning("LLM ask_json failed (%s: %s).", type(e).__name__, e or "no message")
            return None

    async def _tool_loop(self, session, messages: list, final_nudge: str,
                         max_iters: Optional[int] = None, on_event=None) -> str:
        """Let the model investigate with the read-only tools, then take its answer.

        The LAST iteration is reserved for the answer: it is asked without tools, after a
        nudge. Without it, a thorough model's single biggest failure is spending every
        iteration on tool calls and having none left to reply in. Returns the final message
        content ("" if the model said nothing).

        With `on_event` the replies are streamed: on_event("thinking"|"content", text) as they
        are generated, and on_event("tool", name, args) before each tool runs — which also
        means any text streamed in that round was preamble, not the answer."""
        iters = max(1, int(max_iters or self.max_iters))
        for i in range(iters):
            last = i == iters - 1
            if last and i > 0:
                messages.append({"role": "user", "content": final_nudge})
            if on_event is None:
                data = await self._chat(session, messages, use_tools=not last)
            else:
                data = await self._chat_stream(session, messages, not last, on_event)
            msg = data.get("message", {}) or {}
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")}
                            or {"role": "assistant", "content": ""})
            tool_calls = msg.get("tool_calls") or []
            if tool_calls and not last:
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args = self._parse_args(fn.get("arguments"))
                    self.last_tool_calls += 1
                    if on_event is not None:
                        on_event("tool", name, args)
                    result = await self.executor.call(name, args)
                    messages.append({"role": "tool", "content": json.dumps(result, default=str)})
                continue
            return msg.get("content", "") or ""
        return ""

    async def run_audit(self, system: str, user_context: str) -> Optional[dict]:
        return await self._guard(self._run_audit(system, user_context))

    async def _run_audit(self, system: str, user_context: str) -> Optional[dict]:
        if aiohttp is None:
            log.warning("aiohttp missing; skipping LLM audit.")
            return None
        messages = [
            {"role": "system", "content": self._with_memory(system)},
            {"role": "user", "content": user_context},
        ]
        self.last_ctx_peak = 0
        self.last_tool_calls = 0
        timeout = aiohttp.ClientTimeout(total=self.timeout_s)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                content = await self._tool_loop(
                    session, messages,
                    "Stop investigating now. Answer with the ONE JSON object described in the "
                    "schema, using what you have found so far.")
                parsed = extract_json(content)
                if parsed:
                    return parsed
                # one repair attempt
                messages.append({"role": "user",
                                 "content": "Respond with ONLY the JSON object described in the schema, no prose."})
                data = await self._chat(session, messages, use_tools=False)
                parsed = extract_json((data.get("message", {}) or {}).get("content", ""))
                if parsed:
                    return parsed
                log.warning("LLM did not return valid JSON after repair.")
                return None
        except Exception as e:
            # `%s` on an aiohttp/asyncio error is very often the empty string, which logs as
            # "LLM audit failed ()" — true, useless. The type and the traceback are what make
            # it diagnosable a week later.
            log.warning("LLM audit failed (%s: %s); using deterministic report.",
                        type(e).__name__, e or "no message", exc_info=True)
            return None

    async def ask_text(self, system: str, user_context: str, tools: bool = True,
                       max_iters: Optional[int] = None, history: Optional[list] = None,
                       on_event=None) -> Optional[str]:
        return await self._guard(self._ask_text(system, user_context, tools, max_iters,
                                                history, on_event))

    async def _ask_text(self, system: str, user_context: str, tools: bool = True,
                        max_iters: Optional[int] = None, history: Optional[list] = None,
                        on_event=None) -> Optional[str]:
        """A question in, prose out — for the owner's questions over Telegram and the dashboard.

        Same read-only tools and the same whitelist as the audit; the answer is plain text
        for a phone, not JSON. None on any failure: the caller says so honestly rather than
        inventing an answer. `history` is the conversation so far, as user/assistant
        messages placed before this question; `on_event` streams it (see `_tool_loop`)."""
        if aiohttp is None:
            return None
        messages = [{"role": "system", "content": self._with_memory(system)}, *(history or []),
                    {"role": "user", "content": user_context}]
        self.last_ctx_peak = 0
        self.last_tool_calls = 0
        timeout = aiohttp.ClientTimeout(total=self.timeout_s)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if not tools:
                    data = await (self._chat(session, messages, use_tools=False)
                                  if on_event is None else
                                  self._chat_stream(session, messages, False, on_event))
                    text = (data.get("message", {}) or {}).get("content", "")
                else:
                    text = await self._tool_loop(
                        session, messages,
                        "Stop investigating now and answer the question with what you have.",
                        max_iters=max_iters, on_event=on_event)
        except Exception as e:
            log.warning("LLM ask_text failed (%s: %s)", type(e).__name__, e or "no message")
            return None
        text = (text or "").strip()
        return text or None
