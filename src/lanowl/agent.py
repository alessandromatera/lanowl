"""The thinking, read-only tool-calling agent (Ollama /api/chat).

Bounded and fail-safe: capped tool iterations, per-request timeout, one JSON-repair
retry, a model going round in circles stopped (and asked once more), and any failure returns
None so the caller falls back to the deterministic report. The LLM never gates detection or
alerts — it only enriches them.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
from typing import Optional

from .model import model_cfg, model_name, temperature_setting, think_setting, think_words
from .prompts import DEFAULT_PERSONA, call_block, network_block, persona_block
from .tools import TOOL_SPECS, ToolExecutor

log = logging.getLogger("lanowl.agent")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


# The two slips a model makes in otherwise good JSON, mended before giving up on an answer:
# a backslash that is no JSON escape (a sed or grep pattern: `\(`, `\s`) and a comma before a
# closing bracket. Only tried on an answer that does not parse as it is.
_BAD_ESCAPE = re.compile(r'\\(?!["\\/bfnrtu])')
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _loads(text: str):
    """(object, "") or (None, why): `strict=False` accepts a line break written as-is inside
    a string — models do that in multi-line values (a fix's commands, one per line)."""
    try:
        return json.loads(text, strict=False), ""
    except ValueError as e:
        why = str(e)
    for mend in (lambda s: _BAD_ESCAPE.sub(r"\\\\", s), lambda s: _TRAILING_COMMA.sub(r"\1", s)):
        text = mend(text)
        try:
            return json.loads(text, strict=False), ""
        except ValueError:
            pass
    return None, why


def _json_in(text: str) -> tuple:
    """(the JSON object in a model's answer or None, why not)."""
    if not text:
        return None, "an empty answer"
    m = _FENCE.search(text)
    if m:
        text = m.group(1)
    text = text.strip()
    obj, why = _loads(text)
    if obj is None:
        # what is between the outermost braces: a sentence before or after the object
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            obj, why2 = _loads(text[start:end + 1])
            why = why if obj is None else ""
        elif not why:
            why = "no {...} in it"
    if obj is not None and not isinstance(obj, dict):
        return None, "not an object"
    return obj, why


def extract_json(text: str) -> Optional[dict]:
    """The JSON object in a model's answer, or None."""
    return _json_in(text)[0]


def own_temperature(parameters) -> Optional[float]:
    """The model's own temperature: the `temperature` line of /api/show's `parameters`, a text of
    lines `name<spaces>value` ("top_k  20", "top_p  0.95", "temperature  1"). None when there is
    no such line or it does not read as a number."""
    if not isinstance(parameters, str):
        return None
    for line in parameters.splitlines():
        bits = line.split(None, 1)
        if len(bits) == 2 and bits[0] == "temperature":
            try:
                v = float(bits[1])
            except ValueError:
                return None
            return v if math.isfinite(v) else None
    return None


# A thinking model can fall into a loop: its thinking (or its answer) goes round the same
# passage until the call is cut, minutes or half an hour later, on a GPU nobody else can use.
# Every call is watched as it is written (LlmAgent._chat_stream), and a text is looked at each
# time it has grown by LOOP_STEP characters. These are fixed, not settings: they were checked
# against real loops and against long good thinking and answers.
LOOP_WINDOW = 200      # the end of a text that is looked for again, and the shortest passage of an answer
LOOP_REPEATS = 3       # a loop: that end found this often (thinking), or a passage run this often (answer)
LOOP_STEP = 1000       # a text is looked at again each time it has grown by this many characters
LOOP_MAX_PERIOD = 20000    # an answer's passage is looked for up to this long
LOOP_RETRY_MIN_S = 15      # a loop is asked again only if the request has at least this long left


def thinking_loop(text: str) -> Optional[tuple]:
    """(the passage's length, how many times) when the last LOOP_WINDOW characters of a thinking
    occur at least LOOP_REPEATS times in it, else None. The passage's length is the distance
    from the last of them back to the one before."""
    if len(text) < LOOP_WINDOW:
        return None
    end = text[-LOOP_WINDOW:]
    times, at = 0, text.find(end)
    while at != -1:
        times += 1
        at = text.find(end, at + 1)
    if times < LOOP_REPEATS:
        return None
    return len(text) - LOOP_WINDOW - text.rfind(end, 0, len(text) - 1), times


def answer_loop(text: str) -> Optional[tuple]:
    """(the passage's length, how many times) when an answer ENDS with one passage of at least
    LOOP_WINDOW characters repeated LOOP_REPEATS times back to back, else None. Only an exact
    repeat is a loop: an answer may list near-identical items (29 findings that differ in their
    address) and is no loop. The passage is looked for where the last LOOP_WINDOW characters
    occurred before, up to LOOP_MAX_PERIOD back."""
    n = len(text)
    if n < LOOP_WINDOW * LOOP_REPEATS:
        return None
    end = text[-LOOP_WINDOW:]
    stop = n - LOOP_WINDOW                     # the passage ends before the last LOOP_WINDOW: p >= LOOP_WINDOW
    while True:
        at = text.rfind(end, max(0, n - LOOP_WINDOW - LOOP_MAX_PERIOD), stop)
        if at == -1:
            return None
        p = n - LOOP_WINDOW - at
        if p * LOOP_REPEATS <= n and text[-p:] == text[-2 * p:-p] == text[-3 * p:-2 * p]:
            times = 3
            while (times + 1) * p <= n and text[-(times + 1) * p:-times * p] == text[-p:]:
                times += 1
            return p, times
        stop = at + LOOP_WINDOW - 1            # the next one back


def _how_long(s: float) -> str:
    """How long a call ran, for a person: "45 s", "4 min 10 s", "30 min"."""
    s = round(s)
    if s < 60:
        return f"{s} s"
    m, s = divmod(s, 60)
    return f"{m} min" + (f" {s} s" if s else "")


class ModelRepeated(Exception):
    """The model went round in circles: its `where` ("thinking" or "answer") repeated the same
    `passage` characters `times` times, `after` seconds into the call. The call was stopped."""

    def __init__(self, where: str, passage: int, times: int, after: float):
        self.where, self.passage, self.times, self.after = where, passage, times, after
        self.detail = f"a {passage}-character passage, {times} times, in its {where}, after {_how_long(after)}"
        super().__init__(f"the model repeated itself: {self.detail}")


def _why(e: Exception) -> str:
    """A failed call in words, for the log: a model that repeated itself says it all, the other
    failures their type and message (often none, on a timeout)."""
    return str(e) if isinstance(e, ModelRepeated) else f"{type(e).__name__}: {e or 'no message'}"


class LlmAgent:
    def __init__(self, cfg: dict, executor: ToolExecutor):
        o = model_cfg(cfg)
        self.url = str(o.get("url") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model_name(cfg)
        # False, True (the model's own default level) or a level it lists: one for every call
        self.think = think_setting(cfg)
        self.think_info: Optional[dict] = None     # think_levels(): what the model says it can do
        self._think_tried = 0.0
        self.keep_alive = o.get("keep_alive", 0)
        self.timeout_s = o.get("request_timeout_s", 240)
        self.max_iters = o.get("max_tool_iters", 6)
        self.options = {"num_ctx": o.get("num_ctx", 16384)}
        temperature = temperature_setting(cfg)
        if temperature is not None:        # auto: none is sent, so Ollama applies the model's own
            self.options["temperature"] = temperature
        # added to every system prompt (_with_memory): the owner's words about the network,
        # and the voice ("owl" unless config.yaml says otherwise; "" for none)
        self.network = network_block(cfg)
        self.persona = o.get("persona", DEFAULT_PERSONA)
        self.voice = persona_block(self.persona)
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
        # What the LAST audit or question says if it failed because the model repeated itself
        # (ModelRepeated's words), "" if it did not: for the places that tell the owner "no
        # answer", which is not the timeout it used to look like. Audits and questions take the
        # model one at a time (Auditor.model_turn), so one slot will do.
        self.last_repeated = ""
        # memory.py, wired by the orchestrator: its notes end EVERY system prompt this
        # agent sends — audit, questions, weekly review, log triages. None = no memory.
        self.memory = None
        # The owner's switch (Auditor.set_model). While off, every call returns
        # None at once and Ollama is asked nothing (but the model's listing, think_levels, for
        # Settings), whichever caller forgot to check; `cut()`
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

    async def think_levels(self) -> Optional[dict]:
        """What the model says about thinking, from Ollama's /api/show (a listing: nothing is
        loaded): {"model", "can": it thinks at all, "values": its levels, e.g. [False, "low",
        "medium", "xhigh"] ([] when this Ollama does not say), "default": e.g. "medium",
        "temperature": the model's own, from its listed parameters, or None}.
        Asked once per model; after a failure, again 10 minutes later. None = not known yet."""
        if self.think_info is not None and self.think_info.get("model") == self.model:
            return self.think_info
        now = time.time()
        if aiohttp is None or now - self._think_tried < 600:
            return None
        self._think_tried = now
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as s:
                async with s.post(f"{self.url}/api/show", json={"model": self.model}) as resp:
                    resp.raise_for_status()
                    d = await resp.json()
        except Exception as e:
            log.info("the model's thinking levels unknown for now (%s: %s)", type(e).__name__, e or "no message")
            return None
        caps, th = d.get("capabilities"), d.get("thinking") or {}
        info = {"model": self.model, "can": "thinking" in caps if isinstance(caps, list) else True,
                "values": [v for v in (th.get("values") if isinstance(th, dict) else None) or []
                           if isinstance(v, (bool, str))],
                "default": str((th.get("default") if isinstance(th, dict) else "") or ""),
                "temperature": own_temperature(d.get("parameters"))}
        self.think_info = info
        sent = self.think_value()
        if self.think is not False and sent != self.think:
            log.warning("model.think %s: %s, so lanowl asks for %s", think_words(self.think),
                        "this model cannot think" if not info["can"] else
                        "not one of this model's levels (" + ", ".join(
                            "off" if v is False else str(v) for v in info["values"]) + ")",
                        "no thinking" if sent is None else "its default level")
        return info

    def think_value(self):
        """What a request's `think` says, or None to leave it out. Off is said: a thinking model
        sent no `think` thinks anyway. A model that cannot think is never asked to (Ollama
        refuses the request), and a level the model does not list becomes its default."""
        info = self.think_info
        if info is not None and not info["can"]:
            return None
        if not isinstance(self.think, str):
            return bool(self.think)
        if info is not None and info["values"] and self.think not in info["values"]:
            return True
        return self.think

    def _with_memory(self, system: str, asked_only: bool = False, call: str = "") -> str:
        """`system`, then the owner's description of the network and the persona's voice
        (both fixed by config), then the memory's notes. The notes go LAST, so the prompt's
        prefix — and the model server's cached work on it — stays the same when a note
        changes. `asked_only`: the owner's notes only (Memory.block). `call`: where the
        owner's reading starts, for a prompt whose words open a message (prompts.CALLS)."""
        system = "\n\n".join(x for x in (system, self.network, self.voice,
                                         call_block(self.persona, call)) if x)
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
        """One /api/chat call and its whole reply, as a reply that was not streamed is: `message`
        (role, content, thinking, tool_calls) and the last chunk's own fields (done, done_reason,
        eval_count, prompt_eval_count, the durations...). It is read as a stream all the same
        (`_chat_stream`): that is how a model going round in circles is caught as it writes."""
        return await self._chat_stream(session, messages, use_tools, None)

    async def _chat_stream(self, session, messages: list, use_tools: bool, on_delta=None) -> dict:
        """`_chat`, and with `on_delta(kind, text)` every piece of thinking and text is handed on
        as it is generated.

        The dashboard's Ask does that. An answer takes minutes, and a page that shows the
        model reasoning and writing is one you can tell is working — and stop, because closing
        a stream is what makes Ollama stop generating. Ollama sends a tool call whole, in one
        chunk, and the prompt count on the last.

        The pieces are watched either way (thinking_loop, answer_loop). A model going round in
        circles is stopped at once, its stream closed, and the same request is sent once more
        with what is left of the request's time; going round again is ModelRepeated.
        `on_delta("reset")` tells whoever shows the pieces to drop what it has."""
        body = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "keep_alive": self.keep_alive,   # shared box: release the model after the call
            "options": self.options,
        }
        await self.think_levels()
        if self.think_value() is not None:
            body["think"] = self.think_value()
        if use_tools:
            body["tools"] = self._tools()
        try:
            data = await self._read_chat(session, body, on_delta)
        except ModelRepeated as e:
            if on_delta is not None:
                on_delta("reset")
            # each request of a session gets the session's whole time: the second one gets what
            # is left of the first one's
            total = getattr(getattr(session, "timeout", None), "total", None)
            left = None if total is None else total - e.after
            if left is not None and left < LOOP_RETRY_MIN_S:
                log.warning("the model repeated itself (%s): not asking again, only %s of the "
                            "request's time is left", e.detail, _how_long(max(0, left)))
                raise
            log.warning("the model repeated itself (%s): asking once more", e.detail)
            try:
                data = await self._read_chat(session, body, on_delta, left)
            except ModelRepeated as again:
                if on_delta is not None:
                    on_delta("reset")
                log.warning("the model repeated itself (%s) again: given up", again.detail)
                raise
        used = int(data.get("prompt_eval_count") or 0)
        if used > self.last_ctx_peak:
            self.last_ctx_peak = used
        return data

    async def _read_chat(self, session, body: dict, on_delta, left: Optional[float] = None) -> dict:
        """One request of `_chat_stream`, read to its end — or until a text goes round in
        circles: ModelRepeated, and leaving the `async with` closes the connection. `left`: the
        retry's own time, in seconds, instead of the session's."""
        t0 = time.monotonic()
        parts = {"thinking": [], "content": []}
        size = {"thinking": 0, "content": 0}        # characters so far...
        looked = {"thinking": 0, "content": 0}      # ...and when each was last looked at
        tool_calls, last = [], {}

        def add(kind: str, text: str):
            parts[kind].append(text)
            if on_delta is not None:
                on_delta(kind, text)
            size[kind] += len(text)
            if size[kind] - looked[kind] < LOOP_STEP:
                return
            looked[kind] = size[kind]
            parts[kind][:] = ["".join(parts[kind])]
            found = (thinking_loop if kind == "thinking" else answer_loop)(parts[kind][0])
            if found:
                raise ModelRepeated("thinking" if kind == "thinking" else "answer", *found,
                                    time.monotonic() - t0)

        own = {} if left is None else {"timeout": aiohttp.ClientTimeout(total=left)}
        async with session.post(f"{self.url}/api/chat", json=body, **own) as resp:
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
                    add("thinking", m["thinking"])
                if m.get("content"):
                    add("content", m["content"])
                tool_calls += m.get("tool_calls") or []
        if not last.get("done"):
            # the stream ended before Ollama's last chunk: a reply cut off, not an answer
            raise ConnectionError("the model's reply was cut off before it was done")
        msg = {"role": "assistant", "content": "".join(parts["content"]),
               "thinking": "".join(parts["thinking"])}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return {**last, "message": msg}

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
                       timeout_s: Optional[float] = None, call: str = "") -> Optional[dict]:
        return await self._guard(self._ask_json(system, user_context, timeout_s, call))

    async def _ask_json(self, system: str, user_context: str,
                        timeout_s: Optional[float] = None, call: str = "") -> Optional[dict]:
        """One-shot, no tools, JSON back — or None.

        The full `run_audit` loop is the wrong shape for small verdict questions like
        "is anything in this log worth waking someone for": it grants tools, allows
        `max_tool_iters` round trips and has run for 569s. This is a single call with its
        own (shorter) timeout, so a caller on a fast clock can await it without inheriting
        the audit's worst case. Same fail-safe contract: any problem returns None."""
        if aiohttp is None:
            return None
        # a verdict nobody watches: only the notes the owner asked for (Memory.block)
        messages = [{"role": "system", "content": self._with_memory(system, asked_only=True,
                                                                     call=call)},
                    {"role": "user", "content": user_context}]
        timeout = aiohttp.ClientTimeout(total=timeout_s or self.timeout_s)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                data = await self._chat(session, messages, use_tools=False)
                text = (data.get("message", {}) or {}).get("content", "") or ""
                v, why = _json_in(text)
                if v is None:
                    # one repair, as the audit has: the model is told what the parser said
                    messages += [{"role": "assistant", "content": text},
                                 {"role": "user", "content": (
                                     f"That was not valid JSON ({why}). Answer again with ONLY the "
                                     "JSON object, valid: inside strings, escape every backslash "
                                     "(\\\\) and every double quote (\\\").")}]
                    data = await self._chat(session, messages, use_tools=False)
                    text2 = (data.get("message", {}) or {}).get("content", "") or ""
                    v, why2 = _json_in(text2)
                    if v is None:
                        # why, and what it said, so "no usable answer" can be read
                        log.warning("LLM ask_json: no valid JSON in its answer, twice (%s; then %s) "
                                    "(%d chars): %r", why, why2, len(text), text[:300])
                return v
        except Exception as e:
            log.warning("LLM ask_json failed (%s).", _why(e))
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

    async def run_audit(self, system: str, user_context: str, call: str = "") -> Optional[dict]:
        return await self._guard(self._run_audit(system, user_context, call))

    async def _run_audit(self, system: str, user_context: str, call: str = "") -> Optional[dict]:
        if aiohttp is None:
            log.warning("aiohttp missing; skipping LLM audit.")
            return None
        messages = [
            {"role": "system", "content": self._with_memory(system, call=call)},
            {"role": "user", "content": user_context},
        ]
        self.last_ctx_peak = 0
        self.last_tool_calls = 0
        self.last_repeated = ""
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
            # it diagnosable a week later. A model that repeated itself needs neither.
            if isinstance(e, ModelRepeated):
                self.last_repeated = str(e)
            log.warning("LLM audit failed (%s); using deterministic report.", _why(e),
                        exc_info=not isinstance(e, ModelRepeated))
            return None

    async def ask_text(self, system: str, user_context: str, tools: bool = True,
                       max_iters: Optional[int] = None, history: Optional[list] = None,
                       on_event=None, call: str = "") -> Optional[str]:
        return await self._guard(self._ask_text(system, user_context, tools, max_iters,
                                                history, on_event, call))

    async def _ask_text(self, system: str, user_context: str, tools: bool = True,
                        max_iters: Optional[int] = None, history: Optional[list] = None,
                        on_event=None, call: str = "") -> Optional[str]:
        """A question in, prose out — for the owner's questions over Telegram and the dashboard.

        Same read-only tools and the same whitelist as the audit; the answer is plain text
        for a phone, not JSON. None on any failure: the caller says so honestly rather than
        inventing an answer. `history` is the conversation so far, as user/assistant
        messages placed before this question; `on_event` streams it (see `_tool_loop`)."""
        if aiohttp is None:
            return None
        messages = [{"role": "system", "content": self._with_memory(system, call=call)},
                    *(history or []),
                    {"role": "user", "content": user_context}]
        self.last_ctx_peak = 0
        self.last_tool_calls = 0
        self.last_repeated = ""
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
            if isinstance(e, ModelRepeated):
                self.last_repeated = str(e)
            log.warning("LLM ask_text failed (%s)", _why(e))
            return None
        text = (text or "").strip()
        return text or None
