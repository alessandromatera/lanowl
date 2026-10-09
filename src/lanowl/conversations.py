"""The dashboard's Ask tab: conversations with the model, not one-off questions.

A one-shot question box has three problems: the model cannot be stopped once it starts, a
follow-up ("and yesterday?") reaches a model that never saw the first question, and the
list of old answers only grows. So the Ask tab is:

  - a conversation: a follow-up is shown the earlier questions and answers (only the final
    answers — not the tool results behind them, which would make every follow-up a longer
    prompt than the audit's) plus freshly gathered data;
  - streamed: the page sees the model thinking, each read-only check it makes, and the
    answer as it is written;
  - stoppable: Stop cancels the answer, which closes the stream to Ollama, which stops the
    generation and hands the model back to the hourly audit at once;
  - Retry on the last answer, New chat, and the recent conversations kept across a restart
    (the `conversations` record in the state DB) so one started on the phone can be picked
    up on the laptop.

Still the same model, the same read-only tools and the same queue as Telegram
(Auditor.model_turn): one question at a time, the audit first. Telegram keeps one question,
one answer.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import secrets
import time
from typing import Optional

from .memory import strip_footer
from .report import label

log = logging.getLogger("lanowl.conversations")

RECORD = "conversations"
MAX_CONVS = 20          # the Recent list; the conversation touched longest ago goes first
MAX_TURNS = 40          # questions in one conversation; past that, start a new one
HISTORY_TURNS = 8       # earlier answers a follow-up carries
HISTORY_CHARS = 3000    # ...each cut to this
MAX_PENDING = 3         # across every conversation: one model, a short queue
Q_MAX = 1000
BRIEF_MAX = 8000        # a question with the facts gathered for it (an internet event's evidence)
THINK_TAIL = 400        # the live glimpse of the model's reasoning, never stored
MAX_STEPS = 30
_ID = re.compile(r"^[A-Za-z0-9_-]{6,24}$")
_TRANSIENT = ("draft", "think", "phase")    # live while answering; not kept


def _span(v, unit: str = "h") -> str:
    try:
        h = float(v) * (24 if unit == "d" else 1)
    except (TypeError, ValueError):
        h = 24.0
    return f"{h:g}h" if h < 48 else f"{h / 24:g} days"


def describe_tool(name: str, args: dict, inv) -> str:
    """One line a person can read for each check the model makes: 'Searching the router log
    for "pppoe", last 24h', not `router_log {"search": "pppoe"}`. Devices as NAME (address),
    as everywhere else."""
    args = args if isinstance(args, dict) else {}
    s = lambda k, d="": str(args.get(k, d) or d)[:60]                     # noqa: E731
    ip = s("ip")
    dev = inv.get(ip) if (ip and inv is not None) else None
    who = label(dev.name if dev else "", ip) if ip else ""
    if name == "ping_host":
        return f"Pinging {who}"
    if name == "tcp_check":
        return f"Trying port {s('port')} on {who}"
    if name == "http_get":
        return f"Loading {s('path', '/')} on {who}, port {s('port')}"
    if name == "snmp_get":
        return f"Reading SNMP from {who}"
    if name == "mikrotik_read":
        return f"Reading {s('path')} from {who}"
    if name == "mqtt_last":
        return f"Reading MQTT {s('pattern', '#')}"
    if name == "device_forensics":
        return f"Investigating {who}"
    if name == "history_query":
        return (f"Ups and downs of {who}" if who else "Ups and downs") + \
            f", last {_span(args.get('hours', 24))}"
    if name == "router_log":
        return f"Searching the router log for “{s('search')}”, last {_span(args.get('hours', 24))}"
    if name == "log_findings":
        return f"Reading the log checks, last {_span(args.get('hours', 24))}"
    if name == "wan_history":
        return f"Internet history, last {_span(args.get('days', 7), 'd')}"
    if name == "device_stats":
        return f"How {who} has been, last {_span(args.get('days', 7), 'd')}"
    if name == "host_log":
        what = f" for “{s('search')}”" if args.get("search") else ""
        unit = f" ({s('unit')})" if args.get("unit") else ""
        return f"Reading the log of {who}{unit}{what}, last {_span(args.get('hours', 24))}"
    if name == "device_read":
        what = f" for “{s('search')}”" if args.get("search") else ""
        return f"Reading {s('read') or '?'} on {who}{what}"
    if name == "cve_lookup":
        return f"Looking up {s('cve')}" + (f" for {who}" if who else "")
    if name == "propose_action":
        from .actions import CATALOG
        return f"Proposing: {CATALOG.get(s('action'), s('action') or '?')} — {who}"
    if name == "shell":
        c = " ".join(str(args.get("command") or "").split())
        return "$ " + (c[:90] + "…" if len(c) > 90 else c)
    if name == "remember":
        t = s("text")
        return f"Remembering “{t}{'…' if len(str(args.get('text') or '')) > 60 else ''}”"
    if name == "update_memory":
        return f"Changing note #{s('id')}"
    if name == "forget_memory":
        return f"Forgetting note #{s('id')}"
    if name == "run_check":
        dev = s("device")
        d = inv.get(dev) if (dev and inv is not None) else None
        what = (label(d.name if d else "", dev) if dev else "") or s("target") or s("name") or \
            s("subnet") or s("iface") or s("unit") or s("host") or s("link")
        return f"Running {s('check') or '?'}" + (f" — {what}" if what else "")
    return name or "?"



def chat_title(q: str) -> str:
    """A conversation's name: its first words worth reading — not a pasted banner line
    ("=== START OF INFORMATION SECTION ===", 10-08), not a fence, not a bare separator."""
    for line in str(q or "").splitlines():
        t = line.strip().strip("=#*-_`>| ").strip()
        if len(t) >= 3 and not re.fullmatch(r"[\W_]+", t) and not re.fullmatch(r"(start|end) of .*", t, re.I):
            return t[:90]
    return str(q or "").strip()[:90]

class Conversations:
    def __init__(self, auditor):
        self.a = auditor
        self._convs: dict[str, dict] = {}
        self._tasks: dict[str, asyncio.Future] = {}     # turn id -> the task answering it
        self._restore()

    # --- persistence ---------------------------------------------------------
    def _restore(self):
        try:
            rec = self.a.state.load_record(RECORD) or {}
        except Exception:
            log.warning("conversations: record unreadable, starting empty", exc_info=True)
            return
        for c in rec.get("convs") or []:
            if not isinstance(c, dict) or not _ID.match(str(c.get("id", ""))):
                continue
            for t in c.get("turns") or []:
                if t.get("status") == "pending":     # the process died mid-answer
                    t.update(status="failed", done_ts=c.get("updated"),
                             error="lanowl restarted before this was answered.")
            self._convs[c["id"]] = c

    def _save(self):
        convs = [{**c, "turns": [{k: v for k, v in t.items() if k not in _TRANSIENT}
                                 for t in c["turns"]]} for c in self._convs.values()]
        try:
            self.a.state.save_record(RECORD, {"convs": convs})
        except Exception:
            log.warning("conversations: could not save", exc_info=True)

    # --- reading -------------------------------------------------------------
    def pending(self) -> list:
        return [t for c in self._convs.values() for t in c["turns"] if t["status"] == "pending"]

    def view(self, cid: str) -> Optional[dict]:
        c = self._convs.get(cid)
        if c is None:
            return None
        turns = []
        for t in c["turns"]:
            v = {k: v for k, v in t.items() if k not in _TRANSIENT}
            if t["status"] == "pending":
                v.update(phase=t.get("phase") or "queued", draft=t.get("draft") or "",
                         think=t.get("think") or "")
            turns.append(v)
        return {"id": c["id"], "created": c["created"], "updated": c["updated"], "turns": turns}

    def recent(self) -> list:
        cs = sorted(self._convs.values(), key=lambda c: c["updated"], reverse=True)
        return [{"id": c["id"], "title": chat_title(c["turns"][0]["q"]) if c["turns"] else "",
                 "updated": c["updated"], "n": len(c["turns"]),
                 "pending": any(t["status"] == "pending" for t in c["turns"])} for c in cs]

    # --- asking --------------------------------------------------------------
    def ask(self, cid, q, brief: str = "") -> tuple[dict, int]:
        """A question, in conversation `cid` — or a new one when `cid` is empty or unknown
        (deleted, or dropped off the Recent list). Returns (JSON body, HTTP status).
        `brief`: what the model is given instead of the question as shown — the question with
        facts the code gathered (an internet event's evidence, for one)."""
        q = re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+", " ", str(q or "").replace("\r", ""))).strip()
        q = q[:Q_MAX]
        if not q:
            return {"ok": False, "error": "empty question"}, 400
        if self.a.no_llm:
            return self._off()
        c = self._convs.get(str(cid or ""))
        if c is not None and any(t["status"] == "pending" for t in c["turns"]):
            return {"ok": False, "error": "still answering the last question — stop it or wait"}, 409
        if c is not None and len(c["turns"]) >= MAX_TURNS:
            return {"ok": False, "error": "this conversation is long — start a new chat"}, 409
        if len(self.pending()) >= MAX_PENDING:
            return {"ok": False, "error": f"{MAX_PENDING} questions are already waiting for the "
                                          "model — one at a time"}, 429
        now = time.time()
        if c is None:
            c = {"id": secrets.token_urlsafe(9), "created": now, "updated": now, "turns": []}
            self._convs[c["id"]] = c
        t = {"id": secrets.token_urlsafe(6), "q": q}
        if brief:
            t["brief"] = str(brief)[:BRIEF_MAX]
        self._reset(t, now)
        c["turns"].append(t)
        c["updated"] = now
        self._evict()
        self._save()
        log.info("dashboard: question (%d chars, turn %d)", len(q), len(c["turns"]))
        self._start(c, t)
        return {"ok": True, "c": c["id"], "t": t["id"]}, 200

    def retry(self, cid, tid) -> tuple[dict, int]:
        """Ask the last question again: after a failure, a Stop, or an answer you didn't like."""
        c, t = self._find(cid, tid)
        if t is None:
            return {"ok": False, "error": "no such question"}, 404
        if t is not c["turns"][-1] or t["status"] == "pending":
            return {"ok": False, "error": "only the last answer can be asked again"}, 409
        if self.a.no_llm:
            return self._off()
        if len(self.pending()) >= MAX_PENDING:
            return {"ok": False, "error": "the model has a queue — try again in a minute"}, 429
        now = time.time()
        self._reset(t, now)
        c["updated"] = now
        self._save()
        log.info("dashboard: question asked again")
        self._start(c, t)
        return {"ok": True, "c": c["id"], "t": t["id"]}, 200

    def stop(self, cid, tid) -> tuple[dict, int]:
        c, t = self._find(cid, tid)
        if t is None:
            return {"ok": False, "error": "no such question"}, 404
        if t["status"] != "pending":
            return {"ok": True, "status": t["status"]}, 200
        self._finish(t, "stopped")               # at once, for the page; the task follows
        task = self._tasks.get(t["id"])
        if task is not None:
            task.cancel()
        log.info("dashboard: answer stopped (%s)", "was answering" if t.get("started") else "was queued")
        return {"ok": True, "status": "stopped"}, 200

    def stop_all(self, why: str) -> int:
        """Every answer being written or waiting, stopped: the model switched off
        (Auditor.set_model). Returns how many."""
        n = 0
        for c in self._convs.values():
            for t in c["turns"]:
                if t["status"] != "pending":
                    continue
                self._finish(t, "stopped", error=why)
                task = self._tasks.get(t["id"])
                if task is not None:
                    task.cancel()
                n += 1
        if n:
            self._save()
            log.info("dashboard: %d answer(s) stopped — %s", n, why)
        return n

    def _off(self) -> tuple[dict, int]:
        return {"ok": False, "error": "the model is off for this run of lanowl (--no-llm)"
                if self.a._no_llm_cli else "the local model is switched off"}, 503

    def delete(self, cid) -> tuple[dict, int]:
        c = self._convs.pop(str(cid or ""), None)
        if c is None:
            return {"ok": False, "error": "no such conversation"}, 404
        for t in c["turns"]:
            task = self._tasks.get(t["id"])
            if task is not None:
                task.cancel()
        self._save()
        return {"ok": True}, 200

    # --- the work --------------------------------------------------------------
    @staticmethod
    def _reset(t: dict, now: float):
        for k in ("a", "error", "started", "done_ts"):
            t.pop(k, None)
        # `attempt`: a Retry straight after a Stop starts a new run while the old one is
        # still unwinding its cancellation — which must not mark the new one stopped
        t.update(ts=now, status="pending", steps=[], phase="queued", draft="", think="",
                 attempt=int(t.get("attempt") or 0) + 1)

    def _find(self, cid, tid):
        c = self._convs.get(str(cid or ""))
        t = next((x for x in (c or {}).get("turns", []) if x["id"] == tid), None)
        return c, t

    def _evict(self):
        while len(self._convs) > MAX_CONVS:
            idle = [c for c in self._convs.values()
                    if not any(t["status"] == "pending" for t in c["turns"])]
            if not idle:
                return
            del self._convs[min(idle, key=lambda c: c["updated"])["id"]]

    def _history(self, c: dict, t: dict) -> list:
        """The earlier answered questions, as the chat messages the model is shown first."""
        done = [x for x in c["turns"][:c["turns"].index(t)] if x["status"] == "done" and x.get("a")]
        msgs = []
        for x in done[-HISTORY_TURNS:]:
            a = strip_footer(x["a"])        # the memory's lines are the code's, not the model's
            a = a if len(a) <= HISTORY_CHARS else a[:HISTORY_CHARS] + " […]"
            # a question asked with facts keeps them for the follow-ups; a session's brief
            # was for that turn only
            q = x["brief"] if x.get("brief") and x.get("kind") != "session" else x["q"]
            msgs += [{"role": "user", "content": q}, {"role": "assistant", "content": a}]
        return msgs

    async def session_turn(self, cid, p: dict, brief: str) -> Optional[str]:
        """An approved investigation session asked for in this conversation: its report is a
        turn of its own, streamed like any answer — the owner watches the checks go by. A
        conversation deleted meanwhile gets a new one. Returns the report (or what it had
        written when stopped)."""
        now = time.time()
        c = self._convs.get(str(cid or ""))
        if c is None:
            c = {"id": secrets.token_urlsafe(9), "created": now, "updated": now, "turns": []}
            self._convs[c["id"]] = c
        t = {"id": secrets.token_urlsafe(6), "kind": "session", "session": p["id"], "brief": brief,
             "q": f"🔎 Investigation #{p['id']} approved — {p.get('reason') or 'investigate'}"}
        self._reset(t, now)
        c["turns"].append(t)
        c["updated"] = now
        self._evict()
        self._save()
        self._start(c, t)
        task = self._tasks.get(t["id"])
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        return t.get("a") if t["status"] in ("done", "stopped") else None

    def _start(self, c: dict, t: dict):
        task = asyncio.ensure_future(self._run(c, t))
        self._tasks[t["id"]] = task
        task.add_done_callback(lambda _f, tid=t["id"]: self._tasks.pop(tid, None)
                               if self._tasks.get(tid) is _f else None)

    async def _run(self, c: dict, t: dict):
        n = t["attempt"]
        mine = lambda: t.get("attempt") == n and t["status"] == "pending"     # noqa: E731
        history = self._history(c, t)
        sess = self.a.actions._get(t["session"]) if t.get("session") else None
        try:
            text = await self.a.chat.answer(
                t.get("brief") or t["q"], history=history,
                on_event=lambda *e: mine() and self._on_event(t, *e),
                source={"via": "dashboard", "conv": c["id"],
                        "question": (sess or {}).get("origin", {}).get("question") or t["q"],
                        "on_proposed": lambda pid: t.setdefault("proposals", []).append(pid)},
                session=sess)
        except asyncio.CancelledError:
            if mine():
                self._finish(t, "stopped")
                self._save()
            raise
        except Exception:
            log.exception("dashboard question failed")
            text = None
        if not mine():                            # stopped, deleted or retried meanwhile
            return
        if text:
            self._finish(t, "done", text)
        else:
            self._finish(t, "failed", error="No answer — the model did not respond in time.")
        c["updated"] = time.time()
        self._save()

    def _on_event(self, t: dict, kind: str, *args):
        if t["status"] != "pending":
            return
        if kind == "start":
            t.update(phase="thinking", started=time.time())
        elif kind == "thinking":
            t["think"] = (t.get("think", "") + args[0])[-THINK_TAIL:]
            t["phase"] = "thinking"
        elif kind == "content":
            t["draft"] = t.get("draft", "") + args[0]
            t["phase"] = "writing"
        elif kind == "tool":
            # whatever it wrote this round was preamble to a check, not the answer
            if len(t["steps"]) < MAX_STEPS:
                t["steps"].append({"ts": time.time(),
                                   "text": describe_tool(args[0], args[1], self.a.inv)})
            t.update(phase="checking", draft="", think="")

    @staticmethod
    def _finish(t: dict, status: str, text: Optional[str] = None, error: Optional[str] = None):
        if t["status"] != "pending":
            return
        t["status"] = status
        t["done_ts"] = time.time()
        # a stopped or failed answer keeps what it had written: often the useful part
        t["a"] = (text if text is not None else t.get("draft") or "").strip()
        if error:
            t["error"] = error
        for k in _TRANSIENT:
            t.pop(k, None)
