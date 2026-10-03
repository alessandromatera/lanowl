"""The fix for a finding, written out for the owner to apply themselves.

A finding of the security review carries a one-line "fix" ("keys only"), which is a direction,
not a fix: what to type, on which machine, in which order so as not to lock yourself out, and
how to put it back. The model has the machine's own facts (its OS and
version, its sshd settings, its firewall — what the review read this morning), so it can write
the exact change for THIS machine.

NOTHING HERE RUNS. The model changes nothing by itself: this writes text, the page shows it with
a Copy button, and the owner applies it — or not. Written by itself for the security review's
open findings after each morning's review (the model is idle by then), and on the button for
any finding of a review.

The steps follow one rule above all: prove the new way in works BEFORE the old one is turned
off.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Optional

from .reviews import words

log = logging.getLogger("lanowl.fixes")

RECORD = "fixes"
KEEP_DAYS = 30
AUTO = ("critical", "high", "warning")

SYSTEM = """You write the exact fix for ONE problem the monitor found on a home network, for its \
owner to apply THEMSELVES. Nothing you write is run by anyone but them: they read it on their \
phone or laptop, copy the commands, and apply them where you say.

Be exact for THIS machine: use what the facts show — its OS and version (RouterOS 6 and 7 differ; \
Debian and Ubuntu put sshd drop-ins in /etc/ssh/sshd_config.d/), its current settings, its \
firewall as it is. The owner describes the network under THE NETWORK, at the end.

Rules:
- NEVER LOCK THEM OUT. When a change can cut off the way they get in (ssh settings, a firewall on \
management, a VPN, a user), the steps FIRST prove the new way works — a second session kept open, \
a key login tested, the new rule placed before the old one is removed — and only then turn the \
old way off.
- The smallest change that fixes THIS problem. No unrelated hardening.
- Commands exactly as typed, ready to paste. A value only they know: <LIKE_THIS>, and say what \
goes there. Where it is a web page or an app (Cloudflare's dashboard, Home Assistant's settings), \
say where to click, in order.
- "undo": exactly how to put it back as it was.
- If it cannot be fixed on the machine itself, say so and give the best way around it.

Reply with ONLY this JSON object, no prose, no code fence:
{"summary": "<one line: what the fix changes>",
 "steps": [{"where": "<the machine and how to get there, e.g. 'VPS, root shell over ssh'>",
            "do": "<what this step does and why it is in this order>",
            "commands": "<the exact commands, one per line; empty if it is clicking>"}],
 "undo": "<the exact commands or steps that put it back>",
 "check": "<how to see it worked>",
 "careful": "<what could go wrong and how the steps avoid it; empty if nothing>"}"""


def sig(f: dict) -> str:
    """What a fix was written for: a finding that now says something else needs a new one."""
    return hashlib.sha1("|".join(str(f.get(k) or "") for k in ("check", "title", "evidence"))
                        .encode()).hexdigest()[:12]


class Fixes:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("fixes") or {}
        self.enabled = bool(c.get("enabled", True))
        self.timeout_s = float(c.get("model_timeout_s", 600))
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("fixes: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        self.rec.setdefault("items", {})
        self.queue: list = []                 # keys waiting to be written, in order
        self.writing: Optional[str] = None
        self._task: Optional[asyncio.Task] = None

    def _save(self):
        if not self.a._persist_alerts:
            return
        cut = time.time() - KEEP_DAYS * 86400
        self.rec["items"] = {k: v for k, v in self.rec["items"].items() if v.get("ts", 0) >= cut}
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("fixes: record not saved: %s", e)

    # --- which finding ------------------------------------------------------------------------
    def finding(self, key: str) -> tuple:
        """(finding, facts about its machine, where it came from) — or (None, "", "")."""
        a = self.a
        if key.startswith("exp:"):
            f = next((x for x in a.exposure.rec.get("findings") or [] if x["key"] == key), None)
            if f is None:
                return None, "", ""
            fx = (a.exposure.rec.get("facts") or {}).get(f["ip"]) or {}
            facts = fx.get("text") if fx.get("ok") else f"(the machine could not be read: {fx.get('error')})"
            return f, facts or "", "the morning security review"
        r = getattr(a, "drift", None)
        if r is not None and key.startswith(r.PREFIX + ":"):
            f = next((x for x in r.rec.get("findings") or [] if x["key"] == key), None)
            if f is None:
                return None, "", ""
            return f, "", r.TITLE
        return None, "", ""

    VIAS = {"key": "as root by its ssh KEY", "sudo": "with its login from secrets.yaml and its PASSWORD, then sudo",
            "password": "with its login from secrets.yaml and its PASSWORD",
            "routeros": "with its login from secrets.yaml and its PASSWORD, over ssh",
            "esxi": "as root with its PASSWORD from secrets.yaml, over ssh",
            "openwrt": "as root with its PASSWORD from secrets.yaml, over ssh"}

    def logins(self, ip: str) -> list:
        """How lanowl ITSELF logs in to `ip`, every day: a fix that turns off password logins
        would quietly stop its own reads (a fix for an sshd that does not know the morning review
        logs in there with a password locks lanowl out)."""
        a, out = self.a, []
        h = next((x for x in (getattr(a.hostlog, "hosts", None) or []) if x.ip == ip), None)
        if h is not None:
            out.append(f"its log watcher, always connected: as {h.user} by its ssh KEY")
        for what, items in (("the morning security review", a.exposure.hosts),
                            ("the configuration snapshot", getattr(a, "configwatch", None) and a.configwatch.machines),
                            ("the update check", a.updates.hosts)):
            for m in items or []:
                if m.get("ip") == ip:
                    out.append(f"{what}: {self.VIAS.get(m.get('via'), m.get('via'))}")
        return out

    def context(self, f: dict, facts: str, src: str) -> str:
        who = f"{f.get('name') or ''} ({f.get('ip')})" if f.get("ip") else (f.get("source") or "")
        lines = [f"THE PROBLEM (from {src}):",
                 f"  machine: {who}",
                 f"  check: {f.get('check')} · severity: {f.get('severity')}",
                 f"  {f.get('title')}",
                 f"  evidence: {f.get('evidence') or '—'}"]
        if f.get("fix") or f.get("suggestion"):
            lines.append(f"  the review's one-line direction: {f.get('fix') or f.get('suggestion')}")
        if f.get("why"):
            lines.append(f"  likely cause: {f['why']}")
        lg = self.logins(f.get("ip") or "")
        if lg:
            lines += ["", "HOW THE MONITOR ITSELF LOGS IN TO THIS MACHINE every day (a fix that stops one of these "
                      "stops the monitor's own reads there — say so in 'careful', and what to change in its "
                      "config.yaml, e.g. a login by key instead of a password):"]
            lines += [f"  {x}" for x in lg]
        lines += ["", "WHAT THE MACHINE LOOKED LIKE THIS MORNING (read-only, as read by the monitor):",
                  facts or "(nothing read)", "", "Write the fix as JSON."]
        return "\n".join(lines)

    # --- writing ------------------------------------------------------------------------------
    def start(self, key: str, reason: str = "the owner") -> dict:
        if not self.enabled:
            return {"ok": False, "error": "fixes are off"}
        f, _, _ = self.finding(key)
        if f is None:
            return {"ok": False, "error": "no such finding — it may have gone since"}
        if self.a.no_llm:
            return {"ok": False, "error": "the local model is switched off"}
        if key != self.writing and key not in self.queue:
            # the owner's press goes first; the morning's own list after it
            if reason == "the owner":
                self.queue.insert(0, key)
            else:
                self.queue.append(key)
        if self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._work())
        return {"ok": True, "queued": key != self.writing}

    async def _work(self):
        while self.queue:
            key = self.queue.pop(0)
            self.writing = key
            try:
                await self.write(key)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("fixes: writing %s failed", key)
                self.rec["items"][key] = {"ts": time.time(), "status": "failed",
                                          "error": "it failed — see lanowl's log"}
                self._save()
            finally:
                self.writing = None

    async def write(self, key: str) -> Optional[dict]:
        f, facts, src = self.finding(key)
        if f is None:
            return None
        t0 = time.time()
        v = None
        if not self.a.no_llm:
            async with self.a.model_turn():
                v = await self.a.agent.ask_json(SYSTEM, self.context(f, facts, src), timeout_s=self.timeout_s)
        fix = self.normalise(v)
        if fix is None:
            self.rec["items"][key] = {"ts": time.time(), "status": "failed", "sig": sig(f),
                                      "error": "the local model is switched off" if self.a.no_llm
                                      else "the model gave no usable fix"}
        else:
            self.rec["items"][key] = {"ts": time.time(), "status": "ready", "sig": sig(f), "fix": fix}
        self._save()
        log.info("fixes: %s %s in %.0fs", key, "written" if fix else "not written", time.time() - t0)
        return fix

    @staticmethod
    def normalise(v) -> Optional[dict]:
        if not isinstance(v, dict) or not isinstance(v.get("steps"), list):
            return None
        steps = []
        for s in v["steps"][:10]:
            if isinstance(s, dict) and (s.get("do") or s.get("commands")):
                steps.append({"where": words(s.get("where"), 300), "do": words(s.get("do"), 800),
                              "commands": str(s.get("commands") or "").strip()[:3000]})
        if not steps:
            return None
        return {"summary": words(v.get("summary"), 300), "steps": steps,
                "undo": str(v.get("undo") or "").strip()[:3000],
                "check": str(v.get("check") or "").strip()[:1000],
                "careful": str(v.get("careful") or "").strip()[:1000]}

    def after_review(self):
        """After the morning's security review: the open findings worth fixing get theirs, one
        after the other, while the model is idle. One already written for the same words is kept."""
        if not self.enabled or self.a.no_llm:
            return
        x = self.a.exposure
        for f in x.rec.get("findings") or []:
            if f["severity"] not in AUTO or f["key"] in (x.rec.get("dismissed") or {}):
                continue
            have = self.rec["items"].get(f["key"]) or {}
            if have.get("status") == "ready" and have.get("sig") == sig(f):
                continue
            self.start(f["key"], "the morning review")

    # --- reading ------------------------------------------------------------------------------
    def view(self) -> dict:
        out = {}
        for k, v in self.rec["items"].items():
            f, _, _ = self.finding(k)
            out[k] = {**v, "stale": bool(f is not None and v.get("sig") and v["sig"] != sig(f)),
                      "gone": f is None}
        for k in self.queue:
            out.setdefault(k, {})["state"] = "queued"
        if self.writing:
            out.setdefault(self.writing, {})["state"] = "writing"
        return {"enabled": self.enabled, "items": out}
