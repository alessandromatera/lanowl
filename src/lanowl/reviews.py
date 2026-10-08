"""The model's scheduled looks at the network, beyond the hourly audit.

On a healthy network the hourly audit mostly ends "all healthy, nothing to tell", using a
small part of the context it has: the model is idle, not limited. These looks give it more to
do, in the same shape as the morning security review (exposure.py):

  - code COLLECTS facts, read-only, and never judges them;
  - the MODEL reads them and names each thing worth saying with one of a fixed set of checks,
    so the same problem keeps the same key from one run to the next — what lets the owner
    dismiss it once;
  - nothing pages. What is new and at least `warning` rides the next digest, once (`news` /
    `told`); everything is on the dashboard, in the weekly review and in `lanowl_records`.

    drift.py         slowly changing — a week of the sweep's own samples
    configwatch.py   what changed in the machines' configurations (events, not
                             conditions: it uses `Review` alone)

`Review` is the scheduling, the record and the model call; `FindingsReview` adds findings that
are re-derived on every run, with dismissals.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional

from .report import _html, label

log = logging.getLogger("lanowl.reviews")

SEVERITIES = ("critical", "high", "warning", "info")
# what reaches a digest: the owner's "worth a look", not every note the model keeps
DIGEST_FLOOR = ("critical", "high", "warning")


def today_at(hhmm: str, now: float) -> float:
    h, _, m = str(hhmm or "0:0").partition(":")
    lt = time.localtime(now)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, int(h or 0), int(m or 0), 0, 0, 0, -1))


def words(text, n: int) -> str:
    """One line, at most n characters."""
    return " ".join(str(text or "").split())[:n]


def clip(text, n: int) -> str:
    """One line, cut at a word with "…" when longer than n."""
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[:n].rsplit(" ", 1)[0].rstrip(",;:") + "…"


class Review:
    """One scheduled look: when, the record, the model.

    `NAME` is both the record's name and the config section. A run is claimed when it starts
    (`rec["last"]`), so a slow one never starts twice and a restart does not repeat it."""
    NAME = ""
    TITLE = ""
    ICON = "•"

    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get(self.NAME) or {}
        self.c = c
        self.enabled = bool(c.get("enabled", False))
        self.at = str(c.get("at") or "")                  # daily at this time...
        self.every_s = float(c.get("every_h") or 0) * 3600   # ...or every N hours
        self.timeout_s = float(c.get("model_timeout_s", 600))
        self._task: Optional[asyncio.Task] = None
        try:
            self.rec = auditor.state.load_record(self.NAME) or {}
        except Exception:
            log.warning("%s: record unreadable, starting empty", self.NAME, exc_info=True)
            self.rec = {}
        for k, dflt in self.DEFAULTS().items():
            self.rec.setdefault(k, dflt)

    @staticmethod
    def DEFAULTS() -> dict:
        return {"last": 0.0, "last_done": 0.0, "error": "", "told": []}

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(self.NAME, self.rec)
        except Exception as e:
            log.warning("%s: record not saved: %s", self.NAME, e)

    # --- when -------------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def due(self, now: float) -> bool:
        if not self.enabled or self.running:
            return False
        last = float(self.rec.get("last") or 0)
        if self.every_s:
            # not in the first ten minutes after a start: the sweep, the router and the model
            # have enough to do then
            return now - last >= self.every_s and now - self.a._started > 600
        at = today_at(self.at or "07:00", now)
        return now >= at and last < at

    def start(self, reason: str) -> bool:
        if not self.enabled or self.running:
            return False
        self.rec["last"] = time.time()
        self._task = asyncio.ensure_future(self._guarded(reason))
        return True

    async def _guarded(self, reason: str):
        try:
            await self.run(reason)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("%s: the run failed", self.NAME)
            self.rec["error"] = "the run failed — see lanowl's log"
            self._save()

    async def run(self, reason: str):     # pragma: no cover - each review's own
        raise NotImplementedError

    # --- the model --------------------------------------------------------------------------
    def model_off(self) -> str:
        """Why the model cannot be asked, or "" when it can."""
        if self.a.no_llm:
            return "no model (--no-llm)" if self.a._no_llm_cli else "the local model is switched off"
        return ""

    async def ask(self, system: str, context: str) -> Optional[dict]:
        """One JSON answer, in the model's turn (the audit, questions and the other reviews
        wait for each other). None: no model, or no usable answer."""
        if self.model_off():
            return None
        async with self.a.model_turn():
            t0 = time.time()
            v = await self.a.agent.ask_json(system, context, timeout_s=self.timeout_s)
        log.info("%s: the model %s in %.0fs", self.NAME, "answered" if isinstance(v, dict) else
                 "gave no usable answer", time.time() - t0)
        return v if isinstance(v, dict) else None

    # --- the digest -------------------------------------------------------------------------
    def news(self) -> list:
        """Items worth a digest that no digest has carried yet: [(key, line)]."""
        return []

    def mark_told(self, keys) -> None:
        if not keys:
            return
        told = [k for k in self.rec.get("told") or [] if k not in keys] + list(keys)
        self.rec["told"] = told[-400:]
        self._save()


class FindingsReview(Review):
    """Findings re-derived on every run, each with a stable key (`<PREFIX>:<anchor>:<check>`).

    A finding the last run did not raise is gone. The owner's dismissal keeps one out of the
    digest and the dashboard's open list until undone — or until the problem is gone: forgotten
    after MISSES_TO_FORGET runs without it, so it can come back. Told keys follow the same rule:
    a finding that went away and came back is news again."""
    PREFIX = ""
    CHECKS: dict = {}
    MAX_SEVERITY = "high"          # these never page; "critical" is the exposure review's word
    MISSES_TO_FORGET = 3
    DIGEST = DIGEST_FLOOR          # the severities that ride a digest

    @staticmethod
    def DEFAULTS() -> dict:
        return {"last": 0.0, "last_done": 0.0, "error": "", "told": [], "findings": [],
                "dismissed": {}, "summary": "", "reviewed": 0.0}

    def key(self, f: dict) -> str:
        return f"{self.PREFIX}:{f['anchor']}:{f['check']}"

    def anchor(self, f: dict, facts: dict) -> str:   # pragma: no cover - each review's own
        """What the finding is about, as a stable token ("" = drop the finding)."""
        raise NotImplementedError

    def normalise(self, raw, facts: dict) -> list:
        """The model's findings held to the rules: a known check (else "other"), a known
        severity no higher than MAX_SEVERITY, an anchor the facts know — one per key, the worst."""
        by: dict = {}
        top = SEVERITIES.index(self.MAX_SEVERITY)
        for f in raw if isinstance(raw, list) else []:
            if not isinstance(f, dict):
                continue
            chk = str(f.get("check") or "").strip().lower()
            chk = chk if chk in self.CHECKS else "other"
            sev = str(f.get("severity") or "").strip().lower()
            sev = sev if sev in SEVERITIES else "warning"
            if SEVERITIES.index(sev) < top:
                sev = self.MAX_SEVERITY
            anchor = self.anchor(f, facts)
            if not anchor:
                continue
            e = {"anchor": anchor, "check": chk, "severity": sev,
                 "title": words(f.get("title") or self.CHECKS[chk], 160),
                 "evidence": words(f.get("evidence"), 400),
                 "why": words(f.get("why"), 300),
                 "suggestion": words(f.get("suggestion"), 240)}
            e.update(self.extra(f, facts, e))
            e["key"] = self.key(e)
            old = by.get(e["key"])
            if old is None or SEVERITIES.index(sev) < SEVERITIES.index(old["severity"]):
                by[e["key"]] = e
        return sorted(by.values(), key=lambda x: (SEVERITIES.index(x["severity"]), x["key"]))

    def extra(self, f: dict, facts: dict, e: dict) -> dict:
        """More fields for one finding (its device's name and address, its entities)."""
        return {}

    def keep(self, findings: list, summary: str, err: str):
        """A run's outcome: no usable answer keeps the last findings and says why."""
        self.rec["error"] = err
        if findings is not None:
            self.rec["findings"] = findings
            self.rec["summary"] = words(summary, 600)
            self.rec["reviewed"] = time.time()
            self._forget_gone()
        self.rec["last_done"] = time.time()
        self._save()

    def _forget_gone(self):
        keys = {f["key"] for f in self.rec["findings"]}
        for k, d in list(self.rec["dismissed"].items()):
            d["missed"] = 0 if self.matches(k, d) else int(d.get("missed") or 0) + 1
            if d["missed"] >= self.MISSES_TO_FORGET:
                del self.rec["dismissed"][k]
        # told and gone: news again if it comes back
        self.rec["told"] = [k for k in self.rec.get("told") or [] if k in keys]

    def matches(self, key: str, d: dict) -> bool:
        """Does the dismissal `key` still hold for one of the current findings?"""
        return any(f["key"] == key for f in self.rec["findings"])

    def is_dismissed(self, f: dict) -> Optional[dict]:
        return self.rec["dismissed"].get(f["key"])

    # --- the owner --------------------------------------------------------------------------
    def dismiss(self, key: str, note: str = "") -> dict:
        f = next((x for x in self.rec["findings"] if x["key"] == key), None)
        if f is None:
            return {"ok": False, "error": "no such finding — it may have gone since"}
        self.rec["dismissed"][key] = {"ts": time.time(), "note": words(note, 300), "missed": 0,
                                      **self.dismiss_extra(f)}
        self._save()
        log.info("%s: %s dismissed%s", self.NAME, key, f" ({note!r})" if note else "")
        return {"ok": True}

    def dismiss_extra(self, f: dict) -> dict:
        return {}

    def undismiss(self, key: str) -> dict:
        if self.rec["dismissed"].pop(key, None) is None:
            return {"ok": False, "error": "it was not dismissed"}
        self._save()
        return {"ok": True}

    # --- reading ----------------------------------------------------------------------------
    def open_findings(self) -> list:
        return [f for f in self.rec["findings"] if not self.is_dismissed(f)]

    def news(self) -> list:
        told = set(self.rec.get("told") or [])
        return [(f["key"], self.digest_line(f)) for f in self.open_findings()
                if f["severity"] in self.DIGEST and f["key"] not in told]

    def digest_line(self, f: dict) -> str:
        who = label(f.get("name"), f.get("ip")) if f.get("ip") else ""
        return (f"• {_html(who + ': ' if who else '')}{_html(f['title'])}"
                + (f"\n   <i>{_html(clip(f['evidence'], 200))}</i>" if f.get("evidence") else ""))

    def view(self) -> dict:
        d = self.rec["dismissed"]
        return {"enabled": self.enabled, "running": self.running,
                "last": self.rec.get("last_done") or None, "reviewed": self.rec.get("reviewed") or None,
                "summary": self.rec.get("summary") or "", "error": self.rec.get("error") or "",
                "findings": [{**f, **({"dismissed": self.is_dismissed(f)} if self.is_dismissed(f) else {})}
                             for f in self.rec["findings"]],
                "dismissed_n": len(d)}

    def weekly_lines(self) -> list:
        if not self.enabled or not self.rec.get("reviewed"):
            return []
        fs = self.open_findings()
        if not fs:
            return [f"{self.ICON} {self.TITLE}: nothing the owl found worth a look."]
        w = fs[0]
        who = label(w.get("name"), w.get("ip")) + " — " if w.get("ip") else ""
        return [f"{self.ICON} {self.TITLE}: {len(fs)} open, the worst {w['severity']}: {who}{w['title']}"]


def actions_done(a, since: float, ips=None) -> list:
    """What ran on the machines since `since` — updates, reboots, restarts — in words: a change
    the owner made is the first explanation of a change seen."""
    from .actions import CATALOG
    out = []
    for p in getattr(a.actions, "items", None) or []:
        t = p.get("done_ts") or p.get("ts") or 0
        if t < since or p.get("status") not in ("done", "failed", "running") or p.get("action") == "investigate":
            continue
        if ips is not None and p.get("ip") not in ips:
            continue
        out.append(f"{time.strftime('%a %d/%m %H:%M', time.localtime(t))} — "
                   f"{CATALOG.get(p['action'], p['action'])}"
                   + (f" on {label(p.get('name'), p['ip'])}" if p.get("ip") else "")
                   + f": {p.get('status')}" + (" (the owner's)" if p.get("owner") else ""))
    return out[-30:]


_TOKEN = re.compile(r"[^a-z0-9_.-]+")


def token(text: str, n: int = 48) -> str:
    """A model-given name as a key part: lower case, safe characters only."""
    return _TOKEN.sub("-", str(text or "").strip().lower()).strip("-")[:n]
