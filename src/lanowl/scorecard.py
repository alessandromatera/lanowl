"""The model's track record: each diagnosis checked against what really happened.

How far can the model be trusted? Not by its reputation: by its record. On a quiet network it
rarely makes an incident diagnosis; what it does make, every hour, is a cause and a suggestion
for each open issue, e.g. "Remote router: site down — fault at the site's power/ISP"
several hours in a row. Those are the claims graded here:

  - a CLAIM is one problem episode of one device: the first cause the model gave for it (and its
    last, if it changed its mind), at warning or worse — re-stating it hourly is one claim;
  - the episode is over when neither the monitor nor the model has raised the device for an
    hour; then, half an hour later (the router's log has caught up), the model is asked again,
    with hindsight and its read-only tools — the device's ups and downs, what else went down at
    the same minutes, the internet, what ran on it, the owner's notes — whether the cause it
    named is what the evidence shows: right, partly, wrong, or can't tell;
  - the OWNER's word beats the grader's: one tap on the dashboard (right / partly / wrong).
    The owner often knows what nothing recorded — that a remote router had lost its Wi-Fi
    uplink, not its power;
  - totals by kind of problem on Ask's model side, a line in the weekly review, the whole list
    in `lanowl_records` topic=scorecard.

A grade is a fact for deciding, later, what the model may do by itself; this changes nothing it
may do now.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Optional

from . import wanexplain
from .report import label
from .reviews import actions_done, words

log = logging.getLogger("lanowl.scorecard")

RECORD = "scorecard"
VERDICTS = ("right", "partly", "wrong", "cant_tell")
OWNER = ("right", "partly", "wrong")
CLAIM_SEV = ("critical", "high", "warning")
QUIET_S = 3600          # nobody raised it for this long: the episode is over...
SETTLE_S = 1800         # ...and graded this much later
LONG_S = 3 * 86400      # an episode still open after three days is graded "so far"
KEEP_DAYS = 90
KINDS = {"down": "a device down", "degraded": "a service failing", "group": "several devices at once",
         "wan": "the internet", "wan-path": "on the backup line", "observer": "lanowl's own view",
         "model": "seen by the model alone"}

SYSTEM = """You check, WITH HINDSIGHT, a diagnosis the monitor's model made earlier about a problem \
on a family's home network. The problem is over now (or has gone on for days). Below: what the \
model said at the time, and what is known now — the device's ups and downs, the other devices that \
went down at the same minutes, the internet, what was run on it, what the owner told the monitor. \
You may also use the read-only tools (the router's log, a device's history, lanowl's records).

Judge only the CAUSE it named (and whether its advice fitted that cause):
  "right"     = the evidence now shows that cause;
  "partly"    = the right area but a wrong detail, or the right cause with the wrong advice;
  "wrong"     = the evidence shows a different cause;
  "cant_tell" = nothing recorded confirms or contradicts it — then say what WOULD have.
Be strict: plausible is not confirmed, and "it came back by itself" alone proves no cause. The \
owner's notes count as evidence.

Reply with ONLY this JSON object, no prose, no code fence:
{"verdict": "right"|"partly"|"wrong"|"cant_tell",
 "why": "<two sentences at most>",
 "evidence": "<the facts that decide it, quoted; empty for cant_tell>"}"""


def _hm(ts: float) -> str:
    return time.strftime("%a %d/%m %H:%M", time.localtime(ts))


class Scorecard:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("scorecard") or {}
        self.enabled = bool(c.get("enabled", True))
        self.max_per_day = int(c.get("max_per_day", 12))
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("scorecard: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        self.rec.setdefault("claims", [])
        self.rec.setdefault("graded", {})        # day -> how many the model graded
        self._task: Optional[asyncio.Task] = None

    def _save(self):
        if not self.a._persist_alerts:
            return
        cut = time.time() - KEEP_DAYS * 86400
        self.rec["claims"] = [c for c in self.rec["claims"] if c["first"]["ts"] >= cut][-600:]
        days = sorted(self.rec["graded"])[-10:]
        self.rec["graded"] = {d: self.rec["graded"][d] for d in days}
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("scorecard: record not saved: %s", e)

    def _get(self, cid: str) -> Optional[dict]:
        return next((c for c in self.rec["claims"] if c["id"] == cid), None)

    # --- claims, from every audit ---------------------------------------------------------------
    def note_audit(self, llm: Optional[dict], report: Optional[dict], now: Optional[float] = None):
        """An audit's issues: a new claim per device with a new problem, the last words on one
        still going, and the episodes nobody raises any more closed."""
        if not self.enabled or not isinstance(llm, dict):
            return
        now = now or time.time()
        det = {}
        for i in (report or {}).get("issues") or []:
            ip = str(i.get("ip") or "")
            if ip and ip != "-":
                det.setdefault(ip, i)
        raised = set()
        for i in llm.get("issues") or []:
            if not isinstance(i, dict):
                continue
            sev = str(i.get("severity") or "").lower()
            ip = str(i.get("ip") or "").strip()
            cause = words(i.get("root_cause"), 400)
            if sev not in CLAIM_SEV or not ip or ip == "-" or not cause:
                continue
            raised.add(ip)
            said = {"ts": now, "cause": cause, "rec": words(i.get("recommendation"), 300), "sev": sev}
            c = next((x for x in self.rec["claims"] if x["ip"] == ip and x.get("open")), None)
            if c is not None:
                c["seen"] = int(c.get("seen") or 1) + 1
                c["quiet_since"] = None
                if said["cause"] != c["last"]["cause"]:
                    c["last"] = said
                else:
                    c["last"]["ts"] = now
                continue
            d = det.get(ip) or {}
            dev = self.a.inv.get(ip)
            self.rec["claims"].append({
                "id": uuid.uuid4().hex[:10], "ip": ip,
                "device": dev.name if dev is not None else str(i.get("device") or ip),
                "kind": d.get("kind") or "model", "first": said, "last": dict(said), "seen": 1,
                "open": True, "quiet_since": None, "closed": None, "grade": None, "owner": None})
        for c in self.rec["claims"]:
            if not c.get("open") or c["ip"] in raised:
                continue
            if c["ip"] in det:
                c["quiet_since"] = None          # the monitor still sees it: still the same episode
                continue
            c["quiet_since"] = c.get("quiet_since") or now
            if now - c["quiet_since"] >= QUIET_S:
                c["open"], c["closed"] = False, c["quiet_since"]
        self._save()

    # --- grading ------------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def due_claim(self, now: float) -> Optional[dict]:
        for c in self.rec["claims"]:
            if c.get("grade") or c.get("grading_failed", 0) >= 2:
                continue
            if (not c.get("open") and c.get("closed") and now - c["closed"] >= SETTLE_S) or \
                    (c.get("open") and now - c["first"]["ts"] >= LONG_S):
                return c
        return None

    def tick(self, now: float):
        """From the loop: one grading at a time, a few a day, never with the model off."""
        if not self.enabled or self.running or self.a.no_llm:
            return
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        if int(self.rec["graded"].get(day) or 0) >= self.max_per_day:
            return
        c = self.due_claim(now)
        if c is not None:
            self._task = asyncio.ensure_future(self._guarded(c["id"]))

    async def _guarded(self, cid: str):
        try:
            await self.grade(cid)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("scorecard: grading %s failed", cid)
            c = self._get(cid)
            if c is not None:
                c["grading_failed"] = int(c.get("grading_failed") or 0) + 1
                self._save()

    def context(self, c: dict, now: float) -> str:
        a, ip = self.a, c["ip"]
        start = c["first"]["ts"]
        end = c.get("closed") or now
        lo, hi = start - 6 * 3600, end + 3600
        lines = [f"NOW: {_hm(now)}",
                 f"THE DEVICE: {label(c['device'], ip)} — the problem: {KINDS.get(c['kind'], c['kind'])}",
                 f"WHAT THE MODEL SAID first, {_hm(start)} ({c['first']['sev']}): cause: {c['first']['cause']}"
                 + (f" — advice: {c['first']['rec']}" if c['first'].get('rec') else "")]
        if c["last"]["cause"] != c["first"]["cause"]:
            lines.append(f"...and last, {_hm(c['last']['ts'])}: cause: {c['last']['cause']}"
                         + (f" — advice: {c['last']['rec']}" if c['last'].get('rec') else ""))
        lines.append(f"It was raised in {c.get('seen', 1)} audit(s); "
                     + (f"nobody raised it after {_hm(end)}." if c.get("closed") else "it is STILL going."))
        lines += ["", f"ITS UPS AND DOWNS {_hm(lo)} – {_hm(hi)}:"]
        lb = [e for e in a.state.logbook(lo, ip=ip, limit=200) if e["ts"] <= hi]
        lines += [f"  {_hm(e['ts'])} {e['kind']}" + (f" (after {round(e['down_for'] / 60)} min down)"
                                                     if e.get("down_for") else "")
                  for e in sorted(lb, key=lambda e: e["ts"])] or ["  none recorded (it may have been answering, "
                                                                  "slow, or a service of it failing)"]
        downs = [e["ts"] for e in lb if e["kind"] == "down"]
        if downs:
            near = {}
            for e in a.state.logbook(lo, limit=2000):
                if e["ip"] != ip and e["kind"] == "down" and any(abs(e["ts"] - t) <= 600 for t in downs):
                    near.setdefault(e["ip"], e)
            lines += ["", "OTHER DEVICES THAT WENT DOWN within 10 minutes of it:"]
            lines += [f"  {_hm(e['ts'])} {label(e.get('name'), e['ip'])}" for e in list(near.values())[:15]] \
                or ["  none"]
        wm = [e for e in wanexplain.moments(a.state, lo) if e["ts"] <= hi]
        lines += ["", "THE INTERNET in that window:"]
        lines += [f"  {_hm(e['ts'])} {e['kind']} for {round(e['s'])} s" for e in wm[:15]] or ["  no outage recorded"]
        ran = actions_done(a, lo, ips={ip})
        lines += ["", "WHAT RAN ON IT (the owner's or approved actions):"]
        lines += [f"  {x}" for x in ran if x] or ["  nothing"]
        sec = [x for x in a.seclog.since(lo) if x.get("ip") == ip]
        if sec:
            lines += ["", "SECURITY EVENTS for it:"]
            lines += [f"  {_hm(x['ts'])} {x['title']}" + (f" — the owner: {a.seclog.owner_words(x)}"
                                                         if x.get("handled") else "") for x in sec[:6]]
        lines += ["", "Grade it: the JSON."]
        return "\n".join(lines)

    async def grade(self, cid: str) -> Optional[dict]:
        c = self._get(cid)
        if c is None or self.a.no_llm:
            return None
        now = time.time()
        ctx = self.context(c, now)
        async with self.a.model_turn():
            t0 = time.time()
            v = await self.a.agent.run_audit(SYSTEM, ctx)
        verdict = str((v or {}).get("verdict") or "").strip().lower().replace("'", "").replace(" ", "_")
        if verdict not in VERDICTS:
            c["grading_failed"] = int(c.get("grading_failed") or 0) + 1
            self._save()
            log.info("scorecard: %s (%s) — no usable grade", c["device"], cid)
            return None
        c["grade"] = {"ts": time.time(), "verdict": verdict, "why": words(v.get("why"), 400),
                      "evidence": words(v.get("evidence"), 500), "so_far": bool(c.get("open"))}
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        self.rec["graded"][day] = int(self.rec["graded"].get(day) or 0) + 1
        self._save()
        log.info("scorecard: %s (%s) graded %s in %.0fs", c["device"], cid, verdict, time.time() - t0)
        return c["grade"]

    # --- the owner ----------------------------------------------------------------------------
    def owner_says(self, cid: str, verdict: str, note: str = "") -> dict:
        c = self._get(cid)
        if c is None:
            return {"ok": False, "error": "no such diagnosis — it may be older than 90 days"}
        verdict = str(verdict or "").lower()
        if verdict == "clear":
            c["owner"] = None
        elif verdict in OWNER:
            c["owner"] = {"ts": time.time(), "verdict": verdict, "note": words(note, 300)}
        else:
            return {"ok": False, "error": "right, partly, wrong or clear"}
        self._save()
        log.info("scorecard: the owner says %s on %s (%s)", verdict, c["device"], cid)
        return {"ok": True}

    # --- reading ------------------------------------------------------------------------------
    @staticmethod
    def final(c: dict) -> str:
        """The owner's word if they gave one, else the grader's; "" while ungraded."""
        if c.get("owner"):
            return c["owner"]["verdict"]
        return (c.get("grade") or {}).get("verdict") or ""

    def totals(self, since: float = 0.0) -> dict:
        out: dict = {}
        for c in self.rec["claims"]:
            if c["first"]["ts"] < since:
                continue
            for k in ("all", c["kind"]):
                t = out.setdefault(k, {"claims": 0, "graded": 0, "right": 0, "partly": 0, "wrong": 0,
                                       "cant_tell": 0, "owner": 0, "owner_disagreed": 0})
                t["claims"] += 1
                f = self.final(c)
                if f:
                    t["graded"] += 1
                    t[f] += 1
                if c.get("owner"):
                    t["owner"] += 1
                    g = (c.get("grade") or {}).get("verdict")
                    if g and g != c["owner"]["verdict"]:
                        t["owner_disagreed"] += 1
        return out

    def view(self) -> dict:
        cs = sorted(self.rec["claims"], key=lambda c: -c["first"]["ts"])
        return {"enabled": self.enabled, "running": self.running, "kinds": KINDS,
                "totals": self.totals(), "claims": cs[:40]}

    def weekly(self, now: Optional[float] = None) -> dict:
        now = now or time.time()
        week = [c for c in self.rec["claims"] if (c.get("grade") or {}).get("ts", 0) >= now - 7 * 86400
                or (c.get("owner") or {}).get("ts", 0) >= now - 7 * 86400]
        t = {v: sum(1 for c in week if self.final(c) == v) for v in VERDICTS}
        return {"checked_this_week": len(week), **t,
                "owner_corrected": sum(1 for c in week if c.get("owner") and (c.get("grade") or {}).get("verdict")
                                       and c["owner"]["verdict"] != c["grade"]["verdict"]),
                "all_time": self.totals().get("all") or {}}

    def weekly_lines(self) -> list:
        if not self.enabled:
            return []
        w = self.weekly()
        if not w["checked_this_week"]:
            return []
        return [f"🎯 The model's diagnoses checked this week: {w['checked_this_week']} — {w['right']} right, "
                f"{w['partly']} partly, {w['wrong']} wrong, {w['cant_tell']} can't tell"
                + (f" (you corrected {w['owner_corrected']})" if w["owner_corrected"] else "")]

    def records(self, since: float, limit: int) -> dict:
        cs = [c for c in self.rec["claims"] if c["first"]["ts"] >= since]
        return {"totals_all_time": self.totals(), "kinds": KINDS,
                "claims": [{"device": label(c["device"], c["ip"]), "kind": KINDS.get(c["kind"], c["kind"]),
                            "first": {**c["first"], "ts": _hm(c["first"]["ts"])},
                            **({"last": {**c["last"], "ts": _hm(c["last"]["ts"])}}
                               if c["last"]["cause"] != c["first"]["cause"] else {}),
                            "episode": ("still open" if c.get("open") else f"over at {_hm(c['closed'])}"
                                        if c.get("closed") else "?"),
                            "grade": c.get("grade"), "owner": c.get("owner")}
                           for c in sorted(cs, key=lambda c: -c["first"]["ts"])[:limit]]}
