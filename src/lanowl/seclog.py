"""What the logs showed about access, kept until the owner has seen it.

A security event from the logs (a burst of failed logins, a login from outside, a connection
flood, or the model's read of the same lines) must not vanish because newer verdicts pushed it
out of memory, or because the process restarted. And it must reach the dashboard, not only
Telegram. So every such event is an ITEM here, in the SQLite record `seclog`:
  - it stays in What matters until the owner marks it handled — one button, a quick pick
    ("It was me" / "Fixed") and a note if they like. A log line is an event, not a
    condition: nothing can "fix" it, so it never leaves on its own;
  - handled, it sits under Handled for a week, with the owner's words;
  - the record keeps 90 days, for Ask and the weekly review;
  - a rule's page and the model's read of the same lines are ONE item (the model's words are
    attached to it), and a repeat of an item still open (same key) counts on it instead of
    adding a row.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Optional

log = logging.getLogger("lanowl.seclog")

RECORD = "seclog"
KEEP_DAYS = 90
HANDLED_SHOWN_DAYS = 7
PICKS = {"me": "It was me", "fixed": "Fixed"}
_RANK = {"critical": 2, "warning": 1}


def rank(sev: str) -> int:
    return _RANK.get(str(sev or "").lower(), 0)


class SecLog:
    def __init__(self, state):
        self.state = state
        rec = None
        try:
            rec = state.load_record(RECORD)
        except Exception:
            log.warning("seclog: the record could not be read — starting empty", exc_info=True)
        self.rec = rec if isinstance(rec, dict) and isinstance(rec.get("items"), list) else {"items": []}
        self.fresh = rec is None             # never saved: the first start with this module

    def seed(self, events: list, ip_of) -> int:
        """The first start only: the log checks' security problems of the last 24 h, from the
        events table — the Security tab listed them (for 24 h) until this deploy, and they must
        not vanish with it. `ip_of(source)` names the machine. The rules' pages were never
        recorded as anything but Telegram text, so they are not here: Logbook → Telegram has them."""
        if not self.fresh:
            return 0
        self.fresh = False
        n = 0
        for e in sorted(events, key=lambda e: e["ts"]):
            try:
                f = json.loads(e["detail"])
            except (TypeError, ValueError):
                continue
            src = str(f.get("source") or "")
            kind = f.get("kind") or ("security" if src.startswith("host log") else "health")
            if not f.get("problem") or kind != "security" or f.get("severity") not in ("critical", "warning"):
                continue
            self.add(source=src, ip=ip_of(src), sev=f["severity"], title=f.get("summary") or "",
                     detail=f.get("detail") or "", by="model", ts=e["ts"])
            n += 1
        self._save()
        log.info("seclog: first start — %d security problem(s) of the last 24 h carried over", n)
        return n

    # --- written by the watchers ----------------------------------------------------------
    def add(self, *, source: str, ip: str, sev: str, title: str, detail: str = "",
            by: str = "rule", key: str = "", paged: bool = True,
            ts: Optional[float] = None) -> str:
        """One event the logs showed. Returns its id. An item still OPEN under the same key
        (the same rule, host and source) counts the repeat instead: one incident, one row."""
        now = ts or time.time()
        sev = "critical" if str(sev).lower() == "critical" else "warning"
        if key:
            it = next((x for x in reversed(self.rec["items"])
                       if x.get("key") == key and not x.get("handled")), None)
            if it is not None:
                it["count"] = int(it.get("count") or 1) + 1
                it["last"] = now
                it["title"], it["detail"] = str(title)[:300], str(detail)[:1500]
                if rank(sev) > rank(it.get("sev")):
                    it["sev"] = sev
                it["paged"] = bool(it.get("paged")) or paged
                self._save()
                return it["id"]
        it = {"id": uuid.uuid4().hex[:10], "ts": now, "source": source, "ip": ip, "sev": sev,
              "title": str(title)[:300], "detail": str(detail)[:1500], "by": by,
              "key": key, "paged": paged, "count": 1, "last": now, "model": None, "handled": None}
        self.rec["items"].append(it)
        self._save()
        return it["id"]

    def attach(self, item_id: str, sev: str, summary: str, detail: str) -> bool:
        """The model's read of the lines a rule already paged for: said on the same row."""
        it = self._get(item_id)
        if it is None:
            return False
        sev = str(sev or "").lower()
        it["model"] = {"ts": time.time(), "sev": sev,
                       "summary": str(summary)[:300], "detail": str(detail)[:1500]}
        if rank(sev) > rank(it.get("sev")):
            it["sev"] = sev                  # the model saw worse than the rule: the row says so
        self._save()
        return True

    def sev_of(self, item_id: str) -> str:
        it = self._get(item_id)
        return it["sev"] if it else ""

    # --- the owner --------------------------------------------------------------------------
    def handle(self, item_id: str, pick: str = "", note: str = "", by: str = "dashboard") -> dict:
        it = self._get(item_id)
        if it is None:
            return {"ok": False, "error": "no such item — it may be older than 90 days"}
        pick = pick if pick in PICKS else ""
        note = " ".join(str(note or "").split())[:300]
        it["handled"] = {"ts": time.time(), "pick": pick, "note": note, "by": by}
        self._save()
        log.info("seclog: %s handled (%s%s) — %s", item_id, PICKS.get(pick, "no pick"),
                 f", {note!r}" if note else "", it["title"][:80])
        return {"ok": True}

    def unhandle(self, item_id: str) -> dict:
        it = self._get(item_id)
        if it is None or not it.get("handled"):
            return {"ok": False, "error": "it was not marked handled"}
        it["handled"] = None
        self._save()
        log.info("seclog: %s back to open — %s", item_id, it["title"][:80])
        return {"ok": True}

    # --- read -------------------------------------------------------------------------------
    def view(self, now: Optional[float] = None) -> dict:
        """Open items, newest first; handled ones of the last week, newest handled first."""
        now = now or time.time()
        items = self.rec["items"]
        open_ = [x for x in items if not x.get("handled")]
        done = [x for x in items if x.get("handled")
                and now - x["handled"]["ts"] < HANDLED_SHOWN_DAYS * 86400]
        return {"open": sorted(open_, key=lambda x: x.get("last") or x["ts"], reverse=True),
                "handled": sorted(done, key=lambda x: x["handled"]["ts"], reverse=True),
                "picks": PICKS}

    def since(self, ts: float) -> list:
        """Every item raised since `ts` (the weekly review, Ask), oldest first."""
        return [x for x in self.rec["items"] if (x.get("last") or x["ts"]) >= ts]

    @staticmethod
    def owner_words(x: dict) -> str:
        """What the owner said when they marked it handled: the pick, then their note."""
        hd = x.get("handled") or {}
        return " — ".join(w for w in (PICKS.get(hd.get("pick") or ""), hd.get("note") or "") if w)

    def weekly(self, now: Optional[float] = None, days: int = 7) -> dict:
        """The week's security events for the weekly review: how many, which are still open,
        and the owner's words on the ones they handled."""
        now = now or time.time()
        xs = self.since(now - days * 86400)
        opened = [x for x in self.rec["items"] if not x.get("handled")]
        return {"raised_this_week": len(xs),
                "still_open": [f"{x['sev']}: {x['title']} ({x['source']})" for x in opened][:6],
                "handled_this_week": [{"event": x["title"], "owner_said": self.owner_words(x) or "nothing"}
                                      for x in xs if x.get("handled")][:6]}

    # --- internals --------------------------------------------------------------------------
    def _get(self, item_id: str) -> Optional[dict]:
        return next((x for x in self.rec["items"] if x.get("id") == item_id), None)

    def _save(self):
        cut = time.time() - KEEP_DAYS * 86400
        # an open item is never pruned: it waits for the owner however old it is
        done = [x for x in self.rec["items"]
                if x.get("handled") and (x.get("last") or x["ts"]) >= cut][-400:]
        self.rec["items"] = sorted([x for x in self.rec["items"] if not x.get("handled")] + done,
                                   key=lambda x: x["ts"])
        try:
            self.state.save_record(RECORD, self.rec)
        except Exception:
            log.warning("seclog: the record could not be saved", exc_info=True)
