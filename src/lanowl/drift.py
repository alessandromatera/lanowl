"""Slowly changing: the model reads a week of the sweep's own samples.

The thresholds see a device that is down, and one that is clearly worse today than last week
(`StateStore.degrading`, the "📉 Quietly getting worse" lines). What neither sees is a shape:
latency creeping up a few milliseconds a day, a camera that drops every night at 02:00, the
internet line flapping more each week, a device fine on average and bad every evening. A
model reading the whole week can.

Once a day (`drift.at`) code builds a table — per device and per day: probes missed, mean and
worst latency, times it went down, service checks failing; the hours of the day its misses
fall in; the internet per day; what the owner ran on the machines — and the model names what
is slowly changing, each with one check from CHECKS. Nothing pages: new ones ride the next
digest once; all are on Now and in the device's sheet. Devices asleep by design are marked;
paused ones are left out (no alerts, getting worse included).

Only what is meaningful. Left to itself the model reports that a device's latency doubled (8 →
17 ms: its Wi-Fi, not the device), that a spike has cleared, that something recovered — none
of it worth a look. So: latency alone is never a finding, nor something
that got better or is already over; what the model names must hold in its own numbers
(`holds`) — the device failing NOW, three times what it did at the start of the week; and only
a "high" one rides a digest (a "warning" stays on Now and in the weekly review).
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import time

from . import wanexplain
from .model import wan_links
from .reviews import FindingsReview, actions_done, today_at
from .sweep import offline_mode_ips

log = logging.getLogger("lanowl.drift")

DAYS = 7          # full days before today, and today so far

CHECKS = {
    "losing_probes": "missing more of its probes than it used to",
    "drops_more": "going down more often",
    "time_of_day": "trouble at the same hours every day",
    "service": "a service check failing more often",
    "internet": "the internet line getting worse",
    "other": "anything else",
}
GONE = ("slower", "better")          # checks it no longer has: noise, dropped unread

# What `holds` asks of a device's own numbers: in the last two days at least this much...
MISS_PCT, DOWNS, SVC = 2.0, 2, 10
WORSE = 3.0                          # ...and this many times its level at the start of the week

SYSTEM = """You look after a home network for its owner, read on a phone. Below is a \
week of the monitor's own measurements — it probes every device once a minute — one row per \
device, one column per day, oldest first, the last column today so far. Take the numbers as \
fact; a blank (—) is no data, never zero.

Find what is GETTING WORSE AND STILL IS: a device failing more over the days and still \
failing in the last two, or one failing at the same hours every day — compared with its OWN \
earlier days, never with other devices. The owner hates noise; only what is worth their time:
- probes missed rising day after day, to more than a couple of percent now;
- going down more often; a service check failing more; misses always at the same hours (a \
schedule, interference, a nightly job); the internet line dropping more.
NOT findings: latency alone (a Wi-Fi device's milliseconds move with its radio — never a sign \
of anything wearing out); a device that got better; a spike that is already over; a device \
that is simply always slow or always flaky. A change right after something the owner ran (an \
update, a reboot — listed) may be its effect: say so. Devices marked "asleep by design" go dark \
on a schedule — their misses at those hours are expected.

Report only what the numbers show — quote them (e.g. "missed 0.1% → 0.4% → 1.2% → 3.5%"). \
Severity: "high" = it will likely fail soon, or it is safety gear (pumps, alarm, cameras) \
getting worse; "warning" = worth a look this week. Most weeks have nothing: an empty list is \
the right answer then — do not pad.

Name each with ONE check: {checks}. "ip" is the device's address exactly as given ("wan" for \
the internet line).

Reply with ONLY this JSON object, no prose, no code fence:
{{"summary": "<one sentence on what is getting worse, the most important first; empty if nothing>",
 "findings": [{{"ip": "<address>", "check": "<one of the checks>", "severity": "high"|"warning",
   "title": "<one short line for a phone>", "evidence": "<the numbers that show it>",
   "why": "<the likely cause, if the facts suggest one>", "suggestion": "<one concrete step, or empty>"}}]}}"""


def _table(db_path: str, start: float):
    """The week's aggregates in a worker thread on a read-only connection (~700k rows)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10)
    try:
        days = conn.execute(
            "SELECT ip, CAST((ts - ?) / 86400 AS INTEGER) d, COUNT(*), SUM(up), AVG(latency), "
            "MAX(latency), SUM(services IS NOT NULL) FROM samples WHERE ts >= ? GROUP BY ip, d",
            (start, start)).fetchall()
        hours = conn.execute(
            "SELECT ip, CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) h, SUM(1 - up) "
            "FROM samples WHERE ts >= ? AND up = 0 GROUP BY ip, h", (start,)).fetchall()
        downs = conn.execute(
            "SELECT ip, CAST((ts - ?) / 86400 AS INTEGER) d, COUNT(*) FROM transitions "
            "WHERE ts >= ? AND kind = 'down' GROUP BY ip, d", (start, start)).fetchall()
        return days, hours, downs
    finally:
        conn.close()


def _cell(v, fmt="{:.0f}") -> str:
    return "—" if v is None else fmt.format(v)


class Drift(FindingsReview):
    NAME = "drift"
    TITLE = "Slowly changing"
    PREFIX = "drift"
    CHECKS = CHECKS
    ICON = "📉"
    DIGEST = ("high",)        # a "warning" stays on Now and in the weekly review

    def __init__(self, auditor):
        super().__init__(auditor)
        self.at = self.at or "07:15"

    def anchor(self, f: dict, facts: dict) -> str:
        ip = str(f.get("ip") or "").strip()
        if ip.lower() == "wan":
            return "wan"
        return ip if ip in facts.get("ips", ()) else ""

    def extra(self, f: dict, facts: dict, e: dict) -> dict:
        if e["anchor"] == "wan":
            return {"ip": "", "name": "The internet"}
        dev = self.a.inv.get(e["anchor"])
        return {"ip": e["anchor"], "name": dev.name if dev is not None else e["anchor"]}

    # --- collecting -------------------------------------------------------------------------
    async def collect(self, now: float) -> dict:
        start = today_at("00:00", now) - DAYS * 86400
        days, hours, downs = await asyncio.to_thread(_table, self.a.state.db_path, start)
        ncol = DAYS + 1
        labels = [time.strftime("%a %d/%m", time.localtime(start + i * 86400 + 43200))
                  for i in range(DAYS)] + ["today"]
        by: dict = {}
        for ip, d, n, u, av, mx, sf in days:
            if 0 <= d < ncol:
                by.setdefault(ip, {})[d] = (n, u or 0, av, mx, sf or 0)
        dn: dict = {}
        for ip, d, c in downs:
            if 0 <= d < ncol:
                dn.setdefault(ip, {})[d] = c
        hr: dict = {}
        for ip, h, m in hours:
            hr.setdefault(ip, {})[h] = m or 0
        paused = self.a.pauses.ips()
        asleep = offline_mode_ips(self.a.inv)
        rows, ips, stats = [], [], {}
        for dev in self.a.inv.devices:
            if dev.ip in paused or dev.ip not in by or not self.a.state._kept(dev.ip, dev.name):
                continue
            ips.append(dev.ip)
            b = by[dev.ip]
            # the same numbers, for `holds` to check the model's findings against
            stats[dev.ip] = {
                "miss": [100.0 * (b[i][0] - b[i][1]) / b[i][0] if i in b and b[i][0] else None for i in range(ncol)],
                "down": [(dn.get(dev.ip) or {}).get(i, 0) if i in b else None for i in range(ncol)],
                "svc": [b[i][4] if i in b else None for i in range(ncol)]}
            miss = [_cell(100.0 * (b[i][0] - b[i][1]) / b[i][0], "{:.1f}") if i in b and b[i][0] else "—"
                    for i in range(ncol)]
            avg = [_cell(b[i][2]) if i in b else "—" for i in range(ncol)]
            worst = [_cell(b[i][3]) if i in b else "—" for i in range(ncol)]
            went = [str((dn.get(dev.ip) or {}).get(i, 0)) if i in b else "—" for i in range(ncol)]
            svc = [str(b[i][4]) if i in b else "—" for i in range(ncol)]
            tags = [dev.group, dev.criticality]
            if dev.ip in asleep:
                tags.append(f"asleep by design: {'at night' if asleep[dev.ip] == 'sun' else 'in daylight'}")
            line = (f"{dev.name} ({dev.ip}) [{', '.join(t for t in tags if t)}]\n"
                    f"  probes missed %: {' | '.join(miss)}\n"
                    f"  latency mean ms: {' | '.join(avg)}\n"
                    f"  latency worst ms: {' | '.join(worst)}\n"
                    f"  went down: {' | '.join(went)}")
            if any(s not in ("0", "—") for s in svc):
                line += f"\n  samples with a failing service check: {' | '.join(svc)}"
            h = hr.get(dev.ip) or {}
            total = sum(h.values())
            if total >= 20:
                top = sorted(h.items(), key=lambda kv: -kv[1])[:4]
                line += (f"\n  its {total} missed probes by hour of day: "
                         + ", ".join(f"{k:02d}h {v}" for k, v in top)
                         + (f", the other hours {total - sum(v for _, v in top)}" if total > sum(v for _, v in top) else ""))
            rows.append(line)
        rep = self.a._last_report or {}
        open_now = [f"{i.get('device')} ({i.get('ip')}): {i.get('detail')} [{i.get('severity')}]"
                    for i in rep.get("issues") or [] if i.get("severity") != "info"]
        internet, per_day = self._internet(start, ncol, labels)
        return {"ips": set(ips), "labels": labels, "rows": rows, "start": start, "open": open_now,
                "stats": stats, "internet": internet, "internet_n": per_day,
                "paused": [self.a._name(ip) for ip in paused],
                "ran": actions_done(self.a, start),
                "hints": self._hints(now)}

    def _internet(self, start: float, ncol: int, labels: list) -> tuple:
        # the main link's own drops only with a failover the router's log reports (wan.watch)
        L = wan_links(self.a.cfg)
        k = f"{L['main']} drops (router log)"
        ww = self.a.wanwatch
        failover = L["failover"] and bool(getattr(ww, "_edge_patterns", lambda: ("", ""))()[0])
        per = {**({k: [0] * ncol} if failover else {}), "no internet at all": [0] * ncol,
               "short blips": [0] * ncol}
        covers = ww.log_rows[0][0].timestamp() if getattr(ww, "log_rows", None) else None
        try:
            for s, _ in (ww.outages_from_log() if failover else []):
                i = int((s.timestamp() - start) // 86400)
                if 0 <= i < ncol:
                    per[k][i] += 1
        except Exception:
            log.debug("drift: main-link outages unreadable", exc_info=True)
        for e in wanexplain.moments(self.a.state, start):
            i = int((e["ts"] - start) // 86400)
            k = "no internet at all" if e["kind"] == "blackout" else "short blips" if e["kind"] == "blip" else ""
            if k and 0 <= i < ncol:
                per[k][i] += 1
        first = self.a.state.first_event_ts()
        if failover and covers is None:
            per[k] = ["UNKNOWN"] * ncol            # never read: not zero
        elif failover and covers > start:
            per[k] = ["—" if start + (i + 1) * 86400 <= covers else x for i, x in enumerate(per[k])]
        out = [f"  {name}: {' | '.join(str(x) for x in v)}" for name, v in per.items()]
        # per day, the main link's drops and the blackouts together, for `holds` — None where unknown
        dark = per["no internet at all"]
        drops = per[k] if failover else [0] * ncol
        n = [d + dark[i] if isinstance(d, int) else None for i, d in enumerate(drops)]
        if failover and (covers is None or covers > start):
            out.append("  (the router's log covers "
                       + (time.strftime("%a %d/%m %H:%M", time.localtime(covers)) + " onwards"
                          if covers else "nothing yet") + f" — {L['main']} drops before that are UNKNOWN)")
        if first and first > start:
            out.append(f"  (blackouts and blips recorded since {time.strftime('%d/%m', time.localtime(first))})")
        return "\n".join(out), n

    def _hints(self, now: float) -> list:
        """The thresholds' own "quietly getting worse", for the model to confirm or explain."""
        try:
            return [f"{self.a._name(r['ip'])} ({r['ip']}): {r['why']}" for r in self.a.state.degrading(now)]
        except Exception:
            return []

    def context(self, f: dict) -> str:
        lines = [f"TODAY: {time.strftime('%A %d/%m/%Y %H:%M')}",
                 "DAYS (columns, oldest first): " + " | ".join(f["labels"]), "",
                 "THE INTERNET, per day:", f["internet"], ""]
        if f["ran"]:
            lines += ["WHAT RAN ON THE MACHINES this week (the owner's updates, reboots, restarts):"]
            lines += [f"  {x}" for x in f["ran"]] + [""]
        if f["hints"]:
            lines += ["THE MONITOR'S OWN RULE flagged these as worse in the last 24 h than the week before "
                      "(confirm or explain; it compares one day only):"]
            lines += [f"  {x}" for x in f["hints"]] + [""]
        if f["paused"]:
            lines += ["Paused by the owner (no alerts, left out): " + ", ".join(f["paused"]), ""]
        if f.get("open"):
            lines += ["OPEN RIGHT NOW, already reported to the owner by the monitor (do not repeat these; "
                      "only say what the WEEK adds — e.g. that it was getting worse for days before):"]
            lines += [f"  {x}" for x in f["open"]] + [""]
        dis = [f"{k} — {v.get('note') or 'no reason given'}" for k, v in self.rec["dismissed"].items()]
        if dis:
            lines += ["DISMISSED BY THE OWNER (still report each one that still holds, with the SAME ip and "
                      "check — the monitor keeps it out of the news; leaving it out reads as gone):"]
            lines += [f"  {x}" for x in dis] + [""]
        lines += ["DEVICES:"] + f["rows"] + ["", "Return the JSON."]
        return "\n".join(lines)

    # --- the run ----------------------------------------------------------------------------
    async def run(self, reason: str = "scheduled") -> list:
        t0 = time.time()
        facts = await self.collect(t0)
        if not facts["rows"]:
            self.keep(None, "", "no samples yet — nothing to read")
            return []
        off = self.model_off()
        if off:
            self.keep(None, "", off)
            return []
        v = await self.ask(SYSTEM.format(checks="; ".join(f"{k} ({w})" for k, w in CHECKS.items())),
                           self.context(facts))
        if v is None or not isinstance(v.get("findings"), list):
            self.keep(None, "", self.model_off() or "the model gave no usable answer")
            return []
        raw = [f for f in v["findings"] if isinstance(f, dict)
               and str(f.get("check") or "").strip().lower() not in GONE]
        named = self.normalise(raw, facts)
        fs = [f for f in named if f["severity"] in ("high", "warning") and self.holds(f, facts)]
        # the model's sentence only when every finding it named stood; else the ones that did
        summary = (str(v.get("summary") or "") if len(fs) == len(named) == len(v["findings"])
                   else " · ".join(f["title"] for f in fs[:3]))
        self.keep(fs, summary if fs else "", "")
        log.info("drift: %d device(s) read, %d finding(s) kept of %d named in %.0fs (%s)", len(facts["ips"]),
                 len(fs), len(v["findings"]), time.time() - t0, reason)
        return fs

    @staticmethod
    def holds(f: dict, facts: dict) -> bool:
        """Do the numbers say it? The device failing in the last two days — probes missed, times
        down, service checks failing — at least MISS_PCT / DOWNS / SVC and WORSE times its level
        at the start of the week; the internet: more main-link drops and blackouts in the last three
        days than in the four before. The model's reading of a week stays its own; whether there
        is anything to read is the numbers'."""
        if f["anchor"] == "wan":
            n = facts.get("internet_n") or []
            recent, prev = n[-3:], n[-7:-3]
            return (len(recent) == 3 and len(prev) == 4 and None not in recent + prev
                    and sum(recent) >= 3 and sum(recent) > sum(prev))
        st = (facts.get("stats") or {}).get(f["anchor"])
        if not st:
            return False

        def worse(vals, floor, total=False):
            recent = [x for x in vals[-2:] if x is not None]
            early = sorted(x for x in vals[:4] if x is not None)
            if not recent:
                return False
            now = sum(recent) if total else max(recent)
            base = (early[len(early) // 2] if early else 0) * (2 if total else 1)
            return now >= floor and now >= WORSE * base
        return worse(st["miss"], MISS_PCT) or worse(st["down"], DOWNS, total=True) or worse(st["svc"], SVC)

    def ips(self) -> set:
        """The devices the digest's thresholds need not repeat: the model has said it better."""
        return {f["ip"] for f in self.open_findings() if f.get("ip")}
