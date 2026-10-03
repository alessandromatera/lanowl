"""Debounce/flap detection (in-memory) + persistent history (SQLite).

StatusTracker is pure logic (no deps) and is unit-testable: it turns a stream of
raw per-cycle reachability booleans into confirmed up/down transitions, absorbing
transient blips via a debounce threshold.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class Transition:
    ip: str
    kind: str        # 'up' | 'down'
    at: float
    detail: str = ""


class _S:
    __slots__ = ("confirmed", "fail", "ok", "since", "first_fail")

    def __init__(self):
        self.confirmed: Optional[bool] = None
        self.fail = 0
        self.ok = 0
        self.since = 0.0
        self.first_fail = 0.0   # the first miss of the current run of misses


class StatusTracker:
    """Confirmed status = only flips after N consecutive same-direction samples."""

    def __init__(self, debounce_fails: int = 2, recovery_oks: int = 1):
        self.debounce_fails = max(1, debounce_fails)
        self.recovery_oks = max(1, recovery_oks)
        self._s: dict[str, _S] = {}

    def update(self, ip: str, reachable: bool, now: Optional[float] = None,
               debounce_fails: Optional[int] = None) -> Optional[Transition]:
        """`debounce_fails` overrides the global threshold for this one device. The LAN
        answers in milliseconds and a missed sweep there means something; a site on the far
        end of a WireGuard tunnel over two ISPs needs more slack than that — every WAN
        failover costs it a couple of minutes while the tunnel re-keys on the new link, and
        that is not an outage anyone needs to hear about."""
        now = time.time() if now is None else now
        fails = self.debounce_fails if debounce_fails is None else max(1, int(debounce_fails))
        st = self._s.setdefault(ip, _S())
        if reachable:
            st.ok += 1
            st.fail = 0
            st.first_fail = 0.0
            if st.confirmed is not True and st.ok >= self.recovery_oks:
                prev = st.confirmed
                st.confirmed = True
                st.since = now
                if prev is False:  # genuine recovery (None->up is just baseline)
                    return Transition(ip, "up", now)
        else:
            st.fail += 1
            st.ok = 0
            if st.fail == 1:
                st.first_fail = now
            if st.confirmed is not False and st.fail >= fails:
                st.confirmed = False
                st.since = now
                # dated like down_since: the logbook's "went down at" is the first miss.
                # Covers startup-down and up->down.
                return Transition(ip, "down", st.first_fail or now)
        return None

    def rename(self, old_ip: str, new_ip: str):
        """Carry a device's debounce/up-down state across a DHCP address change, so a
        re-bind isn't seen as one device going down and another appearing."""
        st = self._s.pop(old_ip, None)
        if st is not None:
            self._s[new_ip] = st

    def status(self, ip: str) -> Optional[bool]:
        s = self._s.get(ip)
        return s.confirmed if s else None

    def since(self, ip: str) -> float:
        s = self._s.get(ip)
        return s.since if s else 0.0

    def down_since(self, ip: str) -> float:
        """When the device actually stopped answering; 0.0 unless it is confirmed down.

        `since` is the sweep that CONFIRMED it, which by construction is `debounce_fails`
        sweeps after the first miss — a minute or more after the device went quiet. A
        human asking "when did it go down?" means the first miss, and that is the instant
        every message about the outage should carry. A remote site with its own five-sweep
        debounce is the case where the two differ by enough to matter."""
        s = self._s.get(ip)
        return s.first_fail if (s and s.confirmed is False) else 0.0

    def down_ips(self) -> list[str]:
        return [ip for ip, s in self._s.items() if s.confirmed is False]

    def restore(self, ip: str, confirmed: Optional[bool], since: float = 0.0,
                fails: int = 0, first_fail: float = 0.0):
        """Resume a device where the previous process left it (see StateStore.resume).

        Without this every restart forgot that a device was already down: the first sweep
        counted its misses from zero, the outage was re-dated to the moment lanowl came
        up, and the history gained a second `down` for an outage it already had: a router
        dark since 19:48 recovered "after 30280s", counted from the second restart at 23:15."""
        st = self._s.setdefault(ip, _S())
        st.confirmed, st.since, st.ok = confirmed, since, 0
        st.first_fail = first_fail or (since if confirmed is False else 0.0)
        # update() dates an outage on the miss it counts as the first, so a device with a
        # date to keep must never resume at zero misses
        st.fail = max(int(fails), 1 if st.first_fail else 0)


class StateStore:
    """SQLite history: samples + transitions. Used for trends and the LLM's
    `history_query` tool. Opened per-process; sqlite handles our modest volume."""

    def __init__(self, db_path: str, history_days: int = 14):
        self.db_path = db_path
        self.history_days = history_days
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._records: dict[str, str] = {}   # name -> the JSON last written (see save_record)
        # (ip, name) -> is this history about a device monitored now (Inventory.owns). The
        # rows of a device taken out of the inventory stay in the table and age out with the
        # rest; they just stop being read as the network's history. None: read everything.
        self.keep = None
        # ip -> is this address probed now (Inventory.is_known). None: every address is.
        self.probed = None
        self._init_schema()

    def _kept(self, ip: str, name: str = "") -> bool:
        return self.keep is None or bool(self.keep(ip, name or ""))

    def _init_schema(self):
        # WAL + NORMAL: the sweep commits once a second-ish with ~53 inserts, and the
        # rollback journal made each of those a full fsync cycle. WAL also stops a long
        # read (the LLM's history_query, now running on its own task alongside the sweep)
        # from blocking the writer.
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                ts REAL, ip TEXT, up INTEGER, latency REAL, services TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_samples_ip_ts ON samples(ip, ts);
            CREATE TABLE IF NOT EXISTS transitions (
                ts REAL, ip TEXT, kind TEXT, detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_trans_ts ON transitions(ts);
            CREATE INDEX IF NOT EXISTS idx_trans_ip_ts ON transitions(ip, ts);
            CREATE TABLE IF NOT EXISTS records (
                name TEXT PRIMARY KEY, value TEXT, ts REAL
            );
            CREATE TABLE IF NOT EXISTS events (
                ts REAL, kind TEXT, value REAL, detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE TABLE IF NOT EXISTS seen (
                site TEXT, mac TEXT, first_seen REAL, last_seen REAL, ip TEXT, host TEXT, how TEXT,
                PRIMARY KEY (site, mac)
            );
            """
        )
        self.conn.commit()

    # --- things that happen that are not a device going up or down ----------
    # Otherwise the WAN's history lives only in memory (24h of flaps) and in the router's own
    # log (about a week and a half, and nobody reads it back). The weekly review needs "how
    # many times did the main link drop this week", and the model needs "what did the log
    # checks conclude". Both are tiny: a few rows a day.
    EVENTS_KEEP_DAYS = 90

    def record_event(self, kind: str, value: Optional[float] = None, detail: str = "",
                     ts: Optional[float] = None) -> None:
        """kind: main-outage (value = seconds) | blackout (seconds) | blip (seconds) |
        finding (a log check's verdict; detail = JSON) | telegram (a message sent)."""
        try:
            self.conn.execute("INSERT INTO events(ts, kind, value, detail) VALUES (?,?,?,?)",
                              (ts or time.time(), kind, value, detail or ""))
            self.conn.commit()
        except Exception:
            pass     # history is a nicety; it must never take a watcher down

    def events(self, since_ts: float, kind: Optional[str] = None, limit: int = 1000) -> list[dict]:
        if kind:
            rows = self.conn.execute(
                "SELECT ts, kind, value, detail FROM events WHERE ts>=? AND kind=? "
                "ORDER BY ts DESC LIMIT ?", (since_ts, kind, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT ts, kind, value, detail FROM events WHERE ts>=? ORDER BY ts DESC LIMIT ?",
                (since_ts, limit)).fetchall()
        return [dict(r) for r in rows]

    def first_event_ts(self) -> Optional[float]:
        r = self.conn.execute("SELECT MIN(ts) t FROM events").fetchone()
        return r["t"] if r else None

    # --- every device ever seen, per site (new-device detection) -------------
    # Kept for good (a friend back after months must be recognised, not announced as new),
    # so nothing ever deletes from this table. `how`: how it was FIRST seen — dhcp, arp (a
    # fixed address the router talked to) or scan (the monthly scan found it).
    def seen_count(self, site: str = "home") -> int:
        return self.conn.execute("SELECT COUNT(*) c FROM seen WHERE site=?", (site,)).fetchone()["c"]

    def seen_first(self, macs, site: str = "home") -> dict:
        """{MAC: first_seen} — when each of these was first seen on that site."""
        macs = sorted({str(m or "").upper() for m in macs if m})
        out = {}
        for i in range(0, len(macs), 500):
            part = macs[i:i + 500]
            for r in self.conn.execute(
                    f"SELECT mac, first_seen FROM seen WHERE site=? AND mac IN ({','.join('?' * len(part))})",
                    [site] + part).fetchall():
                out[r["mac"]] = r["first_seen"]
        return out

    def seen_all(self, site: Optional[str] = None) -> list:
        """Every device ever seen — on one site, or all of them — newest first."""
        q = "SELECT site, mac, first_seen, last_seen, ip, host, how FROM seen"
        args: tuple = ()
        if site:
            q, args = q + " WHERE site=?", (site,)
        return [dict(r) for r in self.conn.execute(q + " ORDER BY first_seen DESC", args)]

    def mark_seen(self, devices: list, ts: float, site: str = "home") -> list:
        """Upsert observed devices ({ip, mac, host, how}); return those never seen before on
        that site. A name, once known, is not wiped by a sighting without one (an ARP entry)."""
        new = []
        for d in devices:
            mac = (d.get("mac") or "").upper()
            if not mac:
                continue
            row = self.conn.execute("SELECT mac FROM seen WHERE site=? AND mac=?", (site, mac)).fetchone()
            if row is None:
                new.append(d)
                self.conn.execute(
                    "INSERT INTO seen(site, mac, first_seen, last_seen, ip, host, how) VALUES (?,?,?,?,?,?,?)",
                    (site, mac, ts, ts, d.get("ip", ""), d.get("host", ""), d.get("how") or "dhcp"))
            else:
                self.conn.execute(
                    "UPDATE seen SET last_seen=?, ip=?, host=CASE WHEN ?='' THEN host ELSE ? END "
                    "WHERE site=? AND mac=?",
                    (ts, d.get("ip", ""), d.get("host", "") or "", d.get("host", "") or "", site, mac))
        self.conn.commit()
        return new

    def record_sample(self, ip: str, up: bool, latency: Optional[float], services: dict, ts: Optional[float] = None):
        # 53 devices x 1440 sweeps x 14 days is ~1.03M rows, and on a healthy network every
        # one of them carried the string {"failed":[]}. Nothing reads the column when it is
        # empty, so it is stored as NULL: same information, ~15MB less database.
        blob = None
        if services and any(services.values()):
            blob = json.dumps(services, separators=(",", ":"))
        self.conn.execute(
            "INSERT INTO samples(ts, ip, up, latency, services) VALUES (?,?,?,?,?)",
            (ts or time.time(), ip, 1 if up else 0, latency, blob),
        )

    def record_transition(self, t: Transition):
        self.conn.execute(
            "INSERT INTO transitions(ts, ip, kind, detail) VALUES (?,?,?,?)",
            (t.at, t.ip, t.kind, t.detail),
        )

    def commit(self):
        self.conn.commit()

    # --- small documents that must outlive the process ----------------------
    def save_record(self, name: str, obj) -> None:
        """Keep a JSON document across restarts (the alert record); written only on change.

        Called after every sweep and every digest, so the unchanged case — nearly all of
        them — costs a string comparison and no write."""
        text = json.dumps(obj, sort_keys=True, default=str)
        if self._records.get(name) == text:
            return
        self.conn.execute("INSERT OR REPLACE INTO records(name, value, ts) VALUES (?,?,?)",
                          (name, text, time.time()))
        self.conn.commit()
        self._records[name] = text

    def load_record(self, name: str):
        """The document last saved under `name`, or None."""
        row = self.conn.execute("SELECT value FROM records WHERE name=?", (name,)).fetchone()
        if row is None:
            return None
        self._records[name] = row["value"]
        try:
            return json.loads(row["value"])
        except ValueError:
            return None

    def resume(self, ips, now: Optional[float] = None,
               max_gap_s: float = 3600) -> dict[str, dict]:
        """{ip: kwargs for StatusTracker.restore} — each device as the last run left it.

        The confirmed state is the device's last transition; the misses are every sample
        since it last answered. So an outage that began before a restart keeps its start,
        and one half-way through its debounce finishes counting instead of starting over.

        Only a recent history is trusted. After a long gap (Docker Desktop off, the Mac
        asleep) nobody knows what happened in between, and "down since yesterday" that was
        really two outages is worse than dating it from startup."""
        now = time.time() if now is None else now
        q = lambda sql, *a: self.conn.execute(sql, a).fetchone()
        last = max((q("SELECT MAX(ts) t FROM samples WHERE ip=?", ip)["t"] or 0.0
                    for ip in ips), default=0.0)
        if not last or now - last > max_gap_s:
            return {}
        out = {}
        for ip in ips:
            answered = q("SELECT MAX(ts) t FROM samples WHERE ip=? AND up=1", ip)["t"] or 0.0
            st = {"confirmed": None, "since": 0.0, "fails": 0, "first_fail": 0.0}
            t = q("SELECT ts, kind FROM transitions WHERE ip=? ORDER BY ts DESC LIMIT 1", ip)
            # a `down` it answered after, with no `up` on record, is a loose end from an
            # older restart (see logbook): the samples know better than that row
            if t and not (t["kind"] == "down" and answered > t["ts"]):
                st["confirmed"], st["since"] = t["kind"] == "up", t["ts"]
            m = q("SELECT COUNT(*) n, MIN(ts) f FROM samples WHERE ip=? AND up=0 AND ts>?",
                  ip, answered)
            if m["n"]:
                st["fails"], st["first_fail"] = m["n"], m["f"]
            if st["confirmed"] is not None or st["fails"]:
                out[ip] = st
        return out

    def logbook(self, since_ts: float = 0.0, ip: Optional[str] = None,
                limit: int = 200) -> list[dict]:
        """Every confirmed down and up, newest first. An `up` carries `down_for` (seconds, or
        None if its `down` is older than the history); a `down` carries `open` while the
        device has not come back.

        Read from `transitions`, tidying the loose ends restarts left there before the
        tracker was restored across them: each restart wrote a second `down` for an outage
        already on record, and never wrote the `up` of a device that came back while the
        lanowl was away. A repeated `down` is folded into the first — unless the device
        answered in between, in which case the first outage is closed at that answer."""
        where, args = ("WHERE ip=?", (ip,)) if ip else ("", ())
        rows = self.conn.execute(
            f"SELECT ts, ip, kind, detail FROM transitions {where} ORDER BY ts, rowid",
            args).fetchall()
        out: list[dict] = []
        running: dict[str, dict] = {}     # ip -> the `down` entry of its current outage

        def came_back(ip_: str, at: float, name: str):
            down = running.pop(ip_)
            down["open"] = False
            out.append({"ts": at, "ip": ip_, "kind": "up", "name": name,
                        "down_for": at - down["ts"]})

        for r in rows:
            ip_, ts, name = r["ip"], r["ts"], r["detail"] or ""
            if r["kind"] == "down":
                if ip_ in running:
                    back = self.conn.execute(
                        "SELECT MIN(ts) t FROM samples WHERE ip=? AND up=1 AND ts>? AND ts<?",
                        (ip_, running[ip_]["ts"], ts)).fetchone()["t"]
                    if not back:
                        continue          # the same outage, announced again by a restart
                    came_back(ip_, back, name)
                running[ip_] = {"ts": ts, "ip": ip_, "kind": "down", "name": name, "open": True}
                out.append(running[ip_])
            elif ip_ in running:
                came_back(ip_, ts, name)
            else:
                out.append({"ts": ts, "ip": ip_, "kind": "up", "name": name, "down_for": None})
        # An outage still open here may have ended while lanowl was away: a restart
        # resumes such a device as 'unknown' (see resume), and unknown -> up is not a
        # transition, so its `up` is never written, and the dashboard would show devices
        # "still down · 16h47" that have been answering all morning. The samples know better:
        # close it at the first answer.
        for ip_ in list(running):
            if ip and ip_ != ip:
                continue
            back = self.conn.execute(
                "SELECT MIN(ts) t FROM samples WHERE ip=? AND up=1 AND ts>?",
                (ip_, running[ip_]["ts"])).fetchone()["t"]
            if back:
                came_back(ip_, back, running[ip_]["name"])
        # An address nobody probes any more cannot come back: nothing samples it. A device
        # moved (DHCP, a site's MAC) or taken out mid-outage keeps that outage open at the old
        # address, and `keep` still reads it by name: a camera taken out of the inventory while
        # down would stay "still down" on the Timeline for good, its incident shading every
        # lane to now. Its outage ends where its probing did.
        for ip_ in list(running):
            if (ip and ip_ != ip) or self.probed is None or self.probed(ip_):
                continue
            last = self.conn.execute("SELECT MAX(ts) t FROM samples WHERE ip=? AND ts>=?",
                                     (ip_, running[ip_]["ts"])).fetchone()["t"]
            came_back(ip_, last or running[ip_]["ts"], running[ip_]["name"])
        out.sort(key=lambda e: e["ts"], reverse=True)
        return [e for e in out if e["ts"] >= since_ts
                and (ip or self._kept(e["ip"], e["name"]))][:limit]

    def recent_transitions(self, since_ts: float, ip: Optional[str] = None, limit: int = 100) -> list[dict]:
        if ip:
            rows = self.conn.execute(
                "SELECT ts, ip, kind, detail FROM transitions WHERE ts>=? AND ip=? ORDER BY ts DESC LIMIT ?",
                (since_ts, ip, limit),
            ).fetchall()
        else:
            # no LIMIT in SQL: a retired device's rows must not use up the caller's limit
            rows = [r for r in self.conn.execute(
                "SELECT ts, ip, kind, detail FROM transitions WHERE ts>=? ORDER BY ts DESC",
                (since_ts,)).fetchall() if self._kept(r["ip"], r["detail"])][:limit]
        return [dict(r) for r in rows]

    def uptime_pct(self, ip: str, since_ts: float):
        """Percentage of samples where the device answered, in the window. None if no data."""
        r = self.conn.execute(
            "SELECT COUNT(*) n, SUM(up) u FROM samples WHERE ip=? AND ts>=?", (ip, since_ts)
        ).fetchone()
        if not r or not r["n"]:
            return None
        return round(100.0 * (r["u"] or 0) / r["n"], 1)

    def device_history(self, ip: str, since_ts: float, bucket_s: int = 900) -> list[list]:
        """[bucket start, samples, answered, avg latency, max latency] for one device, oldest
        first — the dashboard's 24h chart. A bucket with no samples is simply absent (the
        lanowl was not running), which the page must draw as "no data", never as down.
        Rides the (ip, ts) index: ~1ms for a day."""
        rows = self.conn.execute(
            "SELECT CAST((ts - ?) / ? AS INTEGER) b, COUNT(*) n, SUM(up) u, AVG(latency) a, "
            "MAX(latency) m FROM samples WHERE ip=? AND ts>=? GROUP BY b ORDER BY b",
            (since_ts, bucket_s, ip, since_ts)).fetchall()
        return [[since_ts + r["b"] * bucket_s, r["n"], r["u"] or 0,
                 round(r["a"], 1) if r["a"] is not None else None,
                 round(r["m"], 1) if r["m"] is not None else None] for r in rows]

    def flap_counts(self, since_ts: float) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT ip, COUNT(*) c, MAX(detail) name FROM transitions WHERE ts>=? GROUP BY ip "
            "ORDER BY c DESC", (since_ts,),
        ).fetchall()
        return {r["ip"]: r["c"] for r in rows if self._kept(r["ip"], r["name"])}

    def _window_stats(self, start: float, end: float) -> dict:
        rows = self.conn.execute(
            "SELECT ip, COUNT(*) n, SUM(up) u, AVG(latency) lat FROM samples "
            "WHERE ts >= ? AND ts < ? GROUP BY ip", (start, end)).fetchall()
        return {r["ip"]: {"n": r["n"], "loss": 100.0 * (r["n"] - (r["u"] or 0)) / r["n"],
                          "lat": r["lat"]}
                for r in rows if r["n"]}

    def week_stats(self, start: float, end: float) -> dict:
        """{ip: {n, uptime_pct, latency_ms, transitions}} over [start, end), for the weekly
        review. One pass over the samples plus one over the transitions."""
        out = {}
        for ip, s in self._window_stats(start, end).items():
            out[ip] = {"n": s["n"], "uptime_pct": round(100.0 - s["loss"], 1),
                       "latency_ms": round(s["lat"], 1) if s["lat"] else None,
                       "transitions": 0}
        for r in self.conn.execute(
                "SELECT ip, COUNT(*) c FROM transitions WHERE ts>=? AND ts<? GROUP BY ip",
                (start, end)).fetchall():
            out.setdefault(r["ip"], {"n": 0, "uptime_pct": None, "latency_ms": None,
                                     "transitions": 0})["transitions"] = r["c"]
        return out

    def new_macs(self, since_ts: float) -> list[dict]:
        """Devices first seen after `since_ts`, on any site."""
        rows = self.conn.execute(
            "SELECT site, mac, first_seen, last_seen, ip, host, how FROM seen WHERE first_seen>=? "
            "ORDER BY first_seen", (since_ts,)).fetchall()
        return [dict(r) for r in rows]

    def degrading(self, now: float, window_s: float = 86400,
                  baseline_s: float = 7 * 86400, min_samples: int = 200) -> list[dict]:
        """Devices that still answer, but measurably worse than they used to.

        Every sweep is already written down; nothing has ever read it back to ask "what is
        slowly getting worse?". A pump at the edge of Wi-Fi coverage can run at ~30% packet loss
        with multi-second spikes for weeks, and the first anyone hears of it is three false
        'unreachable' alerts in one hour — after which it gets deleted from monitoring, the
        worst possible outcome for a flood pump.

        A device is only flagged when the RECENT window is worse than its own baseline, so
        gear that has always been slow (a distant Shelly at 900ms) says nothing, and the same
        gear at 2s does. Comparing each device against itself is what keeps this quiet enough
        to be worth reading."""
        recent = self._window_stats(now - window_s, now)
        base = self._window_stats(now - baseline_s, now - window_s)
        out = []
        for ip, r in recent.items():
            b = base.get(ip)
            if not self._kept(ip):
                continue
            if not b or r["n"] < min_samples or b["n"] < min_samples:
                continue        # too little history to say anything honest
            why = []
            if r["loss"] >= 2.0 and r["loss"] >= b["loss"] + 1.0:
                why.append(f"missed {r['loss']:.0f}% of probes (was {b['loss']:.0f}%)")
            if r["lat"] and b["lat"] and r["lat"] >= 2 * b["lat"] and r["lat"] >= 150:
                why.append(f"latency {r['lat']:.0f}ms, {r['lat'] / b['lat']:.1f}x its usual "
                           f"{b['lat']:.0f}ms")
            if why:
                out.append({"ip": ip, "loss_pct": round(r["loss"], 1),
                            "latency_ms": round(r["lat"], 1) if r["lat"] else None,
                            "why": "; ".join(why)})
        out.sort(key=lambda d: -d["loss_pct"])
        return out

    def prune(self):
        """Drop history past the retention window, and occasionally give the space back.

        DELETE only moves pages onto sqlite's free list, so the file never shrinks — it just
        stops growing, at whatever high-water mark the busiest fortnight set. VACUUM is the
        only way to return the space, and it rewrites the whole database, so it runs only
        when there is enough dead weight to be worth the pause."""
        cutoff = time.time() - self.history_days * 86400
        self.conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
        self.conn.execute("DELETE FROM transitions WHERE ts < ?", (cutoff,))
        self.conn.execute("DELETE FROM events WHERE ts < ?",
                          (time.time() - self.EVENTS_KEEP_DAYS * 86400,))
        self.conn.commit()
        try:
            free = self.conn.execute("PRAGMA freelist_count").fetchone()[0]
            total = self.conn.execute("PRAGMA page_count").fetchone()[0]
            if total and free / total > 0.25:
                self.conn.execute("VACUUM")
        except Exception:
            pass   # never let housekeeping take the monitor down

    def close(self):
        try:
            self.conn.commit()
            self.conn.close()
        except Exception:
            pass
