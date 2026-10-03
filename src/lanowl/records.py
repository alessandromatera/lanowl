"""lanowl's own records, for the model: everything the dashboard shows, and what it decided.

A model with tools for the NETWORK only — probes, the router's and the hosts' logs, the
logbook — can only guess when asked about LANOWL itself: "what needs updating on the VPS?",
"why didn't you tell me last night?". The Security tab, the actions and what became of them,
what Telegram was told, the audits' own verdicts, the backups, earlier conversations: all out
of its reach, while the page beside it draws every one.

One tool, `lanowl_records`, reads them all, read-only, from what lanowl already holds:
the same views the dashboard draws (web.state_payload, web.device_info), the updates record
with every package, the events table (90 days: every log-check verdict — the ones that found
nothing too — every action, every Telegram message with its text, every audit with what became
of its digest, every pause), the stored conversations, and lanowl's own log file.

Two rules from earlier lessons:
  - absent data is not zero: every answer says the window it covers, and UNKNOWN where
    there is no record yet;
  - no secret passes: never a login, and anything token- or password-shaped is scrubbed
    from the log file.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Optional

from .actions import CATALOG
from .seclog import SecLog
from .report import label

log = logging.getLogger("lanowl.records")

MAX_CHARS = 14000          # one answer; the model's context is large, not endless
LOG_TAIL_BYTES = 6_000_000  # the log file rotates at 5 MB: this is all of the current one

# What each topic holds, in the tool's own description: a local model reads a description far
# more reliably than an enum.
TOPICS = {
    "security": "the Security tab in brief: what matters now (and what the owner dismissed, "
                "with his reason), the security events the logs showed (failed-login bursts, "
                "logins from outside, the log checks' finds — open until the owner marks them "
                "handled, then with his words), updates and reboots waiting per machine, the last "
                "vulnerability scan, the auth logs watched, DHCP devices not in the inventory, "
                "the sandbox shell's isolation",
    "updates": "per machine: OS, EVERY package waiting (name, new version, installed version, "
               "security or not, held back by Ubuntu), a pending reboot and what asked for it, "
               "RouterOS and firmware installed vs latest with the security releases in "
               "between, Home Assistant's own update list, when it was last read (ip= for one)",
    "exposure": "the model's daily security review: its findings (machine, check, severity, the "
                "evidence, the fix, what the owner dismissed and why), the outside scan of what "
                "the internet reaches, and the facts read from each machine (ip= for one)",
    "vulnerabilities": "the monthly vulnerability scan: when, how many devices, and every CVE "
                       "match per device with its verdict — applies, fixed in its build, not "
                       "affected (NVD's versions), not applicable (the model), unclear — and why",
    "backups": "the machines' backups on the homehub: each one's last backup, its result "
               "and size, what is saved, when the next is due",
    "device": "EVERYTHING about one device (ip= required): what it is, its probes right now, "
              "its DHCP lease, what it depends on and what hangs off it, whether and how it can "
              "be rebooted / updated / backed up / scanned from here, its waiting updates, open "
              "issues, paused or not, the last actions on it",
    "actions": "every action proposed by the model (audit or question) or pressed by the owner: "
               "when, what, on which device, the reason, and what became of it — approved, "
               "rejected, refused and why, expired, its result or error (hours=, ip=)",
    "telegram": "every message lanowl sent on Telegram, with its time and text: alerts, "
                "digests, recoveries, weekly reviews, action results (hours=, search=)",
    "log_checks": "every verdict of the router-log and host-log checks — the ones that found "
                  "NOTHING too: time, source, lines, problem or not, severity, summary "
                  "(hours=, search=)",
    "audits": "each model audit's verdict — health, summary, the issues it raised — and whether "
              "its digest was sent or held back, and why (hours=)",
    "pauses": "devices the owner paused, since when and by whom, and every pause and resume "
              "(hours=)",
    "discovery": "DHCP devices that are not in the inventory, those the owner acknowledged, new "
                 "and moved ones; each with when it was first seen, and the guest Wi-Fi marked",
    "devices_seen": "EVERY device ever seen on every site — the main LAN and its guest Wi-Fi, "
                    "the remote sites; by DHCP, by a fixed address in a router's ARP table, "
                    "or by the monthly scan — kept for good: when each was first and last seen, "
                    "its maker, and what it is now (watched, known, or nobody's). Whether a "
                    "device has been here before (search= a MAC, name, maker, address or site)",
    "scan": "the monthly scan of every site's networks (who answers, from each site's router — "
            "the devices with a fixed address that no DHCP lists): when it last ran, what it "
            "found, its errors, when it runs next",
    "shell": "the commands the model ran in its sandbox shell, with the question that asked "
             "and the exit code, and the sandbox's isolation check",
    "conversations": "earlier questions and answers, on the dashboard and on Telegram "
                     "(search=, hours=)",
    "auditor_log": "lanowl's own log file: what it did and decided, warnings and errors — "
                   "digests held back, audit timings, a watcher failing (search=, hours=, "
                   "level=WARNING for warnings and errors only)",
    "sites": "every site — the main one, the VPN hub, the remote ones: each one's devices "
             "up and down, what a remote site's DHCP sees (name, address, MAC) and which of those "
             "the owner watches",
    "services": "the named services (MQTT, Node-RED, Home Assistant, …) and whether each answers",
    "slow_changes": "the model's daily look at a week of the sweep's own samples: what is slowly "
                    "changing (probes missed rising, latency creeping, more outages, trouble at the "
                    "same hours, the internet line getting worse) — its findings with the numbers, what the "
                    "owner dismissed, and when it last looked",
    "config_changes": "what changed in the machines' configurations (the MikroTiks' exports, the "
                      "homehub's and the VPS's sshd, users, keys, cron, services, ports, "
                      "firewall, WireGuard peers, tunnel routes), compared every morning: each "
                      "change in words, its risk, the diff lines, and whether the owner marked a "
                      "risky one handled (hours=, ip=)",
    "fixes": "the fixes the model wrote out for findings — steps, exact commands, how to undo, "
             "how to check — for the owner to apply themselves (nothing runs them); search= a key",
    "scorecard": "the model's track record: each cause it named for a problem, graded with "
                 "hindsight once the problem was over (right / partly / wrong / can't tell, "
                 "why), the owner's own verdicts, totals per kind of problem (hours=)",
}

SPEC = {"type": "function", "function": {
    "name": "lanowl_records",
    "description": (
        "Read the AUDITOR's OWN records — what it knows, did, decided and sent, everything its "
        "dashboard shows. Read-only, instant, no load on any device. Use it whenever the "
        "question is about lanowl itself or anything it keeps: never say you do not know "
        "before looking here. Topics: "
        + "; ".join(f"{k} — {v}" for k, v in TOPICS.items()) + "."),
    "parameters": {"type": "object", "properties": {
        "topic": {"type": "string", "enum": list(TOPICS)},
        "ip": {"type": "string", "description": "one device (device: required; updates, "
                                                "actions: optional)"},
        "hours": {"type": "number", "description": "how far back (default 48; up to 2160 = 90 "
                                                   "days)"},
        "search": {"type": "string", "description": "words to match, case-insensitive; "
                                                    "several with '|'"},
        "level": {"type": "string", "description": "auditor_log only: WARNING = warnings and "
                                                   "errors only"},
        "limit": {"type": "integer", "description": "at most this many entries (default 40)"},
    }, "required": ["topic"]}}}

# Token- and password-shaped text, scrubbed from anything read out of the log file.
_SECRETS = (
    # a bot token, also glued to "bot" in an API URL — where \b finds no boundary
    (re.compile(r"(?<!\d)\d{6,12}:[A-Za-z0-9_-]{30,}"), "<telegram token>"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
                r"([ \t]*[=:][ \t]*|[ \t]+)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1\2***"),   # one line only
    (re.compile(r"(?i)\bbearer\s+\S+"), "Bearer ***"),
    (re.compile(r"(?i)://[^/\s:@]+:[^/\s@]+@"), "://***:***@"),
)
_LOGLINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ (\w+) ")
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}


def scrub(text: str) -> str:
    for rx, sub in _SECRETS:
        text = rx.sub(sub, text)
    return text


def finding_kind(f: dict) -> str:
    """security | health — the model's label, or the source's default when it gave none."""
    k = str(f.get("kind") or "")
    if k in ("security", "health"):
        return k
    return "security" if str(f.get("source") or "").startswith("host log") else "health"


def _at(ts) -> Optional[str]:
    return time.strftime("%a %d/%m %H:%M", time.localtime(ts)) if ts else None


def _match(search: str):
    """'a|b' -> a predicate over text, case-insensitive; empty = everything."""
    words = [w.strip().lower() for w in (search or "").split("|") if w.strip()]
    return (lambda t: True) if not words else (lambda t: any(w in (t or "").lower() for w in words))


def _clip(obj) -> str:
    """The answer as JSON, cut to MAX_CHARS with a word saying so."""
    s = json.dumps(obj, ensure_ascii=False, default=str)
    if len(s) <= MAX_CHARS:
        return s
    return s[:MAX_CHARS] + ' … [cut: ask for fewer — a smaller limit, fewer hours, a search or an ip]'


class Records:
    def __init__(self, auditor):
        self.a = auditor

    def spec(self) -> dict:
        return SPEC

    # --- the tool ------------------------------------------------------------------------
    def call(self, args: dict) -> dict:
        args = args if isinstance(args, dict) else {}
        topic = str(args.get("topic") or "").strip().lower()
        if topic not in TOPICS:
            return {"error": f"unknown topic {topic!r}; it can be one of: {', '.join(TOPICS)}"}
        try:
            hours = float(args.get("hours") or 48)
            limit = int(args.get("limit") or 40)
        except (TypeError, ValueError):
            return {"error": "hours and limit must be numbers"}
        hours = max(0.1, min(hours, 90 * 24))
        limit = max(1, min(limit, 200))
        now = time.time()
        opts = {"ip": str(args.get("ip") or "").strip(), "hours": hours, "limit": limit,
                "since": now - hours * 3600, "now": now,
                "search": str(args.get("search") or ""),
                "level": str(args.get("level") or "").strip().upper()}
        try:
            out = getattr(self, "_" + topic)(**opts)
        except Exception as e:
            log.exception("lanowl_records %s failed", topic)
            return {"error": f"could not read {topic}: {type(e).__name__}"}
        return {"topic": topic, "records": _clip(out)}

    # --- security --------------------------------------------------------------------------
    def _security(self, now, **_):
        a = self.a
        U = a.updates.view()
        items = self.security_items()
        out: dict = {"what_matters": [f"{i['sev']}: {i['text']} ({i['from']})" for i in items
                                      if i["top"] and not i["dismissed"]],
                     "worth_fixing_not_urgent": [f"{i['text']} ({i['from']})" for i in items
                                                 if not i["top"] and not i["dismissed"]]}
        sv = a.seclog.view(now)
        ev = lambda x: {"what": x["title"], "when": _at(x["ts"]), "where": label(a._name(x["ip"], ""), x["ip"]),
                        "log": x["source"],
                        "found_by": "a fixed rule" if x.get("by") == "rule" else "the log check's model",
                        **({"times": x["count"], "last": _at(x.get("last"))} if (x.get("count") or 1) > 1 else {}),
                        **({"detail": x["detail"]} if x.get("detail") else {}),
                        **({"the_models_read": x["model"]["summary"]} if x.get("model") else {}),
                        "sent_to_telegram": bool(x.get("paged"))}
        out["log_events_open"] = [ev(x) for x in sv["open"]][:15]
        out["log_events_handled_by_the_owner"] = [
            {**ev(x), "handled": _at(x["handled"]["ts"]), "his_words": SecLog.owner_words(x) or "nothing"}
            for x in sv["handled"]][:15]
        if not U.get("enabled"):
            out["updates"] = "the update check is switched off (updates.enabled)"
        elif not U.get("last"):
            out["updates"] = f"UNKNOWN: the daily check has not run yet (it runs at {U.get('at')})"
        else:
            fs = U.get("findings") or []
            out["updates_checked"] = _at(U["last"])
            out["dismissed_by_the_owner"] = [
                {"finding": f["text"], "when": _at(f["dismissed"].get("ts")),
                 "his_reason": f["dismissed"].get("note") or ""}
                for f in fs if f.get("dismissed")]
            out["machines"] = [{"machine": label(h.get("name"), h["ip"]), "os": h.get("os"),
                                "updates_waiting": h.get("updates"),
                                "of_which_security": h.get("security"),
                                **({"reboot_pending_since": _at(h["reboot_since"])}
                                   if h.get("reboot_since") else {}),
                                **({"error": h["error"]} if h.get("error") else {})}
                               for h in U.get("hosts") or []]
            sc = U.get("scan") or {}
            out["vulnerability_scan"] = (
                {"when": _at(sc["ts"]), "devices": sc.get("devices"),
                 "matches": {v["name"]: v.get("words") or f"{v['count']} at CVSS 7+"
                            for v in (sc.get("found") or {}).values()}}
                if sc.get("ts") else "not run yet")
        rep = a._last_report or {}
        hosts = (rep.get("host_logs") or {}).get("hosts") or []
        out["auth_logs_watched"] = [
            {"host": label(h.get("name"), h.get("ip")), "read_ok": h.get("ok"),
             **({"error": h["error"]} if h.get("error") else {}),
             "established_connections": h.get("established"),
             "failed_logins_recently": h.get("failed_auths_window"),
             **({"internet_scanners": f"{(h['noise_24h'] or {}).get('attempts', 0)} failed "
                                      f"passwords from {(h['noise_24h'] or {}).get('sources', 0)} "
                                      f"addresses since {_at((h['noise_24h'] or {}).get('since')) or '?'}"}
                if h.get("public") and h.get("noise_24h") else {})}
            for h in hosts] or "host-log watching is off"
        d = a._discovery or {}
        out["not_in_inventory"] = ({"count": d.get("unknown_count"),
                                    "devices": [{k: x.get(k) for k in ("ip", "mac", "host")}
                                                for x in (d.get("unknown") or [])[:15]]}
                                   if d else "UNKNOWN: DHCP not read yet")
        x = a.exposure.view()
        if x.get("enabled"):
            out["security_review"] = (
                {"reviewed": _at(x["reviewed"]), "summary": x.get("summary"),
                 "findings": [f"{f['severity']}: {label(f['name'], f['ip'])} — {f['title']}"
                              + (" (dismissed by the owner)" if f.get("dismissed") else "")
                              for f in x["findings"]]}
                if x.get("reviewed") else "not run yet — it runs after the morning's update check")
        sh = a.shell.view()
        out["sandbox_shell"] = ({"isolated": sh.get("ok"), "why": sh.get("why"),
                                 "checked": _at(sh.get("checked"))}
                                if sh.get("enabled") else "off")
        return out

    def _host_updates(self, ip: str, h: dict, now: float) -> dict:
        """One machine's update facts, with every package — the view() has counts only."""
        U = self.a.updates
        out = {"machine": label(h.get("name") or U._name(ip), ip), "kind": h.get("kind"),
               "read": _at(h.get("ts"))}
        if h.get("error"):
            out["error"] = h["error"]
            return out
        out["os"] = h.get("os") or (f"RouterOS {h['installed']}" if h.get("installed") else "")
        if h.get("kind") == "linux":
            ups = h.get("updates") or []
            out["packages_waiting"] = [
                {"package": u["pkg"], "new_version": u.get("version"),
                 **({"installed": u["from"]} if u.get("from") else {}),
                 "security": bool(u.get("security")),
                 **({"held_back_by_ubuntu": True} if u.get("phased") else {})} for u in ups]
            if h.get("reboot_since"):
                out["reboot_pending_since"] = _at(h["reboot_since"])
                out["reboot_asked_by"] = h.get("reboot_pkgs") or []
            if h.get("lists_ts") and now - h["lists_ts"] > 7 * 86400:
                out["warning"] = ("its package lists are old: it has not looked for updates "
                                  f"since {_at(h['lists_ts'])}, so what is waiting is UNKNOWN")
            out["kernel"] = h.get("kernel")
        elif h.get("kind") == "routeros":
            out.update(routeros_installed=h.get("installed"), latest=h.get("latest"),
                       channel=h.get("channel"), board=h.get("board"),
                       security_releases_in_between=h.get("security_releases") or [],
                       firmware=h.get("fw"), firmware_available=h.get("fw_new"))
        elif h.get("kind") == "homeassistant":
            out["updates_waiting"] = [{k: u.get(k) for k in ("title", "installed", "latest")}
                                      for u in h.get("ha_updates") or []]
        elif h.get("kind") == "esxi":
            out["release"] = h.get("release")
            out["note"] = "VMware publishes no feed: only the installed build is known"
        out["updatable_from_here"] = ("RouterOS and firmware" if ip in U.ros_upgradable() else
                                      "its apt packages" if ip in U.upgradable() else "no")
        out["findings"] = [f["text"] + (" (dismissed by the owner)" if f.get("dismissed") else "")
                           for f in U.findings() if f.get("ip") == ip]
        return out

    def _updates(self, ip, now, **_):
        U = self.a.updates
        if not U.enabled:
            return "the update check is switched off (updates.enabled)"
        hosts = (U.rec or {}).get("hosts") or {}
        if not hosts:
            return f"UNKNOWN: the daily check has not run yet (it runs at {U.at})"
        if ip:
            if ip not in hosts:
                return (f"{ip} is not in the update check. It covers: "
                        + ", ".join(label(h.get("name") or U._name(x), x) for x, h in hosts.items()))
            return self._host_updates(ip, hosts[ip], now)
        return {"checked": _at(U.rec.get("last_done")),
                "machines": [self._host_updates(x, h, now) for x, h in hosts.items()]}

    def _vulnerabilities(self, **_):
        sc = (self.a.updates.view().get("scan") or {})
        if not sc.get("ts"):
            return (f"not run yet — nmap with the vulners script on day {sc.get('day') or 1} of "
                    "each month" + (f"; last attempt: {sc['error']}" if sc.get("error") else ""))
        return {"when": _at(sc["ts"]), "devices_scanned": sc.get("devices"),
                **({"error": sc["error"]} if sc.get("error") else {}),
                "left_out": f"the groups {', '.join(sorted(self.a.updates.scan_deny)) or 'none'} "
                            "(version probes can crash such devices), lanowl's own host, anything "
                            "outside the main LAN",
                "check": sc.get("check"),
                "found": [{"device": label(v["name"], ip), "cvss7_matches": v["count"],
                           "summary": v.get("words"), "apply": v["confirmed"],
                           "cves": [{k: x.get(k) for k in ("id", "cvss", "product", "port",
                                                            "exploit", "verdict", "why")}
                                    for x in v["vulns"]]}
                          for ip, v in (sc.get("found") or {}).items()],
                "how_to_read": "each CVE the scan matched on a version was checked: a Debian/Ubuntu "
                               "machine's exact package against its distribution's security data "
                               "(OSV) — 'fixed' = fixed in its build; anything else against NVD's "
                               "affected versions — 'not_affected'; what was left, read by the model "
                               "against the machine's settings — 'not_applicable' with the reason, "
                               "or 'applies'. 'unclear' = a version too vague to compare. Only "
                               "'applies' at CVSS 7+ pages. cve_lookup looks one up again."}

    def _exposure(self, ip, **_):
        x = self.a.exposure
        if not x.enabled:
            return "the security review is switched off (exposure.enabled)"
        v = x.view()
        if not v.get("last"):
            return "UNKNOWN: the security review has not run yet (after the morning's update check)"
        facts = {k: ({"name": f["name"], "read_as": f["kind"], "facts": f.get("text")} if f.get("ok")
                     else {"name": f["name"], "could_not_read": f.get("error")})
                 for k, f in x.rec["facts"].items() if not ip or k == ip}
        return {"reviewed": _at(v.get("reviewed")), "read": _at(v["last"]),
                **({"error": v["error"]} if v.get("error") else {}),
                "summary": v.get("summary"),
                "pages_telegram": v["paging"] or f"not before {v['page_from']} (the owner's trial)",
                "findings": [{k: f.get(k) for k in ("ip", "name", "check", "severity", "title",
                                                     "evidence", "fix", "dismissed")}
                             for f in v["findings"] if not ip or f["ip"] == ip],
                "outside": v.get("outside"), "facts": facts}

    def _backups(self, **_):
        b = self.a.backups
        if not b.enabled:
            return "backups are switched off (backups.enabled)"
        return b.view()

    # --- one device --------------------------------------------------------------------------
    def _device(self, ip, now, **_):
        a = self.a
        if not ip:
            return {"error": "device needs ip="}
        if not a.inv.get(ip) and ip != a._self_ip:
            return {"error": f"{ip} is not in the inventory"}
        from .web import device_info
        out = device_info(a, ip)
        hosts = (a.updates.rec or {}).get("hosts") or {}
        if ip in hosts:
            out["updates"] = self._host_updates(ip, hosts[ip], now)
        p = a.pauses.get(ip)
        out["paused"] = ({"since": _at(p["ts"]), "by": p.get("by")} if p else False)
        for k in ("swept",):
            if out.get(k):
                out[k] = _at(out[k])
        for x in out.get("actions") or []:
            x["ts"] = _at(x.get("ts"))
        return out

    # --- what it did and decided ---------------------------------------------------------------
    def _actions(self, ip, since, limit, **_):
        ac = self.a.actions
        who = {"audit": "the model, in the hourly audit", "telegram": "a question on Telegram",
               "dashboard": "a question on the dashboard"}
        out = []
        for p in reversed(ac.items):
            if p.get("ts", 0) < since or (ip and p.get("ip") != ip):
                continue
            o = p.get("outcome") or {}
            try:
                words = ac._status_words(p)
            except Exception:           # one odd record must not cost the whole answer
                words = p.get("status")
            e = {"id": p.get("id"), "at": _at(p.get("ts")),
                 "action": CATALOG.get(p.get("action"), p.get("action")),
                 "device": label(p.get("name"), p["ip"]) if p.get("ip") else "",
                 "asked_by": (f"the owner, on {p.get('via')}" if p.get("owner")
                              else who.get(p.get("via"), p.get("via"))),
                 "reason": p.get("reason") or "", "status": p.get("status"),
                 "what_became_of_it": words}
            if p.get("refused"):
                e["refused_because"] = p["refused"]
            for k in ("result", "error", "check"):
                if o.get(k):
                    e[k] = str(o[k])[:400]
            if p.get("action") == "investigate":
                e["checks"] = [f"{s.get('label')}: {str(s.get('summary'))[:160]}"
                               for s in (p.get("steps") or [])[:8]]
                if p.get("findings"):
                    e["findings"] = p["findings"][:500]
            out.append(e)
            if len(out) >= limit:
                break
        first = min((p.get("ts", 0) for p in ac.items), default=None)
        return {"actions": out, "record_starts": _at(first) or "empty — nothing proposed yet"}

    def _events(self, kind: str, since: float, limit: int = 1000) -> list:
        try:
            return self.a.state.events(since, kind=kind, limit=limit)
        except Exception:
            return []

    def _first_event(self, kind: str) -> Optional[float]:
        try:
            r = self.a.state.conn.execute("SELECT MIN(ts) t FROM events WHERE kind=?",
                                          (kind,)).fetchone()
            return r["t"] if r else None
        except Exception:
            return None

    def _telegram(self, since, limit, search, **_):
        ok = _match(search)
        out = []
        for e in self._events("telegram", since):
            try:
                d = json.loads(e["detail"]) if str(e["detail"]).startswith("{") else {}
            except ValueError:
                d = {}
            text = d.get("text")
            if text is None:
                # an older row kept only the channel; the last 80 are in memory
                m = next((s for s in self.a._sent_log if abs(s["ts"] - e["ts"]) < 2), None)
                text = m["text"] if m else "(its text was not kept)"
            if not ok(text):
                continue
            out.append({"at": _at(e["ts"]), "channel": d.get("channel") or e["detail"],
                        "text": re.sub(r"</?[a-z]+>", "", text)[:1200]})
            if len(out) >= limit:
                break
        return {"messages": out, "record_starts": _at(self._first_event("telegram"))}

    def _log_checks(self, since, limit, search, **_):
        ok = _match(search)
        out, n, probs = [], 0, 0
        for e in self._events("finding", since):
            try:
                f = json.loads(e["detail"])
            except (ValueError, TypeError):
                continue
            n += 1
            probs += bool(f.get("problem"))
            if not ok(" ".join(str(f.get(k) or "") for k in ("source", "summary", "detail"))):
                continue
            if len(out) < limit:
                out.append({"at": _at(e["ts"]), "source": f.get("source"),
                            "about": finding_kind(f),
                            "lines": f.get("lines"), "problem": bool(f.get("problem")),
                            "severity": f.get("severity"), "summary": f.get("summary"),
                            **({"detail": f["detail"]} if f.get("detail") else {})})
        return {"verdicts": out, "in_window": {"total": n, "problems": probs},
                "record_starts": _at(self._first_event("finding"))}

    def _audits(self, since, limit, **_):
        out = []
        for e in self._events("audit", since, limit):
            try:
                d = json.loads(e["detail"])
            except (ValueError, TypeError):
                continue
            out.append({"at": _at(e["ts"]), **d})
        first = self._first_event("audit")
        res = {"audits": out, "record_starts": _at(first)}
        if not first or first > since:
            res["note"] = ("UNKNOWN before " + (_at(first) or "now") + ": no audit was recorded "
                           "earlier — the lanowl_log topic may still have their 'LLM audit done' "
                           "and 'digest suppressed' lines")
        llm = (self.a._last_llm_report or {}).get("llm")
        if llm:
            res["latest_assessment"] = {"at": _at(getattr(self.a, "_last_llm_at", 0)),
                                        "health": llm.get("overall_health"),
                                        "summary": llm.get("summary")}
        return res

    def _pauses(self, since, **_):
        now_p = [{"device": label(e.get("name"), e["ip"]), "since": _at(e["ts"]), "by": e.get("by")}
                 for e in self.a.pauses.entries()]
        hist = []
        for k in ("pause", "resume"):
            for e in self._events(k, since):
                hist.append({"ts": e["ts"], "at": _at(e["ts"]), "what": k,
                             "detail": str(e["detail"])[:200]})
        hist.sort(key=lambda x: x.pop("ts"), reverse=True)
        return {"paused_now": now_p or "nothing is paused", "changes": hist}

    def _discovery(self, **_):
        d = self.a._discovery or {}
        if not d:
            return "UNKNOWN: the router's DHCP leases have not been read yet"
        def dev(x):
            return {**{k: v for k, v in x.items() if k != "first_seen"},
                    **({"first_seen": _at(x["first_seen"])} if x.get("first_seen") else {})}
        return {k: ([dev(x) for x in d[k]] if isinstance(d.get(k), list) and k in
                    ("unknown", "ignored", "recent_new") else d.get(k))
                for k in ("unknown_count", "unknown", "ignored", "new", "recent_new", "moved")
                if d.get(k) is not None} | {"read": _at(d.get("ts")),
                                           "new_means": "never on the main site's DHCP before, first "
                                                        "seen in the last day (recent_new)"}

    def _devices_seen(self, limit, search, **_):
        ok = _match(search)
        rows = [r for r in self.a.sites.seen()
                if ok(f"{r['mac']} {r.get('host')} {r.get('vendor')} {r.get('ip')} {r.get('name', '')} "
                      f"{r.get('site_name')}")]
        first = min((r["first_seen"] for r in rows if r.get("first_seen")), default=None)
        return {"count": len(rows), "kept_since": f"{_at(first) or 'now'} — every device, for good",
                "devices": [{**{k: v for k, v in r.items() if k not in ("first_seen", "last_seen")},
                             "first_seen": _at(r["first_seen"]), "last_seen": _at(r["last_seen"])}
                            for r in rows[:max(1, min(int(limit or 50), 200))]]}

    def _scan(self, **_):
        s = self.a.sites
        out = {"running": s.scanning, "runs": f"monthly, on day {s.scan_day} at {s.scan_at}, "
                                               "and when the owner presses Scan now",
               "last_started": _at(s.rec["scan"].get("last"))}
        for x in [s.get("home")] + s.remote():
            sc = s.rec["scan"].get(x["key"]) or {}
            out[x["name"]] = ({"scanned": _at(sc.get("ts")), "why": sc.get("why"),
                               "error": sc.get("error") or None,
                               "found": [f"{r['ip']} {r['mac']}" for r in sc.get("rows") or []]}
                              if sc else "UNKNOWN: never scanned yet")
        return out

    def _shell(self, since, limit, search, **_):
        ok = _match(search)
        boxes = [(k, sh) for k, sh in (("owner's questions", getattr(self.a, "shell", None)),
                                       ("audit, offline", getattr(self.a, "shell_audit", None)))
                 if sh is not None]
        runs = sorted(({"ts": x["ts"], "at": _at(x["ts"]), "sandbox": k, "via": x.get("via"),
                        "question": (x.get("q") or "")[:200], "command": x.get("cmd"),
                        "exit_code": x.get("rc"), "secs": x.get("secs"),
                        **({"timed_out": True} if x.get("timed_out") else {}),
                        **({"error": x["error"]} if x.get("error") else {})}
                       for k, sh in boxes for x in sh.log
                       if x.get("ts", 0) >= since and ok(f"{x.get('cmd')} {x.get('q')}")),
                      key=lambda r: r["ts"], reverse=True)[:limit]
        for r in runs:
            r.pop("ts")
        return {"isolation": {k: {"enabled": sh.enabled, "ok": sh.state.get("ok"),
                                  "why": sh.state.get("why"), "proven": _at(sh.state.get("ts"))}
                              for k, sh in boxes},
                "proven_when": "at lanowl's start, daily with the security review, and "
                               "whenever a sandbox restarted",
                "commands": runs}

    def _conversations(self, since, limit, search, **_):
        ok = _match(search)
        out = []
        chats = getattr(getattr(self.a, "dashboard", None), "chats", None)
        for c in (chats._convs.values() if chats is not None else []):
            for t in c.get("turns") or []:
                ts = t.get("done_ts") or c.get("updated") or 0
                if t.get("status") == "pending" or ts < since:
                    continue
                out.append({"ts": ts, "where": "dashboard", "q": t.get("q", ""),
                            "a": t.get("a", "")})
        for cid, c in (getattr(self.a.chat, "_tg", None) or {}).items():
            for t in c.get("turns") or []:
                if t.get("ts", 0) >= since:
                    out.append({"ts": t["ts"], "where": "telegram", "q": t.get("q", ""),
                                "a": t.get("a", "")})
        out = [x for x in out if ok(x["q"] + " " + x["a"])]
        out.sort(key=lambda x: x["ts"], reverse=True)
        return {"exchanges": [{"at": _at(x.pop("ts")), **x, "a": x["a"][:700]}
                              for x in out[:limit]],
                "kept": "the dashboard keeps its last 20 conversations; Telegram its last 6 "
                        "exchanges per chat (6 hours idle or /new starts over)"}

    def _auditor_log(self, since, limit, search, level, **_):
        path = str((self.a.cfg.get("logging") or {}).get("file") or "")
        if not path:
            return "lanowl writes no log file (logging.file)"
        path = os.path.abspath(path)
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - LOG_TAIL_BYTES))
                raw = fh.read().decode("utf-8", "replace")
        except OSError as e:
            return {"error": f"cannot read {path}: {e.strerror}"}
        ok = _match(search)
        floor = _LEVELS.get(level, 0)
        rows, first, cur = [], None, None
        for line in raw.splitlines():
            m = _LOGLINE.match(line)
            if m:
                try:
                    ts = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
                except ValueError:
                    continue
                first = first or ts
                cur = None
                if ts >= since and _LEVELS.get(m.group(2), 20) >= floor and ok(line):
                    cur = [line[:400]]
                    rows.append(cur)
            elif cur is not None and len(cur) < 6:
                cur.append(line[:300])           # a traceback's first lines
        rows = rows[-limit:]
        out = {"lines": [scrub("\n".join(r)) for r in rows],
               "file_starts": _at(first)}
        if first and first > since:
            out["note"] = f"UNKNOWN before {_at(first)}: the log file starts there (it rotates)"
        return out

    def _sites(self, **_):
        v = self.a.sites.view(self.a._last_report)
        for s in v["sites"]:
            if s.get("dhcp"):
                s["dhcp"]["read"] = _at(s["dhcp"].get("read"))
        return v

    def _services(self, **_):
        return [{"service": s.get("name"), "host": s.get("host"), "port": s.get("port"),
                 "ok": s.get("ok"), "detail": s.get("detail")}
                for s in ((self.a._last_report or {}).get("services") or [])] \
            or "UNKNOWN: no sweep has finished yet"

    def _review_bit(self) -> str:
        try:
            x = self.a.exposure.view()
        except Exception:
            return ""
        if not x.get("enabled") or not x.get("reviewed"):
            return ""
        fs = [f for f in x["findings"] if not f.get("dismissed")]
        worst = fs[0] if fs else None
        return (f"; the model's security review ({_at(x['reviewed'])}): {len(fs)} finding(s)"
                + (f", the worst {worst['severity']}: {label(worst['name'], worst['ip'])} — "
                   f"{worst['title']}" if worst else ""))

    RANK = {"critical": 0, "high": 1, "warning": 2, "info": 3}

    def security_items(self) -> list:
        """What matters, as the Security tab lists it: the
        update check's findings, the model's review, the security log problems of 24 h and the
        DHCP devices nobody knows — one list, by severity, each saying where it came from.
        The dashboard, /security and this tool read the same. The log events are open ones
        only: handled, they are the owner's business (Handled on the tab)."""
        a, out = self.a, []
        try:
            if a.updates.enabled:
                for f in a.updates.view().get("findings") or []:
                    out.append({"sev": "high" if f.get("page") else "info", "top": bool(f.get("page")),
                                "text": f["text"], "from": "the update check", "ip": f.get("ip"),
                                "dismissed": bool(f.get("dismissed"))})
            x = a.exposure.view()
            for f in x.get("findings") or []:
                out.append({"sev": f["severity"], "top": f["severity"] in ("critical", "high"),
                            "text": f"{label(f['name'], f['ip'])}: {f['title']}", "from": "the model's review",
                            "ip": f["ip"], "dismissed": bool(f.get("dismissed")),
                            "fix": f.get("fix") or ""})
        except Exception:
            log.warning("security items: a source failed", exc_info=True)
        # what the logs showed about access, until the owner marks it handled (seclog.py)
        for x in a.seclog.view()["open"]:
            n = int(x.get("count") or 1)
            out.append({"sev": "critical" if x["sev"] == "critical" else "high", "top": True,
                        "text": x["title"] + (f" ({n} times)" if n > 1 else ""),
                        "from": f"{x['source']}, {_at(x.get('last') or x['ts'])}", "ip": x["ip"],
                        "dismissed": False, "id": x["id"]})
        for s in a.sites.view(a._last_report)["sites"]:
            n = (s.get("dhcp") or {}).get("unknown") or 0
            if n:
                out.append({"sev": "info", "top": False, "from": "DHCP", "dismissed": False,
                            "text": f"{n} device{'s' if n > 1 else ''} on {s['name']}'s network that nobody knows"})
        return sorted(out, key=lambda i: self.RANK.get(i["sev"], 3))

    # --- the model's own scheduled looks (reviews.py) -----------------------------------------
    def _slow_changes(self, **_):
        return self.a.drift.view()

    def _config_changes(self, ip, since, limit, **_):
        v = self.a.configwatch.view()
        v["changes"] = [{**c, "ts": _at(c["ts"]), "since": _at(c.get("since"))} for c in v["changes"]
                        if c["ts"] >= since and (not ip or c["ip"] == ip)][:limit]
        return v

    def _fixes(self, search, **_):
        ok = _match(search)
        return {k: v for k, v in self.a.fixes.view()["items"].items() if ok(k + json.dumps(v, default=str))}

    def _scorecard(self, since, limit, **_):
        return self.a.scorecard.records(since, limit)

    # --- for the question's own context ----------------------------------------------------------
    def security_line(self) -> str:
        """One line for every question's context, so the model knows the Security tab exists
        and what is on it — the details are behind the tool."""
        U = self.a.updates
        if not U.enabled:
            return ""
        try:
            v = U.view()
        except Exception:
            log.warning("security line: the updates view failed", exc_info=True)
            return "SECURITY: UNKNOWN right now (the update record could not be read)."
        if not v.get("last"):
            return f"SECURITY: the daily update check has not run yet (it runs at {v.get('at')})."
        fs = v.get("findings") or []
        pages = [f["text"] for f in fs if f.get("page") and not f.get("dismissed")]
        hosts = v.get("hosts") or []
        waiting = sum(1 for h in hosts if h.get("updates"))
        reb = sum(1 for h in hosts if h.get("reboot_since"))
        dis = sum(1 for f in fs if f.get("dismissed"))
        return (f"SECURITY (checked {_at(v['last'])}): "
                + (f"{len(pages)} finding(s) that matter: " + "; ".join(pages[:4])
                   if pages else "nothing that matters")
                + f"; updates waiting on {waiting} machine(s), {reb} reboot(s) pending"
                + (f"; {dis} finding(s) dismissed by the owner" if dis else "")
                + self._review_bit()
                + ". Details: lanowl_records topic=security / updates / exposure / vulnerabilities.")
