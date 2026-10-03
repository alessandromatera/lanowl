"""lanowl's own dashboard, served from lanowl itself.

The process that knows the answers draws the page. `GET /` is one self-contained HTML
file (no CDN, no fonts from the internet — it has to work precisely when the internet is
down), which polls `GET /api/state`: the live report, the WAN watcher, the host logs, the
last model assessment with its diagnosis, the logbook and what Telegram was told. Four
things can be done from it: Check now, Ask — a conversation with the model, streamed and
stoppable (conversations.py, `GET /api/chat`) — pausing the monitoring of a
device switched off on purpose (pause.py), answering what the model proposes
(actions.py): Reject freely, Approve only with the PIN — and reading and editing the
model's memory (memory.py, More).

What cannot live here is the watchdog that notices lanowl itself dying: that one has to run
on another machine, reading the retained heartbeat.

Safety, for a page on the LAN:
  - it can only READ, plus start an audit or a question — the same model, the same
    read-only tools and whitelist as Telegram — and pause or resume a device, which is the
    one thing it changes: every pause and resume made here is also said on Telegram, so
    nobody on the LAN can quietly stop the monitor watching the alarm; and the model's memory,
    which changes what the model knows (and so how it reads a log), never what is watched;
  - approving a proposed action needs the PIN (`actions.pin_sha256`); the page remembers it
    once entered, and five wrong ones lock dashboard approvals and say so on Telegram;
  - POSTs must be JSON, so a web page elsewhere cannot fire them with a plain form
    (a cross-origin JSON POST needs a CORS preflight this server never grants);
  - the Host header must be an IP address (or a name in `web.allowed_hosts`), which is
    what defeats DNS rebinding — a hostile page cannot borrow a name that points here.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import sqlite3
import time
from typing import Optional

from . import timeline, wanexplain
from .conversations import Conversations
from .model import on_main_lan, wan_links
from .report import label, match_diagnosis

log = logging.getLogger("lanowl.web")

try:
    from aiohttp import web  # type: ignore
except Exception:  # pragma: no cover
    web = None

_HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(_HERE, "web", "index.html")
LLM_FRESH_S = 90 * 60      # an assessment older than this is shown, but as stale
# What the page may load besides itself: the home-screen icon and manifest, so that "Add to
# Home Screen" on a phone gives an app, not a screenshot. Named one by one — never a
# directory listing, never a path from the request.
STATIC = {"/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
          "/icon.svg": ("icon.svg", "image/svg+xml"),
          "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png")}


def state_payload(a, now: float = 0.0) -> dict:
    """Everything the page draws, from what lanowl already holds in memory."""
    now = now or time.time()
    rep = dict(a._last_report or {})
    llm_rep = a._last_llm_report or {}
    llm = llm_rep.get("llm") if llm_rep else None
    llm_at = getattr(a, "_last_llm_at", 0.0) or 0.0
    fresh = bool(llm) and (now - llm_at) <= LLM_FRESH_S
    llm_issues = list((llm or {}).get("issues") or [])

    issues, used = [], set()
    for i in rep.get("issues") or []:
        i = dict(i)
        i["label"] = label(i.get("device"), i.get("ip"))
        if fresh and i.get("severity") != "info":
            d = match_diagnosis(i, llm_issues)
            if d:
                used.add(id(d))
                i["diag"] = {"cause": d.get("root_cause"), "rec": d.get("recommendation")}
        issues.append(i)
    extra = ([{"label": label(d.get("device"), d.get("ip")), "severity": d.get("severity"),
               "cause": d.get("root_cause"), "rec": d.get("recommendation")}
              for d in llm_issues if id(d) not in used
              and d.get("severity") in ("critical", "high", "warning")][:5] if fresh else [])

    # The WAN's own history (events start ts, value seconds). The page is told when the
    # record begins and draws the time before it as "no record", not as a clean line.
    # One per moment (wanexplain.merge); the last few with the code's reading of where it
    # broke, for the Internet card's list.
    wan_events, events_since = [], None
    try:
        wan_events = wanexplain.moments(a.state, now - 7 * 86400)
        evs = wanexplain.evidence(a.state, wan_events[-3]["ts"] - 60) if wan_events else {}
        nw = getattr(a.wanwatch, "netwatch", None)
        for e in wan_events[-3:]:
            v = wanexplain.verdict(e, wanexplain.find(evs, e["ts"]), nw, links=wan_links(a.cfg))
            e.update(where=v["where"], why=v["short"])
        events_since = a.state.first_event_ts()
    except Exception:
        log.debug("wan events unavailable", exc_info=True)

    audit = a._audit_task
    auditing = audit is not None and not audit.done()
    # asked but not started yet: the loop sweeps first. Older than 5 min = the loop is stuck,
    # and a spinner forever would hide that
    asked = bool(a._check_asked) and now - a._check_asked < 300
    return {
        "now": now,
        "sweep": {"ts": rep.get("ts"), "sweeps": a._sweeps, "started": a._started},
        "about": {"model": (a.cfg.get("ollama") or {}).get("model", ""),
                  "llm_mode": (a.cfg.get("cadence") or {}).get("llm_mode", "interval"),
                  "llm_every_s": (a.cfg.get("cadence") or {}).get("llm_interval_s", 3600),
                  "llm_times": (a.cfg.get("cadence") or {}).get("llm_times") or []},
        "health": rep.get("overall_health"), "counts": rep.get("counts") or {},
        "summary": rep.get("summary"),
        "wan": {"state": rep.get("wan_state"), "ok": rep.get("wan_ok"),
                "path": rep.get("wan_path") or {}, "watch": rep.get("wan_watch") or {},
                "events": wan_events,
                "events_since": events_since,
                "links": wan_links(a.cfg)},
        "issues": issues,
        "llm": {"health": llm_rep.get("overall_health") if llm else None,
                "summary": (llm or {}).get("summary"), "at": llm_at or None,
                "fresh": fresh, "also": extra,
                "running": auditing or asked, "queued": asked and not auditing,
                "busy": bool(a._llm_busy)},
        # each device with its site (sites.py), and the sites themselves
        "devices": [{**x, "site": a.sites.of(x.get("ip")), **_listed(a, x.get("ip"))}
                    for x in rep.get("devices") or []],
        "sites": a.sites.view(rep)["sites"],
        "paused": rep.get("paused") or [],
        "pause": {"self_ip": a._self_ip},
        "model_switch": a.model_view(),
        "services": rep.get("services") or [],
        "shadowed": rep.get("shadowed") or {},
        "host_logs": rep.get("host_logs") or {},
        "findings": a.executor._findings(48),
        "discovery": {k: v for k, v in (a._discovery or {}).items()
                      if k in ("unknown", "unknown_count", "ignored", "new", "recent_new", "moved", "ts")},
        "logbook": (a._logbook_cache or {}).get("entries", [])[:200],
        "sent": list(reversed(a._sent_log[-60:])),
        "actions": a.actions.view(now),
        "memory": a.memory.view(),
        "shell": a.shell.view(),
        "shell_audit": a.shell_audit.view(),
        "weekly_last": a._weekly_last or None,
        "updates": a.updates.view(),
        "exposure": a.exposure.view(),
        "backups": a.backups.view(),
        # what the logs showed about access, until the owner marks it handled (seclog.py)
        "seclog": a.seclog.view(now),
        # the model's own looks (reviews.py), the fixes it wrote, its track record
        "drift": a.drift.view(),
        "configwatch": a.configwatch.view(),
        "fixes": a.fixes.view(),
        "scorecard": a.scorecard.view(),
    }


REBOOT_WAYS = {"routeros": "over ssh (RouterOS)", "ssh": "over ssh", "ssh_key": "over ssh, with lanowl's key",
               "reolink": "through its own web API", "homeassistant": "through Home Assistant's API",
               "ha_button": "through Home Assistant's restart button"}
BACKUP_WAYS = {"routeros": "its configuration export and binary backup",
               "homeassistant": "a full Home Assistant backup", "vps": "its keys and VPN configuration",
               "store": "its own files, tarred onto its disk", "files": "its configuration files",
               "esxi": "the host's configuration bundle and every VM's settings",
               "shellies": "every Shelly's settings"}


def device_info(a, ip: str) -> dict:
    """Everything lanowl knows about one machine, for its sheet: what it depends on, its
    checks, its history, its notes. Never a login: only whether one is known."""
    out: dict = {"ip": ip}
    dev = a.inv.get(ip)
    if dev is not None:
        at = dev.attrs
        out.update(name=dev.name, group=dev.group, criticality=dev.criticality,
                   note=dev.note or "", role=at.get("role") or "", mac=at.get("mac") or "",
                   dhcp=at.get("dhcp"), expect_offline=at.get("expect_offline") or "",
                   debounce_fails=at.get("debounce_fails"),
                   router_api=bool(at.get("mikrotik_rest")))
        out["checks"] = [{k: c.get(k) for k in ("type", "port", "name", "timeout_ms", "count", "iface")
                          if c.get(k) is not None} for c in dev.checks]
        parent = at.get("depends_on")
        if parent:
            out["depends_on"] = {"ip": parent, "name": "the internet" if parent == "wan"
                                 else a._name(parent, parent)}
        out["behind"] = [{"ip": d.ip, "name": d.name} for d in a.inv.devices
                         if d.attrs.get("depends_on") == ip]
    snap = a.executor.snapshot
    ds = snap.by_ip(ip) if snap is not None else None
    if ds is not None:
        out["now"] = [{"label": c.label(), "type": c.type, "port": c.port, "ok": c.ok,
                       "detail": c.detail, "latency_ms": c.latency_ms} for c in ds.checks]
        out["swept"] = snap.ts
    lease = next((l for l in (getattr(a.executor, "leases", None) or [])
                  if l.get("address") == ip), None)
    if lease:
        out["lease"] = {k: lease.get(k) for k in ("mac-address", "host-name", "status", "dynamic",
                                                   "comment", "expires-after", "last-seen")
                        if lease.get(k) not in (None, "")}
    rep_ = a._last_report or {}
    out["services"] = [x for x in rep_.get("services") or [] if x.get("ip") == ip]
    out["issues"] = [{k: i.get(k) for k in ("severity", "detail", "kind", "since")}
                     for i in rep_.get("issues") or [] if i.get("ip") == ip]
    ac = a.actions
    rb = ac.reboot.devices.get(ip)
    out["reboot"] = (REBOOT_WAYS.get(rb.get("via"), rb.get("via")) if rb else
                     "the Shelly's own restart (refused if a relay would change)"
                     if dev is not None and dev.name.lower().startswith("shelly") else "")
    uh = next((h for h in a.updates.hosts if h["ip"] == ip), None)
    out["update_check"] = bool(uh)
    out["update_here"] = ("RouterOS and its firmware" if ip in a.updates.ros_upgradable() else
                          "its apt packages" if ip in a.updates.upgradable() else "")
    bm = a.backups.machine(ip) if a.backups.enabled else None
    out["backup"] = ({"what": BACKUP_WAYS.get(bm["via"], bm["via"]), "snapshot": bm.get("snapshot") or ""}
                     if bm else None)
    obs = str((a.cfg.get("observer") or {}).get("host_ip") or "")
    grp = dev.group if dev is not None else ""
    out["scan"] = ("not scanned: lanowl's own host" if ip == obs else
                   "not scanned: only the main LAN is" if not on_main_lan(a.cfg, ip) else
                   f"not scanned: the {grp} group is left out (version probes crash it)"
                   if grp in a.updates.scan_deny else "in the monthly vulnerability scan")
    out["host_log"] = any(h.ip == ip for h in (getattr(a.hostlog, "hosts", None) or []))
    out["login_known"] = a.access.has(ip)
    out["actions"] = [{"id": p.get("id"), "title": ac.public(p)["title"], "status": p.get("status"),
                       "ts": p.get("done_ts") or p.get("ts"), "words": ac._status_words(p)}
                      for p in ac.items if p.get("ip") == ip][-6:][::-1]
    return out


class Dashboard:
    def __init__(self, auditor):
        self.a = auditor
        w = auditor.cfg.get("web") or {}
        self.enabled = bool(w.get("enabled", False)) and web is not None
        self.host = str(w.get("host", "0.0.0.0"))
        self.port = int(w.get("port", 8088))
        self.allowed_hosts = {str(h).lower() for h in (w.get("allowed_hosts") or [])}
        self._runner = None
        self.chats = Conversations(auditor)
        self._hist = (0.0, None)     # the Devices table's history: (when, body)
        self._hist_lock = asyncio.Lock()
        self._tl = (0.0, None)       # the Timeline: (when, body)
        self._streams: set = set()   # one queue per page listening on /api/stream
        self._push_task = None
        self._u7 = (0.0, {})         # each device's 7-day answered share: (when, {ip: pct})

    # --- guards -------------------------------------------------------------
    def _host_ok(self, request) -> bool:
        host = (request.host or "").rsplit(":", 1)[0].strip("[]").lower()
        if host in ("localhost",) or host in self.allowed_hosts:
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _json_ok(request) -> bool:
        return (request.content_type or "").lower() == "application/json"

    async def _guard(self, request, handler):
        if not self._host_ok(request):
            return web.Response(status=421, text="use the address, not a name")
        if request.method == "POST" and not self._json_ok(request):
            return web.Response(status=415, text="JSON only")
        resp = await handler(request)
        if resp.prepared:            # a stream (/api/stream) sent its own headers
            return resp
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    # --- routes -------------------------------------------------------------
    async def index(self, request):
        try:
            with open(INDEX, "rb") as f:
                body = f.read()
        except OSError:
            return web.Response(status=500, text="dashboard page missing from the image")
        return web.Response(body=body, content_type="text/html", charset="utf-8")

    async def api_state(self, request):
        return web.json_response(state_payload(self.a), dumps=_dumps)

    # --- live updates --------------------------------------------------------------------
    # Polling the whole state every 5 s costs ~150 KB each time, whether anything changed or
    # not. So the page listens here: the state is sent when it changes — a sweep, an
    # action's step, an audit starting — within 2 s, and a ping every 15 s says the line is
    # alive. The page still polls whenever this goes quiet (an old browser, a proxy, a drop).
    async def api_stream(self, request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store",
                                           "X-Accel-Buffering": "no", "X-Content-Type-Options": "nosniff"})
        await resp.prepare(request)
        q: asyncio.Queue = asyncio.Queue(maxsize=2)
        self._streams.add(q)
        if self._push_task is None or self._push_task.done():
            self._push_task = asyncio.create_task(self._pusher())
        try:
            await resp.write(b"retry: 5000\n\n" + _sse("state", state_payload(self.a)))
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    msg = b"event: ping\ndata: 1\n\n"
                await resp.write(msg)
        except (ConnectionError, RuntimeError):
            pass                     # the page went away
        finally:
            self._streams.discard(q)
        return resp

    async def _pusher(self):
        """While a page listens: every 2 s, the state if it changed since the last push —
        leaving out what changes on every read (the time, the package lists' ages). It
        starts from the state a page has just been sent on connecting."""
        try:
            last = _fingerprint(state_payload(self.a))
        except Exception:
            last = None
        while self._streams:
            await asyncio.sleep(2)
            try:
                body = state_payload(self.a)
                fp = _fingerprint(body)
            except Exception:
                log.exception("state push")
                continue
            if fp == last:
                continue
            last, msg = fp, _sse("state", body)
            for q in list(self._streams):
                if q.full():             # a slow page gets the newest state, not a backlog
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(msg)

    async def api_seen(self, request):
        """Every device ever seen on every site, newest first — the Logbook's New devices."""
        try:
            return web.json_response({"ok": True, "rows": self.a.sites.seen()})
        except Exception as e:
            log.warning("seen devices not read: %s", e)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def api_device(self, request):
        """One device's last 24h in 15-minute buckets, for the page's detail sheet. Only an
        address the sweep already knows — the query is parameterised anyway, but the page has
        no business asking about anything else."""
        ip = str(request.query.get("ip", ""))
        a = self.a
        known = {d.get("ip") for d in (a._last_report or {}).get("devices") or []}
        # machines the update check or the backups know without watching them
        known |= {h["ip"] for h in a.updates.hosts} | {m["ip"] for m in a.backups.machines}
        if ip not in known:
            return web.json_response({"ok": False, "error": "unknown device"}, status=404)
        now = time.time()
        try:
            info = device_info(a, ip)
        except Exception:
            log.exception("device info for %s", ip)
            info = {"ip": ip}
        return web.json_response({
            "ok": True, "ip": ip, "now": now, "bucket_s": 900, "since": now - 86400,
            "buckets": a.state.device_history(ip, now - 86400, 900),
            "uptime_7d": a.state.uptime_pct(ip, now - 7 * 86400),
            "info": info,
        }, dumps=_dumps)

    async def api_history(self, request):
        """Every watched device's last 24h in 15-minute buckets and its answered share over 7
        days, in one answer: the Devices table draws a sparkline and a percentage per row.
        Measured with ~60 devices: the 7-day shares take ~1 s, the buckets ~0.2 s — too long
        for the loop the sweep runs on. So they run in a thread on
        a read-only connection of their own (the database is WAL: a reader never blocks the
        sweep's writes), one at a time, cached: the buckets a minute, the shares ten minutes."""
        a, now = self.a, time.time()
        if self._hist[1] is not None and now - self._hist[0] < 60:
            return web.json_response(self._hist[1], dumps=_dumps)
        ips = [d.get("ip") for d in (a._last_report or {}).get("devices") or [] if d.get("ip")]
        want_u7 = now - self._u7[0] >= 600 or bool(set(ips) - set(self._u7[1]))
        try:
            async with self._hist_lock:
                if self._hist[1] is not None and time.time() - self._hist[0] < 60:
                    return web.json_response(self._hist[1], dumps=_dumps)
                buckets, u7 = await asyncio.to_thread(_histories, a.state.db_path, ips, now, want_u7)
        except Exception as e:
            log.exception("device histories")
            return web.json_response({"ok": False, "error": str(e)}, status=500)
        if u7 is not None:
            self._u7 = (now, u7)
        since = now - 86400
        body = {"ok": True, "now": now, "since": since, "bucket_s": 900,
                "devices": {ip: {"b": buckets.get(ip, []), "u7": self._u7[1].get(ip)} for ip in ips}}
        if ips:     # not before the first sweep: an empty answer would stick for a minute
            self._hist = (now, body)
        return web.json_response(body, dumps=_dumps)

    async def api_timeline(self, request):
        """Seven days as one stream (timeline.py): incidents grouped the way the alert
        gate groups them, the internet, Telegram, security, actions, new devices, log checks.
        Cached 30 s: every open page asks once a minute."""
        now = time.time()
        if self._tl[1] is not None and now - self._tl[0] < 30:
            return web.json_response(self._tl[1], dumps=_dumps)
        try:
            body = {"ok": True, **timeline.build(self.a, now)}
        except Exception as e:
            log.exception("timeline")
            return web.json_response({"ok": False, "error": str(e)}, status=500)
        self._tl = (now, body)
        return web.json_response(body, dumps=_dumps)

    async def api_wan_event(self, request):
        """One internet event, explained from what was kept (wanexplain.py): the
        Timeline's and the Internet card's rows open it."""
        try:
            ts = float(request.query.get("ts", ""))
        except ValueError:
            return web.json_response({"ok": False, "error": "bad ts"}, status=400)
        try:
            x = wanexplain.explain(self.a, ts)      # a few small queries: on the loop, like the rest
        except Exception as e:
            log.exception("wan event %s", ts)
            return web.json_response({"ok": False, "error": str(e)}, status=500)
        if x is None:
            return web.json_response({"ok": False, "error": "no such event"}, status=404)
        return web.json_response({"ok": True, **x}, dumps=_dumps)

    async def static(self, request):
        name, ctype = STATIC[request.path]
        try:
            with open(os.path.join(_HERE, "web", name), "rb") as f:
                body = f.read()
        except OSError:
            return web.Response(status=404)
        return web.Response(body=body, content_type=ctype)

    async def api_check(self, request):
        self.a.request_check()
        log.info("dashboard: Check now")
        return web.json_response({"ok": True})

    async def api_pause(self, request):
        """{"ip": ..., "paused": true|false} — the switch in a device's sheet."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "bad JSON"}, status=400)
        ip = str((body or {}).get("ip", ""))
        if not isinstance((body or {}).get("paused"), bool) or self.a.inv.get(ip) is None:
            return web.json_response({"ok": False, "error": "unknown device"}, status=400)
        r = self.a.set_paused(ip, body["paused"], "dashboard")
        return web.json_response(r, status=200 if r["ok"] else 409)

    async def api_model(self, request):
        """{"on": true|false} — the local model's switch, at the bottom of Now and on Ask."""
        body = await self._body(request)
        if body is None or not isinstance(body.get("on"), bool):
            return web.json_response({"ok": False, "error": "bad JSON"}, status=400)
        r = self.a.set_model(body["on"], "dashboard")
        return web.json_response(r, status=200 if r["ok"] else 409)

    async def api_action(self, request):
        """{"id", "approve": true|false, "pin"} — a proposal's buttons on the page. Approving
        needs the PIN; rejecting never does (it can only stop something). {"id", "end": true}
        closes an open investigation session; {"id", "cancel": true} takes an approved action
        out of the queue before its turn."""
        body = await self._body(request)
        if body is not None and (body.get("end") is True or body.get("cancel") is True):
            # End and Cancel: like Reject, they can only stop something — no PIN
            act = self.a.actions.end if body.get("end") is True else self.a.actions.cancel
            r = act(body.get("id"), "dashboard")
            return web.json_response(r, status=200 if r.get("ok") else 409)
        if body is None or not isinstance(body.get("approve"), bool):
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        if body["approve"]:
            ok, why = self.a.actions.check_pin(body.get("pin"))
            if not ok:
                msg = {"none": "No PIN is set up for the dashboard — approve on Telegram.",
                       "locked": "Too many wrong PINs — dashboard approvals are locked for now.",
                       "wrong": "Wrong PIN."}[why]
                return web.json_response({"ok": False, "pin": why, "error": msg}, status=403)
        r = self.a.actions.decide(body.get("id"), body["approve"], "dashboard")
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_reboot(self, request):
        """{"ip"} — the Reboot button in a device's sheet (and /api/upgrade: Install on the
        Updates card). Only PROPOSES it, with the same rules and check as the model's
        proposals; the page then approves it with the PIN like any other (api_action).
        {"ok", "id"} or {"ok": false, "error": why not}."""
        body = await self._body(request)
        ip = str((body or {}).get("ip") or "")
        if not ip or self.a.inv.get(ip) is None:
            return web.json_response({"ok": False, "error": "unknown device"}, status=400)
        action = "reboot"
        if request.path == "/api/upgrade":
            action = ("routeros_upgrade" if ip in self.a.updates.ros_upgradable()
                      else "apt_upgrade")
        r = await self.a.actions.ask(action, ip, "dashboard")
        if r.get("refused"):
            return web.json_response({"ok": False, "error": r["refused"]}, status=409)
        p = self.a.actions._get(r.get("proposal"))
        return web.json_response({"ok": True, "id": r.get("proposal"),
                                  "proposal": self.a.actions.public(p) if p else None})

    async def api_updates(self, request):
        """{"scan": false} — the update check now; {"scan": true} — the vulnerability scan now.
        Both read-only, like 'Run a full audit now': no PIN. {"dismiss": key, "note"} and
        {"undismiss": key}: the owner's dismissal of one thing that matters — no PIN either,
        like pausing a device (LAN-only page, every change in the log)."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        # the model's security review (exposure.py): its own findings, its own button
        x = self.a.exposure
        key = str(body.get("dismiss") or body.get("undismiss") or "")
        if key.startswith("exp:"):
            r = (x.dismiss(key, body.get("note") or "") if body.get("dismiss") else x.undismiss(key))
            return web.json_response(r, status=200 if r.get("ok") else 409)
        if body.get("review"):
            started = x.start("dashboard")
            log.info("dashboard: security review now (%s)", "started" if started else "already running")
            return web.json_response({"ok": x.enabled, "started": started,
                                      **({} if x.enabled else {"error": "the security review is off"})})
        u = self.a.updates
        if not u.enabled:
            return web.json_response({"ok": False, "error": "the update check is off"}, status=409)
        if body.get("dismiss") or body.get("undismiss"):
            r = (u.dismiss(str(body["dismiss"]), body.get("note") or "") if body.get("dismiss")
                 else u.undismiss(str(body["undismiss"])))
            return web.json_response(r, status=200 if r.get("ok") else 409)
        if body.get("verify"):
            # the scan's matches checked again (cves.py): no rescan, nothing probed
            started = self.a.cves.start("the owner's Check again")
            log.info("dashboard: CVE check now (%s)", "started" if started else "already running")
            return web.json_response({"ok": True, "started": started})
        started = u.start_scan("dashboard") if body.get("scan") else u.start("dashboard")
        log.info("dashboard: %s now", "vulnerability scan" if body.get("scan") else "update check")
        return web.json_response({"ok": True, "started": started})

    async def api_security(self, request):
        """{"handle": id, "pick": "me"|"fixed", "note"}: the owner has seen a security event the
        logs showed — it leaves What matters for Handled, with his words. {"unhandle": id} puts
        it back. No PIN, like a dismissal: it changes what the page lists, nothing on a machine."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        sl = self.a.seclog
        if body.get("handle"):
            r = sl.handle(str(body["handle"]), str(body.get("pick") or ""), str(body.get("note") or ""))
        elif body.get("unhandle"):
            r = sl.unhandle(str(body["unhandle"]))
        else:
            return web.json_response({"ok": False, "error": "handle or unhandle"}, status=400)
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_reviews(self, request):
        """The model's own looks (reviews.py): {"run": "drift"|"configwatch"} — now,
        read-only like Check now; {"dismiss": key, "note"} / {"undismiss": key} for a finding of
        the first. No PIN, like a dismissal on the Security tab."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        by = {r.NAME: r for r in self.a.reviews}
        if body.get("run"):
            r = by.get(str(body["run"]))
            if r is None or not r.enabled:
                return web.json_response({"ok": False, "error": "no such look, or it is off"}, status=409)
            started = r.start("dashboard")
            log.info("dashboard: %s now (%s)", r.NAME, "started" if started else "already running")
            return web.json_response({"ok": True, "started": started})
        key = str(body.get("dismiss") or body.get("undismiss") or "")
        r = next((x for x in self.a.reviews if getattr(x, "PREFIX", "") and key.startswith(x.PREFIX + ":")), None)
        if r is None:
            return web.json_response({"ok": False, "error": "run, dismiss or undismiss"}, status=400)
        res = r.dismiss(key, body.get("note") or "") if body.get("dismiss") else r.undismiss(key)
        return web.json_response(res, status=200 if res.get("ok") else 409)

    async def api_fix(self, request):
        """{"key": a finding's key}: the model writes its fix out (fixes.py). Nothing runs:
        it is text for the owner to apply themselves — no PIN."""
        body = await self._body(request)
        if body is None or not body.get("key"):
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        r = self.a.fixes.start(str(body["key"]))
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_scorecard(self, request):
        """{"id", "verdict": "right"|"partly"|"wrong"|"clear", "note"}: the owner's word on one of
        the model's diagnoses (scorecard.py) — it beats the grader's."""
        body = await self._body(request)
        if body is None or not body.get("id"):
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        r = self.a.scorecard.owner_says(str(body["id"]), str(body.get("verdict") or ""),
                                        str(body.get("note") or ""))
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_sites(self, request):
        """{"watch": {"site", "mac", "name"}}: watch a device seen on a site's DHCP; {"unwatch":
        ip}: stop; {"known": {"site", "mac", "known": bool}}: it belongs there (or undo). No PIN,
        like a pause — it adds or drops a ping or a count, nothing more."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        s = self.a.sites
        if isinstance(body.get("watch"), dict):
            w = body["watch"]
            r = s.watch(str(w.get("site") or ""), str(w.get("mac") or ""), str(w.get("name") or ""))
        elif body.get("unwatch"):
            r = s.unwatch(str(body["unwatch"]))
        elif isinstance(body.get("known"), dict):
            k = body["known"]
            r = s.know(str(k.get("site") or ""), str(k.get("mac") or ""), bool(k.get("known", True)))
        elif body.get("read"):
            s.rec["read"] = 0
            s.tick()
            r = {"ok": True}
        elif body.get("scan"):
            # every site's networks, from its own router: who answers, never a port
            r = s.start_scan("owner")
        else:
            r = {"ok": False, "error": "nothing to do"}
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_rename(self, request):
        """{"ip", "name"}: the owner's name for a watched device; {"site", "mac", "name"}: for
        one on a site's network. "" = back to the inventory's name. No PIN and no Telegram: it
        changes a label, and the Timeline shows it."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        r = self.a.rename(ip=str(body.get("ip") or ""), name=str(body.get("name") or ""),
                          site=str(body.get("site") or ""), mac=str(body.get("mac") or ""), by="dashboard")
        self._tl = (0.0, None)       # the Timeline shows it at once
        return web.json_response(r, status=200 if r.get("ok") else 409)

    async def api_backups(self, request):
        """{"ip": a machine} or {"ip": null} for all of them — Back up now. No PIN: it only
        copies configurations onto the homehub's disk."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        b = self.a.backups
        if not b.enabled:
            return web.json_response({"ok": False, "error": "backups are off"}, status=409)
        ip = body.get("ip") or None
        started = b.start(str(ip) if ip else None, "manual")
        log.info("dashboard: back up %s now (%s)", ip or "everything",
                 "started" if started else "one is already running")
        return web.json_response({"ok": started, "error": "" if started else
                                  "a backup is already running"}, status=200 if started else 409)

    async def api_memory(self, request):
        """{"op": "add", "text"} · {"op": "edit", "id", "text"} · {"op": "delete", "id"} — the
        owner's own changes to the model's memory (memory.py), from More. No PIN, like
        pausing: the page is LAN-only, and every change is in the log."""
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad request"}, status=400)
        m, op = self.a.memory, body.get("op")
        if op == "add":
            r = m.add(body.get("text"), by="owner", via="dashboard")
        elif op == "edit":
            r = m.edit(body.get("id"), body.get("text"), by="owner", via="dashboard")
        elif op == "delete":
            r = m.forget(body.get("id"), by="owner", via="dashboard")
        else:
            return web.json_response({"ok": False, "error": "unknown op"}, status=400)
        r.pop("change", None)
        return web.json_response(r, status=200 if r.get("ok") else 409)

    # --- Ask: conversations (conversations.py) ---------------------------
    async def api_chat(self, request):
        """One conversation (`?c=`), the recent ones, and what the model is doing — polled
        every second by the page while an answer is being written."""
        a = self.a
        audit = a._audit_task
        return web.json_response({
            "ok": True, "now": time.time(), "conv": self.chats.view(str(request.query.get("c", ""))),
            "recent": self.chats.recent(),
            "model": {"off": bool(a.no_llm), "cli": bool(a._no_llm_cli), "busy": bool(a._llm_busy),
                      "audit": audit is not None and not audit.done(),
                      "queued": len([t for t in self.chats.pending() if not t.get("started")])},
        }, dumps=_dumps)

    @staticmethod
    async def _body(request) -> Optional[dict]:
        try:
            body = await request.json()
        except Exception:
            return None
        return body if isinstance(body, dict) else None

    async def _chat_op(self, request, op):
        body = await self._body(request)
        if body is None:
            return web.json_response({"ok": False, "error": "bad JSON"}, status=400)
        out, status = op(body)
        return web.json_response(out, status=status)

    async def api_ask(self, request):
        """{"q": ..., "c": conversation or absent for a new one} -> {"c", "t"}. {"wan": ts}
        asks about one internet event: the facts the drawer shows go to the model with the
        question — built here, from what lanowl kept, never taken from the page."""
        body = await self._body(request)
        if body is not None and body.get("wan") is not None:
            try:
                x = wanexplain.explain(self.a, float(body["wan"]))
            except (TypeError, ValueError):
                x = None
            if x is None:
                return web.json_response({"ok": False, "error": "no such event"}, status=404)
            q = str(body.get("q") or "") or (
                f"What happened to the internet at {time.strftime('%H:%M:%S on %d/%m', time.localtime(x['ts']))}"
                f" ({x['title']})? Explain it from the evidence.")
            out, status = self.chats.ask(None, q, brief=f"{q}\n\n{x['brief']}")
            return web.json_response(out, status=status)
        return await self._chat_op(request, lambda b: self.chats.ask(b.get("c"), b.get("q")))

    async def api_ask_stop(self, request):
        return await self._chat_op(request, lambda b: self.chats.stop(b.get("c"), b.get("t")))

    async def api_ask_retry(self, request):
        return await self._chat_op(request, lambda b: self.chats.retry(b.get("c"), b.get("t")))

    async def api_chat_delete(self, request):
        return await self._chat_op(request, lambda b: self.chats.delete(b.get("c")))

    # --- lifecycle ------------------------------------------------------------
    async def start(self):
        if not self.enabled:
            log.info("web dashboard disabled (web.enabled=false)")
            return
        @web.middleware
        async def guard(request, handler):
            return await self._guard(request, handler)

        app = web.Application(middlewares=[guard], client_max_size=16 * 1024)
        app.router.add_get("/", self.index)
        app.router.add_get("/api/state", self.api_state)
        app.router.add_get("/api/device", self.api_device)
        app.router.add_get("/api/history", self.api_history)
        app.router.add_get("/api/timeline", self.api_timeline)
        app.router.add_get("/api/wan_event", self.api_wan_event)
        app.router.add_get("/api/stream", self.api_stream)
        app.router.add_get("/api/seen", self.api_seen)
        app.router.add_get("/api/chat", self.api_chat)
        for path in STATIC:
            app.router.add_get(path, self.static)
        app.router.add_post("/api/check", self.api_check)
        app.router.add_post("/api/ask", self.api_ask)
        app.router.add_post("/api/ask/stop", self.api_ask_stop)
        app.router.add_post("/api/ask/retry", self.api_ask_retry)
        app.router.add_post("/api/chat/delete", self.api_chat_delete)
        app.router.add_post("/api/pause", self.api_pause)
        app.router.add_post("/api/model", self.api_model)
        app.router.add_post("/api/action", self.api_action)
        app.router.add_post("/api/reboot", self.api_reboot)
        app.router.add_post("/api/upgrade", self.api_reboot)
        app.router.add_post("/api/updates", self.api_updates)
        app.router.add_post("/api/backups", self.api_backups)
        app.router.add_post("/api/sites", self.api_sites)
        app.router.add_post("/api/security", self.api_security)
        app.router.add_post("/api/memory", self.api_memory)
        app.router.add_post("/api/rename", self.api_rename)
        app.router.add_post("/api/reviews", self.api_reviews)
        app.router.add_post("/api/fix", self.api_fix)
        app.router.add_post("/api/scorecard", self.api_scorecard)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        log.info("web dashboard on http://%s:%d/", self.host, self.port)

    async def stop(self):
        if self._push_task is not None:
            self._push_task.cancel()
        if self._runner is not None:
            await self._runner.cleanup()


_VOLATILE = ("now", "lists_age")


def _strip(o):
    if isinstance(o, dict):
        return {k: _strip(v) for k, v in o.items() if k not in _VOLATILE}
    if isinstance(o, list):
        return [_strip(v) for v in o]
    return o


def _fingerprint(body: dict) -> str:
    """What the page would draw differently — the time and the package lists' ages, which
    change on every read, left out (nothing else does)."""
    import hashlib
    import json
    return hashlib.sha1(json.dumps(_strip(body), sort_keys=True, default=str).encode()).hexdigest()


def _sse(event: str, body) -> bytes:
    return f"event: {event}\ndata: {_dumps(body)}\n\n".encode()


def _listed(a, ip) -> dict:
    """{"listed": the list's name} for a device the owner renamed (names.py)."""
    d = a.inv.get(ip) if ip else None
    ln = (d.attrs or {}).get("listed_name") if d is not None else None
    return {"listed": ln} if ln and ln != d.name else {}


def _histories(db_path: str, ips: list, now: float, want_u7: bool):
    """/api/history's queries, in a worker thread on a read-only connection: the same SQL as
    StateStore.device_history and uptime_pct. Returns ({ip: buckets}, {ip: pct} or None)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    try:
        since, out, u7 = now - 86400, {}, None
        for ip in ips:
            rows = conn.execute(
                "SELECT CAST((ts - ?) / ? AS INTEGER) b, COUNT(*), SUM(up), AVG(latency), MAX(latency) "
                "FROM samples WHERE ip=? AND ts>=? GROUP BY b ORDER BY b", (since, 900, ip, since)).fetchall()
            out[ip] = [[since + b * 900, n, u or 0, round(av, 1) if av is not None else None,
                        round(mx, 1) if mx is not None else None] for b, n, u, av, mx in rows]
        if want_u7:
            u7 = {}
            for ip in ips:
                n, u = conn.execute("SELECT COUNT(*), SUM(up) FROM samples WHERE ip=? AND ts>=?",
                                    (ip, now - 7 * 86400)).fetchone()
                u7[ip] = round(100.0 * (u or 0) / n, 1) if n else None
        return out, u7
    finally:
        conn.close()


def _dumps(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, default=str)
