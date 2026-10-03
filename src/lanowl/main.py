"""lanowl's orchestrator + scheduler.

    python -m lanowl.main --once --no-llm     # dry run: one sweep, print table, no side effects
    python -m lanowl.main --once              # one sweep + one LLM audit, print result
    python -m lanowl.main                     # run forever (the container's command)

Cadence: a deterministic sweep every `sweep_interval_s` (owns detection + immediate
critical alerts); the LLM audit runs on a schedule (interval or fixed times) AND on a
new incident (with cooldown). The LLM never gates alerts.

Three clocks, none of which can stall another:
    sweep loop     `cadence.sweep_interval_s`   devices, services, the report, digests
    WAN watcher    `wan.watch.interval_s`       wanwatch.py, its own task
    host logs      `hostlog.interval_s`         hostlog.py, its own task
    LLM audit      `cadence.llm_interval_s`     its own task, bounded by `llm_max_wall_s`
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys
import time
from typing import Optional
from urllib.parse import urlsplit

from . import logbook, probes, weekly
from .access import Access
from .kinds import Kinds, report as kinds_report
from .actions import Actions
from .backups import Backups
from .configwatch import ConfigWatch
from .drift import Drift
from .fixes import Fixes
from .scorecard import Scorecard
from .updates import Updates
from .cves import Cves
from . import wanexplain
from .agent import LlmAgent
from .alerts import NEW, RECOVERED, STILL, AlertGate
from .chat import Chat
from .memory import Memory
from .names import Names, clean as clean_name, mac_key
from .model import load_config, load_inventory, router_host
from .oui import vendor
from .pause import Pauses, event_detail, intervals, overlaps
from .prompts import (WEEKLY_SYSTEM, build_user_context, build_weekly_context, system_prompt,
                      with_actions, with_shell_offline)
from .report import (_SEV_RANK, _html, build_report, digest_fingerprint, format_alerts,
                     format_diagnosis_note, format_digest, label, merge_llm)
from .exposure import Exposure
from .records import Records
from .seclog import SecLog
from .shell import Shell
from .sites import HOUSE, Sites
from .sinks import (MqttBridge, TelegramOutbox, TelegramPoller, TelegramRejected,
                    telegram_direct, telegram_edit)
from .state import StateStore, StatusTracker
from .sweep import (OLLAMA_KEY, CheckResult, apply_offline_grace, offline_by_design,
                    offline_mode_ips, run_sweep)
from .tools import ToolExecutor
from .hostlog import HostLogWatcher
from .wanwatch import WanWatcher
from .web import Dashboard

log = logging.getLogger("lanowl")

WAN_KEY = "__wan__"

# Issue kinds the sweep no longer alerts on, because the WAN watcher already owns them.
# The sweep still *reports* both for the dashboard, digest and LLM context — it just does
# not feed them to its own gate, which would page twice for one outage.
#   `wan`      no reachability at all: raised on the watcher's 15s clock, not this 60s one.
#   `wan-path` on the backup link. The route poll that detects it still runs here (it needs
#              the sweep's MikroTik session) but hands the result to the watcher via
#              `set_path`, so the level it sees and the completed flaps the watcher reads out
#              of the router log share ONE episode. Before that they were two issues in two
#              gates with no view of each other, and a 57s failover seen by both sent four
#              messages — two alerts and two recoveries — for one event.
WATCHER_OWNED_KINDS = ("wan", "wan-path")

# Issue kinds that never trigger the LLM incident triage. Their alert and recovery text is
# already fully deterministic (format_critical / format_recovery), so the model adds nothing —
# and the audit is awaited inside the sweep loop, so running it here stalls every sweep for
# the length of a cold model load. That stall lands exactly when the next sweep needs to run
# to notice the WAN is back, which turned every WAN blip into a multi-minute 'outage'.
NO_LLM_KINDS = ("wan", "wan-path")


class Auditor:
    def __init__(self, cfg, inv, mqtt, state, tracker, executor, agent, no_llm=False,
                 no_telegram=False, kinds=None):
        self.cfg = cfg
        self.inv = inv
        # what lanowl does with each device beyond watching it, and the owner's own kinds
        # (kinds.py) — planned before this, since every feature reads its list at its start
        self.kinds = kinds or Kinds()
        self.mqtt = mqtt
        self.state = state
        # history of a device no longer in the inventory is not read as the network's
        state.keep = inv.owns
        state.probed = inv.is_known      # an outage at an address no longer probed is over
        self.tracker = tracker
        self.executor = executor
        self.agent = agent
        # `--no-llm`: no model for this run, whatever the switch below says
        self._no_llm_cli = no_llm
        # The owner's switch for the local model (set_model): {"since", "by"} while
        # it is off, None while on. Read in every mode; written, like a pause, only once
        # resume_alerts() has turned persistence on.
        rec = self.state.load_record("model") or {}
        self._model_off = ({"since": float(rec.get("since") or 0), "by": str(rec.get("by") or "")}
                           if rec.get("off") else None)
        if self._model_off:
            log.info("the local model is switched off (since %s, by %s)",
                     time.strftime("%d/%m %H:%M", time.localtime(self._model_off["since"])),
                     self._model_off["by"] or "?")
        if agent is not None:
            agent.off = self.no_llm
        # A rehearsal (`--once --no-telegram`, the container's smoke run) must be able to
        # do everything a real sweep does EXCEPT reach the phone. With lanowl now
        # sending to Telegram itself, --no-mqtt alone no longer guarantees that.
        self.no_telegram = no_telegram
        self.cad = cfg.get("cadence", {})
        # Turns the per-sweep issue list into per-incident messages: one alert and one
        # recovery per episode, flaps folded in, everything from the same sweep batched
        # into a single Telegram message. See alerts.py.
        self.gate = AlertGate.from_config(cfg)
        self._last_incident_llm = 0.0
        self._last_digest = 0.0
        self._last_digest_fp = ""     # content of the last digest actually sent
        self._last_digest_sent = 0.0
        self._digest_news: set[str] = set()   # issue keys not yet carried by a digest
        # Issue keys Telegram has actually DELIVERED to the user as a non-critical problem
        # (i.e. carried by a digest that was really sent). Criticals recover on their own
        # path; these are what earns "...and now it's back" when they heal. Deliberately
        # not "every issue that ever opened": something that opened and healed between two
        # digests was never mentioned, so its recovery is not news either.
        self._told: set[str] = set()
        self._newdev_told: dict = {}      # MAC -> when a new device's one message went out
        # The gate, `_told`, `_digest_news` and the last digest are the record of what the
        # user has been told. resume_alerts() takes it back from SQLite and turns this on;
        # a `--once` rehearsal never does, so it can never overwrite the live record.
        self._persist_alerts = False
        # Devices the owner switched off on purpose (pause.py). Read in every mode, so
        # a rehearsal shows them paused too; written, like the alert record, only once
        # resume_alerts() has turned persistence on.
        # the owner's names (names.py), before anything reads a name: a pause is
        # restored by the name it was taken under
        self.names = Names(self.state.load_record("names"))
        self.names.apply(inv)
        self.pauses = Pauses()
        n = self.pauses.restore(self.state.load_record("paused"),
                                known={d.ip: d.name for d in inv.devices})
        if n:
            log.info("%d device(s) paused by the owner: %s", n,
                     ", ".join(e["name"] for e in self.pauses.entries()))
        self._self_ip = str((cfg.get("observer") or {}).get("host_ip", ""))
        # ip -> (until, why): a reboot the owner approved (reboot.py). Its silence is
        # expected, like a device asleep on schedule — never an alert. Memory only: a restart
        # mid-reboot just reports what it finds.
        self._holds: dict = {}
        self._ran_times: set[str] = set()
        self._last_report = None
        # Raw (un-debounced) WAN reachability of the current sweep. Whether an alert can leave
        # the network depends on the WAN as probed *right now*, not on the debounced status —
        # that only confirms two sweeps later, and a message sent in between would fail.
        self._wan_raw_ok = True
        self._loop = asyncio.get_running_loop()
        self._trigger = asyncio.Event()   # 'Check now' -> immediate audit
        self.mqtt.on_command = self._on_command
        self._last_discovery = 0.0
        self._discovery: dict = {}        # last DHCP-discovery result
        self._last_unknown_count = -1     # -1 so the first result is always logged
        self._mac_index = None            # MAC -> leased IP; None until first lease fetch
        self._wan_path = None             # last known {link, on_backup, detail}
        self._last_wan_path_check = 0.0
        self._iface_index = None          # router interface name -> interface dict
        self._last_iface_check = 0.0
        # only pay for the extra REST GET if some device is actually watched by its port
        self._wants_ifaces = any(c.get("type") == "link"
                                 for d in inv.devices for c in d.checks)
        self.outbox = TelegramOutbox(cfg.get("telegram", {}).get("outbox_file", "tg_outbox.json"))
        # Direct sends go out one at a time. A send can spend up to ~50s retrying across a
        # route flip, and two in flight at once could deliver a recovery before the
        # alert it recovers from.
        self._tg_lock = asyncio.Lock()
        # Fast WAN detection on its own clock and its own task. The sweep is too slow to see
        # a 57s failover and stalls for minutes behind the LLM audit; see wanwatch.py.
        self._llm_busy = False    # an audit is holding the model right now
        # One model, one job at a time: the audit, the weekly review and the owner's
        # questions take turns through this (see model_turn). The log triages do not queue
        # on it — they see `_llm_busy` and defer, as they always have.
        self._llm_lock = asyncio.Lock()
        self._audit_task = None   # the in-flight audit; the sweep never awaits it
        self._pending_digest_reason = None   # a digest asked for while an audit was running
        # when a 'Check now' was asked, until the loop has started its audit: the sweep that
        # runs first takes ~6s, and without this the dashboard saw nothing happen meanwhile
        self._check_asked: Optional[float] = None
        # key -> {"id", "text", "ts"}: the Telegram message that announced each incident, so
        # the incident triage can edit its diagnosis INTO it (edits never notify).
        self._alert_msgs: dict = {}
        self._weekly_task = None
        self._unload_task = None  # the switch going off: the model dropped from Ollama's memory
        self._weekly_last = 0.0
        self._incident_issues: dict = {}     # key -> issue, raised this sweep (see _diff_criticals)
        # --- for lanowl's own dashboard (web.py) ---
        # What Telegram was told, newest last — part of the alert record, so it survives a
        # restart.
        self._sent_log: list = []
        # The last audit's merged report, kept apart from `_last_report`, which the next
        # sweep replaces with a fresh deterministic one within a minute.
        self._last_llm_report: Optional[dict] = None
        self._last_llm_at = 0.0
        self._logbook_cache: Optional[dict] = None
        self._started = time.time()
        self._sweeps = 0          # published in the heartbeat: proof the loop is turning
        self._logbook_sent = False   # lanowl/logbook goes out once at startup, then per change
        # `agent` also lets it triage odd router-log lines; None when --no-llm, so the
        # ping/flap detection keeps working with the model out of the picture entirely.
        # What the logs showed about access, kept until the owner marks it handled
        # (seclog.py) — both watchers write to it, the Security tab reads it.
        self.seclog = SecLog(self.state)
        self.wanwatch = WanWatcher(cfg, self._wanwatch_alert, agent=None if no_llm else agent,
                                   llm_busy=lambda: self._llm_busy,
                                   model_on=lambda: not self.no_llm,
                                   on_event=self._on_event, seclog=self.seclog)
        # the last 24 h of blips, from the record: the digest and the Internet card counted
        # only those since the start, and a deploy made "0 short blips" out of one at 03:19
        try:
            self.wanwatch.blips = [(e["ts"], e["ts"] + e["s"]) for e in
                                   wanexplain.moments(self.state, time.time() - 86400) if e["kind"] == "blip"]
        except Exception:
            log.debug("blips not restored", exc_info=True)
        # The same treatment for the LOGS OF THE HOSTS themselves (a home server, a VPS).
        # Third task, third clock: an ssh round trip to a wedged box must not stall the ping
        # loop or the sweep, and it routes through `_wan_alert` so its findings inherit the
        # outbox.
        self.hostlog = HostLogWatcher(cfg, self._wan_alert,
                                      agent=None if no_llm else agent,
                                      llm_busy=lambda: self._llm_busy,
                                      model_on=lambda: not self.no_llm,
                                      wan_context=lambda: self.wanwatch._wan_context(time.time()),
                                      wan_down=lambda: self.wanwatch.blackout,
                                      on_event=self._on_event, seclog=self.seclog,
                                      # Cloudflare Access in front of the tunnel, checked
                                      # from outside the moment someone logs in through it
                                      access_check=lambda n: self.exposure._name_check(n))
        # first start with seclog.py: what the Security tab listed must not vanish
        self.seclog.seed(self.state.events(time.time() - 24 * 3600, "finding"),
                         lambda src: router_host(self.cfg) if src == "router log" else next(
                             (h.ip for h in self.hostlog.hosts if src == f"host log {h.name}"), ""))
        # the model's tools read what the watchers already hold
        self.executor.wanwatch = self.wanwatch
        self.executor.hostlog = self.hostlog
        self.dashboard = Dashboard(self)
        # The owner's questions, over lanowl's own bot and the dashboard's Ask box.
        self.chat = Chat(self)
        self.mqtt.on_ask = self.chat.on_mqtt
        # What the model may propose and the owner approves with a button (shadow mode:
        # nothing is executed). See actions.py.
        # The owner's device logins (secrets.yaml), for reboots, updates and backups.
        self.access = Access(cfg, inv)
        self.actions = Actions(self)
        self.executor.actions = self.actions
        # Updates, pending reboots, known vulnerabilities: daily, and a monthly scan.
        self.updates = Updates(self)
        # ...each of the scan's CVE matches checked against the machine's own build or NVD, and
        # read by the model: does it apply here? (cves.py)
        self.cves = Cves(self)
        self.executor.cves = self.cves
        # the sites (sites.py): the main one, the VPN hub, remote ones — and the remote devices the
        # owner picked from their DHCP, added to the inventory here
        self.sites = Sites(self)
        self.names.apply(self.inv)       # the devices watched from a site's network, named too
        # the model's daily security review, after the update check (exposure.py)
        self.exposure = Exposure(self)
        # Backups of the machines onto the owner's store: monthly, and before updates.
        self.backups = Backups(self)
        # The model's own scheduled looks, beyond the hourly audit (reviews.py): what is
        # slowly changing, what changed in the machines' configurations. None pages: what is
        # new rides the next digest, once.
        self.drift = Drift(self)
        self.configwatch = ConfigWatch(self)
        self.reviews = (self.drift, self.configwatch)
        # ...the fix for a finding, written out for the owner to apply themselves (never run), and
        # every diagnosis graded once its problem is over (fixes.py, scorecard.py)
        self.fixes = Fixes(self)
        self.scorecard = Scorecard(self)
        # Notes the model keeps across conversations (memory.py): written only in the
        # owner's own questions, read by every model run.
        self.memory = Memory(self)
        self.executor.memory = self.memory
        if self.agent is not None:
            self.agent.memory = self.memory
        # The model's shell, in the sandbox beside this container (shell.py): offered in
        # the owner's questions only, and only while its isolation is proven.
        self.shell = Shell(self)
        self.executor.shell = self.shell
        # ...and the hourly audit's own: offline, no internet, no DNS
        self.shell_audit = Shell(self, audit=True)
        self.executor.shell_audit = self.shell_audit
        # lanowl's own records (records.py): a question may be about anything lanowl knows,
        # did or decided
        self.records = Records(self)
        self.executor.records = self.records
        rec = self.state.load_record("telegram_chat") or {}
        self.poller = TelegramPoller(
            cfg, self.chat.on_telegram, offset=int(rec.get("offset") or 0),
            persist=lambda off: self.state.save_record("telegram_chat", {"offset": off}),
            on_callback=self.chat.on_callback)

    def _on_event(self, kind: str, value=None, detail: str = "", ts=None):
        """History for the weekly review: WAN outages, log-check verdicts, messages sent."""
        self.state.record_event(kind, value, detail or "", ts)

    @property
    def no_llm(self) -> bool:
        """No model: `--no-llm` for this run, or switched off by the owner (set_model)."""
        return self._no_llm_cli or self._model_off is not None

    @contextlib.asynccontextmanager
    async def model_turn(self):
        """Hold the model: one audit, review or answer at a time, and the log triages
        stand aside while it is held."""
        async with self._llm_lock:
            self._llm_busy = True
            try:
                yield
            finally:
                self._llm_busy = False

    def request_check(self):
        """'Check now', from the dashboard button or /check."""
        self._check_asked = time.time()
        self._loop.call_soon_threadsafe(self._trigger.set)

    def request_weekly(self, reason: str = "requested"):
        if self._weekly_task is not None and not self._weekly_task.done():
            return
        self._weekly_task = asyncio.ensure_future(self._run_weekly_guarded(reason))

    def _on_command(self, payload):
        """Invoked from the MQTT (paho) thread on lanowl/cmd -> wake the loop."""
        log.info("check-now command received: %r", str(payload)[:40])
        self.request_check()

    # --- one deterministic cycle ------------------------------------------
    async def sweep_cycle(self):
        await self._refresh_interfaces()
        snap, ollama = await asyncio.gather(
            run_sweep(self.cfg, self.inv, self._mac_index, self._iface_index),
            self._probe_ollama())
        snap.ollama = ollama
        from . import routeros
        rt = routeros.shared(self.cfg)
        snap.router_api = rt.status() if rt.enabled else None
        if ollama is not None:
            # one refused connection while Ollama restarts is not an outage: same debounce
            # as a device. build_report reads the confirmed status from down_ips.
            self.tracker.update(OLLAMA_KEY, ollama.ok)

        # debounce WAN + each device via the tracker. The *confirmed* status is what the
        # report sees: one sweep in which all targets happen to miss is a blip, not an
        # outage, and must not page — that needs `debounce_fails` consecutive failed sweeps,
        # the same rule devices get. (Previously the tracker could only force wan_ok False,
        # never hold it True while the debounce counted, so a single missed sweep alerted.)
        # snap.wan keeps the raw per-target results for the alert detail and for the
        # wan-path trouble heuristic, which must still react on the very first miss.
        self._wan_raw_ok = snap.wan_ok   # before the debounce rewrites it: can we send at all?
        self.tracker.update(WAN_KEY, snap.wan_ok)
        snap.wan_ok = self.tracker.status(WAN_KEY) is not False
        # The watcher probes 4x more often and confirms in ~30s, so when it says the WAN is
        # down it knows sooner than this loop does. Let it win, so the dashboard, digest and
        # LLM context agree with what was already paged. It cannot force the WAN *up*: the
        # sweep's own debounce stays authoritative for the healthy direction.
        if self.wanwatch.blackout:
            snap.wan_ok = False
            self._wan_raw_ok = False

        snap.wan_path = await self._check_wan_path(snap)

        new_transitions = []
        for d in snap.devices:
            # a device may carry its own `debounce_fails` (the WireGuard sites do)
            t = self.tracker.update(d.ip, d.up, debounce_fails=d.attrs.get("debounce_fails"))
            self.state.record_sample(d.ip, d.up, d.latency_ms,
                                     {"failed": d.failed_services()}, ts=snap.ts)
            if t:
                t.detail = d.name   # the history outlives inventory edits: name it now
                new_transitions.append(t)
                self.state.record_transition(t)
        self.state.commit()
        if new_transitions or not self._logbook_sent:
            self._publish_logbook(snap.ts)

        # Scheduled-offline gear dozing off / waking late is still 'asleep', not an outage.
        # Needs the tracker (how long it has been dark), so it runs after the debounce update
        # and before anything reads expected_down. History above keeps the raw truth.
        apply_offline_grace(self.cfg, snap, self.tracker)

        # Dead man's switch. A supervisor restarts a process that CRASHES; nothing notices
        # one that is merely stuck — a wedged socket, a hung ping subprocess, a host asleep —
        # and a monitor that has quietly stopped monitoring looks exactly like a network where
        # nothing is wrong. This is the one fact that cannot be self-reported: somebody else
        # has to observe its absence, so it is published retained for a watchdog on ANOTHER
        # machine (`<base_topic>/heartbeat`).
        self._sweeps += 1
        self.mqtt.publish("heartbeat", {
            "ts": snap.ts, "pid": os.getpid(), "sweeps": self._sweeps,
            "uptime_s": round(snap.ts - self._started),
            "interval_s": self.cad.get("sweep_interval_s", 60),
            "devices": len(snap.devices),
        }, retain=True)

        self.executor.snapshot = snap   # forensics needs the current picture
        report = self._make_report(snap)

        # WAN is back: deliver criticals queued during the outage BEFORE this cycle's
        # recovery message, so Telegram shows the events in the order they happened.
        # Gate on the raw probe, not the debounced status: the send happens now, so what
        # matters is whether the internet answers now.
        if self.outbox.pending and self._wan_raw_ok and not self.no_telegram:
            await self.outbox.flush(self.cfg, self._open_incident_keys(),
                                    on_sent=self._remember_alert)

        incident = self._diff_criticals(report, snap)
        self.actions.tick()        # a proposal nobody answered expires, and its buttons go
        self.shell.tick()          # the sandboxes' isolation: at start, then daily at most
        self.shell_audit.tick()    # (the security review proves it every morning too)
        self.sites.tick()          # the remote sites' DHCP, every half hour
        return snap, report, incident

    def _make_report(self, snap) -> dict:
        """The deterministic report for `snap`, kept for the dashboard and published.

        Also run straight after a pause or resume, on the last sweep's snapshot, so the
        page shows the change at once instead of up to a minute later."""
        for d in snap.devices:
            d.paused = self.pauses.is_paused(d.ip)
            if self.held_until(d.ip):
                d.held = d.expected_down = True
        down_ips = set(self.tracker.down_ips())
        # ...and WHEN each of them stopped answering, so the issue can say so. The first
        # miss, not the confirming sweep — see StatusTracker.down_since.
        report = build_report(snap, self.inv, down_ips, self.cfg,
                              down_since={ip: self.tracker.down_since(ip) for ip in down_ips})
        report = merge_llm(report, None)  # ensures a deterministic summary is present
        report["wan_watch"] = self.wanwatch.snapshot_state()
        if self.hostlog.enabled:
            report["host_logs"] = self.hostlog.snapshot_state()
        if self.wanwatch.enabled and self.wanwatch.observed:
            # ok | backup | down. The watcher probes 4x more often and owns the definition
            # of these three states, so the dashboard box follows it rather than the sweep's
            # own 60s-old answer. Same reason `snap.wan_ok` above defers to it. `observed`
            # keeps `--once` — which builds the watcher but never runs its loop — from
            # overwriting a real answer with an untouched default.
            report["wan_state"] = report["wan_watch"]["state"]
        answering = {d.ip: d.up for d in snap.devices}
        report["paused"] = [
            {"ip": e["ip"], "name": self._name(e["ip"], e["name"]), "ts": e["ts"],
             "by": e["by"], "up": answering.get(e["ip"])}
            for e in self.pauses.entries()]
        if self._model_off:
            report["model_off"] = dict(self._model_off)
        self._last_report = report
        self.mqtt.publish("status", report, retain=True)
        return report

    def _name(self, ip: str, fallback: str = "") -> str:
        dev = self.inv.get(ip)
        return dev.name if dev else (fallback or ip)

    # --- paused devices (pause.py) ----------------------------------
    def set_paused(self, ip: str, paused: bool, by: str, now: Optional[float] = None) -> dict:
        """Pause or resume one device. `by`: dashboard | telegram.

        Returns {"ok", "changed", "text"}, `text` being what the owner is told. From the
        dashboard it also goes to Telegram: the page has no login, so a pause must never
        be silent. From Telegram it is the reply, which the caller sends."""
        dev = self.inv.get(ip)
        if dev is None:
            return {"ok": False, "changed": False,
                    "text": f"{ip} is not a device lanowl watches."}
        who = _html(label(dev.name, ip))
        now = time.time() if now is None else now
        if paused:
            if ip == self._self_ip:
                return {"ok": False, "changed": False,
                        "text": f"{who} is lanowl itself — it cannot be paused."}
            e = self.pauses.pause(ip, dev.name, by, now)
            if e is None:
                return {"ok": True, "changed": False, "text": f"{who} was already paused."}
            self._forget_incidents(ip)
            text = self._pause_text(dev, by)
        else:
            e = self.pauses.resume(ip)
            if e is None:
                return {"ok": True, "changed": False, "text": f"{who} was not paused."}
            src = " — from the dashboard" if by == "dashboard" else ""
            still = ("\n<i>It is still unreachable, so from now on it is reported as down.</i>"
                     if self.tracker.status(ip) is False else "")
            text = f"▶️ <b>Monitoring resumed</b>{src}\n{who}{still}"
        self._on_event("pause" if paused else "resume", None, event_detail(ip, dev.name, by), now)
        self._save_pauses()
        log.info("%s %s (%s) — by %s", "PAUSED" if paused else "RESUMED", dev.name, ip, by)
        if by != "telegram":
            self._emit_telegram("digest", text)
        if self.executor.snapshot is not None:
            self._make_report(self.executor.snapshot)
        self._publish_logbook(now)     # its outages are drawn as paused from now on
        return {"ok": True, "changed": True, "text": text}

    # --- the owner's names (names.py) ------------------------------------------
    def rename(self, ip: str = "", name: str = "", site: str = "", mac: str = "",
               by: str = "dashboard", now: Optional[float] = None) -> dict:
        """Name a device: a watched one by its address, or one on a site's network by site
        and MAC. "" = back to the inventory's name. No PIN and no Telegram: it changes a label,
        and the Timeline shows it. An open incident carries on under the
        new name — the gate, what the digests told, the sent and the queued alerts are
        re-keyed — so nothing is announced as new, nor as recovered."""
        now = time.time() if now is None else now
        name = clean_name(name)
        dev = self.inv.get(ip) if ip else None
        if ip and dev is None:
            return {"ok": False, "error": f"{ip} is not a device lanowl watches"}
        if dev is None:
            if not site or not mac:
                return {"ok": False, "error": "which device?"}
            k = mac_key(site, mac)
            old = self.names.macs.get(k, "")
            self.names.set_key("mac", k, name)
            # the same MAC, watched from there: it takes the name too
            dev = next((d for d in self.inv.devices if Names.key(d) == ("mac", k)), None)
            if dev is None:
                self.state.save_record("names", self.names.dump())
                if old != name:
                    self._on_event("rename", None, json.dumps({"site": site, "mac": k.split("|", 1)[1], "from": old,
                                                               "to": name, "by": by}, ensure_ascii=False), now)
                    log.info("RENAMED %s on %s: %r -> %r (%s)", mac, site, old, name, by)
                return {"ok": True, "changed": old != name, "name": name}
        listed = (dev.attrs or {}).get("listed_name") or dev.name
        new, old = name or listed, dev.name
        self.names.set(dev, "" if new == listed else new)
        self.state.save_record("names", self.names.dump())
        if new == old:
            return {"ok": True, "changed": False, "name": new, "listed": listed}
        self.inv.rename(dev, new)
        self._rekey(dev.ip, old, new)
        self.pauses.renamed(dev.ip, new)
        self._save_pauses()
        self._on_event("rename", None, json.dumps({"ip": dev.ip, "from": old, "to": new, "by": by},
                                                  ensure_ascii=False), now)
        log.info("RENAMED %s: %r -> %r (%s)", dev.ip, old, new, by)
        if self.executor.snapshot is not None:
            self._make_report(self.executor.snapshot)
        self._publish_logbook(now)
        return {"ok": True, "changed": True, "name": new, "listed": listed}

    def _rekey(self, ip: str, old: str, new: str):
        """Issue keys carry the device's name (_key: kind:ip:group:device): every record of
        what the owner was told moves to the new one."""
        def nk(k):
            p = str(k).split(":", 3)
            return f"{p[0]}:{ip}:{p[2]}:{new}" if len(p) == 4 and p[1] == ip and p[3] == old else k
        n = self.gate.rekey(nk)
        self._told = {nk(k) for k in self._told}
        self._digest_news = {nk(k) for k in self._digest_news}
        self._alert_msgs = {nk(k): v for k, v in self._alert_msgs.items()}
        self._incident_issues = {nk(k): ({**v, "device": new} if nk(k) != k else v)
                                 for k, v in self._incident_issues.items()}
        self.outbox.rekey(nk)
        if n:
            log.info("carried %d open incident(s) of %s over to its new name", n, ip)
        self._save_alert_record()

    # --- the owner's switch for the local model ------------------------------------------
    def set_model(self, on: bool, by: str, now: Optional[float] = None) -> dict:
        """Switch the local model on or off. `by`: dashboard | telegram.

        Off: Ollama is asked nothing — no audits, no diagnosis on alerts, no cause lines in the
        digest, no weekly note, no security review, no log triage, no answers. Whatever it is
        doing stops at once and ends as a model that failed (LlmAgent.cut), the model is
        unloaded from the model server, and the Ollama check is no longer probed, so stopping
        Ollama does not page. The sweep, the alerts and the digests go on without it (_digest_without_model).
        It comes back on only by hand, and, as with a pause, a switch made on the dashboard
        is said on Telegram. Returns {"ok", "changed", "text"}."""
        now = time.time() if now is None else now
        if self._no_llm_cli or self.agent is None:
            return {"ok": False, "changed": False,
                    "text": "lanowl was started with --no-llm: there is no model to switch on."}
        if on == (self._model_off is None):
            return {"ok": True, "changed": False,
                    "text": f"The local model is already {'on' if on else 'off'}."}
        src = " — from the dashboard" if by == "dashboard" else ""
        if on:
            self._model_off = None
            self.agent.off = False
            text = (f"🦉 <b>The owl is awake</b> — local model on{src}\n<i>Audits, diagnoses, answers and reviews are "
                    f"back. The first one loads the model, so it takes longer.</i>")
        else:
            self._model_off = {"since": now, "by": by}
            self.agent.off = True
            n = self.agent.cut() + self.dashboard.chats.stop_all("Stopped — the model was switched off.")
            # its check is no longer probed: an open Ollama incident would otherwise end as
            # "back online" once the issue is gone from the report
            self._forget(lambda i: i.get("device") == "Ollama" and i.get("group") == "services",
                         "Ollama")
            self._unload_task = asyncio.ensure_future(self._unload_model())
            text = (f"🦉 <b>The owl is asleep</b> — local model off{src}\n<i>No audits, diagnoses, answers or reviews "
                    f"until you switch it back on (/model on, or on the dashboard). Alerts and "
                    f"digests go on without it.</i>" + ("\nWhat it was doing has been stopped." if n else ""))
        self._on_event("model", 1 if on else 0, by, now)
        self._save_model_switch()
        log.info("LOCAL MODEL %s — by %s", "ON" if on else "OFF", by)
        if by != "telegram":
            self._emit_telegram("digest", text)
        if self.executor.snapshot is not None:
            self._make_report(self.executor.snapshot)
        return {"ok": True, "changed": True, "text": text}

    def model_view(self) -> dict:
        m = self._model_off or {}
        return {"on": not self.no_llm, "cli": self._no_llm_cli, "since": m.get("since"),
                "by": m.get("by"), "name": (self.cfg.get("ollama") or {}).get("model", "")}

    async def _unload_model(self):
        if await self.agent.unload():
            log.info("model %s unloaded from Ollama", self.agent.model)

    def _save_model_switch(self):
        if not self._persist_alerts:
            return
        try:
            self.state.save_record("model", {"off": True, **self._model_off} if self._model_off
                                   else {"off": False})
        except Exception as e:     # never let the bookkeeping cost a sweep
            log.warning("model switch not saved: %s", e)

    def _pause_text(self, dev, by: str) -> str:
        who = _html(label(dev.name, dev.ip))
        src = " — from the dashboard" if by == "dashboard" else ""
        how = "Not watched until you /resume it (or switch it back on in the dashboard)."
        crit = ("\n⚠️ A critical device: nothing about it will page you while it is paused."
                if dev.criticality == "critical" else "")
        return f"⏸ <b>Monitoring paused</b>{src}\n{who}\n<i>{how}</i>{crit}"

    def _forget_incidents(self, ip: str):
        """A device just paused, or about to reboot: close its open incidents without a word
        (AlertGate.forget) and forget that a digest ever named them, so no "back online" is
        owed either."""
        self._forget(lambda i: i.get("ip") == ip and i.get("kind") in ("down", "degraded"), ip)

    def _forget(self, match, what: str):
        keys = self.gate.forget(match)
        for k in keys:
            self._told.discard(k)
            self._digest_news.discard(k)
            self._alert_msgs.pop(k, None)
            self._incident_issues.pop(k, None)
        if keys:
            log.info("closed %d open incident(s) for %s without a recovery", len(keys), what)
            self._save_alert_record()

    # --- reboots in progress (reboot.py) ---------------------------
    def hold(self, ips, until: float, why: str = ""):
        """Hold these devices' alerts until `until` (0 = end the hold now). A device with an
        open incident has it closed without a word first: excused mid-incident, the gate
        would otherwise announce it "back online"."""
        now = time.time()
        for ip in ips:
            if until > now:
                if ip not in self._holds:
                    self._forget_incidents(ip)
                    log.info("alerts held for %s until %s (%s)", ip,
                             time.strftime("%H:%M", time.localtime(until)), why)
                self._holds[ip] = (until, why)
            elif self._holds.pop(ip, None) is not None:
                log.info("alerts no longer held for %s", ip)

    def held_until(self, ip: str) -> float:
        h = self._holds.get(ip)
        if h is None:
            return 0.0
        if h[0] <= time.time():
            self._holds.pop(ip, None)
            return 0.0
        return h[0]

    def _save_pauses(self):
        if not self._persist_alerts:
            return
        try:
            self.state.save_record("paused", self.pauses.dump())
        except Exception as e:     # never let the bookkeeping cost a sweep
            log.warning("pause record not saved: %s", e)

    def _pause_intervals(self, now: float) -> dict:
        """{ip: [(start, end)]} of every pause in the last 90 days (the events table)."""
        try:
            evs = [e for k in ("pause", "resume")
                   for e in self.state.events(now - 90 * 86400, kind=k, limit=2000)]
        except Exception:
            evs = []
        return intervals(evs, self.pauses.dump(), now)

    async def _refresh_interfaces(self):
        """Refresh the router's interface table for `link` checks (throttled).

        One extra read-only router read per interval; skipped entirely when no device uses
        a `link` check. A stale index is kept on a failed fetch rather than turning every
        link-checked device down because the router was briefly unreachable."""
        if not self._wants_ifaces:
            return
        now = time.time()
        if self._iface_index is not None and \
                (now - self._last_iface_check) < self.cfg.get("mikrotik", {}).get("interface_interval_s", 60):
            return
        self._last_iface_check = now
        from .discovery import fetch_interfaces
        idx = await fetch_interfaces(self.cfg)
        if idx is not None:
            self._iface_index = idx

    async def _check_wan_path(self, snap):
        """Poll which link carries the default route (main vs backup link).

        Throttled to `wan.path.interval_s` so the router log isn't flooded with one
        REST login per sweep — but checked every sweep while WAN targets are failing
        (that's exactly when a failover happens) and while on the backup (to catch
        the switch back quickly). Skipped altogether while the WAN watcher is reading it
        over the router API."""
        pcfg = self.cfg.get("wan", {}).get("path")
        if not pcfg:
            return None
        now = time.time()
        if self.wanwatch.path_is_fresh(now):
            # The watcher reads the route itself every ping round while the router API is up
            # (no login per read there); a second poll from here would only race it.
            self._wan_path = self.wanwatch.path
            return self._wan_path
        trouble = (not snap.wan_ok) or any(not ok for ok in snap.wan.values()) or \
            (self._wan_path or {}).get("on_backup")
        if trouble or (now - self._last_wan_path_check) >= pcfg.get("interval_s", 300):
            self._last_wan_path_check = now
            from .discovery import fetch_wan_path
            wp = await fetch_wan_path(self.cfg)
            if wp is not None:
                self._wan_path = wp
                # The watcher logs and alerts on it — see WATCHER_OWNED_KINDS.
                self.wanwatch.set_path(wp)
        return self._wan_path

    async def _probe_ollama(self):
        """The model server, as a named service rather than a device.

        A ping of the model's host and an open port are not a working model. What matters is
        whether lanowl can use the model, so it asks the URL it actually calls (from a
        container, perhaps host.docker.internal). None with the LLM off: nothing needs it."""
        if self.no_llm or self.agent is None:
            return None
        r = await probes.ollama_check(self.agent.url, self.agent.model,
                                      self.cfg.get("probes", {}).get("http_timeout_ms", 4000))
        return CheckResult("ollama", r.ok, urlsplit(self.agent.url).port, r.detail,
                           r.latency_ms, r.data, name="Ollama")

    def _diff_criticals(self, report, snap) -> bool:
        """Hand this sweep's criticals to the alert gate and send whatever it lets
        through. Returns True if something newly announced warrants an incident LLM.

        The gate — not this method — decides what is worth saying: a device that drops,
        comes back and drops again is one incident, and everything raised in the same
        sweep leaves as one message."""
        # Everything worth reporting goes through the gate, but the two tiers leave by
        # different doors — this is the difference between "the internet dropped" and "the
        # TV is off":
        #   critical  -> pages immediately, on the edge, one message per incident;
        #   warning/high -> never pages. It only earns the *next* digest the right to be
        #                sent. A standing problem is therefore reported once, not every
        #                hour for as long as it lasts.
        # A device paused while this sweep was in flight (the outbox flush above awaits)
        # is left out too: its incident was just forgotten, and must not reopen as NEW.
        current = {self._key(i): i for i in report["issues"]
                   if i.get("kind") not in WATCHER_OWNED_KINDS
                   and not self.pauses.is_paused(i.get("ip"))}
        events = self.gate.update(current, now=snap.ts)

        crit = [e for e in events if e.issue.get("severity") == "critical"]
        rest = [e for e in events if e.issue.get("severity") != "critical"]

        for e in events:
            if e.kind == RECOVERED:
                log.info("RECOVERED %s (down %.0fs, %d flap(s))",
                         e.issue["device"], e.duration_s, e.flaps)
            else:
                # log level follows the issue's own severity: a switched-off TV is an
                # INFO event and must not show up when grepping the log for WARNING
                sev = e.issue.get("severity", "info")
                emit = log.warning if sev in ("critical", "high") else log.info
                emit("%s%s %s: %s", sev.upper(), " (still)" if e.kind == STILL else "",
                     e.issue["device"], e.issue["detail"])
        # A batched message covers several incidents and so belongs to no single one; only a
        # message about exactly one incident can be tagged with its key (which is what lets
        # the outbox notice later that it has already healed). Every key it announces is
        # remembered with it, though: that is what lets the incident triage edit its
        # diagnosis into the right message. Alerts and recoveries are formatted apart so the
        # recovery is never tagged with the key of an alert that happened to share its sweep.
        raised = [e for e in crit if e.kind in (NEW, STILL)]
        raised_keys = [e.episode.key for e in raised]
        for msg in format_alerts(raised, snap):
            self._emit_telegram("critical", msg,
                                key=raised_keys[0] if len(raised_keys) == 1 else "",
                                keys=raised_keys)
        for msg in format_alerts([e for e in crit if e.kind == RECOVERED], snap):
            self._emit_telegram("critical", msg)
        # what the next incident triage is asked to explain (see run_llm_audit)
        self._incident_issues = {e.episode.key: e.issue for e in raised
                                 if e.issue.get("kind") not in NO_LLM_KINDS}

        # A problem the user was told about earns a note when it goes away — otherwise the
        # last thing they heard about the boiler is that it was unreachable. Criticals
        # already get this from `crit` above; this is the same courtesy for everything that
        # left by the digest door. The gate has already confirmed the recovery is real
        # (`recovery_confirm_s` of continuous quiet), so this cannot chatter on a flap.
        healed = [e for e in rest
                  if e.kind == RECOVERED and e.episode.key in self._told
                  and self._recovery_is_news(e)]

        # News is tracked per issue KEY, not as a flag. An issue that opens and heals again
        # between two hourly audits (six cameras blinking on tcp/554 at 02:00, back by
        # 02:17) is not worth a message: by digest time there is nothing to look at. Only
        # a key that is still open when the digest runs earns one.
        for e in rest:
            if e.kind in (NEW, STILL):
                self._digest_news.add(e.episode.key)
            elif e.kind == RECOVERED:
                self._digest_news.discard(e.episode.key)
        # Forget the key on ANY recovery, not just a non-critical one. An issue can change
        # severity between the digest that named it and the recovery (a `high` device that
        # a group-majority escalation later made `critical`), and clearing it only from the
        # `rest` branch would leave it in `_told` for the life of the process.
        for e in events:
            if e.kind == RECOVERED:
                self._told.discard(e.episode.key)

        # Sent on the digest channel, never the critical one: a device coming back is good
        # news, and good news must not use the door reserved for things that page.
        for msg in format_alerts(healed, snap):
            self._emit_telegram("digest", msg)
        self._save_alert_record()

        # incident LLM candidate: a critical was actually announced this cycle — except
        # for the WAN kinds, which are reported deterministically and must never hold up
        # the loop (see NO_LLM_KINDS). A device outage in the same cycle still triages.
        # A suppressed (already-known) issue produces no event, so it no longer re-triggers
        # the model either — the noise reduction is the same for the LLM as for Telegram.
        return any(e.kind in (NEW, STILL) and e.issue.get("kind") not in NO_LLM_KINDS
                   for e in crit)

    # --- the alert record, across restarts ---------------------------------
    def resume_alerts(self, now: Optional[float] = None):
        """Take back what the last process had told the user, and keep it from now on.

        Kept only in memory, a restart would re-page every open critical as NEW, send the
        daily digest reminder at once because `_last_digest_sent` was 0, and forget which
        digest-reported devices were owed a "back online". The WAN watcher keeps its own
        record next to this one."""
        now = time.time() if now is None else now
        rec = self.state.load_record("alerts") or {}
        n = self.gate.restore(rec.get("gate"), now)
        self._told = set(rec.get("told") or [])
        self._digest_news = set(rec.get("digest_news") or [])
        self._newdev_told = dict(rec.get("new_devices_told") or {})
        self._last_digest_fp = rec.get("last_digest_fp") or ""
        self._last_digest_sent = float(rec.get("last_digest_sent") or 0.0)
        self._sent_log = list(rec.get("sent_log") or [])[-80:]
        self._weekly_last = float((self.state.load_record("weekly") or {}).get("last") or 0.0)
        w = self.wanwatch.restore_record(self.state.load_record("wanwatch"), now)
        self.wanwatch.persist = lambda r: self.state.save_record("wanwatch", r)
        self._persist_alerts = True
        log.info("resumed the alert record: %d incident(s), %d announced, %d told by digest, "
                 "%d WAN episode(s)", n, len(self.gate.announced_keys()), len(self._told), w)

    def _save_alert_record(self):
        if not self._persist_alerts:
            return
        try:
            self.state.save_record("alerts", {
                "gate": self.gate.dump(),
                "told": sorted(self._told),
                "digest_news": sorted(self._digest_news),
                "new_devices_told": self._newdev_told,
                "last_digest_fp": self._last_digest_fp,
                "last_digest_sent": self._last_digest_sent,
                "sent_log": self._sent_log[-80:],
            })
        except Exception as e:     # losing the record must never cost a sweep
            log.warning("alert record not saved: %s", e)

    @staticmethod
    def _key(issue) -> str:
        return f"{issue['kind']}:{issue['ip']}:{issue['group']}:{issue['device']}"

    def _recovery_is_news(self, event) -> bool:
        """Is this healed non-critical issue worth its own Telegram message?

        Default: yes, for anything that was reported — that is the point. The floor is a
        knob rather than a hard-coded tier because the gear at the bottom of the inventory
        is the flappiest (a twilight Shelly, the garage door), and the person reading the
        phone is the only one who can say where 'good to know' turns into noise."""
        a = self.cfg.get("alerts", {}) or {}
        if not a.get("notify_recovery", True):
            return False
        floor = str(a.get("recovery_min_severity", "info"))
        sev = event.issue.get("severity", "info")
        return _SEV_RANK.get(sev, 0) >= _SEV_RANK.get(floor, 0)

    def _open_incident_keys(self) -> set:
        """Every incident either gate currently holds open.

        The outbox uses this to word a delayed message honestly: something queued during a
        blackout may well have healed by the time there is a route to Telegram again."""
        return set(self.gate.open_keys()) | set(self.wanwatch.open_keys())

    def _emit_telegram(self, channel: str, text: str, key: str = "",
                       wan_ok: Optional[bool] = None, keys=None):
        """channel: 'critical' or 'digest'. Always published to MQTT, so the dashboard's
        event log sees what was said; then delivered to Telegram.

        This process sends, with retries, and anything that cannot be delivered goes to the
        outbox — including a digest. Nothing else on the network is in the path, which is
        the point: the alert that says a server is down must not depend on that server.

        A message that cannot leave the network (no WAN right now) is held in
        the outbox and flushed, in order and stamped with its original time, on the first
        sweep that sees the WAN answer again. `wan_ok` overrides that judgement for a
        caller with a fresher one — the WAN watcher pings four times as often as this
        loop, and its answer is up to 60s newer."""
        if self.no_telegram:
            log.info("telegram suppressed (--no-telegram) [%s]: %.100s", channel, text)
            return
        keys = list(keys or ([key] if key else []))
        # with its text, for "what did you send me on Sunday?" (records.py); with the issue
        # keys it announced, so outages one message announced are one incident on the
        # dashboard's Timeline (timeline.py)
        self._on_event("telegram", None, json.dumps({"channel": channel, "text": text[:1500],
                                                     **({"keys": keys} if keys else {})},
                                                    ensure_ascii=False))
        self._sent_log = (self._sent_log + [{"ts": time.time(), "channel": channel,
                                             "text": text[:1500]}])[-80:]
        no_route = (not self._wan_raw_ok or self.tracker.status(WAN_KEY) is False) \
            if wan_ok is None else (not wan_ok)
        if no_route:
            # No path out of the network: hold it, and send it when the WAN answers again.
            self.outbox.add(text, key, keys=keys)
            return
        self.mqtt.publish(channel, {"text": text, "ts": time.time()}, retain=False)
        asyncio.create_task(self._direct_or_queue(text, key, keys))

    async def _direct_or_queue(self, text: str, key: str = "", keys=None):
        """Send from this process; if the path fails, park the message in the outbox.
        A message Telegram itself rejects is logged and dropped — see TelegramRejected."""
        ids: list = []
        async with self._tg_lock:
            try:
                ok = await telegram_direct(self.cfg, text, ids=ids)
            except TelegramRejected as e:
                log.error("telegram: message rejected and dropped (%s): %.160s", e, text)
                return
        if not ok:
            self.outbox.add(text, key, keys=keys)
        elif keys and ids:
            self._remember_alert(keys, ids[0], text)

    def _remember_alert(self, keys, message_id: int, text: str):
        """Which message announced which incident — for the diagnosis edit. Two days is
        far longer than any triage takes; the record exists only to be edited soon."""
        now = time.time()
        for k in keys or []:
            if k:
                self._alert_msgs[k] = {"id": int(message_id), "text": text, "ts": now}
        self._alert_msgs = {k: v for k, v in self._alert_msgs.items()
                            if now - v["ts"] < 2 * 86400}

    async def _annotate_incident(self, issues: dict, llm: Optional[dict],
                                 ran: Optional[list] = None):
        """Edit the model's diagnosis into the alert that announced the incident.

        One message per incident is the rule (alerts.py), and a diagnosis is
        not a new incident — so it is never a second message. Delivered alerts are edited in
        place (no notification); an alert still waiting in the outbox for the internet to
        come back gets the note appended before it leaves."""
        if not issues or not llm or self.no_telegram:
            return
        by_msg: dict = {}
        for key, issue in issues.items():
            rec = self._alert_msgs.get(key)
            if rec is None:
                note = format_diagnosis_note([issue], llm, ran=ran)
                if note and self.outbox.annotate(key, note):
                    log.info("diagnosis added to the queued alert for %s", issue.get("device"))
                continue
            by_msg.setdefault(rec["id"], (rec, []))[1].append(issue)
        for mid, (rec, its) in by_msg.items():
            note = format_diagnosis_note(its, llm, ran=ran)
            if not note or "🦉" in rec["text"]:
                continue
            text = rec["text"] + note
            # an alert that already carries proposals keeps them, and their buttons
            body, markup = self.actions.decorate(mid, text)
            extra = {"reply_markup": markup} if markup is not None else {}
            async with self._tg_lock:
                ok = await telegram_edit(self.cfg, mid, body, **extra)
            if ok:
                for k, v in self._alert_msgs.items():
                    if v["id"] == mid:
                        v["text"] = text
                log.info("diagnosis edited into alert %s (%s)", mid,
                         ", ".join(str(i.get("device")) for i in its))
            else:
                log.warning("could not edit the diagnosis into alert %s", mid)

    def _wanwatch_alert(self, text: str, key: str = ""):
        """The WAN watcher's messages, unless the main router is restarting on the owner's
        say-so (a reboot or a RouterOS update of it holds "wan", reboot.py): its
        "no internet" and "back" would page a planned restart. Logged, never sent; a WAN
        still down once the hold is over is reported by the watcher's own STILL CRITICAL."""
        if self.held_until("wan"):
            log.info("WAN message held (the router is restarting): %s",
                     text.splitlines()[0][:120] if text else "")
            return
        self._wan_alert(text, key)

    def _wan_alert(self, text: str, key: str = ""):
        """Sink for the WAN watcher task (called from its loop, same thread).

        Identical routing to a sweep critical with one correction: the freshest answer to
        "can anything leave the network right now" is the watcher's own 15s probe, not
        `_wan_raw_ok` from a sweep that may be up to a minute stale — or stuck behind an
        LLM audit. During a real blackout the message is parked and flushed on recovery."""
        if self.no_telegram:
            self._emit_telegram("critical", text, key=key, wan_ok=True)   # logs, sends nothing
            return
        if self.wanwatch.blackout:
            self.outbox.add(text, key)
            return
        if self.outbox.pending:
            # Drain first, then speak. The queue is full of messages from the outage that
            # just ended — "no internet at all", raised when nothing could leave the network —
            # and this one is very often "the internet is back". Publishing to MQTT is
            # instant while the flush is an await, so sending in the natural order puts the
            # recovery on the phone BEFORE the outage it recovers from.
            asyncio.create_task(self._flush_then_send(text, key))
            return
        # wan_ok=True: the watcher got an answer from the internet less than `interval_s`
        # ago. The sweep's own view stays False for a sweep or two after the line is back,
        # and parking "the internet is back" in the outbox for a minute — to be delivered
        # with a "this was delayed" banner — is precisely the lateness being fixed here.
        self._emit_telegram("critical", text, key=key, wan_ok=True)

    async def _flush_then_send(self, text: str, key: str = ""):
        await self.outbox.flush(self.cfg, self._open_incident_keys(),
                                on_sent=self._remember_alert)
        self._emit_telegram("critical", text, key=key, wan_ok=True)

    def _publish_logbook(self, now: float):
        """lanowl/logbook (retained): every device down and up, for the dashboard's Logbook.

        The event log is only what Telegram was told; this is read from SQLite, holds every
        confirmed edge whether anyone was told or not, and a retained message survives a
        restart of whatever reads it."""
        try:
            self._logbook_cache = logbook.payload(self.state, self.inv, self.cfg, now,
                                                  paused=self._pause_intervals(now),
                                                  paused_now=self.pauses.ips())
            self.mqtt.publish("logbook", self._logbook_cache, retain=True)
            self._logbook_sent = True
        except Exception as e:     # never let the dashboard's history take a sweep down
            log.warning("logbook publish failed: %s", e)

    # --- LLM audit --------------------------------------------------------
    def _llm_history(self, since: float):
        """Recent transitions + flap counts, with the scheduled sleep/wake cycles removed.

        A `sun` device going down at dusk and up at dawn is the sun setting; a `day` device
        doing the opposite is the porch light switching off. Left in the context, those two
        events per day read as instability and the model narrates a 'degraded' network that
        the deterministic report never saw.

        Read through the logbook, so a restart's repeated `down` is gone and every `up`
        carries how long the device had been down, even when its `down` is older than
        `since`."""
        transitions = self.state.logbook(since, limit=60)
        flaps = self.state.flap_counts(since)
        scheduled = offline_mode_ips(self.inv)
        # ...and a device the owner switched off on purpose is no more unstable than one
        # the sun switched off
        paused = self._pause_intervals(time.time())

        def by_design(t) -> bool:
            if overlaps(paused, t["ip"], t["ts"] - (t.get("down_for") or 0), t["ts"]):
                return True
            mode = scheduled.get(t["ip"])
            return bool(mode) and offline_by_design(self.cfg, mode, t["ts"])

        if scheduled or paused:
            transitions = [t for t in transitions if not by_design(t)]
            for ip in (set(scheduled) | set(paused)) & set(flaps):
                expected = sum(1 for t in self.state.recent_transitions(since, ip=ip, limit=500)
                               if by_design(t))
                if flaps[ip] - expected > 0:
                    flaps[ip] -= expected
                else:
                    flaps.pop(ip)
        return transitions[:30], flaps

    async def run_llm_audit(self, snap, report, send_digest: bool, reason: str,
                            incident_issues: Optional[dict] = None):
        if self.no_llm:
            return self._digest_without_model(report, send_digest, reason)
        # Held for the whole audit so the log triages stand aside and a question waits its
        # turn: the 27b is dense and ~18GB, and two callers interleaving means reload churn
        # that shows up directly as latency.
        async with self.model_turn():
            now = time.time()
            since = now - 6 * 3600
            transitions, flaps = self._llm_history(since)
            mqtt_hint = self.mqtt.last("#", max_items=8) if self.mqtt.enabled else []
            ctx = build_user_context(snap.to_dict(), snap.anomalies(), transitions,
                                     flaps, self.inv.groups, mqtt_hint,
                                     discovery=self._discovery,
                                     new_devices=self.sites.recent_new(),
                                     shadowed=(report or {}).get("shadowed"),
                                     wan_note=self.wanwatch._wan_context(now),
                                     findings=self.executor._findings(6),
                                     proposals=(self.actions.context(now)
                                                if self.actions.enabled else None))
            log.info("Running LLM audit (%s) ...", reason)
            t0 = time.time()
            # the persona's voice and the network's description: added by LlmAgent
            system = system_prompt("")
            if self.actions.enabled:
                system = with_actions(system, "audit", self.actions.live)
            # what the audit looked at by itself: passive checks and its offline shell
            ran: list = []
            shell = await self.shell_audit.ready()
            if shell:
                system = with_shell_offline(system)
            with self.actions.source("audit", ran=ran), \
                    (self.shell_audit.turn("audit", reason, ran) if shell
                     else contextlib.nullcontext()):
                llm = await self.agent.run_audit(system, ctx)
        num_ctx = int(self.agent.options.get("num_ctx") or 0)
        peak = self.agent.last_ctx_peak
        log.info("LLM audit done in %.1fs (tool calls=%s, ok=%s, ctx peak=%s/%s)",
                 time.time() - t0, self.agent.last_tool_calls, llm is not None, peak, num_ctx)
        if num_ctx and peak >= 0.9 * num_ctx:
            # At the ceiling Ollama has already been truncating from the front, i.e.
            # eating the system prompt. Raise ollama.num_ctx, not max_tool_iters.
            log.warning("LLM context peak %d is within 10%% of num_ctx %d — the model was "
                        "almost certainly working from a truncated prompt", peak, num_ctx)
        # Merge onto the FRESHEST deterministic report, not the one this audit started from.
        # The audit no longer blocks the sweep, so several sweeps have run underneath it and
        # `_last_report` knows about devices this snapshot has never heard of. The narrative
        # is the only part of an audit that ages well; the numbers must be current.
        report = merge_llm(self._last_report or report, llm)
        if ran:
            # listed under the digest, like the 🔧 lines under a Telegram answer
            report["checks_ran"] = [{"label": r.get("label"), "ok": bool(r.get("ok"))} for r in ran]
        self._last_report = report
        if llm is not None:
            self._last_llm_report, self._last_llm_at = report, time.time()
            # each cause it named, kept to be checked once the problem is over (scorecard.py)
            try:
                self.scorecard.note_audit(llm, self._last_report)
            except Exception:
                log.exception("scorecard: the audit's claims were not noted")
        self.mqtt.publish("report", report, retain=True)
        if incident_issues and report.get("llm"):
            await self._annotate_incident(incident_issues, report["llm"], ran)
        self._tell_new_devices(llm)
        # what the audit proposed, AFTER the diagnosis: onto the incident's alert when there
        # is one, so the edit that adds the diagnosis cannot drop the buttons
        await self.actions.flush_audit()
        # A 'Check now' pressed while this audit was already running is answered by this
        # one — the button must always produce a reply, even if it is not the audit it
        # nominally started.
        pending = self._pending_digest_reason
        self._pending_digest_reason = None
        digest = (self._maybe_send_digest(report, pending or reason) if send_digest or pending
                  else "no digest: an incident's triage — its diagnosis goes onto the alert")
        self._record_audit(llm, pending or reason, digest, time.time() - t0, ran)
        return report

    def _digest_without_model(self, report, send_digest: bool, reason: str):
        """No model: what the audit would have sent still goes, the monitor's own report alone
        — otherwise no model would mean no digests either, since they leave from the end of
        the audit."""
        report = self._last_report or report
        pending, self._pending_digest_reason = self._pending_digest_reason, None
        if send_digest or pending:
            digest = self._maybe_send_digest(report, pending or reason)
            self._on_event("audit", None, json.dumps(
                {"reason": pending or reason, "digest": digest,
                 "result": "the local model is switched off — the monitor's own report alone"},
                ensure_ascii=False))
        return report

    def _tell_new_devices(self, llm: Optional[dict]):
        """A device never on the main site's DHCP before, that the audit thought worth an issue:
        ONE message, ever, per MAC. A guest's phone
        the model only mentions; the digest cannot carry this — it goes out only for what the
        monitor itself opened."""
        new = {x.get("ip"): x for x in self.sites.recent_new()} if llm else {}
        if not new:
            return
        now = time.time()
        told_any = False
        for i in llm.get("issues") or []:
            x = new.get(str(i.get("ip") or "").strip())
            mac = str((x or {}).get("mac") or "").upper()
            # the main site's by MAC; another site's by site and MAC
            key = mac if (x or {}).get("site") in (None, HOUSE) else f"{x['site']}:{mac}"
            if not mac or key in self._newdev_told:
                continue
            self._newdev_told[key] = now
            told_any = True
            maker = x.get("vendor") or ""
            what = x.get("host") or ("a device with a private address" if maker.startswith("private")
                                     else maker or "a device with no name")
            when = time.strftime("%H:%M", time.localtime(x["first_seen"]))
            if time.strftime("%Y%m%d", time.localtime(x["first_seen"])) != time.strftime("%Y%m%d"):
                when = time.strftime("%d/%m %H:%M", time.localtime(x["first_seen"]))
            sev = str(i.get("severity") or "info").lower()
            self._emit_telegram("digest", (
                f"🆕 <b>NEW DEVICE</b> {time.strftime('%H:%M:%S')}"
                + (" — <b>" + _html(sev) + "</b>" if sev not in ("info", "") else "") + "\n"
                f"<b>{_html(what)}</b> ({_html(x.get('ip') or '')}) · {_html(mac)}"
                + (f" · at <b>{_html(x.get('site_name'))}</b>" if x.get("site") not in (None, HOUSE) else "")
                + (" · guest Wi-Fi" if x.get("guest") else "")
                + (" · fixed address, no DHCP" if x.get("how") in ("arp", "scan") else "") + "\n"
                + (f"<i>{_html(maker)}</i>\n" if x.get("host") and maker else "")
                + f"First on the network at {when} — never seen here before.\n"
                + (f"<i>{_html(str(i.get('root_cause') or ''))}</i>\n" if i.get("root_cause") else "")
                + (f"<i>{_html(str(i.get('recommendation') or ''))}</i>" if i.get("recommendation") else "")
            ).rstrip())
        if told_any:
            # a device is new for a day: a week of record is plenty to never repeat one
            self._newdev_told = {m: t for m, t in self._newdev_told.items() if now - t < 7 * 86400}
            self._save_alert_record()

    def _record_audit(self, llm: Optional[dict], reason: str, digest: str, secs: float,
                      ran: Optional[list] = None):
        """Each audit's verdict and what became of its digest, in the events table
        (records.py) — otherwise only the log file knows "all healthy — digest suppressed",
        and "why didn't you tell me?" has no answer the model can read."""
        d = {"reason": reason, "secs": round(secs), "tool_calls": self.agent.last_tool_calls,
             "digest": digest,
             **({"ran_by_itself": [f"{'✓' if r.get('ok') else '✗'} {r.get('label')}: "
                                   f"{str(r.get('summary') or '')[:120]}" for r in ran]}
                if ran else {})}
        if llm is None:
            d["result"] = ("the model was switched off mid-audit — the deterministic report stood"
                           if self.no_llm else
                           "the model gave no assessment (timed out or failed) — the deterministic report stood")
        else:
            d.update(health=llm.get("overall_health"), summary=llm.get("summary"),
                     issues=[{"device": label(i.get("device"), i.get("ip")),
                              "severity": i.get("severity"), "cause": i.get("root_cause"),
                              "recommendation": i.get("recommendation")}
                             for i in (llm.get("issues") or [])[:10]])
        self._on_event("audit", None, json.dumps(d, ensure_ascii=False, default=str))

    def _start_llm_audit(self, snap, report, send_digest: bool, reason: str,
                         incident_issues: Optional[dict] = None) -> bool:
        """Run an audit as its OWN task, so the sweep loop keeps its 60s clock.

        Awaited inside the loop, a model audit is time in which no sweep runs and no device
        outage can be noticed — minutes, with a slow model; over a month, hours of blindness
        that buy a handful of digests.

        So detection is completely independent of the model. The audit is still one at a
        time (a second one would only fight the first for the model server) and still
        bounded, but by a wall-clock ceiling of its own rather than by the patience of the
        sweep loop."""
        if self._audit_task is not None and not self._audit_task.done():
            if send_digest:
                # ...but do not lose a request. The running audit will answer it.
                self._pending_digest_reason = reason
            log.info("LLM audit (%s) skipped: one is already running", reason)
            return False
        self._audit_task = asyncio.ensure_future(
            self._run_audit_guarded(snap, report, send_digest, reason, incident_issues))
        return True

    async def _run_audit_guarded(self, snap, report, send_digest: bool, reason: str,
                                 incident_issues: Optional[dict] = None):
        """Wrapper for the background audit: nothing it does may reach the loop.

        A background task that raises would otherwise disappear into asyncio's
        'exception was never retrieved' and take that audit's digest with it silently."""
        ceiling = float(self.cad.get("llm_max_wall_s", 600))
        try:
            await asyncio.wait_for(
                self.run_llm_audit(snap, report, send_digest, reason, incident_issues),
                timeout=ceiling)
        except asyncio.TimeoutError:
            log.warning("LLM audit (%s) abandoned after %.0fs — the deterministic report "
                        "stands, as it did throughout", reason, ceiling)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("LLM audit (%s) failed", reason)
        finally:
            # an audit abandoned half-way may already have proposed something: still the
            # owner's to answer (a no-op when the audit finished and delivered them itself)
            try:
                await self.actions.flush_audit()
            except Exception:
                log.exception("delivering the audit's proposals failed")

    def _maybe_send_digest(self, report: dict, reason: str) -> str:
        """A scheduled digest is sent only when it has something new to say.

        The old rule was "send whenever health != ok", which meant one problem produced
        one Telegram per hour for as long as it lasted — and, because the LLM could
        escalate a healthy report on its own, an hourly message about a switched-off TV.
        The new rule: the gate decides. A digest goes out when a genuinely new issue has
        opened since the last one (`_digest_news`), never merely because a known problem
        is still there. `alerts.digest_repeat_s` is the safety net that re-states a
        standing problem once a day so it cannot be forgotten entirely.

        'Check now' bypasses everything — the button must always answer. Returns what it
        decided, in words, for the audit's record (records.py)."""
        forced = reason == "check-now"
        healthy = report.get("overall_health") == "ok" and not report.get("issues")
        now = time.time()
        # what the model's scheduled looks found that no digest has carried yet (reviews.py):
        # news of its own, once — the network may be healthy and still slowly getting worse
        news = self._review_news()

        if forced:
            self._send_digest(report, now, "requested")
            return "sent: the owner asked for it (Check now)"
        n_news = sum(len(v) for v in news.values())
        if healthy:
            if n_news:
                self._send_digest(report, now, f"{n_news} new from the model's reviews")
                return f"sent: {n_news} new from the model's reviews"
            if self.cad.get("digest_when_ok", False):
                self._send_digest(report, now, "all-clear (digest_when_ok)")
                return "sent: all clear (digest_when_ok)"
            log.info("all healthy — scheduled digest suppressed (no Telegram)")
            return "held back: all healthy, nothing to tell"

        repeat_s = float(self.cfg.get("alerts", {}).get("digest_repeat_s", 86400))
        # The daily re-state is a safety net for a real problem nobody has fixed. It must
        # not resurrect an `info` issue: "the TV is still off" is not worth a message a
        # day later, which is the whole point of reporting it once.
        worth_restating = any(i.get("severity") != "info" for i in report.get("issues", []))
        stale = repeat_s > 0 and worth_restating and \
            (now - self._last_digest_sent) >= repeat_s

        # Only issues that are BOTH unreported and still open. Deliberately not "the issue
        # set changed since last time": that also fires when an issue *leaves* the set, so
        # a device coming back online sent a digest of its own — the exact repeat this
        # whole policy exists to prevent.
        pending = self._digest_news & {self._key(i) for i in report.get("issues", [])}

        if pending:
            self._send_digest(report, now, f"{len(pending)} new issue(s)")
            return f"sent: {len(pending)} new issue(s)"
        if n_news:
            self._send_digest(report, now, f"{n_news} new from the model's reviews")
            return f"sent: {n_news} new from the model's reviews"
        if stale:
            self._send_digest(report, now, "daily reminder, still open")
            return "sent: the daily reminder of a problem still open"
        # _last_digest_sent is 0.0 until this process sends one, and formatting the
        # epoch printed a confusing "since the 01:00 digest" after every restart
        since = (time.strftime("the %H:%M digest", time.localtime(self._last_digest_sent))
                 if self._last_digest_sent else "startup")
        log.info("nothing new since %s — digest suppressed (no Telegram)", since)
        return f"held back: nothing new since {since} — the open issues were already told"

    def _trends(self, report: dict) -> list:
        """Devices degrading against their own baseline, named for the digest.

        Computed here rather than in the sweep: it is a week-wide aggregate over ~1M rows
        and nothing on the alerting path needs it, so it runs only when a digest is actually
        being written."""
        try:
            rows = self.state.degrading(time.time())
        except Exception as e:
            log.warning("trend query failed (%s: %s)", type(e).__name__, e)
            return []
        names = {d.ip: d.name for d in self.inv.devices}
        for r in rows:
            r["device"] = names.get(r["ip"], r["ip"])
        # An issue already open says the same thing louder; no need to say it twice. A
        # paused device is not being watched, getting worse included. Nor one the model's
        # week-long look already explains (drift.py).
        noisy = {i.get("ip") for i in report.get("issues", [])} | self.pauses.ips() | self.drift.ips()
        return [r for r in rows if r["ip"] not in noisy]

    def _date_issues(self, report: dict):
        """Stamp every issue with when its incident began, and how many times it flapped.

        A device going down is dated even when it only ever reaches the digest. A `down` issue already carries the first missed sweep
        as `since` (build_report); the gate's episode is preferred over it because the
        episode spans flaps — a device that dropped at 14:02, came back, and dropped again
        at 14:40 is one incident that began at 14:02, and the freshest issue would say
        14:40. The gate is also the only thing that can date a degraded service or a
        group majority. Nothing here touches identity: digest_fingerprint ignores both."""
        for i in report.get("issues", []):
            key = self._key(i)
            started = self.gate.episode_start(key)
            if started:
                i["since"] = started
                i["flaps"] = self.gate.episode_flaps(key)

    def _review_news(self) -> dict:
        """{review: [(key, line)]} — what each scheduled look found that no digest carried."""
        out = {}
        for r in self.reviews:
            try:
                n = r.news() if r.enabled else []
            except Exception:
                log.warning("%s: news unreadable", r.NAME, exc_info=True)
                n = []
            if n:
                out[r] = n
        return out

    def _send_digest(self, report: dict, now: float, why: str):
        report["trends"] = self._trends(report)
        news = self._review_news()
        report["review_news"] = [{"title": r.TITLE, "icon": r.ICON, "lines": [ln for _, ln in items]}
                                 for r, items in news.items()]
        for r, items in news.items():
            r.mark_told([k for k, _ in items])
        self._date_issues(report)
        self._last_digest_fp = digest_fingerprint(report)
        self._last_digest_sent = now
        self._digest_news.clear()
        # Everything this digest names is now something the user has been told about, so it
        # has earned a recovery message later (see _diff_criticals). Recorded here, at the
        # send, rather than when the issue opened: a digest that is suppressed tells nobody
        # anything, and a recovery for a problem never mentioned is a confusing message.
        self._told |= {self._key(i) for i in report.get("issues", [])
                       if i.get("severity") != "critical"}
        log.info("sending digest (%s)", why)
        self._emit_telegram("digest", format_digest(report, now))
        self._save_alert_record()

    # --- the weekly review ------------------------------------------------
    async def _run_weekly_guarded(self, reason: str):
        try:
            await self.run_weekly(reason)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("weekly review (%s) failed", reason)

    async def run_weekly(self, reason: str) -> str:
        """Count the week, let the model say what matters, send it. See weekly.py.

        The numbers go out whether or not the model answers; the note on top is the part
        that needs it. Waits its turn behind a running audit."""
        now = time.time()
        facts = weekly.compute_facts(self.state, self.inv, self.wanwatch, self.hostlog,
                                     self._discovery, now,
                                     paused=self._pause_intervals(now),
                                     paused_now=self._last_report.get("paused")
                                     if self._last_report else None)
        facts["updates"] = (self.updates.weekly_lines() + self.exposure.weekly_lines()
                            + [ln for r in self.reviews for ln in r.weekly_lines()]
                            + self.scorecard.weekly_lines())
        facts["model_diagnoses_checked"] = self.scorecard.weekly(now)
        facts["by_hand"] = self.actions.by_hand(now)
        facts["security_events"] = self.seclog.weekly(now)
        if self._model_off:
            facts["model_off"] = dict(self._model_off)
        narrative = None
        if not self.no_llm:
            async with self.model_turn():
                t0 = time.time()
                narrative = await self.agent.ask_text(WEEKLY_SYSTEM,
                                                      build_weekly_context(facts), tools=False)
                log.info("weekly review (%s): model %s in %.1fs", reason,
                         "answered" if narrative else "did not answer", time.time() - t0)
        text = weekly.format_weekly(facts, narrative)
        self._emit_telegram("digest", text)
        if reason == "scheduled" and self._persist_alerts:
            self.state.save_record("weekly", {"last": now})
        return text

    async def run_discovery(self, now: float):
        """Pull DHCP leases from the MikroTik and detect unknown devices (throttled)."""
        interval = self.cfg.get("mikrotik", {}).get("discovery_interval_s", 300)
        if now - self._last_discovery < interval:
            return
        self._last_discovery = now
        from .discovery import fetch_leases, compute, build_mac_index, reconcile, fetch_arp, static_from_arp
        leases = await fetch_leases(self.cfg)
        if leases is None:
            return

        # Self-healing: re-bind inventory devices whose MAC now holds a different DHCP IP,
        # so an address change doesn't look like an outage. Done BEFORE computing unknowns.
        self._mac_index = build_mac_index(leases)
        # give the LLM's device_forensics tool the infrastructure view
        self.executor.leases = leases
        self.executor.arp = await fetch_arp(self.cfg)
        moves = reconcile(self.inv, self._mac_index)
        for m in moves:
            # carry debounce state across the move so the device isn't re-reported as new
            self.tracker.rename(m["old_ip"], m["new_ip"])
            self.pauses.rename(m["old_ip"], m["new_ip"])   # ...and a pause, likewise
        if moves:
            self._save_pauses()
        disc_cfg = self.cfg.get("discovery", {})
        if moves and disc_cfg.get("notify_address_changes", True):
            lines = "\n".join(f"• {m['name']}: {m['old_ip']} → {m['new_ip']}" for m in moves)
            self._emit_telegram("digest", f"🔁 <b>DHCP address change</b>\n{lines}")

        # The devices with a FIXED address, which no DHCP lists: on one of the main site's
        # networks in the router's ARP table, holding no
        # lease — and the ones the monthly scan found (sites.py), until the next scan.
        house = self.sites.get(HOUSE)
        lan = self.sites._lan(house)
        static = [x for x in static_from_arp(self.executor.arp, leases, lan)
                  if x["ip"] != self._self_ip]     # lanowl's own host is not a stranger
        leased = {str(l.get("mac-address") or "").upper() for l in leases if l.get("status") == "bound"}
        sc = self.sites.rec["scan"].get(HOUSE) or {}
        static += [{"ip": r["ip"], "mac": r["mac"].upper(), "how": "scan", "found": sc.get("ts")}
                   for r in sc.get("rows") or [] if r["mac"].upper() not in leased and r["ip"] != self._self_ip]
        disc = compute(leases, self.inv, self.cfg, known_macs=self.sites.known_macs(HOUSE), static=static)
        disc["ts"] = now
        disc["moved"] = moves

        # New-device detection: first run establishes a silent baseline (no alert for the
        # devices already on the LAN); afterwards a brand-new MAC is worth telling you about.
        # The same, separately, the first time the fixed addresses are looked at.
        baseline = self.sites.first_look(HOUSE, "dhcp")
        all_bound = [{"ip": l.get("address", ""), "mac": l.get("mac-address", ""),
                      "host": l.get("host-name", "") or l.get("comment", "")}
                     for l in leases if l.get("status") == "bound"]
        new_devs = self.sites.remember(HOUSE, all_bound, "dhcp", now)
        if self.executor.arp:                      # not read: no baseline taken from nothing
            new_devs += self.sites.remember(HOUSE, [x for x in static if x.get("how") == "arp"], "arp", now)
        disc["new"] = new_devs
        disc["baseline"] = baseline
        # When each was FIRST on the main site's DHCP, the guest Wi-Fi included — remembered for
        # good (a friend back after months is recognised, not announced as new). New = never
        # seen before; anything else is "here since" that day,
        # however long it was away. The audit is told the new ones apart (prompts.py).
        rows = disc["unknown"] + disc["ignored"]
        info = self.sites.info(HOUSE, [x.get("mac") for x in rows])
        for x in rows:
            i = info.get(str(x.get("mac") or "").lower()) or {}
            x["first_seen"], x["before"] = i.get("first_seen"), bool(i.get("before"))
        disc["recent_new"] = sorted(
            (x for x in disc["unknown"] if (info.get(str(x.get("mac") or "").lower()) or {}).get("new")),
            key=lambda x: -x["first_seen"])

        self._discovery = disc
        self.mqtt.publish("discovery", disc, retain=True)
        if baseline:
            log.info("discovery: baseline established with %d known-on-network devices", len(all_bound))
        elif new_devs:
            names = [d.get("host") or d["ip"] for d in new_devs]
            log.warning("discovery: %d NEW device(s) joined: %s", len(new_devs), names)
            # Still recorded in history and shown on the dashboard's Discovered panel;
            # only the Telegram ping is opt-in (phones/guests join constantly = noise).
            if disc_cfg.get("notify_new_devices", False):
                lines = "\n".join(f"• {d['ip']}  {d.get('host') or '(no name)'}  {d['mac']}"
                                  + (f" — {vendor(d['mac'])}" if vendor(d['mac']) else "")
                                  for d in new_devs[:8])
                self._emit_telegram("digest", f"🆕 <b>New device(s) on the network</b>\n{lines}")
        # Logged on CHANGE only. As a per-run line it was ~9,000 of the log's 11,655 INFO
        # entries — the same sentence every five minutes, drowning the events worth grepping
        # for. The number is on the dashboard continuously; the log wants the transitions.
        if disc["unknown_count"] != self._last_unknown_count:
            log.info("discovery: %d DHCP device(s) not in inventory (was %d)",
                     disc["unknown_count"], self._last_unknown_count)
            self._last_unknown_count = disc["unknown_count"]

    def _due_for_scheduled_llm(self, now: float) -> bool:
        mode = self.cad.get("llm_mode", "interval")
        if mode == "times":
            hhmm = time.strftime("%H:%M", time.localtime(now))
            if hhmm in (self.cad.get("llm_times") or []) and hhmm not in self._ran_times:
                self._ran_times = {hhmm}   # reset per matching minute
                return True
            return False
        # interval
        return (now - self._last_digest) >= self.cad.get("llm_interval_s", 3600)

    # --- main loop --------------------------------------------------------
    async def loop(self):
        interval = self.cad.get("sweep_interval_s", 60)
        log.info("Auditor started: %d devices, sweep=%ds, llm_mode=%s",
                 len(self.inv.devices), interval, self.cad.get("llm_mode"))
        # Separate task on purpose: everything below can block for minutes behind an LLM
        # audit, and that stall is exactly when a 57s failover goes unseen.
        from . import routeros
        routeros.shared(self.cfg).start()      # the kept router connection (routeros.py)
        watcher = asyncio.ensure_future(self.wanwatch.run())
        hostlogs = asyncio.ensure_future(self.hostlog.run())
        chat = asyncio.ensure_future(self.poller.run()) if not self.no_telegram else None
        try:
            await self.dashboard.start()
        except Exception:        # a port clash must not take the monitor down with it
            log.exception("web dashboard failed to start; monitoring continues without it")
        try:
            await self._loop_body(interval)
        finally:
            await self.dashboard.stop()
            self.wanwatch.stop()
            watcher.cancel()
            self.hostlog.stop()
            hostlogs.cancel()
            self.poller.stop()
            if chat is not None:
                chat.cancel()
            if self._audit_task is not None and not self._audit_task.done():
                self._audit_task.cancel()

    async def _loop_body(self, interval: float):
        prune_every = 3600
        last_prune = 0.0
        while True:
            t0 = time.time()
            forced = self._trigger.is_set()   # a 'Check now' arrived
            self._trigger.clear()
            try:
                # discovery first: re-bind drifted addresses and refresh the lease index
                # so the sweep probes correct IPs and lease-checks have fresh data
                await self.run_discovery(t0)
                snap, report, incident = await self.sweep_cycle()

                # Started, not awaited: see _start_llm_audit. The sweep continues on its own
                # clock while the model thinks, which is the whole point.
                if forced:
                    # on-demand full audit with digest
                    self._start_llm_audit(snap, report, send_digest=True, reason="check-now")
                elif self._due_for_scheduled_llm(t0):
                    self._last_digest = t0
                    self._start_llm_audit(snap, report, send_digest=True, reason="scheduled")
                # incident triage (cooldown-limited), digest suppressed to avoid noise
                elif incident and self.cad.get("llm_on_incident", True) and \
                        (t0 - self._last_incident_llm) >= self.cad.get("llm_incident_cooldown_s", 600):
                    self._last_incident_llm = t0
                    self._start_llm_audit(snap, report, send_digest=False, reason="incident",
                                          incident_issues=dict(self._incident_issues))

                if weekly.is_due(self.cfg, t0, self._weekly_last):
                    self._weekly_last = t0      # claimed now: a slow review must not start twice
                    self.request_weekly("scheduled")
                # updates and the monthly scan run as tasks of their own, like the audit
                if self.updates.due(t0):
                    self.updates.start("scheduled")
                if self.updates.scan_due(t0):
                    self.updates.start_scan("scheduled")
                # a scan whose matches were never checked (the check is newer than the scan, or
                # was cut by a restart): once, ten minutes after a start, not in the scan's way
                elif self.cves.stale() and not self.cves.running and not self.updates.running["scan"] \
                        and t0 - self._started > 600 and t0 - float(self.cves.rec["run"].get("ts") or 0) > 6 * 3600:
                    self.cves.start("its matches had not been checked")
                if self.exposure.due(t0):
                    self.exposure.start("scheduled")
                for r in self.reviews:
                    if r.due(t0):
                        r.start("scheduled")
                self.scorecard.tick(t0)
                self.backups.tick(t0)

                if t0 - last_prune > prune_every:
                    self.state.prune()
                    last_prune = t0
            except Exception as e:
                log.exception("sweep cycle error: %s", e)
            # answered (or lost to the error above); a 'Check now' that came in during this
            # cycle is still asked, and the next cycle takes it
            if forced and (self._check_asked or 0) <= t0:
                self._check_asked = None

            # sleep until the next sweep, but wake immediately on a 'Check now'
            elapsed = time.time() - t0
            try:
                await asyncio.wait_for(self._trigger.wait(), timeout=max(1.0, interval - elapsed))
            except asyncio.TimeoutError:
                pass

    # --- one-shot for --once ----------------------------------------------
    async def once(self, run_llm: bool):
        await self.run_discovery(time.time())   # fresh leases before probing
        snap, report, _ = await self.sweep_cycle()
        if run_llm:
            report = await self.run_llm_audit(snap, report, send_digest=False, reason="--once")
        _print_table(snap, report)
        return report


def _print_table(snap, report):
    c = report["counts"]
    print("\n=== Auditor sweep @ %s ===" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snap.ts)))
    wp = report.get("wan_path") or {}
    # the state word above already says BACKUP; this just names the link carrying traffic
    path = f" via {wp['link']}" if wp.get("link") else ""
    print("Overall: %s | %d/%d up | WAN %s%s" % (
        report["overall_health"].upper(), c["up"], c["total"],
        (report.get("wan_state") or "").upper() or ("OK" if report["wan_ok"] else "DOWN"),
        path))
    print("-" * 68)
    for d in sorted(snap.devices, key=lambda x: (x.group, x.ip)):
        status = "PAUS" if d.paused else "UP " if d.up else ("ZZZ " if d.expected_down else "DOWN")
        failed = ",".join(d.failed_services())
        lat = f"{d.latency_ms:.0f}ms" if d.latency_ms else "-"
        print(f"  {status}  {d.ip:<15} {d.group:<9} {lat:<7} {d.name[:26]:<26} {failed}")
    print("-" * 68)
    if report["issues"]:
        print("Issues:")
        for i in report["issues"]:
            print(f"  [{i['severity']}] {i['device']} — {i['detail']}")
    if report.get("summary"):
        print("Summary:", report["summary"])
    if report.get("llm"):
        print("LLM:", report["llm"].get("summary", ""))
    print()


def _setup_logging(cfg, level_override=None):
    """Rotating file log, plus a console copy only when a human is watching.

    Under a supervisor that redirects stderr to a file, an unconditional StreamHandler
    writes every line twice — two files growing forever with identical
    content, neither of them rotated. The console handler is therefore attached only when
    stderr is a terminal (i.e. someone is running it by hand), and the file handler
    rotates."""
    import sys
    from logging.handlers import RotatingFileHandler

    lcfg = cfg.get("logging", {}) or {}
    level = level_override or lcfg.get("level", "INFO")
    handlers = []
    logfile = lcfg.get("file")
    if logfile:
        try:
            handlers.append(RotatingFileHandler(
                logfile, maxBytes=int(lcfg.get("max_bytes", 5_000_000)),
                backupCount=int(lcfg.get("backups", 3))))
        except Exception:
            pass
    if sys.stderr.isatty() or not handlers:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=getattr(logging, str(level).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=handlers)


async def _amain(args):
    # --config, else LANOWL_CONFIG, else config.yaml where it runs (the same for the inventory)
    cfg = load_config(args.config or os.environ.get("LANOWL_CONFIG") or "config.yaml")
    inv = load_inventory(args.inventory or os.environ.get("LANOWL_INVENTORY") or "inventory.yaml")
    _setup_logging(cfg, args.log_level)
    # each device's kind, login and `manage`, into the lists every feature reads (kinds.py)
    kinds = Kinds.load(cfg, inv, Access(cfg, inv))

    mqtt = MqttBridge(cfg)
    if not args.no_mqtt:
        mqtt.start()
    state = StateStore(cfg.get("state", {}).get("db_path", "lanowl_state.sqlite"),
                       cfg.get("state", {}).get("history_days", 14))
    tracker = StatusTracker(cfg.get("cadence", {}).get("debounce_fails", 2),
                            cfg.get("cadence", {}).get("recovery_oks", 1))
    # Pick every device up where the last run left it, so an outage already under way keeps
    # its start instead of being re-dated to this restart (see StateStore.resume).
    resumed = state.resume([d.ip for d in inv.devices])
    for ip, st in resumed.items():
        tracker.restore(ip, **st)
    log.info("resumed %d device(s) from history, %d of them down", len(resumed),
             sum(1 for st in resumed.values() if st["confirmed"] is False))
    executor = ToolExecutor(cfg, inv, mqtt, state)
    agent = LlmAgent(cfg, executor)
    auditor = Auditor(cfg, inv, mqtt, state, tracker, executor, agent, no_llm=args.no_llm,
                      no_telegram=args.no_telegram, kinds=kinds)
    if not args.once:
        auditor.resume_alerts()

    try:
        if args.once:
            await auditor.once(run_llm=not args.no_llm)
        else:
            await auditor.loop()
    finally:
        from . import routeros
        await routeros.shared(cfg).stop()      # a clean logout, not a dropped socket
        mqtt.stop()
        state.close()


def _check(args) -> int:
    """`lanowl --check`: the plan for every device, read from the same files a start reads.
    1 when something is wrong, so it can gate a deploy."""
    cfg = load_config(args.config or os.environ.get("LANOWL_CONFIG") or "config.yaml")
    inv = load_inventory(args.inventory or os.environ.get("LANOWL_INVENTORY") or "inventory.yaml")
    logging.basicConfig(level=logging.ERROR)
    k = Kinds.load(cfg, inv, Access(cfg, inv))
    print(kinds_report(k, inv))
    return 1 if k.problems or any(p.problems for p in k.plans) else 0


def main():
    ap = argparse.ArgumentParser(prog="lanowl", description="lanowl: a watchful, read-only caretaker for your network")
    ap.add_argument("--config", default=None)
    ap.add_argument("--inventory", default=None)
    ap.add_argument("--once", action="store_true", help="run a single cycle then exit")
    ap.add_argument("--no-llm", action="store_true", help="skip the LLM audit")
    ap.add_argument("--no-mqtt", action="store_true", help="don't connect/publish MQTT")
    ap.add_argument("--no-telegram", action="store_true",
                    help="never send to Telegram (rehearsals: the smoke run)")
    ap.add_argument("--log-level", default=None)
    ap.add_argument("--check", action="store_true",
                    help="say what lanowl will do with each device, and why not; then exit")
    args = ap.parse_args()
    if args.check:
        sys.exit(_check(args))
    try:
        asyncio.run(_amain(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
