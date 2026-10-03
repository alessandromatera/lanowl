"""Talking to lanowl: questions and a few commands over its own Telegram bot.

The model has read-only tools, the history, the router's log and the logbook; this is where
the owner asks it things, on lanowl's own bot:

    /status   what is true right now, instantly, no model involved
    /audit    a full audit with a digest (the dashboard's 'Audit now'); /check still works
    /security what matters, from every check, by severity (the Security tab's list)
    /sites    every site (the main one, the VPN hub, remote ones): up, down, unknown devices
    /week     the weekly review, now
    /reboot   reboot a device (reboot.py) — answered with the Approve button
    /updates  what is waiting to be updated, pending reboots, known vulnerabilities
    /upgrade  update a machine: a Linux host (apt) or a MikroTik
    /backups  the machines' backups on the store (backups.py)
    /pause    stop watching a device switched off on purpose (pause.py)
    /resume   watch it again;  /paused  what is paused
    /memory   the model's notes (memory.py); /remember and /forget change them directly
    /model    the owner's switch for the local model: /model off, /model on (Auditor.set_model)
    /new      start a new conversation
    anything else is a question, answered by the model with the same read-only tools

A Telegram chat is a conversation, like the dashboard's: a question carries
the last few exchanges (TG_TURNS), until /new or TG_IDLE_S of silence. And the owner's
questions — here and on the dashboard — may write the model's memory.

The same questions can arrive on MQTT (`lanowl/ask`, answered on `lanowl/answer`), and from
the dashboard's Ask tab, where they are a conversation (conversations.py).

The model is one at a time: a question asked while the hourly audit is thinking waits for it
and says so, rather than fighting it for the GPU. Answers are the model's and say so; the
deterministic report, the alerts and the gate are exactly as they were.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Optional

from .memory import strip_footer
from .pause import find_devices
from .prompts import (QA_SYSTEM, QA_SYSTEM_CHAT, QA_SYSTEM_TELEGRAM, build_qa_context,
                      investigation_brief, with_actions, with_memory_tools, with_shell)
from .report import _clock, _html, format_digest, label, ran_lines
from .sinks import telegram_call, telegram_direct

log = logging.getLogger("lanowl.chat")

TG_RECORD = "telegram_conv"
TG_TURNS = 6              # earlier exchanges a Telegram question carries
TG_IDLE_S = 6 * 3600      # ...unless the last one is older than this: then it starts over
TG_CHARS = 2500           # each earlier answer cut to this

HELP = ("🦉 <b>lanowl</b> — ask me anything about the network, in any words.\n"
        "e.g. <i>why did the internet drop last night?</i> · <i>how has the boiler been this "
        "week?</i> · <i>who joined the guest Wi-Fi today?</i>\n\n"
        "/status — the network right now (instant)\n"
        "/audit — a full audit and digest (the dashboard's Audit now)\n"
        "/security — what matters, from every check, by severity\n"
        "/sites — every site: the main one, the VPN hub, the remote ones\n"
        "/week — the weekly review, now\n"
        "/reboot <i>device</i> — restart it (you approve with the button)\n"
        "/updates — updates, pending reboots, known vulnerabilities\n"
        "/backups — the machines' backups on the store\n"
        "/upgrade <i>machine</i> — update it (you approve)\n"
        "/pause <i>device</i> — stop watching something you switched off "
        "(e.g. <i>/pause tv, boiler</i>)\n"
        "/resume <i>device</i> | all — watch it again · /paused — what is paused\n"
        "/memory — what I remember · /remember <i>text</i> · /forget <i>number</i>\n"
        "/model on | off — the local model (off: no diagnoses, answers or reviews; alerts "
        "and digests go on)\n"
        "/new — a new conversation (I keep the last few questions for 6 hours)\n\n"
        "<i>Ask and I dig in myself: mtr, DNS, TLS, scans, ARP, a packet capture, the tunnels, "
        "another LAN host, the VPN hub, the remote sites' routers (a ping, their DHCP, a speed "
        "test) — whatever the question needs, listed under my answer. I can read everything "
        "lanowl keeps: updates, the security review, what I sent you and why a digest was held "
        "back. Changing something — restarting a service, rebooting a device — I can only "
        "propose; it runs when you press the button. Pausing changes what I watch. Tell me to remember, change or forget "
        "something and I will — every note I save is printed under my answer.</i>")


def ran_footer(ran: list) -> str:
    """🔧 and one line per check (or command) run in an answer, ✗ for one that failed."""
    return "\n".join(ran_lines(ran))


class Chat:
    def __init__(self, auditor):
        self.a = auditor
        self.cfg = auditor.cfg
        q = (self.cfg.get("telegram", {}) or {}).get("chat") or {}
        self.max_wall_s = float(q.get("answer_max_wall_s", 420))
        # a question's agent loop; None = ollama.max_tool_iters, the audit's
        self.max_iters = int(q["max_iters"]) if q.get("max_iters") else None
        sess = ((self.cfg.get("actions") or {}).get("session") or {})
        self.session_wall_s = float(sess.get("turn_max_s", 900))
        self.session_iters = int(sess.get("max_iters", 24))
        self._tasks: set = set()
        self._tg: dict = {}       # chat_id -> {"turns": [{"q", "a", "ts"}]}
        try:
            rec = auditor.state.load_record(TG_RECORD) or {}
            self._tg = {str(k): v for k, v in (rec.get("chats") or {}).items()
                        if isinstance(v, dict)}
        except Exception:
            log.warning("telegram conversations unreadable, starting fresh", exc_info=True)

    # --- inbound ------------------------------------------------------------
    async def on_telegram(self, text: str, chat_id: str):
        cmd = text.split()[0].split("@")[0].lower() if text.startswith("/") else ""
        log.info("telegram chat: %s", cmd or f"question ({len(text)} chars)")
        if cmd in ("/start", "/help"):
            await self._reply(chat_id, HELP)
        elif cmd == "/status":
            rep = self.a._last_report
            await self._reply(chat_id, format_digest(rep, title="Right now") if rep
                              else "No sweep has finished yet — ask again in a minute.")
        elif cmd in ("/audit", "/check"):          # the dashboard's "Audit now"; /check kept
            await self._reply(chat_id, "🔌 The local model is off — here comes the digest of what "
                                       "the monitor sees, without it." if self.a.no_llm else
                              "🔄 Running a full audit — the digest follows in a minute or two.")
            self.a.request_check()
        elif cmd == "/security":
            await self._reply(chat_id, self.security_text())
        elif cmd == "/sites":
            await self._reply(chat_id, self.sites_text())
        elif cmd == "/week":
            await self._reply(chat_id, "📅 Putting the week together…")
            self.a.request_weekly("requested")
        elif cmd == "/reboot":
            arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            text = await self.reboot_command(arg)
            if text:            # otherwise the proposal, with its buttons, is the answer
                await self._reply(chat_id, text)
        elif cmd == "/upgrade":
            arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            text = await self.upgrade_command(arg)
            if text:
                await self._reply(chat_id, text)
        elif cmd == "/backups":
            await self._reply(chat_id, self.a.backups.text())
        elif cmd == "/updates":
            await self._reply(chat_id, self.updates_text())
        elif cmd in ("/pause", "/resume", "/paused"):
            arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            await self._reply(chat_id, self.pause_command(cmd, arg))
        elif cmd == "/model":
            arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            await self._reply(chat_id, self.model_command(arg))
        elif cmd in ("/memory", "/remember", "/forget"):
            arg = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            await self._reply(chat_id, self.memory_command(cmd, arg))
        elif cmd == "/new":
            had = bool(self._tg.pop(str(chat_id), None))
            self._tg_save()
            await self._reply(chat_id, "🆕 New conversation — the earlier questions are gone "
                                       "(not the memory: /memory)." if had else
                              "🆕 New conversation.")
        elif cmd:
            await self._reply(chat_id, "I don't know that command.\n\n" + HELP)
        else:
            # Its own task: the poller must keep reading (a /status right after a question
            # should not wait minutes behind it).
            t = asyncio.ensure_future(self._answer_telegram(text, chat_id))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    # --- pausing ------------------------------------------------------------
    def pause_command(self, cmd: str, arg: str) -> str:
        """/pause tv, boiler · /resume tv · /resume all · /paused. Several devices at once,
        comma-separated: going on holiday is switching off a handful of things."""
        a = self.a
        if cmd == "/paused" or not arg.strip():
            head = "" if cmd == "/paused" else (
                f"Say which: <i>{cmd} tv</i>, <i>{cmd} boiler, garage door</i>, or an address."
                + (" <i>/resume all</i> ends every pause." if cmd == "/resume" else "") + "\n\n")
            return head + self.paused_list()
        if cmd == "/resume" and arg.strip().casefold() == "all":
            ips = [e["ip"] for e in a.pauses.entries()]
            if not ips:
                return "Nothing is paused."
            return "\n\n".join(a.set_paused(ip, False, "telegram")["text"] for ip in ips)
        out = []
        # /resume looks among the paused devices first: "shelly" is then the one paused
        # Shelly, not eleven of them
        paused_devs = [d for d in a.inv.devices if a.pauses.is_paused(d.ip)]
        for q in [p.strip() for p in arg.split(",") if p.strip()]:
            found = (find_devices(paused_devs, q) if cmd == "/resume" else []) \
                or find_devices(a.inv.devices, q)
            if len(found) == 1:
                out.append(a.set_paused(found[0].ip, cmd == "/pause", "telegram")["text"])
            elif not found:
                out.append(f"❓ No device matches <i>{_html(q)}</i>.")
            else:
                names = "\n".join(f"• {_html(label(d.name, d.ip))}" for d in found[:8])
                more = f"\n…and {len(found) - 8} more" if len(found) > 8 else ""
                out.append(f"❓ <i>{_html(q)}</i> matches {len(found)} devices — say which "
                           f"(more of the name, or the address):\n{names}{more}")
        return "\n\n".join(out)

    # --- the local model's switch (Auditor.set_model) ---------------------------------
    def model_command(self, arg: str) -> str:
        """/model · /model on · /model off. The owner's own switch: no model involved."""
        a = self.a
        arg = arg.strip().casefold()
        if arg in ("on", "off"):
            return a.set_model(arg == "on", "telegram")["text"]
        v = a.model_view()
        if v["cli"]:
            return "🔌 The local model is off for this run (lanowl was started with --no-llm)."
        if v["on"]:
            return (f"🦉 The owl is awake: the local model is <b>on</b>{' (' + _html(v['name']) + ')' if v['name'] else ''}."
                    "\n<i>/model off</i> switches it off: no diagnoses, answers or reviews; alerts "
                    "and digests go on.")
        return (f"🦉 The owl is asleep: the local model is <b>off</b> since {_clock(v['since'] or time.time(), time.time())}"
                + (" (from the dashboard)" if v["by"] == "dashboard" else "")
                + ".\n<i>/model on</i> switches it back on.")

    # --- rebooting ------------------------------------------------------------
    async def reboot_command(self, arg: str) -> str:
        """/reboot ap porch · /reboot 192.168.10.35. One device: a reboot is not something
        to do to a handful at once. Answered by the proposal itself, with its buttons — or
        by why not."""
        a = self.a
        ips = set(a.actions.rebootable())
        devs = [d for d in a.inv.devices if d.ip in ips]
        if not devs:
            return "Rebooting is switched off (actions.enabled)."
        if not arg.strip():
            return ("Say which: <i>/reboot ap porch</i>, or an address. I can reboot:\n"
                    + "\n".join(f"• {_html(label(d.name, d.ip))}" for d in devs))
        found = find_devices(devs, arg) or find_devices(a.inv.devices, arg)
        if not found:
            return f"❓ No device matches <i>{_html(arg)}</i>."
        if len(found) > 1:
            names = "\n".join(f"• {_html(label(d.name, d.ip))}" for d in found[:8])
            return (f"❓ <i>{_html(arg)}</i> matches {len(found)} devices — say which (more of "
                    f"the name, or the address):\n{names}")
        d = found[0]
        if d.ip not in ips:
            return f"✋ {_html(label(d.name, d.ip))} is not a device I can reboot."
        r = await a.actions.ask("reboot", d.ip, "telegram")
        if r.get("refused"):
            return f"✋ Not rebooting {_html(label(d.name, d.ip))}: {_html(r['refused'])}"
        if r.get("already"):
            return (f"⏳ A reboot of {_html(label(d.name, d.ip))} is already waiting for you "
                    f"(#{r['proposal']}) — use its buttons.")
        return ""

    async def upgrade_command(self, arg: str) -> str:
        """/upgrade vps · /upgrade homehub · /upgrade ap porch: like /reboot, the proposal
        is the answer. apt on the Linux hosts, RouterOS on the MikroTiks."""
        a = self.a
        ros = a.updates.ros_upgradable()
        devs = [d for d in a.inv.devices if d.ip in a.updates.upgradable() or d.ip in ros]
        if not devs:
            return "Updating from here is switched off (actions.catalog.apt_upgrade)."
        found = find_devices(devs, arg) if arg.strip() else []
        if len(found) != 1:
            return ("Say which (part of the name, or the address):\n"
                    + "\n".join(f"• {_html(label(d.name, d.ip))}" for d in devs))
        d = found[0]
        r = await a.actions.ask("routeros_upgrade" if d.ip in ros else "apt_upgrade", d.ip,
                                "telegram")
        if r.get("refused"):
            return f"✋ Not updating {_html(label(d.name, d.ip))}: {_html(r['refused'])}"
        if r.get("already"):
            return f"⏳ Already waiting for you (#{r['proposal']}) — use its buttons."
        return ""

    def security_text(self) -> str:
        """/security: the Security tab's What matters — every source, by severity (Records)."""
        items = self.a.records.security_items()
        top = [i for i in items if i["top"] and not i["dismissed"]]
        later = [i for i in items if not i["top"] and not i["dismissed"]]
        dis = sum(1 for i in items if i["dismissed"])
        handled = len(self.a.seclog.view()["handled"])
        dot = {"critical": "🔴", "high": "🟠", "warning": "🟡"}
        lines = [f"🛡 <b>Security</b> — {len(top)} thing(s) that matter"]
        lines += [f"{dot.get(i['sev'], '⚪')} {_html(i['text'])} <i>— {_html(i['from'])}</i>" for i in top[:10]]
        if not top:
            lines.append("Nothing that matters right now.")
        if later:
            lines.append(f"\n<i>Worth fixing, not urgent: {len(later)}"
                         + (f" · dismissed by you: {dis}" if dis else "") + " — the Security tab has them.</i>")
        if any(i.get("id") for i in top):
            lines.append("<i>A log event stays here until you mark it handled on the Security tab.</i>")
        if handled:
            lines.append(f"<i>Handled by you this week: {handled}.</i>")
        x = self.a.exposure.view()
        if x.get("reviewed"):
            lines.append(f"<i>The model's review {_clock(x['reviewed'])}: {_html(x.get('summary') or '')}</i>")
        return "\n".join(lines)

    def sites_text(self) -> str:
        """/sites: each site's devices up, the down ones named, what its DHCP holds unknown."""
        lines = ["🗺 <b>Sites</b>"]
        for s in self.a.sites.view(self.a._last_report)["sites"]:
            dot = "🔴" if s["down"] else "🟢"
            bit = f"{dot} <b>{_html(s['name'])}</b> {s['up']}/{s['total']} up"
            if s["down"]:
                bit += " — down: " + _html(", ".join(s["down"][:4]))
            n = (s.get("dhcp") or {}).get("unknown")
            if n:
                bit += f" · {n} unknown on its network"
            lines.append(bit)
        return "\n".join(lines)

    def updates_text(self) -> str:
        """/updates: the last daily check, what matters first. Instant — the check itself runs
        in the early morning (or from the dashboard)."""
        u = self.a.updates
        if not u.enabled:
            return "The update check is off (updates.enabled)."
        v = u.view()
        if not v["last"]:
            return "🛡 No update check has run yet — it runs every morning at " + _html(v["at"]) + "."
        fs = v["findings"]
        head = f"🛡 <b>Updates &amp; security</b> · checked {_clock(v['last'], time.time())}"
        if not fs:
            return head + "\nNothing waiting."
        def line(f):
            d = f.get("dismissed")
            if d:
                return (f"☑️ {_html(f['text'])} — <i>dismissed{': ' + _html(d['note']) if d['note'] else ''}"
                        "</i>")
            return ("❗ " if f["page"] else "• ") + _html(f["text"])
        return head + "\n" + "\n".join(line(f) for f in fs[:25])

    def paused_list(self) -> str:
        es = self.a.pauses.entries()
        if not es:
            return "Nothing is paused — every device is watched."
        rep = self.a._last_report or {}
        up = {d.get("ip"): d.get("up") for d in rep.get("devices") or []}
        lines = [f"⏸ <b>Paused</b> ({len(es)})"]
        for e in es:
            st = {True: "answering", False: "off"}.get(up.get(e["ip"]), "")
            lines.append(f"• {_html(label(self.a._name(e['ip'], e['name']), e['ip']))} — since "
                         f"{_clock(e['ts'], time.time())}" + (f", {st}" if st else ""))
        return "\n".join(lines)

    # --- memory, by hand ----------------------------------------------------------
    def memory_command(self, cmd: str, arg: str) -> str:
        """/memory · /remember <text> · /forget 3 (or 3, 5). The owner's own changes: saved as
        written, no model involved."""
        m = self.a.memory
        if cmd == "/remember":
            if not arg.strip():
                return "Say what: <i>/remember the office's public IP is …</i>"
            r = m.add(arg, by="owner", via="telegram")
            return (f"💾 Remembered #{r['id']}." if r["ok"] else f"❓ {_html(r['error'])}.")
        if cmd == "/forget":
            ids = [x.strip().lstrip("#") for x in arg.replace(",", " ").split() if x.strip()]
            if not ids:
                return "Say which, by number: <i>/forget 3</i>\n\n" + self.memory_list()
            out = []
            for i in ids:
                r = m.forget(i, by="owner", via="telegram")
                out.append(f"🗑 Forgot #{r['id']}." if r["ok"] else f"❓ {_html(r['error'])}.")
            return "\n".join(out)
        return self.memory_list()

    def memory_list(self) -> str:
        ns = self.a.memory.view()
        if not ns:
            return ("🦉 Nothing remembered yet. Tell me in any words (<i>remember that …</i>), or "
                    "<i>/remember …</i>")
        lines = [f"🦉 <b>What I remember</b> ({len(ns)})"]
        for n in ns:
            who = "you" if n.get("by") == "owner" else "me"
            lines.append(f"<b>#{n['id']}</b> {_html(n['text'])} <i>— {who}, "
                         f"{time.strftime('%d/%m', time.localtime(n.get('upd') or n['ts']))}</i>")
        lines.append("\n<i>/forget 3</i> deletes one · or just tell me what changed")
        return "\n".join(lines)

    async def on_callback(self, data: str) -> str:
        """An Approve/Reject button under a proposal (actions.py)."""
        return await self.a.actions.on_callback(data)

    def on_mqtt(self, payload: str):
        """lanowl/ask (paho thread) -> an answer on lanowl/answer."""
        q = (payload or "").strip()
        if q.startswith("{"):
            try:
                import json
                q = str(json.loads(q).get("q", "")).strip()
            except ValueError:
                pass
        if not q:
            return
        fut = asyncio.run_coroutine_threadsafe(self._answer_mqtt(q), self.a._loop)
        self._tasks.add(fut)
        fut.add_done_callback(self._tasks.discard)

    # --- answering ----------------------------------------------------------
    async def answer(self, question: str, on_wait=None, history: Optional[list] = None,
                     on_event=None, source: Optional[dict] = None,
                     session: Optional[dict] = None) -> Optional[str]:
        """The model's answer, or None. Waits its turn for the model.

        `history` — the dashboard's conversation so far, as user/assistant messages — makes
        it a follow-up; `on_event` streams the work (see LlmAgent._tool_loop), plus
        on_event("start") once the model is ours. Telegram passes neither: one question,
        one answer, as before. Cancelling the caller stops the model mid-answer.

        `source` = {"via": "telegram"|"dashboard", ...} lets the answer PROPOSE an action
        (actions.py); None (MQTT) keeps it read-only. `session`: this is the approved
        investigation's own turn (Chat.investigate) — more room, and the session's rules."""
        a = self.a
        if a.no_llm:
            return None
        if a._llm_lock.locked() and on_wait is not None:
            await on_wait()
        async with a.model_turn():
            if on_event is not None:
                on_event("start")
            now = time.time()
            acts = a.actions.enabled and source is not None
            ctx = build_qa_context(
                question, a._last_report, wan_note=a.wanwatch._wan_context(now),
                findings=a.executor._findings(24), logbook=a.state.logbook(now - 86400, limit=40),
                now=now, host_logs=a.hostlog.snapshot_state() if a.hostlog.enabled else None,
                proposals=a.actions.context(now) if acts else None,
                security=a.records.security_line() if getattr(a, "records", None) else "",
                site_of=((lambda ip: (a.sites.get(a.sites.of(ip)) or {}).get("name", "?"))
                         if getattr(a, "sites", None) else None),
                audit=(getattr(a, "_last_llm_report", None) or {}).get("llm"),
                audit_at=getattr(a, "_last_llm_at", 0.0) or 0.0)
            via = (source or {}).get("via")
            system = (QA_SYSTEM if history is None else
                      QA_SYSTEM_TELEGRAM if via == "telegram" else QA_SYSTEM_CHAT)
            # The owner's own question: its checks run at once (asking was the approval), and
            # it may write the memory. Not an investigation session's turn (it follows up an
            # audit's request as often as a question), not MQTT.
            owned = session is None and via in ("telegram", "dashboard")
            if acts:
                system = with_actions(system, "session" if session else
                                      "asked" if owned else "qa", a.actions.live)
            if owned:
                system = with_memory_tools(system)
            shell = owned and await a.shell.ready()
            if shell:
                system = with_shell(system)
            t0 = time.time()
            changes: list = []
            ran: list = []
            src = {**source, "asked": True, "ran": ran} if (acts and owned) else source
            try:
                with (a.actions.source(**src) if acts else contextlib.nullcontext()), \
                        (a.shell.turn(via, (source or {}).get("question") or question, ran)
                         if shell else contextlib.nullcontext()), \
                        (a.memory.turn(via, (source or {}).get("question") or question)
                         if owned else contextlib.nullcontext()) as mt:
                    try:
                        text = await asyncio.wait_for(
                            a.agent.ask_text(system, ctx, history=history, on_event=on_event,
                                             max_iters=self.session_iters if session
                                             else self.max_iters),
                            timeout=self.session_wall_s if session else self.max_wall_s)
                    finally:
                        changes = list((mt or {}).get("changes") or [])
            except asyncio.TimeoutError:
                text = None
            log.info("question answered in %.1fs (tool calls=%d, ok=%s, ctx peak=%s)",
                     time.time() - t0, a.agent.last_tool_calls, text is not None,
                     a.agent.last_ctx_peak)
            if owned and text:
                text = strip_footer(text) or None
            if changes:
                # printed by the code, whatever the model said — or if it said nothing
                foot = a.memory.footer(changes)
                text = f"{text}\n\n{foot}" if text else foot
            if ran and via == "telegram" and text:
                # what ran on the owner's say-so, listed where they read the answer (the
                # dashboard shows each step on the turn itself)
                text += "\n\n" + ran_footer(ran)
            return text

    async def investigate(self, p: dict) -> Optional[str]:
        """An approved investigation session: the model's own turn to run the checks it asked
        for and report — back where the request came from. A dashboard conversation gets a
        turn of its own (streamed); a Telegram question gets a reply in the chat; the audit's
        lands on the session's own message, which Actions keeps edited."""
        via, origin = p.get("via"), p.get("origin") or {}
        brief = investigation_brief(p)
        if via == "dashboard":
            convs = getattr(getattr(self.a, "dashboard", None), "chats", None)
            if convs is not None:
                return await convs.session_turn(origin.get("conv"), p, brief)
        src = {"via": via or "telegram",
               **({"chat_id": origin["chat_id"]} if origin.get("chat_id") else {}),
               **({"question": origin["question"]} if origin.get("question") else {})}
        text = await self.answer(brief, source=src, session=p)
        if via == "audit":
            await self.a.actions.flush_audit()    # what it proposed along the way
        elif via == "telegram":
            await self._reply(str(origin.get("chat_id") or ""),
                              f"🔎 <b>Investigation #{p['id']} — findings</b>\n"
                              + ("🦉 " + _html(text) if text else
                                 "The model did not finish a report — the checks it ran are on "
                                 "the session's message."))
        return text

    async def _answer_telegram(self, question: str, chat_id: str):
        if self.a.no_llm:
            await self._reply(chat_id, self._off_text(False))
            return
        typing = asyncio.ensure_future(self._typing(chat_id))

        async def waiting():
            await self._reply(chat_id, "⏳ I'm in the middle of the hourly audit — your answer "
                                       "follows as soon as it's done.")
        try:
            text = await self.answer(question, on_wait=waiting,
                                     history=self._tg_history(chat_id),
                                     source={"via": "telegram", "chat_id": chat_id,
                                             "question": question})
        finally:
            typing.cancel()
        if text:
            self._tg_keep(chat_id, question, text)
            await self._reply(chat_id, "🦉 " + _html(text))       # the model's words: the owl's mark
        elif self.a.no_llm:                  # switched off while it was answering
            await self._reply(chat_id, self._off_text(True))
        else:
            rep = self.a._last_report
            await self._reply(chat_id, "🤷 I couldn't work that out (the model did not answer in "
                                       "time). Here is what I know for certain:\n\n"
                              + (format_digest(rep, title="Right now") if rep else ""))

    def _off_text(self, stopped: bool) -> str:
        rep = self.a._last_report
        head = ("🦉 The owl fell asleep before it could answer (the local model was switched off)."
                if stopped else "🦉 The owl is asleep (the local model is off), so it can't answer questions.")
        tail = "" if self.a._no_llm_cli else " <i>/model on</i> switches it back on."
        return (head + tail + (" Here is what I know for certain:\n\n"
                               + format_digest(rep, title="Right now") if rep else ""))

    async def _answer_mqtt(self, question: str):
        text = await self.answer(question)
        self.a.mqtt.publish("answer", {"q": question, "a": text or (
            "(no answer — the local model is off)" if self.a.no_llm else
            "(no answer — the model did not respond in time)"), "ts": time.time()}, retain=True)

    # --- the Telegram conversation ---------------------------------------------
    def _tg_history(self, chat_id: str, now: Optional[float] = None) -> list:
        """The chat's earlier questions and answers, as the messages the model is shown first
        — [] (a new conversation, but with the conversation's prompt) after /new or a long
        silence."""
        now = now or time.time()
        turns = (self._tg.get(str(chat_id)) or {}).get("turns") or []
        if not turns or now - float(turns[-1].get("ts") or 0) > TG_IDLE_S:
            return []
        msgs = []
        for t in turns[-TG_TURNS:]:
            a = strip_footer(t["a"])
            a = a if len(a) <= TG_CHARS else a[:TG_CHARS] + " […]"
            msgs += [{"role": "user", "content": t["q"]}, {"role": "assistant", "content": a}]
        return msgs

    def _tg_keep(self, chat_id: str, q: str, a: str):
        now = time.time()
        c = self._tg.setdefault(str(chat_id), {"turns": []})
        turns = c["turns"]
        if turns and now - float(turns[-1].get("ts") or 0) > TG_IDLE_S:
            turns.clear()
        turns.append({"q": q[:1000], "a": a[:TG_CHARS * 2], "ts": now})
        del turns[:-TG_TURNS]
        self._tg_save()

    def _tg_save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(TG_RECORD, {"chats": self._tg})
        except Exception:
            log.warning("telegram conversations not saved", exc_info=True)

    # --- plumbing -----------------------------------------------------------
    async def _typing(self, chat_id: str):
        """'typing…' in the chat for as long as the model thinks (Telegram shows it ~5s)."""
        try:
            while True:
                await telegram_call(self.cfg, "sendChatAction",
                                    {"chat_id": chat_id, "action": "typing"}, timeout_s=10)
                await asyncio.sleep(4.5)
        except asyncio.CancelledError:
            pass

    async def _reply(self, chat_id: str, text: str):
        """Straight to the chat that asked. Not through the outbox: an answer that arrives an
        hour late, after an outage, answers a question nobody is still asking."""
        if self.a.no_telegram:
            log.info("telegram suppressed (--no-telegram) [reply]: %.100s", text)
            return
        try:
            ok = await telegram_direct(self.cfg, text, chat_id=chat_id)
        except Exception as e:
            log.warning("telegram chat: reply rejected (%s)", e)
            return
        if not ok:
            log.warning("telegram chat: reply not delivered")
