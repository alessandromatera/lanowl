"""Actions the model may PROPOSE and the owner must APPROVE — and, in live mode, that then run.

A model that can only look can say what is wrong but never settle it. So it may PROPOSE, and
the owner approves every action with a button, on Telegram or the dashboard. Shadow mode (the
default) records what WOULD have run, to see what it proposes before anything is live. The
shape:

  - the model gets ONE new tool, `propose_action`, over a fixed catalog (CATALOG). It never
    writes a command: it names an action and a device, and this module builds the command;
  - every proposal is checked against the rules (inventory only, the main LAN only, never
    lanowl's own machine, per-action deny lists, rate limits, a cooldown after anything
    that actually ran) and against the device itself, read-only, BEFORE anyone is asked
    (`_check`). A Shelly whose relay would come back OFF after a reboot is refused here — a
    contactor or a pump can be set up exactly like that;
  - the owner is asked with buttons: on Telegram (one message per proposal, edited through
    its life; from the audit, riding on the incident's own alert — one message per
    incident is the rule) and on the dashboard, where the page behind its login (login.py)
    asks once more in a sheet that names what runs, where, and the risk — so a stray tap
    cannot approve anything;
  - an approval expires after `expire_min`: the network it was proposed for moves on;
  - approving runs the check again, then — live — the action itself (`_execute`), one at a
    time, and reports what happened; in shadow mode it records what WOULD have run.

What runs is built here, from the catalog and validated data, as an argument list: nmap is
exec'd without a shell, the one remote command (a service restart) takes a unit from
an allow-list, a Shelly reboot is one GET to the Shelly's own endpoint. The model's words
(`reason`) are only ever shown, never executed. An action approved on the dashboard is also
announced on Telegram: something that changed the network must never be silent there (the
same rule as pausing a device).

Every proposal — refused ones included — is kept in the `actions` record, so what the model
proposes, and how often the owner says yes, can be read back later.

Investigation sessions: the model LOOKS through `run_check`, over the catalog in checks.py
(ping, mtr, DNS, TLS, scans, host health, the tunnels, captures… from lanowl's host, another
LAN host, the VPN hub and the router), approved per session rather than per command. Its first check with no
session open asks the owner to open one — an `investigate` item with its own buttons, the
checks it wants listed; every further call in that turn joins the list. Approving opens the
session for `session.minutes` / `session.max_checks` and starts a model turn of its own
(Chat.investigate) that runs them, reads each output and reports back where the request came
from. While it is open, questions may run checks too. An End button closes it early. Anything
that CHANGES something stays a proposal with its own button, session or not.

The owner's question is the approval, as with an agent. A turn answering the owner — Telegram or the dashboard,
`source(..., asked=True)` — runs its checks at once (`_run_asked`), up to
`session.max_checks` per answer, with no session and no button; each one is listed under the
Telegram answer and on the dashboard's turn. The hourly audit still has to ask for a
session: nobody asked it anything. Changes are untouched: still a proposal, still a button.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import re
import secrets
import shlex
import time
import xml.etree.ElementTree as ET
from typing import Optional

from . import probes
from .checks import PASSIVE, CheckError, Checks, KEEP_OUT, _exec, parse_nmap_xml  # noqa: F401 (tests patch A._exec)
from .reboot import Rebooter
from .report import _html, label
from .sinks import TelegramRejected, telegram_call, telegram_direct, telegram_edit
from .model import on_main_lan

log = logging.getLogger("lanowl.actions")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

RECORD = "actions"
KEEP = 200                 # proposals kept in the record, refused ones included
SHADOW, LIVE = "shadow", "live"
_VIA = {"telegram": "Telegram", "dashboard": "the dashboard", "audit": "the audit"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_UNIT = re.compile(r"^[A-Za-z0-9@._-]{1,64}$")

# The catalog. Titles are what the owner reads on the button's message.
CATALOG = {
    "nmap_scan": "Scan the open ports",
    "nmap_service": "Identify the services",
    "restart_service": "Restart a service",
    "shelly_reboot": "Reboot the Shelly",
    "reboot": "Reboot the device",
    "apt_upgrade": "Update the system",
    "routeros_upgrade": "Update RouterOS",
    "investigate": "Investigation session",
}
PROPOSABLE = ("nmap_scan", "nmap_service", "restart_service", "shelly_reboot",
              "reboot", "apt_upgrade", "routeros_upgrade")


def unit_risk(unit: str) -> str:
    """What restarting a service interrupts, said on the button's message."""
    if unit.startswith("wg-quick@"):
        return ("every WireGuard tunnel it carries drops until it is back (seconds, if it "
                "comes back up)")
    return f"{unit} is interrupted while it restarts"

# After an action that CHANGED something ran on a device, the same action on it is refused
# for this long (catalog.<action>.cooldown_min overrides): no reboot loops, from anyone.
COOLDOWN_MIN = {"restart_service": 30, "shelly_reboot": 30, "reboot": 30,
                "apt_upgrade": 60, "routeros_upgrade": 60}
RUN_TIMEOUT_S = {"nmap_scan": 180, "nmap_service": 240, "restart_service": 100,
                 "shelly_reboot": 120, "reboot": 780, "apt_upgrade": 3300,
                 "routeros_upgrade": 2000}          # both include the backup taken first;
                                                    # RouterOS + firmware = two reboots
STEPS_SHOWN = 12           # checks listed on a session's Telegram message
SHELLY_BACK_S = 90         # how long a rebooting Shelly may take to answer again
SHELLY_FIRST_S = 4         # ...before the first look (it is still going down)
SHELLY_POLL_S = 3


def cap_first(s: str) -> str:
    return s[:1].upper() + s[1:]


# Keys that held the dashboard PIN: approvals are a confirm on the logged-in page now
OLD_PIN_KEYS = ("pin_sha256", "pin_max_failures", "pin_lockout_min")


def report(cfg: dict) -> tuple:
    """(text, problems) for `lanowl --check`. Never a value."""
    c = cfg.get("actions") or {}
    if not c.get("enabled"):
        head = "Actions: off (actions.enabled)"
    else:
        head = f"Actions: on · {c.get('mode', SHADOW)}"
    old = [k for k in OLD_PIN_KEYS if k in c]
    if old:
        head += (f"\n  ○ {'dashboard PIN':<15} not used any more (the dashboard asks you to "
                 f"confirm instead): remove {', '.join('actions.' + k for k in old)}")
    return head, 0


def _hm(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def _after_reboot(gen: int, default: str, on: Optional[bool]) -> Optional[bool]:
    """What a Shelly output does after a restart, from its power-on setting. None = cannot
    tell (it follows a wall switch we cannot see, or its current state is unknown)."""
    d = str(default or "").lower()
    if d in ("last", "restore_last"):
        return on
    if d == "on":
        return True
    if d == "off":
        return False
    return None


async def _get_json(url: str, timeout_s: float = 4.0) -> Optional[dict]:
    """A read-only GET, JSON back, or None."""
    if aiohttp is None:
        return None
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as s:
            async with s.get(url, allow_redirects=False) as r:
                if r.status != 200:
                    return None
                js = await r.json(content_type=None)
                return js if isinstance(js, dict) else None
    except Exception:
        return None


async def _http_get(url: str, timeout_s: float = 6.0) -> Optional[int]:
    """One GET whose answer does not matter beyond its status — the Shelly reboot call."""
    if aiohttp is None:
        return None
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as s:
            async with s.get(url, allow_redirects=False) as r:
                await r.read()
                return r.status
    except Exception:
        return None


class Actions:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("actions") or {}
        self.switched_on = bool(c.get("enabled", False))     # config.yaml
        mode = str(c.get("mode", SHADOW))
        if mode not in (SHADOW, LIVE):
            log.warning("actions.mode %r is not a mode — running in shadow mode: nothing is "
                        "executed", mode)
            mode = SHADOW
        self.mode = mode
        self.expire_s = float(c.get("expire_min", 15)) * 60
        self.max_pending = int(c.get("max_pending", 3))
        self.max_per_day = int(c.get("max_per_day", 20))
        self.quiet_s = float(c.get("repeat_after_h", 24)) * 3600
        self.cat = c.get("catalog") or {}
        sess = c.get("session") or {}
        self.sess_min = float(sess.get("minutes", 15))
        self.sess_checks = int(sess.get("max_checks", 15))
        self.audit_checks = int(sess.get("audit_checks", 4))     # PASSIVE ones, per audit
        self.sess_day = int(sess.get("max_per_day", 8))
        self.checks = Checks(auditor)
        self.reboot = Rebooter(auditor, self.cat.get("reboot") or {})
        self._check_lock = asyncio.Lock()    # one check at a time, whichever turn asks
        self.items: list = []
        # Telegram messages that carry proposals: str(message_id) -> {"key": the incident it
        # announced ("" = a message of our own), "head", "base", "pids"}
        self.msgs: dict = {}
        self._next = 1
        self._src: Optional[dict] = None     # who is asking, for the model turn in progress
        self._audit_batch: list = []         # proposed during an audit, delivered after it
        self._tasks: set = set()
        self._run_lock = asyncio.Lock()      # one action at a time, whoever approved it
        self._cur: Optional[dict] = None     # the one running: step() writes on it
        self._restore()

    @property
    def live(self) -> bool:
        return self.mode == LIVE

    @property
    def enabled(self) -> bool:
        """Switched on in config.yaml."""
        return self.switched_on

    def off_reason(self) -> str:
        return "actions are switched off (actions.enabled)"

    # --- persistence ---------------------------------------------------------
    def _restore(self):
        try:
            rec = self.a.state.load_record(RECORD) or {}
        except Exception:
            log.warning("actions: record unreadable, starting empty", exc_info=True)
            return
        self.items = [p for p in (rec.get("items") or []) if isinstance(p, dict)][-KEEP:]
        self.msgs = {str(k): v for k, v in (rec.get("msgs") or {}).items() if isinstance(v, dict)}
        self._next = max([int(rec.get("next") or 1)] + [int(p.get("id") or 0) + 1 for p in self.items])
        for p in self.items:
            if p.get("action") == "investigate" and p.get("status") == "open":
                # no model turn survives a restart, and a session is that turn's permission
                p.update(status="done", done_ts=time.time(),
                         outcome={**(p.get("outcome") or {}), "ended": "restart"})
            if p.get("status") == "running" and p.pop("queued", None):
                # approved, but still waiting its turn: it never started
                p.update(status="skipped", done_ts=time.time(),
                         outcome={"ran": False, "check": "lanowl restarted before its "
                                                         "turn came — nothing was done"})
            if p.get("status") == "running":
                # The process died while checking or running it. Never re-run: whether the
                # action happened is unknown, and saying so is the honest answer.
                p.update(status="failed", done_ts=p.get("decided_ts"),
                         outcome={**(p.get("outcome") or {}),
                                  "error": "lanowl restarted while this was running — "
                                           "whether it completed is unknown"})

    def _save(self):
        if not self.a._persist_alerts:            # a --once rehearsal never writes the record
            return
        live = {p["id"] for p in self.items if p.get("id")}
        msgs = {k: v for k, v in self.msgs.items() if set(v.get("pids") or []) & live}
        # a session's raw outputs are for reading it today; older ones keep their summaries
        for p in [x for x in self.items if x.get("action") == "investigate"][:-10]:
            for st in p.get("steps") or []:
                st.pop("output", None)
        try:
            self.a.state.save_record(RECORD, {"next": self._next, "items": self.items[-KEEP:],
                                              "msgs": msgs})
            self.msgs = msgs
        except Exception as e:
            log.warning("actions: record not saved: %s", e)

    def _event(self, p: dict):
        self.a._on_event("action", None, json.dumps(
            {k: p.get(k) for k in ("id", "action", "ip", "via", "status")}, ensure_ascii=False))

    def _get(self, pid) -> Optional[dict]:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return None
        return next((p for p in self.items if p.get("id") == pid), None)

    def _spawn(self, coro):
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    # --- who is asking --------------------------------------------------------
    @contextlib.contextmanager
    def source(self, via: str, **kw):
        """The model turn in progress may propose, on behalf of `via` (telegram | dashboard |
        audit). Turns take the model one at a time (Auditor.model_turn), so one slot will do.
        Outside such a block the tool is not even offered: the weekly review, the log
        triages and MQTT questions cannot propose anything. `asked=True`: the owner's own
        question, whose checks run at once; `ran`: a list each one is appended to."""
        prev = self._src
        self._src = {"via": via, **kw} if self.enabled else None
        try:
            yield
        finally:
            cur, self._src = self._src, prev
            # A session asked for during a question goes out when the turn is over, with
            # every check the model called listed — not one message per call. The audit's
            # rides on its alert (flush_audit), like its proposals.
            pid = (cur or {}).get("session_req")
            p = self._get(pid) if pid else None
            if p is not None and p.get("status") == "pending" and not p.get("tg") \
                    and p["via"] != "audit":
                head = ("🔎 <b>Asked from your question</b>" if p["via"] == "telegram" else
                        "🔎 <b>Asked from a question on the dashboard</b>")
                self._spawn(self._send_own([pid], head, notify=True))

    def offered(self) -> bool:
        return self.enabled and self._src is not None

    def _cfg(self, action: str) -> dict:
        return self.cat.get(action) or {}

    def _restartable(self) -> dict:
        """ip -> [units]: the devices whose listed services may be restarted (`manage:
        [restart]` with `restart: {units: [...]}` in the inventory, kinds.py)."""
        out = {}
        for ip, v in (self._cfg("restart_service").get("hosts") or {}).items():
            units = [str(u).removesuffix(".service") for u in ((v or {}).get("units") or [])
                     if _UNIT.match(str(u))]
            if units:
                out[str(ip)] = units
        return out

    def _restart_listing(self) -> str:
        out = []
        for ip, units in self._restartable().items():
            dev = self.a.inv.get(ip)
            out.append(f"{dev.name if dev else ip} {ip} ({', '.join(units)})")
        return "; ".join(out) or "none"

    def _shelly_ok(self, dev) -> bool:
        """A Shelly whose controller may be restarted: `kind: shelly` with `manage: [reboot]`
        (kinds.py). A device with no kind is judged by its name, as before kinds."""
        allowed = self._cfg("shelly_reboot").get("devices")
        kind = str(dev.attrs.get("kind") or "")
        if allowed is not None:
            return dev.ip in {str(x) for x in allowed}
        return kind == "shelly" or (not kind and dev.name.lower().startswith("shelly"))

    def _cooldown_s(self, action: str) -> float:
        return float(self._cfg(action).get("cooldown_min", COOLDOWN_MIN.get(action, 0))) * 60

    def spec(self) -> dict:
        """The tool as the model sees it. The catalog is spelt out in the description because
        a local model reads descriptions far more reliably than enums."""
        return {"type": "function", "function": {
            "name": "propose_action",
            "description": (
                "PROPOSE one action to the owner. Nothing happens unless the owner approves it "
                "with a button, later: this call returns at once and you will NOT learn the "
                "result in this turn. Actions: "
                "nmap_scan — which TCP ports are open on a device (top 100); "
                "nmap_service — what software answers on 1 to 10 given ports of a device; "
                f"restart_service — restart one listed service, only on: {self._restart_listing()} "
                "(a WireGuard unit drops the tunnels it carries for a moment); "
                "shelly_reboot — restart a Shelly's controller (it never switches what the "
                "Shelly powers; refused when a restart would change a relay); "
                "reboot — restart a whole device, only one of: "
                f"{self.reboot.listing()} (its alerts are held while it restarts); "
                "apt_upgrade — update a Linux machine (its waiting apt updates) on "
                f"{', '.join(self.a.updates.upgradable()) or 'none'} (never reboots); "
                "routeros_upgrade — install MikroTik's newer RouterOS on "
                f"{', '.join(self.a.updates.ros_upgradable()) or 'none'} (downloads, then "
                "reboots it; its alerts are held). "
                "Only for devices in the inventory. "
                "Propose only when it would clearly settle or fix something. To LOOK at "
                "anything (ping, mtr, DNS, certificates, scans, a host's health, the tunnels) "
                "use run_check instead."),
            "parameters": {"type": "object", "properties": {
                "action": {"type": "string", "enum": list(PROPOSABLE)},
                "ip": {"type": "string",
                       "description": "the device it applies to"},
                "reason": {"type": "string",
                           "description": "one sentence for the owner: what you expect it to "
                                          "show or fix"},
                "ports": {"type": "array", "items": {"type": "integer"},
                          "description": "nmap_service only: the ports to identify"},
                "service": {"type": "string",
                            "description": "restart_service only: one of that device's "
                                           "listed services"},
            }, "required": ["action", "ip", "reason"]}}}

    # --- proposing ------------------------------------------------------------
    async def propose(self, args: dict) -> dict:
        """The tool call. Returns what the model is told."""
        src = self._src
        if not (self.enabled and src):
            return {"error": "proposing actions is not available here"}
        return await self._propose(args if isinstance(args, dict) else {}, src)

    async def ask(self, action: str, ip: str, via: str) -> dict:
        """The owner asked for it themselves: /reboot on Telegram, the Reboot
        button in a device's sheet on the dashboard. The same rules and the same check as a
        proposal of the model's — and still a button to press (Telegram) or a confirm
        (dashboard): a typo must not reboot the wrong thing. {"proposal"} or {"refused"}."""
        if not self.enabled:
            return {"refused": self.off_reason()}
        return await self._propose({"action": action, "ip": ip, "reason": ""},
                                   {"via": via, "owner": True})

    async def _propose(self, args: dict, src: dict) -> dict:
        now = time.time()
        p = {"id": None, "action": str(args.get("action") or "").strip(),
             "ip": str(args.get("ip") or "").strip(),
             "reason": " ".join(str(args.get("reason") or "").split())[:300],
             "via": src["via"], "ts": now, "args": {}, "risk": [], "mode": self.mode}
        if src.get("owner"):
            p["owner"] = True
        err = self._validate(p, args)
        if not err:
            dup = next((x for x in self.items if x.get("status") == "pending"
                        and x["action"] == p["action"] and x["ip"] == p["ip"]
                        and x.get("args") == p["args"]), None)
            busy = next((x for x in self.items if x.get("status") == "running"
                         and x["ip"] == p["ip"]), None)
            if busy is not None and p.get("owner"):
                return {"refused": f"#{busy['id']} ({CATALOG.get(busy['action'], busy['action'])}) "
                                   + ("is queued on it — wait for it, or cancel it"
                                      if busy.get("queued") else
                                      "is running on it right now — wait for it to finish")}
            if dup is not None:
                return {"proposal": dup["id"], "already": True,
                        "status": "already proposed and still waiting for the owner (until "
                                  f"{_hm(dup['expires'])}) — do not propose it again"}
            err = self._limits(p, now)
        if not err:
            try:
                chk = await self._check(p)
            except Exception:
                log.exception("actions: check of %s on %s failed", p["action"], p["ip"])
                chk = {"ok": False, "note": "the safety check itself failed"}
            if chk["ok"]:
                p["check"] = chk["note"]
                p["risk"] += chk.get("risk") or []
            else:
                err = chk["note"]

        p["id"] = self._next
        self._next += 1
        if err:
            p.update(status="refused", refused=err)
            self._keep(p)
            log.info("actions: #%d %s on %s REFUSED (%s): %s", p["id"], p["action"], p["ip"],
                     p["via"], err)
            return {"refused": err, "note": "Nothing was proposed to the owner."}
        p.update(status="pending", nonce=secrets.token_hex(4), expires=now + self.expire_s)
        self._keep(p)
        log.info("actions: #%d %s on %s proposed (%s): %s", p["id"], p["action"], p["ip"],
                 p["via"], p["reason"])
        cb = src.get("on_proposed")
        if cb is not None:
            try:
                cb(p["id"])
            except Exception:
                log.debug("on_proposed failed", exc_info=True)
        if p.get("owner"):
            # on Telegram the buttons ARE the answer to /reboot; the dashboard asks for the
            # confirm at once, and what then runs is announced on Telegram (_announce)
            if p["via"] == "telegram":
                self._spawn(self._send_own([p["id"]], "🔁 <b>You asked for it</b>", notify=False))
            return {"proposal": p["id"]}
        if p["via"] == "audit":
            self._audit_batch.append(p["id"])     # after the diagnosis, on the incident's alert
        else:
            head = ("🛠 <b>Proposed from your question</b>" if p["via"] == "telegram" else
                    "🛠 <b>Proposed from a question on the dashboard</b>")
            self._spawn(self._send_own([p["id"]], head, notify=True))
        return {"proposal": p["id"], "status": "waiting for the owner's approval",
                "expires": _hm(p["expires"]),
                "mode": ("LIVE: if the owner approves, it runs, and the result is reported to "
                         "them — you will see it in a later turn" if self.live else
                         "DRY RUN: even if the owner approves, nothing will be executed — this "
                         "is a test of what you would propose"),
                "tell_the_owner": "what you proposed and why, in one line; do not claim it "
                                  "ran or what it found"}

    def _keep(self, p: dict):
        self.items = (self.items + [p])[-KEEP:]
        self._save()
        self._event(p)

    def _nmap_argv(self, p: dict) -> list:
        if p["action"] == "nmap_service":
            return ["nmap", "-sT", "-sV", "-Pn", "-p", ",".join(map(str, p["args"]["ports"])),
                    p["ip"]]
        return ["nmap", "-sT", "-Pn", "--top-ports", "100", "-T4", p["ip"]]

    def _validate(self, p: dict, args: dict) -> str:
        """The rules. Returns why not, or "" — and fills in the command the owner will read."""
        action, ip = p["action"], p["ip"]
        if action not in PROPOSABLE or not self._cfg(action).get("enabled", True):
            return f"unknown action {action!r}; the catalog is: {', '.join(PROPOSABLE)}"
        dev = self.a.inv.get(ip)
        if dev is None or not _IPV4.match(ip):
            return f"{ip or 'that'} is not a device in the inventory"
        p["name"] = dev.name
        if action == "reboot" and not self.reboot.can(ip) and self._shelly_ok(dev):
            # a Shelly has its own reboot, whose check protects what its relays power
            action = p["action"] = "shelly_reboot"
        if action == "routeros_upgrade":
            hosts = self.a.updates.ros_upgradable()
            if ip not in hosts:
                return (f"RouterOS can be updated from here only on: "
                        f"{', '.join(hosts) or 'none'}")
            p["command"] = (f"ssh {ip}: /system package update download, then /system reboot "
                            "(it installs while it boots)"
                            + (" — backed up first" if self.a.backups.covers(ip) else ""))
            if hosts[ip].get("risk"):
                p["risk"].append(str(hosts[ip]["risk"]))
            return ""
        if action == "apt_upgrade":
            hosts = self.a.updates.upgradable()
            if ip not in hosts:
                return (f"updates can be installed from here only on: "
                        f"{', '.join(hosts) or 'none'}")
            p["command"] = (f"ssh {ip}: apt-get upgrade --with-new-pkgs (non-interactive, "
                            "config files kept, nothing restarted by needrestart)"
                            + (" — backed up first" if self.a.backups.covers(ip) else ""))
            if hosts[ip].get("risk"):
                p["risk"].append(str(hosts[ip]["risk"]))
            return ""
        if action == "restart_service":
            # its own allow-list decides (the inventory's `restart: {units}`), a VPS included
            units = self._restartable().get(ip)
            if not units:
                return (f"{dev.name} has no service lanowl may restart; it can restart: "
                        f"{self._restart_listing()}")
            if ip == str((self.a.cfg.get("observer") or {}).get("host_ip") or ""):
                return f"{dev.name} is lanowl's own machine"
            unit = str(args.get("service") or "").strip().removesuffix(".service")
            if unit not in units:
                return (f"service {unit!r} is not in {dev.name}'s list; it can be one of: "
                        f"{', '.join(units)}")
            p["args"] = {"service": unit}
            p["command"] = f"systemctl restart {unit}.service on {dev.name}"
            p["risk"].append(unit_risk(unit))
            return ""
        if action == "reboot":
            # the allow-list decides (the inventory's `manage: [reboot]`), the VPS included;
            # never this machine
            if not self.reboot.can(ip):
                return (f"{dev.name} is not a device lanowl can reboot; it can reboot: "
                        f"{self.reboot.listing()}")
            if ip == str((self.a.cfg.get("observer") or {}).get("host_ip") or ""):
                return f"{dev.name} is lanowl's own machine"
            via = self.reboot.via(ip)
            p["command"] = {"routeros": f"ssh {ip}: /system reboot",
                            "ssh": f"ssh {ip}: reboot",
                            "ssh_key": f"ssh root@{ip}: systemctl reboot",
                            "reolink": f"POST http://{ip}/api.cgi?cmd=Reboot",
                            "homeassistant": "Home Assistant: hassio.host_reboot",
                            "ha_button": "Home Assistant: button.press "
                                         f"{(self.reboot.devices.get(ip) or {}).get('entity', '')}",
                            "profile": f"ssh {ip}: its {dev.attrs.get('kind', '')} profile's reboot",
                            }.get(via, f"{via}: reboot")
            if dev.criticality == "critical":
                p["risk"].append(f"{dev.name} is a CRITICAL device: it is down while it restarts")
            return ""
        if not on_main_lan(self.a.cfg, ip) or dev.attrs.get("depends_on"):
            return f"{dev.name} is not on the main LAN — actions only apply there"
        if ip == str((self.a.cfg.get("observer") or {}).get("host_ip") or ""):
            return f"{dev.name} is lanowl's own machine"
        c = self._cfg(action)
        if ip in [str(x) for x in (c.get("deny_ips") or [])] or \
                dev.group in (c.get("deny_groups") or []):
            return f"{action} is not allowed on {dev.name} ({dev.group})"
        if action == "nmap_scan":
            p["command"] = " ".join(self._nmap_argv(p))
        elif action == "nmap_service":
            raw = args.get("ports")
            raw = raw if isinstance(raw, list) else [raw] if raw not in (None, "") else []
            try:
                ports = sorted({int(x) for x in raw})
            except (TypeError, ValueError):
                return "ports must be numbers"
            if not ports or len(ports) > 10 or not all(0 < x < 65536 for x in ports):
                return "nmap_service needs 1 to 10 ports (1-65535)"
            p["args"] = {"ports": ports}
            p["command"] = " ".join(self._nmap_argv(p))
        elif action == "shelly_reboot":
            if not self._shelly_ok(dev):
                return f"{dev.name} is not a Shelly lanowl may restart"
            p["command"] = f"GET http://{ip}/reboot"      # the generation is read by _check
            if dev.criticality == "critical":
                p["risk"].append(f"{dev.name} is a CRITICAL device: what it powers may drop "
                                 "for a moment while it restarts")
        return ""

    def _limits(self, p: dict, now: float) -> str:
        # Both caps keep the MODEL from flooding the owner: the owner's own presses neither hit
        # them nor use them up (a day of the owner's own updates would otherwise fill the cap,
        # and their presses the next morning be refused)
        if not p.get("owner"):
            live = [x for x in self.items if x.get("status") == "pending" and not x.get("owner")]
            if len(live) >= self.max_pending:
                return (f"{len(live)} proposals are already waiting for the owner — no more "
                        "until they are answered")
            day = [x for x in self.items if x.get("status") != "refused" and not x.get("owner")
                   and now - x["ts"] < 86400]
            if len(day) >= self.max_per_day:
                return f"the limit of {self.max_per_day} proposals a day is reached"
        # the cooldown keeps the MODEL from reboot loops; the owner's own press decides for
        # itself (an Update pressed again after one ran must not be refused for an hour)
        cool = 0 if p.get("owner") else self._cooldown_s(p["action"])
        if cool:
            ran = next((x for x in reversed(self.items) if x.get("status") in ("done", "failed")
                        and (x.get("outcome") or {}).get("ran")
                        and x["action"] == p["action"] and x["ip"] == p["ip"]
                        and now - (x.get("done_ts") or x["ts"]) < cool), None)
            if ran is not None:
                return (f"it already ran on this device at {_hm(ran.get('done_ts') or ran['ts'])}"
                        f" — not again for {cool / 60:.0f} min after that")
        if p["via"] == "audit":
            # An hourly audit that sees the same thing proposes the same thing — every hour.
            # Once the owner has seen one, answered or not, that is enough for a day. A
            # question is different: the owner is asking now.
            # For a session, only the audit's own count: one the owner opened from a question
            # in the morning must not keep the audit from looking into an afternoon outage.
            prev = next((x for x in reversed(self.items) if x.get("status") != "refused"
                         and x["action"] == p["action"] and x["ip"] == p["ip"]
                         and (p["action"] != "investigate" or x.get("via") == "audit")
                         and now - x["ts"] < self.quiet_s), None)
            if prev is not None:
                return (f"the same action was proposed at {_hm(prev['ts'])} and is "
                        f"{self._status_words(prev)} — not again today")
        return ""

    # --- the read-only check --------------------------------------------------
    async def _check(self, p: dict) -> dict:
        """Is it still worth doing, and is it safe? Read-only, a few seconds at most. Run when
        it is proposed and again when it is approved. {"ok", "note", "risk"}."""
        action, ip, name = p["action"], p["ip"], p.get("name") or p["ip"]
        if action in ("nmap_scan", "nmap_service"):
            r = await probes.ping(ip, 1000)
            if not r.ok:
                return {"ok": False, "note": f"{name} is not answering right now — a scan "
                                             "would show nothing"}
            return {"ok": True, "note": f"{name} answering"
                    + (f" ({r.latency_ms:.0f} ms)" if r.latency_ms is not None else "")}
        if action == "restart_service":
            unit = p["args"]["service"]
            q = shlex.quote(f"{unit}.service")
            # is it running, and may this login restart it? `sudo -l <command>` answers for
            # exactly this restart: a narrow NOPASSWD rule counts, a general sudo needs the
            # password the login carries (none: nobody is there to type one)
            pre, pw = self._sudo(ip)
            allowed = (f"; {pre}-l /usr/bin/systemctl restart {q} >/dev/null 2>&1 "
                       "&& echo ALLOWED || echo REFUSED" if pre else "; echo ALLOWED")
            rc, out, err = await self._login_run(ip, f"systemctl is-active {q} || true" + allowed,
                                                 25, sudo_pw=pw)
            if rc is None:
                return {"ok": False, "note": f"cannot reach {name} over ssh: "
                                             f"{(err.strip().splitlines() or ['no answer'])[-1][:120]}"}
            lines = out.strip().splitlines() or ["unknown"]
            state = lines[0] if len(lines) > 1 else "unknown"
            if self.live and lines[-1] != "ALLOWED":
                return {"ok": False, "note": f"lanowl may not restart {unit}.service on {name} "
                                             "(its login has no sudo for it) — it cannot be done "
                                             "from here"}
            return {"ok": True, "note": f"{unit}.service is {state} now"}
        if action == "shelly_reboot":
            return await self._shelly_check(p)
        if action == "reboot":
            return await self.reboot.check(ip, name)
        if action == "apt_upgrade":
            return await self.a.updates.upgrade_check(ip, name)
        if action == "routeros_upgrade":
            return await self.a.updates.ros_upgrade_check(ip, name)
        return {"ok": False, "note": "unknown action"}

    async def _shelly_read(self, ip: str) -> Optional[dict]:
        """{"gen", "model", "outs": [(output, on, power-on setting)], "roller"} or None."""
        info = await _get_json(f"http://{ip}/shelly")
        if info is None:
            return None
        gen = int(info.get("gen") or 1)
        outs, roller = [], False
        if gen >= 2:
            cfg = await _get_json(f"http://{ip}/rpc/Shelly.GetConfig")
            st = await _get_json(f"http://{ip}/rpc/Shelly.GetStatus")
            if cfg is None or st is None:
                return {"gen": gen, "model": info.get("model"), "outs": None, "roller": False}
            roller = any(k.startswith("cover:") for k in cfg)
            for k, v in sorted(cfg.items()):
                if k.startswith("switch:") and isinstance(v, dict):
                    outs.append((k.split(":")[1], (st.get(k) or {}).get("output"),
                                 v.get("initial_state")))
        else:
            s = await _get_json(f"http://{ip}/settings")
            st = await _get_json(f"http://{ip}/status")
            if s is None or st is None:
                return {"gen": gen, "model": info.get("type"), "outs": None, "roller": False}
            roller = s.get("mode") == "roller"
            now_on = st.get("relays") or []
            for i, r in enumerate(s.get("relays") or []):
                outs.append((str(i), (now_on[i] if i < len(now_on) else {}).get("ison"),
                             r.get("default_state")))
        return {"gen": gen, "model": info.get("model") or info.get("type") or "?",
                "outs": outs, "roller": roller}

    async def _shelly_check(self, p: dict) -> dict:
        ip, name = p["ip"], p.get("name") or p["ip"]
        sh = await self._shelly_read(ip)
        if sh is None:
            return {"ok": False, "note": f"{name} does not answer as a Shelly right now "
                                         "(a device that cannot be reached cannot be rebooted)"}
        gen = sh["gen"]
        p["command"] = (f"GET http://{ip}/rpc/Shelly.Reboot" if gen >= 2 else
                        f"GET http://{ip}/reboot")
        if sh["outs"] is None:
            return {"ok": False, "note": f"could not read {name}'s relay settings"}
        if sh["roller"]:
            return {"ok": False, "note": f"{name} drives a roller: a restart is not judged safe"}
        notes, unsafe = [], []
        for idx, on, default in sh["outs"]:
            after = _after_reboot(gen, default, on)
            now_w = {True: "ON", False: "OFF"}.get(on, "in an unknown state")
            if on is None or after is None:
                unsafe.append(f"relay {idx} is {now_w} and powers on as '{default}' — what a "
                              "restart would do to it cannot be told")
            elif after != on:
                unsafe.append(f"relay {idx} is {now_w} now and would come back "
                              f"{'ON' if after else 'OFF'} after a restart (power-on setting "
                              f"'{default}')")
            else:
                notes.append(f"relay {idx} {now_w}, comes back the same ('{default}')")
        if unsafe:
            return {"ok": False, "note": "unsafe: " + "; ".join(unsafe)}
        return {"ok": True, "note": f"{sh['model']} gen {gen}: " + ("; ".join(notes) or "no relay"),
                "outs": sh["outs"]}

    async def _ssh_run(self, ip: str, remote: str, timeout_s: float = 20,
                       root: bool = False) -> tuple:
        """(rc, out, err) of one command on a device lanowl logs in to by its ssh KEY, over the
        key's shared connection (hostlog.py); rc None = could not. Not `HostLogWatcher._ssh`:
        that one marks the host's log as failing when a command fails, and an action is not
        the log. `root`: as root — as it is when the key logs in as root, else through sudo,
        with the login's password on stdin when it carries one, else a NOPASSWD rule."""
        hl = getattr(self.a, "hostlog", None)
        h = next((x for x in (getattr(hl, "hosts", None) or []) if x.ip == ip), None)
        if h is None:
            return None, "", f"{ip} is not a host lanowl logs in to by its key"
        lg, stdin = None, None
        if root and h.user != "root":
            lg = self.a.access.login(ip)
            if lg is not None and lg.password:
                remote, stdin = "sudo -S -p '' sh -c " + shlex.quote(remote), (lg.password + "\n").encode()
            else:
                remote = "sudo -n sh -c " + shlex.quote(remote)
        rc, out, err = await _exec(hl._ssh_argv(h, remote), timeout_s, stdin=stdin)
        if lg is not None and lg.password:
            out, err = out.replace(lg.password, "***"), err.replace(lg.password, "***")
        return rc, out, err

    def _key_host(self, ip: str):
        """Its connection by lanowl's key (hostlog.py), if its login is the key."""
        hl = getattr(self.a, "hostlog", None)
        return next((x for x in (getattr(hl, "hosts", None) or []) if x.ip == ip), None)

    def _sudo(self, ip: str) -> tuple:
        """(prefix, password on stdin?) for one command run as root on `ip`: nothing for root,
        `sudo -S` when the login carries a password, else `sudo -n` (a NOPASSWD rule)."""
        lg = self.a.access.login(ip)
        h = self._key_host(ip)
        user = h.user if h is not None else (lg.user if lg else "")
        if user == "root":
            return "", False
        if lg is not None and lg.password:
            return "sudo -S -p '' ", True
        return "sudo -n ", False

    async def _login_run(self, ip: str, remote: str, timeout_s: float = 20,
                         sudo_pw: bool = False) -> tuple:
        """(rc, out, err) of `remote` on `ip` by whichever login it has: lanowl's key (its
        shared connection, when it has one) or a password. `sudo_pw`: the login's password on
        stdin first."""
        h = self._key_host(ip)
        if h is not None:
            hl = self.a.hostlog
            lg = self.a.access.login(ip)
            pw = lg.password if lg is not None else ""
            rc, out, err = await _exec(hl._ssh_argv(h, remote), timeout_s,
                                       stdin=(pw + "\n").encode() if sudo_pw and pw else None)
            if pw:
                out, err = out.replace(pw, "***"), err.replace(pw, "***")
            return rc, out, err
        return await self.a.access.ssh(ip, remote, sudo_pw=sudo_pw, timeout_s=timeout_s)

    async def _ssh(self, ip: str, remote: str) -> Optional[str]:
        rc, out, _ = await self._login_run(ip, remote, 15)
        return out if rc == 0 else None

    # --- investigation sessions ---------------------------------------------------
    def check_spec(self) -> dict:
        """`run_check` as the model sees it: the catalog, and whether a session is open."""
        src = self._src or {}
        s = None if src.get("asked") else self._session()
        if src.get("asked"):
            left = self.sess_checks - len(src.get("ran") or [])
            state = (f"The owner's question is the approval: each call runs at once and returns "
                     f"the output ({left} left for this answer).")
        elif s:
            state = (f"A SESSION IS OPEN until {_hm(s['until'])} ({s['max'] - s['used']} checks "
                     "left): each call runs at once and returns the output.")
        elif src.get("via") == "audit":
            used = sum(1 for r in src.get("ran") or [] if r.get("kind") == "check")
            state = (f"In the audit, these PASSIVE checks run at once and return the output — "
                     f"{max(0, self.audit_checks - used)} left this audit: "
                     f"{', '.join(c for c in self.checks.available() if c in PASSIVE)}. Any other "
                     "asks the owner for a session, and only while an incident is open.")
        else:
            state = ("No session is open: your first call asks the owner to open one — nothing "
                     "runs until they approve, then you continue automatically in a new turn. "
                     "Every call you make before that is listed for them as what you plan to run.")
        return {"type": "function", "function": {
            "name": "run_check",
            "description": (
                "Run one READ-ONLY network diagnostic from a fixed catalog. " + state + " Compare vantage "
                f"points: {self.checks.vantage_words()}. "
                "Catalog — name (where): slots — what it answers:\n" + self.checks.describe()),
            "parameters": {"type": "object", "properties": {
                "check": {"type": "string", "enum": self.checks.available()},
                "target": {"type": "string", "description": "an IP address or a full host name"},
                "device": {"type": "string",
                           "description": "the IP of a device in the inventory or on the main LAN"},
                "name": {"type": "string", "description": "a DNS name"},
                "type": {"type": "string", "description": "DNS record type, default A"},
                "ports": {"type": "array", "items": {"type": "integer"}},
                "port": {"type": "integer"},
                "host": {"type": "string",
                         "description": f"{self.checks.home_server} (home server) or "
                                        f"{self.checks.vps} (VPS)"},
                "unit": {"type": "string", "description": "a systemd unit"},
                "iface": {"type": "string", "description": "an interface name"},
                "subnet": {"type": "string", "description": "e.g. 192.168.10.0/24"},
                "link": {"type": "string", "enum": ["main", "backup", "both"]},
                "site": {"type": "string", "description": "the site_* checks: a remote site's key"},
                "mode": {"type": "string"}, "proto": {"type": "string"},
                "count": {"type": "integer"}, "seconds": {"type": "integer"},
                "reason": {"type": "string",
                           "description": "what you want to find out — the session's goal the "
                                          "owner reads, when this call asks for one"},
            }, "required": ["check"]}}}

    def _session(self, now: Optional[float] = None) -> Optional[dict]:
        """The open session, if any — closing one whose time or checks have run out."""
        now = now or time.time()
        for p in self.items:
            if p.get("action") != "investigate" or p.get("status") != "open":
                continue
            if now >= p.get("until", 0):
                self._close(p, "time")
            elif p.get("used", 0) >= p.get("max", self.sess_checks):
                self._close(p, "budget")
            else:
                return p
        return None

    def _close(self, p: dict, why: str, by: str = ""):
        now = time.time()
        p.update(status="done", done_ts=now, until=min(p.get("until") or now, now))
        p["outcome"] = {**(p.get("outcome") or {}), "ended": why, **({"ended_by": by} if by else {})}
        log.info("actions: session #%d closed (%s) after %d checks", p["id"], why, p.get("used", 0))
        self._save()
        self._event(p)
        self._spawn(self._refresh(p))

    def end(self, pid, by: str) -> dict:
        """The owner's End button: no more checks. Needs no confirm — it can only stop something."""
        p = self._get(pid)
        if p is None or p.get("action") != "investigate":
            return {"ok": False, "error": "no such session"}
        if p["status"] == "pending":
            return self.decide(pid, False, by)
        if p["status"] != "open":
            return {"ok": False, "status": p["status"], "error": f"#{p['id']} is already closed"}
        self._close(p, "owner", by)
        return {"ok": True, "status": "done", "text": f"#{p['id']} ended — no more checks."}

    def cancel(self, pid, by: str) -> dict:
        """The owner's Cancel on an approved action still waiting its turn. Needs no confirm — it
        can only stop something; one that has started is never stopped halfway."""
        p = self._get(pid)
        if p is None or p.get("action") == "investigate":
            return {"ok": False, "error": "no such action"}
        if p.get("status") != "running" or not p.get("queued"):
            return {"ok": False, "status": p.get("status"), "error":
                    f"#{p['id']} has already started — it cannot be stopped halfway"
                    if p.get("status") == "running" else
                    f"#{p['id']} is not waiting: {self._status_words(p)}"}
        p.pop("queued", None)
        p.update(status="cancelled", done_ts=time.time(), cancelled_by=by,
                 outcome={"ran": False})
        log.info("actions: #%d %s on %s cancelled by %s before its turn", p["id"], p["action"],
                 p["ip"], by)
        self._save()
        self._event(p)
        self._spawn(self._refresh(p))
        self._requeue()
        return {"ok": True, "status": "cancelled",
                "text": f"#{p['id']} cancelled — nothing was done."}

    def _queue(self) -> list:
        """The approved actions waiting their turn, in the order they will run."""
        return sorted((x for x in self.items if x.get("status") == "running" and x.get("queued")),
                      key=lambda x: x.get("decided_ts") or 0)

    def _queue_words(self, p: dict) -> str:
        """"queued behind #31 (Update the system — NAS (192.168.88.20)) and 1 more"."""
        line = self._queue()
        n = next((i for i, x in enumerate(line) if x is p), len(line))
        cur = next((x for x in self.items if x.get("status") == "running" and not x.get("queued")
                    and x.get("action") != "investigate"), None)
        first = (f"#{cur['id']} ({CATALOG.get(cur['action'], cur['action'])} — "
                 f"{label(cur.get('name'), cur['ip'])})" if cur else "the action before it")
        return f"queued behind {first}" + (f" and {n} more" if n else "")

    def step(self, text: str):
        """What the running action is doing now ("backing up", "restarting — waiting for it to
        answer"): the page's live view, so the owner can tell it is not stuck. Each step is
        kept with its time; one outside a running action is ignored."""
        p = self._cur
        if p is None or p.get("status") != "running":
            return
        trail = p.setdefault("trail", [])
        if not trail or trail[-1]["step"] != text:
            trail.append({"step": text, "ts": time.time()})
            p.pop("detail", None)                 # a new step: the last one's word is stale

    def progress(self, text: str = "", n: int = 0, of: int = 0, error: str = ""):
        """A long step's own latest word — apt's latest line and how many packages are set up —
        or that the machine did not answer this time (the last good word is kept)."""
        p = self._cur
        if p is None or p.get("status") != "running":
            return
        d = p.setdefault("detail", {})
        if error:
            d.update(error=error, error_ts=time.time())
        else:
            d.clear()
            d.update(text=str(text)[:200], n=n, of=of, ts=time.time())

    def _requeue(self):
        """The line moved (one started or was cancelled): the messages of those still in it."""
        for x in self._queue():
            self._spawn(self._refresh(x))

    async def run_check(self, args: dict) -> dict:
        """The `run_check` tool call: run it now inside an open session, or ask for one."""
        src = self._src
        if not (self.enabled and src):
            return {"error": "checks are not available here"}
        args = args if isinstance(args, dict) else {}
        try:
            plan = await self.checks.plan(args.get("check"), args)
        except CheckError as e:
            return {"refused": str(e), "note": "Nothing ran."}
        if src.get("asked"):
            return await self._run_asked(plan)
        if src.get("via") == "audit" and plan["check"] in PASSIVE and self._session() is None:
            # the audit looks by itself, a few passive checks an audit; the rest still asks
            return await self._run_asked(plan, audit=True)
        if self._session() is None:
            return self._want_session(plan, args)
        async with self._check_lock:
            s = self._session()                 # it may have closed while this waited
            if s is None:
                return {"refused": "the investigation session closed before this check ran",
                        "note": "Nothing ran. Answer with what you have."}
            s["used"] = s.get("used", 0) + 1
            log.warning("actions: session #%d check %d/%d (%s): %s", s["id"], s["used"], s["max"],
                        src["via"], plan["command"])
            if self.live:
                res = await self.checks.run(plan)
            else:
                res = {"ok": True, "summary": "DRY RUN — nothing was executed", "output": "",
                       "secs": 0}
        step = {"ts": time.time(), "check": plan["check"], "label": plan["label"],
                "command": plan["command"], "ok": bool(res.get("ok")),
                "summary": str(res.get("summary") or "")[:300],
                "output": str(res.get("output") or "")[:KEEP_OUT], "secs": res.get("secs"),
                "via": src["via"]}
        s.setdefault("steps", []).append(step)
        self._save()
        self._spawn(self._refresh(s))
        left = s["max"] - s["used"]
        if left <= 0:
            self._close(s, "budget")
        return {"check": plan["check"], "ran": plan["label"], "command": plan["command"],
                "ok": step["ok"], "summary": step["summary"], "output": res.get("output") or "",
                "session": f"#{s['id']}: {s['used']}/{s['max']} checks used, open until "
                           f"{_hm(s['until'])}" + ("" if left > 0 else
                                                   " — that was the LAST check: answer now")}

    async def _run_asked(self, plan: dict, audit: bool = False) -> dict:
        """A check in the owner's own question: the question approved it, so it runs now — one
        at a time with any session's (the same lock), at most `session.max_checks` per answer.
        `audit`: a PASSIVE check the hourly audit runs by itself, `session.audit_checks` an
        audit (its shell commands are counted apart)."""
        src = self._src
        ran = src.setdefault("ran", [])
        budget, what = (self.audit_checks, "audit") if audit else (self.sess_checks, "answer")
        used = sum(1 for r in ran if r.get("kind") == "check") if audit else len(ran)
        if used >= budget:
            return {"refused": f"this {what} has used its {budget} checks",
                    "note": "Nothing ran. Answer with what you have."}
        async with self._check_lock:
            log.warning("actions: %s check %d/%d (%s): %s", "audit" if audit else "asked",
                        used + 1, budget, src["via"], plan["command"])
            if self.live:
                res = await self.checks.run(plan)
            else:
                res = {"ok": True, "summary": "DRY RUN — nothing was executed", "output": "",
                       "secs": 0}
        ran.append({"ts": time.time(), "kind": "check", "check": plan["check"],
                    "label": plan["label"], "command": plan["command"], "ok": bool(res.get("ok")),
                    "summary": str(res.get("summary") or "")[:300], "secs": res.get("secs")})
        left = budget - used - 1
        return {"check": plan["check"], "ran": plan["label"], "command": plan["command"],
                "ok": bool(res.get("ok")), "summary": str(res.get("summary") or "")[:300],
                "output": res.get("output") or "",
                "left": f"{left} checks left for this {what}" if left > 0 else
                        f"that was the LAST check for this {what}: answer now"}

    def _want_session(self, plan: dict, args: dict) -> dict:
        """No session is open: ask the owner for one (once per turn — later calls in the same
        turn, or while one is already waiting, join its list of planned checks)."""
        src = self._src
        now = time.time()
        p = self._get(src.get("session_req")) if src.get("session_req") else None
        if p is None or p.get("status") != "pending":
            p = next((x for x in self.items if x.get("action") == "investigate"
                      and x.get("status") == "pending"), None)
        if p is None:
            goal = " ".join(str(args.get("reason") or args.get("goal") or
                                src.get("question") or "").split())[:300]
            n = plan["args"]
            focus = next((x for x in (n.get("device"), n.get("target")) if x and self.a.inv.get(x)), "")
            p = {"id": None, "action": "investigate", "ip": focus, "reason": goal or "investigate",
                 "via": src["via"], "ts": now, "args": {"planned": []}, "risk": [],
                 "mode": self.mode, "command": "",
                 "origin": {k: src[k] for k in ("conv", "chat_id", "question") if src.get(k)}}
            if focus:
                p["name"] = self.a.inv.get(focus).name
            err = self._limits(p, now)
            if not err and p["via"] == "audit" and not self._incident_open():
                # The prompt says so too, and a model may do it anyway on a healthy network
                # ("confirm both internet links are healthy"). A session is for an incident;
                # the audit waits for one.
                err = ("the audit may ask for a session only while an incident is open — the "
                       "network has none now")
            if not err:
                today = [x for x in self.items if x.get("action") == "investigate"
                         and x.get("status") != "refused" and now - x["ts"] < 86400]
                if len(today) >= self.sess_day:
                    err = f"the limit of {self.sess_day} investigation sessions a day is reached"
            p["id"] = self._next
            self._next += 1
            if err:
                p.update(status="refused", refused=err)
                self._keep(p)
                log.info("actions: session #%d REFUSED (%s): %s", p["id"], p["via"], err)
                return {"refused": err, "note": "No session was asked for and nothing ran."}
            p.update(status="pending", nonce=secrets.token_hex(4), expires=now + self.expire_s,
                     max=self.sess_checks, minutes=self.sess_min)
            self._keep(p)
            src["session_req"] = p["id"]
            log.info("actions: session #%d asked for (%s): %s", p["id"], p["via"], p["reason"])
            cb = src.get("on_proposed")
            if cb is not None:
                try:
                    cb(p["id"])
                except Exception:
                    log.debug("on_proposed failed", exc_info=True)
            if p["via"] == "audit":
                self._audit_batch.append(p["id"])
        planned = p["args"].setdefault("planned", [])
        if plan["label"] not in planned and len(planned) < 8:
            planned.append(plan["label"])
            self._save()
            if p.get("tg"):                     # already on Telegram: keep its list current
                self._spawn(self._refresh(p))
        return {"status": "NOT RUN — no investigation session is open",
                "requested": f"session #{p['id']} is waiting for the owner's approval "
                             f"(until {_hm(p['expires'])})",
                "planned_so_far": planned,
                "note": "Every check you call now is added to the list the owner sees; none runs "
                        "until they approve. Once they do, you continue AUTOMATICALLY in a new "
                        "turn with the checks available. Now tell the owner in one or two lines "
                        "what you want to investigate and why, and that it waits for their "
                        "approval. Do not claim any check ran or guess what it would show."}

    def _incident_open(self) -> bool:
        try:
            return bool(self.a._open_incident_keys())
        except Exception:
            return False

    async def _continue(self, p: dict):
        """Approved: the model's own turn to investigate, and its report on the session."""
        try:
            text = await self.a.chat.investigate(p)
        except asyncio.CancelledError:
            text = None
        except Exception:
            log.exception("actions: session #%s: the investigation turn failed", p.get("id"))
            text = None
        p["findings_ts"] = time.time()
        if text and text.strip():
            p["findings"] = text.strip()[:6000]
            p.pop("findings_error", None)
        else:
            p["findings_error"] = "the model did not finish a report"
        self._save()
        self._event(p)
        await self._refresh(p)

    # --- deciding -------------------------------------------------------------
    def decide(self, pid, approve: bool, by: str) -> dict:
        """The owner's answer, from Telegram or the dashboard (a logged-in page, after its
        confirm). An approval checks again and then runs — or, in shadow mode, records the dry
        run — in the background: a button press is answered at once."""
        self.tick()
        p = self._get(pid)
        if p is None or p.get("status") == "refused":
            return {"ok": False, "error": "no such proposal"}
        if p["status"] != "pending":
            return {"ok": False, "status": p["status"],
                    "error": f"#{p['id']} is already {self._status_words(p)}"}
        now = time.time()
        if approve and p["action"] == "investigate":
            other = self._session(now)
            if other is not None:
                return {"ok": False, "error": f"session #{other['id']} is still open (until "
                                              f"{_hm(other['until'])}) — end it first"}
            p.update(decided_by=by, decided_ts=now, status="open", mode=self.mode,
                     opened_ts=now, until=now + float(p.get("minutes") or self.sess_min) * 60,
                     used=0, steps=[])
            p.setdefault("max", self.sess_checks)
            log.warning("actions: session #%d OPENED by %s until %s", p["id"], by, _hm(p["until"]))
            self._save()
            self._event(p)
            self._spawn(self._refresh(p))
            self._spawn(self._continue(p))
            return {"ok": True, "status": "open",
                    "text": f"#{p['id']} approved — session open until {_hm(p['until'])}; the "
                            "model is investigating now."}
        p.update(decided_by=by, decided_ts=now)
        log.info("actions: #%d %s by %s", p["id"], "APPROVED" if approve else "rejected", by)
        if not approve:
            p.update(status="rejected", done_ts=now)
            self._save()
            self._event(p)
            self._spawn(self._refresh(p))
            return {"ok": True, "status": "rejected", "text": f"#{p['id']} rejected."}
        # Live actions run one at a time: one approved while another runs waits its turn, in
        # the order approved, and can be cancelled until then — and the owner sees it queued
        ahead = self.live and any(x.get("status") == "running" and x is not p
                                  and x.get("action") != "investigate" for x in self.items)
        p["status"] = "running"
        p["mode"] = self.mode
        if ahead:
            p["queued"] = True
        self._save()
        self._spawn(self._execute(p) if self.live else self._dry_run(p))
        return {"ok": True, "status": "running", "queued": ahead,
                "text": (f"#{p['id']} approved — {self._queue_words(p)}; it runs when its turn "
                         "comes." if ahead else
                         f"#{p['id']} approved — running it now; the result follows."
                         if self.live else
                         f"#{p['id']} approved — dry run: checking, nothing will be executed.")}

    async def _dry_run(self, p: dict):
        try:
            chk = await self._check(p)
        except Exception:
            log.exception("actions: check of #%s failed", p["id"])
            chk = {"ok": False, "note": "the check itself failed"}
        p.update(status="done" if chk["ok"] else "skipped", done_ts=time.time(),
                 outcome={"dry_run": True, "check": chk["note"],
                          **({"would_run": p.get("command")} if chk["ok"] else {})})
        log.info("actions: #%d %s — dry run, %s", p["id"], p["status"], chk["note"])
        self._save()
        self._event(p)
        await self._refresh(p)

    async def _execute(self, p: dict):
        """Live: check again, then run it — one action at a time, the others queued in the
        order approved — and say what happened."""
        # Nothing is awaited before the lock: the queue is joined in the order approved, and
        # asyncio.Lock serves its waiters first come, first served
        if p.get("queued"):
            self._spawn(self._refresh(p))          # its message says queued, with Cancel
        async with self._run_lock:
            if p.get("status") != "running":      # cancelled while it waited its turn
                return
            p["started_ts"] = time.time()
            p["trail"] = []
            self._cur = p
            if p.pop("queued", None):
                self._save()
                self._event(p)
                self._requeue()                    # the ones behind it moved up
            await self._refresh(p)                 # the buttons go at once: it is running
            self.step("checking it again")
            try:
                chk = await self._check(p)
            except Exception:
                log.exception("actions: check of #%s failed", p["id"])
                chk = {"ok": False, "note": "the check itself failed"}
            if not chk["ok"]:
                p.update(status="skipped", done_ts=time.time(),
                         outcome={"ran": False, "check": chk["note"]})
                log.info("actions: #%d skipped at run time: %s", p["id"], chk["note"])
            else:
                log.warning("actions: #%d RUNNING %s on %s (approved on %s): %s", p["id"],
                            p["action"], p["ip"], p.get("decided_by"), p.get("command"))
                t0 = p["run_ts"] = time.time()
                self.step("running")
                try:
                    res = await asyncio.wait_for(self._run(p, chk),
                                                 timeout=RUN_TIMEOUT_S.get(p["action"], 120))
                except asyncio.TimeoutError:
                    res = {"ok": False, "ran": True,
                           "error": "it did not finish in time — its outcome is unknown"}
                except Exception as e:
                    log.exception("actions: #%s failed", p["id"])
                    res = {"ok": False, "ran": True, "error": f"{type(e).__name__}: {e}"}
                p.update(status="done" if res.get("ok") else "failed", done_ts=time.time(),
                         outcome={"check": chk["note"], "secs": round(time.time() - t0),
                                  **{k: v for k, v in res.items() if k != "ok"}})
                log.warning("actions: #%d %s in %ss: %s", p["id"], p["status"].upper(),
                            p["outcome"]["secs"], res.get("result") or res.get("error"))
            self._cur = None
            p.pop("detail", None)                 # the live word; the steps it took are kept
        self._save()
        self._event(p)
        await self._refresh(p)
        if p.get("decided_by") == "dashboard":
            # the page has no login: anything approved there that ran is said on Telegram
            self.a._emit_telegram("digest", self._announce(p))

    async def _run(self, p: dict, chk: dict) -> dict:
        """The action itself. {"ok", "ran", "result", "lines", "error"}."""
        action = p["action"]
        if action in ("nmap_scan", "nmap_service"):
            rc, out, err = await _exec(self._nmap_argv(p) + ["-oX", "-"],
                                       RUN_TIMEOUT_S[action] - 10)
            if rc is None:
                return {"ok": False, "ran": False, "error": err}
            ports = parse_nmap_xml(out)
            if rc != 0 or ports is None:
                return {"ok": False, "ran": True,
                        "error": f"nmap failed (rc {rc}): {(err.strip().splitlines() or ['?'])[-1][:160]}"}
            shown = ports if action == "nmap_service" else [x for x in ports if x["state"] == "open"]
            lines = [f"{x['port']}/{x['proto']} {x['state']} {x['service']}"
                     + (f" — {x['version']}" if x["version"] else "") for x in shown[:25]]
            if action == "nmap_scan":
                result = (f"{len(shown)} open of the top 100 TCP ports" if shown else
                          "no open port among the top 100 TCP ports")
                if shown:
                    result += ": " + ", ".join(f"{x['port']} {x['service']}".strip()
                                               for x in shown[:12])
            else:
                result = "; ".join(f"{x['port']} {x['state']} {x['service']}"
                                   + (f" ({x['version']})" if x["version"] else "")
                                   for x in shown) or "nmap reported nothing"
            return {"ok": True, "ran": True, "result": result, "lines": lines}

        if action == "restart_service":
            unit = p["args"]["service"]
            q = shlex.quote(f"{unit}.service")
            pre, pw = self._sudo(p["ip"])
            wg = unit.startswith("wg-quick@")
            # after WireGuard: do the peers come back? 20 s is enough for an active one
            tail = (f"; sleep 20; echo ---; date +%s; {pre}wg show "
                    f"{shlex.quote(unit.split('@', 1)[1])} latest-handshakes" if wg else "")
            rc, out, err = await self._login_run(
                p["ip"], f"{pre}/usr/bin/systemctl restart {q}; rc=$?; sleep 4; "
                         f"echo \"rc=$rc\"; systemctl is-active {q} || true{tail}", 80, sudo_pw=pw)
            if rc is None:
                return {"ok": False, "ran": False, "error": err or "ssh failed"}
            head, _, hs = out.partition("---")
            m = re.search(r"rc=(\d+)", head)
            state = (head.strip().splitlines() or ["?"])[-1]
            why = (err.strip().splitlines() or ["?"])[-1][:160]
            if not m or m.group(1) != "0":
                if "sudo" in err:          # never got as far as systemd
                    return {"ok": False, "ran": False, "error": f"the restart was refused: {why}"}
                return {"ok": False, "ran": True,
                        "error": f"systemctl restart failed (rc {m.group(1) if m else '?'}): "
                                 f"{why}; {unit}.service is {state}"}
            result = f"{unit}.service restarted — {state} 4 s later"
            if wg:
                rows = [x.split() for x in hs.strip().splitlines()]
                try:
                    now_r = int(rows[0][0])
                    peers = [int(r[1]) for r in rows[1:] if len(r) == 2]
                    back = sum(1 for t in peers if t and now_r - t < 40)
                    result += f"; {back} of {len(peers)} peers handshook again within 20 s"
                except (IndexError, ValueError):
                    result += "; could not read the peers' handshakes"
            return {"ok": state == "active", "ran": True, "result": result,
                    **({} if state == "active" else
                       {"error": f"{unit}.service is {state} after the restart"})}

        if action == "reboot":
            res = await self.reboot.run(p["ip"], p.get("name") or p["ip"], chk)
            if res.get("ok") and any(h["ip"] == p["ip"] for h in self.a.updates.hosts):
                # its "reboot pending" goes now, not at tomorrow morning's check
                self.a.updates.start("after a reboot")
            return res
        if action in ("apt_upgrade", "routeros_upgrade"):
            # backed up first (backups.py); no backup, no update
            self.step("backing up")
            ok, words = await self.a.backups.before_update(p["ip"], chk.get("snap_replace"))
            if not ok:
                return {"ok": False, "ran": False,
                        "error": f"nothing was updated — {words}"}
            run = (self.a.updates.upgrade_run if action == "apt_upgrade"
                   else self.a.updates.ros_upgrade_run)
            res = await run(p["ip"], p.get("name") or p["ip"], chk)
            if words:
                key = "result" if res.get("ok") else "error"
                res[key] = f"{res.get(key, '')} · {words}"
            return res

        if action == "shelly_reboot":
            ip = p["ip"]
            url = p["command"].split(" ", 1)[1]
            before = {idx: on for idx, on, _ in (chk.get("outs") or [])}
            status = await _http_get(url)
            if status != 200:
                return {"ok": False, "ran": status is not None,
                        "error": f"the Shelly did not accept the reboot (HTTP {status})"}
            t0 = time.time()
            self.step("restarting — waiting for it to answer")
            await asyncio.sleep(SHELLY_FIRST_S)
            sh = None
            while time.time() - t0 < SHELLY_BACK_S:
                sh = await self._shelly_read(ip)
                if sh is not None and sh.get("outs") is not None:
                    break
                sh = None
                await asyncio.sleep(SHELLY_POLL_S)
            if sh is None:
                return {"ok": False, "ran": True,
                        "error": f"rebooted, but not answering {SHELLY_BACK_S} s later"}
            back = round(time.time() - t0)
            after = {idx: on for idx, on, _ in sh["outs"]}
            changed = [f"relay {i} was {'ON' if before[i] else 'OFF'}, is now "
                       f"{'ON' if after.get(i) else 'OFF'}" for i in before
                       if before[i] is not None and after.get(i) != before[i]]
            same = ", ".join(f"relay {i} {'ON' if on else 'OFF'}" for i, on in after.items())
            if changed:
                return {"ok": False, "ran": True, "error": "back after "
                        f"{back} s BUT " + "; ".join(changed)}
            return {"ok": True, "ran": True,
                    "result": f"rebooted — answering again after {back} s, {same or 'no relay'} "
                              "as before"}
        return {"ok": False, "ran": False, "error": "unknown action"}

    def _announce(self, p: dict) -> str:
        o = p.get("outcome") or {}
        icon = {"done": "✅", "failed": "⚠️", "skipped": "⏭"}.get(p["status"], "•")
        what = o.get("result") or o.get("error") or o.get("check") or ""
        return (f"{icon} <b>Approved on the dashboard</b> — #{p['id']} "
                f"{_html(CATALOG[p['action']])}, {_html(label(p.get('name'), p['ip']))}\n"
                f"{_html(what)}")

    def tick(self, now: Optional[float] = None):
        """Expire what nobody answered. Called every sweep and before any decision."""
        now = now or time.time()
        self._session(now)                        # closes one whose time is up
        if self.enabled:
            self._spawn(self.checks.refresh_router_test())    # rate-limited inside
        for p in self.items:
            if p.get("status") == "pending" and now >= p.get("expires", 0):
                p.update(status="expired", done_ts=p["expires"])
                log.info("actions: #%d expired unanswered", p["id"])
                self._event(p)
                self._save()
                self._spawn(self._refresh(p))

    # --- Telegram ---------------------------------------------------------------
    async def on_callback(self, data: str) -> str:
        """A button on Telegram: "ax:<a|r|e|c>:<id>:<nonce>" (approve, reject, end a session,
        cancel a queued action). Returns the toast text. The poller
        has already checked it came from the owner's chat."""
        parts = str(data or "").split(":")
        if len(parts) != 4 or parts[0] != "ax" or parts[1] not in ("a", "r", "e", "c"):
            return "Unknown button."
        p = self._get(parts[2])
        if p is None or not hmac.compare_digest(str(p.get("nonce") or ""), parts[3]):
            return "Unknown proposal."
        if parts[1] in ("e", "c"):
            r = (self.end if parts[1] == "e" else self.cancel)(p["id"], "telegram")
            return r.get("text") or r.get("error") or "Done."
        r = self.decide(p["id"], parts[1] == "a", "telegram")
        return r.get("text") or r.get("error") or "Done."

    def _status_words(self, p: dict) -> str:
        st = p.get("status")
        by = _VIA.get(p.get("decided_by"), p.get("decided_by") or "")
        o = p.get("outcome") or {}
        if st == "pending":
            return f"waiting for the owner until {_hm(p['expires'])}"
        if p.get("action") == "investigate" and st in ("open", "done"):
            n = p.get("used", 0)
            if st == "open":
                return (f"approved on {by} at {_hm(p['decided_ts'])} — session OPEN until "
                        f"{_hm(p['until'])}, {n}/{p.get('max')} checks used")
            why = {"time": "time up", "budget": "every check used", "owner": "ended by the owner",
                   "restart": "lanowl restarted"}.get(o.get("ended"), o.get("ended") or "closed")
            return (f"approved on {by} at {_hm(p['decided_ts'])}, closed at {_hm(p['done_ts'])} "
                    f"({why}) after {n} check{'s' if n != 1 else ''}")
        if st == "running" and p.get("queued"):
            return f"approved on {by} at {_hm(p['decided_ts'])}, {self._queue_words(p)}"
        if st == "running":
            return f"approved on {by}, running now"
        if st == "cancelled":
            return (f"approved on {by} at {_hm(p['decided_ts'])}, cancelled on "
                    f"{_VIA.get(p.get('cancelled_by'), p.get('cancelled_by') or '')} at "
                    f"{_hm(p['done_ts'])} before its turn — nothing was done")
        if st == "done" and o.get("dry_run"):
            return f"approved on {by} at {_hm(p['decided_ts'])} — DRY RUN, nothing was executed"
        if st == "done":
            return f"approved on {by} at {_hm(p['decided_ts'])} and RUN: {o.get('result', '')}"
        if st == "failed":
            return (f"approved on {by} at {_hm(p['decided_ts'])}, "
                    f"{'ran but ' if o.get('ran') else ''}FAILED: {o.get('error', '')}")
        if st == "skipped":
            return f"approved on {by} but not run: {o.get('check', '')}"
        if st == "rejected":
            return f"rejected by the owner on {by} at {_hm(p['decided_ts'])}"
        if st == "expired":
            return f"not answered — expired at {_hm(p['expires'])}"
        if st == "refused":
            return f"refused by the rules: {p.get('refused', '')}"
        return str(st)

    def _session_block(self, p: dict, alone: bool, tight: bool = False) -> str:
        st, o = p["status"], p.get("outcome") or {}
        by = _VIA.get(p.get("decided_by"), "")
        focus = f" — {_html(label(p.get('name'), p['ip']))}" if p.get("ip") else ""
        lines = [f"🔎 <b>{'' if alone else '#' + str(p['id']) + ' '}Investigation session</b>{focus}"]
        if p.get("reason"):
            lines.append(f"<i>Goal (model): {_html(p['reason'])}</i>")
        planned = (p.get("args") or {}).get("planned") or []
        dry = p.get("mode", SHADOW) != LIVE
        if st == "pending":
            if planned:
                lines.append("Wants to run: " + "; ".join(_html(x) for x in planned))
            lines.append(f"Up to {p.get('max', self.sess_checks)} read-only checks in "
                         f"{p.get('minutes', self.sess_min):g} min, from the catalog only. A "
                         "restart or reboot still asks you separately.")
            lines.append(f"⏳ Waiting for you until {_hm(p['expires'])} · <i>approving opens the "
                         f"session{' (dry run: nothing is executed)' if dry else ''}</i>")
        elif st == "open":
            lines.append(f"🟢 <b>Open</b> until {_hm(p['until'])} — approved on {by} · "
                         f"{p.get('used', 0)}/{p.get('max')} checks")
        elif st == "done":
            lines.append(f"⏹ {_html(cap_first(self._status_words(p)))}")
        elif st == "rejected":
            lines.append(f"✖️ Rejected on {by} at {_hm(p['decided_ts'])}")
        elif st == "expired":
            lines.append(f"⌛ Expired unanswered at {_hm(p['expires'])}")
        steps = p.get("steps") or []
        shown = steps[-(4 if tight else STEPS_SHOWN):]
        if len(steps) > len(shown):
            lines.append(f"<i>…{len(steps) - len(shown)} earlier checks on the dashboard</i>")
        for x in shown:
            lines.append(f"{'✓' if x.get('ok') else '✗'} {_html(x.get('label', ''))} — "
                         f"{_html(str(x.get('summary', ''))[:90 if tight else 160])}")
        if p.get("findings"):
            f = p["findings"]
            n = 400 if tight else 1500
            f = f if len(f) <= n else f[:n].rstrip() + " […]"
            lines.append(f"🦉 <b>Findings</b> (model, {_hm(p['findings_ts'])}):\n{_html(f)}")
        elif p.get("findings_error"):
            lines.append(f"⚠️ {_html(p['findings_error'])}")
        elif st == "open":
            lines.append("⏳ <i>The model is investigating…</i>")
        return "\n".join(lines)

    def _block(self, p: dict, alone: bool, tight: bool = False) -> str:
        if p.get("action") == "investigate":
            return self._session_block(p, alone, tight)
        who = _html(label(p.get("name"), p["ip"]))
        lines = [f"🛠 <b>{'' if alone else '#' + str(p['id']) + ' '}{_html(CATALOG[p['action']])}"
                 f"</b> — {who}",
                 f"<code>{_html(p.get('command') or '')}</code>"]
        if p.get("owner"):
            lines.append(f"<i>Asked by you on {_VIA.get(p['via'], p['via'])}</i>")
        elif p.get("reason"):
            lines.append(f"<i>Why (model): {_html(p['reason'])}</i>")
        lines += [f"⚠️ {_html(r)}" for r in p.get("risk") or []]
        if p.get("check"):
            lines.append(f"Checked: {_html(p['check'])}")
        st, o = p["status"], p.get("outcome") or {}
        by = _VIA.get(p.get("decided_by"), "")
        dry = p.get("mode", SHADOW) != LIVE
        if st == "pending":
            lines.append(f"⏳ Waiting for you until {_hm(p['expires'])}"
                         + (" · <i>dry run: approving executes nothing</i>" if dry else
                            " · <i>approving runs it</i>"))
        elif st == "running" and p.get("queued"):
            lines.append(f"⏸ Approved on {by} — {_html(self._queue_words(p))}; it runs when its "
                         "turn comes")
        elif st == "running":
            lines.append(f"⏳ Approved on {by} — {'checking' if dry else 'running'}…")
        elif st == "cancelled":
            lines.append(f"✖️ Cancelled on "
                         f"{_VIA.get(p.get('cancelled_by'), p.get('cancelled_by') or '')} at "
                         f"{_hm(p['done_ts'])} before its turn — nothing was done")
        elif st == "done" and o.get("dry_run"):
            lines.append(f"✅ <b>Approved</b> on {by} at {_hm(p['decided_ts'])} — <b>dry run, "
                         f"nothing was executed</b>. At approval: {_html(o.get('check', ''))}")
        elif st == "done":
            lines.append(f"✅ <b>Done</b> — approved on {by} at {_hm(p['decided_ts'])}: "
                         f"{_html(o.get('result', ''))}")
            lines += [f"<code>{_html(x)}</code>" for x in (o.get("lines") or [])[:25]]
        elif st == "failed":
            lines.append(f"⚠️ <b>Failed</b> — approved on {by} at {_hm(p['decided_ts'])}: "
                         f"{_html(o.get('error', ''))}")
        elif st == "skipped":
            lines.append(f"⏭ Approved on {by} at {_hm(p['decided_ts'])}, but not run: "
                         f"{_html(o.get('check', ''))}")
        elif st == "rejected":
            lines.append(f"✖️ Rejected on {by} at {_hm(p['decided_ts'])}")
        elif st == "expired":
            lines.append(f"⌛ Expired unanswered at {_hm(p['expires'])}")
        return "\n".join(lines)

    def _compose(self, m: dict) -> tuple:
        """(text, reply_markup) for one message that carries proposals."""
        ps = [p for p in (self._get(i) for i in m.get("pids") or []) if p is not None]
        base = m.get("base") or ""
        key = m.get("key") or ""
        if key and key in self.a._alert_msgs:          # the alert as it reads now, diagnosis too
            base = self.a._alert_msgs[key]["text"]
        head = m.get("head") or ""
        alone = not key and len(ps) == 1
        text = "\n\n".join([x for x in (base, head) if x] + [self._block(p, alone) for p in ps])
        if len(text) > 3900:              # Telegram's limit is 4096; a session can grow past it
            text = "\n\n".join([x for x in (base, head) if x] +
                                [self._block(p, alone, tight=True) for p in ps])[:4000]
        rows = []
        for p in ps:
            sfx = "" if alone else f" #{p['id']}"
            if p["status"] == "pending":
                ok = "🔎 Open session" if p["action"] == "investigate" else "✅ Approve"
                rows.append([
                    {"text": f"{ok}{sfx}", "callback_data": f"ax:a:{p['id']}:{p['nonce']}"},
                    {"text": f"✖️ Reject{sfx}", "callback_data": f"ax:r:{p['id']}:{p['nonce']}"}])
            elif p["status"] == "open":
                rows.append([{"text": f"⏹ End session{sfx}",
                              "callback_data": f"ax:e:{p['id']}:{p['nonce']}"}])
            elif p["status"] == "running" and p.get("queued"):
                rows.append([{"text": f"✖️ Cancel{sfx}",
                              "callback_data": f"ax:c:{p['id']}:{p['nonce']}"}])
        return text, {"inline_keyboard": rows}

    def decorate(self, message_id, text: str) -> tuple:
        """For an edit of an alert that carries proposals (the diagnosis arriving): the new
        text with the proposals kept under it, and their buttons. An edit without
        reply_markup would silently drop the buttons."""
        m = self.msgs.get(str(message_id))
        if m is None:
            return text, None
        m["base"] = text
        m["head"] = ""
        body, markup = self._compose({**m, "key": ""})
        return body, markup

    async def _send_own(self, pids: list, head: str, notify: bool):
        if self.a.no_telegram:
            log.info("telegram suppressed (--no-telegram) [action]: proposals %s", pids)
            return
        m = {"key": "", "head": head, "base": "", "pids": list(pids)}
        text, markup = self._compose(m)
        ids: list = []
        async with self.a._tg_lock:
            try:
                ok = await telegram_direct(self.a.cfg, text, ids=ids, extra={
                    "reply_markup": markup, "disable_notification": not notify})
            except TelegramRejected as e:
                log.error("actions: proposal message rejected by Telegram: %s", e)
                ok = False
        if not (ok and ids):
            # Not the outbox: a proposal delivered after an outage has expired anyway.
            log.warning("actions: proposals %s not delivered to Telegram — dashboard only", pids)
            return
        self.msgs[str(ids[0])] = m
        for pid in pids:
            p = self._get(pid)
            if p is not None:
                p["tg"] = ids[0]
        self.a._sent_log = (self.a._sent_log + [{"ts": time.time(), "channel": "action",
                                                 "text": text[:1500]}])[-80:]
        self._save()

    async def flush_audit(self):
        """Deliver what the audit proposed: on the alert of the open incident about that
        device when there is one (edited in, no second message — the rule), otherwise
        in one silent message for the whole audit."""
        pids, self._audit_batch = self._audit_batch, []
        pids = [i for i in pids if (self._get(i) or {}).get("status") == "pending"]
        if not pids or self.a.no_telegram:
            if pids:
                log.info("telegram suppressed (--no-telegram) [action]: proposals %s", pids)
            return
        open_keys = self.a._open_incident_keys()
        touched, loose = set(), []
        for pid in pids:
            p = self._get(pid)
            key = next((k for k in self.a._alert_msgs
                        if k in open_keys and f":{p['ip']}:" in f":{k}:"), None)
            if key is None:
                loose.append(pid)
                continue
            rec = self.a._alert_msgs[key]
            m = self.msgs.setdefault(str(rec["id"]), {"key": key, "head": "",
                                                      "base": rec["text"], "pids": []})
            m["pids"].append(pid)
            p["tg"] = rec["id"]
            touched.add(str(rec["id"]))
        for mid in touched:
            await self._edit(mid)
        if loose:
            await self._send_own(loose, "🛠 <b>The audit proposes</b>", notify=False)
        self._save()

    async def _refresh(self, p: dict):
        if p.get("tg") and not self.a.no_telegram:
            await self._edit(str(p["tg"]))

    async def _edit(self, mid: str):
        m = self.msgs.get(mid)
        if m is None:
            return
        text, markup = self._compose(m)
        async with self.a._tg_lock:
            ok = await telegram_edit(self.a.cfg, int(mid), text, reply_markup=markup)
        if not ok:
            log.warning("actions: could not update Telegram message %s", mid)

    # --- reading ----------------------------------------------------------------
    def public(self, p: dict) -> dict:
        return {"id": p.get("id"), "action": p["action"], "title": CATALOG.get(p["action"], p["action"]),
                "ip": p["ip"], "label": label(p.get("name"), p["ip"]) if p.get("ip") else "",
                "reason": p.get("reason"), "via": p.get("via"), "ts": p.get("ts"),
                "owner": bool(p.get("owner")),
                "expires": p.get("expires"), "status": p.get("status"),
                "mode": p.get("mode", SHADOW),
                "command": p.get("command"), "check": p.get("check"), "risk": p.get("risk") or [],
                "refused": p.get("refused"), "decided_by": p.get("decided_by"),
                "decided_ts": p.get("decided_ts"), "done_ts": p.get("done_ts"),
                "started_ts": p.get("started_ts"), "queued": bool(p.get("queued")),
                # the live view: its steps so far, a long step's latest word, when it gives up
                "trail": p.get("trail") or [], "detail": p.get("detail"),
                "deadline": (p["run_ts"] + RUN_TIMEOUT_S.get(p["action"], 120)
                             if p.get("run_ts") else None),
                **({"queue": self._queue_words(p).removeprefix("queued ")}
                   if p.get("queued") else {}),
                "outcome": p.get("outcome"), "words": self._status_words(p),
                **({"goal": p.get("reason"), "planned": (p.get("args") or {}).get("planned") or [],
                    "until": p.get("until"), "used": p.get("used", 0), "max": p.get("max"),
                    "minutes": p.get("minutes"), "steps": p.get("steps") or [],
                    "findings": p.get("findings"), "findings_ts": p.get("findings_ts"),
                    "findings_error": p.get("findings_error")}
                   if p.get("action") == "investigate" else {})}

    def rebootable(self) -> list:
        """Every device a reboot can be asked for: the allow-list, and the Shellies."""
        if not self.enabled:
            return []
        return sorted(set(self.reboot.devices) & {d.ip for d in self.a.inv.devices}
                      | {d.ip for d in self.a.inv.devices if d.name.lower().startswith("shelly")})

    def view(self, now: Optional[float] = None) -> dict:
        now = now or time.time()
        self._session(now)
        live = ("pending", "running", "open")
        pend = [self.public(p) for p in self.items if p.get("status") in live]
        rest = [self.public(p) for p in reversed(self.items) if p.get("status") not in live][:40]
        for x in rest[5:]:              # the page shows the outputs of the latest ones only
            for st in x.get("steps") or []:
                st.pop("output", None)
        return {"enabled": self.enabled, "mode": self.mode, "pending": pend, "recent": rest,
                # what the device sheet offers a Reboot button for
                "rebootable": self.rebootable()}

    def by_hand(self, now: Optional[float] = None, days: float = 30, min_n: int = 3) -> list:
        """What the owner did themselves, again and again: the same action on the same device,
        done `min_n` times or more in `days` — the candidates for a standing order (none is
        built; the weekly review points them out)."""
        now = now or time.time()
        seen: dict = {}
        for p in self.items:
            if p.get("owner") and p.get("status") == "done" and now - (p.get("done_ts") or p["ts"]) < days * 86400:
                k = (p["action"], p.get("ip") or "")
                seen.setdefault(k, {"action": CATALOG.get(p["action"], p["action"]),
                                    "device": label(p.get("name"), p["ip"]) if p.get("ip") else "",
                                    "n": 0})["n"] += 1
        return sorted((v for v in seen.values() if v["n"] >= min_n), key=lambda v: -v["n"])

    def context(self, now: Optional[float] = None, hours: float = 24) -> list:
        """The model's own recent proposals and what became of them — so an audit does not
        re-propose what the owner just turned down, and a follow-up knows what a scan found."""
        now = now or time.time()
        out = []
        for p in self.items:
            if now - p.get("ts", 0) > hours * 3600:
                continue
            if p.get("action") == "investigate":
                steps = p.get("steps") or []
                out.append(f"#{p['id']} investigation session (goal: {p.get('reason', '')}), "
                           f"{time.strftime('%d/%m %H:%M', time.localtime(p['ts']))}, from "
                           f"{_VIA.get(p.get('via'), p.get('via'))}: {self._status_words(p)}"
                           + ("".join(f"\n      {x['label']}: {x['summary'][:160]}"
                                      for x in steps[-8:]))
                           + (f"\n      findings: {p['findings'][:400]}" if p.get("findings") else ""))
                continue
            out.append(f"#{p['id']} {p['action']} on {p.get('name') or p['ip']} ({p['ip']}), "
                       f"{time.strftime('%d/%m %H:%M', time.localtime(p['ts']))}, "
                       f"from {_VIA.get(p.get('via'), p.get('via'))}: {self._status_words(p)}")
        return out[-10:]
