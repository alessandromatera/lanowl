"""The model's shell: one bash command at a time, in a sandbox beside lanowl.

An agent that can only call fixed tools cannot follow a hunch. So the model gets a shell, but
never lanowl's own container (which holds the logins, the bot token and the ssh keys): a
sandbox, open to the internet, reaching the LAN for scanning only, run at once when the owner
asks, never in the hourly audit. docker/sandbox/ is the other half and says how it is walled
in; this is lanowl's side:

  - `shell` is offered only in the owner's own question (Telegram, the dashboard — a
    `turn`), and only while the isolation is PROVEN: `canary` runs, from inside the sandbox,
    the three things that must hold — a TCP handshake to a LAN service succeeds (the control:
    the network is up), the HTTP request that follows gets nothing, and lanowl's own
    dashboard does not answer at all. Anything else turns the tool off; a sandbox that can
    reach what it must not is said on Telegram, once, and when it is over;
  - WHEN: the walls are rules the sandbox sets on itself at start, so they can only change
    when it restarts. Proven when lanowl starts, once a day with the security review
    (exposure.py), and before a shell is offered whenever the sandbox's own start marker
    (boot id + its PID 1's start time, no network) differs from the one proven;
  - the AUDIT's own shell: a second sandbox, `lanowl-sandbox-offline`, the same image with no
    internet and no DNS at all (a resolver is a way out too) — LAN ping, trace and handshakes
    only; its
    canary proves the internet and every resolver unreachable as well. At most
    `shell.audit.max_per_audit` commands an audit;
  - the sandbox is reached through a unix socket on a volume mounted read-only here — never
    the Docker socket (root on the host, so the secrets);
  - every command is kept (the `shell` record, the last KEEP) with who asked and what came
    back, listed under a Telegram answer and on the dashboard.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import stat
import time
from typing import Optional

from .model import router_host

log = logging.getLogger("lanowl.shell")

RECORD = "shell"
KEEP = 200
PROVE_EVERY_S = 86400          # the daily safety net; the security review proves it daily too
RETRY_S = 300                  # until it is proven: a sandbox started after lanowl, or one that
                               # restarted, must not leave the shell off for a day

SPEC = {"type": "function", "function": {
    "name": "shell",
    "description": ("Run ONE bash command in the sandbox (see SHELL) and get its exit code and "
                    "output. It runs at once: the owner's question is the approval."),
    "parameters": {"type": "object", "properties": {
        "command": {"type": "string", "description": "a bash command line; pipes and && are fine"},
        "timeout_s": {"type": "integer", "description": "seconds before it is killed (default 60)"},
    }, "required": ["command"]}}}

SPEC_AUDIT = {"type": "function", "function": {
    "name": "shell",
    "description": ("Run ONE bash command in the audit's OFFLINE sandbox (see SHELL): no "
                    "internet, no DNS — LAN addresses only. Exit code and output back."),
    "parameters": SPEC["function"]["parameters"]}}


def cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def clip(text: str, n: int) -> str:
    """Head and tail: a command's verdict is as often at its end as at its start."""
    text = text or ""
    if len(text) <= n:
        return text
    head = int(n * 0.7)
    tail = n - head
    return (text[:head].rstrip() + f"\n[… {len(text) - n} characters cut …]\n"
            + text[-tail:].lstrip())


def report(cfg: dict) -> tuple:
    """(text, problems) for `lanowl --check`: the model's shell, when it is switched on — its
    LAN control must be set, and must not be lanowl's own host (the sandbox walls that off, so
    the isolation could never be proven and the shell would stay off)."""
    c = (cfg or {}).get("shell") or {}
    if not c.get("enabled"):
        return "Shell: off", 0
    host = str(c.get("canary_lan") or "").partition(":")[0]
    me = os.environ.get("LANOWL_HOST_IP") or str(((cfg or {}).get("observer") or {}).get("host_ip") or "")
    if not host:
        return ("Shell: on\n  ✗ shell.canary_lan  not set: a LAN service that always answers a "
                "handshake, e.g. the router's web page (192.168.88.1:80)"), 1
    if me and host == me:
        return (f"Shell: on\n  ✗ shell.canary_lan  {host} is lanowl's own host, which the sandbox "
                "walls off: choose another LAN service that always answers, e.g. the router's web page"), 1
    return f"Shell: on · its LAN control {c.get('canary_lan')}", 0


class Shell:
    def __init__(self, auditor, audit: bool = False):
        """The owner's shell, or with `audit` the hourly audit's offline one."""
        self.a = auditor
        self.audit = audit
        c = auditor.cfg.get("shell") or {}
        ca = c.get("audit") or {}
        self.enabled = bool(c.get("enabled", False)) and (not audit or bool(ca.get("enabled", False)))
        self.sock = str(ca.get("socket") or "/run/sandbox-offline/exec.sock") if audit else \
            str(c.get("socket") or "/run/sandbox/exec.sock")
        self.timeout = int(c.get("timeout_s", 60))
        self.timeout_max = int(ca.get("timeout_max_s", 120)) if audit else int(c.get("timeout_max_s", 300))
        self.out_max = int(c.get("output_max_chars", 6000))
        self.per_answer = int(ca.get("max_per_audit", 4)) if audit else int(c.get("max_per_answer", 20))
        self.record = RECORD + ("_audit" if audit else "")
        # the canary's LAN control: a service that always answers a handshake (the router's
        # web page is the usual pick) — never lanowl's own host, which the sandbox walls off.
        # Required: there is no address that suits every network.
        probe = str(c.get("canary_lan") or "")
        self.lan_host, _, port = probe.partition(":")
        self.lan_port = int(port or 80)
        self.state = {"ok": None, "why": "not checked yet", "ts": 0.0, "marker": ""}
        self._breach = False
        self._turn: Optional[dict] = None
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Future] = None
        self.log: list = []
        try:
            rec = auditor.state.load_record(self.record) or {}
            self.log = [x for x in rec.get("log") or [] if isinstance(x, dict)][-KEEP:]
        except Exception:
            log.warning("shell: record unreadable, starting empty", exc_info=True)

    # --- is it on offer ---------------------------------------------------------
    def available(self) -> bool:
        return self.enabled and self.state["ok"] is True

    def offered(self) -> bool:
        return self.available() and self._turn is not None

    def spec(self) -> dict:
        return SPEC_AUDIT if self.audit else SPEC

    async def ready(self) -> bool:
        """Right before the shell is offered: proven, and still the same sandbox — its start
        marker unchanged since the proof. A restarted sandbox is proven again first."""
        if not self.enabled:
            return False
        if self.state["ok"] is True:
            m = await self.marker()
            if m and m != self.state.get("marker"):
                log.info("shell%s: the sandbox restarted since it was proven — proving it again",
                         " (audit)" if self.audit else "")
                await self.canary()
        return self.available()

    async def marker(self) -> str:
        """Which sandbox this is: the VM's boot id and the start time of the sandbox's PID 1.
        Both change when it restarts; reading them touches no network."""
        res = await self._exec("cat /proc/sys/kernel/random/boot_id; cut -d' ' -f22 /proc/1/stat", 10)
        return " ".join((res.get("out") or "").split()) if not res.get("error") else ""

    @contextlib.contextmanager
    def turn(self, via: str, question: str = "", ran: Optional[list] = None):
        """The owner's question in progress: `shell` may run, and each command joins `ran`."""
        prev = self._turn
        self._turn = {"via": via, "question": " ".join(str(question or "").split())[:200],
                      "ran": ran if ran is not None else [], "n": 0}
        try:
            yield self._turn
        finally:
            self._turn = prev

    # --- the tool -------------------------------------------------------------------
    async def call(self, args: dict) -> dict:
        t = self._turn
        if t is None or not self.enabled:
            return {"error": "the shell is only available in a question from the owner"
                             + (" or in the audit" if self.audit else "")}
        if self.state["ok"] is not True:
            return {"error": f"the shell is off right now: {self.state['why']}"}
        args = args if isinstance(args, dict) else {}
        cmd = str(args.get("command") or "").strip()
        if not cmd:
            return {"error": "command is missing"}
        if len(cmd) > 4000:
            return {"error": "command too long (4000 characters at most) — write a script to "
                             "/work in steps instead"}
        if t["n"] >= self.per_answer:
            return {"refused": f"this {'audit' if self.audit else 'answer'} has used its "
                               f"{self.per_answer} commands",
                    "note": "Nothing ran. Answer with what you have."}
        try:
            timeout = int(args.get("timeout_s") or self.timeout)
        except (TypeError, ValueError):
            timeout = self.timeout
        timeout = max(1, min(timeout, self.timeout_max))
        t["n"] += 1
        log.warning("shell (%s) %d/%d: %s", t["via"], t["n"], self.per_answer, cmd[:300])
        res = await self._exec(cmd, timeout)
        out = res.get("out") or ""
        entry = {"ts": time.time(), "via": t["via"], "q": t["question"], "cmd": cmd[:1000],
                 "rc": res.get("rc"), "secs": res.get("secs"), "timed_out": bool(res.get("timed_out")),
                 "chars": len(out), **({"error": res["error"]} if res.get("error") else {})}
        self._keep(entry)
        t["ran"].append({"ts": entry["ts"], "kind": "shell", "label": "$ " + " ".join(cmd.split())[:100],
                         "command": cmd[:1000], "ok": res.get("rc") == 0 and not res.get("error"),
                         "summary": f"exit {res.get('rc')}", "secs": res.get("secs")})
        if res.get("error"):
            return {"error": f"the sandbox did not run it: {res['error']}"}
        r = {"exit_code": res.get("rc"), "secs": res.get("secs"), "output": clip(out, self.out_max)}
        if res.get("timed_out"):
            r["note"] = f"killed after {timeout}s — what it printed before is above"
        elif res.get("truncated") or len(out) > self.out_max:
            r["note"] = "output cut — filter it (grep, head, awk) to see the part you need"
        return r

    def _keep(self, entry: dict):
        self.log = (self.log + [entry])[-KEEP:]
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(self.record, {"log": self.log})
        except Exception:
            log.warning("shell: record not saved", exc_info=True)

    async def _exec(self, cmd: str, timeout: float) -> dict:
        """One request to the sandbox's socket. {"rc", "out", "secs", "timed_out",
        "truncated"} or {"error"} — never raises."""
        async with self._lock:
            try:
                if not stat.S_ISSOCK(os.lstat(self.sock).st_mode):
                    return {"error": f"{self.sock} is not a socket"}
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(self.sock, limit=2 ** 21), 5)
            except FileNotFoundError:
                return {"error": "the sandbox is not running (no socket)"}
            except Exception as e:
                return {"error": f"cannot reach the sandbox ({type(e).__name__}: {e})"}
            try:
                writer.write(json.dumps({"cmd": cmd, "timeout": timeout}).encode() + b"\n")
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout + 20)
                res = json.loads(line) if line else {"error": "the sandbox closed the connection"}
            except asyncio.TimeoutError:
                res = {"error": f"no answer from the sandbox within {timeout + 20:.0f}s"}
            except Exception as e:
                res = {"error": f"{type(e).__name__}: {e}"}
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            return res if isinstance(res, dict) else {"error": "a malformed answer"}

    # --- proving the walls: at start, daily, and when the sandbox restarted -------------------
    def tick(self, now: Optional[float] = None):
        """From the sweep: prove the walls once after lanowl starts, then daily once proven (the
        security review proves them every morning; `ready` when the sandbox restarted) — and
        every five minutes until they are: a sandbox started after lanowl, or not running for a
        while, must not leave the shell off until tomorrow. Never awaited."""
        if not self.enabled:
            return
        now = now or time.time()
        if self._task is not None and not self._task.done():
            return
        wait = PROVE_EVERY_S if self.state["ok"] else RETRY_S
        if now - self.state["ts"] < wait and self.state["ok"] is not None:
            return
        self._task = asyncio.ensure_future(self.canary())

    def _self_ip(self) -> str:
        return getattr(self.a, "_self_ip", None) or \
            str((self.a.cfg.get("observer") or {}).get("host_ip") or "")

    def _self_url(self) -> str:
        port = getattr(getattr(self.a, "dashboard", None), "port", 80)
        return f"http://{self._self_ip()}:{port}/api/state"

    async def canary(self) -> dict:
        """Three facts, from inside the sandbox: a LAN handshake works (the control), the
        request after it gets nothing, and the VM itself takes not even a handshake — its
        sshd, which is always up, so a closed port cannot pass for a wall. The audit's offline
        sandbox also: the internet takes no connection, and no resolver answers — neither
        Docker's own nor the router's."""
        h, p = self.lan_host, self.lan_port
        cmd = (f"nc -z -w3 {h} {p} && echo HANDSHAKE-OK || echo HANDSHAKE-FAIL; "
               f"curl -s -m4 -o /dev/null -w 'GET-%{{http_code}}\\n' http://{h}:{p}/; "
               f"curl -s -m4 -o /dev/null -w 'SELF-%{{http_code}}\\n' {self._self_url()}; "
               f"nc -z -w3 {self._self_ip()} 22 && echo VM-OPEN || echo VM-CLOSED")
        if self.audit:
            dns = str(((self.a.cfg.get("actions") or {}).get("checks") or {}).get("router_dns")
                      or router_host(self.a.cfg))
            cmd += ("; curl -s -m4 -o /dev/null -w 'NET-%{http_code}\\n' http://1.1.1.1/; "
                    "dig +time=2 +tries=1 example.com >/dev/null 2>&1 && echo DNS-OPEN || echo DNS-CLOSED; "
                    f"dig +time=2 +tries=1 @{dns} example.com >/dev/null 2>&1 && echo RDNS-OPEN "
                    "|| echo RDNS-CLOSED")
        cmd += "; echo MARK $(cat /proc/sys/kernel/random/boot_id) $(cut -d' ' -f22 /proc/1/stat)"
        res = await self._exec(cmd, 45)
        out = res.get("out") or ""
        codes = {k: out.split(f"{k}-", 1)[1][:3] for k in ("GET", "SELF", "NET") if f"{k}-" in out}
        mark = next((" ".join(x.split()[1:]) for x in out.splitlines() if x.startswith("MARK ")), "")
        leak = self.audit and (codes.get("NET", "000") != "000" or "DNS-OPEN" in out or "RDNS-OPEN" in out)
        if res.get("error"):
            ok, why, breach = False, f"the sandbox is not answering ({res['error']})", False
        elif codes.get("SELF", "000") != "000" or codes.get("GET", "000") != "000" \
                or "VM-OPEN" in out or leak:
            ok, breach = False, True
            why = (f"NOT ISOLATED — from the sandbox, a GET to {h}:{p} answered "
                   f"{codes.get('GET')}, lanowl's dashboard {codes.get('SELF')}, the VM's "
                   f"ssh port {'OPEN' if 'VM-OPEN' in out else 'closed'}"
                   + (f", the internet {codes.get('NET')}, DNS "
                      f"{'answers' if 'DNS-OPEN' in out or 'RDNS-OPEN' in out else 'closed'}"
                      if self.audit else ""))
        elif self.audit and ("NET" not in codes or "DNS-CLOSED" not in out or "RDNS-CLOSED" not in out):
            ok, why, breach = False, "the offline check printed nothing usable", False
        elif "GET" not in codes or "SELF" not in codes or "VM-CLOSED" not in out:
            ok, why, breach = False, "the isolation check printed nothing usable", False
        elif "HANDSHAKE-OK" not in out:
            ok, breach = False, False
            why = (f"isolation not proven: the control ({h}:{p}) is lanowl's own host, which the "
                   "sandbox walls off — set shell.canary_lan to another LAN service that always "
                   "answers, e.g. the router's web page" if h == self._self_ip() else
                   f"isolation not proven: the control ({h}:{p}) did not even take a "
                   "handshake — the LAN or that host is down")
        else:
            ok, why, breach = True, ("fenced off and offline: no internet, no DNS; on your network "
                                     "nothing but a handshake, and never the machine lanowl runs on"
                                     if self.audit else
                                     "fenced off: on your network nothing but a handshake, and never "
                                     "the machine lanowl runs on"), False
        was = self.state["ok"]
        self.state = {"ok": ok, "why": why, "ts": time.time(), "marker": mark}
        who = "the audit's offline shell" if self.audit else "the model's shell"
        if ok != was:
            (log.info if ok else log.warning)("shell%s: %s", " (audit)" if self.audit else "", why)
        if breach and not self._breach:
            log.error("%s: %s — the tool is off", who, why)
            self.a._emit_telegram("critical", f"🚨 <b>{cap(who)} NOT isolated</b>\n"
                                  f"{why}.\nThe shell is off until the check passes again.")
        elif self._breach and not breach and ok:
            self.a._emit_telegram("digest", f"✅ {cap(who)} is isolated again — back on.")
        self._breach = breach
        return self.state

    # --- for the dashboard ---------------------------------------------------------------
    def view(self) -> dict:
        return {"enabled": self.enabled, "offline": self.audit,
                "ok": self.state["ok"], "why": self.state["why"],
                "checked": self.state["ts"] or None,
                "recent": [{k: x.get(k) for k in ("ts", "via", "cmd", "rc", "secs", "timed_out",
                                                  "error")}
                           for x in reversed(self.log[-15:])]}
