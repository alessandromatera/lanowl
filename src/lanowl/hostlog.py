"""Security triage of a Linux host's own log: a home server, a VPS, any box lanowl can ssh into.

The router half of this already exists in wanwatch.py: RouterOS's log is read every 60s and
whatever is not routine background hum is handed to the model. That watches the perimeter,
and only the perimeter. A home server is the box *behind* it — Node-RED, MQTT, Samba, media,
perhaps the model server — and someone who gets a shell there may own the home automation
and the alerting, which makes its auth log the one worth reading on a clock. A public server
(`public: true`) sees the whole internet knock on its door every minute.

Why a separate module rather than a flag inside wanwatch:
  - transport: SSH to a Linux box, not a RouterOS REST GET;
  - vocabulary: sshd/pam/sudo/kernel, not netwatch and a failover script's lines;
  - the failure it hunts: somebody trying to get IN, not the internet line dropping out.
Only the *shape* is shared, and it is shared deliberately — the routine-exclusion list, the
message-shape memo, the cooldown, the never-block-the-clock task, the deferral while an
audit holds the model. Those rules were learnt once on the router and apply unchanged here.

WHAT THIS CAN AND CANNOT SEE. Worth being blunt, because the gap is where false comfort
lives:
  - SSH logins, failed passwords, invalid users, key vs password, sudo, PAM, samba auth,
    and kernel warnings (ufw/netfilter drops, OOM, disk errors): yes, this is exactly the
    stream, and the burst rule below catches a brute force without waiting for the model.
  - A volumetric DDoS: no. An auth log cannot see a flood, and by the time one is big
    enough to matter it is felt at the WAN — which the ping loop in wanwatch.py already
    reports as 'no internet at all'. What IS available cheaply from the same SSH round is
    a census of established connections; it is carried as context and as one deterministic
    ceiling, and it is honest about being crude.
  - An attacker who is already root and edits the journal: no. Nothing host-local can.

Self-noise, the lesson from the router restated. Polling over SSH writes 'Accepted publickey
for <user> from <lanowl's address>' into the very log being read — the same trap as RouterOS logging
`user lanowl logged in` for each REST call, where the tempting fix (drop anything with
'logged in') would have deleted the single most interesting line in the file. So: the poll
reuses ONE ssh connection (ControlMaster/ControlPersist) so a login is rare rather than
per-tick, and the exclusion is by user AND source address. A login as our own user from any
other address is not filtered — that is somebody else, and it is precisely the event this
module exists for.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from . import access
from .seclog import rank
from .wanwatch import verdict_kind

log = logging.getLogger("lanowl.hostlog")

_DIGITS = re.compile(r"\d+")
# journalctl -o short-iso: '2026-09-03T14:29:47+02:00 server sshd[122378]: Accepted ...'
_LINE = re.compile(r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<src>[^:]+):\s*(?P<msg>.*)$")
_CURSOR = re.compile(r"^-- cursor:\s*(?P<c>\S+)\s*$")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# The journal query. An OR of three match groups: the auth and authpriv facilities (every
# sshd/sudo/pam/samba line) plus kernel messages at error and critical, which is where a
# netfilter drop storm, an OOM kill or a disk giving up shows first. Kernel *warnings* are
# deliberately left out — on this box they are boot-time firmware grumbling, one per day.
DEFAULT_MATCH = ["SYSLOG_FACILITY=4", "+", "SYSLOG_FACILITY=10",
                 "+", "_TRANSPORT=kernel", "PRIORITY=2",
                 "+", "_TRANSPORT=kernel", "PRIORITY=3"]

# Lines that are pure background hum on a healthy Ubuntu box. As on the router this is an
# EXCLUSION list, never an allow-list: the whole point of asking a model is to catch the
# thing nobody thought to write a rule for, so anything not matched here is offered up.
#
#   - cron opens and closes a root PAM session twice a minute: most of a quiet server's auth
#     lines, and not one of them means anything;
#   - systemd-logind's session bookkeeping duplicates what sshd already said, with no
#     source address attached, so it can only add noise;
#   - 'Failed publickey' is what a normal client does while offering keys one at a time
#     before the one that works — a failure only in the protocol's sense;
#   - samba session churn is every phone that opens the share.
# The *interesting* halves of these — 'Accepted', 'Failed password', 'Invalid user',
# authentication failure, sudo — are all absent from this list on purpose.
_ROUTINE = (
    "pam_unix(cron:session): session opened for user root",
    "pam_unix(cron:session): session closed for user root",
    "New session ", "Removed session ", "logged out. Waiting for processes to exit",
    "pam_unix(sshd:session): session opened", "pam_unix(sshd:session): session closed",
    "Received disconnect from", "Disconnected from user ",
    "Failed publickey for",
    "pam_unix(samba:session): session opened",
    "pam_unix(samba:session): session closed",
    "Starting Session", "Started Session", "session-",
    # the per-user systemd instance every root ssh login starts on the VPS
    "pam_unix(systemd-user:session): session",
)

# What counts as a failed authentication for the burst rule below. Deliberately narrow:
# every one of these means a credential was offered and rejected, which is the thing that
# repeats when somebody is guessing.
_FAIL_MARKS = (
    "Failed password for", "Invalid user ", "authentication failure",
    "Failed keyboard-interactive", "maximum authentication attempts exceeded",
    "Connection closed by invalid user", "User not known to the underlying auth",
    "error: PAM: Authentication failure",
)

# A PUBLIC host (a VPS) is a different animal: the internet IS its routine — tens of
# thousands of auth lines a day, password guesses from hundreds of addresses. Handing that
# to the model would be triaging scanner noise every 15 minutes, and the burst rule would
# page all day. So for a `public: true` host the pre-authentication hum is removed ON THE
# HOST, by awk, and only counted: nothing that happens before a login succeeds is ever
# access. What is left — a login that succeeded, sudo, a kernel error, anything odd — is
# what reaches the rules and the model. ERE for mawk; brackets instead of backslashes so the
# pattern survives two shells unescaped.
_PUBLIC_NOISE = "|".join((
    "[[]preauth[]]",
    "pam_unix[(]sshd:auth[)]: (authentication failure|check pass; user unknown)",
    "Failed (password|none|keyboard-interactive)",
    "Invalid user ",
    "Connection (closed|reset) by",
    "PAM [0-9]+ more authentication failure",       # 'failure' when it is one, 'failures' after
    "PAM service[(]sshd[)] ignoring max retries",
    "maximum authentication attempts exceeded",
    "banner exchange", "kex_exchange_identification", "Unable to negotiate",
    "Bad protocol version", "Did not receive identification", "Protocol major versions",
    "ssh_dispatch_run_fatal", "Timeout before authentication", "invalid format",
    "MaxStartups", "drop connection #",
))
# ...and, only for `read_log` (the raw log on request), the IPsec keepalives: one tunnel's
# dead-peer-detection exchange can be hundreds of lines an hour, most of what is left after
# the scanners. Without this, "the last 40 lines" is six minutes of four lines repeating. The rekeying and anything else strongSwan says stay in.
_PUBLIC_CHATTER = "N[(]DPD(_ACK)?[)]|[[]NET[]] (received|sending) packet"
_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:?\d\d)(?=\s)")


def _local_ts(line: str) -> str:
    """A server may keep UTC; the owner reads local time. Same instant, offset kept:
    '2026-09-24T13:13:21+00:00' -> '2026-09-24T15:13:21+02:00'."""
    m = _ISO.match(line)
    if not m:
        return line
    from datetime import datetime
    try:
        t = datetime.fromisoformat(m.group(1)).astimezone()
    except ValueError:
        return line
    return t.isoformat() + line[m.end():]

# What a host is, for the model: each host's own `about:` in config says it best (what runs
# there, how people reach it, which source addresses are normal). This is the default.
DEFAULT_ABOUT = """a Linux server on a home LAN behind the main router, with no port forwarded
to it. A source address on the LAN or on an overlay network (Tailscale's and the provider's
100.64.0.0/10, ZeroTier, WireGuard) is normal. If it runs a tunnel that publishes a name on
the internet (Cloudflare Tunnel, say), connections through it arrive from 127.0.0.1 and come
from the INTERNET: a connection closed without a login is someone probing, a failed login from
127.0.0.1 is someone on the internet guessing, and an accepted one is a login from the
internet."""

HOST_SYSTEM_HEAD = """You triage Linux security log lines (Ubuntu, systemd journal). The host is
{about}"""

HOST_SYSTEM_BODY = """

You are given log lines that are NOT part of the host's normal background chatter. Most of
the time they are still harmless: the owner logging in, a phone mounting the Samba share, a
service restarting, one mistyped password. Say so. Report a problem only when the lines show
something a homeowner should act on:

  - repeated failed logins, especially for users that do not exist or for root;
  - a successful login that does not fit — an unfamiliar user, a public source address, a
    password login where this host normally sees keys, a login at an odd hour;
  - sudo or su used by an account that should not, or authorisation failures for it;
  - a new user or group created, an authorized_keys or sshd_config change, a service
    installed or enabled;
  - kernel messages showing a flood of dropped packets, out-of-memory kills, or storage or
    filesystem errors;
  - anything that reads like an intrusion attempt or like a foothold already taken.

Reply with ONLY this JSON object, no prose and no code fence:
{"problem": true|false,
 "kind": "security"|"health",
 "severity": "critical"|"warning"|"info",
 "summary": "<one short line a person reads on a phone>",
 "detail": "<one or two sentences: what the lines show and what to check>"}

"kind" says what the lines are ABOUT, whether or not they are a problem: "security" for access
— logins, sudo, users and keys, a service installed, anything like an intrusion attempt;
"health" for the machine working — out-of-memory kills, storage or filesystem errors, a
service failing, a tunnel re-establishing.

Use "critical" only for an intrusion attempt in progress or a successful login you believe
was not the owner. A failed login or two, or a service being odd, is "warning" at most.

Set "problem": false whenever you are unsure. A false alarm at 3am costs more than a late
notice, and a separate deterministic rule already pages on a burst of failed logins, so you
are the long tail and not the safety net.

You may be given a CONNECTION CENSUS and a WHAT WAS HAPPENING note. Take both as fact. If
the network had no internet during the window, everything that needed the internet failed too
and those failures are symptoms of the outage, not findings — say which outage explains them
and set "problem": false. Judge what the outage does NOT explain on its own merits."""

HOST_SYSTEM = HOST_SYSTEM_HEAD.format(about=DEFAULT_ABOUT) + HOST_SYSTEM_BODY


def host_system(about: str = "") -> str:
    """The triage prompt for one host: its own description, then the shared rules."""
    return HOST_SYSTEM_HEAD.format(about=(about or DEFAULT_ABOUT).strip()) + HOST_SYSTEM_BODY


@dataclass
class _Host:
    """One monitored host and everything remembered about it between polls."""
    name: str
    ip: str
    user: str
    identity: str = ""                # its own key file; "" = lanowl's (secrets.yaml `ssh_key`)
    # its log is read (`manage: [logs]`); a host lanowl only logs in to by key is listed too,
    # for the shared connection the key's other uses ride (actions._ssh_run)
    watch: bool = True
    cursor: Optional[str] = None      # journal cursor: the watermark, opaque and exact
    ok: bool = True                   # did the last poll succeed
    last_error: str = ""
    last_poll: float = 0.0
    lines_seen: int = 0
    # rolling window of (when, source-ip, message) for failed authentications
    fails: list = field(default_factory=list)
    burst_told: dict = field(default_factory=dict)   # source -> when we last paged for it
    conns: int = 0                    # established TCP connections at the last poll
    peers: int = 0                    # ...from this many distinct remote addresses
    conns_over: int = 0               # consecutive polls above the ceiling
    conns_told: float = 0.0
    _shapes: set = field(default_factory=set)        # message shapes already triaged
    # --- per-host settings ---
    public: bool = False              # on the internet: scanner hum is filtered on the host
    about: str = ""                   # how the model is told what this host is
    trusted: list = field(default_factory=list)      # networks a login may come from
    burst: bool = True                # the failed-login burst rule (meaningless on a public host)
    max_established: int = 0          # 0 = the global ceiling
    self_addrs: set = field(default_factory=set)     # where the host sees OUR ssh come from
    self_addr: str = ""                                # ...the latest of them (exposure.py)
    noise: list = field(default_factory=list)        # [(ts, lines, attempts, {sources})]
    logins_told: dict = field(default_factory=dict)  # untrusted source -> when we paged
    # addresses a login arrives from when it came through a tunnel from the internet — a
    # Cloudflare Tunnel hands sshd its connections from 127.0.0.1
    tunnel_from: list = field(default_factory=list)
    # ...and the public names routed to this sshd, whose Cloudflare Access is checked at the
    # moment of such a login
    tunnel_names: list = field(default_factory=list)
    access: dict = field(default_factory=dict)       # the last check: {ts, guarded, names}
    # log line (message part) -> (when, seclog item id, severity): what a rule already paged
    # for, so the model's read of the same lines lands on that row instead of a second message
    covered: dict = field(default_factory=dict)
    own_runs: list = field(default_factory=list)     # [(from, to, what)]: lanowl's own sudo
    last_triage: float = 0.0          # per host, so one noisy box cannot starve the other
    primed_at: float = 0.0            # counting starts here: a restart is not a quiet day


@dataclass
class HostLogWatcher:
    """Polls each configured host's journal, filters the hum, triages the rest.

    Same contract as WanWatcher: its own loop, its own clock, and it never awaits the
    sweep or blocks on the model. `on_alert(text, key="")` is the same sink the WAN
    watcher uses, so these alerts inherit the outbox and the direct-Telegram fallback —
    which matters more here than anywhere else, since the host being reported on is the
    one that normally forwards the message."""

    cfg: dict
    on_alert: Callable[..., None]
    agent: Optional[object] = None                  # LlmAgent; None = triage disabled
    llm_busy: Optional[Callable[[], bool]] = None   # True while an audit holds the model
    model_on: Optional[Callable[[], bool]] = None   # False while the owner has it switched off
    wan_context: Optional[Callable[[], str]] = None # WanWatcher._wan_context, if wired
    # True while the network has no internet: a public host is not polled then (it cannot be
    # reached, and a warning every two minutes about that says nothing new)
    wan_down: Optional[Callable[[], bool]] = None
    # (kind, value, detail, ts) -> None: triage verdicts, for the weekly review
    on_event: Optional[Callable[..., None]] = None
    # seclog.py: every security event kept until the owner marks it handled
    seclog: Optional[object] = None
    # name -> {access_login, https, ...}: one HTTPS GET from outside (Exposure._name_check)
    access_check: Optional[Callable[[str], Awaitable[dict]]] = None

    hosts: list = field(default_factory=list)
    findings: list = field(default_factory=list)    # recent triage verdicts, newest last
    _triage_task: Optional[asyncio.Task] = None
    _last_triage: float = 0.0
    _stop: bool = False

    def __post_init__(self):
        for h in (self._cfg().get("hosts") or []):
            if not h.get("ip") or not h.get("enabled", True):
                continue
            public = bool(h.get("public", False))
            nets = []
            for n in (h.get("trusted") or []):
                try:
                    nets.append(ipaddress.ip_network(str(n), strict=False))
                except ValueError:
                    log.warning("host-log: %s: bad trusted network %r ignored", h["ip"], n)
            self.hosts.append(_Host(name=str(h.get("name") or h["ip"]),
                                    ip=str(h["ip"]), user=str(h.get("user") or "root"),
                                    identity=str(h.get("identity") or ""),
                                    watch=bool(h.get("watch", True)),
                                    public=public, about=str(h.get("about") or ""),
                                    trusted=nets,
                                    burst=bool(h.get("burst", not public)),
                                    max_established=int(h.get("max_established") or 0),
                                    tunnel_from=[str(x) for x in (h.get("tunnel_from") or [])],
                                    tunnel_names=[str(x) for x in (h.get("tunnel_names") or [])]))
        if self.enabled:
            log.info("host-log watcher: %s every %ss",
                     ", ".join(f"{h.user}@{h.ip}" for h in self.watched),
                     self._cfg().get("interval_s", 120))

    # --- config ------------------------------------------------------------
    def _cfg(self) -> dict:
        return (self.cfg.get("hostlog") or {})

    def _hcfg(self, ip: str) -> dict:
        for h in (self._cfg().get("hosts") or []):
            if h.get("ip") == ip:
                return h
        return {}

    def _tcfg(self) -> dict:
        return (self._cfg().get("triage") or {})

    def _bcfg(self) -> dict:
        return (self._cfg().get("burst") or {})

    def _ccfg(self) -> dict:
        return (self._cfg().get("connections") or {})

    @property
    def watched(self) -> list:
        """The hosts whose log is read."""
        return [h for h in self.hosts if h.watch]

    @property
    def enabled(self) -> bool:
        return bool(self._cfg().get("enabled", False)) and bool(self.watched)

    @property
    def observer_ip(self) -> str:
        """The address this process reaches the hosts FROM — our own logins wear it."""
        return str((self.cfg.get("observer") or {}).get("host_ip") or "")

    # --- the task ----------------------------------------------------------
    async def run(self):
        if not self.enabled:
            log.info("host-log watcher disabled (hostlog.enabled=false or no hosts)")
            return
        interval = float(self._cfg().get("interval_s", 120))
        # Prime every host WITHOUT replaying its journal: on a restart the box holds days
        # of history and re-triaging it would page about logins from last week. Same rule
        # the router-log watermark follows.
        for h in self.watched:
            await self._poll(h, prime=True)
        while not self._stop:
            t0 = time.time()
            for h in self.watched:
                try:
                    await self._poll(h)
                except Exception as e:                # never let the watcher die
                    log.exception("host-log poll of %s failed: %s", h.ip, e)
            await asyncio.sleep(max(5.0, interval - (time.time() - t0)))

    def stop(self):
        self._stop = True

    # --- transport ---------------------------------------------------------
    def _ssh_argv(self, h: _Host, remote: str) -> list:
        """ssh with a shared control connection.

        ControlPersist is the whole reason this is not one login every two minutes: the
        first poll authenticates, the rest ride the same socket and write nothing to the
        log they are reading. BatchMode keeps a missing key a fast clean failure instead of
        a password prompt no one is there to answer."""
        s = (self._cfg().get("ssh") or {})
        argv = [str(s.get("binary", "ssh")),
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={int(s.get('connect_timeout_s', 8))}",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={s.get('control_path', '/tmp/lanowl-hostlog-%C')}",
                "-o", f"ControlPersist={s.get('control_persist', '1h')}"]
        key = h.identity or access.ssh_key(self.cfg)
        if key:
            argv += ["-i", key]
        argv += [f"{h.user}@{h.ip}", remote]
        return argv

    async def _ssh(self, h: _Host, remote: str) -> Optional[str]:
        s = (self._cfg().get("ssh") or {})
        try:
            p = await asyncio.create_subprocess_exec(
                *self._ssh_argv(h, remote),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            h.ok, h.last_error = False, "ssh binary not found"
            log.warning("host-log: ssh binary not found")
            return None
        try:
            out, err = await asyncio.wait_for(
                p.communicate(), timeout=float(s.get("command_timeout_s", 25)))
        except asyncio.TimeoutError:
            p.kill()
            h.ok, h.last_error = False, "ssh timeout"
            log.warning("host-log: %s timed out", h.ip)
            return None
        if p.returncode != 0:
            h.ok = False
            h.last_error = (err.decode(errors="replace").strip().splitlines() or [""])[-1][:160]
            log.warning("host-log: %s ssh rc=%s: %s", h.ip, p.returncode, h.last_error)
            return None
        h.ok, h.last_error = True, ""
        return out.decode(errors="replace")

    def _remote_cmd(self, h: _Host) -> str:
        """One shell line: the new journal lines, then the connection census.

        Built as a single command because the expensive part of asking a remote host
        anything is the round trip, not the work. The census is separated by a marker
        rather than a second call for the same reason."""
        hc = self._hcfg(h.ip)
        match = " ".join(hc.get("match") or DEFAULT_MATCH)
        cap = int(self._tcfg().get("fetch_lines", 400))
        if h.public:
            # Everything since the cursor goes through the noise filter on the host, so the
            # cap applies to what is left, not to the scanners.
            cap = max(cap, 20000)
        if h.cursor:
            # --after-cursor is exact and survives rotation and clock changes, which
            # --since does not: the journal's own bookmark, not our guess at one.
            sel = f"--after-cursor='{h.cursor}' -n {cap}"
        else:
            sel = "-n 1"          # priming: we want the cursor, not the history
        jc = f"journalctl -o short-iso --no-pager --show-cursor {sel} {match} 2>/dev/null"
        if h.public:
            # Counted, not shown: lines, failed-password attempts, and the sources (first
            # IPv4 on the line). The cursor line passes through untouched. And where the host
            # sees THIS connection come from — the network's public address today, which is
            # what makes the owner's own logins from home recognisable.
            jc = ('echo "--- self ${SSH_CLIENT%% *}"; '
                  f"{jc} | awk '/{_PUBLIC_NOISE}/ {{ n++; "
                  "if ($0 ~ /Failed (password|none|keyboard)/) a++; "
                  "if (match($0, /[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/)) "
                  "s[substr($0, RSTART, RLENGTH)] = 1; next } { print } "
                  'END { printf "--- noise %d %d", n, a; k = 0; '
                  'for (i in s) { if (k++ < 500) printf " %s", i }; printf "\\n" }\'')
        if not self._ccfg().get("enabled", True):
            return jc
        census = ("echo '--- conns ---'; "
                  "ss -Htn state established 2>/dev/null | wc -l; "
                  "ss -Htn state established 2>/dev/null "
                  "| awk '{n=split($4,a,\":\"); print a[1]}' | sort -u | wc -l")
        return f"{jc}; {census}"

    # --- one poll ----------------------------------------------------------
    async def _poll(self, h: _Host, prime: bool = False):
        if h.public and self.wan_down is not None and self.wan_down():
            return      # no internet: it cannot be reached, and saying so every poll is noise
        raw = await self._ssh(h, self._remote_cmd(h))
        h.last_poll = time.time()
        if raw is None:
            return

        body, _, census = raw.partition("--- conns ---")
        self._read_census(h, census)

        lines, cursor = [], None
        for ln in body.splitlines():
            t = ln.strip()
            m = _CURSOR.match(t)
            if m:
                cursor = m.group("c")
                continue
            if t.startswith("--- self "):
                addr = t[len("--- self "):].strip()
                if addr:
                    h.self_addrs = (h.self_addrs | {addr}) if len(h.self_addrs) < 20 else {addr}
                    h.self_addr = addr
                continue
            if t.startswith("--- noise "):
                if not prime:
                    self._read_noise(h, t)
                continue
            # journalctl's own meta lines — '-- No entries --', '-- Boot ... --',
            # '-- Reboot --'. Dropped: they are not log entries and '-- No entries --'
            # arrives on every quiet poll, which would otherwise be a 'new line' forever.
            # A reboot loses nothing by this: sshd's own 'Server listening on 0.0.0.0
            # port 22' is in this same stream and is not on the routine list.
            if not t or (t.startswith("-- ") and t.endswith("--")):
                continue
            lines.append(ln.rstrip())

        if prime or h.cursor is None:
            h.cursor = cursor
            h.primed_at = h.primed_at or time.time()
            log.info("host-log: %s primed at cursor %s (%d historic line(s) skipped)",
                     h.ip, (cursor or "?")[:24], len(lines))
            return
        if cursor:
            h.cursor = cursor
        h.lines_seen += len(lines)

        # Both deterministic rules run on EVERY poll, before and independently of the shape
        # memo and the triage cooldown — and, note, whether or not the journal had anything
        # new to say. A brute force must not wait fifteen minutes for a model that may be
        # busy; a socket flood leaves no auth lines at all, so a quiet poll returning early
        # would have meant the census was only ever read while something else was happening.
        self._burst_check(h, lines)
        await self._login_check(h, lines)
        self._check_census(h)
        fresh = self._interesting(h, lines) if lines else []
        if fresh:
            self._consider_triage(h, fresh)

    def _read_census(self, h: _Host, census: str):
        nums = [int(x) for x in census.split() if x.strip().isdigit()]
        if len(nums) >= 2:
            h.conns, h.peers = nums[0], nums[1]

    def _read_noise(self, h: _Host, line: str):
        """'--- noise <lines> <attempts> <src> <src> ...' from a public host's filter."""
        parts = line.split()[2:]
        try:
            n, a = int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            return
        now = time.time()
        h.noise.append((now, n, a, set(parts[2:])))
        h.noise = [x for x in h.noise if x[0] > now - 86400]

    def noise_24h(self, h: _Host) -> dict:
        srcs: set = set()
        for x in h.noise:
            srcs |= x[3]
        # lanowl's own tcp/22 probe of the VPS ends in 'Connection closed ... [preauth]'
        # every minute; it is noise, but it is not a scanner
        srcs -= h.self_addrs
        # Counted since this process started watching, not a full day, until it has been
        # watching a day: otherwise a count that has run for twenty seconds reads as "not
        # being attacked".
        since = max(h.primed_at, time.time() - 86400) if h.primed_at else None
        return {"lines": sum(x[1] for x in h.noise), "attempts": sum(x[2] for x in h.noise),
                "sources": len(srcs), "since": since}

    def _trusted(self, h: _Host, src: str) -> bool:
        if src in h.self_addrs or src == self.observer_ip:
            return True
        try:
            a = ipaddress.ip_address(src)
        except ValueError:
            return False
        return any(a in n for n in h.trusted)

    async def _login_check(self, h: _Host, lines: list):
        """On a public host, page on a login that SUCCEEDED from anywhere unexpected.

        The one line that matters among tens of thousands. Where root may log in with a
        password, it is guessed at thousands of times a week. Every one of those failures is
        noise; a single `Accepted` from an address that is not the network's own and not a
        VPN peer is the whole reason to watch the box.
        No model in the path: this must not wait behind an audit. Once per source a day —
        every one of them is still on the Security tab (a repeat counts on the open row).

        A host behind a tunnel (`tunnel_from`): an sshd published on the internet through
        Cloudflare sees every such login from 127.0.0.1 — so there, a login from a tunnel
        address pages the same way. With Cloudflare Access in front of it, checked from outside
        at that moment (`tunnel_names`), a login past Access is a 🟡 warning; without Access,
        or when it could not be checked, it is a 🔴."""
        if not h.public and not h.tunnel_from:
            return
        now = time.time()
        for ln in lines:
            m = _ACCEPTED.search(ln)
            if not m:
                continue
            method, user, src = m.group(1), m.group(2), m.group(3)
            tunnel = src in h.tunnel_from
            if not tunnel and (not h.public or self._trusted(h, src)):
                continue
            lm = _LINE.match(ln)
            msg = lm.group("msg") if lm else ln
            key = f"hostlog-login:{h.ip}:{src}"
            page = (now - h.logins_told.get(src, 0.0)) >= 86400
            guarded = (await self._access(h)) if tunnel else None
            names = ", ".join(h.tunnel_names) or "the Cloudflare Tunnel"
            sev = "warning" if guarded else "critical"
            if tunnel and guarded:
                title = f"{user} logged in with a {method} through {names}, past Cloudflare Access"
                advice = (f"If this was not you: change {user}'s password, check "
                          f"~{user}/.ssh/authorized_keys and who your Access policy lets in.")
            elif tunnel:
                title = (f"{user} logged in with a {method} through the Cloudflare Tunnel — from the "
                         f"internet, " + ("no Cloudflare Access in front" if guarded is False
                                          else "Cloudflare Access could not be checked"))
                advice = (f"If this was not you: change {user}'s password and check "
                          f"~{user}/.ssh/authorized_keys.")
            else:
                title = f"{user} logged in with a {method} from {src} — not the network's own address, not a VPN peer"
                advice = ("If this was not you: change the root password and check "
                          "/root/.ssh/authorized_keys.")
            item = None
            if self.seclog is not None:
                item = self.seclog.add(source=f"host log {h.name}", ip=h.ip, sev=sev, title=title,
                                       detail=f"{msg.strip()}\n{advice}", by="rule", key=key, paged=page)
            h.covered[msg] = (now, item, sev)
            if not page:
                log.info("host-log: %s login from %s (%s, %s) — already told today, on the "
                         "Security tab only", h.ip, src, user, method)
                continue
            h.logins_told[src] = now
            log.warning("host-log: %s LOGIN from %s %s (%s, %s)", h.ip,
                        "untrusted" if not guarded else "the tunnel, past Cloudflare Access,",
                        src, user, method)
            if tunnel and guarded:
                head = (f"🟡 <b>LOGIN THROUGH CLOUDFLARE ACCESS</b> {time.strftime('%H:%M:%S')}\n"
                        f"{h.name} ({h.ip}): <b>{user}</b> logged in with a <b>{method}</b> through "
                        f"<b>{names}</b> — past the Cloudflare Access login (checked just now).\n")
            else:
                head = (f"🔴 <b>LOGIN FROM AN UNKNOWN ADDRESS</b> {time.strftime('%H:%M:%S')}\n"
                        f"{h.name} ({h.ip}): <b>{user}</b> logged in with a <b>{method}</b> "
                        + (f"through the <b>Cloudflare Tunnel</b> (seen as {src}) — from the INTERNET"
                           + (", and Cloudflare Access is NOT in front of it (checked just now)"
                              if guarded is False and h.tunnel_names else "") + ".\n"
                           if tunnel else f"from <b>{src}</b> — not the network's own address, not a VPN peer.\n"))
            self.on_alert(head + f"<i>{self._trim(msg)}</i>\n<i>{advice}</i>", key)

    async def _access(self, h: _Host) -> Optional[bool]:
        """Is Cloudflare Access in front of every name routed to this sshd — right now?
        True/False as measured from outside, None when it could not be told (no names in the
        config, no checker, no answer). Cached ten minutes: a second login is not news."""
        if not h.tunnel_names or self.access_check is None:
            return None
        now = time.time()
        if h.access and now - h.access.get("ts", 0) < 600:
            return h.access.get("guarded")
        results = []
        for n in h.tunnel_names:
            try:
                results.append(await asyncio.wait_for(self.access_check(n), timeout=20))
            except Exception as e:
                log.warning("host-log: Cloudflare Access check of %s failed: %s", n, e)
                results.append({})
        # an HTTPS answer without the Access redirect is an open door; no answer says nothing
        if all(r.get("access_login") is True for r in results):
            guarded: Optional[bool] = True
        elif any(isinstance(r.get("https"), int) and r.get("access_login") is not True
                 for r in results):
            guarded = False
        else:
            guarded = None
        h.access = {"ts": now, "guarded": guarded, "names": list(h.tunnel_names)}
        return guarded

    # --- noise filtering ---------------------------------------------------
    @staticmethod
    def _shape(msg: str) -> str:
        """Message identity with the variable parts removed — the router's rule verbatim.

        'Failed password for root from 10.8.0.5 port 41000' and the same line from another
        port are one recurring condition, not two findings. Without this a brute force
        would triage once per attempt, which is the per-edge spam the alert gate exists to
        prevent; with it, the burst rule below is what notices the repetition."""
        return _DIGITS.sub("#", msg)[:120]

    def _is_ours(self, msg: str, h: Optional[_Host] = None) -> bool:
        """Is this line lanowl's own SSH poll?

        By user AND address, never by user alone. 'Accepted publickey for pi from
        192.168.10.103' is us; the identical line from any other address is somebody else
        using our account, and is the single most important line this module can see.
        A public host sees us arrive from the network's public address instead (`self_addrs`,
        which it reports itself on every poll)."""
        addrs = {self.observer_ip} | (h.self_addrs if h is not None else set())
        if not any(a and re.search(rf"\b{re.escape(a)}\b", msg) for a in addrs):
            return False
        users = {h.user} if h is not None else {x.user for x in self.hosts}
        return any(u and f" {u} " in f" {msg} " for u in users)

    def _interesting(self, h: _Host, lines: list) -> list:
        """Drop the hum and anything whose shape has already had its say."""
        out = []
        for ln in lines:
            m = _LINE.match(ln)
            msg = m.group("msg") if m else ln
            if not msg or any(p in msg for p in _ROUTINE) or self._is_ours(ln, h):
                continue
            shape = self._shape(msg)
            if shape in h._shapes:
                continue
            out.append(ln)
        return out

    # --- deterministic rules ----------------------------------------------
    def _burst_check(self, h: _Host, lines: list):
        """Page on a run of failed authentications, without asking the model.

        This is the rule the LLM triage is explicitly NOT the safety net for. Counted per
        source address so one fat-fingered password from the owner's laptop can never add
        up with a scan from somewhere else, and re-armed only after `repeat_s` so a scanner
        that hammers for an hour still costs one message — the rule."""
        b = self._bcfg()
        if not b.get("enabled", True) or not h.burst:
            return
        window = float(b.get("window_s", 600))
        need = int(b.get("fail_attempts", 8))
        now = time.time()
        for ln in lines:
            m = _LINE.match(ln)
            msg = m.group("msg") if m else ln
            if self._is_ours(ln, h) or not any(k in msg for k in _FAIL_MARKS):
                continue
            src = (_IPV4.findall(msg) or ["?"])[-1]
            h.fails.append((now, src, msg))
        h.fails = [f for f in h.fails if (now - f[0]) <= window]
        if not h.fails:
            return

        by_src: dict = {}
        for t, src, msg in h.fails:
            by_src.setdefault(src, []).append(msg)
        repeat = float(b.get("repeat_s", 3600))
        for src, msgs in by_src.items():
            if len(msgs) < need:
                continue
            if (now - h.burst_told.get(src, 0.0)) < repeat:
                continue
            h.burst_told[src] = now
            users = sorted({u for u in (self._user_of(m) for m in msgs) if u})[:5]
            who = f" (users: {', '.join(users)})" if users else ""
            mins = max(1, round(window / 60))
            log.warning("host-log: %d failed auths on %s from %s", len(msgs), h.ip, src)
            key = f"hostlog-burst:{h.ip}:{src}"
            item = None
            if self.seclog is not None:
                item = self.seclog.add(
                    source=f"host log {h.name}", ip=h.ip, sev="critical", by="rule", key=key,
                    title=f"{len(msgs)} failed logins from {src} in {mins} min{who}",
                    detail=msgs[-1].strip())
            for x in msgs:
                h.covered[x] = (now, item, "critical")
            self.on_alert(
                f"🔴 <b>FAILED LOGINS</b> {time.strftime('%H:%M:%S')}\n"
                f"{h.name} ({h.ip}): {len(msgs)} failed login(s) from <b>{src}</b> "
                f"in the last {mins} min{who}\n"
                f"<i>{self._trim(msgs[-1])}</i>", key)

    @staticmethod
    def _msg(ln: str) -> str:
        m = _LINE.match(ln)
        return m.group("msg") if m else ln

    @staticmethod
    def _user_of(msg: str) -> str:
        # 'Invalid user x from', 'Failed password for (invalid user) x', and sshd's own
        # 'Connection closed by invalid user x'
        m = re.search(r"(?:[Ii]nvalid user|for(?: invalid user)?)\s+(\S+)", msg)
        u = m.group(1) if m else ""
        return "" if u in ("password", "publickey", "keyboard-interactive") else u

    @staticmethod
    def _trim(msg: str, n: int = 140) -> str:
        msg = msg.strip()
        return msg if len(msg) <= n else msg[: n - 1] + "…"

    def _check_census(self, h: _Host):
        """A crude flood ceiling on established connections.

        Crude on purpose, and it is not a DDoS detector — a flood large enough to matter is
        felt at the WAN, where the ping loop in wanwatch.py already calls it 'no internet at
        all'. What this catches is the host-local version: something on the host has opened, or
        had opened against it, far more sockets than it ever normally holds. The default
        ceiling sits well above the ~120 a quiet home server carries at rest, and two consecutive polls
        are required, because one spike while a backup runs is not news."""
        c = self._ccfg()
        if not c.get("enabled", True) or not h.conns:
            return
        ceiling = h.max_established or int(c.get("max_established", 600))
        if h.conns < ceiling:
            h.conns_over = 0
            return
        h.conns_over += 1
        if h.conns_over < int(c.get("confirm_polls", 2)):
            return
        if (time.time() - h.conns_told) < float(c.get("repeat_s", 3600)):
            return
        h.conns_told = time.time()
        log.warning("host-log: %s holding %d established connections", h.ip, h.conns)
        if self.seclog is not None:
            self.seclog.add(source=f"host log {h.name}", ip=h.ip, sev="warning", by="rule",
                            key=f"hostlog-conns:{h.ip}",
                            title=f"{h.conns} established connections from {h.peers} address(es) "
                                  f"— normally well under {ceiling}",
                            detail="Check with: ss -Htn state established | awk '{print $4}' "
                                   "| sort | uniq -c | sort -rn | head")
        self.on_alert(
            f"🟡 <b>CONNECTION FLOOD?</b> {time.strftime('%H:%M:%S')}\n"
            f"{h.name} ({h.ip}) is holding {h.conns} established TCP connections "
            f"from {h.peers} address(es) — normally well under {ceiling}.\n"
            f"<i>Check with: ss -Htn state established | awk '{{print $4}}' "
            f"| sort | uniq -c | sort -rn | head</i>",
            f"hostlog-conns:{h.ip}")

    # --- LLM triage --------------------------------------------------------
    def _consider_triage(self, h: _Host, lines: list):
        """Rate-limited hand-off of the leftover lines to the model.

        The shape memo is only written once a triage actually starts: lines skipped because
        the model was busy stay unexplained and are offered again on the next poll, exactly
        as the router's separate triage watermark does."""
        if self.agent is None or (self.model_on is not None and not self.model_on()):
            return                                    # none, or switched off (Auditor.set_model)
        t = self._tcfg()
        if not t.get("enabled", True):
            return
        if self._triage_task is not None and not self._triage_task.done():
            return                                    # one in flight is enough
        # Per host: a noisy public host must not silence the others for a quarter of an hour.
        if (time.time() - h.last_triage) < float(t.get("cooldown_s", 900)):
            return
        if self.llm_busy is not None and self.llm_busy():
            # The hourly audit has the model. Don't queue behind it — the cursor has already
            # moved, but the shape memo has not, so nothing is lost that a later poll of the
            # same condition would not raise again.
            log.debug("host-log triage deferred: an LLM audit is running")
            return

        batch = lines[-int(t.get("max_lines", 40)):]
        for ln in batch:
            m = _LINE.match(ln)
            h._shapes.add(self._shape(m.group("msg") if m else ln))
        if len(h._shapes) > 500:                      # keep the memo bounded
            h._shapes = set(list(h._shapes)[-250:])

        self._last_triage = h.last_triage = time.time()
        log.info("host-log triage: %d new line(s) from %s -> LLM", len(batch), h.ip)
        self._triage_task = asyncio.ensure_future(self._run_triage(h, batch))

    def _context(self, h: _Host) -> str:
        bits = []
        if h.conns:
            rest = "" if h.public else " (at rest this host sits near 120)"
            bits.append(f"CONNECTION CENSUS: {h.name} currently holds {h.conns} established "
                        f"TCP connections from {h.peers} distinct addresses{rest}.")
        if h.public:
            nz = self.noise_24h(h)
            home = ", ".join(sorted(h.self_addrs)) or "unknown"
            since = time.strftime("%d/%m %H:%M", time.localtime(nz["since"])) if nz.get("since") else "?"
            bits.append(f"SCANNER NOISE, already removed from the lines below: {nz['attempts']} "
                        f"failed password attempts from {nz['sources']} addresses since {since}. "
                        f"The network's public address as this host sees it: {home}.")
        wan = self.wan_context() if self.wan_context is not None else ""
        if wan:
            bits.append(f"WHAT WAS HAPPENING ON THE INTERNET CONNECTION: {wan}")
        acc = h.access
        if acc and time.time() - acc.get("ts", 0) < 3600 and acc.get("guarded") is not None:
            bits.append(f"CLOUDFLARE ACCESS, checked from outside at "
                        f"{time.strftime('%H:%M', time.localtime(acc['ts']))}: "
                        + (f"{', '.join(acc['names'])} asks for a Cloudflare login first, so a "
                           f"connection through the tunnel has passed it before reaching sshd."
                           if acc["guarded"] else
                           f"{', '.join(acc['names'])} does NOT ask for a Cloudflare login — anyone "
                           f"on the internet reaches sshd through the tunnel."))
        runs = [r for r in h.own_runs if time.time() - r[1] < 7200]
        if runs:
            # said, not filtered: the model still judges every sudo line — only it knows WHEN
            # lanowl itself was the one using sudo (exposure.py, daily)
            bits.append("THE AUDITOR ITSELF, on this host: " + "; ".join(
                f"{time.strftime('%H:%M:%S', time.localtime(a))}–"
                f"{time.strftime('%H:%M:%S', time.localtime(b))} {what}" for a, b, what in runs)
                + f" — logged in from {self.observer_ip}. Sudo lines in that window whose command "
                  "is that read-only script are its own; anything else is not.")
        return "\n".join(bits)

    def note_own(self, ip: str, start: float, end: float, what: str):
        """lanowl ran something on `ip` itself (its security review's sudo): the triage
        is told, with the time, so it need not guess whose sudo that was."""
        h = next((x for x in self.hosts if x.ip == ip), None)
        if h is not None:
            h.own_runs = [r for r in h.own_runs if time.time() - r[1] < 7200][-4:] + [(start, end, what)]

    async def _run_triage(self, h: _Host, batch: list):
        t = self._tcfg()
        # Context first, evidence second: a model that meets the lines before the note has
        # usually made up its mind by the time it reads it. Same ordering as the router's.
        ctx = self._context(h)
        prefix = f"{ctx}\n\n" if ctx else ""
        where = "a public server on the internet" if h.public else "a Linux server on the home LAN"
        try:
            verdict = await self.agent.ask_json(
                host_system(h.about),
                f"{prefix}Host: {h.name} ({h.ip}), {where}.\n"
                f"Log lines that are not part of its normal background chatter "
                f"({len(batch)} line(s)):\n\n" + "\n".join(batch),
                timeout_s=float(t.get("timeout_s", 90)))
        except Exception as e:
            log.warning("host-log triage failed: %s", e)
            return
        if not verdict:
            log.info("host-log triage: no usable verdict")
            return
        f = {"ts": time.time(), "source": f"host log {h.name}", "lines": len(batch),
             "problem": bool(verdict.get("problem")),
             "kind": verdict_kind(verdict, "security"),
             "severity": str(verdict.get("severity", "info")).lower(),
             "summary": str(verdict.get("summary", ""))[:200],
             # whole: cut at 300 it loses its last sentence on the dashboard
             "detail": str(verdict.get("detail", ""))[:1500]}
        self.findings = (self.findings + [f])[-30:]
        if self.on_event is not None:
            try:
                self.on_event("finding", None, json.dumps(f, ensure_ascii=False), None)
            except Exception:
                pass
        if not verdict.get("problem"):
            log.info("host-log triage: nothing worth reporting (%s)",
                     str(verdict.get("summary", ""))[:80])
            return

        sev = str(verdict.get("severity", "warning")).lower()
        summary = str(verdict.get("summary", "")).strip() or "unusual activity in the host log"
        detail = str(verdict.get("detail", "")).strip()
        log.warning("host-log triage: %s — %s (%s)", sev.upper(), summary, h.ip)
        notify = sev in (t.get("notify_severities") or ["critical", "warning"])
        # One login, one message (not the rule's 🔴 and this 🟡 seconds apart about the
        # same line). When a rule already paged for any of these lines, the model's
        # words go on the rule's row; only a verdict WORSE than that page is sent as well.
        now = time.time()
        h.covered = {k: v for k, v in h.covered.items() if now - v[0] < 3600}
        hits = [h.covered[m] for m in (self._msg(ln) for ln in batch) if m in h.covered]
        if hits:
            top = max(hits, key=lambda x: rank(x[2]))
            if self.seclog is not None and top[1]:
                self.seclog.attach(top[1], sev, summary, detail)
            if rank(sev) <= rank(top[2]):
                log.info("host-log triage: a rule already paged for these lines — the verdict "
                         "is on its row, not sent again")
                return
        elif (self.seclog is not None and f["kind"] == "security"
              and sev in ("critical", "warning")):
            self.seclog.add(source=f"host log {h.name}", ip=h.ip, sev=sev, title=summary,
                            detail=detail, by="model", paged=notify)
        if not notify:
            return                                    # logged and on the dashboard, but quiet
        emoji = {"critical": "🔴", "warning": "🟡"}.get(sev, "⚪")
        self.on_alert(f"{emoji} <b>HOST LOG</b> {time.strftime('%H:%M:%S')} — {h.name}\n"
                      f"{summary}"
                      + (f"\n<i>{detail}</i>" if detail else "")
                      + f"\n<i>from {len(batch)} new log line(s) on {h.ip}</i>",
                      f"hostlog-triage:{h.ip}")

    # --- dashboard ---------------------------------------------------------
    def snapshot_state(self) -> dict:
        """What the report/dashboard shows. Mirrors WanWatcher.snapshot_state."""
        now = time.time()
        return {
            "enabled": self.enabled,
            "hosts": [{
                "name": h.name, "ip": h.ip, "ok": h.ok, "error": h.last_error,
                "age_s": round(now - h.last_poll) if h.last_poll else None,
                "lines_seen": h.lines_seen,
                "failed_auths_window": len(h.fails),
                "established": h.conns, "peers": h.peers,
                "public": h.public,
                **({"noise_24h": self.noise_24h(h)} if h.public else {}),
            } for h in self.watched],
        }

    # --- the raw log, on request --------------------------------------------
    async def read_log(self, ip: str, hours: float = 24, search: str = "", unit: str = "",
                       limit: int = 40, noise: bool = False) -> dict:
        """The host's journal as it is — for "give me the exact log of the VPS".

        Without this the model has only what the triage made of these lines, and answers that
        request with "I can't pull it from here". This reads them on demand, over
        the same shared ssh connection, read-only: `journalctl`, newest last.

        The model's words never reach the remote shell as shell: `search` and `unit` are
        quoted (and `unit` must look like a unit name), the numbers are numbers. The
        scanner hum and the IPsec keepalives of a public host are left out unless `noise` —
        35k lines a day of "Failed password for root" would bury every line anyone asked
        for — and so are lanowl's own logins."""
        h = next((x for x in self.watched if x.ip == ip), None)
        if h is None:
            return {"error": f"{ip} is not a host whose log lanowl reads; it reads: "
                             + (", ".join(f"{x.name} ({x.ip})" for x in self.watched) or "none")}
        mins = max(1, min(int(float(hours or 24) * 60), 72 * 60))
        limit = max(1, min(int(limit or 40), 100))
        unit = str(unit or "").strip()
        if unit and not re.fullmatch(r"[A-Za-z0-9@._:-]{1,64}", unit):
            return {"error": f"{unit!r} is not a unit name"}
        search = " ".join(str(search or "").split())[:80]
        cmd = f"journalctl -o short-iso --no-pager --since=-{mins}min"
        if unit:
            cmd += f" -u {shlex.quote(unit)}"
        cmd += " 2>/dev/null"
        if h.public and not noise:
            cmd += f" | grep -Ev '{_PUBLIC_NOISE}|{_PUBLIC_CHATTER}'"
        if search:
            cmd += f" | grep -F -i -e {shlex.quote(search)}"
        # a few spare for lanowl's own logins, dropped below
        cmd += f" | tail -n {limit + 20}; true"
        s = (self._cfg().get("ssh") or {})
        try:
            p = await asyncio.create_subprocess_exec(
                *self._ssh_argv(h, cmd), stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(
                p.communicate(), timeout=float(s.get("command_timeout_s", 25)))
        except FileNotFoundError:
            return {"error": "ssh is not installed here"}
        except asyncio.TimeoutError:
            p.kill()
            return {"error": f"reading {h.name}'s log timed out"}
        if p.returncode != 0:
            return {"error": f"could not read {h.name}'s log: "
                             + ((err.decode(errors='replace').strip().splitlines() or ['?'])[-1][:160])}
        lines = [ln for ln in out.decode(errors="replace").splitlines()
                 if ln.strip() and not ln.startswith("-- ") and not self._is_ours(ln, h)]
        lines = [_local_ts(ln)[:240] for ln in lines[-limit:]]
        return {"host": f"{h.name} ({h.ip})", "window": f"last {mins / 60:g}h",
                "unit": unit or "all", "search": search or None,
                "noise": ("included" if noise or not h.public else
                          "left out: failed logins from internet scanners, and IPsec "
                          "keepalives (DPD) — noise=true shows them"),
                "lines": lines, "count": len(lines),
                "note": ("no line matched — in this window, with these filters" if not lines
                         else f"the last {len(lines)} matching lines, oldest first"
                         + (" (there may be more: raise limit or narrow the search)"
                            if len(lines) == limit else ""))}
