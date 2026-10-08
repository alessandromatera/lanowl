"""Fast WAN watcher: a ping loop and a router-log reader that run OUTSIDE the sweep.

Why it exists: a router that fails over in a minute or two makes WAN events shorter than the
sweep can see. The 60 s sweep needs `debounce_fails` consecutive misses before it calls the
WAN down, so a 90 s failover is at most one failed sweep and never trips; a route poll every
few minutes catches a short failover by luck. Sampling slower than the event is a blind spot.

So this module answers three questions on three clocks, and no single slow sampler is
load-bearing:

    ping loop   every `interval_s` (15s)      is there a TOTAL blackout right now?
    log scan    every `log_interval_s` (60s)  did the main link flap since I last looked?
    route poll  every `wan.path.interval_s`   are we on the backup link RIGHT NOW?

The log scan is what makes the coverage complete: a failover script that writes a line on
every transition (`wan.watch.log_down_match` / `log_up_match`) lets a failover that began AND
ended between two polls be seen — the class of event a level-sampling poll never sees.

Those answers collapse into ONE of three states, which is how people on the network actually
experience the internet, and what the dashboard box is coloured by:

    ok      green   traffic is going out over the main link
    backup  yellow  the internet works, but over the backup link — the main link is down
    down    red     nothing answers: there is no internet at all

`backup` and `down` are very different things to be told about, so they get different
messages. Being on the backup is a problem to look at; having no internet at all is the one
people are standing in the middle of, and it is announced on its own — including the moment
it ends, which is why every message here carries absolute wall-clock times. Anything raised
while there is no route out waits in the outbox and is delivered late by definition; a
message that only says "just now" is worthless by the time it arrives.

It runs as its own asyncio task, so a slow model audit never makes it blind.

Alerts go through a dedicated AlertGate, so the rule holds — one message per incident, never
one per edge. A line that flaps five times in an evening pages once and then reports
"unstable for 3h · 5 outages" when it finally settles.

The router is read over one kept api-ssl connection (routeros.py): the log is FOLLOWED, so a
link-down line is acted on about a second after the router writes it, and the default route
is read every ping round because over that connection a read costs no login. With the API
down, both fall back to a REST read of the whole buffer every `log_interval_s`, and the
sweep's `wan.path` poll.

Without `wan.path.route_comment` and the log matches configured, only the ping loop runs: the
internet is ok or down, with no backup link to tell apart.

Read-only: ICMP echo, the router's log and its route table. Nothing here writes to the router.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import probes, routeros, wanexplain
from .alerts import NEW, RECOVERED, STILL, AlertGate
from .discovery import fetch_wan_path, resolve_mikrotik
from .model import router_host, wan_links
from .report import _html, human_duration

log = logging.getLogger("lanowl.wanwatch")

# ONE key for "the internet is not working properly right now", fed by all THREE detectors
# that can see that:
#   ping loop   (this module)  — no reply from any target: no internet at all
#   route poll  (the sweep)    — level: we are on the backup link right now
#   log scan    (this module)  — edge: the main link dropped and came back unobserved
#
# With a key each, ONE failover costs four messages: a blackout alert, a backup-link alert,
# then their two recoveries — two names for one event that a person experiences as "the
# internet went away for a bit". So they are one episode: whichever detector notices first
# opens it, the others enrich its detail, and it closes once.
WAN_KEY = "wan-incident:-:wan:Internet / WAN"

# The three states the whole module reduces to. One at a time, always: `down` outranks
# `backup` because "no internet at all" is the more urgent truth when both are true.
STATE_OK = "ok"          # green  — on the main link, everything answers
STATE_BACKUP = "backup"  # yellow — internet works, over the backup link: the main one is down
STATE_DOWN = "down"      # red    — nothing answers at all

# Router-log lines that are pure background hum. Everything NOT matched here is offered to
# the model — the point of asking a model at all is to catch the thing nobody wrote a rule
# for, so this is an exclusion list, never an allow-list.
#   - lanowl's own REST reads and the netwatch scripts' fetch callbacks
#   - the failover chatter, which the flap detector above already reports: the configured
#     `log_down_match` / `log_up_match` and anything listed in `wan.watch.routine`
#     (added at runtime, see `_routine_patterns`)
# NOTE on logins: RouterOS writes `user lanowl logged in from <us> via rest-api` for every
# REST read this process makes — a fifth of the buffer on a busy day. It is tempting to drop
# anything containing "logged in", but a login by someone who is NOT us is exactly the kind
# of thing worth waking up for. So lanowl's own username is excluded at runtime and every
# other login still reaches the model.
_ROUTINE = (
    "Download from",
    "changed by netwatch", "event up [", "event down [",
    "assigned ", "deassigned ",
)
_DIGITS = re.compile(r"\d+")
_GROUP_SET = re.compile(r"^user group (\S+) changed by ")
_POLICY = re.compile(r"\bpolicy=([^\s)]+)")


def owner_granted(msg: str, group: str, allowed) -> bool:
    """Is this log line the owner setting lanowl's OWN router group to the grants they chose
    for it (config `mikrotik.lanowl_policy`)? Then it is not news.

    Giving lanowl's user `test` and `sniff` (so the model's investigation sessions can ping,
    traceroute and torch from the router) is a group change the triage would rightly warn
    about, by what it can see. But the owner did it on purpose. So a change that ends at no
    more than the chosen set is filtered here, deterministically; one that grants anything
    else (write, policy, sensitive, reboot, password…) still goes to the model like any
    configuration change."""
    m = _GROUP_SET.match(msg.strip())
    if not m or m.group(1) != group:
        return False
    pol = _POLICY.findall(msg)
    if not pol:
        return False
    granted = {x.strip() for x in pol[-1].split(",") if x.strip() and not x.startswith("!")}
    return granted <= {str(x) for x in (allowed or [])}

TRIAGE_SYSTEM = """You triage RouterOS (MikroTik) log lines for a home network.

You are given log lines that are NOT part of the router's normal background chatter.
Most of the time they are still harmless: routine DHCP churn, a device reconnecting to
Wi-Fi, a scheduled script. Say so. Only report a problem when the lines show something a
homeowner should actually act on — repeated authentication failures, an interface or link
going down and staying down, the router rebooting or running out of memory, a configuration
change nobody scheduled, storage or certificate errors, signs of an intrusion attempt.

Reply with ONLY this JSON object, no prose and no code fence:
{"problem": true|false,
 "kind": "security"|"health",
 "severity": "critical"|"warning"|"info",
 "summary": "<one short line a person reads on a phone>",
 "detail": "<one or two sentences: what the lines show and what to check>"}

"kind" says what the lines are ABOUT, whether or not they are a problem: "security" for access
— logins and failed logins, users, a configuration change, a service or port opened, anything
that reads like an intrusion attempt; "health" for the network working — links and the
internet, the router rebooting, memory, storage, DHCP, a VPN tunnel dropping.

Set "problem": false whenever you are unsure. A false alarm at 3am costs more than a late
notice; the deterministic checks already cover reachability, so you are the long tail.

You may be given a WHAT WAS HAPPENING note describing an internet outage. Take it as fact
and reason from it: while the network has no internet, everything that needs the internet
fails too, and those failures are SYMPTOMS of the outage, not findings. A VPN or tunnel
that cannot reach its peer, a cloud service that cannot be resolved, an NTP sync that
fails, a remote backup that times out — inside that window all of these are the outage
being visible in one more place, and the user has already been told about the outage
itself. Set "problem": false and say which outage explains them.

What still matters in that window is anything the outage does NOT explain: the router
rebooting, authentication failures from the LAN, hardware or storage errors, a
configuration change. And if an internet-dependent failure is still happening AFTER the
connection came back, that is a real finding — say so, because it is no longer a
symptom."""

def verdict_kind(verdict: dict, default: str) -> str:
    """A log check's verdict is about security or about health (the dashboard's Security tab
    shows the first, the Logbook both). The model's word, or the source's default
    when it gave none — the router's log is mostly the network working, a host's auth log is
    mostly about access."""
    k = str(verdict.get("kind") or "").strip().lower()
    return k if k in ("security", "health") else default


# RouterOS renders log timestamps a few different ways depending on version and on whether
# the entry is from today. Try them all rather than guess.
_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%b/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%H:%M:%S")


def _clock(ts: float) -> str:
    """An absolute wall-clock time for a message that may well be read much later.

    Every alert this module raises can be delayed: during a blackout there is no route to
    Telegram and it waits in the outbox, and a recovery is only believed after
    `recovery_confirm_s`. "Just now" is therefore usually wrong by the time it is read."""
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "?"


def _parse_log_time(s: str, ref: Optional[datetime.datetime] = None) -> Optional[datetime.datetime]:
    """Parse a RouterOS log timestamp into a naive datetime in the ROUTER's local time.

    Bare `HH:MM:SS` entries carry no date — RouterOS uses that form for 'today'. They are
    dated from `ref` (the newest fully-qualified stamp in the same batch) rather than from
    this machine's clock, so a few seconds of drift between the Mac and the router cannot
    shift an event onto the wrong day.
    """
    s = (s or "").strip()
    for fmt in _TIME_FORMATS:
        try:
            t = datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
        if fmt == "%H:%M:%S":
            base = (ref or datetime.datetime.now()).date()
            t = t.replace(year=base.year, month=base.month, day=base.day)
        return t
    return None


_FLAGS = re.compile(r"^\s*\d+\s+([A-Z ]*?)\s*name=")


def interface_on(out: str, iface: str) -> Optional[bool]:
    """`/interface print terse where name=X` -> is it switched on (no X flag)? None: not listed."""
    for ln in (out or "").splitlines():
        m = _FLAGS.match(ln)
        if m and re.search(rf'\bname="?{re.escape(iface)}"?(\s|$)', ln):
            return "X" not in m.group(1)
    return None


def registration(out: str, iface: str):
    """A wireless registration table (terse) -> the signal (dBm, int) of `iface`'s link to its
    access point, True when connected but the signal is not shown, False when not connected."""
    for ln in (out or "").splitlines():
        if re.search(rf'\binterface="?{re.escape(iface)}"?(\s|$)', ln):
            m = re.search(r"\bsignal-strength=(-?\d+)", ln)
            return int(m.group(1)) if m else True
    return False


@dataclass
class Flap:
    """One completed main-link outage, as recorded by the router itself."""
    start: datetime.datetime
    end: datetime.datetime

    @property
    def seconds(self) -> float:
        return (self.end - self.start).total_seconds()


@dataclass
class _Shim:
    """format_alerts() only reads `.ts` off the snapshot; this stands in for one."""
    ts: float


@dataclass
class WanWatcher:
    cfg: dict
    on_alert: Callable[..., None]   # (text, key="") -> None
    agent: Optional[object] = None      # LlmAgent, for router-log triage; None = disabled
    llm_busy: Optional[Callable[[], bool]] = None   # True while an audit holds the model
    model_on: Optional[Callable[[], bool]] = None   # False while the owner has it switched off

    # --- ping state ---
    targets: dict = field(default_factory=dict)   # target -> ok, last probe
    blackout: bool = False                        # debounce-confirmed total outage
    _fails: int = 0
    _oks: int = 0
    _blackout_since: float = 0.0
    _fail_since: float = 0.0     # first FAILED round of the current run, not the confirmation
    _blackout_paged: bool = False                 # this blackout cleared the min_outage_s floor
    _last_run_paged: bool = False                 # ...kept for `_update_state` once it ended
    blips: list = field(default_factory=list)     # (start, end) blackouts too short to page

    # --- what each one looked like, so a blip can be clicked and understood: the router's
    # log turns over in days, and nothing else kept at the time can say where it broke. So
    # each run of failed rounds keeps its evidence, and the event gets it (wanexplain.py).
    _run: Optional[dict] = None                   # the current run of failed rounds
    _pending_ev: list = field(default_factory=list)   # closed runs, finished ~75 s later
    netwatch: dict = field(default_factory=dict)  # the router's own pings: host -> counters
    _nw_at: float = 0.0
    _isp_gw: str = ""                             # the main link's first hop (its DHCP gateway)
    _isp_at: float = 0.0

    # --- the standby link (`wan.standby`, optional): a backup whose own device switches its
    # uplink on only when the main router stops answering it — e.g. a MikroTik on an LTE or
    # radio link, whose netwatch enables its interface (`iface`) when the main router's
    # address goes quiet. So off — or on — with the main link up is fine, and it is read only
    # while the router has the main link down (`_standby_tick`): still off after `grace_s` is
    # the failover failing; on and connected but no internet through it (its `probe` goes only
    # over it) is a blackout with its reason. wanexplain.standby_story turns the reads into words.
    standby: dict = field(default_factory=dict)      # the last read: {ts, on, link, signal, net, err}
    _sb_reads: list = field(default_factory=list)   # this main-link outage's reads, oldest first
    _sb_down_at: float = 0.0                        # when the router took the main link out (0 = it has it)
    _sb_last: Optional[dict] = None                 # the last outage's {down_at, up_at, reads}
    _sb_task: Optional[asyncio.Task] = None
    _sb_at: float = 0.0

    # --- router-log state ---
    _watermark: Optional[datetime.datetime] = None   # newest log line already processed
    _pending_down: Optional[datetime.datetime] = None
    flaps: list = field(default_factory=list)        # recent completed outages, ALL lengths
    _last_flap: Optional[Flap] = None                # newest SHORT flap (the one we narrate)
    _last_flap_at: float = 0.0
    _last_log_scan: float = 0.0

    # --- the followed log (API up) ---
    # `/log/print follow-only` delivers each new line as the router writes it. The buffer is
    # read in full once per (re)subscription and kept here by `.id`; after that a scan reads
    # this copy and no request goes to the router at all.
    _live: bool = False                              # the follow is running right now
    _resync: bool = True                             # ...but read the whole buffer once more
    _mirror: dict = field(default_factory=dict)      # .id -> row, oldest first
    _mirror_cap: int = 10000
    _follow_conn: int = 0                            # serial of the connection carrying it
    _arrived: list = field(default_factory=list)     # followed rows not merged yet
    _wake: Optional[asyncio.Event] = None            # a main link edge line / a new follow: scan now
    _router: Optional[object] = None                 # routeros.Router
    _access: Optional[object] = None                 # access.Access, for _routine_patterns

    # --- route-poll state (the sweep's poll, or ours over the API; see set_path) ---
    path: Optional[dict] = None                      # last {link, on_backup, detail}
    _path_at: float = 0.0                            # when that answer was read
    _own_path_at: float = 0.0                        # ...by this watcher, over the API

    # --- the three-state view (ok | backup | down) -------------------------
    # Level, not edge: what is true right now. This is what the dashboard box is coloured
    # by and what decides which of the three kinds of message a transition earns. It is
    # deliberately NOT gated by `min_outage_s` — the floor is about what is worth a human's
    # attention, and the dashboard should always show the truth as fast as it is known.
    state: str = STATE_OK
    state_since: float = 0.0
    _down_since: float = 0.0     # when the CURRENT total blackout began (0 = not in one)
    _last_down_at: float = 0.0   # ...and when the last one began, kept after it ended
    _back_at: float = 0.0        # when the last total blackout ended, as observed
    _backup_since: float = 0.0   # when this incident moved onto the backup link
    _restored_at: float = 0.0    # when the internet last returned to the main link

    # Outage seconds and count accumulated for the CURRENTLY OPEN link episode, so the
    # recovery message can report what the router measured. Kept here rather than derived
    # from `flaps` because that list is pruned at 24h, and an episode can outlive it.
    _ep_outage_s: float = 0.0
    _ep_outages: int = 0
    # ...and the same accounting for the total-blackout half of the episode: how many times
    # the network had NO internet during this incident and for how long in total. Separate
    # from the outage numbers above, which count main-link outages the backup may have covered.
    _ep_blackouts: int = 0
    _ep_blackout_s: float = 0.0
    _ep_blackout_told: bool = False   # the user was told "no internet at all" for this one
    _ep_back_told: bool = False       # ...and has since been told it came back
    _ep_main_told: bool = False      # ...and that the MAIN link is carrying it again
    _ep_link_trouble: bool = False    # the main link was implicated, not just the pings

    # --- router-log LLM triage state ---
    _triage_task: Optional[asyncio.Task] = None
    _triage_mark: Optional[datetime.datetime] = None   # separate from _watermark, see below
    _last_triage: float = 0.0
    _seen_shapes: set = field(default_factory=set)   # message shapes already triaged

    _gate: Optional[AlertGate] = None
    _stop: bool = False
    # Auditor.resume_alerts wires this to SQLite; None (tests, `--once`) = nothing is saved
    persist: Optional[Callable[[dict], None]] = None
    # (kind, value, detail, ts) -> None. Every main-link outage, blackout and blip, and every
    # log-triage verdict, for the weekly review.
    on_event: Optional[Callable[..., None]] = None
    # seclog.py: a security problem the router's log showed stays on the
    # Security tab until the owner marks it handled
    seclog: Optional[object] = None
    # The router's log as last read, minus our own REST logins: [(datetime, row)]. The scan
    # already fetches the whole buffer every minute for the flap detector; keeping it is
    # what lets `device_forensics` say "it rejoined DHCP at 14:02:12 with four others".
    log_rows: list = field(default_factory=list)
    # Recent triage verdicts, newest last: what the model concluded about the log's odd
    # lines, so the hourly audit and the owner's questions can see it.
    findings: list = field(default_factory=list)

    def __post_init__(self):
        w = self._wcfg()
        self._gate = AlertGate.from_config(self.cfg)
        log.info("WAN watcher: ping %s every %ss (confirm %sx), router-log scan every %ss",
                 ",".join(self._targets()) or "(none)", w.get("interval_s", 15),
                 w.get("fail_checks", 2), w.get("log_interval_s", 60))

    # --- config helpers ----------------------------------------------------
    def _wcfg(self) -> dict:
        return ((self.cfg.get("wan", {}) or {}).get("watch") or {})

    def _targets(self) -> list:
        return (self.cfg.get("wan", {}) or {}).get("targets", []) or []

    @property
    def enabled(self) -> bool:
        return bool(self._wcfg().get("enabled", True)) and bool(self._targets())

    @property
    def observed(self) -> bool:
        """Has the ping loop actually run yet?

        `--once` builds the watcher but never starts its task, so `state` is still the
        constructor's optimistic default. A caller that prefers this module's answer to
        its own has to know the difference between 'ok' and 'not asked yet'."""
        return bool(self.targets)

    # --- the task ----------------------------------------------------------
    async def run(self):
        """Own loop, own clock. Never awaits the sweep or the LLM."""
        if not self.enabled:
            log.info("WAN watcher disabled (wan.watch.enabled=false or no targets)")
            return
        w = self._wcfg()
        interval = float(w.get("interval_s", 15))
        self._wake = asyncio.Event()
        router = self._rt()
        if router.enabled:
            router.follow("log", "/log/print", {"follow-only": ""},
                          self._on_log_row, self._on_follow)
        # Prime the log watermark WITHOUT replaying history: on a restart the buffer still
        # holds yesterday's flaps and re-announcing them would be a burst of stale pages.
        await self._scan_log(prime=True)
        while not self._stop:
            t0 = time.time()
            try:
                await self._tick()
            except Exception as e:                     # never let the watcher die
                log.exception("WAN watcher tick failed: %s", e)
            # Sleep to the next ping round — but a main link edge the router just wrote is read
            # now, not at the next minute's scan. The ping clock itself is left alone: the
            # blackout debounce is counted in rounds.
            end = time.time() + max(1.0, interval - (time.time() - t0))
            while not self._stop and await self._edge_within(end - time.time()):
                try:
                    await self._scan_log()
                    await self._poll_path()
                    self._emit()
                except Exception as e:
                    log.exception("WAN watcher edge scan failed: %s", e)

    async def _edge_within(self, seconds: float) -> bool:
        """Wait up to `seconds`; True if a main link edge line arrived meanwhile, or the follow
        (re)started and the buffer has to be read again."""
        if seconds <= 0:
            return False
        if self._wake is None:
            await asyncio.sleep(seconds)
            return False
        try:
            await asyncio.wait_for(self._wake.wait(), seconds)
        except asyncio.TimeoutError:
            return False
        self._wake.clear()
        return True

    def stop(self):
        self._stop = True

    async def _tick(self):
        w = self._wcfg()
        changed = await self._ping_round()
        # Scan the router log on a slow clock, but jump on it immediately when the ping
        # state just flipped — that is when "why?" is worth one extra REST GET.
        due = (time.time() - self._last_log_scan) >= float(w.get("log_interval_s", 60))
        if due or changed:
            await self._scan_log()
        await self._poll_path()
        self._standby_tick(time.time())
        self._emit()
        try:
            await self._finish_evidence(time.time())
            await self._router_facts(time.time())
        except Exception as e:                    # evidence must never stop the watcher
            log.warning("WAN watcher: evidence not kept: %s", e)

    def _rt(self):
        if self._router is None:
            self._router = routeros.shared(self.cfg)
        return self._router

    async def _poll_path(self):
        """Which link carries the default route, read here every ping round — only while the
        API connection is up, where a read costs no login and writes nothing to the router's
        log. So a failover colours the box yellow within a round, not at the sweep's
        five-minute poll. With the API down the sweep polls it over REST, as before.

        A failed read ("unknown") is not an answer: the last known path stands, rather than
        a hiccup reading as "back on the main link"."""
        if not self._rt().up or not ((self.cfg.get("wan") or {}).get("path") or {}):
            return
        wp = await fetch_wan_path(self.cfg)
        if wp is None or wp.get("link") == "unknown":
            return
        self.set_path(wp)
        self._own_path_at = time.time()

    def path_is_fresh(self, now: float, max_age_s: float = 60.0) -> bool:
        """Did this watcher read the route itself within `max_age_s`? Then the sweep need not."""
        return self.path is not None and (now - self._own_path_at) <= max_age_s

    # --- the followed log --------------------------------------------------
    def _on_log_row(self, row: dict):
        """One line from `/log/print follow-only`, as the router writes it."""
        if len(self._arrived) < 20000:          # a stalled loop must not grow this forever
            self._arrived.append(row)
        msg = row.get("message") or ""
        down_pat, up_pat = self._edge_patterns()
        if self._wake is not None and down_pat and (down_pat in msg or up_pat in msg):
            self._wake.set()
        if self._rights_changed(msg):
            # An API session keeps the rights it logged in with (REST's ~10-minute lag was
            # its internal session's lifetime), so on a kept connection a change would never
            # take effect. Log in again: one line, and the new rights apply at once.
            self._rt().renew("lanowl's router rights changed")

    def _rights_changed(self, msg: str) -> bool:
        mk = self.cfg.get("mikrotik") or {}
        m = _GROUP_SET.match(msg.strip())
        if m and m.group(1) == str(mk.get("lanowl_group") or "lanowl-ro"):
            return True
        user, _ = resolve_mikrotik(self.cfg)
        return bool(user) and msg.strip().startswith(f"user {user} changed by ")

    def _on_follow(self, live: bool, why: str):
        """The follow (re)started — everything written while it was down went unseen, so the
        next scan reads the whole buffer again — or it stopped, and scans read it in full
        every time until it is back."""
        self._live = live
        self._resync = True
        self._arrived = []
        c = self._rt().conn
        self._follow_conn = c.serial if (live and c is not None) else 0
        if live and self._wake is not None:
            self._wake.set()          # read the gap now, not at the next minute's scan
        if not live:
            log.info("WAN watcher: router log no longer followed (%s); reading it every %ss",
                     why, self._wcfg().get("log_interval_s", 60))

    def _merged(self) -> list:
        for x in self._arrived:
            i = x.get(".id")
            if not i:
                continue
            if x.get(".dead") == "true":
                self._mirror.pop(i, None)
            elif x.get("message") is not None:
                self._mirror[i] = x
        self._arrived = []
        extra = len(self._mirror) - self._mirror_cap
        if extra > 0:
            for i in list(self._mirror)[:extra]:
                del self._mirror[i]
        return list(self._mirror.values())

    async def _read_log(self) -> Optional[list]:
        """The router's whole log buffer, oldest first, or None if it could not be read.

        Followed: the kept copy plus whatever arrived since — no request at all. Otherwise,
        and once after every (re)subscription, a full read: over the API when it is up, else
        REST. That read becomes the copy only if it came over the very connection carrying
        the follow: the Router issues follows before it lets anyone read on a new
        connection, so such a read cannot predate the stream, and the two meet with no gap
        (the overlap is deduplicated by `.id`). A read over REST, or over an older
        connection, is used for this scan and the next one reads again."""
        if self._live and not self._resync:
            return self._merged()
        r = await self._rt().read("log", timeout_s=15)
        if not r.ok:
            log.warning("WAN watcher: router log fetch failed: %s", r.detail)
            return None
        rows = [x for x in (r.data.get("json") or []) if isinstance(x, dict)]
        if self._live and r.data.get("conn") and r.data.get("conn") == self._follow_conn:
            self._mirror = {x[".id"]: x for x in rows if x.get(".id")}
            self._mirror_cap = max(1000, len(rows))
            self._resync = False
            return self._merged()
        return rows

    # --- ping half ---------------------------------------------------------
    async def _ping_round(self) -> bool:
        """Ping every target concurrently. Returns True if the confirmed state flipped.

        WAN is up if ANY target answers, so a confirmed blackout means all of 8.8.8.8,
        208.67.222.222 and 1.0.0.1 missed together `fail_checks` times in a row — at 15s
        that is ~30s, comfortably inside a 57s outage and still far too strict for one
        unlucky packet to trigger."""
        w = self._wcfg()
        timeout = int(self.cfg.get("probes", {}).get("icmp_timeout_ms", 1500))
        tgts = self._targets()
        t0 = time.time()
        results = await asyncio.gather(
            *(probes.ping(t, timeout_ms=timeout, count=1) for t in tgts),
            return_exceptions=True)
        took = time.time() - t0
        self.targets = {t: (getattr(r, "ok", False) is True) for t, r in zip(tgts, results)}
        up = any(self.targets.values())
        # Where it broke: only in a round where nothing answered, the router and
        # the main link's first hop are asked too — lanowl's own link, the main link, or further
        hops = {} if up else await self._ping_hops(timeout)

        was = self.blackout
        now = time.time()
        if up:
            self._oks += 1
            self._fails = 0
            if self.blackout and self._oks >= int(w.get("ok_checks", 1)):
                self.blackout = False
                # The instant the network had internet again, as observed here: the true
                # moment is somewhere in the `interval_s` since the previous round, so this
                # is accurate to ~15s. `_update_state` prefers the router's own link-up line
                # timestamp over it when the log scan has read one for the same event.
                self._back_at = now
                # Short and never announced: under the `min_outage_s` floor, not worth a
                # page. Not silence — it is counted and reported in the digest (see
                # `blips_24h`), the same way a low-criticality device that switched off is
                # reported once rather than paged. Recorded as a blip only: the state's own
                # 'blackout' event is for the ones that paged (`_last_run_paged`).
                self._last_run_paged = self._blackout_paged
                if not self._blackout_paged and self._fail_since:
                    self._event("blip", now - self._fail_since, "", self._fail_since)
                    self.blips.append((self._fail_since, now))
                    self.blips = [b for b in self.blips if b[1] > now - 86400][-50:]
                    log.info("WAN watcher: %.0fs blip, under the %ss paging floor — counted, "
                             "not paged (%d in 24h)", now - self._fail_since,
                             w.get("min_outage_s", 90), len(self.blips))
                self._close_run(now, "blackout" if self._blackout_paged else "blip")
                self._blackout_paged = False
            elif not self.blackout:
                self._run = None          # one failed round that never became a blackout
            if self._oks:
                self._fail_since = 0.0
        else:
            if not self._fails:
                self._fail_since = now   # the outage began HERE, not at the confirmation
                self._open_run(now)
            self._note_round(now, took, hops)
            self._fails += 1
            self._oks = 0
            if not self.blackout and self._fails >= int(w.get("fail_checks", 2)):
                self.blackout = True
                self._blackout_since = now
        if was != self.blackout:
            log.warning("WAN watcher: %s (%s)",
                        "TOTAL BLACKOUT — no WAN on any target" if self.blackout
                        else "WAN reachable again", self.targets)
        return was != self.blackout

    # --- evidence: where it broke (wanexplain.py reads it) ----------------------
    # Three questions, each answered by something that lasts only minutes:
    #   lanowl's own link?  the router did not answer it either (a hop, pinged here)
    #   the main link?               its first hop, the ISP's DHCP gateway, did not answer
    #   the network at all?        the router's OWN pings (netwatch, every 20 s) failed too —
    #                            its counters, read as the run starts and ~75 s after it ends
    # plus the router's log around it, which it keeps for days, not weeks.
    EV_HEAD, EV_TAIL = 8, 4          # failed rounds kept per run: the first and the last
    EV_SETTLE_S = 75                 # past the end: a netwatch test or three, a log scan

    def _ev_on(self) -> bool:
        return bool(self._wcfg().get("evidence", True))

    def _hops(self) -> dict:
        out = {"router": self._router_ip()}
        if self._isp_gw:
            out["isp"] = self._isp_gw
        return out

    async def _ping_hops(self, timeout: int) -> dict:
        if not self._ev_on():
            return {}
        hops = self._hops()
        res = await asyncio.gather(*(probes.ping(ip, timeout_ms=timeout, count=1)
                                     for ip in hops.values()), return_exceptions=True)
        return {k: getattr(r, "ok", False) is True for k, r in zip(hops, res)}

    def _open_run(self, now: float):
        if not self._ev_on():
            return
        p = self.path or {}
        run = {"start": now, "rounds": [], "tail": [], "n": 0, "hops": self._hops(),
               "path": {"link": p.get("link"), "on_backup": bool(p.get("on_backup"))},
               "nw_before": None, "nw_before_ts": None}
        self._run = run

        async def before():
            # its own task: a router lanowl cannot reach must not hold up the ping clock
            run["nw_before"] = await self._read_netwatch()
            run["nw_before_ts"] = time.time()
        asyncio.ensure_future(before())

    def _note_round(self, now: float, took: float, hops: dict):
        r = self._run
        if r is None:
            return
        r["n"] += 1
        row = {"ts": round(now, 1), "took": round(took, 2), **hops}
        if len(r["rounds"]) < self.EV_HEAD:
            r["rounds"].append(row)
        else:
            r["tail"] = (r["tail"] + [row])[-self.EV_TAIL:]

    def _close_run(self, now: float, kind: str):
        """The run just ended as a blip or a blackout: its evidence is finished once the
        router has had time to show what it saw (`_finish_evidence`)."""
        r, self._run = self._run, None
        if r is None or not self._fail_since:
            return
        w = self._wcfg()
        ev = {"v": 1, "kind": kind, "start": self._fail_since, "end": now,
              "s": round(now - self._fail_since, 1),
              "interval_s": float(w.get("interval_s", 15)),
              "timeout_ms": int(self.cfg.get("probes", {}).get("icmp_timeout_ms", 1500)),
              "floor_s": float(w.get("min_outage_s", 90)),
              "targets": self._targets(), "hops": r["hops"],
              "rounds": r["rounds"] + r["tail"], "rounds_n": r["n"], "path": r["path"]}
        reads = [x for x in self._sb_reads if x["ts"] >= self._fail_since - 180]
        if reads:
            ev["standby"] = {"down_at": self._sb_down_at or None, "reads": reads}
        self._pending_ev.append({"due": now + self.EV_SETTLE_S, "ev": ev, "run": r})

    async def _finish_evidence(self, now: float):
        due = [p for p in self._pending_ev if p["due"] <= now]
        if not due:
            return
        self._pending_ev = [p for p in self._pending_ev if p["due"] > now]
        after = await self._read_netwatch()
        for p in due:
            ev, r = p["ev"], p["run"]
            ev.update(nw_before=r.get("nw_before"), nw_before_ts=r.get("nw_before_ts"),
                      nw_after=after, nw_after_ts=time.time() if after is not None else None)
            raw, ev["log_from"] = self._log_window(ev["start"] - wanexplain.LOG_BEFORE, ev["end"] + 60)
            ev["log"] = wanexplain.pick_log(raw, ev["start"], ev["end"])
            ev["main"] = [{"down": s.timestamp(), "up": e.timestamp()}
                           for s, e in self.outages_from_log()
                           if s.timestamp() <= ev["end"] + 30 and e.timestamp() >= ev["start"] - 90]
            self._event("wan-evidence", ev["s"], json.dumps(ev, ensure_ascii=False), ev["start"])
            log.info("WAN watcher: evidence kept for the %s at %s (%d round(s), router %s)",
                     ev["kind"], _clock(ev["start"]), ev["rounds_n"],
                     "read" if after is not None else "not read")

    def _log_window(self, a: float, b: float) -> tuple:
        """The router's log lines between two instants, and where its buffer begins — a line
        that is not there is only news if the buffer went back that far. All of them: which
        ones tell the story is wanexplain.pick_log's (not the lines nearest the middle — a long
        outage's middle is WireGuard retrying)."""
        rows = [(t, x) for t, x in self.log_rows if a <= t.timestamp() <= b]
        first = self.log_rows[0][0].timestamp() if self.log_rows else None
        return ([{"ts": t.timestamp(), "topics": x.get("topics", ""),
                  "message": (x.get("message") or "")[:200]} for t, x in rows], first)

    async def _read_netwatch(self) -> Optional[dict]:
        """The router's own ping checks (/tool/netwatch): host -> done and failed test counts.
        None when the router could not be read — which during a blackout is evidence too."""
        user, _ = resolve_mikrotik(self.cfg)
        if not user:
            return None
        try:
            r = await asyncio.wait_for(self._rt().read("tool/netwatch", timeout_s=5), 7)
        except Exception:
            return None
        if not r.ok:
            return None
        out = {}
        for x in (r.data or {}).get("json") or []:
            if not isinstance(x, dict) or x.get("disabled") == "true":
                continue
            try:
                done, failed = int(x.get("done-tests")), int(x.get("failed-tests"))
            except (TypeError, ValueError):
                continue
            out[str(x.get("host") or "")] = {
                "done": done, "failed": failed, "status": x.get("status") or "",
                "since": x.get("since") or "", "interval": x.get("interval") or "",
                "comment": x.get("comment") or ""}
        self.netwatch, self._nw_at = out, time.time()
        return out

    async def _router_facts(self, now: float):
        """The main link's first hop (hourly) and the router's ping counters (every 10 min, while
        all is well — an event from before lanowl kept evidence is judged by them)."""
        if not self._ev_on() or not resolve_mikrotik(self.cfg)[0]:
            return
        if now - self._isp_at >= 3600:
            self._isp_at = now
            gw = await self._isp_gateway()
            if gw and gw != self._isp_gw:
                log.info("WAN watcher: the main link's first hop is %s", gw)
                self._isp_gw = gw
        if self._rt().up and self.state == STATE_OK and now - self._nw_at >= 600:
            await self._read_netwatch()

    async def _isp_gateway(self) -> str:
        """The gateway of the main link's DHCP client: `wan.watch.isp_dhcp_client` by name,
        else the one named after the main link (`wan.path.main`), else the only one bound."""
        try:
            r = await self._rt().read("ip/dhcp-client", timeout_s=10)
        except Exception:
            return ""
        if not r.ok:
            return ""
        rows = [x for x in (r.data or {}).get("json") or []
                if isinstance(x, dict) and x.get("status") == "bound" and x.get("gateway")]
        want = str(self._wcfg().get("isp_dhcp_client") or "").lower()
        main = str(self._pcfg().get("main") or "").lower()
        for pick in ((lambda x: want and want in (x.get("name", "") + x.get("interface", "")).lower()),
                     (lambda x: main and main in (x.get("name", "") + x.get("interface", "")).lower()),
                     (lambda x: len(rows) == 1)):
            hit = next((x for x in rows if pick(x)), None)
            if hit is not None:
                return str(hit["gateway"])
        return ""

    # --- the backup link, while the main link is down ---------------------------------------------
    def _acfg(self) -> dict:
        return ((self.cfg.get("wan", {}) or {}).get("standby") or {})

    def _main_down_since(self) -> float:
        """When the router took the main link out — its log's link-down line not yet followed by `UP`,
        or the default route on the backup — 0 while it has the main link."""
        if self._pending_down is not None:
            t = self._pending_down.timestamp()
            # a link-up line the scan never saw must not keep the backup link read for ever: ten
            # minutes on, a fresh route on the main link says the router has it back
            if not (time.time() - t > 600 and self.path_is_fresh(time.time(), 120)
                    and not (self.path or {}).get("on_backup")):
                return t
        if (self.path or {}).get("on_backup"):
            return self._sb_down_at or time.time()
        return 0.0

    def _standby_tick(self, now: float):
        """Read the backup link every `every_s` while the main link is down; never while it is up."""
        c = self._acfg()
        if not c.get("ip"):
            return
        down = self._main_down_since()
        if not down:
            if self._sb_down_at:
                self._sb_last = {"down_at": self._sb_down_at, "up_at": now, "reads": self._sb_reads}
                if self._sb_reads:
                    self._event("wan-standby", now - self._sb_down_at,
                                json.dumps(self._sb_last, ensure_ascii=False), self._sb_down_at)
                self._sb_down_at, self._sb_reads = 0.0, []
            return
        if not self._sb_down_at:
            self._sb_down_at, self._sb_reads, self._sb_at = down, [], 0.0
            log.warning("WAN watcher: the router took the main link out at %s — reading the backup link", _clock(down))
        if (self._sb_task is None or self._sb_task.done()) and now - self._sb_at >= float(c.get("every_s", 30)):
            self._sb_at = now
            self._sb_task = asyncio.ensure_future(self._standby_read())

    async def _standby_read(self):
        """One read-only look: is its Wi-Fi on, connected to the provider (and how strong), and
        does the internet come through it. Its own task — an ssh login must not hold the pings."""
        c = self._acfg()
        ip, iface = str(c["ip"]), str(c.get("iface") or "wlan1")
        r = {"ts": round(time.time(), 1), "on": None, "link": None, "signal": None, "net": None, "err": ""}
        try:
            if self._access is None:
                from .access import Access
                self._access = Access(self.cfg)
            rc, out, err = await self._access.ssh(ip, f"/interface print terse where name={iface}",
                                                  user_suffix="+ct", timeout_s=15)
            r["on"] = interface_on(out, iface) if rc == 0 else None
            if r["on"] is None:
                r["err"] = " ".join(((err or out or "") if rc is not None else (err or "no answer")).split())[:120] \
                    or "no answer"
            elif r["on"]:
                rc, out, _ = await self._access.ssh(ip, "/interface wireless registration-table print terse",
                                                    user_suffix="+ct", timeout_s=15)
                if rc == 0:
                    sig = registration(out, iface)
                    r["link"] = sig is not False
                    r["signal"] = sig if isinstance(sig, int) else None
                res = await probes.ping(str(c.get("probe") or "1.1.1.1"), timeout_ms=1500, count=2)
                r["net"] = getattr(res, "ok", False) is True
        except Exception as e:
            r["err"] = f"{type(e).__name__}: {e}"[:120]
        self.standby = r
        if self._sb_down_at:
            self._sb_reads = (self._sb_reads + [r])[-240:]
        log.info("WAN watcher: backup link %s", "unread (" + r["err"] + ")" if r["on"] is None else
                 "Wi-Fi off" if not r["on"] else
                 f"Wi-Fi on, {'connected' if r['link'] else 'not connected' if r['link'] is False else 'link unknown'}"
                 + (f" {r['signal']} dBm" if r["signal"] is not None else "")
                 + f", internet through it: {'yes' if r['net'] else 'no'}")

    def standby_now(self, now: Optional[float] = None) -> Optional[dict]:
        """What the standby link is doing in this main-link outage, in words — or what it did
        in the last one. None when there is nothing definite to say."""
        grace = float(self._acfg().get("grace_s", wanexplain.STANDBY_GRACE_S))
        L = wan_links(self.cfg)
        if self._sb_down_at:
            return wanexplain.standby_story(self._sb_reads, self._sb_down_at, grace, links=L)
        if self._sb_last:
            return wanexplain.standby_story(self._sb_last["reads"], self._sb_last["down_at"], grace, links=L)
        return None

    def _standby_trouble(self) -> str:
        """The standby link failing in THIS main-link outage, in one sentence — "" when it is
        not (yet)."""
        if not self._sb_down_at:
            return ""
        st = self.standby_now()
        return st["line"] if st and st["where"] in wanexplain.STANDBY_TROUBLE else ""

    # --- router-log half ---------------------------------------------------
    def _edge_patterns(self) -> tuple:
        """The failover script's log lines for the main link going down and up
        (`wan.watch.log_down_match` / `log_up_match`). ("", "") = not configured: the log is
        still read (triage, the model's tools), but no link edges come from it."""
        w = self._wcfg()
        d, u = str(w.get("log_down_match") or ""), str(w.get("log_up_match") or "")
        return (d, u) if d and u else ("", "")

    async def _scan_log(self, prime: bool = False):
        """Read the router's log and turn link down/up lines into completed Flaps.

        This is the only detector that sees a failover which starts and finishes between
        two polls: the lines stay in the router's buffer, so a 60s scan cannot miss a 57s
        event the way a 300s route poll does."""
        self._last_log_scan = time.time()
        user, _ = resolve_mikrotik(self.cfg)
        if not user:
            return
        rows = await self._read_log()
        if not rows:
            return

        down_pat, up_pat = self._edge_patterns()

        # newest fully-qualified stamp anchors any bare HH:MM:SS entries
        ref = None
        for x in reversed(rows):
            ref = _parse_log_time(x.get("time", ""))
            if ref:
                break

        # timestamp every row once, then work off that
        stamped = []
        for x in rows:
            t = _parse_log_time(x.get("time", ""), ref)
            if t:
                stamped.append((t, x))
        stamped.sort(key=lambda p: p[0])
        own = self._own_logins()                             # our own REST logins only
        self.log_rows = [(t, x) for t, x in stamped
                         if not any(p in (x.get("message") or "") for p in own)]

        edges = []
        for t, x in (stamped if down_pat else []):
            msg = x.get("message", "") or ""
            kind = "down" if down_pat in msg else ("up" if up_pat in msg else None)
            if kind:
                edges.append((t, kind))

        if prime or self._watermark is None:
            # Adopt the router's own newest timestamp as the starting line. Using this
            # machine's clock instead would replay or skip events whenever the two drift.
            self._watermark = ref or (edges[-1][0] if edges else None)
            self._triage_mark = self._watermark
            if edges and edges[-1][1] == "down":
                self._pending_down = edges[-1][0]   # we started up while it was already down
            log.info("WAN watcher: log watermark set to %s (%d historic edge(s) skipped)",
                     self._watermark, len(edges))
            return

        fresh = [e for e in edges if e[0] > self._watermark]
        for t, kind in fresh:
            if kind == "down":
                self._pending_down = t
            elif self._pending_down is not None:
                self._record_flap(Flap(self._pending_down, t))
                self._pending_down = None

        # Everything else new in the buffer: hand the odd-looking lines to the model.
        # Deliberately its own watermark — triage can decline to run (model busy, cooldown)
        # and those lines must still be waiting at the next scan, whereas the flap watermark
        # below has to advance or the same outage is recorded twice.
        self._consider_triage(stamped)

        if ref and (self._watermark is None or ref > self._watermark):
            self._watermark = ref
        elif fresh:
            self._watermark = fresh[-1][0]

    # --- router-log triage (LLM) -------------------------------------------
    @staticmethod
    def _shape(msg: str) -> str:
        """Message identity with the variable parts removed.

        'login failure for user admin from 10.8.0.5' and the same line from another IP are
        one recurring condition, not two findings — otherwise a brute-force attempt would
        page once per attempt, which is precisely the per-edge spam the alert gate exists
        to prevent."""
        return _DIGITS.sub("#", msg)[:120]

    def _consider_triage(self, stamped: list):
        """Filter the routine hum, then ask the model about what is left (rate-limited).

        `stamped` is every (timestamp, row) in the buffer; the triage watermark decides what
        counts as new. It only moves when a triage actually starts, so lines skipped because
        the model was busy are picked up on a later scan instead of being dropped."""
        if self.agent is None or not stamped:
            return
        if self.model_on is not None and not self.model_on():
            # switched off (Auditor.set_model): back on, it adopts the buffer as it is then
            # rather than replaying the hours it was off
            self._triage_mark = None
            return
        t = self._tcfg()
        if not t.get("enabled", True):
            return
        if self._triage_mark is None:            # first scan: adopt, don't replay the buffer
            self._triage_mark = stamped[-1][0]
            return
        fresh_rows = [x for ts, x in stamped if ts > self._triage_mark]
        if not fresh_rows:
            return
        if self._triage_task is not None and not self._triage_task.done():
            return                                   # one in flight is enough
        if (time.time() - self._last_triage) < float(t.get("cooldown_s", 900)):
            return
        if self.llm_busy is not None and self.llm_busy():
            # The hourly audit has the model. Don't queue behind it — the lines stay in the
            # router's buffer and `_watermark` has not moved, so the next scan re-offers them.
            log.debug("router-log triage deferred: an LLM audit is running")
            return

        # Past every reason to defer: from here the batch is consumed either way, so the
        # watermark moves even if every line turns out to be boring.
        self._triage_mark = stamped[-1][0]

        routine = self._routine_patterns()
        mk = self.cfg.get("mikrotik") or {}
        grp = str(mk.get("lanowl_group") or "lanowl-ro")
        pol = mk.get("lanowl_policy") or ["read", "test", "sniff", "api", "rest-api"]
        interesting = []
        for x in fresh_rows:
            msg = (x.get("message") or "").strip()
            if not msg or any(p in msg for p in routine) or owner_granted(msg, grp, pol):
                continue
            shape = self._shape(msg)
            if shape in self._seen_shapes:
                continue                             # this condition already had its say
            interesting.append((shape, x))
        if not interesting:
            return

        cap = int(t.get("max_lines", 40))
        batch = interesting[-cap:]
        for shape, _ in batch:
            self._seen_shapes.add(shape)
        if len(self._seen_shapes) > 500:             # keep the memo bounded
            self._seen_shapes = set(list(self._seen_shapes)[-250:])

        now = time.time()
        self._last_triage = now
        lines = "\n".join(f"{x.get('time','')}  [{x.get('topics','')}]  {x.get('message','')}"
                          for _, x in batch)
        wan = self._wan_context(now)
        log.info("router-log triage: %d new line(s) -> LLM%s", len(batch),
                 " (with WAN context)" if wan else "")
        # Fire and forget: the model must never hold up the ping clock.
        self._triage_task = asyncio.ensure_future(self._run_triage(lines, len(batch), wan))

    def _tcfg(self) -> dict:
        return (self._wcfg().get("log_triage") or {})

    def _routine_patterns(self) -> tuple:
        """_ROUTINE, the configured failover lines, and lanowl's own logins."""
        w = (self.cfg.get("wan") or {}).get("watch") or {}
        lines = tuple(str(x) for x in ([w.get("log_down_match"), w.get("log_up_match")]
                                        + list(w.get("routine") or [])) if x)
        return _ROUTINE + lines + self._own_logins()

    def _own_logins(self) -> tuple:
        """lanowl's own REST logins (and the update check's ssh ones).

        Our own reads are the single loudest thing in the buffer and carry no information —
        but they must be excluded by *username*, not by the word 'login', so that somebody
        else logging in is still surfaced."""
        user, _ = resolve_mikrotik(self.cfg)
        extra = (f"user {user} logged in", f"user {user} logged out") if user else ()
        # The update check's daily look at the router (updates.py) logs in with the
        # owner's own login over ssh — excluded for exactly that user, from exactly this
        # machine, over ssh: the same login from anywhere else still reaches the model.
        me = str((self.cfg.get("observer") or {}).get("host_ip") or "")
        if me:
            if self._access is None:
                from .access import Access
                self._access = Access(self.cfg)
            for h in (self.cfg.get("updates") or {}).get("hosts") or []:
                lg = self._access.login(str(h.get("ip"))) if h.get("via") == "routeros" else None
                if lg is not None:
                    extra += (f"user {lg.user} logged in from {me} via ssh",
                              f"user {lg.user} logged out from {me} via ssh")
        return extra

    def _wan_context(self, now: float) -> str:
        """What the WAN was doing, for the triage prompt. "" when nothing was wrong.

        Without this the model is handed router log lines with no idea the network had no
        internet, and every internet-dependent thing that failed during the outage reads
        as an independent problem: WireGuard failing its handshakes in the middle of a
        45-minute blackout gets reported as a tunnel fault to go and investigate, queued in
        the outbox behind the outage that caused it.

        This is the same lesson as `report.observer_failure`: one root cause fans out into
        a screenful of symptoms, and the honest report names the cause once. The model
        cannot spot that from the lines alone, because the fact that explains them is not
        IN the lines — the router keeps working perfectly while its uplink is dead."""
        bits = []
        if self.state == STATE_DOWN:
            since = self._down_since or self._fail_since or now
            bits.append(f"The network has had NO internet at all since {_clock(since)} "
                        f"({human_duration(now - since)} ago) and it is STILL down right now.")
        elif self._last_down_at and self._back_at and (now - self._back_at) <= 7200:
            bits.append(f"The network had NO internet at all from {_clock(self._last_down_at)} "
                        f"to {_clock(self._back_at)}. It is working again now.")
        L = wan_links(self.cfg)
        if self.state == STATE_BACKUP:
            link = (self.path or {}).get("link") or L["backup"]
            bits.append(f"The {L['main']} is down; the internet is running on the backup link "
                        f"'{link}'.")
        if not bits and self.flap_count_24h():
            bits.append(f"The {L['main']} has dropped {self.flap_count_24h()} time(s) in the "
                        f"last 24h, briefly each time.")
        return " ".join(bits)

    async def _run_triage(self, lines: str, n: int, wan: str = ""):
        t = self._tcfg()
        # The note goes FIRST: it is the lens the lines have to be read through, and a
        # model that meets the evidence before the context tends to have made up its mind.
        prefix = f"WHAT WAS HAPPENING ON THE INTERNET CONNECTION: {wan}\n\n" if wan else ""
        try:
            verdict = await self.agent.ask_json(
                TRIAGE_SYSTEM,
                f"{prefix}Router log lines that are not part of normal background chatter "
                f"({n} line(s)):\n\n{lines}",
                timeout_s=float(t.get("timeout_s", 90)))
        except Exception as e:
            log.warning("router-log triage failed: %s", e)
            return
        if not verdict:
            log.info("router-log triage: no usable verdict")
            return
        self._note_finding(verdict, n, lines)
        if not verdict.get("problem"):
            log.info("router-log triage: nothing worth reporting (%s)",
                     str(verdict.get("summary", ""))[:80])
            return

        sev = str(verdict.get("severity", "warning")).lower()
        summary = str(verdict.get("summary", "")).strip() or "unusual router log activity"
        detail = str(verdict.get("detail", "")).strip()
        log.warning("router-log triage: %s — %s", sev.upper(), summary)
        notify = sev in (t.get("notify_severities") or ["critical", "warning"])
        if (self.seclog is not None and verdict_kind(verdict, "health") == "security"
                and sev in ("critical", "warning")):
            self.seclog.add(source="router log", ip=self._router_ip(), sev=sev, title=summary,
                            detail=detail, by="model", paged=notify)
        if not notify:
            return                                   # logged and on the dashboard, but quiet
        emoji = {"critical": "🔴", "warning": "🟡"}.get(sev, "⚪")
        when = time.strftime("%H:%M:%S")
        self.on_alert(f"{emoji} <b>ROUTER LOG</b> {when}\n{summary}"
                      + (f"\n<i>{detail}</i>" if detail else "")
                      + f"\n<i>from {n} new log line(s)</i>")

    def _note_finding(self, verdict: dict, n: int, lines: str = ""):
        from .records import kept_lines
        f = {"ts": time.time(), "source": "router log", "lines": n,
             "problem": bool(verdict.get("problem")),
             "kind": verdict_kind(verdict, "health"),
             "severity": str(verdict.get("severity", "info")).lower(),
             "summary": str(verdict.get("summary", ""))[:200],
             # whole: cut at 300 it loses its last sentence on the dashboard
             "detail": str(verdict.get("detail", ""))[:1500],
             # what it read, word for word: a verdict of "fine" can be checked against it
             "log": kept_lines(lines)}
        self.findings = (self.findings + [f])[-30:]
        self._event("finding", None, json.dumps(f, ensure_ascii=False))

    def _router_ip(self) -> str:
        from urllib.parse import urlparse
        return router_host(self.cfg)

    def _event(self, kind: str, value: Optional[float] = None, detail: str = "",
               ts: Optional[float] = None):
        if self.on_event is None:
            return
        try:
            self.on_event(kind, value, detail, ts)
        except Exception as e:      # history must never stop the watcher
            log.debug("event %s not recorded: %s", kind, e)

    def router_log(self, search: str = "", since_ts: float = 0.0, limit: int = 30) -> list:
        """Lines of the router's log containing `search` (case-insensitive), newest first.

        Read from the copy the last scan kept — no extra REST call, so the model can ask as
        often as it likes. Several terms separated by '|' match any of them."""
        terms = [s.strip().lower() for s in (search or "").split("|") if s.strip()]
        out = []
        for t, x in reversed(self.log_rows):
            if since_ts and t.timestamp() < since_ts:
                break
            msg = x.get("message") or ""
            if terms and not any(s in msg.lower() for s in terms):
                continue
            out.append({"time": t.strftime("%Y-%m-%d %H:%M:%S"),
                        "topics": x.get("topics", ""), "message": msg[:200]})
            if len(out) >= limit:
                break
        return out

    def outages_from_log(self) -> list:
        """Every completed main-link outage the router's buffer still remembers: [(start, end)].

        A 10,000-line buffer holds about a week and a half, a far longer memory than `flaps`
        (24h, and only since this process started). Read, not stored: the weekly review and
        the owner's questions get it for free. [] without the failover's log lines configured."""
        down_pat, up_pat = self._edge_patterns()
        if not down_pat:
            return []
        out, pending = [], None
        for t, x in self.log_rows:
            msg = x.get("message", "") or ""
            if down_pat in msg:
                pending = pending or t
            elif up_pat in msg and pending is not None:
                out.append((pending, t))
                pending = None
        return out

    def _record_flap(self, f: Flap):
        """A completed main-link outage, read back from the router's own log.

        Every completed outage is COUNTED here, however long: `self.flaps` is the record of
        "how often did the line drop today" and `_ep_outage_s` is "how long was it actually
        broken during this incident", and both of those are wrong if entries go missing.

        What a *sustained* failover does not get is the 60s hold below. Its link-up line only
        reaches the log after the line is already back, while the route poll has been holding
        the incident open for the whole outage — re-raising it here would reopen an episode
        that just closed and page about a problem that is over. Anything at or above the
        route-poll interval is long enough that the poll cannot have missed it; the short
        ones it structurally cannot see are what this detector is for.

        Skipping the accounting along with the hold would report "RECOVERED (down 237s)" for
        an episode the router timed at 237s + 1197s: a 24-minute outage reaching the phone as
        a 4-minute one, because the 1197s half was dropped on the way out of this function."""
        path_interval = float(((self.cfg.get("wan", {}) or {}).get("path") or {})
                              .get("interval_s", 300))
        now = time.time()
        sustained = f.seconds >= path_interval

        self._ep_outage_s += f.seconds
        self._ep_outages += 1
        # The router's own second for "the internet came back", which beats anything this
        # process can observe: the ping loop only knows it happened inside the last 15s, and
        # the route poll inside the last minute. Set before the `sustained` return below —
        # a long outage ends at a precise instant too, and that is the instant the recovery
        # message has to quote.
        self._restored_at = f.end.timestamp()
        self._event("main-outage", f.seconds, "", f.start.timestamp())
        self.flaps.append(f)
        cutoff = now - 86400
        self.flaps = [x for x in self.flaps
                      if x.end.timestamp() > cutoff or x is f][-50:]

        if sustained:
            log.info("WAN watcher: %.0fs outage at %s counted; holding it open is the "
                     "wan.path poll's job", f.seconds, f.start)
            return
        # Only a short flap turns into a held 'level' for the gate — and only a short flap
        # is narrated, so the message can never describe a long outage the poll already owns.
        self._last_flap = f
        self._last_flap_at = now
        log.warning("WAN watcher: main link flapped %s -> %s (%.0fs, %d in 24h)",
                    f.start.strftime("%H:%M:%S"), f.end.strftime("%H:%M:%S"),
                    f.seconds, self.flap_count_24h())

    def flap_count_24h(self) -> int:
        cutoff = datetime.datetime.now() - datetime.timedelta(days=1)
        return sum(1 for f in self.flaps if f.end >= cutoff)

    def blip_count_24h(self) -> int:
        """Blackouts too short to page, in the last 24h. Reported in the digest."""
        cutoff = time.time() - 86400
        return sum(1 for _, end in self.blips if end >= cutoff)

    def open_keys(self) -> list:
        """Incident keys this watcher currently holds open (for the outbox staleness check)."""
        return self._gate.open_keys() if self._gate else []

    # --- alerting ----------------------------------------------------------
    def set_path(self, wp: Optional[dict]):
        """Called after each `wan.path` route poll: the sweep's, or `_poll_path`'s.

        Its reporting lives here, so that the level it observes and the edges this module
        reads out of the router log end up in one gate under one key. That is the whole fix for the
        double-paged failover: two detectors, two clocks, but one incident."""
        if wp is not None:
            was = (self.path or {}).get("on_backup")
            if wp.get("on_backup") and not was:
                log.warning("WAN path: on BACKUP link '%s' (%s)", wp.get("link"), wp.get("detail"))
            elif was and not wp.get("on_backup"):
                log.info("WAN path: back on main link '%s'", wp.get("link"))
            self.path = wp
            self._path_at = time.time()

    def _blackout_is_pageable(self, now: float) -> bool:
        """Has this blackout lasted long enough to be worth a human's attention?

        A backup link typically takes over a minute or so into a main-link drop, and a single
        line often blips for under a minute, so the shortest total blackouts are events nobody
        on the network notices — and paging for them is worse than useless, because the
        message arrives after the internet is already back: a 44 s blackout pages, the alert
        sits in the outbox (no internet, so nothing can be sent), and it is delivered seconds
        AFTER the line recovered.

        So the floor is on the ping detector only. A drop the router itself attributes to
        the main link still raises the incident through the route poll or the log scan at their
        own severity, however short it was: that one has evidence behind it, whereas a bare
        ping blackout with nothing corroborating it is most often a blip."""
        floor = float(self._wcfg().get("min_outage_s", 90))
        if floor <= 0:
            return True
        started = self._fail_since or self._blackout_since or now
        return (now - started) >= floor

    # --- the three-state view ----------------------------------------------
    def _current_state(self) -> str:
        """ok | backup | down, from what is true at this instant.

        Only the two *level* detectors get a vote. A completed flap the log scan recovered
        is history by the time it is read — the line is already back — so it holds the
        incident open (see `flap_hold_s` below) without colouring the box yellow for a
        minute after everything is fine again. The box answers "how is my internet right
        now", and nothing else."""
        if self.blackout:
            return STATE_DOWN
        if (self.path or {}).get("on_backup"):
            return STATE_BACKUP
        return STATE_OK

    def _router_back_time(self, now: float) -> float:
        """The router's own timestamp for the end of the outage that just finished.

        Better than our own observation when we have it: the log line is written by the
        box doing the failover, to the second, while the ping loop only knows the outage
        ended somewhere inside the last 15s. Ignored when the newest flap is too old to be
        the event we are closing."""
        if not self.flaps:
            return 0.0
        ts = self.flaps[-1].end.timestamp()
        return ts if 0 <= (now - ts) <= 900 else 0.0

    def _update_state(self, now: float):
        """Recompute the state and remember WHEN each transition happened.

        The timestamps are the point. Everything raised while the state is `down` has no
        way out of the network and is delivered late — by the outbox, minutes afterwards —
        and a recovery waits out `recovery_confirm_s` (15 min) before it is believed. So
        the messages cannot lean on "now": each one carries the wall-clock instant the
        thing it describes actually happened."""
        st = self._current_state()
        if st == self.state:
            return
        prev, self.state, self.state_since = self.state, st, now

        if st == STATE_DOWN:
            # `_fail_since` is the first FAILED round, i.e. when the internet actually
            # stopped working — not the confirmation two rounds later.
            self._down_since = self._fail_since or now
            self._ep_blackouts += 1
        elif prev == STATE_DOWN:
            back = self._router_back_time(now) or self._back_at or now
            self._back_at = back
            if self._down_since:
                self._ep_blackout_s += max(0.0, back - self._down_since)
                self._last_down_at = self._down_since
                # a blip under the paging floor is recorded as a 'blip' by the ping loop,
                # never also as a blackout
                if self._last_run_paged:
                    self._event("blackout", max(0.0, back - self._down_since), "",
                                self._down_since)
            self._down_since = 0.0
        if st == STATE_BACKUP and not self._backup_since:
            self._backup_since = now
        if st == STATE_OK:
            self._restored_at = self._router_back_time(now) or now

        log.warning("WAN state: %s -> %s (%s)", prev.upper(), st.upper(),
                    _clock(self.state_since))

    def _state_messages(self, now: float, alerted: bool):
        """The messages the `down` state earns that the incident gate cannot give.

        The gate speaks in incidents — one alert when the internet stops being right, one
        recovery when it is right again — and that is still the spine. But an incident that
        passed through a total blackout has THREE moments a person actually wants, and the
        gate can only give the first and the last:

            the internet stopped working entirely      -> 🔴 NO INTERNET AT ALL
            it works again, whatever link it is on     -> 🟢 INTERNET IS BACK
            ...and it is back on the proper line       -> 🟢 BACK ON THE MAIN LINK

        Each is sent as it happens, not batched. The middle one is the one you want at the
        instant it is true — 45 minutes into a blackout, "it works again, over the backup"
        is the message worth having, even though the incident is nowhere near over. And
        because that message is honest about running on the backup, the return to the main
        link half a minute later is separate news rather than a correction. (With one
        internet line there is no third message.)

        All three are once per incident, which is what keeps a flapping line to one page:
        the second blackout of the same episode is counted, not announced. The last two are
        only sent if the blackout was announced — the trigger is "was the user told?",
        never "how bad was it?" — so a clean failover nobody felt still costs two messages
        in total, the incident alert and its recovery."""
        if not self._wcfg().get("state_messages", True):
            return
        if self.state == STATE_DOWN:
            if self._ep_blackout_told or not self._blackout_is_pageable(now):
                return
            if not alerted and self._gate.silenced(WAN_KEY, now):
                # The gate is inside the quiet window it opened for this same incident.
                # Speaking here would be a cooldown that is not a cooldown; the blackout is
                # still counted, and reported when the incident finally closes. If it is
                # still down when the window ends, the gate's own STILL CRITICAL says so.
                return
            # The incident alert that left on this very tick already opens with "no
            # internet at all" — saying it twice in two seconds is not clearer.
            self._ep_blackout_told = True
            if alerted:
                return
            since = self._down_since or self._fail_since or now
            why = self._standby_trouble()
            L = wan_links(self.cfg)
            self.on_alert(
                f"🔴 <b>NO INTERNET AT ALL</b> {_clock(since)}\n"
                + (f"Nothing answers — not the {L['main']}, not the {L['backup']}.\n"
                   if L["failover"] else "Nothing answers.\n")
                + (f"{_html(why)}\n" if why else "") +
                f"<i>no reply from {', '.join(self._targets())} since {_clock(since)}"
                f" ({human_duration(now - since)} ago)</i>", WAN_KEY)
            return

        # 2) the internet works again — sent on the edge, over whatever link carries it.
        #
        # Deliberately NOT held back until the link settles. The first version of this
        # could wait for the route to name the final link in one message, which reads tidier
        # and is the wrong trade: after 45 minutes of nothing, "it works again" is worth
        # having the second it is true. Naming the backup here is not a lie that needs
        # correcting later — it is what is true now, and the return to the main link is
        # separate news below.
        if self._ep_blackout_told and not self._ep_back_told:
            self._ep_back_told = True
            back = self._back_at or now
            down_for = human_duration(self._ep_blackout_s or max(0.0, back - self._last_down_at))
            # This message says only what the PING loop knows — that the network has working
            # internet again, as of this second. It deliberately does not name the link.
            #
            # The route poll runs on the sweep's clock, so at this instant its answer is
            # normally from before the recovery: the router logs the main link up, the pings
            # recover seven seconds later, and the route poll catches up half a minute after
            # that. Sent off the older answer, this message would say "the main link is still
            # down" about a line that has been carrying traffic for seconds. The link is the
            # next message's job, and that message always comes — the incident cannot close
            # while the network is on the backup, so "when the main link is back" is a
            # promise the code keeps.
            L = wan_links(self.cfg)
            p = self.path or {}
            if p.get("link") and not p.get("on_backup") and self._path_at >= back:
                # ...unless the route already answered AFTER the recovery and said main.
                # Then there is no second edge coming and this is also that message.
                self._ep_main_told = True
                where = f"\n<i>back on the main link '{p['link']}'</i>"
            elif L["failover"]:
                where = f"\n<i>you will be told when the {L['main']} is carrying it again</i>"
            else:
                where = ""
            # what the standby link did meanwhile, while the main one was down
            st = self.standby_now(now)
            self.on_alert(
                f"🟢 <b>INTERNET IS BACK</b> {_clock(back)}\n"
                f"Back at {_clock(back)}, after {down_for} with no internet at all"
                + (f" (since {_clock(self._last_down_at)})." if self._last_down_at else ".")
                + (f"\n{_html(st['line'])}" if st else "")
                + where, WAN_KEY)
            return

        # 3) ...and the main link is carrying the network again (failover only).
        #
        # Only for an incident that went dark: after a clean failover the user never lost
        # internet, so the return to the main link is not urgent and the incident's own
        # recovery (with the totals on it) says so a quarter of an hour later. But when they
        # have been told the network had NOTHING, they have been waiting, and the promise
        # made in the message above has to be kept at the moment it comes true — not fifteen
        # minutes after.
        # `self.path` must actually say so. With no route answer at all the state is `ok`
        # merely because nothing contradicts it — that is enough to colour the box green,
        # and nowhere near enough to tell someone their main link is carrying traffic again.
        p = self.path or {}
        if (self.state == STATE_OK and p.get("link") and not p.get("on_backup")
                and self._ep_blackout_told and self._ep_back_told
                and not self._ep_main_told):
            self._ep_main_told = True
            at = self._restored_at or self.state_since or now
            link = p["link"]
            on_backup_for = (f", after {human_duration(at - self._backup_since)} on the backup"
                             if self._backup_since and at > self._backup_since else "")
            self.on_alert(
                f"🟢 <b>BACK ON THE MAIN LINK</b> {_clock(at)}\n"
                f"'{link}' is carrying the network again as of {_clock(at)}{on_backup_for}.",
                WAN_KEY)

    def _pcfg(self) -> dict:
        return ((self.cfg.get("wan", {}) or {}).get("path") or {})

    def _wan_issue(self, now: float) -> Optional[dict]:
        """The single 'the internet is not right' issue, or None when it is fine.

        One issue, three detectors. Present while any of them says so: no ping reply at all
        (past the floor above), the route poll reporting the backup link, or `flap_hold_s`
        after a completed flap the log scan recovered — that hold is what turns an edge that
        is already over into something a level-based gate can hold an episode open with.

        They contribute clauses to one detail rather than competing issues, so the user gets
        "the internet went away, and here is everything known about why" instead of two
        near-simultaneous pages under two different device names."""
        w = self._wcfg()
        pcfg = self._pcfg()
        p = self.path or {}
        on_backup = bool(p.get("on_backup"))
        hold = float(w.get("flap_hold_s", 60))
        fresh_flap = bool(self._last_flap_at and (now - self._last_flap_at) <= hold
                          and self._last_flap)
        blackout = self.blackout and self._blackout_is_pageable(now)
        if blackout:
            self._blackout_paged = True    # this one earned its page; it is not a blip

        if not (blackout or on_backup or fresh_flap):
            return None
        if on_backup or fresh_flap:
            self._ep_link_trouble = True   # this incident is not only about the pings

        rank = {"critical": 3, "high": 2, "warning": 1, "info": 0}
        sevs, parts = [], []
        if blackout:
            # The strongest statement available: not "a link changed", but "there is no
            # internet in this house right now". Always critical — nothing else it could be.
            # It leads with the instant it started because this is the one alert that
            # CANNOT be delivered while it is true: it goes to the outbox and is read
            # minutes later, often after the line is already back.
            since = self._down_since or self._fail_since or now
            sevs.append("critical")
            parts.append(f"NO INTERNET AT ALL since {_clock(since)} — no reply from "
                         f"{', '.join(self._targets())}")
            why = self._standby_trouble()
            if why:
                parts.append(why)
        if on_backup:
            sevs.append(str(pcfg.get("severity", "critical")))
            parts.append(f"running on the BACKUP link "
                         f"'{p.get('link') or pcfg.get('backup', 'backup')}'"
                         + (f" — {p['detail']}" if p.get("detail") else ""))
        elif fresh_flap:
            f = self._last_flap
            sevs.append(str(w.get("flap_severity", "critical")))
            parts.append(f"main link dropped to the backup for {f.seconds:.0f}s "
                         f"at {f.start.strftime('%H:%M:%S')} "
                         f"({self.flap_count_24h()} time(s) in the last 24h)")

        issue = {
            "device": "Internet / WAN", "ip": "-", "group": "wan",
            # The recovery wording follows the LAST thing that was true: a failover that
            # ends with the route back on main link reads "back on the MAIN link", while a bare
            # blackout that simply stops reads "is back online".
            "kind": "wan-link" if (on_backup or fresh_flap) else "wan",
            "severity": max(sevs, key=lambda s: rank.get(s, 0)),
            "detail": "\n".join(parts),
        }

        # Downtime as the ROUTER measured it, for the recovery message. The episode's own
        # elapsed time is not that number: a completed flap is held 'present' for
        # flap_hold_s after it has already ended, which is why recoveries used to claim
        # "down 60s" and "down 75s" for outages the router timed at 57s. When no log pair
        # was ever read, there is no measurement and the episode's elapsed time — which for
        # a level-based incident IS the real downtime — stands instead.
        if self._ep_outages:
            issue["outage_s"] = self._ep_outage_s
            issue["outages"] = self._ep_outages
        return issue

    def _emit(self):
        """Feed the gate a level view and send whatever it lets through.

        The gate thinks in levels ("this issue is present now"), but a flap is an edge that
        is already over by the time we read it. `flap_hold_s` turns the edge back into a
        short level: the issue is 'present' for a moment after each flap, so a line that
        keeps dropping holds one episode open across all of them and pages once, while
        `recovery_confirm_s` of genuine quiet is what finally closes it."""
        from .report import format_alerts

        now = time.time()
        current = {}

        # Level first: the box on the dashboard is coloured by this, and the transition
        # timestamps it records are what every message below quotes.
        self._update_state(now)

        issue = self._wan_issue(now)
        if issue:
            current[WAN_KEY] = issue

        events = self._gate.update(current, now=now)
        redundant = []   # recoveries whose news has already been sent, in better words

        # The gate keeps the freshest issue dict it was HANDED, which is a snapshot from the
        # last tick on which the incident was still present. Anything the log scan recovers
        # after that — and the link-up line for the final outage necessarily arrives after it —
        # is not in that snapshot. So the closing numbers are taken from the live accumulator
        # instead, which has been counting for the whole episode.
        for e in events:
            if e.kind != RECOVERED or e.episode.key != WAN_KEY:
                continue
            # How long it was broken, from the best evidence this episode produced:
            #   router log   the main link's own DOWN/UP pairs — always the best number;
            #   blackout     nothing in the log, and the incident never involved the link:
            #                then the incident WAS the blackout and its length is the
            #                downtime. The episode's elapsed time is not — the gate only
            #                starts counting at `min_outage_s`, which reported a 200s
            #                outage as "down 1m";
            #   neither      leave it to the episode's elapsed time, which for a level-based
            #                incident (an hour on the backup link) IS the downtime.
            blackout_only = bool(self._ep_blackouts and not self._ep_link_trouble)
            if self._ep_outages:
                e.issue["outage_s"], e.issue["outages"] = self._ep_outage_s, self._ep_outages
            elif blackout_only:
                e.issue["outage_s"], e.issue["outages"] = self._ep_blackout_s, self._ep_blackouts
            # Being on the backup link and having nothing at all are different experiences, so
            # a mixed incident says both. Skipped when the span above already IS the
            # blackout, which would only say the same thing twice.
            if self._ep_blackouts and not blackout_only:
                e.issue["blackouts"] = self._ep_blackouts
                e.issue["blackout_s"] = self._ep_blackout_s

            # An incident that was ONLY a blackout, and only ONE blackout, has already been
            # closed out loud at the instant it ended by the 'INTERNET IS BACK' message —
            # same time, same duration, a quarter of an hour earlier. Repeating it here is
            # a second buzz that says nothing new.
            #
            # The count is what makes that safe. The state messages fire once per incident,
            # so if the line went dark AGAIN after that message, nobody was told about the
            # second one and this is the only thing that will ever mention it. Anything the
            # LINK was involved in also recovers normally: "back on the MAIN link" is news
            # that message could not carry when the network was still on the backup link.
            if blackout_only and self._ep_back_told and self._ep_blackouts == 1:
                redundant.append(id(e))
            # WHEN it came back, not how long ago. The episode's own `clear_since` is not
            # that instant — a completed flap is held 'present' for `flap_hold_s` past the
            # end of the outage — and the message itself is a quarter of an hour late by
            # construction, since that is how long the recovery has to hold to be believed.
            #
            # A measured instant is only accepted when it is close enough to the gate's own
            # clearing to be describing the same event: `_restored_at` is whatever came back
            # last, and after an hour on the backup link with no further log lines that would be
            # the flap the episode STARTED with, not the moment it ended.
            hold = float(self._wcfg().get("flap_hold_s", 60))
            clear = e.episode.clear_since or now
            measured = self._restored_at
            e.issue["restored_at"] = (measured if measured and 0 <= clear - measured <= hold + 120
                                      else clear)

        # The outage accumulator belongs to ONE episode. Reset it once the gate has closed
        # that episode (or dropped it without a word, which a re-fire healing inside its
        # cooldown does) and nothing is holding a new one open — never while the incident
        # is merely waiting out `recovery_confirm_s`, or the recovery would report zero.
        if not self._gate.episode_start(WAN_KEY) and WAN_KEY not in current:
            self._ep_outage_s, self._ep_outages = 0.0, 0
            self._ep_blackout_s, self._ep_blackouts = 0.0, 0
            self._ep_blackout_told = self._ep_back_told = self._ep_link_trouble = False
            self._ep_main_told = False
            self._restored_at = self._backup_since = 0.0

        for e in events:
            if e.kind == RECOVERED:
                log.info("RECOVERED %s (down %.0fs, %d flap(s))",
                         e.issue["device"], e.issue.get("outage_s", e.duration_s), e.flaps)
            else:
                log.warning("%s%s %s: %s", e.issue["severity"].upper(),
                            " (still)" if e.kind == STILL else "",
                            e.issue["device"], e.issue["detail"])
        # Severity alone decides what pages — including recoveries. Reading `e.kind` here
        # too meant a `warning`-severity flap stayed silent going down and then announced
        # itself coming back up, which is the one combination nobody wants.
        pageable = [e for e in events if e.issue.get("severity") == "critical"
                    and id(e) not in redundant]
        msgs = format_alerts(pageable, _Shim(ts=now))
        for msg in msgs:
            # Tagged with the incident key: during a blackout this message cannot leave the
            # house and goes to the outbox, where the tag is how a delayed delivery knows to
            # say "this had already recovered" instead of announcing it in the present tense.
            self.on_alert(msg, WAN_KEY)

        # ...and the two things the incident gate has no way to say: that there is no
        # internet AT ALL, and the moment that ended. `msgs` tells it whether the incident
        # alert that just left already carried the first of those.
        self._state_messages(now, alerted=bool(
            msgs and any(e.kind in (NEW, STILL) for e in pageable)))
        self._save_record()

    # --- the alert record, across restarts ---------------------------------
    # What this watcher has told the user about the current incident: the gate holds the
    # incident itself, these the three state messages and the totals its recovery quotes.
    # Everything else here (pings, route, log watermark) is re-derived within a tick or two.
    _RECORD = ("_ep_outage_s", "_ep_outages", "_ep_blackouts", "_ep_blackout_s",
               "_ep_blackout_told", "_ep_back_told", "_ep_main_told", "_ep_link_trouble",
               "_backup_since", "_restored_at", "_last_down_at", "_back_at")

    def dump_record(self) -> dict:
        return {"gate": self._gate.dump(), **{f: getattr(self, f) for f in self._RECORD}}

    def restore_record(self, rec: Optional[dict], now: Optional[float] = None) -> int:
        """Take back the last process's WAN incident; returns how many episodes it held.

        Without it, a restart while the network was on the backup link announced the same
        incident again, and its recovery quoted only the outages seen since the restart."""
        if not rec:
            return 0
        for f in self._RECORD:
            if f in rec:
                setattr(self, f, rec[f])
        return self._gate.restore(rec.get("gate"), now)

    def _save_record(self):
        if self.persist is None:
            return
        try:
            self.persist(self.dump_record())
        except Exception as e:     # losing the record must never stop the watcher
            log.warning("WAN alert record not saved: %s", e)

    # --- for the report / dashboard ---------------------------------------
    def snapshot_state(self) -> dict:
        longest = max((end - start for start, end in self.blips), default=0)
        p = self.path or {}
        return {
            # The three-state view, for the dashboard box: ok (green) / backup (yellow) /
            # down (red). Not gated by min_outage_s — the floor decides what is worth a
            # message, never what the screen is allowed to show.
            "state": self.state,
            "state_since": self.state_since or None,
            "link": p.get("link"),
            "on_backup": bool(p.get("on_backup")),
            "path_age_s": round(time.time() - self._path_at) if self._path_at else None,
            "down_since": self._down_since or None,   # set only while state == down
            "back_at": self._back_at or None,         # when the last blackout ended
            "blackout": self.blackout,
            "targets": dict(self.targets),
            "flaps_24h": self.flap_count_24h(),
            "last_flap": (self.flaps[-1].start.isoformat() if self.flaps else None),
            "last_flap_s": (round(self.flaps[-1].seconds) if self.flaps else None),
            # Short blackouts under the paging floor: never paged, but never hidden either.
            "blips_24h": self.blip_count_24h(),
            "longest_blip_s": round(longest) if longest else None,
            # the standby link, read only while the main link is down
            "standby": ({**self.standby, "down_at": self._sb_down_at,
                         "story": (self.standby_now() or {}).get("line")}
                        if self._sb_down_at and self.standby else None),
        }
