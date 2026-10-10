"""The devices' own ports and logs, read on a clock.

lanowl watches a device from outside — does it answer — and the owl can read one from inside
when the owner asks (devread.py). Between the two nothing looked: a port back at 100 Mbps after
a power cut, a NIC that drops its link now and then, a disk error in a journal — none of it shows
from outside.

Two reads, one login a device:

    ports   each physical Ethernet port's negotiated speed and duplex. The main router's over its
            kept API connection (routeros.py) every `router_every_s`, with no login; every other
            device lanowl has a login for, every `every_h` hours (never more often than hourly). A
            port that comes up slower than it usually runs (1 Gbps → 100 Mbps, or half duplex) is
            read again a minute later and, still slower, told once in lanowl's own words: the
            numbers, and what the device says the other end offers. Back to its usual speed: told
            once more. A port that does it twice in a week has a device behind it that changes the
            link by itself (one going to sleep drops it to 10/100 for Wake-on-LAN): said so, then
            left quiet. Its sheet still shows it.
    log     the device's own log, the lines written since the last read (`manage: [logs]`). The code
            drops the routine (Wi-Fi clients joining and leaving, DHCP, lanowl's own logins) and
            tags what it recognises (a link, a reboot, a disk); the owl reads the rest and says
            something only when it is not normal. Nothing is sent for the first `quiet_days`: the
            verdicts are kept, so what would have been said can be read before anything is.

Not read here: the main router's log (wanwatch.py, every minute over the same connection) and a
Linux host's auth log when lanowl's key reads it every two minutes (hostlog.py).

Each round is one login, and a device writes every login in its own log (two lines on a MikroTik,
whose memory log keeps a thousand): that is why it is hourly.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import re
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .model import router_host
from .prompts import CALL_SUMMARY
from .records import kept_lines
from .report import _html, human_duration, label
from .wanwatch import verdict_kind

log = logging.getLogger("lanowl.devwatch")

KINDS = ("mikrotik", "openwrt", "linux", "esxi", "unifi")      # the kinds with ports and a log
CONFIRM_S = 60          # a slower port is read again this long after, before it is told
WEEK = 7 * 86400
QUIET_AFTER = 2         # drops and returns in a week that make a port "changes by itself"
SETTLE_S = 7 * 86400    # a port slower for this long runs at its new speed: its usual from then
UNQUIET_S = 30 * 86400  # a quiet port with no change for this long is told again
ANCHOR_N = 40           # the last lines of a read, remembered: where the next read's new ones start
RECENT_N = 30           # lines worth a look kept a device, for its sheet
PENDING_MAX = 200       # lines waiting for the owl (it was busy, or off)
FINDINGS_N = 30

# --- the commands --------------------------------------------------------------------------------
# Every section starts with a marker line, so one login answers both reads.
_PORTS, _LOG = "=== lanowl:ports", "=== lanowl:log"

# each physical Ethernet port (RouterOS): one line, name|status|rate|full-duplex|what the other end
# offers. A port that fails its monitor fails alone, not the line.
ROS_PORTS = (':foreach i in=[/interface ethernet find where disabled=no] do={:do {'
             ':local n [/interface ethernet get $i name]; '
             ':local m [/interface ethernet monitor $i once as-value]; '
             ':put ($n . "|" . ($m->"status") . "|" . ($m->"rate") . "|" . ($m->"full-duplex") . "|" '
             '. [:tostr ($m->"link-partner-advertising")])} on-error={}}')
# its log, one line an entry: id|time|topics|message — the id is stable while the router runs, so
# a line read twice is known even when RouterOS writes its time another way the next day
ROS_LOG = (':foreach i in=[/log find] do={:put ($i . "|" . [/log get $i time] . "|" . '
           '[:tostr [/log get $i topics]] . "|" . [/log get $i message])}')
# each interface's /sys entry (Linux, OpenWrt, UniFi): name|where it sits|state|speed|duplex|wifi|type.
# A physical port is type 1, not under /virtual/, not Wi-Fi.
SYS_PORTS = ('for i in /sys/class/net/*; do n=${i##*/}; [ "$n" = lo ] && continue; '
             'echo "$n|$(readlink -f $i)|$(cat $i/operstate 2>/dev/null)|$(cat $i/speed 2>/dev/null)|'
             '$(cat $i/duplex 2>/dev/null)|$([ -e $i/wireless -o -e $i/phy80211 ] && echo wifi)|'
             '$(cat $i/type 2>/dev/null)"; done')
ESXI_PORTS = "esxcli --formatter=csv network nic list"
# a Linux journal: errors from every service, and the kernel's own lines (links, disks)
JOURNAL_MATCH = "PRIORITY=0 PRIORITY=1 PRIORITY=2 PRIORITY=3 + _TRANSPORT=kernel"
JOURNAL_AUTH = " + SYSLOG_FACILITY=4 + SYSLOG_FACILITY=10"       # when hostlog.py does not read it
JOURNAL_MAX = 400

LOGS = {
    "mikrotik": None,                     # ROS_LOG, inside the RouterOS script
    "openwrt": f'echo "{_LOG} log"; logread 2>/dev/null | tail -n 600',
    "unifi": (f'echo "{_LOG} log"; if [ -r /var/log/messages ]; then tail -n 600 /var/log/messages; '
              'else logread 2>/dev/null | tail -n 600; fi'),
    "esxi": (f'echo "{_LOG} vobd"; tail -n 600 /var/log/vobd.log; '
             f'echo "{_LOG} vmkwarning"; tail -n 300 /var/log/vmkwarning.log'),
}
# what the log of each kind is, for the owl
ABOUT = {
    "mikrotik": "a MikroTik router or access point (RouterOS); its log is in memory and starts "
                "again empty after a restart",
    "openwrt": "an OpenWrt router or access point (logread)",
    "unifi": "a UniFi access point (/var/log/messages)",
    "esxi": "a VMware ESXi host: vobd.log is its events (links, storage, hardware, logins), "
            "vmkwarning.log the kernel's warnings",
    "linux": "a Linux machine: its journal's errors from every service and the kernel's own lines",
}

# --- the routine, dropped by the code --------------------------------------------------------------
# Wi-Fi clients, DHCP, the bridge re-learning a port: what an access point writes all day. And
# ESXi's copies: it writes each event as `vob.*` and again as `esx.*` (a link once a port group),
# so one of them is kept.
_SYSLOG_HUM = re.compile(
    r"\b(?:hostapd|wpa_supplicant|wevent|stahtd|mcad|dnsmasq-dhcp|odhcpd|syswrapper|"
    r"wpa_driver_nl80211)(?:\[\d+\])*:|kernel:\s*(?:\[[\d. ]+\]\s*)?wlan:|\[DHCP-SM\]|\bgarp\.|"
    r"\bEVENT_STA_|\[STA_TRACKER\]|\bsfe_ipv[46]_|Binding to interface '|"
    r"fanctrl_log\(\): Sensor \S+ temp: \d+|\budhcpc(?:\[\d+\])?: (?:sending renew|lease of)|"
    r"entered (?:blocking|disabled|forwarding|learning) state|"
    r"(?:entered|left) promiscuous mode|renamed from veth|\bveth[0-9a-f]+\b|IPv6: ADDRCONF|"
    r"\[UFW (?:BLOCK|AUDIT|ALLOW)\]|synchronized to upstream time servers|"
    r"\[vob\.net\.pg\.uplink\.transition|\[vob\.net\.firewall\.|\[vob\.clock\.|\[vob\.user\.ssh\.session")
_ROS_HUM_TOPICS = {"wireless", "wifi", "caps", "capsman", "dhcp"}
_ROS_BAD = {"error", "critical", "warning"}
_LOGGED_OUT = re.compile(r"\buser \S+ logged out from ")

# what the code recognises, tagged for the owl and the sheet
TAGS = (
    ("link", re.compile(r"\blink (?:is )?(?:up|down)\b|linkstate (?:up|down)|uplink.{0,20} is (?:up|down)|"
                        r"connectivity (?:lost|restored)|Lost network connectivity|NIC Link is|carrier (?:lost|acquired)|"
                        r"link becomes ready|lost carrier", re.I)),
    ("reboot", re.compile(r"\breboot|rebooted|booting|init complete|Linux version \d|system started|"
                          r"without proper shutdown|power (?:loss|failure)|watchdog", re.I)),
    ("storage", re.compile(r"I/O error|EXT4-fs (?:error|warning)|XFS \S+.{0,20}error|Buffer I/O|"
                           r"blk_update_request|lost access to volume|bad sector|read-only file ?system|"
                           r"\bSMART\b|ata\d+.{0,40}(?:error|failed|exception)|nvme\S*.{0,40}(?:error|timeout|reset)|"
                           r"ScsiDeviceIO|filesystem (?:error|corrupt)|No space left", re.I)),
    ("hardware", re.compile(r"temperature|overheat|thermal|voltage|\bpsu\b|power supply|\bfan\b|"
                            r"Machine check|\bECC\b", re.I)),
    ("memory", re.compile(r"out of memory|oom-killer|Killed process|oom_reaper", re.I)),
    ("login", re.compile(r"logged in|session (?:was )?opened|Accepted (?:password|publickey|keyboard)|"
                         r"auth succeeded", re.I)),
    ("failed-login", re.compile(r"login failure|Failed password|authentication failure|Invalid user|"
                                r"auth(?:entication)? fail|Bad password", re.I)),
    ("config", re.compile(r"changed by|added by|removed by|configuration (?:has )?changed", re.I)),
)
# a login or a session, the shape lanowl's own leave in a log
_SESSION = re.compile(r"logged (?:in|out)|login|session|Accepted|auth succeeded|Child connection|"
                      r"Exit \(|Disconnect|connection from|via ssh|SSH", re.I)
# where a login came from, in each kind's words: to learn the address a device sees lanowl at
_FROM = (re.compile(r"user (\S+) logged in from (\S+) via ssh"),                    # RouterOS
         re.compile(r"auth succeeded for '([^']+)' from \[?([0-9a-fA-F.:]+?)\]?:\d+"),  # dropbear
         re.compile(r"SSH session was opened for '([^@']+)@([^']+)'"),              # ESXi
         re.compile(r"Accepted \S+ for (\S+) from (\S+)"))                          # OpenSSH


# --- ports -----------------------------------------------------------------------------------------
@dataclass
class Port:
    name: str
    up: bool
    mbps: int = 0
    full: Optional[bool] = None
    partner: str = ""            # what the other end offers (RouterOS says)


def mbps_of(v) -> int:
    """'1Gbps', '100Mbps', '2.5Gbps', '1000' -> Mbps; 0 = no link or not known (-1, 65535…)."""
    s = str(v or "").strip().lower().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)(g|m)?(?:bps|b/s)?$", s)
    if not m:
        return 0
    n = int(round(float(m.group(1)) * (1000 if m.group(2) == "g" else 1)))
    return n if 0 < n <= 400000 and n != 65535 else 0


def speed_words(mbps: int) -> str:
    return f"{mbps / 1000:g} Gbps" if mbps >= 1000 else f"{mbps} Mbps"


def link_words(mbps: int, full: Optional[bool]) -> str:
    return speed_words(mbps) + ("" if full is None else " full duplex" if full else " HALF duplex")


def _yes(v) -> Optional[bool]:
    s = str(v or "").strip().lower()
    return True if s in ("true", "yes") else False if s in ("false", "no") else None


def _offers(v) -> str:
    """RouterOS's link-partner-advertising, shorter: '10M-baseT-half;1G-baseT-full' -> '10M-half, 1G-full'."""
    parts = [re.sub(r"-base[A-Za-z0-9]+", "", x.strip()) for x in re.split(r"[;,]", str(v or ""))]
    return ", ".join(x for x in parts if x)


def parse_ros_ports(text: str) -> list:
    out = []
    for ln in (text or "").splitlines():
        p = ln.strip().split("|")
        if len(p) < 4 or not p[0].strip():
            continue
        up = p[1].strip() == "link-ok"
        n = mbps_of(p[2]) if up else 0
        out.append(Port(p[0].strip(), up and n > 0, n, _yes(p[3]) if up else None,
                        _offers(p[4]) if len(p) > 4 else ""))
    return out


def parse_ros_monitor(rows: list) -> list:
    """The main router's `interface/ethernet/monitor` rows (API or REST)."""
    out = []
    for r in rows or []:
        if not isinstance(r, dict) or not r.get("name"):
            continue
        up = str(r.get("status") or "") == "link-ok"
        n = mbps_of(r.get("rate")) if up else 0
        out.append(Port(str(r["name"]), up and n > 0, n, _yes(r.get("full-duplex")) if up else None,
                        _offers(r.get("link-partner-advertising"))))
    return out


def parse_sys_ports(text: str) -> list:
    """/sys/class/net, physical ports only. One whose speed is never known (a VM's virtio NIC
    says -1) is left out: there is nothing to compare."""
    out = []
    for ln in (text or "").splitlines():
        p = ln.split("|")
        if len(p) < 7:
            continue
        name, real, state, speed, duplex, wifi, typ = (x.strip() for x in p[:7])
        if typ != "1" or wifi or not real.startswith("/sys/devices/") or "/virtual/" in real \
                or "/gadget/" in real:
            continue
        n = mbps_of(speed)
        if state == "up" and not n:
            continue
        out.append(Port(name, state == "up", n if state == "up" else 0,
                        {"full": True, "half": False}.get(duplex) if state == "up" else None))
    return out


def parse_esxi_ports(text: str) -> list:
    """`esxcli --formatter=csv network nic list`."""
    rows = [r for r in csv.reader(io.StringIO((text or "").strip())) if r]
    if not rows:
        return []
    ix = {h.strip(): i for i, h in enumerate(rows[0])}

    def g(r, k):
        i = ix.get(k)
        return r[i].strip() if i is not None and i < len(r) else ""
    out = []
    for r in rows[1:]:
        name = g(r, "Name")
        if not name:
            continue
        up = (g(r, "LinkStatus") or g(r, "Link")).lower() == "up"
        n = mbps_of(g(r, "Speed")) if up else 0
        out.append(Port(name, up and n > 0, n,
                        {"full": True, "half": False}.get(g(r, "Duplex").lower()) if up else None))
    return out


PARSE_PORTS = {"mikrotik": parse_ros_ports, "openwrt": parse_sys_ports, "unifi": parse_sys_ports,
               "linux": parse_sys_ports, "esxi": parse_esxi_ports}


def step(st: dict, p: Port, now: float) -> str:
    """One reading of one port against the speed it usually runs at; `st` is the port's record.

    Returns "" (nothing to say), "check" (slower, once: read it again before telling), "drop"
    (slower twice in a row), or "back" (its usual speed again, after a drop). No link is no
    judgement: unplugged is the device's business, not a speed."""
    if not p.up or not p.mbps:
        st.pop("seen_low", None)
        return ""
    full = p.full is not False                  # not said: counted as full
    if p.partner:
        st["partner"] = p.partner
    if not st.get("usual"):
        st.update(usual=p.mbps, usual_full=full)
        return ""
    usual, ufull = int(st["usual"]), bool(st.get("usual_full", True))
    if p.mbps < usual or (p.mbps == usual and ufull and not full):
        if st.get("low_since"):
            st["low_mbps"], st["low_full"] = p.mbps, full
            if now - float(st["low_since"]) >= SETTLE_S:          # its speed now
                st.update(usual=p.mbps, usual_full=full, low_since=0, told=False)
            return ""
        if not st.get("seen_low"):
            st["seen_low"] = now
            return "check"
        st["low_since"] = st.pop("seen_low")
        st["low_mbps"], st["low_full"] = p.mbps, full
        return "drop"
    st.pop("seen_low", None)
    low = float(st.get("low_since") or 0)
    if p.mbps > usual or (p.mbps == usual and full and not ufull):
        st.update(usual=p.mbps, usual_full=full)                  # faster: its usual from now on
    if low:
        st["low_since"] = 0
        st["back_after"] = now - low
        st["cycles"] = [t for t in st.get("cycles") or [] if now - t < WEEK] + [now]
        return "back"
    return ""


def quiet(st: dict, now: float) -> bool:
    """A port lanowl stopped telling about (it changes by itself) — until a month without a change."""
    q = float(st.get("quiet") or 0)
    if q and now - max([q] + list(st.get("cycles") or [])) >= UNQUIET_S:
        st["quiet"] = 0
        return False
    return bool(q)


# --- logs ------------------------------------------------------------------------------------------
def sections(text: str) -> dict:
    """{"ports": text, "log:<source>": text} from one round's output."""
    out, cur, buf = {}, None, []
    for ln in (text or "").splitlines():
        if ln.startswith(_PORTS):
            cur, buf = "ports", []
            out[cur] = buf
        elif ln.startswith(_LOG):
            cur, buf = "log:" + (ln[len(_LOG):].strip() or "log"), []
            out[cur] = buf
        elif cur is not None:
            buf.append(ln)
    return {k: "\n".join(v) for k, v in out.items()}


def ros_line(raw: str) -> tuple:
    """'*2A|2026-03-14 07:05:12|system;error;critical|router was …' -> (key, shown line, topics)."""
    p = raw.split("|", 3)
    if len(p) < 4:
        return raw, raw, set()
    topics = {t for t in p[2].split(";") if t}
    return f"{p[0]}|{p[2]}|{p[3]}", f"{p[1]} {','.join(p[2].split(';'))}: {p[3]}", topics


def _h(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:12]


def new_since(keys: list, anchor: list) -> tuple:
    """(index of the first new line, whether the last read was found). The new lines are those
    after the last one the previous read ended with; with that read gone (a restart emptied the
    log, or more was written than one read holds), all of them."""
    a = set(anchor or [])
    for i in range(len(keys) - 1, -1, -1):
        if _h(keys[i]) in a:
            return i + 1, True
    return 0, False


def tags_of(line: str) -> list:
    return [t for t, rx in TAGS if rx.search(line)]


def hum(kind: str, line: str, topics: set) -> bool:
    if kind == "mikrotik":
        # a logout is never news alone: its login, from where, is the line that says who
        return (bool(topics & _ROS_HUM_TOPICS) and not (topics & _ROS_BAD)) or bool(_LOGGED_OUT.search(line))
    return bool(_SYSLOG_HUM.search(line))


def learn_self(lines: list, user: str) -> str:
    """The address the device saw lanowl's own login come from: the last login of lanowl's user
    in what was just read (the read ran inside it). '' when none."""
    for ln in reversed(lines):
        for rx in _FROM:
            m = rx.search(ln)
            if m and m.group(1) == user:
                return m.group(2).strip("[]")
    return ""


def own(line: str, user: str, addrs: set) -> bool:
    """lanowl's own login, logout or command — not news. A login as lanowl's user from anywhere
    else is somebody else, and stays."""
    if any(a and re.search(rf"(?<![\d.]){re.escape(a)}(?![\d])", line) for a in addrs):
        return bool(_SESSION.search(line))
    if "lanowl:" in line:                       # its own command, in a sudo line
        return True
    if user and re.search(rf"pam_unix\((?:sshd|sudo):session\): session (?:opened|closed) for user "
                          rf"(?:{re.escape(user)}\b|root\(uid=0\) by {re.escape(user)}\b)", line):
        return True
    return False


# --- the module --------------------------------------------------------------------------------------
@dataclass
class Target:
    ip: str
    name: str
    kind: str
    ports: bool
    logs: bool
    auth: bool = False          # a Linux journal's auth lines too (hostlog.py does not read them)


SYSTEM = """You read new lines from the own log of one device on a home network: {about}.
lanowl already removed the routine (Wi-Fi clients joining and leaving, DHCP, its own logins) and
marks a line it recognises with a tag in brackets: [link], [reboot], [storage], [hardware],
[memory], [login], [failed-login], [config].

Most of what is left is still normal: a port going down and up once, a computer that sleeps, the
owner logging in from the home network, a clock set after a start, a service restarting once, a
warning the device writes every day. Then say nothing: "problem": false.

"problem": true only for what the owner should know or act on:
  - the device restarted on its own (not by lanowl: see LANOWL'S OWN ACTIONS), above all without
    a proper shutdown, which is a power cut;
  - a link going down and up again and again, or coming back slower;
  - storage, disk or filesystem errors; out of memory; temperature, fans, power supply;
  - a login that does not fit (from outside the home network, a user that should not be there,
    failed passwords again and again), or anything that reads like someone getting in;
  - anything else that reads like a fault building up.

Say what happened and when, with the device's own words for it. Never a reason the lines do not
show. One line is one event: never "failing", "degrading" or "dying" from a single line. If the
network had no internet at the time (WHAT WAS HAPPENING), what failed for that is not a finding.

Reply with ONLY this JSON object, no prose and no code fence:
{{"problem": true|false,
 "kind": "security"|"health",
 "severity": "critical"|"warning"|"info",
 "summary": "<at most two short sentences, the only text the owner reads on the phone>",
 "detail": "<the evidence, for the dashboard: the key lines quoted>"}}

"kind": "security" for access (logins, users, failed passwords, configuration changed by
someone), "health" for the device working. "critical" only for someone getting in or a device
about to fail; a restart or a flapping link is "warning"."""


@dataclass
class DevWatch:
    """The rounds, the port records, the log triage. Its own task (`run`), like hostlog.py: an ssh
    login to a wedged box must not stall the sweep or the WAN watcher."""
    a: object                                   # the Auditor
    on_alert: Callable[..., None]
    agent: Optional[object] = None
    llm_busy: Optional[Callable[[], bool]] = None
    model_on: Optional[Callable[[], bool]] = None
    on_event: Optional[Callable[..., None]] = None

    rec: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    _live: dict = field(default_factory=dict)       # "ip|port" -> the last reading, not kept
    _recheck: dict = field(default_factory=dict)    # ip -> when to read its ports again
    _router_last: float = 0.0
    _router_error: str = ""
    _stop: bool = False
    _busy: bool = False

    def __post_init__(self):
        c = self.cfg
        self.enabled = bool(c.get("enabled", False))
        self.ports_on = self.enabled and bool(c.get("ports", True))
        self.logs_on = self.enabled and bool(c.get("logs", True))
        self.every_s = max(1.0, float(c.get("every_h") or 1)) * 3600      # never more often
        self.router_every_s = max(30.0, float(c.get("router_every_s") or 60))
        self.quiet_days = float(c.get("quiet_days", 7) or 0)
        t = c.get("triage") or {}
        self.timeout_s = float(t.get("timeout_s", 120))
        self.max_lines = int(t.get("max_lines", 60))
        self.notify = [str(x) for x in (t.get("notify_severities") or ["critical", "warning"])]
        try:
            self.rec = self.a.state.load_record("devwatch") or {}
        except Exception:
            log.warning("devwatch: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        self.rec.setdefault("dev", {})
        self.rec.setdefault("ports", {})
        if self.enabled:
            self.rec.setdefault("started", time.time())     # the quiet days count from here

    @property
    def cfg(self) -> dict:
        c = (self.a.cfg or {}).get("devwatch")
        return c if isinstance(c, dict) else {}

    def _save(self):
        if not getattr(self.a, "_persist_alerts", True):
            return
        try:
            self.a.state.save_record("devwatch", self.rec)
        except Exception as e:
            log.warning("devwatch: record not saved: %s", e)

    # --- what is read ------------------------------------------------------------------------
    def _hostlog_reads(self, ip: str) -> bool:
        hl = getattr(self.a, "hostlog", None)
        return bool(hl is not None and hl.enabled and any(h.ip == ip for h in hl.watched))

    def targets(self) -> list:
        """Every device this reads: a kind with ports and a log, a login of the sort it needs
        (devread.py decides), never the main router (its ports are read over the API, its log by
        wanwatch.py)."""
        if not self.enabled:
            return []
        rh = router_host(self.a.cfg)
        out = []
        for d in self.a.inv.devices:
            kind = str(d.attrs.get("kind") or "")
            if kind not in KINDS or d.ip == rh:
                continue
            try:
                reads = self.a.devreads.reads_of(d.ip)
            except Exception:
                reads = {}
            if "ports" not in reads:
                continue
            pl = self.a.kinds.plan(d.ip) if getattr(self.a, "kinds", None) is not None else None
            logs = self.logs_on and pl is not None and "logs" in pl.features
            if not (self.ports_on or logs):
                continue
            out.append(Target(d.ip, d.name, kind, self.ports_on, logs,
                              auth=kind == "linux" and logs and not self._hostlog_reads(d.ip)))
        return out

    def target(self, ip: str) -> Optional[Target]:
        return next((t for t in self.targets() if t.ip == ip), None)

    # --- the clock ---------------------------------------------------------------------------
    async def run(self):
        if not self.enabled:
            log.info("devwatch: off (devwatch.enabled)")
            return
        self.rec.setdefault("started", time.time())
        log.info("devwatch: %d device(s) every %gh, the main router's ports every %ds%s",
                 len(self.targets()), self.every_s / 3600, self.router_every_s,
                 "" if self.ports_on else " (ports off)")
        await asyncio.sleep(20)
        rounds: Optional[asyncio.Task] = None
        while not self._stop:
            now = time.time()
            if self.ports_on and now - self._router_last >= self.router_every_s:
                self._router_last = now
                try:
                    await self.router_round()
                except Exception:
                    log.exception("devwatch: the main router's ports")
            if rounds is None or rounds.done():
                rounds = asyncio.ensure_future(self._due_rounds())
            await asyncio.sleep(10)

    def stop(self):
        self._stop = True

    async def _due_rounds(self):
        """The devices whose hour is up, one at a time; then the ports read again a minute after
        they looked slower."""
        now = time.time()
        for t in self.targets():
            if self._stop:
                return
            d = self.rec["dev"].get(t.ip) or {}
            re_at = self._recheck.get(t.ip)
            if re_at is not None and now >= re_at:
                self._recheck.pop(t.ip, None)
                await self._guard(self.round(t, ports_only=True))
            elif now - float(d.get("last") or 0) >= self.every_s:
                await self._guard(self.round(t))

    async def _guard(self, coro):
        try:
            await coro
        except Exception:
            log.exception("devwatch: a round failed")

    # --- the main router, over its connection --------------------------------------------------
    async def router_round(self):
        from . import routeros
        ip = router_host(self.a.cfg)
        if not ip:
            return
        r = routeros.shared(self.a.cfg)
        eth = await r.request("GET", "interface/ethernet", None, 20)
        if isinstance(eth, dict):
            self._router_error = str(eth.get("error") or "no answer")
            return
        names = [str(x.get("name")) for x in eth if isinstance(x, dict) and x.get("name")
                 and str(x.get("disabled")) not in ("true", "yes")]
        if not names:
            return
        rows = await r.request("POST", "interface/ethernet/monitor",
                               {"numbers": ",".join(names), "once": ""}, 20)
        if isinstance(rows, dict) or len(rows or []) != len(names):
            rows = []                           # one port at a time, where a list is refused
            for n in names:
                x = await r.request("POST", "interface/ethernet/monitor", {"numbers": n, "once": ""}, 20)
                if isinstance(x, list) and x:
                    rows.append({**x[0], "name": x[0].get("name") or n})
        self._router_error = ""
        dev = self.a.inv.get(ip)
        self._ports(Target(ip, dev.name if dev is not None else "the main router", "mikrotik", True,
                           False), parse_ros_monitor(rows), time.time(), recheck=False)
        self._save()

    # --- a device's round ----------------------------------------------------------------------
    def command(self, t: Target, ports_only: bool = False) -> str:
        d = self.rec["dev"].get(t.ip) or {}
        if t.kind == "mikrotik":
            parts = [f':put "{_PORTS}"', ROS_PORTS]
            if t.logs and not ports_only:
                parts += [f':put "{_LOG} log"', ROS_LOG]
            return "; ".join(parts)
        parts = [f'echo "{_PORTS}"', ESXI_PORTS if t.kind == "esxi" else SYS_PORTS]
        if t.logs and not ports_only:
            parts.append(self._linux_log(t, d) if t.kind == "linux" else LOGS[t.kind])
        return "; ".join(parts)

    @staticmethod
    def _linux_log(t: Target, d: dict) -> str:
        cur = str(d.get("cursor") or "")
        match = JOURNAL_MATCH + (JOURNAL_AUTH if t.auth else "")
        # first read: only where the journal is now (its newest entry's cursor), nothing told
        sel = (f"--after-cursor={shlex.quote(cur)} -n {JOURNAL_MAX} {match}" if cur else "-n 1")
        return (f'if command -v journalctl >/dev/null 2>&1; then echo "{_LOG} journal"; '
                f"journalctl --no-pager -o short-iso --show-cursor {sel} 2>&1; "
                f'elif [ -r /var/log/syslog ]; then echo "{_LOG} syslog"; tail -n 600 /var/log/syslog; '
                f'elif [ -r /var/log/messages ]; then echo "{_LOG} messages"; tail -n 600 /var/log/messages; '
                f'elif command -v logread >/dev/null 2>&1; then echo "{_LOG} logread"; logread | tail -n 600; fi')

    async def _exec(self, t: Target, cmd: str, root: bool = False) -> tuple:
        dr = self.a.devreads
        if t.kind == "mikrotik":
            return await dr._routeros(t.ip, cmd, 60)
        rc, out, err = await dr._ssh1(t.ip, cmd, 60, root)
        if rc is None or (rc != 0 and not (out or "").strip()):
            last = ((err or out or "").strip().splitlines() or ["no answer"])[-1][:160]
            return False, last
        return True, out

    async def round(self, t: Target, ports_only: bool = False):
        now = time.time()
        d = self.rec["dev"].setdefault(t.ip, {})
        if not ports_only:
            d["last"] = now                     # claimed: a slow or failed one is not retried at once
        ok, out = await self._exec(t, self.command(t, ports_only), root=bool(d.get("root")))
        if ok and t.kind == "linux" and t.logs and not ports_only and not d.get("root") \
                and re.search(r"not seeing messages from other users|insufficient permissions", out):
            d["root"] = True                    # the journal is root's (or adm's) on this one
            ok, out = await self._exec(t, self.command(t), root=True)
        d["ok"], d["error"] = ok, "" if ok else out
        if not ok:
            log.info("devwatch: %s (%s): %s", t.name, t.ip, out)
            self._save()
            return
        sec = sections(out)
        if t.ports and "ports" in sec:
            self._ports(t, PARSE_PORTS[t.kind](sec["ports"]), now, recheck=not ports_only)
        if t.logs and not ports_only:
            await self._logs(t, d, sec, now)
        self._save()

    # --- ports: the speed it usually runs at --------------------------------------------------
    def _ports(self, t: Target, ports: list, now: float, recheck: bool):
        for p in ports:
            key = f"{t.ip}|{p.name}"
            self._live[key] = {"at": now, "up": p.up, "mbps": p.mbps, "full": p.full}
            st = self.rec["ports"].setdefault(key, {})
            ev = step(st, p, now)
            if ev == "check" and recheck:
                self._recheck[t.ip] = now + CONFIRM_S
            elif ev in ("drop", "back"):
                self._tell_port(t, p, st, ev, now)
        # a port that no longer exists (renamed, a NIC taken out) leaves the record
        seen = {f"{t.ip}|{p.name}" for p in ports}
        for k in [k for k in self.rec["ports"] if k.startswith(t.ip + "|") and k not in seen]:
            if not self.rec["ports"][k].get("low_since"):
                self.rec["ports"].pop(k, None)

    def _tell_port(self, t: Target, p: Port, st: dict, ev: str, now: float):
        who = label(t.name, t.ip)
        detail = {"ip": t.ip, "name": t.name, "port": p.name, "event": ev, "mbps": p.mbps,
                  "full": p.full, "usual": st.get("usual")}
        if self.on_event is not None:
            try:
                self.on_event("link", None, json.dumps(detail, ensure_ascii=False), None)
            except Exception:
                pass
        stamp = time.strftime("%H:%M")
        if ev == "drop":
            log.warning("devwatch: %s %s at %s, usually %s", who, p.name, link_words(p.mbps, p.full),
                        speed_words(int(st["usual"])))
            if st.get("muted") or quiet(st, now):
                st["told"] = False
                return
            st["told"] = True
            offers = st.get("partner") or ""
            self.on_alert(f"🟡 <b>LINK SLOWER</b> {stamp} — <b>{_html(who)}</b>\n"
                          f"{_html(p.name)} is at <b>{_html(link_words(p.mbps, p.full))}</b>; it usually runs at "
                          f"{_html(link_words(int(st['usual']), bool(st.get('usual_full', True))))}."
                          + (f"\n<i>The other end offers: {_html(offers)}</i>" if offers else ""),
                          f"link:{t.ip}:{p.name}")
            return
        log.info("devwatch: %s %s back at %s after %s", who, p.name, link_words(p.mbps, p.full),
                 human_duration(st.get("back_after") or 0))
        told, st["told"] = bool(st.get("told")), False
        by_itself = len(st.get("cycles") or []) >= QUIET_AFTER and not st.get("quiet")
        if by_itself:
            st["quiet"] = now
        if not told:
            return
        self.on_alert(f"🟢 <b>LINK BACK</b> {stamp} — <b>{_html(who)}</b>\n"
                      f"{_html(p.name)} is at {_html(link_words(p.mbps, p.full))} again, after "
                      f"{_html(human_duration(st.get('back_after') or 0))} at "
                      f"{_html(speed_words(int(st.get('low_mbps') or 0)))}."
                      + (f"\n<i>The {_nth(len(st['cycles']))} time this week: the device behind it "
                         "changes the link by itself (one going to sleep does). Not told again; its "
                         "sheet still shows it.</i>" if by_itself else ""),
                      f"link:{t.ip}:{p.name}")

    def set_mute(self, ip: str, port: str, on: bool, by: str = "the dashboard") -> dict:
        key = f"{ip}|{port}"
        st = self.rec["ports"].get(key)
        if st is None:
            return {"ok": False, "error": f"no port {port} known on {ip}"}
        st["muted"] = bool(on)
        if not on:
            st["quiet"] = 0
        self._save()
        dev = self.a.inv.get(ip)
        who = label(dev.name if dev is not None else "", ip)
        self.a._emit_telegram("digest", (f"🔕 <b>{_html(port)}</b> on {_html(who)}: its speed changes are no "
                                         f"longer told (muted from {_html(by)})." if on else
                                         f"🔔 <b>{_html(port)}</b> on {_html(who)}: its speed changes are "
                                         f"told again (from {_html(by)})."))
        return {"ok": True, "muted": bool(on)}

    # --- logs: what is new, what is routine, what the owl reads -------------------------------
    async def _logs(self, t: Target, d: dict, sec: dict, now: float):
        lg = self.a.access.login(t.ip)
        user = (lg.user if lg is not None else "") or ""
        logs = {k[4:]: v for k, v in sec.items() if k.startswith("log:")}
        if not logs:
            d["log_error"] = "no log to read on it (no journal, syslog or logread)"
            return
        d.pop("log_error", None)
        fresh, routine = [], 0
        anchors = d.setdefault("anchor", {})
        for src, text in logs.items():
            if t.kind == "linux" and src == "journal":
                lines = self._journal(d, text)
                if lines is None:
                    continue                        # the first read: only where it is now
                keys, shown, topics = lines, lines, [set()] * len(lines)
            else:
                raw = [ln for ln in text.splitlines() if ln.strip()]
                if t.kind == "mikrotik":
                    parsed = [ros_line(x) for x in raw]
                    keys, shown, topics = [x[0] for x in parsed], [x[1] for x in parsed], [x[2] for x in parsed]
                else:
                    keys, shown, topics = raw, raw, [set()] * len(raw)
                before = anchors.get(src)
                start, found = new_since(keys, before or [])
                anchors[src] = [_h(k) for k in keys[-ANCHOR_N:]]
                if before is None:
                    continue                        # the first read of this log: nothing told
                if not found and before and keys:
                    log.info("devwatch: %s's %s turned over since the last read", t.name, src)
                keys, shown, topics = keys[start:], shown[start:], topics[start:]
            me = learn_self(shown, user)
            if me:
                d["self"] = sorted(set(d.get("self") or []) | {me})[-4:]
            addrs = set(d.get("self") or []) | {self._source(t.ip)}
            for ln, tp in zip(shown, topics):
                if own(ln, user, addrs) or hum(t.kind, ln, tp):
                    routine += 1
                    continue
                tg = tags_of(ln)
                fresh.append((f"[{','.join(tg)}] " if tg else "") + ln[:400])
        d["routine"] = int(d.get("routine") or 0) + routine
        if not fresh:
            return
        d["recent"] = (list(d.get("recent") or []) + [{"ts": now, "line": x} for x in fresh])[-RECENT_N:]
        d["pending"] = (list(d.get("pending") or []) + fresh)[-PENDING_MAX:]
        await self._triage(t, d, routine)

    def _journal(self, d: dict, text: str) -> Optional[list]:
        """The journal's new lines, and its new cursor kept; None on its first read."""
        lines, cursor = [], ""
        for ln in text.splitlines():
            if ln.startswith("-- cursor:"):
                cursor = ln.split(":", 1)[1].strip()
            elif re.search(r"Failed to (?:seek|get) (?:to )?cursor|Failed to seek", ln):
                d.pop("cursor", None)               # rotated away: start again from where it is
                return None
            elif ln.startswith("-- ") or ln.startswith("Hint: ") or not ln.strip():
                continue
            else:
                lines.append(ln)
        first = not d.get("cursor")
        if cursor:
            d["cursor"] = cursor
        return None if first else lines

    def _source(self, ip: str) -> str:
        """The address lanowl reaches `ip` from (no packet is sent)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((ip, 9))
                return s.getsockname()[0]
        except OSError:
            return str((self.a.cfg.get("observer") or {}).get("host_ip") or "")

    # --- the owl ---------------------------------------------------------------------------------
    @property
    def quiet_until(self) -> float:
        """Until when the owl's verdicts are kept, not sent; 0 with no quiet days."""
        if self.quiet_days <= 0:
            return 0.0
        s = self.rec.get("started")
        return (time.time() if s is None else float(s)) + self.quiet_days * 86400

    def _context(self, t: Target, d: dict, routine: int, now: float) -> str:
        dev = self.a.inv.get(t.ip)
        lo = dev.attrs.get("logs") if dev is not None else None
        about = str(lo.get("about") or "") if isinstance(lo, dict) else ""      # its `logs: {about}`
        bits = [f"DEVICE: {label(t.name, t.ip)} — {ABOUT.get(t.kind, t.kind)}"
                + (f"; the owner says: {about or dev.note}" if dev is not None and (about or dev.note) else "")]
        ports = [f"{k.split('|', 1)[1]} {link_words(v['mbps'], v['full']) if v['up'] else 'no link'}"
                 for k, v in self._live.items() if k.startswith(t.ip + "|")]
        if ports:
            bits.append("ITS PORTS NOW: " + "; ".join(ports))
        from .actions import CATALOG
        since = now - self.every_s - 600
        acts = []
        for p in getattr(self.a.actions, "items", None) or []:
            if p.get("ip") == t.ip and float(p.get("done_ts") or p.get("ts") or 0) >= since:
                acts.append(f"{CATALOG.get(p.get('action'), p.get('action'))} — {p.get('status')}"
                            + (f" at {time.strftime('%H:%M', time.localtime(p['done_ts']))}" if p.get("done_ts") else ""))
        bits.append("LANOWL'S OWN ACTIONS on it in this hour: " + ("; ".join(acts) if acts else "none"))
        ww = getattr(self.a, "wanwatch", None)
        wan = ww._wan_context(now) if ww is not None else ""
        if wan:
            bits.append(f"WHAT WAS HAPPENING ON THE INTERNET CONNECTION: {wan}")
        bits.append(f"ROUTINE LINES ALREADY REMOVED: {routine}.")
        return "\n".join(bits)

    async def _triage(self, t: Target, d: dict, routine: int):
        if self.agent is None or (self.model_on is not None and not self.model_on()):
            return                                  # kept on its sheet, waiting
        for _ in range(40):                         # the hourly audit has the model: wait for it
            if self.llm_busy is None or not self.llm_busy():
                break
            await asyncio.sleep(15)
        else:
            log.info("devwatch: %s's lines wait for the next round (the model is busy)", t.name)
            return
        batch = list(d.get("pending") or [])[-self.max_lines:]
        now = time.time()
        try:
            v = await self.agent.ask_json(SYSTEM.format(about=ABOUT.get(t.kind, t.kind)),
                                          self._context(t, d, routine, now) + "\n\nNEW LINES "
                                          f"({len(batch)}):\n" + "\n".join(batch),
                                          timeout_s=self.timeout_s, call=CALL_SUMMARY)
        except Exception as e:
            log.warning("devwatch: %s's triage failed: %s", t.name, e)
            return
        if not v:
            log.info("devwatch: %s's triage: no usable verdict", t.name)
            return
        d["pending"] = []
        sev = str(v.get("severity") or "info").lower()
        problem = bool(v.get("problem"))
        summary = str(v.get("summary") or "").strip()
        held = problem and sev in self.notify and now < self.quiet_until
        f = {"ts": now, "source": f"device log {t.name}", "ip": t.ip, "lines": len(batch),
             "problem": problem, "kind": verdict_kind(v, "health"), "severity": sev,
             "summary": summary[:200], "detail": str(v.get("detail") or "")[:1500],
             "log": kept_lines(batch), **({"held": True} if held else {})}
        self.findings = (self.findings + [f])[-FINDINGS_N:]
        if self.on_event is not None:
            try:
                self.on_event("finding", None, json.dumps(f, ensure_ascii=False), None)
            except Exception:
                pass
        if not problem:
            log.info("devwatch: %s: nothing worth telling (%s)", t.name, summary[:80])
            return
        seclog = getattr(self.a, "seclog", None)
        notify = sev in self.notify and not held
        if seclog is not None and f["kind"] == "security" and sev in ("critical", "warning"):
            seclog.add(source=f["source"], ip=t.ip, sev=sev, title=summary or "a login that does not fit",
                       detail=f["detail"], by="model", paged=notify)
        if held:
            log.info("devwatch: %s: %s — kept, not sent (the first %g days)", t.name, summary[:80],
                     self.quiet_days)
            return
        if not notify:
            return
        emoji = {"critical": "🔴", "warning": "🟡"}.get(sev, "⚪")
        self.on_alert(f"{emoji} <b>DEVICE LOG</b> {time.strftime('%H:%M:%S')} — <b>{_html(label(t.name, t.ip))}</b>\n"
                      + (f"🦉 {_html(summary)}" if summary else "something unusual in its log")
                      + f"\n<i>from {len(batch)} new log line(s)</i>", f"devlog:{t.ip}")

    # --- the dashboard ---------------------------------------------------------------------------
    def ports_of(self, ip: str) -> list:
        now = time.time()
        out = []
        for k, st in sorted(self.rec["ports"].items()):
            if not k.startswith(ip + "|"):
                continue
            lv = self._live.get(k) or {}
            out.append({"name": k.split("|", 1)[1], "up": lv.get("up"), "mbps": lv.get("mbps"),
                        "full": lv.get("full"), "at": lv.get("at"), "usual": st.get("usual"),
                        "usual_full": st.get("usual_full", True), "low_since": st.get("low_since") or 0,
                        "partner": st.get("partner") or "", "muted": bool(st.get("muted")),
                        "quiet": quiet(st, now), "changes_7d": len([c for c in st.get("cycles") or []
                                                                    if now - c < WEEK])})
        return out

    def log_of(self, ip: str) -> dict:
        t = self.target(ip)
        d = self.rec["dev"].get(ip) or {}
        if t is None and not d:
            return {}
        return {"read": bool(t and t.logs), "ports": bool(t and t.ports) or ip == router_host(self.a.cfg),
                "every_h": self.every_s / 3600, "last": d.get("last"), "ok": d.get("ok"),
                "error": d.get("error") or d.get("log_error") or "", "routine": d.get("routine") or 0,
                "recent": list(d.get("recent") or [])[-10:][::-1],
                "quiet_until": self.quiet_until if self.quiet_days else 0}


def _nth(n: int) -> str:
    return {1: "first", 2: "second", 3: "third"}.get(n, f"{n}th")
