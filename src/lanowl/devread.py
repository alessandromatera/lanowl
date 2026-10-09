"""The owl reads a device itself: `device_read`, logged in with lanowl's own login for it.

lanowl logs in to a device for its updates, its configuration, its backups and a reboot — with
the login secrets.yaml names in the device's `credentials:`. The owl's other tools never used
that login: they read the main router with the router's read-only login, and the journal of
the hosts whose log lanowl watches. Asked whether an access point really linked at 1 Gbps, the
owl tried the router's login on the access point (refused: that user is not on it) and told
the owner it had no way in — while lanowl logged in to it every day.

What may run is fixed here, per kind: the model picks a device and a read by name, never a
command. Every read prints, monitors `once`, tails a log or asks an API for a reading. `search`
and `limit` filter what came back, here on lanowl's side: nothing the model writes reaches the
device.

Offered in the owner's own questions (Telegram, the dashboard's Ask), where asking was the
approval, like the shell — never in the audit, over MQTT or in a session's turn — and at most
MAX_PER_ANSWER reads an answer. Each one is listed under the answer, like a check.
"""
from __future__ import annotations

import contextlib
import json
import logging
import re
import shlex
import time
from typing import Optional

from .report import label
from .shell import clip

log = logging.getLogger("lanowl.devread")

MAX_PER_ANSWER = 10
OUT_MAX = 8000                 # characters of one read the model is given
LIMIT = 80                     # lines, unless the model asks for more
LIMIT_MAX = 300

# Each interface's /sys entry: link state, negotiated speed and duplex, how often it lost carrier
# (Linux, OpenWrt, UniFi — busybox has every piece of it).
_SYS_NET = ("for i in /sys/class/net/*; do n=${i##*/}; [ \"$n\" = lo ] && continue; "
            "echo \"$n state=$(cat $i/operstate 2>/dev/null) speed=$(cat $i/speed 2>/dev/null) "
            "duplex=$(cat $i/duplex 2>/dev/null) carrier_changes=$(cat $i/carrier_changes 2>/dev/null)\"; "
            "done")

# The Wi-Fi clients are in the menu of the package the radios run — `wireless` (the older
# driver), `wifi` (7.13 on), `wifiwave2` (7.x before) — and a device may have more than one menu,
# some empty (an older-driver access point on RouterOS 7: `wifi` there and empty, its clients
# under `wireless`). So every menu, each under its own heading: one RouterOS lacks fails only
# its own `:parse`, not the line.
_ROS_CLIENTS = (':foreach m in={"wifi";"wireless";"wifiwave2"} do={ :put ("== /interface " . $m . '
                '" registration-table"); :do { :local f [:parse ("/interface " . $m . '
                '" registration-table print")]; $f } on-error={ :put "(this RouterOS has no such '
                'menu)" } }; :put "== /interface bridge host"; /interface bridge host print')

# kind -> read -> (what it answers, the command). A kind of the owner's own (a profile) reads
# its profile's operations instead (_profile_reads).
READS = {
    "mikrotik": {
        "system": ("model, RouterOS version, uptime, CPU, memory, temperature",
                   "/system resource print; /system routerboard print; /system health print"),
        "ports": ("every interface: running or not, link-downs, last link up/down; each ethernet "
                  "port's negotiated rate and duplex, and what the device at the other end offers "
                  "(link-partner-advertising)",
                  "/interface print terse; /interface ethernet monitor [find] once"),
        "log": ("its own log, the lines as it wrote them", "/log print"),
        "clients": ("its Wi-Fi clients (signal, rates) from each Wi-Fi menu, and the MAC "
                    "addresses its bridge sees on each port", _ROS_CLIENTS),
    },
    "openwrt": {
        "system": ("model, OpenWrt release, uptime, memory, disk",
                   "ubus call system board 2>/dev/null; uptime; free; df -h / /overlay 2>/dev/null"),
        "ports": ("each interface's link state, speed, duplex and carrier changes; the switch "
                  "ports' links on a device with a switch chip",
                  _SYS_NET + "; command -v swconfig >/dev/null 2>&1 && for s in $(swconfig list "
                  "2>/dev/null | awk '{print $2}'); do echo \"== $s\"; swconfig dev $s show "
                  "2>/dev/null | grep -i 'link:'; done"),
        "log": ("its own log (logread), the lines as it wrote them", "logread"),
        "clients": ("its Wi-Fi clients (signal, rates) and its ARP table",
                    "for w in $(iwinfo 2>/dev/null | awk '/ESSID/{print $1}'); do echo \"== $w\"; "
                    "iwinfo $w assoclist; done; echo '== arp'; cat /proc/net/arp"),
    },
    "linux": {
        "system": ("OS, kernel, uptime and load, memory, disks, failed services",
                   ". /etc/os-release 2>/dev/null; echo \"$PRETTY_NAME\"; uname -srm; uptime; "
                   "free -m; df -h -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null; "
                   "systemctl --failed --no-legend --plain 2>/dev/null | sed 's/^/failed: /'"),
        "ports": ("each interface's state, addresses, speed, duplex and carrier changes",
                  "ip -br link 2>/dev/null; ip -br addr 2>/dev/null; " + _SYS_NET),
        "log": ("its system journal (or syslog), the lines as written",
                "journalctl -n 1000 --no-pager -o short-iso 2>/dev/null || "
                "tail -n 1000 /var/log/syslog /var/log/messages 2>/dev/null"),
    },
    "esxi": {
        "system": ("ESXi version, uptime, hardware, datastores",
                   "vmware -vl; esxcli system stats uptime get; esxcli hardware platform get; "
                   "esxcli storage filesystem list"),
        "ports": ("each physical NIC: link, speed, duplex; and its error and drop counters",
                  "esxcli network nic list; for n in $(esxcli network nic list | awk 'NR>2{print $1}'); "
                  "do echo \"== $n\"; esxcli network nic stats get -n $n | grep -iE 'error|drop'; done"),
        "log": ("its event log (vobd.log: links going up and down, storage, hardware)",
                "tail -n 1000 /var/log/vobd.log"),
        "vmkernel": ("its kernel log (vmkernel.log), the busiest one",
                     "tail -n 1000 /var/log/vmkernel.log"),
        "vms": ("every VM and whether it is powered on",
                "vim-cmd vmsvc/getallvms; for id in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); "
                "do echo \"$id $(vim-cmd vmsvc/power.getstate $id | tail -1)\"; done"),
    },
    "unifi": {
        "system": ("model, firmware, uptime, memory",
                   "mca-cli-op info 2>/dev/null; cat /etc/version 2>/dev/null; uptime; free"),
        "ports": ("each interface's link state, speed, duplex and carrier changes", _SYS_NET),
        "log": ("its own log, the lines as it wrote them", "tail -n 1000 /var/log/messages"),
        # the access points as `iw dev` names them (newer models: wifi0ap0, wifi1ap2), else the
        # older models' ath ones; iw's station list, else wlanconfig's table (its header and a line
        # a client — the forty lines of capabilities under each are left on the device)
        "clients": ("its Wi-Fi clients",
                    "for w in $(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type AP/{print i}'; "
                    "[ -n \"$(iw dev 2>/dev/null)\" ] || ls /sys/class/net | grep -E '^ath[0-9]'); "
                    "do echo \"== $w\"; iw dev $w station dump 2>/dev/null | grep -E "
                    "'Station|signal:|bitrate|connected time' || wlanconfig $w list 2>/dev/null | "
                    "grep -E '^ADDR|^([0-9a-f]{2}:){5}'; done"),
    },
    "reolink": {
        "system": ("model, firmware, hardware; the disks of an NVR", ""),
        "sessions": ("who is connected to it right now (its own list)", ""),
        "channels": ("an NVR's cameras: which ones it has online (a camera answers 'not "
                     "support')", ""),
    },
    "homeassistant": {
        "system": ("Home Assistant's version and state", ""),
        "log": ("Home Assistant's own log, the lines as written", ""),
        "unavailable": ("every entity Home Assistant has as unavailable, and since when", ""),
    },
}
# the reads that are logs: the newest lines are the ones wanted, and a long one is cut at its start
LOGS = {"log", "vmkernel"}
_REOLINK = {"system": ["GetDevInfo", "GetHddInfo"], "sessions": ["GetOnline"],
            "channels": ["GetChannelstatus"]}

SPEC_PARAMS = {"type": "object", "properties": {
    "ip": {"type": "string", "description": "the device's address, from DEVICE READS"},
    "read": {"type": "string", "description": "one of that device's reads"},
    "search": {"type": "string", "description": "keep only the lines that contain this "
                                                "(case-insensitive; several with '|')"},
    "limit": {"type": "integer", "description": f"the last N lines (default {LIMIT}, "
                                                f"max {LIMIT_MAX})"},
}, "required": ["ip", "read"]}


def trim_monitor(text: str) -> str:
    """A RouterOS `ethernet monitor` without its two capability lists (`supported`,
    `advertising`: a dozen lines a port, the same on every port). What the other end offers
    (`link-partner-advertising`) stays: it says why a port linked slower than it could."""
    out, skip = [], False
    for ln in (text or "").splitlines():
        m = re.match(r"^\s*([a-z0-9-]+):", ln)
        if m:
            skip = m.group(1) in ("supported", "advertising")
        if not skip:
            out.append(ln)
    return "\n".join(out)


def mark_empty(text: str) -> str:
    """A `== heading` with nothing under it says so — lanowl's words, in brackets: an empty
    Wi-Fi menu read as a missing answer had the model guess."""
    out, lines = [], [ln for ln in (text or "").splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
        out.append(ln)
        if ln.startswith("== ") and (i + 1 == len(lines) or lines[i + 1].startswith("== ")):
            out.append("(lanowl: nothing listed)")
    return "\n".join(out)


def pick_lines(text: str, search: str, limit: int, newest: bool) -> tuple:
    """(text, note): the lines that contain one of `search`'s words, then `limit` of them — the
    newest for a log, else the first. Filtered, never reworded."""
    lines = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    note = []
    words = [w.strip().lower() for w in (search or "").split("|") if w.strip()]
    if words:
        n = len(lines)
        lines = [ln for ln in lines if any(w in ln.lower() for w in words)]
        note.append(f"{len(lines)} of {n} lines contain {' or '.join(repr(w) for w in words)}")
    if len(lines) > limit:
        note.append(f"the {'last' if newest else 'first'} {limit} of {len(lines)} lines")
        lines = lines[-limit:] if newest else lines[:limit]
    return "\n".join(lines), "; ".join(note)


class DeviceReads:
    def __init__(self, auditor):
        self.a = auditor
        self._turn: Optional[dict] = None

    # --- what can be read -------------------------------------------------------
    def _profile_reads(self, kind: str) -> dict:
        prof = (getattr(self.a.kinds, "profiles", None) or {}).get(kind)
        if prof is None:
            return {}
        return {op: (f"its profile's `{op}` command", o["cmd"]) for op, o in prof.ops.items()
                if op not in ("reboot", "backup")}

    def reads_of(self, ip: str) -> dict:
        """{read: (what it answers, command)} for one device — {} when lanowl has no way in:
        no kind with reads, or no login of the sort its kind needs."""
        dev = self.a.inv.get(ip)
        if dev is None:
            return {}
        kind = str(dev.attrs.get("kind") or "")
        reads = READS.get(kind) or self._profile_reads(kind)
        if not reads:
            return {}
        if kind == "homeassistant":           # its API, by the token — not a login
            rb = self.a.actions.reboot
            return reads if (rb.ha_url and rb._ha_token()) else {}
        lg = self.a.access.login(ip)
        if lg is None:
            return {}
        if kind in ("mikrotik", "reolink", "openwrt", "esxi", "unifi") and not lg.password:
            return {}
        if not lg.password and not self._key_host(ip):
            return {}
        return reads

    def targets(self) -> list:
        """[(device, kind, reads)] for every device that can be read."""
        out = []
        for d in self.a.inv.devices:
            r = self.reads_of(d.ip)
            if r:
                out.append((d, str(d.attrs.get("kind")), r))
        return out

    def _key_host(self, ip: str):
        hl = getattr(self.a, "hostlog", None)
        return next((x for x in (getattr(hl, "hosts", None) or []) if x.ip == ip), None)

    # --- is it on offer ---------------------------------------------------------
    def offered(self) -> bool:
        return self._turn is not None and bool(self.targets())

    @contextlib.contextmanager
    def turn(self, via: str, ran: Optional[list] = None):
        """The owner's question in progress: reads run at once, and each joins `ran`."""
        prev = self._turn
        self._turn = {"via": via, "ran": ran if ran is not None else [], "n": 0}
        try:
            yield self._turn
        finally:
            self._turn = prev

    def spec(self) -> dict:
        kinds: dict = {}
        for _, kind, reads in self.targets():
            kinds.setdefault(kind, reads)
        what = "; ".join(f"{k}: " + ", ".join(f"{r} ({v[0]})" for r, v in reads.items())
                         for k, reads in kinds.items())
        return {"type": "function", "function": {
            "name": "device_read",
            "description": ("Read ONE device yourself, logged in with lanowl's own login for it "
                            "(see DEVICE READS): one fixed read-only command per read — you pick "
                            "the read, never the command. It runs at once: the owner's question is "
                            "the approval. Reads by kind — " + what + "."),
            "parameters": SPEC_PARAMS}}

    def prompt_list(self) -> str:
        """The devices, one line each, for the system prompt."""
        return "\n".join(f"- {label(d.name, d.ip)} — {kind}: {', '.join(reads)}"
                         for d, kind, reads in self.targets())

    # --- the tool -------------------------------------------------------------------
    async def call(self, args: dict) -> dict:
        t = self._turn
        if t is None:
            return {"error": "devices can only be read in a question from the owner"}
        args = args if isinstance(args, dict) else {}
        ip, read = str(args.get("ip") or "").strip(), str(args.get("read") or "").strip()
        reads = self.reads_of(ip)
        dev = self.a.inv.get(ip)
        if not reads:
            return {"refused": f"{ip} is not a device lanowl has a login for"
                               + (f" ({dev.name}: no kind with reads, or no login of the sort "
                                  "its kind needs)" if dev is not None else ""),
                    "can_read": [label(d.name, d.ip) for d, _, _ in self.targets()]}
        if read not in reads:
            return {"refused": f"{dev.name} has no read {read!r}", "its_reads": list(reads)}
        if t["n"] >= MAX_PER_ANSWER:
            return {"refused": f"this answer has used its {MAX_PER_ANSWER} device reads",
                    "note": "Nothing ran. Answer with what you have."}
        try:
            limit = max(1, min(int(args.get("limit") or LIMIT), LIMIT_MAX))
        except (TypeError, ValueError):
            limit = LIMIT
        search = str(args.get("search") or "")[:200]
        t["n"] += 1
        kind = str(dev.attrs.get("kind"))
        log.info("device read (%s) %d/%d: %s on %s (%s)%s", t["via"], t["n"], MAX_PER_ANSWER,
                 read, dev.name, ip, f" search {search!r}" if search else "")
        t0 = time.time()
        try:
            ok, text = await self._run(ip, kind, read, reads[read][1])
        except Exception as e:                       # never the answer's end
            log.warning("device read: %s on %s failed", read, ip, exc_info=True)
            ok, text = False, f"{type(e).__name__}: {str(e)[:160]}"
        secs = round(time.time() - t0, 1)
        what = f"{read} “{search[:40]}”" if search else read
        t["ran"].append({"ts": time.time(), "kind": "device", "ok": ok, "secs": secs,
                         "label": f"{what} · on {dev.name}",
                         "summary": "read" if ok else text[:120]})
        if not ok:
            return {"device": label(dev.name, ip), "read": read, "error": text}
        body, note = pick_lines(text, search, limit, newest=read in LOGS)
        r = {"device": label(dev.name, ip), "read": read, "secs": secs,
             "output": clip(body, OUT_MAX) if body else "(nothing)"}
        if note:
            r["note"] = note
        if len(body) > OUT_MAX:
            r["note"] = (r.get("note", "") + "; " if r.get("note") else "") + \
                "output cut — narrow it with search or limit"
        return r

    # --- the ways in ----------------------------------------------------------------
    async def _run(self, ip: str, kind: str, read: str, cmd: str) -> tuple:
        """(ok, the device's own words) — on failure, its last line of complaint."""
        if kind not in READS:                       # a profile's operation, as its profile says
            o = self.a.kinds.profiles[kind].ops[read]
            rc, out, err = await self.a.kinds._ssh(self.a, ip, cmd, o["sudo"], o["timeout_s"])
            if rc is None or rc not in o["ok_rc"]:
                return False, _last(err) or _last(out) or ("no answer" if rc is None else f"rc {rc}")
            return True, out
        if kind == "reolink":
            return await self._reolink(ip, read)
        if kind == "homeassistant":
            return await self._ha(read)
        if kind == "mikrotik":
            ok, out = await self._routeros(ip, cmd, 45 if read == "log" else 30)
            if ok and read == "ports":
                out = trim_monitor(out)
            elif ok and read == "clients":
                out = mark_empty(out)
            return ok, out
        root = kind == "linux" and read == "log"
        return await self._ssh(ip, cmd, 60 if read in LOGS else 40, root=root)

    async def _routeros(self, ip: str, cmd: str, timeout_s: float) -> tuple:
        rc, out, err = await self.a.access.ssh(ip, cmd, user_suffix="+ct", timeout_s=timeout_s)
        if rc is None or (rc != 0 and not (out or "").strip()):
            return False, _last(err) or _last(out) or "no answer"
        return True, out

    async def _ssh(self, ip: str, cmd: str, timeout_s: float, root: bool) -> tuple:
        """By lanowl's key over its shared connection, else by the login's password — as root
        for a journal, through sudo, falling back to the login's own view when sudo says no."""
        lg = self.a.access.login(ip)
        root = root and lg is not None and (lg.user or "root") != "root"
        if root:
            rc, out, err = await self._ssh1(ip, cmd, timeout_s, True)
            if rc == 0 and (out or "").strip():
                return True, out
        rc, out, err = await self._ssh1(ip, cmd, timeout_s, False)
        if rc is None or (rc != 0 and not (out or "").strip()):
            return False, _last(err) or _last(out) or "no answer"
        return True, out

    async def _ssh1(self, ip: str, cmd: str, timeout_s: float, root: bool) -> tuple:
        if self._key_host(ip) is not None:
            return await self.a.actions._ssh_run(ip, cmd, timeout_s, root=root)
        if root:
            return await self.a.access.ssh(ip, "sudo -S -p '' sh -c " + shlex.quote(cmd),
                                           sudo_pw=True, timeout_s=timeout_s)
        return await self.a.access.ssh(ip, cmd, timeout_s=timeout_s)

    async def _reolink(self, ip: str, read: str) -> tuple:
        cmds = [{"cmd": c, "action": 0, "param": {}} for c in _REOLINK[read]]
        r = await self.a.actions.reboot._reolink(ip, cmds)
        if r.get("error"):
            return False, r["error"]
        # one line a command: the line limit then cuts whole answers, not a JSON's middle
        return True, "\n".join(json.dumps(v, ensure_ascii=False) for v in r["value"])

    async def _ha(self, read: str) -> tuple:
        rb = self.a.actions.reboot
        if read == "log":
            # through the Supervisor (Home Assistant OS); the core's own endpoint answers 404
            # in recent releases, but a Supervisor-less install may still have it
            ok, text = await self._ha_text("/api/hassio/core/logs")
            if not ok:
                ok, text = await self._ha_text("/api/error_log")
            return ok, re.sub(r"\x1b\[[0-9;]*m", "", text)
        st, j = await rb._ha("GET", "/api/config" if read == "system" else "/api/states",
                             timeout_s=20)
        if st != 200 or j is None:
            return False, f"Home Assistant's API did not answer (HTTP {st})"
        if read == "system":
            keep = ("version", "state", "safe_mode", "recovery_mode", "time_zone", "config_dir")
            return True, "\n".join(f"{k}: {j.get(k)}" for k in keep if k in j) + \
                f"\ncomponents loaded: {len(j.get('components') or [])}"
        rows = [e for e in j if isinstance(e, dict) and e.get("state") == "unavailable"]
        return True, (f"{len(rows)} unavailable of {len(j)} entities\n" + "\n".join(
            f"{e.get('entity_id')} ({(e.get('attributes') or {}).get('friendly_name', '')}) "
            f"since {e.get('last_changed', '?')}" for e in rows))

    async def _ha_text(self, path: str) -> tuple:
        import aiohttp
        rb = self.a.actions.reboot
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                async with s.get(rb.ha_url + path,
                                 headers={"Authorization": f"Bearer {rb._ha_token()}"}) as r:
                    text = await r.text()
                    if r.status != 200:
                        return False, f"Home Assistant answered HTTP {r.status}"
                    return True, text
        except Exception as e:
            return False, f"Home Assistant's API did not answer ({type(e).__name__})"


def _last(text: str) -> str:
    return ((text or "").strip().splitlines() or [""])[-1][:160]
