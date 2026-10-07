"""The LLM's tool surface — and the authorization boundary.

Only read-only tools exist. The executor rejects (a) any target not in the inventory
(WAN reachability targets are also allowed, and ping_host takes the failover's per-link
probes when they are configured) and (b) is structurally incapable of writes:
it dispatches solely to GET-style probes. This is what enforces "no unauthorized actions
on devices" even if the model hallucinates a destructive intent.

One tool is not a probe: `propose_action` (actions.py). It does not act either — it puts a
proposal in front of the owner, who approves it with a button. And `run_check` (checks.py):
read-only diagnostics from a fixed
catalog — mtr, DNS, TLS, scans, a host's health, the tunnels — that run only inside an
investigation session the owner opened with a button. Both are offered only while a model
turn is allowed to propose (`Actions.source`).

And `lanowl_records` (records.py): not the network but lanowl itself —
what it knows, did, decided and sent, everything its dashboard shows. Read-only, from memory
and its own database.
"""
from __future__ import annotations

import copy
import logging
import re
import time as _time
from typing import Any

from . import probes
from .checks import standby_note
from .model import Inventory, wan_links
from .state import StateStore
from .sinks import MqttBridge

log = logging.getLogger("lanowl.tools")


# OpenAI/Ollama-style tool specifications.
TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "ping_host",
        "description": "ICMP ping a host to check reachability. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string", "description": "IPv4 of an inventoried device or WAN target"}
        }, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "tcp_check",
        "description": "Try a TCP connection to ip:port to see if a service listens. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "port": {"type": "integer"}
        }, "required": ["ip", "port"]}}},
    {"type": "function", "function": {
        "name": "http_get",
        "description": "HTTP GET ip:port/path; returns status code. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "port": {"type": "integer"},
            "path": {"type": "string", "default": "/"}
        }, "required": ["ip", "port"]}}},
    {"type": "function", "function": {
        "name": "snmp_get",
        "description": "SNMP GET a read-only OID (default sysUpTime) from a MikroTik/SNMP device.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "oid": {"type": "string"}
        }, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "mikrotik_read",
        "description": "GET a RouterOS /rest path (e.g. 'system/resource', 'interface', "
                       "'ip/dhcp-server/lease') from a MikroTik router. Read-only GET only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "path": {"type": "string"}
        }, "required": ["ip", "path"]}}},
    {"type": "function", "function": {
        "name": "mqtt_last",
        "description": "Return recent last-values from existing home MQTT topics matching a "
                       "glob (e.g. 'shellies/#', 'zigbee2mqtt/#'). Read-only.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}
        }, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "device_forensics",
        "description": "BEST TOOL FOR A DEVICE THAT IS DOWN. You cannot query a dead host, so this "
                       "asks the INFRASTRUCTURE about it instead: router ARP state, DHCP lease and "
                       "last-seen, how its group peers are doing, and its recent history — all in one "
                       "call. Returns 'hints' that map the evidence to likely causes. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string", "description": "IPv4 of an inventoried device"}
        }, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "history_query",
        "description": "Recent up/down transitions from history, optionally for one ip.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "hours": {"type": "number", "default": 24}
        }, "required": []}}},
    {"type": "function", "function": {
        "name": "router_log",
        "description": "Search the MikroTik router's own log (its whole buffer, already fetched — "
                       "no extra load). Match a MAC, an IP, a DHCP host name or a keyword; "
                       "separate several with '|'. DHCP 'assigned'/'deassigned' lines show a "
                       "device dropping off and rejoining; a failover script's own lines show "
                       "the main internet link failing over. Read-only.",
        "parameters": {"type": "object", "properties": {
            "search": {"type": "string"}, "hours": {"type": "number", "default": 24},
            "limit": {"type": "integer", "default": 30}
        }, "required": ["search"]}}},
    {"type": "function", "function": {
        "name": "log_findings",
        "description": "What the router-log and host-log checks (the router, the watched hosts) "
                       "concluded recently about log lines that were not routine. Read-only.",
        "parameters": {"type": "object", "properties": {
            "hours": {"type": "number", "default": 24}
        }, "required": []}}},
    {"type": "function", "function": {
        "name": "wan_history",
        "description": "Internet connection history: every main-link outage the router "
                       "remembers, total blackouts and short blips, and the state right now. "
                       "Read-only.",
        "parameters": {"type": "object", "properties": {
            "days": {"type": "number", "default": 7}
        }, "required": []}}},
    {"type": "function", "function": {
        "name": "host_log",
        "description": "The RAW system journal of a host whose log lanowl reads (the VPS "
                       "203.0.113.10 and the home server 192.168.10.113): the exact lines, oldest "
                       "first. Use it when the owner asks for the log itself, or to see what "
                       "happened around a time. Optional: unit (a systemd unit, e.g. 'ssh', "
                       "'wg-quick@wg0', 'nodered'), search "
                       "(plain text, case-insensitive), hours (default 24, max 72), limit "
                       "(default 40, max 100). Internet scanner noise (failed logins) and IPsec "
                       "keepalives are left out unless noise=true. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "unit": {"type": "string"},
            "search": {"type": "string"}, "hours": {"type": "number", "default": 24},
            "limit": {"type": "integer", "default": 40},
            "noise": {"type": "boolean", "default": False}
        }, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "device_stats",
        "description": "How one device has been over several days: % of probes answered, "
                       "average latency, and every outage with its duration. Read-only.",
        "parameters": {"type": "object", "properties": {
            "ip": {"type": "string"}, "days": {"type": "number", "default": 7}
        }, "required": ["ip"]}}},
]


def link_probes(cfg: dict) -> dict:
    """{address: "main" | "backup"}: the failover's per-link probes (model.wan_links), which
    the router sends ONLY over one link. ping_host takes them too, and says which link the
    answer is about — refused as "not in inventory", a model concludes it cannot test the
    internet at all."""
    L = wan_links(cfg)
    if not L["failover"]:
        return {}
    return {ip: k for k, ip in (("main", L["main_probe"]), ("backup", L["backup_probe"])) if ip}


def _specs_for(targets: list, cfg: dict) -> list:
    """TOOL_SPECS with the addresses ping_host takes spelled out. "an inventoried device or WAN
    target" named no address, so the model guessed."""
    out = []
    L, probes_ = wan_links(cfg), link_probes(cfg)
    for t in TOOL_SPECS:
        if t["function"]["name"] == "ping_host":
            t = copy.deepcopy(t)
            t["function"]["parameters"]["properties"]["ip"]["description"] = (
                "IPv4 of an inventoried device, or a public address: "
                + (", ".join(targets) + " (the WAN targets: they go over whichever link is "
                   "active, so they answer 'is there internet')" if targets else "")
                + "".join(f"; {ip} (goes ONLY over the {L[k]}"
                          + (", which is STANDBY: it has internet only while the router has "
                             f"failed over to it, so no answer while the {L['main']} carries "
                             "traffic is normal" if k == "backup" and L["standby"] else "") + ")"
                          for ip, k in probes_.items()))
        out.append(t)
    return out


def _ip_re(ip: str):
    """An address as a whole token: '192.168.10.7' must not match '192.168.10.77'."""
    return re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d])")


_SIGNAL = re.compile(r"signal strength (-\d+)")


class ToolExecutor:
    def __init__(self, cfg: dict, inv: Inventory, mqtt: MqttBridge, state: StateStore):
        self.cfg = cfg
        self.inv = inv
        self.mqtt = mqtt
        self.state = state
        targets = list(cfg.get("wan", {}).get("targets", []))
        self.wan_targets = set(targets)
        self.specs = _specs_for(targets, cfg)
        self.links, self.link_probes = wan_links(cfg), link_probes(cfg)
        self.calls = 0
        # refreshed by the orchestrator each cycle so forensics can see current context
        self.snapshot = None      # latest Snapshot
        self.arp = None           # list of router ARP entries (or None if unavailable)
        self.leases = None        # list of DHCP leases (or None)
        # the two log watchers, wired by the orchestrator: the router log they already read,
        # and what their triage concluded. None in tests / --once.
        self.wanwatch = None
        self.hostlog = None
        # actions.py, wired by the orchestrator: None = nothing can be proposed
        self.actions = None
        # memory.py: its tools are offered only inside the owner's own conversation
        self.memory = None
        # shell.py: the sandbox's shell, the same — and only while it is isolated
        self.shell = None
        self.shell_audit = None   # ...the audit's offline one, in the audit's turn only
        # records.py: lanowl's own records (every model turn with tools)
        self.records = None
        # cves.py: one CVE looked up (NVD, the machine's own build) — every turn with
        # tools, like the records: it reads, and only a CVE id and package versions leave
        self.cves = None

    def tool_specs(self) -> list:
        """What the model is offered this turn: the read-only tools, plus `propose_action`
        and `run_check` while the turn is allowed to propose, plus the memory's tools while
        it is the owner's conversation. lanowl's own records are always there: reading
        what it knows and decided is never a risk."""
        out = self.specs
        if self.records is not None:
            out = out + [self.records.spec()]
        if self.cves is not None:
            out = out + [self.cves.spec()]
        if self.actions is not None and self.actions.offered():
            out = out + [self.actions.spec(), self.actions.check_spec()]
        if self.memory is not None and self.memory.offered():
            out = out + self.memory.specs()
        sh = self._shell()
        if sh is not None:
            out = out + [sh.spec()]
        return out

    def _shell(self):
        """The shell on offer this turn: the owner's in their question, the offline one in
        the audit — never both (the model takes one turn at a time)."""
        for sh in (self.shell, self.shell_audit):
            if sh is not None and sh.offered():
                return sh
        return None

    def _router_evidence(self, ip: str, mac: str, hours: float = 24) -> dict:
        """What the router's own log says about one device, and whether it was alone.

        The router writes a DHCP 'deassigned'/'assigned' pair every time a device drops off
        and comes back, and a wireless line with the signal strength for the guest Wi-Fi it
        serves itself. Behind other APs the DHCP churn is the whole story — but it is a good
        one: a boiler, two temperature sensors and an ESP rejoining within two seconds of each
        other is an access point restarting or a power flicker, and no single device's fault."""
        ww = self.wanwatch
        rows = list(getattr(ww, "log_rows", None) or [])
        if not rows:
            return {"unavailable": "router log not read yet"}
        since = _time.time() - hours * 3600
        ipr = _ip_re(ip)
        macl = mac.lower()
        mine, rejoins = [], []
        for t, x in rows:
            ts = t.timestamp()
            if ts < since:
                continue
            msg = x.get("message") or ""
            if (macl and macl in msg.lower()) or ipr.search(msg):
                mine.append((t, msg))
                if " assigned " in msg:
                    rejoins.append(ts)
        out = {"lines_24h": len(mine), "dhcp_rejoins": len(rejoins),
               "recent": [{"time": t.strftime("%Y-%m-%d %H:%M:%S"), "message": m[:160]}
                          for t, m in mine[-8:]]}
        sig = [int(s) for _, m in mine for s in _SIGNAL.findall(m)]
        if sig:
            out["wifi_signal_dbm_last"] = sig[-1]
        # Did it rejoin together with others? Look around its last three rejoins.
        together = []
        for rts in rejoins[-3:]:
            others = set()
            for t, x in rows:
                ts = t.timestamp()
                if abs(ts - rts) > 30:
                    continue
                msg = x.get("message") or ""
                if " assigned " in msg and not ((macl and macl in msg.lower()) or ipr.search(msg)):
                    m = re.search(r"assigned (\S+) for (\S+)\s*(\S*)", msg)
                    if m:
                        dev = self.inv.get(m.group(1))
                        others.add(dev.name if dev else (m.group(3) or m.group(1)))
            if others:
                together.append({"at": _time.strftime("%H:%M:%S", _time.localtime(rts)),
                                 "with": sorted(others)[:8], "count": len(others)})
        if together:
            out["rejoined_with_others"] = together
        return out

    async def _forensics(self, ip: str) -> dict:
        """Ask the infrastructure about a device instead of the device itself."""
        import time as _t
        dev = self.inv.get(ip)
        out = {"ip": ip, "name": dev.name if dev else "?",
               "group": dev.group if dev else "?",
               "criticality": dev.criticality if dev else "?"}
        if dev is not None and dev.attrs.get("kind"):
            out["kind"] = str(dev.attrs["kind"])          # what it is (kinds.py)
        mac = (dev.attrs.get("mac") or "").upper() if dev else ""

        # --- current probe state
        cur = self.snapshot.by_ip(ip) if self.snapshot else None
        probe_up = bool(cur.up) if cur else None
        out["probe"] = {"up": probe_up,
                        "failed_checks": cur.failed_services() if cur else None}

        # --- router ARP
        arp_entry = None
        if self.arp is not None:
            for a in self.arp:
                if a.get("address") == ip:
                    arp_entry = a
                    break
            out["arp"] = ({"present": True, "status": arp_entry.get("status"),
                           "mac": arp_entry.get("mac-address"),
                           "interface": arp_entry.get("interface")}
                          if arp_entry else {"present": False})
        else:
            out["arp"] = {"unavailable": "router ARP not readable"}

        # --- DHCP lease
        lease = None
        if self.leases is not None:
            for l in self.leases:
                if l.get("address") == ip or (mac and (l.get("mac-address") or "").upper() == mac):
                    lease = l
                    break
            out["dhcp"] = ({"lease": lease.get("status"), "last_seen": lease.get("last-seen"),
                            "address": lease.get("address"), "host_name": lease.get("host-name")}
                           if lease else {"lease": "none (static or never leased)"})
        else:
            out["dhcp"] = {"unavailable": "lease table not readable"}

        # --- group peers (is the whole segment dark?)
        if dev and self.snapshot:
            peers = [d for d in self.snapshot.devices if d.group == dev.group and d.ip != ip]
            down = [d.name for d in peers if not d.up]
            out["group_peers"] = {"group": dev.group, "total": len(peers),
                                  "down": len(down), "down_names": down[:6]}

        # --- history
        now = _t.time()
        out["history"] = {
            "uptime_pct_24h": self.state.uptime_pct(ip, now - 86400),
            "transitions_24h": len(self.state.recent_transitions(now - 86400, ip=ip, limit=100)),
            "recent": self.state.recent_transitions(now - 6 * 3600, ip=ip, limit=6),
        }

        # --- reached through something else? (`depends_on`: the WireGuard sites)
        parent_ip = str(dev.attrs.get("depends_on") or "") if dev else ""
        parent_up = None
        if parent_ip:
            if parent_ip == "wan":
                parent_up = bool(self.snapshot.wan_ok) if self.snapshot else None
                out["depends_on"] = {"ip": "wan", "name": "Internet / WAN", "up": parent_up}
            else:
                pd = self.inv.get(parent_ip)
                pc = self.snapshot.by_ip(parent_ip) if self.snapshot else None
                parent_up = bool(pc.up) if pc else None
                out["depends_on"] = {"ip": parent_ip, "name": pd.name if pd else "?",
                                     "up": parent_up}

        # --- the router's own log about it (LAN devices only; see _router_evidence)
        if not parent_ip and (mac or ip):
            out["router_log"] = self._router_evidence(ip, mac)

        # --- deterministic hints (evidence -> likely cause). The model still decides.
        hints = []
        rl = out.get("router_log") or {}
        for tg in rl.get("rejoined_with_others") or []:
            if tg["count"] >= 2:
                hints.append("It rejoined the network at %s together with %d other device(s) "
                             "(%s) -> a SHARED event: an access point restarting or a power "
                             "flicker, not this device." % (tg["at"], tg["count"],
                                                            ", ".join(tg["with"][:4])))
                break
        if rl.get("dhcp_rejoins", 0) >= 4:
            hints.append("The router saw it drop off and rejoin %d times in 24h -> an unstable "
                         "Wi-Fi link or power supply." % rl["dhcp_rejoins"])
        if rl.get("wifi_signal_dbm_last") is not None and rl["wifi_signal_dbm_last"] <= -80:
            hints.append("Its last Wi-Fi signal was %d dBm -> weak coverage where it sits."
                         % rl["wifi_signal_dbm_last"])
        arp_status = (out.get("arp") or {}).get("status")
        if parent_ip:
            # Not on the LAN: the router's ARP/DHCP tables say nothing about it, and the
            # only question that matters is whether the way to it is open.
            out["arp"] = {"not_applicable": "remote device — reached through a tunnel, "
                                            "never on the LAN"}
            out["dhcp"] = {"not_applicable": "remote device — no lease on the main router"}
            arp_status = None
            if probe_up is False:
                if parent_up is False:
                    hints.append("It is reached through %s, which is DOWN -> this is a "
                                 "consequence of that, not a separate fault."
                                 % out["depends_on"]["name"])
                elif parent_up:
                    hints.append("It is reached through %s, which is UP -> the way to it is "
                                 "open; the fault is at the remote site itself (power, its "
                                 "ISP, its own tunnel). Nothing in this house can fix it."
                                 % out["depends_on"]["name"])
        if probe_up is False and not parent_ip:     # LAN evidence: not for a remote device
            if arp_status == "reachable":
                hints.append("ARP is 'reachable' but probes fail -> the HOST IS ALIVE; suspect a "
                             "firewall/service problem or ICMP blocked, NOT a dead device.")
            elif arp_status in ("stale", "delay"):
                hints.append("ARP entry exists but is stale -> device dropped off recently "
                             "(power loss, Wi-Fi drop, or reboot).")
            elif (out.get("arp") or {}).get("present") is False:
                hints.append("No ARP entry at all -> device has been off/absent for a while, "
                             "or never joined this segment.")
            if lease and lease.get("status") == "bound":
                hints.append("DHCP lease still bound (last-seen %s) -> the router saw it recently."
                             % lease.get("last-seen"))
            gp = out.get("group_peers") or {}
            if gp.get("total"):
                # note: down == 0 is the most informative case (isolated fault), so this
                # must not be gated on there being any peers down.
                if gp["down"] and gp["down"] * 2 >= gp["total"]:
                    hints.append("Most peers in the same group are ALSO down -> suspect a shared "
                                 "upstream cause (AP, switch, PoE, power) rather than this device.")
                else:
                    hints.append("Group peers are up (%d/%d) -> the fault is specific to this device."
                                 % (gp["total"] - gp["down"], gp["total"]))
        elif probe_up:
            hints.append("Device is currently answering probes.")
        up24 = out["history"]["uptime_pct_24h"]
        if up24 is not None and up24 < 90:
            hints.append("Only %.1f%% reachable over 24h -> chronically unstable, not a one-off."
                         % up24)
        out["hints"] = hints
        return out

    def _target_allowed(self, ip: str) -> bool:
        return self.inv.is_known(ip) or ip in self.wan_targets

    def _refusal(self, name: str, ip: str) -> str:
        """Why, and what it would take: a bare "not in inventory" had the model tell the owner
        it could not ping at all."""
        ok = sorted(self.wan_targets) + ([f"{ip} ({self.links[k]} only)" for ip, k in self.link_probes.items()]
                                         if name == "ping_host" else [])
        return (f"refused: {ip} is not an inventory device"
                + (f"; the public addresses {name} takes are {', '.join(ok)}" if ok else "")
                + " (read-only, listed targets only)")

    def _link_ping(self, ip: str, r) -> dict:
        """What a ping of a per-link probe means, with which link carries traffic now."""
        link = self.link_probes[ip]
        L = self.links
        p = getattr(self.wanwatch, "path", None) or {}
        ob = bool(p["on_backup"]) if "on_backup" in p else None
        active = {True: f"the {L['backup']}", False: f"the {L['main']}"}.get(ob, "unknown")
        if link == "main" and r.ok:
            why = f"the {L['main']} itself answers" + (f" (the network is still on the {L['backup']} "
                                                       "right now)" if ob else "")
        elif link == "main":
            why = (f"no answer — the network is on the {L['backup']}: this is the {L['main']} "
                   "outage the failover covers" if ob else
                   "no answer (2 pings) — compare with the WAN targets before calling the "
                   f"{L['main']} down")
        elif r.ok:
            why = f"the {L['backup']}'s uplink answers"
        else:
            note = standby_note(ob, L)
            why = (f"no answer — {note}" if note else
                   f"no answer while the network is ON the {L['backup']}: the backup link is failing too"
                   if ob else f"no answer — the {L['backup']} does not answer")
        return {"link": L[link], "active_link_now": active,
                "meaning": f"{ip} goes only over the {L[link]}: {why}"}

    def _findings(self, hours: float) -> list:
        since = _time.time() - hours * 3600
        out = []
        for src in (self.wanwatch, self.hostlog):
            for f in (getattr(src, "findings", None) or []):
                if f.get("ts", 0) >= since:
                    out.append({**f, "at": _time.strftime("%d/%m %H:%M", _time.localtime(f["ts"]))})
        out.sort(key=lambda f: f["ts"], reverse=True)
        return out[:30]

    def _wan_history(self, days: float) -> dict:
        now = _time.time()
        since = now - days * 86400
        ww = self.wanwatch
        outages = []
        if ww is not None:
            for s, e in ww.outages_from_log():
                if s.timestamp() >= since:
                    outages.append({"start": s.strftime("%Y-%m-%d %H:%M:%S"),
                                    "seconds": round((e - s).total_seconds())})
        # one per moment (a short one recorded as a blip AND a blackout is the blip),
        # each with the code's reading of where it broke (wanexplain.py)
        from . import wanexplain
        black = []
        if hasattr(self.state, "events"):
            evs = wanexplain.evidence(self.state, since - 60)
            nw = getattr(ww, "netwatch", None)
            for e in reversed(wanexplain.moments(self.state, since)):
                if e["kind"] == "main-outage":
                    continue
                v = wanexplain.verdict(e, wanexplain.find(evs, e["ts"]), nw, links=self.links)
                black.append({"start": _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(e["ts"])),
                              "seconds": round(e["s"]), "kind": e["kind"], "where_it_broke": v["short"]})
        first = self.state.first_event_ts() if hasattr(self.state, "first_event_ts") else None
        if ww is None or not ww.log_rows:
            # Not read yet (a `--once` run, or the first minute after a start). An empty list
            # here was read as "no outages in 3 days" by the first audit that saw it.
            return {"main_outages": None,
                    "note": "UNKNOWN: the router log has not been read yet — this is missing "
                            "data, not zero outages. Say you cannot tell.",
                    "total_blackouts_and_blips": black[:40]}
        covers = ww.log_rows[0][0]
        out = {
            "main_outages": outages[-60:],
            "main_outages_count": len(outages),
            "main_down_total_s": sum(o["seconds"] for o in outages),
            "router_log_covers_from": covers.strftime("%Y-%m-%d %H:%M"),
            "total_blackouts_and_blips": black[:40],
            "blackout_history_starts": (_time.strftime("%Y-%m-%d", _time.localtime(first))
                                        if first else "today"),
            "now": ww.snapshot_state(),
        }
        # A log that starts inside the window. The router keeps its last ~10,000 lines in
        # memory and a restart empties it: right after an upgrade it holds a few hours, the list
        # above is empty, and a model will say "no outages in the last 3 days" unless told —
        # a `router_log_covers_from` beside it is not enough.
        if covers.timestamp() > since + 3600:
            hm = covers.strftime("%d/%m %H:%M")
            flaps = (", and flaps_24h under 'now' counts only since then"
                     if covers.timestamp() > now - 86400 else "")
            out["note"] = (f"UNKNOWN before {hm}: the router's log starts there (it keeps its "
                           f"last ~10,000 lines in memory, and a restart empties it). Main-link "
                           f"outages before {hm} are missing data, not zero{flaps}: say "
                           f"'none since {hm}', never 'none in {days:g} days'.")
        return out

    def _device_stats(self, ip: str, days: float) -> dict:
        now = _time.time()
        since = now - days * 86400
        dev = self.inv.get(ip)
        r = self.state.conn.execute(
            "SELECT COUNT(*) n, SUM(up) u, AVG(latency) lat FROM samples WHERE ip=? AND ts>=?",
            (ip, since)).fetchone()
        book = self.state.logbook(since, ip=ip, limit=40)
        return {
            "device": dev.name if dev else ip, "ip": ip, "days": days,
            "uptime_pct": round(100.0 * (r["u"] or 0) / r["n"], 1) if r["n"] else None,
            "avg_latency_ms": round(r["lat"], 1) if r["lat"] else None,
            "outages": [{"at": _time.strftime("%d/%m %H:%M", _time.localtime(e["ts"])),
                         "kind": e["kind"],
                         "down_min": (round(e["down_for"] / 60) if e.get("down_for") else None)}
                        for e in book],
        }

    async def call(self, name: str, args: dict) -> dict:
        self.calls += 1
        import time as _t

        if name == "propose_action":
            if self.actions is None or not self.actions.offered():
                return {"tool": name, "error": "proposing actions is not available here"}
            return {"tool": name, "result": await self.actions.propose(args)}
        if name == "run_check":
            if self.actions is None or not self.actions.offered():
                return {"tool": name, "error": "checks are not available here"}
            return {"tool": name, "result": await self.actions.run_check(args)}
        if name == "shell":
            sh = self._shell() or self.shell
            if sh is None:
                return {"tool": name, "error": "there is no shell here"}
            return {"tool": name, "result": await sh.call(args)}
        if name in ("remember", "update_memory", "forget_memory"):
            if self.memory is None or not self.memory.offered():
                return {"tool": name, "error": "memory can only be written in a conversation "
                                               "with the owner"}
            return {"tool": name, "result": self.memory.call(name, args)}

        if name == "cve_lookup":
            if self.cves is None:
                return {"tool": name, "error": "CVE lookups are not available here"}
            return {"tool": name, "result": await self.cves.lookup(str(args.get("cve") or ""),
                                                                   str(args.get("ip") or ""))}

        if name == "lanowl_records":
            if self.records is None:
                return {"tool": name, "error": "lanowl's records are not available here"}
            return {"tool": name, "result": self.records.call(args)}

        # log/history read tools (no host target)
        if name == "host_log":
            if self.hostlog is None or not self.hostlog.enabled:
                return {"tool": name, "error": "host logs are not read by this lanowl"}
            try:
                hours = float(args.get("hours", 24) or 24)
                limit = int(args.get("limit", 40) or 40)
            except (TypeError, ValueError):
                return {"tool": name, "error": "hours and limit must be numbers"}
            return {"tool": name, "result": await self.hostlog.read_log(
                str(args.get("ip", "")), hours=hours, search=str(args.get("search") or ""),
                unit=str(args.get("unit") or ""), limit=limit,
                noise=bool(args.get("noise", False)))}
        if name == "router_log":
            if self.wanwatch is None:
                return {"tool": name, "error": "router log not available"}
            hours = float(args.get("hours", 24) or 24)
            return {"tool": name, "result": self.wanwatch.router_log(
                str(args.get("search", "")), _t.time() - hours * 3600,
                min(int(args.get("limit", 30) or 30), 80))}
        if name == "log_findings":
            return {"tool": name, "result": self._findings(float(args.get("hours", 24) or 24))}
        if name == "wan_history":
            return {"tool": name,
                    "result": self._wan_history(min(float(args.get("days", 7) or 7), 14))}
        if name == "device_stats":
            ip = str(args.get("ip", ""))
            if not self.inv.is_known(ip):
                return {"tool": name, "error": f"unknown device {ip}"}
            return {"tool": name,
                    "result": self._device_stats(ip, min(float(args.get("days", 7) or 7), 14))}

        # glob-pattern read tools (no host target)
        if name == "mqtt_last":
            pattern = str(args.get("pattern", "#"))
            return {"tool": name, "result": self.mqtt.last(pattern)}
        if name == "history_query":
            ip = args.get("ip")
            hours = float(args.get("hours", 24))
            since = _t.time() - hours * 3600
            if ip and not self._target_allowed(ip):
                return {"tool": name, "error": f"unknown device {ip}"}
            return {"tool": name, "result": self.state.recent_transitions(since, ip=ip, limit=50)}

        # host-targeted read tools -> enforce whitelist
        ip = str(args.get("ip", ""))
        per_link = name == "ping_host" and ip in self.link_probes
        if not per_link and not self._target_allowed(ip):
            return {"tool": name, "error": self._refusal(name, ip)}

        if name == "device_forensics":
            return {"tool": name, "result": await self._forensics(ip)}

        p = self.cfg.get("probes", {})
        if name == "ping_host":
            r = await probes.ping(ip, p.get("icmp_timeout_ms", 1000))
        elif name == "tcp_check":
            r = await probes.tcp_check(ip, int(args["port"]), p.get("tcp_timeout_ms", 1500))
        elif name == "http_get":
            r = await probes.http_check(ip, int(args["port"]), str(args.get("path", "/") or "/"),
                                        p.get("http_timeout_ms", 4000))
        elif name == "snmp_get":
            community = p.get("snmp_community", "public")
            r = await probes.snmp_get(ip, str(args.get("oid") or probes.OID_SYSUPTIME),
                                      community, p.get("snmp_timeout_s", 2))
        elif name == "mikrotik_read":
            # the router's read-only login, from secrets.yaml (resolve_mikrotik)
            from . import routeros
            from .discovery import resolve_mikrotik
            mk = self.cfg.get("mikrotik", {})
            user, pw = resolve_mikrotik(self.cfg)
            dev = self.inv.get(ip)
            base = (dev.attrs.get("mikrotik_rest") if dev else None) or f"http://{ip}"
            path = str(args.get("path", "system/resource"))
            router = routeros.shared(self.cfg)
            if ip == router.host:
                r = await router.read(path)      # the main router: its kept API connection
            else:
                r = await probes.mikrotik_rest(base, path, user, pw, mk.get("verify_tls", False))
        else:
            return {"tool": name, "error": f"unknown tool {name}"}

        res = {"ok": r.ok, "detail": r.detail, "latency_ms": r.latency_ms, "data": r.data}
        if per_link:
            res.update(self._link_ping(ip, r))
        return {"tool": name, "result": res}
