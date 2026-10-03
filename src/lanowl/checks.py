"""Diagnostics the model can run inside an investigation session the owner approved.

A network auditor needs more than pings when something is going wrong. One button opens a
short window (actions.session) in which the model runs checks from this catalog on its own,
reads each output and decides the next, the way a person at a terminal would. Anything that CHANGES something is not here:
restarts and reboots are actions (actions.py) and keep their own button even inside
a session.

Why a catalog and not a shell: lanowl's container holds the ssh keys, the logins, the bot
token and the LAN, where a Shelly switches a relay on a plain GET; and the model reads text
strangers write (a public server's auth log, DHCP host names, HTTP bodies). (Its free shell
is a separate sandbox holding none of that: shell.py.) So every check is a fixed program with fixed flags, and the model only fills typed
slots — an address, a name, a port list, a unit — each validated here before anything runs.
Local programs are exec'd without a shell; remote ones run over the host-log ssh connection
with every slot shlex-quoted (and already restricted to characters no shell cares about).

Four places to look from:
  here    lanowl's container on its own host (`observer.host_ip`). With host networking on
          Linux it has the host's real stack, so mtr/traceroute see every hop; behind Docker
          Desktop's NAT every hop answers as the target and per-hop checks are blind. On the
          real wire `arping` and `capture` (tcpdump, headers only) are worth having too;
  lan     another host ON the LAN (`actions.checks.home_server`), a second vantage point.
          If both are VMs on one hypervisor, comparing them tells lanowl's own stack from the
          LAN, but not the hypervisor's uplink from the network;
  vps     a public server (`actions.checks.vps`): the internet's view of the network, and the
          tunnels' own state;
  router  the main router, over its kept API connection (REST while that is down).
          Read-level commands work with lanowl's user; ping, traceroute and ip-scan need its
          group to have the `test` policy, torch `sniff`, and each is only offered once it works.

Per-link checks (with a backup internet link: model.wan_links) need no router help when the
router's own rules send one address ONLY over each link (`wan.path.main_probe` /
`backup_probe`, typically its failover's health probes). A STANDBY backup switches its own
uplink on only when the router selects it as the WAN: while the main link carries traffic, its
probe not answering is how it should be, not "dead". So the checks read which link is active
(`wanwatch.path`) and say "standby" instead.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import shlex
import time
import xml.etree.ElementTree as ET
from typing import Optional

from .report import label
from .model import main_lans, router_host, wan_links

log = logging.getLogger("lanowl.checks")

OUT_MAX = 3500          # characters of output the model is shown per check
KEEP_OUT = 2500         # ...and kept on the session record, for the dashboard
ROUTER_TEST_TTL_S = 600

_IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:-]{0,63}$")
_IFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,31}$")
_DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR", "SRV", "CAA")


def standby_note(on_backup: Optional[bool], links: dict) -> str:
    """Why the backup link not answering may be fine, in words, for a state of the WAN path
    (`wanwatch.path["on_backup"]`, None = unknown; `links`: model.wan_links). "" = its silence
    is a real fault: it is carrying the traffic, or it is not a standby link at all. The
    model's plain ping_host says the same (tools.py)."""
    if not links.get("standby"):
        return ""
    if on_backup is False:
        return (f"standby — expected: the {links['main']} carries traffic, and the {links['backup']} "
                "turns its uplink on only when the router fails over to it")
    if on_backup is None:
        return f"which link is active is unknown; the {links['backup']} only has internet while it is the active link"
    return ""


class CheckError(ValueError):
    """Why a check will not run — said to the model as is."""


async def _exec(argv: list, timeout_s: float, stdin: Optional[bytes] = None,
                env: Optional[dict] = None) -> tuple:
    """(returncode, stdout, stderr) of a program run WITHOUT a shell; rc None = did not run.
    stdin is /dev/null unless given: openssl s_client, for one, waits on an open stdin.
    `env` replaces the environment (access.py hands ssh its askpass that way)."""
    try:
        p = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            env=env)
    except (FileNotFoundError, PermissionError) as e:
        return None, "", f"{argv[0]} is not installed here ({type(e).__name__})"
    try:
        out, err = await asyncio.wait_for(p.communicate(stdin), timeout=timeout_s)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            p.kill()
        return None, "", f"no answer within {timeout_s:.0f}s"
    return p.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def parse_nmap_xml(text: str) -> Optional[list]:
    """nmap -oX: [{port, proto, state, service, version}] for every port it reported, or None
    if the output is not nmap XML."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    out = []
    for port in root.iter("port"):
        st = port.find("state")
        sv = port.find("service")
        ver = " ".join(x for x in ((sv.get("product") if sv is not None else ""),
                                    (sv.get("version") if sv is not None else ""),
                                    (sv.get("extrainfo") if sv is not None else "")) if x)
        out.append({"port": int(port.get("portid") or 0), "proto": port.get("protocol") or "tcp",
                    "state": st.get("state") if st is not None else "?",
                    "service": (sv.get("name") if sv is not None else "") or "",
                    "version": ver})
    return out


def clip(text: str, n: int = OUT_MAX) -> str:
    text = (text or "").strip()
    if len(text) <= n:
        return text
    return text[:n].rstrip() + f"\n[… {len(text) - n} more characters cut]"


# --- the catalog ------------------------------------------------------------------------
# name -> where it runs, what the model reads about it (one line: its slots, then what it
# answers), and how long it may take. `test`: needs the router user's `test` policy.
# `deny`: inventory groups it never touches. Order is the order the model reads them in.
CATALOG = {
    # here: lanowl's own container
    "ping":           {"where": "here", "t": 30, "d": "target[, count≤30] — loss and latency, 10 pings by default"},
    "link_test":      {"where": "here", "t": 30, "d": "link=main|backup|both — each internet link on its own, through an address the router sends only over that link. A STANDBY backup turns its uplink on only when the router fails over to it, so no answer from it while the main link carries traffic is NORMAL, not a fault"},
    "mtr":            {"where": "here", "t": 90, "d": "target[, count≤30] — loss and latency at every hop: WHERE along the path it breaks"},
    "traceroute":     {"where": "here", "t": 70, "d": "target[, mode=icmp|udp|tcp, port] — the path hop by hop, when mtr is blocked (tcp: through firewalls that drop the rest)"},
    "dns_compare":    {"where": "here", "t": 20, "d": "name[, type] — the same lookup from the router's DNS, Quad9, Cloudflare and Google: is the router's DNS broken or different?"},
    "dns_trace":      {"where": "here", "t": 45, "d": "name[, type] — dig +trace from the root: where resolution fails"},
    "http_timing":    {"where": "here", "t": 20, "d": "target[, port, mode=https|http] — GET / once: status, DNS/connect/TLS/first-byte times"},
    "tls_cert":       {"where": "here", "t": 20, "d": "target[, port=443] — certificate subject, issuer, expiry, and whether it verifies"},
    "port_check":     {"where": "here", "t": 60, "d": "device, ports (≤20) — open / closed / filtered, without nmap"},
    "whois":          {"where": "here", "t": 25, "d": "target (a public address) — who owns it: network, organisation, country, abuse contact"},
    "public_ip":      {"where": "here", "t": 15, "d": "— the network's public address and ISP right now, i.e. which link is carrying traffic"},
    "speed_test":     {"where": "here", "t": 50, "d": "— download speed of the active link (25 MB from Cloudflare)"},
    "arping":         {"where": "here", "t": 20, "d": "device (LAN)[, count≤10] — ARP ping from here: is it on the wire even if it ignores ICMP and every port (sleeping phones, some IoT)? Its MAC too"},
    "capture":        {"where": "here", "t": 35, "d": "[target (an address to filter on), port, proto=tcp|udp|icmp|arp, count≤100, seconds≤20] — tcpdump on this host's LAN interface: packet headers only, never contents; lanowl's own ssh is left out"},
    "ping_sweep":     {"where": "here", "t": 60, "d": "subnet (/24 or smaller, on a known network: the main LAN's, a site's) — which addresses answer; names the known ones, lists the strangers and the inventory devices that stayed silent"},
    "nmap_ports":     {"where": "here", "t": 180, "deny": ["security"], "d": "device — open TCP ports among the top 100"},
    "nmap_services":  {"where": "here", "t": 240, "deny": ["security", "iot"], "d": "device, ports (≤10) — what software answers on them (versions)"},
    "nmap_all_ports": {"where": "here", "t": 420, "deny": ["security", "iot"], "d": "device — every TCP port 1-65535 (takes minutes)"},
    "nmap_tls":       {"where": "here", "t": 180, "deny": ["security", "iot"], "d": "device, ports (≤5) — TLS certificate and cipher suites offered"},
    # router: the main router (routeros.py)
    "router_port":    {"where": "router", "t": 20, "d": "iface (e.g. ether1) — link state, speed/duplex, live traffic, error counters and link-downs of one router interface"},
    "router_ping":    {"where": "router", "t": 30, "needs": "test", "d": "target[, count≤10] — ping FROM the router itself"},
    "router_traceroute": {"where": "router", "t": 60, "needs": "test", "d": "target — traceroute from the router"},
    "router_arp_ping": {"where": "router", "t": 20, "needs": "test", "d": "device (LAN) — ARP ping: is it on the wire even if it ignores ICMP (sleeping phones, some IoT)?"},
    "router_torch":   {"where": "router", "t": 30, "needs": "sniff", "d": "iface[, seconds≤10] — the busiest flows on an interface right now. Use bridge-lan to see WHICH LAN device is using the bandwidth; a WAN port only shows the router's public address, after NAT"},
    "router_ip_scan": {"where": "router", "t": 30, "needs": "test", "d": "subnet[, seconds≤10] — what answers on the wire (ARP), from the router"},
    # lan: another host ON the LAN (actions.checks.home_server)
    "lan_ping":       {"where": "lan", "t": 30, "d": "target[, count≤30] — the same ping from the LAN host: compare with `ping` to tell lanowl's own host from the network"},
    "lan_mtr":        {"where": "lan", "t": 90, "d": "target[, count≤30] — mtr from the LAN host"},
    "lan_traceroute": {"where": "lan", "t": 70, "d": "target — traceroute from the LAN host"},
    "lan_dns":        {"where": "lan", "t": 20, "d": "name[, type] — the lookup from the LAN host, with its own resolver and with the router's"},
    "lan_neighbors":  {"where": "lan", "t": 15, "d": "— the LAN host's ARP/neighbour table: which LAN devices are reachable at layer 2, stale or FAILED"},
    # host: the LAN host or the VPS, by `host`
    "host_health":    {"where": "host", "t": 25, "d": "host — load, memory, disks, failed systemd units, busiest processes"},
    "unit_status":    {"where": "host", "t": 20, "d": "host, unit — `systemctl status` of one service with its last lines"},
    "host_net":       {"where": "host", "t": 20, "d": "host — addresses, routes, listening sockets, connection counts"},
    "nic_stats":      {"where": "host", "t": 20, "d": "host — per-interface packet, error and drop counters"},
    # vps: a public server (actions.checks.vps): the internet's view of the network, and the tunnels
    "outside_ping":   {"where": "vps", "t": 30, "d": "target[, count≤30] — ping from the VPS, i.e. from the internet (the network's public address, a remote site)"},
    "outside_mtr":    {"where": "vps", "t": 90, "d": "target[, count≤30] — mtr from the VPS towards the network or anything else"},
    "outside_traceroute": {"where": "vps", "t": 70, "d": "target — traceroute from the VPS"},
    "wg_status":      {"where": "vps", "t": 20, "d": "— every WireGuard peer on the hub: endpoint, last handshake, traffic (every site and phone)"},
    "vps_capture":    {"where": "vps", "t": 35, "d": "iface[, target (an address to filter on), port, proto=tcp|udp|icmp, count≤100, seconds≤20] — tcpdump summary on the VPS (its WAN interface, wg0); ssh is left out"},
    # a remote site's own router (sites.py): OpenWrt or MikroTik — over the tunnels, with the
    # logins in secrets.yaml
    "site_ping":      {"where": "site", "t": 40, "d": "site, target[, count≤10] — ping FROM that site's router: is its internet up, does a device on its network answer?"},
    "site_dhcp":      {"where": "site", "t": 30, "d": "site — who is on that site's DHCP right now: address, MAC, name"},
    "site_speed_test": {"where": "site", "t": 120, "d": "site — that site's internet download speed (10 MB, timed on its router). It uses THEIR bandwidth: only when the owner asks for it"},
}
# The checks the hourly audit may run by itself, with no session:
# PASSIVE — they look at a path, a resolver, a certificate, a tunnel's or a host's state, and
# send a handful of packets at most. Not here, and still behind a session: nmap and port
# scans, sweeps, packet captures (they read traffic), torch, the 25 MB speed test.
PASSIVE = frozenset({
    "ping", "link_test", "mtr", "traceroute", "dns_compare", "dns_trace", "http_timing",
    "tls_cert", "whois", "public_ip", "arping",
    "router_port", "router_ping", "router_traceroute", "router_arp_ping",
    "lan_ping", "lan_mtr", "lan_traceroute", "lan_dns", "lan_neighbors",
    "host_health", "unit_status", "host_net", "nic_stats",
    "outside_ping", "outside_mtr", "outside_traceroute", "wg_status",
    "site_ping", "site_dhcp",
})
# "here" is filled in per instance from observer.host_ip
WHERE_WORDS = {"here": "from here", "lan": "from the LAN host", "vps": "from the VPS", "router": "on the router",
               "site": "on a remote site's router"}


class Checks:
    def __init__(self, auditor):
        self.a = auditor
        self.cfg = auditor.cfg
        c = (self.cfg.get("actions") or {}).get("checks") or {}
        self.deny_extra = c.get("deny_groups") or {}          # {check: [groups]} on top of CATALOG
        self.lan_nets = main_lans(self.cfg)
        self.home_server = str(c.get("home_server") or "")          # another LAN vantage point
        host = str((self.cfg.get("observer") or {}).get("host_ip") or "")
        self.here = f"lanowl's host ({host})" if host else "lanowl's host"
        self.where_words = dict(WHERE_WORDS)
        self.vps_iface = str(c.get("vps_iface") or "eth0")
        self.vps = str(c.get("vps") or "")                          # the outside vantage point
        self.bridge = str(c.get("router_lan_bridge") or "bridge-lan")
        self.router_dns = str(c.get("router_dns") or router_host(self.cfg))
        self.links = wan_links(self.cfg)
        # Can lanowl's router user run the router's tools? None = not probed yet. `test`: ping,
        # traceroute, arp-ping, ip-scan. `sniff`: torch (RouterOS files torch under the packet
        # sniffer's policy, not under `test`).
        self.router_test: Optional[bool] = None
        self.router_sniff: Optional[bool] = None
        self._router_test_at = 0.0

    def _on_backup(self) -> Optional[bool]:
        """Is the network on the backup link right now? None = the WAN watcher does not know."""
        p = getattr(getattr(self.a, "wanwatch", None), "path", None) or {}
        return bool(p["on_backup"]) if "on_backup" in p else None

    def _standby(self) -> str:
        """Why the backup link not answering may be fine, in words, for the current state."""
        return standby_note(self._on_backup(), self.links)

    def _link_test_ok(self) -> bool:
        """link_test needs a backup link and an address that goes only over each link."""
        L = self.links
        return bool(L["failover"] and L["main_probe"] and L["backup_probe"])

    # --- what the model reads -------------------------------------------------
    def available(self) -> list:
        """The checks on offer now: the router's test-policy ones only once it allows them."""
        can = {"test": self.router_test, "sniff": self.router_sniff}
        where_ok = {"lan": bool(self.home_server), "vps": bool(self.vps),
                    "host": bool(self.home_server or self.vps)}
        return [n for n, c in CATALOG.items() if (not c.get("needs") or can.get(c["needs"]))
                and where_ok.get(c["where"], True)
                and (n != "link_test" or self._link_test_ok())]

    def describe(self) -> str:
        lines = []
        for n in self.available():
            c = CATALOG[n]
            lines.append(f"{n} ({self.where_words.get(c['where'], 'on the LAN host or the VPS')}): {c['d']}")
        return "\n".join(lines)

    def vantage_words(self) -> str:
        """The places the checks can look from, as configured: the model compares them."""
        out = [f"{self.here} (here)"]
        if self.home_server:
            out.append(f"the LAN host {self.home_server} (on the LAN)")
        if self.vps:
            out.append(f"the VPS {self.vps} (the internet)")
        return ", ".join(out + ["the router"])

    # --- the router's test policy ----------------------------------------------
    async def refresh_router_test(self, force: bool = False):
        """Can this user run the router's tools? Found by TRYING each — a ping to the router's
        own loopback (`test`), a one-second torch on the LAN bridge (`sniff`) — every 10 min.

        Not by reading the group's policy, for two reasons: RouterOS files
        torch under `sniff`, not `test`, so a policy read would have offered a check that could
        only fail; and a session keeps the rights it logged in with, so right after the owner
        changes the group the policy says yes while the router still says "not enough
        permissions" (over REST, whose sessions live ~10 min, that lasts minutes; the kept
        API connection logs in again when the WAN watcher sees the change in the log). Trying
        measures what works."""
        now = time.time()
        if not force and now - self._router_test_at < ROUTER_TEST_TTL_S:
            return
        self._router_test_at = now
        for attr, what, path, body in (
                ("router_test", "ping/traceroute/arp-ping/ip-scan", "ping",
                 {"address": "127.0.0.1", "count": "1"}),
                ("router_sniff", "torch", "tool/torch",
                 {"interface": self.bridge, "duration": "1s"})):
            r = await self._rest("POST", path, body, timeout_s=10)
            if isinstance(r, dict) and "permission" not in str(r.get("error", "")):
                continue                    # unreachable or odd: keep the last answer
            allowed = isinstance(r, list)
            if allowed != getattr(self, attr):
                log.info("checks: the router %s this user run %s%s",
                         "lets" if allowed else "does not let", what,
                         "" if allowed else f" ({r.get('error')})")
            setattr(self, attr, allowed)

    # --- validating the model's slots ----------------------------------------
    def _who(self, ip: str) -> str:
        d = self.a.inv.get(ip)
        return label(d.name, ip) if d else ip

    def _in_lan(self, ip: str) -> bool:
        """On a network lanowl looks after: `lan_subnets`, and every site's (sites.py
        — not only the main LAN)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._known_nets())

    def _known_nets(self) -> list:
        """`lan_subnets` and every site's networks (sites.py)."""
        sites = getattr(self.a, "sites", None)
        return self.lan_nets + (sites.nets() if sites is not None else [])

    def _target(self, v, what: str = "target") -> str:
        """Any address or host name: pinging, tracing and resolving touch nothing."""
        v = str(v or "").strip().rstrip(".")
        if not v:
            raise CheckError(f"{what} is missing (an address or a host name)")
        if _IPV4.match(v) or (_HOST.match(v) and "." in v):
            return v
        if _HOST.match(v):
            raise CheckError(f"{v!r} is not an address or a full host name (a device's NAME "
                             "is not enough — use its address)")
        raise CheckError(f"{v!r} is not an address or a host name")

    def _device(self, v, check: str) -> str:
        """Something to scan or probe on purpose: an inventory device, or an address on the
        house LAN (a stranger found by ping_sweep). Never an arbitrary internet host."""
        ip = str(v or "").strip()
        if not _IPV4.match(ip):
            raise CheckError(f"device must be an IPv4 address, not {ip!r}")
        dev = self.a.inv.get(ip)
        if dev is None and not self._in_lan(ip):
            raise CheckError(f"{ip} is neither in the inventory nor on the main LAN")
        deny = list(CATALOG[check].get("deny") or []) + list(self.deny_extra.get(check) or [])
        if dev is not None and dev.group in deny:
            raise CheckError(f"{check} is not allowed on {dev.name} ({dev.group})")
        return ip

    @staticmethod
    def _name(v) -> str:
        v = str(v or "").strip().rstrip(".")
        if not v or not _HOST.match(v) or v.startswith("-"):
            raise CheckError(f"name must be a DNS name, not {v!r}")
        return v

    @staticmethod
    def _dtype(v) -> str:
        t = str(v or "A").strip().upper()
        if t not in _DNS_TYPES:
            raise CheckError(f"type must be one of {', '.join(_DNS_TYPES)}")
        return t

    @staticmethod
    def _ports(v, most: int) -> list:
        raw = v if isinstance(v, list) else [v] if v not in (None, "") else []
        if isinstance(v, str) and "," in v:
            raw = v.split(",")
        try:
            ports = sorted({int(x) for x in raw})
        except (TypeError, ValueError):
            raise CheckError("ports must be numbers")
        if not ports or len(ports) > most or not all(0 < x < 65536 for x in ports):
            raise CheckError(f"give 1 to {most} ports (1-65535)")
        return ports

    @staticmethod
    def _int(v, default: int, lo: int, hi: int, what: str) -> int:
        if v in (None, ""):
            return default
        try:
            n = int(float(v))
        except (TypeError, ValueError):
            raise CheckError(f"{what} must be a number")
        return max(lo, min(hi, n))

    def _host(self, v) -> str:
        s = str(v or "").strip().lower()
        alias = {"vps": self.vps, "hub": self.vps, "lan": self.home_server,
                 "home server": self.home_server, "lan host": self.home_server}
        ip = alias.get(s, s)
        hosts = [h.ip for h in (getattr(getattr(self.a, "hostlog", None), "hosts", None) or [])]
        if not ip or ip not in (self.home_server, self.vps) or (hosts and ip not in hosts):
            raise CheckError(f"host must be the LAN host {self.home_server or '(none configured)'} "
                             f"or the VPS {self.vps or '(none configured)'}")
        return ip

    def _subnet(self, v) -> str:
        try:
            n = ipaddress.ip_network(str(v or "").strip(), strict=False)
        except ValueError:
            raise CheckError(f"subnet must look like 192.168.10.0/24, not {v!r}")
        known = [x for x in self._known_nets() if x.version == 4]
        if n.version != 4 or n.prefixlen < 24 or not any(n.subnet_of(x) for x in known):
            raise CheckError(f"subnet must be /24 or smaller inside a known network "
                             f"({', '.join(map(str, known))})")
        return str(n)

    @staticmethod
    def _iface(v) -> str:
        s = str(v or "").strip()
        if not _IFACE.match(s):
            raise CheckError(f"iface must be an interface name, not {s!r}")
        return s

    # --- planning: the model's call -> something that can run -----------------
    async def plan(self, name: str, args: dict) -> dict:
        """Validate a call. {"check", "where", "args", "label", "command"} or CheckError."""
        name = str(name or "").strip()
        if name not in CATALOG:
            raise CheckError(f"unknown check {name!r}; the catalog: {', '.join(self.available())}")
        c = CATALOG[name]
        if c.get("needs"):
            await self.refresh_router_test()
            if not {"test": self.router_test, "sniff": self.router_sniff}.get(c["needs"]):
                raise CheckError(f"{name} is not allowed for lanowl's router user (it "
                                 f"needs the `{c['needs']}` policy on its group, in Winbox). "
                                 f"Use the checks from {self.here} or the LAN host instead.")
        a = args if isinstance(args, dict) else {}
        n: dict = {}
        where = c["where"]
        tgt = lambda: self._target(a.get("target") or a.get("ip") or a.get("device"))   # noqa: E731
        if name in ("ping", "lan_ping", "outside_ping", "mtr", "lan_mtr", "outside_mtr"):
            n["target"] = tgt()
            n["count"] = self._int(a.get("count"), 10, 1, 30, "count")
        elif name in ("traceroute", "lan_traceroute", "outside_traceroute", "router_traceroute"):
            n["target"] = tgt()
            if name == "traceroute":
                mode = str(a.get("mode") or "icmp").lower()
                if mode not in ("udp", "icmp", "tcp"):
                    raise CheckError("mode must be udp, icmp or tcp")
                n["mode"] = mode
                if mode == "tcp":
                    n["port"] = self._ports(a.get("port") or 443, 1)[0]
        elif where == "site":
            site = str(a.get("site") or "").strip().lower()
            keys = [x["key"] for x in self.a.sites.remote()] if getattr(self.a, "sites", None) else []
            if site not in keys:
                raise CheckError(f"site must be one of: {', '.join(keys) or 'none'}")
            n["site"] = site
            if name == "site_ping":
                n["target"] = tgt()
                n["count"] = self._int(a.get("count"), 5, 1, 10, "count")
        elif name == "link_test":
            link = str(a.get("link") or "both").lower()
            if not self._link_test_ok():
                raise CheckError("no backup internet link with per-link probes is configured (wan.path)")
            if link not in ("main", "backup", "both"):
                raise CheckError("link must be main, backup or both")
            n["link"] = link
        elif name in ("dns_compare", "dns_trace", "lan_dns"):
            n["name"] = self._name(a.get("name") or a.get("target"))
            n["type"] = self._dtype(a.get("type"))
        elif name in ("http_timing", "tls_cert"):
            n["target"] = tgt()
            mode = str(a.get("mode") or "https").lower()
            if name == "http_timing" and mode not in ("https", "http"):
                raise CheckError("mode must be https or http")
            if name == "http_timing":
                n["mode"] = mode
            dflt = 443 if (name == "tls_cert" or mode == "https") else 80
            n["port"] = self._ports(a.get("port") or dflt, 1)[0]
            dev = self.a.inv.get(n["target"])
            if dev is not None and dev.group in ("security",):
                raise CheckError(f"{name} is not allowed on {dev.name} ({dev.group})")
        elif name == "port_check":
            n["device"] = self._device(a.get("device") or a.get("target") or a.get("ip"), name)
            n["ports"] = self._ports(a.get("ports") or a.get("port"), 20)
        elif name == "whois":
            ip = str(a.get("target") or a.get("ip") or "").strip()
            try:
                g = ipaddress.ip_address(ip).is_global
            except ValueError:
                g = False
            if not g:
                raise CheckError("whois needs a public IP address")
            n["target"] = ip
        elif name in ("public_ip", "speed_test", "lan_neighbors", "wg_status"):
            pass
        elif name in ("ping_sweep", "router_ip_scan"):
            n["subnet"] = self._subnet(a.get("subnet") or "192.168.10.0/24")
            if name == "router_ip_scan":
                n["seconds"] = self._int(a.get("seconds"), 6, 2, 10, "seconds")
        elif name in ("nmap_ports", "nmap_all_ports"):
            n["device"] = self._device(a.get("device") or a.get("target") or a.get("ip"), name)
        elif name in ("nmap_services", "nmap_tls"):
            n["device"] = self._device(a.get("device") or a.get("target") or a.get("ip"), name)
            n["ports"] = self._ports(a.get("ports") or a.get("port"), 10 if name == "nmap_services" else 5)
        elif name == "router_port":
            n["iface"] = self._iface(a.get("iface"))
        elif name == "router_ping":
            n["target"] = tgt()
            n["count"] = self._int(a.get("count"), 5, 1, 10, "count")
        elif name == "router_arp_ping":
            ip = str(a.get("device") or a.get("target") or a.get("ip") or "").strip()
            if not _IPV4.match(ip) or not self._in_lan(ip):
                raise CheckError("router_arp_ping needs an address on the main LAN")
            n["device"] = ip
        elif name == "router_torch":
            n["iface"] = self._iface(a.get("iface"))
            n["seconds"] = self._int(a.get("seconds"), 5, 2, 10, "seconds")
        elif name in ("host_health", "host_net", "nic_stats"):
            n["host"] = self._host(a.get("host") or a.get("target") or a.get("ip"))
        elif name == "unit_status":
            n["host"] = self._host(a.get("host") or a.get("ip"))
            u = str(a.get("unit") or "").strip()
            if not _UNIT.match(u):
                raise CheckError(f"unit must be a systemd unit name, not {u!r}")
            n["unit"] = u
        elif name == "arping":
            ip = str(a.get("device") or a.get("target") or a.get("ip") or "").strip()
            if not _IPV4.match(ip) or not self._in_lan(ip):
                raise CheckError("arping needs an address on the main LAN (ARP does not cross "
                                 "the router)")
            n["device"] = ip
            n["count"] = self._int(a.get("count"), 3, 1, 10, "count")
        elif name in ("vps_capture", "capture"):
            if name == "vps_capture":
                n["iface"] = self._iface(a.get("iface") or self.vps_iface)
            # the address to filter on is `target`: `host` means which machine a check runs on
            if a.get("target"):
                h = str(a["target"]).strip()
                if not _IPV4.match(h):
                    raise CheckError(f"target (for {name}) must be an IPv4 address")
                n["filter"] = h
            if a.get("port") not in (None, ""):
                n["port"] = self._ports(a.get("port"), 1)[0]
            if a.get("proto"):
                pr = str(a["proto"]).lower()
                allowed = ("tcp", "udp", "icmp") + (("arp",) if name == "capture" else ())
                if pr not in allowed:
                    raise CheckError(f"proto must be {', '.join(allowed)}")
                n["proto"] = pr
            n["count"] = self._int(a.get("count"), 50, 1, 100, "count")
            n["seconds"] = self._int(a.get("seconds"), 10, 2, 20, "seconds")
        if where == "host":
            where = "lan" if n["host"] == self.home_server else "vps"
        return {"check": name, "where": where, "args": n, "label": self._label(name, where, n),
                "command": self._command(name, n)}

    def _label(self, name: str, where: str, n: dict) -> str:
        what = n.get("target") or n.get("name") or n.get("subnet") or n.get("iface") or \
            n.get("unit") or n.get("link") or ""
        if n.get("device"):
            what = self._who(n["device"])
        elif what and _IPV4.match(str(what)):
            what = self._who(what)
        if n.get("ports"):
            what += " port " + ",".join(map(str, n["ports"]))
        return f"{name} {what}".strip() + f" · {self.where_words.get(where, '')}"

    # --- the commands ------------------------------------------------------------
    def _ping_argv(self, t: str, count: int) -> list:
        return ["ping", "-n", "-c", str(count), "-i", "0.3", "-W", "2", t]

    def _mtr_argv(self, t: str, count: int) -> list:
        return ["mtr", "--report", "--report-wide", "--no-dns", "--report-cycles", str(count), t]

    @staticmethod
    def _tr_argv(t: str, mode: str = "udp", port: int = 443) -> list:
        argv = ["traceroute", "-n", "-q", "1", "-w", "2", "-m", "20"]
        if mode == "icmp":
            argv.append("-I")
        elif mode == "tcp":
            argv += ["-T", "-p", str(port)]
        return argv + [t]

    @staticmethod
    def _nmap_argv(name: str, n: dict) -> list:
        ip = n["device"]
        if name == "nmap_ports":
            return ["nmap", "-sT", "-Pn", "--top-ports", "100", "-T4", ip, "-oX", "-"]
        if name == "nmap_services":
            return ["nmap", "-sT", "-sV", "-Pn", "-p", ",".join(map(str, n["ports"])), ip, "-oX", "-"]
        if name == "nmap_all_ports":
            return ["nmap", "-sT", "-Pn", "-p-", "-T4", "--max-retries", "1", ip, "-oX", "-"]
        return ["nmap", "-sT", "-Pn", "-p", ",".join(map(str, n["ports"])),
                "--script", "ssl-cert,ssl-enum-ciphers", ip]

    @staticmethod
    def _arping_argv(n: dict) -> list:
        return ["arping", "-c", str(n["count"]), "-w", str(n["count"] + 2), "-I", lan_iface(),
                n["device"]]

    @staticmethod
    def _capture_argv(n: dict) -> list:
        # -p: no promiscuous mode — this host's own traffic and broadcasts, which is what a
        # bridged VM sees anyway. -q: headers, no payload (lanowl's MQTT is plaintext).
        return ["timeout", str(n["seconds"]), "tcpdump", "-nn", "-q", "-l", "-p",
                "-c", str(n["count"]), "-i", lan_iface()] + ([_bpf(n)] if _bpf(n) else [])

    def _dig_argv(self, server: Optional[str], name: str, t: str) -> list:
        return (["dig"] + ([f"@{server}"] if server else []) +
                [name, t, "+time=2", "+tries=1", "+noall", "+answer", "+comments", "+stats"])

    def _remote(self, name: str, n: dict) -> str:
        """The command line for a check that runs over ssh. Every slot is already restricted
        to characters no shell cares about, and quoted anyway."""
        q = shlex.quote
        if name in ("lan_ping", "outside_ping"):
            return " ".join(map(q, self._ping_argv(n["target"], n["count"])))
        if name in ("lan_mtr", "outside_mtr"):
            return " ".join(map(q, self._mtr_argv(n["target"], n["count"])))
        if name == "lan_traceroute":
            return " ".join(map(q, self._tr_argv(n["target"])))      # pi: UDP, no raw socket
        if name == "outside_traceroute":
            # the VPS has GNU inetutils traceroute: no -n (it does not resolve unless asked)
            return " ".join(map(q, ["traceroute", "-q", "1", "-w", "2", "-m", "20", "-I", n["target"]]))
        if name == "lan_dns":
            return (" ".join(map(q, self._dig_argv(None, n["name"], n["type"]))) + "; echo '---'; "
                    + " ".join(map(q, self._dig_argv(self.router_dns, n["name"], n["type"]))))
        if name == "lan_neighbors":
            return "ip -4 neigh show"
        if name == "host_health":
            return ("uptime; echo '---'; free -m; echo '---'; df -hT -x tmpfs -x devtmpfs -x squashfs "
                    "-x overlay -x efivarfs 2>/dev/null; echo '---'; systemctl --failed --no-legend "
                    "--no-pager; echo '---'; ps -eo pid,pcpu,pmem,etime,comm --sort=-pcpu | head -8")
        if name == "unit_status":
            return f"SYSTEMD_COLORS=0 systemctl status --no-pager --lines=15 {q(n['unit'])}; true"
        if name == "host_net":
            return ("ip -br addr; echo '---'; ip route; echo '---'; ss -Htuln | head -40; "
                    "echo '---'; ss -s")
        if name == "nic_stats":
            return "ip -s -s link"
        if name == "wg_status":
            return "wg show all"
        if name == "vps_capture":
            return (f"timeout {n['seconds']} tcpdump -nn -q -l -c {n['count']} -i {q(n['iface'])} "
                    f"{q(_bpf(n))} 2>&1; true")
        raise CheckError(f"{name} does not run remotely")

    def _command(self, name: str, n: dict) -> str:
        """What the owner reads on the session card: the program as it will run."""
        where = CATALOG[name]["where"]
        if where in ("lan", "vps", "host"):
            host = n.get("host") or (self.home_server if where == "lan" else self.vps)
            return f"ssh {host} {self._remote(name, n)}"
        if where == "router":
            return f"router {name.removeprefix('router_')} {json.dumps(n, sort_keys=True)}"
        if where == "site":
            return f"{n['site']}'s router: {name.removeprefix('site_')}" + (
                f" {n['target']} ×{n['count']}" if name == "site_ping" else "")
        if name in ("ping",):
            return shlex.join(self._ping_argv(n["target"], n["count"]))
        if name == "mtr":
            return shlex.join(self._mtr_argv(n["target"], n["count"]))
        if name == "traceroute":
            return shlex.join(self._tr_argv(n["target"], n["mode"], n.get("port", 443)))
        if name == "link_test":
            mp, bp = self.links["main_probe"], self.links["backup_probe"]
            return "ping -c 10 " + {"main": mp, "backup": bp}.get(n["link"], f"{mp} + {bp}")
        if name == "dns_compare":
            return f"dig {n['name']} {n['type']} @{self.router_dns} @9.9.9.9 @1.1.1.1 @8.8.8.8"
        if name == "dns_trace":
            return f"dig +trace {n['name']} {n['type']}"
        if name == "http_timing":
            return f"curl -o /dev/null {self._url(n)}"
        if name == "tls_cert":
            return f"openssl s_client -connect {n['target']}:{n['port']}"
        if name == "port_check":
            return f"tcp connect {n['device']} {','.join(map(str, n['ports']))}"
        if name == "whois":
            return f"whois {n['target']}"
        if name == "public_ip":
            return "curl https://ipinfo.io/json"
        if name == "speed_test":
            return "curl https://speed.cloudflare.com/__down?bytes=25000000"
        if name == "ping_sweep":
            return f"fping -a -g {n['subnet']}"
        if name == "arping":
            return shlex.join(self._arping_argv(n))
        if name == "capture":
            return shlex.join(self._capture_argv(n))
        if name.startswith("nmap_"):
            return shlex.join([x for x in self._nmap_argv(name, n) if x not in ("-oX", "-")])
        return name

    @staticmethod
    def _url(n: dict) -> str:
        t = n["target"]
        dflt = 443 if n["mode"] == "https" else 80
        return f"{n['mode']}://{t}" + (f":{n['port']}" if n["port"] != dflt else "") + "/"

    # --- running -----------------------------------------------------------------
    async def run(self, plan: dict) -> dict:
        """{"ok", "summary", "output"}. Never raises: a check that failed says why, and a check
        that could not see says UNKNOWN rather than reading as 'nothing there'."""
        name, n = plan["check"], plan["args"]
        t0 = time.time()
        try:
            res = await asyncio.wait_for(self._run(name, plan["where"], n),
                                         timeout=CATALOG[name]["t"] + 15)
        except asyncio.TimeoutError:
            res = {"ok": False, "summary": f"UNKNOWN — no result within {CATALOG[name]['t']}s",
                   "output": ""}
        except Exception as e:
            log.exception("checks: %s failed", name)
            res = {"ok": False, "summary": f"UNKNOWN — the check itself failed ({type(e).__name__})",
                   "output": str(e)[:300]}
        res["secs"] = round(time.time() - t0, 1)
        res["output"] = clip(res.get("output") or "")
        return res

    async def _ssh(self, host: str, remote: str, timeout_s: float) -> tuple:
        hl = getattr(self.a, "hostlog", None)
        h = next((x for x in (getattr(hl, "hosts", None) or []) if x.ip == host), None)
        if h is None:
            return None, "", f"{host} is not a host lanowl logs in to"
        return await _exec(hl._ssh_argv(h, remote), timeout_s)

    async def _rest(self, method: str, path: str, body: Optional[dict], timeout_s: float = 25):
        """A router call in REST's terms (GET `interface`, POST `ping` {…}): the rows, or
        {"error"} — never an exception. Over the kept API connection when it is up
        (routeros.py), else REST."""
        from . import routeros
        return await routeros.shared(self.cfg).request(method, path, body, timeout_s)

    async def _run(self, name: str, where: str, n: dict) -> dict:
        T = CATALOG[name]["t"]
        if where in ("lan", "vps"):
            host = n.get("host") or (self.home_server if where == "lan" else self.vps)
            rc, out, err = await self._ssh(host, self._remote(name, n), T)
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — could not run it on {self._who(host)}: {err}",
                        "output": ""}
            text = out + (("\n" + err) if err.strip() else "")
            return self._summarise(name, n, rc, text)
        if where == "router":
            return await self._run_router(name, n)
        if where == "site":
            return await self.a.sites.run_check(name, n, T)
        return await self._run_here(name, n, T)

    async def _run_here(self, name: str, n: dict, T: int) -> dict:
        if name == "arping":
            rc, out, err = await _exec(self._arping_argv(n), T)
            return self._summarise(name, n, rc, out + err)
        if name == "capture":
            n = {**n, "iface": lan_iface()}
            rc, out, err = await _exec(self._capture_argv(n), T)
            text = out + err
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — {err}", "output": ""}
            # 0: the count was reached; 124: `timeout` ended it. Anything else with no packet
            # printed is tcpdump refusing (no permission, no such interface) — not "quiet".
            if rc not in (0, 124) and not re.search(r"^\d\d:\d\d:\d\d", text, re.M):
                last = text.strip().splitlines()[-1][:160] if text.strip() else f"exit {rc}"
                return {"ok": False, "summary": f"UNKNOWN — tcpdump did not run: {last}",
                        "output": text}
            return self._summarise("vps_capture", n, rc, text)
        if name == "ping":
            rc, out, err = await _exec(self._ping_argv(n["target"], n["count"]), T)
            return self._summarise(name, n, rc, out + err)
        if name == "mtr":
            rc, out, err = await _exec(self._mtr_argv(n["target"], n["count"]), T)
            return self._summarise(name, n, rc, out + err)
        if name == "traceroute":
            rc, out, err = await _exec(self._tr_argv(n["target"], n["mode"], n.get("port", 443)), T)
            return self._summarise(name, n, rc, out + err)
        if name == "link_test":
            L = self.links
            links = [("main", L["main_probe"]), ("backup", L["backup_probe"])]
            links = [x for x in links if n["link"] in (x[0], "both")]
            res = await asyncio.gather(*[_exec(self._ping_argv(ip, 10), T) for _, ip in links])
            parts, outs, ok = [], [], True
            ob = self._on_backup()
            for (ln, ip), (rc, out, err) in zip(links, res):
                s = _ping_stats(out)
                if rc is None or s is None:
                    parts.append(f"{ln}: UNKNOWN ({err or 'no ping output'})")
                    ok = False
                else:
                    bit = (f"{L[ln]} ({ip}): {s['loss']:g}% loss"
                           + (f", avg {s['avg']:.0f} ms" if s.get("avg") is not None else ""))
                    if ln == "backup" and s["loss"] >= 100 and self._standby():
                        bit += f" ({self._standby()})"
                    elif ln == "main" and ob and s["loss"] >= 100:
                        bit += f" (the network is on the {L['backup']}: this is the outage the failover covers)"
                    parts.append(bit)
                outs.append(f"== {L[ln]} via {ip}\n{(out + err).strip()}")
            head = {True: f"on the {L['backup'].upper()} now — ", False: f"on the {L['main']} now — "}.get(ob, "")
            return {"ok": ok, "summary": head + " · ".join(parts), "output": "\n".join(outs)}
        if name == "dns_compare":
            L = self.links

            def via(who, ip):
                # a public resolver the router sends over one link only says which link it is
                if ip == L["main_probe"]:
                    return f"{who} via the {L['main']}"
                if ip == L["backup_probe"]:
                    return f"{who} via the {L['backup']}" + (" (standby: no answer expected)"
                                                               if self._standby() and self._on_backup() is False else "")
                return f"{who} via the active link" if L["failover"] else who
            servers = [("router", self.router_dns), (via("Quad9", "9.9.9.9"), "9.9.9.9"),
                       (via("Cloudflare", "1.1.1.1"), "1.1.1.1"), (via("Google", "8.8.8.8"), "8.8.8.8")]
            res = await asyncio.gather(*[_exec(self._dig_argv(ip, n["name"], n["type"]), T)
                                         for _, ip in servers])
            parts, outs, got = [], [], {}
            for (who, ip), (rc, out, err) in zip(servers, res):
                d = _dig_parse(out)
                if rc is None or d is None:
                    parts.append(f"{who}: UNKNOWN ({(err or out or 'no answer').strip().splitlines()[-1][:60]})")
                else:
                    got[who] = d
                    srt = sorted(d["answers"])      # round-robin order would look like a difference
                    ans = (", ".join(srt[:2]) + (f" +{len(srt) - 2} more" if len(srt) > 2 else "")) \
                        if srt else d["status"]
                    parts.append(f"{who}: {ans}" + (f" ({d['ms']} ms)" if d["ms"] is not None else ""))
                outs.append(f"== {who} @{ip}\n{(out + err).strip()}")
            # A CDN name gets different addresses from different resolvers, and that is
            # normal. What is not: one says NXDOMAIN/SERVFAIL or nothing while others resolve,
            # or one hands out a private address (blocked, or hijacked).
            kinds = {(d["status"], bool(d["answers"])) for d in got.values()}
            private = [w for w, d in got.items() if any(_private(x) for x in d["answers"])]
            if not got:
                head = "UNKNOWN — no server answered"
            elif len(kinds) > 1:
                head = "the servers DISAGREE"
            elif private:
                head = f"{', '.join(private)} returns a PRIVATE address (blocked or redirected)"
            elif len({tuple(sorted(d["answers"])) for d in got.values()}) == 1:
                head = "all servers agree"
            else:
                head = "all resolve it, to different addresses (normal for a CDN, odd for a small site)"
            return {"ok": bool(got), "summary": head + " — " + " · ".join(parts),
                    "output": "\n".join(outs)}
        if name == "dns_trace":
            rc, out, err = await _exec(["dig", "+trace", "+time=2", "+tries=1", n["name"], n["type"]], T)
            return self._summarise(name, n, rc, out + err)
        if name == "http_timing":
            fmt = ("code=%{http_code} ip=%{remote_ip} dns=%{time_namelookup} connect=%{time_connect} "
                   "tls=%{time_appconnect} first_byte=%{time_starttransfer} total=%{time_total} "
                   "size=%{size_download}\n")
            rc, out, err = await _exec(["curl", "-sS", "-o", "/dev/null", "--max-time", "15",
                                        "-w", fmt, self._url(n)], T)
            return self._summarise(name, n, rc, out + err)
        if name == "tls_cert":
            host, port = n["target"], n["port"]
            argv = ["openssl", "s_client", "-connect", f"{host}:{port}"]
            if not _IPV4.match(host):
                argv += ["-servername", host]
            rc, out, err = await _exec(argv, T)
            m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
            if not m:
                return {"ok": False, "summary": f"no certificate from {host}:{port} "
                        f"({(err.strip().splitlines() or ['no TLS'])[-1][:120]})", "output": err[-800:]}
            rc2, x, err2 = await _exec(["openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
                                        "-ext", "subjectAltName"], 10, stdin=m.group(0).encode())
            v = re.search(r"Verify return code: (\d+) \(([^)]*)\)", out)
            return self._summarise(name, n, rc2, x + (f"\nverify: {v.group(1)} ({v.group(2)})" if v else ""))
        if name == "port_check":
            async def one(port):
                t0 = time.time()
                try:
                    _, w = await asyncio.wait_for(asyncio.open_connection(n["device"], port), 2.5)
                    w.close()
                    with contextlib.suppress(Exception):
                        await w.wait_closed()
                    return port, "open", round((time.time() - t0) * 1000)
                except asyncio.TimeoutError:
                    return port, "filtered (no answer)", None
                except ConnectionRefusedError:
                    return port, "closed", None
                except OSError as e:
                    return port, f"error: {e.strerror or e}", None
            res = await asyncio.gather(*[one(p) for p in n["ports"]])
            lines = [f"{p}/tcp {st}" + (f" ({ms} ms)" if ms is not None else "") for p, st, ms in res]
            opened = [str(p) for p, st, _ in res if st == "open"]
            return {"ok": True, "summary": (f"open: {', '.join(opened)}" if opened else "none open")
                    + f" of {len(res)}", "output": "\n".join(lines)}
        if name == "whois":
            rc, out, err = await _exec(["whois", n["target"]], T)
            keep = re.compile(r"^\s*(NetName|netname|OrgName|org-name|Organization|descr|Country|"
                              r"country|CIDR|inetnum|NetRange|route|origin|OriginAS|OrgAbuseEmail|"
                              r"abuse-mailbox|role|person)\s*:", re.I)
            lines = [x.strip() for x in out.splitlines() if keep.match(x)]
            seen, uniq = set(), []
            for x in lines:
                if x not in seen:
                    seen.add(x)
                    uniq.append(x)
            if rc is None or not uniq:
                return {"ok": False, "summary": "UNKNOWN — whois gave nothing usable"
                        + (f" ({err.strip()[:80]})" if err.strip() else ""), "output": out[-1500:]}
            f = {k.lower(): v for k, v in (x.split(":", 1) for x in uniq)}
            org = (f.get("orgname") or f.get("org-name") or f.get("descr") or f.get("netname") or "?").strip()
            cc = (f.get("country") or "?").strip()
            return {"ok": True, "summary": f"{org} ({cc})", "output": "\n".join(uniq[:30])}
        if name == "public_ip":
            rc, out, err = await _exec(["curl", "-sS", "--max-time", "8", "https://ipinfo.io/json"], T)
            try:
                js = json.loads(out)
            except ValueError:
                return {"ok": False, "summary": f"UNKNOWN — {(err or out).strip()[:100]}", "output": out[:500]}
            return {"ok": True, "summary": f"{js.get('ip')} — {js.get('org', '?')}, "
                    f"{js.get('city', '?')} {js.get('country', '')}".strip(),
                    "output": json.dumps({k: js.get(k) for k in ("ip", "hostname", "org", "city", "region", "country")})}
        if name == "speed_test":
            rc, out, err = await _exec(["curl", "-sS", "-o", "/dev/null", "--max-time", "40", "-w",
                                        "%{speed_download} %{size_download} %{time_total} %{remote_ip}",
                                        "https://speed.cloudflare.com/__down?bytes=25000000"], T)
            try:
                bps, size, secs, ip = out.split()
                mbit = float(bps) * 8 / 1e6
                return {"ok": float(size) > 0, "summary": f"{mbit:.1f} Mbit/s down "
                        f"({float(size) / 1e6:.1f} MB in {float(secs):.1f}s from {ip})", "output": out + err}
            except ValueError:
                return {"ok": False, "summary": f"UNKNOWN — {(err or out).strip()[:100]}", "output": out + err}
        if name == "ping_sweep":
            rc, out, err = await _exec(["fping", "-a", "-q", "-r", "1", "-t", "400", "-g", n["subnet"]], T)
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — {err}", "output": ""}
            alive = [x.strip() for x in out.split() if _IPV4.match(x.strip())]
            net = ipaddress.ip_network(n["subnet"])
            known = [ip for ip in alive if self.a.inv.get(ip)]
            strangers = [ip for ip in alive if not self.a.inv.get(ip)]
            silent = [d for d in self.a.inv.devices if _IPV4.match(d.ip)
                      and ipaddress.ip_address(d.ip) in net and d.ip not in alive]
            lines = [f"answer ({len(alive)}): " + ", ".join(self._who(ip) for ip in alive)]
            lines.append("not in the inventory: " + (", ".join(strangers) or "none"))
            lines.append("inventory devices that did not answer: "
                         + (", ".join(label(d.name, d.ip) for d in silent) or "none"))
            return {"ok": True, "summary": f"{len(alive)} answer: {len(known)} known, "
                    f"{len(strangers)} not in the inventory, {len(silent)} inventory devices silent",
                    "output": "\n".join(lines)}
        if name.startswith("nmap_"):
            rc, out, err = await _exec(self._nmap_argv(name, n), T)
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — {err}", "output": ""}
            if name == "nmap_tls":
                return self._summarise(name, n, rc, out + err)
            ports = parse_nmap_xml(out)
            if rc != 0 or ports is None:
                return {"ok": False, "summary": f"nmap failed (rc {rc}): "
                        f"{(err.strip().splitlines() or ['?'])[-1][:160]}", "output": err[-800:]}
            shown = ports if name == "nmap_services" else [x for x in ports if x["state"] == "open"]
            lines = [f"{x['port']}/{x['proto']} {x['state']} {x['service']}"
                     + (f" — {x['version']}" if x["version"] else "") for x in shown[:60]]
            what = {"nmap_ports": "of the top 100", "nmap_all_ports": "of 65535"}.get(name, "")
            if name == "nmap_services":
                summ = "; ".join(lines[:6]) or "nmap reported nothing"
            else:
                summ = (f"{len(shown)} open {what}: " + ", ".join(
                    f"{x['port']} {x['service']}".strip() for x in shown[:12])) if shown \
                    else f"no open port {what}"
            return {"ok": True, "summary": summ, "output": "\n".join(lines)}
        return {"ok": False, "summary": f"UNKNOWN — {name} has no runner here", "output": ""}

    async def _run_router(self, name: str, n: dict) -> dict:
        if name == "router_port":
            ifs = await self._rest("GET", "interface", None)
            if isinstance(ifs, dict):
                return {"ok": False, "summary": f"UNKNOWN — {ifs.get('error')}", "output": ""}
            row = next((x for x in ifs if x.get("name") == n["iface"]), None)
            if row is None:
                names = ", ".join(x.get("name", "") for x in ifs if x.get("type") in ("ether", "bridge", "vlan", "wg", "pppoe-out", "lte"))
                return {"ok": False, "summary": f"no interface {n['iface']!r} on the router; there are: {names}",
                        "output": ""}
            out = {"interface": {k: row.get(k) for k in (
                "name", "type", "running", "disabled", "link-downs", "last-link-down-time",
                "last-link-up-time", "rx-byte", "tx-byte", "rx-error", "tx-error", "rx-drop",
                "tx-drop", "tx-queue-drop", "fp-rx-byte", "fp-tx-byte", "comment") if row.get(k) not in (None, "")}}
            if row.get("type") == "ether":
                mon = await self._rest("POST", "interface/ethernet/monitor", {"numbers": n["iface"], "once": ""})
                if isinstance(mon, list) and mon:
                    out["ethernet"] = {k: mon[0].get(k) for k in ("status", "rate", "full-duplex",
                                       "auto-negotiation", "link-partner-advertising", "sfp-rx-power")
                                       if mon[0].get(k) not in (None, "")}
            tr = await self._rest("POST", "interface/monitor-traffic", {"interface": n["iface"], "once": ""})
            if isinstance(tr, list) and tr:
                out["traffic"] = {k: tr[0].get(k) for k in ("rx-bits-per-second", "tx-bits-per-second",
                                  "rx-packets-per-second", "tx-packets-per-second", "rx-drops-per-second",
                                  "tx-drops-per-second", "rx-errors-per-second") if tr[0].get(k) not in (None, "")}
            e, t = out.get("ethernet") or {}, out.get("traffic") or {}
            i = out["interface"]
            mb = lambda k: f"{int(t.get(k) or 0) / 1e6:.1f}"                                # noqa: E731
            summ = (f"{n['iface']}: {'running' if i.get('running') == 'true' else 'NOT running'}"
                    + (f", {e.get('status')} {e.get('rate', '')}"
                       f"{' full' if e.get('full-duplex') == 'true' else ' HALF'}-duplex" if e else "")
                    + (f" · {mb('rx-bits-per-second')} Mbit/s in, {mb('tx-bits-per-second')} out" if t else "")
                    + f" · {i.get('link-downs', '?')} link-downs"
                    + (f" (last {i['last-link-down-time']})" if i.get("last-link-down-time") else "")
                    + f" · errors rx {i.get('rx-error', 0)} tx {i.get('tx-error', 0)}")
            return {"ok": True, "summary": summ, "output": json.dumps(out, indent=1)}
        if name == "router_ping":
            rows = await self._rest("POST", "ping", {"address": n["target"], "count": str(n["count"])})
            return _router_rows(rows, _router_ping_summary)
        if name == "router_arp_ping":
            rows = await self._rest("POST", "ping", {"address": n["device"], "arp-ping": "yes",
                                                     "interface": self.bridge, "count": "3"})
            return _router_rows(rows, lambda r: _router_ping_summary(r) + (
                f" — answered as MAC {r[-1].get('host')}" if r and ":" in str(r[-1].get("host")) else ""))
        if name == "router_traceroute":
            rows = await self._rest("POST", "tool/traceroute", {"address": n["target"], "count": "1",
                                                                 "max-hops": "20"}, timeout_s=55)

            def tr(r):
                if not r:
                    return "no hops reported"
                last = r[-1]
                addr = last.get("address") or "*"
                where = (f"reached {addr}" if addr == n["target"] else
                         f"last answer from {addr}" if addr not in ("", "*") else "the last hops did not answer")
                return f"{len(r)} hops, {where} ({last.get('loss', '?')}% loss, avg {last.get('avg') or '?'} ms)"
            return _router_rows(rows, tr, last_section=True)
        if name == "router_torch":
            rows = await self._rest("POST", "tool/torch", {
                "interface": n["iface"], "duration": f"{n['seconds']}s",
                "src-address": "0.0.0.0/0", "dst-address": "0.0.0.0/0", "ip-protocol": "any",
                "port": "any"}, timeout_s=n["seconds"] + 15)
            if isinstance(rows, dict):
                return _router_rows(rows, None)
            rows = [r for r in rows or [] if isinstance(r, dict)]
            if rows:                            # one pass per second; the last is the picture
                sec = rows[-1].get(".section")
                rows = [r for r in rows if r.get(".section") == sec]

            def num(v):
                try:
                    return int(float(v or 0))
                except (TypeError, ValueError):
                    return 0
            rows.sort(key=lambda r: num(r.get("tx")) + num(r.get("rx")), reverse=True)
            lines = []
            for r in rows[:15]:
                src, dst = r.get("src-address") or "?", r.get("dst-address") or "?"
                sp, dp = r.get("src-port"), r.get("dst-port")
                lines.append(f"{self._who(src)}{':' + sp if sp else ''} ↔ {self._who(dst)}"
                             f"{':' + dp if dp else ''} {r.get('ip-protocol', '')} — "
                             f"rx {_bps(num(r.get('rx')))}, tx {_bps(num(r.get('tx')))}")
            tot_rx = sum(num(r.get("rx")) for r in rows)
            tot_tx = sum(num(r.get("tx")) for r in rows)
            top = rows[0] if rows else None
            summ = (f"{n['iface']}: rx {_bps(tot_rx)}, tx {_bps(tot_tx)} across {len(rows)} flows"
                    + (f"; busiest {self._who(top.get('src-address') or '?')} ↔ "
                       f"{self._who(top.get('dst-address') or '?')} "
                       f"({_bps(num(top.get('rx')) + num(top.get('tx')))})" if top else ""))
            return {"ok": True, "summary": summ, "output": "\n".join(lines)}
        if name == "router_ip_scan":
            rows = await self._rest("POST", "tool/ip-scan", {
                "address-range": n["subnet"], "interface": self.bridge,
                "duration": f"{n['seconds']}s"}, timeout_s=n["seconds"] + 15)
            if isinstance(rows, dict):
                return _router_rows(rows, None)
            seen = {}
            for r in rows or []:                # progressive sections repeat addresses
                if isinstance(r, dict) and r.get("address"):
                    seen[r["address"]] = r
            known = [ip for ip in seen if self.a.inv.get(ip)]
            lines = [f"{self._who(ip)} {r.get('mac-address', '')} {r.get('dns', '')}".strip()
                     for ip, r in sorted(seen.items(), key=lambda kv: ipaddress.ip_address(kv[0]))]
            return {"ok": True, "summary": f"{len(seen)} answer: {len(known)} known, "
                    f"{len(seen) - len(known)} not in the inventory", "output": "\n".join(lines)}
        return {"ok": False, "summary": f"UNKNOWN — {name} has no runner", "output": ""}

    # --- reading outputs -------------------------------------------------------
    def _summarise(self, name: str, n: dict, rc, text: str) -> dict:
        """One line for the owner and the model, from a program's own output."""
        text = text or ""
        if rc is None:
            return {"ok": False, "summary": f"UNKNOWN — {text.strip()[:160] or 'did not run'}", "output": text}
        if name in ("ping", "lan_ping", "outside_ping"):
            s = _ping_stats(text)
            if s is None:
                return {"ok": False, "summary": f"UNKNOWN — {(text.strip().splitlines() or ['no output'])[-1][:120]}",
                        "output": text}
            return {"ok": True, "summary": f"{s['rx']}/{s['tx']} answered, {s['loss']:g}% loss"
                    + (f", avg {s['avg']:.1f} ms (max {s['max']:.0f})" if s.get("avg") is not None else ""),
                    "output": text}
        if name in ("mtr", "lan_mtr", "outside_mtr"):
            hops = [ln for ln in text.splitlines() if re.match(r"^\s*\d+\.\|--", ln)]
            if not hops:
                return {"ok": False, "summary": f"UNKNOWN — {text.strip()[:140] or 'no mtr output'}", "output": text}
            last = hops[-1].split()
            lossy = [h.split()[1] for h in hops[:-1] if _mtr_loss(h) >= 20]
            t = n["target"]
            if _IPV4.match(t) and last[1] != t:
                # mtr stops listing where the answers stop: the path ends before the target
                return {"ok": True, "summary": f"did NOT reach {t} — the path ends at {last[1]} "
                        f"(hop {len(hops)}, {last[2]} loss there)", "output": text}
            summ = f"{len(hops)} hops; last {last[1]}: {last[2]} loss, avg {last[5]} ms"
            if lossy and _mtr_loss(hops[-1]) >= 20:
                summ += f"; loss starts at {lossy[0]}"
            return {"ok": True, "summary": summ, "output": text}
        if name in ("traceroute", "lan_traceroute", "outside_traceroute"):
            hops = [ln for ln in text.splitlines() if re.match(r"^\s*\d+\s", ln)]
            last = hops[-1].split() if hops else []
            if not last:
                return {"ok": False, "summary": f"UNKNOWN — {text.strip()[:140] or 'no output'}",
                        "output": text}
            summ = f"{len(hops)} hops, " + (f"reached {last[1]}" if last[1] == n["target"] else
                                             f"last answer from {last[1]}" if last[1] != "*" else
                                             "the last hops did not answer")
            return {"ok": True, "summary": summ, "output": text}
        if name == "dns_trace":
            ok = rc == 0 and re.search(r"\sIN\s+" + n["type"] + r"\s", text) is not None
            return {"ok": ok, "summary": "resolved from the root down" if ok else
                    "resolution did not complete — see where it stops", "output": text}
        if name == "lan_dns":
            parts = []
            for who, chunk in zip(("own resolver", "router"), text.split("---")):
                d = _dig_parse(chunk)
                parts.append(f"{who}: " + ("UNKNOWN" if d is None else
                                           (", ".join(d["answers"][:4]) or d["status"])
                                           + (f" ({d['ms']} ms)" if d["ms"] is not None else "")))
            return {"ok": True, "summary": " · ".join(parts), "output": text}
        if name == "http_timing":
            m = dict(re.findall(r"(\w+)=(\S+)", text))
            if "code" not in m:
                return {"ok": False, "summary": f"no answer: {text.strip()[:140]}", "output": text}
            f = lambda k: f"{float(m.get(k, 0)) * 1000:.0f}"                              # noqa: E731
            return {"ok": m["code"] not in ("000",), "summary": (
                f"HTTP {m['code']} from {m.get('ip', '?')} in {f('total')} ms (DNS {f('dns')}, "
                f"connect {f('connect')}, TLS {f('tls')}, first byte {f('first_byte')})"), "output": text}
        if name == "tls_cert":
            end = re.search(r"notAfter=(.+)", text)
            days = ""
            if end:
                with contextlib.suppress(ValueError):
                    t = time.mktime(time.strptime(end.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
                    days = f" ({(t - time.time()) / 86400:.0f} days left)"
            iss = re.search(r"issuer=\s*(.+)", text)
            ver = re.search(r"verify: (\d+) \(([^)]*)\)", text)
            return {"ok": rc == 0, "summary": (f"expires {end.group(1).strip() if end else '?'}{days}"
                    f" · issuer {(iss.group(1).strip() if iss else '?')[:60]}"
                    f" · verify: {ver.group(2) if ver else '?'}"), "output": text}
        if name == "lan_neighbors":
            rows = [ln.split() for ln in text.splitlines() if ln.strip()]
            by = {}
            for r in rows:
                by.setdefault(r[-1], []).append(r[0])
            failed = by.get("FAILED", []) + by.get("INCOMPLETE", [])
            lines = [f"{self._who(r[0])} {' '.join(r[1:])}" for r in rows]
            return {"ok": True, "summary": ", ".join(f"{len(v)} {k}" for k, v in sorted(by.items()))
                    + (f" — not answering ARP: {', '.join(self._who(x) for x in failed[:8])}" if failed else ""),
                    "output": "\n".join(lines)}
        if name == "host_health":
            load = re.search(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)", text)
            mem = re.search(r"Mem:\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d+)", text)
            disks = [(int(m.group(1)), m.group(2)) for m in re.finditer(r"\s(\d+)%\s+(/\S*)", text)]
            fullest = max(disks) if disks else None
            failed = [ln for ln in text.split("---")[3].splitlines() if ln.strip()] if text.count("---") >= 3 else []
            summ = (f"load {load.group(1)}/{load.group(2)}/{load.group(3)}" if load else "load ?")
            if mem:
                summ += f" · memory {int(mem.group(2)) * 100 // max(1, int(mem.group(1)))}% used ({mem.group(3)} MB available)"
            if fullest:
                summ += f" · fullest disk {fullest[1]} {fullest[0]}%"
            summ += f" · {len(failed)} failed unit{'s' if len(failed) != 1 else ''}" + (
                f": {', '.join(x.split()[0].lstrip('●').strip() or x.split()[1] for x in failed[:4])}" if failed else "")
            return {"ok": True, "summary": summ, "output": text}
        if name == "unit_status":
            act = re.search(r"Active:\s*(.+)", text)
            return {"ok": bool(act), "summary": f"{n['unit']}: " + (act.group(1).strip()[:120] if act else
                    (text.strip().splitlines() or ["no status"])[0][:120]), "output": text}
        if name == "nic_stats":
            bad = []
            cur = None
            lines = text.splitlines()
            for i, ln in enumerate(lines):
                m = re.match(r"^\d+:\s+([^:@]+)", ln)
                if m:
                    cur = m.group(1)
                if re.match(r"^\s+(RX|TX):?\s", ln) and "errors" in ln and i + 1 < len(lines):
                    hdr, vals = ln.split(), lines[i + 1].split()
                    kv = dict(zip([h.rstrip(":") for h in hdr[1:]], vals))
                    for k in ("errors", "dropped", "missed", "carrier", "collsns"):
                        if kv.get(k, "0") not in ("0", ""):
                            bad.append(f"{cur} {hdr[0].rstrip(':')} {k} {kv[k]}")
            return {"ok": True, "summary": ("counters not at zero: " + "; ".join(bad[:6])) if bad
                    else "no errors or drops on any interface", "output": text}
        if name == "wg_status":
            out, peers, recent = [], 0, 0
            for ln in text.splitlines():
                if re.search(r"private key|preshared key", ln):
                    continue                     # shown as (hidden) anyway; never pass them on
                ln = re.sub(r"([A-Za-z0-9+/]{8})[A-Za-z0-9+/]{35}=", r"\1…", ln)
                if ln.startswith("peer:"):
                    peers += 1
                m = re.search(r"latest handshake: (.+)", ln)
                if m and not re.search(r"hour|day|week", m.group(1)) and \
                        not re.search(r"([3-9]|\d\d) minutes", m.group(1)):
                    recent += 1
                out.append(ln)
            return {"ok": peers > 0, "summary": f"{peers} peers, {recent} with a handshake in the last "
                    "~3 minutes (a quiet peer re-handshakes only when it has traffic)",
                    "output": "\n".join(out)}
        if name == "arping":
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — {text.strip()[:120]}", "output": text}
            macs = sorted(set(re.findall(r"\[([0-9A-Fa-f:]{17})\]", text)))
            got = len(re.findall(r"reply from", text, re.I))
            who = self._who(n["device"])
            if got:
                return {"ok": True, "summary": f"{who} answers ARP: {got}/{n['count']} replies"
                        + (f" from {', '.join(macs)}" if macs else "")
                        + (" — MORE THAN ONE MAC: an address conflict" if len(macs) > 1 else ""),
                        "output": text}
            return {"ok": True, "summary": f"{who}: no ARP reply to {n['count']} requests — not on "
                    "the wire (off, asleep deeper than ARP, or on another segment)", "output": text}
        if name == "vps_capture":
            pk = [ln for ln in text.splitlines() if re.match(r"^\d\d:\d\d:\d\d", ln)]
            got = re.search(r"(\d+) packets captured", text)
            return {"ok": True, "summary": f"{got.group(1) if got else len(pk)} packets captured on "
                    f"{n['iface']} in ≤{n['seconds']}s", "output": text}
        if name == "nmap_tls":
            states = re.findall(r"^(\d+)/tcp\s+(\S+)", text, re.M)
            subj = re.search(r"Subject: ([^\n]+)", text)
            after = re.search(r"Not valid after:\s*(\S+)", text)
            grade = re.search(r"least strength: (\S+)", text)
            bits = [f"{p} {st}" for p, st in states]
            if subj:
                bits.append(f"certificate {subj.group(1).strip()[:60]}")
            if after:
                bits.append(f"valid until {after.group(1)[:10]}")
            if grade:
                bits.append(f"weakest cipher grade {grade.group(1)}")
            return {"ok": rc == 0, "summary": " · ".join(bits) or "nmap reported nothing",
                    "output": text}
        if name == "host_net":
            sec = text.split("---")
            ifs = [ln.split() for ln in (sec[0] if sec else "").splitlines() if ln.strip()]
            up = [f"{x[0]} {x[2].split('/')[0]}" for x in ifs if len(x) > 2 and x[0] != "lo"]
            listen = len([ln for ln in (sec[2] if len(sec) > 2 else "").splitlines() if ln.strip()])
            est = re.search(r"TCP:\s+\d+ \(estab (\d+)", text)
            return {"ok": bool(ifs), "summary": ("addresses: " + ", ".join(up[:6]) if up else "no addresses")
                    + f" · {listen} listening sockets"
                    + (f" · {est.group(1)} TCP connections established" if est else ""),
                    "output": text}
        # dns_trace, ...: the output is the answer
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        return {"ok": rc == 0, "summary": first[:140] or "(no output)", "output": text}


# --- parsers -----------------------------------------------------------------------------
def _bpf(n: dict) -> str:
    """A capture's filter from validated slots. Our own ssh is left out unless asked for: on
    the VPS it is the session running the capture, here the host-log polling — either would
    drown what was asked."""
    f = [n["proto"]] if n.get("proto") else []
    if n.get("filter"):
        f.append(f"host {n['filter']}")
    if n.get("port"):
        f.append(f"port {n['port']}")
    if n.get("port") != 22 and n.get("proto") != "arp":
        f.append("not tcp port 22")
    return " and ".join(f)


def lan_iface(route_file: str = "/proc/net/route") -> str:
    """The interface of the default route — this host's LAN side ('ens192' on the VM). Read
    from /proc: the image has no iproute2, and with host networking /proc/net is the VM's."""
    try:
        with open(route_file) as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":
                    return f[0]
    except OSError:
        pass
    return "eth0"


def _ping_stats(text: str) -> Optional[dict]:
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss", text)
    if not m:
        return None
    out = {"tx": int(m.group(1)), "rx": int(m.group(2)), "loss": float(m.group(3))}
    r = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", text)
    if r:
        out.update(min=float(r.group(1)), avg=float(r.group(2)), max=float(r.group(3)))
    return out


def _private(addr: str) -> bool:
    try:
        a = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False                   # a CNAME, an MX host…
    return a.is_private or a.is_loopback or a.is_unspecified


def _mtr_loss(line: str) -> float:
    try:
        return float(line.split()[2].rstrip("%"))
    except (IndexError, ValueError):
        return 0.0


def _dig_parse(text: str) -> Optional[dict]:
    st = re.search(r"status: (\w+)", text)
    if not st:
        return None
    ms = re.search(r"Query time: (\d+) msec", text)
    answers = []
    for ln in text.splitlines():
        if ln.startswith(";") or not ln.strip():
            continue
        parts = ln.split()
        if len(parts) >= 5 and parts[2] == "IN":
            answers.append(" ".join(parts[4:]))
    return {"status": st.group(1), "ms": int(ms.group(1)) if ms else None, "answers": answers}


def _bps(v: int) -> str:
    """Torch's rates are bits per second."""
    if v >= 1e6:
        return f"{v / 1e6:.1f} Mbit/s"
    if v >= 1e3:
        return f"{v / 1e3:.0f} kbit/s"
    return f"{v} bit/s"


def _ros_ms(v) -> Optional[float]:
    """A RouterOS duration ('28ms539us', '392us', '1s20ms') in milliseconds."""
    total, found = 0.0, False
    for num, unit in re.findall(r"([\d.]+)(ms|us|s)", str(v or "")):
        total += float(num) * {"s": 1000, "ms": 1, "us": 0.001}[unit]
        found = True
    return total if found else None


def _router_ping_summary(rows: list) -> str:
    last = rows[-1] if rows else {}
    sent, rec = last.get("sent"), last.get("received")
    if sent is None:
        return f"{len(rows)} replies"
    avg = _ros_ms(last.get("avg-rtt"))
    return (f"{rec}/{sent} answered, {last.get('packet-loss', '?')}% loss"
            + (f", avg {avg:.1f} ms" if avg is not None else ""))


def _router_rows(rows, summary, last_section: bool = False) -> dict:
    if isinstance(rows, dict):
        return {"ok": False, "summary": f"UNKNOWN — {rows.get('error', 'no answer')}", "output": ""}
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    if last_section and rows:
        # traceroute repeats every hop once per pass (".section"); the last pass is the answer
        sec = rows[-1].get(".section")
        rows = [r for r in rows if r.get(".section") == sec]
    rows = [{k: v for k, v in r.items() if not k.startswith(".")} for r in rows]
    return {"ok": True, "summary": summary(rows),
            "output": "\n".join(json.dumps(r, separators=(",", ":")) for r in rows[:40])}
