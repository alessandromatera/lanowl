"""DHCP-lease discovery: pull leases from the MikroTik and flag addresses that are not in
the inventory — i.e. new/unknown devices (ESPs, etc.).

Every read here goes through `routeros.shared(cfg)`: the kept api-ssl connection when it is
up, REST otherwise. Read-only: leases, ARP, interfaces and routes, nothing else.
"""
from __future__ import annotations

import ipaddress
import logging

from . import access
from .oui import vendor
from .model import Inventory

log = logging.getLogger("lanowl.discovery")


def resolve_mikrotik(cfg: dict) -> tuple[str, str]:
    """(user, password) of the router's read-only user: the login `mikrotik.credentials`
    names in secrets.yaml, or the environment (access.py). Give it a group of its own with
    read rights only (`mikrotik.lanowl_group`)."""
    lg = access.service_login(cfg, "mikrotik")
    return lg.user, lg.password


def _router(cfg: dict):
    from . import routeros      # imported here: routeros takes resolve_mikrotik from this module
    return routeros.shared(cfg)


async def fetch_leases(cfg: dict):
    user, _ = resolve_mikrotik(cfg)
    if not user:
        return None  # discovery not configured
    r = await _router(cfg).read("ip/dhcp-server/lease")
    if not r.ok:
        log.warning("DHCP lease fetch failed: %s", r.detail)
        return None
    js = r.data.get("json", [])
    return js if isinstance(js, list) else []


async def fetch_arp(cfg: dict):
    """Read-only GET of the router's ARP table. Returns a list or None if unavailable."""
    user, _ = resolve_mikrotik(cfg)
    if not user:
        return None
    r = await _router(cfg).read("ip/arp")
    if not r.ok:
        log.debug("ARP fetch failed: %s", r.detail)
        return None
    js = r.data.get("json", [])
    return js if isinstance(js, list) else []


async def fetch_interfaces(cfg: dict):
    """Read-only GET of the router's interface table -> {name: interface}, or None.

    Used by the `link` check: for a device hanging off a dedicated router port, the
    port's `running` flag is immediate ground truth for "is it still plugged in and
    powered", unlike a DHCP lease which stays bound for the whole lease time."""
    user, _ = resolve_mikrotik(cfg)
    if not user:
        return None
    r = await _router(cfg).read("interface")
    if not r.ok:
        log.debug("interface fetch failed: %s", r.detail)
        return None
    js = r.data.get("json", [])
    if not isinstance(js, list):
        return None
    return {i.get("name"): i for i in js if i.get("name")}


async def fetch_wan_path(cfg: dict):
    """Which WAN link carries the default route (a read of the router's route table).

    The failover netwatch disables the static default route commented
    `wan.path.route_comment` when the main line dies, so that route's disabled/active
    state is the authoritative main-vs-backup signal — pings can't tell the links apart.
    Returns {link, on_backup, detail} or None when not configured."""
    wcfg = (cfg.get("wan", {}) or {}).get("path") or {}
    comment = wcfg.get("route_comment")
    if not comment:
        return None
    user, _ = resolve_mikrotik(cfg)
    if not user:
        return None
    main = wcfg.get("main", "main")
    backup = wcfg.get("backup", "backup")
    r = await _router(cfg).read("ip/route")
    if not r.ok:
        log.warning("WAN-path route fetch failed: %s", r.detail)
        return {"link": "unknown", "on_backup": False, "detail": f"route fetch failed: {r.detail}"}
    routes = r.data.get("json", [])
    mains = [x for x in routes if isinstance(x, dict)
             and x.get("dst-address") == "0.0.0.0/0" and x.get("comment") == comment]
    if not mains:
        return {"link": "unknown", "on_backup": False,
                "detail": f"no default route commented '{comment}' on the router"}
    # REST and the API both omit false flags on some entries: 'active' missing = not active.
    if any(x.get("disabled") != "true" and x.get("active") == "true" for x in mains):
        return {"link": main, "on_backup": False, "detail": f"route '{comment}' active"}
    why = "disabled by failover" if any(x.get("disabled") == "true" for x in mains) \
        else "present but not active"
    return {"link": backup, "on_backup": True, "detail": f"route '{comment}' {why}",
            "severity": wcfg.get("severity", "critical")}


def build_mac_index(leases) -> dict:
    """MAC (upper) -> current bound IP, from the DHCP lease table."""
    idx = {}
    for l in leases or []:
        if l.get("status") != "bound":
            continue
        mac = (l.get("mac-address") or "").upper()
        ip = l.get("address") or ""
        if mac and ip:
            idx[mac] = ip
    return idx


def reconcile(inv: Inventory, mac_index: dict) -> list:
    """Self-healing: if a device's MAC now holds a different IP, re-bind it.

    Returns a list of {name, mac, old_ip, new_ip} for the devices that moved.
    A move is skipped when the target IP already belongs to another inventory device
    (avoids clobbering during a swap)."""
    moves = []
    for dev in inv.devices:
        mac = (dev.attrs.get("mac") or "").upper()
        if not mac:
            continue
        new_ip = mac_index.get(mac)
        if not new_ip or new_ip == dev.ip:
            continue
        other = inv.by_ip.get(new_ip)
        if other is not None and other is not dev:
            log.warning("skip re-bind of %s (%s): %s already used by %s",
                        dev.name, mac, new_ip, other.name)
            continue
        old_ip = dev.ip
        inv.rebind(dev, new_ip)
        moves.append({"name": dev.name, "mac": mac, "old_ip": old_ip, "new_ip": new_ip})
        log.warning("DHCP re-bind: %s (%s) moved %s -> %s", dev.name, mac, old_ip, new_ip)
    return moves


def _ipkey(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except Exception:
        return (999,)


def guest_nets(cfg: dict) -> list:
    """The main router's guest networks (`discovery.guest_nets`): their clients are on the
    same DHCP, marked `guest`."""
    out = []
    for n in ((cfg or {}).get("discovery") or {}).get("guest_nets") or []:
        try:
            out.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            log.warning("discovery: bad guest network %r ignored", n)
    return out


def in_nets(ip: str, nets: list) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


_ARP_GONE = ("failed", "incomplete")
_ARP_LIVE = ("reachable", "delay", "probe")     # the router just heard from it


def static_from_arp(arp, leases, nets) -> list:
    """The devices with a FIXED address, which no DHCP list shows: in the router's ARP table
    with a MAC, on one of `nets`, and holding no DHCP lease. [{ip, mac, how: "arp"}] — the inventory is left to the caller."""
    leased = {str(l.get("mac-address") or "").upper() for l in leases or []
              if l.get("status") == "bound"}
    out, seen = [], set()
    for x in arp or []:
        mac = str(x.get("mac-address") or "").upper()
        ip = str(x.get("address") or "")
        if (not mac or mac in leased or mac in seen or str(x.get("status") or "") in _ARP_GONE
                or str(x.get("complete") or "true") == "false" or str(x.get("disabled")) == "true"
                or not in_nets(ip, nets)):
            continue
        seen.add(mac)
        # stale: the router has not heard from it lately — no sign the address was set by hand
        out.append({"ip": ip, "mac": mac, "how": "arp", **({"stale": True} if x.get("status") == "stale" else {}),
                    **({"ago": 0.0} if x.get("status") in _ARP_LIVE else {})})
    return out


def compute(leases, inv: Inventory, cfg: dict = None, known_macs=None, static=None) -> dict:
    """Unknown = bound leases that are neither an inventory device nor deliberately ignored.

    The ignore list is what keeps "unknown" meaningful. Fifteen phones, laptops and guest
    devices sat in this count permanently: a number that never changes is not a signal, and
    a panel that always says 15 is one nobody reads. Anything acknowledged here is still
    visible under `ignored`, just not counted as something to look into."""
    d = (cfg or {}).get("discovery") or {}
    ign_macs = {m.strip().upper() for m in (d.get("ignore_macs") or []) if m.strip()}
    # ...and those the owner marked Known on the dashboard (sites.py) —
    # the same thing as ignore_macs, without editing config.yaml by hand
    ign_macs |= {str(m).strip().upper() for m in (known_macs or []) if str(m).strip()}
    ign_ips = {i.strip() for i in (d.get("ignore_ips") or []) if i.strip()}

    known = set(inv.by_ip)
    guest = guest_nets(cfg)
    unknown, ignored, bound = [], [], 0
    for l in leases or []:
        if l.get("status") != "bound":
            continue
        bound += 1
        ip = l.get("address", "")
        if ip in known:
            continue
        rec = {
            "ip": ip,
            "mac": l.get("mac-address", ""),
            "host": l.get("host-name", "") or l.get("comment", ""),
            "dynamic": l.get("dynamic", "true"),
            "vendor": vendor(l.get("mac-address", "")),      # oui.py, offline
            "guest": in_nets(ip, guest),
        }
        if rec["mac"].upper() in ign_macs or ip in ign_ips:
            ignored.append(rec)
        else:
            unknown.append(rec)
    # ...and the devices with a fixed address: the router's ARP table, the monthly scan
    have = {r["mac"].upper() for r in unknown + ignored}
    for s in static or []:
        mac, ip = str(s.get("mac") or "").upper(), str(s.get("ip") or "")
        if not mac or mac in have or ip in known:
            continue
        have.add(mac)
        rec = {"ip": ip, "mac": mac, "host": "", "dynamic": "false", "vendor": vendor(mac),
               "guest": in_nets(ip, guest), "how": s.get("how") or "arp",
               **({"found": s["found"]} if s.get("found") else {}), **({"stale": True} if s.get("stale") else {})}
        if mac in ign_macs or ip in ign_ips:
            ignored.append(rec)
        else:
            unknown.append(rec)
    unknown.sort(key=lambda x: _ipkey(x["ip"]))
    ignored.sort(key=lambda x: _ipkey(x["ip"]))
    return {"total_leases": len(leases or []), "bound": bound,
            "unknown_count": len(unknown), "unknown": unknown,
            "ignored_count": len(ignored), "ignored": ignored}
