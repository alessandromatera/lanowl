"""The networks lanowl looks after, as SITES: the main one, a VPN hub, remote ones.

A device list that is one flat list counts a remote office's router with the main site's
lamps. So `sites.list` in config.yaml names each network, and:

  - a device's site is where its address falls (`nets`, first match); the main site
    ("home") is the default;
  - a remote site with a router lanowl can log into (OpenWrt or MikroTik, through the VPN
    hub's tunnels; its login in secrets.yaml) has its DHCP read every `dhcp_every_min`: what
    is on that network, named — shown on the dashboard, and the owner picks what to WATCH (by
    default only the remote routers themselves are watched). A watched device is probed with
    ping from then on, behind its site's router (`depends_on`), at the site's criticality;
    it follows its MAC when DHCP moves it;
  - the SAME for every site, the main one included: its DHCP devices that nobody watches are
    listed under it with two buttons — Watch (ping it from now on) and Known (it belongs
    there: no longer counted as unknown). The main site's leases come from the router's API
    (discovery.py); Known replaces editing `discovery.ignore_macs` by hand, which still works;
  - checks FROM a site's router (checks.py): a ping, its DHCP, a speed test of its
    internet — the last only when the owner asks, it is their bandwidth. A 10 MB file over
    plain HTTP (an old OpenWrt/LEDE may have no TLS); timed on the router itself, to 10 ms
    on OpenWrt, to the second on RouterOS 6 (all its /tool fetch reports).

And the devices with a FIXED address, that no DHCP lists:
  - continuously, for free: each router's ARP table — a MAC on one of the site's networks
    that holds no lease — read with the DHCP (the main site every 5 minutes, the others
    every `dhcp_every_min`);
  - monthly, the silent ones: each network asked "who is there" from its own router —
    RouterOS's ip-scan, or on OpenWrt a ping sweep then its ARP table — never a port. On
    `scan.day` at `scan.at`, and "Scan now".
They are listed with the DHCP ones, marked "fixed address", with the same Known and Watch.
Every device ever seen is remembered per site, for good (`seen` in the state store): new means
never seen there before; what was already there the first time a site (or a way of looking)
is read is "-before", not new.

Nothing here writes to a router: `cat`, `print`, `ping`, `ip-scan`, and a download to nowhere
(`wget -O /dev/null`, `/tool fetch keep-result=no`).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shlex
import time
from typing import Optional

from .model import Device
from .oui import vendor

log = logging.getLogger("lanowl.sites")

RECORD = "sites"
HOUSE = "home"
SPEED_URL = "http://speedtest.tele2.net/10MB.zip"      # plain HTTP: LEDE 17.01 has no TLS
SPEED_BYTES = 10 * 1024 * 1024
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_PAIR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
_NOMAC = "00:00:00:00:00:00"


def _field(line: str, key: str) -> str:
    m = re.search(rf"(?:^|\s){re.escape(key)}=(\"[^\"]*\"|\S+)", line)
    return m.group(1).strip('"') if m else ""


def parse_openwrt_leases(text: str) -> list:
    """/tmp/dhcp.leases: 'expiry mac ip name clientid' per line ('*' = no name)."""
    out = []
    for ln in (text or "").splitlines():
        p = ln.split()
        if len(p) >= 4 and _MAC.match(p[1].lower()):
            out.append({"mac": p[1].lower(), "ip": p[2], "name": "" if p[3] == "*" else p[3],
                        "expires": int(p[0]) if p[0].isdigit() else None})
    return out


def parse_proc_arp(text: str) -> list:
    """/proc/net/arp (OpenWrt): 'IP HW-type Flags HW-address Mask Device'; flags 0x0 =
    incomplete."""
    out = []
    for ln in (text or "").splitlines():
        p = ln.split()
        if len(p) >= 6 and _MAC.match(p[3].lower()) and p[3] != _NOMAC and p[2] != "0x0":
            out.append({"ip": p[0], "mac": p[3].lower(), "iface": p[5]})
    return out


def parse_ip_neigh(text: str) -> list:
    """`ip neigh show` (OpenWrt): 'IP dev IFACE lladdr MAC [router] STATE'; no MAC = gone.
    STALE: the table still holds the address, but the router has not heard from it lately —
    /proc/net/arp shows that the same as a device answering now."""
    out = []
    for ln in (text or "").splitlines():
        p = ln.split()
        if (len(p) >= 6 and p[1] == "dev" and p[3] == "lladdr" and "." in p[0] and _MAC.match(p[4].lower())
                and p[4].lower() != _NOMAC and p[-1] not in ("FAILED", "INCOMPLETE")):
            out.append({"ip": p[0], "mac": p[4].lower(), "iface": p[2], **({"stale": True} if p[-1] == "STALE" else {})})
    return out


def parse_routeros_arp(text: str) -> list:
    """`/ip arp print terse`: key=value per line. A failed entry is gone, MAC or not (RouterOS
    7 keeps the MAC of a device that stopped answering); `status=stale`: not heard from lately."""
    out = []
    for ln in (text or "").splitlines():
        mac, ip = _field(ln, "mac-address").lower(), _field(ln, "address")
        if mac and ip and _MAC.match(mac) and mac != _NOMAC and _field(ln, "status") not in ("failed", "incomplete"):
            out.append({"ip": ip, "mac": mac, "iface": _field(ln, "interface"),
                        **({"stale": True} if _field(ln, "status") == "stale" else {})})
    return out


def parse_pairs(text: str) -> list:
    """Address and MAC side by side, however a RouterOS tool lays its table out (ip-scan)."""
    out = []
    for ip, mac in _PAIR.findall(text or ""):
        if mac.lower() != _NOMAC:
            out.append({"ip": ip, "mac": mac.lower()})
    return out


def _in(ip: str, nets: list) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in nets)


def parse_routeros_leases(text: str) -> list:
    """`/ip dhcp-server lease print terse`: one lease per line, key=value."""
    out = []
    for ln in (text or "").splitlines():
        mac = (_field(ln, "active-mac-address") or _field(ln, "mac-address")).lower()
        ip = _field(ln, "active-address") or _field(ln, "address")
        if not (mac and ip and _MAC.match(mac)):
            continue
        out.append({"mac": mac, "ip": ip, "name": _field(ln, "host-name") or _field(ln, "comment"),
                    "status": _field(ln, "status")})
    return out


class Sites:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("sites") or {}
        self.every_s = float(c.get("dhcp_every_min", 30)) * 60
        self.sites = []
        for s in c.get("list") or []:
            try:
                nets = [ipaddress.ip_network(str(n), strict=False) for n in s.get("nets") or []]
            except ValueError:
                log.warning("sites: bad network in %s — left out", s.get("key"))
                continue
            router = str(s.get("router") or "")
            dev = auditor.inv.get(router) if router else None
            # the router's kind, from the inventory unless the site names it (kinds.py)
            kind = str(s.get("kind") or "") or {"mikrotik": "routeros", "openwrt": "openwrt"}.get(
                str(dev.attrs.get("kind") or "") if dev is not None else "", "")
            self.sites.append({"key": str(s["key"]), "name": str(s.get("name") or s["key"]),
                               "nets": nets, "router": router,
                               "kind": kind,
                               "criticality": str(s.get("criticality")
                                                  or ("low" if s["key"] == HOUSE else "info"))})
        if not any(s["key"] == HOUSE for s in self.sites):
            self.sites.insert(0, {"key": HOUSE, "name": "Home", "nets": [], "router": "",
                                  "kind": "", "criticality": "low"})
        self._task: Optional[asyncio.Task] = None
        # the monthly scan: the same day as the vulnerability scan (updates.py)
        sc = c.get("scan") or {}
        self.scan_on = bool(sc.get("enabled", True))
        self.scan_day = int(sc.get("day") or ((auditor.cfg.get("updates") or {}).get("scan") or {}).get("day") or 1)
        self.scan_at = str(sc.get("at") or "05:00")
        self.scan_secs = int(sc.get("seconds") or 30)
        self._scan_task: Optional[asyncio.Task] = None
        self.new_window_s = float((auditor.cfg.get("discovery") or {}).get("new_window_h", 24)) * 3600
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("sites: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k in ("leases", "watch", "known", "scan", "baselines"):
            self.rec.setdefault(k, {})
        self.restore()

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("sites: record not saved: %s", e)

    # --- where is it -------------------------------------------------------------------------
    def of(self, ip: str) -> str:
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return HOUSE
        return next((s["key"] for s in self.sites if any(a in n for n in s["nets"])), HOUSE)

    def get(self, key: str) -> Optional[dict]:
        return next((s for s in self.sites if s["key"] == key), None)

    @staticmethod
    def routed(s: dict, ip: str) -> bool:
        """Is `ip` on one of the site's networks as configured — the ones routed here?"""
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        return any(a in n for n in s["nets"])

    def remote(self) -> list:
        """The sites with a router lanowl logs into (their DHCP, their checks)."""
        return [s for s in self.sites if s["router"] and s["kind"] in ("openwrt", "routeros")]

    def nets(self) -> list:
        return [n for s in self.sites for n in s["nets"]]

    # --- every device ever seen, per site ---------------------------------------------------
    def remember(self, site: str, rows: list, how: str, now: float) -> list:
        """Into the site's record of every device ever seen; the ones never seen there before.
        The first time a site is looked at a way (its DHCP, its ARP table, the scan) finds what
        was already there: kept as "<how>-before", and not new — the first fixed-address read
        of the main site must not call its switches new."""
        key = f"{site}:{how}"
        before = self.first_look(site, how)
        new = self.a.state.mark_seen([{**r, "how": how + ("-before" if before else "")} for r in rows],
                                     now, site)
        if before:
            self.rec["baselines"][key] = now
            self._save()
            return []
        return new

    def first_look(self, site: str, how: str) -> bool:
        """Has this site never been looked at this way? (Its DHCP counts as looked at when the
        record already holds devices from it.)"""
        if f"{site}:{how}" in self.rec["baselines"]:
            return False
        return not (how == "dhcp" and self.a.state.seen_count(site) > 0)

    def info(self, site: str, macs) -> dict:
        """{mac (lower): {first_seen, new}} from the site's record."""
        now = time.time()
        out = {}
        rows = {r["mac"]: r for r in self.a.state.seen_all(site)} if macs else {}
        for m in macs:
            r = rows.get(str(m).upper())
            if r:
                before = str(r.get("how") or "").endswith("-before")
                out[str(m).lower()] = {"first_seen": r["first_seen"], "before": before,
                                       "new": now - r["first_seen"] <= self.new_window_s and not before}
        return out

    def recent_new(self) -> list:
        """Every site's devices never seen there before, first seen in the last day — for the
        audit (NEW_DEVICES) and its one message. Newest first."""
        out = [{**x, "site": HOUSE, "site_name": self.get(HOUSE)["name"]}
               for x in (getattr(self.a, "_discovery", None) or {}).get("recent_new") or []]
        for s in self.remote():
            for r in self.rows(s["key"])[0]:
                if r.get("new") and not r.get("known"):
                    out.append({"ip": r["ip"], "mac": r["mac"].upper(), "host": r.get("name") or "",
                                "vendor": r.get("vendor") or "", "first_seen": r.get("first_seen"),
                                "how": r.get("how") or "dhcp", "site": s["key"], "site_name": s["name"],
                                **({"stale": True} if r.get("stale") else {}),
                                **({"not_routed_here": True} if s["nets"] and not self.routed(s, r["ip"]) else {})})
        return sorted(out, key=lambda x: -(x.get("first_seen") or 0))

    # --- their DHCP --------------------------------------------------------------------------
    def tick(self, now: Optional[float] = None):
        """From the sweep: read the remote sites' DHCP when due; the monthly scan when due.
        Never awaited."""
        now = now or time.time()
        if self.scan_due(now):
            self.start_scan("monthly")
        if not self.remote() or (self._task is not None and not self._task.done()):
            return
        if now - float(self.rec.get("read") or 0) < self.every_s:
            return
        self.rec["read"] = now
        self._task = asyncio.ensure_future(self.read_all())

    async def read_all(self):
        for s in self.remote():
            try:
                leases, err = await self.leases(s)
            except Exception as e:
                leases, err = None, f"{type(e).__name__}: {e}"
            try:
                arp = await self.arp(s)
            except Exception as e:
                log.info("sites: %s's ARP table not read: %s", s["name"], e)
                arp = None
            prev = self.rec["leases"].get(s["key"]) or {}
            rows = leases if leases is not None else prev.get("rows") or []
            leased = {r["mac"] for r in rows}
            static = ([{"ip": x["ip"], "mac": x["mac"], "how": "arp", **({"stale": True} if x.get("stale") else {})}
                       for x in arp if x["mac"] not in leased and _in(x["ip"], self._lan(s))]
                      if arp is not None else prev.get("static") or [])
            now = time.time()
            self.rec["leases"][s["key"]] = {"ts": now, "error": err, "rows": rows, "static": static}
            if leases:
                self._follow(s, leases)
                self.remember(s["key"], [{"ip": r["ip"], "mac": r["mac"], "host": r.get("name") or ""}
                                         for r in leases if r.get("status") in (None, "", "bound")],
                              "dhcp", now)
            if arp is not None:
                self.remember(s["key"], static, "arp", now)
        self._save()

    def _lan(self, s: dict) -> list:
        """The site's own networks, where ARP means something: not a tunnel's /32."""
        return [n for n in s["nets"] if n.prefixlen < 32]

    async def arp(self, s: dict) -> Optional[list]:
        if s["kind"] == "openwrt":
            # `ip neigh` says which entries are stale; /proc/net/arp where there is no `ip`
            rc, out, err = await self.a.access.ssh(s["router"], "ip neigh show 2>/dev/null || cat /proc/net/arp",
                                                   timeout_s=25)
            return (parse_ip_neigh(out) or parse_proc_arp(out)) if rc == 0 else None
        rc, out, err = await self.a.access.ssh(s["router"], "/ip arp print terse without-paging",
                                               user_suffix="+ct", timeout_s=30)
        return parse_routeros_arp(out) if rc == 0 else None

    # --- the monthly scan: who is there, fixed addresses included --------------------------------
    @property
    def scanning(self) -> bool:
        return self._scan_task is not None and not self._scan_task.done()

    def _today_at(self, hhmm: str, now: float) -> float:
        lt = time.localtime(now)
        try:
            h, m = (int(x) for x in hhmm.split(":"))
        except ValueError:
            h, m = 5, 0
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, h, m, 0, 0, 0, -1))

    def scan_due(self, now: float) -> bool:
        if not self.scan_on or self.scanning or time.localtime(now).tm_mday != self.scan_day:
            return False
        at = self._today_at(self.scan_at, now)
        return now >= at and float(self.rec["scan"].get("last") or 0) < at

    def start_scan(self, why: str) -> dict:
        if self.scanning:
            return {"ok": False, "error": "a scan is already running"}
        self.rec["scan"]["last"] = time.time()
        self._save()
        self._scan_task = asyncio.ensure_future(self._scan_all(why))
        return {"ok": True}

    async def _scan_all(self, why: str):
        t0 = time.time()
        for s in [self.get(HOUSE)] + self.remote():
            try:
                found, errs = await (self._scan_house(s) if s["key"] == HOUSE else self._scan_remote(s))
            except Exception as e:
                log.warning("sites: scan of %s failed", s["name"], exc_info=True)
                found, errs = None, [f"{type(e).__name__}: {e}"]
            prev = self.rec["scan"].get(s["key"]) or {}
            now = time.time()
            self.rec["scan"][s["key"]] = {"ts": now, "why": why, "error": "; ".join(errs),
                                          "rows": found if found is not None else prev.get("rows") or []}
            if found:
                self.remember(s["key"], [{**r, "host": ""} for r in found], "scan", now)
            log.info("sites: scan of %s (%s): %s device(s)%s", s["name"], why,
                     len(found) if found is not None else "no", f" — {'; '.join(errs)}" if errs else "")
        self._save()
        log.info("sites: scan done in %.0fs", time.time() - t0)

    async def _scan_house(self, s: dict) -> tuple:
        """RouterOS ip-scan on each of the main site's networks, on the interface it sits on."""
        from . import routeros
        r = routeros.shared(self.a.cfg)
        addrs = await r.request("GET", "ip/address", None, 20)
        if isinstance(addrs, dict):
            return None, [f"the router's addresses: {addrs.get('error')}"]
        on = {}
        for x in addrs or []:
            try:
                on[ipaddress.ip_network(str(x.get("address")), strict=False)] = x.get("interface")
            except ValueError:
                pass
        found, errs = [], []
        for n in self._lan(s):
            iface = on.get(n)
            if not iface:
                errs.append(f"{n}: not on the router's own interfaces")
                continue
            rows = await r.request("POST", "tool/ip-scan", {"address-range": str(n), "interface": iface,
                                                           "duration": f"{self.scan_secs}s"},
                                   self.scan_secs + 20)
            if isinstance(rows, dict):
                errs.append(f"{n}: {rows.get('error')}")
                continue
            got = {}
            for x in rows or []:               # progressive sections repeat addresses
                if isinstance(x, dict) and x.get("address") and x.get("mac-address"):
                    got[x["address"]] = {"ip": x["address"], "mac": str(x["mac-address"]).lower()}
            found += [g for g in got.values() if _in(g["ip"], [n]) and g["mac"] != _NOMAC]
        # ip-scan misses what ignores ping (a device that is in the ARP table but never in the
        # scan); its ARP requests refresh the table — read it too
        arp = await r.request("GET", "ip/arp", None, 20)
        if isinstance(arp, list):
            have = {g["mac"] for g in found}
            for x in arp:
                mac, ip = str(x.get("mac-address") or "").lower(), str(x.get("address") or "")
                if (mac and mac != _NOMAC.lower() and mac not in have and _in(ip, self._lan(s))
                        and str(x.get("status") or "") not in ("failed", "incomplete")):
                    have.add(mac)
                    found.append({"ip": ip, "mac": mac})
        return found, errs

    async def _scan_remote(self, s: dict) -> tuple:
        """From the site's own router: OpenWrt pings every address (16 at a time, one second
        each) and reads its ARP table; RouterOS runs ip-scan, then its ARP table too."""
        found, errs = {}, []
        for n in self._lan(s):
            if n.num_addresses > 256:
                errs.append(f"{n}: larger than a /24, left out")
                continue
            hosts = " ".join(str(h) for h in n.hosts())
            if s["kind"] == "openwrt":
                cmd = (f"n=0; for a in {hosts}; do ping -c1 -W1 $a >/dev/null 2>&1 & n=$((n+1)); "
                       f"[ $n -ge 16 ] && {{ wait; n=0; }}; done; wait; cat /proc/net/arp")
                rc, out, err = await self.a.access.ssh(s["router"], cmd, timeout_s=120)
                rows = parse_proc_arp(out) if rc == 0 else None
            else:
                cmd = (f"/tool ip-scan address-range={n} duration={self.scan_secs}s; "
                       f"/ip arp print terse without-paging")
                rc, out, err = await self.a.access.ssh(s["router"], cmd, user_suffix="+ct",
                                                       timeout_s=self.scan_secs + 60)
                rows = (parse_pairs(out) + parse_routeros_arp(out)) if rc == 0 else None
            if rows is None:
                errs.append(f"{n}: {(err or 'no answer').strip()[-120:]}")
                continue
            for x in rows:
                if _in(x["ip"], [n]):
                    found.setdefault(x["mac"], {"ip": x["ip"], "mac": x["mac"]})
        return (list(found.values()) if found or not errs else None), errs

    async def leases(self, s: dict) -> tuple:
        if s["kind"] == "openwrt":
            rc, out, err = await self.a.access.ssh(s["router"], "cat /tmp/dhcp.leases", timeout_s=25)
            return (parse_openwrt_leases(out), "") if rc == 0 else (None, (err or "no answer").strip()[-160:])
        rc, out, err = await self.a.access.ssh(s["router"], "/ip dhcp-server lease print terse without-paging",
                                               user_suffix="+ct", timeout_s=30)
        return (parse_routeros_leases(out), "") if rc == 0 else (None, (err or "no answer").strip()[-160:])

    def rows(self, key: str) -> tuple:
        """A site's DHCP devices that nobody watches: ([{ip, mac, name, known}], read-at, error).
        The main site's from discovery (the router's API), a remote site's from its own read."""
        if key == HOUSE:
            d = getattr(self.a, "_discovery", None) or {}
            ign = {str(x.get("mac") or "").lower() for x in d.get("ignored") or []}
            new = {str(x.get("mac") or "").lower() for x in d.get("recent_new") or []}
            rows = [{"ip": x.get("ip", ""), "mac": str(x.get("mac") or "").lower(),
                     "name": x.get("host") or "", "vendor": vendor(x.get("mac") or ""),
                     # here since when, the guest Wi-Fi, never seen before (main.run_discovery)
                     "first_seen": x.get("first_seen"), "guest": bool(x.get("guest")),
                     "new": str(x.get("mac") or "").lower() in new,
                     # a fixed address: from the ARP table, or found by the monthly scan
                     "how": x.get("how") or "dhcp", **({"found": x["found"]} if x.get("found") else {}),
                     **({"stale": True} if x.get("stale") else {}),
                     # already there the first time it was looked at: "here since before …"
                     "before": bool(x.get("before"))}
                    for x in (d.get("unknown") or []) + (d.get("ignored") or [])
                    if self.a.inv.get(x.get("ip", "")) is None]      # watched since the last read
            for r in rows:
                r["known_by"] = "you" if r["mac"] in self.rec["known"] else "config" if r["mac"] in ign else ""
                r["known"] = bool(r["known_by"])
            return sorted(rows, key=lambda r: [int(o) if o.isdigit() else 0 for o in r["ip"].split(".")]), \
                d.get("ts"), ("" if d else "not read yet")
        L = self.rec["leases"].get(key) or {}
        lease_rows = [{**r, "how": "dhcp"} for r in L.get("rows") or []]
        have = {r["mac"] for r in lease_rows}
        static = []
        for r in L.get("static") or []:
            if r["mac"] not in have:
                have.add(r["mac"])
                static.append({"ip": r["ip"], "mac": r["mac"], "name": "", "how": "arp",
                               **({"stale": True} if r.get("stale") else {})})
        sc = self.rec["scan"].get(key) or {}
        for r in sc.get("rows") or []:
            if r["mac"] not in have:
                have.add(r["mac"])
                static.append({"ip": r["ip"], "mac": r["mac"], "name": "", "how": "scan", "found": sc.get("ts")})
        seen = self.info(key, [r["mac"] for r in lease_rows + static])
        rows = [{**r, "known": r["mac"] in self.rec["known"], "vendor": vendor(r["mac"]),
                 "known_by": "you" if r["mac"] in self.rec["known"] else "",
                 "first_seen": (seen.get(r["mac"]) or {}).get("first_seen"),
                 "before": bool((seen.get(r["mac"]) or {}).get("before")),
                 "new": bool((seen.get(r["mac"]) or {}).get("new"))}
                for r in lease_rows + static if self.a.inv.get(r["ip"]) is None]
        return rows, L.get("ts"), L.get("error") or ""

    def seen(self) -> list:
        """Every device ever seen on every site — DHCP, fixed addresses, the scan — newest
        first, kept for good: the Logbook's New devices, and Ask. What each one is today:
        watched, known, or nobody's; and whether it is here now."""
        from .discovery import guest_nets, in_nets
        d = getattr(self.a, "_discovery", None) or {}
        here = {HOUSE: dict(getattr(self.a, "_mac_index", None) or {})}
        here[HOUSE].update({str(x.get("mac") or "").upper(): x.get("ip")
                            for x in (d.get("unknown") or []) + (d.get("ignored") or [])
                            if x.get("how") == "arp"})
        for s in self.remote():
            L = self.rec["leases"].get(s["key"]) or {}
            here[s["key"]] = {r["mac"].upper(): r["ip"] for r in (L.get("rows") or []) + (L.get("static") or [])}
        watched = {(w["site"], w["mac"].upper()): ip for ip, w in self.rec["watch"].items()}
        cfg_ign = {m.strip().upper() for m in ((self.a.cfg.get("discovery") or {}).get("ignore_macs") or [])}
        guest = guest_nets(self.a.cfg)
        names = {s["key"]: s["name"] for s in self.sites}
        out = []
        for r in self.a.state.seen_all():
            site, mac = r.get("site") or HOUSE, str(r.get("mac") or "").upper()
            ip_now = here.get(site, {}).get(mac)
            ip = ip_now or r.get("ip") or ""
            dev = self.a.inv.get(ip_now) if ip_now else None
            if dev is None and (site, mac) in watched:
                dev = self.a.inv.get(watched[(site, mac)])
            k = self.rec["known"].get(mac.lower())
            known = (k is not None and k.get("site", HOUSE) == site) or (site == HOUSE and mac in cfg_ign)
            how = str(r.get("how") or "dhcp").replace("-before", "")
            out.append({"site": site, "site_name": names.get(site, site), "mac": mac.lower(),
                        "first_seen": r.get("first_seen"), "last_seen": r.get("last_seen"),
                        "ip": ip, "host": r.get("host") or "", "vendor": vendor(mac),
                        "guest": site == HOUSE and in_nets(ip, guest), "here": bool(ip_now),
                        "fixed": how in ("arp", "scan"),
                        "before": str(r.get("how") or "").endswith("-before"),
                        "status": "watched" if dev is not None else "known" if known else "",
                        **({"name": dev.name} if dev is not None else
                           {"name": self.a.names.for_mac(site, mac)} if getattr(self.a, "names", None)
                           and self.a.names.for_mac(site, mac) else {})})
        return out

    def has_dhcp(self, s: dict) -> bool:
        return s["key"] == HOUSE or s in self.remote()

    def known_macs(self, key: str) -> list:
        return [m for m, k in self.rec["known"].items() if k.get("site") == key]

    def know(self, site: str, mac: str, known: bool = True) -> dict:
        """Known: it belongs on that network — listed apart, never counted as unknown."""
        mac = str(mac or "").lower()
        s = self.get(site)
        if s is None or not self.has_dhcp(s):
            return {"ok": False, "error": "not a site whose DHCP lanowl reads"}
        if not known:
            if self.rec["known"].pop(mac, None) is None:
                return {"ok": False, "error": "it was not marked known"}
        else:
            row = next((r for r in self.rows(site)[0] if r["mac"] == mac), None)
            if row is None:
                return {"ok": False, "error": "that device is not on the site's list"}
            self.rec["known"][mac] = {"site": site, "name": row.get("name") or "", "ts": time.time()}
        self._save()
        if site == HOUSE and getattr(self.a, "_discovery", None):
            d = self.a._discovery          # the main site's count, now — not at the next DHCP read
            move = [x for x in d.get("unknown") or [] if str(x.get("mac")).lower() == mac] if known else \
                   [x for x in d.get("ignored") or [] if str(x.get("mac")).lower() == mac
                    and not self._config_ignored(x)]
            src, dst = ("unknown", "ignored") if known else ("ignored", "unknown")
            for x in move:
                d[src].remove(x)
                d[dst].append(x)
            d["unknown_count"], d["ignored_count"] = len(d.get("unknown") or []), len(d.get("ignored") or [])
        return {"ok": True}

    def _config_ignored(self, x: dict) -> bool:
        d = (self.a.cfg.get("discovery") or {})
        return str(x.get("mac") or "").upper() in {m.strip().upper() for m in d.get("ignore_macs") or []} \
            or x.get("ip") in (d.get("ignore_ips") or [])

    # --- the devices the owner watches --------------------------------------------------------
    def restore(self):
        for ip, w in list(self.rec["watch"].items()):
            if self.a.inv.get(ip) is None:
                self.a.inv.add(self._device(ip, w))

    def _device(self, ip: str, w: dict) -> Device:
        s = self.get(w["site"]) or {}
        return Device(ip=ip, name=w["name"], group="remote" if w["site"] != HOUSE else "watched",
                      criticality=s.get("criticality", "info" if w["site"] != HOUSE else "low"),
                      checks=[{"type": "icmp"}],
                      note=f"on {s.get('name', w['site'])}'s network, watched from its DHCP "
                           f"(MAC {w['mac']}) since {time.strftime('%d/%m', time.localtime(w['ts']))}",
                      attrs={**({"depends_on": s["router"]} if s.get("router") else {}), "mac": w["mac"],
                             "site": w["site"], "watched": True, "debounce_fails": 5})

    def watch(self, site: str, mac: str, name: str = "") -> dict:
        s = self.get(site)
        if s is None or not self.has_dhcp(s):
            return {"ok": False, "error": "not a site whose DHCP lanowl reads"}
        mac = str(mac or "").lower()
        row = next((r for r in self.rows(site)[0] if r["mac"] == mac), None)
        if row is None:
            return {"ok": False, "error": "that device is not on the site's list"}
        ip = row["ip"]
        if s["nets"] and not self.routed(s, ip):
            # a remote DHCP may hand out a network the tunnels do not carry — and the main
            # site may use the same addresses itself: a ping to it would reach a local guest,
            # not the remote device
            return {"ok": False, "error": f"{ip} is on a network of {s['name']}'s that is not routed "
                                          "here — it cannot be pinged from the main site"}
        if self.a.inv.get(ip) is not None:
            return {"ok": False, "error": f"{ip} is already watched"}
        w = {"site": site, "mac": mac, "ts": time.time(),
             "name": " ".join(str(name or row.get("name") or f"{s['name']} {ip}").split())[:60]}
        self.rec["watch"][ip] = w
        self.a.inv.add(self._device(ip, w))
        self._save()
        log.info("sites: watching %s (%s) on %s", w["name"], ip, s["name"])
        return {"ok": True, "ip": ip, "name": w["name"]}

    def unwatch(self, ip: str) -> dict:
        w = self.rec["watch"].pop(str(ip), None)
        if w is None:
            return {"ok": False, "error": "it was not watched from a site's DHCP"}
        self.a.inv.remove(str(ip))
        self._save()
        log.info("sites: no longer watching %s (%s)", w["name"], ip)
        refresh = getattr(self.a, "refresh_report", None)
        if callable(refresh):
            refresh()                      # off the device list at once, not at the next sweep
        return {"ok": True}

    def _follow(self, s: dict, leases: list):
        """A watched device DHCP moved: its MAC says where it went."""
        by_mac = {r["mac"]: r["ip"] for r in leases}
        for ip, w in list(self.rec["watch"].items()):
            new = by_mac.get(w["mac"])
            if w["site"] == s["key"] and new and new != ip and self.a.inv.get(new) is None:
                dev = self.a.inv.get(ip)
                if dev is not None:
                    self.a.inv.rebind(dev, new)
                self.rec["watch"][new] = self.rec["watch"].pop(ip)
                log.info("sites: %s moved %s -> %s", w["name"], ip, new)

    # --- checks from a site's router (checks.py) -----------------------------------------
    async def run_check(self, name: str, n: dict, timeout_s: float) -> dict:
        s = self.get(n["site"])
        if s is None or s not in self.remote():
            return {"ok": False, "summary": f"UNKNOWN — {n['site']} is not a site lanowl logs into",
                    "output": ""}
        ros = s["kind"] == "routeros"

        async def sh(cmd: str) -> tuple:
            return await self.a.access.ssh(s["router"], cmd, user_suffix="+ct" if ros else "",
                                           timeout_s=timeout_s)
        where = f"from {s['name']}'s router"
        if name == "site_dhcp":
            leases, err = await self.leases(s)
            if leases is None:
                return {"ok": False, "summary": f"UNKNOWN — could not read it: {err}", "output": ""}
            self.rec["leases"][s["key"]] = {"ts": time.time(), "error": "", "rows": leases}
            return {"ok": True, "summary": f"{len(leases)} device(s) on {s['name']}'s DHCP",
                    "output": "\n".join(f"{r['ip']:15} {r['mac']}  {r.get('name') or '(no name)'}"
                                        for r in leases)}
        if name == "site_ping":
            t, c = n["target"], n["count"]
            rc, out, err = await sh(f"/ping address={t} count={c}" if ros else
                                    f"ping -c {c} -W 2 {shlex.quote(t)}")
            if rc is None:
                return {"ok": False, "summary": f"UNKNOWN — could not log into {s['name']}'s router: {err}",
                        "output": ""}
            text = out + err
            if ros:
                m = re.search(r"sent=(\d+) received=(\d+) packet-loss=(\d+)%(?:.*?avg-rtt=(\S+))?", text)
                sent, got, loss, avg = (m.group(1), m.group(2), m.group(3), m.group(4)) if m else (None,) * 4
            else:
                m = re.search(r"(\d+) packets transmitted, (\d+) packets received, (\d+)% packet loss", text)
                a = re.search(r"= [\d.]+/([\d.]+)/", text)
                sent, got, loss = (m.group(1), m.group(2), m.group(3)) if m else (None,) * 3
                avg = f"{float(a.group(1)):.0f}ms" if a else None
            if sent is None:
                return {"ok": False, "summary": f"UNKNOWN — the router printed nothing usable", "output": text}
            return {"ok": got != "0", "output": text,
                    "summary": f"{t} {where}: {got}/{sent} answered, {loss}% loss"
                               + (f", avg {avg}" if avg else "")}
        if name == "site_speed_test":
            if ros:
                rc, out, err = await sh(f'/tool fetch url="{SPEED_URL}" keep-result=no')
                d = re.findall(r"duration:\s*(\d+)s", out or "")
                done = "status: finished" in (out or "")
                if rc is None or not done or not d:
                    return {"ok": False, "output": (out or "") + (err or ""),
                            "summary": f"UNKNOWN — the download did not finish {where}"}
                secs = max(1, int(d[-1]))
                mbit = SPEED_BYTES * 8 / secs / 1e6
                return {"ok": True, "output": out,
                        "summary": f"{s['name']}'s internet: about {mbit:.0f} Mbit/s down "
                                   f"(10 MB in {secs} s — RouterOS times it to the second only)"}
            rc, out, err = await sh(f"a=$(cut -d' ' -f1 /proc/uptime); wget -q -O /dev/null {SPEED_URL}; "
                                    f"r=$?; b=$(cut -d' ' -f1 /proc/uptime); echo RC=$r START=$a END=$b")
            m = re.search(r"RC=(\d+) START=([\d.]+) END=([\d.]+)", out or "")
            if rc is None or not m or m.group(1) != "0":
                return {"ok": False, "output": (out or "") + (err or ""),
                        "summary": f"UNKNOWN — the download did not finish {where}"}
            secs = max(0.01, float(m.group(3)) - float(m.group(2)))
            return {"ok": True, "output": out,
                    "summary": f"{s['name']}'s internet: {SPEED_BYTES * 8 / secs / 1e6:.1f} Mbit/s down "
                               f"(10 MB in {secs:.2f} s)"}
        return {"ok": False, "summary": f"UNKNOWN — {name} is not a site check", "output": ""}

    # --- the dashboard ----------------------------------------------------------------------------
    def _dhcp_view(self, s: dict) -> dict:
        if not self.has_dhcp(s):
            return {}
        rows, read, err = self.rows(s["key"])
        nm = getattr(self.a, "names", None)
        # the owner's name for a row (names.py), over the one DHCP gives
        rows = [{**r, "routed": not s["nets"] or self.routed(s, r["ip"]),
                 **({"name": nm.for_mac(s["key"], r["mac"]), "renamed": True}
                    if nm is not None and nm.for_mac(s["key"], r["mac"]) else {})} for r in rows]
        sc = self.rec["scan"].get(s["key"]) or {}
        return {"dhcp": {"read": read, "error": err, "rows": rows,
                         "unknown": sum(1 for r in rows if not r["known"] and r["routed"]),
                         # the monthly scan of this site's networks
                         "scan": {"ts": sc.get("ts"), "error": sc.get("error") or "",
                                  "found": len(sc.get("rows") or []), "running": self.scanning,
                                  "day": self.scan_day, "at": self.scan_at}}}

    def view(self, report: Optional[dict] = None) -> dict:
        devs = (report or {}).get("devices") or []
        watched = self.rec["watch"]
        out = []
        for s in self.sites:
            mine = [d for d in devs if self.of(d.get("ip")) == s["key"]]
            out.append({"key": s["key"], "name": s["name"],
                        "nets": [str(n) for n in s["nets"]], "router": s["router"],
                        "remote": s in self.remote(),
                        # what the owner watches here, whether or not DHCP still lists it
                        "watched": [{"ip": ip, "name": w["name"], "mac": w["mac"]}
                                    for ip, w in watched.items() if w["site"] == s["key"]],
                        "up": sum(1 for d in mine if d.get("up")), "total": len(mine),
                        "down": [d.get("name") for d in mine
                                 if not d.get("up") and not d.get("asleep") and not d.get("paused")],
                        **self._dhcp_view(s)})
        return {"sites": out}
