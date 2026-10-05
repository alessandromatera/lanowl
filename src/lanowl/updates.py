"""Updates, pending reboots and known vulnerabilities — read-only, once a day and once a month.

Does anything need an update, a restart, or carry a known vulnerability?

  - which machines: those listed in `updates.hosts` — Linux servers (apt), an ESXi host,
    MikroTiks (installed against MikroTik's latest, and whether the versions in between were
    security releases), OpenWrt and UniFi gear (read only), and Home Assistant — whose own
    update list also covers its add-ons and the camera and Shelly firmware it knows;
  - how often: every day in the early morning (`updates.at`), plus a line in the weekly review;
  - what pages (one message per run, only for findings not announced before — never the same
    thing every day): a reboot pending more than 3 days, a security update still not installed
    after 2 days, a security release or a high/critical CVE for something installed, a newly
    opened insecure service (telnet, ftp). Everything else is on the dashboard only;
  - once a month, a vulnerability scan: nmap -sV with the `vulners` script over the main
    LAN's devices, CVSS 7 and up.

How it gets in: the host-log watcher's key where it has one, everything else with the owner's
logins (access.py). It only reads: `apt list --upgradable`, the reboot flag,
`vmware -vl`, `/system package update print`, Home Assistant's `update.*` entities, and a
TCP connect to 21 and 23. Applying an update or a reboot is an action with a button
(actions.py), never done from here.
"""
from __future__ import annotations

import asyncio
import calendar
import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Optional

from . import kinds, probes
from .checks import _exec
from .model import on_main_lan
from .reboot import fmt_s, proc_uptime, routeros_field
from .report import _html, label

log = logging.getLogger("lanowl.updates")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

RECORD = "updates"
MIKROTIK = "https://upgrade.mikrotik.com/routeros"
INSECURE = {21: "ftp", 23: "telnet"}
ROS_DOWNLOAD_S = 240               # a RouterOS package, downloaded before any reboot
ROS_BACK_S = 480                   # ...and the boot that installs it
ROS_POLL_S = 5
ROS_START_S = 30                   # a download asked and not begun this long after never will
ROS_IDLE = re.compile(r"new version is available", re.I)   # the status before any download
# a device's log lines about a failed download: its errors, its packages, its updates
ROS_LOG_WHY = re.compile(r"error|critical|fail|download|package|upgrade|update|disk|space", re.I)
REBOOT_PAGE_S = 3 * 86400          # a reboot pending longer than this pages
SECURITY_PAGE_S = 2 * 86400        # ...and a security update not installed after this
LISTS_STALE_S = 7 * 86400          # apt's lists older than this: "no updates" means nothing
CVSS_PAGE = 7.0
SECURITY_WORDS = re.compile(r"security|CVE-\d|vulnerab", re.I)
ROS_FW_SETTLE_S = 10               # /system routerboard upgrade writes it now; the reboot runs it
APT_WATCH_S = 30                   # a running apt upgrade's latest line, read this often (the page)
# vulners matches the version a service announces. Two ways that is known to be wrong,
# both common (checked by hand on a real scan, none of its CVSS>=7 hits was real):
#   - Debian/Ubuntu backport security fixes WITHOUT changing the upstream version, so
#     "OpenSSH 9.2p1 Debian 2+deb12u7" matched regreSSHion, fixed in that very build;
#   - a version known only by its major line ("Samba smbd 4", gSOAP's generic "2.8") matches
#     every CVE that line ever had.
DISTRO_BUILD = re.compile(r"debian|ubuntu|\+deb\d|deb\d+u\d+", re.I)
GENERIC_PRODUCTS = ("gsoap",)      # nmap names every gSOAP 2.8.x "2.8"
RANK_V = {"applies": 0, "unclear": 1, "not_applicable": 2, "not_affected": 3, "fixed": 4, "ref": 5}

LINUX = ("export LC_ALL=C; . /etc/os-release 2>/dev/null; echo \"OS=$PRETTY_NAME\"; "
         "echo \"KERNEL=$(uname -r)\"; echo \"UPTIME=$(cut -d' ' -f1 /proc/uptime)\"; "
         "if [ -f /var/run/reboot-required ]; then "
         "echo \"REBOOT=$(stat -c %Y /var/run/reboot-required)\"; "
         "sed 's/^/RPKG=/' /var/run/reboot-required.pkgs 2>/dev/null; fi; "
         "echo \"LISTS=$(stat -c %Y /var/lib/apt/lists 2>/dev/null)\"; "
         "apt list --upgradable 2>/dev/null | grep -F '[upgradable' | sed 's/^/UPG=/'; "
         # Ubuntu rolls some updates out gradually and apt holds them back ("deferred due
         # to phasing") until this machine's turn: no button can install them sooner
         "apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null "
         "| sed -n '/deferred due to phasing/,/^[^ ]/{/^ /p}' | sed 's/^/PHASED=/'")


def parse_linux(out: str) -> dict:
    """The facts LINUX prints -> {os, kernel, uptime, reboot_since, reboot_pkgs, updates}."""
    f = {"updates": [], "reboot_pkgs": []}
    phased = set()
    for line in (out or "").splitlines():
        k, _, v = line.partition("=")
        if k == "OS":
            f["os"] = v
        elif k == "KERNEL":
            f["kernel"] = v
        elif k == "UPTIME":
            f["uptime"] = proc_uptime(v)
        elif k == "REBOOT":
            f["reboot_since"] = float(v) if v.strip().isdigit() else time.time()
        elif k == "RPKG" and v.strip():
            f["reboot_pkgs"].append(v.strip())
        elif k == "LISTS" and v.strip().isdigit():
            f["lists_ts"] = float(v)
        elif k == "PHASED":
            phased.update(v.split())
        elif k == "UPG":
            # "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: …]"
            m = re.match(r"([^/\s]+)/(\S+)\s+(\S+)", v)
            if m:
                was = re.search(r"\[upgradable from: ([^\]\s]+)\]", v)
                f["updates"].append({"pkg": m.group(1), "version": m.group(3),
                                     "security": "-security" in m.group(2),
                                     **({"from": was.group(1)} if was else {})})
    for u in f["updates"]:
        u["phased"] = u["pkg"] in phased
    return f


def parse_routeros(out: str) -> dict:
    """/system package update print; /system routerboard print -> {channel, installed, fw…}."""
    def field(name):
        m = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", out or "", re.M)
        return m.group(1).strip('"') if m else ""
    return {"channel": field("channel"), "installed": field("installed-version"),
            "board": field("model") or field("board-name"),
            "fw": field("current-firmware"), "fw_new": field("upgrade-firmware")}


OPENWRT = ("grep -E '^DISTRIB_DESCRIPTION' /etc/openwrt_release; echo \"MODEL=$(cat /tmp/sysinfo/model 2>/dev/null)\"; "
           "echo \"UPTIME=$(cut -d' ' -f1 /proc/uptime)\"; "
           "for i in $(iwinfo 2>/dev/null | awk '/ESSID/ {print $1}'); do "
           "echo \"WIFI=$i $(iwinfo $i assoclist 2>/dev/null | grep -c dBm)\"; done")


def parse_openwrt(out: str) -> dict:
    """OPENWRT's lines -> {os, uptime, clients, radios}."""
    m = re.search(r"DISTRIB_DESCRIPTION='?([^'\n]+)", out or "")
    model = next((ln[6:].strip() for ln in (out or "").splitlines() if ln.startswith("MODEL=")), "")
    up = next((ln[7:].strip() for ln in (out or "").splitlines() if ln.startswith("UPTIME=")), "")
    radios = [ln[5:].split() for ln in (out or "").splitlines() if ln.startswith("WIFI=")]
    clients = sum(int(r[1]) for r in radios if len(r) == 2 and r[1].isdigit())
    return {"os": (m.group(1).strip() if m else "OpenWrt") + (f" ({model})" if model else ""),
            "uptime": proc_uptime(up), "clients": clients if radios else None,
            "radios": len(radios)}


UNIFI = ("mca-cli-op info 2>/dev/null; echo \"ETCVERSION=$(cat /etc/version 2>/dev/null)\"; "
         "echo \"BOARD=$(grep -m1 '^board.name=' /etc/board.info 2>/dev/null | cut -d= -f2)\"; "
         "echo \"UPTIME=$(cut -d' ' -f1 /proc/uptime)\"")


def parse_unifi(out: str) -> dict:
    """mca-cli-op info on a UniFi AP (else its /etc/version and board) -> {os, uptime}."""
    def f(k):
        m = re.search(rf"^\s*{k}:\s*(.+?)\s*$", out or "", re.M)
        return m.group(1) if m else ""

    def kv(k):
        m = re.search(rf"^{k}=(.*)$", out or "", re.M)
        return m.group(1).strip() if m else ""
    model, ver = f("Model") or kv("BOARD"), f("Version") or kv("ETCVERSION")
    up = f("Uptime") or kv("UPTIME")
    secs = re.match(r"([\d.]+)", up)
    return {"os": f"UniFi {model} {ver}".strip() if ver else "",
            "uptime": float(secs.group(1)) if secs else None}


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4])


def between(installed: str, latest: str) -> list:
    """The RouterOS versions after `installed` up to `latest` in the same major.minor line —
    the ones whose changelogs say whether a security fix is being missed. Across a minor
    (7.23.x -> 7.24.y) only the latest line's own releases are listed."""
    a, b = vkey(installed), vkey(latest)
    if len(b) < 2 or not a or b <= a:
        return []
    lo = a[2] + 1 if a[:2] == b[:2] and len(a) > 2 else (1 if a[:2] == b[:2] else 0)
    top = b[2] if len(b) > 2 else 0
    out = []
    for z in range(lo, top + 1):
        out.append(f"{b[0]}.{b[1]}" + (f".{z}" if z else ""))
    return out[-15:]


def parse_vulners(xml_text: str, min_cvss: float = CVSS_PAGE) -> dict:
    """nmap -oX with --script vulners -> {ip: [{port, product, id, cvss, exploit}]}."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    out: dict = {}
    for host in root.iter("host"):
        addr = next((a.get("addr") for a in host.iter("address") if a.get("addrtype") == "ipv4"), "")
        for port in host.iter("port"):
            sv = port.find("service")
            product = " ".join(x for x in ((sv.get("product") or "") if sv is not None else "",
                                           (sv.get("version") or "") if sv is not None else "") if x)
            for sc in port.iter("script"):
                if sc.get("id") != "vulners":
                    continue
                for t in sc.iter("table"):
                    e = {x.get("key"): (x.text or "") for x in t.findall("elem")}
                    if "id" not in e or "cvss" not in e:
                        continue
                    try:
                        cvss = float(e["cvss"])
                    except ValueError:
                        continue
                    if cvss >= min_cvss:
                        out.setdefault(addr, []).append({
                            "port": int(port.get("portid") or 0), "product": product,
                            "version": (sv.get("version") or "") if sv is not None else "",
                            "id": e["id"], "cvss": cvss, "exploit": e.get("is_exploit") == "true"})
    for v in out.values():
        v.sort(key=lambda x: -x["cvss"])
    return out


class Updates:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("updates") or {}
        self.enabled = bool(c.get("enabled", False))
        self.at = str(c.get("at", "06:30"))
        self.hosts = [dict(h) for h in (c.get("hosts") or []) if h.get("ip") and h.get("via")]
        s = c.get("scan") or {}
        self.scan_enabled = bool(s.get("enabled", True))
        self.scan_day = int(s.get("day", 1))
        self.scan_at = str(s.get("at", "04:00"))
        self.scan_top = int(s.get("top_ports", 100))
        self.scan_deny = set(s.get("deny_groups") or ["security", "iot"])
        self._task: Optional[asyncio.Task] = None
        self._scan_task: Optional[asyncio.Task] = None
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("updates: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k, dflt in (("hosts", {}), ("first_seen", {}), ("announced", []), ("ports", {}),
                        ("changelogs", {}), ("scan", {}), ("announced_cve", {}),
                        ("dismissed", {})):
            self.rec.setdefault(k, dflt)

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("updates: record not saved: %s", e)

    # --- when -------------------------------------------------------------------
    @staticmethod
    def _today_at(hhmm: str, now: float) -> float:
        h, _, m = hhmm.partition(":")
        lt = time.localtime(now)
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, int(h or 0), int(m or 0), 0,
                            0, 0, -1))

    def due(self, now: float) -> bool:
        if not self.enabled or (self._task is not None and not self._task.done()):
            return False
        at = self._today_at(self.at, now)
        return now >= at and float(self.rec.get("last") or 0) < at

    def scan_due(self, now: float) -> bool:
        if not (self.enabled and self.scan_enabled) or \
                (self._scan_task is not None and not self._scan_task.done()):
            return False
        if time.localtime(now).tm_mday != self.scan_day:
            return False
        at = self._today_at(self.scan_at, now)
        return now >= at and float(self.rec["scan"].get("ts") or 0) < at

    def start(self, reason: str) -> bool:
        if self._task is not None and not self._task.done():
            return False
        self.rec["last"] = time.time()        # claimed now: a slow run must not start twice
        if reason == "dashboard":
            # the owner's own Check now: the page clears an Update's ✓/✗ with it
            self.rec["last_manual"] = self.rec["last"]
        self._task = asyncio.ensure_future(self._guarded(self.run(reason), "check"))
        return True

    def start_scan(self, reason: str) -> bool:
        if self._scan_task is not None and not self._scan_task.done():
            return False
        self.rec["scan"]["ts"] = time.time()
        self._scan_task = asyncio.ensure_future(self._guarded(self.scan(reason), "scan"))
        return True

    @property
    def running(self) -> dict:
        return {"check": self._task is not None and not self._task.done(),
                "scan": self._scan_task is not None and not self._scan_task.done()}

    async def _guarded(self, coro, what: str):
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("updates: the %s failed", what)

    # --- the daily check -----------------------------------------------------------
    async def run(self, reason: str = "scheduled") -> list:
        """Read every host, work out the findings, page the new ones. Returns the findings."""
        t0 = time.time()
        log.info("updates: checking %d host(s) (%s)", len(self.hosts), reason)
        results = await asyncio.gather(*(self._host(h) for h in self.hosts),
                                       return_exceptions=True)
        for h, r in zip(self.hosts, results):
            if isinstance(r, Exception):
                r = {"error": f"{type(r).__name__}: {r}"[:200]}
            r.update(ts=time.time(), via=h["via"], name=self._name(h["ip"]))
            self.rec["hosts"][h["ip"]] = r
        self._track_first_seen()
        self.rec["ports"] = await self._insecure_ports()
        findings = self.findings()
        self._prune_dismissed(findings)
        await self._announce(findings)
        self.rec["last"] = t0
        self.rec["last_done"] = time.time()
        self._save()
        log.info("updates: done in %.0fs — %d finding(s), %d paging", time.time() - t0,
                 len(findings), sum(1 for f in findings if f["page"]))
        # one Check now, not three: the owner's check goes on into the model's
        # security review, as the morning's does by itself (Exposure.due)
        x = getattr(self.a, "exposure", None)
        if reason == "dashboard" and x is not None and x.enabled:
            x.start("check now")
        return findings

    def _name(self, ip: str) -> str:
        dev = self.a.inv.get(ip)
        if dev is not None:
            return dev.name
        return next((str(h["name"]) for h in self.hosts if h["ip"] == ip and h.get("name")), ip)

    async def _host(self, h: dict) -> dict:
        ip, via = h["ip"], h["via"]
        if via in ("key", "password"):
            if via == "key":
                rc, out, err = await self.a.actions._ssh_run(ip, LINUX, 60)
            else:
                rc, out, err = await self.a.access.ssh(ip, LINUX, timeout_s=60)
            if rc is None or "OS=" not in (out or ""):
                return {"error": f"cannot read it over ssh: {_last(err) or 'no answer'}"}
            return {"kind": "linux", **parse_linux(out)}
        if via == "esxi":
            rc, out, err = await self.a.access.ssh(
                ip, "vmware -vl; esxcli system stats uptime get", timeout_s=40)
            if rc is None or "VMware" not in (out or ""):
                return {"error": f"cannot read it over ssh: {_last(err) or 'no answer'}"}
            lines = [x.strip() for x in out.splitlines() if x.strip()]
            up = next((float(x) / 1e6 for x in lines if x.isdigit()), None)
            return {"kind": "esxi", "os": lines[0], "release": lines[1] if len(lines) > 1 else "",
                    "uptime": up}
        if via == "openwrt":
            # an OpenWrt / LEDE router: its release, board, uptime and
            # Wi-Fi clients. There is no feed of the latest release for a given board: the
            # security review judges the age (exposure.py)
            rc, out, err = await self.a.access.ssh(ip, OPENWRT, timeout_s=30)
            if rc is None or "DISTRIB" not in (out or ""):
                return {"error": f"cannot read it over ssh: {_last(err) or 'no answer'}"}
            return {"kind": "openwrt", **parse_openwrt(out)}
        if via == "unifi":
            # a UniFi AP: updated from the owner's UniFi app — read here, never updated
            # `info` is the interactive shell's alias of mca-cli-op info: not there over ssh -c
            rc, out, err = await self.a.access.ssh(ip, UNIFI, timeout_s=30)
            f = parse_unifi(out) if rc == 0 else {}
            if not f.get("os"):
                return {"error": f"cannot read it over ssh: {_last(err) or 'no answer'}"}
            return {"kind": "unifi", **f}
        if via == "routeros":
            rc, out, err = await self.a.access.ssh(
                ip, "/system package update print; /system routerboard print",
                user_suffix="+ct", timeout_s=30)
            f = parse_routeros(out) if rc == 0 else {}
            if not f.get("installed"):
                return {"error": f"cannot read it over ssh: {_last(err) or 'no answer'}"}
            latest = await self._mikrotik_latest(f["installed"], f["channel"])
            sec = []
            if latest and vkey(latest) > vkey(f["installed"]):
                sec = [v for v in between(f["installed"], latest) if await self._security_release(v)]
            return {"kind": "routeros", **f, "latest": latest, "security_releases": sec}
        if via == "homeassistant":
            st, j = await self.a.actions.reboot._ha("GET", "/api/states", timeout_s=20)
            if st != 200 or not isinstance(j, list):
                return {"error": f"Home Assistant's API did not answer (HTTP {st})"}
            ups = [{"entity": e["entity_id"],
                    "title": (e.get("attributes") or {}).get("title")
                             or (e.get("attributes") or {}).get("friendly_name") or e["entity_id"],
                    "installed": (e.get("attributes") or {}).get("installed_version"),
                    "latest": (e.get("attributes") or {}).get("latest_version")}
                   for e in j if str(e.get("entity_id", "")).startswith("update.")
                   and e.get("state") == "on"]
            st, c = await self.a.actions.reboot._ha("GET", "/api/config")
            return {"kind": "homeassistant", "os": f"Home Assistant {(c or {}).get('version', '?')}",
                    "ha_updates": ups}
        if via == "profile":
            # a kind of the owner's own (kinds.py): its version and its waiting updates, as
            # its profile reads them; reported, never paged
            K, out = self.a.kinds, {}
            prof = K.profile_of(ip)
            if prof is not None and "version" in prof.ops:
                ok, v = await K.run(self.a, ip, "version")
                if not ok:
                    return {"error": f"cannot read it: {v}"}
                out.update(kinds.version_fields(v))
            ok, v = await K.run(self.a, ip, "updates")
            if not ok:
                return {"error": f"cannot read its updates: {v}"}
            return {"kind": prof.kind if prof else "profile", "profile": True, **out,
                    "updates": kinds.update_items(v)}
        return {"error": f"unknown way to read it: {via}"}

    async def _fetch(self, url: str) -> Optional[str]:
        if aiohttp is None:
            return None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                async with s.get(url) as r:
                    return await r.text() if r.status == 200 else None
        except Exception:
            return None

    async def _mikrotik_latest(self, installed: str, channel: str) -> str:
        major = vkey(installed)[:1]
        if not major:
            return ""
        name = (f"NEWESTa7.{channel or 'stable'}" if major[0] >= 7
                else f"NEWEST6.{channel or 'long-term'}")
        cache = self.rec.setdefault("latest", {})
        hit = cache.get(name)
        if hit and time.time() - hit["ts"] < 6 * 3600:
            return hit["v"]
        text = await self._fetch(f"{MIKROTIK}/{name}")
        v = (text or "").split()[0] if text and text.split() else ""
        if v:
            cache[name] = {"v": v, "ts": time.time()}
        return v or (hit or {}).get("v", "")

    async def _security_release(self, version: str) -> bool:
        """Does MikroTik's changelog for `version` speak of security? Cached for good: a
        published changelog does not change."""
        cl = self.rec["changelogs"]
        if version not in cl:
            text = await self._fetch(f"{MIKROTIK}/{version}/CHANGELOG")
            if text is None:
                return False            # not cached: asked again tomorrow
            cl[version] = bool(SECURITY_WORDS.search(text))
        return cl[version]

    def _track_first_seen(self):
        """When each security update was first seen pending, per host: "not installed after
        2 days" needs a start. A package that left the list starts over if it comes back."""
        now = time.time()
        fs = self.rec["first_seen"]
        for ip, h in self.rec["hosts"].items():
            if h.get("kind") != "linux":
                continue
            cur = {u["pkg"] for u in h.get("updates") or [] if u.get("security")}
            old = fs.get(ip) or {}
            fs[ip] = {p: old.get(p, now) for p in cur}

    async def _insecure_ports(self) -> dict:
        """{ip: [port, …]} of the main LAN's devices — and of the hosts this check reads, remote
        routers over their tunnels included — answering on telnet or ftp."""
        ips = [d.ip for d in self.a.inv.devices if on_main_lan(self.a.cfg, d.ip)]
        ips += [h["ip"] for h in self.hosts if h["ip"] not in ips]

        async def one(ip, port):
            return ip, port, (await probes.tcp_check(ip, port, 1200)).ok
        res = await asyncio.gather(*(one(ip, p) for ip in ips for p in INSECURE))
        out: dict = {}
        for ip, port, ok in res:
            if ok:
                out.setdefault(ip, []).append(port)
        return out

    # --- findings ---------------------------------------------------------------------
    def findings(self, now: Optional[float] = None) -> list:
        """[{key, ip, page, text}] — `page`: one of the owner's four rules."""
        now = now or time.time()
        out = []
        for ip, h in self.rec["hosts"].items():
            who = label(h.get("name") or self._name(ip), ip)
            if h.get("error"):
                out.append({"key": f"err:{ip}", "ip": ip, "page": False,
                            "text": f"{who}: not checked — {h['error']}"})
                continue
            if h.get("kind") == "linux":
                rs = h.get("reboot_since")
                if rs:
                    age = now - rs
                    pk = ", ".join(h.get("reboot_pkgs") or [])[:120]
                    out.append({"key": f"reboot:{ip}", "ip": ip, "page": age > REBOOT_PAGE_S,
                                "fp": [f"since {int(rs)}"],
                                "text": f"{who}: reboot pending for {fmt_s(age)}"
                                        + (f" ({pk})" if pk else "")})
                sec = [u["pkg"] for u in h.get("updates") or [] if u.get("security")]
                if sec:
                    oldest = min((self.rec["first_seen"].get(ip) or {}).get(p, now) for p in sec)
                    out.append({"key": f"secupd:{ip}", "ip": ip,
                                "page": now - oldest > SECURITY_PAGE_S, "fp": sorted(set(sec)),
                                "text": f"{who}: {len(sec)} security update(s) not installed "
                                        f"for {fmt_s(now - oldest)} — {', '.join(sec[:6])}"
                                        + ("…" if len(sec) > 6 else "")})
                la = h.get("lists_ts")
                if la and now - la > LISTS_STALE_S:
                    # a box whose last `apt update` was months ago: its "0 updates" says
                    # nothing at all
                    out.append({"key": f"lists:{ip}", "ip": ip, "page": False,
                                "text": f"{who}: its package lists are {fmt_s(now - la)} old — "
                                        "it has not looked for updates since, so what is "
                                        "waiting is unknown"})
                rest = [u for u in h.get("updates") or [] if not u.get("security")]
                held = [u for u in rest if u.get("phased")]
                if rest:
                    out.append({"key": f"upd:{ip}", "ip": ip, "page": False,
                                "text": f"{who}: {len(rest) - len(held)} update(s) waiting"
                                        + (f" + {len(held)} held back by Ubuntu's phased "
                                           "rollout (they come by themselves)" if held else "")}
                               if len(rest) > len(held) else
                               {"key": f"upd:{ip}", "ip": ip, "page": False,
                                "text": f"{who}: {len(held)} update(s) held back by Ubuntu's "
                                        "phased rollout — they install by themselves in a few days"})
            elif h.get("kind") == "routeros":
                inst, lat = h.get("installed", ""), h.get("latest", "")
                if lat and vkey(lat) > vkey(inst):
                    sec = h.get("security_releases") or []
                    out.append({"key": f"ros:{ip}:{lat}", "ip": ip, "page": bool(sec), "fp": [lat],
                                "text": f"{who}: RouterOS {inst} → {lat}"
                                        + (f" — {', '.join(sec)} "
                                           f"{'was a security release' if len(sec) == 1 else 'were security releases'}"
                                           if sec else "")})
                if h.get("fw_new") and h.get("fw") and h["fw_new"] != h["fw"]:
                    out.append({"key": f"fw:{ip}", "ip": ip, "page": False,
                                "text": f"{who}: RouterBOARD firmware {h['fw']} → {h['fw_new']}"})
            elif h.get("profile"):
                ups = h.get("updates") or []
                if ups:
                    names = ", ".join(u["pkg"] for u in ups[:6]) + ("…" if len(ups) > 6 else "")
                    out.append({"key": f"upd:{ip}", "ip": ip, "page": False,
                                "text": f"{who}: {len(ups)} update(s) waiting — {names}"})
            elif h.get("kind") == "homeassistant":
                for u in h.get("ha_updates") or []:
                    out.append({"key": f"ha:{u['entity']}", "ip": ip, "page": False,
                                "text": f"{u['title']}: {u.get('installed')} → {u.get('latest')} "
                                        "(Home Assistant)"})
        for ip, ports in (self.rec.get("ports") or {}).items():
            for p in ports:
                out.append({"key": f"port:{ip}:{p}", "ip": ip, "page": True, "fp": [],
                            "text": f"{label(self._name(ip), ip)}: {INSECURE.get(p, p)} (port {p}) "
                                    "is open — its logins travel unencrypted"})
        for ip, vs in (self.rec["scan"].get("found") or {}).items():
            # each CVE checked against the machine's own build or NVD, then read by the model
            # (cves.py); only one that APPLIES pages
            app = self.applying(ip)
            who = label(self._name(ip), ip)
            if app:
                top = max(app, key=lambda x: x[0].get("cvss") or 0)
                text = (f"{who}: {len(app)} known vulnerabilit{'y' if len(app) == 1 else 'ies'} "
                        f"≥ CVSS {CVSS_PAGE:g} appl{'ies' if len(app) == 1 else 'y'} — worst "
                        f"{top[0]['id']} ({top[0]['cvss']:g}) in "
                        f"{top[0]['product'] or 'port ' + str(top[0]['port'])}: {top[1].get('why', '')}")
            else:
                text = f"{who}: {self.cve_words(ip)}"
            out.append({"key": f"cve:{ip}", "ip": ip, "page": bool(app), "text": text,
                        "fp": sorted({x["id"] for x, _ in app})})
        # the owner's dismissals: out of the list, paging nothing, while nothing new — a
        # non-urgent one as much as one that matters (the Security tab is one list, and its
        # Dismiss works on every row)
        dis = self.rec.get("dismissed") or {}
        for f in out:
            d = dis.get(f["key"])
            if d is not None and not set(f.get("fp") or []) - set(d.get("fp") or []):
                f["page"] = False
                f["dismissed"] = {"ts": d["ts"], "note": d.get("note") or ""}
        return out

    # --- the owner's dismissals -----------------------------------------------------------
    # Dismiss what matters, one by one, as known. It leaves "What matters"
    # and stops paging until something NEW shows up for it: a new vulnerability or version
    # on that device at a scan, a new security package, a new pending reboot, a newer
    # RouterOS release. An insecure port (the alarm's telnet) stays dismissed until undone.
    def dismiss(self, key: str, note: str = "", by: str = "owner") -> dict:
        f = next((x for x in self.findings() if x["key"] == key), None)
        if f is None:
            return {"ok": False, "error": "that finding is not there any more"}
        if f.get("dismissed"):
            return {"ok": True, "already": True}
        note = " ".join(str(note or "").split())[:300]
        self.rec["dismissed"][key] = {"ts": time.time(), "by": by, "note": note,
                                      "fp": f.get("fp") or [], "text": f["text"]}
        self._save()
        log.info("updates: %s dismissed by the %s%s", key, by, f" — {note}" if note else "")
        return {"ok": True}

    def undismiss(self, key: str, by: str = "owner") -> dict:
        if self.rec["dismissed"].pop(key, None) is None:
            return {"ok": False, "error": "it is not dismissed"}
        self._save()
        log.info("updates: %s back in what matters (undone by the %s)", key, by)
        return {"ok": True}

    def _prune_dismissed(self, findings: list):
        """After a check or a scan: a dismissal whose finding brought something new is
        lifted, one whose finding went away is dropped (it would be new if it came back) —
        but a port's lasts until the owner undoes it, and a host that could not be read
        keeps its own."""
        cur = {f["key"]: f for f in findings}
        broken = {ip for ip, h in self.rec["hosts"].items() if h.get("error")}
        for key, d in list(self.rec["dismissed"].items()):
            f = cur.get(key)
            if f is not None and not f.get("dismissed"):
                new = sorted(set(f.get("fp") or []) - set(d.get("fp") or []))
                del self.rec["dismissed"][key]
                log.info("updates: %s back in what matters — something new: %s", key,
                         ", ".join(new)[:200])
            elif f is None and not key.startswith("port:") and key.split(":")[1] not in broken:
                del self.rec["dismissed"][key]
                log.info("updates: %s dismissal dropped — the finding went away", key)

    # --- what each scan match turned out to be (cves.py) ----------------------------
    CVE_WORDS = (("applies", "applies", "apply"), ("unclear", "can't be judged", "can't be judged"),
                 ("not_applicable", "doesn't apply here", "don't apply here"),
                 ("not_affected", "outside the affected versions", "outside the affected versions"),
                 ("fixed", "fixed in its build", "fixed in its build"))

    def verdict_of(self, ip: str, m: dict) -> dict:
        """{v, why, by, url?}: the check's verdict, or — before it has run on this scan — the
        version rule: a vague or backported version is unclear, the rest applies."""
        c = getattr(self.a, "cves", None)
        v = c.verdict(ip, m) if c is not None else None
        if v:
            return v
        if not str(m.get("id") or "").startswith("CVE-"):
            return {"v": "ref", "by": "code", "why": "an exploit or advisory reference with no CVE id: not judged"}
        u = self.unconfirmed(ip, m)
        return ({"v": "unclear", "by": "code", "why": u} if u else
                {"v": "applies", "by": "code", "why": "matches its version — not checked yet"})

    def matches(self, ip: str) -> list:
        """The scan's matches on one machine, once per id: Samba's CVEs come once for port 139
        and again for 445 (the ports kept together, for the page)."""
        out: dict = {}
        for x in (self.rec["scan"].get("found") or {}).get(ip) or []:
            k = str(x.get("id") or "")
            if k in out:
                out[k]["ports"] = sorted(set(out[k]["ports"]) | {x.get("port")})
            else:
                out[k] = {**x, "ports": [x.get("port")]}
        return list(out.values())

    def applying(self, ip: str) -> list:
        """[(match, verdict)] of the CVEs at CVSS 7+ that apply on this machine — what pages."""
        return [(x, v) for x in self.matches(ip)
                for v in [self.verdict_of(ip, x)]
                if v["v"] == "applies" and (x.get("cvss") or 0) >= CVSS_PAGE]

    def cve_words(self, ip: str) -> str:
        vs = self.matches(ip)
        n: dict = {}
        for x in vs:
            k = self.verdict_of(ip, x)["v"]
            n[k] = n.get(k, 0) + 1
        cves = sum(v for k, v in n.items() if k != "ref")
        parts = [f"{n[k]} {one if n[k] == 1 else many}" for k, one, many in self.CVE_WORDS if n.get(k)]
        return (f"none of its {cves} CVE match{'' if cves == 1 else 'es'} ≥ CVSS {CVSS_PAGE:g} applies"
                if not n.get("applies") else f"{cves} CVE match{'' if cves == 1 else 'es'}") + \
            (f" — {', '.join(parts)}" if parts else "") + \
            (f"; {n['ref']} exploit reference{'' if n['ref'] == 1 else 's'} without a CVE id" if n.get("ref") else "")

    def after_cves(self, reason: str):
        """The check has worked out what applies (cves.py): one message for the
        machines with a CVE that applies and was not announced before."""
        found = self.rec["scan"].get("found") or {}
        seen = self.rec.setdefault("announced_cve", {})
        conf = {ip: {x["id"] for x, _ in self.applying(ip)} for ip in found}
        dis = {f["ip"] for f in self.findings() if f["key"].startswith("cve:") and f.get("dismissed")}
        new_ips = [ip for ip, ids in conf.items() if ids - set(seen.get(ip) or []) and ip not in dis]
        # Announced stays announced while the scan still matches it on that machine: the model's
        # reading of the same facts can flip between two checks, and a flip (applies → doesn't
        # → applies) would page the same CVE twice in ten minutes.
        # A CVE the scan no longer finds there (the machine was updated) is forgotten.
        self.rec["announced_cve"] = {
            ip: sorted(ids) for ip in found
            for ids in [(set(seen.get(ip) or []) & {str(x.get("id")) for x in found[ip]}) | conf[ip]] if ids}
        self._prune_dismissed(self.findings())
        self._save()
        if not new_ips:
            return
        lines = [f["text"] for f in self.findings() if f["key"].startswith("cve:") and f["ip"] in new_ips]
        self.a._emit_telegram("digest", (
            f"🛡 <b>{'Monthly vulnerability scan' if 'scan' in reason else 'Known vulnerabilities'}</b> — "
            f"{len(new_ips)} device(s) with a known vulnerability that applies (CVSS ≥ {CVSS_PAGE:g})\n"
            + "\n".join(f"• {_html(x)}" for x in lines[:12])
            + "\n<i>Each one checked against the machine's own build or NVD, then read by the model. "
              "Every match, with why, is on the dashboard: Security → Deep scan results.</i>"))

    def unconfirmed(self, ip: str, v: dict) -> str:
        """Why a version match cannot be trusted, or "" when it can — the rule before the
        check of cves.py has run on a scan."""
        prod = str(v.get("product") or "")
        ver = str(v.get("version") or (prod.split()[-1] if prod.split() else ""))
        if DISTRO_BUILD.search(f"{prod} {ver}"):
            return "a Debian/Ubuntu build — its security fixes are backported without a new version"
        kind = (self.rec["hosts"].get(ip) or {}).get("kind")
        if kind == "linux":
            return "a Debian/Ubuntu machine — its security updates are read from apt every day instead"
        if kind == "esxi":
            # its sshd says "9.8" for VMware's 9.8p1 — the regreSSHion fix itself matched
            return "VMware's own build — patched by ESXi updates; nmap sees '9.8' for 9.8p1"
        if prod.lower().startswith(GENERIC_PRODUCTS) or len(re.findall(r"\d+", ver)) < 2:
            return "only the major version is known, which matches every CVE that line ever had"
        return ""

    async def _announce(self, findings: list):
        """One message for the daily findings that page and were not announced before. One
        that goes away is forgotten, so it pages again if it ever comes back. The scan's own
        findings are the scan's to announce (scan), once a month."""
        pages = [f for f in findings if f["page"] and not f["key"].startswith("cve:")]
        known = set(self.rec.get("announced") or [])
        new = [f for f in pages if f["key"] not in known]
        # a dismissed one counts as announced: undoing it later does not page it again
        self.rec["announced"] = sorted({f["key"] for f in pages}
                                       | {f["key"] for f in findings if f.get("dismissed")})
        if not new:
            return
        self.a._emit_telegram("digest", (
            f"🛡 <b>Updates &amp; security</b> — {len(new)} new\n"
            + "\n".join(f"• {_html(f['text'])}" for f in new[:12])
            + (f"\n…and {len(new) - 12} more" if len(new) > 12 else "")
            + "\n<i>Everything else is on the dashboard, under Security.</i>"))

    # --- the monthly scan -----------------------------------------------------------------
    async def scan(self, reason: str = "scheduled") -> dict:
        """nmap -sV --script vulners over the main LAN's devices; CVSS >= 7 kept. Slow on
        purpose (-T3, one run a month): cheap IoT has been known to fall over under -sV, so
        the security and iot groups are left out, as for nmap_service."""
        ips = [d.ip for d in self.a.inv.devices
               if on_main_lan(self.a.cfg, d.ip) and d.group not in self.scan_deny
               and d.ip != str((self.a.cfg.get("observer") or {}).get("host_ip") or "")]
        t0 = time.time()
        log.info("updates: vulnerability scan of %d device(s) (%s)", len(ips), reason)
        rc, out, err = await _exec(
            ["nmap", "-sT", "-sV", "-Pn", "-T3", "--top-ports", str(self.scan_top),
             "--script", "vulners", "--script-args", f"mincvss={CVSS_PAGE:g}", "-oX", "-"] + ips,
            timeout_s=3600)
        s = self.rec["scan"]
        if rc is None or rc != 0 or "<nmaprun" not in (out or ""):
            s.update(ts=t0, error=f"nmap failed: {_last(err) or f'rc {rc}'}")
            self._save()
            log.warning("updates: the scan failed: %s", s["error"])
            return s
        found = parse_vulners(out)
        s.update(ts=t0, done=time.time(), devices=len(ips), found=found)
        s.pop("error", None)
        self._prune_dismissed(self.findings())
        self._save()
        log.info("updates: scan done in %.0f min — %d device(s) with CVSS ≥ %g; checking each match",
                 (time.time() - t0) / 60, len(found), CVSS_PAGE)
        # each match checked (cves.py), which announces what applies — a version match
        # alone does not page
        c = getattr(self.a, "cves", None)
        if c is not None:
            await c.verify("after the monthly scan")
        else:
            self.after_cves("after the monthly scan")
        return s

    # --- installing them: the apt_upgrade action (actions.py) ----------------------
    def upgradable(self) -> dict:
        """ip -> {via, risk}: the hosts whose updates may be installed with a button."""
        c = (((self.a.cfg.get("actions") or {}).get("catalog") or {}).get("apt_upgrade") or {})
        return {str(ip): dict(v or {}) for ip, v in (c.get("hosts") or {}).items()
                if (v or {}).get("via") in ("key", "password")}

    async def _remote(self, ip: str, cmd: str, timeout_s: float, root_cmd: bool = False) -> tuple:
        """`via: key` logs in as root (a VPS); `via: password` with its login from secrets.yaml, and
        `root_cmd` runs it through sudo -S with the same password."""
        via = self.upgradable().get(ip, {}).get("via")
        if via == "key":
            return await self.a.actions._ssh_run(ip, cmd, timeout_s, root=root_cmd)
        if root_cmd:
            cmd = f"sudo -S -p '' sh -c {_sq(cmd)}"
        return await self.a.access.ssh(ip, cmd, sudo_pw=root_cmd, timeout_s=timeout_s)

    async def upgrade_check(self, ip: str, name: str) -> dict:
        # lists older than a day are refreshed first: what is waiting can only be known then
        rc, out, err = await self._remote(
            ip, "find /var/lib/apt/lists -maxdepth 0 -mmin +1440 | grep -q . && "
                "apt-get update -q >/dev/null 2>&1; true", 300, root_cmd=True)
        rc, out, err = await self._remote(ip, LINUX, 60)
        if rc is None or "OS=" not in (out or ""):
            return {"ok": False, "note": f"cannot read {name} over ssh: {_last(err) or 'no answer'}"}
        f = parse_linux(out)
        # what the page listed (the morning's reading), then the row brought up to date: an
        # unattended upgrade half an hour after the morning check would otherwise leave the
        # page offering it all day — three presses, three "nothing to update"
        before = {u["pkg"]: u for u in (self.rec["hosts"].get(ip) or {}).get("updates") or []}
        read_at = (self.rec["hosts"].get(ip) or {}).get("ts")
        self._refresh_host(ip, f)
        now = [u for u in f["updates"] if not u.get("phased")]
        held = len(f["updates"]) - len(now)
        n, sec = len(now), sum(1 for u in now if u["security"])
        if not n:
            gone = sorted(set(before) - {u["pkg"] for u in f["updates"]})
            since = ""
            if gone:
                how = await self._installed_how(ip, gone)
                since = (f" — {', '.join(gone[:4])}{'…' if len(gone) > 4 else ''}, listed at "
                         f"{time.strftime('%H:%M', time.localtime(read_at)) if read_at else 'the last check'}, "
                         f"{'were' if len(gone) > 1 else 'was'} installed afterwards"
                         + (f", {how}" if how else "") + ". The list is up to date now")
            return {"ok": False, "note": f"{name} has nothing to update{since}"
                                         + (f" — {held} held back by Ubuntu's phased rollout, "
                                            "they install by themselves" if held else "")}
        chk = {"ok": True, "note": f"{n} update(s) waiting ({sec} security)", "before": n,
               "risk": []}
        plan = await self.a.backups.snapshot_plan(ip)
        if plan is not None:
            if plan.get("error"):
                return {"ok": False, "note": f"{plan['error']} — no snapshot, no update"}
            for sname in plan["replace"]:
                chk["risk"].append(f"its VM already has lanowl's snapshot {sname} — "
                                   "approving REMOVES it and takes a new one")
            for sname in plan["keep"]:
                chk["risk"].append(f"its VM also has the snapshot '{sname}' (not lanowl's) "
                                   "— it is kept")
            chk["snap_replace"] = plan["replace"]
        return chk

    def _refresh_host(self, ip: str, f: dict):
        """One machine's row re-read outside the daily check (an Update's pre-check)."""
        h = dict(self.rec["hosts"].get(ip) or {})
        for k in ("updates", "reboot_since", "reboot_pkgs", "lists_ts"):
            h.pop(k, None)
        h.update({"kind": "linux", **f, "ts": time.time()})
        h.pop("error", None)
        self.rec["hosts"][ip] = h
        self._track_first_seen()
        self._save()

    async def _installed_how(self, ip: str, pkgs: list) -> str:
        """"at 06:59, by Ubuntu's automatic security updates" — from the machine's apt history,
        or "" when it does not say."""
        pat = "|".join(re.escape(p) for p in pkgs[:12])
        # apt writes the MACHINE's local time: the VPS runs on UTC, so its "06:59" was 08:59
        # here — said as "06:59" beside the check's "06:30" it read as half an hour later
        cmd = (f"grep -h -B4 -E 'Upgrade:.*[ ,]({pat})[: ]' /var/log/apt/history.log 2>/dev/null "
               "| grep -E '^(Start-Date|Commandline):' | tail -2; echo \"TZ=$(date +%z)\"")
        try:
            rc, out, _ = await self._remote(ip, cmd, 30)
        except Exception:
            return ""
        m = re.search(r"Start-Date:\s*(\d{4})-(\d\d)-(\d\d)\s+(\d\d):(\d\d):(\d\d)", out or "")
        c = re.search(r"Commandline:\s*(\S+)", out or "")
        z = re.search(r"TZ=([+-])(\d\d)(\d\d)", out or "")
        if not m:
            return ""
        off = (1 if not z or z.group(1) == "+" else -1) * (int(z.group(2)) * 3600 + int(z.group(3)) * 60) if z else 0
        at = calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0)) - off
        day = "" if time.strftime("%m-%d", time.localtime(at)) == time.strftime("%m-%d") else \
            time.strftime(" on %d/%m", time.localtime(at))
        who = ("by Ubuntu's automatic security updates (unattended-upgrades)" if c and "unattended" in c.group(1)
               else "by lanowl's own Update" if c and "systemd-run" in (out or "")
               else f"by {c.group(1).rsplit('/', 1)[-1]}" if c else "")
        return f"at {time.strftime('%H:%M', time.localtime(at))}{day}" + (f", {who}" if who else "")

    async def upgrade_run(self, ip: str, name: str, chk: dict) -> dict:
        # systemd-run: dpkg runs as a unit of its own, so an ssh link that drops halfway cannot
        # leave it half-configured. Config files kept as they are; needrestart only LISTS
        # (NEEDRESTART_MODE=l) — nothing is restarted behind the owner's back.
        cmd = ("systemd-run --wait --collect --quiet --unit=lanowl-apt-upgrade-$(date +%s) "
               "--setenv=DEBIAN_FRONTEND=noninteractive --setenv=NEEDRESTART_MODE=l "
               "sh -c 'apt-get update -q && apt-get -y -q -o Dpkg::Options::=--force-confdef "
               "-o Dpkg::Options::=--force-confold --with-new-pkgs upgrade'; echo RC=$?")
        self.a.actions.step("installing the updates")
        watch = asyncio.ensure_future(self._apt_watch(ip, time.time(), int(chk.get("before") or 0)))
        try:
            rc, out, err = await self._remote(ip, cmd, 2700, root_cmd=True)   # a Pi Zero, months behind
        finally:
            watch.cancel()
        self.a.actions.step("reading what is left")
        m = re.search(r"RC=(\d+)", out or "")
        if rc is None or not m:
            return {"ok": False, "ran": rc is not None,
                    "error": f"the upgrade did not report back: {_last(err) or f'rc {rc}'}"}
        rc2, out2, _ = await self._remote(ip, LINUX, 60)
        f = parse_linux(out2) if rc2 == 0 else {"updates": []}
        held = sum(1 for u in f.get("updates") or [] if u.get("phased"))
        left = len(f.get("updates") or []) - held
        done = max(0, int(chk.get("before") or 0) - left - held)
        tail = "; a reboot is now pending — Reboot it when it suits" if f.get("reboot_since") else ""
        if m.group(1) != "0":
            return {"ok": False, "ran": True,
                    "error": f"apt-get failed (exit {m.group(1)}) — {done} installed, {left} left{tail}"}
        self.start("after an upgrade")          # the dashboard's list, at once
        return {"ok": True, "ran": True,
                "result": f"{done} package(s) updated"
                          + (f", {left} left" if left else "")
                          + (f", {held} held back by Ubuntu's phased rollout (they come by "
                             "themselves)" if held else "") + tail}

    async def _apt_watch(self, ip: str, since: float, total: int):
        """While apt runs: its latest line and how many packages are set up, read from the
        machine's own journal (the systemd-run unit's output) — the page's proof that it is not
        stuck. A machine too busy to answer is said so; the last good line is kept."""
        cmd = (f"journalctl -u 'lanowl-apt-upgrade-*' --since @{int(since) - 5} -o cat "
               "--no-pager | awk 'NF {last = $0} /^Setting up / {n++} "
               "END {print \"N=\" n + 0; print last}'")
        while True:
            await asyncio.sleep(APT_WATCH_S)
            try:
                rc, out, err = await self._remote(ip, cmd, 20, root_cmd=True)
            except Exception as e:                # never the upgrade's problem
                rc, out, err = None, "", str(e)
            lines = (out or "").strip().splitlines()
            m = re.fullmatch(r"N=(\d+)", lines[0].strip()) if lines else None
            if rc == 0 and m:
                self.a.actions.progress(text=lines[1].strip() if len(lines) > 1 else "",
                                        n=int(m.group(1)), of=total)
            else:
                self.a.actions.progress(error="no answer from it right now")

    # --- RouterOS: the routeros_upgrade action ---------------------------------------------
    # Download first, reboot after: a download that fails (small APs have ~3 MB of flash
    # free) changes nothing, and the
    # reboot is the Reboot button's own — alerts held, watched until it answers again.
    def ros_upgradable(self) -> dict:
        c = (((self.a.cfg.get("actions") or {}).get("catalog") or {}).get("routeros_upgrade") or {})
        return {str(ip): dict(v or {}) for ip, v in (c.get("hosts") or {}).items()}

    async def _ros_update(self, ip: str, wait_s: float, until) -> dict:
        """`/system package update print`, again until `until(status)` or `wait_s` is up."""
        t0, f = time.time(), {}
        while True:
            rc, out, err = await self.a.access.ssh(ip, "/system package update print",
                                                   user_suffix="+ct", timeout_s=20)
            if rc == 0:
                f = {k: routeros_field(out, k) for k in ("installed-version", "latest-version",
                                                         "status", "channel")}
                if until(f["status"]):
                    return f
            if time.time() - t0 > wait_s:
                return {**f, "timeout": True, "error": _last(err)}
            await asyncio.sleep(ROS_POLL_S)

    async def ros_upgrade_check(self, ip: str, name: str) -> dict:
        dev = self.a.inv.get(ip)
        if dev is not None and dev.attrs.get("role") == "wan-gateway" and \
                (self.a._last_report or {}).get("wan_state") in ("backup", "down"):
            return {"ok": False, "note": f"the network's internet is on the {name} right now — "
                                         "not updating it"}
        chk = await self.a.actions.reboot._check_routeros(ip, name, {})
        if not chk.get("ok"):
            return chk
        rc, out, err = await self.a.access.ssh(
            ip, "/system package update check-for-updates once", user_suffix="+ct", timeout_s=30)
        f = await self._ros_update(ip, 30, lambda st: bool(st) and "finding out" not in st)
        inst, lat = f.get("installed-version", ""), f.get("latest-version", "")
        rb = await self._routerboard(ip)
        fw = bool(rb["fw"] and rb["fw_new"] and rb["fw"] != rb["fw_new"])
        known = bool(lat) and not f.get("timeout")
        await self._refresh_ros(ip, f, rb, known)
        if not known and not fw:
            return {"ok": False, "note": f"{name} could not find out MikroTik's latest version "
                                         f"({f.get('status') or 'no answer'})"}
        ros = known and vkey(lat) > vkey(inst)
        if not ros and not fw:
            return {"ok": False, "note": f"{name} is already on the latest RouterOS ({inst}) "
                                         "and its firmware is current"}
        # the Update button flashes the RouterBOARD firmware too — after
        # RouterOS (which brings the new firmware with it), with one more reboot of its own
        plan = ([f"RouterOS {inst} → {lat}, then its firmware (one more reboot)"] if ros else
                [f"RouterBOARD firmware {rb['fw']} → {rb['fw_new']} (one reboot)"])
        chk.update(note="; ".join(plan) + "; " + chk["note"], before=inst, latest=lat, ros=ros)
        # what goes dark with it: the main router takes the internet, the tunnels, a standby
        # link and the WAN watcher's messages ("wan") with it
        also = {str(x) for x in self.ros_upgradable().get(ip, {}).get("also_hold") or []}
        chk["clients"] = sorted(set(chk.get("clients") or []) | also - {ip})
        return chk

    async def _refresh_ros(self, ip: str, f: dict, rb: dict, known: bool):
        """The row brought up to date with what the Update's check just read, so the dashboard
        shows it at once — as the apt machines' `_refresh_host`."""
        h = self.rec["hosts"].get(ip)
        if not h or h.get("kind") != "routeros":
            return
        inst, lat = f.get("installed-version", ""), f.get("latest-version", "")
        if inst:
            h["installed"] = inst
        if f.get("channel"):
            h["channel"] = f["channel"]
        if known:
            if vkey(lat) <= vkey(inst or h.get("installed", "")):
                h["security_releases"] = []
            elif lat != h.get("latest"):
                h["security_releases"] = [v for v in between(inst, lat) if await self._security_release(v)]
            h["latest"] = lat
        if rb.get("fw"):
            h["fw"], h["fw_new"] = rb["fw"], rb["fw_new"]
        h.pop("error", None)
        h["ts"] = time.time()
        self._save()

    async def _ros_log(self, ip: str) -> Optional[list]:
        """The device's log, line by line as it prints it; None: it could not be read."""
        rc, out, _ = await self.a.access.ssh(ip, "/log print without-paging", user_suffix="+ct",
                                             timeout_s=30)
        return [s.strip() for s in out.splitlines() if s.strip()] if rc == 0 else None

    async def _routerboard(self, ip: str) -> dict:
        rc, out, _ = await self.a.access.ssh(ip, "/system routerboard print", user_suffix="+ct",
                                             timeout_s=20)
        f = parse_routeros(out) if rc == 0 else {}
        return {"fw": f.get("fw", ""), "fw_new": f.get("fw_new", "")}

    async def ros_upgrade_run(self, ip: str, name: str, chk: dict) -> dict:
        h = self.ros_upgradable().get(ip, {})
        hold = float(h.get("hold_min", 10)) * 60
        parts, last = [], None
        if chk.get("ros", True):
            r = await self._ros_package(ip, name, chk, hold)
            if not r.get("ok"):
                return r
            parts.append(r.pop("step"))
            last = r
        rb = await self._routerboard(ip)
        if rb["fw"] and rb["fw_new"] and rb["fw"] != rb["fw_new"]:
            self.a.actions.step("flashing the firmware")
            await self.a.access.ssh(ip, "/system routerboard upgrade", stdin=b"y\n",
                                    user_suffix="+ct", timeout_s=60)
            await asyncio.sleep(ROS_FW_SETTLE_S)
            r2 = await self.a.actions.reboot.run(ip, name, chk, via="routeros", back_s=ROS_BACK_S,
                                                 hold_s=hold)
            if not r2.get("ok"):
                self.start("after an upgrade")
                return {"ok": False, "ran": True,
                        "error": "; ".join(parts + [f"firmware flashed, then: {r2.get('error')}"])}
            rb2 = await self._routerboard(ip)
            if rb2["fw"] != rb2["fw_new"] or not rb2["fw"]:
                self.start("after an upgrade")
                return {"ok": False, "ran": True,
                        "error": "; ".join(parts + [f"rebooted, but the firmware is still "
                                                    f"{rb2['fw'] or '?'} (expected {rb['fw_new']})"])}
            parts.append(f"firmware {rb['fw']} → {rb2['fw']}")
            last = r2
        self.start("after an upgrade")
        if last is None:
            return {"ok": False, "ran": False, "error": "nothing was left to update"}
        return {"ok": True, "ran": True,
                "result": "; ".join(parts) + "; " + last["result"].replace("rebooted — ", "")}

    async def _ros_package(self, ip: str, name: str, chk: dict, hold: float) -> dict:
        """RouterOS itself: download, reboot, read the version back. {"ok", "step"|"error"}."""
        self.a.actions.step("downloading RouterOS")
        # Why a download failed is in the device's log, and only there for now: a MikroTik
        # logs to memory, and the reboot that installs it by hand wipes it. Its last line now
        # marks where this download's lines begin.
        before = await self._ros_log(ip)
        rc, _, _ = await self.a.access.ssh(ip, "/system package update download",
                                           user_suffix="+ct", timeout_s=ROS_DOWNLOAD_S)
        # a command that came back with the status never moving did not start one — no use
        # waiting the full time for it
        asked = time.time()
        f = await self._ros_update(ip, ROS_DOWNLOAD_S, lambda st: bool(re.search(
            r"downloaded|reboot|error|fail|not enough", st or "", re.I)) or (
            rc is not None and bool(ROS_IDLE.search(st or "")) and time.time() - asked > ROS_START_S))
        st = f.get("status", "")
        if f.get("timeout") or not re.search(r"downloaded|reboot", st, re.I):
            return {"ok": False, "ran": False,
                    "error": f"the download did not {'start' if ROS_IDLE.search(st) else 'finish'} "
                             f"— nothing was installed ({st or f.get('error') or 'no answer'}); "
                             f"{_ros_log_says(before, await self._ros_log(ip))}"}
        r = await self.a.actions.reboot.run(ip, name, chk, via="routeros", back_s=ROS_BACK_S,
                                            hold_s=hold)
        if not r.get("ok"):
            return {**r, "error": f"downloaded, then: {r.get('error')}"}
        self.a.actions.step("reading the version back")
        f = await self._ros_update(ip, 60, lambda st: True)
        now_v = f.get("installed-version", "")
        if vkey(now_v) != vkey(chk.get("latest", "")):
            self.start("after an upgrade")
            return {"ok": False, "ran": True,
                    "error": f"it rebooted, but still runs RouterOS {now_v or '?'} "
                             f"(expected {chk.get('latest')})"}
        return {**r, "step": f"RouterOS {chk.get('before')} → {now_v}"}

    # --- what others read ---------------------------------------------------------------
    def view(self) -> dict:
        fs = self.findings() if self.rec.get("hosts") else []
        hosts = []
        for ip, h in self.rec["hosts"].items():
            ros_behind = bool(h.get("latest")) and vkey(h["latest"]) > vkey(h.get("installed", ""))
            fw_pending = bool(h.get("fw") and h.get("fw_new") and h["fw"] != h["fw_new"])
            hosts.append({"ip": ip, "name": h.get("name") or self._name(ip), "kind": h.get("kind"),
                          "os": h.get("os") or (f"RouterOS {h['installed']}" if h.get("installed") else ""),
                          "error": h.get("error"), "uptime": h.get("uptime"),
                          "updates": sum(1 for u in h.get("updates") or [] if not u.get("phased"))
                                     + len(h.get("ha_updates") or []) + int(ros_behind) + int(fw_pending),
                          "phased": sum(1 for u in h.get("updates") or [] if u.get("phased")),
                          "clients": h.get("clients"),
                          "ros_behind": ros_behind, "fw": h.get("fw"), "fw_new": h.get("fw_new"),
                          "security": sum(1 for u in h.get("updates") or [] if u.get("security"))
                                      + int(ros_behind and bool(h.get("security_releases"))),
                          "reboot_since": h.get("reboot_since"), "latest": h.get("latest"),
                          # the list itself, for the device sheet: what an Update
                          # would install, and what asked for the pending reboot
                          "packages": [{"pkg": u["pkg"], "to": u.get("version"),
                                        "from": u.get("from"), "security": bool(u.get("security")),
                                        "phased": bool(u.get("phased"))}
                                       for u in h.get("updates") or []],
                          "reboot_pkgs": h.get("reboot_pkgs") or [],
                          "ha": [{k: u.get(k) for k in ("title", "installed", "latest")}
                                 for u in h.get("ha_updates") or []],
                          "security_releases": h.get("security_releases") or [],
                          "lists_age": (time.time() - h["lists_ts"]) if h.get("lists_ts") else None,
                          "ts": h.get("ts")})
        s = self.rec["scan"]
        return {"enabled": self.enabled, "last": self.rec.get("last_done"), "at": self.at,
                "last_manual": self.rec.get("last_manual"),
                "running": self.running, "hosts": hosts,
                "upgradable": sorted(set(self.upgradable()) | set(self.ros_upgradable())),
                "findings": sorted(({k: v for k, v in f.items() if k != "fp"} for f in fs),
                                   key=lambda f: (not f["page"], f["key"])),
                "scan": {"ts": s.get("done"), "devices": s.get("devices"), "error": s.get("error"),
                         "day": self.scan_day,
                         "check": self.a.cves.view() if getattr(self.a, "cves", None) is not None else None,
                         "found": {ip: self._found_view(ip, v) for ip, v in (s.get("found") or {}).items()}}}

    def _found_view(self, ip: str, v: list) -> dict:
        """One machine's matches for the page: the CVEs with their verdicts, what applies first."""
        vd = [(x, self.verdict_of(ip, x)) for x in self.matches(ip)]
        counts: dict = {}
        for _, d in vd:
            counts[d["v"]] = counts.get(d["v"], 0) + 1
        cves = sorted(((x, d) for x, d in vd if d["v"] != "ref"),
                      key=lambda p: (RANK_V.get(p[1]["v"], 9), -(p[0].get("cvss") or 0)))
        return {"name": self._name(ip), "count": len(v), "cves": len(cves), "refs": counts.get("ref", 0),
                "confirmed": len(self.applying(ip)), "counts": counts, "words": self.cve_words(ip),
                "vulns": [{"id": x["id"], "cvss": x.get("cvss"), "product": x.get("product"),
                           "port": "/".join(str(p) for p in x["ports"]), "exploit": bool(x.get("exploit")), "verdict": d["v"],
                           "why": d.get("why"), "url": d.get("url"), "by": d.get("by")}
                          for x, d in cves[:40]]}

    def weekly_lines(self) -> list:
        """The weekly review's lines: what is waiting, in one or two lines."""
        if not self.enabled or not self.rec.get("hosts"):
            return []
        fs = self.findings()
        n = sum(1 for f in fs if f["key"].startswith(("upd:", "secupd:", "ros:", "ha:")))
        pages = [f for f in fs if f["page"]]
        line = f"🛡 Updates: {n} thing(s) waiting to be updated"
        if pages:
            line += f", {len(pages)} that matter: " + "; ".join(f["text"] for f in pages[:3])
        dism = [f for f in fs if f.get("dismissed")]
        if dism:
            # known to the owner: not news, and the reason is theirs
            line += (f"; {len(dism)} dismissed by the owner as known: "
                     + "; ".join(f["text"] + (f" (owner: {f['dismissed']['note']})"
                                              if f["dismissed"]["note"] else "")
                                 for f in dism[:4]))
        return [line]


def _sq(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _last(text: str) -> str:
    return ((text or "").strip().splitlines() or [""])[-1][:160]


def _ros_log_says(before: Optional[list], after: Optional[list]) -> str:
    """What the device logged since `before` about a download, quoted as it wrote it — the
    lines on errors, packages and updates; never lanowl's own logins."""
    if before is None or after is None:
        return "its log could not be read"
    # the log only grows (its oldest lines dropped when full): the new lines follow the first
    # place `before`'s last lines are found, each stamped to the second
    tail, new = before[-3:], after
    for i in range(len(after) - len(tail) + 1):
        if tail and after[i:i + len(tail)] == tail:
            new = after[i + len(tail):]
            break
    said = [s for s in new if ROS_LOG_WHY.search(s)]
    return f"its log: {' | '.join(said[-3:])}" if said else "its log says nothing about it"
