"""The deterministic sweep: probe every inventory device + WAN, build a snapshot.

This is the source of truth for up/down. It never calls the LLM and never writes
to a device. Overall device 'up' = ICMP reachable OR any service check answered
(some devices block ICMP but answer on a port)."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from . import probes, suncalc
from .model import Device, Inventory


@dataclass
class CheckResult:
    type: str
    ok: bool
    port: Optional[int] = None
    detail: str = ""
    latency_ms: Optional[float] = None
    data: dict = field(default_factory=dict)
    name: Optional[str] = None

    def label(self) -> str:
        return self.name or (f"{self.type}/{self.port}" if self.port else self.type)


@dataclass
class DeviceStatus:
    ip: str
    name: str
    group: str
    criticality: str
    up: bool
    reachable: bool                      # ICMP specifically
    latency_ms: Optional[float]
    checks: list = field(default_factory=list)   # list[CheckResult]
    attrs: dict = field(default_factory=dict)
    expected_down: bool = False          # 'down right now is by design' (e.g. PV gear at night)
    paused: bool = False                 # the owner switched it off on purpose (pause.py)
    held: bool = False                   # rebooting on the owner's say-so (reboot.py)

    @property
    def excused(self) -> bool:
        """Its silence is no news: asleep on schedule, or paused by the owner."""
        return self.expected_down or self.paused

    def failed_services(self) -> list:
        return [c.label() for c in self.checks if not c.ok]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "name": self.name, "group": self.group,
            "criticality": self.criticality, "up": self.up, "reachable": self.reachable,
            "expected_down": self.expected_down, "paused": self.paused, "held": self.held,
            "latency_ms": round(self.latency_ms, 1) if self.latency_ms else None,
            "checks": [
                {"type": c.type, "port": c.port, "ok": c.ok, "detail": c.detail,
                 "name": c.label(), "value": c.data.get("value")}
                for c in self.checks
            ],
        }


# The model server's key in the StatusTracker, beside main.WAN_KEY: debounced like a device,
# but not one — see report.build_report.
OLLAMA_KEY = "__ollama__"


@dataclass
class Snapshot:
    ts: float
    devices: list = field(default_factory=list)   # list[DeviceStatus]
    wan: dict = field(default_factory=dict)        # target -> ok
    wan_ok: bool = True
    wan_path: Optional[dict] = None                # {link, on_backup, detail} from route state
    ollama: Optional[CheckResult] = None           # the model server; None when the LLM is off
    router_api: Optional[dict] = None              # routeros.Router.status(); None = not configured

    def by_ip(self, ip: str) -> Optional[DeviceStatus]:
        for d in self.devices:
            if d.ip == ip:
                return d
        return None

    def to_dict(self) -> dict:
        return {
            "ts": self.ts, "wan_ok": self.wan_ok, "wan": self.wan,
            "wan_path": self.wan_path,
            "devices": [d.to_dict() for d in self.devices],
        }

    def anomalies(self) -> list:
        """Only the interesting stuff (down or degraded) — what the LLM should see."""
        out = []
        for d in self.devices:
            if d.excused:
                continue   # asleep on schedule or paused by the owner: not an anomaly
            if not d.up or d.failed_services():
                out.append({
                    "ip": d.ip, "name": d.name, "group": d.group,
                    "criticality": d.criticality, "up": d.up,
                    "failed": d.failed_services(),
                })
        return out


async def _run_check(dev: Device, check: dict, cfg: dict, sem: asyncio.Semaphore,
                     lease_index: Optional[dict] = None,
                     iface_index: Optional[dict] = None) -> CheckResult:
    p = cfg.get("probes", {})
    ctype = check.get("type")
    port = check.get("port")

    # 'link' = the router port the device hangs off is up. For a host we cannot probe
    # directly this is the fastest honest signal: the port drops within seconds of the
    # device losing power or its cable, whereas a DHCP lease stays 'bound' for the whole
    # lease time (hours) after the device is gone.
    if ctype == "link":
        iname = check.get("iface") or check.get("interface")
        if iface_index is None:
            # interfaces not fetched yet (first cycle) -> don't claim a failure
            return CheckResult("link", True, None, "link: pending", name=check.get("name"))
        if not iname:
            return CheckResult("link", False, None, "link: no iface configured", name=check.get("name"))
        i = iface_index.get(iname)
        if i is None:
            return CheckResult("link", False, None, f"link: interface '{iname}' not found",
                               name=check.get("name"))
        disabled = i.get("disabled") == "true"
        running = i.get("running") == "true"
        ok = running and not disabled
        if ok:
            detail = f"link up ({iname})"
        elif disabled:
            detail = f"link administratively disabled ({iname})"
        else:
            since = i.get("last-link-down-time")
            detail = f"link down ({iname})" + (f" since {since}" if since else "")
        return CheckResult("link", ok, None, detail,
                           data={"iface": iname, "running": running, "disabled": disabled,
                                 "last_link_down": i.get("last-link-down-time")},
                           name=check.get("name"))

    # 'lease' = indirect liveness for hosts we cannot reach directly (other subnets):
    # the device counts as up while it holds a bound DHCP lease on the router.
    # NOTE: a lease stays bound until it expires, so this LAGS a real outage by up to the
    # full lease time. Prefer a `link` check when the device sits on its own router port.
    if ctype == "lease":
        mac = (dev.attrs.get("mac") or "").upper()
        if lease_index is None:
            # leases not fetched yet (first cycle) -> don't claim a failure
            return CheckResult("lease", True, None, "lease: pending", name=check.get("name"))
        if not mac:
            return CheckResult("lease", False, None, "lease: no mac configured", name=check.get("name"))
        ip = lease_index.get(mac)
        ok = ip is not None
        detail = f"lease active ({ip})" if ok else "no active DHCP lease"
        return CheckResult("lease", ok, None, detail, data={"leased_ip": ip},
                           name=check.get("name"))

    # A check may carry its own `timeout_ms` (and, for icmp, `count`), overriding the global
    # `probes` values. One timeout for every device is a compromise between two failure
    # modes: raise it for everyone and a genuinely dead device takes longer to notice; leave
    # it and the weak-signal gear cries wolf. A device at the edge of Wi-Fi coverage is the
    # usual case: normally 3 ms, but ~30% packet loss with spikes past 2.5 s, which reads as
    # an outage several times an hour. Tune its probe; do not drop it from monitoring.
    def _t(default_key: str, fallback: int) -> int:
        return int(check.get("timeout_ms", p.get(default_key, fallback)))

    # 'arp' = the router ARP-pings the device on the LAN bridge: it is on the wire. For gear
    # that ignores ICMP and listens on no port (some thermostats answer nothing but ARP).
    # The router asks, not lanowl: a container behind NAT has no layer 2. Needs the
    # `test` policy on the router user. A router that cannot answer says nothing about the
    # device, so, like `link` and `lease`, that is not claimed as a failure.
    if ctype == "arp":
        from . import routeros
        from .checks import _ros_ms
        rows = await routeros.shared(cfg).request(
            "POST", "ping", {"address": dev.ip, "arp-ping": "yes",
                             "interface": check.get("iface") or "bridge-lan",
                             "count": str(int(check.get("count", 3))), "interval": "0.3"},
            _t("arp_timeout_ms", 8000) / 1000)
        if isinstance(rows, dict) or not rows:
            why = rows.get("error") if isinstance(rows, dict) else "no answer"
            return CheckResult("arp", True, None, f"arp: not checked — router: {why}",
                               name=check.get("name"))
        last = rows[-1]
        ok = int(last.get("received") or 0) > 0
        return CheckResult("arp", ok, None,
                           f"ARP reply from {last.get('host')}" if ok else "no ARP reply",
                           latency_ms=_ros_ms(last.get("avg-rtt")) if ok else None,
                           name=check.get("name"))

    async with sem:
        if ctype == "icmp":
            # ping() is alive-if-ANY-reply, so a higher count buys tolerance for loss the
            # same way a higher timeout buys tolerance for latency.
            r = await probes.ping(dev.ip, _t("icmp_timeout_ms", 1000),
                                  int(check.get("count", 2)))
        elif ctype == "tcp":
            r = await probes.tcp_check(dev.ip, int(port), _t("tcp_timeout_ms", 1500))
        elif ctype == "http":
            r = await probes.http_check(dev.ip, int(port or 80), "/", _t("http_timeout_ms", 4000))
        elif ctype == "snmp":
            community = check.get("community", p.get("snmp_community", "public"))
            r = await probes.snmp_get(dev.ip, probes.OID_SYSUPTIME, community, p.get("snmp_timeout_s", 2))
        else:
            r = probes.ProbeResult(False, None, f"unknown-check:{ctype}")
    return CheckResult(type=ctype, ok=r.ok, port=port, detail=r.detail,
                       latency_ms=r.latency_ms, data=r.data, name=check.get("name"))


async def _sweep_device(dev: Device, cfg: dict, sem: asyncio.Semaphore,
                        lease_index: Optional[dict] = None,
                        asleep_modes: frozenset = frozenset(),
                        iface_index: Optional[dict] = None) -> DeviceStatus:
    results = await asyncio.gather(
        *[_run_check(dev, c, cfg, sem, lease_index, iface_index) for c in dev.checks])
    icmp = next((c for c in results if c.type == "icmp"), None)
    reachable = bool(icmp and icmp.ok)
    any_ok = any(c.ok for c in results)
    latency = icmp.latency_ms if icmp and icmp.ok else next(
        (c.latency_ms for c in results if c.ok and c.latency_ms is not None), None)
    return DeviceStatus(
        ip=dev.ip, name=dev.name, group=dev.group, criticality=dev.criticality,
        up=reachable or any_ok, reachable=reachable, latency_ms=latency,
        checks=list(results), attrs=dev.attrs,
        expected_down=dev.attrs.get("expect_offline") in asleep_modes,
    )


# --- scheduled-offline devices ("asleep", not down) --------------------------
# Two kinds, mirror images of each other, each with its own generous margin:
#   sun -> offline at NIGHT   (PV-powered gear: a solar inverter and its meter)
#   day -> offline in DAYLIGHT (dusk-to-dawn gear: a twilight-switched light)
OFFLINE_MODES = ("sun", "day")


def _site(cfg: dict):
    site = cfg.get("site", {})
    lat, lon = site.get("lat"), site.get("lon")
    return (site, None if lat is None else float(lat), None if lon is None else float(lon))


def _margin_min(site: dict, mode: str) -> float:
    return float(site.get("sun_margin_min", 60) if mode == "sun" else site.get("day_margin_min", 45))


def expected_offline_at(cfg: dict, mode: str, ts: float) -> bool:
    """Is `mode` gear inside its scheduled-offline window at `ts`? False when site is unset."""
    site, lat, lon = _site(cfg)
    if lat is None or lon is None or mode not in OFFLINE_MODES:
        return False
    m = _margin_min(site, mode)
    return (suncalc.is_pv_night(ts, lat, lon, m) if mode == "sun"
            else suncalc.is_solar_day(ts, lat, lon, m))


def asleep_modes_at(cfg: dict, ts: float) -> frozenset:
    """The modes whose devices are expected offline right now."""
    return frozenset(m for m in OFFLINE_MODES if expected_offline_at(cfg, mode=m, ts=ts))


def pv_night_at(cfg: dict, ts: float) -> bool:
    return expected_offline_at(cfg, "sun", ts)


def wake_ts(cfg: dict, mode: str, ts: float) -> Optional[float]:
    """Epoch on ts's local date when `mode` gear stops being expected offline: sunrise+margin
    for PV gear, sunset+margin for dusk-to-dawn gear. None when site is unset (or polar)."""
    site, lat, lon = _site(cfg)
    if lat is None or lon is None or mode not in OFFLINE_MODES:
        return None
    sunrise, sunset = suncalc.sun_times(ts, lat, lon)
    edge = sunrise if mode == "sun" else sunset
    return None if edge is None else edge + _margin_min(site, mode) * 60.0


def offline_mode_ips(inv: Inventory) -> dict:
    """{ip: mode} for every device with a scheduled-offline window."""
    return {d.ip: d.attrs["expect_offline"] for d in inv.devices
            if d.attrs.get("expect_offline") in OFFLINE_MODES}


def grace_s(cfg: dict) -> float:
    site = cfg.get("site", {})
    return float(site.get("offline_grace_min", site.get("sun_grace_min", 30))) * 60.0


def offline_by_design(cfg: dict, mode: str, ts: float) -> bool:
    """Is something that happened at `ts` explained by `mode`'s daily schedule?

    True inside the offline window and through the grace tail just after it ends — which is
    where the wake itself lands: a device comes back when its window is over, by definition.
    Same rule the live state uses, applied to history."""
    if expected_offline_at(cfg, mode, ts):
        return True
    w = wake_ts(cfg, mode, ts)
    return w is not None and 0 <= ts - w <= grace_s(cfg)


def apply_offline_grace(cfg: dict, snap: "Snapshot", tracker) -> None:
    """Keep scheduled-offline gear 'asleep' for `site.offline_grace_min` after it drops off,
    and for the same span after its wake boundary.

    The sun windows have hard edges; the real world does not. The inverter dozes off under a
    thick cloud and boots again minutes later, on a grey morning it wakes some time *after*
    sunrise+margin, and a twilight switch trips on falling light rather than on the almanac.
    All of that is gear sleeping, not the network failing, so none of it should become an
    issue. Whatever is still dark once the grace expires IS reported: a genuinely dead
    inverter in daylight still alerts, just `offline_grace_min` later."""
    grace = grace_s(cfg)
    if grace <= 0:
        return
    wakes = {m: wake_ts(cfg, m, snap.ts) for m in OFFLINE_MODES}
    for d in snap.devices:
        mode = d.attrs.get("expect_offline")
        if d.up or d.expected_down or mode not in OFFLINE_MODES:
            continue
        # anchor on whichever happened last: it dropped off, or its offline window ended
        anchor = tracker.since(d.ip)
        w = wakes.get(mode)
        if w is not None and w <= snap.ts:
            anchor = max(anchor, w)
        if anchor and (snap.ts - anchor) < grace:
            d.expected_down = True


async def run_sweep(cfg: dict, inv: Inventory, lease_index: Optional[dict] = None,
                    iface_index: Optional[dict] = None) -> Snapshot:
    sem = asyncio.Semaphore(cfg.get("probes", {}).get("concurrency", 32))
    asleep = asleep_modes_at(cfg, time.time())
    dev_tasks = [_sweep_device(d, cfg, sem, lease_index, asleep, iface_index)
                 for d in inv.devices]

    wan_cfg = cfg.get("wan", {})
    wan_targets = wan_cfg.get("targets", [])
    p = cfg.get("probes", {})

    async def _wan(t):
        async with sem:
            r = await probes.ping(t, p.get("icmp_timeout_ms", 1000))
        return t, r.ok

    wan_tasks = [_wan(t) for t in wan_targets]
    dev_results = await asyncio.gather(*dev_tasks)
    wan_results = await asyncio.gather(*wan_tasks) if wan_tasks else []

    wan = {t: ok for t, ok in wan_results}
    wan_ok = any(wan.values()) if wan else True
    return Snapshot(ts=time.time(), devices=list(dev_results), wan=wan, wan_ok=wan_ok)
