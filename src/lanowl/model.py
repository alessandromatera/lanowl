"""Config + inventory loading and the device data model."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Device:
    ip: str
    name: str
    group: str = "misc"
    criticality: str = "low"
    checks: list = field(default_factory=list)   # list of {type, port?, community?}
    note: str = ""
    attrs: dict = field(default_factory=dict)     # role, mikrotik_rest, ...

    @property
    def is_critical(self) -> bool:
        return self.criticality == "critical"


@dataclass
class Inventory:
    devices: list = field(default_factory=list)
    groups: dict = field(default_factory=dict)    # group -> {majority_down_critical: bool}
    path: str = ""                                 # the file it was read from

    def __post_init__(self):
        self.by_ip = {d.ip: d for d in self.devices}
        self._names = {d.name.casefold() for d in self.devices}

    def rebind(self, device: Device, new_ip: str):
        """Point a device at a new address (DHCP drift) and refresh the IP index.
        Keeps the originally-configured address in attrs for reference."""
        old_ip = device.ip
        self.by_ip.pop(old_ip, None)
        device.attrs.setdefault("configured_ip", old_ip)
        device.ip = new_ip
        self.by_ip[new_ip] = device

    def add(self, device: Device):
        """A device watched at runtime (sites.py: picked from a site's DHCP list).
        The next sweep probes it — run_sweep reads `devices` every cycle."""
        if device.ip in self.by_ip:
            return
        self.devices.append(device)
        self.by_ip[device.ip] = device
        self._names.add(device.name.casefold())

    def rename(self, device: Device, name: str):
        """The owner's name for it (names.py). The inventory's name is kept in attrs, and
        both keep owning the device's history (`owns` matches a row recorded at another
        address by the name it was recorded under)."""
        device.attrs.setdefault("listed_name", device.name)
        device.name = name
        self._names.add(name.casefold())

    def remove(self, ip: str):
        d = self.by_ip.pop(ip, None)
        if d is not None:
            self.devices.remove(d)
            self._names.discard(d.name.casefold())

    def is_known(self, ip: str) -> bool:
        return ip in self.by_ip

    def owns(self, ip: str, name: str = "") -> bool:
        """Is a row of history about a device monitored NOW?

        By address — including the configured one of a device DHCP has since moved — or, for
        a row recorded at an address it held in between, by the name it was recorded under.
        A device taken out of the inventory owns nothing: its old outages are not the
        network's story any more, and would otherwise linger in the logbook and in the
        model's context for as long as history is kept."""
        if ip in self.by_ip or any(d.attrs.get("configured_ip") == ip for d in self.devices):
            return True
        return bool(name) and name.casefold() in self._names

    def get(self, ip: str) -> Optional[Device]:
        return self.by_ip.get(ip)

    def in_group(self, group: str) -> list:
        return [d for d in self.devices if d.group == group]


_RESERVED = {"ip", "name", "group", "criticality", "checks", "note"}


def load_inventory(path: str) -> Inventory:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return inventory_from(raw, path)


def inventory_from(raw: dict, path: str) -> Inventory:
    """The inventory from inventory.yaml's parsed data (a save checks a file before it is one)."""
    raw = raw if isinstance(raw, dict) else {}
    devices = []
    for d in raw.get("devices") or []:
        attrs = {k: v for k, v in d.items() if k not in _RESERVED}
        devices.append(Device(
            ip=str(d["ip"]),
            name=d.get("name", str(d["ip"])),
            group=d.get("group", "misc"),
            criticality=d.get("criticality", "low"),
            checks=d.get("checks", [{"type": "icmp"}]) or [{"type": "icmp"}],
            note=d.get("note", ""),
            attrs=attrs,
        ))
    return Inventory(devices=devices, groups=raw.get("groups", {}), path=os.path.abspath(path))


def _env_override(cfg: dict) -> dict:
    """What differs between deployments of the same config.yaml, so one file serves all of
    them instead of forked copies that drift. (Secrets are not here: access.py reads them,
    from secrets.yaml or the environment, when they are used.)"""
    # The model server: a GPU model often runs on another machine than the monitor (a Mac's
    # Metal is out of a container's reach, for one), so each deployment names the road to it.
    if os.environ.get("LANOWL_MODEL_URL"):
        if cfg.get("model") is None:
            cfg["model"] = {}
        if isinstance(cfg["model"], dict):       # anything else: --check says what is wrong
            cfg["model"]["url"] = os.environ["LANOWL_MODEL_URL"]
    # The machine lanowl runs on. More than a label: the host-log watcher recognises its OWN
    # ssh logins by this address, so a wrong value turns every poll into "somebody else
    # logged in", and hides a real stranger who comes from the right address.
    if os.environ.get("LANOWL_HOST_IP"):
        cfg.setdefault("observer", {})
        cfg["observer"]["host_ip"] = os.environ["LANOWL_HOST_IP"]
    # The dashboard's port: 80 where lanowl has an address of its own, something else where
    # it shares a host with other services.
    if os.environ.get("LANOWL_WEB_PORT"):
        cfg.setdefault("web", {})
        cfg["web"]["port"] = int(os.environ["LANOWL_WEB_PORT"])
    return cfg


def load_config(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    return config_from(cfg, path)


def config_from(cfg: dict, path: str) -> dict:
    """The config from config.yaml's parsed data, as a start reads it: the defaults that
    hang on where the file is, and the environment's overrides."""
    import copy
    cfg = copy.deepcopy(cfg) if isinstance(cfg, dict) else {}
    # the owner's own device kinds (kinds.py): a `profiles` folder beside config.yaml
    pr = cfg.get("profiles") if isinstance(cfg.get("profiles"), dict) else {}
    here = os.path.dirname(os.path.abspath(path))
    pr.setdefault("dir", os.path.join(here, "profiles"))
    cfg["profiles"] = pr
    # ...and every secret in secrets.yaml beside it (access.py)
    ac = cfg.get("access") if isinstance(cfg.get("access"), dict) else {}
    ac.setdefault("secrets_file", os.path.join(here, "secrets.yaml"))
    cfg["access"] = ac
    cfg["_path"] = os.path.abspath(path)          # where it was read from (lanowl's own backup)
    return _env_override(cfg)


# --- the model -------------------------------------------------------------------------
# Only Ollama for now; `provider` is there so a cloud API is one more value, not a new section.
PROVIDERS = ("ollama",)
DEFAULT_MODEL = "qwen3:30b"


def model_cfg(cfg: dict) -> dict:
    """config.yaml's `model:` section ({} when there is none)."""
    m = (cfg or {}).get("model")
    return m if isinstance(m, dict) else {}


def model_name(cfg: dict) -> str:
    return str(model_cfg(cfg).get("name") or DEFAULT_MODEL)


def model_report(cfg: dict) -> tuple:
    """(text, problems) for `lanowl --check`: which model lanowl will ask, and what in
    config.yaml it would not read — a section it ignores means the defaults, silently."""
    m = model_cfg(cfg)
    lines, bad = [], 0

    def row(mark: str, what: str, text: str):
        nonlocal bad
        bad += mark == "✗"
        lines.append(f"  {mark} {what:<15} {text}")

    provider = str(m.get("provider") or "ollama")
    url = str(m.get("url") or "http://127.0.0.1:11434")
    where = " (from LANOWL_MODEL_URL)" if os.environ.get("LANOWL_MODEL_URL") else ""
    lines.append(f"Model: {provider} · {model_name(cfg)} at {url}{where}")
    if "ollama" in (cfg or {}):
        row("✗", "config.yaml", "`ollama:` is not read any more: rename it `model:`, and its "
                                "`model:` key `name:`")
    if (cfg or {}).get("model") is not None and not isinstance(cfg.get("model"), dict):
        row("✗", "model", "should be a section (url, name, ...), not a value")
    if provider not in PROVIDERS:
        row("✗", "model.provider", f"{provider!r}: only {', '.join(PROVIDERS)} for now")
    if "model" in m:
        row("✗", "model.model", "is `model.name` now")
    return "\n".join(lines), bad


# --- where things are, from config: one definition each ------------------------------
MAIN_SITE = "home"


def main_lans(cfg: dict) -> list:
    """The main site's own networks: `nets` of the `sites.list` entry keyed "home", else
    `actions.checks.lan_subnets`, else the whole of 192.168.0.0/16."""
    import ipaddress
    site = next((s for s in ((cfg or {}).get("sites") or {}).get("list") or []
                 if str(s.get("key")) == MAIN_SITE), None)
    nets = (site or {}).get("nets") or (((cfg or {}).get("actions") or {}).get("checks") or {}).get(
        "lan_subnets") or ["192.168.0.0/16"]
    out = []
    for n in nets:
        try:
            out.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            pass
    return out


def on_main_lan(cfg: dict, ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in main_lans(cfg))


def router_host(cfg: dict) -> str:
    """The main router's address: `mikrotik.api.host`, else the host of
    `mikrotik.dhcp_source`. "" = no router configured."""
    from urllib.parse import urlparse
    mk = (cfg or {}).get("mikrotik") or {}
    return str((mk.get("api") or {}).get("host") or urlparse(str(mk.get("dhcp_source") or "")).hostname or "")


def link_names(cfg: dict) -> tuple:
    """(main, backup): what the owner calls the two internet links (`wan.path.main` /
    `wan.path.backup`), for every message that names one."""
    p = ((cfg or {}).get("wan") or {}).get("path") or {}
    return str(p.get("main") or "main link"), str(p.get("backup") or "backup link")


def wan_failover(cfg: dict) -> bool:
    """Is there a backup internet link to tell apart from the main one? Only when the owner
    configured how to see it (`wan.path.route_comment`, the main default route's comment on
    the router). Most networks have one line: then the internet is just ok or down."""
    return bool((((cfg or {}).get("wan") or {}).get("path") or {}).get("route_comment"))


def wan_links(cfg: dict) -> dict:
    """The internet links as the owner configured them (`wan.path`):
      failover      a backup link exists and can be told apart (wan_failover)
      main, backup  their names
      main_probe    an address the router sends ONLY over the main link ("" = none)
      backup_probe  ...ONLY over the backup link
      standby       the backup switches its uplink on only when the router fails over to it,
                    so its silence while the main link carries traffic is normal"""
    p = ((cfg or {}).get("wan") or {}).get("path") or {}
    main, backup = link_names(cfg)
    return {"failover": wan_failover(cfg), "main": main, "backup": backup,
            "main_probe": str(p.get("main_probe") or ""), "backup_probe": str(p.get("backup_probe") or ""),
            "standby": bool(p.get("backup_standby", False))}
