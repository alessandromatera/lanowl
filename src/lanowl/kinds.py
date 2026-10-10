"""Device kinds: what lanowl does with each device, and how — from the inventory alone.

Every device is described once, in inventory.yaml:

    - ip: 192.168.88.1
      name: Router
      kind: mikrotik                    # what it is
      credentials: routers              # its login, in secrets.yaml
      manage: [updates, upgrade, reboot, config, security, backup]

Watching a device (its `checks`) needs none of this. `manage` lists what lanowl does with it
besides, and each feature's options sit under the feature's own name:

    restart: {units: [mosquitto]}       # the services it may restart
    backup:  {paths: [etc, home]}       # what a backup by password takes
    reboot:  {risk: "the cameras record to it", hold_min: 10, also_hold: [192.168.88.21]}
    upgrade: {risk: "the internet is down while it installs", hold_min: 12, also_hold: [wan]}
    logs:    {public: true, about: "a VPS", trusted: ["10.8.0.0/24"]}

A kind is built in (`KINDS`), or a profile: a YAML file of commands, each read by a fixed
parser, never code (`Profile`). Profiles come from `profiles.dir` (default: a `profiles`
folder beside config.yaml) and from the ones lanowl ships (src/lanowl/profiles); one of yours
with the same kind replaces a shipped one.

The feature modules keep their own ways of reaching a device (their `via`); this module only
decides which, per device and feature, and fills in the lists those modules read (`apply`).
What a kind cannot do, or a device lacks the login for, is a warning at start and in
`lanowl --check` — never a crash, and never a change to how the device is watched. A change
of kind, `manage` or login type takes a restart; a changed password does not.
"""
from __future__ import annotations

import glob
import logging
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Optional

from .access import token as secret_token

log = logging.getLogger("lanowl.kinds")

FEATURES = {
    "logs": "reads its own log every hour; the owl tells what is not routine",
    "updates": "checks its updates every morning",
    "upgrade": "may propose installing them",
    "reboot": "may propose a reboot",
    "restart": "may propose restarting a listed service",
    "config": "tells what changed in its configuration",
    "security": "reviews what it exposes, every day",
    "backup": "backs it up, monthly and before updates",
}
# the config switch each feature runs under
SWITCH = {"logs": "devwatch", "updates": "updates", "upgrade": "actions", "reboot": "actions",
          "restart": "actions", "config": "configwatch", "security": "exposure",
          "backup": "backups"}

# kind -> feature -> how (the feature module's `via`); linux is decided by its login (_linux)
KINDS = {
    "mikrotik": {"logs": "routeros", "updates": "routeros", "upgrade": "routeros", "reboot": "routeros",
                 "config": "routeros", "security": "routeros", "backup": "routeros"},
    "openwrt": {"logs": "openwrt", "updates": "openwrt", "reboot": "ssh", "security": "openwrt"},
    "linux": {f: "linux" for f in FEATURES},
    "esxi": {"logs": "esxi", "updates": "esxi", "security": "esxi", "backup": "esxi"},
    "unifi": {"logs": "unifi", "updates": "unifi", "reboot": "ssh"},
    "homeassistant": {"updates": "homeassistant", "reboot": "homeassistant",
                      "backup": "homeassistant"},
    "reolink": {"reboot": "reolink"},
    "shelly": {"reboot": "shelly", "backup": "shellies"},
    "generic": {},
}
PASSWORD = {"routeros", "openwrt", "ssh", "esxi", "unifi", "reolink", "password", "sudo",
            "files"}                                    # ssh with a password, or an HTTP login
KEY = {"key", "ssh_key", "vps", "store"}                # lanowl's ssh key

# a profile's operations, and the feature each one gives
OPS = ("version", "updates", "uptime", "reboot", "config", "security", "backup")
FEATURE_OP = {"updates": "updates", "reboot": "reboot", "config": "config",
              "security": "security", "backup": "backup"}
PARSERS = ("text", "lines", "first_line", "seconds", "proc_uptime", "boottime")
DEFAULT_PARSE = {"version": "lines", "updates": "lines", "uptime": "proc_uptime"}
OP_KEYS = {"cmd", "parse", "sudo", "timeout_s", "ok_rc", "back_s", "file", "ignore"}
_KIND = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SHIPPED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")


# --- profiles ---------------------------------------------------------------------------------
@dataclass
class Profile:
    kind: str
    about: str = ""
    ops: dict = field(default_factory=dict)     # name -> {cmd, parse, sudo, timeout_s, ...}
    source: str = ""


def parse_profile(text: str, source: str = "") -> Profile:
    """A profile from its YAML; ValueError says what is wrong, in words."""
    import yaml
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise ValueError("a profile is a mapping with `kind` and `ops`")
    kind = str(raw.get("kind") or "")
    if not _KIND.match(kind):
        raise ValueError(f"kind {kind!r}: lowercase letters, digits, - and _")
    if kind in KINDS:
        raise ValueError(f"kind {kind!r} is built in; give the profile a name of its own")
    extra = set(raw) - {"kind", "about", "ops"}
    if extra:
        raise ValueError(f"unknown key(s) {', '.join(sorted(extra))}")
    ops = {}
    for name, spec in (raw.get("ops") or {}).items():
        if name not in OPS:
            raise ValueError(f"unknown operation {name!r}; one of: {', '.join(OPS)}")
        if isinstance(spec, str):
            spec = {"cmd": spec}
        if not isinstance(spec, dict) or not str(spec.get("cmd") or "").strip():
            raise ValueError(f"{name}: needs a `cmd`")
        bad = set(spec) - OP_KEYS
        if bad:
            raise ValueError(f"{name}: unknown key(s) {', '.join(sorted(bad))}")
        op = {"cmd": str(spec["cmd"]).strip(), "sudo": bool(spec.get("sudo", False)),
              "timeout_s": float(spec.get("timeout_s", 60)),
              "ok_rc": [int(x) for x in (spec.get("ok_rc") or [0])]}
        if not 1 <= op["timeout_s"] <= 3600:
            raise ValueError(f"{name}: timeout_s between 1 and 3600")
        p = spec.get("parse", DEFAULT_PARSE.get(name, "text"))
        if isinstance(p, dict):
            if set(p) != {"regex"}:
                raise ValueError(f"{name}: parse is a parser's name or {{regex: ...}}")
            try:
                re.compile(str(p["regex"]))
            except re.error as e:
                raise ValueError(f"{name}: bad regex: {e}")
            p = {"regex": str(p["regex"])}
        elif p not in PARSERS:
            raise ValueError(f"{name}: parse {p!r}; one of: {', '.join(PARSERS)}, {{regex: ...}}")
        op["parse"] = p
        if name == "reboot":
            op["back_s"] = float(spec.get("back_s", 300))
        if name == "backup":
            f = str(spec.get("file") or f"{kind}-backup.txt")
            if not _FILE.match(f):
                raise ValueError(f"backup: file {f!r} is a plain file name")
            op["file"] = f
        if name == "config":
            try:
                op["ignore"] = [re.compile(str(x)) for x in (spec.get("ignore") or [])]
            except re.error as e:
                raise ValueError(f"config: bad ignore regex: {e}")
        ops[name] = op
    if not ops:
        raise ValueError("no operations: a profile needs at least one under `ops`")
    return Profile(kind, str(raw.get("about") or ""), ops, source)


def load_profiles(dirs: list) -> tuple:
    """({kind: Profile}, [problem]) from every *.yaml in `dirs`, the later ones winning."""
    out, problems = {}, []
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.yaml")) + glob.glob(os.path.join(d, "*.yml"))):
            try:
                with open(path, encoding="utf-8") as f:
                    pr = parse_profile(f.read(), path)
                out[pr.kind] = pr
            except Exception as e:
                problems.append(f"profile {os.path.basename(path)}: {e}")
    return out, problems


def parse_output(op: dict, text: str):
    """A command's output read by the operation's parser. ValueError when it does not read."""
    text = text or ""
    if op.get("ignore"):
        text = "\n".join(ln for ln in text.splitlines()
                         if not any(rx.search(ln) for rx in op["ignore"]))
    p = op.get("parse", "text")
    if isinstance(p, dict):
        out = []
        for m in re.finditer(p["regex"], text, re.M):
            gd = {k: v.strip() for k, v in m.groupdict().items() if v is not None}
            out.append(gd or {"value": (m.group(1) if m.groups() else m.group(0)).strip()})
        return out
    if p == "text":
        return text.strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if p == "lines":
        return lines
    if p == "first_line":
        return lines[0] if lines else ""
    try:
        if p in ("seconds", "proc_uptime"):
            return float(text.split()[0])
        if p == "boottime":                 # `{ sec = 1696300000, usec = 0 } …`, or an epoch
            m = re.search(r"sec\s*=\s*(\d+)", text) or re.match(r"\s*(\d{9,})", text)
            return max(0.0, time.time() - int(m.group(1)))
    except (IndexError, ValueError, AttributeError):
        raise ValueError(f"not a number of seconds: {text.strip()[:60]!r}")
    raise ValueError(f"unknown parser {p!r}")


def version_fields(v) -> dict:
    """{"os", "release"} from a `version` operation's result."""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        d = v[0]
        return {"os": d.get("os") or d.get("value") or "", "release": d.get("release") or ""}
    if isinstance(v, list):
        return {"os": v[0] if v else "", "release": v[1] if len(v) > 1 else ""}
    return {"os": str(v).splitlines()[0] if str(v).strip() else "", "release": ""}


def update_items(v) -> list:
    """[{"pkg", "version"?}] from an `updates` operation's result."""
    if isinstance(v, str):
        v = [ln.strip() for ln in v.splitlines() if ln.strip()]
    out = []
    for x in v or []:
        if isinstance(x, dict):
            pkg = x.get("pkg") or x.get("value") or next(iter(x.values()), "")
            out.append({"pkg": str(pkg), **({"version": x["version"]} if x.get("version") else {})})
        else:
            out.append({"pkg": str(x)})
    return out


# --- the plan: per device, what and how ---------------------------------------------------------
@dataclass
class DevicePlan:
    ip: str
    name: str
    kind: str = ""
    login: str = ""                          # "", "password", "key", "key+password"
    features: dict = field(default_factory=dict)   # feature -> via
    problems: list = field(default_factory=list)
    off: dict = field(default_factory=dict)        # feature -> the config switch that is off


def _opts(dev, f: str) -> dict:
    v = dev.attrs.get(f)
    return dict(v) if isinstance(v, dict) else {}


def _login_words(lg) -> str:
    if lg is None:
        return ""
    return "key+password" if lg.key and lg.password else "key" if lg.key else "password"


def _linux(f: str, lg, ip: str, store: str) -> str:
    key = lg is not None and bool(lg.key)
    if f == "logs":            # by the key, hostlog.py also reads its auth log every two minutes
        return "key" if key else "sudo"
    if f in ("updates", "upgrade", "restart"):
        return "key" if key else "password"
    if f == "reboot":
        return "ssh_key" if key else "ssh"
    if f in ("config", "security"):
        return "key" if key else "sudo"
    if f == "backup":
        return "store" if ip == store else "vps" if key else "files"
    return ""


def _how(f: str, kind: str, dev, lg, prof: Optional[Profile], ctx: dict) -> tuple:
    """(via, "") or ("", why not)."""
    o = _opts(dev, f)
    if f == "reboot" and o.get("ha_button"):
        return (("ha_button", "") if ctx["ha"] else
                ("", "a reboot by a Home Assistant button needs access.ha_url and its token"))
    if prof is not None:
        op = FEATURE_OP.get(f)
        if not op or op not in prof.ops:
            return "", f"the {kind} profile has no `{op or f}` operation"
        if lg is None:
            return "", f"{f} needs a login (credentials:) in secrets.yaml"
        return "profile", ""
    table = KINDS[kind]
    if f not in table:
        return "", f"kind {kind} cannot do {f} (it can: {', '.join(table) or 'only be watched'})"
    how = _linux(f, lg, dev.ip, ctx["store"]) if kind == "linux" else table[f]
    if how == "homeassistant" and f != "backup" and not ctx["ha"]:
        return "", f"{f} on Home Assistant needs access.ha_url and its token"
    if (how in PASSWORD or (how == "homeassistant" and f == "backup")) and (lg is None or not lg.password):
        return "", f"{f} needs a login with a password (credentials:) in secrets.yaml"
    if how in KEY and (lg is None or not lg.key):
        return "", (f"{f} needs a login with lanowl's ssh key (`key: true`) in secrets.yaml"
                    + (" — the backup store is written over it" if how == "store" else ""))
    if f == "restart" and not [u for u in (o.get("units") or []) if str(u).strip()]:
        return "", "restart needs the services it may restart: `restart: {units: [...]}`"
    if how == "files" and not o.get("paths"):
        return "", "a backup over a password login needs what to take: `backup: {paths: [...]}`"
    return how, ""


def derive(cfg: dict, inv, access, profiles: dict) -> list:
    """[DevicePlan] for every device with a `kind` or `manage`."""
    ctx = {"store": str(((cfg.get("backups") or {}).get("store") or {}).get("host") or ""),
           "ha": bool((cfg.get("access") or {}).get("ha_url") and secret_token(cfg, "homeassistant"))}
    plans = []
    for d in inv.devices:
        kind = str(d.attrs.get("kind") or "").strip().lower()
        manage = d.attrs.get("manage") or []
        manage = [str(m).strip().lower() for m in ([manage] if isinstance(manage, str) else manage)]
        if not kind and not manage:
            continue
        lg = access.login(d.ip) if access is not None else None
        pl = DevicePlan(d.ip, d.name, kind, _login_words(lg))
        plans.append(pl)
        prof = profiles.get(kind)
        if not kind:
            pl.problems.append("`manage` needs a `kind`")
            continue
        if kind not in KINDS and prof is None:
            pl.problems.append(f"unknown kind {kind!r}: built in are {', '.join(KINDS)}, or add "
                               f"profiles/{kind}.yaml")
            continue
        for f in dict.fromkeys(manage):
            if f not in FEATURES:
                pl.problems.append(f"unknown feature {f!r}: one of {', '.join(FEATURES)}")
                continue
            how, why = _how(f, kind, d, lg, prof, ctx)
            if how:
                pl.features[f] = how
            else:
                pl.problems.append(why)
        for f in pl.features:
            if not (cfg.get(SWITCH[f]) or {}).get("enabled", False):
                pl.off[f] = f"{SWITCH[f]}.enabled"
    return plans


# --- what the feature modules read --------------------------------------------------------------
# config.yaml's old per-feature lists: replaced by the inventory, said so once
OLD = (("updates", "hosts"), ("exposure", "hosts"), ("configwatch", "machines"),
       ("backups", "machines"), ("hostlog", "hosts"), ("actions.catalog.reboot", "devices"),
       ("actions.catalog.apt_upgrade", "hosts"), ("actions.catalog.routeros_upgrade", "hosts"),
       ("actions.catalog.restart_service", "host"), ("actions.catalog.restart_service", "units"),
       ("actions.catalog.vps_restart", "host"))


def _node(cfg: dict, path: str) -> dict:
    node = cfg
    for k in path.split("."):
        if not isinstance(node.get(k), dict):
            node[k] = {}
        node = node[k]
    return node


def apply(cfg: dict, inv, access, plans: list, profiles: dict) -> list:
    """Fill in each feature's list from the plans. Returns the warnings for config.yaml lists
    that the inventory now replaces (they are ignored)."""
    warns = []
    for path, key in OLD:
        node = cfg
        for k in path.split("."):
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, dict) and node.get(key):
            warns.append(f"config.yaml's {path}.{key} is ignored: what lanowl does with a device "
                         "is set in the inventory now (kind, credentials, manage)")
    devs = {d.ip: d for d in inv.devices}
    by = {f: [] for f in FEATURES}
    for pl in plans:
        for f, how in pl.features.items():
            by[f].append((pl, how, devs[pl.ip]))

    def row(pl, how, **kw):
        return {"ip": pl.ip, "name": pl.name, "via": how, **kw}

    _node(cfg, "updates")["hosts"] = [row(pl, h) for pl, h, _ in by["updates"]]
    _node(cfg, "exposure")["hosts"] = [row(pl, h) for pl, h, _ in by["security"]]
    _node(cfg, "configwatch")["machines"] = [row(pl, h) for pl, h, _ in by["config"]]

    # every device whose login is lanowl's key gets the key's shared connection; its log is
    # read only with `logs`
    hosts = []
    for d in inv.devices:
        lg = access.login(d.ip) if access is not None else None
        if lg is None or not lg.key:
            continue
        pl = next((p for p in plans if p.ip == d.ip), None)
        watch = pl is not None and "logs" in pl.features
        o = _opts(d, "logs")
        hosts.append({"name": d.name, "ip": d.ip, "user": lg.user or "root",
                      "identity": "" if lg.key == "default" else lg.key, "watch": watch,
                      **{k: o[k] for k in ("public", "about", "trusted", "burst",
                                           "max_established", "tunnel_from", "tunnel_names")
                         if k in o}})
    _node(cfg, "hostlog")["hosts"] = hosts

    machines, shellies = [], []
    for pl, how, d in by["backup"]:
        if how == "shellies":
            shellies.append(pl.ip)
            continue
        o = _opts(d, "backup")
        machines.append(row(pl, how, **{k: o[k] for k in ("paths", "snapshot", "sudo", "name")
                                        if k in o}))
    if shellies:
        machines.append({"ip": "shellies", "name": "Shellies", "via": "shellies",
                         "devices": shellies})
    me = (cfg.get("backups") or {}).get("self")
    if me:
        machines.append({"ip": "lanowl", "name": "lanowl", "via": "lanowl",
                         "daily": int(me.get("daily", 7)) if isinstance(me, dict) else 7})
    _node(cfg, "backups")["machines"] = machines

    reboot, shelly = {}, []
    for pl, how, d in by["reboot"]:
        if how == "shelly":
            shelly.append(pl.ip)
            continue
        o = _opts(d, "reboot")
        v = {"via": how, **{k: o[k] for k in ("risk", "hold_min", "also_hold") if k in o}}
        if how == "ha_button":
            v["entity"] = str(o["ha_button"])
        if how == "profile":
            v["back_s"] = profiles[pl.kind].ops["reboot"]["back_s"]
        reboot[pl.ip] = v
    _node(cfg, "actions.catalog.reboot")["devices"] = reboot
    _node(cfg, "actions.catalog.shelly_reboot")["devices"] = shelly

    apt, ros = {}, {}
    for pl, how, d in by["upgrade"]:
        # what it puts at risk; for a router, also how long its alerts and those of what goes
        # dark with it ("wan", the tunnels) are held while it installs
        o = {k: v for k, v in _opts(d, "upgrade").items() if k in ("risk", "hold_min", "also_hold")}
        if how == "routeros":
            ros[pl.ip] = o
        else:
            apt[pl.ip] = {"via": how, **({"risk": o["risk"]} if "risk" in o else {})}
    _node(cfg, "actions.catalog.apt_upgrade")["hosts"] = apt
    _node(cfg, "actions.catalog.routeros_upgrade")["hosts"] = ros

    rs = _node(cfg, "actions.catalog.restart_service")
    rs.pop("host", None)
    rs.pop("units", None)
    rs["hosts"] = {pl.ip: {"via": how, "units": [str(u) for u in _opts(d, "restart")["units"]]}
                   for pl, how, d in by["restart"]}
    (cfg.get("actions") or {}).get("catalog", {}).pop("vps_restart", None)
    return warns


# --- running a profile's operation -----------------------------------------------------------
class Kinds:
    """The profiles and the plans, for the feature modules at run time (`auditor.kinds`)."""

    def __init__(self, profiles: Optional[dict] = None, plans: Optional[list] = None,
                 problems: Optional[list] = None):
        self.profiles = profiles or {}
        self.plans = plans or []
        self.problems = problems or []           # the profiles' own, and config.yaml's
        self._by_ip = {p.ip: p for p in self.plans}

    @classmethod
    def load(cls, cfg: dict, inv, access) -> "Kinds":
        """Read the profiles, plan every device, fill in the feature lists, log what is wrong."""
        mine = str((cfg.get("profiles") or {}).get("dir") or "")
        profiles, problems = load_profiles([SHIPPED] + ([mine] if mine else []))
        plans = derive(cfg, inv, access, profiles)
        problems += apply(cfg, inv, access, plans, profiles)
        k = cls(profiles, plans, problems)
        for w in problems:
            log.warning("kinds: %s", w)
        for pl in plans:
            for w in pl.problems:
                log.warning("kinds: %s (%s): %s", pl.name, pl.ip, w)
        log.info("kinds: %d device(s) managed, %d profile(s): %s", len(plans), len(profiles),
                 ", ".join(sorted(profiles)) or "none")
        return k

    def plan(self, ip: str) -> Optional[DevicePlan]:
        return self._by_ip.get(ip)

    def profile_of(self, ip: str) -> Optional[Profile]:
        pl = self._by_ip.get(ip)
        return self.profiles.get(pl.kind) if pl is not None else None

    async def _ssh(self, a, ip: str, cmd: str, root: bool, timeout_s: float) -> tuple:
        if a.access.by_key(ip):
            return await a.actions._ssh_run(ip, cmd, timeout_s, root=root)
        lg = a.access.login(ip)
        if root and lg is not None and lg.user != "root":
            return await a.access.ssh(ip, "sudo -S -p '' sh -c " + shlex.quote(cmd),
                                      sudo_pw=True, timeout_s=timeout_s)
        return await a.access.ssh(ip, cmd, timeout_s=timeout_s)

    async def run(self, a, ip: str, op: str):
        """(True, parsed result) or (False, why) of one of the device's profile operations."""
        prof = self.profile_of(ip)
        if prof is None or op not in prof.ops:
            return False, f"its kind has no {op} operation"
        o = prof.ops[op]
        rc, out, err = await self._ssh(a, ip, o["cmd"], o["sudo"], o["timeout_s"])
        if rc is None or rc not in o["ok_rc"]:
            why = ((err or "").strip().splitlines() or [""])[-1][:160]
            return False, why or ("no answer" if rc is None else f"it ended with rc {rc}")
        try:
            return True, parse_output(o, out)
        except ValueError as e:
            return False, f"its output did not read: {e}"

    async def send_reboot(self, a, ip: str) -> tuple:
        """(sent, why): the profile's reboot, detached so the answer comes back first."""
        prof = self.profile_of(ip)
        o = prof.ops["reboot"]
        cmd = f"( sleep 2; {o['cmd']} ) </dev/null >/dev/null 2>&1 & echo REBOOTING"
        rc, out, err = await self._ssh(a, ip, cmd, o["sudo"], 20)
        if "REBOOTING" not in (out or ""):
            return False, ("the reboot command did not run: "
                           + (((err or "").strip().splitlines() or [f"rc {rc}"])[-1][:160]))
        return True, ""

    def stream_argv(self, a, ip: str, op: str) -> Optional[tuple]:
        """(argv, env, stdin, file name, timeout) of an operation NOT run yet, whose output is
        streamed somewhere (a backup onto the store). None = no way in."""
        prof = self.profile_of(ip)
        o = prof.ops[op]
        cmd, stdin = o["cmd"], None
        lg = a.access.login(ip)
        if lg is None:
            return None
        if a.access.by_key(ip):
            hl = a.hostlog
            h = next((x for x in hl.hosts if x.ip == ip), None)
            if h is None:
                return None
            if o["sudo"] and h.user != "root":
                if lg.password:
                    cmd, stdin = "sudo -S -p '' sh -c " + shlex.quote(cmd), (lg.password + "\n").encode()
                else:
                    cmd = "sudo -n sh -c " + shlex.quote(cmd)
            return hl._ssh_argv(h, cmd), None, stdin, o.get("file") or f"{prof.kind}.out", o["timeout_s"]
        if o["sudo"] and lg.user != "root":
            cmd, stdin = "sudo -S -p '' sh -c " + shlex.quote(cmd), (lg.password + "\n").encode()
        got = a.access.command(ip, cmd)
        if got is None:
            return None
        return got[0], got[1], stdin, o.get("file") or f"{prof.kind}.out", o["timeout_s"]


# --- `lanowl --check` ------------------------------------------------------------------------
def report(k: Kinds, inv) -> str:
    """What lanowl will do with each device, and why not — for the owner, in words."""
    lines = []
    n_prob = sum(len(p.problems) for p in k.plans) + len(k.problems)
    lines.append(f"{len(inv.devices)} device(s) watched, {len(k.plans)} managed, "
                 f"{n_prob} problem(s). Profiles: {', '.join(sorted(k.profiles)) or 'none'}. "
                 "✓ on · ○ switched off in config.yaml · ✗ cannot")
    for w in k.problems:
        lines.append(f"  ! {w}")
    for pl in k.plans:
        login = f"login: {pl.login}" if pl.login else "no login"
        lines.append("")
        lines.append(f"{pl.name} ({pl.ip}) · {pl.kind or '?'} · {login}")
        for f in pl.features:
            if f in pl.off:
                lines.append(f"  ○ {f:<9} {FEATURES[f]} — off: {pl.off[f]} in config.yaml")
            else:
                lines.append(f"  ✓ {f:<9} {FEATURES[f]}")
        for w in pl.problems:
            lines.append(f"  ✗ {w}")
    return "\n".join(lines)
