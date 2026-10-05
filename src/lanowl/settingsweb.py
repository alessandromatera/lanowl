"""The dashboard's Settings, devices and first-run setup: the routes (settings.py does the work).

Every route here is behind the login (web.py), except `/api/setup/claim`: the first page of a
new install, which takes the setup code and the password. A route that writes a file asks for
the password again when this browser has not typed it in the last ten minutes (login.py
`recent`); a 403 with {"auth": "needed"} tells the page to ask. Never a 401 — that is the page's
"logged out, reload".

  GET  /api/settings              the forms with their values and sources, the files, the
                                  history, what waits for a restart, the secrets by name
  POST /api/settings/plan         {file, ops} -> the diff, the changes, --check's new ✗
  POST /api/settings/save         {file, ops, base, password?}
  POST /api/settings/restore      {id, preview | base, password?}
  POST /api/settings/password     {new, password?} -> a new dashboard password (everyone out)
  POST /api/restart               Restart to apply
  GET  /api/settings/devices      inventory.yaml's devices, the kinds and what each can do,
                                  the logins by name, the devices watched in lanowl's state
  POST /api/settings/device       {ip | null, device | null, preview | base, password?, how}
  POST /api/settings/migrate      the devices watched in lanowl's state, into inventory.yaml
  GET  /api/setup                 does the first-run setup apply (no devices, or the example's)
  POST /api/setup/router          {dhcp_source, credentials} -> logged in? how many leases?
  POST /api/setup/leases          the same router: its DHCP list, for picking
  POST /api/setup/sweep           no MikroTik: who answers a ping on the main network
  POST /api/setup/write           {devices, router?, preview | bases, password?}
  POST /api/setup/claim           {code, password}: the first password, from the setup code
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time

from . import access, schema
from .login import COOKIE, MAX_LEN, MIN_LEN, SESSION_S, hash_password, verify
from .settings import NAMES, digest
from .yamledit import load

log = logging.getLogger("lanowl.settingsweb")

try:
    from aiohttp import web  # type: ignore
except Exception:  # pragma: no cover
    web = None

CRITS = ("critical", "high", "warning", "low", "info")
CHECKS = ("icmp", "tcp", "http", "snmp", "arp", "link", "lease")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
# a kind guessed from a maker's name (oui.py), for the first-run list: a guess, marked as one
GUESS = (("mikrotik", "mikrotik"), ("routerboard", "mikrotik"), ("shelly", "shelly"),
         ("allterco", "shelly"), ("reolink", "reolink"), ("ubiquiti", "unifi"),
         ("raspberry", "linux"), ("synology", "linux"), ("qnap", "linux"), ("vmware", "esxi"),
         ("nabu casa", "homeassistant"), ("gl.inet", "openwrt"), ("gl technologies", "openwrt"))


def guess_kind(vendor: str) -> str:
    v = (vendor or "").lower()
    return next((k for m, k in GUESS if m in v), "")


def clean_device(d: dict, kinds: dict) -> tuple:
    """(device, error): what the device form sent, checked and in the example's key order.
    Only the fields the form edits are touched; others the file already had are kept by the
    caller (it merges onto the device as it is)."""
    if not isinstance(d, dict):
        return None, "not a device"
    out = {}
    ip = str(d.get("ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, f"{ip or 'the address'} is not an IP address"
    out["ip"] = ip
    name = " ".join(str(d.get("name") or "").split())[:80]
    if not name:
        return None, "a device needs a name"
    out["name"] = name
    for k in ("mac", "group", "role", "note", "site", "depends_on", "expect_offline", "kind", "credentials"):
        v = d.get(k)
        if v not in (None, ""):
            out[k] = " ".join(str(v).split()) if k != "note" else str(v).strip()
    if "mac" in out and not re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", out["mac"]):
        return None, f"{out['mac']} is not a MAC address"
    if "mac" in out:
        out["mac"] = out["mac"].upper().replace("-", ":")
    crit = str(d.get("criticality") or "low")
    if crit not in CRITS:
        return None, f"criticality is one of {', '.join(CRITS)}"
    out["criticality"] = crit
    if out.get("expect_offline") not in (None, "sun", "day"):
        return None, "expect_offline is sun or day"
    if d.get("debounce_fails") not in (None, ""):
        try:
            out["debounce_fails"] = max(1, int(d["debounce_fails"]))
        except (TypeError, ValueError):
            return None, "debounce_fails is a number"
    if "kind" in out and out["kind"] not in kinds:
        return None, f"no kind {out['kind']!r}: one of {', '.join(sorted(kinds))}"
    man = [m for m in (d.get("manage") or []) if isinstance(m, str)]
    if man:
        can = kinds.get(out.get("kind", ""), [])
        bad = [m for m in man if m not in can]
        if bad:
            return None, f"a {out.get('kind') or 'device with no kind'} cannot {', '.join(bad)}"
        out["manage"] = man
    for k in ("restart", "logs", "reboot", "upgrade", "backup"):
        if isinstance(d.get(k), dict) and d[k]:
            out[k] = d[k]
    checks = []
    for c in d.get("checks") or []:
        if not isinstance(c, dict) or c.get("type") not in CHECKS:
            return None, f"a check is one of {', '.join(CHECKS)}"
        c = {k: v for k, v in c.items() if v not in (None, "")}
        if c["type"] in ("tcp", "http"):
            try:
                c["port"] = int(c.get("port") or (80 if c["type"] == "http" else 0))
            except (TypeError, ValueError):
                return None, "a check's port is a number"
            if not 0 < c["port"] < 65536:
                return None, f"a {c['type']} check needs a port"
        checks.append(c)
    out["checks"] = checks or [{"type": "icmp"}]
    return _ordered(out, {}), ""


class SettingsRoutes:
    def __init__(self, dashboard):
        self.d = dashboard
        self.a = dashboard.a
        self._router_try = 0.0

    @property
    def s(self):
        return self.a.settings

    def routes(self, app):
        r = app.router
        r.add_get("/api/settings", self.get)
        r.add_post("/api/settings/plan", self.plan)
        r.add_post("/api/settings/save", self.save)
        r.add_post("/api/settings/restore", self.restore)
        r.add_post("/api/settings/password", self.password)
        r.add_post("/api/restart", self.restart)
        r.add_get("/api/settings/devices", self.devices)
        r.add_post("/api/settings/device", self.device)
        r.add_post("/api/settings/migrate", self.migrate)
        r.add_get("/api/setup", self.setup)
        r.add_post("/api/setup/router", self.router)
        r.add_post("/api/setup/leases", self.leases)
        r.add_post("/api/setup/sweep", self.sweep)
        r.add_post("/api/setup/write", self.write)
        r.add_post("/api/setup/claim", self.claim)

    # --- helpers --------------------------------------------------------------------------
    @staticmethod
    def _j(body, status=200):
        return web.json_response(body, status=status)

    async def _authed(self, request, body: dict):
        """None when this browser may write; else the 403 that tells the page what to ask."""
        lg = self.d.login
        if lg is None or not lg.on:
            return None
        tok = request.cookies.get(COOKIE, "")
        if lg.recent(tok):
            return None
        pw = str(body.get("password") or "")
        if not pw:
            return self._j({"ok": False, "auth": "needed"}, 403)
        async with self.d._login_lock:
            until = lg.locked()
            if until:
                return self._j({"ok": False, "auth": "locked", "until": until}, 403)
            ok = await asyncio.get_running_loop().run_in_executor(None, verify, pw[:1024], lg.hash)
            r = lg.reauth(tok, ok, request.remote or "")
        if r.get("ok"):
            return None
        return self._j({"ok": False, "auth": r.get("why"), "left": r.get("left"), "until": r.get("until")}, 403)

    def _recent(self, request) -> bool:
        lg = self.d.login
        return lg is None or lg.recent(request.cookies.get(COOKIE, ""))

    # --- Settings ---------------------------------------------------------------------------
    async def get(self, request):
        s = self.s
        out = {"ok": True, **s.view(), **s.values(), "recent": self._recent(request),
               "secrets": secrets_view(self.a.cfg, self.a.inv),
               "restart": {"waiting": self.a.restart_blockers(), "since": self.a._started},
               "login": {"on": bool(self.d.login and self.d.login.on),
                         "source": self.d.login.source if self.d.login else ""}}
        return self._j(out)

    async def plan(self, request):
        body = await self.d._body(request)
        name = str((body or {}).get("file") or "")
        if name not in NAMES or not isinstance(body.get("ops"), list):
            return self._j({"ok": False, "error": "bad request"}, 400)
        ops, err = _ops(body["ops"])
        if err:
            return self._j({"ok": False, "error": err}, 400)
        p = self.s.plan(name, ops)
        p.pop("text", None)
        return self._j(p, 200 if p["ok"] else 409)

    async def save(self, request):
        body = await self.d._body(request)
        name = str((body or {}).get("file") or "")
        if name not in NAMES or not isinstance(body.get("ops"), list):
            return self._j({"ok": False, "error": "bad request"}, 400)
        ops, err = _ops(body["ops"])
        if err:
            return self._j({"ok": False, "error": err}, 400)
        if any(tuple(o["path"][:2]) in schema.HASHES for o in ops):
            return self._j({"ok": False, "error": "the password has a button of its own"}, 400)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        r = self.s.save(name, ops, str(body.get("base") or ""), request.remote or "")
        return self._j(r, 200 if r["ok"] else 409)

    async def restore(self, request):
        body = await self.d._body(request) or {}
        sid = body.get("id")
        if body.get("preview"):
            p = self.s.restore_plan(sid)
            p.pop("text", None)
            return self._j(p, 200 if p.get("ok") else 409)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        r = self.s.restore(sid, str(body.get("base") or ""), request.remote or "")
        return self._j(r, 200 if r["ok"] else 409)

    async def password(self, request):
        """A new dashboard password, from Settings: into config.yaml (read-only there: kept in
        the state, like /password's). Every browser is logged out, this one too."""
        body = await self.d._body(request) or {}
        lg = self.d.login
        if lg is None or not lg.on:
            return self._j({"ok": False, "error": "the dashboard's login is switched off"}, 409)
        new = str(body.get("new") or "")
        if not MIN_LEN <= len(new) <= MAX_LEN:
            return self._j({"ok": False, "error": f"a password has {MIN_LEN} characters or more"}, 400)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        hashed = await asyncio.get_running_loop().run_in_executor(None, hash_password, new)
        r = self._write_hash(hashed, request.remote or "", "save")
        if not r["ok"]:
            return self._j(r, 409)
        lg.set_from_page(hashed, r["in_config"])
        resp = self._j({"ok": True, "in_config": r["in_config"]})
        resp.del_cookie(COOKIE, path="/")
        return resp

    def _write_hash(self, hashed: str, ip: str, how: str) -> dict:
        """web.password_hash into config.yaml when it can be written; else {"in_config": False}."""
        f = self.s.files["config"]
        if not f.status()["writable"]:
            return {"ok": True, "in_config": False}
        base = digest(f.read())
        r = self.s.save("config", [{"op": "set", "path": ["web", "password_hash"], "value": hashed}],
                        base, ip, how=how)
        if r.get("why") == "check":       # a check that fails over a password is no reason to keep it out
            return {"ok": True, "in_config": False}
        return {**r, "in_config": bool(r.get("ok"))}

    async def restart(self, request):
        r = self.a.request_restart(request.remote or "the dashboard")
        return self._j(r, 200 if r["ok"] else 409)

    # --- devices --------------------------------------------------------------------------
    def _kinds(self) -> dict:
        """kind -> the features it can do (kinds.py), the owner's profiles included."""
        from .kinds import KINDS, FEATURE_OP, FEATURES
        out = {k: [f for f in FEATURES if f in v or (k == "linux")] for k, v in KINDS.items()}
        for kind, prof in (getattr(self.a.kinds, "profiles", {}) or {}).items():
            ops = getattr(prof, "ops", {}) or {}
            out[kind] = [f for f, op in FEATURE_OP.items() if op in ops]
        return out

    async def devices(self, request):
        from .kinds import FEATURES, SWITCH
        text = self.s.files["inventory"].read()
        raw = load(text) or {}
        logins = access.shared(self.a.cfg).data()["logins"]
        sites = getattr(self.a, "sites", None)
        watched = []
        if sites is not None:
            for ip, w in (sites.rec.get("watch") or {}).items():
                dev = self.a.inv.get(ip)
                watched.append({"ip": ip, "name": dev.name if dev else w.get("name"), "mac": w.get("mac"),
                                "site": w.get("site")})
        return self._j({"ok": True, "base": digest(text), "devices": raw.get("devices") or [],
                        "groups": list((raw.get("groups") or {}).keys()), "kinds": self._kinds(),
                        "features": FEATURES,
                        "switches": {f: bool((self.a.cfg.get(sw) or {}).get("enabled")) for f, sw in SWITCH.items()},
                        "logins": [{"name": n, "type": ("key + password" if lg.key and lg.password else
                                                        "key" if lg.key else "password")}
                                   for n, lg in sorted(logins.items())],
                        "watched": watched, "status": self.s.files["inventory"].status(),
                        "recent": self._recent(request)})

    def _device_ops(self, body: dict, raw: dict) -> tuple:
        devs = raw.get("devices") or []
        old_ip = body.get("ip")
        idx = next((i for i, x in enumerate(devs) if isinstance(x, dict) and str(x.get("ip")) == str(old_ip)), None) \
            if old_ip else None
        if old_ip and idx is None:
            return None, f"{old_ip} is not in inventory.yaml"
        if body.get("device") is None:
            return ([{"op": "remove", "path": ["devices", idx]}], "") if idx is not None else (None, "nothing to remove")
        dev, err = clean_device(body["device"], self._kinds())
        if err:
            return None, err
        others = {str(x.get("ip")) for i, x in enumerate(devs) if isinstance(x, dict) and i != idx}
        if dev["ip"] in others:
            return None, f"{dev['ip']} is in inventory.yaml already"
        if idx is None:
            return [{"op": "insert", "path": ["devices"], "value": dev}], ""
        # the fields the form does not edit stay as the file has them
        kept = {k: v for k, v in devs[idx].items() if k not in _FORM_KEYS}
        return [{"op": "set", "path": ["devices", idx], "value": {**_ordered(dev, kept)}}], ""

    async def device(self, request):
        body = await self.d._body(request) or {}
        text = self.s.files["inventory"].read()
        ops, err = self._device_ops(body, load(text) or {})
        if err:
            return self._j({"ok": False, "error": err}, 400)
        if body.get("preview"):
            p = self.s.plan("inventory", ops, text)
            p.pop("text", None)
            return self._j(p, 200 if p["ok"] else 409)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        how = "watch" if body.get("how") == "watch" else "save"
        r = self.s.save("inventory", ops, str(body.get("base") or ""), request.remote or "", how=how)
        if r["ok"] and how == "watch" and body.get("device"):
            self._watch_now(body["device"])
        return self._j(r, 200 if r["ok"] else 409)

    def _watch_now(self, dev: dict):
        """Watch: written to inventory.yaml, and pinged from now on, as before — no restart."""
        from .model import inventory_from
        d, _ = clean_device(dev, self._kinds())
        if d and self.a.inv.get(d["ip"]) is None:
            self.a.inv.add(inventory_from({"devices": [d]}, "").devices[0])
            refresh = getattr(self.a, "refresh_report", None)
            if callable(refresh):
                refresh()

    async def migrate(self, request):
        """The devices Watch kept in lanowl's state before it wrote inventory.yaml: moved there
        in one save, then out of the state."""
        body = await self.d._body(request) or {}
        sites = self.a.sites
        rows = []
        for ip, w in list((sites.rec.get("watch") or {}).items()):
            dev = self.a.inv.get(ip)
            if dev is None:
                continue
            a = dev.attrs or {}
            d = {"ip": ip, "name": dev.name, "mac": str(w.get("mac") or "").upper(), "group": dev.group,
                 "criticality": dev.criticality}
            if w.get("site") and w["site"] != "home":
                d["site"] = w["site"]
                if a.get("depends_on"):
                    d["depends_on"] = a["depends_on"]
                d["debounce_fails"] = int(a.get("debounce_fails") or 5)
            d["checks"] = [{"type": "icmp"}]
            rows.append(d)
        if not rows:
            return self._j({"ok": False, "error": "nothing to move"}, 409)
        text = self.s.files["inventory"].read()
        have = {str(x.get("ip")) for x in (load(text) or {}).get("devices") or [] if isinstance(x, dict)}
        ops = [{"op": "insert", "path": ["devices"], "value": d} for d in rows if d["ip"] not in have]
        if body.get("preview"):
            p = self.s.plan("inventory", ops, text) if ops else {"ok": True, "diff": [], "changes": [], "problems": [],
                                                               "base": digest(text)}
            p.pop("text", None)
            return self._j(p, 200 if p["ok"] else 409)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        r = self.s.save("inventory", ops, str(body.get("base") or ""), request.remote or "") if ops else \
            {"ok": True, "changes": []}
        if r["ok"]:
            for d in rows:
                sites.rec["watch"].pop(d["ip"], None)
            sites._save()
        return self._j(r, 200 if r["ok"] else 409)

    # --- the first-run setup ------------------------------------------------------------
    def _needed(self) -> str:
        """"empty" (no devices), "example" (still the example's seven), or ""."""
        raw = load(self.s.files["inventory"].read()) or {}
        devs = [d for d in raw.get("devices") or [] if isinstance(d, dict)]
        if not devs:
            return "empty"
        ex = schema.example_path("inventory.example.yaml")
        try:
            with open(ex, encoding="utf-8") as f:
                exd = [str(d.get("ip")) for d in (load(f.read()) or {}).get("devices") or []]
        except OSError:
            exd = []
        return "example" if exd and sorted(str(d.get("ip")) for d in devs) == sorted(exd) else ""

    async def setup(self, request):
        mk = self.a.cfg.get("mikrotik") or {}
        name = access.service_login_name(self.a.cfg, "mikrotik")
        lg = access.service_login(self.a.cfg, "mikrotik")
        return self._j({"ok": True, "needed": self._needed(), "dhcp_source": mk.get("dhcp_source") or "",
                        "credentials": name, "login_set": bool(lg.user and lg.password),
                        "files": {k: f.status() for k, f in self.s.files.items()},
                        "bases": {k: digest(f.read()) for k, f in self.s.files.items()},
                        "recent": self._recent(request)})

    def _router_cfg(self, body: dict) -> tuple:
        """A copy of the config with the router the setup page typed: (cfg, error)."""
        import copy
        src = str(body.get("dhcp_source") or "").strip().rstrip("/")
        if src and not re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+$", src):
            return None, "the router's address is http:// or https:// and its address, e.g. http://192.168.88.1"
        name = str(body.get("credentials") or "").strip() or "router-read"
        cfg = copy.deepcopy({k: v for k, v in self.a.cfg.items()})
        cfg.setdefault("mikrotik", {})
        cfg["mikrotik"] = {**(cfg.get("mikrotik") or {}), "dhcp_source": src, "credentials": name}
        return cfg, ""

    async def _rest(self, cfg: dict, path: str):
        from . import probes
        lg = access.service_login(cfg, "mikrotik")
        mk = cfg["mikrotik"]
        return await probes.mikrotik_rest(mk["dhcp_source"], path, lg.user, lg.password,
                                          bool(mk.get("verify_tls", False)), 8000)

    async def router(self, request):
        body = await self.d._body(request) or {}
        cfg, err = self._router_cfg(body)
        if err:
            return self._j({"ok": False, "error": err}, 400)
        name = cfg["mikrotik"]["credentials"]
        lg = access.service_login(cfg, "mikrotik")
        if not (lg.user and lg.password):
            return self._j({"ok": False, "login": False, "name": name,
                            "error": f"secrets.yaml has no login {name!r} (a user and a password) yet"})
        if not cfg["mikrotik"]["dhcp_source"]:
            return self._j({"ok": False, "login": True, "error": "type the router's address"})
        now = time.time()
        if now - self._router_try < 3:     # one try at a time: each refused one is a line in the router's log
            return self._j({"ok": False, "login": True, "error": "a moment: the last try was just now"}, 429)
        self._router_try = now
        r = await self._rest(cfg, "system/resource")
        if not r.ok:
            why = ("the router refused the login (HTTP 401): check its password in secrets.yaml, and on "
                   "the router that this user may log in from lanowl's address" if r.detail == "mikrotik http 401"
                   else f"the router did not answer as a MikroTik: {r.detail}")
            return self._j({"ok": False, "login": True, "user": lg.user, "error": why})
        res = r.data.get("json") or {}
        res = res[0] if isinstance(res, list) and res else res
        leases = await self._rest(cfg, "ip/dhcp-server/lease")
        n = len(leases.data.get("json") or []) if leases.ok else 0
        return self._j({"ok": True, "login": True, "user": lg.user, "version": (res or {}).get("version", ""),
                        "board": (res or {}).get("board-name", ""), "leases": n})

    async def leases(self, request):
        from .oui import vendor
        body = await self.d._body(request) or {}
        cfg, err = self._router_cfg(body)
        if err:
            return self._j({"ok": False, "error": err}, 400)
        r = await self._rest(cfg, "ip/dhcp-server/lease")
        if not r.ok:
            return self._j({"ok": False, "error": f"the router's DHCP list could not be read: {r.detail}"}, 409)
        rows = []
        for x in r.data.get("json") or []:
            ip, mac = str(x.get("address") or ""), str(x.get("mac-address") or "").upper()
            if not _IP.match(ip) or x.get("disabled") == "true":
                continue
            v = vendor(mac)
            rows.append({"ip": ip, "mac": mac, "name": str(x.get("host-name") or x.get("comment") or ""),
                         "comment": str(x.get("comment") or ""), "vendor": v, "kind": guess_kind(v),
                         "static": x.get("dynamic") == "false", "status": str(x.get("status") or ""),
                         "last_seen": str(x.get("last-seen") or ""),
                         "here": x.get("status") == "bound"})
        rows.sort(key=lambda r: tuple(int(o) for o in r["ip"].split(".")))
        host = re.sub(r"^https?://", "", cfg["mikrotik"]["dhcp_source"]).split(":")[0].split("/")[0]
        return self._j({"ok": True, "router": host, "rows": rows})

    async def sweep(self, request):
        """No MikroTik: ping every address of the main network once (fping), then read the
        host's ARP table for the MACs. Addresses, MACs, makers — no names."""
        from .model import main_lans
        from .oui import vendor
        nets = []
        for n in main_lans(self.a.cfg) or []:
            try:
                net = ipaddress.ip_network(str(n), strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.num_addresses <= 1024:
                nets.append(str(net))
        if not nets:
            return self._j({"ok": False, "error": "no main network to sweep (sites.list, the site keyed home)"}, 409)
        try:
            proc = await asyncio.create_subprocess_exec("fping", "-a", "-q", "-r", "1", "-t", "300", "-g", *nets[:1],
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except (OSError, asyncio.TimeoutError) as e:
            return self._j({"ok": False, "error": f"the sweep did not run: {e}"}, 409)
        alive = [x.strip() for x in out.decode(errors="ignore").split() if _IP.match(x.strip())]
        arp = {}
        try:
            with open("/proc/net/arp", encoding="ascii") as f:
                for ln in f.read().splitlines()[1:]:
                    p = ln.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        arp[p[0]] = p[3].upper()
        except OSError:
            pass
        rows = []
        for ip in alive:
            mac = arp.get(ip, "")
            v = vendor(mac) if mac else ""
            rows.append({"ip": ip, "mac": mac, "name": "", "vendor": v, "kind": guess_kind(v),
                         "static": False, "here": True, "last_seen": ""})
        rows.sort(key=lambda r: tuple(int(o) for o in r["ip"].split(".")))
        return self._j({"ok": True, "router": "", "rows": rows, "swept": nets[0]})

    async def write(self, request):
        """The setup's last step: the picked devices into inventory.yaml (the example's devices
        out), and the router into config.yaml when the page changed it."""
        body = await self.d._body(request) or {}
        kinds = self._kinds()
        devs = []
        for d in body.get("devices") or []:
            dev, err = clean_device(d, kinds)
            if err:
                return self._j({"ok": False, "error": f"{d.get('ip') or '?'}: {err}"}, 400)
            devs.append(dev)
        if len({d["ip"] for d in devs}) != len(devs):
            return self._j({"ok": False, "error": "the same address twice"}, 400)
        itext = self.s.files["inventory"].read()
        raw = load(itext) or {}
        have = [x for x in raw.get("devices") or [] if isinstance(x, dict)]
        replace = self._needed() == "example"
        iops = [{"op": "remove", "path": ["devices", i]} for i in range(len(have) - 1, -1, -1)] if replace else []
        keep = set() if replace else {str(x.get("ip")) for x in have}
        iops += [{"op": "insert", "path": ["devices"], "value": d} for d in devs if d["ip"] not in keep]
        cops = []
        router = body.get("router") or {}
        mk = self.a.cfg.get("mikrotik") or {}
        for k in ("dhcp_source", "credentials"):
            v = str(router.get(k) or "").strip().rstrip("/") if k in router else None
            if v is not None and v != str(mk.get(k) or ""):
                cops.append({"op": "set", "path": ["mikrotik", k], "value": v})
        if body.get("preview"):
            out = {"ok": True, "inventory": self.s.plan("inventory", iops, itext) if iops else None,
                   "config": self.s.plan("config", cops) if cops else None}
            for k in ("inventory", "config"):
                if out[k]:
                    out[k].pop("text", None)
                    out["ok"] = out["ok"] and out[k]["ok"]
            return self._j(out, 200 if out["ok"] else 409)
        denied = await self._authed(request, body)
        if denied is not None:
            return denied
        bases = body.get("bases") or {}
        ip = request.remote or ""
        r = {"ok": True}
        if iops:
            r["inventory"] = self.s.save("inventory", iops, str(bases.get("inventory") or ""), ip, how="setup")
            if not r["inventory"]["ok"]:
                return self._j({"ok": False, **r["inventory"]}, 409)
        if cops:
            r["config"] = self.s.save("config", cops, str(bases.get("config") or ""), ip, how="setup")
            if not r["config"]["ok"]:
                return self._j({"ok": False, **r["config"]}, 409)
        return self._j(r)

    async def claim(self, request):
        """The first page of a new install: the setup code, then the password. Open without a
        login — that is the point — and only while there is no password."""
        lg = self.d.login
        if lg is None or not lg.on or not lg.needed:
            return self._j({"ok": False, "why": "none"}, 409)
        body = await self.d._body(request) or {}
        pw = str(body.get("password") or "")
        async with self.d._login_lock:
            r = lg.code_ok(str(body.get("code") or ""), request.remote or "")
            if not r["ok"]:
                return self._j(r, 403)
            if not MIN_LEN <= len(pw) <= MAX_LEN:
                return self._j({"ok": False, "why": "short"}, 400)
            hashed = await asyncio.get_running_loop().run_in_executor(None, hash_password, pw)
            w = self._write_hash(hashed, request.remote or "", "setup")
            token = lg.set_from_page(hashed, bool(w.get("in_config")), keep_in=True)
        resp = self._j({"ok": True, "in_config": bool(w.get("in_config"))})
        from .web import _https
        resp.set_cookie(COOKIE, token, max_age=SESSION_S, path="/", httponly=True, samesite="Lax",
                        secure=_https(request))
        log.warning("dashboard: password set with the setup code, from %s", request.remote or "?")
        return resp


# the keys the device form edits; anything else a device has in the file is kept as it is
_FORM_KEYS = {"ip", "name", "mac", "group", "criticality", "role", "note", "site", "depends_on",
              "expect_offline", "debounce_fails", "kind", "credentials", "manage", "restart", "logs",
              "reboot", "upgrade", "backup", "checks"}


def _ordered(dev: dict, kept: dict) -> dict:
    from .settings import DEVICE_ORDER
    both = {**kept, **dev}
    keys = [k for k in DEVICE_ORDER if k in both] + [k for k in both if k not in DEVICE_ORDER]
    return {k: both[k] for k in keys}


def _ops(raw) -> tuple:
    """The page's operations, checked: set and del on a path of names (no list indexes from
    the page into config.yaml)."""
    import yaml
    out = []
    for o in raw:
        if not isinstance(o, dict) or o.get("op") not in ("set", "del") or not isinstance(o.get("path"), list) \
                or not o["path"] or not all(isinstance(k, str) and k for k in o["path"]):
            return None, "bad operation"
        if o["op"] == "set" and isinstance(o.get("yaml"), str):
            # a field edited as YAML (a list of maps, a catalog): parsed here, never by the page
            try:
                v = yaml.safe_load(o["yaml"]) if o["yaml"].strip() else None
            except yaml.YAMLError as e:
                return None, f"{'.'.join(o['path'])} is not valid YAML: {str(e).splitlines()[0]}"
            out.append({"op": "set", "path": o["path"], "value": v})
            continue
        out.append({"op": o["op"], "path": o["path"], **({"value": o.get("value")} if o["op"] == "set" else {})})
    return out, ""


def secrets_view(cfg: dict, inv) -> dict:
    """secrets.yaml by name: what is set, what is missing, what uses it. Never a value."""
    f = access.shared(cfg)
    d = f.data()
    used: dict = {}
    for dev in (inv.devices if inv is not None else []):
        n = str(dev.attrs.get("credentials") or "")
        if n:
            used.setdefault(n, []).append(dev.name)
    for ip, n in d["devices"].items():
        used.setdefault(n, []).append(ip)
    for sec in ("mikrotik", "mqtt"):
        if sec == "mqtt" and not (cfg.get("mqtt") or {}).get("host"):
            continue
        if sec == "mikrotik" and not (cfg.get("mikrotik") or {}).get("dhcp_source"):
            continue
        used.setdefault(access.service_login_name(cfg, sec), []).append(
            "the router's read-only user" if sec == "mikrotik" else "the MQTT broker")
    logins = [{"name": n, "set": True, "type": "key + password" if lg.key and lg.password else
               "key" if lg.key else "password", "used_by": used.get(n, [])} for n, lg in sorted(d["logins"].items())]
    missing = [{"name": n, "set": False, "used_by": u} for n, u in sorted(used.items()) if n not in d["logins"]]
    tokens = []
    for name, need in (("telegram", (cfg.get("telegram") or {}).get("chat_id")),
                       ("homeassistant", (cfg.get("access") or {}).get("ha_url"))):
        _, where = access.token_from(cfg, name)
        tokens.append({"name": name, "set": bool(where), "where": where, "needed": bool(need)})
    key = access.ssh_key(cfg)
    return {"path": f.path, "error": f.error, "exists": os.path.exists(f.path), "logins": logins + missing,
            "tokens": tokens, "ssh_key": {"path": key, "exists": bool(key) and os.path.exists(key)}}
