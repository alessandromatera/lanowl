"""The dashboard's Settings, devices and first-run setup: the routes (settings.py does the work).

Every route here is behind the login (web.py), except `/api/setup/claim`: the first page of a
new install, which takes the setup code and the password. A logged-in browser may write: the
login is the guard, and nothing asks the password again.

  GET  /api/settings              the forms with their values and sources, the files, the
                                  history, what waits for a restart, the secrets by name
  POST /api/settings/plan         {file, ops} -> the diff, the changes, --check's new ✗
  POST /api/settings/save         {file, ops, base}
  POST /api/settings/restore      {id, preview | base}
  POST /api/settings/password     {new} -> a new dashboard password (everyone out)
  POST /api/restart               Restart to apply
  GET  /api/settings/devices      inventory.yaml's devices, the kinds and what each can do,
                                  the logins by name, the devices watched in lanowl's state
  POST /api/settings/device       {ip | null, device | null, login?, preview | base + sbase,
                                  how}: a device, and its own login (secrets.yaml)
  POST /api/settings/migrate      the devices watched in lanowl's state, into inventory.yaml
  POST /api/settings/secret       {op: login | token | remove, name, user?, how?, value?,
                                  preview | base}: secrets.yaml, write-only
  POST /api/settings/site         {key | null, site: {name, nets, router, criticality} | null,
                                  preview | base}: a site of `sites.list`, added, changed or
                                  removed (config.yaml)
  GET  /api/setup                 does the first-run setup apply (no devices, or the example's)
  POST /api/setup/router          {dhcp_source, credentials, user?, password?} -> logged in?
                                  how many leases? (a typed login is tried, not written)
  POST /api/setup/leases          the same router: its DHCP list, for picking
  POST /api/setup/sweep           no MikroTik: who answers a ping on the main network
  POST /api/setup/telegram        {token} -> the bot's name (getMe)
  POST /api/setup/telegram/chats  {token, offset} -> the chats that wrote to it (getUpdates)
  POST /api/setup/telegram/hello  {token, chat_id} -> one line to that chat
  POST /api/setup/write           {devices, router?, logins?, telegram?, timezone?,
                                   preview | bases}: secrets.yaml, inventory.yaml,
                                  config.yaml, in that order
  POST /api/setup/claim           {code, password}: the first password, from the setup code

A secret the page sends is checked, written, and never sent back: no route answers with one,
and nothing here logs one.
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
_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")      # a login's name in secrets.yaml
_TG_TOKEN = re.compile(r"^\d{3,15}:[A-Za-z0-9_-]{20,64}$")
SECRET_MAX = 1024
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
        self._tg_busy = False

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
        r.add_post("/api/settings/secret", self.secret)
        r.add_post("/api/settings/site", self.site)
        r.add_get("/api/setup", self.setup)
        r.add_post("/api/setup/router", self.router)
        r.add_post("/api/setup/leases", self.leases)
        r.add_post("/api/setup/sweep", self.sweep)
        r.add_post("/api/setup/telegram", self.tg_check)
        r.add_post("/api/setup/telegram/chats", self.tg_chats)
        r.add_post("/api/setup/telegram/hello", self.tg_hello)
        r.add_post("/api/setup/write", self.write)
        r.add_post("/api/setup/claim", self.claim)

    # --- helpers --------------------------------------------------------------------------
    @staticmethod
    def _j(body, status=200):
        return web.json_response(body, status=status)

    # --- Settings ---------------------------------------------------------------------------
    async def get(self, request):
        s = self.s
        out = {"ok": True, **s.view(), **s.values(),
               "secrets": {**secrets_view(self.a.cfg, self.a.inv), "file": s.files["secrets"].status(),
                           "base": digest(s.files["secrets"].read())},
               "restart": {"waiting": self.a.restart_blockers(), "since": self.a._started,
                           "answering": int(getattr(getattr(self.a, "chat", None), "answering", 0) or 0)},
               "login": {"on": bool(self.d.login and self.d.login.on),
                         "source": self.d.login.source if self.d.login else ""},
               "sites": sites_view(load(s.files["config"].read()) or {},
                                   load(s.files["inventory"].read()) or {})}
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
        r = self.s.save(name, ops, str(body.get("base") or ""), request.remote or "")
        return self._j(r, 200 if r["ok"] else 409)

    async def restore(self, request):
        body = await self.d._body(request) or {}
        sid = body.get("id")
        if body.get("preview"):
            p = self.s.restore_plan(sid)
            p.pop("text", None)
            return self._j(p, 200 if p.get("ok") else 409)
        r = self.s.restore(sid, str(body.get("base") or ""), request.remote or "")
        r.pop("text", None)
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

    # --- sites ----------------------------------------------------------------------------
    async def site(self, request):
        """A site of `sites.list`, from Settings → Sites or a router's page ("Make it a site"):
        checked here (site_list), then saved like any change of config.yaml."""
        body = await self.d._body(request) or {}
        if body.get("site") is not None and not isinstance(body.get("site"), dict):
            return self._j({"ok": False, "error": "bad request"}, 400)
        text = self.s.files["config"].read()
        raw = load(text) or {}
        new, err = site_list(raw, load(self.s.files["inventory"].read()) or {},
                             str(body.get("key") or "") or None, body.get("site"))
        if err:
            return self._j({"ok": False, "error": err}, 400)
        ops = [{"op": "set", "path": ["sites", "list"], "value": new}] if new else \
            [{"op": "del", "path": ["sites", "list"]}]
        if body.get("preview"):
            p = self.s.plan("config", ops, text)
            p.pop("text", None)
            return self._j(p, 200 if p["ok"] else 409)
        r = self.s.save("config", ops, str(body.get("base") or ""), request.remote or "")
        r.pop("text", None)
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
        used = {}
        for dev in raw.get("devices") or []:
            if isinstance(dev, dict) and dev.get("credentials"):
                used.setdefault(str(dev["credentials"]), []).append(str(dev.get("name") or dev.get("ip")))
        sites = getattr(self.a, "sites", None)
        watched = []
        if sites is not None:
            for ip, w in (sites.rec.get("watch") or {}).items():
                dev = self.a.inv.get(ip)
                watched.append({"ip": ip, "name": dev.name if dev else w.get("name"), "mac": w.get("mac"),
                                "site": w.get("site")})
        return self._j({"ok": True, "base": digest(text), "devices": raw.get("devices") or [],
                        "groups": inv_groups(raw), "kinds": self._kinds(),
                        "features": FEATURES,
                        "switches": {f: bool((self.a.cfg.get(sw) or {}).get("enabled")) for f, sw in SWITCH.items()},
                        "logins": [{"name": n, "type": ("key + password" if lg.key and lg.password else
                                                        "key" if lg.key else "password"),
                                    "how": "key" if lg.key else "password", "user": lg.user,
                                    "used": used.get(n, [])}
                                   for n, lg in sorted(logins.items())],
                        "secrets": {"writable": self.s.files["secrets"].status()["writable"],
                                    "public_key": public_key(self.a.cfg)},
                        "watched": watched, "status": self.s.files["inventory"].status()})

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

    def _device_login(self, body: dict) -> tuple:
        """(secrets ops, error) of the device form's own login: {name, user, how, password}.
        The device then names it (`credentials:`). A login as it already is: no op."""
        lg = body.get("login")
        if not isinstance(lg, dict) or not isinstance(body.get("device"), dict):
            return [], ""
        name = str(lg.get("name") or "").strip()
        if not _LOGIN.match(name):
            return None, "a login's name is letters, digits, - . and _"
        if not self.s.files["secrets"].status()["writable"]:
            return None, "secrets.yaml cannot be written by lanowl: " + \
                self.s.files["secrets"].status()["why"]
        raw = load(self.s.files["secrets"].read()) or {}
        have = raw.get("logins") if isinstance(raw.get("logins"), dict) else {}
        ops, err = login_op(name, {"user": lg.get("user"), "how": lg.get("how"), "value": lg.get("password")},
                            have.get(name))
        if err.startswith("nothing to save"):
            ops, err = [], ""
        if err:
            return None, f"its login: {err}"
        body["device"]["credentials"] = name
        return ops, ""

    async def device(self, request):
        body = await self.d._body(request) or {}
        sops, err = self._device_login(body)
        if err:
            return self._j({"ok": False, "error": err}, 400)
        text = self.s.files["inventory"].read()
        ops, err = self._device_ops(body, load(text) or {})
        if err:
            return self._j({"ok": False, "error": err}, 400)
        if body.get("preview"):
            sp = self.s.plan("secrets", sops) if sops else None
            p = self.s.plan("inventory", ops, text, secrets_text=sp["text"] if sp and sp.get("ok") else None)
            p.pop("text", None)
            if sp:
                sp.pop("text", None)
                p["secrets"] = sp
                p["ok"] = p["ok"] and sp["ok"]
                if not sp["ok"]:
                    p["error"] = sp.get("error")
            return self._j(p, 200 if p["ok"] else 409)
        how = "watch" if body.get("how") == "watch" else "save"
        if sops:
            rs = self.s.save("secrets", sops, str(body.get("sbase") or ""), request.remote or "")
            rs.pop("text", None)
            if not rs["ok"]:
                return self._j(rs, 409)
        r = self.s.save("inventory", ops, str(body.get("base") or ""), request.remote or "", how=how)
        if r["ok"] and how == "watch" and body.get("device"):
            await self._watch_now(body["device"])
        return self._j(r, 200 if r["ok"] else 409)

    async def _watch_now(self, dev: dict):
        """Watch: written to inventory.yaml, and pinged from now on, as before — no restart.
        Probed at once, so the page shows it now and not at the next sweep."""
        from .model import inventory_from
        d, _ = clean_device(dev, self._kinds())
        if d and self.a.inv.get(d["ip"]) is None:
            self.a.inv.add(inventory_from({"devices": [d]}, "").devices[0])
            probe = getattr(self.a, "probe_now", None)
            if callable(probe):
                try:
                    await probe(d["ip"])
                    return
                except Exception:
                    log.warning("settings: the first probe of %s failed", d["ip"], exc_info=True)
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
        r = self.s.save("inventory", ops, str(body.get("base") or ""), request.remote or "") if ops else \
            {"ok": True, "changes": []}
        if r["ok"]:
            for d in rows:
                sites.rec["watch"].pop(d["ip"], None)
            sites._save()
        return self._j(r, 200 if r["ok"] else 409)

    # --- secrets.yaml, write-only ---------------------------------------------------------
    def _secret_ops(self, body: dict, raw: dict) -> tuple:
        """(ops, error) of one Secrets save: a login set or replaced, a token set or replaced,
        a login taken out (not while something still names it)."""
        op, name = str(body.get("op") or ""), str(body.get("name") or "").strip()
        logins = raw.get("logins") if isinstance(raw.get("logins"), dict) else {}
        value = body.get("value")
        value = "" if value is None else str(value)
        if len(value) > SECRET_MAX or "\x00" in value:
            return None, "that value is too long"
        if op == "token":
            if name not in access.TOKENS:
                return None, f"no token {name!r}: one of {', '.join(access.TOKENS)}"
            if not value.strip():
                return None, "paste the token"
            if name == "telegram" and not _TG_TOKEN.match(value.strip()):
                return None, "a bot's token looks like 123456:ABC-DEF…: a number, a colon, then letters"
            return [{"op": "set", "path": ["tokens", name], "value": value.strip()}], ""
        if not _LOGIN.match(name):
            return None, "a login's name is letters, digits, - . and _"
        if op == "remove":
            if name not in logins:
                return None, f"secrets.yaml has no login {name!r}"
            users = login_users(self.a.cfg, self.a.inv, raw).get(name)
            if users:
                return None, f"{name} is used by {', '.join(users[:5])}: give {'it' if len(users) == 1 else 'them'} another login first"
            return [{"op": "del", "path": ["logins", name]}], ""
        if op != "login":
            return None, "bad request"
        return login_op(name, body, logins.get(name))

    async def secret(self, request):
        body = await self.d._body(request) or {}
        f = self.s.files["secrets"]
        text = f.read()
        ops, err = self._secret_ops(body, load(text) or {})
        if err:
            return self._j({"ok": False, "error": err}, 400)
        if body.get("preview"):
            p = self.s.plan("secrets", ops, text)
            p.pop("text", None)
            return self._j(p, 200 if p["ok"] else 409)
        r = self.s.save("secrets", ops, str(body.get("base") or ""), request.remote or "")
        r.pop("text", None)
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
        from .firstrun import env_tz
        mk = self.a.cfg.get("mikrotik") or {}
        name = access.service_login_name(self.a.cfg, "mikrotik")
        lg = access.service_login(self.a.cfg, "mikrotik")
        d = access.shared(self.a.cfg).data()
        tok, where = access.token_from(self.a.cfg, "telegram")
        return self._j({"ok": True, "needed": self._needed(), "dhcp_source": mk.get("dhcp_source") or "",
                        "credentials": name, "login_set": bool(lg.user and lg.password),
                        "login_user": lg.user or "",
                        "secrets_path": access.secrets_path(self.a.cfg),
                        "logins": [{"name": n, "user": x.user, "how": "key" if x.key else "password"}
                                   for n, x in sorted(d["logins"].items())],
                        "groups": inv_groups(load(self.s.files["inventory"].read()) or {}),
                        "telegram": {"token": bool(tok), "where": where,
                                     "chat_id": str((self.a.cfg.get("telegram") or {}).get("chat_id") or "")},
                        "timezone": str(self.a.cfg.get("timezone") or ""), "tz_env": env_tz(),
                        "public_key": public_key(self.a.cfg),
                        "files": {k: f.status() for k, f in self.s.files.items()},
                        "bases": {k: digest(f.read()) for k, f in self.s.files.items()}})

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

    @staticmethod
    def _typed(body: dict):
        """The router's login as the page typed it, or None: tried, never kept here."""
        u, p = str(body.get("user") or "").strip(), body.get("password")
        p = "" if p is None else str(p)
        if u and p and len(u) <= 128 and len(p) <= SECRET_MAX:
            return access.Login(u, p)
        return None

    async def _rest(self, cfg: dict, path: str, lg=None):
        from . import probes
        lg = lg or access.service_login(cfg, "mikrotik")
        mk = cfg["mikrotik"]
        return await probes.mikrotik_rest(mk["dhcp_source"], path, lg.user, lg.password,
                                          bool(mk.get("verify_tls", False)), 8000)

    async def router(self, request):
        body = await self.d._body(request) or {}
        cfg, err = self._router_cfg(body)
        if err:
            return self._j({"ok": False, "error": err}, 400)
        name = cfg["mikrotik"]["credentials"]
        typed = self._typed(body)
        lg = typed or access.service_login(cfg, "mikrotik")
        if not (lg.user and lg.password):
            path = access.secrets_path(cfg)
            sf = access.shared(cfg)
            why = (f"{path} could not be read: {sf.error}" if sf.error else
                   "type the router user's name and password" if self.s.files["secrets"].status()["writable"] else
                   f"{path} has no login {name!r} with a user and a password yet" if os.path.exists(path) else
                   f"there is no {path}")
            return self._j({"ok": False, "login": False, "name": name, "path": path, "error": why})
        if not cfg["mikrotik"]["dhcp_source"]:
            return self._j({"ok": False, "login": True, "error": "type the router's address"})
        now = time.time()
        if now - self._router_try < 3:     # one try at a time: each refused one is a line in the router's log
            return self._j({"ok": False, "login": True, "error": "a moment: the last try was just now"}, 429)
        self._router_try = now
        r = await self._rest(cfg, "system/resource", lg)
        if not r.ok:
            where = "the user and the password" if typed else "its password in secrets.yaml"
            why = (f"the router refused the login (HTTP 401): check {where}, and on the router that "
                   "this user may log in from lanowl's address" if r.detail == "mikrotik http 401"
                   else f"the router did not answer as a MikroTik: {r.detail}")
            return self._j({"ok": False, "login": True, "user": lg.user, "error": why})
        res = r.data.get("json") or {}
        res = res[0] if isinstance(res, list) and res else res
        leases = await self._rest(cfg, "ip/dhcp-server/lease", lg)
        n = len(leases.data.get("json") or []) if leases.ok else 0
        return self._j({"ok": True, "login": True, "user": lg.user, "version": (res or {}).get("version", ""),
                        "board": (res or {}).get("board-name", ""), "leases": n})

    async def leases(self, request):
        from .oui import vendor
        body = await self.d._body(request) or {}
        cfg, err = self._router_cfg(body)
        if err:
            return self._j({"ok": False, "error": err}, 400)
        r = await self._rest(cfg, "ip/dhcp-server/lease", self._typed(body))
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

    # --- Telegram, from the setup: the token, then /start -----------------------------------
    async def _tg(self, token: str, method: str, params: dict = None, timeout: float = 15) -> dict:
        """One Bot API call: its JSON answer, or {"ok": False, "description": why}. The token is
        in the URL Telegram asks for, and nowhere else: not in a log line, not in an answer."""
        import aiohttp
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as sess:
                async with sess.post(f"https://api.telegram.org/bot{token}/{method}", json=params or {}) as r:
                    j = await r.json(content_type=None)
                    return j if isinstance(j, dict) else {"ok": False, "description": f"HTTP {r.status}"}
        except asyncio.TimeoutError:
            return {"ok": False, "description": "Telegram did not answer in time"}
        except Exception as e:
            return {"ok": False, "description": f"Telegram could not be reached: {type(e).__name__}"}

    @staticmethod
    def _tg_token(body: dict) -> str:
        t = str(body.get("token") or "").strip()
        return t if _TG_TOKEN.match(t) else ""

    def _tg_mine(self, token: str) -> bool:
        """lanowl itself already reads this bot's messages (a second reader gets 409)."""
        return bool(token) and token == access.token(self.a.cfg, "telegram") and \
            bool(getattr(getattr(self.a, "poller", None), "enabled", False))

    async def tg_check(self, request):
        body = await self.d._body(request) or {}
        token = self._tg_token(body)
        if not token:
            return self._j({"ok": False, "error": "a bot's token looks like 123456:ABC-DEF…: a number, a colon, "
                                                  "then letters. @BotFather gives it"}, 400)
        j = await self._tg(token, "getMe")
        if not j.get("ok"):
            return self._j({"ok": False, "error": f"Telegram answered: {str(j.get('description') or '?')[:200]}"})
        me = j.get("result") or {}
        return self._j({"ok": True, "user": str(me.get("username") or ""), "name": str(me.get("first_name") or ""),
                        "mine": self._tg_mine(token)})

    async def tg_chats(self, request):
        """Who wrote to the bot: a long poll of its updates (20 s), the chats in them. The
        page calls it again until the owner picks one, for up to five minutes."""
        body = await self.d._body(request) or {}
        token = self._tg_token(body)
        if not token:
            return self._j({"ok": False, "error": "no token"}, 400)
        if self._tg_mine(token):
            return self._j({"ok": False, "error": "lanowl already reads this bot's messages: its chat is "
                                                  "telegram.chat_id in Settings"}, 409)
        if self._tg_busy:
            return self._j({"ok": False, "busy": True, "error": "already listening"}, 429)
        self._tg_busy = True
        try:
            params = {"timeout": 20, "allowed_updates": ["message"]}
            try:
                if body.get("offset"):
                    params["offset"] = int(body["offset"])
            except (TypeError, ValueError):
                pass
            j = await self._tg(token, "getUpdates", params, timeout=30)
        finally:
            self._tg_busy = False
        if not j.get("ok"):
            return self._j({"ok": False, "error": f"Telegram answered: {str(j.get('description') or '?')[:200]}"})
        chats, offset = {}, int(body.get("offset") or 0) if str(body.get("offset") or "").isdigit() else 0
        for u in j.get("result") or []:
            offset = max(offset, int(u.get("update_id") or 0) + 1)
            m = u.get("message") or {}
            c = m.get("chat") or {}
            if "id" not in c:
                continue
            who = c.get("title") or " ".join(x for x in (c.get("first_name"), c.get("last_name")) if x) or \
                c.get("username") or str(c["id"])
            chats[str(c["id"])] = {"id": str(c["id"]), "type": str(c.get("type") or ""), "name": str(who)[:80],
                                   "username": str(c.get("username") or ""), "text": str(m.get("text") or "")[:40],
                                   "at": int(m.get("date") or 0)}
        return self._j({"ok": True, "chats": list(chats.values()), "offset": offset})

    async def tg_hello(self, request):
        body = await self.d._body(request) or {}
        token, chat = self._tg_token(body), str(body.get("chat_id") or "").strip()
        if not token or not re.fullmatch(r"-?\d{1,20}", chat):
            return self._j({"ok": False, "error": "bad request"}, 400)
        j = await self._tg(token, "sendMessage", {"chat_id": chat, "text": "🦉 lanowl found this chat. Finish the "
                                                  "setup on the dashboard: alerts and answers come here."})
        if not j.get("ok"):
            return self._j({"ok": False, "error": f"Telegram answered: {str(j.get('description') or '?')[:200]}"})
        return self._j({"ok": True})

    async def write(self, request):
        """The setup's last step: the logins and the bot's token into secrets.yaml, the picked
        devices into inventory.yaml (the example's devices out), the router, the chat and the
        time zone into config.yaml. In that order: each file is checked with the ones before it
        as they will be."""
        from .firstrun import env_tz, valid_tz
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
        # secrets.yaml: the router's login as typed, the new logins the devices use, the token
        stext = self.s.files["secrets"].read()
        sraw = load(stext) or {}
        have = sraw.get("logins") if isinstance(sraw.get("logins"), dict) else {}
        router = body.get("router") or {}
        sops = []
        rname = str(router.get("credentials") or "").strip() or "router-read"
        if self._typed(router):
            if not _LOGIN.match(rname):
                return self._j({"ok": False, "error": "the router login's name is letters, digits, - . and _"}, 400)
            o, err = login_op(rname, {"user": router.get("user"), "how": "password", "value": router.get("password")},
                              have.get(rname))
            if err:
                return self._j({"ok": False, "error": f"the router's login: {err}"}, 400)
            sops += o
        used = {str(d.get("credentials")) for d in devs if d.get("credentials")}
        for name, lg in (body.get("logins") or {}).items() if isinstance(body.get("logins"), dict) else ():
            if name not in used or name == rname and self._typed(router):
                continue
            if not _LOGIN.match(str(name)):
                return self._j({"ok": False, "error": f"{name}: a login's name is letters, digits, - . and _"}, 400)
            lg = lg if isinstance(lg, dict) else {}
            o, err = login_op(str(name), {"user": lg.get("user"), "how": lg.get("how"), "value": lg.get("password")},
                              have.get(name))
            if err:
                return self._j({"ok": False, "error": f"login {name}: {err}"}, 400)
            sops += o
        tg = body.get("telegram") if isinstance(body.get("telegram"), dict) else {}
        token = self._tg_token(tg)
        if tg.get("token") and not token:
            return self._j({"ok": False, "error": "the bot's token does not look like one"}, 400)
        if token and token != access.token(self.a.cfg, "telegram"):
            sops.append({"op": "set", "path": ["tokens", "telegram"], "value": token})
        itext = self.s.files["inventory"].read()
        raw = load(itext) or {}
        have = [x for x in raw.get("devices") or [] if isinstance(x, dict)]
        replace = self._needed() == "example"
        iops = [{"op": "remove", "path": ["devices", i]} for i in range(len(have) - 1, -1, -1)] if replace else []
        keep = set() if replace else {str(x.get("ip")) for x in have}
        iops += [{"op": "insert", "path": ["devices"], "value": d} for d in devs if d["ip"] not in keep]
        cops = []
        mk = self.a.cfg.get("mikrotik") or {}
        for k in ("dhcp_source", "credentials"):
            v = str(router.get(k) or "").strip().rstrip("/") if k in router else None
            if v is not None and v != str(mk.get(k) or ""):
                cops.append({"op": "set", "path": ["mikrotik", k], "value": v})
        chat = str(tg.get("chat_id") or "").strip()
        if chat:
            if not re.fullmatch(r"-?\d{1,20}", chat):
                return self._j({"ok": False, "error": "a chat id is a number"}, 400)
            if chat != str((self.a.cfg.get("telegram") or {}).get("chat_id") or ""):
                cops.append({"op": "set", "path": ["telegram", "chat_id"], "value": chat})
        tz = str(body.get("timezone") or "").strip()
        if tz and valid_tz(tz) and not env_tz() and not str(self.a.cfg.get("timezone") or "").strip():
            cops.append({"op": "set", "path": ["timezone"], "value": tz})
        if body.get("preview"):
            sp = self.s.plan("secrets", sops, stext) if sops else None
            after = sp["text"] if sp and sp.get("ok") else None
            out = {"ok": True, "secrets": sp,
                   "inventory": self.s.plan("inventory", iops, itext, secrets_text=after) if iops else None,
                   "config": self.s.plan("config", cops, secrets_text=after) if cops else None}
            for k in ("secrets", "inventory", "config"):
                if out[k]:
                    out[k].pop("text", None)
                    out["ok"] = out["ok"] and out[k]["ok"]
            return self._j(out, 200 if out["ok"] else 409)
        bases = body.get("bases") or {}
        ip = request.remote or ""
        r = {"ok": True}
        for name, ops in (("secrets", sops), ("inventory", iops), ("config", cops)):
            if not ops:
                continue
            r[name] = self.s.save(name, ops, str(bases.get(name) or ""), ip, how="setup")
            r[name].pop("text", None)
            if not r[name]["ok"]:
                return self._j({"ok": False, **r[name], "done": [k for k in r if k not in ("ok", name)]}, 409)
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


# --- sites: sites.list in config.yaml (sites.py reads it at start) ----------------------------
HOME = "home"
SITE_ROUTERS = {"mikrotik": "routeros", "openwrt": "openwrt"}    # a device's kind -> its site's
SITE_KEYS = ("key", "name", "nets", "router", "kind", "criticality")


def _site_nets(s) -> list:
    out = []
    for n in (s.get("nets") or []) if isinstance(s, dict) else []:
        try:
            out.append(ipaddress.ip_network(str(n), strict=False))
        except ValueError:
            pass
    return out


def sites_view(raw_cfg: dict, raw_inv: dict) -> dict:
    """What Settings → Sites and a router's page show, from the files as they are now (a save
    waits for a restart): every site, the main one first even when the file does not name it,
    and the inventory's routers — which site each is the router of, if any."""
    from .model import main_lans, on_main_side, router_host
    raw_cfg = raw_cfg if isinstance(raw_cfg, dict) else {}
    lst = [s for s in ((raw_cfg.get("sites") or {}).get("list") or []) if isinstance(s, dict)]
    out = []
    for s in lst:
        k = str(s.get("key") or "")
        out.append({"key": k, "name": str(s.get("name") or k), "nets": [str(n) for n in s.get("nets") or []],
                    "router": str(s.get("router") or ""), "kind": str(s.get("kind") or ""),
                    "criticality": str(s.get("criticality") or ("low" if k == HOME else "info")),
                    "home": k == HOME, "in_file": True})
    if not any(x["home"] for x in out):
        out.insert(0, {"key": HOME, "name": "Home", "nets": [], "router": "", "kind": "", "criticality": "low",
                       "home": True, "in_file": False})
    out.sort(key=lambda x: not x["home"])
    home = next(x for x in out if x["home"])
    main = router_host(raw_cfg)
    routers = []
    for d in (raw_inv or {}).get("devices") or [] if isinstance(raw_inv, dict) else []:
        if isinstance(d, dict) and str(d.get("kind") or "") in SITE_ROUTERS:
            ip = str(d.get("ip") or "")
            routers.append({"ip": ip, "name": str(d.get("name") or ip), "group": str(d.get("group") or ""),
                            "kind": str(d.get("kind")), "login": bool(d.get("credentials")),
                            "main": ip == main, "main_side": on_main_side(raw_cfg, ip),
                            "site": next((x["key"] for x in out if x["router"] == ip), "")})
    # the main site's networks when the file names none: what main_lans falls back to
    return {"list": out, "routers": routers, "main_router": main,
            "home_default": [] if home["nets"] else [str(n) for n in main_lans(raw_cfg)]}


def _ipv4(s: str) -> bool:
    try:
        return _IP.match(s) is not None and ipaddress.ip_address(s).version == 4
    except ValueError:
        return False


def _site_key(name: str, taken: set) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28] or "site"
    if base == HOME:
        base = "home-2"
    k, i = base, 2
    while k in taken:
        k, i = f"{base}-{i}", i + 1
    return k


def site_list(raw_cfg: dict, raw_inv: dict, key, site) -> tuple:
    """(the new `sites.list`, error): the site `key` (None: a new one) set to `site`
    {name, nets, router, criticality}, or removed (`site` None). The main site ("home") is
    kept: its name and networks change, it has no router of its own (that is
    mikrotik.dhcp_source) and is never removed. A key never changes: lanowl's state names
    sites by it. The keys a file's entry has beyond the form's stay as they are."""
    from .model import router_host
    raw_cfg = raw_cfg if isinstance(raw_cfg, dict) else {}
    cur = [dict(s) for s in ((raw_cfg.get("sites") or {}).get("list") or []) if isinstance(s, dict)]
    idx = next((i for i, s in enumerate(cur) if str(s.get("key")) == key), None) if key else None
    home = key == HOME
    main = router_host(raw_cfg)
    if key and idx is None and not home:
        return None, f"there is no site {key} in config.yaml"
    if site is None:
        if home:
            return None, "the main site stays: change its name or its networks instead"
        return cur[:idx] + cur[idx + 1:], ""
    was = cur[idx] if idx is not None else {}
    others = [s for i, s in enumerate(cur) if i != idx]
    name = re.sub(r"\s+", " ", str(site.get("name") or "")).strip()
    if not name or len(name) > 40:
        return None, "Give the site a name, up to 40 characters"
    nets = []
    raw_nets = site.get("nets") or []
    if isinstance(raw_nets, str):
        raw_nets = re.split(r"[,\s]+", raw_nets)
    for n in raw_nets:
        n = str(n).strip()
        if not n:
            continue
        try:
            net = ipaddress.ip_network(n if "/" in n else n + "/32", strict=False)
        except ValueError:
            return None, f"{n} is not a network: write it like 192.168.0.0/24"
        if net.version != 4:
            return None, f"{n}: IPv4 networks only"
        if str(net) not in nets:
            nets.append(str(net))
    if not nets and not home:
        return None, "A site needs its network: the addresses on its side, like 192.168.0.0/24"
    for s in others:
        for n in _site_nets(s):
            if str(n) in nets:
                return None, f"{n} is {s.get('name') or s.get('key')}'s already"
    router = str(site.get("router") or "").strip()
    kind = ""
    if router and not _ipv4(router):
        return None, f"{router} is not an address: the router's, like 192.168.0.1"
    if router and home:
        return None, "the main site's router is the one lanowl reads the DHCP list from (mikrotik.dhcp_source)"
    if router and router == str(was.get("router") or "") and was.get("kind"):
        kind = str(was["kind"])            # as the file has it: written by hand, perhaps
    elif router:
        dev = next((d for d in (raw_inv or {}).get("devices") or []
                    if isinstance(d, dict) and str(d.get("ip")) == router), None)
        if dev is None:
            return None, (f"{router} is not in inventory.yaml: add it in Settings → Devices first, "
                          "as a mikrotik or an openwrt, with its login")
        kind = SITE_ROUTERS.get(str(dev.get("kind") or ""), "")
        if not kind:
            return None, (f"{dev.get('name') or router} is {'a ' + str(dev['kind']) if dev.get('kind') else 'a device with no kind'}: "
                          "lanowl reads a site's DHCP list from a mikrotik or an openwrt")
        if router == main:
            return None, f"{router} is the main router: its networks are the main site's"
        s = next((s for s in others if str(s.get("router") or "") == router), None)
        if s is not None:
            return None, f"{router} is {s.get('name') or s.get('key')}'s router already"
    if main and not home and _ipv4(main):
        n = next((n for n in nets if ipaddress.ip_address(main) in ipaddress.ip_network(n)), None)
        if n:
            return None, f"{n} holds the main router, {main}: those are the main site's addresses"
    if router and not any(ipaddress.ip_address(router) in ipaddress.ip_network(n) for n in nets):
        return None, f"{router} is not on {', '.join(nets)}: add the address lanowl reaches it at, {router}/32"
    crit = str(site.get("criticality") or ("low" if home else "info"))
    if crit not in CRITS:
        return None, f"criticality is one of {', '.join(CRITS)}"
    k = HOME if home else str(was.get("key") or "") or _site_key(name, {str(s.get("key")) for s in cur} | {HOME})
    entry = {"key": k, "name": name, **({"nets": nets} if nets else {}),
             **({"router": router, "kind": kind} if router else {}),
             **({"criticality": crit} if not home or crit != "low" else {})}
    entry.update({f: v for f, v in was.items() if f not in SITE_KEYS})
    if idx is not None:
        cur[idx] = entry
    elif home:
        cur.insert(0, entry)
    else:
        cur.append(entry)
    return cur, ""


def inv_groups(raw: dict) -> list:
    """Every group inventory.yaml knows: its `groups:` section, then each one a device uses (a
    group made on a device's page lives only there)."""
    raw = raw if isinstance(raw, dict) else {}
    named = list((raw.get("groups") or {}).keys()) if isinstance(raw.get("groups"), dict) else []
    used = [str(d.get("group")) for d in raw.get("devices") or [] if isinstance(d, dict) and d.get("group")]
    return list(dict.fromkeys(str(g) for g in named + used))


def login_op(name: str, body: dict, old) -> tuple:
    """(ops, error): a login set as the page sent it — {user, how: password | key, value}.
    A password left empty keeps the one the file has. With lanowl's key, a password the login
    already had (for sudo) is kept."""
    user = str(body.get("user") or "").strip()
    how = str(body.get("how") or "password")
    value = body.get("value")
    value = "" if value is None else str(value)
    old = old if isinstance(old, dict) else {}
    if not user or len(user) > 128 or any(c in user for c in "\r\n\x00"):
        return None, "type the user lanowl logs in as"
    if len(value) > SECRET_MAX or "\x00" in value:
        return None, "that password is too long"
    if how == "key":
        new = {"user": user, "key": old.get("key") if isinstance(old.get("key"), str) and old.get("key") else True}
        pw = value or (str(old.get("password")) if old.get("key") and old.get("password") else "")
        if pw:
            new["password"] = pw
    elif how == "password":
        pw = value or str(old.get("password") or "")
        if not pw:
            return None, "type its password"
        new = {"user": user, "password": pw}
    else:
        return None, "a login is a password or lanowl's key"
    if new == old:
        return None, "nothing to save: type a new password, or change the user"
    return [{"op": "set", "path": ["logins", name], "value": new}], ""


def login_users(cfg: dict, inv, raw: dict) -> dict:
    """login name -> what names it: devices (by name), the `devices:` map, the router, MQTT."""
    used: dict = {}
    for dev in (inv.devices if inv is not None else []):
        n = str(dev.attrs.get("credentials") or "")
        if n:
            used.setdefault(n, []).append(dev.name)
    for ip, n in ((raw or {}).get("devices") or {}).items() if isinstance((raw or {}).get("devices"), dict) else ():
        used.setdefault(str(n), []).append(str(ip))
    if (cfg.get("mikrotik") or {}).get("dhcp_source"):
        used.setdefault(access.service_login_name(cfg, "mikrotik"), []).append("the router's read-only user")
    if (cfg.get("mqtt") or {}).get("host"):
        used.setdefault(access.service_login_name(cfg, "mqtt"), []).append("the MQTT broker")
    return used


def public_key(cfg: dict) -> str:
    key = access.ssh_key(cfg)
    return access._public_key(key) if key and os.path.exists(key) else ""


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
               "key" if lg.key else "password", "how": "key" if lg.key else "password", "user": lg.user,
               "used_by": used.get(n, [])} for n, lg in sorted(d["logins"].items())]
    missing = [{"name": n, "set": False, "used_by": u} for n, u in sorted(used.items()) if n not in d["logins"]]
    tokens = []
    for name, need in (("telegram", (cfg.get("telegram") or {}).get("chat_id")),
                       ("homeassistant", (cfg.get("access") or {}).get("ha_url"))):
        _, where = access.token_from(cfg, name)
        tokens.append({"name": name, "set": bool(where), "where": where, "needed": bool(need)})
    key = access.ssh_key(cfg)
    return {"path": f.path, "error": f.error, "exists": os.path.exists(f.path), "logins": logins + missing,
            "tokens": tokens, "ssh_key": {"path": key, "exists": bool(key) and os.path.exists(key),
                                          "public": public_key(cfg)}}
