"""Settings on the dashboard (settings.py, settingsweb.py, login.py): `python -m tests.test_settings`.

No network, no Telegram — the sender is a fake, the files are in a temporary folder.
Pinned down here:

  1. a save writes the file in place (the same inode: a single-file mount allows nothing
     else), keeps the old text as a version, records who and what, tells Telegram in one line,
     and is "not running yet" until a restart; undo puts it back the same way;
  2. what stops a save: a file changed since the page read it, a value the environment sets,
     a read-only file, a file replaced on the host, a ✗ that --check did not give before;
     the password's hash never shows, in the diff or on Telegram;
  3. the login: its lock survives a restart; a logged-in browser saves with nothing asked
     again; the setup code is made once, kept, and opens the first password, which goes
     into config.yaml;
  4. the routes: the forms and their sources, a save, a device
     added from the form, the first password from the setup code, Restart to apply.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import login as L
from lanowl import settings as ST
from lanowl.model import load_config, load_inventory
from lanowl.state import StateStore
from lanowl.yamledit import load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "correct horse"
_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _files(d, password=True):
    """The example files, as a new user has them (no router login to make a ✗ of its own)."""
    cfg = open(os.path.join(ROOT, "config.example.yaml"), encoding="utf-8").read()
    cfg = cfg.replace('db_path: "lanowl_state.sqlite"', f'db_path: "{os.path.join(d, "s.sqlite")}"')
    if password:
        cfg = cfg.replace('password_hash: ""', f'password_hash: "{L.hash_password(PW)}"')
    open(os.path.join(d, "config.yaml"), "w").write(cfg)
    shutil.copy(os.path.join(ROOT, "inventory.example.yaml"), os.path.join(d, "inventory.yaml"))
    sec = open(os.path.join(ROOT, "secrets.example.yaml"), encoding="utf-8").read()
    sec = sec.replace("ssh_key: /config/id_ed25519", "ssh_key: ''")
    open(os.path.join(d, "secrets.yaml"), "w").write(sec)
    os.chmod(os.path.join(d, "secrets.yaml"), 0o600)


class _Kinds:
    profiles: dict = {}


class _A:
    def __init__(self, d):
        self.cfg = load_config(os.path.join(d, "config.yaml"))
        self.inv = load_inventory(os.path.join(d, "inventory.yaml"))
        self.state = StateStore(self.cfg["state"]["db_path"])
        self.told = []
        self.kinds = _Kinds()
        self.sites = None
        self.restarts = []
        self.probed = []
        self._started = time.time()
        self.settings = ST.Settings(self, self.cfg["_path"], self.inv.path)

    def _emit_telegram(self, channel, text, **kw):
        self.told.append(text)

    def restart_blockers(self):
        return []

    def request_restart(self, by):
        self.restarts.append(by)
        return {"ok": True}

    async def probe_now(self, ip):
        self.probed.append(ip)


def _base(a, name):
    return ST.digest(a.settings.files[name].read())


def test_save_and_undo():
    print("\n-- a save: in place, kept, said; undo puts it back --")
    with tempfile.TemporaryDirectory() as d:
        _files(d)
        a = _A(d)
        s = a.settings
        path = s.files["config"].path
        orig = open(path).read()
        ino = os.stat(path).st_ino
        ops = [{"op": "set", "path": ["model", "name"], "value": "qwen3:32b"},
               {"op": "del", "path": ["model", "keep_alive"]}]
        p = s.plan("config", ops)
        check(p["ok"] and p["changes"] == ["model.name qwen3:30b → qwen3:32b", "model.keep_alive 10m → default"]
              and not p["problems"] and any('+  name: "qwen3:32b"' in ln for ln in p["diff"]),
              "the plan: the diff, the changes in words, no new ✗")
        stale = s.save("config", ops, "0" * 16, "192.168.88.47")
        check(not stale["ok"] and stale["why"] == "changed" and open(path).read() == orig,
              "planned on another version of the file: nothing written")
        r = s.save("config", ops, _base(a, "config"), "192.168.88.47")
        new = open(path).read()
        check(r["ok"] and 'name: "qwen3:32b"' in new and "keep_alive" not in new.split("telegram:")[0],
              "saved")
        check(os.stat(path).st_ino == ino, "in place: the same file, not a new one renamed over it")
        vers = os.listdir(s.dir)
        check(len(vers) == 1 and open(os.path.join(s.dir, vers[0])).read() == orig
              and stat.S_IMODE(os.stat(os.path.join(s.dir, vers[0])).st_mode) == 0o600,
              "the file as it was is kept, readable by lanowl only")
        check(len(a.told) == 1 and "config.yaml changed" in a.told[0] and "192.168.88.47" in a.told[0]
              and "model.name qwen3:30b → qwen3:32b" in a.told[0], "Telegram: one line, what and from where")
        check("config" in s.pending() and s.history()[0]["changes"] == r["changes"], "not running yet; in the history")
        rp = s.restore_plan(r["id"])
        check(rp["ok"] and any('-  name: "qwen3:32b"' in ln for ln in rp["diff"]), "undo shows its diff first")
        back = s.restore(r["id"], _base(a, "config"), "192.168.88.47")
        check(back["ok"] and open(path).read() == orig and "put back" in a.told[-1], "undo: the file as it was, said too")
        check(s.pending() == {}, "...and nothing waits for a restart any more")
        ST.Settings(a, path, a.inv.path)          # a restart reads the history back
        check(len(ST.Settings(a, path, a.inv.path).history()) == 2, "the history survives a restart")


def test_guards():
    print("\n-- what stops a save --")
    with tempfile.TemporaryDirectory() as d:
        _files(d)
        a = _A(d)
        s = a.settings
        os.environ["LANOWL_MODEL_URL"] = "http://198.51.100.9:11434"
        try:
            p = s.plan("config", [{"op": "set", "path": ["model", "url"], "value": "http://x"}])
        finally:
            del os.environ["LANOWL_MODEL_URL"]
        check(not p["ok"] and "LANOWL_MODEL_URL" in p["error"], "a value the environment sets: change it there")
        p = s.plan("config", [{"op": "set", "path": ["mikrotik", "credentials"], "value": "nobody"}])
        check(p["ok"] and p["problems"] and any("nobody" in x for x in p["problems"]),
              "a new ✗ from --check is named")
        r = s.save("config", [{"op": "set", "path": ["mikrotik", "credentials"], "value": "nobody"}],
                   _base(a, "config"))
        check(not r["ok"] and r["why"] == "check" and "nobody" in r["error"], "...and stops the save")
        p = s.plan("config", [{"op": "set", "path": ["web", "password_hash"], "value": L.hash_password("other one")}])
        check(all("scrypt$" not in ln for ln in p["diff"]) and any("(hidden)" in ln for ln in p["diff"])
              and p["changes"] == ["web.password_hash changed"], "the password's hash never shows")
        if os.geteuid() != 0:
            s.files["config"].writable_at_start = False          # mounted read-only from the start
            os.chmod(s.files["config"].path, 0o444)
            r = s.save("config", [{"op": "set", "path": ["model", "think"], "value": False}], _base(a, "config"))
            os.chmod(s.files["config"].path, 0o644)
            check(not r["ok"] and r["why"] == "readonly" and "read-write" in r["error"], "a read-only file: said how to fix")
        real = ST.os.stat

        class _St:
            def __init__(self, st):
                self.st_nlink, self.st_mode, self.st_ino = 0, st.st_mode, st.st_ino
        ST.os.stat = lambda p, *a_, **k: _St(real(p, *a_, **k))
        try:
            st = s.files["config"].status()
        finally:
            ST.os.stat = real
        check(st["why"] == "replaced" and "restart the container" in ST.WHY["replaced"],
              "a file replaced on the host (no name left): restart the container first")
        if os.geteuid() != 0:
            f = s.files["config"]
            f.writable_at_start = True
            os.chmod(f.path, 0o444)
            st2 = f.status()
            os.chmod(f.path, 0o644)
            check(st2["why"] == "replaced", "writable at start and read-only now: replaced (its mount dropped)")
            f.writable_at_start = False
            os.chmod(f.path, 0o444)
            st3 = f.status()
            os.chmod(f.path, 0o644)
            check(st3["why"] == "readonly", "read-only from the start: the compose file's mount")


def test_login():
    print("\n-- the login: a lock that survives, the password again, the setup code --")
    with tempfile.TemporaryDirectory() as d:
        _files(d)
        a = _A(d)
        lg = L.Login(a)
        for _ in range(5):
            lg.attempt(False, "192.168.88.66")
        check(bool(L.Login(a).locked()), "five wrong: locked, and a restart does not lift it")
        lg._locked_until, lg._fails = 0.0, []
        lg._save()
        tok = lg.attempt(True)["token"]
        check(lg.check(tok) and lg.check(tok, time.time() + 3600), "logged in: it stays in, nothing asks again")
    with tempfile.TemporaryDirectory() as d:
        _files(d, password=False)
        a = _A(d)
        lg = L.Login(a)
        code = lg.ensure_code()
        check(len(code) == 8 and set(code) <= set(L._CODE_CHARS) and L.Login(a).setup_code == code
              and L.setup_code(a.cfg) == code, "the setup code: made once, kept, read by --setup-code")
        check(lg.code_ok("AAAA-AAAA")["why"] == "wrong" and lg.code_ok(code[:4].lower() + "-" + code[4:])["ok"],
              "wrong: refused; the right one however it is typed")
        tok = lg.set_from_page(L.hash_password(PW), in_config=True, keep_in=True)
        check(tok and lg.check(tok) and not lg.setup_code and L.verify(PW, lg.hash) and not lg.needed,
              "it opens the first password, and this browser is in")
        check(L.setup_code({**a.cfg, "web": {**a.cfg["web"], "password_hash": lg.hash}}) == "",
              "with a password there is no setup code")


def test_routes():
    print("\n-- the routes --")
    out = {}

    async def go(d, password):
        from aiohttp import ClientSession, CookieJar, web
        import lanowl.web as W
        from lanowl.settingsweb import SettingsRoutes
        a = _A(d)
        a.login = L.Login(a)
        if not password:
            a.login.ensure_code()
        dash = W.Dashboard.__new__(W.Dashboard)
        dash.a, dash.login, dash.allowed_hosts, dash._login_lock = a, a.login, set(), asyncio.Lock()

        @web.middleware
        async def guard(request, handler):
            return await dash._guard(request, handler)
        app = web.Application(middlewares=[guard])
        app.router.add_post("/api/login", dash.api_login)
        SettingsRoutes(dash).routes(app)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        try:
            async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
                if password:
                    await s.post(base + "/api/login", json={"password": PW})
                    async with s.get(base + "/api/settings") as r:
                        out["get"] = (r.status, await r.json())
                    body = {"file": "config", "ops": [{"op": "set", "path": ["model", "think"], "value": False}],
                            "base": _base(a, "config")}
                    async with s.post(base + "/api/settings/save", json=body) as r:
                        out["saved"] = (r.status, await r.json())
                    dev = {"ip": "192.168.88.44", "name": "ESP 3A1F2C", "group": "iot", "criticality": "low",
                           "checks": [{"type": "icmp"}]}
                    async with s.post(base + "/api/settings/device", json={"ip": None, "device": dev, "preview": True}) as r:
                        out["dev_plan"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/device",
                                      json={"ip": None, "device": dev, "base": _base(a, "inventory")}) as r:
                        out["dev_save"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/device",
                                      json={"ip": None, "device": {**dev, "kind": "shelly", "manage": ["logs"]},
                                            "preview": True}) as r:
                        out["dev_bad"] = (r.status, await r.json())
                    wdev = {**dev, "ip": "192.168.88.45", "name": "Kettle"}
                    async with s.post(base + "/api/settings/device",
                                      json={"ip": None, "device": wdev, "how": "watch", "base": _base(a, "inventory")}) as r:
                        out["watch"] = (r.status, list(a.probed), a.inv.get("192.168.88.45") is not None)
                    async with s.post(base + "/api/setup/claim", json={"code": "x", "password": PW}) as r:
                        out["claim_taken"] = r.status
                    async with s.post(base + "/api/setup/router",
                                      json={"dhcp_source": "http://198.51.100.1", "credentials": "nobody"}) as r:
                        out["router_missing"] = (r.status, await r.json())
                    # devices Watch kept in lanowl's state, before it wrote inventory.yaml
                    from lanowl.model import Device

                    class _Sites:
                        rec = {"watch": {"192.168.88.71": {"site": "home", "mac": "aa:bb:cc:dd:ee:ff", "name": "Kettle",
                                                           "ts": 1.0},
                                         "10.8.0.33": {"site": "office", "mac": "aa:bb:cc:dd:ee:01", "name": "Printer",
                                                       "ts": 1.0}}}
                        saved = 0

                        def _save(self):
                            self.saved += 1
                    a.sites = _Sites()
                    a.inv.add(Device(ip="192.168.88.71", name="Kitchen kettle", group="watched", criticality="low",
                                     checks=[{"type": "icmp"}], attrs={"mac": "aa:bb:cc:dd:ee:ff", "watched": True}))
                    a.inv.add(Device(ip="10.8.0.33", name="Printer", group="remote", criticality="info",
                                     checks=[{"type": "icmp"}], attrs={"mac": "aa:bb:cc:dd:ee:01", "site": "office",
                                                                       "depends_on": "10.8.0.9", "watched": True}))
                    async with s.post(base + "/api/settings/migrate", json={"preview": True}) as r:
                        out["mig_plan"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/migrate", json={"base": _base(a, "inventory")}) as r:
                        out["mig"] = (r.status, await r.json(), dict(a.sites.rec["watch"]), a.sites.saved)
                    async with s.post(base + "/api/restart", json={}) as r:
                        out["restart"] = (r.status, list(a.restarts))
                    out["inv"] = open(a.settings.files["inventory"].path).read()
                    out["inv_after_mig"] = out["inv"]
                else:
                    async with s.get(base + "/api/settings") as r:
                        out["closed"] = r.status
                    async with s.post(base + "/api/setup/claim", json={"code": "WRONG123", "password": PW}) as r:
                        out["claim_wrong"] = (r.status, await r.json())
                    async with s.post(base + "/api/setup/claim",
                                      json={"code": a.login.setup_code, "password": PW}) as r:
                        out["claim"] = (r.status, await r.json(), r.headers.get("Set-Cookie", ""))
                    async with s.get(base + "/api/settings") as r:
                        out["after"] = r.status
                    out["cfg"] = open(a.settings.files["config"].path).read()
                    out["told"] = list(a.told)
        finally:
            await runner.cleanup()

    with tempfile.TemporaryDirectory() as d:
        _files(d)
        asyncio.run(go(d, True))
    with tempfile.TemporaryDirectory() as d:
        _files(d, password=False)
        asyncio.run(go(d, False))
    st, body = out["get"]
    model = next(x for x in body["sections"] if x["key"] == "model")
    name = next(f for f in model["fields"] if f.get("path") == ["model", "name"])
    pwf = next(f for x in body["sections"] for f in x["fields"] if f.get("path") == ["web", "password_hash"])
    check(st == 200 and name["source"] == "file" and name["value"] == "qwen3:30b" and name["help"]
          and body["files"]["config"]["writable"], "the forms: a value, where it comes from, the example's help")
    check(pwf["value"] is True and "scrypt" not in str(body), "the password: set, never its hash")
    check(out["saved"][0] == 200 and out["saved"][1]["ok"], "a logged-in browser saves: no password asked again")
    check(out["dev_plan"][0] == 200 and any("192.168.88.44" in ln for ln in out["dev_plan"][1]["diff"]),
          "a device from the form: its diff")
    check(out["dev_save"][0] == 200 and "ip: 192.168.88.44" in out["inv"] and 'name: "ESP 3A1F2C"' in out["inv"],
          "...written into inventory.yaml")
    check(out["dev_bad"][0] == 400 and "cannot logs" in out["dev_bad"][1]["error"], "only what its kind can do")
    check(out["watch"] == (200, ["192.168.88.45"], True), "Watch: written, watched, and probed at once (on the page now)")
    from lanowl.settingsweb import inv_groups
    check(inv_groups({"groups": {"network": {}}, "devices": [{"ip": "1", "group": "office"}, {"ip": "2", "group": "network"}]})
          == ["network", "office"], "the groups offered: the groups: section, then one made on a device's page")
    check(out["claim_taken"] == 409, "with a password, the setup code opens nothing")
    rm = out["router_missing"][1]
    check(rm["login"] is False and "secrets.yaml" in rm["path"] and "type the router user's name and password" in rm["error"],
          "Try the router with no login typed and none in secrets.yaml: asks for the user and the password")
    check(out["mig_plan"][0] == 200 and len(out["mig_plan"][1]["changes"]) == 2, "the devices kept in the state: their diff")
    inv = load(out["inv_after_mig"])
    kettle = next(d for d in inv["devices"] if d["ip"] == "192.168.88.71")
    printer = next(d for d in inv["devices"] if d["ip"] == "10.8.0.33")
    check(out["mig"][0] == 200 and out["mig"][2] == {} and out["mig"][3] == 1
          and kettle["name"] == "Kitchen kettle" and kettle["mac"] == "AA:BB:CC:DD:EE:FF"
          and printer["site"] == "office" and printer["depends_on"] == "10.8.0.9" and printer["debounce_fails"] == 5,
          "...moved into inventory.yaml (the name the owner gave it, the remote one with its site), out of the state")
    check(out["restart"] == (200, ["127.0.0.1"]), "Restart to apply asks lanowl to restart")
    check(out["closed"] == 401, "a new install: Settings closed")
    check(out["claim_wrong"][0] == 403 and out["claim_wrong"][1]["why"] == "wrong", "a wrong setup code: refused")
    check(out["claim"][0] == 200 and "lanowl_session=" in out["claim"][2] and out["after"] == 200,
          "the right one with a password: logged in")
    check('password_hash: "scrypt$' in out["cfg"] and any("first-run setup" in t for t in out["told"])
          and all("scrypt" not in t for t in out["told"]), "the hash in config.yaml; Telegram told, without it")


SECRET = 'h"un:ter, 2}#2'          # quotes, a colon, a comma, a brace, a hash: YAML's worst


def test_secrets():
    print("\n-- secrets.yaml: write-only --")
    with tempfile.TemporaryDirectory() as d:
        _files(d)
        a = _A(d)
        s = a.settings
        from lanowl import access
        from lanowl.settingsweb import login_op
        path = s.files["secrets"].path
        ino = os.stat(path).st_ino
        ops, err = login_op("router-read", {"user": "lanowl", "how": "password", "value": SECRET},
                            (load(open(path).read()) or {})["logins"].get("router-read"))
        p = s.plan("secrets", ops)
        shown = repr(p["diff"]) + repr(p["changes"])
        check(p["ok"] and SECRET not in shown and "change-me" not in shown and any("(new)" in ln for ln in p["diff"])
              and p["changes"] == ["login router-read: password replaced"], "the plan: dots, \"(new)\", no value")
        r = s.save("secrets", ops, _base(a, "secrets"), "192.168.88.47")
        check(r["ok"] and access.shared(a.cfg).data()["logins"]["router-read"].password == SECRET,
              "saved, and in use at once: no restart")
        check(os.stat(path).st_ino == ino and stat.S_IMODE(os.stat(path).st_mode) == 0o600, "in place, still mode 600")
        check(len(a.told) == 1 and a.told[0].startswith("🔑") and "router-read" in a.told[0]
              and SECRET not in a.told[0], "Telegram: the login named, never the value")
        check("secrets" not in s.pending() and SECRET not in repr(s.history()), "nothing waits for a restart; no value in the history")
        vers = [v for v in os.listdir(s.dir) if v.startswith("secrets-")]
        check(len(vers) == 1 and stat.S_IMODE(os.stat(os.path.join(s.dir, vers[0])).st_mode) == 0o600,
              "the file as it was is kept, mode 600")
        rp = s.restore_plan(r["id"])
        check(rp["ok"] and SECRET not in repr(rp["diff"]) and rp["changes"] == ["login router-read: password replaced"],
              "undo shows dots too")
        o, e = login_op("router-read", {"user": "lanowl", "how": "password", "value": ""}, {"user": "lanowl", "password": SECRET})
        check(o is None and "nothing to save" in e, "the same user and no new password: nothing to save")
        o, e = login_op("router-read", {"user": "other", "how": "password", "value": ""}, {"user": "lanowl", "password": SECRET})
        check(o[0]["value"] == {"user": "other", "password": SECRET}, "a new user, the password left empty: the one there is kept")
        o, e = login_op("nas", {"user": "admin", "how": "key"}, {"user": "admin", "key": True, "password": "sudo-pw"})
        check(o is None, "lanowl's key with its sudo password, unchanged: nothing to save")
        o, e = login_op("srv", {"user": "root", "how": "key"}, None)
        check(o[0]["value"] == {"user": "root", "key": True}, "lanowl's key: no password asked")
        # a device that names a login the same save adds: --check reads them together
        dev_ops = [{"op": "insert", "path": ["devices"], "value": {"ip": "192.168.88.60", "name": "TV", "kind": "linux",
                                                                    "credentials": "tv", "checks": [{"type": "icmp"}]}}]
        alone = s.plan("inventory", dev_ops)
        sp = s.plan("secrets", login_op("tv", {"user": "root", "how": "key"}, None)[0])
        together = s.plan("inventory", dev_ops, secrets_text=sp["text"])
        check(any("'tv'" in x for x in alone["problems"]) and not together["problems"],
              "a device naming a new login: a ✗ alone, none with the login written first")

    print("\n-- masking: whatever the layout, no value comes out --")
    lay = ('logins:\n  a: {user: x, password: "p,1}2"}\n  b:\n    user: y\n    password: |\n      long secret one\n'
           '  c: {user: z, password: plainPW123}   # was plainPW123\n'
           'tokens: {telegram: "123:ABCSECRETTOKEN", homeassistant: hatok123}\n')
    m = ST.mask(lay)
    check(all(v not in m for v in ("p,1}2", "long secret one", "plainPW123", "123:ABCSECRETTOKEN", "hatok123")),
          "flow maps, block scalars, a value in a comment, tokens on one line")


def test_setup_and_secret_routes():
    print("\n-- the routes: Secrets, the setup with logins, Telegram from /start --")
    out = {}
    tg_calls = []

    async def fake_tg(self, token, method, params=None, timeout=15):
        tg_calls.append((method, dict(params or {})))
        if token.endswith("BAD" * 7):
            return {"ok": False, "error_code": 401, "description": "Unauthorized"}
        if method == "getMe":
            return {"ok": True, "result": {"username": "house_owl_bot", "first_name": "House owl"}}
        if method == "getUpdates":
            return {"ok": True, "result": [{"update_id": 41, "message": {"text": "/start", "date": 1,
                    "chat": {"id": 100000001, "type": "private", "first_name": "Alex"}}}]}
        if method == "sendMessage":
            return {"ok": True, "result": {}}
        return {"ok": False, "description": "?"}

    class _Rest:
        def __init__(self, ok, data=None, detail=""):
            self.ok, self.data, self.detail = ok, data or {}, detail

    async def fake_mk(src, path, user, password, verify, timeout):
        out.setdefault("mk", []).append((path, user, password == SECRET))
        if password != SECRET:
            return _Rest(False, detail="mikrotik http 401")
        if path == "system/resource":
            return _Rest(True, {"json": {"version": "7.16", "board-name": "hAP"}})
        if path == "ip/arp":                 # a switch with a fixed address; a leased one; elsewhere; gone
            return _Rest(True, {"json": [{"address": "192.168.88.20", "mac-address": "aa:bb:cc:00:11:22", "status": "reachable"},
                                         {"address": "192.168.88.31", "mac-address": "00:0C:42:AA:BB:31", "status": "reachable"},
                                         {"address": "10.9.9.9", "mac-address": "00:0C:42:AA:BB:39", "status": "reachable"},
                                         {"address": "192.168.88.32", "mac-address": "00:0C:42:AA:BB:32", "status": "failed"}]})
        return _Rest(True, {"json": [{"address": "192.168.88.20", "mac-address": "aa:bb:cc:00:11:22", "host-name": "nvr",
                                      "dynamic": "false", "status": "bound"}]})

    async def go(d):
        from aiohttp import ClientSession, CookieJar, web
        import lanowl.web as W
        from lanowl import probes
        from lanowl.settingsweb import SettingsRoutes
        SettingsRoutes._tg = fake_tg
        probes.mikrotik_rest = fake_mk
        a = _A(d)
        a.login = L.Login(a)
        dash = W.Dashboard.__new__(W.Dashboard)
        dash.a, dash.login, dash.allowed_hosts, dash._login_lock = a, a.login, set(), asyncio.Lock()

        @web.middleware
        async def guard(request, handler):
            return await dash._guard(request, handler)
        app = web.Application(middlewares=[guard])
        app.router.add_post("/api/login", dash.api_login)
        SettingsRoutes(dash).routes(app)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        tok = "123456:" + "A" * 35
        try:
            async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
                await s.post(base + "/api/login", json={"password": PW})
                async with s.get(base + "/api/settings") as r:
                    out["get"] = await r.text()
                sec = {"op": "login", "name": "routers", "user": "admin", "how": "password", "value": SECRET}
                async with s.post(base + "/api/settings/secret", json={**sec, "preview": True}) as r:
                    out["sec_plan"] = (r.status, await r.text())
                async with s.post(base + "/api/settings/secret", json={**sec, "base": _base(a, "secrets")}) as r:
                    out["sec_saved"] = (r.status, await r.text())
                async with s.post(base + "/api/settings/secret",
                                  json={"op": "remove", "name": "routers", "base": _base(a, "secrets")}) as r:
                    out["sec_rm_used"] = (r.status, await r.json())
                async with s.post(base + "/api/settings/secret",
                                  json={"op": "token", "name": "telegram", "value": "nope"}) as r:
                    out["sec_badtok"] = (r.status, await r.json())
                # the setup: the router as typed
                rb = {"dhcp_source": "http://192.168.88.1", "credentials": "router-read", "user": "lanowl"}
                async with s.post(base + "/api/setup/router", json={**rb, "password": "wrong"}) as r:
                    out["r_wrong"] = await r.json()
                await asyncio.sleep(3.1)                       # one try every three seconds
                async with s.post(base + "/api/setup/router", json={**rb, "password": SECRET}) as r:
                    out["r_ok"] = (r.status, await r.text())
                async with s.post(base + "/api/setup/leases", json={**rb, "password": SECRET}) as r:
                    out["leases"] = await r.json()
                # Telegram: the token, then /start, then one line to the chat
                async with s.post(base + "/api/setup/telegram", json={"token": "12:x"}) as r:
                    out["tg_shape"] = (r.status, await r.json())
                async with s.post(base + "/api/setup/telegram", json={"token": "123456:" + "BAD" * 7}) as r:
                    out["tg_bad"] = await r.json()
                async with s.post(base + "/api/setup/telegram", json={"token": tok}) as r:
                    out["tg_me"] = await r.json()
                async with s.post(base + "/api/setup/telegram/chats", json={"token": tok, "offset": 0}) as r:
                    out["tg_chats"] = await r.json()
                async with s.post(base + "/api/setup/telegram/hello", json={"token": tok, "chat_id": "100000001"}) as r:
                    out["tg_hello"] = await r.json()
                # the setup's write: the router's login, a new login on a device, the token, the chat, the zone
                body = {"devices": [{"ip": "192.168.88.20", "name": "NVR", "group": "cameras", "criticality": "high",
                                     "kind": "linux", "credentials": "cams", "checks": [{"type": "icmp"}]}],
                        "router": {**rb, "password": SECRET},
                        "logins": {"cams": {"user": "root", "how": "key"}, "unused": {"user": "x", "how": "password",
                                                                                     "password": "zzz"}},
                        "telegram": {"token": tok, "chat_id": "100000001"}, "timezone": "Europe/Berlin"}
                async with s.post(base + "/api/setup/write", json={**body, "preview": True}) as r:
                    out["w_plan"] = (r.status, await r.text())
                pj = json.loads(out["w_plan"][1])
                bases = {k: (pj.get(k) or {}).get("base") for k in ("secrets", "inventory", "config")}
                told = len(a.told)
                async with s.post(base + "/api/setup/write", json={**body, "bases": bases}) as r:
                    out["w"] = (r.status, await r.text())
                out["files"] = {k: open(a.settings.files[k].path).read() for k in ("secrets", "inventory", "config")}
                out["told"] = a.told[told:]
                # a device added with its own login, typed on its page
                dv = {"ip": "192.168.88.61", "name": "Office NAS", "group": "servers", "criticality": "high",
                      "kind": "linux", "checks": [{"type": "icmp"}]}
                lg = {"name": "office-nas", "user": "admin", "how": "password", "password": SECRET}
                async with s.post(base + "/api/settings/device", json={"ip": None, "device": dv, "login": lg, "preview": True}) as r:
                    out["dl_plan"] = (r.status, await r.text())
                dp = json.loads(out["dl_plan"][1])
                async with s.post(base + "/api/settings/device", json={"ip": None, "device": dv, "login": lg,
                                                                       "base": dp.get("base"), "sbase": (dp.get("secrets") or {}).get("base")}) as r:
                    out["dl_saved"] = (r.status, await r.text())
                out["dl_files"] = (open(a.settings.files["inventory"].path).read(), open(a.settings.files["secrets"].path).read())
        finally:
            await runner.cleanup()

    import json
    with tempfile.TemporaryDirectory() as d:
        _files(d)
        cfg = open(os.path.join(d, "config.yaml")).read().replace('timezone: "Europe/Berlin"', 'timezone: ""')
        open(os.path.join(d, "config.yaml"), "w").write(cfg)
        saved_tz = {k: os.environ.pop(k, None) for k in ("TZ", "LANOWL_TZ_FROM")}
        try:
            asyncio.run(go(d))
        finally:
            for k, v in saved_tz.items():
                if v is not None:
                    os.environ[k] = v
    check(SECRET not in out["get"] and '"user": "lanowl"' in out["get"], "Settings: the logins' users, never a value")
    check(out["sec_plan"][0] == 200 and SECRET not in out["sec_plan"][1] and "(new)" in out["sec_plan"][1],
          "a Secrets save, planned: dots")
    check(out["sec_saved"][0] == 200 and SECRET not in out["sec_saved"][1], "a Secrets save from a logged-in browser: saved; the answer has no value")
    rm = out["sec_rm_used"]
    check(rm[0] == 400 and "Router" in rm[1]["error"] and "another login" in rm[1]["error"],
          "a login a device uses: not removed, and says which")
    check(out["sec_badtok"][0] == 400 and "@BotFather" not in out["sec_badtok"][1]["error"], "a token that is not one: refused")
    dlp = json.loads(out["dl_plan"][1])
    check(out["dl_plan"][0] == 200 and SECRET not in out["dl_plan"][1] and dlp["secrets"]["changes"] == ["login office-nas added (admin, a password)"]
          and any("credentials: office-nas" in ln for ln in dlp["diff"]) and not dlp["problems"],
          "a device with its own login: two diffs (inventory.yaml naming it, secrets.yaml adding it), no value")
    inv_t, sec_t = out["dl_files"]
    devn = next(x for x in load(inv_t)["devices"] if x["ip"] == "192.168.88.61")
    check(out["dl_saved"][0] == 200 and SECRET not in out["dl_saved"][1] and devn.get("credentials") == "office-nas"
          and load(sec_t)["logins"]["office-nas"] == {"user": "admin", "password": SECRET}, "...saved: the device and its login")
    check(out["r_wrong"]["login"] is True and "check the user and the password" in out["r_wrong"]["error"],
          "the router refuses a typed login: says so, about what was typed")
    check(out["r_ok"][0] == 200 and '"ok": true' in out["r_ok"][1] and SECRET not in out["r_ok"][1]
          and any(m[0] == "ip/dhcp-server/lease" and m[2] for m in out["mk"]), "the typed login works: tried, not written")
    check(out["leases"]["ok"] and out["leases"]["rows"][0]["ip"] == "192.168.88.20", "its DHCP list, with the typed login")
    lr = {x["ip"]: x for x in out["leases"]["rows"]}
    check(sorted(lr) == ["192.168.88.20", "192.168.88.31"] and lr["192.168.88.31"].get("fixed") and lr["192.168.88.31"]["here"]
          and out["leases"]["fixed"] == 1 and not lr["192.168.88.20"].get("fixed"),
          "...and the fixed addresses in its ARP table on the main network: not a leased one, not another network's, not a gone one")
    check(lr["192.168.88.20"]["watched"] and not lr["192.168.88.31"]["watched"], "a device inventory.yaml has is marked watched")
    check(out["tg_shape"][0] == 400 and "tg_shape" and not any(c[0] == "getMe" and False for c in tg_calls),
          "a token of the wrong shape never reaches Telegram")
    check(out["tg_bad"]["ok"] is False and out["tg_bad"]["error"] == "Telegram answered: Unauthorized",
          "a wrong token: Telegram's own word for it")
    check(out["tg_me"] == {"ok": True, "user": "house_owl_bot", "name": "House owl", "mine": False}, "the bot's name")
    ch = out["tg_chats"]
    check(ch["ok"] and ch["offset"] == 42 and ch["chats"][0]["id"] == "100000001" and ch["chats"][0]["name"] == "Alex",
          "/start: the chat that wrote, and where to go on from")
    check(out["tg_hello"]["ok"] and any(c[0] == "sendMessage" and c[1]["chat_id"] == "100000001" for c in tg_calls),
          "one line to that chat")
    wp = out["w_plan"]
    check(wp[0] == 200 and SECRET not in wp[1] and "zzz" not in wp[1] and "AAAAAAAAAA" not in wp[1],
          "the setup's write, planned: three diffs, no value in them")
    pj = json.loads(wp[1])
    check(pj["secrets"]["changes"] == ["login router-read: password replaced", "login cams added (root, lanowl's key)",
                                       "token telegram set"] and not pj["inventory"]["problems"] and not pj["config"]["problems"],
          "secrets.yaml: the router's login, the new one a device uses (not the unused one), the token; nothing for --check")
    f = out["files"]
    sec = load(f["secrets"])
    check(out["w"][0] == 200 and sec["logins"]["router-read"] == {"user": "lanowl", "password": SECRET}
          and sec["logins"]["cams"] == {"user": "root", "key": True} and "unused" not in sec["logins"]
          and sec["tokens"]["telegram"] == "123456:" + "A" * 35, "written: secrets.yaml")
    cfgw = load(f["config"])
    check(cfgw["telegram"]["chat_id"] == "100000001" and cfgw["timezone"] == "Europe/Berlin"
          and cfgw["mikrotik"]["credentials"] == "router-read", "config.yaml: the chat and the time zone")
    check(any(dv["ip"] == "192.168.88.20" and dv.get("credentials") == "cams" for dv in load(f["inventory"])["devices"]),
          "inventory.yaml: the device with its login")
    sent = [c[1] for c in tg_calls if c[0] == "sendMessage" and "set up" in str(c[1].get("text"))]
    check(out["told"] == [] and len(sent) == 1 and sent[0]["chat_id"] == "100000001"
          and "1 device (1 with a login)" in sent[0]["text"] and "this chat" in sent[0]["text"]
          and SECRET not in str(sent[0]) and "AAAAAAAAAA" not in sent[0]["text"],
          "Telegram: ONE line for the whole write, through the bot and the chat it just set; never a value")


def test_follow():
    print("\n-- a remote site's device in inventory.yaml follows its own DHCP, not the main one --")
    from lanowl.discovery import reconcile
    from lanowl.model import Device, Inventory
    from lanowl.sites import Sites
    home = Device(ip="192.168.88.71", name="Kettle", attrs={"mac": "AA:BB:CC:DD:EE:FF"})
    far = Device(ip="10.8.0.33", name="Printer", attrs={"mac": "AA:BB:CC:DD:EE:01", "site": "office"})
    inv = Inventory(devices=[home, far])
    moves = reconcile(inv, {"AA:BB:CC:DD:EE:FF": "192.168.88.72", "AA:BB:CC:DD:EE:01": "192.168.88.90"})
    check(home.ip == "192.168.88.72" and far.ip == "10.8.0.33" and len(moves) == 1,
          "the main router's leases move the main site's device, never the remote one")

    class _A2:
        pass
    a = _A2()
    a.inv = inv
    st = Sites.__new__(Sites)
    st.a, st.rec = a, {"watch": {}}
    st._follow({"key": "office"}, [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.8.0.34"}])
    check(far.ip == "10.8.0.34", "its own site's DHCP moves it")


def test_sites():
    print("\n-- sites: a router made a site, Settings → Sites, the most specific network wins --")
    from lanowl.model import best_site, on_main_lan, on_main_side, site_of
    from lanowl.settingsweb import site_list, sites_view
    from lanowl.sites import Sites
    import ipaddress
    office = {"ip": "10.8.0.9", "name": "Office router", "group": "office", "kind": "mikrotik", "credentials": "office"}
    inv = {"devices": [{"ip": "192.168.88.1", "name": "Router", "kind": "mikrotik"},
                       {"ip": "192.168.88.2", "name": "AP", "kind": "openwrt"},
                       {"ip": "192.168.88.10", "name": "NAS", "kind": "linux"}, office]}
    bare = {"mikrotik": {"dhcp_source": "http://192.168.88.1"}}          # a new install: no sites
    cfg = {**bare, "sites": {"list": [{"key": "home", "name": "Home", "nets": ["192.168.88.0/24"]}]}}

    v = sites_view(bare, inv)
    r = {x["ip"]: x for x in v["routers"]}
    check([s["key"] for s in v["list"]] == ["home"] and not v["list"][0]["in_file"] and v["home_default"] == ["192.168.0.0/16"],
          "no sites in the file: the main site is listed anyway, with the networks it has by default")
    check(r["192.168.88.1"]["main"] and r["192.168.88.2"]["main_side"] and not r["10.8.0.9"]["main_side"]
          and "192.168.88.10" not in r, "the routers: the main one, one on the main network, one elsewhere; no linux")

    new, err = site_list(bare, inv, None, {"name": "Office", "nets": "192.168.0.0/24, 10.8.0.9",
                                           "router": "10.8.0.9", "criticality": "info"})
    check(not err and new == [{"key": "office", "name": "Office", "nets": ["192.168.0.0/24", "10.8.0.9/32"],
                               "router": "10.8.0.9", "kind": "routeros", "criticality": "info"}],
          f"Make it a site: the entry, its kind from the router's ({err or new})")
    bad = [({"name": "", "nets": ["192.168.0.0/24"]}, "a name"),
           ({"name": "X", "nets": []}, "its network"),
           ({"name": "X", "nets": ["192.168.0.300/24"]}, "not a network"),
           ({"name": "X", "nets": ["192.168.88.0/24"]}, "Home's already"),
           ({"name": "X", "nets": ["192.168.88.0/25"]}, "holds the main router"),
           ({"name": "X", "nets": ["192.168.0.0/24"], "router": "192.168.0.1"}, "not in inventory.yaml"),
           ({"name": "X", "nets": ["192.168.88.10/32"], "router": "192.168.88.10"}, "a linux"),
           ({"name": "X", "nets": ["192.168.0.0/24"], "router": "10.8.0.9"}, "not on 192.168.0.0/24"),
           ({"name": "X", "nets": ["192.168.0.0/24"], "criticality": "loud"}, "criticality is one of")]
    for body, why in bad:
        _, err = site_list(cfg, inv, None, body)
        check(why in err, f"refused: {why} ({err})")
    _, err = site_list(cfg, inv, "home", None)
    check("stays" in err, "the main site is never removed")

    two, _ = site_list(cfg, inv, None, {"name": "Office", "nets": ["10.8.0.9/32", "192.168.0.0/24"], "router": "10.8.0.9"})
    _, err = site_list({**cfg, "sites": {"list": two}}, inv, None, {"name": "Shop", "nets": ["10.9.0.0/24"], "router": "10.8.0.9"})
    check("Office's router already" in err, "a router is the router of one site")
    two[1]["dhcp"] = "keep me"                                   # a key the form does not know
    ed, err = site_list({**cfg, "sites": {"list": two}}, inv, "office",
                        {"name": "Main office", "nets": ["10.8.0.9/32", "192.168.0.0/24"], "router": "10.8.0.9", "criticality": "warning"})
    check(not err and ed[1]["key"] == "office" and ed[1]["name"] == "Main office" and ed[1]["criticality"] == "warning"
          and ed[1]["dhcp"] == "keep me", "an edit keeps the key and what the form does not edit")
    gone, _ = site_list({**cfg, "sites": {"list": two}}, inv, "office", None)
    check([s["key"] for s in gone] == ["home"], "Remove: out of the list")
    h, err = site_list(bare, inv, "home", {"name": "Casa", "nets": "192.168.88.0/24"})
    check(not err and h == [{"key": "home", "name": "Casa", "nets": ["192.168.88.0/24"]}], "the main site, named in the file for the first time")
    k, _ = site_list({"sites": {"list": [{"key": "office", "name": "Office", "nets": ["10.20.0.0/24"]}]}}, inv, None,
                     {"name": "Office", "nets": ["10.21.0.0/24"]})
    check(k[1]["key"] == "office-2", "a new key never takes one in use")

    words = ST.describe("config", bare, {**bare, "sites": {"list": new}})
    check(words == ["site Office added: 192.168.0.0/24, 10.8.0.9/32, its router 10.8.0.9"], f"in words: {words}")
    words = ST.describe("config", {"sites": {"list": two}}, {"sites": {"list": ed}})
    check("site Main office: name Office → Main office" in words and "site Main office: criticality info → warning" in words
          and not any(w.startswith("sites.list") for w in words), f"an edit, in words: {words}")
    check(ST.describe("config", {"sites": {"list": two}}, {"sites": {"list": gone}}) == ["site Office removed"], "a removal, in words")

    # the most specific network wins: a site inside the main one's default 192.168.0.0/16
    shp = {**bare, "sites": {"list": [{"key": "shop", "name": "Shop", "nets": ["192.168.0.0/24"], "router": "192.168.0.1"}]}}
    check(site_of(shp, "192.168.0.5") == "shop" and site_of(shp, "192.168.88.5") == "home",
          "a site's /24 inside the default /16: its addresses are the site's")
    check(not on_main_lan(shp, "192.168.0.5") and on_main_lan(shp, "192.168.88.5") and on_main_lan(bare, "192.168.0.5"),
          "the main LAN (updates, reboots, the scan) leaves a site's addresses out")
    wide = {"sites": {"list": [{"key": "home", "nets": ["192.168.0.0/16"]}, {"key": "shop", "nets": ["192.168.0.0/24"]}]}}
    check(site_of(wide, "192.168.0.5") == "shop" and site_of(wide, "192.168.7.5") == "home",
          "listed after a main site that holds it: the site still wins")
    check(on_main_side(bare, "192.168.88.2") and not on_main_side(bare, "10.8.0.9"), "the main router's /24 is the main site's")
    n = lambda x: ipaddress.ip_network(x)    # noqa: E731
    check(best_site(ipaddress.ip_address("10.8.0.16"), [("vpn", n("10.8.0.0/24")), ("cabin", n("10.8.0.16/32"))]) == "cabin",
          "a /32 wins over the /24 holding it")
    st = Sites.__new__(Sites)
    st.sites = [{"key": "home", "nets": [n("192.168.0.0/16")]}, {"key": "shop", "nets": [n("192.168.0.0/24")]}]
    check(st.of("192.168.0.9") == "shop" and st.of("192.168.5.9") == "home" and st.of("x") == "home", "sites.py places them the same way")

    # the route: plan, save, and a save on a file changed since
    d = tempfile.mkdtemp(prefix="lanowl-sites-")
    try:
        _files(d)
        from lanowl.yamledit import apply
        ip = os.path.join(d, "inventory.yaml")
        open(ip, "w").write(apply(open(ip).read(), [{"op": "insert", "path": ["devices"], "value": office}]))
        out = {}

        async def go():
            from aiohttp import ClientSession, CookieJar, web
            import lanowl.web as W
            from lanowl.settingsweb import SettingsRoutes
            a = _A(d)
            a.login = L.Login(a)
            dash = W.Dashboard.__new__(W.Dashboard)
            dash.a, dash.login, dash.allowed_hosts, dash._login_lock = a, a.login, set(), asyncio.Lock()

            @web.middleware
            async def guard(request, handler):
                return await dash._guard(request, handler)
            app = web.Application(middlewares=[guard])
            app.router.add_post("/api/login", dash.api_login)
            SettingsRoutes(dash).routes(app)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            body = {"key": None, "site": {"name": "Office", "nets": ["10.8.0.9/32", "192.168.0.0/24"], "router": "10.8.0.9",
                                          "criticality": "info"}}
            try:
                async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
                    async with s.post(base + "/api/settings/site", json={**body, "preview": True}) as r:
                        out["anon"] = r.status
                    await s.post(base + "/api/login", json={"password": PW})
                    async with s.get(base + "/api/settings") as r:
                        out["get"] = (await r.json())["sites"]
                    async with s.post(base + "/api/settings/site", json={**body, "preview": True}) as r:
                        out["plan"] = (r.status, await r.json())
                    old = _base(a, "config")
                    async with s.post(base + "/api/settings/site", json={**body, "base": old}) as r:
                        out["save"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/site", json={"key": "home", "base": old,
                                                                         "site": {"name": "Casa", "nets": ["192.168.88.0/24"]}}) as r:
                        out["stale"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/site", json={"key": "home", "site": None, "preview": True}) as r:
                        out["home"] = (r.status, await r.json())
                    out["told"] = list(a.told)
                    out["pending"] = a.settings.view().get("pending") or {}
            finally:
                await runner.cleanup()
        asyncio.run(go())
        check(out["anon"] == 401, "logged out: no site is written")
        g = out["get"]
        check([x["key"] for x in g["list"]] == ["home"] and any(x["ip"] == "10.8.0.9" and not x["site"] for x in g["routers"]),
              "GET /api/settings: the sites and the routers")
        st_, p = out["plan"]
        check(st_ == 200 and p["changes"] == ["site Office added: 10.8.0.9/32, 192.168.0.0/24, its router 10.8.0.9"]
              and not p["problems"] and "text" not in p, f"the plan, in words ({p.get('changes') or p})")
        st_, r = out["save"]
        lst = load(open(os.path.join(d, "config.yaml")).read())["sites"]["list"]
        check(st_ == 200 and r["ok"] and [x["key"] for x in lst] == ["home", "office"] and lst[1]["kind"] == "routeros",
              "saved into config.yaml, after the main site")
        check(any("site Office added" in x for x in out["told"]) and "config" in out["pending"],
              "Telegram told in one line; it waits for a restart")
        check(out["stale"][0] == 409 and "changed since" in out["stale"][1]["error"], "a page that read the file before is refused")
        check(out["home"][0] == 400, "the main site cannot be removed from the page")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_small_bugs():
    print("\n-- the 10-06 onboarding test's small bugs --")
    from lanowl import schema
    from lanowl.backups import report as backups_report
    from lanowl.access import Access
    from lanowl import settingsweb as SW
    from lanowl.model import inventory_from
    with tempfile.TemporaryDirectory() as d:
        _files(d, password=False)
        a = _A(d)
        s = a.settings
        r = s.save("config", [{"op": "set", "path": ["web", "password_hash"], "value": L.hash_password(PW)}],
                   _base(a, "config"))
        check(r["ok"] and s.pending() == {}, "the first password is saved, and is not a change waiting for a restart (5)")
        r = s.save("config", [{"op": "set", "path": ["model", "name"], "value": "qwen3:32b"}], _base(a, "config"))
        check(r["ok"] and "config" in s.pending(), "...a real change still is")
        text = open(s.files["config"].path).read()
        line = next(ln for ln in text.splitlines() if "password_hash:" in ln)
        check(line.rstrip().endswith("set on its first page"), f"the hash's comment is whole, not cut (8): {line.strip()[-40:]}")
    # every comment the example continues on a second line: its first line ends a thought
    ex = open(os.path.join(ROOT, "config.example.yaml"), encoding="utf-8").read()
    lines = ex.split("\n")
    cut = []
    for i, ln in enumerate(lines[:-1]):
        c = schema._comment(ln)
        nxt = lines[i + 1]
        if c and not ln.lstrip().startswith("#") and nxt.lstrip().startswith("#") and \
                len(nxt) - len(nxt.lstrip()) > len(ln) - len(ln.lstrip()):
            w = c.rstrip().split()[-1].lower() if c.split() else ""
            if c.rstrip().endswith((":", ",", ";")) or w in ("with", "the", "a", "an", "of", "to", "and", "or", "its", "for", "in", "on", "by"):
                cut.append(c)
    check(not cut, f"no comment in the example is cut when a new key takes its first line: {cut}")
    # a checks change, in words (40)
    ch = ST.describe("inventory", {"devices": [{"ip": "192.168.88.2", "name": "AP", "checks": [{"type": "icmp"}]}]},
                     {"devices": [{"ip": "192.168.88.2", "name": "AP", "checks": [{"type": "icmp"}, {"type": "tcp", "port": 22},
                                                                                  {"type": "link", "iface": "ether3"}]}]})
    check(ch == ["AP: checks icmp → icmp, tcp 22, link ether3"], f"a checks change in words, not {{…}} (40): {ch}")
    # a link check names its router port (27)
    dev, err = SW.clean_device({"ip": "192.168.88.2", "name": "AP", "checks": [{"type": "link"}]}, {})
    check(dev is None and "router port" in err, "a link check without its interface is refused (27)")
    dev, err = SW.clean_device({"ip": "192.168.88.2", "name": "AP", "checks": [{"type": "link", "iface": "ether3"}]}, {})
    check(dev is not None and dev["checks"] == [{"type": "link", "iface": "ether3"}], "...with it, kept")
    from lanowl.main import checks_report
    inv = inventory_from({"devices": [{"ip": "192.168.88.2", "name": "AP", "checks": [{"type": "link"}]}]}, "/x/inventory.yaml")
    text, n = checks_report(inv)
    check(n == 1 and "AP (192.168.88.2)" in text and "iface" in text, "--check: ✗ for one already in the file")
    # backups: a store lanowl cannot write to, said at save time (41)
    with tempfile.TemporaryDirectory() as d:
        sec = os.path.join(d, "secrets.yaml")
        open(sec, "w").write("logins:\n  pw: {user: admin, password: x}\n  k: {user: root, key: true}\n")
        os.chmod(sec, 0o600)
        cfg = {"access": {"secrets_file": sec}, "backups": {"enabled": True, "store": {"host": "192.168.88.12"}}}
        def inv_of(cred):
            return inventory_from({"devices": [{"ip": "192.168.88.12", "name": "NAS", "credentials": cred}]} if cred else
                                  {"devices": []}, os.path.join(d, "inventory.yaml"))
        t0, n0 = backups_report(cfg, inv_of(None), Access(cfg, inv_of(None)))
        t1, n1 = backups_report(cfg, inv_of("pw"), Access(cfg, inv_of("pw")))
        t2, n2 = backups_report(cfg, inv_of("k"), Access(cfg, inv_of("k")))
        t3, n3 = backups_report({**cfg, "backups": {"enabled": False}}, inv_of(None), Access(cfg, inv_of(None)))
    check(n0 == 1 and "not one of your devices" in t0, "a store that is no device: ✗")
    check(n1 == 1 and "no login with its ssh key" in t1, "a store reached by password only: ✗ (the backups go over the key)")
    check(n2 == 0 and t2 == "" and n3 == 0 and t3 == "", "a store with lanowl's key, or backups off: nothing said")
    # the router's address as people type it (4)
    check(SW.router_url("192.168.88.1") == "http://192.168.88.1" and SW.router_url("https://192.168.88.1/") == "https://192.168.88.1"
          and SW.router_url("router.lan:8080") == "http://router.lan:8080" and SW.router_url("") == ""
          and SW.router_url("a b") is None, "the router's address: http:// added when not typed")
    # the sweep's network on a fresh install (2, 33), and the gateway
    check(SW.sweep_net({}, "", "192.168.88.47") == ("192.168.88.0/24", "lanowl's own network"),
          "no site, no router: lanowl's own /24 — not 192.168.0.0/16")
    check(SW.sweep_net({}, "http://192.168.70.1", "192.168.88.47")[0] == "192.168.70.0/24", "...the typed router's /24 first")
    check(SW.sweep_net({"sites": {"list": [{"key": "home", "nets": ["10.20.30.0/23"]}]}}, "", "192.168.88.47")[0] == "10.20.30.0/23",
          "...the main site's network when it names one")
    check(SW.sweep_net({"sites": {"list": [{"key": "home", "nets": ["192.168.0.0/16"]}]}}, "", "")[0] == "",
          "a network too big, nothing else known: no sweep, and why")
    check(SW.sweep_net({}, "http://8.8.8.8", "")[0] == "", "never a public network")
    real = SW.default_gateway
    try:
        SW.default_gateway = lambda: "192.168.88.1"
        g1 = SW.gateway("192.168.88.47")
        SW.default_gateway = lambda: "172.17.0.1"          # Docker's bridge: not the house's router
        g2 = SW.gateway("192.168.88.47")
    finally:
        SW.default_gateway = real
    check(g1 == {"ip": "192.168.88.1", "how": "found"} and g2 == {"ip": "192.168.88.1", "how": "guess"} and SW.gateway("") == {},
          "the gateway: found on lanowl's network, else a guess at its .1")

    class _Req:
        def __init__(self, host):
            self.host = host
    check(SW.lan_ip(_Req("192.168.88.47:8098"), {"observer": {"host_ip": "172.17.0.2"}}) == "192.168.88.47"
          and SW.lan_ip(_Req("lanowl.example:8088"), {"observer": {"host_ip": "192.168.88.5"}}) == "192.168.88.5"
          and SW.lan_ip(_Req("lanowl.example"), {"observer": {"host_ip": "203.0.113.5"}}) == "",
          "lanowl's address on the network: the page's, else the one it found; never a public one")
    line = SW.setup_line([{"ip": "1", "credentials": "x"}, {"ip": "2"}], True, False, "192.168.88.140")
    check(line.startswith("🦉 <b>lanowl is set up</b> from the dashboard (192.168.88.140): 2 devices (1 with a login), "
                          "the router's DHCP list."), f"the setup's line: {line}")


def test_turnkey_routes():
    print("\n-- Find my devices, Try, Home Assistant's token, what lanowl does, Watch at once --")
    import json
    out = {}

    class _Rest:
        def __init__(self, ok, data=None, detail=""):
            self.ok, self.data, self.detail = ok, data or {}, detail

    async def fake_mk(src, path, user, password, verify, timeout):
        if password != SECRET:
            return _Rest(False, detail="mikrotik http 401")
        if path == "system/resource":
            return _Rest(True, {"json": {"version": "7.16", "board-name": "hAP"}})
        if path.startswith("user?name="):
            return _Rest(True, {"json": [{"name": user, "group": "full"}]})
        if path.startswith("user/group?name="):
            return _Rest(True, {"json": [{"name": "full", "policy": "local,ssh,reboot,read,write,policy,api,rest-api,!dude"}]})
        if path == "ip/arp":
            return _Rest(True, {"json": [{"address": "192.168.88.31", "mac-address": "00:0C:42:AA:BB:31", "status": "stale"}]})
        return _Rest(True, {"json": [{"address": "192.168.88.40", "mac-address": "EC:64:C9:00:00:40", "host-name": "",
                                      "dynamic": "true", "status": "bound"}]})

    async def fake_fping(self, net):
        return ["192.168.88.31", "192.168.88.12", "192.168.88.40"], {}, ""

    async def fake_port(ip, port, sem):           # what answers, per device
        return {"192.168.88.12": {8123: ""}, "192.168.88.31": {22: "SSH-2.0-ROSSSH", 8291: ""},
                "192.168.88.40": {80: ""}}.get(ip, {}).get(port)

    async def fake_get(url, limit=65536):
        if url.endswith("/shelly") and "192.168.88.40" in url:
            return 200, "", json.dumps({"name": "Pump", "app": "Pro1", "gen": 2, "auth_en": False})
        return 404, "", ""

    tried = []

    async def fake_try(acc, kind, ip, user="", password="", token="", key=None):
        tried.append((kind, ip, user, bool(password), bool(token)))
        if kind == "homeassistant":
            return {"ok": token == "ha-tok-1", "what": "API running.", "said": "HTTP 401: 401: Unauthorized"}
        return {"ok": password == SECRET, "what": "Linux 6.1", "said": "Permission denied (publickey,password)."}

    async def go(d):
        from aiohttp import ClientSession, CookieJar, web
        import lanowl.web as W
        from lanowl import identify, probes, trylogin
        from lanowl.settingsweb import SettingsRoutes
        probes.mikrotik_rest = fake_mk
        SettingsRoutes._fping = fake_fping
        identify._port, identify._get, identify._cache = fake_port, fake_get, {}
        trylogin.try_login = fake_try
        a = _A(d)
        a.login = L.Login(a)
        dash = W.Dashboard.__new__(W.Dashboard)
        dash.a, dash.login, dash.allowed_hosts, dash._login_lock = a, a.login, set(), asyncio.Lock()

        @web.middleware
        async def guard(request, handler):
            return await dash._guard(request, handler)
        app = web.Application(middlewares=[guard])
        app.router.add_post("/api/login", dash.api_login)
        SettingsRoutes(dash).routes(app)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        try:
            async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
                await s.post(base + "/api/login", json={"password": PW})
                rb = {"dhcp_source": "192.168.88.1", "credentials": "router-read", "user": "admin", "password": SECRET}
                async with s.post(base + "/api/setup/router", json=rb) as r:
                    out["router"] = await r.json()
                async with s.post(base + "/api/setup/find", json={**rb, "with_router": True}) as r:
                    out["find"] = await r.json()
                async with s.post(base + "/api/setup/find", json={"ips": ["8.8.8.8"]}) as r:
                    out["find_public"] = (r.status, await r.json())
                async with s.post(base + "/api/setup/try", json={"ip": "192.168.88.9", "kind": "linux", "user": "root", "password": "nope"}) as r:
                    out["try_bad"] = await r.json()
                async with s.post(base + "/api/setup/try", json={"ip": "192.168.88.9", "kind": "linux", "user": "root", "password": SECRET}) as r:
                    out["try_soon"] = (r.status, await r.json())
                await asyncio.sleep(3.1)
                async with s.post(base + "/api/setup/try", json={"ip": "192.168.88.9", "kind": "linux", "user": "root", "password": SECRET}) as r:
                    out["try_ok"] = await r.json()
                body = {"devices": [{"ip": "192.168.88.12", "name": "Home Assistant", "group": "servers", "criticality": "high",
                                     "kind": "homeassistant", "checks": [{"type": "icmp"}]},
                                    {"ip": "192.168.88.40", "name": "Pump", "group": "iot", "criticality": "low",
                                     "kind": "shelly", "checks": [{"type": "icmp"}]},
                                    {"ip": "192.168.88.61", "name": "NAS", "group": "servers", "criticality": "high",
                                     "kind": "linux", "credentials": "nas", "checks": [{"type": "icmp"}]}],
                        "logins": {"nas": {"user": "root", "how": "password", "password": SECRET}},
                        "ha": {"ip": "192.168.88.12", "token": "ha-tok-1"},
                        "features": {"updates": True, "security": False, "config": False, "approve": True}}
                async with s.post(base + "/api/setup/write", json={**body, "preview": True}) as r:
                    pj = await r.json()
                bases = {k: (pj.get(k) or {}).get("base") for k in ("secrets", "inventory", "config")}
                async with s.post(base + "/api/setup/write", json={**body, "bases": bases}) as r:
                    out["write"] = (r.status, await r.text())
                out["files"] = {k: open(a.settings.files[k].path).read() for k in ("secrets", "inventory", "config")}
                # Watch: pinged at once, so nothing waits for a restart because of it
                a.settings.at_start = {k: ST.digest(f.read()) for k, f in a.settings.files.items()}
                a.settings.running = {k: ST.running_digest(k, a.settings.files[k].read()) for k in ST.RESTART}
                async with s.get(base + "/api/settings/devices") as r:
                    v = await r.json()
                dev = {"ip": "192.168.88.70", "name": "Printer", "group": "misc", "criticality": "low", "checks": [{"type": "icmp"}]}
                async with s.post(base + "/api/settings/device", json={"ip": None, "device": dev, "base": v["base"], "how": "watch"}) as r:
                    out["watch"] = await r.json()
                out["pending_after_watch"] = a.settings.pending()
        finally:
            await runner.cleanup()

    with tempfile.TemporaryDirectory() as d:
        _files(d)
        asyncio.run(go(d))
    check(out["router"]["ok"] and out["router"]["can_write"] is True, "Try the router: a user that may write is said to")
    f = out["find"]
    rows = {x["ip"]: x for x in f.get("rows") or []}
    check(f["ok"] and set(rows) == {"192.168.88.12", "192.168.88.31", "192.168.88.40"},
          f"Find my devices: the DHCP list, the ARP table's fixed address, the sweep's ({sorted(rows)})")
    check(rows["192.168.88.31"]["kind"] == "mikrotik" and rows["192.168.88.31"]["here"] and "ARP" in rows["192.168.88.31"]["how"]
          and "ping" in rows["192.168.88.31"]["how"], "a stale ARP entry that answers ping is here now, and what it is")
    check(rows["192.168.88.12"]["kind"] == "homeassistant" and rows["192.168.88.12"]["how"] == ["ping"],
          "one only the sweep found, identified by what answers")
    check(rows["192.168.88.40"]["kind"] == "shelly" and rows["192.168.88.40"]["name"] == "Pump", "a Shelly, by its own name")
    check([ln["t"] for ln in f["lines"]][:3] == ["the router's DHCP list", "its ARP table: the fixed addresses",
                                                 "one ping to every address of 192.168.88.0/24"],
          "what lanowl looked at, said")
    check(out["find_public"][0] == 400, "Add by address: only a home network's")
    check(not out["try_bad"]["ok"] and out["try_bad"]["said"] == "Permission denied (publickey,password)."
          and out["try_soon"][0] == 429 and out["try_ok"]["ok"], "Try: the device's answer, word for word; one try per device every 3 s")
    check(out["write"][0] == 200 and SECRET not in out["write"][1] and "ha-tok-1" not in out["write"][1], "written, no value in the answer")
    fs = out["files"]
    inv = {x["ip"]: x for x in load(fs["inventory"])["devices"]}
    cfg = load(fs["config"])
    check(load(fs["secrets"])["tokens"]["homeassistant"] == "ha-tok-1" and cfg["access"]["ha_url"] == "http://192.168.88.12:8123",
          "Home Assistant: its token, and its address from the device")
    check(inv["192.168.88.12"].get("manage") == ["updates", "reboot"] and inv["192.168.88.40"].get("manage") == ["reboot"]
          and inv["192.168.88.61"].get("manage") == ["updates", "reboot", "upgrade"] and "credentials" not in inv["192.168.88.40"],
          f"what lanowl does: each device what its kind can of what was chosen ({[inv[k].get('manage') for k in sorted(inv)]})")
    check(cfg["updates"]["enabled"] is True and cfg["actions"]["enabled"] is True and cfg["actions"]["mode"] == "live"
          and cfg["exposure"]["enabled"] is False, "...and the features switched on that were chosen, and only those")
    check(out["watch"]["ok"] and "inventory" not in out["pending_after_watch"], "Watch: no 'Restart to apply' for it")


def test_defaults_whole():
    print("\n-- every on/off setting has lanowl's own default --")
    from lanowl import schema
    bools = {tuple(f["path"]) for sec in schema.sections(open(os.path.join(ROOT, "config.example.yaml")).read())
             for f in sec["fields"] if f["type"] == "bool"}
    check(bools <= set(schema.DEFAULTS), f"missing: {sorted(bools - set(schema.DEFAULTS))}")
    check(set(schema.DEFAULTS) <= bools, f"not in the example: {sorted(set(schema.DEFAULTS) - bools)}")


if __name__ == "__main__":
    for fn in [test_save_and_undo, test_guards, test_login, test_routes, test_secrets, test_setup_and_secret_routes,
               test_follow, test_sites, test_small_bugs, test_turnkey_routes, test_defaults_whole]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all settings tests passed")
