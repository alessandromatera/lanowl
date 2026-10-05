"""Settings on the dashboard (settings.py, settingsweb.py, login.py): `python -m tests.test_settings`.

No network, no Telegram — the sender is a fake, the files are in a temporary folder.
Pinned down here:

  1. a save writes the file in place (the same inode: a single-file mount allows nothing
     else), keeps the old text as a version, records who and what, tells Telegram in one line,
     and is "not running yet" until a restart; undo puts it back the same way;
  2. what stops a save: a file changed since the page read it, a value the environment sets,
     a read-only file, a file replaced on the host, a ✗ that --check did not give before;
     the password's hash never shows, in the diff or on Telegram;
  3. the login: its lock survives a restart; a save asks the password again after ten
     minutes, and wrong ones count toward the lock; the setup code is made once, kept, and
     opens the first password, which goes into config.yaml;
  4. the routes: the forms and their sources, a save that needs the password again, a device
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
        self._started = time.time()
        self.settings = ST.Settings(self, self.cfg["_path"], self.inv.path)

    def _emit_telegram(self, channel, text, **kw):
        self.told.append(text)

    def restart_blockers(self):
        return []

    def request_restart(self, by):
        self.restarts.append(by)
        return {"ok": True}


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
        check(st["why"] == "replaced" and "restart" in ST.WHY["replaced"],
              "a file replaced on the host (no name left): restart first")


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
        now = time.time()
        check(lg.recent(tok, now) and not lg.recent(tok, now + L.REAUTH_S + 1), "the password again after ten minutes")
        r = lg.reauth(tok, False, "192.168.88.47", now + 700)
        check(r == {"ok": False, "why": "wrong", "left": 4}, "a wrong one there counts toward the lock")
        lg.reauth(tok, True, "", now + 700)
        check(lg.recent(tok, now + 750), "the right one: ten minutes more")
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
                    for t in a.login.sessions.values():
                        t["authed"] = 0                       # typed long ago
                    body = {"file": "config", "ops": [{"op": "set", "path": ["model", "think"], "value": False}],
                            "base": _base(a, "config")}
                    async with s.post(base + "/api/settings/save", json=body) as r:
                        out["needed"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/save", json={**body, "password": "wrong one"}) as r:
                        out["wrong"] = (r.status, await r.json())
                    async with s.post(base + "/api/settings/save", json={**body, "password": PW}) as r:
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
                    async with s.post(base + "/api/setup/claim", json={"code": "x", "password": PW}) as r:
                        out["claim_taken"] = r.status
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
    check(out["needed"] == (403, {"ok": False, "auth": "needed"}), "a save after ten minutes: the password again")
    check(out["wrong"][0] == 403 and out["wrong"][1]["auth"] == "wrong", "a wrong one: refused")
    check(out["saved"][0] == 200 and out["saved"][1]["ok"], "the right one: saved")
    check(out["dev_plan"][0] == 200 and any("192.168.88.44" in ln for ln in out["dev_plan"][1]["diff"]),
          "a device from the form: its diff")
    check(out["dev_save"][0] == 200 and "ip: 192.168.88.44" in out["inv"] and 'name: "ESP 3A1F2C"' in out["inv"],
          "...written into inventory.yaml")
    check(out["dev_bad"][0] == 400 and "cannot logs" in out["dev_bad"][1]["error"], "only what its kind can do")
    check(out["claim_taken"] == 409, "with a password, the setup code opens nothing")
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


if __name__ == "__main__":
    for fn in [test_save_and_undo, test_guards, test_login, test_routes, test_follow]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all settings tests passed")
