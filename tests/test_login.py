"""The dashboard's login (login.py, web.py): run with `python -m tests.test_login`.

No network, no Telegram — the senders are fakes. Pinned down here:

  1. the hash: scrypt, checked in constant time; anything else in web.password_hash is no
     password at all, and the dashboard stays closed;
  2. the password comes from config.yaml, else /password on Telegram; config.yaml's wins;
  3. five wrong passwords lock the login for 15 minutes, for every browser, and Telegram
     hears it once with the address of the last try; /password lifts the lock;
  4. a login is a cookie remembered for 30 days after the last visit, across a restart;
     a new password, or Log out everywhere, ends every one;
  5. the page: logged out, every address is the login page and every /api call is 401,
     except the login and the icon; web.login: false opens it; a good password sets an
     HttpOnly cookie that opens it;
  6. /password on Telegram: the message is deleted, only the hash is kept;
  7. --check: ✓ for a password, ✗ for none or a broken one, ○ when switched off.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import login as L
from lanowl import sinks
from lanowl.state import StateStore

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


PW = "correct horse"
CHAT_ID = "100000001"


class _A:
    """What Login reads of lanowl: the config, the state, the Telegram sender."""

    def __init__(self, d, web=None, chat=True):
        self.cfg = {"web": {"enabled": True, **(web or {})},
                    "telegram": {"chat_id": CHAT_ID, "chat": {"enabled": chat}},
                    "state": {"db_path": os.path.join(d, "s.sqlite")}}
        self.state = StateStore(self.cfg["state"]["db_path"])
        self.told = []

    def _emit_telegram(self, channel, text, **kw):
        self.told.append(text)


def _token_on():
    real = sinks.resolve_tg_token
    sinks.resolve_tg_token = lambda cfg: "123:test"
    return lambda: setattr(sinks, "resolve_tg_token", real)


# --- 1. the hash ---------------------------------------------------------------------------
def test_hash():
    print("\n-- the hash --")
    h = L.hash_password(PW)
    check(h.startswith("scrypt$32768$8$1$") and L.valid_hash(h), "scrypt, with its parameters")
    check(L.verify(PW, h) and not L.verify(PW + "!", h) and not L.verify("", h), "the right one only")
    check(L.hash_password(PW) != h, "a new salt every time")
    for bad in ("", PW, "scrypt$3$8$1$YQ==$YQ==", "scrypt$1073741824$8$1$YQ==$YQ==", "sha256$abc"):
        check(not L.valid_hash(bad) and not L.verify(PW, bad), f"no password: {bad[:24]!r}")


# --- 2. where it comes from -------------------------------------------------------------------
def test_sources():
    print("\n-- config.yaml, else /password; none = closed --")
    with tempfile.TemporaryDirectory() as d:
        a = _A(d)
        lg = L.Login(a)
        check(lg.on and lg.needed and lg.source == "", "on by default, and closed without a password")
        check(not lg.set_password("short")["ok"] and lg.needed, "a password has 8 characters or more")
        r = lg.set_password(PW)
        check(r["ok"] and "30 days" in r["text"] and lg.source == "Telegram" and not lg.needed,
              "/password sets it")
        check("password" in str(a.state.load_record(L.RECORD)) and PW not in str(a.state.load_record(L.RECORD)),
              "only its hash is kept")
        check(L.Login(a).source == "Telegram", "and it outlives a restart")

        b = _A(d, web={"password_hash": L.hash_password("from the file")})
        lb = L.Login(b)
        r = lb.set_password("another one")
        check(lb.source == "config.yaml" and not r["ok"] and "config.yaml" in r["text"],
              "config.yaml's wins, and /password points there")
        tok = lb.attempt(L.verify("from the file", lb.hash))["token"]
        check(lb.check(tok), "config.yaml's opens it")

        c = _A(d, web={"password_hash": "hunter22"})
        lc = L.Login(c)
        check(lc.needed and not lc.set_password(PW)["ok"] and "not a password hash" in lc.ask_text(),
              "the password itself in password_hash: closed, fix it there")
        check(L.Login(_A(d, web={"login": False})).needed is False, "web.login: false needs nothing")
        check("/password" in lg.needed_text(True) and "/password" not in lg.needed_text(False),
              "the start message names /password only where Telegram answers")


# --- 3. the lock ---------------------------------------------------------------------------------
def test_lock():
    print("\n-- five wrong passwords lock it; /password lifts the lock --")
    undo = _token_on()
    try:
        with tempfile.TemporaryDirectory() as d:
            a = _A(d)
            lg = L.Login(a)
            lg.set_password(PW)
            t = 1000.0
            lefts = [lg.attempt(False, "192.168.88.47", t + i)["left"] for i in range(4)]
            check(lefts == [4, 3, 2, 1] and not a.told, "four wrong: how many are left, nothing said")
            r = lg.attempt(False, "192.168.88.47", t + 5)
            check(r["why"] == "locked" and r["until"] == t + 5 + L.LOCK_S, "the fifth locks it for 15 minutes")
            check(len(a.told) == 1 and "locked until" in a.told[0] and "192.168.88.47" in a.told[0]
                  and "/password" in a.told[0], "Telegram hears it once, with the address")
            check(lg.attempt(True, "192.168.88.10", t + 60)["why"] == "locked",
                  "even the right one waits: the lock is for every browser")
            check(lg.attempt(True, "192.168.88.10", t + 5 + L.LOCK_S + 1)["ok"], "after 15 minutes it opens")
            for i in range(5):
                lg.attempt(False, "", t + 2000 + i)
            check(lg.locked(t + 2010), "locked again")
            r = lg.set_password("a new password", now=t + 2010)
            check(r["ok"] and "lock is lifted" in r["text"] and not lg.locked(t + 2011),
                  "/password lifts it")
            check(len(a.told) == 2 and "the last from" not in a.told[1], "no address, none named")
    finally:
        undo()


# --- 4. browsers ---------------------------------------------------------------------------
def test_sessions():
    print("\n-- 30 days after the last visit; across a restart; a new password ends them --")
    with tempfile.TemporaryDirectory() as d:
        a = _A(d)
        lg = L.Login(a)
        lg.set_password(PW)
        now = time.time()
        one = lg.attempt(True, "", now)["token"]
        two = lg.attempt(True, "", now)["token"]
        check(lg.check(one, now + 1) and lg.check(two, now + 1) and not lg.check("guess", now + 1),
              "each browser its own login")
        check(all(len(k) == 64 for k in a.state.load_record(L.RECORD)["sessions"]) and
              one not in str(a.state.load_record(L.RECORD)), "only their hashes are kept")
        check(lg.check(one, now + 20 * 86400) and lg.check(one, now + 40 * 86400),
              "a visit renews it: 40 days on, still in")
        check(not lg.check(two, now + 31 * 86400), "a browser away 31 days is out")
        lg._save()
        lb = L.Login(a)
        check(lb.check(one, now + 40 * 86400 + 5), "a restart logs nobody out")
        lb.logout(one)
        check(not lb.check(one), "Log out ends this browser")
        three, four = (lb.attempt(True)["token"] for _ in range(2))
        lb.logout(three, everywhere=True)
        check(not lb.check(three) and not lb.check(four), "Log out everywhere ends every one")
        five = lb.attempt(True)["token"]
        lb.set_password("a new password")
        check(not lb.check(five), "a new password logs every browser out")
        six = lb.attempt(True)["token"]
        lc = L.Login(_A(d, web={"password_hash": L.hash_password("now in the file")}))
        check(not lc.check(six), "logins made under another password do not survive a change in config.yaml")


# --- 5. the page ---------------------------------------------------------------------------
async def _page(d, web_cfg, steps):
    from aiohttp import ClientSession, CookieJar, web
    import lanowl.web as W
    a = _A(d, web=web_cfg)
    a.login = L.Login(a)
    dash = W.Dashboard.__new__(W.Dashboard)
    dash.a, dash.login, dash.allowed_hosts, dash._login_lock = a, a.login, set(), asyncio.Lock()

    @web.middleware
    async def guard(request, handler):
        return await dash._guard(request, handler)

    async def index(request):
        return web.Response(text="the dashboard")

    async def state(request):
        return web.json_response({"health": "ok"})

    app = web.Application(middlewares=[guard])
    app.router.add_get("/", index)
    app.router.add_get("/api/state", state)
    app.router.add_get("/icon.svg", dash.static)
    app.router.add_get("/api/login", dash.api_login_state)
    app.router.add_post("/api/login", dash.api_login)
    app.router.add_post("/api/logout", dash.api_logout)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as s:
            await steps(s, base, a)
    finally:
        await runner.cleanup()


def test_page():
    print("\n-- the page: closed until logged in --")
    out = {}

    async def closed(s, base, a):
        async with s.get(base + "/") as r:
            out["none_page"] = (r.status, await r.text())
        async with s.post(base + "/api/login", json={"password": PW}) as r:
            out["none_login"] = (r.status, await r.json())

    async def steps(s, base, a):
        async with s.get(base + "/") as r:
            out["page"] = (r.status, await r.text(), r.headers.get("X-Frame-Options"))
        async with s.get(base + "/api/state") as r:
            out["api"] = (r.status, await r.json())
        async with s.get(base + "/icon.svg") as r:
            out["icon"] = r.status
        async with s.post(base + "/api/login", data="password=x") as r:
            out["form"] = r.status
        async with s.post(base + "/api/login", json={"password": ""}) as r:
            out["empty"] = (r.status, (await r.json()).get("why"))
        async with s.post(base + "/api/login", json={"password": "wrong one"}) as r:
            out["wrong"] = (r.status, await r.json())
        async with s.post(base + "/api/login", json={"password": PW}) as r:
            out["right"] = (r.status, r.headers.get("Set-Cookie", ""))
        async with s.get(base + "/") as r:
            out["in"] = await r.text()
        async with s.get(base + "/api/login") as r:
            out["in_state"] = (await r.json())["state"]
        async with s.get(base + "/api/state") as r:
            out["api_in"] = r.status
        async with s.post(base + "/api/logout", json={}) as r:
            out["logout"] = r.status
        async with s.get(base + "/api/state") as r:
            out["api_out"] = r.status

    async def opened(s, base, a):
        async with s.get(base + "/api/state") as r:
            out["off"] = r.status

    async def named(s, base, a):
        async with s.get(base + "/", headers={"Host": "evil.example"}) as r:
            out["host"] = r.status

    with tempfile.TemporaryDirectory() as d:
        asyncio.run(_page(d, {}, closed))
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(_page(d, {"password_hash": L.hash_password(PW)}, steps))
        asyncio.run(_page(d, {"login": False}, opened))
        asyncio.run(_page(d, {"password_hash": L.hash_password(PW)}, named))

    check(out["none_page"][0] == 200 and '"state": "none"' in out["none_page"][1]
          and "the dashboard" not in out["none_page"][1], "no password: the page says how to set one, nothing else")
    check(out["none_login"][0] == 401 and out["none_login"][1]["why"] == "none", "and nothing logs in")
    check(out["page"][0] == 200 and '"state": "login"' in out["page"][1] and "Log in" in out["page"][1]
          and "the dashboard" not in out["page"][1] and out["page"][2] == "DENY",
          "logged out: the login page, never framed")
    check(out["api"] == (401, {"ok": False, "login": "login"}), "and every /api call is 401")
    check(out["icon"] == 200, "the icon stays open (the home-screen app)")
    check(out["form"] == 415, "a form post is still refused: JSON only")
    check(out["empty"] == (400, "empty"), "an empty field is not a guess")
    check(out["wrong"][0] == 401 and out["wrong"][1] == {"ok": False, "why": "wrong", "left": 4},
          "a wrong one: how many are left")
    ck = out["right"][1].lower()
    check(out["right"][0] == 200 and "lanowl_session=" in ck and "httponly" in ck and "samesite=lax" in ck
          and "max-age=2592000" in ck and "secure" not in ck, "the right one: an HttpOnly cookie for 30 days")
    check(out["in"] == "the dashboard" and out["api_in"] == 200 and out["in_state"] == "in", "which opens it")
    check(out["logout"] == 200 and out["api_out"] == 401, "Log out closes it again")
    check(out["off"] == 200, "web.login: false: open without a cookie")
    check(out["host"] == 421, "the host-name guard still comes first")


# --- 6. /password on Telegram -----------------------------------------------------------------
def test_password_on_telegram():
    print("\n-- /password on Telegram: the message is deleted --")
    from lanowl import chat as C
    from lanowl import main as m
    from lanowl.agent import LlmAgent
    from lanowl.model import Inventory
    from lanowl.sinks import MqttBridge
    from lanowl.state import StatusTracker
    from lanowl.tools import ToolExecutor
    out = {"replies": [], "calls": []}

    async def go(d):
        cfg = {"telegram": {"via": "direct", "chat_id": CHAT_ID, "outbox_file": os.path.join(d, "o.json")},
               "web": {"enabled": True}, "observer": {"host_ip": "192.168.88.5"}}
        inv, st = Inventory(devices=[]), StateStore(os.path.join(d, "s.sqlite"))
        mq = MqttBridge(cfg)
        ex = ToolExecutor(cfg, inv, mq, st)
        a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
        real = C.telegram_call

        async def call(cfg, method, payload, timeout_s=15):
            out["calls"].append((method, payload))
            return {"ok": method != "deleteMessage" or payload["message_id"] != 99}

        async def reply(chat_id, text):
            out["replies"].append(text)
        C.telegram_call = call
        a.chat._reply = reply
        try:
            await a.chat.on_telegram("/password", CHAT_ID, 7)
            await a.chat.on_telegram("short", CHAT_ID, 8)
            await a.chat.on_telegram("/password", CHAT_ID, 9)
            await a.chat.on_telegram(PW, CHAT_ID, 10)
            out["set"] = (a.login.source, L.verify(PW, a.login.hash))
            await a.chat.on_telegram("/password@lanowl_example_bot another password", CHAT_ID, 99)
            out["changed"] = L.verify("another password", a.login.hash)
            # after /password, a command cancels the wait
            await a.chat.on_telegram("/password", CHAT_ID, 11)
            await a.chat.on_telegram("/status", CHAT_ID, 12)
            out["kept"] = L.verify("another password", a.login.hash)
            out["record"] = str(st.load_record(L.RECORD))
        finally:
            C.telegram_call = real
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = out["replies"]
    deleted = [p["message_id"] for meth, p in out["calls"] if meth == "deleteMessage"]
    check("8 characters or more" in r[0], "/password asks for it")
    check(8 in deleted and "8 characters or more" in r[1], "a short one is deleted too, and refused")
    check(10 in deleted and out["set"] == ("Telegram", True) and "password set" in r[3],
          "the password is deleted and set")
    check(out["changed"] and 99 in deleted and "changed" in r[4] and "delete it yourself" in r[4],
          "/password in one go works; a message it could not delete is said")
    check(out["kept"] and 12 not in deleted, "a command cancels the wait")
    check(PW not in out["record"] and "another password" not in out["record"], "never the password itself")


# --- 7. --check ------------------------------------------------------------------------------
def test_report():
    print("\n-- --check: the dashboard needs a password --")
    base = {"telegram": {"chat": {"enabled": True}}, "state": {"db_path": "/nonexistent/x.sqlite"}}
    off = L.report({**base, "web": {"enabled": False}})
    good = L.report({**base, "web": {"enabled": True, "password_hash": L.hash_password(PW)}})
    raw = L.report({**base, "web": {"enabled": True, "password_hash": "hunter22"}})
    none = L.report({**base, "web": {"enabled": True}})
    nochat = L.report({"web": {"enabled": True}, "state": base["state"]})
    opened = L.report({**base, "web": {"enabled": True, "login": False}})
    check(off[1] == 0 and "off" in off[0], "no dashboard: nothing needed")
    check(good[1] == 0 and "✓ login" in good[0] and "config.yaml" in good[0], "config.yaml's: ✓")
    check(raw[1] == 1 and "not a password hash" in raw[0] and "hunter22" not in raw[0],
          "the password itself in password_hash: ✗, without repeating it")
    check(none[1] == 1 and "/password" in none[0] and "--hash-password" in none[0], "none: ✗, both ways named")
    check(nochat[1] == 1 and "/password" not in nochat[0], "no Telegram chat: only config.yaml")
    check(opened[1] == 0 and "○ login" in opened[0] and "web.login: false" in opened[0],
          "switched off: said, not a failure")
    with tempfile.TemporaryDirectory() as d:
        a = _A(d)
        L.Login(a).set_password(PW)
        tg = L.report({**a.cfg})
    check(tg[1] == 0 and "set on Telegram" in tg[0], "--check finds /password's in the state: ✓")


if __name__ == "__main__":
    for fn in [test_hash, test_sources, test_lock, test_sessions, test_page,
               test_password_on_telegram, test_report]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all login tests passed")
