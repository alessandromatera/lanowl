"""Router API client tests: run with `python -m tests.test_routeros`.

A fake RouterOS speaks the API's wire format on localhost, so the client meets the same
framing, tags, `!trap`s and dropped sockets a RouterOS 7 router will hand it. What is pinned down:

  1. the framing: word lengths across every size boundary, `=a=b=c` values;
  2. one socket carries many commands: a slow one does not hold up a fast one or the log
     stream beside it, a timeout cancels on the router and leaves the connection alone;
  3. the kept connection: ONE login however many reads, a heartbeat, a reconnect after the
     router drops it, the follow re-issued on the new connection;
  4. the fallback: API unreachable -> REST, so nothing that reads the router goes blind;
  5. the pin: a certificate that is not the pinned one gets no password;
  6. the WAN watcher on a followed log: a link edge is acted on without waiting for the
     minute's scan, a scan reads no buffer while followed, and a rights change logs in again.
"""
from __future__ import annotations

import asyncio
import datetime
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
# the router's read-only login, as a deployment may give it: from the environment
os.environ["LANOWL_MIKROTIK_USER"], os.environ["LANOWL_MIKROTIK_PASS"] = "lanowl", "p"

from lanowl import probes, routeros
from lanowl.routeros import ApiError, Connection, Router
from lanowl.wanwatch import WanWatcher

_fails = []


def check(cond, msg):
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        _fails.append(msg)


# --- a fake router ------------------------------------------------------------------------
class FakeRouter:
    """Enough of RouterOS's API: /login, prints from a table, a slow command, a follow, a
    /cancel, `!trap` for anything unknown — and the ability to drop every socket or to stop
    answering, which is what a reboot looks like from outside."""

    def __init__(self, tables=None, user="lanowl", password="p"):
        self.tables = tables or {}
        self.user, self.password = user, password
        self.logins = 0
        self.commands = []            # every command word received, in order
        self.cancelled = []
        self.follows = []             # (writer, tag) of running follow-only commands
        self.writers = []
        self.mute = False             # stop answering (a hung router)
        self.server = None
        self.port = 0
        self.ssl = None

    async def start(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0, ssl=self.ssl)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.kick()
        self.server.close()
        await self.server.wait_closed()

    def kick(self):
        for w in self.writers:
            try:
                w.close()
            except Exception:
                pass
        self.writers, self.follows = [], []

    def _say(self, w, *words):
        w.write(routeros.encode(list(words)))

    def push(self, row: dict):
        for w, tag in list(self.follows):
            self._say(w, "!re", *[f"={k}={v}" for k, v in row.items()], f".tag={tag}")

    async def _client(self, reader, writer):
        self.writers.append(writer)
        try:
            while True:
                words = await routeros.read_sentence(reader)
                cmd, tag, attrs = routeros.parse(words)
                self.commands.append(cmd)
                if self.mute:
                    continue
                asyncio.ensure_future(self._answer(writer, cmd, tag, attrs))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass

    async def _answer(self, w, cmd, tag, attrs):
        t = f".tag={tag}"
        if cmd == "/login":
            if attrs.get("name") == self.user and attrs.get("password") == self.password:
                self.logins += 1
                self._say(w, "!done", t)
            else:
                self._say(w, "!trap", "=message=invalid user name or password (6)", t)
                self._say(w, "!done", t)
        elif cmd == "/cancel":
            self.cancelled.append(attrs.get("tag"))
            self.follows = [(x, g) for x, g in self.follows if g != attrs.get("tag")]
            self._say(w, "!trap", "=category=2", "=message=interrupted", f".tag={attrs.get('tag')}")
            self._say(w, "!done", f".tag={attrs.get('tag')}")
            self._say(w, "!done", t)
        elif cmd == "/log/print" and "follow-only" in attrs:
            self.follows.append((w, tag))
        elif cmd == "/slow":
            await asyncio.sleep(float(attrs.get("s", "0.5")))
            self._say(w, "!re", "=v=slow", t)
            self._say(w, "!done", t)
        elif cmd == "/empty/print":
            self._say(w, "!empty", t)
            self._say(w, "!done", t)
        elif cmd.endswith("/print") and cmd[:-6] in self.tables:
            for row in self.tables[cmd[:-6]]:
                self._say(w, "!re", *[f"={k}={v}" for k, v in row.items()], t)
            self._say(w, "!done", t)
        elif cmd == "/system/identity/print":
            self._say(w, "!re", "=name=hAP", t)
            self._say(w, "!done", t)
        elif cmd in self.tables:              # a command (ping, torch…) answers its rows
            for row in self.tables[cmd]:
                self._say(w, "!re", *[f"={k}={v}" for k, v in row.items()], t)
            self._say(w, "!done", t)
        else:
            self._say(w, "!trap", "=message=no such command or directory (x)", t)
            self._say(w, "!done", t)


def cfg_for(port, **api):
    a = {"enabled": True, "host": "127.0.0.1", "port": port, "tls": False,
         "heartbeat_s": 0.2, "timeout_s": 1, "retry_s": 0.1}
    a.update(api)
    return {"mikrotik": {"dhcp_source": "http://127.0.0.1",
                         "api": a},
            "wan": {"targets": ["8.8.8.8"],
                    "watch": {"enabled": True, "interval_s": 15, "fail_checks": 2,
                              "log_interval_s": 60, "log_down_match": "Fiber DOWN",
                              "log_up_match": "Fiber UP", "flap_hold_s": 60,
                              "log_triage": {"enabled": False}},
                    "path": {"interval_s": 300, "route_comment": "Fiber",
                             "main": "fiber", "backup": "antenna"}},
            "probes": {"icmp_timeout_ms": 500},
            "alerts": {"recovery_confirm_s": 900, "cooldown_s": 3600}}


async def settle(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        await asyncio.sleep(0.02)
    return cond()


def rest_stub(calls, rows=None):
    async def _r(base, path, user, pw, verify=False, timeout_ms=5000):
        calls.append(path)
        return probes.ProbeResult(True, None, "mikrotik", {"json": rows if rows is not None else [{"via": "rest"}]})
    probes.mikrotik_rest = _r


# --- 1. framing ---------------------------------------------------------------------------
def test_framing():
    print("\n-- the wire format --")

    async def go():
        sizes = [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000]
        words = ["x" * n for n in sizes if n] + ["=message=a=b=c", "=.id=*1A", ".tag=7"]
        r = asyncio.StreamReader()
        r.feed_data(routeros.encode(words))
        r.feed_eof()
        back = await routeros.read_sentence(r)
        return words, back

    words, back = asyncio.run(go())
    check(back == words, "every length boundary survives the round trip (up to 2 MiB words)")
    kind, tag, attrs = routeros.parse(["!re", "=message=a=b=c", "=.id=*1A", ".tag=7"])
    check((kind, tag, attrs) == ("!re", "7", {"message": "a=b=c", ".id": "*1A"}),
          "`=message=a=b=c` keeps its '=' and `.tag` is lifted out")
    check(routeros.command_words("/ping", {"address": "1.1.1.1", "once": ""}, None, "3") ==
          ["/ping", "=address=1.1.1.1", "=once=", ".tag=3"],
          "REST's flag `once: \"\"` becomes the API's `=once=`")


# --- 2. one socket, many commands --------------------------------------------------------
def test_multiplexing_and_timeouts():
    print("\n-- one socket carries many commands --")

    async def go():
        fr = await FakeRouter({"/ip/route": [{"dst-address": "0.0.0.0/0", "comment": "Fiber",
                                              "active": "true"}]}).start()
        c = await Connection.open("127.0.0.1", fr.port, "lanowl", "p", tls=False)
        seen = []
        c.stream("/log/print", {"follow-only": ""}, seen.append, lambda why: None)
        slow = asyncio.ensure_future(c.call("/slow", {"s": "0.6"}, timeout_s=3))
        t0 = time.time()
        fast = await c.call("/ip/route/print", timeout_s=3)
        fast_s = time.time() - t0
        await settle(lambda: fr.follows)
        fr.push({".id": "*1", "time": "2026-09-25 10:00:00", "message": "hello"})
        await settle(lambda: seen)
        mid_stream = list(seen)
        slow_rows = await slow
        # a trap is an answer, not a dead connection
        try:
            await c.call("/nope/print", timeout_s=2)
            trapped = None
        except ApiError as e:
            trapped = str(e)
        empty = await c.call("/empty/print", timeout_s=2)
        # a timeout cancels on the router and leaves the connection usable
        try:
            await c.call("/slow", {"s": "2"}, timeout_s=0.2)
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
        await settle(lambda: fr.cancelled)
        after = await c.call("/ip/route/print", timeout_s=2)
        out = dict(fast=fast, fast_s=fast_s, mid=mid_stream, slow=slow_rows, trapped=trapped,
                   empty=empty, timed_out=timed_out, cancelled=list(fr.cancelled),
                   after=after, closed=c.closed, logins=fr.logins)
        c.close()
        await fr.stop()
        return out

    o = asyncio.run(go())
    check(o["fast"] and o["fast"][0]["comment"] == "Fiber" and o["fast_s"] < 0.4,
          f"a quick read is answered while a slow command runs ({o['fast_s']:.2f}s)")
    check(o["mid"] and o["mid"][0]["message"] == "hello",
          "a followed log line arrives while the slow command is still running")
    check(o["slow"] == [{"v": "slow"}], "...and the slow command still gets its own answer")
    check(o["trapped"] and "no such command" in o["trapped"], "a !trap raises ApiError with the router's words")
    check(o["empty"] == [], "7.18's `!empty` + `!done` is an empty answer, not a hang")
    check(o["timed_out"] and o["cancelled"], "a timeout sends /cancel for that tag")
    check(o["after"] and not o["closed"], "...and the connection is still good afterwards")
    check(o["logins"] == 1, "all of that was ONE login")


# --- 3. the kept connection ---------------------------------------------------------------
def test_one_login_heartbeat_reconnect_refollow():
    print("\n-- the kept connection: one login, heartbeat, reconnect, follow re-issued --")

    async def go():
        fr = await FakeRouter({"/interface": [{"name": "ether1", "running": "true"}]}).start()
        r = Router(cfg_for(fr.port))
        states, rows = [], []
        r.follow("log", "/log/print", {"follow-only": ""}, rows.append,
                 lambda live, why: states.append(live))
        await settle(lambda: r.up and fr.follows)
        reads = [await r.read("interface") for _ in range(20)]
        await asyncio.sleep(0.5)                  # a couple of heartbeats
        beats = fr.commands.count("/system/identity/print")
        logins_before = fr.logins
        fr.kick()                                 # the router reboots
        await settle(lambda: states[-1:] == [False])
        down_seen = states[-1:] == [False]
        await settle(lambda: r.up and fr.follows, timeout=5)
        fr.push({".id": "*9", "time": "2026-09-25 10:00:00", "message": "after reboot"})
        await settle(lambda: rows)
        out = dict(ok=all(x.ok for x in reads), via=reads[0].data["json"][0]["name"],
                   logins_before=logins_before, beats=beats, down_seen=down_seen,
                   logins=fr.logins, states=list(states), rows=list(rows),
                   connects=r.connects, rest=r.rest_calls)
        await r.stop()
        await fr.stop()
        return out

    o = asyncio.run(go())
    check(o["ok"] and o["via"] == "ether1" and o["logins_before"] == 1,
          "twenty reads, one login (REST: a session and three log lines every ~10 min)")
    check(o["beats"] >= 2, f"the heartbeat runs on its own ({o['beats']} in 0.5s at 0.2s)")
    check(o["down_seen"], "a dropped socket tells the follower at once")
    check(o["logins"] == 2 and o["connects"] == 2, "the keeper logs in again by itself after the drop")
    check(o["states"] == [True, False, True], f"follow: live, lost, live again ({o['states']})")
    check(o["rows"] and o["rows"][0]["message"] == "after reboot",
          "the follow was re-issued on the new connection")
    check(o["rest"] == 0, "and nothing fell back to REST while the API was there")


def test_a_hung_router_is_dropped():
    print("\n-- a router that stops answering is dropped by the heartbeat --")

    async def go():
        fr = await FakeRouter().start()
        r = Router(cfg_for(fr.port, timeout_s=0.3))
        await r._ensure()
        states = []
        r.follow("log", "/log/print", {"follow-only": ""}, lambda row: None,
                 lambda live, why: states.append((live, why)))
        r.start()
        fr.mute = True
        lost = await settle(lambda: any(not live for live, _ in states), timeout=3)
        why = next((w for live, w in states if not live), "")
        fr.mute = False
        back = await settle(lambda: r.up and states[-1][0], timeout=5)
        await r.stop()
        await fr.stop()
        return lost, why, back

    lost, why, back = asyncio.run(go())
    check(lost and "heartbeat" in why, f"no answer within timeout_s -> connection dropped ({why})")
    check(back, "...and reopened once the router answers again")


# --- 4. the fallback ----------------------------------------------------------------------
def test_api_down_falls_back_to_rest():
    print("\n-- API unreachable: every read still answers, over REST --")
    real = probes.mikrotik_rest
    calls = []
    rest_stub(calls, [{"name": "ether1"}])

    async def go():
        s = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = s.sockets[0].getsockname()[1]
        s.close()
        await s.wait_closed()                     # nothing listens there now
        r = Router(cfg_for(port))
        a = await r.read("interface")
        b = await r.read("interface")             # within the backoff: straight to REST
        st = r.status()
        await r.stop()
        return a, b, st

    try:
        a, b, st = asyncio.run(go())
    finally:
        probes.mikrotik_rest = real
    check(a.ok and a.data["json"][0]["name"] == "ether1", "the read is answered over REST")
    check(b.ok and calls == ["interface", "interface"], "...and the next one too, without re-trying the API")
    check(st["via"] == "rest" and st["rest_fallbacks"] == 2 and st["error"],
          f"status says so: via rest, {st['rest_fallbacks']} fallback(s), '{st['error'][:40]}'")

    calls.clear()
    rest_stub(calls)

    async def disabled():
        r = Router({"mikrotik": {}})
        x = await r.read("log")
        return x, r.status()

    try:
        x, st = asyncio.run(disabled())
    finally:
        probes.mikrotik_rest = real
    check(x.ok and calls == ["log"] and st["rest_fallbacks"] == 0,
          "API not configured: plain REST, as before, and not counted as a fallback")

    # the router takes the connection and drops it before answering the login — what a
    # service restricted to another address, or a reboot mid-handshake, looks like
    calls.clear()
    rest_stub(calls)

    async def hangup():
        async def drop(reader, writer):
            await routeros.read_sentence(reader)
            writer.close()
        s = await asyncio.start_server(drop, "127.0.0.1", 0)
        r = Router(cfg_for(s.sockets[0].getsockname()[1]))
        try:
            x = await r.read("log")
            raised = None
        except Exception as e:           # the contract: never
            x, raised = None, e
        st = r.status()
        await r.stop()
        s.close()
        await s.wait_closed()
        return x, raised, st

    try:
        x, raised, st = asyncio.run(hangup())
    finally:
        probes.mikrotik_rest = real
    check(raised is None and x is not None and x.ok and calls == ["log"],
          f"dropped during login: the read is still answered over REST ({raised!r})")
    check("ApiDown" in st["error"], f"...and the reason is kept ({st['error'][:50]})")


def test_a_refused_login_is_not_repeated():
    """A 401 is the router refusing the login — a wrong password, or a user allowed only from
    another address. Every try writes a critical "login failure" line in the router's log, so
    lanowl asks once, says what to check, and waits until the login changes or 15 min pass."""
    print("\n-- a login the router refuses is asked once, not every minute --")
    real = probes.mikrotik_rest
    calls = []

    async def refuse(base, path, user, pw, verify=False, timeout_ms=5000):
        calls.append((path, user, pw))
        return probes.ProbeResult(False, None, "mikrotik http 401")
    probes.mikrotik_rest = refuse
    before = {k: os.environ.get(k) for k in ("LANOWL_MIKROTIK_USER", "LANOWL_MIKROTIK_PASS")}
    os.environ.update(LANOWL_MIKROTIK_USER="lanowl", LANOWL_MIKROTIK_PASS="old")
    cfg = {"mikrotik": {"dhcp_source": "http://192.168.88.1"}, "observer": {"host_ip": "192.168.88.5"}}

    async def go():
        r = Router(cfg)
        a = await r.read("ip/dhcp-server/lease")
        b = await r.read("log")
        os.environ["LANOWL_MIKROTIK_PASS"] = "new"          # the owner fixed secrets.yaml
        c = await r.read("log")
        return a, b, c

    import logging
    seen = []
    h = logging.Handler()
    h.emit = lambda rec: seen.append(rec.getMessage())
    logging.getLogger("lanowl.routeros").addHandler(h)
    try:
        a, b, c = asyncio.run(go())
    finally:
        probes.mikrotik_rest = real
        logging.getLogger("lanowl.routeros").removeHandler(h)
        for k, v in before.items():                        # the other tests' login, back
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    check(not a.ok and not b.ok and len(calls) == 2, f"refused: the next read does not ask ({len(calls)} asks)")
    check("refused the login 'lanowl'" in b.detail and "secrets.yaml" in b.detail,
          f"...and says why ({b.detail[:60]})")
    check(calls[-1][2] == "new", "a changed password is tried at once")
    warn = [m for m in seen if "HTTP 401" in m]
    check(len(warn) == 2 and "192.168.88.5" in warn[0] and "address=" in warn[0],
          "said once per refusal, with what to check: the password, and this host's address")
    check(not any("old" in m or "new" in m.split("HTTP")[0] for m in warn), "never the password")


def test_rest_only_paths_go_to_rest():
    print("\n-- a path only REST understands is answered by REST --")
    real = probes.mikrotik_rest
    calls = []
    rest_stub(calls, {"name": "ether1"})

    async def go():
        fr = await FakeRouter({"/ping": [{"seq": "0", "received": "1"}]}).start()
        r = Router(cfg_for(fr.port))
        a = await r.read("interface/ether1")     # REST: one item by name; API: no such menu
        b = await r.request("POST", "ping", {"address": "127.0.0.1", "count": "1"})
        c = await r.request("POST", "tool/nope", {})
        await r.stop()
        await fr.stop()
        return a, b, c

    try:
        a, b, c = asyncio.run(go())
    finally:
        probes.mikrotik_rest = real
    check(a.ok and calls == ["interface/ether1"], "GET interface/ether1 -> REST")
    check(b == [{"seq": "0", "received": "1"}], "POST ping runs as the API command /ping")
    check(isinstance(c, dict) and "no such command" in c.get("error", ""),
          "a refused command is reported, not retried over REST")


# --- 5. the pin ---------------------------------------------------------------------------
def _selfsigned(d):
    if not shutil.which("openssl"):
        return None
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=192.168.10.1", "-keyout", key, "-out", crt],
                   check=True, capture_output=True)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(crt, key)
    der = ssl.PEM_cert_to_DER_cert(open(crt).read())
    return ctx, routeros.fingerprint_of(der)


def test_the_pin():
    print("\n-- TLS: the pinned certificate gets the password, another one does not --")
    with tempfile.TemporaryDirectory() as d:
        made = _selfsigned(d)
        if made is None:
            print("  skip (no openssl)")
            return
        ctx, fp = made

        async def go():
            fr = FakeRouter()
            fr.ssl = ctx
            await fr.start()
            good = Router(cfg_for(fr.port, tls=True, fingerprint=":".join(
                fp[i:i + 2].upper() for i in range(0, len(fp), 2))))   # as RouterOS prints it
            ok = await good.read("empty")
            await good.stop()
            bad = Router(cfg_for(fr.port, tls=True, fingerprint="00" * 32))
            real = probes.mikrotik_rest
            rest_stub([])
            try:
                await bad.read("empty")
            finally:
                probes.mikrotik_rest = real
            st = bad.status()
            retry_in = bad._retry_at - time.time()
            await bad.stop()
            unpinned = Router(cfg_for(fr.port, tls=True))
            await unpinned.read("empty")
            ufp = unpinned.conn.fingerprint if unpinned.conn else ""
            await unpinned.stop()
            await fr.stop()
            return ok, fr.logins, st, retry_in, ufp

        ok, logins, st, retry_in, ufp = asyncio.run(go())
        check(ok.ok and ok.detail == "mikrotik", "pinned (in RouterOS's AA:BB:… form): connected over TLS")
        check(logins == 2, "the wrong pin sent no login (2 = the pinned one + the unpinned one)")
        check("not the pinned one" in st["error"] and retry_in > 600,
              "a pin mismatch is reported and not retried for a long while")
        check(ufp == fp, "unpinned: connects, and knows the fingerprint to pin")


# --- 6. the WAN watcher on a followed log ------------------------------------------------
def _stamp(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def test_watcher_follows_the_log():
    print("\n-- the WAN watcher on a followed log --")
    now = datetime.datetime.now().replace(microsecond=0)
    buffer = [{".id": f"*{i:X}", "time": _stamp(now - datetime.timedelta(minutes=30 - i)),
               "topics": "system,info", "message": f"line {i}"} for i in range(1, 11)]
    routes = [{"dst-address": "0.0.0.0/0", "comment": "Fiber", "active": "true",
               "disabled": "false"}]

    async def go():
        fr = await FakeRouter({"/log": buffer, "/ip/route": routes}).start()
        cfg = cfg_for(fr.port)
        routeros._shared = None
        router = routeros.shared(cfg)
        alerts = []
        w = WanWatcher(cfg, lambda text, key="": alerts.append(text))
        real_ping = probes.ping

        async def up(ip, timeout_ms=1000, count=2):
            return probes.ProbeResult(True, 1.0, "icmp")
        probes.ping = up
        task = asyncio.ensure_future(w.run())
        try:
            await settle(lambda: w._live and w._watermark is not None and not w._resync, 3)
            await settle(lambda: w.path is not None, 3)
            prints_after_prime = fr.commands.count("/log/print")
            path0 = dict(w.path or {})
            fresh = w.path_is_fresh(time.time())

            # the fiber drops: the router disables the route and writes the line
            routes[0]["disabled"], routes[0]["active"] = "true", "false"
            t_down = now + datetime.timedelta(seconds=1)
            fr.push({".id": "*20", "time": _stamp(t_down), "topics": "script,info",
                     "message": "Fiber DOWN - health IP disabled"})
            on_backup = await settle(lambda: (w.path or {}).get("on_backup"), 3)
            pending = w._pending_down

            routes[0]["disabled"], routes[0]["active"] = "false", "true"
            fr.push({".id": "*21", "time": _stamp(t_down + datetime.timedelta(seconds=57)),
                     "topics": "script,info", "message": "Fiber UP - health IP enabled"})
            flapped = await settle(lambda: len(w.flaps) == 1, 3)
            back = await settle(lambda: not (w.path or {}).get("on_backup"), 3)
            full_reads = fr.commands.count("/log/print") - prints_after_prime

            # a scan while followed reads nothing from the router
            before = len(fr.commands)
            await w._scan_log()
            scan_cmds = fr.commands[before:]
            in_copy = [x["message"] for x in w.router_log("Fiber")]

            # the owner changes lanowl's group: log in again for the new rights
            logins = fr.logins
            fr.push({".id": "*22", "time": _stamp(t_down + datetime.timedelta(seconds=90)),
                     "topics": "system,info",
                     "message": "user group lanowl-ro changed by admin (policy=read,test,sniff,api,rest-api)"})
            prints = fr.commands.count("/log/print")
            relogged = await settle(lambda: fr.logins == logins + 1 and w._live, 3)
            resynced = await settle(lambda: not w._resync
                                    and fr.commands.count("/log/print") == prints + 2, 3)
        finally:
            w.stop()
            task.cancel()
            probes.ping = real_ping
            await router.stop()
            await fr.stop()
            routeros._shared = None
        return dict(prints=prints_after_prime, path0=path0, fresh=fresh, on_backup=on_backup,
                    pending=pending, flapped=flapped, flap=w.flaps[:1], back=back,
                    full_reads=full_reads, scan_cmds=scan_cmds, in_copy=in_copy,
                    relogged=relogged, resynced=resynced, alerts=alerts)

    o = asyncio.run(go())
    check(o["prints"] == 2, f"primed from ONE full read plus the follow ({o['prints']} /log/print)")
    check(o["path0"].get("link") == "fiber" and o["fresh"],
          "the watcher reads the route itself over the API (the sweep can skip its poll)")
    check(o["on_backup"] and o["pending"] is not None,
          "Fiber DOWN: acted on within a second — route re-read, on the antenna — not at the minute's scan")
    check(o["flapped"] and abs(o["flap"][0].seconds - 57) < 1 if o["flap"] else False,
          "Fiber UP: the 57s flap is recorded with the router's own timestamps")
    check(o["back"], "...and the route is back on the fiber")
    check(o["full_reads"] == 0, "no full re-read of the buffer for any of it")
    check("/log/print" not in o["scan_cmds"], f"a scan while followed reads the kept copy ({o['scan_cmds']})")
    check(any("Fiber DOWN" in m for m in o["in_copy"]), "router_log() sees the followed lines")
    check(o["relogged"], "a change to lanowl's group logs in again (an API session keeps its old rights)")
    check(o["resynced"], "...and the new follow re-reads the buffer once, at once")


def test_rights_change_matches_only_ours():
    cfg = cfg_for(1)
    w = WanWatcher(cfg, lambda text, key="": None)
    yes = ["user group lanowl-ro changed by admin (policy=read,api)",
           "user lanowl changed by admin (group=full)"]
    no = ["user group full changed by admin (policy=read)", "user admin changed by admin",
          "user lanowl logged in from 192.168.10.103 via api"]
    check(all(w._rights_changed(m) for m in yes) and not any(w._rights_changed(m) for m in no),
          "only lanowl's own user or group counts as a rights change")


def test_arp_check_in_the_sweep():
    """`{type: arp}`: the router ARP-pings a device that answers nothing else (the thermostat)."""
    from lanowl import sweep
    from lanowl.model import Device
    asked = []

    class FakeRouter:
        def __init__(self, answer):
            self.answer = answer

        async def request(self, method, path, body=None, timeout_s=None):
            asked.append((method, path, body))
            return self.answer

    def run(answer):
        real = routeros.shared
        routeros.shared = lambda cfg: FakeRouter(answer)
        try:
            dev = Device("192.168.10.121", "Thermostat", "home", "warning")
            return asyncio.run(sweep._run_check(dev, {"type": "arp"}, {}, asyncio.Semaphore(1)))
        finally:
            routeros.shared = real
    up = run([{"host": "02:00:5E:10:00:06", "sent": "1", "received": "1", "avg-rtt": "80ms118us"},
              {"host": "02:00:5E:10:00:06", "sent": "2", "received": "2", "avg-rtt": "85ms453us"}])
    check(up.ok and abs(up.latency_ms - 85.453) < 0.001 and "02:00:5E:10:00:06" in up.detail,
          f"an ARP reply is up, with the router's average as latency ({up.detail})")
    check(asked[0] == ("POST", "ping", {"address": "192.168.10.121", "arp-ping": "yes",
                                        "interface": "bridge-lan", "count": "3", "interval": "0.3"}),
          "asked on the LAN bridge, three tries")
    down = run([{"host": "192.168.10.121", "status": "timeout", "sent": "3", "received": "0"}])
    check(not down.ok and down.detail == "no ARP reply", "no reply is down")
    blind = run({"error": "not enough permissions (9)"})
    check(blind.ok and "not checked" in blind.detail,
          "a router that cannot ask says nothing about the device: not claimed as down")


if __name__ == "__main__":
    for fn in [test_framing, test_multiplexing_and_timeouts,
               test_one_login_heartbeat_reconnect_refollow, test_a_hung_router_is_dropped,
               test_api_down_falls_back_to_rest, test_a_refused_login_is_not_repeated,
               test_rest_only_paths_go_to_rest, test_the_pin,
               test_watcher_follows_the_log, test_rights_change_matches_only_ours,
               test_arp_check_in_the_sweep]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all router API tests passed")
