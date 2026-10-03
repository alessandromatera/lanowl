"""Live updates: run with `python -m tests.test_stream` (inside the image: it needs aiohttp).

What these pin down: /api/stream sends the
state at once, then again only when something the page draws has changed — not when only the
time or a package list's age moved, which change on every read — and the guard leaves a
stream's own headers alone.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def test_fingerprint():
    from lanowl.web import _fingerprint, _sse
    a = {"now": 1, "sweep": {"ts": 5}, "updates": {"hosts": [{"ip": "x", "lists_age": 10}]}}
    b = {"now": 2, "sweep": {"ts": 5}, "updates": {"hosts": [{"ip": "x", "lists_age": 13}]}}
    c = {"now": 2, "sweep": {"ts": 6}, "updates": {"hosts": [{"ip": "x", "lists_age": 13}]}}
    check(_fingerprint(a) == _fingerprint(b), "only the time and a list's age moved: the same state")
    check(_fingerprint(a) != _fingerprint(c), "a new sweep: a new state")
    m = _sse("state", {"t": "two\nlines"}).decode()
    check(m.startswith("event: state\ndata: ") and m.endswith("\n\n") and m.count("\n") == 3,
          "one event, its data on one line (a newline inside is escaped)")


async def _stream():
    from aiohttp import ClientSession, ClientTimeout, web
    import lanowl.web as W
    states = [{"now": 1, "sweep": {"ts": 1}, "updates": {"hosts": [{"lists_age": 5}]}}]
    real = W.state_payload
    W.state_payload = lambda a, now=0.0: dict(states[-1])
    d = W.Dashboard.__new__(W.Dashboard)
    d.a, d._streams, d._push_task, d.allowed_hosts = object(), set(), None, set()

    @web.middleware
    async def guard(request, handler):
        return await d._guard(request, handler)

    app = web.Application(middlewares=[guard])
    app.router.add_get("/api/stream", d.api_stream)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    async def event(r, timeout):
        async def one():
            ev = data = None
            while True:
                line = (await r.content.readline()).decode().rstrip("\n")
                if line.startswith("event: "):
                    ev = line[7:]
                elif line.startswith("data: "):
                    data = line[6:]
                elif line == "" and ev:
                    return ev, data
        return await asyncio.wait_for(one(), timeout)

    try:
        async with ClientSession(timeout=ClientTimeout(total=30)) as s:
            async with s.get(f"http://127.0.0.1:{port}/api/stream") as r:
                check(r.headers.get("Content-Type", "").startswith("text/event-stream"), "an event stream")
                ev, data = await event(r, 5)
                check(ev == "state" and json.loads(data)["sweep"]["ts"] == 1, "the state at once")
                states.append({"now": 2, "sweep": {"ts": 1}, "updates": {"hosts": [{"lists_age": 9}]}})
                await asyncio.sleep(3)           # the pusher looks once: nothing to say
                states.append({"now": 3, "sweep": {"ts": 2}, "updates": {"hosts": [{"lists_age": 9}]}})
                ev, data = await event(r, 6)
                check(ev == "state" and json.loads(data)["sweep"]["ts"] == 2,
                      "the next event is the new sweep — nothing was pushed for the time moving")
    finally:
        W.state_payload = real
        if d._push_task:
            d._push_task.cancel()
        await runner.cleanup()


if __name__ == "__main__":
    try:
        import aiohttp  # noqa: F401
    except ImportError:
        print("aiohttp is not installed here — the stream tests run inside the image")
        sys.exit(0)
    test_fingerprint()
    asyncio.run(_stream())
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all stream tests passed")
