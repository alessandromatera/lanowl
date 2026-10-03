"""The main router over its classic API (api-ssl): ONE connection, logged in once, kept open.

Why not REST for everything: over plain HTTP the password crosses the LAN with each request,
and behind REST RouterOS opens an internal API session roughly every ten minutes. Each one
writes three log lines ("logged in from <us> via rest-api", "logged in via api", "logged out
via api") and leaves one `/user active` entry that is never removed (a RouterOS bug seen from
7.16 through 7.24.2: thousands of entries after a few weeks). Measured on a busy router, those
lines were 43% of a 10,000-line log buffer, so the log that the WAN history, `router_log` and
the triage all read reached back only ten days.

Over one kept connection: one login per router reboot, one `/user active` entry that goes away
with us, and the log can be FOLLOWED — a link-down line arrives in about a second instead of
at the next one-minute re-read of the whole buffer.

Two layers:

    Connection  one TLS socket. Sentences out, sentences in, each reply routed to its command
                by `.tag`, so a ten-second torch never holds up the log stream beside it.
    Router      keeps a Connection alive: a heartbeat every `heartbeat_s`, reconnect with
                backoff after a reboot, follow subscriptions re-issued on every new
                connection. `read`/`request` take the same paths as REST and FALL BACK to
                REST whenever the API is not up — a dead connection must never blind the WAN
                watcher, and a missing certificate must not switch discovery off.

The certificate is self-signed, so trust is a pinned SHA-256 fingerprint (`mikrotik.api.
fingerprint`), checked BEFORE the password is sent. Unpinned, the link is still encrypted but
not authenticated, and that is logged with the fingerprint to pin.

Nothing here sends a command the REST code did not already send; the user's group has no
`write` either way.
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import logging
import socket
import ssl
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from . import probes
from .discovery import resolve_mikrotik

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

log = logging.getLogger("lanowl.routeros")


class ApiError(Exception):
    """The router answered `!trap`: it refused the command or the command failed. REST would
    have been told the same, so this is never a reason to fall back."""


class ApiDown(Exception):
    """No usable connection: never opened, closed, or lost in the middle of a command."""


# --- the wire format ----------------------------------------------------------------------
# A word is its length (1-5 bytes, the high bits saying how many) followed by that many bytes;
# a sentence is words ended by an empty one. That is the whole framing.
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xf0" + n.to_bytes(4, "big")


def encode(words) -> bytes:
    out = bytearray()
    for w in words:
        b = w.encode("utf-8")
        out += _enc_len(len(b)) + b
    out += b"\x00"
    return bytes(out)


async def _read_len(r: asyncio.StreamReader) -> int:
    b = (await r.readexactly(1))[0]
    if b < 0x80:
        return b
    if b < 0xC0:
        return ((b & 0x3F) << 8) | (await r.readexactly(1))[0]
    if b < 0xE0:
        return ((b & 0x1F) << 16) | int.from_bytes(await r.readexactly(2), "big")
    if b < 0xF0:
        return ((b & 0x0F) << 24) | int.from_bytes(await r.readexactly(3), "big")
    return int.from_bytes(await r.readexactly(4), "big")


async def read_sentence(r: asyncio.StreamReader) -> list:
    words = []
    while True:
        n = await _read_len(r)
        if n == 0:
            return words
        # RouterOS stores bytes; DHCP host names are whatever the client sent
        words.append((await r.readexactly(n)).decode("utf-8", "replace"))


def parse(words: list) -> tuple:
    """(`!re`|`!done`|`!trap`|`!empty`|`!fatal`, tag or None, {attribute: value})."""
    kind, tag, attrs = (words[0] if words else ""), None, {}
    for w in words[1:]:
        if w.startswith(".tag="):
            tag = w[5:]
        elif w.startswith("="):
            k, _, v = w[1:].partition("=")     # a value may itself contain '='
            attrs[k] = v
    return kind, tag, attrs


def command_words(cmd: str, attrs: Optional[dict] = None, query=None, tag: str = "") -> list:
    words = [cmd] + [f"={k}={'' if v is None else v}" for k, v in (attrs or {}).items()]
    words += [f"?{q}" for q in (query or [])]
    if tag:
        words.append(f".tag={tag}")
    return words


def fingerprint_of(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _norm_fp(s: str) -> str:
    return "".join(c for c in str(s or "").lower() if c in "0123456789abcdef")


# --- one connection -----------------------------------------------------------------------
class _Pending:
    __slots__ = ("rows", "error", "future", "on_row", "on_end")

    def __init__(self, future=None, on_row=None, on_end=None):
        self.rows, self.error = [], None
        self.future, self.on_row, self.on_end = future, on_row, on_end


class Connection:
    """One logged-in api-ssl socket. `call` for a command that ends, `stream` for one that
    does not (`follow-only`), both multiplexed on the same socket by tag."""

    def __init__(self, reader, writer):
        self._r, self._w = reader, writer
        self._pending: dict = {}
        self._tags = itertools.count(1)
        self.closed = False
        self.why = ""
        self.fingerprint = ""
        self.serial = 0           # which of the Router's connections this is (1, 2, …)
        self._task = asyncio.ensure_future(self._read_loop())

    @classmethod
    async def open(cls, host: str, port: int, user: str, password: str,
                   fingerprint: str = "", timeout_s: float = 10.0, tls: bool = True):
        ctx = None
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # self-signed: the pin below is the trust
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx), timeout_s)
        _keepalive(writer.get_extra_info("socket"))
        got = ""
        if tls:
            got = fingerprint_of(writer.get_extra_info("ssl_object").getpeercert(binary_form=True))
            want = _norm_fp(fingerprint)
            if want and got != want:
                writer.close()
                raise ApiError(f"the router's certificate is not the pinned one "
                               f"(got sha256 {got[:16]}…, pinned {want[:16]}…) — password not sent")
        conn = cls(reader, writer)
        conn.fingerprint = got
        try:
            await conn.call("/login", {"name": user, "password": password}, timeout_s=timeout_s)
        except BaseException as e:
            conn.close(f"login failed: {e}")
            raise
        return conn

    def _send(self, words: list):
        if self.closed:
            raise ApiDown(self.why or "closed")
        self._w.write(encode(words))

    async def call(self, cmd: str, attrs: Optional[dict] = None, query=None,
                   timeout_s: float = 10.0) -> list:
        """Run a command to its `!done` and return its `!re` rows.

        On a timeout the command is cancelled on the router and asyncio.TimeoutError raised;
        the connection itself is left alone — slow is not dead, the heartbeat decides that."""
        if self.closed:
            raise ApiDown(self.why or "closed")
        tag = str(next(self._tags))
        p = _Pending(future=asyncio.get_running_loop().create_future())
        self._pending[tag] = p
        try:
            self._send(command_words(cmd, attrs, query, tag))
            return await asyncio.wait_for(p.future, timeout_s)
        except asyncio.TimeoutError:
            self.cancel(tag)
            raise
        finally:
            self._pending.pop(tag, None)

    def stream(self, cmd: str, attrs: Optional[dict], on_row: Callable[[dict], None],
               on_end: Callable[[Optional[str]], None]) -> str:
        """Start a command that keeps answering; every row goes to `on_row` as it arrives.
        `on_end(why)` once when it stops: the router ended it, or the connection went."""
        tag = str(next(self._tags))
        self._pending[tag] = _Pending(on_row=on_row, on_end=on_end)
        try:
            self._send(command_words(cmd, attrs, None, tag))
        except ApiDown:
            self._pending.pop(tag, None)
            raise
        return tag

    def cancel(self, tag: str):
        """Stop a running command. Its late `!trap interrupted`/`!done` land on no one."""
        self._pending.pop(tag, None)
        if not self.closed:
            try:
                self._send(command_words("/cancel", {"tag": tag}, None, f"c{tag}"))
            except Exception:
                pass

    async def _read_loop(self):
        why = "connection closed by the router"
        try:
            while True:
                words = await read_sentence(self._r)
                kind, tag, attrs = parse(words)
                if kind == "!fatal":
                    # the reason is a bare word, not an attribute
                    why = "router ended the session: " + (words[1] if len(words) > 1 else "fatal")
                    break
                p = self._pending.get(tag)
                if p is None:
                    continue          # a cancelled command's tail, or /cancel's own !done
                if kind == "!re":
                    if p.on_row is None:
                        p.rows.append(attrs)
                    else:
                        try:
                            p.on_row(attrs)
                        except Exception:      # a consumer's bug must not end the socket
                            log.exception("router API: stream consumer failed")
                elif kind == "!trap":
                    p.error = attrs.get("message") or "the router refused the command"
                elif kind in ("!done", "!empty"):
                    # 7.18+ answers an empty print with `!empty` and then `!done`: finishing at
                    # the first leaves the second to fall on an unknown tag, which is ignored
                    self._pending.pop(tag, None)
                    self._finish(p)
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            why = self.why or "closed"
        except Exception as e:
            why = f"{type(e).__name__}: {e}"
        self._fail_all(why)

    def _finish(self, p: _Pending):
        if p.future is not None:
            if not p.future.done():
                if p.error is not None:
                    p.future.set_exception(ApiError(p.error))
                else:
                    p.future.set_result(p.rows)
        elif p.on_end is not None:
            p.on_end(p.error or "the router ended the command")

    def _fail_all(self, why: str):
        if not self.closed:
            self.closed, self.why = True, why
        pend, self._pending = list(self._pending.values()), {}
        for p in pend:
            if p.future is not None and not p.future.done():
                p.future.set_exception(ApiDown(why))
            elif p.on_end is not None:
                try:
                    p.on_end(why)
                except Exception:
                    log.exception("router API: stream end handler failed")
        try:
            self._w.close()
        except Exception:
            pass

    def close(self, why: str = "closed"):
        if self.closed:
            return
        self.why = why
        self._fail_all(why)
        if not self._task.done():
            self._task.cancel()


def _keepalive(sock):
    """Let the kernel notice a router that vanished without a FIN, between heartbeats."""
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, v in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), v)
    except OSError:
        pass


# --- the kept connection + REST fallback --------------------------------------------------
class Router:
    """The main router, read over the API when it is up and over REST when it is not."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        mk = cfg.get("mikrotik") or {}
        a = mk.get("api") or {}
        self.enabled = bool(a.get("enabled", False))
        self.rest_base = str(mk.get("dhcp_source") or "").rstrip("/")
        self.host = str(a.get("host") or urlparse(self.rest_base).hostname or "")
        if not self.host:
            self.enabled = False                   # no router configured: REST reads fail softly
        self.port = int(a.get("port", 8729))
        self.tls = bool(a.get("tls", True))
        self.fingerprint = _norm_fp(a.get("fingerprint", ""))
        self.heartbeat_s = float(a.get("heartbeat_s", 30))
        self.timeout_s = float(a.get("timeout_s", 10))
        self.retry_s = float(a.get("retry_s", 5))       # first retry; doubles up to a minute
        self.verify_tls = bool(mk.get("verify_tls", False))

        self.conn: Optional[Connection] = None
        self._lock: Optional[asyncio.Lock] = None
        self._retry_at = 0.0
        self._backoff = 0.0
        self._keeper: Optional[asyncio.Task] = None
        self._stopped = False
        self._follows: dict = {}         # name -> (cmd, attrs, on_row, on_state)
        self._follow_tags: dict = {}     # name -> tag on the current connection

        # what the dashboard and the log can say about it
        self.connects = 0
        self.connected_since = 0.0
        self.last_error = ""
        self.rest_calls = 0              # reads that went to REST although the API is on
        self._told_down = False
        self._told_unpinned = False

    # --- status --------------------------------------------------------------
    @property
    def up(self) -> bool:
        return self.conn is not None and not self.conn.closed

    def status(self) -> dict:
        return {"enabled": self.enabled, "up": self.up, "via": "api" if self.up else "rest",
                "since": self.connected_since if self.up else 0.0,
                "connects": self.connects, "rest_fallbacks": self.rest_calls,
                "error": "" if self.up else self.last_error,
                "pinned": bool(self.fingerprint)}

    # --- connection upkeep ----------------------------------------------------
    async def _ensure(self) -> Optional[Connection]:
        """The live connection, opening one if it is time to try. None = use REST."""
        if not self.enabled or self._stopped:
            return None
        if self.up:
            return self.conn
        if self.conn is not None:                 # died since: say so once, then reopen
            self._drop(self.conn, self.conn.why or "closed")
        if time.time() < self._retry_at:
            return None
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self.up:
                return self.conn
            if time.time() < self._retry_at:
                return None
            user, pw = resolve_mikrotik(self.cfg)
            if not user:
                self._failed("no router credentials", 3600)
                return None
            try:
                c = await Connection.open(self.host, self.port, user, pw, self.fingerprint,
                                          self.timeout_s, self.tls)
            except ApiError as e:
                # the router answered and refused (wrong password, no `api` right) or the pin
                # did not match: retrying every minute would only write "login failure" lines
                # for the triage to find, so wait a long while
                self._failed(str(e), 900)
                return None
            except Exception as e:
                # unreachable, refused, TLS failed, or dropped mid-login (a wrong `address=`
                # on the service): every reader must still get its REST answer, so nothing
                # escapes from here
                self._failed(f"{type(e).__name__}: {e}" if str(e) else type(e).__name__, None)
                return None
            self.conn = c
            self.connects += 1
            c.serial = self.connects
            self.connected_since = time.time()
            self.last_error = ""
            self._told_down = False
            log.info("router API: connected to %s:%s as %s (connection #%d)",
                     self.host, self.port, user, self.connects)
            if not self.fingerprint and c.fingerprint and not self._told_unpinned:
                self._told_unpinned = True
                log.warning("router API: pin this certificate: mikrotik.api.fingerprint: %s",
                            c.fingerprint)
            for name in list(self._follows):
                self._subscribe(c, name)
            self._start_keeper()
            return c

    def _failed(self, why: str, wait_s: Optional[float]):
        if wait_s is None:     # unreachable / refused: 5s, doubling to a minute (a reboot)
            wait_s = self._next_backoff()
        self._retry_at = time.time() + wait_s
        self.last_error = why
        if not self._told_down:
            self._told_down = True
            log.warning("router API: %s:%s unavailable (%s); reading over REST until it is back",
                        self.host, self.port, why)

    def _drop(self, c: Connection, why: str):
        if self.conn is c:
            self.conn = None
            self.last_error = why
            log.warning("router API: connection lost (%s)", why)
            if time.time() - self.connected_since < 60:
                # dying young, again and again, would be a login a minute: back off as if
                # the router were unreachable
                self._retry_at = time.time() + self._next_backoff()
        c.close(why)

    def _next_backoff(self) -> float:
        self._backoff = min(60.0, max(self.retry_s, self._backoff * 2))
        return self._backoff

    def renew(self, why: str):
        """Log in again now. An API session keeps the rights it logged in with, so after the
        owner changes this user's group the kept connection has to be replaced to see it."""
        c = self.conn
        if c is None or c.closed or self._stopped:
            return
        log.info("router API: logging in again (%s)", why)
        self.conn = None
        c.close(why)
        self._retry_at = 0.0
        asyncio.ensure_future(self._ensure())

    def _start_keeper(self):
        if self._keeper is None or self._keeper.done():
            self._keeper = asyncio.ensure_future(self._keep())

    async def _keep(self):
        """Heartbeat the live connection; reopen a dead one even when nobody is reading, so
        the log follow comes back by itself after a router reboot."""
        while not self._stopped:
            try:
                c = self.conn
                if c is not None and not c.closed:
                    try:
                        await c.call("/system/identity/print", timeout_s=self.timeout_s)
                        if time.time() - self.connected_since >= 60:
                            self._backoff = 0.0      # it has stayed up: the next loss starts afresh
                    except Exception as e:
                        self._drop(c, f"heartbeat failed: {type(e).__name__} {e}".strip())
                if not self.up:
                    await self._ensure()
            except Exception:                  # the keeper must outlive any one bad turn
                log.exception("router API: keeper turn failed")
            await asyncio.sleep(self.heartbeat_s if self.up else
                                max(1.0, min(self.heartbeat_s, self._retry_at - time.time())))

    def start(self):
        """Open the connection now and keep it (the monitor's loop). Callers that never call
        this still get a connection on first use; this just makes it not wait for one."""
        if self.enabled:
            self._start_keeper()

    async def stop(self):
        self._stopped = True
        if self._keeper is not None:
            self._keeper.cancel()
        if self.conn is not None:
            self.conn.close("lanowl stopping")
            self.conn = None

    # --- follow subscriptions -------------------------------------------------
    def follow(self, name: str, cmd: str, attrs: Optional[dict],
               on_row: Callable[[dict], None], on_state: Callable[[bool, str], None]):
        """Keep `cmd` running on every connection. `on_state(True, "")` each time it is
        (re)issued — anything that happened while it was down was NOT seen, so re-read —
        and `on_state(False, why)` when it stops."""
        self._follows[name] = (cmd, attrs, on_row, on_state)
        if self.up:
            self._subscribe(self.conn, name)
        elif self.enabled:
            self._start_keeper()
        else:
            on_state(False, "router API disabled")

    def _subscribe(self, c: Connection, name: str):
        cmd, attrs, on_row, on_state = self._follows[name]

        def ended(why):
            if self._follow_tags.get(name) == tag:
                self._follow_tags.pop(name, None)
            log.info("router API: follow %s stopped (%s)", name, why)
            on_state(False, str(why or "stopped"))

        try:
            tag = c.stream(cmd, attrs, on_row, ended)
        except ApiDown as e:
            on_state(False, str(e))
            return
        self._follow_tags[name] = tag
        on_state(True, "")

    # --- reads ----------------------------------------------------------------
    async def request(self, method: str, path: str, body: Optional[dict] = None,
                      timeout_s: Optional[float] = None):
        """REST-shaped: GET `ip/route` or POST `ping` {address, count}. Returns the rows (a
        list; REST answers a singleton menu with one object) or {"error": "..."}, never
        raises — the contract of the REST calls it replaces. Over the API when it is up,
        else over REST."""
        return (await self._request(method, path, body, timeout_s))[0]

    async def _request(self, method: str, path: str, body: Optional[dict],
                       timeout_s: Optional[float]) -> tuple:
        """`request`, plus the serial of the API connection that answered (0 = REST)."""
        timeout_s = timeout_s or self.timeout_s
        path = path.strip("/")
        c = await self._ensure()
        if c is not None:
            cmd = f"/{path}/print" if method.upper() == "GET" else f"/{path}"
            try:
                return await c.call(cmd, {k: str(v) for k, v in (body or {}).items()},
                                    timeout_s=timeout_s), c.serial
            except ApiError as e:
                if method.upper() != "GET" or "no such command" not in str(e):
                    return {"error": f"router said: {e}"}, c.serial
                # REST's paths say more than a menu: `interface/ether1`, `ip/route?dst-…`.
                # A GET the API cannot parse is one only REST can answer.
            except asyncio.TimeoutError:
                return {"error": "the router did not answer in time"}, c.serial
            except ApiDown as e:
                self._drop(c, str(e))
        if self.enabled:
            self.rest_calls += 1
        return await self._rest(method, path, body, timeout_s), 0

    async def read(self, path: str, timeout_s: Optional[float] = None) -> probes.ProbeResult:
        """GET `path` as a ProbeResult, the shape `probes.mikrotik_rest` returns; `.data
        ["conn"]` is the serial of the API connection that answered, 0 for REST."""
        r, serial = await self._request("GET", path, None, timeout_s)
        if isinstance(r, dict) and "error" in r:
            return probes.ProbeResult(False, None, str(r["error"]))
        return probes.ProbeResult(True, None, "mikrotik", {"json": r, "conn": serial})

    async def _rest(self, method: str, path: str, body: Optional[dict], timeout_s: float):
        """The REST call this module exists to avoid, kept as the fallback."""
        if method.upper() == "GET":
            user, pw = resolve_mikrotik(self.cfg)
            # probes.mikrotik_rest is looked up at call time, so the tests' stubs still apply
            r = await probes.mikrotik_rest(self.rest_base, path, user, pw, self.verify_tls,
                                           int(timeout_s * 1000))
            return r.data.get("json") if r.ok else {"error": r.detail}
        if aiohttp is None:
            return {"error": "aiohttp missing"}
        user, pw = resolve_mikrotik(self.cfg)
        if not user:
            return {"error": "no router credentials"}
        url = f"{self.rest_base}/rest/{path}"
        try:
            async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout_s),
                    connector=aiohttp.TCPConnector(ssl=self.verify_tls),
                    auth=aiohttp.BasicAuth(user, pw)) as s:
                async with s.request(method, url, json=body) as r:
                    txt = await r.text()
                    try:
                        js: Any = json.loads(txt)
                    except ValueError:
                        js = {"error": txt[:200]}
                    if r.status >= 400:
                        det = js.get("detail") or js.get("message") if isinstance(js, dict) else ""
                        return {"error": f"router said {r.status}: {det or txt[:160]}"}
                    return js
        except asyncio.TimeoutError:
            return {"error": "the router did not answer in time"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}


# One per process: every reader shares the one connection — that is the point.
_shared: Optional[Router] = None


def shared(cfg: dict) -> Router:
    global _shared
    if _shared is None or _shared.cfg is not cfg:
        _shared = Router(cfg)
    return _shared
