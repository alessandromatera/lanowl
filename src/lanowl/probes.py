"""Read-only probe primitives. Every function here is passive: ICMP echo,
TCP connect, HTTP GET, SNMP GET, MikroTik REST GET. No writes, ever.

All functions degrade gracefully: a missing optional dependency or a missing
service yields a "not reachable / unknown" result rather than raising.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

# ---- optional deps (import lazily / tolerate absence) ----------------------
try:  # faster single-socket ICMP; unprivileged on macOS
    from icmplib import async_ping as _icmplib_async_ping  # type: ignore
except Exception:  # pragma: no cover
    _icmplib_async_ping = None

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

_PING_TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
_SNMP_BIN = shutil.which("snmpget")


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: Optional[float] = None
    detail: str = ""
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------
async def ping(ip: str, timeout_ms: int = 1000, count: int = 2) -> ProbeResult:
    """ICMP reachability. Prefers icmplib, falls back to the system `ping`.

    Sends `count` echo requests and treats the host as alive if ANY reply arrives:
    battery/Wi-Fi IoT devices (ESP, Shelly) routinely drop a single packet, and a
    one-shot probe turns that into a false 'down'."""
    if _icmplib_async_ping is not None:
        try:
            host = await _icmplib_async_ping(ip, count=count, timeout=timeout_ms / 1000,
                                             interval=0.25, privileged=False)
            if host.is_alive:
                return ProbeResult(True, host.avg_rtt, "icmp")
            return ProbeResult(False, None, "icmp:no-reply")
        except Exception as e:  # permission / platform issue -> fall back
            _ = e
    return await _ping_system(ip, timeout_ms, count)


async def _ping_system(ip: str, timeout_ms: int, count: int = 2) -> ProbeResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", str(count), ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout=timeout_ms / 1000 + 1.0 + 0.5 * count)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ProbeResult(False, None, "icmp:timeout")
        if proc.returncode == 0:
            m = _PING_TIME_RE.search(out.decode(errors="ignore"))
            return ProbeResult(True, float(m.group(1)) if m else None, "icmp")
        return ProbeResult(False, None, "icmp:no-reply")
    except FileNotFoundError:
        return ProbeResult(False, None, "icmp:no-ping-binary")


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------
async def tcp_check(ip: str, port: int, timeout_ms: int = 1500) -> ProbeResult:
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout_ms / 1000)
        latency = (loop.time() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ProbeResult(True, latency, f"tcp/{port} open")
    except asyncio.TimeoutError:
        return ProbeResult(False, None, f"tcp/{port} timeout")
    except (ConnectionRefusedError, OSError) as e:
        return ProbeResult(False, None, f"tcp/{port} {type(e).__name__}")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
async def http_check(ip: str, port: int = 80, path: str = "/", timeout_ms: int = 4000,
                     scheme: Optional[str] = None) -> ProbeResult:
    """A 2xx/3xx/4xx response means the service is up (401/403 still = alive)."""
    if aiohttp is None:
        # Fall back to a bare TCP check if aiohttp isn't installed.
        r = await tcp_check(ip, port, timeout_ms)
        r.detail = f"http(tcp-fallback) {r.detail}"
        return r
    scheme = scheme or ("https" if port in (443, 8443) else "http")
    url = f"{scheme}://{ip}:{port}{path}"
    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    connector = aiohttp.TCPConnector(ssl=False)
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as s:
            async with s.get(url, allow_redirects=False) as resp:
                latency = (loop.time() - start) * 1000
                ok = resp.status < 500
                return ProbeResult(ok, latency, f"http {resp.status}", {"status": resp.status})
    except asyncio.TimeoutError:
        return ProbeResult(False, None, "http timeout")
    except Exception as e:
        return ProbeResult(False, None, f"http {type(e).__name__}")


async def ollama_check(url: str, model: str, timeout_ms: int = 4000) -> ProbeResult:
    """Does the model server work: answering, with the configured model installed?

    An open port only says a process holds 11434. /api/tags and /api/ps are listings —
    nothing is loaded or generated — so this can run every sweep without touching the 18GB
    model; measured at <60ms even mid-generation. `loaded` is detail only: a model that
    keep_alive let go is still ready, just slower to its first answer."""
    if aiohttp is None:
        return ProbeResult(False, None, "ollama:aiohttp-missing")
    url = url.rstrip("/")
    wanted = {model, f"{model}:latest"}           # "llama3" is listed as "llama3:latest"
    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    loop = asyncio.get_event_loop()
    start = loop.time()
    try:
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(f"{url}/api/tags") as resp:
                if resp.status != 200:
                    return ProbeResult(False, None, f"http {resp.status}")
                tags = await resp.json()
            latency = (loop.time() - start) * 1000
            if not wanted & {m.get("name") for m in tags.get("models", [])}:
                return ProbeResult(False, latency, f"{model} not installed")
            async with s.get(f"{url}/api/ps") as resp:
                ps = await resp.json() if resp.status == 200 else {}
    except asyncio.TimeoutError:
        return ProbeResult(False, None, "not answering (timeout)")
    except Exception as e:
        return ProbeResult(False, None, f"not answering ({type(e).__name__})")
    loaded = bool(wanted & {m.get("name") for m in ps.get("models", [])})
    return ProbeResult(True, latency, "loaded" if loaded else "ready", {"loaded": loaded})


# ---------------------------------------------------------------------------
# SNMP (via net-snmp CLI if present; otherwise unavailable, not fatal)
# ---------------------------------------------------------------------------
# A couple of universally-useful read-only OIDs.
OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"

snmp_available = _SNMP_BIN is not None


async def snmp_get(ip: str, oid: str = OID_SYSUPTIME, community: str = "public",
                   timeout_s: int = 2) -> ProbeResult:
    if _SNMP_BIN is None:
        return ProbeResult(False, None, "snmp:cli-not-installed")
    try:
        proc = await asyncio.create_subprocess_exec(
            _SNMP_BIN, "-v2c", "-c", community, "-t", str(timeout_s), "-r", "0",
            "-Oqv", ip, oid,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout_s + 1.5)
        if proc.returncode == 0:
            val = out.decode(errors="ignore").strip().strip('"')
            return ProbeResult(True, None, "snmp", {"oid": oid, "value": val})
        return ProbeResult(False, None, f"snmp:{err.decode(errors='ignore').strip()[:60]}")
    except asyncio.TimeoutError:
        return ProbeResult(False, None, "snmp:timeout")
    except Exception as e:
        return ProbeResult(False, None, f"snmp:{type(e).__name__}")


# ---------------------------------------------------------------------------
# MikroTik REST (read-only GET)
# ---------------------------------------------------------------------------
async def mikrotik_rest(base: str, path: str, user: str, password: str,
                        verify_tls: bool = False, timeout_ms: int = 5000) -> ProbeResult:
    """GET against RouterOS /rest (served by the router's www service).
    Only GET is used — read-only. Returns parsed JSON in .data['json']."""
    if aiohttp is None:
        return ProbeResult(False, None, "mikrotik:aiohttp-missing")
    if not user:
        return ProbeResult(False, None, "mikrotik:no-credentials")
    url = base.rstrip("/") + "/rest/" + path.lstrip("/")
    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    auth = aiohttp.BasicAuth(user, password)
    connector = aiohttp.TCPConnector(ssl=verify_tls)
    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector, auth=auth) as s:
            async with s.get(url) as resp:  # GET only — never POST/PATCH/DELETE
                if resp.status >= 400:
                    return ProbeResult(False, None, f"mikrotik http {resp.status}")
                js: Any = await resp.json(content_type=None)
                return ProbeResult(True, None, "mikrotik", {"json": js})
    except asyncio.TimeoutError:
        return ProbeResult(False, None, "mikrotik:timeout")
    except Exception as e:
        return ProbeResult(False, None, f"mikrotik:{type(e).__name__}")
