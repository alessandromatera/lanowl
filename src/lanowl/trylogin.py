"""Try a device's login before it is written: the setup's and Settings' "Try" button.

One read-only call, the way lanowl itself will log in to that kind, and the device's own answer
quoted word for word — never a reason made up here:

  linux, openwrt, unifi, esxi, a profile of yours   ssh, `uname -sr` (a password, or lanowl's key)
  mikrotik                                           ssh, `/system resource print`
  reolink                                            its HTTP API: Login, then Logout
  homeassistant                                      GET /api/ with the token
  shelly                                             no login: lanowl talks to it without one;
                                                     its /shelly says what it is

The password goes to ssh through SSH_ASKPASS (access.py), never on a command line, and is
scrubbed from whatever comes back. Only a home network's addresses (RFC 1918). One password
prompt per try (some systems, ESXi among them, lock an account after a few wrong ones).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Optional

from .access import LEGACY, Login
from .model import is_lan

SSH_KINDS = {"linux": "uname -sr", "openwrt": "uname -sr", "unifi": "uname -sr", "esxi": "uname -sr",
             "mikrotik": "/system resource print"}


def allowed(ip: str) -> bool:
    return is_lan(ip)


def _scrub(text: str, secret: str) -> str:
    return text.replace(secret, "••••") if secret else text


def _last(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""


async def _ssh(acc, ip: str, user: str, password: str, key: str, remote: str) -> dict:
    if key:
        argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + acc.known_hosts,
                "-o", "IdentitiesOnly=yes", "-i", key] + LEGACY + ["-l", user, ip, "--", remote]
        env = dict(os.environ)
    else:
        argv = acc.ssh_argv(ip, user, remote)
        env = acc._env(Login(user, password))
    try:
        p = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE, env=env)
        out, err = await asyncio.wait_for(p.communicate(), 25)
    except asyncio.TimeoutError:
        return {"ok": False, "said": "no answer in 25 seconds"}
    except OSError as e:
        return {"ok": False, "said": f"ssh did not run: {e}"}
    out = _scrub(out.decode("utf-8", "replace"), password)
    err = _scrub(err.decode("utf-8", "replace"), password)
    if p.returncode == 0:
        if remote.startswith("/system"):
            v = re.search(r"version:\s*(\S+)", out)
            b = re.search(r"board-name:\s*(.+)", out)
            what = " · ".join(x for x in (b.group(1).strip() if b else "", "RouterOS " + v.group(1) if v else "") if x)
        else:
            what = _last(out)
        return {"ok": True, "what": what}
    return {"ok": False, "said": _last(err) or _last(out) or f"ssh ended with {p.returncode}"}


async def _reolink(ip: str, user: str, password: str) -> dict:
    import aiohttp
    base = f"http://{ip}/api.cgi"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            async with s.post(base + "?cmd=Login", json=[{"cmd": "Login", "param": {"User": {
                    "Version": "0", "userName": user, "password": password}}}]) as r:
                j = await r.json(content_type=None)
            first = (j or [{}])[0] if isinstance(j, list) else {}
            tok = ((first.get("value") or {}).get("Token") or {}).get("name")
            if not tok:
                e = first.get("error") or {}
                return {"ok": False, "said": _scrub(f"{e.get('detail') or 'no token'} (rspCode {e.get('rspCode')})", password)}
            async with s.post(f"{base}?cmd=GetDevInfo&token={tok}", json=[{"cmd": "GetDevInfo", "action": 0}]) as r:
                info = await r.json(content_type=None)
            async with s.post(f"{base}?cmd=Logout&token={tok}", json=[{"cmd": "Logout", "param": {}}]) as r:
                await r.read()
        dev = (((info or [{}])[0].get("value") or {}).get("DevInfo") or {}) if isinstance(info, list) else {}
        return {"ok": True, "what": " · ".join(x for x in (str(dev.get("model") or ""), str(dev.get("firmVer") or "")) if x)}
    except Exception as e:
        return {"ok": False, "said": f"{type(e).__name__} {str(e)[:120]}".strip()}


async def _ha(ip: str, token: str) -> dict:
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            async with s.get(f"http://{ip}:8123/api/", headers={"Authorization": f"Bearer {token}"}) as r:
                body = (await r.content.read(2048)).decode("utf-8", "replace")
                if r.status == 200:
                    try:
                        msg = json.loads(body).get("message", "")
                    except ValueError:
                        msg = ""
                    return {"ok": True, "what": msg or "its API answered"}
                return {"ok": False, "said": _scrub(f"HTTP {r.status}: {body.strip()[:160]}", token)}
    except Exception as e:
        return {"ok": False, "said": f"{type(e).__name__} {str(e)[:120]}".strip()}


async def _shelly(ip: str) -> dict:
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
            async with s.get(f"http://{ip}/shelly") as r:
                j = await r.json(content_type=None) if r.status == 200 else None
            if isinstance(j, dict) and (j.get("auth_en") is True or j.get("auth") is True):   # gen 2 / gen 1
                return {"ok": False, "said": "its /shelly says a password is on (" + ("auth_en" if "auth_en" in j else "auth")
                                             + ": true): lanowl talks to Shellys without one, so it can only watch this one"}
            async with s.get(f"http://{ip}/rpc/Shelly.GetStatus") as r:
                if r.status == 401:
                    return {"ok": False, "said": "HTTP 401: it asks for a password; lanowl talks to Shellys "
                                                 "without one, so it can only watch this one"}
        if isinstance(j, dict):
            return {"ok": True, "what": " · ".join(x for x in (str(j.get("app") or j.get("model") or j.get("type") or ""),
                                                             str(j.get("ver") or j.get("fw") or "")) if x)}
        return {"ok": False, "said": "no /shelly page: it does not answer like a Shelly"}
    except Exception as e:
        return {"ok": False, "said": f"{type(e).__name__} {str(e)[:120]}".strip()}


async def try_login(acc, kind: str, ip: str, user: str = "", password: str = "", token: str = "",
                    key: Optional[str] = None) -> dict:
    """{"ok", "what" (what it is, when it worked), "said" (its answer, when it did not)}."""
    if not allowed(ip):
        return {"ok": False, "said": "only an address of your home network is tried"}
    if kind == "shelly":
        return await _shelly(ip)
    if kind == "homeassistant":
        if not token:
            return {"ok": False, "said": "paste its token first"}
        return await _ha(ip, token)
    if kind == "reolink":
        if not (user and password):
            return {"ok": False, "said": "type its user and password first"}
        return await _reolink(ip, user, password)
    remote = SSH_KINDS.get(kind, "uname -sr")
    if not user or not (password or key):
        return {"ok": False, "said": "type its user and password first"}
    return await _ssh(acc, ip, user + ("+ct" if kind == "mikrotik" else ""), password, key or "", remote)
