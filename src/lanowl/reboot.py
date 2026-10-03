"""Rebooting a device, with the owner's own logins (access.py).

A device can be rebooted from the dashboard, on Telegram (/reboot) and as the model's
proposal, with the owner's own logins from secrets.yaml — no dedicated key per device.

Which devices, and how, is an allow-list in config.yaml (`actions.catalog.reboot.devices`):

    routeros       ssh, `/system reboot` — MikroTik routers and APs (RouterOS 6 and 7)
    ssh            ssh, `reboot` — through `sudo -S` when the login is not root
    ssh_key        a server reached by the host-log watcher's key (root)
    reolink        the camera's or the NVR's own HTTP API: Login, then Reboot
    homeassistant  Home Assistant's API, hassio.host_reboot: the whole HA OS VM
    ha_button      a restart button Home Assistant already has (a TV, say)

The main router may be listed, with a warning: while it restarts the internet is gone, so the
devices reached through it and the WAN watcher's messages ("wan") are held with it. Never
listed: lanowl's own machine. Better left out: the host lanowl or its model runs on, and
anything whose restart is a security gap (an alarm). Shellies keep `shelly_reboot`, whose
check refuses a restart that would change a relay.

A reboot, in order:
  1. the check — at proposing AND at approval, read-only: log in, read its uptime, model or
     version. A device that cannot be logged in to cannot be rebooted, and says why;
  2. alerts held for the device — and for an AP, for the Wi-Fi clients on it right now —
     for `hold_min` (5 minutes by default). A planned reboot must not page;
  3. the command. Where a shell runs it, it is detached (`sleep 2; reboot` in the background)
     so the command returns before the link goes;
  4. watch it stop answering, then answer again. Where there is an uptime, it proves the
     restart; a device that never went down did not reboot, and that is a failure;
  5. the hold ends two minutes after it is back — or at `hold_min`, and a device still down
     then is reported as any other.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional

from . import probes

log = logging.getLogger("lanowl.reboot")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

KINDS = ("routeros", "ssh", "ssh_key", "reolink", "homeassistant", "ha_button", "profile")
BACK_S = {"routeros": 240, "ssh": 300, "ssh_key": 300, "reolink": 300, "homeassistant": 600,
          "ha_button": 300, "profile": 300}          # how long it may take to answer again
NEEDS_PASSWORD = ("routeros", "ssh", "reolink")     # the rest: lanowl's key, HA, a profile
DOWN_WAIT_S = 90                     # ...and to stop answering at all
POLL_S = 3
AFTER_BACK_S = 120                   # the hold's tail once it is back: its clients reconnect
DETACHED = "( sleep 2; reboot ) </dev/null >/dev/null 2>&1 & echo REBOOTING"
_UPTIME = re.compile(r"(\d+)([wdhms])")
_UNIT_S = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}


def routeros_uptime(text: str) -> Optional[float]:
    """`uptime: 3w1d19h29m50s` -> seconds."""
    m = re.search(r"uptime:\s*(\S+)", text or "")
    if not m:
        return None
    parts = _UPTIME.findall(m.group(1))
    return float(sum(int(n) * _UNIT_S[u] for n, u in parts)) if parts else None


def routeros_field(text: str, name: str) -> str:
    m = re.search(rf"^\s*{re.escape(name)}:\s*(.+?)\s*$", text or "", re.M)
    return m.group(1) if m else ""


def proc_uptime(text: str) -> Optional[float]:
    try:
        return float((text or "").split()[0])
    except (IndexError, ValueError):
        return None


def fmt_s(s: Optional[float]) -> str:
    if s is None:
        return "?"
    s = int(s)
    if s < 120:
        return f"{s} s"
    if s < 7200:
        return f"{s // 60} min"
    if s < 172800:
        return f"{s // 3600} h"
    return f"{s // 86400} days"


class Rebooter:
    def __init__(self, auditor, cfg: dict):
        self.a = auditor
        self.devices = {}
        for ip, v in (cfg.get("devices") or {}).items():
            v = dict(v or {})
            if v.get("via") in KINDS:
                self.devices[str(ip)] = v
            else:
                log.warning("reboot: %s has no known way (via: %r) — left out", ip, v.get("via"))
        self.hold_s = float(cfg.get("hold_min", 5)) * 60
        ha = (auditor.cfg.get("access") or {})
        self.ha_url = str(ha.get("ha_url") or "").rstrip("/")
        self.ha_token_file = str(ha.get("ha_token_file") or ".ha_token")

    # --- what can be rebooted --------------------------------------------------
    def can(self, ip: str) -> bool:
        return ip in self.devices

    def via(self, ip: str) -> str:
        return (self.devices.get(ip) or {}).get("via", "")

    def hold_for(self, ip: str) -> float:
        return float((self.devices.get(ip) or {}).get("hold_min", self.hold_s / 60)) * 60

    def listing(self) -> str:
        """The rebootable devices, for the model's tool description."""
        out = []
        for ip in self.devices:
            dev = self.a.inv.get(ip)
            out.append(f"{dev.name if dev else ip} {ip}")
        return ", ".join(out) or "none"

    # --- the check ---------------------------------------------------------------
    async def check(self, ip: str, name: str) -> dict:
        """{"ok", "note", "risk", "uptime", "clients", "uid"} — read-only."""
        d = self.devices.get(ip)
        if d is None:
            return {"ok": False, "note": f"{name} is not in the list of devices lanowl may "
                                         "reboot (config.yaml actions.catalog.reboot)"}
        via = d["via"]
        dev = self.a.inv.get(ip)
        risk = [str(d["risk"])] if d.get("risk") else []
        if dev is not None and dev.attrs.get("role") == "wan-gateway":
            st = (self.a._last_report or {}).get("wan_state")
            if st in ("backup", "down"):
                return {"ok": False, "note": f"the network's internet is on the {name} right now "
                                             f"(WAN {st}) — not rebooting it"}
        if via in NEEDS_PASSWORD and not self.a.access.has(ip):
            return {"ok": False, "note": f"no login with a password for {name} in secrets.yaml"}
        chk = await getattr(self, "_check_" + via)(ip, name, d)
        chk.setdefault("risk", [])
        chk["risk"] = risk + chk["risk"]
        wifi = list(chk.get("clients") or [])
        # what goes dark with it and is not on its Wi-Fi: the tunnels behind the VPS
        chk["clients"] = sorted(set(wifi) | {str(x) for x in d.get("also_hold") or []} - {ip})
        if chk.get("ok") and chk["clients"]:
            chk["note"] += (f"; alerts held for {len(chk['clients'])} more device(s) "
                            + ("on its Wi-Fi" if wifi else "behind it"))
        return chk

    async def _check_routeros(self, ip, name, d) -> dict:
        rc, out, err = await self.a.access.ssh(ip, "/system resource print", user_suffix="+ct",
                                               timeout_s=20)
        up = routeros_uptime(out) if rc == 0 else None
        if up is None:
            return {"ok": False, "note": f"cannot log in to {name} over ssh: "
                                         f"{_last(err) or 'no answer'}"}
        note = (f"{routeros_field(out, 'board-name') or 'RouterOS'} "
                f"{routeros_field(out, 'version')}, up {fmt_s(up)}")
        clients = []
        if self._is_ap(ip):
            rc, out, _ = await self.a.access.ssh(
                ip, "/interface wireless registration-table print terse without-paging",
                user_suffix="+ct", timeout_s=20)
            clients = self._watched(re.findall(r"mac-address=([0-9A-Fa-f:]{17})", out or ""))
        return {"ok": True, "note": note, "uptime": up, "clients": clients}

    async def _check_ssh(self, ip, name, d) -> dict:
        # root, or a sudo that takes the listed password (sudo -S reads it on stdin)
        rc, out, err = await self.a.access.ssh(
            ip, "cat /proc/uptime; id -u; [ \"$(id -u)\" = 0 ] || "
                "{ sudo -S -p '' true 2>/dev/null && echo SUDO_OK; }",
            sudo_pw=True, timeout_s=25)
        lines = (out or "").split("\n")
        up = proc_uptime(lines[0]) if rc is not None else None
        if up is None:
            return {"ok": False, "note": f"cannot log in to {name} over ssh: "
                                         f"{_last(err) or 'no answer'}"}
        uid = (lines[1].strip() if len(lines) > 1 else "")
        if uid != "0" and "SUDO_OK" not in out:
            return {"ok": False, "note": f"logged in to {name}, but its user may not reboot "
                                         "it (sudo refused the listed password)"}
        clients = []
        if self._is_ap(ip):
            rc, dump, _ = await self.a.access.ssh(ip, "mca-dump", timeout_s=25)
            try:
                j = json.loads(dump) if rc == 0 else {}
                clients = self._watched([s.get("mac", "") for v in j.get("vap_table") or []
                                         for s in v.get("sta_table") or []])
            except ValueError:
                pass
        return {"ok": True, "note": f"up {fmt_s(up)}" + ("" if uid == "0" else ", via sudo"),
                "uptime": up, "uid": uid, "clients": clients}

    async def _check_ssh_key(self, ip, name, d) -> dict:
        # read as root: a login that may not become root could not reboot it either
        rc, out, err = await self.a.actions._ssh_run(ip, "cat /proc/uptime", 20, root=True)
        up = proc_uptime(out) if rc == 0 else None
        if up is None:
            return {"ok": False, "note": f"cannot reach {name} over ssh: {_last(err) or 'no answer'}"}
        return {"ok": True, "note": f"up {fmt_s(up)}", "uptime": up}

    async def _check_profile(self, ip, name, d) -> dict:
        K = self.a.kinds
        prof = K.profile_of(ip)
        if prof is not None and "uptime" in prof.ops:
            ok, up = await K.run(self.a, ip, "uptime")
            if not ok:
                return {"ok": False, "note": f"cannot read {name}'s uptime: {up}"}
            return {"ok": True, "note": f"up {fmt_s(up)}", "uptime": up}
        rc, _, err = await K._ssh(self.a, ip, "true", False, 20)
        if rc != 0:
            return {"ok": False, "note": f"cannot log in to {name}: {_last(err) or 'no answer'}"}
        return {"ok": True, "note": f"{name} answers over ssh"}

    async def _check_reolink(self, ip, name, d) -> dict:
        r = await self._reolink(ip, [{"cmd": "GetDevInfo", "action": 0, "param": {}}])
        if r.get("error"):
            return {"ok": False, "note": f"cannot log in to {name}: {r['error']}"}
        info = ((r["value"][0] or {}).get("value") or {}).get("DevInfo") or {}
        return {"ok": True, "note": f"{info.get('model') or 'Reolink'} firmware "
                                    f"{info.get('firmVer') or '?'}"}

    async def _check_homeassistant(self, ip, name, d) -> dict:
        st, j = await self._ha("GET", "/api/config")
        if st != 200 or not isinstance(j, dict):
            return {"ok": False, "note": f"Home Assistant's API does not answer (HTTP {st})"}
        return {"ok": True, "note": f"Home Assistant {j.get('version')}, {j.get('state', '?')}"}

    async def _check_ha_button(self, ip, name, d) -> dict:
        ent = str(d.get("entity") or "")
        st, j = await self._ha("GET", f"/api/states/{ent}")
        if st != 200 or not isinstance(j, dict):
            return {"ok": False, "note": f"Home Assistant has no button {ent} (HTTP {st})"}
        if j.get("state") == "unavailable":
            return {"ok": False, "note": f"Home Assistant cannot reach {name} right now "
                                         f"({ent} is unavailable)"}
        return {"ok": True, "note": f"through Home Assistant's {ent}"}

    def _is_ap(self, ip: str) -> bool:
        dev = self.a.inv.get(ip)
        return dev is not None and dev.attrs.get("role") == "ap"

    def _watched(self, macs: list) -> list:
        """The inventory's devices among these MACs (the DHCP lease index maps them)."""
        idx = self.a._mac_index or {}
        ips = {idx.get(m.upper()) for m in macs if m}
        return sorted(i for i in ips if i and self.a.inv.get(i) is not None)

    # --- the reboot ----------------------------------------------------------------
    async def run(self, ip: str, name: str, chk: dict, via: str = "",
                  back_s: float = 0, hold_s: float = 0) -> dict:
        """{"ok", "ran", "result" | "error"}. `via`/`back_s`/`hold_s`: for a reboot that is
        part of something longer — a RouterOS upgrade installs during the boot."""
        via = via or self.via(ip)
        back_s = back_s or float((self.devices.get(ip) or {}).get("back_s") or 0) or BACK_S[via]
        held = [ip] + list(chk.get("clients") or [])
        t0 = time.time()
        self.a.hold(held, t0 + (hold_s or self.hold_for(ip)), f"reboot of {name}")
        self.a.actions.step("sending the reboot")
        sent, why = await getattr(self, "_send_" + via)(ip, chk)
        if not sent:
            self.a.hold(held, 0)
            return {"ok": False, "ran": False, "error": why}
        log.warning("reboot: %s (%s) — command sent", name, ip)
        self.a.actions.step("waiting for it to go down")
        down_at = None
        while time.time() - t0 < DOWN_WAIT_S:
            await asyncio.sleep(POLL_S)
            if not await self._answers(ip):
                down_at = time.time()
                break
        back_at = None
        if down_at is None:
            # rebooted between two looks, or never: the uptime tells, where there is one
            up = await self._uptime(ip, via)
            if up is None or up > time.time() - t0 + 10:
                self.a.hold(held, 0)
                return {"ok": False, "ran": True,
                        "error": f"sent, but {name} never stopped answering in {DOWN_WAIT_S} s"
                                 + (f" and has been up {fmt_s(up)}" if up is not None else "")
                                 + f" — it did not reboot{f' ({why})' if why else ''}"}
            back_at = time.time()
        else:
            self.a.actions.step("restarting — waiting for it to answer")
            while time.time() - t0 < back_s:
                await asyncio.sleep(POLL_S)
                if await self._answers(ip):
                    back_at = time.time()
                    break
        if back_at is None:
            # the hold runs out by itself at hold_min; from then on it is reported as usual
            return {"ok": False, "ran": True,
                    "error": f"it went down {round(down_at - t0)} s after the command, but is "
                             f"not answering {round(back_s)} s later"}
        secs = round(back_at - t0)
        extra = ""
        if via == "homeassistant":
            self.a.actions.step("waiting for Home Assistant itself")
            while time.time() - t0 < BACK_S[via]:
                st, _ = await self._ha("GET", "/api/")
                if st == 200:
                    extra = f"; Home Assistant itself answering after {round(time.time() - t0)} s"
                    break
                await asyncio.sleep(POLL_S * 2)
            else:
                extra = "; the VM answers, but Home Assistant's API not yet"
        up = None
        for _ in range(4):                 # sshd comes up a little after the first ping
            up = await self._uptime(ip, via)
            if up is not None:
                break
            await asyncio.sleep(5)
        self.a.hold(held, min(self.a.held_until(ip), time.time() + AFTER_BACK_S))
        return {"ok": True, "ran": True,
                "result": f"rebooted — answering again after {secs} s"
                          + (f" (up {fmt_s(up)})" if up is not None else "") + extra}

    async def _answers(self, ip: str) -> bool:
        # the VPS is watched by its ssh port, everything else answers ping
        if self.via(ip) == "ssh_key":
            return (await probes.tcp_check(ip, 22, 1500)).ok
        return (await probes.ping(ip, 1000, count=1)).ok

    async def _uptime(self, ip: str, via: str) -> Optional[float]:
        if via == "routeros":
            rc, out, _ = await self.a.access.ssh(ip, "/system resource print", user_suffix="+ct",
                                                 timeout_s=15)
            return routeros_uptime(out) if rc == 0 else None
        if via == "ssh":
            rc, out, _ = await self.a.access.ssh(ip, "cat /proc/uptime", timeout_s=15)
            return proc_uptime(out) if rc == 0 else None
        if via == "ssh_key":
            rc, out, _ = await self.a.actions._ssh_run(ip, "cat /proc/uptime", 15)
            return proc_uptime(out) if rc == 0 else None
        if via == "profile":
            prof = self.a.kinds.profile_of(ip)
            if prof is not None and "uptime" in prof.ops:
                ok, up = await self.a.kinds.run(self.a, ip, "uptime")
                return up if ok else None
        return None

    async def _send_routeros(self, ip, chk) -> tuple:
        # a console asks "Reboot, yes? [y/N]": the "y" answers it if it asks here too
        rc, out, err = await self.a.access.ssh(ip, "/system reboot", stdin=b"y\n",
                                               user_suffix="+ct", timeout_s=15)
        if rc is None and "no login" in err:
            return False, err
        if "denied" in err.lower():
            return False, f"the login was refused: {_last(err)}"
        return True, _last(err)

    async def _send_ssh(self, ip, chk) -> tuple:
        root = chk.get("uid") == "0"
        cmd = DETACHED if root else ("sudo -S -p '' sh -c '( sleep 2; reboot ) </dev/null "
                                     ">/dev/null 2>&1 &' && echo REBOOTING")
        rc, out, err = await self.a.access.ssh(ip, cmd, sudo_pw=not root, timeout_s=20)
        if "REBOOTING" not in (out or ""):
            return False, f"the reboot command did not run: {_last(err) or f'rc {rc}'}"
        return True, ""

    async def _send_ssh_key(self, ip, chk) -> tuple:
        rc, out, err = await self.a.actions._ssh_run(
            ip, "( sleep 2; systemctl reboot ) </dev/null >/dev/null 2>&1 & echo REBOOTING", 20,
            root=True)
        if "REBOOTING" not in (out or ""):
            return False, f"the reboot command did not run: {_last(err) or f'rc {rc}'}"
        return True, ""

    async def _send_profile(self, ip, chk) -> tuple:
        return await self.a.kinds.send_reboot(self.a, ip)

    async def _send_reolink(self, ip, chk) -> tuple:
        r = await self._reolink(ip, [{"cmd": "Reboot", "param": {}}], logout=False)
        if r.get("error"):
            return False, r["error"]
        code = (r["value"][0] or {}).get("code")
        return (True, "") if code == 0 else (False, f"the camera refused the reboot (code {code})")

    async def _send_homeassistant(self, ip, chk) -> tuple:
        st, _ = await self._ha("POST", "/api/services/hassio/host_reboot", {}, timeout_s=15)
        if st in (200, None):             # None: it went down before it answered
            return True, ""
        return False, f"Home Assistant refused the reboot (HTTP {st})"

    async def _send_ha_button(self, ip, chk) -> tuple:
        ent = str((self.devices.get(ip) or {}).get("entity") or "")
        st, _ = await self._ha("POST", "/api/services/button/press", {"entity_id": ent})
        return (True, "") if st == 200 else (False, f"Home Assistant refused it (HTTP {st})")

    # --- the device APIs ------------------------------------------------------------
    async def _reolink(self, ip: str, cmds: list, logout: bool = True) -> dict:
        """Log in to a Reolink with its line of the list, run `cmds`, log out. {"value"} or
        {"error"}. The password is only ever in the Login call's body."""
        lg = self.a.access.login(ip)
        if lg is None:
            return {"error": "no login in secrets.yaml"}
        if aiohttp is None:
            return {"error": "aiohttp is not installed"}
        base = f"http://{ip}/api.cgi"
        to = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=to) as s:
                async with s.post(base + "?cmd=Login", json=[{"cmd": "Login", "param": {"User": {
                        "Version": "0", "userName": lg.user, "password": lg.password}}}]) as r:
                    j = await r.json(content_type=None)
                tok = (((j or [{}])[0].get("value") or {}).get("Token") or {}).get("name")
                if not tok:
                    return {"error": "the login was refused "
                                     f"(code {((j or [{}])[0].get('error') or {}).get('rspCode')})"}
                async with s.post(f"{base}?cmd={cmds[0]['cmd']}&token={tok}", json=cmds) as r:
                    val = await r.json(content_type=None)
                if logout:
                    async with s.post(f"{base}?cmd=Logout&token={tok}",
                                      json=[{"cmd": "Logout", "param": {}}]) as r:
                        await r.read()
            return {"value": val if isinstance(val, list) and val else [{}]}
        except Exception as e:
            return {"error": f"{type(e).__name__} {str(e)[:80]}".strip()}

    def _ha_token(self) -> str:
        try:
            with open(self.ha_token_file) as f:
                return f.read().strip()
        except OSError:
            return ""

    async def _ha(self, method: str, path: str, body: Optional[dict] = None,
                  timeout_s: float = 10) -> tuple:
        """(status, json) from Home Assistant's API; status None = no answer."""
        tok = self._ha_token()
        if not tok or not self.ha_url or aiohttp is None:
            return 0, None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as s:
                async with s.request(method, self.ha_url + path, json=body,
                                     headers={"Authorization": f"Bearer {tok}"}) as r:
                    try:
                        j = await r.json(content_type=None)
                    except Exception:
                        j = None
                    return r.status, j
        except Exception:
            return None, None


def _last(text: str) -> str:
    return ((text or "").strip().splitlines() or [""])[-1][:160]
