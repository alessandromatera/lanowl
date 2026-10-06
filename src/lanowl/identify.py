"""What a device on the network is, from what answers: the setup's "Find my devices".

Only on that button, once per address (the result is kept for an hour, so a reload does not
ask again), and only on a home network's addresses (RFC 1918): a TCP connection to each of a
few ports, two seconds at most, 32 at a time — about half a minute for 50 devices. Then, where
a port answers: the ssh greeting on 22, the title of the web page on 80 or 443, and a Shelly's
own description at /shelly. Nothing is logged into, nothing is sent but a GET, and no port
scan beyond these.

What it found is said as the reason under each device ("port 8123 answers: Home Assistant"),
and turned into a kind, a group, a name and how much it matters — each the owner's to change.
"""
from __future__ import annotations

import asyncio
import html
import json
import re
import time
from typing import Optional

from .model import is_lan
from .oui import PRIVATE

PORTS = (22, 80, 443, 554, 631, 1883, 8006, 8123, 8291, 9000, 11434)
CONNECT_S = 2.0
PARALLEL = 32
KEEP_S = 3600
_cache: dict = {}            # ip -> (ts, what the probe found)

# the groups a found device lands in, and the words the page gives them
GROUPS = {"network": "Router and Wi-Fi", "servers": "Servers", "cameras": "Cameras", "iot": "Smart home",
          "misc": "Other", "phones": "Phones, tablets, laptops", "unknown": "Don't know yet"}
# how much each matters, by default: the owner's to change
CRIT = {"network": "high", "servers": "high", "cameras": "warning", "iot": "low", "misc": "low",
        "phones": "info", "unknown": "low"}
_GENERIC_TITLES = re.compile(r"^(login|log in|web ?client|index|home|welcome|router|untitled|302 found|"
                             r"301 moved|document moved|redirect|404 not found|403 forbidden|unauthorized)\b", re.I)


def allowed(ip: str) -> bool:
    """Probe only a home network's addresses."""
    return is_lan(ip)


def short_vendor(v: str) -> str:
    """A maker as people say it: "Reolink Innovation Limited" → "Reolink"."""
    v = str(v or "").strip()
    if not v or v == PRIVATE:
        return v
    v = re.sub(r"\s*\(.*?\)", "", v)
    v = re.sub(r"[,.]?\s*(Innovation|Technolog(y|ies)|Electronics?|Communications?|Networks?|Systems?|Industrial|"
               r"Information|International|Holdings?|Group|Corp(oration)?|Co|Ltd|Limited|Inc|LLC|GmbH|S\.?p\.?A|"
               r"S\.?r\.?l|AG|AB|SA|BV|Company)\b\.?.*$", "", v, flags=re.I)
    return v.strip(" ,.-") or str(v)


async def _port(ip: str, port: int, sem: asyncio.Semaphore) -> Optional[str]:
    """None: closed. "": open. A text: what it said first (ssh's greeting)."""
    async with sem:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), CONNECT_S)
        except (OSError, asyncio.TimeoutError):
            return None
        said = ""
        try:
            if port == 22:
                said = (await asyncio.wait_for(r.readline(), CONNECT_S)).decode("ascii", "replace").strip()[:80]
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
        return said


async def _get(url: str, limit: int = 65536) -> tuple:
    """(status, headers' Server, body text), or (0, "", "") — one GET, no login, no cookies."""
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4)) as s:
            async with s.get(url, ssl=False, allow_redirects=True, max_redirects=2) as r:
                body = (await r.content.read(limit)).decode("utf-8", "replace")
                return r.status, r.headers.get("Server", ""), body
    except Exception:
        return 0, "", ""


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    t = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else ""
    return t[:60]


async def probe(ip: str, sem: Optional[asyncio.Semaphore] = None, now: Optional[float] = None) -> dict:
    """{"open": [ports], "ssh": greeting, "title", "server", "shelly": {...}}, kept an hour."""
    now = time.time() if now is None else now
    hit = _cache.get(ip)
    if hit and now - hit[0] < KEEP_S:
        return hit[1]
    if not allowed(ip):
        return {"open": [], "skipped": True}
    sem = sem or asyncio.Semaphore(PARALLEL)
    said = await asyncio.gather(*(_port(ip, p, sem) for p in PORTS))
    out = {"open": [p for p, x in zip(PORTS, said) if x is not None], "ssh": said[0] or ""}
    if 80 in out["open"] or 443 in out["open"]:
        base = f"http://{ip}" if 80 in out["open"] else f"https://{ip}"
        st, server, body = await _get(base + "/")
        out["title"], out["server"] = _title(body), server[:60]
        if 80 in out["open"]:
            st, _, body = await _get(f"http://{ip}/shelly", 4096)
            if st == 200:
                try:
                    j = json.loads(body)
                    if isinstance(j, dict) and (j.get("type") or j.get("model") or j.get("gen")):
                        out["shelly"] = {k: str(j.get(k) or "") for k in ("name", "model", "type", "app", "gen")}
                except ValueError:
                    pass
    _cache[ip] = (now, out)
    return out


def identify(row: dict, p: dict) -> dict:
    """What it is, from the probe and the maker: {"what", "why", "kind", "group", "name",
    "phone"}. `row`: {"ip", "name" (from DHCP), "vendor"}. Each a suggestion."""
    v = short_vendor(row.get("vendor") or "")
    vl = (row.get("vendor") or "").lower()
    opn = set(p.get("open") or [])
    ssh, title = str(p.get("ssh") or ""), str(p.get("title") or "")
    tl, sl = title.lower(), ssh.lower()
    sh = p.get("shelly")
    out = {"what": v, "why": "", "kind": "", "group": "unknown", "name": "", "phone": False}

    def be(what, why, kind="", group="misc"):
        out.update(what=what, why=why, kind=kind, group=group)

    if sh:
        model = sh.get("app") or sh.get("model") or sh.get("type") or "Shelly"
        be("Shelly " + model if not model.lower().startswith("shelly") else model, f"/shelly says {model}", "shelly", "iot")
        out["name"] = sh.get("name") or ""
    elif 8291 in opn or "rosssh" in sl or "routeros" in tl or "mikrotik" in tl:
        be("MikroTik RouterOS", "port 8291 answers (Winbox)" if 8291 in opn else f"it says {title or ssh}", "mikrotik", "network")
    elif 8123 in opn or "home assistant" in tl:
        be("Home Assistant", "port 8123 answers like Home Assistant", "homeassistant", "servers")
    elif "esxi" in tl or "vmware esxi" in tl:
        be("VMware ESXi", f"its web page says {title}", "esxi", "servers")
    elif 8006 in opn or "proxmox" in tl:
        be("Proxmox VE", "port 8006 answers like Proxmox", "linux", "servers")
    elif "luci" in tl or "openwrt" in tl or "gl.inet" in tl or "gl-" in tl:
        be(title if "gl" in tl else "OpenWrt", f"its web page is {title}", "openwrt", "network")
    elif "unifi" in tl or "ubiquiti" in vl:
        be("UniFi" if "ubiquiti" in vl else title, "Ubiquiti" + (f", ssh: {ssh}" if ssh else ""), "unifi", "network")
    elif "reolink" in vl or "reolink" in tl or {554, 9000} <= opn:     # 9000: a Reolink's own port, beside its RTSP
        be("Reolink", "port 9000 answers like a Reolink" if 9000 in opn else "made by Reolink", "reolink", "cameras")
    elif 554 in opn:
        be(v or "a camera", "port 554 answers (RTSP video)", "", "cameras")
    elif any(x in tl for x in ("synology", "truenas", "qnap", "unraid", "openmediavault")):
        be(title, f"its web page says {title}", "linux", "servers")
    elif "openssh" in sl and any(x in sl for x in ("debian", "ubuntu", "raspbian")):
        be(v or "Linux", f"ssh says {ssh}", "linux", "servers")
    elif "openssh" in sl and "vmware" in vl:
        be("a virtual machine", f"VMware network card, ssh says {ssh}", "linux", "servers")
    elif 631 in opn:
        be(v or "a printer", "IPP printing on port 631", "", "misc")
    elif 11434 in opn:
        be(v or "a computer", "Ollama answers on port 11434: a model server", "", "servers")
    elif 1883 in opn:
        be(v or "an MQTT broker", "MQTT on port 1883", "", "servers")
    elif "openssh" in sl or "dropbear" in sl:
        be(v or "a computer", f"ssh says {ssh}", "linux" if "openssh" in sl else "", "servers" if "openssh" in sl else "misc")
    elif row.get("vendor") == PRIVATE:
        out.update(what="a phone, tablet or laptop", why="a private MAC: it hides its own", group="phones", phone=True)
    elif vl.startswith(("apple", "samsung", "google", "xiaomi", "oneplus", "huawei")) and not opn:
        out.update(what=v, why=f"{v}, no open port", group="phones", phone=True)
    elif title:
        be(title, f"its web page says {title}", "", "misc")
    elif opn:
        be(v or "unknown maker", "answers on port " + ", ".join(str(x) for x in sorted(opn)), "", "misc")
    else:
        out.update(what=v or "unknown maker", why="answers nothing but ping: give it a name, or leave it")
    if not out["name"]:
        dhcp = str(row.get("name") or "").strip()
        good_title = title and not _GENERIC_TITLES.match(title) and title.lower() not in (out["what"] or "").lower()
        out["name"] = dhcp or (title if good_title and not out["phone"] else "") or \
            f"{out['what'] or 'device'} {str(row.get('ip') or '').split('.')[-1]}"
    return out


async def find(rows: list, now: Optional[float] = None) -> list:
    """Every row probed (in parallel, 32 connections at a time) and identified, in place."""
    sem = asyncio.Semaphore(PARALLEL)
    found = await asyncio.gather(*(probe(r["ip"], sem, now) for r in rows))
    for r, p in zip(rows, found):
        r.update(identify(r, p))
        r["ports"] = sorted(p.get("open") or [])
        r["crit"] = CRIT.get(r["group"], "low")
    return rows
