"""The daily security review: the MODEL finds what is exposed — not a list someone wrote.

A checklist someone wrote finds only what that person already knew to look for: a public host
can keep taking root passwords from the whole internet while every check written for it
passes. So:

  - code COLLECTS, read-only, what decides how exposed each machine is — who may log in and
    how, what listens, the firewall, which management services answer and from where, UPnP,
    an open resolver, the firmware's age — from every machine lanowl can log into;
  - it looks from OUTSIDE at what the internet can really reach: a public host (a VPS),
    scanned from here (TCP connect, rate-limited). The network itself is scanned from that
    host only if its public address is really the router's. Behind a provider's carrier-grade
    NAT (a 100.64.0.0/10 address on the router, another one seen from outside) the public
    address is the provider's box, shared, not ours to scan — and nothing inbound reaches the
    network through it anyway;
  - the MODEL reads it all against what good looks like and names each problem with one of a
    fixed set of checks, so "VPS: ssh accepts passwords" keeps the same name every day however
    it is worded — which is what lets the owner dismiss it once;
  - its findings go on the Security tab, marked as the model's. Paging only from
    `exposure.page_from` (two weeks of watching what it finds first), and then only a NEW
    critical one, once.

Never read: a password, a key, a Wi-Fi passphrase, a password hash (only whether an account
has a password at all), an SNMP community. Everything read goes through records.scrub too.
Runs after the morning's update check, or from the Security tab.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import shlex
import time
import xml.etree.ElementTree as ET
from typing import Optional

from .checks import _exec

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None
from .records import scrub
from .report import _html, label

log = logging.getLogger("lanowl.exposure")

RECORD = "exposure"
FACTS_MAX = 6000               # characters kept per machine
SEVERITIES = ("critical", "high", "warning", "info")

# The checks the model names a problem with. The key of a finding is machine + check: stable
# across rewordings, so a dismissal holds.
CHECKS = {
    "ssh_password_login": "ssh accepts passwords",
    "ssh_root_login": "root may log in over ssh",
    "no_firewall": "no firewall where one is needed",
    "internet_exposed": "a service reachable from the internet that should not be",
    "management_exposed": "a management service (ssh, web, winbox, api) reachable from where it should not be",
    "insecure_protocol": "telnet, ftp or plain-http management",
    "account": "an account without a password, a default or unexpected account, sudo without a password",
    "upnp": "UPnP lets devices open ports on their own",
    "open_resolver": "DNS answers the internet",
    "end_of_life": "firmware or OS no longer maintained",
    "weak_crypto": "old or weak crypto still allowed",
    "wifi": "an open or weakly protected Wi-Fi",
    "other": "anything else",
}

LINUX = r"""export LC_ALL=C
echo "== os"; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME, kernel $(uname -r)"
echo "== sshd (effective settings)"
sshd -T 2>/dev/null | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|authenticationmethods|allowusers|allowgroups|denyusers|maxauthtries|x11forwarding|permittunnel|gatewayports|allowtcpforwarding|gssapiauthentication|kerberosauthentication|allowagentforwarding|disableforwarding|subsystem|forcecommand|chrootdirectory) ' || echo "UNKNOWN: sshd -T did not run"
echo "== listening (proto local-address)"; ss -Htlnu 2>/dev/null | awk '{print $1, $5}' | sort -u
echo "== firewall"
command -v iptables >/dev/null && { iptables -S INPUT 2>&1 | head -40; iptables -S FORWARD 2>&1 | head -8; }
command -v nft >/dev/null && echo "nft: $(nft list ruleset 2>/dev/null | grep -cE 'accept|drop|reject') rule(s)"
command -v ufw >/dev/null && ufw status 2>&1 | head -12
echo "== accounts with a login shell"; awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" uid="$3" "$7}' /etc/passwd
echo "== account passwords (set / EMPTY; hashes never read)"
awk -F: '{s=$2; if (s=="") print $1": EMPTY PASSWORD"; else if (s !~ /^[!*x]/) print $1": set"}' /etc/shadow 2>/dev/null
echo "== sudo"; getent group sudo admin wheel 2>/dev/null; grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^[[:space:]]*#'
echo "== authorized ssh keys"; for d in /root /home/*; do f="$d/.ssh/authorized_keys"; [ -f "$f" ] && echo "$f: $(grep -cvE '^[[:space:]]*(#|$)' "$f") key(s)"; done
echo "== fail2ban"; systemctl is-active fail2ban 2>/dev/null || echo "not running / not installed"
echo "== automatic security updates"; systemctl is-active unattended-upgrades 2>/dev/null; grep -h Unattended /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo "20auto-upgrades: none"
p=$(ps -eo args 2>/dev/null | grep -m1 '^[c]loudflared')
if [ -n "$p" ]; then
  echo "== cloudflare tunnel (routes the INTERNET to services here; token never read)"
  echo "$p" | sed -E 's/(--token|token)[ =][^ ]+/\1 <hidden>/g; s/eyJ[A-Za-z0-9_-]{20,}/<hidden>/g' | cut -c1-160
  m=$(echo "$p" | sed -nE 's/.*--metrics ([^ ]+).*/\1/p')
  [ -n "$m" ] && curl -s -m5 "http://$m/config" | head -c 3000 && echo
fi
"""

ESXI = r"""echo "== version"; vmware -vl
echo "== sshd"; ssh -V 2>&1; grep -Ei '^(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|GSSAPIAuthentication|AllowTcpForwarding|AllowAgentForwarding|PermitTunnel|DisableForwarding|Subsystem)' /etc/ssh/sshd_config
echo "== firewall"; esxcli network firewall get
echo "== rulesets enabled (allowed from: All unless listed)"; esxcli network firewall ruleset list | grep -i true
esxcli network firewall ruleset allowedip list | grep -v ' All$' | grep -v '^---' | head -20
echo "== listening (proto local-address)"; esxcli network ip connection list | awk '$6=="LISTEN" {print $1, $4}' | sort -u | head -40
"""

# RouterOS: each group is one ssh command — a command RouterOS does not know fails the WHOLE
# line, so a v6/v7 difference must cost one group, not everything. Nothing that prints a
# secret: no /ppp secret, no wireless security profiles, no /snmp (its community), no scripts.
ROUTEROS = (
    "/system resource print; /system routerboard print; /system package update print",
    "/ip service print detail; /ip ssh print; /user print detail; /user group print",
    "/ip firewall filter print detail where chain=input; /ip firewall nat print detail",
    "/ip upnp print; /ip upnp interfaces print; /ip dns print; /ip cloud print",
    "/tool mac-server print; /tool mac-server mac-winbox print; "
    "/ip neighbor discovery-settings print; /ip socks print; /ip proxy print",
)

OPENWRT = r"""echo "== os"; grep -E 'DISTRIB_(DESCRIPTION|TARGET)' /etc/openwrt_release; cat /tmp/sysinfo/model 2>/dev/null
echo "== dropbear (ssh)"; uci -q show dropbear
echo "== web (uhttpd)"; uci -q show uhttpd | grep -E 'listen_http|redirect_https|rfc1918_filter' || echo "uhttpd: not installed"
echo "== firewall"; uci -q show firewall | grep -E "=(zone|rule|redirect|forwarding)$|\.(name|input|forward|src|dest|src_dport|dest_port|proto|target|family|enabled)="
echo "== listening (proto local-address)"; netstat -lntu 2>/dev/null | awk 'NR>2 {print $1, $4}' | sort -u
echo "== upnp"; uci -q show upnpd | grep -E 'enabled|enable_upnp|enable_natpmp' || echo "upnpd: not installed"
echo "== wifi (no keys)"; uci -q show wireless | grep -E "\.(ssid|encryption|disabled|mode|network)="
echo "== account passwords (set / EMPTY; hashes never read)"
awk -F: '{s=$2; if (s=="") print $1": EMPTY PASSWORD"; else if (s !~ /^[!*x]/) print $1": set"}' /etc/shadow
"""

SYSTEM = """You review the security of a home network for its owner, read on a phone. The facts \
below were read from the machines this morning by the monitor, read-only; take them as fact. \
Where a machine could not be read, it says so: that is not evidence of anything. The owner \
describes the network under THE NETWORK, at the end.

HOW TO READ IT:
- A PUBLIC host (a VPS, anything with its own internet address) is reachable from the whole \
internet on every port it listens on, unless its own firewall drops it; a provider firewall that \
filters nothing but ping is no firewall.
- Behind a carrier-grade NAT nothing on the internet can open a connection INTO the network \
through its address; behind an ordinary NAT, only through forwarded ports and UPnP.
- Remote access over WireGuard, ZeroTier or a similar overlay arrives from inside. But any \
CLOUDFLARE TUNNEL a machine runs is a door: each hostname the tunnel routes (its "ingress", in the \
facts) reaches the service behind it from the internet, and a connection through it arrives \
from 127.0.0.1. Such a route is guarded only if Cloudflare Access protects it — then the PUBLIC \
NAMES check shows a redirect to a cloudflareaccess.com login; otherwise anyone reaches the \
service (for ssh:// routes with Cloudflare's own client). Judge the service behind each route as \
if it were on the internet.
- What the owner says they chose on purpose (IoT on the main LAN, ssh kept reachable on a public \
host) is not a finding — but HOW something can be logged into still matters.

WHAT GOOD LOOKS LIKE: ssh by keys only, root not by password; a firewall on anything public; \
management (ssh, web UI, winbox, api, telnet, ftp) answering only from the LAN, the tunnels or the \
overlays — never from a WAN interface; no telnet, no ftp, no plain-http management from outside; \
no account without a password, no unexpected sudo without a password; UPnP off unless a device \
needs it; DNS not answering the internet; firmware and OS still getting security updates; Wi-Fi \
with WPA2 or better.

The OUTSIDE SCAN is what the internet reaches: an open port there on a public host is exposed \
to anyone. The PUBLIC NAMES are the owner's own hostnames, looked up and requested from outside.

Report only what the facts show — quote the fact. A risk the facts cannot show is not a finding. \
Do not report what is fine. Severity: "critical" = someone on the internet can get in or nearly \
(a password login open to the internet for root, an account without a password reachable from \
outside, a management service open to the internet); "high" = a real weakness one step from that; \
"warning" = worth fixing; "info" = worth knowing. Be sparing with critical.

Name each problem with ONE check from this list (the machine + the check is its name, so the same \
problem must get the same check every day): {checks}.

Reply with ONLY this JSON object, no prose, no code fence:
{{"summary": "<two sentences at most: how exposed the network is, the worst thing first>",
 "findings": [{{"ip": "<the machine's address, exactly as given>", "check": "<one of the checks>",
   "severity": "critical"|"high"|"warning"|"info",
   "title": "<one short line: the problem, for a phone>",
   "evidence": "<the fact that shows it, quoted>",
   "fix": "<one concrete step>"}}]}}"""


def _q(s: str) -> str:
    return shlex.quote(s)


def top_ports(n: int = 1000, path: str = "/usr/share/nmap/nmap-services") -> list:
    """nmap's own most-used TCP ports, from its services file — the list `--top-ports` uses."""
    ports = []
    try:
        with open(path) as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 3 and p[1].endswith("/tcp"):
                    try:
                        ports.append((float(p[2]), int(p[1].split("/")[0])))
                    except ValueError:
                        continue
    except OSError:
        return []
    ports.sort(reverse=True)
    return sorted({p for _, p in ports[:n]})


def parse_open(xml_text: str) -> list:
    """nmap -oX -> the open TCP ports, with the service nmap guesses by port number."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    out = []
    for port in root.iter("port"):
        st = port.find("state")
        if st is not None and st.get("state") == "open":
            sv = port.find("service")
            out.append({"port": int(port.get("portid") or 0),
                        "service": sv.get("name") if sv is not None else ""})
    return out


def _cgnat(addr: str) -> bool:
    """The provider's shared NAT range (RFC 6598), where a carrier-grade NAT puts the router's
    WAN address. Not any private address: overlays (ZeroTier's 10.147.x, WireGuard tunnels)
    put private addresses on the router too."""
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


def clip(text: str, n: int = FACTS_MAX) -> str:
    text = scrub(text or "").strip()
    return text if len(text) <= n else text[:n] + f"\n[… {len(text) - n} characters cut]"


class Exposure:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("exposure") or {}
        self.enabled = bool(c.get("enabled", False))
        self.hosts = [dict(h) for h in (c.get("hosts") or []) if h.get("ip") and h.get("via")]
        self.page_from = str(c.get("page_from") or "")
        sc = c.get("outside_scan") or {}
        self.scan_ports = int(sc.get("top_ports", 1000))
        self.scan_rate = int(sc.get("max_rate", 20))
        # the owner's own hostnames, looked at from outside: a tunnel's public names lead
        # inside, so what they answer is exposure too
        self.names = [str(n).strip().lower() for n in (c.get("public_names") or []) if str(n).strip()]
        self.timeout_s = float(c.get("model_timeout_s", 900))
        self._task: Optional[asyncio.Task] = None
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("exposure: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k, dflt in (("facts", {}), ("findings", []), ("dismissed", {}), ("announced", []),
                        ("outside", {})):
            self.rec.setdefault(k, dflt)

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("exposure: record not saved: %s", e)

    # --- when ---------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def due(self, now: float) -> bool:
        """Once a day, after the morning's update check has finished."""
        if not self.enabled or self.running:
            return False
        U = self.a.updates
        at = U._today_at(U.at, now)
        return float(U.rec.get("last_done") or 0) >= at and float(self.rec.get("last") or 0) < at

    def start(self, reason: str) -> bool:
        if not self.enabled or self.running:
            return False
        self.rec["last"] = time.time()          # claimed now: a slow run must not start twice
        self._task = asyncio.ensure_future(self._guarded(reason))
        return True

    async def _guarded(self, reason: str):
        try:
            await self.run(reason)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("exposure: the review failed")
            self.rec["error"] = "the review failed — see lanowl's log"
            self._save()

    # --- collecting -----------------------------------------------------------------------
    def _name(self, ip: str, h: Optional[dict] = None) -> str:
        dev = self.a.inv.get(ip)
        return dev.name if dev is not None else str((h or {}).get("name") or ip)

    async def _facts(self, h: dict) -> dict:
        t0 = time.time()
        try:
            return await self._read(h)
        finally:
            if h["via"] in ("key", "sudo") and getattr(self.a, "hostlog", None) is not None:
                # its own sudo lands in the auth log the host-log triage reads: say so, with
                # the time, rather than hide it (hostlog.note_own)
                self.a.hostlog.note_own(h["ip"], t0, time.time(),
                                        "its daily security review (a read-only script, "
                                        + ("as root" if h["via"] == "key" else "via sudo") + ")")

    async def _read(self, h: dict) -> dict:
        ip, via = h["ip"], h["via"]
        acc = self.a.access
        if via == "key":                                       # root, over lanowl's key
            rc, out, err = await self.a.actions._ssh_run(ip, "sh -c " + _q(LINUX), 90, root=True)
        elif via == "sudo":                                    # the listed login + its sudo
            rc, out, err = await acc.ssh(ip, "sudo -S -p '' sh -c " + _q(LINUX),
                                         sudo_pw=True, timeout_s=90)
        elif via == "esxi":
            rc, out, err = await acc.ssh(ip, ESXI, timeout_s=90)
        elif via == "openwrt":
            rc, out, err = await acc.ssh(ip, OPENWRT, timeout_s=60)
        elif via == "profile":                                 # the owner's own kind
            ok, v = await self.a.kinds.run(self.a, ip, "security")
            return {"ok": True, "text": clip(v)} if ok else {"ok": False, "error": v}
        elif via == "routeros":
            parts, errs = [], []
            for cmd in ROUTEROS:
                rc, out, err = await acc.ssh(ip, cmd, user_suffix="+ct", timeout_s=40)
                if rc is None or (out or "").lstrip().startswith(("bad command", "syntax error",
                                                                      "expected ")):
                    errs.append(f"[{cmd.split(';')[0]} …: {(err or out or 'no answer').strip()[:120]}]")
                else:
                    parts.append(f"== {cmd}\n{out}")
            if not parts:
                return {"ok": False, "error": "; ".join(errs)[:300] or "no answer"}
            return {"ok": True, "text": clip("\n".join(parts + errs))}
        else:
            return {"ok": False, "error": f"unknown way to read it: {via}"}
        if rc is None or not (out or "").strip():
            return {"ok": False, "error": (err or "no answer").strip().splitlines()[-1][:200]
                    if (err or "").strip() else "no answer"}
        return {"ok": True, "text": clip(out)}

    def _public_host(self) -> str:
        """The server on the internet the network is looked at from: `actions.checks.vps`, else
        the first reviewed host lanowl reaches by its key at a public address."""
        vps = str(((self.a.cfg.get("actions") or {}).get("checks") or {}).get("vps") or "")
        if vps:
            return vps
        lans = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12",
                                                    "192.168.0.0/16", "100.64.0.0/10")]
        for h in self.hosts:
            try:
                addr = ipaddress.ip_address(h["ip"])
            except ValueError:
                continue
            if h["via"] == "key" and not any(addr in n for n in lans):
                return h["ip"]
        return ""

    async def _outside(self) -> dict:
        """What the internet reaches: the public host scanned from here; the network from that
        host only when its public address is really on the router (never the provider's NAT)."""
        out: dict = {"ts": time.time()}
        vps = self._public_host()
        if vps:
            rc, xml, err = await _exec(
                ["nmap", "-sT", "-Pn", "-n", "--top-ports", str(self.scan_ports),
                 "--max-rate", str(self.scan_rate), "-oX", "-", vps], 600)
            out["vps"] = ({"ip": vps, "open": parse_open(xml), "ports_tried": self.scan_ports}
                          if rc == 0 else {"ip": vps, "error": (err or "nmap failed").strip()[-200:]})
        if self.names:
            out["public_names"] = await asyncio.gather(*(self._name_check(n) for n in self.names))
        seen, router_addrs = self._house_public(), await self._router_addrs()
        if not seen:
            out["home"] = {"note": "UNKNOWN: the network's public address is not known yet"}
        elif seen not in router_addrs:
            wan = next((a for a in sorted(router_addrs) if _cgnat(a)), "")
            out["home"] = {"public_address": seen, "scanned": False,
                            "note": f"behind the provider's NAT: the router's own WAN address is "
                                    f"{wan or 'private'}, so {seen} is the provider's and nothing "
                                    "on the internet can open a connection into the network"}
        else:
            out["home"] = await self._scan_house_from_vps(seen)
        return out

    async def _name_check(self, name: str) -> dict:
        """One of the owner's hostnames from outside: what it resolves to, and what one HTTPS
        GET gets — without following a redirect, which is where Cloudflare Access would send a
        stranger to log in."""
        out: dict = {"name": name}
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(name, 443, proto=6)
            out["resolves_to"] = sorted({i[4][0] for i in infos})[:4]
        except Exception as e:
            out["resolves_to"] = f"does not resolve ({type(e).__name__})"
            return out
        if aiohttp is None:
            return out
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                async with s.get(f"https://{name}/", allow_redirects=False) as r:
                    body = (await r.content.read(4096)).decode("utf-8", "replace")
                    loc = r.headers.get("Location", "")
                    t = re.search(r"<title>([^<]{0,120})</title>", body, re.I)
                    out.update(https=r.status, server=r.headers.get("Server", ""),
                               **({"redirects_to": loc[:160]} if loc else {}),
                               **({"title": t.group(1).strip()} if t else {}),
                               **({"body": "empty"} if not body.strip() else {}),
                               access_login=("cloudflareaccess.com" in loc))
        except Exception as e:
            out["https"] = f"no answer ({type(e).__name__})"
        return out

    def _house_public(self) -> str:
        h = next((x for x in (getattr(self.a.hostlog, "hosts", None) or []) if x.public), None)
        return str(getattr(h, "self_addr", "") or "") if h is not None else ""

    async def _router_addrs(self) -> set:
        try:
            from . import routeros
            r = await routeros.shared(self.a.cfg).read("ip/address")
            rows = (r.data or {}).get("json") or [] if r.ok and isinstance(r.data, dict) else []
            return {str(x.get("address", "")).split("/")[0] for x in rows}
        except Exception:
            return set()

    async def _scan_house_from_vps(self, addr: str) -> dict:
        ports = " ".join(str(p) for p in top_ports(self.scan_ports))
        if not ports:
            return {"public_address": addr, "error": "no port list (nmap-services missing)"}
        vps = self._public_host()
        cmd = (f"for p in {ports}; do echo $p; done | xargs -P 20 -I{{}} sh -c "
               + _q(f"nc -z -w 2 {addr} {{}} 2>/dev/null && echo OPEN {{}}") + "; true")
        rc, out, err = await self.a.actions._ssh_run(vps, cmd, 400)
        if rc is None:
            return {"public_address": addr, "error": (err or "no answer").strip()[-200:]}
        return {"public_address": addr, "scanned_from": vps, "ports_tried": self.scan_ports,
                "open": sorted(int(x.split()[1]) for x in (out or "").splitlines()
                               if x.startswith("OPEN "))}

    # --- the review ---------------------------------------------------------------------------
    async def run(self, reason: str = "scheduled") -> list:
        t0 = time.time()
        log.info("exposure: reading %d machine(s) (%s)", len(self.hosts), reason)
        res = await asyncio.gather(*(self._facts(h) for h in self.hosts), return_exceptions=True)
        facts = {}
        for h, r in zip(self.hosts, res):
            if isinstance(r, Exception):
                r = {"ok": False, "error": f"{type(r).__name__}: {r}"[:200]}
            facts[h["ip"]] = {"name": self._name(h["ip"], h), "kind": h["via"], "read": time.time(), **r}
        outside = await self._outside()
        # the model's sandboxes, proven with the review (daily is enough: their walls change
        # only when they restart) — and a fact for it: a sandbox that could reach out is
        # exposure too
        boxes = {}
        for key, sh in (("owner", getattr(self.a, "shell", None)),
                        ("audit", getattr(self.a, "shell_audit", None))):
            if sh is not None and sh.enabled:
                st = await sh.canary()
                boxes[key] = {"isolated": st.get("ok"), "why": st.get("why")}
        outside["model_sandboxes"] = boxes
        self.rec.update(facts=facts, outside=outside)
        findings, summary, err = await self._review(facts, outside)
        self.rec["error"] = err
        if findings is not None:
            self.rec["findings"] = findings
            self.rec["summary"] = summary
            self.rec["reviewed"] = time.time()
        self.rec["last_done"] = time.time()
        self._prune_dismissed()
        await self._announce()
        self._save()
        # each open finding's fix written out for the owner (fixes.py) — never run
        fx = getattr(self.a, "fixes", None)
        if fx is not None and findings is not None:
            fx.after_review()
        # the scan's CVE matches judged again with this morning's facts (cves.py) — what was
        # announced stays announced, so it pages only what is new
        c = getattr(self.a, "cves", None)
        if c is not None and c.after_review and ((self.a.updates.rec.get("scan") or {}).get("found")):
            c.start("after the security review")
        log.info("exposure: done in %.0fs — %d machine(s) read, %s finding(s)%s", time.time() - t0,
                 sum(1 for f in facts.values() if f.get("ok")),
                 len(findings) if findings is not None else "no",
                 f" ({err})" if err else "")
        return findings or []

    def context(self, facts: dict, outside: dict) -> str:
        lines = [f"TODAY: {time.strftime('%A %Y-%m-%d')}", "", "OUTSIDE SCAN (what the internet reaches):",
                 json.dumps(outside, ensure_ascii=False, default=str), ""]
        dis = [f"{k} — {v.get('note') or 'no reason given'}" for k, v in self.rec["dismissed"].items()]
        if dis:
            # Still to be REPORTED while they hold: the code keeps a dismissed finding out of what
            # matters. Told "do not report these", a model obeys, the code reads the silence as
            # "fixed", and the owner's dismissals are forgotten.
            lines += ["DISMISSED BY THE OWNER (known and accepted, the key is ip:check). Still report "
                      "each one that still holds, with the SAME ip and check — the monitor keeps it "
                      "out of what matters; leaving it out would read as if it were fixed:"]
            lines += [f"  {x}" for x in dis] + [""]
        for ip, f in facts.items():
            lines.append(f"=== {f['name']} ({ip}) — read as {f['kind']}")
            lines.append(f["text"] if f.get("ok") else f"COULD NOT BE READ: {f.get('error')}")
            lines.append("")
        lines.append("Review it and return the JSON.")
        return "\n".join(lines)

    async def _review(self, facts: dict, outside: dict) -> tuple:
        if self.a.no_llm:
            return None, "", "no model (--no-llm)" if self.a._no_llm_cli else "the local model is switched off"
        system = SYSTEM.format(checks="; ".join(f"{k} ({v})" for k, v in CHECKS.items()))
        async with self.a.model_turn():
            v = await self.a.agent.ask_json(system, self.context(facts, outside),
                                            timeout_s=self.timeout_s)
        if not isinstance(v, dict) or not isinstance(v.get("findings"), list):
            return None, "", ("the local model was switched off" if self.a.no_llm
                              else "the model gave no usable review")
        return self.normalise(v["findings"], facts), str(v.get("summary") or "")[:400], ""

    def normalise(self, raw: list, facts: dict) -> list:
        """The model's findings, held to the rules: a machine it was shown, a check from the list,
        a known severity — and one finding per machine + check (the worst, with the others'
        titles folded in)."""
        by: dict = {}
        known = set(facts) | {x.get("ip") for x in (self.rec.get("outside") or {}).values()
                              if isinstance(x, dict)}
        for f in raw:
            if not isinstance(f, dict):
                continue
            ip = str(f.get("ip") or "").strip()
            if ip not in known:
                continue
            chk = str(f.get("check") or "").strip().lower()
            chk = chk if chk in CHECKS else "other"
            sev = str(f.get("severity") or "").strip().lower()
            sev = sev if sev in SEVERITIES else "warning"
            e = {"key": f"exp:{ip}:{chk}", "ip": ip, "check": chk, "severity": sev,
                 "name": self._name(ip, facts.get(ip)),
                 "title": " ".join(str(f.get("title") or CHECKS[chk]).split())[:160],
                 "evidence": " ".join(str(f.get("evidence") or "").split())[:300],
                 "fix": " ".join(str(f.get("fix") or "").split())[:240]}
            old = by.get(e["key"])
            if old is None:
                by[e["key"]] = e
            elif SEVERITIES.index(sev) < SEVERITIES.index(old["severity"]):
                e["title"] = f"{e['title']}; {old['title']}"[:240]
                by[e["key"]] = e
            else:
                old["title"] = f"{old['title']}; {e['title']}"[:240]
        return sorted(by.values(), key=lambda x: (SEVERITIES.index(x["severity"]), x["key"]))

    # --- the owner's side -------------------------------------------------------------------------
    def dismiss(self, key: str, note: str = "") -> dict:
        """A finding of the last review — or, by its key (exp:<ip>:<check>), one the owner has
        already decided about that the last review did not raise."""
        m = re.match(r"^exp:([0-9a-fA-F.:]+):([a-z_]+)$", str(key))
        if not any(f["key"] == key for f in self.rec["findings"]) and not (m and m.group(2) in CHECKS):
            return {"ok": False, "error": "no such finding"}
        self.rec["dismissed"][key] = {"ts": time.time(), "note": " ".join(str(note).split())[:300],
                                      "missed": 0}
        self._save()
        return {"ok": True}

    def undismiss(self, key: str) -> dict:
        if self.rec["dismissed"].pop(key, None) is None:
            return {"ok": False, "error": "it was not dismissed"}
        self._save()
        return {"ok": True}

    MISSES_TO_FORGET = 3

    def _prune_dismissed(self):
        """A dismissal lasts until the owner undoes it — or the problem is gone: forgotten after
        MISSES_TO_FORGET reviews in a row without it, so it can come back if the problem does.
        Not after one: a model that leaves a finding out once has not proved it fixed."""
        if self.rec.get("reviewed") and self.rec.get("reviewed") >= self.rec.get("last", 0):
            keys = {f["key"] for f in self.rec["findings"]}
            for k, d in list(self.rec["dismissed"].items()):
                d["missed"] = 0 if k in keys else int(d.get("missed") or 0) + 1
                if d["missed"] >= self.MISSES_TO_FORGET:
                    del self.rec["dismissed"][k]

    def paging(self, now: Optional[float] = None) -> bool:
        """The trial: until `page_from` the findings stay on the dashboard and the weekly review."""
        if not self.page_from:
            return True
        try:
            return (now or time.time()) >= time.mktime(time.strptime(self.page_from, "%Y-%m-%d"))
        except ValueError:
            return False

    async def _announce(self):
        new = [f for f in self.rec["findings"] if f["severity"] == "critical"
               and f["key"] not in self.rec["dismissed"] and f["key"] not in self.rec["announced"]]
        # a key that went away is forgotten, so it pages again if it comes back
        keys = {f["key"] for f in self.rec["findings"]}
        self.rec["announced"] = [k for k in self.rec["announced"] if k in keys]
        if not new or not self.paging():
            return
        lines = ["🔴 <b>Security review</b> " + time.strftime("%H:%M") + " — new and critical:"]
        for f in new[:5]:
            lines.append(f"• <b>{_html(label(f['name'], f['ip']))}</b>: {_html(f['title'])}"
                         + (f"\n  <i>{_html(f['fix'])}</i>" if f.get("fix") else ""))
        lines.append("<i>The model's review of this morning's facts — the Security tab has the evidence.</i>")
        self.a._emit_telegram("critical", "\n".join(lines))
        self.rec["announced"] += [f["key"] for f in new]

    # --- reading ------------------------------------------------------------------------------
    def view(self) -> dict:
        d = self.rec["dismissed"]
        return {"enabled": self.enabled, "running": self.running, "last": self.rec.get("last_done"),
                "reviewed": self.rec.get("reviewed"), "summary": self.rec.get("summary") or "",
                "error": self.rec.get("error") or "", "paging": self.paging(),
                "page_from": self.page_from,
                "findings": [{**f, **({"dismissed": d[f["key"]]} if f["key"] in d else {})}
                             for f in self.rec["findings"]],
                "machines": [{"ip": ip, "name": f["name"], "ok": f.get("ok"),
                              "error": f.get("error")} for ip, f in self.rec["facts"].items()],
                "outside": self.rec.get("outside") or {}}

    def weekly_lines(self) -> list:
        if not self.enabled or not self.rec.get("reviewed"):
            return []
        fs = [f for f in self.rec["findings"] if f["key"] not in self.rec["dismissed"]]
        if not fs:
            return ["🔎 Security review: nothing exposed that the model could find."]
        worst = fs[0]      # plain text: the weekly review escapes its lines itself
        return [f"🔎 Security review: {len(fs)} finding(s), the worst {worst['severity']}: "
                f"{label(worst['name'], worst['ip'])} — {worst['title']}"]
