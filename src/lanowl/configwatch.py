"""What changed in the machines' configurations, said in plain words.

Backups keep each machine's configuration, but nobody compares two of them: a firewall rule, a
user, an ssh key or a port forward added on a Tuesday is visible to nobody — whether the owner
added it and forgot, or someone else did. Every morning after the update check (and on the
Security tab's Compare now):

  - code reads, read-only, a configuration snapshot of each machine: a MikroTik's
    `/export terse` (one line per item, secrets hidden — RouterOS 6 asked to hide them), a
    Linux host's effective sshd settings, accounts, sudo rules, ssh key fingerprints, crontabs,
    enabled services, listening ports, firewall, WireGuard peers, Cloudflare Tunnel routes;
  - compares it with yesterday's (the first one is the baseline: nothing to say);
  - the MODEL says what each change does and how risky it is — none, low, high, critical —
    knowing what the owner ran on the machine in between (an upgrade explains changed defaults);
  - code holds it to the facts: a quoted line must be in the diff, and a change in a section
    that decides who gets in (firewall, users, keys, sshd, services, schedulers, VPN) that the
    model did not explain is listed anyway, as the rule's (`RISKY`). No model: the rule alone.

A change is an event, not a condition: it is listed under What changed for 30 days. A high or
critical one is also a security event (seclog.py) — in To decide, with Handled
("It was me") — and rides the next digest once. Nothing pages.
"""
from __future__ import annotations

import asyncio
import difflib
import logging
import re
import shlex
import time
import uuid
from typing import Optional

from .records import scrub


def change_id(c: dict) -> str:
    """One change's name across the Timeline, Security and Now: its own id when it has one."""
    if c.get("id"):
        return f"cfg:{c['id']}"
    import zlib
    return f"cfg:{c.get('ip')}:{float(c.get('ts') or 0):.0f}:{zlib.crc32(str(c.get('what') or '').encode()):08x}"
from .reboot import routeros_field
from .report import _html, label
from .reviews import Review, actions_done, clip, today_at, words

log = logging.getLogger("lanowl.configwatch")

RISKS = ("none", "low", "high", "critical")
KEEP_DAYS = 30
DIFF_MAX = 7000             # characters of one machine's diff shown to the model

LINUX = r"""export LC_ALL=C
echo "== sshd (effective settings)"; sshd -T 2>/dev/null | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|authenticationmethods|allowusers|allowgroups|denyusers|denygroups|x11forwarding|permittunnel|gatewayports|allowtcpforwarding|allowagentforwarding|subsystem|forcecommand|chrootdirectory|authorizedkeysfile|trustedusercakeys) ' | sort
echo "== accounts with a login shell"; awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1" uid="$3" home="$6" shell="$7}' /etc/passwd | sort
echo "== groups that grant power"; getent group sudo admin wheel docker adm lxd 2>/dev/null | sort
echo "== sudo rules"; grep -rhvE '^[[:space:]]*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d 2>/dev/null | sort
echo "== authorized ssh keys (fingerprints)"; for d in /root /home/*; do f="$d/.ssh/authorized_keys"; [ -f "$f" ] && ssh-keygen -lf "$f" 2>/dev/null | sed "s|^|$f: |"; done
echo "== crontabs"; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed "s|^|$u: |"; done
grep -HvE '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d/* 2>/dev/null
echo "== services and timers enabled"; systemctl list-unit-files --state=enabled --type=service,timer --no-legend 2>/dev/null | awk '{print $1}' | sort
echo "== listening (proto address process)"; ss -Htlnup 2>/dev/null | awk '{p=$5; sub(/.*:/,"",p); if (p+0 < 32768) print $1, $5, $7}' | sed -E 's/,pid=[0-9]+,fd=[0-9]+//g; s/users:\(\(//; s/\)\)//' | sort -u
echo "== firewall"; command -v iptables >/dev/null && iptables -S 2>/dev/null | grep -vE '^-A f2b-[^ ]+ -s '
command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -vE 'elements = |^[[:space:]]*[0-9a-f.:/]+,?[[:space:]]*$' | head -200
echo "== wireguard peers"; command -v wg >/dev/null && wg show all allowed-ips 2>/dev/null | sort
p=$(ps -eo args 2>/dev/null | grep -m1 '^[c]loudflared')
if [ -n "$p" ]; then
  echo "== cloudflare tunnel routes"
  m=$(echo "$p" | sed -nE 's/.*--metrics ([^ ]+).*/\1/p')
  [ -n "$m" ] && curl -s -m5 "http://$m/config" | tr ',' '\n' | grep -E '"(hostname|service|path)"' | head -40
fi
echo "== containers"; command -v docker >/dev/null && docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | sort
"""

# Sections where a change decides who can get in or what runs by itself: never left unsaid.
RISKY_ROS = ("/ip firewall", "/ipv6 firewall", "/ip service", "/user", "/ip ssh", "/ip upnp",
             "/ip dns", "/ip socks", "/ip proxy", "/tool mac-server", "/interface wireguard",
             "/ip ipsec", "/system scheduler", "/system script", "/ppp secret", "/snmp",
             "/ip cloud", "/certificate", "/ip hotspot", "/tool netwatch", "/tool romon",
             "/interface l2tp-server", "/interface pptp-server", "/interface sstp-server",
             "/interface ovpn-server", "/ip neighbor discovery-settings")
RISKY_LINUX = ("sshd", "accounts", "groups", "sudo", "authorized ssh keys", "crontabs", "firewall",
               "wireguard", "cloudflare", "listening")

SYSTEM = """You read what changed in the configuration of a family's home network machines since \
the last snapshot (normally yesterday morning), for its owner, read on a phone. The diffs below are \
exact: "-" lines were there before, "+" lines are there now. The machines are MikroTik routers and \
access points (a RouterOS export, one item per line, secrets hidden) and Linux servers (a snapshot \
of their sshd settings, accounts, sudo, ssh keys, crontabs, services, listening ports, firewall, \
WireGuard peers, Cloudflare Tunnel routes). Take them as fact.

The owner describes the network under THE NETWORK, at the end. Behind a provider's \
carrier-grade NAT, a port open "on the WAN" is reachable from the provider's network, not the \
internet; a public host (a VPS) is open to the whole internet wherever its firewall lets traffic \
through; a Cloudflare Tunnel route is a way in from outside.

The owner changes these machines themselves — most changes are theirs. Your job is not to guess who; it \
is to say, for each change, WHAT IT DOES in plain words (e.g. "a new firewall rule now accepts \
winbox (8291) from any interface", "the user 'lanowl' joined the group 'full'", "a new WireGuard \
peer may use 10.8.0.9") and HOW IT CHANGES WHO CAN GET IN OR WHAT RUNS BY ITSELF:
  "critical" = it opens the network from the internet or adds a way in for someone new (a port \
forward, management open on the WAN, a new admin user or ssh key, password login turned on, a \
firewall drop removed);
  "high"     = it weakens security inside, or adds something that runs by itself (a scheduler or \
script, a cron job, a new service listening);
  "low"      = an ordinary change (a static lease, a name, a Wi-Fi channel, a route);
  "none"     = no real change (a re-ordering, a default the system rewrote after an update, a \
process that only moved).
What RAN on each machine in between is listed: an update or reboot explains changed defaults and \
moved processes — say so. What its OWN LOG showed in between (lanowl's log checks) and the devices \
NEW on the network in between are listed too: a change that matches an admin session from the LAN \
at that time, or a device that just joined, is most likely the owner's own work — say so in `why`, \
naming the session ("made in the admin session from 192.168.88.10 at 14:05, the router log says"). \
Keep "critical" for what would let someone in even if the owner made it by mistake (management open \
to the internet, password login on a public host, a firewall drop removed); a VPN peer, a route or a \
user the owner added in their own session is "high" at most. One change may span several lines: \
describe it once, quoting its lines.

Reply with ONLY this JSON object, no prose, no code fence:
{"summary": "<one sentence: what changed overall, the riskiest first>",
 "changes": [{"ip": "<the machine's address, exactly as given>", "what": "<one line for a phone>",
   "risk": "none"|"low"|"high"|"critical", "why": "<why that risk; empty for none/low>",
   "lines": ["<the diff lines it is about, copied exactly, with their + or ->", ...]}]}"""


def _q(s: str) -> str:
    return shlex.quote(s)


# An interface the router's own scripts switch on and off: "/interface wireless enable wlan1" in a
# netwatch's down-script, "... disable wlan1" in its up-script. On a standby backup link that IS
# the failover (its radio is on only while the main line is down), so its `disabled=` is state,
# not configuration — compared, the radio's state would read as a change every morning.
_TOGGLED = re.compile(r'/interface(?:\s+[a-z0-9-]+)?\s+(?:enable|disable)\s+(?:\[\s*find\s+(?:default-)?name=)?"?([A-Za-z0-9_.@-]+)')
_DISABLED = re.compile(r"\s+disabled=(?:yes|no)\b")


def toggled(text: str) -> set:
    """The interfaces an export's own scripts or netwatch enable and disable."""
    return set(_TOGGLED.findall(text or ""))


def clean_export(text: str) -> str:
    """A RouterOS export as lines that compare: no comment header (its date, software id and
    serial), no blank lines, no trailing spaces, nothing secret-shaped — and no `disabled=` on an
    interface the router's own scripts switch on and off (`toggled`)."""
    names = toggled(text)
    out = []
    for raw in (text or "").splitlines():
        s = raw.rstrip()
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        if names and s.startswith("/interface") and any(
                f"default-name={n} ]" in s or re.search(rf'\bname="?{re.escape(n)}"?(\s|$)', s) for n in names):
            s = _DISABLED.sub("", s)
        out.append(s)
    return scrub("\n".join(out))


# nftables prints each rule's packet and byte counts: they move every second, and would make
# every Linux firewall "changed" every morning — all counters.
_COUNTER = re.compile(r"\bcounter packets \d+ bytes \d+")


def _same(text: str) -> str:
    return text


def clean_linux(text: str) -> str:
    return scrub("\n".join(_COUNTER.sub("counter", x.rstrip()) for x in (text or "").splitlines() if x.strip()))


# how a kept snapshot is cleaned again before it is compared: a better cleaner is no change
CLEAN = {"routeros": clean_export, "linux": clean_linux, "profile": _same}


def section_of(line: str, kind: str, header: str = "") -> str:
    """Which part of the configuration a line belongs to: a RouterOS line's own path (terse
    exports start every line with it), a Linux snapshot's last `== header`."""
    if kind == "routeros":
        m = re.match(r"^(/[a-z0-9 /-]+?) (add|set|remove)\b", line.strip())
        return m.group(1) if m else (line.strip().split(" ", 1)[0] or "?")
    return header or "?"


def risky(section: str, kind: str) -> bool:
    if kind == "routeros":
        return any(section == p or section.startswith(p + " ") for p in RISKY_ROS)
    return any(section.startswith(p) for p in RISKY_LINUX)


def diff(old: str, new: str, kind: str) -> list:
    """[(sign, line, section)] for every line removed or added, in order."""
    a, b = old.splitlines(), new.splitlines()
    out = []
    hdr_a = hdr_b = ""
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    heads_a = _headers(a)
    heads_b = _headers(b)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for i in range(i1, i2):
            hdr_a = heads_a[i]
            out.append(("-", a[i], section_of(a[i], kind, hdr_a)))
        for j in range(j1, j2):
            hdr_b = heads_b[j]
            out.append(("+", b[j], section_of(b[j], kind, hdr_b)))
    return out


def _headers(lines: list) -> list:
    """The `== header` each line sits under (a Linux snapshot)."""
    cur, out = "", []
    for x in lines:
        if x.startswith("== "):
            cur = x[3:].strip()
        out.append(cur)
    return out


def hunks(old: str, new: str, n: int = 1) -> str:
    """The unified diff the model reads, headers off."""
    lines = [x for x in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=n)
             if not x.startswith(("---", "+++"))]
    text = "\n".join(lines)
    return text if len(text) <= DIFF_MAX else text[:DIFF_MAX] + f"\n[… {len(text) - DIFF_MAX} characters cut]"


class ConfigWatch(Review):
    NAME = "configwatch"
    TITLE = "What changed"
    ICON = "🛠️"

    def __init__(self, auditor):
        super().__init__(auditor)
        self.machines = [dict(m) for m in (self.c.get("machines") or [])
                         if m.get("ip") and m.get("via") in ("routeros", "key", "sudo", "profile")]
        self.timeout_s = float(self.c.get("model_timeout_s", 900))

    @staticmethod
    def DEFAULTS() -> dict:
        return {"last": 0.0, "last_done": 0.0, "error": "", "told": [], "snap": {}, "changes": [],
                "machines": {}, "summary": ""}

    def due(self, now: float) -> bool:
        """Once a day, after the morning's update check — like the security review."""
        if not self.enabled or self.running:
            return False
        U = self.a.updates
        at = today_at(self.at or U.at, now)
        done = float(U.rec.get("last_done") or 0) >= at if U.enabled else now >= at
        return done and float(self.rec.get("last") or 0) < at

    def _name(self, ip: str, m: Optional[dict] = None) -> str:
        dev = self.a.inv.get(ip)
        return dev.name if dev is not None else str((m or {}).get("name") or ip)

    # --- reading ------------------------------------------------------------------------------
    async def read(self, m: dict) -> dict:
        ip, via, acc = m["ip"], m["via"], self.a.access
        t0 = time.time()
        try:
            if via == "routeros":
                rc, out, err = await acc.ssh(ip, "/system resource print", user_suffix="+ct", timeout_s=20)
                if rc != 0 or "version" not in (out or ""):
                    return {"ok": False, "error": words(err or out or "no answer", 160)}
                v7 = (re.findall(r"\d+", routeros_field(out, "version")) or ["0"])[0] >= "7"
                rc, out, err = await acc.ssh(ip, "/export terse" if v7 else "/export terse hide-sensitive",
                                             user_suffix="+ct", timeout_s=120)
                if rc != 0 or "/" not in (out or ""):
                    return {"ok": False, "error": words(err or "the export came back empty", 160)}
                return {"ok": True, "kind": "routeros", "text": clean_export(out)}
            if via == "profile":                      # the owner's own kind (kinds.py)
                ok, v = await self.a.kinds.run(self.a, ip, "config")
                return {"ok": True, "kind": "profile", "text": v} if ok else \
                    {"ok": False, "error": words(v, 160)}
            if via == "key":
                rc, out, err = await self.a.actions._ssh_run(ip, "sh -c " + _q(LINUX), 90, root=True)
            else:
                rc, out, err = await acc.ssh(ip, "sudo -S -p '' sh -c " + _q(LINUX), sudo_pw=True, timeout_s=90)
            if rc is None or not (out or "").strip():
                e = (err or "").strip()
                return {"ok": False, "error": words(e.splitlines()[-1] if e else "no answer", 160)}
            return {"ok": True, "kind": "linux", "text": clean_linux(out)}
        finally:
            if via in ("key", "sudo") and getattr(self.a, "hostlog", None) is not None:
                self.a.hostlog.note_own(ip, t0, time.time(), "its daily configuration snapshot (a read-only "
                                        "script, " + ("as root" if via == "key" else "via sudo") + ")")

    # --- the run ------------------------------------------------------------------------------
    async def run(self, reason: str = "scheduled") -> list:
        t0 = time.time()
        res = await asyncio.gather(*(self.read(m) for m in self.machines), return_exceptions=True)
        changed = {}         # ip -> {"name", "kind", "old", "new", "diff", "since"}
        for m, r in zip(self.machines, res):
            ip = m["ip"]
            if isinstance(r, Exception):
                r = {"ok": False, "error": f"{type(r).__name__}: {r}"[:160]}
            name = self._name(ip, m)
            st = {"name": name, "ok": bool(r.get("ok")), "error": r.get("error") or "", "ts": t0}
            if r.get("ok"):
                old = self.rec["snap"].get(ip)
                st["first"] = old is None
                # the snapshot kept is cleaned again, so a better cleaner never reads as a change
                was = old and CLEAN.get(r["kind"], clean_linux)(old["text"])
                if old is not None and was != r["text"]:
                    d = diff(was, r["text"], r["kind"])
                    if d:
                        changed[ip] = {"name": name, "kind": r["kind"], "old": was, "new": r["text"],
                                       "diff": d, "since": old["ts"]}
                self.rec["snap"][ip] = {"text": r["text"], "ts": t0, "kind": r["kind"]}
                st["lines"] = r["text"].count("\n") + 1
            else:
                st["kept_from"] = (self.rec["snap"].get(ip) or {}).get("ts")
            self.rec["machines"][ip] = st
        new = await self._judge(changed) if changed else []
        self._file(new)
        self.rec["error"] = self.rec.get("error_model") or "" if changed else ""
        self.rec["last_done"] = time.time()
        self._prune()
        self._save()
        log.info("configwatch: %d machine(s) read, %d changed, %d change(s) noted in %.0fs (%s)",
                 sum(1 for s in self.rec["machines"].values() if s.get("ok") and s.get("ts") == t0),
                 len(changed), len(new), time.time() - t0, reason)
        return new

    async def _judge(self, changed: dict) -> list:
        """The model's reading of the diffs, held to them; the rule's for what it left out."""
        self.rec["error_model"] = ""
        v = None
        off = self.model_off()
        if off:
            self.rec["error_model"] = off
        else:
            v = await self.ask(SYSTEM, self.context(changed))
            if (v is None or not isinstance(v.get("changes"), list)) and not self.model_off():
                # once more before the rule's reading stands: one unusable answer would leave the
                # owner's own change flagged "high" by the rule alone
                log.warning("configwatch: the model's answer was not usable (%s) — asking once more",
                            "no JSON" if v is None else f"keys {sorted(v)[:6]}")
                v = await self.ask(SYSTEM, self.context(changed))
            if v is None or not isinstance(v.get("changes"), list):
                self.rec["error_model"] = self.model_off() or "the model gave no usable answer — the rule's reading stands"
                v = None
        out, covered = [], set()          # (ip, section) the model explained
        if v is not None:
            self.rec["summary"] = words(v.get("summary"), 400)
            for c in v["changes"]:
                if not isinstance(c, dict):
                    continue
                ip = str(c.get("ip") or "").strip()
                if ip not in changed:
                    continue
                d = changed[ip]["diff"]
                known = {f"{s}{x.strip()}": sec for s, x, sec in d}
                lines, secs = [], set()
                for q in c.get("lines") or []:
                    q = str(q).strip()
                    # with its sign as asked; without one, whichever side has it
                    keys = [q[:1] + q[1:].strip()] if q[:1] in "+-" else ["+" + q, "-" + q]
                    k = next((x for x in keys if x in known), None)
                    if k is not None:
                        lines.append(k[:300])
                        secs.add(known[k])
                risk = str(c.get("risk") or "").strip().lower()
                risk = risk if risk in RISKS else "low"
                kind = changed[ip]["kind"]
                if risk == "none" and any(risky(s, kind) for s in secs):
                    risk = "low"           # a change where who-gets-in lives is never "nothing"
                covered |= {(ip, s) for s in secs}
                out.append(self._item(ip, changed[ip], words(c.get("what"), 200), risk,
                                      words(c.get("why"), 300), lines[:8], sorted(secs), "model"))
        for ip, ch in changed.items():
            kind = ch["kind"]
            secs = sorted({s for _, _, s in ch["diff"]} - {s for i, s in covered if i == ip})
            if v is not None:
                secs = [s for s in secs if risky(s, kind)]    # the model spoke; only what decides access
            if not secs:
                continue
            n = sum(1 for _, _, s in ch["diff"] if s in secs)
            hot = [s for s in secs if risky(s, kind)]
            what = (f"{n} line(s) changed in {', '.join(secs[:4])}" + (" …" if len(secs) > 4 else "")
                    + (" — not explained by the model" if v is not None else ""))
            lines = [f"{sg}{x}"[:300] for sg, x, s in ch["diff"] if s in secs][:8]
            out.append(self._item(ip, ch, what, "high" if hot else "low",
                                  "a change where access is decided" if hot else "", lines, secs, "rule"))
        return out

    def _item(self, ip, ch, what, risk, why, lines, secs, by) -> dict:
        return {"id": uuid.uuid4().hex[:10], "ts": time.time(), "since": ch["since"], "ip": ip,
                "name": ch["name"], "what": what or "a change", "risk": risk, "why": why,
                "lines": lines, "sections": secs, "by": by}

    def _file(self, new: list):
        """Kept for KEEP_DAYS; a high or critical one is a security event as well (To decide,
        Handled) — one per change."""
        for c in new:
            if c["risk"] in ("high", "critical"):
                c["sid"] = self.a.seclog.add(
                    source=f"configuration of {c['name']}", ip=c["ip"],
                    sev="critical" if c["risk"] == "critical" else "warning",
                    title=f"{c['name']}: {c['what']}",
                    detail=(c["why"] + "\n" if c["why"] else "") + "\n".join(c["lines"]),
                    by=c["by"], key=f"cfg:{c['id']}", paged=True)
        self.rec["changes"] = (self.rec["changes"] + new)[-400:]

    def _prune(self):
        cut = time.time() - KEEP_DAYS * 86400
        self.rec["changes"] = [c for c in self.rec["changes"] if c["ts"] >= cut]
        live = {c["id"] for c in self.rec["changes"]}
        self.rec["told"] = [k for k in self.rec.get("told") or [] if k in live]
        known = {m["ip"] for m in self.machines}
        for k in ("snap", "machines"):
            self.rec[k] = {ip: v for ip, v in self.rec[k].items() if ip in known}

    def _logs_between(self, ip: str, since: float) -> list:
        """The log checks of this machine's log since the last snapshot: the router's for the
        main router, a host's own for a host (10-08: the review rated the owner's own WireGuard
        peer critical while the router log had already tied the work to their session)."""
        import json as _json
        hosts = {f"host log {h.name}": h.ip for h in (getattr(getattr(self.a, "hostlog", None), "hosts", None) or [])}
        try:
            from .model import router_host
            router = router_host(self.a.cfg)
        except Exception:
            router = ""
        out = []
        for e in reversed(self.a.state.events(since, kind="finding", limit=300)):
            try:
                f = _json.loads(e.get("detail") or "{}")
            except ValueError:
                continue
            src = str(f.get("source") or "")
            if (src == "router log" and ip == router) or hosts.get(src) == ip:
                out.append(f"{time.strftime('%a %H:%M', time.localtime(e['ts']))} "
                           f"{'PROBLEM ' + str(f.get('severity')) if f.get('problem') else 'fine'}: "
                           f"{str(f.get('summary') or '')[:200]}")
        return out[-12:]

    def new_devices_between(self, since: float) -> list:
        try:
            rows = self.a.sites.seen()
        except Exception:
            return []
        return [f"{r.get('name') or r.get('host') or r.get('vendor') or 'a device'} ({r.get('ip')}, {r.get('mac')}) "
                f"first seen {time.strftime('%a %H:%M', time.localtime(r['first_seen']))}"
                for r in rows if (r.get("first_seen") or 0) >= since and not r.get("before")][:12]

    def context(self, changed: dict) -> str:
        lines = [f"NOW: {time.strftime('%A %d/%m/%Y %H:%M')}", ""]
        oldest = min((ch["since"] for ch in changed.values()), default=time.time())
        news = self.new_devices_between(oldest)
        lines += ["NEW ON THE NETWORK since the oldest snapshot: " + ("; ".join(news) if news else "nothing"), ""]
        for ip, ch in changed.items():
            since = ch["since"]
            ran = actions_done(self.a, since, ips={ip})
            lines.append(f"=== {ch['name']} ({ip}) — {'RouterOS export' if ch['kind'] == 'routeros' else 'Linux snapshot'}, "
                         f"compared with {time.strftime('%a %d/%m %H:%M', time.localtime(since))}")
            lines.append("What ran on it in between: " + ("; ".join(ran) if ran else "nothing lanowl knows of"))
            seen = self._logs_between(ip, since)
            lines.append("What its own log showed in between (lanowl's log checks): "
                         + ("; ".join(seen) if seen else "nothing read, or nothing worth a line"))
            lines.append(hunks(ch["old"], ch["new"]))
            lines.append("")
        lines.append("Return the JSON.")
        return "\n".join(lines)

    # --- the digest and the owner -------------------------------------------------------------
    def news(self) -> list:
        told = set(self.rec.get("told") or [])
        return [(c["id"], self.digest_line(c)) for c in self.rec["changes"]
                if c["risk"] in ("high", "critical") and c["id"] not in told
                and not self._handled(c)]

    def _handled(self, c: dict) -> bool:
        it = self.a.seclog._get(c.get("sid") or "") if c.get("sid") else None
        return bool(it and it.get("handled"))

    def digest_line(self, c: dict) -> str:
        return (f"• {_html(label(c['name'], c['ip']))}: {_html(c['what'])} — <b>{_html(c['risk'])}</b>"
                + (f"\n   <i>{_html(clip(c['why'], 180))}</i>" if c.get("why") else ""))

    def start_now(self) -> bool:
        return self.start("dashboard")

    def view(self) -> dict:
        ch = sorted(self.rec["changes"], key=lambda c: -c["ts"])
        out = []
        for c in ch[:120]:
            it = self.a.seclog._get(c.get("sid") or "") if c.get("sid") else None
            out.append({**c, "tid": change_id(c), **({"handled": it.get("handled")} if it and it.get("handled") else {})})
        return {"enabled": self.enabled, "running": self.running, "last": self.rec.get("last_done") or None,
                "summary": self.rec.get("summary") or "", "error": self.rec.get("error") or "",
                "changes": out,
                "machines": [{"ip": ip, **{k: v for k, v in st.items() if k != "text"}}
                             for ip, st in self.rec["machines"].items()]}

    def weekly_lines(self) -> list:
        if not self.enabled or not self.rec.get("last_done"):
            return []
        week = [c for c in self.rec["changes"] if time.time() - c["ts"] < 7 * 86400]
        if not week:
            return ["🛠️ Configurations: nothing changed this week."]
        hot = [c for c in week if c["risk"] in ("high", "critical")]
        return [f"🛠️ Configurations: {len(week)} change(s) this week"
                + (f", {len(hot)} that change who can get in — the worst: {label(hot[0]['name'], hot[0]['ip'])}: "
                   f"{hot[0]['what']}" if hot else ", none that change who can get in")]
