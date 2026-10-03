"""Is a vulnerability the monthly scan matched real on this machine?

A version scan matches hundreds of CVEs on a handful of machines, and most of the serious
ones are not real: Debian and Ubuntu fix a flaw without changing the version the service
announces, "Samba smbd 4" matches every Samba CVE there ever was, and several OpenSSH ones
only exist for the ssh CLIENT or with a setting that is off. Not a web search (keys,
search-engine pages, and web text fed to a model that can propose actions), but fixed
sources, looked up by the code:

  - a Debian/Ubuntu machine lanowl logs into: the EXACT package installed (dpkg), asked
    of OSV.dev (the distributions' own security data) — "is this build still affected?"
    answers backports properly. Not in its list = fixed in the build;
  - everything else: NVD's record of the CVE — its description and the versions it affects.
    A version outside them = not affected;
  - what is left affected by version goes to the local model with the CVE's description and
    the facts the security review read off the machine (its sshd settings…): does the flaw's
    own condition hold here? It may only say "not_applicable" with the reason, or "applies";
    unsure is "applies". Off, or failing: every one stays "applies".

Only an "applies" with CVSS 7+ pages (updates.py). What leaves the network: package
names, versions and CVE ids — never an address or a name.

Verdicts: applies · fixed (the distribution's build has the fix) · not_affected (NVD's
versions exclude it) · not_applicable (the model, with its reason) · unclear (a version too
vague to compare, or a source that could not be asked) · ref (an exploit or advisory id with
no CVE — listed, never judged).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional

from .report import label

log = logging.getLogger("lanowl.cves")

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

RECORD = "cves"
OSV_URL = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_GAP_S = 6.5                 # NVD without a key: 5 requests in any 30 s
NVD_KEEP_S = 30 * 86400
NVD_PV = 2                      # how an NVD record was parsed: an older one is read again
OSV_KEEP_S = 3 * 86400          # a build's list grows as CVEs are published
MODEL_CHUNK = 8
DESC_MAX = 600
FACTS_MAX = 4000
VERDICTS = ("applies", "unclear", "not_applicable", "not_affected", "fixed", "ref")
RANK = {v: i for i, v in enumerate(VERDICTS)}
DISTRO_BUILD = re.compile(r"debian|ubuntu|\+deb\d|deb\d+u\d+", re.I)
GENERIC_PRODUCTS = ("gsoap",)   # nmap names every gSOAP 2.8.x "2.8"

# the service nmap names -> the Debian/Ubuntu binary package whose version answers for it
PACKAGES = (("openssh", "openssh-server"), ("cups", "cups-daemon"), ("samba", "samba"),
            ("dnsmasq", "dnsmasq-base"), ("nginx", "nginx"), ("apache", "apache2"),
            ("lighttpd", "lighttpd"), ("dropbear", "dropbear-bin"), ("mosquitto", "mosquitto"),
            ("bind", "bind9"), ("postfix", "postfix"), ("vsftpd", "vsftpd"), ("exim", "exim4-base"),
            ("avahi", "avahi-daemon"), ("squid", "squid"), ("proftpd", "proftpd-core"))

SYSTEM = """You judge whether known vulnerabilities (CVEs) that a network scan matched really \
apply to one machine of a family's home network. The monitor already did the version work: \
every CVE below either lists this machine's version among the affected ones, or is still open \
in its distribution's security tracker. Your part is the rest — does the flaw's OWN condition \
hold on this machine?

For each CVE answer "not_applicable" only when the flaw cannot be reached here:
- it needs a feature, setting or component that the MACHINE FACTS show is off or absent — \
quote the fact;
- it is in a client-side program (the ssh/scp/sftp client, ssh-agent, a desktop tool) while \
the scan found a listening server, and a client flaw needs the owner to connect to a hostile \
server;
- it needs a platform or setup this machine is not (Windows, Active Directory, a specific \
distribution, a specific architecture).
Otherwise answer "applies" — also when the facts cannot tell. Never assume a setting the \
facts do not show. You are not judging how bad it is, only whether it applies.

One exception about versions: a CVE marked "VERSION UNDECIDED" is one where NVD's version \
data could not be compared with the machine's exact version (NVD often drops OpenSSH's "p1"). \
For those only: if the description, or the fix's published release, shows that the first \
fixed version is at or below the machine's exact version, answer "not_affected" with \
"fixed_in" set to that first fixed version. If you do not know it for certain, answer as usual.

Reply with ONLY this JSON object, no prose, no code fence:
{"verdicts": [{"id": "CVE-…", "verdict": "applies"|"not_applicable"|"not_affected",
  "fixed_in": "<only with not_affected: the first fixed version>",
  "reason": "<one short sentence for a phone: the condition, and the fact that decides it>"}]}"""


def _vparts(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4])


def _cmp(a: tuple, b: tuple) -> Optional[int]:
    """-1, 0, 1 — or None when one is a shorter prefix of the other: "9.8" against "9.8p1" is
    ESXi's sshd announcing 9.8 for VMware's 9.8p1, and nothing here can tell which."""
    n = min(len(a), len(b))
    if a[:n] == b[:n]:
        return 0 if len(a) == len(b) else None
    return -1 if a[:n] < b[:n] else 1


def in_ranges(product: str, version: str, ranges: list) -> Optional[bool]:
    """Is `version` of `product` inside NVD's affected versions? None: cannot tell (no range
    for this product, or a version that cannot be compared to a bound)."""
    key = (product.split() or [""])[0].lower()
    mine = _vparts(version)
    if not mine:
        return None
    hit, unsure, seen = False, False, False
    for r in ranges:
        crit = str(r.get("cpe") or "").lower().split(":")
        if len(crit) < 6 or key not in crit[4]:
            continue
        seen = True
        exact = crit[5] if crit[5] not in ("*", "-") else ""
        if exact:
            upd = crit[6] if len(crit) > 6 and crit[6] not in ("*", "-") else ""
            c = _cmp(mine, _vparts(exact + upd))
            if c == 0:
                hit = True
            elif c is None:
                unsure = True
            continue
        ok = True
        for k, want in (("si", (0, 1)), ("se", (1,)), ("ei", (-1, 0)), ("ee", (-1,))):
            if not r.get(k):
                continue
            c = _cmp(mine, _vparts(r[k]))
            if c is None:
                unsure = True
                ok = False
                break
            if c not in want:
                ok = False
                break
        hit = hit or ok
    if not seen:
        return None
    return True if hit else None if unsure else False


def ecosystem(os_id: str, version_id: str) -> str:
    """os-release ID and VERSION_ID -> OSV's ecosystem name ("Debian:12", "Ubuntu:24.04:LTS")."""
    i, v = str(os_id or "").lower(), str(version_id or "").strip('"')
    if i in ("debian", "raspbian") and v:
        return f"Debian:{v.split('.')[0]}"
    if i == "ubuntu" and re.fullmatch(r"\d\d\.\d\d", v):
        yy, mm = v.split(".")
        return f"Ubuntu:{v}:LTS" if mm == "04" and int(yy) % 2 == 0 else f"Ubuntu:{v}"
    return ""


def tracker_url(eco: str, cve: str) -> str:
    if eco.startswith("Ubuntu"):
        return f"https://ubuntu.com/security/{cve}"
    return f"https://security-tracker.debian.org/tracker/{cve}"


def nvd_url(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def parse_nvd(j: dict) -> Optional[dict]:
    """NVD's answer for one CVE -> {desc, cvss, vector, ranges}."""
    try:
        c = j["vulnerabilities"][0]["cve"]
    except (KeyError, IndexError, TypeError):
        return None
    desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    cvss, vector = None, ""
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for m in (c.get("metrics") or {}).get(k) or []:
            d = m.get("cvssData") or {}
            if d.get("baseScore") is not None:
                cvss, vector = float(d["baseScore"]), str(d.get("vectorString") or "")
                break
        if cvss is not None:
            break
    # software ("a") entries only: regreSSHion's record lists hundreds of vendors' firmware
    # ("o"), and cut at 60 entries OpenSSH's own range is lost (an unaffected 9.8p1 then
    # reads as affected)
    ranges = []
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and str(m.get("criteria", "")).startswith("cpe:2.3:a:"):
                    ranges.append({"cpe": m.get("criteria", ""),
                                   "si": m.get("versionStartIncluding"), "se": m.get("versionStartExcluding"),
                                   "ei": m.get("versionEndIncluding"), "ee": m.get("versionEndExcluding")})
    return {"desc": desc[:DESC_MAX], "cvss": cvss, "vector": vector, "ranges": ranges[:300], "pv": NVD_PV}


def vague(product: str, version: str) -> str:
    """Why a version cannot be compared at all, or ""."""
    if product.lower().startswith(GENERIC_PRODUCTS):
        return "nmap names every build of it by its major line only, which matches every CVE that line ever had"
    if len(_vparts(version)) < 2:
        return "only the major version is known, which matches every CVE that line ever had"
    return ""


# the sshd settings a CVE's condition turns on, read with `sshd -T` (config `cves.ssh_facts`)
SSHD_KEYS = ("port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|"
             "gssapiauthentication|kerberosauthentication|allowagentforwarding|allowtcpforwarding|permittunnel|"
             "disableforwarding|x11forwarding|maxauthtries|subsystem|authorizedprincipalsfile|trustedusercakeys|"
             "authorizedkeyscommand|usepam")


class Cves:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("cves") or {}
        # again after each morning's security review, with its fresh facts
        self.after_review = bool(c.get("after_review", True))
        # machines the security review does not read, whose sshd settings the check reads
        # itself (a Mac, Home Assistant, an ESXi host)
        self.ssh_facts = {str(ip): dict(v or {}) for ip, v in (c.get("ssh_facts") or {}).items()}
        self._task: Optional[asyncio.Task] = None
        self._nvd_at = 0.0
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("cves: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k in ("verdicts", "hosts", "nvd", "osv", "run"):
            self.rec.setdefault(k, {})

    def _save(self):
        if not getattr(self.a, "_persist_alerts", True):
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("cves: record not saved: %s", e)

    # --- when ------------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, reason: str) -> bool:
        if self.running:
            return False
        self._task = asyncio.ensure_future(self._guarded(reason))
        return True

    def stale(self) -> bool:
        """The scan found something the verdicts were not worked out for."""
        sc = self.a.updates.rec.get("scan") or {}
        return bool(sc.get("found")) and (self.rec["run"].get("scan_ts") != sc.get("done")
                                          or not self.rec["run"].get("done"))

    async def _guarded(self, reason: str):
        try:
            await self.verify(reason)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("cves: the check failed")
            self.rec["run"].update(error=f"{type(e).__name__}: {e}"[:200], running=False)
            self._save()

    # --- the work ----------------------------------------------------------------------
    async def verify(self, reason: str = "after the scan") -> dict:
        U = self.a.updates
        sc = U.rec.get("scan") or {}
        found = sc.get("found") or {}
        t0 = time.time()
        self.rec["run"] = {"ts": t0, "reason": reason, "scan_ts": sc.get("done"), "running": True}
        log.info("cves: checking %d device(s)' matches (%s)", len(found), reason)
        verdicts: dict = {}
        to_model: dict = {}                       # ip -> [(match, text about the CVE)]
        notes = []
        for ip, matches in found.items():
            out = verdicts.setdefault(ip, {})
            distro = await self._distro(ip, matches)
            for m in matches:
                cid = str(m.get("id") or "")
                if cid in out:
                    continue
                base = {"cvss": m.get("cvss"), "product": m.get("product"), "port": m.get("port"),
                        "exploit": bool(m.get("exploit"))}
                if not cid.startswith("CVE-"):
                    out[cid] = {**base, "v": "ref", "by": "code",
                                "why": "an exploit or advisory reference with no CVE id: not judged"}
                    continue
                r = await self._one(ip, m, distro)
                if r.get("v") == "affected":
                    to_model.setdefault(ip, []).append((m, r))
                    out[cid] = {**base, "v": "applies", "by": r["by"], "url": r.get("url"),
                                "why": r["why"] + "; the model has not read it", "model": False}
                else:
                    out[cid] = {**base, **r}
            if distro and distro.get("error"):
                notes.append(f"{ip}: {distro['error']}")
        await self._model(to_model, verdicts)
        self.rec["verdicts"] = verdicts
        counts: dict = {}
        for vs in verdicts.values():
            for x in vs.values():
                counts[x["v"]] = counts.get(x["v"], 0) + 1
        self.rec["run"] = {"ts": t0, "done": time.time(), "reason": reason, "scan_ts": sc.get("done"),
                           "counts": counts, "running": False, "notes": notes[:10],
                           "model": not self.a.no_llm}
        self._prune()
        self._save()
        log.info("cves: done in %.0fs — %s", time.time() - t0,
                 ", ".join(f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: RANK.get(kv[0], 9))))
        U.after_cves(reason)
        return self.rec["run"]

    async def _one(self, ip: str, m: dict, distro: Optional[dict]) -> dict:
        """One CVE on one machine, without the model: {v, by, why, url?} — v "affected"
        when the model is to read it."""
        cid, prod = str(m["id"]), str(m.get("product") or "")
        ver = str(m.get("version") or (prod.split()[-1] if prod.split() else ""))
        pkg = self._pkg_for(prod, distro)
        if pkg is not None:
            src, sver = pkg
            open_ = await self._osv(distro["eco"], src, sver)
            if open_ is None:
                return {"v": "unclear", "by": "osv", "why": "the distribution's security data (OSV) could not be asked"}
            url = tracker_url(distro["eco"], cid)
            if cid not in open_:
                return {"v": "fixed", "by": "osv", "url": url,
                        "why": f"fixed in its build: {distro['eco']} {src} {sver} is not affected"}
            return {"v": "affected", "by": "osv", "url": url, "desc": open_[cid],
                    "why": f"still open for {distro['eco']} {src} {sver}"}
        if DISTRO_BUILD.search(f"{prod} {ver}"):
            return {"v": "unclear", "by": "code",
                    "why": "a Debian/Ubuntu build whose installed package lanowl cannot read — "
                           "its fixes are backported without a new version"}
        # the version the machine itself reports, where lanowl can log in: ESXi's sshd
        # announces "9.8" for VMware's 9.8p1, and "before 9.8p1" cannot be decided on "9.8"
        exact = await self._exact_ssh(ip) if prod.lower().startswith("openssh") else ""
        if exact:
            ver, prod = exact, f"OpenSSH {exact} (as the machine itself reports it)"
        why = vague(prod, ver)
        if why:
            return {"v": "unclear", "by": "code", "why": why}
        n = await self._nvd(cid)
        if n is None:
            return {"v": "unclear", "by": "nvd", "why": "NVD could not be asked"}
        inside = in_ranges(prod, ver, n.get("ranges") or [])
        if inside is False:
            return {"v": "not_affected", "by": "nvd", "url": nvd_url(cid),
                    "why": f"NVD's affected versions do not include {prod}"}
        return {"v": "affected", "by": "nvd", "url": nvd_url(cid), "desc": n.get("desc") or "",
                "vector": n.get("vector"), "undecided": inside is None, "version": ver,
                "why": (f"NVD lists {prod} among the affected versions" if inside else
                        f"{prod} cannot be compared exactly with NVD's affected versions")}

    async def _exact_ssh(self, ip: str) -> str:
        """`ssh -V` on a machine the update check logs into that is not a Debian/Ubuntu one
        (ESXi): "9.8p1", or "" when it cannot be read. Once per check."""
        if ip in self.ssh_facts:
            f = await self._sshd(ip)
            if f.get("version"):
                return f["version"]
        run = self.rec["run"]
        seen = run.setdefault("ssh_v", {})
        if ip in seen:
            return seen[ip]
        seen[ip] = ""
        h = next((x for x in self.a.updates.hosts if x["ip"] == ip), None)
        if h is None or h.get("via") not in ("esxi", "password", "key"):
            return ""
        try:
            if h["via"] == "key":
                rc, out, err = await self.a.actions._ssh_run(ip, "ssh -V 2>&1", 30)
            else:
                rc, out, err = await self.a.access.ssh(ip, "ssh -V 2>&1", timeout_s=30)
        except Exception:
            return ""
        m = re.search(r"OpenSSH_([\d.]+p?\d*)", f"{out or ''} {err or ''}")
        seen[ip] = m.group(1) if m else ""
        return seen[ip]

    # --- the machine's own packages ----------------------------------------------------------
    def _pkg_for(self, product: str, distro: Optional[dict]):
        if not distro or not distro.get("eco"):
            return None
        p = product.lower()
        for key, pkg in PACKAGES:
            if p.startswith(key) and pkg in (distro.get("pkgs") or {}):
                return tuple(distro["pkgs"][pkg])
        return None

    async def _distro(self, ip: str, matches: list) -> Optional[dict]:
        """A Debian/Ubuntu machine the update check logs into: its release and the packages
        behind the services the scan matched — {eco, pkgs: {binary: (source, version)}}."""
        U = self.a.updates
        h = next((x for x in U.hosts if x["ip"] == ip), None)
        if h is None or h.get("via") not in ("key", "password") or \
                (U.rec["hosts"].get(ip) or {}).get("kind") != "linux":
            return None
        want = sorted({pkg for m in matches for key, pkg in PACKAGES
                       if str(m.get("product") or "").lower().startswith(key)})
        if not want:
            return None
        cmd = (". /etc/os-release; echo \"OS=$ID $VERSION_ID\"; dpkg-query -W -f='PKG=${Package} "
               "${source:Package} ${source:Version}\\n' " + " ".join(want) + " 2>/dev/null; true")
        if h["via"] == "key":
            rc, out, err = await self.a.actions._ssh_run(ip, cmd, 40)
        else:
            rc, out, err = await self.a.access.ssh(ip, cmd, timeout_s=40)
        osl = re.search(r"^OS=(\S+) (\S+)", out or "", re.M)
        if not osl:
            return {"error": f"its packages could not be read ({(err or '').strip()[-80:] or 'no answer'})"}
        pkgs = {m.group(1): (m.group(2), m.group(3))
                for m in re.finditer(r"^PKG=(\S+) (\S+) (\S+)", out or "", re.M)}
        d = {"eco": ecosystem(osl.group(1), osl.group(2)), "pkgs": pkgs, "ts": time.time()}
        self.rec["hosts"][ip] = d
        return d

    # --- the two sources ---------------------------------------------------------------------
    async def _post(self, url: str, body: dict) -> Optional[dict]:
        if aiohttp is None:
            return None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
                async with s.post(url, json=body) as r:
                    return await r.json() if r.status == 200 else None
        except Exception as e:
            log.info("cves: %s: %s", url, e)
            return None

    async def _get(self, url: str) -> tuple:
        if aiohttp is None:
            return None, None
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
                async with s.get(url, headers={"User-Agent": "lanowl"}) as r:
                    return r.status, (await r.json() if r.status == 200 else None)
        except Exception as e:
            log.info("cves: %s: %s", url, e)
            return None, None

    async def _osv(self, eco: str, pkg: str, version: str) -> Optional[dict]:
        """{CVE id: its description} still affecting this exact build, or None if not asked."""
        key = f"{eco}|{pkg}|{version}"
        hit = self.rec["osv"].get(key)
        if hit and time.time() - hit["ts"] < OSV_KEEP_S:
            return hit["ids"]
        j = await self._post(OSV_URL, {"package": {"name": pkg, "ecosystem": eco}, "version": version})
        if j is None:
            return (hit or {}).get("ids")
        ids = {}
        for v in j.get("vulns") or []:
            names = [v.get("id", "")] + list(v.get("aliases") or []) + list(v.get("upstream") or [])
            text = (v.get("summary") or v.get("details") or "")[:DESC_MAX]
            for n in names:
                c = re.search(r"CVE-\d{4}-\d+", str(n))
                if c:
                    ids.setdefault(c.group(0), text)
        self.rec["osv"][key] = {"ids": ids, "ts": time.time()}
        return ids

    async def _nvd(self, cid: str) -> Optional[dict]:
        hit = self.rec["nvd"].get(cid)
        if hit and hit.get("pv") != NVD_PV:
            hit = None
        if hit and time.time() - hit["ts"] < NVD_KEEP_S:
            return hit
        for attempt in range(3):
            wait = self._nvd_at + NVD_GAP_S - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self._nvd_at = time.time()
            st, j = await self._get(NVD_URL + cid)
            if st == 200 and j is not None:
                n = parse_nvd(j)
                if n is None:
                    break
                self.rec["nvd"][cid] = {**n, "ts": time.time()}
                return self.rec["nvd"][cid]
            if st not in (403, 429, 503):
                break
            await asyncio.sleep(30)              # rate-limited: NVD's window is 30 s
        return hit

    def _prune(self):
        keep = {c for vs in self.rec["verdicts"].values() for c in vs}
        self.rec["nvd"] = {k: v for k, v in self.rec["nvd"].items() if k in keep}
        now = time.time()
        self.rec["osv"] = {k: v for k, v in self.rec["osv"].items() if now - v["ts"] < 30 * 86400}

    async def _sshd(self, ip: str) -> dict:
        """`sshd -T` on a machine of `cves.ssh_facts`, once per check: {text, version} or
        {error}. A setting sshd -T does not list at all was not built in: GSSAPI above all, the
        condition of CVE-2026-60000 — Home Assistant's add-on and ESXi have none."""
        run = self.rec["run"]
        got = run.setdefault("sshd", {})
        if ip in got:
            return got[ip]
        c = self.ssh_facts.get(ip)
        if c is None:
            return {}
        sshd = str(c.get("sshd") or "sshd")
        # ...and whether any authorized_keys trusts a certificate authority: CVE-2026-35414 is the
        # `principals=` option on a `cert-authority` line, which AuthorizedPrincipalsFile does
        # not govern (the model once cited "authorizedprincipalsfile none" for it)
        inner = (f"{sshd} -T 2>&1 | grep -Ei '^({SSHD_KEYS}) '; ssh -V 2>&1; "
                 "for f in /etc/ssh/keys-*/authorized_keys /root/.ssh/authorized_keys "
                 "/home/*/.ssh/authorized_keys /Users/*/.ssh/authorized_keys; do [ -e \"$f\" ] || continue; "
                 "if [ -r \"$f\" ]; then echo \"AK $f $(grep -c cert-authority \"$f\")\"; else echo \"AKX $f\"; fi; "
                 "done; true")
        # all of it as root: another user's ~/.ssh is not even visible to the login
        cmd = ("sudo -S -p '' sh -c '" + inner.replace("'", "'\"'\"'") + "'") if c.get("sudo") else inner
        try:
            rc, out, err = await self.a.access.ssh(ip, cmd, timeout_s=40, sudo_pw=bool(c.get("sudo")))
        except Exception as e:
            rc, out, err = None, "", str(e)
        lines = [x.strip() for x in (out or "").splitlines() if x.strip()]
        conf = [x for x in lines if re.match(rf"^({SSHD_KEYS}) ", x, re.I)]
        ver = next((m.group(1) for x in lines for m in [re.search(r"OpenSSH_([\d.]+p?\d*)", x)] if m), "")
        if not conf:
            got[ip] = {"error": f"its sshd settings could not be read ({(err or out or 'no answer').strip()[-120:]})",
                       "version": ver}
            return got[ip]
        text = ["== sshd, effective settings (sshd -T, read by the check just now)", *conf]
        for k, what in (("gssapiauthentication", "GSSAPI"), ("kerberosauthentication", "Kerberos")):
            if not any(x.lower().startswith(k + " ") for x in conf):
                text.append(f"{k}: NOT LISTED — this sshd was built without {what} support, so it "
                            f"cannot be switched on")
        if ver:
            text.append(f"version: OpenSSH {ver} (ssh -V on the machine)")
        ak = [x.split() for x in lines if x.startswith("AK ")]
        ak = [(p[1], int(p[2])) for p in ak if len(p) == 3 and p[2].isdigit()]
        unread = [x.split()[1] for x in lines if x.startswith("AKX ") and len(x.split()) > 1]
        if ak:
            n = sum(k for _, k in ak)
            text.append(f"authorized_keys: {len(ak)} file(s) read ({', '.join(f for f, _ in ak)}), "
                        f"{n} line(s) with cert-authority — "
                        + ("no certificate authority is trusted there" if not n else "a certificate authority IS trusted"))
        if unread:
            text.append(f"authorized_keys: {', '.join(unread)} exist(s) but this login cannot read them — "
                        "whether they trust a certificate authority is unknown")
        if not ak and not unread:
            text.append("authorized_keys: none exists on this machine — no key, and so no certificate "
                        "authority, is trusted for a login")
        got[ip] = {"text": "\n".join(text), "version": ver}
        return got[ip]

    # --- the model ---------------------------------------------------------------------------
    async def _facts(self, ip: str) -> str:
        """What is known of the machine's settings: the security review's reading this morning,
        and `sshd -T` read by the check itself for the machines the review does not read."""
        # sshd -T first: it is what the CVEs turn on, and one machine's review text alone can
        # fill the budget
        parts = []
        s = await self._sshd(ip)
        if s.get("text") or s.get("error"):
            parts.append(s.get("text") or s["error"])
        x = getattr(self.a, "exposure", None)
        f = ((getattr(x, "rec", None) or {}).get("facts") or {}).get(ip) if x is not None else None
        if f and f.get("ok") and f.get("text"):
            parts.append("== the security review's reading this morning\n" + str(f["text"]))
        return "\n".join(parts)[:FACTS_MAX] if parts else "none read from this machine: its settings are unknown"

    def _context(self, ip: str, items: list, facts: str) -> str:
        U = self.a.updates
        h = U.rec["hosts"].get(ip) or {}
        dev = self.a.inv.get(ip)
        lines = [f"MACHINE: {label(U._name(ip), ip)}"
                 + (f" — {dev.attrs.get('role') or dev.group}" if dev is not None else "")
                 + (f"; {h['os']}" if h.get("os") else "")
                 + (f"; {dev.attrs['note']}" if dev is not None and dev.attrs.get("note") else ""),
                 "", "MACHINE FACTS:", facts, "",
                 "THE CVEs (the scan saw the service on the port named):"]
        for m, r in items:
            lines.append(f"- {m['id']} (CVSS {m.get('cvss')}{', ' + r['vector'] if r.get('vector') else ''}) "
                         f"— {m.get('product')} on port {m.get('port')}; {r['why']}."
                         + (f" VERSION UNDECIDED: the machine runs exactly {r['version']}." if r.get("undecided") else ""))
            lines.append(f"  {(r.get('desc') or 'no description')[:DESC_MAX]}")
        lines += ["", "Judge each CVE above and return the JSON."]
        return "\n".join(lines)

    async def _model(self, to_model: dict, verdicts: dict):
        a = self.a
        if not to_model or a.no_llm or a.agent is None:
            return
        for ip, items in to_model.items():
            facts = await self._facts(ip)
            for i in range(0, len(items), MODEL_CHUNK):
                part = items[i:i + MODEL_CHUNK]
                async with a.model_turn():
                    v = await a.agent.ask_json(SYSTEM, self._context(ip, part, facts), timeout_s=420)
                got = {str(x.get("id")): x for x in (v or {}).get("verdicts") or [] if isinstance(x, dict)}
                for m, r in part:
                    x = got.get(m["id"])
                    if x is None:
                        continue
                    reason = " ".join(str(x.get("reason") or "").split())[:240]
                    cur = verdicts[ip][m["id"]]
                    if str(x.get("verdict")) == "not_applicable" and reason:
                        cur.update(v="not_applicable", by="model", model=True, why=reason)
                    elif str(x.get("verdict")) == "not_affected" and r.get("undecided") and \
                            _cmp(_vparts(r["version"]), _vparts(x.get("fixed_in"))) in (0, 1) and \
                            len(_vparts(x.get("fixed_in"))) >= 2:
                        # only where the code could not compare the version itself, and only
                        # with a fixed version the code checks against the machine's own
                        cur.update(v="not_affected", by="model", model=True,
                                   why=f"fixed in {x['fixed_in']}, and it runs {r['version']}"
                                       + (f" — {reason}" if reason else ""))
                    else:
                        cur.update(model=True, why=r["why"] + (f"; the model: {reason}" if reason else ""))

    # --- what others read ----------------------------------------------------------------------
    def verdict(self, ip: str, m: dict) -> Optional[dict]:
        return (self.rec["verdicts"].get(ip) or {}).get(str(m.get("id") or ""))

    def view(self) -> dict:
        r = self.rec["run"]
        return {"running": self.running, "ts": r.get("done"), "reason": r.get("reason"),
                "counts": r.get("counts") or {}, "error": r.get("error"), "stale": self.stale(),
                "model": r.get("model")}

    async def lookup(self, cid: str, ip: str = "") -> dict:
        """The `cve_lookup` tool: NVD's record of one CVE, and what lanowl concluded about
        it on each machine (or on `ip`); for a Debian/Ubuntu machine, its build asked again."""
        cid = str(cid or "").strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
            return {"error": "give a CVE id like CVE-2024-6387"}
        n = await self._nvd(cid)
        out: dict = {"cve": cid, "url": nvd_url(cid)}
        if n is not None:
            out.update(description=n.get("desc"), cvss=n.get("cvss"), vector=n.get("vector"),
                       affected_versions=[{k: v for k, v in r.items() if v} for r in n.get("ranges") or []][:12])
        else:
            out["nvd"] = "UNKNOWN: NVD could not be asked"
        on = {}
        for vip, vs in self.rec["verdicts"].items():
            if ip and vip != ip:
                continue
            if cid in vs:
                x = vs[cid]
                on[label(self.a.updates._name(vip), vip)] = {k: x.get(k) for k in ("v", "why", "product", "port", "cvss", "url")}
        out["on_the_machines"] = on or ("the last scan did not match it on any machine" if not ip else
                                        "the last scan did not match it there")
        d = self.rec["hosts"].get(ip) if ip else None
        if d and d.get("eco"):
            builds = {}
            for pkg, (src, ver) in (d.get("pkgs") or {}).items():
                ids = await self._osv(d["eco"], src, ver)
                builds[f"{src} {ver}"] = ("UNKNOWN: OSV could not be asked" if ids is None else
                                          "still affected in this build" if cid in ids else
                                          "not affected in this build (fixed, or never affected)")
            out["distribution"] = {"release": d["eco"], "builds": builds}
        self._save()
        return out

    def spec(self) -> dict:
        return {"type": "function", "function": {
            "name": "cve_lookup",
            "description": "Look up one CVE: NVD's description, CVSS and affected versions, what "
                           "lanowl concluded about it on each machine the monthly scan matched "
                           "it on (applies / fixed in its build / not affected / not applicable, "
                           "with why), and with ip= a Debian/Ubuntu machine's installed build asked "
                           "of its distribution's security data again. Only the CVE id and package "
                           "versions leave the network. Read-only.",
            "parameters": {"type": "object", "properties": {
                "cve": {"type": "string", "description": "e.g. CVE-2024-6387"},
                "ip": {"type": "string"}}, "required": ["cve"]}}}
