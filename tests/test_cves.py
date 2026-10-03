"""Does a CVE the scan matched apply here? Run with `python -m tests.test_cves`.

No network, no host, no model — OSV, NVD, ssh and the model are fakes. Pinned down here
(cves.py):

  1. NVD's affected versions read right — OpenSSH's p-levels, and "9.8" against "9.8p1"
     is "cannot tell", never "affected" or "not";
  2. a Debian/Ubuntu machine is judged by its exact package (OSV), not the version its
     service announces; ESXi by the version `ssh -V` reports on the machine itself;
  3. the model may only take a CVE down to "not_applicable", with its reason; switched off,
     everything affected stays "applies";
  4. only "applies" at CVSS 7+ pages, once; a reference without a CVE id is never judged;
  5. cve_lookup answers the model's questions from the same sources.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import cves as C
from tests.test_reboot import _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


SSH = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"


def test_ranges():
    print("\n-- NVD's affected versions --")
    before_104 = [{"cpe": SSH, "ee": "10.4"}]
    regresshion = [{"cpe": SSH, "si": "8.5p1", "ee": "9.8p1"}, {"cpe": SSH, "ee": "4.4p1"}]
    check(C.in_ranges("OpenSSH 10.3", "10.3", before_104) is True, "10.3 is before 10.4: affected")
    check(C.in_ranges("OpenSSH 10.4", "10.4", before_104) is False, "10.4 is not")
    check(C.in_ranges("OpenSSH 9.8", "9.8", regresshion) is None,
          "'9.8' against 'before 9.8p1': cannot tell (ESXi announces 9.8 for 9.8p1)")
    check(C.in_ranges("OpenSSH 9.8p1", "9.8p1", regresshion) is False, "9.8p1 itself: not affected")
    check(C.in_ranges("OpenSSH 9.6p1", "9.6p1", regresshion) is True, "9.6p1: inside 8.5p1–9.8p1")
    check(C.in_ranges("OpenSSH 9.3p1", "9.3p1", [{"cpe": "cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*"}]) is True,
          "an exact version with its p-level")
    check(C.in_ranges("Dropbear sshd", "2022.83", before_104) is None, "no range for this product: cannot tell")
    check(C.vague("gSOAP 2.8", "2.8") and C.vague("Samba smbd 4", "4") and not C.vague("OpenSSH 10.3", "10.3"),
          "gSOAP's '2.8' and 'Samba smbd 4' are too vague to compare")
    check(C.ecosystem("debian", "12") == "Debian:12" and C.ecosystem("raspbian", "12") == "Debian:12"
          and C.ecosystem("ubuntu", "24.04") == "Ubuntu:24.04:LTS" and C.ecosystem("ubuntu", "24.10") == "Ubuntu:24.10",
          "os-release to OSV's ecosystems (a Raspberry Pi's too)")
    n = C.parse_nvd({"vulnerabilities": [{"cve": {"descriptions": [{"lang": "en", "value": "sshd flaw"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": SSH, "versionEndExcluding": "10.4"},
                                                     {"vulnerable": False, "criteria": "cpe:2.3:o:x:y:*"}]}]}]}}]})
    check(n and n["cvss"] == 8.1 and n["ranges"] == [{"cpe": SSH, "si": None, "se": None, "ei": None, "ee": "10.4"}],
          "NVD's record: description, CVSS, the vulnerable ranges only")
    firmware = [{"vulnerable": True, "criteria": f"cpe:2.3:o:netapp:a{i}_firmware:-:*:*:*:*:*:*:*"} for i in range(400)]
    n = C.parse_nvd({"vulnerabilities": [{"cve": {"descriptions": [], "metrics": {}, "configurations": [{"nodes": [
        {"cpeMatch": firmware}, {"cpeMatch": [{"vulnerable": True, "criteria": SSH, "versionStartIncluding": "8.5p1",
                                               "versionEndExcluding": "9.8p1"}]}]}]}}]})
    check(C.in_ranges("OpenSSH 9.8p1", "9.8p1", n["ranges"]) is False and C.in_ranges("OpenSSH 9.6p1", "9.6p1", n["ranges"]),
          "regreSSHion's 400 firmware entries do not push OpenSSH's own range out")


M = lambda ip_prod, ver, cid, cvss=9.8: {"port": 22, "product": ip_prod, "version": ver, "id": cid,  # noqa: E731
                                         "cvss": cvss, "exploit": False}


def _setup(a, model_off=False):
    U = a.updates
    U.hosts = [{"ip": "192.168.10.35", "via": "password"}, {"ip": "192.168.10.111", "via": "esxi"}]
    U.rec["hosts"] = {"192.168.10.35": {"kind": "linux", "name": "AirPrint"}, "192.168.10.111": {"kind": "esxi"}}
    U.rec["scan"] = {"done": 1790000000.0, "ts": 1790000000.0, "found": {
        "192.168.10.35": [M("OpenSSH 9.2p1 Debian 2+deb12u10", "9.2p1 Debian 2+deb12u10", "CVE-2024-6387", 8.1),
                         M("OpenSSH 9.2p1 Debian 2+deb12u10", "9.2p1 Debian 2+deb12u10", "CVE-2026-60000", 7.5),
                         M("OpenSSH 9.2p1 Debian 2+deb12u10", "9.2p1 Debian 2+deb12u10", "PACKETSTORM:179290", 10.0)],
        "192.168.10.111": [M("OpenSSH 9.8", "9.8", "CVE-2024-6387", 8.1), M("OpenSSH 9.8", "9.8", "CVE-2026-59998", 7.0),
                         M("OpenSSH 9.8", "9.8", "CVE-2026-1", 8.1), M("OpenSSH 9.8", "9.8", "CVE-2026-2", 8.1),
                         M("OpenSSH 9.8", "9.8", "CVE-2026-3", 8.1)],
        "192.168.10.31": [{"port": 8000, "product": "gSOAP 2.8", "version": "2.8", "id": "CVE-2017-9765", "cvss": 8.1}]}}
    calls = {"ssh": [], "osv": [], "nvd": [], "model": []}

    async def ssh(ip, cmd, **kw):
        calls["ssh"].append((ip, cmd))
        if ip == "192.168.10.35":
            return 0, "OS=raspbian 12\nPKG=openssh-server openssh 1:9.2p1-2+deb12u10\n", ""
        if ip == "192.168.10.111":
            return 0, "OpenSSH_9.8p1, OpenSSL 3.0.15 3 Sep 2024\n", ""
        return None, "", "no"
    a.access.ssh = ssh

    async def osv(eco, pkg, ver):
        calls["osv"].append((eco, pkg, ver))
        return {"CVE-2026-60000": "sshd in OpenSSH before 10.4 allows a denial of service"}
    a.cves._osv = osv

    async def nvd(cid):
        calls["nvd"].append(cid)
        return {"desc": {"CVE-2024-6387": "regreSSHion", "CVE-2026-59998":
                         "GSSAPIStrictAcceptorCheck has no value if the server is in Windows Active Directory"}.get(cid, ""),
                "cvss": 8.1, "vector": "", "ts": time.time(),
                "ranges": [{"cpe": SSH, "si": "8.5p1", "ee": "9.8p1"}] if cid == "CVE-2024-6387" else
                          [{"cpe": SSH, "si": "8.6", "ei": "9.8"}] if cid in ("CVE-2026-1", "CVE-2026-3") else [{"cpe": SSH, "ee": "10.4"}]}
    a.cves._nvd = nvd

    async def model(system, ctx, timeout_s=None):
        calls["model"].append(ctx)
        if "192.168.10.111" in ctx:
            return {"verdicts": [{"id": "CVE-2026-59998", "verdict": "not_applicable",
                                  "reason": "needs GSSAPI in Active Directory; ESXi is not joined to one"},
                                 {"id": "CVE-2026-1", "verdict": "not_affected", "fixed_in": "9.8p1", "reason": "fixed in 9.8p1"},
                                 {"id": "CVE-2026-2", "verdict": "not_affected", "fixed_in": "9.8p1", "reason": "fixed in 9.8p1"},
                                 {"id": "CVE-2026-3", "verdict": "not_affected", "fixed_in": "9.9p1", "reason": "fixed in 9.9p1"}]}
        return {"verdicts": [{"id": "CVE-2026-60000", "verdict": "applies", "reason": "sshd listens on the LAN"}]}
    a.agent.ask_json = model
    if model_off:
        a._model_off = {"ts": time.time(), "by": "test"}
    return calls


def test_verify():
    print("\n-- each match checked, then the model --")
    out = {}

    async def go(d):
        a = _auditor(d)[1]
        sent = []
        a._emit_telegram = lambda ch, text, **kw: sent.append(text)
        out["calls"] = _setup(a)
        await a.cves.verify("test")
        out["v"] = a.cves.rec["verdicts"]
        out["sent"] = list(sent)
        out["f"] = {f["ip"]: f for f in a.updates.findings() if f["key"].startswith("cve:")}
        out["view"] = a.updates.view()["scan"]
        await a.cves.verify("test again")
        out["sent2"] = sent[len(out["sent"]):]
        # the model's reading flips (applies → doesn't → applies must not page twice)
        real = a.agent.ask_json

        async def flip(system, ctx, timeout_s=None):
            v = await real(system, ctx, timeout_s)
            for x in v["verdicts"]:
                if x["id"] == "CVE-2026-60000":
                    x.update(verdict="not_applicable", reason="GSSAPI is off")
            return v
        a.agent.ask_json = flip
        await a.cves.verify("flip")
        a.agent.ask_json = real
        await a.cves.verify("flop")
        out["sent3"] = sent[len(out["sent"]) + len(out["sent2"]):]
        out["lookup"] = await a.cves.lookup("cve-2024-6387", "192.168.10.35")
        out["tool"] = await a.executor.call("cve_lookup", {"cve": "CVE-2026-59998"})
        out["specs"] = [t["function"]["name"] for t in a.executor.tool_specs()]
        out["stale"] = a.cves.stale()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    v, calls = out["v"], out["calls"]
    ap, esx = v["192.168.10.35"], v["192.168.10.111"]
    check(("Debian:12", "openssh", "1:9.2p1-2+deb12u10") in calls["osv"],
          "AirPrint: its exact package asked of OSV (a Raspberry Pi is Debian 12)")
    check(ap["CVE-2024-6387"]["v"] == "fixed" and "security-tracker.debian.org" in ap["CVE-2024-6387"]["url"],
          "regreSSHion: fixed in its build, with the tracker's link")
    check(ap["CVE-2026-60000"]["v"] == "applies" and ap["CVE-2026-60000"].get("model") is True,
          "a CVE still open in Debian, read by the model: applies")
    check(ap["PACKETSTORM:179290"]["v"] == "ref", "an exploit id without a CVE: a reference, not judged")
    check(esx["CVE-2024-6387"]["v"] == "not_affected" and "9.8p1" in esx["CVE-2024-6387"]["why"],
          "ESXi: `ssh -V` says 9.8p1, so regreSSHion is outside NVD's versions")
    check(esx["CVE-2026-59998"]["v"] == "not_applicable" and "Active Directory" in esx["CVE-2026-59998"]["why"],
          "the model's not_applicable, with its reason")
    check(esx["CVE-2026-1"]["v"] == "not_affected" and esx["CVE-2026-1"]["by"] == "model",
          "NVD's '≤ 9.8' against 9.8p1: undecided by the code, the model reads the description's bound")
    check(esx["CVE-2026-2"]["v"] == "applies",
          "but where NVD's versions do include it, the model's 'not_affected' is not taken")
    check(esx["CVE-2026-3"]["v"] == "applies",
          "nor a 'fixed in 9.9p1' for a machine on 9.8p1: the code checks the model's fixed version")
    check(v["192.168.10.31"]["CVE-2017-9765"]["v"] == "unclear" and "CVE-2017-9765" not in calls["nvd"],
          "gSOAP '2.8': unclear, and NVD not even asked")
    check(not any("192.168.10.35" in c and "CVE-2024-6387" in c for c in calls["model"]),
          "the model is not asked about what the code already settled")
    f = out["f"]
    check(f["192.168.10.35"]["page"] and f["192.168.10.111"]["page"] and not f["192.168.10.31"]["page"],
          "only the machines where one applies page")
    check(len(out["sent"]) == 1 and "CVE-2026-60000" in out["sent"][0] and "CVE-2026-2" in out["sent"][0]
          and "192.168.10.31" not in out["sent"][0], "one message, naming what applies — nothing else")
    check(out["sent2"] == [], "checked again with nothing new: silent")
    check(out["sent3"] == [], "a verdict that flips away and back does not page again")
    fv = out["view"]["found"]["192.168.10.111"]
    check(fv["confirmed"] == 2 and "5 CVE matches" in fv["words"]
          and [x["verdict"] for x in fv["vulns"]] == ["applies", "applies", "not_applicable", "not_affected", "not_affected"],
          f"the page: what applies first, then why each does not ({fv['words']})")
    check(out["view"]["check"]["ts"] and not out["stale"], "the check is recorded against this scan")
    lk = out["lookup"]
    check(lk["cve"] == "CVE-2024-6387" and "not affected in this build" in str(lk.get("distribution")),
          "cve_lookup: the id normalised, the machine's build asked again")
    check("fixed" in str(lk["on_the_machines"]), "and what the check concluded there")
    check("cve_lookup" in out["specs"] and "not_applicable" in str(out["tool"]["result"]),
          "offered to the model as a tool, answering from the same record")


def test_model_off():
    print("\n-- the model switched off: nothing is taken down --")
    out = {}

    async def go(d):
        a = _auditor(d)[1]
        a._emit_telegram = lambda ch, text, **kw: None
        out["calls"] = _setup(a, model_off=True)
        await a.cves.verify("test")
        out["v"] = a.cves.rec["verdicts"]
        out["view"] = a.cves.view()
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    esx = out["v"]["192.168.10.111"]["CVE-2026-59998"]
    check(out["calls"]["model"] == [], "the model is asked nothing")
    check(esx["v"] == "applies" and esx.get("model") is False and "not read it" in esx["why"],
          "what it would have read stays 'applies', and says so")
    check(out["view"]["model"] is False, "the page is told the model was off")


def test_ssh_facts():
    print("\n-- sshd -T read on the machines the review does not read --")
    out = {}

    async def go(d):
        a = _auditor(d)[1]
        a._emit_telegram = lambda ch, text, **kw: None
        calls = _setup(a)
        a.cves.ssh_facts = {"192.168.10.111": {"sshd": "/usr/lib/vmware/openssh/bin/sshd"}, "192.168.10.103": {"sudo": True}}
        a.updates.rec["scan"]["found"]["192.168.10.103"] = [M("OpenSSH 10.3", "10.3", "CVE-2026-60000", 7.5)]
        seen = []

        async def ssh(ip, cmd, **kw):
            seen.append((ip, cmd, kw.get("sudo_pw")))
            if ip == "192.168.10.111":
                return 0, ("port 22\npermitrootlogin yes\npasswordauthentication no\npermittunnel no\n"
                           "authorizedprincipalsfile none\nOpenSSH_9.8p1, OpenSSL 3.0.15\n"
                           "AK /etc/ssh/keys-root/authorized_keys 0\n"), ""
            if ip == "192.168.10.103":
                return 0, "gssapiauthentication no\nkerberosauthentication no\nOpenSSH_10.3p1, LibreSSL 3.3.6\n", ""
            return 0, "OS=raspbian 12\nPKG=openssh-server openssh 1:9.2p1-2+deb12u10\n", ""
        a.access.ssh = ssh
        # the review's own reading of ESXi, long: sshd -T must still reach the model
        a.exposure.rec.setdefault("facts", {})["192.168.10.111"] = {"ok": True, "text": "== firewall\n" + "x" * 6000}
        await a.cves.verify("test")
        out["seen"], out["model"] = seen, calls["model"]
        out["v"] = a.cves.rec["verdicts"]
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    esx = [c for c in out["model"] if "192.168.10.111" in c]
    check(esx and "authorizedprincipalsfile none" in esx[0] and "built without GSSAPI" in esx[0],
          "ESXi: sshd -T reaches the model (before the review's long text), what it does not list reads as not built in")
    check(esx and "0 line(s) with cert-authority — no certificate authority is trusted there" in esx[0],
          "and whether an authorized_keys trusts a certificate authority (CVE-2026-35414's condition)")
    mac = [c for c in out["model"] if "192.168.10.103" in c]
    check(mac and "gssapiauthentication no" in mac[0] and "built without GSSAPI" not in mac[0]
          and "none exists on this machine" in mac[0],
          "the Mac: its GSSAPI setting as sshd reports it")
    s94 = [x for x in out["seen"] if x[0] == "192.168.10.103"]
    check(len(s94) == 1 and s94[0][1].startswith("sudo -S -p '' sh -c 'sshd -T") and s94[0][2] is True,
          "read once per check; with sudo -S where the login is not root")
    check(out["v"]["192.168.10.111"]["CVE-2024-6387"]["v"] == "not_affected",
          "the version from sshd's own ssh -V counts for the ranges too")


if __name__ == "__main__":
    for t in (test_ranges, test_verify, test_model_off, test_ssh_facts):
        t()
    print(f"\n{'all passed' if not _fails else f'{len(_fails)} FAILED'}")
    sys.exit(1 if _fails else 0)
