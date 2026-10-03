"""Investigation sessions and their checks: run with `python -m tests.test_checks`.

No network, no model, no Telegram — every program the checks would run is a fake that
records its argument list. Pinned down here (checks.py + the sessions in actions.py):

  1. the model only fills typed slots: a shell trick, an option, a bare device name, an
     internet host to scan, a /16, a private address to whois — all refused before anything
     runs; deny groups hold (no nmap on the alarm, no version probes on IoT);
  2. the commands are argument lists (or, over ssh, quoted strings) built by the code;
  3. outputs become one honest line each — and a check that could not see says UNKNOWN;
  4. no session open: the first run_check ASKS for one and runs nothing; later calls join its
     list; one Telegram message with Open session / Reject when the turn ends;
  5. approving opens it and starts the model's own turn; checks run, are counted and listed on
     the message; the budget, the clock and the End button each close it; a restart closes it;
  6. shadow mode runs nothing even inside a session; the audit's request is silent and once
     a day; sessions a day are capped;
  7. vps_restart: only the VPS, only the listed units, root without sudo, peers counted after;
  8. the router's test-policy checks exist only once the router allows them;
  9. mikrotik_read gets the router's credentials from the secret file.
"""
from __future__ import annotations

import asyncio
import os
import shlex
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import actions as A
from lanowl import checks as C
from lanowl.model import Device
from tests.test_actions import DEVICES, _Tg, _settle

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


VPS = "203.0.113.10"
CFG = {"actions": {
    "enabled": True, "mode": "live", "expire_min": 15, "max_pending": 3, "max_per_day": 20,
    "repeat_after_h": 24, "pin_sha256": A.pin_hash("2389"),
    "catalog": {"nmap_scan": {"deny_groups": ["security"]},
                "nmap_service": {"deny_groups": ["security", "iot"]},
                "restart_service": {"host": "192.168.10.113", "units": ["nodered"]},
                "vps_restart": {"host": VPS, "units": ["wg-quick@wg0", "xl2tpd"]},
                "shelly_reboot": {}},
    "session": {"minutes": 15, "max_checks": 3, "max_per_day": 8},
    "checks": {"lan_subnets": ["192.168.10.0/24"], "home_server": "192.168.10.113", "vps": VPS}},
    "mikrotik": {"dhcp_source": "http://192.168.10.1"},
    "wan": {"path": {"route_comment": "Fiber", "main": "fiber", "backup": "antenna",
                     "main_probe": "9.9.9.9", "backup_probe": "1.1.1.1", "backup_standby": True}},
    "hostlog": {"enabled": True, "hosts": [
        {"name": "VM HomeHub", "ip": "192.168.10.113", "user": "pi"},
        {"name": "VPS", "ip": VPS, "user": "root", "public": True}]}}


def _auditor(d, mode="live", extra=None):
    from lanowl import main as m
    from lanowl.agent import LlmAgent
    from lanowl.model import Inventory
    from lanowl.sinks import MqttBridge
    from lanowl.state import StateStore, StatusTracker
    from lanowl.tools import ToolExecutor
    cfg = {"telegram": {"via": "direct", "chat_id": "100000001",
                        "outbox_file": os.path.join(d, "o.json")},
           "alerts": {"recovery_confirm_s": 0, "cooldown_s": 0},
           "observer": {"host_ip": "192.168.10.103"}, **CFG, **(extra or {})}
    cfg["actions"] = {**cfg["actions"], "mode": mode}
    devs = [Device(x.ip, x.name, x.group, x.criticality, attrs=dict(x.attrs)) for x in DEVICES]
    devs.append(Device(VPS, "VPS", "vpn", "critical", attrs={"depends_on": "wan"}))
    inv = Inventory(devices=devs)
    st = StateStore(os.path.join(d, "s.sqlite"))
    mq = MqttBridge(cfg)
    ex = ToolExecutor(cfg, inv, mq, st)
    a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
    a.resume_alerts()
    return a


class _Exec:
    """Fake for checks._exec: records every argv, answers from a table of substrings."""

    def __init__(self, answers=None):
        self.calls, self.answers = [], answers or {}

    async def __call__(self, argv, timeout_s, stdin=None):
        self.calls.append(list(argv))
        line = " ".join(argv)
        for k, v in self.answers.items():
            if k in line:
                return v
        return 0, "", ""

    def install(self):
        self.real = C._exec
        C._exec = self
        return self

    def restore(self):
        C._exec = self.real


def run(coro):
    return asyncio.run(coro)


# --- 1. the slots ------------------------------------------------------------------------
def test_slots():
    print("\n-- the model only fills typed slots --")
    out = {}

    async def go(d):
        a = _auditor(d)
        ch = a.actions.checks

        async def p(check_name, **args):
            try:
                return await ch.plan(check_name, args)
            except C.CheckError as e:
                return {"refused": str(e)}
        for k, (name, args) in {
            "unknown": ("rm", {}),
            "semicolon": ("ping", {"target": "8.8.8.8; rm -rf /"}),
            "subshell": ("mtr", {"target": "$(id)"}),
            "option": ("traceroute", {"target": "-oX"}),
            "space": ("dns_compare", {"name": "a b.com"}),
            "bare_name": ("ping", {"target": "boiler"}),
            "scan_internet": ("nmap_ports", {"device": "8.8.8.8"}),
            "scan_alarm": ("nmap_ports", {"device": "192.168.10.34"}),
            "probe_iot": ("nmap_services", {"device": "192.168.10.30", "ports": [80]}),
            "many_ports": ("port_check", {"device": "192.168.10.31", "ports": list(range(1, 22))}),
            "whois_private": ("whois", {"target": "192.168.10.31"}),
            "wide_subnet": ("ping_sweep", {"subnet": "192.168.0.0/16"}),
            "other_subnet": ("ping_sweep", {"subnet": "10.8.0.0/24"}),
            "unit_trick": ("unit_status", {"host": "192.168.10.113", "unit": "ssh; reboot"}),
            "other_host": ("host_health", {"host": "192.168.10.31"}),
            "dns_type": ("dns_compare", {"name": "example.com", "type": "ANY; ls"}),
            "iface_trick": ("vps_capture", {"iface": "eth0 -w /tmp/x"}),
            "router_test": ("router_ping", {"target": "8.8.8.8"}),
            "tls_alarm": ("tls_cert", {"target": "192.168.10.34"}),
        }.items():
            out[k] = await p(name, **args)
        out["ok_host"] = await p("ping", target="example.com.", count=99)
        out["stranger"] = await p("nmap_ports", device="192.168.10.201")
        out["ports"] = await p("port_check", device="192.168.10.31", ports=[443, "80", 80])
        out["vps_alias"] = await p("host_health", host="vps")
        out["whois"] = await p("whois", target="45.33.32.156")
        out["sub"] = await p("ping_sweep", subnet="192.168.10.77/24")
        out["desc"] = ch.describe()
        ch.router_test = True
        ch._router_test_at = time.time()
        out["router_ok"] = await p("router_ping", target="8.8.8.8", count=50)
        out["torch_no_sniff"] = await p("router_torch", iface="ether2_Fiber")
        out["desc_test"] = ch.describe()
    with tempfile.TemporaryDirectory() as d:
        run(go(d))
    for k in ("unknown", "semicolon", "subshell", "option", "space", "bare_name", "scan_internet",
              "scan_alarm", "probe_iot", "many_ports", "whois_private", "wide_subnet",
              "other_subnet", "unit_trick", "other_host", "dns_type", "iface_trick",
              "router_test", "tls_alarm"):
        check("refused" in out[k], f"refused: {k} — {out[k].get('refused', out[k])}")
    check("use its address" in out["bare_name"]["refused"], "a device's name alone: told to use the address")
    check("`test` policy" in out["router_test"]["refused"] and "Winbox" in out["router_test"]["refused"],
          "a router test-policy check says what the owner would have to change")
    check(out["ok_host"].get("args") == {"target": "example.com", "count": 30},
          "a host name is fine to ping; count clamped to 30")
    check(out["stranger"].get("args") == {"device": "192.168.10.201"},
          "a stranger on the main LAN can be scanned (ping_sweep finds them)")
    check(out["ports"]["args"]["ports"] == [80, 443], "ports: numbers, deduplicated, sorted")
    check(out["vps_alias"]["args"]["host"] == VPS and out["vps_alias"]["where"] == "vps",
          "'vps' means the VPS, and runs there")
    check(out["whois"]["args"]["target"] == "45.33.32.156", "whois on a public address")
    check(out["sub"]["args"]["subnet"] == "192.168.10.0/24", "a subnet is normalised")
    check("router_ping" not in out["desc"] and "router_port" in out["desc"],
          "without the policy the model is not even shown the test-policy checks")
    check(out["router_ok"]["args"] == {"target": "8.8.8.8", "count": 10} and "router_ping" in out["desc_test"],
          "with it, they appear (count clamped to 10)")
    check("`sniff` policy" in out["torch_no_sniff"].get("refused", "") and "router_torch" not in out["desc_test"],
          "torch is RouterOS's `sniff`, not `test`: without it, torch stays hidden")
    check(len(C.CATALOG) >= 35, f"the catalog is the 'huge list': {len(C.CATALOG)} checks")


# --- 2. the commands -----------------------------------------------------------------------
def test_commands():
    print("\n-- the commands are built by the code --")
    ex = _Exec().install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            ch = a.actions.checks
            for name, args in [("ping", {"target": "9.9.9.9", "count": 5}),
                               ("mtr", {"target": "example.com"}),
                               ("traceroute", {"target": "1.1.1.1", "mode": "tcp", "port": 443}),
                               ("nmap_all_ports", {"device": "192.168.10.31"}),
                               ("lan_dns", {"name": "example.com", "type": "AAAA"}),
                               ("unit_status", {"host": "vps", "unit": "wg-quick@wg0"}),
                               ("vps_capture", {"iface": "wg0", "target": "10.8.0.2", "proto": "udp"}),
                               ("vps_capture", {"port": 22, "count": 500})]:
                plan = await ch.plan(name, args)
                out.setdefault("plans", []).append(plan)
                await ch.run(plan)
            out["calls"] = list(ex.calls)
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
    finally:
        ex.restore()
    c = out["calls"]
    check(c[0] == ["ping", "-n", "-c", "5", "-i", "0.3", "-W", "2", "9.9.9.9"], "ping: an argument list")
    check(c[1] == ["mtr", "--report", "--report-wide", "--no-dns", "--report-cycles", "10", "example.com"],
          "mtr: report mode, 10 cycles")
    check(c[2] == ["traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", "-T", "-p", "443", "1.1.1.1"],
          "traceroute over TCP 443")
    check(c[3] == ["nmap", "-sT", "-Pn", "-p-", "-T4", "--max-retries", "1", "192.168.10.31", "-oX", "-"],
          "every port, connect scan only (what works behind Docker's NAT)")
    ssh = [x for x in c[4:] if x[0] == "ssh"]
    check(len(ssh) == 4 and all("192.168.10.113" in " ".join(x) or VPS in " ".join(x) for x in ssh),
          "the remote checks go over the host-log ssh connection")
    r_dns, r_unit, r_cap, r_cap22 = (x[-1] for x in ssh)
    check("dig example.com AAAA" in r_dns and "@192.168.10.1" in r_dns, "the LAN host's own resolver, then the router's")
    check("systemctl status --no-pager --lines=15 wg-quick@wg0" in r_unit and "root@" + VPS in " ".join(ssh[1]),
          "unit status on the VPS, as root")
    check(r_cap == ("timeout 10 tcpdump -nn -q -l -c 50 -i wg0 "
                    + shlex.quote("udp and host 10.8.0.2 and not tcp port 22") + " 2>&1; true"),
          "a capture's filter is built from checked parts, ssh left out, bounded in time and count")
    check("port 22" in r_cap22 and "not tcp port 22" not in r_cap22 and "-c 100" in r_cap22,
          "asked for port 22, it is not excluded; count clamped to 100")
    check(out["plans"][0]["label"] == "ping 9.9.9.9 · from here"
          and out["plans"][3]["label"] == "nmap_all_ports NVR (192.168.10.31) · from here",
          "labels name devices as NAME (address) and say where it ran")


# --- 3. the outputs ------------------------------------------------------------------------
PING_OK = """PING 9.9.9.9 (9.9.9.9) 56(84) bytes of data.
--- 9.9.9.9 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 2712ms
rtt min/avg/max/mdev = 9.101/11.320/15.900/1.2 ms"""
PING_DEAD = """--- 1.1.1.1 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9200ms"""
MTR = """Start: 2026-09-24T21:53:04+0200
HOST: x                             Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 192.168.10.1                0.0%    10    0.4   0.9   0.4   1.4   0.7
  2.|-- 100.64.0.1                 0.0%    10    3.0   3.1   2.9   3.5   0.2
  3.|-- 198.51.100.1              40.0%    10   12.0  12.1  11.9  12.5   0.2
  4.|-- 9.9.9.9                   40.0%    10   11.0  11.3  10.9  12.0   0.3"""


def _dig(ans, ms=12, status="NOERROR"):
    return (0, f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n"
               + "".join(f"example.com.\t60\tIN\tA\t{x}\n" for x in ans)
               + f";; Query time: {ms} msec\n", "")


def test_outputs():
    print("\n-- outputs become one honest line --")
    ex = _Exec({"ping -n -c 10 -i 0.3 -W 2 9.9.9.9": (0, PING_OK, ""),
                "ping -n -c 10 -i 0.3 -W 2 1.1.1.1": (1, PING_DEAD, ""),
                "mtr": (0, MTR, ""),
                "dig @192.168.10.1": _dig([], 2, "NXDOMAIN"),
                "dig @9.9.9.9": _dig(["93.184.216.34"]),
                "dig @1.1.1.1": _dig(["93.184.216.34"]),
                "dig @8.8.8.8": (None, "", "no answer within 20s"),
                "fping": (1, "192.168.10.1\n192.168.10.31\n192.168.10.201\n", ""),
                "free -m": (0, " 21:00 up 3 days,  load average: 0.52, 0.40, 0.31\n---\n"
                               "              total        used        free      shared  buff/cache   available\n"
                               "Mem:           7937        3968        1000          10        2969        3700\n---\n"
                               "/dev/sda2 ext4 98G 90G 8G 92% /\n---\n"
                               "● jellyfin.service loaded failed failed Jellyfin\n---\n  PID %CPU\n", ""),
                "wg show": (0, "interface: wg0\n  public key: AAAAAAAAbbbbbbbbccccccccddddddddeeeeeeeeFFF=\n"
                               "  private key: (hidden)\n  listening port: 51820\n\n"
                               "peer: GGGGGGGGhhhhhhhhiiiiiiiijjjjjjjjkkkkkkkkLLL=\n  preshared key: (hidden)\n"
                               "  endpoint: 5.6.7.8:1234\n  allowed ips: 10.8.0.2/32\n"
                               "  latest handshake: 1 minute, 5 seconds ago\n\n"
                               "peer: MMMMMMMMnnnnnnnnooooooooppppppppqqqqqqqqRRR=\n  allowed ips: 10.8.0.16/32\n"
                               "  latest handshake: 2 hours, 3 minutes ago\n", ""),
                })
    ex.install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            ch = a.actions.checks
            out["lt_unknown"] = await ch.run(await ch.plan("link_test", {"link": "backup"}))
            a.wanwatch.path = {"link": "fiber", "on_backup": False}
            for name, args in [("link_test", {"link": "both"}), ("mtr", {"target": "9.9.9.9"}),
                               ("dns_compare", {"name": "example.com"}),
                               ("ping_sweep", {"subnet": "192.168.10.0/24"}),
                               ("host_health", {"host": "192.168.10.113"}), ("wg_status", {})]:
                out[name] = await ch.run(await ch.plan(name, args))
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
    finally:
        ex.restore()
    lt = out["link_test"]["summary"]
    check(lt.startswith("on the fiber now") and "fiber (9.9.9.9): 0% loss, avg 11 ms" in lt
          and "antenna (1.1.1.1): 100% loss (standby — expected" in lt,
          f"each link on its own; the antenna's silence while on the fiber is STANDBY, not dead: {lt}")
    check("only has internet while it is the active link" in out["lt_unknown"]["summary"],
          "not knowing which link is active, it says what the silence could mean")
    check("(standby: no answer expected)" in out["dns_compare"]["summary"],
          "the DNS comparison labels the antenna's resolver as standby")
    check(out["mtr"]["summary"] == "4 hops; last 9.9.9.9: 40.0% loss, avg 11.3 ms; loss starts at 198.51.100.1",
          f"mtr: where the loss starts — {out['mtr']['summary']}")
    dc = out["dns_compare"]["summary"]
    check(dc.startswith("the servers DISAGREE") and "router: NXDOMAIN" in dc
          and "Google via the active link: UNKNOWN" in dc,
          f"DNS: a router answering differently is said first; a dead server is UNKNOWN — {dc}")
    ps = out["ping_sweep"]
    check("3 answer: 1 known, 2 not in the inventory" in ps["summary"] and "192.168.10.201" in ps["output"]
          and "Alarm (192.168.10.34)" in ps["output"],
          "a sweep names the known, lists the stranger and the inventory devices that stayed silent")
    hh = out["host_health"]["summary"]
    check("load 0.52/0.40/0.31" in hh and "memory 49% used" in hh and "fullest disk / 92%" in hh
          and "1 failed unit: jellyfin.service" in hh, f"host health in one line: {hh}")
    wg = out["wg_status"]
    check("private key" not in wg["output"] and "preshared" not in wg["output"]
          and "GGGGGGGG…" in wg["output"] and "hhhhhhhh" not in wg["output"],
          "WireGuard: key lines dropped, public keys truncated")
    check(wg["summary"].startswith("2 peers, 1 with a handshake"), f"peers counted: {wg['summary']}")


# --- 4-6. sessions -------------------------------------------------------------------------
def test_session_lifecycle():
    print("\n-- a session: asked for, approved, used, closed --")
    ex = _Exec({"ping": (0, PING_OK, ""), "mtr": (0, MTR, "")}).install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            tg = _Tg().install()
            try:
                ac = a.actions
                out["outside"] = await ac.run_check({"check": "ping", "target": "9.9.9.9"})
                with ac.source("telegram", chat_id="100000001", question="why is it slow?"):
                    r1 = await a.executor.call("run_check", {"check": "link_test", "link": "both",
                                                             "reason": "find which link is slow"})
                    r2 = await a.executor.call("run_check", {"check": "mtr", "target": "9.9.9.9"})
                    r3 = await a.executor.call("run_check", {"check": "mtr", "target": "9.9.9.9"})
                    out["mid_turn_sent"] = len(tg.sent)
                await _settle()
                out.update(r1=r1["result"], r2=r2["result"], r3=r3["result"],
                           calls_before=list(ex.calls), sent=list(tg.sent))
                p = ac.items[-1]
                out["pending"] = dict(p, args=dict(p["args"]))

                async def fake_investigate(sess):
                    # what the model does in its own turn: run checks, then report
                    with ac.source("telegram", chat_id="100000001"):
                        out["s1"] = await ac.run_check({"check": "mtr", "target": "9.9.9.9"})
                        out["s2"] = await ac.run_check({"check": "ping", "target": "9.9.9.9"})
                    return "The fiber loses 40% from 198.51.100.1 on — the ISP's side."
                a.chat.investigate = fake_investigate
                out["toast"] = await a.chat.on_callback(f"ax:a:{p['id']}:{p['nonce']}")
                for _ in range(10):
                    await _settle()
                out["open"] = {k: p.get(k) for k in ("status", "used", "max", "findings", "until")}
                out["steps"] = [dict(x) for x in p.get("steps") or []]
                out["edit_open"] = tg.edits[-1]
                with ac.source("dashboard"):
                    out["specs"] = [t["function"]["name"] for t in a.executor.tool_specs()]
                out["specs_outside"] = [t["function"]["name"] for t in a.executor.tool_specs()]
                with ac.source("dashboard"):
                    out["s3"] = await ac.run_check({"check": "ping", "target": "1.1.1.1"})
                    out["s4"] = await ac.run_check({"check": "ping", "target": "1.1.1.1"})
                await _settle()
                out["after_budget"] = (p["status"], (p.get("outcome") or {}).get("ended"))
                out["edit_closed"] = tg.edits[-1]
                out["ctx"] = ac.context()
                out["public"] = ac.public(p)
            finally:
                tg.restore()
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
    finally:
        ex.restore()
    check("error" in out["outside"], "outside a turn that may propose, no check runs")
    r1 = out["r1"]
    check("NOT RUN" in r1["status"] and "waiting for the owner" in r1["requested"],
          "no session open: the first call asks for one and says nothing ran")
    check(out["r2"]["planned_so_far"] == ["link_test both · from here", "mtr 9.9.9.9 · from here"]
          and out["r3"]["planned_so_far"] == out["r2"]["planned_so_far"],
          "later calls join the list (once each)")
    check(out["calls_before"] == [], "NOTHING was executed before the owner approved")
    check(out["mid_turn_sent"] == 0 and len(out["sent"]) == 1, "one message, sent when the turn ends")
    msg = out["sent"][0]
    kb = msg["extra"]["reply_markup"]["inline_keyboard"]
    check("Investigation session" in msg["text"] and "find which link is slow" in msg["text"]
          and "mtr 9.9.9.9" in msg["text"] and kb[0][0]["text"] == "🔎 Open session"
          and msg["extra"].get("disable_notification") is False,
          "it says the goal and the planned checks, with Open session / Reject, and notifies")
    pp = out["pending"]
    check(pp["action"] == "investigate" and pp["status"] == "pending"
          and pp["origin"] == {"chat_id": "100000001", "question": "why is it slow?"},
          "the request remembers where it was asked, to answer there")
    check("session open until" in out["toast"], "Approve opens it")
    s1 = out["s1"]
    check(s1.get("summary", "").startswith("4 hops") and "1/3 checks used" in s1["session"],
          "inside the session a check runs at once and returns its output")
    check([x["check"] for x in out["steps"]] == ["mtr", "ping"] and out["steps"][0]["command"].startswith("mtr"),
          "every check is recorded on the session: label, command, summary, output")
    check(out["open"]["findings"].startswith("The fiber loses 40%"), "the model's report is kept on it")
    e = out["edit_open"]
    check("🟢 <b>Open</b>" in e["text"] and "✓ mtr 9.9.9.9" in e["text"] and "🦉 <b>Findings</b>" in e["text"]
          and e["markup"]["inline_keyboard"][0][0]["callback_data"].startswith("ax:e:"),
          "the Telegram message shows it open, each check, the findings — and an End button")
    check("run_check" in out["specs"] and "run_check" not in out["specs_outside"],
          "run_check is offered in a turn that may propose, and only there")
    check("3/3" in out["s3"]["session"] and "LAST check" in out["s3"]["session"],
          "while open, a question can use it too — and is told when it was the last check")
    check("NOT RUN" in out["s4"].get("status", "") and out["after_budget"] == ("done", "budget"),
          "the budget closes it; the next call asks for a new session instead of running")
    ec = out["edit_closed"]
    check("⏹" in ec["text"] and "every check used" in ec["text"] and ec["markup"] == {"inline_keyboard": []},
          "closed: the message says why and the End button goes")
    check(any("investigation session" in x and "mtr 9.9.9.9" in x and "findings:" in x for x in out["ctx"]),
          "the model's next turns see what the session found")
    check(out["public"]["steps"] and out["public"]["goal"] == "find which link is slow",
          "the dashboard gets the steps and the goal")


def test_session_time_end_restart_shadow():
    print("\n-- the clock, the End button, a restart, shadow mode, the audit, the daily cap --")
    ex = _Exec({"ping": (0, PING_OK, "")}).install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            tg = _Tg().install()
            ac = a.actions

            async def quiet(sess):
                return "ok"
            a.chat.investigate = quiet
            try:
                async def ask_and_open(via="telegram"):
                    with ac.source(via):
                        await ac.run_check({"check": "ping", "target": "9.9.9.9", "reason": "r"})
                    await _settle()
                    p = next(x for x in reversed(ac.items) if x["action"] == "investigate")
                    ac.decide(p["id"], True, "telegram")
                    await _settle()
                    return p
                p = await ask_and_open()
                out["second_open"] = None
                ac.tick(time.time() + 16 * 60)
                await _settle()
                out["timed"] = (p["status"], p["outcome"].get("ended"))
                p2 = await ask_and_open()
                out["end_toast"] = await a.chat.on_callback(f"ax:e:{p2['id']}:{p2['nonce']}")
                out["ended"] = (p2["status"], p2["outcome"].get("ended"), p2["outcome"].get("ended_by"))
                with ac.source("telegram"):
                    out["after_end"] = await ac.run_check({"check": "ping", "target": "9.9.9.9"})
                await _settle()
                # a third, left open across a restart
                p3 = next(x for x in reversed(ac.items) if x["action"] == "investigate")
                ac.decide(p3["id"], True, "dashboard")
                await _settle()
                out["open_before_restart"] = p3["status"]
                a2 = A.Actions(a)
                out["after_restart"] = [(x["status"], (x.get("outcome") or {}).get("ended"))
                                        for x in a2.items if x["id"] == p3["id"]][0]
                # the dashboard's End, through the web API, needs no PIN
                ac.items = [x for x in ac.items if x["id"] != p3["id"]]
                p4 = await ask_and_open()
                from lanowl.web import Dashboard

                class _Req:
                    headers = {"Content-Type": "application/json"}
                    content_type = "application/json"
                    host = "192.168.10.103:8088"

                    async def json(self):
                        return {"id": p4["id"], "end": True}
                resp = await Dashboard(a).api_action(_Req())
                out["web_end"] = (resp.status, p4["status"])
            finally:
                tg.restore()

        async def shadow(d):
            a = _auditor(d, mode="shadow")
            tg = _Tg().install()
            ac = a.actions

            async def quiet(sess):
                return "ok"
            a.chat.investigate = quiet
            try:
                with ac.source("dashboard"):
                    await ac.run_check({"check": "ping", "target": "9.9.9.9", "reason": "r"})
                await _settle()
                p = ac.items[-1]
                ac.decide(p["id"], True, "telegram")
                await _settle()
                n = len(ex.calls)
                with ac.source("dashboard"):
                    out["dry"] = await ac.run_check({"check": "ping", "target": "9.9.9.9"})
                out["dry_calls"] = len(ex.calls) - n
                # the audit: an ACTIVE check (the passive ones it runs itself, test_audit_self)
                # never on a healthy network; during an incident silent, once a day
                ac.end(p["id"], "telegram")
                with ac.source("audit"):
                    out["audit0"] = await ac.run_check({"check": "speed_test", "reason": "z"})
                a._open_incident_keys = lambda: {"down:192.168.10.113:servers:VM HomeHub"}
                with ac.source("audit"):
                    out["audit1"] = await ac.run_check({"check": "speed_test", "reason": "a"})
                await ac.flush_audit()
                await _settle()
                out["audit_msg"] = tg.sent[-1]
                ac.decide(ac.items[-1]["id"], False, "telegram")
                with ac.source("audit"):
                    out["audit2"] = await ac.run_check({"check": "speed_test", "reason": "b"})
                # the daily cap
                ac.sess_day = 3
                with ac.source("telegram"):
                    out["cap"] = await ac.run_check({"check": "public_ip", "reason": "c"})
                    await _settle()
                ac.decide(ac.items[-1]["id"], False, "telegram")
                with ac.source("telegram"):
                    out["cap2"] = await ac.run_check({"check": "public_ip", "reason": "d"})
            finally:
                tg.restore()
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
        with tempfile.TemporaryDirectory() as d:
            run(shadow(d))
    finally:
        ex.restore()
    check(out["timed"] == ("done", "time"), "15 minutes later it is closed by the clock")
    check("ended" in out["end_toast"] and out["ended"] == ("done", "owner", "telegram"),
          "the End button closes it at once")
    check("NOT RUN" in out["after_end"].get("status", ""), "after End, a check asks again instead of running")
    check(out["open_before_restart"] == "open" and out["after_restart"] == ("done", "restart"),
          "a restart closes an open session (its turn is gone) — never silently reopened")
    check(out["web_end"] == (200, "done"), "the dashboard's End works without a PIN")
    check(out["dry"]["summary"].startswith("DRY RUN") and out["dry_calls"] == 0,
          "shadow mode: even inside a session nothing is executed")
    check("refused" in out["audit0"] and "incident" in out["audit0"]["refused"],
          "the audit never asks for a session on a healthy network (enforced, not just prompted)")
    check("NOT RUN" in out["audit1"]["status"] and out["audit_msg"]["extra"].get("disable_notification") is True
          and "The audit proposes" in out["audit_msg"]["text"],
          "the audit's request is one SILENT message")
    check("refused" in out["audit2"] and "not again today" in out["audit2"]["refused"],
          "the audit does not ask again within a day")
    check("NOT RUN" in out["cap"].get("status", "") and "refused" in out["cap2"]
          and "3 investigation sessions a day" in out["cap2"]["refused"],
          "sessions a day are capped")


# --- 7. vps_restart --------------------------------------------------------------------------
def test_vps_restart():
    print("\n-- vps_restart: only the VPS, only the listed units, peers counted after --")
    out = {}

    async def go(d):
        a = _auditor(d)
        tg = _Tg().install()
        seen = []
        now = int(time.time())

        async def fake_ssh_run(ip, remote, timeout_s=20):
            seen.append((ip, remote))
            if "is-active" in remote and "restart" not in remote:
                return 0, "active\n", ""
            return 0, f"rc=0\nactive\n---\n{now}\nKEY1\t{now - 5}\nKEY2\t0\n", ""
        a.actions._ssh_run = fake_ssh_run
        try:
            with a.actions.source("telegram"):
                P = lambda **k: a.actions.propose({"action": "vps_restart", "reason": "r", **k})  # noqa: E731
                out["lan"] = await P(ip="192.168.10.113", service="wg-quick@wg0")
                out["unit"] = await P(ip=VPS, service="sshd")
                out["trick"] = await P(ip=VPS, service="xl2tpd; reboot")
                out["ok"] = await P(ip="vps", service="wg-quick@wg0.service")
            await _settle()
            p = a.actions.items[-1]
            out["p"] = dict(p)
            a.actions.decide(p["id"], True, "telegram")
            for _ in range(20):
                await _settle()
            out["done"] = dict(p)
            out["seen"] = list(seen)
        finally:
            tg.restore()
    with tempfile.TemporaryDirectory() as d:
        run(go(d))
    for k in ("lan", "unit", "trick"):
        check("refused" in out[k], f"refused: {k} — {out[k].get('refused')}")
    p = out["p"]
    check(out["ok"].get("proposal") and p["ip"] == VPS
          and p["command"] == f"ssh root@{VPS} systemctl restart wg-quick@wg0.service",
          "the VPS by name, a listed unit: root over ssh, no sudo")
    check(any("the remote ones" in r for r in p["risk"]), "the message says what drops: every tunnel, the remote sites included")
    o = out["done"]["outcome"]
    check(out["done"]["status"] == "done" and o["result"] ==
          "wg-quick@wg0.service restarted — active 4 s later; 1 of 2 peers handshook again within 20 s",
          f"after the restart it counts the peers that came back: {o.get('result')}")
    rem = out["seen"][-1][1]
    check("systemctl restart wg-quick@wg0.service" in rem and "sudo" not in rem
          and "wg show wg0 latest-handshakes" in rem, "the command run on the VPS")


def test_router_probe():
    print("\n-- router checks are offered only once a real ping on the router works --")
    out = {}

    async def go(d):
        a = _auditor(d)
        ch = a.actions.checks
        seen = []

        def answer(r):
            async def fake(method, path, body, user="", pw="", timeout_s=25):
                seen.append((method, path, body))
                return r
            return fake
        ch._rest = answer({"error": "router said 500: not enough permissions (9)"})
        await ch.refresh_router_test(force=True)
        out["denied"] = (ch.router_test, "router_ping" in ch.available())
        ch._rest = answer([{"host": "127.0.0.1", "sent": "1", "received": "1"}])
        await ch.refresh_router_test(force=True)
        out["allowed"] = (ch.router_test, "router_ping" in ch.available())
        ch._rest = answer({"error": "the router did not answer in time"})
        await ch.refresh_router_test(force=True)
        out["unreachable"] = ch.router_test
        out["seen"] = seen[0]
    with tempfile.TemporaryDirectory() as d:
        run(go(d))
    check(out["seen"] == ("POST", "ping", {"address": "127.0.0.1", "count": "1"}),
          "the probe is one ping to the router's own loopback")
    check(out["denied"] == (False, False), "'not enough permissions' -> the checks are not offered")
    check(out["allowed"] == (True, True), "a ping that works -> they are")
    check(out["unreachable"] is True, "a router that does not answer keeps the last verdict")


def test_router_outputs():
    print("\n-- the router's own outputs, as it really sends them --")
    out = {}

    async def go(d):
        a = _auditor(d)
        ch = a.actions.checks
        ch.router_test = ch.router_sniff = True
        ch._router_test_at = time.time()
        answers = {
            "ping": [{"avg-rtt": "27ms260us", "host": "9.9.9.9", "packet-loss": "0", "received": "1", "sent": "1"},
                     {"avg-rtt": "27ms836us", "host": "9.9.9.9", "packet-loss": "0", "received": "2", "sent": "2"}],
            "tool/traceroute": [
                {".section": "0", "address": "100.64.0.1", "loss": "0", "avg": "24"},
                {".section": "1", "address": "100.64.0.1", "loss": "0", "avg": "24.3"},
                {".section": "1", "address": "9.9.9.9", "loss": "0", "avg": "27.3"}],
            "tool/torch": [
                {".section": "0", "src-address": "192.168.10.31", "dst-address": "1.2.3.4", "rx": "1", "tx": "1"},
                {".section": "1", "src-address": "192.168.10.36", "dst-address": "23.2.2.2", "ip-protocol": "tcp",
                 "src-port": "5000", "dst-port": "443", "rx": "150000", "tx": "24000000"},
                {".section": "1", "src-address": "192.168.10.31", "dst-address": "1.2.3.4", "ip-protocol": "udp",
                 "rx": "5000", "tx": "3000"}],
            "tool/ip-scan": [{".section": "0", "address": "192.168.10.31", "mac-address": "EC:71"},
                             {".section": "1", "address": "192.168.10.31", "mac-address": "EC:71"},
                             {".section": "1", "address": "192.168.10.201", "mac-address": "AA:BB"}]}

        async def fake(method, path, body, user="", pw="", timeout_s=25):
            return answers[path]
        ch._rest = fake
        for name, args in [("router_ping", {"target": "9.9.9.9"}),
                           ("router_traceroute", {"target": "9.9.9.9"}),
                           ("router_torch", {"iface": "bridge-lan", "seconds": 3}),
                           ("router_ip_scan", {"subnet": "192.168.10.0/24"})]:
            out[name] = await ch.run(await ch.plan(name, args))
    with tempfile.TemporaryDirectory() as d:
        run(go(d))
    check(out["router_ping"]["summary"] == "2/2 answered, 0% loss, avg 27.8 ms",
          f"RouterOS durations read as milliseconds: {out['router_ping']['summary']}")
    check(out["router_traceroute"]["summary"].startswith("2 hops, reached 9.9.9.9"),
          f"traceroute: only the last pass counts — {out['router_traceroute']['summary']}")
    t = out["router_torch"]
    check("busiest TV Lounge" in t["summary"] or "busiest 192.168.10.36" in t["summary"],
          f"torch: the last pass, busiest first, named — {t['summary']}")
    check(t["output"].splitlines()[0].endswith("rx 150 kbit/s, tx 24.0 Mbit/s") and len(t["output"].splitlines()) == 2,
          "rates in bits per second, one line per flow")
    check(out["router_ip_scan"]["summary"] == "2 answer: 1 known, 1 not in the inventory"
          and "NVR (192.168.10.31)" in out["router_ip_scan"]["output"],
          "ip-scan: repeated passes counted once, devices named")


# --- 9. mikrotik_read ------------------------------------------------------------------------
def test_mikrotik_read_credentials():
    print("\n-- mikrotik_read reads the router's credentials from the secret file --")
    from lanowl import probes
    seen = {}

    async def fake(base, path, user, pw, verify_tls=False, timeout_ms=5000):
        seen.update(user=user, pw=pw, path=path)
        return probes.ProbeResult(True, None, "mikrotik", {"json": {}})
    real = probes.mikrotik_rest
    probes.mikrotik_rest = fake
    try:
        with tempfile.TemporaryDirectory() as d:
            sf = os.path.join(d, ".mikrotik")
            with open(sf, "w") as f:
                f.write("lanowl:s3cret\n")

            async def go():
                a = _auditor(d, extra={"mikrotik": {"user": "", "password": "", "secret_file": sf}})
                a.inv.devices.append(Device("192.168.10.1", "Router", "network", "critical"))
                a.inv.by_ip["192.168.10.1"] = a.inv.devices[-1]
                return await a.executor.call("mikrotik_read", {"ip": "192.168.10.1", "path": "interface"})
            run(go())
    finally:
        probes.mikrotik_rest = real
    check(seen.get("user") == "lanowl" and seen.get("pw") == "s3cret",
          "the user and password come from the file (they were '' before, on every call)")




# --- the owner's question is the approval -------------------------------------------------
ARPING = """ARPING 192.168.10.62
Unicast reply from 192.168.10.62 [34:94:54:AA:BB:CC]  3.101ms
Unicast reply from 192.168.10.62 [34:94:54:AA:BB:CC]  2.870ms
Sent 2 probes (1 broadcast(s))
Received 2 response(s)
"""
CAPTURE = """19:02:01.100 IP 192.168.10.95.51234 > 192.168.10.1.53: UDP, length 32
19:02:01.130 IP 192.168.10.1.53 > 192.168.10.95.51234: UDP, length 48
2 packets captured
2 packets received by filter
"""


def test_asked_runs_at_once():
    print("\n-- the owner's question approves its checks: they run at once, the audit still asks --")
    ex = _Exec({"ping": (0, PING_OK, ""), "mtr": (0, MTR, "")}).install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            tg = _Tg().install()
            try:
                ac = a.actions
                ran = []
                with ac.source("telegram", chat_id="100000001", question="is 9.9.9.9 ok?",
                               asked=True, ran=ran):
                    out["spec"] = ac.check_spec()["function"]["description"]
                    out["r1"] = await a.executor.call("run_check", {"check": "mtr", "target": "9.9.9.9"})
                    out["r2"] = await a.executor.call("run_check", {"check": "ping", "target": "9.9.9.9"})
                    out["r3"] = await a.executor.call("run_check", {"check": "ping", "target": "9.9.9.9"})
                    out["r4"] = await a.executor.call("run_check", {"check": "ping", "target": "9.9.9.9"})
                await _settle()
                out["ran"], out["calls"] = ran, len(ex.calls)
                out["items"] = [p for p in ac.items if p.get("action") == "investigate"]
                out["sent"] = list(tg.sent)
                with ac.source("audit"):
                    # an ACTIVE check: the passive ones the audit runs itself (test_audit_self)
                    out["audit"] = await ac.run_check({"check": "speed_test"})

                # through Chat.answer: a Telegram question is `asked`, and lists what ran
                async def ask_text(system, ctx, **kw):
                    out["system"] = system
                    await a.executor.call("run_check", {"check": "mtr", "target": "9.9.9.9"})
                    await a.executor.call("run_check", {"check": "ping", "target": "nope"})
                    return "The path is clean."
                a.agent.ask_text = ask_text
                out["tg"] = await a.chat.answer("is the fiber ok?", history=[],
                                                source={"via": "telegram", "chat_id": "100000001"})
                out["dash"] = await a.chat.answer("is the fiber ok?", history=[],
                                                  source={"via": "dashboard", "conv": "x"})
            finally:
                tg.restore()
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
    finally:
        ex.restore()
    check("question is the approval" in out["spec"] and "3 left" in out["spec"],
          "run_check tells the model the question approved it, and how many are left")
    check(out["r1"]["result"]["summary"].startswith("4 hops") and out["r2"]["result"]["ok"],
          "each call runs at once and returns its output")
    check("LAST check" in out["r3"]["result"]["left"] and "refused" in out["r4"]["result"]
          and out["calls"] == 3, "at most session.max_checks per answer; the next is refused, nothing runs")
    check(out["items"] == [] and out["sent"] == [], "no session was asked for, no button was sent")
    check([r["check"] for r in out["ran"]] == ["mtr", "ping", "ping"]
          and out["ran"][0]["command"].startswith("mtr"), "each one is recorded for the answer")
    au = out["audit"]
    check("summary" not in au and ("NOT RUN" in au.get("status", "") or "refused" in au),
          f"the audit still has to ask for a session — here refused, no incident is open ({au})")
    check("QUESTION IS THE APPROVAL" in out["system"] and "opens with a button" not in out["system"],
          "the owner's question gets the asked prompt, not the session one")
    check(out["tg"] == "The path is clean.\n\n🔧 mtr 9.9.9.9 · from here",
          f"the Telegram answer lists what ran — a refused slot is not listed ({out['tg']!r})")
    check(out["dash"] == "The path is clean.", "the dashboard shows its steps on the turn instead")


def test_capture_and_arping():
    print("\n-- arping and a packet capture from lanowl's host --")
    ex = _Exec({"arping -c 2": (0, ARPING, ""), "arping -c 3": (1, "Sent 3 probes\nReceived 0 response(s)\n", ""),
                "tcpdump -nn -q -l -p -c 50": (0, CAPTURE, ""),
                "tcpdump -nn -q -l -p -c 9": (1, "", "tcpdump: ens192: You don't have permission to capture on that device\n")}).install()
    out = {}
    try:
        async def go(d):
            a = _auditor(d)
            ch = a.actions.checks
            out["bad"] = []
            for args in ({"check": "arping", "device": "8.8.8.8"},
                         {"check": "capture", "proto": "gre"},
                         {"check": "capture", "target": "evil.example"}):
                try:
                    await ch.plan(args["check"], args)
                    out["bad"].append(None)
                except C.CheckError as e:
                    out["bad"].append(str(e))
            p1 = await ch.plan("arping", {"device": "192.168.10.62", "count": 2})
            p2 = await ch.plan("arping", {"device": "192.168.10.63"})
            p3 = await ch.plan("capture", {"target": "192.168.10.1", "port": 53, "proto": "udp"})
            p4 = await ch.plan("capture", {"count": 9, "proto": "arp"})
            out["plans"] = [p1, p2, p3, p4]
            out["big"] = (await ch.plan("capture", {"count": 500, "seconds": 99}))["args"]
            out["res"] = [await ch.run(p) for p in (p1, p2, p3, p4)]
        with tempfile.TemporaryDirectory() as d:
            run(go(d))
    finally:
        ex.restore()
    check(all(out["bad"]), f"a public address, an odd proto, a name are refused ({out['bad']})")
    check(out["big"]["count"] == 100 and out["big"]["seconds"] == 20,
          f"a big count or window is held to 100 packets / 20 s ({out['big']})")
    p1, p2, p3, p4 = out["plans"]
    iface = C.lan_iface()
    check(p1["command"] == f"arping -c 2 -w 4 -I {iface} 192.168.10.62", f"arping's command ({p1['command']})")
    check(p3["command"] == f"timeout 10 tcpdump -nn -q -l -p -c 50 -i {iface} "
                          "'udp and host 192.168.10.1 and port 53 and not tcp port 22'",
          f"the capture: headers only, no promiscuous mode, our own ssh left out ({p3['command']})")
    check(p4["command"].endswith("-c 9 -i " + iface + " arp"), "an ARP capture needs no ssh filter")
    r1, r2, r3, r4 = out["res"]
    check(r1["ok"] and "2/2 replies from 34:94:54:AA:BB:CC" in r1["summary"], f"arping answered ({r1['summary']})")
    check(r2["ok"] and "no ARP reply" in r2["summary"], "silence is said plainly")
    check(r3["ok"] and r3["summary"].startswith("2 packets captured"), f"the capture counts ({r3['summary']})")
    check(not r4["ok"] and r4["summary"].startswith("UNKNOWN — tcpdump did not run")
          and "permission" in r4["summary"], "a tcpdump that could not capture says UNKNOWN, not 'quiet'")
    check(C.lan_iface("/nonexistent") == "eth0", "no route table readable: a sane default")


if __name__ == "__main__":
    for fn in [test_slots, test_commands, test_outputs, test_session_lifecycle,
               test_session_time_end_restart_shadow, test_vps_restart, test_router_probe,
               test_router_outputs,
               test_mikrotik_read_credentials, test_asked_runs_at_once, test_capture_and_arping]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
