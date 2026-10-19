"""The owl runs a command on a device itself: `device_command`, with lanowl's own login for it.

device_read (devread.py) gives the owl a few fixed reads per kind. For what they do not show —
the routes, a setting, a counter — the owl writes the command itself, on every device lanowl
has a way in to: the shell of an OpenWrt,
a Linux, an ESXi, a UniFi or a profile's kind; RouterOS's own CLI; a Reolink's, Home
Assistant's or a Shelly's API.

Two lanes, by the command:
  - on its kind's READ-ONLY list (below): it runs at once — the owner's question is the
    approval, as with a device read. One program in a known form, plain words, no shell
    syntax: the words are quoted again before they are sent, so nothing in them reaches a
    shell as code;
  - anything else — a change, a pipe, a program not on the list: the owner approves it first
    (actions.py: a proposal, with its buttons on Telegram and on the dashboard), within WAIT_S,
    and it runs exactly as they read it. The answer waits with it: the output comes back to
    the owl in the same turn, and the wait does not count against the answer's time.

The lists are the boundary. A command left off them costs the owner a button press; one wrongly
on them would change a device unasked — so every entry is a form that only reads, and anything
unsure stays off. What comes back is masked (mask_secrets): passwords, keys, tokens and password
hashes never reach the model, the record or Telegram.

Offered in the owner's own questions only (Telegram, the dashboard's Ask), like device_read —
never in the audit, over MQTT or in a session's turn.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import posixpath
import re
import shlex
import time
from typing import Optional

from .devread import LIMIT, LIMIT_MAX, OUT_MAX, pick_lines
from .report import label
from .shell import clip

log = logging.getLogger("lanowl.devcmd")

MAX_PER_ANSWER = 10            # commands an answer may run, read-only or approved
MAX_ASKED = 3                  # ...of which the owner may be asked to approve
WAIT_S = 300                   # how long a command waits for the owner's approval
RUN_S = 60                     # one command's own time limit
CARD_LINES = 12                # output lines kept on the approval card (Telegram, the dashboard)

SH_KINDS = ("openwrt", "linux", "unifi", "esxi")
API_KINDS = ("reolink", "homeassistant", "shelly")


def family(kind: str, profiles=()) -> str:
    """How a kind takes a command: "sh", "routeros", or its API's name; "" = it takes none."""
    if kind == "mikrotik":
        return "routeros"
    if kind in API_KINDS:
        return kind
    return "sh" if kind in SH_KINDS or kind in profiles else ""


# --- what comes back --------------------------------------------------------------------
# A setting whose name says it is secret, in the forms devices print them: `key=v`, `key: v`,
# `"key": "v"`, `option key 'v'` (OpenWrt's files), `PrivateKey = v` (WireGuard).
_SECRET = (r"[\w.-]*?(?:pass(?:word|wd|phrase)?|secret|psk|private[-_]?key|pre[-_]?shared[-_]?key"
           r"|(?<![a-z])key|token|community)")
_VALUE = r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;}\]]+)"
_SET_RE = re.compile(r"(?i)(\"?" + _SECRET + r"\"?\s*[=:]\s*)" + _VALUE)
_OPT_RE = re.compile(r"(?i)(\b(?:option|list)\s+" + _SECRET + r"\s+)" + _VALUE)
_HASH_RE = re.compile(r"\$(?:1|2[aby]?|5|6|y|apr1)\$[^\s:\"']+")


def _hide(m) -> str:
    v = m.group(2)
    q = v[0] if v[:1] in ("'", '"') else ""
    return m.group(1) + q + "***" + q


def mask_secrets(text: str, also=()) -> str:
    """The text with every secret's value replaced by ***: by its setting's name, a password
    hash by its shape, and the strings in `also` (the login's own password, a token) wherever
    they appear."""
    for s in also:
        if s and len(s) >= 4:
            text = text.replace(s, "***")
    text = _OPT_RE.sub(_hide, text)
    text = _SET_RE.sub(_hide, text)
    return _HASH_RE.sub("$***", text)


# --- the shell's read-only list -----------------------------------------------------------
_SH_SYNTAX = {";": "more than one command", "&": "more than one command",
              "|": "a pipe", ">": "a redirect", "<": "a redirect", "$": "a substitution",
              "`": "a substitution", "(": "a subshell", ")": "a subshell", "{": "a group",
              "}": "a group", "\\": "an escape", "*": "a wildcard", "?": "a wildcard",
              "[": "a wildcard", "]": "a wildcard", "!": "shell syntax", "#": "a comment",
              "~": "a home path", "\n": "more than one line", "\r": "more than one line"}
_BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
_NAME = re.compile(r"^[\w.:@+-]{1,64}$")         # an interface, a unit, a package, a host
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_INT = re.compile(r"^\d{1,6}$")


def sh_words(cmd: str) -> tuple:
    """(words, "") — or (None, why) when the command is more than plain words: anything a
    shell would read as code (outside quotes, or a $ ` \\ inside double quotes)."""
    q = None
    for ch in cmd:
        if q == "'":
            q = None if ch == "'" else q
            continue
        if q == '"':
            if ch == '"':
                q = None
            elif ch in "$`\\":
                return None, f"a substitution (‘{ch}’ inside double quotes)"
            continue
        if ch in "'\"":
            q = ch
        elif ch in _SH_SYNTAX:
            return None, f"{_SH_SYNTAX[ch]} (‘{ch.strip() or 'a new line'}’)"
    if q:
        return None, "an unclosed quote"
    try:
        words = shlex.split(cmd)
    except ValueError as e:
        return None, str(e)
    return (words, "") if words else (None, "an empty command")


def _form(args: list, *forms) -> str:
    """"" when `args` is one of `forms`: tuples of literal words and slots — NAME, MAC, INT,
    ANY (one word not starting with -)."""
    def fits(a, f):
        if f == "NAME":
            return bool(_NAME.match(a)) and not a.startswith("-")
        if f == "MAC":
            return bool(_MAC.match(a))
        if f == "INT":
            return bool(_INT.match(a))
        if f == "ANY":
            return bool(a) and not a.startswith("-")
        return a == f
    for f in forms:
        if len(f) == len(args) and all(fits(a, x) for a, x in zip(args, f)):
            return ""
    return "not one of its read-only forms"


def _opts(args: list, letters: str = "", valued=(), longs=(), pos=(0, 0), pos_ok=None,
          val_ok=None) -> str:
    """"" when every arg is a known flag: single letters from `letters` (also combined, -tn), a
    flag in `valued` that takes the next word (or --name=value), a long flag in `longs`; or a
    positional — between pos[0] and pos[1] of them (-1: any number), each passing `pos_ok`."""
    n, i = 0, 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name in valued:
                if not eq:
                    i += 1
                    if i >= len(args):
                        return f"{name} needs a value"
                    val = args[i]
                if val_ok and not val_ok(name, val):
                    return f"{name} {val} is out of its read-only range"
            elif a not in longs:
                return f"{a} is not on its read-only list"
        elif a.startswith("-") and len(a) > 1 and not _INT.match(a[1:]):
            if a in valued:
                i += 1
                if i >= len(args):
                    return f"{a} needs a value"
                if val_ok and not val_ok(a, args[i]):
                    return f"{a} {args[i]} is out of its read-only range"
            elif a[:2] in valued and len(a) > 2 and a[:2] != a:
                if val_ok and not val_ok(a[:2], a[2:]):
                    return f"{a} is out of its read-only range"
            elif a in longs:
                pass
            elif not all(c in letters for c in a[1:]):
                return f"{a} is not on its read-only list"
        else:
            n += 1
            if pos_ok is not None and not pos_ok(a):
                return f"{a!r} is not something it only reads"
        i += 1
    if n < pos[0] or (pos[1] >= 0 and n > pos[1]):
        return "not one of its read-only forms"
    return ""


# Files the read-only list may print: what they hold is the network and the machine's state.
_READ_EXACT = {"/proc/" + x for x in (
    "meminfo", "loadavg", "uptime", "cpuinfo", "version", "stat", "vmstat", "interrupts",
    "softirqs", "mounts", "partitions", "swaps", "diskstats", "modules", "devices",
    "filesystems")} | {"/etc/" + x for x in (
        "os-release", "openwrt_release", "openwrt_version", "issue", "hostname", "hosts",
        "resolv.conf", "board.json", "ethers", "fstab", "dnsmasq.conf")} | {
    "/tmp/dhcp.leases", "/tmp/resolv.conf", "/tmp/resolv.conf.auto",
    "/var/lib/misc/dnsmasq.leases"}
_READ_UNDER = ("/proc/net/", "/proc/sys/net/", "/sys/", "/var/log/", "/etc/config/",
               "/tmp/resolv.conf.d/", "/tmp/state/", "/tmp/sysinfo/", "/tmp/log/")


def readable(path: str) -> bool:
    if not path.startswith("/") or ".." in path.split("/"):
        return False
    p = posixpath.normpath(path)
    return p in _READ_EXACT or any(p.startswith(d) for d in _READ_UNDER)


def _files(args: list, letters="", valued=(), val_ok=None, need=1) -> str:
    why = _opts(args, letters, valued, pos=(need, -1), pos_ok=readable, val_ok=val_ok)
    if why and "not something it only reads" in why:
        return why.replace("is not something it only reads", "is not a file on its read-only "
                           "list (the state under /proc/net, /sys, /var/log, /etc/config, …)")
    return why


def _num(lo: float, hi: float):
    def ok(_flag, v):
        try:
            return lo <= float(v) <= hi
        except ValueError:
            return False
    return ok


def _ip(args):
    flags = {"-s", "-stats", "-statistics", "-d", "-details", "-br", "-brief", "-j", "-json",
             "-p", "-pretty", "-o", "-oneline", "-4", "-6", "-c", "-color", "-h", "-human",
             "-t", "-timestamp", "-ts"}
    i = 0
    while i < len(args) and args[i] in flags:
        i += 1
    rest = args[i:]
    objs = {"link", "l", "address", "addr", "a", "route", "r", "ro", "neighbour", "neighbor",
            "neigh", "n", "rule", "ru", "maddress", "maddr", "m", "mroute", "tunnel", "tun",
            "ntable", "netconf", "vrf", "nexthop", "nh", "-6"}
    if not rest:
        return "ip needs an object (link, addr, route, neigh, rule)"
    if rest[0] not in objs:
        return f"ip {rest[0]} is not on its read-only list"
    if len(rest) > 1 and rest[1] not in ("show", "list", "ls", "lst", "get"):
        return f"ip {rest[0]} {rest[1]} changes something — only show, list and get read"
    return ""


def _systemctl(args):
    read = {"status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files",
            "list-timers", "list-sockets", "list-dependencies", "show", "cat"}
    pos = [a for a in args if not a.startswith("-")]
    if pos and pos[0] not in read:
        return f"systemctl {pos[0]} is not on its read-only list (status, show, list-units, …)"
    return _opts([a for a in args if a != (pos[0] if pos else None)], "alq",
                 valued=("--type", "-t", "--state", "-n", "--lines", "-p", "--property",
                         "-o", "--output"),
                 longs=("--no-pager", "--plain", "--no-legend", "--all", "--full", "--failed",
                        "--value"), pos=(0, -1), pos_ok=lambda a: bool(_NAME.match(a)))


def _journalctl(args):
    return _opts(args, "kqrxeb", valued=(
        "-u", "--unit", "-n", "--lines", "--since", "--until", "-S", "-U", "-p",
        "--priority", "-o", "--output", "-g", "--grep", "-t", "--identifier"),
        longs=("--no-pager", "--dmesg", "--reverse", "--utc", "--no-hostname", "--quiet",
               "--all", "--boot"),
        # a field to match (_SYSTEMD_UNIT=…), or the boot -b means (-1: the one before)
        pos=(0, -1), pos_ok=lambda a: "=" in a or bool(re.match(r"^-?\d{1,3}$", a)),
        val_ok=lambda f, v: f not in ("-n", "--lines") or (_INT.match(v) and int(v) <= 2000))


def _docker(args):
    if not args:
        return "docker needs a command (ps, logs, inspect, stats --no-stream)"
    sub, rest = args[0], args[1:]
    if sub in ("version", "info"):
        return _opts(rest, valued=("--format", "-f"))
    if sub in ("ps", "images"):
        return _opts(rest, "aqsln", valued=("--format", "--filter", "-f", "-n", "--last"),
                     longs=("--all", "--no-trunc", "--quiet", "--size", "--latest", "--digests"))
    if sub == "inspect":
        return _opts(rest, "s", valued=("--format", "-f", "--type"), longs=("--size",),
                     pos=(1, -1), pos_ok=lambda a: bool(_NAME.match(a)))
    if sub == "logs":
        return _opts(rest, "t", valued=("--tail", "-n", "--since", "--until"),
                     longs=("--timestamps", "--details"), pos=(1, 1),
                     pos_ok=lambda a: bool(_NAME.match(a)),
                     val_ok=lambda f, v: f not in ("--tail", "-n") or v == "all" or
                     (_INT.match(v) and int(v) <= 2000))
    if sub == "stats":
        if "--no-stream" not in rest:
            return "docker stats needs --no-stream (it would never end)"
        return _opts(rest, "a", valued=("--format",), longs=("--no-stream", "--all", "--no-trunc"),
                     pos=(0, -1), pos_ok=lambda a: bool(_NAME.match(a)))
    if sub in ("network", "volume") and rest[:1] in (["ls"], ["inspect"]):
        return _opts(rest[1:], "q", valued=("--format", "-f", "--filter"),
                     pos=(0 if rest[0] == "ls" else 1, -1), pos_ok=lambda a: bool(_NAME.match(a)))
    return f"docker {sub} is not on its read-only list"


def _ping(args):
    if not any(a == "-c" or (a.startswith("-c") and _INT.match(a[2:])) for a in args):
        return "ping needs -c with a count (up to 10)"
    return _opts(args, "46qnD", valued=("-c", "-W", "-w", "-i", "-I", "-s", "-t"),
                 pos=(1, 1), pos_ok=lambda a: bool(_NAME.match(a)),
                 val_ok=lambda f, v: {"-c": _num(1, 10), "-W": _num(1, 10), "-w": _num(1, 30),
                                      "-i": _num(0.2, 5), "-s": _num(0, 1500),
                                      "-t": _num(1, 255)}.get(f, lambda *_: True)(f, v))


def _esxcli(args):
    i = 0
    while i < len(args) and args[i].startswith("--formatter"):
        i += 1 if "=" in args[i] else 2
    words = []
    for a in args[i:]:
        if a.startswith("-"):
            break
        words.append(a)
    if not words or words[-1] not in ("list", "get"):
        return "esxcli: only its list and get commands read"
    return ""


def _vimcmd(args):
    if not args or not re.match(r"^[a-z]+(/[\w.]+)+$", args[0]):
        return "vim-cmd needs a command (vmsvc/getallvms, …)"
    last = args[0].rsplit("/", 1)[1]
    if not re.match(r"^(get[\w.]*|power\.getstate|hostsummary|hosthardware|runtimeinfo|"
                    r"listsummary|info|list\w*)$", last):
        return f"vim-cmd {args[0]} is not on its read-only list (its get… commands)"
    return _opts(args[1:], pos=(0, 3), pos_ok=lambda a: bool(_NAME.match(a)))


def _ubus(args):
    i = 0
    while i < len(args) and args[i] in ("-v", "-S"):
        i += 1
    rest = args[i:]
    if not rest:
        return "ubus needs list or call"
    if rest[0] == "list":
        return _form(rest[1:], (), ("ANY",))
    if rest[0] == "call" and len(rest) in (3, 4):
        obj, method = rest[1], rest[2]
        if obj.split(".")[0] in ("file", "session", "rc", "exec"):
            return f"ubus {obj} is not on its read-only list"
        if not re.match(r"^(status|dump|board|info|list\w*|get\w*|get_\w+|scan_results)$", method):
            return f"ubus {obj} {method} is not on its read-only list (status, dump, info, get…)"
        if len(rest) == 4:
            try:
                if not isinstance(json.loads(rest[3]), dict):
                    return "ubus's argument is a JSON object"
            except ValueError:
                return "ubus's argument is a JSON object"
        return ""
    return f"ubus {rest[0]} is not on its read-only list"


def _grep(args):
    rest, has_e = [], False
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "-m", "-A", "-B", "-C"):
            if i + 1 >= len(args):
                return f"{a} needs a value"
            if a == "-e":
                has_e = True
            elif not _INT.match(args[i + 1]):
                return f"{a} takes a number"
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            if not all(c in "ivncwxEFhHlos" for c in a[1:]):
                return f"grep {a} is not on its read-only list"
        else:
            rest.append(a)
        i += 1
    files = rest if has_e else rest[1:]
    if not files:
        return "grep needs a file on the read-only list (it reads no input here)"
    bad = next((f for f in files if not readable(f)), None)
    return f"{bad} is not a file on its read-only list" if bad else ""


def _nmcli(args):
    i = 0
    while i < len(args) and args[i] in ("-t", "-p", "-f", "-c", "--terse", "--pretty",
                                        "--fields", "--colors"):
        i += 2 if args[i] in ("-f", "--fields", "-c", "--colors") else 1
    return _form(args[i:], (), ("general",), ("general", "status"), ("device",), ("d",),
                 ("dev",), ("device", "status"), ("device", "show"), ("device", "show", "NAME"),
                 ("device", "wifi", "list", "--rescan", "no"), ("connection",), ("con",), ("c",),
                 ("connection", "show"), ("connection", "show", "--active"),
                 ("connection", "show", "ANY"), ("radio",), ("radio", "all"),
                 ("networking", "connectivity"))


_LOG_FLAGS = dict(letters="t", valued=("-e", "-l"),
                  val_ok=lambda f, v: f != "-l" or (_INT.match(v) and int(v) <= 2000))

# program -> its read-only forms: "" = reads only, else why not. The program's own flags that
# change, follow forever or read a file elsewhere are simply absent.
SH_READ = {
    # files and the machine
    "cat": lambda a: _files(a),
    "head": lambda a: _files(a, valued=("-n", "-c"), val_ok=lambda f, v: bool(_INT.match(v))),
    "tail": lambda a: _files(a, valued=("-n", "-c"), val_ok=lambda f, v: bool(_INT.match(v))),
    "wc": lambda a: _files(a, "lcwm"),
    "grep": _grep,
    "ls": lambda a: _opts(a, "laAhtrSRd1FiGns", pos=(0, -1)),
    "stat": lambda a: _opts(a, "Ltf", valued=("-c",), pos=(1, -1)),
    "df": lambda a: _opts(a, "hkmTiPal", pos=(0, -1)),
    "free": lambda a: _opts(a, "mhkbtwg"),
    "uptime": lambda a: _opts(a, "ps"),
    "uname": lambda a: _opts(a, "asnrvmpio"),
    "date": lambda a: _opts(a, "uRI", longs=("--iso-8601", "--iso-8601=seconds", "-Iseconds"),
                            pos=(0, 1), pos_ok=lambda x: x.startswith("+")),
    "hostname": lambda a: _opts(a, "fiIsdA"),
    "id": lambda a: _opts(a, "unG"), "whoami": lambda a: _opts(a), "nproc": lambda a: _opts(a),
    "who": lambda a: _opts(a, "abHu"), "w": lambda a: _opts(a, "his"),
    "last": lambda a: _opts(a, "xFwi", valued=("-n",), pos=(0, 1), pos_ok=lambda x: bool(_NAME.match(x))),
    "lscpu": lambda a: _opts(a, "e"), "lsmod": lambda a: _opts(a),
    "lsblk": lambda a: _opts(a, "afmpdS", valued=("-o",)), "lsusb": lambda a: _opts(a, "tv"),
    "lspci": lambda a: _opts(a, "vknt", longs=("-vv", "-nn")),
    "mount": lambda a: _opts(a), "findmnt": lambda a: _opts(a, "lD", pos=(0, 1)),
    "ps": lambda a: "",                          # ps changes nothing, whatever it is asked
    "top": lambda a: _form(a, ("-b", "-n", "1"), ("-bn1",), ("-b", "-n1"), ("-n", "1", "-b")),
    "vmstat": lambda a: _opts(a, "swatdSa", pos=(0, 2), pos_ok=lambda x: _INT.match(x) and int(x) <= 5),
    "sensors": lambda a: _opts(a, "Auj", pos=(0, -1), pos_ok=lambda x: bool(_NAME.match(x))),
    "vcgencmd": lambda a: _form(a, ("measure_temp",), ("get_throttled",), ("version",),
                                ("measure_volts",), ("measure_volts", "ANY"),
                                ("measure_clock", "ANY"), ("get_mem", "ANY")),
    "sysctl": lambda a: _opts(a, "anNe", pos=(0, -1), pos_ok=lambda x: "=" not in x),
    "dmesg": lambda a: _opts(a, "TtxkrLH", valued=("-l", "--level", "-f", "--facility", "-s")),
    "logread": lambda a: _opts(a, **_LOG_FLAGS),
    "journalctl": _journalctl,
    "systemctl": _systemctl,
    "timedatectl": lambda a: _form(a, (), ("status",), ("show",), ("show-timesync",),
                                   ("timesync-status",)),
    "hostnamectl": lambda a: _form(a, (), ("status",)),
    "networkctl": lambda a: _form(a, (), ("list",), ("status",), ("status", "NAME"), ("lldp",)),
    "resolvectl": lambda a: _form(a, (), ("status",), ("status", "NAME"), ("dns",), ("domain",),
                                  ("statistics",), ("query", "ANY")),
    "chronyc": lambda a: _form([x for x in a if x not in ("-n", "-c")], ("tracking",),
                               ("sources",), ("sources", "-v"), ("sourcestats",), ("activity",),
                               ("ntpdata",), ("serverstats",)),
    "ntpq": lambda a: _opts(a, "pnw"),
    "smartctl": lambda a: _opts(a, "aHiAxcj", valued=("-d", "-l"), longs=("--scan", "--all"),
                                pos=(0, 1), pos_ok=lambda x: x.startswith("/dev/")),
    "docker": _docker,
    "lsof": lambda a: "",                        # lsof only lists
    # packages
    "opkg": lambda a: _form(a, ("list-installed",), ("list-installed", "ANY"),
                            ("list-upgradable",), ("info", "ANY"), ("status", "ANY"),
                            ("files", "ANY"), ("print-architecture",), ("whatdepends", "ANY")),
    "apt": lambda a: _form(a, ("list", "--installed"), ("list", "--upgradable"),
                           ("list", "--installed", "ANY"), ("policy", "ANY"), ("show", "ANY")),
    "apt-cache": lambda a: _opts(a[1:], pos=(1, -1)) if a[:1] in (
        ["policy"], ["show"], ["search"], ["depends"], ["rdepends"]) else "only policy, show, search",
    "dpkg": lambda a: _form(a, ("-l",), ("-l", "ANY"), ("-s", "ANY"), ("-L", "ANY"),
                            ("--get-selections",)),
    "dpkg-query": lambda a: _opts(a, "lWsL", valued=("-f", "--showformat"), pos=(0, -1)),
    # the network
    "ip": _ip,
    "ifconfig": lambda a: _form(a, (), ("-a",), ("NAME",)),
    "iwconfig": lambda a: _form(a, (), ("NAME",)),
    "route": lambda a: _form(a, (), ("-n",), ("-e",), ("-ne",), ("-en",), ("-n", "-e"),
                             ("get", "ANY"), ("-n", "get", "ANY")),
    "netstat": lambda a: _opts(a, "anptulrisewxveg46WA"),
    "ss": lambda a: "" if not any(x in ("--kill", "--events") or (x.startswith("-") and not
                                  x.startswith("--") and set(x[1:]) & {"K", "E"}) for x in a)
                       else "ss --kill and --events are not reads",
    "arp": lambda a: _opts(a, "anev", pos=(0, 1), pos_ok=lambda x: bool(_NAME.match(x))),
    "bridge": lambda a: "" if [x for x in a if not x.startswith("-")][:1] in (
        ["link"], ["fdb"], ["vlan"], ["mdb"]) and [x for x in a if not x.startswith("-")][1:2] in (
        [], ["show"], ["list"], ["ls"]) else "bridge: only its show reads",
    "brctl": lambda a: _form(a, ("show",), ("show", "NAME"), ("showmacs", "NAME"),
                             ("showstp", "NAME")),
    "iw": lambda a: _form(a, (), ("dev",), ("list",), ("phy",), ("reg", "get"),
                          ("dev", "NAME", "info"), ("dev", "NAME", "link"),
                          ("dev", "NAME", "station", "dump"), ("dev", "NAME", "station", "get", "MAC"),
                          ("dev", "NAME", "survey", "dump"), ("dev", "NAME", "mpath", "dump"),
                          ("dev", "NAME", "scan", "dump"), ("dev", "NAME", "get", "ANY"),
                          ("phy", "NAME", "info"), ("NAME", "info"), ("NAME", "link"),
                          ("NAME", "station", "dump")),
    "iwinfo": lambda a: _form(a, (), ("NAME",), *[("NAME", w) for w in (
        "info", "assoclist", "freqlist", "txpowerlist", "countrylist", "htmodelist")]),
    "ubus": _ubus,
    "uci": lambda a: _form([x for x in a if x not in ("-q", "-X", "-N")], ("show",),
                           ("show", "ANY"), ("get", "ANY"), ("export",), ("export", "ANY"),
                           ("changes",), ("changes", "ANY")),
    "swconfig": lambda a: _form(a, ("list",), ("dev", "NAME", "show"), ("dev", "NAME", "help"),
                                ("dev", "NAME", "get", "ANY"), ("dev", "NAME", "port", "INT", "show"),
                                ("dev", "NAME", "port", "INT", "get", "ANY"),
                                ("dev", "NAME", "vlan", "INT", "show"),
                                ("dev", "NAME", "vlan", "INT", "get", "ANY")),
    "wg": lambda a: _form(a, (), ("show",), ("show", "NAME"), ("show", "NAME", "ANY"),
                          ("showconf", "NAME")),
    "ethtool": lambda a: _form(a, ("NAME",), *[(f, "NAME") for f in (
        "-i", "-S", "-m", "-a", "-k", "-g", "-c", "-l", "-T", "-P", "--driver", "--statistics",
        "--module-info", "--show-features", "--show-ring", "--show-coalesce", "--show-channels",
        "--show-pause", "--show-eee", "--show-fec", "--phy-statistics")]),
    "mii-tool": lambda a: _opts(a, "v", pos=(0, -1), pos_ok=lambda x: bool(_NAME.match(x))),
    "rfkill": lambda a: _form(a, (), ("list",), ("list", "ANY")),
    "ping": _ping, "ping6": _ping,
    "traceroute": lambda a: _opts(a, "nIT46", valued=("-w", "-q", "-m", "-i"), pos=(1, 1),
                                  pos_ok=lambda x: bool(_NAME.match(x)),
                                  val_ok=lambda f, v: {"-w": _num(1, 5), "-q": _num(1, 3),
                                                       "-m": _num(1, 30)}.get(f, lambda *_: True)(f, v)),
    "nslookup": lambda a: _opts(a, longs=tuple(f"-type={t}" for t in (
        "a", "aaaa", "mx", "ns", "txt", "ptr", "soa", "srv", "cname", "any")), pos=(1, 2),
        pos_ok=lambda x: bool(_NAME.match(x))),
    "dig": lambda a: "",                         # a DNS question; dig changes nothing
    "nmcli": _nmcli,
    # ESXi
    "esxcli": _esxcli,
    "vim-cmd": _vimcmd,
    "vmware": lambda a: _form(a, ("-v",), ("-l",), ("-vl",)),
    **{p: (lambda a: _form(a, ("-l",))) for p in ("esxcfg-nics", "esxcfg-vmknic",
                                                  "esxcfg-vswitch", "esxcfg-route")},
    # UniFi
    "mca-cli-op": lambda a: _form(a, ("info",)),
    "mca-dump": lambda a: _form(a, ()),
    "wlanconfig": lambda a: _form(a, ("NAME", "list"), ("NAME", "list", "ANY")),
    # macOS (a profile's kind)
    "sw_vers": lambda a: _opts(a, longs=("-productVersion", "-buildVersion", "-productName")),
    "networksetup": lambda a: "" if a and re.match(r"^-(get|list)\w+$", a[0]) and not any(
        x.startswith("-") for x in a[1:]) else "networksetup: only its -get… and -list… read",
    "scutil": lambda a: _form(a, ("--dns",), ("--nwi",), ("--proxy",), ("--get", "ANY")),
    "system_profiler": lambda a: _opts(a, valued=("-detailLevel",), longs=("-json",),
                                       pos=(1, -1), pos_ok=lambda x: bool(re.match(r"^SP\w+DataType$", x))),
    "pmset": lambda a: _form(a, ("-g",), ("-g", "ANY")),
    "log": lambda a: _opts(a[1:], valued=("--last", "--predicate", "--style", "--start",
                                          "--end"), longs=("--info", "--debug", "--source"))
    if a[:1] == ["show"] else "log: only log show reads",
    "ipconfig": lambda a: _opts(a[1:], pos=(0, 2), pos_ok=lambda x: bool(_NAME.match(x))) if a[:1]
    and a[0] in ("getifaddr", "getpacket", "getsummary", "getoption", "getv6packet")
    else "ipconfig: only its get… read",
    "wdutil": lambda a: _form(a, ("info",)),
}
# a log's newest lines are the ones wanted
LOG_PROGRAMS = {"logread", "journalctl", "dmesg", "log", "tail"}


def sh_readonly(cmd: str) -> tuple:
    """(True, the command to send — every word quoted again) or (False, why it needs the
    owner's approval)."""
    words, why = sh_words(cmd)
    if words is None:
        return False, why
    prog = words[0]
    if "/" in prog:
        if posixpath.dirname(prog) not in _BIN_DIRS:
            return False, f"{prog} is not one of its programs"
        prog = posixpath.basename(prog)
    rule = SH_READ.get(prog)
    if rule is None:
        return False, f"{prog} is not one of its programs"
    why = rule(words[1:])
    if why:
        return False, why if why.startswith(prog) else f"{prog}: {why}"
    return True, " ".join(shlex.quote(w) for w in [prog] + words[1:])


# --- RouterOS ---------------------------------------------------------------------------------
_ROS_BAD = set("[]{};$\\`\n\r")
_ROS_WRITE = {"add", "set", "remove", "disable", "enable", "reset", "reboot", "shutdown",
              "upgrade", "install", "uninstall", "run", "execute", "import", "load", "save",
              "send", "fetch", "flush", "clear", "move", "edit", "comment", "unset", "find",
              "reset-counters", "reset-counters-all", "reset-configuration", "make-static",
              "check-for-updates", "download", "apply-changes", "scan", "sniff", "torch",
              "bandwidth-test", "blink", "cable-test", "generate", "sign", "renew", "release",
              "cancel", "resume", "stop", "start", "restore", "erase", "format-drive",
              "disconnect", "reconnect", "kill", "factory-reset"}
_ROS_VERB_ARGS_BAD = ("file=", "interval=", "follow", "follow-only", "show-sensitive", "append",
                      "duration=")


def _ros_words(cmd: str) -> list:
    return re.findall(r'[^\s"]*"[^"]*"[^\s"]*|\S+', cmd)


def ros_readonly(cmd: str) -> tuple:
    """(True, the command) or (False, why): a `print`, an `export`, a `monitor … once`, a
    counted `ping` or `traceroute` — RouterOS's own CLI, with none of its scripting."""
    bad = next((c for c in cmd if c in _ROS_BAD), None)
    if bad is not None:
        return False, f"RouterOS scripting (‘{bad.strip() or 'a new line'}’)"
    words = _ros_words(cmd.strip())
    if not words or words[0].startswith(":"):
        return False, "RouterOS scripting (a ‘:’ command)"
    # `/interface/wifi/print` (7.x) and `/interface wifi print` are the same path
    path, i = [], 0
    while i < len(words) and "=" not in words[i] and '"' not in words[i]:
        path += [p for p in words[i].split("/") if p]
        i += 1
        if path and path[-1] in ("print", "export", "monitor", "ping", "traceroute"):
            break
    verb, menu, args = (path[-1] if path else ""), path[:-1], words[i:]
    if verb not in ("print", "export", "monitor", "ping", "traceroute"):
        return False, ("not a print, export, monitor … once, ping or traceroute"
                       if not (set(path) & _ROS_WRITE) else
                       f"‘{next(w for w in path if w in _ROS_WRITE)}’ changes something")
    w = next((w for w in menu if w in _ROS_WRITE or not re.match(r"^[a-z0-9-]+$", w)), None)
    if w is not None:
        return False, f"‘{w}’ is not part of a menu it only reads"
    a = next((x for x in args if x.split("=", 1)[0] + ("=" if "=" in x else "")
              in _ROS_VERB_ARGS_BAD or x in _ROS_VERB_ARGS_BAD), None)
    if a is not None:
        return False, f"‘{a}’ makes it write a file, follow forever or show secrets"
    if verb == "monitor" and "once" not in args:
        return False, "monitor without once would never end"
    if verb in ("ping", "traceroute"):
        cnt = next((x.split("=", 1)[1] for x in args if x.startswith("count=")), "")
        if not (_INT.match(cnt) and 1 <= int(cnt) <= (10 if verb == "ping" else 3)):
            return False, f"{verb} needs count= (up to {10 if verb == 'ping' else 3})"
    return True, cmd.strip()


# --- the APIs -----------------------------------------------------------------------------
def _json_param(s: str):
    if not s:
        return {}
    try:
        v = json.loads(s)
    except ValueError:
        return None
    return v if isinstance(v, dict) else None


def api_parse(fam: str, cmd: str) -> tuple:
    """(parts, read_only, why) — parts None = not a command for this API at all."""
    cmd = cmd.strip()
    if fam == "reolink":
        m = re.match(r"^([A-Za-z][A-Za-z0-9]*)\s*(\{.*\})?$", cmd, re.S)
        prm = _json_param(m.group(2) or "") if m else None
        if not m or prm is None:
            return None, False, "a Reolink command is its name and an optional JSON param: GetNetPort {\"channel\": 0}"
        ro = m.group(1).startswith("Get")
        return {"cmd": m.group(1), "param": prm}, ro, "" if ro else "only its Get… commands read"
    if fam == "homeassistant":
        m = re.match(r"^(?:(GET|POST|PUT|DELETE|PATCH)\s+)?(/api/\S*)\s*(\{.*\})?$", cmd, re.S)
        body = _json_param(m.group(3) or "") if m else None
        if not m or body is None:
            return None, False, "a Home Assistant command is METHOD /api/… and an optional JSON body"
        method = m.group(1) or "GET"
        ro = method == "GET" and not m.group(3)
        return ({"method": method, "path": m.group(2), "body": body or None}, ro,
                "" if ro else "only GET reads")
    if fam == "shelly":
        m = re.match(r"^([A-Z][A-Za-z0-9]*\.[A-Z][A-Za-z0-9]*)\s*(\{.*\})?$", cmd, re.S)
        if m:
            prm = _json_param(m.group(2) or "")
            if prm is None:
                return None, False, "a Shelly method's params are a JSON object"
            ro = bool(re.match(r"^(Get|List)", m.group(1).split(".")[1]))
            return ({"method": m.group(1), "params": prm}, ro,
                    "" if ro else "only its Get… and List… methods read")
        m = re.match(r"^/[\w/.-]*(\?\S*)?$", cmd)
        if not m:
            return None, False, "a Shelly command is an RPC method (Wifi.GetStatus) or a Gen1 path (/status)"
        ro = bool(re.match(r"^/(shelly|status|settings(/(sta|ap|cloud|mqtt|login|relay/\d|light/\d|"
                           r"roller/\d|meter/\d|emeter/\d))?|meter/\d|emeter/\d)$", cmd))
        return {"path": cmd}, ro, "" if ro else "only /status, /settings and /shelly read"
    return None, False, "this device takes no commands"


def classify(fam: str, cmd: str) -> dict:
    """{"read_only": bool, "why": why it is not, "run": what is sent} — or {"bad": why it is
    not a command this device takes}. Pure: describe_tool names the lane before it runs."""
    cmd = str(cmd or "").strip()
    if not cmd:
        return {"bad": "an empty command"}
    if len(cmd) > 600:
        return {"bad": "a command of more than 600 characters"}
    if fam == "sh":
        ok, x = sh_readonly(cmd)
        return {"read_only": True, "run": x} if ok else {"read_only": False, "why": x, "run": cmd}
    if fam == "routeros":
        ok, x = ros_readonly(cmd)
        return {"read_only": True, "run": x} if ok else {"read_only": False, "why": x, "run": cmd}
    parts, ro, why = api_parse(fam, cmd)
    if parts is None:
        return {"bad": why}
    return {"read_only": ro, "why": why, "run": parts}


SPEC_PARAMS = {"type": "object", "properties": {
    "ip": {"type": "string", "description": "the device's address"},
    "command": {"type": "string", "description": "the command, in the device's own language "
                                                 "(see DEVICE COMMANDS)"},
    "reason": {"type": "string", "description": "one sentence the owner reads if it needs their "
                                                "approval: what it will show or change"},
    "search": {"type": "string", "description": "keep only the output lines that contain this "
                                                "(case-insensitive; several with '|')"},
    "limit": {"type": "integer", "description": f"at most N lines (default {LIMIT}, max {LIMIT_MAX})"},
}, "required": ["ip", "command", "reason"]}


class DeviceCommands:
    def __init__(self, auditor):
        self.a = auditor
        self._turn: Optional[dict] = None
        self._outputs: dict = {}            # proposal id -> the approved command's output

    # --- where ------------------------------------------------------------------
    def _profiles(self):
        return getattr(self.a.kinds, "profiles", None) or {}

    def family_of(self, ip: str) -> str:
        """How this device takes a command — "" when lanowl has no way in: a device it can
        read (devread.py: a kind and the login that kind needs), or a Shelly."""
        dev = self.a.inv.get(ip)
        if dev is None:
            return ""
        kind = str(dev.attrs.get("kind") or "")
        if kind == "shelly":
            return "shelly"
        if not self.a.devreads.reads_of(ip):
            return ""
        return family(kind, self._profiles())

    def targets(self) -> list:
        return [d for d in self.a.inv.devices if self.family_of(d.ip)]

    def shellys(self) -> list:
        return [d for d in self.a.inv.devices if str(d.attrs.get("kind") or "") == "shelly"]

    # --- is it on offer -------------------------------------------------------------
    def offered(self) -> bool:
        return self._turn is not None and bool(self.targets())

    @contextlib.contextmanager
    def turn(self, via: str, ran: Optional[list] = None):
        """The owner's question in progress: commands run (or are asked for), and each joins
        `ran`. `waited`: the seconds it spent waiting for the owner — paused() — which the
        answer's time limit does not count."""
        prev = self._turn
        self._turn = {"via": via, "ran": ran if ran is not None else [], "n": 0, "asked": 0,
                      "waited": 0.0, "since": None}
        try:
            yield self._turn
        finally:
            self._turn = prev

    def paused(self) -> float:
        t = self._turn
        if t is None:
            return 0.0
        return t["waited"] + (time.time() - t["since"] if t["since"] else 0.0)

    def spec(self) -> dict:
        approvals = self.a.actions.offered()
        return {"type": "function", "function": {
            "name": "device_command",
            "description": (
                "Run ONE command you write on a device, logged in with lanowl's own login for it "
                "(see DEVICE COMMANDS) — for what device_read's fixed reads do not show. A "
                "command on that kind's READ-ONLY list runs at once and returns its output. "
                + ("Anything else waits for the owner's approval with a button (up to "
                   f"{WAIT_S // 60} min, this answer waiting with it) and runs only if they "
                   "approve; its output then comes back here."
                   if approvals else "Anything else is refused here: approvals are off.")),
            "parameters": SPEC_PARAMS}}

    # --- the tool -------------------------------------------------------------------
    async def call(self, args: dict) -> dict:
        t = self._turn
        if t is None:
            return {"error": "commands can only be run in a question from the owner"}
        args = args if isinstance(args, dict) else {}
        ip, cmd = str(args.get("ip") or "").strip(), str(args.get("command") or "").strip()
        fam = self.family_of(ip)
        dev = self.a.inv.get(ip)
        if not fam:
            return {"refused": f"{ip} is not a device lanowl has a way in to"
                               + (f" ({dev.name}: no kind that takes commands, or no login "
                                  "of the sort its kind needs)" if dev is not None else ""),
                    "can_run_on": [label(d.name, d.ip) for d in self.targets()]}
        if ip == str((self.a.cfg.get("observer") or {}).get("host_ip") or ""):
            return {"refused": f"{dev.name} is lanowl's own machine"}
        c = classify(fam, cmd)
        if c.get("bad"):
            return {"refused": f"not a command {dev.name} takes: {c['bad']}", "nothing_ran": True}
        if t["n"] >= MAX_PER_ANSWER:
            return {"refused": f"this answer has used its {MAX_PER_ANSWER} commands",
                    "note": "Nothing ran. Answer with what you have."}
        try:
            limit = max(1, min(int(args.get("limit") or LIMIT), LIMIT_MAX))
        except (TypeError, ValueError):
            limit = LIMIT
        search = str(args.get("search") or "")[:200]
        if not c["read_only"]:
            return await self._ask(t, dev, fam, cmd, c["why"], str(args.get("reason") or ""),
                                   search, limit)
        t["n"] += 1
        log.info("device command (%s) %d/%d, read-only: %s on %s (%s)", t["via"], t["n"],
                 MAX_PER_ANSWER, cmd, dev.name, ip)
        t0 = time.time()
        ok, text = await self.execute(ip, fam, c["run"], RUN_S)
        secs = round(time.time() - t0, 1)
        t["ran"].append({"ts": time.time(), "kind": "device", "ok": ok, "secs": secs,
                         "label": f"{cmd[:60]} · on {dev.name}",
                         "summary": "ran" if ok else text[:120]})
        return self._result(dev, cmd, ok, text, search, limit,
                            lane="read-only: ran at once", secs=secs)

    def _result(self, dev, cmd: str, ok: bool, text: str, search: str, limit: int,
                **extra) -> dict:
        prog = (cmd.split() or [""])[0].rsplit("/", 1)[-1]
        newest = prog in LOG_PROGRAMS or cmd.lstrip("/").startswith("log ")
        body, note = pick_lines(text, search, limit, newest=newest)
        r = {"device": label(dev.name, dev.ip), "command": cmd, **extra,
             "output": clip(body, OUT_MAX) if body else "(nothing)"}
        if not ok:
            r["failed"] = True
        if note:
            r["note"] = note
        if len(body) > OUT_MAX:
            r["note"] = (r.get("note", "") + "; " if r.get("note") else "") + \
                "output cut — narrow it with search or limit"
        return r

    async def _ask(self, t: dict, dev, fam: str, cmd: str, why: str, reason: str,
                   search: str, limit: int) -> dict:
        """Not read-only: the owner approves it first — then it runs, and its output is this
        call's answer. Waits up to WAIT_S; a stopped answer withdraws the request."""
        acts = self.a.actions
        if not acts.offered():
            return {"refused": f"not on the read-only list ({why}), and asking the owner is "
                               "off here (actions.enabled) — nothing ran",
                    "nothing_ran": True}
        if t["asked"] >= MAX_ASKED:
            return {"refused": f"this answer has already asked the owner {MAX_ASKED} times",
                    "nothing_ran": True}
        t["asked"] += 1
        t["n"] += 1
        p = await acts.ask_command(dev.ip, dev.name, cmd, " ".join(reason.split())[:300],
                                   self._risks(dev, fam, why), WAIT_S)
        if p is None:
            return {"refused": "asking the owner is not available here", "nothing_ran": True}
        log.info("device command (%s) %d/%d, waiting for the owner: #%s %s on %s (%s)",
                 t["via"], t["n"], MAX_PER_ANSWER, p["id"], cmd, dev.name, dev.ip)
        t["since"] = time.time()
        try:
            while p.get("status") == "pending" and time.time() < p["expires"]:
                await asyncio.sleep(1)
            if p.get("status") == "pending":
                acts.withdraw(p, "expired")
            end = time.time() + 120          # approved: it runs, after any action ahead of it
            while p.get("status") == "running" and time.time() < end:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            if p.get("status") == "pending":     # the answer was stopped: so is the request
                acts.withdraw(p, "withdrawn")
            raise
        finally:
            t["waited"] += time.time() - t["since"]
            t["since"] = None
        st, o = p.get("status"), p.get("outcome") or {}
        out = self._outputs.pop(p["id"], None)
        entry = {"ts": time.time(), "kind": "device", "secs": o.get("secs", 0),
                 "label": f"{cmd[:60]} · on {dev.name} (#{p['id']})"}
        if st in ("done", "failed") and out is not None:
            entry.update(ok=st == "done", summary=f"approved, {o.get('result') or o.get('error', '')}"[:120])
            t["ran"].append(entry)
            return self._result(dev, cmd, st == "done", out, search, limit,
                                lane=f"approved by the owner on {_by(p)}", proposal=p["id"])
        t["ran"].append({**entry, "ok": False, "summary": f"not run: {st}"})
        words = {"rejected": "the owner REJECTED it — nothing ran; do not ask again for it in "
                             "other words",
                 "expired": f"the owner did not answer within {WAIT_S // 60} min — nothing ran",
                 "done": "approved, but actions are a DRY RUN: nothing ran",
                 "running": "approved, but still waiting its turn behind another action: its "
                            "output will be on its card, not in this answer",
                 "skipped": f"approved, but not run: {o.get('check', '')}",
                 "cancelled": "cancelled before it ran — nothing ran"}
        return {"device": label(dev.name, dev.ip), "command": cmd, "proposal": p["id"],
                "not_run": words.get(st, f"{st} — nothing ran")}

    def _risks(self, dev, fam: str, why: str) -> list:
        lg = self.a.access.login(dev.ip)
        hl = self.a.devreads._key_host(dev.ip)
        user = hl.user if hl is not None else (lg.user if lg is not None else "")
        how = (f"it runs as {user or '?'} over ssh" if fam in ("sh", "routeros")
               else "it goes to its API")
        out = [f"Not on the read-only list — {why}. It may CHANGE {dev.name}; {how}. Read the "
               "command before you approve."]
        if dev.criticality == "critical":
            out.append(f"{dev.name} is a CRITICAL device.")
        risk = (self.a.actions.reboot.devices.get(dev.ip) or {}).get("risk")
        if risk:
            out.append(f"If it takes {dev.name} down: {risk}")
        return out

    # --- the approved one -----------------------------------------------------------
    async def run_approved(self, p: dict) -> dict:
        """Actions._run's: the command the owner approved, exactly as they read it. Its output
        goes to the answer waiting for it; the card keeps its first lines."""
        ip = p["ip"]
        fam = self.family_of(ip)
        if not fam:
            return {"ok": False, "ran": False, "error": "lanowl has no way in to it any more"}
        c = classify(fam, p["args"]["command"])
        if c.get("bad"):
            return {"ok": False, "ran": False, "error": c["bad"]}
        run = c["run"] if fam in API_KINDS or c["read_only"] else p["args"]["command"]
        ok, text = await self.execute(ip, fam, run, RUN_S)
        self._outputs[p["id"]] = text
        while len(self._outputs) > 20:           # nobody came for these
            self._outputs.pop(next(iter(self._outputs)))
        lines = [ln[:160] for ln in text.splitlines() if ln.strip()]
        res = {"ok": ok, "ran": True, "lines": lines[:CARD_LINES]}
        n = len(lines)
        say = f"{n} line{'s' if n != 1 else ''} of output" + (
            f", the first {CARD_LINES} here" if n > CARD_LINES else "")
        if ok:
            res["result"] = say if n else "it ran, no output"
        else:
            res["error"] = (lines[-1] if lines else "no answer")[:160]
        return res

    # --- the ways in ----------------------------------------------------------------
    async def execute(self, ip: str, fam: str, run, timeout_s: float) -> tuple:
        """(ok, its output, masked). ok: it ran and said it worked (rc 0, HTTP 200)."""
        lg = self.a.access.login(ip)
        also = [lg.password] if lg is not None and lg.password else []
        try:
            if fam == "sh":
                rc, out, err = await self.a.devreads._ssh1(ip, run, timeout_s, False)
                ok, text = rc == 0, _joined(rc, out, err)
            elif fam == "routeros":
                rc, out, err = await self.a.access.ssh(ip, run, user_suffix="+ct",
                                                       timeout_s=timeout_s)
                # RouterOS answers 0 to a command it refused, with the reason on its output
                ok = rc == 0 and not re.search(r"^(bad command|expected|syntax error|failure:|"
                                               r"not enough permissions|no such item|"
                                               r"input does not match)", out or "", re.M | re.I)
                text = _joined(rc, out, err)
            elif fam == "reolink":
                r = await self.a.actions.reboot._reolink(ip, [{"cmd": run["cmd"], "action": 0,
                                                               "param": run["param"]}])
                if r.get("error"):
                    ok, text = False, r["error"]
                else:
                    v = r["value"][0] if r["value"] else {}
                    ok = v.get("code") == 0
                    text = json.dumps(v, indent=1, ensure_ascii=False)
            elif fam == "homeassistant":
                rb = self.a.actions.reboot
                tok = rb._ha_token()
                also.append(tok or "")
                ok, text = await _http(run["method"], (rb.ha_url or "") + run["path"],
                                       run["body"], {"Authorization": f"Bearer {tok}"}, timeout_s)
            else:                                 # shelly
                if "method" in run:
                    ok, text = await _http("POST", f"http://{ip}/rpc", {
                        "id": 1, "method": run["method"], "params": run["params"]}, {}, timeout_s)
                else:
                    ok, text = await _http("GET", f"http://{ip}{run['path']}", None, {}, timeout_s)
        except Exception as e:                    # never the answer's end
            log.warning("device command on %s failed", ip, exc_info=True)
            ok, text = False, f"{type(e).__name__}: {str(e)[:160]}"
        return ok, mask_secrets(text, also)


def _by(p: dict) -> str:
    return {"telegram": "Telegram", "dashboard": "the dashboard"}.get(p.get("decided_by"),
                                                                    p.get("decided_by") or "?")


def _joined(rc, out: str, err: str) -> str:
    """What came back, stdout first; the exit code when it was not 0 — the device's own words."""
    text = (out or "").rstrip()
    if (err or "").strip():
        text += ("\n" if text else "") + "[stderr] " + err.strip()
    if rc is None:
        text += ("\n" if text else "") + "(lanowl: it did not run, or did not finish in time)"
    elif rc != 0:
        text += ("\n" if text else "") + f"(lanowl: exit code {rc})"
    return text


async def _http(method: str, url: str, body, headers: dict, timeout_s: float) -> tuple:
    """(ok, the answer as text: its JSON indented, else its body) of one HTTP call."""
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as s:
            async with s.request(method, url, json=body, headers=headers,
                                 allow_redirects=False) as r:
                raw = await r.read()
                text = raw[:200_000].decode("utf-8", "replace")
                with contextlib.suppress(ValueError):
                    text = json.dumps(json.loads(text), indent=1, ensure_ascii=False)
                if r.status != 200:
                    return False, f"HTTP {r.status}\n{text}".rstrip()
                return True, text
    except Exception as e:
        return False, f"no answer ({type(e).__name__})"
