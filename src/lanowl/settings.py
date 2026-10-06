"""Settings from the dashboard: config.yaml, inventory.yaml and secrets.yaml, changed where they are.

The two files stay the owner's: a save edits them as text (yamledit.py), so every comment and
every line nobody touched comes out as it was, and a file edited by hand keeps working. A
save goes like this:

  1. the change is planned: the new text, the diff from the old, `lanowl --check`'s rules
     run on it — a ✗ the old file did not have stops it there, and says why;
  2. the page shows the diff; the owner confirms (and types the password again when this
     browser has not in the last ten minutes: login.py);
  3. the file as it was is kept, in lanowl's state (the last KEEP versions of each file),
     and the new text is written IN PLACE — the container mounts each of the two files on
     its own, and a rename onto a single-file mount fails;
  4. Telegram gets one line saying what changed, from which address;
  5. nothing runs differently until lanowl restarts: the page says so until it has.

Undo puts a file back as it was before a save, the same way: diff, confirm, Telegram.

secrets.yaml is written the same way, and is WRITE-ONLY: a password or a token goes in from the
page and never comes back out. Its diff shows each value as dots ("(new)" where it changes),
its changes say "login routers: password replaced", the Telegram line names the login, and
the versions kept of it are mode 600 like the rest. It needs no restart: lanowl reads it
again by itself (access.py).

What the page may not do: change a value the environment sets (it wins, model.py), show a
secret, or save over a file that changed after the page read it, or one that was replaced on
the host (an editor that saves by renaming drops a single-file read-write mount: lanowl sees
the file was writable and is not now, and asks for the container to be restarted first).
"""
from __future__ import annotations

import hashlib
import html
import logging
import os
import re
import time
from typing import Optional

from . import access, schema
from .yamledit import EditError, apply, load

log = logging.getLogger("lanowl.settings")

RECORD = "settings"
KEEP = 30                  # versions kept of each file
SHOWN = 3                  # changes named in the Telegram line; the rest are counted
NAMES = {"config": "config.yaml", "inventory": "inventory.yaml", "secrets": "secrets.yaml"}
RESTART = ("config", "inventory")       # read at start; secrets.yaml is read again by itself
# a device's keys, in the order the example writes them: where a new one goes
DEVICE_ORDER = ["ip", "name", "mac", "group", "criticality", "role", "note", "site", "depends_on",
                "expect_offline", "debounce_fails", "kind", "credentials", "manage", "restart",
                "logs", "reboot", "upgrade", "backup", "checks"]
DEVICE_QUOTED = ("name", "note", "role", "about", "risk")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class ConfigFile:
    def __init__(self, path: str):
        self.path = path
        self.writable_at_start = None        # set by Settings: a file that was, and is not now,
                                             # was replaced on the host

    def read(self) -> str:
        try:
            with open(self.path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def status(self) -> dict:
        """{"exists", "writable", "why"}: why is "", "missing", "replaced" (renamed over on
        the host: the container still holds the old file) or "readonly"."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return {"exists": False, "writable": False, "why": "missing"}
        if st.st_nlink == 0:
            return {"exists": True, "writable": False, "why": "replaced"}
        if not os.access(self.path, os.W_OK):
            # a file renamed over on the host drops the container's read-write mount of it (the
            # kernel detaches a mount whose file is replaced): the new file shows through the
            # read-only folder. Writable at start and not now means just that.
            return {"exists": True, "writable": False,
                    "why": "replaced" if self.writable_at_start else "readonly"}
        return {"exists": True, "writable": True, "why": ""}

    def write(self, text: str):
        """In place: the same file, its owner and mode kept — never a rename."""
        data = text.encode("utf-8")
        fd = os.open(self.path, os.O_WRONLY)
        try:
            view, n = memoryview(data), 0
            while n < len(data):
                n += os.write(fd, view[n:])
            os.ftruncate(fd, len(data))
            os.fsync(fd)
        finally:
            os.close(fd)


WHY = {"missing": "{name} is not there", "readonly": "{name} is read-only for lanowl: its "
       "compose file mounts the config folder read-only — mount it read-write "
       "(docker/compose.yaml: ../config:/config; docs/running/upgrading.md)", "replaced": "{name} was replaced on the host (an editor "
       "that saves by renaming, or rsync), which drops its read-write mount: restart the "
       "container (docker compose restart lanowl), then save"}


def _fmt(v) -> str:
    if v is None:
        return "(not set)"
    if isinstance(v, bool):
        return "on" if v else "off"
    if isinstance(v, list):
        s = ", ".join(_fmt(x) for x in v) or "[]"
    elif isinstance(v, dict):
        s = "{…}"
    else:
        s = str(v) if str(v) != "" else '""'
    return s if len(s) <= 40 else s[:39] + "…"


def _leaves(d, p=()):
    if isinstance(d, dict) and d:
        for k, v in d.items():
            yield from _leaves(v, p + (str(k),))
    else:
        yield p, d


SITES = ("sites", "list")


def _site_words(old, new) -> list:
    """sites.list, a site at a time: "site Office added: 192.168.0.0/24, its router
    192.168.0.1", "site Office: criticality info → warning", "site Office removed"."""
    if old == new:
        return []
    by = lambda v: {str(s.get("key")): s for s in v or [] if isinstance(s, dict)}   # noqa: E731
    o, n, out = by(old), by(new), []
    for k, s in n.items():
        label = str(s.get("name") or k)
        was = o.get(k)
        if was is None:
            out.append(f"site {label} added: {_fmt(s.get('nets') or [])}"
                       + (f", its router {s['router']}" if s.get("router") else ""))
            continue
        for f in list(dict.fromkeys(list(was) + list(s))):
            if f != "key" and was.get(f) != s.get(f):
                out.append(f"site {label}: {f} {_fmt(was.get(f))} → {_fmt(s.get(f))}")
    out += [f"site {s.get('name') or k} removed" for k, s in o.items() if k not in n]
    return out


def describe(name: str, old, new) -> list:
    """What changed, in words: "model.name qwen3:30b → qwen3:32b", "NVR: criticality high →
    critical", "TV (192.168.88.60) added". Never a hash's value."""
    out = []
    if name == "inventory":
        o, n = old or {}, new or {}
        od = {str(d.get("ip")): d for d in (o.get("devices") or []) if isinstance(d, dict)}
        nd = {str(d.get("ip")): d for d in (n.get("devices") or []) if isinstance(d, dict)}
        by_name = {str(d.get("name")): ip for ip, d in od.items()}
        moved = {}
        for ip, d in nd.items():
            if ip not in od and str(d.get("name")) in by_name and by_name[str(d.get("name"))] not in nd:
                moved[ip] = by_name[str(d.get("name"))]
        for ip, d in nd.items():
            was = od.get(moved.get(ip, ip))
            label = str(d.get("name") or ip)
            if was is None:
                out.append(f"{label} ({ip}) added")
                continue
            for k in list(dict.fromkeys(list(was) + list(d))):
                if was.get(k) != d.get(k):
                    out.append(f"{label}: {k} {_fmt(was.get(k))} → {_fmt(d.get(k))}")
        for ip, d in od.items():
            if ip not in nd and ip not in moved.values():
                out.append(f"{d.get('name') or ip} ({ip}) removed")
        if o.get("groups") != n.get("groups"):
            out.append("groups changed")
        return out
    oleaves, nleaves = dict(_leaves(old or {})), dict(_leaves(new or {}))
    out += _site_words(oleaves.get(SITES), nleaves.get(SITES))
    for p in list(dict.fromkeys(list(oleaves) + list(nleaves))):
        a, b = oleaves.get(p), nleaves.get(p)
        if a == b or p == SITES or (p not in oleaves and isinstance(b, dict) and not b):
            continue
        key = ".".join(p)
        if p in schema.HASHES:
            out.append(f"{key} {'set' if b and not a else 'removed' if a and not b else 'changed'}")
        elif p not in nleaves:
            out.append(f"{key} {_fmt(a)} → default")
        else:
            out.append(f"{key} {_fmt(a)} → {_fmt(b)}")
    return out


# --- secrets.yaml: what a page may see of it --------------------------------------------
DOTS = "••••••••"
_KEY = re.compile(r'^(\s*)(?:-\s+)?("(?:[^"\\]|\\.)*"|\'(?:[^\']|\'\')*\'|[^\s:#{}\[\],"\'][^:#{}\[\],]*?)\s*:(?=\s|$)')
_QUOTED = r'"(?:[^"\\]|\\.)*"|\'(?:[^\']|\'\')*\''
_FLOW_VAL = re.compile(r'((?:^|[{,])\s*("(?:[^"\\]|\\.)*"|[^\s:,{}"\'][^:,{}]*?)\s*:\s*)(' + _QUOTED + r'|[^,{}\s][^,{}]*?)(?=\s*[,}])')


def _secret_values(text: str) -> dict:
    """{("logins", name): password, ("tokens", name): token} of a secrets.yaml text."""
    try:
        raw = load(text) or {}
    except Exception:
        return {}
    out = {}
    if not isinstance(raw, dict):
        return out
    for n, v in (raw.get("logins") or {}).items() if isinstance(raw.get("logins"), dict) else ():
        if isinstance(v, dict) and v.get("password") not in (None, ""):
            out[("logins", str(n))] = str(v["password"])
    for n, v in (raw.get("tokens") or {}).items() if isinstance(raw.get("tokens"), dict) else ():
        if v not in (None, ""):
            out[("tokens", str(n))] = str(v)
    return out


def _unq(k: str) -> str:
    return k[1:-1] if len(k) >= 2 and k[0] == k[-1] and k[0] in "\"'" else k


def mask(text: str, other: Optional[str] = None) -> str:
    """secrets.yaml's text with every password and token as dots, for a diff. `other`: the
    text it is compared with — a value that is not the other's says "(new)". Whatever the
    file's layout, no value comes out: a text where one still would is masked whole."""
    mine = _secret_values(text)
    theirs = _secret_values(other) if other is not None else None

    def dots(where: tuple) -> str:
        if theirs is not None and where in mine and theirs.get(where) != mine.get(where):
            return DOTS + " (new)"
        return DOTS

    out, stack, block = [], [], None
    for ln in text.split("\n"):
        st = ln.lstrip()
        ind = len(ln) - len(st)
        if block is not None:
            if not st or ind > block:
                out.append((" " * ind + DOTS) if st else ln)
                continue
            block = None
        if not st or st.startswith("#"):
            out.append(ln)
            continue
        m = _KEY.match(ln)
        if not m:
            out.append(ln)
            continue
        key = _unq(m.group(2).strip())
        while stack and stack[-1][0] >= ind:
            stack.pop()
        stack.append((ind, key))
        path = [k for _, k in stack]
        rest = ln[m.end():]
        top = path[0]
        if top not in ("logins", "tokens"):
            out.append(ln)
            continue
        body = rest.strip()
        lead = ln[:m.end()] + rest[:len(rest) - len(rest.lstrip())]
        if body.startswith("{"):                     # a flow map: every token, every password
            def sub(mm, path=path):
                k = _unq(mm.group(2).strip())
                if top == "tokens" and len(path) == 1:
                    return mm.group(1) + dots(("tokens", k))
                if k == "password":
                    return mm.group(1) + dots(("logins", path[1] if len(path) > 1 else ""))
                if top == "logins" and len(path) == 1:
                    return mm.group(0)                # a login's name in `logins: {...}`: below
                return mm.group(0)
            masked = _FLOW_VAL.sub(sub, body)
            if top == "logins" and len(path) == 1:     # logins: {a: {user: x, password: y}}
                masked = re.sub(r'(password\s*:\s*)(' + _QUOTED + r'|[^,{}\s][^,{}]*?)(?=\s*[,}])',
                                lambda mm: mm.group(1) + DOTS, masked)
            out.append(lead + masked)
            continue
        value_here = body and not body.startswith("#")
        if (top == "tokens" and len(path) == 2) or (top == "logins" and len(path) >= 3 and key == "password"):
            where = ("tokens", path[1]) if top == "tokens" else ("logins", path[1])
            if value_here:
                if body[0] in "|>":
                    block = ind
                out.append(lead + dots(where))
            else:
                out.append(ln)
            continue
        out.append(ln)
    # the net under it: a line that still holds a value (a layout the walk does not know, a
    # value written in a comment, a line of a multi-line one) keeps its key and loses the rest
    pieces = {p.strip() for v in mine.values() for p in [v] + v.splitlines() if len(p.strip()) >= 3}
    final = []
    for ln in out:
        if not any(p in ln for p in pieces):
            final.append(ln)
            continue
        st = ln.lstrip()
        pad = ln[:len(ln) - len(st)]
        m = _KEY.match(ln)
        final.append(pad + "# " + DOTS if st.startswith("#") else
                     ln[:m.end()] + " " + DOTS if m and not any(p in ln[:m.end()] for p in pieces) else pad + DOTS)
    return "\n".join(final)


def describe_secrets(old, new) -> list:
    """What changed in secrets.yaml, by name: "login routers added (admin, a password)",
    "login router-read: password replaced", "token telegram set". Never a value."""
    o, n = old if isinstance(old, dict) else {}, new if isinstance(new, dict) else {}
    out = []
    ol = o.get("logins") if isinstance(o.get("logins"), dict) else {}
    nl = n.get("logins") if isinstance(n.get("logins"), dict) else {}
    how = lambda v: "lanowl's key" + (" and a password" if v.get("password") else "") if v.get("key") \
        else "a password"
    for name in dict.fromkeys(list(ol) + list(nl)):
        a, b = ol.get(name), nl.get(name)
        a, b = (a if isinstance(a, dict) else None), (b if isinstance(b, dict) else None)
        if a == b:
            continue
        if a is None:
            out.append(f"login {name} added ({b.get('user') or 'no user'}, {how(b)})")
        elif b is None:
            out.append(f"login {name} removed")
        else:
            bits = []
            if a.get("user") != b.get("user"):
                bits.append(f"user {a.get('user') or '(none)'} → {b.get('user') or '(none)'}")
            if bool(a.get("key")) != bool(b.get("key")):
                bits.append("now " + how(b))
            if a.get("password") != b.get("password") and b.get("password"):
                bits.append("password " + ("replaced" if a.get("password") else "set"))
            elif a.get("password") and not b.get("password") and not b.get("key"):
                bits.append("password removed")
            out.append(f"login {name}: " + (", ".join(bits) or "changed"))
    ot = o.get("tokens") if isinstance(o.get("tokens"), dict) else {}
    nt = n.get("tokens") if isinstance(n.get("tokens"), dict) else {}
    for name in dict.fromkeys(list(ot) + list(nt)):
        a, b = ot.get(name) or "", nt.get(name) or ""
        if a != b:
            out.append(f"token {name} " + ("set" if b and not a else "removed" if a and not b else "replaced"))
    od = o.get("devices") if isinstance(o.get("devices"), dict) else {}
    nd = n.get("devices") if isinstance(n.get("devices"), dict) else {}
    for ip in dict.fromkeys(list(od) + list(nd)):
        if od.get(ip) != nd.get(ip):
            out.append(f"devices: {ip} → {nd.get(ip) or '(none)'}")
    if o.get("ssh_key") != n.get("ssh_key"):
        out.append(f"ssh_key {_fmt(o.get('ssh_key'))} → {_fmt(n.get('ssh_key'))}")
    for k in dict.fromkeys(list(o) + list(n)):
        if k not in ("logins", "tokens", "devices", "ssh_key") and o.get(k) != n.get(k):
            out.append(f"{k} changed")
    return out


class Settings:
    def __init__(self, auditor, cfg_path: str, inv_path: str):
        self.a = auditor
        self.files = {"config": ConfigFile(cfg_path), "inventory": ConfigFile(inv_path),
                      "secrets": ConfigFile(access.secrets_path(auditor.cfg))}
        self.at_start = {k: digest(f.read()) for k, f in self.files.items()}
        for f in self.files.values():
            f.writable_at_start = f.status()["writable"]
        self.started = time.time()
        db = ((auditor.cfg.get("state") or {}).get("db_path")) or "lanowl_state.sqlite"
        self.dir = os.path.join(os.path.dirname(os.path.abspath(db)), "settings-versions")
        self._example = None
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("settings: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        self.rec.setdefault("saves", [])
        self.rec.setdefault("next", 1)

    # --- the example: forms, order, comments ------------------------------------------
    def example(self) -> str:
        if self._example is None:
            p = schema.example_path("config.example.yaml")
            try:
                with open(p, encoding="utf-8") as f:
                    self._example = f.read()
            except OSError:
                self._example = ""
        return self._example

    def _style(self, name: str) -> dict:
        if name == "secrets":
            return {"order": lambda p: ["logins", "devices", "tokens", "ssh_key"] if not p else [],
                    "comment": None, "new_style": '"'}
        if name == "config":
            ex = self.example()
            return {"order": schema.order(ex) if ex else None, "comment": schema.comments(ex) if ex else None,
                    "new_style": '"'}
        return {"order": lambda p: DEVICE_ORDER if len(p) == 2 and p[0] == "devices" else
                ["groups", "devices"] if not p else [],
                "quoted": DEVICE_QUOTED, "new_style": None}

    # --- planning ---------------------------------------------------------------------
    def locked(self, ops: list) -> list:
        """The paths among `ops` the environment sets: the page may not change them."""
        out = []
        for op in ops:
            for p, var in schema.ENV.items():
                if tuple(op["path"][:len(p)]) == p and schema.env(var):
                    out.append(f"{'.'.join(p)} is set by {var} in the environment, which wins: change it there")
        return out

    def plan(self, name: str, ops: list, text: Optional[str] = None, secrets_text: Optional[str] = None) -> dict:
        """What a save would do, without doing it: {"ok", "base", "text", "diff", "changes",
        "problems"}; {"ok": False, "error"} when it cannot be done. `secrets_text`: the
        secrets.yaml the same save writes first (the setup), for --check's rules."""
        f = self.files[name]
        old = f.read() if text is None else text
        base = digest(old)
        locked = self.locked(ops) if name == "config" else []
        if locked:
            return {"ok": False, "error": locked[0], "base": base}
        try:
            new = apply(old, ops, **self._style(name))
        except EditError as e:
            return {"ok": False, "error": f"{NAMES[name]}: {e}", "base": base}
        return self._planned(name, old, new, base, secrets_text)

    def _planned(self, name: str, old: str, new: str, base: str, secrets_text: Optional[str] = None) -> dict:
        import difflib
        if name == "secrets":            # never a value: dots, "(new)" where one changes
            a, b = mask(old), mask(new, old)
            changes = describe_secrets(load(old), load(new))
        else:
            a, b = old, new
            changes = describe(name, load(old), load(new))
        diff = list(difflib.unified_diff(a.splitlines(), b.splitlines(), NAMES[name], NAMES[name],
                                         lineterm="", n=2))[2:]
        diff = [ln if "password_hash" not in ln or not ln.startswith(("+", "-"))
                else ln.split("password_hash")[0] + "password_hash: (hidden)" for ln in diff]
        return {"ok": True, "base": base, "text": new, "diff": diff, "changes": changes,
                "problems": self.problems(name, new, secrets_text)}

    def problems(self, name: str, new: str, secrets_text: Optional[str] = None) -> list:
        """The ✗ lines `lanowl --check` gives with the new file that it does not give now."""
        from .main import check_report
        from .model import config_from, inventory_from
        try:
            texts = {k: self.files[k].read() for k in RESTART}
            before = self._check(texts, config_from, inventory_from, check_report)
            if name == "secrets":
                secrets_text = new
            else:
                texts[name] = new
            after = self._check(texts, config_from, inventory_from, check_report, secrets_text)
        except Exception as e:           # a check that crashes must not hide the reason
            log.warning("settings: check failed", exc_info=True)
            return [f"lanowl --check could not read the new file: {type(e).__name__}: {e}"]
        return [x for x in after if x not in before]

    def _check(self, texts, config_from, inventory_from, check_report, secrets_text=None) -> list:
        cfg = config_from(load(texts["config"]) or {}, self.files["config"].path)
        inv = inventory_from(load(texts["inventory"]) or {}, self.files["inventory"].path)
        if secrets_text is None:
            text, _ = check_report(cfg, inv)
        else:
            with access.overlay(cfg, secrets_text):
                text, _ = check_report(cfg, inv)
        return [ln.strip()[1:].strip() for ln in text.splitlines() if ln.strip().startswith("✗")]

    # --- saving -----------------------------------------------------------------------
    def save(self, name: str, ops: list, base: str, ip: str = "", how: str = "save",
             text: Optional[str] = None, note: str = "", secrets_text: Optional[str] = None) -> dict:
        """Write the change. `base`: the digest of the file the page planned on — another
        change since, from the page or by hand, and nothing is written. `text`: the whole
        new file (undo) instead of `ops`."""
        f = self.files[name]
        st = f.status()
        if not st["writable"]:
            return {"ok": False, "why": st["why"], "error": WHY[st["why"]].format(name=NAMES[name])}
        old = f.read()
        if digest(old) != base:
            return {"ok": False, "why": "changed", "error": f"{NAMES[name]} changed since this page "
                                                             "read it: look at it again, then save"}
        p = self._planned(name, old, text, base, secrets_text) if text is not None else \
            self.plan(name, ops, old, secrets_text)
        if not p["ok"]:
            return p
        if p["problems"]:
            return {"ok": False, "why": "check", "error": "lanowl --check would say: " + "; ".join(p["problems"]),
                    "problems": p["problems"]}
        if p["text"] == old:
            return {"ok": True, "same": True, "changes": []}
        try:
            kept = self._keep(name, old)
            f.write(p["text"])
        except OSError as e:
            return {"ok": False, "why": "write", "error": f"{NAMES[name]} could not be written: {e.strerror}"}
        if name == "secrets":
            access.reread(self.a.cfg)        # in use from now on: no restart
        last = next((s for s in reversed(self.rec["saves"]) if s["file"] == name), None)
        hand = bool(last and last.get("after") and last["after"] != base)    # edited on the host since
        entry = {"id": self.rec["next"], "ts": time.time(), "file": name, "how": how, "from": ip,
                 "changes": p["changes"], "before": kept, "after": digest(p["text"]),
                 **({"note": note} if note else {}), **({"hand": True} if hand else {})}
        self.rec["next"] += 1
        self.rec["saves"].append(entry)
        self._trim()
        self._save()
        self._tell(entry)
        log.warning("settings: %s %s from %s: %s", NAMES[name], how, ip or "?", "; ".join(p["changes"])[:300])
        return {"ok": True, "id": entry["id"], "changes": p["changes"], "base": entry["after"]}

    def _keep(self, name: str, text: str) -> str:
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fn = f"{name}-{time.strftime('%Y%m%d-%H%M%S')}-{digest(text)[:6]}.yaml"
        path = os.path.join(self.dir, fn)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
        return fn

    def _trim(self):
        for name in self.files:
            mine = [s for s in self.rec["saves"] if s["file"] == name]
            for s in mine[:-KEEP]:
                self.rec["saves"].remove(s)
                try:
                    os.remove(os.path.join(self.dir, s["before"]))
                except OSError:
                    pass

    def _save(self):
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("settings: record not saved: %s", e)

    def _tell(self, e: dict):
        """One Telegram line: which file, how, from where, what. It goes to the chat lanowl
        runs with now — so a save that moves the alerts to another chat is still heard here."""
        fname = NAMES[e["file"]]
        ch = e["changes"]
        shown = "; ".join(html.escape(c) for c in ch[:SHOWN])
        more = f"; and {len(ch) - SHOWN} more, in Settings → History" if len(ch) > SHOWN else ""
        where = f" ({html.escape(e['from'])})" if e.get("from") else ""
        head = {"save": f"{'🔑' if e['file'] == 'secrets' else '⚙️'} <b>{fname} changed</b> from the dashboard{where}",
                "restore": f"⚙️ <b>{fname} put back</b> {html.escape(e.get('note') or '')}, from the dashboard{where}",
                "setup": f"{'🔑' if e['file'] == 'secrets' else '⚙️'} <b>{fname} written</b> by the first-run setup{where}",
                "watch": f"⚙️ <b>{fname} changed</b> by Watch on the dashboard{where}"}.get(e["how"], fname)
        try:
            self.a._emit_telegram("digest", head + (": " + shown + more if shown else ""))
        except Exception:
            log.warning("settings: the Telegram line was not sent", exc_info=True)

    # --- undo ---------------------------------------------------------------------------
    def entry(self, sid) -> Optional[dict]:
        return next((s for s in self.rec["saves"] if str(s["id"]) == str(sid)), None)

    def _version(self, e: dict) -> Optional[str]:
        try:
            with open(os.path.join(self.dir, e["before"]), encoding="utf-8") as f:
                return f.read()
        except (OSError, KeyError):
            return None

    def restore_plan(self, sid) -> dict:
        e = self.entry(sid)
        text = self._version(e) if e else None
        if text is None:
            return {"ok": False, "error": "that version is not kept any more"}
        old = self.files[e["file"]].read()
        p = self._planned(e["file"], old, text, digest(old))
        return {**p, "file": e["file"]}

    def restore(self, sid, base: str, ip: str = "") -> dict:
        e = self.entry(sid)
        text = self._version(e) if e else None
        if text is None:
            return {"ok": False, "error": "that version is not kept any more"}
        note = "as it was before the " + time.strftime("%d/%m %H:%M", time.localtime(e["ts"])) + " save"
        return self.save(e["file"], [], base, ip, how="restore", text=text, note=note)

    # --- what the page shows -------------------------------------------------------------
    def pending(self) -> dict:
        """Saved and not running yet: each file whose text is not the one lanowl started with."""
        out = {}
        for name in RESTART:
            f = self.files[name]
            now = digest(f.read())
            if now != self.at_start[name]:
                saves = [s for s in self.rec["saves"] if s["file"] == name and s["ts"] >= self.started]
                out[name] = {"saves": [{"id": s["id"], "ts": s["ts"]} for s in saves],
                             "hand": not saves or saves[-1].get("after") != now}
        return out

    def history(self) -> list:
        return [{k: s.get(k) for k in ("id", "ts", "file", "how", "from", "changes", "note", "hand")}
                | {"kept": os.path.exists(os.path.join(self.dir, s["before"]))}
                for s in reversed(self.rec["saves"])]

    def view(self) -> dict:
        files = {}
        for name, f in self.files.items():
            text = f.read()
            st = f.status()
            files[name] = {"path": f.path, "base": digest(text), **st,
                           "why_text": WHY[st["why"]].format(name=NAMES[name]) if st["why"] else ""}
        return {"files": files, "pending": self.pending(), "history": self.history()[:KEEP * 2]}

    def values(self) -> dict:
        """config.yaml's sections as forms: each field with its value and where it comes from
        (the file, the environment — which wins — or not set)."""
        raw = load(self.files["config"].read()) or {}
        out = []
        for sec in schema.sections(self.example()):
            fields = []
            for fd in sec["fields"]:
                fd = dict(fd)
                if fd["type"] != "group":
                    v = raw
                    present = True
                    for k in fd["path"]:
                        if isinstance(v, dict) and k in v:
                            v = v[k]
                        else:
                            present = False
                            break
                    env = fd["env"] and schema.env(fd["env"])
                    if env:
                        fd["source"], fd["value"] = "env", env
                    elif present:
                        fd["source"], fd["value"] = "file", v
                    else:
                        fd["source"], fd["value"] = "default", None
                    if fd["path"] == ["observer", "host_ip"] and fd["source"] != "env" and not fd["value"]:
                        fd["found"] = str(self.a.cfg.get("_host_ip_found") or "")
                    if fd["hash"]:
                        fd["value"] = bool(fd["value"])
                    if fd["type"] == "yaml" and fd["source"] == "file":
                        import yaml
                        fd["text"] = yaml.safe_dump(fd["value"], default_flow_style=False, sort_keys=False,
                                                    allow_unicode=True).strip()
                fields.append(fd)
            sec = dict(sec, fields=fields, present=sec["key"] in raw)
            out.append(sec)
        return {"sections": out}
