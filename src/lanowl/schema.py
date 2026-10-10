"""The Settings forms, read from config.example.yaml.

Every section of config.yaml becomes a form, and nothing about it is written twice: the
example file says what a key is (its value says the type), what it is for (its comment),
where it sits (the file's own `# --- heading ---` lines) and in what order. A key added to
the example shows up in Settings with no dashboard work. What a value cannot say — the
choices of a "shadow" or "live", a unit, a path inside the container, the password's hash —
is the short tables below.

A key that is not in the owner's file is not shown with the example's value as if it were
lanowl's: for a few dozen keys the example says one thing and the code's default another
(the example is a starting point, not the defaults). The page says the key is not in the
file, and shows what the example has as a hint.
"""
from __future__ import annotations

import os
import re
from typing import Optional

import yaml
from yaml.nodes import MappingNode, ScalarNode

_HERE = os.path.dirname(os.path.abspath(__file__))

# what a value cannot say
CHOICES = {
    ("model", "provider"): ["ollama"],
    ("model", "persona"): ["owl", ""],
    ("cadence", "llm_mode"): ["interval", "times"],
    ("alerts", "recovery_min_severity"): ["info", "warning", "critical"],
    ("wan", "watch", "flap_severity"): ["critical", "warning"],
    ("wan", "path", "severity"): ["critical", "warning"],
    ("actions", "mode"): ["shadow", "live"],
    ("logging", "level"): ["DEBUG", "INFO", "WARNING", "ERROR"],
    ("weekly", "day"): ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
}
UNITS = (("_ms", "ms"), ("_s", "seconds"), ("_min", "minutes"), ("_h", "hours"),
         ("_days", "days"), ("_pct", "%"))
# the environment wins over the file for these (model.py _env_override, firstrun.py's time
# zone): locked on the page
ENV = {("model", "url"): "LANOWL_MODEL_URL", ("observer", "host_ip"): "LANOWL_HOST_IP",
       ("web", "port"): "LANOWL_WEB_PORT", ("timezone",): "TZ"}
# never shown: set or not, with a button of its own
HASHES = {("web", "password_hash")}
# What lanowl itself does when config.yaml leaves an on/off key out — read from the code, not
# the example (six differ from it: the example switches on what a new install wants). Settings
# draws a switch that is not in the file from here; the tests check the list whole.
DEFAULTS = {
    ("model", "think"): True, ("telegram", "chat", "enabled"): False, ("web", "enabled"): False,
    ("web", "login"): True, ("cadence", "llm_on_incident"): True, ("cadence", "digest_when_ok"): False,
    ("alerts", "notify_recovery"): True, ("wan", "critical"): True, ("wan", "watch", "enabled"): True,
    ("wan", "watch", "state_messages"): True, ("wan", "watch", "log_triage", "enabled"): True,
    ("wan", "path", "backup_standby"): False, ("mikrotik", "verify_tls"): False, ("mikrotik", "api", "enabled"): False,
    ("discovery", "notify_new_devices"): False, ("discovery", "notify_address_changes"): True,
    ("sites", "scan", "enabled"): True, ("observer", "enabled"): True, ("mqtt", "tls"): False,
    ("weekly", "enabled"): False, ("actions", "enabled"): False, ("hostlog", "enabled"): False,
    ("hostlog", "burst", "enabled"): True, ("hostlog", "connections", "enabled"): True,
    ("hostlog", "triage", "enabled"): True, ("updates", "enabled"): False, ("updates", "scan", "enabled"): True,
    ("cves", "after_review"): True, ("exposure", "enabled"): False, ("drift", "enabled"): False,
    ("configwatch", "enabled"): False, ("fixes", "enabled"): True, ("scorecard", "enabled"): True,
    ("backups", "enabled"): False, ("shell", "enabled"): False, ("shell", "audit", "enabled"): False,
    ("devwatch", "enabled"): False, ("devwatch", "ports"): True, ("devwatch", "logs"): True,
}
# paths inside the container and other plumbing: under "Advanced" in their section
ADVANCED = {("telegram", "outbox_file"), ("state", "db_path"), ("logging", "file"),
            ("access", "known_hosts"), ("hostlog", "ssh"), ("shell", "socket"),
            ("shell", "audit", "socket"), ("telegram", "chat", "poll_timeout_s"),
            ("probes", "concurrency"), ("mikrotik", "lanowl_group"), ("mikrotik", "lanowl_policy")}
TITLES = {"network": "Your network", "timezone": "Time zone", "model": "The model", "telegram": "Telegram",
          "web": "The dashboard", "cadence": "Cadence", "alerts": "Alerts", "probes": "Probes",
          "wan": "The internet", "mikrotik": "The router", "discovery": "New devices",
          "sites": "Sites", "site": "Sunrise and sunset", "observer": "lanowl's own host",
          "mqtt": "MQTT", "weekly": "The week in review", "state": "State", "logging": "The log",
          "access": "Access", "actions": "Actions", "hostlog": "Host logs", "updates": "Updates",
          "cves": "Vulnerabilities", "exposure": "Exposure", "drift": "Drift",
          "configwatch": "Config watch", "fixes": "Fixes", "scorecard": "Scorecard",
          "backups": "Backups", "shell": "The model's shell", "devwatch": "Device ports and logs"}


def env(var: str) -> str:
    """A variable of ENV as the environment set it. TZ that lanowl set itself from config.yaml
    (firstrun.py) is not the environment's."""
    if var == "TZ":
        from .firstrun import env_tz
        return env_tz()
    return os.environ.get(var, "")


def example_path(name: str) -> str:
    """An example file: shipped inside the package (the wheel), else the checkout's own."""
    for p in (os.path.join(_HERE, "examples", name), os.path.join(_HERE, "..", "..", name)):
        if os.path.exists(p):
            return os.path.abspath(p)
    return ""


def _comment(line: str) -> Optional[str]:
    """The comment on a line, outside quotes; None when there is none."""
    q = None
    for i, c in enumerate(line):
        if q:
            if c == q and (q == "'" or line[i - 1] != "\\"):
                q = None
        elif c in "\"'":
            q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[i + 1:].strip()
    return None


def _unit(key: str) -> str:
    for suffix, unit in UNITS:
        if key.endswith(suffix):
            return unit
    return ""


def _kind(node, value) -> str:
    if isinstance(node, ScalarNode) and node.style in ("|", ">"):
        return "text"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list) and all(isinstance(x, (str, int, float)) for x in value):
        return "list"
    return "yaml"             # a list of maps, a map of maps: edited as YAML


class _Reader:
    def __init__(self, text: str):
        self.text = text
        self.lines = text.split("\n")

    def help_for(self, key_node, deeper_than: int) -> str:
        """The key's own comment: after it on its line, the comment lines that continue it
        (indented deeper than the keys), and the comment lines right above it."""
        ln = key_node.start_mark.line
        parts = []
        above, i = [], ln - 1
        col = key_node.start_mark.column
        while i >= 0:
            s = self.lines[i]
            if s.strip().startswith("#") and len(s) - len(s.lstrip()) == col and not _heading(s):
                above.insert(0, s.strip()[1:].strip())
                i -= 1
            else:
                break
        if col > 0:                 # a section's own lines above are the section's help
            parts += [a for a in above if a]
        c = _comment(self.lines[ln])
        if c:
            parts.append(c)
        j = ln + 1
        while j < len(self.lines):
            s = self.lines[j]
            st = s.lstrip()
            if st.startswith("#") and len(s) - len(st) > deeper_than:
                parts.append(st[1:].strip())
                j += 1
            else:
                break
        return " ".join(p for p in parts if p)

    def above(self, key_node) -> str:
        ln, out = key_node.start_mark.line - 1, []
        while ln >= 0 and self.lines[ln].startswith("#") and not _heading(self.lines[ln]):
            out.insert(0, self.lines[ln][1:].strip())
            ln -= 1
        return " ".join(x for x in out if x and not x.startswith("="))


def _heading(line: str) -> str:
    """`# --- the model (optional: ...) ---` -> "The model (optional: ...)"; the `====` block's
    title line -> "Optional features"."""
    m = re.match(r"^#\s*-{3,}\s*(.+?)\s*-{3,}\s*$", line)
    if m:
        h = m.group(1)
        return h[:1].upper() + h[1:]
    return ""


def sections(text: Optional[str] = None) -> list:
    """[{key, title, heading, help, fields: [{path, label, type, help, unit, choices,
    advanced, group, example, env, hash}]}] in the example's order."""
    if text is None:
        p = example_path("config.example.yaml")
        if not p:
            return []
        with open(p, encoding="utf-8") as f:
            text = f.read()
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    data = yaml.safe_load(text) or {}
    r = _Reader(text)
    out, heading, optional = [], "", False
    lines = text.split("\n")
    prev_end = 0
    for k, v in root.value:
        for ln in range(prev_end, k.start_mark.line):
            h = _heading(lines[ln])
            if h:
                heading = h
            if lines[ln].startswith("# ====") and not optional:
                optional = True
            if optional and lines[ln].startswith("# Optional features"):
                heading = "Optional features"
        prev_end = k.start_mark.line + 1
        sec = {"key": k.value, "title": TITLES.get(k.value, k.value), "heading": heading,
               "help": " ".join(x for x in (r.above(k), _comment(lines[k.start_mark.line]) or "") if x),
               "fields": []}
        if isinstance(v, MappingNode):
            _fields(r, v, data[k.value], [k.value], "", sec["fields"], k.start_mark.column)
        else:
            sec["fields"].append(_field(r, k, v, data[k.value], [k.value], ""))
        out.append(sec)
    return out


def _fields(r: _Reader, node: MappingNode, data: dict, path: list, group: str, out: list, col: int):
    """A section's keys; a map inside it is a group of fields of its own — unless every value
    in it is a map (a catalog of named entries), which is edited as YAML."""
    for k, v in node.value:
        p = path + [k.value]
        val = data.get(k.value)
        if isinstance(v, MappingNode) and isinstance(val, dict) and val \
                and not all(isinstance(x, dict) for x in val.values()):
            sub = " · ".join(x for x in (group, k.value) if x)
            out.append({"group": sub, "path": p, "type": "group", "help": r.help_for(k, k.start_mark.column)})
            _fields(r, v, val, p, sub, out, k.start_mark.column)
        else:
            out.append(_field(r, k, v, val, p, group))


def _field(r: _Reader, k, v, val, path: list, group: str) -> dict:
    t = tuple(path)
    adv = t in ADVANCED or any(t[:n] in ADVANCED for n in range(1, len(t)))
    f = {"path": path, "label": path[-1], "group": group, "type": _kind(v, val),
         "help": r.help_for(k, k.start_mark.column), "unit": _unit(path[-1]),
         "choices": CHOICES.get(t), "advanced": adv, "example": val,
         "env": ENV.get(t, ""), "hash": t in HASHES}
    if f["type"] == "yaml":
        f["example_text"] = yaml.safe_dump(val, default_flow_style=False, sort_keys=False, allow_unicode=True).strip()
    return f


def order(text: str):
    """order(path) -> the keys of the section at `path`, in the example's order (where a
    new key goes in the owner's file)."""
    data = yaml.safe_load(text) or {}

    def f(path):
        d = data
        for k in path:
            if not isinstance(d, dict):
                return []
            d = d.get(k)
        return list(d.keys()) if isinstance(d, dict) else []
    return f


def comments(text: str):
    """comment(path) -> the example's comment for that key (beside a new key in the file)."""
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    lines = text.split("\n")

    def f(path):
        n = root
        k = None
        for key in path:
            if not isinstance(n, MappingNode):
                return ""
            hit = next(((kn, vn) for kn, vn in n.value if kn.value == str(key)), None)
            if hit is None:
                return ""
            k, n = hit
        return (_comment(lines[k.start_mark.line]) or "") if k is not None else ""
    return f
