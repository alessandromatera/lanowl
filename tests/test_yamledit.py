"""Editing config.yaml and inventory.yaml as text (yamledit.py): `python -m tests.test_yamledit`.

Pinned down here:

  1. a changed value changes only its own characters: the comment after it stays, at its
     column; a flow map wrapped over two lines stays wrapped; quotes stay quotes;
  2. a new key goes on a line of its own where the example has it, with the example's
     comment; a section that is missing is made; a key taken out takes its lines with it;
  3. lists keep what did not change: an item changed in place keeps its comment and style,
     an item added copies its neighbours' quoting, an item removed takes only its lines;
  4. devices: a field of one device, a device added in the file's own layout, one removed;
  5. a file indented differently (items at column 0) is edited in its own layout;
  6. whatever the edit, the result parses to exactly the change — or nothing is returned.
"""
from __future__ import annotations

import difflib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.yamledit import EditError, apply, expected, load, scalar

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def changed(a: str, b: str) -> list:
    return [ln for ln in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0)
            if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]


CFG = open(os.path.join(ROOT, "config.example.yaml"), encoding="utf-8").read()
INV = open(os.path.join(ROOT, "inventory.example.yaml"), encoding="utf-8").read()
DEV = dict(new_style=None, quoted=("name", "note", "role"))


def test_values():
    t = apply(CFG, [{"op": "set", "path": ["model", "name"], "value": "qwen3:32b"}])
    d = changed(CFG, t)
    check(d == ['-  name: "qwen3:30b"                 # any Ollama model with tool calling; bigger reasons better',
                '+  name: "qwen3:32b"                 # any Ollama model with tool calling; bigger reasons better'],
          "one value: one line, quotes and comment kept")
    t = apply(CFG, [{"op": "set", "path": ["telegram", "chat_id"], "value": "100000001"}])
    line = [ln for ln in t.splitlines() if "chat_id:" in ln and "allowed" not in ln][0]
    old = [ln for ln in CFG.splitlines() if "chat_id:" in ln and "allowed" not in ln][0]
    check(line.index("#") == old.index("#"), "a longer value: the comment stays at its column")
    t = apply(CFG, [{"op": "set", "path": ["hostlog", "triage", "max_lines"], "value": 50}])
    d = changed(CFG, t)
    check(len(d) == 2 and "max_lines: 50," in d[1] and "notify_severities" not in d[1],
          "inside a flow map wrapped over two lines: only that value, still wrapped")
    t = apply(CFG, [{"op": "set", "path": ["model", "think"], "value": False}])
    check(changed(CFG, t) == ["-  think: true", "+  think: false"], "a switch")
    t = apply(CFG, [{"op": "set", "path": ["cadence", "llm_times"], "value": ["07:00", "19:00"]}])
    check(changed(CFG, t)[1] == '+  llm_times: ["07:00", "19:00"]', "a list of times, quoted like before")
    t = apply(CFG, [{"op": "set", "path": ["network", "description"], "value": "One.\nTwo.\n"}])
    d = changed(CFG, t)
    check(d[-2:] == ["+    One.", "+    Two."] and "\n\n# --- the model" in t,
          "a block of text: replaced, the blank line after it kept")


def test_keys():
    t = apply(CFG, [{"op": "del", "path": ["model", "keep_alive"]}])
    check(changed(CFG, t) == ['-  keep_alive: "10m"                 # how long the model stays loaded after a call'],
          "a key taken out: its line, nothing else")
    small = "model:\n  name: x\n  temperature: 0.2\n"
    order = lambda p: ["provider", "url", "name", "think", "num_ctx", "keep_alive", "temperature"] if p == ["model"] else []
    comment = lambda p: "how long the model stays loaded after a call" if p == ["model", "keep_alive"] else ""
    t = apply(small, [{"op": "set", "path": ["model", "keep_alive"], "value": "30m"}], order=order, comment=comment)
    check(t.splitlines()[2].startswith('  keep_alive: "30m"') and t.splitlines()[2].endswith(
        "# how long the model stays loaded after a call") and t.splitlines()[3] == "  temperature: 0.2",
          "a new key: where the example has it, with its comment")
    t = apply(small, [{"op": "set", "path": ["model", "provider"], "value": "ollama"}], order=order)
    check(t.splitlines()[1] == '  provider: "ollama"', "a new first key: above the others")
    t = apply(small, [{"op": "set", "path": ["mqtt", "host"], "value": "198.51.100.5"}])
    check(t.endswith('mqtt:\n  host: "198.51.100.5"\n') and t.startswith(small), "a missing section is made at the end")
    t = apply("model:\n  name: x\nmqtt:\n", [{"op": "set", "path": ["mqtt", "host"], "value": "h"}])
    check(load(t) == {"model": {"name": "x"}, "mqtt": {"host": "h"}}, "an empty section is filled")
    t = apply(CFG, [{"op": "set", "path": ["sites", "scan", "seconds"], "value": 45}])
    check(changed(CFG, t)[1] == '+  scan: {enabled: true, at: "05:00", seconds: 45}', "a value in a one-line map")
    t = apply("a: {x: 1}\n", [{"op": "set", "path": ["a", "y"], "value": 2}])
    check(t == "a: {x: 1, y: 2}\n", "a new key in a one-line map")
    t = apply("a: {x: 1, y: 2}\n", [{"op": "del", "path": ["a", "x"]}])
    check(t == "a: {y: 2}\n", "a key out of a one-line map")


def test_lists():
    t = apply(CFG, [{"op": "set", "path": ["sites", "list"], "value": [
        {"key": "home", "name": "Home", "nets": ["192.168.88.0/24"]},
        {"key": "office", "name": "Office", "nets": ["10.8.0.9/32"]}]}])
    d = changed(CFG, t)
    check(d == ['+    - {key: office, name: "Office", nets: ["10.8.0.9/32"]}'],
          "an item added: one line, quoted like the item beside it")
    t = apply(CFG, [{"op": "set", "path": ["sites", "list"], "value": [
        {"key": "home", "name": "Home", "nets": ["192.168.88.0/24", "192.168.89.0/24"]}]}])
    check(changed(CFG, t) == ['-    - {key: home, name: "Home", nets: ["192.168.88.0/24"]}',
                              '+    - {key: home, name: "Home", nets: ["192.168.88.0/24", "192.168.89.0/24"]}'],
          "an item changed: in place, its style kept")
    t = apply(CFG, [{"op": "set", "path": ["wan", "targets"], "value": ["8.8.8.8", "1.1.1.1"]}])
    check(t.count("# neutral public addresses") == 1 and changed(CFG, t)[1].startswith('+  targets: ["8.8.8.8", "1.1.1.1"]  '),
          "a one-line list replaced, its comment kept")


def test_devices():
    inv = load(INV)
    i = [x["ip"] for x in inv["devices"]].index("192.168.88.10")
    t = apply(INV, [{"op": "set", "path": ["devices", i, "criticality"], "value": "high"},
                    {"op": "set", "path": ["devices", i, "checks"], "value": [
                        {"type": "icmp"}, {"type": "tcp", "port": 22}, {"type": "tcp", "port": 8123, "name": "HA"}]}], **DEV)
    d = changed(INV, t)
    check(len(d) == 4 and "+    criticality: high" in d and any("port: 8123" in x and "# a named check" in x for x in d),
          "a device's field, and a check changed in place with its comment")
    new = {"ip": "192.168.88.44", "name": "ESP 3A1F2C", "group": "iot", "criticality": "low",
           "mac": "DC:A6:32:44:4F:1B", "checks": [{"type": "icmp"}]}
    t = apply(INV, [{"op": "insert", "path": ["devices"], "value": new}], **DEV)
    added = [x[1:] for x in changed(INV, t)]
    check(added == ["  - ip: 192.168.88.44", '    name: "ESP 3A1F2C"', "    group: iot", "    criticality: low",
                    '    mac: "DC:A6:32:44:4F:1B"', "    checks:", "      - {type: icmp}"],
          "a device added: in the example's layout")
    check(load(t)["devices"][-1] == new and t.index("192.168.88.44") > t.index("192.168.88.60") and
          t.index("192.168.88.44") < t.index("# A Mac, by the shipped"),
          "...after the last device, before the commented examples")
    tv = [x["ip"] for x in inv["devices"]].index("192.168.88.60")
    t = apply(INV, [{"op": "remove", "path": ["devices", tv]}], **DEV)
    d = changed(INV, t)
    check(len(d) == 6 and all(x.startswith("-") for x in d) and "# A Mac" in t, "a device removed: its lines only")
    col0 = "devices:\n- ip: 198.51.100.1\n  name: a\n  checks:\n  - {type: icmp}\n"
    t = apply(col0, [{"op": "insert", "path": ["devices"], "value": {"ip": "198.51.100.2", "name": "b"}}], **DEV)
    check(t == col0 + '- ip: 198.51.100.2\n  name: "b"\n', "items at column 0: the new one too")
    t = apply("devices: []\n", [{"op": "insert", "path": ["devices"], "value": {"ip": "198.51.100.2", "name": "b",
                                                                              "checks": [{"type": "icmp"}]}}], **DEV)
    check(load(t) == {"devices": [{"ip": "198.51.100.2", "name": "b", "checks": [{"type": "icmp"}]}]},
          "the first device into an empty list")
    t = apply("devices:\n  - ip: 198.51.100.1\n    name: a\n", [{"op": "remove", "path": ["devices", 0]}], **DEV)
    check(load(t) == {"devices": []}, "the last device out: an empty list, not nothing")


def test_exact():
    check(scalar("13:00") == '"13:00"' and scalar("192.168.88.1") == "192.168.88.1" and scalar("yes") == '"yes"'
          and scalar("10") == '"10"', "plain only where YAML reads it back the same")
    ops = [{"op": "set", "path": ["model", "name"], "value": "a: b # c"}]
    t = apply(CFG, ops)
    check(load(t)["model"]["name"] == "a: b # c", "a value that needs quotes gets them")
    check(expected({"a": {"b": 1}}, [{"op": "del", "path": ["a", "b"]}, {"op": "set", "path": ["c", "d"], "value": 2}])
          == {"a": {}, "c": {"d": 2}}, "the change as data")
    try:
        apply("a: [1\n", [{"op": "set", "path": ["a"], "value": 2}])
        check(False, "a broken file is refused")
    except EditError:
        check(True, "a broken file is refused")
    # every key of the example set to a new value: each edit comes out exact
    data, bad = load(CFG), []

    def leaves(d, p):
        for k, v in d.items():
            if isinstance(v, dict) and v:
                yield from leaves(v, p + [k])
            else:
                yield p + [k], v
    for path, v in leaves(data, []):
        new = (not v) if isinstance(v, bool) else (v + 1) if isinstance(v, (int, float)) else \
            (v + ["x"] if isinstance(v, list) and all(isinstance(i, str) for i in v) else "changed" if isinstance(v, str) else None)
        if new is None:
            continue
        try:
            t = apply(CFG, [{"op": "set", "path": path, "value": new}])
            if len(changed(CFG, t)) > 2 and not isinstance(v, str):
                bad.append(".".join(path) + " (more lines than its own)")
        except EditError as e:
            bad.append(".".join(path) + f" ({e})")
    check(not bad, f"every value of the example, changed one at a time: exact{' — ' + ', '.join(bad[:5]) if bad else ''}")


if __name__ == "__main__":
    for fn in [test_values, test_keys, test_lists, test_devices, test_exact]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all yamledit tests passed")
