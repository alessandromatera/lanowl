"""A new install with an empty config folder (firstrun.py): `python -m tests.test_firstrun`.

No network: the host address is read from a socket that sends nothing, and only checked for
its shape. Pinned down here:

  1. an empty folder gets config.yaml, inventory.yaml, secrets.yaml (each mode 600) and an ssh
     key; a folder with config.yaml gets nothing, and neither does one lanowl cannot write;
  2. the files it writes are a working start: they load, `--check` has nothing against them
     but the password still to choose, there is no example address in them, and Settings and
     the setup can edit them (a login into `logins:` with nothing under it, a device into
     `devices: []`);
  3. the time zone: config.yaml's, unless TZ in the environment says otherwise — and a TZ that
     lanowl set itself is not taken for the environment's after Restart to apply;
  4. lanowl's own address is found only when nothing set it.
"""
from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import access, firstrun
from lanowl.main import _no_config, check_report
from lanowl.model import load_config, load_inventory
from lanowl.yamledit import apply, load

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def test_prepare():
    print("\n-- an empty config folder: lanowl writes its own files --")
    with tempfile.TemporaryDirectory() as d:
        cfg, inv = os.path.join(d, "config.yaml"), os.path.join(d, "inventory.yaml")
        made = firstrun.prepare(cfg, inv)
        keygen = shutil.which("ssh-keygen") is not None
        check(made[:3] == ["config.yaml", "inventory.yaml", "secrets.yaml"]
              and (made[3] == "id_ed25519" if keygen else made[3].startswith("no ssh key")),
              "config.yaml, inventory.yaml, secrets.yaml and lanowl's ssh key")
        modes = {n: stat.S_IMODE(os.stat(os.path.join(d, n)).st_mode)
                 for n in ("config.yaml", "inventory.yaml", "secrets.yaml")}
        check(set(modes.values()) == {0o600}, "each one mode 600")
        if keygen:
            check(stat.S_IMODE(os.stat(os.path.join(d, "id_ed25519")).st_mode) == 0o600
                  and open(os.path.join(d, "id_ed25519.pub")).read().startswith("ssh-ed25519 "),
                  "the key: private 600, its public half beside it")
        before = {n: open(os.path.join(d, n)).read() for n in ("config.yaml", "secrets.yaml")}
        check(firstrun.prepare(cfg, inv) == [] and
              all(open(os.path.join(d, n)).read() == t for n, t in before.items()),
              "a second start: nothing written, nothing touched")
        texts = "".join(open(os.path.join(d, n)).read() for n in ("config.yaml", "inventory.yaml", "secrets.yaml"))
        check("192.168." not in texts and "change-me" not in texts, "no example address, no example password")

        c, i = load_config(cfg), load_inventory(inv)
        sec = access.shared(c).data()
        text, bad = check_report(c, i)
        xs = [ln.strip() for ln in text.splitlines() if ln.strip().startswith("✗")]
        check(c["web"]["enabled"] and c["telegram"]["chat"]["enabled"] and c["wan"]["targets"]
              and c["weekly"]["enabled"] and i.devices == [] and sec["logins"] == {} and
              sec["ssh_key"] == os.path.join(d, "id_ed25519"),
              "they load: the dashboard on, the internet watched, no device, no login, the key's path")
        check(len(xs) == 1 and "no password" in xs[0], "--check: only the password still to choose")

        s = open(os.path.join(d, "secrets.yaml")).read()
        s2 = apply(s, [{"op": "set", "path": ["logins", "router-read"], "value": {"user": "lanowl", "password": 'p"w: x'}},
                       {"op": "set", "path": ["tokens", "telegram"], "value": "123456:" + "A" * 30}], new_style='"')
        got = load(s2)
        check(got["logins"]["router-read"] == {"user": "lanowl", "password": 'p"w: x'}
              and got["tokens"]["telegram"].startswith("123456:") and s2.startswith("# lanowl's secrets"),
              "secrets.yaml takes a login and a token where nothing was, its comments kept")
        iv = open(inv).read()
        iv2 = apply(iv, [{"op": "insert", "path": ["devices"], "value": {"ip": "192.0.2.10", "name": "Router",
                                                                          "checks": [{"type": "icmp"}]}}], new_style=None)
        check(load(iv2)["devices"][0]["ip"] == "192.0.2.10", "inventory.yaml takes a device into devices: []")
        cf = open(cfg).read()
        cf2 = apply(cf, [{"op": "set", "path": ["timezone"], "value": "Europe/Berlin"},
                         {"op": "set", "path": ["telegram", "chat_id"], "value": "100000001"}])
        check(load(cf2)["timezone"] == "Europe/Berlin" and load(cf2)["telegram"]["chat_id"] == "100000001"
              and load(cf2)["telegram"]["chat"]["enabled"] is True, "config.yaml takes the time zone and the chat")

    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "config.yaml"), "w").write("web: {enabled: true}\n")
        check(firstrun.prepare(os.path.join(d, "config.yaml"), os.path.join(d, "inventory.yaml")) == []
              and sorted(os.listdir(d)) == ["config.yaml"], "an install with config.yaml: nothing added")
    if os.geteuid() != 0:
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o555)
            try:
                cfg = os.path.join(d, "config.yaml")
                check(firstrun.prepare(cfg, os.path.join(d, "inventory.yaml")) == [] and
                      "cannot write" in _no_config(cfg) and "../config:/config" in _no_config(cfg),
                      "a folder mounted read-only: nothing written, and the start says how to fix it")
            finally:
                os.chmod(d, 0o755)
    check("start lanowl once" in _no_config("/nonexistent-lanowl/config.yaml") and _no_config(__file__) == "",
          "no folder at all: said too; a file that is there: no complaint")


def test_timezone():
    print("\n-- the time zone: config.yaml's, unless the environment's --")
    saved = {k: os.environ.get(k) for k in ("TZ", firstrun.TZ_MARK)}
    try:
        for k in saved:
            os.environ.pop(k, None)
        check(firstrun.apply_timezone({"timezone": "Asia/Tokyo"}) == "config" and os.environ["TZ"] == "Asia/Tokyo"
              and time.strftime("%Z") in ("JST",), "config.yaml's zone, for this process")
        check(firstrun.env_tz() == "", "...and it is not the environment's: Settings keeps the field open")
        # Restart to apply keeps the environment: the zone taken out of config.yaml goes too
        check(firstrun.apply_timezone({}) == "" and "TZ" not in os.environ, "taken out of config.yaml: gone at the restart")
        check(firstrun.apply_timezone({"timezone": "Mars/Olympus"}) == "bad" and "TZ" not in os.environ,
              "not a time zone: ignored (the start's log says so)")
        os.environ["TZ"] = "Europe/Berlin"
        check(firstrun.apply_timezone({"timezone": "Asia/Tokyo"}) == "env" and os.environ["TZ"] == "Europe/Berlin"
              and firstrun.env_tz() == "Europe/Berlin", "TZ in the environment wins")
        from lanowl import schema
        check(schema.env("TZ") == "Europe/Berlin", "...and locks the field in Settings")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        time.tzset()


def test_host_ip():
    print("\n-- lanowl's own address: found only when nothing set it --")
    c = {"observer": {"host_ip": "192.0.2.5"}}
    check(firstrun.fill_host_ip(c) == "" and c["observer"]["host_ip"] == "192.0.2.5" and "_host_ip_found" not in c,
          "set in config.yaml: left alone")
    c = {}
    ip = firstrun.fill_host_ip(c)
    check(ip == "" or (c["observer"]["host_ip"] == ip == c["_host_ip_found"] and ip.count(".") == 3
                       and not ip.startswith("127.")), "not set: the address this machine reaches the internet from")


def test_no_chat_no_outbox():
    print("\n-- before Telegram is set up, nothing waits for it --")
    import asyncio
    from lanowl import main as m
    from lanowl.agent import LlmAgent
    from lanowl.model import Inventory
    from lanowl.sinks import MqttBridge
    from lanowl.state import StateStore, StatusTracker
    from lanowl.tools import ToolExecutor
    sent = []

    async def fake_send(cfg, text, ids=None, **kw):
        sent.append(text)
        return False                      # a path that fails: the outbox's case

    async def go(d, chat):
        cfg = {"telegram": {"chat_id": chat, "outbox_file": os.path.join(d, "o.json")}}
        inv = Inventory(devices=[])
        st = StateStore(os.path.join(d, "s.sqlite"))
        mq = MqttBridge(cfg)
        ex = ToolExecutor(cfg, inv, mq, st)
        a = m.Auditor(cfg, inv, mq, st, StatusTracker(), ex, LlmAgent(cfg, ex))
        a._wan_raw_ok = True
        a._emit_telegram("digest", "the dashboard is closed until a password is set")
        await asyncio.sleep(0.05)
        return len(a.outbox.pending) if isinstance(a.outbox.pending, (list, tuple)) else a.outbox.pending

    real = m.telegram_direct
    m.telegram_direct = fake_send
    try:
        with tempfile.TemporaryDirectory() as d:
            none = asyncio.run(go(d, ""))
        tried = len(sent)
        with tempfile.TemporaryDirectory() as d:
            some = asyncio.run(go(d, "100000001"))
    finally:
        m.telegram_direct = real
    check(not none and tried == 0, "no chat yet: not sent, not queued for the chat the setup adds later")
    check(bool(some), "a chat whose path fails: queued, as before")


def test_answering_counted():
    print("\n-- an answer being written is counted (the restart sheet says so) --")
    import asyncio
    from lanowl.chat import Chat
    c = Chat.__new__(Chat)
    c.answering = 0
    seen = []

    async def fake(self, *a, **k):
        seen.append(self.answering)
        await asyncio.sleep(0)
        return "ok"
    real = Chat._answer
    Chat._answer = fake
    try:
        r = asyncio.run(c.answer("why?"))
    finally:
        Chat._answer = real
    check(r == "ok" and seen == [1] and c.answering == 0, "one while it is written, none after")


if __name__ == "__main__":
    for fn in [test_prepare, test_timezone, test_host_ip, test_no_chat_no_outbox, test_answering_counted]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all first-run tests passed")
