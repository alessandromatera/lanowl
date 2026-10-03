"""Backups of the machines: run with `python -m tests.test_backups`.

No device, no store, no Telegram — ssh, scp, the disk and the senders are fakes.
Pinned down here (backups.py):

  1. a MikroTik: its export (show-sensitive on RouterOS 7, byte for byte) and its binary
     backup, copied off with scp and ALWAYS deleted from the device;
  2. a failed backup leaves no half folder behind and says why;
  3. before an update: backed up first (and the homehub's VM snapshotted); no backup, no
     update — and the update's result says it was backed up;
  4. the last 6 monthly kept per machine, before-update ones 90 days; lanowl's own
     snapshots older than 7 days removed, nobody else's;
  5. Home Assistant: its own backup made, streamed, and removed on HA even if the copy fails;
  6. the store tars itself onto its own disk, without node_modules; tar's "files
     changed" is fine, a real failure is not;
  7. the 1st at 03:00; one message for a failed monthly run, one for backups gone stale;
  8. lanowl itself: its database (a whole SQLite copy, gzipped) and files, daily, the last
     7 dailies and 6 monthlies kept apart; a failing daily says so once, and once when back.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import backups as B
from tests.test_reboot import _auditor

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


CFG = {"enabled": True, "day": 1, "at": "03:00", "keep": 6, "keep_before_days": 90,
       "snapshot_days": 7, "store": {"host": "192.168.10.113", "path": "/srv/lanowl-backups", "group": "samba"},
       "machines": [{"ip": "192.168.10.32", "via": "routeros"}, {"ip": "192.168.10.104", "via": "homeassistant"},
                    {"ip": "192.168.10.113", "via": "store", "snapshot": "HomeHub"},
                    {"ip": "192.168.10.111", "via": "esxi"}, {"ip": "bogus", "via": "ftp"}]}


class _Disk:
    """The homehub's disk, faked: what was written, run and removed."""
    def __init__(self, bk):
        self.cmds, self.files = [], {}

        async def run(remote, timeout_s=60, stdin=None):
            self.cmds.append(remote)
            if remote.startswith("ls -1"):
                return 0, "\n".join(self.listing), ""
            return 0, "", ""

        async def mkdir(d):
            self.cmds.append(f"mkdir {d}")

        async def put_bytes(d, fname, data):
            self.files[f"{d}/{fname}"] = data
            return fname, len(data)

        async def put_stream(d, fname, argv, env=None, src_stdin=None, timeout_s=900, ok_rcs=(0,)):
            if self.stream_fail:
                raise B.BackupError(f"{fname}: the source failed (rc 1): boom")
            self.files[f"{d}/{fname}"] = ("stream", argv[-1], src_stdin)
            return fname, 12345
        self.listing, self.stream_fail = [], False
        bk._store_run, bk._mkdir, bk._put_bytes, bk._put_stream = run, mkdir, put_bytes, put_stream


def _setup(d):
    m, a = _auditor(d)
    a.cfg["backups"] = CFG
    a.backups = B.Backups(a)
    a.backups.a._persist_alerts = False
    sent = []
    a._emit_telegram = lambda ch, text, **kw: sent.append(text)
    return a, a.backups, _Disk(a.backups), sent


def test_routeros_and_failure():
    print("\n-- a MikroTik: export + binary backup, removed from the device; a failure leaves nothing --")
    out = {}

    async def go(d):
        a, bk, disk, _ = _setup(d)
        calls = []
        ver = ["6.49.22"]

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            calls.append((remote, raw))
            if remote == "/system resource print":
                return 0, f"uptime: 1h\n version: {ver[0]} (long-term)\n", ""
            if remote.startswith("/export"):
                return 0, "# sep/26/2026\n/interface bridge\nadd name=bridge-lan\n", ""
            if remote.startswith("/file print"):
                return 0, " 0 name=flash/lanowl-backup.backup type=backup size=40.5KiB\n", ""
            return 0, "", ""
        a.access.ssh = ssh
        scp_ok = [True]

        async def scp_get(ip, remote_path, local_path, timeout_s=60):
            out.setdefault("scp", []).append(remote_path)
            if not scp_ok[0]:
                return 1, "scp: connection lost"
            open(local_path, "wb").write(b"BINARY-BACKUP")
            return 0, ""
        a.access.scp_get = scp_get
        m = bk.machine("192.168.10.32")
        out["ok"] = await bk.backup(m, "manual")
        out["calls"], out["files"] = list(calls), dict(disk.files)
        calls.clear()
        ver[0] = "7.24.4"
        await bk.backup(m, "manual")
        out["v7"] = [c for c in calls if c[0].startswith("/export")]
        calls.clear()
        scp_ok[0] = False
        out["fail"] = await bk.backup(m, "monthly")
        out["fail_calls"], out["disk"] = list(calls), list(disk.cmds)
        out["rec"] = dict(bk.rec["machines"]["192.168.10.32"])
        out["skipped"] = [x["ip"] for x in bk.machines]
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    ok = out["ok"]
    check(ok["ok"] and ok["files"] == ["export.rsc", "system.backup"] and ok["size"] > 0,
          f"export.rsc and system.backup written ({ok.get('files')})")
    check(ok["dir"].startswith("/srv/lanowl-backups/ap-porch/") and ok["dir"].endswith("_manual"),
          f"under its machine, stamped and kinded ({ok['dir']})")
    check(("/export", True) in out["calls"], "RouterOS 6: /export, kept byte for byte (raw)")
    check(out["v7"] and out["v7"][0][0] == "/export show-sensitive", "RouterOS 7: /export show-sensitive")
    check(out["scp"][0] == "/flash/lanowl-backup.backup"
          and any(c[0].startswith('/file remove [find name="flash/lanowl-backup.backup"]') for c in out["calls"]),
          "the binary backup copied off with scp and deleted from the device")
    check(not out["fail"]["ok"] and "could not copy the binary backup" in out["fail"]["error"]
          and any(c[0].startswith("/file remove") for c in out["fail_calls"]),
          "scp failing: a failure — and the file is still deleted from the device")
    check(any(c.startswith("rm -rf ") and out["fail"]["dir"] in c for c in out["disk"]),
          "a failed backup's folder is removed: never a half backup")
    check(out["rec"]["ok"] is False and out["rec"].get("last_ok"), "the record: last try failed, last good kept")
    check("bogus" not in out["skipped"], "a machine with no known way is left out")


def test_before_update():
    print("\n-- before an update: backed up (and snapshotted) first; no backup, no update --")
    out = {}

    async def go(d):
        a, bk, disk, _ = _setup(d)
        res = {"192.168.10.32": True, "192.168.10.113": True}

        async def backup(m, kind):
            out.setdefault("kinds", []).append(kind)
            return {"ok": res[m["ip"]], "size": 2048, "error": "the device did not answer"}
        bk.backup = backup
        snaps = []

        async def snapshot(vm, replace=None):
            snaps.append(vm)
            return out.get("snap_ok", True), "lanowl-before-update-x"
        bk.snapshot = snapshot
        out["none"] = await bk.before_update("192.168.10.35")
        out["ap"] = await bk.before_update("192.168.10.32")
        out["hs"] = await bk.before_update("192.168.10.113")
        out["snaps"] = list(snaps)
        out["snap_ok"] = False
        out["hs_bad"] = await bk.before_update("192.168.10.113")
        res["192.168.10.32"] = False
        out["ap_bad"] = await bk.before_update("192.168.10.32")
        # through the action: routeros_upgrade refused when its backup fails
        a.cfg["actions"]["catalog"]["routeros_upgrade"] = {"hosts": {"192.168.10.32": {}}}
        p = {"id": 1, "action": "routeros_upgrade", "ip": "192.168.10.32", "name": "AP-Porch"}
        ran = []

        async def ros_run(ip, name, chk):
            ran.append(ip)
            return {"ok": True, "ran": True, "result": "RouterOS 6.49.21 → 6.49.22"}
        a.updates.ros_upgrade_run = ros_run
        out["refused"] = await a.actions._run(p, {})
        res["192.168.10.32"] = True
        out["done"] = await a.actions._run(p, {})
        out["ran"] = ran
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["none"] == (True, ""), "a machine without a backup configured: nothing to do")
    check(out["ap"] == (True, "backed up first (2.0 KB)") and out["kinds"][0] == "before-update",
          "backed up first, as a before-update backup")
    check(out["hs"][0] and "VM snapshot taken" in out["hs"][1] and out["snaps"] == ["HomeHub"],
          "the homehub: its VM snapshotted too")
    check(not out["hs_bad"][0] and "snapshot failed" in out["hs_bad"][1], "no snapshot: no update")
    check(not out["ap_bad"][0] and "the backup failed" in out["ap_bad"][1], "no backup: no update")
    r = out["refused"]
    check(not r["ok"] and not r["ran"] and r["error"].startswith("nothing was updated — the backup failed"),
          "the action refuses to update, and says why")
    check(out["ran"] == ["192.168.10.32"] and out["done"]["result"].endswith("· backed up first (2.0 KB)"),
          "with the backup: it updates, and the result says it was backed up")


def test_keeping_and_snapshots():
    print("\n-- the last 6 monthly; before-update 90 days; lanowl's own snapshots after 7 days --")
    out = {}

    async def go(d):
        a, bk, disk, _ = _setup(d)
        now = time.time()
        stamp = lambda days: time.strftime("%Y-%m-%d_%H%M", time.localtime(now - days * 86400))
        disk.listing = ([f"{stamp(30 * i)}_monthly" for i in range(8)] + [f"{stamp(1)}_manual"]
                        + [f"{stamp(100)}_before-update", f"{stamp(10)}_before-update", "notes.txt"])
        await bk._prune(bk.machine("192.168.10.32"))
        out["rm"] = [c for c in disk.cmds if c.startswith("rm -rf")]
        out["listing"] = list(disk.listing)
        rm = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            if "snapshot.get" in remote:
                return 0, ("VMID=6\nGet Snapshot:\n|-ROOT\n"
                           f"--Snapshot Name        : lanowl-before-update-{stamp(9)}\n--Snapshot Id        : 3\n"
                           f"--Snapshot Name        : lanowl-before-update-{stamp(2)}\n--Snapshot Id        : 4\n"
                           "--Snapshot Name        : before-os-upgrade\n--Snapshot Id        : 1\n"), ""
            rm.append(remote)
            return 0, "", ""
        a.access.ssh = ssh
        await bk.prune_snapshots()
        out["snap_rm"] = rm
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    l = out["listing"]
    gone = out["rm"][0] if out["rm"] else ""
    monthly = sorted(n for n in l if n.endswith(("_monthly", "_manual")))
    check(all(n in gone for n in monthly[:3]) and not any(n in gone for n in monthly[3:]),
          "monthly and manual: the newest 6 kept, the 3 oldest removed")
    before = sorted(n for n in l if n.endswith("_before-update"))
    check(before[0] in gone and before[1] not in gone, "before-update: kept 90 days")
    check("notes.txt" not in gone, "anything it did not make is never touched")
    check(out["snap_rm"] == ["vim-cmd vmsvc/snapshot.remove 6 3"],
          "only its own snapshot older than 7 days is removed — not the owner's")


def test_home_assistant_and_homehub():
    print("\n-- Home Assistant: its own backup, streamed, removed on HA; the homehub tars itself --")
    out = {}

    async def go(d):
        a, bk, disk, _ = _setup(d)
        calls = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            calls.append((ip, remote, sudo_pw))
            if "ha backups new" in remote:
                return 0, '{"result":"ok","data":{"slug":"9f1c2b3a"}}', ""
            if remote.startswith("find /backup"):
                return 0, "/backup/lanowl_2026-09-26_1600_9f1c2b3a.tar\n", ""
            if "tar czf" in remote:
                return 0, out.get("tar_out", "RC=1\n48213000\n"), ""
            return 0, "", ""
        a.access.ssh = ssh
        a.access.command = lambda ip, remote, user_suffix="": (["ssh", ip, remote], {}, None)
        ha = bk.machine("192.168.10.104")
        out["ha"] = await bk.backup(ha, "manual")
        out["ha_calls"] = [c[1] for c in calls]
        out["ha_file"] = [v for k, v in disk.files.items() if k.endswith("home-assistant.tar")]
        calls.clear()
        disk.stream_fail = True
        out["ha_fail"] = await bk.backup(ha, "manual")
        out["ha_fail_calls"] = [c[1] for c in calls]
        disk.stream_fail = False
        calls.clear()
        hs = bk.machine("192.168.10.113")
        out["hs"] = await bk.backup(hs, "monthly")
        out["hs_call"] = calls[-1]
        out["tar_out"] = "RC=2\n0\n"
        out["hs_bad"] = await bk.backup(hs, "monthly")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["ha"]["ok"] and out["ha"]["files"] == ["home-assistant.tar"]
          and out["ha_file"][0][1] == "cat /backup/lanowl_2026-09-26_1600_9f1c2b3a.tar",
          "HA: made with ha backups new, the new file streamed across")
    check(any(c.startswith("ha backups remove 9f1c2b3a") for c in out["ha_calls"])
          and not any("automatic" in c for c in out["ha_calls"]),
          "...and its own copy removed on HA (HA's automatic ones untouched)")
    check(not out["ha_fail"]["ok"] and any(c.startswith("ha backups remove 9f1c2b3a") for c in out["ha_fail_calls"]),
          "the copy failing: still removed on HA")
    ip, remote, sudo_pw = out["hs_call"]
    check(sudo_pw and remote.startswith("sudo -S -p '' sh -c") and "--exclude=node_modules" in remote
          and "/srv/lanowl-backups/vm-homehub/" in remote and "chgrp -R samba" in remote,
          "the store: tar through sudo, straight onto its own disk, no node_modules, its group")
    check(out["hs"]["ok"] and out["hs"]["size"] == 48213000, "tar's 'files changed while reading' (1) is fine")
    check(not out["hs_bad"]["ok"] and "tar on the store failed" in out["hs_bad"]["error"], "a real tar failure is not")


def test_schedule_and_messages():
    print("\n-- the 1st at 03:00; one message for a failed monthly run, one for stale backups --")
    out = {}

    async def go(d):
        a, bk, disk, sent = _setup(d)
        lt = time.localtime()
        first = time.mktime((lt.tm_year, lt.tm_mon, 1, 3, 30, 0, 0, 0, -1))
        out["due"] = [bk.due(first - 3600), bk.due(first)]
        bk.rec["last_run"] = first
        out["due"].append(bk.due(first + 60))

        async def backup(m, kind):
            return {"ok": m["ip"] != "192.168.10.104", "error": "Home Assistant did not answer", "size": 1}
        bk.backup = backup
        await bk._run(bk.machines, "monthly")
        await bk._run(bk.machines, "manual")
        out["sent_run"] = list(sent)
        sent.clear()
        bk.rec["machines"] = {"192.168.10.32": {"last_ok": time.time() - 70 * 86400},
                              "192.168.10.111": {"last_ok": time.time() - 3 * 86400}}

        async def nothing():
            return None
        bk.prune_snapshots = nothing
        await bk._daily()
        await bk._daily()
        out["sent_stale"] = list(sent)
        out["text"] = bk.text()
        out["next"] = time.localtime(bk.next_run())
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    check(out["due"] == [False, True, False], "due on the 1st after 03:00, once")
    check(len(out["sent_run"]) == 1 and "Monthly backup</b> — 1 of 4 failed" in out["sent_run"][0]
          and "Home Assistant did not answer" in out["sent_run"][0],
          "a failed monthly run: one message naming what failed; a manual run: none")
    check(len(out["sent_stale"]) == 1 and "Mikrotik AP-Porch" not in out["sent_stale"][0]
          and "AP-Porch" in out["sent_stale"][0] and "ESXI" not in out["sent_stale"][0],
          "two months without a good backup: one message, once")
    check("Backups" in out["text"] and "never" in out["text"], "/backups lists every machine")
    check(out["next"].tm_mday == 1 and out["next"].tm_hour == 3, "the next run: a 1st, at 03:00")


def test_the_auditor_itself():
    """lanowl backs itself up too: its volume and its config."""
    print("\n-- lanowl itself: its database and files, daily, the dailies pruned apart --")
    out = {}

    async def go(d):
        a, bk, disk, sent = _setup(d)
        bk.machines.append({"ip": "192.168.10.95", "via": "lanowl", "name": "VM monitor", "daily": 7})
        a.state.record_event("finding", None, "{}")         # something in the database
        streamed = []

        async def put_stream(dd, fname, argv, env=None, src_stdin=None, timeout_s=900, ok_rcs=(0,)):
            if fname.endswith(".gz"):
                import gzip, sqlite3, subprocess
                data = subprocess.run(argv, capture_output=True).stdout      # gzip -c the copy
                raw = gzip.decompress(data)
                tmp = os.path.join(d, "restored.sqlite")
                open(tmp, "wb").write(raw)
                out["events"] = sqlite3.connect(tmp).execute("select count(*) from events").fetchone()[0]
            streamed.append((fname, argv))
            return fname, 100
        bk._put_stream = put_stream
        m = bk.machine("192.168.10.95")
        res = await bk.backup(m, "daily")
        out["res"], out["streamed"] = res, streamed
        out["note"] = next((v for k, v in disk.files.items() if k.endswith("state.txt")), b"").decode()
        out["tmp_left"] = [f for f in os.listdir(tempfile.gettempdir()) if f.startswith("lanowl-backup-")]
        # pruning: 9 dailies and 8 monthlies — 7 dailies and 6 monthlies stay
        now = time.time()
        stamp = lambda days: time.strftime("%Y-%m-%d_%H%M", time.localtime(now - days * 86400))
        disk.listing = [f"{stamp(i)}_daily" for i in range(1, 10)] + [f"{stamp(30 * i)}_monthly" for i in range(1, 9)]
        disk.cmds.clear()
        await bk._prune(m)
        out["gone"] = next((c for c in disk.cmds if c.startswith("rm -rf")), "")
        out["listing"] = list(disk.listing)
        # the daily schedule: at 03:00, not on the monthly day; one message when it fails, one when back
        lt = time.localtime()
        day2 = time.mktime((lt.tm_year, lt.tm_mon, 2, 3, 30, 0, 0, 0, -1))
        day1 = time.mktime((lt.tm_year, lt.tm_mon, 1, 3, 30, 0, 0, 0, -1))
        out["due"] = [bk._self_due(day2 - 3600), bk._self_due(day2), bk._self_due(day1)]
        results = iter([False, False, True])

        async def backup(mm, kind):
            ok = next(results)
            return {"ok": ok, "error": "the homehub did not answer", "size": 1}
        bk.backup = backup
        for _ in range(3):
            await bk._run([m], "daily")
        out["sent"] = list(sent)
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    r = out["res"]
    check(r["ok"] and r["files"] == ["lanowl_state.sqlite.gz", "lanowl-files.tgz", "state.txt"],
          f"the database, the files, a note ({r.get('files') or r.get('error')})")
    check(out["events"] == 1, "the database copy is whole and readable (SQLite's own backup)")
    tar = next(a for f, a in out["streamed"] if f == "lanowl-files.tgz")
    check(tar[:3] == ["tar", "czf", "-"] and all(os.path.exists(x) for x in tar[3:]),
          "the files: only those that exist in this container")
    check("restore" in out["note"] and "NOT encrypted" in out["note"], "the note says how to restore, and that it is clear")
    check(out["tmp_left"] == [], "the temporary copy is removed")
    l, gone = out["listing"], out["gone"]
    dailies, monthlies = sorted(n for n in l if n.endswith("_daily")), sorted(n for n in l if n.endswith("_monthly"))
    check(all(n in gone for n in dailies[:2]) and not any(n in gone for n in dailies[2:]), "the last 7 dailies kept")
    check(all(n in gone for n in monthlies[:2]) and not any(n in gone for n in monthlies[2:]),
          "the last 6 monthlies kept — the dailies do not crowd them out")
    check(out["due"] == [False, True, False], "daily at 03:00 — not on the monthly day")
    check(len(out["sent"]) == 2 and "Daily backup" in out["sent"][0] and "works again" in out["sent"][1],
          "one message when it starts failing, one when it works again — not every day")


def test_snapshot_replaced_only_when_approved():
    print("\n-- an older snapshot: named on the approval, replaced only then; someone else's is kept --")
    out = {}
    listing = ("Get Snapshot:\n|-ROOT\n--Snapshot Name        : lanowl-before-update-2026-09-26_1607\n"
               "--Snapshot Id        : 2\n--Snapshot Desciption  : taken by lanowl\n"
               "--Snapshot Created On  : 9/26/2026 14:7:10\n--Snapshot State       : powered on\n"
               "--|-CHILD\n----Snapshot Name        : before-os-upgrade\n----Snapshot Id        : 3\n"
               "----Snapshot Desciption  : \n----Snapshot Created On  : 9/20/2026 10:0:0\n")

    async def go(d):
        a, bk, disk, _ = _setup(d)
        calls = []

        async def ssh(ip, remote, stdin=None, timeout_s=20, user_suffix="", tty=False, sudo_pw=False, raw=False):
            calls.append(remote)
            if "snapshot.create" in remote:
                name = remote.split("snapshot.create $id ")[1].split()[0]
                return 0, listing + f"--Snapshot Name : {name}\n", ""
            if "snapshot.get" in remote:
                return 0, listing, ""
            return 0, "", ""
        a.access.ssh = ssh
        out["snaps"] = await bk.snapshots("HomeHub")
        out["plan"] = await bk.snapshot_plan("192.168.10.113")
        out["none"] = await bk.snapshot_plan("192.168.10.32")
        out["ok"] = await bk.snapshot("HomeHub", ["lanowl-before-update-2026-09-26_1607", "before-os-upgrade"])
        out["calls"] = calls
        # the update's check puts them on the approval
        a.cfg["actions"]["catalog"]["apt_upgrade"] = {"hosts": {"192.168.10.113": {"via": "password"}}}

        async def remote(ip, cmd, timeout_s, root_cmd=False):
            return 0, "OS=Ubuntu\nUPG=vim/noble-updates 2 amd64 [upgradable from: 1]\n", ""
        a.updates._remote = remote
        out["chk"] = await a.updates.upgrade_check("192.168.10.113", "VM HomeHub")
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(go(d))
    sn = out["snaps"]
    check([(x["name"], x["id"], x["mine"]) for x in sn] == [("lanowl-before-update-2026-09-26_1607", "2", True),
                                                           ("before-os-upgrade", "3", False)],
          "the VM's snapshots read, lanowl's own told apart")
    check(out["plan"] == {"vm": "HomeHub", "replace": ["lanowl-before-update-2026-09-26_1607"],
                          "keep": ["before-os-upgrade"]} and out["none"] is None,
          "the plan: replace lanowl's, keep anyone else's; no plan without a snapshot configured")
    removes = [c for c in out["calls"] if "snapshot.remove" in c]
    check(out["ok"][0] and len(removes) == 1 and removes[0].endswith("snapshot.remove $id 2"),
          "approved: lanowl's older one removed (never the owner's), then the new one taken")
    risk = out["chk"].get("risk") or []
    check(any("approving REMOVES it" in r and "2026-09-26_1607" in r for r in risk)
          and any("before-os-upgrade" in r and "kept" in r for r in risk)
          and out["chk"]["snap_replace"] == ["lanowl-before-update-2026-09-26_1607"],
          "the approval names both: which one goes, which one stays")


if __name__ == "__main__":
    for fn in [test_routeros_and_failure, test_before_update, test_keeping_and_snapshots,
               test_home_assistant_and_homehub, test_schedule_and_messages,
               test_snapshot_replaced_only_when_approved, test_the_auditor_itself]:
        fn()
    print()
    if _fails:
        print(f"{len(_fails)} FAILED")
        sys.exit(1)
    print("all passed")
