"""Backups of the network's machines, onto a disk of the owner's.

  - what: every machine listed under `backups.machines`, each with the way it is taken (`via`);
  - where: `backups.store` — a Linux host lanowl logs into by its ssh key (a hostlog host), and
    a path on it. A disk of its own is best: not the datastore the VMs it backs up live on;
  - when: day `day` of every month at `at` (the last `keep` kept per machine), and before every
    update (kept `keep_before_days`) — the update is refused if its backup fails; before an apt
    update of a VM on an ESXi host, also a snapshot of the VM, removed after `snapshot_days`;
  - alerts: one Telegram message when a monthly run had a failure, or when a machine has had
    no good backup for two months; the rest is on the Security tab and /backups;
  - Home Assistant: lanowl makes a full backup of its own, copies it across and deletes it on
    HA. HA's own automatic backups are never touched.

NOT ENCRYPTED: these files hold the network's passwords and keys in the clear, readable by
anyone who can read the store's path. Keep that path as private as secrets.yaml.

Layout:   <path>/<machine>/<YYYY-MM-DD_HHMM>_<monthly|before-update|manual|daily>/<files>

How each one is taken (`via`):
    routeros       /export (show-sensitive on RouterOS 7) + a binary /system backup, copied
                   off with scp and deleted from the device (small APs have ~3 MB of flash free)
    homeassistant  `ha backups new` over ssh, streamed across, then `ha backups remove`
    vps            a server reached by lanowl's ssh KEY: its configuration files as one tar
                   (`paths`, or VPS_PATHS), + a state.txt — as root (sudo when the key's user
                   is not root)
    store          the store host itself: `paths` (or STORE_PATHS) tarred ON it, straight onto
                   its own disk — nothing crosses the network
    files          a few paths as a tar, with the machine's login from secrets.yaml
    esxi           the host's configuration bundle + every VM's .vmx
    shellies       every Shelly's settings, scripts, schedules and webhooks, one JSON
    profile        a kind of the owner's own (kinds.py): its profile's `backup` command, its
                   output streamed into one file
    lanowl         lanowl ITSELF: a consistent copy of its database (SQLite's own backup,
                   while it runs), gzipped — history, logbook, memory, actions, conversations,
                   dismissals, Known and Watched, pauses, the update and review records — and a
                   tar of its secrets, its ssh known_hosts and the config it runs with. DAILY
                   at `at`, the last `daily` kept, besides the monthly ones with the others
Everything else streams source → lanowl → `ssh <store> 'cat > file'`, written as .part and
renamed when complete, so a file that is there is whole.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import shlex
import tempfile
import time
from typing import Optional

from . import access
from .checks import _exec
from .reboot import routeros_field
from .report import _html, label

log = logging.getLogger("lanowl.backups")

RECORD = "backups"
VIAS = ("routeros", "homeassistant", "vps", "store", "files", "esxi", "shellies", "lanowl",
        "profile")
KINDS = ("monthly", "before-update", "manual")
_DIR = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{4})_(monthly|before-update|manual|daily)$")
STALE_S = 62 * 86400               # no good backup for two months: worth a message
Q = shlex.quote


def lanowl_files(a) -> list:
    """lanowl's own files, wherever its config puts them, those that exist: config.yaml,
    the inventory, secrets.yaml, the profiles folder, its ssh key and the known hosts."""
    cfg = a.cfg
    key = access.ssh_key(cfg)               # none named: ssh's own, which lanowl does not own
    out = []
    for p in [cfg.get("_path"), getattr(a.inv, "path", ""), access.secrets_path(cfg),
              (cfg.get("profiles") or {}).get("dir"), key, key and key + ".pub",
              a.access.known_hosts, os.path.expanduser("~/.ssh/known_hosts")]:
        p = os.path.abspath(str(p)) if p else ""
        if p and os.path.exists(p) and p not in out:
            out.append(p)
    return out


# a server's configuration (`via: vps`), unless the machine lists its own `paths`
VPS_PATHS = (
    "etc/wireguard etc/rc.local etc/ssh/sshd_config etc/ssh/sshd_config.d "
    "etc/ssh/ssh_host_ed25519_key etc/ssh/ssh_host_ed25519_key.pub etc/ssh/ssh_host_rsa_key "
    "etc/ssh/ssh_host_rsa_key.pub etc/ssh/ssh_host_ecdsa_key etc/ssh/ssh_host_ecdsa_key.pub "
    "root/.ssh root/.bashrc root/.profile etc/sysctl.conf etc/sysctl.d etc/systemd/network "
    "etc/netplan etc/hostname etc/hosts etc/fstab etc/apt/sources.list etc/apt/sources.list.d "
    "etc/apt/apt.conf.d/20auto-upgrades etc/apt/apt.conf.d/50unattended-upgrades "
    "etc/cloud/cloud.cfg etc/cloud/cloud.cfg.d etc/systemd/system etc/default/ufw etc/ufw "
    "etc/iptables var/spool/cron/crontabs etc/cron.d etc/crontab etc/logrotate.d etc/rsyslog.d")
VPS_STATE = ("echo '# wg'; wg show 2>&1; echo '# addresses'; ip -br a; echo '# routes'; ip route; "
             "echo '# firewall'; iptables-save; "
             "echo '# packages'; dpkg-query -W -f '${Package} ${Version}\\n'")
# the store host's own files (`via: store`), unless the machine lists its own `paths`
STORE_PATHS = "etc home root var/spool/cron opt usr/local"
STORE_TAR = ("tar czf {out} --ignore-failed-read --warning=no-file-changed "
             "--exclude=node_modules --exclude='home/*/.cache' "
             "--exclude='home/*/.npm' --exclude='*.log' -C / {paths}")


class BackupError(Exception):
    pass


def slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", name or "").strip("-").lower()[:48] or "machine"


def _last(text: str) -> str:
    return ((text or "").strip().splitlines() or [""])[-1][:160]


def human_size(n: Optional[int]) -> str:
    if not n:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def report(cfg: dict, inv, acc) -> tuple:
    """(text, problems) for `lanowl --check`, and so for a Settings save: backups switched on
    with a store lanowl cannot write to fail at their first run — said here instead. Nothing
    at all while backups are off, or when the store is reachable."""
    c = (cfg or {}).get("backups") or {}
    if not isinstance(c, dict) or not c.get("enabled"):
        return "", 0
    host = str((c.get("store") or {}).get("host") or "") if isinstance(c.get("store"), dict) else ""
    if not host:
        why = "backups are on, and no machine keeps them: backups.store.host is empty"
    elif inv.get(host) is None:
        why = (f"backups.store.host {host} is not one of your devices: add it, with a login by "
               "lanowl's ssh key — the backups are written over that login")
    elif not acc.by_key(host):
        why = (f"lanowl has no login with its ssh key to the store {host}: give that device a login "
               "with lanowl's key — the backups are written over it")
    else:
        return "", 0
    return f"Backups:\n  ✗ {why}", 1


class Backups:
    def __init__(self, auditor):
        self.a = auditor
        c = auditor.cfg.get("backups") or {}
        self.enabled = bool(c.get("enabled", False))
        self.day = int(c.get("day", 1))
        self.at = str(c.get("at", "03:00"))
        self.keep = int(c.get("keep", 6))
        self.keep_before_s = float(c.get("keep_before_days", 90)) * 86400
        self.snapshot_s = float(c.get("snapshot_days", 7)) * 86400
        st = c.get("store") or {}
        self.store_ip = str(st.get("host") or "")
        self.base = str(st.get("path") or "/srv/lanowl-backups").rstrip("/")
        self.share = str(st.get("share") or "")          # how the owner reaches it (shown only)
        self.group = str(st.get("group") or "")          # chgrp'd, setgid, if set (a Samba share's)
        self.machines = []
        for m in c.get("machines") or []:
            m = dict(m or {})
            if m.get("via") in VIAS and (m.get("ip") or m.get("via") == "shellies"):
                m.setdefault("ip", "shellies")
                self.machines.append(m)
            else:
                log.warning("backups: %r has no known way to be backed up — left out", m)
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()          # one backup at a time, scheduled or before an update
        self.current = ""                    # the machine being backed up now, for the page
        try:
            self.rec = auditor.state.load_record(RECORD) or {}
        except Exception:
            log.warning("backups: record unreadable, starting empty", exc_info=True)
            self.rec = {}
        for k, dflt in (("machines", {}), ("announced", []), ("last_run", 0.0), ("last_daily", 0.0),
                        ("last_self", 0.0)):
            self.rec.setdefault(k, dflt)

    def _save(self):
        if not self.a._persist_alerts:
            return
        try:
            self.a.state.save_record(RECORD, self.rec)
        except Exception as e:
            log.warning("backups: record not saved: %s", e)

    # --- who is who ------------------------------------------------------------
    def name(self, m: dict) -> str:
        if m.get("name"):
            return str(m["name"])
        if m["via"] == "shellies":
            return "Shellies"
        dev = self.a.inv.get(m["ip"])
        return dev.name if dev else m["ip"]

    def machine(self, ip: str) -> Optional[dict]:
        return next((m for m in self.machines if m["ip"] == ip), None)

    def covers(self, ip: str) -> bool:
        return self.enabled and self.machine(ip) is not None

    # --- the store's disk --------------------------------------------------------
    def _store_argv(self, remote: str) -> list:
        if not self.store_ip:
            raise BackupError("no backups.store.host configured")
        hl = self.a.hostlog
        h = next((x for x in (getattr(hl, "hosts", None) or []) if x.ip == self.store_ip), None)
        if h is None:
            raise BackupError(f"lanowl has no ssh login to the store {self.store_ip}")
        return hl._ssh_argv(h, remote)

    async def _store_run(self, remote: str, timeout_s: float = 60,
                         stdin: Optional[bytes] = None) -> tuple:
        return await _exec(self._store_argv(remote), timeout_s, stdin=stdin)

    def _dest(self, m: dict, kind: str, stamp: str) -> str:
        return f"{self.base}/{slug(self.name(m))}/{stamp}_{kind}"

    async def _mkdir(self, d: str):
        # the share's group, setgid, if one is set: everything below stays readable through it
        grp = (f"chgrp {Q(self.group)} {Q(self.base)} 2>/dev/null; chmod 2770 {Q(self.base)} "
               "2>/dev/null; ") if self.group else ""
        rc, _, err = await self._store_run(
            f"umask 007; mkdir -p {Q(self.base)} && {grp}mkdir -p {Q(d)}")
        if rc != 0:
            raise BackupError(f"cannot create {d} on the store: {_last(err)}")

    async def _put_bytes(self, d: str, fname: str, data: bytes) -> tuple:
        f = f"{d}/{fname}"
        rc, out, err = await self._store_run(
            f"umask 007; cat > {Q(f + '.part')} && mv {Q(f + '.part')} {Q(f)} && stat -c %s {Q(f)}",
            120, stdin=data)
        if rc != 0:
            raise BackupError(f"writing {fname} on the store failed: {_last(err)}")
        return fname, int((out or "0").split()[0]) if (out or "").strip().isdigit() else len(data)

    async def _put_stream(self, d: str, fname: str, src_argv: list, src_env: Optional[dict] = None,
                          src_stdin: Optional[bytes] = None, timeout_s: float = 900,
                          ok_rcs=(0,)) -> tuple:
        """Stream a program's stdout into a file on the store, without holding it here:
        a Home Assistant backup is a few hundred MB."""
        f = f"{d}/{fname}"
        dst_argv = self._store_argv(
            f"umask 007; cat > {Q(f + '.part')} && mv {Q(f + '.part')} {Q(f)} && stat -c %s {Q(f)}")
        r, w = os.pipe()
        try:
            src = await asyncio.create_subprocess_exec(
                *src_argv, stdin=asyncio.subprocess.PIPE if src_stdin else asyncio.subprocess.DEVNULL,
                stdout=w, stderr=asyncio.subprocess.PIPE, env=src_env)
            dst = await asyncio.create_subprocess_exec(
                *dst_argv, stdin=r, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        finally:
            os.close(r)
            os.close(w)
        try:
            if src_stdin:
                src.stdin.write(src_stdin)
                await src.stdin.drain()
                src.stdin.close()
            (s_out, s_err), (d_out, d_err) = await asyncio.wait_for(
                asyncio.gather(src.communicate(), dst.communicate()), timeout_s)
        except asyncio.TimeoutError:
            for p in (src, dst):
                with contextlib.suppress(ProcessLookupError):
                    p.kill()
            raise BackupError(f"{fname}: not finished in {timeout_s:.0f} s")
        if src.returncode not in ok_rcs:
            raise BackupError(f"{fname}: the source failed (rc {src.returncode}): "
                              f"{_last(s_err.decode(errors='replace'))}")
        if dst.returncode != 0:
            raise BackupError(f"writing {fname} on the store failed: "
                              f"{_last(d_err.decode(errors='replace'))}")
        out = d_out.decode(errors="replace").split()
        return fname, int(out[0]) if out and out[0].isdigit() else 0

    # --- one machine ------------------------------------------------------------------
    async def backup(self, m: dict, kind: str) -> dict:
        """Back up one machine now. {"ok", "error", "dir", "size", "files"}."""
        async with self._lock:
            self.current = self.name(m)
            t0 = time.time()
            stamp = time.strftime("%Y-%m-%d_%H%M", time.localtime(t0))
            d = self._dest(m, kind, stamp)
            res = {"ok": False, "dir": d, "kind": kind, "ts": t0}
            try:
                await self._mkdir(d)
                files = await getattr(self, "_" + m["via"])(m, d, stamp)
                res.update(ok=True, files=[f for f, _ in files], size=sum(s for _, s in files))
            except BackupError as e:
                res["error"] = str(e)
            except Exception as e:
                log.exception("backups: %s failed", self.name(m))
                res["error"] = f"{type(e).__name__}: {e}"[:200]
            finally:
                self.current = ""
            if not res["ok"]:
                with contextlib.suppress(Exception):
                    await self._store_run(f"rm -rf {Q(d)}")      # never a half backup
            res["secs"] = round(time.time() - t0)
            r = self.rec["machines"].setdefault(m["ip"], {})
            r.update(last_try=t0, ok=res["ok"], error=res.get("error", ""), kind=kind)
            if res["ok"]:
                r.update(last_ok=t0, size=res["size"], dir=d, files=res["files"])
                with contextlib.suppress(Exception):
                    await self._prune(m)
            self._save()
            (log.info if res["ok"] else log.warning)(
                "backups: %s (%s) %s in %ss%s", self.name(m), kind,
                "done" if res["ok"] else "FAILED", res["secs"],
                f" — {human_size(res.get('size'))} in {d}" if res["ok"] else f": {res.get('error')}")
            return res

    async def _routeros(self, m, d, stamp) -> list:
        A, ip = self.a.access, m["ip"]
        rc, out, err = await A.ssh(ip, "/system resource print", user_suffix="+ct", timeout_s=20)
        if rc != 0 or "version" not in out:
            raise BackupError(f"cannot log in: {_last(err) or 'no answer'}")
        v7 = (re.findall(r"\d+", routeros_field(out, "version")) or ["0"])[0] >= "7"
        rc, exp, err = await A.ssh(ip, "/export show-sensitive" if v7 else "/export",
                                   user_suffix="+ct", timeout_s=120, raw=True)
        if rc != 0 or "/" not in exp:
            raise BackupError(f"the configuration export failed: {_last(err) or 'empty'}")
        files = [await self._put_bytes(d, "export.rsc", exp.encode())]
        # the binary backup: saved on the device, copied off, deleted there — whatever happens
        await A.ssh(ip, "/system backup save name=lanowl-backup dont-encrypt=yes",
                    user_suffix="+ct", timeout_s=90)
        rc, out, _ = await A.ssh(ip, '/file print terse without-paging where name~"lanowl-backup"',
                                 user_suffix="+ct", timeout_s=20)
        found = re.search(r"name=(\S*lanowl-backup\.backup)", out or "")
        if not found:
            raise BackupError("the device did not save its binary backup")
        path = found.group(1)
        fd, tmp = tempfile.mkstemp(suffix=".backup")
        os.close(fd)
        try:
            rc, err = await A.scp_get(ip, "/" + path, tmp)
            data = open(tmp, "rb").read() if rc == 0 else None
        finally:
            os.remove(tmp)
            await A.ssh(ip, f'/file remove [find name="{path}"]', user_suffix="+ct", timeout_s=20)
        if not data:
            raise BackupError(f"could not copy the binary backup off the device: {_last(err)}")
        files.append(await self._put_bytes(d, "system.backup", data))
        return files

    async def _homeassistant(self, m, d, stamp) -> list:
        A, ip = self.a.access, m["ip"]
        rc, out, err = await A.ssh(
            ip, f"touch /tmp/lanowl-mark && ha backups new --name lanowl-{stamp} --raw-json",
            timeout_s=1200)
        try:
            bslug = json.loads(out)["data"]["slug"]
        except (ValueError, KeyError, TypeError):
            raise BackupError(f"Home Assistant did not make the backup: {_last(out or err)}")
        try:
            rc, out, err = await A.ssh(
                ip, "find /backup -maxdepth 1 -name '*.tar' -newer /tmp/lanowl-mark", timeout_s=20)
            cands = [x for x in (out or "").split() if x.endswith(".tar")]
            path = next((x for x in cands if bslug in x or "lanowl" in x), cands[0] if cands else "")
            if not path:
                raise BackupError("the new backup file was not found in /backup")
            cmd = A.command(ip, f"cat {Q(path)}")
            return [await self._put_stream(d, "home-assistant.tar", cmd[0], cmd[1],
                                           timeout_s=1800)]
        finally:
            # lanowl's own copy on HA goes; HA's automatic backups are never touched
            await A.ssh(ip, f"ha backups remove {Q(bslug)}; rm -f /tmp/lanowl-mark", timeout_s=60)

    async def _vps(self, m, d, stamp) -> list:
        hl = self.a.hostlog
        h = next((x for x in hl.hosts if x.ip == m["ip"]), None)
        if h is None:
            raise BackupError(f"lanowl has no ssh login to {m['ip']}")
        paths = " ".join(Q(p.lstrip("/")) for p in m.get("paths") or []) or VPS_PATHS
        tar = (f"for p in {paths}; do [ -e \"/$p\" ] && echo \"$p\"; done "
               "| tar czf - -C / -T -")
        pw = None
        if h.user != "root":                 # ssh host keys and root's files: as root
            lg = self.a.access.login(m["ip"])
            if lg is not None and lg.password:
                tar, pw = "sudo -S -p '' sh -c " + Q(tar), (lg.password + "\n").encode()
            else:
                tar = "sudo -n sh -c " + Q(tar)
        files = [await self._put_stream(d, "vps-files.tgz", hl._ssh_argv(h, tar), src_stdin=pw,
                                        timeout_s=300)]
        rc, out, _ = await self.a.actions._ssh_run(m["ip"], VPS_STATE, 60, root=True)
        if rc == 0:
            files.append(await self._put_bytes(d, "state.txt", out.encode()))
        return files

    async def _store(self, m, d, stamp) -> list:
        # tarred where it lives, onto its own disk: nothing crosses the network
        fname = f"{slug(self.name(m))}.tgz"
        out_f = f"{d}/{fname}"
        paths = " ".join(Q(p.lstrip("/")) for p in m.get("paths") or []) or STORE_PATHS
        grp = f"chgrp -R {Q(self.group)} {Q(d)}; " if self.group else ""
        script = (f"umask 007; {STORE_TAR.format(out=Q(out_f), paths=paths)} 2>/tmp/lanowl-tar.err; "
                  f"rc=$?; {grp}echo RC=$rc; stat -c %s {Q(out_f)}")
        if self.a.access.by_key(m["ip"]):
            rc, out, err = await self.a.actions._ssh_run(m["ip"], script, 1800, root=True)
        else:
            rc, out, err = await self.a.access.ssh(m["ip"], "sudo -S -p '' sh -c " + Q(script),
                                                   sudo_pw=True, timeout_s=1800)
        rcm = re.search(r"RC=(\d+)", out or "")
        if rc is None or not rcm or rcm.group(1) not in ("0", "1"):      # 1 = files changed
            raise BackupError(f"tar on the store failed: {_last(err) or (rcm and 'rc ' + rcm.group(1))}")
        size = (out or "").strip().splitlines()[-1]
        return [(fname, int(size) if size.isdigit() else 0)]

    async def _files(self, m, d, stamp) -> list:
        paths = " ".join(Q(p) for p in m.get("paths") or [])
        if not paths:
            raise BackupError("no paths configured")
        tar = f"tar czf - --ignore-failed-read {paths} 2>/dev/null"
        if m.get("sudo"):
            tar = "sudo -S -p '' sh -c " + Q(tar)
        cmd = self.a.access.command(m["ip"], tar)
        if cmd is None:
            raise BackupError("no login for it in secrets.yaml")
        pw = (cmd[2].password + "\n").encode() if m.get("sudo") else None
        return [await self._put_stream(d, f"{slug(self.name(m))}.tgz", cmd[0], cmd[1],
                                       src_stdin=pw, timeout_s=300, ok_rcs=(0, 1))]

    async def _esxi(self, m, d, stamp) -> list:
        A, ip = self.a.access, m["ip"]
        rc, out, err = await A.ssh(ip, "vim-cmd hostsvc/firmware/sync_config && "
                                       "vim-cmd hostsvc/firmware/backup_config", timeout_s=180)
        found = re.search(r"/downloads/([^/\s]+)/(configBundle-\S+?\.tgz)", out or "")
        if not found:
            raise BackupError(f"the host did not make its configuration bundle: {_last(out or err)}")
        cmd = A.command(ip, f"cat /scratch/downloads/{found.group(1)}/{found.group(2)}")
        files = [await self._put_stream(d, "configBundle.tgz", cmd[0], cmd[1], timeout_s=300)]
        rc, out, _ = await A.ssh(ip, "vim-cmd vmsvc/getallvms; for f in /vmfs/volumes/*/*/*.vmx; "
                                     "do echo \"=== $f\"; cat \"$f\"; done", timeout_s=60, raw=True)
        if rc == 0:
            files.append(await self._put_bytes(d, "vms.txt", out.encode()))
        return files

    async def _shellies(self, m, d, stamp) -> list:
        from .actions import _get_json
        out, answered, total = {}, 0, 0
        listed = {str(x) for x in m["devices"]} if m.get("devices") is not None else None
        for dev in self.a.inv.devices:
            if listed is not None and dev.ip not in listed:
                continue
            if listed is None and not dev.name.lower().startswith("shelly"):
                continue
            total += 1
            ip = dev.ip
            info = await _get_json(f"http://{ip}/shelly")
            if info is None:
                out[ip] = {"name": dev.name, "error": "not answering"}
                continue
            e = {"name": dev.name, "shelly": info}
            if int(info.get("gen") or 1) >= 2:
                for rpc in ("Shelly.GetConfig", "Script.List", "Schedule.List", "Webhook.List",
                            "KVS.GetMany"):
                    e[rpc] = await _get_json(f"http://{ip}/rpc/{rpc}")
                for sc in ((e.get("Script.List") or {}).get("scripts") or []):
                    e[f"Script.GetCode {sc.get('id')}"] = await _get_json(
                        f"http://{ip}/rpc/Script.GetCode?id={sc.get('id')}")
            else:
                e["settings"] = await _get_json(f"http://{ip}/settings")
                e["actions"] = await _get_json(f"http://{ip}/settings/actions")
            out[ip] = e
            answered += 1
        if not answered:
            raise BackupError("no Shelly answered")
        data = json.dumps({"taken": stamp, "answered": answered, "of": total, "shellies": out},
                          indent=1, ensure_ascii=False)
        return [await self._put_bytes(d, "shellies.json", data.encode())]

    async def _profile(self, m, d, stamp) -> list:
        got = self.a.kinds.stream_argv(self.a, m["ip"], "backup")
        if got is None:
            raise BackupError("no way to log in to it (its login in secrets.yaml)")
        argv, env, stdin, fname, timeout_s = got
        return [await self._put_stream(d, fname, argv, env, src_stdin=stdin,
                                       timeout_s=max(timeout_s, 60))]

    async def _lanowl(self, m, d, stamp) -> list:
        """lanowl itself: its database, then its secrets, known hosts and config."""
        src = self.a.state.db_path
        tmp = os.path.join(tempfile.gettempdir(), f"lanowl-backup-{stamp}.sqlite")

        def copy():
            import sqlite3
            a, b = sqlite3.connect(src), sqlite3.connect(tmp)
            try:
                a.backup(b)                  # consistent, while lanowl keeps writing
            finally:
                b.close()
                a.close()
        try:
            await asyncio.to_thread(copy)
            files = [await self._put_stream(d, "lanowl_state.sqlite.gz", ["gzip", "-c", tmp],
                                            timeout_s=600)]
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        paths = lanowl_files(self.a)
        files.append(await self._put_stream(d, "lanowl-files.tgz", ["tar", "czf", "-", *paths],
                                            timeout_s=120))
        note = (f"lanowl's own backup, {stamp}.\n"
                f"lanowl_state.sqlite.gz: its database ({os.path.getsize(src) // 1024} KB before "
                f"compression) — restore: stop the container, gunzip it over /state/lanowl_state.sqlite "
                f"in lanowl-state volume, start it.\n"
                f"lanowl-files.tgz (NOT encrypted): {', '.join(paths)} — the secrets go back "
                f"where the container mounts them from (root, 600).\n")
        files.append(await self._put_bytes(d, "state.txt", note.encode()))
        return files

    async def _prune(self, m: dict):
        """The last `keep` monthly/manual backups of this machine; before-update ones for
        `keep_before_days`. Only directories this module names, and only under its base."""
        base = f"{self.base}/{slug(self.name(m))}"
        rc, out, _ = await self._store_run(f"ls -1 {Q(base)} 2>/dev/null")
        names = sorted(n for n in (out or "").split() if _DIR.match(n))
        routine = [n for n in names if n.endswith(("_monthly", "_manual"))]
        daily = [n for n in names if n.endswith("_daily")]
        drop = routine[:-self.keep] if self.keep > 0 else []
        drop += daily[:-int(m.get("daily") or 7)]           # the dailies never crowd out a monthly
        now = time.time()
        for n in names:
            if n.endswith("_before-update"):
                ts = time.mktime(time.strptime(_DIR.match(n).group(1), "%Y-%m-%d_%H%M"))
                if now - ts > self.keep_before_s:
                    drop.append(n)
        if drop:
            await self._store_run("rm -rf " + " ".join(Q(f"{base}/{n}") for n in drop))
            log.info("backups: %s — %d old backup(s) removed", self.name(m), len(drop))

    # --- before an update --------------------------------------------------------------
    async def before_update(self, ip: str, replace: Optional[list] = None) -> tuple:
        """(ok, words). A machine with a backup configured is backed up — and, with
        `snapshot:`, its VM snapshotted — before it is updated; not ok = do not update."""
        m = self.machine(ip) if self.enabled else None
        if m is None:
            return True, ""
        r = await self.backup(m, "before-update")
        if not r["ok"]:
            return False, f"the backup failed: {r.get('error')}"
        words = f"backed up first ({human_size(r.get('size'))})"
        if m.get("snapshot"):
            self.a.actions.step("taking the VM snapshot")
            ok, why = await self.snapshot(str(m["snapshot"]), replace)
            if not ok:
                return False, f"backed up, but the VM snapshot failed: {why}"
            words += ", VM snapshot taken" + (" (the older one replaced)" if replace else "")
        return True, words

    def _esxi_ip(self) -> str:
        return next((x["ip"] for x in self.machines if x["via"] == "esxi"), "")

    async def snapshots(self, vm: str) -> Optional[list]:
        """The VM's snapshots: [{"name", "id", "created", "mine"}]; None = could not read."""
        rc, out, _ = await self.a.access.ssh(
            self._esxi_ip(), f"id=$(vim-cmd vmsvc/getallvms | awk '$2==\"{vm}\"{{print $1}}'); "
                             "vim-cmd vmsvc/snapshot.get $id", timeout_s=60)
        if rc != 0:
            return None
        out_l = []
        for sname, sid, created in re.findall(r"Snapshot Name\s*:\s*(.+?)\s*\n[\s\S]*?Snapshot Id"
                                              r"\s*:\s*(\d+)[\s\S]*?Snapshot Created On\s*:\s*(.+?)\s*\n",
                                              out + "\n"):
            out_l.append({"name": sname, "id": sid, "created": created,
                          "mine": sname.startswith("lanowl-before-update-")})
        return out_l

    async def snapshot_plan(self, ip: str) -> Optional[dict]:
        """Before an update of a machine with a VM snapshot: what is there already. lanowl's
        own older snapshot is REPLACED — named on the approval, so approving is the owner's
        explicit yes to removing it; anyone else's is never touched."""
        m = self.machine(ip) if self.enabled else None
        if m is None or not m.get("snapshot"):
            return None
        snaps = await self.snapshots(str(m["snapshot"]))
        if snaps is None:
            return {"vm": m["snapshot"], "error": "the ESXi did not list its snapshots"}
        return {"vm": m["snapshot"], "replace": [s["name"] for s in snaps if s["mine"]],
                "keep": [s["name"] for s in snaps if not s["mine"]]}

    async def snapshot(self, vm: str, replace: Optional[list] = None) -> tuple:
        # the approved replacement first: never a chain of lanowl's own snapshots
        for old in [x for x in (replace or []) if x.startswith("lanowl-before-update-")]:
            cur = await self.snapshots(vm) or []
            hit = next((s for s in cur if s["name"] == old), None)
            if hit is None:
                continue
            rc, out, err = await self.a.access.ssh(
                self._esxi_ip(), f"id=$(vim-cmd vmsvc/getallvms | awk '$2==\"{vm}\"{{print $1}}'); "
                                 f"vim-cmd vmsvc/snapshot.remove $id {hit['id']}", timeout_s=900)
            if rc != 0:
                return False, f"could not remove the older snapshot {old}: {_last(err or out)}"
            log.info("backups: snapshot %s of %s removed (replaced, as approved)", old, vm)
        name = time.strftime("lanowl-before-update-%Y-%m-%d_%H%M")
        rc, out, err = await self.a.access.ssh(
            self._esxi_ip(),
            f"id=$(vim-cmd vmsvc/getallvms | awk '$2==\"{vm}\"{{print $1}}'); "
            f"[ -n \"$id\" ] || {{ echo NOVM; exit 1; }}; "
            f"vim-cmd vmsvc/snapshot.create $id {name} 'taken by lanowl before an update' 0 0 "
            f"&& vim-cmd vmsvc/snapshot.get $id", timeout_s=600)
        if "NOVM" in (out or ""):
            return False, f"no VM called {vm} on the ESXi"
        if name not in (out or ""):
            return False, _last(err or out) or "not created"
        log.info("backups: snapshot %s of %s taken", name, vm)
        return True, name

    async def prune_snapshots(self):
        """lanowl's own snapshots older than `snapshot_days` go. Others are left alone."""
        for vm in {str(m["snapshot"]) for m in self.machines if m.get("snapshot")}:
            rc, out, _ = await self.a.access.ssh(
                self._esxi_ip(), f"id=$(vim-cmd vmsvc/getallvms | awk '$2==\"{vm}\"{{print $1}}'); "
                                 "echo VMID=$id; vim-cmd vmsvc/snapshot.get $id", timeout_s=60)
            vmid = re.search(r"VMID=(\d+)", out or "")
            if rc != 0 or not vmid:
                continue
            for sname, sid in re.findall(r"Snapshot Name\s*:\s*(lanowl-before-update-\S+)"
                                         r"[\s\S]*?Snapshot Id\s*:\s*(\d+)", out):
                ts = time.mktime(time.strptime(sname[-15:], "%Y-%m-%d_%H%M"))
                if time.time() - ts > self.snapshot_s:
                    await self.a.access.ssh(self._esxi_ip(), f"vim-cmd vmsvc/snapshot.remove "
                                                             f"{vmid.group(1)} {sid}", timeout_s=900)
                    log.info("backups: snapshot %s of %s removed (older than %d days)", sname,
                             vm, self.snapshot_s / 86400)

    # --- the monthly run, and the daily look ---------------------------------------------
    def _at(self, now: float) -> float:
        h, _, mi = self.at.partition(":")
        lt = time.localtime(now)
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, int(h or 0), int(mi or 0), 0, 0, 0, -1))

    def due(self, now: float) -> bool:
        if not self.enabled or self.running:
            return False
        return (time.localtime(now).tm_mday == self.day and now >= self._at(now)
                and float(self.rec.get("last_run") or 0) < self._at(now))

    def _self_due(self, now: float) -> bool:
        """The daily backup of the machines that keep one (lanowl): at `at`, once a day —
        not on the monthly day, when the monthly run takes it."""
        if self.running or not any(m.get("daily") for m in self.machines):
            return False
        if time.localtime(now).tm_mday == self.day:
            return False
        return now >= self._at(now) and float(self.rec.get("last_self") or 0) < self._at(now)

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def tick(self, now: float):
        """From the sweep loop: the monthly run when due; once a day, old snapshots and
        backups gone stale."""
        if not self.enabled:
            return
        if self.due(now):
            self.start(None, "monthly")
        elif self._self_due(now):
            self.rec["last_self"] = now               # claimed now
            ms = [m for m in self.machines if m.get("daily")]
            self._task = asyncio.ensure_future(self._guarded(self._run(ms, "daily")))
        if now - float(self.rec.get("last_daily") or 0) > 86400 and not self.running:
            self.rec["last_daily"] = now
            self._task = asyncio.ensure_future(self._guarded(self._daily()))

    def start(self, ip: Optional[str], kind: str = "manual") -> bool:
        """Back up one machine (`ip`) or all of them (None), as its own task."""
        if self.running:
            return False
        ms = [m for m in self.machines if ip is None or m["ip"] == ip]
        if not ms:
            return False
        if kind == "monthly":
            self.rec["last_run"] = time.time()        # claimed now: a slow run must not restart
        self._task = asyncio.ensure_future(self._guarded(self._run(ms, kind)))
        return True

    async def _guarded(self, coro):
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("backups: the run failed")

    async def _run(self, ms: list, kind: str):
        results = [(m, await self.backup(m, kind)) for m in ms]
        self._save()
        bad = [(m, r) for m, r in results if not r["ok"]]
        if kind == "daily":
            # one message when it starts failing, one when it works again — never every day
            was = bool(self.rec.get("daily_failing"))
            self.rec["daily_failing"] = bool(bad)
            self._save()
            if was and not bad:
                self.a._emit_telegram("digest", "💾 The daily backup of "
                                      + ", ".join(_html(self.name(m)) for m, _ in results) + " works again.")
            if was or not bad:
                return
        if kind in ("monthly", "daily") and bad:
            # rule 7: a scheduled run with a failure is one message; the good ones are not news
            self.a._emit_telegram("digest", (
                f"💾 <b>{'Monthly' if kind == 'monthly' else 'Daily'} backup</b> — {len(bad)} of {len(results)} failed\n"
                + "\n".join(f"• {_html(label(self.name(m), m['ip'] if m['ip'] != 'shellies' else ''))}: "
                            f"{_html(r.get('error') or '?')}" for m, r in bad)
                + "\n<i>The rest are on the store. Security tab → Backups.</i>"))

    async def _daily(self):
        with contextlib.suppress(Exception):
            await self.prune_snapshots()
        now = time.time()
        stale = []
        for m in self.machines:
            r = self.rec["machines"].get(m["ip"]) or {}
            if r.get("last_ok") and now - r["last_ok"] > STALE_S:
                stale.append(m)
        keys = {f"stale:{m['ip']}" for m in stale}
        new = [m for m in stale if f"stale:{m['ip']}" not in set(self.rec["announced"])]
        self.rec["announced"] = sorted(keys)
        self._save()
        if new:
            self.a._emit_telegram("digest", (
                "💾 <b>Backups getting old</b>\n"
                + "\n".join(f"• {_html(self.name(m))}: last good backup "
                            f"{time.strftime('%d/%m/%Y', time.localtime(self.rec['machines'][m['ip']]['last_ok']))}"
                            for m in new)
                + "\n<i>Security tab → Backups → Back up now.</i>"))

    # --- what others read -------------------------------------------------------------------
    def next_run(self, now: Optional[float] = None) -> float:
        lt = time.localtime(now or time.time())
        y, mo = lt.tm_year, lt.tm_mon
        t = self._at(time.mktime((y, mo, self.day, 12, 0, 0, 0, 0, -1)))
        if t <= (now or time.time()):
            y, mo = (y + 1, 1) if mo == 12 else (y, mo + 1)
            t = self._at(time.mktime((y, mo, self.day, 12, 0, 0, 0, 0, -1)))
        return t

    def view(self) -> dict:
        ms = []
        for m in self.machines:
            r = self.rec["machines"].get(m["ip"]) or {}
            ms.append({"key": m["ip"], "name": self.name(m), "ip": "" if m["ip"] == "shellies" else m["ip"],
                       "via": m["via"], "last_ok": r.get("last_ok"), "size": r.get("size"),
                       "last_try": r.get("last_try"), "ok": r.get("ok"), "error": r.get("error"),
                       "kind": r.get("kind"), "files": r.get("files") or [],
                       "busy": self.current == self.name(m)})
        return {"enabled": self.enabled, "running": self.running, "current": self.current,
                "next": self.next_run() if self.enabled else None, "keep": self.keep,
                "where": self.share or f"{self.store_ip}:{self.base}", "encrypted": False,
                "machines": ms}

    def text(self) -> str:
        """/backups on Telegram."""
        if not self.enabled:
            return "Backups are off (backups.enabled)."
        v = self.view()
        lines = [f"💾 <b>Backups</b> → {_html(v['where'])}",
                 f"<i>next monthly run {time.strftime('%d/%m %H:%M', time.localtime(v['next']))}</i>"]
        for x in v["machines"]:
            if x["ok"] is False:
                mark = f"❌ {_html(x['error'] or '')}"
            elif x["last_ok"]:
                mark = (f"✅ {time.strftime('%d/%m %H:%M', time.localtime(x['last_ok']))} · "
                        f"{human_size(x['size'])}")
            else:
                mark = "— never"
            lines.append(f"• {_html(x['name'])}: {mark}")
        return "\n".join(lines)
