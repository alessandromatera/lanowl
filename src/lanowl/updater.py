"""The updater: the one optional container that may recreate lanowl's own containers.

    python -m lanowl.updater          # the helper (docker/compose.yaml, profile "updater")
    python -m lanowl.updater --probe  # inside lanowl's container: does its dashboard answer?

WHY IT IS SEPARATE. A container that can talk to Docker's socket is root on the machine. lanowl
(a web page, an AI model's words, a dozen devices' logins) must never be that. So this small,
stdlib-only program, run from the SAME image, is the only holder of the socket: it has no
network, a read-only disk, no capabilities and nothing to say to anyone but lanowl, over one unix
socket in a volume the two share.

WHAT IT ACCEPTS. One JSON line, exactly {"op": "status"} or {"op": "update"}. Anything else — a
different op, an extra field, an image name, a command, a line longer than 256 bytes — is
refused and does nothing. lanowl can say "go"; it can never choose an image, a container or a
command. What "update" does is fixed here and chosen from Docker's own labels:

  1. Which containers: the ones of the updater's OWN compose project (its own container, found
     by HOSTNAME, names the project) whose service is lanowl, sandbox or sandbox-offline, and
     which are running. Never another project's, never any other service, never itself.
  2. Pull each one's own image reference (the Docker daemon pulls: the updater has no network).
     A name with no registry in it (`lanowl:latest`) was built on this machine: refused.
  3. Same image id as the running one: nothing to do.
  4. Else, one container at a time (sandboxes first, lanowl last — its own process dies while
     it is replaced, which is why this program is not part of it): rename the old one
     `<name>-previous`, stop it, create the new one from its own configuration, start it.
  5. Proof: a sandbox must stay up 20 seconds; lanowl must stay up three minutes WITHOUT a
     restart and its dashboard must answer (asked from inside its container with `exec`).
  6. Good: the -previous ones are removed. Bad: the new ones are removed, the old ones renamed
     back and started, and the reason is the new container's last log lines, verbatim.
  7. What happened is written to /run/updater/last.json, for lanowl to tell the owner.

The decisions (which containers, the create body, the proof's verdict) are plain functions
over Docker's JSON, tested with fixtures; the Docker calls are the thin Docker class.
"""
from __future__ import annotations

import copy
import http.client
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.parse

from . import __version__

SOCK = "/run/updater/updater.sock"
LAST = "/run/updater/last.json"
DOCKER_SOCK = "/var/run/docker.sock"
MAX_IN = 256                          # bytes of a request line; a real one is 16
OPS = ("status", "update")
PROJECT = "com.docker.compose.project"
SERVICE = "com.docker.compose.service"
IMAGE_LABEL = "com.docker.compose.image"
ORDER = ("sandbox", "sandbox-offline", "lanowl")      # the only services, in the order they are replaced
SANDBOX_PROOF_S = 20
LANOWL_PROOF_S = 180
POLL_S = 5
PROBE_EVERY_S = 15
PREVIOUS = "-previous"
LOG_LINES = 15
NO_BUILD_HERE = ("this lanowl was built on this machine, not pulled from a registry: update it where it "
                 "was built (docker compose -f docker/compose.yaml build && ... up -d)")


class Refused(Exception):
    """A request or a plan the updater will not carry out; the text is what the owner reads."""


class DockerError(Exception):
    pass


# --- the request: what is accepted ------------------------------------------------------------
def parse_request(line: bytes) -> str:
    """The op of a request line; Refused for anything but {"op": "status"} or {"op": "update"}."""
    if len(line) > MAX_IN:
        raise Refused("too long")
    try:
        obj = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Refused("not JSON")
    if not isinstance(obj, dict) or set(obj) != {"op"}:
        raise Refused("only {\"op\": ...} is accepted")
    op = obj["op"]
    if not isinstance(op, str) or op not in OPS:
        raise Refused("unknown op")
    return op


# --- which containers --------------------------------------------------------------------------
def _labels(c: dict) -> dict:
    return (c.get("Config") or {}).get("Labels") or {}


def _name(c: dict) -> str:
    return str(c.get("Name") or "").lstrip("/")


def pick_containers(own: dict, found: list) -> list:
    """The containers an update may replace, from their `docker inspect` JSON: same compose project
    as the updater's own container, service lanowl / sandbox / sandbox-offline, running, not the
    updater itself, not a leftover `-previous`. Sandboxes first, lanowl last."""
    project = _labels(own).get(PROJECT, "")
    if not project:
        raise Refused("the updater is not part of a compose project, so it cannot tell which containers are lanowl's")
    picked = []
    for c in found:
        if c.get("Id") == own.get("Id") or _labels(c).get(PROJECT) != project:
            continue
        if _labels(c).get(SERVICE) not in ORDER or _name(c).endswith(PREVIOUS):
            continue
        st = c.get("State") or {}
        if st.get("Running") or st.get("Restarting"):
            picked.append(c)
    return sorted(picked, key=lambda c: ORDER.index(_labels(c)[SERVICE]))


def leftovers(own: dict, found: list) -> list:
    """Names of `-previous` containers of this project: an update that died half-way. A new one
    would rename over them, so it does not start until the owner has looked."""
    project = _labels(own).get(PROJECT, "")
    return [_name(c) for c in found if _labels(c).get(PROJECT) == project and _name(c).endswith(PREVIOUS)
            and _labels(c).get(SERVICE) in ORDER]


def pullable(ref: str) -> tuple:
    """(image, tag-or-digest) of a reference the registry can have; Refused for one built here."""
    ref = str(ref or "")
    if not ref or ref.startswith("sha256:") or "/" not in ref or any(ch in ref for ch in " ?#\\\n"):
        raise Refused(NO_BUILD_HERE)
    if "@" in ref:
        return ref, ""
    last = ref.rsplit("/", 1)[1]
    if ":" in last:
        image, _, tag = ref.rpartition(":")
        return image, tag
    return ref, "latest"


# --- the new container's configuration ---------------------------------------------------------
RUNTIME_ENDPOINT = ("NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway",
                    "GlobalIPv6Address", "GlobalIPv6PrefixLen", "MacAddress", "DNSNames")


def strip_image_defaults(cfg: dict, image_cfg: dict) -> dict:
    """The container's Config without what only came from its OLD image (inspect shows the merge):
    the new image brings its own environment, command, labels and so on. What the compose file or
    the owner set stays."""
    cfg = copy.deepcopy(cfg)
    img = image_cfg or {}
    for k in ("Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck", "StopSignal", "Shell"):
        if k in cfg and cfg.get(k) == img.get(k):
            del cfg[k]
    for k in ("ExposedPorts", "Volumes", "Labels"):
        if isinstance(cfg.get(k), dict):
            cfg[k] = {a: b for a, b in cfg[k].items() if a not in (img.get(k) or {}) or (img.get(k) or {})[a] != b}
            if not cfg[k]:
                del cfg[k]
    if cfg.get("Env"):
        old = set(img.get("Env") or [])
        cfg["Env"] = [e for e in cfg["Env"] if e not in old]
        if not cfg["Env"]:
            del cfg["Env"]
    return cfg


def create_body(old: dict, old_image_cfg: dict, ref: str, new_image_id: str) -> tuple:
    """(body, extra_networks) to create the replacement of the inspected container `old`: its
    Config (the image reference by name, so a later update sees the same name), HostConfig and
    its first network's endpoint; `extra_networks` are connected after the create. Runtime-only
    fields (addresses, endpoint ids, the old container's id as hostname and alias) are left out."""
    cfg = strip_image_defaults(old.get("Config") or {}, old_image_cfg)
    short = str(old.get("Id") or "")[:12]
    if cfg.get("Hostname") == short:
        del cfg["Hostname"]
    for k in ("ArgsEscaped", "MacAddress", "Image"):
        cfg.pop(k, None)
    cfg["Image"] = ref
    labels = dict(cfg.get("Labels") or {})
    if IMAGE_LABEL in labels:
        labels[IMAGE_LABEL] = new_image_id        # docker compose recreates when this differs from the image
    if labels:
        cfg["Labels"] = labels
    host = copy.deepcopy(old.get("HostConfig") or {})
    mode = str(host.get("NetworkMode") or "")
    if mode == "host" or mode.startswith("container:"):
        cfg.pop("Hostname", None)        # the host's (or the other container's) name, not a setting; Docker may refuse both
        cfg.pop("Domainname", None)
    nets = {}
    for n, ep in ((old.get("NetworkSettings") or {}).get("Networks") or {}).items():
        if n in ("host", "none"):
            continue
        ep = {k: v for k, v in (ep or {}).items() if k not in RUNTIME_ENDPOINT and v not in (None, [], "", {})}
        if ep.get("Aliases"):
            ep["Aliases"] = [x for x in ep["Aliases"] if x != short]
            if not ep["Aliases"]:
                del ep["Aliases"]
        nets[n] = ep
    body = {**cfg, "HostConfig": host}
    first = mode if mode in nets else next(iter(nets), "")
    if first:
        body["NetworkingConfig"] = {"EndpointsConfig": {first: nets[first]}}
    return body, {n: ep for n, ep in nets.items() if n != first}


# --- the proof ---------------------------------------------------------------------------------
def verdict(info: dict, started_at: str, elapsed: float, need_s: float, probe_ok, need_probe: bool) -> tuple:
    """("wait" | "ok" | "fail", reason) for a new container, from its `docker inspect` and, for lanowl,
    the last answer of its dashboard (None: not asked yet). It fails the moment the container is not
    running, has restarted, or (at the end) its dashboard does not answer; it is good only after
    `need_s` seconds of none of that."""
    st = info.get("State") or {}
    if not st.get("Running") or st.get("Restarting"):
        return "fail", f"it stopped (exit code {st.get('ExitCode')})" if not st.get("Running") else "it keeps restarting"
    if int(info.get("RestartCount") or 0) > 0 or st.get("StartedAt") != started_at:
        return "fail", "it restarted"
    if elapsed < need_s:
        return "wait", ""
    if need_probe and probe_ok is not True:
        return ("wait", "") if probe_ok is None else ("fail", "its dashboard did not answer")
    return "ok", ""


def demux(data: bytes) -> str:
    """Docker's multiplexed log/exec stream (8-byte header: stream, 3 zeros, size) as text; a stream
    that is not framed (a container with a tty) is returned as it is."""
    out, i = [], 0
    if data[:1] not in (b"\x00", b"\x01", b"\x02") or data[1:4] != b"\x00\x00\x00":
        return data.decode("utf-8", "replace")
    while i + 8 <= len(data):
        n = struct.unpack(">I", data[i + 4:i + 8])[0]
        out.append(data[i + 8:i + 8 + n])
        i += 8 + n
    return b"".join(out).decode("utf-8", "replace")


# --- Docker's API over its socket --------------------------------------------------------------
class _Unix(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("docker", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


class Docker:
    def __init__(self, path: str = DOCKER_SOCK):
        self.path = path

    def call(self, method: str, url: str, body=None, timeout: float = 60, ok=(200, 201, 204, 304)) -> bytes:
        c = _Unix(self.path, timeout)
        try:
            data = json.dumps(body).encode() if body is not None else None
            c.request(method, url, body=data, headers={"Content-Type": "application/json"} if data else {})
            r = c.getresponse()
            out = r.read()
            if r.status not in ok:
                try:
                    msg = json.loads(out).get("message", "")
                except Exception:
                    msg = out[:200].decode("utf-8", "replace")
                raise DockerError(f"Docker said {r.status} to {method} {url.split('?')[0]}: {msg}")
            return out
        finally:
            c.close()

    def j(self, method, url, body=None, timeout=60):
        out = self.call(method, url, body, timeout)
        return json.loads(out) if out else {}

    def ping(self) -> bool:
        try:
            return self.call("GET", "/_ping", timeout=5) == b"OK"
        except Exception:
            return False

    def inspect(self, cid: str) -> dict:
        return self.j("GET", f"/containers/{urllib.parse.quote(cid, safe='')}/json")

    def project(self, project: str) -> list:
        flt = json.dumps({"label": [f"{PROJECT}={project}"]})
        return self.j("GET", "/containers/json?all=1&filters=" + urllib.parse.quote(flt))

    def image(self, ref: str) -> dict:
        return self.j("GET", "/images/" + urllib.parse.quote(ref, safe="/:@") + "/json")

    def pull(self, image: str, tag: str):
        q = {"fromImage": image}
        if tag:
            q["tag"] = tag
        out = self.call("POST", "/images/create?" + urllib.parse.urlencode(q), timeout=900)
        for ln in out.decode("utf-8", "replace").splitlines():       # an error can arrive inside a 200
            try:
                e = json.loads(ln).get("error")
            except ValueError:
                continue
            if e:
                raise DockerError(str(e))

    def rename(self, cid, name):
        self.call("POST", f"/containers/{cid}/rename?name={urllib.parse.quote(name)}")

    def stop(self, cid, t=30):
        self.call("POST", f"/containers/{cid}/stop?t={int(t)}", timeout=t + 30)

    def start(self, cid):
        self.call("POST", f"/containers/{cid}/start")

    def create(self, name: str, body: dict) -> str:
        return self.j("POST", "/containers/create?name=" + urllib.parse.quote(name), body)["Id"]

    def connect(self, net: str, cid: str, endpoint: dict):
        self.call("POST", f"/networks/{urllib.parse.quote(net, safe='')}/connect",
                  {"Container": cid, "EndpointConfig": endpoint})

    def remove(self, cid):
        self.call("DELETE", f"/containers/{cid}?force=1")

    def logs(self, cid: str, tail: int = LOG_LINES) -> str:
        return demux(self.call("GET", f"/containers/{cid}/logs?stdout=1&stderr=1&tail={int(tail)}")).strip()

    def exec(self, cid: str, cmd: list) -> tuple:
        e = self.j("POST", f"/containers/{cid}/exec", {"Cmd": cmd, "AttachStdout": True, "AttachStderr": True})["Id"]
        out = self.call("POST", f"/exec/{e}/start", {"Detach": False, "Tty": False}, timeout=30)
        return self.j("GET", f"/exec/{e}/json").get("ExitCode"), demux(out)


# --- the update ----------------------------------------------------------------------------------
def plan(d, own_id: str) -> list:
    """The containers an update would replace (inspect JSON); Refused, in words, when it must not."""
    own = d.inspect(own_id)
    project = _labels(own).get(PROJECT, "")
    found = [d.inspect(c["Id"]) for c in d.project(project)] if project else []
    left = leftovers(own, found)
    if left:
        raise Refused("an earlier update did not finish: " + ", ".join(left) + " is still here — look at it first "
                      "(docker ps -a), then remove it or rename it back")
    chosen = pick_containers(own, found)
    if not chosen:
        raise Refused("no lanowl container of this compose project is running")
    for c in chosen:
        pullable((c.get("Config") or {}).get("Image"))
    return chosen


def write_last(rec: dict, path: str = ""):
    path = path or LAST
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f)
    os.replace(tmp, path)


def _version(d, cid: str) -> str:
    try:
        code, out = d.exec(cid, ["python", "-c", "import lanowl,sys;sys.stdout.write(lanowl.__version__)"])
        return out.strip() if code == 0 and len(out.strip()) < 40 else ""
    except Exception:
        return ""


def execute(d, chosen: list, last_path: str = "", clock=time.time, sleep=time.sleep,
            proof_s: float = LANOWL_PROOF_S, sandbox_proof_s: float = SANDBOX_PROOF_S) -> dict:
    """Carry the update out; returns what to write to last.json. Never raises."""
    t0 = clock()
    rec = {"state": "running", "started": t0, "from": "", "to": "", "reason": ""}
    done = []                         # [{"name", "old", "new"}] in the order replaced
    try:
        write_last(rec, last_path)
        refs = {}
        for c in chosen:
            ref = (c.get("Config") or {}).get("Image")
            if ref not in refs:
                d.pull(*pullable(ref))
                refs[ref] = d.image(ref)["Id"]
        todo = [c for c in chosen if c.get("Image") != refs[(c.get("Config") or {}).get("Image")]]
        if not todo:
            return _finish(rec, "nothing", "already the latest", last_path, clock)
        lan = next((c for c in todo if _labels(c).get(SERVICE) == "lanowl"), None)
        rec["from"] = _version(d, lan["Id"]) if lan else ""
        write_last(rec, last_path)
        for c in todo:
            ref = (c.get("Config") or {}).get("Image")
            name = _name(c)
            entry = {"name": name, "old": c["Id"], "new": ""}
            body, extra = create_body(c, d.image(c["Image"]).get("Config") or {}, ref, refs[ref])
            done.append(entry)
            d.rename(c["Id"], name + PREVIOUS)
            d.stop(c["Id"])
            entry["new"] = d.create(name, body)
            for net, ep in extra.items():
                d.connect(net, entry["new"], ep)
            d.start(entry["new"])
            bad = _prove(d, entry["new"], _labels(c).get(SERVICE) == "lanowl", clock, sleep,
                         proof_s if _labels(c).get(SERVICE) == "lanowl" else sandbox_proof_s)
            if bad:
                raise _Bad(bad, entry["new"])
        if lan:
            rec["to"] = _version(d, done[-1]["new"])
        for e in done:
            try:
                d.remove(e["old"])
            except DockerError:
                pass                  # the update worked; a leftover -previous is told next time
        return _finish(rec, "ok", "", last_path, clock)
    except _Bad as e:
        quoted = ""
        try:
            quoted = d.logs(e.cid)
        except Exception:
            pass
        reason = f"{e.why}" + (f"; its last log lines:\n{quoted}" if quoted else "; its log was empty")
        return _rollback(d, rec, done, reason, last_path, clock)
    except (DockerError, Refused, OSError, KeyError, ValueError) as e:
        if not done:
            return _finish(rec, "failed", f"{e}" + (" — if this lanowl was built on this machine, update it where it was built"
                                                    if "pull" in str(e).lower() or "denied" in str(e).lower() else ""),
                           last_path, clock)
        return _rollback(d, rec, done, f"{e}", last_path, clock)
    except Exception as e:            # anything else (a half answer from Docker, odd JSON): never leave lanowl stopped
        why = f"{type(e).__name__}: {e}"
        return _rollback(d, rec, done, why, last_path, clock) if done else _finish(rec, "failed", why, last_path, clock)


class _Bad(Exception):
    def __init__(self, why: str, cid: str):
        super().__init__(why)
        self.why, self.cid = why, cid


def _prove(d, cid: str, is_lanowl: bool, clock, sleep, need_s: float) -> str:
    """"" when the new container proved itself, else why not."""
    t0 = clock()
    started = d.inspect(cid).get("State", {}).get("StartedAt")
    probe, last_probe = None, -PROBE_EVERY_S
    while True:
        el = clock() - t0
        if is_lanowl and el >= 10 and clock() - last_probe >= PROBE_EVERY_S:
            try:
                code, _ = d.exec(cid, ["python", "-m", "lanowl.updater", "--probe"])
                probe = code == 0
            except Exception:
                probe = False
            last_probe = clock()
        v, why = verdict(d.inspect(cid), started, el, need_s, probe, is_lanowl)
        if v == "ok":
            return ""
        if v == "fail":
            return why
        sleep(POLL_S)


def _finish(rec: dict, state: str, reason: str, path: str, clock) -> dict:
    rec.update(state=state, reason=reason, finished=clock())
    try:
        write_last(rec, path)
    except OSError:
        pass
    return rec


def _rollback(d, rec: dict, done: list, reason: str, path: str, clock) -> dict:
    """The new containers away, the old ones back under their names and running."""
    try:
        for e in reversed(done):
            if e["new"]:
                try:
                    d.stop(e["new"], 10)
                except DockerError:
                    pass
                d.remove(e["new"])
        for e in done:                # sandboxes first, as they were started
            d.rename(e["old"], e["name"])
        for e in done:
            d.start(e["old"])
    except (DockerError, OSError) as err:
        return _finish(rec, "failed", f"{reason}; and it could not be put back: {err}", path, clock)
    return _finish(rec, "rolled_back", reason, path, clock)


# --- the server ------------------------------------------------------------------------------------
class Updater:
    def __init__(self, docker=None, own_id: str = "", sock: str = SOCK, last: str = LAST):
        self.d = docker or Docker()
        self.own = own_id or os.environ.get("HOSTNAME", "")
        self.sock, self.last = sock, last
        self.job = None

    @property
    def busy(self) -> bool:
        return self.job is not None and self.job.is_alive()

    def answer(self, line: bytes) -> dict:
        try:
            op = parse_request(line)
        except Refused as e:
            return {"ok": False, "error": f"refused: {e}"}
        if op == "status":
            last = {}
            try:
                with open(self.last, encoding="utf-8") as f:
                    last = json.load(f)
            except (OSError, ValueError):
                pass
            return {"ok": True, "version": __version__, "busy": self.busy, "docker": self.d.ping(), "last": last}
        if self.busy:
            return {"ok": False, "error": "an update is already running"}
        try:
            chosen = plan(self.d, self.own)
        except Refused as e:
            return {"ok": False, "error": str(e)}
        except (DockerError, OSError, KeyError, ValueError) as e:
            return {"ok": False, "error": f"Docker did not answer as expected: {e}"}
        self.job = threading.Thread(target=execute, args=(self.d, chosen, self.last), daemon=True)
        self.job.start()
        return {"ok": True, "started": True, "containers": [_name(c) for c in chosen]}

    def serve(self):
        os.makedirs(os.path.dirname(self.sock), exist_ok=True)
        try:
            os.unlink(self.sock)
        except FileNotFoundError:
            pass
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.sock)
        os.chmod(self.sock, 0o660)
        s.listen(4)
        print(f"lanowl updater {__version__}: listening on {self.sock}", flush=True)
        while True:
            conn, _ = s.accept()
            with conn:
                try:
                    # five seconds for the whole line, not for each byte: a client that trickles one
                    # byte at a time must not hold the updater (it answers one client at a time)
                    deadline = time.monotonic() + 5
                    buf = b""
                    while b"\n" not in buf and len(buf) <= MAX_IN:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            break
                        conn.settimeout(left)
                        chunk = conn.recv(MAX_IN + 1 - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                    line = buf.split(b"\n", 1)[0] if b"\n" in buf else buf
                    if len(buf) > MAX_IN and b"\n" not in buf[:MAX_IN]:
                        line = b"x" * (MAX_IN + 1)
                    conn.sendall((json.dumps(self.answer(line)) + "\n").encode())
                except OSError:
                    pass


# --- inside lanowl's container -------------------------------------------------------------------------
def probe_url(cfg: dict, env: dict) -> str:
    """The dashboard's address as lanowl itself reads it (the environment wins over config.yaml; 8088
    when neither says); "" when config.yaml (read: a dict) has the dashboard switched off. A config
    that could not be read (None) is not taken as "off": the dashboard is asked for at 8088."""
    web = ((cfg or {}).get("web") or {}) if cfg is not None else {}
    if cfg is not None and not web.get("enabled", False):
        return ""
    port = env.get("LANOWL_WEB_PORT") or web.get("port") or 8088
    return f"http://127.0.0.1:{int(port)}/"


def probe() -> int:
    """Exit 0 when the dashboard answers (any HTTP answer, a login page included), 1 when not."""
    import urllib.error
    import urllib.request
    cfg = None
    try:
        from .model import load_config
        cfg = load_config(os.environ.get("LANOWL_CONFIG") or "/config/config.yaml")
    except Exception:
        pass
    try:
        url = probe_url(cfg, os.environ)
    except (TypeError, ValueError):
        url = "http://127.0.0.1:8088/"
    if not url:
        return 0
    try:
        urllib.request.urlopen(url, timeout=5).close()
        return 0
    except urllib.error.HTTPError:
        return 0
    except Exception:
        return 1


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--probe"]:
        return probe()
    if argv:
        print("usage: python -m lanowl.updater   (the helper)   |   --probe", file=sys.stderr)
        return 2
    Updater().serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
