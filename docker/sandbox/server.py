"""The sandbox's end of the model's shell: run one bash command, answer with its output.

Listens on a unix socket on a volume lanowl mounts read-only (/run/sandbox/exec.sock).
One request per connection, one JSON line each way:

    -> {"cmd": "mtr -r -c 5 9.9.9.9", "timeout": 60}
    <- {"rc": 0, "out": "...", "secs": 5.2, "timed_out": false, "truncated": false}

One command at a time. Each runs in its own process group, which is killed when the command
ends or times out, so nothing it started in the background outlives it. Runs as uid 10001
(entrypoint.sh has already dropped everything else). Standard library only.
"""
import json
import os
import signal
import socket
import subprocess
import threading
import time

SOCK = "/run/sandbox/exec.sock"
OUT_MAX = 64 * 1024          # bytes of output kept; the rest is read and thrown away
REQ_MAX = 64 * 1024
TIMEOUT_MAX = 600
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/work",
       "LANG": "C.UTF-8", "TERM": "dumb", "TZ": os.environ.get("TZ", "Europe/Berlin")}


def run(cmd: str, timeout: float) -> dict:
    t0 = time.time()
    p = subprocess.Popen(["/bin/bash", "-c", cmd], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd="/work",
                         env=ENV, start_new_session=True)
    buf, state = bytearray(), {"truncated": False}

    def drain():
        while True:
            chunk = p.stdout.read(8192)
            if not chunk:
                return
            room = OUT_MAX - len(buf)
            if room > 0:
                buf.extend(chunk[:room])
            if len(chunk) > room:
                state["truncated"] = True

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    try:
        os.killpg(p.pid, signal.SIGKILL)      # the command's whole group, finished or not
    except ProcessLookupError:
        pass
    p.wait()
    reader.join(timeout=2)
    return {"rc": p.returncode, "out": buf.decode(errors="replace"),
            "secs": round(time.time() - t0, 1), "timed_out": timed_out,
            "truncated": state["truncated"]}


def handle(conn: socket.socket):
    conn.settimeout(10)
    data = b""
    while not data.endswith(b"\n") and len(data) < REQ_MAX:
        chunk = conn.recv(8192)
        if not chunk:
            break
        data += chunk
    try:
        req = json.loads(data)
        cmd = str(req["cmd"])
        timeout = max(1.0, min(float(req.get("timeout") or 60), TIMEOUT_MAX))
    except (ValueError, KeyError, TypeError):
        res = {"error": "bad request"}
    else:
        res = run(cmd, timeout)
    conn.settimeout(10)
    conn.sendall(json.dumps(res).encode() + b"\n")


def main():
    os.chmod(os.path.dirname(SOCK), 0o700)      # ours since the entrypoint's chown
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o600)       # lanowl connects as root; nobody else needs to
    srv.listen(4)
    print(f"sandbox: listening on {SOCK} as uid {os.getuid()}", flush=True)
    while True:
        conn, _ = srv.accept()
        with conn:
            try:
                handle(conn)
            except Exception as e:           # one bad request must not end the server
                print(f"sandbox: request failed: {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    main()
