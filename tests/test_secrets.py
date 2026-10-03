"""Every secret lanowl uses, from one file: run with `python -m tests.test_secrets`.

  1. secrets.yaml holds the tokens and lanowl's ssh key beside the logins; a blank token is no
     token; a file that is not YAML is said once, not re-read until it changes;
  2. a token: its variable first, then the file its _FILE twin names (Docker secrets), then
     secrets.yaml — and an edit to the file is seen without a restart;
  3. the router's and the broker's logins: named by their section's `credentials:`, each half
     from the environment if given; none at all leaves the broker anonymous;
  4. lanowl's ssh key reaches every key login (the host-log watcher's ssh), a host's own key
     wins, LANOWL_SSH_KEY wins over the file;
  5. config.yaml holds none of it: secrets.yaml is found beside it, and the environment's
     logins no longer land in the config;
  6. the Home Assistant features need its token as well as its address;
  7. `lanowl --check` says where each secret comes from and what is missing, never a value.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

for _v in [k for k in os.environ if k.startswith("LANOWL_")]:     # only what each test sets
    del os.environ[_v]

from lanowl import access as X  # noqa: E402
from lanowl import kinds as K  # noqa: E402
from lanowl.model import Device, Inventory, load_config  # noqa: E402

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


SECRETS = """
logins:
  routers:     {user: admin, password: "r0uter-pw"}
  router-read: {user: lanowl, password: "read-pw"}
  broker:      {user: lanowl-mqtt, password: "mq-pw"}
  server:      {user: root, key: true}
devices:
  192.168.88.20: routers
tokens:
  telegram: "111:tg-secret"
  homeassistant: "ha-secret"
  blank: ""
ssh_key: KEY
"""
VALUES = ("r0uter-pw", "read-pw", "mq-pw", "tg-secret", "ha-secret", "env-tok", "file-tok")


def _write(path: str, text: str, mode: int = 0o600):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def _touch_later(path: str):
    """A new mtime even within the file system's clock tick."""
    t = os.stat(path).st_mtime + 2
    os.utime(path, (t, t))


def _setup(d: str, text: str = SECRETS) -> dict:
    key = os.path.join(d, "id_lanowl")
    _write(key, "k\n")
    _write(key + ".pub", "ssh-ed25519 AAAAC3Nza-test lanowl\n", 0o644)
    sec = os.path.join(d, "secrets.yaml")
    _write(sec, text.replace("KEY", key))
    return {"access": {"secrets_file": sec, "known_hosts": os.path.join(d, "kh")}}


# --- 1. the file --------------------------------------------------------------------------
def test_file():
    print("\n-- secrets.yaml: logins, tokens, lanowl's key --")
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d)
        data = X.shared(cfg).data()
        check(data["tokens"] == {"telegram": "111:tg-secret", "homeassistant": "ha-secret"},
              "the tokens; a blank one is no token")
        check(data["ssh_key"] == os.path.join(d, "id_lanowl"), "lanowl's ssh key, by its path")
        check(X.shared(cfg) is X.Access(cfg).file, "one reader per file, the same for everyone")
        _write(cfg["access"]["secrets_file"], "logins: [unclosed\n")
        _touch_later(cfg["access"]["secrets_file"])
        f = X.shared(cfg)
        check(f.data()["tokens"] == {} and "not valid YAML" in f.error,
              "a file that is not YAML: nothing from it, and why")
        m = f._mtime
        f.data()
        check(f._mtime == m and "not valid YAML" in f.error, "...and not re-read until it changes")


# --- 2. tokens ----------------------------------------------------------------------------
def test_tokens():
    print("\n-- a token: the variable, its _FILE, secrets.yaml; an edit needs no restart --")
    from lanowl import sinks
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d)
        check(X.token_from(cfg, "telegram") == ("111:tg-secret", "secrets.yaml")
              and sinks.resolve_tg_token(cfg) == "111:tg-secret", "from secrets.yaml")
        sec = cfg["access"]["secrets_file"]
        _write(sec, SECRETS.replace("111:tg-secret", "222:tg-secret"))
        _touch_later(sec)
        check(sinks.resolve_tg_token(cfg) == "222:tg-secret", "a new token in the file: used at once")
        tf = os.path.join(d, "tg")
        _write(tf, "333:file-tok\n")
        os.environ["LANOWL_TG_TOKEN_FILE"] = tf
        check(X.token_from(cfg, "telegram") == ("333:file-tok", "LANOWL_TG_TOKEN_FILE"),
              "a Docker secret (LANOWL_TG_TOKEN_FILE) over the file")
        os.environ["LANOWL_TG_TOKEN"] = "444:env-tok"
        check(X.token_from(cfg, "telegram") == ("444:env-tok", "LANOWL_TG_TOKEN"),
              "the variable over both")
        del os.environ["LANOWL_TG_TOKEN"]
        os.environ["LANOWL_TG_TOKEN_FILE"] = os.path.join(d, "missing")
        check(X.token(cfg, "telegram") == "222:tg-secret", "a _FILE that is not there: secrets.yaml")
        del os.environ["LANOWL_TG_TOKEN_FILE"]
        os.environ["LANOWL_HA_TOKEN"] = "555:env-tok"
        check(X.token(cfg, "homeassistant") == "555:env-tok", "Home Assistant's: LANOWL_HA_TOKEN")
        del os.environ["LANOWL_HA_TOKEN"]
        os.remove(sec)
        check(X.token(cfg, "telegram") == "", "no file, no variable: no token")


# --- 3. the router's and the broker's logins ---------------------------------------------------
def test_services():
    print("\n-- the router's and the broker's logins --")
    from lanowl import discovery, sinks
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d)
        check(discovery.resolve_mikrotik(cfg) == ("lanowl", "read-pw"),
              "the router: the login `router-read` when mikrotik names none")
        cfg["mikrotik"] = {"credentials": "routers"}
        check(discovery.resolve_mikrotik(cfg) == ("admin", "r0uter-pw"), "...or the one it names")
        os.environ["LANOWL_MIKROTIK_USER"] = "reader"
        lg, where = X.service_login_from(cfg, "mikrotik")
        check(lg[:2] == ("reader", "r0uter-pw") and where == "LANOWL_MIKROTIK_USER + secrets.yaml login routers",
              "a variable gives its half, the file the other")
        del os.environ["LANOWL_MIKROTIK_USER"]
        check(X.service_login(cfg, "mqtt")[:2] == ("", ""), "the broker: no login `mqtt`, none")

        class FakeClient:
            def __init__(self, *a):
                self.auth = None

            def username_pw_set(self, u, p):
                self.auth = (u, p)

            def __getattr__(self, name):
                return lambda *a, **k: None
        real = sinks.mqtt
        made = []

        class FakeMqtt:
            class CallbackAPIVersion:
                VERSION1 = 1

            @staticmethod
            def Client(*a):
                made.append(FakeClient())
                return made[-1]
        sinks.mqtt = FakeMqtt
        try:
            cfg["mqtt"] = {"host": "192.168.88.5"}
            sinks.MqttBridge(cfg).start()
            cfg["mqtt"]["credentials"] = "broker"
            sinks.MqttBridge(cfg).start()
        finally:
            sinks.mqtt = real
        check(made[0].auth is None and made[1].auth == ("lanowl-mqtt", "mq-pw"),
              "MQTT: anonymous without a login, the named login with one")


# --- 4. lanowl's ssh key ---------------------------------------------------------------------
def test_key():
    print("\n-- lanowl's ssh key: every key login --")
    from lanowl.hostlog import HostLogWatcher, _Host
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d)
        key = os.path.join(d, "id_lanowl")
        w = HostLogWatcher(cfg, lambda t, key="": None)
        argv = w._ssh_argv(_Host(name="Server", ip="192.168.88.10", user="root"), "true")
        check(argv[argv.index("-i") + 1] == key, "the host-log watcher's ssh: secrets.yaml's key")
        argv = w._ssh_argv(_Host(name="Mac", ip="192.168.88.50", user="me", identity="/k/own"), "true")
        check(argv[argv.index("-i") + 1] == "/k/own", "a login's own key file wins")
        os.environ["LANOWL_SSH_KEY"] = "/run/secrets/lanowl_key"
        check(X.ssh_key(cfg) == "/run/secrets/lanowl_key", "LANOWL_SSH_KEY wins over the file")
        del os.environ["LANOWL_SSH_KEY"]
        _write(cfg["access"]["secrets_file"], "logins: {}\n")
        _touch_later(cfg["access"]["secrets_file"])
        argv = w._ssh_argv(_Host(name="Server", ip="192.168.88.10", user="root"), "true")
        check("-i" not in argv, "none named: ssh's own default")


# --- 5. config.yaml holds none of it ------------------------------------------------------
def test_config():
    print("\n-- config.yaml: no secret in it --")
    with tempfile.TemporaryDirectory() as d:
        cp = os.path.join(d, "config.yaml")
        _write(cp, "mikrotik: {dhcp_source: 'http://192.168.88.1'}\n")
        os.environ["LANOWL_MIKROTIK_USER"], os.environ["LANOWL_MQTT_PASS"] = "reader", "mq-pw"
        cfg = load_config(cp)
        del os.environ["LANOWL_MIKROTIK_USER"], os.environ["LANOWL_MQTT_PASS"]
        check(cfg["access"]["secrets_file"] == os.path.join(d, "secrets.yaml"),
              "secrets.yaml: beside config.yaml unless it says otherwise")
        check("user" not in cfg["mikrotik"] and "mqtt" not in cfg,
              "the environment's logins stay out of the config (the model and the dashboard read it)")
        _write(cp, "access: {secrets_file: /run/secrets/secrets.yaml}\n")
        check(load_config(cp)["access"]["secrets_file"] == "/run/secrets/secrets.yaml", "...or where it says")


# --- 6. Home Assistant ----------------------------------------------------------------------
def test_ha():
    print("\n-- Home Assistant: its address and its token --")
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d, SECRETS.replace('  homeassistant: "ha-secret"\n', ""))
        cfg["access"]["ha_url"] = "http://192.168.88.30:8123"
        inv = Inventory(devices=[Device("192.168.88.30", "HA", "servers", "high",
                                        attrs={"kind": "homeassistant", "manage": ["updates", "reboot"]})])
        pl = K.derive(cfg, inv, X.Access(cfg, inv), {})[0]
        check(not pl.features and any("its token" in w for w in pl.problems),
              "an address without a token: its API features refused, and why")
        _write(cfg["access"]["secrets_file"], SECRETS.replace("KEY", "/x"))
        _touch_later(cfg["access"]["secrets_file"])
        pl = K.derive(cfg, inv, X.Access(cfg, inv), {})[0]
        check(sorted(pl.features) == ["reboot", "updates"] and not pl.problems, "with its token: on")


# --- 7. lanowl --check -------------------------------------------------------------------------
def test_report():
    print("\n-- lanowl --check: where each secret comes from, never its value --")
    with tempfile.TemporaryDirectory() as d:
        cfg = _setup(d)
        cfg.update({"telegram": {"chat_id": "100000001"}, "mikrotik": {"dhcp_source": "http://192.168.88.1"},
                    "mqtt": {"host": "192.168.88.5", "credentials": "broker"}})
        inv = Inventory(devices=[Device("192.168.88.10", "Server", "servers", "high",
                                        attrs={"credentials": "server"}),
                                 Device("192.168.88.11", "Typo", "servers", "low",
                                        attrs={"credentials": "sevrer"})])
        text, bad = X.report(cfg, inv)
        print("    | " + text.replace("\n", "\n    | "))
        check("✓ Telegram token  from secrets.yaml" in text and "✓ router login    lanowl, from secrets.yaml login router-read" in text
              and "✓ MQTT login      lanowl-mqtt, from secrets.yaml login broker" in text,
              "each secret, and where it comes from")
        check("ssh-ed25519 AAAAC3Nza-test lanowl" in text, "lanowl's key: its public half, to install")
        check(bad == 1 and "Typo (192.168.88.11) names 'sevrer', which secrets.yaml does not have" in text,
              "a login name the file does not have: one problem, named")
        check(not any(v in text for v in VALUES), "no password or token in it")
        _write(cfg["access"]["secrets_file"], "logins: {}\n", 0o644)
        _touch_later(cfg["access"]["secrets_file"])
        text, bad = X.report(cfg, None)
        check("others can read it: chmod 600" in text, "secrets.yaml that others can read: said")
        check("✗ Telegram token  telegram.chat_id is set and there is no token" in text
              and "the router (192.168.88.1) is read with the login 'router-read'" in text
              and "mqtt.credentials names 'broker'" in text and bad == 4,
              "what is used and missing: a problem each")
        cfg2 = {"access": {"secrets_file": os.path.join(d, "none.yaml")}}
        text, bad = X.report(cfg2, None)
        check(bad == 0 and "not found" in text and "○ Telegram token  not used" in text,
              "nothing configured that needs one: nothing missing")


if __name__ == "__main__":
    test_file()
    test_tokens()
    test_services()
    test_key()
    test_config()
    test_ha()
    test_report()
    print(f"\n{len(_fails)} FAILED" if _fails else "\nall passed")
    sys.exit(1 if _fails else 0)
