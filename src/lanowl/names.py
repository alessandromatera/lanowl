"""Names the owner gives on the dashboard.

A device can be renamed on the dashboard. The names live in lanowl's own record (`names`),
never in inventory.yaml, so a regenerated inventory does not undo a name. They apply
everywhere a name is read: the page, the alerts, the digest, the model. A rename needs no PIN
and sends no message; it shows on the Timeline, and a name can go back to the inventory's.

Two kinds, by what identifies the device for good:
  - a device of the inventory, by its configured address (DHCP drift moves `ip`, never
    `configured_ip`);
  - anything on a site's network — a DHCP row, a fixed address, and a device watched from
    there — by site and MAC, so the name follows it when DHCP moves it, and a device named on
    its row keeps that name when it is picked to be watched.
"""
from __future__ import annotations

from typing import Optional

MAX_LEN = 60


def clean(name) -> str:
    """One line, no control characters, at most MAX_LEN characters."""
    s = "".join(ch for ch in str(name or "") if ch.isprintable())
    return " ".join(s.split())[:MAX_LEN]


def mac_key(site: str, mac: str) -> str:
    return f"{site}|{str(mac or '').lower()}"


class Names:
    def __init__(self, rec: Optional[dict] = None):
        rec = rec or {}
        self.ips: dict = {str(k): str(v) for k, v in (rec.get("ips") or {}).items() if v}
        self.macs: dict = {str(k): str(v) for k, v in (rec.get("macs") or {}).items() if v}

    def dump(self) -> dict:
        return {"ips": dict(self.ips), "macs": dict(self.macs)}

    @staticmethod
    def key(dev) -> tuple:
        """("mac", site|mac) for a device watched from a site's network, else ("ip", its
        configured address)."""
        a = dev.attrs or {}
        if a.get("watched") and a.get("mac"):
            return "mac", mac_key(a.get("site") or "", a["mac"])
        return "ip", str(a.get("configured_ip") or dev.ip)

    def of(self, dev) -> str:
        kind, k = self.key(dev)
        return (self.macs if kind == "mac" else self.ips).get(k, "")

    def for_mac(self, site: str, mac: str) -> str:
        return self.macs.get(mac_key(site, mac), "")

    def set(self, dev, name: str) -> None:
        """Keep `name` for this device; "" forgets it (back to the list's name)."""
        kind, k = self.key(dev)
        self.set_key(kind, k, name)

    def set_key(self, kind: str, k: str, name: str) -> None:
        d = self.macs if kind == "mac" else self.ips
        if name:
            d[k] = name
        else:
            d.pop(k, None)

    def apply(self, inv) -> list:
        """Give every device of `inv` its name. Idempotent; returns [(device, old name)] for
        the ones it changed."""
        out = []
        for dev in list(inv.devices):
            want = self.of(dev) or (dev.attrs or {}).get("listed_name") or dev.name
            if want != dev.name:
                old = dev.name
                inv.rename(dev, want)
                out.append((dev, old))
        return out
