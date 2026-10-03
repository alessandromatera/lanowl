"""Who made a device, from its MAC: for the DHCP devices nobody knows.

Offline: nmap's own prefix list, already in the image for the scans (46k prefixes, 24-bit and
the longer IEEE blocks). No lookup service is called: a MAC is the network's own business.

Most unknown devices on a home network wear a PRIVATE address: the second-lowest bit
of the first byte set (x2, x6, xA, xE). That is a phone, tablet or laptop giving each Wi-Fi a
random MAC of its own (iOS, Android and Windows all do by default): no list can name its maker,
and saying so is the useful answer.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

log = logging.getLogger("lanowl.oui")

PREFIXES = "/usr/share/nmap/nmap-mac-prefixes"
PRIVATE = "private address — a phone, tablet or laptop hiding its own MAC"
_table: Optional[dict] = None


def _load(path: str = PREFIXES) -> dict:
    t: dict = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or " " not in line:
                    continue
                p, name = line.rstrip("\n").split(" ", 1)
                if re.fullmatch(r"[0-9A-Fa-f]{6,9}", p):
                    t[p.upper()] = name.strip()
    except OSError:
        log.warning("oui: %s not readable — vendors unknown", path)
    return t


def vendor(mac: str, path: str = PREFIXES) -> str:
    """The maker, PRIVATE for a randomized address, "" when unknown."""
    global _table
    h = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
    if len(h) < 6:
        return ""
    first = int(h[:2], 16)
    if first & 0x01:
        return ""                                    # multicast: not a device
    if first & 0x02:
        return PRIVATE
    if _table is None:
        _table = _load(path)
    for n in (9, 7, 6):                              # the longest block first (MA-S, MA-M, MA-L)
        v = _table.get(h[:n])
        if v:
            return v
    return ""
