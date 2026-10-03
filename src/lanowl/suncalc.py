"""Dependency-free sunrise/sunset math for `expect_offline: sun` devices.

PV-powered gear (the Solar inverter and its EM100 meter) powers its own network
interface from the panels: no sun, no WiFi. That is not an outage, so the sweep
needs to know when the sun is down. Uses the classic NOAA / Ed Williams
approximation — accurate to a few minutes, which is plenty because callers apply
a configurable margin around the events anyway (panels need real light, not the
first grazing ray, to boot the electronics).
"""
from __future__ import annotations

import calendar
import math
import time
from typing import Optional, Tuple

_ZENITH = 90.833   # official sunrise/sunset zenith, degrees


def _sun_event_utc_hours(y: int, m: int, d: int, lat: float, lon: float, rising: bool):
    """UTC hour (0..24) of sunrise/sunset on the given civil date.
    Returns 'polar_day' / 'polar_night' when the sun never crosses the horizon."""
    n1 = math.floor(275 * m / 9)
    n2 = math.floor((m + 9) / 12)
    n3 = 1 + math.floor((y - 4 * math.floor(y / 4) + 2) / 3)
    n = n1 - (n2 * n3) + d - 30

    lng_hour = lon / 15.0
    t = n + ((6 - lng_hour) / 24 if rising else (18 - lng_hour) / 24)
    ma = (0.9856 * t) - 3.289                          # mean anomaly
    l = (ma + 1.916 * math.sin(math.radians(ma))
         + 0.020 * math.sin(math.radians(2 * ma)) + 282.634) % 360.0

    ra = math.degrees(math.atan(0.91764 * math.tan(math.radians(l)))) % 360.0
    ra += (math.floor(l / 90) - math.floor(ra / 90)) * 90   # same quadrant as L
    ra /= 15.0                                              # degrees -> hours

    sin_dec = 0.39782 * math.sin(math.radians(l))
    cos_dec = math.cos(math.asin(sin_dec))
    cos_h = (math.cos(math.radians(_ZENITH)) - sin_dec * math.sin(math.radians(lat))) \
        / (cos_dec * math.cos(math.radians(lat)))
    if cos_h > 1:
        return "polar_night"
    if cos_h < -1:
        return "polar_day"

    h = (360 - math.degrees(math.acos(cos_h))) if rising else math.degrees(math.acos(cos_h))
    t_mean = h / 15.0 + ra - 0.06571 * t - 6.622
    return (t_mean - lng_hour) % 24.0


def sun_times(ts: float, lat: float, lon: float) -> Tuple[Optional[float], Optional[float]]:
    """(sunrise_epoch, sunset_epoch) for the LOCAL calendar date of `ts`.
    A None means the sun never rises/sets that day (polar latitudes only)."""
    lt = time.localtime(ts)
    y, m, d = lt.tm_year, lt.tm_mon, lt.tm_mday
    midnight_utc = calendar.timegm((y, m, d, 0, 0, 0))
    out = []
    for rising in (True, False):
        uth = _sun_event_utc_hours(y, m, d, lat, lon, rising)
        out.append(None if isinstance(uth, str) else midnight_utc + uth * 3600.0)
    return out[0], out[1]


def is_pv_night(ts: float, lat: float, lon: float, margin_min: float = 60.0) -> bool:
    """True when PV-powered gear is expected to be offline: from `margin` before
    sunset until `margin` after sunrise the next morning."""
    sunrise, sunset = sun_times(ts, lat, lon)
    if sunrise is None or sunset is None:
        # polar edge cases: no sunrise -> permanent night; no sunset -> permanent day
        return sunrise is None
    m = margin_min * 60.0
    return ts < sunrise + m or ts > sunset - m


def is_solar_day(ts: float, lat: float, lon: float, margin_min: float = 45.0) -> bool:
    """True when dusk-to-dawn gear is expected to be offline: from `margin` before
    sunrise until `margin` after sunset.

    The mirror image of `is_pv_night`, and deliberately NOT its complement: both
    windows are generous, so each kind of device is only expected to answer in the
    solid middle of its own on-period. A twilight switch trips on falling light, not
    on the almanac, so the hour around each edge belongs to neither."""
    sunrise, sunset = sun_times(ts, lat, lon)
    if sunrise is None or sunset is None:
        # polar edge cases: no sunset -> permanent day; no sunrise -> permanent night
        return sunset is None
    m = margin_min * 60.0
    return sunrise - m <= ts <= sunset + m
