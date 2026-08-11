#!/usr/bin/env python3
"""Adaptive timeout resolution for severe-restriction networks.

the default 1s per-hop timeout misflags slow DPI/CNAT hops
as "***" (no response), corrupting middlebox inference; total-block paths such
as dnstt need ~60s. This module provides pure, side-effect-free helpers.

Two layers:
  1. ``resolve_timeout`` maps a named profile (fast/degraded/shutdown) to a
     base timeout; an explicit CLI value always wins.
  2. ``adaptive_timeout`` scales the base timeout to a multiple of the last
     observed RTT, bounded by a floor/cap. Timeout only ever grows from the
     base, so a trace never becomes more aggressive mid-run.
"""

import math

TIMEOUT_PROFILES = {
    "fast": 1,        # open networks (default)
    "degraded": 3,    # allowlisted / DPI latency inflation
    "shutdown": 60,   # total-block paths e.g. dnstt
}

DEFAULT_ADAPTIVE_SCALE = 3
DEFAULT_ADAPTIVE_CAP = 60
DEFAULT_ADAPTIVE_FLOOR = 1


def resolve_timeout(profile=None, explicit=None):
    """Return the effective base timeout in seconds.

    ``explicit`` (from ``--timeout``) takes precedence over ``profile``.
    Unknown profiles raise ValueError; absent arguments default to ``fast``.
    """
    if explicit is not None:
        return int(explicit)
    if profile is not None:
        if profile not in TIMEOUT_PROFILES:
            raise ValueError(f"unknown timeout profile: {profile!r}")
        return TIMEOUT_PROFILES[profile]
    return TIMEOUT_PROFILES["fast"]


def adaptive_timeout(base_timeout, last_rtt=None, scale=DEFAULT_ADAPTIVE_SCALE,
                     cap=DEFAULT_ADAPTIVE_CAP, floor=DEFAULT_ADAPTIVE_FLOOR):
    """Scale ``base_timeout`` toward ``last_rtt * scale``, bounded to [floor, cap].

    With no usable RTT the base is returned unchanged. The result is always at
    least ``base_timeout`` (timeout only grows), so mid-trace adaptation never
    makes probing more aggressive.
    """
    if not last_rtt or last_rtt <= 0:
        return int(base_timeout)
    scaled = last_rtt * scale
    grown = max(int(base_timeout), scaled)
    bounded = max(floor, min(grown, cap))
    return math.ceil(bounded)
