#!/usr/bin/env python3
"""Port-pool rotation with RST-flood cooling-off backoff.

port 443 is deep-inspected; random non-443 ports are safer.
When a hop triggers a RST flood ("sticks"), the offending
port is put on a cooling-off timeout and subsequent probes rotate to the next
clean port in the pool.

This module is pure: it holds no network state. Callers feed observed RST
events via :meth:`PortRandomizer.register_rst` and read the next probe port
via :meth:`PortRandomizer.next_port`. ``now`` is injectable for deterministic
unit testing.
"""

import random
from time import monotonic

# Non-443 ports are less aggressively inspected.
# 443 is intentionally excluded from the default pool.
DEFAULT_PORT_POOL = [80, 8080, 8443, 2053, 2083, 2087, 2096]

DEFAULT_RST_THRESHOLD = 3
DEFAULT_COOLING_OFF_SECONDS = 30


class PortRandomizer:
    """Rotate a pre-scanned clean port pool; back off on RST floods."""

    def __init__(self, ports=DEFAULT_PORT_POOL, rst_threshold=DEFAULT_RST_THRESHOLD,
                 cooling_off_seconds=DEFAULT_COOLING_OFF_SECONDS, seed=None):
        if not ports:
            raise ValueError("port pool must contain at least one port")
        invalid = [p for p in ports if not (1 <= int(p) <= 65535)]
        if invalid:
            raise ValueError(f"ports must be in 1..65535: {invalid!r}")
        self._ports = [int(p) for p in ports]
        self._rst_threshold = int(rst_threshold)
        self._cooling_off_seconds = float(cooling_off_seconds)
        self._rng = random.Random(seed)
        self._order = list(self._ports)
        self._rng.shuffle(self._order)
        self._idx = 0
        self._rst_counts = {}        # port -> consecutive RST count
        self._cooling_until = {}     # port -> monotonic deadline

    @property
    def ports(self):
        return list(self._ports)

    @property
    def rst_threshold(self):
        return self._rst_threshold

    @property
    def cooling_off_seconds(self):
        return self._cooling_off_seconds

    def is_available(self, port, now=None):
        """True if `port` is not currently on cooling-off backoff."""
        t = self._time(now)
        deadline = self._cooling_until.get(port)
        return deadline is None or t >= deadline

    def register_rst(self, port, now=None):
        """Account a RST observed on `port`.

        Returns True iff the consecutive-RST threshold was hit, which puts the
        port on cooling-off (and resets its consecutive counter).
        """
        t = self._time(now)
        self._rst_counts[port] = self._rst_counts.get(port, 0) + 1
        if self._rst_counts[port] >= self._rst_threshold:
            self._cooling_until[port] = t + self._cooling_off_seconds
            self._rst_counts[port] = 0
            return True
        return False

    def reset_rst(self, port):
        """Forget RST accounting for `port` (e.g. after a successful probe)."""
        self._rst_counts.pop(port, None)
        self._cooling_until.pop(port, None)

    def next_port(self, now=None):
        """Return the next available (non-cooling) port, rotating the pool.

        If every port is cooling-off, returns the next port in rotation
        anyway (a probe is better than a stall; timeout budget).
        """
        t = self._time(now)
        count = len(self._order)
        for _ in range(count):
            port = self._order[self._idx]
            self._idx = (self._idx + 1) % count
            if self.is_available(port, t):
                return port
        return self._order[self._idx]

    @staticmethod
    def _time(now):
        return monotonic() if now is None else now


def parse_port_pool(spec):
    """Parse a ``"80,443,8080"`` / list spec into a validated list of ints.

    Empty / falsy spec yields the DEFAULT_PORT_POOL. Whitespace is tolerated.
    """
    if not spec:
        return list(DEFAULT_PORT_POOL)
    if isinstance(spec, (list, tuple)):
        items = spec
    else:
        items = [p.strip() for p in str(spec).split(",") if p.strip()]
    ports = [int(p) for p in items]
    if not ports:
        return list(DEFAULT_PORT_POOL)
    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValueError(f"ports must be in 1..65535: {invalid!r}")
    return ports
