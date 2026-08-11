"""Removing the operator from a saved measurement (backlog §2.8).

Two different things hide under the word "anonymise" and they cost different
amounts, so they are kept apart:

* **The operator's own address** carries no measurement value whatsoever. Every
  probe has its `IP.src` overwritten at send time (`Tracer.send_packet`), so the
  stored value says who ran the trace and nothing about the network. Removed
  unconditionally — the tool already does this for the *public* address, and
  doing it for one and not the other was an accident, not a policy.
* **Private hops on the path** are measurement data: hop count, the shape of the
  access network, where the NAT sits. Removing them costs something real, so it
  is opt-in behind `--anonymize`.

CGNAT space (RFC 6598) is deliberately *not* pseudonymised even under the flag.
It is the carrier's infrastructure rather than the operator's LAN, and
`utils.dpi.is_cgnat_address` reads it back out of the saved hops to set
`cgnat_hop` — scrubbing it would silently disable a detector that took a field
trip to justify.
"""
import ipaddress
import re

# The project's existing sentinel for "an address that was removed": already
# used by `traceroute_struct.set_endtime` and `convert_packetlist.packet2json`.
SENTINEL_SOURCE = "127.1.2.7"

# RFC 5737 TEST-NET-1 — reserved for documentation, guaranteed unroutable, and
# obviously not a real hop. Substitutes have to stay parseable IPv4 literals:
# `utils/vis.py` builds node ids through `ipaddress.IPv4Address` and would raise
# on a placeholder like "redacted".
PSEUDONYM_NETWORK = ipaddress.ip_network("192.0.2.0/24")

# RFC 1918 only. `ipaddress.is_private` is deliberately not used: it also covers
# 100.64/10 (which must survive, see the module docstring), loopback, and
# link-local, none of which are the operator's LAN.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def is_private_hop(address):
    """True for an RFC 1918 address — the operator's own network."""
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return any(parsed in network for network in PRIVATE_NETWORKS)


class Pseudonymiser:
    """Stable first-seen mapping from private addresses into TEST-NET-1.

    Stable because the graph merges nodes by address: give the same box two
    names across repeats or packet arms and one hop becomes two, changing the
    shape of the very thing being measured.
    """

    def __init__(self):
        self._assigned = {}
        self._pool = PSEUDONYM_NETWORK.hosts()

    def __call__(self, address):
        if address not in self._assigned:
            try:
                self._assigned[address] = str(next(self._pool))
            except StopIteration:
                # 254 distinct private hops in one run is not a real trace, but
                # raising here would lose a completed measurement at save time.
                self._assigned[address] = str(PSEUDONYM_NETWORK.broadcast_address)
        return self._assigned[address]

    @property
    def mapping(self):
        return dict(self._assigned)


def hop_addresses(entries):
    """Every address a hop reported answering from."""
    seen = []
    for entry in entries:
        for hop in getattr(entry, "result", []):
            for result in hop.get("result", []):
                if isinstance(result, dict) and result.get("from"):
                    seen.append(result["from"])
    return seen


def build_replacements(entries, source_ip="", pseudonymise=False):
    """Map of address -> replacement for one save."""
    replacements = {}
    if source_ip and source_ip != SENTINEL_SOURCE:
        replacements[source_ip] = SENTINEL_SOURCE
    if pseudonymise:
        alias = Pseudonymiser()
        for address in hop_addresses(entries):
            if address not in replacements and is_private_hop(address):
                replacements[address] = alias(address)
    return replacements


def _compile(addresses):
    # Bounded on both sides so 192.168.1.5 cannot match inside 192.168.1.50.
    return re.compile(
        r"(?<![\d.])(" + "|".join(re.escape(a) for a in addresses) + r")(?![\d.])")


def _rewrite(value, pattern, replacements):
    if isinstance(value, str):
        return pattern.sub(lambda m: replacements[m.group(0)], value)
    if isinstance(value, dict):
        return {k: _rewrite(v, pattern, replacements) for k, v in value.items()}
    if isinstance(value, list):
        return [_rewrite(v, pattern, replacements) for v in value]
    return value


def scrub(entries, source_ip="", pseudonymise=False):
    """Rewrite addresses in place across a list of `traceroute_data` entries.

    Walks every string in the nested hop structure rather than named fields:
    the operator's address appears in `src_addr`, in each hop's `summary`, and
    again inside the `packets` blob, and a field-by-field scrub is one new key
    away from leaking again.

    Returns the replacement map, for the caller to report.
    """
    replacements = build_replacements(entries, source_ip, pseudonymise)
    if not replacements:
        return replacements
    pattern = _compile(replacements)
    for entry in entries:
        if getattr(entry, "src_addr", None):
            entry.src_addr = _rewrite(entry.src_addr, pattern, replacements)
        if getattr(entry, "result", None):
            entry.result = _rewrite(entry.result, pattern, replacements)
    return replacements
