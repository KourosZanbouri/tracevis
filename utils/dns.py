#!/usr/bin/env python3
"""DNS probe construction for traceroute-based censorship measurement.

Restricted networks commonly hijack plain DNS into a filter net, leave a DNS
tunnel as the only channel that survives a total shutdown, and treat DoT
(TCP/853) differently again -- so the modes here probe all three.

TraceVis traces packet *paths* by sending raw scapy packets with an incrementing
TTL. These helpers build the DNS-family probe packets used by the ``--dns``,
``--dnstcp``, ``--dnsdot`` and ``--dnstt`` modes. They are pure (no I/O) and
return the same 4-tuple shape ``get_dns_packets`` always returned so the rest of
the tracer works unchanged.
"""
from scapy.all import DNS, DNSQR, IP, TCP, UDP

import utils.dpi

ACCESSIBLE_ADDRESS = "www.example.com"
DEFAULT_BLOCKED_ADDRESS = "www.twitter.com"

# DNS hijack blackhole target. Membership is tested against the
# whole filter net, not this one address — see `utils.dpi.is_blackhole_address`.
BLACKHOLE_ADDR = utils.dpi.BLACKHOLE_ADDR

# --- default destination pool (backlog §1.3) ---------------------------------
#
# These are destination *sweeps*, not the probe's A/B. The accessible-vs-blocked
# contrast is carried by the domain pair (ACCESSIBLE_ADDRESS vs
# DEFAULT_BLOCKED_ADDRESS): every `get_*_packets` sends both to the same list of
# destinations.
#
# The addresses stay literals. Resolving them would hand the choice of
# destination to whatever resolver the network provides, and under a DNS-hijack
# regime that resolver is the thing being measured. Literals
# fix the address field — they do *not* defeat on-path redirection of UDP/53 to
# a local resolver, which nothing in the destination field can. Detecting that
# is a separate job; see backlog §2.12.
#
# Each entry earns its place by answering a different question on a restricted
# network. Removing the ones that fail is exactly wrong — "8.8.8.8 is unreachable" *is*
# the measurement, and a pool where everything works measures nothing. What was
# dropped is redundancy, not failure.
#
#   1.1.1.1  control              the one destination observed reachable, on
#                                 TCP 443, 8443 and 2053.
#   1.0.0.1  same-operator        Cloudflare, like 1.1.1.1 — and observed
#            control              *unreachable* on 2053 in the same run where
#                                 1.1.1.1 answered. A per-operator allowlist
#                                 predicts these two behave alike; a per-IP one
#                                 predicts they do not. They did not.
#   8.8.8.8  treatment            observed unreachable on TCP/443 and
#                                 reachable on UDP/53 — the one destination
#                                 known to differ by port, which is what rules
#                                 out a purely per-destination model.
#
# 9.9.9.9 was dropped: everywhere it was measured it was simply unreachable,
# duplicating 8.8.8.8's treatment role without asking a different question.
#
# These roles are a hypothesis carried from one network, not a property of the
# addresses; elsewhere they may not hold. `-i/--ips` replaces the
# pool outright.
RESOLVER_CONTROL = "1.1.1.1"
RESOLVER_SAME_OPERATOR_CONTROL = "1.0.0.1"
RESOLVER_TREATMENT = "8.8.8.8"

DEFAULT_TARGETS = [
    RESOLVER_CONTROL,
    RESOLVER_SAME_OPERATOR_CONTROL,
    RESOLVER_TREATMENT,
]

# Per-mode names kept because `tracevis.py` selects by mode and they may need to
# diverge later. `--sni-test` also draws on DOT_RESOLVERS, which is why the DoT
# pool is not DoT-specific.
DEFAULT_DNS_RESOLVERS = list(DEFAULT_TARGETS)
DOT_RESOLVERS = list(DEFAULT_TARGETS)
DNSTT_RESOLVERS = list(DEFAULT_TARGETS)

TARGET_ROLES = {
    RESOLVER_CONTROL: "control",
    RESOLVER_SAME_OPERATOR_CONTROL: "same-operator control",
    RESOLVER_TREATMENT: "treatment",
}


def describe_targets(targets):
    """`1.1.1.1 (control), 1.0.0.1 (same-operator control), 8.8.8.8 (treatment)`.

    Printed when a run falls back to the default pool, so the operator can see
    the design without reading this file — a sweep whose roles are invisible
    gets read as a list of equals.
    """
    return ", ".join(
        target + (f" ({TARGET_ROLES[target]})" if target in TARGET_ROLES else "")
        for target in targets)


def filter_blackholed(resolvers):
    """Drop any resolver pointing at the filtering blackhole address.

    Inert against every pool above, and verified so by
    `test_no_default_target_is_ever_filtered_out`: it compares against a literal
    that a pool of literals never contains. It guards a caller that passes a
    *resolved* or user-supplied list — which nothing does today. It matters that
    it stays inert: silently dropping the treatment would leave a run that only
    ever probes destinations known to work, which is unfalsifiable by
    construction.
    """
    return [str(r) for r in resolvers
            if not utils.dpi.is_blackhole_address(r)]


def build_dns_query(resolver_ip, domain, proto="udp", dport=53, ttl=1):
    """Build a single DNS query packet for path tracing.

    Mirrors the original packet shape (``IP id=1, ttl=1``; transport ``sport=53``)
    so existing UDP/TCP DNS traces behave identically when ``proto="udp"``.
    """
    ip = IP(dst=str(resolver_ip), id=1, ttl=ttl)
    dns = DNS(rd=1, id=1, qd=DNSQR(qname=domain))
    if proto == "tcp":
        transport = TCP(sport=53, dport=int(dport))
    else:
        transport = UDP(sport=53, dport=int(dport))
    return ip / transport / dns


def get_dns_packets(blocked_address="", accessible_address="", dns_over_tcp=False):
    if blocked_address == "":
        blocked_address = DEFAULT_BLOCKED_ADDRESS
    if accessible_address == "":
        accessible_address = ACCESSIBLE_ADDRESS
    resolver = DEFAULT_DNS_RESOLVERS[0]
    proto = "tcp" if dns_over_tcp else "udp"
    dns_request_1 = build_dns_query(resolver, accessible_address, proto=proto, dport=53)
    dns_request_2 = build_dns_query(resolver, blocked_address, proto=proto, dport=53)
    return dns_request_1, accessible_address, dns_request_2, blocked_address


def get_dot_packets(blocked_address="", accessible_address=""):
    """DNS-over-TLS probe: DNS query over TCP to port 853."""
    if blocked_address == "":
        blocked_address = DEFAULT_BLOCKED_ADDRESS
    if accessible_address == "":
        accessible_address = ACCESSIBLE_ADDRESS
    resolver = DOT_RESOLVERS[0]
    dot_request_1 = build_dns_query(resolver, accessible_address, proto="tcp", dport=853)
    dot_request_2 = build_dns_query(resolver, blocked_address, proto="tcp", dport=853)
    return dot_request_1, accessible_address, dot_request_2, blocked_address


def get_dnstt_packets(blocked_address="", accessible_address=""):
    """dnstt probe: DNS query over UDP to port 53.

    dnstt tunnels DNS-over-HTTPS inside DNS-over-UDP/53; for path tracing the
    outer probe is a UDP/53 DNS query to a resolver that answers on port 53.
    """
    if blocked_address == "":
        blocked_address = DEFAULT_BLOCKED_ADDRESS
    if accessible_address == "":
        accessible_address = ACCESSIBLE_ADDRESS
    resolver = DNSTT_RESOLVERS[0]
    dnstt_request_1 = build_dns_query(resolver, accessible_address, proto="udp", dport=53)
    dnstt_request_2 = build_dns_query(resolver, blocked_address, proto="udp", dport=53)
    return dnstt_request_1, accessible_address, dnstt_request_2, blocked_address
