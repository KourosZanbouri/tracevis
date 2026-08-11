#!/usr/bin/env python3
"""DPI / CGNAT / SNI-path classification.

Pure, dependency-free classifier that maps *observable* signals — the
network-state emitted by `utils.geolocate.classify_network_state` plus optional
per-hop NAT / middlebox / PEP evidence and the probe's L4 proto/dport — into
the path-level posture flags carried on every `traceroute_data`:

  - ``dpi_cleared``   : path traversed a DPI layer without inspection
                         (path-cleared case).
  - ``cgnat_hop``     : a carrier-grade NAT hop was observed.
  - ``sni_inspected`` : a TCP-reassembly middlebox / PEP terminated an
                         SNI-bearing (TCP/443) flow.
  - ``rst_flood``     : multiple TCP RST responses observed on the same
                         flow / port, indicating active DPI reset injection
                         ("RST floods").
  - ``tcp_silently_dropped`` : TCP traffic was sent but no TCP-layer response
                                 (SYN-ACK, data, or RST) was received and the
                                 destination was unreachable — the path silently
                                 dropped packets without signalling (measured
                                 networks block TCP with a silent drop rather
                                 than RST injection).

The function is intentionally coarse: it returns *path-level* booleans from the
signals available at classification time. Per-hop SNI evidence is refined in
`utils/vis.py` from the raw answered/received packets (`detect_nat_pep_middlebox`).
"""

import ipaddress
from collections import namedtuple

# in the restricted regime every residential flow is forced through
# a CGNAT layer, and that CGNAT is exactly the tiered-allowlist boundary, so an
# "allowlisted" network_state is itself the CGNAT-layer signal.
CGNAT_NETWORK_STATES = ("allowlisted",)

# RFC 6598 reserves 100.64.0.0/10 exclusively for carrier-grade NAT, so a hop
# inside it *is* a CGNAT hop — no inference needed. RFC 1918 space is
# deliberately not included: it is equally consistent with an ordinary home
# router, and a flag that fires on every LAN says nothing.
#
# This exists because deriving `cgnat_hop` from `network_state` alone made it
# unfirable in practice: a network whose traces all crossed an obvious RFC 6598
# hop still reported False, because the detector had reached its (allowlisted)
# provider and called the network `open`.
CGNAT_PREFIX = ipaddress.ip_network("100.64.0.0/10")


def is_cgnat_address(address) -> bool:
    """True when `address` is in RFC 6598 CGNAT space."""
    if not address:
        return False
    try:
        return ipaddress.ip_address(str(address)) in CGNAT_PREFIX
    except ValueError:
        # "***", a hostname, an IPv6 literal — nothing to conclude either way.
        return False


# The threat report this was built against names 10.10.34.34 as the filtering
# blackhole, and the code matched that one literal. Measurement found blocked
# names answered with a *different* host in the same prefix, from every resolver
# probed, so the single-address test could never fire. The filter net is the /24;
# the canonical address is one host inside it.
BLACKHOLE_NETWORK = ipaddress.ip_network("10.10.34.0/24")
BLACKHOLE_ADDR = "10.10.34.34"


def is_blackhole_address(address) -> bool:
    """True when `address` belongs to the filtering blackhole net."""
    if not address:
        return False
    try:
        return ipaddress.ip_address(str(address)) in BLACKHOLE_NETWORK
    except ValueError:
        return False

# SNI is only extractable by a TCP-reassembly DPI layer on a
# TLS handshake, i.e. a TCP/443 (SNI-bearing) flow.
SNI_PORT = 443

DpiSignal = namedtuple("DpiSignal", ["dpi_cleared", "cgnat_hop", "sni_inspected", "rst_flood", "tcp_silently_dropped"])


def classify_dpi_path(
    is_nat: bool = False,
    is_middlebox: bool = False,
    is_pep: bool = False,
    network_state: str = "unknown",
    sent_proto: str = "",
    sent_dport: int = -1,
    rst_count: int = 0,
    rst_threshold: int = 3,
    dst_reached: bool = True,
    cgnat_observed: bool = False,
    reply_forged: bool = False,
) -> DpiSignal:
    """Classify the DPI/CGNAT/SNI posture of a path from observable signals.

    Args:
        is_nat:        a NAT hop was observed on this path (vis per-hop).
        is_middlebox:  a middlebox hop was observed (vis per-hop).
        is_pep:        a PEP hop was observed (vis per-hop).
        network_state: classify_network_state result (open|allowlisted|
                       shutdown|unknown).
        sent_proto:    the probe's layer-4 protocol ("TCP"/"UDP"/"ICMP"/"").
        sent_dport:    the probe's destination port (-1 when unknown).
        rst_count:     per-hop TCP RST response count from ``count_rst_responses``.
        rst_threshold: minimum RSTs to flag ``rst_flood`` (default 3).
        dst_reached:    whether the destination IP responded (False for blocked
                        TCP paths — measured behaviour is a silent drop).
        cgnat_observed: a hop in RFC 6598 space was seen on this path (see
                        ``is_cgnat_address``). Direct evidence, independent of
                        what the network-state detector concluded.
        reply_forged:   the destination's answer was written by something else
                        (see ``utils.forgery``). Direct evidence of active
                        on-path interception.

    Returns:
        DpiSignal(dpi_cleared, cgnat_hop, sni_inspected, rst_flood,
                  tcp_silently_dropped).
    """
    # CGNAT: the allowlisted tier *is* the CGNAT layer; a per-hop NAT in
    # an allowlisted regime confirms it. An observed RFC 6598 hop settles it
    # outright, whatever the detector made of the network.
    cgnat_hop = (
        bool(cgnat_observed)
        or network_state in CGNAT_NETWORK_STATES
        or (bool(is_nat) and network_state in CGNAT_NETWORK_STATES)
    )

    # SNI: only a middlebox/PEP doing TCP reassembly on a 443 flow can
    # extract SNI.
    sni_inspected = (
        bool(is_middlebox or is_pep)
        and sent_proto == "TCP"
        and sent_dport == SNI_PORT
    )

    # RST floods: multiple TCP RSTs on the same flow indicate
    # active DPI reset injection (e.g. SNI-triggered blocking on 443).
    rst_flood = rst_count >= rst_threshold

    # Silent drop: TCP traffic sent but no TCP-layer response received
    # and destination unreachable. Measurement showed this to be the actual
    # blocking mechanism — packets are silently dropped rather than RST'd.
    # Only applies to TCP probes where some progress was made (ICMP at hop N but
    # destination never reached, no RSTs).
    tcp_silently_dropped = (
        sent_proto == "TCP"
        and not dst_reached
        and not rst_flood
        and not (is_middlebox or is_pep)  # not a visible middlebox that we can tag separately
    )

    # Path-cleared: no SNI inspection, no RST flood, no silent drop, and
    # the network is outright open.
    #
    # `cgnat_hop` is deliberately *not* a term here. It used to be, but the
    # clause was inert: `cgnat_hop` could only be true when network_state was
    # "allowlisted", and this branch already requires "open", so the two could
    # never disagree. Now that `cgnat_hop` reports observed CGNAT rather than
    # standing in for the regime, keeping the clause would mean every carrier
    # putting its subscribers behind 100.64/10 — most of them censoring nothing
    # — reported an uncleared path. Being NATted is a fact about the topology;
    # being inspected is a fact about the DPI, and only the second belongs here.
    # A forged reply is the strongest evidence of interception this tool has:
    # something on the path answered in the destination's name. A path cannot be
    # "cleared" and impersonated at once, and the two flags used to be able to
    # say so in the same measurement.
    dpi_cleared = (
        not bool(reply_forged)
        and not sni_inspected
        and not rst_flood
        and not tcp_silently_dropped
        and network_state == "open"
    )

    return DpiSignal(
        dpi_cleared=dpi_cleared,
        cgnat_hop=cgnat_hop,
        sni_inspected=sni_inspected,
        rst_flood=rst_flood,
        tcp_silently_dropped=tcp_silently_dropped,
    )
