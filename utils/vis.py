#!/usr/bin/env python3

import ast
import html
import ipaddress
import json
import os
import socket
from collections import namedtuple
from itertools import pairwise

import networkx as nx

import utils.convert_packetlist
import utils.dpi
import utils.renderer

ROUTER_COLOR = "green"
WINDOWS_COLOR = "blue"
LINUX_COLOR = "purple"
MIDDLEBOX_COLOR = "red"
PEP_COLOR = "green"
NAT_COLOR = "dodgerblue"
NO_RESPONSE_COLOR = "gray"

# M4: a hop that SNI-inspected a TCP/443 flow (DPI extraction).
DPI_COLOR = "orange"
DPI_NAME = "SNI-inspected"
# Backlog §2.12: the node the graph draws at the destination is not the
# destination — something on the path answered in its name.
FORGED_COLOR = "crimson"
FORGED_NAME = "Forged reply (impersonating the destination)"

# Backlog §2.3: a carrier-grade NAT hop (RFC 6598) — the tiered-access
# allowlist boundary. Rendered distinctly from generic NAT so the tier
# transition point is visible in the graph.
CGNAT_COLOR = "teal"
CGNAT_NAME = "CGNAT (allowlist boundary)"
CGNAT_SHAPE = "hexagon"
CGNAT_BORDER = "#20b2aa"

ROUTER_NAME = "Router"
WINDOWS_NAME = "Windows"
LINUX_NAME = "Linux"
MIDDLEBOX_NAME = "Middlebox"
PEP_NAME = "PEP"
NAT_NAME = "NAT"
NO_RESPONSE_NAME = "unknown"

REQUEST_COLORS = [
    "DarkTurquoise", "HotPink", "LimeGreen", "Red", "DodgerBlue", "Orange",
    "MediumSlateBlue", "DarkGoldenrod", "Green", "Brown", "YellowGreen", "Magenta"
]


OFFLINE_TEMPLATE_PATH = os.path.dirname(
    __file__) + "/templates/template_offline.html.jinja"
MAIN_TEMPLATE_PATH = os.path.dirname(
    __file__) + "/templates/template_main.html.jinja"

multi_directed_graph = nx.MultiDiGraph()


def resolve_or_ip(addr):
    """Resolve a hostname to an address, or pass through if already one.

    Fixes GitHub issue #68: vis() crashes when src_addr or dst_addr is a
    hostname instead of an address.

    Backlog §2.1: both families are accepted. `socket.gethostbyname` is
    IPv4-only, so a name with only a AAAA record raised `gaierror` and fell
    through to the hostname, which then failed to parse as an address further
    down. `getaddrinfo` answers for both.
    """
    try:
        ipaddress.ip_address(addr)
        return addr
    except (ValueError, TypeError):
        pass
    try:
        # AF_UNSPEC: whichever family the name actually has. IPv4 is preferred
        # when a name has both, so an existing dual-stacked capture keeps
        # resolving exactly as it did.
        infos = socket.getaddrinfo(addr, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return addr
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return addr


def address_node_id(addr, prefix="x", suffix="x"):
    """Graph node id for an address, in either family.

    The id is the address as an integer, which is unique within a family but
    *not across* families: `::1` and `0.0.0.1` are both 1. The family is
    folded into the id so a dual-stack capture cannot collapse two different
    hops onto one node.

    Returns None when `addr` is not an address at all, so callers can decide
    -- some hops are "***" or a hostname that never resolved.
    """
    try:
        parsed = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None
    family = "" if parsed.version == 4 else "v6"
    return prefix + family + str(int(parsed)) + suffix


def _node_id_or_label(addr, prefix="x", suffix="x"):
    """A node id for anything, address or not.

    `resolve_or_ip` normally hands these an address, but it returns the name
    unchanged when resolution fails -- offline, or a name that no longer
    exists -- and the old code then raised `AddressValueError` and took the
    whole render down. That was GitHub issue #68's crash in a different guise.
    Falling back to the literal keeps the graph renderable and keeps two
    different unresolved names on two different nodes.
    """
    node_id = address_node_id(addr, prefix=prefix, suffix=suffix)
    if node_id is not None:
        return node_id
    safe = "".join(char if char.isalnum() else "_" for char in str(addr))
    return prefix + "name" + safe + suffix


def get_packet_type(packet_obj):
    if len(packet_obj.keys()) > 1:
        return list(packet_obj.keys())[1]


def take_one_complement(chksum_int_value):
    complement_str = ''
    for ch in "{0:04x}".format(chksum_int_value):
        complement_str += ("{0:01x}".format(15 - int(ch, base=16)))
    return int(complement_str, base=16)


def calculate_chksum(ip_in_icmp, sent_ttl):
    # the word for checksum is hex of TTL and proto. i.e.: 0xttlproto
    # so each TTL worth 256
    sent_ttl_int = int(sent_ttl)
    received_chksum = ip_in_icmp['chksum']
    received_ttl_int = int(ip_in_icmp['ttl'])
    checksum_str = ''
    if sent_ttl_int > 1 and sent_ttl_int > received_ttl_int:
        corrected_ttl = sent_ttl_int - received_ttl_int
        remained_value = corrected_ttl * 256
        checksum_hex = take_one_complement(int(received_chksum, base=16))
        checksum_tmp = checksum_hex + remained_value
        max_chksum_value = 0xffff
        if checksum_tmp > max_chksum_value:
            checksum_tmp = (checksum_tmp & max_chksum_value) + \
                (checksum_tmp >> 16)
            if checksum_tmp > max_chksum_value:
                checksum_tmp = (checksum_tmp & max_chksum_value) + \
                    (checksum_tmp >> 16)
        checksum_str = hex(take_one_complement(checksum_tmp))
    else:
        checksum_str = received_chksum
    return checksum_str


# --- middlebox fingerprinting (GitHub issue #47) -----------------------------

MiddleboxFingerprint = namedtuple("MiddleboxFingerprint", [
    "mss_clamped", "mss_clamp_value", "ts_stripped", "ipid_pattern",
])

NO_FINGERPRINT = MiddleboxFingerprint(
    mss_clamped=False, mss_clamp_value=None, ts_stripped=False,
    ipid_pattern="unknown")

# Common MSS clamp values observed in the wild — middleboxes that rewrite
# the advertised MSS almost always clamp it to one of these (or a nearby
# value to avoid fragmentation on a lower-MTU link). A clamp *to one of these*
# is stronger evidence of a deliberate middlebox rewrite than an arbitrary
# smaller MSS, which can also come from a genuinely lower-MTU peer, so
# ``mss_clamp_value`` carries the observed value and the tooltip says which
# case it is.
MSS_CLAMP_VALUES = frozenset({1350, 1380, 1420, 1440, 1452, 1460})

# Upper bound on a per-packet IP-ID increment that still counts as a
# monotonic global counter rather than randomisation.
#
# The naive rule is ``delta == 1``, but that only holds when our probes are
# the *only* traffic the responder emits. A real router or middlebox runs a
# single global IP-ID counter shared by every flow it originates, so between
# two of our probes it has usually sent a handful of other packets and the
# ID advances by more than one. Measured against this repository's own
# captures, ``delta == 1`` classified 0 of 164 hops as sequential while 116
# of them show exactly this signature (e.g. 41021 → 41029 → 41037). Those
# were all being reported as "random", which the tooltip presents as evidence
# of a randomising middlebox — a false positive on the majority of hops.
IPID_SEQUENTIAL_MAX_DELTA = 2048

# IP-ID is a 16-bit field, so a global counter wraps. Deltas are computed
# modulo this so a wrap does not read as a backwards jump.
IPID_MODULUS = 1 << 16


def _parse_tcp_options(options_str):
    """Parse the stringified TCP options from a serialized packet.

    ``packet2json`` writes ``options`` as ``repr`` of the scapy options list,
    e.g. ``"[('MSS', 1460), ('SAckOK', b''), ('WScale', 6), ('TS', '0:1')]``.
    """
    if not options_str:
        return []
    try:
        return ast.literal_eval(options_str)
    except (ValueError, SyntaxError):
        return []


def _extract_mss(options):
    """Return the MSS value from a parsed options list, or None."""
    for name, value in options:
        if name.upper() == "MSS":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


_TIMESTAMP_OPTION_NAMES = frozenset({"TS", "TIMESTAMP"})


def _has_timestamp_option(options):
    """True when a TCP Timestamp option is present in the list.

    scapy names this option ``TS``; other serialisers spell it ``Timestamp``.
    Both are matched case-insensitively — the previous
    ``name.upper() == "Timestamp"`` comparison could never be true, because an
    upper-cased string never equals a mixed-case literal.
    """
    for name, _value in options:
        if str(name).upper() in _TIMESTAMP_OPTION_NAMES:
            return True
    return False


def _collect_ip_ids(received_packets):
    """Return the IP-ID values carried by a list of serialized packets."""
    ip_ids = []
    for pkt in received_packets:
        ip_layer = pkt.get("IP") if isinstance(pkt, dict) else None
        if not ip_layer:
            continue
        try:
            ip_ids.append(int(str(ip_layer.get("id")), 0))
        except (TypeError, ValueError):
            continue
    return ip_ids


def _classify_ipid_pattern(received_packets):
    """Classify the IP-ID sequence across multiple received packets.

    Returns one of: ``"constant"``, ``"sequential"``, ``"random"``,
    ``"unknown"`` (when there is not enough data).

    - **constant**  : every IP-ID is identical — a device that does not run a
                      per-packet counter (some NATs, load-balancers), or a
                      host that always sends ID 0 with DF set.
    - **sequential**: IP-IDs advance monotonically by a small, bounded amount
                      — a single global counter, the classic Linux/BSD stack
                      signature. See ``IPID_SEQUENTIAL_MAX_DELTA`` for why the
                      bound is not 1.
    - **random**    : no discernible pattern — modern firewalls and
                      middleboxes that randomize.
    - **unknown**   : fewer than two usable IP-IDs; cannot classify.

    Zero IDs are kept in the sequence rather than filtered out, so the
    "constant" test and the delta test see the same data. Filtering them for
    one test but not the other made ``[0, 5, 5]`` report "constant".
    """
    ip_ids = _collect_ip_ids(received_packets)

    if len(ip_ids) < 2:
        return "unknown"

    if len(set(ip_ids)) == 1:
        return "constant"

    # Wrap-aware deltas: a 16-bit counter rolling over 65535 → 3 is an
    # increment of 4, not a jump of -65532.
    deltas = [(b - a) % IPID_MODULUS for a, b in pairwise(ip_ids)]
    if all(0 < d <= IPID_SEQUENTIAL_MAX_DELTA for d in deltas):
        return "sequential"

    return "random"


def fingerprint_middlebox(sent, received, ipid_packets=None):
    """Apply two fingerprinting techniques to a hop's sent/received packets.

    GitHub issue #47. Returns a :class:`MiddleboxFingerprint` namedtuple:

    - ``mss_clamped``     : sent MSS > received MSS (MSS clamping by a NAT/DPI).
    - ``mss_clamp_value`` : the received MSS when clamped, else ``None``. When
                            it is one of :data:`MSS_CLAMP_VALUES` the rewrite
                            matches a well-known middlebox clamp.
    - ``ts_stripped``     : sent carries a TCP Timestamp option but the received
                            reply does not (TCP option stripping).
    - ``ipid_pattern``    : ``"constant"`` / ``"sequential"`` / ``"random"`` /
                            ``"unknown"`` — the entropy of the IP-ID field
                            for this hop.

    ``ipid_packets`` supplies the packet list used for the IP-ID analysis.
    It defaults to ``received``, but callers should pass every reply collected
    from the *same responding IP across all repeat probes at this hop*.
    IP-ID entropy is a property of the responder, not of one probe: tracevis
    records each repeat as its own result with at most one received packet, so
    classifying within a single result leaves ~99% of hops at "unknown".
    Aggregating per responder raised that from 22 to 155 classified hops
    across this repository's own captures.

    All analyses work on the JSON-serialized packet dicts produced by
    ``convert_packetlist.packet2json``. They are best-effort: when the needed
    fields are absent (e.g. ICMP time-exceeded packets that don't carry TCP
    options) the corresponding flag stays False.
    """
    mss_clamped = False
    mss_clamp_value = None
    ts_stripped = False

    sent_tcp = sent.get("TCP") if isinstance(sent, dict) else None
    if sent_tcp:
        sent_options = _parse_tcp_options(sent_tcp.get("options"))
        sent_mss = _extract_mss(sent_options)
        sent_has_ts = _has_timestamp_option(sent_options)

        for recv_pkt in reversed(received):
            recv_tcp = recv_pkt.get("TCP") if isinstance(recv_pkt, dict) else None
            if not recv_tcp:
                continue
            recv_options = _parse_tcp_options(recv_tcp.get("options"))
            recv_mss = _extract_mss(recv_options)
            if sent_mss is not None and recv_mss is not None and recv_mss < sent_mss:
                mss_clamped = True
                mss_clamp_value = recv_mss
            if sent_has_ts and not _has_timestamp_option(recv_options):
                ts_stripped = True
            break

    ipid_pattern = _classify_ipid_pattern(
        received if ipid_packets is None else ipid_packets)

    if not mss_clamped and not ts_stripped and ipid_pattern == "unknown":
        return NO_FINGERPRINT

    return MiddleboxFingerprint(
        mss_clamped=mss_clamped,
        mss_clamp_value=mss_clamp_value,
        ts_stripped=ts_stripped,
        ipid_pattern=ipid_pattern,
    )


def collect_hop_ipid_packets(hop_results):
    """Group every received packet at one hop by the IP that replied.

    ``hop_results`` is the ``result`` list of a single hop entry — one element
    per repeat probe. Returns ``{responder_ip: [packet, ...]}`` so
    :func:`fingerprint_middlebox` can classify IP-ID entropy per responder
    across all repeats instead of within a single probe.
    """
    per_responder = {}
    for result in hop_results:
        if not isinstance(result, dict):
            continue
        from_ip = result.get("from")
        if not from_ip or from_ip == "***":
            continue
        packets = result.get("packets")
        if not isinstance(packets, dict):
            continue
        received = packets.get("received")
        if not received:
            continue
        per_responder.setdefault(from_ip, []).extend(received)
    return per_responder


def detect_nat_pep_middlebox(sent, received):
    is_nat = False
    is_middlebox = False
    is_pep = False
    packet_type = ""
    tcpflag = ""
    if not 'ICMP' in received[0].keys():
        # sent packet 1 = {}
        # received packets = [
        #                     {received packet 1},
        #                     {received packet 2},
        #                     {received packet 3}
        #                    ]
        if 'TCP' in received[0].keys():
            if len(received) > 1:
                if received[0]['TCP']['flags'] == "A" and 'ICMP' in received[1].keys():
                    is_pep = True
                    packet_type = get_packet_type(received[1])
                    ip_id_is_same = received[1]['IP in ICMP']['id'] == sent['IP']['id']
                    calculated_chksum = calculate_chksum(
                        received[1]['IP in ICMP'], sent['IP']['ttl'])
                    if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
                        is_nat = True
                    if not ip_id_is_same:
                        is_pep = True  # todo xhdix: mark as $something else
                elif received[0]['TCP']['flags'] in ["R", "RA", "F", "FA"] and 'ICMP' in received[1].keys():
                    is_pep = True
                    is_middlebox = True
                    packet_type = get_packet_type(received[1])
                    ip_id_is_same = received[1]['IP in ICMP']['id'] == sent['IP']['id']
                    calculated_chksum = calculate_chksum(
                        received[1]['IP in ICMP'], sent['IP']['ttl'])
                    if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
                        is_nat = True
                    if not ip_id_is_same:
                        is_pep = True  # todo xhdix: mark as $something else
                elif received[0]['TCP']['flags'] in ["R", "RA", "F", "FA"]:
                    packet_type = get_packet_type(received[0])
                    tcpflag = received[0]['TCP']['flags']
                    if received[0]['IP']['id'] == sent['IP']['id']:
                        is_middlebox = True
                else:
                    packet_type = get_packet_type(received[1])
                    if packet_type == 'TCP':
                        tcpflag = received[1]['TCP']['flags']
                    if received[1]['IP']['id'] == sent['IP']['id']:
                        is_middlebox = True
            # we need hello from server, not ACK from middlebox
            elif received[0]['TCP']['flags'] != "A":
                packet_type = get_packet_type(received[0])
                tcpflag = received[0]['TCP']['flags']
                if received[0]['IP']['id'] == sent['IP']['id']:
                    is_middlebox = True
            # here we just want to have a correct path, so we ignore the lack of ACK before Server Hello in some weird networks
            elif received[0]['TCP']['flags'] == "A" and 'Raw' in received[0].keys():
                packet_type = get_packet_type(received[0])
                tcpflag = received[0]['TCP']['flags']
                if received[0]['IP']['id'] == sent['IP']['id']:
                    is_middlebox = True
            else:
                is_pep = True
        else:
            packet_type = get_packet_type(received[0])
            if received[0]['IP']['id'] == sent['IP']['id']:
                is_middlebox = True
    else:
        packet_type = 'ICMP'
        ip_id_is_same = received[0]['IP in ICMP']['id'] == sent['IP']['id']
        calculated_chksum = calculate_chksum(
            received[0]['IP in ICMP'], sent['IP']['ttl'])
        if calculated_chksum != sent['IP']['chksum'] and ip_id_is_same:
            is_nat = True
        if not ip_id_is_same:
            is_pep = True  # todo xhdix: mark as $something else
    return is_nat, is_middlebox, is_pep, packet_type, tcpflag


def parse_ttl(response_ttl, current_ttl):
    device_color = ""
    backttl = 0
    is_middlebox = False
    device_os_name = ""
    if response_ttl <= 20:
        backttl = int((current_ttl - response_ttl) / 2) + 1
        device_color = MIDDLEBOX_COLOR
        is_middlebox = True
        device_os_name = MIDDLEBOX_NAME
    elif response_ttl <= 64:
        backttl = 64 - response_ttl + 1
        device_color = LINUX_COLOR
        device_os_name = LINUX_NAME
    elif response_ttl <= 128:
        backttl = 128 - response_ttl + 1
        device_color = WINDOWS_COLOR
        device_os_name = WINDOWS_NAME
    else:
        backttl = 255 - response_ttl + 1
        device_color = ROUTER_COLOR
        device_os_name = ROUTER_NAME
    return backttl, device_color, device_os_name, is_middlebox


def visualize(previous_node_id, current_node_id,
              current_node_label, current_node_title, device_color,
              current_edge_title, requset_color, current_edge_label,
              current_node_shape):
    if not multi_directed_graph.has_node(current_node_id):
        multi_directed_graph.add_node(current_node_id,
                                      label=current_node_label, color=device_color,
                                      title=current_node_title, shape=current_node_shape)
    multi_directed_graph.add_edge(previous_node_id, current_node_id, label=current_edge_label,
                                  color=requset_color, title=current_edge_title)


def tooltips_append_lines(is_nat, is_middlebox, is_pep, packet_type, tcpflag,
                          dpi_cleared=False, cgnat_hop=False, sni_inspected=False,
                          rst_flood=False, tcp_silently_dropped=False,
                          forgery_evidence="", is_cgnat_hop=False,
                          allowlist_boundary=False, fingerprint=None):
    append_line = ''
    if packet_type == "TCP":
        append_line = "<br/>response TCP flag: " + tcpflag
    tooltip = ("<br/>NAT: " + str(is_nat)
            + "<br/>Middlebox: " + str(is_middlebox)
            + "<br/>PEP: " + str(is_pep)
            + "<br/>response packet: " + packet_type
            + append_line
            + "<br/>DPI cleared: " + str(dpi_cleared)
            + "<br/>CGNAT hop: " + str(cgnat_hop)
            + "<br/>SNI inspected: " + str(sni_inspected)
            + "<br/>RST flood: " + str(rst_flood)
            + "<br/>TCP silently dropped: " + str(tcp_silently_dropped)
            + ("<br/>REPLY FORGED: " + html.escape(forgery_evidence)
               if forgery_evidence else ""))
    if is_cgnat_hop:
        tooltip += "<br/>Per-hop CGNAT: True"
    if allowlist_boundary:
        tooltip += "<br/>Allowlist boundary: tier transition"
    # GitHub issue #47: middlebox fingerprint — TCP option mutation and
    # IP-ID entropy. Only shown when the fingerprint is non-trivial.
    if fingerprint is not None:
        if fingerprint.mss_clamped:
            tooltip += "<br/>MSS clamped: received MSS < sent MSS"
            if fingerprint.mss_clamp_value is not None:
                tooltip += " (" + str(fingerprint.mss_clamp_value)
                if fingerprint.mss_clamp_value in MSS_CLAMP_VALUES:
                    tooltip += ", a well-known clamp"
                tooltip += ")"
        if fingerprint.ts_stripped:
            tooltip += "<br/>TCP timestamps stripped"
        if fingerprint.ipid_pattern != "unknown":
            tooltip += "<br/>IP-ID pattern: " + fingerprint.ipid_pattern
    return tooltip


def styled_tooltips(
        current_request_color, current_ttl_str, backttl, request_ip, elapsed_ms,
        packet_size, repeat_step, device_os_name, append_lines, annotation):
    time_size = "*"
    elapsed_ms_str = "*"
    packet_size_str = "*"
    if packet_size != "*":
        packet_size_str = str(packet_size) + "B"
    if elapsed_ms != "*":
        elapsed_ms_str = str(format(elapsed_ms, '.3f')) + "ms"
        time_size = str(format(elapsed_ms/packet_size, '.3f')) + "ms/B"
    tooltips_str = "<pre style=\"color:" + current_request_color
    tooltips_str += "\">TTL: " + current_ttl_str
    tooltips_str += "<br/>Back-TTL: " + backttl
    tooltips_str += "<br/>Request to: " + request_ip
    tooltips_str += "<br/>annotation: " + annotation
    tooltips_str += "<br/>Time: " + elapsed_ms_str
    tooltips_str += "<br/>Size: " + packet_size_str
    tooltips_str += "<br/>Time/Size: " + time_size
    tooltips_str += "<br/>OS: " + device_os_name
    tooltips_str += append_lines
    tooltips_str += "<br/>Repeat step: " + repeat_step + "</pre>"
    return tooltips_str


def already_reached_destination_str(previous_node_id, dst_addr_id):
    if dst_addr_id in previous_node_id:
        return True
    else:
        return False


def initialize_detected(length_all):
    nodes = []
    for _ in range(length_all):
        nodes.append({"is_nat": False, "is_middlebox": False, "is_pep": False, "is_cgnat": False})
    return nodes


def initialize_first_nodes_nx(src_addr, length_all):
    nodes = []
    for _ in range(length_all):
        nodes.append(str(src_addr))
    return nodes


def _vp_identity(measurement):
    """Identify the vantage point a measurement came from.

    Prefers the explicit RIPE Atlas probe id; falls back to the source address
    so a locally-run multi-source capture still counts as distinct VPs.
    """
    return measurement.get("vp") or measurement.get("src_addr", "")


def _extract_vp_hop_sequence(measurement):
    """Return one responder set per hop, source to destination, for one VP.

    Reads the raw measurement JSON (the same dict ``vis()`` iterates over).
    Star hops (``"***"``) contribute nothing. The destination is appended as
    the final set so the comparison covers the full path.

    A *set per hop* rather than a flat list of every reply matters: tracevis
    sends ``--repeat`` probes per hop and records each as its own result, so a
    flat list repeated each IP once per probe. Two VPs that lost a different
    number of probes then had different list lengths and the positional
    suffix comparison silently misaligned. Sets also handle a load-balanced
    hop that answers from several addresses.

    Addresses are normalised through :func:`resolve_or_ip` so they match the
    node labels in the rendered graph, which are normalised the same way.
    Without this, a hostname destination (GitHub issue #68) produced a
    convergence set holding the hostname while the graph node was labelled
    with the resolved IP, and nothing ever matched.
    """
    hops = []
    for hop_entry in measurement.get("result", []):
        responders = set()
        for result in hop_entry.get("result", []):
            if not isinstance(result, dict):
                continue
            from_ip = result.get("from")
            if from_ip and from_ip != "***":
                responders.add(resolve_or_ip(from_ip))
        if responders:
            hops.append(responders)
    dst_addr = measurement.get("dst_addr", "")
    if dst_addr:
        dst_addr = resolve_or_ip(dst_addr)
        if not hops or dst_addr not in hops[-1]:
            hops.append({dst_addr})
    return hops


def _find_vp_convergence(measurements):
    """Find the convergence point across multiple VP traces.

    GitHub issue #44 (reverse traceroute). When tracing the same destination
    from N vantage points, the forward paths diverge near the VPs but converge
    toward the destination. The shared suffix — the last segment where *all*
    VPs agree — approximates the reverse/last-mile path that is common to every
    observation.

    Measurements are **grouped by destination** before comparison. A multi-VP
    capture holds one measurement per (VP × destination), and tracevis's core
    workflow compares an accessible and a blocked destination in one run. The
    previous version pooled every measurement regardless of destination, so
    the differing final hops broke the suffix walk immediately and the
    function returned an empty set for every real multi-destination capture —
    the flag rendered its legend and marked nothing.

    A destination only contributes if at least two *distinct* vantage points
    traced it; two runs from one VP share their whole path by construction and
    would flag the entire graph as a reverse-path leg.

    Returns the union of the shared suffixes across destinations, as a set of
    hop addresses. Returns an empty set when no destination was reached from
    two or more distinct VPs.
    """
    by_destination = {}
    for measurement in measurements:
        dst = resolve_or_ip(measurement.get("dst_addr", ""))
        by_destination.setdefault(dst, []).append(measurement)

    converged = set()
    for group in by_destination.values():
        if len({_vp_identity(m) for m in group}) < 2:
            continue

        sequences = [_extract_vp_hop_sequence(m) for m in group]
        if any(not seq for seq in sequences):
            continue

        # Walk backward from the destination while every VP still has a
        # responder in common at that position.
        min_len = min(len(seq) for seq in sequences)
        for i in range(1, min_len + 1):
            shared = set(sequences[0][-i])
            for seq in sequences[1:]:
                shared &= seq[-i]
            if not shared:
                break
            converged |= shared

    return converged


def save_measurement_graph(graph_name, attach_jscss, phase_overlay=False,
                           highlight_selected=False, renderer="visjs",
                           reverse_path=False, reverse_path_ips=None):
    renderer_obj = utils.renderer.get_renderer(renderer)
    result = renderer_obj.render(
        multi_directed_graph, graph_name,
        attach_jscss=attach_jscss, phase_overlay=phase_overlay,
        highlight_selected=highlight_selected,
        reverse_path=reverse_path,
        reverse_path_ips=reverse_path_ips)
    html_content = result.html
    graph_path = result.graph_path
    with open(graph_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print("saved: " + graph_path)


def count_cgnat_nodes(graph=None):
    """How many CGNAT (allowlist-boundary) nodes the rendered graph holds."""
    graph = multi_directed_graph if graph is None else graph
    return sum(1 for _, data in graph.nodes(data=True)
               if data.get("color") == CGNAT_COLOR)


def mark_allowlisted_tier(graph=None):
    """Backlog §2.4: flag every node downstream of a CGNAT allowlist boundary.

    The CGNAT hop is where a path leaves the operator's allowlisted tier, so
    everything reachable *after* it is inside that tier. §2.3 shipped the
    boundary itself (a teal hexagon) and the tier-transition edge label; this
    is the band behind it, which was the half left open.

    Marking is a union over all CGNAT nodes: a node reached post-boundary from
    any vantage point belongs to the band, even when another VP reached the
    same node without crossing one. ``nx.descendants`` follows directed edges
    only, so this is the downstream cone and not the whole graph, and it
    terminates on a routing cycle by construction.

    Boundary nodes are excluded from their own band — they are already drawn
    distinctly, and a second CGNAT hop downstream of the first should keep
    reading as a boundary rather than dissolving into the tier behind it.

    Sets ``allowlisted_tier=True`` and returns how many nodes were marked.
    Styling is deliberately left to the renderer: this records the finding,
    and each backend draws it in its own idiom.
    """
    graph = multi_directed_graph if graph is None else graph
    boundaries = {node for node, data in graph.nodes(data=True)
                  if data.get("color") == CGNAT_COLOR}
    tier = set()
    for node in boundaries:
        tier |= nx.descendants(graph, node)
    tier -= boundaries
    for node in tier:
        graph.nodes[node]["allowlisted_tier"] = True
    return len(tier)


def count_allowlisted_tier_nodes(graph=None):
    """How many nodes mark_allowlisted_tier() has flagged."""
    graph = multi_directed_graph if graph is None else graph
    return sum(1 for _, data in graph.nodes(data=True)
               if data.get("allowlisted_tier"))


def _inject_phase_overlay(html_content, cgnat_nodes=None, tier_nodes=None):
    """Backlog §2.4: inject a phase/tier overlay legend into the rendered graph.

    vis.js positions nodes dynamically at render time, so a CSS band cannot be
    anchored to specific nodes. Instead the overlay is a legend indicator: a
    coloured box with explanatory text that appears in the graph corner,
    telling the operator that teal hexagon nodes mark the allowlisted tier
    boundary.

    ``cgnat_nodes`` is how many CGNAT hops the graph actually contains. The
    legend used to be a fixed caption, so it announced "teal hex = CGNAT
    boundary" over graphs holding no teal hexagon at all. It now says what was
    found, and says so plainly when the answer is nothing.

    ``tier_nodes`` is how many nodes ``mark_allowlisted_tier`` flagged as
    downstream of that boundary — the band the renderer outlines in teal.
    Reporting it matters because the band is often most of the graph: when
    the CGNAT sits at hop 2, nearly every node really is behind it, and a
    reader needs the count to tell "the tier is wide" from "the marking is
    broken".
    """
    if cgnat_nodes is None:
        caption = "(teal hex = CGNAT boundary)"
    elif cgnat_nodes == 0:
        caption = "(no CGNAT boundary on this path)"
    elif cgnat_nodes == 1:
        caption = "(1 teal hex = CGNAT boundary)"
    else:
        caption = f"({cgnat_nodes} teal hexes = CGNAT boundary)"
    if tier_nodes:
        plural = "" if tier_nodes == 1 else "s"
        caption += f"\n{tier_nodes} node{plural} behind it"
    elif tier_nodes == 0:
        caption += "\nno nodes behind it"
    overlay_html = (
        '<div id="phase-overlay" style="'
        'position:fixed;top:30px;right:20px;'
        'width:140px;'
        'background:rgba(46,139,87,0.85);'
        'color:#fff;padding:8px;border-radius:8px;'
        'font-size:12px;font-family:sans-serif;'
        'border:2px solid #20b2aa;z-index:1000;">'
        'Allowlisted tier<br/>'
        '<span style="font-size:10px;">'
        + html.escape(caption).replace("\n", "<br/>") + '</span>'
        '</div>'
    )
    insertion_point = html_content.find("</body>")
    if insertion_point == -1:
        insertion_point = len(html_content)
    return html_content[:insertion_point] + overlay_html + html_content[insertion_point:]


def _inject_edge_highlight(html_content):
    """GitHub issue #2: inject edge-click path highlighting into the rendered graph.

    Clicking an edge highlights the entire upstream path from the source node
    to that edge. Clicking the background (no node/edge) clears the highlight.
    """
    js = """
    <script>
    (function() {
        if (typeof network === 'undefined' || !network) return;
        var HIGHLIGHT = '#ff9500';
        // Remember each element's own colour before overwriting it. Setting
        // the colour back to `undefined` on clear does not restore anything —
        // it drops the element to the vis.js default and permanently destroys
        // the DPI / forgery / OS colour coding after a single click.
        var savedEdgeColors = {};
        var savedNodeColors = {};

        function paintEdge(id) {
            if (!(id in savedEdgeColors)) {
                var e = edges.get(id);
                savedEdgeColors[id] = e ? e.color : undefined;
            }
            edges.update({id: id, color: HIGHLIGHT});
        }
        function paintNode(id) {
            if (!(id in savedNodeColors)) {
                var n = nodes.get(id);
                savedNodeColors[id] = n ? n.color : undefined;
            }
            nodes.update({id: id, color: HIGHLIGHT});
        }
        function clearHighlight() {
            Object.keys(savedEdgeColors).forEach(function(id) {
                edges.update({id: id, color: savedEdgeColors[id]});
            });
            Object.keys(savedNodeColors).forEach(function(id) {
                nodes.update({id: id, color: savedNodeColors[id]});
            });
            savedEdgeColors = {};
            savedNodeColors = {};
        }
        function highlightPathToEdge(edgeId) {
            clearHighlight();
            var edge = edges.get(edgeId);
            if (!edge) return;
            // A traced path can contain a routing loop, and a multi-VP graph
            // gives most nodes several parents. Without a visited set the
            // upstream walk revisits an edge forever and hangs the tab, with
            // a DataSet update (and redraw) on every iteration.
            var seenEdges = {};
            var currentEdge = edgeId;
            paintNode(edge.to);
            while (currentEdge !== undefined && !seenEdges[currentEdge]) {
                seenEdges[currentEdge] = true;
                paintEdge(currentEdge);
                var e = edges.get(currentEdge);
                if (!e || !e.from) break;
                paintNode(e.from);
                var incoming = edges.get({
                    returnType: "id",
                    filter: function(e2) { return e2.to === e.from; }
                });
                currentEdge = undefined;
                if (incoming) {
                    // Prefer an edge we have not walked yet, so parallel
                    // edges between the same pair do not end the walk early.
                    for (var i = 0; i < incoming.length; i++) {
                        if (!seenEdges[incoming[i]]) {
                            currentEdge = incoming[i];
                            break;
                        }
                    }
                }
            }
        }
        network.on("click", function(params) {
            if (params.edges.length > 0 && params.nodes.length === 0) {
                highlightPathToEdge(params.edges[0]);
            } else {
                clearHighlight();
            }
        });
    })();
    </script>"""
    insertion_point = html_content.find("</body>")
    if insertion_point == -1:
        insertion_point = len(html_content)
    return html_content[:insertion_point] + js + html_content[insertion_point:]


def _inject_reverse_path_legend(html_content):
    """GitHub issue #44: inject a legend explaining the reverse-path edges."""
    legend_html = (
        '<div id="reverse-path-legend" style="'
        'position:fixed;top:60px;right:20px;'
        'background:rgba(255,165,0,0.9);'
        'color:#000;padding:8px;border-radius:8px;'
        'font-size:12px;font-family:sans-serif;'
        'border:2px solid #ff8c00;z-index:1000;">'
        'Reverse-path leg<br/>'
        '<span style="font-size:10px;">'
        '(VP convergence)</span>'
        '</div>'
    )
    insertion_point = html_content.find("</body>")
    if insertion_point == -1:
        insertion_point = len(html_content)
    return html_content[:insertion_point] + legend_html + html_content[insertion_point:]


# Network states in which the rendered page cannot count on reaching a CDN.
# "shutdown" is a total block; "allowlisted" means only a permitted set of
# destinations resolves, and cdnjs.cloudflare.com is not usually on it.
CENSORED_NETWORK_STATES = frozenset({"shutdown", "allowlisted"})


def observed_censored_states(measurements):
    """Return the censored network states recorded in a measurement list."""
    return {
        state for state in (
            m.get("network_state", "") for m in measurements
            if isinstance(m, dict)
        )
        if state in CENSORED_NETWORK_STATES
    }


def needs_offline_assets(measurements):
    """True when the graph must embed its JS/CSS instead of linking a CDN.

    ``template_main.html.jinja`` pulls vis.js and vis.css from
    cdnjs.cloudflare.com. On the networks this tool exists to measure that
    host is exactly what is unreachable, and the operator is left with a
    blank page.

    This used to be driven solely by ``no_internet``, which GitHub issue #75
    redefined: a DNS answer now proves the network is up, so a DNS-hijacked
    shutdown reports ``no_internet=False`` and the CDN fallback stopped
    firing on the one network that most needs it. Deciding from the recorded
    ``network_state`` instead keeps issue #75's connectivity fix intact and
    also covers rendering a saved measurement later with ``-f``, where no
    live connectivity check happens at all.
    """
    return bool(observed_censored_states(measurements))


def source_node_id(src_addr, vp_id=None):
    """Graph node id for a vantage point's source address.

    The id carries the VP when one is known, because RIPE Atlas probes report
    their *private* address (the sample capture has 192.168.178.26 and
    192.168.254.43). Two probes on different LANs can easily report the same
    RFC 1918 address, and keying the node on the address alone silently merged
    them into one source with no way to tell them apart.
    """
    numeric = _node_id_or_label(src_addr)
    if vp_id:
        return numeric + "vp" + str(vp_id)
    return numeric


def build_request_colors(all_measurements):
    """Return a per-measurement colour list, keyed by vantage point when present.

    Two problems this fixes.

    Indexing ``REQUEST_COLORS`` directly by measurement number raised
    ``IndexError`` past the twelfth measurement. That is not a corner case for
    ``--vps``: ``utils.ripe_atlas.MEASUREMENT_IDS`` holds nine measurement ids
    and ``download_multi_from_atlas`` loops probes x ids, so **two probes can
    produce eighteen measurements** and the render died with a traceback after
    the download had already been saved. The index now wraps.

    The colour also did not mean what ``--vps`` advertised. It was assigned per
    measurement, so with the accessible/blocked destination pair that tracevis
    exists to compare, one vantage point got two different colours and no
    colour identified a VP. When any measurement carries a ``vp``, colour is
    assigned per distinct VP instead, which is what "per-VP colour-coded edges"
    was supposed to mean. Without VPs the per-measurement behaviour is kept.
    """
    identities = [m.get("vp") for m in all_measurements]
    if any(identities):
        order = []
        for vp_id in identities:
            key = vp_id if vp_id else None
            if key not in order:
                order.append(key)
        return [REQUEST_COLORS[order.index(vp if vp else None)
                               % len(REQUEST_COLORS)]
                for vp in identities]
    return [REQUEST_COLORS[i % len(REQUEST_COLORS)]
            for i in range(len(all_measurements))]


class MeasurementFormatError(ValueError):
    """A capture file that cannot be rendered, carrying a reason to print.

    `vis()` used to dereference the file's shape directly -- `json.load`,
    then `all_measurements[0]["src_addr"]` -- so every malformed input left
    an unhandled traceback on the operator's terminal instead of a sentence:
    `JSONDecodeError` for a truncated file, `IndexError` for `[]`, `KeyError`
    for a JSON object rather than a list. A capture arriving truncated is an
    ordinary outcome on the networks this tool measures, so its own reader
    should not be the thing that breaks.
    """


# The fields `vis()` actually dereferences rather than reads with `.get()`.
# Checked against every measurement in this repository's captures -- 96 of
# them -- so requiring these cannot reject a file the tool used to render.
REQUIRED_MEASUREMENT_FIELDS = ("src_addr", "dst_addr", "result")


def load_measurements(measurement_path):
    """Read a capture, or raise MeasurementFormatError saying what is wrong.

    Validates only the shape that rendering depends on. Anything else absent
    is the renderer's business and is already handled with defaults -- an
    over-strict reader would reject captures that render perfectly well.
    """
    try:
        with open(measurement_path, encoding="utf-8") as json_file:
            data = json.load(json_file)
    except OSError as exc:
        raise MeasurementFormatError(
            f"cannot read {measurement_path}: {exc}") from exc
    except ValueError as exc:
        raise MeasurementFormatError(
            f"{measurement_path} is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise MeasurementFormatError(
            f"{measurement_path} holds a JSON {type(data).__name__}, not the "
            "list of measurements a capture is")
    if not data:
        raise MeasurementFormatError(
            f"{measurement_path} holds no measurements")

    for index, measurement in enumerate(data):
        where = f"{measurement_path}: measurement {index}"
        if not isinstance(measurement, dict):
            raise MeasurementFormatError(
                f"{where} is a {type(measurement).__name__}, not a JSON object")
        missing = [field for field in REQUIRED_MEASUREMENT_FIELDS
                   if field not in measurement]
        if missing:
            raise MeasurementFormatError(
                f"{where} is missing " + ", ".join(missing))
        hops = measurement["result"]
        if not isinstance(hops, list) or not hops:
            raise MeasurementFormatError(
                f"{where} has no hops in `result`")
        # vis() indexes result[0]["result"] to size the repeat loop.
        first = hops[0]
        if not isinstance(first, dict) or not first.get("result"):
            raise MeasurementFormatError(
                f"{where} has a first hop with no probe results")
    return data


def vis(measurement_path, attach_jscss, edge_lable: str = "none",
        phase_overlay: bool = False, highlight_selected: bool = False,
        renderer="visjs", reverse_path=False):
    # The graph is module-level, and nothing used to clear it: a second call in
    # the same process rendered the first measurement's nodes into the second
    # file. The CLI renders once per run so it never surfaced there, but it made
    # `vis()` wrong as a function and impossible to test in isolation.
    multi_directed_graph.clear()
    try:
        all_measurements = load_measurements(measurement_path)
    except MeasurementFormatError as exc:
        print("Error!\n" + str(exc))
        return False
    if not attach_jscss and needs_offline_assets(all_measurements):
        print("· · · - · network state is "
              + ", ".join(sorted(observed_censored_states(all_measurements)))
              + ": embedding JS/CSS so the graph opens without a CDN")
        attach_jscss = True
    measurement_steps = 0
    src_addr = all_measurements[0]["src_addr"]
    src_addr = resolve_or_ip(src_addr)
    # Colour is assigned per vantage point when the capture has any, and per
    # measurement otherwise. See build_request_colors() for why.
    request_colors = build_request_colors(all_measurements)
    for measurement in all_measurements:
        curr_src_addr = measurement.get("src_addr", src_addr)
        curr_src_addr = resolve_or_ip(curr_src_addr)
        curr_src_id = source_node_id(curr_src_addr, measurement.get("vp"))
        if curr_src_id not in multi_directed_graph:
            vp_label = "source address"
            vp_id = measurement.get("vp")
            if vp_id:
                vp_label = f"source (VP {vp_id})"
            multi_directed_graph.add_node(
                curr_src_id, label=curr_src_addr,
                color="Chocolate", title=vp_label, shape="diamond")
        dst_addr = measurement["dst_addr"]
        dst_addr = resolve_or_ip(dst_addr)
        dst_addr_id = _node_id_or_label(dst_addr)
        annotation = "-"
        if "annotation" in measurement.keys():
            annotation = measurement["annotation"]
        vp_id = measurement.get("vp")
        if vp_id:
            annotation = f"VP {vp_id}" + (f" / {annotation}" if annotation != "-" else "")
        ioda_status = measurement.get("ioda_status")
        if ioda_status and isinstance(ioda_status, dict):
            cc = ioda_status.get("country", "")
            if ioda_status.get("outage"):
                annotation = (f"{annotation} / IODA[{cc}]:"
                              f" outage (value={ioda_status.get('latest_value', '?')})")
        all_results = measurement["result"]
        results_repeat_length = len(all_results[0]["result"])
        previous_node_ids = initialize_first_nodes_nx(
            curr_src_id, results_repeat_length)
        already_detected = initialize_detected(results_repeat_length)
        for try_step in all_results:  # will be up to 255
            current_ttl = try_step["hop"]
            current_ttl_str = str(current_ttl)
            results = try_step["result"]
            # GitHub issue #47: IP-ID entropy is a property of the responder,
            # so gather every reply from each responding IP across all repeat
            # probes at this hop before classifying any single one of them.
            hop_ipid_packets = collect_hop_ipid_packets(results)
            repeat_steps = 0
            skip_next = False
            for result in results:
                if skip_next:
                    skip_next = False
                    continue
                not_yet_destination = not (already_reached_destination_str(
                    previous_node_ids[repeat_steps], dst_addr_id))
                if not_yet_destination:
                    if "late" in result.keys():
                        skip_next = True
                    current_node_label = "***"
                    current_edge_title = "***"
                    current_edge_label = ""
                    current_node_id = "0"
                    current_node_shape = "dot"
                    elapsed_ms = "*"
                    packet_size = "*"
                    backttl = "*"
                    device_color = NO_RESPONSE_COLOR
                    device_name = NO_RESPONSE_NAME
                    append_lines = ""
                    is_middlebox = False
                    is_forged_reply = False
                    # Set only inside the branch that has received packets to
                    # analyse, but read unconditionally further down. A hop
                    # that answered while carrying an empty `packets.received`
                    # -- which RIPE Atlas data and any capture written without
                    # packet blobs both produce -- reached that read with the
                    # name unbound and took the whole render down with an
                    # UnboundLocalError. Predates §2.1; found by rendering an
                    # IPv6 capture, but nothing about it is family-specific.
                    is_allowlist_boundary = False
                    if 'x' in result.keys():
                        current_node_id = (
                            "unknown" + previous_node_ids[repeat_steps] + "x")
                        if edge_lable != "none":
                            current_edge_label = "*"
                        # A star hop can still carry a reason — a TCP handshake
                        # refused by an injected RST or an ICMP prohibited sends
                        # no data packet, so there is no answer to draw, but
                        # "nothing came back" and "a box said no" are different
                        # findings and the graph should not show them alike.
                        if result.get("note"):
                            append_lines += "<br/>" + html.escape(result["note"])
                    else:
                        answer_ip = result["from"]
                        backttl, device_color, device_name, is_middlebox_ttl = parse_ttl(
                            result["ttl"], current_ttl)
                        if "rtt" in result.keys():
                            elapsed_ms = result["rtt"]
                        if edge_lable == "rtt":
                            if elapsed_ms != "*":
                                current_edge_label = format(elapsed_ms, '.3f')
                        elif edge_lable == "backttl":
                            current_edge_label = str(backttl)
                        current_node_id = _node_id_or_label(answer_ip)
                        current_node_label = answer_ip
                        packet_size = result.get("size", "*")
                        if "packets" in result.keys():
                            if "received" in result['packets'].keys():
                                if len(result['packets']['received']) != 0:
                                    is_nat, is_middlebox, is_pep, packet_type, tcpflag = detect_nat_pep_middlebox(
                                        result['packets']['sent'], result['packets']['received']
                                    )
                                    # GitHub issue #47: two new middlebox
                                    # fingerprinting techniques — TCP option
                                    # mutation (MSS clamping, timestamp
                                    # stripping) and IP-ID entropy analysis.
                                    # The IP-ID sample is every reply this
                                    # responder sent across all repeat probes
                                    # at this hop, not just this one probe's.
                                    fingerprint = fingerprint_middlebox(
                                        result['packets']['sent'],
                                        result['packets']['received'],
                                        ipid_packets=hop_ipid_packets.get(
                                            answer_ip))
                                    # M4 per-hop
                                    # DPI/CGNAT/SNI posture. Combine the
                                    # path-level struct fields (set in trace.py)
                                    # with the per-hop NAT/PEP/middlebox evidence
                                    # and the probe's L4 proto/port.
                                    path_cgnat = bool(measurement.get("cgnat_hop", False))
                                    path_cleared = bool(measurement.get("dpi_cleared", False))
                                    path_sni = bool(measurement.get("sni_inspected", False))
                                    path_rst_flood = bool(measurement.get("rst_flood", False))
                                    path_tcp_drop = bool(measurement.get("tcp_silently_dropped", False))
                                    reply_forged = bool(measurement.get("reply_forged", False))
                                    forgery_evidence = measurement.get("forgery_evidence", "")
                                    probe_proto = measurement.get("proto", "")
                                    # Prefer the port this hop actually probed:
                                    # with RST backoff the path-level `port` is
                                    # only where the trace started, and the
                                    # sni_inspected gate gates on dport == 443.
                                    hop_dport = result.get("dport")
                                    probe_dport = int(
                                        hop_dport if hop_dport is not None
                                        else (measurement.get("port", -1) or -1))
                                    rst_count = result.get("rst_count", 0)
                                    # Measurements written before the struct
                                    # carried `network_state` are read the old
                                    # way — back then `cgnat_hop` was true only
                                    # in an allowlisted regime, so the inference
                                    # held. It no longer does for new files.
                                    path_state = measurement.get("network_state") or (
                                        "allowlisted" if path_cgnat else "open")
                                    cgnat_observed = utils.dpi.is_cgnat_address(
                                        answer_ip)
                                    _hop = utils.dpi.classify_dpi_path(
                                        is_nat=is_nat,
                                        is_middlebox=is_middlebox or is_middlebox_ttl,
                                        is_pep=is_pep,
                                        network_state=path_state,
                                        sent_proto=probe_proto,
                                        sent_dport=probe_dport,
                                        rst_count=rst_count,
                                        cgnat_observed=cgnat_observed,
                                    )
                                    dpi_cleared = path_cleared or (_hop.dpi_cleared and not path_sni)
                                    cgnat_hop = path_cgnat or _hop.cgnat_hop
                                    sni_inspected = path_sni or _hop.sni_inspected
                                    rst_flood = path_rst_flood or _hop.rst_flood
                                    tcp_silently_dropped = path_tcp_drop or _hop.tcp_silently_dropped
                                    # Backlog §2.3: CGNAT is the allowlist
                                    # boundary — render it distinctly from generic
                                    # NAT so the tier transition is visible.
                                    is_allowlist_boundary = (
                                        cgnat_observed and path_state == "allowlisted"
                                    )
                                    if (is_middlebox_ttl or is_middlebox
                                            ) and not already_detected[repeat_steps]["is_middlebox"]:
                                        pass  # we decide about it later
                                    elif cgnat_observed and not already_detected[repeat_steps]["is_cgnat"]:
                                        device_color = CGNAT_COLOR
                                        device_name = CGNAT_NAME
                                        current_node_shape = CGNAT_SHAPE
                                        already_detected[repeat_steps]["is_cgnat"] = True
                                        if current_node_id != dst_addr_id:
                                            current_node_id = "cgnat" + current_node_id + "x"
                                    elif is_pep and not already_detected[repeat_steps]["is_pep"]:
                                        device_color = PEP_COLOR
                                        device_name = PEP_NAME
                                        current_node_shape = "star"
                                        already_detected[repeat_steps]["is_pep"] = True
                                        if current_node_id != dst_addr_id:
                                            current_node_id = "pep" + current_node_id + "x"
                                    elif is_nat and not already_detected[repeat_steps]["is_nat"]:
                                        device_color = NAT_COLOR
                                        device_name = NAT_NAME
                                        already_detected[repeat_steps]["is_nat"] = True
                                        if current_node_id != dst_addr_id:
                                            current_node_id = "nat" + current_node_id + "x"
                                    elif (sni_inspected
                                          and not (is_pep or is_nat
                                                   or is_middlebox_ttl or is_middlebox)
                                          and not already_detected[repeat_steps]["is_middlebox"]):
                                        # Path-level SNI inspection on a hop not
                                        # already tagged PEP/NAT/middlebox.
                                        device_color = DPI_COLOR
                                        device_name = DPI_NAME
                                        current_node_shape = "diamond"
                                        already_detected[repeat_steps]["is_middlebox"] = True
                                    # Backlog §2.12: this reply claims to come
                                    # from the destination and did not. Drawing
                                    # it as the destination would put the
                                    # censor's box on the graph wearing the
                                    # destination's name, which is exactly the
                                    # confusion the detector exists to remove.
                                    is_forged_reply = (
                                        reply_forged and answer_ip == dst_addr)
                                    append_lines = tooltips_append_lines(
                                        is_nat, is_middlebox, is_pep, packet_type, tcpflag,
                                        dpi_cleared=dpi_cleared, cgnat_hop=cgnat_hop,
                                        sni_inspected=sni_inspected, rst_flood=rst_flood,
                                        tcp_silently_dropped=tcp_silently_dropped,
                                        forgery_evidence=forgery_evidence,
                                        is_cgnat_hop=cgnat_observed,
                                        allowlist_boundary=is_allowlist_boundary,
                                        fingerprint=fingerprint)
                                    if (is_middlebox_ttl or is_middlebox):
                                        already_detected[repeat_steps]["is_middlebox"] = True
                                    if is_pep:
                                        already_detected[repeat_steps]["is_pep"] = True
                                    if is_nat:
                                        already_detected[repeat_steps]["is_nat"] = True
                                    if cgnat_observed:
                                        already_detected[repeat_steps]["is_cgnat"] = True
                                if is_forged_reply:
                                    # Takes precedence over the generic middlebox
                                    # marking below, which `parse_ttl` already
                                    # raises for any reply under TTL 20 — true
                                    # here, but it says "some box" where this
                                    # says "a box answering in the destination's
                                    # name", and carries the evidence for it.
                                    current_node_id = "forged" + current_node_id + "x"
                                    current_node_shape = "triangleDown"
                                    device_color = FORGED_COLOR
                                    device_name = FORGED_NAME
                                    already_detected[repeat_steps]["is_middlebox"] = True
                                elif is_middlebox_ttl or is_middlebox:
                                    current_node_id = "middlebox" + current_node_id + "x"
                                    current_node_shape = "star"
                                    device_color = MIDDLEBOX_COLOR
                                    device_name = MIDDLEBOX_NAME
                                    already_detected[repeat_steps]["is_middlebox"] = True
                                elif current_node_id == dst_addr_id:
                                    current_node_shape = "square"
                                    # Backlog §2.4: phase/tier overlay annotation on
                                # the edge that crosses into the allowlisted tier.
                                # Append rather than replace. The guard used
                                # to be `not current_edge_label`, and the
                                # default --label backttl always sets one, so
                                # the boundary marker was invisible in normal
                                # use -- it only appeared under --label none.
                                if is_allowlist_boundary:
                                    current_edge_label = (
                                        f"{current_edge_label} → allowlisted tier"
                                        if current_edge_label
                                        else "→ allowlisted tier")
                    repeat_step_str = str(repeat_steps + 1)
                    current_edge_title = styled_tooltips(
                        current_request_color=(
                            request_colors[measurement_steps]),
                        current_ttl_str=current_ttl_str, backttl=str(backttl),
                        request_ip=dst_addr, elapsed_ms=elapsed_ms,
                        packet_size=packet_size, repeat_step=repeat_step_str,
                        device_os_name=device_name, append_lines=append_lines,
                        annotation=annotation
                    )
                    visualize(
                        previous_node_ids[repeat_steps], current_node_id,
                        current_node_label, device_name, device_color,
                        current_edge_title, request_colors[measurement_steps],
                        current_edge_label, current_node_shape
                    )
                    previous_node_ids[repeat_steps] = current_node_id
                repeat_steps += 1
        measurement_steps += 1
    print("saving measurement graph...")
    # Backlog §2.4: the tier band is gated on --phase-overlay, the flag that
    # already owns the tier/phase visualisation. Default rendering is left
    # exactly as it was.
    if phase_overlay:
        tier_nodes = mark_allowlisted_tier()
        if tier_nodes:
            print("· · · - · allowlisted tier: " + str(tier_nodes)
                  + " node(s) downstream of the CGNAT boundary")
        else:
            print("· · · - · allowlisted tier: no CGNAT boundary on this "
                  "capture; no band to draw")
    reverse_path_ips = None
    if reverse_path:
        reverse_path_ips = _find_vp_convergence(all_measurements)
        if reverse_path_ips:
            print("· · · - · reverse-path convergence: "
                  + str(len(reverse_path_ips)) + " shared hop(s)")
        else:
            # Say so rather than rendering a legend for edges that do not
            # exist. The usual cause is a capture with only one vantage point
            # per destination, which has nothing to cross-reference.
            print("· · · - · --reverse-path: no destination was traced from "
                  "two or more vantage points; nothing to mark")
    save_measurement_graph(measurement_path, attach_jscss,
                           phase_overlay=phase_overlay,
                           highlight_selected=highlight_selected,
                           renderer=renderer,
                           reverse_path=reverse_path,
                           reverse_path_ips=reverse_path_ips)
    print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
    # `tracevis.py` has always read this as a success flag
    # (`if utils.vis.vis(...): print("finished.")`), but the function returned
    # None, so the branch was dead and a completed render said nothing. It
    # matters now beyond the missing line: --monitor decides whether a run
    # counted, and inferring that from a falsy return would mark every
    # successful run as failed.
    return True
