#!/usr/bin/env python3

import html
import ipaddress
import json
import os
import socket

import networkx as nx
import pyvis._version
from pyvis.network import Network

import utils.convert_packetlist
import utils.dpi

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
    """Resolve a hostname to an IPv4 address, or pass through if already an IP.

    Fixes GitHub issue #68: vis() crashes when src_addr or dst_addr is a
    hostname instead of an IPv4 address.
    """
    try:
        ipaddress.IPv4Address(addr)
        return addr
    except (ipaddress.AddressValueError, ValueError):
        pass
    try:
        return socket.gethostbyname(addr)
    except socket.gaierror:
        return addr


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
                          allowlist_boundary=False):
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


def save_measurement_graph(graph_name, attach_jscss, phase_overlay=False):
    net_vis = Network("1500px", "1500px",
                      directed=True, bgcolor="#eeeeee")
    if pyvis._version.__version__ > '0.1.9':
        net_vis.from_nx(multi_directed_graph, show_edge_weights=False)
    else:
        net_vis.from_nx(multi_directed_graph)
    net_vis.set_edge_smooth('dynamic')
    if attach_jscss:
        net_vis.set_template(OFFLINE_TEMPLATE_PATH)
    else:
        net_vis.set_template(MAIN_TEMPLATE_PATH)
    if graph_name.endswith(".json"):
        graph_name = graph_name[:-5]
    graph_path = graph_name + ".html"
    html_content = net_vis.generate_html()
    if phase_overlay:
        html_content = _inject_phase_overlay(html_content)
    with open(graph_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print("saved: " + graph_path)


def _inject_phase_overlay(html_content):
    """Backlog §2.4: inject a phase/tier overlay legend into the rendered graph.

    vis.js positions nodes dynamically at render time, so a CSS band cannot be
    anchored to specific nodes. Instead the overlay is a legend indicator: a
    coloured box with explanatory text that appears in the graph corner,
    telling the operator that teal hexagon nodes mark the allowlisted tier
    boundary.
    """
    overlay_html = (
        '<div id="phase-overlay" style="'
        'position:fixed;top:30px;right:20px;'
        'width:140px;'
        'background:rgba(46,139,87,0.85);'
        'color:#fff;padding:8px;border-radius:8px;'
        'font-size:12px;font-family:sans-serif;'
        'border:2px solid #20b2aa;z-index:1000;">'
        'Allowlisted tier<br/>'
        '<span style="font-size:10px;">(teal hex = CGNAT boundary)</span>'
        '</div>'
    )
    insertion_point = html_content.find("</body>")
    if insertion_point == -1:
        insertion_point = len(html_content)
    return html_content[:insertion_point] + overlay_html + html_content[insertion_point:]


def vis(measurement_path, attach_jscss, edge_lable: str = "none",
        phase_overlay: bool = False):
    # The graph is module-level, and nothing used to clear it: a second call in
    # the same process rendered the first measurement's nodes into the second
    # file. The CLI renders once per run so it never surfaced there, but it made
    # `vis()` wrong as a function and impossible to test in isolation.
    multi_directed_graph.clear()
    all_measurements = []
    with open(measurement_path) as json_file:
        all_measurements = json.load(json_file)
    measurement_steps = 0
    src_addr = all_measurements[0]["src_addr"]
    src_addr = resolve_or_ip(src_addr)
    src_addr_id = 'x' + str(int(ipaddress.IPv4Address(src_addr))) + 'x'
    multi_directed_graph.add_node(
        src_addr_id, label=src_addr, color="Chocolate", title="source address",
        shape="diamond")
    for measurement in all_measurements:
        curr_src_addr = measurement.get("src_addr", src_addr)
        curr_src_addr = resolve_or_ip(curr_src_addr)
        curr_src_id = 'x' + str(
            int(ipaddress.IPv4Address(curr_src_addr))) + 'x'
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
        dst_addr_id = 'x' + str(int(ipaddress.IPv4Address(dst_addr))) + 'x'
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
                        current_node_id = 'x' + str(
                            int(ipaddress.IPv4Address(answer_ip))) + 'x'
                        current_node_label = answer_ip
                        packet_size = result.get("size", "*")
                        if "packets" in result.keys():
                            if "received" in result['packets'].keys():
                                if len(result['packets']['received']) != 0:
                                    is_nat, is_middlebox, is_pep, packet_type, tcpflag = detect_nat_pep_middlebox(
                                        result['packets']['sent'], result['packets']['received']
                                    )
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
                                        allowlist_boundary=is_allowlist_boundary)
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
                                if is_allowlist_boundary and not current_edge_label:
                                    current_edge_label = "→ allowlisted tier"
                    repeat_step_str = str(repeat_steps + 1)
                    current_edge_title = styled_tooltips(
                        current_request_color=(
                            REQUEST_COLORS[measurement_steps]),
                        current_ttl_str=current_ttl_str, backttl=str(backttl),
                        request_ip=dst_addr, elapsed_ms=elapsed_ms,
                        packet_size=packet_size, repeat_step=repeat_step_str,
                        device_os_name=device_name, append_lines=append_lines,
                        annotation=annotation
                    )
                    visualize(
                        previous_node_ids[repeat_steps], current_node_id,
                        current_node_label, device_name, device_color,
                        current_edge_title, REQUEST_COLORS[measurement_steps],
                        current_edge_label, current_node_shape
                    )
                    previous_node_ids[repeat_steps] = current_node_id
                repeat_steps += 1
        measurement_steps += 1
    print("saving measurement graph...")
    save_measurement_graph(measurement_path, attach_jscss,
                           phase_overlay=phase_overlay)
    print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
