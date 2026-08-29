#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import platform
import sys
import textwrap
from copy import deepcopy

import utils.arms
import utils.csv
import utils.dns
import utils.iface
import utils.ioda
import utils.monitor
import utils.packet_input
import utils.portpool
import utils.reassembly
import utils.ripe_atlas
import utils.sni
import utils.timing
import utils.trace
import utils.vis

TIMEOUT = 1
MAX_TTL = 50
REPEAT_REQUESTS = 3
DEFAULT_OUTPUT_DIR = "./tracevis_data/"
OS_NAME = platform.system()

# Probe modes whose *meaning* is their destination port: UDP/53, TCP/53,
# TCP/853 and the UDP/53 dnstt carrier. Rewriting the port on these does not
# move the probe somewhere safer, it stops it being a DNS probe at all —
# nothing answers on UDP/2053, so the run silently measures the reachability of
# an arbitrary port instead. `--sni-test` and the packet samples are the
# 443-shaped probes the port pool exists for.
PORT_BOUND_MODES = ("dns", "dnstcp", "dnsdot", "dnstt")


def reject_non_ipv4_targets(request_ips):
    """Return the targets that are not IPv4 addresses (GitHub issue #69).

    tracevis probes IPv4 only — `utils/ephemeral_port.py` binds `AF_INET`,
    `utils/traceroute_struct.py` fixes `af=4`, `utils/vis.py` parses every hop
    as `IPv4Address` and `utils/packet_input.py` rejects non-IPv4 packets. But
    nothing validated the target list, so an IPv6 literal passed to `-i` was
    accepted here and failed later inside scapy or the renderer, well away from
    the thing that caused it.

    `--ipv4` is therefore an explicit, checked assertion of what the tool
    already does, and this is what makes the flag act rather than merely parse:
    a target that is not IPv4 is named and the run stops before probing.
    """
    rejected = []
    for target in request_ips:
        try:
            ipaddress.IPv4Address(str(target).strip())
        except (ipaddress.AddressValueError, ValueError):
            rejected.append(str(target))
    return rejected


def use_default_targets(default_resolvers):
    """Fall back to the curated destination pool, and say what it is.

    The pool is not a list of equals: it pairs a field-confirmed reachable
    control with destinations chosen to fail differently (see `utils/dns.py`).
    A run that prints three addresses and no roles invites reading the result as
    "one of three resolvers worked" rather than as the comparison it is.
    """
    targets = utils.dns.filter_blackholed(default_resolvers)
    print("· · · - · default targets: " + utils.dns.describe_targets(targets))
    return targets


def combine_json_files(json_list_files):
    print("saving combined json file...")
    all_measurements = []
    for json_list_file in json_list_files:
        for json_file in json_list_file:
            print("· - · · · adding: " + json_file)
            with open(json_file) as json_file:
                for measurement in json.load(json_file):
                    all_measurements.append(measurement)
    print("· · · - ·      · · · - ·      · · · - ·      · · · - · ")
    combined_data_path = json_list_files[0][0].replace(
        ".json", "_combined.json")
    with open(combined_data_path, "w") as combined_jsonfile:
        combined_jsonfile.write(json.dumps(all_measurements,
                                           default=lambda o: o.__dict__))
    print("saved: " + combined_data_path)
    print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
    return combined_data_path


def dump_args_to_file(file, args, packet_info):
    print("saving measurement config...")
    args_without_config_arg = args.copy()
    if 'config_file' in args_without_config_arg:
        del args_without_config_arg['config_file']
    if packet_info:
        args_without_config_arg['packet_data'] = packet_info.as_dict()
        args_without_config_arg['packet_input_method'] = 'json'
    with open(file, 'w') as f:
        json.dump(args_without_config_arg, f, indent=4, sort_keys=True)
    print("saved: " + file)
    print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")


def process_input_args(args, parser):
    cli_args_dict = vars(args)
    passed_args = {
        opt.dest
        for opt in parser._option_string_actions.values()
        if hasattr(args, opt.dest) and opt.default != getattr(args, opt.dest)
    }
    args_dict = cli_args_dict.copy()
    if args.config_file:
        with open(args.config_file) as f:
            args_dict.update(json.load(f))
    for k in passed_args:
        args_dict[k] = cli_args_dict.get(k)
    _DNS_FAMILY = ('dns', 'dnstcp', 'dnsdot', 'dnstt')
    if any(flag in passed_args for flag in _DNS_FAMILY):
        args_dict['packet'] = False
        args_dict['packet_input_method'] = None
    if 'packet' in passed_args:
        args_dict['dns'] = False
        args_dict['dnstcp'] = False
        args_dict['dnsdot'] = False
        args_dict['dnstt'] = False
    return args_dict


def get_args(sys_args, auto_exit=True):
    parser = argparse.ArgumentParser(
        description='Traceroute with any packet. \
            Visualize the routes. Discover Middleboxes and Firewalls', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--config-file', type=str, default=None,
                        help='Load configuration from file'),
    parser.add_argument('-n', '--name', action='store',
                        help="prefix for the graph file name")
    parser.add_argument('-i', '--ips', type=str,
                        help="add comma-separated IPs (up to 6 for two packet and up to 12 for one packet)")
    parser.add_argument('-p', '--packet', action='store_true',
                        help="receive one or two packets from the IP layer via the terminal input and trace route with")
    parser.add_argument('--packet-input-method', dest='packet_input_method', choices=['json', 'hex', 'interactive'], default="hex",
                        help=textwrap.dedent("""Select packet input method 
- json: load packet data from a json/file(set via --packet-data)
- hex: paste hex dump of packet into interactive shell 
- interactive: use full featured scapy and python console to craft packet\n\n"""))
    parser.add_argument("--packet-data", dest='packet_data', type=str,
                        help="Packet json data if input method is 'json' (use @file to load from file)", default=None)
    parser.add_argument('--dns', action='store_true',
                        help="trace route with a simple DNS over UDP packet")
    parser.add_argument('--dnstcp', action='store_true',
                        help="trace route with a simple DNS over TCP packet")
    parser.add_argument('--dnsdot', action='store_true',
                        help="trace route with a DNS-over-TLS probe (TCP/853)")
    parser.add_argument('--dnstt', action='store_true',
                        help="trace route with a dnstt probe (DNS over UDP/53)")
    parser.add_argument('--sni-test', dest='sni_test', action='store_true',
                        help="test SNI filtering: send a TLS ClientHello over "
                             "TCP/443 and detect RST injection")
    parser.add_argument('-c', '--continue', action='store_true',
                        help="further TTL advance after reaching the endpoint (up to max ttl)")
    parser.add_argument('-m', '--maxttl', type=int,
                        help="set max TTL (up to 255, default: 50)")
    parser.add_argument('-t', '--timeout', type=int,
                        help="set timeout in seconds for each request (default: 1 second)")
    parser.add_argument('-r', '--repeat', type=int,
                        help="set the number of repetitions of each request (default: 3 steps)")
    parser.add_argument('-R', '--ripe', type=str,
                        help="download the latest traceroute measuremets of a RIPE Atlas probe via ID and visualize")
    parser.add_argument('-V', '--vps', type=str,
                        help="comma-separated RIPE Atlas probe IDs for multi-VP download (§2.2). "
                             "Downloads the same measurement from each probe and renders "
                             "them in one combined graph, one edge colour per vantage "
                             "point.")
    parser.add_argument('--ioda-country', dest='ioda_country', type=str,
                        default=None,
                        help="cross-check a RIPE Atlas VP against IODA outage status "
                             "for this 2-letter country code (default: IR). Only used with --vps.")
    parser.add_argument('-I', '--ripemids', type=str,
                        help="add comma-separated RIPE Atlas measurement IDs (up to 12)")
    parser.add_argument('-f', '--file', type=str, action='append', nargs='+',
                        help="open a measurement file and visualize")
    parser.add_argument('--csv', action='store_true',
                        help="create a sorted csv file instead of visualization")
    parser.add_argument('--csvraw', action='store_true',
                        help="create a raw csv file instead of visualization")
    parser.add_argument('-a', '--attach', action='store_true',
                        help="attach VisJS javascript and CSS to the HTML file (work offline)")
    parser.add_argument('-l', '--label', type=str,
                        help="set edge label: none, rtt, backttl. (default: backttl)")
    parser.add_argument('--domain1', type=str,
                        help="change the default accessible domain name (dns trace)")
    parser.add_argument('-d', '--domain2', type=str,
                        help="change the default blocked domain name (dns trace)")
    parser.add_argument('--annot1', type=str,
                        help="annotation for the first packets (dns and packet trace)")
    parser.add_argument('--annot2', type=str,
                        help="annotation for the second packets (dns and packet trace)")
    parser.add_argument('--rexmit', action='store_true',
                        help="same as rexmit option (only one packet. all TTL steps, same stream)")
    parser.add_argument('--paris', action='store_true',
                        help="same as 'new,rexmit' option (like Paris-Traceroute)")
    parser.add_argument('--port', type=int,
                        help="change the destination port in the packets")
    # resilient timing + port rotation. Exposed on the CLI (in
    # addition to config-file) so users can opt in without a config file; CLI
    # wins over config per process_input_args' passed_args override.
    parser.add_argument('--port-pool', dest='port_pool', type=str, default=None,
                        help="CSV of clean (non-443-leaning) ports to rotate "
                             "through; ignored if --port is set")
    parser.add_argument('--timeout-profile', dest='timeout_profile', type=str,
                        default=None, choices=['fast', 'degraded', 'shutdown'],
                        help="named RTT profile: fast(1s)/degraded(3s)/"
                             "shutdown(60s); explicit --timeout "
                             "wins")
    parser.add_argument('--adaptive-timeout', dest='adaptive_timeout',
                        action='store_true',
                        help="grow the per-hop timeout toward the last observed "
                             "RTT, bounded by 60s; off by default so "
                             "existing runs keep their timing")
    parser.add_argument('--anonymize', dest='anonymize', action='store_true',
                        help="also pseudonymise RFC1918 hops in the saved "
                             "measurement. Your own source address "
                             "is removed either way; this drops the shape of "
                             "your access network too, so it is opt-in. CGNAT "
                             "hops are kept — they are the carrier's, and the "
                             "cgnat_hop detector reads them back")
    parser.add_argument('--network-mode', dest='network_mode', type=str,
                        default="auto",
                        choices=['open', 'allowlisted', 'shutdown', 'auto'],
                        help="override network-state behaviour: "
                             "open/allowlisted/shutdown short-circuit or run full "
                             "detection; 'auto' = detect (default)")
    parser.add_argument('--phase-overlay', dest='phase_overlay',
                        action='store_true',
                        help="show an allowlisted-tier overlay legend on the "
                             "rendered graph (backlog §2.4)")
    parser.add_argument('--highlight-selected', dest='highlight_selected',
                        action='store_true',
                        help="click an edge in the rendered graph to highlight "
                             "the upstream path to it (GitHub issue #2)")
    parser.add_argument('--renderer', dest='renderer', default="visjs",
                        choices=["visjs", "plotly"],
                        help="graphing backend for the rendered HTML "
                        "(GitHub issue #64; default: visjs)")
    parser.add_argument('--reverse-path', dest='reverse_path',
                        action='store_true',
                        help="detect VP convergence and mark the shared "
                        "last-mile segment as a reverse-path leg "
                        "(GitHub issue #44; needs a measurement holding the "
                        "same destination from 2+ vantage points, via --vps "
                        "or several -f files)")
    parser.add_argument('--reassembly-probe', dest='reassembly_probe',
                        type=str, default=None,
                        help="probe whether a middlebox reassembles the TCP "
                             "stream, and how long it holds the buffer "
                             "(backlog 1.4, rescoped -- see "
                             "docs/rescope-1.4-reassembly.md). Takes "
                             "IP:PORT. Needs root. NOT validated against live "
                             "DPI; treat its verdicts as provisional.")
    parser.add_argument('--compare-arms', dest='compare_arms',
                        action='store_true',
                        help="compare paired control/treatment probes in the "
                             "measurement and report what each pair supports "
                             "(backlog 2.10). Works on a fresh trace or on an "
                             "existing capture via -f.")
    parser.add_argument('--monitor', dest='monitor', action='store_true',
                        help="repeat the trace on an interval and report what "
                             "changed between runs (backlog 2.7). Applies to "
                             "live traces only; -f/--ripe/--vps read a "
                             "capture that already exists.")
    parser.add_argument('--monitor-interval', dest='monitor_interval', type=int,
                        default=utils.monitor.DEFAULT_INTERVAL,
                        help="seconds between monitored runs "
                             f"(default: {utils.monitor.DEFAULT_INTERVAL})")
    parser.add_argument('--monitor-runs', dest='monitor_runs', type=int,
                        default=0,
                        help="how many monitored runs to make; 0 (the default) "
                             "runs until interrupted")
    parser.add_argument('--ipv4', dest='ipv4', action='store_true',
                        help="require every probe target to be IPv4, and stop "
                             "before probing if one is not. tracevis is "
                             "IPv4-only throughout; this makes that explicit "
                             "and checked (GitHub issue #69)")
    # this argument ('-o', '--options') will be changed or removed before v1.0.0
    parser.add_argument('-o', '--options', type=str, default="new",
                        help=""" (this argument will be changed or removed before v1.0.0)
change the behavior of the trace route 
- 'rexmit' : to be similar to doing retransmission with incremental TTL (only one packet, one destination)
- 'new' : to change source port, sequence number, etc in each request (default)
- 'new,rexmit' : to begin with the 'new' option in each of the three steps for all destinations and then rexmit"""
                        )
    parser.add_argument('--iface', type=str,
                        help="set the target network interface name or index mumber")
    parser.add_argument('--show-ifaces', action='store_true',
                        help="show the network interfaces")
    if len(sys_args) == 0 and auto_exit:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args(sys_args)
    args_dict = process_input_args(args, parser)
    return args_dict


def render_measurement(args, measurement_path, attach_jscss, edge_lable,
                       input_packet):
    """Dump the run's config beside its capture and render the graph.

    Extracted so the monitored loop renders each run exactly the way a
    one-shot run does, rather than growing a second, drifting copy.
    """
    if not args.get("file"):
        config_dump_file_name = f"{os.path.splitext(measurement_path)[0]}.conf"
        dump_args_to_file(config_dump_file_name, args, input_packet)
    return utils.vis.vis(
        measurement_path=measurement_path, attach_jscss=attach_jscss,
        edge_lable=edge_lable,
        phase_overlay=bool(args.get("phase_overlay")),
        highlight_selected=bool(args.get("highlight_selected")),
        renderer=args.get("renderer", "visjs"),
        reverse_path=bool(args.get("reverse_path")))


def run_reassembly_probe(target, accessible_address):
    """Backlog §1.4 (rescoped): measure a middlebox's stream reassembly.

    Returns the sweep result, or None if the target could not be parsed. The
    verdict is printed with an explicit note that nothing here has been run
    against live DPI -- the classifier is only as good as the assumption that
    a silent probe means a dropped one, and that assumption is the part a
    restricting network still has to confirm.
    """
    host, _, port = target.partition(":")
    try:
        ipaddress.IPv4Address(host.strip())
        dport = int(port) if port else 443
    except (ValueError, ipaddress.AddressValueError):
        print(f"Error!\n--reassembly-probe expects IP:PORT, got: {target}")
        return None

    packet_1, _annot1, _packet_2, _annot2 = utils.sni.make_sni_packets(
        blocked_address=accessible_address or "www.example.com",
        accessible_address=accessible_address or "www.example.com")
    payload = bytes(packet_1[utils.sni.Raw].load) \
        if packet_1.haslayer(utils.sni.Raw) else b""
    if not payload:
        print("Error!\n--reassembly-probe could not build a ClientHello")
        return None

    source_ip = utils.trace.user_source_ip_address
    sender = utils.reassembly.make_scapy_sender(
        host.strip(), dport, source_ip)
    result = utils.reassembly.probe_reassembly(sender, payload)
    print()
    print(utils.reassembly.format_sweep(result))
    return result


def report_arm_comparison(measurement_path):
    """Backlog §2.10: compare paired control/treatment probes in a capture.

    Printed rather than written into the measurement: it is an interpretation
    of the data, and interpretations belong beside the data rather than inside
    it, where a later re-read could not tell the two apart.
    """
    try:
        with open(measurement_path, encoding="utf-8") as handle:
            measurements = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"· · · - · --compare-arms: could not read the measurement: {exc}")
        return None
    if not isinstance(measurements, list):
        print("· · · - · --compare-arms: not a measurement list")
        return None
    verdicts = utils.arms.compare_arms(measurements)
    print()
    print(utils.arms.format_arms(verdicts))
    return verdicts


def run_monitored_session(args, trace_kwargs, edge_lable, input_packet,
                          output_dir):
    """Backlog §2.7: trace on an interval and report what moved between runs.

    Each run is traced and rendered as it completes, so an interrupted session
    still leaves a usable graph for everything already measured. The trend is
    printed at the end and written beside the captures.
    """
    interval = int(args.get("monitor_interval") or utils.monitor.DEFAULT_INTERVAL)
    runs = int(args.get("monitor_runs") or 0)
    print(f"· · · - · monitor: every {interval}s, "
          + (f"{runs} run(s)" if runs else "until interrupted"))

    def one_run():
        was_successful, measurement_path, no_internet = utils.trace.trace_route(
            **trace_kwargs)
        if not was_successful:
            return None
        render_measurement(args, measurement_path, bool(no_internet),
                           edge_lable, input_packet)
        return measurement_path

    records = utils.monitor.run_monitor(one_run, runs=runs, interval=interval)
    paths = [record.path for record in records if record.ok and record.path]
    failed = [record for record in records if not record.ok]
    if failed:
        print(f"· · · - · monitor: {len(failed)} of {len(records)} run(s) failed")
    if len(paths) < 2:
        print("· · · - · monitor: fewer than two completed runs; "
              "nothing to compare")
        return records
    summaries = [utils.monitor.summarise_measurement(path) for path in paths]
    report = utils.monitor.format_trend(utils.monitor.build_trend(summaries))
    print()
    print(report)
    trend_path = os.path.join(output_dir, "monitor-trend.txt")
    try:
        with open(trend_path, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")
        print("saved: " + trend_path)
    except OSError as exc:
        print(f"· · · - · monitor: could not write the trend: {exc}")
    return records


def main(args):
    if args.get('packet_data') and isinstance(args.get('packet_data'), str):
        if args.get('packet_data')[0] == '@':
            with open(args.get('packet_data')[1:]) as f:
                args['packet_data'] = json.load(f)
        else:
            args['packet_data'] = json.loads(args.get('packet_data'))
    input_packet = None
    name_prefix = ""
    continue_to_max_ttl = False
    max_ttl = MAX_TTL
    timeout = TIMEOUT
    repeat_requests = REPEAT_REQUESTS
    attach_jscss = False
    request_ips = []
    packet_1 = None
    annotation_1 = ""
    do_tcph1 = False
    packet_2 = None
    annotation_2 = ""
    do_tcph2 = False
    blocked_address = ""
    accessible_address = ""
    do_traceroute = False
    was_successful = False
    measurement_path = ""
    edge_lable = "backttl"
    trace_retransmission = False
    trace_with_retransmission = False
    network_mode = args.get("network_mode", "auto")
    iface = None
    dst_port = -1
    port_pool_ports = None
    output_dir = os.getenv('TRACEVIS_OUTPUT_DIR', DEFAULT_OUTPUT_DIR)
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if args.get("name"):
        name_prefix = args["name"] + "-"
    if args.get("ips"):
        request_ips = args["ips"].replace(' ', '').split(',')
    if args.get("domain1"):
        accessible_address = args["domain1"]
    if args.get("domain2"):
        blocked_address = args["domain2"]
    if args.get("continue"):
        continue_to_max_ttl = True
    if args.get("maxttl"):
        max_ttl = args["maxttl"]
    if args.get("timeout"):
        timeout = args["timeout"]
    # pick the base timeout from a named profile when no
    # explicit --timeout is supplied. Settable from a config file or, since
    # M5a, the --timeout-profile flag; an explicit --timeout still wins.
    timeout_profile = args.get("timeout_profile")
    if timeout_profile:
        timeout = utils.timing.resolve_timeout(
            profile=timeout_profile, explicit=args.get("timeout"))
    if args.get("repeat"):
        repeat_requests = args["repeat"]
    if args.get("attach"):
        attach_jscss = True
    if args.get("annot1"):
        annotation_1 = args["annot1"]
    if args.get("annot2"):
        annotation_2 = args["annot2"]
    if args.get("label"):
        edge_lable = args["label"].lower()
    if args.get("rexmit"):
        trace_retransmission = True
    if args.get("paris"):
        trace_with_retransmission = True
    if args.get("port"):
        dst_port = args["port"]
    # when no explicit --port is set, rotate a clean
    # (non-443-leaning) port pool. Picking one rotated port at trace start moves
    # the probe off the aggressively-inspected port 443. Settable
    # from a config file or, since M5a, the --port-pool flag; live per-hop
    # RST-backoff rotation is provided by utils.portpool.PortRandomizer and
    # wired in a later milestone.
    port_pool_spec = args.get("port_pool")
    # A port-bound probe (see PORT_BOUND_MODES) cannot be moved off its port
    # without ceasing to be that probe. The pool is a convenience — "pick a
    # clean port for me" — so it is dropped rather than honoured here. An
    # explicit --port is a deliberate instruction and is still obeyed, with a
    # warning, because "is UDP/2053 reachable at all?" is a legitimate question.
    port_bound_modes = [mode for mode in PORT_BOUND_MODES if args.get(mode)]
    if port_bound_modes:
        named = ", ".join("--" + mode for mode in port_bound_modes)
        if port_pool_spec:
            print(f"Notice: --port-pool is ignored with {named}: rewriting the "
                  "destination port would stop this being a DNS probe (nothing "
                  "answers there). Use it with --sni-test or a packet sample.")
            port_pool_spec = None
        if dst_port != -1:
            print(f"Warning: --port overrides the port {named} is defined by, "
                  "so this measures reachability of that port, not DNS.")
    if port_pool_spec and dst_port == -1:
        try:
            ports = utils.portpool.parse_port_pool(port_pool_spec)
            dst_port = utils.portpool.PortRandomizer(ports=ports).next_port()
            port_pool_ports = ports
            print("· · · - · selected port from pool: " + str(dst_port))
        except ValueError as exc:
            print(f"Notice: invalid port_pool ({exc}); ignoring")
    if args.get("options"):
        trace_options = args["options"].replace(' ', '').split(',')
        if "new" in trace_options and "rexmit" in trace_options:
            print("Notice: this argument will be changed or removed before v1.0.0")
            print("use --paris intead")
            trace_with_retransmission = True
        elif "rexmit" in trace_options:
            print("Notice: this argument will be changed or removed before v1.0.0")
            print("use --rexmit intead")
            trace_retransmission = True
        else:
            pass  # "new" is default
    if args.get("iface"):
        iface = utils.iface.get_iface_object(args["iface"])
    if args.get("show_ifaces"):
        utils.iface.show_ifaces()
        sys.exit()
    if args.get("dns") or args.get("dnstcp") or args.get("dnsdot") or args.get("dnstt"):
        do_traceroute = True
        name_prefix += "dns"
        if args.get("dnsdot"):
            packet_1, annotation_1, packet_2, annotation_2 = utils.dns.get_dot_packets(
                blocked_address=blocked_address, accessible_address=accessible_address)
            default_resolvers = utils.dns.DOT_RESOLVERS
        elif args.get("dnstt"):
            packet_1, annotation_1, packet_2, annotation_2 = utils.dns.get_dnstt_packets(
                blocked_address=blocked_address, accessible_address=accessible_address)
            default_resolvers = utils.dns.DNSTT_RESOLVERS
        else:
            packet_1, annotation_1, packet_2, annotation_2 = utils.dns.get_dns_packets(
                blocked_address=blocked_address, accessible_address=accessible_address,
                dns_over_tcp=(args["dnstcp"]))
            default_resolvers = utils.dns.DEFAULT_DNS_RESOLVERS
        if len(request_ips) == 0:
            request_ips = use_default_targets(default_resolvers)
    if args.get("sni_test"):
        do_traceroute = True
        name_prefix += "sni"
        packet_1, annotation_1, packet_2, annotation_2 = utils.sni.make_sni_packets(
            blocked_address=blocked_address, accessible_address=accessible_address)
        do_tcph1 = True
        do_tcph2 = True
        default_resolvers = utils.dns.DOT_RESOLVERS
        if len(request_ips) == 0:
            request_ips = use_default_targets(default_resolvers)
    if args.get("packet") or args.get("rexmit"):
        do_traceroute = True
        name_prefix += "packet"
        try:
            if args.get('packet_input_method') == 'json':
                input_packet = utils.packet_input.InputPacketInfo.from_json(
                    OS_NAME, trace_retransmission, packet_data=deepcopy(
                        args.get('packet_data'))
                )
            elif args.get('packet_input_method') == 'interactive':
                input_packet = utils.packet_input.InputPacketInfo.from_scapy(
                    OS_NAME, trace_retransmission)
            elif args.get('packet_input_method') == 'hex':
                input_packet = utils.packet_input.InputPacketInfo.from_stdin(
                    OS_NAME, trace_retransmission)
            else:
                raise RuntimeError("Bad input type")
        except (utils.packet_input.BADPacketException, utils.packet_input.FirewallException) as e:
            print(f"{e!s}")
            sys.exit(1)
        except Exception as e:
            print(f"Error!\n{e!s}")
            sys.exit(2)
        if do_tcph1 or do_tcph2:
            name_prefix += "-tcph"
    if trace_with_retransmission:
        name_prefix += "-paristr"
    if args.get("ipv4"):
        rejected = reject_non_ipv4_targets(request_ips)
        if rejected:
            print("Error!\n--ipv4 was requested but these targets are not "
                  "IPv4 addresses: " + ", ".join(rejected))
            sys.exit(1)
        print("· · · - · --ipv4: " + str(len(request_ips))
              + " target(s) confirmed IPv4")
    if args.get("reassembly_probe"):
        run_reassembly_probe(args["reassembly_probe"], accessible_address)
        return
    if do_traceroute:
        try:
            if args.get("packet") or args.get("rexmit"):
                with input_packet as ctx:
                    packet_1, packet_2, do_tcph1, do_tcph2 = ctx
            trace_kwargs = {
                "ip_list": request_ips, "request_packet_1": packet_1,
                "output_dir": output_dir, "max_ttl": max_ttl,
                "timeout": timeout, "repeat_requests": repeat_requests,
                "request_packet_2": packet_2, "name_prefix": name_prefix,
                "annotation_1": annotation_1, "annotation_2": annotation_2,
                "continue_to_max_ttl": continue_to_max_ttl,
                "do_tcph1": do_tcph1, "do_tcph2": do_tcph2,
                "trace_retransmission": trace_retransmission,
                "trace_with_retransmission": trace_with_retransmission,
                "iface": iface, "dst_port": dst_port,
                "network_mode": network_mode, "port_pool": port_pool_ports,
                "adaptive_timeout": bool(args.get("adaptive_timeout")),
                "anonymize": bool(args.get("anonymize")),
            }
            if args.get("monitor"):
                # Backlog §2.7. Returns instead of falling through: a monitored
                # session renders each run as it completes and closes with the
                # trend, so there is no single measurement left for the
                # one-shot path below to render.
                run_monitored_session(args, trace_kwargs, edge_lable,
                                      input_packet, output_dir)
                return
            was_successful, measurement_path, no_internet = utils.trace.trace_route(
                **trace_kwargs)
        except KeyboardInterrupt:
            # Don't let Ctrl-C silently discard an in-progress trace: flush
            # whatever partial hops were collected so the user keeps the graph.
            print()
            measurement_path = utils.trace.save_partial_measurement(
                output_dir=output_dir, name_prefix=name_prefix,
                continue_to_max_ttl=continue_to_max_ttl)
            was_successful = bool(measurement_path)
            no_internet = False
        except Exception as e:
            print(f"Error!\n{e!s}")
            sys.exit(2)
        if no_internet:
            attach_jscss = True
    if args.get("vps"):
        measurement_ids = ""
        if args.get("ripemids"):
            measurement_ids = args["ripemids"].replace(' ', '').split(',')
        name_prefix = name_prefix + "ripe-atlas-multi"
        was_successful, measurement_path = utils.ripe_atlas.download_multi_from_atlas(
            probe_ids=args["vps"], output_dir=output_dir, name_prefix=name_prefix,
            measurement_ids=measurement_ids)
        ioda_country = args.get("ioda_country") or "IR"
        if was_successful:
            try:
                status = utils.ioda.fetch_ioda_status(ioda_country)
                print(f"IODA status for {ioda_country}: "
                      f"available={status['available']} "
                      f"outage={status['outage']} "
                      f"value={status['latest_value']}")
                # Write it into the capture as well. Printing alone left the
                # cross-check invisible in the graph: utils.vis reads
                # measurement["ioda_status"] and nothing ever set it.
                annotated = utils.ioda.annotate_measurements(
                    measurement_path, status)
                if annotated:
                    print(f"· · · - · IODA[{status['country']}] recorded on "
                          f"{annotated} measurement(s)")
                elif status.get("error"):
                    print("· · · - · IODA unavailable, not recorded: "
                          + str(status["error"]))
            except Exception as e:
                print(f"IODA fetch failed: {e}")
    if args.get("ripe"):
        measurement_ids = ""
        if args.get("ripemids"):
            measurement_ids = args["ripemids"].replace(' ', '').split(',')
        name_prefix = name_prefix + "ripe-atlas"
        was_successful, measurement_path = utils.ripe_atlas.download_from_atlas(
            probe_id=args["ripe"], output_dir=output_dir, name_prefix=name_prefix,
            measurement_ids=measurement_ids)
    if args.get("file"):
        try:
            # -f filename*.json
            #       [['filename1.json','filename2.json','filename3.json',]]
            #
            # -f filename1.json -f filename2.json
            #       [['filename1.json'],['filename2.json']]
            #
            if len(args["file"]) > 1 or len(args["file"][0]) > 1:
                measurement_path = combine_json_files(args["file"])
            else:
                measurement_path = args["file"][0][0]
        except Exception as e:
            print(f"Error!\n{e!s}")
            sys.exit(1)
        if args.get("csv"):
            utils.csv.json2csv(measurement_path)
        elif args.get("csvraw"):
            utils.csv.json2csv(measurement_path, False)
        else:
            was_successful = True
    if was_successful and args.get("compare_arms"):
        report_arm_comparison(measurement_path)
    if was_successful and render_measurement(
            args, measurement_path, attach_jscss, edge_lable, input_packet):
        print("finished.")


if __name__ == "__main__":
    main(get_args(sys.argv[1:]))
