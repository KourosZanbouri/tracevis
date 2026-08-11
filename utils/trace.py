#!/usr/bin/env python3
from __future__ import absolute_import, unicode_literals

import json
import platform
import sys
import time
from copy import deepcopy
from datetime import datetime
from time import sleep

from scapy.all import (DNS, ICMP, IP, TCP, UDP, PacketList, RandInt, RandShort,
                       Raw, SndRcvList, conf, get_if_addr, send, sr, sr1)

import utils.anonymize
import utils.dpi
import utils.ephemeral_port
import utils.forgery
import utils.geolocate
import utils.portpool
import utils.timing
from utils.traceroute_struct import traceroute_data

LOCALHOST = '127.0.0.1'
SLEEP_TIME = 1
OS_NAME = platform.system()

# TCP RST flood threshold for DPI reset injection.
DEFAULT_RST_THRESHOLD = 3

# Appended to a measurement's annotation when the `--paris` preflight handshake
# failed, so the JSON records that the arm replayed a bare SYN rather than the
# configured data packet.
PREFLIGHT_FAILED_NOTE = " [preflight handshake failed — SYN replayed]"

# scapy >= 2.6 deletes `iface` from every layer-3 send and warns
# (`SyntaxWarning: 'iface' has no effect on L3 I/O sr()`), because an L3 socket
# picks its interface from the routing table, not from the call. Passing it
# printed three warnings at the head of every run and did nothing, so the
# interface is now steered the only way that works at L3: `conf.iface` (see
# `Tracer._select_iface`) plus the source address already written into IP.src.


# --- legacy module-level mirror (backlog §2.6) -------------------------------
# Trace state now lives on `Tracer`. These names are kept because they are the
# module's published surface: `tracevis.py` calls `save_partial_measurement`
# after `trace_route` has already raised, and the tests read the collected data
# back through the module. A running `Tracer` republishes them (`_publish`), and
# because `measurement_data` is rebound to the *same list object* the tracer
# appends to, the mirror stays live for the duration of a trace rather than
# being a stale copy.
have_2_packet = False
user_iface = conf.iface
user_source_ip_address = get_if_addr(user_iface)
measurement_data = [[], []]

# The tracer currently publishing into the mirror, or None. `_mirror_tracer`
# hands this back rather than rebuilding, so the interrupt path reaches the real
# run's state — `anonymize` and the classification context live there and a
# reconstructed tracer has neither.
_active_tracer = None


def choose_desirable_packet(request_and_answers, do_tcphandshake):
    # request_and_answers.summary()
    summary_postfix = str(request_and_answers.summary)
    print("    " + summary_postfix)
    if do_tcphandshake and not request_and_answers[0][1].haslayer(ICMP):
        desirable_packet = None
        # [0][0] = sent packet 1 -- [0][1] == received packet 1
        # [1][0] = sent packet 1 -- [1][1] == received packet 2
        # [2][0] = sent packet 1 -- [2][1] == received packet 3
        if len(request_and_answers) > 1:
            if request_and_answers[0][1][TCP].flags == "A" and request_and_answers[1][1].haslayer(ICMP):
                # todo xhdix: flag the first hop as a middlebox
                desirable_packet = request_and_answers[1]
            # todo xhdix: flag as middlebox if [0][1][TCP].flags in ["R", "RA", "F", "FA"] and [1][1].haslayer(ICMP
            elif request_and_answers[0][1][TCP].flags in ["R", "RA", "F", "FA"]:
                desirable_packet = request_and_answers[0]
            else:
                desirable_packet = request_and_answers[1]
        # we need hello from server, not ACK from middlebox
        elif request_and_answers[0][1][TCP].flags != "A":
            desirable_packet = request_and_answers[0]
        # here we just want to have a correct path, so we ignore the lack of ACK before Server Hello in some weird networks
        elif request_and_answers[0][1][TCP].flags == "A" and request_and_answers[0][1].haslayer(Raw):
            desirable_packet = request_and_answers[0]
        else:
            return None, ""
        return desirable_packet, summary_postfix
    else:
        desirable_packet = request_and_answers[0]
        return desirable_packet, ""


def guess_back_ttl(current_ttl, ttl):
    backttl = 0
    if ttl <= 20:
        backttl = int((current_ttl - ttl) / 2) + 1
    elif ttl <= 64:
        backttl = 64 - ttl + 1
    elif ttl <= 128:
        backttl = 128 - ttl + 1
    else:
        backttl = 255 - ttl + 1
    return backttl


def count_rst_responses(request_and_answers):
    """Count TCP RST responses in a list of (sent, received) answer pairs.

    multiple RSTs on the same flow indicate active DPI
    reset injection (e.g. SNI-triggered blocking on port 443).
    """
    rst_count = 0
    for sent, received in request_and_answers:
        if received is not None and received.haslayer(TCP):
            flags = received[TCP].flags
            if flags == "R" or flags == "RA" or "R" in str(flags):
                rst_count += 1
    return rst_count


def find_syn_ack(request_and_answers):
    """Return the (sent, received) pair whose reply is a real SYN-ACK, else None.

    A SYN is not only ever answered by a SYN-ACK. A filtering middlebox answers
    with an ICMP error and a DPI answers with an injected RST —
    `sr()` matches both to the SYN, so the answer list is *not* empty and the
    handshake still has not happened.
    """
    for _, received in request_and_answers:
        if received is None or not received.haslayer(TCP):
            continue
        flags = str(received[TCP].flags)
        if "S" in flags and "A" in flags:
            return received
    return None


def describe_answer(request_and_answers):
    """One-line description of what came back, for the operator and the JSON."""
    for _, received in request_and_answers:
        if received is not None:
            return received.summary()
    return "nothing"


def parse_packet(answered, unanswered, current_ttl, elapsed_ms, do_tcphandshake,
                 extra_rst_count=0, failure_note=""):
    rst_count = count_rst_responses(answered) + extra_rst_count
    if answered is not None and len(answered) != 0:
        request_and_answer, summary_postfix = choose_desirable_packet(
            answered, do_tcphandshake)
        if request_and_answer is not None and len(answered) != 0:
            req_answer = request_and_answer[1]
            packet_send_time = request_and_answer[0].sent_time
            packet_receive_time = req_answer.time
            packet_elapsed_ms = float(
                format(abs((packet_receive_time - packet_send_time) * 1000), '.3f'))
            if packet_elapsed_ms > 0:
                elapsed_ms = packet_elapsed_ms
            backttl = guess_back_ttl(current_ttl, req_answer[IP].ttl)
            print("   <<< answer:"
                  + "   ip.src: " + req_answer[IP].src
                  + "   ip.ttl: " + str(req_answer[IP].ttl)
                  + "   back-ttl: " + str(backttl))
            answer_summary = req_answer.summary()
            print("      " + answer_summary)
            print("· - · · · rtt: " + str(elapsed_ms) + "ms · · · - · ")
            if len(summary_postfix) != 0:
                answer_summary += " . - - . - . " + summary_postfix
            return req_answer[IP].src, elapsed_ms, len(req_answer), req_answer[IP].ttl, answer_summary, answered, unanswered, rst_count
    # else for both:
    print("              *** no response *** ")
    print("· - · · · rtt: " + str(elapsed_ms) +
          "ms · · · · · · · · timeout ")
    return "***", elapsed_ms, 0, 0, (failure_note or "*"), answered, unanswered, rst_count


def tcp_options_correction(tcp_options, new_timestamp, syn_ack_timestamp):
    new_options = []
    default_timestamp = ('Timestamp', (new_timestamp, syn_ack_timestamp))
    for attr in tcp_options:
        if 'Timestamp' == str(attr[0]):
            new_options.append(default_timestamp)
        else:
            new_options.append(attr)
    return new_options


def generate_syn_tcp_options(new_timestamp):
    if OS_NAME == "Linux":
        tcp_options = [('MSS', 1460), ('SAckOK', b''),
                       ('Timestamp', (new_timestamp, 0)), ('NOP', None), ('WScale', 7)]
        return tcp_options
    elif OS_NAME == "Windows":
        tcp_options = [('MSS', 1460), ('NOP', None),
                       ('NOP', None), ('SAckOK', b'')]
        return tcp_options
    elif OS_NAME == "Darwin":
        tcp_options = [('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None),
                       ('NOP', None), ('Timestamp', (new_timestamp, 0)), ('SAckOK', b''), ('EOL', None)]
        return tcp_options
    else:
        return []


def generate_ack_tcp_options(new_timestamp, syn_ack_timestamp):
    if OS_NAME == "Linux" or OS_NAME == "Darwin":
        tcp_options = [('NOP', None), ('NOP', None),
                       ('Timestamp', (new_timestamp, syn_ack_timestamp))]
        return tcp_options
    else:
        return []


def get_timestamp(tcp_options):
    default_timestamp = 0
    for attr in tcp_options:
        if 'Timestamp' == str(attr[0]):
            default_timestamp = attr[1][0]
    return default_timestamp


def get_new_timestamp():
    timestamp_now = time.time()
    return timestamp_now, (int(timestamp_now) ^ int(RandInt()))


def already_reached_destination_int(previous_node_id, current_node_ip):
    if previous_node_id == current_node_ip:
        return True
    else:
        return False


def randomize_retransmission_ip_id(request_packet):
    """Give a `--rexmit` trace a random starting IP ID (backlog §1.7).

    This used to be `id += 15` ("== sysctl net.ipv4.tcp_retries2"), meaning every
    retransmission trace started at *the stored packet's ID plus exactly 15* — a
    constant offset from a value baked into a committed sample, which is a
    ready-made correlation handle for anyone watching the flow.

    The per-retransmission `id += 1` in `retransmission_single_packet` is
    deliberately kept: real OS retransmissions do increment sequentially, so
    randomising every packet would make the probe look *less* like the
    retransmission stream it is imitating. Only the starting point moves, which
    matches what `send_single_packet` already does for every other probe.

    `int()` resolves the volatile now — leaving a `RandShort` in the field would
    re-randomise on every rebuild and destroy the sequential increment.
    """
    request_packet[IP].id = int(RandShort())
    return request_packet


def change_dst_port(request_packet, dst_port):
    if request_packet.haslayer(TCP):
        request_packet[TCP].dport = dst_port
    elif request_packet.haslayer(UDP):
        request_packet[UDP].dport = dst_port
    return request_packet


class Tracer:
    """One traceroute run and the state it owns.

    Backlog §2.6 asked for this so the trace loop stops writing through module
    globals. The near-term payoff is not parallelism — nothing runs traces
    concurrently today — it is that per-run state (the collected measurements,
    and in M5c a `PortRandomizer` and per-hop RTT history) has somewhere to
    live, and that the loop can be driven from a test without root or a link.

    The module keeps a mirror of `measurement_data` / `have_2_packet` for the
    published surface; see the note at the top of the file.
    """

    def __init__(self, iface=None, source_ip=None):
        self.iface = self._select_iface(iface)
        self.source_ip = (
            source_ip if source_ip is not None
            else (get_if_addr(self.iface) if iface is not None
                  else user_source_ip_address))
        self.have_2_packet = False
        self.measurement_data = [[], []]
        # M5c: live RST backoff. `None` means no rotation, which is the default
        # and the behaviour of every run that does not pass --port-pool.
        self.port_randomizer = None
        self.current_dport = None
        self.last_probe_dport = None
        # M5c: opt-in per-hop timeout growth, keyed by (packet index, ip index).
        self.adaptive_timeout = False
        self.last_rtt = {}
        # Per-probe evidence from a handshake that never completed.
        self.handshake_rst_count = 0
        self.handshake_failure_note = ""
        # Set once the trace knows what it is measuring; `finalise_measurements`
        # needs it and the interrupt path has no other way to reach it.
        self.classification_context = None
        # Backlog §2.8: pseudonymise private hops on the way to disk. The
        # operator's own address is removed either way.
        self.anonymize = False

    @staticmethod
    def _select_iface(iface):
        """Resolve the interface, and make `--iface` actually mean something.

        At layer 3 scapy picks the interface from the routing table and ignores
        any `iface=` handed to `sr`/`send` (see the note at the top of the file),
        so `--iface` used to be a no-op that only steered `get_if_addr`. Setting
        `conf.iface` is the supported lever: it is what scapy falls back to when
        the route lookup does not pin an interface.
        """
        if iface is None:
            return user_iface
        conf.iface = iface
        return iface

    def _publish(self):
        """Point the legacy module mirror at this run's state."""
        global measurement_data, have_2_packet, user_iface, user_source_ip_address
        global _active_tracer
        _active_tracer = self
        measurement_data = self.measurement_data
        have_2_packet = self.have_2_packet
        user_iface = self.iface
        user_source_ip_address = self.source_ip

    # --- sending -------------------------------------------------------------

    def send_packet_with_tcphandshake(self, this_request, timeout):
        timestamp_start, new_timestamp = get_new_timestamp()
        ip_address = this_request[IP].dst
        destination_port = this_request[TCP].dport
        syn_tcp_options = generate_syn_tcp_options(new_timestamp)
        ans = []
        unans = PacketList([])
        sent_syns = []
        syn_ack = None
        refused = False
        max_repeat = 0
        # here we are trying to do a new TCP handshake every time because
        # we are trying to trace packet data, not SYN packet. And
        # we know about intermittent stream blocking
        #
        # Retries are for *silence* only. An answer that is not a SYN-ACK — an
        # ICMP prohibited, an injected RST — means a box on the path is awake and
        # refusing, and firing four more SYNs at it buys no new information while
        # making the probe look like a SYN flood to the censor watching it.
        while syn_ack is None and not refused and max_repeat < 5:
            source_port = utils.ephemeral_port.ephemeral_port_reserve(
                self.source_ip, "tcp")
            send_syn = IP(src=self.source_ip,
                          dst=ip_address, id=RandShort(), flags="DF")/TCP(
                sport=source_port, dport=destination_port, seq=RandInt(),
                flags="S", options=syn_tcp_options)
            sent_syns.append(send_syn)
            tcp_handshake_timeout = timeout + max_repeat
            ans, unans = sr(send_syn, verbose=0,
                            timeout=tcp_handshake_timeout)
            max_repeat += 1
            if len(ans) == 0:
                print("Warning: No response to SYN packet yet")
                continue
            # The old code went straight from "the answer list is non-empty" to
            # `ans[0][1][TCP]`. On an ICMP answer that layer does not exist —
            # scapy >= 2.6 no longer resolves `TCPerror` as `TCP` — so the run
            # died with `IndexError: Layer [TCP] not found`, and because
            # tracevis.py turns that into `sys.exit(2)` every hop collected so
            # far was lost. Seen in the field.
            self.handshake_rst_count += count_rst_responses(ans)
            syn_ack = find_syn_ack(ans)
            if syn_ack is None:
                refused = True
                self.handshake_failure_note = (
                    "[no SYN-ACK: " + describe_answer(ans) + "]")
        if syn_ack is None:
            if refused:
                print("Error: TCP handshake to " + ip_address + ":"
                      + str(destination_port) + " was answered by "
                      + describe_answer(ans)
                      + " — not a SYN-ACK, so the data packet was not sent")
            else:
                print("Error: doing TCP handshake failed "
                      + str(max_repeat)
                      + " times. You should test with PingVis instead")  # todo: xhdix
            sleep(timeout + max_repeat)  # double sleep (￣o￣) . z Z.
            # The refused case has an empty `unans` (the SYN *was* answered), and
            # `generate_packets_for_each_ip` indexes `unanswered[0][0]` whenever
            # there are no answers — so hand back the SYNs actually sent.
            return SndRcvList([]), (unans if len(unans) else PacketList(sent_syns))
        timeout += 2  # we should wait more for data packets.
        syn_ack_timestamp = get_timestamp(syn_ack[TCP].options)
        new_timestamp = new_timestamp + \
            int((time.time() - timestamp_start) * 1000)
        ack_tcp_options = generate_ack_tcp_options(
            new_timestamp, syn_ack_timestamp)
        send_ack = IP(src=self.source_ip,
                      dst=ip_address, id=(send_syn[IP].id + 1), flags="DF")/TCP(
            sport=source_port, dport=destination_port, seq=syn_ack[TCP].ack,
            ack=syn_ack[TCP].seq + 1, flags="A", options=ack_tcp_options)
        send(send_ack, verbose=0)
        send_data = this_request
        send_data[IP].src = self.source_ip
        send_data[IP].id = send_syn[IP].id + 2
        send_data[TCP].sport = source_port
        send_data[TCP].seq = syn_ack[TCP].ack
        send_data[TCP].ack = syn_ack[TCP].seq + 1
        send_data[TCP].options = tcp_options_correction(
            send_data[TCP].options, new_timestamp, syn_ack_timestamp)
        del(send_data[TCP].chksum)
        del(send_data[IP].len)
        del(send_data[IP].chksum)
        request_and_answers, unanswered = sr(
            send_data, verbose=0, timeout=timeout, multi=True)
        # send_fin = send_ack.copy() # todo: xhdix
        # send_fin[IP].id=send_syn[IP].id + 1
        # send_fin[TCP].flags = "FA"
        # send(send_fin, verbose=0)
        # send_last_ack=send_fin.copy()
        # send_last_ack[IP].id=send_fin[IP].id + 1
        # send_last_ack[TCP].flags = "A"
        # send(send_last_ack, verbose=0)
        return request_and_answers, unanswered

    def send_single_packet(self, this_request, timeout):
        this_request[IP].id = RandShort()
        if this_request.haslayer(TCP):
            this_request[TCP].sport = utils.ephemeral_port.ephemeral_port_reserve(
                self.source_ip, "tcp")
            if this_request[TCP].flags == "S":
                this_request[TCP].seq = RandInt()
            _, new_timestamp = get_new_timestamp()
            this_request[TCP].options = tcp_options_correction(
                this_request[TCP].options, new_timestamp, 0)
            del(this_request[TCP].chksum)
        elif this_request.haslayer(UDP):
            this_request[UDP].sport = utils.ephemeral_port.ephemeral_port_reserve(
                self.source_ip, "udp")
            del(this_request[UDP].len)
            del(this_request[UDP].chksum)
        if this_request.haslayer(DNS):
            this_request[DNS].id = RandShort()
        del(this_request[IP].len)
        del(this_request[IP].chksum)
        request_and_answers, unanswered = sr(
            this_request, verbose=0, timeout=timeout)
        return request_and_answers, unanswered

    def retransmission_single_packet(self, this_request, timeout, is_data_packet):
        this_request[IP].id += 1
        del(this_request[IP].chksum)
        if is_data_packet:
            request_and_answers, unanswered = sr(
                this_request, verbose=0, timeout=timeout, multi=True)
        else:
            request_and_answers, unanswered = sr(
                this_request, verbose=0, timeout=timeout)
        return request_and_answers, unanswered

    def _effective_timeout(self, base_timeout, probe_key):
        """Per-hop timeout, grown toward the last observed RTT.

        A flat 1s misflags a slow DPI/CGNAT hop as "***" and corrupts the
        middlebox inference downstream. `utils.timing.adaptive_timeout` only ever
        grows the value and caps it at 60s, so a trace never becomes more
        aggressive mid-run.
        """
        if not self.adaptive_timeout:
            return base_timeout
        return utils.timing.adaptive_timeout(
            base_timeout, self.last_rtt.get(probe_key))

    def _record_rtt(self, probe_key, answer_ip, elapsed_ms):
        """Remember the RTT of an *answered* hop only.

        `parse_packet` returns the wall-clock elapsed time even when the probe
        timed out — which is, by construction, the timeout itself. Feeding that
        back as "the last RTT" would ratchet every blocked path straight to the
        60s cap on the next TTL step and hold it there for the rest of the run.
        """
        if answer_ip == "***" or not elapsed_ms or elapsed_ms <= 0:
            return
        self.last_rtt[probe_key] = elapsed_ms / 1000.0

    def _register_rst_feedback(self, rst_count, dport):
        """Feed observed RSTs to the port pool and rotate on threshold.

        Repeated RSTs on a flow are DPI reset injection; the answer is to move
        to another port and let the burned one cool off.
        The RSTs are read from `answered` (via `count_rst_responses`) — an
        earlier design note said to look in `sr()`'s `unanswered`, but that list
        holds *sent* packets that drew no reply, so no RST can appear there.
        """
        if self.port_randomizer is None or dport is None:
            return
        if rst_count <= 0:
            self.port_randomizer.reset_rst(dport)
            return
        tripped = False
        for _ in range(rst_count):
            tripped = self.port_randomizer.register_rst(dport) or tripped
        if tripped:
            self.current_dport = self.port_randomizer.next_port()
            print("· · · - · RST flood on port " + str(dport)
                  + " — cooling it off and rotating to port "
                  + str(self.current_dport))

    def send_packet(self, request_packet, request_ip, current_ttl, timeout,
                    do_tcphandshake, trace_retransmission, do_not_parse):
        this_request = request_packet
        this_request[IP].src = self.source_ip
        this_request[IP].dst = request_ip
        this_request[IP].ttl = current_ttl
        self.handshake_rst_count = 0
        self.handshake_failure_note = ""
        if self.current_dport is not None:
            change_dst_port(this_request, self.current_dport)
        self.last_probe_dport = None
        if this_request.haslayer(TCP):
            self.last_probe_dport = this_request[TCP].dport
        elif this_request.haslayer(UDP):
            self.last_probe_dport = this_request[UDP].dport
        if not do_not_parse:
            print(">>>request:"
                  + "   ip.dst: " + request_ip
                  + "   ip.ttl: " + str(current_ttl))
        request_and_answers = []
        unanswered = []
        start_time = time.perf_counter()
        if trace_retransmission:
            request_and_answers, unanswered = self.retransmission_single_packet(
                this_request, timeout, do_tcphandshake)
        elif do_tcphandshake:
            request_and_answers, unanswered = self.send_packet_with_tcphandshake(
                this_request, timeout)
        else:
            request_and_answers, unanswered = self.send_single_packet(
                this_request, timeout)
        end_time = time.perf_counter()
        elapsed_ms = float(format(abs((end_time - start_time) * 1000), '.3f'))
        if do_not_parse:
            return request_and_answers, unanswered
        if do_tcphandshake and not trace_retransmission:
            sleep(timeout)  # double sleep (￣o￣) . z Z. maybe we should wait more
        # A handshake refused by an injected RST never reaches the data-packet
        # `sr()`, so its RSTs are invisible to `count_rst_responses(answered)` —
        # which is precisely the DPI behaviour described on port 443.
        # Carrying the count through is what lets `rst_flood` fire, and what lets
        # M5c's port rotation see a flood it would otherwise never be told about.
        parsed = parse_packet(request_and_answers, unanswered,
                              current_ttl, elapsed_ms, do_tcphandshake,
                              self.handshake_rst_count,
                              self.handshake_failure_note)
        self._register_rst_feedback(parsed[7], self.last_probe_dport)
        return parsed

    def check_for_permission(self):
        try:
            this_request = IP(
                src=self.source_ip,
                dst=LOCALHOST, ttl=0)/TCP(
                sport=0, dport=53)/DNS()
            sr1(this_request, verbose=0, timeout=0)
        except OSError:
            print("Error: Unable to send a packet with unprivileged user. Please run as root/admin.")
            sys.exit(1)

    # --- bookkeeping ---------------------------------------------------------

    def are_equal(self, original_list, result_list):
        counter = 0
        for item in original_list:
            original_item = item
            reault_item_1 = result_list[0][counter]
            if reault_item_1 != original_item:
                return False
            if self.have_2_packet:
                reault_item_2 = result_list[1][counter]
                if reault_item_2 != original_item:
                    return False
            counter += 1
        return True

    def initialize_first_nodes_json(self, request_ips):
        nodes = []
        for _ in request_ips:
            nodes.append(self.source_ip)
        if self.have_2_packet:
            return [nodes, nodes.copy()]
        else:
            return [nodes]

    def initialize_json_first_nodes(
            self, request_ips, annotation_1, annotation_2, packet_1_proto,
            packet_2_proto, packet_1_port, packet_2_port, packet_1_size,
            packet_2_size, paris_id, public_ip, network_asn, network_name,
            country_code, city):
        start_time = int(datetime.utcnow().timestamp())
        for request_ip in request_ips:
            self.measurement_data[0].append(
                traceroute_data(
                    dst_addr=request_ip, annotation=annotation_1,
                    src_addr=self.source_ip, proto=packet_1_proto, port=packet_1_port,
                    timestamp=start_time, paris_id=paris_id, size=packet_1_size,
                    from_ip=public_ip, network_asn=network_asn,
                    network_name=network_name, country_code=country_code, city=city
                )
            )
            if self.have_2_packet:
                self.measurement_data[1].append(
                    traceroute_data(
                        dst_addr=request_ip, annotation=annotation_2,
                        src_addr=self.source_ip, proto=packet_2_proto, port=packet_2_port,
                        timestamp=start_time, paris_id=paris_id, size=packet_2_size,
                        from_ip=public_ip, network_asn=network_asn,
                        network_name=network_name, country_code=country_code, city=city
                    )
                )

    def get_packets_info(self, request_packets):
        packet_1_proto = ""
        packet_2_proto = ""
        packet_1_port = -1
        packet_2_port = -1
        packet_1_size = -1
        packet_2_size = -1
        if (request_packets[0]).haslayer(IP):
            packet_1_proto = "IP"
            packet_1_size = len(request_packets[0])
        if (request_packets[0]).haslayer(TCP):
            packet_1_proto = "TCP"
            packet_1_port = request_packets[0][TCP].dport
        elif (request_packets[0]).haslayer(UDP):
            packet_1_proto = "UDP"
            packet_1_port = request_packets[0][UDP].dport
        elif(request_packets[0]).haslayer(ICMP):
            packet_1_proto = "ICMP"
        if self.have_2_packet:
            if (request_packets[1]).haslayer(IP):
                packet_2_proto = "IP"
                packet_2_size = len(request_packets[1])
            if (request_packets[1]).haslayer(TCP):
                packet_2_proto = "TCP"
                packet_2_port = request_packets[1][TCP].dport
            elif (request_packets[1]).haslayer(UDP):
                packet_2_proto = "UDP"
                packet_2_port = request_packets[1][UDP].dport
            elif(request_packets[1]).haslayer(ICMP):
                packet_2_proto = "ICMP"
        return packet_1_proto, packet_2_proto, packet_1_port, packet_2_port, packet_1_size, packet_2_size

    def _scrub_for_disk(self, entries):
        """Remove the operator from the copy that is about to be written."""
        replacements = utils.anonymize.scrub(
            entries, source_ip=self.source_ip, pseudonymise=self.anonymize)
        aliases = {a: b for a, b in replacements.items()
                   if b != utils.anonymize.SENTINEL_SOURCE}
        if aliases:
            print("· · · - · --anonymize: "
                  + ", ".join(f"{a} -> {b}" for a, b in aliases.items()))

    def save_measurement_data(
            self, request_ips, measurement_name, continue_to_max_ttl, output_dir):
        end_time = int(datetime.utcnow().timestamp())
        measurement_data_json = []
        ip_steps = 0
        measurement_data_save = deepcopy(self.measurement_data)
        # Backlog §2.8. Runs on the deepcopy, so the in-memory trace keeps its
        # real addresses for anything still reading them, and only what reaches
        # disk is scrubbed. One pass over both blocks so a hop keeps one
        # pseudonym across every packet arm and repeat.
        self._scrub_for_disk(
            [entry for block in measurement_data_save for entry in block])
        while ip_steps < len(request_ips):
            measurement_data_save[0][ip_steps].set_endtime(end_time)
            if not continue_to_max_ttl:
                measurement_data_save[0][ip_steps].clean_extra_result()
            measurement_data_json.append(measurement_data_save[0][ip_steps])
            if self.have_2_packet:
                measurement_data_save[1][ip_steps].set_endtime(end_time)
                if not continue_to_max_ttl:
                    measurement_data_save[1][ip_steps].clean_extra_result()
                measurement_data_json.append(measurement_data_save[1][ip_steps])
            ip_steps += 1
        data_path = output_dir + measurement_name + ".json"
        with open(data_path, "w") as jsonfile:
            jsonfile.write(json.dumps(measurement_data_json,
                           default=lambda o: o.__dict__, indent=4))
        print("saved: " + data_path)
        return data_path

    def finalise_measurements(self):
        """Run the post-trace analysis over whatever hops were collected.

        Both save paths go through here. They did not: `save_partial_measurement`
        wrote straight to disk, so an interrupted trace kept the *pre-trace*
        classification — the very thing this pass exists to correct. Every
        detector was wrong on that path at once: `dpi_cleared` true on a blocked
        path, `cgnat_hop` false with an RFC 6598 hop sitting in the saved data,
        and `reply_forged` false with a reflected reply sitting next to it. The
        evidence was all present and simply never read.

        It matters most exactly where it was missing: under
        `--timeout-profile shutdown` a trace runs for hours, so Ctrl-C is a
        normal way to end one.
        """
        context = getattr(self, "classification_context", None)
        if not context:
            # Interrupted before the trace loop began; there is nothing to
            # classify and no network state to classify it against.
            return
        self.recompute_dpi_from_per_hop(
            context["request_ips"], context["network_state"],
            context["p1_proto"], context["p1_port"],
            context["p2_proto"] if self.have_2_packet else None,
            context["p2_port"] if self.have_2_packet else None,
            context["repeat_requests"],
        )

    def save_partial_measurement(self, output_dir, name_prefix, continue_to_max_ttl):
        """Flush whatever partial measurement is in flight to disk.

        Called when the user interrupts the trace (Ctrl-C / EOF) so partial
        results are not lost. Returns the saved `.json` path, or "" if nothing
        was collected yet.
        """
        if not self.measurement_data[0]:
            return ""
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M")
        measurement_name = (name_prefix or "") + stamp + "-partial"
        request_ips = [entry.dst_addr for entry in self.measurement_data[0]]
        print("· · · - · interrupted — saving partial measurement")
        self.finalise_measurements()
        return self.save_measurement_data(
            request_ips=request_ips, measurement_name=measurement_name,
            continue_to_max_ttl=continue_to_max_ttl, output_dir=output_dir)

    def _record_preflight_failure(self, req_step, ip_index, dst_ip):
        """Make a failed `--paris` preflight visible in the log and the JSON."""
        print("Warning: preflight handshake to " + dst_ip + " failed. The packet"
              " replayed at every TTL is the unanswered SYN, not the configured"
              " data packet — this arm is NOT comparable with one that"
              " completed its handshake.")
        block = self.measurement_data[req_step]
        if ip_index < len(block):
            entry = block[ip_index]
            if PREFLIGHT_FAILED_NOTE not in (entry.annotation or ""):
                entry.annotation = (entry.annotation or "") + PREFLIGHT_FAILED_NOTE

    def generate_packets_for_each_ip(self, request_packets, request_ips,
                                     do_tcphandshake, timeout=1):
        request_packets_for_rexmit = [[], []]
        req_step = 0
        print("· - · · · wait · - · · · in preparation · - · · ·")
        for req_packet in request_packets:
            for ip_index, dst_ip in enumerate(request_ips):
                new_packet = req_packet.copy()
                request_and_answers, unanswered = self.send_packet(
                    new_packet, dst_ip,
                    0, timeout, do_tcphandshake[req_step], False, True)
                if len(request_and_answers) != 0:
                    request_packets_for_rexmit[req_step].append(
                        request_and_answers[0][0].copy())
                else:
                    # The preflight produced no answer, so what gets replayed at
                    # every TTL is `unanswered[0][0]` — the bare SYN, not the data
                    # packet the probe is meant to carry. That silently turns a
                    # ClientHello-vs-ClientHello port comparison into
                    # ClientHello-vs-SYN, varying payload *and* port together, in
                    # exactly the case such a comparison exists to detect.
                    #
                    # The substitution stays: once the handshake has failed there
                    # is no valid seq/ack for the intended packet, and inventing
                    # one is not better-founded than replaying the SYN. What
                    # changes is that it can no longer happen quietly.
                    self._record_preflight_failure(req_step, ip_index, dst_ip)
                    request_packets_for_rexmit[req_step].append(
                        unanswered[0][0].copy())
            req_step = 1
        print("- · - · -     - · - · -     - · - · -     - · - · -")
        print(
            " ********************************************************************** ")
        print(
            " ********************************************************************** ")
        print(
            " ********************************************************************** ")
        return request_packets_for_rexmit

    def recompute_dpi_from_per_hop(
        self, request_ips, network_state, p1_proto, p1_port,
        p2_proto=None, p2_port=None, repeat_requests=1,
    ):
        """Update path-level DPI flags after the trace loop, using real per-hop data.

        The initial ``classify_dpi_path`` call runs before any packets are sent
        and uses ``rst_count=0``, ``is_nat=False``, etc.  This walks the collected
        measurements and re-runs the classifier with the actual per-hop RST counts
        and reachability verdict so that blocked TCP paths are no longer
        mis-labelled ``dpi_cleared=True``.

        Measured behaviour: TCP paths are silently dropped — ``rst_count``
        stays 0 but the destination is never reached.  The
        ``tcp_silently_dropped`` flag (added to ``DpiSignal``) captures this.
        """
        # `measurement_data` is always a 2-element list, but the second block is
        # only populated when the trace carries a second packet
        # (`initialize_json_first_nodes` gates that append on `have_2_packet`).
        # Walking it unconditionally raised IndexError *after* a completed trace
        # and before the save, so every single-packet trace lost all of its
        # results — `tracevis.py` catches the exception and exits 2.
        for access_block_idx, access_block in enumerate(self.measurement_data):
            for ip_idx in range(min(len(request_ips), len(access_block))):
                entry = access_block[ip_idx]
                # Determine probe proto/port for this measurement block
                if access_block_idx == 0:
                    sent_proto, sent_dport = p1_proto, p1_port
                elif p2_proto is not None:
                    sent_proto, sent_dport = p2_proto, p2_port
                else:
                    sent_proto, sent_dport = p1_proto, p1_port

                # Collect per-hop RST counts, check destination reachability, and
                # look for a CGNAT hop. The last one is why this walk exists at
                # all: `network_state` is decided by whether a detection provider
                # answered, and under an allowlist regime that provider is
                # allowlisted — so a tiered network was classified `open` while
                # every trace crossed an RFC 6598 hop. The hop addresses are the
                # evidence, and they are already here.
                max_rst_count = 0
                dst_reached = False
                cgnat_observed = False
                for hop_entry in entry.result:
                    for hr in hop_entry.get("result", []):
                        if not isinstance(hr, dict):
                            continue
                        rst_count = hr.get("rst_count", 0)
                        if rst_count:
                            max_rst_count = max(max_rst_count, rst_count)
                        resp_from = hr.get("from", "")
                        if resp_from and resp_from == entry.dst_addr:
                            dst_reached = True
                        if utils.dpi.is_cgnat_address(resp_from):
                            cgnat_observed = True

                # Backlog §2.12. Runs before the classifier because a forged
                # reply is evidence the classifier needs: it rules out
                # `dpi_cleared`. Reads the saved hops, which is also why an
                # existing measurement can be re-examined without re-tracing.
                forged = utils.forgery.find_forged_destination_reply(entry)
                entry.reply_forged = forged.forged
                entry.forgery_evidence = forged.evidence
                if forged.forged:
                    print("· · · - · forged reply from " + str(entry.dst_addr)
                          + " (" + forged.evidence + "): that answer was not"
                          " written by the destination")

                dpi_signal = utils.dpi.classify_dpi_path(
                    network_state=network_state,
                    sent_proto=sent_proto,
                    sent_dport=sent_dport,
                    rst_count=max_rst_count,
                    dst_reached=dst_reached,
                    cgnat_observed=cgnat_observed,
                    reply_forged=forged.forged,
                )
                entry.dpi_cleared = dpi_signal.dpi_cleared
                entry.cgnat_hop = dpi_signal.cgnat_hop
                entry.sni_inspected = dpi_signal.sni_inspected
                entry.rst_flood = dpi_signal.rst_flood
                entry.tcp_silently_dropped = dpi_signal.tcp_silently_dropped

    # --- the trace loop ------------------------------------------------------

    def run(
            self, ip_list, request_packet_1, output_dir: str,
            max_ttl: int, timeout: int, repeat_requests: int,
            request_packet_2: str = "", name_prefix: str = "",
            annotation_1: str = "", annotation_2: str = "",
            continue_to_max_ttl: bool = False,
            do_tcph1: bool = False, do_tcph2: bool = False,
            trace_retransmission: bool = False,
            trace_with_retransmission: bool = False,
            dst_port: int = -1, network_mode: str = "auto",
            port_pool=None, adaptive_timeout: bool = False,
            anonymize: bool = False
    ):
        self.check_for_permission()
        self.adaptive_timeout = adaptive_timeout
        self.anonymize = anonymize
        # M5c live RST backoff. Only armed when the user
        # asked for a pool, and it only ever fires on the RST threshold — a run
        # that sees no RST flood behaves exactly as it did before.
        #
        # Never under --paris: `generate_packets_for_each_ip` bakes the port into
        # the packets it precomputes and replays, so rewriting dport mid-run
        # would desynchronise them from the handshake they belong to.
        if port_pool and not trace_with_retransmission:
            self.port_randomizer = utils.portpool.PortRandomizer(ports=port_pool)
            self.current_dport = dst_port if dst_port != -1 else None
        elif port_pool and trace_with_retransmission:
            print("Notice: --port-pool rotation is disabled under --paris"
                  " (the retransmitted packets carry a fixed port).")
        measurement_name = ""
        request_packets = []
        do_tcphandshake = []
        request_ips = []
        was_successful = False
        repeat_all_steps = 0
        paris_id = 0
        if do_tcph1:
            annotation_1 += " (+tcph)"
        if do_tcph2:
            annotation_2 += " (+tcph)"
        if request_packet_1 is None:
            print("packet is invalid!")
            sys.exit(1)
        if request_packet_2 == "":
            if trace_retransmission:
                randomize_retransmission_ip_id(request_packet_1)
            if dst_port != -1:
                request_packet_1 = change_dst_port(request_packet_1, dst_port)
            request_packets.append(request_packet_1)
            do_tcphandshake.append(do_tcph1)
            self.have_2_packet = False
        else:
            if trace_retransmission:
                randomize_retransmission_ip_id(request_packet_1)
                randomize_retransmission_ip_id(request_packet_2)
            if dst_port != -1:
                request_packet_1 = change_dst_port(request_packet_1, dst_port)
                request_packet_2 = change_dst_port(request_packet_2, dst_port)
            request_packets.append(request_packet_1)
            request_packets.append(request_packet_2)
            do_tcphandshake.append(do_tcph1)
            do_tcphandshake.append(do_tcph2)
            self.have_2_packet = True
        self._publish()
        if len(ip_list) == 0:
            if request_packet_1[IP].dst == "" or request_packet_1[IP].dst == LOCALHOST:
                if self.have_2_packet:
                    if request_packet_2[IP].dst == "" or request_packet_2[IP].dst == LOCALHOST:
                        print("You must set at least one IP. (--ips || -i)")
                        sys.exit(1)
                else:
                    print("You must set at least one IP. (--ips || -i)")
                    sys.exit(1)
            else:
                request_ips.append(request_packet_1[IP].dst)
            if self.have_2_packet:
                if request_packet_2[IP].dst not in ["", LOCALHOST, request_ips[0]]:
                    request_ips.append(request_packet_2[IP].dst)
        else:
            request_ips = ip_list
        p1_proto, p2_proto, p1_port, p2_port, p1_size, p2_size = self.get_packets_info(
            request_packets)
        if trace_with_retransmission:
            paris_id = repeat_requests
        elif trace_retransmission:
            paris_id = -1

        (no_internet, public_ip, network_asn, network_name, country_code,
         city, network_state, provider_status) = utils.geolocate.run_geolocate(
            network_mode=network_mode)
        print("· · · - · network state: " + network_state)

        measurement_name = (f"{name_prefix}-{network_asn}-tracevis-" if name_prefix else f"{network_asn}-tracevis-") + \
            datetime.utcnow().strftime("%Y%m%d-%H%M")

        self.initialize_json_first_nodes(
            request_ips=request_ips, annotation_1=annotation_1, annotation_2=annotation_2,
            packet_1_proto=p1_proto, packet_2_proto=p2_proto,
            packet_1_port=p1_port, packet_2_port=p2_port,
            packet_1_size=p1_size, packet_2_size=p2_size, paris_id=paris_id,
            public_ip=public_ip, network_asn=network_asn, network_name=network_name,
            country_code=country_code, city=city
        )
        print("- · - · -     - · - · -     - · - · -     - · - · -")

        # Attach path-level DPI/CGNAT/SNI posture (M4).
        # network_state is the geolocate 7-tuple component above; per-hop NAT/PEP
        # evidence is refined later in vis.py from the raw answered packets. This
        # tags every traceroute_data entry so the JSON + visualization carry the
        # posture even before the trace loop runs per-hop detection.
        # NOTE: this is the *initial* classification — flags are recomputed from
        # actual per-hop data after the trace loop by recompute_dpi_from_per_hop().
        dpi_signal = utils.dpi.classify_dpi_path(
            network_state=network_state,
            sent_proto=p1_proto,
            sent_dport=p1_port,
        )
        # Everything `recompute_dpi_from_per_hop` needs, kept so the interrupt
        # path can run it too — see `finalise_measurements`.
        self.classification_context = {
            "request_ips": request_ips, "network_state": network_state,
            "p1_proto": p1_proto, "p1_port": p1_port,
            "p2_proto": p2_proto, "p2_port": p2_port,
            "repeat_requests": repeat_requests,
        }
        for access_block_steps_data in self.measurement_data:
            for measurement_entry in access_block_steps_data:
                measurement_entry.network_state = network_state
                measurement_entry.provider_status = provider_status
                measurement_entry.dpi_cleared = dpi_signal.dpi_cleared
                measurement_entry.cgnat_hop = dpi_signal.cgnat_hop
                measurement_entry.sni_inspected = dpi_signal.sni_inspected
                measurement_entry.rst_flood = dpi_signal.rst_flood
                measurement_entry.tcp_silently_dropped = dpi_signal.tcp_silently_dropped
        while repeat_all_steps < repeat_requests:
            repeat_all_steps += 1
            request_packets_for_rexmit = []
            if trace_with_retransmission:
                # The preflight used to hardcode `timeout=1`, which silently
                # ignored --timeout-profile on this path: a `shutdown` run asked
                # for 60s everywhere and got 1s for the one handshake whose
                # result every TTL then replays.
                request_packets_for_rexmit = self.generate_packets_for_each_ip(
                    request_packets, request_ips, do_tcphandshake, timeout)
                trace_retransmission = True
            previous_node_ids = self.initialize_first_nodes_json(request_ips)
            for current_ttl in range(1, max_ttl + 1):
                if not continue_to_max_ttl and self.are_equal(request_ips, previous_node_ids):
                    ip_steps = 0
                    access_block_steps = 0
                    while ip_steps < len(request_ips):
                        # to avoid confusing the order of results when we have already reached our destination
                        self.measurement_data[access_block_steps][ip_steps].add_hop(
                            current_ttl, "", 0, 0, 0, "", None, None
                        )
                        ip_steps += 1
                        if self.have_2_packet and ip_steps == len(request_ips) and access_block_steps == 0:
                            ip_steps = 0
                            access_block_steps = 1
                else:
                    ip_steps = 0
                    access_block_steps = 0
                    print(
                        "  · - · - · repeat step: " + str(repeat_all_steps)
                        + "  · - · - ·  ttl step: " + str(current_ttl) + " · - · - ·")
                    print(" · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
                    while ip_steps < len(request_ips):
                        sleep_time = SLEEP_TIME
                        not_yet_destination = not (already_reached_destination_int(
                            previous_node_ids[access_block_steps][ip_steps],
                            request_ips[ip_steps]))
                        current_packet = None
                        if trace_with_retransmission:
                            current_packet = request_packets_for_rexmit[access_block_steps][ip_steps]
                        else:
                            current_packet = request_packets[access_block_steps]
                        if not continue_to_max_ttl:
                            if not_yet_destination:
                                probe_key = (access_block_steps, ip_steps)
                                answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary, answered, unanswered, rst_count = self.send_packet(
                                    current_packet, request_ips[ip_steps],
                                    current_ttl,
                                    self._effective_timeout(timeout, probe_key),
                                    do_tcphandshake[access_block_steps],
                                    trace_retransmission, False)
                                self._record_rtt(probe_key, answer_ip, elapsed_ms)
                                self.measurement_data[access_block_steps][ip_steps].add_hop(
                                    current_ttl, answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary, answered, unanswered, rst_count, self.last_probe_dport
                                )
                            else:
                                sleep_time = 0
                                # to avoid confusing the order of results when we have already reached our destination
                                self.measurement_data[access_block_steps][ip_steps].add_hop(
                                    current_ttl, "", 0, 0, 0, "", None, None
                                )
                        else:
                            probe_key = (access_block_steps, ip_steps)
                            answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary, answered, unanswered, rst_count = self.send_packet(
                                current_packet, request_ips[ip_steps],
                                current_ttl,
                                self._effective_timeout(timeout, probe_key),
                                do_tcphandshake[access_block_steps],
                                trace_retransmission, False)
                            self._record_rtt(probe_key, answer_ip, elapsed_ms)
                            self.measurement_data[access_block_steps][ip_steps].add_hop(
                                current_ttl, answer_ip, elapsed_ms, packet_size, req_answer_ttl, answer_summary, answered, unanswered, rst_count, self.last_probe_dport
                            )
                        if not_yet_destination:
                            if answer_ip == "***":
                                sleep_time = 0
                            previous_node_ids[access_block_steps][ip_steps] = answer_ip
                        print(
                            " · · · - - - · · ·     · · · - - - · · ·     · · · - - - · · · ")
                        if self.have_2_packet or len(request_ips) > 1:
                            sleep(sleep_time)
                        else:
                            sleep(0.1)
                        ip_steps += 1
                        was_successful = True
                        if self.have_2_packet and ip_steps == len(request_ips) and access_block_steps == 0:
                            ip_steps = 0
                            access_block_steps = 1
                            print(
                                " ********************************************************************** ")
                    print(
                        " ********************************************************************** ")
                    print(
                        " ********************************************************************** ")
                    print(
                        " ********************************************************************** ")
        if was_successful:
            print("saving measurement data...")
            # Post-trace DPI reclassify: update path-level flags using actual per-hop
            # evidence collected during probing. The initial classification above
            # used pre-trace defaults (rst_count=0, no per-hop NAT/middlebox evidence).
            # Measurement showed TCP paths are silently dropped, so
            # rst_count=0 but destination unreachable — the silent-drop flag and
            # corrected dpi_cleared must be set from real per-hop data.
            self.finalise_measurements()
            data_path = self.save_measurement_data(
                request_ips, measurement_name, continue_to_max_ttl, output_dir)
            print("· · · - · -     · · · - · -     · · · - · -     · · · - · -")
            return(was_successful, data_path, no_internet)
        else:
            return(was_successful, "", no_internet)


# --- published module surface (compatibility wrappers) -----------------------

def _mirror_tracer():
    """The running `Tracer`, or a fresh view over the legacy module mirror.

    `tracevis.py`'s Ctrl-C handler calls in after `trace_route` has already
    raised, so this has to reach the *real* run. Rebuilding a `Tracer` here
    reached its collected hops — those are shared by identity — but silently
    lost everything else the run had configured: `--anonymize` was ignored on an
    interrupted trace, and the post-trace analysis had no network state to work
    from.

    The identity check is what keeps the fallback honest: a caller that rebinds
    `trace.measurement_data` (the tests do, between cases) is no longer looking
    at the published run, and gets a fresh tracer exactly as before.
    """
    if (_active_tracer is not None
            and _active_tracer.measurement_data is measurement_data):
        return _active_tracer
    tracer = Tracer()
    tracer.measurement_data = measurement_data
    tracer.have_2_packet = have_2_packet
    return tracer


def send_packet(request_packet, request_ip, current_ttl, timeout,
                do_tcphandshake, trace_retransmission, do_not_parse):
    return _mirror_tracer().send_packet(
        request_packet, request_ip, current_ttl, timeout,
        do_tcphandshake, trace_retransmission, do_not_parse)


def check_for_permission():
    return _mirror_tracer().check_for_permission()


def save_measurement_data(request_ips, measurement_name, continue_to_max_ttl, output_dir):
    return _mirror_tracer().save_measurement_data(
        request_ips, measurement_name, continue_to_max_ttl, output_dir)


def save_partial_measurement(output_dir, name_prefix, continue_to_max_ttl):
    return _mirror_tracer().save_partial_measurement(
        output_dir, name_prefix, continue_to_max_ttl)


def trace_route(
        ip_list, request_packet_1, output_dir: str,
        max_ttl: int, timeout: int, repeat_requests: int,
        request_packet_2: str = "", name_prefix: str = "",
        annotation_1: str = "", annotation_2: str = "",
        continue_to_max_ttl: bool = False,
        do_tcph1: bool = False, do_tcph2: bool = False,
        trace_retransmission: bool = False,
        trace_with_retransmission: bool = False, iface=None,
        dst_port: int = -1, network_mode: str = "auto", port_pool=None,
        adaptive_timeout: bool = False, anonymize: bool = False
):
    tracer = Tracer(iface=iface)
    tracer._publish()
    return tracer.run(
        ip_list=ip_list, request_packet_1=request_packet_1, output_dir=output_dir,
        max_ttl=max_ttl, timeout=timeout, repeat_requests=repeat_requests,
        request_packet_2=request_packet_2, name_prefix=name_prefix,
        annotation_1=annotation_1, annotation_2=annotation_2,
        continue_to_max_ttl=continue_to_max_ttl,
        do_tcph1=do_tcph1, do_tcph2=do_tcph2,
        trace_retransmission=trace_retransmission,
        trace_with_retransmission=trace_with_retransmission,
        dst_port=dst_port, network_mode=network_mode, port_pool=port_pool,
        adaptive_timeout=adaptive_timeout, anonymize=anonymize)
