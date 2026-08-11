"""Characterization tests for the `utils/trace.py` send path and trace loop.

`utils/trace.py` is the one module whose main loop has never been covered: it
needs root and a live link, so the M5 architecture notes recorded
"no packet-capture test harness" as the blocker for the globals->`Tracer`
refactor (backlog §2.6). This module removes that blocker.

The harness is deliberately small. `utils/trace.py` does
`from scapy.all import send, sr, sr1`, which binds those names in *its* module
namespace, so `mock.patch("utils.trace.sr", ...)` is enough to intercept every
probe — no dependency injection needed. `FakeNetwork` records what would have
gone on the wire and answers by a scripted rule.

These tests pin *current* behaviour, including behaviour that is known to be
wrong (see `test_paris_preflight_substitutes_the_unanswered_syn`). They exist so
the refactor can be proved behaviour-preserving; each intentional change gets
its test updated in the commit that makes the change, never before.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from unittest import mock

from scapy.all import ICMP, IP, TCP, UDP, IPerror, PacketList, Raw, TCPerror
from scapy.plist import SndRcvList

import tracevis
import utils.dns
from utils import trace

SRC = "127.1.2.7"
GEO_RESULT = (False, "203.0.113.7", "AS64500", "Example", "XX", "Nowhere",
              "open", "cloudflare=ok,ipinfo=ok,ifconfig=ok")


def icmp_time_exceeded(hop_ip, ttl=64):
    """An ICMP time-exceeded reply, as an intermediate hop would send."""
    return IP(src=hop_ip, ttl=ttl) / ICMP(type=11, code=0)


def icmp_prohibited(hop_ip, dst_ip, dport=443, ttl=250):
    """ICMP dest-unreach / administratively-prohibited, as a filter box sends.

    The embedded quote is `IPerror/TCPerror`, which scapy >= 2.6 no longer
    resolves as a `TCP` layer — the detail that made this a crash rather than a
    wrong number.
    """
    return (IP(src=hop_ip, ttl=ttl) / ICMP(type=3, code=13)
            / IPerror(dst=dst_ip) / TCPerror(dport=dport))


def tcp_reply(src_ip, flags="SA", ttl=64):
    return IP(src=src_ip, ttl=ttl) / TCP(sport=443, dport=40000, flags=flags,
                                         seq=1000, ack=2000,
                                         options=[("Timestamp", (77, 88))])


def answered(sent, received, rtt_ms=10.0):
    """A one-entry `sr()` answer list.

    `parse_packet` subtracts `sent.sent_time` from `received.time`, and scapy
    leaves `sent_time` as None on a packet that was never really transmitted —
    so both must be set explicitly or the arithmetic raises TypeError.
    """
    sent.sent_time = 1_000.0
    received.time = 1_000.0 + (rtt_ms / 1000.0)
    return SndRcvList([(sent, received)])


class Probe:
    """Snapshot of one probe at send time.

    The trace loop mutates and reuses the same packet object for every TTL, so
    the fields have to be copied out now; holding the packet would record only
    its final state.
    """

    def __init__(self, packet, kwargs):
        self.dst = packet[IP].dst
        self.ttl = packet[IP].ttl
        self.src = packet[IP].src
        self.ip_id = packet[IP].id
        self.timeout = kwargs.get("timeout")
        self.multi = kwargs.get("multi", False)
        self.kwargs = dict(kwargs)
        self.dport = None
        self.flags = None
        if packet.haslayer(TCP):
            self.dport = packet[TCP].dport
            self.flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            self.dport = packet[UDP].dport

    def __repr__(self):
        return f"<Probe {self.dst}:{self.dport} ttl={self.ttl}>"


class FakeClock:
    """Wall-clock stand-in, so a mocked `sr()` can still *cost* its timeout.

    Without this the harness cannot see the bug it most needs to guard against.
    A real probe that times out blocks for `timeout` seconds, and `send_packet`
    measures that with `perf_counter` and reports it as the hop's elapsed time —
    which is what makes feeding a timed-out hop back into the adaptive timeout a
    ratchet. A mocked `sr` returns instantly, so without a fake clock every
    timeout looks like it took 0.01ms and the ratchet is invisible.
    """

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeNetwork:
    """Scripted stand-in for `scapy.sr()`.

    `rule(packet)` returns the reply, or None for a timeout. `rtt` may be a
    fixed value or a callable of the packet, for tests that care what RTT the
    answered hop reports.
    """

    def __init__(self, rule=None, rtt=10.0):
        self.probes = []
        self.clock = FakeClock()
        self._rule = rule or (lambda packet: None)
        self._rtt = rtt if callable(rtt) else (lambda packet: rtt)

    def __call__(self, packet, **kwargs):
        # Resolve volatiles once, as real `sr()` does: it iterates the packet,
        # which turns a `RandShort()` in `IP.id` into a concrete value, and
        # returns *that* packet in the answer list. Reading `packet[IP].id`
        # off an unresolved packet yields a fresh random every time, so
        # without this the harness cannot reproduce a reply that reflects the
        # query's IP ID — which is the whole of backlog §2.12's primary signal.
        packet = next(iter(packet))
        self.probes.append(Probe(packet, kwargs))
        received = self._rule(packet)
        if received is None:
            # A real unanswered probe blocks for the whole timeout.
            self.clock.advance(kwargs.get("timeout") or 0)
            return SndRcvList([]), PacketList([packet])
        rtt_ms = self._rtt(packet)
        self.clock.advance(rtt_ms / 1000.0)
        return answered(packet.copy(), received, rtt_ms), PacketList([])

    @property
    def order(self):
        """(dst, dport, ttl) per probe — the trace loop's visiting order."""
        return [(p.dst, p.dport, p.ttl) for p in self.probes]


def patched(net, stack):
    """Patch every escape hatch out of the process for the duration of a test."""
    stack.enter_context(mock.patch("utils.trace.sr", net))
    stack.enter_context(mock.patch("utils.trace.sr1", return_value=None))
    stack.enter_context(mock.patch("utils.trace.send", return_value=None))
    stack.enter_context(mock.patch("utils.trace.sleep", return_value=None))
    stack.enter_context(mock.patch("utils.trace.time.perf_counter", net.clock))
    stack.enter_context(mock.patch("utils.trace.user_source_ip_address", SRC))
    stack.enter_context(mock.patch(
        "utils.ephemeral_port.ephemeral_port_reserve", return_value=40000))
    stack.enter_context(mock.patch(
        "utils.geolocate.run_geolocate", return_value=GEO_RESULT))
    stack.enter_context(redirect_stdout(io.StringIO()))
    return net


class TraceTestCase(unittest.TestCase):
    """Resets the module globals the trace loop writes through."""

    def setUp(self):
        trace.measurement_data = [[], []]
        trace.have_2_packet = False
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        trace.measurement_data = [[], []]
        trace.have_2_packet = False
        for name in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def run_trace(self, net, **kwargs):
        defaults = {
            "ip_list": ["1.1.1.1"], "output_dir": self.tmp + "/",
            "max_ttl": 2, "timeout": 1, "repeat_requests": 1}
        defaults.update(kwargs)
        with ExitStack() as stack:
            patched(net, stack)
            return trace.trace_route(**defaults)


class TestSendPacketDispatch(TraceTestCase):
    def _send(self, net, packet, **kwargs):
        opts = {"request_ip": "9.9.9.9", "current_ttl": 7, "timeout": 1,
                "do_tcphandshake": False, "trace_retransmission": False,
                "do_not_parse": False}
        opts.update(kwargs)
        with ExitStack() as stack:
            patched(net, stack)
            return trace.send_packet(request_packet=packet, **opts)

    def test_destination_ttl_and_source_are_rewritten_per_probe(self):
        """The stored packet's own addressing is advisory, not authoritative.

        `samples/` relies on this: refreshing a sample's targets is a one-line
        `ips` edit precisely because `send_packet` overwrites `IP.dst`, so the
        frozen hexdumps never need regenerating.
        """
        net = FakeNetwork()
        packet = IP(src="192.168.1.3", dst="8.8.8.8", ttl=1) / UDP(dport=53)
        self._send(net, packet)
        probe = net.probes[0]
        self.assertEqual(probe.dst, "9.9.9.9")
        self.assertEqual(probe.ttl, 7)
        self.assertEqual(probe.src, SRC)

    def test_plain_probe_goes_through_send_single_packet(self):
        net = FakeNetwork()
        self._send(net, IP(dst="8.8.8.8") / UDP(dport=53))
        self.assertEqual(len(net.probes), 1)
        self.assertFalse(net.probes[0].multi)

    def test_handshake_probe_sends_a_syn_before_the_data_packet(self):
        """`do_tcphandshake` routes through `send_packet_with_tcphandshake`."""
        net = FakeNetwork(rule=lambda p: tcp_reply("9.9.9.9"))
        self._send(net, IP(dst="1.1.1.1") / TCP(dport=443, flags="PA") / Raw(b"hello"),
                   do_tcphandshake=True)
        self.assertEqual(len(net.probes), 2)
        self.assertEqual(net.probes[0].flags, "S")      # handshake SYN
        self.assertEqual(net.probes[1].flags, "PA")     # the data packet
        self.assertTrue(net.probes[1].multi)

    def test_retransmission_probe_bumps_ip_id_and_skips_the_handshake(self):
        net = FakeNetwork()
        packet = IP(dst="1.1.1.1", id=100) / TCP(dport=443, flags="PA")
        self._send(net, packet, trace_retransmission=True, do_tcphandshake=True)
        # One probe only: retransmission wins over the handshake branch.
        self.assertEqual(len(net.probes), 1)
        self.assertEqual(packet[IP].id, 101)
        self.assertTrue(net.probes[0].multi)

    def test_handshake_retries_the_syn_five_times_with_a_growing_timeout(self):
        """The retry ladder that sets the cost of a dead port.

        Five SYNs at `timeout + 0..4`, then a `timeout + 5` sleep — ~33s per TTL
        step at the degraded (3s) profile, which is where
        `samples/reality-non443.conf`'s runtime estimate comes from.
        """
        net = FakeNetwork()                       # never answers
        self._send(net, IP(dst="1.1.1.1") / TCP(dport=8443, flags="PA"),
                   do_tcphandshake=True, timeout=3)
        self.assertEqual([p.timeout for p in net.probes], [3, 4, 5, 6, 7])


class TestTraceLoopOrdering(TraceTestCase):
    def test_loop_is_ttl_outermost_and_lockstepped_across_destinations(self):
        """Probe order is (ttl, packet, destination) — not one trace at a time.

        Any per-(destination, port) reading of a result rests on this: when only
        some probes survive, which ones they were is only interpretable if the
        probe order is known. If this test ever changes, every such analysis has
        to be redone.
        """
        net = FakeNetwork()
        self.run_trace(
            net,
            ip_list=["1.1.1.1", "8.8.8.8"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            request_packet_2=IP(dst="0.0.0.0") / TCP(dport=8443, flags="S"),
            max_ttl=2)
        self.assertEqual(net.order, [
            ("1.1.1.1", 443, 1), ("8.8.8.8", 443, 1),
            ("1.1.1.1", 8443, 1), ("8.8.8.8", 8443, 1),
            ("1.1.1.1", 443, 2), ("8.8.8.8", 443, 2),
            ("1.1.1.1", 8443, 2), ("8.8.8.8", 8443, 2),
        ])

    def test_probing_stops_once_the_destination_answers(self):
        """`are_equal` short-circuits the remaining TTLs (unless --continue)."""
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("1.1.1.1"))
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53), max_ttl=5)
        # TTL 1 reaches the destination; TTLs 2-5 are recorded as empty hops.
        self.assertEqual([p.ttl for p in net.probes], [1])

    def test_continue_to_max_ttl_keeps_probing_past_the_destination(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("1.1.1.1"))
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53), max_ttl=4,
            continue_to_max_ttl=True)
        self.assertEqual([p.ttl for p in net.probes], [1, 2, 3, 4])

    def test_repeat_requests_replays_the_whole_ttl_sweep(self):
        net = FakeNetwork()
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=2, repeat_requests=3)
        self.assertEqual([p.ttl for p in net.probes], [1, 2] * 3)


class TestTraceLoopOutput(TraceTestCase):
    def test_a_completed_trace_writes_measurement_json(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        was_successful, path, no_internet = self.run_trace(
            net, request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53))
        self.assertTrue(was_successful)
        self.assertFalse(no_internet)
        self.assertTrue(os.path.exists(path))

    def test_unanswered_hops_are_recorded_as_timeouts(self):
        net = FakeNetwork()                       # never answers
        self.run_trace(
            net, request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53), max_ttl=2)
        hops = trace.measurement_data[0][0].result
        self.assertEqual(len(hops), 2)
        for hop in hops:
            self.assertEqual(hop["result"][0]["x"], "*")

    def test_dst_port_override_rewrites_both_packets(self):
        """`--port` collapses a two-port A/B, which is why the Reality sample
        pins `port: null` and the README warns against combining them."""
        net = FakeNetwork()
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            request_packet_2=IP(dst="0.0.0.0") / TCP(dport=8443, flags="S"),
            max_ttl=1, dst_port=9999)
        self.assertEqual({p.dport for p in net.probes}, {9999})


class TestParisPreflight(TraceTestCase):
    def _run_failing_preflight(self, **kwargs):
        net = FakeNetwork()                       # preflight never answers
        opts = {
            "ip_list": ["1.1.1.1"],
            "request_packet_1":
                IP(dst="0.0.0.0") / TCP(dport=443, flags="PA") / Raw(b"x" * 20),
            "max_ttl": 1, "do_tcph1": True, "trace_with_retransmission": True}
        opts.update(kwargs)
        self.run_trace(net, **opts)
        return net

    def test_a_failed_preflight_still_replays_the_syn(self):
        """The substitution itself is kept, deliberately.

        Under `--paris` the handshake runs once as a preflight and its *result*
        is replayed at every TTL. When the preflight fails there is no valid
        seq/ack for the intended data packet, so `unanswered[0][0]` — the bare
        SYN — is what gets replayed. Inventing a packet instead is not
        better-founded. What must not happen is it happening quietly; see the
        next two tests.
        """
        net = self._run_failing_preflight()
        self.assertEqual(net.probes[0].flags, "S")
        self.assertEqual(net.probes[-1].flags, "S")

    def test_a_failed_preflight_is_recorded_in_the_measurement(self):
        """The confound has to survive into the JSON, not just the console.

        A dead port turns a ClientHello-vs-ClientHello comparison into
        ClientHello-vs-SYN — payload and port varying together, in exactly the
        case such a comparison exists to detect. Whoever reads the output later
        needs to see that from the file alone.
        """
        self._run_failing_preflight()
        annotation = trace.measurement_data[0][0].annotation
        self.assertIn(trace.PREFLIGHT_FAILED_NOTE, annotation)

    def test_a_successful_preflight_is_not_annotated(self):
        net = FakeNetwork(rule=lambda p: tcp_reply("1.1.1.1"))
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="PA") / Raw(b"x"),
            max_ttl=1, do_tcph1=True, trace_with_retransmission=True)
        self.assertNotIn(trace.PREFLIGHT_FAILED_NOTE,
                         trace.measurement_data[0][0].annotation)

    def test_preflight_honours_the_configured_timeout(self):
        """The preflight used to hardcode `timeout=1`.

        That silently ignored `--timeout-profile` on the one handshake whose
        result every TTL then replays: a `shutdown` run asked for 60s everywhere
        and gave the decisive probe 1s.
        """
        net = self._run_failing_preflight(timeout=60)
        self.assertEqual(net.probes[0].timeout, 60)


class TestRstBackoff(TraceTestCase):
    """M5c: live port rotation on RST floods.

    `utils.portpool.PortRandomizer` shipped with cooldown logic in M2 and was
    never called during a trace; the port was chosen once at start-up and never
    revisited. These pin the wiring.
    """

    @staticmethod
    def rst_reply(packet):
        return IP(src="172.16.4.43", ttl=64) / TCP(sport=packet[TCP].dport,
                                                   dport=40000, flags="RA")

    def test_no_pool_means_no_rotation(self):
        """Default behaviour is untouched: without --port-pool nothing rotates
        however many RSTs come back."""
        net = FakeNetwork(rule=self.rst_reply)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            max_ttl=6)
        self.assertEqual({p.dport for p in net.probes}, {443})

    def test_a_pool_without_rst_floods_does_not_rotate(self):
        """Arming the pool is not enough — rotation is a response to evidence.

        A run that never trips the threshold has to look exactly like today's,
        or every existing --port-pool run silently changes shape.
        """
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=8080, flags="S"),
            max_ttl=4, continue_to_max_ttl=True,
            dst_port=8080, port_pool=[8080, 2053, 2083])
        self.assertEqual({p.dport for p in net.probes}, {8080})

    def test_rst_flood_rotates_to_another_port_in_the_pool(self):
        net = FakeNetwork(rule=self.rst_reply)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=8080, flags="S"),
            max_ttl=6, continue_to_max_ttl=True,
            dst_port=8080, port_pool=[8080, 2053, 2083])
        used = [p.dport for p in net.probes]
        # One RST per probe, threshold 3: the first three stay on 8080, then it
        # is cooled off and the probe moves to another pool member.
        self.assertEqual(used[:3], [8080, 8080, 8080])
        self.assertNotEqual(used[3], 8080)
        self.assertIn(used[3], (2053, 2083))

    def test_rotation_is_disabled_under_paris(self):
        """`generate_packets_for_each_ip` bakes the port into the packets it
        replays, so rewriting dport mid-run would desynchronise them."""
        net = FakeNetwork(rule=self.rst_reply)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=8080, flags="S"),
            max_ttl=6, continue_to_max_ttl=True, trace_with_retransmission=True,
            dst_port=8080, port_pool=[8080, 2053, 2083])
        self.assertEqual({p.dport for p in net.probes}, {8080})

    def test_the_probed_port_is_recorded_per_hop(self):
        """Rotation makes the path-level `port` only a starting value.

        `utils/vis.py` derives `probe_dport` for the `sni_inspected` gate
        (dport == 443) from it, so without a per-hop record every hop after a
        rotation is classified against the wrong port.
        """
        net = FakeNetwork(rule=self.rst_reply)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=8080, flags="S"),
            max_ttl=6, continue_to_max_ttl=True,
            dst_port=8080, port_pool=[8080, 2053, 2083])
        recorded = [hop["result"][0].get("dport")
                    for hop in trace.measurement_data[0][0].result]
        self.assertEqual(recorded[:3], [8080, 8080, 8080])
        self.assertNotEqual(recorded[3], 8080)
        self.assertEqual(recorded, [p.dport for p in net.probes])


class TestHandshakeAnswerIsNotAlwaysSynAck(TraceTestCase):
    """A SYN can be answered by something that is not a SYN-ACK.

    Observed on a restricted network: the run died with
    `Error! Layer [TCP] not found` and, because `tracevis.py` turns that into
    `sys.exit(2)`, every hop collected up to that point was lost. The handshake
    read `ans[0][1][TCP]` the moment the answer list was non-empty, which holds
    only for a SYN-ACK — an ICMP prohibited from a filter box has no TCP layer at
    all, and an injected RST is a refusal, not a handshake.
    """

    HELLO = None  # built per test; the loop mutates the packet it is given

    @staticmethod
    def data_packet(dport=443):
        return IP(dst="0.0.0.0") / TCP(dport=dport, flags="PA",
                                       options=[("Timestamp", (1, 2))]) / Raw(b"hi")

    @staticmethod
    def refuse_syn_with(reply):
        """Answer the handshake SYN only; the data packet must never be sent."""
        def rule(packet):
            if packet.haslayer(TCP) and str(packet[TCP].flags) == "S":
                return reply(packet)
            return None
        return rule

    def hops(self):
        return trace.measurement_data[0][0].result

    def test_an_icmp_answer_to_the_syn_does_not_lose_the_whole_run(self):
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: icmp_prohibited("10.10.34.34", p[IP].dst)))
        was_successful, path, _ = self.run_trace(
            net, ip_list=["1.1.1.1"], request_packet_1=self.data_packet(),
            do_tcph1=True, max_ttl=3, continue_to_max_ttl=True)
        self.assertTrue(was_successful)
        self.assertTrue(os.path.exists(path))
        self.assertEqual(len(self.hops()), 3)

    def test_the_refused_handshake_is_a_star_hop_carrying_the_reason(self):
        """The path must not gain a node: the SYN goes out at the default TTL,
        so whoever refused it is not the hop being probed. The evidence still
        has to survive into the JSON, or the run looks like a plain timeout."""
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: icmp_prohibited("10.10.34.34", p[IP].dst)))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=self.data_packet(), do_tcph1=True,
                       max_ttl=2, continue_to_max_ttl=True)
        first = self.hops()[0]["result"][0]
        self.assertEqual(first["x"], "*")
        self.assertNotIn("from", first)
        self.assertIn("dest-unreach", first["note"])
        self.assertIn("10.10.34.34", first["note"])

    def test_a_plain_timeout_still_serialises_without_a_note(self):
        """The new keys are additive: a hop that simply never answered has to
        serialise exactly as it did before."""
        net = FakeNetwork()
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=self.data_packet(), do_tcph1=True,
                       max_ttl=2, continue_to_max_ttl=True)
        self.assertEqual(sorted(self.hops()[0]["result"][0]), ["packets", "x"])

    def test_an_injected_rst_on_the_syn_is_counted_not_swallowed(self):
        """A refused handshake never reaches the
        data-packet `sr()`, so without carrying the count out of the handshake
        these RSTs are invisible to every downstream classifier."""
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: IP(src=p[IP].dst, ttl=50) / TCP(
                sport=p[TCP].dport, dport=p[TCP].sport, flags="RA")))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=self.data_packet(), do_tcph1=True,
                       max_ttl=2, continue_to_max_ttl=True)
        self.assertEqual(self.hops()[0]["result"][0]["rst_count"], 1)

    def test_a_refusal_is_not_retried(self):
        """Silence gets five SYNs; a refusal gets one.

        A box that answers is awake, so four more SYNs buy nothing — and a
        five-fold SYN burst aimed at a censor's DPI is not a safe default for
        whoever is holding the laptop.
        """
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: icmp_prohibited("10.10.34.34", p[IP].dst)))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=self.data_packet(), do_tcph1=True,
                       max_ttl=1, continue_to_max_ttl=True)
        self.assertEqual(len(net.probes), 1)
        self.assertEqual(net.probes[0].flags, "S")

    def test_syn_rsts_can_trip_the_port_rotation(self):
        """M5c rotation could only ever see RSTs answering the *data* packet,
        which a refused handshake never sends."""
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: IP(src=p[IP].dst, ttl=50) / TCP(
                sport=p[TCP].dport, dport=p[TCP].sport, flags="RA")))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=self.data_packet(dport=8080),
                       do_tcph1=True, max_ttl=5, continue_to_max_ttl=True,
                       dst_port=8080, port_pool=[8080, 2053, 2083])
        used = [p.dport for p in net.probes]
        self.assertEqual(used[:3], [8080, 8080, 8080])
        self.assertIn(used[3], (2053, 2083))

    def test_a_refused_preflight_still_yields_a_packet_to_replay(self):
        """--paris indexes `unanswered[0][0]` when the preflight found nothing.
        A refusal leaves `sr()`'s unanswered list empty, so the SYNs actually
        sent have to be handed back or the preflight dies on an empty list."""
        net = FakeNetwork(rule=self.refuse_syn_with(
            lambda p: icmp_prohibited("10.10.34.34", p[IP].dst)))
        was_successful, _, _ = self.run_trace(
            net, ip_list=["1.1.1.1"], request_packet_1=self.data_packet(),
            do_tcph1=True, max_ttl=2, trace_with_retransmission=True)
        self.assertTrue(was_successful)
        self.assertIn(trace.PREFLIGHT_FAILED_NOTE,
                      trace.measurement_data[0][0].annotation)


class TestLayer3SendsCarryNoIface(TraceTestCase):
    """scapy >= 2.6 deletes `iface` from L3 sends and warns.

    Three `SyntaxWarning`s were printed at the head of every run — the first
    before the banner, so it read like a startup failure — and the flag they came
    from had no effect on the wire at all.
    """

    def test_no_probe_is_sent_with_an_iface_kwarg(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
                       max_ttl=3, continue_to_max_ttl=True)
        self.assertTrue(net.probes)
        for probe in net.probes:
            self.assertNotIn("iface", probe.kwargs)

    def test_the_handshake_path_sends_no_iface_either(self):
        net = FakeNetwork(rule=lambda p: tcp_reply("1.1.1.1"))
        with ExitStack() as stack:
            patched(net, stack)
            trace.send_packet(
                request_packet=IP(dst="1.1.1.1") / TCP(dport=443, flags="PA"),
                request_ip="1.1.1.1", current_ttl=1, timeout=1,
                do_tcphandshake=True, trace_retransmission=False,
                do_not_parse=False)
        self.assertEqual(len(net.probes), 2)
        for probe in net.probes:
            self.assertNotIn("iface", probe.kwargs)


class TestAdaptiveTimeout(TraceTestCase):
    """M5c: opt-in per-hop timeout growth (`--adaptive-timeout`, backlog §1.8)."""

    def test_off_by_default_the_timeout_never_moves(self):
        """A slow hop with the flag off changes nothing — existing runs keep
        their timing."""
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"), rtt=3000.0)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=4, timeout=1, continue_to_max_ttl=True)
        self.assertEqual({p.timeout for p in net.probes}, {1})

    def test_a_slow_answered_hop_grows_the_next_timeout(self):
        """A 3s RTT at scale 3 asks for ~9s on the following hop."""
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"), rtt=3000.0)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=3, timeout=1, continue_to_max_ttl=True,
            adaptive_timeout=True)
        # The first probe has no history and uses the base; later ones grow.
        self.assertEqual([p.timeout for p in net.probes], [1, 9, 9])

    def test_growth_is_capped(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"), rtt=90_000.0)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=3, timeout=1, continue_to_max_ttl=True,
            adaptive_timeout=True)
        self.assertEqual(net.probes[1].timeout, 60)

    def test_rtt_history_is_kept_per_destination(self):
        """A slow destination must not inflate a fast one's timeout."""
        net = FakeNetwork(
            rule=lambda p: icmp_time_exceeded("10.0.0.1"),
            rtt=lambda p: 3000.0 if p[IP].dst == "1.1.1.1" else 5.0)
        self.run_trace(
            net, ip_list=["1.1.1.1", "8.8.8.8"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=2, timeout=1, continue_to_max_ttl=True,
            adaptive_timeout=True)
        by_dst = {}
        for probe in net.probes:
            by_dst.setdefault(probe.dst, []).append(probe.timeout)
        self.assertEqual(by_dst["1.1.1.1"], [1, 9])
        self.assertEqual(by_dst["8.8.8.8"], [1, 1])

    def test_a_timed_out_hop_must_not_grow_the_timeout(self):
        """The trap this feature is one line away from.

        `parse_packet` returns the wall-clock elapsed time even when nothing
        answered — which *is* the timeout. Feeding that back as "the last RTT"
        would ratchet every blocked path to the 60s cap on the second TTL step
        and hold it there, turning a 20-hop dead arm into a 20-minute one.
        """
        net = FakeNetwork()                       # nothing ever answers
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=5, timeout=1, continue_to_max_ttl=True,
            adaptive_timeout=True)
        self.assertEqual({p.timeout for p in net.probes}, {1})

class TestPostTraceDpiRecompute(TraceTestCase):
    def test_single_packet_trace_survives_the_post_trace_recompute(self):
        """Regression: a one-packet trace used to lose all of its results.

        `measurement_data` is always a 2-element list, but the second block is
        only filled when a second packet is configured. `_recompute_dpi_from_per_hop`
        walked both blocks unconditionally and raised IndexError *after* the trace
        completed and *before* the JSON was written — `tracevis.py` catches it and
        exits 2, so the whole run was discarded. Eight of the twelve shipped
        samples are single-packet, and no test ran a trace, so nothing caught it.
        """
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        was_successful, path, _ = self.run_trace(
            net, ip_list=["1.1.1.1", "8.8.8.8"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            max_ttl=2)
        self.assertTrue(was_successful)
        self.assertTrue(os.path.exists(path), "single-packet trace saved nothing")
        self.assertEqual(trace.measurement_data[1], [])

    def test_blocked_tcp_path_is_flagged_as_silently_dropped(self):
        """The post-trace reclassify must override the pre-trace optimism.

        Flags are first set before any packet is sent (network_state "open" ->
        `dpi_cleared=True`); `_recompute_dpi_from_per_hop` has to correct that
        from the hops actually observed.
        """
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("172.16.4.43")
                          if p[IP].ttl <= 1 else None)
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            max_ttl=3)
        entry = trace.measurement_data[0][0]
        self.assertFalse(entry.dpi_cleared)
        self.assertTrue(entry.tcp_silently_dropped)

    def test_reached_tcp_path_is_not_flagged(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("1.1.1.1"))
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / TCP(dport=443, flags="S"),
            max_ttl=3)
        entry = trace.measurement_data[0][0]
        self.assertFalse(entry.tcp_silently_dropped)
        self.assertTrue(entry.dpi_cleared)


class TestSavedMeasurementLeaksNothing(TraceTestCase):
    """Backlog §2.8. Field captures carried the operator's local address in
    `src_addr` and in every stored packet blob, because `set_endtime` only
    scrubbed the source when it equalled the *public* address — true for an
    unNATted host and for nobody else.

    Asserted against the bytes on disk rather than the objects: the leak was in
    what got written, and that is the only artefact anyone shares.
    """

    HOPS = ("192.168.1.1", "100.76.0.1", "172.16.4.43")

    def path_rule(self, packet):
        ttl = packet[IP].ttl
        if 1 <= ttl <= len(self.HOPS):
            return icmp_time_exceeded(self.HOPS[ttl - 1])
        return None

    def saved(self, **kwargs):
        net = FakeNetwork(rule=self.path_rule)
        _, path, _ = self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
            max_ttl=3, continue_to_max_ttl=True, **kwargs)
        with open(path) as handle:
            return handle.read()

    def test_the_source_address_never_reaches_disk(self):
        with mock.patch("utils.trace.user_source_ip_address", "192.168.1.5"):
            blob = self.saved()
        self.assertNotIn("192.168.1.5", blob)
        self.assertIn(SRC, blob)

    def test_path_hops_are_kept_by_default(self):
        """Anonymising is not free. Hop addresses are the measurement, so the
        default removes identity only."""
        blob = self.saved()
        for address in self.HOPS:
            self.assertIn(address, blob)

    def test_anonymize_pseudonymises_private_hops(self):
        blob = self.saved(anonymize=True)
        self.assertNotIn("192.168.1.1", blob)
        self.assertNotIn("172.16.4.43", blob)
        self.assertIn("192.0.2.", blob)

    def test_anonymize_keeps_the_cgnat_hop(self):
        """`utils.dpi.is_cgnat_address` reads this back out of the saved hops;
        pseudonymising it would disable `cgnat_hop` without saying so."""
        blob = self.saved(anonymize=True)
        self.assertIn("100.76.0.1", blob)
        self.assertIn('"cgnat_hop": true', blob)

    def test_anonymize_keeps_the_destination(self):
        blob = self.saved(anonymize=True)
        self.assertIn("1.1.1.1", blob)


class TestForgedReplyDetection(TraceTestCase):
    """Backlog §2.12 end to end: the interceptor reproduced in the harness.

    The mechanism observed in the field — the box reflects the
    query rather than composing a reply, so the IP ID comes back unchanged and
    the TTL is whatever was left of the probe's.
    """

    HOPS = ("192.168.1.1", "100.76.0.1", "172.16.4.43")
    DESTINATION_STEP = 5

    def path(self, packet, forge):
        ttl = packet[IP].ttl
        if 1 <= ttl <= len(self.HOPS):
            return icmp_time_exceeded(self.HOPS[ttl - 1])
        if ttl < self.DESTINATION_STEP:
            return None
        if forge:
            # Reflected: the query's own IP ID, and its exhausted TTL.
            return IP(src=packet[IP].dst, id=packet[IP].id, ttl=1) / UDP(sport=53)
        return IP(src=packet[IP].dst, id=54321, ttl=52) / UDP(sport=53)

    def run_probe(self, forge):
        net = FakeNetwork(rule=lambda p: self.path(p, forge))
        _, saved, _ = self.run_trace(
            net, ip_list=["1.1.1.1"], max_ttl=6, continue_to_max_ttl=True,
            request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53))
        entry = trace.measurement_data[0][0]
        with open(saved) as handle:
            return entry, handle.read()

    def test_a_reflected_reply_is_flagged_with_its_evidence(self):
        entry, blob = self.run_probe(forge=True)
        self.assertTrue(entry.reply_forged)
        self.assertIn("ip-id-reflected", entry.forgery_evidence)
        self.assertIn("reply-ttl-implausible", entry.forgery_evidence)
        self.assertIn('"reply_forged": true', blob)

    def test_a_genuine_reply_is_not_flagged(self):
        entry, blob = self.run_probe(forge=False)
        self.assertFalse(entry.reply_forged)
        self.assertEqual(entry.forgery_evidence, "")
        self.assertIn('"reply_forged": false', blob)

    def test_a_forged_reply_is_not_a_cleared_path(self):
        """`dpi_cleared` used to stay true beside `reply_forged`."""
        entry, _ = self.run_probe(forge=True)
        self.assertFalse(entry.dpi_cleared)

    def test_the_evidence_survives_into_the_saved_measurement(self):
        """A flag saying someone forged your traffic has to be re-checkable
        from the file, not just from the console."""
        _, blob = self.run_probe(forge=True)
        self.assertIn("ip-id-reflected", blob)


class TestInterruptedTraceIsStillAnalysed(TraceTestCase):
    """Ctrl-C wrote straight to disk, skipping the post-trace analysis.

    So an interrupted trace kept the *pre-trace* classification — the very thing
    that pass exists to correct — and every detector was wrong at once:
    `dpi_cleared` true on an intercepted path, `cgnat_hop` false with an RFC 6598
    hop in the saved hops, `reply_forged` false with a reflected reply beside it.
    `--anonymize` was ignored too, because the module-level entry point rebuilt a
    `Tracer` and lost the run's settings.

    It matters most exactly where it was missing: under
    `--timeout-profile shutdown` a trace runs for hours, so Ctrl-C is a normal
    way to end one.
    """

    HOPS = ("192.168.1.1", "100.76.0.1")

    def rule(self, packet):
        ttl = packet[IP].ttl
        if 1 <= ttl <= len(self.HOPS):
            return icmp_time_exceeded(self.HOPS[ttl - 1])
        # The destination answers, but the reply is reflected — forged.
        return IP(src=packet[IP].dst, id=packet[IP].id, ttl=1) / UDP(sport=53)

    def interrupted_save(self, **kwargs):
        net = FakeNetwork(rule=self.rule)
        sent = {"n": 0}

        def interrupt_after_four(*args, **kwds):
            sent["n"] += 1
            if sent["n"] > 4:
                raise KeyboardInterrupt
            return net(*args, **kwds)

        with ExitStack() as stack:
            patched(net, stack)
            stack.enter_context(mock.patch("utils.trace.sr", interrupt_after_four))
            stack.enter_context(
                mock.patch("utils.trace.user_source_ip_address", "192.168.1.5"))
            try:
                trace.trace_route(
                    ip_list=["1.1.1.1"], output_dir=self.tmp + "/", max_ttl=8,
                    timeout=1, repeat_requests=1, continue_to_max_ttl=True,
                    request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53), **kwargs)
            except KeyboardInterrupt:
                path = trace.save_partial_measurement(
                    output_dir=self.tmp + "/", name_prefix="p",
                    continue_to_max_ttl=True)
        with open(path) as handle:
            return json.load(handle)[0], open(path).read()

    def test_the_partial_save_carries_the_real_flags(self):
        measurement, _ = self.interrupted_save()
        self.assertTrue(measurement["cgnat_hop"])
        self.assertTrue(measurement["reply_forged"])
        self.assertIn("ip-id-reflected", measurement["forgery_evidence"])
        self.assertFalse(measurement["dpi_cleared"])

    def test_anonymize_is_honoured_on_the_interrupt_path(self):
        _, blob = self.interrupted_save(anonymize=True)
        self.assertNotIn("192.168.1.1", blob)
        self.assertIn("192.0.2.", blob)

    def test_the_source_is_scrubbed_either_way(self):
        for kwargs in ({}, {"anonymize": True}):
            _, blob = self.interrupted_save(**kwargs)
            self.assertNotIn("192.168.1.5", blob)

    def test_an_interrupt_before_the_trace_loop_saves_nothing_and_raises_nothing(self):
        """`finalise_measurements` has no context to work from at that point."""
        trace.measurement_data = [[], []]
        trace._active_tracer = None
        with redirect_stdout(io.StringIO()):
            self.assertEqual(trace.save_partial_measurement(
                output_dir=self.tmp + "/", name_prefix="p",
                continue_to_max_ttl=True), "")


class TestCgnatDetection(TraceTestCase):
    """The trace already collects the evidence; it just was not consulted.

    Reproduces the measured topology: hop 2 in RFC 6598 space, on a network
    the detector calls `open` because the provider it reaches is allowlisted.
    """

    @staticmethod
    def cgnat_path(packet):
        hops = {1: "192.168.1.1", 2: "100.76.0.1", 3: "172.16.4.43"}
        hop = hops.get(packet[IP].ttl)
        return icmp_time_exceeded(hop) if hop else None

    def measurement(self):
        return trace.measurement_data[0][0]

    def test_a_cgnat_hop_is_detected_on_an_open_network(self):
        self.run_trace(FakeNetwork(rule=self.cgnat_path), ip_list=["1.1.1.1"],
                       request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
                       max_ttl=4, continue_to_max_ttl=True)
        self.assertEqual(self.measurement().network_state, "open")
        self.assertTrue(self.measurement().cgnat_hop)

    def test_a_path_with_no_cgnat_hop_is_not_flagged(self):
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        self.run_trace(net, ip_list=["1.1.1.1"],
                       request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
                       max_ttl=4, continue_to_max_ttl=True)
        self.assertFalse(self.measurement().cgnat_hop)

    def test_the_provider_evidence_is_recorded_alongside_the_state(self):
        """A state with no evidence cannot be re-read later: working out how a
        saved capture had been classified meant guessing from which metadata
        fields happened to be populated."""
        self.run_trace(FakeNetwork(rule=self.cgnat_path), ip_list=["1.1.1.1"],
                       request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
                       max_ttl=2, continue_to_max_ttl=True)
        self.assertEqual(self.measurement().provider_status, GEO_RESULT[7])
        self.assertIn('"provider_status"', self.measurement().json())

    def test_the_network_state_is_recorded_in_the_measurement(self):
        """`vis.py` used to reconstruct the regime from `cgnat_hop`, which only
        worked while the two were the same thing."""
        self.run_trace(FakeNetwork(rule=self.cgnat_path), ip_list=["1.1.1.1"],
                       request_packet_1=IP(dst="0.0.0.0") / UDP(dport=53),
                       max_ttl=2, continue_to_max_ttl=True)
        self.assertIn('"network_state": "open"', self.measurement().json())


class TestRetransmissionIpId(TraceTestCase):
    """Backlog §1.7: a predictable IP ID is a correlation handle."""

    def _ids(self, runs=6):
        seen = []
        for _ in range(runs):
            net = FakeNetwork()
            packet = IP(dst="0.0.0.0", id=1000) / TCP(dport=443, flags="S")
            self.setUp()
            self.run_trace(
                net, ip_list=["1.1.1.1"], request_packet_1=packet,
                max_ttl=1, trace_retransmission=True)
            seen.append(net.probes[0].ip_id)
        return seen

    def test_the_starting_id_is_not_a_fixed_offset_from_the_stored_packet(self):
        """It used to be exactly `stored + 15`, and the stored value is a
        constant committed in `samples/`."""
        ids = self._ids()
        self.assertNotIn(1015, ids, "still a fixed +15 from the stored ID")
        self.assertGreater(len(set(ids)), 1, "starting ID is not random")

    def test_retransmissions_still_increment_sequentially(self):
        """Randomising *every* packet would be worse, not better.

        Real OS retransmissions increment the IP ID, so a stream that jumped
        around would look less like the retransmission it is imitating. Only the
        starting point is randomised.
        """
        net = FakeNetwork()
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0", id=1000) / TCP(dport=443, flags="S"),
            max_ttl=4, continue_to_max_ttl=True, trace_retransmission=True)
        ids = [p.ip_id for p in net.probes]
        self.assertEqual(ids, list(range(ids[0], ids[0] + len(ids))))

    def test_two_packets_get_independent_starting_ids(self):
        net = FakeNetwork()
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0", id=1000) / TCP(dport=443, flags="S"),
            request_packet_2=IP(dst="0.0.0.0", id=1000) / TCP(dport=8443, flags="S"),
            max_ttl=1, trace_retransmission=True)
        first = {p.ip_id for p in net.probes if p.dport == 443}
        second = {p.ip_id for p in net.probes if p.dport == 8443}
        self.assertTrue(first.isdisjoint(second),
                        "both packets started from the same ID")

    def test_a_normal_trace_is_unaffected(self):
        """`send_single_packet` already randomises; this must not double-apply."""
        net = FakeNetwork()
        self.run_trace(
            net, ip_list=["1.1.1.1"],
            request_packet_1=IP(dst="0.0.0.0", id=1000) / UDP(dport=53),
            max_ttl=2, continue_to_max_ttl=True)
        self.assertEqual(len(net.probes), 2)


class TestPortBoundModeGuards(unittest.TestCase):
    """`--port-pool` with a DNS mode silently stops measuring DNS.

    Found in a clean-network smoke run: `--dns --port-pool
    8080,2053` recorded `port: 2053`, where no resolver listens.
    """

    def _kwargs(self, argv):
        captured = {}

        def stub(**kwargs):
            captured.update(kwargs)
            return (False, "", False)

        args = tracevis.get_args(argv, auto_exit=False)
        with mock.patch("utils.trace.trace_route", side_effect=stub), \
                mock.patch("utils.vis.vis", return_value=False), \
                redirect_stdout(io.StringIO()):
            tracevis.main(args)
        return captured

    def _stdout(self, argv):
        buffer = io.StringIO()

        def stub(**kwargs):
            return (False, "", False)

        args = tracevis.get_args(argv, auto_exit=False)
        with mock.patch("utils.trace.trace_route", side_effect=stub), \
                mock.patch("utils.vis.vis", return_value=False), \
                redirect_stdout(buffer):
            tracevis.main(args)
        return buffer.getvalue()

    def test_the_default_target_pool_reaches_the_trace_with_its_roles(self):
        """Backlog §1.3: the pool is a control/treatment comparison, and every
        mode that falls back to it must get the whole thing — dropping the
        unreachable half would leave a run that cannot fail."""
        for mode in ("--dns", "--dnstcp", "--dnsdot", "--dnstt", "--sni-test"):
            kwargs = self._kwargs([mode, "-m", "1"])
            self.assertEqual(kwargs["ip_list"], utils.dns.DEFAULT_TARGETS, mode)

    def test_the_roles_are_printed_when_the_default_pool_is_used(self):
        for mode in ("--dns", "--dnstcp", "--dnsdot", "--dnstt", "--sni-test"):
            out = self._stdout([mode, "-m", "1"])
            self.assertIn("1.1.1.1 (control)", out, mode)
            self.assertIn("8.8.8.8 (treatment)", out, mode)

    def test_explicit_ips_replace_the_pool_without_role_labels(self):
        out = self._stdout(["--dns", "-i", "203.0.113.9", "-m", "1"])
        self.assertNotIn("(control)", out)

    def test_port_pool_is_dropped_for_dns_modes(self):
        for mode in ("--dns", "--dnstcp", "--dnsdot", "--dnstt"):
            kwargs = self._kwargs([mode, "--port-pool", "8080,2053", "-m", "1"])
            self.assertEqual(kwargs["dst_port"], -1, f"{mode}: port was rewritten")
            self.assertIsNone(kwargs["port_pool"], f"{mode}: pool still armed")

    def test_port_pool_still_applies_to_the_sni_probe(self):
        """The 443-shaped probes are exactly what the pool is for."""
        kwargs = self._kwargs(["--sni-test", "--port-pool", "8080,2053", "-m", "1"])
        self.assertIn(kwargs["dst_port"], (8080, 2053))
        self.assertEqual(kwargs["port_pool"], [8080, 2053])

    def test_an_explicit_port_is_still_obeyed_for_dns(self):
        """Deliberate instruction, warned about but honoured — "is UDP/2053
        reachable?" is a legitimate question."""
        kwargs = self._kwargs(["--dns", "--port", "2053", "-m", "1"])
        self.assertEqual(kwargs["dst_port"], 2053)


class TestEndToEndFromASampleConfig(TraceTestCase):
    """The full path a user takes: config file -> main() -> trace -> saved JSON.

    The single-packet crash reached `main` because nothing exercised this path;
    `test_config_file` only parses, and `TestSampleWiring` stops at `trace_route`
    with the tracer stubbed out. This runs the real loop against a fake network.
    """

    def test_a_single_packet_sample_runs_and_saves(self):
        import tracevis
        net = FakeNetwork(rule=lambda p: icmp_time_exceeded("10.0.0.1"))
        with ExitStack() as stack:
            patched(net, stack)
            stack.enter_context(mock.patch.dict(
                os.environ, {"TRACEVIS_OUTPUT_DIR": self.tmp + "/"}))
            stack.enter_context(mock.patch("utils.vis.vis", return_value=False))
            args = tracevis.get_args(
                ["--config-file", "samples/syn443.conf", "-m", "2", "-r", "1"],
                auto_exit=False)
            tracevis.main(args)
        saved = [f for f in os.listdir(self.tmp) if f.endswith(".json")]
        self.assertEqual(len(saved), 1, f"expected one measurement, got {saved}")
        self.assertTrue(net.probes, "no probes were sent")


if __name__ == "__main__":
    unittest.main()
