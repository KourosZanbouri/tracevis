"""Tests for middlebox reassembly probing (backlog §1.4, rescoped).

See docs/rescope-1.4-reassembly.md. None of this has been run against live
DPI; what is tested here is that the emitter builds a stream a reassembling
observer sees as the original payload, that the sweep runs the probes it says
it will, and that the classifier does not claim more than its inputs support.
"""

import time
import unittest
import unittest.mock
from itertools import pairwise

from utils import reassembly


class TestSegmentPayload(unittest.TestCase):
    def test_segments_reassemble_to_the_original(self):
        payload = bytes(range(256))
        segments = reassembly.segment_payload(payload, 7)
        self.assertEqual(reassembly.reassemble(segments), payload)

    def test_round_trip_holds_across_sizes_and_splits(self):
        """The probe measures its own bug if this ever fails."""
        for size in (1, 2, 3, 17, 64, 255, 1500):
            payload = bytes((i * 7) % 256 for i in range(size))
            for count in (1, 2, 3, 4, 8, 16):
                segments = reassembly.segment_payload(payload, count)
                self.assertEqual(reassembly.reassemble(segments), payload,
                                 f"size={size} count={count}")

    def test_sequence_numbers_are_contiguous(self):
        segments = reassembly.segment_payload(b"x" * 50, 4, initial_seq=1000)
        self.assertEqual(segments[0].seq, 1000)
        for earlier, later in pairwise(segments):
            self.assertEqual(later.seq, earlier.seq + len(earlier.payload))

    def test_no_segment_carries_the_whole_payload(self):
        # The point of segmenting: a per-packet inspector sees no complete
        # payload in any single segment.
        payload = b"\x16\x03\x01" + b"hcaptcha.com" + b"A" * 40
        for segment in reassembly.segment_payload(payload, 4):
            self.assertNotEqual(segment.payload, payload)
            self.assertLess(len(segment.payload), len(payload))

    def test_the_remainder_is_spread_not_dumped_on_one_segment(self):
        """A lone oversized segment would be a signature of this tool."""
        segments = reassembly.segment_payload(b"x" * 10, 4)
        sizes = [len(s.payload) for s in segments]
        self.assertEqual(sum(sizes), 10)
        self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_the_first_segment_has_no_delay(self):
        segments = reassembly.segment_payload(b"x" * 20, 4, delay_ms=250)
        self.assertEqual(segments[0].delay_ms, 0)
        self.assertTrue(all(s.delay_ms == 250 for s in segments[1:]))

    def test_only_the_last_segment_is_marked_last(self):
        segments = reassembly.segment_payload(b"x" * 20, 4)
        self.assertEqual([s.is_last for s in segments],
                         [False, False, False, True])

    def test_more_segments_than_bytes_is_clamped(self):
        segments = reassembly.segment_payload(b"abc", 10)
        self.assertEqual(len(segments), 3)
        self.assertEqual(reassembly.reassemble(segments), b"abc")

    def test_a_single_segment_is_the_whole_payload(self):
        segments = reassembly.segment_payload(b"abcdef", 1)
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0].payload, b"abcdef")

    def test_rejects_an_empty_payload(self):
        with self.assertRaises(ValueError):
            reassembly.segment_payload(b"", 4)

    def test_rejects_a_nonsense_segment_count(self):
        with self.assertRaises(ValueError):
            reassembly.segment_payload(b"abc", 0)


class TestSweepPlan(unittest.TestCase):
    def test_the_control_comes_first_and_is_a_single_segment(self):
        """Without it a sweep cannot tell an expired buffer from no block."""
        plan = reassembly.sweep_plan(delays_ms=(0, 100))
        self.assertEqual(plan[0], (1, 0))

    def test_every_requested_delay_is_planned(self):
        plan = reassembly.sweep_plan(delays_ms=(0, 50, 500), segment_count=3)
        self.assertEqual(plan[1:], [(3, 0), (3, 50), (3, 500)])

    def test_defaults_are_coarse_and_ordered(self):
        delays = [delay for _count, delay in reassembly.sweep_plan()[1:]]
        self.assertEqual(delays, sorted(delays))
        self.assertEqual(delays[0], 0)


class TestRunSweep(unittest.TestCase):
    def test_the_control_outcome_is_taken_from_the_first_probe(self):
        outcomes = iter([reassembly.BLOCKED, reassembly.DELIVERED,
                         reassembly.DELIVERED])
        control, results = reassembly.run_sweep(
            lambda _s: next(outcomes), b"x" * 20,
            reassembly.sweep_plan(delays_ms=(0, 100)),
            sleeper=lambda _s: None)
        self.assertEqual(control, reassembly.BLOCKED)
        self.assertEqual(results, [(0, reassembly.DELIVERED),
                                   (100, reassembly.DELIVERED)])

    def test_each_probe_carries_its_planned_delay(self):
        seen = []

        def sender(segments):
            seen.append(max((s.delay_ms for s in segments), default=0))
            return reassembly.BLOCKED

        reassembly.run_sweep(sender, b"x" * 20,
                             reassembly.sweep_plan(delays_ms=(0, 100, 900)),
                             sleeper=lambda _s: None)
        self.assertEqual(seen, [0, 0, 100, 900])

    def test_it_does_not_pause_after_the_last_probe(self):
        slept = []
        reassembly.run_sweep(lambda _s: reassembly.BLOCKED, b"x" * 20,
                             reassembly.sweep_plan(delays_ms=(0, 100)),
                             sleeper=slept.append)
        self.assertEqual(len(slept), 2)

    def test_a_patched_time_sleep_is_honoured(self):
        # Resolved at call time, not bound in the signature -- the same
        # defect that made a supposedly-stubbed monitor test sleep for real.
        with unittest.mock.patch.object(time, "sleep") as slept:
            reassembly.run_sweep(lambda _s: reassembly.BLOCKED, b"x" * 20,
                                 reassembly.sweep_plan(delays_ms=(0, 100)))
        self.assertEqual(slept.call_count, 2)


class TestClassifySweep(unittest.TestCase):
    def test_a_bounded_buffer_is_reported_with_its_bound(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.BLOCKED), (100, reassembly.BLOCKED),
            (1000, reassembly.DELIVERED)])
        self.assertEqual(result.verdict, reassembly.BUFFER_MEASURED)
        self.assertEqual(result.buffer_ms, 1000)

    def test_blocked_at_every_delay_means_the_buffer_outlasts_the_sweep(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.BLOCKED), (5000, reassembly.BLOCKED)])
        self.assertEqual(result.verdict, reassembly.REASSEMBLES)
        self.assertIsNone(result.buffer_ms)
        self.assertIn("longer sweep", result.needs)

    def test_delivered_at_every_delay_means_no_reassembly(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.DELIVERED), (100, reassembly.DELIVERED)])
        self.assertEqual(result.verdict, reassembly.NO_REASSEMBLY)

    def test_a_delivered_control_means_there_is_no_block_to_measure(self):
        """No block fired, so any segmented result is noise."""
        result = reassembly.classify_sweep(reassembly.DELIVERED, [
            (0, reassembly.BLOCKED)])
        self.assertEqual(result.verdict, reassembly.NOT_STREAM_BASED)
        self.assertIsNone(result.buffer_ms)

    def test_interleaved_outcomes_are_not_read_as_a_threshold(self):
        """A buffer timeout produces a threshold, not alternation."""
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.BLOCKED), (100, reassembly.DELIVERED),
            (1000, reassembly.BLOCKED)])
        self.assertEqual(result.verdict, reassembly.INCONCLUSIVE)
        self.assertIsNone(result.buffer_ms)

    def test_an_unknown_control_settles_nothing(self):
        result = reassembly.classify_sweep(reassembly.UNKNOWN, [
            (0, reassembly.BLOCKED)])
        self.assertEqual(result.verdict, reassembly.INCONCLUSIVE)

    def test_unknown_probe_outcomes_are_discarded_not_counted(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.UNKNOWN), (100, reassembly.UNKNOWN)])
        self.assertEqual(result.verdict, reassembly.INCONCLUSIVE)

    def test_no_verdict_claims_strong_confidence(self):
        """Nothing here has been validated against live DPI, so nothing
        in it is entitled to call itself strong."""
        cases = [
            (reassembly.BLOCKED, [(0, reassembly.BLOCKED),
                                  (1000, reassembly.DELIVERED)]),
            (reassembly.BLOCKED, [(0, reassembly.BLOCKED)]),
            (reassembly.BLOCKED, [(0, reassembly.DELIVERED)]),
            (reassembly.DELIVERED, [(0, reassembly.BLOCKED)]),
            (reassembly.UNKNOWN, [(0, reassembly.BLOCKED)]),
        ]
        for control, results in cases:
            self.assertIn(
                reassembly.classify_sweep(control, results).confidence,
                ("weak", "moderate"))


class TestFormatting(unittest.TestCase):
    def test_it_always_says_it_is_unvalidated(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.BLOCKED), (1000, reassembly.DELIVERED)])
        self.assertIn("never been run against live DPI",
                      reassembly.format_sweep(result))

    def test_a_measured_buffer_is_shown(self):
        result = reassembly.classify_sweep(reassembly.BLOCKED, [
            (0, reassembly.BLOCKED), (1000, reassembly.DELIVERED)])
        self.assertIn("1000ms", reassembly.format_sweep(result))


class TestScapySender(unittest.TestCase):
    """The send path, with every scapy entry point injected.

    What a real middlebox does in response is untestable here and untested;
    what the sender itself does -- handshake, segment order, sequence
    numbers, and how it maps a reply to an outcome -- is not.
    """

    def _sender(self, reply="payload"):
        from scapy.all import IP, TCP, Raw
        self.sent = []

        def sr_func(packet, **_kwargs):
            if str(packet[TCP].flags) == "S":
                if reply == "no-synack":
                    return [], [packet]
                if reply == "syn-refused":
                    # Answered, but not with a SYN-ACK. The field case from
                    # M5f: an injected RST or an ICMP error to the SYN.
                    return [(packet, IP(src=packet[IP].dst) / TCP(
                        sport=packet[TCP].dport, dport=packet[TCP].sport,
                        flags="RA", seq=0, ack=packet[TCP].seq + 1))], []
                return [(packet, IP(src=packet[IP].dst) / TCP(
                    sport=packet[TCP].dport, dport=packet[TCP].sport,
                    flags="SA", seq=5000, ack=packet[TCP].seq + 1))], []
            if reply == "silent":
                return [], [packet]
            if reply == "rst":
                return [(packet, IP(src=packet[IP].dst) / TCP(flags="R"))], []
            if reply == "bare-ack":
                return [(packet, IP(src=packet[IP].dst) / TCP(flags="A"))], []
            return [(packet, IP(src=packet[IP].dst) / TCP(flags="PA")
                     / Raw(load=b"\x16\x03\x03"))], []

        self.slept = []
        return reassembly.make_scapy_sender(
            "1.1.1.1", 443, "10.0.0.1", sr_func=sr_func,
            send_func=lambda packet, **_k: self.sent.append(packet),
            sleeper=self.slept.append, port_reserver=lambda: 40000)

    @staticmethod
    def _payload():
        return b"\x16\x03\x01" + b"A" * 40

    def test_the_bytes_on_the_wire_reassemble_to_the_payload(self):
        from scapy.all import Raw
        sender = self._sender()
        sender(reassembly.segment_payload(self._payload(), 4))
        wire = b"".join(bytes(packet[Raw].load) for packet in self.sent)
        self.assertEqual(wire, self._payload())

    def test_wire_sequence_numbers_are_contiguous(self):
        from scapy.all import TCP, Raw
        sender = self._sender()
        sender(reassembly.segment_payload(self._payload(), 4))
        for earlier, later in pairwise(self.sent):
            self.assertEqual(later[TCP].seq,
                             earlier[TCP].seq + len(bytes(earlier[Raw].load)))

    def test_no_single_packet_carries_the_whole_payload(self):
        from scapy.all import Raw
        sender = self._sender()
        sender(reassembly.segment_payload(self._payload(), 4))
        for packet in self.sent:
            self.assertNotEqual(bytes(packet[Raw].load), self._payload())

    def test_the_inter_segment_delays_are_applied(self):
        sender = self._sender()
        sender(reassembly.segment_payload(self._payload(), 4, delay_ms=250))
        # First segment has no delay; the other three wait 250ms each.
        self.assertEqual(self.slept, [0.25, 0.25, 0.25])

    def test_application_bytes_back_means_delivered(self):
        sender = self._sender(reply="payload")
        self.assertEqual(sender(reassembly.segment_payload(self._payload(), 4)),
                         reassembly.DELIVERED)

    def test_an_injected_rst_means_blocked(self):
        sender = self._sender(reply="rst")
        self.assertEqual(sender(reassembly.segment_payload(self._payload(), 4)),
                         reassembly.BLOCKED)

    def test_silence_means_blocked(self):
        # Sound only because the probe sends a ClientHello to a host that
        # would answer one; documented on make_scapy_sender.
        sender = self._sender(reply="silent")
        self.assertEqual(sender(reassembly.segment_payload(self._payload(), 4)),
                         reassembly.BLOCKED)

    def test_a_refused_handshake_is_unknown_not_blocked(self):
        """A closed port is a fact about the port, not about inspection."""
        sender = self._sender(reply="no-synack")
        self.assertEqual(sender(reassembly.segment_payload(self._payload(), 4)),
                         reassembly.UNKNOWN)
        self.assertEqual(self.sent, [], "no payload may be sent without a handshake")

    def test_a_syn_answered_by_an_rst_is_unknown_not_blocked(self):
        """Answered, but not with a SYN-ACK — a refused connection.

        Distinct from silence, and the case that actually happens: an
        injected RST or an ICMP error to the SYN. Reporting it as BLOCKED
        would invent a payload finding out of a closed port, and sending the
        segments anyway would measure a connection that does not exist.
        """
        sender = self._sender(reply="syn-refused")
        self.assertEqual(sender(reassembly.segment_payload(self._payload(), 4)),
                         reassembly.UNKNOWN)
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
