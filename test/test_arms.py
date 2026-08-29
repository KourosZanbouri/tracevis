"""Tests for A/B arm comparison (backlog §2.10)."""

import unittest

from utils import arms


def _measurement(dst="1.1.1.1", annotation="treatment", proto="TCP", port=443,
                 reached=False, last_hop=3, total_hops=20, handshake=None,
                 app_answer=False):
    """A capture-shaped measurement whose arm facts are controllable."""
    result = []
    for index in range(1, total_hops + 1):
        replies = []
        if index <= last_hop:
            replies.append({"from": f"10.0.0.{index}", "rtt": 1.0,
                            "summary": "IP / ICMP time-exceeded"})
        elif reached and index == total_hops:
            replies.append({"from": dst, "rtt": 1.0,
                            "summary": ("IP / TCP > PA / Raw" if app_answer
                                        else "IP / TCP > A")})
        else:
            replies.append({"x": "*"})
        if handshake is not None:
            replies[0]["handshake"] = handshake
        result.append({"hop": index, "result": replies})
    if reached:
        result[-1]["result"] = [{
            "from": dst, "rtt": 1.0,
            "summary": "IP / TCP > PA / Raw" if app_answer else "IP / TCP > A",
            **({"handshake": handshake} if handshake is not None else {})}]
    return {"dst_addr": dst, "annotation": annotation, "proto": proto,
            "port": port, "result": result}


def _control(**kwargs):
    kwargs.setdefault("annotation", "TLS ClientHello :443 (control)")
    return _measurement(**kwargs)


class TestSummariseArm(unittest.TestCase):
    def test_reads_reachability_and_the_last_responding_hop(self):
        summary = arms.summarise_arm(
            _measurement(reached=True, last_hop=4, total_hops=10))
        self.assertTrue(summary.reached)
        self.assertEqual(summary.last_responding_hop, 10)

    def test_an_unreached_arm_reports_where_it_died(self):
        summary = arms.summarise_arm(_measurement(reached=False, last_hop=3))
        self.assertFalse(summary.reached)
        self.assertEqual(summary.last_responding_hop, 3)

    def test_application_payload_is_distinguished_from_a_bare_ack(self):
        """A server answering with bytes is different from a bare TCP ack."""
        with_payload = arms.summarise_arm(
            _measurement(reached=True, app_answer=True))
        bare = arms.summarise_arm(_measurement(reached=True, app_answer=False))
        self.assertTrue(with_payload.app_answered)
        self.assertFalse(bare.app_answered)

    def test_handshake_is_none_when_the_capture_does_not_record_it(self):
        # Captures predating §2.10 exist and must not be read as a failure.
        self.assertIsNone(arms.summarise_arm(_measurement()).handshake)

    def test_a_successful_handshake_is_not_unproven_by_a_later_failure(self):
        measurement = _measurement(last_hop=2, total_hops=3)
        measurement["result"][0]["result"][0]["handshake"] = True
        measurement["result"][1]["result"][0]["handshake"] = False
        self.assertTrue(arms.summarise_arm(measurement).handshake)


class TestClassification(unittest.TestCase):
    def _verdict(self, control, treatment):
        verdicts = arms.compare_arms([control, treatment])
        self.assertEqual(len(verdicts), 1)
        return verdicts[0]

    def test_handshake_through_and_payload_silent_is_a_drop(self):
        """The case the samples could not settle before.

        The handshake is not TTL-limited, so a SYN-ACK proves the destination
        was reachable; a data probe that then gets nothing was dropped.
        """
        entry = self._verdict(
            _control(reached=True, last_hop=4, app_answer=True),
            _measurement(reached=False, handshake=True))
        self.assertEqual(entry.verdict, arms.PAYLOAD_DROPPED)
        self.assertEqual(entry.confidence, "strong")
        self.assertEqual(entry.needs, "")

    def test_without_the_handshake_datum_it_only_says_probably(self):
        """An honest downgrade, not a guess dressed as a finding."""
        entry = self._verdict(
            _control(reached=True, last_hop=4, app_answer=True),
            _measurement(reached=False, handshake=None))
        self.assertEqual(entry.verdict, arms.PAYLOAD_PROBABLY_DROPPED)
        self.assertEqual(entry.confidence, "moderate")
        self.assertIn("handshake", entry.needs)

    def test_a_failed_handshake_says_the_payload_was_never_delivered(self):
        entry = self._verdict(
            _control(reached=True, last_hop=4, app_answer=True),
            _measurement(reached=False, handshake=False))
        self.assertEqual(entry.verdict, arms.TREATMENT_UNREACHABLE)

    def test_both_arms_dying_at_the_same_hop_is_not_payload_based(self):
        """The wireguard case: a port block, which is a result, not a failure."""
        entry = self._verdict(
            _control(reached=False, last_hop=3, proto="UDP", port=51820),
            _measurement(reached=False, last_hop=3, proto="UDP", port=51820))
        self.assertEqual(entry.verdict, arms.PORT_BLOCKED)
        self.assertIn("not the payload", entry.reason)

    def test_both_dying_at_different_hops_is_inconclusive(self):
        entry = self._verdict(
            _control(reached=False, last_hop=2),
            _measurement(reached=False, last_hop=3))
        self.assertEqual(entry.verdict, arms.INCONCLUSIVE)
        self.assertEqual(entry.confidence, "weak")

    def test_both_arms_delivered(self):
        entry = self._verdict(
            _control(reached=True, last_hop=4),
            _measurement(reached=True, last_hop=4))
        self.assertEqual(entry.verdict, arms.BOTH_DELIVERED)

    def test_a_failed_control_invalidates_the_pairing(self):
        entry = self._verdict(
            _control(reached=False, last_hop=3),
            _measurement(reached=True, last_hop=4))
        self.assertEqual(entry.verdict, arms.CONTROL_FAILED)
        self.assertEqual(entry.confidence, "weak")


class TestPairing(unittest.TestCase):
    def test_arms_are_paired_per_destination(self):
        verdicts = arms.compare_arms([
            _control(dst="1.1.1.1"), _measurement(dst="1.1.1.1"),
            _control(dst="8.8.8.8"), _measurement(dst="8.8.8.8"),
        ])
        self.assertEqual(sorted(v.dst for v in verdicts), ["1.1.1.1", "8.8.8.8"])

    def test_a_capture_with_no_control_yields_nothing(self):
        self.assertEqual(arms.compare_arms([_measurement(), _measurement()]), [])

    def test_a_capture_with_no_treatment_yields_nothing(self):
        self.assertEqual(arms.compare_arms([_control(), _control()]), [])

    def test_non_dict_entries_are_skipped(self):
        self.assertEqual(arms.compare_arms(["junk", None, 7]), [])

    def test_several_treatments_share_one_control(self):
        verdicts = arms.compare_arms([
            _control(reached=True, last_hop=4),
            _measurement(annotation="arm A"),
            _measurement(annotation="arm B"),
        ])
        self.assertEqual(len(verdicts), 2)


class TestFormatting(unittest.TestCase):
    def test_says_so_when_there_is_nothing_to_compare(self):
        self.assertIn("no control/treatment pairs", arms.format_arms([]))

    def test_renders_the_verdict_and_its_confidence(self):
        report = arms.format_arms(arms.compare_arms([
            _control(reached=True, last_hop=4, app_answer=True),
            _measurement(reached=False, handshake=True)]))
        self.assertIn(arms.PAYLOAD_DROPPED, report)
        self.assertIn("[strong]", report)

    def test_names_what_would_settle_an_open_question(self):
        report = arms.format_arms(arms.compare_arms([
            _control(reached=False, last_hop=3),
            _measurement(reached=False, last_hop=3)]))
        self.assertIn("needs:", report)


if __name__ == "__main__":
    unittest.main()
