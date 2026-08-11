"""Backlog §2.12 — replies written by something other than the destination.

Calibrated against a capture (kept locally, not published) that is labelled in
both directions: three destinations, each probed with an accessible domain
(reached the real resolver) and a blocked one (answered by an interceptor),
inside one minute. The numbers below are that capture verbatim.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import utils.vis
from utils import forgery

# From the calibration capture.
# (destination, sent IP ID, reply IP ID, reply IP TTL, TTL step it answered at)
GENUINE = [
    ("1.1.1.1", 30012, 12807, 52, 9),
    ("1.0.0.1", 42993, 48316, 52, 10),
    ("8.8.8.8", 1763, 25421, 118, 12),
]
FORGED = [
    ("1.1.1.1", 11796, 11796, 1, 9),
    ("1.0.0.1", 32816, 32816, 1, 9),
    ("8.8.8.8", 33182, 33182, 1, 9),
]


def reply(sent_id, received_id, reply_ttl):
    """The saved IP-header pair for one answered hop, as the tracer writes it —
    strings, because `convert_packetlist` renders every field with `show2()`."""
    return {"id": str(sent_id)}, {"id": str(received_id), "ttl": str(reply_ttl)}


class _Entry:
    """Stand-in for the parts of `traceroute_data` the detector reads."""

    def __init__(self, dst_addr, hops):
        self.dst_addr = dst_addr
        self.result = hops


def hop(step, from_ip, sent_ip=None, received_ip=None):
    result = {"from": from_ip}
    if received_ip is not None:
        result["packets"] = {"sent": {"IP": sent_ip or {}},
                             "received": [{"IP": received_ip}]}
    return {"hop": step, "result": [result]}


class TestIpIdReflection(unittest.TestCase):
    """The strong signal: a box that mutates the request in place leaves the
    query's IP ID on the reply. ~1 in 65536 per probe by chance."""

    def test_the_field_forgeries_are_all_caught(self):
        for dst, sent, received, _, _ in FORGED:
            self.assertTrue(forgery.is_ip_id_reflected(sent, received), dst)

    def test_no_genuine_reply_reflects(self):
        for dst, sent, received, _, _ in GENUINE:
            self.assertFalse(forgery.is_ip_id_reflected(sent, received), dst)

    def test_a_zero_id_on_both_sides_is_not_a_match(self):
        """Linux writes IP ID 0 on DF packets, so 0 == 0 says nothing about who
        composed the reply — it would fire on ordinary traffic."""
        self.assertFalse(forgery.is_ip_id_reflected(0, 0))
        self.assertFalse(forgery.is_ip_id_reflected("0x0", "0"))

    def test_missing_or_unparseable_ids_are_not_a_match(self):
        for sent, received in ((None, None), ("", "7"), ("abc", "abc"),
                               (None, 4242)):
            self.assertFalse(forgery.is_ip_id_reflected(sent, received),
                             (sent, received))

    def test_hex_and_decimal_render_the_same_id(self):
        self.assertTrue(forgery.is_ip_id_reflected("0x2e14", "11796"))


class TestTtlPlausibility(unittest.TestCase):
    """A reply from `d` hops away should arrive with `initial_ttl - d`, and real
    initial TTLs are 64, 128 or 255."""

    def test_the_field_forgeries_imply_an_impossible_initial_ttl(self):
        for dst, _, _, reply_ttl, step in FORGED:
            self.assertEqual(forgery.implied_initial_ttl(reply_ttl, step), 10, dst)
            self.assertTrue(forgery.is_reply_ttl_implausible(reply_ttl, step), dst)

    def test_genuine_replies_imply_a_real_initial_ttl(self):
        for dst, _, _, reply_ttl, step in GENUINE:
            implied = forgery.implied_initial_ttl(reply_ttl, step)
            self.assertIn(implied, (61, 62, 130), dst)
            self.assertFalse(forgery.is_reply_ttl_implausible(reply_ttl, step), dst)

    def test_an_asymmetric_return_path_does_not_trip_it(self):
        """The threshold sits far below 64 precisely because the return path can
        be longer than the forward one; 20 extra hops still does not fire."""
        self.assertFalse(forgery.is_reply_ttl_implausible(64 - 30, 10))

    def test_a_missing_or_zero_ttl_is_not_evidence(self):
        for reply_ttl, step in ((None, 9), (0, 9), ("", 9), (52, None)):
            self.assertFalse(forgery.is_reply_ttl_implausible(reply_ttl, step),
                             (reply_ttl, step))


class TestClassifyReply(unittest.TestCase):
    def test_either_signal_alone_is_enough(self):
        """They are independent — one is about who composed the packet, the
        other about how far it travelled — so requiring both would throw away a
        detection whenever an interceptor fixes up one of them."""
        id_only = forgery.classify_reply(*reply(500, 500, 52), hop_distance=9)
        ttl_only = forgery.classify_reply(*reply(500, 900, 1), hop_distance=9)
        self.assertTrue(id_only.forged)
        self.assertEqual(id_only.evidence, "ip-id-reflected")
        self.assertTrue(ttl_only.forged)
        self.assertIn("reply-ttl-implausible", ttl_only.evidence)

    def test_the_evidence_names_both_when_both_fire(self):
        signal = forgery.classify_reply(*reply(11796, 11796, 1), hop_distance=9)
        self.assertIn("ip-id-reflected", signal.evidence)
        self.assertIn("implied-initial=10", signal.evidence)

    def test_a_genuine_reply_yields_no_evidence(self):
        signal = forgery.classify_reply(*reply(30012, 12807, 52), hop_distance=9)
        self.assertFalse(signal.forged)
        self.assertEqual(signal.evidence, "")

    def test_missing_headers_are_not_evidence(self):
        self.assertFalse(forgery.classify_reply().forged)
        self.assertFalse(forgery.classify_reply(sent_ip={}, received_ip={}).forged)


class TestFindForgedDestinationReply(unittest.TestCase):
    def test_the_whole_field_capture_is_classified_correctly(self):
        for dst, sent, received, reply_ttl, step in FORGED:
            entry = _Entry(dst, [hop(step, dst, *reply(sent, received, reply_ttl))])
            self.assertTrue(forgery.find_forged_destination_reply(entry).forged, dst)
        for dst, sent, received, reply_ttl, step in GENUINE:
            entry = _Entry(dst, [hop(step, dst, *reply(sent, received, reply_ttl))])
            self.assertFalse(forgery.find_forged_destination_reply(entry).forged, dst)

    def test_only_replies_claiming_to_be_the_destination_are_judged(self):
        """An intermediate hop's ICMP legitimately quotes the packet that
        triggered it, so its IP ID matches by design — judging those would flag
        every hop of every trace."""
        entry = _Entry("1.1.1.1", [
            hop(1, "192.168.1.1", *reply(11796, 11796, 1)),
            hop(2, "100.76.0.1", *reply(32816, 32816, 1)),
        ])
        self.assertFalse(forgery.find_forged_destination_reply(entry).forged)

    def test_a_trace_that_never_reached_its_destination_is_not_forged(self):
        entry = _Entry("8.8.8.8", [hop(1, "192.168.1.1", *reply(1, 2, 64))])
        self.assertFalse(forgery.find_forged_destination_reply(entry).forged)

    def test_hops_with_no_reply_are_skipped(self):
        entry = _Entry("1.1.1.1", [{"hop": 4, "result": [{"x": "*"}]},
                                   hop(9, "1.1.1.1", *reply(7, 7, 1))])
        self.assertTrue(forgery.find_forged_destination_reply(entry).forged)

    def test_an_empty_or_malformed_entry_is_handled(self):
        for entry in (_Entry("1.1.1.1", []), _Entry("", None),
                      _Entry("1.1.1.1", [{"hop": 1, "result": []}])):
            self.assertFalse(forgery.find_forged_destination_reply(entry).forged)


class TestForgedReplyIsDrawnAsSuch(unittest.TestCase):
    """The graph must not put the interceptor's answer on the destination node.

    `parse_ttl` already reddens any reply under TTL 20, so the forged hop was
    drawn as a generic `Middlebox` before this. That says "some box"; the point
    of §2.12 is to say "a box answering in the destination's name", and to carry
    the evidence for the claim.
    """

    def render(self, forged):
        measurement = {
            "dst_addr": "1.1.1.1", "annotation": "www.twitter.com",
            "proto": "UDP", "port": 53, "src_addr": "127.1.2.7",
            "from_ip": "127.1.2.7", "af": 4, "size": 61, "timestamp": 0,
            "endtime": 1, "asn": "AS0", "asname": "", "cc": "", "city": "",
            "dst_name": "", "lts": -1, "msm_id": -1, "msm_name": "traceroute",
            "paris_id": 0, "prb_id": -1, "ttr": -1,
            "network_state": "allowlisted", "provider_status": "",
            "dpi_cleared": False, "cgnat_hop": True, "sni_inspected": False,
            "rst_flood": False, "tcp_silently_dropped": False,
            "reply_forged": forged,
            "forgery_evidence": "ip-id-reflected" if forged else "",
            "result": [{
                "hop": 9,
                "result": [{
                    "from": "1.1.1.1", "rtt": 9.0, "size": 77, "ttl": 1,
                    "summary": "IP / UDP / DNS Ans 10.10.34.35",
                    "rst_count": 0, "dport": 53,
                    "packets": {"sent": {"IP": {"id": "11796", "ttl": "9",
                                                "chksum": "0x0",
                                                "src": "127.1.2.7",
                                                "dst": "1.1.1.1"}},
                                "received": [{"IP": {"id": "11796", "ttl": "1",
                                                     "src": "1.1.1.1",
                                                     "dst": "127.1.2.7"},
                                              "UDP": {"sport": "domain"}}]},
                }],
            }],
        }
        directory = tempfile.mkdtemp()
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump([measurement], handle)
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable="backttl")
        with open(path.replace(".json", ".html"), errors="replace") as handle:
            return handle.read()

    def test_a_forged_reply_gets_its_own_node_and_label(self):
        page = self.render(forged=True)
        self.assertIn("Forged reply", page)
        self.assertIn("ip-id-reflected", page)

    def test_it_outranks_the_generic_middlebox_marking(self):
        """Both fire on this hop — TTL 1 is under `parse_ttl`'s threshold — and
        the specific finding has to win.

        Asserted on the node id rather than on the word "Middlebox", which
        appears in every tooltip as the `Middlebox: False` line.
        """
        page = self.render(forged=True)
        self.assertIn("forgedx", page)
        self.assertNotIn("middleboxx", page)

    def test_an_unflagged_reply_falls_back_to_the_middlebox_marking(self):
        page = self.render(forged=False)
        self.assertNotIn("Forged reply", page)
        self.assertIn("middlebox", page)


if __name__ == "__main__":
    unittest.main()
