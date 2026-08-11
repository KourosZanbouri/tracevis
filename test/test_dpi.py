#!/usr/bin/env python3
import unittest

from utils.dpi import (
    SNI_PORT,
    DpiSignal,
    classify_dpi_path,
    is_cgnat_address,
)
from utils.traceroute_struct import traceroute_data


class TestClassifyDpiPath(unittest.TestCase):
    def test_returns_namedtuple(self):
        signal = classify_dpi_path()
        self.assertIsInstance(signal, DpiSignal)
        self.assertEqual(
            signal._fields, ("dpi_cleared", "cgnat_hop", "sni_inspected", "rst_flood", "tcp_silently_dropped"))

    def test_open_network_no_evidence_is_cleared(self):
        signal = classify_dpi_path(network_state="open")
        self.assertTrue(signal.dpi_cleared)
        self.assertFalse(signal.cgnat_hop)
        self.assertFalse(signal.sni_inspected)
        self.assertFalse(signal.rst_flood)
        self.assertFalse(signal.tcp_silently_dropped)

    def test_rst_below_threshold_not_flood(self):
        signal = classify_dpi_path(network_state="open", rst_count=2)
        self.assertFalse(signal.rst_flood)

    def test_rst_at_threshold_is_flood(self):
        signal = classify_dpi_path(network_state="open", rst_count=3)
        self.assertTrue(signal.rst_flood)
        self.assertFalse(signal.dpi_cleared)

    def test_tcp_silent_drop_not_cleared(self):
        # Measured behaviour: TCP silently dropped, no RSTs,
        # destination unreachable → tcp_silently_dropped=True, dpi_cleared=False.
        signal = classify_dpi_path(
            network_state="open", sent_proto="TCP", sent_dport=443,
            rst_count=0, dst_reached=False)
        self.assertTrue(signal.tcp_silently_dropped)
        self.assertFalse(signal.dpi_cleared)

    def test_tcp_silent_drop_not_triggered_for_udp(self):
        # UDP probes that don't reach the destination are not silent-drop TCP.
        signal = classify_dpi_path(
            network_state="open", sent_proto="UDP", sent_dport=53,
            rst_count=0, dst_reached=False)
        self.assertFalse(signal.tcp_silently_dropped)

    def test_tcp_silent_drop_not_triggered_when_rst_flood(self):
        # If RST flood is already detected, don't also flag silent drop.
        signal = classify_dpi_path(
            network_state="open", sent_proto="TCP", sent_dport=443,
            rst_count=5, dst_reached=False)
        self.assertTrue(signal.rst_flood)
        self.assertFalse(signal.tcp_silently_dropped)

    def test_tcp_silent_drop_not_triggered_when_dst_reached(self):
        signal = classify_dpi_path(
            network_state="open", sent_proto="TCP", sent_dport=443,
            rst_count=0, dst_reached=True)
        self.assertFalse(signal.tcp_silently_dropped)

    def test_allowlisted_state_is_cgnat_layer(self):
        # allowlisted tier == CGNAT boundary.
        signal = classify_dpi_path(network_state="allowlisted")
        self.assertTrue(signal.cgnat_hop)
        self.assertFalse(signal.dpi_cleared)

    def test_nat_in_allowlisted_is_cgnat(self):
        signal = classify_dpi_path(
            is_nat=True, network_state="allowlisted")
        self.assertTrue(signal.cgnat_hop)

    def test_nat_in_open_is_not_cgnat(self):
        # consumer home NAT in an open network is not the CGNAT tier.
        signal = classify_dpi_path(is_nat=True, network_state="open")
        self.assertFalse(signal.cgnat_hop)
        self.assertTrue(signal.dpi_cleared)

    def test_sni_inspected_at_tcp_443_middlebox(self):
        signal = classify_dpi_path(
            is_middlebox=True, network_state="open",
            sent_proto="TCP", sent_dport=SNI_PORT)
        self.assertTrue(signal.sni_inspected)
        self.assertFalse(signal.dpi_cleared)

    def test_sni_inspected_at_pep_tcp_443(self):
        signal = classify_dpi_path(
            is_pep=True, network_state="open",
            sent_proto="TCP", sent_dport=SNI_PORT)
        self.assertTrue(signal.sni_inspected)

    def test_sni_not_inspected_when_not_tcp_443(self):
        # SNI extraction needs TCP/443.
        udp = classify_dpi_path(
            is_middlebox=True, network_state="open",
            sent_proto="UDP", sent_dport=SNI_PORT)
        self.assertFalse(udp.sni_inspected)
        wrong_port = classify_dpi_path(
            is_middlebox=True, network_state="open",
            sent_proto="TCP", sent_dport=80)
        self.assertFalse(wrong_port.sni_inspected)

    def test_shutdown_state_not_cleared(self):
        signal = classify_dpi_path(network_state="shutdown")
        self.assertFalse(signal.dpi_cleared)
        self.assertFalse(signal.cgnat_hop)

    def test_unknown_state_not_cleared(self):
        signal = classify_dpi_path(network_state="unknown")
        self.assertFalse(signal.dpi_cleared)


class TestCgnatFromObservedHops(unittest.TestCase):
    """`cgnat_hop` used to be `network_state == "allowlisted"` wearing a
    different name, which made it unfirable in the one place it mattered: the
    flag could not fire on a network whose every trace crossed an RFC 6598 hop,
    because the detector had reached its (allowlisted) provider and called the
    network `open`."""

    def test_rfc6598_addresses_are_cgnat(self):
        for address in ("100.64.0.0", "100.76.0.1", "100.127.255.255"):
            self.assertTrue(is_cgnat_address(address), address)

    def test_addresses_outside_the_prefix_are_not(self):
        # The /10 boundary, both sides, plus the RFC 1918 space that is
        # deliberately excluded — a flag that fires on every home LAN is noise.
        for address in ("100.63.255.255", "100.128.0.0", "192.168.1.1",
                        "172.16.4.43", "10.0.0.1", "1.1.1.1"):
            self.assertFalse(is_cgnat_address(address), address)

    def test_non_addresses_are_not_cgnat(self):
        for value in ("***", "", None, "not-an-ip", "*"):
            self.assertFalse(is_cgnat_address(value), repr(value))

    def test_an_observed_cgnat_hop_beats_the_network_state(self):
        signal = classify_dpi_path(network_state="open", cgnat_observed=True)
        self.assertTrue(signal.cgnat_hop)

    def test_cgnat_alone_does_not_make_a_path_uncleared(self):
        """Being NATted is a fact about the topology; being inspected is a fact
        about the DPI. Most carriers behind 100.64/10 censor nothing, so
        coupling the two would raise a false alarm on all of them."""
        signal = classify_dpi_path(
            network_state="open", sent_proto="TCP", sent_dport=443,
            dst_reached=True, cgnat_observed=True)
        self.assertTrue(signal.cgnat_hop)
        self.assertTrue(signal.dpi_cleared)

    def test_cgnat_does_not_mask_a_real_block(self):
        signal = classify_dpi_path(
            network_state="open", sent_proto="TCP", sent_dport=443,
            dst_reached=False, cgnat_observed=True)
        self.assertTrue(signal.cgnat_hop)
        self.assertTrue(signal.tcp_silently_dropped)
        self.assertFalse(signal.dpi_cleared)


class TestForgedReplyRulesOutClearance(unittest.TestCase):
    """A path cannot be "cleared" and impersonated at the same time.

    Both flags could say so in one measurement until `reply_forged` became a
    term here: a forged reply is the strongest evidence of interception the tool
    has, since something on the path answered in the destination's name.
    """

    def test_a_forged_reply_clears_dpi_cleared(self):
        signal = classify_dpi_path(network_state="open", sent_proto="UDP",
                                   dst_reached=True, reply_forged=True)
        self.assertFalse(signal.dpi_cleared)

    def test_an_otherwise_identical_path_is_cleared(self):
        signal = classify_dpi_path(network_state="open", sent_proto="UDP",
                                   dst_reached=True, reply_forged=False)
        self.assertTrue(signal.dpi_cleared)

    def test_forgery_does_not_disturb_the_other_flags(self):
        signal = classify_dpi_path(network_state="open", sent_proto="UDP",
                                   dst_reached=True, reply_forged=True,
                                   cgnat_observed=True)
        self.assertTrue(signal.cgnat_hop)
        self.assertFalse(signal.sni_inspected)
        self.assertFalse(signal.rst_flood)


class TestSetEndtimeScrubsTheSource(unittest.TestCase):
    """The struct's own last line of defence (backlog §2.8).

    `Tracer.save_measurement_data` scrubs the whole measurement before writing,
    so this is redundant for the normal path — deliberately. It is the guarantee
    for any other caller that builds a `traceroute_data` and saves it, and the
    condition it replaces (`src_addr == from_ip`) was true only for an unNATted
    host, which is nobody this tool is aimed at.
    """

    def _entry(self, src_addr):
        return traceroute_data(
            dst_addr="1.1.1.1", annotation="a", proto="IP", port=33435,
            timestamp=0, src_addr=src_addr, from_ip="203.0.113.7")

    def test_a_natted_source_is_scrubbed(self):
        entry = self._entry("192.168.1.5")
        entry.set_endtime(1)
        self.assertEqual(entry.src_addr, "127.1.2.7")

    def test_the_public_address_is_scrubbed_too(self):
        entry = self._entry("192.168.1.5")
        entry.set_endtime(1)
        self.assertEqual(entry.from_ip, "127.1.2.7")


class TestTracerouteStructM4Fields(unittest.TestCase):
    def test_defaults(self):
        td = traceroute_data(
            dst_addr="1.1.1.1", annotation="a", proto="IP", port=33435,
            timestamp=0)
        self.assertFalse(td.dpi_cleared)
        self.assertFalse(td.cgnat_hop)
        self.assertFalse(td.sni_inspected)
        self.assertFalse(td.rst_flood)
        self.assertFalse(td.tcp_silently_dropped)

    def test_custom_values_serialized(self):
        td = traceroute_data(
            dst_addr="1.1.1.1", annotation="a", proto="IP", port=33435,
            timestamp=0, dpi_cleared=True, cgnat_hop=False, sni_inspected=True,
            rst_flood=True, tcp_silently_dropped=True)
        blob = td.json()
        self.assertIn('"dpi_cleared": true', blob)
        self.assertIn('"cgnat_hop": false', blob)
        self.assertIn('"sni_inspected": true', blob)
        self.assertIn('"rst_flood": true', blob)
        self.assertIn('"tcp_silently_dropped": true', blob)


if __name__ == "__main__":
    unittest.main()
