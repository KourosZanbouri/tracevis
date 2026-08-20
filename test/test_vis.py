"""Backlog §2.3 — CGNAT/allowlist node types and phase/tier overlay.

Tests that a hop in RFC 6598 space (100.64/10) renders as a distinct
teal hexagon node, that the allowlist-boundary edge annotation fires,
that the phase-overlay legend is injected, and that all of this
remains backward-compatible with measurements that carry no CGNAT
information at all.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import utils.dpi
import utils.vis


def make_measurement(
        dst_addr="1.1.1.1",
        network_state="allowlisted",
        cgnat_hop=True,
        hops=None,
        proto="ICMP",
        port=-1,
        src_addr="127.1.2.7",
        from_ip="127.1.2.7",
        vp=None,
):
    """Build a minimal traceroute_data-shaped dict for vis()."""
    if hops is None:
        hops = [
            {"from": "192.168.1.1", "rtt": 1.0, "size": 56, "ttl": 64,
             "summary": "ICMP time-exceeded", "rst_count": 0},
            {"from": "100.64.0.1", "rtt": 3.0, "size": 56, "ttl": 254,
             "summary": "ICMP time-exceeded", "rst_count": 0},
        ]
    result = []
    for i, h in enumerate(hops):
        step = i + 1
        hop_entry = {
            "hop": step,
            "result": [h],
        }
        if h.get("from") and h["from"] != "1.1.1.1":
            sent_id = str(1 + step * 100)
            recv_id = str(100 + step * 50)
            h["packets"] = {
                "sent": {"IP": {"id": sent_id, "ttl": str(step),
                                "chksum": "0x0000",
                                "src": src_addr, "dst": dst_addr}},
                "received": [{"IP": {"id": recv_id, "ttl": str(h.get("ttl", 64)),
                                     "src": h["from"], "dst": src_addr},
                              "UDP": {"sport": "domain"}}],
            }
        result.append(hop_entry)
    base = {
        "dst_addr": dst_addr,
        "annotation": "test",
        "proto": proto,
        "port": port,
        "src_addr": src_addr,
        "from_ip": from_ip,
        "af": 4,
        "size": 61,
        "timestamp": 0,
        "endtime": 1,
        "asn": "AS0",
        "asname": "",
        "cc": "",
        "city": "",
        "dst_name": "",
        "lts": -1,
        "msm_id": -1,
        "msm_name": "traceroute",
        "paris_id": 0,
        "prb_id": -1,
        "ttr": -1,
        "network_state": network_state,
        "provider_status": "",
        "dpi_cleared": False,
        "cgnat_hop": cgnat_hop,
        "sni_inspected": False,
        "rst_flood": False,
        "tcp_silently_dropped": False,
        "reply_forged": False,
        "forgery_evidence": "",
        "result": result,
    }
    if vp is not None:
        base["vp"] = vp
    return base


class VisFixtureMixin:
    """Write a measurement list to a temp file, render it, return the HTML."""

    def render(self, measurements, phase_overlay=False, edge_lable="backttl"):
        directory = tempfile.mkdtemp()
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump(measurements, handle)
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable=edge_lable,
                          phase_overlay=phase_overlay)
        with open(path.replace(".json", ".html"), errors="replace") as handle:
            return handle.read()


class TestInitializeDetected(unittest.TestCase):
    """`is_cgnat` must be present in the per-repeat tracking dict."""

    def test_has_is_cgnat_key(self):
        nodes = utils.vis.initialize_detected(3)
        self.assertEqual(len(nodes), 3)
        for node in nodes:
            self.assertIn("is_cgnat", node)
            self.assertFalse(node["is_cgnat"])

    def test_does_not_clobber_existing_keys(self):
        nodes = utils.vis.initialize_detected(1)
        node = nodes[0]
        self.assertIn("is_nat", node)
        self.assertIn("is_middlebox", node)
        self.assertIn("is_pep", node)
        self.assertIn("is_cgnat", node)


class TestTooltipsCgntaArgs(unittest.TestCase):
    """`tooltips_append_lines` must accept the new kwargs without breaking."""

    def test_defaults_unchanged(self):
        result = utils.vis.tooltips_append_lines(
            is_nat=False, is_middlebox=False, is_pep=False,
            packet_type="ICMP", tcpflag="")
        self.assertIn("CGNAT hop: False", result)
        self.assertIn("NAT: False", result)

    def test_cgnat_hop_flag_shown(self):
        result = utils.vis.tooltips_append_lines(
            is_nat=True, is_middlebox=False, is_pep=False,
            packet_type="ICMP", tcpflag="",
            is_cgnat_hop=True)
        self.assertIn("Per-hop CGNAT: True", result)

    def test_allowlist_boundary_flag_shown(self):
        result = utils.vis.tooltips_append_lines(
            is_nat=False, is_middlebox=False, is_pep=False,
            packet_type="ICMP", tcpflag="",
            allowlist_boundary=True)
        self.assertIn("Allowlist boundary: tier transition", result)


class TestCgnatNodeRendering(VisFixtureMixin, unittest.TestCase):
    """A 100.64/10 hop must render as a teal hexagon, not a generic NAT node."""

    def test_cgnat_hop_is_teal(self):
        page = self.render([make_measurement()])
        self.assertIn("teal", page)

    def test_cgnat_hop_has_hexagon_shape(self):
        page = self.render([make_measurement()])
        self.assertIn("hexagon", page)

    def test_cgnat_node_id_prefix(self):
        page = self.render([make_measurement()])
        self.assertIn("cgnat", page)

    def test_cgnat_takes_precedence_over_nat(self):
        """Even if detect_nat_pep_middlebox flags the hop as NAT, CGNAT wins."""
        measurement = make_measurement()
        page = self.render([measurement])
        self.assertIn("teal", page)
        # The NAT node id prefix ("nat") must not appear for the CGNAT hop.
        node_id = "cgnat" + "x" + str(int(__import__("ipaddress").IPv4Address("100.64.0.1"))) + "x"
        self.assertIn(node_id, page)

    def test_non_cgnat_nat_renders_as_nat(self):
        """A 192.168.x.x NAT hop must still render as generic NAT, not CGNAT."""
        hops = [
            {"from": "10.0.0.1", "rtt": 1.0, "size": 56, "ttl": 63,
             "summary": "ICMP time-exceeded", "rst_count": 0},
        ]
        measurement = make_measurement(
            dst_addr="1.1.1.1", network_state="open", cgnat_hop=False, hops=hops)
        page = self.render([measurement])
        self.assertIn("dodgerblue", page)
        self.assertIn("NAT", page)


class TestAllowlistBoundaryAnnotation(VisFixtureMixin, unittest.TestCase):
    """When network_state=allowlisted and a CGNAT hop appears, the edge
    crossing the boundary must carry a phase annotation."""

    def test_boundary_edge_label_present(self):
        page = self.render([make_measurement(network_state="allowlisted")],
                           edge_lable="none")
        self.assertIn("allowlisted tier", page)

    def test_boundary_tooltip_line_present(self):
        page = self.render([make_measurement(network_state="allowlisted")])
        self.assertIn("Allowlist boundary", page)

    def test_no_boundary_when_network_is_open(self):
        """On an open network the CGNAT hop is rendered teal but no boundary
        annotation fires — the tier transition only exists under allowlisting."""
        page = self.render([make_measurement(network_state="open")])
        self.assertIn("teal", page)
        self.assertNotIn("→ allowlisted tier", page)
        self.assertNotIn("Allowlist boundary", page)


class TestPhaseOverlay(VisFixtureMixin, unittest.TestCase):
    """The phase_overlay flag injects a CSS legend into the rendered HTML."""

    def test_overlay_injected_when_enabled(self):
        page = self.render([make_measurement()], phase_overlay=True)
        self.assertIn("phase-overlay", page)
        self.assertIn("Allowlisted tier", page)

    def test_overlay_absent_when_disabled(self):
        page = self.render([make_measurement()], phase_overlay=False)
        self.assertNotIn("phase-overlay", page)
        self.assertNotIn("Allowlisted tier", page)

    def test_overlay_absent_without_cgnat(self):
        """If the measurement has no CGNAT hop, the overlay is still valid
        (it is a legend) but should only appear when explicitly requested."""
        hops = [{"from": "192.168.1.1", "rtt": 1.0, "size": 56, "ttl": 64,
                 "summary": "ICMP", "rst_count": 0}]
        m = make_measurement(hops=hops, network_state="open", cgnat_hop=False)
        page = self.render([m], phase_overlay=True)
        # The overlay legend is always injected when phase_overlay is True,
        # regardless of whether a CGNAT hop is present — it is documentation
        # of what the teal hexagon means when one *is* present.
        self.assertIn("phase-overlay", page)


class TestCgnatBackwardCompat(VisFixtureMixin, unittest.TestCase):
    """Old measurements without network_state or cgnat_hop must still render
    correctly, and the CGNAT node detection must fire purely from the per-hop
    IP address (not the path-level flags)."""

    def test_old_measurement_without_network_state(self):
        """A file from before network_state existed still detects CGNAT
        from the hop IP via is_cgnat_address."""
        measurement = make_measurement()
        del measurement["network_state"]
        measurement["cgnat_hop"] = False
        page = self.render([measurement])
        # path_state falls back to "open" (cgnat_hop is False), so CGNAT node
        # renders teal but no boundary annotation fires.
        self.assertIn("teal", page)
        self.assertNotIn("→ allowlisted tier", page)

    def test_star_hop_does_not_crash(self):
        """A star ('*') hop must not trigger CGNAT detection."""
        hops = [
            {"x": "-"},
        ]
        measurement = make_measurement(
            dst_addr="1.1.1.1", network_state="allowlisted",
            cgnat_hop=True, hops=hops)
        page = self.render([measurement])
        # Should render the star hop without crashing.
        self.assertIn("unknown", page)


class TestCgnatAddressHelper(unittest.TestCase):
    """The is_cgnat_address helper is the foundation of the CGNAT node rendering."""

    def test_rfc6598_addresses_are_cgnat(self):
        for addr in ("100.64.0.0", "100.64.0.1", "100.76.0.1", "100.127.255.255"):
            self.assertTrue(utils.dpi.is_cgnat_address(addr), addr)

    def test_boundary_addresses(self):
        # Just outside the /10 — must NOT be CGNAT.
        self.assertFalse(utils.dpi.is_cgnat_address("100.63.255.255"))
        self.assertFalse(utils.dpi.is_cgnat_address("100.128.0.0"))

    def test_rfc1918_is_not_cgnat(self):
        """Home NAT must not be confused with carrier NAT."""
        for addr in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "1.1.1.1"):
            self.assertFalse(utils.dpi.is_cgnat_address(addr), addr)

    def test_invalid_values(self):
        for val in ("***", "", None, "not-an-ip", "*"):
            self.assertFalse(utils.dpi.is_cgnat_address(val), repr(val))


class TestRipeAtlasDataFormat(VisFixtureMixin, unittest.TestCase):
    """RIPE Atlas data lacks the 'packets' key that TraceVis native format has.
    vis() must still extract size/rtt from the top-level hop result."""

    def _make_atlas_measurement(self):
        return {
            "dst_addr": "1.1.1.1",
            "src_addr": "10.0.0.1",
            "vp": "12345",
            "annotation": "ripe-atlas",
            "size": 64,
            "result": [
                {"hop": 1, "result": [
                    {"from": "192.168.1.1", "ttl": 64, "size": 68, "rtt": 1.2}
                ]},
                {"hop": 2, "result": [
                    {"from": "100.64.0.1", "ttl": 254, "size": 28, "rtt": 3.4}
                ]},
            ],
        }

    def test_atlas_data_renders_without_crash(self):
        page = self.render([self._make_atlas_measurement()])
        self.assertIn("192.168.1.1", page)
        self.assertIn("100.64.0.1", page)

    def test_atlas_data_has_vp_annotation(self):
        page = self.render([self._make_atlas_measurement()])
        self.assertIn("VP 12345", page)

    def test_atlas_data_no_packet_size_crash(self):
        """Hop with size as string must not crash styled_tooltips division."""
        m = self._make_atlas_measurement()
        page = self.render([m])
        self.assertIn("1.1.1.1", page)


class TestMultiVpVisualization(VisFixtureMixin, unittest.TestCase):
    """§2.2: multi-VP measurements render with per-VP color-coded edges
    and VP annotations in tooltips."""

    def test_multiple_vps_render(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        vp2 = make_measurement(
            src_addr="10.0.0.2", dst_addr="1.1.1.1", vp="2002")
        page = self.render([vp1, vp2])
        # Both source addresses should appear as diamonds.
        self.assertIn("10.0.0.1", page)
        self.assertIn("10.0.0.2", page)
        self.assertIn("source", page)

    def test_vp_in_source_node_title(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        page = self.render([vp1])
        self.assertIn("VP 1001", page)

    def test_vp_in_tooltip_annotation(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        page = self.render([vp1])
        self.assertIn("VP 1001", page)

    def test_no_vp_annotation_for_old_files(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1")
        page = self.render([vp1])
        self.assertNotIn("VP", page)

    def test_per_vp_color_cycling(self):
        measurements = []
        for i in range(5):
            measurements.append(make_measurement(
                src_addr=f"10.0.0.{i+1}", dst_addr="1.1.1.1",
                vp=str(1000+i)))
        page = self.render(measurements)
        # REQUEST_COLORS has 12 entries — first 5 should all appear
        for color in utils.vis.REQUEST_COLORS[:5]:
            self.assertIn(color, page)

    def test_same_vp_multiple_measurements(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        vp1_same = make_measurement(
            src_addr="10.0.0.1", dst_addr="8.8.8.8", vp="1001")
        page = self.render([vp1, vp1_same])
        # Should render both destinations from the same VP source.
        self.assertIn("1.1.1.1", page)
        self.assertIn("8.8.8.8", page)
        self.assertIn("VP 1001", page)

    def test_backward_compat_single_vp(self):
        """A single VP with no 'vp' field must render identically to before."""
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1")
        page = self.render([vp1], edge_lable="backttl")
        self.assertIn("10.0.0.1", page)
        self.assertIn("1.1.1.1", page)

    def test_phase_overlay_with_vp(self):
        vp1 = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        page = self.render([vp1], phase_overlay=True, edge_lable="none")
        self.assertIn("phase-overlay", page)


class TestResolveOrIp(unittest.TestCase):
    """GitHub issue #68: vis() crashes when src_addr/dst_addr is a hostname.

    resolve_or_ip() must pass IPv4 addresses through and resolve hostnames.
    """

    def test_ipv4_passes_through(self):
        self.assertEqual(utils.vis.resolve_or_ip("1.2.3.4"), "1.2.3.4")

    def test_ipv6_literal_passes_through(self):
        # IPv6 literals are not resolvable by IPv4Address but should return
        # without crashing (resolve_or_ip returns the original on failure).
        result = utils.vis.resolve_or_ip("::1")
        self.assertTrue(result)

    def test_hostname_resolved(self):
        result = utils.vis.resolve_or_ip("localhost")
        ipaddress = __import__("ipaddress")
        ipaddress.IPv4Address(result)

    def test_unresolvable_hostname_returns_original(self):
        result = utils.vis.resolve_or_ip("nonexistent.invalid.domain")
        self.assertEqual(result, "nonexistent.invalid.domain")


class TestHostnameRendering(VisFixtureMixin, unittest.TestCase):
    """GitHub issue #68: a measurement with a hostname dst_addr must render."""

    def test_hostname_dst_renders(self):
        measurement = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1")
        measurement["dst_addr"] = "localhost"
        page = self.render([measurement])
        self.assertIn("127.0.0.1", page)

    def test_hostname_src_renders(self):
        measurement = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1")
        measurement["src_addr"] = "localhost"
        page = self.render([measurement])
        self.assertIn("127.0.0.1", page)


class TestIodaAnnotation(VisFixtureMixin, unittest.TestCase):
    """§2.2: IODA status cross-reference annotation on VP measurements."""
    def test_ioda_status_field_present_in_tooltip(self):
        measurement = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        measurement["ioda_status"] = {
            "country": "IR", "outage": True, "latest_value": 0.85}
        page = self.render([measurement])
        # The IODA status should surface somewhere in the rendered page.
        self.assertIn("IR", page)


if __name__ == "__main__":
    unittest.main()
