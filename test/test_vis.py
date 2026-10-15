"""Backlog §2.3 — CGNAT/allowlist node types and phase/tier overlay.

Tests that a hop in RFC 6598 space (100.64/10) renders as a distinct
teal hexagon node, that the allowlist-boundary edge annotation fires,
that the phase-overlay legend is injected, and that all of this
remains backward-compatible with measurements that carry no CGNAT
information at all.
"""
import glob
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import unittest.mock
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

    def render(self, measurements, phase_overlay=False, edge_lable="backttl",
               highlight_selected=False, reverse_path=False):
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
                          phase_overlay=phase_overlay,
                          highlight_selected=highlight_selected,
                          reverse_path=reverse_path)
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


class TestEdgeHighlight(VisFixtureMixin, unittest.TestCase):
    """GitHub issue #2: highlight path of selected edge."""

    def test_highlight_js_injected_when_enabled(self):
        page = self.render([make_measurement()], highlight_selected=True)
        self.assertIn("highlightPathToEdge", page)
        self.assertIn("network.on", page)

    def test_no_highlight_js_when_disabled(self):
        page = self.render([make_measurement()], highlight_selected=False)
        self.assertNotIn("highlightPathToEdge", page)

    def test_clear_highlight_on_background_click(self):
        page = self.render([make_measurement()], highlight_selected=True)
        self.assertIn("clearHighlight", page)


class TestIodaAnnotation(VisFixtureMixin, unittest.TestCase):
    """§2.2/§3.2: the IODA status written by utils.ioda reaches the graph.

    This used to assert only that "IR" appeared somewhere in the page, which
    any rendering would satisfy.
    """
    def render_with(self, ioda_status):
        measurement = make_measurement(
            src_addr="10.0.0.1", dst_addr="1.1.1.1", vp="1001")
        if ioda_status is not None:
            measurement["ioda_status"] = ioda_status
        return self.render([measurement])

    def test_an_outage_names_its_datasources(self):
        page = self.render_with({"country": "IR", "outage": True,
                                 "datasources": ["bgp", "ping-slash24"]})
        self.assertIn("IODA[IR]: outage (bgp, ping-slash24)", page)

    def test_a_clean_result_is_shown(self):
        self.assertIn("IODA[IR]: no outage",
                      self.render_with({"country": "IR", "outage": False}))

    def test_no_status_adds_no_ioda_line(self):
        self.assertNotIn("IODA[", self.render_with(None))


class TestMiddleboxFingerprint(unittest.TestCase):
    """GitHub issue #47: TCP option mutation and IP-ID entropy analysis."""

    def test_mss_clamped_detected(self):
        """Received MSS smaller than sent MSS → mss_clamped=True."""
        sent = {"TCP": {"options": "[('MSS', 1460)]"}}
        received = [{"TCP": {"options": "[('MSS', 1380)]"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertTrue(fp.mss_clamped)
        self.assertFalse(fp.ts_stripped)
        self.assertEqual(fp.ipid_pattern, "unknown")

    def test_mss_not_clamped_when_receives_larger(self):
        sent = {"TCP": {"options": "[('MSS', 1380)]"}}
        received = [{"TCP": {"options": "[('MSS', 1460)]"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertFalse(fp.mss_clamped)

    def test_timestamp_stripped_detected(self):
        """Sent has TS option, received TCP reply does not."""
        sent = {"TCP": {"options": "[('MSS', 1460), ('TS', '0:1')]"}}
        received = [{"TCP": {"options": "[('MSS', 1460)]"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertTrue(fp.ts_stripped)

    def test_timestamp_present_not_stripped(self):
        sent = {"TCP": {"options": "[('MSS', 1460), ('TS', '0:1')]"}}
        received = [{"TCP": {"options": "[('MSS', 1460), ('TS', '1:2')]"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertFalse(fp.ts_stripped)

    def test_ipid_constant_pattern(self):
        sent = {"IP": {"id": "100"}}
        received = [
            {"IP": {"id": "54321"}},
            {"IP": {"id": "54321"}},
            {"IP": {"id": "54321"}},
        ]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertEqual(fp.ipid_pattern, "constant")

    def test_ipid_sequential_pattern(self):
        sent = {"IP": {"id": "100"}}
        received = [
            {"IP": {"id": "54321"}},
            {"IP": {"id": "54322"}},
            {"IP": {"id": "54323"}},
        ]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertEqual(fp.ipid_pattern, "sequential")

    def test_ipid_random_pattern(self):
        sent = {"IP": {"id": "100"}}
        received = [
            {"IP": {"id": "54321"}},
            {"IP": {"id": "12345"}},
            {"IP": {"id": "54321"}},
        ]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertEqual(fp.ipid_pattern, "random")

    def test_ipid_unknown_single_packet(self):
        sent = {"IP": {"id": "100"}}
        received = [{"IP": {"id": "54321"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertEqual(fp.ipid_pattern, "unknown")

    def test_no_tcp_options_no_fingerprint(self):
        """UDP/ICMP packets without TCP options → no mss/ts signals."""
        sent = {"UDP": {"sport": "domain"}}
        received = [{"UDP": {"sport": "domain"}}]
        fp = utils.vis.fingerprint_middlebox(sent, received)
        self.assertFalse(fp.mss_clamped)
        self.assertFalse(fp.ts_stripped)
        self.assertEqual(fp.ipid_pattern, "unknown")

    def test_no_packets_no_fingerprint(self):
        fp = utils.vis.fingerprint_middlebox({}, [])
        self.assertFalse(fp.mss_clamped)
        self.assertFalse(fp.ts_stripped)
        self.assertEqual(fp.ipid_pattern, "unknown")


class TestFingerprintInTooltip(VisFixtureMixin, unittest.TestCase):
    """Fingerprint data must surface in the rendered tooltip."""

    def test_mss_clamp_in_tooltip(self):
        measurement = make_measurement()
        # Replace a hop with TCP packets carrying different MSS values.
        measurement["result"][1]["result"][0]["packets"] = {
            "sent": {"IP": {"id": "100", "ttl": "1", "chksum": "0x0000",
                            "src": "127.1.2.7", "dst": "1.1.1.1"},
                     "TCP": {"options": "[('MSS', 1460)]", "dport": "443",
                             "flags": "PA"}},
            "received": [{"IP": {"id": "54321", "ttl": "64",
                                 "src": "100.64.0.1", "dst": "127.1.2.7"},
                          "TCP": {"options": "[('MSS', 1380)]", "flags": "A"}}],
        }
        page = self.render([measurement], edge_lable="none")
        self.assertIn("MSS clamped", page)

    def test_ipid_pattern_in_tooltip(self):
        measurement = make_measurement()
        measurement["result"][1]["result"][0]["packets"] = {
            "sent": {"IP": {"id": "100", "ttl": "1", "chksum": "0x0000",
                            "src": "127.1.2.7", "dst": "1.1.1.1"},
                     "UDP": {"sport": "domain"}},
            "received": [{"IP": {"id": "54321", "ttl": "64",
                                 "src": "100.64.0.1", "dst": "127.1.2.7"},
                          "UDP": {"sport": "domain"}},
                         {"IP": {"id": "54321", "ttl": "64",
                                 "src": "100.64.0.1", "dst": "127.1.2.7"},
                          "UDP": {"sport": "domain"}}],
        }
        page = self.render([measurement], edge_lable="none")
        self.assertIn("IP-ID pattern: constant", page)


class TestVpConvergence(unittest.TestCase):
    """GitHub issue #44: _find_vp_convergence detects the shared last-mile
    segment across multiple VP traces."""

    def _make_vp_measurement(self, src_addr, hops, vp=None):
        result = []
        for i, h in enumerate(hops):
            step = i + 1
            hop_entry = {"hop": step, "result": [h]}
            result.append(hop_entry)
        base = {
            "dst_addr": "1.1.1.1",
            "src_addr": src_addr,
            "result": result,
        }
        if vp:
            base["vp"] = vp
        return base

    def test_converges_at_destination(self):
        """When VPs share only the destination, convergence set is {dst}."""
        vp1 = self._make_vp_measurement("10.0.0.1", [
            {"from": "100.64.0.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ])
        vp2 = self._make_vp_measurement("10.0.0.2", [
            {"from": "192.168.1.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ])
        result = utils.vis._find_vp_convergence([vp1, vp2])
        self.assertIn("1.1.1.1", result)

    def test_converges_before_destination(self):
        """When VPs share a multi-hop suffix, all shared IPs are returned."""
        vp1 = self._make_vp_measurement("10.0.0.1", [
            {"from": "100.64.0.1", "ttl": 64},
            {"from": "203.0.113.5", "ttl": 64},
            {"from": "203.0.113.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ])
        vp2 = self._make_vp_measurement("10.0.0.2", [
            {"from": "192.168.1.1", "ttl": 64},
            {"from": "203.0.113.5", "ttl": 64},
            {"from": "203.0.113.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ])
        result = utils.vis._find_vp_convergence([vp1, vp2])
        self.assertEqual(result, {"203.0.113.5", "203.0.113.1", "1.1.1.1"})

    def test_single_vp_returns_empty(self):
        """A single VP has no peer to converge with."""
        vp1 = self._make_vp_measurement("10.0.0.1", [
            {"from": "100.64.0.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ])
        result = utils.vis._find_vp_convergence([vp1])
        self.assertEqual(result, set())


class TestReversePathRendering(VisFixtureMixin, unittest.TestCase):
    """GitHub issue #44: --reverse-path marks converged edges as dashed amber."""

    def _make_vp_measurement(self, src_addr, hops, vp=None):
        result = []
        for i, h in enumerate(hops):
            step = i + 1
            hop_entry = {"hop": step, "result": [h]}
            if h.get("from") and h["from"] != "1.1.1.1":
                sent_id = str(1 + step * 100)
                recv_id = str(100 + step * 50)
                h["packets"] = {
                    "sent": {"IP": {"id": sent_id, "ttl": str(step),
                                    "chksum": "0x0000",
                                    "src": src_addr, "dst": "1.1.1.1"}},
                    "received": [{"IP": {"id": recv_id, "ttl": str(h.get("ttl", 64)),
                                         "src": h["from"], "dst": src_addr},
                                  "UDP": {"sport": "domain"}}],
                }
            result.append(hop_entry)
        base = {
            "dst_addr": "1.1.1.1",
            "src_addr": src_addr,
            "result": result,
        }
        if vp:
            base["vp"] = vp
        return base

    def test_reverse_path_legend_injected(self):
        vp1 = self._make_vp_measurement("10.0.0.1", [
            {"from": "100.64.0.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ], vp="1001")
        vp2 = self._make_vp_measurement("10.0.0.2", [
            {"from": "192.168.1.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ], vp="2002")
        page = self.render([vp1, vp2], reverse_path=True, edge_lable="none")
        self.assertIn("reverse-path-legend", page)

    def test_reverse_path_no_legend_without_flag(self):
        vp1 = self._make_vp_measurement("10.0.0.1", [
            {"from": "100.64.0.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ], vp="1001")
        vp2 = self._make_vp_measurement("10.0.0.2", [
            {"from": "192.168.1.1", "ttl": 64},
            {"from": "1.1.1.1", "ttl": 64},
        ], vp="2002")
        page = self.render([vp1, vp2], edge_lable="none")
        self.assertNotIn("reverse-path-legend", page)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Regression tests for the review of the issue #2 / #44 / #47 / #64 / #75 work.
# Each class documents the defect it pins down.
# ---------------------------------------------------------------------------


class TestIpIdSequentialBound(unittest.TestCase):
    """`delta == 1` was too strict and inverted the verdict on most hops.

    A router runs one global IP-ID counter shared by every flow it originates,
    so between two of our probes it advances by more than one. Against this
    repository's own captures the old rule classified 0 of 164 hops as
    sequential and called all 164 "random" — which the tooltip presents as a
    randomising middlebox.
    """

    def _pkts(self, ids):
        return [{"IP": {"id": str(i)}} for i in ids]

    def test_global_counter_signature_is_sequential(self):
        """Real observed sequence from tracevis_data (delta 8)."""
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([41021, 41029, 41037])),
            "sequential")

    def test_small_increments_are_sequential(self):
        for ids in ([42765, 42769, 42773], [10502, 10506, 10510],
                    [61993, 62000, 62007], [100, 101, 102]):
            with self.subTest(ids=ids):
                self.assertEqual(
                    utils.vis._classify_ipid_pattern(self._pkts(ids)),
                    "sequential")

    def test_large_jumps_are_still_random(self):
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([54321, 12345, 33333])),
            "random")

    def test_decreasing_is_random(self):
        """A backwards step is not a monotonic counter."""
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([500, 400, 300])),
            "random")

    def test_wraparound_is_sequential(self):
        """A 16-bit counter rolling over is an increment, not a -65532 jump."""
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([65530, 65534, 2, 6])),
            "sequential")

    def test_boundary_delta_is_sequential(self):
        base = 1000
        ids = [base, base + utils.vis.IPID_SEQUENTIAL_MAX_DELTA]
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts(ids)), "sequential")

    def test_just_over_boundary_is_random(self):
        base = 1000
        ids = [base, base + utils.vis.IPID_SEQUENTIAL_MAX_DELTA + 1]
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts(ids)), "random")


class TestIpIdZeroHandling(unittest.TestCase):
    """The constant test filtered zeros while the delta test did not."""

    def _pkts(self, ids):
        return [{"IP": {"id": str(i)}} for i in ids]

    def test_zero_mixed_with_repeats_is_not_constant(self):
        """[0, 5, 5] is not a constant IP-ID; the old code said it was."""
        self.assertNotEqual(
            utils.vis._classify_ipid_pattern(self._pkts([0, 5, 5])),
            "constant")

    def test_all_zero_is_constant(self):
        """A host that always sends ID 0 (DF set) is genuinely constant."""
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([0, 0, 0])),
            "constant")

    def test_identical_nonzero_is_constant(self):
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([777, 777, 777])),
            "constant")

    def test_single_packet_is_unknown(self):
        self.assertEqual(
            utils.vis._classify_ipid_pattern(self._pkts([1])), "unknown")

    def test_unparseable_ids_are_skipped(self):
        self.assertEqual(
            utils.vis._classify_ipid_pattern(
                [{"IP": {"id": "not-a-number"}}, {"IP": {"id": "5"}}]),
            "unknown")


class TestIpIdAggregationLevel(unittest.TestCase):
    """IP-ID entropy is a property of the responder, not of one probe.

    tracevis records each repeat probe as its own result carrying at most one
    received packet, so classifying inside a single result left ~99% of hops
    at "unknown".
    """

    def _hop_results(self):
        return [
            {"from": "10.0.0.5",
             "packets": {"sent": {}, "received": [{"IP": {"id": "100"}}]}},
            {"from": "10.0.0.5",
             "packets": {"sent": {}, "received": [{"IP": {"id": "104"}}]}},
            {"from": "10.0.0.5",
             "packets": {"sent": {}, "received": [{"IP": {"id": "108"}}]}},
            {"from": "10.0.0.9",
             "packets": {"sent": {}, "received": [{"IP": {"id": "7"}}]}},
            {"from": "***"},
        ]

    def test_collect_groups_by_responder(self):
        grouped = utils.vis.collect_hop_ipid_packets(self._hop_results())
        self.assertEqual(sorted(grouped), ["10.0.0.5", "10.0.0.9"])
        self.assertEqual(len(grouped["10.0.0.5"]), 3)
        self.assertEqual(len(grouped["10.0.0.9"]), 1)

    def test_star_hops_excluded(self):
        self.assertNotIn("***",
                         utils.vis.collect_hop_ipid_packets(self._hop_results()))

    def test_single_result_alone_cannot_classify(self):
        """One probe's received list has one packet — not enough."""
        single = self._hop_results()[0]["packets"]["received"]
        self.assertEqual(utils.vis._classify_ipid_pattern(single), "unknown")

    def test_aggregated_across_repeats_classifies(self):
        grouped = utils.vis.collect_hop_ipid_packets(self._hop_results())
        fp = utils.vis.fingerprint_middlebox(
            {}, self._hop_results()[0]["packets"]["received"],
            ipid_packets=grouped["10.0.0.5"])
        self.assertEqual(fp.ipid_pattern, "sequential")

    def test_ipid_packets_defaults_to_received(self):
        """Omitting the argument keeps the original single-probe behaviour."""
        fp = utils.vis.fingerprint_middlebox(
            {}, [{"IP": {"id": "1"}}, {"IP": {"id": "2"}}])
        self.assertEqual(fp.ipid_pattern, "sequential")


class TestTimestampOptionSpelling(unittest.TestCase):
    """`name.upper() == "Timestamp"` could never be true."""

    def test_ts_spelling(self):
        self.assertTrue(utils.vis._has_timestamp_option([("TS", "0:1")]))

    def test_timestamp_spelling(self):
        self.assertTrue(
            utils.vis._has_timestamp_option([("Timestamp", "0:1")]))

    def test_lowercase_spelling(self):
        self.assertTrue(utils.vis._has_timestamp_option([("ts", "0:1")]))

    def test_absent(self):
        self.assertFalse(utils.vis._has_timestamp_option([("MSS", 1460)]))


class TestMssClampValue(unittest.TestCase):
    """MSS_CLAMP_VALUES was defined with a documented purpose and never used."""

    def test_clamp_value_recorded(self):
        fp = utils.vis.fingerprint_middlebox(
            {"TCP": {"options": "[('MSS', 1460)]"}},
            [{"TCP": {"options": "[('MSS', 1380)]"}}])
        self.assertTrue(fp.mss_clamped)
        self.assertEqual(fp.mss_clamp_value, 1380)
        self.assertIn(fp.mss_clamp_value, utils.vis.MSS_CLAMP_VALUES)

    def test_unrecognised_clamp_value_still_reported(self):
        fp = utils.vis.fingerprint_middlebox(
            {"TCP": {"options": "[('MSS', 1460)]"}},
            [{"TCP": {"options": "[('MSS', 1111)]"}}])
        self.assertTrue(fp.mss_clamped)
        self.assertEqual(fp.mss_clamp_value, 1111)
        self.assertNotIn(fp.mss_clamp_value, utils.vis.MSS_CLAMP_VALUES)

    def test_no_clamp_leaves_value_none(self):
        fp = utils.vis.fingerprint_middlebox(
            {"TCP": {"options": "[('MSS', 1380)]"}},
            [{"TCP": {"options": "[('MSS', 1460)]"}}])
        self.assertFalse(fp.mss_clamped)
        self.assertIsNone(fp.mss_clamp_value)

    def test_well_known_clamp_named_in_tooltip(self):
        fp = utils.vis.fingerprint_middlebox(
            {"TCP": {"options": "[('MSS', 1460)]"}},
            [{"TCP": {"options": "[('MSS', 1380)]"}}])
        tooltip = utils.vis.tooltips_append_lines(
            False, False, False, "TCP", "SA", fingerprint=fp)
        self.assertIn("MSS clamped", tooltip)
        self.assertIn("1380", tooltip)
        self.assertIn("well-known clamp", tooltip)

    def test_arbitrary_clamp_not_called_well_known(self):
        fp = utils.vis.fingerprint_middlebox(
            {"TCP": {"options": "[('MSS', 1460)]"}},
            [{"TCP": {"options": "[('MSS', 1111)]"}}])
        tooltip = utils.vis.tooltips_append_lines(
            False, False, False, "TCP", "SA", fingerprint=fp)
        self.assertIn("1111", tooltip)
        self.assertNotIn("well-known clamp", tooltip)

    def test_empty_fingerprint_is_the_shared_sentinel(self):
        self.assertIs(utils.vis.fingerprint_middlebox({}, []),
                      utils.vis.NO_FINGERPRINT)


class TestVpConvergenceGroupsByDestination(unittest.TestCase):
    """The function pooled every measurement regardless of destination.

    A multi-VP capture holds one measurement per (VP x destination), and
    tracevis's core workflow compares an accessible and a blocked destination
    in one run. The differing final hops broke the suffix walk immediately, so
    every real multi-destination capture produced an empty set and --reverse-
    path rendered a legend over nothing.
    """

    def _vp(self, src, hops, dst, vp=None, repeats=1):
        result = [{"hop": i + 1,
                   "result": [{"from": ip} for _ in range(repeats)]}
                  for i, ip in enumerate(hops)]
        base = {"src_addr": src, "dst_addr": dst, "result": result}
        if vp:
            base["vp"] = vp
        return base

    def test_two_destinations_no_longer_collapse_to_empty(self):
        measurements = [
            self._vp("10.0.0.1", ["1.1.1.1", "9.9.9.9"], "8.8.4.4", vp="1"),
            self._vp("10.0.0.2", ["2.2.2.2", "9.9.9.9"], "8.8.4.4", vp="2"),
            self._vp("10.0.0.1", ["1.1.1.1", "7.7.7.7"], "8.8.8.8", vp="1"),
            self._vp("10.0.0.2", ["2.2.2.2", "7.7.7.7"], "8.8.8.8", vp="2"),
        ]
        result = utils.vis._find_vp_convergence(measurements)
        self.assertEqual(
            result, {"9.9.9.9", "8.8.4.4", "7.7.7.7", "8.8.8.8"})

    def test_single_destination_still_works(self):
        measurements = [
            self._vp("10.0.0.1", ["1.1.1.1", "9.9.9.9"], "8.8.4.4", vp="1"),
            self._vp("10.0.0.2", ["2.2.2.2", "9.9.9.9"], "8.8.4.4", vp="2"),
        ]
        self.assertEqual(utils.vis._find_vp_convergence(measurements),
                         {"9.9.9.9", "8.8.4.4"})

    def test_same_vp_traced_twice_is_not_convergence(self):
        """Two runs from one VP share their whole path by construction."""
        one = self._vp("10.0.0.1", ["1.1.1.1", "9.9.9.9"], "8.8.4.4", vp="1")
        self.assertEqual(
            utils.vis._find_vp_convergence([one, dict(one)]), set())

    def test_distinct_sources_count_as_distinct_vps(self):
        """A local multi-source capture has no `vp` key; fall back to src."""
        measurements = [
            self._vp("10.0.0.1", ["1.1.1.1", "9.9.9.9"], "8.8.4.4"),
            self._vp("10.0.0.2", ["2.2.2.2", "9.9.9.9"], "8.8.4.4"),
        ]
        self.assertIn("9.9.9.9", utils.vis._find_vp_convergence(measurements))

    def test_unequal_probe_counts_do_not_misalign(self):
        """A lost probe changed one VP's list length in the old flat-list form."""
        measurements = [
            self._vp("10.0.0.1", ["1.1.1.1", "9.9.9.9"], "8.8.4.4",
                     vp="1", repeats=3),
            self._vp("10.0.0.2", ["2.2.2.2", "9.9.9.9"], "8.8.4.4",
                     vp="2", repeats=2),
        ]
        self.assertEqual(utils.vis._find_vp_convergence(measurements),
                         {"9.9.9.9", "8.8.4.4"})

    def test_no_shared_suffix_returns_only_shared_destination(self):
        measurements = [
            self._vp("10.0.0.1", ["1.1.1.1", "3.3.3.3"], "8.8.4.4", vp="1"),
            self._vp("10.0.0.2", ["2.2.2.2", "4.4.4.4"], "8.8.4.4", vp="2"),
        ]
        self.assertEqual(utils.vis._find_vp_convergence(measurements),
                         {"8.8.4.4"})

    def test_empty_input(self):
        self.assertEqual(utils.vis._find_vp_convergence([]), set())


class TestVpConvergenceLabelNormalisation(unittest.TestCase):
    """The set held the raw dst_addr while graph nodes hold the resolved IP."""

    def test_hostname_destination_is_resolved(self):
        def fake_resolve(addr):
            return "93.184.216.34" if addr == "example.com" else addr

        measurements = [
            {"src_addr": "10.0.0.1", "dst_addr": "example.com", "vp": "1",
             "result": [{"hop": 1, "result": [{"from": "1.1.1.1"}]}]},
            {"src_addr": "10.0.0.2", "dst_addr": "example.com", "vp": "2",
             "result": [{"hop": 1, "result": [{"from": "2.2.2.2"}]}]},
        ]
        with unittest.mock.patch.object(utils.vis, "resolve_or_ip",
                                        side_effect=fake_resolve):
            result = utils.vis._find_vp_convergence(measurements)
        self.assertEqual(result, {"93.184.216.34"})
        self.assertNotIn("example.com", result)


class TestOfflineAssetEscalation(unittest.TestCase):
    """GitHub issue #75 redefined no_internet and broke the CDN fallback.

    template_main.html.jinja links vis.js from cdnjs.cloudflare.com. A
    DNS-hijacked shutdown now reports no_internet=False, so tracevis stopped
    forcing self-contained output on exactly the network that cannot reach a
    CDN. The decision is made from the recorded network_state instead.
    """

    def test_shutdown_needs_offline_assets(self):
        self.assertTrue(
            utils.vis.needs_offline_assets([{"network_state": "shutdown"}]))

    def test_allowlisted_needs_offline_assets(self):
        self.assertTrue(
            utils.vis.needs_offline_assets([{"network_state": "allowlisted"}]))

    def test_open_does_not(self):
        self.assertFalse(
            utils.vis.needs_offline_assets([{"network_state": "open"}]))

    def test_unknown_does_not(self):
        self.assertFalse(
            utils.vis.needs_offline_assets([{"network_state": "unknown"}]))

    def test_missing_state_does_not(self):
        self.assertFalse(utils.vis.needs_offline_assets([{}]))

    def test_any_censored_measurement_escalates(self):
        self.assertTrue(utils.vis.needs_offline_assets(
            [{"network_state": "open"}, {"network_state": "shutdown"}]))

    def test_observed_states_reported(self):
        self.assertEqual(
            utils.vis.observed_censored_states(
                [{"network_state": "shutdown"},
                 {"network_state": "allowlisted"},
                 {"network_state": "open"}]),
            {"shutdown", "allowlisted"})


class TestOfflineAssetEscalationEndToEnd(unittest.TestCase):
    """The escalated page must actually be self-contained."""

    def _render(self, state):
        directory = tempfile.mkdtemp()
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump([make_measurement(network_state=state)], handle)
        buf = io.StringIO()
        with redirect_stdout(buf):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable="none")
        with open(path.replace(".json", ".html"), errors="replace") as handle:
            return handle.read(), buf.getvalue()

    @staticmethod
    def _live_external_refs(page):
        """External refs, ignoring the ones the offline template comments out."""
        stripped = re.sub(r"<!--.*?-->", "", page, flags=re.DOTALL)
        return re.findall(r'(?:src|href)="(https?://[^"]+)"', stripped)

    def test_shutdown_page_has_no_external_refs(self):
        page, log = self._render("shutdown")
        self.assertEqual(self._live_external_refs(page), [])
        self.assertIn("embedding JS/CSS", log)

    def test_allowlisted_page_has_no_external_refs(self):
        page, _ = self._render("allowlisted")
        self.assertEqual(self._live_external_refs(page), [])

    def test_open_page_still_uses_the_cdn_template(self):
        page, log = self._render("open")
        self.assertNotEqual(self._live_external_refs(page), [])
        self.assertNotIn("embedding JS/CSS", log)


class TestReversePathLegendHonesty(VisFixtureMixin, unittest.TestCase):
    """The legend must not appear when no edge carries the marking."""

    def _vp(self, src, hops, dst="1.1.1.1", vp=None):
        result = [{"hop": i + 1, "result": [{"from": ip, "ttl": 64}]}
                  for i, ip in enumerate(hops)]
        base = {**make_measurement(dst_addr=dst, src_addr=src),
                "src_addr": src, "dst_addr": dst, "result": result}
        if vp:
            base["vp"] = vp
        return base

    def test_no_legend_when_only_one_vp(self):
        page = self.render([self._vp("10.0.0.1", ["100.64.0.1", "1.1.1.1"])],
                           reverse_path=True, edge_lable="none")
        self.assertNotIn("reverse-path-legend", page)

    def test_legend_when_two_vps_converge(self):
        page = self.render(
            [self._vp("10.0.0.1", ["100.64.0.1", "1.1.1.1"], vp="1"),
             self._vp("10.0.0.2", ["192.168.1.1", "1.1.1.1"], vp="2")],
            reverse_path=True, edge_lable="none")
        self.assertIn("reverse-path-legend", page)


class TestEdgeHighlightScript(VisFixtureMixin, unittest.TestCase):
    """GitHub issue #2: the injected walk must be loop-safe and reversible."""

    def _page(self):
        return self.render([make_measurement()], highlight_selected=True,
                           edge_lable="none")

    def test_walk_has_a_visited_set(self):
        """Without one, a routing loop spins forever and hangs the tab."""
        self.assertIn("seenEdges", self._page())

    def test_original_colours_are_saved_before_painting(self):
        page = self._page()
        self.assertIn("savedEdgeColors", page)
        self.assertIn("savedNodeColors", page)

    def test_clear_does_not_blank_colours(self):
        """`color: undefined` dropped elements to the vis.js default."""
        page = self._page()
        self.assertNotIn("color: undefined", page)

    def test_not_injected_without_the_flag(self):
        page = self.render([make_measurement()], edge_lable="none")
        self.assertNotIn("highlightPathToEdge", page)


# ---------------------------------------------------------------------------
# Regression tests for the review of the §2.2 / §2.3 / #68 / #69 work.
# ---------------------------------------------------------------------------


class TestRequestColorIndexing(unittest.TestCase):
    """Indexing REQUEST_COLORS by measurement number crashed past the twelfth.

    Not a corner case for --vps: utils.ripe_atlas.MEASUREMENT_IDS holds nine
    ids and download_multi_from_atlas loops probes x ids, so two probes can
    produce eighteen measurements. The render died with an IndexError after the
    download had already been saved.
    """

    def _measurements(self, count, vps=None):
        out = []
        for i in range(count):
            m = {"dst_addr": "1.1.1.1", "src_addr": f"10.0.{i}.1"}
            if vps:
                m["vp"] = vps[i % len(vps)]
            out.append(m)
        return out

    def test_thirteen_measurements_does_not_raise(self):
        colors = utils.vis.build_request_colors(self._measurements(13))
        self.assertEqual(len(colors), 13)

    def test_wraps_well_past_the_palette(self):
        colors = utils.vis.build_request_colors(self._measurements(100))
        self.assertEqual(len(colors), 100)
        self.assertTrue(set(colors) <= set(utils.vis.REQUEST_COLORS))

    def test_eighteen_measurements_render(self):
        """Two RIPE Atlas probes x the nine default measurement ids."""
        directory = tempfile.mkdtemp()
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))
        path = os.path.join(directory, "m.json")
        measurements = []
        for vp in ("1", "2"):
            for i in range(9):
                m = make_measurement(vp=vp, dst_addr=f"9.9.9.{i + 1}")
                m["src_addr"] = f"192.168.{vp}.10"
                m["vp"] = vp
                measurements.append(m)
        with open(path, "w") as handle:
            json.dump(measurements, handle)
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable="none")
        self.assertGreater(utils.vis.multi_directed_graph.number_of_edges(), 0)


class TestPerVpColouring(unittest.TestCase):
    """"per-VP colour-coded edges" was per-*measurement* colouring.

    With the accessible/blocked destination pair tracevis exists to compare,
    one vantage point got two different colours and no colour identified a VP.
    """

    def _capture(self):
        out = []
        for vp in ("1", "2"):
            for dst in ("8.8.4.4", "8.8.8.8"):
                out.append({"vp": vp, "dst_addr": dst,
                            "src_addr": f"192.168.{vp}.10"})
        return out

    def test_one_colour_per_vantage_point(self):
        capture = self._capture()
        colors = utils.vis.build_request_colors(capture)
        by_vp = {}
        for measurement, color in zip(capture, colors):
            by_vp.setdefault(measurement["vp"], set()).add(color)
        for vp, used in by_vp.items():
            self.assertEqual(len(used), 1, f"VP {vp} used {used}")

    def test_colours_differ_between_vantage_points(self):
        capture = self._capture()
        colors = utils.vis.build_request_colors(capture)
        first = {m["vp"]: c for m, c in zip(capture, colors)}
        self.assertNotEqual(first["1"], first["2"])

    def test_falls_back_to_per_measurement_without_vps(self):
        capture = [{"dst_addr": "1.1.1.1"}, {"dst_addr": "8.8.8.8"}]
        colors = utils.vis.build_request_colors(capture)
        self.assertEqual(colors, utils.vis.REQUEST_COLORS[:2])

    def test_more_vps_than_palette_entries_wrap(self):
        capture = [{"vp": str(i), "dst_addr": "1.1.1.1"} for i in range(30)]
        colors = utils.vis.build_request_colors(capture)
        self.assertEqual(len(colors), 30)


class TestSourceNodeIdentity(unittest.TestCase):
    """VP 1's source node was anonymous, and colliding VPs merged."""

    def test_vp_is_part_of_the_node_id(self):
        self.assertNotEqual(
            utils.vis.source_node_id("192.168.1.10", "1"),
            utils.vis.source_node_id("192.168.1.10", "2"))

    def test_no_vp_keeps_the_plain_numeric_id(self):
        self.assertEqual(utils.vis.source_node_id("1.1.1.1"),
                         utils.vis.source_node_id("1.1.1.1", None))


class TestSourceNodeLabelling(VisFixtureMixin, unittest.TestCase):
    """The seed node claimed the id before the loop could label VP 1."""

    def _sources(self, measurements):
        self.render(measurements, edge_lable="none")
        return sorted(
            (data["label"], data["title"])
            for _, data in utils.vis.multi_directed_graph.nodes(data=True)
            if data.get("shape") == "diamond")

    def _vp(self, vp, src):
        m = make_measurement(vp=vp)
        m["src_addr"] = src
        m["vp"] = vp
        return m

    def test_first_vp_is_labelled_too(self):
        sources = self._sources([self._vp("1", "192.168.178.26"),
                                 self._vp("2", "192.168.254.43")])
        titles = [title for _, title in sources]
        self.assertIn("source (VP 1)", titles)
        self.assertIn("source (VP 2)", titles)
        self.assertNotIn("source address", titles)

    def test_probes_sharing_a_private_address_stay_separate(self):
        """RIPE Atlas probes report RFC 1918 addresses; collisions happen."""
        sources = self._sources([self._vp("1", "192.168.1.10"),
                                 self._vp("2", "192.168.1.10")])
        self.assertEqual(len(sources), 2)
        self.assertEqual([t for _, t in sources],
                         ["source (VP 1)", "source (VP 2)"])

    def test_single_measurement_without_vp_is_unchanged(self):
        sources = self._sources([make_measurement()])
        self.assertEqual([t for _, t in sources], ["source address"])


class TestAllowlistBoundaryLabel(VisFixtureMixin, unittest.TestCase):
    """The boundary marker was suppressed by the default --label.

    The guard was `not current_edge_label`, and --label backttl (the default)
    always sets one, so the annotation only ever appeared under --label none.
    """

    def _boundary_labels(self, edge_lable):
        measurement = make_measurement(network_state="allowlisted",
                                       cgnat_hop=True)
        self.render([measurement], edge_lable=edge_lable)
        return [data.get("label") or ""
                for _, _, data in utils.vis.multi_directed_graph.edges(data=True)
                if "allowlisted tier" in (data.get("label") or "")]

    def test_visible_with_the_default_label(self):
        self.assertTrue(self._boundary_labels("backttl"))

    def test_visible_with_rtt_labels(self):
        self.assertTrue(self._boundary_labels("rtt"))

    def test_visible_with_no_labels(self):
        self.assertEqual(self._boundary_labels("none"), ["→ allowlisted tier"])

    def test_backttl_value_is_kept_alongside_the_marker(self):
        """Appending, not replacing — the hop's backttl must survive."""
        for label in self._boundary_labels("backttl"):
            self.assertRegex(label, r"^\S+ → allowlisted tier$")


class TestPhaseOverlayIsDataDriven(unittest.TestCase):
    """The legend announced a CGNAT boundary on graphs holding no CGNAT node."""

    def test_reports_absence(self):
        html = utils.vis._inject_phase_overlay("<body></body>", cgnat_nodes=0)
        self.assertIn("no CGNAT boundary on this path", html)

    def test_reports_one(self):
        html = utils.vis._inject_phase_overlay("<body></body>", cgnat_nodes=1)
        self.assertIn("1 teal hex", html)

    def test_reports_several(self):
        html = utils.vis._inject_phase_overlay("<body></body>", cgnat_nodes=4)
        self.assertIn("4 teal hexes", html)

    def test_unknown_count_keeps_the_generic_caption(self):
        html = utils.vis._inject_phase_overlay("<body></body>")
        self.assertIn("teal hex = CGNAT boundary", html)

    def test_count_matches_the_graph(self):
        graph = utils.vis.nx.MultiDiGraph()
        graph.add_node("a", color=utils.vis.CGNAT_COLOR)
        graph.add_node("b", color="green")
        graph.add_node("c", color=utils.vis.CGNAT_COLOR)
        self.assertEqual(utils.vis.count_cgnat_nodes(graph), 2)


class TestPhaseOverlayEndToEnd(VisFixtureMixin, unittest.TestCase):
    def test_no_cgnat_hop_says_so(self):
        page = self.render([make_measurement(cgnat_hop=False, hops=[
            {"from": "192.168.1.1", "rtt": 1.0, "size": 56, "ttl": 64,
             "summary": "x", "rst_count": 0},
            {"from": "8.8.8.8", "rtt": 3.0, "size": 56, "ttl": 254,
             "summary": "x", "rst_count": 0}])],
            phase_overlay=True, edge_lable="none")
        self.assertIn("no CGNAT boundary on this path", page)

    def test_cgnat_hop_is_counted(self):
        page = self.render([make_measurement(cgnat_hop=True)],
                           phase_overlay=True, edge_lable="none")
        self.assertIn("1 teal hex", page)


class TestAllowlistedTierMarking(unittest.TestCase):
    """Backlog §2.4: the band of nodes behind the CGNAT allowlist boundary."""

    @staticmethod
    def _chain(*colors):
        """A linear path n0 -> n1 -> ... with the given node colours."""
        graph = utils.vis.nx.MultiDiGraph()
        for i, color in enumerate(colors):
            graph.add_node(f"n{i}", label=f"10.0.0.{i}", color=color)
        for i in range(len(colors) - 1):
            graph.add_edge(f"n{i}", f"n{i + 1}")
        return graph

    def test_marks_everything_downstream_of_the_boundary(self):
        graph = self._chain("Chocolate", utils.vis.CGNAT_COLOR, "green", "red")
        self.assertEqual(utils.vis.mark_allowlisted_tier(graph), 2)
        self.assertTrue(graph.nodes["n2"]["allowlisted_tier"])
        self.assertTrue(graph.nodes["n3"]["allowlisted_tier"])

    def test_leaves_everything_upstream_alone(self):
        graph = self._chain("Chocolate", utils.vis.CGNAT_COLOR, "green")
        utils.vis.mark_allowlisted_tier(graph)
        self.assertNotIn("allowlisted_tier", graph.nodes["n0"])

    def test_the_boundary_is_not_inside_its_own_band(self):
        # The CGNAT node is already drawn distinctly; folding it into the tier
        # would make a second boundary downstream of the first disappear.
        graph = self._chain("Chocolate", utils.vis.CGNAT_COLOR,
                            utils.vis.CGNAT_COLOR, "green")
        utils.vis.mark_allowlisted_tier(graph)
        self.assertNotIn("allowlisted_tier", graph.nodes["n1"])
        self.assertNotIn("allowlisted_tier", graph.nodes["n2"])
        self.assertTrue(graph.nodes["n3"]["allowlisted_tier"])

    def test_no_boundary_marks_nothing(self):
        graph = self._chain("Chocolate", "green", "red")
        self.assertEqual(utils.vis.mark_allowlisted_tier(graph), 0)
        self.assertEqual(utils.vis.count_allowlisted_tier_nodes(graph), 0)

    def test_a_routing_cycle_terminates(self):
        # nx.descendants is cycle-safe; a hand-rolled walk was not, and a
        # traced path really can loop.
        graph = utils.vis.nx.MultiDiGraph()
        graph.add_node("cg", color=utils.vis.CGNAT_COLOR)
        graph.add_node("x", color="green")
        graph.add_node("y", color="green")
        graph.add_edges_from([("cg", "x"), ("x", "y"), ("y", "x")])
        self.assertEqual(utils.vis.mark_allowlisted_tier(graph), 2)

    def test_union_across_vantage_points(self):
        """A node behind a boundary on *any* VP's path is in the tier."""
        graph = utils.vis.nx.MultiDiGraph()
        graph.add_node("vp1", color="Chocolate")
        graph.add_node("vp2", color="Chocolate")
        graph.add_node("cg", color=utils.vis.CGNAT_COLOR)
        graph.add_node("shared", color="green")
        graph.add_edges_from([("vp1", "cg"), ("cg", "shared"),
                              ("vp2", "shared")])
        # vp2 reached `shared` without crossing a boundary; vp1 did not.
        self.assertEqual(utils.vis.mark_allowlisted_tier(graph), 1)
        self.assertTrue(graph.nodes["shared"]["allowlisted_tier"])
        self.assertNotIn("allowlisted_tier", graph.nodes["vp2"])

    def test_only_the_downstream_cone_is_marked(self):
        """Edges are directed; an unrelated branch must not be swept in."""
        graph = utils.vis.nx.MultiDiGraph()
        graph.add_node("src", color="Chocolate")
        graph.add_node("cg", color=utils.vis.CGNAT_COLOR)
        graph.add_node("behind", color="green")
        graph.add_node("sibling", color="green")
        graph.add_edges_from([("src", "cg"), ("cg", "behind"),
                              ("src", "sibling")])
        utils.vis.mark_allowlisted_tier(graph)
        self.assertTrue(graph.nodes["behind"]["allowlisted_tier"])
        self.assertNotIn("allowlisted_tier", graph.nodes["sibling"])

    def test_count_matches_what_was_marked(self):
        graph = self._chain("Chocolate", utils.vis.CGNAT_COLOR, "green", "red")
        marked = utils.vis.mark_allowlisted_tier(graph)
        self.assertEqual(marked, utils.vis.count_allowlisted_tier_nodes(graph))


class TestPhaseOverlayReportsTheBand(unittest.TestCase):
    """The band is often most of the graph, so the count has to be shown.

    Without it a reader cannot tell "the allowlisted tier is wide" from "the
    marking is broken" -- and on this repository's own captures the band runs
    as high as 97 of 100 nodes.
    """

    def test_reports_the_tier_size(self):
        html = utils.vis._inject_phase_overlay(
            "<body></body>", cgnat_nodes=1, tier_nodes=97)
        self.assertIn("97 nodes behind it", html)

    def test_singular_tier(self):
        html = utils.vis._inject_phase_overlay(
            "<body></body>", cgnat_nodes=1, tier_nodes=1)
        self.assertIn("1 node behind it", html)

    def test_reports_an_empty_tier(self):
        html = utils.vis._inject_phase_overlay(
            "<body></body>", cgnat_nodes=0, tier_nodes=0)
        self.assertIn("no nodes behind it", html)

    def test_omitted_tier_keeps_the_old_caption(self):
        html = utils.vis._inject_phase_overlay("<body></body>", cgnat_nodes=1)
        self.assertIn("1 teal hex", html)
        self.assertNotIn("behind it", html)

    def test_caption_line_break_is_markup_not_an_escaped_newline(self):
        html = utils.vis._inject_phase_overlay(
            "<body></body>", cgnat_nodes=1, tier_nodes=4)
        self.assertIn("<br/>4 nodes behind it", html)


class TestAddressFamilyAgnosticNodeIds(unittest.TestCase):
    """Backlog §2.1: the graph layer accepts both address families."""

    def test_ipv4_ids_are_unchanged(self):
        """Existing captures must render to exactly the ids they always did."""
        self.assertEqual(utils.vis.address_node_id("1.1.1.1"), "x16843009x")
        self.assertEqual(utils.vis.address_node_id("192.168.1.1"),
                         "x3232235777x")

    def test_ipv6_addresses_get_an_id(self):
        node_id = utils.vis.address_node_id("2606:4700:4700::1111")
        self.assertTrue(node_id.startswith("xv6"))
        self.assertTrue(node_id.endswith("x"))

    def test_the_families_cannot_collide(self):
        """`::1` and `0.0.0.1` are both the integer 1.

        Without the family in the id a dual-stack capture would draw two
        different hops as one node.
        """
        self.assertNotEqual(utils.vis.address_node_id("::1"),
                            utils.vis.address_node_id("0.0.0.1"))

    def test_a_non_address_has_no_id(self):
        self.assertIsNone(utils.vis.address_node_id("not-an-address"))
        self.assertIsNone(utils.vis.address_node_id("***"))
        self.assertIsNone(utils.vis.address_node_id(None))

    def test_the_fallback_keeps_unresolved_names_apart(self):
        # resolve_or_ip returns the name unchanged when resolution fails, and
        # the id builder used to raise on it and take the render down.
        first = utils.vis._node_id_or_label("a.example")
        second = utils.vis._node_id_or_label("b.example")
        self.assertNotEqual(first, second)
        self.assertNotIn(".", first)

    def test_resolve_or_ip_passes_ipv6_through(self):
        self.assertEqual(utils.vis.resolve_or_ip("2606:4700:4700::1111"),
                         "2606:4700:4700::1111")
        self.assertEqual(utils.vis.resolve_or_ip("::1"), "::1")

    def test_resolve_or_ip_still_passes_ipv4_through(self):
        self.assertEqual(utils.vis.resolve_or_ip("8.8.8.8"), "8.8.8.8")

    def test_resolve_or_ip_returns_an_unresolvable_name_unchanged(self):
        self.assertEqual(
            utils.vis.resolve_or_ip("no-such-host.invalid"),
            "no-such-host.invalid")


class TestRespondingHopWithoutPacketBlobs(unittest.TestCase):
    """A hop that answered but carries an empty `packets.received`.

    `is_allowlist_boundary` was assigned only inside the branch that has
    received packets to analyse, and read unconditionally below it, so such a
    capture crashed the whole render with UnboundLocalError. RIPE Atlas data
    and any capture written without packet blobs both have this shape.
    Predates §2.1 and is not family-specific — found while rendering an IPv6
    capture, reproduced identically on the IPv4 equivalent.
    """

    @staticmethod
    def _capture(dst, src, hops):
        return [{
            "af": 6 if ":" in dst else 4, "dst_addr": dst, "src_addr": src,
            "dst_name": "", "annotation": "probe", "endtime": 1000,
            "from_ip": "127.0.0.1", "lts": -1, "msm_id": -1,
            "msm_name": "traceroute", "paris_id": 0, "prb_id": -1,
            "proto": "UDP", "port": 53, "size": 100, "timestamp": 900,
            "ttr": -1, "asn": "AS0", "asname": "", "cc": "", "city": "",
            "dpi_cleared": True, "cgnat_hop": False, "sni_inspected": False,
            "rst_flood": False, "tcp_silently_dropped": False,
            "network_state": "open",
            "result": [
                {"hop": index + 1,
                 "result": [{"from": address, "rtt": 1.0, "size": 56,
                             "ttl": 60, "summary": "s", "rst_count": 0,
                             "packets": {"sent": [], "received": []}}]}
                for index, address in enumerate(hops)],
        }]

    def _render(self, capture):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "c.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(capture, handle)
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=True,
                          edge_lable="backttl")
        return utils.vis.multi_directed_graph

    def test_an_ipv4_capture_without_packet_blobs_renders(self):
        graph = self._render(self._capture(
            "1.1.1.1", "192.168.1.5", ["192.168.1.1", "10.0.0.1", "1.1.1.1"]))
        self.assertEqual(graph.number_of_nodes(), 4)

    def test_an_ipv6_capture_renders(self):
        graph = self._render(self._capture(
            "2606:4700:4700::1111", "2001:db8::5",
            ["2001:db8::1", "2001:db8:1::1", "2606:4700:4700::1111"]))
        self.assertEqual(graph.number_of_nodes(), 4)
        labels = {data.get("label") for _n, data in graph.nodes(data=True)}
        self.assertIn("2606:4700:4700::1111", labels)

    def test_a_dual_stack_capture_keeps_the_families_apart(self):
        capture = self._capture("0.0.0.1", "192.168.1.5",
                                ["192.168.1.1", "0.0.0.1"])
        capture += self._capture("::1", "2001:db8::5", ["2001:db8::1", "::1"])
        graph = self._render(capture)
        labels = {data.get("label") for _n, data in graph.nodes(data=True)}
        self.assertIn("0.0.0.1", labels)
        self.assertIn("::1", labels)


class TestMalformedCapturesAreReportedNotRaised(unittest.TestCase):
    """`vis()` dereferenced the file's shape directly and left tracebacks.

    `json.load` then `all_measurements[0]["src_addr"]` produced
    JSONDecodeError on a truncated file, IndexError on `[]` and KeyError on a
    JSON object. A capture arriving truncated is an ordinary outcome on the
    networks this tool measures, so its own reader should not be the thing
    that breaks.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _write(self, name, raw=None, payload=None):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(raw if raw is not None else json.dumps(payload))
        return path

    @staticmethod
    def _hop():
        return {"hop": 1, "result": [{"from": "10.0.0.1", "rtt": 1.0,
                                      "size": 56, "ttl": 60, "summary": "s",
                                      "rst_count": 0,
                                      "packets": {"sent": [], "received": []}}]}

    def _ok(self):
        return {"src_addr": "192.168.1.5", "dst_addr": "1.1.1.1",
                "result": [self._hop()]}

    def _reason(self, **kwargs):
        with self.assertRaises(utils.vis.MeasurementFormatError) as caught:
            utils.vis.load_measurements(self._write("c.json", **kwargs))
        return str(caught.exception)

    def test_truncated_json(self):
        self.assertIn("not valid JSON", self._reason(raw="{not json"))

    def test_an_empty_list(self):
        self.assertIn("no measurements", self._reason(payload=[]))

    def test_a_json_object_rather_than_a_list(self):
        self.assertIn("not the list of measurements",
                      self._reason(payload={"a": 1}))

    def test_a_list_of_scalars(self):
        self.assertIn("not a JSON object", self._reason(payload=[1, 2, 3]))

    def test_a_missing_required_field_is_named(self):
        capture = self._ok()
        del capture["src_addr"]
        self.assertIn("missing src_addr", self._reason(payload=[capture]))

    def test_several_missing_fields_are_all_named(self):
        self.assertIn("missing src_addr, dst_addr",
                      self._reason(payload=[{"result": [self._hop()]}]))

    def test_an_empty_result_list(self):
        self.assertIn("no hops", self._reason(payload=[{**self._ok(),
                                                        "result": []}]))

    def test_a_first_hop_with_no_probe_results(self):
        self.assertIn("no probe results", self._reason(
            payload=[{**self._ok(), "result": [{"hop": 1, "result": []}]}]))

    def test_the_offending_measurement_is_identified_by_index(self):
        """A capture holds many measurements; naming which one matters."""
        self.assertIn("measurement 1", self._reason(
            payload=[self._ok(), {"src_addr": "x"}]))

    def test_a_missing_file_is_reported_not_raised(self):
        with self.assertRaises(utils.vis.MeasurementFormatError) as caught:
            utils.vis.load_measurements(os.path.join(self.dir, "nope.json"))
        self.assertIn("cannot read", str(caught.exception))

    def test_vis_returns_false_rather_than_raising(self):
        path = self._write("c.json", raw="{not json")
        with redirect_stdout(io.StringIO()) as buf:
            result = utils.vis.vis(measurement_path=path, attach_jscss=True)
        self.assertFalse(result)
        self.assertIn("not valid JSON", buf.getvalue())

    def test_a_valid_capture_is_accepted_unchanged(self):
        path = self._write("c.json", payload=[self._ok()])
        self.assertEqual(len(utils.vis.load_measurements(path)), 1)

    def test_the_reader_does_not_reject_this_repository_s_captures(self):
        """An over-strict reader would be worse than the crash it replaces."""
        captures = glob.glob("tracevis_data*/*.json")
        self.assertGreater(len(captures), 0, "no captures found to check")
        for path in captures:
            utils.vis.load_measurements(path)

    def test_only_the_fields_rendering_dereferences_are_required(self):
        # `annotation` is absent from real captures and must stay optional.
        self.assertEqual(set(utils.vis.REQUIRED_MEASUREMENT_FIELDS),
                         {"src_addr", "dst_addr", "result"})
