"""Validation for the shipped `samples/*.conf` configurations.

`test_operationality.test_config_file` only proves a sample round-trips through
`get_args`, and because the config merge is `args_dict.update(json)` that
comparison is effectively self-referential — a sample with a misspelled key, a
non-IPv4 packet or a contradictory mode combination passes it unchanged.

These tests assert the properties a sample must actually hold to produce a
usable trace: every key is a real argparse destination, every stored packet
decodes as IPv4 through the project's own loader, targets are well-formed and
within the visualiser's colour budget, and the probe modes are mutually
consistent.
"""
import io
import ipaddress
import json
import os
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from unittest import mock

from scapy.all import IP, TCP, UDP, hexdump

import tracevis
import utils.dns
import utils.sni
from test.test_anonymize import recomputed_chksum
from utils.packet_input import BADPacketException, InputPacketInfo
from utils.vis import REQUEST_COLORS

SAMPLES_DIR = "samples"

REFRESHED_POOL = "1.1.1.1,104.16.133.229,142.251.36.14,151.101.1.57"

# Protocol-shape A/B samples that deliberately pin a single destination: the
# contrast is the payload, and `1.1.1.1:443` is the only arm observed
# completing a TCP handshake, so it is the only place the comparison can be made.
SINGLE_TARGET_AB = ("grpc-h2c.conf", "shadowsocks.conf")
CONTROLLED_AB_SAMPLES = SINGLE_TARGET_AB + ("wireguard.conf",)

# `tracevis.py` help for -i/--ips: "up to 6 for two packet and up to 12 for one
# packet" — the ceiling is len(REQUEST_COLORS), indexed per measurement entry in
# `utils/vis.py:437`, and an over-long pool raises IndexError *after* the trace.
MAX_MEASUREMENT_ENTRIES = len(REQUEST_COLORS)

# Modes that build their own probe packets and therefore cannot coexist with a
# stored `packet_data` (tracevis.py:290-320; `packet` silently wins).
NON_PACKET_MODES = ("dns", "dnstcp", "dnsdot", "dnstt", "sni_test")


def sample_files():
    return sorted(os.listdir(SAMPLES_DIR))


def load_sample(name):
    with open(os.path.join(SAMPLES_DIR, name)) as f:
        return json.load(f)


def decode_packet(packet_data, key):
    """Decode a stored hexdump with the project's own loader, muting its print."""
    with redirect_stdout(io.StringIO()):
        return InputPacketInfo._read_json_packet(deepcopy(packet_data), key)


def probe_count(config):
    """How many probes a sample produces per target.

    Every non-`packet` mode builds an (accessible, blocked) *pair* even though
    `packet_data` is null, so counting `packet2` alone under-reports them and
    would let an over-long DNS target list through to an `IndexError` in
    `utils/vis.py:437` after a completed trace.
    """
    if config.get("packet"):
        return 2 if "packet2" in (config.get("packet_data") or {}) else 1
    return 2


def tls_payload_without_random(packet):
    """ClientHello bytes with the 32-byte random masked out.

    Record header is 5 bytes, handshake type+length 4 more, then the body opens
    with a 2-byte legacy_version — so the random occupies bytes 11..43 and is
    the only field expected to differ between two otherwise-identical probes.
    """
    payload = bytes(packet[TCP].payload)
    return payload[:11] + payload[43:]


class TestSamples(unittest.TestCase):
    def test_every_sample_is_a_conf_file(self):
        """`test_config_file` feeds *every* directory entry to --config-file."""
        for name in sample_files():
            path = os.path.join(SAMPLES_DIR, name)
            self.assertTrue(os.path.isfile(path), f"{name} is not a file")
            self.assertTrue(name.endswith(".conf"), f"{name} is not a .conf")

    def test_keys_are_known_argparse_destinations(self):
        """A key that is not an argparse dest is silently carried and ignored."""
        with redirect_stdout(io.StringIO()):
            known = set(tracevis.get_args([], auto_exit=False))
        for name in sample_files():
            for key in load_sample(name):
                self.assertIn(key, known, f"{name}: unknown config key {key!r}")

    def test_stored_packets_decode_as_ipv4(self):
        for name in sample_files():
            packet_data = load_sample(name).get("packet_data")
            if not packet_data:
                continue
            for key in ("packet1", "packet2"):
                if key not in packet_data:
                    continue
                packet = decode_packet(packet_data, key)
                self.assertEqual(packet.version, 4, f"{name}/{key} is not IPv4")

    def test_handshake_flag_is_honoured_by_the_loader(self):
        """`from_json` only applies `handshake` to a PSH/ACK TCP packet.

        A sample asking for a handshake on any other packet shape gets it
        silently dropped, so the trace runs without the handshake it declared.
        """
        for name in sample_files():
            packet_data = load_sample(name).get("packet_data")
            if not packet_data:
                continue
            for key in ("packet1", "packet2"):
                entry = packet_data.get(key)
                if not entry or not entry.get("handshake"):
                    continue
                packet = decode_packet(packet_data, key)
                self.assertTrue(packet.haslayer(TCP), f"{name}/{key}: not TCP")
                self.assertEqual(str(packet[TCP].flags), "PA",
                                 f"{name}/{key}: handshake needs PSH/ACK")

    def test_targets_are_valid_and_within_the_colour_budget(self):
        for name in sample_files():
            config = load_sample(name)
            ips = config.get("ips")
            if not ips:
                continue
            targets = ips.split(",")
            for target in targets:
                # IPv6 would raise here and is unsupported end to end (the
                # visualiser and traceroute struct are IPv4-only).
                self.assertEqual(ipaddress.ip_address(target).version, 4,
                                 f"{name}: {target} is not IPv4")
            self.assertLessEqual(
                len(targets) * probe_count(config), MAX_MEASUREMENT_ENTRIES,
                f"{name}: {len(targets)} targets x {probe_count(config)} probes "
                f"exceeds the {MAX_MEASUREMENT_ENTRIES}-colour budget")

    def test_probe_modes_are_mutually_consistent(self):
        for name in sample_files():
            config = load_sample(name)
            enabled = [mode for mode in NON_PACKET_MODES if config.get(mode)]
            if config.get("packet"):
                self.assertEqual(
                    enabled, [], f"{name}: packet mode conflicts with {enabled}")
                self.assertTrue(config.get("packet_data"),
                                f"{name}: packet mode without packet_data")
            else:
                self.assertEqual(
                    len(enabled), 1,
                    f"{name}: expected exactly one probe mode, got {enabled}")


class TestRefreshedSamples(unittest.TestCase):
    """Backlog §2.5 — the refreshed, allowlist-aware sample pool."""

    def test_reality_sample_varies_only_the_port(self):
        """Port is the single variable: 443 control vs 8443 treatment.

        The two probes must be otherwise identical — same SNI, same TLS bytes
        modulo the ClientHello random — or the comparison confounds port with
        SNI and the sample answers nothing.
        """
        config = load_sample("reality-non443.conf")
        self.assertEqual(config["ips"], "1.1.1.1")
        packets = {}
        for key in ("packet1", "packet2"):
            packet = decode_packet(config["packet_data"], key)
            # TLS record: handshake(0x16) / ClientHello(0x01).
            payload = bytes(packet[TCP].payload)
            self.assertEqual(payload[0], 0x16)
            self.assertEqual(payload[5], 0x01)
            self.assertIn(b"hcaptcha.com", payload)
            self.assertTrue(config["packet_data"][key]["handshake"])
            packets[key] = packet
        self.assertEqual(packets["packet1"][TCP].dport, 443)
        self.assertEqual(packets["packet2"][TCP].dport, 8443)
        # Byte-for-byte identical once the per-hello random is masked. Equal
        # *lengths* would not do: swapping cipher suites or the extension set
        # while holding length constant would confound port with hello shape.
        self.assertEqual(tls_payload_without_random(packets["packet1"]),
                         tls_payload_without_random(packets["packet2"]),
                         "probes differ by more than the port")

    def test_reality_annotations_match_the_ports_they_describe(self):
        config = load_sample("reality-non443.conf")
        for key, annotation in (("packet1", "annot1"), ("packet2", "annot2")):
            dport = decode_packet(config["packet_data"], key)[TCP].dport
            self.assertIn(f":{dport}", config[annotation],
                          f"{annotation} does not name port {dport}")

    def test_new_samples_do_not_use_paris_retransmission(self):
        """`paris: true` would silently replace a failed arm with a bare SYN.

        With retransmission mode on, `generate_packets_for_each_ip` runs the
        handshake once as a preflight and, when it fails, retransmits
        `unanswered[0][0]` — the SYN — at every TTL (`utils/trace.py:461-463`).
        For the port A/B that turns a dead treatment port into a
        ClientHello-vs-SYN comparison, confounding port with probe type in
        exactly the case the sample exists to detect.
        """
        for name in ("reality-non443.conf", "dnstt.conf") + CONTROLLED_AB_SAMPLES:
            config = load_sample(name)
            self.assertFalse(config["paris"], f"{name}: paris must be off")
            self.assertFalse(config["rexmit"], f"{name}: rexmit must be off")
            # `from_json` reads packet2 and the handshake flags only when
            # retransmission is off, so `paris: true` would also silently strip
            # the handshake from every A/B arm that declares one.
            for key in ("packet1", "packet2"):
                entry = (config.get("packet_data") or {}).get(key)
                if entry and entry.get("handshake"):
                    self.assertFalse(
                        config["paris"],
                        f"{name}/{key}: paris would drop the declared handshake")

    def test_no_sample_embeds_a_real_source_address(self):
        """Was scoped to the new samples only, because nine older ones carried
        the address of the machine that generated them. They
        got there because the config dump wrote the packet exactly as sent;
        `InputPacketInfo._dump` now applies the sentinel on every input path, and
        the committed samples were rewritten to match (backlog §2.8)."""
        for name in sorted(os.listdir(SAMPLES_DIR)):
            config = load_sample(name)
            if not config.get("packet_data"):
                continue
            for key in ("packet1", "packet2"):
                if key not in config["packet_data"]:
                    continue
                packet = decode_packet(config["packet_data"], key)
                self.assertEqual(packet.src, "127.1.2.7",
                                 f"{name}/{key} leaks a source address")

    def test_stored_packets_carry_checksums_that_verify(self):
        """A stale checksum is a fingerprint of its own — a header that does not
        verify against its own address is more distinctive than the address was.

        Both layers: the L4 checksum covers an IP pseudo-header, so rewriting
        the source invalidates it too. `quicvd29.conf` had been shipping a stale
        pair since whenever its source was first rewritten, which the earlier
        version of this assertion could not see: it compared a parsed packet's
        checksum against a rebuild of itself, and a rebuild keeps a checksum
        that is already set.
        """
        for name in sorted(os.listdir(SAMPLES_DIR)):
            config = load_sample(name)
            if not config.get("packet_data"):
                continue
            for key in ("packet1", "packet2"):
                if key not in config["packet_data"]:
                    continue
                packet = decode_packet(config["packet_data"], key)
                for layer in (IP, TCP, UDP):
                    if not packet.haslayer(layer):
                        continue
                    self.assertEqual(
                        recomputed_chksum(packet, layer), packet[layer].chksum,
                        f"{name}/{key}: {layer.__name__} checksum is stale")

    def test_dnstt_sample_traces_the_udp53_carrier(self):
        config = load_sample("dnstt.conf")
        self.assertTrue(config["dnstt"])
        self.assertFalse(config["packet"])
        self.assertIsNone(config["packet_data"])
        # A port override would move the probe off the UDP/53 dnstt carrier.
        self.assertIsNone(config["port"])
        self.assertIsNone(config["port_pool"])
        self.assertEqual(config["timeout_profile"], "shutdown")

    def test_generic_samples_target_the_refreshed_pool(self):
        """Payload-bound probes keep their own target; generic ones share a pool.

        `clienthello`/`httpget` name instagram.com inside the payload and `ntp`
        can only be answered by an NTP server, so retargeting those at a CDN
        pool would make the probe incoherent. Every other packet sample is a
        generic path probe and moves to the refreshed pool.
        """
        payload_bound = {"clienthello.conf", "httpget.conf", "ntp.conf"}
        # A/B samples pin one destination on purpose — see SINGLE_TARGET_AB.
        exempt = payload_bound | {"reality-non443.conf"} | set(SINGLE_TARGET_AB)
        for name in sample_files():
            config = load_sample(name)
            if not config.get("packet") or name in exempt:
                continue
            self.assertEqual(config["ips"], REFRESHED_POOL,
                             f"{name}: stale target pool")


class TestProtocolShapeSamples(unittest.TestCase):
    """Protocols that previously had no probe shape.

    Each is a controlled A/B: two probes differing in exactly one thing, so a
    difference in outcome has one explanation. Regenerate with
    `PYTHONPATH=. python3 tools/build_protocol_samples.py`.
    """

    def test_tcp_ab_samples_vary_only_the_payload(self):
        """Same host, same port, both handshaking — payload shape is the variable.

        They pin `1.1.1.1:443` because it is the only destination any run
        saw complete a TCP handshake. Without a completed handshake the probe is
        a stray PSH/ACK that any stack drops, and the run answers nothing.
        """
        for name in SINGLE_TARGET_AB:
            config = load_sample(name)
            self.assertEqual(config["ips"], "1.1.1.1", name)
            ports, payloads = set(), []
            for key in ("packet1", "packet2"):
                packet = decode_packet(config["packet_data"], key)
                self.assertTrue(config["packet_data"][key]["handshake"],
                                f"{name}/{key}: needs a handshake to be in-stream")
                ports.add(packet[TCP].dport)
                payloads.append(bytes(packet[TCP].payload))
            self.assertEqual(ports, {443}, f"{name}: port must not vary")
            self.assertNotEqual(payloads[0], payloads[1], f"{name}: no contrast")

    def test_the_control_arm_is_the_hello_sni_test_sends(self):
        """The control has to be a shape already known to pass, or a failure in
        the treatment arm proves nothing."""
        control = utils.sni.build_tls_clienthello("hcaptcha.com")
        for name in SINGLE_TARGET_AB:
            packet = decode_packet(load_sample(name)["packet_data"], "packet1")
            payload = bytes(packet[TCP].payload)
            self.assertEqual(tls_payload_without_random(packet),
                             control[:11] + control[43:],
                             f"{name}: control arm is not the --sni-test hello")
            self.assertEqual(payload[0], 0x16)

    def test_grpc_sample_sends_a_real_h2c_preface(self):
        """443 is deep-inspected and non-TLS patterns draw RSTs.
        The h2c preface is the cleanest non-TLS pattern available."""
        packet = decode_packet(load_sample("grpc-h2c.conf")["packet_data"], "packet2")
        payload = bytes(packet[TCP].payload)
        self.assertTrue(payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        # 24-byte preface + a 9-byte empty SETTINGS frame (type 0x04).
        self.assertEqual(len(payload), 33)
        self.assertEqual(payload[24:], b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")

    def test_shadowsocks_sample_is_headerless_high_entropy(self):
        """Shadowsocks AEAD has no magic, version or header by design — the
        probe must not accidentally acquire one."""
        packet = decode_packet(load_sample("shadowsocks.conf")["packet_data"], "packet2")
        payload = bytes(packet[TCP].payload)
        self.assertEqual(len(payload), 32 + 18 + 64)   # salt + length block + chunk
        self.assertGreater(len(set(payload)), 64, "payload is not high-entropy")
        for marker in (b"\x16\x03", b"PRI", b"HTTP", b"\x01\x00\x00\x00"):
            self.assertFalse(payload.startswith(marker), f"looks like {marker!r}")

    def test_wireguard_sample_contrasts_the_header_against_noise(self):
        """Same port, same length — only the recognisable header differs.

        If the WireGuard arm dies earlier than the noise arm, the DPI matched
        the *pattern* rather than "unknown UDP on 51820".
        """
        config = load_sample("wireguard.conf")
        wg = bytes(decode_packet(config["packet_data"], "packet1")[UDP].payload)
        noise = bytes(decode_packet(config["packet_data"], "packet2")[UDP].payload)
        # Handshake initiation: type=1, 3 reserved zero bytes, 148 bytes total
        # (WireGuard whitepaper §5.4.2).
        self.assertEqual(wg[:4], b"\x01\x00\x00\x00")
        self.assertEqual(len(wg), 148)
        self.assertEqual(len(noise), len(wg), "length must not be a variable")
        self.assertNotEqual(wg[:4], noise[:4])
        for key in ("packet1", "packet2"):
            packet = decode_packet(config["packet_data"], key)
            self.assertEqual(packet[UDP].dport, 51820)
            self.assertFalse(config["packet_data"][key]["handshake"], "UDP")


class TestSampleWiring(unittest.TestCase):
    """End-to-end: a config file must reach `trace_route` as the probe it claims.

    Parsing a sample proves nothing about what gets sent. These run `main()`
    with `trace_route` stubbed out and assert the kwargs it would have received.
    Nothing touches the network: `run_geolocate`, `check_for_permission` and the
    send loop all live inside the stubbed `trace_route`.
    """

    def _trace_kwargs(self, config_name):
        captured = {}

        def stub(**kwargs):
            captured.update(kwargs)
            return (False, "", False)

        args = tracevis.get_args(
            ["--config-file", os.path.join(SAMPLES_DIR, config_name)],
            auto_exit=False)
        with mock.patch("utils.trace.trace_route", side_effect=stub), \
                mock.patch("utils.vis.vis", return_value=False), \
                redirect_stdout(io.StringIO()):
            tracevis.main(args)
        return captured

    def test_reality_sample_keeps_both_ports_through_to_the_tracer(self):
        kwargs = self._trace_kwargs("reality-non443.conf")
        self.assertEqual(kwargs["ip_list"], ["1.1.1.1"])
        self.assertEqual(kwargs["max_ttl"], 20)
        self.assertEqual(kwargs["timeout"], 3)      # degraded profile
        self.assertEqual(kwargs["repeat_requests"], 1)
        # Both probes must get the handshake, or the ClientHello is never
        # delivered in-stream and the sample measures nothing.
        self.assertTrue(kwargs["do_tcph1"])
        self.assertTrue(kwargs["do_tcph2"])
        # `dst_port` must stay unset: --port/--port-pool rewrite *both* packets
        # to one port (utils/trace.py:596-598), collapsing the A/B.
        self.assertEqual(kwargs["dst_port"], -1)
        self.assertEqual(kwargs["request_packet_1"][TCP].dport, 443)
        self.assertEqual(kwargs["request_packet_2"][TCP].dport, 8443)
        self.assertIn("hcaptcha.com", kwargs["annotation_1"])
        # Retransmission mode must stay off, or each arm is a preflight
        # handshake replayed per TTL rather than a real in-stream ClientHello.
        self.assertFalse(kwargs["trace_with_retransmission"])
        self.assertFalse(kwargs["trace_retransmission"])

    def test_dnstt_sample_sends_udp53_probes(self):
        kwargs = self._trace_kwargs("dnstt.conf")
        self.assertEqual(kwargs["ip_list"], utils.dns.DEFAULT_TARGETS)
        self.assertEqual(kwargs["timeout"], 60)     # shutdown profile
        self.assertEqual(kwargs["max_ttl"], 20)
        for key in ("request_packet_1", "request_packet_2"):
            self.assertEqual(kwargs[key][UDP].dport, 53)
        self.assertFalse(kwargs["do_tcph1"])


class TestSampleLoaderGuards(unittest.TestCase):
    def test_non_ipv4_packet_is_rejected(self):
        """Regression: the guard built the exception without raising it, so a
        malformed hexdump was silently mis-parsed as garbage IPv4."""
        # A complete 40-byte IPv6 header: version 6, no next header, ::1 -> ::1.
        ipv6_header = (b"\x60\x00\x00\x00\x00\x00\x3b\x40"
                       + b"\x00" * 15 + b"\x01"
                       + b"\x00" * 15 + b"\x01")
        packet_data = {"packet1": {"hex": hexdump(ipv6_header, dump=True),
                                   "handshake": False}}
        with redirect_stdout(io.StringIO()), \
                self.assertRaises(BADPacketException):
            InputPacketInfo._read_json_packet(packet_data, "packet1")


if __name__ == "__main__":
    unittest.main()
