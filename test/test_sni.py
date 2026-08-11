import struct
import unittest

from scapy.all import IP, TCP, Raw

from utils.sni import build_tls_clienthello, make_sni_packets, make_sni_probe

# Extension types we emit, mapped to the width of their *inner* list-length
# prefix. Getting these wrong makes a strict TLS parser answer `decode_error`
# instead of a ServerHello, and makes a fingerprinting DPI see an anomalous
# hello — which would confound "this port is filtered" with "this hello is
# rejected everywhere".
INNER_LENGTH_WIDTH = {
    0x0000: 2,  # server_name
    0x000a: 2,  # supported_groups
    0x000b: 1,  # ec_point_formats
    0x000d: 2,  # signature_algorithms
    0x002b: 1,  # supported_versions
}


def parse_extensions(hello):
    """Walk a ClientHello and return {ext_type: ext_data}, checking framing."""
    record_length = struct.unpack("!H", hello[3:5])[0]
    body = hello[5:]
    assert record_length == len(body), "TLS record length mismatch"
    handshake_length = int.from_bytes(body[1:4], "big")
    client_hello = body[4:]
    assert handshake_length == len(client_hello), "handshake length mismatch"

    pos = 2 + 32                                     # legacy_version + random
    pos += 1 + client_hello[pos]                     # legacy_session_id
    pos += 2 + struct.unpack("!H", client_hello[pos:pos + 2])[0]   # cipher_suites
    pos += 1 + client_hello[pos]                     # compression_methods
    total = struct.unpack("!H", client_hello[pos:pos + 2])[0]
    pos += 2
    assert pos + total == len(client_hello), "extensions block length mismatch"

    extensions = {}
    end = pos + total
    while pos < end:
        ext_type = struct.unpack("!H", client_hello[pos:pos + 2])[0]
        ext_length = struct.unpack("!H", client_hello[pos + 2:pos + 4])[0]
        data = client_hello[pos + 4:pos + 4 + ext_length]
        assert len(data) == ext_length, f"extension {ext_type:#06x} truncated"
        extensions[ext_type] = data
        pos += 4 + ext_length
    assert pos == end, "extensions block overran"
    return extensions


class TestClientHelloStructure(unittest.TestCase):
    """The hello must survive a strict parse, not merely contain the SNI.

    Regression: `supported_versions` shipped without its 1-byte list length,
    `signature_algorithms` without its 2-byte list length, and extension 0x000a
    (supported_groups) carried 3 bytes of ec_point_formats data.
    """

    def test_every_extension_declares_a_consistent_inner_length(self):
        extensions = parse_extensions(build_tls_clienthello("example.com"))
        for ext_type, data in extensions.items():
            self.assertIn(ext_type, INNER_LENGTH_WIDTH,
                          f"unexpected extension {ext_type:#06x}")
            width = INNER_LENGTH_WIDTH[ext_type]
            if width == 1:
                inner = data[0]
            else:
                inner = struct.unpack("!H", data[0:2])[0]
            self.assertEqual(
                inner, len(data) - width,
                f"extension {ext_type:#06x}: inner length {inner} != "
                f"{len(data) - width}")

    def test_versions_and_algorithm_lists_hold_whole_entries(self):
        extensions = parse_extensions(build_tls_clienthello("example.com"))
        # supported_versions: 1-byte length, then 2-byte versions.
        self.assertEqual((len(extensions[0x002b]) - 1) % 2, 0)
        self.assertIn(b"\x03\x04", extensions[0x002b])       # TLS 1.3 offered
        # signature_algorithms / supported_groups: 2-byte entries.
        for ext_type in (0x000d, 0x000a):
            self.assertEqual((len(extensions[ext_type]) - 2) % 2, 0)

    def test_sni_extension_carries_the_hostname(self):
        extensions = parse_extensions(build_tls_clienthello("hcaptcha.com"))
        server_name = extensions[0x0000]
        # list length (2) + name type (1) + name length (2) + the name
        self.assertEqual(server_name[2], 0x00)               # host_name
        length = struct.unpack("!H", server_name[3:5])[0]
        self.assertEqual(server_name[5:5 + length], b"hcaptcha.com")


class TestTLSClientHello(unittest.TestCase):
    def test_record_header(self):
        hello = build_tls_clienthello("example.com")
        self.assertEqual(hello[0], 0x16)            # content_type: handshake
        self.assertEqual(hello[1:3], b"\x03\x03")    # version: TLS 1.2
        self.assertEqual(hello[5], 0x01)            # handshake type: ClientHello

    def test_sni_hostname_present(self):
        sni = "www.google.com"
        hello = build_tls_clienthello(sni)
        self.assertIn(sni.encode(), hello)

    def test_sni_extension_type(self):
        """The Server Name Indication extension type (0x0000) must be present."""
        hello = build_tls_clienthello("example.com")
        self.assertIn(b"\x00\x00", hello)

    def test_random_is_32_bytes(self):
        """TLS random is exactly 32 bytes and changes per call."""
        h1 = build_tls_clienthello("example.com")
        h2 = build_tls_clienthello("example.com")
        # record(5) + handshake header(4) + legacy_version(2) => random at 11:43
        self.assertEqual(len(h1[11:43]), 32)
        self.assertNotEqual(h1[11:43], h2[11:43])

    def test_cipher_suites_present(self):
        """At least one cipher suite (e.g. TLS_AES_256_GCM_SHA384 = 0x1301) present."""
        hello = build_tls_clienthello("example.com")
        self.assertIn(b"\x13\x01", hello)

    def test_extensions_present(self):
        """Extensions block must exist (length > 0)."""
        hello = build_tls_clienthello("example.com")
        # Extensions length is a uint16 right after compression methods.
        # At minimum, the SNI extension bytes must be there.
        self.assertIn(b"\x00\x00", hello)


class TestSNIProbe(unittest.TestCase):
    def test_make_sni_probe(self):
        pkt, sni, _ = make_sni_probe("1.1.1.1", "www.google.com")
        self.assertEqual(pkt[IP].dst, "1.1.1.1")
        self.assertEqual(pkt[TCP].dport, 443)
        self.assertIn("PA", str(pkt[TCP].flags))
        self.assertIn(b"www.google.com", bytes(pkt[Raw].load))
        self.assertEqual(sni, "www.google.com")

    def test_make_sni_probe_ttl(self):
        pkt, _, _ = make_sni_probe("8.8.8.8", "example.com", ttl=5)
        self.assertEqual(pkt[IP].ttl, 5)

    def test_make_sni_packets_pair(self):
        p1, acc, p2, blocked = make_sni_packets(
            blocked_address="google.com", accessible_address="example.com")
        self.assertEqual(p1[TCP].dport, 443)
        self.assertEqual(p2[TCP].dport, 443)
        self.assertIn(b"example.com", bytes(p1[Raw].load))
        self.assertIn(b"google.com", bytes(p2[Raw].load))
        self.assertEqual(acc, "example.com")
        self.assertEqual(blocked, "google.com")

    def test_make_sni_packets_defaults(self):
        p1, _, p2, _ = make_sni_packets()
        self.assertIn(b"example.com", bytes(p1[Raw].load))
        self.assertIn(b"google.com", bytes(p2[Raw].load))


if __name__ == "__main__":
    unittest.main()
