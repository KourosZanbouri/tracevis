"""Backlog §2.8 — keeping the operator out of a shared capture.

Field captures carried the operator's local address in `src_addr` and in every
stored packet blob, and nine committed samples carried a real LAN address, so
these pin both halves: what is removed unconditionally, and what only
`--anonymize` removes.
"""
import unittest

from scapy.all import IP

from utils import anonymize


def recomputed_chksum(packet, layer=IP):
    """The checksum this packet *should* carry, computed from its own bytes.

    Not `IP(bytes(packet)).chksum` — rebuilding a packet that already holds a
    concrete checksum keeps it, so that comparison is true whatever the field
    says. Only clearing the field first makes scapy recompute.
    """
    probe = packet.copy()
    del probe[layer].chksum
    return IP(bytes(probe))[layer].chksum


class _Entry:
    """Stand-in for the parts of `traceroute_data` the scrubber touches."""

    def __init__(self, src_addr="192.168.1.5", hops=()):
        self.src_addr = src_addr
        self.result = [
            {"hop": i + 1, "result": [hop]} for i, hop in enumerate(hops)]


def hop(from_ip, summary="", sent_src="192.168.1.5"):
    return {
        "from": from_ip,
        "summary": summary or f"IP / ICMP {from_ip} > 192.168.1.5 time-exceeded",
        "packets": {"sent": {"IP": {"src": sent_src, "dst": "1.1.1.1"}}},
    }


class TestPrivateHopDetection(unittest.TestCase):
    def test_rfc1918_is_private(self):
        for address in ("10.0.0.1", "172.16.4.43", "192.168.1.1",
                        "172.31.255.255"):
            self.assertTrue(anonymize.is_private_hop(address), address)

    def test_cgnat_is_not_treated_as_private(self):
        """RFC 6598 is the carrier's, not the operator's — and `utils.dpi`
        reads it back out of the saved hops to set `cgnat_hop`. Scrubbing it
        would silently disable a detector that took field measurement to justify."""
        self.assertFalse(anonymize.is_private_hop("100.76.0.1"))

    def test_public_and_boundary_addresses_are_not_private(self):
        for address in ("1.1.1.1", "172.15.0.1", "172.32.0.1", "9.255.255.255",
                        "11.0.0.1", "192.167.1.1", "192.169.1.1"):
            self.assertFalse(anonymize.is_private_hop(address), address)

    def test_non_addresses_are_not_private(self):
        for value in ("***", "", None, "not-an-ip"):
            self.assertFalse(anonymize.is_private_hop(value), repr(value))


class TestSourceScrubIsUnconditional(unittest.TestCase):
    def test_the_source_goes_from_every_string_not_just_src_addr(self):
        """It appears in `src_addr`, in each hop's `summary`, and again inside
        the `packets` blob. A field-by-field scrub is one new key away from
        leaking again, so the walk is generic."""
        entry = _Entry(hops=[hop("192.168.1.1")])
        anonymize.scrub([entry], source_ip="192.168.1.5")
        blob = str(entry.__dict__)
        self.assertNotIn("192.168.1.5", blob)
        self.assertEqual(entry.src_addr, anonymize.SENTINEL_SOURCE)
        self.assertIn(anonymize.SENTINEL_SOURCE, entry.result[0]["result"][0]["summary"])

    def test_hops_survive_without_the_flag(self):
        entry = _Entry(hops=[hop("192.168.1.1"), hop("100.76.0.1")])
        anonymize.scrub([entry], source_ip="192.168.1.5")
        kept = [h["result"][0]["from"] for h in entry.result]
        self.assertEqual(kept, ["192.168.1.1", "100.76.0.1"])

    def test_a_longer_address_is_not_corrupted_by_the_substitution(self):
        """Naive replacement turns 192.168.1.50 into 127.1.2.70."""
        entry = _Entry(src_addr="192.168.1.50", hops=[hop("192.168.1.50")])
        anonymize.scrub([entry], source_ip="192.168.1.5")
        self.assertEqual(entry.src_addr, "192.168.1.50")

    def test_nothing_to_do_is_a_no_op(self):
        entry = _Entry(src_addr=anonymize.SENTINEL_SOURCE, hops=[hop("1.1.1.1")])
        self.assertEqual(anonymize.scrub([entry], source_ip=""), {})


class TestPseudonymisation(unittest.TestCase):
    def test_private_hops_are_replaced_only_with_the_flag(self):
        entry = _Entry(hops=[hop("192.168.1.1"), hop("172.16.4.43")])
        anonymize.scrub([entry], source_ip="192.168.1.5", pseudonymise=True)
        replaced = [h["result"][0]["from"] for h in entry.result]
        for address in replaced:
            self.assertTrue(address.startswith("192.0.2."), address)
        self.assertEqual(len(set(replaced)), 2)

    def test_cgnat_and_public_hops_are_kept_under_the_flag(self):
        entry = _Entry(hops=[hop("100.76.0.1"), hop("1.1.1.1")])
        anonymize.scrub([entry], source_ip="192.168.1.5", pseudonymise=True)
        kept = [h["result"][0]["from"] for h in entry.result]
        self.assertEqual(kept, ["100.76.0.1", "1.1.1.1"])

    def test_one_box_keeps_one_pseudonym_across_arms_and_repeats(self):
        """The graph merges nodes by address: two names for one hop turns a
        single box into two, changing the shape of what is being measured."""
        entries = [_Entry(hops=[hop("192.168.1.1")]) for _ in range(3)]
        anonymize.scrub(entries, source_ip="192.168.1.5", pseudonymise=True)
        seen = {e.result[0]["result"][0]["from"] for e in entries}
        self.assertEqual(len(seen), 1)

    def test_substitutes_stay_parseable_ipv4(self):
        """`utils/vis.py` builds node ids through `ipaddress.IPv4Address`, so a
        placeholder like "redacted" would raise at render time."""
        import ipaddress
        alias = anonymize.Pseudonymiser()
        ipaddress.IPv4Address(alias("10.0.0.1"))

    def test_the_same_address_always_gets_the_same_pseudonym(self):
        """The class's whole contract. `build_replacements` happens to ask once
        per address today, so nothing else would notice if the memo broke."""
        alias = anonymize.Pseudonymiser()
        first = alias("10.0.0.1")
        alias("10.0.0.2")
        self.assertEqual(alias("10.0.0.1"), first)

    def test_the_pool_does_not_raise_when_exhausted(self):
        """254 private hops is not a real trace, but raising here would lose a
        completed measurement at save time."""
        alias = anonymize.Pseudonymiser()
        for i in range(300):
            self.assertTrue(alias(f"10.0.{i // 256}.{i % 256}"))

    def test_the_replacement_map_is_returned_for_reporting(self):
        entry = _Entry(hops=[hop("192.168.1.1")])
        mapping = anonymize.scrub(
            [entry], source_ip="192.168.1.5", pseudonymise=True)
        self.assertEqual(mapping["192.168.1.5"], anonymize.SENTINEL_SOURCE)
        self.assertIn("192.168.1.1", mapping)


class TestConfigDumpSeam(unittest.TestCase):
    """How LAN addresses reached `samples/` in the first place.

    Every run writes a `.conf` beside its `.json` containing the packet exactly
    as sent — hexdump and all — and those configs are what people share and what
    the committed samples were made from. `_read_pasted_packet` applied the
    sentinel; the JSON input path did not, so nine samples shipped with a real
    `192.168.*` source.
    """

    @staticmethod
    def _decode(entry):
        import base64
        import binascii
        import re

        from scapy.all import IP
        text = base64.b64decode(entry["hex"][4:]).decode("utf8", "replace")
        raw = b""
        for line in text.splitlines():
            m = re.match(r'^\s*[0-9A-Fa-f]{4}\s+((?:[0-9A-Fa-f]{2} ?)+)', line)
            if m:
                raw += binascii.unhexlify(m.group(1).replace(" ", ""))
        return IP(raw)

    def _dumped(self):
        from scapy.all import IP, TCP

        from utils.packet_input import InputPacketInfo
        # Round-tripped through bytes on purpose: that is how a real stored
        # packet arrives, and it is the only way `chksum` holds a concrete value
        # for the *old* source. A freshly constructed packet leaves the field
        # None, so scapy recomputes it at build time and a missing recompute in
        # `_dump` would be invisible here.
        packet = IP(bytes(IP(src="192.168.1.9", dst="1.1.1.1")
                          / TCP(dport=443) / b"hi"))
        info = InputPacketInfo(packet, None, False, False, False)
        return packet, info.as_dict()

    def test_the_dumped_packet_carries_the_sentinel(self):
        _, dumped = self._dumped()
        self.assertEqual(
            self._decode(dumped["packet1"]).src, anonymize.SENTINEL_SOURCE)

    def test_the_dumped_checksums_match_the_rewritten_address(self):
        """Both layers — the L4 checksum covers an IP pseudo-header."""
        from scapy.all import TCP
        _, dumped = self._dumped()
        packet = self._decode(dumped["packet1"])
        for layer in (IP, TCP):
            self.assertEqual(recomputed_chksum(packet, layer),
                             packet[layer].chksum, layer.__name__)

    def test_the_live_packet_is_not_mutated(self):
        """The dump is a copy: the packet about to be traced keeps whatever the
        caller built, and `send_packet` overwrites `IP.src` regardless."""
        packet, _ = self._dumped()
        self.assertEqual(packet.src, "192.168.1.9")

    def test_the_payload_survives_the_rewrite(self):
        _, dumped = self._dumped()
        self.assertEqual(bytes(self._decode(dumped["packet1"]).payload.payload),
                         b"hi")


if __name__ == "__main__":
    unittest.main()
