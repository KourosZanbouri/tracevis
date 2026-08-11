import unittest

from scapy.all import DNS, DNSQR, IP, TCP, UDP

from utils import dns


class TestResolverFiltering(unittest.TestCase):
    def test_drops_blackhole(self):
        self.assertEqual(dns.filter_blackholed(["1.1.1.1", dns.BLACKHOLE_ADDR, "8.8.8.8"]),
                         ["1.1.1.1", "8.8.8.8"])

    def test_keeps_all_when_clean(self):
        self.assertEqual(dns.filter_blackholed(["1.1.1.1", "8.8.8.8"]), ["1.1.1.1", "8.8.8.8"])

    def test_empty(self):
        self.assertEqual(dns.filter_blackholed([]), [])

    def test_blackhole_constant_matches_report(self):
        # report section 4.1
        self.assertEqual(dns.BLACKHOLE_ADDR, "10.10.34.34")


class TestDefaultTargetPool(unittest.TestCase):
    """The pool is a comparison, not a list of resolvers that ought to work.

    Backlog §1.3. The temptation was to delete the destinations that
    measurement found unreachable, which would have left a pool where everything
    answers — unfalsifiable by construction, and it would have destroyed the
    contrast that made the rate-vs-allowlist result readable in the first place.
    """

    POOLS = ("DEFAULT_DNS_RESOLVERS", "DOT_RESOLVERS", "DNSTT_RESOLVERS")

    def pools(self):
        return [(name, getattr(dns, name)) for name in self.POOLS]

    def test_every_pool_pairs_a_control_with_a_treatment(self):
        for name, pool in self.pools():
            self.assertIn(dns.RESOLVER_CONTROL, pool, name)
            self.assertIn(dns.RESOLVER_TREATMENT, pool, name)

    def test_the_same_operator_control_is_present(self):
        """1.0.0.1 is Cloudflare like 1.1.1.1 and behaved differently on 2053,
        which is what separates a per-IP allowlist from a per-operator one."""
        for name, pool in self.pools():
            self.assertIn(dns.RESOLVER_SAME_OPERATOR_CONTROL, pool, name)

    def test_no_default_target_is_ever_filtered_out(self):
        """The check that had to happen before any of this was worth changing.

        `filter_blackholed` runs over the pool at trace time. If it dropped the
        treatment, runs would silently probe only destinations known to work.
        It cannot: it compares against a literal a pool of literals never holds.
        """
        for name, pool in self.pools():
            self.assertEqual(dns.filter_blackholed(pool), pool, name)

    def test_the_pools_are_independent_objects(self):
        """Aliasing would let one mode's edit silently retarget the others."""
        objects = [dns.DEFAULT_TARGETS] + [pool for _, pool in self.pools()]
        self.assertEqual(len({id(pool) for pool in objects}), len(objects))

    def test_every_target_carries_a_documented_role(self):
        for name, pool in self.pools():
            for target in pool:
                self.assertIn(target, dns.TARGET_ROLES, f"{name}: {target}")

    def test_describe_targets_labels_each_role(self):
        described = dns.describe_targets(dns.DEFAULT_TARGETS)
        self.assertIn("1.1.1.1 (control)", described)
        self.assertIn("8.8.8.8 (treatment)", described)

    def test_describe_targets_passes_through_unknown_addresses(self):
        """`-i` replaces the pool, and a user's own targets have no roles."""
        self.assertEqual(dns.describe_targets(["203.0.113.9"]), "203.0.113.9")


class TestBuildDnsQuery(unittest.TestCase):
    def test_udp_shape(self):
        pkt = dns.build_dns_query("1.1.1.1", "www.example.com", proto="udp", dport=53)
        self.assertEqual(pkt[IP].dst, "1.1.1.1")
        self.assertEqual(pkt[IP].ttl, 1)
        self.assertIn(UDP, pkt)
        self.assertEqual(pkt[UDP].dport, 53)
        self.assertEqual(pkt[UDP].sport, 53)
        self.assertIn(DNS, pkt)
        # scapy stores qname as FQDN (trailing dot); strip for comparison.
        self.assertEqual(pkt[DNSQR].qname.strip(b"."), b"www.example.com")

    def test_tcp_shape(self):
        pkt = dns.build_dns_query("1.1.1.1", "www.example.com", proto="tcp", dport=853)
        self.assertIn(TCP, pkt)
        self.assertEqual(pkt[TCP].dport, 853)
        self.assertEqual(pkt[IP].ttl, 1)

    def test_query_id_and_ttl_preserved(self):
        pkt = dns.build_dns_query("9.9.9.9", "www.twitter.com")
        self.assertEqual(pkt[IP].id, 1)
        self.assertEqual(pkt[IP].ttl, 1)


class TestDnsPacketBuilders(unittest.TestCase):
    def test_get_dns_packets_shape(self):
        p1, addr1, p2, addr2 = dns.get_dns_packets(dns_over_tcp=False)
        self.assertEqual(addr1, dns.ACCESSIBLE_ADDRESS)
        self.assertEqual(addr2, dns.DEFAULT_BLOCKED_ADDRESS)
        self.assertEqual(p1[IP].dst, dns.DEFAULT_DNS_RESOLVERS[0])
        self.assertIn(UDP, p1)
        self.assertIn(DNSQR, p2)

    def test_get_dns_packets_tcp(self):
        p1, _, p2, _ = dns.get_dns_packets(dns_over_tcp=True)
        self.assertIn(TCP, p1)
        self.assertIn(TCP, p2)

    def test_get_dot_packets(self):
        p1, addr1, p2, _addr2 = dns.get_dot_packets()
        self.assertIn(TCP, p1)
        self.assertEqual(p1[TCP].dport, 853)
        self.assertEqual(p1[IP].dst, dns.DOT_RESOLVERS[0])
        self.assertEqual(p2[UDP].dport if p2.haslayer(UDP) else p2[TCP].dport, 853)
        self.assertEqual(addr1, dns.ACCESSIBLE_ADDRESS)

    def test_get_dnstt_packets(self):
        p1, addr1, _p2, addr2 = dns.get_dnstt_packets()
        self.assertIn(UDP, p1)
        self.assertEqual(p1[UDP].dport, 53)
        self.assertEqual(p1[IP].dst, dns.DNSTT_RESOLVERS[0])
        self.assertEqual(addr2, dns.DEFAULT_BLOCKED_ADDRESS)
        self.assertEqual(addr1, dns.ACCESSIBLE_ADDRESS)

    def test_default_domains(self):
        # when not supplied, accessible=twitter-blocked pair uses the constants
        _, a1, _, a2 = dns.get_dnstt_packets()
        self.assertEqual(a1, dns.ACCESSIBLE_ADDRESS)    # example.com
        self.assertEqual(a2, dns.DEFAULT_BLOCKED_ADDRESS)  # twitter.com


if __name__ == "__main__":
    unittest.main()
