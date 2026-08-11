import unittest

from utils.timing import TIMEOUT_PROFILES, adaptive_timeout, resolve_timeout


class TestResolveTimeout(unittest.TestCase):
    def test_explicit_overrides_profile(self):
        self.assertEqual(resolve_timeout(profile="shutdown", explicit=5), 5)

    def test_profile_mapping(self):
        self.assertEqual(resolve_timeout(profile="fast"), 1)
        self.assertEqual(resolve_timeout(profile="degraded"), 3)
        self.assertEqual(resolve_timeout(profile="shutdown"), 60)

    def test_default_is_fast(self):
        self.assertEqual(resolve_timeout(), 1)
        self.assertEqual(resolve_timeout(profile=None, explicit=None), 1)

    def test_unknown_profile_raises(self):
        with self.assertRaises(ValueError):
            resolve_timeout(profile="bogus")


class TestAdaptiveTimeout(unittest.TestCase):
    def test_no_rtt_returns_base(self):
        self.assertEqual(adaptive_timeout(1), 1)
        self.assertEqual(adaptive_timeout(3, last_rtt=0), 3)

    def test_scales_with_rtt(self):
        # last RTT 0.5s, scale 3 -> 1.5 grown -> int(1.5) handled via min/max
        self.assertEqual(adaptive_timeout(1, last_rtt=0.5, scale=3, cap=60), 2)

    def test_never_shrinks_below_base(self):
        # tiny RTT must not make the timeout smaller than the base.
        self.assertEqual(adaptive_timeout(5, last_rtt=0.001, scale=2), 5)

    def test_capped(self):
        self.assertEqual(adaptive_timeout(1, last_rtt=100, scale=3, cap=60, floor=1), 60)

    def test_floored(self):
        self.assertEqual(adaptive_timeout(0, last_rtt=100, scale=3, cap=60, floor=4), 60)
        self.assertGreaterEqual(adaptive_timeout(0, last_rtt=0.001, scale=1, cap=60, floor=2), 2)

    def test_profiles_constant_keys(self):
        self.assertEqual(set(TIMEOUT_PROFILES), {"fast", "degraded", "shutdown"})


if __name__ == "__main__":
    unittest.main()
