import unittest

from utils.portpool import (
    DEFAULT_PORT_POOL,
    PortRandomizer,
    parse_port_pool,
)


class TestConstruction(unittest.TestCase):
    def test_default_pool_excludes_443(self):
        self.assertNotIn(443, DEFAULT_PORT_POOL)
        self.assertIn(80, DEFAULT_PORT_POOL)

    def test_empty_pool_rejected(self):
        with self.assertRaises(ValueError):
            PortRandomizer(ports=[])

    def test_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            PortRandomizer(ports=[80, 0])
        with self.assertRaises(ValueError):
            PortRandomizer(ports=[70000])


class TestNextPort(unittest.TestCase):
    def test_rotates_full_cycle(self):
        rz = PortRandomizer(ports=[80, 443, 8080], seed=7)
        seen = {rz.next_port() for _ in range(3)}
        self.assertEqual(seen, {80, 443, 8080})

    def test_seed_is_deterministic(self):
        a = PortRandomizer(ports=[80, 443, 8080, 8443], seed=42)
        b = PortRandomizer(ports=[80, 443, 8080, 8443], seed=42)
        self.assertEqual([a.next_port() for _ in range(4)], [b.next_port() for _ in range(4)])

    def test_single_port_pool(self):
        rz = PortRandomizer(ports=[2053])
        self.assertEqual(rz.next_port(), 2053)
        self.assertEqual(rz.next_port(), 2053)


class TestRstBackoff(unittest.TestCase):
    def test_threshold_triggers_cooling_off(self):
        rz = PortRandomizer(ports=[80, 443], rst_threshold=3, cooling_off_seconds=30, seed=1)
        self.assertFalse(rz.register_rst(443, now=0.0))
        self.assertFalse(rz.register_rst(443, now=0.0))
        self.assertTrue(rz.register_rst(443, now=0.0))   # 3rd -> cooling-off
        # 443 is now cooling; next_port must skip it
        for _ in range(3):
            self.assertNotEqual(rz.next_port(now=0.0), 443)

    def test_port_recovers_after_cooling(self):
        rz = PortRandomizer(ports=[80, 443], rst_threshold=1, cooling_off_seconds=30, seed=1)
        rz.register_rst(443, now=0.0)            # immediate cooling-off
        self.assertNotEqual(rz.next_port(now=0.0), 443)
        self.assertEqual(rz.next_port(now=31.0), 443)  # recovered

    def test_reset_rst_clears_cooling(self):
        rz = PortRandomizer(ports=[80, 443], rst_threshold=1, cooling_off_seconds=30, seed=1)
        rz.register_rst(443, now=0.0)
        rz.reset_rst(443)
        # 443 available again after explicit reset
        for _ in range(3):
            self.assertTrue(PortRandomizer(ports=[80, 443], seed=1).is_available(80))

    def test_all_cooling_off_returns_some_port(self):
        rz = PortRandomizer(ports=[80], rst_threshold=1, cooling_off_seconds=30, seed=1)
        rz.register_rst(80, now=0.0)
        # Only one port and it's cooling -> still returns it rather than stalling.
        self.assertEqual(rz.next_port(now=0.0), 80)


class TestParsePortPool(unittest.TestCase):
    def test_csv(self):
        self.assertEqual(parse_port_pool("80,8080,8443"), [80, 8080, 8443])

    def test_whitespace_tolerated(self):
        self.assertEqual(parse_port_pool(" 80 , 443 "), [80, 443])

    def test_list_input(self):
        self.assertEqual(parse_port_pool([80, 443]), [80, 443])

    def test_empty_falls_back_to_default(self):
        self.assertEqual(parse_port_pool(""), list(DEFAULT_PORT_POOL))
        self.assertEqual(parse_port_pool(None), list(DEFAULT_PORT_POOL))

    def test_invalid_rejected(self):
        with self.assertRaises(ValueError):
            parse_port_pool("80,99999")
        with self.assertRaises(ValueError):
            parse_port_pool("80,notaport")


if __name__ == "__main__":
    unittest.main()
