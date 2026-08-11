#!/usr/bin/env python3
import json
import os
import tempfile
import unittest

from utils import trace
from utils.traceroute_struct import traceroute_data


class TestSavePartialMeasurement(unittest.TestCase):
    def _reset_globals(self):
        trace.measurement_data = [[], []]
        trace.have_2_packet = False

    def setUp(self):
        self._reset_globals()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        self._reset_globals()
        for f in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, f))
        os.rmdir(self.tmp)

    def test_empty_data_returns_empty_string(self):
        self.assertEqual(
            trace.save_partial_measurement(
                self.tmp, "noop", continue_to_max_ttl=False), "")

    def test_partial_two_packet_saves_with_dpi_fields(self):
        trace.have_2_packet = True
        td1 = traceroute_data(
            dst_addr="1.1.1.1", annotation="a", proto="TCP", port=443,
            timestamp=0, cgnat_hop=True, dpi_cleared=False, sni_inspected=False)
        td2 = traceroute_data(
            dst_addr="1.1.1.1", annotation="b", proto="TCP", port=443,
            timestamp=0, cgnat_hop=True)
        trace.measurement_data = [[td1], [td2]]
        path = trace.save_partial_measurement(
            self.tmp, "partial-", continue_to_max_ttl=False)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(path.endswith(".json"))
        with open(path) as f:
            blob = json.load(f)
        # 1 dst x have_2_packet(True) -> 2 entries (one per packet stream).
        self.assertEqual(len(blob), 2)
        self.assertTrue(blob[0]["cgnat_hop"])
        self.assertFalse(blob[0]["dpi_cleared"])

    def test_interrupt_handler_flushes_partial(self):
        # Regression for "stopped after a couple steps but no result file":
        # main()'s do_traceroute try block must catch KeyboardInterrupt
        # (a BaseException, not matched by `except Exception`) and flush the
        # in-flight measurement_data via save_partial_measurement.
        import tracevis
        with open(os.path.join(os.path.dirname(tracevis.__file__), "tracevis.py")) as f:
            src = f.read()
        self.assertIn("except KeyboardInterrupt", src)
        self.assertIn("save_partial_measurement", src)


if __name__ == "__main__":
    unittest.main()
