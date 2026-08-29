import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import utils.ioda
import utils.vis


class TestIodaStatus(unittest.TestCase):
    """Tests for utils.ioda.fetch_ioda_status and helpers."""

    def test_defaults(self):
        status = utils.ioda.fetch_ioda_status("IR")
        self.assertIn("country", status)
        self.assertEqual(status["country"], "IR")
        self.assertIn("available", status)
        self.assertIn("outage", status)
        self.assertIn("latest_value", status)

    @patch('utils.ioda.urllib.request.urlopen')
    def test_successful_fetch(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "country": "IR",
            "data_files": [
                {"date": "2024-01-15"},
                {"date": "2024-01-14"},
            ]
        }).encode()
        mock_urlopen.return_value = mock_resp
        status = utils.ioda.fetch_ioda_status("IR")
        self.assertTrue(status["available"])
        self.assertEqual(status["latest_date"], "2024-01-15")
        self.assertEqual(len(status["data_files"]), 2)
        self.assertIsNone(status["error"])

    @patch('utils.ioda.urllib.request.urlopen')
    def test_fetch_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("timed out")
        status = utils.ioda.fetch_ioda_status("IR", timeout=1)
        self.assertFalse(status["available"])
        self.assertIn("error", status)
        self.assertIsNotNone(status["error"])

    @patch('utils.ioda.urllib.request.urlopen')
    def test_fetch_http_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 404, "Not Found", {}, None)
        status = utils.ioda.fetch_ioda_status("XX")
        self.assertFalse(status["available"])
        self.assertIn("error", status)

    def test_parse_ioda_index_dict(self):
        data = {"data_files": [{"date": "2024-03-01"}, {"date": "2024-02-28"}]}
        result = utils.ioda._parse_ioda_index(data)
        self.assertEqual(result["latest_date"], "2024-03-01")
        self.assertEqual(len(result["data_files"]), 2)

    def test_parse_ioda_index_files_key(self):
        data = {"files": [{"date": "2024-03-01"}, {"date": "2024-02-28"}]}
        result = utils.ioda._parse_ioda_index(data)
        self.assertEqual(result["latest_date"], "2024-03-01")

    def test_parse_ioda_index_list(self):
        data = [{"date": "2024-03-01"}, {"date": "2024-02-28"}]
        result = utils.ioda._parse_ioda_index(data)
        self.assertEqual(result["latest_date"], "2024-03-01")

    def test_parse_ioda_index_empty(self):
        result = utils.ioda._parse_ioda_index({})
        self.assertIsNone(result["latest_date"])
        self.assertEqual(result["data_files"], [])

    def test_parse_ioda_index_mixed_types(self):
        data = {"data_files": [{"date": "2024-01-01"}, "2024-01-02"]}
        result = utils.ioda._parse_ioda_index(data)
        self.assertEqual(result["latest_date"], "2024-01-02")

    def test_coerce_float_int(self):
        self.assertEqual(utils.ioda._coerce_float(5), 5.0)

    def test_coerce_float_float(self):
        self.assertEqual(utils.ioda._coerce_float(0.75), 0.75)

    def test_coerce_float_dict(self):
        self.assertEqual(utils.ioda._coerce_float({"value": 0.8}), 0.8)

    def test_coerce_float_dict_val_key(self):
        self.assertEqual(utils.ioda._coerce_float({"val": 0.3}), 0.3)

    def test_coerce_float_none(self):
        self.assertEqual(utils.ioda._coerce_float("not a number"), 0.0)

    def test_coerce_float_empty_dict(self):
        self.assertEqual(utils.ioda._coerce_float({}), 0.0)


class TestIodaOutage(unittest.TestCase):
    """Tests for fetch_ioda_outage."""

    def test_returns_status_dict(self):
        status = utils.ioda.fetch_ioda_outage("IR", target_date="2024-01-15")
        self.assertIn("country", status)
        self.assertEqual(status["country"], "IR")
        self.assertIn("available", status)
        self.assertIn("outage", status)
        self.assertIn("error", status)

    def test_unavailable_returns_no_outage(self):
        status = utils.ioda.fetch_ioda_outage("ZZ", target_date="2099-01-01")
        self.assertFalse(status["available"])
        self.assertFalse(status["outage"])

    @patch('utils.ioda.urllib.request.urlopen')
    def test_outage_detected(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "data_files": [{"date": "2024-01-15"}]
        }).encode()
        mock_urlopen.return_value = mock_resp

        with patch('utils.ioda._fetch_daily_outage') as mock_daily:
            mock_daily.return_value = [0.3, 0.6, 0.8]
            status = utils.ioda.fetch_ioda_outage("IR", target_date="2024-01-15")
            self.assertTrue(status["available"])
            self.assertTrue(status["outage"])
            self.assertEqual(status["latest_value"], 0.8)
            self.assertEqual(status["latest_date"], "2024-01-15")

    @patch('utils.ioda.urllib.request.urlopen')
    def test_no_outage_when_values_low(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({
            "data_files": [{"date": "2024-01-15"}]
        }).encode()
        mock_urlopen.return_value = mock_resp

        with patch('utils.ioda._fetch_daily_outage') as mock_daily:
            mock_daily.return_value = [0.1, 0.2, 0.3]
            status = utils.ioda.fetch_ioda_outage("IR", target_date="2024-01-15")
            self.assertFalse(status["outage"])
            self.assertEqual(status["latest_value"], 0.3)


class TestIodaUrlFormat(unittest.TestCase):
    """Tests for URL construction."""

    def test_default_url_format(self):
        url = utils.ioda._default_url("IR")
        self.assertIn("ioda.caida.org", url)
        self.assertIn("IR", url)
        self.assertIn("/index.json", url)

    def test_url_uppercases_country(self):
        url = utils.ioda._default_url("ir")
        self.assertIn("IR", url)


if __name__ == "__main__":
    unittest.main()


class TestAnnotateMeasurements(unittest.TestCase):
    """The IODA cross-check never reached the graph.

    tracevis.py fetched the status and printed it to the terminal; nothing
    wrote measurement["ioda_status"], which is the key utils.vis reads to
    render the IODA tooltip line. Zero saved captures carried it.
    """

    def _capture(self, measurements=None):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "m.json")
        if measurements is None:
            measurements = [{"dst_addr": "1.1.1.1", "vp": "1"},
                            {"dst_addr": "1.1.1.1", "vp": "2"}]
        with open(path, "w") as handle:
            json.dump(measurements, handle)
        self.addCleanup(lambda: (os.remove(path), os.rmdir(directory)))
        return path

    @staticmethod
    def _status(**over):
        status = {"country": "IR", "available": True, "outage": True,
                  "latest_value": 0.85, "latest_date": "2026-08-29"}
        status.update(over)
        return status

    def test_writes_the_key_every_measurement(self):
        path = self._capture()
        self.assertEqual(
            utils.ioda.annotate_measurements(path, self._status()), 2)
        with open(path) as handle:
            written = json.load(handle)
        self.assertTrue(all("ioda_status" in m for m in written))
        self.assertEqual(written[0]["ioda_status"]["country"], "IR")
        self.assertTrue(written[0]["ioda_status"]["outage"])

    def test_records_a_clean_country_too(self):
        """No outage is a finding; it should still be recorded."""
        path = self._capture()
        self.assertEqual(
            utils.ioda.annotate_measurements(
                path, self._status(outage=False, latest_value=1.0)), 2)
        with open(path) as handle:
            self.assertFalse(json.load(handle)[0]["ioda_status"]["outage"])

    def test_unavailable_status_is_not_recorded(self):
        path = self._capture()
        self.assertEqual(
            utils.ioda.annotate_measurements(
                path, {"country": "IR", "available": False,
                       "error": "timeout"}), 0)
        with open(path) as handle:
            self.assertNotIn("ioda_status", json.load(handle)[0])

    def test_missing_status_is_not_recorded(self):
        self.assertEqual(
            utils.ioda.annotate_measurements(self._capture(), None), 0)

    def test_missing_file_does_not_raise(self):
        self.assertEqual(
            utils.ioda.annotate_measurements("/nonexistent/x.json",
                                             self._status()), 0)

    def test_unparseable_file_does_not_raise(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            handle.write("not json")
        self.addCleanup(lambda: (os.remove(path), os.rmdir(directory)))
        self.assertEqual(
            utils.ioda.annotate_measurements(path, self._status()), 0)

    def test_non_list_payload_is_ignored(self):
        path = self._capture(measurements={"dst_addr": "1.1.1.1"})
        self.assertEqual(
            utils.ioda.annotate_measurements(path, self._status()), 0)

    def test_each_measurement_gets_its_own_dict(self):
        """A shared dict would let one edit leak across measurements."""
        path = self._capture()
        utils.ioda.annotate_measurements(path, self._status())
        with open(path) as handle:
            written = json.load(handle)
        written[0]["ioda_status"]["country"] = "XX"
        self.assertEqual(written[1]["ioda_status"]["country"], "IR")


class TestAnnotationReachesTheGraph(unittest.TestCase):
    """End to end: annotate a capture, render it, find IODA in the tooltip."""

    def test_ioda_line_appears_in_the_rendered_tooltip(self):
        from test.test_vis import make_measurement
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump([make_measurement(vp="1001")], handle)
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))

        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable="none")
        before = [d.get("title", "") for _, _, d
                  in utils.vis.multi_directed_graph.edges(data=True)
                  if "IODA" in d.get("title", "")]
        self.assertEqual(before, [], "nothing should carry IODA before wiring")

        utils.ioda.annotate_measurements(
            path, {"country": "IR", "available": True, "outage": True,
                   "latest_value": 0.85, "latest_date": "2026-08-29"})
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(measurement_path=path, attach_jscss=False,
                          edge_lable="none")
        after = [d.get("title", "") for _, _, d
                 in utils.vis.multi_directed_graph.edges(data=True)
                 if "IODA[IR]" in d.get("title", "")]
        self.assertTrue(after)
        self.assertIn("outage (value=0.85)", after[0])
