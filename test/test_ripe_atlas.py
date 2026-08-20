import json
import unittest
from unittest.mock import MagicMock, patch

import utils.ripe_atlas


class TestParseIdList(unittest.TestCase):
    """Tests for utils.ripe_atlas._parse_id_list."""

    def test_parse_string_single(self):
        self.assertEqual(utils.ripe_atlas._parse_id_list("12345"), [12345])

    def test_parse_string_multi(self):
        self.assertEqual(
            utils.ripe_atlas._parse_id_list("12345,67890"),
            [12345, 67890])

    def test_parse_string_with_spaces(self):
        self.assertEqual(
            utils.ripe_atlas._parse_id_list("12345, 67890 ,  1"),
            [12345, 67890, 1])

    def test_parse_list(self):
        self.assertEqual(
            utils.ripe_atlas._parse_id_list([123, 456]),
            [123, 456])

    def test_parse_int(self):
        self.assertEqual(utils.ripe_atlas._parse_id_list(42), [42])

    def test_parse_empty_string(self):
        self.assertEqual(utils.ripe_atlas._parse_id_list(""), [])

    def test_parse_none(self):
        self.assertEqual(utils.ripe_atlas._parse_id_list(None), [])


class TestDownloadMultiFromAtlas(unittest.TestCase):
    """Tests for download_multi_from_atlas."""

    def _setup_urlopen(self, mock_urlopen, raw_bytes):
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = raw_bytes
        mock_urlopen.return_value = mock_resp
        return mock_resp

    @patch('utils.ripe_atlas.json.dump')
    @patch('utils.ripe_atlas.json.loads')
    @patch('utils.ripe_atlas.urllib.request.urlopen')
    def test_basic_download(self, mock_urlopen, mock_loads, mock_dump):
        entry = {"src_addr": "1.2.3.4", "dst_addr": "5.6.7.8", "result": []}
        mock_loads.return_value = [entry]
        self._setup_urlopen(mock_urlopen, b'[]')
        result = utils.ripe_atlas.download_multi_from_atlas(
            probe_ids="1,2", output_dir="/tmp/",
            name_prefix="test", measurement_ids="5001")
        was_successful, _ = result
        self.assertTrue(was_successful)

    @patch('utils.ripe_atlas.json.dump')
    @patch('utils.ripe_atlas.urllib.request.urlopen')
    def test_vp_annotation(self, mock_urlopen, mock_dump):
        raw = b'[{"src_addr":"1.2.3.4","dst_addr":"5.6.7.8","result":[]}]'
        self._setup_urlopen(mock_urlopen, raw)
        captured = []
        mock_dump.side_effect = lambda *a, **kw: captured.append(a[0])
        utils.ripe_atlas.download_multi_from_atlas(
            probe_ids="100,200", output_dir="/tmp/",
            name_prefix="test-vp", measurement_ids="5001")
        saved = captured[0]
        self.assertIn("vp", saved[0])
        self.assertEqual(saved[0]["vp"], "100")
        self.assertEqual(saved[1]["vp"], "200")

    @patch('utils.ripe_atlas.sys.exit')
    @patch('utils.ripe_atlas.json.loads')
    @patch('utils.ripe_atlas.urllib.request.urlopen')
    def test_no_measurements_exits(self, mock_urlopen, mock_loads, mock_exit):
        self._setup_urlopen(mock_urlopen, b'[]')
        mock_loads.return_value = []
        utils.ripe_atlas.download_multi_from_atlas(
            probe_ids="1", output_dir="/tmp/",
            name_prefix="fail-test", measurement_ids="9999")
        mock_exit.assert_called_with(1)

    @patch('utils.ripe_atlas.json.dump')
    @patch('utils.ripe_atlas.urllib.request.urlopen')
    def test_multiple_probes_multiple_measurements(self, mock_urlopen, mock_dump):
        real_data = [
            [{"src_addr": "1.1.1.1", "dst_addr": "9.9.9.9", "result": []}],
            [{"src_addr": "2.2.2.2", "dst_addr": "9.9.9.9", "result": []}],
            [{"src_addr": "1.1.1.1", "dst_addr": "8.8.8.8", "result": []}],
            [{"src_addr": "2.2.2.2", "dst_addr": "8.8.8.8", "result": []}],
        ]
        call_count = [0]

        def mock_read():
            idx = call_count[0] % len(real_data)
            call_count[0] += 1
            return json.dumps(real_data[idx]).encode()

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.side_effect = mock_read
        mock_urlopen.return_value = mock_resp

        captured = []
        mock_dump.side_effect = lambda *a, **kw: captured.append(a[0])

        utils.ripe_atlas.download_multi_from_atlas(
            probe_ids="1,2", output_dir="/tmp/",
            name_prefix="multi", measurement_ids="5001,5004")

        saved = captured[0]
        self.assertEqual(len(saved), 4)
        vps = {e["vp"] for e in saved}
        self.assertEqual(vps, {"1", "2"})
        addrs = {e["src_addr"] for e in saved}
        self.assertEqual(addrs, {"1.1.1.1", "2.2.2.2"})


if __name__ == "__main__":
    unittest.main()
