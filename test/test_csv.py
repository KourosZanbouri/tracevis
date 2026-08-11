"""CSV export — a converter with module-level state and no coverage.

Found during the M7 audit, and the same defect class as `utils.vis`'s
accumulating graph: the header/row templates are module-level and were appended
to rather than reset, so a second conversion in one process wrote a duplicate
header into the middle of the file. Silent, because line 1 still looks right.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import utils.csv

HEADER_START = "destination_address"

MEASUREMENT = {
    "af": 4, "dst_addr": "1.1.1.1", "annotation": "www.example.com",
    "proto": "UDP", "port": 53, "src_addr": "127.1.2.7",
    "from_ip": "127.1.2.7", "timestamp": 0, "endtime": 1, "size": 61,
    "dst_name": "", "lts": -1, "msm_id": -1, "msm_name": "traceroute",
    "paris_id": 0, "prb_id": -1, "ttr": -1,
    "result": [
        {"hop": 1, "result": [{"from": "192.168.1.1", "rtt": 1.5, "size": 89,
                               "ttl": 64, "summary": "hop one"}]},
        {"hop": 2, "result": [{"x": "*"}]},
    ],
}


class CsvTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.remove(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    @staticmethod
    def data_rows(lines):
        """Rows carrying data. `data_to_csv` inserts a blank separator row
        between hop groups when sorting, which is deliberate formatting."""
        return [line for line in lines[1:]
                if line.strip(",") and not line.startswith(HEADER_START)]

    def convert(self, payload, name="m", raw=None, **kwargs):
        path = os.path.join(self.directory, name + ".json")
        with open(path, "w") as handle:
            handle.write(raw if raw is not None else json.dumps(payload))
        with redirect_stdout(io.StringIO()) as out:
            utils.csv.json2csv(path, **kwargs)
        csv_path = path.replace(".json", ".csv")
        if not os.path.exists(csv_path):
            return None, out.getvalue()
        with open(csv_path) as handle:
            return handle.read().splitlines(), out.getvalue()


class TestRepeatedConversion(CsvTestCase):
    def test_one_header_row_however_many_conversions(self):
        for run in range(3):
            lines, _ = self.convert([MEASUREMENT], name=f"m{run}")
            headers = [line for line in lines if line.startswith(HEADER_START)]
            self.assertEqual(len(headers), 1, f"conversion {run + 1}")

    def test_the_row_width_does_not_grow(self):
        widths = []
        for run in range(3):
            lines, _ = self.convert([MEASUREMENT], name=f"m{run}")
            widths.append(lines[0].count(","))
        self.assertEqual(len(set(widths)), 1, widths)

    def test_the_data_rows_are_unchanged_between_runs(self):
        first, _ = self.convert([MEASUREMENT], name="a")
        second, _ = self.convert([MEASUREMENT], name="b")
        self.assertEqual(first, second)


class TestEmptyAndInvalidInput(CsvTestCase):
    """`data[0]` raised IndexError on both, *after* `parse_json` had already
    printed a tidy explanation of the problem."""

    def test_a_file_with_no_measurements_is_reported(self):
        lines, out = self.convert([])
        self.assertIsNone(lines)
        self.assertIn("no measurements", out)

    def test_invalid_json_is_reported(self):
        lines, out = self.convert(None, raw="{not json")
        self.assertIsNone(lines)
        self.assertIn("not valid", out)

    def test_a_missing_file_is_a_no_op(self):
        with redirect_stdout(io.StringIO()):
            utils.csv.json2csv(os.path.join(self.directory, "absent.json"))


def measurement_with(repeats, hop_repeats=None):
    """A measurement whose hops carry `repeats` responses each."""
    def responses(count):
        return [{"from": f"10.0.0.{i + 1}", "rtt": 1.0 + i, "size": 89,
                 "ttl": 64, "summary": f"r{i}"} for i in range(count)]
    counts = hop_repeats or [repeats, repeats]
    return dict(MEASUREMENT, result=[
        {"hop": n + 1, "result": responses(c)} for n, c in enumerate(counts)])


class TestRepeatCount(CsvTestCase):
    """The column count was hardcoded at three, so `-r 1` and `-r 2` raised
    IndexError — and `tracevis.py` does not catch it, so `--csv` ended in a raw
    traceback. Most of `samples/` sets `repeat: 1`, and so does every run that
    prefers breadth over repetition."""

    def test_every_repeat_count_converts(self):
        for repeats in (1, 2, 3, 5):
            lines, _ = self.convert([measurement_with(repeats)], name=f"r{repeats}")
            self.assertIsNotNone(lines, repeats)
            self.assertEqual(len(self.data_rows(lines)), 2, repeats)

    def test_the_width_follows_the_data(self):
        for repeats in (1, 2, 3):
            lines, _ = self.convert([measurement_with(repeats)], name=f"w{repeats}")
            header = lines[0]
            self.assertIn(f"response_from_{repeats},", header)
            self.assertNotIn(f"response_from_{repeats + 1},", header)

    def test_column_order_is_unchanged(self):
        """response_from/rtt/ttl grouped per repeat, summaries last — anyone's
        existing spreadsheet is keyed on it."""
        lines, _ = self.convert([measurement_with(2)])
        self.assertEqual(
            lines[0].rstrip(","),
            "destination_address,protocol,annotation,hop,"
            "response_from_1,rtt_1,ttl_1,response_from_2,rtt_2,ttl_2,"
            "summary_1,summary_2")

    def test_uneven_hops_are_padded_to_the_widest(self):
        """A hop that answered fewer times than another must still line up."""
        lines, _ = self.convert([measurement_with(0, hop_repeats=[3, 1])])
        self.assertEqual(len({line.count(",") for line in lines}), 1)
        short = self.data_rows(lines)[1]
        self.assertEqual(short.count(utils.csv.BLANK), 8)


class TestContent(CsvTestCase):
    def test_hops_and_stars_both_appear(self):
        lines, _ = self.convert([MEASUREMENT])
        body = "\n".join(lines[1:])
        self.assertIn("192.168.1.1", body)
        self.assertIn("1.1.1.1", body)
        self.assertIn("*", body)

    def test_the_annotation_identifies_the_probe(self):
        """Two arms of an A/B differ only by annotation in the CSV."""
        lines, _ = self.convert([MEASUREMENT])
        self.assertIn("www.example.com", "\n".join(lines))

    def test_a_measurement_without_an_annotation_still_converts(self):
        bare = {k: v for k, v in MEASUREMENT.items() if k != "annotation"}
        lines, _ = self.convert([bare])
        self.assertTrue(any(line.startswith("1.1.1.1") for line in lines[1:]))


if __name__ == "__main__":
    unittest.main()
