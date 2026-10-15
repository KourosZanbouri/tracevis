"""IODA outage cross-check (backlog §2.2, rewritten for §3.2).

The previous suite mocked a schema no IODA endpoint serves, so 30 tests passed
while the feature never fetched anything. These run against responses recorded
from the real v2 API (`test/fixtures/ioda_events_*.json`, fetched 2026-10-15):

- `ir_20260120`: three events overlapping 20 Jan 2026, twelve days into the
  January shutdown. No *alert* fires anywhere near that date, which is why the
  module reads events.
- `ir_20260820`: a trace's ten minutes on 20 Aug 2026. Two outages overlap it,
  begun on 8 Jan and 8 Mar. A 14- or 90-day lookback finds neither.
- `ir_20261005`: two short BGP events on 5 Oct, on top of the long ones.
- `ir_20261010`: the long outages, still open in October.
- `is_20261010_empty`: a country with no outage at all.

All were fetched with the parameters the module sends (`extendWindow` = 1 year).

One opt-in test hits the live API: `TRACEVIS_LIVE_TESTS=1`.
"""
import json
import os
import tempfile
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import utils.ioda

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
JAN_20 = (1768867200, 1768953600)          # 2026-01-20 00:00 .. 01-21 00:00 UTC
OCT_10 = (1791590400, 1791676800)          # 2026-10-10 00:00 .. 10-11 00:00 UTC


def fixture(name):
    with open(os.path.join(FIXTURES, f"ioda_events_{name}.json"), "rb") as handle:
        return handle.read()


def response(body):
    resp = MagicMock()
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = body
    return resp


class TestParseEvents(unittest.TestCase):
    def test_reads_the_recorded_shutdown_events(self):
        events = utils.ioda.parse_events(json.loads(fixture("ir_20260120")))
        self.assertEqual(
            sorted(e["datasource"] for e in events),
            ["gtr", "merit-nt", "ping-slash24"])
        ping = next(e for e in events if e["datasource"] == "ping-slash24")
        # Began 8 Jan 16:40 UTC, the shutdown's first signal.
        self.assertEqual(ping["from"], 1767890400)
        self.assertEqual(ping["until"], 1769100000)

    def test_a_quiet_day_has_no_events(self):
        self.assertEqual(
            utils.ioda.parse_events(json.loads(fixture("is_20261010_empty"))), [])

    def test_an_api_error_is_not_read_as_no_outage(self):
        with self.assertRaises(ValueError):
            utils.ioda.parse_events({"error": "bad entityCode", "data": []})

    def test_a_payload_without_an_event_list_is_rejected(self):
        for payload in ({"type": "outages.events"}, {"data": {}}, [], "x"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                utils.ioda.parse_events(payload)

    def test_malformed_entries_are_skipped_not_fatal(self):
        events = utils.ioda.parse_events({"data": [
            "junk", {"datasource": "bgp"}, {"datasource": "bgp", "from": 10, "until": 20}]})
        self.assertEqual(len(events), 1)

    def test_a_full_page_is_rejected_as_possibly_truncated(self):
        """A missing event reads as "no outage", so a cut-off list cannot be used."""
        page = {"data": [{"datasource": "bgp", "from": i, "until": i + 1}
                         for i in range(utils.ioda.IODA_EVENT_LIMIT)]}
        with self.assertRaises(ValueError):
            utils.ioda.parse_events(page)

    def test_short_events_sit_beside_the_long_ones(self):
        events = utils.ioda.parse_events(json.loads(fixture("ir_20261005")))
        self.assertEqual(sorted(e["datasource"] for e in events),
                         ["bgp", "bgp", "gtr", "merit-nt"])

    def test_an_open_ended_event_keeps_until_none(self):
        events = utils.ioda.parse_events(
            {"data": [{"datasource": "bgp", "from": 10, "until": None}]})
        self.assertIsNone(events[0]["until"])


class TestEventsOverlapping(unittest.TestCase):
    EVENTS = (
        {"datasource": "a", "from": 100, "until": 200, "score": 1},
        {"datasource": "ongoing", "from": 150, "until": None, "score": 1},
    )

    def test_an_outage_that_began_before_the_window_still_counts(self):
        """The case a lookback over alerts would have missed."""
        events = utils.ioda.parse_events(json.loads(fixture("ir_20260120")))
        mid_shutdown = (1768900000, 1768900600)       # 20 Jan, a 10-minute trace
        self.assertIn("ping-slash24", {
            e["datasource"] for e in utils.ioda.events_overlapping(events, *mid_shutdown)})

    def test_an_outage_begun_months_before_the_trace_is_reported(self):
        """With IODA's default 14-day lookback this trace saw no outage."""
        events = utils.ioda.parse_events(json.loads(fixture("ir_20260820")))
        overlapping = utils.ioda.events_overlapping(events, 1787221469, 1787221700)
        self.assertEqual(
            utils.ioda.tooltip_line({"country": "IR", "outage": True,
                                     "events": overlapping}),
            "IODA[IR]: outage (gtr since 2026-01-08, merit-nt since 2026-03-08)")

    def test_events_that_ended_before_the_window_are_dropped(self):
        """The API widens every query by 14 days, so it returns these."""
        self.assertEqual(
            [e["datasource"] for e in utils.ioda.events_overlapping(self.EVENTS, 210, 300)],
            ["ongoing"])

    def test_touching_boundaries_overlap(self):
        self.assertEqual(len(utils.ioda.events_overlapping(self.EVENTS[:1], 200, 300)), 1)
        self.assertEqual(len(utils.ioda.events_overlapping(self.EVENTS[:1], 0, 100)), 1)

    def test_a_window_before_everything_overlaps_nothing(self):
        self.assertEqual(utils.ioda.events_overlapping(self.EVENTS, 0, 99), [])


@patch("utils.ioda.urllib.request.urlopen")
class TestFetch(unittest.TestCase):
    def test_success_reads_events(self, urlopen):
        urlopen.return_value = response(fixture("ir_20260120"))
        status = utils.ioda.fetch_ioda_events("ir", *JAN_20)
        self.assertTrue(status["available"])
        self.assertIsNone(status["error"])
        self.assertEqual(status["country"], "IR")
        self.assertEqual(len(status["events"]), 3)

    def test_queries_the_real_endpoint_for_the_window(self, urlopen):
        urlopen.return_value = response(fixture("is_20261010_empty"))
        utils.ioda.fetch_ioda_events("ir", *OCT_10)
        url = urlopen.call_args[0][0].full_url
        self.assertTrue(url.startswith(
            "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?"))
        for part in ("entityType=country", "entityCode=IR",
                     f"from={OCT_10[0]}", f"until={OCT_10[1]}",
                     "extendWindow=31536000", "limit=500"):
            self.assertIn(part, url)

    def test_failures_are_unavailable_not_raised(self, urlopen):
        failures = [
            TimeoutError("timed out"),
            urllib.error.URLError("no route"),
            urllib.error.HTTPError("u", 503, "unavailable", {}, None),
        ]
        for exc in failures:
            with self.subTest(exc=exc):
                urlopen.side_effect = exc
                status = utils.ioda.fetch_ioda_events("IR", *JAN_20)
                self.assertFalse(status["available"])
                self.assertTrue(status["error"])
                self.assertEqual(status["events"], [])

    def test_unparseable_or_error_bodies_are_unavailable(self, urlopen):
        for body in (b"<html>", json.dumps({"error": "nope", "data": []}).encode()):
            with self.subTest(body=body):
                urlopen.side_effect = None
                urlopen.return_value = response(body)
                self.assertFalse(utils.ioda.fetch_ioda_events("IR", *JAN_20)["available"])


class TestMeasurementWindow(unittest.TestCase):
    def test_start_and_end(self):
        self.assertEqual(
            utils.ioda.measurement_window({"timestamp": 10, "endtime": 20}), (10, 20))

    def test_missing_or_backwards_end_is_an_instant(self):
        for m in ({"timestamp": 10}, {"timestamp": 10, "endtime": -1},
                  {"timestamp": 10, "endtime": 5}):
            with self.subTest(m=m):
                self.assertEqual(utils.ioda.measurement_window(m), (10, 10))

    def test_no_usable_start(self):
        for m in ({}, {"timestamp": -1}, {"timestamp": "x"}, {"timestamp": 0}):
            with self.subTest(m=m):
                self.assertIsNone(utils.ioda.measurement_window(m))


class TestAnnotateMeasurements(unittest.TestCase):
    def capture(self, measurements):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump(measurements, handle)
        self.addCleanup(lambda: (os.remove(path), os.rmdir(directory)))
        return path

    def read(self, path):
        with open(path) as handle:
            return json.load(handle)

    def fetch_returning(self, name):
        calls = []

        def fetch(country, start, end):
            calls.append((country, start, end))
            return {"country": country.upper(), "available": True, "error": None,
                    "events": utils.ioda.parse_events(json.loads(fixture(name)))}
        return fetch, calls

    def test_each_measurement_is_judged_against_its_own_window(self):
        path = self.capture([
            {"vp": "1", "timestamp": 1768900000, "endtime": 1768900600},   # 20 Jan
            {"vp": "2", "timestamp": OCT_10[0], "endtime": OCT_10[0] + 600},
        ])
        fetch, _ = self.fetch_returning("ir_20260120")
        annotated, outages, _ = utils.ioda.annotate_measurements(path, "IR", fetch=fetch)
        self.assertEqual((annotated, outages), (2, 1))
        jan, octo = self.read(path)
        self.assertTrue(jan["ioda_status"]["outage"])
        self.assertEqual(jan["ioda_status"]["datasources"],
                         ["gtr", "merit-nt", "ping-slash24"])
        self.assertEqual(jan["ioda_status"]["window"], [1768900000, 1768900600])
        self.assertFalse(octo["ioda_status"]["outage"])
        self.assertEqual(octo["ioda_status"]["datasources"], [])

    def test_one_request_spans_the_whole_capture(self):
        path = self.capture([
            {"timestamp": 300, "endtime": 400}, {"timestamp": 100, "endtime": 150}])
        fetch, calls = self.fetch_returning("is_20261010_empty")
        utils.ioda.annotate_measurements(path, "ir", fetch=fetch)
        self.assertEqual(calls, [("ir", 100, 400)])

    def test_measurements_far_apart_get_separate_requests(self):
        """A real multi-VP capture mixed Aug 2026 and Dec 2021 results; one
        request across 4.6 years risks IODA's page limit."""
        path = self.capture([
            {"timestamp": 1787221469, "endtime": 1787221654},
            {"timestamp": 1640569658, "endtime": 1640569825},
            {"timestamp": 1787221635, "endtime": 1787221700}])
        fetch, calls = self.fetch_returning("is_20261010_empty")
        self.assertEqual(
            utils.ioda.annotate_measurements(path, "IR", fetch=fetch)[:2], (3, 0))
        self.assertEqual(calls, [("IR", 1640569658, 1640569825),
                                 ("IR", 1787221469, 1787221700)])

    def test_a_failed_span_leaves_only_its_measurements_unannotated(self):
        path = self.capture([{"timestamp": 100, "endtime": 150},
                             {"timestamp": 10_000_000, "endtime": 10_000_100}])
        down = {"country": "IR", "available": False, "events": [], "error": "down"}

        def fetch(country, start, end):
            if start >= 10_000_000:
                return down
            return {"country": "IR", "available": True, "error": None, "events": []}
        annotated, outages, status = utils.ioda.annotate_measurements(
            path, "IR", fetch=fetch)
        self.assertEqual((annotated, outages, status), (1, 0, down))
        first, second = self.read(path)
        self.assertIn("ioda_status", first)
        self.assertNotIn("ioda_status", second)

    def test_a_measurement_without_a_time_is_left_alone(self):
        path = self.capture([{"timestamp": 100, "endtime": 150}, {"dst_addr": "x"}])
        fetch, _ = self.fetch_returning("is_20261010_empty")
        self.assertEqual(
            utils.ioda.annotate_measurements(path, "IR", fetch=fetch)[:2], (1, 0))
        self.assertNotIn("ioda_status", self.read(path)[1])

    def test_unavailable_writes_nothing(self):
        measurements = [{"timestamp": 100, "endtime": 150}]
        path = self.capture(measurements)
        status = {"country": "IR", "available": False, "events": [], "error": "down"}
        result = utils.ioda.annotate_measurements(
            path, "IR", fetch=lambda *a: status)
        self.assertEqual(result, (0, 0, status))
        self.assertEqual(self.read(path), measurements)

    def test_nothing_to_check_does_not_fetch(self):
        def fetch(*args):
            raise AssertionError("fetched with nothing to check")
        for content in ([{"dst_addr": "x"}], {"not": "a list"}, []):
            with self.subTest(content=content):
                path = self.capture(content)
                self.assertEqual(
                    utils.ioda.annotate_measurements(path, "IR", fetch=fetch),
                    (0, 0, None))

    def test_unreadable_capture_does_not_raise(self):
        self.assertEqual(
            utils.ioda.annotate_measurements("/nonexistent/m.json", "IR"), (0, 0, None))
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "bad.json")
        with open(path, "w") as handle:
            handle.write("{truncated")
        self.addCleanup(lambda: (os.remove(path), os.rmdir(directory)))
        self.assertEqual(utils.ioda.annotate_measurements(path, "IR"), (0, 0, None))

    def test_end_to_end_through_the_http_layer(self):
        """The real fetch, the recorded response, the real annotation."""
        path = self.capture([{"timestamp": 1768900000, "endtime": 1768900600}])
        with patch("utils.ioda.urllib.request.urlopen",
                   return_value=response(fixture("ir_20260120"))):
            annotated, outages, status = utils.ioda.annotate_measurements(path, "IR")
        self.assertEqual((annotated, outages), (1, 1))
        self.assertTrue(status["available"])
        self.assertEqual(
            utils.ioda.tooltip_line(self.read(path)[0]["ioda_status"]),
            "IODA[IR]: outage (gtr since 2026-01-08, merit-nt since 2026-01-18,"
            " ping-slash24 since 2026-01-08)")


class TestTooltipLine(unittest.TestCase):
    def test_outage_dates_each_datasource_from_its_earliest_event(self):
        self.assertEqual(utils.ioda.tooltip_line({
            "country": "IR", "outage": True, "events": [
                {"datasource": "bgp", "from": 1791244500},
                {"datasource": "bgp", "from": 1791231300},
                {"datasource": "gtr", "from": 1767897000}]}),
            "IODA[IR]: outage (bgp since 2026-10-05, gtr since 2026-01-08)")

    def test_outage_names_the_datasources(self):
        self.assertEqual(utils.ioda.tooltip_line(
            {"country": "IR", "outage": True, "datasources": ["bgp"]}),
            "IODA[IR]: outage (bgp)")

    def test_a_clean_result_is_shown_too(self):
        self.assertEqual(
            utils.ioda.tooltip_line({"country": "IR", "outage": False}),
            "IODA[IR]: no outage")

    def test_nothing_recorded_shows_nothing(self):
        for value in (None, "x", []):
            self.assertEqual(utils.ioda.tooltip_line(value), "")


@unittest.skipUnless(os.environ.get("TRACEVIS_LIVE_TESTS") == "1",
                     "live API test; set TRACEVIS_LIVE_TESTS=1")
class TestLiveIoda(unittest.TestCase):
    """Guards against the §3.2 failure: a mocked endpoint that does not exist."""

    def test_the_january_shutdown_is_visible(self):
        status = utils.ioda.fetch_ioda_events("IR", *JAN_20, timeout=60)
        self.assertTrue(status["available"], status["error"])
        self.assertIn("ping-slash24", {e["datasource"] for e in status["events"]})

    def test_an_outage_begun_months_earlier_is_still_found(self):
        """Pins the server-side behaviour EXTEND_WINDOW exists for."""
        status = utils.ioda.fetch_ioda_events(
            "IR", 1787221469, 1787221700, timeout=60)
        self.assertTrue(status["available"], status["error"])
        overlapping = utils.ioda.events_overlapping(
            status["events"], 1787221469, 1787221700)
        self.assertIn("gtr", {e["datasource"] for e in overlapping})


if __name__ == "__main__":
    unittest.main()
