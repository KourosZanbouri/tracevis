"""Tests for continuous monitoring (backlog §2.7) and the collision fix."""

import json
import os
import tempfile
import unittest
import unittest.mock

import utils.trace
from utils import monitor
from utils.traceroute_struct import traceroute_data


def _measurement(dst="1.1.1.1", annotation="", reached=True, hops=3,
                 state="", **signals):
    """A measurement dict shaped like what utils.trace writes."""
    result = []
    for index in range(hops):
        replies = [{"from": f"10.0.0.{index + 1}", "rtt": 1.0}]
        if reached and index == hops - 1:
            replies = [{"from": dst, "rtt": 1.0}]
        result.append({"hop": index + 1, "result": replies})
    data = {
        "dst_addr": dst, "src_addr": "192.168.1.1", "annotation": annotation,
        "timestamp": 1000, "proto": "TCP", "port": 443, "result": result,
    }
    if state:
        data["network_state"] = state
    for name in monitor.TRACKED_SIGNALS:
        data[name] = bool(signals.get(name, False))
    return data


def _write(directory, name, measurements):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(measurements, handle)
    return path


class TestRunMonitorScheduling(unittest.TestCase):
    """The loop is tested without sleeping and without tracing.

    The clock and the sleep are arguments precisely so this is possible; a
    loop that could only be exercised by waiting five minutes per run would
    not be exercised at all.
    """

    def setUp(self):
        self.slept = []
        self.ticks = iter(range(1000))

    def _sleeper(self, seconds):
        self.slept.append(seconds)

    def _clock(self):
        return next(self.ticks)

    def test_runs_the_requested_number_of_times(self):
        calls = []
        records = monitor.run_monitor(
            lambda: calls.append(1) or "/tmp/x.json", runs=3, interval=7,
            sleeper=self._sleeper, clock=self._clock, reporter=None)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record.ok for record in records))

    def test_does_not_sleep_after_the_final_run(self):
        # Sleeping after the last run makes the mode hang for a whole extra
        # interval before returning, for nothing.
        monitor.run_monitor(lambda: "/tmp/x.json", runs=3, interval=7,
                            sleeper=self._sleeper, clock=self._clock,
                            reporter=None)
        self.assertEqual(self.slept, [7, 7])

    def test_sleeps_the_configured_interval(self):
        monitor.run_monitor(lambda: "/tmp/x.json", runs=4, interval=42,
                            sleeper=self._sleeper, clock=self._clock,
                            reporter=None)
        self.assertEqual(set(self.slept), {42})

    def test_records_are_indexed_and_timestamped(self):
        records = monitor.run_monitor(
            lambda: "/tmp/x.json", runs=3, interval=1,
            sleeper=self._sleeper, clock=self._clock, reporter=None)
        self.assertEqual([r.index for r in records], [1, 2, 3])
        self.assertEqual([r.started for r in records], [0, 1, 2])

    def test_a_failing_run_does_not_stop_the_loop(self):
        """A trace failing on a hostile network is data, not a reason to stop."""
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 2:
                raise OSError("network unreachable")
            return "/tmp/x.json"

        records = monitor.run_monitor(flaky, runs=4, interval=1,
                                      sleeper=self._sleeper, clock=self._clock,
                                      reporter=None)
        self.assertEqual(len(records), 4)
        self.assertEqual([r.ok for r in records], [True, False, True, True])
        self.assertIn("network unreachable", records[1].error)

    def test_an_unsuccessful_run_is_recorded_as_not_ok(self):
        records = monitor.run_monitor(lambda: None, runs=2, interval=1,
                                      sleeper=self._sleeper, clock=self._clock,
                                      reporter=None)
        self.assertEqual([r.ok for r in records], [False, False])
        self.assertEqual([r.error for r in records], [None, None])

    def test_interrupt_keeps_every_completed_run(self):
        calls = []

        def interrupted():
            calls.append(1)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return "/tmp/x.json"

        records = monitor.run_monitor(interrupted, runs=0, interval=1,
                                      sleeper=self._sleeper, clock=self._clock,
                                      reporter=None)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record.ok for record in records))

    def test_interrupt_during_the_sleep_keeps_completed_runs(self):
        def stop(_seconds):
            raise KeyboardInterrupt

        records = monitor.run_monitor(lambda: "/tmp/x.json", runs=0, interval=1,
                                      sleeper=stop, clock=self._clock,
                                      reporter=None)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0].ok)

    def test_zero_runs_means_until_interrupted(self):
        calls = []

        def forever():
            calls.append(1)
            if len(calls) == 6:
                raise KeyboardInterrupt
            return "/tmp/x.json"

        monitor.run_monitor(forever, runs=0, interval=1, sleeper=self._sleeper,
                            clock=self._clock, reporter=None)
        self.assertEqual(len(calls), 6)


class TestSummariseMeasurement(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_reads_reachability_from_the_replies(self):
        path = _write(self.dir, "a.json", [_measurement(reached=True)])
        summary = monitor.summarise_measurement(path)
        self.assertTrue(summary["destinations"]["1.1.1.1"]["reached"])

    def test_an_unanswered_destination_is_not_reached(self):
        # A path that dies at hop 4 still produces a full run of hops; the
        # question is whether the destination itself ever answered.
        path = _write(self.dir, "b.json", [_measurement(reached=False)])
        summary = monitor.summarise_measurement(path)
        self.assertFalse(summary["destinations"]["1.1.1.1"]["reached"])

    def test_arms_of_the_same_destination_stay_separate(self):
        """Collapsing on dst_addr would average a control with its treatment."""
        path = _write(self.dir, "c.json", [
            _measurement(annotation="control", reached=True),
            _measurement(annotation="treatment", reached=False),
        ])
        summary = monitor.summarise_measurement(path)
        self.assertEqual(len(summary["destinations"]), 2)
        self.assertTrue(summary["destinations"]["1.1.1.1 [control]"]["reached"])
        self.assertFalse(summary["destinations"]["1.1.1.1 [treatment]"]["reached"])

    def test_absent_network_state_is_unknown_not_a_crash(self):
        # network_state postdates most of this repository's captures.
        path = _write(self.dir, "d.json", [_measurement()])
        summary = monitor.summarise_measurement(path)
        self.assertEqual(summary["network_state"], monitor.UNKNOWN_STATE)

    def test_network_state_is_read_when_present(self):
        path = _write(self.dir, "e.json", [_measurement(state="allowlisted")])
        self.assertEqual(
            monitor.summarise_measurement(path)["network_state"], "allowlisted")

    def test_signals_are_carried(self):
        path = _write(self.dir, "f.json",
                      [_measurement(sni_inspected=True, rst_flood=True)])
        signals = monitor.summarise_measurement(path)["destinations"]["1.1.1.1"]["signals"]
        self.assertTrue(signals["sni_inspected"])
        self.assertTrue(signals["rst_flood"])
        self.assertFalse(signals["cgnat_hop"])

    def test_a_missing_file_returns_none(self):
        self.assertIsNone(
            monitor.summarise_measurement(os.path.join(self.dir, "nope.json")))

    def test_unparseable_json_returns_none(self):
        # A truncated write is an ordinary outcome on the networks this tool
        # measures; it must not take the loop down.
        path = os.path.join(self.dir, "g.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.assertIsNone(monitor.summarise_measurement(path))

    def test_a_non_list_payload_returns_none(self):
        path = _write(self.dir, "h.json", {"not": "a list"})
        self.assertIsNone(monitor.summarise_measurement(path))

    def test_an_empty_capture_returns_none(self):
        path = _write(self.dir, "i.json", [])
        self.assertIsNone(monitor.summarise_measurement(path))


class TestBuildTrend(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _summary(self, name, measurements):
        return monitor.summarise_measurement(_write(self.dir, name, measurements))

    def test_detects_a_reachability_change(self):
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement(reached=False)]),
            self._summary("2.json", [_measurement(reached=True)]),
        ])
        self.assertTrue(trend["destinations"]["1.1.1.1"]["reachability_changed"])

    def test_steady_reachability_is_not_a_change(self):
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement(reached=True)]),
            self._summary("2.json", [_measurement(reached=True)]),
        ])
        self.assertFalse(trend["destinations"]["1.1.1.1"]["reachability_changed"])

    def test_detects_a_network_state_change(self):
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement(state="open")]),
            self._summary("2.json", [_measurement(state="allowlisted")]),
        ])
        self.assertTrue(trend["network_state_changed"])
        self.assertEqual(trend["network_states"], ["open", "allowlisted"])

    def test_detects_a_signal_change(self):
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement(sni_inspected=False)]),
            self._summary("2.json", [_measurement(sni_inspected=True)]),
        ])
        self.assertEqual(
            trend["destinations"]["1.1.1.1"]["changed_signals"], ["sni_inspected"])

    def test_a_destination_that_stops_being_probed_is_visible(self):
        """Absence is recorded, not smoothed away."""
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement(dst="1.1.1.1"),
                                     _measurement(dst="8.8.8.8")]),
            self._summary("2.json", [_measurement(dst="1.1.1.1")]),
        ])
        self.assertEqual(trend["destinations"]["8.8.8.8"]["missing_runs"], 1)
        self.assertIsNone(trend["destinations"]["8.8.8.8"]["series"][1])

    def test_unreadable_runs_are_dropped_not_counted(self):
        trend = monitor.build_trend([
            self._summary("1.json", [_measurement()]), None,
            self._summary("2.json", [_measurement()]),
        ])
        self.assertEqual(trend["runs"], 2)

    def test_no_summaries_is_not_a_crash(self):
        trend = monitor.build_trend([])
        self.assertEqual(trend["runs"], 0)
        self.assertEqual(monitor.format_trend(trend), "no runs to compare")


class TestFormatTrend(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _trend(self, runs):
        summaries = [
            monitor.summarise_measurement(_write(self.dir, f"{i}.json", m))
            for i, m in enumerate(runs)]
        return monitor.format_trend(monitor.build_trend(summaries))

    def test_marks_reached_and_unreached(self):
        report = self._trend([[_measurement(reached=False)],
                              [_measurement(reached=True)]])
        self.assertIn("x·", report)
        self.assertIn("REACHABILITY CHANGED", report)

    def test_marks_a_run_where_a_target_was_absent(self):
        report = self._trend([
            [_measurement(dst="1.1.1.1"), _measurement(dst="8.8.8.8")],
            [_measurement(dst="1.1.1.1")]])
        self.assertRegex(report, r"8\.8\.8\.8\s+·-")

    def test_says_so_when_nothing_moved(self):
        report = self._trend([[_measurement(reached=True, state="open")],
                              [_measurement(reached=True, state="open")]])
        self.assertIn("nothing changed across these runs", report)

    def test_flags_a_state_change_in_the_header(self):
        report = self._trend([[_measurement(state="open")],
                              [_measurement(state="shutdown")]])
        self.assertIn("open → shutdown", report)
        self.assertIn("*** CHANGED ***", report)


class TestMeasurementFilesAreNeverOverwritten(unittest.TestCase):
    """Names are stamped to the minute and nothing checked the name was free.

    Two runs inside the same minute -- the ordinary case under --monitor --
    wrote to the same path and the second silently destroyed the first. Both
    printed the same "saved:" line, so the loss left no trace.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp() + os.sep
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def _save(self, marker):
        tracer = utils.trace.Tracer()
        tracer.measurement_data = [[traceroute_data(
            dst_addr="1.1.1.1", annotation=marker, proto="TCP", port=443,
            timestamp=1, src_addr="10.0.0.1")], []]
        tracer.have_2_packet = False
        return tracer.save_measurement_data(
            request_ips=["1.1.1.1"], measurement_name="AS0-tracevis-20260829-1200",
            continue_to_max_ttl=False, output_dir=self.dir)

    def test_same_minute_runs_get_separate_files(self):
        paths = [self._save(f"RUN-{i}") for i in range(1, 5)]
        self.assertEqual(len(set(paths)), 4)

    def test_no_run_is_destroyed(self):
        paths = [self._save(f"RUN-{i}") for i in range(1, 5)]
        survived = []
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                survived.append(json.load(handle)[0]["annotation"])
        survived.sort()
        self.assertEqual(survived, ["RUN-1", "RUN-2", "RUN-3", "RUN-4"])

    def test_the_first_run_keeps_the_unsuffixed_name(self):
        # Every filename the tool already produces must be unchanged; only
        # the colliding path behaves differently.
        first = self._save("RUN-1")
        self.assertTrue(first.endswith("AS0-tracevis-20260829-1200.json"))

    def test_the_suffix_counts_up(self):
        self._save("a")
        second = self._save("b")
        third = self._save("c")
        self.assertTrue(second.endswith("-2.json"))
        self.assertTrue(third.endswith("-3.json"))

    def test_creation_is_exclusive(self):
        """A check-then-open would leave a race; "x" mode does not."""
        handle, path = utils.trace.Tracer._open_new_measurement_file(
            os.path.join(self.dir, "z.json"))
        handle.close()
        self.assertEqual(handle.mode, "x")
        self.assertTrue(os.path.exists(path))


class TestTheDefaultSleepIsPatchable(unittest.TestCase):
    """`sleeper=time.sleep` in the signature binds once, at import.

    A caller patching `time.sleep` would then be silently ignored and would
    wait out the real interval believing it had been stubbed -- which is
    exactly what happened during validation, on a 60s interval. Resolving
    inside the function makes the patch take.
    """

    def test_a_patched_time_sleep_is_honoured(self):
        # The interval is deliberately tiny. The assertion that catches the
        # defect is the call count -- with the bug the mock is never called
        # at all -- and a large interval would make the failing case sleep
        # for real rather than fail, which is a test that hangs instead of
        # reporting.
        import time as time_module
        with unittest.mock.patch.object(time_module, "sleep") as slept:
            monitor.run_monitor(lambda: "/tmp/x.json", runs=3, interval=1,
                                reporter=None)
        self.assertEqual(slept.call_count, 2)

    def test_a_patched_time_time_is_honoured(self):
        import time as time_module
        with unittest.mock.patch.object(time_module, "sleep"), \
                unittest.mock.patch.object(time_module, "time",
                                           side_effect=[10, 20]):
            records = monitor.run_monitor(lambda: "/tmp/x.json", runs=2,
                                          interval=1, reporter=None)
        self.assertEqual([r.started for r in records], [10, 20])


if __name__ == "__main__":
    unittest.main()
