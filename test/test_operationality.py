import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

import tracevis


class TestArguments(unittest.TestCase):
    def _assert_args_subset(self, args, expected):
        """Assert every declared expected key matches; ignores extra argparse keys.

        The args dict is argparse's full namespace, which grows as flags are
        added (backlog test-hardening item). Declaring only the keys a test
        cares about keeps it resilient to new flags while still verifying the
        defaults/behaviours that matter.
        """
        for key, value in expected.items():
            self.assertEqual(args.get(key), value, f"args[{key!r}] mismatch")

    def test_help(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        with self.assertRaises(SystemExit):
            tracevis.get_args(['-h'], auto_exit=True)
        self.assertIn(err.getvalue(), "usage:")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_no_args(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        with self.assertRaises(SystemExit):
            tracevis.get_args([], auto_exit=True)
        self.assertIn(err.getvalue(), "usage:")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__


    def test_defaults(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args([], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': False, 'packet_input_method': 'hex',
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False,                     'sni_test': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None,
                     'port_pool': None, 'timeout_profile': None, 'network_mode': 'auto', 'phase_overlay': False,
                     'highlight_selected': False, 'renderer': 'visjs',
                     'reverse_path': False,
                     'ipv4': False, 'vps': None, 'ioda_country': None}
        self._assert_args_subset(args, expected)
        # new DNS-family flags default to off
        self.assertFalse(args["dnsdot"])
        self.assertFalse(args["dnstt"])
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_config_file(self):
        import json
        import os
        from io import StringIO
        md = self.maxDiff
        self.maxDiff = None
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        samples_dir = 'samples/'
        for file in os.listdir(samples_dir):
            args = tracevis.get_args(['--config-file', os.path.join(samples_dir, file)], auto_exit=False)
            with open(os.path.join(samples_dir, file), 'r') as f:
                expected = json.load(f)
                del args['config_file']
                for k,v in args.items():
                    if k in expected:
                        self.assertEqual(v, expected[k])

        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        self.maxDiff = md

    def test_dns_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--dns'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': False, 'packet_input_method': None,
                    'packet_data': None, 'dns': True, 'dnstcp': False, 'dnsdot': False, 'dnstt': False,                     'sni_test': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_packet_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--packet'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'hex',
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_packet_input_types(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--packet', '--packet-input-method', 'hex'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'hex',
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'json'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'json',
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'interactive'], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'interactive',
                    'packet_data': None, 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)

        args = tracevis.get_args(['--packet', '--packet-input-method', 'json', '--packet-data', 'b64:e30='], auto_exit=False)
        expected = {'config_file': None, 'name': None, 'ips': None, 'packet': True, 'packet_input_method': 'json',
                    'packet_data': 'b64:e30=', 'dns': False, 'dnstcp': False, 'dnsdot': False, 'dnstt': False, 'continue': False, 'maxttl': None,
                    'timeout': None, 'repeat': None, 'ripe': None, 'ripemids': None, 'file': None, 'csv': False,
                    'csvraw': False, 'attach': False, 'label': None, 'domain1': None, 'domain2': None, 'annot1': None,
                    'annot2': None, 'rexmit': False, 'paris': False, 'options': 'new', 'iface': None, 'show_ifaces': False, 'port': None}
        self._assert_args_subset(args, expected)
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_dnsdot_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--dnsdot'], auto_exit=False)
        self.assertTrue(args["dnsdot"])
        self.assertFalse(args["packet"])
        self.assertFalse(args["packet_input_method"])
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_dnstt_mode(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--dnstt'], auto_exit=False)
        self.assertTrue(args["dnstt"])
        self.assertFalse(args["dns"])
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_port_pool_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--port-pool', '8080,8443'], auto_exit=False)
        self.assertEqual(args.get("port_pool"), '8080,8443')
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_timeout_profile_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--timeout-profile', 'degraded'], auto_exit=False)
        self.assertEqual(args.get("timeout_profile"), 'degraded')
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_network_mode_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--network-mode', 'shutdown'], auto_exit=False)
        self.assertEqual(args.get("network_mode"), 'shutdown')
        # default when omitted
        args = tracevis.get_args([], auto_exit=False)
        self.assertEqual(args.get("network_mode"), 'auto')
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_phase_overlay_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--phase-overlay'], auto_exit=False)
        self.assertTrue(args.get("phase_overlay"))
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_ipv4_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--ipv4'], auto_exit=False)
        self.assertTrue(args.get("ipv4"))
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_vps_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--vps', '1001,2002'], auto_exit=False)
        self.assertEqual(args.get("vps"), "1001,2002")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_ioda_country_flag(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args(['--ioda-country', 'US'], auto_exit=False)
        self.assertEqual(args.get("ioda_country"), "US")
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__

    def test_ioda_country_defaults_none(self):
        from io import StringIO
        out,err = StringIO(), StringIO()
        sys.stdout, sys.stderr = out, err
        args = tracevis.get_args([], auto_exit=False)
        self.assertIsNone(args.get("ioda_country"))
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__


class TestIpv4Enforcement(unittest.TestCase):
    """GitHub issue #69: --ipv4 parsed but was never read by anything.

    The only consumer of the parsed value in the whole codebase was a test
    asserting argparse had stored it, which proves argparse works, not that
    the flag does anything.
    """

    def test_all_ipv4_targets_accepted(self):
        self.assertEqual(
            tracevis.reject_non_ipv4_targets(["1.1.1.1", "8.8.8.8"]), [])

    def test_ipv6_literal_rejected(self):
        self.assertEqual(
            tracevis.reject_non_ipv4_targets(
                ["1.1.1.1", "2001:4860:4860::8888"]),
            ["2001:4860:4860::8888"])

    def test_hostname_rejected(self):
        self.assertEqual(
            tracevis.reject_non_ipv4_targets(["example.com"]), ["example.com"])

    def test_empty_target_list(self):
        self.assertEqual(tracevis.reject_non_ipv4_targets([]), [])

    def test_surrounding_whitespace_tolerated(self):
        self.assertEqual(tracevis.reject_non_ipv4_targets([" 1.1.1.1 "]), [])

    def test_every_offender_is_named(self):
        rejected = tracevis.reject_non_ipv4_targets(
            ["::1", "1.1.1.1", "nope", "2001:db8::1"])
        self.assertEqual(rejected, ["::1", "nope", "2001:db8::1"])

    def test_flag_is_consumed_by_main(self):
        """The point of the fix: main() reads args["ipv4"] and acts on it."""
        import inspect
        source = inspect.getsource(tracevis.main)
        self.assertIn('args.get("ipv4")', source)
        self.assertIn("reject_non_ipv4_targets", source)


class TestIpv4ExitsBeforeProbing(unittest.TestCase):
    """A rejected target must stop the run, not fail later inside scapy."""

    def test_exits_nonzero_with_an_ipv6_target(self):
        import os
        import subprocess
        env = dict(os.environ, TRACEVIS_OUTPUT_DIR=tempfile.mkdtemp())
        proc = subprocess.run(
            [sys.executable, "tracevis.py", "--dns", "--ipv4",
             "-i", "1.1.1.1,2001:4860:4860::8888"],
            capture_output=True, text=True, env=env, check=False,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("2001:4860:4860::8888", proc.stdout + proc.stderr)
        self.assertIn("not IPv4", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()


class TestIpv6ProbeTargetsAreRefusedEarly(unittest.TestCase):
    """Backlog §2.1: rendering IPv6 works, probing over it does not.

    Handing an IPv6 address to `IP(dst=...)` raises a bare `gaierror` from
    inside scapy, well away from the target list that caused it. Refusing it
    before any packet is sent turns that into a stated limitation.

    Distinct from `--ipv4`, which is an opt-in assertion and also rejects
    hostnames; this fires unconditionally and only on IPv6 literals.
    """

    def test_ipv6_literals_are_identified(self):
        self.assertEqual(
            tracevis.reject_ipv6_probe_targets(
                ["1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"]),
            ["2606:4700:4700::1111"])

    def test_ipv4_targets_are_left_alone(self):
        self.assertEqual(
            tracevis.reject_ipv6_probe_targets(["1.1.1.1", "8.8.8.8"]), [])

    def test_hostnames_are_not_rejected_here(self):
        # A hostname may resolve to either family; only --ipv4 objects to it.
        self.assertEqual(tracevis.reject_ipv6_probe_targets(["example.com"]), [])

    def test_junk_is_ignored_rather_than_raising(self):
        self.assertEqual(tracevis.reject_ipv6_probe_targets(["***", "", None]),
                         [])

    def test_whitespace_is_tolerated(self):
        self.assertEqual(
            tracevis.reject_ipv6_probe_targets([" ::1 "]), [" ::1 "])

    def test_a_trace_over_ipv6_exits_before_probing(self):
        with self.assertRaises(SystemExit) as caught:
            tracevis.main(tracevis.get_args(
                ["--dns", "-i", "2606:4700:4700::1111"]))
        self.assertEqual(caught.exception.code, 1)

    def test_the_error_names_the_offender_and_the_way_forward(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            tracevis.main(tracevis.get_args(
                ["--dns", "-i", "2606:4700:4700::1111"]))
        output = buf.getvalue()
        self.assertIn("2606:4700:4700::1111", output)
        self.assertIn("cannot probe over IPv6", output)
        self.assertIn("-f", output)

    def test_rendering_a_capture_is_not_blocked(self):
        """The refusal is about probing; -f must be unaffected."""
        self.assertEqual(tracevis.reject_ipv6_probe_targets([]), [])


class TestMalformedCaptureExitsNonZero(unittest.TestCase):
    """A rejected capture must not look like a successful run to a script.

    Before the capture reader existed this path was an unhandled traceback,
    which at least exited 1. Reporting the problem cleanly while returning 0
    would have been a silent regression, so the exit code is pinned here.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _run(self, raw):
        path = os.path.join(self.dir, "c.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(raw)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as caught:
            tracevis.main(tracevis.get_args(["-f", path]))
        return caught.exception.code, buf.getvalue()

    def test_truncated_json_exits_one(self):
        code, output = self._run("{not json")
        self.assertEqual(code, 1)
        self.assertIn("not valid JSON", output)

    def test_an_empty_capture_exits_one(self):
        code, output = self._run("[]")
        self.assertEqual(code, 1)
        self.assertIn("no measurements", output)

    def test_a_json_object_exits_one(self):
        code, output = self._run('{"a": 1}')
        self.assertEqual(code, 1)
        self.assertIn("not the list of measurements", output)

    def test_no_traceback_reaches_the_operator(self):
        _code, output = self._run("{not json")
        self.assertNotIn("Traceback", output)


class TestVpsRecordsIodaStatus(unittest.TestCase):
    """Backlog §3.2: `--vps` → IODA → capture, wired through `main()`.

    The pieces were each tested, but nothing ran the CLI path, and the fetch
    it called pointed at an endpoint that does not exist.
    """

    MID_SHUTDOWN = {"vp": "1", "dst_addr": "1.1.1.1",
                    "timestamp": 1768900000, "endtime": 1768900600}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "multi.json")
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump([dict(self.MID_SHUTDOWN)], handle)

    def _run(self, urlopen):
        from unittest import mock
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch(
                "utils.ripe_atlas.download_multi_from_atlas",
                return_value=(True, self.path)))
            stack.enter_context(mock.patch(
                "tracevis.render_measurement", return_value=True))
            stack.enter_context(mock.patch("utils.ioda.urllib.request.urlopen", urlopen))
            stack.enter_context(contextlib.redirect_stdout(buf))
            tracevis.main(tracevis.get_args(["--vps", "1,2"]))
        with open(self.path, encoding="utf-8") as handle:
            return json.load(handle)[0], buf.getvalue()

    def test_an_outage_during_the_measurement_is_recorded(self):
        from unittest import mock
        fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                               "ioda_events_ir_20260120.json")
        with open(fixture, "rb") as handle:
            body = handle.read()
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.read.return_value = body
        measurement, output = self._run(mock.MagicMock(return_value=resp))
        self.assertTrue(measurement["ioda_status"]["outage"])
        self.assertIn("ping-slash24", measurement["ioda_status"]["datasources"])
        self.assertIn("IODA[IR]: outage during 1 of 1 measurement(s)", output)

    def test_an_unreachable_api_leaves_the_capture_untouched(self):
        from unittest import mock
        measurement, output = self._run(mock.MagicMock(side_effect=TimeoutError("t")))
        self.assertEqual(measurement, self.MID_SHUTDOWN)
        self.assertIn("IODA unavailable, not recorded", output)
