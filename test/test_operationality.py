import sys
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


if __name__ == "__main__":
    unittest.main()
