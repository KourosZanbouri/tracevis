import json
import time
import unittest
from unittest import mock
from urllib.error import HTTPError

from utils import dns, geolocate

# Position of `network_state` in the run_geolocate/get_meta_vars tuple. Named
# because it stopped being the last element once the probe evidence was
# appended, and `[-1]` silently started asserting on the wrong field.
STATE = 6


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = json.dumps(payload).encode()
        self.status = status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _cf_payload(client_ip):
    return {"clientIp": client_ip, "asn": 13335, "asOrganization": "Cloudflare",
            "country": "US", "city": "Ams"}


def _ipinfo_payload(client_ip):
    return {"ip": client_ip, "org": "AS15169 Google LLC",
            "country": "US", "city": "Ashburn"}


class TestClassifyNetworkState(unittest.TestCase):
    def test_open(self):
        meta = {"clientIp": "203.0.113.10", "asn": 13335,
                "asOrganization": "Cloudflare", "country": "US", "city": "Ams"}
        self.assertEqual(geolocate.classify_network_state(meta, dns_blackhole=False), "open")

    def test_allowlisted(self):
        meta = {"clientIp": "203.0.113.10", "asn": 13335,
                "asOrganization": "Cloudflare", "country": "US", "city": "Ams"}
        self.assertEqual(geolocate.classify_network_state(meta, dns_blackhole=True), "allowlisted")

    def test_shutdown(self):
        self.assertEqual(geolocate.classify_network_state(None, dns_blackhole=True), "shutdown")

    def test_unknown(self):
        self.assertEqual(geolocate.classify_network_state(None, dns_blackhole=False), "unknown")

    def test_blackholed_ip_is_not_reachable(self):
        self.assertEqual(geolocate.classify_network_state(
            {"clientIp": geolocate.BLACKHOLE_ADDR}, True), "shutdown")
        self.assertEqual(geolocate.classify_network_state({"clientIp": ""}, False), "unknown")


def _by_provider(**outcomes):
    """Fake `urlopen` keyed on provider name rather than call order.

    Order-based fakes stopped working once every provider is probed rather than
    just enough of them to get an answer, and keying on the name says what each
    test means anyway.
    """
    def _fake(request, timeout=None):
        for provider in geolocate.PROVIDERS:
            if provider.url == request.full_url:
                outcome = outcomes[provider.name]
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
        raise AssertionError("unexpected url " + request.full_url)
    return _fake


class TestFetchMeta(unittest.TestCase):
    def test_returns_first_usable_provider(self):
        fake = _by_provider(
            cloudflare=OSError("cloudflare blocked"),
            ipinfo=_FakeResponse(_ipinfo_payload("1.2.3.4")),
            ifconfig=_FakeResponse(_ipinfo_payload("5.6.7.8")),
        )
        with mock.patch.object(geolocate, "urlopen", side_effect=fake) as m:
            meta = geolocate.fetch_meta(timeout=5)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["clientIp"], "1.2.3.4")
        # All three are probed now, even though the second one answered: which
        # providers stay silent is itself the signal (see probe_providers).
        self.assertEqual(m.call_count, len(geolocate.PROVIDERS))

    def test_all_providers_fail_returns_none(self):
        with mock.patch.object(geolocate, "urlopen", side_effect=OSError("down")):
            self.assertIsNone(geolocate.fetch_meta(timeout=5))

    def test_blackholed_response_is_skipped(self):
        # Cloudflare returns the blackhole IP -> reject -> falls to ipinfo.
        fake = _by_provider(
            cloudflare=_FakeResponse(_cf_payload(geolocate.BLACKHOLE_ADDR)),
            ipinfo=_FakeResponse(_ipinfo_payload("9.9.9.9")),
            ifconfig=OSError("down"),
        )
        with mock.patch.object(geolocate, "urlopen", side_effect=fake):
            meta = geolocate.fetch_meta(timeout=5)
        self.assertEqual(meta["clientIp"], "9.9.9.9")

    def test_non_200_skipped(self):
        fake = _by_provider(
            cloudflare=_FakeResponse({}, status=502),
            ipinfo=_FakeResponse(_ipinfo_payload("7.7.7.7")),
            ifconfig=OSError("down"),
        )
        with mock.patch.object(geolocate, "urlopen", side_effect=fake):
            meta = geolocate.fetch_meta(timeout=5)
        self.assertEqual(meta["clientIp"], "7.7.7.7")

    def test_normalize_ipinfo_parses_org(self):
        meta = {"ip": "8.8.8.8", "org": "AS15169 Google LLC",
                "country": "US", "city": "Ashburn"}
        normalized = geolocate._normalize_ipinfo(meta)
        self.assertEqual(normalized["asn"], 15169)
        self.assertEqual(normalized["asOrganization"], "Google LLC")
        self.assertEqual(normalized["clientIp"], "8.8.8.8")

    def test_normalize_ifconfig_no_asn(self):
        meta = {"ip": "8.8.4.4", "country": "US", "city": "Ashburn"}
        normalized = geolocate._normalize_ifconfig(meta)
        self.assertEqual(normalized["asn"], "")
        self.assertEqual(normalized["asOrganization"], "")


class _RawResponse(_FakeResponse):
    """A 200 whose body is not JSON — what an injected block page looks like."""

    def __init__(self, body=b"<html>blocked</html>"):
        self._payload = body
        self.status = 200


class TestProviderReachability(unittest.TestCase):
    """`reachable` asks a narrower question than `meta`: did the provider answer?

    The distinction is what keeps a busy ipinfo.io from looking like censorship.
    """

    def _probe(self, outcome):
        def _fake(request, timeout=None):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        with mock.patch.object(geolocate, "urlopen", side_effect=_fake):
            return geolocate.PROVIDERS[0].probe(timeout=1)

    def test_a_usable_answer_is_reachable_and_carries_meta(self):
        probe = self._probe(_FakeResponse(_cf_payload("203.0.113.7")))
        self.assertTrue(probe.reachable)
        self.assertEqual(probe.meta["clientIp"], "203.0.113.7")

    def test_a_rate_limited_provider_is_still_reachable(self):
        error = HTTPError("https://x/", 429, "Too Many Requests", {}, None)
        # HTTPError is file-like; leaving it to the GC emits a ResourceWarning
        # on stderr later, which lands in an unrelated test's assertion.
        self.addCleanup(error.close)
        probe = self._probe(error)
        self.assertTrue(probe.reachable)
        self.assertIsNone(probe.meta)

    def test_an_error_status_is_still_reachable(self):
        probe = self._probe(_FakeResponse({}, status=502))
        self.assertTrue(probe.reachable)

    def test_a_connection_failure_is_not_reachable(self):
        probe = self._probe(OSError("timed out"))
        self.assertFalse(probe.reachable)

    def test_a_blackholed_answer_is_not_reachable(self):
        """Anywhere in the filter net, not just the canonical .34 — the address
        actually observed in the field was .35."""
        for address in (geolocate.BLACKHOLE_ADDR, "10.10.34.35", "10.10.34.36"):
            probe = self._probe(_FakeResponse(_cf_payload(address)))
            self.assertFalse(probe.reachable, address)

    def test_an_unparseable_body_is_not_reachable(self):
        self.assertFalse(self._probe(_RawResponse()).reachable)


class TestDnsHijackDetection(unittest.TestCase):
    """A hijack the detector could not see.

    `www.twitter.com` resolved to **10.10.34.35** from 1.1.1.1, 8.8.8.8 and
    9.9.9.9 alike — replies with IP TTL 1 and 9 ms RTT, against TTL 52/118/53
    and 43-188 ms for the accessible domain from the same resolvers. The probe
    returned False anyway, for two independent reasons.
    """

    def _resolves_to(self, address):
        return mock.patch.object(geolocate.socket, "gethostbyname",
                                 return_value=address)

    def test_the_probe_domain_is_one_that_is_actually_blocked(self):
        """It was `example.com` — the accessible control, by construction never
        hijacked, so the test could only ever come back False."""
        self.assertNotEqual(geolocate.BLACKHOLE_PROBE_DOMAIN, "example.com")
        self.assertEqual(geolocate.BLACKHOLE_PROBE_DOMAIN,
                         dns.DEFAULT_BLOCKED_ADDRESS)

    def test_the_observed_answer_is_recognised(self):
        """10.10.34.35, not the .34 the constant named."""
        with self._resolves_to("10.10.34.35"):
            self.assertTrue(geolocate.detect_dns_blackhole())

    def test_the_whole_filter_net_is_recognised(self):
        for address in ("10.10.34.0", "10.10.34.34", "10.10.34.36",
                        "10.10.34.255"):
            with self._resolves_to(address):
                self.assertTrue(geolocate.detect_dns_blackhole(), address)

    def test_a_neighbouring_net_is_not_the_blackhole(self):
        for address in ("10.10.33.35", "10.10.35.35", "10.0.0.1", "1.1.1.1"):
            with self._resolves_to(address):
                self.assertFalse(geolocate.detect_dns_blackhole(), address)

    def test_a_hijack_makes_the_network_allowlisted(self):
        meta = {"clientIp": "198.51.100.4"}
        all_reachable = [geolocate.ProviderProbe(p.name, None, True)
                         for p in geolocate.PROVIDERS]
        self.assertEqual(
            geolocate.classify_network_state(meta, True, all_reachable),
            "allowlisted")


class TestProviderStatusIsRecorded(unittest.TestCase):
    """The state alone is not checkable after the fact.

    Deciding whether a saved capture had been classified by the DNS hijack, by
    the provider differential, or by a build that predated both meant inferring
    it from which metadata fields happened to be populated.
    """

    def test_the_rendering_names_each_provider_and_its_outcome(self):
        probes = [geolocate.ProviderProbe("cloudflare", None, False),
                  geolocate.ProviderProbe("ipinfo", None, False),
                  geolocate.ProviderProbe("ifconfig", {"clientIp": "x"}, True)]
        self.assertEqual(geolocate.describe_probes(probes),
                         "cloudflare=silent,ipinfo=silent,ifconfig=ok")

    def test_it_is_a_string_because_it_crosses_a_process_boundary(self):
        """`posix_run_geolocate` shares values as `c_wchar` arrays."""
        self.assertIsInstance(geolocate.describe_probes([]), str)

    def test_get_meta_vars_returns_it(self):
        probes = [geolocate.ProviderProbe("cloudflare", None, False),
                  geolocate.ProviderProbe("ipinfo", None, True),
                  geolocate.ProviderProbe("ifconfig", None, True)]
        with mock.patch.object(geolocate, "probe_providers",
                               return_value=({"clientIp": "198.51.100.4"}, probes)), \
                mock.patch.object(geolocate, "detect_dns_blackhole",
                                  return_value=False):
            result = geolocate.get_meta_vars()
        self.assertEqual(result[7], "cloudflare=silent,ipinfo=ok,ifconfig=ok")


class TestReachabilityDifferential(unittest.TestCase):
    @staticmethod
    def _probes(*reachable):
        return [geolocate.ProviderProbe(f"p{i}", None, ok)
                for i, ok in enumerate(reachable)]

    def test_no_probes_is_not_a_differential(self):
        self.assertFalse(geolocate.is_reachability_differential(None))
        self.assertFalse(geolocate.is_reachability_differential([]))

    def test_all_reachable_is_not_a_differential(self):
        self.assertFalse(geolocate.is_reachability_differential(
            self._probes(True, True, True)))

    def test_one_silent_of_three_is_not_enough(self):
        """A single provider having a bad day must not relabel an open network:
        `dpi_cleared` keys off `open`, so a false `allowlisted` reads as a
        censorship finding."""
        self.assertFalse(geolocate.is_reachability_differential(
            self._probes(True, True, False)))

    def test_a_silent_majority_is_a_differential(self):
        self.assertTrue(geolocate.is_reachability_differential(
            self._probes(True, False, False)))

    def test_a_silent_majority_makes_a_reachable_network_allowlisted(self):
        meta = {"clientIp": "198.51.100.4"}
        self.assertEqual(geolocate.classify_network_state(
            meta, dns_blackhole=False,
            probes=self._probes(True, False, False)), "allowlisted")

    def test_omitting_probes_keeps_the_pre_m5f_behaviour(self):
        meta = {"clientIp": "203.0.113.7"}
        self.assertEqual(
            geolocate.classify_network_state(meta, dns_blackhole=False), "open")


class TestDetectDnsBlackhole(unittest.TestCase):
    def test_blackhole_detected(self):
        with mock.patch.object(geolocate.socket, "gethostbyname",
                               return_value=geolocate.BLACKHOLE_ADDR):
            self.assertTrue(geolocate.detect_dns_blackhole())

    def test_clean_resolution(self):
        with mock.patch.object(geolocate.socket, "gethostbyname",
                               return_value="93.184.216.34"):
            self.assertFalse(geolocate.detect_dns_blackhole())

    def test_resolution_error(self):
        with mock.patch.object(geolocate.socket, "gethostbyname",
                               side_effect=OSError("dns down")):
            self.assertFalse(geolocate.detect_dns_blackhole())

    def test_hung_resolver_does_not_block(self):
        # A hijacked/unresponsive resolver must not stall the measurement
        # (high-latency paths).
        def _hang(*_args, **_kwargs):
            time.sleep(5)
            return "1.2.3.4"

        with mock.patch.object(geolocate.socket, "gethostbyname", side_effect=_hang):
            start = time.monotonic()
            result = geolocate.detect_dns_blackhole(timeout=0.2)
            elapsed = time.monotonic() - start
        self.assertFalse(result)
        self.assertLess(elapsed, 1.0)


class TestGetMetaVarsIntegration(unittest.TestCase):
    def _patch(self, meta, blackhole, probes=None):
        if probes is None:
            # Every provider answered — the plain case, no differential.
            probes = [geolocate.ProviderProbe(p.name, None, True)
                      for p in geolocate.PROVIDERS]
        return (
            mock.patch.object(geolocate, "probe_providers",
                              return_value=(meta, probes)),
            mock.patch.object(geolocate, "detect_dns_blackhole", return_value=blackhole),
        )

    def test_open_path_populates_fields(self):
        meta = {"clientIp": "203.0.113.7", "asn": 13335,
                "asOrganization": "Cloudflare", "country": "US", "city": "Ams"}
        p1, p2 = self._patch(meta, False)
        with p1, p2:
            no_internet, public_ip, _, _, _, _, state, _ = geolocate.get_meta_vars()
        self.assertFalse(no_internet)
        self.assertEqual(public_ip, "203.0.113.7")
        self.assertEqual(state, "open")

    def test_shutdown_path_keeps_defaults(self):
        p1, p2 = self._patch(None, True)
        with p1, p2:
            no_internet, public_ip, _, _, _, _, state, _ = geolocate.get_meta_vars()
        self.assertTrue(no_internet)
        self.assertEqual(public_ip, "127.1.2.7")
        self.assertEqual(state, "shutdown")

    def test_allowlisted_when_meta_up_but_dns_blackholed(self):
        meta = {"clientIp": "203.0.113.7", "asn": 13335,
                "asOrganization": "Cloudflare", "country": "US", "city": "Ams"}
        p1, p2 = self._patch(meta, True)
        with p1, p2:
            result = geolocate.get_meta_vars()
        self.assertEqual(result[STATE], "allowlisted")
        self.assertFalse(result[0])

    def test_returns_seven_tuple(self):
        p1, p2 = self._patch(None, False)
        with p1, p2:
            self.assertEqual(len(geolocate.get_meta_vars()), 8)

    def test_a_silent_majority_is_allowlisted_even_with_clean_dns(self):
        """A measured tiered network, reproduced.

        DNS was not hijacked and a provider answered, so the old classifier said
        `open` — while the network silently dropped TCP to 8.8.8.8 and TCP/853
        everywhere. Only `ifconfig.co` had answered, which is why those runs are
        named `AS0` and report an unabbreviated country name.
        """
        meta = {"clientIp": "198.51.100.4", "asn": "", "asOrganization": "",
                "country": "Freedonia", "city": ""}
        probes = [
            geolocate.ProviderProbe("cloudflare", None, False),
            geolocate.ProviderProbe("ipinfo", None, False),
            geolocate.ProviderProbe("ifconfig", meta, True),
        ]
        p1, p2 = self._patch(meta, False, probes)
        with p1, p2:
            result = geolocate.get_meta_vars()
        self.assertEqual(result[STATE], "allowlisted")
        self.assertFalse(result[0])


class TestRunGeolocate(unittest.TestCase):
    def test_shutdown_short_circuit(self):
        result = geolocate.run_geolocate(network_mode="shutdown")
        self.assertEqual(len(result), 8)
        self.assertTrue(result[0])          # no_internet
        self.assertEqual(result[STATE], "shutdown")

    def _run(self, mode, detected_state):
        detected = (False, "203.0.113.7", "AS13335", "CF", "US", "Ams",
                    detected_state, "cloudflare=ok,ipinfo=ok,ifconfig=ok")
        with mock.patch.object(geolocate, "posix_run_geolocate",
                               return_value=detected), \
                mock.patch.object(geolocate, "windows_run_geolocate",
                                  return_value=detected):
            return geolocate.run_geolocate(network_mode=mode)

    def test_auto_keeps_what_the_detector_decided(self):
        self.assertEqual(self._run("auto", "open")[STATE], "open")

    def test_an_explicit_mode_overrides_the_detector(self):
        """The escape hatch for a misclassification. `--network-mode
        allowlisted` used to be parsed, passed down, and thrown away."""
        self.assertEqual(self._run("allowlisted", "open")[STATE], "allowlisted")
        self.assertEqual(self._run("open", "allowlisted")[STATE], "open")

    def test_an_override_keeps_the_fetched_metadata(self):
        result = self._run("allowlisted", "open")
        self.assertEqual(result[1], "203.0.113.7")
        self.assertEqual(result[2], "AS13335")
        self.assertEqual(len(result), 8)

    def test_posix_target_is_picklable_module_level(self):
        # Regression for "Can't pickle local object" on py3.14: the
        # multiprocessing.Process target in posix_run_geolocate must be a
        # module-level function (nested locals can't be pickled across the
        # spawn/forkserver boundary).
        self.assertNotIn("<locals>", geolocate._get_meta.__qualname__)
        import pickle
        pickle.dumps(geolocate._get_meta)  # module-level funcs pickle by name


if __name__ == "__main__":
    unittest.main()
