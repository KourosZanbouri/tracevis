#!/usr/bin/env python3

import ctypes
import json
import os
import platform
import re
import socket
import time
from collections import namedtuple
from multiprocessing import Process, RawArray, Value
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import utils.dpi

OS_NAME = platform.system()

# --- Filtering DNS-hijacks resolve blocked names into this net ---
# Kept as a name for the canonical address; membership is tested against the
# whole /24 via `utils.dpi.is_blackhole_address` (see the note there).
BLACKHOLE_ADDR = utils.dpi.BLACKHOLE_ADDR
# Single source of truth for the version. The user-agent used to carry a
# hardcoded 0.10.5 while the repository was tagged v1.0.0 — it is the one
# version string that leaves the machine, so it is the one that should not drift.
VERSION = "1.1.0"
USER_AGENT = f'TraceVis/{VERSION} (WikiCensorship)'

# The domain the hijack probe resolves. It has to be one that is actually
# **blocked**: this was `example.com`, the accessible control, which is by
# definition never hijacked — so the probe returned False on a network that was
# demonstrably hijacking DNS — the blocked name was answered into the filter net
# from every resolver probed. Mirrors
# `utils.dns.DEFAULT_BLOCKED_ADDRESS`, duplicated rather than imported to keep
# this module free of scapy — it runs in a privilege-dropped subprocess.
# `test_the_probe_domain_matches_the_blocked_domain_used_elsewhere` keeps the
# two in step.
BLACKHOLE_PROBE_DOMAIN = "www.twitter.com"

# Network regimes, including the network-layer allowlist tier.
NETWORK_STATES = ("open", "allowlisted", "shutdown", "unknown")

# Probe budgets kept well inside the 10s parent wait window in run_geolocate
# so state is classified before the parent gives up.
META_TIMEOUT = 2       # per metadata provider (3 providers -> ~6s worst case)
DNS_TIMEOUT = 3        # DNS blackhole probe
DETECT_JOIN_TIMEOUT = 8  # cap a runaway probe thread


# One provider's outcome. `reachable` answers a narrower question than `meta`:
# did an HTTP transaction with the real provider complete at all? That is the
# question the allowlist signature is written in — see
# `is_reachability_differential`.
ProviderProbe = namedtuple("ProviderProbe", ["name", "meta", "reachable"])


class _Provider:
    """A single metadata provider.

    Relying on one endpoint (Cloudflare speed) is a single point of failure:
    that IP can be CGNAT'd and SNI-inspected like anything else, so it is often
    unreachable in restricted networks. Each provider is tried in order and
    the first usable result wins.
    """

    def __init__(self, name, url, normalize):
        self.name = name
        self.url = url
        self._normalize = normalize

    def probe(self, timeout):
        """Fetch metadata, and separately report whether the host answered."""
        try:
            req = Request(self.url, headers={"user-agent": USER_AGENT})
            with urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    return ProviderProbe(self.name, None, True)
                raw = json.load(response)
        except HTTPError:
            # An error *status* is proof the provider answered. Rate limits and
            # outages must not look like censorship, or a busy ipinfo.io would
            # relabel an open network. (HTTPError subclasses OSError, so this
            # has to be caught first.)
            return ProviderProbe(self.name, None, True)
        except (OSError, ValueError):
            # No HTTP transaction: connection refused, timed out, TLS failed,
            # DNS failed — or the body was not JSON, which is what an injected
            # block page looks like. None of these reached the provider.
            return ProviderProbe(self.name, None, False)
        meta = self._normalize(raw)
        # Reject blackholed responses: even if a provider answers, a hijacked
        # DNS may have directed us to the GFW blackhole IP.
        if utils.dpi.is_blackhole_address(meta.get("clientIp")):
            return ProviderProbe(self.name, None, False)
        if not meta.get("clientIp"):
            return ProviderProbe(self.name, None, True)
        return ProviderProbe(self.name, meta, True)

    def fetch(self, timeout):
        return self.probe(timeout).meta


def _normalize_cloudflare(raw):
    return {
        "clientIp": raw.get("clientIp", ""),
        "asn": raw.get("asn", ""),
        "asOrganization": raw.get("asOrganization", ""),
        "country": raw.get("country", ""),
        "city": raw.get("city", ""),
    }


def _normalize_ipinfo(raw):
    org = raw.get("org", "") or ""
    asn = ""
    org_name = org
    match = re.match(r"AS(\d+)\s+(.*)", org)
    if match:
        asn = int(match.group(1))
        org_name = match.group(2)
    return {
        "clientIp": raw.get("ip", ""),
        "asn": asn,
        "asOrganization": org_name,
        "country": raw.get("country", ""),
        "city": raw.get("city", ""),
    }


def _normalize_ifconfig(raw):
    return {
        "clientIp": raw.get("ip", ""),
        "asn": "",
        "asOrganization": "",
        "country": raw.get("country", ""),
        "city": raw.get("city", ""),
    }


# Cloudflare is tried first (it yields ASN/org) but is frequently CGNAT'd and
# SNI-inspected, hence the two fallbacks. Order matters: best metadata first.
PROVIDERS = [
    _Provider("cloudflare", "https://speed.cloudflare.com/meta", _normalize_cloudflare),
    _Provider("ipinfo", "https://ipinfo.io/json", _normalize_ipinfo),
    _Provider("ifconfig", "https://ifconfig.co/json", _normalize_ifconfig),
]


def probe_providers(timeout=9):
    """Probe every provider; return (first usable meta, all probe outcomes).

    Every provider is tried even once one has answered. The extra requests are
    the point: *which* providers answer is the signal. Under a tiered-access
    regime the allowlisted ones do and the rest do not, and that differential is
    the only thing distinguishing an allowlisted network from an open one when
    DNS is not being hijacked (see `is_reachability_differential`).

    Cost is bounded by the same budget as before — the restricted case already
    tried all three, because the first two were the ones failing.
    """
    probes = [provider.probe(timeout) for provider in PROVIDERS]
    meta = next((probe.meta for probe in probes if probe.meta is not None), None)
    return meta, probes


def fetch_meta(timeout=9):
    """The first usable meta dict, or None when no provider answered.

    A result is usable when it carries a non-empty, non-blackhole client IP.
    """
    return probe_providers(timeout)[0]


def describe_probes(probes):
    """`cloudflare=silent,ipinfo=ok,ifconfig=ok` — the evidence behind the state.

    Recorded in every measurement because the state alone is not checkable after
    the fact. Working out whether a saved capture had been classified by
    the DNS hijack, by the provider differential, or by a build that predated
    either meant inferring it from which fields the metadata happened to carry.

    A string rather than a structure because it crosses a `multiprocessing`
    boundary in `posix_run_geolocate`, where the shared values are `c_wchar`
    arrays.
    """
    return ",".join(
        probe.name + ("=ok" if probe.reachable else "=silent") for probe in probes)


def is_reachability_differential(probes):
    """True when most providers were silent while at least one still answered.

    This is the allowlist signature that the DNS-blackhole test misses. A
    measured tiered network was classified `open` — DNS was not hijacked to the
    blackhole, and *a* provider answered — while it silently dropped TCP to most
    destinations. The evidence was already in the run and unused: only one
    provider had answered, because the others were unreachable.

    A strict majority is required. One provider having a bad day — a rate limit,
    an outage, a DNS hiccup — must not be enough to relabel an open network,
    because `dpi_cleared` keys off `open` and a false `allowlisted` reads as a
    censorship finding.
    """
    if not probes:
        return False
    silent = sum(1 for probe in probes if not probe.reachable)
    return silent > (len(probes) - silent)


class DnsResult:
    """Result of a DNS blackhole probe.

    ``blackholed`` preserves the historical bool return of
    ``detect_dns_blackhole`` — a domain that resolved into the blackhole net.

    ``resolved`` is the new signal for GitHub issue #75: True when
    ``gethostbyname`` returned *any* answer at all, proving the network and
    resolver are reachable. ``detect_dns_blackhole`` used to return False for
    both "resolved cleanly" and "resolution failed", which collapsed two
    distinct signals into one and masked a connectivity proof.

    ``__bool__`` returns ``blackholed`` so existing callers that do
    ``assertTrue(detect_dns_blackhole())`` keep working unchanged.
    """

    __slots__ = ("blackholed", "resolved")

    def __init__(self, blackholed: bool, resolved: bool = False):
        self.blackholed = blackholed
        self.resolved = resolved

    def __bool__(self):
        return self.blackholed


def detect_dns_blackhole(probe_domain=BLACKHOLE_PROBE_DOMAIN, timeout=3):
    """Return :class:`DnsResult` indicating blackhole verdict and resolution.

    ``DnsResult`` is bool-coercible to ``blackholed`` for backward
    compatibility — ``assertTrue(detect_dns_blackhole())`` still checks the
    blackhole verdict.

    Resolution runs in a worker thread with a bounded ``timeout`` so that a
    hijacked, unresponsive resolver on a high-latency path cannot stall the
    whole measurement.
    """
    resolved = {"value": None}

    def _resolve():
        try:
            resolved["value"] = socket.gethostbyname(probe_domain)
        except OSError:
            pass

    worker = Thread(target=_resolve, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return DnsResult(False, False)
    if resolved["value"] is not None:
        return DnsResult(
            utils.dpi.is_blackhole_address(resolved["value"]),
            resolved=True,
        )
    return DnsResult(False, False)


def classify_network_state(meta=None, dns_blackhole=False, probes=None):
    """Pure classifier over observable signals.

    Returns one of ``NETWORK_STATES``:
      - ``shutdown``   : no provider reachable AND dns blackholed (total block)
      - ``allowlisted``: a provider is reachable, and either dns is blackholed
                         or most providers were silent (tiered access;
                         SNI filtering on allowlisted IPs)
      - ``open``       : provider reachable, dns clean, no reachability
                         differential
      - ``unknown``    : no signal (transient failure / dns clean but no meta)

    ``probes`` is the list from ``probe_providers``. Omitting it keeps the
    pre-M5f behaviour, where a hijacked DNS was the only way to see an
    allowlisted network — which is why one that does not hijack DNS read as
    ``open`` on a network that was demonstrably not.
    """
    reachable = (
        bool(meta)
        and bool(meta.get("clientIp"))
        and not utils.dpi.is_blackhole_address(meta.get("clientIp"))
    )
    if not reachable:
        return "shutdown" if dns_blackhole else "unknown"
    if dns_blackhole or is_reachability_differential(probes):
        return "allowlisted"
    return "open"


def get_meta_json():
    # Kept for backward compatibility; thin wrapper over fetch_meta.
    return fetch_meta(timeout=9)


def get_meta_vars():
    no_internet = True
    public_ip = '127.1.2.7'  # we should know that what we are going to clean
    network_asn = 'AS0'
    network_name = ''
    country_code = ''
    city = ''
    network_state = 'unknown'
    provider_status = ''

    print("· - · · · detecting IP, ASN, country, etc · - · · · ")
    # Fetch external metadata and probe DNS blackhole concurrently: this keeps
    # the result well inside the 10s parent wait window so the network state is
    # classified even in a total shutdown rather than stalling
    # until the parent gives up with a stale 'unknown'.
    meta_box = {"value": None, "probes": []}
    # dns_box stores the DnsResult from detect_dns_blackhole, which now carries
    # both the blackhole verdict and whether DNS resolution succeeded. The
    # resolution signal is what fixes GitHub issue #75: a successful DNS
    # response (even into the blackhole) proves the network is up, independent
    # of whether the metadata HTTP providers were reachable.
    dns_box = {"result": None}

    def _fetch_meta():
        meta_box["value"], meta_box["probes"] = probe_providers(
            timeout=META_TIMEOUT)

    def _probe_dns():
        dns_box["result"] = detect_dns_blackhole(timeout=DNS_TIMEOUT)

    # Both threads start before either join, so they run concurrently. The
    # sequential joins below do NOT serialise them — they simply mean the
    # main thread waits for meta first, then DNS. Both threads are racing the
    # network coming up during this window.
    meta_thread = Thread(target=_fetch_meta, daemon=True)
    dns_thread = Thread(target=_probe_dns, daemon=True)
    meta_thread.start()
    dns_thread.start()
    meta_thread.join(DETECT_JOIN_TIMEOUT)
    dns_thread.join(DETECT_JOIN_TIMEOUT)

    user_meta = meta_box.get("value")
    probes = meta_box.get("probes") or []
    dns_result = dns_box.get("result")
    if dns_result is None:
        dns_result = DnsResult(False, False)
    dns_blackhole = dns_result.blackholed
    dns_resolved = dns_result.resolved
    network_state = classify_network_state(user_meta, dns_blackhole, probes)
    provider_status = describe_probes(probes)
    if dns_blackhole:
        print("· · · - · DNS hijack confirmed: " + BLACKHOLE_PROBE_DOMAIN
              + " resolves into " + str(utils.dpi.BLACKHOLE_NETWORK))

    # Say *why*, whenever some providers answered and others did not. A state
    # the user cannot check is a state the user cannot trust — and this one
    # decides `dpi_cleared` for the whole run.
    silent = [probe.name for probe in probes if not probe.reachable]
    if silent and len(silent) != len(probes):
        print("· · · - · silent metadata providers: " + ", ".join(silent)
              + " (" + str(len(probes) - len(silent)) + " of "
              + str(len(probes)) + " answered)")

    # no_internet is only False when we have positive proof the network is up.
    # A metadata provider answering proves connectivity. So does a successful
    # DNS resolution — even into the blackhole, because gethostbyname returning
    # any answer means the resolver is reachable and the network is not down.
    # The old code checked only user_meta, so a run that started with no
    # internet and came up just before the DNS probe still reported
    # no_internet=True with stale placeholder metadata. GitHub issue #75.
    if dns_resolved or user_meta is not None:
        no_internet = False
    if user_meta is not None:
        if 'clientIp' in user_meta:
            public_ip = user_meta['clientIp']
            print("· · · - · " + public_ip)
            print('. - . - . we use public IP to know what to remove from data!')
        if user_meta.get('asn'):
            network_asn = ("AS" + str(user_meta['asn']))
            print("· · · - · " + network_asn)
        if user_meta.get('asOrganization'):
            network_name = user_meta['asOrganization']
            print("· · · - · " + network_name)
        if user_meta.get('country'):
            country_code = user_meta['country']
            print("· · · - · " + country_code)
        if user_meta.get('city'):
            city = user_meta['city']
            print("· · · - · " + city)
    return (no_internet, public_ip, network_asn, network_name, country_code,
            city, network_state, provider_status)


def drop_privileges():
    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    os.umask(0o077)


# Module-level (not nested) so multiprocessing can pickle the target across the
# spawn/forkserver boundary on modern Python (nested locals raise
# "Can't pickle local object" on 3.14's default start method).
def _get_meta(no_internet, public_ip, network_asn, network_name,
              country_code, city, network_state, provider_status):
    # drop_privileges requires root; if we lack the caps it means we are
    # already unprivileged, so fall through and still fetch metadata.
    try:
        drop_privileges()
    except (PermissionError, OSError):
        pass
    (no_internet.value, public_ip.value, network_asn.value, network_name.value,
     country_code.value, city.value, network_state.value,
     provider_status.value) = get_meta_vars()


def posix_run_geolocate():
    user_meta_info_timeout = 10   # Seconds
    no_internet = Value(ctypes.c_bool, True)
    public_ip = RawArray(ctypes.c_wchar, 40)
    public_ip.value = '127.1.2.7'
    network_asn = RawArray(ctypes.c_wchar, 100)
    network_asn.value = 'AS0'
    network_name = RawArray(ctypes.c_wchar, 100)
    country_code = RawArray(ctypes.c_wchar, 100)
    city = RawArray(ctypes.c_wchar, 100)
    network_state = RawArray(ctypes.c_wchar, 32)
    network_state.value = 'unknown'
    provider_status = RawArray(ctypes.c_wchar, 256)
    p = Process(target=_get_meta, daemon=True, args=(
        no_internet, public_ip, network_asn, network_name, country_code, city,
        network_state, provider_status))
    p.start()
    user_meta_info_start_time = time.time()
    while (time.time() - user_meta_info_start_time < user_meta_info_timeout) and no_internet.value:
        time.sleep(1)

    return (no_internet.value, public_ip.value, network_asn.value,
            network_name.value, country_code.value, city.value,
            network_state.value, provider_status.value)


def windows_run_geolocate():
    def get_meta():
        nonlocal no_internet, public_ip, network_asn, network_name, country_code, city, network_state, provider_status
        (no_internet, public_ip, network_asn, network_name, country_code,
         city, network_state, provider_status) = get_meta_vars()

    user_meta_info_timeout = 10   # Seconds
    no_internet = True
    public_ip = '127.1.2.7'  # we should know that what we are going to clean
    network_asn = 'AS0'
    network_name = ''
    country_code = ''
    city = ''
    network_state = 'unknown'
    provider_status = ''
    user_meta_info_start_time = 0
    p = Thread(target=get_meta, daemon=True)
    p.start()
    user_meta_info_start_time = time.time()
    while (time.time() - user_meta_info_start_time < user_meta_info_timeout) and no_internet:
        time.sleep(1)

    return (no_internet, public_ip, network_asn, network_name, country_code,
            city, network_state, provider_status)


def run_geolocate(network_mode="auto"):
    # threat windows and other posix systems differently
    # windows get suspicious when we spawn an independent Process
    # so we need to use thread for that
    # in other posix systems we need dropping privilege and as
    # this is not possible in python threads we stick to process for those systems
    #
    # network_mode gates behaviour by regime. "shutdown"
    # short-circuits (skips network I/O entirely); "auto" runs the full
    # detection chain and classifies from observed signals.
    #
    # "open" and "allowlisted" are the user overriding the detector, and are now
    # honoured as such. They used to fall through and have their answer thrown
    # away, which left no way to correct a misclassification — exactly the
    # situation a mis-classified tiered network is in. Metadata is still fetched, because
    # the public IP and ASN are needed regardless of the regime.
    if network_mode == "shutdown":
        return True, '127.1.2.7', 'AS0', '', '', '', 'shutdown', ''
    if os.name == "posix":
        result = posix_run_geolocate()
    else:
        result = windows_run_geolocate()
    if network_mode in ("open", "allowlisted"):
        if result[6] != network_mode:
            print("· · · - · network state overridden by --network-mode: "
                  + result[6] + " -> " + network_mode)
        return result[:6] + (network_mode,) + result[7:]
    return result
