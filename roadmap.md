# Roadmap

Phased plan to make TraceVis accurate/robust in severe restriction networks
(allowlist, DPI-reassembly, CGNAT, port-443 inspection, RST floods, BGP withdrawal).
Each milestone ends with green tests and a written review.

---

## Milestone 0 — Foundation (DONE)

- [x] Read full project.
- [x] Baseline: 7 unit tests pass; scapy/pyvis/networkx installed (py3.14).
- [x] Produced `backlog.md`.

## Milestone 1 — Allowlist-aware network detection & state (P0: 1.1, 1.2)

Goal: Stop the false "no internet" failures caused by relying solely on
`speed.cloudflare.com` (CGNAT'd + SNI-filtered) under the new regime.

Scope:
- Refactor `utils/geolocate.py` into a pluggable **multi-provider detector**
  (Cloudflare speed, Akamai meta, Fastly metadata, an allowlisted IP ICMP probe).
- Add **network-state classification**: `open` | `allowlisted` | `shutdown` |
  `unknown`, derived from reachability heuristics.
- Expose `--network-mode {auto,open,allowlisted,shutdown}` CLI on `tracevis.py`;
  in `auto` mode the detection chain runs before tracing.
- **Tests**: unit tests with mocked HTTP/ICMP responses for each provider +
  state-classification logic; no live network required.

Acceptance:
- 100% of new + existing tests pass.
- `geolocate` module unit-covered for all 4 states + 2 failure modes.
- No change to default CLI behavior when online (preserve API).

## Milestone 2 — Packet entropy & RST-flood resilience (P0: 1.4, 1.5, 1.7, 1.8)

Goal: Make TTL-stepped traces survivable against stateful DPI / RST floods /
port-443 deep inspection.

Scope:
- Add port-pool rotation (`--port-pool`) + RST-flood backoff that hops ports.
- Randomize retransmission `IP.id` increments (replace `id += 15`).
- Add adaptive timeout scaling per hop + `--timeout-profile {fast,degraded,shutdown}`.
- Keep `--port` backward compatible.

Acceptance: testable via scapy loopback simulation (RST flood + blackhole).

## Milestone 3 — DNS resilience (P0: 1.6)

Scope: DoT/DoH + dnstt packet support + blackhole detection; refresh DNS targets.

## Milestone 4 — DPI-aware detection & struct (P1: 1.9, 2.0, 2.1)

Scope: classifiers in `vis.py` + new `traceroute_data` fields + IPv6 path.

## Milestone 5 — Visualization & samples (P2: 2.3, 2.5)

Scope: new node types, phase overlay, refreshed sample configs.

- [x] **M5a** — CLI ergonomics (`--port-pool`, `--timeout-profile`, `--network-mode`).
- [x] **M5d** — refreshed sample pool (§2.5): `reality-non443.conf` +
  `dnstt.conf` added, seven generic samples retargeted, `test/test_samples.py`
  added as the first real validation of `samples/`.
- [x] **M5b/c** — globals→`Tracer` refactor (§2.6) + live RST-triggered port
  rotation (§1.5) + opt-in `--adaptive-timeout` (§1.8). Unblocked by
  `test/test_tracer.py`, the packet harness whose absence caused the original
  deferral. DPI backoff descoped — its trigger (`sni_inspected`) is only
  derivable post-trace in `vis.py`, so it cannot fire mid-loop; see
  the architecture notes. Smoke-tested on an unrestricted network; the backoff
  paths still need a restricting network to fire against.
- [ ] `ipv6-quic.conf` — **blocked** on backlog §2.1: the codebase is IPv4-only
  (`utils/packet_input.py::_supported_or_correct`, `utils/vis.py` `IPv4Address`,
  `utils/traceroute_struct.py` `af=4`), so an IPv6 sample cannot load or trace.

- [x] **M5e** — three protocol-shape A/B samples
  (`grpc-h2c`, `shadowsocks`, `wireguard`), `--port-pool`
  guarded against the port-bound DNS modes, and §1.7 retransmission IP-ID
  randomisation. `backlog.md` corrected — five completed items were still
  showing as open.

- [x] **M5f** — four defects surfaced by running the refreshed pool against a
  restricting network: a TCP handshake answered by an ICMP error or an injected
  RST crashed the run and discarded every hop collected (`Layer [TCP] not
  found`); three scapy `SyntaxWarning`s opened every run because `iface` is
  deleted at layer 3, which also meant `--iface` had been a no-op; `cgnat_hop`
  was `network_state` under a second name, so it could never fire; and the
  network-state detector called a tiered network `open` because a DNS hijack was
  its only allowlist signal.


- [x] **M5g** — the default target pool (backlog §1.3). Rescoped on review:
  removing destinations that fail would leave a pool where everything answers,
  destroying the contrast that makes a result readable. Curated into labelled
  roles (control / same-operator control / treatment) instead, one redundant
  entry dropped, literals kept, and `filter_blackholed()` verified inert against
  the pool. The limit of literals — on-path UDP/53 redirection — became §2.12.


## Milestone 6 — Hardening (P3: 2.8, 2.9) + docs

Scope: `--anonymize`, drop IPython hard-dep, CHANGELOG, README update, release.

- [x] **M6a** — `--anonymize` (§2.8). The operator's own address is now removed
  from everything written to disk, unconditionally; private-hop pseudonymisation
  is the opt-in half, since hop addresses are measurement data. CGNAT hops are
  kept so `cgnat_hop` keeps working. Closed the leak chain that put LAN
  addresses into `samples/` and rewrote the nine that had them — which turned up
  a stale checksum pair in `quicvd29.conf` that a vacuous assertion had been
  hiding.
- [x] **M6b** — the DNS hijack detector, corrected against measurement. It
  resolved the *accessible* control domain and compared against a single
  address, while the filter uses that whole prefix.
  Both fixed, plus `provider_status` recorded in every measurement so a state
  can be re-read for its evidence.
- [x] **M6c** — the interactive console (§2.9), README, release. IPython was
  never in `requirements.txt` but the stdlib fallback sat after an
  unconditional `raise`, so it was unreachable; the prompt's namespace was the
  reader's own `locals()` rather than scapy's, so the banner's instruction did
  not work as written. `test/test_packet_input.py` covers the path for the first
  time. README corrected in `cf036c9`; version given a single source of truth.

## Milestone 7 — Forged-reply detection (§2.12)

- [x] IP-ID reflection plus TTL implausibility, each sufficient alone. Built
  against a labelled capture holding both forged and genuine replies, and
  validated to zero false positives across every measurement available.

**The roadmap is complete.** What remains is in `backlog.md`: 2.4 (node
tint of allowlisted-tier nodes), 2.7 (`--monitor`), 2.1 (IPv6), 2.10 (needs a
controlled endpoint), and 1.4 (needs rescope first). §2.2 (multi-VP + IODA)
and §2.3 (CGNAT/allowlist node types + phase overlay) are shipped.

---

## Execution discipline

Every milestone task runs the full gate:
Planning → Architecture Review → Implementation → Static Analysis →
Code Review → Security Review → Performance Review → Testing →
Validation → Documentation → Merge.

A review note, a validation note and any architecture decisions are written
after each task and kept with the working notes. `CHANGELOG.md` is updated on
each merge.
