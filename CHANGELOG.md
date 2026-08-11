# Changelog

All notable changes to this project are documented in this file.
Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed (post-M7 audit)
- **An interrupted trace kept its pre-trace classification.** `Ctrl-C` wrote
  straight to disk, skipping the post-trace analysis entirely, so every detector
  was wrong at once: `dpi_cleared` true on an intercepted path, `cgnat_hop` false
  with an RFC 6598 hop sitting in the saved hops, `reply_forged` false with a
  reflected reply beside it. The evidence was all present and simply never read.
  It matters most exactly where it was missing — under
  `--timeout-profile shutdown` a trace runs for hours, so Ctrl-C is a normal way
  to end one.
- **`--anonymize` was ignored on that same path.** `_mirror_tracer()` rebuilt a
  `Tracer` from the module mirror, which shares the collected hops by identity
  but loses everything the run configured. It now hands back the live tracer,
  guarded by an identity check so a caller that rebinds `measurement_data` still
  gets a fresh one.
- **`dpi_cleared` could be true beside `reply_forged`.** A path cannot be
  cleared and impersonated at once; a forged reply is the strongest evidence of
  interception the tool has, and is now a term in the clearance test.
- **`--csv` crashed on any measurement taken with `-r 1` or `-r 2`.**
  `parse_json` hardcoded three repeats and indexed `res_from[2]`, so
  `IndexError` — uncaught, so a raw traceback. Most of `samples/` sets
  `repeat: 1`, and so does any run that prefers breadth. The width follows the data
  and short hops are padded; 3-repeat output is byte-identical to before,
  column order included.
- **`--csv` corrupted the file on a second conversion in one process.** The
  header and row templates are module-level and were appended to rather than
  reset, injecting a duplicate header at line 2 — the same defect class as
  `utils.vis`'s accumulating graph, found by looking for it.
- **`--csv` raised `IndexError` on an empty or invalid file**, after
  `parse_json` had already printed a tidy explanation.
- `test/test_csv.py` added (13 tests); the module had none.

### Added (Milestone 7 — forged-reply detection, backlog §2.12)
- **TraceVis now detects a reply the destination never sent.** This is the
  answer to the objection raised against §1.3: hardcoding `8.8.8.8` fixes the
  destination *field*, not the destination, and nothing in the outgoing packet
  can stop an on-path box answering in its place. The reply cannot hide, though.
  Two signals, either sufficient on its own:
  - **IP-ID reflection** — the reply carries the query's own IP ID, because the
    box mutated the request in place rather than composing an answer. 3/3 on the
    forged replies in the reference capture, 0/3 on the genuine ones, ~1 in
    65536 by chance. IP ID 0 is excluded (Linux writes it on DF packets).
  - **TTL implausibility** — the forged replies arrived with TTL 1 from a
    claimed nine hops out, implying an initial TTL of 10; the genuine ones imply
    61, 62 and 130. Flagged when the implied initial TTL falls below 32.
  - Recorded as `reply_forged` and `forgery_evidence` on every measurement, so
    the claim can be re-checked from the file rather than taken on trust, and
    drawn as its own node ("Forged reply (impersonating the destination)").
  - Validated over every measurement available, including unrestricted-network
    baselines: **no false positives and no misses**.
- Dropped from the original scoping, and said so rather than omitted: the **DF
  flag**, which the field write-up lists as a corroborator but which
  the genuine `8.8.8.8` reply in the same capture also lacks. **Back-TTL** was
  the originally proposed primary; the field data made it the corroborator.

### Fixed (Milestone 7)
- **`utils/vis.py` accumulated state between renders.** `multi_directed_graph`
  is module-level and nothing cleared it, so a second `vis()` call in one
  process drew the first measurement's nodes into the second file. The CLI
  renders once per run so it never surfaced in production, but it made `vis()`
  wrong as a function and untestable in isolation.
- **The test harness was less faithful than scapy.** `FakeNetwork` passed an
  unresolved packet, so `packet[IP].id` — a `RandShort()` volatile — returned a
  different value on every read. Real `sr()` iterates the packet, resolving
  volatiles once, and returns that concrete packet; the harness now does the
  same. Without it §2.12's primary signal could not be reproduced in a test.

## [1.1.0] — 2026-08-10

Everything below landed after `v1.0.0` (Aug 7): milestones M4 through M6, and
measurements from a censoring network that drove most of it. Highlights:

- **Detection built from measurement.** DPI/CGNAT/SNI classifiers, RST-flood and
  silent-drop signals, network-state detection with two independent allowlist
  signals, and a DNS-hijack test that catches on-path interception.
- **Resilience.** Port-pool rotation with live RST backoff, timeout profiles,
  opt-in adaptive per-hop timeouts, randomised retransmission IP IDs.
- **A refreshed, labelled sample pool**, including the three protocol shapes the
  threat report names, and a default target pool that is a control/treatment
  comparison rather than a list of resolvers.
- **`--anonymize`**, and the operator's own address removed from everything
  written to disk unconditionally.
- **A trace-loop test harness** (`test/test_tracer.py`), which immediately found
  a crash on `main` that was discarding whole runs.
- 254 tests, up from 7 at the start of M0.

### Added (Milestone 6c — the interactive console, backlog §2.9)
- **`--packet-input-method interactive` no longer requires IPython.** The stdlib
  `code.interact` fallback existed but sat *after* an unconditional
  `raise NotImplementedError`, so it was unreachable and anyone without IPython
  — which is not in `requirements.txt`, and is exactly what a restricted
  environment is likely to lack — was told "Currently Only IPython Console is
  supported!". The import failure is now caught and the built-in console used.
- **The prompt's namespace is scapy's**, so `IP(dst="1.1.1.1")/TCP()` works as
  the banner instructs. It used to be the reader's own `locals()` — `cls`,
  `show`, and the scapy *module* — so following the banner produced a NameError
  and the packet had to be built as `scapy.all.IP(...)`.
- **Leaving the console without assigning `p`** now says so. It was a `KeyError`
  swallowed by a bare `except:` and reported as IPython being absent — as was
  any error raised inside the session itself. Assigning something that is not a
  packet is also named rather than surfacing as an `AttributeError`.
- `test/test_packet_input.py` (13 tests) — this path had no coverage at all.

### Changed (Milestone 6c)
- The version now has a single source of truth (`utils.geolocate.VERSION`). The
  user-agent sent to metadata providers read `TraceVis/0.10.5` while the
  repository was tagged `v1.0.0`; it is the one version string that leaves the
  machine.

### Fixed (Milestone 6b — the DNS hijack detector was aimed at the wrong target)
- **`detect_dns_blackhole()` could never fire**, for two independent reasons,
  on a network that the same run proves is hijacking DNS: the blocked domain
  was answered from every resolver probed, with a spoofed source address, by one
  box sitting close to the operator.
  - It resolved **`example.com`** — `BLACKHOLE_PROBE_DOMAIN`, which is the
    *accessible control*. A domain that is not blocked is never hijacked, so
    the probe could only ever return False. It now resolves the blocked domain
    (`www.twitter.com`, mirroring `utils.dns.DEFAULT_BLOCKED_ADDRESS`).
  - It compared against **`10.10.34.34`** exactly, and the observed answer was
    `.35`. Membership is now tested against the filter net `10.10.34.0/24` via
    the new `utils.dpi.is_blackhole_address`, which also replaces the two other
    exact-match tests (`_Provider.probe`, `classify_network_state`) and
    `utils.dns.filter_blackholed`.
  - A confirmed hijack prints why, and takes the network to `allowlisted` —
    which such a network now classifies as, on the DNS evidence alone, without
    needing the provider differential.

### Added (Milestone 6b)
- **Measurements record which metadata providers answered** —
  `provider_status: "cloudflare=silent,ipinfo=ok,ifconfig=ok"`. `network_state`
  was recorded without its evidence, so working out whether a saved capture had
  been classified by a DNS hijack, by the provider differential, or by a build
  predating either meant inferring it from which metadata fields happened to be
  populated. A string, not a structure, because it crosses the `multiprocessing`
  boundary in `posix_run_geolocate` where values are `c_wchar` arrays.
  `run_geolocate` and `get_meta_vars` now return an 8-tuple.

### Added (Milestone 6a — `--anonymize`, backlog §2.8)
- **The operator's own address no longer reaches disk, in any mode.** Measured
  rather than assumed: the public address was already scrubbed everywhere, but
  the *local* one survived in `src_addr`, in each hop's `summary`, and in every
  stored packet blob. `set_endtime` only removed it when it
  equalled the public address — true for a host with no NAT in front of it, and
  for nobody this tool is aimed at. It carries no measurement value:
  `Tracer.send_packet` overwrites `IP.src` on every probe.
- **`--anonymize` additionally pseudonymises RFC 1918 hops** into RFC 5737
  TEST-NET-1 (`192.0.2.0/24`), stably within a run so the graph still merges one
  box into one node. Opt-in because hop addresses *are* measurement data — hop
  count, the shape of the access network, where the NAT sits.
  - **CGNAT (RFC 6598) hops are kept even under the flag.** They are the
    carrier's, not the operator's, and `utils.dpi.is_cgnat_address` reads them
    back out of the saved hops to set `cgnat_hop`; scrubbing them would have
    silently disabled that detector.
- **Every dumped `.conf` now carries the sentinel source.** This was the leak
  chain that put LAN addresses into `samples/`: a run writes a config containing
  the packet exactly as held, and those configs become samples.
  `_read_pasted_packet` applied the sentinel, the JSON input path did not.
- **The nine leaking samples were rewritten** to the sentinel source, with IP
  *and* L4 checksums recomputed —
  the transport checksum covers an IP pseudo-header, so the new source
  invalidates it too. Behaviour-neutral: the tracer clears both before sending.

### Fixed (Milestone 6a)
- **`samples/quicvd29.conf` shipped a stale checksum pair.** Its source had been
  rewritten to the sentinel at some earlier point without recomputing, so its IP
  and UDP checksums did not verify against their own header — a sharper
  fingerprint than the address was. Found only because the checksum assertion
  guarding this was itself vacuous: it compared a parsed packet against a
  rebuild of itself, and a rebuild keeps a checksum that is already set.
- `test/test_geolocate.py` no longer uses the operator's real public address as
  a fixture (RFC 5737 `198.51.100.4` instead).

### Changed (Milestone 5g — the default target pool, backlog §1.3)
- **The default resolver pool is now a labelled comparison, not a list of
  resolvers that ought to work.** The item was originally scoped as "these
  defaults are unreachable under an allowlist, replace them". Acting on that
  would have made the tool worse: **`8.8.8.8` being unreachable *is* the
  measurement**, and a pool where everything answers is unfalsifiable by
  construction: a contrast only reads as a result when the sweep contains both
  a destination that answers and one that does not.
  - Each entry now answers a distinct question, and says so both in
    `utils/dns.py` and on stdout at run time —
    `default targets: 1.1.1.1 (control), 1.0.0.1 (same-operator control), 8.8.8.8 (treatment)`.
    `1.0.0.1` is Cloudflare like `1.1.1.1` and was field-confirmed *unreachable*
    on 2053 in the same run where `1.1.1.1` answered, which is what separates a
    per-IP allowlist from a per-operator one.
  - Only `9.9.9.9` was dropped, and for redundancy rather than for failing:
    everywhere it was measured it was simply unreachable, duplicating
    `8.8.8.8`'s role. That shortens every `--dnsdot` and `--sni-test` default run
    by a quarter (both drew on the 4-entry DoT pool).
  - `samples/dnstt.conf` retargeted to match.
- **Addresses stay literals, deliberately.** Resolving them would hand the choice
  of destination to whatever resolver the network provides, which under a
  DNS-hijack regime is the thing being measured.

### Verified, not changed
- **`filter_blackholed()` does not silently drop the treatment.** It runs over
  the pool at trace time, and a pool that lost its unreachable half would leave
  runs that cannot fail. It compares against the literal `10.10.34.34`, which a
  pool of literals never contains, so it removes nothing — now pinned by
  `test_no_default_target_is_ever_filtered_out`.
- **Literals do not defend against on-path redirection**, and nothing in the
  destination field could: a transparent UDP/53 redirect to a local resolver
  looks identical on the wire. Filed as backlog §2.12 — TraceVis already records
  `from` and a back-TTL per hop, so a forged answer written close to the
  operator would not fit the path it claims to have travelled.

### Fixed (Milestone 5f — bugs surfaced by running against a restricting network)
- **A refused TCP handshake destroyed the entire run.**
  `send_packet_with_tcphandshake` treated any non-empty answer list as a
  SYN-ACK, but a SYN is also answered by an ICMP error (a filtering middlebox)
  or an injected RST. On the ICMP answer the reply is
  `IP/ICMP/IPerror/TCPerror`, and scapy ≥ 2.6 no longer resolves `TCPerror` as
  `TCP` — so `ans[0][1][TCP]` raised `IndexError: Layer [TCP] not found`,
  `tracevis.py` turned it into `sys.exit(2)`, and **every hop collected up to
  that point was lost**. The RST case did not crash: it sent the ACK and the
  data packet on a connection that had just been refused. Both are now
  recognised as failed handshakes.
  - A refusal is **not retried** — silence still gets the five-SYN ladder, but a
    box that answers is awake, and a five-fold SYN burst at a censor's DPI is
    not a safe default.
  - The refusing box does **not** become a hop: the handshake SYN goes out at
    the default TTL, so it is not the hop under test.
  - A star hop can now carry evidence. `note` (what answered the SYN) and
    `rst_count` are recorded when there is something to say, and `utils/vis.py`
    renders the note into the hop tooltip. A plain timeout serialises exactly as
    before.
  - Handshake RSTs now reach the classifiers. A refused handshake never sends a
    data packet, so its RSTs were invisible to `rst_flood` and to M5c's port
    rotation — the signal that leads a reset-injection diagnosis.
- **Three scapy `SyntaxWarning`s at the head of every run**, the first before
  the banner, so a normal start looked like a failure. scapy ≥ 2.6 deletes
  `iface` from every layer-3 send and warns, since an L3 socket picks its
  interface from the routing table. The kwarg is gone — and with it the
  discovery that **`--iface` was a no-op**: scapy had been deleting it. An
  explicit `--iface` now sets `conf.iface`, the supported lever at L3.

- **`cgnat_hop` never fired, on any network** (backlog §2.11). It was derived
  from `network_state == "allowlisted"` alone — i.e. it was the network-state
  flag wearing a second name — so it stayed `False` even on traces that crossed
  an obvious RFC 6598 hop. The detector had called
  the network `open`, because the provider it reaches is itself allowlisted.
  It is now derived from evidence: `utils.dpi.is_cgnat_address()` tests hops
  against RFC 6598 `100.64.0.0/10`, and `recompute_dpi_from_per_hop` checks
  every hop it already walks. RFC 1918 space is deliberately excluded — a flag
  that fires on every home LAN says nothing.
  - **`dpi_cleared` no longer depends on `cgnat_hop`.** The clause was inert
    (`cgnat_hop` implied `allowlisted`, `dpi_cleared` requires `open`), and
    keeping it would have made every carrier behind 100.64/10 — most of them
    censoring nothing — report an uncleared path. Being NATted is a fact about
    the topology; being inspected is a fact about the DPI.
  - `traceroute_data` now records `network_state`. `utils/vis.py` had been
    reconstructing the regime from `cgnat_hop`, which only worked while the two
    were the same thing; measurements written before this field still get the
    old inference.
  - The tooltip already reported `CGNAT hop`, so existing measurements show the
    corrected flag on re-render without re-tracing.

- **A tiered-access network that does not hijack DNS classified itself as
  `open`.** `classify_network_state` had exactly one allowlist signal — DNS
  resolving to the report's blackhole address — so a network that blocks by
  silently dropping TCP instead came back `open`. That
  propagates: `dpi_cleared` requires `open`, so every path that reached its
  destination was reported as having cleared the DPI.
  - The missing signal was already sitting in the run. `fetch_meta` stopped at
    the first provider that answered, so nobody noticed that **only
    `ifconfig.co` answered** — Cloudflare and ipinfo did not, which is why those
    captures are named `AS0` and report an unabbreviated country name
    rather than `IR`. Providers are now all probed, and a **silent majority**
    with at least one still answering is the allowlist signature
    (`is_reachability_differential`).
  - Reachability is deliberately measured at the transport level, not the
    payload: an HTTP error status (a rate-limited ipinfo.io, an outage) counts
    as *reachable*, so it cannot look like censorship. A connection failure, a
    blackholed answer, or a non-JSON body counts as silent.
  - A **strict majority** is required. One provider having a bad day must not
    relabel an open network, because a false `allowlisted` reads as a
    censorship finding.
  - The run now prints which providers stayed silent, since this state decides
    `dpi_cleared` for the whole measurement.
- **`--network-mode open|allowlisted` was parsed, passed down, and discarded.**
  Only `shutdown` did anything. All three now take effect; the explicit modes
  override the detector's verdict (and say so) while still fetching the public
  IP and ASN. This is the escape hatch when the classifier is wrong about a
  particular network.

### Added (Milestone 5f)
- A field write-up (kept locally) covering the restricted-network runs.
  Headline: the **per-destination allowlist model beats the rate model** (with
  `8.8.8.8` probed *first* it still failed while `1.1.1.1` succeeded 3/3), the
  SNI made no difference on either destination, and `1.1.1.1` was reachable on
  **443, 8443 and 2053** — so "non-443 is safer" has nothing
  to be safer than. No RSTs were observed at all. Also records that the
  `grpc-h2c`/`shadowsocks`/`wireguard` A/Bs are confounded by their
  destinations (backlog §2.10) and that `cgnat_hop` never fires despite an
  obvious RFC 6598 hop (backlog §2.11).

### Added (Milestone 5e — protocol-shape probes)
- **Three protocol shapes the report names but the pool had no probe for**
  (backlog §2.5). Each is a **controlled A/B** — two probes
  differing in exactly one thing, so a difference in outcome has one
  explanation. Regenerate with
  `PYTHONPATH=. python3 tools/build_protocol_samples.py`.
  - `samples/grpc-h2c.conf` — TLS ClientHello (control) vs an **HTTP/2 cleartext
    preface**, both to `1.1.1.1:443` with a handshake. §4.2 says 443 is
    deep-inspected and "non-TLS patterns trigger RST"; the h2c preface is the
    cleanest non-TLS pattern available.
  - `samples/shadowsocks.conf` — same control vs **Shadowsocks AEAD opening
    bytes** (32-byte salt + length block + chunk: headerless and high-entropy by
    design). Tests whether 443's DPI rejects payloads that are not TLS-shaped.
  - `samples/wireguard.conf` — **WireGuard handshake initiation** (type 1,
    148 bytes, whitepaper §5.4.2) vs same-length random UDP on 51820. If the
    WireGuard arm dies earlier, the DPI matched the *pattern*, not "unknown UDP
    on an odd port".
  Both TCP samples pin `1.1.1.1:443`, the only destination observed completing
  a handshake — without one the probe is a stray PSH/ACK that any stack drops
  and the run answers nothing.

### Fixed (Milestone 5e)
- **`--port-pool` no longer silently breaks the DNS probes.** The pool rewrote
  the destination port away from 53/853, so the run measured the reachability of
  an arbitrary port instead of DNS — nothing answers on UDP/2053. Observed in
  a clean-network smoke run, which recorded `port: 2053` for a `--dns` trace. The pool is now dropped with a notice for `--dns`/`--dnstcp`/
  `--dnsdot`/`--dnstt`; an explicit `--port` is still obeyed (with a warning),
  since "is UDP/2053 reachable?" is a legitimate question.
- **Retransmission traces no longer carry a constant IP-ID signature**
  (backlog §1.7). `--rexmit` set `id += 15` on the stored packet, so
  every such trace started at *a committed sample's ID plus exactly 15* — a
  ready-made correlation handle. The starting ID is now random, matching what
  `send_single_packet` already does for every other probe. The
  per-retransmission `id += 1` is deliberately kept: real OS retransmissions
  increment sequentially, so randomising every packet would make the probe look
  *less* like the stream it imitates.

### Fixed (Milestone 5b/c — trace harness)
- **Every single-packet trace lost all of its results.**
  `_recompute_dpi_from_per_hop` (added in `fdffb1a`) walked both blocks of
  `measurement_data` unconditionally, but the second is only populated when a
  second packet is configured. A one-packet trace therefore raised `IndexError`
  *after* the trace completed and *before* `save_measurement_data` ran;
  `tracevis.py` catches it, prints `Error!`, and exits 2. Eight of the twelve
  shipped samples are single-packet (`clienthello`, `httpget`, `ntp`,
  `portpool_degraded`, `syn443`, and the four `quic*`), and the runs all
  used two-packet modes (`--dns*`, `--sni-test`), so nothing caught it — no test
  had ever run a trace. Under `--timeout-profile shutdown` this discarded a run
  that could have taken hours. Found by the new harness below.

### Changed (Milestone 5b/c — Tracer refactor, backlog §2.6)
- `utils/trace.py` state moved onto a **`Tracer` class**. `trace_route` keeps a
  byte-identical signature and remains the entry point; the pure helpers stay
  module-level. A running tracer republishes `measurement_data`/`have_2_packet`
  to the module names — the same list object, so `tracevis.py`'s Ctrl-C handler
  still reaches live data after `trace_route` has raised. Proved equivalent by an
  AST diff of every moved body (including the 135-line trace loop), not only by
  tests. Note that backlog §2.6's "for concurrency" framing oversells it: nothing
  runs traces in parallel and this does not change that. The benefit is per-run
  state and testability.

### Added (Milestone 5b/c — live backoff)
- **RST-triggered port rotation** (backlog §1.5).
  `utils.portpool.PortRandomizer` shipped in M2 and had never been called during
  a trace; the per-hop RST count now feeds `register_rst`, and crossing the
  threshold cools the port off and rotates. Armed only with `--port-pool`, fires
  only on the threshold, never under `--paris` (the preflight bakes the port into
  the packets it replays). A run that sees no flood is unchanged.
- **Per-hop destination port** recorded in `add_hop` and preferred by
  `utils/vis.py`. Rotation makes the path-level `port` only a starting value, and
  `sni_inspected` gates on `dport == 443`, so without this every hop after a
  rotation would be classified against a port it never probed. Older measurement
  files have no per-hop value and keep the previous behaviour.
- **`--adaptive-timeout`** (backlog §1.8), off by default. Grows the
  per-hop timeout toward the last observed RTT (scale 3, cap 60s), tracked per
  (packet, destination). Only *answered* hops record an RTT: `parse_packet`
  returns wall-clock elapsed even on a timeout, so feeding that back would
  ratchet any blocked path to the cap on the second TTL step.

### Fixed (Milestone 5b/c — `--paris` preflight)
- The preflight hardcoded `timeout=1`, silently ignoring `--timeout-profile` on
  the one handshake whose result every TTL then replays.
- A failed preflight still replays the bare SYN — there is no valid seq/ack for
  the intended packet once the handshake has failed — but it no longer does so
  quietly: it warns, and appends a note to the measurement's annotation so the
  confound is visible from the saved JSON.

### Added (Milestone 5b/c — trace harness)
- `test/test_tracer.py` (17 tests): the first coverage of `utils/trace.py`'s send
  path and trace loop. The M5 architecture notes recorded "no
  packet-capture test harness" as the blocker for the globals→`Tracer` refactor;
  this removes it. `utils/trace.py` does `from scapy.all import sr`, so patching
  `utils.trace.sr` intercepts every probe — no injection machinery, no root, no
  network. Pins the facts other work depends on: `send_packet` rewrites
  `IP.dst`/`ttl`/`src` per probe (why refreshing a sample's targets is a one-line
  `ips` edit), the trace loop is TTL-outermost and lock-stepped across
  destinations (the basis of the per-(destination, port) reinterpretation), and
  the handshake's five-SYN retry ladder (where the Reality sample's runtime
  estimate comes from). Two tests deliberately characterise *known defects* in
  the `--paris` preflight so the fixes are visible as behaviour changes.

### Fixed (build & CI — post-M5d audit)
- **The Docker image did not build.** `74753c9` installed `libcap2` (the shared
  library) but `setcap` ships in `libcap2-bin`, so the `RUN` layer aborted with
  `setcap: not found` (exit 127). Verified by building the committed Dockerfile.
- **The `setcap` layer would have bricked the image even if it had built.**
  `setcap cap_net_raw,cap_net_admin=eip` on the interpreter sets the file
  *effective* bit; when the container's bounding set lacks a listed capability
  the kernel fails the `execve` outright, and `NET_ADMIN` is **not** in Docker's
  default set. Reproduced on a minimal image: `docker run … python -c 'print(1)'`
  → `exec /usr/local/bin/python: operation not permitted`, as root *and* as
  non-root; it only ran with `--cap-add NET_ADMIN`. That breaks the two run
  recipes the README documents. The layer is removed — raw sockets come from
  the container's capabilities at run time (`--cap-add NET_RAW NET_ADMIN`),
  which is what the README already tells users to pass.
- Dropped `ruff`/`pytest` from the runtime image (dev-only; the suite is
  stdlib `unittest` and runs in the image without them).
- `.dockerignore`: `__pycache__/` only matched at the context root
  (`.dockerignore` patterns are not implicitly recursive) and nothing excluded
  the measurement output. The image carried **8.7 MB** of payload including
  `verify/`, whose JSON records a real public source IP. Now 1.0 MB.
- `.github/workflows/docker.yml`: the image was only ever built on
  `release: published`, which is how a broken Dockerfile reached `main`. Added a
  build-only job on push/PR that also smoke-tests the entrypoint under the
  **default** capability set and runs the suite inside the image.
- `.github/workflows/unittest.yml`: pinned `python-version: '3.14'`. A bare `3`
  resolves to whatever is current, while the geolocate multipath probe requires
  3.14's `multiprocessing` and the image pins `python:3.14-slim`.
- Bumped pinned actions to current majors: `actions/checkout@v7`,
  `actions/setup-python@v7`, `docker/build-push-action@v7`,
  `docker/login-action@v4`, `docker/metadata-action@v6`,
  `github/codeql-action/*@v4`.
- Restored the two field-analysis write-ups, now kept locally (removed in
  `027fc64`; restored, and since kept locally)
  **with the M5d correction applied in place**: the
  "connection-rate-based TCP blocking" conclusion and the earlier "stateful
  SNI-triggered blocking" reading are both marked superseded where they appear,
  and each report now carries the per-(destination, port) allowlist model with
  its probe-method caveat and the two runs that would settle it. The technical
  report's "extensions all present" note is annotated as predating the
  `utils/sni.py` framing fix. Their raw captures were not restored.
- Doc corrections: `test/test_samples.py` is **15** tests, not 10
  (CHANGELOG + `project-status.md`); the per-module test breakdown in
  `project-status.md` restated from actual counts; references to `res/res/` and
  `new-res/` now note that those captures were removed in `027fc64` instead of
  pointing at paths that no longer exist.

### Added (Milestone 5d — refreshed sample pool, backlog §2.5)
- `samples/reality-non443.conf` (new): a Reality-shaped probe pair — a real TCP
  handshake followed by a TLS ClientHello built with
  `utils.sni.build_tls_clienthello`, delivered as PSH/ACK data. Both probes
  borrow the same SNI (`hcaptcha.com`, a "well-selected SNI": a real domain a
  censor is unlikely to want to break) and are byte-identical apart from the
  per-hello TLS random and the **destination port**: 443 (control)
  vs 8443 (treatment), so one run isolates the port variable the
  "port ≠ 443 survives longer" claim rests on. Targets `1.1.1.1` — the only
  destination observed completing a handshake on 443 — with `repeat: 1`
  and `maxttl: 20` to bound cost. `--port`/`--port-pool` must not be added:
  they rewrite both packets to one port and collapse the comparison.
- `samples/dnstt.conf` (new): dnstt carrier probe over UDP/53 to
  `1.1.1.1,8.8.8.8,9.9.9.9` with `timeout_profile: shutdown`. This is the one
  channel observed still completing end to end.
- Seven generic path samples (`syn`, `syn443`, `portpool_degraded`,
  `quicv0xbabababa`, `quicv1ech`, `quicv1withsni`, `quicvd29`) retargeted to the
  refreshed pool `1.1.1.1,104.16.133.229,142.251.36.14,151.101.1.57`. Only the
  `ips` string changed — `utils/trace.py:285` rewrites `IP.dst` per probe, so no
  hexdump needed regenerating. `clienthello`, `httpget` and `ntp` keep their
  targets: their payloads name the destination.
- `test/test_samples.py` (new, 15 tests): the first real validation of the
  sample pool. `test_operationality.test_config_file` merges the config into the
  args dict and then compares it against itself, so it cannot fail on a
  misspelled key, a non-IPv4 packet or a contradictory mode. The new tests
  assert argparse-known keys, IPv4-decodable packets, `handshake` only on
  PSH/ACK packets (the loader silently drops it otherwise), valid targets within
  the 12-entry `REQUEST_COLORS` budget, and one-probe-mode-per-sample.

### Fixed (malformed TLS ClientHello extensions)
- `utils/sni.py::build_tls_clienthello` emitted three extensions that a strict
  TLS parser rejects, which affects `--sni-test` (the tool's headline probe) as
  well as the new sample: `supported_versions` (0x002b) omitted its 1-byte list
  length and declared an odd-length version list; `signature_algorithms`
  (0x000d) omitted its 2-byte list length; and extension 0x000a was labelled
  `ec_point_formats` while 0x000a is `supported_groups`, carrying 3 bytes valid
  as neither. A server answers `decode_error` instead of a ServerHello, and a
  DPI that parses extensions sees an anomalous hello — which would confound
  "this port is filtered" with "this hello is rejected everywhere". Now emits a
  correct `supported_versions`, `signature_algorithms`, `supported_groups`
  (x25519/secp256r1/secp384r1) and `ec_point_formats`.
- `test/test_sni.py::TestClientHelloStructure` (new, 3 tests): walks every
  extension and validates its inner length prefix. Reverting the fix fails 2/3.

### Fixed (sample loader silently accepted malformed packets)
- `utils/packet_input.py:183`: `_read_json_packet` **constructed**
  `BADPacketException` without raising it, so a hexdump that is not IPv4 (or
  does not start at the IP layer) was mis-parsed as garbage IPv4 and traced
  anyway. Now raised, which is what the surrounding `try/except
  BADPacketException` in `tracevis.py` already expected. Regression test in
  `test/test_samples.py::TestSampleLoaderGuards`.
- `tracevis.py:242,266`: comments claimed `timeout_profile` and `port_pool` had
  "no argparse dest" — both gained CLI flags in M5a.

### Fixed (interrupted-trace partial save)
- `utils/trace.py`: added `save_partial_measurement()` which flushes the
  in-flight global `measurement_data` to disk with a `-partial` timestamped
  name. `tracevis.py main()` now catches `KeyboardInterrupt` (a `BaseException`,
  previously missed by `except Exception`) around the `trace_route` call,
  flushes the partial file, and still renders the pyvis graph — so stopping
  TraceVis after a few hops no longer discards the partial result. Empty
  in-flight state returns `""` (no file written).
- `test/test_trace_partial.py` (new, 3 tests): partial two-packet save with
  `cgnat_hop`/`dpi_cleared` fields preserved, empty-data guard, and a
  regression check that `main()` has an `except KeyboardInterrupt` handler.

### Fixed (geolocate multiprocessing on Python 3.14)
- `utils/geolocate.py`: `posix_run_geolocate` passed a **nested local** function
  to `multiprocessing.Process`, which is unpicklable under 3.14's default
  (spawn/forkserver) start method and crashed *every* trace with
  `Can't pickle local object <function get_meta>`. Hoisted the target to the
  module-level `_get_meta` (now `pickle`-by-reference). This unblocks
  `--dns --dnsdot --dnstt --packet` (all paths call geolocate at trace start).
- `drop_privileges()` is now tolerated (non-fatal) when the caller already lacks
  root/CAP_SETGID, so non-root runs no longer stall at geolocate; the child
  proceeds to fetch metadata as the current user. (Full scapy `sr()` tracing
  still requires `sudo` for raw sockets.)
- `test/test_geolocate.py`: regression test
  `test_posix_target_is_picklable_module_level` (`__qualname__` has no
  `<locals>`; `pickle.dumps(_get_meta)` succeeds).

### Added (Milestone 5a — CLI ergonomics for resilient probing)
- `tracevis.py`: new CLI flags `--port-pool` (dest `port_pool`, CSV),
  `--timeout-profile` (dest `timeout_profile`, choices fast/degraded/shutdown),
  and `--network-mode` (dest `network_mode`, choices open/allowlisted/shutdown/
  auto, default `auto`). These expose the M2/M3 config-only knobs on the CLI;
  `process_input_args`'s `passed_args` override means CLI wins over config-file.
- `utils/trace.py`: `trace_route` gains `network_mode: str = "auto"`, threaded
  into `utils.geolocate.run_geolocate(network_mode=...)` (regimes:
  `shutdown` short-circuits, `open`/`allowlisted`/`auto` run full detection).
- `test/test_operationality.py`: `test_defaults` expected dict updated with the
  three new keys; new `test_port_pool_flag`, `test_timeout_profile_flag`,
  `test_network_mode_flag` cover the flags and the `auto` default.

### Notes (M5a)
- M5a deliberately stops at CLI exposure + `network_mode` plumbing. **Live
  per-hop** RST-backoff rotation (M5b) and the `trace.py` globals→class refactor
  that enables it remain deferred — see `project-status.md` pending work and
  the M5 scoping notes.

### Added (Milestone 4 — DPI/CGNAT/SNI classification + vis + struct)
- `utils/dpi.py` (new): pure `classify_dpi_path(is_nat, is_middlebox, is_pep,
  network_state, sent_proto, sent_dport)` → `DpiSignal(dpi_cleared, cgnat_hop,
  sni_inspected)` + `SNI_PORT = 443`. Heuristics pinned to the report:
  `cgnat_hop` on the allowlisted CGNAT tier (§2.3); `sni_inspected` only on a
  middlebox/PEP probe of TCP/443 (§4.2/§6); `dpi_cleared` only on `open` with
  no evidence (§4.5).
- `utils/traceroute_struct.py`: `traceroute_data` gains `dpi_cleared` /
  `cgnat_hop` / `sni_inspected` (bool, default False), serialized into the
  per-measurement JSON.
- `utils/trace.py`: after the geolocate 7-tuple (L533) + `initialize_json_first_nodes`,
  a path-level DpiSignal is stamped onto every `measurement_data` entry from
  `network_state` + probe L4 `(p1_proto, p1_port)` — every measurement is
  tagged before probing, per-hop loop untouched.
- `utils/vis.py`: per-hop DpiSignal (struct path-level field + `detect_nat_pep_middlebox`
  evidence + `measurement["proto"]/["port"]`) added to tooltips
  (`tooltips_append_lines`) + an `orange` diamond `DPI_COLOR`/`DPI_NAME` node
  for SNI-inspected hops that are not otherwise PEP/NAT/middlebox (no clobber).
- 12 new unit tests in `test/test_dpi.py` (classifier matrix + struct defaults/serialization).

### Notes (M4)
- M4 flags that **SNI inspection likely occurred** (middlebox/PEP on TCP/443),
  it does **not** parse TLS handshakes (scapy TLS is not a dependency); full
  DoT/DoH TLS client is backlog §4.
- Live per-hop DPI backoff in `trace.py` deferred to the globals→class refactor
  (backlog §2.6 / M5 perf pass).

### Added (Milestone 3 — DNS resilience: DoT/DoH + dnstt + blackhole routing)
- `utils/dns.py` rewritten as the single DNS-probe module. Adds
  `get_dns_packets` (UDP/53), `get_dot_packets` (TCP/853 DoT-shaped), and
  `get_dnstt_packets` (UDP/53 dnstt-shaped) packet builders, all returning the
  same 4-tuple shape `(packet_1, annotation_1, packet_2, annotation_2)` so the
  `main()` DNS branch unpacks uniformly. Adds `build_dns_query(...)` (tunable
  proto/dport) and `filter_blackholed(resolvers)` which drops the GFW blackhole
  `10.10.34.34` before egress.
- New constants mirroring the report: `BLACKHOLE_ADDRESS`,
  `DEFAULT_BLOCKED_ADDRESS` (`www.twitter.com`, a tiered block),
  `ACCESSIBLE_ADDRESS` (`www.example.com` control), `DEFAULT_DNS_RESOLVERS` /
  `DNSTT_RESOLVERS` (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9).
- `tracevis.py`: new mutually-exclusive flags `--dnsdot` and `--dnstt`
  (DNS tunnelling / port-443 inspection); plain `--dns` (UDP/53)
  remains default. `process_input_args` enforces mutual exclusion and routes
  into `main()`'s unified DNS branch which applies `filter_blackholed` to the
  resolver list (no blackholed resolver reaches the 7-tuple annotation).
- 13 new unit tests in `test/test_dns.py` (builders, 4-tuple shape, blackhole
  filtering vs report constants); `test/test_operationality.py` arg-dict
  fixture extended with `dnsdot`/`dnstt` and cleaned of pre-existing lint
  smells (I001/UP031).
- M3 architecture, review and validation notes (kept locally).

### Notes (M3)
- M3 ships reachability-shaped DNS probes (TCP-SYN-to-853 / UDP/53 path
  queries), not a real DoT/DoH TLS client (scapy TLS not a dependency). A real
  DoT/DoH client is tracked as a future enhancement (backlog §4).
- Live per-hop DNS backoff in `trace.py` deferred to the globals→class refactor
  (backlog §2.6 / M5 perf pass), consistent with M2's per-hop RST-backoff
  deferral.

### Added (Milestone 2 — packet-resilience timing + port-pool rotation)
- `utils/portpool.py`: `PortRandomizer` rotates a clean port pool
  and backs a port off (cooling-off) when it accumulates a RST-flood threshold
  on a RST flood. The default pool excludes the aggressively-inspected
  port 443. Ships `parse_port_pool()` (CSV/list/None).
- `utils/timing.py`: `resolve_timeout(profile, explicit)` maps
  fast(1s)/degraded(3s)/shutdown(60s) profiles where an
  explicit value wins; `adaptive_timeout()` grows the timeout toward a multiple
  of the last observed RTT, never shrinking below the base.
- `tracevis.py/main()` wires both **config-driven**: set `port_pool` and
  `timeout_profile` keys in a `--config-file` (no new argparse flags) to pick a
  rotated non-443 port and a stage-aware base timeout.
- `samples/portpool_degraded.conf` example demonstrating both.
- 25 new unit tests (`test/test_portpool.py`, `test/test_timing.py`).

### Notes (M2)
- The per-hop RST-backoff rotation is shipped as logic + tests; live wiring into
  the `trace.py` trace loop is deferred to the planned globals→class refactor
  (backlog §2.6) to avoid regressing rexmit/paris semantics.

### Added (Milestone 1 — allowlist-aware network detection)
- Multi-provider external metadata detection. `utils/geolocate.py` now falls
  back across Cloudflare → ipinfo → ifconfig instead of relying solely on the
  Cloudflare speed endpoint (which is CGNAT'd and SNI-inspected per the
  an allowlisted CGNAT tier).
- DNS-hijack (GFW blackhole `10.10.34.34`) detection with a bounded-timeout
  resolver probe so an unresponsive/hijacked resolver cannot stall a
  measurement.
- Pure `classify_network_state()` classifier emitting one of
  `open` / `allowlisted` / `shutdown` / `unknown`, covering the network-layer
  allowlist tier as well as the outright-block case.
- Metadata + DNS-blackhole probes now run concurrently within a 10s budget so
  the network state is classified even during a total shutdown (previously
  timed out to a stale `unknown`).
- `--network-mode` parameter accepted on `run_geolocate()` (reserved; only
  `shutdown` short-circuits today).
- 20 new unit tests in `test/test_geolocate.py` (no live network required).

### Changed
- `utils.geolocate.run_geolocate()` now returns a 7-tuple; the 7th element is
  the classified `network_state`. Sole caller updated (`utils/trace.py:533`).
- A trace now prints the detected network state (e.g.
  `· · · - · network state: shutdown`).

### Notes
- Default behaviour is preserved for open networks (`network_mode="auto"`).
  State-driven endpoint / timeout selection lands in Milestone 2.
