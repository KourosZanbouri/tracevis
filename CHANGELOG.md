# Changelog

All notable changes to this project are documented in this file.
Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Upgrade notes
- **Captures taken before this release on a non-UTC host have shifted
  timestamps, and cannot be corrected.** `timestamp` and `endtime` were off by
  the negative of the host's UTC offset: −12600 s (−3 h 30 m) on a host in
  Iran, zero on a UTC host. The offset was never recorded, so there is nothing
  to correct them from. `endtime − timestamp` is unaffected. RIPE Atlas
  downloads were never affected, since their epochs come from Atlas.
- **`ioda_status` has a new shape**: `{country, outage, datasources, events,
  window}`, judged per measurement. The old shape (`latest_value`,
  `latest_date`) was never written to any capture, because the old fetcher
  never succeeded (below).
- New measurement field **`clock`**: `"utc"` on every measurement the tracer
  writes from now on. A tracevis capture without it predates this fix. The
  field is absent from RIPE Atlas data, which needs no such marker.

### Fixed (backlog §3.2 — the IODA cross-check had never reached IODA)
- `utils/ioda.py` called `ioda.caida.org/ioda-data/data/v3/{CC}/index.json`,
  which does not exist, and parsed a schema no endpoint serves. Its 30 tests
  mocked that schema, so they passed while every `--vps` run reported IODA
  as *unavailable*. Rewritten against the real v2 API
  (`api.ioda.inetintel.cc.gatech.edu/v2/outages/events`).
- **Judged per measurement, against the time it ran**, rather than against
  "latest". Measurements close in time share one request; windows more than a
  day apart get their own. A real multi-VP capture here mixed Aug 2026 and
  Dec 2021 results, and one request across both risked IODA's 500-event page
  limit. A full page is treated as an error, since a missing event would read
  as "no outage".
- **Events, not alerts, with a one-year lookback.** IODA alerts mark state
  changes, so a trace twelve days into the January shutdown had none near it.
  Events are intervals, but IODA only looks back `extendWindow` (14 days by
  default) for where one began. Measured against the API: a trace on 20 Aug
  2026 saw nothing with 14 or 90 days of lookback, while with a year it sees
  outages open since 8 Jan (`gtr`) and 8 Mar (`merit-nt`).
- The tooltip names each datasource with its start date, and a clean result
  now reads `IODA[IR]: no outage` instead of showing nothing.
- Tests run against responses recorded from the real API
  (`test/fixtures/ioda_events_*.json`, fetched with the module's own
  parameters). Two opt-in live tests (`TRACEVIS_LIVE_TESTS=1`) pin the
  server-side behaviour, and a new `main()`-level test covers
  `--vps` → IODA → capture.

### Fixed (backlog §3.1 — timestamps shifted by the host's UTC offset)
- `utils/trace.py` computed both epochs as
  `int(datetime.utcnow().timestamp())`. `utcnow()` returns a *naive* datetime
  holding UTC wall-clock time, and `.timestamp()` interprets a naive datetime
  as **local** time, so every capture taken in the tool's main environment
  claimed to start three and a half hours before it did. That skews
  `--monitor`'s run labels, misaligns a capture against RIPE Atlas data, and
  would have matched a trace to the wrong side of an outage window. It was
  invisible because CI, Docker and the development sandbox all run in UTC,
  where the error is exactly zero. Now `int(time.time())`.
- The six remaining `utcnow()` calls (file-name stamps in `utils/trace.py` and
  `utils/ripe_atlas.py`) produced correct values but are deprecated on the
  Python 3.14 this project pins. They now use `datetime.now(timezone.utc)`, and
  file names are unchanged.
- `test/test_tracer.py::TestTimestampsAreUtcEpochs` runs a trace at UTC+3:30.
  It uses a POSIX `TZ` string, so it needs no tzdata and cannot silently fall
  back to UTC. Against the old code it fails by exactly 12600 s.
- CI runs the unit suite a second time under `TZ=Asia/Tehran`.

## [1.3.0] — 2026-08-29

### Upgrade notes
- **`dpi_cleared` values change.** It now requires evidence the probe reached
  the destination. Measurements that previously reported `dpi_cleared=True`
  about a probe that never arrived now report `False` — 38 of the 96
  measurements in this repository's captures were in that state. This is a
  correction, not a policy change, but anything consuming the field will see
  different values for the same captures.
- **`utils.vis.vis()` returns a bool**, where it previously returned `None`.
  `tracevis.py` has always read it as a success flag; now it is one, and a
  rejected capture exits 1.
- Hop results gain an optional `handshake` boolean, written only when a TCP
  handshake was attempted. Absent means "not tried", which is distinct from
  "it failed".

### Fixed (a malformed capture left a traceback instead of a message)
- **`vis()` dereferenced the capture's shape directly** — `json.load`, then
  `all_measurements[0]["src_addr"]` — so every malformed input reached the
  operator as an unhandled traceback: `JSONDecodeError` on a truncated file,
  `IndexError` on `[]`, `KeyError` on a JSON object rather than a list. A
  capture arriving truncated is an ordinary outcome on the networks this tool
  measures, so its own reader should not be the thing that breaks.
- New `load_measurements()` and `MeasurementFormatError` in `utils/vis.py`.
  Eleven malformed shapes now produce a sentence naming the file, the problem
  and — where a capture holds several measurements — **which one** is at
  fault. `vis()` returns False rather than raising.
- **The reader validates only what rendering dereferences**
  (`src_addr`, `dst_addr`, `result`, and a first hop with probe results),
  checked against all 96 measurements in this repository's 19 captures. An
  over-strict reader would reject files that render perfectly well, which
  would be worse than the crash it replaces; `annotation`, for instance, is
  absent from real captures and stays optional.
- `tracevis.py` now **exits 1** when a render is attempted and rejected.
  Before the reader existed this path was an unhandled traceback, which at
  least exited 1 — reporting the problem cleanly while returning 0 would have
  been a silent regression, and a test pins the exit code.

### Changed (four test mocks, because a return value started meaning something)
- `mock.patch("utils.vis.vis", return_value=False)` appeared in four places.
  The value was arbitrary when `vis()` returned `None` regardless; it now
  means "the render failed", which `tracevis.py` turns into a non-zero exit.
  All four stand in for a render that succeeded and return True.

### Fixed (a responding hop with no packet blobs crashed the whole render)
- **`is_allowlist_boundary` was assigned only inside the branch that has
  received packets to analyse, and read unconditionally below it.** A hop that
  answered while carrying an empty `packets.received` — the shape RIPE Atlas
  data and any capture written without packet blobs both have — reached that
  read with the name unbound and took the entire render down with
  `UnboundLocalError`.
- Pre-existing and **not** family-specific: found while rendering an IPv6
  capture, then reproduced identically on the IPv4 equivalent at HEAD.

### Added (backlog §2.1 — IPv6 measurements render; probing still does not)
- **The rendering and analysis half is now address-family agnostic.**
  `utils/vis.py` gains `address_node_id`, which builds a node id for either
  family and **folds the family into the id** — `::1` and `0.0.0.1` are both
  the integer 1, so without that a dual-stack capture would draw two different
  hops as one node. IPv4 ids are byte-identical to before (`1.1.1.1` is still
  `x16843009x`), so existing graphs are unaffected.
- `resolve_or_ip` now uses `getaddrinfo` rather than the IPv4-only
  `gethostbyname`, which raised `gaierror` on a name with only a AAAA record
  and fell through to the hostname. IPv4 is still preferred when a name has
  both, so dual-stacked names resolve exactly as they did.
- Unresolvable names no longer crash the render. The id builder raised
  `AddressValueError` on anything that was not an address — GitHub issue #68's
  crash in a different guise — and now falls back to the literal, keeping two
  different unresolved names on two different nodes.
- `traceroute_struct.address_family()` derives `af` from the destination
  instead of the hardcoded `4` at every call site, so an IPv6 measurement no
  longer describes itself as IPv4 in the field RIPE Atlas uses for exactly
  that.

### Not done (backlog §2.1 — probing over IPv6)
- **Probing is still IPv4 only, and now says so before it fails.**
  `utils/trace.py` builds every packet on scapy's `IP` layer (29 sites),
  `utils/ephemeral_port.py` binds `AF_INET`, and ICMPv6 time-exceeded parsing
  does not exist. Passing an IPv6 address to `IP(dst=...)` raises a bare
  `gaierror` from inside scapy, well away from the target list that caused it.
  `reject_ipv6_probe_targets` refuses such targets before any packet is sent
  and points at what does work; `utils/packet_input.py`'s rejection message
  now names the real reason instead of "it's not IPv4".
- **Why it stops here rather than being half-built:** this environment has
  zero global IPv6 addresses, none on loopback, and no root, so a live IPv6
  trace cannot be run, let alone validated. Shipping a send path that cannot
  be exercised is the same mistake §1.4's rescope exists to avoid, and it
  would be harder to detect — a broken IPv6 trace looks exactly like a blocked
  one, which is the failure mode this tool exists to distinguish.

### Added (backlog §1.4, rescoped — middlebox reassembly probe)
- **Rescope written up in `docs/rescope-1.4-reassembly.md`.** The item as
  written — fragment a ClientHello so no packet holds a complete SNI — targets
  a middlebox that inspects packets individually. Current DPI reassembles the
  stream before inspecting, which is what makes SNI extraction possible in the
  first place; `utils/dpi.py` already encodes that. Shipping the emitter as
  specified would ship a circumvention technique that is already dead, and
  whose failure would be indistinguishable from ordinary blocking.
- **What is left is the inverse, and it is a better measurement.** If the
  middlebox reassembles, it holds state, and state has a timeout. Sweeping the
  inter-segment delay upward until the block stops firing measures how long it
  will hold a partial stream — a property of the equipment that is not
  otherwise observable from outside.
- **New module `utils/reassembly.py`** and `--reassembly-probe IP:PORT`:
  segments a payload with correct sequence numbers (remainder spread across
  the leading segments, so no segment is conspicuously large), plans a coarse
  logarithmic delay sweep, and classifies the outcome. Five verdicts, two of
  which are refusals to conclude: *buffer bounded*, *reassembles*, *does not
  reassemble*, *block is not stream-based*, *inconclusive*.
- The single-segment control is not optional and comes first in every sweep.
  Without it the sweep cannot tell "the buffer expired" from "no block was
  firing on this path at all".

### Notes (§1.4) — what this does **not** establish
- **Nothing here has been run against live DPI.** This environment has neither
  root nor a censoring path. The emitter, the sweep and the classifier are
  tested offline, and the send path against injected scapy entry points, so
  what is verified is that the code does what it says — not that a real
  middlebox behaves the way the classifier assumes.
- Accordingly **no verdict is allowed to claim "strong" confidence**, and a
  test pins that. Every report ends with a line saying it is unvalidated.
- The one assumption worth naming: the sender maps **silence to BLOCKED**.
  That is sound only because the probe sends a ClientHello to a host that
  would answer one. A handshake that is refused, or answered by anything other
  than a SYN-ACK, is reported UNKNOWN and no payload is sent — a closed port is
  a fact about the port, not about how payloads are inspected.

### Fixed (`dpi_cleared` claimed a clean path for probes that never arrived)
- **`utils/dpi.py` computed `dpi_cleared` with no term for whether the probe
  reached the destination.** The flag means "nothing interfered with this
  path", and the two guards that might have stood in for one both had holes:
  `tcp_silently_dropped` is gated on `sent_proto == "TCP"` *and* on no
  middlebox being tagged. So a UDP probe that never arrived, and a TCP probe
  that never arrived on a path with a visible middlebox, were both reported as
  cleared.

  Measured across the repository's own captures: **38 of 96 stored
  measurements** — 40% — carried `dpi_cleared=True` about a probe that never
  reached its destination. Not only UDP; the `rotation-sni` partial capture
  has six TCP measurements in the same state.

  There is deliberately **no** `udp_silently_dropped` sibling. Silence from a
  closed UDP port is indistinguishable from an on-path drop without a
  destination that would answer, and a flag asserting a drop the tool cannot
  observe would be worse than the gap it fills. Declining to claim "cleared"
  is supportable; claiming "dropped" is not.

### Added (backlog §2.10 — arm comparison, and the datum that settles it)
- **`utils/trace.py` now records TCP handshake *success*, not only failure.**
  The handshake runs to the destination without a TTL limit, so a SYN-ACK is
  proof the destination was reachable at that moment — which is exactly what
  separates "the path dropped this payload" from "the destination was never
  reachable". Only failure had ever been recorded, and only as free text, so a
  capture could not carry the argument. It is now a per-hop `handshake`
  boolean, written only when a handshake was actually attempted: absent means
  "not tried", which is a different finding from "it failed".
- **New module `utils/arms.py`** and `--compare-arms`, which pairs
  control/treatment probes per destination and reports what each pair
  supports, with an explicit confidence and — where the question is still
  open — what would settle it.
- The backlog entry for §2.10 was **wrong and is corrected**. It recorded the
  samples as unanswerable without a controlled endpoint. Re-reading the
  captures:
  - `grpc-h2c` / `shadowsocks`: the control reaches `1.1.1.1` at hop 10/9 with
    a `PSH-ACK` carrying payload; the treatment, on an identical path (same
    first three hops), same port and same destination, gets nothing across 20
    hops. Verdict *payload probably dropped on path*, moderate — held back
    from "strong" only because these captures predate the `handshake` field.
    A re-run settles them with **no new endpoint**.
  - `wireguard`: both arms die at hop 3 on all four destinations, so the block
    is not payload-based — it is the port or the path. That is a result, not a
    failure to measure.
  - An endpoint is still genuinely required for the UDP arm, where silence
    from a closed port cannot be told from an on-path drop.

### Changed (a test contract, deliberately)
- `test_a_plain_timeout_still_serialises_without_a_note` asserted that a star
  hop serialises as exactly `["packets", "x"]`. On a probe that attempted a
  handshake it now also carries the handshake verdict, which is the whole
  point of the change — a star hop is precisely where the question is asked.
  Renamed and re-documented, and the half of the contract that still holds is
  pinned by a new test: a trace that never attempts a handshake serialises
  exactly as it did before.

### Known, not changed
- `tracevis.py -f <malformed.json>` exits with an unhandled `JSONDecodeError`
  from `utils/vis.py`. Pre-existing — reproduced identically at HEAD before
  this work — and separate from the §2.10 changes; `--compare-arms` reports
  the same file cleanly and carries on.

### Fixed (data loss — measurement files could silently overwrite each other)
- **`utils/trace.py` never checked whether a measurement filename was free.**
  Names are stamped to the minute (`%Y%m%d-%H%M`), so two runs inside the same
  minute derived the same path and the second destroyed the first. Both runs
  printed the same `saved:` line, so nothing about the output revealed that a
  capture had been lost.

  Found while building `--monitor`, which makes same-minute runs ordinary
  rather than accidental, and fixed before the loop existed rather than after.
  Reproduced first: four runs stamped to the same minute left one file on disk
  holding only the last one's data.

  The fix creates the file exclusively (`open(..., "x")`) and counts up a
  suffix on collision, so the first run keeps exactly the name it has always
  had and only the colliding path behaves differently. Exclusive creation
  rather than a check-then-open: the check would leave the very race it exists
  to close.

### Added (backlog §2.7 — continuous monitoring)
- **New module `utils/monitor.py`** and `--monitor` / `--monitor-interval`
  (default 300s) / `--monitor-runs` (`0` = until interrupted). A single capture
  dates quickly on a network whose filtering changes; the mode repeats the
  trace and reports what moved between runs.
- Split into three layers so the interesting one is testable: `run_monitor`
  (scheduling and run accounting, with the clock and the sleep injected),
  `summarise_measurement` (one capture → per-destination posture), and
  `build_trend` / `format_trend` (the comparison). The whole loop is tested
  without sleeping and without tracing.
- **A failing run is recorded and the loop continues.** A trace failing on a
  hostile network is a data point about the network, not a reason to stop
  watching it. Only `KeyboardInterrupt` stops the session, and it keeps every
  run already completed — each run is rendered as it finishes, so an interrupt
  still leaves usable graphs.
- The trend reports per-destination reachability across runs, the network state
  at each run, and any DPI/CGNAT/RST signal that changed; it is printed and
  written to `monitor-trend.txt`. Destination *arms* are kept apart
  (`1.1.1.1 [control]` vs `1.1.1.1 [treatment]`) — collapsing on `dst_addr`
  would average a control with its treatment into one meaningless line.
- "Reached" means the destination address actually answered, not that the
  trace ran to completion: a path that dies at hop 4 still produces a full run
  of star hops.

### Fixed (`utils.vis.vis()` never signalled success)
- The function had no `return`, so `if utils.vis.vis(...)` in `tracevis.py` was
  always falsy and a completed render printed no `finished.`. Pre-existing —
  reproduced at `v1.1.0` — and cosmetic until now: `--monitor` decides whether
  a run counted, and a falsy return would have marked every successful run as
  failed.

### Notes (§2.7)
- Validated against a real series rather than only synthetic data. Two captures
  in `tracevis_data_res_after/` are the same configuration six minutes apart on
  an allowlisted network, and the trend reports a reachability change between
  them. Checked against the raw JSON: at 21:35 nothing answered from `1.1.1.1`
  and the path died at `172.16.4.43`; at 21:41 `1.1.1.1` answered. The
  detection is a true positive, not an artefact of the summariser.
- Nine defects were re-injected to confirm the tests catch them, including the
  restored overwrite bug. All nine were caught.
- One defect was found by validation rather than by review: `run_monitor` took
  `sleeper=time.sleep` as a **default argument**, which binds at import, so
  `mock.patch` on `time.sleep` was silently ignored and a supposedly-stubbed
  test slept out the real 60-second interval. Both are now resolved at call
  time. The regression test uses a 1-second interval on purpose — the
  assertion that catches the defect is the call count, and a large interval
  would make the failing case hang instead of report.

### Added (backlog §2.4 — the allowlisted-tier node band)
- **`mark_allowlisted_tier()` in `utils/vis.py`** flags every node in the
  downstream cone of a CGNAT hop. §2.3 shipped the boundary itself (a teal
  hexagon) and the tier-transition edge label; the band behind it was the half
  left open, which is why §2.4 stood as PARTIAL.

  Semantics, chosen deliberately: the marking is a **union** over every
  boundary and every vantage point, so a node reached post-boundary by any VP
  is in the tier even when another VP reached it without crossing one.
  `nx.descendants` follows directed edges, so this is the downstream cone and
  not the whole graph, and it terminates on a routing cycle by construction.
  Boundary hops are excluded from their own band, so a second CGNAT downstream
  of the first still reads as a boundary rather than dissolving into the tier.

- **The band is an outline, not a recolour.** `utils/vis.py` records
  `allowlisted_tier` as a node *attribute* and each renderer styles it in its
  own idiom: `VisJsRenderer` promotes the node's `color` string to vis.js's
  `{background, border}` object, `PlotlyRenderer` uses the marker outline
  (Plotly has no border-colour field). Overwriting `color` outright would have
  erased the DPI/NAT/PEP/forged classification the graph exists to show — on
  the widest capture that is 97 of 100 nodes losing their device colour.

- **`count_allowlisted_tier_nodes()`**, and the `--phase-overlay` legend now
  reports the band size alongside the boundary count. This is not decoration:
  across this repository's captures the band runs from 2 of 5 nodes up to 97 of
  100, and without the number a wide tier and a broken marking look identical.

- Gated on `--phase-overlay`, the flag that already owns the tier
  visualisation, so no graph gains a band unless it was asked for. Verified by
  rendering all 19 captures on both backends at `v1.2.0` and again after the
  change: the 19 vis.js pages are **byte-for-byte identical**. The Plotly
  pages are not, and the difference is worth stating precisely — the marker
  spec moved from a scalar `line: {color: '#333', width: 1}` to the per-point
  `line: {color: d.lineColors, width: d.lineWidths}`, and the payload gained
  two arrays. On a graph with no tier those arrays hold nothing but the
  default outline, and Plotly renders a uniform per-point array exactly as it
  renders the scalar; both versions were executed under node and produce
  equivalent traces. So the bytes differ and the rendered page does not.

### Notes (§2.4)
- Validated across all 19 captures in the repository: the data model, the
  vis.js payload and the Plotly payload agree on the tier size for every one
  of them, and the four captures with no CGNAT hop mark zero nodes.
- The Plotly band is asserted by **executing** the emitted script under node
  against a mock `Plotly`, not by inspecting the payload handed to it. The
  payload-level assertions all passed while the marker spec still hardcoded a
  scalar outline — the band was computed, serialised, and then discarded at
  the point Plotly was called. That is the same shape of defect as the
  reverse-path styling applied after `from_nx()`, and only running the script
  catches it.
- The legend's CGNAT count is taken from the unstyled graph. Boundary nodes
  are excluded from the tier, so reading it off the styled copy survives
  today by accident — `count_cgnat_nodes()` matches `color` against
  `CGNAT_COLOR` as a string, and the promotion turns `color` into a dict.

### Known, not changed
- `utils.vis.vis()` has no return statement, so `if utils.vis.vis(...)` in
  `tracevis.py` is always falsy and the closing `finished.` is never printed.
  Pre-existing (reproduced at `v1.1.0`), cosmetic, and left for the `--monitor`
  work, which needs real run-success signalling rather than a patched-over
  truthiness check.

## [1.2.0] — 2026-08-29

### Added (GitHub issue #44 — reverse-path detection via VP convergence)
- **`_find_vp_convergence()` in `utils/vis.py`** detects the shared last-mile
  segment across multiple VP traces. Measurements are grouped by destination,
  and within each group the walk runs backward from the destination while every
  vantage point still has a responder in common. Edges whose destination node
  is in the resulting set are rendered as dashed amber — approximating the
  reverse path that all Vantage Points observe identically. A legend overlay
  explains the marking, and is emitted only when at least one edge actually
  carries it. Works with both `--renderer visjs` and `--renderer plotly`.
- `--reverse-path` CLI flag in `tracevis.py`. It needs a measurement holding
  the same destination from two or more distinct vantage points (via `--vps`,
  or several `-f` files combined); with a single VP it says so and marks
  nothing.

### Added (GitHub issue #64 — graphing backend abstraction)
- New module `utils/renderer.py`: `Renderer` base class + `VisJsRenderer`
  (wraps the existing pyvis/vis.js path) and `PlotlyRenderer` (Plotly.js with a
  numpy-free layered layout that places nodes in columns by hop distance).
  `get_renderer()` dispatches by name. The Plotly backend groups edge segments
  by colour into a handful of traces rather than one trace per edge, and
  carries per-point hover text so each node and edge shows its own tooltip.
- `save_measurement_graph()` and `vis()` now accept a `renderer=` parameter;
  `--renderer {visjs,plotly}` CLI flag added. The pyvis import is now isolated
  inside `renderer.py`; `utils/vis.py` no longer imports it directly.

### Added (GitHub issue #2 — edge-click path highlighting)
- `_inject_edge_highlight()` in `utils/vis.py` injects JavaScript so clicking
  an edge highlights the entire upstream path; clicking empty space restores
  every element's original colour. The walk keeps a visited set, so a routing
  loop in the traced path terminates instead of hanging the browser tab.
  `--highlight-selected` CLI flag added. The Plotly backend implements the same
  interaction through Plotly's own event emitter.

### Added (GitHub issue #47 — middlebox fingerprinting)
- New `MiddleboxFingerprint` namedtuple and `fingerprint_middlebox(sent,
  received, ipid_packets=None)` function in `utils/vis.py` — TCP option
  mutation analysis (MSS clamping, timestamp stripping) and IP-ID entropy
  classification (constant, sequential, random). A detected clamp reports the
  observed MSS and says whether it matches a well-known middlebox clamp value.
  IP-ID entropy is classified per responding hop IP across all repeat probes,
  via `collect_hop_ipid_packets()`. Fingerprint data appears in hop tooltips.

  Note: `ts_stripped` can only fire on probes that carry a TCP Timestamp
  option. tracevis does not set one on its own probes, so in practice this
  signal applies to imported packets (`--packet`) and RIPE Atlas data.

### Added (GitHub issue #75 — DNS resolution race condition)
- `detect_dns_blackhole()` now returns a `DnsResult` object with explicit
  `blackholed` and `resolved` fields; `__bool__` returns `blackholed` for
  backward compatibility. `get_meta_vars()` no longer conflates "DNS unreachable"
  with "no internet" — a reachable `user_meta` (or a resolved DNS probe) now
  correctly clears `no_internet` even when the blackhole probe timed out.
- Because `no_internet` now means "the network is reachable" rather than "we
  got metadata", it is no longer the right signal for deciding whether the
  rendered graph may link its JS/CSS from a CDN. That decision moved to
  `utils.vis.needs_offline_assets()`, which reads the recorded `network_state`.

### Fixed (review of the §2.2 / §2.3 / #68 / #69 work)
Found the same way as the review above: by exercising the shipped flags against
this repository's own captures.

- **`--vps` could not render two probes at all.** Edge colour was looked up as
  `REQUEST_COLORS[measurement_steps]` against a 12-entry palette, so the
  thirteenth measurement raised `IndexError` and the run ended in a traceback
  *after* the download had been saved. `utils.ripe_atlas.MEASUREMENT_IDS` holds
  nine measurement ids and `download_multi_from_atlas` loops probes x ids, so
  **two probes produce up to eighteen measurements** — the documented primary
  use case. The index now wraps, via `build_request_colors()`.
- **Edge colour did not identify a vantage point**, though `--vps` help, the
  README and the commit message all said it did. It was assigned per
  measurement, so with the accessible/blocked destination pair tracevis exists
  to compare, one VP got two colours and no colour mapped to a VP. Colour is
  now assigned per distinct VP when the capture has any, falling back to
  per-measurement otherwise.
- **The first vantage point's source node was anonymous.** A seed node claimed
  the id before the loop ran, and the loop's `if curr_src_id not in graph`
  guard then never fired for it, so an N-VP graph showed "source (VP 2)" …
  "source (VP N)" plus one unidentifiable "source address". The seed is gone
  and every source node is labelled.
- **Two probes reporting the same private address merged into one node.** RIPE
  Atlas probes report RFC 1918 addresses (the sample capture has
  192.168.178.26 and 192.168.254.43), so two probes on different LANs can
  collide. `source_node_id()` now keys the node on the VP as well.
- **The IODA cross-check never reached the graph.** `tracevis.py` fetched the
  status and printed it to the terminal; nothing ever wrote
  `measurement["ioda_status"]`, which is the key `utils/vis.py` reads to render
  the `IODA[CC]: outage (value=...)` tooltip line. Zero saved captures carried
  it, and the only thing that ever populated it was a test injecting the dict
  by hand. New `utils.ioda.annotate_measurements()` writes the fetched status
  into the capture, and degrades to a no-op (never losing the measurement) when
  IODA is unreachable or the file cannot be rewritten.
- **`--ipv4` (#69) did nothing.** The only read of the parsed value anywhere in
  the codebase was a test asserting argparse had stored it. tracevis is IPv4-
  only throughout, so there was no mode to switch; the flag is now an explicit,
  checked assertion — `reject_non_ipv4_targets()` names any target that is not
  an IPv4 address and the run stops before probing, instead of failing later
  inside scapy or the renderer.
- **The allowlist-boundary edge marker was invisible by default.** The guard
  was `if is_allowlist_boundary and not current_edge_label`, and the default
  `--label backttl` always sets a label, so "→ allowlisted tier" only appeared
  under `--label none`. On a real allowlisted capture with a CGNAT hop: 6
  markers with `--label none`, 0 with the default. It now appends, so the hop's
  own label survives alongside it (`2 → allowlisted tier`).
- **`--phase-overlay` was a fixed caption.** It announced "teal hex = CGNAT
  boundary" over graphs containing no CGNAT node at all. It now reports what
  the graph holds, including saying plainly when the answer is none.

Verified working as documented, and left alone: CGNAT teal-hexagon rendering
(checked against the 17 captures here that contain RFC 6598 hops),
`resolve_or_ip()`'s hostname fix (#68), and RIPE Atlas data with no per-hop
`packets` dict.

### Fixed (review of the #2 / #44 / #47 / #64 / #75 work)
Each of these was found by exercising the new flags against this repository's
own captures rather than by re-reading the code; the numbers below come from
those captures.

- **`--reverse-path` marked nothing at all.** Four independent faults stacked
  up, and the flag rendered its "reverse-path leg" legend over a graph with no
  reverse-path edges on it:
  - `_find_vp_convergence()` pooled every measurement regardless of
    destination. A multi-VP capture holds one measurement per (VP x
    destination), and comparing an accessible against a blocked destination is
    tracevis's core workflow — so the differing final hops broke the suffix
    walk on its first step and the function returned an empty set. It now
    groups by destination and unions the per-destination results.
  - `VisJsRenderer` applied the amber/dashed styling to the networkx graph
    *after* `from_nx()` had already copied it into pyvis, so the styling never
    reached the page. It now runs before the copy, on a clone, leaving the
    caller's graph unmutated.
  - The dash was written as `dash`, which vis.js ignores; the property is
    `dashes`.
  - The convergence set held raw addresses while graph node labels are
    normalised through `resolve_or_ip()`, so a hostname destination could
    never match. Both sides are normalised now.
  - A destination now needs two *distinct* vantage points to count. Two runs
    from one VP share their whole path by construction and previously flagged
    the entire graph.
  - The legend is emitted only when at least one edge carries the marking;
    otherwise the run says why nothing was marked.

- **IP-ID fingerprinting reported the opposite of the truth on most hops.**
  `_classify_ipid_pattern()` required consecutive IDs to differ by exactly 1 to
  count as sequential. Routers run one global IP-ID counter shared across every
  flow they originate, so between two of our probes the ID advances by more
  than one (41021 -> 41029 -> 41037 is a typical observed sequence). Across the
  captures in this repository the old rule found 0 of 164 hops sequential and
  labelled all 164 "random" — which the tooltip presents as evidence of a
  randomising middlebox. The rule is now "monotonic with a bounded increment"
  (`IPID_SEQUENTIAL_MAX_DELTA`, wrap-aware): 116 sequential, 39 random, 9
  constant.
- **IP-ID entropy was measured at the wrong level.** It was classified within a
  single probe's `received` list, but tracevis records each repeat probe as its
  own result carrying at most one packet, so 99% of hops came back "unknown".
  `collect_hop_ipid_packets()` now groups every reply by responding IP across a
  hop's repeats: 155 hops classifiable where 22 were before.
- **`_classify_ipid_pattern()` was inconsistent about zero IDs** — the
  "constant" test filtered them out while the delta test did not, so
  `[0, 5, 5]` reported "constant". Both tests now see the same sequence.
- **`_has_timestamp_option()` had a dead comparison.** `name.upper() ==
  "Timestamp"` can never be true; only the `TS` spelling was ever matched.
- **`--highlight-selected` did nothing under `--renderer plotly`, and shipped
  in every Plotly page regardless of the flag.** `self._injected_js(
  'highlight_selected')` passed a truthy string literal rather than the
  argument. The handler was inert anyway: Plotly emits its events through
  `gd.on()`, not `addEventListener`, and it read `event.trace` (not part of
  Plotly's click payload) and called `Plotly.relayout` for a trace property.
  The interaction is now implemented against Plotly's event emitter and gated
  on the flag.
- **The vis.js highlight walk could hang the browser tab.** It followed
  incoming edges upstream with no visited set, so a routing loop in the traced
  path looped forever, calling a DataSet update (and a redraw) each iteration.
  It now carries a visited set. Clearing the highlight also used to write
  `color: undefined`, which drops elements to the vis.js default rather than
  restoring them, permanently destroying the DPI/forgery/OS colour coding after
  one click; original colours are now saved and restored exactly.
- **Plotly node and edge tooltips showed every other element's tooltip.**
  `hovertemplate` was set to a single joined string, which Plotly applies to
  every point in the trace. Hover text is now a per-point array.
- **The Plotly backend emitted one trace per edge** (84 for this repository's
  multi-VP capture). Segments are now grouped by colour into a handful of
  traces plus one hover-marker trace — 8 instead of 84 for the same graph.
- **The Plotly backend accepted `attach_jscss` and ignored it**, always linking
  `cdn.plot.ly`. It now inlines a vendored bundle from `lib/plotly/plotly.min.js`
  when one is present, and otherwise says plainly that the page will need the
  CDN and that `--renderer visjs` produces a self-contained page.
- **The Plotly circular layout was unreadable** for anything past a handful of
  nodes — it placed hop 1 beside hop 12 and ran every edge across the middle of
  the plot. Replaced with a layered layout that puts nodes in columns by hop
  distance from the source.
- **A censored network could produce a graph that needs a CDN.** The main
  template links vis.js from `cdnjs.cloudflare.com`, and self-contained output
  was triggered solely by `no_internet`. Issue #75 redefined that flag so a
  DNS-hijacked shutdown reports `no_internet=False`, which stopped the fallback
  firing on exactly the network that cannot reach a CDN. `vis()` now escalates
  to embedded assets whenever a measurement records a `shutdown` or
  `allowlisted` `network_state`, which also covers re-rendering a saved capture
  with `-f`, where no live connectivity check happens.
- Removed dead code the features left behind: `MSS_CLAMP_VALUES` and
  `NO_FINGERPRINT` were defined and never used (both are now used),
  `edge_is_reverse` was built and never read, `trace_count` was emitted into
  the page unused, and `traceroute_data.middlebox_fingerprint` was added to the
  constructor but never written or read by anything.
- Restored the continuation-line alignment in `utils/geolocate.py` that the
  issue #75 change de-indented.

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

### Added (backlog §2.2 — multi-vantage + IODA cross-check)
- **`--vps`** flag: comma-separated RIPE Atlas probe IDs that download the same
  measurement from each probe and render them in one combined graph with
  per-VP colour-coded edges (reuses the existing `REQUEST_COLORS` cycle).
  Each measurement entry is annotated with `"vp": probe_id` and the
  annotation/tooltip surfaces it as `VP {id}`.
- **`--ioda-country`** flag: cross-checks IODA v3 outage data for the given
  2-letter country code (default: IR). When IODA reports an active outage,
  the annotation gains `IODA[{CC}]: outage (value=...)`. The fetcher
  degrades gracefully when the API is unreachable.

### Added (GitHub issue #69 — `--ipv4` flag)
- Explicit `--ipv4` CLI flag to force IPv4-only probing. The codebase was
  already IPv4-only at the socket layer; the flag makes it explicit and
  guards against future IPv6 paths.

### Fixed (§2.2 — RIPE Atlas data format compatibility)
- **`vis()` crashed on RIPE Atlas data.** The `packet_size` and
  `current_node_label` assignments were nested inside `if "packets" in
  result.keys():`, which only TraceVis-native measurements have. RIPE Atlas
  traceroute hops put `size`, `rtt`, etc. at the top level without a `packets`
  key, so `packet_size` stayed `"*"` while `elapsed_ms` was a float, causing
  `TypeError` at `elapsed_ms / packet_size`. The two assignments are now
  unconditional (`result.get("size", "*")`), so both data formats render.

### Fixed (GitHub issue #68 — domain-based graph crash)
- `vis()` called `ipaddress.IPv4Address(addr)` on `src_addr`/`dst_addr`, which
  raised `AddressValueError` when the target was a hostname. Now resolves
  hostnames to IPv4 via `socket.gethostbyname()` before node-id conversion.
  `test/test_vis.py` adds `TestResolveOrIp` and `TestHostnameRendering`.

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
