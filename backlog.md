# Backlog

Each item is an atomic, testable unit of work. Risk is estimated as
**L/M/H** (Low/Medium/High) probability × impact. Dependencies are noted.

> Legend: Priority = P0/P1/P2/P3.

**Status at a glance.** Done: 1.1, 1.2, 1.3, 1.5, 1.6, 1.7, 1.8,
1.9, 2.0, 2.5, 2.6, 2.8, 2.9, 2.11, 2.12. Partial: 2.3. Needs rescoping before it can be
scheduled: 1.4. Genuinely open: 2.1, 2.2, 2.4, 2.7, 2.10.

**The roadmap is complete as of M6c; everything still open lives here.**

---

## P0 — Critical (must fix for the tool to function at all)

| ID | Task | Why | Risk | Depends on |
|----|------|-----|------|------------|
| 1.1 | ~~Make network detection multi-provider & allowlist-aware~~ **DONE (M1)** | `geolocate.py` only used Cloudflare speed; those IPs can be CGNAT'd and SNI-filtered, which produced false "no internet" verdicts. | M | — |
| 1.2 | ~~Classify network state (open / allowlisted / shutdown) + expose to CLI~~ **DONE (M1 + M5a `--network-mode`, corrected M5f)** | Behaviour should adapt to the regime rather than assume an open network. M5f: a DNS hijack was the only allowlist signal, so a tiered network that drops TCP instead classified as `open` — a silent majority of metadata providers is now the second signal, and `--network-mode open\|allowlisted` (previously discarded) overrides the verdict. | M | 1.1 |
| 1.3 | ~~Resolver defaults~~ **DONE (M5d samples + M5g pool)** | The original framing — "these defaults are unreachable under an allowlist, replace them" — was wrong, and acting on it would have made the tool worse: *`8.8.8.8` being unreachable is the measurement*, and a pool where everything answers is unfalsifiable by construction. A contrast only reads as a result when the sweep contains both a destination that answers and one that does not. Resolved instead by curating the pool into labelled roles (control / same-operator control / treatment), dropping only the entry that duplicated another's role, and confirming nothing filters the treatment out at trace time. Literals kept deliberately — resolving them hands the destination choice to the resolver under measurement. | H | 1.2 |
| 1.4 | **NEEDS RESCOPING** — TCP-reassembly-resistant packet emitter (jittered fragments) | Fragmentation to evade SNI inspection is a technique that current DPI defeats by reassembling before inspecting, so building it as originally written ships something already dead. The measurable value left is the inverse: an emitter that *confirms* reassembly and times the buffer. Rescope before scheduling. | H | — |
| 1.5 | ~~Port-pool rotation + RST-flood backoff (port hop)~~ **DONE (M2 logic, M5c live wiring)** | Port 443 is the most deeply inspected; other ports are often less so. RST floods otherwise kill a trace outright. | H | 1.2 |
| 1.6 | ~~dnstt + DoT/DoH packet support + blackhole detection~~ **DONE (M3)** | A DNS tunnel is frequently the only channel that survives a total block, and hijacked DNS needs detecting rather than trusting. | H | 1.2 |
| 1.7 | ~~Randomize retransmission IP-id (remove deterministic `id += 15`)~~ **DONE (M5e)** | A predictable IP ID is a flow-correlation handle. | L | — |

## P1 — High

| ID | Task | Why | Risk | Depends on |
|----|------|-----|------|------------|
| 1.8 | ~~Adaptive timeout/repeat per hop + profile flag~~ **DONE (M5c, opt-in `--adaptive-timeout`)** | A 1s timeout misflags slow DPI hops as silent; blackout paths need up to 60s. | M | 1.2 |
| 1.9 | ~~DPI / CGNAT / SNI-filter / blackhole classifiers~~ **DONE (M4)** | `vis.py` had no DPI detection at all, so a blocked path and a clean one rendered identically. | M | 1.2 |
| 2.0 | ~~Extend traceroute_data fields~~ **DONE (M4 + M5c per-hop `dport`)** | The struct had nowhere to record allowlist / SNI / blackhole evidence. | L | 1.9 |
| 2.1 | IPv6 support (packets, targets, vis, ip6tables RST drop) | IPv6 paths are often less filtered; the codebase is currently IPv4-only. | H | 1.2 |
| 2.2 | Multi-RIPE-probe + IODA/Radar status probe | A single vantage point cannot reproduce allowlist asymmetry — that needs distributed probes. | M | 1.1 |
| 2.12 | ~~Detect on-path interception from the reply itself~~ **DONE (M7)** | Addressing a probe to a chosen resolver guarantees the destination *field*, not the destination, and nothing in the outgoing packet can prevent an on-path box answering in its place — but the reply has to come back, and it carries evidence. Two signals, either sufficient: **IP-ID reflection** (the reply keeps the query's IP ID, so the box mutated the request rather than composing an answer; ~1-in-65536 per probe by chance) and **TTL implausibility** (the reply implies an initial TTL no real stack emits). Built against a capture holding both forged and genuine replies, and validated to zero false positives over every measurement available. DF was dropped as a signal: genuine replies lack it too. | M | 2.0 |
| 2.10 | Give `grpc-h2c` / `shadowsocks` / `wireguard` a destination that answers their experimental arm | All three have been run: control reached, experimental arm never did — but the arms point at `1.1.1.1:443` (TLS-only) and `:51820` (no WireGuard endpoint), so "the DPI dropped it" and "the server ignored it" are indistinguishable. The samples cannot answer their question until the operator has an endpoint that would answer. | M | 2.5 |
| 2.11 | ~~Derive `cgnat_hop` from per-hop evidence, not from `network_state` alone~~ **DONE (M5f)** | `cgnat_hop` was derived from `network_state` alone, so it could not fire on a network the detector had already mis-classified — including ones whose traces crossed an obvious RFC 6598 hop. Now tested against `100.64.0.0/10` in `recompute_dpi_from_per_hop` and per-hop in `vis.py`. The semantics question resolved the other way than expected: `dpi_cleared`'s `not cgnat_hop` clause turned out to be **inert** (`cgnat_hop` implied `allowlisted`, `dpi_cleared` requires `open`), so dropping it changed nothing and stopped the new evidence from raising a false alarm on every uncensored CGNAT carrier. | M | 1.9 |

## P2 — Medium / polish

| ID | Task | Why | Risk | Depends on |
|----|------|-----|------|------------|
| 2.3 | **PARTIAL** — per-hop SNI node + DPI tooltips shipped (M4); no CGNAT/allowlist node types | The graph cannot yet render a layered filtering stack as distinct node types. | M | 1.9 |
| 2.4 | Phase/tier overlay in graph | A trace cannot show where it crosses into an allowlisted prefix. | M | 1.2 |
| 2.5 | ~~Refresh sample configs to allowlisted/non-443 pool~~ **DONE (M5d; protocol shapes added M5e)** | Samples targeted SNI-blocked IPs on 443, so most of the pool measured the same block twice. M5e added probe shapes for three protocols that had none: WireGuard, Shadowsocks, gRPC-on-443. | L | 1.2, 1.5 |
| 2.6 | ~~Refactor globals → Tracer class~~ **DONE (M5b)** | `trace.py`'s module globals made per-run state and testing awkward. *Note: parallel traces are still not possible — the delivered benefit is per-run state and testability, not concurrency.* | M | — |

## P3 — Low / future

| ID | Task | Why | Risk | Depends on |
|----|------|-----|------|------------|
| 2.7 | Continuous `--monitor` mode | Filtering behaviour evolves quickly, so a single run dates fast; repeated tracking is what makes a trend visible. | M | 1.2 |
| 2.8 | ~~`--anonymize` output + secure-by-default~~ **DONE (M6a)** | Raw packet captures land on disk and carry the operator's own network. Split by cost: the operator's own address is removed unconditionally (it has none — `send_packet` overwrites `IP.src` on every probe), while private-hop pseudonymisation is opt-in because hop addresses are the measurement. CGNAT hops survive the flag so `cgnat_hop` keeps working. Also closed the leak chain into `samples/`: the config dump wrote the packet as held. | L | — |
| 2.9 | ~~Drop IPython hard-dep in `from_scapy`~~ **DONE (M6c)** | A hard dependency may be absent in a restricted environment. It was never in `requirements.txt`, but the stdlib `code.interact` fallback sat after an unconditional `raise NotImplementedError` and so was unreachable. Also fixed while there: the prompt's namespace was the reader's own `locals()` (so the banner's `IP(...)/TCP()` raised NameError), and a bare `except:` reported every in-session error — including forgetting to assign `p` — as IPython being absent. | L | — |

---

## Risk register (top)

| Risk | Mitigation |
|------|------------|
| Breaking existing public behavior (CLI/tests) | Preserve defaults; gate new behavior behind explicit flags; keep `--dns` path working. |
| No network in CI to test real traces | Unit-test detection/DPI/dns logic with mocked `urlopen`/`sr` responses; use scapy loopback for RST/flood sims. |
| Python 3.14 / scapy API drift | Pin tested scapy version; test against installed deps. |
| Scope creep / rewrites | Each task isolated to one module; keep each change inside one module. |
