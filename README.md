# TraceVis
Traceroute with any packet. Visualize the routes. Discover Middleboxes and Firewalls

[![CodeQL](https://github.com/KourosZanbouri/tracevis/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/KourosZanbouri/tracevis/actions/workflows/codeql-analysis.yml)
[![Dockerise](https://github.com/KourosZanbouri/tracevis/actions/workflows/docker.yml/badge.svg)](https://github.com/KourosZanbouri/tracevis/actions/workflows/docker.yml)
[![unittest](https://github.com/KourosZanbouri/tracevis/actions/workflows/unittest.yml/badge.svg)](https://github.com/KourosZanbouri/tracevis/actions/workflows/unittest.yml)


TraceVis is a research project whose main goal is to find middleboxes. Where a packet is tampered with or blocked. This tool also has other features such as downloading and visualizing traceroute data from RIPE Atlas probes.


![example graph](https://user-images.githubusercontent.com/12384263/159377323-1e4e594e-aca8-4f91-8174-0ba58f6a6454.png)

## Built against measurement, not a threat model

The detection features here exist because a restricted network did something
specific and the tool failed to see it. Each was written against a capture that
already contained the answer, then validated against every capture available —
including unrestricted ones, because a detector that never produces a negative
is not a detector.

Worked examples:

- **Answer forgery.** A capture showed a destination "replying" from nine hops
  out with the query's own IP ID and a TTL of 1, where the genuine answers from
  the same destinations carried TTL 52-118 and 10-16× the round-trip time.
  Something on the path was mutating the request and sending it back rather than
  forwarding it. `utils/forgery.py` detects this, with no false positives
  across every measurement it was validated against.
- **Silent drop vs reset.** Blocked TCP is widely expected to draw a RST. Every
  measurement taken said otherwise — zero RSTs, packets simply discarded — so
  `tcp_silently_dropped` exists alongside `rst_flood`, and the notes record
  where measurement and expectation disagreed rather than smoothing it over.
- **Detection that agreed with itself.** `cgnat_hop` was derived from the
  network-state verdict rather than from the hops, so it could not fire on a
  network the detector had already mis-classified. It now reads the addresses.

The captures these were built against are **not** published: a measurement
describes one network's traffic at one moment, and a general-purpose tool should
not ship someone's network as a fixture. What generalises — the signals, the
thresholds, and why they sit where they do — is in the code and its tests.

## Install and build

#### Note:
You need to install [npcap](https://npcap.com/) in **Windows**. If you already have programs like Wireshark or Nmap/Zenmap, they will install this automatically. 

(**Not** required on **Linux**.)

### Using docker:
##### Pull docker image from github container registry:

```sh
docker pull ghcr.io/kouroszanbouri/tracevis
```

##### Or clone project and build docker image on your machine:

```sh
docker build -t tracevis .
```

##### Run the published image (detached mode with persistent data):

```sh
sudo docker run -dit \
  --name tracevis \
  -v "$HOME/tracevis:/tracevis_data" \
  ghcr.io/kouroszanbouri/tracevis:latest
```

> The container writes output to `/tracevis_data/` (the `TRACEVIS_OUTPUT_DIR`
> env var in the Dockerfile). Bind-mount a host directory there to persist
> results. Use `--cap-add NET_RAW --cap-add NET_ADMIN` if running without
> `sudo`/`--privileged` and the container needs raw sockets.

### Directly:
##### Download or clone project and then install Python dependencies:

```sh
python3 -m pip install -r requirements.txt
```

#### Running locally as non-root (Linux, Python 3.14)

Scapy needs raw sockets to send/receive traceroute packets. You have two safe
options that avoid running the whole tool as `root`:

**Option A — grant the raw-socket capability to your python binary** (so you
can run `python3 tracevis.py …` as a normal user):

```sh
# point setcap at YOUR interpreter path, e.g. the venv python or system python3.14
python_bin="$(readlink -f "$(command -v python3.14)")"
sudo setcap cap_net_raw,cap_net_admin=eip "$python_bin"
```

> Why `python3.14` and a venv? Newer `pip` requires/encourages a virtualenv, and
> the geolocate metadata probe must run under 3.14's `multiprocessing` (the
> nested-function pickle bug was fixed for 3.14 in this repo). Create the venv,
> `pip install -r requirements.txt` inside it, then `setcap` the venv's
> `python` (e.g. `sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python`).

**Option B — use Docker** (keeps the capability inside the container), then
drop a shell as the container user or run privileged only if needed:

```sh
docker run -it --cap-add NET_RAW --cap-add NET_ADMIN tracevis --dns --paris
```

## Network regime detection

Under a tiered-access regime — where a network-layer allowlist decides which
destinations exist at all — relying on a single metadata endpoint is unreliable,
because that endpoint can be CGNAT'd and SNI-inspected like anything else. TraceVis probes **every** provider
(Cloudflare, ipinfo, ifconfig) and resolves a **blocked** domain to see whether
the answer lands in the `10.10.34.0/24` filter net, then classifies the network:

- `open` — a provider answered, DNS is clean, and no provider was silenced
- `allowlisted` — a provider answered, **and** either DNS is hijacked or most
  providers were silent (tiered access)
- `shutdown` — nothing reachable and DNS hijacked (total block)
- `unknown` — indeterminate (transient)

Two signals, because a tiered network need not hijack DNS and a hijacking one
need not block the providers:

- **DNS hijack.** The probe resolves a domain that is actually blocked — using
  the accessible control domain, as an earlier version did, can never detect a
  hijack — and matches the whole filter net rather than one address.
- **Reachability differential.** *Which* providers answer is itself the signal:
  under tiered access the allowlisted ones do and the rest do not. Judged at the
  transport level, so a rate-limited or broken-but-answering provider is not
  mistaken for a censored one, and a strict majority must be silent so one flaky
  provider cannot relabel an open network.

The state is printed at the start of every trace, along with the evidence
(`silent metadata providers: …`, `DNS hijack confirmed: …`), and both are stored
in the measurement as `network_state` and `provider_status`. A state you cannot
check is a state you cannot trust — and it decides `dpi_cleared` for the run.

`--network-mode {auto,open,allowlisted,shutdown}` overrides the verdict when the
classifier is wrong about your network. `shutdown` additionally skips all
detection I/O. `auto` is the default.

## Resilient timing & port rotation (config or CLI)

In networks where port 443 is deep-inspected and per-hop RTT is inflated by DPI,
you can opt into resilient probing — via a config file (see
`samples/portpool_degraded.conf`) or directly on the CLI
(`--port-pool`, `--timeout-profile`). When both are given, the CLI flag wins.

- `timeout_profile` / `--timeout-profile` — one of `fast` (1s, default),
  `degraded` (3s, for allowlisted/DPI paths), or `shutdown` (60s, for
  total-block paths such as DNS tunnels). An explicit `--timeout` still wins.
- `port_pool` / `--port-pool` — a CSV like `8080,8443,2053,2083`. When no
  `--port` is given, TraceVis starts on a clean (non-443-leaning) port from the
  pool. **Live rotation:** if a port draws enough TCP RSTs to cross the
  flood threshold, it is put on cooling-off and probing moves to the next port
  in the pool. Rotation only happens in response to an actual RST flood, so a
  run that never sees one behaves exactly as it would without it. The port each
  hop actually probed is recorded per hop in the JSON. Rotation is disabled
  under `--paris`, where the retransmitted packets carry a fixed port.
- `--iface` — the interface to trace from. At layer 3 scapy picks the interface
  from the routing table and ignores a per-call one, so this sets `conf.iface`
  and the source address; it had no effect at all before M5f.
- `--adaptive-timeout` (off by default) — grows the per-hop timeout toward the
  last observed RTT (×3, capped at 60s), tracked separately per destination, so
  a genuinely slow DPI hop is not misread as "no response". Only hops that
  *answered* update the estimate. Turning this on changes how long a trace takes
  and therefore what counts as a timeout, which is why it is opt-in.

## What a saved measurement says about you

Your own source address is **never** written to disk — not in `src_addr`, not in
a hop summary, not inside a stored packet, and not in the `.conf` saved beside
each run. It is replaced with `127.1.2.7`. This costs nothing: every probe has
its `IP.src` overwritten at send time, so the stored value only ever identified
whoever ran the trace.

Everything else is kept by default, because it is the measurement. If you are
sharing a capture and would rather not publish the shape of your own network:

- `--anonymize` — replaces RFC 1918 hops (`10.*`, `172.16-31.*`, `192.168.*`)
  with addresses from RFC 5737 `192.0.2.0/24`, consistently within a run so the
  graph still merges one router into one node. The substitution is printed.

  Carrier-grade NAT hops (`100.64.0.0/10`) are **kept** even with the flag: they
  are your ISP's infrastructure rather than your LAN, and the `cgnat_hop`
  classifier reads them back out of the saved hops.

Not scrubbed, by design: your targets, annotations, measurement name, and the
ASN/country of your connection. Those are what you chose to measure and the
context needed to read the result — if they are sensitive in your situation,
that is a decision about what to publish, not something the tool can guess.

## DPI / CGNAT / SNI classification (in-graph signals)

TraceVis tags every path with the three inspection layers most disruptive in
restricted networks. See `utils/dpi.py`.

- `cgnat_hop` — a hop in RFC 6598 space (`100.64.0.0/10`) was seen on the path.
  Derived from the hop addresses themselves, so it fires whatever the detector
  made of the network. Consumer NAT (RFC 1918) is deliberately *not* flagged: a
  signal that fires on every home LAN says nothing.
- `sni_inspected` — a middlebox/PEP handled a **TCP/443** probe (SNI-bearing
  flow); shown in-graph as an **orange diamond** node plus a tooltip line.
- `rst_flood` — three or more TCP RSTs on one flow: active reset injection.
- `tcp_silently_dropped` — TCP was sent, nothing came back at the TCP layer, and
  the destination was never reached. This is the one that actually fires in
  practice: every restricted-network run measured saw silent drops and **zero**
  RSTs.
  On its own it is not proof of censorship — a destination that ignores a bare
  TTL-limited SYN looks identical — so read it against the accessible control.
- `reply_forged` — the answer that came back from the destination **was not
  written by the destination**. Two signals, either sufficient: the reply
  carries the query's own IP ID (a box mutating the request in place rather
  than composing an answer), or its TTL implies an initial value no real stack
  emits. `forgery_evidence` names which fired, and the hop is drawn as its own
  node rather than as the destination. See `utils/forgery.py`.
- `dpi_cleared` — no inspection evidence and the network is `open`. Being NATted
  is deliberately not part of this: that is a fact about the topology, not about
  whether anyone inspected the traffic.

These ride on every `traceroute_data` record and render in the pyvis tooltip
(`NAT`/`Middlebox`/`PEP` plus the five DPI lines). Each hop additionally records
the port it actually probed (`dport`, which matters once RST rotation moves it),
its `rst_count`, and — when a TCP handshake was refused rather than ignored — a
`note` saying what answered instead.

## DNS resilience (DoT/DoH + dnstt + blackhole routing)

In networks where DNS is hijacked into the `10.10.34.0/24` filter net, or where
only DNS/UDP is permitted, use one of the DNS modes. Each sends the same
**accessible vs blocked domain** pair, so every run carries its own control.

- `--dns` (default) — plain UDP/53.
- `--dnstcp` — the same query over TCP/53.
- `--dnsdot` — TCP/853, the DoT port. Note this is a DNS query *on* 853, not a
  TLS session: it measures whether anything answers on that port, not whether
  DoT works.
- `--dnstt` — the dnstt carrier shape over UDP/53.

At most one may be set. `--port-pool` is ignored for all four with a notice —
rewriting the destination port would stop the probe being a DNS probe — while an
explicit `--port` is obeyed with a warning, since "is UDP/2053 reachable at all?"
is a fair question just not a DNS one.

### The default target pool

With no `-i/--ips`, the DNS modes and `--sni-test` fall back to three
destinations that are **not** a list of equals, and the run prints which is
which:

```
· · · - · default targets: 1.1.1.1 (control), 1.0.0.1 (same-operator control), 8.8.8.8 (treatment)
```

`1.1.1.1` is the only destination measurement has found reachable there;
`1.0.0.1` is Cloudflare too and was *unreachable* in the same run that `1.1.1.1`
answered, which separates a per-IP allowlist from a per-operator one; `8.8.8.8`
is reachable on UDP/53 and not on TCP/443, which is what rules out a purely
per-destination model. Deleting the destinations that fail would leave a pool
where everything answers — unfalsifiable by construction. The roles are a
hypothesis carried from one network, not a property of the addresses.

## How to use

##### Default DNS trace:

```sh
python3 ./tracevis.py --dns
```

or with docker image:

```sh
docker run ghcr.io/kouroszanbouri/tracevis --dns
```

or trace in paris mode:

```sh
python3 ./tracevis.py --dns --paris
```

##### Packet trace:

```sh
python3 ./tracevis.py --packet
```

or with docker image:

```sh
docker run -it ghcr.io/kouroszanbouri/tracevis --packet
```

##### trace with a config file:

```sh
python3 ./tracevis.py --config ./samples/quicv0xbabababa.conf
```

or you can override:

```
python3 ./tracevis.py --config ./samples/syn.conf -i "75.2.60.5,99.83.231.61"
```

_(There is more in `./samples`: Client-Hello, NTP, HTTP-GET, and more QUIC packets)_

###### The sample target pool

Generic path-probing samples (`syn`, `syn443`, `portpool_degraded`, all four
`quic*`) share one refreshed target pool:
`1.1.1.1,104.16.133.229,142.251.36.14,151.101.1.57` — Cloudflare's anycast
resolver plus a Cloudflare, Google and Fastly edge. `1.1.1.1` leads because it
is the only TCP destination observed completing a handshake, which makes it
the control for A/B tests.

Three samples deliberately keep their own targets, because their payload names
the destination and retargeting would make the probe incoherent:
`clienthello.conf` and `httpget.conf` (both carry `instagram.com`) and
`ntp.conf` (only an NTP server can answer it).

- `reality-non443.conf` — a **Reality-shaped** probe pair:
  a real TCP handshake followed by a minimal but structurally valid TLS 1.2/1.3
  ClientHello carrying a borrowed SNI (`hcaptcha.com`, the one "well-selected
  SNI" — a real domain whose traffic a censor is unlikely to want to break).
  It is *not* a browser fingerprint — five extensions,
  no GREASE/ALPN/key_share — so it is distinguishable from real Chrome traffic
  by any DPI doing JA3/JA4.
  The two probes are **identical except for the destination port** — packet 1
  goes to **443** as the control, packet 2 to **8443** — so a single run
  isolates the port variable that the common "a port other than 443 survives
  longer" advice rests on. **Measured: both arms reached**, and the same
  destination also answered on two further ports — so where that was measured,
  443 was not penalised and the advice had nothing to improve on. `1.1.1.1` is
  the target because it is the only destination observed completing a TCP
  handshake on 443, making the control arm known-good.

  > Do **not** add `--port` or `--port-pool` to this sample: both rewrite the
  > dport of *both* packets to a single value and collapse the comparison.

  > This is **not** a Reality client — TraceVis sends one crafted probe per TTL
  > step and never completes a TLS session. It measures where the path dies for
  > a Reality-shaped flow; it cannot exercise Reality's stateful "cooling-off"
  > blacklisting, which needs repeated reconnects. Note also that
  > `utils/dpi.py`'s `sni_inspected` classifier only fires on port 443, so it
  > reports on the control arm only. SNI is deliberately not varied here —
  > `--sni-test` owns that dimension, and where this was measured the blocking
  > was not SNI-based.

  > A **silently dropped** treatment port retries the handshake five times per
  > TTL step before giving up, so a fully dead port costs roughly 11 minutes for
  > that arm. A **refused** one (RST, or ICMP prohibited) is not retried — a box
  > that answers is awake, and four more SYNs buy nothing — so it costs one
  > probe, and the hop records what refused it. A refusal is the good case: it
  > proves the path to that port is open.

- `dnstt.conf` — the dnstt carrier probe: plain DNS over
  **UDP/53** to three resolvers with `--timeout-profile shutdown` (60s), the
  only channel observed still working end to end. Because the
  shutdown profile is slow, the sample caps `maxttl` at 20 and `repeat` at 1;
  drop to `--timeout-profile degraded` when you are not in a blackout.

###### Protocol-shape probes

Three protocols commonly used to get through a restrictive network had no probe
shape in the pool. Each sample is a **controlled A/B**: two probes that differ in exactly one
thing, so a difference in outcome has one explanation.

- `grpc-h2c.conf` — a TLS ClientHello (control) against an **HTTP/2 cleartext
  preface**, both to `1.1.1.1:443`, both with a handshake. Port 443 is where
  deep inspection is most often reported, with non-TLS payloads said to draw a
  RST; the h2c preface is the cleanest non-TLS pattern there is. If the control reaches and the preface
  does not, 443 is being checked for TLS conformance rather than merely watched.
- `shadowsocks.conf` — the same control against **Shadowsocks AEAD opening
  bytes** (32-byte salt, encrypted length block, encrypted chunk — headerless
  and high-entropy by design). Tests the same claim from the other side: does
  443 reject a payload simply for not looking like TLS?
- `wireguard.conf` — a **WireGuard handshake initiation** (type 1, 148 bytes)
  against same-length random UDP on port 51820. WireGuard is widely reported as
  blackholed on handshake detection. Same port, same length, so if the
  WireGuard arm dies earlier the DPI matched the *pattern* rather than "unknown
  UDP on an odd port". UDP, so there is no handshake cost and it runs against
  the full target pool.

> Both TCP samples pin `1.1.1.1:443` deliberately. It is the only destination
> observed completing a TCP handshake, and without a completed handshake
> the probe is a stray PSH/ACK that any stack drops — the run would answer
> nothing. As with `reality-non443.conf`, do not add `--port` or `--port-pool`.

Regenerate them with
`PYTHONPATH=. python3 tools/build_protocol_samples.py` (the crypto-shaped
fields are random on each build, which is correct — none of them carry real key
material, and none needs to).

##### Download traceroute data from a RIPE Atlas probe:

```sh
python3 ./tracevis.py --ripe [probe-id]
```

or with docker image:

```sh  
docker run \
    --mount type=bind,source=/path/to/results,target=/tracevis_data/ \
    ghcr.io/kouroszanbouri/tracevis --ripe [probe-id]
# OR
docker run \
    -v /path/to/results/:/tracevis_data/ \
    ghcr.io/kouroszanbouri/tracevis --ripe [probe-id]

```

##### Visualize a json file:

```sh
python3 ./tracevis.py --file ./path/to/file.json
```

or with docker image:

```sh
docker run \
    --mount type=bind,source=/path/to/results,target=/tracevis_data/ \
    ghcr.io/kouroszanbouri/tracevis --file /tracevis_data/file.json
# OR
docker run \
    -v /path/to/results/:/tracevis_data/ \
    ghcr.io/kouroszanbouri/tracevis --file /tracevis_data/file.json

```

##### See the help message: 

```sh
python3 ./tracevis.py -h
```

or with docker image:

```sh
docker run ghcr.io/kouroszanbouri/tracevis
```

##

#### Examples:

![example graph](https://user-images.githubusercontent.com/12384263/144353391-b7add54f-ef8b-48e0-988f-8c64b95dca76.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825581-e2bd4bdb-874f-4fad-9a54-6c39beab0398.png)

![example cli](https://user-images.githubusercontent.com/12384263/137825216-e76ddeaa-0592-422b-a08b-bd44329a6934.png)

![example cli](https://user-images.githubusercontent.com/12384263/144353450-4c6fd048-4353-482c-9571-523ad68eda30.png)

![example graph](https://user-images.githubusercontent.com/12384263/137825263-b5bc658e-a5af-47e3-9839-d1c75fa6be1b.png)

![example graph](https://user-images.githubusercontent.com/12384263/144697205-471b83a1-b98b-4b9f-8860-d8649a3d3e90.png)

![example graph](https://user-images.githubusercontent.com/12384263/144353412-37214aaa-040d-4b1f-a4b5-b812b96b1521.png)



## Credits and license

TraceVis was created by the [WikiCensorship](https://github.com/wikicensorship)
project ([wikicensorship/tracevis](https://github.com/wikicensorship/tracevis)).
This repository continues that work as an independent fork; the original
authors' commit history is preserved intact.

Released into the public domain under [the Unlicense](LICENSE), as upstream was.
