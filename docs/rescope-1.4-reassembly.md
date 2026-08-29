# Backlog §1.4 — rescope

## The item as written

> TCP-reassembly-resistant packet emitter (jittered fragments)

The goal was to split a TLS ClientHello across fragments so that no single
packet contains a complete SNI, and so evade SNI-based blocking.

## Why it cannot ship as written

The technique targets a middlebox that inspects packets individually. Current
DPI reassembles the TCP stream before inspecting it, which is precisely what
makes SNI extraction possible at all — `utils/dpi.py` already encodes this:

> only a middlebox/PEP doing TCP reassembly on a 443 flow can extract SNI

So an emitter built to defeat per-packet inspection defeats something the
measured networks stopped doing. Building it would ship a circumvention
technique that is already dead, and — worse for a measurement tool — one
whose failure would be indistinguishable from the network simply blocking
the traffic.

## What is left that is worth measuring

The inverse. If the middlebox reassembles, that is a **behaviour with
parameters**, and the parameters are measurable:

1. **Does it reassemble at all?** Send the same ClientHello as one segment and
   as N segments with no delay. If the block fires both ways, the middlebox
   reassembles. If it fires only on the single segment, it inspects
   per-packet — which would be a notable finding about that network.

2. **How long does it hold the buffer?** Reassembly requires state, and state
   has a timeout. Sweep the inter-segment delay upward. The delay at which the
   block *stops* firing is the point where the middlebox gave up holding the
   partial stream. That number is a fingerprint of the equipment, and it is
   not otherwise observable from outside.

This turns a dead circumvention idea into a measurement no other part of the
tool makes. It also stays inside what this project is for: characterising the
filtering, not defeating it.

## Scope

- `utils/reassembly.py` — segment a payload into TCP segments with correct
  sequence numbers and a controlled inter-segment delay; plan a delay sweep;
  classify the outcome of a sweep into a reassembly verdict and, where the
  data supports one, a buffer bound.
- `--reassembly-probe` on the CLI, driving it through the existing tracer.

## What this cannot establish here

The classification is only as good as the signal that the block "fired", and
that signal comes from a real restricting network. This environment has
neither root nor a censoring path, so the emitter, the sweep and the
classifier are validated offline — segment construction against scapy,
scheduling and classification as pure functions, and the wiring through the
tracer against the existing `FakeNetwork` harness. **No part of this has been
run against live DPI.** A buffer bound reported by this code is a bound
derived from whatever outcomes it was given; whether those outcomes mean what
the classifier assumes is the thing that still needs a restricting network.
