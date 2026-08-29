"""Middlebox reassembly probing (backlog §1.4, rescoped).

See `docs/rescope-1.4-reassembly.md` for why the original item — fragmenting
a ClientHello to evade SNI inspection — cannot ship, and why the inverse is
what is left worth measuring.

The measurement in one line: if a middlebox blocks on SNI, it must reassemble
the TCP stream to find the SNI, and reassembly needs state with a timeout.
Splitting the ClientHello across segments and raising the inter-segment delay
until the block stops firing measures that timeout.

Three pure pieces, none of which send anything:

* ``segment_payload``  — one payload into N TCP segments with correct
  sequence numbers, so a reassembling observer sees the original bytes.
* ``sweep_plan``       — the delays to try, coarse-to-fine.
* ``classify_sweep``   — outcomes in, a verdict and (where supported) a
  buffer bound out.

Sending is the caller's job, which is what keeps all of this testable without
a network.
"""

from collections import namedtuple

# Delays in milliseconds. Coarse and logarithmic on purpose: a reassembly
# buffer that holds for 5s is not meaningfully different from one that holds
# for 5.1s, and every extra step is another probe against a network that is
# watching how much traffic you generate.
DEFAULT_DELAYS_MS = (0, 10, 50, 100, 500, 1000, 2000, 5000, 10000)

# Outcomes a caller reports back for one probe.
BLOCKED = "blocked"        # the block fired: RST injected, or silence
DELIVERED = "delivered"    # the payload got through and was answered
UNKNOWN = "unknown"        # the probe itself failed; says nothing either way

Segment = namedtuple("Segment", ["seq", "payload", "delay_ms", "is_last"])

SweepResult = namedtuple("SweepResult", [
    "verdict", "confidence", "buffer_ms", "reason", "needs",
])

# Verdicts.
REASSEMBLES = "middlebox reassembles the stream"
NO_REASSEMBLY = "middlebox does not reassemble"
BUFFER_MEASURED = "middlebox reassembles; buffer bounded"
NOT_STREAM_BASED = "block is not stream-based"
INCONCLUSIVE = "inconclusive"


def segment_payload(payload, segment_count, initial_seq=0, delay_ms=0):
    """Split ``payload`` into ``segment_count`` TCP segments.

    Sequence numbers advance by the bytes actually carried, so an observer
    that reassembles sees exactly ``payload`` and one that does not sees no
    single segment containing it whole. The delay is attached to each segment
    rather than applied here: this function builds a plan, it does not sleep.

    A remainder is spread over the leading segments rather than dumped on the
    last one, so no segment is conspicuously larger than its neighbours --
    a lone big segment would be a signature of this tool rather than of
    ordinary traffic.
    """
    if segment_count < 1:
        raise ValueError("segment_count must be at least 1")
    if not payload:
        raise ValueError("payload must not be empty")
    # One byte per segment is the finest split the payload allows.
    segment_count = min(segment_count, len(payload))

    base, remainder = divmod(len(payload), segment_count)
    segments = []
    offset = 0
    for index in range(segment_count):
        size = base + (1 if index < remainder else 0)
        chunk = payload[offset:offset + size]
        segments.append(Segment(
            seq=initial_seq + offset,
            payload=chunk,
            # The first segment has nothing to wait behind.
            delay_ms=0 if index == 0 else delay_ms,
            is_last=index == segment_count - 1,
        ))
        offset += size
    return segments


def reassemble(segments):
    """Rebuild the payload from segments — the property the probe relies on.

    Present so the invariant is checkable rather than assumed: if this does
    not return the original bytes, the probe is measuring its own bug.
    """
    return b"".join(
        segment.payload for segment in sorted(segments, key=lambda s: s.seq))


def sweep_plan(delays_ms=None, segment_count=4):
    """The probes to run, in order. Each entry is (segment_count, delay_ms).

    The single-segment control comes first and is not optional. Without it a
    sweep cannot tell "the block stopped firing because the buffer expired"
    from "the block was never firing on this path in the first place".
    """
    delays = tuple(DEFAULT_DELAYS_MS if delays_ms is None else delays_ms)
    return [(1, 0), *[(segment_count, delay) for delay in delays]]


def classify_sweep(control_outcome, results):
    """Turn sweep outcomes into a verdict.

    ``control_outcome`` is the single-segment probe. ``results`` is an ordered
    sequence of ``(delay_ms, outcome)`` for the segmented probes.
    """
    usable = [(delay, outcome) for delay, outcome in results
              if outcome in (BLOCKED, DELIVERED)]

    if control_outcome == UNKNOWN or not usable:
        return SweepResult(
            INCONCLUSIVE, "weak", None,
            ("the control probe or every segmented probe failed, so nothing "
             "can be compared"),
            "a path where the single-segment control produces a clear outcome")

    if control_outcome == DELIVERED:
        # Nothing blocked the whole ClientHello, so there is no block whose
        # reassembly could be probed. Any segmented result here is noise.
        return SweepResult(
            NOT_STREAM_BASED, "moderate", None,
            ("the single-segment control was delivered, so no block fired on "
             "this payload and there is no reassembly behaviour to measure"),
            "a destination or SNI that this network actually blocks")

    # control_outcome == BLOCKED from here: a block exists.
    blocked = [delay for delay, outcome in usable if outcome == BLOCKED]
    delivered = [delay for delay, outcome in usable if outcome == DELIVERED]

    if not blocked:
        return SweepResult(
            NO_REASSEMBLY, "moderate", None,
            ("the whole payload was blocked but no segmented probe was, even "
             "with no inter-segment delay, so the middlebox is not "
             "reassembling the stream before it inspects"),
            "a repeat run, since a single clean sweep can also mean the block "
            "was withdrawn between probes")

    if not delivered:
        return SweepResult(
            REASSEMBLES, "moderate", None,
            (f"every segmented probe was blocked, out to {max(blocked)}ms "
             "between segments, so the middlebox reassembles and its buffer "
             "outlasts the delays tried"),
            "a longer sweep, to find the delay at which the buffer expires")

    # The informative case: blocked at short delays, delivered at long ones.
    last_blocked = max(blocked)
    first_delivered = min(d for d in delivered if d > last_blocked) \
        if any(d > last_blocked for d in delivered) else None
    if first_delivered is None:
        return SweepResult(
            INCONCLUSIVE, "weak", None,
            ("blocked and delivered outcomes are interleaved rather than "
             "separating at a threshold, which a buffer timeout would not "
             "produce"),
            "a repeat run; interleaving usually means the block is "
            "intermittent rather than delay-dependent")

    return SweepResult(
        BUFFER_MEASURED, "moderate", first_delivered,
        (f"blocked with up to {last_blocked}ms between segments and delivered "
         f"at {first_delivered}ms, so the middlebox reassembles and stops "
         f"holding the partial stream between those two delays"),
        "")


def run_sweep(sender, payload, plan, sleeper=None):
    """Run a sweep and return ``(control_outcome, [(delay_ms, outcome)])``.

    ``sender(segments)`` sends one probe and returns BLOCKED / DELIVERED /
    UNKNOWN. Injecting it keeps every ordering and timing decision here
    testable without a network, and leaves the one part that genuinely needs
    a network -- deciding what an outcome *was* -- in one place.

    ``sleeper`` is resolved at call time rather than defaulted in the
    signature, so a caller patching ``time.sleep`` is honoured. A default
    argument binds at import and would silently ignore the patch.
    """
    import time as _time
    sleeper = _time.sleep if sleeper is None else sleeper

    control_outcome = UNKNOWN
    results = []
    for index, (segment_count, delay_ms) in enumerate(plan):
        segments = segment_payload(payload, segment_count, delay_ms=delay_ms)
        outcome = sender(segments)
        if index == 0:
            # sweep_plan() always puts the single-segment control first.
            control_outcome = outcome
        else:
            results.append((delay_ms, outcome))
        # A pause between probes, not between segments: firing a sweep as
        # fast as the loop allows looks like a scan to whatever is watching.
        if index < len(plan) - 1:
            sleeper(1)
    return control_outcome, results


def probe_reassembly(sender, payload, delays_ms=None, segment_count=4,
                     sleeper=None):
    """Run a full sweep and classify it. The module's front door."""
    plan = sweep_plan(delays_ms=delays_ms, segment_count=segment_count)
    control_outcome, results = run_sweep(sender, payload, plan,
                                         sleeper=sleeper)
    return classify_sweep(control_outcome, results)


def format_sweep(result):
    """Render a sweep verdict as text."""
    lines = [f"reassembly probe: {result.verdict}  [{result.confidence}]"]
    if result.buffer_ms is not None:
        lines.append(f"  reassembly buffer expires by {result.buffer_ms}ms "
                     "between segments")
    lines.append(f"  {result.reason}")
    if result.needs:
        lines.append(f"  needs: {result.needs}")
    lines.append("  NOTE: this classification has never been run against live "
                 "DPI; see docs/rescope-1.4-reassembly.md")
    return "\n".join(lines)


def make_scapy_sender(dst, dport, source_ip, timeout=3,
                      sr_func=None, send_func=None, sleeper=None,
                      port_reserver=None):
    """Build the ``sender(segments)`` callable ``probe_reassembly`` drives.

    Every scapy entry point is an argument so the send logic -- handshake,
    segment order, the inter-segment delays, how an outcome is decided -- is
    testable without root and without a network. Only what a real middlebox
    does in response is left untested, and that is the part no amount of
    mocking could establish anyway.

    Outcome mapping, and its one real assumption: a fresh connection is made
    per probe, the segments are written in order with their delays, and then
    the reply decides. An injected RST is BLOCKED. Application bytes back are
    DELIVERED. **Silence is treated as BLOCKED**, which is sound only because
    this probe sends a ClientHello to a host that would answer one -- a
    silent drop is the documented blocking mechanism on these networks. Point
    it at a host that would not answer and that mapping stops being true; the
    handshake failing at all is reported UNKNOWN rather than guessed at.
    """
    import time as _time

    from scapy.all import IP, TCP, Raw
    sleeper = _time.sleep if sleeper is None else sleeper
    if sr_func is None or send_func is None:
        from scapy.all import send as _send
        from scapy.all import sr as _sr
        sr_func = sr_func or _sr
        send_func = send_func or _send

    def _reserve():
        if port_reserver is not None:
            return port_reserver()
        import utils.ephemeral_port
        return utils.ephemeral_port.ephemeral_port_reserve(source_ip, "tcp")

    def sender(segments):
        sport = _reserve()
        syn = IP(src=source_ip, dst=dst) / TCP(
            sport=sport, dport=dport, flags="S", seq=1000)
        answered, _unanswered = sr_func(syn, verbose=0, timeout=timeout)
        if not answered:
            return UNKNOWN
        reply = answered[0][1]
        if not reply.haslayer(TCP) or "S" not in str(reply[TCP].flags):
            # An RST or an ICMP error to the SYN says the connection was
            # refused, which is a fact about the port and not about how the
            # payload is inspected.
            return UNKNOWN
        server_seq = reply[TCP].seq + 1
        base_seq = reply[TCP].ack

        for segment in segments:
            if segment.delay_ms:
                sleeper(segment.delay_ms / 1000.0)
            packet = IP(src=source_ip, dst=dst) / TCP(
                sport=sport, dport=dport, flags="PA",
                seq=base_seq + segment.seq, ack=server_seq) / Raw(
                    load=segment.payload)
            send_func(packet, verbose=0)

        probe = IP(src=source_ip, dst=dst) / TCP(
            sport=sport, dport=dport, flags="A",
            seq=base_seq + sum(len(s.payload) for s in segments),
            ack=server_seq)
        answered, _unanswered = sr_func(probe, verbose=0, timeout=timeout)
        if not answered:
            return BLOCKED
        response = answered[0][1]
        if response.haslayer(TCP) and "R" in str(response[TCP].flags):
            return BLOCKED
        if response.haslayer(Raw) and bytes(response[Raw].load):
            return DELIVERED
        return BLOCKED

    return sender
