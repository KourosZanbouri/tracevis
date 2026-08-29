"""A/B arm comparison for paired-probe captures (backlog §2.10).

Several samples send two probes to the same destination and port, differing
only in payload: a **control** the network is known to pass, and a
**treatment** whose fate is the question. `grpc-h2c`, `shadowsocks` and
`wireguard` are all built this way.

The backlog recorded these as unanswerable — "the DPI dropped it" and "the
server ignored it" being indistinguishable without a destination that would
answer the treatment. That is true for one of the three and not for the other
two, and the difference is worth extracting rather than waiting on an
endpoint:

* When the control reaches the destination and gets an application answer,
  and the treatment on the *same path, port and destination* gets nothing at
  all, the path carried one payload and not the other. A server that dislikes
  a payload still answers at the TCP layer.
* When **both** arms die at the same hop, the block is not payload-based at
  all — it is the port or the path. Also a result.
* When neither arm can be told apart because nothing answers either way, this
  module says so, and names what would settle it, instead of guessing.

The strongest single datum is whether the treatment's TCP handshake reached
the destination. The handshake is not TTL-limited, so a SYN-ACK proves the
destination was reachable at that moment, which separates "dropped on the
path" from "never reachable". `utils/trace.py` records it per hop as
``handshake``; captures taken before that exist and are handled as unknown.
"""

from collections import namedtuple

CONTROL_MARKER = "(control)"

ArmSummary = namedtuple("ArmSummary", [
    "key", "annotation", "dst", "proto", "port",
    "reached", "last_responding_hop", "total_hops",
    "handshake",          # True / False / None (not recorded or not attempted)
    "app_answered",       # a reply from the destination carrying payload
])

ArmVerdict = namedtuple("ArmVerdict", [
    "dst", "control", "treatment", "verdict", "confidence", "reason", "needs",
])

# Verdicts, in the order a reader should think about them.
PAYLOAD_DROPPED = "payload dropped on path"
PAYLOAD_PROBABLY_DROPPED = "payload probably dropped on path"
TREATMENT_UNREACHABLE = "destination unreachable for the treatment"
PORT_BLOCKED = "port or path blocked regardless of payload"
BOTH_DELIVERED = "both arms delivered"
CONTROL_FAILED = "control failed — the pairing proves nothing"
INCONCLUSIVE = "inconclusive"


def _is_control(measurement):
    return CONTROL_MARKER in (measurement.get("annotation") or "").lower() \
        or CONTROL_MARKER in (measurement.get("annotation") or "")


def summarise_arm(measurement):
    """Reduce one measurement to the facts an arm comparison needs."""
    dst = measurement.get("dst_addr", "")
    reached = False
    app_answered = False
    last_hop = 0
    handshake = None
    hops = measurement.get("result") or []
    for hop in hops:
        for reply in hop.get("result") or []:
            if reply.get("handshake") is not None and handshake is not True:
                # Any successful handshake across the run settles reachability,
                # so once this is True it is never revisited: a later failure
                # does not unprove an earlier SYN-ACK. The `is not True` guard
                # is what enforces that -- an `or handshake` on the assignment
                # would be dead code, because the guard means we only ever get
                # here while `handshake` is None or False.
                handshake = bool(reply["handshake"])
            if reply.get("from"):
                last_hop = hop.get("hop", last_hop)
                if reply["from"] == dst:
                    reached = True
                    summary = str(reply.get("summary") or "")
                    # A bare ACK/RST is a TCP-layer answer; "Raw" means the
                    # destination sent application bytes back.
                    if "Raw" in summary or "PA" in summary:
                        app_answered = True
    return ArmSummary(
        key=f"{dst} [{measurement.get('annotation') or '-'}]",
        annotation=measurement.get("annotation") or "-",
        dst=dst,
        proto=measurement.get("proto", ""),
        port=measurement.get("port", -1),
        reached=reached,
        last_responding_hop=last_hop,
        total_hops=len(hops),
        handshake=handshake,
        app_answered=app_answered,
    )


def _classify(control, treatment):
    """Decide what a control/treatment pair supports, and how strongly."""
    if not control.reached and treatment.reached:
        return (CONTROL_FAILED, "weak",
                ("the control never reached the destination but the treatment "
                 "did, so the pairing is inverted or the control is wrong"),
                "a control the network is known to pass")

    if control.reached and treatment.reached:
        return (BOTH_DELIVERED, "strong",
                ("both arms reached the destination, so nothing on the path "
                 "dropped either payload"),
                "")

    if not control.reached and not treatment.reached:
        if control.last_responding_hop == treatment.last_responding_hop:
            return (PORT_BLOCKED, "moderate",
                    (f"neither arm got past hop {control.last_responding_hop},"
                     " and they died at the same hop, so what stopped them is"
                     " not the payload"),
                    ("a destination that answers this port, to separate an "
                     "on-path block from a closed port"))
        return (INCONCLUSIVE, "weak",
                ("neither arm reached the destination and they died at "
                 "different hops"),
                "a destination that answers this port")

    # The interesting case: control through, treatment not.
    if treatment.handshake is True:
        return (PAYLOAD_DROPPED, "strong",
                ("the treatment's TCP handshake reached the destination, so it"
                 " was reachable; the data probe carrying the payload then got"
                 " nothing back, and a server that dislikes a payload still"
                 " answers at the TCP layer"),
                "")
    if treatment.handshake is False:
        return (TREATMENT_UNREACHABLE, "moderate",
                ("the treatment's handshake never completed, so the payload"
                 " was never delivered and this pairing says nothing about how"
                 " the payload itself is treated"),
                "a run where the treatment's handshake succeeds")
    return (PAYLOAD_PROBABLY_DROPPED, "moderate",
            (f"the control reached {control.dst} and the treatment, on the"
             " same path and port, got nothing across"
             f" {treatment.total_hops} hops — but this capture does not record"
             " whether the treatment's handshake reached the destination, so a"
             " server that declined the payload is not fully excluded"),
            ("a re-run with a build that records the handshake outcome, which"
             " settles it without needing a new endpoint"))


def compare_arms(measurements):
    """Pair control/treatment arms per destination and classify each pair."""
    by_dst = {}
    for measurement in measurements:
        if not isinstance(measurement, dict) or not measurement.get("dst_addr"):
            continue
        by_dst.setdefault(measurement["dst_addr"], []).append(measurement)

    verdicts = []
    for dst, group in by_dst.items():
        controls = [m for m in group if _is_control(m)]
        treatments = [m for m in group if not _is_control(m)]
        if not controls or not treatments:
            continue
        control = summarise_arm(controls[0])
        for treatment_measurement in treatments:
            treatment = summarise_arm(treatment_measurement)
            verdict, confidence, reason, needs = _classify(control, treatment)
            verdicts.append(ArmVerdict(
                dst=dst, control=control, treatment=treatment,
                verdict=verdict, confidence=confidence, reason=reason,
                needs=needs))
    return verdicts


def format_arms(verdicts):
    """Render arm verdicts as text."""
    if not verdicts:
        return ("no control/treatment pairs found — an arm comparison needs a "
                f"measurement whose annotation contains '{CONTROL_MARKER}'")
    lines = [f"arm comparison over {len(verdicts)} pair(s)", ""]
    for entry in verdicts:
        lines.append(f"  {entry.dst}  {entry.control.proto}/{entry.control.port}")
        lines.append(f"    control  : {entry.control.annotation[:64]}")
        lines.append(f"               reached={entry.control.reached} "
                     f"last-hop={entry.control.last_responding_hop} "
                     f"app-answer={entry.control.app_answered}")
        lines.append(f"    treatment: {entry.treatment.annotation[:64]}")
        lines.append(f"               reached={entry.treatment.reached} "
                     f"last-hop={entry.treatment.last_responding_hop} "
                     f"handshake={entry.treatment.handshake}")
        lines.append(f"    → {entry.verdict}  [{entry.confidence}]")
        lines.append(f"      {entry.reason}")
        if entry.needs:
            lines.append(f"      needs: {entry.needs}")
        lines.append("")
    return "\n".join(lines).rstrip()
