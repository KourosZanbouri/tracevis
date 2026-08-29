"""Continuous monitoring (backlog §2.7).

Filtering behaviour changes faster than a single measurement stays true, so
one capture dates quickly; what makes a change legible is the same probe
repeated and compared. This module runs the existing trace pipeline on an
interval and reports what moved between runs.

Three layers, deliberately separated so the interesting one is testable:

1. ``run_monitor`` — scheduling and run accounting. It takes the thing to run,
   the clock and the sleep as arguments, so the loop can be tested without
   sleeping and without tracing.
2. ``summarise_measurement`` — reduces one capture to a per-destination
   posture (reached, hop count, DPI/CGNAT/RST signals, network state).
3. ``build_trend`` / ``format_trend`` — compare those summaries across runs
   and say what changed. A pile of independent graphs is not a trend; the
   comparison is the deliverable.
"""

import json
import time
from collections import namedtuple

# The per-measurement booleans worth tracking over time. All are recorded on
# the measurement itself by utils.trace, so a summary needs no re-analysis.
TRACKED_SIGNALS = (
    "dpi_cleared",
    "cgnat_hop",
    "sni_inspected",
    "rst_flood",
    "tcp_silently_dropped",
    "reply_forged",
)

DEFAULT_INTERVAL = 300
UNKNOWN_STATE = "unknown"

RunRecord = namedtuple("RunRecord", ["index", "started", "path", "ok", "error"])


def _destination_key(measurement):
    """Identify a measurement arm.

    A capture routinely holds the same destination twice under different
    annotations -- that A/B contrast is the whole point of the protocol-shape
    samples -- so collapsing on ``dst_addr`` alone would average a control
    and its treatment into one meaningless line.
    """
    dst = measurement.get("dst_addr", "")
    annotation = (measurement.get("annotation") or "").strip()
    if annotation and annotation != "-":
        return f"{dst} [{annotation}]"
    return dst


def _destination_reached(measurement):
    """Did any hop actually answer from the destination address?

    "The trace ran to completion" is not the same question: a path that dies
    at hop 4 still produces 20 hops of stars.
    """
    dst = measurement.get("dst_addr")
    if not dst:
        return False
    for hop in measurement.get("result") or []:
        for reply in hop.get("result") or []:
            if reply.get("from") == dst:
                return True
    return False


def _responding_hops(measurement):
    """How many hops produced a reply from anything."""
    count = 0
    for hop in measurement.get("result") or []:
        if any(reply.get("from") for reply in hop.get("result") or []):
            count += 1
    return count


def summarise_measurement(path):
    """Reduce one capture file to the posture it recorded.

    Returns ``None`` when the file cannot be read or is not a measurement
    list. A monitor run whose capture is unreadable must not take the loop
    down with it -- on the networks this tool measures, a truncated write is
    an ordinary outcome.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            measurements = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(measurements, list) or not measurements:
        return None

    destinations = {}
    timestamp = None
    # `network_state` postdates most of this repository's captures, so it is
    # genuinely absent from older files rather than merely empty.
    state = UNKNOWN_STATE
    for measurement in measurements:
        if not isinstance(measurement, dict):
            continue
        if timestamp is None and measurement.get("timestamp"):
            timestamp = measurement["timestamp"]
        if measurement.get("network_state"):
            state = measurement["network_state"]
        destinations[_destination_key(measurement)] = {
            "reached": _destination_reached(measurement),
            "hops": _responding_hops(measurement),
            "signals": {name: bool(measurement.get(name))
                        for name in TRACKED_SIGNALS},
        }
    if not destinations:
        return None
    return {
        "path": path,
        "timestamp": timestamp,
        "network_state": state,
        "destinations": destinations,
    }


def build_trend(summaries):
    """Compare per-run summaries and report what moved.

    A destination absent from a run is recorded as ``None`` for that run
    rather than skipped, so a target that stops being probed is visible
    instead of silently smoothing into the series.
    """
    summaries = [s for s in summaries if s]
    keys = []
    for summary in summaries:
        for key in summary["destinations"]:
            if key not in keys:
                keys.append(key)

    destinations = {}
    for key in keys:
        series = []
        for summary in summaries:
            entry = summary["destinations"].get(key)
            series.append(None if entry is None else dict(entry))
        seen = [e for e in series if e is not None]
        reachability = {e["reached"] for e in seen}
        changed_signals = sorted(
            name for name in TRACKED_SIGNALS
            if len({e["signals"][name] for e in seen}) > 1)
        destinations[key] = {
            "series": series,
            "reachability_changed": len(reachability) > 1,
            "changed_signals": changed_signals,
            "missing_runs": sum(1 for e in series if e is None),
        }

    states = [s["network_state"] for s in summaries]
    return {
        "runs": len(summaries),
        "network_states": states,
        "network_state_changed": len(set(states)) > 1,
        "destinations": destinations,
    }


def format_trend(trend):
    """Render a trend as text. ``·`` reached, ``x`` unreachable, ``-`` absent."""
    if not trend["runs"]:
        return "no runs to compare"
    lines = []
    lines.append(f"monitor trend over {trend['runs']} run(s)")
    lines.append("  network state: " + " → ".join(trend["network_states"])
                 + ("   *** CHANGED ***" if trend["network_state_changed"] else ""))
    lines.append("")
    lines.append("  reachability (· reached, x unreachable, - not probed)")
    width = max((len(k) for k in trend["destinations"]), default=0)
    for key, entry in trend["destinations"].items():
        marks = "".join(
            "-" if e is None else ("·" if e["reached"] else "x")
            for e in entry["series"])
        notes = []
        if entry["reachability_changed"]:
            notes.append("REACHABILITY CHANGED")
        if entry["changed_signals"]:
            notes.append("signals: " + ", ".join(entry["changed_signals"]))
        suffix = ("   " + "; ".join(notes)) if notes else ""
        lines.append(f"    {key:<{width}}  {marks}{suffix}")
    if not any(e["reachability_changed"] or e["changed_signals"]
               for e in trend["destinations"].values()):
        lines.append("")
        lines.append("  nothing changed across these runs")
    return "\n".join(lines)


def run_monitor(runner, runs=0, interval=DEFAULT_INTERVAL,
                sleeper=None, clock=None, reporter=print):
    """Run ``runner`` repeatedly, returning a RunRecord for each attempt.

    ``runs=0`` means run until interrupted. The clock and the sleep are
    injected so the loop's own behaviour -- ordering, the interval, what
    happens when a run raises -- can be tested without sleeping through it.

    They default to ``None`` and are resolved here rather than in the
    signature: a default of ``time.sleep`` binds the function object once, at
    import, so ``mock.patch`` on ``time.sleep`` afterwards is silently
    ignored and the caller waits out the real interval believing it was
    stubbed. Resolving at call time makes the patch take.

    A run that raises is recorded and the loop continues. That is the whole
    reason the mode exists: a trace failing on a hostile network is a data
    point about the network, not a reason to stop watching it. Only
    KeyboardInterrupt stops the loop, and it keeps every run already done.
    """
    sleeper = time.sleep if sleeper is None else sleeper
    clock = time.time if clock is None else clock
    records = []
    index = 0
    try:
        while True:
            index += 1
            started = clock()
            try:
                path = runner()
                records.append(RunRecord(index=index, started=started,
                                         path=path, ok=bool(path), error=None))
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 - a failed run is data
                records.append(RunRecord(index=index, started=started,
                                         path=None, ok=False, error=str(exc)))
                if reporter:
                    reporter(f"· · · - · monitor run {index} failed: {exc}")
            if runs and index >= runs:
                break
            # Sleeping after the final run would make the mode take a whole
            # extra interval to return for no reason.
            sleeper(interval)
    except KeyboardInterrupt:
        if reporter:
            reporter(f"\n· · · - · monitor interrupted after {len(records)} run(s)")
    return records
