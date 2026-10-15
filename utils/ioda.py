"""IODA outage cross-check for RIPE Atlas captures (backlog §2.2, §3.2).

Asks IODA whether it recorded an outage for a country *while each measurement
in a capture was running*, and writes the answer onto the measurement, where
`utils.vis` renders it into the hop tooltip.

Backlog §3.2: the first version of this module called
`ioda.caida.org/ioda-data/data/v3/...`, which does not exist, and parsed a
schema nobody serves; its tests mocked that schema, so they passed while the
feature never fetched anything. This version targets the real v2 API, and its
tests run against responses recorded from it.

Why *events* and not *alerts*: an alert marks a state change, so during a
long outage the last one can be months old. A trace taken on 20 Jan 2026,
twelve days into that shutdown, has no alert anywhere near it. An event is an
interval (`from`, `until`), which is the question being asked.

IODA builds those intervals at query time, looking back `extendWindow` for
where each one started (14 days by default). Iran's `gtr` outage began on
8 Jan 2026 and was still open in October, so with the default a trace in
August saw nothing. Measured: a 90-day lookback still missed the `merit-nt`
outage that began on 8 Mar. `EXTEND_WINDOW` is a year. An outage older than
that is not reported. By then it is arguably IODA's new baseline rather than
an event, but it is a limit, not a guarantee.
"""

import json
import time
import urllib.parse
import urllib.request

IODA_EVENTS_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events"
IODA_TIMEOUT = 15
USER_AGENT = "tracevis"
# The API's default page size. A response this full may have been cut short,
# and a missing event reads as "no outage", so a full page is an error.
IODA_EVENT_LIMIT = 500
# Measurement windows closer than this share one request. A multi-VP capture
# can mix measurements years apart (Atlas serves each probe's latest result),
# and one request spanning all of them risks the page limit above.
SPAN_MERGE_GAP = 86400
EXTEND_WINDOW = 365 * 86400


def fetch_ioda_events(country_code, start, end, timeout=IODA_TIMEOUT):
    """Fetch IODA outage events for *country_code* overlapping [start, end].

    *start* and *end* are UTC epoch seconds. Returns a dict that never raises:
    ``{"country", "available", "events", "error"}``. Each event is reduced to
    ``{"datasource", "from", "until", "score"}``. ``until`` may be None for an
    outage still in progress.
    """
    result = {"country": country_code.upper(), "available": False,
              "events": [], "error": None}
    query = urllib.parse.urlencode({
        "entityType": "country", "entityCode": country_code.upper(),
        "from": int(start), "until": int(end), "format": "ioda",
        "limit": IODA_EVENT_LIMIT, "extendWindow": EXTEND_WINDOW})
    try:
        request = urllib.request.Request(
            f"{IODA_EVENTS_URL}?{query}", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode())
        result["events"] = parse_events(payload)
        result["available"] = True
    except Exception as exc:  # noqa: BLE001 — every failure means "no answer"
        result["error"] = str(exc) or exc.__class__.__name__
    return result


def parse_events(payload):
    """The events in an IODA v2 ``outages.events`` response.

    Raises ValueError on a response that is not one (an API error, or a
    different endpoint's shape), so the caller reports it rather than
    recording "no outage" on the strength of a payload it did not understand.
    """
    if not isinstance(payload, dict) or payload.get("error"):
        raise ValueError(
            f"IODA error: {payload.get('error') if isinstance(payload, dict) else payload!r}")
    data = payload.get("data")
    if not isinstance(data, list):
        # ValueError, not TypeError: the caller's contract is "this is not an
        # IODA events response", whatever shape it arrived in.
        raise ValueError("IODA response has no event list")  # noqa: TRY004
    if len(data) >= IODA_EVENT_LIMIT:
        raise ValueError(
            f"IODA returned a full page ({len(data)} events); it may be "
            "truncated, so it cannot show the absence of an outage")
    events = []
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("from"), (int, float)):
            continue
        until = entry.get("until")
        events.append({
            "datasource": str(entry.get("datasource", "?")),
            "from": int(entry["from"]),
            "until": int(until) if isinstance(until, (int, float)) else None,
            "score": entry.get("score"),
        })
    return events


def events_overlapping(events, start, end):
    """The events whose interval overlaps [start, end].

    Filtered here rather than trusted to the server: the API widens every query
    by ``extendWindow`` (14 days by default), so it also returns events that
    had ended before the measurement began.
    """
    return [e for e in events
            if e["from"] <= end and (e["until"] is None or e["until"] >= start)]


def measurement_window(measurement):
    """(start, end) epochs for a measurement, or None if it has no usable time.

    RIPE Atlas results carry ``timestamp`` and ``endtime``. A measurement with
    only ``timestamp`` is treated as an instant.
    """
    start = measurement.get("timestamp")
    if not isinstance(start, (int, float)) or start <= 0:
        return None
    end = measurement.get("endtime")
    if not isinstance(end, (int, float)) or end < start:
        end = start
    return int(start), int(end)


def merge_spans(windows, gap=SPAN_MERGE_GAP):
    """Merge (start, end) windows lying within *gap* seconds of each other."""
    spans = []
    for start, end in sorted(windows):
        if spans and start - spans[-1][1] <= gap:
            spans[-1][1] = max(spans[-1][1], end)
        else:
            spans.append([start, end])
    return [tuple(span) for span in spans]


def annotate_measurements(measurement_path, country_code, fetch=fetch_ioda_events):
    """Write IODA's outage status onto every measurement in a saved capture.

    Measurements close in time share one request (`merge_spans`). Each
    measurement is then judged against its own window.

    Returns ``(annotated, outages, status)``: how many measurements were
    annotated, how many of those overlap an outage, and a fetch result: the
    first failed one if any request failed (its measurements stay
    unannotated), otherwise the last successful one. *status* is None if the
    capture could not be read or had no usable times. A failure
    here never loses the capture: the annotation is extra information on a
    download that already succeeded.
    """
    try:
        with open(measurement_path, encoding="utf-8") as handle:
            measurements = json.load(handle)
    except (OSError, ValueError):
        return 0, 0, None
    if not isinstance(measurements, list):
        return 0, 0, None
    windows = [measurement_window(m) if isinstance(m, dict) else None
               for m in measurements]
    usable = [w for w in windows if w is not None]
    if not usable:
        return 0, 0, None
    events_by_span = {}
    status = failure = None
    for span in merge_spans(usable):
        status = fetch(country_code, *span)
        if status.get("available"):
            events_by_span[span] = status["events"]
        elif failure is None:
            failure = status
    status = failure or status
    count = outages = 0
    for measurement, window in zip(measurements, windows):
        span = next((s for s in events_by_span
                     if s[0] <= window[0] and window[1] <= s[1]), None) \
            if window is not None else None
        if span is None:
            continue
        overlapping = events_overlapping(events_by_span[span], *window)
        measurement["ioda_status"] = {
            "country": status["country"],
            "outage": bool(overlapping),
            "datasources": sorted({e["datasource"] for e in overlapping}),
            "events": overlapping,
            "window": list(window),
        }
        count += 1
        outages += bool(overlapping)
    try:
        with open(measurement_path, "w", encoding="utf-8") as handle:
            json.dump(measurements, handle)
    except OSError:
        return 0, 0, status
    return count, outages, status



def tooltip_line(ioda_status):
    """The tooltip text for a measurement's IODA status, or "" for none.

    Each datasource is shown with the date its outage began, so a condition
    months old (Iran's `gtr` since 8 Jan 2026) reads differently from one that
    started during the trace. Clean results are shown too: "no outage" is a
    finding when the path looks blocked, since it points at targeted
    filtering rather than a national event.
    """
    if not isinstance(ioda_status, dict):
        return ""
    country = ioda_status.get("country", "")
    if ioda_status.get("outage"):
        began = {}
        for event in ioda_status.get("events") or []:
            if isinstance(event, dict) and isinstance(event.get("from"), int):
                name = event.get("datasource", "?")
                began[name] = min(began.get(name, event["from"]), event["from"])
        if began:
            sources = ", ".join(
                f"{name} since {time.strftime('%Y-%m-%d', time.gmtime(start))}"
                for name, start in sorted(began.items()))
        else:
            sources = ", ".join(ioda_status.get("datasources") or []) or "?"
        return f"IODA[{country}]: outage ({sources})"
    return f"IODA[{country}]: no outage"
