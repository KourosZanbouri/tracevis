import json
import urllib.request

IODA_BASE_URL = "https://ioda.caida.org/ioda-data/data/v3"
IODA_TIMEOUT = 15


def fetch_ioda_status(country_code, timeout=IODA_TIMEOUT):
    return _fetch_ioda_status_url(
        country_code, _default_url(country_code), timeout)


def _default_url(country_code):
    return f"{IODA_BASE_URL}/{country_code.upper()}/index.json"


def _fetch_ioda_status_url(country_code, url, timeout):
    result = {
        "country": country_code.upper(),
        "available": False,
        "outage": False,
        "latest_value": 0.0,
        "latest_date": None,
        "error": None,
    }
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "tracevis/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        result["available"] = True
        result.update(_parse_ioda_index(data))
    except Exception as e:  # noqa: BLE001 — network/JSON errors are all handled the same
        result["error"] = str(e)
    return result


def _parse_ioda_index(data):
    dates = []
    if isinstance(data, dict):
        files = data.get("data_files") or data.get("files") or []
        for entry in files:
            if isinstance(entry, dict):
                dates.append(entry)
            elif isinstance(entry, str):
                dates.append({"date": entry})
    elif isinstance(data, list):
        dates = data
    dates.sort(
        key=lambda d: d.get("date", "") if isinstance(d, dict) else str(d),
        reverse=True)
    latest_date = None
    if dates and isinstance(dates[0], dict):
        latest_date = dates[0].get("date")
    return {
        "latest_date": latest_date,
        "data_files": dates,
    }


def fetch_ioda_outage(country_code, target_date=None, timeout=IODA_TIMEOUT):
    status = fetch_ioda_status(country_code, timeout=timeout)
    if not status["available"]:
        return status
    query_date = target_date or status["latest_date"]
    if query_date is None:
        return status
    values = _fetch_daily_outage(country_code, query_date, timeout)
    if values is None:
        return status
    latest_val = max(values) if values else 0.0
    status["latest_value"] = latest_val
    status["outage"] = latest_val > 0.5
    status["latest_date"] = query_date
    return status


def _fetch_daily_outage(country_code, date_str, timeout):
    parts = str(date_str).replace("-", "").replace("/", "")
    if len(parts) != 8:
        return None
    year, month, day = parts[:4], parts[4:6], parts[6:8]
    url = (
        f"{IODA_BASE_URL}/{country_code.upper()}"
        f"/{year}/{month}/{day}/data.json"
    )
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "tracevis/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        vals = []
        if isinstance(data, dict):
            for key in ("values", "value", "data", "events"):
                arr = data.get(key)
                if isinstance(arr, list):
                    vals = [_coerce_float(v) for v in arr]
                    break
            if not vals:
                vals = _extract_values_generic(data)
        elif isinstance(data, list):
            vals = [_coerce_float(v) for v in data]
        return vals if vals else None
    except Exception:  # noqa: BLE001 — unreachable host returns no data
        return None


def _extract_values_generic(data):
    vals = []
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "value" in node and isinstance(node["value"], (int, float)):
                vals.append(node["value"])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return vals


def _coerce_float(v):
    if isinstance(v, dict):
        for key in ("value", "val", "v", "outage"):
            if key in v and isinstance(v[key], (int, float)):
                return v[key]
    if isinstance(v, (int, float)):
        return v
    return 0.0
