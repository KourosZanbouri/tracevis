#!/usr/bin/env python3
import json
import os.path

csv_header_all = ""
csv_blank_row = ""
csv_prepared_row = ""

# Filler for a hop with fewer responses than the widest hop in the file.
BLANK = "-"


def prepare_csv_variables(keys):
    """Build the header and row templates for one conversion.

    These are module-level and used to be *appended to*, so a second
    `json2csv()` in the same process wrote a duplicate header row into the
    middle of the file — silently, since the corruption is on line 2 and the
    first line still looks right. The CLI converts once per run so it never
    surfaced there, the same way `utils.vis` never surfaced its accumulating
    graph. Reset first.
    """
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    csv_header_all = ""
    csv_blank_row = ""
    csv_prepared_row = ""
    for item in keys:
        csv_header_all += item + ','
        csv_blank_row += ','
        csv_prepared_row += "{" + item + "},"
    csv_header_all += '\n'
    csv_blank_row += '\n'
    csv_prepared_row += '\n'


def parse_json(file_name: str) -> list:
    data = []
    rows = []
    widest = 0
    with open(file_name, "r") as jsonfile:
        json_str = jsonfile.read()
    try:
        json_data = json.loads(json_str)
    except:
        print("JSON format is not valid!")
        return ""
    for measurement in json_data:
        dst_addr = measurement["dst_addr"]
        proto = measurement["proto"]
        if "annotation" in measurement.keys():
            annot = measurement["annotation"]
        else:
            annot = "-"
        for hop_row in measurement["result"]:
            hop = hop_row["hop"]
            res_from = []
            rtt = []
            ttl = []
            summary = []
            skip_next = False
            for result in hop_row["result"]:
                if skip_next:
                    skip_next = False
                    continue
                if "late" in result.keys():
                    skip_next = True
                if 'x' in result.keys():
                    res_from.append(result["x"])
                    rtt.append(result["x"])
                    ttl.append(result["x"])
                    summary.append("-")
                else:
                    res_from.append(result["from"])
                    if "rtt" in result.keys():
                        rtt.append(result["rtt"])
                    else:
                        rtt.append("*")
                    ttl.append(result["ttl"])
                    if "summary" in result.keys():
                        summary.append(result["summary"])
                    else:
                        summary.append("-")
            rows.append({
                "destination_address": dst_addr,
                "protocol": proto,
                "annotation": annot,
                "hop": hop,
                "_from": res_from, "_rtt": rtt, "_ttl": ttl, "_summary": summary,
            })
            widest = max(widest, len(res_from))
    # The column count used to be hardcoded at three, so `res_from[2]` raised
    # IndexError on any measurement taken with `-r 1` or `-r 2` — which is most
    # of `samples/` and of every run observed so far, and `tracevis.py` does not
    # catch it, so `--csv` ended in a raw traceback. The width now follows the
    # data, and short hops are padded so every row carries the same columns.
    for row in rows:
        per_hop = {"from": row.pop("_from"), "rtt": row.pop("_rtt"),
                   "ttl": row.pop("_ttl"), "summary": row.pop("_summary")}
        # Column order is preserved exactly: response_from/rtt/ttl grouped per
        # repeat, then every summary at the end. Anyone's existing spreadsheet
        # is keyed on it.
        for index in range(widest):
            for column, values in (("response_from", per_hop["from"]),
                                   ("rtt", per_hop["rtt"]),
                                   ("ttl", per_hop["ttl"])):
                row[f"{column}_{index + 1}"] = (
                    values[index] if index < len(values) else BLANK)
        for index in range(widest):
            summaries = per_hop["summary"]
            row[f"summary_{index + 1}"] = (
                summaries[index] if index < len(summaries) else BLANK)
        data.append(row)
    return data


def data_to_csv(data: list, sort_it: bool) -> str:
    global csv_header_all
    global csv_blank_row
    global csv_prepared_row
    csv_str = csv_header_all
    last_hop = 1
    for row in data:
        if sort_it:
            if row["hop"] > last_hop:
                csv_str += csv_blank_row
        else:
            if row["hop"] < last_hop:
                csv_str += csv_blank_row
        csv_str += csv_prepared_row.format_map(row)
        last_hop = row["hop"]
    return csv_str


def json2csv(file_name: str, sort_it: bool = True):
    if os.path.isfile(file_name):
        new_file_name = file_name.replace(".json", ".csv")
        data = parse_json(file_name)
        if not data:
            # `parse_json` returns "" on invalid JSON and [] on a file holding
            # no measurements; `data[0]` raised IndexError on both, after
            # `parse_json` had already printed a tidy explanation.
            print("· · · · · · · · no measurements to convert.")
            return
        prepare_csv_variables(data[0].keys())
        with open(new_file_name, "w") as csvfile:
            if sort_it:
                data = sorted(data, key=lambda d: d['hop'])
            csv = data_to_csv(data, sort_it)
            if csv != "":  # todo (xhdix): it will never be empty. we shold do better
                print("saving measurement in csv...")
                csvfile.write(csv)
                print("saved: " + new_file_name)
    else:
        print("error: " + file_name + " does not exist!")
