#!/usr/bin/env python3
"""Summarise a hyperfine `--export-json` file for the report-only startup
overhead step (issue #10 AC3). Prints a Markdown table to stdout.

Both hyperfine shapes are read: 1.x writes each run's wall time (seconds) to
`results[i].times`; 2.x writes `results[i].measurements[j].time_wall_clock.value`.
A result whose shape is unknown is shown as n/a. This script never raises on
the JSON content: the step is report-only, and a crash here hides the numbers.
"""
import json
import statistics
import sys

TARGET_MS = 25.0


def wall_ms(result):
    """Sorted per-run wall times in ms, or None when the shape is unknown."""
    times = result.get("times")
    if isinstance(times, list) and times:
        try:
            return sorted(float(t) * 1e3 for t in times)
        except (TypeError, ValueError):
            return None
    measurements = result.get("measurements")
    if isinstance(measurements, list) and measurements:
        try:
            return sorted(float(m["time_wall_clock"]["value"]) * 1e3 for m in measurements)
        except (KeyError, TypeError, ValueError):
            return None
    return None


def p90(sorted_ms):
    return sorted_ms[min(len(sorted_ms) - 1, round(0.9 * (len(sorted_ms) - 1)))]


def render(doc, labels):
    """Returns (markdown lines, overhead in ms or None, warning text or None)."""
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        results = []
    rows = []
    for i, label in enumerate(labels):
        times = wall_ms(results[i]) if i < len(results) and isinstance(results[i], dict) else None
        rows.append((label, times))
    lines = [
        "### sbx run startup overhead (issue #10 AC3, report-only)",
        "",
        "| command | median (ms) | p90 (ms) |",
        "|---|---|---|",
    ]
    for label, times in rows:
        if times:
            lines.append(f"| `{label}` | {statistics.median(times):.2f} | {p90(times):.2f} |")
        else:
            lines.append(f"| `{label}` | n/a | n/a |")
    lines.append("")
    (_, bash), (_, sbx) = rows[0], rows[1]
    if not bash or not sbx:
        lines.append("Overhead: n/a (a result could not be read from the hyperfine JSON).")
        return lines, None, None
    overhead = statistics.median(sbx) - statistics.median(bash)
    lines.append(f"Overhead (median sbx - median bash): {overhead:.2f} ms; target < {TARGET_MS:g} ms.")
    warning = None
    if overhead >= TARGET_MS:
        warning = f"sbx run startup overhead is {overhead:.1f} ms (>= {TARGET_MS:g} ms target)"
    return lines, overhead, warning


LABELS = [
    "/usr/bin/bash -c true",
    "sbx run --policy bench.json -- /usr/bin/bash -c true",
]


def main(argv):
    try:
        with open(argv[1], encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, IndexError) as err:
        print("### sbx run startup overhead (issue #10 AC3, report-only)")
        print("")
        print(f"Overhead: n/a (cannot read the hyperfine JSON: {err}).")
        return 0
    lines, _, warning = render(doc, LABELS)
    print("\n".join(lines))
    if warning:
        print(f"::warning::{warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
