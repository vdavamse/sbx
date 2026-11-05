#!/usr/bin/env python3
"""Assert an offline `sbx check --conformance --json` report (issues #13, #15).

Usage: assert_conformance.py CONF_JSON RC [TITLE]

Shared by the `test` job (on the runner) and the `kubernetes` job (inside the
example pod), so the expected numbers live in one place. Passes when: the report
is kind "conformance" version 1; the network mode is not "unavailable"; no check
FAILs; the only non-ok/warn checks are the six network checks E01-E06, skipped as
opt-in; the offline tiers (host, lab, init) have exactly OFFLINE_CHECKS checks and
every one is ok or warn; and the exit code is 0. With TITLE, a one-line summary is
appended to $GITHUB_STEP_SUMMARY (when set). Exits 1 with every reason otherwise.
"""

import json
import os
import sys

# host 46 + lab 19 + init 1 (update together with the catalog).
OFFLINE_CHECKS = 46 + 19 + 1
NETWORK = {"E01", "E02", "E03", "E04", "E05", "E06"}


def problems(r, rc):
    out = []
    if r.get("kind") != "conformance" or r.get("version") != 1:
        out.append(f"not a version-1 conformance report: kind {r.get('kind')!r}")
        return out
    if r.get("network_mode") not in ("transparent", "explicit"):
        out.append(f"network mode {r.get('network_mode')!r} (expected transparent or explicit)")
    checks = r.get("checks", [])
    fails = [c["id"] for c in checks if c["status"] == "fail"]
    if fails:
        out.append(f"FAIL checks: {fails}")
    non_ok = {
        c["id"]: (c["status"], c.get("skip_kind"))
        for c in checks
        if c["status"] not in ("ok", "warn")
    }
    want = {i: ("skip", "opt-in") for i in NETWORK}
    if non_ok != want:
        out.append(f"unexpected non-ok set: {non_ok}")
    offline = [c for c in checks if c["tier"] in ("host", "lab", "init")]
    if len(offline) != OFFLINE_CHECKS:
        out.append(f"{len(offline)} offline checks (expected {OFFLINE_CHECKS})")
    bad = [c["id"] for c in offline if c["status"] not in ("ok", "warn")]
    if bad:
        out.append(f"offline checks not ok or warn: {bad}")
    if rc != 0:
        out.append(f"rc {rc} (expected 0)")
    return out


def main(argv):
    if len(argv) not in (3, 4):
        sys.exit(__doc__)
    try:
        with open(argv[1], encoding="utf-8") as f:
            r = json.load(f)
        rc = int(argv[2])
    except (OSError, ValueError) as err:
        sys.exit(f"FAIL: cannot read the report: {err}")
    found = problems(r, rc)
    s = r.get("summary", {})
    line = (
        f"{s.get('ok')} ok, {s.get('fail')} FAIL, {s.get('warn')} warn, "
        f"{s.get('capability_skips')} capability skip, {s.get('not_implemented')} not implemented, "
        f"{s.get('opt_in_skips')} opt-in, {s.get('duration_ms')} ms"
    )
    if len(argv) == 4 and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(f"### {argv[3]}\n{line}\n")
    if found:
        sys.exit("FAIL: " + "; ".join(found))
    print(f"ok: {line}")


if __name__ == "__main__":
    main(sys.argv)
