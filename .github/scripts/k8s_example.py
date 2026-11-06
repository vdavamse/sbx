#!/usr/bin/env python3
"""Helpers for the `kubernetes` CI job (issue #15, docs/kubernetes.md).

The offline conformance assertions are shared with the test job in
assert_conformance.py. Subcommands:

  variant NAME POD_YAML
      Print examples/kubernetes/pod.yaml with one required setting removed and the
      pod renamed to sbx-NAME. NAME is one of: no-procmount, seccomp-runtimedefault,
      no-apparmor. Plain text edits (no YAML library); each edit must match exactly
      once, so a changed manifest fails loudly instead of testing the wrong thing.

  assert-ok CHECK_JSON RC
      `sbx check --json` from the example pod: rc 0, network mode transparent, every
      item ok except landlock (report-only); keep-alive must be ok too.

  assert-fail CHECK_JSON RC ITEM ERRNO [ITEM ERRNO ...]
      `sbx check --json` from a variant pod: rc 1, network mode unavailable, and each
      ITEM is FAIL. ERRNO is a number, or `-` for an item whose errno is null (the
      bwrap items report bwrap's stderr instead).

  summary CHECK_JSON TITLE
      A Markdown block for $GITHUB_STEP_SUMMARY (never fails on content).
"""

import json
import sys

VARIANTS = {
    "no-procmount": [("        procMount: Unmasked\n", "")],
    "seccomp-runtimedefault": [
        (
            "        seccompProfile:\n"
            "          type: Localhost\n"
            "          localhostProfile: profiles/sbx/sbx-userns.json\n",
            "",
        )
    ],
    "no-apparmor": [("        appArmorProfile:\n          type: Unconfined\n", "")],
}


def variant(name, path):
    if name not in VARIANTS:
        sys.exit(f"unknown variant {name!r}; one of {sorted(VARIANTS)}")
    text = open(path, encoding="utf-8").read()
    edits = VARIANTS[name] + [("  name: sbx-example\n", f"  name: sbx-{name}\n")]
    for old, new in edits:
        if text.count(old) != 1:
            sys.exit(f"variant {name}: expected exactly one {old!r} in {path}")
        text = text.replace(old, new)
    sys.stdout.write(text)


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as err:
        sys.exit(f"FAIL: cannot read {path}: {err}")


# The `sbx check` items (src/host/mod.rs CapId::ALL), all of which must be present.
# keep-alive is report-only like landlock, but the example's seccomp profile allows
# what it needs (pidfd_open, setns), so it must be ok in the pod, as on the runner.
# conntrack is report-only too: ok, or skip when the pod cannot read the table.
ITEMS = {
    "userns", "netns", "netns-ipv6", "nft", "fallback",
    "bwrap", "bwrap-run", "bwrap-proc", "seccomp", "landlock", "keep-alive",
    "conntrack",
}


def assert_ok(path, rc):
    r = load(path)
    missing = sorted(ITEMS - {c["id"] for c in r["capabilities"]})
    if missing:
        print(json.dumps(r, indent=2))
        sys.exit(f"FAIL: items missing from the report: {missing}")
    bad = [
        f"{c['id']}={c['status']}"
        for c in r["capabilities"]
        if c["id"] != "landlock" and c["status"] != "ok"
        and not (c["id"] == "conntrack" and c["status"] == "skip")
    ]
    if rc != 0 or r["network_mode"] != "transparent" or bad:
        print(json.dumps(r, indent=2))
        sys.exit(f"FAIL: rc {rc}, network mode {r['network_mode']}, not ok: {bad}")
    print(f"ok: rc 0, transparent, {len(r['capabilities'])} items")


def assert_fail(path, rc, pairs):
    r = load(path)
    by = {c["id"]: c for c in r["capabilities"]}
    problems = []
    if rc != 1:
        problems.append(f"rc {rc} (expected 1)")
    if r["network_mode"] != "unavailable":
        problems.append(f"network mode {r['network_mode']} (expected unavailable)")
    for item, errno in zip(pairs[::2], pairs[1::2]):
        # `item` may carry a required detail substring: "userns:blocked by a seccomp filter".
        item, _, text = item.partition(":")
        c = by.get(item)
        want = None if errno == "-" else int(errno)
        if c is None or c["status"] != "fail" or c["errno"] != want or text not in c["detail"]:
            problems.append(f"{item}: {c} (expected FAIL with errno {want} and detail containing {text!r})")
        else:
            print(f"ok: {item} FAIL errno {c['errno']}: {c['detail']}")
    if problems:
        print(json.dumps(r, indent=2))
        sys.exit("FAIL: " + "; ".join(problems))


def summary(path, title):
    print(f"### {title}")
    try:
        r = load(path)
        print(f"network mode: `{r.get('network_mode')}`")
        print("")
        print("| item | status | detail | evidence |")
        print("|---|---|---|---|")
        for c in r.get("capabilities", []):
            ev = (c.get("evidence") or "").replace("|", "\\|")
            print(f"| {c.get('id')} | {c.get('status')} | {c.get('detail')} | {ev} |")
    except (OSError, ValueError, AttributeError, TypeError) as err:
        print(f"no report: {err}")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, args = argv[1], argv[2:]
    if cmd == "variant" and len(args) == 2:
        variant(args[0], args[1])
    elif cmd == "assert-ok" and len(args) == 2:
        assert_ok(args[0], int(args[1]))
    elif cmd == "assert-fail" and len(args) >= 4 and len(args) % 2 == 0:
        assert_fail(args[0], int(args[1]), args[2:])
    elif cmd == "summary" and len(args) == 2:
        summary(args[0], args[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
