#!/usr/bin/env python3
"""Helpers for the `kubernetes` CI job (issue #15, docs/kubernetes.md).

Subcommands:

  variant NAME POD_YAML
      Print examples/kubernetes/pod.yaml with one required setting removed and the
      pod renamed to sbx-NAME. NAME is one of: no-procmount, seccomp-runtimedefault,
      no-apparmor. Plain text edits (no YAML library); each edit must match exactly
      once, so a changed manifest fails loudly instead of testing the wrong thing.

  assert-ok CHECK_JSON RC
      `sbx check --json` from the example pod: rc 0, network mode transparent, every
      item ok except landlock (report-only).

  assert-fail CHECK_JSON RC ITEM ERRNO [ITEM ERRNO ...]
      `sbx check --json` from a variant pod: rc 1, network mode unavailable, and each
      ITEM is FAIL. ERRNO is a number, or `-` for an item whose errno is null (the
      bwrap items report bwrap's stderr instead).

  assert-conformance CONF_JSON RC
      `sbx check --conformance --json`: the same assertions as the test job's
      conformance step (nothing FAILs, the 63 offline checks are ok or warn, the six
      network checks are opt-in skips, rc 0).

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
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def assert_ok(path, rc):
    r = load(path)
    bad = [
        f"{c['id']}={c['status']}"
        for c in r["capabilities"]
        if c["id"] != "landlock" and c["status"] != "ok"
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
        c = by.get(item)
        want = None if errno == "-" else int(errno)
        if c is None or c["status"] != "fail" or c["errno"] != want:
            problems.append(f"{item}: {c} (expected FAIL with errno {want})")
        else:
            print(f"ok: {item} FAIL errno {c['errno']}: {c['detail']}")
    if problems:
        print(json.dumps(r, indent=2))
        sys.exit("FAIL: " + "; ".join(problems))


def assert_conformance(path, rc):
    r = load(path)
    assert r["kind"] == "conformance" and r["version"] == 1, r.get("kind")
    assert r["network_mode"] != "unavailable", r["network_mode"]
    fails = [c["id"] for c in r["checks"] if c["status"] == "fail"]
    assert not fails, f"FAIL checks: {fails}"
    net = {"E01", "E02", "E03", "E04", "E05", "E06"}
    non_ok = {
        c["id"]: (c["status"], c.get("skip_kind"))
        for c in r["checks"]
        if c["status"] not in ("ok", "warn")
    }
    want = {i: ("skip", "opt-in") for i in net}
    assert non_ok == want, f"unexpected non-ok set: {non_ok}"
    offline = [c for c in r["checks"] if c["tier"] in ("host", "lab", "init")]
    assert len(offline) == 43 + 19 + 1 and all(
        c["status"] in ("ok", "warn") for c in offline
    ), "63 offline checks must pass"
    assert rc == 0, f"rc {rc} (expected 0)"
    s = r["summary"]
    print(f"ok: {s['ok']} ok, {s['fail']} FAIL, {s['warn']} warn, {s['opt_in_skips']} opt-in")


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
    elif cmd == "assert-conformance" and len(args) == 2:
        assert_conformance(args[0], int(args[1]))
    elif cmd == "summary" and len(args) == 2:
        summary(args[0], args[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
