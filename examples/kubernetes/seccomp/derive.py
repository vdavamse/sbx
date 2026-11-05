#!/usr/bin/env python3
"""Derive sbx-userns.json from Docker's default seccomp profile (issue #15).

Usage: derive.py UPSTREAM_DEFAULT_JSON OUTPUT_JSON

UPSTREAM_DEFAULT_JSON is `seccomp/default.json` from https://github.com/moby/profiles
at the commit pinned below (the version Docker Engine docker-v29.9.1 vendors). Its
SHA-256 is checked before anything is written.

The output is meant for a container that drops ALL capabilities (the example pod
does). Two steps:

1. Resolve the capability conditions for an empty capability set, the way Docker
   evaluates them: drop every rule that applies only when the container holds a
   capability (`includes.caps`), and make every rule that applies when it lacks one
   (`excludes.caps`) unconditional. Reason: containerd 2.3.4 ignored these
   conditions when it loaded the unmodified file as a Kubernetes Localhost profile
   (observed: `setns`, `quotactl` and `clone3` were allowed with all capabilities
   dropped; docs/kubernetes.md, "Seccomp"). With the conditions resolved, the
   profile means the same thing on a runtime that honours them and on one that
   ignores them.
2. Add one unconditional ALLOW rule, right after the base allow list, for
   ADDED_SYSCALLS. Upstream allows `unshare`, `mount`, `umount2`, `sethostname` and
   `setns` only with CAP_SYS_ADMIN, allows `clone` without it only when no namespace flag
   is set, and does not list `pivot_root`. Each one was shown to be needed by
   removing it and running `sbx check` (`setns` is needed only by the report-only
   `keep-alive` item: `run --keep-alive` and `attach`).

Everything else is copied unchanged: the default action (EPERM), the architecture
map and every other rule, including the one that makes `clone3` fail with ENOSYS
(C libraries fall back to `clone`; sbx and bubblewrap did not need `clone3`).
Python standard library only; no network access.
"""

import hashlib
import json
import sys

UPSTREAM_REPO = "https://github.com/moby/profiles"
UPSTREAM_TAG = "seccomp/v0.2.4"
UPSTREAM_COMMIT = "245180c51918481c0525424b3ee025d2b435d46c"
UPSTREAM_PATH = "seccomp/default.json"
UPSTREAM_SHA256 = "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"

ADDED_SYSCALLS = [
    "clone",
    "mount",
    "pivot_root",
    "sethostname",
    "setns",
    "umount2",
    "unshare",
]

COMMENT = (
    "sbx (docs/kubernetes.md): namespace creation and joining, mount, pivot_root and sethostname "
    "without capabilities, for unprivileged user namespaces in a hostUsers: false pod"
)


def resolve_no_caps(rule: dict):
    """The rule as it applies to a container with no capabilities, or None."""
    if rule.get("includes", {}).get("caps"):
        return None
    out = dict(rule)
    excludes = dict(rule.get("excludes", {}))
    if excludes.pop("caps", None) is not None:
        if excludes:
            out["excludes"] = excludes
        else:
            del out["excludes"]
    return out


def derive(upstream: dict) -> dict:
    syscalls = upstream["syscalls"]
    base = syscalls[0]
    if base.get("action") != "SCMP_ACT_ALLOW" or set(base) - {"names", "action"}:
        raise SystemExit("unexpected upstream layout: rule 0 is not the base allow list")
    overlap = sorted(set(ADDED_SYSCALLS) & set(base["names"]))
    if overlap:
        raise SystemExit(f"upstream already allows {overlap} unconditionally; re-review")
    rest = [r for r in (resolve_no_caps(r) for r in syscalls[1:]) if r is not None]
    for rule in rest:
        if "caps" in rule.get("includes", {}) or "caps" in rule.get("excludes", {}):
            raise SystemExit(f"unresolved capability condition: {rule}")
    added = {"names": ADDED_SYSCALLS, "action": "SCMP_ACT_ALLOW", "comment": COMMENT}
    out = dict(upstream)
    out["syscalls"] = [base, added] + rest
    return out


def main(argv: list) -> int:
    if len(argv) != 3:
        print("usage: derive.py UPSTREAM_DEFAULT_JSON OUTPUT_JSON", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != UPSTREAM_SHA256:
        print(
            f"upstream SHA-256 mismatch: got {digest}, pinned {UPSTREAM_SHA256} "
            f"({UPSTREAM_REPO} {UPSTREAM_TAG} {UPSTREAM_COMMIT} {UPSTREAM_PATH})",
            file=sys.stderr,
        )
        return 1
    out = derive(json.loads(raw))
    with open(argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f, indent="\t")
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
