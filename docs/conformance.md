# Conformance

`sbx check --conformance` runs every security guarantee as an executable check:
81 checks in nine groups, the same code that `cargo test --test conformance`
runs in CI. The [threat model](threat-model.md) maps each guarantee to the
checks that prove it, and lists what they do not prove.

- **A: allow list** (`allow-list`): allowed names resolve and reach the upstream;
  everything else is refused on DNS, CONNECT and TLS.
- **B: SNI/Host confusion** (`sni-host`): a mismatched SNI, Host or ECH hello is
  refused, and a second ClientHello tears the connection down.
- **C: no direct egress** (`no-direct-egress`): no route, no raw, packet, XDP,
  vsock or ICMP sockets, no non-53 UDP, no IPv6, no netlink changes.
- **D: isolation** (`isolation`): host loopback, abstract and pathname unix
  sockets, other sessions' listeners, files and fake IPs, and host processes
  are unreachable.
- **E: tooling** (`tooling`, network tier): real `curl`, `git`, `pip` and `npm`
  through the policy, and the real-network negatives; opt-in with `--network`.
- **F: fail-closed** (`fail-closed`): SIGKILL, SIGSTOP and a missing proxy leave
  no path open; a broken nftables load or audit log ends the run with rc 125.
- **G: cleanup** (`cleanup`): background processes die on exit, timeout and
  signals; the sandbox network namespace is empty afterwards.
- **I: persistent sessions** (`session`): an attached call cannot see or signal
  the resident or another call; a holder SIGKILL ends the resident and the calls;
  a different policy is refused; a foreign-uid connection is refused (an opt-in
  skip here, see the threat model); the idle and max-lifetime ends. Needs bwrap.
- **H: secrets** (`secrets`): the caller's environment, `/proc` environments,
  inherited descriptors, HOME and processes are not visible to the payload.

The tiers: **host** (a `sbx run` per scenario, built-in policies), **init**
(the production `sbx __init` with the listeners dropped), **lab** (an
unprivileged nested user, network and mount namespace with a local fixture on
9.9.9.9 and a lab DNS that never touches the real network), and **network**
(opt-in, real hosts). The offline tiers need no root and never dial a real
upstream: every lab upstream is local.
Their files live under `$TMPDIR/sbx-conformance-*`, with two documented
exceptions: the D04 control socket `/tmp/sbxc-<8 hex>.s` (kept short because
`sun_path` is 108 bytes), and, when `$TMPDIR` lies under `$HOME`, the base
directory under `/tmp` (so the sandbox's bind parents do not expose `$HOME`).
Both are removed at the end of a run.

```
sbx check --conformance                    # every offline check
sbx check --conformance --only A,D         # a group, or ids: --only A01,H06
sbx check --conformance --list             # the catalog (add --json for each check's needs)
sbx check --conformance --network --json   # add the network tier; JSON report
```

Exit codes: `0` when nothing failed and nothing needed by a selected check was
missing (warn rows and opt-in skips are allowed); `1` when a check FAILs or a
selected check is skipped for a missing capability or is not implemented in this
build; `2` for a usage error. The JSON document has `kind: "conformance"` and
`version: 1`; `summary.conformant` matches the exit code. A FAIL keeps the
temporary artifacts and prints their path on stderr. A full offline run takes a
few seconds (the budget is 120 s).

A `warn` (D05) means a unix socket file is visible inside the sandbox: a policy
hazard, not a defect. Find the bind that holds it with
`sbx check --policy P --host` (the `bind-sockets` item).

**Lab tier.** The 19 lab checks (A02–A06, A12, B01–B09, C02, C07, F02, F04) run
inside a child that unshares user, network and mount namespaces: no root, and
`lo` gets `9.9.9.9` (the fixture) and the trap addresses. The lab's
`resolv.conf` and `nsswitch.conf` are bound over the host's (`/etc/hosts` is
not touched). Its DNS answers `*.conformance.test` only and never forwards, and
it logs every query so the checks can prove that. The lab does not disable
`nscd`: a host name cache can only make A02–A06 fail (their "lab DNS saw the
name" control is absent), never pass without the proxy's own lookup. The lab
child dies with `sbx check` (`PR_SET_PDEATHSIG`), and its timing uses the
monotonic clock, which every process on the host shares. If the host cannot create a
nested user namespace, the lab checks are capability skips (rc `1`) with the
stage that failed, never passes. The lab is bounded to 60 s.

**Network tier.** `--network` runs six real tool checks (E01–E06) against
pypi.org, github.com, registry.npmjs.org and example.com, one `sbx run` each,
within a 300 s total allowance. E06 first proves the same policy reaches
pypi.org, so its negatives cannot pass vacuously. A missing tool (`curl`, `git`, `python3` with
pip, `npm`) is an opt-in skip, not a failure. The CI job `conformance-network`
runs it nightly; it does not gate pull requests.

Operator policies are not supported by `--conformance` in v1.
