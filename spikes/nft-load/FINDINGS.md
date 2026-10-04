# FINDINGS — Spike: how to load nftables rules from Rust (issue #1)

Date: 2026-10-04 · Kernel: WSL2 6.18.40.1 · nft: v1.0.9 · Rust: 1.99 stable ·
Target: `x86_64-unknown-linux-musl`

## TL;DR

**Chosen: `netlink-bindings =0.3.5` + `netlink-socket2 =0.3.5`** (MIT OR
Apache-2.0, pure Rust, generated from kernel YAML specs), with the one
expression the crate cannot generate (`redir`) **hand-encoded through the
crate's public `Pusher` escape hatch** — the kernel-stored bytes are identical
to the `nft`-loaded reference (verified via raw GETCHAIN/GETRULE dumps, and by
`nft list ruleset` reproducing the rule).

Result: a **680,736-byte** static-pie musl binary (no dynamic deps, no C
toolchain beyond Rust's bundled musl startup objects) that runs as a normal
user, creates its own user+net namespace, loads the exact ruleset atomically
in one netlink write, verifies it via kernel dumps, and proves every
acceptance criterion with real traffic. All gates green: `cargo fmt`,
`clippy -D warnings`, unit tests, **10/10 consecutive full runs exit 0**,
`--break-rules` fail-closed verified (exit 3, `FAIL-CLOSED-VERIFIED`), and an
independent oracle check — entering the live netns and running
`nft list ruleset` prints **exactly** the reference ruleset, including
`redirect to :15001` from the hand-encoded expression.

## Acceptance-criteria evidence

| AC | How it is proven | Result |
|---|---|---|
| Static musl binary, no C runtime deps, runs unprivileged | `file` → `static-pie linked, stripped`; `readelf -d` → no `NEEDED`; `readelf -l` → no `INTERP`; `ldd` → `statically linked`; runs as uid 1000 and under `env -i` | ✅ |
| `unshare(USER\|NET)` + uid/gid maps (+ `setgroups deny`) | `src/netns.rs`; read-back via rtnetlink dumps; EPERM → AppArmor hint (exit 1) | ✅ |
| `lo` up, `10.255.255.1/32`, `default dev lo src 10.255.255.1` | typed rt-link/rt-addr/rt-route ops; **order load-bearing** (Q1: addr before route, else EADDRNOTAVAIL); GETLINK/GETADDR/GETROUTE asserts (exit 2) | ✅ |
| Exact ruleset, loaded atomically in one batch | single `writev` `Chained` batch: BEGIN(+genid), NEWTABLE, NEWCHAIN×2, NEWRULE×3 (CREATE\|APPEND), END; ERESTART/genid retry ≤5; post-load dump verification asserts every attribute byte-exact (exit 3/4) | ✅ |
| Fail closed on any error | dedicated exit codes 1–7; `--break-rules` proves the kernel rejects a broken batch (ENOENT) **and rolls back the whole transaction** (GETTABLE empty) → `FAIL-CLOSED-VERIFIED` + exit 3; unexpected acceptance → exit 7 | ✅ |
| TCP redirect + `SO_ORIGINAL_DST` | t1: connect `203.0.113.7:443` → accepted on `127.0.0.1:15001`, `SO_ORIGINAL_DST=203.0.113.7:443`, server sees peer `10.255.255.1`, client `getpeername` unchanged, reply path works with zero extra rules (conntrack un-NAT) | ✅ |
| UDP-53 redirect | t3: round-trip on a socket connected to `203.0.113.7:53` (`QUERY\n` → `PONG 127.0.0.1:53`) + listener event (bare `redirect` keeps dport 53) | ✅ |
| UDP-non-53 drop, deterministic proof | t5: `send()` fails **synchronously with EPERM** + `/proc/net/snmp` `Ip OutDiscards` +1 (no timeouts); t4 positive control: local UDP allowed → ECONNREFUSED | ✅ |
| Structured PASS/FAIL + aggregate exit; 10× runs | table/`--json` on stdout, statuses on stderr; `scripts/local-test.sh` 10/10 exit 0; CI adds a 5× flake loop | ✅ |
| Apache-2.0-compatible deps, pinned | `netlink-bindings`/`netlink-socket2` MIT OR Apache-2.0; exact `=0.3.5` pins; committed `Cargo.lock`; CI `--locked` | ✅ |
| Write-up | this file + `ISSUE_COMMENT.md` | ✅ |

## Chosen option — details

### Crate

`netlink-bindings` (+ its socket layer `netlink-socket2`), both `=0.3.5`, by
one-d-wide. Type-safe Rust bindings **generated from the kernel's netlink YAML
specs**; features used: `nftables`, `rt-link`, `rt-addr`, `rt-route`
(`default-features = false`, plus `nlctrl` pulled in transitively by
netlink-socket2). Only dependency tree: `libc` + `strip-async` (proc-macro).
Pure Rust → links statically for musl with no external C toolchain.

### Maintenance snapshot (verified 2026-10-04 via crates.io/GitHub)

| | netlink-bindings | netlink-socket2 |
|---|---|---|
| Version used | 0.3.5 (pinned `=`) | 0.3.5 (pinned `=`) |
| License | MIT OR Apache-2.0 | MIT OR Apache-2.0 |
| Published | 2026-09-11 | 2026-09-11 |
| Cadence | ~monthly | ~monthly |
| Downloads | ~5.8k | ~3.8k |
| Repo | one-d-wide/netlink-bindings (~12★, single org, main = 0.3.6-dev) | same repo |

**Young-crate caveat** (0.x, small bus factor) and mitigations:

- exact version pins + committed `Cargo.lock` + CI `--locked` → no surprise
  updates;
- MIT/Apache licensing allows vendoring the sources into the repo if the crate
  is ever abandoned;
- the spike never trusts the crate blindly: every loaded object is verified
  against the kernel's own dump (`verify_dump`), and the ruleset is
  cross-checked with the independent `nft` CLI oracle;
- the hand-encoding skill (below) means a fallback to raw netlink bytes needs
  no new dependencies at all.

### The `redir` gap and the escape hatch

`redirect` is not in the crate's bundled kernel YAML spec (0 occurrences —
verified), so there is no generated `redir` expression type. The crate exposes
a public, documented escape hatch: `netlink_bindings::traits::Pusher`
(`as_vec_mut()` on every push-builder) plus `utils::{push_header,
push_nested_header, finalize_nested_header}`. `src/rules.rs::push_redir` uses
it to append an expression whose kernel-stored bytes are identical to the
`nft`-loaded reference (raw GETRULE dump, `rules/ground-truth.md` §5):

```text
NFTA_EXPR_NAME(1) = "redir\0"
NFTA_EXPR_DATA(2) = nest {                    # bare `redirect`: EMPTY nest
  NFTA_REDIR_REG_PROTO_MIN(1) = 1 (BE u32)    # Reg1
  NFTA_REDIR_REG_PROTO_MAX(2) = 1 (BE u32)    # Reg1
  NFTA_REDIR_FLAGS(3)         = 2 (BE u32)    # NF_NAT_RANGE_PROTO_SPECIFIED
}
```

Correctness evidence (three independent layers):

1. `rules/ground-truth.md` — raw `NETLINK_NETFILTER` dumps of the `nft`-loaded
   reference ruleset (checked into the repo);
2. in-binary `verify_dump` — after every load, the kernel dump must match the
   expected attribute values exactly (exit 4 otherwise), including raw
   `fib RESULT==3`;
3. `nft list ruleset` inside the live netns prints
   `meta l4proto tcp fib daddr type != local redirect to :15001` — nft's own
   printer accepts and reproduces the hand-encoded rule.

### Batch/transaction pattern (reusable for #5)

```text
GETGEN → Chained::new(sock.reserve_seq(256))
       → BATCH_BEGIN(+genid) NEWTABLE NEWCHAIN×2 NEWRULE×3(CREATE|APPEND) BATCH_END
       → sock.request_chained(&c.finalize())?.recv_all()
ERESTART (genid raced) → re-GETGEN + rebuild + resend, ≤5 attempts
any other error → fail closed (exit 3); kernel batch is all-or-nothing (F6)
```

## Binary size (measured, stripped, static-pie, musl)

| Release profile | Bytes | KiB |
|---|---|---|
| `opt-level = "s"`, lto=fat, codegen-units=1, panic=abort, strip | 684,832 | 668.8 |
| `opt-level = "z"` (same otherwise) — **chosen** | 680,736 | 664.8 |

CI asserts < 1 MiB (1,048,576 B). Both profiles pass all functional tests
identically.

## Rejected options

| Option | License | Verdict & why |
|---|---|---|
| **rustables 0.9.0** | **GPL-3.0-or-later** | **Rejected on license alone** — GPL deps would poison an Apache-2.0 binary. Also: no typed `Redir`/`Fib` expressions, bindgen/libclang build dependency, and the issue's "wraps libnftnl" premise is outdated (it is pure Rust at runtime but still needs a C toolchain at build time). |
| **nftnl-rs 0.5.1** (Codeberg, 4neko) | MPL-2.0, but README declares the license *unstable* | Rejected: explicitly abandoned (2025-09-28: "no plans to actively maintain"), scope limited to sets, no typed redir/fib. |
| **mullvad `nftnl` 0.9.4** | MIT OR Apache-2.0 | Rejected as primary, **kept as fallback**. Production-proven (813k downloads, used by Mullvad VPN) but links the *system* libnftnl+libmnl via pkg-config (no vendored build) → a static musl binary would need an Alpine/musl-cross C toolchain with `libnftnl.a`, a real burden for "single static binary"; and it still lacks typed `Redir`/`Fib`. |
| **Shell out to `nft`** | n/a | Rejected as primary: runtime dependency on `/usr/sbin/nft` (+ its library set) contradicts the single-static-binary requirement and adds a parser/locale failure surface. **Kept as the CI/local cross-check oracle** (independent implementation validating our bytes). |

## Empirical quirks (evidence base — reuse in #5)

All verified on WSL2 6.18.40.1 during design probes and re-verified by the
spike's own self-tests:

| # | Fact | Handling in the spike |
|---|---|---|
| F1 | TCP redirect works end-to-end; `SO_ORIGINAL_DST` returns the original `203.0.113.7:443`; accepted peer = sandbox IP; reply path needs zero extra rules (conntrack un-NAT) | t1 asserts all of it |
| F2 | nat chain at priority `dstnat` (−100) runs before filter (0); filter-first would drop everything | chain priorities hard-coded −100/0 and dump-verified |
| F3 | Packet dropped by OUTPUT policy ⇒ `send()` fails **synchronously EPERM**; `Ip OutDiscards` +1 | t5's deterministic drop proof (no timeouts) |
| F4 | `IP_RECVORIGDSTADDR` reports the **post-DNAT** `127.0.0.1:53`, not the original | t3 proof = round-trip on connected socket; cmsg logged informational only |
| F5 | Chain counters absent from GETCHAIN dumps on this kernel | counters logged opportunistically, never asserted |
| F6 | Kernel batch is all-or-nothing: ENOENT mid-batch rolls back table+chains from the same batch | `--break-rules` asserts rejection + empty GETTABLE |
| F7 | Fresh netns: lo DOWN, 127.0.0.1/8 auto-added on up; addr-then-route order works | netns.rs sequence + read-back asserts |
| F8 | Direct connect to the listener: `SO_ORIGINAL_DST` succeeds and returns the connection's own local address | t2 asserts equality with own addr |
| F9 | nft 1.0.9 requires explicit chain priorities in `.nft` files | `reference.nft` uses `priority dstnat` / `priority filter` |
| F10 | Local UDP to a closed port ⇒ ECONNREFUSED (allowed by filter) | t4 positive control — validates the EPERM signal is drop-specific |
| F11 | Generated `FibResult` enum is **off by one** vs kernel (spec lacks `NFT_FIB_RESULT_UNSPEC=0`): generated `Addrtype==2`, kernel stores `3` | encoder pushes raw `3u32` (commented); `verify_dump` asserts raw `RESULT==3`; candidate upstream spec issue |
| Q1 | Route `src 10.255.255.1` rejected (EADDRNOTAVAIL) unless the address is local → assign `10.255.255.1/32` to `lo` **before** the route | netns.rs order + read-back |
| — | `NEWTABLE`/`NEWCHAIN` accepted without `NLM_F_CREATE`; `NEWRULE` uses CREATE\|APPEND (crate-example flag discipline) | confirmed empirically on first run |
| — | Unprivileged `nsenter -U -n` into the sandbox fails at nsenter's own `setgroups()` (setgroups=deny is permanent in the userns); `setns(user)+setns(net)` directly works | local-test.sh cross-check uses python `os.setns`; CI uses `sudo nsenter` |

## Guidance for issue #5 (`sbx-init`)

- Port `src/netns.rs` and `src/rules.rs` nearly as-is: setup order (Q1),
  ERESTART retry, `Pusher` hand-encode pattern, `verify_dump`, exit-code
  discipline.
- Bind real proxy listeners **before** loading rules (no
  redirect-live-without-listener window); pass fds via SCM_RIGHTS instead of
  in-process threads.
- IPv6: rules are `ip`-family only; v6 egress fails closed structurally (no
  route in a fresh netns → ENETUNREACH). Consider `inet` family + explicit v6
  blackhole in #5.
- Keep pins `=0.3.5` + lockfile; if the crate is abandoned: vendor it
  (license permits), or fall back to mullvad `nftnl` with a musl C toolchain,
  or raw hand-rolled netlink (the spike already demonstrates every needed
  byte).
- Consider filing the F11 spec bug (missing `UNSPEC` enum entries) upstream
  against one-d-wide/netlink-bindings.

## Reproducing

```sh
bash scripts/local-test.sh          # build + staticness + size + 10× + break-rules + oracle + json
cargo test                          # unit tests (arg parsing, JSON escaping, SNMP parsing)
./target/x86_64-unknown-linux-musl/release/nft-load-spike --verbose --dump-rules
```

CI: `.github/workflows/spike-nft.yml` (path-filtered) runs fmt/clippy, the
musl build, staticness/size asserts, the self-tests as the unprivileged
`runner` user with a `sudo nsenter` + `nft list ruleset` cross-check, the
fail-closed case, and a 5× flake loop; logs are uploaded as artifacts.
