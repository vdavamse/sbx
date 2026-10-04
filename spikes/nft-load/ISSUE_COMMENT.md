# Spike result: loading nftables rules from Rust (static musl, unprivileged netns)

**Chosen: [`netlink-bindings`](https://crates.io/crates/netlink-bindings) `=0.3.5` + `netlink-socket2` `=0.3.5`** — pure Rust (MIT OR Apache-2.0), generated from the kernel's netlink YAML specs. The one expression the crate can't generate (`redir` — absent from the bundled kernel spec) is hand-encoded through the crate's public `Pusher` escape hatch; the kernel-stored bytes are identical to the `nft`-loaded reference (verified via raw GETCHAIN/GETRULE dumps, and by `nft list ruleset` reproducing the rule). Full write-up: `spikes/nft-load/FINDINGS.md` in the PR; ground-truth byte dumps in `spikes/nft-load/rules/ground-truth.md`.

## Binary size

| Profile (lto=fat, codegen-units=1, panic=abort, strip) | Bytes |
|---|---|
| `opt-level="s"` | 684,832 |
| `opt-level="z"` (**chosen**) | **680,736** (~665 KiB) |

`static-pie linked, stripped`, no `NEEDED` entries, no `INTERP`, `ldd` → "statically linked". Links with plain `gcc` — no musl-cross toolchain needed.

## Maintenance snapshot (2026-10-04)

- 0.3.5 published **2026-09-11**, ~monthly cadence, ~5.8k / ~3.8k downloads, repo `one-d-wide/netlink-bindings` (young, ~12★, single org).
- Mitigations: exact pins + committed `Cargo.lock` + CI `--locked`; license permits vendoring on abandonment; every load is dump-verified against kernel values and cross-checked with the independent `nft` CLI; documented fallbacks (mullvad `nftnl` static build; raw netlink — the hand-encode pattern already in-repo).

## Rejected alternatives

| Option | Why rejected |
|---|---|
| `rustables` 0.9.0 | **GPL-3.0-or-later** — poisons an Apache-2.0 binary regardless of technical merit. Also no typed `Redir`/`Fib`, bindgen/libclang build dep ("wraps libnftnl" premise in the issue is outdated). |
| `nftnl-rs` 0.5.1 (Codeberg) | Explicitly abandoned ("no plans to actively maintain", 2025-09), sets-only scope, README declares license unstable. |
| mullvad `nftnl` 0.9.4 | MIT/Apache, production-proven (813k dl) — but links **system libnftnl/libmnl via pkg-config** → static musl needs an Alpine/musl-cross C toolchain; no typed `Redir`/`Fib`. Kept as **fallback**. |
| Shell out to `nft` | Runtime dependency contradicts single-static-binary. Kept as **CI cross-check oracle**. |

## Acceptance criteria — all proven in-binary (7/7 self-tests, exit 0)

- **TCP redirect + `SO_ORIGINAL_DST`**: connect `203.0.113.7:443` → accepted on `127.0.0.1:15001`; `SO_ORIGINAL_DST=203.0.113.7:443`; server peer = `10.255.255.1`; client `getpeername` unchanged; reply path works with zero extra rules.
- **UDP-53 redirect**: round-trip on a socket connected to `203.0.113.7:53` (`QUERY\n` → `PONG 127.0.0.1:53`). Note: `IP_RECVORIGDSTADDR` reports the **post-DNAT** address, so the round-trip (+ listener peer check) is the proof; cmsg logged informational.
- **UDP-non-53 drop, deterministic**: `send()` fails **synchronously EPERM** + `/proc/net/snmp` `Ip OutDiscards` +1 — no timeouts involved. Positive control: local UDP → ECONNREFUSED (proves the EPERM is drop-specific).
- **Atomic + fail closed**: ruleset loads in a **single netlink write** (BATCH_BEGIN+genid → NEWTABLE → NEWCHAIN×2 → NEWRULE×3 → BATCH_END) with ERESTART/genid retry; `--break-rules` proves the kernel rejects a broken batch (ENOENT) **and rolls back everything** (`FAIL-CLOSED-VERIFIED`, exit 3; unexpected acceptance → exit 7). Distinct exit codes 0–7 for every failure class; post-load dump verification asserts the stored bytes (exit 4).
- **Unprivileged netns**: `unshare(USER|NET)` + setgroups-deny + uid/gid maps; `lo` up, `10.255.255.1/32`, `default dev lo src 10.255.255.1` via typed rtnetlink ops with dump read-back. (Kernel rejects non-local `RTA_PREFSRC` → the address must be assigned **before** the route.)
- **Stability**: 10/10 consecutive local runs exit 0 (`scripts/local-test.sh`); CI adds fmt/clippy `-D warnings`, `--locked` build, staticness/size asserts, 5× flake loop, and a `sudo nsenter` + `nft list ruleset` cross-check that prints exactly the reference ruleset.

## Quirks worth knowing (all encoded as assertions/comments)

- Generated `FibResult` enum is **off by one** vs the kernel (spec lacks `UNSPEC`): kernel stores `fib daddr type` result as raw **3**; encoder/verifier use the raw value (candidate upstream issue).
- nft compares the fib result as a **4-byte** value (`02 00 00 00`) — replicated byte-exactly.
- nat chain priority must be `dstnat` (−100) < filter (0), or the drop policy runs first.
- Chain counters are absent from dumps on some kernels → logged opportunistically, never asserted.
- Ubuntu 24.04+/GHA: AppArmor `kernel.apparmor_restrict_unprivileged_userns` blocks unshare → EPERM detected with a hint (exit 1); CI flips the sysctl.
- Bare `redirect` on UDP/53 keeps the port (dport already 53) — matches the AC intent.

Spike lives in `spikes/nft-load/` (standalone Cargo project; #2 should exclude `spikes/` from the workspace). Ready for #5 to port `netns.rs`/`rules.rs` nearly as-is.
