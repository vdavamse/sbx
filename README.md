# sbx

Run untrusted commands — AI-agent tool calls, user-submitted scripts, CI
steps — inside a locked-down Linux sandbox, without host privileges.

`sbx` is a single static Rust binary and a CLI: no daemon, no API server.
Each `sbx run` invocation builds a fresh sandbox (mount/PID/network/user
namespaces via unmodified `bwrap`, plus an nftables egress policy inside a
private network namespace), executes the command under a JSON policy with a
timeout and an audit trail, and tears everything down on exit.

## Non-goals

- **Not a container runtime.** No images, registries, OCI specs, or
  long-lived "containers" — one command, one sandbox, one lifetime.
- **Linux only.** The sandbox is built from Linux kernel features
  (namespaces, nftables); there are no macOS or Windows plans.
- **No eBPF cgroup firewall.** Egress filtering uses nftables inside the
  sandbox's network namespace, which works unprivileged (proven by the
  issue #1 spike, `spikes/nft-load`).
- **No TLS interception in v1.** The egress proxy passes TLS through and
  filters on SNI/IP; no MITM CA is installed inside the sandbox.

## Status

**Skeleton** (issue #2). The CLI parses the full documented interface, but
`run`, `check`, `gc` and the internal `__init` helper are stubs that exit
`1` with `not implemented yet`. The architecture and issue roadmap live in
tracking issue #20. `spikes/` holds standalone experiment packages that are
excluded from the Cargo workspace.

## How it will work (summary of #20)

`sbx run` hosts an egress proxy (TLS passthrough, allow-listed
destinations) and a fake-IP DNS resolver, and writes an audit log (JSON
Lines). It re-execs itself as `sbx __init`, which unshares user + network
namespaces, brings up loopback, installs ~6 nftables rules (TCP → proxy
port, UDP/53 → resolver, drop the rest) and hands the listener sockets back
over a unix socket (SCM_RIGHTS). `sbx run` then launches unmodified `bwrap`
with dropped capabilities, user namespaces disabled inside the sandbox,
allow-listed mounts, an empty environment, and the sandboxed command.

## CLI

```
sbx run --policy policy.json --session-dir DIR [--cwd PATH]
        [--timeout 120s] [--audit FILE] -- COMMAND [ARGS...]
sbx check --policy policy.json
sbx gc --older-than 7d ROOT
```

Durations are human format (`500ms`, `90s`, `2h`, `7d`); `--timeout`
defaults to `120s`. Everything after `--` in `sbx run` is the command,
verbatim, including hyphenated arguments.

## Build

Requires Rust ≥ 1.85 via [rustup](https://rustup.rs/):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/sbx
```

For `aarch64-unknown-linux-musl`, add the target and provide a cross
linker (the dependency tree is pure Rust, so a stock cross toolchain is
enough):

```sh
rustup target add aarch64-unknown-linux-musl
sudo apt-get install gcc-aarch64-linux-gnu   # or use cargo-zigbuild
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl
```

## MSRV

Rust **1.85**, edition 2024 — recorded in `Cargo.toml` (`rust-version`)
and enforced by the CI `msrv` job. Bumping the MSRV is a deliberate,
documented change: if a dependency update breaks the `msrv` job, either
pin the older version (`cargo update -p <crate> --precise <ver>`) or raise
`rust-version` with justification.

## Static binaries

Release musl builds are fully static. Note that `file(1)` reports them as
`static-pie linked` (static position-independent executable) rather than
the literal string `statically linked` — both mean no dynamic loader and no
shared-library dependencies (`ldd` confirms `statically linked`). PIE is
kept on purpose: it preserves ASLR for the sandbox launcher itself.

## Development

```sh
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs lint, MSRV, tests, static musl builds
for x86_64 + aarch64 (with staticness asserts and a smoke run of the built
binary), and `cargo deny` (advisories / licenses / bans / sources per
`deny.toml`).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Security

Sandbox escapes and other vulnerabilities: please report them privately —
see [SECURITY.md](SECURITY.md).
