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

**In progress** (issues #2–#7). The CLI parses the full documented
interface, and `check` is real: it validates a policy file against the
versioned policy schema (`--policy`) and prints that JSON Schema
(`--print-schema`); example policies live in [`examples/`](examples/).
The library also carries the egress decision core (issue #4): the
domain allow-list matcher and the resolved-address guard that the proxy
and fake-IP resolver (#7–#9) will call. The internal `__init` helper is
real (issue #5): `sbx run` (#10) will re-exec it with one end of a
control socketpair, and it unshares user + network namespaces, brings
loopback up as `10.255.255.1` with a default route into the sandbox,
disables IPv6, binds the three proxy listeners (transparent `:15001/tcp`,
explicit `:3128/tcp`, DNS `:53/udp`), atomically loads the spike-proven
nftables ruleset with post-load dump verification, hands the listener
fds to the parent over SCM_RIGHTS, waits for the go byte, then `exec`s
the payload command. `__init` setup failures are staged — `sbx __init:
<stage>: <reason>` on stderr, exit `1`, payload never started; success
is silent and the exit code is the payload's. The bwrap argv builder is
real (issue #6): the library turns a policy + session directory into the
full unmodified-bwrap invocation (allow-list mounts, a
cleared-and-whitelisted environment, pid/ipc/uts/user isolation,
`--disable-userns`, synthetic `/etc`), materializes the session's
synthetic files, and discovers/validates the host bwrap (≥ 0.8); `run`
(#10) wires it behind `__init`. The transparent egress proxy is real
(issue #7): the parent serves the handed-off transparent listener fd,
recovers the sandbox's dialed destination via `SO_ORIGINAL_DST`, maps
fake IPs back to names through a DNS-map seam (#9 plugs in), and
inspects — never terminates — the protocol preamble: TLS `ClientHello`
SNI on 443 (rustls parser, no crypto provider, ECH denied) and the HTTP
request line + `Host` on 80. Allowed names are resolved and dialed by
name under the resolved-address guard — every resolved address, plus a
connected-peer re-check as the DNS-rebinding backstop — then the
buffered bytes are replayed and the connection is relayed, with the
validated name binding enforced for the whole connection lifetime: HTTP
heads are replayed with an inserted `Connection: close` (no keep-alive
reuse past the validated request), and on 443 a relay-phase scanner
tears the connection down on any second `ClientHello` (the post-HRR
retry shape) — the library module docs record the accepted residuals;
every connection produces exactly one audit decision with the pinned deny
vocabulary through the sink seam #10 plugs into (whose `teardown` hook
surfaces blocked relay-phase attacks). `run` and `gc` are stubs
that exit `1` with `not implemented yet`. Exit codes: `0`
success, `1` runtime failure (including an invalid or unreadable
policy file), `2` usage error (clap's convention). The architecture
and issue roadmap live in tracking issue #20. `spikes/` holds
standalone experiment packages that are excluded from the Cargo
workspace.

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
sbx check --print-schema
sbx gc --older-than 7d ROOT
```

Durations are human format (`500ms`, `90s`, `2h`, `7d`) and must be
greater than zero — a zero `--older-than` cutoff would match every session,
and a zero `--timeout` is ambiguous. `--timeout` defaults to `120s`.
Everything after `--` in `sbx run` is the command, verbatim, including
hyphenated arguments.

`check --policy` validates a policy file (silently; exit `1` with
`sbx check: <reason>` on failure) and `check --print-schema` prints the
policy JSON Schema (draft 2020-12) to stdout; the two flags are mutually
exclusive. Policy files follow schema version 1 — see
[`examples/`](examples/).

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

Release musl builds are fully static. `file(1)` reports them as
`static-pie linked` on x86_64 (the host toolchain defaults to PIE) or
`statically linked` on aarch64 (the cross toolchain links a non-PIE
executable) — both mean no dynamic loader and no shared-library
dependencies. CI asserts the spelling-agnostic regex plus the absence of
a `PT_INTERP` segment (`readelf`), which is architecture-agnostic; `ldd`
output is informational only, since its wording varies on foreign-arch
binaries. PIE is kept wherever the toolchain provides it — forcing a
single spelling would sacrifice ASLR for the sandbox launcher itself.

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
