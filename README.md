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

**In progress** (issues #2–#10). The CLI parses the full documented
interface, `check` is real, and `run` is real (issue #10, see
[Running commands](#running-commands)): it validates a policy file against the
versioned policy schema (`--policy`) and prints that JSON Schema
(`--print-schema`); example policies live in [`examples/`](examples/).
The library also carries the egress decision core (issue #4): the
domain allow-list matcher and the resolved-address guard that the proxy
and fake-IP resolver (#7–#9) call. The explicit HTTP proxy (#8)
serves `CONNECT` and absolute-form requests on the explicit listener with
the same policy and inspectors; `sbx run` (#10) serves both listeners.
The fake-IP DNS resolver is real (issue #9): A queries for allow-listed names
get a per-run address from `198.18.0.0/15` that the transparent proxy maps back
to the name; AAAA gets an empty answer, every other name NXDOMAIN, and nothing
is ever forwarded upstream (TCP DNS is not served).
The internal `__init` helper is
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
fake IPs back to names through the fake-IP map (#9), and
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
surfaces blocked relay-phase attacks). `sbx run` is the sandbox
lifecycle (issue #10): timeouts, signals, stdio pumps, the output cap and the
JSONL audit log; its exit codes are in [Running commands](#running-commands).
`gc` is still a stub that exits `1` with `not implemented yet`. For `check`
and `__init`: `0` success, `1` runtime failure (including an invalid or
unreadable policy file), `2` usage error (clap's convention). The architecture
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
        [--timeout DURATION] [--audit FILE] -- COMMAND [ARGS...]
sbx check --policy policy.json
sbx check --print-schema
sbx gc --older-than 7d ROOT
```

Durations are human format (`500ms`, `90s`, `2h`, `7d`) and must be
greater than zero — a zero `--older-than` cutoff would match every session,
and a zero `--timeout` is ambiguous. `--timeout` defaults to the policy's
`limits.timeout`, and the effective timeout is the smaller of the two (the
CLI value can shorten the policy limit, never extend it).
Everything after `--` in `sbx run` is the command, verbatim, including
hyphenated arguments.

`check --policy` validates a policy file (silently; exit `1` with
`sbx check: <reason>` on failure) and `check --print-schema` prints the
policy JSON Schema (draft 2020-12) to stdout; the two flags are mutually
exclusive. Policy files follow schema version 1 — see
[`examples/`](examples/).

## Running commands

`sbx run --policy P --session-dir D [--cwd C] [--timeout T] [--audit F] -- CMD…`
runs `CMD` verbatim (no shell, arguments byte-exact) inside the bwrap sandbox
built from the policy. Inside the sandbox a private network namespace carries
sbx's transparent proxy, explicit proxy and fake-IP DNS resolver.

**Exit codes**

| Situation | rc | audit `outcome` | stderr (sbx's own line) |
|---|---|---|---|
| the command exits N | N | `exited` | none |
| the command is killed by a signal (bwrap reports it as 128+N) | 128+N | `exited` | none |
| `--timeout` / policy `limits.timeout` elapsed | 124 | `timeout` | `sbx run: timed out after 90s` |
| sbx received SIGTERM / SIGINT / SIGHUP / SIGQUIT | 143 / 130 / 129 / 131 | `terminated` | `sbx run: terminated by SIGTERM` |
| an sbx failure (policy, mode, session, audit, bwrap, setup, network, audit write) | 125 | `failed` | `sbx run: <reason>` |
| a usage error | 2 | — | clap's message |

A payload that exits 124, 125 or 128+N is indistinguishable from sbx's own
codes by exit status alone; the audit `outcome` says which it was. A failure
after the payload started (for example `execvp` of a missing binary, rc 1) keeps
the status of the failing stage and is printed by that stage.

**Timeouts.** The clock starts when `run` starts, so sandbox setup counts.
Setup itself is limited to 30 seconds. On timeout or on a signal sbx SIGKILLs
the whole sandbox at once: the command gets no grace period.

**Signals.** sbx watches SIGTERM, SIGINT, SIGHUP and SIGQUIT. A signal the
caller left ignored stays ignored. Any other fatal signal (SIGUSR1, SIGALRM…)
kills sbx with its default action, and the sandbox then dies with it. Job-control
stop (SIGTSTP) is not handled.

A non-interactive shell starts background jobs (`sbx run … &`) with SIGINT and
SIGQUIT ignored (POSIX). Those dispositions are inherited, so such a sandbox
ignores Ctrl-C-style signals as well, like `nohup`. Send SIGTERM, or reset the
disposition in the script before starting `sbx run`.

**Standard streams.** The payload's stdout and stderr are always pipes, so it
never sees a terminal on fds 0–2. stdin is inherited when it is not a terminal.
When it is a terminal that is sbx's foreground group, sbx pumps it. A background
terminal stdin is `/dev/null`, so a background read cannot stop sbx.

**Output cap.** `limits.output_bytes` bounds stdout and stderr combined. The
excess is drained and discarded (the command is not killed). When the cap is hit
sbx prints `sbx run: output truncated at N bytes (limits.output_bytes)` as its
last line, and the exit row records `output_truncated: true`. If the caller closes
sbx's stdout, the command gets EPIPE or SIGPIPE, as with a plain pipe.

**Session directory.** `--session-dir` is created with mode 0700 and must be
owned by the current user. Only one run may use a session at a time: a lock on
`sbx.lock` inside it is held for the whole run, and a second run fails with
`session directory is in use`. The directory's mtime is updated at the start and
the end of every run, which is the activity signal `gc` (#12) reads.

**Audit log.** `--audit F` appends one JSON object per line to `F`. The file is
created with mode 0600, must be a regular file (never a symlink, FIFO or
directory), and must not be inside the session directory. Every row has the
same keys in the same order:

`ts`, `event` (`dns` | `connect` | `deny` | `close` | `exit`), `host`, `sni`,
`port`, `bytes` (`{"up","down"}` on `close`), `reason`, `via`, `verdict`,
`rcode`, `qtype`, `client`. The `exit` row adds `code`, `outcome`, `signal`,
`duration_ms`, `output_truncated` and `dns_poisoned`.

```json
{"ts":"2026-10-15T18:23:01.123Z","event":"dns","host":"github.com","sni":null,"port":null,"bytes":null,"reason":"answered github.com A 198.18.0.1","via":null,"verdict":"answered","rcode":0,"qtype":1,"client":"10.255.255.1:41000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"connect","host":"github.com","sni":"github.com","port":443,"bytes":null,"reason":"allowed github.com via 140.82.121.4:443","via":"transparent","verdict":"allowed","rcode":null,"qtype":null,"client":"10.255.255.1:40000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"exit","host":null,"sni":null,"port":null,"bytes":null,"reason":"command exited with status 0","via":null,"verdict":null,"rcode":null,"qtype":null,"client":null,"code":0,"outcome":"exited","signal":null,"duration_ms":1234,"output_truncated":false,"dns_poisoned":false}
```

Rows are in event order: a connection's `connect`, then `deny` (teardown) if
any, then `close`. The `exit` row is always last. A connection still open when
the run ends gets no `close` row. The log is not fsynced. If a write fails
mid-run the run fails closed (rc 125, `sbx run: audit log write failed: …`).

**Network.** Only ports 443 (TLS, SNI-checked) and 80 (HTTP, `Host`-checked)
are inspected; any other listed port is denied. ECH and GREASE-ECH are denied. In
transparent mode sbx sets no proxy environment variables. In explicit mode the
payload gets the proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
`NO_PROXY` and their lowercase twins) pointing at the explicit listener. The
explicit proxy's response table is in the `proxy::explicit` module docs (200 for
an allowed CONNECT; 400, 403, 502 and 504 otherwise).

**Requirements.** Linux ≥ 5.3 (pidfd), bubblewrap ≥ 0.8 (`SBX_BWRAP` overrides
discovery), and unprivileged user namespaces. The integration suite
(`tests/sandbox_run.rs`) runs every scenario; on hosts without bwrap or userns
it prints SKIP for the sandboxed scenarios.

**Startup overhead (issue #10 AC3).** Measured with
`hyperfine -N --warmup 10 --runs 100` on the release static-musl build (static-pie,
as shipped), from a native Linux filesystem, with a user-space bubblewrap 0.9.0
(`SBX_BWRAP`), the policy `ro ["/usr"]`, transparent mode, empty allow list:

| command | median | p90 |
|---|---|---|
| `/usr/bin/bash -c true` | 1.50 ms | 1.76 ms |
| `sbx run … -- /usr/bin/bash -c true` | 11.15 ms | 12.01 ms |

Overhead ≈ 9.7 ms, under the 25 ms target. Measure from a native filesystem:
on WSL2 the Windows drive (`/mnt/c`, a 9p mount without page caching) adds
about 14 ms to every exec of the binary (the same build measured there:
34–37 ms median). A trivial static-pie binary starts in 0.4 ms, and the sbx
binary starts in 0.6 ms on either PIE or non-PIE builds, so the position-independent
build is not the cost. CI runs on ext4 and reports the number on every run
(report-only, with a warning at ≥ 25 ms).

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
