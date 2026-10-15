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

**In progress** (issues #2–#11). The CLI parses the full documented
interface, `check` is real (issue #11 added the host report, see
[Host check](#host-check)), and `run` is real (issue #10, see
[Running commands](#running-commands)): `check --policy` validates a policy file
against the versioned policy schema and `--print-schema` prints that JSON Schema;
example policies live in [`examples/`](examples/).
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
sbx check [--json]
sbx check --policy policy.json --host [--json]
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

`check` with no policy prints the [host report](#host-check). `check --policy`
validates a policy file (silently, and without probing the host; exit `1` with
`sbx check: <reason>` on failure); add `--host` to also check the policy against
this host. `check --print-schema` prints the policy JSON Schema (draft 2020-12)
to stdout. `--print-schema` cannot be combined with `--policy`, `--host` or
`--json`. Policy files follow schema version 1 — see [`examples/`](examples/).

## Host check

`sbx check` reports what this host can run, and which fix would unlock more.
It runs the same setup stages `sbx run` runs, in a throwaway namespace, plus two
nested bwrap launches, so its answer is the one `run` will get. It takes about
20 ms and changes nothing on the host.

```
$ sbx check
sbx 0.1.0 host check (kernel 6.8.0-1-generic)

  ok    userns      unprivileged user + network namespaces work
  ok    netns       sandbox loopback network configured
  ok    netns-ipv6  IPv6 disabled inside the sandbox network namespace
  ok    nft         nftables NAT redirect loaded and verified
  ok    fallback    default route removable for explicit mode
  ok    bwrap       bubblewrap 0.9.0 at /usr/bin/bwrap
  ok    bwrap-run   bwrap starts a sandbox inside the sbx namespaces
  ok    bwrap-proc  bwrap mounts a fresh /proc
  ok    landlock    Landlock ABI 7 (report-only)

network mode: transparent (policies with network mode transparent, explicit or none can run)
```

The items, in order: `userns` (unprivileged user and network namespaces),
`netns` (the sandbox loopback), `netns-ipv6` (IPv6 can be disabled inside the
sandbox), `nft` (the nftables NAT redirect that transparent mode needs),
`fallback` (the default route can be removed, which the explicit mode needs),
`bwrap` (the bubblewrap binary and its version), `bwrap-run` and `bwrap-proc`
(bwrap can start a sandbox here, and mount a fresh `/proc`), and `landlock`
(report only; sbx does not use Landlock yet). An item is `ok`, `FAIL` (with the
evidence and a `fix:` line), `skip` (not probed because an item it depends on
failed, with the reason), or `warn` (a degraded but working state, with a fix).

**Network modes.** The host provides one of three modes, from strongest to
weakest:

| host provides | runs policies with `network.mode` | means |
|---|---|---|
| `transparent` | `transparent`, `explicit`, `none` | the full firewall loads (nft redirect) |
| `explicit` | `explicit`, `none` | no nft redirect; direct IPv4 connections fail with ENETUNREACH, direct IPv6 with EADDRNOTAVAIL (IPv6 is disabled in the sandbox); the explicit proxy (127.0.0.1:3128) and the local DNS listener answer; the transparent listener (127.0.0.1:15001) accepts but nothing is redirected to it |
| `unavailable` | nothing | the sandbox cannot be set up; fix the `FAIL` items first |

A policy with `network.mode: transparent` cannot run on an `explicit` host:
`sbx run` refuses it with rc 125. A policy with `explicit` or `none` runs on an
`explicit` host. The explicit fallback happens only when the policy allows it,
and it is never silent: `sbx run` prints one notice line with the nft error, and
the audit exit row records the mode the run got (see [Running commands](#running-commands)).

**Policy comparison.** `sbx check --policy P --host` adds four checks to the
host report: `network-mode` (the policy's mode against the host), `infra-etc`
(the `/etc` files every sandbox binds), `policy-paths` (every `filesystem.ro` and
`filesystem.rw` path exists) and `deny-paths` (a deny entry that is a file cannot
be masked, and one that sits under a bound path or an sbx-generated `/etc` file
is flagged).

**JSON.** `sbx check --json` prints the same report as a JSON object with
`"version": 1`: `network_mode`, `runnable_modes`, `probe_error` and one object per
item (`id`, `status`, `detail`, `evidence`, `errno`, `impact`, `fix`). The keys
are stable; new items may be added in later versions.

**Exit codes.** `0`: the report was produced and the host provides at least the
explicit mode (and, with `--policy P --host`, the policy runs here). `1`: the host
is unavailable, the probe failed, the policy is invalid or unreadable, or the policy
cannot run on this host. `2`: a usage error. The full report is always on stdout,
and the reasons on stderr.

**Fix hints.** Each failing item carries one fix. Where the fix depends on the
platform, the Kubernetes and Docker forms are given:

| item | the condition | fix |
|---|---|---|
| `userns` | AppArmor restricts unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns = 1`) | `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or give sbx an AppArmor profile that allows userns; Kubernetes: `appArmorProfile` Unconfined or a Localhost profile that allows userns |
| `userns` | `kernel.unprivileged_userns_clone = 0` | `sudo sysctl -w kernel.unprivileged_userns_clone=1` |
| `userns` | `unshare` is blocked by a seccomp filter (EPERM, typical in containers) | Kubernetes: `hostUsers: false` plus a Localhost seccomp profile allowing `unshare`, `clone`/`clone3` with namespace flags, `mount` and `pivot_root` (or `seccompProfile` Unconfined); Docker: `--security-opt seccomp=unconfined` or an equivalent profile |
| `userns` | `unshare` is not permitted (EPERM) | allow unprivileged user namespaces for this user (AppArmor/SELinux policy, seccomp, `kernel.unprivileged_userns_clone`) |
| `userns` | `user.max_user_namespaces = 0` | `sudo sysctl -w user.max_user_namespaces=15000` |
| `userns` | ENOSPC: the limit is exhausted or nesting is forbidden (for example inside `bwrap --disable-userns`) | run sbx outside sandboxes that forbid nested user namespaces, or raise `user.max_user_namespaces` |
| `userns` | ENOSPC with `user.max_net_namespaces = 0` while user namespaces are allowed | `sudo sysctl -w user.max_net_namespaces=15000` |
| `userns` | EUSERS: nested too deeply | run sbx at a shallower nesting level |
| `userns` | EINVAL: no user or network namespace support | use a kernel built with `CONFIG_USER_NS=y` and `CONFIG_NET_NS=y` |
| `userns` | the id maps cannot be written (`/proc/self/{setgroups,uid_map,gid_map}`) | allow writes to those files in a fresh user namespace (a read-only or masked `/proc` blocks them) |
| `netns` | the loopback cannot be configured, or the proxy and DNS listeners cannot be bound | report a bug with the evidence line and `uname -r` |
| `netns-ipv6` | `/proc/sys` is read-only (EROFS, typical in containers) | Kubernetes: `securityContext.procMount: Unmasked` (requires `hostUsers: false`); Docker: `--security-opt systempaths=unconfined` |
| `netns-ipv6` | writing `/proc/sys/net` is denied | the same as above (`procMount: Unmasked`; `systempaths=unconfined`) |
| `nft` | the nftables NAT redirect is unavailable (transparent mode needs it; explicit and none do not) | `sudo modprobe -a nf_tables nf_nat nft_chain_nat nft_redir nft_fib nft_fib_ipv4`, or use network mode `explicit` |
| `nft` | the kernel's ruleset differs from the expected one | report a bug with the evidence line and `uname -r` |
| `fallback` | the default route cannot be removed (the explicit mode is unavailable) | report a bug with the evidence line and `uname -r` |
| `bwrap` | bwrap is not found | install bubblewrap 0.8 or newer (for example `apt-get install bubblewrap`), or set `SBX_BWRAP` |
| `bwrap` | bwrap is older than 0.8, or unusable | install bubblewrap 0.8 or newer, or set `SBX_BWRAP` to one |
| `bwrap-run` | bwrap cannot apply `--disable-userns` because `/proc/sys` is read-only | `procMount: Unmasked` (Kubernetes) or `systempaths=unconfined` (Docker) |
| `bwrap-run` | bwrap cannot start a sandbox inside the sbx namespaces | allow `mount` and `pivot_root` inside nested user namespaces (Kubernetes: a Localhost seccomp profile that allows them, or `seccompProfile` and `appArmorProfile` Unconfined) |
| `bwrap-proc` | bwrap cannot mount a fresh `/proc` (a masked `/proc`, typical in containers) | `procMount: Unmasked` (Kubernetes) or `systempaths=unconfined` (Docker) |
| `landlock` | Landlock is not supported (report only) | none needed today; kernels 5.13 or newer built with `CONFIG_SECURITY_LANDLOCK=y` provide it |
| `landlock` | Landlock is built in but disabled (report only) | add `landlock` to the `lsm=` kernel boot parameter |

**Masked `/proc`.** On a host that masks `/proc` in a way that passes the
probe but fails later, the sandbox starts and then bwrap exits with its own rc
1; `sbx run` reports that exit as the payload's status, not as a refusal. `sbx
check` reports the failure as `bwrap-proc` with the `procMount` hint. `sbx run` does
no pre-check, so the payload's own rc (bwrap's rc 1) passes through. A per-run
pre-check is tracked as a follow-up.

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
| the sandbox itself is killed by a signal sbx did not send (for example the OOM killer; 137 for SIGKILL) | 128+N | `signaled` | `sbx run: sandbox killed by signal N (NAME)` |
| `--timeout` / policy `limits.timeout` elapsed | 124 | `timeout` | `sbx run: timed out after 90s` |
| sbx received SIGTERM / SIGINT / SIGHUP / SIGQUIT | 143 / 130 / 129 / 131 | `terminated` | `sbx run: terminated by SIGTERM` |
| an sbx failure (policy, mode, session, audit, bwrap, setup, network, audit write) | 125 | `failed` | `sbx run: <reason>` |
| the host cannot provide the policy's network mode, or cannot run sandboxes (issue #11) | 125 | `failed` | `sbx run: policy requires network mode <mode> but this host provides only explicit: <reason>; fix: <fix>; run \`sbx check\` for a full host report` (or `… but this host cannot run sandboxes: …`); the staged line of `__init` comes first |
| the explicit fallback ran (the nft redirect is unavailable, the policy is `explicit` or `none`) | the command's own | the command's | `sbx run: notice: running in network mode explicit because the nftables NAT redirect is unavailable (<reason>); run \`sbx check\` for details` |
| a usage error | 2 | — | clap's message |

The audit row's `outcome` is one of: `exited` (the command ended by itself, or
was killed by a signal bwrap relayed as 128+N), `signaled` (the sandbox, not
the command, was killed by a signal sbx did not send), `timeout`, `terminated`
(sbx received TERM/INT/HUP/QUIT) and `failed` (an sbx failure, including an
audit write failure). A payload that exits 124, 125 or 128+N is
indistinguishable from sbx's own codes by exit status alone; the audit
`outcome` says which it was.

If the sandbox does not report its exit within 5 seconds of the SIGKILL that
sbx sent at teardown, sbx prints `sbx run: sandbox did not exit within 5s of
SIGKILL` and keeps the rc it computed. The diagnostic reports that teardown
took longer than its 5-second budget; it does not change the exit status. A failure
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
directory) owned by the current user with a single hard link, and must not be
inside the session directory or any path the policy mounts (`ro` or `rw`), by
lexical and by real (symlink-resolved) location. Several runs may share one
file: each row is appended under an advisory `flock`, and a run that cannot get
the lock within 250 ms fails closed (125, `audit log write failed: …`). Every row has the
same keys in the same order:

`ts`, `event` (`dns` | `connect` | `deny` | `close` | `exit`), `host`, `sni`,
`port`, `bytes` (`{"up","down"}` on `close`), `reason`, `via`, `verdict`,
`rcode`, `qtype`, `client`. The `exit` row adds `code`, `outcome`, `signal`,
`duration_ms`, `output_truncated`, `dns_poisoned` and `net_mode` (`transparent`
or `explicit`: the network mode the run got, or `null` when `__init` never reported a mode
(setup never completed); `net_mode` is the last key).

```json
{"ts":"2026-10-15T18:23:01.123Z","event":"dns","host":"github.com","sni":null,"port":null,"bytes":null,"reason":"answered github.com A 198.18.0.1","via":null,"verdict":"answered","rcode":0,"qtype":1,"client":"10.255.255.1:41000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"connect","host":"github.com","sni":"github.com","port":443,"bytes":null,"reason":"allowed github.com via 140.82.121.4:443","via":"transparent","verdict":"allowed","rcode":null,"qtype":null,"client":"10.255.255.1:40000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"exit","host":null,"sni":null,"port":null,"bytes":null,"reason":"command exited with status 0","via":null,"verdict":null,"rcode":null,"qtype":null,"client":null,"code":0,"outcome":"exited","signal":null,"duration_ms":1234,"output_truncated":false,"dns_poisoned":false,"net_mode":"transparent"}
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
discovery), and unprivileged user namespaces. Run `sbx check` to see what this
host provides and what to fix ([Host check](#host-check)). The integration suite
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
