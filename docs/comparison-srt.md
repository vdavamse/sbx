# sbx compared with srt

A measured comparison of sbx with Anthropic's
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) on
Linux. Both tools give a command a bubblewrap sandbox and an allow-list of
network destinations. They differ in how traffic reaches the filter, in what
the filter checks, and in what they protect by default. Each row below comes
from one run of [`bench/srt-compare/run.sh`](../bench/srt-compare/README.md),
which anyone can repeat. The full output, with the command, the output and
each tool's log line for every cell, is in
[results/2026-11-08-wsl2](../bench/srt-compare/results/2026-11-08-wsl2/results.md).

This document lives in the sbx repository and was written by its authors.
Read it with that in mind, and re-run the benchmark before relying on a row.

## Versions and host

| | |
|---|---|
| sbx | 0.1.0, static musl release binary (`sbx-0.1.0-x86_64-unknown-linux-musl`, checked against its `.sha256`) |
| srt | `@anthropic-ai/sandbox-runtime` 0.0.81 from npm (integrity `sha512-bjHDu87g…VW/w==`), tag `v0.0.81` = `c40cf14a65d025e3cd27f071f13a73c12b3b1f92`, run through its CLI with node 24.1.0 |
| srt dependencies | socat 1.8.0.0 and ripgrep 14.1.0 (Ubuntu packages, unpacked without root) |
| host | WSL2, Linux 6.18.54.1-microsoft-standard-WSL2 x86_64, Ubuntu 24.04.2 LTS, bubblewrap 0.9.0 (not setuid). `sbx check`: network mode `transparent` |

This is one Linux host. srt also runs on macOS and Windows, and sbx does not
(see [Where srt wins](#where-srt-wins)).

## Policy equivalence

Both policies allow `example.com` on port 443 only, plus three `nip.io` names
that resolve to special addresses (scenario N6). Both make `/usr` read-only
and one directory writable: `rw`, a git checkout and the working directory.
Everything else is denied. The files are in
[`bench/srt-compare/policies/`](../bench/srt-compare/policies/).

The two models differ, so an equal policy needs care:

- **Reads.** sbx mounts only what the policy lists, so reads are denied by
  default. srt reads everything by default, and the policy denies regions.
  The direct srt equivalent, `denyRead: ["/"]`, cannot be used with srt's
  proxy (variant V3: `curl: (56) Proxy CONNECT aborted`). The deny masks
  `/tmp`, where srt keeps the bridge socket the in-sandbox socat connects to
  (`/tmp/claude-http-*.sock`). That is a consequence of the configuration,
  not a defect in srt's proxy.
  The srt policy therefore denies `/home`, `/root`, `/mnt`, `/opt`, `/srv`,
  `/var`, `/etc`, `/run`, `/boot`, `/media`, `/snap`, `/init` and
  `/lost+found`. It re-allows `/etc/ssl` and the `/etc` files sbx binds for
  its own use: `passwd`, `group`, `hosts`, `nsswitch.conf`, `ld.so.cache`,
  `localtime`, `alternatives` and `ca-certificates`. Without `passwd` and
  `hosts`, git over ssh breaks under srt (variant V4: `No user exists for uid
  1000`, and the `socat` in srt's `GIT_SSH_COMMAND` cannot resolve
  `localhost`). sbx generates its own `passwd`, `group`, `hosts` and
  `resolv.conf` instead.
  **What stays readable under srt and not under sbx:** all of the host's
  `/tmp`, including the benchmark's work directory and other users' temporary
  files, and the tools directory (srt's own package and socat have to be
  readable inside). The merged-usr links (`/bin`, `/lib`, `/lib64`, `/sbin`)
  are readable under both, since they lead into `/usr`.
- **Names.** sbx `=example.com` and srt `example.com:443` both mean the exact
  name. A bare sbx `example.com` also covers subdomains, and a bare srt
  `example.com` allows every port (variant V1 below).
- **Private ranges.** sbx denies a dial to a private, loopback, link-local or
  metadata address for every allowed name. srt denies loopback, link-local,
  metadata and the host's own addresses by default. RFC 1918 and CGNAT space
  need `deniedResolvedAddresses`, so the srt policy lists them (variant V2
  shows the default).
- **Environment.** sbx passes no variables unless `env.pass` names them. srt
  passes the caller's whole environment, and its policy has no "pass nothing"
  switch. `credentials.envVars` can withhold or mask variables by name. The
  benchmark leaves it unset, because the threat being tested is "a secret the
  operator forgot to list" (F6).
- **srt runtime.** srt's proxy sockets live in `$TMPDIR`. A long `TMPDIR`
  makes srt fail with `listen EINVAL` (the 108-byte `sun_path` limit), so the
  runner starts srt with `TMPDIR=/tmp`.

## Results

Outcome words: `allowed`/`works` (the permitted action succeeded),
`blocked`/`fails-closed` (the action did not reach its target), `LEAKED`
(it reached a denied target), `planted` (it wrote a file that the host runs
later), and `passed-uninspected` (the bytes reached the allowed upstream, and
the part that differed was encrypted). A row whose target cannot answer (N6)
counts as `blocked` only when the tool logged an explicit deny, and is
`unverified` otherwise. The runner checks first that its own fixtures (the
loopback listener, the abstract socket, the decoy process) answer from the
host.

### Network

| ID | scenario | sbx | srt | evidence |
|---|---|---|---|---|
| N1 | HTTPS to the allowed name | allowed | allowed | both `http=200` |
| N2 | HTTPS to a denied name | blocked | blocked | sbx: `dns denied … www.google.com is not in the policy allow list`. srt: CONNECT answered 403 |
| N3a | proxy variables unset, curl to the allowed name | **works** | fails-closed | sbx: `connect allowed host=example.com sni=example.com … via transparent`. srt: `Could not resolve host` (no network outside the proxy) |
| N3b | proxy variables unset, curl to a denied name | blocked | blocked | |
| N3c | raw socket + TLS to the allowed name | **works** | fails-closed | sbx: TLS handshake and `HTTP/1.1 200 OK`. srt: `gaierror` |
| N3d | raw socket + TLS to a denied name | blocked | blocked | |
| N3e | bash `/dev/tcp` to a denied name, port 80 | blocked | blocked | |
| N4a | direct IP 1.1.1.1:443, raw | blocked | blocked | |
| N4b | `curl https://1.1.1.1/` with proxy variables | blocked | blocked | srt: CONNECT 403 |
| N4c | raw DNS to 8.8.8.8:53/udp for a denied name | blocked | blocked | sbx answers it from its own resolver: `rcode=3`, `dns denied` row. srt: `Network is unreachable` |
| N4d | raw DNS to 8.8.8.8:53/tcp | blocked | blocked | |
| N5a | domain fronting: TCP to the allowed name, SNI and `Host` of another site (`curl --connect-to www.cloudflare.com:443:example.com:443`) | **blocked** | **LEAKED** | sbx: `deny … SNI www.cloudflare.com does not match the DNS-map name example.com`. srt: `Allowed by config rule: example.com:443`, then `connect=200 http=200`. Cloudflare served www.cloudflare.com through the tunnel to example.com |
| N5b | raw TLS to the allowed name with a foreign SNI | blocked | blocked | sbx: the same SNI deny. srt: no network outside the proxy |
| N5c | SNI of the allowed name, foreign `Host` header | passed-uninspected | passed-uninspected | Neither tool sees the encrypted `Host` without TLS termination. Cloudflare answered `403` |
| N6a | allowed name resolving to 127.0.0.1 | blocked | blocked | sbx: `denied dial to 127.0.0.1:443: loopback address`. srt: `blocked: resolved to a loopback address` |
| N6b | allowed name resolving to 169.254.169.254 | blocked | blocked | both deny it as link-local |
| N6c | allowed name resolving to 10.0.0.1 | blocked | blocked | sbx: `private-use address (RFC 1918)` by default. srt: `resolved to a listed address`, because of `deniedResolvedAddresses` (see V2) |
| N7a | host service on 127.0.0.1, raw connect | blocked | blocked | both have a private loopback (`Connection refused`) |
| N7b | host service on 127.0.0.1 through the proxy | blocked | blocked | srt: `No matching rule, denying: 127.0.0.1:<port>` |
| N7c | host service as `localhost` | blocked | blocked | |
| N7d | host abstract unix socket | blocked | blocked | sbx: separate network namespace (`Connection refused`). srt: seccomp refuses `socket(AF_UNIX)` (`Operation not permitted`) |
| N8a | git over HTTPS to the allowed name | allowed | allowed | both reach the server (`repository … not found`) |
| N8b | ssh to the allowed name, port 22 | blocked | blocked | sbx: `port 22 is not in the policy port list`. srt: plain ssh has no route |
| N8c | git over ssh, port 22 | blocked | blocked | srt routes git's ssh through its proxy (`GIT_SSH_COMMAND`) and denies it: `No matching rule, denying: example.com:22` |
| N8d | UDP datagram to the allowed name, port 443 | blocked | blocked | sbx: `sendto` gets `EPERM`. srt: fails at DNS, so this row does not test UDP there |
| N8e | UDP datagram to 1.1.1.1:443 (no DNS) | blocked | blocked | sbx: `EPERM`. srt: `Network is unreachable` |

srt with the benchmark policy changed in one place each:

| ID | case | srt |
|---|---|---|
| V1 | allow entry without `:port` (`example.com`), git over ssh | dialed: `Allowed by config rule: example.com:22` |
| V2 | no `deniedResolvedAddresses`, name resolving to 10.0.0.1 | dialed: `Allowed by config rule: 10.0.0.1.nip.io:443`, then a connect timeout |
| V3 | `denyRead: ["/"]`, HTTPS to the allowed name | broken: `curl: (56) Proxy CONNECT aborted` |
| V4 | `/etc/passwd`, `/etc/group` and `/etc/hosts` not readable, git over ssh | broken: `No user exists for uid 1000` |

### Filesystem and processes

| ID | scenario | sbx | srt | evidence |
|---|---|---|---|---|
| F1 | write in the rw dir | allowed | allowed | |
| F2 | write in host `/tmp` outside the rw dir | blocked | blocked | sbx: the write succeeds inside, on the sandbox's own `/tmp` (kept in the session directory). Nothing appears at the host path |
| F3 | write in the host `$HOME` | blocked | blocked | |
| F4 | write in `/usr` | blocked | blocked | |
| F5 | list `~/.ssh` | blocked | blocked | srt: only because the policy denies `/home`. srt with no settings file reads everything |
| F6 | read secrets from the environment | **blocked** | **LEAKED** | srt printed both canaries (`SBX_BENCH_SECRET`, `AWS_SECRET_ACCESS_KEY`) |
| F7 | see a host process in `/proc` | blocked | blocked | both have a pid namespace (3 pids visible) |
| F8 | read the host `/etc/passwd` | blocked | LEAKED | Caused by the benchmark's srt policy, which has to allow the host file for ssh and socat (V4). sbx generates one |
| F9 | plant `.git/hooks/pre-commit` in the rw checkout | **planted** | **blocked** | sbx: the hook is on the host with `echo pwned` in it. srt: `Read-only file system` (a mandatory deny path) |
| F10 | plant `.bashrc` in the rw dir | **planted** | **blocked** | srt: `Permission denied` |

### Startup, footprint, privileges

| | sbx | srt |
|---|---|---|
| startup, median of 20 runs of `true` (hyperfine) | **20.6 ms** (min 13.7, max 23.9) | 508 ms (min 318, max 704) |
| what is installed | one static binary, 6.4 MB, plus bubblewrap | node 22.12+ (the node binary is 122 MB), the npm package (19 MB of `node_modules`), socat (448 KB), ripgrep (5.1 MB), bubblewrap |
| root, setuid, daemon | none of them. It needs unprivileged user namespaces | none of them. It needs unprivileged user namespaces (Ubuntu 24.04 with AppArmor's userns restriction needs a sysctl or a profile, per srt's README) |

The host was busy with other work during the recorded run: a bare `true`
took a median of 1.0 ms, where it takes about 0.5 ms on this machine idle. All
the times above are inflated by that contention, and the ratio between the
two tools is what to read from them. For an idle host, [Usage](usage.md)
reports `sbx run … -- bash -c true` at 11.15 ms median (`hyperfine --runs
100`, from a native filesystem).

The same run measured where srt's time goes: starting node takes 55 ms, and
loading the CLI (`srt --version`) takes 185 ms. A run with an empty policy
takes 538 ms, which adds starting the proxies and the socat bridges and
srt's scan for its mandatory deny paths. Both tools ran from a native
filesystem, with the rw directory as the working directory. srt's
library (`SandboxManager`) starts the proxies once and wraps many commands,
so an embedder pays the proxy start once. The CLI pays it on every call.

### Audit and observability

- **sbx** writes one JSON row per event with `--audit F`: every DNS answer and
  denial, connect, deny with its reason, close with byte counts, and an
  `exit` row with the outcome
  ([Usage](usage.md#running-commands)). Every blocked attempt in the table
  above that reached sbx's resolver or proxy has a row. Example:
  `{"event":"deny","host":"example.com","port":443,"reason":"SNI www.cloudflare.com does not match the DNS-map name example.com",…}`.
  An attempt that never leaves the namespace, such as a connect to the
  sandbox's own loopback or a UDP `sendto` refused with `EPERM`, has none.
- **srt's CLI** records nothing by default. `--debug` prints the proxy's
  decisions to stderr as text (`No matching rule, denying: example.com:22`,
  `Connection to 10.0.0.1.nip.io blocked: resolved to a listed address`),
  mixed with mount and setup lines. The library keeps a violation store, and
  `annotateStderrWithSandboxFailures` adds a `<sandbox_violations>` block to
  a command's stderr. `deniedDomainReasons` lets an operator tell the model
  why a host is blocked. On Linux, filesystem denials are not reported. srt's
  README suggests `strace`.

### Harness ergonomics

| ID | case | sbx | srt |
|---|---|---|---|
| E1 | command exits 7 | 7 | 7 |
| E2 | command killed by SIGKILL | 137 | 137 |
| E3 | timeout | `--timeout 2s`: 124, `sbx run: timed out after 2s`, no process left | no timeout option. Coreutils `timeout 2`: 124, no process left |
| E4 | SIGTERM to the tool | 143, `sbx run: terminated by SIGTERM` | **0**. srt exits 0 when its child dies of SIGINT or SIGTERM (`src/cli.ts`), so a cancelled command reads as a success |
| E5 | malformed policy | 125, the parse error | 1, `Refusing to run with the built-in defaults…` |
| E6 | sandbox cannot start (no bwrap) | 125 | 1 |
| E7 | command not found | **1** (`bwrap: execvp …`), the same as a command that exits 1 | **127**, from the `bash -c` that srt always runs |
| E8 | 5 MB of output | capped at `limits.output_bytes` (1 MiB here): `sbx run: output truncated at 1048576 bytes (limits.output_bytes)`, and `output_truncated: true` in the audit | not capped (5000000 bytes) |
| E9 | persistent session | `run --keep-alive` and `attach` (an attach of `true` in tens of ms). An attached `curl` reached the resident's HTTP server on 127.0.0.1 (`http=200`): the calls share localhost | none in the CLI. The library keeps proxies across calls, but each command is a new sandbox |

srt reports each of its own failures before or around a run as 1, so a
harness cannot tell a sandbox failure from a command that exits 1. sbx uses 125 for its own failures. srt
always runs the command through `bash -c` (argv is shell-quoted and re-parsed).
`sbx run` executes argv directly.

## Where sbx wins

- **Proxy-unaware clients work, and still fail closed.** The transparent
  redirect and fake-IP DNS route every TCP connect to the proxy, so a client
  that ignores `HTTPS_PROXY` reaches the allowed name (N3a, N3c), and denied
  names, IPs and DNS servers stay blocked (N3b to N4d). Under srt such a
  client has no network at all. That is safe, but tools without proxy support
  break. srt's README lists this as a known limitation.
- **SNI is checked against the name.** A TLS ClientHello whose SNI is not the
  name the connection was opened for is denied. A fronted request through the
  allowed name's CDN to another site went through srt and was refused by sbx
  (N5a). srt checks only the CONNECT target, unless `tlsTerminate` with
  `requireHostMatch` is enabled.
- **Safer defaults.** Reads are denied unless mounted, the environment is
  empty unless passed (F6), private ranges are denied for every name (V2),
  ports are a separate list (V1), and the sandbox gets a generated
  `/etc/passwd` and `/etc/hosts`. srt has to be given the host's files for
  ssh to work (F8, V4). Each srt network gap above has a setting that closes
  it. srt cannot pass an empty environment, and denying `/tmp` hides its
  bridge socket (V3). An operator has to know each setting.
- **Startup and footprint.** 20.6 ms against 508 ms per command, and one
  static binary against a node runtime plus three tools.
- **Harness contract.** A timeout, an output cap, distinct exit codes for
  sandbox failures (125) and signals (143), a JSON audit row for each network
  decision, and persistent sessions.

## Where srt wins

- **Platforms.** srt runs on macOS (`sandbox-exec`), on Linux, and on Windows
  (alpha, through a dedicated user account and WFP filters). sbx is Linux-only.
- **Maturity.** srt is the sandbox behind Claude Code's sandboxing. npm
  listed 77 published versions on 2026-11-08 (recorded by `setup.sh`). Per
  its README, its CI runs the whole suite against the bubblewrap Ubuntu ships
  and against 0.12.0, and the mount-plan suites against 0.4.1 as well. sbx
  0.1.0 is its first release.
- **Auto-run files in writable paths.** srt makes `.git/hooks`,
  `.git/config`, shell rc files, `.gitconfig`, `.mcp.json`, `.vscode/` and
  similar paths read-only inside every writable directory by default (F9,
  F10). sbx lets a payload plant a git hook that runs on the host at the next
  commit. This is threat-model R7, which sbx only documents.
- **Unix sockets.** srt's seccomp filter refuses `socket(AF_UNIX)` outright
  (N7d), so a socket file that a broad bind exposes cannot be used. sbx
  allows `AF_UNIX` and relies on the mounts: a bind of `/run` or a home
  directory hands the payload every socket under it, which `sbx check` warns
  about ([Usage](usage.md#running-commands), "Unix sockets under binds").
- **Request-level features.** srt can terminate TLS for allowed hosts and pass
  each request to a `filterRequest` callback. It can mask a credential in the
  sandbox and inject it on the way out, refuse `Host`/SNI mismatches
  (`requireHostMatch`), give the model a reason for each denied domain, update
  its config while a command runs (`--control-fd`), and embed as a library.
  sbx's TLS termination is a build-time option with URL-path rules
  ([TLS termination](tls-termination.md)). It has no credential injection and
  no live policy update.
- **Missing commands exit 127** (E7), as a shell does. Under `sbx run` the
  exit is bwrap's 1.

## Where neither helps

- **Fronting with the allowed SNI** (N5c). When the SNI is the allowed name
  and the encrypted `Host` names another site on the same edge, both tools
  pass the bytes. Here Cloudflare refused the mismatch. Other CDNs may not.
  Only TLS termination closes this. In sbx it is
  [R1](threat-model.md#7-residual-risks), and srt's README warns about
  fronting.
- **Writes to the working tree.** Both tools let the payload change
  `Makefile`, `package.json` scripts, `.envrc` and CI files in a writable
  checkout. Treat everything a sandboxed command writes as untrusted.

## Limits of this comparison

- One host (WSL2) and one recorded run. Earlier runs of the same probes during
  development gave the same verdicts, but only this run is committed.
  Kernel, bubblewrap and distribution differences can change results,
  especially for srt's Ubuntu AppArmor note and for sbx's nftables
  requirement.
- srt was run through its CLI. An embedder using the library gets the
  violation store, `updateConfig` and long-lived proxies, which change the
  latency and observability rows.
- sbx ran in transparent mode. On a host without the nftables NAT redirect,
  sbx falls back to explicit mode. That mode uses proxy variables, like srt,
  and N3a/N3c then fail closed under both tools.
- The fronting rows depend on example.com being served by Cloudflare at run
  time.
- Optional hardening was off on both sides: sbx `--landlock`, cgroup limits and
  TLS termination, and srt `tlsTerminate`, `requireHostMatch`, `credentials`
  and `allowNestedUserNamespaces`.
