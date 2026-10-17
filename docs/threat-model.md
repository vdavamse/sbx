# sbx threat model and security guarantees

This document states what `sbx` protects against, what it does not, and what is left over (the
residual risks). Each guarantee (S1 to S16) names the conformance checks that test it
(`sbx check --conformance`, see the README `## Conformance` section) and the code that implements
it. Checks that are not in the catalog are named separately.

Scope: `sbx` at `main` @ `53ee605` (2026-10-17). Code references are `path:identifier` (a function,
constant, type or test name). Line numbers are left out on purpose; re-verify the references when
the code changes. `tests/threat_model_doc.rs` checks that every check id cited here exists in the
catalog, that every catalog check is cited in section 6, that the check counts stated here and in
the README match the catalog, and that every `path:identifier` reference resolves.

This is a statement of bounds, not a claim of safety. Sandboxing reduces risk. It is not a virtual
machine, and it does not protect against a broken kernel or a broken bwrap.

## 1. Summary

- **What sbx runs.** One untrusted command per call, inside its own network, mount and PID
  namespaces. The payload gets no capabilities. Its environment is the policy's `env` settings
  plus infra variables; the caller's environment is not passed through.
- **What it enforces.** Egress from the payload is limited to the names the policy allows, on the
  ports sbx inspects (443 and 80 in transparent mode; the explicit proxy in explicit mode). Names
  match exactly or on a dot boundary. Resolved addresses are checked against the IANA
  special-purpose tables. The filesystem is an allow list. Host loopback, other sessions and the
  caller's environment are hidden. Processes are killed when the run ends. Connections handled by
  the proxies are audited (S16 states the limits).
- **Top residual risks** (section 7):
  1. **R1, domain fronting (High).** An allowed name on a shared CDN edge can open other sites on
     the same edge, because the encrypted `Host` or `:authority` is not inspected. v1 does not close
     this.
  2. **R2, allowed destinations are exfiltration channels (High by design).** Allowing `github.com`
     allows uploading to any GitHub repository. sbx enforces names, not intent.
  3. **R26, bwrap CVE-2026-87766 (Low after sbx's pre-launch guard, #39).** A setup-time symlink
     traversal in bwrap before 0.12.0. sbx verifies every path bwrap resolves under a `rw` bind
     before it spawns, and refuses a planted symlink with rc 125. sbx's minimum bwrap version is
     still 0.8, so an older bwrap starts, and `sbx check` warns below 0.12.0.
  4. **R15, kernel and bwrap bugs (High impact, low likelihood).** sbx shares the host kernel.
- The table in section 7 gives all residuals with their severity and tracking issue.

## 2. System and assets

Each `sbx run` call does this:

1. `sbx __init` runs in a fresh user and network namespace. It brings up `lo`, loads the nftables
   rules in transparent mode (`src/init/rules.rs:build_batch`), verifies them with a kernel dump
   (`src/init/rules.rs:verify_dump`), and only then lets the payload start.
2. The transparent proxy (`src/proxy/mod.rs:decide`), the explicit proxy
   (`src/proxy/explicit.rs:decide_explicit`) and the fake-IP resolver
   (`src/dns/mod.rs:handle_datagram`, `serve_dns`) run on a thread (`sbx-net`) of the `sbx run`
   process. They accept on sockets whose listening ends sit in the sandbox netns (`src/init/fdpass.rs`).
3. bwrap (`src/bwrap/mod.rs:build`) starts the payload with the filesystem allow list, a cleared
   environment (`src/bwrap/mod.rs:Launch::command`) and the seccomp filter
   (`src/bwrap/seccomp.rs:program_memfd`).
4. The `sbx run` process supervises the chain, writes the audit log and tears everything down
   (`src/run/lifecycle.rs:teardown`).

**Assets** the policy protects: the host filesystem and the secrets in it; the host network,
including loopback services and the LAN; other sessions of the same caller; the caller's
environment and open file descriptors; networks beyond the allow list; and the audit trail, which records the
connections and DNS queries the proxies handled. It does not record attempts stopped before
the proxies (R29).

## 3. Adversary

- **The payload (in scope).** Arbitrary code run by the caller. It can make any syscall the seccomp
  filter allows, send any bytes to any address it can reach, and write anything into `rw` binds and
  the session directory.
- **A hostile upstream or DNS answer for an allowed name (in scope).** The resolved-address guard
  (S7) and the peer address re-check limit what an allowed name can make sbx dial.
- **A co-tenant sandbox of the same user (in scope).** Other sessions' sockets, files and fake IPs
  must be unreachable (S11).

**Out of model:** the host root; the caller that starts `sbx` (it chooses the policy and the
paths); the policy author; other processes of the same uid on the host (R24).

## 4. Trust boundaries and assumptions

- **Host kernel: trusted and shared.** Linux 5.3 or later (the `pidfd` and `PR_SET_PDEATHSIG`
  behaviour that sbx relies on). Namespaces, seccomp, netfilter and procfs behave as documented,
  and unprivileged user namespaces are enabled. sbx adds no isolation beyond these (R15, R16).
- **Host bwrap: trusted, unmodified, version 0.8 or later.** It is found through `SBX_BWRAP`, then
  absolute `PATH` entries, then `/usr/local/bin`, `/usr/bin` and `/bin` (`src/bwrap/version.rs`;
  minimum `BWRAP_MIN`). Whoever controls `PATH` or `SBX_BWRAP` controls enforcement. The 0.8 minimum
  admits versions with CVE-2026-87766, which the pre-launch guard covers (R26). sbx does not check for a setuid bwrap, and that
  configuration is not tested. This document makes no claim about it.
- **The caller: trusted.** It picks the policy, the session directory and the audit path, runs as
  the same uid, and receives stdout and stderr. sbx is not a privilege boundary between the caller
  and sbx. Session directories must sit under a root- or euid-owned base with unguessable names
  (`src/bwrap/etc.rs` module docs; R23).
- **The policy author: trusted, and responsible for what the policy allows.** sbx enforces the
  minimum the policy states. Broad binds (R6, R7), broad names (R1 to R3), and secrets passed with
  `env.pass` defeat the intent without breaking the contract. `sbx check --policy P --host` checks
  feasibility, not wisdom.
- **The payload: untrusted.** Arbitrary 64-bit code, any syscall the filter allows, uid 0 inside a
  user namespace that maps to the caller's uid, no capabilities.
- **The sbx proxies and resolver: part of the trusted chain, but they parse payload bytes.** They run
  on the `sbx-net` thread of the `sbx run` process: as the caller's uid, in the host network
  namespace, outside bwrap and outside the seccomp filter. A parser bug there is not contained by
  the sandbox (R28).
- **Upstreams and DNS: untrusted.** The content of an allowed server is not policed.
- **Audit consumers.** The JSONL log contains payload-influenced strings (R19). It is not fsynced
  (R18). It is written under the caller's uid, so the integrity limit is that uid, not host root:
  payload-planted code that runs later outside the sandbox (R7) can rewrite it. Consumers must parse
  it as untrusted data.
- **Output consumers.** stdout, stderr, and files in `rw` binds and the session directory are
  untrusted (R7, R21).
- **Platform.** A usr-merged host (the `/bin` and `/lib` shims); x86_64 or aarch64; a native
  filesystem for the session root (R23).

## 5. Network modes

The policy requests a network mode. `sbx check` reports the modes the host supports. Each run's
audit rows carry a `net_mode` field, which records the mode in effect for that run. Use the audit
row to see which mode a given run used.

- **transparent.** The payload is in a netns with only `lo`. nftables redirects TCP to the
  transparent proxy and UDP/53 to the fake resolver, and drops everything else
  (`src/init/rules.rs:build_batch`). The proxy checks names against the policy. The full guarantee
  set (S1 to S13) applies.
- **explicit.** No nftables redirect is loaded and there is no route. The payload gets proxy
  environment variables. Egress confinement still holds ("no route", `C04`), but the transparent-only
  checks do not run here, and tools that ignore proxy variables fail (R11). The kernel verification
  in S4 applies to transparent mode only.
- **none.** No network. Name lookups answer NXDOMAIN (`C04`).

Explicit mode is not equal in strength to transparent mode. Its residuals differ (R8, R10, R11).

## 6. Guarantees

Each of the 71 catalog checks is cited at least once in this table. "Proven by" lists the checks
that test the guarantee. "Limits" states what the guarantee does not mean.

| # | Guarantee | Mechanism (`path:identifier`) | Proven by | Limits (what it does not mean) |
|---|---|---|---|---|
| S1 | The only egress is sbx's proxies and resolver. The netns has only `lo`. TCP is redirected to the transparent proxy, UDP/53 to the fake resolver, and everything else is dropped. IPv6 is disabled. | `src/init/netns.rs:add_default_route`, `disable_ipv6`; `src/init/rules.rs:build_batch`, `verify_dump`; `src/bwrap/mod.rs` module docs point 6 (never `--unshare-net`) | `C01` `C02` `C03` `C05` `C06` `C07` `C08` `C09` | Allowed destinations are reachable by design (R2, R3). In explicit and none modes there is no nftables redirect; there the guarantee is "no route" (`C04`). The fake resolver never forwards upstream (`C07`). |
| S2 | Only four socket families can be created: AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK. AF_VSOCK, AF_PACKET and AF_XDP cannot. io_uring returns ENOSYS. The x32 ABI and 32-bit syscalls are killed. Raw and ICMP sockets are blocked by other layers (see Limits). | Family filter: `src/bwrap/seccomp.rs:program_memfd`, `native_program_bytes`, `ALLOWED_FAMILIES`. Raw and ICMP: no `CAP_NET_RAW` in the payload's user namespace (`src/bwrap/mod.rs:build`, `--cap-drop ALL`), and the sandbox netns's `net.ipv4.ping_group_range` (`1 0`, see Limits) | `C10` `C11` `C12` `C14`; integration `seccomp-allowed-families`, `seccomp-vsock-eafnosupport`, `seccomp-io-uring-enosys` (`tests/sandbox_run.rs`) | The seccomp filter is a family allow list, not a syscall allow list (R16). Seccomp does not filter socket types inside the allowed families. Raw and ICMP sockets rely on the capability drop and on the `ping_group_range` of `1 0` in the sandbox netns, not on seccomp. The sandbox netns starts with that value and `/proc/sys` is read-only inside the sandbox, so the host's sysctl value does not apply (not re-tested here). `C12` tests the ping-socket case. Pathname unix sockets under policy binds are reachable (R6). Netlink allows every protocol (R17). |
| S3 | The payload cannot change its network. It has no capabilities and cannot create nested user namespaces. Link, address and route changes fail. | bwrap `--unshare-user --disable-userns --cap-drop ALL` (`src/bwrap/mod.rs` module docs point 7) | `C13` `D10` | A kernel bug that grants capabilities is out of model (R15). |
| S4 | Fail-closed for transparent mode. The payload does not start until the nftables rules are verified in the kernel. A failed nftables load or audit write ends the run with exit code 125. The payload dies with its parent (`PR_SET_PDEATHSIG`). | `src/init/mod.rs` module docs point 1 (listeners bind, rules load, verify, go byte); `src/init/fdpass.rs`; `src/init/mod.rs` `PR_SET_PDEATHSIG` handling; `src/run/serve.rs:FaultLatch` | `F01` `F02` `F03` `F04` `F05` `F06` | No catalog check exercises the fault latch that makes "proxy death ends the sandbox" happen. `F03` shows that egress is refused once the proxy is gone; it does not show the sandbox ending. `F02` and `F04` show no new upstream connection after SIGKILL or SIGSTOP. The kernel verification does not apply in explicit mode, where no nftables rules are loaded (S1, section 5). Fail-closed is about egress, not availability (R20). |
| S5 | Names match exactly or on a dot boundary. `notpypi.org`, `pypi.org.evil.com`, IDN lookalikes and non-allowed ports are denied. Case, a trailing dot and subdomains are normalised. | `src/egress.rs:allowed` (IDNA normalisation through `Domain::parse`); test `src/egress.rs:bare_suffix_check_is_the_bug_class` | `A06` `A07` `A08` `A09` `A11`; positive controls `A01` `A02` `A03` `A04` `A05` | Allowing `example.com` allows every subdomain. There is no exact-only rule in v1 (R3, #44). Allowing a shared CDN or host allows everything it serves (R1). |
| S6 | IP literals are denied on the CONNECT, absolute-form and transparent paths, including `inet_aton` spellings such as `0x7f.1`. | `src/proxy/explicit.rs:decide_explicit` (target grammar); `src/proxy/mod.rs:canonicalize_host`; `src/dns/map.rs:FakeIpMap` (the transparent path only knows fake IPs). The `inet_aton` spellings are pinned by the unit tests `src/egress.rs:ip_literals_and_inet_aton_forms_denied` and `src/proxy/explicit.rs:parse_authority_table` (the `0x7f.1:443` case). | `A10` (canonical dotted-quad literals only: the `a10.*` operations in `src/conformance/host_tier.rs`) | The `inet_aton` forms are proven by unit tests, not by a conformance check. The catalog check covers canonical dotted-quad literals only. |
| S7 | Resolved-address guard. An allowed name that resolves to loopback, private, link-local or any other IANA special-purpose address is denied. The dial is by name, and the peer address is re-checked. | `src/egress.rs:guard` (tables from the IANA IPv4 and IPv6 special-purpose registries, "Last Updated 2025-10-09"); `src/proxy/mod.rs:connect_upstream` | `A12` (loopback, private and metadata addresses only) | Public addresses outside those tables are dialable, including platform endpoints such as Azure's 168.63.129.16 and the host's own public addresses (R12, #41). The full IANA table is covered by the unit tests `src/egress.rs:iana_registry_entries_all_denied` and `src/egress.rs:tables_and_oracles_reconcile`, not by `A12`. The tables need periodic re-audit (section 11). |
| S8 | TLS SNI binds the connection to the authorised name. The SNI must equal the dialed or CONNECT name. A missing SNI, non-TLS bytes on 443 and ECH are denied. A second ClientHello tears the connection down. | `src/proxy/hello.rs:inspect_tls`; `src/proxy/relay.rs:RelayScanner` | `B01` `B02` `B03` `B07` `B08` `B09`; real-network `E06` | Only the SNI is checked. The encrypted `Host` or `:authority` is invisible to a passthrough proxy: domain fronting (R1). An encrypted TLS 1.2 renegotiation is invisible (R9). |
| S9 | The HTTP `Host` binds a port-80 request. There is exactly one Host, it must equal the name, and keep-alive follow-ups are cut by an inserted `Connection: close`. The explicit absolute-form requires `http://` and a matching Host. | `src/proxy/http.rs:inspect_http`; `src/proxy/explicit.rs:decide_explicit` | `B04` `B05` `B06` `B10` | Plain HTTP can be read and altered on the path. A server that ignores `close` can still process a second request (R8). Pipelined requests on the explicit path are not covered by `B06` (R8). |
| S10 | DNS does not leave the sandbox. The fake-IP resolver answers allowed names from `198.18.0.0/15` and returns NXDOMAIN for the rest. It has no forwarding, no TCP DNS and no DoT. Each run has its own map. | `src/dns/mod.rs:handle_datagram`, `serve_dns`; `src/dns/map.rs:FakeIpMap` (pool `198.18.0.1` to `198.19.255.254`, 131,070 addresses, not expired or reused within a run) | `A01` `A07` `C06` `C07` `C08` `D09` | A name like `<data>.<allowed suffix>` makes the host resolver look it up, so the label reaches the host resolver and the zone's authoritative server (R4). A host `/etc/hosts` entry or a bound nscd or resolved socket changes the path (R5, R6). |
| S11 | Host loopback and other sessions are unreachable. Host `127.0.0.1`, host abstract sockets, other sessions' listeners, abstract sockets, files and fake IPs are all unreachable. | per-run netns (`src/init/netns.rs`); allow-list mounts (`src/bwrap/mod.rs:build`); per-run `FakeIpMap` | `D01` `D02` `D03` `D06` `D07` `D08` `D09` | A same-uid host process can still reach the sandbox from outside (ptrace, `/proc`). That direction is out of model (R24). |
| S12 | The filesystem is the allow list. The sandbox sees the policy `ro` and `rw` binds, 7 infra `/etc` paths (`src/bwrap/argv.rs:INFRA_ETC`), synthetic `/etc` files, and the session's `work`, `home` and `tmp`. It does not see the host root. | `src/bwrap/mod.rs:build`; `src/bwrap/argv.rs:INFRA_ETC`; `src/bwrap/etc.rs`; deny masks in `src/bwrap/mod.rs:build` | `D04` (pathname unix sockets outside the binds) `D08` (another session's files) `H06` (HOME and processes) `D11` (a deny mask survives an ancestor rename) `D12` (a planted symlink under an rw bind is refused before launch); `D05` (warn: a unix socket file under a bind is visible); integration `allowlist-only-visible`, `write-refused`, `writes-outside-session-fail`, `deny-masks-path` (`tests/sandbox_bwrap.rs`) | `rw` binds are host writes that persist and may run later outside the sandbox (R7). The infra paths are disclosed (R13). Deny masks are computed per run and are lexical; the pins against in-sandbox renames of their parents hold (`D11`, R27, #40). With bwrap before 0.12.0, a setup-time symlink traversal under `rw` binds is refused before launch (`D12`, R26, #39); a concurrent host writer can still race that check. No catalog check covers an arbitrary non-allowed host path, or a write to an `ro` bind (#45). |
| S13 | No caller secrets are inherited into the payload environment. The payload environment is the policy's `env` settings plus infra. The caller's environment, `/proc/*/environ`, non-CLOEXEC file descriptors, `HOME` and the caller's processes are not visible. | `src/bwrap/mod.rs:Launch::command` (`env_clear`, `--clearenv`); `src/init/mod.rs:fd_hygiene`; `--unshare-pid` | `H01` `H02` `H03` `H04` `H05` `H06` | Values that the policy passes with `env.pass` are visible to the payload. Secrets in bound paths are readable. `/proc/1/cmdline` shows the bwrap argv, including host paths (R13). |
| S14 | Processes left behind are killed. On natural exit, timeout, signals and SIGKILL of `sbx`, the sandbox's processes do not survive. | `src/run/lifecycle.rs:teardown`; `src/run/sys.rs:pidfd_kill`; `--die-with-parent`; `PR_SET_PDEATHSIG` | `G01` `G02` `G03` `G04` `G05` `F01` | Session reuse is checked (`G05`) only after a natural exit. Reuse after a timeout or a signal is not checked. |
| S15 | Real tools work through the policy. This is a functional guarantee, tested in the network tier. | the whole chain | `E01` `E02` `E03` `E04` `E05` | Opt-in with `--network`. Run in nightly CI only. |
| S16 | Connections handled by the proxies are audited. Each connection gets a decision row. A failed audit write ends the run with exit code 125. | `src/proxy/mod.rs` module docs points 1 and 5; `src/run/audit.rs`; `src/proxy/mod.rs:redact_for_audit` | `F06` (audit write failure ends the run) | Attempts stopped by nftables drops, seccomp or missing capabilities produce no row (R29). No catalog check proves that each connection gets exactly one row. The log is not fsynced. Connections still open at exit get no `close` row. A flood can grow the log (R18). Redaction is partial on the transparent path (R19). |

## 7. Residual risks

Severity is measured against the contract (egress, confinement, secrets).
**High**: defeats egress filtering or confinement for a realistic configuration. **Medium**:
exfiltration or escape that needs a specific policy or a server quirk. **Low**: narrow, or disclosure
only. **Info**: an availability or operational cost. "Tracking" names the issue that handles the
residual, or "doc only" when no change is planned.

| # | Residual | Sev | Mitigation (now, later) | Tracking |
|---|---|---|---|---|
| R1 | **Domain fronting and vhost confusion on 443.** The SNI names an allowed host on a shared CDN, and the encrypted `Host` or h2 `:authority` names another site on the same CDN. The issue that started this work reports this against Fastly without TLS termination; it was not reproduced in this repository. Any allowed name on a shared edge may open the sites that edge serves. Check where your allowed names are hosted. | High | Allow only what you need, and prefer names you control. Later: opt-in TLS termination for selected hosts (#17). #17 does not yet name a `Host` or `:authority` check. A passthrough proxy cannot close this (`src/proxy/http.rs` module docs point 6; `src/proxy/mod.rs` module docs point 12). | #17 |
| R2 | **Allowed destinations are exfiltration channels.** For example `git push` to any GitHub repository, a gist, a package upload or an issue comment. sbx enforces names, not intent. | High (by design) | Minimal allow lists. No credentials in the sandbox (S13). Read-only tokens where possible. Later: URL-path rules (#17). The audit row shows bytes up and down per connection. | #17 |
| R3 | **The subdomain wildcard is implicit.** Allowing `github.com` also allows every subdomain, including user-content subdomains on platforms you may not control. | Medium | Allow the narrowest names. Later: an exact-only rule syntax. | #44 |
| R4 | **DNS-label exfiltration through host resolution.** A name like `<data>.<allowed suffix>` is resolved on the host, so the label reaches the host resolver path and the zone's authoritative server. The SNI also carries it to the allowed server. | Medium | Inherent to suffix rules and host resolution. Narrow allow lists reduce the zones in play. | doc only |
| R5 | **Host `/etc/hosts` is bound into the sandbox.** An allowed name pinned there resolves to its real IP, and the proxy denies it (`UnknownFakeIp`, fail-closed). This breaks Kubernetes `hostAliases` and discloses host entries. | Low | Fail-closed today. Later: a synthetic hosts file. | #35 |
| R6 | **Host unix sockets under policy binds are reachable.** A read-only bind does not block `connect()`. Binding `/run`, `/var/run` or `/tmp` exposes `docker.sock` (host root), D-Bus, the ssh-agent and nscd or systemd-resolved (a resolver that bypasses the fake resolver, so R4 becomes arbitrary-name tunnelling). | High if such a bind is present; otherwise none | Keep `/run`, `/var/run`, `/tmp` and socket directories out of policies. `D05` warns. Later: a `sbx check --policy --host` warning; Landlock `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (ABI 9), which #19 does not yet specify. | #35; nothing filed for RESOLVE_UNIX |
| R7 | **`rw` binds are host writes.** The payload can plant `.git/hooks`, `.envrc`, `Makefile`, CI configuration or shell rc files that run later outside the sandbox. The session `work`, `home` and `tmp` persist across calls in the same session, so one call can poison the next. | High for agents with a read-write checkout | Treat everything written as untrusted output. Review the diff before running host tooling on it. Keep `rw` to the working tree. Use a fresh session per trust domain. | doc only |
| R8 | **HTTP/1 follow-up requests.** Plain HTTP on 80 relies on the server honouring `Connection: close`. A non-conforming server could process a second request with a foreign Host, or an Upgrade tunnel. On the explicit path, pipelined second requests are not inspected (`src/proxy/explicit.rs` module docs point 10); `B06` covers only the transparent path. | Low | Prefer HTTPS. Later: a per-request relay scanner and body framing on the explicit path, and strict framing on the transparent path. | #29 |
| R9 | **Encrypted TLS 1.2 renegotiation** with a new ClientHello is invisible to any non-terminating proxy. Other scanner false-teardown families are listed in `src/proxy/relay.rs` module docs point 3. | Low | TLS 1.2 renegotiation is rare. | doc only |
| R10 | **Explicit-proxy edge cases.** A leading `//` origin-form is forwarded as-is. Fields named by a `Connection` token are forwarded. A CONNECT dial failure after the 200 is a silent close (a diagnostic issue, not a security one). | Low | Documented. | #29 |
| R11 | **Tools that ignore DNS and proxy settings fail rather than leak.** In transparent mode, any TCP connection to a non-fake IP is denied. In explicit mode there is no route. | Info (availability) | Use transparent mode where the host supports it (`sbx check`). | doc only |
| R12 | **Guard coverage is a deny-list of IANA special-purpose ranges.** A public platform endpoint outside those ranges (for example Azure's 168.63.129.16) and the host's own public interface addresses are dialable if an allowed name resolves to them. That needs control of the name's DNS, or a name that legitimately resolves there. srt's README lists both classes as denied (section 9). | Low | Later: add platform endpoints, and an opt-in "deny the host's own addresses" or extra-CIDR policy field. | #41 |
| R13 | **Information disclosure inside the sandbox.** Host `/etc/hosts`, `/etc/ssl`, `/etc/ca-certificates`, `/etc/alternatives`, `/etc/localtime`, `/etc/nsswitch.conf` and `/etc/ld.so.cache` are visible (`INFRA_ETC`). `/proc/1/cmdline` shows the bwrap argv (policy paths and the session path). The kernel version and the procfs views are visible. **UNVERIFIED:** that netlink uevent multicast is readable from the payload. | Low | Documented. A synthetic hosts file (#35). | #35 |
| R14 | **Resource exhaustion.** There are no CPU, memory, pids or disk quotas (`SECURITY.md`). The bwrap scaffold and the deny `--tmpfs` masks are unsized (half of RAM by default). There is no relay idle timeout and no connection cap (`src/proxy/mod.rs` module docs point 6). The fake-IP pool holds 131,070 names, and exhausting it refuses only new names. The output cap bounds only stdout and stderr. **UNVERIFIED:** the connection-tracking table may fill under a flood of connections; this was not tested here. | Medium (host DoS) | Run under a cgroup or pod limits, and set `limits.timeout`. Later: a `limits` extension. | #43, #29 |
| R15 | **Kernel and bwrap bugs.** sbx shares the host kernel. A namespace, seccomp or netfilter bug, or a bwrap setup bug, can break confinement. Example: CVE-2026-87766 (GHSA-pxhw-h44j-8pfx), a bwrap setup-time symlink traversal fixed in bwrap 0.12.0. See R26. | High impact, low likelihood | Keep the kernel and bwrap patched. For hostile multi-tenant workloads, add a VM boundary (for example Kata, Firecracker or gVisor). `sbx check` reports the bwrap version. | `D12` (planted symlink refused); doc (CVE: R26, #39) |
| R16 | **Broad syscall surface.** The seccomp filter is a family allow list. Every other syscall is allowed, including `bpf`, `perf_event_open`, `userfaultfd` and `keyctl`, so the kernel attack surface is as wide as an unprivileged user's. | Medium | Host sysctls: `kernel.unprivileged_bpf_disabled`, `kernel.perf_event_paranoid`, `vm.unprivileged_userfaultfd=0`. Later: a syscall deny list. | #42 |
| R17 | **Netlink: all protocols allowed** inside the sandbox netns. The payload has no capabilities, so it cannot change anything (`C13`). Reads across namespaces are not restricted by sbx. | Low | Keep. Restricting netlink breaks `ip`, `ss` and `getifaddrs`. | doc only |
| R18 | **Audit integrity and volume.** One row per DNS datagram, so a payload can grow the log quickly. The log is not fsynced. Connections still open at exit get no `close` row. Connection-task panics leave only a missing row (#10). The audit file is refused under any policy path, so a broad bind (for example `ro: ["/home"]`) refuses audit paths under it. A policy of `ro: ["/"]` is rejected, because `/` is not allowed as a policy path (`src/policy.rs:check_path`). | Low | Put the audit file on a quota'd filesystem. Later: sampling or rate limits. | #29, #43 |
| R19 | **Audit redaction gap.** On the transparent path, `TargetMismatch`, the unrecognised-form detail and `HostInvalid` log client strings verbatim. The log is JSON-escaped, but can carry payload-chosen text. | Low | Audit consumers must treat every field as untrusted text (section 4). | #29 |
| R20 | **Availability costs of fail-closed defenses.** These are not risks; they are listed so operators are not surprised. GREASE-ECH clients are denied. Legitimate HRR retries are torn down. There is no HTTP keep-alive and no WebSocket or h2c upgrade on 80. Only ports 443 and 80 are inspected; other policy ports deny. IPv4 only. 32-bit binaries are killed. AF_ALG and AF_BLUETOOTH fail. io_uring returns ENOSYS. | Info | Documented. | doc only |
| R21 | **Terminal escape sequences.** The payload never gets a tty, but escape sequences in forwarded stdout and stderr reach the caller's terminal (output spoofing). | Low | Callers that display output should sanitise it. | #29 |
| R22 | **Pre-spawn steps run with signals blocked.** A hung NFS session path delays SIGTERM handling. The timeout applies only after setup. | Info | Use local session roots. | #29 |
| R23 | **gc edge cases.** NFS `.nfsXXXX` silly-rename files are a known gc residual (`src/gc/mod.rs` module docs). **flock on NFS and 9p is not handled**: sbx does not detect those filesystems, so a live session's lock may not be honoured and gc could remove that session. An interrupted gc leaves a tombstone (`ROOT/.sbx-gc.<pid>.<nonce>`) that the next gc collects; a mount inside a session can survive into a tombstone, and the walker's behaviour on such a mount was not analysed here. Foreign-owned top-level entries are skipped silently; a foreign-owned entry inside a session aborts that gc walk (`src/gc/walk.rs`, `WalkError::Foreign`). A same-uid writer can make gc fail. Session-directory ancestors are the caller's placement contract (lexical checks only; symlinked ancestors are followed). | Info (flock on NFS and 9p: Medium) | Do not run gc on NFS or 9p session roots. | doc only |
| R24 | **Same-uid host processes** can ptrace, signal or read the `/proc` entries of `sbx run`, bwrap and the payload from outside. The sandbox protects the host from the payload, not the payload from the host user. | Out of model | Run sbx under a dedicated uid if the caller's other processes are untrusted. | doc only |
| R25 | **IANA table staleness.** The guard tables are a snapshot. Transition ranges (Teredo, 6to4, local-use NAT64 `64:ff9b:1::/48`) are denied outright, which breaks transition-only networks. There is no escape hatch. | Low | Re-audit when this document is revised (section 11). An escape hatch only if a real use case appears. | doc only |
| R26 | **bwrap CVE-2026-87766 (GHSA-pxhw-h44j-8pfx).** bwrap before 0.12.0 resolves a bind dest's parents through symlinks during setup, and `/oldroot` is the host root at that point. A payload that ran earlier under a bind (writable, or read-only inside a writable tree) can plant a symlink, so bwrap creates a directory at any host path the caller can write, or binds a host directory as a source. sbx now verifies every path bwrap resolves under any policy or session bind before it spawns (`src/bwrap/guard.rs`, S8a): each component must be a real directory (the right type at the end), nothing may be missing under a writable bind, and a deny or a bind that reaches the host through a symlink alias of its counterpart is refused too. The refusal is rc 125 with nothing created. The minimum bwrap version stays 0.8 (`BWRAP_MIN`), so an older bwrap starts; `sbx check` warns below 0.12.0 (`bwrap-cve`), and `mount-chains` fails on a planted link. Residuals: a writer that is not a sandbox of this exact policy (another policy over the same tree, an older sbx, a host process, a host bind-mount alias of the tree) can change a component between the check and bwrap's setup on bwrap before 0.12.0. Same-policy sandboxes are pinned (R27) and cannot. Hard links are not seen at run time (R27). | Low (after the guard; was High) | Install bwrap 0.12.0 or later, which removes the window. Keep sbx and bwrap updated. Do not run host tools or other policies over a tree that a sandbox writes. Follow-up: bwrap `--block-fd` plus a mountinfo check before the payload is released. | `D12` (planted symlink refused before launch); `sbx check` `mount-chains` and `bwrap-cve`; #39 |
| R27 | **Deny masks are lexical and per run.** A deny entry hides a path name. A payload can rename an ancestor directory it controls, or follow links, to reach the denied content through another name. sbx pins every intermediate directory between a policy bind and a nested bind or a deny mask (writable or read-only, at any nesting, including the parents of nested writable binds) with a self-bind, so an in-sandbox rename or rmdir of those directories fails with EBUSY, and a rename across a pinned boundary fails with EXDEV (`mv` falls back to copy). The nested read-only bypass, the nested writable bypass and the nested-bind source swap are closed by these pins and by the pre-launch walk. A bind or deny reached through a host symlink alias is refused before launch. Residuals: a host hard link to a denied file, and a host bind-mount alias of a denied directory, are not detected at run time (`sbx check` warns on hard links, `deny-links`). Content moved by a writer outside this policy is not followed, since a deny hides a path, not an inode. The pin cost grows superlinearly with the pin count (`sbx check` warns above 50). | Low to Medium | Grant only the paths that are needed, and do not rely on deny entries for secrecy alone. A deny entry under a writable bind must exist as a real directory on the host (a missing one is refused). Keep the deny list short. Do not hard-link secrets into a tree that is mounted elsewhere. | `D11` (a deny mask survives ancestor renames, nested binds included); #40 |
| R28 | **The proxy and DNS parsers run outside the sandbox boundary.** They run on the `sbx-net` thread of the `sbx run` process, as the caller's uid, in the host network namespace, outside bwrap and the seccomp filter. They parse payload bytes. A memory-safety or logic bug in a parser is not contained by the sandbox. | Low likelihood, High impact | Rust code, which is memory-safe; no security audit has been done. Keep parsers small and test them. | doc only |
| R29 | **The audit log is incomplete by design and under the caller's uid.** It records what the proxies and resolver handle. An attempt stopped before them (an nftables drop, a seccomp denial, a missing capability) produces no row. The log is written under the caller's uid, so payload-planted code (R7) that runs later outside the sandbox can rewrite it. | Medium (audit completeness; not a confinement failure) | Read the audit log as evidence of proxied traffic only. sbx already refuses audit paths inside the session dir or any policy path (checked lexically and after resolving symlinks), so the remaining threat is code running later as the caller's uid: forward rows off-host as they are written, or have root mark the file append-only (`chattr +a`; sbx opens it `O_APPEND`, and only its truncate-on-write-error rollback would then fail). | doc only |

## 8. Design decisions: why not

These sections state the decisions recorded in #20 and in the code. Claims about other projects cite
the project's public repository at the commit read. A claim that was not checked is marked.

### 8.1 Why not an eBPF cgroup firewall

Source: `https://github.com/lawrencegripper/ebpf-cgroup-firewall` at commit `f7fca64` (2025-03-17),
read for this document, and #20.

- **Privilege model.** #20 states that attaching `CGROUP_SOCK_ADDR` or `CGROUP_SKB` programs needs
  `CAP_BPF` and `CAP_NET_ADMIN` in the initial user namespace. This was not re-verified. The evaluated
  tool's README attaches with `sudo` (`README.md`, "Attach to a Docker Container"). sbx's chain runs
  unprivileged: nftables inside a private netns is shown to work unprivileged by the #1 spike
  (`spikes/nft-load`).
- **Bypass in the evaluated tool.** Its name checks use bare suffix matching: `strings.HasSuffix(q.Name,
  domain+".")` in `pkg/dns/dns.go`, and `strings.HasSuffix(req.Host, domain)` in
  `pkg/proxy/blocking_request_handler.go`. Allowing `github.com` in that model admits
  `evilgithub.com` on the proxy path, as the code reads. sbx matches exactly or on a dot boundary
  (`src/egress.rs:allowed`; `A08`, `A09`). The bypass was read from the code and not run.
- **Fails open (inferred, untested).** The evaluated tool keeps its cgroup links as file descriptors,
  not pinned. Its code notes "TODO store link and use it to pin", and a comment warns that the
  program is unloaded if the link reference is dropped (`pkg/ebpf/ebpf.go`). From this, the failure
  mode is that enforcement ends if the firewall process dies while the workload keeps running. That
  failure was not tested. In sbx, proxy death is meant to end the sandbox (S4; `F03`).
- **TLS.** The evaluated tool intercepts CONNECTs with a host-installed mkcert root CA
  (`pkg/proxy/proxy.go`, `customAlwaysMitm`) and pins `github.com/elazarl/goproxy v1.7.0` (`go.mod`).
  In goproxy v1.7.0 the default upstream transport `Tr`, set in `NewProxyHttpServer` (`proxy.go`),
  uses `tlsClientSkipVerify`, which `certs.go` defines with `InsecureSkipVerify: true`. The evaluated
  tool does not override `Tr` (searched in the repository). So its upstream leg does not verify
  upstream certificates. This was read from the goproxy source and not run. sbx passes TLS through,
  and the client verifies end to end.
- **Scope.** The evaluated tool is IPv4 only and drops AAAA records (its README). Correlation is per
  cgroup, not per call.

### 8.2 Why not a bwrap fork

- Nothing sbx needs requires patching bwrap. The netns, nftables rules and listener sockets are set up
  by `sbx __init` before bwrap starts, and bwrap joins the inherited netns (no `--unshare-net`;
  `src/bwrap/mod.rs` module docs point 6). The other flags are stock: `--seccomp`, `--clearenv`,
  `--info-fd` (pid-1 identity), `--disable-userns`, `--die-with-parent` and `--new-session`.
- Security fixes then arrive through the distribution's bwrap package. A fork would make sbx the
  maintainer of a setuid-capable C program. The consequence is that CVE-2026-87766 is handled as a
  deployment requirement (install bwrap 0.12.0 or later; R26, #39). sbx also carries a pre-launch
  guard for the shapes the CVE needs (`src/bwrap/guard.rs`), because the version string cannot show
  a distribution backport.
- Operators can audit "unmodified bwrap 0.8 or later" and replace it through `SBX_BWRAP`. `sbx check`
  reports the version (`src/bwrap/version.rs`, `BWRAP_MIN`).
- Cost accepted: bwrap behaviours that sbx works around and documents. `PWD` is re-exported under
  `--clearenv`. `--dev` exposes the host tty when stdout is a tty, so sbx always pipes stdio. The
  usr-merge shim ordering. The unsized tmpfs (R14).

### 8.3 Why not an external proxy

sbx embeds its proxy (rustls `Acceptor` for SNI, `httparse`, `hickory-proto`). An external daemon
would add a process whose death must also fail closed, and an IPC channel between them. Section 9
shows how the other projects place their proxies. This document makes no claim that existing Rust
proxies lack SNI-checked transparent mode; that was not surveyed.

### 8.4 Why TLS passthrough in v1

No CA is installed in the sandbox. Clients verify servers end to end, there is no key material to
protect, and certificate pinning and mTLS keep working. The cost is that R1 and R2 cannot be closed.
#17 proposes opt-in termination for selected hosts, with a per-run in-memory CA and verified upstreams. Its title names URL-path rules; nothing in it yet names a `Host` or `:authority` check, so the R1 fix is not yet specified.

## 9. Comparison

Sources, all dated:

- **sbx**: this repository, `main` @ `53ee605`.
- **srt** (`https://github.com/anthropics/sandbox-runtime`): commit `3ed9739` (`git describe`: `v0.0.77-7-g3ed9739`, 2026-09-28),
  `README.md`, and `srt:src/sandbox/linux-sandbox-utils.ts` where cited.
- **Greywall** (`https://github.com/GreyhavenHQ/greywall`): the public README at commit `60ab1b5` (2026-10-17)
  through a summarising fetch. **Not verified** line by line. Where the README is silent, the cell
  says "not stated".
- **Landlock**: `https://docs.kernel.org/userspace-api/landlock.html`, read on 2026-10-17.

| Aspect | sbx | srt (Linux) | Greywall (Linux) | Landlock-only |
|---|---|---|---|---|
| Network enforcement | Private netns with nftables redirect to in-process proxies (transparent). Explicit mode has no route. | `--unshare-net` removes the network namespace. Host HTTP and SOCKS5 proxies are reached over unix sockets bridged by socat (README "Network Isolation Architecture"; `socatPath` option in `srt:src/sandbox/linux-sandbox-utils.ts`) | Network namespace with `tun2socks` TUN capture to greyproxy (SOCKS5 on localhost 43052) and a DNS bridge on 43053 (README) | Not a host control: TCP bind and connect port rules from ABI 4, UDP from ABI 10 |
| Tools that ignore proxy settings | Transparent mode: works if allowed, otherwise denied. Explicit mode: fails. | Rely on `HTTP(S)_PROXY` and `ALL_PROXY`; tools that ignore them cannot connect (README "Linux proxy bypass") | Transparent capture through TUN (README) | Not applicable |
| Name matching | Exact or dot-boundary suffix; IDNA-normalised | `allowedDomains` with `*.example.com` wildcards, optional `:port`, and `deniedDomains` taking precedence (README "Configuration Options") | Not stated | Cannot express names |
| TLS SNI check and ECH | SNI must equal the name; ECH denied; second-hello scanner | README: the filter "does not otherwise inspect the traffic" beyond the domain; domain fronting acknowledged | Not stated | Not applicable |
| TLS termination | No in v1; opt-in later (#17) | Experimental opt-in `network.tlsTerminate` (README) | Not stated (credential substitution is mentioned) | Not applicable |
| Non-HTTP TCP | Denied; only 443 and 80 are inspected | SOCKS5 to allowed domains on any or listed port (README) | SOCKS5 through greyproxy (README) | Port rules only |
| DNS | In-process fake-IP resolver; never forwards DNS queries. Allowed names are resolved on the host at connect time (the proxy dials by name and the guard checks the result; R4) | Name resolution through the proxy, on the host (README) | DNS bridge to greyproxy (README) | Not applicable |
| Resolved-address check | IANA special-purpose tables plus a peer re-check | Loopback, unspecified, link-local, multicast, broadcast, cloud metadata including 168.63.129.16, the host's own interface addresses, `deniedResolvedAddresses`; RFC 1918 ranges are not in the listed default set (README "Resolved-address check") | Not stated | Not applicable |
| Filesystem model | Allow list: nothing visible unless listed | Read allowed everywhere by default, with `denyRead` and `allowRead`; write allow-only; mandatory deny paths (README) | Deny-by-default; working directory accessible (README) | Path rules from ABI 1, unprivileged |
| Environment | Cleared; the policy's `pass` and `set` only, plus infra variables | Not stated as a general rule; `denyRead` and credential handling are documented (README) | "Environment sanitization" listed (README, no detail) | Not applicable (Landlock does not manage the environment) |
| Unix sockets | AF_UNIX allowed; pathname sockets under binds reachable (#35) | Seccomp blocks AF_UNIX `socket()` creation unless `allowAllUnixSockets` is set (README "Unix Socket Restrictions") | Not stated | Abstract scope from ABI 6; pathname `RESOLVE_UNIX` from ABI 9 |
| Other socket families | Family allow list (vsock, packet and others denied) | Network namespace removes INET; AF_UNIX as above; other families not stated | Seccomp BPF listed as a layer; families not stated (README) | Not applicable |
| Privileges and daemon | None; single binary; no daemon. Needs a host bwrap 0.8 or later; versions before 0.12.0 carry CVE-2026-87766 (R26) | Node.js package; bwrap, socat and ripgrep dependencies (README) | README: `greywall setup` installs and starts greyproxy; bubblewrap and socat required | None |
| Conformance suite | 71 executable checks, `sbx check --conformance` | Not stated | Not stated | Not applicable |
| Platforms | Linux only | macOS, Linux, Windows (alpha) | Linux, macOS (reduced network on macOS) | Linux 5.13 or later |

Notes on the table:

- Landlock is complementary. It is defense in depth, not an egress control, because it cannot
  express names. #19 proposes it as an optional layer.
- srt's resolved-address check covers two classes that sbx's guard does not (R12): the cloud metadata
  address 168.63.129.16 and the host's own interface addresses. The sbx guard covers the IANA
  special-purpose ranges, which srt's list does not cover in the same way.
- srt's filesystem default is read-everywhere. sbx's is nothing-visible-unless-listed.

## 10. Verifying on your host

- `sbx check` reports the host's capabilities and the modes it supports.
- `sbx check --conformance` runs every offline tier (host, init and lab) against the built-in policies,
  not the caller's policy. The lab tier uses local fixtures. A PASS is a point-in-time result for this
  host. `--network` adds the network tier (opt-in, needs internet). The README `## Conformance` section
  describes what PASS, FAIL, warn and skip mean.
- `sbx check` reports `ok bwrap <version>` for any bwrap 0.8 or later. On a version before 0.12.0 it
  warns (`bwrap-cve`, for example `bubblewrap 0.9.0 predates 0.12.0`) when the policy has mount
  paths inside `rw` paths. It never fails on the version (R26). `mount-chains` fails when the
  guard would refuse at run time (R26, R27).
- `D05` is a warning, not a failure. It means a unix socket file is visible under a bind. Review the
  bind list when it appears.
- Checks that need the transparent path are skipped in explicit mode. That is expected.

## 11. Maintenance

- **Keeping this document true.** `tests/threat_model_doc.rs` runs under `cargo test --locked`. It
  checks that every backticked check id exists in the catalog, that every catalog check is cited in
  section 6, that each "N checks" statement here and in the README matches the catalog size (trailing
  punctuation allowed), that README.md and SECURITY.md link this file, that every `src/` path exists,
  that every `path:identifier` reference (and each bare identifier in a comma-separated list after it)
  names a non-comment occurrence in that file, and that every "module docs point N" names a numbered
  point in that file. Limitation: the identifier check is a whole-word search of code lines, not a
  parse, so it can be satisfied by an unrelated use of the same name.
- **IANA tables.** `src/egress.rs` transcribes the IANA IPv4 and IPv6 special-purpose registries.
  Its comments record "Last Updated 2025-10-09" and a transcription on 2026-10-04 with a re-fetch and
  diff at implementation time. On 2026-10-17 both registries still showed "Last Updated: 2025-10-09",
  so no registry revision has been published since. A row-by-row diff of the code tables (which fold
  registry rows) was not repeated in this change. Repeat it when the registry date changes, and record
  the date here.
- **Coverage gaps.** `D04` covers pathname unix sockets outside the binds, `D08` another session's
  files, and `H06` HOME and processes. No check covers an arbitrary non-allowed host path, or a write
  to an `ro` bind (S12). #45 tracks these gaps. The deny-mask rename (R27, #40) is covered by `D11`, and the planted-symlink refusal (R26, #39) by `D12`. Explicit-mode pipelining (R8) is not covered by any check.
- **When to update.** When a check id is added or removed, when a residual is closed or its severity
  changes, when a follow-up issue is filed, or when a registry revision is published.
