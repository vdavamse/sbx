# Host check

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
  ok    seccomp     bwrap installs sbx's socket-family filter (installation only; denials not probed)
  ok    landlock    Landlock ABI 7 (report-only): available: filesystem, TCP bind, signal scope
  ok    keep-alive  pidfd and an unprivileged setns into a fresh user and network namespace work (run --keep-alive, attach)
  ok    conntrack   conntrack table: 312 of 262144 entries in use in this network namespace (report-only; each sandbox namespace may grow to 262144, using host kernel memory)

network mode: transparent (policies with network mode transparent, explicit or none can run)
```

The items, in order: `userns` (unprivileged user and network namespaces),
`netns` (the sandbox loopback), `netns-ipv6` (IPv6 can be disabled inside the
sandbox), `nft` (the nftables NAT redirect that transparent mode needs),
`fallback` (the default route can be removed, which the explicit mode needs),
`bwrap` (the bubblewrap binary and its version), `bwrap-run` and `bwrap-proc`
(bwrap can start a sandbox here, and mount a fresh `/proc`), `seccomp` (bwrap
installs sbx's socket-family filter, see [Running commands](usage.md#running-commands):
a failure here makes the network mode `unavailable`, because the sandbox cannot
start without the filter), and `landlock` (report only: the Landlock ABI and which
parts of the optional layer the kernel provides, see **Landlock layer** under [Running commands](usage.md#running-commands)),
and `keep-alive` (report only: a pidfd of this process and an unprivileged `setns`
into a fresh user and network namespace, the two things `run --keep-alive` and
`attach` need; see [Persistent sessions](usage.md#persistent-sessions)). A `keep-alive`
failure is a `warn`. Like `landlock`, it is report only: it never limits the
network mode, so a host that runs plain sandboxes still exits 0.
`conntrack` (report only) shows the host's conntrack table: the sandbox's NAT redirect needs
conntrack, and each sandbox network namespace's entries count against `nf_conntrack_max` and use
host kernel memory. It is `skip` when the table cannot be read.
An item is `ok`, `FAIL` (with the evidence and a `fix:` line), `skip` (not probed because an item it depends on
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
the audit exit row records the mode the run got (see [Running commands](usage.md#running-commands)).

**Policy comparison.** `sbx check --policy P --host` adds nine checks to the
host report: `network-mode` (the policy's mode against the host), `infra-etc`
(the `/etc` files every sandbox binds), `policy-paths` (every `filesystem.ro` and
`filesystem.rw` path exists), `deny-paths` (a deny entry that is a file cannot
be masked, and one that sits under a bound path or an sbx-generated `/etc` file
is flagged), `bind-sockets` (a `warn` listing the unix socket files under
`filesystem.ro` and `filesystem.rw`, outside `filesystem.deny`; see
[Unix sockets under binds](usage.md#running-commands)), `mount-chains` (the pre-launch
verification of `run` below, which fails the policy when `run` would refuse),
`bwrap-cve` (warns when bwrap is older than 0.12.0 and the policy has mount
paths under its binds), `deny-links` (warns when a file under a deny path has a
hard link outside it), `pin-cost` (warns above 50 directory pins) and
`deny-tmpfs-size` (warns when bwrap is older than 0.10 and the policy has deny
masks, which then stay unsized). A `warn` does not stop the policy from running.

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
platform, the Kubernetes and Docker forms are given (for Kubernetes, the full
setup is in [docs/kubernetes.md](kubernetes.md)):

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
| `mount-chains` | a path bwrap resolves under a policy bind is a symbolic link, is missing or has the wrong type, or a deny path is reachable through a host symlink alias | remove the symbolic link, create the directory on the host, or move the entry out of the `rw` path (the message names the component) |
| `bwrap-cve` | bwrap is older than 0.12.0 and the policy has mount paths under its binds (a warning; the run still starts) | install bubblewrap 0.12.0 or later (CVE-2026-87766); a distribution backport is not visible in the version string |
| `deny-links` | a regular file under a deny path has a hard link outside it (a warning) | remove the extra hard link, or deny the other name as well |
| `deny-tmpfs-size` | bubblewrap is older than 0.10, so the deny masks are unsized tmpfs (a warning; from 0.10 each mask is capped at 1 MiB) | install bubblewrap 0.10 or later, or run under a memory limit |
| `pin-cost` | the policy needs more than 50 directory pins (a warning): each pin is an extra bind, and startup grows superlinearly with the count | keep the deny list short, or deny a parent directory instead of many nested entries |
| `bwrap-run` | bwrap cannot apply `--disable-userns` because `/proc/sys` is read-only | `procMount: Unmasked` (Kubernetes) or `systempaths=unconfined` (Docker) |
| `bwrap-run` | bwrap cannot start a sandbox inside the sbx namespaces | allow `mount` and `pivot_root` inside nested user namespaces (Kubernetes: a Localhost seccomp profile that allows them, or `seccompProfile` and `appArmorProfile` Unconfined) |
| `bwrap-proc` | bwrap cannot mount a fresh `/proc` (a masked `/proc`, typical in containers) | `procMount: Unmasked` (Kubernetes) or `systempaths=unconfined` (Docker) |
| `seccomp` | bwrap cannot install sbx's socket-family seccomp filter (no `CONFIG_SECCOMP_FILTER`, or an outer policy that forbids `prctl(PR_SET_SECCOMP)` / `seccomp(2)`) | no program exists for this architecture (sbx ships the filter for x86_64 and aarch64 only); otherwise a kernel built with `CONFIG_SECCOMP_FILTER=y`, and an outer seccomp or container profile that allows `prctl(PR_SET_SECCOMP)` and `seccomp(2)` (Kubernetes: a Localhost seccomp profile that allows them, or `seccompProfile` Unconfined) |
| `keep-alive` | `pidfd_open` is refused (ENOSYS below Linux 5.3, or an outer seccomp profile) (report only) | run sbx on Linux 5.3 or newer; Kubernetes: a Localhost seccomp profile that allows `pidfd_open`, or `seccompProfile` Unconfined |
| `keep-alive` | the holder stand-in's `unshare(CLONE_NEWUSER\|CLONE_NEWNET)` is refused (EPERM or EACCES). The probe's own namespace was created, so only the nested user and network namespaces are refused; report only | allow nested `unshare(CLONE_NEWUSER)` and `unshare(CLONE_NEWNET)` for this user (a seccomp or container profile that blocks them; Kubernetes: a Localhost seccomp profile that allows them, or `seccompProfile` Unconfined; Docker: `--security-opt seccomp=unconfined`), or do not use `run --keep-alive` |
| `keep-alive` | an unprivileged `setns` into a fresh user and network namespace is refused (EPERM or EACCES; report only) | allow `setns(CLONE_NEWUSER)` and `setns(CLONE_NEWNET)` for this user (a container seccomp profile often blocks `setns`; Kubernetes: a Localhost seccomp profile that allows it, or `seccompProfile` Unconfined; Docker: `--security-opt seccomp=unconfined`), or do not use `run --keep-alive` |
| `keep-alive` | the holder stand-in cannot be started, or the join fails for another reason (report only) | allow unprivileged user and network namespaces and `setns` for this user, or do not use `run --keep-alive`; plain `sbx run` does not need them |
| `landlock` | Landlock is not supported (report only) | none needed today; kernels 5.13 or newer built with `CONFIG_SECURITY_LANDLOCK=y` provide it |
| `landlock` | Landlock is built in but disabled (report only) | add `landlock` to the `lsm=` kernel boot parameter |

**Masked `/proc`.** On a host that masks `/proc` in a way that passes the
probe but fails later, the sandbox starts and then bwrap exits with its own rc
1; `sbx run` reports that exit as the payload's status, not as a refusal. `sbx
check` reports the failure as `bwrap-proc` with the `procMount` hint. `sbx run` does
no pre-check, so the payload's own rc (bwrap's rc 1) passes through.
