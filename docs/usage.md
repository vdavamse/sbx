# Usage

The reference for `sbx run`, persistent sessions (`--keep-alive`, `attach`, `stop`) and `sbx gc`,
and how a run is put together. The [README](../README.md) has the quick start; the host report is
in [Host check](host-check.md).

For agents and agent harnesses, the skill in [`skills/sbx/`](../skills/sbx/SKILL.md)
summarizes the parts of this reference that are easy to get wrong (the sandbox
layout, `--cwd`, standard streams, exit codes, the audit log) and links back here.
Install it by copying the directory to `~/.claude/skills/sbx` or to a project's
`.claude/skills/sbx`. Its two use cases, an agent running inside the sandbox and a
harness that runs each bash tool call through `sbx run`, have tested wrappers in
[`examples/harness/`](../examples/harness/).

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
| the host cannot provide the policy's network mode, or cannot run sandboxes | 125 | `failed` | `sbx run: policy requires network mode <mode> but this host provides only explicit: <reason>; fix: <fix>; run \`sbx check\` for a full host report` (or `… but this host cannot run sandboxes: …`); the staged line of `__init` comes first |
| the explicit fallback ran (the nft redirect is unavailable, the policy is `explicit` or `none`) | the command's own | the command's | `sbx run: notice: running in network mode explicit because the nftables NAT redirect is unavailable (<reason>); run \`sbx check\` for details` |
| a Landlock shim failure under `--landlock` (the shim could not apply the rules, could not check the host ABI, or could not exec the payload) | 125 | `failed` | `sbx run: landlock: <reason>`. The shim starts with a marker on the status pipe and adds its reason after it, so a payload's own 125 (marker only) is never reported as this one, and a shim that never started is reported by the row above |
| the Landlock shim did not start under `--landlock` (bwrap could not exec `/proc/self/fd/N`, or the dynamic loader failed before the shim's first act, so the status pipe holds no start marker) | 125 | `failed` | `sbx run: landlock: the shim did not start (rc N)`, where N is bwrap's own rc (1 for bwrap's exec failure, 127 for the loader) |
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

**Filesystem policy.** `ro` and `rw` paths are bound at the same path inside the
sandbox. A `deny` entry is an empty `tmpfs` over its path: it hides the path name,
and only that name. Before the payload starts, `run` checks the host side of every
path bwrap will resolve under a policy bind (read-only or writable):

- A path that is a symbolic link, is missing, or has the wrong type on the way to
  a bind dest or a deny entry is refused: rc 125, `sbx run: filesystem path … `,
  with nothing created outside the session directory and the audit log. Each component is opened without following links, so
  bwrap never sees one. A `deny` entry under `rw` must already exist as a
  directory on the host; bwrap would otherwise create it, and its parents, there.
- A `deny` path that the host reaches through a symbolic link alias of another
  bind is refused, and so is a bind whose host source is a link into a deny path:
  either way the mask would not cover that inode.
- Every directory between an `rw` path and a `deny` entry, or a nested bind (read-only
  or writable), is pinned with a self-bind, including the parents of nested writable binds. A payload cannot rename or remove a pinned directory
  (EBUSY), so the mask stays where it was. A rename across a pinned boundary fails
  with EXDEV: `mv` falls back to copy, but a tool that only calls `rename(2)` sees
  the error. Pins cost startup time that grows superlinearly with their count: on
  WSL2, 60 pins add about 17 ms, 300 pins about 180 ms and 900 pins about 1 s. `sbx check`
  warns above 50 pins (`pin-cost`). Keep deny lists short, and deny a parent instead of
  many nested entries.

The check runs once, before the spawn. It does not stop a writer that is not a sandbox of
this exact policy (another policy, an older sbx, a host process, a host bind-mount alias
of the tree) from changing the tree during the window. That window is a known residual
on every bwrap version (R26 in [the threat model](threat-model.md), Medium when policies share a writable
tree; bwrap 0.12.0 closes only the dest side, not a swapped bind source): **do not share an
`rw` tree between policies**, and do not let
host tools write into an `rw` tree while sandboxes run. A bind whose host source reaches
another bind\'s tree through a symbolic link is refused (N19): bind the real path. Hard links made on the host to a denied
file, and host bind-mount aliases, are not detected at run time; `sbx check` warns about
hard links (`deny-links`).

**Protected paths (`filesystem.protect`).** Some files inside an `rw` tree run later on
the host without anyone running them from the tree: a git hook runs at the next
`git commit`, a `core.fsmonitor` line in `.git/config` runs at every `git status` (a
git-aware shell prompt is enough), and editors and agents load their project config
when they open the folder. sbx binds these read-only inside every `rw` path, by default
and on every launch (`run`, `run --keep-alive` and each `attach` call). The default list
is the one Anthropic's sandbox-runtime (srt) uses:

```text
.bashrc .bash_profile .zshrc .zprofile .profile .gitconfig .gitmodules
.git/hooks/ .git/config .ripgreprc .mcp.json .vscode/ .idea/
.claude/commands/ .claude/agents/
```

- **Where.** At the top level of each `rw` path and in its real directories up to 3
  levels below (`rw/a/b/c/.git/hooks`, as srt). The scan follows no symbolic link and
  does not enter `node_modules` directories, `deny` paths or other policy binds. It
  skips an unreadable directory that belongs to another user (a container volume), and
  refuses one of yours. A worktree's `.git` file is protected itself. Inside each
  `.git`, the existing submodule git directories (`.git/modules/…`: `hooks/`, `config`,
  `commondir`) and linked worktrees (`.git/worktrees/*/commondir` and `gitdir`) are
  protected too. A `commondir` file that the payload creates in a git directory would
  make host git take its hooks and config from elsewhere; sbx renames it aside when the
  run ends and prints `sbx: warning: the sandbox created …`. Each protected path is a nested
  read-only bind, so the directories on the way to it are pinned (see above): the
  payload cannot rename them away, and each pin costs startup time like any other.
- **Sessions.** `run --keep-alive` scans when the session starts, and every `attach`
  call binds the paths the session saved instead of scanning again (a scan of a tree
  the resident writes would let it pick the binds of the next call). A protected path
  the resident creates during the session is protected from the next session on.
- **Missing entries.** At the top level, a missing entry gets an empty, read-only
  placeholder directory for the run (at its first missing component: `.git` when there
  is no `.git`). It stops the payload from creating the file, and git ignores empty
  directories, so it never shows up in `git status` or a `git add -A`. sbx removes the
  placeholders when the run ends. While the run lasts they are visible on the host
  (`ls -a`). A placeholder is an empty directory with a 1970-01-01 modification time; one
  left behind by a crash is removed by the next run in the same session directory, by
  `sbx gc` when it collects that session, or by the next launch that scans the tree.
  Below the top level, missing entries are not protected.
- **What breaks.** With `.git/config` read-only, `git config`, `git remote add`,
  `git branch --set-upstream-to` and `git init` in the `rw` path fail inside the sandbox
  with `error: could not write config file .git/config: Device or resource busy`.
  `git commit`, `git checkout`, `git fetch` and other commands that do not write the
  config keep working. Tools that read a placeholder (an editor reading `.mcp.json`)
  get `EISDIR`. With `rw` on a home directory, a missing `~/.gitconfig` becomes a
  placeholder for the run, and host git warns `unable to access … Is a directory` until
  the run ends: bind the project, not the home directory. A user's own empty directory
  at a protected name with a 1970-01-01 modification time is taken for a placeholder and
  removed.
- **Refusals.** A protected name that is a symbolic link is refused (rc 125,
  `sbx run: protected path … is a symbolic link; sbx cannot bind it read-only`), and so
  is a scan of more than 20 000 directories in one `rw` path.

The list is replaced by an explicit one; `"@default"` stands for the default list.
Run git commands that rewrite the config on the host, or turn the protection off:

```json
"filesystem": { "ro": ["/usr"], "rw": ["/home/me/project"], "deny": [],
                "protect": ["@default", "Makefile", ".envrc", ".github/"] }

"filesystem": { "ro": ["/usr"], "rw": ["/home/me/project"], "deny": [],
                "protect": [] }
```

This does not make `rw` safe (R7 in [the threat model](threat-model.md)): a `Makefile`,
an `.envrc`, `package.json` scripts and CI files still run when someone runs them, and the
default list does not cover them. Review the diff before running host tooling on it.

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

**Resource limits.** `limits` may also set `processes`, `open_files`,
`file_bytes` and `address_space_bytes` (positive integers; absent means the
caller's own limit is inherited). They become `RLIMIT_NPROC`, `RLIMIT_NOFILE`,
`RLIMIT_FSIZE` and `RLIMIT_AS`, with soft and hard limits both set, so the
command cannot raise them. `__init` sets them after it creates the sandbox's
user namespace and right before it execs bwrap. Per limit:

- `processes` counts the sandbox's own processes and threads (Linux 5.14 and
  later; older kernels count every process of the caller's uid). When sbx runs
  as root, it is enforced only on Linux 5.17 and later. bwrap uses two of them.
- `open_files` must not exceed the caller's hard limit (or `fs.nr_open`).
- `file_bytes` bounds each file, not the total disk use. A write past it fails
  and the writer gets `SIGXFSZ`.
- `address_space_bytes` is virtual memory, not resident memory. Runtimes that
  reserve large address ranges (JVM, V8, Go) need generous values.

bwrap runs under the same limits, so very small values (`processes` below 3,
a handful of `open_files`, a few MiB of address space) make bwrap itself fail.
A limit the caller cannot grant fails setup (125, with
`sbx __init: exec: cannot set limits.<field> …`). These are per-process
limits, not a cgroup: they do not bound the total memory of all sandboxed
processes, tmpfs sizes or the total disk use. See
[R14](threat-model.md#7-residual-risks).

```json
"limits": { "timeout": "120s", "output_bytes": 10485760,
            "processes": 256, "open_files": 1024,
            "file_bytes": 1073741824, "address_space_bytes": 8589934592 }
```

**cgroup limits.** `limits.memory_bytes` and `limits.pids` bound
the whole sandbox, not each process: they become `memory.max` (with
`memory.swap.max` 0 where swap is accounted) and `pids.max` on a child cgroup
that holds `__init`, bwrap and every payload process. Over `memory_bytes` the
kernel OOM-kills a sandboxed process (typically exit 137); past `pids` a fork
fails with `EAGAIN`. They need a delegated cgroup v2 that sbx runs in alone,
for example:

```sh
systemd-run --user --scope -p Delegate=yes sbx run --policy p.json --session-dir s -- make
```

sbx then moves itself into a leaf (`sbx-supervisor`), enables the `memory` and
`pids` controllers for its cgroup's children and creates `sbx-sandbox-<pid>`,
removed after the run. When the cgroup is not delegated, lacks a controller, or
holds other processes (sbx's own `--keep-alive` launcher excepted), a run with
either limit is refused (125, `need a delegated cgroup v2`): the limit is never
dropped silently. With `memory_bytes`, a host where swap is active but not
accounted for cgroups (`swapaccount=0`) is refused too, since the limit could
not keep the sandbox out of swap. sbx checks that its cgroup is writable, not
who manages it: run as root it can restructure any cgroup it sits in alone, so
give it a dedicated scope (`Delegate=yes`). With
`--keep-alive`, each run and each attached call gets its own child cgroup, so
the limits apply per call; an `sbx attach` needs the same delegation.

**Run-level caps.** Three more bounds apply to every run, with no
policy field:

- **Deny masks are sized.** With bubblewrap 0.10 or later, each `deny` tmpfs is
  capped at 1 MiB of file data (`--size`), so a payload cannot fill RAM with
  file contents through a writable mask (the inode count is not capped). A
  tool that writes more than 1 MiB into a denied directory now gets `ENOSPC`.
  Older bubblewrap has no `--size`: the masks stay unsized, and
  `sbx check --policy P --host` warns (`deny-tmpfs-size`).
- **Concurrent proxy connections.** At most 256 connections are open through the
  proxies at once (both listeners together); set another value with
  `sbx run --max-connections N` (1 to 65536). A connection over the cap is
  closed unread and gets one `deny` audit row whose reason starts with
  `conn_limit:` (these rows have no budget, unlike `dns` rows). A
  `--keep-alive` session shares the cap across its calls.
- **Fake-IP names.** A run maps at most 4096 distinct names (a `--keep-alive`
  session shares one map across its calls). A new name past that gets
  NXDOMAIN for every query type, with a `dns` audit row under the run's DNS
  row budget; names already mapped keep answering.

`sbx check` also reports the host's conntrack table (`conntrack`, report-only).
The nat redirect in the sandbox needs conntrack; on current kernels each network
namespace's entries are checked against the host's `nf_conntrack_max`, and they
use host kernel memory. Disk use in `rw` binds and the session directory is not
bounded (no quotas; R14).

**Session directory.** `--session-dir` is created with mode 0700 and must be
owned by the current user. Only one run may use a session at a time: a lock on
`sbx.lock` inside it is held for the whole run, and a second run fails with
`session directory is in use`. The directory's mtime is updated at the start and
the end of every run, which is the activity signal `gc` reads — see
[Garbage collection](#garbage-collection).

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
`rcode`, `qtype`, `client`. On `close`, `reason` is `null` for a natural end or
`"idle_timeout"` when the relay idle timeout closed the connection. A `deny` row
with `verdict` `teardown` records a relay-phase denial after the connection was
allowed: a second TLS `ClientHello`, or an HTTP request on the connection that
failed the checks (`relay torn down: HTTP request N denied: …`). Requests after
the first one on a keep-alive connection are not logged one by one, because their
name and port are the connection's. The `exit` row adds `code`, `outcome`, `signal`,
`duration_ms`, `output_truncated`, `dns_poisoned`, `net_mode` (`transparent`
or `explicit`: the network mode the run got, or `null` when `__init` never reported a mode
(setup never completed)) and `dns_suppressed` (the last key).

`dns` rows are rate limited per run, because every DNS datagram is one row: a
burst of 1000 rows, then 100 rows per second. Rows over the limit are not
written. The exit row's `dns_suppressed` counts them. The DNS answers
themselves are not affected. Proxy rows (`connect`, `deny`, `close`) are not
rate limited.

```json
{"ts":"2026-10-15T18:23:01.123Z","event":"dns","host":"github.com","sni":null,"port":null,"bytes":null,"reason":"answered github.com A 198.18.0.1","via":null,"verdict":"answered","rcode":0,"qtype":1,"client":"10.255.255.1:41000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"connect","host":"github.com","sni":"github.com","port":443,"bytes":null,"reason":"allowed github.com via 140.82.121.4:443","via":"transparent","verdict":"allowed","rcode":null,"qtype":null,"client":"10.255.255.1:40000"}
{"ts":"2026-10-15T18:23:01.123Z","event":"exit","host":null,"sni":null,"port":null,"bytes":null,"reason":"command exited with status 0","via":null,"verdict":null,"rcode":null,"qtype":null,"client":null,"code":0,"outcome":"exited","signal":null,"duration_ms":1234,"output_truncated":false,"dns_poisoned":false,"net_mode":"transparent","dns_suppressed":0}
```

Rows are in event order: a connection's `connect`, then `deny` (teardown) if
any, then `close`. An explicit connection is one request (or one tunnel) and
gets exactly one such group. The `exit` row is always last. A connection still open when
the run ends gets no `close` row. The log is not fsynced. If a write fails
mid-run the run fails closed (rc 125, `sbx run: audit log write failed: …`).

**Network.** Only ports 443 (TLS, SNI-checked) and 80 (HTTP, `Host`-checked)
are inspected; any other listed port is denied. ECH and GREASE-ECH are denied.
HTTP keep-alive on port 80 (and inside CONNECT-80 tunnels) covers bodyless
requests only: each request's head is checked before its bytes go upstream, and
a request with a body, `Connection: close`, `Upgrade` or HTTP/1.0 ends the
connection after it. In
transparent mode sbx sets no proxy environment variables. In explicit mode the
payload gets the proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`,
`NO_PROXY` and their lowercase twins) pointing at the explicit listener. The
explicit proxy's response table is in the `proxy::explicit` module docs (200 for
an allowed CONNECT; 400, 403, 502 and 504 otherwise).

**Unix sockets under binds.** A read-only bind does not block
`connect(2)` on a unix socket file: `ro` only stops writes to the file itself.
A policy that binds `/run`, `/var/run`, a directory under `/tmp` (such as
`/tmp/.X11-unix`) or a home directory therefore hands the payload every socket
under it, for example `docker.sock` (host root),
the D-Bus buses, an ssh-agent, or nscd and systemd-resolved (a resolver that
bypasses the fake-IP DNS). Keep socket directories out of `filesystem.ro` and
`filesystem.rw`, or mask them with `filesystem.deny`. A bind at exactly `/tmp`,
`/root`, `/work`, `/proc` or `/dev` is covered by sbx's own mount there, so the
host sockets under it are not reachable; under `/proc` and `/dev` this holds for
deeper binds too, since those mounts come after every bind. `sbx check --policy
P --host` warns about each reachable socket file under a bind (`bind-sockets`),
and also warns when a directory under a bind can be searched but not listed
(such as mode 0711), since `connect` needs only search permission and a socket
inside it stays reachable by name. The
conformance check `D05` warns about any socket file visible inside the sandbox.

**`/etc/hosts`.** The sandbox's `/etc/hosts` is generated, like
`resolv.conf`, `passwd` and `group`: it holds only `127.0.0.1 localhost` and
`127.0.1.1 sandbox` (the sandbox hostname). There is no `::1` entry, because
IPv6 is disabled inside the sandbox. The host's file is never bound, so a host entry cannot pin an
allowed name to a real address past the fake-IP resolver, and host entries are
not disclosed. A policy that lists `/etc/hosts` in `filesystem.ro` gets the
generated file (it mounts last). Names that a host's `/etc/hosts` or Kubernetes
`hostAliases` define are resolved by the proxy on the host side. They work for
allowed names only when they map to a public address: the resolved-address guard
still denies loopback, private, link-local and other special-purpose addresses,
which is where `hostAliases` usually point.

**Socket families and syscalls.** Every `sbx run` installs a seccomp
filter through bwrap (`--seccomp`), and the payload can create sockets only in
four families: `AF_UNIX`, `AF_INET`, `AF_INET6` and `AF_NETLINK`. Everything else
fails with `EAFNOSUPPORT` (errno 97): `AF_VSOCK` in particular, which is not
network-namespaced and reaches the host or hypervisor on VM-backed hosts (WSL2,
Hyper-V, Kata, Firecracker, cloud VMs), and with it `AF_PACKET`, `AF_XDP`,
`AF_BLUETOOTH`, `AF_ALG`, `AF_CAN`, `AF_TIPC` and `AF_RDS`. `socketpair(2)` is
checked the same way. Two behaviour changes follow from the list. `AF_ALG` (the
kernel crypto API, used by some `openssl` and `cryptsetup` engines) and
`AF_BLUETOOTH` worked before and now fail. `AF_PACKET` already failed (EPERM) and
now fails with EAFNOSUPPORT.

The filter also closes the other ways to reach those families:

- **io_uring** (`io_uring_setup`, `io_uring_enter`, `io_uring_register`) returns
  `ENOSYS`, because `IORING_OP_SOCKET` would create sockets without `socket(2)`.
  The application sees `ENOSYS` from `io_uring_setup` and falls back: libuv
  does so on any setup error, and liburing callers can fall back on the error.
- **32-bit and x32 binaries are unsupported.** The filter checks the audit
  architecture first, so an i386 or arm32 payload (including the `int 0x80`
  entry and its `socketcall(2)` path) and an x32-ABI syscall are killed with
  `SIGSYS`: `sbx run` exits 159 (128+31). Run 64-bit binaries only.

**Syscall deny-list.** A conservative set of syscalls fails with
`EPERM` (errno 1, the answer Docker's default profile gives): the kernel keyring
(`keyctl`, `add_key`, `request_key`), `bpf`, `perf_event_open`, `userfaultfd`,
`kexec_load`, `kexec_file_load`, kernel modules (`init_module`, `finit_module`,
`delete_module`), `open_by_handle_at`, the mount APIs (`mount`, `umount2`,
`pivot_root`, `open_tree`, `open_tree_attr`, `move_mount`, `fsopen`, `fsconfig`,
`fsmount`, `fspick`, `mount_setattr`), `quotactl`, `quotactl_fd`, `syslog`,
`swapon`, `swapoff`, `reboot`, `acct` and, on x86_64, `iopl`, `ioperm` and
`uselib`. `personality(2)` accepts only Docker's personas
(`PER_LINUX`, `PER_LINUX32`, `UNAME26` and the query); `ADDR_NO_RANDOMIZE`
fails, so `setarch -R` fails, gdb warns that it cannot disable address
randomization (`set disable-randomization off` silences it), and lldb cannot
launch a process until `settings set target.disable-aslr false` is set. A payload started with a non-default personality (for example
`sbx run` itself launched under `setarch -R`) cannot write that personality back.
Behaviour changes: `perf`, `rr`, `bpftool`, `bpftrace`, `dmesg` and `keyctl` fail
inside the sandbox, and tools that cache credentials in the kernel keyring
(some Kerberos and `ecryptfs` setups) fall back or fail. `ptrace` stays allowed,
so `gdb` and `strace` work on processes inside the sandbox.

Netlink sockets are allowed for every protocol (they live in the sandbox's own
network namespace). Every syscall not named above is allowed: this is a
deny-list, not a syscall allow-list. If bwrap cannot install the filter, the payload never
starts and `run` reports bwrap's own failure (rc 1, like any other bwrap setup
failure), not 125. `run` refuses with rc 125 only when sbx itself cannot prepare
the filter, for example on an architecture without a program (sbx ships
x86_64 and aarch64 only). `sbx check` reports the `seccomp` item as FAIL in both
cases. The integration
suite (`tests/sandbox_run.rs`, scenarios `seccomp-*`) and the CI musl smoke pin
these results.

**Landlock layer.** `--landlock` adds a Linux Landlock ruleset on top
of the bwrap sandbox. It is off by default, and with `--landlock off` the bwrap
command is the same as before. The mode is one of:

- `best-effort`: apply the rules the kernel supports. A kernel without Landlock,
  or with an older ABI, runs with the subset it has, silently.
- `require`: apply the full set or refuse. The set needs Landlock ABI 6 (Linux
  6.12 or later). On an older kernel `run` exits 125 before it starts anything,
  with `sbx run: landlock require: …` on stderr.

The rules follow the bwrap mount list. Read-only binds, the infra `/etc` set and
the generated files can be read and executed. Read-write binds, the session
`work`, `home` and `tmp` leaves, `/proc` and `/dev` can be written. The root
directory can be listed, but nothing can be created in it. `--landlock-bind-tcp PORT`
(repeatable; `0` is the kernel's ephemeral range) allows a TCP bind on that port.
Without a port, binds are denied. The layer also stops the payload from signalling
processes outside its domain, including bwrap's pid 1 (signal scope, ABI 6).

The layer is a second check on top of the mounts and the network namespace. It
does not restrict `connect(2)`: egress stays with the network namespace and the
proxies. It also does not handle abstract-socket scope or `RESOLVE_UNIX`
(see [threat model](threat-model.md), R6). The shim is sbx's own executable,
opened by `run` and exec'd inside the sandbox through `/proc/self/fd`. A
dynamically linked sbx build needs its shared libraries visible inside the sandbox
when `--landlock` is on. The static musl release does not. This is not checked
before the run.

Three limits of the layer that operators hit in practice:

- **Deny masks and new directories.** A `deny` entry is a tmpfs over the path and
  gets no Landlock rule of its own. Under a read-only mount, or outside every
  mount, the masked directory is therefore not writable (`EACCES`). The same holds
  for intermediate directories that bwrap creates on the root tmpfs: they are
  reached only through the root's list-only rule, so they take no entries.
- **ABI 1 (Linux 5.13 to 5.18).** `LANDLOCK_ACCESS_FS_REFER` is an ABI 2 right and
  is not handled there, so with `best-effort` on an ABI 1 kernel a rename or hard
  link across directories fails with `EXDEV`, even inside `/work`. The kernel does
  this for any ruleset without REFER, and `sbx` does not work around it.
- **Shim failures are not silent.** The shim writes its reason to a status pipe
  before it exits 125, and `run` reports it as `failed` (exit-code table above).
  `best-effort` fails closed when the kernel reports the ruleset as not enforced
  while the host has Landlock (for example an outer seccomp profile refuses
  `landlock_*`), instead of running the payload unrestricted.

**Requirements.** Linux ≥ 5.3 (pidfd), bubblewrap ≥ 0.8 (`SBX_BWRAP` overrides
discovery), and unprivileged user namespaces. Run `sbx check` to see what this
host provides and what to fix ([Host check](host-check.md)). The integration suite
(`tests/sandbox_run.rs`) runs every scenario; on hosts without bwrap or userns
it prints SKIP for the sandboxed scenarios.

**Startup overhead.** Measured with
`hyperfine -N --warmup 10 --runs 100` on the release static-musl build (static-pie,
as shipped), from a native Linux filesystem, with a user-space bubblewrap 0.9.0
(`SBX_BWRAP`), the policy `ro ["/usr"]`, transparent mode, empty allow list:

| command | median | p90 |
|---|---|---|
| `/usr/bin/bash -c true` | 1.50 ms | 1.76 ms |
| `sbx run … -- /usr/bin/bash -c true` | 11.15 ms | 12.01 ms |

Overhead ≈ 9.7 ms, under the 25 ms target. The socket-family seccomp filter was re-measured with the same method on the same host, against a build without it: mean 11.2 ms versus 10.8 ms (+0.4 ms, within the run-to-run spread of ±0.6–0.8 ms). Measure from a native filesystem:
on WSL2 the Windows drive (`/mnt/c`, a 9p mount without page caching) adds
about 14 ms to every exec of the binary (the same build measured there:
34–37 ms median). A trivial static-pie binary starts in 0.4 ms, and the sbx
binary starts in 0.6 ms on either PIE or non-PIE builds, so the position-independent
build is not the cost. CI runs on ext4 and reports the number on every run
(report-only, with a warning at ≥ 25 ms).

## Persistent sessions

`sbx run --keep-alive` starts a session. The command after `--` is its
resident, and a holder process stays alive with the session's namespaces, proxies
and audit writer, so later commands can join it. `sbx attach` runs a command in a
running session, and `sbx stop` ends it. Use this when a process from one call
(a dev server, say) must stay reachable from the next. No daemon is needed.

```
sbx run --keep-alive --policy P --session-dir S -- npm run dev   # returns once the session is up
sbx attach --policy P --session-dir S -- curl -s http://127.0.0.1:3000/
sbx stop --session-dir S
```

- **Opt in.** Plain `sbx run` is unchanged. `--keep-alive` is the only way to
  create a session. `sbx check` reports whether the host can hold and join a
  session (the `keep-alive` item, report only: it never changes the exit code).
- **Same policy.** Attach refuses a policy that is not byte-identical to the
  session's policy (rc 125, the reason on stderr). Nothing runs in that case.
- **Each call is a sandbox.** Every attached call gets its own bwrap, with its
  own pid namespace, mounts and seccomp filter, built as for `sbx run`. Calls
  and the resident share the session's network namespace, its localhost ports
  and its abstract unix sockets (their namespace is the network namespace). That
  sharing is what makes a dev server reachable, and it is a documented exception
  to isolation (S19, R31).
- **Landlock.** `run --keep-alive --landlock MODE [--landlock-bind-tcp PORT]…`
  sets the optional Landlock layer for the resident and for every attached call,
  through the same code path as `run --landlock`. The settings are the session's:
  the holder pins them at start, and an attach applies exactly those. `sbx attach`
  takes no `--landlock` flag (a usage error, rc 2), so an attach cannot weaken the
  layer. With `--keep-alive`, at most 256 `--landlock-bind-tcp` ports are
  accepted (rc 2 above that, before anything runs), because the session's
  settings travel in one control frame. With `--landlock require` (or `best-effort` on Linux 6.12+, Landlock
  ABI 6), the signal scope adds a second barrier behind the per-call pid namespace
  (S19): a call cannot signal the resident or another call. The holder can still
  end a call (on stop, or when the holder dies), because the
  holder and the attach sit outside every call's Landlock domain (S24).
- **Lifetime.** `--idle-timeout` (default 15m) ends the session after no call has
  run for that long. `--max-lifetime` (default 8h) ends it after that long
  regardless. `--max-lifetime` above 24h is a usage error (rc 2). The resident's
  exit ends the session too. Each end kills the resident and every running call,
  writes their exit rows, and removes the control socket. The clock starts when
  `run --keep-alive` starts, so setup counts toward `--max-lifetime`.
- **Policy timeout.** The resident is not bound by the policy's `limits.timeout`.
  Only the session lifetime (`--max-lifetime`) bounds it. Each attached call is
  bounded by its own `--timeout`, or by `limits.timeout` when that is absent.
- **Output.** The holder's output (the resident's stdout and stderr) goes to
  `S/holder.log`, not to the caller, and it is bounded by `limits.output_bytes`.
  Attached calls print to the caller as in `sbx run`.
- **Death.** If the holder is killed, the resident and every attached call die
  too (S20). A later `sbx run --keep-alive` on the same directory starts a new
  session.
- **Transparent mode only.** `run --keep-alive` refuses to start a session whose
  policy is not `transparent` (rc 125, before anything runs). It also refuses a
  host that falls back to explicit mode, because then no nftables rules exist for
  an attach to join. Attach keeps its own refusal for a session in that state.
- **Control socket.** `sbx.ctl` lives in the session directory and is reachable
  only by the same uid on the host. The sandbox cannot reach it: the session root
  is not bound (only `work`, `home`, `tmp` and the `etc` files are), and a policy
  path that is or contains the session directory is refused, lexically by the
  launch builder and through a symlink by the pre-launch guard, for `run` and for
  every attach call (R35, closed). A same-uid
  client can hold the control loop for up to 2 s per connection, in batches of
  8 connections per wake (R34). Each connection has one 2 s deadline for its
  request and its reply.
- **Audit.** With `--audit`, the session writes one file. Each call's exit row
  carries `call_id`, and the resident's exit row has `call_id` 0. Proxy and DNS
  rows carry no `call_id` (R30). The `dns` rate limit covers the whole session,
  so only the resident's exit row carries `dns_suppressed`.
- **Resource limits.** The policy's `limits` RLIMITs apply to every attached
  call as they apply to the resident.

**Exit codes**

| command | rc | meaning |
|---|---|---|
| `run --keep-alive` | 0 | the session is up (the holder keeps running) |
| `run --keep-alive` | 125 | the session could not start; the reason is on stderr |
| `run --keep-alive`, `attach` | 2 | usage error (for example `--max-lifetime` above 24h, or more than 256 `--landlock-bind-tcp` ports with `--keep-alive`) |
| `attach` | the call's own rc | as in `sbx run`: 124 on `--timeout`, 128+N on a signal |
| `attach` | 125 | refused or failed: no session, a different policy, an explicit-mode session, or the holder exited |
| `stop` | 0 | the session is stopped, or nothing was running |
| `stop` | 125 | the holder refused the stop or could not be reached |

## Garbage collection

`sbx gc --older-than D [--dry-run] ROOT` removes the session directories under
`ROOT` that have been idle for longer than `D`. It is the only command that
deletes sessions, so it is conservative by design.

- **What counts as a session.** An immediate child of `ROOT` that is a real
  directory (never a symlink) owned by you, with no group or other write bit,
  that contains an `sbx.lock` regular file with one link. A directory without
  `sbx.lock` is not a session: it is skipped, and gc never creates the lock.
  A session directory must be readable and searchable by its owner: a session
  with mode `0000` or `0300` is reported (`cannot open`) and left in place.
- **Reserved names.** A session may not be named like a tombstone
  (`.sbx-gc.<pid>.<16 hex digits>`). `sbx run` refuses such a `--session-dir`
  with exit 125 (`has a name reserved for sbx gc tombstones`).
- **Age.** The directory mtime, read while gc holds the session's lock, with a
  clock taken at that moment. `run` touches the mtime at start and end, so a
  session that is running, or that ended recently, is young. A future mtime is
  kept.
- **What is never touched.** A locked (live) session; any symlink, at any
  level (symlinks are removed as links, never followed); entries owned by
  another user; anything across a mount point (see below).
- **Protect placeholders.** Before it removes a session, gc removes the
  `filesystem.protect` placeholders a crashed run of that session listed in
  `protect.list`: only empty directories with the placeholder mark (a 1970-01-01
  modification time) that no running sandbox holds.
- **Delete protocol.** gc takes the session's lock, renames the directory to
  `ROOT/.sbx-gc.<pid>.<nonce>` (a *tombstone*), empties it, unlinks the lock and
  removes the tombstone. Concurrent gc processes exclude each other with a
  `flock` on the directory itself, so a second gc skips an entry the first one
  is removing and reports it at most once. An interrupted gc leaves a
  tombstone; the next gc collects it regardless of its age. `run` checks, after
  it takes the lock, that the session it locked was not tombstoned meanwhile,
  and refuses (exit 125) if it was.
- **Mount points.** A bind mount, or a filesystem mounted inside a session, is
  not descended into. The session directory is moved to a tombstone and emptied
  up to the mount point; the mounted part and the rest of the tombstone stay
  where they are, and gc reports `mount point at "<path>"` and the tombstone
  path (`remainder left at`). Once the mount is gone, the next gc finishes the
  job. A session directory that is itself a mount point is left in place
  (`session directory is a mount point`). A bind-mounted file is reported with
  the same mount-point message, although it is not a directory.
- **ROOT rules.** ROOT must exist and be a directory. Its final component must
  not be a symlink. Symlinks in ancestor directories are followed, as with any
  path you type. A ROOT with a `..` component is refused (the reason is ``must not contain `..` ``). ROOT
  must be owned by you or by root, and if it is group- or world-writable it must
  have the sticky bit. `/` is always refused.
- **Output and exit codes.** One line per collected entry on stdout, in name
  order: `removed "<path>"`, or `would remove "<path>"` with `--dry-run`.
  Failures are on stderr as `sbx gc: "<path>": <reason>`. Exit `0`: every
  eligible session was handled (including "nothing to do"). Exit `1`: ROOT was
  refused, or a session failed (for example a group-writable session, which is
  left in place); gc continues with the other sessions and reports the failure
  at the end. Exit `2`: a usage error (for example `--older-than 0s`). A session
  that is in use, still young, or being removed by another gc is not a failure
  and prints nothing.
- **Messages for hoisted subtrees.** To keep the number of open directories
  bounded, the walker can move a deep subdirectory up to the top of the
  session under a name `.sbx-gc-hoist.<N>`. A failure inside such a subtree is
  reported with that name in its path.
- **`--dry-run`.** It briefly takes each candidate's lock to check that the
  session is free, then releases it. A `run` that starts in that instant fails
  with `session directory is in use` (exit 125) and can be retried. It only
  checks what is checkable before removing: it cannot predict a failure inside
  the tree, such as a mount point, an entry owned by another user, or a
  directory that cannot be read (EACCES) and cannot be repaired. Those show up
  in a real run.
- **Limitations.**
  - NFS `.nfsXXXX` silly-rename files and flock semantics on NFS and 9p are
    not handled.
  - A btrfs subvolume has a different `st_dev` and is refused as a mount point.
  - On kernels older than 5.8 the mount id comes from `name_to_handle_at`
    instead of `statx`. If ROOT's filesystem does not support file handles
    (procfs, and overlayfs on some older kernels when it is not exported),
    the whole ROOT is refused with `cannot stat` and nothing is removed (fail
    closed). A session on such a filesystem inside a handle-capable ROOT is
    reported as `cannot stat` and left in place. The `MOUNT_ROOT` attribute is
    also unavailable there, so the mount-id comparison is the only check.
  - A process running as your user that writes into a session while gc empties
    it can make gc fail (`could not empty the directory after N passes`); the
    tombstone is left for the next gc.

## How a run works

`sbx run` re-executes itself as the internal `sbx __init` helper. `__init` unshares a user and a
network namespace, brings the sandbox loopback up as `10.255.255.1` with a default route, disables
IPv6, and binds three listeners: the transparent proxy (`127.0.0.1:15001/tcp`), the explicit
proxy (`127.0.0.1:3128/tcp`) and the DNS resolver (`127.0.0.1:53/udp`). It loads the nftables ruleset (TCP to the
transparent proxy, UDP 53 to the resolver, everything else dropped) and verifies it by dumping it
back. Then it hands the listener sockets to `sbx run` over a unix socketpair (`SCM_RIGHTS`), waits for
`sbx run`'s go byte (sent once the proxies and the resolver are serving), and then execs
unmodified `bwrap` with the policy's mounts, a cleared environment (the policy's
`env` plus the variables sbx sets), pid, ipc, uts and user isolation, `--disable-userns`, a generated `/etc` and the seccomp
filter. A setup failure is reported as `sbx __init: <stage>: <reason>`, and the payload never
starts.

- **DNS.** The resolver answers A queries for allow-listed names with a per-run address from
  `198.18.0.0/15` (the fake IP) and maps it back to the name for the proxy. Other query types for an
  allowed name (AAAA included) get an empty answer, a name outside the allow list gets NXDOMAIN
  for every type, nothing is forwarded upstream, and DNS over TCP is not served.
- **Proxy.** The transparent proxy recovers the dialed fake IP (`SO_ORIGINAL_DST`), maps it to the
  name, and checks the first bytes: the TLS `ClientHello` SNI on port 443 (ECH denied) and the HTTP
  request line and `Host` on port 80. An allowed name is resolved and dialed by sbx under the
  resolved-address guard, which checks every resolved address and the connected peer again. The
  buffered bytes are then replayed and the connection is relayed, with the validated name binding
  enforced for every request on a connection: each HTTP/1 request head is inspected before any of
  that request's bytes are forwarded (`Host`, target, framing and `Connection` tokens). Bodies are
  framed and streamed as they are validated: a framing error inside a body truncates it and tears
  the connection down, so the body's earlier chunks may already have been forwarded. Bodyless
  HTTP/1.1 requests keep the connection alive, while a request with a body, `Connection: close`,
  `Upgrade` or HTTP/1.0 is the last one forwarded, and nothing after it reaches the server: a
  client that writes again after its last request (an upgrade included) is torn down with a
  `relay torn down` deny row. Explicit forward is always one request per connection. On 443 a
  second `ClientHello` (the post-HRR retry shape) tears the connection down. Every connection
  gets one audit decision. An idle relay closes after `--relay-idle-timeout` (default `300s`).
- **TLS.** The default build never terminates TLS. The opt-in build feature is described in
  [TLS termination](tls-termination.md).
