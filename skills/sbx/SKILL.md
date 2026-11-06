---
name: sbx
description: Run commands, or a whole AI agent, inside the sbx Linux sandbox (bubblewrap plus an allow-listed egress proxy). Use when running untrusted or agent-generated shell commands with sbx, writing an sbx policy, wrapping an agent harness's bash tool with `sbx run`, or debugging why something inside an sbx sandbox cannot see a file, reach a host, or seems to hang.
---

# sbx

`sbx run --policy P --session-dir S -- CMD…` runs `CMD` in a fresh, unprivileged sandbox:
private mount, PID, user and network namespaces, a cleared environment, and egress only
to the names in the policy's allow list. Each run is one process tree with one lifetime.
There is no daemon. The full reference is [docs/usage.md](https://github.com/vdavamse/sbx/blob/main/docs/usage.md). This
skill covers what people get wrong.

Before relying on a host or a policy, run `sbx check --policy P --host`. Exit 0 means
the policy can run on this host. Exit 1 means it cannot: the report on stdout marks the
failing items, and the reasons are on stderr.

## What the sandbox sees

| Inside the sandbox | Comes from | Notes |
|---|---|---|
| each `filesystem.ro` / `filesystem.rw` path | the same host path | bound at the **same path**, read-only or writable |
| `/work` | `S/work` | writable; the default working directory |
| `/root` (`$HOME`) | `S/home` | writable; tool config, caches, history |
| `/tmp` (`$TMPDIR`) | `S/tmp` | writable, and persists with the session (not a fresh tmpfs) |
| `S` itself, `S/sbx.lock`, `S/sbx.ctl` | — | **not visible**; a policy path that is or contains `S` is refused (125) |
| `/bin`, `/sbin`, `/lib`, `/lib64` | symlinks to `usr/…` | usable only if `/usr` is bound (and skipped when a bind covers them) |
| `/etc` | generated | `passwd`, `group`, `hosts`, `resolv.conf`, plus `ssl`, `ca-certificates`, `alternatives`, `ld.so.cache`, `localtime`, `nsswitch.conf` from the host, plus any policy bind under `/etc` |
| `/proc`, `/dev` | fresh | |
| anything else on the host | — | does not exist; a `deny` entry is an empty tmpfs over its path |

- The command runs as uid 0 (`root`) inside, mapped to your own uid. Files written to
  `rw` paths are owned by you on the host.
- The environment is cleared except `HOME=/root`, `TMPDIR=/tmp`, a standard `PATH`,
  the names in `env.pass` that are set in the caller's environment, and `env.set`.
  sbx adds its own variables only in explicit mode (the proxy variables) and with the
  opt-in [TLS termination](https://github.com/vdavamse/sbx/blob/main/docs/tls-termination.md)
  build (`SSL_CERT_FILE` and the other CA bundle variables).
- To keep state between runs, reuse `S`: `/work`, `/root` and `/tmp` persist. A fresh
  `S` gives a clean sandbox.

## `--cwd` is a sandbox path

`--cwd C` only sets the working directory inside the sandbox. It mounts nothing and
grants no write access. `C` must be absolute (a relative one is refused: rc 125,
`cwd must be absolute`), and it must exist inside the sandbox: `/work`, a path under `/root`
or `/tmp`, or a path under a policy bind. Otherwise bwrap fails with
`bwrap: Can't chdir to C: No such file or directory` and **rc 1** (not 125). To work in a
host project, put the project in `filesystem.rw` (or `ro`) and pass the same path as
`--cwd`. Whether it is writable comes from the policy alone.

## Standard streams: no TTY

stdout and stderr are always pipes, and stdin is never a terminal. A bare
`sbx run … -- bash` reads its script from stdin with no prompt, so from a terminal it
looks hung. Give the command explicitly:

```sh
sbx run --policy P --session-dir S -- bash -c 'make test 2>&1 | tail -20'
printf '%s\n' 'cd /work' 'ls' | sbx run --policy P --session-dir S -- bash -s
```

Interactive TUIs (editors, `top`, agent TUIs) are not supported. Use a non-interactive
or headless mode.

## Exit codes

| rc | meaning |
|---|---|
| N | the command exited N |
| 124 | `--timeout` or `limits.timeout` elapsed; stderr `sbx run: timed out after …` |
| 125 | sbx itself failed or refused (policy, session, audit path, host); stderr `sbx run: <reason>` (`sbx attach: …` for attach) |
| 128+N | killed by signal N (137 = SIGKILL, for example the OOM killer) |
| 1 | also bwrap's own setup failure (`bwrap: …` on stderr), for example a bad `--cwd` |
| 2 | usage error (clap) |

A command can exit 124, 125 or 128+N by itself. Only the `outcome` of the audit `exit` row
(`exited`, `timeout`, `failed`, `signaled`, `terminated`) tells them apart. The full table
is in [docs/usage.md, Exit codes](https://github.com/vdavamse/sbx/blob/main/docs/usage.md#running-commands).

## Network

- `network.mode`: `transparent` (programs connect normally), `explicit` (sbx sets
  `HTTPS_PROXY` and the other proxy variables) or `none`.
- `network.allow`: `example.com` allows the name and its subdomains; `=api.example.com`
  allows that host only. `network.ports`: 443 (SNI-checked) and 80 (`Host`-checked).
  Any other port is denied.
- DNS is answered inside the sandbox. An allowed name gets a fake IP from `198.18.0.0/15`
  (A records only; AAAA is empty). Any other name gets **NXDOMAIN**, so a blocked host
  looks like `Could not resolve host`, not like a refused connection.
- `--audit A` writes JSON Lines: `dns`, `connect`, `deny`, `close` and a final `exit` row.
  A denied name shows as `"event":"dns","verdict":"denied","reason":"… is not in the
  policy allow list"`. Without `--audit` there is no log.
- `A` must not be inside `S` or any `ro` / `rw` path (rc 125), and it must be a regular
  file you own. Several runs may append to one file.

```sh
jq -c 'select(.verdict=="denied" or .verdict=="teardown") | {event,host,reason}' A  # what was blocked
tail -n 1 A | jq '{code,outcome,output_truncated}'              # how the run ended
```

## Sessions and limits

- One `sbx run` per session directory at a time. A second one fails with
  `session directory is in use` (125).
- `limits.output_bytes` caps stdout and stderr together. Past it the output is dropped,
  the command keeps running, and sbx prints `sbx run: output truncated at N bytes
  (limits.output_bytes)` as its last stderr line.
- `sbx run --keep-alive … -- SERVER` keeps a session up. `sbx attach --policy P
  --session-dir S -- CMD` runs more commands in it (same localhost), and
  `sbx stop --session-dir S` ends it. This needs `transparent` mode and the identical
  policy file. See [Persistent sessions](https://github.com/vdavamse/sbx/blob/main/docs/usage.md#persistent-sessions).
- `sbx gc --older-than 7d ROOT` deletes idle session directories under `ROOT`.

## Use cases

- Running an agent (Claude Code, a coding CLI) entirely inside the sandbox:
  [references/agent-in-sandbox.md](references/agent-in-sandbox.md).
- A harness that wraps its agent's bash tool so every tool call is an `sbx run`:
  [references/harness-bash-tool.md](references/harness-bash-tool.md), with tested
  wrappers in [examples/harness/](https://github.com/vdavamse/sbx/tree/main/examples/harness).
