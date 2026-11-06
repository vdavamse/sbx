# Wrapping a harness's bash tool with `sbx run`

The agent runs on the host, but each bash tool call it makes runs in a sandbox. This
is the pattern for harness engineers: the model's commands never touch the host
directly. Tested wrappers:
[`examples/harness/sbx_bash_tool.py`](https://github.com/vdavamse/sbx/blob/main/examples/harness/sbx_bash_tool.py)
(`subprocess.run`) and
[`examples/harness/sbx_bash_tool.ts`](https://github.com/vdavamse/sbx/blob/main/examples/harness/sbx_bash_tool.ts)
(`child_process.spawn`). Each has a `--selftest` that CI runs against a real sbx.

## One call

```sh
sbx run --policy P --session-dir S --cwd C --timeout T --audit A \
  -- bash -c "$CMD" </dev/null
```

- **`bash -c`** with the model's command as a single argument. sbx passes the argv
  verbatim: there is no outer shell, so no quoting layer is added or lost.
- **stdin.** Use `/dev/null` (or a pipe you control). There is no TTY, and a command
  that reads stdin would wait forever.
- **`--timeout T`.** Per call, at most the policy's `limits.timeout` (the smaller one
  wins).
- **`--audit A`.** `A` must be outside `S` and outside every policy path, or the run is
  refused (125). Use one file per session, so the rows after your call are your call's.

## Sessions: what persists and what does not

Use **one session directory per conversation (or per agent)**. Then `/work`, `/root`
and `/tmp` persist across tool calls, so files the model wrote in one call are there in
the next.

Shell state does **not** persist: every call is a new `bash`. A `cd`, an `export`, a
shell function, or a background job (`server &`) ends with the call, and the sandbox
kills every remaining process when the call ends. The harness has to carry the state:

- **cwd.** Track it yourself and pass `--cwd`. The wrappers set an `EXIT` trap that
  writes `$PWD` to `/tmp/.sbx-tool-cwd` (that is `S/tmp/.sbx-tool-cwd` on the host), so
  the cwd survives `exit N` and truncated output. The sandbox controls that file: read
  it without following symlinks, and accept only a short absolute path. `--cwd` must be
  absolute and must exist inside the sandbox. A missing one fails in bwrap
  (`bwrap: Can't chdir to …`, rc 1), so reset to `/work` when that happens.
- **env.** Keep a map of the variables you want and prepend `export K='v'` lines to the
  script. Secrets belong in `env.pass` in the policy instead (they come from the
  harness's own environment).
- **Long-lived processes** (a dev server, a database) need a persistent session.
  `sbx run --keep-alive --policy P --session-dir S -- npm run dev` starts it and returns
  rc 0 once it is up. Then each tool call is
  `sbx attach --policy P --session-dir S [--cwd C] [--timeout T] -- bash -c "$CMD"`,
  which shares the session's localhost. Run `sbx stop --session-dir S` when the
  conversation ends. The resident's output goes to `S/holder.log`. Keep-alive needs
  network mode `transparent` and the byte-identical policy file for every attach.
- **Attach is not a drop-in replacement for run.** `sbx attach` takes no `--audit`:
  every call's rows go to the file given to `run --keep-alive --audit`, and concurrent
  calls interleave their `exit` rows, which carry a `call_id`. Match a call's exit row
  by `call_id`, or classify it by rc and stderr alone. Attach's own lines start with
  `sbx attach: ` (for example `sbx attach: timed out after 1s`). The example wrappers
  only implement the `run` route.

## Concurrency

Only one `sbx run` can use a session directory at a time. A second one fails at once
with rc 125 and `sbx run: session directory is in use: "…"`. While a keep-alive session
holds `S`, plain `run` on it fails the same way, so use `attach`.

- Serialize the tool calls of one conversation (a lock or a queue per session). Both
  wrappers do this.
- Parallel tool calls need separate session directories. Note that they then do not
  see each other's `/work`. Alternatively, attach them all to one keep-alive session:
  attached calls can run concurrently.

## Mapping the result back to the model

| sbx result | tell the model |
|---|---|
| rc N, audit `outcome` `exited` | the command's output and `exit code N` |
| rc 124, `outcome` `timeout` | "timed out after T and was killed", plus the partial output |
| rc 125, `outcome` `failed` (stderr `sbx run: …`), or no `exit` row at all | a **sandbox/harness error**, not the command's failure: surface sbx's stderr line, and log it for the operator |
| `outcome` `terminated` (rc 129–143) | sbx itself got a signal (the harness is shutting down): a sandbox error |
| rc 1 with stderr `bwrap: …` | a sandbox setup error (usually a stale `--cwd`) |
| rc 128+N | killed by signal N; 137 is SIGKILL (for example out of memory) |
| stderr `sbx run: output truncated at N bytes (limits.output_bytes)` or audit `output_truncated: true` | the output is cut, so say so; truncation alone does not stop the command |

- Exit status alone is ambiguous, because a command may exit 124 or 125 itself. The
  audit `exit` row's `outcome` is authoritative, which is why the wrappers always pass
  `--audit` and read the rows appended during the call.
- Keep sbx's own stderr apart from the command's output. The wrappers run the command as
  `{ eval "$__sbx_cmd"; } 2>&1`, so the command's stdout and stderr reach sbx's stdout
  interleaved, and sbx's stderr carries mostly `sbx run: …` and `bwrap: …` lines. It is
  not a trusted channel: the command can still reach it (bash keeps the original stderr
  on a spare fd), so classify by the audit `outcome` first and use stderr only to
  explain. Skip `sbx run: notice: …` lines (a host in explicit-mode fallback prints one
  on every run).
- `limits.output_bytes` counts stdout and stderr together. Keep it modest (the model
  cannot use megabytes anyway), and tell the model when output was cut.

## Policy per task

Keep a few policies and pick one per task. Do not widen one policy for everything.

| task | `filesystem` | `network` |
|---|---|---|
| read-only investigation | `ro`: `/usr`, the repo | `none` |
| build and test | `ro`: `/usr`, toolchains; `rw`: the repo (or work in `/work`) | `none`, or `transparent` with only the registries |
| needs the internet | as above | `transparent`, a short `allow` list, `=host` entries where one host is enough |

Do not bind `/run`, `/var/run`, `/tmp/.X11-unix` or a home directory: a read-only bind
still lets the payload `connect` to sockets under it, such as `docker.sock` or an
ssh-agent. Do not share one `rw` tree between two policies running at the same time.
See [Filesystem policy](https://github.com/vdavamse/sbx/blob/main/docs/usage.md#running-commands).

## Start-up checks

At harness start-up, run `sbx check --policy P --host` for every policy you will use.
Fail fast unless it exits 0. Exit 1 means the policy is invalid, or this host cannot
run it, and the report says what to fix. This catches a missing bubblewrap, disabled
user namespaces, or a policy path that does not exist, before the model's first call.

## Cleanup

`sbx stop --session-dir S` for keep-alive sessions. `sbx gc --older-than 7d ROOT`
removes idle session directories under `ROOT` (one directory level, locked sessions are
skipped). Rotate or delete the audit files yourself: gc does not touch them.
