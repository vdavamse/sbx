# sbx vs srt benchmark

A reproducible comparison of sbx with Anthropic's
[sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (`srt`) on
Linux. The write-up is [docs/comparison-srt.md](../../docs/comparison-srt.md).
The run it reports is in [results/2026-11-08-wsl2/](results/2026-11-08-wsl2/results.md).

## Run it

```sh
bench/srt-compare/setup.sh            # fetch sbx 0.1.0 and srt 0.0.81 (no root)
bench/srt-compare/run.sh OUT          # about 3 minutes; writes OUT/results.md
```

`setup.sh` downloads the sbx release tarball and checks it against its
`.sha256`. It installs `@anthropic-ai/sandbox-runtime` at a pinned version
with npm into its own prefix, outside every writable path. srt's README warns
that a copy inside a writable path can be rewritten by a sandboxed command.
srt's Linux dependencies (`socat`, `ripgrep`) come from the host when present.
Otherwise they are unpacked from the Debian/Ubuntu packages with
`apt-get download`, which needs no root. Set `SBX_VERSION` or `SRT_VERSION` to
compare other releases. Tools go to `${TMPDIR:-/tmp}/sbx-srt-tools` by
default; keep them on a native filesystem (on WSL2 not under `/mnt/c`).

`run.sh` needs bash, curl, git, ssh, `/usr/bin/python3`, node >= 22.12,
bubblewrap, unprivileged user namespaces, and outbound HTTPS to example.com,
www.google.com, www.cloudflare.com and nip.io. hyperfine is optional (for the
startup numbers). `sbx check` must report network mode `transparent`.

## What it does

- **Policies.** [policies/](policies/) holds one template per tool. The
  runner fills in the run's paths and copies the result to OUT. Both allow only `example.com` on port 443, plus three
  `nip.io` names for the rebinding scenarios. Both make `/usr` read-only and
  one directory (`rw`, a git checkout) writable, and deny everything else.
  The srt policy adds what srt needs to express the same rules (see
  [Policy equivalence](../../docs/comparison-srt.md#policy-equivalence)).
- **Scenarios.** Each scenario is one bash script that runs unchanged inside
  both sandboxes (`sbx run … -- bash -c` and `srt -c`). Its exit status picks
  the outcome word. The evidence is the script's output plus what the tool
  logged: sbx's `--audit` rows, and srt's `--debug` proxy decisions.
  Filesystem writes are judged on the host: a write that succeeds inside but
  does not appear at the host path (sbx's `/tmp` is the session's own
  directory) counts as blocked.
- **Probes.** [probe.py](probe.py) makes raw socket, TLS, DNS, UDP and unix
  socket calls that ignore proxy variables.
- **Host fixtures.** The runner starts a listener on a random 127.0.0.1 port
  and on an abstract unix socket, a `sleep` decoy process, and two canary
  secrets in the environment. It removes them on exit, together with any
  canary file a sandbox managed to write (one is aimed at `$HOME`).
- **Ergonomics.** Exit codes for a normal exit, a signal, a timeout, SIGTERM to
  the tool, a bad policy, a missing bwrap and a missing command. Also output
  limits and persistent sessions.
- **Ops.** Startup latency (hyperfine, 20 runs of `true`) and install
  footprint.

## Outcome words

| word | meaning |
|---|---|
| `allowed` / `works` | the permitted action succeeded |
| `BROKEN` | a permitted baseline failed (the run is not valid) |
| `blocked` / `fails-closed` / `refused` | the action did not reach its target |
| `LEAKED` / `planted` | the action reached a target the policy denies, or wrote a file that runs later on the host |
| `passed-uninspected` | the bytes reached the allowed upstream, and the tool could not see the part that differed (the encrypted `Host`) |
| `dialed` | srt's proxy accepted the destination and dialed it (variants V1, V2) |

The results depend on the network at run time. example.com is served by
Cloudflare, which makes the fronting scenarios (N5) realistic. If that
changes, N5a may stop leaking under either tool for reasons unrelated to the
tool.
