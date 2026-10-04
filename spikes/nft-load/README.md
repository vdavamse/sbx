# nft-load spike (sbx issue #1)

Proof-of-concept for how `sbx-init` (issue #5) will load nftables rules:
a **fully static musl Rust binary** that runs **unprivileged**, creates a
**user + net namespace**, configures `lo` with a sandbox IP and default route,
loads a fixed nftables ruleset **atomically in a single netlink batch**,
**fails closed** on any error, and **self-tests** the result with real traffic.

Everything happens inside a private netns owned by the process; when the
process exits, the sandbox (interfaces, addresses, routes, rules) is destroyed
by the kernel. Nothing outside the namespace is touched.

Full write-up (chosen option, sizes, maintenance status, rejected candidates,
empirical kernel quirks): **[FINDINGS.md](FINDINGS.md)**.

## Layout

```
spikes/nft-load/
├── Cargo.toml / Cargo.lock    # exact pins (=0.3.5), committed lockfile
├── src/
│   ├── main.rs                # CLI, orchestration, exit codes
│   ├── consts.rs              # uAPI constants (SO_ORIGINAL_DST etc.), config
│   ├── netns.rs               # unshare + maps + lo/addr/route + read-back
│   ├── rules.rs               # atomic batch, hand-encoded redir, dump verify
│   ├── listeners.rs           # TCP/UDP listeners + canaries (server-speaks-first)
│   ├── selftest.rs            # t1..t6 traffic self-tests
│   └── report.rs              # PASS/FAIL table + --json
├── rules/
│   ├── reference.nft          # human-readable reference ruleset (nft syntax)
│   └── ground-truth.md        # byte-exact netlink encoding (captured dumps)
└── scripts/
    ├── local-test.sh          # full local gate (build/static/size/10x/break-rules/oracle)
    └── nldump.py              # raw NETLINK_NETFILTER dump tool (text/JSON)
```

Standalone Cargo project on purpose — the repo has no workspace yet. Issue #2
must exclude `spikes/` from the future workspace
(`exclude = ["spikes/nft-load"]`).

## Build

Requires: Rust stable with the musl target. No C toolchain beyond what Rust
ships (pure-Rust deps link fine against Rust's self-contained musl startup
objects with plain `gcc`/`cc`).

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
# -> target/x86_64-unknown-linux-musl/release/nft-load-spike  (~665 KiB, static)
```

## Run

```sh
./target/x86_64-unknown-linux-musl/release/nft-load-spike            # full run
./target/x86_64-unknown-linux-musl/release/nft-load-spike --json     # machine-readable
./target/x86_64-unknown-linux-musl/release/nft-load-spike --break-rules   # fail-closed proof
bash scripts/local-test.sh                                           # full local gate
```

Flags:

| Flag | Effect |
|---|---|
| `--break-rules` | Load a deliberately broken batch (rule → nonexistent chain); require kernel rejection + atomic rollback; prints `FAIL-CLOSED-VERIFIED:` on stderr; exit 3 when verified |
| `--json` | Single JSON report object on stdout (`ok`, `exit_code`, `tests[]`, `binary_bytes`, `genid`, `attempts`) |
| `--skip-selftests` | Skip traffic tests (netns + rule load + dump verify still run) |
| `--dump-rules` | Print the decoded post-load netlink dump (stderr) |
| `--keep-alive N` | After the report print `READY pid=<pid>` on stderr and sleep N s (lets an observer enter the netns, e.g. `sudo nsenter -t <pid> -n nft list ruleset`) |
| `--verbose` | Extra status/diagnostic lines on stderr |
| `--help` | Usage |

Status/diagnostic lines go to **stderr**; the PASS/FAIL table + `SUMMARY` (or
the JSON object) go to **stdout**.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | everything passed |
| 1 | usage error / environment (unshare EPERM → AppArmor hint, see below) |
| 2 | netns setup or read-back verification failed |
| 3 | nftables batch load failed (**fail closed**) — also the *verified* `--break-rules` outcome |
| 4 | post-load dump verification mismatch |
| 5 | self-test failure |
| 6 | listener bind failure |
| 7 | broken batch unexpectedly accepted (`--break-rules`) |

## Safety notes

- The binary never needs root and never modifies the host: `unshare` creates a
  fresh user+net namespace; all interfaces/addresses/routes/rules live and die
  with it (process death destroys the sandbox).
- `10.255.255.1` is only meaningful inside the private netns; `203.0.113.7`
  is TEST-NET-3 (RFC 5737), never routed on the Internet.
- On Ubuntu 24.04+ / GitHub runners, AppArmor may block unprivileged user
  namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`) — the binary
  detects EPERM from `unshare` and prints a hint (exit 1). The CI workflow
  flips the sysctl.
- If your environment blocks userns entirely, there is no fallback by design:
  the spike must fail closed, not silently run without the sandbox.

## Cross-checking the loaded ruleset by hand

With `--keep-alive`, an observer can dump the live ruleset using the `nft` CLI
as an independent oracle:

```sh
./nft-load-spike --keep-alive 60 2>err.log &
PID=$(sed -n 's/.*READY pid=\([0-9]*\).*/\1/p' err.log)
sudo nsenter -t "$PID" -n nft list ruleset     # needs root (CI does this)
```

Locally without sudo, `nsenter -U -n` fails at nsenter's own `setgroups()`
call (the sandbox userns has `setgroups=deny`, permanently). Use
`scripts/local-test.sh` instead — it joins the namespaces with a tiny
python3 `os.setns` helper and greps the `nft list ruleset` output.
