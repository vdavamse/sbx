# sbx

Run untrusted commands — AI-agent tool calls, user-submitted scripts, CI
steps — inside a locked-down Linux sandbox, without host privileges.

`sbx` is a single static Rust binary and a CLI: no daemon, no API server.
Each `sbx run` invocation builds a fresh sandbox (mount/PID/network/user
namespaces via unmodified `bwrap`, plus an nftables egress policy inside a
private network namespace), executes the command under a JSON policy with a
timeout and an audit trail, and tears everything down on exit.

## Quick start

You need Linux 5.3 or newer with unprivileged user namespaces, bubblewrap 0.8
or newer, and Rust 1.85 or newer (via rustup) to build. No release has been tagged
yet, so build from source (x86_64 shown; for aarch64 see
[docs/building.md](docs/building.md)):

```sh
sudo apt-get install bubblewrap          # or point SBX_BWRAP at a bwrap binary
git clone https://github.com/vdavamse/sbx && cd sbx
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl
sudo install target/x86_64-unknown-linux-musl/release/sbx /usr/local/bin/
```

Write a policy. This one lets the sandbox read `/usr`, write one project
directory, and reach PyPI over HTTPS. sbx always adds a few things of its own:
the TLS roots and a small generated `/etc`, `/proc`, `/dev`, and a private
`/work`, `/root` and `/tmp` in the session directory.

```json
{
  "version": 1,
  "filesystem": { "ro": ["/usr"], "rw": ["/home/me/project"], "deny": [] },
  "network": { "mode": "transparent", "allow": ["pypi.org", "files.pythonhosted.org"], "ports": [443] },
  "env": { "pass": [], "set": {} },
  "limits": { "timeout": "120s", "output_bytes": 10485760 }
}
```

Save it as `p.json` (with your own project path), then check the host and the
policy:

```
$ sbx check
sbx 0.1.0 host check (kernel 6.8.0-1-generic)

  ok    userns      unprivileged user + network namespaces work
  ...
  ok    bwrap       bubblewrap 0.9.0 at /usr/bin/bwrap
  ...
network mode: transparent (policies with network mode transparent, explicit or none can run)

$ sbx check --policy p.json --host     # the host report again, then the policy items
...
policy p.json (requires transparent):
  ok    network-mode  ...
  ...
policy: can run on this host
```

Run a command. Everything after `--` is the command, verbatim:

```
$ sbx run --policy p.json --session-dir ~/.cache/sbx/demo --cwd /home/me/project \
    -- pip install --target deps requests
Collecting requests
...
Successfully installed certifi-… charset_normalizer-… idna-… requests-… urllib3-…
```

The packages land in `/home/me/project/deps` on the host. (`--target` is there
because `/usr` is read-only in the sandbox, and Debian and Ubuntu refuse a
system-wide `pip install` anyway.) A name outside the allow list does not
resolve, and `--audit` records why:

```
$ sbx run --policy p.json --session-dir ~/.cache/sbx/demo --audit audit.jsonl \
    -- curl -sS https://example.com
curl: (6) Could not resolve host: example.com
$ head -1 audit.jsonl
{"ts":"…","event":"dns","host":"example.com",…,"reason":"example.com is not in the policy allow list",…,"verdict":"denied","rcode":3,…}
```

`sbx run` exits with the command's own status (6 here). Its own failures use
124 (timeout) and 125 (an sbx failure); the full table is in
[docs/usage.md](docs/usage.md#running-commands).

## How it works

`sbx run` starts a private user and network namespace and loads a small
nftables ruleset there: TCP goes to an in-process proxy, DNS to a fake-IP
resolver, and everything else is dropped. It then launches unmodified `bwrap`
with the policy's mounts, a cleared environment, no capabilities and user
namespaces disabled inside the sandbox. The resolver answers only allow-listed
names. The proxy checks the TLS SNI (port 443) or the HTTP `Host` (port 80)
against the allow list, dials the real host itself, and passes TLS through
untouched. With `--audit`, DNS answers, connections and the exit status are
written to a JSON Lines log.

The details are in [docs/usage.md](docs/usage.md#how-a-run-works). What this
protects against, and what it does not, is in the
[threat model](docs/threat-model.md).

## CLI

```
sbx run --policy policy.json --session-dir DIR [--cwd PATH]
        [--timeout DURATION] [--audit FILE] [--max-connections N]
        [--landlock off|best-effort|require] [--landlock-bind-tcp PORT]...
        -- COMMAND [ARGS...]
sbx run --keep-alive --policy policy.json --session-dir DIR
        [--idle-timeout DURATION] [--max-lifetime DURATION]
        [--audit FILE] -- COMMAND [ARGS...]
sbx attach --policy policy.json --session-dir DIR [--cwd PATH]
        [--timeout DURATION] -- COMMAND [ARGS...]
sbx stop --session-dir DIR
sbx check [--json]
sbx check --conformance [--network] [--only ID|GROUP,...] [--list] [--json]
sbx check --policy policy.json --host [--json]
sbx check --policy policy.json
sbx check --print-schema
sbx gc --older-than 7d [--dry-run] ROOT
```

Durations are human format (`500ms`, `90s`, `2h`, `7d`) and must be
greater than zero — a zero `--older-than` cutoff would match every session,
and a zero `--timeout` is ambiguous. `--timeout` defaults to the policy's
`limits.timeout`, and the effective timeout is the smaller of the two (the
CLI value can shorten the policy limit, never extend it).
Everything after `--` in `sbx run` is the command, verbatim, including
hyphenated arguments.

`check` with no policy prints the [host report](docs/host-check.md). `check --policy`
validates a policy file (silently, and without probing the host; exit `1` with
`sbx check: <reason>` on failure); add `--host` to also check the policy against
this host. `check --print-schema` prints the policy JSON Schema (draft 2020-12)
to stdout. `--print-schema` cannot be combined with `--policy`, `--host` or
`--json`.

## Policy

A policy is a JSON file, schema version 1 (`sbx check --print-schema`; examples
in [`examples/`](examples/)):

- `filesystem`: `ro` and `rw` paths are bound at the same path inside the
  sandbox; a `deny` entry hides its path with an empty tmpfs.
- `network`: `mode` is `transparent` (the command connects normally and the
  proxy filters it), `explicit` (the command uses sbx's HTTP proxy through the
  proxy variables sbx sets; direct connections never leave the sandbox) or
  `none` (no network access). `allow` lists the reachable names, and `ports`
  the allowed ports (443 and 80 are inspected; any other is denied).
- `env`: `pass` names the caller's variables to inherit; `set` adds fixed
  values. Everything else is cleared, except `HOME`, `PATH` and `TMPDIR`
  (which `pass` or `set` can override) and the proxy and CA variables sbx sets itself.
- `limits`: `timeout` and `output_bytes`, plus optional per-process limits and
  whole-sandbox cgroup limits (`memory_bytes`, `pids`).

The run-time rules for each field are in [docs/usage.md](docs/usage.md#running-commands).

### Policy allow list

`network.allow` lists the names the sandbox may reach. Each entry is a domain
name with no scheme, port, path, wildcard or IP literal. A plain entry allows
the name and every subdomain of it. An entry prefixed with `=` allows that
exact host only, not its subdomains:

```json
"network": {
  "mode": "transparent",
  "allow": ["github.com", "=api.example.com"],
  "ports": [443, 80]
}
```

With that policy, `github.com`, `api.github.com` and any other subdomain of
`github.com` are allowed. `api.example.com` is allowed. `example.com`,
`v2.api.example.com` and `evilgithub.com` are denied. Case and IDNA spelling
normalize the same way for both forms, so `=EXAMPLE.com` is the entry
`=example.com`. A trailing root dot is rejected in a policy, as it is for a
plain entry.

Prefer `=name` when one host is enough. A broad entry also allows every
subdomain, including user-content subdomains on a shared platform (residual R3
in the [threat model](docs/threat-model.md)). `sbx check --policy` rejects `=`
alone, `==name`, `=*.name`, `= name` and `=1.2.3.4` with the same messages as
any other invalid domain, and any entry whose name normalises to start with `=`
(for example a fullwidth `＝name`, which is not read as the marker).

## Host check

`sbx check` reports what this host can run, and which fix would unlock more. It
runs the same setup stages `sbx run` runs, in a throwaway namespace, takes about
20 ms and changes nothing on the host. Each failing item carries a `fix:` line.
`sbx check --policy P --host` also checks a policy against the host. The items,
network modes, JSON output, exit codes and the full fix table are in
[docs/host-check.md](docs/host-check.md).

## Conformance

`sbx check --conformance` runs every security guarantee as an executable check:
81 checks in nine groups, the same code that `cargo test --test conformance`
runs in CI. The offline tiers need no root and never touch the real network;
`--network` adds real `curl`, `git`, `pip` and `npm` checks. Groups, tiers and
exit codes: [docs/conformance.md](docs/conformance.md).

## Persistent sessions

`sbx run --keep-alive` starts a session whose command stays running (a dev
server, say), `sbx attach` runs further commands in it, and `sbx stop` ends it.
`sbx gc` removes idle session directories. See
[docs/usage.md](docs/usage.md#persistent-sessions).

## Kubernetes

[docs/kubernetes.md](docs/kubernetes.md) shows how to run sbx in a pod with its
own user namespace (`hostUsers: false`), without privileged mode or added
capabilities. The example manifests, image and kind config are in
[`examples/kubernetes/`](examples/kubernetes/).

## TLS termination

The default build passes TLS through. An opt-in build feature terminates TLS
for named hosts to enforce URL-path rules: see [docs/tls-termination.md](docs/tls-termination.md).

## Non-goals

- **Not a container runtime.** No images, registries, OCI specs, or
  long-lived "containers" — one command, one sandbox, one lifetime.
- **Linux only.** The sandbox is built from Linux kernel features
  (namespaces, nftables); there are no macOS or Windows plans.
- **No eBPF cgroup firewall.** Egress filtering uses nftables inside the
  sandbox's network namespace, which works unprivileged. Why: see the
  [threat model](docs/threat-model.md#81-why-not-an-ebpf-cgroup-firewall).
- **No TLS interception in the default build.** The default binary filters on
  SNI and IP and installs no CA in the sandbox. Why, and the domain-fronting
  residual this leaves: see the
  [threat model](docs/threat-model.md#84-why-tls-passthrough-in-v1).

## Documentation

- [docs/usage.md](docs/usage.md): `sbx run` in full (exit codes, filesystem
  rules, limits, audit log, network, seccomp, Landlock), persistent sessions,
  garbage collection, and how a run works.
- [docs/host-check.md](docs/host-check.md): the host report and its fixes.
- [docs/conformance.md](docs/conformance.md): the conformance suite.
- [docs/kubernetes.md](docs/kubernetes.md): running sbx in a pod.
- [docs/tls-termination.md](docs/tls-termination.md): the opt-in TLS termination.
- [docs/building.md](docs/building.md): building, MSRV, static binaries,
  releases and development.
- [docs/threat-model.md](docs/threat-model.md): guarantees and residual risks.

## Security

Sandbox escapes and other vulnerabilities: please report them privately —
see [SECURITY.md](SECURITY.md). Threat model and security guarantees, with the
residual risks: [docs/threat-model.md](docs/threat-model.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
