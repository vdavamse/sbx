# Security Policy

`sbx` is a sandbox for running untrusted code. Containment *is* the
product, so a security bug here is a product bug of the highest priority.

## Reporting a vulnerability

Please report vulnerabilities **privately** using GitHub's private
vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability** — this opens a draft GitHub Security
   Advisory that only the maintainers can see.

If private vulnerability reporting is not enabled yet, please open an issue
*without technical details* asking the maintainer to enable it (Settings →
Code security → Private vulnerability reporting), and the report will
continue in the private advisory thread.

Please **do not** file a public issue for a security report.

## What to include

- Steps to reproduce or a proof of concept (commands, policy file,
  environment, kernel version).
- The affected version or commit.
- Your assessment of the impact: what the sandbox failed to prevent.

## Scope

- **In scope — the sandbox failing its contract:** escaping the namespace,
  mount, or policy confinement; exfiltrating data past the egress policy;
  running past the timeout without being killed; gaps in the audit trail;
  vulnerabilities in `sbx` itself, its dependencies, or its unprivileged
  setup path (`sbx __init`).
- **In scope — socket families (issue #34):** the seccomp filter that bwrap
  installs allow-lists the socket families `sbx run` creates (`AF_UNIX`,
  `AF_INET`, `AF_INET6`, `AF_NETLINK`). Any way for a payload to create a socket
  of another family, or to reach one through an io_uring, x32 or i386 entry, is
  a sandbox escape in scope. Netlink protocol semantics and host-side pathname
  unix sockets exposed through the filesystem policy are not covered by the
  family filter (filesystem and netlink policy are separate concerns).
- **In scope — conformance (issue #13):** a `FAIL` from `sbx check --conformance`
  on a host where `sbx check` reports the needed network mode is a sandbox
  defect; attach the JSON report and the kept artifacts directory. `warn` rows
  (D05) describe policy hazards, not defects. The lab tier's upstreams are all
  local (`9.9.9.9` inside the lab's own network namespace); the network tier
  (`--network`) is the only part that reaches the real internet.
- **Out of scope — the product working as designed:** untrusted code
  misbehaving *within* the sandbox: writing inside its writable mounts, or
  talking to allow-listed destinations. Note: v1 enforces a wall-clock
  timeout but no CPU/memory/disk quotas; resource exhaustion affecting the
  host is a known limitation, not a reportable vulnerability. The sandbox
  contains the command; it does not make the command benign.

## Response

Reports are triaged best-effort by the maintainer. Expect an
acknowledgment in the advisory thread, and fixes to land on `main`.
Pre-1.0, `main` is the only supported version — there are no backport or
version-support commitments.
