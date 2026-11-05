# Running sbx in Kubernetes

This guide shows how to run `sbx` inside a Kubernetes pod without privileged mode and without
added capabilities. The pod runs in its own user namespace (`hostUsers: false`), and `sbx` builds
its sandboxes inside it. The example lives in [`examples/kubernetes/`](../examples/kubernetes/),
and the `kubernetes` CI job runs it on every pull request.

Read it together with the README sections [Host check](../README.md#host-check) and
[Conformance](../README.md#conformance) and with the [threat model](threat-model.md). Item names
such as `userns` and `netns-ipv6` are `sbx check` items; row names such as S7 and R5 are rows of
the threat model.

## What was tested, and what was not

Everything marked **observed** below was run in this environment on 2026-11-05:

| component | version |
|---|---|
| kind | v0.33.0 |
| node image | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` (Kubernetes v1.37.0, Debian 13 node, containerd 2.3.4, runc 1.4.3) |
| host | WSL2, kernel 6.18.54.1-microsoft-standard-WSL2, Docker 28.2.2, AppArmor built in but not enabled, no `kernel.apparmor_restrict_unprivileged_userns` sysctl |
| image | `debian:trixie-slim` (pinned by digest), bubblewrap `0.12.0-1~deb13u1`, sbx from the static musl build |

Not tested by sbx: nodes with AppArmor enabled (including Ubuntu 24.04 nodes with the userns
restriction), SELinux-enforcing nodes, CRI-O, GKE, EKS, AKS and GKE Autopilot. What this guide says
about them comes from vendor documentation (linked) or from the text `sbx check` prints, and is
labelled as such. The CI job runs on a GitHub-hosted Ubuntu runner, which has AppArmor; it records
the AppArmor results as report-only steps (see [CI](#ci)).

## Quick start (kind)

From the repository root:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
ctx=$(mktemp -d)
cp target/x86_64-unknown-linux-musl/release/sbx examples/default.json "$ctx"/
docker build -f examples/kubernetes/Dockerfile -t sbx-k8s-example:dev "$ctx"

kind create cluster --name sbx --config examples/kubernetes/kind-config.yaml
kind load docker-image sbx-k8s-example:dev --name sbx
kubectl apply -f examples/kubernetes/pod.yaml
kubectl wait --for=condition=Ready pod/sbx-example

kubectl exec sbx-example -- cat /proc/self/uid_map   # observed: "0 2401763328 65536"
kubectl exec sbx-example -- sbx check
kubectl exec sbx-example -- sbx check --policy /etc/sbx/default.json --host
kubectl exec sbx-example -- sbx check --conformance

kind delete cluster --name sbx
```

The kind config mounts `examples/kubernetes/seccomp/` at `/var/lib/kubelet/seccomp/profiles/sbx`
on the node, which is where the pod's `localhostProfile` points.

**Observed results in the pod.** `uid_map` was `0 <host id> 65536` (in the host user namespace it
is `0 0 4294967295`), so `hostUsers: false` was in effect. `sbx check`:

```
  ok    userns      unprivileged user + network namespaces work
  ok    netns       sandbox loopback network configured
  ok    netns-ipv6  IPv6 disabled inside the sandbox network namespace
  ok    nft         nftables NAT redirect loaded and verified
  ok    fallback    default route removable for explicit mode
  ok    bwrap       bubblewrap 0.12.0 at /usr/bin/bwrap
  ok    bwrap-run   bwrap starts a sandbox inside the sbx namespaces
  ok    bwrap-proc  bwrap mounts a fresh /proc
  ok    seccomp     bwrap installs sbx's socket-family filter (installation only; denials not probed)
  ok    landlock    Landlock ABI 7 (report-only)

network mode: transparent (policies with network mode transparent, explicit or none can run)
```

`sbx check --policy /etc/sbx/default.json --host` reported all five policy items ok (rc 0;
`infra-etc`: `all 6 infrastructure /etc paths exist`, `bind-sockets`: `no unix socket files under
the 2 filesystem.ro/rw paths`), and
`sbx check --conformance` reported `69 checks: 63 ok, 0 FAIL, 0 warn, 6 skip (6 opt-in, 0
capability, 0 not implemented)`, `result: conformant (opt-in skips only)`. The six skips are the
network tier (`E01` to `E06`), which needs `--network` and was not run here. A plain
`sbx run --policy /etc/sbx/default.json ... -- /usr/bin/sh -c 'echo hello-from-sandbox; cat
/etc/hosts'` exited 0, printed only `127.0.0.1 localhost` and `::1 localhost` for the sandbox's
`/etc/hosts`, and its audit exit row had `"net_mode":"transparent"`.

## What sbx needs from the pod

Each row below was removed once from the example pod in the kind cluster, and the table shows
what `sbx check` reported. Every other setting stayed as in the example.

| setting | why sbx needs it | without it (observed) |
|---|---|---|
| `hostUsers: false` | Gives the pod its own user namespace; Kubernetes accepts `procMount: Unmasked` only with it. | The API server rejected the pod: ``spec.containers[0].securityContext.procMount: Invalid value: "Unmasked": `hostUsers` must be false to use `Unmasked` ``. With `procMount` also removed, the pod ran in the host user namespace (`uid_map` `0 0 4294967295`) and failed exactly like the `procMount` row. |
| `procMount: Unmasked` | `sbx __init` writes `disable_ipv6` under `/proc/sys/net` in its own network namespace (`src/init/netns.rs:disable_ipv6`), and bwrap needs a writable `/proc/sys` for `--disable-userns`. With the default `/proc` the runtime makes `/proc/sys` read-only and masks paths. | `netns-ipv6` FAIL: `cannot disable IPv6 in the sandbox network namespace: /proc/sys is read-only (EROFS; typical inside containers)`, evidence `ipv6: write disable_ipv6 failed: Read-only file system (os error 30)`. `bwrap-run` FAIL: `bwrap cannot apply --disable-userns: /proc/sys is read-only`, evidence `bwrap: cannot open /proc/sys/user/max_user_namespaces: Read-only file system`. `bwrap-proc` and `seccomp` were skipped. Network mode `unavailable`, rc 1. |
| `seccompProfile: Localhost` (the derived profile) | The runtime default profile does not let a process without capabilities create namespaces, mount or `pivot_root`. | With `RuntimeDefault`: `userns` FAIL: `unshare(CLONE_NEWUSER\|CLONE_NEWNET) is blocked by a seccomp filter (EPERM; typical inside containers)`; every probe-derived item was skipped. Network mode `unavailable`, rc 1. |
| `appArmorProfile: Unconfined` | On nodes with AppArmor, the runtime's default profile applies otherwise (see [AppArmor](#apparmor)). | **Not observable here**: AppArmor was not enabled on the test host, so removing the setting changed nothing (all items ok). The CI job records this case on an AppArmor runner as report-only. |

The fix lines `sbx check` printed for these failures match the README
[fix hints](../README.md#host-check) table: `procMount: Unmasked` for `netns-ipv6` and `bwrap-run`
(both texts come from `PROC_FIX` in `src/host/classify.rs`), and the Localhost seccomp profile for
`userns` (`U_SECCOMP`). The `bwrap-proc` failure (a masked `/proc`) could not be shown on its own:
with the default `/proc`, `bwrap-run` fails first and `bwrap-proc` is skipped.

The rest of the example's security context is hardening that sbx works with (observed): it runs as
uid 65532 with `runAsNonRoot`, drops ALL capabilities, sets `allowPrivilegeEscalation: false`
(`NoNewPrivs: 1`), and uses `readOnlyRootFilesystem: true` with `emptyDir` volumes for `/tmp` and
`HOME`. `HOME` is `/home/sbx` because conformance check `H06` refuses a `HOME` under `/tmp`. No
service account token is mounted.

## Seccomp

[`examples/kubernetes/seccomp/sbx-userns.json`](../examples/kubernetes/seccomp/sbx-userns.json) is
derived from Docker's default profile, `seccomp/default.json` in
[moby/profiles](https://github.com/moby/profiles) at tag `seccomp/v0.2.4`, commit
`245180c51918481c0525424b3ee025d2b435d46c` (the version Docker Engine `docker-v29.9.1` vendors).
[`derive.py`](../examples/kubernetes/seccomp/derive.py) does the derivation, checks the upstream
SHA-256, and the CI job re-runs it and diffs the result against the committed file. It makes two
changes, both for a container that drops ALL capabilities:

1. **Resolve the capability conditions.** Docker's file allows some syscalls only when the
   container holds a capability (`includes.caps`) and others only when it lacks one
   (`excludes.caps`). The derived file keeps exactly the rules that apply with no capabilities and
   removes the conditions. Reason (observed): containerd 2.3.4 with runc 1.4.3 ignored these
   conditions when it loaded the unmodified Docker file as a Localhost profile. In a pod with ALL
   capabilities dropped, `setns(-1, 0)` returned EBADF, `quotactl` returned EINVAL and `clone3`
   returned EINVAL, so the kernel saw them; under `RuntimeDefault`, and under Docker 28.2.2 with the
   same file, they returned EPERM, EPERM and ENOSYS. With the conditions resolved, the derived
   profile returned EPERM, EPERM and ENOSYS in the pod too.
2. **Add one rule** that allows `clone`, `mount`, `pivot_root`, `sethostname`, `umount2` and
   `unshare` unconditionally.

Each added syscall was removed once and `sbx check` run (observed):

| removed | `sbx check` result |
|---|---|
| `unshare` | `userns` FAIL (seccomp, EPERM), in Docker and in the pod |
| `clone` | `bwrap-run` FAIL, evidence `bwrap: No permissions to create a new namespace, ...` (Docker). In the pod all items stayed ok: containerd also ignored the architecture condition of Docker's s390 `clone` rule, which then allowed bwrap's `clone` call on amd64. |
| `mount` | `bwrap-run` FAIL, evidence `bwrap: Failed to make / slave: Operation not permitted` |
| `pivot_root` | `bwrap-run` FAIL, evidence `bwrap: pivot_root: Operation not permitted` |
| `umount2` | `bwrap-run` FAIL, evidence `bwrap: unmount old root: Operation not permitted` |
| `sethostname` | `bwrap-run` FAIL, evidence `bwrap: Can't set hostname to sandbox: Operation not permitted` |

`clone3` is not added: sbx and bubblewrap did not need it, and Docker's rule that makes it fail
with ENOSYS stays (C libraries fall back to `clone` on ENOSYS). The `U_SECCOMP` fix text in
`sbx check` names `clone/clone3`; allowing `clone3` is not required by what was observed here.

The derived file still contains rules with architecture conditions (`includes.arches`,
`excludes.arches`) and one `minKernel` condition. Ignoring the architecture conditions on amd64
changes nothing beyond the rules above: the s390 `clone` rule is covered by the unconditional
`clone`, and the other architecture-only names do not exist on amd64. This reasoning was checked
only on amd64 (the pod started and the results above hold); aarch64 was not tested.

What the added syscalls mean for the pod: the sbx container can create user, network and mount
namespaces and mount inside them. Inside a user namespace it owns, a process gets capabilities over
that namespace's resources only; this is the same surface any host with unprivileged user
namespaces exposes (threat model section 4, "Host kernel: trusted and shared"; R15, R16). The
payload does not get these abilities: bwrap runs it with `--disable-userns` and `--cap-drop ALL`
(S3; checks `C13` and `D10` passed in the pod), and sbx's own filter returns EPERM for `mount`,
`umount2` and `pivot_root` in the payload (S2, the deny list in the README section
[Running commands](../README.md#running-commands)). sbx's filter does not filter the namespace flags
of `clone` and `unshare`; `--disable-userns` and the capability drop refuse them (R16).

Seccomp filters stack: the pod's filter stays in force for every process sbx starts, so the payload
runs under both the pod's profile and sbx's own filter (kernel documentation:
[Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html)). sbx did not test this
separately.

**`seccompProfile: Unconfined` instead.** This also worked (observed: `Seccomp: 0`, every item ok,
conformance 63 ok). The pod then has no syscall filter of its own, and the payload is left with
sbx's own filter only: the socket-family allow list plus a deny list, not a syscall allow list
(S2, R16). The sbx container itself, including the proxies that parse payload bytes (R28), then
runs with no seccomp filter at all. The Pod Security Standards
Baseline level forbids `Unconfined` seccomp.

**Installing the profile.** The kubelet resolves `localhostProfile` relative to its seccomp
directory (`/var/lib/kubelet/seccomp` by default). The file must exist on every node that can run
the pod before the pod starts. The kind config mounts it; on a real cluster use your node
provisioning, a DaemonSet that copies it, or an operator such as the Kubernetes Security Profiles
Operator (not tested by sbx).

## AppArmor

The example sets `appArmorProfile: Unconfined` on the sbx container. What was observed and what
was not:

- On the test host AppArmor was not enabled. The pod ran with `Unconfined` and also with the
  setting removed; `sbx check` was all ok both times.
- A `Localhost` AppArmor profile on that host was rejected by the kubelet: `Pod was rejected:
  Cannot enforce AppArmor: AppArmor is not enabled on the host` (observed). This is why the example
  does not ship one.
- **Not tested by sbx:** whether the runtime's default AppArmor profile breaks sbx on an AppArmor
  node. The `bwrap-run` fix text in `sbx check` names "seccompProfile and appArmorProfile
  Unconfined" as one remedy (`R_FAIL` in `src/host/classify.rs`).

**Ubuntu's user namespace restriction.** Ubuntu 23.10 and later can restrict unprivileged user
namespaces with `kernel.apparmor_restrict_unprivileged_userns = 1`; GitHub's Ubuntu runners have it
on, and the CI test job turns it off. `sbx check` reads that sysctl: when it is 1 and an early setup
stage fails with EPERM or EACCES (and the failure is not a seccomp block at `unshare`), the `userns`
item reports `unprivileged user namespaces are restricted by AppArmor
(kernel.apparmor_restrict_unprivileged_userns = 1)` with the fix `sudo sysctl -w
kernel.apparmor_restrict_unprivileged_userns=0, or give sbx an AppArmor profile that allows userns;
Kubernetes: appArmorProfile Unconfined or a Localhost profile that allows userns` (`U_APPARMOR`,
`src/host/classify.rs:staged`). The sysctl is global, so inside a pod it reflects the node.

Caution, not tested by sbx: Ubuntu documents that with the restriction on, "unprivileged processes
will only be able to create user namespaces if they are confined" by a profile with the `userns,`
rule, or hold CAP_SYS_ADMIN
([Ubuntu blog, "Restricted unprivileged user namespaces"](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)).
By that description, `appArmorProfile: Unconfined` alone would not lift the restriction, although
the `sbx check` fix text lists it. On such nodes, set the sysctl to 0 on the node, or load a
Localhost AppArmor profile with the `userns,` rule. The CI job records what `sbx check` reports in
the pod under the runner's defaults before it relaxes them.

## Pod Security Admission

Observed in the kind cluster with namespaces labelled `pod-security.kubernetes.io/enforce`:

| level | example pod | example without `appArmorProfile` |
|---|---|---|
| `baseline` | rejected: `forbidden AppArmor profile (container "sbx" must not set AppArmor profile type to "Unconfined")` | admitted; `sbx check` all ok (AppArmor off on that host) |
| `restricted` | rejected: the AppArmor reason, and `procMount (container "sbx" must not set securityContext.procMount to "Unmasked")` | rejected: the `procMount` reason |

So `baseline` admits `procMount: Unmasked` for a pod with `hostUsers: false` (the relaxation the
[user namespaces page](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
describes) and the Localhost seccomp profile, but not `Unconfined` AppArmor. `restricted` does not
admit sbx at all. On AppArmor nodes in a `baseline` namespace, the options are a Localhost AppArmor
profile (allowed by `baseline`; not tested by sbx) or a namespace exemption.

## Node requirements

- **User namespaces for pods.** Stable since Kubernetes v1.36. Per the
  [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/):
  Linux 6.3 or later (tmpfs idmap mounts), idmap mount support on the filesystem of
  `/var/lib/kubelet/pods/` and of every volume the pod uses (NFS volumes cannot be used), runc 1.2+
  or crun 1.9+, and containerd 2.0+ or CRI-O 1.25+. A pod with `hostUsers: false` cannot also set
  `hostNetwork`, `hostIPC` or `hostPID`. In the kind cluster the API server reported the
  `UserNamespacesSupport` and `ProcMountType` gates enabled with an empty stage label (observed,
  `kubernetes_feature_enabled` metric).
- **Unprivileged user namespaces in the kernel.** sbx creates its own user and network namespaces
  inside the pod. The `userns` item names the sysctl or policy that blocks them
  (`user.max_user_namespaces`, `kernel.unprivileged_userns_clone`, the AppArmor restriction above,
  or an SELinux or seccomp policy).
- **nftables modules for transparent mode.** A pod cannot load kernel modules. If the node kernel
  lacks the NAT redirect, `nft` fails with `nftables NAT redirect is unavailable` and the host
  provides only `explicit` (`T_LOAD`); load the modules on the node (`nf_tables nf_nat
  nft_chain_nat nft_redir nft_fib nft_fib_ipv4`) or use policies with network mode `explicit` or
  `none`. On the test host the modules were present and `nft` was ok in the pod; a node without
  them was not tested.
- **bubblewrap in the image.** 0.8 or later is accepted (`BWRAP_MIN`); use 0.12.0 or later because
  of CVE-2026-87766 (R26). The example image reports `bubblewrap 0.12.0`.
- **SELinux.** Not tested by sbx. If an SELinux policy denies namespace creation, expect `userns`
  FAIL with `unshare(CLONE_NEWUSER|CLONE_NEWNET) is not permitted (EPERM)`, whose fix names
  AppArmor/SELinux policy (`U_EPERM`).

## Network modes in a pod

The modes are the same as on a host (README [Host check](../README.md#host-check), threat model
section 5). sbx creates its own network namespace inside the pod and loads its nftables rules
there, so the pod needs no `NET_ADMIN`. The pod's own network namespace is what sbx calls the host
network: the proxies dial upstreams from it (threat model section 4, "The sbx proxies and
resolver").

## What changes in Kubernetes

The threat model's "host" is the sbx container. The guarantees S1 to S16 apply inside it unchanged
(the offline conformance tiers passed in the pod, above). What differs:

- **The outer boundary is the pod.** The host kernel is the node kernel, shared with every pod on
  the node (R15). Same-uid processes in the sbx container, such as the agent that calls `sbx run`,
  are out of model and can reach the sandbox from outside (R24).
- **`hostAliases` and the pod's `/etc/hosts`.** The sandbox gets a generated `/etc/hosts` with
  `localhost` entries only (R5, closed; observed in the pod), so the kubelet-managed file is not
  disclosed (R13). The proxy resolves allowed names on the pod side, where `hostAliases` entries
  apply. Per the README section [Running commands](../README.md#running-commands) (`/etc/hosts`),
  such a name works only when it maps to a public address; private, link-local and other
  special-purpose addresses stay denied by the resolved-address guard (S7). Not tested in a pod.
- **Name resolution uses the pod's resolver.** Allowed names are resolved with the pod's
  `/etc/resolv.conf` (in kind: the cluster DNS service at `10.96.0.10`, with search domains). Labels
  of `<data>.<allowed suffix>` names reach the cluster DNS and the upstream authoritative servers
  (R4).
- **Cluster addresses.** The resolved-address guard (S7) denies private, link-local and other
  IANA special-purpose addresses, the Azure wireserver and the pod's own interface addresses. That
  covers cluster IPs and pod IPs in private ranges and link-local metadata addresses (the catalog
  check is `A12`; the rest is unit-tested, see S7). A cluster that uses public address space for
  pods or services is not covered (R12).
- **Resources.** sbx sets no CPU, memory or pids quotas (R14). The example sets pod requests,
  limits and `emptyDir` size limits; size them for your payloads.
- **The unmasked `/proc`.** `procMount: Unmasked` exposes `/proc` paths the runtime normally masks
  or makes read-only, which is why Kubernetes requires `hostUsers: false` for it. Observed as uid
  65532 in the pod: `/proc/kcore` and `/proc/timer_list` could not be opened (EACCES), and writes to
  `/proc/sys/kernel/domainname` and `/proc/sys/net/ipv4/ip_forward` were refused (EACCES). Inside the
  sandbox, `/proc` is the fresh one bwrap mounts (`bwrap-proc`).

## Managed platforms

None of these was tested by sbx. Check the vendor's current documentation before relying on this.

- **GKE Autopilot: not usable.** Google documents that "if the Pod securityContext sets `procMount`
  to `Unmasked`, Autopilot rejects the Pod" in GKE 1.33 and later
  ([Autopilot security](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security)).
  Without it, `netns-ipv6` and `bwrap-run` fail (above). The same page says Autopilot blocks node
  access, so a Localhost seccomp profile cannot be installed either.
- **GKE Standard.** No Google documentation on `hostUsers` was found when this guide was written.
  The upstream node requirements above apply.
- **EKS.** No AWS documentation on `hostUsers` was found on AWS's documentation site when this
  guide was written. The upstream node requirements above apply.
- **AKS.** Microsoft documents user namespaces with Kubernetes 1.33 or later on Azure Linux 3.0 or
  Ubuntu 24.04 nodes, and AppArmor enabled by default on the node OS. Its seccomp section says "AKS
  only supports the default seccomp profiles (`RuntimeDefault` and `Unconfined`). Custom seccomp
  profiles aren't supported"
  ([Secure container access](https://learn.microsoft.com/en-us/azure/aks/secure-container-access)).
  By that statement the Localhost profile of this example is unsupported on AKS, and `Unconfined`
  (with the trade-off above) would be the documented option. Ubuntu 24.04 nodes may also have the
  AppArmor userns restriction (see [AppArmor](#apparmor)).

## Defence in depth: pod egress policy

sbx's proxies connect from the pod's network namespace, so a NetworkPolicy, or a Cilium
`toFQDNs` policy
([Cilium: DNS-based policies](https://docs.cilium.io/en/stable/security/dns/)), on the sbx pod limits
where they can connect even if sbx were misconfigured or had a bug (R28). Allow the pod's DNS
server and the names your sbx policies allow. This is optional and was not tested by sbx.

## CI

The `kubernetes` job in `.github/workflows/ci.yml` runs this example with the pinned versions
above. It validates `pod.yaml` with kubeconform v0.8.0 (strict, Kubernetes 1.37.0 schemas from
`yannh/kubernetes-json-schema` at a pinned commit), re-derives the seccomp profile, builds the
image, creates the kind cluster, and checks that `uid_map` is not the host map. Then:

- report-only: `sbx check` in the pod under the runner's AppArmor defaults;
- the runner's AppArmor restriction is relaxed the same way the test job relaxes it;
- gating: `sbx check` (every item except `landlock` ok, network mode `transparent`),
  `sbx check --policy /etc/sbx/default.json --host` (rc 0) and `sbx check --conformance` (the test
  job's assertions: no FAIL, the 63 offline checks ok or warn, `E01` to `E06` opt-in, rc 0);
- gating: the `procMount` and seccomp rows of the table above (`netns-ipv6` errno 30 and
  `bwrap-run`; `userns` errno 1);
- report-only: the pod without `appArmorProfile`.

The job was run locally with the same steps against the kind cluster described above, and every
step passed there. Its behaviour on the GitHub runner, where AppArmor is enabled, is known only
once CI has run it.
