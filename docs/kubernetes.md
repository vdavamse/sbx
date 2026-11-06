# Running sbx in Kubernetes

This guide shows how to run `sbx` inside a Kubernetes pod without privileged mode and without
added capabilities. The pod runs in its own user namespace (`hostUsers: false`), and `sbx` builds
its sandboxes inside it. The example lives in [`examples/kubernetes/`](../examples/kubernetes/),
and the `kubernetes` CI job runs it on every pull request.

Read it together with [Host check](host-check.md) and
[Conformance](conformance.md) and with the [threat model](threat-model.md). Item names
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
the runner's AppArmor state and the pod without `appArmorProfile` as report-only steps, but its kind
node does not enforce AppArmor on pods (see [CI](#ci)).

## Quick start (kind)

From the repository root:

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl
ctx=$(mktemp -d)
cp target/x86_64-unknown-linux-musl/release/sbx examples/default.json "$ctx"/
docker build -f examples/kubernetes/Dockerfile -t sbx-k8s-example:dev "$ctx"

kind create cluster --name sbx --config examples/kubernetes/kind-config.yaml
# On hosts with DMI (most Linux VMs and bare metal; not WSL), kind bind-mounts files under
# /sys/devices/virtual/dmi/id/ in the node, and the pod sandbox then fails with a sysfs
# EPERM (see "Node requirements"). Remove them in this single-node cluster (observed in CI):
for _ in 1 2 3 4; do
  docker exec sbx-control-plane sh -c 'for m in $(awk "\$5 ~ \"^/sys/devices/virtual/dmi/id/\" {print \$5}" /proc/self/mountinfo); do umount "$m" || true; done'
done
docker exec sbx-control-plane sh -c 'awk "\$5 ~ \"^/sys/devices/virtual/dmi/\"" /proc/self/mountinfo'   # expect no output
kind load docker-image sbx-k8s-example:dev --name sbx
kubectl apply -f examples/kubernetes/pod.yaml
kubectl wait --for=condition=Ready pod/sbx-example

kubectl exec sbx-example -- cat /proc/self/uid_map   # observed: "0 <host id> 65536"
kubectl exec sbx-example -- sbx check
kubectl exec sbx-example -- sbx check --policy /etc/sbx/default.json --host
kubectl exec sbx-example -- sbx check --conformance

kind delete cluster --name sbx
```

The kind config mounts `examples/kubernetes/seccomp/` at `/var/lib/kubelet/seccomp/profiles/sbx`
on the node, which is where the pod's `localhostProfile` points.

**Observed results in the pod.** `uid_map` was `0 <host id> 65536`, with a different host id on
each pod (for example `0 3753443328 65536`); in the host user namespace it is `0 0 4294967295`. So
`hostUsers: false` was in effect. `sbx check`:

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
  ok    landlock    Landlock ABI 7 (report-only): available: filesystem, TCP bind, signal scope
  ok    keep-alive  pidfd and an unprivileged setns into a fresh user and network namespace work (run --keep-alive, attach)

network mode: transparent (policies with network mode transparent, explicit or none can run)
```

Newer builds report a twelfth item, the report-only `conntrack` row (issue #43). The CI
`kubernetes` job observed it ok in the pod on 2026-11-06 (commit 213d73b), with the other 11
items unchanged:

```
  ok    conntrack   conntrack table: 0 of 262144 entries in use in this network namespace (report-only; each sandbox namespace may grow to 262144, using host kernel memory)
```

`sbx check --policy /etc/sbx/default.json --host` reported all nine policy items ok, rc 0:

```
policy /etc/sbx/default.json (requires transparent):
  ok    network-mode  policy requires transparent; this host provides transparent
  ok    infra-etc     all 6 infrastructure /etc paths exist
  ok    policy-paths  all 2 filesystem.ro/rw paths exist
  ok    deny-paths    no deny path is a file under a bound path or /etc
  ok    bind-sockets  no unix socket files under the 2 filesystem.ro/rw paths
  ok    mount-chains  0 mount paths under the binds are real directories; no deny path has a host alias
  ok    bwrap-cve     bubblewrap 0.12.0 carries the CVE-2026-87766 fix (0.12.0 or later)
  ok    pin-cost      0 directory pins for the rw tree (warns above 50)
  ok    deny-links    no regular file under a deny path has a hard link outside it

policy: can run on this host
```

`sbx check --conformance` reported `81 checks: 74 ok, 0 FAIL, 0 warn, 7 skip (7 opt-in, 0
capability, 0 not implemented)`, `result: conformant (opt-in skips only)`. The seven skips are the
network tier (`E01` to `E06`), which needs `--network` and was not run here, and `I04`, which needs
a second uid and is an opt-in skip on every host. A plain
`sbx run --policy /etc/sbx/default.json ... -- /usr/bin/sh -c 'echo hello-from-sandbox; cat
/etc/hosts'` exited 0, printed only `127.0.0.1 localhost` and `127.0.1.1 sandbox` for the sandbox's
`/etc/hosts`, and its audit exit row had `"net_mode":"transparent"`.

**Optional features (observed in the pod).** A persistent session worked: `sbx run --keep-alive
... -- /usr/bin/sleep 300`, then `sbx attach ... -- /usr/bin/sh -c 'echo attached'` and `sbx stop`
all returned 0. It needs `setns`, which the example's seccomp profile allows for that reason (see
[Seccomp](#seccomp)); without it the `keep-alive` item is a report-only `warn` and plain `sbx run`
is unaffected. CI gates on the `keep-alive` item being ok and on the session conformance checks
(`I01` to `I03`, `I05`, `I06`), which start, attach to and stop real sessions in the pod; the
`sleep`/`attach`/`stop` run above was manual. The Landlock layer worked too:
`sbx run --landlock require ...` returned 0, and a `touch /usr/x` inside it failed with
`Read-only file system`. The `landlock_*` syscalls are in Docker's base allow list, so the derived
profile allows them unchanged.

## What sbx needs from the pod

Each row below was removed once from the example pod in the kind cluster, and the table shows
what `sbx check` reported. Every other setting stayed as in the example.

| setting | why sbx needs it | without it (observed) |
|---|---|---|
| `hostUsers: false` | Gives the pod its own user namespace; Kubernetes accepts `procMount: Unmasked` only with it. | The API server rejected the pod: ``spec.containers[0].securityContext.procMount: Invalid value: "Unmasked": `hostUsers` must be false to use `Unmasked` ``. With `procMount` also removed, the pod ran in the host user namespace (`uid_map` `0 0 4294967295`) and failed exactly like the `procMount` row. |
| `procMount: Unmasked` | `sbx __init` writes `disable_ipv6` under `/proc/sys/net` in its own network namespace (`src/init/netns.rs:disable_ipv6`), and bwrap needs a writable `/proc/sys` for `--disable-userns`. With the default `/proc` the runtime makes `/proc/sys` read-only and masks paths. | `netns-ipv6` FAIL: `cannot disable IPv6 in the sandbox network namespace: /proc/sys is read-only (EROFS; typical inside containers)`, evidence `ipv6: write disable_ipv6 failed: Read-only file system (os error 30)`. `bwrap-run` FAIL: `bwrap cannot apply --disable-userns: /proc/sys is read-only`, evidence `bwrap: cannot open /proc/sys/user/max_user_namespaces: Read-only file system`. `bwrap-proc` and `seccomp` were skipped. Network mode `unavailable`, rc 1. |
| `seccompProfile: Localhost` (the derived profile) | The runtime default profile does not let a process without capabilities create namespaces, mount or `pivot_root`. | With `RuntimeDefault`: `userns` FAIL: `unshare(CLONE_NEWUSER\|CLONE_NEWNET) is blocked by a seccomp filter (EPERM; typical inside containers)`; every probe-derived item was skipped. Network mode `unavailable`, rc 1. |
| `appArmorProfile: Unconfined` | On nodes with AppArmor, the runtime's default profile applies otherwise (see [AppArmor](#apparmor)). | **Not observable here**: AppArmor was not enabled on the test host, so removing the setting changed nothing (all items ok). In CI on an AppArmor runner the pod without it was still `unconfined` (`/proc/self/attr/current`) and all items were ok, most likely because containerd in the kind node does not detect AppArmor (the node has no securityfs mounted; inferred, not verified), so it applies no default profile; that is not a test of an AppArmor-enforcing node either. |

The fix lines `sbx check` printed for these failures match the
[fix hints](host-check.md) table: `procMount: Unmasked` for `netns-ipv6` and `bwrap-run`
(both texts come from `PROC_FIX` in `src/host/classify.rs`), and the Localhost seccomp profile for
`userns` (`U_SECCOMP`). The `bwrap-proc` failure (a masked `/proc`) could not be shown on its own:
with the default `/proc`, `bwrap-run` fails first and `bwrap-proc` is skipped.

The rest of the example's security context is hardening that sbx works with (observed): it runs as
uid 65532 with `runAsNonRoot`, drops ALL capabilities, sets `allowPrivilegeEscalation: false`
(`NoNewPrivs: 1`), and uses `readOnlyRootFilesystem: true` with `emptyDir` volumes for `/tmp` and
`HOME`. `HOME` is `/home/sbx` because with a `HOME` under `/tmp` conformance check `H06` is a
capability skip (observed: `cannot test: HOME is unset or lies under /root, /work, /tmp, /usr, /etc,
/proc or /dev`), which makes the run `incomplete` (rc 1) and fails the CI assertion. No service
account token is mounted. In production, pin the image by registry digest (`image@sha256:...`)
rather than by tag.

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
   profile returned EPERM for `quotactl` and ENOSYS for `clone3` in the pod too (`setns` returns
   EBADF there because step 2 adds it on purpose).
2. **Add one rule** that allows `clone`, `mount`, `pivot_root`, `sethostname`, `setns`, `umount2`
   and `unshare` unconditionally.

Each added syscall was removed once and `sbx check` run (observed):

| removed | `sbx check` result |
|---|---|
| `unshare` | `userns` FAIL (seccomp, EPERM), in Docker and in the pod |
| `clone` | `bwrap-run` FAIL, evidence `bwrap: No permissions to create a new namespace, ...` (Docker). In the pod all items stayed ok: containerd also ignored the architecture condition of Docker's s390 `clone` rule, which then allowed bwrap's `clone` call on amd64. |
| `mount` | `bwrap-run` FAIL, evidence `bwrap: Failed to make / slave: Operation not permitted` |
| `pivot_root` | `bwrap-run` FAIL, evidence `bwrap: pivot_root: Operation not permitted` |
| `umount2` | `bwrap-run` FAIL, evidence `bwrap: unmount old root: Operation not permitted` |
| `sethostname` | `bwrap-run` FAIL, evidence `bwrap: Can't set hostname to sandbox: Operation not permitted` |
| `setns` | `keep-alive` warn (report-only), evidence `setns into the holder stand-in's user and network namespaces failed: Operation not permitted (os error 1)`; every other item ok, network mode `transparent`. Only `run --keep-alive` and `attach` need it. |

`clone3` is not added: sbx and bubblewrap did not need it, and Docker's rule that makes it fail
with ENOSYS stays (C libraries fall back to `clone` on ENOSYS). The `U_SECCOMP` fix text in
`sbx check` names `clone/clone3`; allowing `clone3` is not required by what was observed here.

The derived file still contains rules with architecture conditions (`includes.arches`,
`excludes.arches`) and one `minKernel` condition. Ignoring the architecture conditions on amd64
changes nothing beyond the rules above: the s390 `clone` rule is covered by the unconditional
`clone`, and the other architecture-only names do not exist on amd64. This reasoning was checked
only on amd64 (the pod started and the results above hold); aarch64 was not tested.

What the added syscalls mean for the pod: `clone` and `unshare` are allowed with any flags, so the
sbx container can create a new user namespace and, inside it, namespaces of every other type
(mount, network, PID, IPC, UTS, cgroup, time), and mount, `pivot_root` and set the hostname there.
`setns` lets it join namespaces. Per [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html)
and [user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), that
needs CAP_SYS_ADMIN over the target (and, for a non-user namespace, in the caller's own user
namespace, so the owning user namespace is joined first). A process without capabilities in the pod has that only in
user namespaces created by a process with its own uid in the pod's user namespace, and in the
namespaces those own; this is how `sbx attach` joins a session's holder. So, given a file
descriptor, it can join the namespaces of any same-uid sbx session in the pod (same-uid access is
out of model, R24). It cannot join the pod's own namespaces, the node's, or another uid's (read
from the man pages; not tested by sbx). This bound relies on `hostUsers: false`: with the host
user namespace, the same rule would apply to user namespaces created by any process on the node (another
container or a host daemon) with the same host uid, given a file descriptor to them. It is still
bounded: the capabilities a process gets in a user namespace it creates or joins apply only to
that namespace and the namespaces it owns, never to the pod's or the node's resources, and the
pod itself holds no capabilities. This is the same surface any host with unprivileged user namespaces
exposes (threat model section 4, "Host kernel: trusted and shared"; R15, R16). The
payload does not get these abilities: bwrap runs it with `--disable-userns` and `--cap-drop ALL`
(S3; checks `C13` and `D10` passed in the pod), and sbx's own filter returns EPERM for `mount`,
`umount2` and `pivot_root` in the payload (S2, the deny list in
[Running commands](usage.md#running-commands)). sbx's filter does not filter the namespace flags
of `clone` and `unshare`; `--disable-userns` and the capability drop refuse them (R16).

Seccomp filters stack: the pod's filter stays in force for every process sbx starts, so the payload
runs under both the pod's profile and sbx's own filter (kernel documentation:
[Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html)). sbx did not test this
separately.

**`seccompProfile: Unconfined` instead.** This also worked (observed: `Seccomp: 0`, every item ok,
conformance 74 ok). The pod then has no syscall filter of its own, and the payload is left with
sbx's own filter only: the socket-family allow list plus a deny list, not a syscall allow list
(S2, R16). The sbx container itself, including the proxies that parse payload bytes (R28), then
runs with no seccomp filter at all. Per the
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/),
the Baseline level forbids `Unconfined` seccomp.

**Installing the profile.** The kubelet resolves `localhostProfile` relative to its seccomp
directory (`/var/lib/kubelet/seccomp` by default). The file must exist on every node that can run
the pod before the pod starts. The kind config mounts it; on a real cluster use your node
provisioning, a DaemonSet that copies it, or an operator such as the Kubernetes Security Profiles
Operator (not tested by sbx).

## AppArmor

The example sets `appArmorProfile: Unconfined` on the sbx container. What was observed and what
was not:

- On the test host AppArmor was not enabled. The pod ran with `Unconfined` and also with the
  setting removed; `sbx check` was all ok both times. On nodes without AppArmor the setting is a
  no-op, kept so the same manifest can be used on AppArmor nodes.
- A `Localhost` AppArmor profile on that host was rejected by the kubelet: `Pod was rejected:
  Cannot enforce AppArmor: AppArmor is not enabled on the host` (observed). This is why the example
  does not ship one.
- **Not tested by sbx:** whether the runtime's default AppArmor profile breaks sbx on an AppArmor
  node. Expected from containerd's source: the default profile it generates (`contrib/apparmor/template.go`
  at [v2.3.4](https://github.com/containerd/containerd/blob/v2.3.4/contrib/apparmor/template.go))
  contains `deny mount,`, denies writes under `/proc/sys` except `/proc/sys/kernel/shm*`, and denies
  most writes under `/sys`. sbx needs `mount` (bwrap) and writes to `/proc/sys/net/...` and
  `/proc/sys/user/max_user_namespaces` (see the `procMount` row above). The `bwrap-run` fix text in
  `sbx check` names "seccompProfile and appArmorProfile Unconfined" as one remedy (`R_FAIL` in
  `src/host/classify.rs`).
- **Not tested by sbx:** Ubuntu's `bwrap-userns-restrict` profile. Ubuntu's `apparmor` package
  (checked: `5.0.2-0ubuntu1~26.04.1`) ships `/etc/apparmor.d/bwrap-userns-restrict` with
  `profile bwrap /usr/bin/bwrap`, which attaches by path and stacks `unpriv_bwrap` on everything
  bwrap runs; the CI test job notes that `unpriv_bwrap` denies nested user namespaces and unloads
  it. Whether it attaches to the bwrap binary inside a container on such a node was not tested.

**What `Unconfined` gives up.** On an AppArmor node it removes the runtime's default profile, so the
mount and `/proc/sys` and `/sys` write denials above no longer apply to the sbx container; together
with `procMount: Unmasked` that whole layer is gone, and the user namespace, the seccomp profile and
the missing capabilities are what remain. The hardened option is a Localhost AppArmor profile that
allows `userns,` and the mount operations bwrap needs (`mount`, `umount`, `pivot_root`) and keeps
the rest. sbx does not ship one, because it could not be tested here (the kubelet rejects Localhost
profiles on nodes without AppArmor, observed above).

**Ubuntu's user namespace restriction.** Ubuntu 23.10 and later can restrict unprivileged user
namespaces with `kernel.apparmor_restrict_unprivileged_userns = 1`; GitHub's Ubuntu runners have it
on, and the CI test job turns it off. The sysctl is global, so inside a pod it reflects the node.
How `sbx check` reports a namespace failure in a pod follows from `src/host/classify.rs:staged`:

- A pod with a seccomp profile (`Localhost` or `RuntimeDefault`) has `Seccomp: 2` in
  `/proc/self/status` (observed). For an EPERM from `unshare` in such a pod the AppArmor row is
  skipped, and the item is the seccomp row (`U_SECCOMP`, "blocked by a seccomp filter"), whatever
  caused the EPERM: seccomp, AppArmor or an SELinux policy. The one exception is
  `kernel.unprivileged_userns_clone = 0`, which is reported as that sysctl (`U_CLONE_SYSCTL`). The
  generic row (`U_EPERM`) cannot appear in such a pod.
- In such a pod, the AppArmor row (`U_APPARMOR`, `unprivileged user namespaces are restricted by AppArmor
  (kernel.apparmor_restrict_unprivileged_userns = 1)`) appears only when the sysctl is 1 and a later
  setup stage (`idmap`, `netns`, `listeners` or `ipv6`) fails with EPERM or EACCES; a failure at `unshare`,
  whatever its errno, never gives this row in such a pod. Its fix reads
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0, or give sbx an AppArmor profile
  that allows userns; Kubernetes: appArmorProfile Unconfined or a Localhost profile that allows
  userns`.

So in a pod, a `userns` FAIL that says "seccomp" does not prove that seccomp is the cause; check the
node's AppArmor and SELinux state too.

Caution, not tested by sbx: Ubuntu documents that with the restriction on, "unprivileged processes
will only be able to create user namespaces if they are confined" by a profile with the `userns,`
rule, or hold CAP_SYS_ADMIN
([Ubuntu blog, "Restricted unprivileged user namespaces"](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)).
By that description, `appArmorProfile: Unconfined` alone would not lift the restriction, although
the `sbx check` fix text lists it, so that part of the fix text is likely wrong. On such nodes, set
the sysctl to 0 on the node, or load a Localhost AppArmor profile with the `userns,` rule. CI does not answer
this: it relaxes the runner's restriction before creating the cluster, and its kind node does not
enforce AppArmor on pods.

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

- **User namespaces for pods.** Per the
  [Kubernetes documentation](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/):
  stable since Kubernetes v1.36; Linux 6.3 or later (tmpfs idmap mounts), idmap mount support on the filesystem of
  `/var/lib/kubelet/pods/` and of every volume the pod uses (NFS volumes cannot be used), runc 1.2+
  or crun 1.9+, and containerd 2.0+ or CRI-O 1.25+. A pod with `hostUsers: false` cannot also set
  `hostNetwork`, `hostIPC` or `hostPID`. In the kind cluster the API server reported the
  `UserNamespacesSupport` and `ProcMountType` gates enabled with an empty stage label (observed,
  `kubernetes_feature_enabled` metric).
- **A fully visible `/sys` on the node.** The runtime mounts a fresh sysfs for a `hostUsers: false`
  pod, and the kernel allows that inside a user namespace only when an existing sysfs mount is
  fully visible: every mount inherited below it (locked) must sit on a directory that sysfs itself
  keeps empty for mounts, such as `/sys/fs/cgroup` or `/sys/kernel/debug` (the kernel's
  `mnt_already_visible` check). A file bind-mounted over a path under `/sys` never qualifies,
  and the pod sandbox fails with
  `error mounting "sysfs" to rootfs at "/sys": ... operation not permitted`. Observed in CI: kind bind-mounts files over
  `/sys/devices/virtual/dmi/id/product_name` and `product_uuid` on hosts with DMI (GitHub runners;
  not WSL), and the example pod could not start until the job removed those mounts. On a real node,
  check for file overmounts under `/sys` if you see that error (not tested by sbx beyond kind).
- **Unprivileged user namespaces in the kernel.** sbx creates its own user and network namespaces
  inside the pod. The `userns` item names the sysctl or policy that blocks them
  (`user.max_user_namespaces`, `kernel.unprivileged_userns_clone`, the AppArmor restriction above,
  or a seccomp policy); in a pod with a seccomp profile, an EPERM at `unshare` is reported as
  seccomp unless `kernel.unprivileged_userns_clone = 0` (see [AppArmor](#apparmor)).
- **nftables modules for transparent mode.** A pod cannot load kernel modules. If the node kernel
  lacks the NAT redirect, `nft` fails with `nftables NAT redirect is unavailable` and the host
  provides only `explicit` (`T_LOAD`); load the modules on the node (`nf_tables nf_nat
  nft_chain_nat nft_redir nft_fib nft_fib_ipv4`) or use policies with network mode `explicit` or
  `none`. On the test host the modules were present and `nft` was ok in the pod; a node without
  them was not tested.
- **bubblewrap in the image.** 0.8 or later is accepted (`BWRAP_MIN`); use 0.12.0 or later because
  of CVE-2026-87766 (R26). The example image reports `bubblewrap 0.12.0`.
- **SELinux.** Not tested by sbx. If an SELinux policy denies `unshare` with EPERM in a pod with a
  seccomp profile, `sbx check` reports it as the seccomp row (`U_SECCOMP`), not as the generic
  "not permitted" row that names SELinux (see [AppArmor](#apparmor) for the rule). A denial at a
  later stage is reported for that stage (for example `userns` "cannot write the user namespace id
  maps" at `idmap`), unless the AppArmor sysctl is 1, in which case an EPERM or EACCES at `idmap`, `netns`,
  `listeners` or `ipv6` is reported as the AppArmor row.

## Network modes in a pod

The modes are the same as on a host ([Host check](host-check.md), threat model
section 5). sbx creates its own network namespace inside the pod and loads its nftables rules
there, so the pod needs no `NET_ADMIN`. The pod's own network namespace is what sbx calls the host
network: the proxies dial upstreams from it (threat model section 4, "The sbx proxies and
resolver").

## What changes in Kubernetes

The threat model's "host" is the sbx container. The guarantees S1 to S24 are implemented by the
same code paths in a pod. S25 and S26 belong to the opt-in `tls-termination` build feature; the
example image is built without it, so they were not tested here. What was shown in the pod: the offline conformance tiers (host, lab and
init) passed. For the persistent-session guarantees, conformance `I01` to `I03`, `I05` and `I06`
passed in the pod (S17, S19 to S21); S18's `I04` was an opt-in skip, and S22 has no catalog check
and was not shown. For the Landlock guarantees (S23, S24) only the smoke run under "Optional
features" above was observed. What was not: the network tier `E01` to `E06` was skipped, so S15
and the `E06` part of S8 were not shown in a pod, and the unit and integration tests that threat model section 6 cites
were not run in a pod. What differs:

- **The outer boundary is the pod.** The host kernel is the node kernel, shared with every pod on
  the node (R15). Same-uid processes in the sbx container, such as the agent that calls `sbx run`,
  are out of model and can reach the sandbox from outside (R24).
- **`hostAliases` and the pod's `/etc/hosts`.** The sandbox gets a generated `/etc/hosts` with
  only `localhost` and the sandbox hostname (R5, closed; observed in the pod), so the
  kubelet-managed file is not disclosed. The proxy resolves allowed names on the pod side, where
  `hostAliases` entries apply. Per [Running commands](usage.md#running-commands) (`/etc/hosts`),
  such a name works only when it maps to a public address; private, link-local and other
  special-purpose addresses stay denied by the resolved-address guard (S7). Not tested in a pod.
- **Name resolution uses the pod's resolver.** Allowed names are resolved with the pod's
  `/etc/resolv.conf` (in kind: the cluster DNS service at `10.96.0.10`, with search domains). Labels
  of `<data>.<allowed suffix>` names reach the cluster DNS and the upstream authoritative servers
  (R4).
- **Cluster and node addresses.** The resolved-address guard (S7) denies private, link-local and
  other IANA special-purpose addresses, the Azure wireserver and "the host's own interface
  addresses". That covers cluster IPs and pod IPs in private ranges and link-local metadata
  addresses (the catalog check is `A12`; the rest is unit-tested, see S7). A cluster that uses
  public address space for pods or services is not covered (R12).
- **The node's addresses are not in the host-address set.** `sbx run` gathers that set with
  `getifaddrs` in the network namespace it runs in (`src/run/sys.rs:host_interface_addrs`), which in
  a pod is the pod's: it holds the pod's addresses, not the node's (read from the code; not tested).
  A node with a public address is therefore not denied (R12): an allowed name that resolves to it
  reaches whatever the node serves on the ports sbx inspects, 443 and 80 (for example an ingress
  controller on the host network). Other ports, such as the kubelet's 10250 or NodePorts, are denied
  by the port rule (only 443 and 80 are inspected; [Running commands](usage.md#running-commands)).
- **Resources.** sbx sets no CPU, memory or pids quotas (R14). The example sets pod requests,
  limits and `emptyDir` size limits; size them for your payloads. Kubernetes has no per-pod pids
  field in the pod spec; the kubelet's `podPidsLimit` setting caps the processes of every pod on a
  node and bounds a fork bomb in a payload (not tested by sbx).
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
  access; from that we infer (not documented as such, not tested) that a Localhost seccomp profile
  cannot be installed either.
- **GKE Standard.** No Google documentation on `hostUsers` was found when this guide was written.
  The upstream node requirements above apply.
- **EKS.** No AWS documentation on `hostUsers` was found on AWS's documentation site when this
  guide was written. The upstream node requirements above apply.
- **AKS.** Microsoft documents user namespaces with Kubernetes 1.33 or later on Azure Linux 3.0 or
  Ubuntu 24.04 nodes, and AppArmor enabled by default on the node OS. Its seccomp section says "AKS
  only supports the default seccomp profiles (`RuntimeDefault` and `Unconfined`). Custom seccomp
  profiles aren't supported"
  ([Secure container access](https://learn.microsoft.com/en-us/azure/aks/secure-container-access)).
  The same page also walks through a custom Localhost seccomp profile, so the page contradicts
  itself; check with Microsoft before relying on a Localhost profile on AKS. `Unconfined` (with the
  trade-off above) is the option the page lists as supported. Ubuntu 24.04 nodes may also have the
  AppArmor userns restriction (see [AppArmor](#apparmor)).

## Defence in depth: pod egress policy

sbx's proxies connect from the pod's network namespace, so an egress policy on the sbx pod limits
where they can connect even if sbx were misconfigured or had a bug (R28). Both options are optional
and were not tested by sbx:

- A plain Kubernetes NetworkPolicy matches IP blocks, pods and ports, not names. Use it to allow
  egress only to the cluster DNS server and to ports 443 and 80, and to deny cluster-internal ranges
  the payload has no reason to reach (the node and pod CIDRs, see the node-address bullet above).
- A Cilium `toFQDNs` policy
  ([Cilium: DNS-based policies](https://docs.cilium.io/en/stable/security/dns/)) can allow by name.
  Cilium's examples pair it with a DNS rule that lets Cilium see the pod's lookups. List the names
  your sbx policies allow.

## CI

The `kubernetes` job in `.github/workflows/ci.yml` runs this example with the pinned versions
above. It validates `pod.yaml` with kubeconform v0.8.0 (strict, Kubernetes 1.37.0 schemas from
`yannh/kubernetes-json-schema` at a pinned commit), re-derives the seccomp profile, builds the
image, creates the kind cluster, and checks that `uid_map` is not the host map. Then:

- report-only: the runner's AppArmor state (observed on `ubuntu-latest`, which was ubuntu-26.04,
  image 20261101.186.1: AppArmor enabled, `kernel.apparmor_restrict_unprivileged_userns = 1`, and the
  profiles `:glycin:bwrap`, `bwrap`, `unpriv_bwrap` and `unprivileged_userns` loaded);
- the runner's AppArmor is relaxed the same two ways the test job relaxes it, before the cluster
  is created: `kernel.apparmor_restrict_unprivileged_userns=0`, and unloading the
  `bwrap-userns-restrict` profile. (Relaxing it was not what made the pod start; see the next item.)
- kind's DMI file overmounts under `/sys` are removed in the node (see
  [Node requirements](#node-requirements)); without that, the pod sandbox fails to start on
  GitHub runners;
- gating: `sbx check` (every item except the report-only `landlock` ok, including `keep-alive`;
  the report-only `conntrack` ok or skip; network mode `transparent`),
  `sbx check --policy /etc/sbx/default.json --host` (rc 0) and `sbx check --conformance` (the same
  `.github/scripts/assert_conformance.py` the test job uses: no FAIL, the 77 offline checks ok or
  warn except `I04`, which is an opt-in skip like `E01` to `E06`, rc 0);
- gating: the `procMount` and seccomp rows of the table above (`netns-ipv6` errno 30 and
  `bwrap-run`; `userns` errno 1);
- report-only: the pod without `appArmorProfile`.

The job passes on the GitHub `ubuntu-latest` runner (ubuntu-26.04, kernel 7.0, containerd 2.3.4, runc 1.4.3 in
the kind node) and with the same steps locally. On failure it prints diagnostics: the runner and
node kernel, the node's mounts under `/sys` and `/proc`, and the runtime versions.
