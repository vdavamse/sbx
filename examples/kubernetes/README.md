# Kubernetes example

sbx in a user-namespaced pod (`hostUsers: false`), without privileged mode or added
capabilities. The guide is [docs/kubernetes.md](../../docs/kubernetes.md): what each setting is
for, what was tested, and what breaks without it. The `kubernetes` CI job runs this example.

| file | what it is |
|---|---|
| `pod.yaml` | The example pod. Validated with kubeconform v0.8.0 (`-strict`, Kubernetes 1.37.0). |
| `Dockerfile` | The image: `debian:trixie-slim` pinned by digest, bubblewrap `0.12.0-1~deb13u1`, the static sbx binary and `examples/default.json` as `/etc/sbx/default.json`. Build steps are in its header. |
| `kind-config.yaml` | A one-node kind cluster (kind v0.33.0, `kindest/node:v1.37.0` pinned by digest) that mounts `seccomp/` where the pod's `localhostProfile` points. Create it from the repository root. |
| `seccomp/sbx-userns.json` | The Localhost seccomp profile. Generated; do not edit by hand. |
| `seccomp/derive.py` | Generates `sbx-userns.json` from the pinned upstream file. |

## Seccomp profile provenance

- Upstream: <https://github.com/moby/profiles>, file `seccomp/default.json`, tag
  `seccomp/v0.2.4`, commit `245180c51918481c0525424b3ee025d2b435d46c` (the version Docker Engine
  `docker-v29.9.1` vendors in `vendor/modules.txt`).
- Upstream file SHA-256: `785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334`
  (checked by `derive.py`).
- Changes, for a container that drops ALL capabilities: the capability conditions are resolved
  for an empty capability set, and one rule allows `clone`, `mount`, `pivot_root`, `sethostname`,
  `umount2` and `unshare`. The reasons and the observations behind each are in `derive.py` and in
  [docs/kubernetes.md, "Seccomp"](../../docs/kubernetes.md#seccomp).
- Use it only for containers that drop ALL capabilities: with capabilities, Docker's own file would
  allow more, and this one does not reflect that.

Regenerate and compare:

```sh
curl -fsSL -o /tmp/default.json \
  https://raw.githubusercontent.com/moby/profiles/245180c51918481c0525424b3ee025d2b435d46c/seccomp/default.json
python3 -I examples/kubernetes/seccomp/derive.py /tmp/default.json /tmp/sbx-userns.json
diff -u examples/kubernetes/seccomp/sbx-userns.json /tmp/sbx-userns.json
```

## Other pins

| what | pin | checksum source |
|---|---|---|
| kind | v0.33.0 | `kind-linux-amd64.sha256sum` from the release |
| node image | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` | kind v0.33.0 release notes |
| kubectl | v1.37.0 | `kubectl.sha256` from dl.k8s.io |
| kubeconform | v0.8.0 | `CHECKSUMS` from the release |
| JSON schemas | `yannh/kubernetes-json-schema` commit `102361970337d65537d40141dc29b991b8e95786` | git commit |
| base image | `debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` (pulled 2026-11-05) | registry digest |
| bubblewrap | `0.12.0-1~deb13u1` (Debian package version) | Debian archive signatures (apt) |

The exact bubblewrap version stops resolving when Debian replaces it in the archive. The image build
then fails, and the pin must be updated on purpose.
