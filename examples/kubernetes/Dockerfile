# Example image for running sbx in a Kubernetes pod (issue #15, docs/kubernetes.md).
#
# Build context: a directory holding exactly two files, the static sbx binary (`sbx`)
# and the policy (`default.json`). From the repository root, after the static musl
# build that CI uses:
#   cargo build --release --locked --target x86_64-unknown-linux-musl
#   ctx=$(mktemp -d)
#   cp target/x86_64-unknown-linux-musl/release/sbx examples/default.json "$ctx"/
#   docker build -f examples/kubernetes/Dockerfile -t sbx-k8s-example:dev "$ctx"
#
# Pins: the base image by digest (debian:trixie-slim, pulled 2026-11-05) and the
# bubblewrap package by its exact Debian version. bubblewrap 0.12.0 is the first
# release with the fix for CVE-2026-87766 (docs/threat-model.md R26). An exact apt
# version stops resolving when Debian replaces it; the build then fails loudly, and
# the pin must be updated on purpose.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG BWRAP_VERSION=0.12.0-1~deb13u1

# bubblewrap: the sandbox launcher sbx drives. ca-certificates: /etc/ssl and
# /etc/ca-certificates, two of the /etc paths every sandbox binds (missing from the
# bare base image; `sbx check --policy P --host`, item infra-etc). tzdata: time zone
# data for payloads. The release image (packaging/container/Dockerfile) uses the
# same base digest; this one adds the pinned bubblewrap version, tzdata, the policy
# file, a HOME outside /tmp and a `sleep` command for `kubectl exec`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      "bubblewrap=${BWRAP_VERSION}" ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

# HOME outside /tmp: conformance check H06 needs a HOME that is not under /root,
# /work, /tmp, /usr, /etc, /proc or /dev. /etc/sbx is created first because
# COPY --chmod would apply the file mode to a directory it creates.
RUN install -d -m 0755 /etc/sbx \
 && install -d -o 65532 -g 65532 -m 0700 /home/sbx

COPY --chmod=0755 sbx /usr/local/bin/sbx
COPY --chmod=0644 default.json /etc/sbx/default.json

# A fixed non-root user. With hostUsers: false this uid is mapped to an
# unprivileged host uid as well; the image does not depend on it being root.
USER 65532:65532
ENV HOME=/home/sbx
WORKDIR /home/sbx

# The example pod keeps the container alive and runs sbx through `kubectl exec`.
CMD ["sleep", "infinity"]
