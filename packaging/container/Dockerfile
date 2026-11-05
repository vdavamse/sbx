# sbx + bubblewrap base layer (issue #16).
#
# Built by .github/workflows/release.yml once per architecture on a native
# runner (no QEMU), from the SAME static binary that is attached to the
# GitHub Release; the build context must hold that binary at ./sbx.
#
# The sandbox needs unprivileged user namespaces from the container runtime
# (for Docker, e.g. a seccomp/AppArmor profile that allows them); run
# `sbx check` inside the container to see what the host provides.

# Debian 13 (trixie) slim, pinned by index digest (multi-arch). Bump the
# digest deliberately, together with a re-run of the release dry run.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# bubblewrap: the sandbox launcher sbx drives. ca-certificates: TLS for the
# payloads sbx runs (sbx itself never terminates TLS by default).
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 sbx /usr/local/bin/sbx

ENTRYPOINT ["/usr/local/bin/sbx"]
CMD ["--help"]
