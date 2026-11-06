# Building and releases

## Build

Requires Rust ≥ 1.85 via [rustup](https://rustup.rs/):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/sbx
```

The default build has no crypto provider, so its dependency tree is pure Rust.
The opt-in TLS termination (see [TLS termination](tls-termination.md))
adds `ring` and a C compiler; build it with `--features tls-termination`.

For `aarch64-unknown-linux-musl`, add the target and provide a cross
linker (the dependency tree is pure Rust, so a stock cross toolchain is
enough):

```sh
rustup target add aarch64-unknown-linux-musl
sudo apt-get install gcc-aarch64-linux-gnu   # or use cargo-zigbuild
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl
```

## MSRV

Rust **1.85**, edition 2024 — recorded in `Cargo.toml` (`rust-version`)
and enforced by the CI `msrv` job. Bumping the MSRV is a deliberate,
documented change: if a dependency update breaks the `msrv` job, either
pin the older version (`cargo update -p <crate> --precise <ver>`) or raise
`rust-version` with justification.

## Static binaries

Release musl builds are fully static. `file(1)` reports them as
`static-pie linked` on x86_64 (the host toolchain defaults to PIE) or
`statically linked` on aarch64 (the cross toolchain links a non-PIE
executable) — both mean no dynamic loader and no shared-library
dependencies. CI asserts the spelling-agnostic regex plus the absence of
a `PT_INTERP` segment (`readelf`), which is architecture-agnostic; `ldd`
output is informational only, since its wording varies on foreign-arch
binaries. PIE is kept wherever the toolchain provides it — forcing a
single spelling would sacrifice ASLR for the sandbox launcher itself.

## Releases

Pushing a `vX.Y.Z` tag that matches `Cargo.toml` runs
`.github/workflows/release.yml`, which publishes:

- **GitHub Release:** `sbx-X.Y.Z-{x86_64,aarch64}-unknown-linux-musl.tar.gz`
  (the static binary, LICENSE, README and `docs/`), a `.sha256` per tarball, the wheels
  and a combined `SHA256SUMS`. Every tarball and wheel carries a build
  provenance attestation:
  `gh attestation verify sbx-X.Y.Z-x86_64-unknown-linux-musl.tar.gz --repo vdavamse/sbx`.
- **PyPI:** [`sbx-bin`](https://pypi.org/project/sbx-bin/), a platform wheel
  per architecture that bundles the same binary and exposes only
  `sbx_bin.binary_path()` (the `ripgrep` wheel pattern). Uploaded with
  trusted publishing (OIDC); no PyPI token exists.
- **Container image:** `ghcr.io/vdavamse/sbx:X.Y.Z` (amd64 and arm64):
  Debian slim with `bubblewrap` and `sbx` as the entrypoint, attested by
  digest. It runs as a non-root user; the container runtime must allow
  unprivileged user namespaces. (A new GHCR package is private: make it
  public once after the first release.)

Release artifacts are the default-feature build: pure Rust, no C crypto.
Opt-in features are never enabled in them. On pull requests that touch the
pipeline (and on manual dispatch), the workflow is a dry run: it builds and
checks everything and publishes nothing.

## Development

```sh
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs lint, MSRV, tests, static musl builds
for x86_64 + aarch64 (with staticness asserts and a smoke run of the built
binary), and `cargo deny` (advisories / licenses / bans / sources per
`deny.toml`).

`spikes/` holds standalone experiment packages; they are excluded from the
Cargo workspace.
