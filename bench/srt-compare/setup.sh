#!/usr/bin/env bash
# Fetch pinned copies of sbx and srt (plus srt's socat/ripgrep if the host has
# none) into TOOLS, without root. Writes TOOLS/tools.env for run.sh.
#
#   bench/srt-compare/setup.sh [TOOLS]      (default: ${TMPDIR:-/tmp}/sbx-srt-tools)
#
# Each version gets its own directory (TOOLS/sbx-<v>, TOOLS/srt-<v>), so
# SBX_VERSION=… or SRT_VERSION=… fetches that release instead of reusing
# whatever is already there. tools.env points at the versions of the last call.
#
# Keep TOOLS on a native Linux filesystem (not /mnt/c on WSL2: exec from 9p
# adds ~14 ms per start) and outside any path either policy makes writable.
set -euo pipefail

SBX_VERSION=${SBX_VERSION:-0.1.0}
SRT_VERSION=${SRT_VERSION:-0.0.81}
TOOLS=${1:-${TMPDIR:-/tmp}/sbx-srt-tools}
mkdir -p "$TOOLS"
TOOLS=$(cd "$TOOLS" && pwd)
arch=$(uname -m)
die() { echo "setup.sh: $*" >&2; exit 1; }

# sbx: the static musl release binary, checked against its .sha256.
SBXDIR=$TOOLS/sbx-$SBX_VERSION
tgz=sbx-$SBX_VERSION-$arch-unknown-linux-musl.tar.gz
if [[ ! -x $SBXDIR/sbx ]]; then
  mkdir -p "$SBXDIR"
  base=https://github.com/vdavamse/sbx/releases/download/v$SBX_VERSION
  curl -fsSL -o "$SBXDIR/$tgz" "$base/$tgz" || die "no release asset $tgz (sbx ships x86_64 and aarch64 musl builds)"
  curl -fsSL -o "$SBXDIR/$tgz.sha256" "$base/$tgz.sha256"
  (cd "$SBXDIR" && sha256sum -c "$tgz.sha256")
  tar -xzf "$SBXDIR/$tgz" -C "$SBXDIR" --strip-components=1
fi
[[ $("$SBXDIR/sbx" --version) == "sbx $SBX_VERSION" ]] || die "$SBXDIR/sbx is not version $SBX_VERSION"

# srt: the npm package at a pinned version, in its own prefix (never inside a
# writable path: srt's README warns that a writable copy can be rewritten).
SRTDIR=$TOOLS/srt-$SRT_VERSION
SRT_CLI=$SRTDIR/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js
if [[ ! -f $SRT_CLI ]]; then
  npm install --no-audit --no-fund --prefix "$SRTDIR" \
    "@anthropic-ai/sandbox-runtime@$SRT_VERSION" >/dev/null
fi
[[ $(node "$SRT_CLI" --version) == "$SRT_VERSION" ]] || die "$SRT_CLI is not version $SRT_VERSION"
# Provenance: the tarball's integrity, the whole resolved dependency tree (npm
# installs without a lockfile, so transitive versions float), and how many
# versions npm has published as of today.
{
  echo "integrity: $(npm view "@anthropic-ai/sandbox-runtime@$SRT_VERSION" dist.integrity)"
  echo "published versions on $(date -u +%F): $(npm view @anthropic-ai/sandbox-runtime versions --json | grep -c '"')"
  npm ls --all --prefix "$SRTDIR" 2>/dev/null | tail -n +2
} >"$SRTDIR/provenance.txt"

# srt's Linux dependencies. Use the host's when present; otherwise unpack the
# distribution packages into TOOLS/prefix (Debian/Ubuntu, no root needed).
find_or_unpack() {
  local bin=$1 pkg=$2 deb
  if command -v "$bin" >/dev/null 2>&1 && [[ $(type -t "$bin") == file ]]; then
    command -v "$bin"
    return
  fi
  if [[ ! -x $TOOLS/prefix/usr/bin/$bin ]]; then
    command -v apt-get >/dev/null || die "$bin is not installed and this host has no apt-get: install $pkg"
    mkdir -p "$TOOLS/debs" "$TOOLS/prefix"
    (cd "$TOOLS/debs" && apt-get download "$pkg" >/dev/null)
    deb=$(ls -t "$TOOLS"/debs/"$pkg"_*.deb | head -1)
    dpkg-deb -x "$deb" "$TOOLS/prefix"
  fi
  echo "$TOOLS/prefix/usr/bin/$bin"
}
SOCAT=$(find_or_unpack socat socat)
RG=$(find_or_unpack rg ripgrep)

cat >"$TOOLS/tools.env" <<EOF
TOOLS=$TOOLS
SBX=$SBXDIR/sbx
SRT_DIR=$SRTDIR
SRT_CLI=$SRT_CLI
SOCAT=$SOCAT
RG=$RG
EOF
cat "$TOOLS/tools.env"
