#!/usr/bin/env bash
# Fetch pinned copies of sbx and srt (plus srt's socat/ripgrep if the host has
# none) into TOOLS, without root. Writes TOOLS/tools.env for run.sh.
#
#   bench/srt-compare/setup.sh [TOOLS]      (default: ${TMPDIR:-/tmp}/sbx-srt-tools)
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

# sbx: the static musl release binary, checked against its .sha256.
tgz=sbx-$SBX_VERSION-$arch-unknown-linux-musl.tar.gz
if [[ ! -x $TOOLS/sbx/sbx ]]; then
  mkdir -p "$TOOLS/sbx"
  base=https://github.com/vdavamse/sbx/releases/download/v$SBX_VERSION
  curl -fsSL -o "$TOOLS/sbx/$tgz" "$base/$tgz"
  curl -fsSL -o "$TOOLS/sbx/$tgz.sha256" "$base/$tgz.sha256"
  (cd "$TOOLS/sbx" && sha256sum -c "$tgz.sha256")
  tar -xzf "$TOOLS/sbx/$tgz" -C "$TOOLS/sbx" --strip-components=1
fi

# srt: the npm package at a pinned version, in its own prefix (never inside a
# writable path: srt's README warns that a writable copy can be rewritten).
if [[ ! -f $TOOLS/srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js ]]; then
  npm install --no-audit --no-fund --prefix "$TOOLS/srt" \
    "@anthropic-ai/sandbox-runtime@$SRT_VERSION" >/dev/null
fi
npm view "@anthropic-ai/sandbox-runtime@$SRT_VERSION" dist.integrity >"$TOOLS/srt/integrity.txt"

# srt's Linux dependencies. Use the host's when present; otherwise unpack the
# distribution packages into TOOLS/prefix (Debian/Ubuntu, no root needed).
find_or_unpack() {
  local bin=$1 pkg=$2
  if command -v "$bin" >/dev/null 2>&1 && [[ $(type -t "$bin") == file ]]; then
    command -v "$bin"
    return
  fi
  if [[ ! -x $TOOLS/prefix/usr/bin/$bin ]]; then
    mkdir -p "$TOOLS/debs" "$TOOLS/prefix"
    (cd "$TOOLS/debs" && apt-get download "$pkg" >/dev/null)
    dpkg-deb -x "$TOOLS"/debs/"$pkg"_*.deb "$TOOLS/prefix"
  fi
  echo "$TOOLS/prefix/usr/bin/$bin"
}
SOCAT=$(find_or_unpack socat socat)
RG=$(find_or_unpack rg ripgrep)

cat >"$TOOLS/tools.env" <<EOF
TOOLS=$TOOLS
SBX=$TOOLS/sbx/sbx
SRT_CLI=$TOOLS/srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js
SOCAT=$SOCAT
RG=$RG
EOF
cat "$TOOLS/tools.env"
