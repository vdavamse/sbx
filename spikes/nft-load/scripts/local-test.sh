#!/usr/bin/env bash
# Local gate for the nft-load spike (sbx issue #1).
#
#   1. unit tests (cargo test --locked) — same gate CI runs
#   2. build the static musl release (--locked)
#   3. assert staticness (file/ldd/readelf: no NEEDED, no INTERP)
#   4. assert size < 1 MiB
#   5. run the binary with `env -i` (no environment dependencies)
#   6. 10x full self-test runs, each must exit 0
#   7. 1x --break-rules: must exit 3 with FAIL-CLOSED-VERIFIED on stderr
#   8. cross-check: enter the live netns of a --keep-alive run and compare
#      `nft list ruleset` output against the reference ruleset (best effort:
#      uses python3 os.setns — plain unprivileged `nsenter -U -n` fails at
#      nsenter's own setgroups() because setgroups=deny is permanent in the
#      sandbox userns; CI uses `sudo nsenter` instead)
#   9. --json report must be valid JSON containing "ok":true
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/usr/sbin:/sbin:$PATH"

TARGET=x86_64-unknown-linux-musl
BIN=target/$TARGET/release/nft-load-spike
MAX_SIZE=1048576 # 1 MiB — same assert as CI

say() { printf '\n=== %s ===\n' "$*"; }
cleanup() { rm -f run.out run.err break.err ka.err ruleset.txt cross.err out.json; }
trap cleanup EXIT

say "unit tests (cargo test --locked)"
cargo test --locked

say "build (musl release, --locked)"
cargo build --release --locked --target "$TARGET"

say "staticness"
file "$BIN"
# file(1) says "statically linked" or "static-pie linked" depending on the
# musl toolchain's default PIE mode — both are fully static.
file "$BIN" | grep -qE "static(-pie)? linked" || { echo "FAIL: not statically linked"; exit 1; }
if readelf -d "$BIN" 2>/dev/null | grep -q "NEEDED"; then
  echo "FAIL: dynamic NEEDED entries present:"; readelf -d "$BIN" | grep NEEDED; exit 1
fi
if readelf -l "$BIN" 2>/dev/null | grep -q "INTERP"; then
  echo "FAIL: INTERP segment present"; exit 1
fi
# glibc ldd exits 1 when it prints "not a dynamic executable" — swallow its
# status (subshell, pipefail-safe) and let grep be the only judge.
(ldd "$BIN" 2>&1 || true) | grep -qE "statically linked|not a dynamic executable" || { echo "FAIL: ldd disagrees"; exit 1; }
echo "OK: static (no NEEDED, no INTERP, ldd agrees)"

say "size"
SIZE=$(stat -c %s "$BIN")
echo "binary_bytes=$SIZE (limit $MAX_SIZE)"
[ "$SIZE" -lt "$MAX_SIZE" ] || { echo "FAIL: binary too large"; exit 1; }

say "env -i run (no environment dependencies)"
set +e
env -i "./$BIN" >run.out 2>run.err
RC=$?
set -e
[ "$RC" -eq 0 ] || { echo "FAIL: env -i run exit $RC"; cat run.err; exit 1; }
echo "OK: env -i full run exit 0"

say "10x full self-test runs"
for i in $(seq 1 10); do
  set +e
  "./$BIN" >run.out 2>run.err
  RC=$?
  set -e
  if [ "$RC" -ne 0 ]; then
    echo "FAIL: run $i exit $RC"; cat run.err; tail -20 run.out; exit 1
  fi
  echo "run $i: exit 0 OK"
done

say "--break-rules fail-closed"
set +e
"./$BIN" --break-rules >run.out 2>break.err
RC=$?
set -e
[ "$RC" -eq 3 ] || { echo "FAIL: --break-rules exit $RC (want 3)"; cat break.err; exit 1; }
grep -q "FAIL-CLOSED-VERIFIED" break.err || { echo "FAIL: no FAIL-CLOSED-VERIFIED marker"; cat break.err; exit 1; }
echo "OK: exit 3 + $(grep -m1 FAIL-CLOSED-VERIFIED break.err)"

say "cross-check: nft list ruleset inside the live netns"
if command -v python3 >/dev/null && command -v nft >/dev/null; then
  "./$BIN" --keep-alive 10 >run.out 2>ka.err &
  BGPID=$!
  for _ in $(seq 1 100); do grep -q "READY pid=" ka.err 2>/dev/null && break; sleep 0.2; done
  PID=$(sed -n 's/.*READY pid=\([0-9]*\).*/\1/p' ka.err | head -1)
  if [ -n "$PID" ]; then
    set +e
    python3 - "$PID" >ruleset.txt 2>cross.err <<'EOF'
import os, sys
pid = sys.argv[1]
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
ufd = os.open(f"/proc/{pid}/ns/user", os.O_RDONLY)
nfd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
os.setns(ufd, CLONE_NEWUSER)
os.setns(nfd, CLONE_NEWNET)
os.execvp("nft", ["nft", "list", "ruleset"])
EOF
    CROSS_RC=$?
    set -e
    if [ "$CROSS_RC" -eq 0 ]; then
      cat ruleset.txt
      grep -q "redirect to :15001" ruleset.txt || { echo "FAIL: redirect rule missing"; exit 1; }
      grep -q "policy drop" ruleset.txt || { echo "FAIL: policy drop missing"; exit 1; }
      grep -q 'fib daddr type != local' ruleset.txt || { echo "FAIL: fib rule missing"; exit 1; }
      echo "OK: independent nft oracle matches the reference ruleset"
    else
      echo "WARN: cross-check unavailable (rc=$CROSS_RC): $(cat cross.err)"
    fi
  else
    echo "WARN: no READY marker; skipping cross-check"
  fi
  wait "$BGPID" || true
else
  echo "SKIP: python3/nft not available"
fi

say "--json report shape"
set +e
"./$BIN" --json >out.json 2>run.err
RC=$?
set -e
[ "$RC" -eq 0 ] || { echo "FAIL: --json run exit $RC"; cat run.err; exit 1; }
grep -q '"ok":true' out.json || { echo "FAIL: json not ok"; cat out.json; exit 1; }
if command -v python3 >/dev/null; then
  python3 -c 'import json; json.load(open("out.json"))' && echo "OK: valid JSON, \"ok\":true"
else
  echo "OK: contains \"ok\":true (python3 unavailable for full validation)"
fi

say "ALL LOCAL GATES PASSED"
