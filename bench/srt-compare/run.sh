#!/usr/bin/env bash
# Run the sbx vs srt comparison and write a results matrix with evidence.
#
#   bench/srt-compare/setup.sh            # once: fetch pinned sbx and srt
#   bench/srt-compare/run.sh [OUT]        # default OUT: ./srt-compare-results
#   ONLY=latency bench/srt-compare/run.sh OUT   # host.txt and latency.txt only
#
# Startup latency is sensitive to other load on the host: re-record it alone
# with ONLY=latency on an idle machine (the bare `true` row shows the noise).
#
# Tool paths come from TOOLS/tools.env (written by setup.sh; TOOLS defaults to
# ${TMPDIR:-/tmp}/sbx-srt-tools) or from SBX, SRT_CLI, SOCAT, RG in the
# environment. Needs: bash, curl, git, ssh, python3 at /usr/bin/python3,
# node >= 22.12, and optionally hyperfine (for the startup numbers).
#
# The run touches the host only in these ways: a listener on a random
# 127.0.0.1 port and on an abstract unix socket, a `sleep` decoy process, two
# canary secrets in the sandboxes' environment, and the canary files the
# sandboxes try to create (in WORK, in /usr, and $HOME/.sbx-bench-canary-*).
# All of them are removed on exit.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT=${1:-$PWD/srt-compare-results}
TOOLS=${TOOLS:-${TMPDIR:-/tmp}/sbx-srt-tools}
# shellcheck disable=SC1091
[[ -f $TOOLS/tools.env ]] && . "$TOOLS/tools.env"
: "${SBX:?set SBX or run setup.sh}" "${SRT_CLI:?set SRT_CLI or run setup.sh}"
: "${SOCAT:?set SOCAT or run setup.sh}" "${RG:?set RG or run setup.sh}"
PY=/usr/bin/python3
# srt puts its proxy sockets in $TMPDIR; a long TMPDIR overflows the 108-byte
# sun_path limit (srt fails with "listen EINVAL"), so give it a short one.
SRT_TMPDIR=${SRT_TMPDIR:-/tmp}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sbx-srt-work.XXXXXX")
RW=$WORK/rw
TOKEN=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
REALHOME=$HOME
pids=()
cleanup() {
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null; done
  "$SBX" stop --session-dir "$WORK/sess-ka" >/dev/null 2>&1
  rm -f "$REALHOME/.sbx-bench-canary-$TOKEN" "/usr/sbx-bench-$TOKEN" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$RW" "$OUT/raw"
OUT=$(cd "$OUT" && pwd)
# ONLY=latency leaves a full run's evidence in OUT alone.
[[ ${ONLY:-all} == latency ]] || rm -f "$OUT"/raw/* "$OUT/results.tsv"
cp "$HERE/probe.py" "$RW/probe.py"
git init -q "$RW"   # the rw dir is a checkout, as an agent's working tree would be

render() {
  sed -e "s#@RW@#$RW#g" -e "s#@TOOLS@#$TOOLS#g" -e "s#@SOCAT@#$SOCAT#g" -e "s#@RG@#$RG#g" "$1"
}
render "$HERE/policies/sbx.json.in" >"$WORK/sbx.json"
render "$HERE/policies/srt.json.in" >"$WORK/srt.json"
cp "$WORK/sbx.json" "$WORK/srt.json" "$OUT/"
AUDIT=$WORK/audit.jsonl
: >"$AUDIT"

# ---------------------------------------------------------------- host side

# A host service on loopback and on an abstract unix socket, each answering
# with a marker the probes look for.
"$PY" -I - "$TOKEN" >"$WORK/listener.port" 2>/dev/null <<'EOF' &
import socket, sys, threading
tok = sys.argv[1]
t = socket.socket(); t.bind(("127.0.0.1", 0)); t.listen(16)
print(t.getsockname()[1], flush=True)
u = socket.socket(socket.AF_UNIX); u.bind("\0sbx-bench-" + tok); u.listen(16)
def serve(srv, body):
    while True:
        c, _ = srv.accept()
        try:
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        finally:
            c.close()
threading.Thread(target=serve, args=(u, b"HOST-ABSTRACT"), daemon=True).start()
serve(t, b"HOST-LOOPBACK")
EOF
pids+=($!)
for _ in $(seq 50); do [[ -s $WORK/listener.port ]] && break; sleep 0.1; done
LPORT=$(cat "$WORK/listener.port")
bash -c "exec -a sbx-bench-decoy-$TOKEN sleep 900" &
pids+=($!)
DECOY=$!

# Positive controls: each fixture must answer from the host, or the rows that
# probe it would read "blocked" for nothing.
fail() { echo "run.sh: $*" >&2; exit 1; }
[[ $LPORT =~ ^[0-9]+$ ]] || fail "the loopback listener did not start"
curl -s -m 5 --noproxy '*' "http://127.0.0.1:$LPORT/" | grep -q HOST-LOOPBACK || fail "the loopback listener does not answer"
"$PY" -I "$HERE/probe.py" abstract "sbx-bench-$TOKEN" >/dev/null || fail "the abstract socket does not answer"
sleep 0.2
tr '\0' ' ' <"/proc/$DECOY/cmdline" 2>/dev/null | grep -q "sbx-bench-decoy-$TOKEN" || fail "the decoy process is not running"
export SBX_BENCH_SECRET=canary-$TOKEN AWS_SECRET_ACCESS_KEY=canary-aws-$TOKEN

# ---------------------------------------------------------------- host info
{
  echo "date:     $(date -u +%FT%TZ)"
  echo "kernel:   $(uname -srm)"
  echo "distro:   $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "bwrap:    $(bwrap --version 2>&1)"
  echo "node:     $(node --version)"
  echo "sbx:      $("$SBX" --version) ($(sha256sum "$SBX" | cut -c1-16)…)"
  echo "srt:      $(node "$SRT_CLI" --version)"
  echo "srt tag:  $(git ls-remote https://github.com/anthropics/sandbox-runtime "refs/tags/v$(node "$SRT_CLI" --version)" 2>/dev/null | cut -c1-40)"
  echo "socat:    $("$SOCAT" -V 2>/dev/null | sed -n 's/^socat version \([^ ]*\).*/\1/p')"
  echo "ripgrep:  $("$RG" --version | head -1)"
  echo "sbx check: $("$SBX" check 2>&1 | grep '^network mode')"
  echo "runner:   $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)$(git -C "$HERE" status --porcelain -- . 2>/dev/null | grep -q . && echo ' (modified)')"
  [[ -f ${SRT_DIR:-$TOOLS/srt}/provenance.txt ]] && sed -n '1,2p' "${SRT_DIR:-$TOOLS/srt}/provenance.txt" | sed 's/^/srt npm /'
} >"$OUT/host.txt"
cat "$OUT/host.txt"

# ---------------------------------------------------------------- runners
# Every scenario is one bash script run unchanged inside both sandboxes. Its
# exit status picks the outcome word; the evidence is its output plus what
# each tool logged: sbx's audit rows, srt's --debug proxy decisions.
# The script sends its stderr to stdout, so stdout holds everything the
# command said and srt's --debug log is alone on stderr. PATH also carries the
# directory of srt's socat (its GIT_SSH_COMMAND calls a bare `socat`).
PRELUDE="exec 2>&1
export PATH=/usr/bin:/bin:$(dirname "$SOCAT")
cd '$RW'
P() { /usr/bin/python3 -I '$RW/probe.py' \"\$@\"; }
# show CMD... : run CMD, print the last lines of its output, succeed when the
# output matches the extended regex in \$RE.
show() { o=\$(\"\$@\" 2>&1); printf '%s\\n' \"\$o\" | tail -6; printf '%s\\n' \"\$o\" | grep -qE \"\$RE\"; }
c() { /usr/bin/curl -sS -m 15 -o /dev/null -w 'connect=%{http_connect} http=%{http_code} ip=%{remote_ip}\n' \"\$@\"; }
noproxy() { ( unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; \"\$@\" ); }
"

run_sbx() { # script -> rc; output in $1.out, evidence in $1.log
  local f=$1 script=$2 before
  before=$(wc -l <"$AUDIT")
  timeout 90 "$SBX" run --policy "$WORK/sbx.json" --session-dir "$WORK/sess" \
    --audit "$AUDIT" --cwd "$RW" -- /usr/bin/bash -c "$script" >"$f.out" 2>&1
  local rc=$?
  tail -n +"$((before + 1))" "$AUDIT" | "$PY" -I -c '
import json, sys
for l in sys.stdin:
    r = json.loads(l)
    if r["event"] == "exit":
        print("exit code=%s outcome=%s" % (r["code"], r["outcome"])); continue
    if r["event"] == "close":
        continue
    print(r["event"], r["verdict"], "host=%s sni=%s port=%s:" % (r["host"], r["sni"], r["port"]), r["reason"])
' >"$f.log"
  return $rc
}

run_srt() {
  local f=$1 script=$2
  (cd "$RW" && TMPDIR=$SRT_TMPDIR timeout 90 node "$SRT_CLI" --debug --settings "${SRT_CONF:-$WORK/srt.json}" -c "$script") \
    >"$f.out" 2>"$f.err"
  local rc=$?
  # srt's own failures and bwrap's (an execvp that fails) are not prefixed.
  grep -v '^\[SandboxDebug\]' "$f.err" | grep -E '^(Error|Fatal|Failed|Process|bwrap)' >>"$f.out"
  grep '^\[SandboxDebug\]' "$f.err" | sed 's/^\[SandboxDebug\] //' |
    grep -E 'Connection (blocked|allowed)|config rule|denying|resolved|HTTP request blocked|violation|refus' |
    sort -u >"$f.log"
  rm -f "$f.err"
  return $rc
}

esc() { sed -e 's/|/\\|/g' | tr '\n' ' ' | cut -c1-220; }

scen() { # ID "title" success-word failure-word 'script' [host-path] [deny-regex]
  # With deny-regex the failure-word needs proof: the tool's log or the
  # script's output must match the regex (an explicit deny). A failed script
  # without it is "unverified", because the target may not have answered.
  # With host-path the verdict is taken on the host: success-word when the
  # path is a non-empty file there after the run. A write that succeeded
  # inside but landed elsewhere (sbx's /tmp is the session's own tmp
  # directory) is the failure-word, and so is the empty placeholder file srt
  # leaves for a mandatory deny. Only a regular file counts: sbx's placeholder
  # for a missing protected name is a directory (removed after the run).
  local id=$1 title=$2 ok=$3 bad=$4 body=$5 hostpath=${6:-} denyre=${7:-} tool f word rc
  local script="$PRELUDE
( $body ); r=\$?; if [ \$r = 0 ]; then echo OUTCOME=$ok; else echo OUTCOME=$bad; fi"
  local row="$id	$title"
  for tool in sbx srt; do
    f=$OUT/raw/$id.$tool
    "run_$tool" "$f" "$script"
    rc=$?
    word=$(sed -n 's/^OUTCOME=//p' "$f.out" | tail -1)
    [[ -z $word ]] && word="error(rc=$rc)"
    if [[ -n $denyre && $word == "$bad" ]] && ! grep -qE "$denyre" "$f.log" "$f.out"; then
      word=unverified
    fi
    if [[ -n $hostpath && ( $word == "$ok" || $word == "$bad" ) ]]; then
      if [[ -f $hostpath && -s $hostpath ]]; then
        word=$ok; echo "host: $hostpath written ($(head -c 40 "$hostpath"))" >>"$f.log"; rm -f "$hostpath"
      else
        [[ $word == "$ok" ]] && echo "host: write succeeded inside, but $hostpath is not on the host (the sandbox has its own mount there)" >>"$f.log"
        word=$bad
      fi
    fi
    row+="	$word"
    { echo "### $id $title — $tool"; echo; echo '```'; echo "\$ $body"; echo "--- output (rc=$rc)";
      grep -v '^OUTCOME=' "$f.out" | head -20; echo "--- $tool log"; head -15 "$f.log"; echo '```'; echo; } >>"$OUT/evidence.md"
  done
  echo "$row" | tee -a "$OUT/results.tsv"
}

if [[ ${ONLY:-all} != latency ]]; then
: >"$OUT/evidence.md"
# ---------------------------------------------------------------- network
scen N1  "HTTPS to the allowed name (baseline)" allowed BROKEN \
  'c https://example.com/'
scen N2  "HTTPS to a denied name" LEAKED blocked \
  'c https://www.google.com/'
scen N3a "proxy env unset: curl to the allowed name" works fails-closed \
  'noproxy c --noproxy "*" https://example.com/'
scen N3b "proxy env unset: curl to a denied name" LEAKED blocked \
  'noproxy c --noproxy "*" https://www.google.com/'
scen N3c "raw socket + TLS to the allowed name" works fails-closed \
  'P tcp example.com 443 example.com'
scen N3d "raw socket + TLS to a denied name" LEAKED blocked \
  'P tcp www.google.com 443 www.google.com'
scen N3e "bash /dev/tcp to a denied name, port 80" LEAKED blocked \
  'RE=HTTP/ show timeout 10 bash -c "exec 3<>/dev/tcp/www.google.com/80 && printf \"HEAD / HTTP/1.0\r\n\r\n\" >&3 && head -c 12 <&3"'
scen N4a "direct IP 1.1.1.1:443 (raw)" LEAKED blocked \
  'P tcp 1.1.1.1 443 one.one.one.one'
scen N4b "direct IP https://1.1.1.1/ (curl, proxy env kept)" LEAKED blocked \
  'c -k https://1.1.1.1/'
scen N4c "raw DNS to 8.8.8.8:53/udp for a denied name" LEAKED blocked \
  'P dns 8.8.8.8 www.google.com udp'
scen N4d "raw DNS to 8.8.8.8:53/tcp for a denied name" LEAKED blocked \
  'P dns 8.8.8.8 www.google.com tcp'
scen N5a "fronting: TCP to the allowed name, SNI+Host of another site (curl --connect-to)" LEAKED blocked \
  'c --connect-to www.cloudflare.com:443:example.com:443 https://www.cloudflare.com/'
scen N5b "fronting: raw TLS to the allowed name with a foreign SNI" LEAKED blocked \
  'P tcp example.com 443 www.cloudflare.com'
scen N5c "fronting: SNI of the allowed name, foreign Host header" passed-uninspected stopped \
  'c https://example.com/ -H "Host: www.cloudflare.com"'
# Nothing answers at these addresses, so the verdict needs the tool's deny.
DIALDENY='denied dial|blocked: resolved to'
scen N6a "allowed name resolving to 127.0.0.1 (127.0.0.1.nip.io)" LEAKED blocked \
  'c https://127.0.0.1.nip.io/' "" "$DIALDENY"
scen N6b "allowed name resolving to 169.254.169.254" LEAKED blocked \
  'c https://169.254.169.254.nip.io/' "" "$DIALDENY"
scen N6c "allowed name resolving to 10.0.0.1 (RFC1918)" LEAKED blocked \
  'c https://10.0.0.1.nip.io/' "" "$DIALDENY"
scen N7a "host loopback service, raw connect to 127.0.0.1" LEAKED blocked \
  "P tcp 127.0.0.1 $LPORT"
scen N7b "host loopback service by IP, proxy variables honoured (curl --noproxy '')" LEAKED blocked \
  "RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://127.0.0.1:$LPORT/"
scen N7c "host loopback service by name (localhost)" LEAKED blocked \
  "RE=HOST-LOOPBACK show /usr/bin/curl -sS -m 10 --noproxy '' http://localhost:$LPORT/"
scen N7d "host abstract unix socket" LEAKED blocked \
  "P abstract sbx-bench-$TOKEN"
scen N8a "git over HTTPS to the allowed name" allowed blocked \
  'RE="not found|404|did not send" GIT_TERMINAL_PROMPT=0 show git ls-remote https://example.com/x.git'
scen N8b "ssh to the allowed name, port 22" LEAKED blocked \
  'RE="SSH-2\.0|Permission denied \(publickey|Host key verification" show ssh -F /dev/null -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@example.com true'
scen N8c "git over ssh to the allowed name, port 22" LEAKED blocked \
  'RE="SSH-2\.0|Permission denied \(publickey|Host key verification" GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh} -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8" show git ls-remote ssh://git@example.com/x.git'
scen N8d "UDP datagram to the allowed name, port 443" LEAKED blocked \
  'P udp example.com 443'
scen N8e "UDP datagram to an IP literal (1.1.1.1:443, no DNS needed)" LEAKED blocked \
  'P udp 1.1.1.1 443' "" 'RESULT=no-send'

# ---------------------------------------------------------------- filesystem / process
scen F1 "write inside the rw dir (baseline)" allowed BROKEN \
  "echo ok > '$RW/inside' && cat '$RW/inside'"
scen F2 "write outside the rw dir (host /tmp)" LEAKED blocked \
  "echo canary > '$WORK/outside-canary'" "$WORK/outside-canary"
scen F3 "write into the host \$HOME" LEAKED blocked \
  "echo canary > '$REALHOME/.sbx-bench-canary-$TOKEN'" "$REALHOME/.sbx-bench-canary-$TOKEN"
scen F4 "write to /usr" LEAKED blocked \
  "echo canary > /usr/sbx-bench-$TOKEN" "/usr/sbx-bench-$TOKEN"
if [[ -d $REALHOME/.ssh ]]; then
scen F5 "list ~/.ssh (names only)" LEAKED blocked \
  "n=\$(ls -A '$REALHOME/.ssh' 2>&1) && echo \"listed \$(echo \"\$n\" | grep -c .) entries\" || { echo \"\$n\"; false; }"
else
  printf 'F5\tlist ~/.ssh (names only)\tn/a (no ~/.ssh on this host)\tn/a (no ~/.ssh on this host)\n' | tee -a "$OUT/results.tsv"
fi
scen F6 "read secrets from the environment" LEAKED blocked \
  'printenv SBX_BENCH_SECRET && printenv AWS_SECRET_ACCESS_KEY'
scen F7 "see a host process (/proc)" LEAKED blocked \
  "m=sbx-bench-decoy; m=\$m-$TOKEN; n=0; f=1
   for p in /proc/[0-9]*; do n=\$((n+1)); case \"\$(tr '\\0' ' ' <\$p/cmdline 2>/dev/null)\" in *\"\$m\"*) f=0; echo \"found \$p\";; esac; done
   echo \"visible pids: \$n\"; exit \$f"
scen F8 "read the host /etc/passwd (the srt policy has to allow it, see V4)" LEAKED blocked \
  "grep '^[^:]*:[^:]*:$(id -u):' /etc/passwd | cut -d: -f1,3 | sed 's/^[^:]*/<host user>/' | grep ."
scen F9 "plant a git hook in the rw checkout (.git/hooks/pre-commit)" planted blocked \
  "echo 'echo pwned' > '$RW/.git/hooks/pre-commit'" "$RW/.git/hooks/pre-commit"
scen F10 "plant a shell rc file in the rw dir (.bashrc)" planted blocked \
  "echo 'echo pwned' >> '$RW/.bashrc'" "$RW/.bashrc"

# ---------------------------------------------------------------- srt defaults
# srt with the benchmark policy changed in one place each: what the settings
# this comparison adds for srt are for (V1, V2), and what srt needs to run at
# all (V3 to V4b).
variant() { # ID "title" python-edit 'script' log|out regex match-word other-word [other-regex]
  # The word is match-word when the regex matches srt's log (log) or the
  # script's output (out) and srt logged no deny. Otherwise it is other-word;
  # with other-regex, other-word needs that regex in the output or the log,
  # and the row is "unclear" without it (srt may not have run the script).
  local id=$1 title=$2 edit=$3 body=$4 src=$5 re=$6 yes=$7 no=$8 nore=${9:-} f=$OUT/raw/$1.srt word
  "$PY" -I -c "import json,sys; c=json.load(open(sys.argv[1])); $edit; json.dump(c,open(sys.argv[2],'w'),indent=1)" \
    "$WORK/srt.json" "$WORK/srt-$id.json"
  SRT_CONF=$WORK/srt-$id.json run_srt "$f" "$PRELUDE
$body"
  if grep -qE "$re" "$f.$src" && ! grep -qE 'blocked|denying' "$f.log"; then word=$yes
  elif [[ -z $nore ]] || grep -qE "$nore" "$f.out" "$f.log"; then word=$no
  else word=unclear; fi
  printf '%s\t%s\t%s\t%s\n' "$id" "$title" "n/a" "$word" | tee -a "$OUT/variants.tsv"
  { echo "### $id $title — srt"; echo; echo '```'; echo "\$ $body"; echo "--- output"; head -8 "$f.out";
    echo "--- srt log"; head -8 "$f.log"; echo '```'; echo; } >>"$OUT/evidence.md"
}
: >"$OUT/variants.tsv"
variant V1 "srt allow entry without :port, then git over ssh (port 22)" \
  'c["network"]["allowedDomains"]=[d.split(":")[0] for d in c["network"]["allowedDomains"]]' \
  'GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$GIT_SSH_COMMAND -o BatchMode=yes -o ConnectTimeout=8" timeout 20 git ls-remote ssh://git@example.com/x.git' \
  log 'Allowed by config rule: example.com:22' dialed refused
variant V2 "srt without deniedResolvedAddresses, name resolving to 10.0.0.1" \
  'c["network"].pop("deniedResolvedAddresses")' \
  'c -m 8 https://10.0.0.1.nip.io/' \
  log 'Allowed by config rule: 10.0.0.1.nip.io' dialed refused
variant V3 "srt with denyRead [\"/\"] and /usr re-allowed, HTTPS to the allowed name" \
  'c["filesystem"]["denyRead"]=["/"]; c["filesystem"]["allowRead"]+=["/usr"]' \
  'c https://example.com/' \
  out 'http=200' works broken 'http=000'
variant V3b "as V3, with /tmp (srt's bridge sockets) also re-allowed" \
  'c["filesystem"]["denyRead"]=["/"]; c["filesystem"]["allowRead"]+=["/usr", "/tmp"]' \
  'c https://example.com/' \
  out 'http=200' works broken 'http=000'
GITSSH='GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$GIT_SSH_COMMAND -o BatchMode=yes" git ls-remote ssh://git@example.com/x.git'
variant V4a "srt without /etc/passwd and /etc/group readable, git over ssh" \
  'c["filesystem"]["allowRead"]=[p for p in c["filesystem"]["allowRead"] if p not in ("/etc/passwd","/etc/group")]' \
  "$GITSSH" out 'No user exists' broken works 'denying: example.com:22'
variant V4b "srt without /etc/hosts readable, git over ssh" \
  'c["filesystem"]["allowRead"]=[p for p in c["filesystem"]["allowRead"] if p != "/etc/hosts"]' \
  "$GITSSH" out 'getaddrinfo\("localhost"' broken works 'denying: example.com:22'

# Did a sandbox write leave the canaries on the host? (checked here, outside)
{
  left=$(ls -d "$WORK/outside-canary" "$REALHOME/.sbx-bench-canary-$TOKEN" "/usr/sbx-bench-$TOKEN" 2>/dev/null)
  echo "canaries left on the host after all runs: ${left:-none}"
} | tee "$OUT/canaries.txt"

# ---------------------------------------------------------------- ergonomics
sbxr() { "$SBX" run --policy "$WORK/sbx.json" --session-dir "$WORK/sess" --cwd "$RW" "$@"; }
srtr() { TMPDIR=$SRT_TMPDIR node "$SRT_CLI" --settings "$WORK/srt.json" "$@"; }
# rc of a command, how long it took, and the last line it wrote to stderr.
# Timed with /proc/uptime (monotonic, 10 ms steps): the wall clock can step
# on WSL2 while a run is in flight.
up() { local u; read -r u _ </proc/uptime; echo "${u/./}"; }
rcof() {
  local t0 err rc
  t0=$(up)
  err=$("$@" 2>&1 >/dev/null)
  rc=$?
  echo "rc=$rc t=$((($(up) - t0) * 10))ms ${err##*$'\n'}"
}
leftover() { echo "leftover: $(pgrep -fc "^(/usr/bin/)?sleep $1\$")"; }
: >"$OUT/ergonomics.tsv"
erg() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(echo "$3" | esc)" "$(echo "$4" | esc)" | tee -a "$OUT/ergonomics.tsv"; }
cd "$RW" || exit 1

erg E1 "command exits 7" \
  "$(rcof sbxr -- /usr/bin/sh -c 'exit 7')" "$(rcof srtr -c 'exit 7')"
erg E2 "command killed by its own SIGKILL" \
  "$(rcof sbxr -- /usr/bin/sh -c 'kill -9 $$')" "$(rcof srtr -c 'kill -9 $$')"
erg E3 "timeout 2 s (sbx --timeout; srt has no timeout, so coreutils timeout)" \
  "$(rcof sbxr --timeout 2s -- /usr/bin/sleep 41; sleep 1; leftover 41)" \
  "$(TMPDIR=$SRT_TMPDIR rcof timeout 2 node "$SRT_CLI" --settings "$WORK/srt.json" -c 'sleep 42'; sleep 1; leftover 42)"
s=$("$SBX" run --policy "$WORK/sbx.json" --session-dir "$WORK/sess" -- /usr/bin/sleep 43 2>&1 & p=$!; sleep 1; kill -TERM $p; wait $p; echo "rc=$?"; sleep 1; leftover 43)
r=$(TMPDIR=$SRT_TMPDIR node "$SRT_CLI" --settings "$WORK/srt.json" -c 'sleep 44' 2>&1 & p=$!; sleep 1.5; kill -TERM $p; wait $p; echo "rc=$?"; sleep 1; leftover 44)
erg E4 "SIGTERM to the tool during a run" "$s" "$r"
echo '{' >"$WORK/bad.json"
erg E5 "malformed policy file" \
  "$(rcof "$SBX" run --policy "$WORK/bad.json" --session-dir "$WORK/sess2" -- /usr/bin/true)" \
  "$(TMPDIR=$SRT_TMPDIR rcof node "$SRT_CLI" --settings "$WORK/bad.json" -c true)"
"$PY" -I -c 'import json,sys; c=json.load(open(sys.argv[1])); c["bwrapPath"]="/no/such/bwrap"; json.dump(c,open(sys.argv[2],"w"))' \
  "$WORK/srt.json" "$WORK/srt-nobwrap.json"
erg E6 "sandbox cannot start (bwrap missing)" \
  "$(SBX_BWRAP=/no/such/bwrap rcof sbxr -- /usr/bin/true)" \
  "$(TMPDIR=$SRT_TMPDIR rcof node "$SRT_CLI" --settings "$WORK/srt-nobwrap.json" -c true)"
erg E7 "command not found" \
  "$(rcof sbxr -- /no/such/cmd)" "$(rcof srtr -- /no/such/cmd)"
e8=$(sbxr --audit "$WORK/e8.jsonl" -- /usr/bin/head -c 5000000 /dev/zero 2>"$WORK/e8.err" | wc -c)
erg E8 "5 MB of output (the sbx policy caps output at 1 MiB)" \
  "bytes=$e8 $(tail -1 "$WORK/e8.err"); audit output_truncated=$(grep -o '"output_truncated":[a-z]*' "$WORK/e8.jsonl" | cut -d: -f2)" \
  "bytes=$(srtr -c 'head -c 5000000 /dev/zero' 2>/dev/null | wc -c)"
# The resident serves the rw dir on the session's loopback; an attached call
# fetches from it, which shows the calls share localhost.
s="start: $(rcof "$SBX" run --keep-alive --policy "$WORK/sbx.json" --session-dir "$WORK/sess-ka" --cwd "$RW" -- /usr/bin/python3 -m http.server 8765 --bind 127.0.0.1)"
s="$s; attach: $(rcof "$SBX" attach --policy "$WORK/sbx.json" --session-dir "$WORK/sess-ka" -- /usr/bin/true)"
sleep 1
s="$s; attach curl of the resident: $("$SBX" attach --policy "$WORK/sbx.json" --session-dir "$WORK/sess-ka" -- /usr/bin/curl -s -o /dev/null -w 'http=%{http_code}' http://127.0.0.1:8765/probe.py 2>&1)"
"$SBX" stop --session-dir "$WORK/sess-ka" >/dev/null 2>&1
erg E9 "persistent session (sbx run --keep-alive, then attach true)" "$s" \
  "not in the CLI (each srt call starts its own proxies; the library's SandboxManager keeps them across wrapWithSandbox calls)"

fi # ONLY != latency

# ---------------------------------------------------------------- startup latency
cd "$RW" || exit 1   # both tools run with the rw dir as cwd
{
  echo "startup latency, 20 runs of true, median (ms):"
  if command -v hyperfine >/dev/null; then
    hyperfine -N --warmup 3 --runs 20 --export-json "$WORK/hf.json" \
      "/usr/bin/true" \
      "$SBX run --policy $WORK/sbx.json --session-dir $WORK/sess --cwd $RW -- /usr/bin/true" \
      "env TMPDIR=$SRT_TMPDIR node $SRT_CLI --settings $WORK/srt.json -- /usr/bin/true" >/dev/null 2>"$WORK/hf.err" ||
      { echo "hyperfine failed:"; cat "$WORK/hf.err"; }
    # Where srt's time goes: node itself, loading the CLI, and a run with an
    # empty policy (proxies and bridges, no deny-path work).
    printf '%s\n' '{"network":{"allowedDomains":[],"deniedDomains":[]},"filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}' |
      "$PY" -I -c 'import json,sys; c=json.load(sys.stdin); c["socatPath"]=sys.argv[1]; c["ripgrep"]={"command":sys.argv[2]}; json.dump(c,open(sys.argv[3],"w"))' \
        "$SOCAT" "$RG" "$WORK/srt-empty.json"
    hyperfine -N --warmup 3 --runs 20 --export-json "$WORK/hf2.json" \
      "node -e 0" \
      "node $SRT_CLI --version" \
      "env TMPDIR=$SRT_TMPDIR node $SRT_CLI --settings $WORK/srt-empty.json -- /usr/bin/true" >/dev/null 2>"$WORK/hf.err" ||
      { echo "hyperfine failed:"; cat "$WORK/hf.err"; }
    [[ -s $WORK/hf.json && -s $WORK/hf2.json ]] && "$PY" -I -c '
import json, sys
names = ["bare true", "sbx run", "srt", "node -e 0", "srt --version", "srt, empty policy"]
rows = json.load(open(sys.argv[1]))["results"] + json.load(open(sys.argv[2]))["results"]
for r, n in zip(rows, names):
    t = sorted(r["times"] if "times" in r else [m["time_wall_clock"]["value"] for m in r["measurements"]])
    med = (t[len(t) // 2] + t[(len(t) - 1) // 2]) / 2
    print("  %-17s median %7.1f  min %7.1f  max %7.1f  (n=%d)" % (n, med * 1e3, t[0] * 1e3, t[-1] * 1e3, len(t)))
' "$WORK/hf.json" "$WORK/hf2.json"
  else
    for name in sbx srt; do
      ts=()
      for _ in $(seq 20); do
        t0=$(up)
        if [[ $name == sbx ]]; then "$SBX" run --policy "$WORK/sbx.json" --session-dir "$WORK/sess" --cwd "$RW" -- /usr/bin/true
        else TMPDIR=$SRT_TMPDIR node "$SRT_CLI" --settings "$WORK/srt.json" -- /usr/bin/true; fi
        ts+=($((($(up) - t0) * 10)))
      done
      printf '  %-10s median %5d (10 ms resolution, /proc/uptime)\n' "$name" "$(printf '%s\n' "${ts[@]}" | sort -n | sed -n 10p)"
    done
  fi
} | tee "$OUT/latency.txt"
cd "$HERE" || exit 1
if [[ ${ONLY:-all} == latency ]]; then
  find "$OUT" -type f -exec sed -i -e "s#$WORK#<WORK>#g" -e "s#$TOOLS#<TOOLS>#g" -e "s#$REALHOME/#<HOME>/#g" {} +
  exit 0
fi

# ---------------------------------------------------------------- footprint
{
  echo "install footprint:"
  echo "  sbx binary:        $(du -h "$SBX" | cut -f1)  ($(file -b "$SBX" | cut -d, -f1-2))"
  echo "  srt package:       $(du -sh "${SRT_CLI%/node_modules/*}/node_modules" | cut -f1) node_modules ($(ls "${SRT_CLI%/node_modules/*}/node_modules" | wc -l) top-level entries)"
  echo "  node runtime:      $(du -h "$(readlink -f "$(command -v node)")" | cut -f1) ($(node --version))"
  echo "  socat:             $(du -hL "$SOCAT" | cut -f1)   ripgrep: $(du -hL "$RG" | cut -f1)"
  echo "  bwrap:             $(du -h "$(command -v bwrap)" | cut -f1) $(stat -c '%A %U' "$(command -v bwrap)") (setuid: $([[ -u $(command -v bwrap) ]] && echo yes || echo no))"
} | tee "$OUT/footprint.txt"

# ---------------------------------------------------------------- matrix
{
  echo "# sbx vs srt: results"
  echo
  echo '```'; cat "$OUT/host.txt"; echo '```'
  echo
  echo "| ID | scenario | sbx | srt |"
  echo "|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}' "$OUT/results.tsv"
  echo
  echo "## srt with the benchmark policy changed in one place each"
  echo
  echo "| ID | case | srt |"
  echo "|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | %s |\n", $1, $2, $4}' "$OUT/variants.tsv"
  echo
  echo "## Ergonomics"
  echo
  echo "| ID | case | sbx | srt |"
  echo "|---|---|---|---|"
  awk -F'\t' '{printf "| %s | %s | `%s` | `%s` |\n", $1, $2, $3, $4}' "$OUT/ergonomics.tsv"
  echo
  echo '```'; cat "$OUT/latency.txt" "$OUT/footprint.txt" "$OUT/canaries.txt"; echo '```'
  echo
  echo "## Evidence"
  echo
  cat "$OUT/evidence.md"
} >"$OUT/results.md"
# Local paths are noise in a shared report. The placeholders cannot be read
# as shell syntax, and HOME is replaced only as a path prefix, so a policy
# entry such as "/root" survives when HOME=/root.
find "$OUT" -type f -exec sed -i -e "s#$WORK#<WORK>#g" -e "s#$TOOLS#<TOOLS>#g" -e "s#$REALHOME/#<HOME>/#g" {} +
echo "wrote $OUT/results.md"
