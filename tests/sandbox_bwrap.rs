//! Integration suite for the bwrap argv builder (issue #6) — spawns real
//! bwrap sandboxes from `sbx::bwrap::build()`'s output and proves the
//! acceptance criteria end-to-end.
//!
//! Why the STANDARD harness (contrast with sandbox_init.rs's
//! `harness = false`, so no `Cargo.toml` `[[test]]` entry here):
//! sandbox_init needs the hand-rolled runner because its child roles are
//! the test binary itself and `unshare(CLONE_NEWUSER)` requires a
//! single-threaded process. Here every bwrap runs in its OWN spawned
//! process (bwrap unshares in the child, never in the test process) and
//! the payloads are `/bin/sh -c` scripts — no self-re-exec, no
//! single-thread constraint ⇒ libtest's default parallel harness is safe.
//! Scenarios still print house-format `PASS {name}` / `SKIP {name}:
//! {reason}` lines and bounded-wait every spawn (D19/R12 discipline).
//!
//! Gating: one `OnceLock` probe, initialized exactly once — `find_bwrap`
//! (skip: `BWRAP_SKIP`), `--version` parsed against `BWRAP_MIN` (skip:
//! `BWRAP_OLD_SKIP`), then a live smoke through the PRODUCTION pipeline
//! itself — materialize → `build()` → `Launch::command()` (skip:
//! `USERNS_SKIP` on AppArmor/seccomp-style blocks; every probe failure
//! prints its captured rc/stderr diagnostic first, so a CI skip names
//! its own cause). On a host without bwrap (local WSL) all nine
//! scenarios print SKIP and the suite exits 0; CI installs bubblewrap
//! and must show nine PASS lines.
//!
//! The probe initializer also pollutes the harness environment with
//! `SBX_IT_SECRET` — the sentinel `secret-env-absent` proves never
//! crosses into the sandbox (the `env_clear` + `--clearenv` chain, AC-ii).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sbx::bwrap::etc::session_layout;
use sbx::bwrap::version::{BWRAP_MIN, find_bwrap, parse_version};
use sbx::bwrap::{Build, build};
use sbx::policy::Policy;

/// Prefix of every payload marker line on stdout (suite convention — the
/// sandbox_init `SBX-IT-MARKER` twin).
const MARKER: &str = "SBX-BW-MARKER";

/// SKIP reason strings. The first two are VERBATIM the sandbox_init.rs
/// pins (same causes, same words — pinned there at lines 136–137);
/// `BWRAP_OLD_SKIP` is this suite's one genuinely new cause (the binary
/// exists but predates `--disable-userns`).
const USERNS_SKIP: &str = "unprivileged userns unavailable (AppArmor? CI: sysctl kernel.apparmor_restrict_unprivileged_userns=0)";
const BWRAP_SKIP: &str = "bwrap not installed (CI: apt-get install bubblewrap)";
const BWRAP_OLD_SKIP: &str =
    "bwrap too old: --disable-userns needs >= 0.8 (CI: apt-get install bubblewrap)";

/// The parent-env pollution sentinel (design §2.7): planted in the harness
/// environment by the probe initializer; `secret-env-absent` asserts it
/// appears nowhere inside the sandbox.
const SENTINEL_ENV: &str = "SBX_IT_SECRET";
const SENTINEL: &str = "sbx-secret-sentinel-0xDEADBEEF";

/// Every wait in this suite is bounded by this deadline (the sandbox_init
/// 5 s discipline).
const BOUND: Duration = Duration::from_secs(5);

/// The infra env trio every sandbox gets (Q3/Q7) — pinned literals, also
/// asserted by the argv goldens.
const EXPECTED_INFRA_ENV: [&str; 3] = [
    "HOME=/root",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TMPDIR=/tmp",
];

/// `PWD=/work` — bwrap ALWAYS exports PWD (bubblewrap.c v0.9.0 main():
/// `xsetenv ("PWD", new_cwd, 1)` runs after the --clearenv/--setenv parse
/// handling and before the payload fork/exec; bwrap.1: "--clearenv … Unset
/// all environment variables, except for PWD and any that are subsequently
/// set by --setenv"). With `--chdir /work` the value is deterministic.
const EXPECTED_PWD: &str = "PWD=/work";

/// The live smoke (design §2.7 gate step 3, review C1): the PRODUCTION
/// pipeline — materialize a scratch session, `build()` the `BASE_POLICY`
/// (ro `/usr`, mode none) around `/bin/true`, spawn via
/// `Launch::command()`. A hand-rolled argv is exactly the drift class
/// review C1 caught: the first version shipped only the `/bin` shim, so
/// dynamically-linked `/bin/true` never found its `/lib64` loader
/// (`PT_INTERP` resolves inside the new root), the smoke failed on every
/// real host, and the whole suite would silently skip with the WRONG
/// reason. Through `build()` the gate proves exactly what every scenario
/// needs — the full flag block, all four usr-merge shims, the
/// infra/generated `/etc` binds, the session leaves — and cannot drift
/// from it again. Failure to run THIS (AppArmor-blocked userns, seccomp,
/// missing `/usr` …) skips the suite with `USERNS_SKIP`.
fn smoke_launch(bwrap: &Path) -> Result<Outcome, String> {
    let session = TempSession::new("probe-smoke");
    let policy = Policy::from_json_str(BASE_POLICY).expect("BASE_POLICY must parse");
    let empty = no_env();
    let command = [OsString::from("/bin/true")];
    let input = Build {
        policy: &policy,
        session_dir: &session.dir,
        bwrap_path: bwrap,
        command: &command,
        cwd: None,
        passed_env: &empty,
    };
    // The run_payload pipeline with `/bin/true` instead of a `/bin/sh`
    // script (the smoke needs no shell — only the loader + coreutils-free
    // exec).
    session_layout(&session.dir)
        .materialize()
        .map_err(|e| format!("materialize {}: {e}", session.dir.display()))?;
    let launch = build(&input).map_err(|e| format!("build: {e}"))?;
    run_bounded(launch.command(), "bwrap live smoke")
}

// ---------------------------------------------------------------------------
// gating probe
// ---------------------------------------------------------------------------

enum Probe {
    Ready(PathBuf),
    Skip(&'static str),
}

static PROBE: OnceLock<Probe> = OnceLock::new();

/// The one-time probe: find → version → live smoke (design §2.7). Also
/// plants the `SBX_IT_SECRET` parent-env pollution for `secret-env-absent`.
fn probe() -> &'static Probe {
    PROBE.get_or_init(|| {
        // SAFETY: this environment write happens exactly once, inside
        // OnceLock::get_or_init, before this process's first bwrap spawn;
        // every other test in this binary reads the environment only
        // through this same probe gate (OnceLock's initialization barrier
        // orders the write before every dependent spawn); SBX_IT_SECRET is
        // a novel name no other code reads; and libtest's own environment
        // reads complete at startup, before any test thread spawns. (The
        // fully race-free alternative — self-re-exec spawner roles — would
        // need `harness = false`, which the standard-harness decision for
        // this suite rules out.)
        unsafe {
            std::env::set_var(SENTINEL_ENV, SENTINEL);
        }

        let Some(bwrap) = find_bwrap() else {
            return Probe::Skip(BWRAP_SKIP);
        };
        // Version gate: {bwrap} --version, bounded, parsed with the strict
        // grammar; None ("unparseable") and below-min both mean not-usable
        // (fail-closed) and share the pinned OLD skip reason. Probe
        // failures print the captured diagnostics first (review S2): the
        // pinned reason strings stay byte-identical, but the CI log names
        // the actual cause.
        let mut version_cmd = Command::new(&bwrap);
        version_cmd.arg("--version").env_clear();
        let version_out = run_bounded(version_cmd, "bwrap --version");
        let version_ok = match &version_out {
            Ok(out) => {
                out.rc == 0
                    && parse_version(&out.stdout).is_some_and(|version| version >= BWRAP_MIN)
            }
            Err(_) => false,
        };
        if !version_ok {
            match &version_out {
                Ok(out) => house_print(&format!(
                    "bwrap version gate failed: rc={} stdout={:?} stderr={:?}",
                    out.rc,
                    out.stdout.trim(),
                    out.stderr.trim()
                )),
                Err(err) => house_print(&format!("bwrap version gate failed: {err}")),
            }
            return Probe::Skip(BWRAP_OLD_SKIP);
        }
        // Live smoke through the production pipeline (review C1 — see
        // smoke_launch). Any failure skips with the userns reason — the
        // scenarios cannot do less than this.
        match smoke_launch(&bwrap) {
            Ok(out) if out.rc == 0 => Probe::Ready(bwrap),
            Ok(out) => {
                house_print(&format!(
                    "bwrap live smoke failed: rc={} stderr={:?}",
                    out.rc,
                    out.stderr.trim()
                ));
                Probe::Skip(USERNS_SKIP)
            }
            Err(err) => {
                house_print(&format!("bwrap live smoke failed: {err}"));
                Probe::Skip(USERNS_SKIP)
            }
        }
    })
}

/// Gate entry for a scenario: the resolved bwrap path, or `None` after
/// printing the house-format SKIP line (the test still PASSES — SKIPs
/// exit 0, D19).
fn probe_ready(name: &str) -> Option<&'static Path> {
    match probe() {
        Probe::Ready(bwrap) => Some(bwrap.as_path()),
        Probe::Skip(reason) => {
            house_print(&format!("SKIP {name}: {reason}"));
            None
        }
    }
}

// ---------------------------------------------------------------------------
// spawn helpers (the sandbox_init wait_bounded/reader-thread discipline)
// ---------------------------------------------------------------------------

/// A reaped sandbox run: rc + fully drained stdio.
struct Outcome {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn reader_thread<R: Read + Send + 'static>(mut src: R) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = String::new();
        // Bounded: EOF arrives once every write end (bwrap, its pid-1
        // reaper, and the payload tree) is closed — i.e. after reap or
        // group-kill.
        let _ = src.read_to_string(&mut buf);
        buf
    })
}

/// `try_wait` polled at 10 ms; on deadline expiry SIGKILL the WHOLE
/// process group (the child leads it — `process_group(0)` ⇒ pgid == pid;
/// m4: bwrap grandchildren inherit the stdio pipes, so a child-only kill
/// could wedge the reader joins) BEFORE the child-only kill+reap. Copy of
/// sandbox_init's `wait_bounded_core(_, _, kill_group=true)`.
fn wait_bounded(child: &mut Child, what: &str) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + BOUND;
    loop {
        match child
            .try_wait()
            .map_err(|e| format!("try_wait {what}: {e}"))?
        {
            Some(status) => return Ok(status),
            None => {
                if Instant::now() >= deadline {
                    // SAFETY: kill(2) with the negative pid of the group
                    // THIS harness spawned the child to lead
                    // (process_group(0) ⇒ pgid == child.id()); ESRCH is
                    // fine (the group may already be gone) and the
                    // child-only kill+wait below reaps regardless.
                    unsafe {
                        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{what} timed out after 5s (killed)"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Spawn with piped stdio + reader threads + own process group, bounded
/// wait, threads ALWAYS joined before returning (never leak across tests).
fn run_bounded(mut cmd: Command, what: &str) -> Result<Outcome, String> {
    use std::os::unix::process::CommandExt;

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    // The HARNESS's spawn (nowhere near bwrap's own no-pre_exec fd
    // discipline): setpgid does not touch fd inheritance.
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| format!("spawn {what}: {e}"))?;
    let stdout = reader_thread(child.stdout.take().expect("stdout is piped"));
    let stderr = reader_thread(child.stderr.take().expect("stderr is piped"));
    let wait = wait_bounded(&mut child, what);
    let stdout = stdout
        .join()
        .map_err(|_| format!("{what}: stdout reader panicked"))?;
    let stderr = stderr
        .join()
        .map_err(|_| format!("{what}: stderr reader panicked"))?;
    let status = wait?;
    Ok(Outcome {
        rc: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// Per-scenario session directory: unique name (pid + scenario, so
/// parallel libtest threads never collide), `Drop` removes the tree
/// (errors ignored — cleanup is best effort).
struct TempSession {
    dir: PathBuf,
}

impl TempSession {
    fn new(scenario: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("sbx-bwrap-it-{}-{scenario}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // pristine start
        Self { dir }
    }
}

impl Drop for TempSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The full scenario pipeline: materialize the session layout → parse the
/// policy fixture → `sbx::bwrap::build` → spawn via `Launch::command()`
/// (which pins the `env_clear` spawner contract in EVERY scenario) →
/// bounded reap. Payload = `/bin/sh -c {script}`.
fn run_payload(
    bwrap: &Path,
    session: &TempSession,
    policy_json: &str,
    passed_env: &BTreeMap<String, OsString>,
    script: &str,
) -> Result<Outcome, String> {
    let policy = Policy::from_json_str(policy_json)
        .map_err(|e| format!("policy fixture must parse: {e}\n{policy_json}"))?;
    session_layout(&session.dir)
        .materialize()
        .map_err(|e| format!("materialize {}: {e}", session.dir.display()))?;
    let command: Vec<OsString> = ["/bin/sh", "-c", script]
        .iter()
        .map(OsString::from)
        .collect();
    let input = Build {
        policy: &policy,
        session_dir: &session.dir,
        bwrap_path: bwrap,
        command: &command,
        cwd: None,
        passed_env,
    };
    let launch = build(&input).map_err(|e| format!("build: {e}"))?;
    run_bounded(launch.command(), "bwrap payload")
}

// ---------------------------------------------------------------------------
// policy fixtures (inline JSON consts + a replacement helper — the
// policy.rs DRAFT/draft_with precedent)
// ---------------------------------------------------------------------------

/// The scenario base policy: ro /usr (payload tooling: sh, grep, tr, cat,
/// id, whoami, unshare, env, touch, ls — all from the /usr bind on noble),
/// everything else empty. Each scenario replaces exactly what it pins.
const BASE_POLICY: &str = r#"{
  "version": 1,
  "filesystem": { "ro": ["/usr"], "rw": [], "deny": [] },
  "network": { "mode": "none", "allow": [], "ports": [] },
  "env": { "pass": [], "set": {} },
  "limits": { "timeout": "120s", "output_bytes": 10485760 }
}"#;

fn policy_with(replacements: &[(&str, &str)]) -> String {
    let mut json = BASE_POLICY.to_owned();
    for (from, to) in replacements {
        assert!(json.contains(from), "fixture lacks {from:?}");
        json = json.replace(from, to);
    }
    json
}

fn no_env() -> BTreeMap<String, OsString> {
    BTreeMap::new()
}

// ---------------------------------------------------------------------------
// marker/assertion helpers
// ---------------------------------------------------------------------------

/// The contents of every `{MARKER} {prefix}…` line, in stdout order.
fn marker_lines<'a>(out: &'a Outcome, prefix: &str) -> Vec<&'a str> {
    let full = format!("{MARKER} {prefix}");
    out.stdout
        .lines()
        .filter_map(|line| line.strip_prefix(&full))
        .collect()
}

fn has_marker(out: &Outcome, text: &str) -> bool {
    out.stdout.contains(&format!("{MARKER} {text}"))
}

/// Print a house-format line (`PASS {name}` / `SKIP {name}: {reason}`) so
/// it is VISIBLE in `cargo test` logs: libtest captures per-test
/// `print!`/`eprintln!` output of PASSING tests (shown only on failure),
/// but a direct write through the `std::io::stdout()` handle bypasses the
/// thread-local capture sink (probe-verified on this toolchain). The CI
/// verification step greps these lines from the test-job log (design §3)
/// — hence they must not be captured. Errors are ignored (output-only,
/// EPIPE-safe: std ignores SIGPIPE, so a closed pipe is just an Err).
fn house_print(line: &str) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
}

/// rc 0 + silent stderr (the house success shape — sandbox_init's
/// assert_success precedent).
fn assert_clean_success(out: &Outcome) {
    assert_eq!(out.rc, 0, "payload rc (stderr: {:?})", out.stderr);
    assert!(
        out.stderr.trim().is_empty(),
        "stderr must be silent: {:?}",
        out.stderr
    );
}

// ---------------------------------------------------------------------------
// the nine scenarios
// ---------------------------------------------------------------------------

/// AC-i: nothing outside the allow list is visible. The allow-listed set
/// (policy /usr + the infra/generated /etc entries + the session leaves)
/// all exist; host paths nobody bound (/home, /opt, /var, /srv, /mnt,
/// /sys, /etc/shadow, /etc/machine-id) do NOT; /etc/passwd is the
/// synthetic one (Q7).
#[test]
fn allowlist_only_visible() {
    const NAME: &str = "allowlist-only-visible";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let script = r#"
for p in /usr /bin/sh /etc/passwd /etc/hosts /root /tmp /work /etc/ssl; do
  if test -e "$p"; then echo "SBX-BW-MARKER exists $p"; else echo "SBX-BW-MARKER MISSING $p"; fi
done
for p in /home /opt /var /srv /mnt /sys /etc/shadow /etc/machine-id; do
  if test -e "$p"; then echo "SBX-BW-MARKER LEAK $p"; fi
done
echo "SBX-BW-MARKER passwd-count=$(grep -c '^root:x:0:0:root:/root:/bin/bash$' /etc/passwd)"
"#;
    let out = run_payload(bwrap, &session, BASE_POLICY, &no_env(), script)
        .expect("allowlist-only-visible payload run");
    assert_clean_success(&out);
    for path in [
        "/usr",
        "/bin/sh", // the usr-merge shim resolving through the /usr bind
        "/etc/passwd",
        "/etc/hosts",
        "/root",
        "/tmp",
        "/work",
        "/etc/ssl",
    ] {
        assert!(
            has_marker(&out, &format!("exists {path}")),
            "allow-listed {path} must exist:\n{}",
            out.stdout
        );
    }
    assert!(
        !out.stdout.contains(&format!("{MARKER} MISSING")),
        "an allow-listed path is missing:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} LEAK")),
        "a non-allow-listed path is visible:\n{}",
        out.stdout
    );
    assert!(
        has_marker(&out, "passwd-count=1"),
        "/etc/passwd must be the synthetic one (exactly the pinned root \
         entry):\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}

/// AC-ii: a parent-process secret env var is not readable anywhere in the
/// sandbox. The harness environment carries `SBX_IT_SECRET` (planted by
/// the probe initializer); the sandbox must show it in NO dump — `env`,
/// `/proc/1/environ`, `/proc/self/environ`, nor any `/proc/*/environ` —
/// and the payload env must be EXACTLY the allow-listed set.
///
/// `/proc/1/environ` is the load-bearing dump: bwrap's pid-1 reaper is a
/// fork/clone of the bwrap main process, so its environ block is bwrap's
/// own exec environment — `Launch::command()`'s `env_clear()` is what
/// makes it empty (`--clearenv` alone would NOT: it only cleans the
/// payload). The exact-env pin additionally records bwrap's own
/// unconditional `PWD` export (see `EXPECTED_PWD`).
#[test]
fn secret_env_absent() {
    const NAME: &str = "secret-env-absent";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let policy = policy_with(&[(r#""pass": []"#, r#""pass": ["LANG"]"#)]);
    let mut passed_env = BTreeMap::new();
    passed_env.insert("LANG".to_owned(), OsString::from("C.UTF-8"));
    let script = format!(
        r#"
env | sort | while IFS= read -r line; do echo "SBX-BW-MARKER env $line"; done
cat /proc/1/environ | tr '\0' '\n' | while IFS= read -r line; do echo "SBX-BW-MARKER pid1 $line"; done
cat /proc/self/environ | tr '\0' '\n' | while IFS= read -r line; do echo "SBX-BW-MARKER self $line"; done
for f in /proc/[0-9]*/environ; do
  if grep -q '{SENTINEL}' "$f" 2>/dev/null; then echo "SBX-BW-MARKER grep-hit $f"; fi
done
echo "SBX-BW-MARKER dumps-done"
"#
    );
    let out = run_payload(bwrap, &session, &policy, &passed_env, &script)
        .expect("secret-env-absent payload run");
    assert_clean_success(&out);
    assert!(
        has_marker(&out, "dumps-done"),
        "the dump script must run to completion:\n{}",
        out.stdout
    );
    // The sentinel appears in NO dump line (env, pid1, self) and no
    // /proc/*/environ grep hit.
    assert!(
        !out.stdout.contains(SENTINEL),
        "{SENTINEL_ENV} leaked into the sandbox:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} grep-hit")),
        "the sentinel is readable in some /proc/*/environ:\n{}",
        out.stdout
    );
    // /proc/1/environ is EMPTY: zero pid1 lines. This is the end-to-end
    // env_clear pin — bwrap's spawn environment (which --clearenv does
    // NOT clean) never existed.
    assert!(
        marker_lines(&out, "pid1 ").is_empty(),
        "/proc/1/environ must be empty (Launch::command()'s env_clear \
         contract):\n{}",
        out.stdout
    );
    // The payload env is EXACTLY the expected set: infra trio + the one
    // passed LANG + bwrap's own PWD export (EXPECTED_PWD) — no PWD leak
    // from the harness (there is none: env_clear), no sentinel, nothing
    // else. Both the `env` dump and /proc/self/environ must agree.
    let mut expected: Vec<&str> = vec!["LANG=C.UTF-8", EXPECTED_PWD];
    expected.extend(EXPECTED_INFRA_ENV);
    expected.sort_unstable();
    let mut env_lines = marker_lines(&out, "env ");
    env_lines.sort_unstable();
    assert_eq!(
        env_lines, expected,
        "payload env must be exactly the allow-listed set:\n{}",
        out.stdout
    );
    let mut self_lines = marker_lines(&out, "self ");
    self_lines.sort_unstable();
    assert_eq!(
        self_lines, expected,
        "/proc/self/environ must match the env dump:\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}

/// AC-iii: writes outside the session directory fail — with the bwrap
/// semantics pinned from source:
///
/// - `/work`, `/root`, `/tmp` (the session leaves) are writable, and the
///   written files are visible HOST-SIDE under `session/{work,home,tmp}/`
///   (bind-through).
/// - `/usr/nope` is REFUSED: the policy ro bind is MS_RDONLY ⇒ EROFS for
///   everyone, capabilities or not. `/usr/nope` never appears on the host.
/// - `/etc/nope` and `/nope` — DEVIATION from the design sketch, verified
///   against bubblewrap.c v0.9.0: the sandbox's scaffold directories (/ =
///   `mkdir ("newroot", 0755)` under `umask (0)`, /etc =
///   `mkdir_with_parents` parents) live on sandbox-private tmpfs and are
///   owned by the sandbox uid — which equals bwrap's real uid (default
///   `opt_sandbox_uid = real_uid`; in the sbx chain that is 0 via #5's id
///   maps), and the payload IS that uid. DAC owner-write needs no
///   capability, so `--cap-drop ALL` does not refuse these: the writes
///   SUCCEED — onto the sandbox-local tmpfs. The security property (the
///   AC's point) is host-side: neither `/etc/nope` nor `/nope` may exist
///   on the host afterwards, and both vanish with the sandbox. Recorded
///   for the #14 threat model (scaffold-write semantics).
#[test]
fn writes_outside_session_fail() {
    const NAME: &str = "writes-outside-session-fail";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let script = r#"
if touch /work/ok 2>/dev/null; then echo "SBX-BW-MARKER wrote /work"; else echo "SBX-BW-MARKER FAILED /work"; fi
if touch /root/ok 2>/dev/null; then echo "SBX-BW-MARKER wrote /root"; else echo "SBX-BW-MARKER FAILED /root"; fi
if touch /tmp/ok 2>/dev/null; then echo "SBX-BW-MARKER wrote /tmp"; else echo "SBX-BW-MARKER FAILED /tmp"; fi
if touch /usr/nope 2>/dev/null; then echo "SBX-BW-MARKER LEAK-write /usr"; else echo "SBX-BW-MARKER refused /usr"; fi
if touch /etc/nope 2>/dev/null; then echo "SBX-BW-MARKER wrote-scaffold /etc"; else echo "SBX-BW-MARKER refused /etc"; fi
if touch /nope 2>/dev/null; then echo "SBX-BW-MARKER wrote-scaffold /"; else echo "SBX-BW-MARKER refused /"; fi
"#;
    let out = run_payload(bwrap, &session, BASE_POLICY, &no_env(), script)
        .expect("writes-outside-session-fail payload run");
    assert_clean_success(&out);
    // The session leaves are writable.
    for dir in ["/work", "/root", "/tmp"] {
        assert!(
            has_marker(&out, &format!("wrote {dir}")),
            "{dir} must be writable:\n{}",
            out.stdout
        );
    }
    assert!(
        !out.stdout.contains(&format!("{MARKER} FAILED")),
        "a session leaf refused a write:\n{}",
        out.stdout
    );
    // The ro-bound allow-list entry refuses writes (EROFS).
    assert!(
        has_marker(&out, "refused /usr"),
        "/usr is a read-only bind — writes must fail:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} LEAK-write")),
        "a read-only bind accepted a write:\n{}",
        out.stdout
    );
    // Scaffold dirs (/, /etc): source-verified owner-writable sandbox
    // tmpfs (see the fn doc) — pinned as wrote-scaffold; if a future
    // bwrap hardens these, this assertion fails loudly and a human
    // reviews (the brittle-golden philosophy).
    assert!(
        has_marker(&out, "wrote-scaffold /etc"),
        "expected the source-verified scaffold semantics for /etc:\n{}",
        out.stdout
    );
    assert!(
        has_marker(&out, "wrote-scaffold /"),
        "expected the source-verified scaffold semantics for /:\n{}",
        out.stdout
    );
    // Host-side: the session bind-through landed on the host, and NOTHING
    // outside the session did.
    for leaf in ["work", "home", "tmp"] {
        assert!(
            session.dir.join(leaf).join("ok").exists(),
            "session {leaf}/ok must be visible host-side (bind-through)"
        );
    }
    assert!(
        !Path::new("/usr/nope").exists(),
        "/usr/nope must not exist on the host"
    );
    assert!(
        !Path::new("/etc/nope").exists(),
        "/etc/nope must not exist on the host (scaffold writes are sandbox-local)"
    );
    assert!(
        !Path::new("/nope").exists(),
        "/nope must not exist on the host (scaffold writes are sandbox-local)"
    );
    house_print(&format!("PASS {NAME}"));
}

/// AC-i (deny half, Q5): a deny path is masked by a tmpfs mounted over
/// it — its CONTENTS are gone — while the parent stays visible.
///
/// DEVIATION from the design sketch (`test -e → LEAK`), forced by mount
/// semantics: a `--tmpfs` mask KEEPS the mountpoint visible as an
/// (empty) directory, so `test -e` cannot distinguish masked from
/// present. The true masking assertion is content-emptiness — pinned
/// here, with a host-side non-empty sanity check first so the assertion
/// can never be vacuous. (File-valued deny dests remain a documented v1
/// limitation — design §Risks; #11/#13 follow-ups.)
#[test]
fn deny_masks_path() {
    const NAME: &str = "deny-masks-path";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    // Vacuity guard: the mask assertion only means something if the host
    // directory is non-empty (true on noble; checked BEFORE the run).
    let host_entries = std::fs::read_dir("/usr/share/doc")
        .map(|dir| dir.count())
        .unwrap_or(0);
    assert!(
        host_entries > 0,
        "host /usr/share/doc is empty or unreadable — the mask assertion would be vacuous"
    );
    let session = TempSession::new(NAME);
    let policy = policy_with(&[(r#""deny": []"#, r#""deny": ["/usr/share/doc"]"#)]);
    let script = r#"
if test -d /usr/share/doc; then echo "SBX-BW-MARKER mask-dir-exists"; else echo "SBX-BW-MARKER mask-dir-MISSING"; fi
echo "SBX-BW-MARKER doc-entries=$(ls -A /usr/share/doc 2>/dev/null | wc -l)"
if test -d /usr/share; then echo "SBX-BW-MARKER parent-exists"; else echo "SBX-BW-MARKER parent-MISSING"; fi
"#;
    let out = run_payload(bwrap, &session, &policy, &no_env(), script)
        .expect("deny-masks-path payload run");
    assert_clean_success(&out);
    assert!(
        has_marker(&out, "mask-dir-exists"),
        "the tmpfs mask keeps the mountpoint visible:\n{}",
        out.stdout
    );
    assert!(
        has_marker(&out, "doc-entries=0"),
        "the deny mask must empty /usr/share/doc (host has {host_entries} \
         entries):\n{}",
        out.stdout
    );
    assert!(
        has_marker(&out, "parent-exists"),
        "the parent of a deny path must stay visible:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} mask-dir-MISSING"))
            && !out.stdout.contains(&format!("{MARKER} parent-MISSING")),
        "unexpected MISSING marker:\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}

/// Requirement pin: `--disable-userns` end-to-end through the BUILDER's
/// flag set — creating a new userns from inside the sandbox must fail
/// (bwrap sets `user.max_user_namespaces` to its last needed slot before
/// entering the second-level userns, so the kernel answers ENOSPC on
/// noble — the `mutation-eperm-bwrap` finding; any failure errno proves
/// the block, success does not).
#[test]
fn userns_disabled() {
    const NAME: &str = "userns-disabled";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let script = r#"
if unshare -U true 2>/dev/null; then echo "SBX-BW-MARKER userns-ALLOWED"; else echo "SBX-BW-MARKER userns-blocked"; fi
"#;
    let out = run_payload(bwrap, &session, BASE_POLICY, &no_env(), script)
        .expect("userns-disabled payload run");
    assert_clean_success(&out);
    assert!(
        has_marker(&out, "userns-blocked"),
        "unshare(CLONE_NEWUSER) must be blocked by --disable-userns:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} userns-ALLOWED")),
        "a nested userns was created despite --disable-userns:\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}

/// Requirement pin: fresh pidns — pid 1 is the bwrap reaper (issue text:
/// never the host's procfs), the harness's pid is invisible, and only
/// sandbox pids exist. The harness pid crosses purely through the policy
/// `env.set` → `--setenv` chain.
#[test]
fn proc_isolation() {
    const NAME: &str = "proc-isolation";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let pid = std::process::id();
    let policy = policy_with(&[(
        r#""set": {}"#,
        &format!(r#""set": {{ "HARNESS_PID": "{pid}" }}"#),
    )]);
    // Pure-shell /proc scan (glob + prefix-strip builtins — the
    // sigpipe-default style precedent).
    let script = r#"
echo "SBX-BW-MARKER pid1=$(cat /proc/1/cmdline | tr '\0' ' ')"
if test -e "/proc/$HARNESS_PID"; then echo "SBX-BW-MARKER host-pid-LEAK"; else echo "SBX-BW-MARKER host-pid-absent"; fi
for p in /proc/[0-9]*; do
  echo "SBX-BW-MARKER pid ${p#/proc/}"
done
"#;
    let out = run_payload(bwrap, &session, &policy, &no_env(), script)
        .expect("proc-isolation payload run");
    assert_clean_success(&out);
    // Pid 1 is bwrap: the reaper is a fork of the bwrap main process and
    // never execs, so its cmdline is the full bwrap argv.
    let pid1 = marker_lines(&out, "pid1=");
    assert_eq!(pid1.len(), 1, "exactly one pid1 marker:\n{}", out.stdout);
    assert!(
        pid1[0].contains("bwrap"),
        "pid 1 must be bwrap (issue text; the reaper never execs): {:?}",
        pid1[0]
    );
    // The harness pid does not exist in the fresh pidns.
    assert!(
        has_marker(&out, "host-pid-absent"),
        "the host pid must be invisible in the sandbox pidns:\n{}",
        out.stdout
    );
    assert!(
        !out.stdout.contains(&format!("{MARKER} host-pid-LEAK")),
        "the host pid is visible inside the sandbox:\n{}",
        out.stdout
    );
    // Only sandbox pids: the tree is tiny (reaper 1, sh 2, transient
    // children) — anything ≥ 21 could only be a host pid leak.
    let pids: Vec<u32> = marker_lines(&out, "pid ")
        .iter()
        .map(|text| {
            text.parse()
                .unwrap_or_else(|e| panic!("pid marker {text:?} is not a number: {e}"))
        })
        .collect();
    assert!(pids.contains(&1), "pid 1 must be listed: {pids:?}");
    assert!(
        pids.iter().all(|p| *p <= 20),
        "the sandbox pidns holds only the small sandbox tree: {pids:?}"
    );
    assert!(
        !pids.contains(&pid),
        "the harness pid {pid} must not appear: {pids:?}"
    );
    house_print(&format!("PASS {NAME}"));
}

/// Requirement pin (Q7 identity, review C2): the sandbox uid PASSES
/// THROUGH the spawner's real uid — this suite spawns bwrap directly from
/// the unprivileged harness, and bubblewrap.c v0.9.0 defaults
/// `opt_sandbox_uid = real_uid` (:2796–7), so the uid here is the
/// runner's, NOT 0. The uid-0 identity of the production chain (where
/// the spawner is `__init`, already ns-root) is pinned end-to-end by
/// sandbox_init.rs `full-chain-bwrap`. `whoami` is deliberately NOT
/// pinned here: the synthetic passwd describes root only (Q7), so at a
/// non-zero uid it legitimately cannot resolve. The uid-independent pins:
/// the UTS hostname is `sandbox` (read via /proc/sys — no hostname(1)
/// dependency), the generated resolv.conf points at the netns-local
/// resolver, and /etc/group is the synthetic one.
#[test]
fn identity_and_hostname() {
    const NAME: &str = "identity-and-hostname";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    // SAFETY: getuid(2) takes no arguments, never fails, and is
    // async-signal-safe. The harness's real uid is exactly the value
    // bubblewrap maps into the sandbox (opt_sandbox_uid default).
    let expected_uid = unsafe { libc::getuid() };
    let script = r#"
echo "SBX-BW-MARKER uid=$(id -u)"
echo "SBX-BW-MARKER hostname=$(cat /proc/sys/kernel/hostname)"
echo "SBX-BW-MARKER resolv=$(cat /etc/resolv.conf)"
echo "SBX-BW-MARKER group=$(cat /etc/group)"
"#;
    let out = run_payload(bwrap, &session, BASE_POLICY, &no_env(), script)
        .expect("identity-and-hostname payload run");
    assert_clean_success(&out);
    let expected = [
        format!("uid={expected_uid}"),
        "hostname=sandbox".to_owned(),
        "resolv=nameserver 127.0.0.1".to_owned(),
        "group=root:x:0:".to_owned(),
    ];
    for expected in &expected {
        assert!(
            has_marker(&out, expected),
            "missing identity marker {expected:?}:\n{}",
            out.stdout
        );
    }
    house_print(&format!("PASS {NAME}"));
}

/// AC-ii (explicit half, Q4): explicit mode exports exactly the eight
/// proxy vars with the consts-derived pinned values, alongside the infra
/// trio (+ bwrap's own PWD — see `EXPECTED_PWD`).
#[test]
fn explicit_proxy_env() {
    const NAME: &str = "explicit-proxy-env";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let policy = policy_with(&[(r#""mode": "none""#, r#""mode": "explicit""#)]);
    let script = r#"
env | sort | while IFS= read -r line; do echo "SBX-BW-MARKER env $line"; done
"#;
    let out = run_payload(bwrap, &session, &policy, &no_env(), script)
        .expect("explicit-proxy-env payload run");
    assert_clean_success(&out);
    // Pinned values (consts::EXPLICIT_TCP_PORT / SANDBOX_ADDR literals —
    // deliberately spelled out: the argv goldens pin the same strings).
    const PROXY: &str = "http://127.0.0.1:3128";
    const NO_PROXY: &str = "localhost,127.0.0.1,10.255.255.1";
    let mut expected: Vec<String> = EXPECTED_INFRA_ENV
        .into_iter()
        .chain([EXPECTED_PWD])
        .map(str::to_owned)
        .collect();
    for name in [
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    ] {
        expected.push(format!("{name}={PROXY}"));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        expected.push(format!("{name}={NO_PROXY}"));
    }
    expected.sort();
    let mut env_lines: Vec<String> = marker_lines(&out, "env ")
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    env_lines.sort();
    assert_eq!(
        env_lines, expected,
        "explicit mode must export exactly the pinned proxy + infra env:\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}

/// AC-ii (transparent half, Q4): non-explicit modes export ZERO proxy
/// vars (any case) — the env is exactly the infra trio + bwrap's PWD.
#[test]
fn transparent_no_proxy_env() {
    const NAME: &str = "transparent-no-proxy-env";
    let Some(bwrap) = probe_ready(NAME) else {
        return;
    };
    let session = TempSession::new(NAME);
    let policy = policy_with(&[(r#""mode": "none""#, r#""mode": "transparent""#)]);
    let script = r#"
env | sort | while IFS= read -r line; do echo "SBX-BW-MARKER env $line"; done
"#;
    let out = run_payload(bwrap, &session, &policy, &no_env(), script)
        .expect("transparent-no-proxy-env payload run");
    assert_clean_success(&out);
    let mut env_lines = marker_lines(&out, "env ");
    for line in &env_lines {
        assert!(
            !line.to_lowercase().contains("proxy"),
            "transparent mode must export no proxy vars (any case): {line:?}"
        );
    }
    let mut expected: Vec<&str> = vec![EXPECTED_PWD];
    expected.extend(EXPECTED_INFRA_ENV);
    expected.sort_unstable();
    env_lines.sort_unstable();
    assert_eq!(
        env_lines, expected,
        "the env must be exactly the infra trio + PWD:\n{}",
        out.stdout
    );
    house_print(&format!("PASS {NAME}"));
}
