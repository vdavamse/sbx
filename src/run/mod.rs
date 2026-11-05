//! `sbx run` — the sandbox lifecycle (issue #10).
//!
//! 1. **Contract.** `sbx run --policy P --session-dir D [--cwd C] [--timeout T]
//!    [--relay-idle-timeout T] [--audit F] -- CMD…` runs `CMD` verbatim (no shell) inside the bwrap
//!    sandbox built from the policy, with sbx's transparent/explicit proxies and
//!    fake-IP DNS in a private network namespace. Exit codes: §6 below.
//! 2. **Startup order (S0–S18).** Signals are blocked before any thread exists
//!    (S2); the session lock is taken before materialize and before any audit
//!    row (S4); the audit file opens before anything is spawned (S5); the only
//!    spawn before the window is `bwrap --version` (S6); the `__init` spawn is
//!    the only one inside the fd window (S9–S11); the network runtime is first
//!    polled and reported ready before the go byte is sent (S16–S17). S8a
//!    (#39/#40) runs after the argv is built and before the spawn: the
//!    pre-launch guard verifies every path bwrap resolves under a bind
//!    cover, rw or ro (`bwrap::guard`), and refuses with rc 125 if any is a symlink,
//!    is missing or has the wrong type, or if a deny is reachable through a
//!    host symlink alias. Nothing is spawned, and nothing is created outside the session
//!    directory and the audit log.
//! 3. **Teardown and pid-1 identity.** Pid 1 of the sandbox is learned from
//!    bwrap's `--info-fd` (`child-pid`), verified (`PPid == bwrap`, `NSpid` last
//!    `== 1`), and killed through its pidfd. Waiting on that pidfd proves the whole
//!    pid namespace is gone. bwrap is reaped last, the pumps are drained, and the
//!    exit row is written.
//!    (Issue #11: the network-mode refusal happens at S14. `__init` reports its
//!    achieved mode or a staged failure over the control socket; a refusal is
//!    rc 125 with the shared classifier's text and the `sbx check` hint, and an
//!    explicit fallback prints one notice and is recorded as `net_mode`.)
//! 4. **Exit codes.** The command's own code; 124 timeout; 125 sbx failure;
//!    128+N terminated by signal N (sbx's own signal or a signalled payload that
//!    bwrap relayed); 2 usage (clap). A policy whose network mode the host
//!    cannot provide is 125 (issue #11). A payload that itself exits 124/125 is
//!    indistinguishable by rc alone — the audit `outcome` disambiguates.
//! 5. **Signals.** SIGTERM, SIGINT, SIGHUP and SIGQUIT are collected by signalfd
//!    (no handlers). A signal the caller left ignored stays ignored. On receipt the
//!    sandbox is SIGKILLed at once and sbx exits 128+N without re-raising.
//! 6. **Stdio.** stdout and stderr are always pipes, pumped through a shared
//!    `limits.output_bytes` budget; the excess is drained and discarded. stdin is
//!    inherited unless it is a terminal, in which case it is pumped only when sbx
//!    is the terminal's foreground group (otherwise /dev/null). The payload never
//!    sees a tty on fds 0–2.
//! 7. **Audit.** `--audit` writes one JSON object per line (schema: notes §5),
//!    append-only, 0600, regular file only, never inside the session directory.
//!    The exit row's last key `net_mode` (issue #11) is the achieved network
//!    mode (`transparent` or `explicit`), or null when setup never completed.
//!    A write failure is fail-closed (Q7). The exit row is always last. No fsync.
//! 8. **Supervision.** A failing or panicking network task, a dead network thread
//!    or an audit failure ends the run with 125 (the latch wakes the main loop).
//! 9. **Concurrency and session.** Each run has its own netns, DNS pool and
//!    listeners. Two runs on one session directory are refused (`sbx.lock`,
//!    flock). The session mtime is touched at start and end (#12). A session
//!    that `sbx gc` tombstones while the run is locking is detected and refused
//!    (125).
//! 10. **Limitations.** Pins (#40) make a cross-directory `rename(2)` or `link(2)`
//!     across a pinned boundary fail with EXDEV, so raw-rename tools (some
//!     package managers' atomic moves) fail inside a sandbox whose policy has a
//!     bind or deny under an `rw` path at depth 2 or more; `mv` copies
//!     instead. A missing deny path under an `rw` bind is refused (bwrap would
//!     create it on the host). The guard's check and bwrap's setup are separate
//!     steps: a writer outside the same policy can race them (R26): dests and
//!     sources on bwrap before 0.12.0, bind sources on every version. Connections still open at exit get no `close` row. The
//!     audit log is not fsynced. Socket families: only AF_UNIX, AF_INET,
//!     AF_INET6 and AF_NETLINK are creatable (issue #34; everything else is
//!     EAFNOSUPPORT, including AF_VSOCK), io_uring is ENOSYS, and 32-bit or
//!     x32 payloads are killed by the filter (SIGSYS, rc 159). See
//!     [`crate::bwrap::seccomp`]. Background-terminal stdin is /dev/null. Parent
//!     death: `__init` arms `PR_SET_PDEATHSIG = SIGKILL` right after its signal
//!     reset and refuses to continue unless its parent is the `run` pid it was
//!     given (`--parent-pid`), so a `run` that dies before teardown takes the
//!     chain with it. Teardown still kills pid 1 directly (the bwrap child's
//!     pdeathsig is bound to bwrap's own parent thread). Requires Linux >= 5.3
//!     (pidfd) and bubblewrap >= 0.8.
//! 11. **Landlock layer (issue #19, `--landlock` and `--landlock-bind-tcp`).**
//!     Off by default; the argv is then byte-identical to a run without the flag.
//!     With it on, `run` refuses `require` on a kernel below ABI 6 before anything
//!     is spawned (rc 125, [`crate::landlock::require_refusal`], S5b), opens sbx's
//!     own executable (S8b) and passes it to `__init` as `--exe-fd` (S9–S11), and
//!     bwrap runs the shim, which applies the rules and execs the payload. A status
//!     pipe (S8b, S9–S11) carries the shim's news back. The shim first writes a
//!     start marker, before any argument parsing. A failure adds its reason after
//!     the marker, then exits 125. After teardown, `run` reads the pipe:
//!     - no marker: the shim never started (bwrap's exec of it failed, or the
//!       dynamic loader did), so the outcome is `failed` with `sbx run: landlock:
//!       the shim did not start (rc N)`, rc 125;
//!     - marker and reason: `failed` with `sbx run: landlock: <reason>`, rc 125;
//!     - marker only: the shim started and nothing failed, so the outcome is
//!       unchanged, whatever the payload did (its own 125 included).
//!
//!     Outcomes that are already `failed` keep their own reason. See
//!     [`crate::landlock`] module docs point 9.

mod audit;
pub(crate) mod keepalive;
mod lifecycle;
mod mode;
mod plan;
mod serve;
mod session;
mod spawn;
mod stdio;
mod sys;

use std::convert::Infallible;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::bwrap::etc::session_layout;
use crate::bwrap::seccomp;
use crate::bwrap::version::{BwrapStatus, classify_version_output, find_bwrap};
use crate::bwrap::{Build, build};
use crate::dns::{DnsLimits, DnsServer, FakeIpMap};
use crate::host::facts::RunFacts;
use crate::init::fdpass;
use crate::init::fdpass::{AchievedMode, ListenerFds};
use crate::policy::Policy;
use crate::proxy::Proxy;
use sys::pollfd;

use audit::{AuditLog, exit_row_for, open_audit, ts};
use lifecycle::{Cause, Pid1, Sandbox, main_loop, supervise, teardown};
use mode::{effective_network, fallback_notice, refusal};
use plan::{
    absolutize, audit_inside_session, effective_timeout, exit_code, lexical_normalize, passed_env,
    sbx_diagnostic,
};
use serve::{Fault, FaultLatch, serve_tasks, start_net};
use session::SessionLock;
use spawn::{ChildFds, SetupEnd, init_command, wait_for_fds};
use stdio::{OutputBudget, Pumps};

/// Exit code for GNU-timeout-style timeouts.
pub(crate) const EXIT_TIMEOUT: i32 = 124;
/// Exit code for sbx-detected failures (Q1).
pub(crate) const EXIT_FAILURE: i32 = 125;
/// The 30 s budget for `__init` to hand over its listener fds.
pub(crate) const SETUP_TIMEOUT: Duration = crate::init::consts::GO_TIMEOUT;
/// How long the network runtime has to report readiness.
pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// Grace for bwrap's info JSON during teardown.
pub(crate) const INFO_GRACE: Duration = Duration::from_secs(1);
/// Per pidfd wait during teardown.
pub(crate) const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum wait for the stdio pumps after the sandbox is gone.
pub(crate) const PUMP_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// bwrap's info JSON is at most this many bytes; anything larger is unparseable.
pub(crate) const INFO_MAX_BYTES: usize = 4096;
/// The lock file inside the session directory.
pub(crate) const LOCK_FILE: &str = "sbx.lock";

/// The parsed `sbx run` invocation (cli.rs dispatch).
#[derive(Debug, Clone)]
pub struct RunArgs {
    pub policy: PathBuf,
    pub session_dir: PathBuf,
    pub cwd: Option<PathBuf>,
    /// None = the policy's `limits.timeout` (Q2).
    pub timeout: Option<Duration>,
    /// None = [`crate::proxy::Limits::default`]'s relay idle timeout (300 s).
    /// Accepted in `none` mode, where no relay exists (issue #29, C4).
    pub relay_idle_timeout: Option<Duration>,
    pub audit: Option<PathBuf>,
    /// The payload argv, verbatim (Q9).
    pub cmd: Vec<OsString>,
    /// Hidden fail-only test driver, forwarded to `__init` (issue #11, Q6).
    pub test_break_rules: bool,
    /// `--landlock` (issue #19); `Off` adds no layer.
    pub landlock: crate::landlock::Mode,
    /// `--landlock-bind-tcp` ports (issue #19), in command-line order.
    pub landlock_bind_tcp: Vec<u16>,
    /// `--keep-alive`: start a persistent session holder (issue #18).
    pub keep_alive: bool,
    /// `--idle-timeout` (keep-alive only); None = [`keepalive::limits::DEFAULT_IDLE`].
    pub idle_timeout: Option<Duration>,
    /// `--max-lifetime` (keep-alive only); None = the 8h default.
    pub max_lifetime: Option<Duration>,
}

/// An sbx-detected failure (rc 125). Display is the reason only; the `sbx run: `
/// prefix is composed at exactly one site (`report_failure`).
#[derive(Debug)]
pub struct RunError(String);

impl RunError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RunError {}

/// How the run ended (input to the exit code, the exit reason and the exit row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// bwrap exited normally with this status (payload rc; 128+N for a signalled payload).
    Exited(i32),
    /// bwrap itself was killed by a signal sbx did not send (OOM...).
    Signaled(i32),
    /// The effective timeout elapsed.
    TimedOut(Duration),
    /// sbx received TERM/INT/HUP/QUIT.
    Terminated(i32),
    /// An sbx-detected failure; the text is the reason.
    Failed(String),
}

/// The CLI seam. Pre-spawn failures return 125; every path after the `__init`
/// spawn ends in `process::exit` (the runtime is never dropped). `--keep-alive`
/// forks a session holder first (see [`keepalive::holder`]).
pub fn run(args: RunArgs) -> ExitCode {
    if args.keep_alive {
        return keepalive::holder::launch(args);
    }
    run_session(args, None)
}

/// The run body shared by a plain run (`hold` is `None`) and the session holder
/// (`hold` is `Some`, issue #18: it reports readiness to the launcher and the
/// session's exit rows carry `call_id` 0).
pub(crate) fn run_session(args: RunArgs, mut hold: Option<keepalive::holder::Hold>) -> ExitCode {
    let t0 = Instant::now();
    let mut audit: Option<Arc<AuditLog>> = None;
    let call_id = hold.is_some().then_some(0);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute(args, t0, &mut audit, &mut hold)
    }));
    std::panic::set_hook(previous_hook);
    let failure = match result {
        Ok(Ok(never)) => match never {},
        Ok(Err(Early::Failed(err))) => err.reason().to_owned(),
        Ok(Err(Early::Signal(sig))) => {
            let text = format!("terminated by signal {sig}");
            if let Some(h) = hold.as_mut() {
                h.fail(&text);
            }
            conclude(
                Outcome::Terminated(sig),
                audit.as_deref(),
                t0,
                Conclusion {
                    call_id,
                    ..Conclusion::default()
                },
            )
        }
        Ok(Err(Early::TimedOut(limit))) => {
            let text = format!("timed out after {limit:?}");
            if let Some(h) = hold.as_mut() {
                h.fail(&text);
            }
            conclude(
                Outcome::TimedOut(limit),
                audit.as_deref(),
                t0,
                Conclusion {
                    call_id,
                    ..Conclusion::default()
                },
            )
        }
        Err(payload) => format!("internal error: {}", panic_text(payload.as_ref())),
    };
    if let Some(h) = hold.as_mut() {
        h.fail(&failure);
    }
    report_failure(&failure, t0, audit.as_deref(), call_id)
}

/// Why `execute` stopped before the supervised phase: an sbx failure (125), a
/// signal (128+N) or the deadline (124) that hit a blocking pre-spawn step.
enum Early {
    Failed(RunError),
    Signal(i32),
    TimedOut(Duration),
}

impl From<RunError> for Early {
    fn from(err: RunError) -> Self {
        Early::Failed(err)
    }
}

/// Facts about the run that only the end of the run knows.
#[derive(Default)]
struct Conclusion {
    /// Persistent sessions only (issue #18): the call id of the exit row.
    call_id: Option<u32>,
    truncated: bool,
    poisoned: bool,
    stragglers: bool,
    cap: u64,
    /// The forwarded stderr ends mid-line: start sbx's lines on a fresh line.
    stderr_partial: bool,
    /// The network mode the sandbox actually got (`transparent` | `explicit`);
    /// `None` when setup never completed (issue #11, Q5).
    net_mode: Option<&'static str>,
}

/// The final step of every run that got past S5: M1 (an audit write failure
/// anywhere in the run is a failure, never a silent success), the exit row,
/// the diagnostics (after the pumps are done, m8), then `process::exit`.
fn conclude(outcome: Outcome, audit: Option<&AuditLog>, t0: Instant, facts: Conclusion) -> ! {
    std::process::exit(conclude_prepare(outcome, audit, t0, facts))
}

/// The run's last writes (the exit row and sbx's diagnostics); returns the exit
/// code without exiting, so the caller can release its locks and answer its
/// peers first.
fn conclude_prepare(
    mut outcome: Outcome,
    audit: Option<&AuditLog>,
    t0: Instant,
    facts: Conclusion,
) -> i32 {
    if let Some(audit) = audit {
        mark_audit_failure(&mut outcome, audit);
        audit.finish(&exit_row_for(
            ts(SystemTime::now()),
            &outcome,
            t0.elapsed(),
            facts.truncated,
            facts.poisoned,
            facts.net_mode,
            facts.call_id,
        ));
        mark_audit_failure(&mut outcome, audit);
    }
    let mut lines = Vec::new();
    if let Some(line) = sbx_diagnostic(&outcome) {
        lines.push(line);
    }
    if facts.truncated {
        lines.push(format!(
            "sbx run: output truncated at {} bytes (limits.output_bytes)",
            facts.cap
        ));
    }
    if facts.stragglers {
        lines.push("sbx run: sandbox did not exit within 5s of SIGKILL".to_owned());
    }
    write_diagnostics(facts.stderr_partial, &lines);
    exit_code(&outcome)
}

/// Writes sbx's own stderr lines, best effort (review 4): a closed or broken stderr
/// must never panic or change the exit code, so errors are ignored and nothing here
/// uses `eprintln!`. A partial line of forwarded payload stderr is terminated first
/// (review 3), so sbx's text is never glued onto the payload's last bytes.
fn write_diagnostics(partial: bool, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let mut out = io::stderr().lock();
    if partial {
        let _ = out.write_all(b"\n");
    }
    for line in lines {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
}

/// M1: a recorded audit write failure turns any non-failed outcome into the
/// pinned `audit log write failed: …` failure (exit 125).
fn mark_audit_failure(outcome: &mut Outcome, audit: &AuditLog) {
    if let Some(text) = audit.failure() {
        if !matches!(outcome, Outcome::Failed(_)) {
            *outcome = Outcome::Failed(format!("audit log write failed: {text}"));
        }
    }
}

/// m3: `t0 + timeout` saturates to a far deadline instead of panicking on overflow.
fn deadline_from(t0: Instant, timeout: Duration) -> Instant {
    t0.checked_add(timeout)
        .unwrap_or_else(|| t0 + Duration::from_secs(60 * 60 * 24 * 365 * 100))
}

/// m4: a ready wait that ends because the run deadline passed is a timeout (124),
/// not a startup failure (125). Otherwise the latch's reason, or a fixed one.
fn ready_wait_cause(
    now: Instant,
    deadline: Instant,
    timeout: Duration,
    latch: Option<Fault>,
) -> Cause {
    if now >= deadline {
        return Cause::Timeout(timeout);
    }
    let text = match latch {
        Some(Fault::Net(text)) => format!("network service failed: {text}"),
        _ => "network service did not start in time".to_owned(),
    };
    Cause::Setup(RunError::new(text))
}

/// The single site that writes the `sbx run: ` prefix for pre-spawn failures.
fn report_failure(
    reason: &str,
    t0: Instant,
    audit: Option<&AuditLog>,
    call_id: Option<u32>,
) -> ExitCode {
    if let Some(audit) = audit {
        audit.finish(&exit_row_for(
            ts(SystemTime::now()),
            &Outcome::Failed(reason.to_owned()),
            t0.elapsed(),
            false,
            false,
            None,
            call_id,
        ));
    }
    write_diagnostics(false, &[format!("sbx run: {reason}")]);
    ExitCode::from(EXIT_FAILURE as u8)
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_owned();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_owned()
}

/// The `bwrap --version` gate (S6): the only spawn before the fd window. Bounded
/// by the run deadline and interruptible by sbx's signals (a slow or hung
/// `bwrap` must not outlive `--timeout`; the child is killed on overrun).
fn check_bwrap_version(
    bwrap: &Path,
    deadline: Instant,
    timeout: Duration,
    signals: &sys::Signals,
) -> Result<(), Early> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut child = Command::new(bwrap)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| RunError::new(format!("cannot run {bwrap:?} --version: {err}")))?;
    let pidfd = match sys::pidfd_open(child.id() as libc::pid_t) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::new(format!("cannot watch bwrap --version: {err}")).into());
        }
    };
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut out = Vec::new();
    let (mut exited, mut eof) = (false, false);
    while !(exited && eof) {
        let mut fds = vec![pollfd(signals.fd().as_raw_fd(), libc::POLLIN)];
        if !exited {
            fds.push(pollfd(pidfd.as_raw_fd(), libc::POLLIN));
        }
        if !eof {
            fds.push(pollfd(stdout.as_raw_fd(), libc::POLLIN));
        }
        let ready_count = sys::poll_fds(&mut fds, Some(deadline))
            .map_err(|err| RunError::new(format!("cannot wait for bwrap --version: {err}")));
        let ready_count = match ready_count {
            Ok(n) => n,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err.into());
            }
        };
        if ready_count == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Early::TimedOut(timeout));
        }
        if sys::ready(fds[0].revents) {
            if let Some(sig) = signals.read() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Early::Signal(sig));
            }
        }
        // Each pollfd is found by position: signal first, then pidfd (if any), then stdout.
        let mut idx = 1;
        if !exited {
            if sys::ready(fds[idx].revents) {
                exited = true;
            }
            idx += 1;
        }
        if !eof && sys::ready(fds[idx].revents) {
            let mut chunk = [0u8; 256];
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => eof = true,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    }
    let status = child
        .wait()
        .map_err(|err| RunError::new(format!("cannot collect bwrap --version: {err}")))?;
    let text = String::from_utf8_lossy(&out).into_owned();
    // The shared gate (issue #11): the refusal text is BwrapStatus's, pinned.
    match classify_version_output(bwrap, status.success(), status.code(), &text).run_reason() {
        None => Ok(()),
        Some(reason) => Err(RunError::new(reason).into()),
    }
}

/// stdin policy (§8): inherit when not a tty; pump when the tty is ours in the
/// foreground; otherwise /dev/null (a background read would SIGTTIN all of sbx).
fn stdin_mode() -> (Stdio, bool) {
    match sys::stdin_tty_foreground() {
        (false, _) => (Stdio::inherit(), false),
        (true, true) => (Stdio::piped(), true),
        (true, false) => (Stdio::null(), false),
    }
}

fn child_exit_message(status: io::Result<ExitStatus>) -> String {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(st) => match (st.code(), st.signal()) {
            (Some(code), _) => {
                format!("sandbox setup failed: sbx __init exited with status {code}")
            }
            (None, Some(sig)) => {
                format!("sandbox setup failed: sbx __init was killed by signal {sig}")
            }
            (None, None) => "sandbox setup failed: sbx __init ended in an unknown state".into(),
        },
        Err(err) => format!("sandbox setup failed: {err}"),
    }
}

/// S0–S18. Returns only through `process::exit` (after the spawn) or `Err`.
fn execute(
    args: RunArgs,
    t0: Instant,
    audit_slot: &mut Option<Arc<AuditLog>>,
    hold: &mut Option<keepalive::holder::Hold>,
) -> Result<Infallible, Early> {
    // S3 first: the policy is read BEFORE any signal is blocked (review 5). The open
    // is non-blocking and a non-regular file is refused, so a FIFO or device cannot
    // hang the run with the signals masked.
    // A holder pins the exact bytes it parsed (issue #18); a plain run does not keep them.
    let (policy, pinned): (Policy, Option<Vec<u8>>) = if hold.is_some() {
        let bytes = keepalive::pin::read_policy_bytes(&args.policy).map_err(RunError::new)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| RunError::new(format!("{} is not valid UTF-8", args.policy.display())))?;
        let policy = Policy::from_json_str(text).map_err(|err| RunError::new(err.to_string()))?;
        (policy, Some(bytes))
    } else {
        (load_policy(&args.policy)?, None)
    };

    // S1–S2: signal state before any thread and before any spawn.
    sys::reset_sigchld();
    let signals = sys::Signals::install()
        .map_err(|err| RunError::new(format!("cannot block signals: {err}")))?;

    // S3: mode, timeout, paths.
    let rw_roots: Vec<PathBuf> = policy
        .filesystem
        .rw
        .iter()
        .map(|p| p.as_path().to_path_buf())
        .collect();
    // Round 2: the payload sees the ro paths too, so the audit log may not live under
    // one of those either (its rows, or a lock held there, would be the payload's).
    let ro_roots: Vec<PathBuf> = policy
        .filesystem
        .ro
        .iter()
        .map(|p| p.as_path().to_path_buf())
        .collect();
    // A session that attach can join needs the nftables redirect (issue #18):
    // refuse before anything is spawned when the policy is not transparent.
    if hold.is_some() && policy.network.mode != crate::policy::NetworkMode::Transparent {
        return Err(RunError::new(
            "--keep-alive needs network mode transparent: attach joins the session's nftables rules, which explicit and none policies do not load",
        )
        .into());
    }
    // A holder's setup is bounded like any run's (SETUP_TIMEOUT). Its lifetime is
    // not: the session clock (`--max-lifetime`) starts at t0 and bounds it, and the
    // resident is never bound by the policy's limits.timeout (issue #18, review 6).
    let timeout = match hold.as_ref() {
        Some(_) => SETUP_TIMEOUT,
        None => effective_timeout(args.timeout, policy.limits.timeout),
    };
    let deadline = deadline_from(t0, timeout);
    let session = lexical_normalize(&absolutize(&args.session_dir)?);
    let audit_path = match &args.audit {
        Some(path) => Some(lexical_normalize(&absolutize(path)?)),
        None => None,
    };
    if let Some(path) = &audit_path {
        if audit_inside_session(path, &session) {
            return Err(refused(Writable::Session, path).into());
        }
        // Review 1: a policy rw path is writable by the payload exactly like the
        // session directory, so the audit log must not live under one either.
        for root in &rw_roots {
            if audit_inside_session(path, root) {
                return Err(refused(Writable::PolicyRw, path).into());
            }
        }
        for root in &ro_roots {
            if audit_inside_session(path, root) {
                return Err(refused(Writable::PolicyRo, path).into());
            }
        }
    }

    // S4: the session lock comes before materialize and before any audit row.
    let lock = SessionLock::acquire(&session)?;
    if hold.is_some() {
        keepalive::holder::redirect_log(&session)?;
    }

    // S5: the audit log (refuses before any spawn).
    let latch = FaultLatch::new()
        .map_err(|err| RunError::new(format!("cannot create the fault latch: {err}")))?;
    let audit_file = match &audit_path {
        Some(path) => {
            let roots = writable_roots(&session, &rw_roots, &ro_roots)?;
            check_real_audit_location(path, &roots)?;
            let file = open_audit(path)?;
            check_opened_audit_location(&file, &roots)?;
            Some(file)
        }
        None => None,
    };
    let audit = AuditLog::new(audit_file, latch.clone());
    *audit_slot = Some(audit.clone());

    // S5b (issue #19): `--landlock require` on a kernel below ABI 6 is refused here,
    // before any spawn (the shim re-checks and fails closed too).
    if args.landlock == crate::landlock::Mode::Require {
        if let Some(reason) = crate::landlock::require_refusal(crate::landlock::kernel_abi()) {
            return Err(RunError::new(reason).into());
        }
    }

    // S6: bwrap discovery and version gate.
    let bwrap = find_bwrap()
        .ok_or_else(|| RunError::new(BwrapStatus::NotFound.run_reason().unwrap_or_default()))?;
    check_bwrap_version(&bwrap, deadline, timeout, &signals)?;

    // S7: env pass-through and the session layout.
    let env = passed_env(&policy, |name| std::env::var_os(name));
    session_layout(&session)
        .materialize()
        .map_err(|err| RunError::new(format!("cannot prepare the session directory: {err}")))?;

    // S8: the bwrap info pipe, the seccomp program memfd (issue #34: every
    // launch is filtered; an unsupported arch refuses here, rc 125), and the
    // launch argv.
    let (info_read, info_write) = sys::pipe_cloexec()
        .map_err(|err| RunError::new(format!("cannot create the info pipe: {err}")))?;
    let seccomp_memfd = seccomp::program_memfd()
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    // S8b (issue #19): with the Landlock layer on, sbx's own executable is opened
    // here (O_CLOEXEC, like every std open) and becomes the shim's program, and a
    // status pipe carries the shim's failure reason back (M1). The read end is
    // non-blocking; the write end is handed over in the spawn window.
    let LandlockSetup {
        exe: exe_file,
        status: status_pipe,
    } = landlock_setup(args.landlock)?;
    let landlock_layer = landlock_layer(
        &exe_file,
        &status_pipe,
        args.landlock,
        &args.landlock_bind_tcp,
    );
    let launch = build(&Build {
        policy: &policy,
        session_dir: &session,
        bwrap_path: &bwrap,
        command: &args.cmd,
        cwd: args.cwd.as_deref(),
        passed_env: &env,
        info_fd: Some(info_write.as_raw_fd()),
        seccomp_fd: seccomp_memfd.as_raw_fd(),
        landlock: landlock_layer,
    })
    .map_err(|err| RunError::new(err.to_string()))?;

    // S8a (#39/#40, N19): before anything is spawned, verify the launch (see
    // verify_launch). Refusal is 125; nothing is created outside the session
    // directory and the audit log (S5/S7 ran already).
    verify_launch(&launch)?;

    // S9–S11: the control socketpair and the single spawn window.
    let (parent_end, child_end) = fdpass::control_socketpair()
        .map_err(|err| RunError::new(format!("cannot create the control socketpair: {err}")))?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the control socket: {err}")))?;
    let info_fd = sys::clear_cloexec(info_write.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the info pipe: {err}")))?;
    let seccomp_fd = sys::clear_cloexec(seccomp_memfd.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    let exe_fd = match &exe_file {
        Some(file) => Some(
            sys::clear_cloexec(file.as_fd())
                .map_err(|err| RunError::new(format!("cannot prepare the shim: {err}")))?,
        ),
        None => None,
    };
    let status_fd = match &status_pipe {
        Some((_, write)) => Some(
            sys::clear_cloexec(write.as_fd())
                .map_err(|err| RunError::new(format!("cannot prepare the shim status: {err}")))?,
        ),
        None => None,
    };
    let (stdin, stdin_piped) = stdin_mode();
    let mut child = init_command(
        ChildFds {
            control: child_fd,
            info: info_fd,
            seccomp: seccomp_fd,
            exe: exe_fd,
            status: status_fd,
        },
        policy.network.mode,
        args.test_break_rules,
        &launch,
        stdin,
    )
    .spawn()
    .map_err(|err| RunError::new(format!("cannot spawn sbx __init: {err}")))?;
    drop(child_end);
    drop(info_write);
    drop(seccomp_memfd);
    drop(exe_file);
    // The write end lives on in __init, bwrap and the shim only; sbx keeps just the
    // read end. Without this drop an empty pipe would never report EOF.
    let (status_read, status_write) = match status_pipe {
        Some((read, write)) => (Some(read), Some(write)),
        None => (None, None),
    };
    drop(status_write);

    // S12: a pidfd for the child (unreaped, so its pid cannot be recycled).
    let child_pidfd = match sys::pidfd_open(child.id() as libc::pid_t) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = child.kill();
            return Err(RunError::new(format!("cannot watch sbx __init: {err}")).into());
        }
    };
    let mut sb = Sandbox {
        bwrap_pid: child.id() as libc::pid_t,
        child,
        child_pidfd,
        pid1: Pid1::Pending {
            info: info_read,
            buf: Vec::new(),
        },
        go_sent: false,
    };

    // The map is shared by the proxies and the resolver, and read at teardown.
    let map = Arc::new(FakeIpMap::new(&DnsLimits::default()));
    let mut pumps: Option<Pumps> = None;
    let mut holder: Option<keepalive::holder::Holder> = None;

    // S13–S17. Any failure here is a Cause::Setup and goes through teardown.
    // The achieved network mode, recorded on the exit row (issue #11, Q5).
    let mut net_mode: Option<&'static str> = None;
    let startup = (|| -> Result<(), Cause> {
        pumps = Some(
            Pumps::start(
                &mut sb.child,
                OutputBudget::new(policy.limits.output_bytes),
                stdin_piped,
            )
            .map_err(|err| {
                Cause::Setup(RunError::new(format!(
                    "cannot start the stdio pumps: {err}"
                )))
            })?,
        );
        // S14: wait for the listener fds from __init. A staged failure refuses
        // the run (rc 125) with the shared classifier's text; an explicit
        // fallback runs with a notice and is recorded as `net_mode`.
        let fds: ListenerFds = match wait_for_fds(
            parent_end.as_fd(),
            sb.child_pidfd.as_fd(),
            &signals,
            deadline,
            t0 + SETUP_TIMEOUT,
        ) {
            SetupEnd::Ready { fds, mode } => {
                // Review #2: the parent refuses an explicit result the policy
                // cannot accept, whatever `--min-mode` said.
                if let Some(err) = mode::achieved_refusal(policy.network.mode, &mode) {
                    return Err(Cause::Setup(err));
                }
                net_mode = Some(mode.label());
                if let AchievedMode::Explicit { reason, .. } = &mode {
                    write_diagnostics(false, &[fallback_notice(reason, policy.network.mode)]);
                }
                // Issue #18: a session that fell back to explicit mode can never be
                // attached (no nftables rules to join): refuse it at startup.
                if hold.is_some() && !matches!(mode, AchievedMode::Transparent) {
                    return Err(Cause::Setup(RunError::new(
                        "--keep-alive needs the transparent network mode, but this host provides only explicit (the nftables redirect is unavailable); attach could not join this session; run `sbx check`",
                    )));
                }
                // Issue #18: bind sbx.ctl and capture the session namespaces
                // while __init is parked, before the go byte. The Landlock settings
                // are the session's: an attach applies exactly these.
                if let Some(h) = hold.as_ref() {
                    holder = Some(
                        keepalive::holder::prepare(
                            h,
                            t0,
                            &session,
                            sb.bwrap_pid,
                            keepalive::holder::HolderInputs {
                                pin_bytes: pinned.clone().unwrap_or_default(),
                                net_mode: mode.label(),
                                audit: audit.clone(),
                                map: map.clone(),
                                landlock: keepalive::proto::SessionLandlock {
                                    mode: args.landlock,
                                    bind_tcp: args.landlock_bind_tcp.clone(),
                                },
                            },
                        )
                        .map_err(Cause::Setup)?,
                    );
                }
                fds
            }
            SetupEnd::Refused(failure) => {
                // Let __init finish its own staged stderr line before teardown
                // kills and reaps it.
                let _ = sys::wait_readable(sb.child_pidfd.as_fd(), INFO_GRACE);
                return Err(Cause::Setup(refusal(
                    policy.network.mode,
                    &failure,
                    &RunFacts::read(),
                )));
            }
            SetupEnd::Signal(sig) => return Err(Cause::Signal(sig)),
            SetupEnd::TimedOut => return Err(Cause::Timeout(timeout)),
            SetupEnd::SetupTimedOut => {
                return Err(Cause::Setup(RunError::new(
                    "sandbox setup timed out after 30s",
                )));
            }
            SetupEnd::ChildExited => {
                return Err(Cause::Setup(RunError::new(child_exit_message(
                    sb.child.wait(),
                ))));
            }
            SetupEnd::Failed(err) => return Err(Cause::Setup(err)),
        };
        // S15: the proxies and the resolver share one map and one sink.
        let net = effective_network(&policy);
        // Issue #41: the proxy dials from this (the host's) network
        // namespace, so the host's own interface addresses join the guard's
        // deny set. Gathered once, here; failing to list them refuses the
        // run rather than running with a silently empty set (fail-closed).
        let host_addrs = sys::host_interface_addrs().map_err(|err| {
            Cause::Setup(RunError::new(format!(
                "cannot list the host's interface addresses: {err}"
            )))
        })?;
        let host_addrs = crate::egress::HostAddrs::new(host_addrs);
        // Issue #29, C4: the relay idle timeout is the only proxy limit an
        // operator tunes; every other limit keeps its pinned default.
        let limits = crate::proxy::Limits {
            relay_idle_timeout: args
                .relay_idle_timeout
                .unwrap_or(crate::proxy::Limits::default().relay_idle_timeout),
            ..crate::proxy::Limits::default()
        };
        let proxy = Proxy::system(&net, map.clone(), audit.clone(), host_addrs, limits);
        let dns = DnsServer::new(&net, map.clone(), audit.clone());
        // S16: start the runtime; go only after every task was first-polled.
        let ready = start_net(serve_tasks(fds, proxy, dns), latch.clone()).map_err(|err| {
            Cause::Setup(RunError::new(format!(
                "cannot start the network thread: {err}"
            )))
        })?;
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(READY_TIMEOUT);
        match ready.recv_timeout(wait) {
            Ok(Ok(())) => {}
            Ok(Err(text)) => {
                return Err(Cause::Setup(RunError::new(format!(
                    "network service failed: {text}"
                ))));
            }
            Err(_) => {
                return Err(ready_wait_cause(
                    Instant::now(),
                    deadline,
                    timeout,
                    latch.take(),
                ));
            }
        }
        // S17: release the sandbox.
        fdpass::send_go(parent_end.as_raw_fd()).map_err(|err| {
            Cause::Setup(RunError::new(format!("cannot release the sandbox: {err}")))
        })?;
        sb.go_sent = true;
        drop(parent_end);
        // Issue #18: the session is up. The launcher may return now.
        if let Some(h) = hold.as_mut() {
            h.signal_ready();
        }
        Ok(())
    })();

    // S18: supervise until the first cause, then tear down.
    let cause = match startup {
        Ok(()) => match holder.as_mut() {
            // A holder's supervisor also serves the control socket (issue #18).
            Some(h) => supervise(
                &mut sb,
                &signals,
                &latch,
                deadline_from(t0, Duration::from_secs(60 * 60 * 24 * 365 * 100)),
                timeout,
                h,
            ),
            None => main_loop(&mut sb, &signals, &latch, deadline, timeout),
        },
        Err(cause) => cause,
    };
    if let Some(h) = holder.as_mut() {
        h.end_calls(keepalive::holder::CALL_GRACE);
    }
    let (mut outcome, end, stragglers) = teardown(sb, cause, pumps);
    outcome = landlock_status_outcome(outcome, status_read.as_ref());
    let _ = lock.touch();
    // The exit row is written before the lock is released and before a `sbx stop`
    // is answered (issue #18, review 2): a stop that returns has left the audit
    // file complete and the directory free for the next holder.
    let code = conclude_prepare(
        outcome,
        Some(&audit),
        t0,
        Conclusion {
            call_id: hold.is_some().then_some(0),
            truncated: end.truncated,
            stderr_partial: end.stderr_partial,
            poisoned: map.poisoned(),
            stragglers,
            cap: policy.limits.output_bytes,
            net_mode,
        },
    );
    // Review 6 of #57: the control socket is closed before the lock is released,
    // and the stops are answered after both (exit row, socket and lock are done).
    let stops = holder.take().map(|h| h.close_control());
    drop(lock);
    if let Some(stops) = stops {
        stops.answer();
    }
    std::process::exit(code)
}

/// The Landlock descriptors of one launch (issue #19): sbx's own executable, for
/// the shim, and the shim's status pipe. Both are opened only under a layer.
pub(crate) struct LandlockSetup {
    pub(crate) exe: Option<File>,
    /// The status pipe: (read end, write end).
    pub(crate) status: Option<(OwnedFd, OwnedFd)>,
}

/// Opens the descriptors a launch with `mode` needs (none when `mode` is off).
/// `run` and every persistent-session attach call go through this one function
/// (issue #18 with #56: the layer is the session's in both).
pub(crate) fn landlock_setup(mode: crate::landlock::Mode) -> Result<LandlockSetup, RunError> {
    match mode {
        crate::landlock::Mode::Off => Ok(LandlockSetup {
            exe: None,
            status: None,
        }),
        _ => {
            let exe = File::open("/proc/self/exe")
                .map_err(|err| RunError::new(format!("cannot open the sbx executable: {err}")))?;
            let pipe = sys::pipe_cloexec().map_err(|err| {
                RunError::new(format!("cannot create the shim status pipe: {err}"))
            })?;
            Ok(LandlockSetup {
                exe: Some(exe),
                status: Some(pipe),
            })
        }
    }
}

/// The [`crate::landlock::Layer`] for a launch, or `None` when there is none.
pub(crate) fn landlock_layer(
    exe: &Option<File>,
    status: &Option<(OwnedFd, OwnedFd)>,
    mode: crate::landlock::Mode,
    bind_tcp: &[u16],
) -> Option<crate::landlock::Layer> {
    match (exe, status) {
        (Some(file), Some((_, status_write))) => Some(crate::landlock::Layer {
            mode,
            bind_tcp: bind_tcp.to_vec(),
            exe_fd: file.as_raw_fd(),
            status_fd: status_write.as_raw_fd(),
            host_abi: crate::landlock::host_abi(),
        }),
        _ => None,
    }
}

/// The outcome after the shim's status pipe is read (issue #19 M1 and round 3
/// item 2): the pipe says whether the shim started and whether it failed. It ends
/// the run as `failed` only when the payload's own outcome is not already one.
pub(crate) fn landlock_status_outcome(mut outcome: Outcome, status: Option<&OwnedFd>) -> Outcome {
    if let Some(bytes) = status.and_then(read_status) {
        match crate::landlock::decode_status(&bytes) {
            crate::landlock::StatusReport::Started => {}
            crate::landlock::StatusReport::Failed(reason) => {
                if !matches!(outcome, Outcome::Failed(_)) {
                    outcome = Outcome::Failed(format!("landlock: {reason}"));
                }
            }
            crate::landlock::StatusReport::NotStarted => {
                if !matches!(outcome, Outcome::Failed(_)) {
                    let rc = exit_code(&outcome);
                    outcome =
                        Outcome::Failed(format!("landlock: the shim did not start (rc {rc})"));
                }
            }
        }
    }
    outcome
}

/// Reads the shim's status pipe without blocking (issue #19 M1): the bytes there
/// (empty when nothing was written). The shim writes its marker first and any
/// reason before exiting 125, so the data is in the pipe by the time the payload
/// is gone. A pipe still held by a dying bwrap reads as EAGAIN, which ends the
/// read with what is there. Decoding is `landlock::decode_status`.
fn read_status(fd: &OwnedFd) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::from(fd.try_clone().ok()?);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    Some(bytes)
}

/// The S8a pre-launch verification of a built launch (#39/#40, N19): every path
/// bwrap will resolve under a bind cover (rw or ro) is a real directory chain,
/// no deny mask is reachable through a host symlink, and no two binds overlap
/// through a host symlink. Run before any spawn, by `run` and by every attach
/// call (a payload can plant a link between the resident's start and an attach).
pub(crate) fn verify_launch(launch: &crate::bwrap::Launch) -> Result<(), RunError> {
    for check in launch.path_checks() {
        crate::bwrap::guard::verify(check).map_err(|err| RunError::new(err.to_string()))?;
    }
    crate::bwrap::guard::verify_aliases(launch.alias_checks())
        .map_err(|err| RunError::new(err.to_string()))?;
    crate::bwrap::guard::verify_binds(launch.bind_specs())
        .map_err(|err| RunError::new(err.to_string()))?;
    Ok(())
}

/// Which writable location an audit path collides with (for the pinned messages).
#[derive(Clone, Copy)]
enum Writable {
    Session,
    PolicyRw,
    PolicyRo,
}

fn refused(kind: Writable, path: &Path) -> RunError {
    match kind {
        Writable::Session => RunError::new(format!(
            "--audit must not be inside the session directory ({path:?})"
        )),
        Writable::PolicyRw => RunError::new(format!(
            "--audit must not be inside a writable policy path ({path:?})"
        )),
        Writable::PolicyRo => RunError::new(format!(
            "--audit must not be inside a policy filesystem path ({path:?})"
        )),
    }
}

/// The canonical writable roots: the session directory and every policy `rw` path
/// that exists (a missing rw path cannot contain the log).
fn writable_roots(
    session: &Path,
    rw: &[PathBuf],
    ro: &[PathBuf],
) -> Result<Vec<(Writable, PathBuf)>, RunError> {
    let real_session = std::fs::canonicalize(session).map_err(|err| {
        RunError::new(format!(
            "cannot resolve session directory {session:?}: {err}"
        ))
    })?;
    let mut roots = vec![(Writable::Session, real_session)];
    for path in rw {
        if let Ok(real) = std::fs::canonicalize(path) {
            roots.push((Writable::PolicyRw, real));
        }
    }
    for path in ro {
        if let Ok(real) = std::fs::canonicalize(path) {
            roots.push((Writable::PolicyRo, real));
        }
    }
    Ok(roots)
}

/// M2 (and review 1): the audit path's REAL parent must not be inside any writable
/// root. Checked before the open, so a refused path never creates a file.
fn check_real_audit_location(path: &Path, roots: &[(Writable, PathBuf)]) -> Result<(), RunError> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    let real_parent = std::fs::canonicalize(parent).map_err(|err| {
        RunError::new(format!(
            "cannot resolve audit log directory {parent:?}: {err}"
        ))
    })?;
    for (kind, root) in roots {
        if real_parent.starts_with(root) {
            return Err(refused(*kind, path));
        }
    }
    Ok(())
}

/// M2, after the open: the descriptor's real path (`/proc/self/fd/N`) must not be
/// inside any writable root either (defence in depth against a raced symlink).
fn check_opened_audit_location(file: &File, roots: &[(Writable, PathBuf)]) -> Result<(), RunError> {
    use std::os::fd::AsRawFd;
    let real = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|err| RunError::new(format!("cannot resolve the audit log path: {err}")))?;
    for (kind, root) in roots {
        if real.starts_with(root) {
            return Err(refused(*kind, &real));
        }
    }
    Ok(())
}

/// Reads the policy through a non-blocking open (review 5): a FIFO, device or other
/// non-regular file is refused instead of blocking the run. Errors keep the
/// `Policy::from_file` wording.
fn load_policy(path: &Path) -> Result<Policy, RunError> {
    use std::io::Read;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| RunError::new(format!("cannot read {}: {err}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|err| RunError::new(format!("cannot read {}: {err}", path.display())))?;
    if !meta.file_type().is_file() {
        let kind = if meta.file_type().is_fifo() {
            "a FIFO"
        } else {
            "not a regular file"
        };
        return Err(RunError::new(format!(
            "policy {} is {kind}; expected a regular file",
            path.display()
        )));
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|err| {
        if err.kind() == io::ErrorKind::InvalidData {
            RunError::new(format!("{} is not valid UTF-8", path.display()))
        } else {
            RunError::new(format!("cannot read {}: {err}", path.display()))
        }
    })?;
    Policy::from_json_str(&text).map_err(|err| RunError::new(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lifecycle::Cause;
    use serve::Fault;

    #[test]
    fn run_error_display_is_reason_only() {
        let err = RunError::new("policy invalid");
        assert_eq!(err.to_string(), "policy invalid");
        assert_eq!(err.reason(), "policy invalid");
    }

    #[test]
    fn deadline_saturates_on_huge_timeouts() {
        // m3: a huge policy/CLI timeout must not panic on `t0 + timeout`.
        let t0 = Instant::now();
        let far = deadline_from(t0, Duration::MAX);
        assert!(far > t0);
        assert_eq!(
            deadline_from(t0, Duration::from_secs(5)),
            t0 + Duration::from_secs(5)
        );
    }

    #[test]
    fn ready_wait_past_deadline_is_timeout() {
        // m4: the run deadline passing during the ready wait is a timeout (124).
        let t0 = Instant::now();
        let limit = Duration::from_millis(50);
        let deadline = t0 + limit;
        let cause = ready_wait_cause(deadline + Duration::from_millis(1), deadline, limit, None);
        assert!(matches!(cause, Cause::Timeout(d) if d == limit));
        // Before the deadline, the latch reason (or the fixed text) is a setup failure.
        let early = ready_wait_cause(t0, deadline, limit, Some(Fault::Net("boom".into())));
        assert!(matches!(&early, Cause::Setup(e) if e.reason() == "network service failed: boom"));
        let none = ready_wait_cause(t0, deadline, limit, None);
        assert!(
            matches!(&none, Cause::Setup(e) if e.reason() == "network service did not start in time")
        );
    }

    #[test]
    fn exit_code_constants() {
        assert_eq!(EXIT_TIMEOUT, 124);
        assert_eq!(EXIT_FAILURE, 125);
        assert_eq!(SETUP_TIMEOUT, Duration::from_secs(30));
    }
}
