//! `sbx __init --probe` — the host capability probe behind `sbx check`
//! (issue #11, T3/T4).
//!
//! The probe is the SAME stage functions `__init` runs for a real sandbox
//! (unshare → idmap → netns → ipv6 → listeners → nft-load → nft-verify →
//! fallback), executed in this throwaway process's fresh namespaces, plus
//! three nested bwrap launches (issue #34 adds the seccomp one) built from the same flag constants as
//! `bwrap::build` (Phase 1: the probe must be sbx's own nested path, not a
//! `bwrap --version` guess). Every step is recorded as data: the probe never
//! prints failures to stderr, and it exits 0 whenever it ran — the parent
//! classifies the step outcomes ([`crate::host::classify`]).
//!
//! Step cascade (design §3.3): a failed unshare or idmap skips every later
//! step; a failed netns skips the nft/fallback/ipv6/listener steps but the
//! bwrap steps still run; ipv6 and listeners are diagnostic and never cascade.
//!
//! Issue #18 (keep-alive) adds two steps after the bwrap ones, and they do not
//! depend on the probe's own namespaces: `pidfd-open` (a pidfd of this process)
//! and `keep-alive`, which proves the join a session attach performs. A child
//! (the holder stand-in) unshares a fresh user and network namespace and parks;
//! the probe captures its namespace descriptors, and a second child (the
//! joiner, forked so the probe keeps its own namespaces) runs
//! [`crate::run::keepalive::join::join_namespaces`] on them. Both children are
//! bounded by [`KEEP_ALIVE_PROBE_TIMEOUT`] and reaped on every path.
//!
//! Output: exactly one JSON line on stdout (`ProbeReport`, `version` 1).

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use netlink_socket2::NetlinkSocket;
use serde::{Deserialize, Serialize};

use super::fdpass::truncate_reason;
use super::{InitError, netns, rules};

/// The probe protocol version (`ProbeReport::version`). Bumped to 2 for issue
/// #34's `bwrap-seccomp` step: the parent (`host::facts`) accepts exactly the
/// version it was built with, so a stale probe is refused, not misread.
pub const PROBE_VERSION: u32 = 3;

/// The step names, in report order (pinned by `probe_steps_pinned`).
pub const PROBE_STEPS: [&str; 13] = [
    "unshare",
    "idmap",
    "netns",
    "ipv6",
    "listeners",
    "nft-load",
    "nft-verify",
    "fallback",
    "bwrap-run",
    "bwrap-proc",
    "bwrap-seccomp",
    "pidfd-open",
    "keep-alive",
];

/// Bound on each nested bwrap launch (the parent's whole probe is bounded
/// separately; see `host::facts::PROBE_TIMEOUT`).
pub const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on each child of the keep-alive step: the holder stand-in's readiness
/// message, and the joiner's exit (issue #18).
pub const KEEP_ALIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The probe's JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub version: u32,
    pub steps: Vec<ProbeStep>,
}

/// One probe step outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStep {
    pub step: String,
    pub status: StepStatus,
    pub errno: Option<i32>,
    pub reason: Option<String>,
}

/// Step status on the probe wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Ok,
    Fail,
    Skip,
}

/// How a nested bwrap child ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BwrapExit {
    Code(i32),
    Signal(i32),
    TimedOut,
    SpawnFailed(String),
}

/// CLI seam for `sbx __init --probe` (dispatched by `crate::cli`). Same
/// prologue as [`super::run_init`]: signal mask reset, silenced panic hook
/// with `catch_unwind`, parent-death signal armed. Rc 0 with one JSON line
/// whenever the probe ran (whatever the step outcomes); rc 1 with
/// `sbx __init: internal error: …` on a caught panic or a failed prologue.
pub fn run_probe(bwrap: Option<PathBuf>, test_break_rules: bool) -> ExitCode {
    super::reset_signal_mask();
    if let Err(err) = super::arm_parent_death(None) {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        probe_pipeline(bwrap.as_deref(), test_break_rules)
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(line) => {
                println!("{line}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("sbx __init: internal error: probe report: {err}");
                ExitCode::FAILURE
            }
        },
        Err(payload) => {
            eprintln!(
                "sbx __init: internal error: {}",
                super::panic_message(&payload)
            );
            ExitCode::FAILURE
        }
    }
}

/// Accumulates the steps in order.
#[derive(Default)]
struct Steps(Vec<ProbeStep>);

impl Steps {
    fn push(&mut self, name: &str, status: StepStatus, errno: Option<i32>, reason: Option<String>) {
        self.0.push(ProbeStep {
            step: name.to_owned(),
            status,
            errno,
            reason,
        });
    }

    fn ok(&mut self, name: &str) {
        self.push(name, StepStatus::Ok, None, None);
    }

    fn fail(&mut self, name: &str, err: &InitError) {
        self.push(
            name,
            StepStatus::Fail,
            err.errno(),
            Some(truncate_reason(err.reason()).to_owned()),
        );
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.push(name, StepStatus::Skip, None, Some(reason.to_owned()));
    }

    /// Skip every step not recorded yet (the cascade's tail).
    fn skip_rest(&mut self, reason: &str) {
        for name in PROBE_STEPS.iter().skip(self.0.len()) {
            self.skip(name, reason);
        }
    }

    fn finish(self) -> ProbeReport {
        debug_assert_eq!(self.0.len(), PROBE_STEPS.len());
        ProbeReport {
            version: PROBE_VERSION,
            steps: self.0,
        }
    }
}

/// The probe pipeline. Pure sequencing over the real stage functions; the
/// only externally visible effects are the namespaces and the nft ruleset of
/// THIS process (which exits right after).
pub(crate) fn probe_pipeline(bwrap: Option<&Path>, test_break_rules: bool) -> ProbeReport {
    let mut steps = Steps::default();

    let ids = match netns::unshare_namespaces() {
        Ok(ids) => {
            steps.ok("unshare");
            ids
        }
        Err(err) => {
            steps.fail("unshare", &err);
            steps.skip_rest("skipped: unshare failed");
            return steps.finish();
        }
    };
    if let Err(err) = netns::write_id_maps(ids) {
        steps.fail("idmap", &err);
        steps.skip_rest("skipped: idmap failed");
        return steps.finish();
    }
    steps.ok("idmap");

    match netns::configure_netns() {
        Ok(()) => {
            steps.ok("netns");
            match netns::disable_ipv6() {
                Ok(()) => steps.ok("ipv6"),
                Err(err) => steps.fail("ipv6", &err),
            }
            match super::listeners::bind_all() {
                Ok(listeners) => {
                    drop(listeners);
                    steps.ok("listeners");
                }
                Err(err) => steps.fail("listeners", &err),
            }
            let mut sock = NetlinkSocket::new();
            match rules::load(&mut sock, test_break_rules) {
                Ok(_) => {
                    steps.ok("nft-load");
                    match rules::verify_dump(&mut sock) {
                        Ok(()) => steps.ok("nft-verify"),
                        Err(err) => steps.fail("nft-verify", &err),
                    }
                }
                Err(err) => {
                    steps.fail("nft-load", &err);
                    steps.skip("nft-verify", "skipped: nft-load failed");
                }
            }
            match netns::remove_default_route() {
                Ok(()) => steps.ok("fallback"),
                Err(err) => steps.fail("fallback", &err),
            }
        }
        Err(err) => {
            steps.fail("netns", &err);
            steps.skip("ipv6", "skipped: netns failed");
            steps.skip("listeners", "skipped: netns failed");
            steps.skip("nft-load", "skipped: netns failed");
            steps.skip("nft-verify", "skipped: netns failed");
            steps.skip("fallback", "skipped: netns failed");
        }
    }

    bwrap_steps(&mut steps, bwrap);
    keep_alive_steps(&mut steps);
    steps.finish()
}

/// Issue #18: the `pidfd-open` and `keep-alive` steps (module docs). Both run
/// after the bwrap steps and do not need the probe's own namespaces.
fn keep_alive_steps(steps: &mut Steps) {
    match pidfd_open_self() {
        Ok(()) => steps.ok("pidfd-open"),
        Err(err) => steps.push(
            "pidfd-open",
            StepStatus::Fail,
            err.raw_os_error(),
            Some(truncate_reason(&format!("pidfd_open of this process failed: {err}")).to_owned()),
        ),
    }
    match keep_alive_join() {
        Ok(()) => steps.ok("keep-alive"),
        Err(fault) => steps.push(
            "keep-alive",
            StepStatus::Fail,
            fault.errno,
            Some(truncate_reason(&fault.reason).to_owned()),
        ),
    }
}

/// Why the keep-alive join failed: the errno when there is one, and the reason.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KeepAliveFault {
    pub(crate) errno: Option<i32>,
    pub(crate) reason: String,
}

fn fault_of(err: &std::io::Error, what: &str) -> KeepAliveFault {
    KeepAliveFault {
        errno: err.raw_os_error(),
        reason: format!("{what}: {err}"),
    }
}

/// `pidfd_open(2)` on this process. Raw, so ENOSYS (a kernel below 5.3) keeps
/// its errno; the attach needs a pidfd for its own process and its holder.
fn pidfd_open_self() -> std::io::Result<()> {
    // SAFETY: SYS_pidfd_open takes (pid, flags) by value; no pointers.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative return is a fresh descriptor this function owns.
    unsafe {
        libc::close(fd as RawFd);
    }
    Ok(())
}

/// A forked child the probe must not leave behind: SIGKILL and reap on drop, so
/// every path (success, failure, panic unwinding through here) ends it.
struct Reaper(Option<libc::pid_t>);

impl Reaper {
    fn pid(&self) -> libc::pid_t {
        self.0.unwrap_or(-1)
    }

    /// Reaps a child that has already exited (EOF on its pipe).
    fn wait(&mut self) {
        if let Some(pid) = self.0.take() {
            let mut status: libc::c_int = 0;
            // SAFETY: waitpid on a child this process forked and has not reaped.
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
        }
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            // SAFETY: kill and waitpid on a child this process forked; SIGKILL
            // cannot be blocked, so the blocking wait ends.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

/// One bounded read: the bytes the descriptor yields once it is readable (empty
/// at EOF), or `None` when the deadline passes first.
fn read_bounded(fd: RawFd, deadline: Instant) -> std::io::Result<Option<Vec<u8>>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = libc::c_int::try_from(remaining.as_millis()).unwrap_or(libc::c_int::MAX);
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call.
    let ready = unsafe { libc::poll(&mut pfd, 1, millis) };
    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ready == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; 16];
    // SAFETY: read into a buffer this function owns, on a descriptor it was given.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Some(buf[..n as usize].to_vec()))
}

/// A close-on-exec pipe (read end, write end), both blocking. Every read goes
/// through [`read_bounded`], which polls first, so no read can block.
fn pipe_cloexec() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two descriptors into the array it is given.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned by nobody else.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

/// The holder stand-in's answer: `K` once it is parked in its fresh namespaces,
/// or `E` and the errno (five bytes, one write).
pub(crate) fn decode_holder_answer(bytes: &[u8]) -> Result<(), KeepAliveFault> {
    match bytes {
        [b'K', ..] => Ok(()),
        [b'E', e0, e1, e2, e3] => {
            let errno = i32::from_ne_bytes([*e0, *e1, *e2, *e3]);
            Err(KeepAliveFault {
                errno: Some(errno),
                reason: format!(
                    "unshare(CLONE_NEWUSER|CLONE_NEWNET) in the holder stand-in failed: {}",
                    std::io::Error::from_raw_os_error(errno)
                ),
            })
        }
        _ => Err(KeepAliveFault {
            errno: None,
            reason: "the holder stand-in exited before it was ready".to_owned(),
        }),
    }
}

/// The joiner's answer: nothing on success (EOF after its exit), or the errno of
/// its failed `setns` (four bytes).
pub(crate) fn decode_joiner_answer(bytes: &[u8]) -> Result<(), KeepAliveFault> {
    match bytes {
        [] => Ok(()),
        [e0, e1, e2, e3] => {
            let errno = i32::from_ne_bytes([*e0, *e1, *e2, *e3]);
            Err(KeepAliveFault {
                errno: Some(errno),
                reason: format!(
                    "setns into the holder stand-in's user and network namespaces failed: {}",
                    std::io::Error::from_raw_os_error(errno)
                ),
            })
        }
        _ => Err(KeepAliveFault {
            errno: None,
            reason: "the joiner sent an unexpected answer".to_owned(),
        }),
    }
}

/// The keep-alive join (module docs): a holder stand-in in a fresh user and
/// network namespace, its namespace descriptors captured as `run --keep-alive`
/// captures the session's, and a forked joiner that runs the attach's `setns`
/// pair on them. The probe's own namespaces are untouched.
fn keep_alive_join() -> Result<(), KeepAliveFault> {
    let deadline = Instant::now() + KEEP_ALIVE_PROBE_TIMEOUT;
    let timeout_reason = |what: &str| KeepAliveFault {
        errno: None,
        reason: format!(
            "{what} did not answer within {}s",
            KEEP_ALIVE_PROBE_TIMEOUT.as_secs()
        ),
    };

    let (answer_read, answer_write) =
        pipe_cloexec().map_err(|e| fault_of(&e, "cannot create a pipe"))?;
    // SAFETY: fork in the single-threaded probe; the child runs only libc calls
    // and never returns (`holder_child`).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(fault_of(
            &std::io::Error::last_os_error(),
            "cannot fork the holder stand-in",
        ));
    }
    if pid == 0 {
        holder_child(answer_write.as_raw_fd());
    }
    drop(answer_write);
    let holder = Reaper(Some(pid));
    let bytes = read_bounded(answer_read.as_raw_fd(), deadline)
        .map_err(|e| fault_of(&e, "cannot read the holder stand-in's answer"))?
        .ok_or_else(|| timeout_reason("the holder stand-in"))?;
    decode_holder_answer(&bytes)?;

    let (user, net) = crate::run::keepalive::join::capture_namespaces(holder.pid())
        .map_err(|e| fault_of(&e, "cannot open the holder stand-in's namespaces"))?;
    let (join_read, join_write) =
        pipe_cloexec().map_err(|e| fault_of(&e, "cannot create a pipe"))?;
    // SAFETY: as for the holder fork above; `joiner_child` never returns.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(fault_of(
            &std::io::Error::last_os_error(),
            "cannot fork the joiner",
        ));
    }
    if pid == 0 {
        joiner_child(user.as_raw_fd(), net.as_raw_fd(), join_write.as_raw_fd());
    }
    drop(join_write);
    let mut joiner = Reaper(Some(pid));
    let bytes = read_bounded(join_read.as_raw_fd(), deadline)
        .map_err(|e| fault_of(&e, "cannot read the joiner's answer"))?
        .ok_or_else(|| timeout_reason("the joiner"))?;
    decode_joiner_answer(&bytes)?;
    // EOF: the joiner has exited, so this wait does not block for long.
    joiner.wait();
    Ok(())
}

/// The holder stand-in (the child that never returns): arms its death signal,
/// unshares a fresh user and network namespace, reports `K` or `E`+errno, and
/// parks until the probe reaps it.
fn holder_child(report: RawFd) -> ! {
    // SAFETY: prctl, unshare, write, pause and _exit take plain integers and a
    // buffer this function owns; no Rust state is touched after the fork.
    unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        );
        let mut msg = [0u8; 5];
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) == 0 {
            msg[0] = b'K';
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            msg[0] = b'E';
            msg[1..].copy_from_slice(&errno.to_ne_bytes());
        }
        libc::write(report, msg.as_ptr().cast(), msg.len());
        loop {
            libc::pause();
        }
    }
}

/// The joiner (the child that never returns): arms its death signal, joins the
/// holder's namespaces as the attach does, and exits 0, or reports the errno of
/// the failed `setns` (four bytes) and exits 1.
fn joiner_child(user: RawFd, net: RawFd, report: RawFd) -> ! {
    // SAFETY: as for `holder_child`; the joiner exits through `_exit`.
    unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        );
    }
    match crate::run::keepalive::join::join_namespaces(user, net) {
        Ok(()) => unsafe { libc::_exit(0) },
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(0);
            // SAFETY: one write of four bytes this function owns, then _exit.
            unsafe {
                libc::write(report, errno.to_ne_bytes().as_ptr().cast(), 4);
                libc::_exit(1)
            }
        }
    }
}

/// The two nested bwrap launches (control without `--proc`, then `--proc`),
/// run from inside the probe's namespaces exactly as production runs them.
fn bwrap_steps(steps: &mut Steps, bwrap: Option<&Path>) {
    let Some(bwrap) = bwrap else {
        steps.skip("bwrap-run", "skipped: no usable bwrap");
        steps.skip("bwrap-proc", "skipped: no usable bwrap");
        steps.skip("bwrap-seccomp", "skipped: no usable bwrap");
        return;
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            steps.push(
                "bwrap-run",
                StepStatus::Fail,
                None,
                Some(format!("cannot locate the sbx binary: {err}")),
            );
            steps.skip("bwrap-proc", "skipped: bwrap-run failed");
            steps.skip("bwrap-seccomp", "skipped: bwrap-run failed");
            return;
        }
    };
    let (exit, stderr) = run_bwrap_child(bwrap, &exe, false, None);
    let run = bwrap_step("bwrap-run", exit, &stderr);
    let run_ok = run.status == StepStatus::Ok;
    steps.0.push(run);
    if !run_ok {
        steps.skip("bwrap-proc", "skipped: bwrap-run failed");
        steps.skip("bwrap-seccomp", "skipped: bwrap-run failed");
        return;
    }
    let (exit, stderr) = run_bwrap_child(bwrap, &exe, true, None);
    steps.0.push(bwrap_step("bwrap-proc", exit, &stderr));
    steps.0.push(seccomp_step(bwrap, &exe));
}

/// Issue #34: the `bwrap-seccomp` step — a nested launch with `--seccomp N`
/// (the sealed program memfd `run` uses), proving bwrap installs sbx's
/// socket-family filter in this host's namespaces and outer policy. The
/// memfd is created here (the same constructor `run` uses) and made
/// inheritable for the one child only; the parent closes it right after the
/// spawn. A failure to create it is a FAIL with its reason (e.g. an arch
/// without a program), not a skip.
fn seccomp_step(bwrap: &Path, exe: &Path) -> ProbeStep {
    let memfd = match crate::bwrap::seccomp::program_memfd() {
        Ok(fd) => fd,
        Err(err) => {
            return ProbeStep {
                step: "bwrap-seccomp".to_owned(),
                status: StepStatus::Fail,
                errno: err.raw_os_error(),
                reason: Some(
                    truncate_reason(&format!("cannot prepare the seccomp filter: {err}"))
                        .to_owned(),
                ),
            };
        }
    };
    let (exit, stderr) = run_bwrap_child(bwrap, exe, false, Some(memfd.as_raw_fd()));
    drop(memfd);
    bwrap_step("bwrap-seccomp", exit, &stderr)
}

/// Pure: a bwrap child outcome → a probe step. `ok` iff it exited 0. Any
/// other outcome is `fail` with errno None; the reason is the first
/// non-empty stderr line (bounded), else the exit description.
pub(crate) fn bwrap_step(name: &'static str, exit: BwrapExit, stderr: &[u8]) -> ProbeStep {
    let first_line = || {
        String::from_utf8_lossy(stderr)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| truncate_reason(line).to_owned())
    };
    let (status, reason) = match exit {
        BwrapExit::Code(0) => (StepStatus::Ok, None),
        BwrapExit::Code(code) => (
            StepStatus::Fail,
            Some(first_line().unwrap_or_else(|| format!("exited with status {code}"))),
        ),
        BwrapExit::Signal(sig) => (
            StepStatus::Fail,
            Some(first_line().unwrap_or_else(|| format!("killed by signal {sig}"))),
        ),
        BwrapExit::TimedOut => (
            StepStatus::Fail,
            Some(format!(
                "timed out after {}s",
                BWRAP_PROBE_TIMEOUT.as_secs()
            )),
        ),
        BwrapExit::SpawnFailed(error) => (
            StepStatus::Fail,
            Some(truncate_reason(&format!("cannot start bwrap: {error}")).to_owned()),
        ),
    };
    ProbeStep {
        step: name.to_owned(),
        status,
        errno: None,
        reason,
    }
}

/// Spawn one nested bwrap launch of the probe payload (this binary,
/// `--version`) and wait for it, bounded. `seccomp_fd` (issue #34) is the
/// program memfd the child inherits: its CLOEXEC is cleared here, so it
/// survives into bwrap only. Returns the outcome and the child's stderr
/// (empty when it did not exit on its own).
fn run_bwrap_child(
    bwrap: &Path,
    exe: &Path,
    with_proc: bool,
    seccomp_fd: Option<RawFd>,
) -> (BwrapExit, Vec<u8>) {
    let argv: Vec<OsString> = crate::bwrap::probe_argv(bwrap, exe, with_proc, seccomp_fd);
    if let Some(fd) = seccomp_fd {
        // SAFETY: F_SETFD on the memfd the caller owns; it is closed by the
        // caller after this spawn returns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return (
                BwrapExit::SpawnFailed(std::io::Error::last_os_error().to_string()),
                Vec::new(),
            );
        }
    }
    let spawned = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => return (BwrapExit::SpawnFailed(err.to_string()), Vec::new()),
    };
    wait_bounded(&mut child, BWRAP_PROBE_TIMEOUT)
}

/// Poll `try_wait` every 1 ms up to `timeout`; on expiry kill and reap.
fn wait_bounded(child: &mut Child, timeout: Duration) -> (BwrapExit, Vec<u8>) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_end(&mut stderr);
                }
                return (exit_of(status), stderr);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (BwrapExit::TimedOut, Vec::new());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return (BwrapExit::SpawnFailed(err.to_string()), Vec::new());
            }
        }
    }
}

fn exit_of(status: ExitStatus) -> BwrapExit {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => BwrapExit::Code(code),
        None => BwrapExit::Signal(status.signal().unwrap_or(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::consts::MAX_REASON_BYTES;

    #[test]
    fn probe_steps_pinned() {
        assert_eq!(
            PROBE_STEPS,
            [
                "unshare",
                "idmap",
                "netns",
                "ipv6",
                "listeners",
                "nft-load",
                "nft-verify",
                "fallback",
                "bwrap-run",
                "bwrap-proc",
                "bwrap-seccomp",
                "pidfd-open",
                "keep-alive"
            ]
        );
        assert_eq!(PROBE_VERSION, 3);
        assert_eq!(BWRAP_PROBE_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn bwrap_step_table() {
        let ok = bwrap_step("bwrap-run", BwrapExit::Code(0), b"");
        assert_eq!(ok.status, StepStatus::Ok);
        assert_eq!(ok.reason, None);

        let fail = bwrap_step(
            "bwrap-proc",
            BwrapExit::Code(1),
            b"\n  bwrap: Can't mount proc\nmore\n",
        );
        assert_eq!(fail.status, StepStatus::Fail);
        assert_eq!(fail.reason.as_deref(), Some("bwrap: Can't mount proc"));

        let silent = bwrap_step("bwrap-run", BwrapExit::Code(1), b"");
        assert_eq!(silent.reason.as_deref(), Some("exited with status 1"));

        let sig = bwrap_step("bwrap-run", BwrapExit::Signal(9), b"");
        assert_eq!(sig.reason.as_deref(), Some("killed by signal 9"));

        let timeout = bwrap_step("bwrap-run", BwrapExit::TimedOut, b"ignored");
        assert_eq!(timeout.reason.as_deref(), Some("timed out after 5s"));

        let spawn = bwrap_step("bwrap-run", BwrapExit::SpawnFailed("ENOENT".into()), b"");
        assert_eq!(spawn.reason.as_deref(), Some("cannot start bwrap: ENOENT"));
        assert_eq!(spawn.errno, None);
    }

    #[test]
    fn bwrap_step_bounds_long_lines() {
        let long = "x".repeat(500);
        let step = bwrap_step("bwrap-run", BwrapExit::Code(1), long.as_bytes());
        let reason = step.reason.expect("a reason");
        assert_eq!(reason.len(), 500);
        assert!(reason.len() <= MAX_REASON_BYTES);
        let huge = "y".repeat(2000);
        let step = bwrap_step("bwrap-run", BwrapExit::Code(1), huge.as_bytes());
        assert!(step.reason.expect("a reason").len() <= MAX_REASON_BYTES);
    }

    #[test]
    fn probe_report_json_golden() {
        let report = ProbeReport {
            version: PROBE_VERSION,
            steps: vec![
                ProbeStep {
                    step: "unshare".into(),
                    status: StepStatus::Ok,
                    errno: None,
                    reason: None,
                },
                ProbeStep {
                    step: "bwrap-proc".into(),
                    status: StepStatus::Skip,
                    errno: None,
                    reason: Some("skipped: no usable bwrap".into()),
                },
            ],
        };
        assert_eq!(
            serde_json::to_string(&report).expect("serialises"),
            r#"{"version":3,"steps":[{"step":"unshare","status":"ok","errno":null,"reason":null},{"step":"bwrap-proc","status":"skip","errno":null,"reason":"skipped: no usable bwrap"}]}"#
        );
        let back: ProbeReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn steps_cascade_skip_rest() {
        let mut steps = Steps::default();
        steps.ok("unshare");
        steps.skip_rest("skipped: unshare failed");
        let report = steps.finish();
        assert_eq!(report.steps.len(), PROBE_STEPS.len());
        assert_eq!(report.steps[1].status, StepStatus::Skip);
        assert_eq!(report.steps[9].step, "bwrap-proc");
        assert_eq!(report.steps[10].step, "bwrap-seccomp");
        assert_eq!(report.steps[11].step, "pidfd-open");
        assert_eq!(report.steps[12].step, "keep-alive");
    }

    #[test]
    fn keep_alive_answers_decode_strictly() {
        // K: parked in the fresh namespaces.
        assert_eq!(decode_holder_answer(b"K\0\0\0\0"), Ok(()));
        // E + errno: the unshare failed, with the errno kept.
        let eperm = libc::EPERM.to_ne_bytes();
        let fault = decode_holder_answer(&[b'E', eperm[0], eperm[1], eperm[2], eperm[3]])
            .expect_err("E is a failure");
        assert_eq!(fault.errno, Some(libc::EPERM));
        assert!(
            fault
                .reason
                .starts_with("unshare(CLONE_NEWUSER|CLONE_NEWNET) in the holder stand-in failed:")
        );
        // EOF, a short or unknown message: the stand-in is not ready.
        for bytes in [&b""[..], b"E", b"X\0\0\0\0"] {
            let fault = decode_holder_answer(bytes).expect_err("not ready");
            assert_eq!(fault.errno, None, "{bytes:?}");
        }
    }

    #[test]
    fn joiner_answers_decode_strictly() {
        assert_eq!(decode_joiner_answer(b""), Ok(()));
        let enospc = libc::ENOSPC.to_ne_bytes();
        let fault = decode_joiner_answer(&enospc).expect_err("four bytes are an errno");
        assert_eq!(fault.errno, Some(libc::ENOSPC));
        assert!(
            fault.reason.starts_with(
                "setns into the holder stand-in's user and network namespaces failed:"
            )
        );
        assert_eq!(decode_joiner_answer(b"abc").expect_err("short").errno, None);
    }
}
