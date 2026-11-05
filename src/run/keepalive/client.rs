//! `sbx attach` and `sbx stop`: the caller side of a persistent session (issue #18,
//! design points 4 and 5).
//!
//! 1. **Attach refusal is rc 125, before anything runs.** The policy bytes must
//!    equal the session's pinned bytes; otherwise the holder refuses with
//!    [`super::holder`]'s pinned reason and attach exits 125 without starting a
//!    call. Any other handshake failure is also 125.
//! 2. **The call is the normal sandbox, minus setup.** Attach joins the session's
//!    user and network namespaces through `__init --join-user --join-net`, which
//!    re-verifies the session's nftables ruleset before the bwrap exec. The call's
//!    bwrap, seccomp program and argv are built exactly as in a normal run.
//! 3. **Holder death kills the call.** Attach watches the holder's pidfd, which
//!    the holder sent in the accept reply. When the holder exits, the call is
//!    torn down and attach exits 125.
//! 4. **Stop.** `sbx stop` sends `Stop` and waits for `Done`, which the holder
//!    sends only after the session is gone. A session that is not running (no
//!    socket, or a stale socket with no listener) is rc 0.
//! 5. **Exit codes.** A call's own code, 124 on `--timeout`, 143/130/129/131 on a
//!    signal to attach, 125 on any attach failure. A call killed through its
//!    holder's teardown reports `terminated`.

use std::convert::Infallible;
use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use super::ctl;
use super::proto::{CallEnd, Reply, Request};
use crate::bwrap::seccomp;
use crate::bwrap::version::{BwrapStatus, find_bwrap};
use crate::bwrap::{Build, Launch, build};
use crate::policy::Policy;
use crate::run::lifecycle::{Cause, Extra, Pid1, Sandbox, supervise, teardown};
use crate::run::plan::{
    absolutize, effective_timeout, exit_code, lexical_normalize, outcome_label, passed_env,
    sbx_diagnostic,
};
use crate::run::serve::FaultLatch;
use crate::run::stdio::{OutputBudget, PumpEnd, Pumps};
use crate::run::sys;
use crate::run::{
    EXIT_FAILURE, Early, Outcome, RunError, check_bwrap_version, deadline_from, stdin_mode,
    write_diagnostics,
};

/// The parsed `sbx attach` invocation.
#[derive(Debug, Clone)]
pub(crate) struct AttachArgs {
    pub(crate) policy: PathBuf,
    pub(crate) session_dir: PathBuf,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) cmd: Vec<OsString>,
}

/// Watches the holder's pidfd (rule 3).
struct HolderWatch {
    pidfd: OwnedFd,
}

impl Extra for HolderWatch {
    fn fds(&self) -> Vec<RawFd> {
        vec![self.pidfd.as_raw_fd()]
    }

    fn wake(&mut self, revents: &[libc::c_short]) -> Option<Cause> {
        if revents.first().is_some_and(|ev| sys::ready(*ev)) {
            return Some(Cause::Setup(RunError::new("session holder exited")));
        }
        None
    }
}

/// `sbx attach`.
pub(crate) fn attach(args: AttachArgs) -> ExitCode {
    let t0 = Instant::now();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute_attach(args, t0)));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(Ok(never)) => match never {},
        Ok(Err(Early::Failed(err))) => attach_failed(err.reason()),
        Ok(Err(Early::Signal(sig))) => {
            conclude_attach(Outcome::Terminated(sig), PumpEnd::default(), false, 0)
        }
        Ok(Err(Early::TimedOut(limit))) => {
            conclude_attach(Outcome::TimedOut(limit), PumpEnd::default(), false, 0)
        }
        Err(payload) => attach_failed(&format!(
            "internal error: {}",
            payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_owned())
        )),
    }
}

/// One `sbx attach` line on stderr and rc 125.
fn attach_failed(reason: &str) -> ExitCode {
    eprintln!("sbx attach: {reason}");
    ExitCode::from(EXIT_FAILURE as u8)
}

/// Prints the attach diagnostics and exits with the call's rc (never returns).
fn conclude_attach(outcome: Outcome, end: PumpEnd, stragglers: bool, cap: u64) -> ! {
    let mut lines = Vec::new();
    if let Some(line) = sbx_diagnostic(&outcome) {
        lines.push(line.replacen("sbx run:", "sbx attach:", 1));
    }
    if end.truncated {
        lines.push(format!(
            "sbx attach: output truncated at {cap} bytes (limits.output_bytes)"
        ));
    }
    if stragglers {
        lines.push("sbx attach: sandbox did not exit within 5s of SIGKILL".to_owned());
    }
    write_diagnostics(end.stderr_partial, &lines);
    std::process::exit(exit_code(&outcome))
}

/// Everything from the handshake to the call's end.
fn execute_attach(args: AttachArgs, t0: Instant) -> Result<Infallible, Early> {
    let policy_bytes = super::pin::read_policy_bytes(&args.policy).map_err(RunError::new)?;
    let text = std::str::from_utf8(&policy_bytes)
        .map_err(|_| RunError::new(format!("{} is not valid UTF-8", args.policy.display())))?;
    let policy = Policy::from_json_str(text).map_err(|err| RunError::new(err.to_string()))?;
    let session = lexical_normalize(&absolutize(&args.session_dir)?);
    let timeout = effective_timeout(args.timeout, policy.limits.timeout);
    let deadline = deadline_from(t0, timeout);

    let dir = ctl::open_session_dir(&session).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            RunError::new(format!("no session is running in {}", session.display()))
        } else {
            RunError::new(format!("cannot open the session directory: {err}"))
        }
    })?;
    let stream = ctl::connect_ctl(dir.as_fd()).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound
            || err.kind() == std::io::ErrorKind::ConnectionRefused
        {
            RunError::new(format!("no session is running in {}", session.display()))
        } else {
            RunError::new(format!("cannot reach the session: {err}"))
        }
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    // Rule 2 of the handshake: our own pidfd travels with the Attach request.
    let self_pidfd = sys::pidfd_open(std::process::id() as libc::pid_t)
        .map_err(|err| RunError::new(format!("cannot open the attach pidfd: {err}")))?;
    let (op, payload) = Request::Attach(policy_bytes).encode();
    ctl::send_frame(&stream, op, &payload, &[self_pidfd.as_raw_fd()])
        .map_err(|err| RunError::new(format!("cannot send the attach request: {err:?}")))?;
    let (frame, fds) = ctl::recv_frame(&stream)
        .map_err(|err| RunError::new(format!("the session did not answer: {err:?}")))?;
    let (id, mut fds) = match Reply::decode(frame) {
        Ok(Reply::Accepted(id)) if fds.len() == 3 => (id, fds),
        Ok(Reply::Refused(reason)) => {
            return Err(RunError::new(format!("session refused the call: {reason}")).into());
        }
        _ => return Err(RunError::new("the session sent an unexpected answer").into()),
    };
    let user_ns = fds.remove(1);
    let net_ns = fds.remove(1);
    let holder_pidfd = fds.remove(0);
    drop(self_pidfd);

    let cap = policy.limits.output_bytes;
    let (outcome, end, stragglers) = match run_call(
        &args,
        &session,
        &policy,
        deadline,
        timeout,
        holder_pidfd,
        user_ns,
        net_ns,
    ) {
        Ok(done) => done,
        Err(early) => (early_outcome(early), PumpEnd::default(), false),
    };
    report_call_end(&dir, id, &outcome, t0);
    conclude_attach(outcome, end, stragglers, cap)
}

fn early_outcome(early: Early) -> Outcome {
    match early {
        Early::Failed(err) => Outcome::Failed(err.reason().to_owned()),
        Early::Signal(sig) => Outcome::Terminated(sig),
        Early::TimedOut(limit) => Outcome::TimedOut(limit),
    }
}

/// Spawns `__init --join-user --join-net …` for the call, supervises it and
/// returns the outcome with the output facts (rules 2 and 3).
#[allow(clippy::too_many_arguments)]
fn run_call(
    args: &AttachArgs,
    session: &Path,
    policy: &Policy,
    deadline: Instant,
    timeout: Duration,
    holder_pidfd: OwnedFd,
    user_ns: OwnedFd,
    net_ns: OwnedFd,
) -> Result<(Outcome, PumpEnd, bool), Early> {
    let signals = sys::Signals::install()
        .map_err(|err| RunError::new(format!("cannot block signals: {err}")))?;
    sys::reset_sigchld();
    let bwrap = find_bwrap()
        .ok_or_else(|| RunError::new(BwrapStatus::NotFound.run_reason().unwrap_or_default()))?;
    check_bwrap_version(&bwrap, deadline, timeout, &signals)?;
    let env = passed_env(policy, |name| std::env::var_os(name));
    let (info_read, info_write) = sys::pipe_cloexec()
        .map_err(|err| RunError::new(format!("cannot create the info pipe: {err}")))?;
    let seccomp_memfd = seccomp::program_memfd()
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    let launch: Launch = build(&Build {
        policy,
        session_dir: session,
        bwrap_path: &bwrap,
        command: &args.cmd,
        cwd: args.cwd.as_deref(),
        passed_env: &env,
        info_fd: Some(info_write.as_raw_fd()),
        seccomp_fd: seccomp_memfd.as_raw_fd(),
        landlock: None, // TEMPORARY during the rebase: the session's Landlock is wired next.
    })
    .map_err(|err| RunError::new(err.to_string()))?;

    let info_fd = sys::clear_cloexec(info_write.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the info pipe: {err}")))?;
    let seccomp_fd = sys::clear_cloexec(seccomp_memfd.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    let user_fd = sys::clear_cloexec(user_ns.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the namespace fds: {err}")))?;
    let net_fd = sys::clear_cloexec(net_ns.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the namespace fds: {err}")))?;
    let (stdin, stdin_piped) = stdin_mode();
    let child = join_command(
        user_fd,
        net_fd,
        info_fd,
        seccomp_fd,
        std::process::id(),
        &launch,
        stdin,
    )
    .spawn()
    .map_err(|err| RunError::new(format!("cannot spawn sbx __init: {err}")))?;
    drop(info_write);
    drop(seccomp_memfd);
    drop(user_ns);
    drop(net_ns);

    let child_pidfd = sys::pidfd_open(child.id() as libc::pid_t)
        .map_err(|err| RunError::new(format!("cannot watch sbx __init: {err}")))?;
    let mut sb = Sandbox {
        bwrap_pid: child.id() as libc::pid_t,
        child,
        child_pidfd,
        pid1: Pid1::Pending {
            info: info_read,
            buf: Vec::new(),
        },
        // The join has no go byte; teardown treats the child as launched.
        go_sent: true,
    };
    let pumps = Pumps::start(
        &mut sb.child,
        OutputBudget::new(policy.limits.output_bytes),
        stdin_piped,
    )
    .map_err(|err| RunError::new(format!("cannot start the stdio pumps: {err}")))?;
    let latch = FaultLatch::new()
        .map_err(|err| RunError::new(format!("cannot create the fault latch: {err}")))?;
    let mut watch = HolderWatch {
        pidfd: holder_pidfd,
    };
    let cause = supervise(&mut sb, &signals, &latch, deadline, timeout, &mut watch);
    Ok(teardown(sb, cause, Some(pumps)))
}

/// The `__init --join` argv: the namespace descriptors, the kept bwrap fds, and
/// the call's bwrap argv after `--`.
fn join_command(
    user: RawFd,
    net: RawFd,
    info: RawFd,
    seccomp: RawFd,
    parent_pid: u32,
    launch: &Launch,
    stdin: Stdio,
) -> Command {
    let mut argv: Vec<OsString> = vec![
        "__init".into(),
        "--join-user".into(),
        user.to_string().into(),
        "--join-net".into(),
        net.to_string().into(),
        "--keep-fd".into(),
        info.to_string().into(),
        "--seccomp-fd".into(),
        seccomp.to_string().into(),
        "--parent-pid".into(),
        parent_pid.to_string().into(),
        "--".into(),
    ];
    argv.extend(launch.argv().iter().cloned());
    let mut cmd = Command::new("/proc/self/exe");
    cmd.args(argv)
        .env_clear()
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    cmd
}

/// Rule 6 of design point 4: tells the holder how the call ended. Best effort;
/// the holder may already be gone, and the call's rc is unaffected either way.
fn report_call_end(dir: &OwnedFd, id: u32, outcome: &Outcome, t0: Instant) {
    let Ok(stream) = ctl::connect_ctl(dir.as_fd()) else {
        return;
    };
    let end = CallEnd {
        call_id: id,
        rc: exit_code(outcome),
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        outcome: outcome_label(outcome),
    };
    let (op, payload) = Request::CallEnd(end).encode();
    if ctl::send_frame(&stream, op, &payload, &[]).is_ok() {
        let _ = ctl::recv_frame(&stream);
    }
}

/// `sbx stop --session-dir DIR` (rule 4).
pub(crate) fn stop(session_dir: PathBuf) -> ExitCode {
    let session = match absolutize(&session_dir) {
        Ok(path) => lexical_normalize(&path),
        Err(err) => {
            eprintln!("sbx stop: {}", err.reason());
            return ExitCode::from(EXIT_FAILURE as u8);
        }
    };
    let dir = match ctl::open_session_dir(&session) {
        Ok(fd) => fd,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sbx stop: cannot open the session directory: {err}");
            return ExitCode::from(EXIT_FAILURE as u8);
        }
    };
    let stream: UnixStream = match ctl::connect_ctl(dir.as_fd()) {
        Ok(stream) => stream,
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("sbx stop: cannot reach the session: {err}");
            return ExitCode::from(EXIT_FAILURE as u8);
        }
    };
    // The holder answers after its teardown, which can take a few seconds.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let (op, payload) = Request::Stop.encode();
    if let Err(err) = ctl::send_frame(&stream, op, &payload, &[]) {
        eprintln!("sbx stop: cannot send the stop request: {err:?}");
        return ExitCode::from(EXIT_FAILURE as u8);
    }
    match ctl::recv_frame(&stream).and_then(|(frame, _)| Reply::decode(frame)) {
        Ok(Reply::Done) => ExitCode::SUCCESS,
        Ok(Reply::Refused(reason)) => {
            eprintln!("sbx stop: {reason}");
            ExitCode::from(EXIT_FAILURE as u8)
        }
        Ok(Reply::Accepted(_)) | Err(_) => {
            eprintln!("sbx stop: the session did not confirm the stop");
            ExitCode::from(EXIT_FAILURE as u8)
        }
    }
}
