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
use super::proto::{CallEnd, ProtoError, Reply, Request, SessionLandlock};
use crate::bwrap::seccomp;
use crate::bwrap::version::{BwrapStatus, find_bwrap};
use crate::bwrap::{Build, Launch, build};
use crate::policy::Policy;
use crate::run::lifecycle::{Cause, Extra, Pid1, Sandbox, supervise, teardown};
use crate::run::plan::{
    absolutize, effective_timeout, exit_code, exit_reason, lexical_normalize, outcome_label,
    passed_env, sbx_diagnostic,
};
use crate::run::serve::FaultLatch;
use crate::run::stdio::{OutputBudget, PumpEnd, Pumps};
use crate::run::sys;
use crate::run::{
    EXIT_FAILURE, Early, LandlockSetup, Outcome, RunError, check_bwrap_version, deadline_from,
    stdin_mode, write_diagnostics,
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

    // Rule 2 of the handshake: our own pidfd travels with the Attach request.
    let self_pidfd = sys::pidfd_open(std::process::id() as libc::pid_t)
        .map_err(|err| RunError::new(format!("cannot open the attach pidfd: {err}")))?;
    let (op, payload) = Request::Attach(policy_bytes).encode();
    if let Err(err) = ctl::send_frame(&stream, op, &payload, &[self_pidfd.as_raw_fd()]) {
        if let Some(reason) = early_refusal(&stream, &err) {
            return Err(RunError::new(format!("session refused the call: {reason}")).into());
        }
        return Err(RunError::new(format!("cannot send the attach request: {err:?}")).into());
    }
    let (frame, fds) = ctl::recv_frame(&stream)
        .map_err(|err| RunError::new(format!("the session did not answer: {err:?}")))?;
    let (id, landlock, mut fds) = match Reply::decode(frame) {
        // The session's Landlock settings come with the admission: the call applies
        // them, and the attach has no Landlock flags of its own to weaken them.
        Ok(Reply::Accepted(id, landlock)) if fds.len() == 3 => (id, landlock, fds),
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
        &landlock,
    ) {
        Ok(done) => done,
        Err(early) => (early_outcome(early), PumpEnd::default(), false),
    };
    report_call_end(&dir, id, &outcome, end.truncated, t0);
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
    landlock: &SessionLandlock,
) -> Result<(Outcome, PumpEnd, bool), Early> {
    let signals = sys::Signals::install()
        .map_err(|err| RunError::new(format!("cannot block signals: {err}")))?;
    sys::reset_sigchld();
    let bwrap = find_bwrap()
        .ok_or_else(|| RunError::new(BwrapStatus::NotFound.run_reason().unwrap_or_default()))?;
    let bwrap_version = check_bwrap_version(&bwrap, deadline, timeout, &signals)?;
    let env = passed_env(policy, |name| std::env::var_os(name));
    let (info_read, info_write) = sys::pipe_cloexec()
        .map_err(|err| RunError::new(format!("cannot create the info pipe: {err}")))?;
    let seccomp_memfd = seccomp::program_memfd()
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    // The session's Landlock layer (issue #56 with #18): the same setup, the same
    // layer and the same refusal as the resident's `run`, so every call is confined
    // exactly as the resident is. `require` on a kernel below ABI 6 is refused
    // before anything is spawned.
    if landlock.mode == crate::landlock::Mode::Require {
        if let Some(reason) = crate::landlock::require_refusal(crate::landlock::kernel_abi()) {
            return Err(RunError::new(reason).into());
        }
    }
    let setup = crate::run::landlock_setup(landlock.mode)?;
    let layer =
        crate::run::landlock_layer(&setup.exe, &setup.status, landlock.mode, &landlock.bind_tcp);
    let launch: Launch = build(&Build {
        policy,
        session_dir: session,
        bwrap_path: &bwrap,
        command: &args.cmd,
        cwd: args.cwd.as_deref(),
        passed_env: &env,
        info_fd: Some(info_write.as_raw_fd()),
        seccomp_fd: seccomp_memfd.as_raw_fd(),
        landlock: layer,
        deny_tmpfs_size: crate::bwrap::deny_tmpfs_size_for(bwrap_version),
    })
    .map_err(|err| RunError::new(err.to_string()))?;
    // S8a (#39/#40, N19) on every call: a payload may have planted a link under a
    // writable bind since the resident started, so the call re-verifies its launch.
    crate::run::verify_launch(&launch)?;

    let info_fd = sys::clear_cloexec(info_write.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the info pipe: {err}")))?;
    let seccomp_fd = sys::clear_cloexec(seccomp_memfd.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the seccomp filter: {err}")))?;
    let user_fd = sys::clear_cloexec(user_ns.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the namespace fds: {err}")))?;
    let net_fd = sys::clear_cloexec(net_ns.as_fd())
        .map_err(|err| RunError::new(format!("cannot prepare the namespace fds: {err}")))?;
    let exe_fd = match &setup.exe {
        Some(file) => Some(
            sys::clear_cloexec(file.as_fd())
                .map_err(|err| RunError::new(format!("cannot prepare the shim: {err}")))?,
        ),
        None => None,
    };
    let status_fd = match &setup.status {
        Some((_, write)) => Some(
            sys::clear_cloexec(write.as_fd())
                .map_err(|err| RunError::new(format!("cannot prepare the shim status: {err}")))?,
        ),
        None => None,
    };
    let (stdin, stdin_piped) = stdin_mode();
    // Issue #43: the call's cgroup limits. The join execs bwrap at once (no go
    // byte), so sbx spawns from inside the child cgroup (`spawn_inside`).
    let limits_cgroup = crate::run::cgroup_for(policy)?;
    let mut command = join_command(
        JoinFds {
            user: user_fd,
            net: net_fd,
            info: info_fd,
            seccomp: seccomp_fd,
            shim: JoinShim {
                exe: exe_fd,
                status: status_fd,
            },
        },
        std::process::id(),
        &crate::init::rlimit::from_limits(&policy.limits),
        &launch,
        stdin,
    );
    let spawned = match &limits_cgroup {
        None => command.spawn(),
        Some(cg) => {
            let (spawned, back) = cg
                .spawn_inside(|| command.spawn())
                .map_err(|err| RunError::new(err.to_string()))?;
            match (spawned, back) {
                (Ok(mut child), Err(err)) => {
                    // sbx stayed in the sandbox cgroup: refuse rather than
                    // supervise from inside the limited cgroup.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::new(err.to_string()).into());
                }
                (spawned, _) => spawned,
            }
        }
    };
    let child = spawned.map_err(|err| RunError::new(format!("cannot spawn sbx __init: {err}")))?;
    let _cgroup_guard = crate::run::CgroupGuard(limits_cgroup);
    drop(info_write);
    drop(seccomp_memfd);
    drop(user_ns);
    drop(net_ns);
    let LandlockSetup {
        exe: exe_file,
        status: status_pipe,
    } = setup;
    drop(exe_file);
    let (status_read, status_write) = match status_pipe {
        Some((read, write)) => (Some(read), Some(write)),
        None => (None, None),
    };
    drop(status_write);

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
    let (outcome, end, stragglers) = teardown(sb, cause, Some(pumps));
    // The shim's status pipe, read as `run` reads it (issue #19 M1).
    let outcome = crate::run::landlock_status_outcome(outcome, status_read.as_ref());
    Ok((outcome, end, stragglers))
}

/// The descriptors one join hands `__init --join`: the session's namespace fds,
/// the kept bwrap fds, and the shim's fds when the session has a Landlock layer.
struct JoinFds {
    user: RawFd,
    net: RawFd,
    info: RawFd,
    seccomp: RawFd,
    shim: JoinShim,
}

/// The shim's descriptors of one join (`--exe-fd` and `--status-fd`).
#[derive(Clone, Copy)]
struct JoinShim {
    exe: Option<RawFd>,
    status: Option<RawFd>,
}

/// The `__init --join` argv: the namespace descriptors, the kept bwrap fds, the
/// policy's resource limits (issue #43: a call is limited as the resident is),
/// and the call's bwrap argv after `--`.
fn join_command(
    fds: JoinFds,
    parent_pid: u32,
    rlimits: &[crate::init::rlimit::Rlimit],
    launch: &Launch,
    stdin: Stdio,
) -> Command {
    let JoinFds {
        user,
        net,
        info,
        seccomp,
        shim,
    } = fds;
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
    ];
    if let Some(exe) = shim.exe {
        argv.push("--exe-fd".into());
        argv.push(exe.to_string().into());
    }
    if let Some(status) = shim.status {
        argv.push("--status-fd".into());
        argv.push(status.to_string().into());
    }
    for limit in rlimits {
        argv.push("--rlimit".into());
        argv.push(limit.to_string().into());
    }
    argv.push("--".into());
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
fn report_call_end(dir: &OwnedFd, id: u32, outcome: &Outcome, truncated: bool, t0: Instant) {
    let Ok(stream) = ctl::connect_ctl(dir.as_fd()) else {
        return;
    };
    let end = CallEnd {
        call_id: id,
        rc: exit_code(outcome),
        duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        outcome: outcome_label(outcome),
        truncated,
        // The same reason `sbx run` writes on its exit row (bounded by the codec).
        reason: exit_reason(outcome),
    };
    let (op, payload) = Request::CallEnd(end).encode();
    if ctl::send_frame(&stream, op, &payload, &[]).is_ok() {
        let _ = ctl::recv_frame(&stream);
    }
}

/// How long `sbx stop` waits for the holder's answer (rule 4). The holder answers
/// only after its teardown, which can take a few seconds (the call grace period is
/// [`super::holder::CALL_GRACE`], 5 s), so the wait is generous: 120 s.
pub(crate) const STOP_ANSWER_WAIT: Duration = Duration::from_secs(120);

/// `sbx stop --session-dir DIR` (rule 4).
pub(crate) fn stop(session_dir: PathBuf) -> ExitCode {
    stop_with_wait(session_dir, STOP_ANSWER_WAIT)
}

/// `sbx stop` with the answer wait as a parameter, so a test can prove the
/// give-up path without sleeping for the real budget. Prints the reason on stderr
/// and returns rc 125 when the stop is not confirmed.
fn stop_with_wait(session_dir: PathBuf, answer_wait: Duration) -> ExitCode {
    match stop_session(session_dir, answer_wait) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("sbx stop: {reason}");
            ExitCode::from(EXIT_FAILURE as u8)
        }
    }
}

/// The stop itself. `Ok` when the session is stopped or was not running; `Err` with
/// the reason otherwise (the caller prints it and exits 125). The holder's answer is
/// awaited for at most `answer_wait` from the moment the request is sent.
fn stop_session(session_dir: PathBuf, answer_wait: Duration) -> Result<(), String> {
    let session = match absolutize(&session_dir) {
        Ok(path) => lexical_normalize(&path),
        Err(err) => return Err(err.reason().to_owned()),
    };
    let dir = match ctl::open_session_dir(&session) {
        Ok(fd) => fd,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("cannot open the session directory: {err}")),
    };
    let stream: UnixStream = match ctl::connect_ctl(dir.as_fd()) {
        Ok(stream) => stream,
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            return Ok(());
        }
        Err(err) => return Err(format!("cannot reach the session: {err}")),
    };
    let (op, payload) = Request::Stop.encode();
    if let Err(err) = ctl::send_frame_until(
        &stream,
        op,
        &payload,
        &[],
        Instant::now() + Duration::from_secs(5),
    ) {
        if let Some(reason) = early_refusal(&stream, &err) {
            return Err(reason);
        }
        return Err(format!("cannot send the stop request: {err:?}"));
    }
    // The holder answers after its teardown, which can take a few seconds: the
    // whole wait has the `answer_wait` deadline (STOP_ANSWER_WAIT in production).
    let answer = ctl::recv_frame_until(&stream, Instant::now() + answer_wait);
    match answer.and_then(|(frame, _)| Reply::decode(frame)) {
        Ok(Reply::Done) => Ok(()),
        Ok(Reply::Refused(reason)) => Err(reason),
        Ok(Reply::Accepted(_, _)) | Err(_) => {
            Err("the session did not confirm the stop".to_owned())
        }
    }
}

/// How long a client looks for an early refusal after its send failed.
pub(crate) const EARLY_REFUSAL_WAIT: Duration = Duration::from_secs(1);

/// The holder may answer and close BEFORE reading the request: a peer of
/// another uid is refused ("not the session owner") before its frame is read.
/// The client's send then fails with EPIPE or ECONNRESET, but the refusal is
/// already queued on the AF_UNIX socket (a peer's close never discards data it
/// sent), so read it: the caller sees the holder's reason, not a transport
/// error. Anything else (no frame, not a refusal) is `None`, and the send
/// error stands.
fn early_refusal(stream: &UnixStream, err: &ProtoError) -> Option<String> {
    let ProtoError::Io(io) = err else {
        return None;
    };
    // EPIPE is what Linux reports on the send. ECONNRESET is accepted too: it
    // is the peer's unread-data reset, and AF_UNIX still delivers the queued
    // frame before surfacing that error on a read.
    if !matches!(
        io.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
    ) {
        return None;
    }
    let (frame, _) = ctl::recv_frame_until(stream, Instant::now() + EARLY_REFUSAL_WAIT).ok()?;
    match Reply::decode(frame) {
        Ok(Reply::Refused(reason)) => Some(reason),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch session directory with no `sbx.ctl` yet (mode 0700, like a real one).
    fn scratch_session(tag: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("sbx-stop-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("session dir");
        dir
    }

    #[test]
    fn stop_answer_wait_is_pinned_at_120_seconds() {
        assert_eq!(STOP_ANSWER_WAIT, Duration::from_secs(120));
    }

    /// A holder that accepts the stop and never answers: `sbx stop` gives up when
    /// its wait runs out, with the pinned reason and rc 125. The wait is 300 ms, so
    /// the test does not sleep for the real budget.
    #[test]
    fn a_holder_that_never_answers_makes_stop_give_up_at_the_deadline() {
        let dir = scratch_session("silent");
        let dirfd = ctl::open_session_dir(&dir).expect("open the session dir");
        let listener = ctl::bind_ctl(dirfd.as_fd()).expect("bind the control socket");
        let (release, held) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let (conn, _) = listener.accept().expect("the stop connects");
            // Keep the connection open and silent until the test is done.
            let _ = held.recv();
            drop(conn);
        });

        let wait = Duration::from_millis(300);
        let started = Instant::now();
        let outcome = stop_session(dir.clone(), wait);
        let elapsed = started.elapsed();
        let code = stop_with_wait(dir.clone(), wait);
        let _ = release.send(());
        holder.join().expect("the fake holder ends");

        assert_eq!(
            outcome,
            Err("the session did not confirm the stop".to_owned())
        );
        assert!(elapsed >= wait, "gave up before the deadline: {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(20),
            "waited far beyond the deadline: {elapsed:?}"
        );
        assert_eq!(code, ExitCode::from(EXIT_FAILURE as u8));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A holder that answers with a refusal: the reason is carried to the caller.
    #[test]
    fn a_refused_stop_carries_the_holders_reason() {
        let dir = scratch_session("refused");
        let dirfd = ctl::open_session_dir(&dir).expect("open the session dir");
        let listener = ctl::bind_ctl(dirfd.as_fd()).expect("bind the control socket");
        let holder = std::thread::spawn(move || {
            let (conn, _) = listener.accept().expect("the stop connects");
            // Read the request first, as the real holder does: answering and
            // closing before the client has sent its Stop races its write
            // into EPIPE (seen on CI).
            ctl::recv_frame(&conn).expect("the stop request arrives");
            let (op, payload) = Reply::Refused("session is stopping".into()).encode();
            ctl::send_frame(&conn, op, &payload, &[]).expect("answer");
        });
        let outcome = stop_session(dir.clone(), Duration::from_secs(10));
        holder.join().expect("the fake holder ends");
        assert_eq!(outcome, Err("session is stopping".to_owned()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A holder that refuses and closes WITHOUT reading the request (as the
    /// real holder does for a foreign uid): the client's send hits EPIPE, and
    /// the queued refusal is still reported.
    #[test]
    fn a_refusal_before_the_request_is_read_survives_epipe() {
        let dir = scratch_session("early");
        let dirfd = ctl::open_session_dir(&dir).expect("open the session dir");
        let listener = ctl::bind_ctl(dirfd.as_fd()).expect("bind the control socket");
        let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            for _ in 0..2 {
                let (conn, _) = listener.accept().expect("a client connects");
                let (op, payload) = Reply::Refused("not the session owner".into()).encode();
                ctl::send_frame(&conn, op, &payload, &[]).expect("answer");
                // Close without reading anything, then say so.
                drop(conn);
                let _ = closed_tx.send(());
            }
        });

        // The helper, deterministically: the send happens only after the
        // holder has dropped its end, so it must fail (EPIPE), and the
        // refusal queued before the close must be recovered.
        let client = ctl::connect_ctl(dirfd.as_fd()).expect("connect");
        closed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the holder closes");
        let err =
            ctl::send_frame(&client, b'S', &[], &[]).expect_err("a send to a closed peer fails");
        assert_eq!(
            early_refusal(&client, &err).as_deref(),
            Some("not the session owner")
        );

        // End to end through stop. Not deterministic about WHICH path runs
        // (the tiny Stop frame races the holder's close inside stop_session:
        // either the send succeeds and the normal reply path reads the
        // refusal, or it fails and early_refusal does), but both must report
        // the holder's reason. The helper half above pins the EPIPE branch.
        assert_eq!(
            stop_session(dir.clone(), Duration::from_secs(10)),
            Err("not the session owner".to_owned())
        );
        holder.join().expect("the fake holder ends");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Other send errors are not mistaken for a refusal.
    #[test]
    fn early_refusal_ignores_other_errors() {
        let (a, _b) = UnixStream::pair().expect("pair");
        assert_eq!(early_refusal(&a, &ProtoError::TooLarge(1)), None);
        assert_eq!(early_refusal(&a, &ProtoError::Eof), None);
        let refused = ProtoError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(early_refusal(&a, &refused), None);
    }

    /// No socket at all is a session that is not running: rc 0.
    #[test]
    fn stop_of_a_session_that_is_not_running_is_ok() {
        let dir = scratch_session("absent");
        assert_eq!(stop_session(dir.clone(), STOP_ANSWER_WAIT), Ok(()));
        assert_eq!(
            stop_with_wait(dir.clone(), STOP_ANSWER_WAIT),
            ExitCode::SUCCESS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
