//! The session holder: `sbx run --keep-alive` (issue #18, design points 2, 3, 6, 7).
//!
//! 1. **Launch and detach.** `run --keep-alive` forks. The child is the holder:
//!    it calls `setsid`, points fds 0–2 at `/dev/null`, and runs the normal run
//!    startup with the resident command. The launcher waits on a pipe. The
//!    holder writes `R` once the resident is running, the control socket is
//!    bound and the namespace descriptors are captured; the launcher then exits
//!    0. Before that, the holder writes `E<reason>` on any failure and exits
//!    125, and the launcher prints the reason. The launcher never outlives a
//!    failed start, and the caller's stdout and stderr pipes close at `R`.
//! 2. **Logs.** After the session lock is taken the holder's stdout and stderr
//!    go to `<session>/holder.log` (`O_NOFOLLOW`, mode 0600). The resident's
//!    output is bounded by `limits.output_bytes`, as in a normal run, and the
//!    holder adds only its own diagnostics.
//! 3. **Pinned identity.** The holder pins the policy bytes it started with
//!    ([`PolicyPin`]). An attach admitted by byte equality shares the session's
//!    namespaces. Attaches to an explicit-mode session are refused (the join
//!    re-verifies nftables, which only the transparent mode loads).
//! 4. **Control socket.** `sbx.ctl` is bound before the go byte (see
//!    [`super::ctl`]). Each connection has a 2 s I/O budget, its peer uid is
//!    checked, and a frame that fails to decode is dropped without a reply. The
//!    holder serves connections serially from the supervisor loop.
//! 5. **Attach handshake.** An `Attach` request carries the attach process's
//!    pidfd (SCM_RIGHTS). The holder keeps it: the attach is the call's
//!    process, and the holder's pidfd for the attach is how a stop reaches it.
//!    The accepted reply returns three descriptors: the holder's own pidfd (the
//!    attach watches it, and kills its call if the holder dies), the session
//!    user-namespace fd and the session network-namespace fd.
//! 6. **Call end.** `CallEnd` must come from the same pid that attached. The
//!    holder writes the call's exit row (with `call_id`) and ends the call's
//!    idle accounting. An attach that dies without reporting is recorded as
//!    `failed`.
//! 7. **Lifetime.** [`Clock`] decides idle (no call for `--idle-timeout`) and
//!    max lifetime (`--max-lifetime` from the start). Either ends the session
//!    with the `timeout` outcome (rc 124). `sbx stop` ends it with the
//!    `terminated` outcome (rc 143 in the exit row).
//! 8. **Shutdown order.** Stop accepting attaches; send SIGTERM to every
//!    attached call's process (its own teardown kills its call); wait up to
//!    [`CALL_GRACE`] while still serving `CallEnd`; SIGKILL the stragglers and
//!    record them `terminated`; tear the resident down; unlink `sbx.ctl`; then
//!    reply `Done` to every `sbx stop` that asked. A stop returns only after the
//!    session is gone.
//! 9. **Death of the holder.** If the holder is killed, the resident dies through
//!    the existing chain (`PR_SET_PDEATHSIG` on `__init`, `--die-with-parent` on
//!    bwrap), and each attach dies because it watches the holder's pidfd. Nothing
//!    is left running after the holder. The stale `sbx.ctl` is replaced by the
//!    next holder, under the session lock.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::ctl;
use super::join::capture_namespaces;
use super::limits::{Clock, DEFAULT_IDLE, DEFAULT_MAX_LIFETIME, EndReason};
use super::pin::{MISMATCH, PolicyPin};
use super::proto::{Reply, Request};
use crate::run::audit::{AuditLog, call_exit_row, ts};
use crate::run::lifecycle::{Cause, Extra};
use crate::run::sys;
use crate::run::{RunArgs, RunError};

/// The holder's log file inside the session directory.
pub(crate) const LOG_FILE: &str = "holder.log";
/// How long an attached call may take to end after SIGTERM (rule 8).
pub(crate) const CALL_GRACE: Duration = Duration::from_secs(5);
/// The I/O budget of one control connection (rule 4).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest refusal reason the launcher will print.
const MAX_MESSAGE: usize = 1024;

/// The launcher's pipe and the holder's lifetime limits (rule 1).
pub(crate) struct Hold {
    ready: Option<std::fs::File>,
    pub(crate) idle: Duration,
    pub(crate) max: Duration,
}

impl Hold {
    /// Wraps the write end of the launcher's pipe.
    pub(crate) fn new(ready: OwnedFd, idle: Duration, max: Duration) -> Self {
        Self {
            ready: Some(std::fs::File::from(ready)),
            idle,
            max,
        }
    }

    /// Reports the session up (`R`) and closes the pipe. A no-op after the first call.
    pub(crate) fn signal_ready(&mut self) {
        if let Some(mut file) = self.ready.take() {
            let _ = file.write_all(b"R");
        }
    }

    /// Reports a failure before readiness (`E<reason>`). A no-op after readiness.
    pub(crate) fn fail(&mut self, reason: &str) {
        if let Some(mut file) = self.ready.take() {
            let mut msg = vec![b'E'];
            let mut end = reason.len().min(MAX_MESSAGE);
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            msg.extend_from_slice(&reason.as_bytes()[..end]);
            let _ = file.write_all(&msg);
        }
    }
}

/// `sbx run --keep-alive`, the launcher side (rule 1). Returns the exit code of
/// the launcher; the holder child never returns from [`crate::run`].
pub(crate) fn launch(args: RunArgs) -> ExitCode {
    let idle = args.idle_timeout.unwrap_or(DEFAULT_IDLE);
    let max = args.max_lifetime.unwrap_or(DEFAULT_MAX_LIFETIME);
    let (read_end, write_end) = match sys::pipe_cloexec() {
        Ok(pair) => pair,
        Err(err) => return launch_failed(&format!("cannot create the readiness pipe: {err}")),
    };
    // `pipe_cloexec` makes both ends non-blocking for the poll-based supervisors.
    // The readiness handoff is a plain blocking read, so both ends are blocking.
    for end in [&read_end, &write_end] {
        if let Err(err) = set_blocking(end) {
            return launch_failed(&format!("cannot configure the readiness pipe: {err}"));
        }
    }
    // SAFETY: fork before any thread exists in this process (run's single-threaded
    // startup); the child immediately becomes the holder.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return launch_failed(&format!(
            "cannot fork the session holder: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        drop(read_end);
        // SAFETY: setsid and the fd redirections are plain syscalls on this process.
        unsafe {
            libc::setsid();
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::dup2(null, 1);
                libc::dup2(null, 2);
                if null > 2 {
                    libc::close(null);
                }
            }
        }
        let hold = Hold::new(write_end, idle, max);
        return crate::run::run_session(args, Some(hold));
    }
    drop(write_end);
    let mut file = std::fs::File::from(read_end);
    let mut first = [0u8; 1];
    let got = loop {
        match std::io::Read::read(&mut file, &mut first) {
            Ok(n) => break n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break 0,
        }
    };
    if got == 1 && first[0] == b'R' {
        return ExitCode::SUCCESS;
    }
    let mut rest = Vec::new();
    let _ = std::io::Read::read_to_end(&mut file, &mut rest);
    let mut text = Vec::with_capacity(1 + rest.len());
    if got == 1 {
        text.push(first[0]);
    }
    text.extend_from_slice(&rest);
    let reason = match text.first() {
        Some(b'E') => String::from_utf8_lossy(&text[1..]).into_owned(),
        _ => reap_holder_reason(pid),
    };
    launch_failed(&reason)
}

/// Clears `O_NONBLOCK` on a descriptor.
fn set_blocking(fd: &OwnedFd) -> std::io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL on an fd this process owns.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The exit reason when the holder died without a message.
fn reap_holder_reason(pid: libc::pid_t) -> String {
    let mut status = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    "session holder exited before the session was ready".to_owned()
}

/// Prints one `sbx run:` line and returns rc 125 (the launcher's failure).
fn launch_failed(reason: &str) -> ExitCode {
    eprintln!("sbx run: {reason}");
    ExitCode::from(crate::run::EXIT_FAILURE as u8)
}

/// Opens `<session>/holder.log` and points fds 1 and 2 at it (rule 2). The
/// session directory is already locked and verified by the caller.
pub(crate) fn redirect_log(session: &Path) -> Result<(), RunError> {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(session.join(LOG_FILE))
        .map_err(|err| RunError::new(format!("cannot open the holder log: {err}")))?;
    // SAFETY: dup2 of an fd this process owns onto the standard streams.
    unsafe {
        if libc::dup2(log.as_raw_fd(), 1) < 0 || libc::dup2(log.as_raw_fd(), 2) < 0 {
            return Err(RunError::new(format!(
                "cannot redirect the holder output: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// One admitted attached call.
struct Call {
    id: u32,
    /// The attach process (the pid that sent `Attach`; `CallEnd` must match it).
    pid: libc::pid_t,
    /// The attach process's pidfd: readable when the attach exits.
    pidfd: OwnedFd,
    started: Instant,
}

/// The holder's state for the life of the session.
pub(crate) struct Holder {
    listener: UnixListener,
    dir: OwnedFd,
    pin: PolicyPin,
    clock: Clock,
    self_pidfd: OwnedFd,
    user_ns: OwnedFd,
    net_ns: OwnedFd,
    net_mode: &'static str,
    audit: Arc<AuditLog>,
    calls: Vec<Call>,
    next_id: u32,
    stopping: bool,
    stop_waiters: Vec<UnixStream>,
    stop_requested: bool,
}

/// Builds the holder after the resident is up and before the go byte (rule 4 and
/// the pre-go capture of design point 2): binds `sbx.ctl`, captures the
/// namespace descriptors of the parked `__init` (`init_pid`), and pins the policy.
pub(crate) fn prepare(
    hold: &Hold,
    session: &Path,
    init_pid: libc::pid_t,
    pin_bytes: Vec<u8>,
    net_mode: &'static str,
    audit: Arc<AuditLog>,
) -> Result<Holder, RunError> {
    let dir = ctl::open_session_dir(session)
        .map_err(|err| RunError::new(format!("cannot open the session directory: {err}")))?;
    let listener = ctl::bind_ctl(dir.as_fd())
        .map_err(|err| RunError::new(format!("cannot bind the control socket: {err}")))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| RunError::new(format!("cannot configure the control socket: {err}")))?;
    let (user_ns, net_ns) = capture_namespaces(init_pid)
        .map_err(|err| RunError::new(format!("cannot capture the session namespaces: {err}")))?;
    let self_pidfd = sys::pidfd_open(std::process::id() as libc::pid_t)
        .map_err(|err| RunError::new(format!("cannot open the holder pidfd: {err}")))?;
    Ok(Holder {
        listener,
        dir,
        pin: PolicyPin::new(pin_bytes),
        clock: Clock::new(Instant::now(), hold.idle, hold.max),
        self_pidfd,
        user_ns,
        net_ns,
        net_mode,
        audit,
        calls: Vec::new(),
        next_id: 1,
        stopping: false,
        stop_waiters: Vec::new(),
        stop_requested: false,
    })
}

/// Writes one reply with optional descriptors. Best effort: a vanished peer is
/// the peer's problem.
fn reply(stream: &UnixStream, msg: &Reply, fds: &[RawFd]) {
    let (op, payload) = msg.encode();
    let _ = ctl::send_frame(stream, op, &payload, fds);
}

impl Holder {
    /// Reads every pending connection (rule 4). Serial by design: each one has a
    /// bounded I/O budget.
    fn accept_all(&mut self, now: Instant) {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => self.handle(stream, now),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }

    /// One connection: peer check, one frame, one reply (or a silent drop).
    fn handle(&mut self, stream: UnixStream, now: Instant) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        let Ok((pid, uid)) = ctl::peer_creds(&stream) else {
            return;
        };
        if uid != unsafe { libc::geteuid() } {
            reply(
                &stream,
                &Reply::Refused("not the session owner".into()),
                &[],
            );
            return;
        }
        let Ok((frame, fds)) = ctl::recv_frame(&stream) else {
            return;
        };
        let Ok(request) = Request::decode(frame) else {
            return;
        };
        match request {
            Request::Attach(policy) => self.attach(&stream, pid, &policy, fds, now),
            Request::CallEnd(end) => self.call_end(&stream, pid, end, now),
            Request::Stop => {
                self.stopping = true;
                self.stop_requested = true;
                // Replied to at finish, so a stop returns only once the session is gone.
                self.stop_waiters.push(stream);
            }
        }
    }

    fn attach(
        &mut self,
        stream: &UnixStream,
        pid: libc::pid_t,
        policy: &[u8],
        fds: Vec<OwnedFd>,
        now: Instant,
    ) {
        if self.stopping {
            reply(stream, &Reply::Refused("session is stopping".into()), &[]);
            return;
        }
        if fds.len() != 1 {
            reply(
                stream,
                &Reply::Refused("attach must send exactly one descriptor".into()),
                &[],
            );
            return;
        }
        if self.net_mode != "transparent" {
            reply(
                stream,
                &Reply::Refused("attach needs a transparent-mode session".into()),
                &[],
            );
            return;
        }
        if !self.pin.matches(policy) {
            reply(stream, &Reply::Refused(MISMATCH.into()), &[]);
            return;
        }
        let id = self.next_id;
        let Some(next) = id.checked_add(1) else {
            reply(
                stream,
                &Reply::Refused("session call ids are exhausted".into()),
                &[],
            );
            return;
        };
        self.next_id = next;
        let pidfd = fds.into_iter().next().expect("one descriptor was checked");
        self.calls.push(Call {
            id,
            pid,
            pidfd,
            started: now,
        });
        self.clock.call_started();
        let raw = [
            self.self_pidfd.as_raw_fd(),
            self.user_ns.as_raw_fd(),
            self.net_ns.as_raw_fd(),
        ];
        let (op, payload) = Reply::Accepted(id).encode();
        if ctl::send_frame(stream, op, &payload, &raw).is_err() {
            // The attach never got the call: take it back.
            self.calls.retain(|c| c.id != id);
            self.clock.call_ended(now);
        }
    }

    fn call_end(
        &mut self,
        stream: &UnixStream,
        pid: libc::pid_t,
        end: super::proto::CallEnd,
        now: Instant,
    ) {
        let Some(pos) = self.calls.iter().position(|c| c.id == end.call_id) else {
            reply(stream, &Reply::Refused("unknown call".into()), &[]);
            return;
        };
        if self.calls[pos].pid != pid {
            reply(
                stream,
                &Reply::Refused("call belongs to another process".into()),
                &[],
            );
            return;
        }
        self.calls.remove(pos);
        self.audit.append_row(&call_exit_row(
            ts(SystemTime::now()),
            end.call_id,
            end.rc,
            end.outcome,
            end.duration_ms,
            Some(self.net_mode),
        ));
        self.clock.call_ended(now);
        reply(stream, &Reply::Done, &[]);
    }

    /// Records calls whose attach died without reporting (rule 6).
    fn reap_dead(&mut self, dead_ids: &[u32], now: Instant) {
        for id in dead_ids {
            let Some(pos) = self.calls.iter().position(|c| c.id == *id) else {
                continue; // reported in the meantime
            };
            if !matches!(
                sys::wait_readable(self.calls[pos].pidfd.as_fd(), Duration::ZERO),
                Ok(true)
            ) {
                continue;
            }
            let call = self.calls.remove(pos);
            let ms = u64::try_from(now.saturating_duration_since(call.started).as_millis())
                .unwrap_or(u64::MAX);
            self.audit.append_row(&call_exit_row(
                ts(SystemTime::now()),
                call.id,
                crate::run::EXIT_FAILURE,
                "failed",
                ms,
                Some(self.net_mode),
            ));
            self.clock.call_ended(now);
        }
    }

    /// Rule 8: SIGTERM every call, serve until they end or [`CALL_GRACE`] passes,
    /// then SIGKILL and record the stragglers.
    pub(crate) fn end_calls(&mut self, grace: Duration) {
        self.stopping = true;
        for call in &self.calls {
            let _ = sys::pidfd_signal(call.pidfd.as_fd(), libc::SIGTERM);
        }
        let until = Instant::now() + grace;
        while !self.calls.is_empty() {
            let now = Instant::now();
            if now >= until {
                break;
            }
            let mut pfds: Vec<libc::pollfd> = self
                .fds()
                .into_iter()
                .map(|fd| sys::pollfd(fd, libc::POLLIN))
                .collect();
            let step = until.min(now + Duration::from_millis(100));
            if sys::poll_fds(&mut pfds, Some(step)).is_err() {
                break;
            }
            let revents: Vec<libc::c_short> = pfds.iter().map(|p| p.revents).collect();
            let _ = self.wake(&revents);
        }
        let now = Instant::now();
        for call in self.calls.drain(..) {
            let _ = sys::pidfd_kill(call.pidfd.as_fd());
            let ms = u64::try_from(now.saturating_duration_since(call.started).as_millis())
                .unwrap_or(u64::MAX);
            self.audit.append_row(&call_exit_row(
                ts(SystemTime::now()),
                call.id,
                143,
                "terminated",
                ms,
                Some(self.net_mode),
            ));
        }
    }

    /// Rule 8, last steps: remove `sbx.ctl` and answer every `sbx stop`.
    pub(crate) fn finish(mut self) {
        ctl::unlink_ctl(self.dir.as_fd());
        drop(self.listener);
        for waiter in self.stop_waiters.drain(..) {
            reply(&waiter, &Reply::Done, &[]);
        }
    }
}

impl Extra for Holder {
    fn fds(&self) -> Vec<RawFd> {
        let mut fds = vec![self.listener.as_raw_fd()];
        fds.extend(self.calls.iter().map(|c| c.pidfd.as_raw_fd()));
        fds
    }

    fn deadline(&self) -> Option<Instant> {
        Some(self.clock.next_deadline())
    }

    fn wake(&mut self, revents: &[libc::c_short]) -> Option<Cause> {
        let now = Instant::now();
        // Snapshot the calls whose attach is gone before any connection is
        // served: a CallEnd queued before the attach exited is then honoured.
        let dead: Vec<u32> = self
            .calls
            .iter()
            .zip(revents.iter().skip(1))
            .filter(|(_, ev)| sys::ready(**ev))
            .map(|(c, _)| c.id)
            .collect();
        if revents.first().is_some_and(|ev| sys::ready(*ev)) {
            self.accept_all(now);
        }
        self.reap_dead(&dead, now);
        if self.stop_requested {
            return Some(Cause::Signal(libc::SIGTERM));
        }
        match self.clock.expired(now) {
            Some(EndReason::Idle) => Some(Cause::Timeout(self.clock.idle())),
            Some(EndReason::MaxLifetime) => Some(Cause::Timeout(self.clock.max())),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// A blocking reader and the holder's write end. `pipe_cloexec` makes both
    /// ends non-blocking, so the read end is switched back for the test reader.
    fn pipe() -> (std::fs::File, OwnedFd) {
        let (r, w) = sys::pipe_cloexec().expect("pipe");
        set_blocking(&r).expect("blocking read end");
        (std::fs::File::from(r), w)
    }

    #[test]
    fn ready_is_reported_once_and_nothing_follows() {
        let (mut r, w) = pipe();
        let mut hold = Hold::new(w, DEFAULT_IDLE, DEFAULT_MAX_LIFETIME);
        hold.signal_ready();
        hold.signal_ready();
        hold.fail("too late");
        drop(hold); // closes the write end, so the read below ends
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"R");
    }

    #[test]
    fn failure_is_reported_as_e_and_capped() {
        let (mut r, w) = pipe();
        let mut hold = Hold::new(w, DEFAULT_IDLE, DEFAULT_MAX_LIFETIME);
        let long = "x".repeat(5000);
        hold.fail(&long);
        drop(hold);
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got[0], b'E');
        assert_eq!(got.len(), 1 + MAX_MESSAGE);
    }

    #[test]
    fn failure_cut_keeps_utf8_whole() {
        let (mut r, w) = pipe();
        let mut hold = Hold::new(w, DEFAULT_IDLE, DEFAULT_MAX_LIFETIME);
        let text = format!("{}é", "a".repeat(MAX_MESSAGE - 1));
        hold.fail(&text);
        drop(hold);
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert!(std::str::from_utf8(&got[1..]).is_ok());
    }
}
