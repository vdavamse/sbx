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
//!    [`super::ctl`]). Each connection has one 2 s deadline, `REQUEST_TIMEOUT`,
//!    covering its whole request and its reply: every read and write polls
//!    against the time left, so a peer that trickles bytes is cut off at the
//!    deadline and cannot extend it. Its peer uid is checked, and a frame that
//!    fails to decode is dropped without a reply. Each supervisor wake accepts at
//!    most `ACCEPT_BATCH` (8) connections and then returns to the loop, so
//!    signals, the lifetime clock and the resident are checked between batches.
//!    Connections are served serially, so a stalled peer costs at most its own
//!    deadline.
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
//! 10. **Accept failures.** `accept()` errors are classified by errno
//!     ([`classify_accept`]). A resource exhaustion (`EMFILE`, `ENFILE`, `ENOBUFS`,
//!     `ENOMEM`) takes the listener out of the poll for [`ACCEPT_BACKOFF`] and
//!     retries afterwards, so a full descriptor table cannot spin the holder and
//!     the session keeps serving once descriptors free up. Any other error ends the
//!     session fail-closed: the exit row records `failed` and the calls are
//!     stopped. A client that gave up (`ECONNABORTED`) is skipped.
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
use super::proto::{Reply, Request, SessionLandlock};
use crate::dns::FakeIpMap;
use crate::run::audit::{AuditLog, CallExit, call_exit_row, ts};
use crate::run::lifecycle::{Cause, Extra};
use crate::run::sys;
use crate::run::{RunArgs, RunError};

/// The holder's log file inside the session directory.
pub(crate) const LOG_FILE: &str = "holder.log";
/// How long an attached call may take to end after SIGTERM (rule 8).
pub(crate) const CALL_GRACE: Duration = Duration::from_secs(5);
/// The budget of one control connection: the whole request and its reply share
/// this single deadline (rule 4). A slow client cannot extend it byte by byte.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// How many accept batches the teardown drain serves at most (review 4).
pub(crate) const DRAIN_ROUNDS: usize = 8;
/// The most connections one supervisor wake serves (rule 4): the loop runs its
/// signal, child and clock checks between batches.
pub(crate) const ACCEPT_BATCH: usize = 8;
/// The longest refusal reason the launcher will print.
const MAX_MESSAGE: usize = 1024;
/// How long the listener is left out of the poll after a resource-exhaustion
/// `accept` failure (rule 10). A retry happens after this long, not in a spin.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(250);

/// What the holder does with an `accept()` failure (rule 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptFault {
    /// The queue is empty for now (`EAGAIN`): stop accepting this round.
    Drained,
    /// A client gave up before accept (`ECONNABORTED` and the like): try the next.
    Next,
    /// Descriptors or memory are exhausted (`EMFILE`, `ENFILE`, `ENOBUFS`,
    /// `ENOMEM`): leave the listener out of the poll for [`ACCEPT_BACKOFF`].
    Backoff,
    /// Anything else: the control socket is unusable; the session ends
    /// fail-closed (exit row `failed`).
    Fatal,
}

/// Classifies an `accept()` failure by its errno (rule 10; pure, unit-tested).
pub(crate) fn classify_accept(errno: Option<i32>) -> AcceptFault {
    match errno {
        Some(libc::EAGAIN) => AcceptFault::Drained,
        Some(libc::ECONNABORTED | libc::EPROTO | libc::EINTR) => AcceptFault::Next,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => AcceptFault::Backoff,
        _ => AcceptFault::Fatal,
    }
}

/// The fd the poll sees for the listener: the listener itself, or `-1` (which
/// `poll` ignores) while the holder backs off after an exhaustion error.
pub(crate) fn listener_poll_fd(listener: RawFd, backing_off: bool) -> RawFd {
    if backing_off { -1 } else { listener }
}

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
        // Review 9 of #57: the holder lives for hours, so it must not keep the
        // caller's inherited descriptors (a jobserver pipe, say). Everything above
        // stdio goes, except the readiness pipe's write end.
        close_inherited_fds(write_end.as_raw_fd());
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

/// The descriptors to close in the holder: every open one above stdio except
/// `keep` (review 9; pure, unit-tested).
pub(crate) fn fds_to_close(open: Vec<RawFd>, keep: RawFd) -> Vec<RawFd> {
    open.into_iter()
        .filter(|fd| *fd > 2 && *fd != keep)
        .collect()
}

/// Closes the inherited descriptors of the forked holder (review 9). Scans
/// `/proc/self/fd` first, so the scan's own directory descriptor is never closed
/// under the iterator.
fn close_inherited_fds(keep: RawFd) {
    let open: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
        .map(|dir| {
            dir.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok())
                .collect()
        })
        .unwrap_or_default();
    for fd in fds_to_close(open, keep) {
        // SAFETY: a descriptor number this process holds; EBADF (already closed,
        // e.g. the scan's own) is ignored.
        unsafe {
            libc::close(fd);
        }
    }
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
    /// The session's fake-IP map, shared with the proxies (its poison flag is
    /// the call rows' `dns_poisoned`).
    map: Arc<FakeIpMap>,
    /// The Landlock settings pinned at start, sent with every accepted attach.
    landlock: SessionLandlock,
    calls: Vec<Call>,
    next_id: u32,
    stopping: bool,
    stop_waiters: Vec<UnixStream>,
    stop_requested: bool,
    /// Set after a resource-exhaustion `accept` failure (rule 10).
    backoff_until: Option<Instant>,
    /// Set by a fatal `accept` failure; the next wake ends the session.
    fatal: Option<String>,
    /// The deadline of the connection being served (rule 4).
    conn_deadline: Instant,
}

/// What the holder is built from besides the session paths (`prepare`).
pub(crate) struct HolderInputs {
    /// The policy bytes the session pins.
    pub(crate) pin_bytes: Vec<u8>,
    /// The achieved network mode (`transparent` or `explicit`).
    pub(crate) net_mode: &'static str,
    pub(crate) audit: Arc<AuditLog>,
    /// The session's fake-IP map, shared with the proxies.
    pub(crate) map: Arc<FakeIpMap>,
    /// The session's Landlock settings, pinned at start (issue #56 with #18): an
    /// attach applies exactly these, and sends none of its own.
    pub(crate) landlock: SessionLandlock,
}

/// Builds the holder after the resident is up and before the go byte (rule 4 and
/// the pre-go capture of design point 2): binds `sbx.ctl`, captures the
/// namespace descriptors of the parked `__init` (`init_pid`), and pins the policy.
pub(crate) fn prepare(
    hold: &Hold,
    t0: Instant,
    session: &Path,
    init_pid: libc::pid_t,
    inputs: HolderInputs,
) -> Result<Holder, RunError> {
    let HolderInputs {
        pin_bytes,
        net_mode,
        audit,
        map,
        landlock,
    } = inputs;
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
        // The lifetime runs from the start of the run, setup included (review 6).
        clock: Clock::new(t0, hold.idle, hold.max),
        self_pidfd,
        user_ns,
        net_ns,
        net_mode,
        audit,
        map,
        landlock,
        calls: Vec::new(),
        next_id: 1,
        stopping: false,
        stop_waiters: Vec::new(),
        stop_requested: false,
        backoff_until: None,
        fatal: None,
        conn_deadline: Instant::now(),
    })
}

/// Writes one reply with optional descriptors, before `deadline`. Best effort: a
/// vanished or stalled peer loses its reply, and the caller undoes the work.
fn reply(stream: &UnixStream, msg: &Reply, fds: &[RawFd], deadline: Instant) {
    let (op, payload) = msg.encode();
    let _ = ctl::send_frame_until(stream, op, &payload, fds, deadline);
}

/// Whether the pidfd `fd` names process `pid` (review 3). The pid is read from
/// the descriptor's fdinfo, so a caller cannot register a pidfd of some other
/// process as its attach and get that process's call ended by the holder.
pub(crate) fn pidfd_names_process(fd: RawFd, pid: libc::pid_t) -> bool {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("Pid:"))
                .and_then(|v| v.trim().parse::<libc::pid_t>().ok())
        })
        .is_some_and(|named| named == pid)
}

/// How one accept round ended (rule 10 and the batch cap).
#[derive(Debug)]
pub(crate) enum RoundEnd {
    /// The backlog is empty for now.
    Drained,
    /// The batch cap was reached; more may be waiting.
    Capped,
    /// Descriptors or memory are exhausted: back off.
    Backoff,
    /// The socket is unusable: end the session.
    Fatal(String),
}

/// The connections one accept round collected, and how the round ended.
#[derive(Debug)]
pub(crate) struct AcceptRound {
    pub(crate) streams: Vec<UnixStream>,
    pub(crate) end: RoundEnd,
}

/// Accepts up to `cap` connections (rule 4). `accept` is the listener's accept;
/// a client that gave up is skipped, and skips count toward the cap so an endless
/// stream of them cannot hold the loop either.
pub(crate) fn accept_round(
    mut accept: impl FnMut() -> std::io::Result<UnixStream>,
    cap: usize,
) -> AcceptRound {
    let mut streams = Vec::new();
    let mut skipped = 0usize;
    loop {
        if streams.len() >= cap || skipped >= cap {
            return AcceptRound {
                streams,
                end: RoundEnd::Capped,
            };
        }
        match accept() {
            Ok(stream) => streams.push(stream),
            Err(err) => {
                let end = match classify_accept(err.raw_os_error()) {
                    AcceptFault::Next => {
                        skipped += 1;
                        continue;
                    }
                    AcceptFault::Drained => RoundEnd::Drained,
                    AcceptFault::Backoff => RoundEnd::Backoff,
                    AcceptFault::Fatal => {
                        RoundEnd::Fatal(format!("control socket failed: accept: {err}"))
                    }
                };
                return AcceptRound { streams, end };
            }
        }
    }
}

impl Holder {
    /// One supervisor wake's accept round (rule 4): at most [`ACCEPT_BATCH`]
    /// connections, served serially, each under its own deadline.
    fn accept_all(&mut self, now: Instant) {
        let round = accept_round(|| self.listener.accept().map(|(s, _)| s), ACCEPT_BATCH);
        for stream in round.streams {
            self.handle(stream, now);
        }
        match round.end {
            RoundEnd::Drained | RoundEnd::Capped => {}
            RoundEnd::Backoff => self.backoff_until = Some(now + ACCEPT_BACKOFF),
            RoundEnd::Fatal(text) => self.fatal = Some(text),
        }
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.backoff_until.is_some_and(|until| now < until)
    }

    /// One connection: peer check, one frame, one reply (or a silent drop).
    fn handle(&mut self, stream: UnixStream, now: Instant) {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        self.conn_deadline = deadline;
        let _ = stream.set_nonblocking(false);
        let Ok((pid, uid)) = ctl::peer_creds(&stream) else {
            return;
        };
        if uid != unsafe { libc::geteuid() } {
            reply(
                &stream,
                &Reply::Refused("not the session owner".into()),
                &[],
                deadline,
            );
            return;
        }
        let Ok((frame, fds)) = ctl::recv_frame_until(&stream, deadline) else {
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
            reply(
                stream,
                &Reply::Refused("session is stopping".into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        if fds.len() != 1 {
            reply(
                stream,
                &Reply::Refused("attach must send exactly one descriptor".into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        if !pidfd_names_process(fds[0].as_raw_fd(), pid) {
            reply(
                stream,
                &Reply::Refused("the attach descriptor does not name the sending process".into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        if self.net_mode != "transparent" {
            reply(
                stream,
                &Reply::Refused("attach needs a transparent-mode session".into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        if !self.pin.matches(policy) {
            reply(
                stream,
                &Reply::Refused(MISMATCH.into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        let id = self.next_id;
        let Some(next) = id.checked_add(1) else {
            reply(
                stream,
                &Reply::Refused("session call ids are exhausted".into()),
                &[],
                self.conn_deadline,
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
        let (op, payload) = Reply::Accepted(id, self.landlock.clone()).encode();
        if ctl::send_frame_until(stream, op, &payload, &raw, self.conn_deadline).is_err() {
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
            reply(
                stream,
                &Reply::Refused("unknown call".into()),
                &[],
                self.conn_deadline,
            );
            return;
        };
        if self.calls[pos].pid != pid {
            reply(
                stream,
                &Reply::Refused("call belongs to another process".into()),
                &[],
                self.conn_deadline,
            );
            return;
        }
        self.calls.remove(pos);
        self.audit.append_row(&call_exit_row(
            ts(SystemTime::now()),
            &CallExit {
                call_id: end.call_id,
                code: end.rc,
                outcome: end.outcome,
                duration_ms: end.duration_ms,
                net_mode: Some(self.net_mode),
                truncated: end.truncated,
                dns_poisoned: self.map.poisoned(),
                reason: &end.reason,
            },
        ));
        self.clock.call_ended(now);
        reply(stream, &Reply::Done, &[], self.conn_deadline);
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
                &CallExit {
                    call_id: call.id,
                    code: crate::run::EXIT_FAILURE,
                    outcome: "failed",
                    duration_ms: ms,
                    net_mode: Some(self.net_mode),
                    truncated: false,
                    dns_poisoned: self.map.poisoned(),
                    reason: "the attach process exited without reporting the call end",
                },
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
            self.audit.append_row(&call_exit_row(ts(SystemTime::now()), &CallExit {
call_id: call.id,
code: 143,
outcome: "terminated",
duration_ms: ms,
net_mode: Some(self.net_mode),
truncated: false,
dns_poisoned: self.map.poisoned(),
reason: "the session stopped while the call was running; it was killed after the grace period",
}));
        }
    }

    /// Rule 8, last steps: remove `sbx.ctl` and answer every `sbx stop`.
    ///
    /// Review 6 of #57: the socket is gone before the session lock is released,
    /// so a holder that takes the lock next finds no stale `sbx.ctl` to unlink
    /// over its own. The stops are answered later, by [`StopWaiters::answer`],
    /// after the lock is released (the exit row is already written).
    pub(crate) fn close_control(mut self) -> StopWaiters {
        self.drain_backlog();
        ctl::unlink_ctl(self.dir.as_fd());
        StopWaiters(std::mem::take(&mut self.stop_waiters))
    }

    /// Answers the connections already queued at the listener (review 4): a
    /// connection that arrived after the supervisor ended but before the listener
    /// closes would otherwise be reset, and its client would see rc 125. A `Stop`
    /// joins the waiters (answered with `Done` by `finish`), and an `Attach` is
    /// refused as stopping (`end_calls` set that flag). Bounded: a flood of
    /// connections cannot hold the teardown.
    fn drain_backlog(&mut self) {
        for _ in 0..DRAIN_ROUNDS {
            let now = Instant::now();
            let round = accept_round(|| self.listener.accept().map(|(s, _)| s), ACCEPT_BATCH);
            let capped = matches!(round.end, RoundEnd::Capped);
            for stream in round.streams {
                self.handle(stream, now);
            }
            if !capped {
                break;
            }
        }
    }
}

/// The `sbx stop` connections waiting for the session to be gone.
pub(crate) struct StopWaiters(Vec<UnixStream>);

impl StopWaiters {
    /// Answers every waiting stop with `Done` (review 6: called only after the
    /// exit row is written and the session lock is released).
    pub(crate) fn answer(self) {
        for waiter in self.0 {
            reply(&waiter, &Reply::Done, &[], Instant::now() + REQUEST_TIMEOUT);
        }
    }
}

impl Extra for Holder {
    fn fds(&self) -> Vec<RawFd> {
        let backing_off = self.backing_off(Instant::now());
        let mut fds = vec![listener_poll_fd(self.listener.as_raw_fd(), backing_off)];
        fds.extend(self.calls.iter().map(|c| c.pidfd.as_raw_fd()));
        fds
    }

    fn deadline(&self) -> Option<Instant> {
        let next = self.clock.next_deadline();
        Some(match self.backoff_until {
            Some(until) => next.min(until),
            None => next,
        })
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
        if self.backoff_until.is_some_and(|until| now >= until) {
            self.backoff_until = None;
        }
        self.reap_dead(&dead, now);
        if let Some(text) = self.fatal.take() {
            return Some(Cause::Setup(RunError::new(text)));
        }
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

    #[test]
    fn accept_failures_are_classified_by_errno() {
        assert_eq!(classify_accept(Some(libc::EMFILE)), AcceptFault::Backoff);
        assert_eq!(classify_accept(Some(libc::ENFILE)), AcceptFault::Backoff);
        assert_eq!(classify_accept(Some(libc::ENOBUFS)), AcceptFault::Backoff);
        assert_eq!(classify_accept(Some(libc::ENOMEM)), AcceptFault::Backoff);
        assert_eq!(classify_accept(Some(libc::EAGAIN)), AcceptFault::Drained);
        assert_eq!(classify_accept(Some(libc::ECONNABORTED)), AcceptFault::Next);
        assert_eq!(classify_accept(Some(libc::EINVAL)), AcceptFault::Fatal);
        assert_eq!(classify_accept(None), AcceptFault::Fatal);
    }

    #[test]
    fn a_backing_off_listener_is_polled_as_a_negative_fd() {
        // poll(2) ignores negative fds, so the exhausted listener cannot spin the loop.
        assert_eq!(listener_poll_fd(7, false), 7);
        assert_eq!(listener_poll_fd(7, true), -1);
    }

    #[test]
    fn one_round_serves_at_most_the_batch_cap() {
        // The listener always has a connection waiting: the round stops at the cap,
        // so the supervisor runs between batches.
        let mut calls = 0usize;
        let round = accept_round(
            || {
                calls += 1;
                UnixStream::pair().map(|(a, _b)| a)
            },
            ACCEPT_BATCH,
        );
        assert_eq!(round.streams.len(), ACCEPT_BATCH);
        assert!(matches!(round.end, RoundEnd::Capped));
        assert_eq!(calls, ACCEPT_BATCH);
    }

    #[test]
    fn a_round_stops_when_the_backlog_is_empty() {
        let mut served = 0usize;
        let round = accept_round(
            || {
                served += 1;
                if served <= 2 {
                    UnixStream::pair().map(|(a, _b)| a)
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
                }
            },
            ACCEPT_BATCH,
        );
        assert_eq!(round.streams.len(), 2);
        assert!(matches!(round.end, RoundEnd::Drained));
    }

    #[test]
    fn a_round_reports_backoff_and_fatal_errors() {
        let round = accept_round(
            || Err(std::io::Error::from_raw_os_error(libc::EMFILE)),
            ACCEPT_BATCH,
        );
        assert!(matches!(round.end, RoundEnd::Backoff));
        let round = accept_round(
            || Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            ACCEPT_BATCH,
        );
        assert!(matches!(round.end, RoundEnd::Fatal(_)));
    }

    #[test]
    fn endless_skips_do_not_hold_the_round() {
        // A client that always gives up before accept is counted as a skip, so the
        // round still ends at the cap.
        let round = accept_round(
            || Err(std::io::Error::from_raw_os_error(libc::ECONNABORTED)),
            ACCEPT_BATCH,
        );
        assert!(round.streams.is_empty());
        assert!(matches!(round.end, RoundEnd::Capped));
    }

    #[test]
    fn a_pidfd_names_only_its_own_process() {
        let own = sys::pidfd_open(std::process::id() as libc::pid_t).expect("pidfd");
        assert!(pidfd_names_process(
            own.as_raw_fd(),
            std::process::id() as libc::pid_t
        ));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn");
        let theirs = sys::pidfd_open(child.id() as libc::pid_t).expect("pidfd of child");
        // The descriptor names the child, so it does not name this process.
        assert!(pidfd_names_process(
            theirs.as_raw_fd(),
            child.id() as libc::pid_t
        ));
        assert!(!pidfd_names_process(
            theirs.as_raw_fd(),
            std::process::id() as libc::pid_t
        ));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A holder over a real listener, with dummy descriptors and an audit log
    /// that writes nothing: enough to exercise the control handlers in-process.
    fn test_holder(listener: UnixListener, dir: OwnedFd) -> Holder {
        let dev_null = || OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null"));
        listener.set_nonblocking(true).expect("nonblocking");
        Holder {
            listener,
            dir,
            pin: PolicyPin::new(b"policy".to_vec()),
            clock: Clock::new(Instant::now(), DEFAULT_IDLE, DEFAULT_MAX_LIFETIME),
            self_pidfd: dev_null(),
            user_ns: dev_null(),
            net_ns: dev_null(),
            net_mode: "transparent",
            audit: AuditLog::new(None, crate::run::serve::FaultLatch::new().expect("latch")),
            map: Arc::new(FakeIpMap::new(&crate::dns::DnsLimits::default())),
            landlock: SessionLandlock::off(),
            calls: Vec::new(),
            next_id: 1,
            stopping: true,
            stop_waiters: Vec::new(),
            stop_requested: false,
            backoff_until: None,
            fatal: None,
            conn_deadline: Instant::now(),
        }
    }

    #[test]
    fn teardown_answers_queued_stops_done_and_attaches_stopping() {
        // Review 4: two clients connected while the holder was tearing down, with
        // no supervisor left to serve them. Both get an answer, not a reset.
        use crate::run::keepalive::ctl::{recv_frame, send_frame};
        let dir = std::env::temp_dir().join(format!("sbx-holder-drain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("dir");
        }
        let dirfd = ctl::open_session_dir(&dir).expect("open dir");
        let listener = ctl::bind_ctl(dirfd.as_fd()).expect("bind");
        let holder = test_holder(listener, dirfd);

        let stop_client = ctl::connect_ctl(holder.dir.as_fd()).expect("connect");
        let (op, payload) = Request::Stop.encode();
        send_frame(&stop_client, op, &payload, &[]).expect("send stop");
        let attach_client = ctl::connect_ctl(holder.dir.as_fd()).expect("connect");
        let (op, payload) = Request::Attach(b"policy".to_vec()).encode();
        send_frame(&attach_client, op, &payload, &[]).expect("send attach");

        holder.close_control().answer();

        let (frame, _) = recv_frame(&attach_client).expect("the attach gets an answer");
        assert_eq!(
            Reply::decode(frame).expect("reply"),
            Reply::Refused("session is stopping".into())
        );
        let (frame, _) = recv_frame(&stop_client).expect("the stop gets Done");
        assert_eq!(Reply::decode(frame).expect("reply"), Reply::Done);
        assert!(
            !dir.join(ctl::CTL_NAME).exists(),
            "the control socket is removed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_holder_closes_everything_above_stdio_but_the_readiness_pipe() {
        assert_eq!(
            fds_to_close(vec![0, 1, 2, 3, 5, 9, 900], 5),
            vec![3, 9, 900]
        );
        assert!(fds_to_close(vec![0, 1, 2], 1).is_empty());
    }
}
