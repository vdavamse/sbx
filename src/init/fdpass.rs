//! The control-socket protocol: socketpair factory, SCM_RIGHTS listener-fd
//! hand-off, and the go byte — both directions (issue #5).
//!
//! Wire protocol (pinned; parent and child are always the *same binary* —
//! `run` re-execs `current_exe` — so strict byte validation needs no version
//! negotiation):
//!
//! * **Transport**: `AF_UNIX` + `SOCK_SEQPACKET` socketpair, both ends
//!   created `SOCK_CLOEXEC`; the child end is CLOEXEC-cleared only in the
//!   spawn window ([`prepare_child_end`] carries the full discipline and its
//!   bug-class history). SEQPACKET gives message boundaries (the 1-byte /
//!   fd-batch messages are unambiguous), clean bidirectional EOF (`recv == 0`
//!   is peer close), and `MSG_CTRUNC` detection. The child's `control` stage
//!   enforces `SO_TYPE == SOCK_SEQPACKET`, so a mistaken `UnixStream::pair()`
//!   in future code fails fast instead of misbehaving.
//! * **Message 1, child → parent (setup)** (issue #11): either a *ready*
//!   message — `'F'` plus the achieved mode (`'t'` transparent, or `'e'` +
//!   the nft errno + reason) — or a *failure* message `'E'` + stage code +
//!   errno + reason with no fds (`recv_setup` returns it as
//!   [`SetupMsg::Failed`]). A ready message carries one `SCM_RIGHTS` cmsg:
//!   exactly [`LISTENER_FD_COUNT`] fds in the fixed wire order
//!   **transparent :15001/tcp, explicit :3128/tcp, dns :53/udp** (pinned by
//!   [`ListenerFds`]). The parent receives with `MSG_CMSG_CLOEXEC` so the
//!   dup'd fds cannot leak into #10's later bwrap spawn.
//! * **Message 2, parent → child (go)**: data exactly `[`[`GO_BYTE`]`]`
//!   ('G'). The child blocks with `SO_RCVTIMEO` = [`GO_TIMEOUT`] and
//!   enforces the EXACT length (recv into a 16-byte buffer, require
//!   `n == 1`): any other byte, a longer message merely starting with 'G'
//!   (SEQPACKET boundaries make the length visible — M1), EOF, or timeout
//!   aborts staged rc-1 and the payload is never exec'd.
//! * **Lifetime**: the child closes the control fd *before* exec, so
//!   control-socket EOF means **exec time**, NOT sandbox death — #10's
//!   liveness check is `Child::wait`. The parent drops its copy of the child
//!   end immediately after spawn.
//!
//! #10's usage pattern (parent side):
//!
//! ```ignore
//! let (parent_end, child_end) = fdpass::control_socketpair()?;
//! let child_fd = fdpass::prepare_child_end(child_end.as_fd())?;   // window opens
//! let child = Command::new(current_exe).arg("__init").arg("--fd").arg(child_fd.to_string())
//!     .arg("--").args(bwrap_argv)                                  // #6's argv
//!     .spawn()?;
//! drop(child_end);                                                 // window closed; parent keeps ONLY parent_end
//! let fds = fdpass::recv_listener_fds(parent_end.as_raw_fd())?;    // CLOEXEC-clean
//! start_serving(fds);                                              // #7/#8/#9 — BEFORE go (the go guarantee)
//! fdpass::send_go(parent_end.as_raw_fd())?;
//! let status = child.wait()?;   // NOTE: control-socket EOF happens at EXEC time (the child
//!                               // closes its end before exec) — sandbox liveness is Child::wait, NOT the socket.
//! ```

use std::io;
use std::mem::{size_of, size_of_val};
use std::net::{TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use std::fmt;

use super::consts::{
    FAIL_PAYLOAD_BYTE, FDS_PAYLOAD_BYTE, GO_BYTE, GO_TIMEOUT, LISTENER_FD_COUNT, MAX_REASON_BYTES,
    MODE_EXPLICIT, MODE_TRANSPARENT, SETUP_MSG_MAX,
};
use super::{InitError, Stage};

/// The three listener sockets in wire order — one type pins the fd order for
/// BOTH directions: the child's `listeners::bind_all` builds it, the
/// parent's [`recv_listener_fds`] rebuilds it (design D11).
///
/// The fields are public by design: #7 takes `transparent` (blocking +
/// CLOEXEC — flip `set_nonblocking(true)` before
/// `tokio::net::TcpListener::from_std`), #8 takes `explicit`, #9 takes
/// `dns`. Dropping the struct closes the sockets — on the parent side the
/// sandbox's proxy is gone the moment it drops (issue #5's acceptance
/// criterion, proven by the integration suite's `proxy-gone` scenario).
#[derive(Debug)]
pub struct ListenerFds {
    /// Transparent-proxy listener (127.0.0.1:15001/tcp) — wire index 0.
    pub transparent: TcpListener,
    /// Explicit-proxy listener (127.0.0.1:3128/tcp) — wire index 1.
    pub explicit: TcpListener,
    /// DNS listener (127.0.0.1:53/udp) — wire index 2.
    pub dns: UdpSocket,
}

impl ListenerFds {
    /// Wrap three bound sockets in wire order.
    pub fn new(transparent: TcpListener, explicit: TcpListener, dns: UdpSocket) -> Self {
        Self {
            transparent,
            explicit,
            dns,
        }
    }

    /// The fds to hand over SCM_RIGHTS, in protocol order.
    pub fn as_raw_fds(&self) -> [RawFd; LISTENER_FD_COUNT] {
        [
            self.transparent.as_raw_fd(),
            self.explicit.as_raw_fd(),
            self.dns.as_raw_fd(),
        ]
    }

    /// Take ownership of three fds just received over SCM_RIGHTS, in wire
    /// order.
    ///
    /// SAFETY contract (upheld by the single caller,
    /// [`recv_listener_fds`]): the fds must have just been installed into
    /// this process's fd table by the kernel's SCM_RIGHTS receive — they
    /// alias nothing pre-existing — and ownership passes to the returned
    /// std socket types, which close them exactly once on drop.
    fn from_raw_fds(fds: [RawFd; LISTENER_FD_COUNT]) -> Self {
        // SAFETY: recv_listener_fds only ever passes fds that recvmsg just
        // installed via SCM_RIGHTS (fresh table entries, no aliasing);
        // ownership moves into the std types.
        unsafe {
            Self {
                transparent: TcpListener::from_raw_fd(fds[0]),
                explicit: TcpListener::from_raw_fd(fds[1]),
                dns: UdpSocket::from_raw_fd(fds[2]),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parent side (used by #10 and by tests/sandbox_init.rs)
// ---------------------------------------------------------------------------

/// Create the control socketpair: `AF_UNIX` + `SOCK_SEQPACKET`, BOTH ends
/// `SOCK_CLOEXEC`. Returns `(parent_end, child_end)`.
///
/// Both-ends-CLOEXEC at creation is half of the R6 discipline — see
/// [`prepare_child_end`] for the bug class it prevents. SEQPACKET (not
/// STREAM) is required: message boundaries + clean EOF both ways +
/// `MSG_CTRUNC` detection; the child's `control` stage rejects anything
/// else.
pub fn control_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut sv = [0 as libc::c_int; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair(2) just returned two fresh, valid, owned fds.
    Ok(unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) })
}

/// Clear `CLOEXEC` on the child end and return its fd number for
/// `sbx __init --fd N`. Call IMMEDIATELY before spawning `__init`, and drop
/// the parent's copy of the child end IMMEDIATELY after the spawn returns.
///
/// # Why this discipline (risk R6 — a bug class the probe hit)
///
/// A socketpair created WITHOUT `SOCK_CLOEXEC` leaks BOTH ends into every
/// spawned child: the parent's close then never produces EOF on the child's
/// end (the child's inherited copy of the *parent's* end keeps the socket
/// alive — a 300 s hang was observed in the probe), and the child could send
/// itself the go byte. Hence:
///
/// * both ends are created `SOCK_CLOEXEC` ([`control_socketpair`]);
/// * ONLY the child end is cleared, ONLY in the spawn window;
/// * the parent drops its copy of the child end immediately after spawn.
///
/// Residual race: between the clear and the spawn, a CONCURRENT spawn from
/// another thread would inherit the child end too. #10 must therefore spawn
/// `__init` before any other process spawn and join/suspend other spawning
/// tasks across this window (documented handoff; the issue #5 integration
/// harness follows the same rule).
///
/// No `pre_exec` is needed: `std::process::Command` never closes or
/// renumbers fds it does not know about, so the CLOEXEC-cleared child end
/// survives fork+exec at the SAME number (probe-proven; honors issue #5's
/// "no pre_exec" design statement).
pub fn prepare_child_end(child_end: BorrowedFd<'_>) -> io::Result<RawFd> {
    let rc = unsafe { libc::fcntl(child_end.as_raw_fd(), libc::F_SETFD, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(child_end.as_raw_fd())
}

/// RAII guard over fds the kernel installed via SCM_RIGHTS (m1):
/// [`recv_listener_fds`] must not leak them on any rejection path — an open
/// listener socket would pin the dead sandbox's netns (and hold the fds
/// until the parent exits). Anything still owned at drop is closed;
/// [`ReceivedFdGuard::release`] transfers ownership to [`ListenerFds`] on
/// the success path only.
///
/// The guard's close-on-drop is deliberately NOT unit-tested in-process:
/// asserting fd closure under parallel cargo test is thread-hostile (fd
/// numbers race with every other fd-opening test — the design-D13
/// rationale); its input contract (every installed fd reaches the sink on
/// EVERY rejection path) is pinned purely by
/// `rejected_messages_never_strand_collected_fds`.
#[derive(Default)]
struct ReceivedFdGuard(Vec<RawFd>);

impl ReceivedFdGuard {
    /// Transfer ownership out, disarming the guard.
    fn release(mut self) -> Vec<RawFd> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for ReceivedFdGuard {
    fn drop(&mut self) {
        for fd in self.0.drain(..) {
            // SAFETY: an fd the kernel installed into THIS process's table
            // via SCM_RIGHTS and that no std object took ownership of;
            // each number is closed exactly once (release() disarms).
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// The parent's view of the child's setup message (issue #11): the three
/// listener fds with the achieved network mode, or the staged failure the
/// child reports instead of exiting silently.
#[derive(Debug)]
pub enum SetupMsg {
    /// `'F'` + mode + three fds: the pipeline reached `send-fds`.
    Ready {
        fds: ListenerFds,
        mode: AchievedMode,
    },
    /// `'E'`: a staged failure in `__init` (no fds).
    Failed(StagedFailure),
}

/// The network mode `__init` achieved (issue #11, Q1/Q5). `Explicit` carries
/// the nft-load failure that forced the fallback — the evidence run quotes
/// in its notice and records in the audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AchievedMode {
    /// The full firewall loaded and verified.
    Transparent,
    /// nft-load was refused; the default route is gone, direct connects fail
    /// with ENETUNREACH, only the explicit listener is reachable.
    Explicit {
        /// The errno of the refused batch (0 on the wire = unknown = None).
        errno: Option<i32>,
        /// `nft-load: <reason>`.
        reason: String,
    },
}

impl AchievedMode {
    /// The pinned audit/notice label: `"transparent"` or `"explicit"`.
    pub fn label(&self) -> &'static str {
        match self {
            AchievedMode::Transparent => "transparent",
            AchievedMode::Explicit { .. } => "explicit",
        }
    }
}

/// A staged `__init` failure as received over the `'E'` message: the stage,
/// its errno (when the failing call had one) and the reason text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFailure {
    pub stage: Stage,
    pub errno: Option<i32>,
    pub reason: String,
}

impl fmt::Display for StagedFailure {
    /// `<stage>: <reason>` — the evidence string (the `sbx __init:` prefix is
    /// not part of it).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage.as_str(), self.reason)
    }
}

/// Parent side: receive the child's setup message (`'F'` or `'E'`).
///
/// Strict (same-binary invariant, module docs): see [`decode_setup_message`]
/// for every accepted and rejected shape. A `'F'` message delivers the
/// listener fds and the achieved mode; an `'E'` message is a successful
/// receive of a staged failure. EOF (peer closed) is
/// [`io::ErrorKind::UnexpectedEof`]. Every rejection path closes the fds the
/// kernel already installed (`ReceivedFdGuard`, m1).
pub fn recv_setup(ctrl: RawFd) -> io::Result<SetupMsg> {
    let mut data = vec![0u8; SETUP_MSG_MAX];
    let mut ctrlbuf = CtrlBuf([0; CTRL_BUF_LEN]);
    let (n, msg_flags, controllen) =
        recvmsg_raw(ctrl, &mut data, &mut ctrlbuf.0, libc::MSG_CMSG_CLOEXEC)?;
    // From recvmsg's return the kernel may have installed fds into our
    // table — including on messages the strict decode is about to REJECT.
    let mut guard = ReceivedFdGuard::default();
    if n == 0 {
        // A zero-length SEQPACKET message can legally carry SCM_RIGHTS fds
        // (m1): collect them so they are closed on this path too.
        let _ = decode_setup_message(&[], &ctrlbuf.0[..controllen], msg_flags, &mut guard.0);
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed before sending the setup message",
        ));
    }
    let head = decode_setup_message(
        &data[..n],
        &ctrlbuf.0[..controllen],
        msg_flags,
        &mut guard.0,
    )?;
    match head {
        Head::Failed(failure) => Ok(SetupMsg::Failed(failure)),
        Head::Ready(mode) => {
            // decode enforces the exact count; the defensive reshape keeps
            // from_raw_fds' SAFETY contract local.
            match guard.release().try_into() {
                Ok(raw) => Ok(SetupMsg::Ready {
                    fds: ListenerFds::from_raw_fds(raw),
                    mode,
                }),
                Err(unexpected) => {
                    for fd in &unexpected {
                        // SAFETY: kernel-installed fds never transferred to a
                        // std object; each number is closed exactly once here.
                        unsafe {
                            libc::close(*fd);
                        }
                    }
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("expected {LISTENER_FD_COUNT} fds, got {}", unexpected.len()),
                    ))
                }
            }
        }
    }
}

/// Kept for the integration suites and the pre-#11 call sites: `Ready` →
/// the fds (the mode is discarded); `Failed(f)` → an [`io::Error`] whose text
/// is `sbx __init: <stage>: <reason>`, the same line `__init` printed.
pub fn recv_listener_fds(ctrl: RawFd) -> io::Result<ListenerFds> {
    match recv_setup(ctrl)? {
        SetupMsg::Ready { fds, .. } => Ok(fds),
        SetupMsg::Failed(f) => Err(io::Error::other(format!("sbx __init: {f}"))),
    }
}

/// Parent side: send the go byte — exactly `[`[`GO_BYTE`]`]`, one message.
///
/// Retries on EINTR (m2) — and this is the side that NEEDS it: the parent
/// is the process with signal handlers installed (#10: tokio
/// ctrl-c/SIGTERM/SIGCHLD, typically registered without `SA_RESTART`), so
/// an interrupted `send` here would otherwise surface as a spurious
/// `Interrupted system call` on a healthy startup. The retry is safe: for
/// `AF_UNIX` + `SOCK_SEQPACKET` a queued message is atomic and EINTR is
/// only returned when the interrupt hit BEFORE anything was queued, so the
/// go byte cannot duplicate. `MSG_NOSIGNAL` makes the call
/// disposition-independent (no SIGPIPE kill even if a future caller
/// restores the default disposition).
pub fn send_go(ctrl: RawFd) -> io::Result<()> {
    loop {
        let n = unsafe {
            libc::send(
                ctrl,
                [GO_BYTE].as_ptr().cast::<libc::c_void>(),
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            // Signal delivery is not a protocol event (m2): retry.
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n != 1 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// child side (used by the __init pipeline)
// ---------------------------------------------------------------------------

/// Child side: send the setup message `'F'` + mode bytes with the three
/// listener fds in ONE SCM_RIGHTS message, wire order per [`ListenerFds`].
///
/// EPIPE means the parent died before receiving the fds — probe-verified;
/// `MSG_NOSIGNAL` makes the detection independent of the SIGPIPE
/// disposition: staged [`Stage::SendFds`] failure, the payload is never
/// exec'd.
pub fn send_listener_fds(
    ctrl: RawFd,
    fds: &[RawFd; LISTENER_FD_COUNT],
    mode: &AchievedMode,
) -> Result<(), InitError> {
    let mut data = Vec::with_capacity(SETUP_MSG_MAX);
    encode_ready(mode, &mut data);
    let mut ctrlbuf = Vec::new();
    encode_fds_cmsg(fds, &mut ctrlbuf);
    sendmsg_raw(ctrl, &data, &ctrlbuf).map_err(|err| {
        InitError::new(
            Stage::SendFds,
            if err.raw_os_error() == Some(libc::EPIPE) {
                format!("parent died before receiving the listener fds ({err})")
            } else {
                format!("sendmsg listener fds: {err}")
            },
        )
        .with_errno(err.raw_os_error())
    })
}

/// Child side: report a staged failure to the parent (`'E'` message, no
/// fds). Best effort — every error is ignored: the staged stderr line is
/// printed regardless, and a parent that is already gone has nothing to
/// classify.
pub fn send_failure(ctrl: RawFd, err: &InitError) {
    let mut data = Vec::with_capacity(SETUP_MSG_MAX);
    encode_failure(err.stage(), err.errno(), err.reason(), &mut data);
    let _ = sendmsg_raw(ctrl, &data, &[]);
}

/// Child side: block until the parent's go byte arrives. Staged
/// [`Stage::WaitGo`] errors; anything but the exact go-byte message — EOF,
/// timeout, a wrong byte, or a LONGER message merely starting with 'G'
/// (SEQPACKET boundaries make the length visible; M1) — aborts and the
/// payload is never exec'd (D4 strictness).
pub fn wait_go(ctrl: RawFd) -> Result<(), InitError> {
    wait_go_timeout(ctrl, GO_TIMEOUT)
}

/// [`wait_go`] with an injectable timeout (design D17): unit tests use
/// 100 ms so the suite never sleeps 30 s; production passes [`GO_TIMEOUT`].
fn wait_go_timeout(ctrl: RawFd, timeout: Duration) -> Result<(), InitError> {
    // `as _` infers the field types: libc deprecates the `time_t` /
    // `suseconds_t` ALIASES on musl targets (they go 64-bit in musl 1.2,
    // libc #1848), and naming them would warn on the release musl build —
    // inference names nothing and is correct on every target.
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    let rc = unsafe {
        libc::setsockopt(
            ctrl,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast::<libc::c_void>(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(InitError::new(
            Stage::WaitGo,
            format!("setsockopt SO_RCVTIMEO: {}", io::Error::last_os_error()),
        ));
    }
    // SEQPACKET preserves message boundaries: receive into a buffer LARGER
    // than the protocol message so a longer 'G'-prefixed message is caught
    // by its length instead of being silently truncated into an acceptable
    // 1-byte recv (M1 — the frozen contract is data exactly [GO_BYTE]).
    let mut buf = [0u8; 16];
    let n = loop {
        let n = unsafe { libc::recv(ctrl, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // Signal delivery is not a protocol event (m2): retry.
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // SO_RCVTIMEO expiry surfaces as EAGAIN/EWOULDBLOCK on the
            // blocking recv.
            return Err(InitError::new(
                Stage::WaitGo,
                if err.kind() == io::ErrorKind::WouldBlock {
                    format!(
                        "timed out after {}s waiting for the go byte (parent stuck?)",
                        timeout.as_secs()
                    )
                } else {
                    format!("recv go byte: {err}")
                },
            ));
        }
        break n as usize;
    };
    if n == 0 {
        return Err(InitError::new(
            Stage::WaitGo,
            "control socket closed before the go byte (parent died?)",
        ));
    }
    if n != 1 || buf[0] != GO_BYTE {
        return Err(InitError::new(
            Stage::WaitGo,
            format!(
                "expected exactly the go byte {GO_BYTE:#04x} ('G'), got {n} byte(s): {:#04x?}",
                &buf[..n]
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pure codec (unit-tested in memory, no sockets)
// ---------------------------------------------------------------------------

/// The kernel/libc `CMSG_ALIGN` (alignment to `size_t`) as a const fn. The
/// libc crate exports the `CMSG_*` helpers as `unsafe fn`; the pure codec
/// computes identical values without touching a pointer
/// (`cmsg_math_matches_libc` pins the equality).
const fn cmsg_align(len: usize) -> usize {
    (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// `CMSG_LEN`: aligned header size + data length (the `cmsg_len` value).
const fn cmsg_hdr_len(data_len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + data_len
}

/// `CMSG_SPACE`: aligned header + aligned data — the slot a cmsg occupies
/// in the control buffer (and where the next one would start).
const fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(data_len) + cmsg_align(size_of::<libc::cmsghdr>())
}

/// Pure encoder of the fds ancillary data: one well-formed `SOL_SOCKET`/
/// `SCM_RIGHTS` cmsg (header + fd array + alignment padding, `CMSG_SPACE`
/// total) appended to `ctrl`. The data payload is the caller's (see
/// [`encode_ready`]). In-memory only — [`sendmsg_raw`] copies `ctrl` into an
/// aligned buffer.
pub(crate) fn encode_fds_cmsg(fds: &[RawFd], ctrl: &mut Vec<u8>) {
    let fds_len = size_of_val(fds);
    let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
    hdr.cmsg_len = cmsg_hdr_len(fds_len) as _;
    hdr.cmsg_level = libc::SOL_SOCKET;
    hdr.cmsg_type = libc::SCM_RIGHTS;
    // SAFETY: byte image of an owned, properly aligned, fully initialized
    // cmsghdr (zeroed, then three fields set).
    ctrl.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const libc::cmsghdr).cast::<u8>(),
            size_of::<libc::cmsghdr>(),
        )
    });
    for fd in fds {
        ctrl.extend_from_slice(&fd.to_ne_bytes());
    }
    // Pad to CMSG_SPACE so msg_controllen matches the kernel's convention
    // for the buffer a cmsg chain lives in.
    let total = cmsg_space(fds_len);
    while ctrl.len() < total {
        ctrl.push(0);
    }
}

/// Pure encoder of a `'F'` ready message's data: `'F'`, then the mode byte
/// (`'t'` transparent, or `'e'` + errno i32 LE (0 = unknown) + the reason).
pub(crate) fn encode_ready(mode: &AchievedMode, data: &mut Vec<u8>) {
    data.push(FDS_PAYLOAD_BYTE);
    match mode {
        AchievedMode::Transparent => data.push(MODE_TRANSPARENT),
        AchievedMode::Explicit { errno, reason } => {
            data.push(MODE_EXPLICIT);
            data.extend_from_slice(&errno.unwrap_or(0).to_le_bytes());
            data.extend_from_slice(truncate_reason(reason).as_bytes());
        }
    }
}

/// Pure encoder of an `'E'` failure message's data: `'E'`, the stage code,
/// errno i32 LE (0 = none), the reason (≤ [`MAX_REASON_BYTES`]).
pub(crate) fn encode_failure(stage: Stage, errno: Option<i32>, reason: &str, data: &mut Vec<u8>) {
    data.push(FAIL_PAYLOAD_BYTE);
    data.push(stage.code());
    data.extend_from_slice(&errno.unwrap_or(0).to_le_bytes());
    data.extend_from_slice(truncate_reason(reason).as_bytes());
}

/// The longest prefix of `reason` that is at most [`MAX_REASON_BYTES`] bytes
/// and ends on a char boundary.
pub(crate) fn truncate_reason(reason: &str) -> &str {
    if reason.len() <= MAX_REASON_BYTES {
        return reason;
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// What the strict decode accepted, before the caller assembles fds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Head {
    Ready(AchievedMode),
    Failed(StagedFailure),
}

/// Pure decoder of the setup message — strict, fail-closed, overflow-free.
///
/// `data` is the received payload verbatim, `ctrl` the ancillary bytes
/// verbatim (recvmsg's `msg_controllen`), `msg_flags` recvmsg's flags. Every
/// SCM_RIGHTS fd found is appended to `fds_out` — the CALLER's sink, so fds
/// the kernel already installed are visible to the caller's guard on EVERY
/// rejection path (m1). The cmsg walk therefore runs FIRST. Every rejection
/// is an [`io::Error`] (`InvalidData` unless noted), never a panic:
///
/// * `cmsg_len` out of bounds, a foreign cmsg, or a fd chunk that is not a
///   whole `RawFd` ⇒ `InvalidData` (the walk stops at the first violation);
/// * `MSG_CTRUNC` or `MSG_TRUNC` ⇒ `EMSGSIZE`;
/// * empty data ⇒ `InvalidData`;
/// * first byte ∉ {`F`, `E`} ⇒ `InvalidData`;
/// * `F` + mode ∉ {`t`, `e`} ⇒ `InvalidData`; `F t` with length ≠ 2 ⇒
///   `InvalidData`; `F e` with length < 6 or a reason over
///   [`MAX_REASON_BYTES`] ⇒ `InvalidData`; a `F` message with fd count ≠
///   [`LISTENER_FD_COUNT`] ⇒ `InvalidData`;
/// * `E` with length < 6, a reason over the limit, an unknown stage code, a
///   negative errno, any fd, or a non-UTF-8 reason ⇒ `InvalidData`;
/// * errno 0 on the wire maps to `None`; a negative errno is rejected.
pub(crate) fn decode_setup_message(
    data: &[u8],
    ctrl: &[u8],
    msg_flags: i32,
    fds_out: &mut Vec<RawFd>,
) -> io::Result<Head> {
    let mut off = 0usize;
    while off < ctrl.len() {
        // Overflow-free: `off < ctrl.len()` makes the subtraction below
        // safe, and `cmsg_len` (arbitrary usize) is only COMPARED before
        // anything adds to it — a value near usize::MAX is rejected here,
        // never wrapped.
        let remaining = ctrl.len() - off;
        if remaining < size_of::<libc::cmsghdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("truncated cmsg header ({remaining} bytes remain)"),
            ));
        }
        let hdr = cmsghdr_at(&ctrl[off..]);
        // Compared in u64 space: a garbage length near the type's MAX is
        // rejected by `cmsg_len > remaining` without any wrapping addition.
        let cmsg_len = hdr.cmsg_len as u64;
        let remaining = remaining as u64;
        let data_off = cmsg_hdr_len(0) as u64;
        if cmsg_len < data_off || cmsg_len > remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cmsg_len {cmsg_len} out of bounds ({remaining} bytes remain)"),
            ));
        }
        // Safe narrowing: cmsg_len ≤ remaining ≤ ctrl.len() ≤ isize::MAX.
        let cmsg_len = cmsg_len as usize;
        let data_off = data_off as usize;
        if hdr.cmsg_level != libc::SOL_SOCKET || hdr.cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "foreign cmsg (level {} type {}): only SOL_SOCKET/SCM_RIGHTS is accepted",
                    hdr.cmsg_level, hdr.cmsg_type
                ),
            ));
        }
        let body = &ctrl[off + data_off..off + cmsg_len];
        if body.len() % size_of::<RawFd>() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SCM_RIGHTS payload of {} bytes is not a multiple of the {}-byte fd width",
                    body.len(),
                    size_of::<RawFd>()
                ),
            ));
        }
        for chunk in body.chunks_exact(size_of::<RawFd>()) {
            let bytes: [u8; size_of::<RawFd>()] = chunk
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed fd chunk"))?;
            fds_out.push(RawFd::from_ne_bytes(bytes));
        }
        // Advance to the next cmsg slot (cannot overflow: see above).
        off += cmsg_align(cmsg_len);
    }
    if msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    let invalid = |reason: String| io::Error::new(io::ErrorKind::InvalidData, reason);
    match data.first() {
        None => Err(invalid("empty setup message".to_owned())),
        Some(&FDS_PAYLOAD_BYTE) => {
            let mode = match data.get(1) {
                Some(&MODE_TRANSPARENT) => {
                    if data.len() != 2 {
                        return Err(invalid(format!(
                            "transparent ready message must be 2 bytes, got {}",
                            data.len()
                        )));
                    }
                    AchievedMode::Transparent
                }
                Some(&MODE_EXPLICIT) => {
                    if data.len() < 6 {
                        return Err(invalid(format!(
                            "explicit ready message must carry an errno, got {} bytes",
                            data.len()
                        )));
                    }
                    if data.len() - 6 > MAX_REASON_BYTES {
                        return Err(invalid("ready reason exceeds the limit".to_owned()));
                    }
                    let (errno, reason) = decode_errno_reason(&data[2..])?;
                    AchievedMode::Explicit { errno, reason }
                }
                other => {
                    return Err(invalid(format!("unknown mode byte {other:02x?}")));
                }
            };
            if fds_out.len() != LISTENER_FD_COUNT {
                return Err(invalid(format!(
                    "expected {LISTENER_FD_COUNT} fds, got {}",
                    fds_out.len()
                )));
            }
            Ok(Head::Ready(mode))
        }
        Some(&FAIL_PAYLOAD_BYTE) => {
            if !fds_out.is_empty() {
                return Err(invalid(format!(
                    "a failure message must carry no fds, got {}",
                    fds_out.len()
                )));
            }
            if data.len() < 6 {
                return Err(invalid(format!(
                    "failure message too short ({} bytes)",
                    data.len()
                )));
            }
            if data.len() - 6 > MAX_REASON_BYTES {
                return Err(invalid("failure reason exceeds the limit".to_owned()));
            }
            let stage = Stage::from_code(data[1])
                .ok_or_else(|| invalid(format!("unknown stage code {}", data[1])))?;
            let (errno, reason) = decode_errno_reason(&data[2..])?;
            Ok(Head::Failed(StagedFailure {
                stage,
                errno,
                reason,
            }))
        }
        Some(other) => Err(invalid(format!(
            "expected the first byte {FDS_PAYLOAD_BYTE:#04x} ('F') or {FAIL_PAYLOAD_BYTE:#04x} ('E'), got {other:#04x}"
        ))),
    }
}

/// `errno i32 LE` + UTF-8 reason: `0` ⇒ `None`, negative ⇒ rejected.
fn decode_errno_reason(bytes: &[u8]) -> io::Result<(Option<i32>, String)> {
    let invalid = |reason: String| io::Error::new(io::ErrorKind::InvalidData, reason);
    let raw: [u8; 4] = bytes[..4]
        .try_into()
        .map_err(|_| invalid("truncated errno".to_owned()))?;
    let errno = i32::from_le_bytes(raw);
    if errno < 0 {
        return Err(invalid(format!("negative errno {errno}")));
    }
    let reason = std::str::from_utf8(&bytes[4..])
        .map_err(|_| invalid("reason is not UTF-8".to_owned()))?
        .to_owned();
    Ok((if errno == 0 { None } else { Some(errno) }, reason))
}

/// Read the `cmsghdr` at the start of `buf` (which must be at least
/// `size_of::<cmsghdr>()` bytes long) by COPYING into an aligned local —
/// never by creating a reference into the possibly under-aligned byte
/// slice (which would be UB by Rust's aliasing rules).
fn cmsghdr_at(buf: &[u8]) -> libc::cmsghdr {
    debug_assert!(buf.len() >= size_of::<libc::cmsghdr>());
    let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
    // SAFETY: copies exactly size_of::<cmsghdr>() bytes from a caller-
    // length-checked slice into an owned, properly aligned local; the
    // source and destination cannot overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            (&mut hdr as *mut libc::cmsghdr).cast::<u8>(),
            size_of::<libc::cmsghdr>(),
        );
    }
    hdr
}

// ---------------------------------------------------------------------------
// sendmsg/recvmsg wrappers
// ---------------------------------------------------------------------------

/// Control-buffer size for sendmsg/recvmsg: one `CMSG_SPACE(3 fds)` cmsg is
/// 32 bytes on Linux/x86_64; 128 keeps headroom on any platform.
const CTRL_BUF_LEN: usize = 128;

/// Align-8 control buffer: the cmsg walk casts this memory to `*cmsghdr`
/// (alignment 8 on 64-bit Linux); a plain `[u8; N]` is only align-1, and
/// creating references to under-aligned structs is UB (the spike's
/// `listeners.rs` CtrlBuf precedent).
#[repr(align(8))]
struct CtrlBuf([u8; CTRL_BUF_LEN]);

/// `sendmsg` of one data payload + encoded cmsg bytes. `ctrl` must fit the
/// aligned buffer (only [`encode_fds_message`]'s output — 32 B for three
/// fds — ever reaches here).
///
/// Retries on EINTR (m2 — same contract as [`recvmsg_raw`]): the interrupt
/// hit before anything was queued (SEQPACKET messages are atomic), so the
/// fds message cannot duplicate on retry. `MSG_NOSIGNAL` keeps the
/// caller's EPIPE detection independent of the SIGPIPE disposition.
fn sendmsg_raw(sock: RawFd, data: &[u8], ctrl: &[u8]) -> io::Result<()> {
    let mut buf = CtrlBuf([0; CTRL_BUF_LEN]);
    if ctrl.len() > buf.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "control data of {} bytes exceeds the {}-byte buffer",
                ctrl.len(),
                CTRL_BUF_LEN
            ),
        ));
    }
    buf.0[..ctrl.len()].copy_from_slice(ctrl);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf.0.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = ctrl.len() as _;
    let n = loop {
        let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // Signal delivery is not a protocol event (m2): retry.
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        break n;
    };
    if n as usize != data.len() {
        return Err(io::Error::from(io::ErrorKind::WriteZero));
    }
    Ok(())
}

/// `recvmsg` into caller buffers; returns `(bytes_read, msg_flags,
/// msg_controllen)`. `ctrl` must be the aligned [`CtrlBuf`] memory.
/// Retries on EINTR (m2): signal delivery is not a protocol event, and an
/// interrupted recvmsg consumed nothing — safe to repeat even with
/// `MSG_CMSG_CLOEXEC`.
fn recvmsg_raw(
    sock: RawFd,
    data: &mut [u8],
    ctrl: &mut [u8],
    flags: libc::c_int,
) -> io::Result<(usize, libc::c_int, usize)> {
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = ctrl.len() as _;
    let n = loop {
        let n = unsafe { libc::recvmsg(sock, &mut msg, flags) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        break n;
    };
    Ok((n as usize, msg.msg_flags, msg.msg_controllen as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
    use std::os::fd::AsFd;
    use std::time::Instant;

    use crate::init::consts::MAX_REASON_BYTES;

    /// A real control socketpair (thread-safe: only `unshare` is
    /// thread-forbidden, socketpair/recvmsg are fine under cargo test).
    fn pair() -> (OwnedFd, OwnedFd) {
        control_socketpair().expect("socketpair must succeed")
    }

    /// Is `FD_CLOEXEC` set on this fd?
    fn cloexec(fd: RawFd) -> bool {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD: {}", io::Error::last_os_error());
        flags & libc::FD_CLOEXEC != 0
    }

    /// `SO_TYPE` of a socket fd.
    fn so_type(fd: RawFd) -> libc::c_int {
        let mut ty: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut ty as *mut libc::c_int).cast::<libc::c_void>(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt SO_TYPE: {}", io::Error::last_os_error());
        ty
    }

    /// Encode a setup message's pieces: `data` is the given payload bytes
    /// verbatim, `ctrl` the fds cmsg from the production encoder.
    fn encode(payload: &[u8], fds: &[RawFd]) -> (Vec<u8>, Vec<u8>) {
        let mut ctrl = Vec::new();
        encode_fds_cmsg(fds, &mut ctrl);
        (payload.to_vec(), ctrl)
    }

    /// Craft a raw cmsg (header byte image + data) for the malformed-input
    /// tests — `len_value` is written verbatim into `cmsg_len`.
    fn craft_cmsg(level: i32, ctype: i32, len_value: usize, data: &[u8]) -> Vec<u8> {
        let mut hdr: libc::cmsghdr = unsafe { std::mem::zeroed() };
        hdr.cmsg_len = len_value as _;
        hdr.cmsg_level = level;
        hdr.cmsg_type = ctype;
        let mut out = Vec::new();
        // SAFETY: byte image of an owned, aligned, initialized cmsghdr.
        out.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                (&hdr as *const libc::cmsghdr).cast::<u8>(),
                size_of::<libc::cmsghdr>(),
            )
        });
        out.extend_from_slice(data);
        out
    }

    // ---- pure codec ------------------------------------------------------

    /// Decode through the production sink contract: returns
    /// `(result, sink)` — the sink is what the caller's
    /// [`ReceivedFdGuard`] would own (m1).
    fn decode(data: &[u8], ctrl: &[u8], msg_flags: i32) -> (io::Result<Head>, Vec<RawFd>) {
        let mut sink = Vec::new();
        let result = decode_setup_message(data, ctrl, msg_flags, &mut sink);
        (result, sink)
    }

    fn ready_bytes(mode: &AchievedMode) -> Vec<u8> {
        let mut data = Vec::new();
        encode_ready(mode, &mut data);
        data
    }

    fn explicit(errno: Option<i32>, reason: &str) -> AchievedMode {
        AchievedMode::Explicit {
            errno,
            reason: reason.to_owned(),
        }
    }

    // ---- golden wire bytes (issue #11) -----------------------------------

    #[test]
    fn ready_wire_goldens() {
        assert_eq!(ready_bytes(&AchievedMode::Transparent), [0x46, 0x74]);
        assert_eq!(
            ready_bytes(&explicit(Some(2), "x")),
            [0x46, 0x65, 0x02, 0, 0, 0, b'x']
        );
        assert_eq!(ready_bytes(&explicit(None, "")), [0x46, 0x65, 0, 0, 0, 0]);
    }

    #[test]
    fn failure_wire_golden() {
        let mut data = Vec::new();
        encode_failure(Stage::NftLoad, Some(2), "x", &mut data);
        assert_eq!(data, [0x45, 0x07, 0x02, 0, 0, 0, b'x']);
    }

    #[test]
    fn stage_code_is_the_wire_code() {
        let mut data = Vec::new();
        encode_failure(Stage::Fallback, None, "r", &mut data);
        assert_eq!(data[1], 9);
    }

    // ---- decode: accept --------------------------------------------------

    #[test]
    fn ready_transparent_roundtrip_in_memory() {
        let (_, ctrl) = encode(&[], &[5, 6, 7]);
        let data = ready_bytes(&AchievedMode::Transparent);
        let (result, sink) = decode(&data, &ctrl, 0);
        assert_eq!(
            result.expect("valid"),
            Head::Ready(AchievedMode::Transparent)
        );
        assert_eq!(sink, [5, 6, 7]);
    }

    #[test]
    fn ready_explicit_roundtrip_in_memory() {
        let mode = explicit(Some(2), "nft-load: batch failed");
        let (_, ctrl) = encode(&[], &[5, 6, 7]);
        let (result, sink) = decode(&ready_bytes(&mode), &ctrl, 0);
        assert_eq!(result.expect("valid"), Head::Ready(mode));
        assert_eq!(sink, [5, 6, 7]);
    }

    #[test]
    fn failed_roundtrip_in_memory_has_no_fds() {
        let mut data = Vec::new();
        encode_failure(Stage::Unshare, Some(28), "unshare failed", &mut data);
        let (result, sink) = decode(&data, &[], 0);
        assert_eq!(
            result.expect("valid"),
            Head::Failed(StagedFailure {
                stage: Stage::Unshare,
                errno: Some(28),
                reason: "unshare failed".into(),
            })
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn errno_zero_is_none() {
        let mut data = Vec::new();
        encode_failure(Stage::Netns, None, "x", &mut data);
        let (result, _) = decode(&data, &[], 0);
        match result.expect("valid") {
            Head::Failed(f) => assert_eq!(f.errno, None),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn truncate_reason_char_boundary() {
        assert_eq!(truncate_reason("short"), "short");
        let long = "é".repeat(600); // 2 bytes each: 1200 bytes
        let cut = truncate_reason(&long);
        assert!(cut.len() <= MAX_REASON_BYTES);
        assert_eq!(cut.len(), MAX_REASON_BYTES, "512 is a char boundary for é");
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
        let odd = format!("{}é", "a".repeat(511));
        assert_eq!(truncate_reason(&odd).len(), 511, "é would straddle 512");
    }

    // ---- decode: reject table ---------------------------------------------

    fn expect_invalid(data: &[u8], ctrl: &[u8], flags: i32, fds_expected: usize) {
        let (result, sink) = decode(data, ctrl, flags);
        let err = result.expect_err(&format!("must reject {data:02x?}"));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{data:02x?}: {err}");
        assert_eq!(sink.len(), fds_expected, "fds stay in the sink (m1)");
    }

    #[test]
    fn decode_reject_table() {
        let (_, three) = encode(&[], &[5, 6, 7]);
        let (_, none) = encode(&[], &[]);
        // empty data
        expect_invalid(&[], &none, 0, 0);
        // unknown first byte
        expect_invalid(b"X", &three, 0, 3);
        // F with unknown mode
        expect_invalid(&[0x46, b'z'], &three, 0, 3);
        // F t with length != 2
        expect_invalid(&[0x46, 0x74, 0x00], &three, 0, 3);
        // F e shorter than the errno
        expect_invalid(&[0x46, 0x65, 0, 0], &three, 0, 3);
        // F e reason over the limit
        let mut long = vec![0x46, 0x65, 0, 0, 0, 0];
        long.extend(std::iter::repeat_n(b'a', MAX_REASON_BYTES + 1));
        expect_invalid(&long, &three, 0, 3);
        // F t with the wrong fd count
        expect_invalid(&[0x46, 0x74], &none, 0, 0);
        let (_, two) = encode(&[], &[5, 6]);
        expect_invalid(&[0x46, 0x74], &two, 0, 2);
        // F e with a negative errno
        expect_invalid(&[0x46, 0x65, 0xff, 0xff, 0xff, 0xff], &three, 0, 3);
        // F e with a reason that is not UTF-8
        expect_invalid(&[0x46, 0x65, 2, 0, 0, 0, 0xff], &three, 0, 3);
        // E shorter than the header
        expect_invalid(&[0x45, 0x07, 0, 0], &none, 0, 0);
        // E with an unknown stage code (0 and 13)
        expect_invalid(&[0x45, 0x00, 0, 0, 0, 0], &none, 0, 0);
        expect_invalid(&[0x45, 0x0d, 0, 0, 0, 0], &none, 0, 0);
        // E carrying fds
        expect_invalid(&[0x45, 0x07, 0, 0, 0, 0], &three, 0, 3);
        // E with a negative errno
        expect_invalid(&[0x45, 0x07, 0xff, 0xff, 0xff, 0xff], &none, 0, 0);
        // E reason over the limit
        let mut long = vec![0x45, 0x07, 0, 0, 0, 0];
        long.extend(std::iter::repeat_n(b'a', MAX_REASON_BYTES + 1));
        expect_invalid(&long, &none, 0, 0);
    }

    #[test]
    fn decode_msg_ctrunc_and_trunc_are_emsgsize() {
        let (data, ctrl) = encode(&[], &[5, 6, 7]);
        let mut ready = ready_bytes(&AchievedMode::Transparent);
        ready.truncate(data.len().max(2));
        for flags in [libc::MSG_CTRUNC, libc::MSG_TRUNC] {
            let (result, sink) = decode(&ready, &ctrl, flags);
            let err = result.expect_err("truncation rejected");
            assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
            assert_eq!(sink.len(), 3, "the fds are still collected (m1)");
        }
    }

    #[test]
    fn decode_rejects_truncated_cmsg() {
        let (data, ctrl) = encode(&[], &[5, 6, 7]);
        let short = &ctrl[..size_of::<libc::cmsghdr>() - 1];
        let (result, _) = decode(&ready_bytes(&AchievedMode::Transparent), short, 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let _ = data;
    }

    #[test]
    fn decode_rejects_non_scm_rights_cmsg() {
        let fd_bytes = 5i32.to_ne_bytes();
        let foreign = craft_cmsg(
            libc::SOL_SOCKET,
            libc::SCM_CREDENTIALS,
            cmsg_hdr_len(4),
            &fd_bytes,
        );
        let (result, _) = decode(&ready_bytes(&AchievedMode::Transparent), &foreign, 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let wrong_level = craft_cmsg(
            libc::IPPROTO_IP,
            libc::SCM_RIGHTS,
            cmsg_hdr_len(4),
            &fd_bytes,
        );
        let (result, _) = decode(&ready_bytes(&AchievedMode::Transparent), &wrong_level, 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_cmsg_len_garbage_does_not_wrap() {
        let (_, mut ctrl) = encode(&[], &[5, 6, 7]);
        // cmsg_len near usize::MAX: rejected by the bounds compare, no wrap.
        let huge = craft_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, usize::MAX - 3, &[]);
        let (result, _) = decode(&ready_bytes(&AchievedMode::Transparent), &huge, 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        ctrl.truncate(3);
        let (result, _) = decode(&ready_bytes(&AchievedMode::Transparent), &ctrl, 0);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn cmsg_math_matches_libc() {
        // Meta-test: the safe const-fn mirror of the kernel's CMSG_* math
        // equals libc's (unsafe) macros for every length the codec uses —
        // plus ragged ones. If libc's layout ever changes, this fails.
        for len in [0usize, 1, 3, 4, 7, 8, 12, 16, 17, 1024] {
            assert_eq!(
                cmsg_hdr_len(len),
                unsafe { libc::CMSG_LEN(len as libc::c_uint) } as usize,
                "CMSG_LEN({len})"
            );
            assert_eq!(
                cmsg_space(len),
                unsafe { libc::CMSG_SPACE(len as libc::c_uint) } as usize,
                "CMSG_SPACE({len})"
            );
        }
    }

    // ---- socketpair factory + spawn window -------------------------------

    #[test]
    fn socketpair_ends_are_cloexec_seqpacket() {
        // R6 discipline, half one: BOTH ends CLOEXEC at creation; SEQPACKET
        // is the enforced transport (D1).
        let (a, b) = pair();
        for end in [&a, &b] {
            let fd = end.as_raw_fd();
            assert!(cloexec(fd), "both ends must be created CLOEXEC");
            assert_eq!(so_type(fd), libc::SOCK_SEQPACKET);
        }
    }

    #[test]
    fn prepare_child_end_clears_cloexec_and_returns_number() {
        // R6 discipline, half two: ONLY the child end is cleared, and the
        // returned number is exactly the fd the child will see post-exec
        // (no renumbering — the issue's no-pre_exec design).
        let (a, b) = pair();
        assert!(cloexec(b.as_raw_fd()), "precondition: created CLOEXEC");
        let n = prepare_child_end(b.as_fd()).expect("fcntl F_SETFD must succeed");
        assert_eq!(n, b.as_raw_fd());
        assert!(!cloexec(n), "child end must be CLOEXEC-cleared");
        assert!(cloexec(a.as_raw_fd()), "parent end must stay CLOEXEC");
    }

    // ---- go byte ---------------------------------------------------------

    #[test]
    fn go_byte_roundtrip_real_socketpair() {
        let (a, b) = pair();
        send_go(a.as_raw_fd()).expect("go byte must send");
        wait_go(b.as_raw_fd()).expect("exact go byte must be accepted");
    }

    #[test]
    fn wait_go_eof_is_staged_error() {
        // Parent died / closed without go: staged WaitGo failure — the
        // payload is never exec'd (probe-verified race).
        let (a, b) = pair();
        drop(a);
        let err = wait_go(b.as_raw_fd()).expect_err("EOF must abort");
        assert_eq!(err.stage(), Stage::WaitGo);
        assert!(err.reason().contains("closed"), "{err}");
    }

    #[test]
    fn wait_go_rejects_wrong_byte() {
        // Strictness (D4): 'X' is not the go byte.
        let (a, b) = pair();
        let n = unsafe { libc::send(a.as_raw_fd(), b"X".as_ptr().cast::<libc::c_void>(), 1, 0) };
        assert_eq!(n, 1, "send: {}", io::Error::last_os_error());
        let err = wait_go_timeout(b.as_raw_fd(), Duration::from_secs(5))
            .expect_err("a wrong byte must abort");
        assert_eq!(err.stage(), Stage::WaitGo);
        assert!(
            err.reason().contains("expected exactly the go byte"),
            "{err}"
        );
        assert!(err.reason().contains("0x58"), "'X' = {:#04x}: {err}", b'X');
    }

    #[test]
    fn wait_go_rejects_g_prefixed_longer_message() {
        // M1: SEQPACKET preserves message boundaries and the frozen
        // contract is data EXACTLY [GO_BYTE] — a longer message merely
        // STARTING with 'G' must abort (a 1-byte recv would silently
        // truncate it into acceptance; the 'F' direction already enforces
        // the exact length). The reason renders the actual length + bytes.
        for msg in [b"G\x00".as_slice(), b"GG", b"GO!"] {
            let (a, b) = pair();
            let sent = unsafe {
                libc::send(
                    a.as_raw_fd(),
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                    0,
                )
            };
            assert_eq!(
                sent,
                msg.len() as isize,
                "send {msg:?}: {}",
                io::Error::last_os_error()
            );
            let err = wait_go_timeout(b.as_raw_fd(), Duration::from_secs(5))
                .expect_err("a 'G'-prefixed longer message must abort");
            assert_eq!(err.stage(), Stage::WaitGo);
            assert!(
                err.reason().contains("expected exactly the go byte"),
                "{err}"
            );
            assert!(
                err.reason().contains(&format!("{} byte(s)", msg.len())),
                "the reason must render the actual length: {err}"
            );
        }
    }

    #[test]
    fn wait_go_timeout_is_bounded() {
        // D17: the injectable timeout bounds the wait — 100 ms here, so the
        // suite never sleeps 30 s; production passes GO_TIMEOUT.
        let (_a, b) = pair(); // peer ALIVE but silent — timeout, not EOF
        let start = Instant::now();
        let err = wait_go_timeout(b.as_raw_fd(), Duration::from_millis(100))
            .expect_err("silence must time out");
        let elapsed = start.elapsed();
        assert_eq!(err.stage(), Stage::WaitGo);
        assert!(err.reason().contains("timed out"), "{err}");
        assert!(
            elapsed >= Duration::from_millis(100),
            "too fast: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "injectable timeout must bound the wait: {elapsed:?}"
        );
    }

    // ---- fds hand-off over a real socketpair -----------------------------

    #[test]
    fn send_and_recv_listener_fds_real_socketpair() {
        // The full child→parent hand-off over a real socketpair: wire order
        // survives (local_addrs match) and every received fd is CLOEXEC
        // (MSG_CMSG_CLOEXEC, D3 — #10's bwrap spawn must not inherit them).
        let (a, b) = pair();
        let t = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind t");
        let e = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind e");
        let u = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind u");
        let fds = [t.as_raw_fd(), e.as_raw_fd(), u.as_raw_fd()];
        send_listener_fds(a.as_raw_fd(), &fds, &AchievedMode::Transparent)
            .expect("send must succeed");

        let received = recv_listener_fds(b.as_raw_fd()).expect("recv must succeed");
        assert_eq!(
            received.transparent.local_addr().expect("local_addr t"),
            t.local_addr().expect("local_addr t"),
            "wire index 0 is the transparent listener"
        );
        assert_eq!(
            received.explicit.local_addr().expect("local_addr e"),
            e.local_addr().expect("local_addr e"),
            "wire index 1 is the explicit listener"
        );
        assert_eq!(
            received.dns.local_addr().expect("local_addr u"),
            u.local_addr().expect("local_addr u"),
            "wire index 2 is the dns socket"
        );
        for fd in received.as_raw_fds() {
            assert!(
                cloexec(fd),
                "received fds must be CLOEXEC (MSG_CMSG_CLOEXEC)"
            );
        }
        // The received fds are dups: distinct numbers, same sockets.
        for (got, sent) in received.as_raw_fds().iter().zip(fds) {
            assert_ne!(*got, sent, "SCM_RIGHTS installs fresh fd numbers");
        }
    }

    #[test]
    fn recv_listener_fds_eof() {
        // Child died before sending: the parent sees UnexpectedEof, never a
        // hang and never a partial ListenerFds.
        let (a, b) = pair();
        drop(a);
        let err = recv_listener_fds(b.as_raw_fd()).expect_err("EOF must fail");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn setup_message_roundtrip_over_real_socketpair() {
        let (a, b) = pair();
        let t = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind t");
        let e = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind e");
        let u = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("bind u");
        let fds = [t.as_raw_fd(), e.as_raw_fd(), u.as_raw_fd()];
        let mode = explicit(Some(2), "nft-load: batch failed");
        send_listener_fds(a.as_raw_fd(), &fds, &mode).expect("send");
        match recv_setup(b.as_raw_fd()).expect("recv") {
            SetupMsg::Ready { fds: got, mode: m } => {
                assert_eq!(m, mode);
                assert_eq!(got.as_raw_fds().len(), 3);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn failure_message_roundtrip_over_real_socketpair() {
        let (a, b) = pair();
        let err = InitError::new(Stage::Ipv6, "write disable_ipv6 failed").with_errno(Some(30));
        send_failure(a.as_raw_fd(), &err);
        match recv_setup(b.as_raw_fd()).expect("recv") {
            SetupMsg::Failed(f) => {
                assert_eq!(f.stage, Stage::Ipv6);
                assert_eq!(f.errno, Some(30));
                assert_eq!(f.to_string(), "ipv6: write disable_ipv6 failed");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn recv_listener_fds_on_failure_is_staged_error_text() {
        let (a, b) = pair();
        send_failure(
            a.as_raw_fd(),
            &InitError::new(Stage::NftLoad, "batch failed"),
        );
        let err = recv_listener_fds(b.as_raw_fd()).expect_err("failure is not fds");
        assert_eq!(err.to_string(), "sbx __init: nft-load: batch failed");
    }

    #[test]
    fn explicit_mode_label_pinned() {
        assert_eq!(AchievedMode::Transparent.label(), "transparent");
        assert_eq!(explicit(None, "").label(), "explicit");
    }

    /// Review (fuzz): the setup-message decoder never panics and never
    /// accepts a message outside the pinned shapes. Deterministic xorshift
    /// inputs, no real fds (ctrl bytes are random or empty).
    #[test]
    fn decode_never_panics_on_random_input() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for i in 0..100_000u32 {
            let dlen = (next() % 600) as usize;
            let mut data: Vec<u8> = (0..dlen).map(|_| next() as u8).collect();
            if !data.is_empty() {
                data[0] = (*b"FEx")[(next() % 3) as usize];
            }
            if data.len() > 1 && i % 2 == 0 {
                data[1] = [b't', b'e', 7, 0, 13, 255][(next() % 6) as usize];
            }
            let ctrl: Vec<u8> = if next() % 4 == 0 {
                (0..(next() % 64) as usize).map(|_| next() as u8).collect()
            } else {
                Vec::new()
            };
            let flags = if next() % 10 == 0 { libc::MSG_TRUNC } else { 0 };
            let mut fds = Vec::new();
            let _ = decode_setup_message(&data, &ctrl, flags, &mut fds);
        }
        // Reason limits are exact at the boundary.
        let mut over = vec![b'E', 7, 2, 0, 0, 0];
        over.extend(std::iter::repeat_n(b'a', MAX_REASON_BYTES + 1));
        assert!(decode_setup_message(&over, &[], 0, &mut Vec::new()).is_err());
        let mut at = vec![b'E', 7, 2, 0, 0, 0];
        at.extend(std::iter::repeat_n(b'a', MAX_REASON_BYTES));
        assert!(decode_setup_message(&at, &[], 0, &mut Vec::new()).is_ok());
        assert!(decode_setup_message(b"F", &[], 0, &mut Vec::new()).is_err());
        // A multibyte reason encodes within the limit and round-trips.
        let mut v = Vec::new();
        encode_failure(Stage::Fallback, Some(5), &"é".repeat(600), &mut v);
        assert!(v.len() - 6 <= MAX_REASON_BYTES);
        assert!(decode_setup_message(&v, &[], 0, &mut Vec::new()).is_ok());
    }
}
