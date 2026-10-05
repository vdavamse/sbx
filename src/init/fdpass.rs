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
//! * **Message 1, child → parent (fds)**: data exactly
//!   `[`[`FDS_PAYLOAD_BYTE`]`]` ('F') plus one `SCM_RIGHTS` cmsg carrying
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

use super::consts::{FDS_PAYLOAD_BYTE, GO_BYTE, GO_TIMEOUT, LISTENER_FD_COUNT};
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

/// Parent side: receive the listener-fd message from `__init`.
///
/// Strict (same-binary invariant): the data payload must be exactly
/// `[`[`FDS_PAYLOAD_BYTE`]`]` and the message must carry exactly
/// [`LISTENER_FD_COUNT`] fds; anything else — `MSG_CTRUNC`, a foreign cmsg,
/// a malformed `cmsg_len`, a wrong count — is an [`io::Error`], never a
/// partial success. Received with `MSG_CMSG_CLOEXEC` (design D3): the
/// parent's dup'd fds must not leak into the later bwrap spawn (#10). EOF
/// (peer closed) is [`io::ErrorKind::UnexpectedEof`]. Every rejection path
/// CLOSES the fds the kernel already installed (the `ReceivedFdGuard` RAII
/// guard, m1): an open socket would pin the dead sandbox's netns.
///
/// #10 handoff: this receive is deliberately UNBOUNDED here (a plain
/// blocking `recvmsg`) — `run` must install its own deadline (`SO_RCVTIMEO`
/// on the parent end, or a child-liveness poll) and, on a child rc 1, drop
/// any received [`ListenerFds`] and close the parent end; the integration
/// harness's `fail-eof-after-fds` scenario demonstrates the pattern.
pub fn recv_listener_fds(ctrl: RawFd) -> io::Result<ListenerFds> {
    let mut data = [0u8; 16];
    let mut ctrlbuf = CtrlBuf([0; CTRL_BUF_LEN]);
    let (n, msg_flags, controllen) =
        recvmsg_raw(ctrl, &mut data, &mut ctrlbuf.0, libc::MSG_CMSG_CLOEXEC)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed before sending the listener fds",
        ));
    }
    // From recvmsg's return the kernel may have installed fds into our
    // table — including on messages the strict decode is about to REJECT.
    // The guard owns them from here until ownership transfers into
    // ListenerFds on the success path (m1).
    let mut guard = ReceivedFdGuard::default();
    decode_fds_message(
        &data[..n],
        &ctrlbuf.0[..controllen],
        msg_flags,
        &mut guard.0,
    )?;
    // decode enforces the exact count; the defensive reshape keeps
    // from_raw_fds' SAFETY contract local — and even this unreachable arm
    // closes the fds instead of leaking them (no panics: a decode bug must
    // surface as an error, not an abort in the parent).
    match guard.release().try_into() {
        Ok(raw) => Ok(ListenerFds::from_raw_fds(raw)),
        Err(unexpected) => {
            for fd in &unexpected {
                // SAFETY: kernel-installed fds never transferred to a std
                // object; each number is closed exactly once here.
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

/// Child side: send all three listener fds in ONE SCM_RIGHTS message
/// (`[`[`FDS_PAYLOAD_BYTE`]`]` data payload + the fd cmsg), wire order per
/// [`ListenerFds`].
///
/// EPIPE means the parent died before receiving the fds — probe-verified;
/// `MSG_NOSIGNAL` makes the detection independent of the SIGPIPE
/// disposition: staged [`Stage::SendFds`] failure, the payload is never
/// exec'd.
pub fn send_listener_fds(ctrl: RawFd, fds: &[RawFd; LISTENER_FD_COUNT]) -> Result<(), InitError> {
    let mut data = Vec::with_capacity(1);
    let mut ctrlbuf = Vec::new();
    encode_fds_message(FDS_PAYLOAD_BYTE, fds, &mut data, &mut ctrlbuf);
    sendmsg_raw(ctrl, &data, &ctrlbuf).map_err(|err| {
        InitError::new(
            Stage::SendFds,
            if err.raw_os_error() == Some(libc::EPIPE) {
                format!("parent died before receiving the listener fds ({err})")
            } else {
                format!("sendmsg listener fds: {err}")
            },
        )
    })
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

/// Pure encoder of the fds message: appends the one-byte data payload to
/// `data` and one well-formed `SOL_SOCKET`/`SCM_RIGHTS` cmsg (header + fd
/// array + alignment padding, `CMSG_SPACE` total) to `ctrl`. In-memory only
/// — [`sendmsg_raw`] copies `ctrl` into an aligned buffer.
pub(crate) fn encode_fds_message(
    payload: u8,
    fds: &[RawFd],
    data: &mut Vec<u8>,
    ctrl: &mut Vec<u8>,
) {
    data.push(payload);
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

/// Pure decoder of the fds message — strict, fail-closed, overflow-free.
///
/// `data` is the received payload verbatim, `ctrl` the ancillary bytes
/// verbatim (recvmsg's `msg_controllen`), `msg_flags` recvmsg's flags.
/// Every SCM_RIGHTS fd found is appended to `fds_out` — the CALLER's sink,
/// so fds the kernel already installed are visible to the caller's
/// [`ReceivedFdGuard`] on EVERY rejection path, including rejections that
/// fire after the cmsg walk (m1: a rejected message must never strand open
/// sockets pinning the dead sandbox's netns). The walk therefore runs
/// FIRST; the message-level checks (CTRUNC flag, payload byte, fd count)
/// follow. Kernel-written chains are well-formed, so bailing on the first
/// malformed header cannot strand real installed fds — malformed headers
/// only occur in crafted in-memory inputs.
///
/// Bounds discipline follows the spike's `listeners.rs` precedent, written
/// so a garbage `cmsg_len` (including near `usize::MAX`) can never wrap an
/// addition: the claimed length is compared against the REMAINING buffer
/// via subtraction, and rejected on any violation. Every rejection is an
/// [`io::Error`], never a panic, and a foreign cmsg is rejected rather than
/// skipped (fail-closed — unexpected ancillary data is a protocol
/// violation):
///
/// * `cmsg_len` shorter than the aligned header or longer than the remaining
///   buffer ⇒ `InvalidData`;
/// * any non-`SOL_SOCKET`/`SCM_RIGHTS` cmsg ⇒ `InvalidData`;
/// * `MSG_CTRUNC` in `msg_flags` ⇒ `EMSGSIZE` (the kernel truncated the
///   cmsg chain; its contents cannot be trusted);
/// * data ≠ `[`[`FDS_PAYLOAD_BYTE`]`]` ⇒ `InvalidData`;
/// * fd count ≠ [`LISTENER_FD_COUNT`] ⇒ `InvalidData`.
pub(crate) fn decode_fds_message(
    data: &[u8],
    ctrl: &[u8],
    msg_flags: i32,
    fds_out: &mut Vec<RawFd>,
) -> io::Result<()> {
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
        // cmsg_len's width is platform-dependent (size_t on 64-bit Linux,
        // socklen_t on other ABIs); comparing in u64 space keeps the bounds
        // check uniform — a garbage length near the type's MAX is rejected
        // by `cmsg_len > remaining` without any addition that could wrap.
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
            // chunks_exact guarantees the length; the map_err keeps the
            // decoder panic-free by construction anyway.
            let bytes: [u8; size_of::<RawFd>()] = chunk
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed fd chunk"))?;
            fds_out.push(RawFd::from_ne_bytes(bytes));
        }
        // Advance to the next cmsg slot. The addition cannot overflow:
        // cmsg_len ≤ remaining ≤ ctrl.len() and off ≤ ctrl.len(), both far
        // below usize::MAX for any real (≤ CTRL_BUF_LEN) buffer.
        off += cmsg_align(cmsg_len);
    }
    if msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    if data.len() != 1 || data[0] != FDS_PAYLOAD_BYTE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected the 1-byte payload [{FDS_PAYLOAD_BYTE:#04x}], got {data:02x?}"),
        ));
    }
    if fds_out.len() != LISTENER_FD_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected {LISTENER_FD_COUNT} fds, got {}", fds_out.len()),
        ));
    }
    Ok(())
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

    /// Encode a message through the production encoder.
    fn encode(payload: u8, fds: &[RawFd]) -> (Vec<u8>, Vec<u8>) {
        let (mut data, mut ctrl) = (Vec::new(), Vec::new());
        encode_fds_message(payload, fds, &mut data, &mut ctrl);
        (data, ctrl)
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
    fn decode(data: &[u8], ctrl: &[u8], msg_flags: i32) -> (io::Result<()>, Vec<RawFd>) {
        let mut sink = Vec::new();
        let result = decode_fds_message(data, ctrl, msg_flags, &mut sink);
        (result, sink)
    }

    #[test]
    fn fds_message_roundtrip_in_memory() {
        let (data, ctrl) = encode(FDS_PAYLOAD_BYTE, &[5, 6, 7]);
        assert_eq!(data, [FDS_PAYLOAD_BYTE]);
        let (result, sink) = decode(&data, &ctrl, 0);
        result.expect("valid message decodes");
        assert_eq!(sink, [5, 6, 7]);
    }

    #[test]
    fn decode_rejects_wrong_payload_byte() {
        // Strictness (D4): the marker byte is part of the protocol; so is
        // the payload LENGTH (a multi-byte payload is not our message).
        // m1: the cmsg walk runs FIRST, so the installed fds are in the
        // sink for the caller's guard even on these rejections.
        let (_, ctrl) = encode(FDS_PAYLOAD_BYTE, &[5, 6, 7]);
        let (data, _) = encode(b'X', &[5, 6, 7]);
        let (result, sink) = decode(&data, &ctrl, 0);
        let err = result.expect_err("wrong byte must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(sink, [5, 6, 7], "the rejection must not strand the fds");
        let (result, _) = decode(&[], &ctrl, 0);
        assert_eq!(
            result.expect_err("empty data must be rejected").kind(),
            io::ErrorKind::InvalidData
        );
        let (result, _) = decode(&[FDS_PAYLOAD_BYTE, FDS_PAYLOAD_BYTE], &ctrl, 0);
        assert_eq!(
            result.expect_err("multi-byte data must be rejected").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn decode_rejects_wrong_fd_count() {
        // Exactly LISTENER_FD_COUNT fds: fewer or more is a protocol
        // violation, never a partial success (D4) — and the sink holds
        // whatever arrived (m1: the guard closes it, no stranded fds).
        let cases: [&[RawFd]; 3] = [&[5, 6], &[5, 6, 7, 8], &[]];
        for fds in cases {
            let (data, ctrl) = encode(FDS_PAYLOAD_BYTE, fds);
            let (result, sink) = decode(&data, &ctrl, 0);
            let err = match result {
                Ok(()) => panic!("{fds:?} fds must be rejected"),
                Err(err) => err,
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{fds:?}");
            assert_eq!(sink, fds, "sink mirrors the arrived fds: {fds:?}");
        }
    }

    #[test]
    fn decode_rejects_truncated_cmsg() {
        // Every truncation shorter than the advertised cmsg_len must be
        // rejected — no panic, no UB, no partial acceptance. The bounds
        // check fires before any fd parse, so the sink stays empty.
        let (data, ctrl) = encode(FDS_PAYLOAD_BYTE, &[5, 6, 7]);
        let full = cmsg_hdr_len(3 * size_of::<RawFd>());
        assert!(ctrl.len() >= full, "sanity: ctrl holds the full cmsg");
        for cut in 1..full {
            let (result, sink) = decode(&data, &ctrl[..cut], 0);
            let err = match result {
                Ok(()) => panic!("truncation to {cut} bytes must be rejected"),
                Err(err) => err,
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "cut {cut}");
            assert!(sink.is_empty(), "cut {cut}: rejected before any fd parse");
        }
    }

    #[test]
    fn decode_rejects_msg_ctrunc() {
        // The kernel truncated the cmsg chain: its contents cannot be
        // trusted, even when they parse — reject with EMSGSIZE (spike
        // listeners.rs precedent). m1: the walk runs first, so the fds the
        // kernel installed for the truncated chain are in the sink for the
        // guard to close.
        let (data, ctrl) = encode(FDS_PAYLOAD_BYTE, &[5, 6, 7]);
        let (result, sink) = decode(&data, &ctrl, libc::MSG_CTRUNC);
        let err = result.expect_err("MSG_CTRUNC must be rejected");
        assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
        assert_eq!(sink, [5, 6, 7], "CTRUNC must not strand the fds");
    }

    #[test]
    fn decode_rejects_non_scm_rights_cmsg() {
        // Fail-closed, not ignore: a foreign cmsg in our control message is
        // a protocol violation (the same-binary invariant means it can only
        // come from a bug or an attacker).
        let data = [FDS_PAYLOAD_BYTE];
        let foreign = [
            craft_cmsg(
                libc::SOL_SOCKET,
                libc::SCM_CREDENTIALS,
                cmsg_hdr_len(12),
                &[0; 12],
            ),
            craft_cmsg(libc::IPPROTO_IP, 99, cmsg_hdr_len(12), &[0; 12]),
        ];
        for ctrl in foreign {
            let (result, sink) = decode(&data, &ctrl, 0);
            let err = result.expect_err("foreign cmsg rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(sink.is_empty(), "a foreign-only chain installs nothing");
        }
        // A foreign cmsg AFTER a valid SCM_RIGHTS one is rejected too — and
        // the leading valid cmsg's fds are in the sink for the guard (m1:
        // the kernel installed them; the rejection must not strand them).
        let (data2, mut valid) = encode(FDS_PAYLOAD_BYTE, &[5, 6, 7]);
        valid.extend_from_slice(&craft_cmsg(
            libc::SOL_SOCKET,
            libc::SCM_CREDENTIALS,
            cmsg_hdr_len(12),
            &[0; 12],
        ));
        let (result, sink) = decode(&data2, &valid, 0);
        let err = result.expect_err("trailing foreign cmsg");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(sink, [5, 6, 7], "leading fds must not strand");
    }

    #[test]
    fn decode_cmsg_len_garbage_does_not_wrap() {
        // The overflow-free bounds invariant (spike comment precedent): a
        // cmsg_len near usize::MAX must be rejected by the comparison
        // against the REMAINING buffer — an addition-based check would wrap
        // and could accept. Zero, sub-header and non-fd-multiple lengths
        // too; every rejection fires before any fd parse (empty sink).
        let data = [FDS_PAYLOAD_BYTE];
        for len_value in [usize::MAX, usize::MAX - 7, 0, 1, cmsg_hdr_len(0) - 1] {
            let ctrl = craft_cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, len_value, &[0; 12]);
            let (result, sink) = decode(&data, &ctrl, 0);
            let err = match result {
                Ok(()) => panic!("cmsg_len {len_value} must be rejected"),
                Err(err) => err,
            };
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "len {len_value}");
            assert!(
                sink.is_empty(),
                "len {len_value}: rejected before any fd parse"
            );
        }
        // A cmsg_len whose fd area is not a multiple of the fd width.
        let ctrl = craft_cmsg(
            libc::SOL_SOCKET,
            libc::SCM_RIGHTS,
            cmsg_hdr_len(3 * size_of::<RawFd>() + 2),
            &[0; 3 * size_of::<RawFd>() + 2],
        );
        let (result, sink) = decode(&data, &ctrl, 0);
        let err = result.expect_err("ragged fd area rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(sink.is_empty(), "ragged area: rejected before any fd parse");
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
        send_listener_fds(a.as_raw_fd(), &fds).expect("send must succeed");

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
}
