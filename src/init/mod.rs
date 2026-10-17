//! The `sbx __init` namespace child (issue #5) — per-call user+network
//! namespace setup, nftables rules, listener fd hand-off, payload exec.
//!
//! 1. **Stage order is load-bearing.** [`Stage`] enumerates the pipeline
//!    order (`fallback`, issue #11, sits between `nft-verify` and `send-fds`): the `control` stage validates the inherited socketpair end
//!    *before* any namespace work (fast, deterministic, namespace- and
//!    privilege-independent failure — which is what makes the CI build-job
//!    smoke runnable on any runner); listeners bind *before* the nftables
//!    rules load (no redirect-live-without-listener window: a
//!    bound-but-unaccepted socket completes handshakes into its backlog, so
//!    there is no RST window either); rules load *and* dump-verify before
//!    the listener fds are sent and before the go byte releases the payload
//!    (no fail-open window: the payload can never run before the firewall is
//!    kernel-verified).
//! 2. **Single-threaded until exec.** `unshare(CLONE_NEWUSER)` fails with
//!    EPERM in a multithreaded process, so `__init` never spawns a thread,
//!    and no unit test ever calls `unshare` (a successful one would capture
//!    the whole test binary's namespaces). This is also why `run` (#10)
//!    re-execs a fresh `__init` child instead of setting namespaces up
//!    in-process.
//! 3. **Fail-closed everywhere.** Any setup failure aborts with exit code 1
//!    *before* the payload is exec'd — the command never runs in a
//!    half-configured sandbox. Success is silent (house `check` precedent);
//!    diagnostics go to stderr only on failure.
//! 4. **Error vocabulary and exit codes.** [`InitError`] pairs a [`Stage`]
//!    with a reason; its `Display` is the single formatting site of the
//!    pinned `sbx __init: <stage>: <reason>` shape. Exit codes stay the
//!    README/cli contract: 0 = the payload's own code (via `exec`), 1 =
//!    staged setup failure (payload never exec'd), 2 = usage (clap).
//!    `__init` never panics out to the user: the CLI seam catches unwinds
//!    and reports them as staged rc-1 errors — with the default panic hook
//!    silenced for the pipeline's duration (m3), so the staged line is the
//!    only stderr output — never exit 101.
//! 5. **Protocol strictness is free.** Parent (`run`, #10) and child are
//!    always the *same binary* — `run` re-execs `current_exe` — so the
//!    control protocol validates exact bytes ('F' + mode or 'E' failure, 'G'
//!    go, exactly three fds on a ready message) with no version negotiation
//!    (design D4). Since issue #11 a staged failure in the setup stages is
//!    reported as an `'E'` message before the staged stderr line (run
//!    classifies it; the stderr text is unchanged).
//! 6. **Exec hygiene: fds AND runtime state (spike risks R5/R6).** The
//!    control fd (`--fd N`) is deliberately *not* CLOEXEC — it must survive
//!    the re-exec from `run` — so it is closed explicitly before the payload
//!    exec, backed by a `/proc/self/fd` scan. Listener sockets are std-owned
//!    (CLOEXEC by default): they die at exec even if the scan ever missed
//!    one, while the parent's SCM_RIGHTS-dup'd copies live on (cross-netns fd
//!    passing). The socketpair itself is created CLOEXEC on *both* ends with
//!    the child end cleared only in the spawn window — see
//!    [`fdpass::prepare_child_end`] for the bug class that discipline
//!    prevents. The same seam applies to runtime state: std sets `SIGPIPE` to
//!    `SIG_IGN` at startup and ignored dispositions survive `execve` (bwrap
//!    does not reset them either — upstream `bubblewrap.c`'s only `SIG_DFL`
//!    restore is `SIGCHLD`), so `exec_payload` restores `SIG_DFL` right
//!    before the `execvp` — the payload would otherwise inherit broken
//!    `cmd | head`-style pipe semantics — and re-ignores `SIGPIPE` on the
//!    failure return so the staged diagnostics stay EPIPE-safe.
//!    Issue #10 adds two things. The hidden `--keep-fd N` (the bwrap info pipe
//!    `run` hands through) survives hygiene, and it is validated before any
//!    namespace work. Issue #34 adds the hidden `--seccomp-fd N` (the sealed
//!    socket-family program memfd bwrap reads as `--seccomp`), validated the
//!    same way and content-checked against this binary's own program. The only
//!    fds above 2 that survive hygiene are `--keep-fd` and `--seccomp-fd`. The signal mask is reset
//!    first thing: std does not reset the blocked mask across spawn, and
//!    `run` blocks TERM/INT/HUP/QUIT for its signalfd.
//! 7. **Consumers.** [`fdpass`] doubles as the parent-side API #10 drives
//!    (`control_socketpair` → `prepare_child_end` → spawn →
//!    `recv_listener_fds` → serve (#7/#8/#9) → `send_go`); [`consts`] is the
//!    cross-issue constant surface (ports for #6, `SO_ORIGINAL_DST` for #7,
//!    `IP_RECVORIGDSTADDR` for #9, `GO_TIMEOUT` for #10). Control-socket EOF
//!    means *exec time* (the child closes its end before exec), NOT sandbox
//!    death — #10's liveness check is `Child::wait`.
//!
//! 8. **Network mode fallback (issue #11, Q1).** `--min-mode` is the weakest
//!    mode the caller accepts (the policy's own). The full nftables firewall
//!    is always tried first; only an atomic `nft-load` refusal with a policy
//!    of explicit or none falls back: the default route is removed and the
//!    routing table read back (fail closed), and the achieved mode is
//!    reported. `nft-verify` and every other stage stay fatal.

pub mod consts;
pub mod fdpass;
pub mod probe;
// Private: implementation detail of the pipeline below. `fdpass` (the
// parent-side API #10 drives) and `consts` (the cross-issue constant
// surface) are the module's public face. (They were declared `pub` while
// unwired — design D16 — and tightened here in the wiring commit, keeping
// every SHA warning-free without `#[allow(dead_code)]` churn.)
mod listeners;
mod netns;
mod rules;

// Conformance lab child (issue #13): the lab namespace helpers.
pub(crate) use netns::{OuterIds, configure_lab_lo, write_id_maps};

use std::any::Any;
use std::ffi::OsString;
use std::fmt;
use std::os::fd::RawFd;
use std::process::ExitCode;

use netlink_socket2::NetlinkSocket;

use crate::policy::NetworkMode;
pub use fdpass::AchievedMode;

/// The setup stage a failure occurred in — the `<stage>` of every
/// `sbx __init: <stage>: <reason>` message.
///
/// The variants are declared in pipeline order (module docs point 1); the
/// pinned user-visible names come from [`Stage::as_str`] and are frozen by
/// the `stage_names_pinned` test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Validating the inherited control socketpair end (`--fd N`).
    Control,
    /// `unshare(CLONE_NEWUSER | CLONE_NEWNET)`.
    Unshare,
    /// Writing `/proc/self/{setgroups,uid_map,gid_map}`.
    Idmap,
    /// `lo` up + `10.255.255.1/32` + default route, with read-back asserts.
    Netns,
    /// Disabling IPv6 (sysctl) and verifying `if_inet6` is empty.
    Ipv6,
    /// Binding the three bare listener sockets.
    Listeners,
    /// Loading the atomic nftables batch (with ERESTART retry).
    NftLoad,
    /// Verifying the loaded ruleset against the kernel's own dump.
    NftVerify,
    /// Explicit fallback: default-route removal + routing read-back (issue
    /// #11). Only reached when the nft batch was refused and the policy
    /// allows the explicit mode.
    Fallback,
    /// Handing the listener fds to the parent over SCM_RIGHTS.
    SendFds,
    /// Blocking on the parent's go byte.
    WaitGo,
    /// `execvp` of the payload argv.
    Exec,
}

impl Stage {
    /// The pinned stage name — the `<stage>` in every `sbx __init:` message.
    ///
    /// Exhaustive match: a new variant without a pinned name fails to
    /// compile (house convention for pinned message vocabularies).
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Control => "control",
            Stage::Unshare => "unshare",
            Stage::Idmap => "idmap",
            Stage::Netns => "netns",
            Stage::Ipv6 => "ipv6",
            Stage::Listeners => "listeners",
            Stage::NftLoad => "nft-load",
            Stage::NftVerify => "nft-verify",
            Stage::Fallback => "fallback",
            Stage::SendFds => "send-fds",
            Stage::WaitGo => "wait-go",
            Stage::Exec => "exec",
        }
    }

    /// Wire code for the `'E'` setup-failure message (issue #11). Exhaustive
    /// match, pinned by `stage_codes_pinned`: Control=1, Unshare=2, Idmap=3,
    /// Netns=4, Ipv6=5, Listeners=6, NftLoad=7, NftVerify=8, Fallback=9,
    /// SendFds=10, WaitGo=11, Exec=12.
    pub fn code(self) -> u8 {
        match self {
            Stage::Control => 1,
            Stage::Unshare => 2,
            Stage::Idmap => 3,
            Stage::Netns => 4,
            Stage::Ipv6 => 5,
            Stage::Listeners => 6,
            Stage::NftLoad => 7,
            Stage::NftVerify => 8,
            Stage::Fallback => 9,
            Stage::SendFds => 10,
            Stage::WaitGo => 11,
            Stage::Exec => 12,
        }
    }

    /// Inverse of [`Stage::code`]; unknown codes are `None`.
    pub fn from_code(code: u8) -> Option<Stage> {
        ALL_STAGES.iter().copied().find(|s| s.code() == code)
    }

    /// Stages whose failure `__init` reports to the parent with an `'E'`
    /// message: the pipeline's middle, `Unshare..=Fallback`. Control (the
    /// fd itself is unusable), SendFds/WaitGo (the channel is the problem)
    /// and Exec (the control fd is already closed by fd hygiene) are not.
    pub fn reports_to_parent(self) -> bool {
        matches!(
            self,
            Stage::Unshare
                | Stage::Idmap
                | Stage::Netns
                | Stage::Ipv6
                | Stage::Listeners
                | Stage::NftLoad
                | Stage::NftVerify
                | Stage::Fallback
        )
    }
}

/// Every stage in pipeline order (codes 1..=12).
pub const ALL_STAGES: [Stage; 12] = [
    Stage::Control,
    Stage::Unshare,
    Stage::Idmap,
    Stage::Netns,
    Stage::Ipv6,
    Stage::Listeners,
    Stage::NftLoad,
    Stage::NftVerify,
    Stage::Fallback,
    Stage::SendFds,
    Stage::WaitGo,
    Stage::Exec,
];

/// A staged setup failure: which [`Stage`] failed, and why.
///
/// The reason is complete and user-facing; `Display` is the single
/// formatting site of the pinned `sbx __init: <stage>: <reason>` shape
/// (module docs point 4). Every construction site passes a full reason —
/// the message is composed in exactly one place, here.
#[derive(Debug)]
pub struct InitError {
    stage: Stage,
    reason: String,
    /// The OS errno behind the failure, when the failing call had one
    /// (issue #11). Carried on the `'E'` message and consumed by the
    /// host classifier; never part of `Display`.
    errno: Option<i32>,
}

impl InitError {
    /// Construct a staged error from a stage and its reason text.
    pub fn new(stage: Stage, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: reason.into(),
            errno: None,
        }
    }

    /// Attach the OS errno of the failing call (issue #11). `Display` is
    /// unchanged.
    pub fn with_errno(mut self, errno: Option<i32>) -> Self {
        self.errno = errno;
        self
    }

    /// The OS errno behind the failure, if any.
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }

    /// The stage that failed.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The reason text, without the `sbx __init: <stage>:` prefix.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // THE single formatting site for the staged-message contract;
        // init_error_display_single_site pins it for every stage.
        write!(f, "sbx __init: {}: {}", self.stage.as_str(), self.reason)
    }
}

impl std::error::Error for InitError {}

// ---------------------------------------------------------------------------
// the pipeline
// ---------------------------------------------------------------------------

/// CLI seam for `sbx __init` (dispatched by [`crate::cli::run`]).
///
/// Never panics and never returns 101 (N4): staged setup failures print
/// `sbx __init: <stage>: <reason>` to stderr and return
/// [`ExitCode::FAILURE`] with the payload NEVER exec'd; a caught unwind
/// prints `sbx __init: internal error: <payload>` and also returns 1 —
/// with the default panic hook silenced for the pipeline's duration (m3),
/// the staged line is the ONLY stderr output, exactly as the pinned
/// message shape promises. On success the process image is REPLACED by the
/// payload (`exec`), so the exit code the caller observes is the payload's
/// own — the [`ExitCode::SUCCESS`] arm is unreachable in practice (the
/// pipeline only returns `Ok` if `execvp` returns, which success never
/// does).
pub fn run_init(args: InitArgs) -> ExitCode {
    // Issue #10 (E10): `run` blocks TERM/INT/HUP/QUIT for its signalfd, and
    // std's Command does NOT reset the blocked mask across spawn. `__init` is
    // single-threaded, so resetting its thread mask resets the process mask;
    // bwrap and the payload then start with an empty mask. FIRST statement.
    reset_signal_mask();
    // m3: the default panic hook prints `thread 'main' panicked …` to
    // stderr BEFORE catch_unwind hands us the payload — that noise would
    // precede (and break the pinned prefix of) the staged `sbx __init:
    // internal error:` line, so silence the hook for the pipeline's
    // duration. The previous hook is restored before returning: production
    // exits or execs right after either way, and unit tests calling this
    // seam must not lose panic diagnostics for the rest of the suite.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    // The catch_unwind backstop: a bug anywhere in the pipeline degrades to
    // a staged rc-1 error, never a 101 + backtrace (release keeps unwinding
    // — sbx has no panic=abort). AssertUnwindSafety: the pipeline is a pure
    // sequence of syscalls over Copy/owned inputs; a poisoned intermediate
    // state cannot be observed because we abort (rc 1) after a catch.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pipeline(&args)));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            // Issue #11: the parent classifies staged failures from the 'E'
            // message (no stderr parsing). Best effort — the staged stderr
            // line below is printed regardless, so standalone use is
            // unchanged.
            if err.stage().reports_to_parent() {
                fdpass::send_failure(args.fd, &err);
            }
            eprintln!("{err}");
            ExitCode::FAILURE
        }
        Err(payload) => {
            eprintln!("sbx __init: internal error: {}", panic_message(&payload));
            ExitCode::FAILURE
        }
    }
}

/// Arguments of the `__init` pipeline (issue #11 grew the old positional
/// list; the struct keeps call sites readable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    /// The control socket fd (`--fd`).
    pub fd: RawFd,
    /// The bwrap info pipe to keep across the exec (`--keep-fd`, issue #10).
    pub keep_fd: Option<RawFd>,
    /// The sealed seccomp-program memfd to keep for bwrap (`--seccomp-fd`,
    /// issue #34). Optional for direct `__init` callers; `run` always passes it.
    pub seccomp_fd: Option<RawFd>,
    /// Expected parent pid (`--parent-pid`, m6).
    pub parent_pid: Option<i32>,
    /// The weakest network mode the caller accepts — the policy's own mode
    /// (`--min-mode`). `Transparent` (the default for direct callers and
    /// every existing test) disables the explicit fallback.
    pub min_mode: NetworkMode,
    /// Hidden fail-only test driver (`--test-break-rules`).
    pub test_break_rules: bool,
    /// The payload argv, exec'd last.
    pub cmd: Vec<OsString>,
}

/// Whether a policy whose mode is `min_mode` accepts the explicit fallback
/// (issue #11, Q1): explicit and none do, transparent does not.
pub(crate) fn fallback_allowed(min_mode: NetworkMode) -> bool {
    min_mode != NetworkMode::Transparent
}

/// The full stage sequence — THE ORDER IS LOAD-BEARING (module docs point
/// 1). Each stage call constructs its own staged errors; this fn only
/// sequences them. Returns `Err(exec_payload(..))` when exec fails; `Ok`
/// would mean execvp returned success, which is impossible.
fn pipeline(args: &InitArgs) -> Result<(), InitError> {
    let fd = args.fd;
    arm_parent_death(args.parent_pid)?; // m6: first, so a dying parent takes us with it
    validate_control_fd(fd)?; // Stage::Control — BEFORE unshare: fast, deterministic
    if let Some(keep) = args.keep_fd {
        validate_keep_fd(keep, fd)?; // Stage::Control too (issue #10, Q13)
    }
    if let Some(seccomp) = args.seccomp_fd {
        validate_seccomp_fd(seccomp, fd, args.keep_fd)?; // Stage::Control (issue #34)
    }
    let ids = netns::unshare_namespaces()?; // Stage::Unshare
    netns::write_id_maps(ids)?; // Stage::Idmap
    netns::configure_netns()?; // Stage::Netns
    netns::disable_ipv6()?; // Stage::Ipv6
    let listeners = listeners::bind_all()?; // Stage::Listeners — BEFORE rules (N5)
    // Lazy: the real netlink socket opens on the first request — post-
    // unshare, hence bound to the NEW netns; SOCK_CLOEXEC (crate default)
    // ⇒ it dies at exec.
    let mut sock = NetlinkSocket::new();
    // Issue #11 (Q1): the full firewall is always tried first. Only an
    // atomic `nft-load` refusal (nothing committed) may fall back to the
    // explicit mode, and only when the policy allows it. `nft-verify` and
    // every other stage stay fatal.
    let mode = match rules::load(&mut sock, args.test_break_rules) {
        Ok(stats) => {
            // D20: LoadStats is retained for #10's startup/audit notes; success is
            // silent (D6), so the child has no consumer yet — the explicit read
            // keeps the forward-looking fields warning-free without allow() churn.
            let _ = (stats.genid, stats.attempts);
            rules::verify_dump(&mut sock)?; // Stage::NftVerify — Q7(a): production ALWAYS verifies
            AchievedMode::Transparent
        }
        Err(err) if err.stage() == Stage::NftLoad && fallback_allowed(args.min_mode) => {
            // Atomic batch: nothing was committed. Remove the default route
            // so direct connects fail fast (E1/E2), verify it is gone, and
            // report WHY transparent was not achieved.
            netns::remove_default_route()?; // Stage::Fallback (read-back verified)
            AchievedMode::Explicit {
                errno: err.errno(),
                reason: format!("{}: {}", err.stage().as_str(), err.reason()),
            }
        }
        Err(err) => return Err(err),
    };
    fdpass::send_listener_fds(fd, &listeners.as_raw_fds(), &mode)?; // Stage::SendFds
    fdpass::wait_go(fd)?; // Stage::WaitGo (SO_RCVTIMEO = GO_TIMEOUT, strict 'G')
    // Close our copies before hygiene (the parent's SCM_RIGHTS dups keep
    // the sockets alive); CLOEXEC would kill them at exec anyway — the
    // fd_hygiene scan below is defense in depth.
    drop(listeners);
    drop(sock);
    fd_hygiene(fd, &keep_set(args));
    Err(exec_payload(&args.cmd)) // Stage::Exec — returns ONLY on failure
}

/// The fds that survive [`fd_hygiene`] on purpose (issue #10 and #34): the
/// bwrap info pipe and the seccomp program memfd. Both are consumed by bwrap
/// before the payload runs; both were validated in the control stage.
fn keep_set(args: &InitArgs) -> Vec<RawFd> {
    args.keep_fd.into_iter().chain(args.seccomp_fd).collect()
}

/// Validate `--fd` before any namespace work: a bad control fd fails fast
/// and deterministically (staged rc 1) even where unprivileged userns is
/// unavailable — this is what makes the CI build-job smoke
/// namespace-independent.
///
/// Checks: `getsockname` succeeds (EBADF ⇒ not a valid fd; ENOTSOCK ⇒ not a
/// socket), the family is AF_UNIX, and `SO_TYPE` is SOCK_SEQPACKET (design
/// D1 — a mistaken `UnixStream::pair()` (SOCK_STREAM) in future code fails
/// here instead of misbehaving on the wire protocol).
fn validate_control_fd(fd: RawFd) -> Result<(), InitError> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&mut sa as *mut libc::sockaddr_storage).cast::<libc::sockaddr>(),
            &mut len,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(InitError::new(
            Stage::Control,
            match err.raw_os_error() {
                Some(libc::EBADF) => {
                    format!("--fd {fd} is not a valid file descriptor (EBADF)")
                }
                Some(libc::ENOTSOCK) => format!("--fd {fd} is not a socket (ENOTSOCK)"),
                _ => format!("getsockname on --fd {fd} failed: {err}"),
            },
        ));
    }
    if sa.ss_family != libc::AF_UNIX as libc::sa_family_t {
        return Err(InitError::new(
            Stage::Control,
            format!(
                "--fd {fd} is not an AF_UNIX socket (family {})",
                sa.ss_family
            ),
        ));
    }
    let mut so_type: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut so_type as *mut libc::c_int).cast::<libc::c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 {
        return Err(InitError::new(
            Stage::Control,
            format!(
                "getsockopt SO_TYPE on --fd {fd} failed: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    if so_type != libc::SOCK_SEQPACKET {
        return Err(InitError::new(
            Stage::Control,
            format!(
                "--fd {fd} is not a SOCK_SEQPACKET control socket (type {so_type}, expected {})",
                libc::SOCK_SEQPACKET
            ),
        ));
    }
    Ok(())
}

/// Panic payload → message: `&str`/`String` contents for the common
/// `panic!("...")` case, else a fixed fallback (never a second panic).
fn panic_message(payload: &Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_owned();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_owned()
}

/// Close the control fd explicitly — the ONE fd that is deliberately not
/// CLOEXEC (R5: it must never leak into the untrusted payload) — then
/// defense in depth: collect the `/proc/self/fd` entries > 2, DROP the
/// directory handle first (its own dirfd may be in the collected set; std
/// opened it O_CLOEXEC), then close each collected number ignoring EBADF
/// (R17: collect-then-drop-then-close). The process is single-threaded ⇒
/// no fd-reuse race between collect and close. Best effort: if
/// `/proc/self/fd` is unreadable, stop after the explicit close — every
/// other fd in this process is CLOEXEC (std + netlink crate defaults) and
/// dies at exec anyway. The end-to-end proof is the integration suite's
/// `check-net` role asserting fds == {0,1,2} after exec (D13 — in-process
/// closing tests are thread-hostile under parallel cargo test).
fn fd_hygiene(control: RawFd, keep: &[RawFd]) {
    // SAFETY: closing an fd this process owns; EBADF (already closed) is
    // ignored by design.
    unsafe {
        libc::close(control);
    }
    let Some(fds) = scan_fds_above_stdio() else {
        return;
    };
    for fd in fds_to_close(fds, keep) {
        // SAFETY: single-threaded process; the number came from our own
        // /proc/self/fd; EBADF is tolerated (the scan's dirfd may already
        // be closed, or a RAII drop beat us to it).
        unsafe {
            libc::close(fd);
        }
    }
    for &kept in keep {
        // Defense in depth (issue #10, #34): every kept fd must survive execvp
        // even if the caller forgot to clear CLOEXEC on it. Each was validated
        // in the control stage (validate_keep_fd / validate_seccomp_fd).
        // SAFETY: F_SETFD on an fd validated before the pipeline's hygiene.
        unsafe {
            libc::fcntl(kept, libc::F_SETFD, 0);
        }
    }
}

/// Issue #34: `--seccomp-fd` is the sealed memfd holding sbx's socket-family
/// program ([`crate::bwrap::seccomp`]). bwrap reads it in the sandbox child
/// and applies the filter as the last step before exec, so a wrong or forged
/// program would silently change the sandbox. Verified here, before any
/// namespace work: it must be a sealed memfd (write/grow/shrink sealed)
/// whose bytes equal this binary's own `native_program_bytes()` (the same
/// binary is the producer and the verifier). Every failure stages `control`
/// and exits 1; the offset is rewound because bwrap reads from the current
/// offset.
fn validate_seccomp_fd(
    seccomp: RawFd,
    control: RawFd,
    keep: Option<RawFd>,
) -> Result<(), InitError> {
    let fail = |reason: String| InitError::new(Stage::Control, reason);
    if seccomp <= 2 {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} must be greater than 2"
        )));
    }
    if seccomp == control {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} must differ from --fd"
        )));
    }
    if keep == Some(seccomp) {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} must differ from --keep-fd"
        )));
    }
    // SAFETY: fstat on a number we were handed; the result is only read.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(seccomp, &mut st) } != 0 {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} is not a valid file descriptor (EBADF)"
        )));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} is not a sealed memfd"
        )));
    }
    // SAFETY: fcntl F_GET_SEALS on the fd validated above.
    let seals = unsafe { libc::fcntl(seccomp, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    if seals < 0 || seals & required != required {
        return Err(fail(format!(
            "--seccomp-fd {seccomp} is not a sealed memfd"
        )));
    }
    let mismatch = || {
        fail(format!(
            "--seccomp-fd {seccomp} does not hold sbx's seccomp program"
        ))
    };
    let expected = crate::bwrap::seccomp::native_program_bytes().ok_or_else(mismatch)?;
    let mut buf = vec![0u8; expected.len() + 1];
    // SAFETY: pread into a buffer we own; the file offset is not moved.
    let n = unsafe { libc::pread(seccomp, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if usize::try_from(n) != Ok(expected.len()) || buf[..expected.len()] != expected[..] {
        return Err(mismatch());
    }
    // SAFETY: lseek on the validated fd; bwrap reads from the current offset.
    if unsafe { libc::lseek(seccomp, 0, libc::SEEK_SET) } < 0 {
        return Err(fail(format!("--seccomp-fd {seccomp} cannot be rewound")));
    }
    Ok(())
}

/// Issue #10 (Q13): `--keep-fd` is the bwrap info pipe `run` hands through.
/// Validated in the control stage so a bad value fails before any namespace
/// work. The write end must be a pipe open for writing (bwrap writes the
/// `child-pid` JSON there); a forged pid cannot be produced by the payload
/// because bwrap closes the info fd before the payload exists (E3) and `run`
/// verifies PPid/NSpid anyway.
fn validate_keep_fd(keep: RawFd, control: RawFd) -> Result<(), InitError> {
    let fail = |reason: String| InitError::new(Stage::Control, reason);
    if keep <= 2 {
        return Err(fail(format!("--keep-fd {keep} must be greater than 2")));
    }
    if keep == control {
        return Err(fail(format!("--keep-fd {keep} must differ from --fd")));
    }
    // SAFETY: fstat/fcntl on a number we were handed; the result is only read.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(keep, &mut st) } != 0 {
        return Err(fail(format!(
            "--keep-fd {keep} is not a valid file descriptor (EBADF)"
        )));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(fail(format!("--keep-fd {keep} is not a pipe")));
    }
    let flags = unsafe { libc::fcntl(keep, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_WRONLY {
        return Err(fail(format!("--keep-fd {keep} is not open for writing")));
    }
    Ok(())
}

/// Pure core of [`fd_hygiene`]'s close set: the scanned fds minus `keep`
/// (the one fd that survives the re-exec on purpose; issue #10).
fn fds_to_close(scan: Vec<RawFd>, keep: &[RawFd]) -> Vec<RawFd> {
    scan.into_iter().filter(|fd| !keep.contains(fd)).collect()
}

/// Issue #10 (E10): empty the calling thread's signal mask. `__init` is
/// single-threaded, so this is the process mask. The return value is ignored on
/// purpose: SIG_SETMASK with a valid empty set and a NULL old-set pointer cannot
/// fail (EINVAL is only for a bad `how`), and there is no caller to report to.
fn reset_signal_mask() {
    // SAFETY: an empty sigset_t is initialised with sigemptyset before use;
    // SIG_SETMASK with a NULL old-set pointer is always valid.
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        let _ = libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }
}

/// m6: `PR_SET_PDEATHSIG = SIGKILL`, so the sandbox chain dies with `run` even if
/// `run` dies before it could tear down. If the parent is already gone (the
/// prctl would have fired for a parent that died earlier), or differs from the
/// expected pid, refuse to continue. Staged as a control error.
fn arm_parent_death(expected_parent: Option<i32>) -> Result<(), InitError> {
    // SAFETY: prctl with plain integer arguments; no pointers.
    if unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(InitError::new(
            Stage::Control,
            format!(
                "cannot arm parent-death signal: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    if let Some(expected) = expected_parent {
        // SAFETY: getppid takes no arguments and cannot fail.
        let actual = unsafe { libc::getppid() };
        if actual != expected {
            return Err(InitError::new(
                Stage::Control,
                format!(
                    "parent process changed before setup (expected pid {expected}, found {actual})"
                ),
            ));
        }
    }
    Ok(())
}

/// Pure collector for [`fd_hygiene`] (unit-testable without closing
/// anything): the sorted, deduped open fds above stdio (> 2), or `None`
/// when `/proc/self/fd` is unreadable (the documented degrade path).
fn scan_fds_above_stdio() -> Option<Vec<RawFd>> {
    let dir = std::fs::read_dir("/proc/self/fd").ok()?;
    let mut fds: Vec<RawFd> = dir
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str()?.parse::<RawFd>().ok())
        .filter(|fd| *fd > 2)
        .collect();
    // `dir` (and its dirfd) drops HERE — before the caller closes anything
    // (R17: collect-then-drop-then-close).
    fds.sort_unstable();
    fds.dedup();
    Some(fds)
}

/// `execvp` the payload argv (PATH search; an absolute argv[0] bypasses it
/// — parity with `std::process::Command`, and #6 emits an absolute bwrap
/// path anyway, R16). Returns ONLY on failure; on success this process
/// image is gone.
///
/// Errno staging: ENOENT ⇒ "cannot exec {argv0:?}: not found", EACCES ⇒
/// "…: permission denied", other ⇒ "…: {io::Error}". An interior NUL in an
/// argument is kernel-forbidden (hence unreachable from real argv — the
/// kernel's argv strings are NUL-terminated by construction) and maps to a
/// staged error instead of a panic (N4).
///
/// Runtime-state hygiene across the exec seam (module docs point 6):
/// `SIGPIPE` is restored to `SIG_DFL` immediately before the `execvp` —
/// std's startup `SIG_IGN` would otherwise survive `execve` (and bwrap:
/// upstream `bubblewrap.c` restores only `SIGCHLD`) and break the payload's
/// `cmd | head`-style pipe semantics — and set back to `SIG_IGN` on the
/// failure return, keeping [`run_init`]'s staged `eprintln` EPIPE-safe.
/// The integration suite's `sigpipe-default` scenario pins the restore
/// end-to-end with a non-Rust payload.
fn exec_payload(cmd: &[OsString]) -> InitError {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(argv0) = cmd.first() else {
        return InitError::new(Stage::Exec, "no payload command given");
    };
    let c_argv: Vec<CString> = match cmd
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            return InitError::new(
                Stage::Exec,
                format!("cannot exec {argv0:?}: a payload argument contains an interior NUL byte"),
            );
        }
    };
    let ptrs: Vec<*const libc::c_char> = c_argv
        .iter()
        .map(|s| s.as_ptr())
        .chain([std::ptr::null()])
        .collect();
    // The environment is inherited VERBATIM (execvp semantics — no envp
    // parameter): #6 owns env hygiene (bwrap `--clearenv` + explicit
    // `--setenv` for HTTP(S)_PROXY etc.). bwrap passes the environment
    // through by default, so anything in `run`'s env would otherwise reach
    // the untrusted payload.
    //
    // SIGPIPE hygiene (module docs point 6): std ignores SIGPIPE at
    // startup, ignored dispositions survive execve, and bwrap does not
    // reset them — restore the default RIGHT before the exec so the
    // payload gets normal `cmd | head`-style pipe semantics. Ordering is
    // safe: every EPIPE-detecting send of this process is done by here
    // (send_listener_fds ran before wait-go, and both sends are
    // MSG_NOSIGNAL anyway).
    //
    // SAFETY: signal() sets one disposition (SIGPIPE) to a constant
    // handler (SIG_DFL); the child is single-threaded and installs no
    // handlers of its own, so there is nothing to race.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // SAFETY: execvp with a NULL-terminated argv of valid C strings built
    // above; ptrs and c_argv outlive the call (it only returns on error).
    unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };
    let err = std::io::Error::last_os_error();
    // The exec failed — re-ignore SIGPIPE before returning: run_init's
    // staged eprintln onto a dead stderr pipe must not SIGPIPE-kill the
    // diagnostics (rc-1 contract, module docs point 4).
    //
    // SAFETY: as above — one disposition, constant handler,
    // single-threaded.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    InitError::new(
        Stage::Exec,
        match err.raw_os_error() {
            Some(libc::ENOENT) => format!("cannot exec {argv0:?}: not found"),
            Some(libc::EACCES) => format!("cannot exec {argv0:?}: permission denied"),
            _ => format!("cannot exec {argv0:?}: {err}"),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn args(fd: RawFd, keep_fd: Option<RawFd>, parent_pid: Option<i32>) -> InitArgs {
        InitArgs {
            fd,
            keep_fd,
            seccomp_fd: None,
            parent_pid,
            min_mode: NetworkMode::Transparent,
            test_break_rules: false,
            cmd: vec![OsString::from("/bin/true")],
        }
    }

    /// Every stage, in pipeline order. Kept next to the pinned-name match so
    /// adding a variant without extending both fails the suite.
    fn all_stages() -> [Stage; 12] {
        ALL_STAGES
    }

    #[test]
    fn stage_names_pinned() {
        // Exhaustive match returning the 11 exact literals: a new variant
        // fails to compile this test, so the user-visible stage vocabulary
        // can never drift silently.
        for stage in all_stages() {
            let expected = match stage {
                Stage::Control => "control",
                Stage::Unshare => "unshare",
                Stage::Idmap => "idmap",
                Stage::Netns => "netns",
                Stage::Ipv6 => "ipv6",
                Stage::Listeners => "listeners",
                Stage::NftLoad => "nft-load",
                Stage::NftVerify => "nft-verify",
                Stage::Fallback => "fallback",
                Stage::SendFds => "send-fds",
                Stage::WaitGo => "wait-go",
                Stage::Exec => "exec",
            };
            assert_eq!(stage.as_str(), expected);
        }
    }

    #[test]
    fn stage_codes_pinned() {
        for (i, stage) in all_stages().into_iter().enumerate() {
            assert_eq!(stage.code() as usize, i + 1, "{stage:?}");
            assert_eq!(Stage::from_code(stage.code()), Some(stage));
        }
        assert_eq!(Stage::from_code(0), None);
        assert_eq!(Stage::from_code(13), None);
    }

    #[test]
    fn reports_to_parent_table() {
        for stage in all_stages() {
            let want = !matches!(
                stage,
                Stage::Control | Stage::SendFds | Stage::WaitGo | Stage::Exec
            );
            assert_eq!(stage.reports_to_parent(), want, "{stage:?}");
        }
    }

    #[test]
    fn init_error_errno_builder() {
        let err = InitError::new(Stage::Unshare, "unshare failed").with_errno(Some(28));
        assert_eq!(err.errno(), Some(28));
        assert_eq!(err.to_string(), "sbx __init: unshare: unshare failed");
        assert_eq!(InitError::new(Stage::Unshare, "x").errno(), None);
    }

    #[test]
    fn fallback_allowed_table() {
        assert!(!fallback_allowed(NetworkMode::Transparent));
        assert!(fallback_allowed(NetworkMode::Explicit));
        assert!(fallback_allowed(NetworkMode::None));
    }

    #[test]
    fn init_error_display_single_site() {
        // For EVERY stage the rendering is exactly
        // `sbx __init: <stage>: <reason>` — pins both the format and the
        // single-Display-site rule (module docs point 4).
        for stage in all_stages() {
            let err = InitError::new(stage, "boom");
            assert_eq!(
                err.to_string(),
                format!("sbx __init: {}: boom", stage.as_str()),
                "stage {:?}",
                stage
            );
            assert_eq!(err.stage(), stage);
            assert_eq!(err.reason(), "boom");
        }
        // The reason accepts any Into<String>.
        let owned = InitError::new(Stage::Exec, String::from("owned reason"));
        assert_eq!(owned.reason(), "owned reason");
    }

    // ---- pipeline helpers (commit 5) ---------------------------------------

    #[test]
    fn panic_message_extracts_str_string_and_fallback() {
        // The catch_unwind backstop's payload rendering: the common
        // panic!("literal") and panic!(String) cases keep their text;
        // anything else gets the fixed fallback (never a second panic).
        let p: Box<dyn Any + Send> = Box::new("static str");
        assert_eq!(panic_message(&p), "static str");
        let p: Box<dyn Any + Send> = Box::new(String::from("owned string"));
        assert_eq!(panic_message(&p), "owned string");
        let p: Box<dyn Any + Send> = Box::new(42u32);
        assert_eq!(panic_message(&p), "non-string panic payload");
    }

    #[test]
    fn validate_control_fd_rejects_bad_fd() {
        // fd 999 is (probe-verified) not open in a test process: EBADF with
        // the pinned reason. Safe in test threads — a plain syscall, no
        // namespaces involved.
        let err = validate_control_fd(999).expect_err("fd 999 must be rejected");
        assert_eq!(err.stage(), Stage::Control);
        assert!(err.reason().contains("EBADF"), "{err}");
        assert!(err.reason().contains("--fd 999"), "{err}");
    }

    #[test]
    fn validate_control_fd_rejects_non_socket() {
        // /dev/null is a valid fd but not a socket: ENOTSOCK (this is the
        // integration suite's fail-nonsocket-fd scenario, in-process).
        let file = std::fs::File::open("/dev/null").expect("/dev/null must open");
        let err = validate_control_fd(file.as_raw_fd()).expect_err("a file is not a socket");
        assert_eq!(err.stage(), Stage::Control);
        assert!(err.reason().contains("not a socket"), "{err}");
        assert!(err.reason().contains("ENOTSOCK"), "{err}");
    }

    #[test]
    fn validate_control_fd_rejects_stream_socketpair() {
        // D1 pin: a SOCK_STREAM unix socketpair (what UnixStream::pair()
        // would give #10 by mistake) is a valid AF_UNIX socket but NOT the
        // control transport — rejected at the control stage instead of
        // misbehaving on message boundaries later.
        let mut sv = [0 as libc::c_int; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair: {}", std::io::Error::last_os_error());
        // OwnedFd guards: close both ends on every exit path.
        let _a = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let _b = unsafe { OwnedFd::from_raw_fd(sv[1]) };
        let err = validate_control_fd(sv[0]).expect_err("SOCK_STREAM must be rejected");
        assert_eq!(err.stage(), Stage::Control);
        assert!(err.reason().contains("SOCK_SEQPACKET"), "{err}");
    }

    #[test]
    fn validate_control_fd_accepts_control_socketpair() {
        // The production transport passes: both ends of the SEQPACKET pair.
        let (a, b) = fdpass::control_socketpair().expect("socketpair must succeed");
        validate_control_fd(a.as_raw_fd()).expect("parent end must validate");
        validate_control_fd(b.as_raw_fd()).expect("child end must validate");
    }

    #[test]
    fn scan_fds_above_stdio_finds_open_files() {
        // The PURE collector: finds open fds above stdio, sorted + deduped,
        // and closes nothing itself (the closing loop + exec path is proven
        // end-to-end by the integration suite's check-net `fds=0,1,2`
        // marker instead — D13: in-process closing tests are thread-hostile
        // under parallel cargo test).
        let f1 = std::fs::File::open("/dev/null").expect("open 1");
        let f2 = std::fs::File::open("/dev/null").expect("open 2");
        let scan = scan_fds_above_stdio().expect("/proc/self/fd must be readable on Linux");
        assert!(scan.contains(&f1.as_raw_fd()), "{scan:?}");
        assert!(scan.contains(&f2.as_raw_fd()), "{scan:?}");
        assert!(scan.iter().all(|fd| *fd > 2), "never lists stdio: {scan:?}");
        assert!(
            scan.windows(2).all(|w| w[0] < w[1]),
            "sorted + deduped: {scan:?}"
        );
        // The scan itself closed nothing: both files are still open and a
        // second scan still sees them.
        let again = scan_fds_above_stdio().expect("second scan");
        assert!(again.contains(&f1.as_raw_fd()) && again.contains(&f2.as_raw_fd()));
        drop((f1, f2));
    }

    #[test]
    fn arm_parent_death_checks_the_parent_pid() {
        // m6: the expected parent must be the actual one; a pid that cannot be our
        // parent is refused with the pinned message.
        // SAFETY: getppid takes no arguments and cannot fail.
        let actual = unsafe { libc::getppid() };
        arm_parent_death(Some(actual)).expect("the real parent is accepted");
        let err = arm_parent_death(Some(i32::MAX))
            .expect_err("a wrong parent pid must be refused")
            .to_string();
        assert!(
            err.starts_with("sbx __init: control: parent process changed before setup"),
            "{err}"
        );
    }

    #[test]
    fn validate_keep_fd_table() {
        // Pinned reasons (issue #10 §4.2); each rejection is staged Control.
        let msg = |k: RawFd, c: RawFd| validate_keep_fd(k, c).expect_err("must reject").to_string();
        let c = 999; // control fd: never equal to the keep fds under test
        assert_eq!(
            msg(2, c),
            "sbx __init: control: --keep-fd 2 must be greater than 2"
        );
        assert_eq!(
            msg(c, c),
            "sbx __init: control: --keep-fd 999 must differ from --fd"
        );
        assert_eq!(
            msg(998, c),
            "sbx __init: control: --keep-fd 998 is not a valid file descriptor (EBADF)"
        );
        // A regular file is open but not a pipe.
        let file = std::fs::File::open("/proc/self/status").expect("open");
        use std::os::fd::AsRawFd;
        let raw = file.as_raw_fd();
        assert_eq!(
            msg(raw, c),
            format!("sbx __init: control: --keep-fd {raw} is not a pipe")
        );
        // A read-only pipe end is a pipe but not writable.
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        assert_eq!(
            msg(rd, c),
            format!("sbx __init: control: --keep-fd {rd} is not open for writing")
        );
        assert!(validate_keep_fd(wr, c).is_ok());
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
    }

    #[test]
    fn fds_to_close_skips_keep() {
        assert_eq!(fds_to_close(vec![3, 5, 9], &[5]), vec![3, 9]);
        assert_eq!(fds_to_close(vec![3, 5], &[]), vec![3, 5]);
        assert_eq!(fds_to_close(vec![5], &[7]), vec![5]);
    }

    /// A memfd holding `bytes`, sealed (write/grow/shrink) or not, rewound.
    fn memfd_with(bytes: &[u8], seal: bool) -> OwnedFd {
        // SAFETY: memfd_create with a valid NUL-terminated name; the fd is ours.
        let raw = unsafe {
            libc::memfd_create(
                c"sbx-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(raw >= 0, "memfd_create failed");
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: write from a valid buffer to a fd we own.
        let n = unsafe { libc::write(raw, bytes.as_ptr().cast(), bytes.len()) };
        assert_eq!(usize::try_from(n).unwrap(), bytes.len());
        if seal {
            // SAFETY: F_ADD_SEALS on our memfd.
            let rc = unsafe {
                libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK,
                )
            };
            assert_eq!(rc, 0);
        }
        // SAFETY: lseek on our memfd.
        unsafe { libc::lseek(raw, 0, libc::SEEK_SET) };
        fd
    }

    #[test]
    fn validate_seccomp_fd_table() {
        // No program on this architecture: nothing to validate against.
        let Some(good) = crate::bwrap::seccomp::native_program_bytes() else {
            return;
        };
        let msg = |s: RawFd, c: RawFd, k: Option<RawFd>| {
            validate_seccomp_fd(s, c, k)
                .expect_err("must reject")
                .to_string()
        };
        assert_eq!(
            msg(2, 999, None),
            "sbx __init: control: --seccomp-fd 2 must be greater than 2"
        );
        assert_eq!(
            msg(7, 7, None),
            "sbx __init: control: --seccomp-fd 7 must differ from --fd"
        );
        assert_eq!(
            msg(7, 999, Some(7)),
            "sbx __init: control: --seccomp-fd 7 must differ from --keep-fd"
        );
        assert_eq!(
            msg(998, 999, None),
            "sbx __init: control: --seccomp-fd 998 is not a valid file descriptor (EBADF)"
        );

        let sealed_good = memfd_with(&good, true);
        let raw = sealed_good.as_raw_fd();
        assert!(validate_seccomp_fd(raw, 999, None).is_ok());
        // Rewound after validation: the offset is 0 for bwrap.
        // SAFETY: lseek SEEK_CUR reads the offset without moving it.
        assert_eq!(unsafe { libc::lseek(raw, 0, libc::SEEK_CUR) }, 0);

        // A pipe is not a memfd.
        let mut p = [0 as RawFd; 2];
        // SAFETY: pipe2 into a 2-element array.
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (pr, pw) = (p[0], p[1]);
        assert_eq!(
            msg(pw, 999, None),
            format!("sbx __init: control: --seccomp-fd {pw} is not a sealed memfd")
        );
        // SAFETY: closing the pipe ends we just created.
        unsafe {
            libc::close(pr);
            libc::close(pw);
        }

        let unsealed = memfd_with(&good, false);
        assert_eq!(
            msg(unsealed.as_raw_fd(), 999, None),
            format!(
                "sbx __init: control: --seccomp-fd {} is not a sealed memfd",
                unsealed.as_raw_fd()
            )
        );

        let wrong = memfd_with(&[0u8; 8], true);
        assert_eq!(
            msg(wrong.as_raw_fd(), 999, None),
            format!(
                "sbx __init: control: --seccomp-fd {} does not hold sbx's seccomp program",
                wrong.as_raw_fd()
            )
        );

        // A prefix of the right program is not the right program.
        let short = memfd_with(&good[..good.len() - 8], true);
        assert!(validate_seccomp_fd(short.as_raw_fd(), 999, None).is_err());
    }

    #[test]
    fn fds_to_close_keeps_both_info_and_seccomp() {
        // Issue #34: the info pipe and the seccomp memfd both survive hygiene;
        // everything else in the scan is closed.
        assert_eq!(fds_to_close(vec![3, 5, 9, 12], &[5, 9]), vec![3, 12]);
        assert_eq!(fds_to_close(vec![4, 5], &[5, 9]), vec![4]);
    }

    #[test]
    fn keep_set_is_info_and_seccomp() {
        // The production helper itself (pipeline() calls it), not a copy.
        let mut both = args(7, Some(5), None);
        both.seccomp_fd = Some(9);
        assert_eq!(keep_set(&both), vec![5, 9]);
        let mut seccomp_only = args(7, None, None);
        seccomp_only.seccomp_fd = Some(9);
        assert_eq!(keep_set(&seccomp_only), vec![9]);
        assert!(keep_set(&args(7, None, None)).is_empty());
    }

    #[test]
    fn pipeline_bad_keep_fd_stages_control() {
        // The control fd is validated first; a bad control fd with a keep fd
        // present still stages Control, before any namespace work.
        let err = pipeline(&args(999, Some(2), None)).expect_err("bad control fd must abort first");
        assert_eq!(err.stage(), Stage::Control);
    }

    #[test]
    fn pipeline_bad_control_fd_stages_error() {
        // The pipeline's first act is control-fd validation, BEFORE unshare
        // — so this is safe in a test thread and pins the stage attribution.
        let err = pipeline(&args(999, None, None)).expect_err("fd 999 must abort the pipeline");
        assert_eq!(err.stage(), Stage::Control);
        assert!(err.to_string().starts_with("sbx __init: control:"), "{err}");
    }

    #[test]
    fn run_init_bad_control_fd_returns_not_panics() {
        // The CLI seam smoke: run_init returns an ExitCode instead of
        // panicking (ExitCode is opaque on stable — the rc VALUE is pinned
        // at the two real seams: the integration suite and the CI smoke
        // script, R18). Writes one staged line to stderr; that is the
        // production behavior on failure. The m3 panic-hook silencing is
        // NOT pinned in-process: capturing stderr would need a fd-2 dup2,
        // which is thread-hostile under parallel cargo test (the D13
        // rationale) — the hook swap is restore-on-return by construction,
        // and the staged-prefix shape is pinned by the integration suite's
        // fail-* scenarios and the CI smoke's `sbx __init: control:` grep.
        let _code = run_init(args(999, None, None));
    }
}
