//! libc wrappers for `sbx run` (issue #10, T4/T7). Every `unsafe` block
//! documents its SAFETY argument. Linux >= 5.3 (pidfd).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

/// `pidfd_open(2)`: a pollable handle to `pid` that becomes readable on exit.
/// The caller must not have reaped `pid` yet (its number cannot be recycled
/// before then).
pub(crate) fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: SYS_pidfd_open takes (pid, flags) by value; no pointers.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pidfd_open unavailable (Linux >= 5.3 required)",
            ));
        }
        return Err(err);
    }
    // SAFETY: a non-negative return is a fresh fd owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

/// SIGKILL through a pidfd (no pid-reuse race). ESRCH (already gone) is Ok.
pub(crate) fn pidfd_kill(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: SYS_pidfd_send_signal(pidfd, sig, siginfo=NULL, flags=0).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err);
        }
    }
    Ok(())
}

/// A non-blocking, close-on-exec eventfd (counter 0).
pub(crate) fn eventfd() -> io::Result<OwnedFd> {
    // SAFETY: eventfd takes plain integers.
    let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd from eventfd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Makes an eventfd readable. Errors are ignored: the only failure mode is a
/// full counter, which is already "signalled".
pub(crate) fn eventfd_signal(fd: BorrowedFd<'_>) {
    let one: u64 = 1;
    // SAFETY: writes 8 bytes from a live local to an fd we borrow.
    unsafe {
        libc::write(
            fd.as_raw_fd(),
            (&one as *const u64).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
        );
    }
}

/// `pipe2(O_CLOEXEC)`. The read end is set non-blocking (the supervisor polls
/// it); the write end stays blocking for the child.
pub(crate) fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two fds into the array we pass.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both fds are fresh and owned by us from here on.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    set_nonblocking(read.as_raw_fd())?;
    Ok((read, write))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Clears FD_CLOEXEC — used only inside the spawn window (R6).
pub(crate) fn clear_cloexec(fd: BorrowedFd<'_>) -> io::Result<RawFd> {
    // SAFETY: F_SETFD on a valid fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd.as_raw_fd())
}

/// Whether `sig`'s disposition is SIG_IGN (inherited from the caller).
fn is_ignored(sig: i32) -> bool {
    // SAFETY: sigaction with a NULL new action only reads the disposition.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, std::ptr::null(), &mut old) != 0 {
            return false;
        }
        old.sa_sigaction == libc::SIG_IGN
    }
}

/// The signals `run` watches, minus those the caller left ignored (Q5).
pub(crate) fn select_signals(ignored: impl Fn(i32) -> bool) -> Vec<i32> {
    [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT]
        .into_iter()
        .filter(|sig| !ignored(*sig))
        .collect()
}

/// The blocked-and-collected signal set (signalfd, no handlers).
pub(crate) struct Signals {
    fd: OwnedFd,
}

impl Signals {
    /// MUST run before any thread exists: threads inherit the mask.
    pub(crate) fn install() -> io::Result<Self> {
        let set = select_signals(is_ignored);
        // SAFETY: sigset_t initialised by sigemptyset before use.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut mask) };
        for sig in &set {
            // SAFETY: sigaddset on the local, initialised mask.
            unsafe { libc::sigaddset(&mut mask, *sig) };
        }
        // SAFETY: the mask is a valid sigset_t; the old-mask pointer may be NULL.
        // pthread_sigmask reports its error as the RETURN value (an errno), not errno.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        // SAFETY: signalfd(-1, &mask, flags) creates a new fd.
        let raw = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh fd from signalfd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd })
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The signal number of one pending signalfd record, if any.
    pub(crate) fn read(&self) -> Option<i32> {
        // SAFETY: signalfd_siginfo is 128 bytes; we read exactly one record.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&mut info as *mut libc::signalfd_siginfo).cast::<libc::c_void>(),
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if n == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
            Some(info.ssi_signo as i32)
        } else {
            None
        }
    }
}

/// SIGCHLD back to SIG_DFL: `Child::wait` needs it not ignored (S1).
pub(crate) fn reset_sigchld() {
    // SAFETY: signal(2) with SIG_DFL has no pointer arguments.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
    }
}

/// Milliseconds until `deadline` for poll(2), rounded UP so a sub-millisecond
/// wait never busy-spins; `None` ⇒ -1 (wait forever); clamped to i32::MAX.
pub(crate) fn poll_timeout_ms(now: Instant, deadline: Option<Instant>) -> libc::c_int {
    let Some(deadline) = deadline else { return -1 };
    let remaining = deadline.saturating_duration_since(now);
    let ms = remaining.as_nanos().div_ceil(1_000_000);
    ms.min(i32::MAX as u128) as libc::c_int
}

/// poll(2) with EINTR retried and the deadline recomputed on every retry.
/// Returns the number of ready entries (0 on deadline).
pub(crate) fn poll_fds(fds: &mut [libc::pollfd], deadline: Option<Instant>) -> io::Result<usize> {
    loop {
        let timeout = poll_timeout_ms(Instant::now(), deadline);
        // SAFETY: `fds` is a valid slice of pollfd for the duration of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// A `pollfd` for `fd` waiting for `events`.
pub(crate) fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

/// True when the poll result says the fd is readable or hung up / errored
/// (a hang-up is "readable" for every caller here: EOF or exit).
pub(crate) fn ready(revents: libc::c_short) -> bool {
    revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
}

/// Waits up to `timeout` for `fd` to become readable.
pub(crate) fn wait_readable(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
    let mut fds = [pollfd(fd.as_raw_fd(), libc::POLLIN)];
    let deadline = Instant::now() + timeout;
    let n = poll_fds(&mut fds, Some(deadline))?;
    Ok(n > 0 && ready(fds[0].revents))
}

/// `(isatty(0), sbx is the foreground process group of fd 0's terminal)`.
pub(crate) fn stdin_tty_foreground() -> (bool, bool) {
    // SAFETY: isatty / tcgetpgrp / getpgrp take plain fds and return integers.
    unsafe {
        let tty = libc::isatty(0) == 1;
        if !tty {
            return (false, false);
        }
        (true, libc::tcgetpgrp(0) == libc::getpgrp())
    }
}

/// `getifaddrs(3)`: the host's own IPv4/IPv6 interface addresses, for the
/// egress guard's host-address deny set (issue #41). Called in the PARENT,
/// i.e. the host network namespace the proxy dials from.
///
/// Interfaces flagged `IFF_LOOPBACK` are skipped: their usual addresses
/// (127/8, ::1) are already denied by the guard's tables, and the
/// conformance lab binds its public fixture address to `lo` inside its own
/// namespace. A public address configured on `lo` (a DSR/anycast VIP) is
/// therefore not covered — threat-model R12 records it.
pub(crate) fn host_interface_addrs() -> io::Result<Vec<std::net::IpAddr>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Owns the getifaddrs list: freed exactly once on every exit path,
    // including a panic between the call and the end of the walk.
    struct List(*mut libc::ifaddrs);
    impl Drop for List {
        fn drop(&mut self) {
            // SAFETY: self.0 came from a successful getifaddrs and is freed
            // only here; no reference into the list outlives the List.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a freshly allocated list head into `head`.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = List(head);
    let mut out = Vec::new();
    let mut cur = list.0;
    while !cur.is_null() {
        // SAFETY: `cur` is a non-null node of the list `list` owns, which
        // is still alive.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0 {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points to a sockaddr; unaligned
        // reads avoid relying on the allocator's alignment.
        let family = unsafe { std::ptr::read_unaligned(ifa.ifa_addr) }.sa_family;
        match i32::from(family) {
            libc::AF_INET => {
                // SAFETY: AF_INET ⇒ the storage is a sockaddr_in.
                let sin =
                    unsafe { std::ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in) };
                out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))));
            }
            libc::AF_INET6 => {
                // SAFETY: AF_INET6 ⇒ the storage is a sockaddr_in6.
                let sin6 =
                    unsafe { std::ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in6) };
                out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn poll_timeout_ms_rounding() {
        let now = Instant::now();
        assert_eq!(poll_timeout_ms(now, None), -1);
        assert_eq!(poll_timeout_ms(now, Some(now)), 0);
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_micros(1))),
            1
        ); // ceil
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_millis(5))),
            5
        );
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_micros(5_001))),
            6
        );
        assert_eq!(
            poll_timeout_ms(now, Some(now + Duration::from_secs(3_000_000))),
            i32::MAX
        );
    }

    #[test]
    fn select_signals_skips_ignored() {
        assert_eq!(
            select_signals(|_| false),
            vec![libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT]
        );
        assert_eq!(
            select_signals(|s| s == libc::SIGINT),
            vec![libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT]
        );
        assert!(select_signals(|_| true).is_empty());
    }

    #[test]
    fn eventfd_roundtrip() {
        let efd = eventfd().expect("eventfd");
        // Not readable before a signal.
        assert!(!wait_readable(efd.as_fd(), Duration::ZERO).expect("poll"));
        eventfd_signal(efd.as_fd());
        assert!(wait_readable(efd.as_fd(), Duration::from_secs(1)).expect("poll"));
    }

    #[test]
    fn pidfd_open_child_becomes_readable() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn");
        let pidfd = pidfd_open(child.id() as libc::pid_t).expect("pidfd");
        assert!(wait_readable(pidfd.as_fd(), Duration::from_secs(10)).expect("poll"));
        child.wait().expect("reap");
    }

    #[test]
    fn pidfd_kill_esrch_is_ok() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn");
        let pidfd = pidfd_open(child.id() as libc::pid_t).expect("pidfd");
        child.wait().expect("reap");
        // The process is gone: SIGKILL through its pidfd reports ESRCH, which is Ok.
        pidfd_kill(pidfd.as_fd()).expect("ESRCH must be Ok");
    }

    #[test]
    fn host_interface_addrs_lists_no_loopback() {
        // Smoke test (hermetic on any runner): the call succeeds and no
        // 127/8 or ::1 address — which only a loopback interface carries on
        // a normal host — is reported. The IFF_LOOPBACK skip itself is
        // exercised end to end by the conformance lab, whose 9.9.9.9 fixture
        // on `lo` would otherwise be denied.
        let addrs = host_interface_addrs().expect("getifaddrs");
        assert!(
            addrs.iter().all(|a| !a.is_loopback()),
            "loopback-interface address leaked: {addrs:?}"
        );
    }
}
