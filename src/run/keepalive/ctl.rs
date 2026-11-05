//! The control socket `<session>/sbx.ctl` (issue #18, design point 6).
//!
//! 1. **Directory first, by fd.** The session directory is opened with
//!    `O_DIRECTORY|O_NOFOLLOW` and must be a directory owned by the caller with
//!    no group or other permissions. Every later step names the socket relative
//!    to that fd (`fstatat` with `AT_SYMLINK_NOFOLLOW`), so a symlink swapped in
//!    for the directory or for `sbx.ctl` is never followed for the check.
//! 2. **Bind and connect through `/proc/self/fd`.** `bind(2)` and `connect(2)`
//!    take a path, so they name `/proc/self/fd/<dir>/sbx.ctl`. The magic link
//!    resolves to the directory already verified in rule 1, which keeps the
//!    path under `sun_path`'s 108 bytes whatever the session directory's own
//!    length is.
//! 3. **Only our own socket is replaced.** A leftover `sbx.ctl` is unlinked
//!    only when it is a socket owned by the caller (a holder that was SIGKILLed
//!    leaves one behind; the session lock proves no live holder owns it). Any
//!    other entry, including a symlink to a socket, is refused.
//! 4. **Mode 0600 and the peer check.** The socket is `0600`. On every accepted
//!    connection [`peer_is_same_uid`] compares `SO_PEERCRED`'s uid with the
//!    holder's euid; a mismatch is refused by the caller.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

/// The control socket's file name inside the session directory.
pub(crate) const CTL_NAME: &str = "sbx.ctl";

fn io_last() -> io::Error {
    io::Error::last_os_error()
}

fn cname() -> CString {
    CString::new(CTL_NAME).expect("no interior NUL in the socket name")
}

/// `fstatat(dir, sbx.ctl, AT_SYMLINK_NOFOLLOW)`. `Ok(None)` when the name does
/// not exist.
fn stat_ctl(dir: BorrowedFd<'_>) -> io::Result<Option<libc::stat>> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let name = cname();
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(Some(st));
    }
    let err = io_last();
    if err.kind() == io::ErrorKind::NotFound {
        return Ok(None);
    }
    Err(err)
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// The `/proc/self/fd` path of `sbx.ctl` inside the verified directory (rule 2).
fn proc_path(dir: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}/{CTL_NAME}", dir.as_raw_fd())
}

/// Opens a session directory for the control socket (rule 1): a real directory
/// (not a symlink), owned by the caller, with no group or other permission bits.
pub(crate) fn open_session_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in session path"))?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(io_last());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io_last());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session path is not a directory",
        ));
    }
    if st.st_uid != euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "session directory is not owned by the current user",
        ));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "session directory is group- or world-accessible",
        ));
    }
    Ok(owned)
}

/// Binds `sbx.ctl` in the verified directory `dir` (rules 2, 3 and 4).
pub(crate) fn bind_ctl(dir: BorrowedFd<'_>) -> io::Result<UnixListener> {
    if let Some(st) = stat_ctl(dir)? {
        let ours_socket = st.st_mode & libc::S_IFMT == libc::S_IFSOCK && st.st_uid == euid();
        if !ours_socket {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "sbx.ctl exists and is not a stale control socket of this user",
            ));
        }
        let name = cname();
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io_last());
        }
    }
    let path = proc_path(dir);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Connects to `sbx.ctl` in the verified directory `dir`. The entry must be a
/// socket owned by the caller with no group or other permission bits, checked
/// without following links.
pub(crate) fn connect_ctl(dir: BorrowedFd<'_>) -> io::Result<UnixStream> {
    match stat_ctl(dir)? {
        None => Err(io::Error::new(io::ErrorKind::NotFound, "no control socket")),
        Some(st) => {
            if st.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || st.st_uid != euid()
                || st.st_mode & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sbx.ctl is not a private control socket of this user",
                ));
            }
            UnixStream::connect(proc_path(dir))
        }
    }
}

/// The most descriptors one frame may carry (the attach request sends one;
/// the attach reply sends three).
pub(crate) const MAX_FDS: usize = 4;

/// The budget of one blocking client call (send or receive a whole frame).
pub(crate) const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Waits until `fd` is ready for `events`, or `deadline` passes (a
/// `TimedOut` error). Hang-up also counts as ready: the next syscall reports it.
fn wait_fd(fd: RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control deadline passed",
            ));
        }
        let ms = (deadline - now).as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one pollfd, a live pointer to it, and a bounded timeout.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let err = io_last();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc > 0 {
            return Ok(());
        }
    }
}

/// Reads exactly `buf.len()` bytes before `deadline` (one budget for the whole
/// read: a peer that trickles bytes cannot extend it).
fn read_until(fd: RawFd, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        wait_fd(fd, libc::POLLIN, deadline)?;
        // SAFETY: the pointer and length name the unfilled tail of `buf`.
        let n = unsafe {
            libc::recv(
                fd,
                buf[pos..].as_mut_ptr().cast(),
                buf.len() - pos,
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io_last();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                _ => return Err(err),
            }
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed mid-frame",
            ));
        }
        pos += n as usize;
    }
    Ok(())
}

/// Sends one frame before `deadline`. `fds` travel with the first bytes of the
/// header (SCM_RIGHTS). `MSG_NOSIGNAL`: a vanished peer is an error, never SIGPIPE.
pub(crate) fn send_frame_until(
    stream: &UnixStream,
    op: u8,
    payload: &[u8],
    fds: &[RawFd],
    deadline: Instant,
) -> Result<(), super::proto::ProtoError> {
    use super::proto::{MAX_FRAME, ProtoError};
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge(payload.len()));
    }
    if fds.len() > MAX_FDS {
        return Err(ProtoError::Malformed("too many descriptors for one frame"));
    }
    let fd = stream.as_raw_fd();
    let mut total = Vec::with_capacity(5 + payload.len());
    total.push(op);
    total.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    total.extend_from_slice(payload);
    let fd_bytes = std::mem::size_of_val(fds);
    // u64 storage keeps the control block aligned for struct cmsghdr.
    let mut control = [0u64; 8];
    let mut sent = 0usize;
    let mut fds_pending = !fds.is_empty();
    while sent < total.len() {
        wait_fd(fd, libc::POLLOUT, deadline)?;
        let mut iov = libc::iovec {
            iov_base: total[sent..].as_ptr() as *mut libc::c_void,
            iov_len: total.len() - sent,
        };
        // SAFETY: zeroed msghdr is a valid starting state; fields are set below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if fds_pending {
            let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control block is large enough for one cmsghdr with `fds`.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    fd_bytes,
                );
            }
        }
        let rc = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if rc < 0 {
            let err = io_last();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                _ => return Err(ProtoError::Io(err)),
            }
        }
        sent += rc as usize;
        fds_pending = false;
    }
    Ok(())
}

/// Sends one frame within the default client budget.
pub(crate) fn send_frame(
    stream: &UnixStream,
    op: u8,
    payload: &[u8],
    fds: &[RawFd],
) -> Result<(), super::proto::ProtoError> {
    send_frame_until(stream, op, payload, fds, Instant::now() + CLIENT_TIMEOUT)
}

/// Receives one frame and the descriptors that came with its header, all before
/// `deadline`. The descriptors are close-on-exec (`MSG_CMSG_CLOEXEC`) and owned by
/// the caller. A frame with `MSG_CTRUNC` fails closed.
pub(crate) fn recv_frame_until(
    stream: &UnixStream,
    deadline: Instant,
) -> Result<(super::proto::Frame, Vec<std::os::fd::OwnedFd>), super::proto::ProtoError> {
    use super::proto::{Frame, MAX_FRAME, ProtoError};
    use std::os::fd::FromRawFd;
    let fd = stream.as_raw_fd();
    let mut header = [0u8; 5];
    let mut got = 0usize;
    // Descriptors are collected from every header read, so they are owned (and
    // closed on any error path) as soon as they arrive.
    let mut fds: Vec<std::os::fd::OwnedFd> = Vec::new();
    while got < header.len() {
        wait_fd(fd, libc::POLLIN, deadline)?;
        let mut control = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: header[got..].as_mut_ptr().cast(),
            iov_len: header.len() - got,
        };
        // SAFETY: zeroed msghdr is a valid starting state; fields are set below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let rc =
            unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT) };
        if rc < 0 {
            let err = io_last();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => continue,
                _ => return Err(ProtoError::Io(err)),
            }
        }
        // SAFETY: walks the cmsgs the kernel just wrote into `control`.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let count = data_len / std::mem::size_of::<RawFd>();
                    let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                    for i in 0..count {
                        fds.push(std::os::fd::OwnedFd::from_raw_fd(*data.add(i)));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(ProtoError::Malformed("control data truncated"));
        }
        if rc == 0 {
            if got == 0 {
                return Err(ProtoError::Eof);
            }
            return Err(ProtoError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed mid-header",
            )));
        }
        got += rc as usize;
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    read_until(fd, &mut payload, deadline)?;
    Ok((
        Frame {
            op: header[0],
            payload,
        },
        fds,
    ))
}

/// Receives one frame within the default client budget.
pub(crate) fn recv_frame(
    stream: &UnixStream,
) -> Result<(super::proto::Frame, Vec<std::os::fd::OwnedFd>), super::proto::ProtoError> {
    recv_frame_until(stream, Instant::now() + CLIENT_TIMEOUT)
}

/// The pid and uid of the peer (`SO_PEERCRED`).
pub(crate) fn peer_creds(stream: &UnixStream) -> io::Result<(libc::pid_t, u32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io_last());
    }
    Ok((cred.pid, cred.uid))
}

/// Removes `sbx.ctl` at the end of a session. Only a socket owned by this user
/// is removed; a missing or foreign entry is left alone.
pub(crate) fn unlink_ctl(dir: BorrowedFd<'_>) {
    if let Ok(Some(st)) = stat_ctl(dir) {
        if st.st_mode & libc::S_IFMT == libc::S_IFSOCK && st.st_uid == euid() {
            let name = cname();
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::path::PathBuf;

    fn session(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sbx-keepalive-ctl-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("mkdir");
        dir
    }

    #[test]
    fn bind_and_connect_round_trip_with_mode_0600() {
        let dir = session("bind");
        let fd = open_session_dir(&dir).expect("open");
        let listener = bind_ctl(fd.as_fd()).expect("bind");
        let mode = std::fs::metadata(dir.join(CTL_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let client = connect_ctl(fd.as_fd()).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        assert_eq!(
            peer_creds(&server).unwrap().1,
            euid(),
            "the peer is this user"
        );
        assert_eq!(peer_creds(&client).unwrap().1, euid());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bind_refuses_a_regular_file_in_the_way() {
        let dir = session("regular");
        std::fs::write(dir.join(CTL_NAME), b"not a socket").unwrap();
        let fd = open_session_dir(&dir).unwrap();
        let err = bind_ctl(fd.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(dir.join(CTL_NAME)).unwrap(), b"not a socket");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bind_refuses_a_symlink_and_never_follows_it() {
        let dir = session("symlink");
        let elsewhere = session("elsewhere");
        symlink(elsewhere.join("target"), dir.join(CTL_NAME)).unwrap();
        let fd = open_session_dir(&dir).unwrap();
        let err = bind_ctl(fd.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            !elsewhere.join("target").exists(),
            "the link target was not created"
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(elsewhere);
    }

    #[test]
    fn bind_replaces_a_stale_socket_of_this_user() {
        let dir = session("stale");
        let fd = open_session_dir(&dir).unwrap();
        let first = bind_ctl(fd.as_fd()).unwrap();
        drop(first); // the socket file stays behind, as after a SIGKILL
        assert!(dir.join(CTL_NAME).exists());
        let _second = bind_ctl(fd.as_fd()).expect("stale socket is replaced");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_refuses_a_symlink_to_a_live_socket() {
        let dir = session("connect-link");
        let fd = open_session_dir(&dir).unwrap();
        let _listener = {
            let real = session("connect-real");
            let rfd = open_session_dir(&real).unwrap();
            let l = bind_ctl(rfd.as_fd()).unwrap();
            symlink(real.join(CTL_NAME), dir.join(CTL_NAME)).unwrap();
            let _ = std::fs::remove_dir_all(real);
            l
        };
        let err = connect_ctl(fd.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connect_reports_a_missing_socket() {
        let dir = session("missing");
        let fd = open_session_dir(&dir).unwrap();
        assert_eq!(
            connect_ctl(fd.as_fd()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_session_dir_refuses_symlinks_and_group_readable_dirs() {
        let dir = session("open");
        let link = dir.with_extension("link");
        let _ = std::fs::remove_file(&link);
        symlink(&dir, &link).unwrap();
        assert!(
            open_session_dir(&link).is_err(),
            "a symlinked session dir is refused"
        );
        let _ = std::fs::remove_file(&link);

        let wide = session("wide");
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = open_session_dir(&wide).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(wide);
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn descriptors_travel_with_the_header_and_work_on_the_far_side() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = crate::run::sys::pipe_cloexec().unwrap();
        send_frame(&a, b'A', b"policy", &[w.as_raw_fd()]).unwrap();
        drop(w); // only the received copy keeps the pipe open
        let (frame, fds) = recv_frame(&b).unwrap();
        assert_eq!(frame.op, b'A');
        assert_eq!(frame.payload, b"policy");
        assert_eq!(fds.len(), 1);
        let mut far = std::fs::File::from(fds.into_iter().next().unwrap());
        far.write_all(b"via-scm").unwrap();
        drop(far);
        // `pipe_cloexec` makes the read end non-blocking; a test reader wants blocking reads.
        unsafe {
            let flags = libc::fcntl(r.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(r.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
        let mut got = String::new();
        std::fs::File::from(r).read_to_string(&mut got).unwrap();
        assert_eq!(got, "via-scm");
    }

    #[test]
    fn recv_reports_eof_when_the_peer_closes_before_a_header() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(matches!(
            recv_frame(&b),
            Err(super::super::proto::ProtoError::Eof)
        ));
    }

    #[test]
    fn peer_creds_names_this_process_and_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let (pid, uid) = peer_creds(&a).unwrap();
        assert_eq!(pid, std::process::id() as libc::pid_t);
        assert_eq!(uid, euid());
    }

    #[test]
    fn a_trickling_peer_is_cut_off_at_the_frame_deadline() {
        // The header declares 1000 bytes; the peer sends one byte every 50 ms.
        // A per-read timeout would never fire; the frame deadline must.
        use super::super::proto::ProtoError;
        use std::io::Write;
        let (mut a, b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let mut header = vec![b'A'];
            header.extend_from_slice(&1000u32.to_be_bytes());
            let _ = a.write_all(&header);
            for _ in 0..200 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if a.write_all(&[0]).is_err() {
                    break;
                }
            }
        });
        let started = Instant::now();
        let result = recv_frame_until(&b, started + Duration::from_millis(300));
        let elapsed = started.elapsed();
        assert!(
            matches!(&result, Err(ProtoError::Io(e)) if e.kind() == io::ErrorKind::TimedOut),
            "expected a deadline error, got {:?}",
            result.as_ref().err()
        );
        assert!(elapsed < Duration::from_millis(1500), "took {elapsed:?}");
        drop(b);
        let _ = writer.join();
    }

    #[test]
    fn a_silent_peer_is_cut_off_at_the_deadline() {
        use super::super::proto::ProtoError;
        let (_a, b) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let result = recv_frame_until(&b, started + Duration::from_millis(100));
        assert!(matches!(result, Err(ProtoError::Io(e)) if e.kind() == io::ErrorKind::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
