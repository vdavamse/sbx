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
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

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

/// Whether the peer of `stream` runs as the same effective uid (`SO_PEERCRED`).
pub(crate) fn peer_is_same_uid(stream: &UnixStream) -> io::Result<bool> {
    // `UnixStream::peer_cred` is not stable on every supported toolchain, so
    // the same `SO_PEERCRED` read is made directly.
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
    Ok(cred.uid == euid())
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
        assert!(peer_is_same_uid(&server).unwrap(), "the peer is this user");
        assert!(peer_is_same_uid(&client).unwrap());
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
}
