//! Session directory and its exclusive lock (issue #10, T3, Q10).
//!
//! The lock is a `flock(LOCK_EX|LOCK_NB)` on `<session>/sbx.lock` held by the
//! open file description; the kernel releases it at process exit, and the fd is
//! CLOEXEC so the payload never inherits it. The directory mtime is touched at
//! the start and the end of a run — the activity signal #12's `gc` reads.
//! After locking, `verify_bound` re-checks that the lock and the directory are
//! still the ones `sbx gc` would see (#12 T6): `gc` tombstones a locked, expired
//! session by rename and unlinks its lock later.

use std::ffi::CString;
use std::fs::{DirBuilder, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::{LOCK_FILE, RunError};

pub(crate) struct SessionLock {
    dir: OwnedFd,
    _lock: OwnedFd,
}

impl SessionLock {
    /// Create (0700), verify and lock the session directory. Runs BEFORE
    /// `materialize` so a losing concurrent run never rewrites the winner's
    /// live `/etc` files.
    pub(crate) fn acquire(path: &Path) -> Result<Self, RunError> {
        // #12: a directory named like a `sbx gc` tombstone would be taken for
        // one by a concurrent gc (it renames sessions to that shape). Refused.
        if let Some(base) = path.file_name() {
            if crate::gc::is_tombstone_name(base.as_encoded_bytes()) {
                return Err(RunError::new(format!(
                    "session directory {path:?} has a name reserved for `sbx gc` tombstones"
                )));
            }
        }
        crate::bwrap::etc::check_session_dir(path).map_err(RunError::new)?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|err| {
                RunError::new(format!("cannot create session directory {path:?}: {err}"))
            })?;
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|err| {
                RunError::new(format!("cannot open session directory {path:?}: {err}"))
            })?;
        let meta = dir_file.metadata().map_err(|err| {
            RunError::new(format!("cannot stat session directory {path:?}: {err}"))
        })?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !meta.is_dir() || meta.uid() != euid {
            return Err(RunError::new(format!(
                "session directory {path:?} is not a directory owned by the current user"
            )));
        }
        // m7: fail closed on a directory anyone else can write into (group/other
        // write bits), instead of silently trusting or re-permissioning it.
        if meta.mode() & 0o022 != 0 {
            return Err(RunError::new(format!(
                "session directory {path:?} is group- or world-writable (mode {:o}); use 0700",
                meta.mode() & 0o777
            )));
        }
        let dir = OwnedFd::from(dir_file);

        let name = std::ffi::CString::new(LOCK_FILE).expect("constant has no NUL");
        // SAFETY: `dir` is a valid directory fd we own; `name` is NUL-terminated;
        // the returned fd (if >= 0) is freshly created and owned by us.
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if raw < 0 {
            return Err(RunError::new(format!(
                "cannot open {LOCK_FILE} in session directory {path:?}: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: `raw` is a fresh fd returned by openat above.
        let lock = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: flock on a valid fd we own; non-blocking so contention is an error.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = io::Error::last_os_error();
            return Err(if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                RunError::new(format!("session directory is in use: {path:?}"))
            } else {
                RunError::new(format!("cannot lock session directory {path:?}: {err}"))
            });
        }
        verify_bound(path, &dir, &lock)?;
        let this = Self { dir, _lock: lock };
        this.touch().map_err(|err| {
            RunError::new(format!("cannot update session directory {path:?}: {err}"))
        })?;
        Ok(this)
    }

    /// `futimens(dir, NULL)`: mtime and atime become "now" (#12 activity signal).
    pub(crate) fn touch(&self) -> io::Result<()> {
        // SAFETY: futimens with a NULL times pointer sets both to the current
        // time; `dir` is a valid fd we own.
        if unsafe { libc::futimens(self.dir.as_raw_fd(), std::ptr::null()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    fn mtime(&self) -> io::Result<std::time::SystemTime> {
        std::fs::File::from(self.dir.try_clone()?)
            .metadata()?
            .modified()
    }
}

/// #12 T6: `sbx gc` renames a locked, expired session to a tombstone and
/// later unlinks its sbx.lock. A run that opened the directory before that
/// rename can then create and flock a fresh lock in the tombstone (or flock
/// the unlinked old one). After locking, the lock must still be linked, still
/// be the directory's `sbx.lock`, and the directory must still sit at `path`.
fn verify_bound(path: &Path, dir: &OwnedFd, lock: &OwnedFd) -> Result<(), RunError> {
    let replaced = || {
        RunError::new(format!(
            "session directory {path:?} was removed or replaced while it was being locked (concurrent sbx gc?)"
        ))
    };
    let stat_err =
        |err: io::Error| RunError::new(format!("cannot stat session directory {path:?}: {err}"));
    let lock_st = fstat_fd(lock.as_fd()).map_err(stat_err)?;
    if lock_st.st_nlink == 0 {
        return Err(replaced());
    }
    let name = CString::new(LOCK_FILE).expect("constant has no NUL");
    let named = match fstatat_lock(dir.as_fd(), &name) {
        Ok(st) => st,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(replaced()),
        Err(err) => return Err(stat_err(err)),
    };
    if (named.st_dev, named.st_ino) != (lock_st.st_dev, lock_st.st_ino) {
        return Err(replaced());
    }
    let dir_st = fstat_fd(dir.as_fd()).map_err(stat_err)?;
    let at_path = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err(replaced()),
        Err(err) => return Err(stat_err(err)),
    };
    if (at_path.dev(), at_path.ino()) != (dir_st.st_dev, dir_st.st_ino) {
        return Err(replaced());
    }
    Ok(())
}

fn fstat_fd(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: fstat writes one `struct stat` into `st`, which we own.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded, so the struct is fully initialized.
    Ok(unsafe { st.assume_init() })
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`: relative to the directory fd, so
/// a renamed directory is detected rather than followed by path.
fn fstatat_lock(dir: BorrowedFd<'_>, name: &CString) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `name` is NUL-terminated; fstatat writes into `st`, which we own.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded, so the struct is fully initialized.
    Ok(unsafe { st.assume_init() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "sbx-run-session-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
    }

    #[test]
    fn acquire_creates_0700_dir_and_lock() {
        let dir = unique_dir("create");
        let lock = SessionLock::acquire(&dir).expect("acquire");
        let meta = std::fs::metadata(&dir).expect("dir exists");
        assert!(meta.is_dir());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        let lock_meta = std::fs::metadata(dir.join(LOCK_FILE)).expect("lock exists");
        assert_eq!(lock_meta.permissions().mode() & 0o777, 0o600);
        drop(lock);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn acquire_rejects_group_or_world_writable_dir() {
        // m7: an existing session directory with group/other write bits is refused.
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("wide");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let err = SessionLock::acquire(&dir)
            .err()
            .expect("wide mode must be refused");
        assert!(
            err.reason().contains("group- or world-writable"),
            "{}",
            err.reason()
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        SessionLock::acquire(&dir).expect("0700 accepted");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn second_acquire_is_in_use() {
        let dir = unique_dir("inuse");
        let first = SessionLock::acquire(&dir).expect("first acquire");
        let err = SessionLock::acquire(&dir)
            .err()
            .expect("second acquire must fail");
        assert_eq!(
            err.reason(),
            format!("session directory is in use: {dir:?}")
        );
        drop(first);
        // Released with the open file description.
        SessionLock::acquire(&dir).expect("re-acquire after release");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn acquire_rejects_symlinked_session_dir() {
        let real = unique_dir("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        let link = unique_dir("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = SessionLock::acquire(&link)
            .err()
            .expect("symlink must be rejected");
        assert!(
            err.reason().contains("session directory"),
            "{}",
            err.reason()
        );
        std::fs::remove_file(&link).ok();
        std::fs::remove_dir_all(&real).ok();
    }

    #[test]
    fn acquire_rejects_root_alias() {
        let err = SessionLock::acquire(Path::new("/"))
            .err()
            .expect("root must be rejected");
        assert!(err.reason().contains("host root"), "{}", err.reason());
    }

    #[test]
    fn touch_updates_mtime() {
        let dir = unique_dir("touch");
        let lock = SessionLock::acquire(&dir).expect("acquire");
        // Push the mtime into the past, then touch.
        let past = UNIX_EPOCH + std::time::Duration::from_secs(1);
        let times = [
            libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
        ];
        let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).expect("cstr");
        // SAFETY: valid NUL-terminated path and a two-element timespec array.
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) },
            0
        );
        assert_eq!(lock.mtime().expect("mtime"), past);
        lock.touch().expect("touch");
        let now = SystemTime::now();
        let got = lock.mtime().expect("mtime");
        assert!(got > past, "touch must move mtime forward");
        assert!(now.duration_since(got).unwrap_or_default().as_secs() < 60);
        drop(lock);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Open the directory and its lock the way `acquire` does, without
    /// locking, so a test can move the directory under them.
    fn open_pair(path: &Path) -> (OwnedFd, OwnedFd) {
        let dir = OwnedFd::from(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .expect("open dir"),
        );
        let lock = OwnedFd::from(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path.join(LOCK_FILE))
                .expect("open lock"),
        );
        (dir, lock)
    }

    fn pinned(path: &Path) -> String {
        format!(
            "session directory {path:?} was removed or replaced while it was being locked (concurrent sbx gc?)"
        )
    }

    #[test]
    fn verify_bound_ok_for_fresh_acquire() {
        let dir = unique_dir("bound-ok");
        let lock = SessionLock::acquire(&dir).expect("acquire");
        let (d, l) = open_pair(&dir);
        verify_bound(&dir, &d, &l).expect("an intact pair is bound");
        drop(lock);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_bound_detects_renamed_dir() {
        let dir = unique_dir("bound-rename");
        SessionLock::acquire(&dir).map(drop).expect("acquire");
        let (d, l) = open_pair(&dir);
        let moved = dir.with_extension("tomb");
        std::fs::rename(&dir, &moved).expect("rename");
        let err = verify_bound(&dir, &d, &l).expect_err("renamed dir");
        assert_eq!(err.reason(), pinned(&dir));
        std::fs::remove_dir_all(&moved).ok();
    }

    #[test]
    fn verify_bound_detects_unlinked_lock() {
        let dir = unique_dir("bound-unlink");
        SessionLock::acquire(&dir).map(drop).expect("acquire");
        let (d, l) = open_pair(&dir);
        std::fs::remove_file(dir.join(LOCK_FILE)).expect("unlink lock");
        let err = verify_bound(&dir, &d, &l).expect_err("unlinked lock");
        assert_eq!(err.reason(), pinned(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_bound_detects_replaced_lock() {
        let dir = unique_dir("bound-replace");
        SessionLock::acquire(&dir).map(drop).expect("acquire");
        let (d, l) = open_pair(&dir);
        std::fs::remove_file(dir.join(LOCK_FILE)).expect("unlink lock");
        std::fs::write(dir.join(LOCK_FILE), b"").expect("new lock");
        let err = verify_bound(&dir, &d, &l).expect_err("replaced lock");
        assert_eq!(err.reason(), pinned(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn acquire_after_tombstone_creates_fresh_session() {
        let dir = unique_dir("bound-fresh");
        SessionLock::acquire(&dir).map(drop).expect("acquire");
        let moved = dir.with_extension("tomb");
        std::fs::rename(&dir, &moved).expect("rename away");
        SessionLock::acquire(&dir).expect("a fresh session at the old path");
        assert!(dir.join(LOCK_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&moved).ok();
    }

    #[test]
    fn acquire_refuses_tombstone_shaped_name() {
        // m4: `sbx gc` tombstones are `.sbx-gc.<pid>.<nonce>`; a session with
        // that name would be mistaken for one.
        let dir = std::env::temp_dir()
            .join(format!("sbx-run-session-{}-tomb", std::process::id()))
            .join(".sbx-gc.42.0123456789abcdef");
        let err = SessionLock::acquire(&dir)
            .err()
            .expect("tombstone-shaped name must be refused");
        assert_eq!(
            err.reason(),
            format!("session directory {dir:?} has a name reserved for `sbx gc` tombstones")
        );
        assert!(!dir.exists(), "refused before anything is created");
    }
}
