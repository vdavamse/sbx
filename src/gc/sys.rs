//! libc and raw-syscall wrappers for `sbx gc` (issue #12). Every `unsafe`
//! block documents its SAFETY argument. This is the only `unsafe` surface of
//! `gc`: `walk.rs` and `mod.rs` are pure logic over these wrappers, mirroring
//! `run/sys.rs`. Everything here is Linux-specific (statx, renameat2, /proc).

use std::collections::hash_map::RandomState;
use std::ffi::{CStr, CString};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `struct statx_timestamp`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct StatxTimestamp {
    _tv_sec: i64,
    _tv_nsec: u32,
    _reserved: i32,
}

/// `struct statx` (256 bytes). Declared by hand because libc's struct is
/// gnu-only; the layout is asserted below. Only the fields `gc` reads are
/// named, the rest are padding.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Statx {
    pub(crate) mask: u32,
    _blksize: u32,
    pub(crate) attributes: u64,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    _gid: u32,
    pub(crate) mode: u16,
    _spare0: u16,
    pub(crate) ino: u64,
    _size: u64,
    _blocks: u64,
    pub(crate) attributes_mask: u64,
    _times: [StatxTimestamp; 4],
    _rdev_major: u32,
    _rdev_minor: u32,
    pub(crate) dev_major: u32,
    pub(crate) dev_minor: u32,
    pub(crate) mnt_id: u64,
    _spare: [u64; 13],
}

const _: () = assert!(std::mem::size_of::<Statx>() == 256);
const _: () = assert!(std::mem::size_of::<StatxTimestamp>() == 16);

/// `STATX_TYPE | MODE | NLINK | UID | INO`: what `gc` asks for.
const STATX_BASIC: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x100;
/// Linux 5.8: `mnt_id` is valid.
pub(crate) const STATX_MNT_ID: u32 = 0x1000;
/// Linux 5.8: the inode is the root of a mount (`attributes` bit).
pub(crate) const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;

impl Statx {
    pub(crate) fn dev(&self) -> u64 {
        libc::makedev(self.dev_major, self.dev_minor)
    }
}

/// The mount a directory sits on: its `mnt_id` when the kernel reports it
/// (Linux >= 5.8), otherwise its `st_dev` (Q6). A same-filesystem bind mount
/// has the same `st_dev`, so the fallback cannot see it; see the README
/// residual for kernels < 5.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountId {
    mnt_id: Option<u64>,
    dev: u64,
}

impl MountId {
    pub(crate) fn of(fd: BorrowedFd<'_>) -> io::Result<Self> {
        Ok(Self::from_statx(&statx_fd(fd)?))
    }

    pub(crate) fn from_statx(x: &Statx) -> Self {
        Self {
            mnt_id: (x.mask & STATX_MNT_ID != 0).then_some(x.mnt_id),
            dev: x.dev(),
        }
    }

    /// True iff `x` (a child's statx, or a session's) sits on this mount and
    /// is not itself a mount root. A mount root is a mount point, so it is
    /// never "on" the parent's mount.
    pub(crate) fn contains(&self, x: &Statx) -> bool {
        if x.attributes_mask & STATX_ATTR_MOUNT_ROOT != 0
            && x.attributes & STATX_ATTR_MOUNT_ROOT != 0
        {
            return false;
        }
        match (self.mnt_id, x.mask & STATX_MNT_ID != 0) {
            (Some(id), true) => x.mnt_id == id,
            _ => x.dev() == self.dev,
        }
    }
}

fn statx_raw(dirfd: RawFd, path: &CStr, flags: libc::c_int) -> io::Result<Statx> {
    let mut buf = MaybeUninit::<Statx>::zeroed();
    // SAFETY: SYS_statx(dirfd, path, flags, mask, buf) writes at most 256
    // bytes into `buf`, which is a 256-byte zeroed struct we own; `path` is
    // NUL-terminated and outlives the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::c_long::from(dirfd),
            path.as_ptr(),
            libc::c_long::from(flags),
            libc::c_long::from(STATX_BASIC | STATX_MNT_ID),
            buf.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel fully initialized `buf` on success (and it started
    // zeroed in any case); every field is plain integers.
    Ok(unsafe { buf.assume_init() })
}

/// `statx(fd, "", AT_EMPTY_PATH|AT_NO_AUTOMOUNT|AT_SYMLINK_NOFOLLOW)`. Works
/// on O_PATH fds. On kernels without `STATX_MNT_ID` (< 5.8) the mount id is
/// filled in from `name_to_handle_at`, which reports the same id space as
/// `/proc/self/mountinfo` (Linux 2.6.39+), so the mount checks still see a
/// same-filesystem bind mount.
pub(crate) fn statx_fd(fd: BorrowedFd<'_>) -> io::Result<Statx> {
    let mut x = statx_raw(
        fd.as_raw_fd(),
        c"",
        libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW,
    )?;
    if x.mask & STATX_MNT_ID == 0 {
        x.mnt_id = mount_id_via_handle(fd)?;
        x.mask |= STATX_MNT_ID;
    }
    Ok(x)
}

/// The mount id of an open fd, via `name_to_handle_at(fd, "", AT_EMPTY_PATH)`.
fn mount_id_via_handle(fd: BorrowedFd<'_>) -> io::Result<u64> {
    /// A `struct file_handle` with room for the largest handle the kernel
    /// returns (`MAX_HANDLE_SZ` = 128).
    #[repr(C)]
    struct HandleBuf {
        handle_bytes: u32,
        handle_type: i32,
        data: [u8; 128],
    }
    let mut buf = HandleBuf {
        handle_bytes: 128,
        handle_type: 0,
        data: [0; 128],
    };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: `buf` is a file_handle-shaped struct whose handle_bytes says 128
    // bytes of storage, and `mount_id` is a live c_int; both outlive the call.
    // AT_EMPTY_PATH with "" names the fd itself.
    let rc = unsafe {
        libc::name_to_handle_at(
            fd.as_raw_fd(),
            c"".as_ptr(),
            (&mut buf as *mut HandleBuf).cast(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(mount_id).map_err(|_| io::Error::other("negative mount id"))
}

fn open_raw(dirfd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: openat(dirfd, name, flags, mode) with a NUL-terminated name;
    // `dirfd` is a valid fd or AT_FDCWD; mode is unused without O_CREAT.
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOCTTY,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor returned by openat and nothing else
    // owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open `name` relative to `dir`. Every caller passes `O_NOFOLLOW`.
pub(crate) fn openat(dir: BorrowedFd<'_>, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    open_raw(dir.as_raw_fd(), name, flags)
}

/// Open an absolute or cwd-relative path (only ROOT uses this).
pub(crate) fn open_path(path: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    open_raw(libc::AT_FDCWD, path, flags)
}

pub(crate) fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: fstat writes one `struct stat` into `st`, which we own.
    let rc = unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded, so the struct is fully initialized.
    Ok(unsafe { st.assume_init() })
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT)`: never follows
/// a symlink, never triggers an automount.
pub(crate) fn fstatat_nofollow(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<libc::stat> {
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `name` is NUL-terminated; fstatat writes one `struct stat`
    // into `st`, which we own.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded, so the struct is fully initialized.
    Ok(unsafe { st.assume_init() })
}

/// `unlinkat(dir, name, 0 | AT_REMOVEDIR)`. A non-directory is unlinked, never
/// followed; a symlink is removed as itself.
pub(crate) fn unlinkat(dir: BorrowedFd<'_>, name: &CStr, remove_dir: bool) -> io::Result<()> {
    let flags = if remove_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `name` is NUL-terminated; unlinkat takes no pointers beyond it.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat2(from_dir, from, to_dir, to, RENAME_NOREPLACE)`. Raw syscall: no
/// libc wrapper is needed on glibc or musl. Linux >= 3.15.
pub(crate) fn renameat2_noreplace(
    from_dir: BorrowedFd<'_>,
    from: &CStr,
    to_dir: BorrowedFd<'_>,
    to: &CStr,
) -> io::Result<()> {
    const RENAME_NOREPLACE: libc::c_long = 1;
    // SAFETY: SYS_renameat2 takes two dirfds, two NUL-terminated paths and a
    // flags word; all pointers are valid for the duration of the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::c_long::from(from_dir.as_raw_fd()),
            from.as_ptr(),
            libc::c_long::from(to_dir.as_raw_fd()),
            to.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `flock(LOCK_EX|LOCK_NB)`: `Ok(true)` locked, `Ok(false)` held elsewhere.
pub(crate) fn flock_ex_nb(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: flock on a descriptor we borrow; no pointers.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(err)
    }
}

/// `fchmod` on a directory fd (Q7: only directories are ever chmod'ed).
pub(crate) fn fchmod(fd: BorrowedFd<'_>, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: fchmod on a descriptor we borrow; no pointers.
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `chmod("/proc/self/fd/N")`: changes the inode behind an O_PATH fd, which
/// `fchmod` refuses. The magic link is followed by design.
pub(crate) fn chmod_proc_fd(fd: BorrowedFd<'_>, mode: libc::mode_t) -> io::Result<()> {
    let path = proc_fd_path(fd);
    // SAFETY: `path` is NUL-terminated and outlives the call.
    if unsafe { libc::chmod(path.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reopen the directory behind an O_PATH fd via `/proc/self/fd/N`. The magic
/// link is a symlink, so O_NOFOLLOW must NOT be passed (the probe got ENOTDIR).
/// The caller verifies dev/ino against the O_PATH fd.
pub(crate) fn reopen_proc_fd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let path = proc_fd_path(fd);
    open_raw(
        libc::AT_FDCWD,
        &path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
    )
}

fn proc_fd_path(fd: BorrowedFd<'_>) -> CString {
    CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("no NUL in a /proc path")
}

/// `getrlimit(RLIMIT_NOFILE).rlim_cur`; `RLIM_INFINITY` maps to `u64::MAX`.
pub(crate) fn rlimit_nofile_soft() -> u64 {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one `struct rlimit` into `r`, which we own.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } != 0 {
        // Unknown limit: assume the most conservative common default.
        return 1024;
    }
    // rlim_t is u64 on every Linux target this crate builds for; RLIM_INFINITY
    // is already u64::MAX there.
    r.rlim_cur
}

/// The effective uid (ownership checks compare against it).
pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// 64 random bits without `unsafe`: std seeds `RandomState` from the OS
/// (getrandom), and each `RandomState::new()` gets fresh keys.
pub(crate) fn nonce() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// `st_mtime` + `st_mtime_nsec` as a `SystemTime`, pre-epoch handled.
pub(crate) fn mtime(st: &libc::stat) -> SystemTime {
    let secs = st.st_mtime;
    let nsec: i64 = st.st_mtime_nsec;
    let nanos = Duration::from_nanos(u64::try_from(nsec).unwrap_or(0));
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(secs.unsigned_abs()))
            .and_then(|t| t.checked_add(nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))
            .and_then(|t| t.checked_add(nanos))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// An owning `readdir` stream. `new` takes the fd (`fdopendir` owns it on
/// success); drop is `closedir`.
pub(crate) struct DirStream(NonNull<libc::DIR>);

impl DirStream {
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        // SAFETY: fdopendir takes ownership of `raw` on success. On failure
        // the fd is left open and `fd` drops it below.
        let dir = unsafe { libc::fdopendir(raw) };
        match NonNull::new(dir) {
            Some(dir) => {
                // Release our OwnedFd only now: the DIR is the single owner.
                let _ = fd.into_raw_fd();
                Ok(Self(dir))
            }
            None => Err(io::Error::last_os_error()),
        }
    }

    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        // SAFETY: dirfd on a live DIR returns its descriptor, which the DIR
        // keeps open for as long as `self` lives.
        unsafe { BorrowedFd::borrow_raw(libc::dirfd(self.0.as_ptr())) }
    }

    /// The next entry name, skipping `.` and `..`. `errno` is zeroed before
    /// each `readdir`, so a NULL return with errno 0 is end of stream.
    pub(crate) fn next_name(&mut self) -> io::Result<Option<CString>> {
        loop {
            // SAFETY: __errno_location returns this thread's errno slot.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: `self.0` is a live DIR we own.
            let ent = unsafe { libc::readdir(self.0.as_ptr()) };
            if ent.is_null() {
                let err = io::Error::last_os_error();
                return if err.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(err)
                };
            }
            // SAFETY: readdir returned a non-null dirent; its d_name is
            // NUL-terminated. We copy it out before the next readdir.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            if name == c"." || name == c".." {
                continue;
            }
            return Ok(Some(name.to_owned()));
        }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: we own the DIR; closedir runs exactly once, here.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}

/// `fstatat(AT_FDCWD, path, ...)` for the ROOT checks: `follow` selects
/// `stat` (true) or `lstat` (false).
pub(crate) fn stat_path(path: &CStr, follow: bool) -> io::Result<libc::stat> {
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let mut st = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `path` is NUL-terminated; fstatat writes one `struct stat` into
    // `st`, which we own.
    let rc = unsafe { libc::fstatat(libc::AT_FDCWD, path.as_ptr(), st.as_mut_ptr(), flags) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded, so the struct is fully initialized.
    Ok(unsafe { st.assume_init() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn handle_mount_id_matches_statx_and_separates_mounts() {
        let dir = std::fs::File::open(std::env::temp_dir()).expect("open tmp");
        let st = statx_raw(dir.as_raw_fd(), c"", libc::AT_EMPTY_PATH).expect("statx");
        if st.mask & STATX_MNT_ID != 0 {
            assert_eq!(mount_id_via_handle(dir.as_fd()).expect("handle"), st.mnt_id);
        }
    }
}
