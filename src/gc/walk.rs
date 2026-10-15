//! The `sbx gc` walker (issue #12, T5): empties a session directory whose
//! lock is held, without following symlinks, crossing mounts, or touching
//! entries another user owns.
//!
//! The walk is iterative (an explicit stack of open directory streams), so
//! depth costs heap, not call stack. It is also fd-bounded: at most
//! [`fd_budget`] directory fds are open at once. A directory that would exceed
//! the budget is hoisted: it is renamed into the walked top with a
//! `.sbx-gc-hoist.N` name, which lowers its depth. Passes repeat until the
//! tree is empty, and every pass that does not finish either removes an inode
//! or hoists a subtree closer to the top, so the loop terminates (see
//! [`remove_contents_with`]).
//!
//! Unreadable directories (mode without `r`/`x`) are recovered through an
//! O_PATH fd and `chmod("/proc/self/fd/N")`. Only directories are ever
//! chmod'ed (Q7).

use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use super::sys::{self, DirStream, MountId};

/// What the walker is allowed to empty.
pub(crate) struct WalkOpts<'a> {
    /// A name among the top's immediate children that is left alone (the
    /// session's `sbx.lock`, which the caller unlinks itself).
    pub(crate) keep_top: Option<&'a CStr>,
    /// Entries owned by any other uid abort the walk (Q11).
    pub(crate) euid: u32,
}

/// Counters for one [`remove_contents`] call.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct WalkStats {
    pub(crate) removed: u64,
    pub(crate) hoisted: u64,
    pub(crate) passes: u32,
}

/// Why the walk stopped. Paths are relative to the walked top; `"."` is the
/// top itself.
#[derive(Debug)]
pub(crate) enum WalkError {
    /// A mount point (or a bind-mounted file) inside the tree.
    MountPoint(PathBuf),
    /// An entry owned by another uid (Q11).
    Foreign { path: PathBuf, uid: u32 },
    /// A syscall failed on `path`.
    Io {
        op: &'static str,
        path: PathBuf,
        err: io::Error,
    },
    /// Passes stopped making progress: entries reappear or cannot be removed.
    NoProgress { passes: u32 },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MountPoint(rel) => write!(f, "mount point at {rel:?}; not descending"),
            Self::Foreign { path, uid } => {
                write!(f, "{path:?} is owned by uid {uid}, not the current user")
            }
            Self::Io { op, path, err } => write!(f, "cannot {op} {path:?}: {err}"),
            Self::NoProgress { passes } => write!(
                f,
                "could not empty the directory after {passes} passes (entries reappear or cannot be removed)"
            ),
        }
    }
}

/// Hard ceiling on open directory fds in one walk.
pub(crate) const MAX_STACK: usize = 64;
/// fds the process holds besides the walk: stdio, ROOT, the session dir, the
/// lock, and transient O_PATH/reopen/child descriptors.
pub(crate) const RESERVED_FDS: u64 = 16;

/// `clamp(soft - RESERVED_FDS, 2, MAX_STACK)`. 32 -> 16, 1024 -> 64, 10 -> 2
/// (at that point EMFILE surfaces as an [`WalkError::Io`]).
pub(crate) fn fd_budget(soft: u64) -> usize {
    soft.saturating_sub(RESERVED_FDS).clamp(2, MAX_STACK as u64) as usize
}

/// Empty `dir` (keeping `opts.keep_top` if present) using the process's own
/// `RLIMIT_NOFILE` to size the stack.
pub(crate) fn remove_contents(
    dir: BorrowedFd<'_>,
    opts: &WalkOpts<'_>,
) -> Result<WalkStats, WalkError> {
    remove_contents_with(dir, opts, fd_budget(sys::rlimit_nofile_soft()))
}

/// [`remove_contents`] with an explicit stack bound. `max_depth >= 2`: the
/// hoist fires only at stack depth >= 2, so a hoist always moves a subtree
/// strictly closer to the top.
///
/// Termination: a pass that does not finish either removes at least one
/// inode or hoists at least one subtree. A hoist from depth k >= 2 to depth 1
/// lowers every node of that subtree, so the sum of all depths strictly
/// decreases. A concurrent writer of the same uid can keep the loop going;
/// that is reported as [`WalkError::NoProgress`] when a pass makes no
/// progress. The session lock excludes `sbx run`.
pub(crate) fn remove_contents_with(
    dir: BorrowedFd<'_>,
    opts: &WalkOpts<'_>,
    max_depth: usize,
) -> Result<WalkStats, WalkError> {
    assert!(max_depth >= 2, "the hoist fires at stack depth >= 2");
    let top_st = sys::fstat(dir).map_err(|e| io_err("stat", PathBuf::from("."), e))?;
    let mnt = MountId::of(dir).map_err(|e| io_err("stat", PathBuf::from("."), e))?;
    let mut w = Walk {
        top: dir,
        euid: opts.euid,
        keep_top: opts.keep_top.map(CStr::to_owned),
        mnt,
        dev: top_st.st_dev,
        max_depth,
        hoist_seq: 0,
    };
    let mut stats = WalkStats::default();
    loop {
        stats.passes += 1;
        let p = one_pass(&mut w)?;
        stats.removed += p.removed;
        stats.hoisted += p.hoisted;
        if !p.incomplete && p.hoisted == 0 {
            return Ok(stats);
        }
        if p.removed == 0 && p.hoisted == 0 {
            return Err(WalkError::NoProgress {
                passes: stats.passes,
            });
        }
    }
}

struct Walk<'a> {
    top: BorrowedFd<'a>,
    euid: u32,
    keep_top: Option<CString>,
    mnt: MountId,
    dev: u64,
    max_depth: usize,
    hoist_seq: u64,
}

#[derive(Default)]
struct PassStats {
    removed: u64,
    hoisted: u64,
    /// Something was skipped (a vanished or swapped child, a non-empty
    /// rmdir): the next pass has to come back.
    incomplete: bool,
}

fn io_err(op: &'static str, path: PathBuf, err: io::Error) -> WalkError {
    WalkError::Io { op, path, err }
}

/// `names` are the directories between the top and the current stack frame;
/// `last` is the entry being reported. Built from raw bytes so non-UTF-8
/// names print exactly.
fn rel_path(names: &[CString], last: Option<&CStr>) -> PathBuf {
    let mut bytes: Vec<u8> = Vec::new();
    for part in names
        .iter()
        .map(|n| n.as_bytes())
        .chain(last.map(|l| l.to_bytes()))
    {
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(part);
    }
    if bytes.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(OsStr::from_bytes(&bytes))
    }
}

/// One full pass over the top. `stack[0]` is the top itself; `names[i]` is
/// the name of `stack[i + 1]` in its parent.
fn one_pass(w: &mut Walk<'_>) -> Result<PassStats, WalkError> {
    let mut ps = PassStats::default();
    // A fresh descriptor per pass gives each pass its own readdir offset.
    let top_fd = sys::openat(w.top, c".", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|e| io_err("open", PathBuf::from("."), e))?;
    let bottom = DirStream::new(top_fd).map_err(|e| io_err("opendir", PathBuf::from("."), e))?;
    let mut stack = vec![bottom];
    let mut names: Vec<CString> = Vec::new();
    loop {
        let next = stack
            .last_mut()
            .expect("the top frame is never popped")
            .next_name()
            .map_err(|e| io_err("read", rel_path(&names, None), e))?;
        let Some(name) = next else {
            if stack.len() == 1 {
                break;
            }
            // Close the child before rmdir (its fd would pin the inode).
            drop(stack.pop());
            let dname = names.pop().expect("names mirrors the stack");
            let parent = stack.last().expect("the top frame").fd();
            match sys::unlinkat(parent, &dname, true) {
                Ok(()) => ps.removed += 1,
                Err(e) => match e.raw_os_error() {
                    Some(libc::ENOENT) => {}
                    Some(libc::ENOTEMPTY) => ps.incomplete = true,
                    Some(libc::EBUSY) => {
                        return Err(WalkError::MountPoint(rel_path(&names, Some(&dname))));
                    }
                    _ => return Err(io_err("remove", rel_path(&names, Some(&dname)), e)),
                },
            }
            continue;
        };
        if stack.len() == 1 && w.keep_top.as_deref() == Some(name.as_c_str()) {
            continue;
        }
        let tfd = stack.last().expect("the top frame").fd();
        let st = match sys::fstatat_nofollow(tfd, &name) {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => return Err(io_err("stat", rel_path(&names, Some(&name)), e)),
        };
        if st.st_uid != w.euid {
            return Err(WalkError::Foreign {
                path: rel_path(&names, Some(&name)),
                uid: st.st_uid,
            });
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            // Symlinks, files, FIFOs and sockets are unlinked, never followed
            // or chmod'ed (Q7).
            match sys::unlinkat(tfd, &name, false) {
                Ok(()) => ps.removed += 1,
                Err(e) => match e.raw_os_error() {
                    Some(libc::ENOENT) => {}
                    Some(libc::EBUSY) => {
                        return Err(WalkError::MountPoint(rel_path(&names, Some(&name))));
                    }
                    _ => return Err(io_err("remove", rel_path(&names, Some(&name)), e)),
                },
            }
            continue;
        }
        if st.st_dev != w.dev {
            return Err(WalkError::MountPoint(rel_path(&names, Some(&name))));
        }
        let child = match open_child_dir(w, tfd, &name, &names)? {
            Some(fd) => fd,
            None => {
                // Vanished, or swapped to a non-directory: the next pass
                // unlinks it.
                ps.incomplete = true;
                continue;
            }
        };
        if stack.len() >= w.max_depth {
            drop(child);
            if hoist(w, tfd, &name, &names)? {
                ps.hoisted += 1;
            } else {
                ps.incomplete = true;
            }
            continue;
        }
        let frame = DirStream::new(child)
            .map_err(|e| io_err("opendir", rel_path(&names, Some(&name)), e))?;
        stack.push(frame);
        names.push(name);
    }
    Ok(ps)
}

/// Open a child directory for walking (Q6, Q7): O_NOFOLLOW, then the mount
/// and ownership checks, then `0700` if the mode blocks us. `Ok(None)` means
/// the entry is gone or is no longer a directory.
fn open_child_dir(
    w: &Walk<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    names: &[CString],
) -> Result<Option<OwnedFd>, WalkError> {
    let path = || rel_path(names, Some(name));
    let plain = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = match sys::openat(parent, name, plain) {
        Ok(fd) => fd,
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => return Ok(None),
            Some(libc::EACCES) => recover_unreadable(w, parent, name, names)?,
            _ => return Err(io_err("open", path(), e)),
        },
    };
    let x = sys::statx_fd(fd.as_fd()).map_err(|e| io_err("stat", path(), e))?;
    if !w.mnt.contains(&x) {
        return Err(WalkError::MountPoint(path()));
    }
    if x.uid != w.euid {
        return Err(WalkError::Foreign {
            path: path(),
            uid: x.uid,
        });
    }
    if u32::from(x.mode) & 0o700 != 0o700 {
        sys::fchmod(fd.as_fd(), 0o700).map_err(|e| io_err("chmod", path(), e))?;
    }
    Ok(Some(fd))
}

/// The EACCES recovery: open O_PATH (no read permission needed), check the
/// mount and owner, `chmod` through `/proc/self/fd`, then reopen through
/// `/proc/self/fd` (no O_NOFOLLOW there: the magic link is a symlink) and
/// verify that the inode did not change. The caller re-runs the checks on the
/// reopened fd.
fn recover_unreadable(
    w: &Walk<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    names: &[CString],
) -> Result<OwnedFd, WalkError> {
    let path = || rel_path(names, Some(name));
    let p = sys::openat(
        parent,
        name,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
    .map_err(|e| io_err("open", path(), e))?;
    let x = sys::statx_fd(p.as_fd()).map_err(|e| io_err("stat", path(), e))?;
    if !w.mnt.contains(&x) {
        return Err(WalkError::MountPoint(path()));
    }
    if x.uid != w.euid {
        return Err(WalkError::Foreign {
            path: path(),
            uid: x.uid,
        });
    }
    sys::chmod_proc_fd(p.as_fd(), 0o700).map_err(|e| io_err("chmod", path(), e))?;
    let fd = sys::reopen_proc_fd(p.as_fd()).map_err(|e| io_err("reopen", path(), e))?;
    let y = sys::statx_fd(fd.as_fd()).map_err(|e| io_err("stat", path(), e))?;
    if (y.ino, y.dev()) != (x.ino, x.dev()) {
        return Err(io_err("reopen", path(), io::Error::other("inode changed")));
    }
    Ok(fd)
}

/// Move the child `name` (in `parent`) to `top/.sbx-gc-hoist.N`. The child
/// must already be `0700` (its `..` is rewritten by the rename). `Ok(false)`:
/// the child vanished.
fn hoist(
    w: &mut Walk<'_>,
    parent: BorrowedFd<'_>,
    name: &CStr,
    names: &[CString],
) -> Result<bool, WalkError> {
    loop {
        w.hoist_seq += 1;
        let target = CString::new(format!(".sbx-gc-hoist.{}", w.hoist_seq))
            .expect("a formatted name has no NUL");
        match sys::renameat2_noreplace(parent, name, w.top, &target) {
            Ok(()) => return Ok(true),
            Err(e) => match e.raw_os_error() {
                Some(libc::EEXIST) => continue,
                Some(libc::ENOENT) => return Ok(false),
                Some(libc::EBUSY) => {
                    return Err(WalkError::MountPoint(rel_path(names, Some(name))));
                }
                _ => return Err(io_err("move", rel_path(names, Some(name)), e)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory that is made traversable and removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "sbx-gc-walk-{}-{}-{tag}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&p).expect("mkdir scratch");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod scratch");
            Self(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            make_traversable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Give every real directory under `p` (not through symlinks) `0700`, so
    /// the test tree can be removed whatever the walker left behind.
    fn make_traversable(p: &Path) {
        let Ok(md) = fs::symlink_metadata(p) else {
            return;
        };
        if !md.is_dir() {
            return;
        }
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                make_traversable(&e.path());
            }
        }
    }

    fn walk_dir(dir: &Path, keep_top: Option<&CStr>) -> Result<WalkStats, WalkError> {
        let f = fs::File::open(dir).expect("open walk top");
        remove_contents(
            f.as_fd(),
            &WalkOpts {
                keep_top,
                euid: sys::euid(),
            },
        )
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn build_chain(top: &Path, depth: usize) {
        let mut p = top.to_path_buf();
        for _ in 0..depth {
            p.push("d");
            fs::create_dir(&p).expect("mkdir chain");
            fs::write(p.join("f"), b"x").expect("write chain file");
        }
    }

    #[test]
    fn removes_mixed_tree_keeps_top_lock() {
        let s = Scratch::new("mixed");
        let top = s.0.join("top");
        fs::create_dir(&top).expect("mkdir top");
        fs::write(top.join("sbx.lock"), b"").expect("top lock");
        fs::write(top.join("file1"), b"x").expect("file");
        let d1 = top.join("d1");
        fs::create_dir(&d1).expect("d1");
        fs::write(d1.join("file"), b"x").expect("file in d1");
        fs::write(d1.join("sbx.lock"), b"").expect("nested lock");
        symlink("/nonexistent-target", top.join("l")).expect("symlink");
        let fifo = CString::new(top.join("fifo").as_os_str().as_bytes()).expect("cstr");
        // SAFETY: mkfifo with a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        drop(std::os::unix::net::UnixListener::bind(top.join("sock")).expect("bind"));
        let d2 = top.join("d2");
        fs::create_dir_all(d2.join("d3")).expect("d2/d3");
        symlink("/", d2.join("root")).expect("symlink in d2");

        let stats = walk_dir(&top, Some(c"sbx.lock")).expect("walk");
        assert_eq!(names_in(&top), vec!["sbx.lock".to_string()]);
        // file1, d1 (file, nested lock, rmdir), l, fifo, sock, d2 (root
        // symlink, d3 rmdir, rmdir): 10 removals; the top lock is kept.
        assert_eq!(stats.removed, 10);
        assert_eq!(stats.hoisted, 0);
    }

    #[test]
    fn hostile_modes_removed() {
        let s = Scratch::new("modes");
        let top = s.0.join("top");
        let a = top.join("a");
        let b = a.join("b");
        let c = b.join("c");
        let d = c.join("d");
        fs::create_dir_all(&d).expect("tree");
        fs::write(d.join("f"), b"x").expect("file");
        fs::create_dir(top.join("e")).expect("e");
        fs::write(top.join("e").join("g"), b"x").expect("g");
        // Deepest first, so each chmod still has search permission on its path.
        for (dir, mode) in [(&d, 0o500), (&c, 0o300), (&b, 0o100), (&a, 0o000)] {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).expect("chmod");
        }
        fs::set_permissions(top.join("e"), fs::Permissions::from_mode(0o000)).expect("chmod e");
        walk_dir(&top, None).expect("walk hostile modes");
        assert_eq!(names_in(&top), Vec::<String>::new());
    }

    #[test]
    fn symlink_targets_untouched() {
        let s = Scratch::new("symlinks");
        let outside = s.0.join("outside");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("canary"), b"keep").expect("canary");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o750)).expect("mode");
        let top = s.0.join("work");
        fs::create_dir(&top).expect("work");
        symlink(&outside, top.join("l")).expect("l");
        symlink("/", top.join("root")).expect("root link");
        walk_dir(&top, None).expect("walk");
        assert_eq!(names_in(&top), Vec::<String>::new());
        assert_eq!(fs::read(outside.join("canary")).expect("canary"), b"keep");
        let mode = fs::metadata(&outside).expect("outside").mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[test]
    fn hard_link_outside_survives_mode_unchanged() {
        let s = Scratch::new("hardlink");
        let outside = s.0.join("outside-file");
        fs::write(&outside, b"keep").expect("outside file");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o400)).expect("mode");
        let top = s.0.join("work");
        fs::create_dir(&top).expect("work");
        fs::hard_link(&outside, top.join("h")).expect("hard link");
        walk_dir(&top, None).expect("walk");
        assert_eq!(names_in(&top), Vec::<String>::new());
        let md = fs::metadata(&outside).expect("outside survives");
        assert_eq!(md.nlink(), 1);
        assert_eq!(md.mode() & 0o777, 0o400);
    }

    #[test]
    fn deep_chain_hoists_with_small_budget() {
        for depth in [2usize, 3] {
            let s = Scratch::new(&format!("chain{depth}"));
            let top = s.0.join("top");
            fs::create_dir(&top).expect("top");
            fs::write(top.join("sbx.lock"), b"").expect("lock");
            build_chain(&top, 300);
            let f = fs::File::open(&top).expect("open");
            let stats = remove_contents_with(
                f.as_fd(),
                &WalkOpts {
                    keep_top: Some(c"sbx.lock"),
                    euid: sys::euid(),
                },
                depth,
            )
            .expect("walk chain");
            assert!(stats.hoisted > 0, "depth {depth}: {stats:?}");
            assert!(stats.passes > 1, "depth {depth}: {stats:?}");
            assert_eq!(names_in(&top), vec!["sbx.lock".to_string()]);
        }
    }

    #[test]
    fn hoist_name_collision() {
        let s = Scratch::new("collide");
        let top = s.0.join("top");
        fs::create_dir(&top).expect("top");
        for i in 1..=3 {
            fs::write(top.join(format!(".sbx-gc-hoist.{i}")), b"x").expect("collider");
        }
        build_chain(&top, 40);
        let f = fs::File::open(&top).expect("open");
        let stats = remove_contents_with(
            f.as_fd(),
            &WalkOpts {
                keep_top: None,
                euid: sys::euid(),
            },
            2,
        )
        .expect("walk with collisions");
        assert!(stats.hoisted > 0);
        assert_eq!(names_in(&top), Vec::<String>::new());
    }

    #[test]
    fn non_utf8_names_removed() {
        let s = Scratch::new("nonutf8");
        let top = s.0.join("top");
        fs::create_dir(&top).expect("top");
        for name in [&b"\xff\xfe"[..], b"a\nb"] {
            let p = top.join(OsStr::from_bytes(name));
            fs::write(&p, b"x").expect("file");
            let d = top.join(OsStr::from_bytes(&[name, b"-dir"].concat()));
            fs::create_dir(&d).expect("dir");
            fs::write(d.join("inner"), b"x").expect("inner");
        }
        walk_dir(&top, None).expect("walk");
        assert_eq!(names_in(&top), Vec::<String>::new());
    }

    #[test]
    fn foreign_uid_aborts() {
        let s = Scratch::new("foreign");
        let top = s.0.join("top");
        fs::create_dir(&top).expect("top");
        fs::write(top.join("one"), b"x").expect("one");
        fs::write(top.join("two"), b"x").expect("two");
        let f = fs::File::open(&top).expect("open");
        let err = remove_contents(
            f.as_fd(),
            &WalkOpts {
                keep_top: None,
                euid: sys::euid().wrapping_add(1),
            },
        )
        .expect_err("a foreign uid must abort");
        assert!(
            matches!(err, WalkError::Foreign { uid, .. } if uid == sys::euid()),
            "{err:?}"
        );
        // The first entry aborts before anything is removed.
        assert_eq!(names_in(&top).len(), 2);
    }

    #[test]
    fn fd_budget_clamps() {
        assert_eq!(fd_budget(32), 16);
        assert_eq!(fd_budget(1024), 64);
        assert_eq!(fd_budget(10), 2);
        assert_eq!(fd_budget(u64::MAX), 64);
    }

    #[test]
    fn walk_error_display_pinned() {
        assert_eq!(
            WalkError::MountPoint(PathBuf::from("work/b")).to_string(),
            "mount point at \"work/b\"; not descending"
        );
        assert_eq!(
            WalkError::Foreign {
                path: PathBuf::from("x"),
                uid: 4242
            }
            .to_string(),
            "\"x\" is owned by uid 4242, not the current user"
        );
        assert_eq!(
            WalkError::Io {
                op: "open",
                path: PathBuf::from("."),
                err: io::Error::other("boom"),
            }
            .to_string(),
            "cannot open \".\": boom"
        );
        assert_eq!(
            WalkError::NoProgress { passes: 3 }.to_string(),
            "could not empty the directory after 3 passes (entries reappear or cannot be removed)"
        );
    }

    #[test]
    fn rel_path_joins_bytes() {
        let names = vec![CString::new("a").unwrap(), CString::new("b").unwrap()];
        assert_eq!(rel_path(&names, Some(c"c")), PathBuf::from("a/b/c"));
        assert_eq!(rel_path(&[], None), PathBuf::from("."));
    }
}
