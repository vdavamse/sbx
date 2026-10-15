//! `sbx gc` — remove expired session directories (issue #12).
//!
//! A session is an immediate child of ROOT that is a real directory owned by
//! the current user, has no group/other write bit, and holds an `sbx.lock`
//! regular file (Q1: a directory without one is not a session and is never
//! touched). A session is expired when its directory mtime is older than
//! `--older-than` (Q4: read under the lock, so a `run` that just finished or
//! started counts as young; a future mtime is kept).
//!
//! Protocol for one session (design §3.4): stat and open without following
//! anything; take the session's `flock` with `LOCK_NB` (a live run holds it
//! and the session is skipped); re-check that the locked lock is still the
//! directory's `sbx.lock` and the directory is still at its name; check the
//! age and the mount; rename the directory to a tombstone
//! `ROOT/.sbx-gc.<pid>.<nonce>` (`RENAME_NOREPLACE`); empty it with the
//! bounded walker ([`walk::remove_contents`]); unlink the lock; rmdir the
//! tombstone. An interrupted gc leaves a tombstone that the next gc collects
//! (Q5). `sbx run` performs the matching post-lock binding check (#12 T6), so
//! a run that races the rename is refused.
//!
//! ROOT is refused (rc 1) when it is missing, not a directory, a symlink in
//! any form (Q2), the host root, owned by neither the current user nor root,
//! or group/world-writable without the sticky bit (Q3).
//!
//! Output (Q9): stdout `removed "<path>"` / `would remove "<path>"`, one line
//! per collected entry in bytewise name order; stderr
//! `sbx gc: "<path>": <reason>`. Silent (neither output nor failure): live
//! sessions, young sessions, non-sessions, foreign-owned top-level entries,
//! non-directories and symlinks (Q8, design deviation 2).
//!
//! Known residuals (#14): NFS `.nfsXXXX` files, flock on NFS/9p, btrfs
//! subvolumes (a different st_dev, refused as a mount). Mount identity is the
//! kernel mount id (`STATX_MNT_ID`, or `name_to_handle_at` on kernels < 5.8),
//! so a same-filesystem bind mount is detected on every kernel that supports
//! file handles; a filesystem without them makes gc fail closed.

use std::ffi::{CStr, CString, OsStr};
use std::fmt::{self, Display};
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

pub(crate) mod sys;
pub(crate) mod walk;

/// Test support for the integration suite: runs gc's mount checks on the
/// calling thread as on a kernel without `STATX_MNT_ID` and `MOUNT_ROOT` (< 5.8),
/// through the `name_to_handle_at` fallback. Not a configuration option.
#[doc(hidden)]
pub fn force_mount_id_fallback(on: bool) {
    sys::set_force_handle_mount_id(on);
}

use sys::{DirStream, MountId};

/// The lock file's name inside a session (the name `sbx run` uses).
const LOCK_NAME: &CStr = c"sbx.lock";
/// Attempts at a fresh tombstone name before giving up (`EEXIST` only).
const TOMBSTONE_TRIES: u32 = 8;

/// The parsed `sbx gc` invocation (cli.rs dispatch).
#[derive(Debug, Clone)]
pub struct GcArgs {
    pub root: PathBuf,
    pub older_than: Duration,
    pub dry_run: bool,
}

/// The `sbx gc` entry point: prints to the process stdio and returns the exit
/// code (0 = every eligible session handled, 1 = refused ROOT or any
/// per-session failure).
pub fn gc(args: GcArgs) -> ExitCode {
    let mut rep = Reporter::new(io::stdout().lock(), io::stderr().lock());
    collect(&args, &mut rep);
    rep.exit_code()
}

/// Testable core: never panics on I/O, every outcome goes through `rep`.
pub(crate) fn collect<O: Write, E: Write>(args: &GcArgs, rep: &mut Reporter<O, E>) {
    let root = match open_root(&args.root) {
        Ok(root) => root,
        Err(reason) => {
            rep.fail(&args.root, reason);
            return;
        }
    };
    let names = match snapshot(&root) {
        Ok(names) => names,
        Err(err) => {
            rep.fail(&args.root, format!("cannot read: {err}"));
            return;
        }
    };
    let ctx = Ctx {
        root: &root,
        root_path: &args.root,
        older_than: args.older_than,
        dry_run: args.dry_run,
        euid: sys::euid(),
    };
    for name in &names {
        let path = args.root.join(OsStr::from_bytes(name.as_bytes()));
        let kind = if is_tombstone_name(name.as_bytes()) {
            Kind::Tombstone
        } else {
            Kind::Session
        };
        match run_protocol(&ctx, name, &path, kind, rep) {
            Ok(()) | Err(None) => {}
            Err(Some(reason)) => rep.fail(&path, reason),
        }
    }
}

/// Stdout and stderr with the gc output rules: a closed stdout (BrokenPipe)
/// is silent and does not fail the run; any other stdout error is reported
/// once and fails it.
pub(crate) struct Reporter<O: Write, E: Write> {
    out: O,
    err: E,
    failed: bool,
    out_closed: bool,
}

impl<O: Write, E: Write> Reporter<O, E> {
    pub(crate) fn new(out: O, err: E) -> Self {
        Self {
            out,
            err,
            failed: false,
            out_closed: false,
        }
    }

    fn out_line(&mut self, text: fmt::Arguments<'_>) {
        if self.out_closed {
            return;
        }
        if let Err(err) = writeln!(self.out, "{text}") {
            self.out_closed = true;
            if err.kind() != io::ErrorKind::BrokenPipe {
                self.failed = true;
                let _ = writeln!(self.err, "sbx gc: cannot write to stdout: {err}");
            }
        }
    }

    pub(crate) fn removed(&mut self, path: &Path) {
        self.out_line(format_args!("removed {path:?}"));
    }

    pub(crate) fn would_remove(&mut self, path: &Path) {
        self.out_line(format_args!("would remove {path:?}"));
    }

    pub(crate) fn fail(&mut self, path: &Path, reason: impl Display) {
        self.failed = true;
        let _ = writeln!(self.err, "sbx gc: {path:?}: {reason}");
    }

    pub(crate) fn exit_code(&self) -> ExitCode {
        if self.failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
}

// ---- ROOT (T2) --------------------------------------------------------------

/// An opened, validated ROOT.
struct Root {
    fd: OwnedFd,
    mnt: MountId,
}

/// Open and validate ROOT. The error is the reason shown after `sbx gc: <root>:`.
fn open_root(root: &Path) -> Result<Root, String> {
    // Lexical normalization drops trailing `/` and `.` segments, so `link/`
    // and `link/.` reach O_NOFOLLOW's final component (the probe showed that
    // both follow the link otherwise).
    if root
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("must not contain `..`".to_string());
    }
    let norm: PathBuf = root.components().collect();
    if norm.has_root() && norm.components().count() == 1 {
        return Err("refusing to collect the host root".to_string());
    }
    let c_norm = CString::new(norm.as_os_str().as_bytes())
        .map_err(|_| "cannot open: path contains NUL".to_string())?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = match sys::open_path(&c_norm, flags) {
        Ok(fd) => fd,
        Err(err) => {
            return Err(match err.raw_os_error() {
                Some(libc::ENOENT) => "does not exist".to_string(),
                Some(libc::ENOTDIR | libc::ELOOP) => match sys::stat_path(&c_norm, false) {
                    Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                        "is a symbolic link".to_string()
                    }
                    Ok(_) => "is not a directory".to_string(),
                    Err(e) => format!("cannot open: {e}"),
                },
                _ => format!("cannot open: {err}"),
            });
        }
    };
    let st = sys::fstat(fd.as_fd()).map_err(|e| format!("cannot stat: {e}"))?;
    let host = sys::stat_path(c"/", true).map_err(|e| format!("cannot stat /: {e}"))?;
    if (st.st_dev, st.st_ino) == (host.st_dev, host.st_ino) {
        return Err("refusing to collect the host root".to_string());
    }
    check_root_meta(st.st_uid, st.st_mode, sys::euid())?;
    let mnt = MountId::of(fd.as_fd()).map_err(|e| format!("cannot stat: {e}"))?;
    Ok(Root { fd, mnt })
}

/// Q3: owned by the current user or root; group/world-writable only with the
/// sticky bit. `mode` is the full `st_mode`.
fn check_root_meta(uid: u32, mode: u32, euid: u32) -> Result<(), String> {
    if uid != euid && uid != 0 {
        return Err(format!(
            "is not owned by the current user or root (uid {uid})"
        ));
    }
    if mode & 0o022 != 0 && mode & libc::S_ISVTX == 0 {
        return Err(format!(
            "is group- or world-writable without the sticky bit (mode {:o})",
            mode & 0o7777
        ));
    }
    Ok(())
}

// ---- snapshot and names (T2) ------------------------------------------------

/// Every name in ROOT, bytewise sorted. Taken before any rename, so tombstones
/// created by this run are never revisited.
fn snapshot(root: &Root) -> io::Result<Vec<CString>> {
    let fd = sys::openat(root.fd.as_fd(), c".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut stream = DirStream::new(fd)?;
    let mut names = Vec::new();
    while let Some(name) = stream.next_name()? {
        names.push(name);
    }
    names.sort();
    Ok(names)
}

/// Prefix of a tombstone name (Q5).
pub(crate) const TOMBSTONE_PREFIX: &str = ".sbx-gc.";

/// `.sbx-gc.<1..10 decimal digits>.<exactly 16 lowercase hex>`. Anything else
/// (including the walker's `.sbx-gc-hoist.N`) is an ordinary entry.
pub(crate) fn is_tombstone_name(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(TOMBSTONE_PREFIX.as_bytes()) else {
        return false;
    };
    let Some(dot) = rest.iter().position(|&b| b == b'.') else {
        return false;
    };
    let (pid, nonce) = (&rest[..dot], &rest[dot + 1..]);
    (1..=10).contains(&pid.len())
        && pid.iter().all(u8::is_ascii_digit)
        && nonce.len() == 16
        && nonce
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The tombstone name for `pid` and `nonce`.
pub(crate) fn tombstone_name(pid: u32, nonce: u64) -> CString {
    CString::new(format!("{TOMBSTONE_PREFIX}{pid}.{nonce:016x}")).expect("no NUL in a tombstone")
}

/// Q4: a future mtime is kept; expired iff `now - mtime > older_than`.
pub(crate) fn is_expired(mtime: SystemTime, now: SystemTime, older_than: Duration) -> bool {
    match now.duration_since(mtime) {
        Ok(age) => age > older_than,
        Err(_) => false,
    }
}

// ---- the per-entry protocol (T3, T4) ----------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An ordinary entry: a session, subject to every check.
    Session,
    /// A leftover tombstone: collected regardless of age (Q5), no Q14 check,
    /// and no rename (it already is one).
    Tombstone,
}

struct Ctx<'a> {
    root: &'a Root,
    root_path: &'a Path,
    older_than: Duration,
    dry_run: bool,
    euid: u32,
}

/// The outcome of one entry's protocol. `Err(None)`: a silent skip (not a
/// failure). `Err(Some(reason))`: a failure, reported on the entry's path.
type Bail = Option<String>;

fn fail<T>(reason: impl Into<String>) -> Result<T, Bail> {
    Err(Some(reason.into()))
}

fn skip<T>() -> Result<T, Bail> {
    Err(None)
}

/// `ENOENT`, `ENOTDIR` and `ELOOP` mean the entry raced away (swapped or
/// removed since the stat): a silent skip, not a failure.
fn raced(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
    )
}

/// An entry this process has opened: the directory, and for a locked entry
/// its `sbx.lock` (held open until the entry is gone or the walk ended).
struct Held {
    dir: OwnedFd,
    lock: Option<OwnedFd>,
}

/// Test-only hooks at the two races the review found: between opening
/// `sbx.lock` and its flock (a run can touch the directory there), and after
/// the binding checks, before the tombstone rename (a sibling can swap the
/// name there). Each runs once, then is cleared.
#[cfg(test)]
mod hooks {
    use std::cell::RefCell;
    pub(super) type Hook = Box<dyn FnOnce()>;
    thread_local! {
        pub(super) static BEFORE_FLOCK: RefCell<Option<Hook>> = const { RefCell::new(None) };
        pub(super) static BEFORE_RENAME: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }
    pub(super) fn fire(which: &'static std::thread::LocalKey<RefCell<Option<Hook>>>) {
        let f = which.with(|h| h.borrow_mut().take());
        if let Some(f) = f {
            f();
        }
    }
}

/// The protocol up to the lock (design steps 1–9, plus the gc-vs-gc
/// directory flock): every decision here is made on the fd we opened.
fn run_protocol<O: Write, E: Write>(
    ctx: &Ctx<'_>,
    name: &CStr,
    path: &Path,
    kind: Kind,
    rep: &mut Reporter<O, E>,
) -> Result<(), Bail> {
    let root_fd = ctx.root.fd.as_fd();
    let is_tomb = kind == Kind::Tombstone;

    // 1. stat without following; only real directories are candidates.
    let st = match sys::fstatat_nofollow(root_fd, name) {
        Ok(st) => st,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return skip(),
        Err(e) => return fail(format!("cannot stat: {e}")),
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return skip();
    }
    // 2. another user's top-level entry is not ours to judge (design deviation 2).
    if st.st_uid != ctx.euid {
        return skip();
    }
    // 3. open without following anything.
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let dir = match sys::openat(root_fd, name, flags) {
        Ok(fd) => fd,
        Err(e) if raced(&e) => return skip(),
        Err(e) => return fail(format!("cannot open: {e}")),
    };
    // 4. the opened fd must still be the directory we stat'ed, and ours.
    let d = sys::fstat(dir.as_fd()).map_err(|e| Some(format!("cannot stat: {e}")))?;
    if (d.st_dev, d.st_ino) != (st.st_dev, st.st_ino) || d.st_uid != ctx.euid {
        return skip();
    }
    // 4b. gc-vs-gc: a flock on the directory itself. Another gc holding it is
    //     working on this entry; skip silently. It is held until the entry is
    //     gone (the rmdir in step 19 happens before the fd is dropped), so a
    //     later gc finds nothing to report.
    match sys::flock_ex_nb(dir.as_fd()) {
        Ok(true) => {}
        Ok(false) => return skip(),
        Err(e) => return fail(format!("cannot lock directory: {e}")),
    }
    // 5. the lock. Absent: not a session (Q1), so nothing is created. A
    //    tombstone without one is walked lockless.
    let lock_st = match sys::fstatat_nofollow(dir.as_fd(), LOCK_NAME) {
        Ok(l) => Some(l),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => None,
        Err(e) => return fail(format!("cannot stat sbx.lock: {e}")),
    };
    let Some(lock_st) = lock_st else {
        if is_tomb {
            return remove_locked(ctx, name, path, kind, rep, Held { dir, lock: None });
        }
        return skip();
    };
    let shape_ok = lock_st.st_mode & libc::S_IFMT == libc::S_IFREG
        && lock_st.st_uid == ctx.euid
        && lock_st.st_nlink == 1;
    if !shape_ok {
        if is_tomb {
            // A malformed lock in a tombstone is deleted like any other entry.
            return remove_locked(ctx, name, path, kind, rep, Held { dir, lock: None });
        }
        // 7. the lock must be a regular file, ours, with one link.
        return fail(
            "sbx.lock is not a regular file owned by the current user with one link; left in place",
        );
    }
    // 8. open the lock and check it is the one we stat'ed.
    let lock = match sys::openat(
        dir.as_fd(),
        LOCK_NAME,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    ) {
        Ok(fd) => fd,
        Err(e) if raced(&e) => return skip(),
        Err(e) => return fail(format!("cannot open sbx.lock: {e}")),
    };
    let lk = sys::fstat(lock.as_fd()).map_err(|e| Some(format!("cannot stat sbx.lock: {e}")))?;
    if (lk.st_dev, lk.st_ino) != (lock_st.st_dev, lock_st.st_ino) {
        return skip();
    }
    #[cfg(test)]
    hooks::fire(&hooks::BEFORE_FLOCK);
    // 9. flock with LOCK_NB: a live run holds it (in use: not a failure, Q8).
    match sys::flock_ex_nb(lock.as_fd()) {
        Ok(true) => {}
        Ok(false) => return skip(),
        Err(e) => return fail(format!("cannot lock sbx.lock: {e}")),
    }
    remove_locked(
        ctx,
        name,
        path,
        kind,
        rep,
        Held {
            dir,
            lock: Some(lock),
        },
    )
}

/// Steps 10–19, after the lock. Every age and mode decision is taken from a
/// fresh `fstat` of the directory made here, under the lock (M1): the mtime
/// read before the lock can predate a run that just finished.
fn remove_locked<O: Write, E: Write>(
    ctx: &Ctx<'_>,
    name: &CStr,
    path: &Path,
    kind: Kind,
    rep: &mut Reporter<O, E>,
    held: Held,
) -> Result<(), Bail> {
    let root_fd = ctx.root.fd.as_fd();
    let is_tomb = kind == Kind::Tombstone;
    let Held { dir, lock } = held;

    // 10. binding (the gc mirror of #12 T6): the held lock is still linked, is
    //     still the directory's sbx.lock, and the directory is still at `name`.
    if let Some(lock) = &lock {
        let lk =
            sys::fstat(lock.as_fd()).map_err(|e| Some(format!("cannot stat sbx.lock: {e}")))?;
        let named = match sys::fstatat_nofollow(dir.as_fd(), LOCK_NAME) {
            Ok(n) => n,
            Err(e) if raced(&e) => return skip(),
            Err(e) => return fail(format!("cannot stat sbx.lock: {e}")),
        };
        if lk.st_nlink == 0 || (named.st_dev, named.st_ino) != (lk.st_dev, lk.st_ino) {
            return skip();
        }
    }
    let dir_st = sys::fstat(dir.as_fd()).map_err(|e| Some(format!("cannot stat: {e}")))?;
    let here = match sys::fstatat_nofollow(root_fd, name) {
        Ok(h) => h,
        Err(e) if raced(&e) => return skip(),
        Err(e) => return fail(format!("cannot stat: {e}")),
    };
    if (here.st_dev, here.st_ino) != (dir_st.st_dev, dir_st.st_ino) {
        return skip();
    }

    // 6 (under the lock). Q14: a group/world-writable session is left in place.
    if !is_tomb && dir_st.st_mode & 0o022 != 0 {
        return fail(format!(
            "session directory is group- or world-writable (mode {:o}); left in place",
            dir_st.st_mode & 0o777
        ));
    }
    // 11. age, from the fresh mtime and a fresh clock (M1). Tombstones are
    //     collected regardless.
    if !is_tomb && !is_expired(sys::mtime(&dir_st), SystemTime::now(), ctx.older_than) {
        return skip();
    }

    // 12. a mount point (or a bind-mounted directory) is left in place.
    let x = sys::statx_fd(dir.as_fd()).map_err(|e| Some(format!("cannot stat: {e}")))?;
    if !ctx.root.mnt.contains(&x) {
        return fail("session directory is a mount point; left in place");
    }

    // 13. dry run: report, and drop the lock by returning (Q10).
    if ctx.dry_run {
        rep.would_remove(path);
        return Ok(());
    }

    // 14. the tombstone: a session is renamed (RENAME_NOREPLACE); a tombstone
    //     already is one.
    #[cfg(test)]
    hooks::fire(&hooks::BEFORE_RENAME);
    let tomb_name = if is_tomb {
        name.to_owned()
    } else {
        rename_to_tombstone(ctx, name)?
    };
    let tomb_path = ctx.root_path.join(OsStr::from_bytes(tomb_name.as_bytes()));
    let remainder = || {
        if is_tomb {
            String::new()
        } else {
            format!("; remainder left at {tomb_path:?}")
        }
    };

    // 15. the tombstone must be the directory we locked. If the name was
    //     swapped between the checks and the rename, the swapped-in entry is
    //     now at the tombstone name: put it back under `name` (NOREPLACE). If
    //     that fails, report the tombstone path loudly.
    let at_tomb = sys::fstatat_nofollow(root_fd, &tomb_name)
        .map_err(|e| Some(format!("cannot stat {tomb_path:?}: {e}")))?;
    if (at_tomb.st_dev, at_tomb.st_ino) != (dir_st.st_dev, dir_st.st_ino) {
        if is_tomb {
            return fail(format!(
                "tombstone {tomb_path:?} is not the locked session; left in place"
            ));
        }
        return match sys::renameat2_noreplace(root_fd, &tomb_name, root_fd, name) {
            Ok(()) => fail(format!(
                "session directory was replaced while it was being locked; the replacement was restored to {path:?}"
            )),
            Err(e) => fail(format!(
                "session directory was replaced while it was being locked; the replacement is at {tomb_path:?} and could not be restored: {e}"
            )),
        };
    }

    // 16. the walker needs search and write permission on the top.
    if dir_st.st_mode & 0o700 != 0o700 {
        sys::fchmod(dir.as_fd(), 0o700)
            .map_err(|e| Some(format!("cannot chmod: {e}{}", remainder())))?;
    }

    // 17. empty it, keeping the lock (step 18 unlinks it).
    let opts = walk::WalkOpts {
        keep_top: lock.as_ref().map(|_| LOCK_NAME),
        euid: ctx.euid,
    };
    if let Err(e) = walk::remove_contents(dir.as_fd(), &opts) {
        return fail(format!("{e}{}", remainder()));
    }

    // 18. unlink the lock we kept; then release it.
    if lock.is_some() {
        match sys::unlinkat(dir.as_fd(), LOCK_NAME, false) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return fail(format!("cannot remove sbx.lock: {e}{}", remainder())),
        }
    }
    drop(lock);

    // 19. rmdir the empty tombstone while still holding the directory fd, so
    //     a concurrent gc that opened it is still blocked by the directory
    //     flock and cannot report it a second time.
    let removed = sys::unlinkat(root_fd, &tomb_name, true);
    drop(dir);
    match removed {
        Ok(()) => rep.removed(path),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => rep.removed(path),
        Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY) => {
            return fail(format!(
                "a concurrent sbx run recreated entries during removal; left at {tomb_path:?} for the next gc"
            ));
        }
        Err(e) => return fail(format!("cannot remove tombstone {tomb_path:?}: {e}")),
    }
    Ok(())
}

/// Step 14: rename `name` to a fresh tombstone name with `RENAME_NOREPLACE`.
/// `EEXIST` retries with a new nonce; `ENOENT` means another gc took it.
fn rename_to_tombstone(ctx: &Ctx<'_>, name: &CStr) -> Result<CString, Bail> {
    let root_fd = ctx.root.fd.as_fd();
    let mut last = io::Error::from_raw_os_error(libc::EEXIST);
    for _ in 0..TOMBSTONE_TRIES {
        let tomb = tombstone_name(std::process::id(), sys::nonce());
        match sys::renameat2_noreplace(root_fd, name, root_fd, &tomb) {
            Ok(()) => return Ok(tomb),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => last = e,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return skip(),
            Err(e) => return fail(format!("cannot rename to a tombstone: {e}")),
        }
    }
    fail(format!("cannot rename to a tombstone: {last}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_name_matches_run() {
        assert_eq!(LOCK_NAME.to_str().expect("utf8"), crate::run::LOCK_FILE);
    }

    #[test]
    fn tombstone_names() {
        for ok in [
            ".sbx-gc.1.0123456789abcdef",
            ".sbx-gc.4294967295.00000000deadbeef",
        ] {
            assert!(is_tombstone_name(ok.as_bytes()), "{ok}");
        }
        for bad in [
            ".sbx-gc.1.0123456789ABCDEF",  // uppercase hex
            ".sbx-gc.1.0123456789abcde",   // 15 hex
            ".sbx-gc.1.0123456789abcdef0", // 17 hex
            ".sbx-gc..0123456789abcdef",   // missing pid
            ".sbx-gc.1.0123456789abcdef!", // trailing byte
            ".sbx-gc.",
            ".sbx-gc-hoist.1",
            "sbx-gc.1.0123456789abcdef",
            ".sbx-gc.12345678901.0123456789abcdef", // 11-digit pid
        ] {
            assert!(!is_tombstone_name(bad.as_bytes()), "{bad}");
        }
        assert!(!is_tombstone_name(b".sbx-gc.1.0123456789abcd\xffx"));
    }

    #[test]
    fn tombstone_name_round_trips() {
        let t = tombstone_name(42, 0xdead_beef);
        assert_eq!(t.to_str().expect("utf8"), ".sbx-gc.42.00000000deadbeef");
        assert!(is_tombstone_name(t.as_bytes()));
    }

    #[test]
    fn expiry_rules() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let day = Duration::from_secs(86_400);
        assert!(!is_expired(now, now, day), "equal is not expired");
        assert!(!is_expired(now + day, now, day), "future is kept");
        assert!(is_expired(now - day - Duration::from_secs(1), now, day));
        assert!(
            !is_expired(now - day, now, day),
            "exactly the cutoff is kept"
        );
    }

    #[test]
    fn check_root_meta_matrix() {
        let me = 1000;
        assert!(check_root_meta(me, 0o40700, me).is_ok());
        assert!(
            check_root_meta(0, 0o40755, me).is_ok(),
            "root-owned is fine"
        );
        assert!(
            check_root_meta(me, 0o41777, me).is_ok(),
            "sticky world-writable"
        );
        assert_eq!(
            check_root_meta(me + 1, 0o40700, me).unwrap_err(),
            "is not owned by the current user or root (uid 1001)"
        );
        assert_eq!(
            check_root_meta(me, 0o40777, me).unwrap_err(),
            "is group- or world-writable without the sticky bit (mode 777)"
        );
        assert!(check_root_meta(me, 0o40775, me).is_err());
    }

    // ---- collect() end to end, against real temp ROOTs --------------------

    use std::fs::{self, FileTimes, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch ROOT parent, made traversable and removed on drop.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "sbx-gc-mod-{}-{}-{tag}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&p).expect("mkdir tmp");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod tmp");
            Self(p)
        }
        fn root(&self) -> PathBuf {
            let r = self.0.join("root");
            fs::create_dir_all(&r).expect("mkdir root");
            fs::set_permissions(&r, fs::Permissions::from_mode(0o700)).expect("chmod root");
            r
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            fn traversable(p: &Path) {
                if let Ok(md) = fs::symlink_metadata(p) {
                    if md.is_dir() {
                        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                        if let Ok(rd) = fs::read_dir(p) {
                            for e in rd.flatten() {
                                traversable(&e.path());
                            }
                        }
                    }
                }
            }
            traversable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn backdate(p: &Path, age: Duration) {
        let when = SystemTime::now() - age;
        let f = fs::File::open(p).expect("open for times");
        f.set_times(FileTimes::new().set_modified(when))
            .expect("backdate");
    }

    fn lock_file(p: &Path) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p.join("sbx.lock"))
            .expect("create sbx.lock");
    }

    /// A session with a lock, backdated last (creating the lock touches mtime).
    fn session(root: &Path, name: &str, age: Duration) -> PathBuf {
        let p = root.join(name);
        fs::create_dir(&p).expect("mkdir session");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod session");
        lock_file(&p);
        backdate(&p, age);
        p
    }

    const DAY: Duration = Duration::from_secs(86_400);

    /// Run `collect` once; returns (stdout, stderr, failed).
    fn run_gc(root: &Path, older_than: Duration, dry_run: bool) -> (String, String, bool) {
        let args = GcArgs {
            root: root.to_path_buf(),
            older_than,
            dry_run,
        };
        let mut rep = Reporter::new(Vec::new(), Vec::new());
        collect(&args, &mut rep);
        (
            String::from_utf8(rep.out).expect("utf8 stdout"),
            String::from_utf8(rep.err).expect("utf8 stderr"),
            rep.failed,
        )
    }

    /// Hold an exclusive flock on `p` (a separate open file description).
    fn hold_lock(p: &Path) -> fs::File {
        let f = fs::File::open(p).expect("open lock");
        // SAFETY: flock on an fd we own; no pointers.
        assert_eq!(
            unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&f),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            },
            0
        );
        f
    }

    #[test]
    fn old_session_removed_young_kept() {
        let t = Tmp::new("old-young");
        let root = t.root();
        let old = session(&root, "old", DAY * 2);
        let young = session(&root, "young", Duration::from_secs(3600));
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert_eq!(out, format!("removed {:?}\n", root.join("old")));
        assert!(err.is_empty() && !failed, "{err}");
        assert!(!old.exists());
        assert!(young.join("sbx.lock").exists());
    }

    #[test]
    fn locked_session_kept() {
        let t = Tmp::new("locked");
        let root = t.root();
        let s = session(&root, "old", DAY * 2);
        let held = hold_lock(&s.join("sbx.lock"));
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed);
        assert!(s.join("sbx.lock").exists());
        drop(held);
        let (out, _, _) = run_gc(&root, DAY, false);
        assert_eq!(out, format!("removed {:?}\n", root.join("old")));
    }

    #[test]
    fn dir_without_lock_is_not_session() {
        let t = Tmp::new("nolock");
        let root = t.root();
        let p = root.join("plain");
        fs::create_dir(&p).expect("mkdir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        backdate(&p, DAY * 9);
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed);
        assert!(p.is_dir());
        assert!(!p.join("sbx.lock").exists(), "gc must not create a lock");
    }

    #[test]
    fn symlink_entry_in_root_ignored() {
        let t = Tmp::new("evil");
        let root = t.root();
        let outside = t.0.join("outside");
        fs::create_dir(&outside).expect("outside");
        lock_file(&outside);
        backdate(&outside, DAY * 9);
        symlink(&outside, root.join("evil")).expect("symlink");
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed);
        assert!(outside.join("sbx.lock").exists());
    }

    #[test]
    fn group_writable_session_reported() {
        let t = Tmp::new("groupw");
        let root = t.root();
        let g = session(&root, "g", DAY * 2);
        fs::set_permissions(&g, fs::Permissions::from_mode(0o775)).expect("chmod g");
        backdate(&g, DAY * 2);
        session(&root, "old", DAY * 2);
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert_eq!(out, format!("removed {:?}\n", root.join("old")));
        assert_eq!(
            err,
            format!(
                "sbx gc: {:?}: session directory is group- or world-writable (mode 775); left in place\n",
                root.join("g")
            )
        );
        assert!(failed);
        assert!(g.join("sbx.lock").exists());
    }

    #[test]
    fn bad_lock_shape_reported() {
        let t = Tmp::new("shape");
        let root = t.root();
        // sbx.lock as a directory.
        let s1 = root.join("s1");
        fs::create_dir_all(s1.join("sbx.lock")).expect("lock dir");
        backdate(&s1, DAY * 2);
        // sbx.lock as a symlink.
        let s2 = root.join("s2");
        fs::create_dir(&s2).expect("s2");
        symlink("/etc/passwd", s2.join("sbx.lock")).expect("lock symlink");
        backdate(&s2, DAY * 2);
        // sbx.lock with two hard links.
        let s3 = session(&root, "s3", DAY * 2);
        fs::hard_link(s3.join("sbx.lock"), s3.join("other")).expect("hard link");
        backdate(&s3, DAY * 2);
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty(), "{out}");
        assert!(failed);
        let reason =
            "sbx.lock is not a regular file owned by the current user with one link; left in place";
        for s in ["s1", "s2", "s3"] {
            let line = format!("sbx gc: {:?}: {reason}\n", root.join(s));
            assert!(err.contains(&line), "missing {line:?} in {err:?}");
        }
    }

    #[test]
    fn dry_run_keeps_and_releases_lock() {
        let t = Tmp::new("dry");
        let root = t.root();
        let s = session(&root, "old", DAY * 2);
        let (out, err, failed) = run_gc(&root, DAY, true);
        assert_eq!(out, format!("would remove {:?}\n", root.join("old")));
        assert!(err.is_empty() && !failed);
        assert!(s.join("sbx.lock").exists());
        // The dry run released the lock: a run could take it now.
        drop(hold_lock(&s.join("sbx.lock")));
    }

    #[test]
    fn future_mtime_kept() {
        let t = Tmp::new("future");
        let root = t.root();
        let s = session(&root, "future", Duration::ZERO);
        let when = SystemTime::now() + DAY * 9;
        fs::File::open(&s)
            .expect("open")
            .set_times(FileTimes::new().set_modified(when))
            .expect("future mtime");
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed);
        assert!(s.is_dir());
    }

    #[test]
    fn leftover_tombstone_collected() {
        let t = Tmp::new("tomb");
        let root = t.root();
        // Lockless, young: collected anyway (Q5).
        let lockless = root.join(".sbx-gc.1.0123456789abcdef");
        fs::create_dir_all(lockless.join("inner")).expect("tomb");
        fs::write(lockless.join("inner/f"), b"x").expect("file");
        // With an unlocked lock file.
        let locked = root.join(".sbx-gc.2.0123456789abcdef");
        fs::create_dir(&locked).expect("tomb2");
        lock_file(&locked);
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert_eq!(
            out,
            format!(
                "removed {:?}\nremoved {:?}\n",
                root.join(".sbx-gc.1.0123456789abcdef"),
                root.join(".sbx-gc.2.0123456789abcdef")
            )
        );
        assert!(err.is_empty() && !failed, "{err}");
        assert!(!lockless.exists() && !locked.exists());
    }

    #[test]
    fn busy_tombstone_skipped() {
        let t = Tmp::new("busytomb");
        let root = t.root();
        let tomb = root.join(".sbx-gc.3.0123456789abcdef");
        fs::create_dir(&tomb).expect("tomb");
        lock_file(&tomb);
        let held = hold_lock(&tomb.join("sbx.lock"));
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed);
        assert!(tomb.join("sbx.lock").exists());
        drop(held);
    }

    #[test]
    fn root_refusals() {
        let t = Tmp::new("refuse");
        let missing = t.0.join("missing");
        let (out, err, failed) = run_gc(&missing, DAY, false);
        assert!(out.is_empty() && failed);
        assert_eq!(err, format!("sbx gc: {missing:?}: does not exist\n"));

        let file = t.0.join("file");
        fs::write(&file, b"x").expect("file");
        let (_, err, failed) = run_gc(&file, DAY, false);
        assert!(failed);
        assert_eq!(err, format!("sbx gc: {file:?}: is not a directory\n"));

        let real = t.root();
        let link = t.0.join("link");
        symlink(&real, &link).expect("symlink");
        for spelling in [
            link.clone(),
            PathBuf::from(format!("{}/", link.display())),
            PathBuf::from(format!("{}/.", link.display())),
        ] {
            let (_, err, failed) = run_gc(&spelling, DAY, false);
            assert!(failed);
            assert_eq!(err, format!("sbx gc: {spelling:?}: is a symbolic link\n"));
        }

        for host in ["/", "//", "/."] {
            let (out, err, failed) = run_gc(Path::new(host), DAY, false);
            assert!(out.is_empty() && failed);
            assert_eq!(
                err,
                format!("sbx gc: {host:?}: refusing to collect the host root\n")
            );
        }

        let wide = t.0.join("wide");
        fs::create_dir(&wide).expect("wide");
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o777)).expect("chmod");
        let (_, err, failed) = run_gc(&wide, DAY, false);
        assert!(failed);
        assert_eq!(
            err,
            format!(
                "sbx gc: {wide:?}: is group- or world-writable without the sticky bit (mode 777)\n"
            )
        );

        let sticky = t.0.join("sticky");
        fs::create_dir(&sticky).expect("sticky");
        fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).expect("chmod");
        let (out, err, failed) = run_gc(&sticky, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed, "{err}");
    }

    /// M1: the age must come from the directory as it is under the lock. A run
    /// that touches the session between the stat and the flock (it just
    /// finished) makes the session young: it must be kept.
    #[test]
    fn touch_between_stat_and_flock_keeps_session() {
        let t = Tmp::new("m1-touch");
        let root = t.root();
        let s = session(&root, "old", DAY * 2);
        let target = s.clone();
        hooks::BEFORE_FLOCK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                backdate(&target, Duration::ZERO);
            }));
        });
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && err.is_empty() && !failed, "{out} {err}");
        assert!(
            s.join("sbx.lock").exists(),
            "a just-touched session was removed"
        );
    }

    /// m2: a sibling swaps the name between the binding checks and the rename,
    /// so the rename moves the swapped-in directory. gc must put it back under
    /// its name, report the swap, and leave our directory where it was.
    #[test]
    fn name_swapped_before_rename_is_restored() {
        let t = Tmp::new("m2-swap");
        let root = t.root();
        let s = session(&root, "old", DAY * 2);
        let moved = t.0.join("moved-original");
        let (target, moved2) = (s.clone(), moved.clone());
        hooks::BEFORE_RENAME.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                fs::rename(&target, &moved2).expect("move original away");
                fs::create_dir(&target).expect("swap in a replacement");
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("chmod");
            }));
        });
        let (out, err, failed) = run_gc(&root, DAY, false);
        assert!(out.is_empty() && failed);
        assert!(
            err.contains("session directory was replaced while it was being locked; the replacement was restored to"),
            "{err}"
        );
        assert!(s.is_dir(), "the replacement must be back under its name");
        assert!(
            !s.join("sbx.lock").exists(),
            "the replacement is not our session"
        );
        assert!(
            moved.join("sbx.lock").exists(),
            "our directory was emptied or moved"
        );
        let leftovers: Vec<String> = names_in(&root);
        assert_eq!(
            leftovers,
            vec!["old".to_string()],
            "no tombstone may remain"
        );
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn root_with_parent_dir_refused() {
        let t = Tmp::new("dotdot");
        let real = t.root();
        let p = PathBuf::from(format!(
            "{}/../{}",
            real.display(),
            real.file_name().unwrap().to_string_lossy()
        ));
        let (out, err, failed) = run_gc(&p, DAY, false);
        assert!(out.is_empty() && failed);
        assert_eq!(err, format!("sbx gc: {p:?}: must not contain `..`\n"));
    }
}
