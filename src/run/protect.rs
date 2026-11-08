//! `filesystem.protect` (issue #73, threat-model R7): read-only binds over the
//! files inside an `rw` path that run later on the host.
//!
//! 1. **Scan.** Before every launch (`run`, the keep-alive holder, every
//!    `attach` call) each policy `rw` path that is a directory is scanned: the
//!    path itself and the real directories up to [`SEARCH_DEPTH`] levels below
//!    it (srt's `mandatoryDenySearchDepth`). The scan does not follow symlinks
//!    and does not enter `.git` or `node_modules` directories, deny paths,
//!    other policy bind dests or protected directories. It visits at most
//!    [`SCAN_BUDGET`] directories per `rw` path and refuses the run past that.
//! 2. **Targets.** For each entry, the walk stops at the first component that
//!    is missing or is not a directory. An existing path is a target: it is
//!    bound read-only onto itself, so the existing nested-bind handling pins
//!    every directory on the way and the pre-launch guard verifies the chain
//!    (#39, #40). A worktree's `.git` file therefore protects itself for
//!    `.git/hooks/` and `.git/config`. A symlink is refused (a bind would
//!    follow it). Targets under a deny path or a nested policy bind are left
//!    to those.
//! 3. **Placeholders.** A missing component at the top level of an `rw` path
//!    gets a placeholder: an empty directory with mtime 0 (the marker), bound
//!    read-only like a target. A directory also stands in for a missing file:
//!    git ignores empty directories, so a placeholder never shows up as an
//!    untracked file that an agent could commit. Below the top level, missing
//!    entries get nothing.
//! 4. **Cleanup.** Every launch holds a shared `flock` on each placeholder it
//!    binds, created or found (a placeholder of a concurrent run on the same
//!    tree). At its end it takes the lock exclusively without waiting and
//!    removes the placeholder if it is still the same empty directory; a
//!    placeholder another live launch still holds is left to that launch. A
//!    run or holder lists its placeholders in `<session>/protect.list` before
//!    creating them. After a crash, the next run in that session directory
//!    and `sbx gc` remove the listed ones that still carry the marker, and any
//!    later launch that finds a marked placeholder adopts it and removes it at
//!    its end. Residuals: a crash between `mkdir` and the mtime reset leaves
//!    an unmarked empty directory; flock does not work on some network
//!    filesystems (the gc residuals).

use std::collections::VecDeque;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::policy::{AbsolutePath, Policy};

/// Directory levels below an `rw` path that are scanned (srt's default
/// `mandatoryDenySearchDepth`).
pub(crate) const SEARCH_DEPTH: usize = 3;
/// Directories visited per `rw` path before the scan refuses the run.
pub(crate) const SCAN_BUDGET: usize = 20_000;
/// The placeholder list inside the session directory.
pub(crate) const MANIFEST: &str = "protect.list";
/// The largest manifest that is read back (a corrupt one is ignored past it).
const MANIFEST_MAX: u64 = 1 << 20;
/// Directories the scan never enters: `.git` holds no protected entry of its
/// own, and `node_modules` trees are large and not run by host tooling.
const SKIP_DIRS: [&str; 2] = [".git", "node_modules"];

/// One parsed `filesystem.protect` entry.
struct Entry {
    comps: Vec<String>,
}

fn parse_entries(list: &[String]) -> Vec<Entry> {
    list.iter()
        .map(|e| Entry {
            comps: e
                .trim_end_matches('/')
                .split('/')
                .map(str::to_owned)
                .collect(),
        })
        .collect()
}

/// What the scan found for one entry under one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Found {
    Existing(PathBuf),
    Missing(PathBuf),
}

impl Found {
    fn path(&self) -> &Path {
        match self {
            Found::Existing(p) | Found::Missing(p) => p,
        }
    }
}

/// A placeholder this launch holds a shared lock on.
struct Held {
    parent: OwnedFd,
    name: CString,
    fd: OwnedFd,
    dev: u64,
    ino: u64,
}

/// The protected paths of one launch and the placeholders it holds. Dropping
/// it releases them (early returns); [`Protected::release`] does the same
/// explicitly before `process::exit`, which runs no destructors.
pub(crate) struct Protected {
    paths: Vec<AbsolutePath>,
    held: Vec<Held>,
    manifest: Option<(PathBuf, File)>,
}

impl Protected {
    /// The policy with the protected paths added to `filesystem.ro`: nested
    /// read-only binds under their `rw` path, which the argv builder pins and
    /// the guard verifies like any other.
    pub(crate) fn apply(&self, policy: &Policy) -> Policy {
        let mut out = policy.clone();
        out.filesystem.ro.extend(self.paths.iter().cloned());
        out
    }

    /// Removes the placeholders no other live launch holds, then the
    /// manifest. Idempotent.
    pub(crate) fn release(&mut self) {
        for held in self.held.drain(..).rev() {
            remove_held(&held);
        }
        if let Some((path, file)) = self.manifest.take() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
    }

    fn record(&mut self, session: Option<&Path>, path: &Path) -> Result<(), String> {
        let Some(session) = session else {
            return Ok(());
        };
        if self.manifest.is_none() {
            let file_path = session.join(MANIFEST);
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&file_path)
                .map_err(|err| format!("cannot write {file_path:?}: {err}"))?;
            self.manifest = Some((file_path, file));
        }
        let (file_path, file) = self.manifest.as_mut().expect("opened above");
        let mut line = path.as_os_str().as_bytes().to_vec();
        line.push(0);
        file.write_all(&line)
            .map_err(|err| format!("cannot write {file_path:?}: {err}"))
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
        self.release();
    }
}

/// Scans the policy's `rw` paths and prepares the launch's protected paths:
/// placeholders for missing top-level entries are created (and listed in the
/// session's manifest when `session` is given), and every placeholder found or
/// created is locked shared.
pub(crate) fn prepare(policy: &Policy, session: Option<&Path>) -> Result<Protected, String> {
    let mut out = Protected {
        paths: Vec::new(),
        held: Vec::new(),
        manifest: None,
    };
    let entries = parse_entries(&policy.filesystem.protect_entries());
    if entries.is_empty() {
        return Ok(out);
    }
    let fs = &policy.filesystem;
    let binds: Vec<&str> = fs
        .ro
        .iter()
        .chain(&fs.rw)
        .map(AbsolutePath::as_str)
        .collect();
    let denies: Vec<&str> = fs.deny.iter().map(AbsolutePath::as_str).collect();
    let mut found: Vec<Found> = Vec::new();
    for root in &fs.rw {
        scan_root(root.as_str(), &entries, &binds, &denies, &mut found)?;
    }
    for item in found {
        let path = item.path().to_path_buf();
        let text = path
            .to_str()
            .ok_or_else(|| {
                format!("protected path {path:?} is not valid UTF-8; sbx cannot bind it (set filesystem.protect to drop the entry)")
            })?
            .to_owned();
        let abs = AbsolutePath::from_built(text)
            .map_err(|err| format!("protected path {path:?}: {err}"))?;
        match item {
            Found::Existing(_) => {
                if is_marked(&path) {
                    out.record(session, &path)?;
                    out.held.push(adopt(&path)?);
                }
            }
            Found::Missing(_) => {
                out.record(session, &path)?;
                match create(&path)? {
                    Some(held) => out.held.push(held),
                    // Created concurrently: someone else's now, or a
                    // placeholder of a concurrent run.
                    None => match std::fs::symlink_metadata(&path) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            return Err(symlink_error(&path));
                        }
                        Ok(_) if is_marked(&path) => out.held.push(adopt(&path)?),
                        Ok(_) => {}
                        Err(err) => {
                            return Err(format!("cannot inspect protected path {path:?}: {err}"));
                        }
                    },
                }
            }
        }
        out.paths.push(abs);
    }
    Ok(out)
}

/// Segment-exact "equals or is under" on lexically canonical paths.
fn at_or_under(path: &Path, root: &str) -> bool {
    path.starts_with(root)
}

fn symlink_error(path: &Path) -> String {
    format!(
        "protected path {path:?} is a symbolic link; sbx cannot bind it read-only (a bind follows the link). Replace it with the real file, or drop the entry from filesystem.protect"
    )
}

/// The scan of one `rw` path (module docs points 1–2), appending to `out`
/// (deduplicated by path).
fn scan_root(
    root: &str,
    entries: &[Entry],
    binds: &[&str],
    denies: &[&str],
    out: &mut Vec<Found>,
) -> Result<(), String> {
    // A missing or non-directory rw path has nothing to scan; bwrap and the
    // guard report a missing one.
    if !std::fs::metadata(root).is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    // A target is skipped when a deny path masks it or a nested policy bind
    // (other than this rw path) covers it.
    let skipped = |path: &Path| {
        denies.iter().any(|d| at_or_under(path, d))
            || binds
                .iter()
                .any(|b| *b != root && at_or_under(path, b) && Path::new(b).starts_with(root))
    };
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::from([(PathBuf::from(root), 0)]);
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        visited += 1;
        if visited > SCAN_BUDGET {
            return Err(format!(
                "the filesystem.protect scan of {root:?} found more than {SCAN_BUDGET} directories within {SEARCH_DEPTH} levels; bind a narrower rw path, or set filesystem.protect to [] to turn the protection off"
            ));
        }
        for entry in entries {
            if let Some(found) = resolve(&dir, entry, depth == 0)? {
                if !skipped(found.path()) && !out.iter().any(|f| f.path() == found.path()) {
                    out.push(found);
                }
            }
        }
        if depth == SEARCH_DEPTH {
            continue;
        }
        let mut children: Vec<PathBuf> = Vec::new();
        let reader = std::fs::read_dir(&dir).map_err(|err| {
            format!(
                "cannot scan {dir:?} for filesystem.protect: {err}; fix the permissions, or set filesystem.protect to [] to turn the protection off"
            )
        })?;
        for child in reader {
            let child = child.map_err(|err| format!("cannot scan {dir:?}: {err}"))?;
            // DirEntry::file_type does not follow a symlink.
            let is_dir = child
                .file_type()
                .map_err(|err| format!("cannot scan {dir:?}: {err}"))?
                .is_dir();
            let name = child.file_name();
            if !is_dir || SKIP_DIRS.iter().any(|s| name.as_bytes() == s.as_bytes()) {
                continue;
            }
            let path = dir.join(&name);
            let is_bind = binds.iter().any(|b| Path::new(b) == path);
            let is_target = out.iter().any(|f| f.path() == path);
            if is_bind || is_target || denies.iter().any(|d| at_or_under(&path, d)) {
                continue;
            }
            children.push(path);
        }
        children.sort();
        queue.extend(children.into_iter().map(|c| (c, depth + 1)));
    }
    Ok(())
}

/// One entry under one directory (module docs point 2).
fn resolve(dir: &Path, entry: &Entry, top: bool) -> Result<Option<Found>, String> {
    let mut path = dir.to_path_buf();
    let last = entry.comps.len() - 1;
    for (i, comp) in entry.comps.iter().enumerate() {
        path.push(comp);
        match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(top.then_some(Found::Missing(path)));
            }
            // A component below a non-directory is not a path at all.
            Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => return Ok(None),
            Err(err) => return Err(format!("cannot inspect protected path {path:?}: {err}")),
            Ok(meta) if meta.file_type().is_symlink() => return Err(symlink_error(&path)),
            // A placeholder (a concurrent run's `.git` or `.claude`) is the
            // target itself: nothing is created inside it.
            Ok(meta) if meta.is_dir() && i != last && !is_marked(&path) => {}
            Ok(_) => return Ok(Some(Found::Existing(path))),
        }
    }
    unreachable!("the loop returns at the last component")
}

/// A placeholder carries the marker: an empty directory with mtime 0.
fn marked(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_mtime == 0 && st.st_mtime_nsec == 0
}

fn is_marked(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    use std::os::unix::fs::MetadataExt;
    meta.is_dir()
        && meta.mtime() == 0
        && meta.mtime_nsec() == 0
        && std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_none())
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = cstring(path.as_os_str().as_bytes())?;
    // SAFETY: NUL-terminated path; a successful call returns a fresh fd.
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor returned by open.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn open_child_dir(parent: BorrowedFd<'_>, name: &CString) -> io::Result<OwnedFd> {
    // SAFETY: valid dir fd and NUL-terminated name; a successful call returns
    // a fresh fd. O_NOFOLLOW refuses a symlink at the name.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor returned by openat.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid fd; `st` is a writable struct stat filled on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialized by the successful fstat.
    Ok(unsafe { st.assume_init() })
}

fn fstatat_nofollow(dir: BorrowedFd<'_>, name: &CString) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid dir fd, NUL-terminated name, writable struct stat.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialized by the successful fstatat.
    Ok(unsafe { st.assume_init() })
}

fn flock(fd: BorrowedFd<'_>, op: libc::c_int) -> io::Result<bool> {
    // SAFETY: flock on a valid fd.
    if unsafe { libc::flock(fd.as_raw_fd(), op) } == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(false);
    }
    Err(err)
}

fn split(path: &Path) -> io::Result<(OwnedFd, CString)> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    };
    Ok((open_dir(parent)?, cstring(name.as_bytes())?))
}

/// Creates a placeholder at `path` and locks it shared. `None`: the name
/// appeared since the scan.
fn create(path: &Path) -> Result<Option<Held>, String> {
    let fail = |err: io::Error| format!("cannot create the placeholder {path:?}: {err}");
    let (parent, name) = split(path).map_err(fail)?;
    // SAFETY: valid dir fd and NUL-terminated name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(None);
        }
        return Err(fail(err));
    }
    let fd = open_child_dir(parent.as_fd(), &name).map_err(fail)?;
    let zero = [libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; 2];
    // SAFETY: valid fd and a two-element timespec array.
    if unsafe { libc::futimens(fd.as_raw_fd(), zero.as_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: valid dir fd and NUL-terminated name.
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(fail(err));
    }
    flock(fd.as_fd(), libc::LOCK_SH).map_err(fail)?;
    let st = fstat(fd.as_fd()).map_err(fail)?;
    Ok(Some(Held {
        parent,
        name,
        fd,
        dev: st.st_dev,
        ino: st.st_ino,
    }))
}

/// Locks a marked placeholder found by the scan (a concurrent run's, or one a
/// crash left behind) shared, and checks it is still the one at `path`.
fn adopt(path: &Path) -> Result<Held, String> {
    let fail = |err: io::Error| format!("cannot lock the placeholder {path:?}: {err}");
    let (parent, name) = split(path).map_err(fail)?;
    let fd = open_child_dir(parent.as_fd(), &name).map_err(fail)?;
    // Blocking: a remover holds the exclusive lock only for its final check.
    flock(fd.as_fd(), libc::LOCK_SH).map_err(fail)?;
    let st = fstat(fd.as_fd()).map_err(fail)?;
    let here = fstatat_nofollow(parent.as_fd(), &name);
    if !here.is_ok_and(|h| (h.st_dev, h.st_ino) == (st.st_dev, st.st_ino)) || !marked(&st) {
        return Err(format!(
            "the placeholder {path:?} changed while sbx prepared the run; run again"
        ));
    }
    Ok(Held {
        parent,
        name,
        fd,
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

/// Removes a held placeholder when no other launch holds it and it is still
/// the same marked directory (module docs point 4). Best effort.
fn remove_held(held: &Held) {
    if !flock(held.fd.as_fd(), libc::LOCK_EX | libc::LOCK_NB).unwrap_or(false) {
        return;
    }
    let Ok(here) = fstatat_nofollow(held.parent.as_fd(), &held.name) else {
        return;
    };
    if (here.st_dev, here.st_ino) != (held.dev, held.ino) || !marked(&here) {
        return;
    }
    // ENOTEMPTY (the host added something) leaves it in place.
    // SAFETY: valid dir fd and NUL-terminated name.
    unsafe {
        libc::unlinkat(
            held.parent.as_raw_fd(),
            held.name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
}

/// Removes a listed placeholder after a crash: only a marked directory that
/// no live launch holds.
fn remove_listed(path: &Path) {
    if !path.is_absolute() {
        return;
    }
    let Ok((parent, name)) = split(path) else {
        return;
    };
    let Ok(fd) = open_child_dir(parent.as_fd(), &name) else {
        return;
    };
    let Ok(st) = fstat(fd.as_fd()) else {
        return;
    };
    if !marked(&st) {
        return;
    }
    remove_held(&Held {
        parent,
        name,
        fd,
        dev: st.st_dev,
        ino: st.st_ino,
    });
}

/// Crash recovery (module docs point 4): removes the placeholders a previous
/// run or holder of the session in `dir` listed, then the list. Best effort;
/// `sbx gc` calls it on a locked expired session, `run` right after taking the
/// session lock.
pub(crate) fn cleanup_manifest_at(dir: BorrowedFd<'_>) {
    let name = CString::new(MANIFEST).expect("constant has no NUL");
    // SAFETY: valid dir fd and NUL-terminated name; a successful call returns
    // a fresh fd.
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return;
    }
    // SAFETY: `raw` is a fresh descriptor returned by openat.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let Ok(st) = fstat(fd.as_fd()) else {
        return;
    };
    if st.st_mode & libc::S_IFMT == libc::S_IFREG && (st.st_size as u64) <= MANIFEST_MAX {
        let mut bytes = Vec::new();
        if File::from(fd).read_to_end(&mut bytes).is_ok() {
            for item in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
                remove_listed(Path::new(OsStr::from_bytes(item)));
            }
        }
    }
    // SAFETY: valid dir fd and NUL-terminated name.
    unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
}

/// [`cleanup_manifest_at`] for a session directory path.
pub(crate) fn cleanup_manifest(session: &Path) {
    if let Ok(dir) = open_dir(session) {
        cleanup_manifest_at(dir.as_fd());
    }
}

/// The protected paths `prepare` would bind, as text, for tests.
#[cfg(test)]
fn scan_for_test(policy: &Policy) -> Result<Vec<(String, bool)>, String> {
    let entries = parse_entries(&policy.filesystem.protect_entries());
    let fs = &policy.filesystem;
    let binds: Vec<&str> = fs
        .ro
        .iter()
        .chain(&fs.rw)
        .map(AbsolutePath::as_str)
        .collect();
    let denies: Vec<&str> = fs.deny.iter().map(AbsolutePath::as_str).collect();
    let mut found = Vec::new();
    for root in &fs.rw {
        scan_root(root.as_str(), &entries, &binds, &denies, &mut found)?;
    }
    Ok(found
        .into_iter()
        .map(|f| match f {
            Found::Existing(p) => (p.to_string_lossy().into_owned(), true),
            Found::Missing(p) => (p.to_string_lossy().into_owned(), false),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sbx-protect-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn policy(rw: &Path, protect: Option<&str>, deny: &str) -> Policy {
        let protect = protect
            .map(|p| format!(r#","protect":{p}"#))
            .unwrap_or_default();
        Policy::from_json_str(&format!(
            r#"{{"version":1,"filesystem":{{"ro":["/usr"],"rw":[{rw:?}],"deny":[{deny}]{protect}}},"network":{{"mode":"none","allow":[],"ports":[]}},"env":{{"pass":[],"set":{{}}}},"limits":{{"timeout":"10s","output_bytes":1024}}}}"#
        ))
        .expect("policy")
    }

    fn rel(found: &[(String, bool)], root: &Path) -> Vec<(String, bool)> {
        let root = root.to_string_lossy().into_owned() + "/";
        found
            .iter()
            .map(|(p, e)| (p.strip_prefix(&root).unwrap_or(p).to_owned(), *e))
            .collect()
    }

    #[test]
    fn scan_finds_existing_and_missing_top_level_entries() {
        let root = scratch("scan");
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/config"), "").unwrap();
        std::fs::write(root.join(".bashrc"), "").unwrap();
        std::fs::create_dir_all(root.join("a/b/c/.git/hooks")).unwrap();
        std::fs::create_dir_all(root.join("a/b/c/d/.git/hooks")).unwrap();
        std::fs::write(root.join("a/.zshrc"), "").unwrap();
        let found = rel(
            &scan_for_test(&policy(
                &root,
                Some(r#"[".bashrc",".zshrc",".git/hooks/",".git/config",".claude/commands/"]"#),
                "",
            ))
            .unwrap(),
            &root,
        );
        assert!(found.contains(&(".bashrc".into(), true)), "{found:?}");
        assert!(found.contains(&(".git/hooks".into(), true)), "{found:?}");
        assert!(found.contains(&(".git/config".into(), true)), "{found:?}");
        // Missing at the top level: the first missing component.
        assert!(found.contains(&(".zshrc".into(), false)), "{found:?}");
        assert!(found.contains(&(".claude".into(), false)), "{found:?}");
        // Below the top level, existing only, up to 3 levels.
        assert!(found.contains(&("a/.zshrc".into(), true)), "{found:?}");
        assert!(
            found.contains(&("a/b/c/.git/hooks".into(), true)),
            "{found:?}"
        );
        assert!(
            !found.iter().any(|(p, _)| p.starts_with("a/b/c/d/")),
            "depth 4 is not scanned: {found:?}"
        );
        assert!(
            !found.iter().any(|(p, _)| p == "a/.bashrc"),
            "missing below the top level: {found:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn worktree_git_file_is_protected_and_symlinks_are_refused() {
        let root = scratch("worktree");
        std::fs::write(root.join(".git"), "gitdir: /elsewhere\n").unwrap();
        let found = rel(&scan_for_test(&policy(&root, None, "")).unwrap(), &root);
        assert!(found.contains(&(".git".into(), true)), "{found:?}");
        assert_eq!(found.iter().filter(|(p, _)| p == ".git").count(), 1);
        std::os::unix::fs::symlink("/etc/passwd", root.join(".bashrc")).unwrap();
        let err = scan_for_test(&policy(&root, None, "")).unwrap_err();
        assert!(err.contains("is a symbolic link"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn opt_out_and_extension() {
        let root = scratch("optout");
        assert!(
            scan_for_test(&policy(&root, Some("[]"), ""))
                .unwrap()
                .is_empty()
        );
        let found = rel(
            &scan_for_test(&policy(&root, Some(r#"["@default","Makefile"]"#), "")).unwrap(),
            &root,
        );
        assert!(found.contains(&("Makefile".into(), false)), "{found:?}");
        assert!(found.contains(&(".bashrc".into(), false)), "{found:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn skips_deny_and_nested_binds() {
        let root = scratch("skips");
        std::fs::create_dir_all(root.join("sub/.vscode")).unwrap();
        std::fs::create_dir_all(root.join("hidden/.vscode")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/x/.vscode")).unwrap();
        let deny = format!("{:?}", root.join("hidden").to_str().unwrap());
        let p = policy(&root, None, &deny);
        let found = rel(&scan_for_test(&p).unwrap(), &root);
        assert!(found.contains(&("sub/.vscode".into(), true)), "{found:?}");
        assert!(
            !found.iter().any(|(p, _)| p.starts_with("hidden/")),
            "{found:?}"
        );
        assert!(
            !found.iter().any(|(p, _)| p.starts_with("node_modules/")),
            "{found:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn placeholders_are_created_marked_and_removed() {
        let root = scratch("placeholders");
        let session = scratch("placeholders-session");
        let pol = policy(&root, Some(r#"[".bashrc",".git/hooks/"]"#), "");
        let mut prot = prepare(&pol, Some(&session)).unwrap();
        for name in [".bashrc", ".git"] {
            let meta = std::fs::symlink_metadata(root.join(name)).unwrap();
            assert!(meta.is_dir(), "{name} is a directory placeholder");
            assert_eq!(meta.mtime(), 0, "{name} carries the marker");
        }
        assert!(session.join(MANIFEST).exists());
        let effective = prot.apply(&pol);
        assert_eq!(effective.filesystem.ro.len(), 3);
        // A second launch on the same tree adopts them; the first one's end
        // leaves them to it.
        let mut second = prepare(&pol, None).unwrap();
        prot.release();
        assert!(
            root.join(".bashrc").exists(),
            "still held by the second launch"
        );
        assert!(!session.join(MANIFEST).exists());
        second.release();
        assert!(!root.join(".bashrc").exists());
        assert!(!root.join(".git").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&session);
    }

    #[test]
    fn manifest_cleanup_removes_only_marked_placeholders() {
        let root = scratch("manifest");
        let session = scratch("manifest-session");
        let pol = policy(&root, Some(r#"[".bashrc",".zshrc"]"#), "");
        let mut prot = prepare(&pol, Some(&session)).unwrap();
        // A crash: the held locks go away, the placeholders and the list stay.
        prot.held.clear();
        prot.manifest = None;
        drop(prot);
        // The host reuses one of them.
        std::fs::write(root.join(".zshrc/keep"), "").unwrap();
        cleanup_manifest(&session);
        assert!(!root.join(".bashrc").exists());
        assert!(root.join(".zshrc/keep").exists());
        assert!(!session.join(MANIFEST).exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&session);
    }

    #[test]
    fn user_directories_are_never_removed() {
        let root = scratch("user");
        std::fs::create_dir(root.join(".vscode")).unwrap();
        let pol = policy(&root, Some(r#"[".vscode/"]"#), "");
        let mut prot = prepare(&pol, None).unwrap();
        assert!(prot.held.is_empty());
        prot.release();
        assert!(root.join(".vscode").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
