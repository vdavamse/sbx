//! `filesystem.protect` (issue #73, threat-model R7): read-only binds over the
//! files inside an `rw` path that run later on the host.
//!
//! 1. **Scan.** Before a `run` or a keep-alive holder launches, each policy
//!    `rw` path that is a directory is scanned: the path itself and the real
//!    directories up to [`SEARCH_DEPTH`] levels below it (srt's
//!    `mandatoryDenySearchDepth`). The scan does not follow symlinks and does
//!    not enter `.git` or `node_modules` directories (point 5 looks into
//!    `.git`), deny paths, other policy bind dests or protected directories.
//!    It skips an unreadable directory owned by another user (the payload
//!    cannot change it either) and refuses an unreadable one of this user (the
//!    payload could `chmod` it to hide it from a later scan). It visits at most
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
//!    gets a placeholder: an empty directory with mtime 0 (the marker), built
//!    under a temporary `.sbx-protect.<pid>.<n>` name, locked, marked, and
//!    renamed into place without replacing anything (so a placeholder is never
//!    seen unmarked or unlocked at the protected name), and bound
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
//!    its end. A placeholder is locked before it is marked, so no cleanup can
//!    take it in between. Residuals: a crash between `mkdir` and the mark
//!    leaves an unmarked empty `.sbx-protect.*` directory; a user's own empty directory with
//!    mtime 0 at a protected name is taken for a placeholder; flock does not
//!    work on some network filesystems (the gc residuals).
//! 5. **Git directories.** In every real `.git` directory the scan reaches,
//!    the existing `commondir` and `gitdir` files of each linked worktree
//!    (`.git/worktrees/*/`) and the `hooks/`, `config` and `commondir` of each
//!    submodule git directory (`.git/modules/**`, a directory with a `HEAD`)
//!    are targets too, and so is every existing `config.worktree`: each of
//!    them redirects or runs host git. A symlinked `worktrees` or `modules` is
//!    refused. A `commondir` or `config.worktree` cannot be pre-empted with a
//!    placeholder (git refuses a directory there), so one that appears during
//!    the run in a git directory that had none is renamed aside at the end,
//!    through the directory fd held since the scan, with a warning. This runs
//!    only when the list protects something under `.git`.
//! 6. **Keep-alive sessions.** The holder saves its target list in
//!    `<session>/protect.paths`, and every `attach` call binds exactly that
//!    list instead of scanning again. A scan of a tree the resident writes
//!    would let the resident choose new nested binds and pins and race them
//!    between the guard and bwrap; with the saved list every launch of the
//!    session has the binds the resident already has mounted and pinned (the
//!    same-policy invariant of R26). A call creates and removes nothing.
//!    Two concurrent `run`s of one policy on one tree do not share a list: that
//!    race stays open (threat-model R7, R26).
//! 7. **Host writers.** A rename over, or a removal of, a protected path on the
//!    host (git rewrites `.git/config` by renaming `config.lock` over it, `git
//!    clean -fd` removes empty directories) detaches the read-only bind in the
//!    sandbox's mount namespace (Linux 3.18 and later), so the payload can
//!    write the path from then on. sbx cannot prevent it; it records every
//!    target's (dev, ino) at the start and warns at the end when one changed.

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
/// A keep-alive holder's protected paths, inside the session directory.
pub(crate) const PATHS: &str = "protect.paths";
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
    /// A missing top-level entry: (the rw path, the placeholder path).
    Missing(PathBuf, PathBuf),
}

impl Found {
    fn path(&self) -> &Path {
        match self {
            Found::Existing(p) | Found::Missing(_, p) => p,
        }
    }
}

/// The files whose appearance in a git directory redirects host git: a
/// `commondir` (hooks and config from another directory) and a
/// `config.worktree` (read on top of `config` with `extensions.worktreeConfig`).
const GIT_REDIRECTS: [&str; 2] = ["commondir", "config.worktree"];

/// A git directory, held open from the scan (so a later swap of its path for
/// a symlink cannot redirect the check), and the [`GIT_REDIRECTS`] it lacked.
struct Watched {
    path: PathBuf,
    fd: OwnedFd,
    absent: Vec<&'static str>,
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
    /// Git directories that lacked a redirecting file at the scan (module
    /// docs point 5).
    gitdirs: Vec<Watched>,
    /// The session's saved path list (a keep-alive holder), removed at release.
    saved: Option<PathBuf>,
    /// (dev, ino) of every target when the launch was prepared (module docs
    /// point 7).
    identities: Vec<(u64, u64)>,
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
        self.warn_lapsed();
        for held in self.held.drain(..).rev() {
            remove_held(&held);
        }
        if let Some((path, file)) = self.manifest.take() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
        if let Some(path) = self.saved.take() {
            let _ = std::fs::remove_file(path);
        }
        for watched in self.gitdirs.drain(..) {
            block_redirects(&watched);
        }
    }

    /// Module docs point 7: a target that a host process replaced (git's
    /// lock-file rename of `.git/config`) or removed during the run lost its
    /// read-only bind in the sandbox from then on. Warn, once per target.
    fn warn_lapsed(&mut self) {
        for path in self.lapsed() {
            eprintln!(
                "sbx: warning: the protected path {path:?} was replaced or removed on the host while the sandbox ran, so the sandbox could write it from then on; review it before running git or other host tools on the tree"
            );
        }
        self.identities.clear();
    }

    /// The targets whose (dev, ino) changed since the launch was prepared.
    fn lapsed(&self) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        self.paths
            .iter()
            .zip(&self.identities)
            .filter(|(abs, id)| {
                std::fs::symlink_metadata(abs.as_path())
                    .ok()
                    .map(|m| (m.dev(), m.ino()))
                    != Some(**id)
            })
            .map(|(abs, _)| abs.as_str().to_owned())
            .collect()
    }

    /// Records the identity of the target just pushed (module docs point 7).
    fn push_target(&mut self, abs: AbsolutePath) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(abs.as_path())
            .map_err(|err| format!("cannot inspect protected path {:?}: {err}", abs.as_str()))?;
        self.identities.push((meta.dev(), meta.ino()));
        self.paths.push(abs);
        Ok(())
    }

    fn empty() -> Self {
        Protected {
            paths: Vec::new(),
            held: Vec::new(),
            manifest: None,
            gitdirs: Vec::new(),
            saved: None,
            identities: Vec::new(),
        }
    }

    /// A keep-alive holder saves its protected paths in the session directory
    /// (module docs point 6); every attach call binds exactly these.
    pub(crate) fn save(&mut self, session: &Path) -> Result<(), String> {
        let path = session.join(PATHS);
        let mut bytes = Vec::new();
        for p in &self.paths {
            bytes.extend_from_slice(p.as_str().as_bytes());
            bytes.push(0);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|err| format!("cannot write {path:?}: {err}"))?;
        file.write_all(&bytes)
            .map_err(|err| format!("cannot write {path:?}: {err}"))?;
        self.saved = Some(path);
        Ok(())
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
    let mut out = Protected::empty();
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
        scan_root(
            root.as_str(),
            &entries,
            &binds,
            &denies,
            &mut found,
            &mut out.gitdirs,
        )?;
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
            Found::Missing(root, _) => {
                let tmp = temp_name(&path);
                out.record(session, &tmp)?;
                out.record(session, &path)?;
                match create(&root, &path, &tmp)? {
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
        out.push_target(abs)?;
    }
    Ok(out)
}

/// The protected paths of a keep-alive session, for an attach call (module
/// docs point 6): the holder's saved list, not a new scan, so every launch of
/// the session has the same nested binds and pins as the resident. Each path
/// must lie inside one of the policy's `rw` paths. A call creates and removes
/// nothing.
pub(crate) fn load(policy: &Policy, session: &Path) -> Result<Protected, String> {
    let mut out = Protected::empty();
    if policy.filesystem.protect_entries().is_empty() {
        return Ok(out);
    }
    let path = session.join(PATHS);
    let fail = |err: io::Error| {
        format!("cannot read the session's protected paths {path:?}: {err}; restart the session")
    };
    let dir = open_dir(session).map_err(fail)?;
    let name = cstring(PATHS.as_bytes()).map_err(fail)?;
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
        return Err(fail(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh descriptor returned by openat.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let st = fstat(fd.as_fd()).map_err(fail)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_size as u64 > MANIFEST_MAX {
        return Err(fail(io::Error::from_raw_os_error(libc::EINVAL)));
    }
    let mut bytes = Vec::new();
    File::from(fd).read_to_end(&mut bytes).map_err(fail)?;
    for item in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let text = std::str::from_utf8(item)
            .map_err(|_| fail(io::Error::from_raw_os_error(libc::EINVAL)))?;
        let abs = AbsolutePath::from_built(text.to_owned()).map_err(|err| {
            format!("the session's protected path {text:?} is invalid: {err}; restart the session")
        })?;
        let inside = policy
            .filesystem
            .rw
            .iter()
            .any(|rw| abs.as_path() != rw.as_path() && abs.as_path().starts_with(rw.as_path()));
        if !inside {
            return Err(format!(
                "the session's protected path {text:?} is not inside an rw path of the policy; restart the session"
            ));
        }
        out.push_target(abs)?;
    }
    Ok(out)
}

/// Module docs point 5: a [`GIT_REDIRECTS`] file that appeared in a git
/// directory during the run would make host git run hooks or read config the
/// payload chose. It is renamed aside within the directory held open since
/// the scan (never through its path), with a warning.
fn block_redirects(watched: &Watched) {
    for name in &watched.absent {
        let Ok(cname) = cstring(name.as_bytes()) else {
            continue;
        };
        if fstatat_nofollow(watched.fd.as_fd(), &cname).is_err() {
            continue;
        }
        let path = watched.path.join(name);
        let aside_name = format!("{name}.sbx-blocked.{}", std::process::id());
        let aside = watched.path.join(&aside_name);
        let Ok(caside) = cstring(aside_name.as_bytes()) else {
            continue;
        };
        match crate::gc::sys::renameat2_noreplace(
            watched.fd.as_fd(),
            &cname,
            watched.fd.as_fd(),
            &caside,
        ) {
            Ok(()) => eprintln!(
                "sbx: warning: the sandbox created {path:?}, which would make git on the host run hooks or read config the sandbox chose; renamed it to {aside:?}"
            ),
            Err(err) => eprintln!(
                "sbx: warning: the sandbox created {path:?}, which would make git on the host run hooks or read config the sandbox chose, and sbx could not rename it ({err}); remove it before running git there"
            ),
        }
    }
}

/// Holds `dir` (a git directory) open and records which [`GIT_REDIRECTS`] it
/// lacks.
fn watch(dir: &Path, gitdirs: &mut Vec<Watched>) -> Result<(), String> {
    let c = cstring(dir.as_os_str().as_bytes())
        .map_err(|err| format!("cannot open the git directory {dir:?}: {err}"))?;
    // SAFETY: NUL-terminated path; a successful call returns a fresh fd.
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let err = io::Error::last_os_error();
        // Gone since the scan saw it: nothing to watch. Anything else (EMFILE
        // with many git directories) refuses rather than skipping the check.
        if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) {
            return Ok(());
        }
        return Err(format!(
            "cannot open the git directory {dir:?} for filesystem.protect: {err}"
        ));
    }
    // SAFETY: `raw` is a fresh descriptor returned by open.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let absent: Vec<&'static str> = GIT_REDIRECTS
        .into_iter()
        .filter(|n| cstring(n.as_bytes()).is_ok_and(|c| fstatat_nofollow(fd.as_fd(), &c).is_err()))
        .collect();
    if !absent.is_empty() {
        gitdirs.push(Watched {
            path: dir.to_path_buf(),
            fd,
            absent,
        });
    }
    Ok(())
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
    gitdirs: &mut Vec<Watched>,
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
        let push = |found: Found, out: &mut Vec<Found>| {
            if !skipped(found.path()) && !out.iter().any(|f| f.path() == found.path()) {
                out.push(found);
            }
        };
        for entry in entries {
            if let Some(found) = resolve(&dir, entry, depth == 0)? {
                push(found, out);
            }
        }
        let gitdir = dir.join(".git");
        let guards_git = entries
            .iter()
            .any(|e| e.comps.first().is_some_and(|c| c == ".git"));
        if guards_git && is_real_dir(&gitdir) && !is_marked(&gitdir) && !skipped(&gitdir) {
            let mut extra = Vec::new();
            git_extras(&gitdir, &mut extra, gitdirs)?;
            for found in extra {
                push(found, out);
            }
        }
        if depth == SEARCH_DEPTH {
            continue;
        }
        let mut children: Vec<PathBuf> = Vec::new();
        let reader = match std::fs::read_dir(&dir) {
            Ok(reader) => reader,
            // Another user's unreadable directory (a container volume): the
            // payload runs as this user and cannot change it either. One of
            // our own could be chmod'ed back by the payload, so it refuses.
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied && !owned(&dir) => {
                continue;
            }
            Err(err) => {
                return Err(format!(
                    "cannot scan {dir:?} for filesystem.protect: {err}; fix the permissions, or set filesystem.protect to [] to turn the protection off"
                ));
            }
        };
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

fn owned(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    std::fs::symlink_metadata(path).is_ok_and(|m| m.uid() == euid)
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Directories of a git directory that hold no protected file of their own.
const GIT_BULK: [&str; 4] = ["objects", "refs", "logs", "lfs"];

/// The git directories inside `.git` (module docs point 5): a linked
/// worktree's admin directory under `worktrees/` (its `commondir` and `gitdir`
/// redirect host git) and every submodule git directory under `modules/`
/// (its `hooks/`, `config` and `commondir`), plus every `config.worktree`.
/// Existing ones only. `gitdirs` collects the git directories that lack a
/// [`GIT_REDIRECTS`] file. A symlinked `worktrees` or `modules` is refused.
/// Runs only when the list protects something under `.git`.
fn git_extras(
    gitdir: &Path,
    out: &mut Vec<Found>,
    gitdirs: &mut Vec<Watched>,
) -> Result<(), String> {
    let existing = |path: PathBuf, out: &mut Vec<Found>| -> Result<(), String> {
        match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("cannot inspect protected path {path:?}: {err}")),
            Ok(meta) if meta.file_type().is_symlink() => Err(symlink_error(&path)),
            Ok(_) => {
                out.push(Found::Existing(path));
                Ok(())
            }
        }
    };
    // `worktrees` and `modules` themselves: read_dir would follow a link.
    let sub = |name: &str| -> Result<PathBuf, String> {
        let path = gitdir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(symlink_error(&path)),
            _ => Ok(path),
        }
    };
    // Children found through DirEntry::file_type, which does not follow links.
    let children = |dir: &Path| -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect();
        v.sort();
        v
    };
    // Only a linked worktree's admin directory has a commondir; one in a
    // `.git` directory is a redirect someone planted (a run with the
    // protection off, or one that died before its release).
    let planted = gitdir.join("commondir");
    if std::fs::symlink_metadata(&planted).is_ok() {
        return Err(format!(
            "{planted:?} exists; a .git directory never has a commondir file, and this one makes git on the host run hooks and read config from another directory. Inspect and remove it, or set filesystem.protect to [] to turn the protection off"
        ));
    }
    existing(gitdir.join("config.worktree"), out)?;
    watch(gitdir, gitdirs)?;
    for admin in children(&sub("worktrees")?) {
        for name in ["commondir", "gitdir", "config.worktree"] {
            existing(admin.join(name), out)?;
        }
        watch(&admin, gitdirs)?;
    }
    // Submodule git directories nest (`modules/a/modules/b`); a directory
    // with a HEAD file is one.
    let mut queue: VecDeque<(PathBuf, usize)> = children(&sub("modules")?)
        .into_iter()
        .map(|d| (d, 1))
        .collect();
    let mut visited = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        visited += 1;
        if visited > SCAN_BUDGET {
            return Err(format!(
                "the filesystem.protect scan of {gitdir:?} found more than {SCAN_BUDGET} submodule directories; set filesystem.protect to [] to turn the protection off"
            ));
        }
        let is_gitdir = dir.join("HEAD").is_file();
        if is_gitdir {
            for name in ["hooks", "config", "commondir", "config.worktree"] {
                existing(dir.join(name), out)?;
            }
            watch(&dir, gitdirs)?;
        }
        if depth >= 2 * SEARCH_DEPTH {
            continue;
        }
        for child in children(&dir) {
            let name = child
                .file_name()
                .map(|n| n.as_bytes().to_vec())
                .unwrap_or_default();
            if is_gitdir && (name == b"hooks" || GIT_BULK.iter().any(|b| name == b.as_bytes())) {
                continue;
            }
            queue.push_back((child, depth + 1));
        }
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
                return Ok(top.then(|| Found::Missing(dir.to_path_buf(), path)));
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

/// The parent of `path` (inside the rw path `root`), opened from `root`
/// component by component without following a symlink, and the last name.
fn split_under(root: &Path, path: &Path) -> io::Result<(OwnedFd, CString)> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let comps: Vec<&OsStr> = rel.iter().collect();
    let Some((last, dirs)) = comps.split_last() else {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    };
    let mut dir = open_dir(root)?;
    for comp in dirs {
        dir = open_child_dir(dir.as_fd(), &cstring(comp.as_bytes())?)?;
    }
    Ok((dir, cstring(last.as_bytes())?))
}

/// The temporary name a placeholder is built under, next to its final name.
fn temp_name(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    path.with_file_name(format!(
        ".sbx-protect.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Creates a placeholder at `path` (inside the rw path `root`): built under
/// the temporary name `tmp`, locked shared and marked there, then renamed into
/// place without replacing anything, so an unmarked or unlocked placeholder is
/// never visible at the protected name. `None`: the name appeared since the
/// scan.
fn create(root: &Path, path: &Path, tmp: &Path) -> Result<Option<Held>, String> {
    let fail = |err: io::Error| format!("cannot create the placeholder {path:?}: {err}");
    let (parent, name) = split_under(root, path).map_err(fail)?;
    let tmp_name = cstring(
        tmp.file_name()
            .ok_or_else(|| fail(io::Error::from_raw_os_error(libc::EINVAL)))?
            .as_bytes(),
    )
    .map_err(fail)?;
    // SAFETY: valid dir fd and NUL-terminated name.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), tmp_name.as_ptr(), 0o755) } != 0 {
        return Err(fail(io::Error::last_os_error()));
    }
    let discard = |parent: &OwnedFd| {
        // SAFETY: valid dir fd and NUL-terminated name.
        unsafe { libc::unlinkat(parent.as_raw_fd(), tmp_name.as_ptr(), libc::AT_REMOVEDIR) };
    };
    let built = (|| -> io::Result<OwnedFd> {
        let fd = open_child_dir(parent.as_fd(), &tmp_name)?;
        flock(fd.as_fd(), libc::LOCK_SH)?;
        let zero = [libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }; 2];
        // SAFETY: valid fd and a two-element timespec array.
        if unsafe { libc::futimens(fd.as_raw_fd(), zero.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    })();
    let fd = match built {
        Ok(fd) => fd,
        Err(err) => {
            discard(&parent);
            return Err(fail(err));
        }
    };
    if let Err(err) =
        crate::gc::sys::renameat2_noreplace(parent.as_fd(), &tmp_name, parent.as_fd(), &name)
    {
        discard(&parent);
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(None);
        }
        return Err(fail(err));
    }
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
    // The listed parent is the rw path or a real directory inside it: a
    // symlink in its place now is not followed (the next scan adopts instead).
    let (Some(parent_path), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let Ok(cparent) = cstring(parent_path.as_os_str().as_bytes()) else {
        return;
    };
    let Ok(name) = cstring(name.as_bytes()) else {
        return;
    };
    // SAFETY: NUL-terminated path; a successful call returns a fresh fd.
    let raw = unsafe {
        libc::open(
            cparent.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return;
    }
    // SAFETY: `raw` is a fresh descriptor returned by open.
    let parent = unsafe { OwnedFd::from_raw_fd(raw) };
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
    let mut gitdirs = Vec::new();
    for root in &fs.rw {
        scan_root(
            root.as_str(),
            &entries,
            &binds,
            &denies,
            &mut found,
            &mut gitdirs,
        )?;
    }
    Ok(found
        .into_iter()
        .map(|f| match f {
            Found::Existing(p) => (p.to_string_lossy().into_owned(), true),
            Found::Missing(_, p) => (p.to_string_lossy().into_owned(), false),
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
    fn submodule_and_worktree_git_dirs_are_targets() {
        let root = scratch("gitdirs");
        let git = root.join(".git");
        std::fs::create_dir_all(git.join("hooks")).unwrap();
        std::fs::write(git.join("config"), "").unwrap();
        std::fs::create_dir_all(git.join("worktrees/w")).unwrap();
        std::fs::write(git.join("worktrees/w/commondir"), "../..\n").unwrap();
        std::fs::write(git.join("worktrees/w/gitdir"), "/x/.git\n").unwrap();
        let sub = git.join("modules/lib");
        std::fs::create_dir_all(sub.join("hooks")).unwrap();
        std::fs::create_dir_all(sub.join("objects/aa")).unwrap();
        std::fs::write(sub.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(sub.join("config"), "").unwrap();
        let nested = sub.join("modules/inner");
        std::fs::create_dir_all(nested.join("hooks")).unwrap();
        std::fs::write(nested.join("HEAD"), "x\n").unwrap();
        let found = rel(&scan_for_test(&policy(&root, None, "")).unwrap(), &root);
        for want in [
            ".git/worktrees/w/commondir",
            ".git/worktrees/w/gitdir",
            ".git/modules/lib/hooks",
            ".git/modules/lib/config",
            ".git/modules/lib/modules/inner/hooks",
        ] {
            assert!(found.contains(&(want.into(), true)), "{want}: {found:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_new_commondir_is_renamed_aside() {
        let root = scratch("commondir");
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        let pol = policy(&root, Some(r#"[".git/hooks/"]"#), "");
        let mut prot = prepare(&pol, None).unwrap();
        std::fs::write(root.join(".git/commondir"), "/evil\n").unwrap();
        prot.release();
        assert!(!root.join(".git/commondir").exists());
        let aside = std::fs::read_dir(root.join(".git"))
            .unwrap()
            .flatten()
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("commondir.sbx-blocked.")
            });
        assert!(aside, "renamed aside, not deleted");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_worktree_is_protected_or_renamed_and_links_are_refused() {
        let root = scratch("cfgwt");
        let git = root.join(".git");
        std::fs::create_dir_all(git.join("hooks")).unwrap();
        std::fs::write(git.join("config.worktree"), "").unwrap();
        let found = rel(&scan_for_test(&policy(&root, None, "")).unwrap(), &root);
        assert!(
            found.contains(&(".git/config.worktree".into(), true)),
            "{found:?}"
        );
        // A new config.worktree in a git dir that had none is renamed aside.
        std::fs::remove_file(git.join("config.worktree")).unwrap();
        let mut prot = prepare(&policy(&root, Some(r#"[".git/hooks/"]"#), ""), None).unwrap();
        std::fs::write(git.join("config.worktree"), "[core]\n").unwrap();
        prot.release();
        assert!(!git.join("config.worktree").exists());
        // Without a .git entry in the list, sbx leaves .git alone.
        let found = scan_for_test(&policy(&root, Some(r#"[".bashrc"]"#), "")).unwrap();
        assert!(!found.iter().any(|(p, _)| p.contains("/.git")), "{found:?}");
        // A symlinked modules directory is refused, not followed.
        std::os::unix::fs::symlink("/usr", git.join("modules")).unwrap();
        let err = scan_for_test(&policy(&root, None, "")).unwrap_err();
        assert!(err.contains("is a symbolic link"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_host_rename_over_a_target_is_reported() {
        let root = scratch("lapse");
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n").unwrap();
        let mut prot = prepare(&policy(&root, Some(r#"[".git/config"]"#), ""), None).unwrap();
        assert!(prot.lapsed().is_empty());
        // git's lock-file rewrite: a new inode renamed over the target.
        std::fs::write(root.join(".git/config.lock"), "[core]\n").unwrap();
        std::fs::rename(root.join(".git/config.lock"), root.join(".git/config")).unwrap();
        let lapsed = prot.lapsed();
        assert_eq!(lapsed.len(), 1);
        assert!(lapsed[0].ends_with("/.git/config"), "{lapsed:?}");
        prot.release();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_planted_top_level_commondir_refuses() {
        let root = scratch("planted-commondir");
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        std::fs::write(root.join(".git/commondir"), "/elsewhere\n").unwrap();
        let err = scan_for_test(&policy(&root, None, "")).unwrap_err();
        assert!(err.contains("never has a commondir file"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn attach_list_round_trips_and_is_validated() {
        let root = scratch("saved");
        let session = scratch("saved-session");
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
        let pol = policy(&root, Some(r#"[".git/hooks/",".bashrc"]"#), "");
        let mut prot = prepare(&pol, Some(&session)).unwrap();
        prot.save(&session).unwrap();
        let loaded = load(&pol, &session).unwrap();
        assert_eq!(loaded.paths, prot.paths);
        assert!(loaded.held.is_empty() && loaded.gitdirs.is_empty());
        // A path outside the policy's rw paths is refused.
        std::fs::write(session.join(PATHS), b"/etc/shadow\0").unwrap();
        let err = load(&pol, &session).err().expect("refused");
        assert!(err.contains("is not inside an rw path"), "{err}");
        // A protecting policy needs the list.
        std::fs::remove_file(session.join(PATHS)).unwrap();
        assert!(load(&pol, &session).is_err());
        // The opt-out needs nothing.
        assert!(load(&policy(&root, Some("[]"), ""), &session).is_ok());
        prot.release();
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
