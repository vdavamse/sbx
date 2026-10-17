//! Pre-launch path verification (#39 / #40): the S8a guard.
//!
//! bwrap 0.9.0 resolves every bind dest and every `--tmpfs` mask by walking
//! the destination path inside the sandbox root, and it follows symlinks
//! there. A payload that ran earlier under a writable bind (or that still
//! sits in a reused session leaf) can therefore plant a symlink that makes
//! bwrap create a directory, or mount over, an arbitrary host path (CVE-2026-
//! 87766). The payload also controls the contents of every writable tree, so
//! sbx cannot trust them. This module checks, before anything is spawned,
//! that every path bwrap will resolve under a writable cover is a real
//! directory chain (no symlinks, nothing missing, the right type), and that
//! no deny mask is reachable on the host through a second path.
//!
//! The walk is fd-relative: each component is `openat(O_PATH | O_NOFOLLOW)`
//! from the previous one and then `fstat`ed. This is the semantics of
//! `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)`, without needing that
//! syscall (no ENOSYS fallback), and it names the failing component.
//!
//! Coverage: every bind, deny and pin under a policy or session mount, read-only
//! covers included (a planted link under a read-only bind still redirects
//! bwrap's setup-time mkdir to the host). Residuals (R26, R27): a writer that
//! is not a sandbox of this exact policy (a different policy, an older sbx,
//! a host process, a host bind-mount alias of the tree) can change a component
//! between this check and bwrap's setup. Hard links made on the host are not
//! seen at run time (`sbx check` warns on them).

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::argv::{AliasCheck, BindSpec, Kind, PathCheck};

/// A refusal reason (the `run` layer adds the `sbx run: ` prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError(String);

impl GuardError {
    /// A refusal with the given reason text.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

/// The `(on the way to …)` suffix, omitted when the component IS the target.
/// A pinned directory says so: the failing component is then sbx's own pin,
/// not a policy entry.
fn way(here: &str, check: &PathCheck) -> String {
    let cover = if check.writable {
        "the rw path"
    } else {
        "the read-only bind"
    };
    if check.pinned {
        format!("(a pinned directory inside {cover} {:?})", check.origin)
    } else if here == check.target {
        format!("(inside {cover} {:?})", check.origin)
    } else {
        format!(
            "(on the way to {:?} inside {cover} {:?})",
            check.target, check.origin
        )
    }
}

/// `fstat` on an open `O_PATH` descriptor.
fn fstat(fd: &OwnedFd) -> std::io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is a valid open descriptor and `st` is a writable
    // `struct stat` that fstat fills completely on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: initialized by the successful fstat above.
    Ok(unsafe { st.assume_init() })
}

/// `openat(dir, name, O_PATH | O_NOFOLLOW | O_CLOEXEC)`: never follows a
/// symlink in the final component, and resolves nothing but `name` itself.
fn open_nofollow(dir: &OwnedFd, name: &[u8]) -> std::io::Result<OwnedFd> {
    let name = CString::new(name).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `dir` is a valid descriptor, `name` is NUL-terminated, and a
    // successful call returns a fresh descriptor we take ownership of.
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor returned by openat.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Verifies one path check. `Ok` means bwrap resolves `target` through real
/// directories only, and everything below an existing prefix is either
/// present (and of the right type) or, for a session leaf, left to bwrap.
pub fn verify(check: &PathCheck) -> Result<(), GuardError> {
    let root = CString::new(check.root.as_os_str().as_bytes())
        .map_err(|_| GuardError(format!("cannot verify {:?}: NUL byte", check.root)))?;
    // SAFETY: NUL-terminated path; a successful call returns a fresh
    // descriptor that `OwnedFd` takes ownership of.
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let err = std::io::Error::last_os_error();
        if check.allow_missing && err.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(GuardError(format!(
            "cannot verify filesystem path {:?} {}: {err}",
            check.root,
            way(&check.origin, check)
        )));
    }
    // SAFETY: `raw` is a fresh descriptor returned by open.
    let mut cur = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut here = check.origin.clone();
    let last_index = check.rel.len().saturating_sub(1);
    for (i, comp) in check.rel.iter().enumerate() {
        here.push('/');
        here.push_str(comp);
        let next = match open_nofollow(&cur, comp.as_bytes()) {
            Ok(fd) => fd,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if check.allow_missing {
                    return Ok(());
                }
                return Err(GuardError(format!(
                    "filesystem path {here:?} does not exist {}; create it on the host or remove the entry",
                    way(&here, check)
                )));
            }
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                return Err(symlink_error(&here, check));
            }
            Err(err) => {
                return Err(GuardError(format!(
                    "cannot verify filesystem path {here:?} {}: {err}",
                    way(&here, check)
                )));
            }
        };
        let st = fstat(&next).map_err(|err| {
            GuardError(format!(
                "cannot verify filesystem path {here:?} {}: {err}",
                way(&here, check)
            ))
        })?;
        let fmt = st.st_mode & libc::S_IFMT;
        if fmt == libc::S_IFLNK {
            return Err(symlink_error(&here, check));
        }
        let dest_dir = fmt == libc::S_IFDIR;
        if i != last_index {
            if !dest_dir {
                return Err(GuardError(format!(
                    "filesystem path {here:?} is not a directory {}",
                    way(&here, check)
                )));
            }
        } else {
            match &check.kind {
                Kind::Dir => {
                    if !dest_dir {
                        return Err(GuardError(format!(
                            "filesystem path {here:?} is not a directory {}",
                            way(&here, check)
                        )));
                    }
                }
                Kind::LikeSource(src) => {
                    // An unreadable source is bwrap's to report; only a
                    // readable one can disagree with the destination.
                    match std::fs::metadata(src).map(|m| m.is_dir()).ok() {
                        Some(true) if !dest_dir => {
                            return Err(GuardError(format!(
                                "filesystem path {here:?} is not a directory but its bind source {src:?} is"
                            )));
                        }
                        Some(false) if dest_dir => {
                            return Err(GuardError(format!(
                                "filesystem path {here:?} is a directory but its bind source {src:?} is not"
                            )));
                        }
                        _ => {}
                    }
                }
            }
        }
        cur = next;
    }
    Ok(())
}

fn symlink_error(here: &str, check: &PathCheck) -> GuardError {
    GuardError(format!(
        "unsafe filesystem path {here:?}: it is a symbolic link {}; refusing to start because bwrap would follow it during setup",
        way(here, check)
    ))
}

/// The canonical form of `p`, or `None` when it does not exist.
fn realpath(p: &Path, cache: &mut BTreeMap<PathBuf, Option<PathBuf>>) -> Option<PathBuf> {
    cache
        .entry(p.to_path_buf())
        .or_insert_with(|| std::fs::canonicalize(p).ok())
        .clone()
}

/// Verifies the host-symlink aliases of the deny masks (#40, Q5). Let `D` be a
/// deny path and `S` a policy bind (source `src`, dest `dest`), both resolved
/// on the host, and `cd`, `cs` their realpaths. Refused when:
/// - `cd` lies under `cs` and `dest/<cd - cs>` is not `D`: the mask is
///   reached through the bind at another path, so it does not cover that
///   inode; or
/// - `cs` lies under `cd` (the bind's content IS the deny's content, reached
///   through a link) and the bind dest is not under `D`: the bind exposes the
///   masked directory at a path the mask does not hide.
///
/// Paths that do not exist are skipped (the walk or bwrap report them).
pub fn verify_aliases(aliases: &[AliasCheck]) -> Result<(), GuardError> {
    let mut cache = BTreeMap::new();
    for a in aliases {
        let deny = PathBuf::from(&a.deny);
        let (Some(cd), Some(cs)) = (realpath(&deny, &mut cache), realpath(&a.src, &mut cache))
        else {
            continue;
        };
        if let Ok(rel) = cd.strip_prefix(&cs) {
            let mapped = PathBuf::from(&a.dest).join(rel);
            if mapped != deny {
                return Err(GuardError(format!(
                    "deny path {:?} is reachable on the host as {:?} through the bind of {:?} (mounted at {:?}); refusing to start because the deny mask would not cover that path",
                    a.deny,
                    mapped.display().to_string(),
                    a.src,
                    a.dest
                )));
            }
        }
        if cs.starts_with(&cd) && !Path::new(&a.dest).starts_with(&deny) {
            return Err(GuardError(format!(
                "the bind of {:?} (mounted at {:?}) is the deny path {:?} reached through a host symbolic link; refusing to start because the mask would not hide it",
                a.src, a.dest, a.deny
            )));
        }
    }
    Ok(())
}

/// Whether two binds' real sources nest the same way their lexical sources
/// do: `lb` under `lc` lexically must mean `rb` under `rc` with the same suffix,
/// and the reverse; equal lexical sources need equal real sources.
fn nests_consistently(lb: &Path, lc: &Path, rb: &Path, rc: &Path) -> bool {
    if lb == lc {
        return rb == rc;
    }
    if let Ok(rel) = lb.strip_prefix(lc) {
        return rb == rc.join(rel);
    }
    if let Ok(rel) = lc.strip_prefix(lb) {
        return rc == rb.join(rel);
    }
    false
}

/// N19 (#40): refuses a policy or session bind whose real source overlaps
/// another bind's real source, when the overlap is not the lexical nesting.
/// Such a bind is mounted under a path the payload can rename or re-create
/// through a symbolic link into a writable tree, so no pin or walk on its
/// lexical chain can hold. Applies whenever either bind is writable: two
/// read-only binds cannot be changed by the payload. Binds that do not exist
/// are skipped.
pub fn verify_binds(binds: &[BindSpec]) -> Result<(), GuardError> {
    let mut cache = BTreeMap::new();
    let real: Vec<Option<PathBuf>> = binds.iter().map(|b| realpath(&b.src, &mut cache)).collect();
    for (i, b) in binds.iter().enumerate() {
        let Some(rb) = &real[i] else { continue };
        for (j, c) in binds.iter().enumerate().skip(i + 1) {
            let Some(rc) = &real[j] else { continue };
            if !(b.writable || c.writable) {
                continue;
            }
            if !(rb.starts_with(rc) || rc.starts_with(rb)) {
                continue;
            }
            if nests_consistently(&b.src, &c.src, rb, rc) {
                continue;
            }
            let kind = |w: bool| if w { "writable" } else { "read-only" };
            return Err(GuardError(format!(
                "the {} bind {:?} (mounted at {:?}) resolves on the host to {:?}, which overlaps the {} bind {:?} (mounted at {:?}, resolving to {:?}) through a host symbolic link; refusing to start because the payload could change the shared tree and swap the source between runs; bind the real path instead",
                kind(b.writable),
                b.src,
                b.dest,
                rb,
                kind(c.writable),
                c.src,
                c.dest,
                rc
            )));
        }
    }
    Ok(())
}

/// The check-time hard-link scan budget: directory entries visited under one
/// deny path before the scan stops and says so (Q6; a run never scans).
pub const LINK_SCAN_BUDGET: usize = 10_000;

/// Regular files under `dir` (a deny path) that have another hard link, so
/// the mask hides only one of their names. Bounded by [`LINK_SCAN_BUDGET`];
/// symlinks are not followed. A non-directory yields nothing.
pub fn hard_links_under(dir: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    // lstat the root first: a symlink root is not scanned (read_dir would
    // follow it into the host tree it names).
    if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
        return out;
    }
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > LINK_SCAN_BUDGET {
                out.push(format!(
                    "{} (not fully scanned: more than {LINK_SCAN_BUDGET} entries)",
                    dir.display()
                ));
                return out;
            }
            // `DirEntry::metadata` is lstat: symlinks are neither dirs nor files here.
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() && meta.nlink() > 1 {
                out.push(entry.path().display().to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sbx-guard-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn check(root: &Path, rel: &[&str], kind: Kind, allow_missing: bool) -> PathCheck {
        PathCheck {
            target: format!("/w/{}", rel.join("/")),
            origin: "/w".to_owned(),
            root: root.to_path_buf(),
            rel: rel.iter().map(|s| (*s).to_owned()).collect(),
            kind,
            pinned: false,
            writable: true,
            allow_missing,
        }
    }

    #[test]
    fn read_only_cover_tolerates_missing_but_not_links() {
        // A ro cover: bwrap aborts on a missing dest itself, so the walk
        // defers the missing case; a planted link is still refused.
        let d = tmp("rocover");
        std::fs::create_dir_all(d.join("r")).unwrap();
        assert!(verify(&check(&d, &["r", "x", "y"], Kind::Dir, true)).is_ok());
        std::os::unix::fs::symlink(d.join("r"), d.join("l")).unwrap();
        let err = verify(&check(&d, &["l", "x"], Kind::Dir, true)).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    #[test]
    fn pinned_failures_say_so() {
        let d = tmp("pinmsg");
        let mut c = check(&d, &["a", "b"], Kind::Dir, false);
        c.pinned = true;
        let err = verify(&c).unwrap_err();
        assert!(err.to_string().contains("a pinned directory"), "{err}");
    }

    #[test]
    fn bind_containing_the_deny_through_a_link_is_refused() {
        // Direction 2: the bind's source is a link into the deny's directory.
        let d = tmp("alias2");
        std::fs::create_dir_all(d.join("q/secrets/sub")).unwrap();
        std::os::unix::fs::symlink(d.join("q/secrets/sub"), d.join("lnk")).unwrap();
        let bad = AliasCheck {
            deny: d.join("q/secrets").display().to_string(),
            src: d.join("lnk"),
            dest: d.join("lnk").display().to_string(),
        };
        let err = verify_aliases(&[bad]).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        // The same bind under the deny's own dest is allowed.
        let under = AliasCheck {
            deny: d.join("q/secrets").display().to_string(),
            src: d.join("lnk"),
            dest: d.join("q/secrets/sub").display().to_string(),
        };
        assert!(verify_aliases(&[under]).is_ok());
    }

    #[test]
    fn ok_when_every_component_is_a_real_directory() {
        let d = tmp("ok");
        std::fs::create_dir_all(d.join("a/b/s")).unwrap();
        assert!(verify(&check(&d, &["a", "b", "s"], Kind::Dir, false)).is_ok());
    }

    #[test]
    fn symlink_intermediate_and_leaf_are_refused() {
        let d = tmp("sym");
        std::fs::create_dir_all(d.join("real/s")).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("a")).unwrap();
        let err = verify(&check(&d, &["a", "s"], Kind::Dir, false)).unwrap_err();
        assert!(err.to_string().contains("it is a symbolic link"), "{err}");
        std::fs::create_dir_all(d.join("c")).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("c/leaf")).unwrap();
        let err = verify(&check(&d, &["c", "leaf"], Kind::Dir, false)).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    #[test]
    fn missing_is_refused_unless_allowed() {
        let d = tmp("miss");
        let strict = verify(&check(&d, &["x", "y"], Kind::Dir, false)).unwrap_err();
        assert!(strict.to_string().contains("does not exist"), "{strict}");
        assert!(verify(&check(&d, &["x", "y"], Kind::Dir, true)).is_ok());
        assert!(
            !d.join("x").exists(),
            "the verifier must not create anything"
        );
    }

    #[test]
    fn file_and_directory_mismatches_are_refused() {
        let d = tmp("type");
        std::fs::create_dir_all(d.join("dir")).unwrap();
        std::fs::write(d.join("file"), b"x").unwrap();
        std::fs::write(d.join("mid"), b"x").unwrap();
        // A file where a directory must be on the way.
        let err = verify(&check(&d, &["mid", "z"], Kind::Dir, false)).unwrap_err();
        assert!(err.to_string().contains("is not a directory"), "{err}");
        // A deny target that is a file.
        let err = verify(&check(&d, &["file"], Kind::Dir, false)).unwrap_err();
        assert!(err.to_string().contains("is not a directory"), "{err}");
        // Dest kind disagrees with the bind source kind, both ways.
        let err = verify(&check(
            &d,
            &["file"],
            Kind::LikeSource(d.join("dir")),
            false,
        ))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("is not a directory but its bind source"),
            "{err}"
        );
        let err = verify(&check(
            &d,
            &["dir"],
            Kind::LikeSource(d.join("file")),
            false,
        ))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("is a directory but its bind source"),
            "{err}"
        );
        assert!(verify(&check(&d, &["dir"], Kind::LikeSource(d.join("dir")), false)).is_ok());
    }

    #[test]
    fn non_ascii_names_are_walked_verbatim() {
        let d = tmp("utf8");
        std::fs::create_dir_all(d.join("ä/ß")).unwrap();
        assert!(verify(&check(&d, &["ä", "ß"], Kind::Dir, false)).is_ok());
        std::os::unix::fs::symlink(d.join("ä"), d.join("ü")).unwrap();
        assert!(verify(&check(&d, &["ü", "ß"], Kind::Dir, false)).is_err());
    }

    fn bind(src: PathBuf, writable: bool) -> BindSpec {
        BindSpec {
            dest: src.display().to_string(),
            src,
            writable,
        }
    }

    #[test]
    fn host_alias_overlap_is_refused_ro_and_rw() {
        // N19: `lnk -> real`; ro lnk/p next to rw real (or rw lnk/p) is refused.
        let d = tmp("n19");
        std::fs::create_dir_all(d.join("real/p")).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("lnk")).unwrap();
        let rw_real = bind(d.join("real"), true);
        let ro_alias = bind(d.join("lnk/p"), false);
        let err = verify_binds(&[ro_alias.clone(), rw_real.clone()]).unwrap_err();
        assert!(
            err.to_string().contains("through a host symbolic link"),
            "{err}"
        );
        let rw_alias = bind(d.join("lnk/p"), true);
        assert!(verify_binds(&[rw_real.clone(), rw_alias]).is_err());
        // Two read-only binds cannot be changed by the payload: allowed.
        let ro_real = bind(d.join("real"), false);
        assert!(verify_binds(&[ro_alias, ro_real]).is_ok());
        // No alias at all: lexical nesting is fine.
        assert!(verify_binds(&[rw_real, bind(d.join("real/p"), false)]).is_ok());
    }

    #[test]
    fn consistent_alias_nesting_is_allowed() {
        // `lnk2 -> real2`: lnk2 rw and lnk2/sub ro nest the same way their
        // real paths do, so the overlap is the lexical one.
        let d = tmp("n19ok");
        std::fs::create_dir_all(d.join("real2/sub")).unwrap();
        std::os::unix::fs::symlink(d.join("real2"), d.join("lnk2")).unwrap();
        let binds = [bind(d.join("lnk2"), true), bind(d.join("lnk2/sub"), false)];
        assert!(verify_binds(&binds).is_ok());
    }

    #[test]
    fn a_symlink_root_is_not_scanned() {
        // m4: the root is lstat-ed first; a link to a real directory with a
        // hard-linked file is not followed.
        let d = tmp("linkroot");
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::fs::write(d.join("real/f"), b"f").unwrap();
        std::fs::hard_link(d.join("real/f"), d.join("real/g")).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("link")).unwrap();
        assert!(hard_links_under(&d.join("link")).is_empty());
        assert_eq!(hard_links_under(&d.join("real")).len(), 2);
    }

    #[test]
    fn hard_links_are_found_inside_a_deny_dir_only() {
        let d = tmp("links");
        std::fs::create_dir_all(d.join("deny/sub")).unwrap();
        std::fs::write(d.join("deny/sub/key"), b"K").unwrap();
        std::fs::write(d.join("deny/lone"), b"L").unwrap();
        std::fs::hard_link(d.join("deny/sub/key"), d.join("outside-name")).unwrap();
        let found = hard_links_under(&d.join("deny"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].ends_with("deny/sub/key"), "{found:?}");
        // A non-directory and a missing path yield nothing.
        assert!(hard_links_under(&d.join("deny/lone")).is_empty());
        assert!(hard_links_under(&d.join("missing")).is_empty());
    }

    #[test]
    fn alias_of_a_deny_path_is_refused() {
        let d = tmp("alias");
        std::fs::create_dir_all(d.join("proj/secrets")).unwrap();
        std::os::unix::fs::symlink(d.join("proj"), d.join("alias")).unwrap();
        let deny = d.join("proj/secrets").display().to_string();
        // The real bind maps the deny onto itself: fine.
        let ok = AliasCheck {
            deny: deny.clone(),
            src: d.join("proj"),
            dest: d.join("proj").display().to_string(),
        };
        assert!(verify_aliases(&[ok]).is_ok());
        // The symlink bind exposes the same inode at another path.
        let bad = AliasCheck {
            deny,
            src: d.join("alias"),
            dest: d.join("alias").display().to_string(),
        };
        let err = verify_aliases(&[bad]).unwrap_err();
        assert!(err.to_string().contains("reachable on the host"), "{err}");
    }
}
