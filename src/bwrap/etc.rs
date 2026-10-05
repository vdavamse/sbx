//! Session layout + the synthetic `/etc` files (issue #6).
//!
//! 1. **Why on disk** — fd-passing synthetic files (`--ro-bind-data`) is
//!    impossible: #5's `fd_hygiene` closes every fd > 2 before the payload
//!    exec (Q6). The generated files therefore live under `<session>/etc/`
//!    and the argv builder binds each one individually (`--ro-bind`).
//! 2. **Layout** — `<session>/{work,home,tmp}` (the three writable leaves)
//!    plus `<session>etc/{resolv.conf,passwd,group}`. Only the leaves are
//!    ever bind-mounted into the sandbox — the session directory itself and
//!    its parent never are (allow-list purity, [`super`] module docs point
//!    3). Sandbox destinations: `work` → [`DEST_WORK`], `home` →
//!    [`DEST_HOME`] (the sandbox uid is 0 — #5's id maps are `0 <outer> 1`
//!    — so HOME is `/root`, Q7), `tmp` → [`DEST_TMP`].
//! 3. **Pinned contents** — `resolv.conf` points DNS at the netns-local
//!    resolver (`127.0.0.1:53` — the nft rules redirect udp/53 there, #9);
//!    `passwd`/`group` describe the single root identity (Q7) so
//!    `id`/`whoami`/getpwuid consumers resolve WITHOUT binding the host's
//!    `/etc/passwd`. Every file ends in exactly one `\n` — pinned
//!    byte-exact by the tests below.
//! 4. **Idempotent, hardened materialization** —
//!    [`SessionLayout::materialize`] writes the same bytes on every call
//!    (create+truncate), so retries and relaunches are free and the
//!    `sbx gc` (#12) interplay stays simple. It is hardened against a
//!    local attacker who can pre-create parts of the session path
//!    (session naming/uniqueness is #10's — this API cannot assume it)
//!    and against a previous sandboxed payload holding an unfortunate
//!    policy bind: a root-alias/non-canonical session dir is rejected
//!    BEFORE any I/O (`check_session_dir` — [`super::build`]'s rows 5–6
//!    twin; `materialize` is public and callable without `build()`);
//!    directories are private-by-default (created AND re-pinned 0700 —
//!    `work`/`home`/`tmp` hold the untrusted command's checkout and
//!    artifacts, which umask-default 0755 would expose to every local
//!    user) and VERIFIED on a single `O_NOFOLLOW | O_DIRECTORY` fd (real
//!    directories — never symlinks — owned by the effective uid, fchmod
//!    re-pin) — the session root and below: ANCESTORS of `session_dir`
//!    are kernel-resolved and #10's placement contract (unique,
//!    unguessable names under a root- or euid-owned base), and the
//!    recursive creation gives any implicitly-created ancestors 0700 too
//!    (#10 handoff: a root daemon materializing under a shared base for
//!    per-user spawners would block traversal); the synthetic files are
//!    opened `O_NOFOLLOW | O_NONBLOCK`, type-gated on the fd (regular
//!    files only) and chmodded on the FD, so a planted
//!    `<session>/etc/passwd` symlink fails closed (ELOOP) instead of
//!    redirecting the truncate+write onto its target (CWE-59), and a
//!    planted FIFO fails closed instantly (ENXIO — or the fd type gate
//!    with a reader attached) instead of hanging the open. Files are
//!    explicitly 0644
//!    (umask-independent; sandbox-internal permissions are irrelevant —
//!    single uid 0). The session ROOT's lifecycle belongs to #10/#12:
//!    `materialize` creates it implicitly but never deletes anything.

use std::fs::Permissions;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Sandbox-side destination of the session's `work/` leaf (Q7) — also the
/// builder's default `--chdir` target.
pub const DEST_WORK: &str = "/work";

/// Sandbox-side destination of the session's `home/` leaf (Q7). The sandbox
/// uid is 0 (#5's id maps are `0 <outer> 1`), so HOME is `/root`.
pub const DEST_HOME: &str = "/root";

/// Sandbox-side destination of the session's `tmp/` leaf (Q7) — also the
/// `TMPDIR` value.
pub const DEST_TMP: &str = "/tmp";

/// Pinned content of the generated `/etc/resolv.conf` (Q6): all DNS goes to
/// the netns-local resolver — #9 serves `127.0.0.1:53` (the nft rules
/// redirect udp/53 there). Exactly one trailing `\n`.
pub const RESOLV_CONF_CONTENT: &str = "nameserver 127.0.0.1\n";

/// Pinned content of the generated `/etc/passwd` (Q7): the single root
/// identity the sandbox uid 0 resolves against. Exactly one trailing `\n`.
pub const PASSWD_CONTENT: &str = "root:x:0:0:root:/root:/bin/bash\n";

/// Pinned content of the generated `/etc/group` (Q7). Exactly one trailing
/// `\n`.
pub const GROUP_CONTENT: &str = "root:x:0:\n";

/// The host-side session directory layout — pure path joins, no validation,
/// no I/O ([`session_layout`]); [`SessionLayout::materialize`] is the
/// side-effecting half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLayout {
    /// The session directory itself (never bind-mounted — only the leaves
    /// below are).
    pub session_dir: PathBuf,
    /// `<session>/work` — writable, binds to [`DEST_WORK`].
    pub work: PathBuf,
    /// `<session>/home` — writable, binds to [`DEST_HOME`].
    pub home: PathBuf,
    /// `<session>/tmp` — writable, binds to [`DEST_TMP`].
    pub tmp: PathBuf,
    /// `<session>/etc` — holds the generated files; the DIRECTORY is never
    /// bound (each file is bound individually, module docs point 1).
    pub etc_dir: PathBuf,
    /// `<session>/etc/resolv.conf` — generated, content
    /// [`RESOLV_CONF_CONTENT`].
    pub resolv_conf: PathBuf,
    /// `<session>/etc/passwd` — generated, content [`PASSWD_CONTENT`].
    pub passwd: PathBuf,
    /// `<session>/etc/group` — generated, content [`GROUP_CONTENT`].
    pub group: PathBuf,
}

/// Compute the layout for `session_dir` — pure joins (module docs point 2);
/// nothing is created or validated. `session_dir` absoluteness is
/// [`super::build`]'s job (row 3 of its validation table).
pub fn session_layout(session_dir: &Path) -> SessionLayout {
    let etc_dir = session_dir.join("etc");
    SessionLayout {
        work: session_dir.join("work"),
        home: session_dir.join("home"),
        tmp: session_dir.join("tmp"),
        resolv_conf: etc_dir.join("resolv.conf"),
        passwd: etc_dir.join("passwd"),
        group: etc_dir.join("group"),
        etc_dir,
        session_dir: session_dir.to_path_buf(),
    }
}

/// The session-dir lexical rules shared by [`super::build`] (validation
/// rows 5–6) and [`SessionLayout::materialize`] (which is public and
/// callable WITHOUT `build()`) — one source for the pinned messages, so
/// both seams reject identically.
///
/// Rejects the host root under every alias spelling (`/`, `//`, `/.` —
/// `components()` collapses separator runs and normalizes `.` away, so
/// RootDir-only IS the alias class): with `--session-dir /`,
/// `materialize()` would truncate and rewrite the host's OWN
/// `/etc/{resolv.conf,passwd,group}` (guaranteed destruction when sbx
/// runs as root; only EACCES saves it otherwise), and the leaves would
/// bind the host's `/home` and `/tmp` rw into the sandbox. Rejects
/// non-canonical segments — `.`, `..`, empty (`//` interior / trailing
/// slash) — with `check_path`'s exact lexical vocabulary: the layout
/// joins are pure, so a TOCTOU-prone spelling like `/etc/..` aliases
/// host directories (`Path::new("/etc/..").join("passwd")` resolves to
/// the HOST's `/passwd` neighborhood, not the session's). The segment
/// scan runs on raw BYTES (`components()` cannot see `.` or `//` — they
/// are normalized away — and bytes are the non-UTF-8-safe spelling of
/// `check_path`'s string split).
///
/// Absoluteness is NOT checked here — [`super::build`] row 3 owns that
/// rule for the argv path, and a relative (but canonical) `session_dir`
/// stays `materialize`'s documented caller choice.
pub(super) fn check_session_dir(dir: &Path) -> Result<(), String> {
    // Root aliases first: components() collapses "//" and normalizes "."
    // away, so [RootDir] exactly == every spelling of the host root.
    if dir.components().eq(std::iter::once(Component::RootDir)) {
        return Err(format!(
            "session directory must not be the host root (got {dir:?})"
        ));
    }
    // Then the segment rules, on raw bytes. skip-first: the segment
    // before an absolute path's first '/' is empty by construction (the
    // check_path skip(1) precedent).
    use std::os::unix::ffi::OsStrExt;
    let bytes = dir.as_os_str().as_bytes();
    let mut segments = bytes.split(|byte| *byte == b'/');
    if bytes.first() == Some(&b'/') {
        segments.next();
    }
    if segments.any(|seg| seg.is_empty() || seg == b"." || seg == b"..") {
        return Err(format!(
            "session directory must be lexically canonical: no '.', '..' or empty ('//'/trailing-slash) segments (got {dir:?})"
        ));
    }
    Ok(())
}

impl SessionLayout {
    /// Create the directories and write the three synthetic files with
    /// their pinned contents — idempotent (module docs point 4): the same
    /// bytes on every call, existing files truncated and rewritten, so a
    /// retry after a failed launch is free.
    ///
    /// Hardened (module docs point 4): the root-alias guard runs BEFORE
    /// any I/O; directories are created 0700, then verified AND re-pinned
    /// on a single `O_NOFOLLOW | O_DIRECTORY` fd (fstat owner check +
    /// fchmod — no replace race between check and chmod), so an
    /// attacker-planted symlink or foreign-owned directory AT THE SESSION
    /// ROOT OR BELOW fails closed instead of receiving the synthetic
    /// files. ANCESTORS of `session_dir` are resolved by the kernel and
    /// are #10's placement contract: unique, unguessable names under a
    /// root-owned or euid-owned base — a predictable multi-component path
    /// under a world-writable base remains redirectable by an ancestor
    /// plant (documented limitation; #10/#14). The files are opened
    /// `O_NOFOLLOW | O_NONBLOCK`, type-gated on the fd (regular files
    /// only — a planted FIFO fails closed instantly instead of hanging
    /// the open) and chmodded on the fd (race-free — a path-based
    /// `set_permissions` has a replace race).
    ///
    /// The session root itself is created implicitly — its lifecycle
    /// (creation policy, garbage collection) belongs to #10/#12, not here.
    pub fn materialize(&self) -> std::io::Result<()> {
        // Guard before ANY I/O (build() rows 5–6 twin — see
        // check_session_dir): a root-alias session dir would aim the pure
        // layout joins at the host's own /etc, /home, /tmp.
        check_session_dir(&self.session_dir).map_err(invalid_input)?;
        // Create every leaf's parent chain (work/home/tmp plus etc_dir,
        // which implicitly creates the session root) — privately.
        for dir in [&self.work, &self.home, &self.tmp, &self.etc_dir] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(dir)?;
        }
        // Verify + re-pin EVERY directory on a single fd each (see
        // check_private_dir — no check-then-chmod replace race), the
        // implicitly-created session root included: a pre-existing dir was
        // not created by the DirBuilder above, so its type/owner/mode are
        // unchecked until here. The re-pin also tightens dirs an earlier,
        // pre-hardening sbx left behind at umask defaults.
        for dir in [
            &self.session_dir,
            &self.work,
            &self.home,
            &self.tmp,
            &self.etc_dir,
        ] {
            check_private_dir(dir)?;
        }
        for (path, content) in [
            (&self.resolv_conf, RESOLV_CONF_CONTENT),
            (&self.passwd, PASSWD_CONTENT),
            (&self.group, GROUP_CONTENT),
        ] {
            write_synthetic_file(path, content)?;
        }
        Ok(())
    }
}

/// Private-by-default session directories (review round 2): the umask
/// default (typically 0755) would make the untrusted command's checkout,
/// artifacts and scratch data world-readable.
const DIR_MODE: u32 = 0o700;

fn invalid_input(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

// A REAL directory owned by the effective uid, verified AND re-pinned on
// ONE fd (review round 2): symlink_metadata-then-path-chmod has a replace
// race between the two calls — the file side avoids it with fd-chmod, and
// so does this. O_NOFOLLOW: a planted symlink at the final component fails
// ELOOP; O_DIRECTORY: a non-directory fails ENOTDIR — both surface as the
// pinned "real directory" message. The fstat owner check and the fchmod
// then run against the SAME opened inode, so a swap between check and
// chmod cannot redirect the pin. (Ancestor components are still
// kernel-resolved — #10's placement contract; see materialize's doc.)
fn check_private_dir(dir: &Path) -> std::io::Result<()> {
    let dir_fd = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
    {
        Ok(fd) => fd,
        Err(err) if matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
            return Err(invalid_input(format!(
                "{} must be a real directory (not a symlink or file)",
                dir.display()
            )));
        }
        Err(err) => return Err(err),
    };
    let meta = dir_fd.metadata()?;
    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(invalid_input(format!(
            "{} must be owned by the invoking user (uid {euid})",
            dir.display()
        )));
    }
    // fchmod on the fd — race-free re-pin to private.
    dir_fd.set_permissions(Permissions::from_mode(DIR_MODE))
}

// create + truncate + write: identical bytes on every call — idempotent
// by construction (a tampered or partial file from an interrupted earlier
// run is simply rewritten). O_NOFOLLOW: a planted symlink at the file's
// path fails ELOOP instead of truncating+overwriting the TARGET with the
// pinned bytes (CWE-59 — the payload of an earlier run, or any local user
// who can pre-create the session path, must not be able to steer this
// write). O_NONBLOCK (review round 3): a planted FIFO fails the open
// instantly (ENXIO) instead of blocking until a reader appears — a hang
// is the one non-fail-closed outcome this hardened path must not have;
// the flag is a no-op for regular files. The fd-based type gate then
// rejects the openable residuals (a FIFO WITH a cooperative reader
// attached, a char device): only a regular file receives the pinned
// bytes — same single-fd, race-free discipline as check_private_dir.
// The chmod runs on the FD, not the path: race-free, and
// umask-independent (the open's .mode() is umask-filtered; the explicit
// set makes 0644 exact). The 0644 is host-side tidiness, not a security
// boundary (the bind is read-only inside the sandbox and every sandbox
// process is uid 0 — module docs point 3/4).
fn write_synthetic_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(invalid_input(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    std::io::Write::write_all(&mut file, content.as_bytes())?;
    file.set_permissions(Permissions::from_mode(FILE_MODE))
}

/// Explicit 0644 for the synthetic files (see [`write_synthetic_file`]).
const FILE_MODE: u32 = 0o644;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Scratch dir under temp_dir (the from_file_reports_non_utf8
    /// precedent); each test uses its own name, so parallel cargo test
    /// cannot collide.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sbx-bwrap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn dest_and_content_consts_pinned() {
        // The Q6/Q7 pinned surface: sandbox destinations and the synthetic
        // file bytes. Any edit here is a deliberate, reviewed change — the
        // argv goldens AND the integration scenarios assert the same
        // literals.
        assert_eq!(DEST_WORK, "/work");
        assert_eq!(DEST_HOME, "/root");
        assert_eq!(DEST_TMP, "/tmp");
        assert_eq!(RESOLV_CONF_CONTENT, "nameserver 127.0.0.1\n");
        assert_eq!(PASSWD_CONTENT, "root:x:0:0:root:/root:/bin/bash\n");
        assert_eq!(GROUP_CONTENT, "root:x:0:\n");
    }

    #[test]
    fn session_layout_is_pure_joins() {
        let layout = session_layout(Path::new("/tmp/s"));
        assert_eq!(layout.session_dir, Path::new("/tmp/s"));
        assert_eq!(layout.work, Path::new("/tmp/s/work"));
        assert_eq!(layout.home, Path::new("/tmp/s/home"));
        assert_eq!(layout.tmp, Path::new("/tmp/s/tmp"));
        assert_eq!(layout.etc_dir, Path::new("/tmp/s/etc"));
        assert_eq!(layout.resolv_conf, Path::new("/tmp/s/etc/resolv.conf"));
        assert_eq!(layout.passwd, Path::new("/tmp/s/etc/passwd"));
        assert_eq!(layout.group, Path::new("/tmp/s/etc/group"));
        // Pure: computing a layout creates nothing.
        let absent = session_layout(Path::new("/nonexistent/sbx-etc-layout-test"));
        assert!(
            !absent.work.exists(),
            "session_layout must not touch the filesystem"
        );
    }

    #[test]
    fn check_session_dir_rejects_root_aliases() {
        // Review round 2 (major): the pure layout joins make a root-alias
        // session dir aim straight at host directories —
        // Path::new("/").join("etc") IS the host's /etc. Every alias
        // spelling is rejected with the pinned messages (build() rows 5–6
        // and materialize()'s pre-I/O guard share this helper).
        assert_eq!(
            check_session_dir(Path::new("/")).unwrap_err(),
            r#"session directory must not be the host root (got "/")"#
        );
        assert_eq!(
            check_session_dir(Path::new("//")).unwrap_err(),
            r#"session directory must not be the host root (got "//")"#
        );
        // "/." IS the host root (components() normalizes the "." away) —
        // the root message, not the lexical one.
        assert_eq!(
            check_session_dir(Path::new("/.")).unwrap_err(),
            r#"session directory must not be the host root (got "/.")"#
        );
        // Non-canonical segments: check_path's exact lexical vocabulary.
        const LEXICAL: &str = "session directory must be lexically canonical: no '.', '..' or empty ('//'/trailing-slash) segments";
        for bad in ["/etc/..", "/tmp/x/./y", "/tmp/s/", "/tmp//s", ""] {
            let err = check_session_dir(Path::new(bad)).unwrap_err();
            assert!(err.starts_with(LEXICAL), "{err}");
            assert!(err.ends_with(&format!("(got {bad:?})")), "{err}");
        }
        // Legal shapes pass.
        for ok in ["/tmp/s", "/var/lib/sbx/s1"] {
            assert_eq!(check_session_dir(Path::new(ok)), Ok(()), "{ok}");
        }
        // Absoluteness is NOT this helper's job (build() row 3 owns it;
        // materialize keeps its documented relative-dir caller choice —
        // canonical relative paths stay legal).
        assert_eq!(check_session_dir(Path::new("rel/ative")), Ok(()));
        // Relative traversal spellings are rejected too ("../escape").
        assert!(check_session_dir(Path::new("../escape")).is_err());
        assert!(check_session_dir(Path::new("./s")).is_err());
    }

    #[test]
    fn materialize_guards_run_before_any_io() {
        // The guard is materialize()'s FIRST statement — proven with
        // spellings whose would-be layout targets are unwritable even for
        // root (procfs), so a regressed guard fails loudly here instead
        // of touching the host. Root aliases ("/", "//") are pinned
        // through check_session_dir above and through build()'s rows 5–6
        // (golden_error_pins) — deliberately NOT materialized here: a
        // regressed guard running as root would clobber the host's /etc
        // before the assertion could fire.
        let err = session_layout(Path::new("/proc/self/.."))
            .materialize()
            .expect_err("a non-canonical session dir must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            r#"session directory must be lexically canonical: no '.', '..' or empty ('//'/trailing-slash) segments (got "/proc/self/..")"#
        );
        let err = session_layout(Path::new("/"))
            .materialize()
            .expect_err("the host root must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            r#"session directory must not be the host root (got "/")"#
        );
    }

    #[test]
    fn materialize_creates_pinned_layout_idempotently() {
        let dir = scratch("etc");
        let layout = session_layout(&dir);
        layout.materialize().expect("materialize must succeed");

        // The five directories exist (the session root implicitly with
        // the leaves) — and are PRIVATE (0700, review round 2: the
        // umask default would expose the payload's checkout/artifacts to
        // every local user).
        for created in [
            &dir,
            &layout.work,
            &layout.home,
            &layout.tmp,
            &layout.etc_dir,
        ] {
            assert!(
                created.is_dir(),
                "{} must be a directory",
                created.display()
            );
            assert_eq!(
                mode_of(created),
                0o700,
                "{} must be 0700",
                created.display()
            );
        }
        // The three files: byte-exact pinned contents, 0644.
        for (path, content) in [
            (&layout.resolv_conf, RESOLV_CONF_CONTENT),
            (&layout.passwd, PASSWD_CONTENT),
            (&layout.group, GROUP_CONTENT),
        ] {
            assert_eq!(
                std::fs::read(path).expect("file must exist"),
                content.as_bytes(),
                "{}",
                path.display()
            );
            assert_eq!(mode_of(path), 0o644, "{} must be 0644", path.display());
        }

        // Idempotent: a tampered file is truncated and rewritten to the
        // pinned bytes by the second call — no-op-diff semantics for
        // retries/relaunches (module docs point 4) — and a loosened dir
        // mode is re-pinned to 0700 (an earlier, pre-hardening sbx or a
        // foreign umask cannot leave the session world-readable).
        std::fs::write(&layout.passwd, b"tampered").expect("scratch must be writable");
        std::fs::set_permissions(&layout.work, Permissions::from_mode(0o755)).expect("chmod");
        layout
            .materialize()
            .expect("second materialize must succeed");
        assert_eq!(
            std::fs::read(&layout.passwd).expect("file must exist"),
            PASSWD_CONTENT.as_bytes()
        );
        assert_eq!(mode_of(&layout.work), 0o700, "mode must be re-pinned");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn materialize_rejects_planted_symlink_file() {
        // Review round 2 (major, CWE-59): a symlink planted at a
        // synthetic file's path must NOT redirect the truncate+write onto
        // its target — O_NOFOLLOW fails ELOOP instead, and the target's
        // bytes/mode are untouched. (Attacker model: any local user who
        // can pre-create the session path — session naming/uniqueness is
        // #10's and cannot be assumed here — or a previous run's payload
        // holding an unfortunate policy bind; build() row 13 rejects the
        // policy half, O_NOFOLLOW the pre-planted half.)
        let dir = scratch("etc-symlink-file");
        let victim = dir.join("victim");
        let session = dir.join("session");
        std::fs::create_dir_all(session.join("etc")).expect("temp dirs must be creatable");
        std::fs::write(&victim, b"sentinel-bytes").expect("scratch must be writable");
        std::fs::set_permissions(&victim, Permissions::from_mode(0o600)).expect("chmod");
        std::os::unix::fs::symlink(&victim, session.join("etc/passwd")).expect("symlink");

        let layout = session_layout(&session);
        let err = layout
            .materialize()
            .expect_err("a planted symlink must fail closed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got: {err}"
        );
        // The target is untouched — neither truncated+rewritten nor
        // chmodded (the fd-based set_permissions never saw it).
        assert_eq!(
            std::fs::read(&victim).expect("victim must survive"),
            b"sentinel-bytes"
        );
        assert_eq!(mode_of(&victim), 0o600);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn materialize_rejects_planted_fifo() {
        // Review round 3 (minor): the one non-fail-closed outcome the
        // O_NOFOLLOW hardening left — a FIFO planted at a synthetic
        // file's path passes the symlink gate but blocks an O_WRONLY
        // open indefinitely when no reader ever attaches (`sbx run`
        // wedges before any timeout applies). O_NONBLOCK makes the
        // readerless open fail instantly (ENXIO — phase 1), and the fd
        // type gate rejects the openable residual: a FIFO WITH a
        // cooperative reader attached (phase 2). Reachability is narrow
        // — the dir gate stops the cross-uid planter one layer earlier,
        // leaving same-uid plants — but the DIRECTORY side already fails
        // fast on its analogous plant (O_DIRECTORY → ENOTDIR), so the
        // file side must too.
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::FileTypeExt as _;

        let dir = scratch("etc-fifo-file");
        let session = dir.join("session");
        std::fs::create_dir_all(session.join("etc")).expect("temp dirs must be creatable");
        let fifo = session.join("etc").join("passwd");
        let c_path =
            std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("scratch path is NUL-free");
        // SAFETY: mkfifo(3) takes a valid NUL-terminated path pointer and
        // a mode; the CString keeps the scratch-path bytes alive for the
        // duration of the call, and nothing else creates this path.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let layout = session_layout(&session);

        // Phase 1 — no reader: the open fails instantly instead of
        // hanging. This assertion RETURNING is the hang-regression pin:
        // a regressed flag fails as a test-suite timeout, not a silent
        // pass.
        let err = layout
            .materialize()
            .expect_err("a readerless FIFO must fail closed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENXIO),
            "expected ENXIO from O_NONBLOCK on a readerless FIFO, got: {err}"
        );

        // Phase 2 — cooperative reader attached: the open SUCCEEDS, so
        // the fd type gate is the half that rejects, with the pinned
        // InvalidInput message. O_RDONLY|O_NONBLOCK opens a readerless
        // FIFO instantly (POSIX), so no spawn/timing race is involved.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .expect("a nonblocking read-open of a FIFO must succeed");
        let err = layout
            .materialize()
            .expect_err("a FIFO must fail closed even with a reader");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("must be a regular file"),
            "unexpected message: {err}"
        );
        drop(reader);

        // The FIFO itself survived — never opened for write, truncated
        // nor replaced (the type gate runs before any byte is written).
        assert!(
            std::fs::symlink_metadata(&fifo)
                .expect("fifo must survive")
                .file_type()
                .is_fifo()
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn materialize_rejects_symlinked_or_foreign_dirs() {
        // Review round 2 (major): the dir verification half — a symlinked
        // <session>/etc (create_dir_all-style creation FOLLOWS it) fails
        // the real-directory check, so nothing below a redirected path
        // receives the synthetic files.
        let dir = scratch("etc-symlink-dir");
        let elsewhere = dir.join("elsewhere");
        let session = dir.join("session");
        std::fs::create_dir_all(&elsewhere).expect("temp dirs must be creatable");
        std::fs::create_dir_all(&session).expect("temp dirs must be creatable");
        std::os::unix::fs::symlink(&elsewhere, session.join("etc")).expect("symlink");

        let layout = session_layout(&session);
        let err = layout
            .materialize()
            .expect_err("a symlinked etc dir must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("must be a real directory"),
            "unexpected message: {err}"
        );
        // Nothing was written through the symlink.
        assert!(!elsewhere.join("passwd").exists());

        // The owner check's negative half needs a second uid (foreign
        // pre-created dirs) — untestable without privilege; the positive
        // half (owner == euid) runs in every materialize above. The
        // check itself is pinned by construction: check_private_dir
        // compares the fstat uid of the single O_NOFOLLOW|O_DIRECTORY fd
        // against geteuid().
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
