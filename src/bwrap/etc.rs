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
//! 4. **Idempotent materialization** — [`SessionLayout::materialize`]
//!    writes the same bytes on every call (create+truncate), so retries and
//!    relaunches are free and the `sbx gc` (#12) interplay stays simple.
//!    Files are explicitly 0644 (umask-independent; sandbox-internal
//!    permissions are irrelevant — single uid 0); directories get the
//!    `create_dir_all` defaults under the umask. The session ROOT's
//!    lifecycle belongs to #10/#12: `materialize` creates it implicitly
//!    (`create_dir_all`) but never deletes anything.

use std::path::{Path, PathBuf};

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

impl SessionLayout {
    /// Create the directories and write the three synthetic files with
    /// their pinned contents — idempotent (module docs point 4): the same
    /// bytes on every call, existing files truncated and rewritten, so a
    /// retry after a failed launch is free.
    ///
    /// The session root itself is created implicitly (`create_dir_all`) —
    /// its lifecycle (creation policy, garbage collection) belongs to
    /// #10/#12, not here.
    pub fn materialize(&self) -> std::io::Result<()> {
        // create_dir_all for every leaf's parent chain: work/home/tmp plus
        // etc_dir (which shares the session root).
        for dir in [&self.work, &self.home, &self.tmp, &self.etc_dir] {
            std::fs::create_dir_all(dir)?;
        }
        for (path, content) in [
            (&self.resolv_conf, RESOLV_CONF_CONTENT),
            (&self.passwd, PASSWD_CONTENT),
            (&self.group, GROUP_CONTENT),
        ] {
            // create + truncate + write: identical bytes on every call —
            // idempotent by construction (a tampered or partial file from
            // an interrupted earlier run is simply rewritten).
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)?;
            std::io::Write::write_all(&mut file, content.as_bytes())?;
            set_mode_0644(path)?;
        }
        Ok(())
    }
}

// Explicit 0644: umask-independent host-side tidiness (the bind is
// read-only inside the sandbox, and every sandbox process is uid 0 — the
// mode is not a security boundary, module docs point 4).
fn set_mode_0644(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
    fn materialize_creates_pinned_layout_idempotently() {
        // Scratch dir under temp_dir (the from_file_reports_non_utf8
        // precedent); this test is the only user of this exact name, so
        // parallel cargo test cannot collide with it.
        let dir = std::env::temp_dir().join(format!("sbx-bwrap-etc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = session_layout(&dir);
        layout.materialize().expect("materialize must succeed");

        // The four directories exist (and the session root with them).
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
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o644, "{} must be 0644", path.display());
        }

        // Idempotent: a tampered file is truncated and rewritten to the
        // pinned bytes by the second call — no-op-diff semantics for
        // retries/relaunches (module docs point 4).
        std::fs::write(&layout.passwd, b"tampered").expect("scratch must be writable");
        layout
            .materialize()
            .expect("second materialize must succeed");
        assert_eq!(
            std::fs::read(&layout.passwd).expect("file must exist"),
            PASSWD_CONTENT.as_bytes()
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn permissions_ext_mode_pinned_shape() {
        // Meta-test for the 0o644 helper contract: from_mode(0o644) yields
        // exactly rw-r--r-- under any umask (set_permissions is explicit,
        // not umask-filtered).
        let dir = std::env::temp_dir().join(format!("sbx-bwrap-etc-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        let path = dir.join("f");
        std::fs::write(&path, b"x").expect("writable");
        set_mode_0644(&path).expect("set_mode_0644 must succeed");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o644);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
