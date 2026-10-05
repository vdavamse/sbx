//! bwrap discovery and version parsing (issue #6, Q10).
//!
//! 1. **Version floor** — [`BWRAP_MIN`] is the `--disable-userns` floor
//!    (bwrap 0.8.0; CI's Ubuntu noble ships 0.9.0). Call sites compare
//!    with plain tuple `>=` (component-wise NUMERIC — `(0,10,0) >=
//!    (0,8,0)`, never lexical). [`parse_version`] returning `None` means
//!    "unparseable", NOT "too old" — callers treat both as not-usable
//!    (fail-closed); #11 reports which one it was.
//! 2. **Discovery order** — `SBX_BWRAP` override (the test/CI hook:
//!    returned VERBATIM when set and non-empty — no existence or
//!    absoluteness check; [`super::build`]'s absolute check and the spawn
//!    failure are the fail-closed backstops) → `PATH` scan (first
//!    `<dir>/bwrap` that is a file with any execute bit; NON-ABSOLUTE
//!    entries are SKIPPED — unlike a shell's PATH search, an empty or
//!    relative entry must never resolve the sandbox-enforcement binary
//!    against the cwd) → fixed
//!    fallbacks `/usr/local/bin/bwrap`, `/usr/bin/bwrap`, `/bin/bwrap`
//!    (PATH is unset or empty in #10's env_clear world). Else `None` —
//!    callers SKIP or report, never guess.
//! 3. **Purity** — [`find_bwrap`] is the env-reading shell around the
//!    private `find_bwrap_with(override, path)`: unit tests pass the env
//!    values as parameters and never mutate the process environment
//!    (thread-hostile under parallel `cargo test` — the D13 rationale).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The minimum bwrap version sbx can use: 0.8.0 introduced
/// `--disable-userns`, which the hardening block depends on (issue #6;
/// the kernel also requires `--unshare-user` for it, which the argv
/// always carries).
pub const BWRAP_MIN: (u32, u32, u32) = (0, 8, 0);

/// Parse `bwrap --version` output — strict grammar, fail-closed.
///
/// The trimmed input must start with the literal `bubblewrap` followed by
/// whitespace; the next whitespace-delimited token must be `X.Y` or
/// `X.Y.Z` with all-numeric `u32` components (a missing patch means `.0`,
/// so `"bubblewrap 0.8"` → `Some((0, 8, 0))` — two-component spellings are
/// tolerated). Anything else (`"bubblewrap 0.9.0-1"`, `"bwrap 0.9"`, the
/// empty string) → `None`. Content AFTER the version token is ignored
/// (build metadata spellings); `None` is "unparseable", not "too old"
/// (module docs point 1).
pub fn parse_version(output: &str) -> Option<(u32, u32, u32)> {
    let rest = output.trim().strip_prefix("bubblewrap")?;
    // Whitespace must separate the program token from the version token:
    // "bubblewrap0.9.0" is not a version line.
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let token = rest.split_whitespace().next()?;
    let mut components = token.split('.');
    let major = parse_component(components.next()?)?;
    let minor = parse_component(components.next()?)?;
    let patch = match components.next() {
        Some(text) => parse_component(text)?,
        None => 0, // "bubblewrap 0.8" ⇒ (0, 8, 0)
    };
    // Four or more components is not the grammar.
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

// One version component: non-empty, all ASCII digits, u32-representable.
// Rejects "", "+1", "0-1" (the "bubblewrap 0.9.0-1" distro-suffix case)
// and u32 overflow — all fail-closed to None.
fn parse_component(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Locate the bwrap binary (module docs point 2): `SBX_BWRAP` override →
/// `PATH` scan → fixed fallbacks. `None` when nothing is found — callers
/// SKIP (integration tests) or report (#11), never guess.
pub fn find_bwrap() -> Option<PathBuf> {
    find_bwrap_with(
        std::env::var_os("SBX_BWRAP").as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

// The pure core (module docs point 3): env values arrive as parameters, so
// the unit tests below never touch the process environment.
fn find_bwrap_with(override_env: Option<&OsStr>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    // (1) SBX_BWRAP: verbatim when set and non-empty — deliberately no
    // existence/absoluteness check here (build()'s absolute check and the
    // spawn failure are the fail-closed backstops); an empty value is not
    // a path and falls through.
    if let Some(path) = override_env {
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    // (2) PATH scan: first <dir>/bwrap that is a FILE with any execute
    // bit. Non-absolute entries are SKIPPED (review round 2) — this is
    // deliberately NOT the shell's PATH search, where an empty entry
    // resolves against the cwd: momentarily entertaining a cwd-planted
    // ./bwrap as the sandbox-enforcement binary is the wrong posture for
    // a security tool, and a hit would shadow every legitimate absolute
    // entry later in PATH only to die at build()'s row-1 absolute check
    // (fail-closed, but a confusing launch failure with /usr/bin/bwrap
    // sitting right there).
    if let Some(path_var) = path_var {
        for dir in std::env::split_paths(path_var) {
            if !dir.is_absolute() {
                continue;
            }
            let candidate = dir.join("bwrap");
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    // (3) Fixed fallbacks, first existing file. An existing-but-broken
    // (non-executable) bwrap is returned and fails closed at spawn time
    // with a real diagnostic — silently skipping it to a fallback would
    // hide the broken install.
    for candidate in ["/usr/local/bin/bwrap", "/usr/bin/bwrap", "/bin/bwrap"] {
        let candidate = Path::new(candidate);
        if candidate.is_file() {
            return Some(candidate.to_path_buf());
        }
    }
    None
}

// A regular file with any execute bit (u/g/o — the spawn runs as the
// current user, but a host install executable by ANYONE is a usable
// discovery signal; the exec itself is the authority).
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The fixed fallback list — host-dependent (CI HAS /usr/bin/bwrap,
    /// local WSL does not), so tests that fall through to step (3) assert
    /// membership in this set instead of a specific outcome.
    const FALLBACKS: [&str; 3] = ["/usr/local/bin/bwrap", "/usr/bin/bwrap", "/bin/bwrap"];

    fn is_fallback_or_none(found: &Option<PathBuf>) -> bool {
        match found {
            None => true,
            Some(path) => FALLBACKS.iter().any(|f| path == Path::new(f)),
        }
    }

    #[test]
    fn parse_version_table() {
        let cases = [
            // Accepted spellings (module docs: strict token grammar).
            ("bubblewrap 0.9.0", Some((0, 9, 0))),
            ("bubblewrap 0.9.0\n", Some((0, 9, 0))), // trailing newline (command output)
            ("  bubblewrap 0.8  ", Some((0, 8, 0))), // trimmed; two components ⇒ patch .0
            ("bubblewrap 0.10.0", Some((0, 10, 0))), // numeric, not lexical (0.10 ≥ 0.8)
            ("bubblewrap 1.2.3", Some((1, 2, 3))),
            ("bubblewrap\t0.9.0", Some((0, 9, 0))), // any whitespace separates
            ("bubblewrap 0.9.0 (noble)", Some((0, 9, 0))), // content after the token is ignored
            // Rejected — None is "unparseable", callers treat it as
            // not-usable (fail-closed).
            ("bubblewrap 0.9.0-1", None), // distro suffix on the token
            ("bwrap 0.9", None),          // wrong program token
            ("", None),
            ("bubblewrap", None),         // no version token
            ("bubblewrap0.9.0", None),    // no whitespace after the program token
            ("bubblewrap 0.9.0.1", None), // four components
            ("bubblewrap x.y.z", None),
            ("bubblewrap 0.-1.0", None),
            ("bubblewrap .9.0", None),            // empty component
            ("bubblewrap 99999999999.0.0", None), // u32 overflow
        ];
        for (input, expected) in cases {
            assert_eq!(parse_version(input), expected, "{input:?}");
        }
    }

    #[test]
    fn bwrap_min_pinned_and_numeric() {
        // The --disable-userns floor (issue #6) — pinned; comparison is
        // component-wise numeric via plain tuple >= (never string-lexical:
        // "0.10.0" < "0.8.0" as TEXT but (0,10,0) > (0,8,0) as tuples).
        assert_eq!(BWRAP_MIN, (0, 8, 0));
        assert!(parse_version("bubblewrap 0.8.0").is_some_and(|v| v >= BWRAP_MIN));
        assert!(parse_version("bubblewrap 0.10.0").is_some_and(|v| v >= BWRAP_MIN));
        assert!(parse_version("bubblewrap 0.9.0").is_some_and(|v| v >= BWRAP_MIN));
        assert!(!parse_version("bubblewrap 0.7.9").is_some_and(|v| v >= BWRAP_MIN));
    }

    #[test]
    fn find_bwrap_override_wins_verbatim() {
        // SBX_BWRAP is returned VERBATIM when set and non-empty — no
        // existence check (the fail-closed backstops are build()'s
        // absolute check and the spawn failure).
        let found = find_bwrap_with(Some(OsStr::new("/opt/custom/bwrap")), None);
        assert_eq!(found.as_deref(), Some(Path::new("/opt/custom/bwrap")));
        // An empty override is not a path: it falls through to the fixed
        // fallbacks (host-dependent — assert membership only).
        let found = find_bwrap_with(Some(OsStr::new("")), None);
        assert!(is_fallback_or_none(&found), "unexpected result {found:?}");
        // No override, no PATH: same — the fixed fallbacks or None.
        let found = find_bwrap_with(None, None);
        assert!(is_fallback_or_none(&found), "unexpected result {found:?}");
    }

    #[test]
    fn find_bwrap_path_scan_requires_executable_file() {
        // Scratch dir (etc.rs precedent); only this test uses these names,
        // so parallel cargo test cannot collide.
        let dir = std::env::temp_dir().join(format!("sbx-bwrap-version-{}", std::process::id()));
        let bin = dir.join("bin");
        let noexec = dir.join("noexec");
        let asdir = dir.join("asdir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&bin).expect("temp dirs must be creatable");
        std::fs::create_dir_all(&noexec).expect("temp dirs must be creatable");
        std::fs::create_dir_all(asdir.join("bwrap")).expect("temp dirs must be creatable");

        // (a) An executable file named bwrap is found.
        let exe = bin.join("bwrap");
        std::fs::write(&exe, b"#!/bin/sh\n").expect("scratch must be writable");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            find_bwrap_with(None, Some(bin.as_os_str())).as_deref(),
            Some(exe.as_path())
        );

        // (b) A non-executable file is skipped (falls through to the fixed
        // fallbacks — never the noexec path).
        let bad = noexec.join("bwrap");
        std::fs::write(&bad, b"#!/bin/sh\n").expect("scratch must be writable");
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let found = find_bwrap_with(None, Some(noexec.as_os_str()));
        assert!(
            found.as_deref() != Some(bad.as_path()),
            "a non-executable file must be skipped: {found:?}"
        );
        assert!(is_fallback_or_none(&found), "unexpected result {found:?}");

        // (c) A DIRECTORY named bwrap is not a binary.
        let found = find_bwrap_with(None, Some(asdir.as_os_str()));
        assert!(
            found.as_deref() != Some(asdir.join("bwrap").as_path()),
            "a directory must be skipped: {found:?}"
        );

        // (d) PATH order: the first directory lacks bwrap, the second has
        // it — the second is returned.
        let joined = format!("{}:{}", noexec.display(), bin.display());
        assert_eq!(
            find_bwrap_with(None, Some(OsStr::new(&joined))).as_deref(),
            Some(exe.as_path())
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn find_bwrap_skips_relative_path_entries() {
        // Review round 2: empty/relative PATH entries must never resolve
        // bwrap against the cwd. Plant an executable ./bwrap in the
        // process cwd (the package root under cargo test) and scan
        // PATH=":" — the empty entry yields the relative candidate
        // "bwrap", which the pre-fix scan happily returned, shadowing
        // every legitimate absolute entry after it. Post-fix the result
        // is a fixed fallback or None (host-dependent — assert
        // absoluteness/membership, never the planted file). The guard
        // removes the plant on EVERY exit path (panic included); no other
        // test in this binary probes a relative PATH, so the plant cannot
        // disturb the parallel runs.
        struct CwdGuard(PathBuf);
        impl Drop for CwdGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let planted = std::env::current_dir()
            .expect("cwd must be readable")
            .join("bwrap");
        let _guard = CwdGuard(planted.clone());
        assert!(
            !planted.exists(),
            "the package root must not already contain a bwrap file"
        );
        std::fs::write(&planted, b"#!/bin/sh\n").expect("cwd must be writable");
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let found = find_bwrap_with(None, Some(OsStr::new(":")));
        assert_ne!(
            found.as_deref(),
            Some(Path::new("bwrap")),
            "the empty entry's cwd-relative candidate must be skipped (it \
             exists and is executable — the pre-fix scan returned it)"
        );
        assert_ne!(
            found.as_deref(),
            Some(planted.as_path()),
            "the cwd-planted bwrap must never be returned"
        );
        assert!(
            found.as_ref().is_none_or(|path| path.is_absolute()),
            "discovery must yield absolute candidates only: {found:?}"
        );
        assert!(is_fallback_or_none(&found), "unexpected result {found:?}");

        // A relative directory entry is skipped the same way — even one
        // that WOULD contain an executable bwrap when resolved against
        // the cwd (the plant above is exactly that candidate: "." +
        // "/bwrap").
        let found = find_bwrap_with(None, Some(OsStr::new(".")));
        assert_ne!(
            found.as_deref(),
            Some(Path::new("./bwrap")),
            "a relative PATH entry must be skipped: {found:?}"
        );
        assert!(is_fallback_or_none(&found), "unexpected result {found:?}");
    }
}
