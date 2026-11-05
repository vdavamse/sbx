//! The policy pin of a persistent session (issue #18, design point 4).
//!
//! 1. **Identity by bytes.** The holder keeps the exact bytes of the policy it
//!    started with. An attach presents its own policy bytes; the session admits
//!    the call only when they are identical. The design named a hash; the pin
//!    keeps the bytes instead, which is a stricter test (no collision question)
//!    and needs no digest crate. The memory cost is one policy file.
//! 2. **Reading is bounded and non-blocking.** The file is opened with
//!    `O_NONBLOCK` and must be a regular file (a FIFO would hang the caller),
//!    and it is read at most [`MAX_POLICY_BYTES`] bytes, so an oversized file
//!    is refused rather than truncated and silently pinned.
//! 3. **Refusal reasons are fixed texts.** A mismatch is the pinned
//!    [`MISMATCH`] text; the caller maps it to rc 125.

use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

/// The refusal text for an attach whose policy differs from the session's.
pub(crate) const MISMATCH: &str = "policy differs from the session's policy";

/// The largest policy file a session pins or an attach presents (256 KiB).
pub(crate) const MAX_POLICY_BYTES: usize = 256 * 1024;

/// The policy bytes a session was started with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyPin(Vec<u8>);

impl PolicyPin {
    /// Pins `bytes`. Callers read them with [`read_policy_bytes`].
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// True only when `presented` is byte-for-byte the pinned policy.
    pub(crate) fn matches(&self, presented: &[u8]) -> bool {
        self.0.as_slice() == presented
    }

    /// The pinned bytes (the holder hands them to `run`'s policy loader).
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Reads a policy file for pinning or for an attach (rule 2).
pub(crate) fn read_policy_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    if !meta.file_type().is_file() {
        let kind = if meta.file_type().is_fifo() {
            "a FIFO"
        } else {
            "not a regular file"
        };
        return Err(format!(
            "policy {} is {kind}; expected a regular file",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    // One byte past the cap tells an oversized file from an exact-size one.
    (&mut file)
        .take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|err: io::Error| format!("cannot read {}: {err}", path.display()))?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "policy {} is larger than {MAX_POLICY_BYTES} bytes",
            path.display()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "sbx-keepalive-pin-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, bytes).expect("write temp policy");
        path
    }

    #[test]
    fn pin_matches_only_identical_bytes() {
        let pin = PolicyPin::new(b"{\"version\":1}\n".to_vec());
        assert!(pin.matches(b"{\"version\":1}\n"));
        assert!(
            !pin.matches(b"{\"version\":1}"),
            "a trailing newline counts"
        );
        assert!(!pin.matches(b"{\"version\":2}\n"));
        assert!(!pin.matches(b""));
        assert_eq!(pin.bytes(), b"{\"version\":1}\n");
    }

    #[test]
    fn read_returns_exact_bytes() {
        let path = temp_file("exact", b"policy-bytes");
        assert_eq!(read_policy_bytes(&path).unwrap(), b"policy-bytes");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_refuses_an_oversized_file() {
        let big = vec![b'x'; MAX_POLICY_BYTES + 1];
        let path = temp_file("big", &big);
        let err = read_policy_bytes(&path).unwrap_err();
        assert!(err.contains("larger than"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_accepts_exactly_the_cap() {
        let exact = vec![b'x'; MAX_POLICY_BYTES];
        let path = temp_file("cap", &exact);
        assert_eq!(read_policy_bytes(&path).unwrap().len(), MAX_POLICY_BYTES);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_refuses_a_fifo_without_hanging() {
        let path = std::env::temp_dir().join(format!("sbx-keepalive-fifo-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = read_policy_bytes(&path).unwrap_err();
        assert!(err.contains("a FIFO"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_reports_a_missing_file() {
        let err = read_policy_bytes(Path::new("/nonexistent/sbx-policy.json")).unwrap_err();
        assert!(
            err.starts_with("cannot read /nonexistent/sbx-policy.json"),
            "{err}"
        );
    }
}
