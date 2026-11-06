//! Issue #17: the CLI surface of opt-in TLS termination.
//!
//! The policy gate is shared by `sbx check --policy` and `sbx run`, so both
//! must agree: a binary built without the `tls-termination` feature refuses a
//! policy that names mitm hosts (check rc 1, run rc 125, no session directory
//! created); a feature build accepts it at `check`. Standard libtest: the
//! refusal happens before any namespace or bwrap work, so no privilege is
//! needed.

use std::path::{Path, PathBuf};
use std::process::Command;

const MITM_POLICY: &str = r#"{
  "version": 1,
  "filesystem": { "ro": ["/usr"], "rw": [], "deny": [] },
  "network": {
    "mode": "transparent",
    "allow": ["=api.example.com"],
    "ports": [443],
    "mitm_hosts": ["api.example.com"],
    "paths": ["https://api.example.com/v1/"]
  },
  "env": { "pass": [], "set": {} },
  "limits": { "timeout": "30s", "output_bytes": 1048576 }
}"#;

/// A scratch directory unique to this test process and name.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sbx-termination-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn write_policy(dir: &Path) -> PathBuf {
    let path = dir.join("mitm.json");
    std::fs::write(&path, MITM_POLICY).expect("policy file");
    path
}

#[test]
fn check_gates_mitm_policies_on_the_build_feature() {
    let dir = scratch("check");
    let policy = write_policy(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["check", "--policy"])
        .arg(&policy)
        .output()
        .expect("spawn sbx check");
    let stderr = String::from_utf8_lossy(&out.stderr);
    if cfg!(feature = "tls-termination") {
        assert_eq!(out.status.code(), Some(0), "{stderr}");
    } else {
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains(
                "network.mitm_hosts requires an sbx built with the tls-termination feature"
            ),
            "{stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(feature = "tls-termination"))]
#[test]
fn run_refuses_before_creating_any_session_directory() {
    let dir = scratch("run");
    let policy = write_policy(&dir);
    let session = dir.join("session");
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["run", "--policy"])
        .arg(&policy)
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "/bin/true"])
        .output()
        .expect("spawn sbx run");
    assert_eq!(
        out.status.code(),
        Some(125),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("network.mitm_hosts requires an sbx built with the tls-termination feature"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !session.exists(),
        "a refused policy must not create the session"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
