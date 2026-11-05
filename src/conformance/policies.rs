//! The built-in policies (issue #13, §8.1). Operator policies are out of v1
//! (Q8): these are the only policies the host tier runs.

use std::path::Path;

use serde_json::{Value, json};

/// The three host-tier policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// `p-transparent`: transparent mode, the full allow list.
    Transparent,
    /// `p-explicit`: explicit mode, the conformance name only.
    Explicit,
    /// `p-lab-transparent` (PR2): transparent, the conformance name only.
    LabTransparent,
    /// `p-none`: mode none (NXDOMAIN for everything).
    NoNetwork,
}

/// The allow list of the transparent policy. `=exact.conformance.test` is the
/// exact-only rule A13 exercises (issue #44).
pub const TRANSPARENT_ALLOW: [&str; 4] = [
    "allowed.conformance.test",
    "pypi.org",
    "localhost",
    "=exact.conformance.test",
];
/// The allow list of the explicit and none policies.
pub const ALLOWED_ONLY: [&str; 1] = ["allowed.conformance.test"];

/// The policy's JSON text. `exe` is the sbx binary path bound read-only (omitted
/// when it lives under `/usr/`, which is already bound).
pub fn policy_json(which: Builtin, exe: &str, network_tag: Option<&str>) -> String {
    let _ = network_tag;
    let mut ro = vec![json!("/usr")];
    if !exe.starts_with("/usr/") {
        ro.push(json!(exe));
    }
    let (mode, allow, ports): (&str, Vec<&str>, Vec<u16>) = match which {
        Builtin::Transparent => ("transparent", TRANSPARENT_ALLOW.to_vec(), vec![443, 80]),
        Builtin::Explicit => ("explicit", ALLOWED_ONLY.to_vec(), vec![443, 80]),
        Builtin::LabTransparent => ("transparent", ALLOWED_ONLY.to_vec(), vec![443, 80]),
        Builtin::NoNetwork => ("none", ALLOWED_ONLY.to_vec(), vec![443]),
    };
    let doc: Value = json!({
        "version": 1,
        "filesystem": {"ro": ro, "rw": [], "deny": []},
        "network": {"mode": mode, "allow": allow, "ports": ports},
        "env": {"pass": ["SBX_CONFORMANCE_PASSED"], "set": {"SBX_CONFORMANCE_SET": "1"}},
        "limits": {"timeout": "30s", "output_bytes": 1048576}
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// A filesystem policy for the #40 scenarios (D11, D12): mode none, `/usr`
/// and the sbx binary read-only, the given rw and deny paths.
pub fn fs_policy_json(exe: &str, rw: &[String], deny: &[String]) -> String {
    paths_policy_json(exe, &[], rw, deny)
}

/// [`fs_policy_json`] plus extra read-only binds (#45, D13-D15).
pub fn paths_policy_json(exe: &str, ro_extra: &[String], rw: &[String], deny: &[String]) -> String {
    let mut ro = vec![json!("/usr")];
    if !exe.starts_with("/usr/") {
        ro.push(json!(exe));
    }
    ro.extend(ro_extra.iter().map(|p| json!(p)));
    let doc: Value = json!({
        "version": 1,
        "filesystem": {"ro": ro, "rw": rw, "deny": deny},
        "network": {"mode": "none", "allow": ALLOWED_ONLY, "ports": [443]},
        "env": {"pass": [], "set": {}},
        "limits": {"timeout": "30s", "output_bytes": 1048576}
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Write a policy file under `dir`, returning its path.
pub fn write_policy(dir: &Path, name: &str, text: &str) -> std::io::Result<std::path::PathBuf> {
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, text)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    #[test]
    fn policies_valid() {
        for which in [Builtin::Transparent, Builtin::Explicit, Builtin::NoNetwork] {
            let text = policy_json(which, "/mnt/sbx", None);
            Policy::from_json_str(&text).unwrap_or_else(|e| panic!("{which:?}: {e:?}"));
        }
    }

    #[test]
    fn paths_policy_valid_and_carries_every_list() {
        let text = paths_policy_json(
            "/opt/sbx",
            &["/x/ro".to_owned()],
            &["/x/rw".to_owned()],
            &["/x/ro/secret".to_owned(), "/x/rw/secret".to_owned()],
        );
        Policy::from_json_str(&text).unwrap_or_else(|e| panic!("{e:?}"));
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["filesystem"]["ro"], json!(["/usr", "/opt/sbx", "/x/ro"]));
        assert_eq!(v["filesystem"]["rw"], json!(["/x/rw"]));
        assert_eq!(
            v["filesystem"]["deny"],
            json!(["/x/ro/secret", "/x/rw/secret"])
        );
        assert_eq!(v["network"]["mode"], "none");
        // fs_policy_json is the no-extra-ro special case.
        assert_eq!(
            fs_policy_json("/opt/sbx", &["/x/rw".to_owned()], &[]),
            paths_policy_json("/opt/sbx", &[], &["/x/rw".to_owned()], &[])
        );
    }

    #[test]
    fn exe_is_bound_only_outside_usr() {
        let text = policy_json(Builtin::Explicit, "/opt/sbx", None);
        assert!(text.contains("/opt/sbx"));
        let text = policy_json(Builtin::Explicit, "/usr/bin/sbx", None);
        assert_eq!(text.matches("/usr/bin/sbx").count(), 0);
    }
}
