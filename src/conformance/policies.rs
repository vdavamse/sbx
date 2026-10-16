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
    /// `p-none`: mode none (NXDOMAIN for everything).
    NoNetwork,
}

/// The allow list of the transparent policy.
pub const TRANSPARENT_ALLOW: [&str; 3] = ["allowed.conformance.test", "pypi.org", "localhost"];
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
    fn exe_is_bound_only_outside_usr() {
        let text = policy_json(Builtin::Explicit, "/opt/sbx", None);
        assert!(text.contains("/opt/sbx"));
        let text = policy_json(Builtin::Explicit, "/usr/bin/sbx", None);
        assert_eq!(text.matches("/usr/bin/sbx").count(), 0);
    }
}
