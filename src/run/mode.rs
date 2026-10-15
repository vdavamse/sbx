//! Network-mode capability check (issue #10, Q12). `PROVIDED_MODE` is the #11
//! seam: until host detection lands, every host is assumed transparent-capable,
//! and a host that is not fails inside `__init` (nft load) with rc 125.

use super::RunError;
use crate::policy::{self, NetworkMode};

/// What this host provides. #11 replaces the constant with detection.
pub(crate) const PROVIDED_MODE: NetworkMode = NetworkMode::Transparent;

/// Capability strength: none < explicit < transparent.
fn rank(mode: NetworkMode) -> u8 {
    match mode {
        NetworkMode::None => 0,
        NetworkMode::Explicit => 1,
        NetworkMode::Transparent => 2,
    }
}

fn label(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Transparent => "transparent",
        NetworkMode::Explicit => "explicit",
        NetworkMode::None => "none",
    }
}

/// Refuse a policy whose required mode is stronger than what the host provides.
pub(crate) fn check_mode(required: NetworkMode, provided: NetworkMode) -> Result<(), RunError> {
    if rank(provided) >= rank(required) {
        Ok(())
    } else {
        Err(RunError::new(format!(
            "policy requires network mode {} but this host provides only {}",
            label(required),
            label(provided)
        )))
    }
}

/// The network section the proxies and the resolver are built from. Mode
/// `none` clamps allow/ports to empty: the proxies and DNS are still served,
/// so every attempt becomes an audited denial. Other modes are unchanged.
/// bwrap::build always gets the ORIGINAL policy (Q11: no env injection).
pub(crate) fn effective_network(policy: &policy::Policy) -> policy::Network {
    let mut net = policy.network.clone();
    if net.mode == NetworkMode::None {
        net.allow.clear();
        net.ports.clear();
    }
    net
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_mode_matrix() {
        use NetworkMode::{Explicit, None as NoNet, Transparent};
        let modes = [NoNet, Explicit, Transparent];
        for required in modes {
            for provided in modes {
                let ok = rank(provided) >= rank(required);
                let result = check_mode(required, provided);
                assert_eq!(result.is_ok(), ok, "{required:?} vs {provided:?}");
                if let Err(err) = result {
                    assert_eq!(
                        err.reason(),
                        format!(
                            "policy requires network mode {} but this host provides only {}",
                            label(required),
                            label(provided)
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn provided_mode_is_transparent_until_11() {
        assert_eq!(PROVIDED_MODE, NetworkMode::Transparent);
    }

    fn policy_with(mode: &str) -> policy::Policy {
        policy::Policy::from_json_str(&format!(
            r#"{{"version":1,"filesystem":{{"ro":[],"rw":[],"deny":[]}},
                "network":{{"mode":"{mode}","allow":["a.example"],"ports":[80,443]}},
                "env":{{"pass":[],"set":{{}}}},
                "limits":{{"timeout":"1s","output_bytes":1000}}}}"#
        ))
        .expect("policy parses")
    }

    #[test]
    fn effective_network_none_clamps() {
        let net = effective_network(&policy_with("none"));
        assert_eq!(net.mode, NetworkMode::None);
        assert!(net.allow.is_empty());
        assert!(net.ports.is_empty());
    }

    #[test]
    fn effective_network_other_modes_unchanged() {
        for mode in ["transparent", "explicit"] {
            let policy = policy_with(mode);
            let net = effective_network(&policy);
            assert_eq!(net, policy.network, "{mode}");
        }
    }
}
