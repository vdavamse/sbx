//! Network-mode refusal and the explicit-fallback notice (issue #10 Q12,
//! issue #11). The host's capability is no longer assumed: `__init` reports
//! the staged failure (or the achieved mode) over the control socket, and
//! [`refusal`] turns a failure into the pinned rc-125 reason through the shared
//! classifier ([`crate::host::classify`]), so `run` and `sbx check` agree.

use super::RunError;
use crate::host::EffectiveMode;
use crate::host::classify;
use crate::host::facts::RunFacts;
use crate::init::fdpass::StagedFailure;
use crate::policy::{self, NetworkMode};

/// The refusal for a policy whose mode `__init` could not provide (staged
/// failure in `f`). Pinned shape: `<check_mode text>: <detail>; fix: <fix>;
/// run `sbx check` for a full host report`.
pub(crate) fn refusal(required: NetworkMode, f: &StagedFailure, facts: &RunFacts) -> RunError {
    let cap = classify::staged(f, facts);
    let provided = cap.impact.unwrap_or(EffectiveMode::Unavailable);
    let headline = match classify::check_mode(required, provided) {
        Err(text) => text,
        Ok(()) => format!(
            "policy requires network mode {} but this host cannot run sandboxes",
            required_word(required)
        ),
    };
    let mut reason = format!("{headline}: {}", cap.detail);
    if let Some(fix) = &cap.fix {
        reason.push_str(&format!("; fix: {fix}"));
    }
    reason.push_str("; run `sbx check` for a full host report");
    RunError::new(reason)
}

fn required_word(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Transparent => "transparent",
        NetworkMode::Explicit => "explicit",
        NetworkMode::None => "none",
    }
}

/// The stderr notice of an explicit fallback (pinned, issue #11 Q5). `reason`
/// is the nft-load evidence (`nft-load: …`).
pub(crate) fn fallback_notice(reason: &str, required: NetworkMode) -> String {
    match required {
        NetworkMode::None => format!(
            "sbx run: notice: running in network mode explicit (policy mode none) because the nftables NAT redirect is unavailable ({reason}); run `sbx check` for details"
        ),
        _ => format!(
            "sbx run: notice: running in network mode explicit because the nftables NAT redirect is unavailable ({reason}); run `sbx check` for details"
        ),
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

    fn staged(stage: crate::init::Stage, errno: Option<i32>, reason: &str) -> StagedFailure {
        StagedFailure {
            stage,
            errno,
            reason: reason.to_owned(),
        }
    }

    fn no_sysctls() -> RunFacts {
        RunFacts::default()
    }

    #[test]
    fn refusal_pinned() {
        use crate::init::Stage;
        let nft = staged(
            Stage::NftLoad,
            Some(2),
            "batch failed (attempt 1/5, genid 1): No such file or directory (os error 2)",
        );
        let err = refusal(NetworkMode::Transparent, &nft, &no_sysctls());
        assert_eq!(
            err.reason(),
            "policy requires network mode transparent but this host provides only explicit: nftables NAT redirect is unavailable (transparent mode needs it; explicit and none do not); fix: load the nftables modules (sudo modprobe -a nf_tables nf_nat nft_chain_nat nft_redir nft_fib nft_fib_ipv4) or use network mode explicit; run `sbx check` for a full host report"
        );
        let ns = staged(
            Stage::Unshare,
            Some(28),
            "unshare failed: No space left on device (os error 28)",
        );
        let facts = RunFacts {
            sysctl: crate::host::facts::Sysctls {
                max_user_namespaces: Some(2147483647),
                ..Default::default()
            },
            seccomp: None,
        };
        let err = refusal(NetworkMode::Explicit, &ns, &facts);
        assert!(err.reason().starts_with("policy requires network mode explicit but this host cannot run sandboxes: no user namespace can be created here"), "{}", err.reason());
        let ipv6 = staged(
            Stage::Ipv6,
            Some(30),
            "write disable_ipv6 failed: Read-only file system (os error 30)",
        );
        let err = refusal(NetworkMode::Transparent, &ipv6, &no_sysctls());
        assert!(
            err.reason().contains("cannot disable IPv6"),
            "{}",
            err.reason()
        );
        assert!(
            err.reason()
                .ends_with("run `sbx check` for a full host report")
        );
        let aa = staged(
            Stage::Idmap,
            Some(1),
            "write /proc/self/uid_map = \"0 1000 1\": Operation not permitted (os error 1)",
        );
        let aa_facts = RunFacts {
            sysctl: crate::host::facts::Sysctls {
                apparmor_restrict_userns: Some(1),
                ..Default::default()
            },
            seccomp: None,
        };
        let err = refusal(NetworkMode::None, &aa, &aa_facts);
        assert!(
            err.reason().contains("restricted by AppArmor"),
            "{}",
            err.reason()
        );
    }

    #[test]
    fn fallback_notice_pinned() {
        assert_eq!(
            fallback_notice("nft-load: batch failed", NetworkMode::Explicit),
            "sbx run: notice: running in network mode explicit because the nftables NAT redirect is unavailable (nft-load: batch failed); run `sbx check` for details"
        );
        assert_eq!(
            fallback_notice("nft-load: batch failed", NetworkMode::None),
            "sbx run: notice: running in network mode explicit (policy mode none) because the nftables NAT redirect is unavailable (nft-load: batch failed); run `sbx check` for details"
        );
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
