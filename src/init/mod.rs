//! The `sbx __init` namespace child (issue #5) — per-call user+network
//! namespace setup, nftables rules, listener fd hand-off, payload exec.
//!
//! 1. **Stage order is load-bearing.** [`Stage`] enumerates the pipeline
//!    order: the `control` stage validates the inherited socketpair end
//!    *before* any namespace work (fast, deterministic, namespace- and
//!    privilege-independent failure — which is what makes the CI build-job
//!    smoke runnable on any runner); listeners bind *before* the nftables
//!    rules load (no redirect-live-without-listener window: a
//!    bound-but-unaccepted socket completes handshakes into its backlog, so
//!    there is no RST window either); rules load *and* dump-verify before
//!    the listener fds are sent and before the go byte releases the payload
//!    (no fail-open window: the payload can never run before the firewall is
//!    kernel-verified).
//! 2. **Single-threaded until exec.** `unshare(CLONE_NEWUSER)` fails with
//!    EPERM in a multithreaded process, so `__init` never spawns a thread,
//!    and no unit test ever calls `unshare` (a successful one would capture
//!    the whole test binary's namespaces). This is also why `run` (#10)
//!    re-execs a fresh `__init` child instead of setting namespaces up
//!    in-process.
//! 3. **Fail-closed everywhere.** Any setup failure aborts with exit code 1
//!    *before* the payload is exec'd — the command never runs in a
//!    half-configured sandbox. Success is silent (house `check` precedent);
//!    diagnostics go to stderr only on failure.
//! 4. **Error vocabulary and exit codes.** [`InitError`] pairs a [`Stage`]
//!    with a reason; its `Display` is the single formatting site of the
//!    pinned `sbx __init: <stage>: <reason>` shape. Exit codes stay the
//!    README/cli contract: 0 = the payload's own code (via `exec`), 1 =
//!    staged setup failure (payload never exec'd), 2 = usage (clap).
//!    `__init` never panics out to the user: the CLI seam catches unwinds
//!    and reports them as staged rc-1 errors, never exit 101.
//! 5. **Protocol strictness is free.** Parent (`run`, #10) and child are
//!    always the *same binary* — `run` re-execs `current_exe` — so the
//!    control protocol validates exact bytes ('F' payload, 'G' go, exactly
//!    three fds) with no version negotiation (design D4).
//! 6. **fd discipline (spike risks R5/R6).** The control fd (`--fd N`) is
//!    deliberately *not* CLOEXEC — it must survive the re-exec from `run` —
//!    so it is closed explicitly before the payload exec, backed by a
//!    `/proc/self/fd` scan. Listener sockets are std-owned (CLOEXEC by
//!    default): they die at exec even if the scan ever missed one, while the
//!    parent's SCM_RIGHTS-dup'd copies live on (cross-netns fd passing).
//!    The socketpair itself is created CLOEXEC on *both* ends with the child
//!    end cleared only in the spawn window — see [`fdpass::prepare_child_end`]
//!    for the bug class that discipline prevents.
//! 7. **Consumers.** [`fdpass`] doubles as the parent-side API #10 drives
//!    (`control_socketpair` → `prepare_child_end` → spawn →
//!    `recv_listener_fds` → serve (#7/#8/#9) → `send_go`); [`consts`] is the
//!    cross-issue constant surface (ports for #6, `SO_ORIGINAL_DST` for #7,
//!    `IP_RECVORIGDSTADDR` for #9, `GO_TIMEOUT` for #10). Control-socket EOF
//!    means *exec time* (the child closes its end before exec), NOT sandbox
//!    death — #10's liveness check is `Child::wait`.

pub mod consts;
pub mod fdpass;

use std::fmt;

/// The setup stage a failure occurred in — the `<stage>` of every
/// `sbx __init: <stage>: <reason>` message.
///
/// The variants are declared in pipeline order (module docs point 1); the
/// pinned user-visible names come from [`Stage::as_str`] and are frozen by
/// the `stage_names_pinned` test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Validating the inherited control socketpair end (`--fd N`).
    Control,
    /// `unshare(CLONE_NEWUSER | CLONE_NEWNET)`.
    Unshare,
    /// Writing `/proc/self/{setgroups,uid_map,gid_map}`.
    Idmap,
    /// `lo` up + `10.255.255.1/32` + default route, with read-back asserts.
    Netns,
    /// Disabling IPv6 (sysctl) and verifying `if_inet6` is empty.
    Ipv6,
    /// Binding the three bare listener sockets.
    Listeners,
    /// Loading the atomic nftables batch (with ERESTART retry).
    NftLoad,
    /// Verifying the loaded ruleset against the kernel's own dump.
    NftVerify,
    /// Handing the listener fds to the parent over SCM_RIGHTS.
    SendFds,
    /// Blocking on the parent's go byte.
    WaitGo,
    /// `execvp` of the payload argv.
    Exec,
}

impl Stage {
    /// The pinned stage name — the `<stage>` in every `sbx __init:` message.
    ///
    /// Exhaustive match: a new variant without a pinned name fails to
    /// compile (house convention for pinned message vocabularies).
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Control => "control",
            Stage::Unshare => "unshare",
            Stage::Idmap => "idmap",
            Stage::Netns => "netns",
            Stage::Ipv6 => "ipv6",
            Stage::Listeners => "listeners",
            Stage::NftLoad => "nft-load",
            Stage::NftVerify => "nft-verify",
            Stage::SendFds => "send-fds",
            Stage::WaitGo => "wait-go",
            Stage::Exec => "exec",
        }
    }
}

/// A staged setup failure: which [`Stage`] failed, and why.
///
/// The reason is complete and user-facing; `Display` is the single
/// formatting site of the pinned `sbx __init: <stage>: <reason>` shape
/// (module docs point 4). Every construction site passes a full reason —
/// the message is composed in exactly one place, here.
#[derive(Debug)]
pub struct InitError {
    stage: Stage,
    reason: String,
}

impl InitError {
    /// Construct a staged error from a stage and its reason text.
    pub fn new(stage: Stage, reason: impl Into<String>) -> Self {
        Self {
            stage,
            reason: reason.into(),
        }
    }

    /// The stage that failed.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The reason text, without the `sbx __init: <stage>:` prefix.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // THE single formatting site for the staged-message contract;
        // init_error_display_single_site pins it for every stage.
        write!(f, "sbx __init: {}: {}", self.stage.as_str(), self.reason)
    }
}

impl std::error::Error for InitError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every stage, in pipeline order. Kept next to the pinned-name match so
    /// adding a variant without extending both fails the suite.
    fn all_stages() -> [Stage; 11] {
        [
            Stage::Control,
            Stage::Unshare,
            Stage::Idmap,
            Stage::Netns,
            Stage::Ipv6,
            Stage::Listeners,
            Stage::NftLoad,
            Stage::NftVerify,
            Stage::SendFds,
            Stage::WaitGo,
            Stage::Exec,
        ]
    }

    #[test]
    fn stage_names_pinned() {
        // Exhaustive match returning the 11 exact literals: a new variant
        // fails to compile this test, so the user-visible stage vocabulary
        // can never drift silently.
        for stage in all_stages() {
            let expected = match stage {
                Stage::Control => "control",
                Stage::Unshare => "unshare",
                Stage::Idmap => "idmap",
                Stage::Netns => "netns",
                Stage::Ipv6 => "ipv6",
                Stage::Listeners => "listeners",
                Stage::NftLoad => "nft-load",
                Stage::NftVerify => "nft-verify",
                Stage::SendFds => "send-fds",
                Stage::WaitGo => "wait-go",
                Stage::Exec => "exec",
            };
            assert_eq!(stage.as_str(), expected);
        }
    }

    #[test]
    fn init_error_display_single_site() {
        // For EVERY stage the rendering is exactly
        // `sbx __init: <stage>: <reason>` — pins both the format and the
        // single-Display-site rule (module docs point 4).
        for stage in all_stages() {
            let err = InitError::new(stage, "boom");
            assert_eq!(
                err.to_string(),
                format!("sbx __init: {}: boom", stage.as_str()),
                "stage {:?}",
                stage
            );
            assert_eq!(err.stage(), stage);
            assert_eq!(err.reason(), "boom");
        }
        // The reason accepts any Into<String>.
        let owned = InitError::new(Stage::Exec, String::from("owned reason"));
        assert_eq!(owned.reason(), "owned reason");
    }
}
