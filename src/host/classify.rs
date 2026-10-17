//! The pure classifier (issue #11, T1): staged `__init` failures and bwrap
//! probe steps → report items, the effective network mode, the policy
//! comparison, and every pinned user-visible text.
//!
//! Single mapping for both commands: `sbx run` calls [`staged`] (and
//! [`check_mode`]) on the failure `__init` reports; `sbx check` calls
//! [`assemble`] on the probe's step list. Nothing here touches the system, so
//! every row is unit-tested with synthetic facts.

use std::path::Path;

use crate::bwrap::guard::{self, GuardError};
use crate::bwrap::version::{BWRAP_MIN, BwrapStatus, Unsupported};
use crate::bwrap::{AliasCheck, PathCheck};
use crate::init::Stage;
use crate::init::fdpass::StagedFailure;
use crate::init::probe::{ProbeReport, ProbeStep, StepStatus};
use crate::policy::{NetworkMode, Policy};

use super::facts::{HostFacts, Landlock, ProbeOutcome, RunFacts};
use super::{
    CapId, Capability, EffectiveMode, PolicyCheck, PolicyItem, REPORT_VERSION, Report, Status,
};

// ---------------------------------------------------------------------------
// pinned texts
// ---------------------------------------------------------------------------

const BUG_FIX: &str =
    "report a bug at https://github.com/vdavamse/sbx/issues with the evidence line and `uname -r`";
const PROC_FIX: &str = "Kubernetes: securityContext.procMount: Unmasked (requires hostUsers: false); Docker: --security-opt systempaths=unconfined";

const U_APPARMOR: (&str, &str) = (
    "unprivileged user namespaces are restricted by AppArmor (kernel.apparmor_restrict_unprivileged_userns = 1)",
    "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0, or give sbx an AppArmor profile that allows userns; Kubernetes: appArmorProfile Unconfined or a Localhost profile that allows userns",
);
const U_CLONE_SYSCTL: (&str, &str) = (
    "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone = 0)",
    "sudo sysctl -w kernel.unprivileged_userns_clone=1",
);
const U_SECCOMP: (&str, &str) = (
    "unshare(CLONE_NEWUSER|CLONE_NEWNET) is blocked by a seccomp filter (EPERM; typical inside containers)",
    "Kubernetes: hostUsers: false plus a Localhost seccomp profile allowing unshare, clone/clone3 with namespace flags, mount and pivot_root (or seccompProfile Unconfined); Docker: --security-opt seccomp=unconfined or an equivalent profile",
);
const U_EPERM: (&str, &str) = (
    "unshare(CLONE_NEWUSER|CLONE_NEWNET) is not permitted (EPERM)",
    "allow unprivileged user namespaces for this user (check AppArmor/SELinux policy, seccomp and kernel.unprivileged_userns_clone)",
);
const U_MAX_ZERO: (&str, &str) = (
    "user namespaces are disabled (user.max_user_namespaces = 0)",
    "sudo sysctl -w user.max_user_namespaces=15000",
);
const U_MAX_NET_ZERO: (&str, &str) = (
    "no network namespace can be created here: user.max_net_namespaces = 0 (ENOSPC; user namespaces are allowed)",
    "sudo sysctl -w user.max_net_namespaces=15000",
);
const U_ENOSPC: (&str, &str) = (
    "no user namespace can be created here: the limit is exhausted or nesting is forbidden (ENOSPC; for example inside bwrap --disable-userns)",
    "run sbx outside sandboxes that forbid nested user namespaces, or raise user.max_user_namespaces",
);
const U_EUSERS: (&str, &str) = (
    "user namespaces are nested too deeply (EUSERS; the kernel allows 32 levels)",
    "run sbx at a shallower nesting level",
);
const U_EINVAL: (&str, &str) = (
    "the kernel does not support user or network namespaces (EINVAL)",
    "use a kernel built with CONFIG_USER_NS=y and CONFIG_NET_NS=y",
);
const U_OTHER: (&str, &str) = (
    "unshare(CLONE_NEWUSER|CLONE_NEWNET) failed",
    "allow unprivileged user and network namespaces for this user",
);
const U_IDMAP: (&str, &str) = (
    "cannot write the user namespace id maps (/proc/self/setgroups, uid_map, gid_map)",
    "allow writes to /proc/self/{setgroups,uid_map,gid_map} in a fresh user namespace (a read-only or masked /proc blocks them)",
);
const N_NETNS: (&str, &str) = ("cannot configure the sandbox loopback interface", BUG_FIX);
const N_LISTENERS: (&str, &str) = (
    "cannot bind the proxy and DNS listeners inside the sandbox network namespace",
    BUG_FIX,
);
const N_INTERNAL: (&str, &str) = ("sandbox setup failed", BUG_FIX);
const V_EROFS: (&str, &str) = (
    "cannot disable IPv6 in the sandbox network namespace: /proc/sys is read-only (EROFS; typical inside containers)",
    PROC_FIX,
);
const V_DENIED: (&str, &str) = (
    "cannot disable IPv6 in the sandbox network namespace: writing /proc/sys/net is denied",
    PROC_FIX,
);
const V_OTHER: (&str, &str) = (
    "cannot disable IPv6 in the sandbox network namespace",
    BUG_FIX,
);
const T_LOAD: (&str, &str) = (
    "nftables NAT redirect is unavailable (transparent mode needs it; explicit and none do not)",
    "load the nftables modules (sudo modprobe -a nf_tables nf_nat nft_chain_nat nft_redir nft_fib nft_fib_ipv4) or use network mode explicit",
);
const T_VERIFY: (&str, &str) = (
    "the kernel's copy of the sbx nftables ruleset differs from the expected one",
    BUG_FIX,
);
const F_FAIL: (&str, &str) = (
    "cannot remove the sandbox default route, so the explicit fallback is unavailable",
    BUG_FIX,
);
const R_ROFS: (&str, &str) = (
    "bwrap cannot apply --disable-userns: /proc/sys is read-only",
    PROC_FIX,
);
const R_FAIL: (&str, &str) = (
    "bwrap cannot start a sandbox inside the sbx namespaces",
    "allow mount and pivot_root inside nested user namespaces (Kubernetes: a Localhost seccomp profile that allows them, or seccompProfile and appArmorProfile Unconfined)",
);
const P_FAIL: (&str, &str) = (
    "bwrap cannot mount a fresh /proc (masked /proc, typical in containers)",
    PROC_FIX,
);
const B_NOT_FOUND: (&str, &str) = (
    "bwrap not found (searched SBX_BWRAP, PATH, /usr/local/bin, /usr/bin, /bin)",
    "install bubblewrap >= 0.8.0 (for example apt-get install bubblewrap) or set SBX_BWRAP",
);
const B_FIX: &str = "install bubblewrap >= 0.8.0 or set SBX_BWRAP to one";
/// `seccomp` FAIL (issue #34): `run` cannot start without the filter, so this
/// limits the mode to unavailable (fail closed).
const R_SECCOMP: (&str, &str) = (
    "bwrap cannot install sbx's socket-family seccomp filter",
    "no program exists for this architecture (sbx ships the filter for x86_64 and aarch64 only); otherwise a kernel built with CONFIG_SECCOMP_FILTER=y, and an outer seccomp or container profile that allows prctl(PR_SET_SECCOMP) and seccomp(2) (Kubernetes: a Localhost seccomp profile that allows them, or seccompProfile Unconfined)",
);
const L_ENOSYS: (&str, &str) = (
    "Landlock is not supported by this kernel (report-only)",
    "none needed today; kernels >= 5.13 built with CONFIG_SECURITY_LANDLOCK=y provide it",
);
const L_DISABLED: (&str, &str) = (
    "Landlock is built in but disabled (report-only)",
    "add landlock to the lsm= kernel boot parameter",
);

const OK_USERNS: &str = "unprivileged user + network namespaces work";
const OK_NETNS: &str = "sandbox loopback network configured";
const OK_IPV6: &str = "IPv6 disabled inside the sandbox network namespace";
const OK_NFT: &str = "nftables NAT redirect loaded and verified";
const OK_FALLBACK: &str = "default route removable for explicit mode";
const OK_BWRAP_RUN: &str = "bwrap starts a sandbox inside the sbx namespaces";
const OK_BWRAP_PROC: &str = "bwrap mounts a fresh /proc";
const OK_SECCOMP: &str =
    "bwrap installs sbx's socket-family filter (installation only; denials not probed)";

const SKIP_USERNS: &str = "not probed: user namespaces are unavailable";
const SKIP_NETNS: &str = "not probed: the sandbox network could not be configured";
const SKIP_BWRAP: &str = "not probed: bwrap is unavailable";
const SKIP_BWRAP_RUN: &str = "not probed: bwrap cannot start a sandbox here";
const SKIP_PROBE: &str = "not probed: the namespace probe failed";

// ---------------------------------------------------------------------------
// staged failures (sbx run and sbx check)
// ---------------------------------------------------------------------------

fn is_permission(errno: Option<i32>) -> bool {
    matches!(errno, Some(libc::EPERM) | Some(libc::EACCES))
}

fn staged_row(
    id: CapId,
    pinned: (&str, &str),
    f: &StagedFailure,
    impact: EffectiveMode,
) -> Capability {
    Capability {
        id,
        status: Status::Fail,
        detail: pinned.0.to_owned(),
        evidence: Some(f.to_string()),
        errno: f.errno,
        impact: Some(impact),
        fix: Some(pinned.1.to_owned()),
    }
}

/// The single mapping from a staged `__init` failure to a host capability
/// (issue #11, §5.1). Rows are evaluated top to bottom; the first match wins.
/// `facts` supplies the AppArmor sysctl (row 1), the unprivileged-userns
/// sysctl (row 2), the seccomp mode (row 3) and `max_user_namespaces`
/// (rows 5–6).
pub fn staged(f: &StagedFailure, facts: &RunFacts) -> Capability {
    let e = f.errno;
    let aa = facts.sysctl.apparmor_restrict_userns == Some(1);
    let early = matches!(
        f.stage,
        Stage::Unshare | Stage::Idmap | Stage::Netns | Stage::Listeners | Stage::Ipv6
    );
    // M1 (review): at unshare, EPERM with seccomp filter 2 is the seccomp
    // block; AppArmor restriction on an unconfined process fails later (idmap
    // or after), so the seccomp row takes precedence here.
    let seccomp_unshare = f.stage == Stage::Unshare && facts.seccomp == Some(2);
    if early && aa && is_permission(e) && !seccomp_unshare {
        return staged_row(CapId::Userns, U_APPARMOR, f, EffectiveMode::Unavailable);
    }
    match f.stage {
        Stage::Unshare => {
            let row = if e == Some(libc::EPERM) && facts.sysctl.unprivileged_userns_clone == Some(0)
            {
                U_CLONE_SYSCTL
            } else if e == Some(libc::EPERM) && facts.seccomp == Some(2) {
                U_SECCOMP
            } else if e == Some(libc::EPERM) {
                U_EPERM
            } else if e == Some(libc::ENOSPC) && facts.sysctl.max_user_namespaces == Some(0) {
                U_MAX_ZERO
            } else if e == Some(libc::ENOSPC) && facts.sysctl.max_net_namespaces == Some(0) {
                // Review #1: the netns limit, not the userns one, is exhausted.
                U_MAX_NET_ZERO
            } else if e == Some(libc::ENOSPC) {
                U_ENOSPC
            } else if e == Some(libc::EUSERS) {
                U_EUSERS
            } else if e == Some(libc::EINVAL) {
                U_EINVAL
            } else {
                U_OTHER
            };
            staged_row(CapId::Userns, row, f, EffectiveMode::Unavailable)
        }
        Stage::Idmap => staged_row(CapId::Userns, U_IDMAP, f, EffectiveMode::Unavailable),
        Stage::Netns => staged_row(CapId::Netns, N_NETNS, f, EffectiveMode::Unavailable),
        Stage::Listeners => staged_row(CapId::Netns, N_LISTENERS, f, EffectiveMode::Unavailable),
        Stage::Ipv6 => {
            let row = if e == Some(libc::EROFS) {
                V_EROFS
            } else if is_permission(e) {
                V_DENIED
            } else {
                V_OTHER
            };
            staged_row(CapId::NetnsIpv6, row, f, EffectiveMode::Unavailable)
        }
        Stage::NftLoad => staged_row(CapId::Nft, T_LOAD, f, EffectiveMode::Explicit),
        Stage::NftVerify => staged_row(CapId::Nft, T_VERIFY, f, EffectiveMode::Unavailable),
        Stage::Fallback => staged_row(CapId::Fallback, F_FAIL, f, EffectiveMode::Unavailable),
        // Never reported by __init (module docs point 1); defensive.
        Stage::Control | Stage::SendFds | Stage::WaitGo | Stage::Exec => {
            staged_row(CapId::Netns, N_INTERNAL, f, EffectiveMode::Unavailable)
        }
    }
}

// ---------------------------------------------------------------------------
// probe steps that are bwrap launches, bwrap, landlock
// ---------------------------------------------------------------------------

/// A failed nested bwrap launch (`bwrap-run` / `bwrap-proc`): `evidence` is the
/// step's reason (the first stderr line of the child).
pub fn bwrap_step(id: CapId, evidence: &str) -> Capability {
    let pinned = match id {
        CapId::BwrapRun if evidence.contains("Read-only file system") => R_ROFS,
        CapId::BwrapRun => R_FAIL,
        _ => P_FAIL,
    };
    Capability {
        id,
        status: Status::Fail,
        detail: pinned.0.to_owned(),
        evidence: Some(evidence.to_owned()),
        errno: None,
        impact: Some(EffectiveMode::Unavailable),
        fix: Some(pinned.1.to_owned()),
    }
}

/// A failed `bwrap-seccomp` step (issue #34): bwrap could not install the
/// filter, or sbx could not prepare it (no program for this arch).
pub fn seccomp_step(evidence: &str) -> Capability {
    Capability {
        id: CapId::Seccomp,
        status: Status::Fail,
        detail: R_SECCOMP.0.to_owned(),
        evidence: Some(evidence.to_owned()),
        errno: None,
        impact: Some(EffectiveMode::Unavailable),
        fix: Some(R_SECCOMP.1.to_owned()),
    }
}

fn version_text((x, y, z): (u32, u32, u32)) -> String {
    format!("{x}.{y}.{z}")
}

/// The `bwrap` item from the gate outcome.
pub fn bwrap(status: &BwrapStatus) -> Capability {
    let fail = |detail: String, fix: &str| Capability {
        id: CapId::Bwrap,
        status: Status::Fail,
        detail,
        evidence: None,
        errno: None,
        impact: Some(EffectiveMode::Unavailable),
        fix: Some(fix.to_owned()),
    };
    match status {
        BwrapStatus::Ok { path, version } => Capability {
            id: CapId::Bwrap,
            status: Status::Ok,
            detail: format!(
                "bubblewrap {} at {}",
                version_text(*version),
                path.display()
            ),
            evidence: None,
            errno: None,
            impact: None,
            fix: None,
        },
        BwrapStatus::NotFound => fail(B_NOT_FOUND.0.to_owned(), B_NOT_FOUND.1),
        BwrapStatus::SpawnFailed { path, error } => fail(
            format!("cannot run {} --version: {error}", path.display()),
            B_FIX,
        ),
        BwrapStatus::Unsupported {
            path,
            first_line,
            why,
        } => {
            let detail = match why {
                Unsupported::TooOld(version) => format!(
                    "bubblewrap {} at {} is too old (need >= {} for --disable-userns)",
                    version_text(*version),
                    path.display(),
                    version_text(BWRAP_MIN)
                ),
                Unsupported::Unparseable => format!(
                    "cannot parse the version reported by {} ({first_line:?})",
                    path.display()
                ),
                Unsupported::ExitStatus(Some(code)) => {
                    format!("{} --version failed (exit status {code})", path.display())
                }
                Unsupported::ExitStatus(None) => {
                    format!("{} --version failed (killed by a signal)", path.display())
                }
            };
            fail(detail, B_FIX)
        }
    }
}

/// The report-only `landlock` item (never limits the network mode).
pub fn landlock(l: &Landlock) -> Capability {
    let (status, detail, fix) = match l {
        Landlock::Abi(n) => (Status::Ok, format!("Landlock ABI {n} (report-only)"), None),
        Landlock::Errno(libc::ENOSYS) => (
            Status::Warn,
            L_ENOSYS.0.to_owned(),
            Some(L_ENOSYS.1.to_owned()),
        ),
        Landlock::Errno(libc::EOPNOTSUPP) => (
            Status::Warn,
            L_DISABLED.0.to_owned(),
            Some(L_DISABLED.1.to_owned()),
        ),
        Landlock::Errno(n) => (
            Status::Warn,
            format!("Landlock status unknown (errno {n}, report-only)"),
            Some(BUG_FIX.to_owned()),
        ),
    };
    Capability {
        id: CapId::Landlock,
        status,
        detail,
        evidence: None,
        errno: match l {
            Landlock::Errno(n) => Some(*n),
            Landlock::Abi(_) => None,
        },
        impact: None,
        fix,
    }
}

// ---------------------------------------------------------------------------
// assembly
// ---------------------------------------------------------------------------

fn ok_row(id: CapId, detail: &str) -> Capability {
    Capability {
        id,
        status: Status::Ok,
        detail: detail.to_owned(),
        evidence: None,
        errno: None,
        impact: None,
        fix: None,
    }
}

fn skip_row(id: CapId, detail: &str) -> Capability {
    Capability {
        id,
        status: Status::Skip,
        detail: detail.to_owned(),
        evidence: None,
        errno: None,
        // m2 (review): a skip without an explained cause is not evidence the
        // host works, so it limits the mode to unavailable (fail closed).
        impact: (detail == SKIP_PROBE).then_some(EffectiveMode::Unavailable),
        fix: None,
    }
}

/// The probe steps that feed each probe-derived item, and the ok detail.
const PROBE_SLOTS: [(CapId, &[&str], &str); 8] = [
    (CapId::Userns, &["unshare", "idmap"], OK_USERNS),
    (CapId::Netns, &["netns", "listeners"], OK_NETNS),
    (CapId::NetnsIpv6, &["ipv6"], OK_IPV6),
    (CapId::Nft, &["nft-load", "nft-verify"], OK_NFT),
    (CapId::Fallback, &["fallback"], OK_FALLBACK),
    (CapId::BwrapRun, &["bwrap-run"], OK_BWRAP_RUN),
    (CapId::BwrapProc, &["bwrap-proc"], OK_BWRAP_PROC),
    (CapId::Seccomp, &["bwrap-seccomp"], OK_SECCOMP),
];

fn stage_of(step: &str) -> Option<Stage> {
    Some(match step {
        "unshare" => Stage::Unshare,
        "idmap" => Stage::Idmap,
        "netns" => Stage::Netns,
        "ipv6" => Stage::Ipv6,
        "listeners" => Stage::Listeners,
        "nft-load" => Stage::NftLoad,
        "nft-verify" => Stage::NftVerify,
        "fallback" => Stage::Fallback,
        _ => return None,
    })
}

fn find_step<'a>(report: &'a ProbeReport, name: &str) -> Option<&'a ProbeStep> {
    report.steps.iter().find(|step| step.step == name)
}

/// Full report from gathered facts: the item rows in `CapId::ALL` order and
/// the effective network mode (`min` over every item's impact; probe failure
/// means unavailable).
pub fn assemble(facts: &HostFacts) -> Report {
    let mut slots: [Option<Capability>; CapId::ALL.len()] = Default::default();
    let index = |id: CapId| CapId::ALL.iter().position(|c| *c == id).unwrap_or(0);
    let mut probe_error = None;

    match &facts.probe {
        ProbeOutcome::Failed(err) => {
            probe_error = Some(err.clone());
            for (id, _, _) in PROBE_SLOTS {
                slots[index(id)] = Some(skip_row(id, SKIP_PROBE));
            }
        }
        ProbeOutcome::Ran(report) => {
            // 1. Failed steps, in probe order: each classified once, into its
            //    own slot (row 1 may route an early failure to `userns`).
            for step in report.steps.iter().filter(|s| s.status == StepStatus::Fail) {
                let reason = step.reason.clone().unwrap_or_default();
                let cap = match step.step.as_str() {
                    "bwrap-run" => bwrap_step(CapId::BwrapRun, &reason),
                    "bwrap-proc" => bwrap_step(CapId::BwrapProc, &reason),
                    "bwrap-seccomp" => seccomp_step(&reason),
                    name => {
                        let Some(stage) = stage_of(name) else {
                            continue;
                        };
                        staged(
                            &StagedFailure {
                                stage,
                                errno: step.errno,
                                reason,
                            },
                            &facts.run,
                        )
                    }
                };
                let slot = index(cap.id);
                if slots[slot].is_none() {
                    slots[slot] = Some(cap);
                }
            }

            // 2. Items without a failure: ok when every constituent step is ok,
            //    otherwise skipped with the cause.
            let userns_failed = slots[index(CapId::Userns)]
                .as_ref()
                .is_some_and(|c| c.status == Status::Fail);
            let netns_failed = slots[index(CapId::Netns)]
                .as_ref()
                .is_some_and(|c| c.status == Status::Fail);
            let bwrap_ok = matches!(facts.bwrap, BwrapStatus::Ok { .. });
            let bwrap_run_failed = slots[index(CapId::BwrapRun)]
                .as_ref()
                .is_some_and(|c| c.status == Status::Fail);
            for (id, constituents, ok_detail) in PROBE_SLOTS {
                if slots[index(id)].is_some() {
                    continue;
                }
                let all_ok = constituents.iter().all(|name| {
                    find_step(report, name).is_some_and(|s| s.status == StepStatus::Ok)
                });
                if all_ok {
                    slots[index(id)] = Some(ok_row(id, ok_detail));
                    continue;
                }
                let detail = if userns_failed {
                    SKIP_USERNS
                } else if matches!(id, CapId::BwrapRun | CapId::BwrapProc | CapId::Seccomp)
                    && !bwrap_ok
                {
                    SKIP_BWRAP
                } else if matches!(id, CapId::BwrapProc | CapId::Seccomp) && bwrap_run_failed {
                    SKIP_BWRAP_RUN
                } else if netns_failed {
                    SKIP_NETNS
                } else {
                    SKIP_PROBE
                };
                slots[index(id)] = Some(skip_row(id, detail));
            }

            // 3. The fallback item is warn-only while the full firewall works
            //    (the explicit path is not needed then).
            let nft_ok = slots[index(CapId::Nft)]
                .as_ref()
                .is_some_and(|c| c.status == Status::Ok);
            if let Some(fallback) = slots[index(CapId::Fallback)].as_mut() {
                if fallback.status == Status::Fail && nft_ok {
                    fallback.status = Status::Warn;
                    fallback.impact = None;
                }
            }
        }
    }

    slots[index(CapId::Bwrap)] = Some(bwrap(&facts.bwrap));
    slots[index(CapId::Landlock)] = Some(landlock(&facts.landlock));

    let capabilities: Vec<Capability> = CapId::ALL
        .iter()
        .map(|id| {
            slots[index(*id)]
                .take()
                .unwrap_or_else(|| skip_row(*id, SKIP_PROBE))
        })
        .collect();

    let network_mode = if probe_error.is_some() {
        EffectiveMode::Unavailable
    } else {
        capabilities
            .iter()
            .filter_map(|c| c.impact)
            .fold(EffectiveMode::Transparent, std::cmp::min)
    };

    Report {
        version: REPORT_VERSION,
        sbx_version: env!("CARGO_PKG_VERSION"),
        kernel: facts.kernel.clone(),
        network_mode,
        runnable_modes: network_mode.runnable_modes().to_vec(),
        probe_error,
        capabilities,
        policy: None,
    }
}

// ---------------------------------------------------------------------------
// refusal text and the policy comparison
// ---------------------------------------------------------------------------

fn mode_word(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Transparent => "transparent",
        NetworkMode::Explicit => "explicit",
        NetworkMode::None => "none",
    }
}

/// The refusal text for a policy whose mode the host cannot provide (shared by
/// `sbx run` and `sbx check --policy --host`). `Ok(())` iff provided.
pub fn check_mode(required: NetworkMode, provided: EffectiveMode) -> Result<(), String> {
    if provided.provides(required) {
        return Ok(());
    }
    match provided {
        EffectiveMode::Explicit => Err(format!(
            "policy requires network mode {} but this host provides only explicit",
            mode_word(required)
        )),
        _ => Err(format!(
            "policy requires network mode {} but this host cannot run sandboxes",
            mode_word(required)
        )),
    }
}

/// The policy against the host: four items in the fixed order `network-mode`,
/// `infra-etc`, `policy-paths`, `deny-paths`. `exists` and `is_non_dir` are the
/// filesystem seams (`metadata` based in production, injected in tests).
pub fn policy_check(
    path: &str,
    policy: &Policy,
    provided: EffectiveMode,
    exists: &dyn Fn(&Path) -> bool,
    is_non_dir: &dyn Fn(&Path) -> bool,
) -> PolicyCheck {
    policy_check_with(
        path,
        policy,
        provided,
        &Seams {
            exists,
            is_non_dir,
            verify: &guard::verify,
            alias: &|check: &AliasCheck| guard::verify_aliases(std::slice::from_ref(check)),
            bwrap: None,
            hard_links: &guard::hard_links_under,
        },
    )
}

/// The host-side seams of [`policy_check_with`]: the probes the pure
/// classification needs, injected so tests control them.
pub struct Seams<'a> {
    /// Whether a policy or infra path exists.
    pub exists: &'a dyn Fn(&Path) -> bool,
    /// Whether a deny path is present and not a directory.
    pub is_non_dir: &'a dyn Fn(&Path) -> bool,
    /// The fd-relative pre-launch walk (#39), per check.
    pub verify: &'a dyn Fn(&PathCheck) -> Result<(), GuardError>,
    /// The deny-alias refusal (#40, Q5), per alias pair.
    pub alias: &'a dyn Fn(&AliasCheck) -> Result<(), GuardError>,
    /// The usable bwrap's version, `None` when bwrap is unusable.
    pub bwrap: Option<(u32, u32, u32)>,
    /// The bounded hard-link scan of one deny path (Q6).
    pub hard_links: &'a dyn Fn(&Path) -> Vec<String>,
}

/// [`policy_check`] with explicit seams. Items: `network-mode`, `infra-etc`,
/// `policy-paths`, `deny-paths`, `mount-chains` (#39/#40, fails),
/// `bwrap-cve` (warns below 0.12.0), `deny-links` (warns on hard links).
/// Only a `Fail` makes the policy not runnable; `Warn` and `Skip` do not.
pub fn policy_check_with(
    path: &str,
    policy: &Policy,
    provided: EffectiveMode,
    seams: &Seams<'_>,
) -> PolicyCheck {
    let exists = seams.exists;
    let is_non_dir = seams.is_non_dir;
    let required = policy.network.mode;
    let mut checks = Vec::with_capacity(7);

    let network = match check_mode(required, provided) {
        Ok(()) => PolicyItem {
            id: "network-mode",
            status: Status::Ok,
            detail: format!(
                "policy requires {}; this host provides {}",
                mode_word(required),
                provided.as_str()
            ),
            fix: None,
        },
        Err(text) => PolicyItem {
            id: "network-mode",
            status: Status::Fail,
            detail: text,
            fix: Some(match provided {
                EffectiveMode::Explicit => {
                    "use network mode explicit or none, or fix the nft item".to_owned()
                }
                _ => "fix the failed host items".to_owned(),
            }),
        },
    };
    checks.push(network);

    let infra_missing: Vec<&str> = crate::bwrap::infra_etc_paths()
        .iter()
        .copied()
        .filter(|p| !exists(Path::new(p)))
        .collect();
    checks.push(list_item(
        "infra-etc",
        infra_missing.as_slice(),
        format!(
            "all {} infrastructure /etc paths exist",
            crate::bwrap::infra_etc_paths().len()
        ),
        "missing or inaccessible infrastructure paths (bwrap binds them and aborts without them)",
        "install the packages that provide them (for example ca-certificates and tzdata)",
    ));

    let policy_paths: Vec<String> = policy
        .filesystem
        .ro
        .iter()
        .chain(policy.filesystem.rw.iter())
        .map(|p| p.as_path().display().to_string())
        .collect();
    let policy_missing: Vec<String> = policy_paths
        .iter()
        .filter(|p| !exists(Path::new(p)))
        .cloned()
        .collect();
    checks.push(list_item(
        "policy-paths",
        &policy_missing,
        format!("all {} filesystem.ro/rw paths exist", policy_paths.len()),
        "missing or inaccessible policy paths (bwrap aborts on a missing bind source)",
        "create them or remove them from filesystem.ro/rw",
    ));

    let ro_rw: Vec<&Path> = policy
        .filesystem
        .ro
        .iter()
        .chain(policy.filesystem.rw.iter())
        .map(|p| p.as_path())
        .collect();
    let infra: Vec<&str> = crate::bwrap::infra_etc_paths().to_vec();
    let generated = crate::bwrap::generated_etc_paths();
    let flagged: Vec<String> = policy
        .filesystem
        .deny
        .iter()
        .map(|p| p.as_path())
        .filter(|deny| is_non_dir(deny))
        .filter(|deny| {
            ro_rw.iter().any(|root| deny.starts_with(root))
                || infra.iter().any(|root| deny.starts_with(root))
                || generated.iter().any(|g| *deny == Path::new(g))
        })
        .map(|deny| deny.display().to_string())
        .collect();
    checks.push(list_item(
        "deny-paths",
        &flagged,
        "no deny path is a file under a bound path or /etc".to_owned(),
        "deny paths that are files cannot be masked (bwrap mounts an empty tmpfs on each)",
        "deny the parent directory instead",
    ));

    let plan = crate::bwrap::path_plan(policy, None);
    checks.push(mount_chains_item(&plan, seams));
    let bwrap_item = bwrap_cve_item(plan.checks.len(), seams.bwrap);
    checks.push(bwrap_item);
    checks.push(pin_cost_item(plan.pins));
    checks.push(deny_links_item(policy, seams.hard_links));

    let runnable = checks.iter().all(|c| c.status != Status::Fail);
    PolicyCheck {
        path: path.to_owned(),
        required,
        runnable,
        checks,
    }
}

/// `mount-chains` (#39/#40, fails): every bwrap-resolved path under a writable
/// bind must be a real directory chain (or the right type at the end), and no
/// deny path may be reachable through a host alias. The same refusal `run`
/// makes at S8a, so a policy that fails here fails there.
fn mount_chains_item(plan: &crate::bwrap::Plan, seams: &Seams<'_>) -> PolicyItem {
    let mut reasons: Vec<String> = Vec::new();
    for check in &plan.checks {
        if let Err(err) = (seams.verify)(check) {
            reasons.push(err.to_string());
        }
    }
    for alias in &plan.aliases {
        if let Err(err) = (seams.alias)(alias) {
            reasons.push(err.to_string());
        }
    }
    reasons.dedup();
    let n = plan.checks.len();
    if reasons.is_empty() {
        return PolicyItem {
            id: "mount-chains",
            status: Status::Ok,
            detail: format!(
                "{n} mount paths under the binds are real directories; no deny path has a host alias"
            ),
            fix: None,
        };
    }
    PolicyItem {
        id: "mount-chains",
        status: Status::Fail,
        detail: reasons.join("; "),
        fix: Some(
            "remove the symbolic links, create the missing directories on the host, or move the entries out of the rw paths"
                .to_owned(),
        ),
    }
}

/// `bwrap-cve` (warns, never fails): bubblewrap below 0.12.0 predates the
/// CVE-2026-87766 fix, unless the distribution backported it. Only a policy
/// with mount paths under a policy or session bind is affected (a read-only
/// bind too: the CVE's mkdir follows a planted link under any bind).
fn bwrap_cve_item(n: usize, bwrap: Option<(u32, u32, u32)>) -> PolicyItem {
    use crate::bwrap::version::BWRAP_CVE_FIXED;
    let Some(version) = bwrap else {
        return PolicyItem {
            id: "bwrap-cve",
            status: Status::Skip,
            detail: "bubblewrap is not usable on this host, so its version was not compared with the CVE-2026-87766 fix".to_owned(),
            fix: None,
        };
    };
    let shown = format!("{}.{}.{}", version.0, version.1, version.2);
    if version >= BWRAP_CVE_FIXED || n == 0 {
        return PolicyItem {
            id: "bwrap-cve",
            status: Status::Ok,
            detail: if version >= BWRAP_CVE_FIXED {
                format!("bubblewrap {shown} carries the CVE-2026-87766 fix (0.12.0 or later)")
            } else {
                format!(
                    "bubblewrap {shown} predates 0.12.0, but this policy has no mount paths under its binds"
                )
            },
            fix: None,
        };
    }
    PolicyItem {
        id: "bwrap-cve",
        status: Status::Warn,
        detail: format!(
            "bubblewrap {shown} predates 0.12.0 (CVE-2026-87766) unless your distribution backported the fix; this policy has {n} mount paths under its binds. sbx verifies them before each run, but a concurrent writer can still race that check"
        ),
        fix: Some("install bubblewrap 0.12.0 or later".to_owned()),
    }
}

/// `pin-cost` (warns above 50 pins): every pin is one more bind for bwrap,
/// which re-reads mountinfo per bind, so startup grows superlinearly with the
/// pin count (about 13 ms at 0 pins and 28 ms at 60 pins on WSL2).
fn pin_cost_item(pins: usize) -> PolicyItem {
    if pins <= PIN_WARN_THRESHOLD {
        return PolicyItem {
            id: "pin-cost",
            status: Status::Ok,
            detail: format!(
                "{pins} directory pins for the rw tree (warns above {PIN_WARN_THRESHOLD})"
            ),
            fix: None,
        };
    }
    PolicyItem {
        id: "pin-cost",
        status: Status::Warn,
        detail: format!(
            "{pins} directory pins are needed (sbx pins the parents of nested binds and deny masks under rw paths); bwrap re-reads mountinfo per bind, so startup grows superlinearly with the pin count (measured on WSL2: 60 pins +17 ms, 300 pins +180 ms, 900 pins +1 s)"
        ),
        fix: Some(
            "flatten the deny and nested-bind layout (fewer deny entries below nested directories), or deny a parent directory instead".to_owned(),
        ),
    }
}

/// The pin count above which `sbx check` warns (see `pin-cost`).
pub const PIN_WARN_THRESHOLD: usize = 50;

/// `deny-links` (warns): a regular file under a deny path that has another
/// hard link is visible through that name, which the mask does not hide.
fn deny_links_item(policy: &Policy, hard_links: &dyn Fn(&Path) -> Vec<String>) -> PolicyItem {
    // Only a deny under a policy path names a host directory the sandbox can
    // see; a session-only deny (under /root, /tmp or /work) has no host state.
    let policy_paths: Vec<&Path> = policy
        .filesystem
        .ro
        .iter()
        .chain(policy.filesystem.rw.iter())
        .map(|p| p.as_path())
        .collect();
    let found: Vec<String> = policy
        .filesystem
        .deny
        .iter()
        .map(|deny| deny.as_path())
        .filter(|deny| policy_paths.iter().any(|root| deny.starts_with(root)))
        .flat_map(hard_links)
        .collect();
    if found.is_empty() {
        return PolicyItem {
            id: "deny-links",
            status: Status::Ok,
            detail: "no regular file under a deny path has another hard link".to_owned(),
            fix: None,
        };
    }
    PolicyItem {
        id: "deny-links",
        status: Status::Warn,
        detail: format!(
            "{} file(s) under deny paths have another hard link, which a host process can read under that name: {}",
            found.len(),
            found.join(", ")
        ),
        fix: Some("remove the extra hard links, or deny the other names as well".to_owned()),
    }
}

/// One path-list item: ok with `ok_detail` when `missing` is empty, else a
/// failure listing the paths (`, `-joined) after `fail_text`.
fn list_item<S: AsRef<str>>(
    id: &'static str,
    missing: &[S],
    ok_detail: String,
    fail_text: &str,
    fix: &str,
) -> PolicyItem {
    if missing.is_empty() {
        return PolicyItem {
            id,
            status: Status::Ok,
            detail: ok_detail,
            fix: None,
        };
    }
    let list: Vec<&str> = missing.iter().map(|s| s.as_ref()).collect();
    PolicyItem {
        id,
        status: Status::Fail,
        detail: format!("{fail_text}: {}", list.join(", ")),
        fix: Some(fix.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::host::facts::Sysctls;
    use crate::init::fdpass::StagedFailure;

    fn f(stage: Stage, errno: Option<i32>, reason: &str) -> StagedFailure {
        StagedFailure {
            stage,
            errno,
            reason: reason.to_owned(),
        }
    }

    /// (stage, errno, facts, expected id, expected detail) — one row per §5.1.
    #[test]
    fn staged_table() {
        let none = RunFacts::default();
        let aa = sysctls(Some(1), None, None);
        let clone0 = sysctls(Some(0), Some(0), None);
        let max0 = sysctls(Some(0), None, Some(0));
        let max_big = sysctls(Some(0), None, Some(2147483647));
        let netns0 = RunFacts {
            sysctl: Sysctls {
                max_user_namespaces: Some(15000),
                max_net_namespaces: Some(0),
                ..Default::default()
            },
            seccomp: None,
        };
        let seccomp2 = RunFacts {
            seccomp: Some(2),
            ..RunFacts::default()
        };
        let cases: Vec<(StagedFailure, RunFacts, CapId, (&str, &str))> = vec![
            (
                f(Stage::Unshare, Some(libc::EPERM), "x"),
                aa,
                CapId::Userns,
                U_APPARMOR,
            ),
            (
                f(Stage::Idmap, Some(libc::EACCES), "x"),
                aa,
                CapId::Userns,
                U_APPARMOR,
            ),
            (
                f(Stage::Netns, Some(libc::EPERM), "x"),
                aa,
                CapId::Userns,
                U_APPARMOR,
            ),
            (
                f(Stage::Listeners, Some(libc::EPERM), "x"),
                aa,
                CapId::Userns,
                U_APPARMOR,
            ),
            (
                f(Stage::Ipv6, Some(libc::EPERM), "x"),
                aa,
                CapId::Userns,
                U_APPARMOR,
            ),
            (
                f(Stage::Unshare, Some(libc::EPERM), "x"),
                clone0,
                CapId::Userns,
                U_CLONE_SYSCTL,
            ),
            (
                f(Stage::Unshare, Some(libc::EPERM), "x"),
                seccomp2,
                CapId::Userns,
                U_SECCOMP,
            ),
            (
                f(Stage::Unshare, Some(libc::EPERM), "x"),
                none,
                CapId::Userns,
                U_EPERM,
            ),
            (
                f(Stage::Unshare, Some(libc::ENOSPC), "x"),
                max0,
                CapId::Userns,
                U_MAX_ZERO,
            ),
            (
                f(Stage::Unshare, Some(libc::ENOSPC), "x"),
                max_big,
                CapId::Userns,
                U_ENOSPC,
            ),
            (
                f(Stage::Unshare, Some(libc::ENOSPC), "x"),
                netns0,
                CapId::Userns,
                U_MAX_NET_ZERO,
            ),
            (
                f(Stage::Unshare, Some(libc::EUSERS), "x"),
                none,
                CapId::Userns,
                U_EUSERS,
            ),
            (
                f(Stage::Unshare, Some(libc::EINVAL), "x"),
                none,
                CapId::Userns,
                U_EINVAL,
            ),
            (f(Stage::Unshare, None, "x"), none, CapId::Userns, U_OTHER),
            (
                f(Stage::Idmap, Some(libc::EROFS), "x"),
                none,
                CapId::Userns,
                U_IDMAP,
            ),
            (
                f(Stage::Netns, Some(libc::ENOENT), "x"),
                none,
                CapId::Netns,
                N_NETNS,
            ),
            (
                f(Stage::Listeners, Some(libc::EADDRINUSE), "x"),
                none,
                CapId::Netns,
                N_LISTENERS,
            ),
            (
                f(Stage::Ipv6, Some(libc::EROFS), "x"),
                none,
                CapId::NetnsIpv6,
                V_EROFS,
            ),
            (
                f(Stage::Ipv6, Some(libc::EPERM), "x"),
                none,
                CapId::NetnsIpv6,
                V_DENIED,
            ),
            (
                f(Stage::Ipv6, Some(libc::EACCES), "x"),
                none,
                CapId::NetnsIpv6,
                V_DENIED,
            ),
            (f(Stage::Ipv6, None, "x"), none, CapId::NetnsIpv6, V_OTHER),
            (f(Stage::NftLoad, Some(2), "x"), none, CapId::Nft, T_LOAD),
            (f(Stage::NftVerify, None, "x"), none, CapId::Nft, T_VERIFY),
            (f(Stage::Fallback, None, "x"), none, CapId::Fallback, F_FAIL),
            (f(Stage::Control, None, "x"), none, CapId::Netns, N_INTERNAL),
            (f(Stage::SendFds, None, "x"), none, CapId::Netns, N_INTERNAL),
            (f(Stage::WaitGo, None, "x"), none, CapId::Netns, N_INTERNAL),
            (f(Stage::Exec, None, "x"), none, CapId::Netns, N_INTERNAL),
        ];
        for (failure, facts, id, pinned) in cases {
            let cap = staged(&failure, &facts);
            assert_eq!(cap.id, id, "{failure:?}");
            assert_eq!(cap.status, Status::Fail, "{failure:?}");
            assert_eq!(cap.detail, pinned.0, "{failure:?}");
            assert_eq!(cap.fix.as_deref(), Some(pinned.1), "{failure:?}");
            assert_eq!(cap.evidence.as_deref(), Some(failure.to_string().as_str()));
            assert_eq!(cap.errno, failure.errno);
        }
    }

    #[test]
    fn staged_impacts() {
        let none = RunFacts::default();
        let impact = |f: StagedFailure| staged(&f, &none).impact;
        assert_eq!(
            impact(f(Stage::NftLoad, Some(2), "x")),
            Some(EffectiveMode::Explicit)
        );
        assert_eq!(
            impact(f(Stage::NftVerify, None, "x")),
            Some(EffectiveMode::Unavailable)
        );
        assert_eq!(
            impact(f(Stage::Unshare, Some(libc::EPERM), "x")),
            Some(EffectiveMode::Unavailable)
        );
        assert_eq!(
            impact(f(Stage::Fallback, None, "x")),
            Some(EffectiveMode::Unavailable)
        );
    }

    #[test]
    fn bwrap_step_rows() {
        let run_ro = bwrap_step(
            CapId::BwrapRun,
            "bwrap: cannot open /proc/sys/user/max_user_namespaces: Read-only file system",
        );
        assert_eq!(run_ro.detail, R_ROFS.0);
        assert_eq!(run_ro.fix.as_deref(), Some(R_ROFS.1));
        let run = bwrap_step(CapId::BwrapRun, "bwrap: setup failed");
        assert_eq!(run.detail, R_FAIL.0);
        let proc = bwrap_step(CapId::BwrapProc, "bwrap: Can't mount proc");
        assert_eq!(proc.detail, P_FAIL.0);
        for cap in [run_ro, run, proc] {
            assert_eq!(cap.status, Status::Fail);
            assert_eq!(cap.impact, Some(EffectiveMode::Unavailable));
            assert_eq!(cap.errno, None);
        }
    }

    #[test]
    fn bwrap_rows_pinned() {
        let ok = bwrap(&bwrap_ok());
        assert_eq!(ok.status, Status::Ok);
        assert_eq!(ok.detail, "bubblewrap 0.9.0 at /usr/bin/bwrap");
        let nf = bwrap(&BwrapStatus::NotFound);
        assert_eq!(nf.detail, B_NOT_FOUND.0);
        assert_eq!(nf.fix.as_deref(), Some(B_NOT_FOUND.1));
        let old = bwrap(&BwrapStatus::Unsupported {
            path: "/x/bwrap".into(),
            first_line: "bubblewrap 0.7.9".into(),
            why: Unsupported::TooOld((0, 7, 9)),
        });
        assert_eq!(
            old.detail,
            "bubblewrap 0.7.9 at /x/bwrap is too old (need >= 0.8.0 for --disable-userns)"
        );
        let unparse = bwrap(&BwrapStatus::Unsupported {
            path: "/x/bwrap".into(),
            first_line: "bubblewrap 0.9.0-1".into(),
            why: Unsupported::Unparseable,
        });
        assert_eq!(
            unparse.detail,
            "cannot parse the version reported by /x/bwrap (\"bubblewrap 0.9.0-1\")"
        );
        let exit = bwrap(&BwrapStatus::Unsupported {
            path: "/x/bwrap".into(),
            first_line: String::new(),
            why: Unsupported::ExitStatus(Some(1)),
        });
        assert_eq!(exit.detail, "/x/bwrap --version failed (exit status 1)");
        let sig = bwrap(&BwrapStatus::Unsupported {
            path: "/x/bwrap".into(),
            first_line: String::new(),
            why: Unsupported::ExitStatus(None),
        });
        assert_eq!(sig.detail, "/x/bwrap --version failed (killed by a signal)");
        let spawn = bwrap(&BwrapStatus::SpawnFailed {
            path: "/x/bwrap".into(),
            error: "No such file".into(),
        });
        assert_eq!(spawn.detail, "cannot run /x/bwrap --version: No such file");
    }

    #[test]
    fn landlock_rows() {
        let abi = landlock(&Landlock::Abi(7));
        assert_eq!(abi.status, Status::Ok);
        assert_eq!(abi.detail, "Landlock ABI 7 (report-only)");
        assert_eq!(abi.impact, None);
        let enosys = landlock(&Landlock::Errno(libc::ENOSYS));
        assert_eq!(enosys.status, Status::Warn);
        assert_eq!(enosys.detail, L_ENOSYS.0);
        let disabled = landlock(&Landlock::Errno(libc::EOPNOTSUPP));
        assert_eq!(disabled.detail, L_DISABLED.0);
        let other = landlock(&Landlock::Errno(libc::EPERM));
        assert_eq!(
            other.detail,
            format!(
                "Landlock status unknown (errno {}, report-only)",
                libc::EPERM
            )
        );
        assert_eq!(other.impact, None);
        assert!(other.fix.is_some());
    }

    #[test]
    fn pinned_strings() {
        assert_eq!(OK_USERNS, "unprivileged user + network namespaces work");
        assert_eq!(SKIP_USERNS, "not probed: user namespaces are unavailable");
        assert_eq!(
            SKIP_NETNS,
            "not probed: the sandbox network could not be configured"
        );
        assert_eq!(SKIP_BWRAP, "not probed: bwrap is unavailable");
        assert_eq!(
            SKIP_BWRAP_RUN,
            "not probed: bwrap cannot start a sandbox here"
        );
        assert_eq!(SKIP_PROBE, "not probed: the namespace probe failed");
        assert_eq!(
            T_LOAD.0,
            "nftables NAT redirect is unavailable (transparent mode needs it; explicit and none do not)"
        );
        assert_eq!(
            U_MAX_ZERO.0,
            "user namespaces are disabled (user.max_user_namespaces = 0)"
        );
        assert_eq!(
            U_CLONE_SYSCTL.1,
            "sudo sysctl -w kernel.unprivileged_userns_clone=1"
        );
        assert_eq!(
            BUG_FIX,
            "report a bug at https://github.com/vdavamse/sbx/issues with the evidence line and `uname -r`"
        );
    }

    #[test]
    fn every_fail_has_fix() {
        let all: Vec<Capability> = vec![
            staged(
                &f(Stage::Unshare, Some(libc::EPERM), "x"),
                &RunFacts::default(),
            ),
            staged(&f(Stage::Ipv6, None, "x"), &RunFacts::default()),
            staged(&f(Stage::NftLoad, None, "x"), &RunFacts::default()),
            staged(&f(Stage::Fallback, None, "x"), &RunFacts::default()),
            bwrap_step(CapId::BwrapRun, "x"),
            bwrap_step(CapId::BwrapProc, "x"),
            bwrap(&BwrapStatus::NotFound),
            bwrap(&BwrapStatus::SpawnFailed {
                path: "/b".into(),
                error: "e".into(),
            }),
            landlock(&Landlock::Errno(libc::ENOSYS)),
            landlock(&Landlock::Errno(libc::EPERM)),
        ];
        for cap in all {
            if matches!(cap.status, Status::Fail | Status::Warn) {
                assert!(cap.fix.is_some(), "{cap:?}");
            }
        }
    }

    #[test]
    fn assemble_unexplained_skips_fail_closed() {
        // m2 (review): every probe step skipped with no cause → unavailable.
        let mut probe = ok_steps();
        for step in &mut probe.steps {
            step.status = StepStatus::Skip;
            step.reason = Some("x".into());
        }
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            RunFacts::default(),
        ));
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
        assert_eq!(crate::host::report::exit_code(&report), 1);
        let userns = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Userns)
            .expect("userns");
        assert_eq!(userns.detail, SKIP_PROBE);
        assert_eq!(userns.impact, Some(EffectiveMode::Unavailable));
    }

    #[test]
    fn staged_seccomp_beats_apparmor_at_unshare() {
        // M1 (review): AppArmor restriction on an unconfined process surfaces
        // at idmap or later; at unshare with seccomp filter 2 the seccomp row wins.
        let f = StagedFailure {
            stage: Stage::Unshare,
            errno: Some(libc::EPERM),
            reason: "unshare failed: Operation not permitted (os error 1)".into(),
        };
        let facts = RunFacts {
            sysctl: sysctls(Some(1), None, None).sysctl,
            seccomp: Some(2),
        };
        let cap = staged(&f, &facts);
        assert_eq!(cap.detail, U_SECCOMP.0);
        assert_eq!(cap.fix.as_deref(), Some(U_SECCOMP.1));
        // Without the seccomp filter the AppArmor row still applies at unshare.
        let apparmor_only = staged(&f, &sysctls(Some(1), None, None));
        assert_eq!(apparmor_only.detail, U_APPARMOR.0);
    }

    #[test]
    fn assemble_all_ok() {
        let report = assemble(&ok_host());
        assert_eq!(report.network_mode, EffectiveMode::Transparent);
        assert_eq!(report.probe_error, None);
        assert_eq!(report.capabilities.len(), 10);
        assert!(report.capabilities.iter().all(|c| c.status == Status::Ok));
        let ids: Vec<CapId> = report.capabilities.iter().map(|c| c.id).collect();
        assert_eq!(ids, CapId::ALL);
    }

    #[test]
    fn assemble_nft_fail_explicit() {
        let probe = ProbeOutcome::Ran(with_step(
            with_step(
                ok_steps(),
                "nft-load",
                StepStatus::Fail,
                Some(2),
                Some("batch failed (attempt 1/5, genid 1): No such file or directory (os error 2)"),
            ),
            "nft-verify",
            StepStatus::Skip,
            None,
            Some("skipped: nft-load failed"),
        ));
        let report = assemble(&host(probe, bwrap_ok(), RunFacts::default()));
        assert_eq!(report.network_mode, EffectiveMode::Explicit);
        let nft = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Nft)
            .expect("nft");
        assert_eq!(nft.status, Status::Fail);
        assert_eq!(nft.impact, Some(EffectiveMode::Explicit));
        assert_eq!(
            nft.evidence.as_deref(),
            Some(
                "nft-load: batch failed (attempt 1/5, genid 1): No such file or directory (os error 2)"
            )
        );
        let fallback = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Fallback)
            .expect("fallback");
        assert_eq!(fallback.status, Status::Ok);
        assert_eq!(report.runnable_modes, vec!["explicit", "none"]);
    }

    #[test]
    fn assemble_nft_and_fallback_fail_unavailable() {
        let mut probe = failed_at("nft-load", Some(2), "x", "skipped: nft-load failed");
        for step in &mut probe.steps {
            if step.step == "fallback" {
                step.status = StepStatus::Fail;
                step.reason = Some("route del default: gone".into());
            }
        }
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            RunFacts::default(),
        ));
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
        let fallback = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Fallback)
            .expect("fallback");
        assert_eq!(fallback.status, Status::Fail);
        assert_eq!(fallback.impact, Some(EffectiveMode::Unavailable));
    }

    #[test]
    fn assemble_fallback_fail_nft_ok_warns() {
        let mut probe = ok_steps();
        for step in &mut probe.steps {
            if step.step == "fallback" {
                step.status = StepStatus::Fail;
                step.reason = Some("route del default: no such route".into());
            }
        }
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            RunFacts::default(),
        ));
        let fallback = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Fallback)
            .expect("fallback");
        assert_eq!(fallback.status, Status::Warn);
        assert_eq!(fallback.impact, None);
        assert!(fallback.fix.is_some());
        assert_eq!(report.network_mode, EffectiveMode::Transparent);
    }

    #[test]
    fn assemble_userns_fail_skips() {
        let probe = failed_at(
            "unshare",
            Some(28),
            "unshare failed: No space left on device (os error 28)",
            "skipped: unshare failed",
        );
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            sysctls(Some(0), None, Some(2147483647)),
        ));
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
        let by = |id| {
            report
                .capabilities
                .iter()
                .find(|c| c.id == id)
                .expect("row")
                .clone()
        };
        assert_eq!(by(CapId::Userns).detail, U_ENOSPC.0);
        assert_eq!(by(CapId::Netns).detail, SKIP_USERNS);
        assert_eq!(by(CapId::NetnsIpv6).detail, SKIP_USERNS);
        assert_eq!(by(CapId::Nft).detail, SKIP_USERNS);
        assert_eq!(by(CapId::Fallback).detail, SKIP_USERNS);
        assert_eq!(by(CapId::BwrapRun).detail, SKIP_USERNS);
        assert_eq!(by(CapId::BwrapProc).detail, SKIP_USERNS);
        assert_eq!(by(CapId::Bwrap).status, Status::Ok);
        assert_eq!(by(CapId::Landlock).status, Status::Ok);
    }

    #[test]
    fn assemble_apparmor_at_idmap_routes_to_userns() {
        let probe = failed_at(
            "idmap",
            Some(libc::EPERM),
            "write /proc/self/setgroups: Operation not permitted",
            "skipped: idmap failed",
        );
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            sysctls(Some(1), None, None),
        ));
        let userns = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::Userns)
            .expect("userns");
        assert_eq!(userns.detail, U_APPARMOR.0);
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
    }

    #[test]
    fn assemble_ipv6_erofs() {
        let probe = with_step(
            ok_steps(),
            "ipv6",
            StepStatus::Fail,
            Some(libc::EROFS),
            Some("write disable_ipv6 failed: Read-only file system (os error 30)"),
        );
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            RunFacts::default(),
        ));
        let v6 = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::NetnsIpv6)
            .expect("ipv6");
        assert_eq!(v6.detail, V_EROFS.0);
        assert_eq!(v6.errno, Some(libc::EROFS));
        let run = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::BwrapRun)
            .expect("bwrap-run");
        assert_eq!(run.status, Status::Ok, "ipv6 never cascades");
    }

    #[test]
    fn assemble_bwrap_missing_skips_bwrap_steps() {
        let report = assemble(&host(
            ProbeOutcome::Ran(ok_steps()),
            BwrapStatus::NotFound,
            RunFacts::default(),
        ));
        let by = |id| {
            report
                .capabilities
                .iter()
                .find(|c| c.id == id)
                .expect("row")
                .clone()
        };
        assert_eq!(by(CapId::Bwrap).detail, B_NOT_FOUND.0);
        assert_eq!(
            by(CapId::BwrapRun).status,
            Status::Ok,
            "the probe ran its own bwrap"
        );
    }

    #[test]
    fn assemble_bwrap_run_rofs() {
        let probe = failed_at(
            "bwrap-run",
            None,
            "bwrap: cannot open /proc/sys/user/max_user_namespaces: Read-only file system",
            "x",
        );
        let report = assemble(&host(
            ProbeOutcome::Ran(probe),
            bwrap_ok(),
            RunFacts::default(),
        ));
        let run = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::BwrapRun)
            .expect("run");
        assert_eq!(run.detail, R_ROFS.0);
        let proc = report
            .capabilities
            .iter()
            .find(|c| c.id == CapId::BwrapProc)
            .expect("proc");
        assert_eq!(proc.detail, SKIP_BWRAP_RUN);
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
    }

    #[test]
    fn assemble_probe_failed() {
        let report = assemble(&host(
            ProbeOutcome::Failed("timed out after 20s".into()),
            bwrap_ok(),
            RunFacts::default(),
        ));
        assert_eq!(report.probe_error.as_deref(), Some("timed out after 20s"));
        assert_eq!(report.network_mode, EffectiveMode::Unavailable);
        let by = |id| {
            report
                .capabilities
                .iter()
                .find(|c| c.id == id)
                .expect("row")
                .clone()
        };
        assert_eq!(by(CapId::Userns).detail, SKIP_PROBE);
        assert_eq!(by(CapId::Bwrap).status, Status::Ok);
    }

    #[test]
    fn check_mode_matrix() {
        use NetworkMode::{Explicit, None as NoNet, Transparent};
        for required in [NoNet, Explicit, Transparent] {
            for provided in [
                EffectiveMode::Unavailable,
                EffectiveMode::Explicit,
                EffectiveMode::Transparent,
            ] {
                let got = check_mode(required, provided);
                let want = provided.provides(required);
                assert_eq!(got.is_ok(), want, "{required:?} vs {provided:?}");
            }
        }
        assert_eq!(
            check_mode(Transparent, EffectiveMode::Explicit),
            Err(
                "policy requires network mode transparent but this host provides only explicit"
                    .to_owned()
            )
        );
        assert_eq!(
            check_mode(NoNet, EffectiveMode::Unavailable),
            Err("policy requires network mode none but this host cannot run sandboxes".to_owned())
        );
    }

    #[test]
    fn effective_mode_provides_matrix() {
        use NetworkMode::{Explicit, None as NoNet, Transparent};
        assert!(EffectiveMode::Transparent.provides(Transparent));
        assert!(EffectiveMode::Transparent.provides(Explicit));
        assert!(EffectiveMode::Transparent.provides(NoNet));
        assert!(!EffectiveMode::Explicit.provides(Transparent));
        assert!(EffectiveMode::Explicit.provides(Explicit));
        assert!(EffectiveMode::Explicit.provides(NoNet));
        assert!(!EffectiveMode::Unavailable.provides(NoNet));
        assert_eq!(EffectiveMode::Unavailable.runnable_modes(), &[] as &[&str]);
        assert_eq!(
            EffectiveMode::Explicit.runnable_modes(),
            &["explicit", "none"]
        );
    }

    fn policy_of(json: &str) -> Policy {
        Policy::from_json_str(json).expect("policy parses")
    }

    #[test]
    fn policy_check_table() {
        let json = r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":["/tmp/sbx-rw-check"],"deny":["/usr/lib/secret","/etc/passwd"]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let policy = policy_of(json);
        let all_exist = |_: &Path| true;
        let all_files = |_: &Path| true;
        let ok = policy_check(
            "p.json",
            &policy,
            EffectiveMode::Transparent,
            &all_exist,
            &|_| false,
        );
        assert!(ok.runnable, "{ok:?}");
        assert_eq!(
            ok.checks[0].detail,
            "policy requires transparent; this host provides transparent"
        );
        assert_eq!(ok.checks[1].detail, "all 7 infrastructure /etc paths exist");
        assert_eq!(ok.checks[2].detail, "all 2 filesystem.ro/rw paths exist");
        assert_eq!(
            ok.checks[3].detail,
            "no deny path is a file under a bound path or /etc"
        );
        // missing ro path
        let missing_ro = |p: &Path| p != Path::new("/usr");
        let r = policy_check(
            "p.json",
            &policy,
            EffectiveMode::Transparent,
            &missing_ro,
            &|_| false,
        );
        assert!(!r.runnable);
        assert_eq!(r.checks[2].status, Status::Fail);
        assert!(
            r.checks[2].detail.ends_with(": /usr"),
            "{:?}",
            r.checks[2].detail
        );
        // deny file under a ro root
        let r = policy_check(
            "p.json",
            &policy,
            EffectiveMode::Transparent,
            &all_exist,
            &all_files,
        );
        assert_eq!(r.checks[3].status, Status::Fail);
        assert!(
            r.checks[3].detail.contains("/usr/lib/secret"),
            "{:?}",
            r.checks[3].detail
        );
        // deny == a generated /etc file
        assert!(
            r.checks[3].detail.contains("/etc/passwd"),
            "{:?}",
            r.checks[3].detail
        );
        // network mismatch
        let r = policy_check(
            "p.json",
            &policy,
            EffectiveMode::Explicit,
            &all_exist,
            &|_| false,
        );
        assert_eq!(r.checks[0].status, Status::Fail);
        assert_eq!(
            r.checks[0].fix.as_deref(),
            Some("use network mode explicit or none, or fix the nft item")
        );
        // missing infra
        let no_infra = |p: &Path| !p.starts_with("/etc/");
        let r = policy_check(
            "p.json",
            &policy,
            EffectiveMode::Transparent,
            &no_infra,
            &|_| false,
        );
        assert_eq!(r.checks[1].status, Status::Fail);
        assert!(r.checks[1].detail.starts_with("missing or inaccessible infrastructure paths (bwrap binds them and aborts without them): "));
    }

    /// Seams for the new items: real existence, injected walk/alias/links.
    fn new_seams<'a>(
        exists: &'a dyn Fn(&Path) -> bool,
        is_non_dir: &'a dyn Fn(&Path) -> bool,
        verify: &'a dyn Fn(&PathCheck) -> Result<(), GuardError>,
        bwrap: Option<(u32, u32, u32)>,
        hard_links: &'a dyn Fn(&Path) -> Vec<String>,
    ) -> Seams<'a> {
        Seams {
            exists,
            is_non_dir,
            verify,
            alias: &|_| Ok(()),
            bwrap,
            hard_links,
        }
    }

    #[test]
    fn mount_chain_failure_fails_the_item_and_the_policy() {
        // The walk's refusal reason is the item's detail, and it blocks.
        let json = r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":["/tmp"],"deny":["/tmp/x/secret"]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let all = |_: &Path| true;
        let no = |_: &Path| false;
        let refuse = |c: &PathCheck| {
            Err(GuardError::new(format!(
                "unsafe filesystem path {:?}: boom",
                c.target
            )))
        };
        let none = |_: &Path| Vec::new();
        let seams = new_seams(&all, &no, &refuse, Some((0, 12, 0)), &none);
        let r = policy_check_with(
            "p.json",
            &policy_of(json),
            EffectiveMode::Transparent,
            &seams,
        );
        let item = r
            .checks
            .iter()
            .find(|c| c.id == "mount-chains")
            .expect("item");
        assert_eq!(item.status, Status::Fail);
        assert!(
            item.detail
                .contains("unsafe filesystem path \"/tmp/x/secret\": boom"),
            "{}",
            item.detail
        );
        assert!(!r.runnable);
        assert_eq!(
            item.fix.as_deref().map(|f| f.contains("symbolic links")),
            Some(true)
        );
    }

    #[test]
    fn bwrap_cve_warns_below_0_12_only_with_mount_paths() {
        let with_rw = r#"{"version":1,"filesystem":{"ro":["/usr","/tmp/x"],"rw":["/tmp"],"deny":[]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let no_rw = r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":[],"deny":[]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let all = |_: &Path| true;
        let no = |_: &Path| false;
        let ok = |_: &PathCheck| Ok(());
        let none = |_: &Path| Vec::new();
        let item = |json: &str, bwrap: Option<(u32, u32, u32)>| {
            let seams = new_seams(&all, &no, &ok, bwrap, &none);
            let r = policy_check_with(
                "p.json",
                &policy_of(json),
                EffectiveMode::Transparent,
                &seams,
            );
            let cve = r
                .checks
                .into_iter()
                .find(|c| c.id == "bwrap-cve")
                .expect("item");
            (cve, r.runnable)
        };
        // 0.9.0 with a rw tree: the warning, and the policy still runs.
        let (cve, runnable) = item(with_rw, Some((0, 9, 0)));
        assert_eq!(cve.status, Status::Warn);
        assert!(
            cve.detail.contains("predates 0.12.0 (CVE-2026-87766)"),
            "{}",
            cve.detail
        );
        assert!(runnable);
        // 0.9.0 with no rw path: nothing to warn about.
        let (cve, _) = item(no_rw, Some((0, 9, 0)));
        assert_eq!(cve.status, Status::Ok);
        // 0.12.0: fixed.
        let (cve, _) = item(with_rw, Some((0, 12, 0)));
        assert_eq!(cve.status, Status::Ok);
        // No usable bwrap: skipped, and not a refusal by itself.
        let (cve, runnable) = item(with_rw, None);
        assert_eq!(cve.status, Status::Skip);
        assert!(runnable);
    }

    #[test]
    fn deny_links_warns_without_blocking() {
        let json = r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":[],"deny":["/usr/lib/secret"]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let all = |_: &Path| true;
        let no = |_: &Path| false;
        let ok = |_: &PathCheck| Ok(());
        let links = |_: &Path| vec!["/usr/lib/secret/key".to_owned()];
        let seams = new_seams(&all, &no, &ok, Some((0, 12, 0)), &links);
        let r = policy_check_with(
            "p.json",
            &policy_of(json),
            EffectiveMode::Transparent,
            &seams,
        );
        let item = r
            .checks
            .iter()
            .find(|c| c.id == "deny-links")
            .expect("item");
        assert_eq!(item.status, Status::Warn);
        assert!(
            item.detail.contains("/usr/lib/secret/key"),
            "{}",
            item.detail
        );
        assert!(r.runnable, "a hard-link warning must not block the run");
    }

    #[test]
    fn policy_deny_dir_is_ok() {
        let json = r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":[],"deny":["/usr/lib/secret"]},"network":{"mode":"explicit","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#;
        let r = policy_check(
            "p.json",
            &policy_of(json),
            EffectiveMode::Explicit,
            &|_| true,
            &|_| false,
        );
        assert!(r.runnable);
    }
}
