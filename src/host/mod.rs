//! `sbx check` — host capability detection and the effective network mode
//! (issue #11).
//!
//! `sbx run` assumes nothing about the host it runs on: it asks `__init` to
//! set the sandbox up and turns a staged failure into a classified refusal.
//! `sbx check` answers the same question up front. One classifier
//! ([`classify`]) serves both: `check` feeds it from a throwaway probe
//! (`sbx __init --probe`, the same stage functions in a disposable
//! namespace, plus two nested bwrap launches), `run` feeds it from the staged
//! failure `__init` reports over the control socket. There are no stderr
//! parsers and no extra process spawns on a healthy `run`.
//!
//! Module map: [`facts`] gathers the impure inputs (sysctls, seccomp,
//! Landlock syscall, `bwrap --version`, the probe); [`classify`] is the pure
//! mapping from those facts to report items and pinned texts; [`report`]
//! renders the human and JSON reports and the exit code.
//!
//! Network-mode ladder: `transparent` (the full firewall) > `explicit` (the
//! no-nft variant; serves `explicit` and `none` policies) > `unavailable`.
//! Exit codes (Q4): 0 = report produced and the effective mode is at least
//! explicit (and, with `--policy P --host`, the policy runs here); 1 =
//! unavailable, a probe failure, an invalid policy, or a policy that needs
//! more than the host provides; 2 = usage (clap).

pub mod classify;
pub mod facts;
pub mod report;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::bwrap::version::BwrapStatus;
use crate::policy::{NetworkMode, Policy};

/// Report items, in report order (`CapId::ALL`). The `as_str` names are the
/// JSON `id` values and the human column (pinned by `cap_ids_pinned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapId {
    Userns,
    Netns,
    NetnsIpv6,
    Nft,
    Fallback,
    Bwrap,
    BwrapRun,
    BwrapProc,
    Seccomp,
    Landlock,
}

impl CapId {
    /// Every item, in report order.
    pub const ALL: [CapId; 10] = [
        CapId::Userns,
        CapId::Netns,
        CapId::NetnsIpv6,
        CapId::Nft,
        CapId::Fallback,
        CapId::Bwrap,
        CapId::BwrapRun,
        CapId::BwrapProc,
        CapId::Seccomp,
        CapId::Landlock,
    ];

    /// The pinned item name.
    pub fn as_str(self) -> &'static str {
        match self {
            CapId::Userns => "userns",
            CapId::Netns => "netns",
            CapId::NetnsIpv6 => "netns-ipv6",
            CapId::Nft => "nft",
            CapId::Fallback => "fallback",
            CapId::Bwrap => "bwrap",
            CapId::BwrapRun => "bwrap-run",
            CapId::BwrapProc => "bwrap-proc",
            CapId::Seccomp => "seccomp",
            CapId::Landlock => "landlock",
        }
    }
}

impl Serialize for CapId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// An item's status. Human labels: `ok`, `FAIL`, `skip`, `warn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Fail,
    Skip,
    Warn,
}

impl Status {
    /// The human label of the status column.
    pub fn label(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Fail => "FAIL",
            Status::Skip => "skip",
            Status::Warn => "warn",
        }
    }
}

/// The strongest sandbox network enforcement the host provides. Ordered
/// `Unavailable < Explicit < Transparent`. There is no `None` level: the
/// explicit variant serves `none` policies too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectiveMode {
    Unavailable,
    Explicit,
    Transparent,
}

impl EffectiveMode {
    /// `"unavailable"`, `"explicit"` or `"transparent"`.
    pub fn as_str(self) -> &'static str {
        match self {
            EffectiveMode::Unavailable => "unavailable",
            EffectiveMode::Explicit => "explicit",
            EffectiveMode::Transparent => "transparent",
        }
    }

    /// Whether a policy requiring `required` can run on a host that provides
    /// `self`.
    pub fn provides(self, required: NetworkMode) -> bool {
        match self {
            EffectiveMode::Transparent => true,
            EffectiveMode::Explicit => {
                matches!(required, NetworkMode::Explicit | NetworkMode::None)
            }
            EffectiveMode::Unavailable => false,
        }
    }

    /// The policy `network.mode` spellings this host can run.
    pub fn runnable_modes(self) -> &'static [&'static str] {
        match self {
            EffectiveMode::Transparent => &["transparent", "explicit", "none"],
            EffectiveMode::Explicit => &["explicit", "none"],
            EffectiveMode::Unavailable => &[],
        }
    }
}

/// One report item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    pub id: CapId,
    pub status: Status,
    pub detail: String,
    /// The raw staged failure (`<stage>: <reason>`) or bwrap stderr line.
    pub evidence: Option<String>,
    pub errno: Option<i32>,
    /// The highest network mode this item allows; `None` = no limit.
    pub impact: Option<EffectiveMode>,
    /// The remedy; `Some` for every `Fail` and every `Warn` row.
    pub fix: Option<String>,
}

/// The whole host report (JSON version 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub version: u32,
    pub sbx_version: &'static str,
    pub kernel: String,
    pub network_mode: EffectiveMode,
    pub runnable_modes: Vec<&'static str>,
    pub probe_error: Option<String>,
    pub capabilities: Vec<Capability>,
    /// Only with `--policy P --host` and a valid policy.
    pub policy: Option<PolicyCheck>,
}

/// `--policy P --host`: the policy against this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyCheck {
    pub path: String,
    pub required: NetworkMode,
    pub runnable: bool,
    pub checks: Vec<PolicyItem>,
}

/// One policy check (`id` in the fixed order `network-mode`, `infra-etc`,
/// `policy-paths`, `deny-paths`, `mount-chains`, `bwrap-cve`, `deny-links`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyItem {
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

/// The JSON report version.
pub const REPORT_VERSION: u32 = 1;

/// A parsed probing `sbx check` invocation (cli.rs builds it).
pub struct CheckArgs {
    pub policy: Option<PathBuf>,
    pub host: bool,
    pub json: bool,
    pub test_break_rules: bool,
}

/// CLI seam for the probing forms of `sbx check` (bare, `--json`, and
/// `--policy P --host`). The validate-only and `--print-schema` forms stay in
/// `cli.rs`, probe-free.
///
/// Always prints the full report on stdout (an invalid policy included, rc 1)
/// and the reasons on stderr.
pub fn check(args: CheckArgs) -> ExitCode {
    let mut rc: u8 = 0;
    let mut policy: Option<(String, Policy)> = None;
    if let Some(path) = &args.policy {
        match Policy::from_file(path) {
            Ok(parsed) => policy = Some((path.to_string_lossy().into_owned(), parsed)),
            Err(err) => {
                eprintln!("sbx check: {err}");
                rc = 1;
            }
        }
    }

    let facts = facts::gather(&facts::GatherOptions {
        test_break_rules: args.test_break_rules,
    });
    let mut report = classify::assemble(&facts);
    if args.host {
        if let Some((path, parsed)) = &policy {
            let bwrap = match &facts.bwrap {
                BwrapStatus::Ok { version, .. } => Some(*version),
                _ => None,
            };
            let exists = |p: &Path| std::fs::metadata(p).is_ok();
            let is_non_dir = |p: &Path| std::fs::metadata(p).is_ok_and(|m| !m.is_dir());
            report.policy = Some(classify::policy_check_with(
                path,
                parsed,
                report.network_mode,
                &classify::Seams {
                    exists: &exists,
                    is_non_dir: &is_non_dir,
                    verify: &crate::bwrap::guard::verify,
                    alias: &|a: &crate::bwrap::AliasCheck| {
                        crate::bwrap::guard::verify_aliases(std::slice::from_ref(a))
                    },
                    bwrap,
                    hard_links: &crate::bwrap::guard::hard_links_under,
                },
            ));
        }
    }

    let text = if args.json {
        report::render_json(&report)
    } else {
        report::render_human(&report)
    };
    let mut out = std::io::stdout();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => {}
        // A closed stdout is not an sbx failure (house precedent, --print-schema).
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(err) => {
            eprintln!("sbx check: cannot write the report to stdout: {err}");
            rc = 1;
        }
    }
    for line in report::stderr_lines(&report) {
        eprintln!("{line}");
    }
    ExitCode::from(rc.max(report::exit_code(&report)))
}

/// Test fixtures shared by the classifier and report goldens (issue #11).
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;

    use crate::bwrap::version::BwrapStatus;
    use crate::init::probe::{PROBE_STEPS, PROBE_VERSION, ProbeReport, ProbeStep, StepStatus};

    use super::facts::{HostFacts, Landlock, ProbeOutcome, RunFacts, Sysctls};

    /// Every probe step ok (the H1 fixture).
    pub(crate) fn ok_steps() -> ProbeReport {
        ProbeReport {
            version: PROBE_VERSION,
            steps: PROBE_STEPS
                .iter()
                .map(|name| ProbeStep {
                    step: (*name).to_owned(),
                    status: StepStatus::Ok,
                    errno: None,
                    reason: None,
                })
                .collect(),
        }
    }

    /// A failed step with a reason; `rest` skipped with the given reason.
    pub(crate) fn failed_at(
        name: &str,
        errno: Option<i32>,
        reason: &str,
        skip_reason: &str,
    ) -> ProbeReport {
        let mut report = ok_steps();
        let mut seen_fail = false;
        for step in &mut report.steps {
            if step.step == name {
                step.status = StepStatus::Fail;
                step.errno = errno;
                step.reason = Some(reason.to_owned());
                seen_fail = true;
            } else if seen_fail {
                step.status = StepStatus::Skip;
                step.reason = Some(skip_reason.to_owned());
            }
        }
        report
    }

    /// Set one step's outcome, leaving every other step as it is.
    pub(crate) fn with_step(
        mut report: ProbeReport,
        name: &str,
        status: StepStatus,
        errno: Option<i32>,
        reason: Option<&str>,
    ) -> ProbeReport {
        for step in &mut report.steps {
            if step.step == name {
                step.status = status;
                step.errno = errno;
                step.reason = reason.map(str::to_owned);
            }
        }
        report
    }

    pub(crate) fn bwrap_ok() -> BwrapStatus {
        BwrapStatus::Ok {
            path: PathBuf::from("/usr/bin/bwrap"),
            version: (0, 9, 0),
        }
    }

    pub(crate) fn host(probe: ProbeOutcome, bwrap: BwrapStatus, run: RunFacts) -> HostFacts {
        HostFacts {
            kernel: "6.8.0-test".to_owned(),
            run,
            landlock: Landlock::Abi(4),
            bwrap,
            probe,
        }
    }

    pub(crate) fn ok_host() -> HostFacts {
        host(
            ProbeOutcome::Ran(ok_steps()),
            bwrap_ok(),
            RunFacts::default(),
        )
    }

    pub(crate) fn sysctls(apparmor: Option<i64>, clone: Option<i64>, max: Option<i64>) -> RunFacts {
        RunFacts {
            sysctl: Sysctls {
                apparmor_restrict_userns: apparmor,
                unprivileged_userns_clone: clone,
                max_user_namespaces: max,
                max_net_namespaces: None,
            },
            seccomp: None,
        }
    }
}
