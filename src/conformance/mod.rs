//! `sbx check --conformance` — every security guarantee as an executable
//! check (issue #13).
//!
//! 1. Contract: `check --conformance [--network] [--only ID|GROUP,...] [--list]
//!    [--json]` prints 69 checks in catalog order; rc 0 only when nothing failed
//!    and nothing needed by a selected check was missing (see [`report`]).
//! 2. Tiers: host scenarios (`sbx run` with a built-in policy and a probe
//!    payload), the init tier (F03, the production `sbx __init`), the lab tier
//!    (PR2; its checks report not-implemented here) and the network tier
//!    (opt-in, PR2).
//! 3. Scenarios: one `sbx run` feeds several checks; evaluators are pure
//!    functions over the recorded evidence. Scenarios run lazily, so `--only`
//!    runs only what is needed.
//! 4. Non-vacuity: every negative assertion has a recorded control; a control
//!    failure is a FAIL (`control failed: ...`), never a vacuous pass.
//! 5. Gating: the host facts come from `host::facts::gather` and
//!    `host::classify::assemble`; a check whose needs the host lacks is a
//!    capability skip (rc 1); opt-in skips (no `--network`) are rc 0.
//! 6. Budget: 120 s for the offline tiers; a scenario not started by then is a
//!    capability skip.
//! 7. Hermeticity: no root and no upstream dial. Files live under
//!    `$TMPDIR/sbx-conformance-*`, except the D04 control socket
//!    `/tmp/sbxc-<8 hex>.s` (sun_path length) and, when `$TMPDIR` is under
//!    `$HOME`, the base under `/tmp`. Artifacts are kept on FAIL.
//!
//! Interruption: a normal exit removes the temp base. SIGINT, SIGTERM or
//!    SIGKILL to the suite itself is not trapped: the base (with its copy of
//!    the binary) stays under `$TMPDIR/sbx-conformance-*` until removed by hand
//!    or by an `rm -rf` of that prefix; each scenario's `sbx run` is in its own
//!    process group and is killed by the runner's `Drop` guards on unwinding.
//!
//! 8. No hooks: `run` and `__init` behave exactly as without `--conformance`.
//!
//! Known gaps (documented, not hidden): the `/etc/hosts` and socket-file
//! findings are tracked in #35 (D05 warns, C06 notes); operator policies are
//! out of v1 (built-in policies only).

pub mod catalog;
pub mod host_tier;
pub mod init_tier;
pub mod policies;
pub mod probe;
pub mod report;
pub mod scenarios;
pub mod spawn;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use catalog::{CATALOG, Need, Tier};
use report::{CheckResult, LabStatus, Report, SkipKind};
use scenarios::{Env, Scn};

use crate::host::{EffectiveMode, classify, facts};

/// The offline-tier budget (§12).
pub const OFFLINE_BUDGET: Duration = Duration::from_secs(120);

/// Parsed `check --conformance` arguments.
pub struct ConformanceArgs {
    pub network: bool,
    pub only: Vec<String>,
    pub list: bool,
    pub json: bool,
}

/// `sbx check --conformance`: run (or list) the suite and print the report.
pub fn check(args: ConformanceArgs) -> ExitCode {
    if args.list {
        let text = if args.json {
            report::render_list_json()
        } else {
            report::render_list()
        };
        return write_stdout(&text).unwrap_or(ExitCode::from(1));
    }
    let selected: Option<std::collections::BTreeSet<&'static str>> = if args.only.is_empty() {
        None
    } else {
        match catalog::select(&args.only) {
            Ok(set) => Some(set),
            Err(bad) => {
                eprintln!("sbx check: unknown conformance check or group `{bad}`");
                return ExitCode::from(2);
            }
        }
    };
    let started = Instant::now();
    let facts = facts::gather(&facts::GatherOptions {
        test_break_rules: false,
    });
    let host = classify::assemble(&facts);
    let mode = host.network_mode;
    let kernel = host.kernel.clone();
    let (base, nonce) = match make_base() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sbx check: conformance cannot create its temp base: {e}");
            return ExitCode::from(1);
        }
    };
    // The probe runs from a private copy in the base directory, never from
    // the caller's location: a binary under $HOME would make the sandbox's
    // bind parents visible and H06 would then fail for a reason unrelated to
    // sbx (CI runs from $HOME/work). The copy is removed with the base.
    let exe_copy = base.join("sbx");
    if let Err(e) = std::fs::copy("/proc/self/exe", &exe_copy) {
        eprintln!("sbx check: conformance cannot copy the sbx binary: {e}");
        let _ = std::fs::remove_dir_all(&base);
        return ExitCode::from(1);
    }
    let exe_text = match exe_copy.to_str() {
        Some(t) => t.to_owned(),
        None => {
            eprintln!("sbx check: conformance: the temp base path is not UTF-8");
            let _ = std::fs::remove_dir_all(&base);
            return ExitCode::from(1);
        }
    };
    let env = Env {
        exe: PathBuf::from(&exe_text),
        exe_text: exe_text.clone(),
        base: base.clone(),
        secret: format!("sec-{nonce}"),
        passed: format!("pas-{nonce}"),
        nonce: nonce.clone(),
    };
    let deadline = started + OFFLINE_BUDGET;
    let mut memo: BTreeMap<&'static str, Scn> = BTreeMap::new();
    let mut results: Vec<CheckResult> = Vec::new();
    for d in CATALOG.iter() {
        let selected_here = selected.as_ref().is_none_or(|s| s.contains(d.id));
        if !selected_here {
            results.push(CheckResult::skip(
                d.id,
                SkipKind::NotSelected,
                report::NOT_SELECTED,
            ));
            continue;
        }
        let r = run_one(d, mode, args.network, &env, &mut memo, deadline);
        results.push(r);
    }
    let report = Report {
        sbx_version: env!("CARGO_PKG_VERSION"),
        kernel,
        network_mode: mode,
        lab: LabStatus {
            status: "not-run",
            detail: Some("the lab tier lands in the second #13 PR".to_owned()),
        },
        network_requested: args.network,
        only: if args.only.is_empty() {
            None
        } else {
            Some(args.only.clone())
        },
        results,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    let text = if args.json {
        report::render_json(&report)
    } else {
        report::render_human(&report)
    };
    let rc = match write_stdout(&text) {
        Some(_) => report::exit_code(&report),
        None => 1,
    };
    for line in report::stderr_lines(&report) {
        eprintln!("{line}");
    }
    let failed = report.summary().fail > 0;
    if failed {
        eprintln!(
            "sbx check: conformance artifacts kept in {}",
            base.display()
        );
    } else {
        let _ = std::fs::remove_dir_all(&base);
    }
    ExitCode::from(rc)
}

fn write_stdout(text: &str) -> Option<ExitCode> {
    let mut out = std::io::stdout();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => Some(ExitCode::SUCCESS),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Some(ExitCode::SUCCESS),
        Err(e) => {
            eprintln!("sbx check: cannot write the report to stdout: {e}");
            None
        }
    }
}

/// Create `$TMPDIR/sbx-conformance-<pid>-<nonce8>` (mode 0700) and a 16-byte nonce.
fn make_base() -> std::io::Result<(PathBuf, String)> {
    let mut raw = [0u8; 16];
    // SAFETY: getrandom into a 16-byte buffer we own.
    let n = unsafe { libc::getrandom(raw.as_mut_ptr().cast(), raw.len(), 0) };
    if n != raw.len() as isize {
        return Err(std::io::Error::last_os_error());
    }
    let nonce: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    // $TMPDIR may sit under $HOME; the base must not (see the copy in `check`).
    let mut root = std::env::temp_dir();
    if let Some(home) = std::env::var_os("HOME") {
        if root.starts_with(&home) {
            root = PathBuf::from("/tmp");
        }
    }
    let base = root.join(format!(
        "sbx-conformance-{}-{}",
        std::process::id(),
        &nonce[..8]
    ));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&base)?;
    Ok((base, nonce))
}

/// The capability text for a check the host cannot run (§8.4 gating table).
fn host_cannot(mode: EffectiveMode, d: &catalog::CheckDef) -> Option<String> {
    if mode == EffectiveMode::Unavailable && d.tier != Tier::Network {
        let _ = d.id;
        return Some("the host cannot run sandboxes (run `sbx check`)".to_owned());
    }
    if d.needs.contains(&Need::Transparent) && mode == EffectiveMode::Explicit {
        return Some(
            "needs network mode transparent; this host provides explicit (run `sbx check`)"
                .to_owned(),
        );
    }
    None
}

fn run_one(
    d: &catalog::CheckDef,
    mode: EffectiveMode,
    network: bool,
    env: &Env,
    memo: &mut BTreeMap<&'static str, Scn>,
    deadline: Instant,
) -> CheckResult {
    match d.tier {
        Tier::Network => {
            if !network {
                return CheckResult::skip(
                    d.id,
                    SkipKind::OptIn,
                    "network tier not requested (add --network)",
                );
            }
            CheckResult::skip(
                d.id,
                SkipKind::NotImplemented,
                "the network tier lands in the second #13 PR",
            )
        }
        Tier::Lab => {
            if let Some(why) = host_cannot(mode, d) {
                return CheckResult::skip(d.id, SkipKind::Capability, why);
            }
            CheckResult::skip(
                d.id,
                SkipKind::NotImplemented,
                "the lab tier lands in the second #13 PR",
            )
        }
        Tier::Init => {
            if let Some(why) = host_cannot(mode, d) {
                return CheckResult::skip(d.id, SkipKind::Capability, why);
            }
            if Instant::now() > deadline {
                return CheckResult::skip(
                    d.id,
                    SkipKind::Capability,
                    "suite budget (120 s) exhausted",
                );
            }
            let exe = env.exe.clone();
            let mut r = init_tier::f03(&exe, &env.exe_text);
            r.scenario = Some("init".to_owned());
            r
        }
        Tier::Host => {
            if let Some(why) = host_cannot(mode, d) {
                return CheckResult::skip(d.id, SkipKind::Capability, why);
            }
            let names = host_tier::scenarios_of(d.id);
            if names.is_empty() {
                return CheckResult::skip(d.id, SkipKind::NotImplemented, "no scenario plan");
            }
            for name in names {
                if !memo.contains_key(name) {
                    let group = scenarios::group_of(name);
                    if Instant::now() > deadline {
                        memo.insert(
                            name,
                            Scn::unavailable(name, "suite budget (120 s) exhausted".to_owned()),
                        );
                        continue;
                    }
                    for s in scenarios::run_group(env, group) {
                        memo.insert(s.name, s);
                    }
                    if !memo.contains_key(name) {
                        memo.insert(
                            name,
                            Scn::unavailable(
                                name,
                                format!("scenario group {group} produced no {name}"),
                            ),
                        );
                    }
                }
            }
            if let Some(why) = names
                .iter()
                .find_map(|n| memo.get(n).and_then(|s| s.skip.clone()))
            {
                return CheckResult::skip(d.id, SkipKind::Capability, why);
            }
            let scenes: BTreeMap<&'static str, Scn> = names
                .iter()
                .filter_map(|n| memo.get(n).map(|s| (*n, s.clone())))
                .collect();
            let mut r = host_tier::evaluate(d.id, &scenes);
            r.scenario = Some(names.join(","));
            r.scenario_ms = Some(
                names
                    .iter()
                    .filter_map(|n| memo.get(n).map(|s| s.ms))
                    .max()
                    .unwrap_or(0),
            );
            if d.id == "C06" && hosts_has_foreign_entries() {
                r.evidence
                    .push("note: /etc/hosts has non-loopback entries; see #35".to_owned());
            }
            r
        }
    }
}

/// Whether `/etc/hosts` pins a non-loopback address (Q7 note for C06).
fn hosts_has_foreign_entries() -> bool {
    std::fs::read_to_string("/etc/hosts").is_ok_and(|text| {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .any(|l| {
                let mut parts = l.split_whitespace();
                let ip = parts.next().unwrap_or("");
                !(ip.starts_with("127.") || ip == "::1") && parts.next().is_some()
            })
    })
}
