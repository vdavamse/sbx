//! `sbx __init --probe` — the host capability probe behind `sbx check`
//! (issue #11, T3/T4).
//!
//! The probe is the SAME stage functions `__init` runs for a real sandbox
//! (unshare → idmap → netns → ipv6 → listeners → nft-load → nft-verify →
//! fallback), executed in this throwaway process's fresh namespaces, plus
//! three nested bwrap launches (issue #34 adds the seccomp one) built from the same flag constants as
//! `bwrap::build` (Phase 1: the probe must be sbx's own nested path, not a
//! `bwrap --version` guess). Every step is recorded as data: the probe never
//! prints failures to stderr, and it exits 0 whenever it ran — the parent
//! classifies the step outcomes ([`crate::host::classify`]).
//!
//! Step cascade (design §3.3): a failed unshare or idmap skips every later
//! step; a failed netns skips the nft/fallback/ipv6/listener steps but the
//! bwrap steps still run; ipv6 and listeners are diagnostic and never cascade.
//!
//! Output: exactly one JSON line on stdout (`ProbeReport`, `version` 1).

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use netlink_socket2::NetlinkSocket;
use serde::{Deserialize, Serialize};

use super::fdpass::truncate_reason;
use super::{InitError, netns, rules};

/// The probe protocol version (`ProbeReport::version`). Bumped to 2 for issue
/// #34's `bwrap-seccomp` step: the parent (`host::facts`) accepts exactly the
/// version it was built with, so a stale probe is refused, not misread.
pub const PROBE_VERSION: u32 = 2;

/// The step names, in report order (pinned by `probe_steps_pinned`).
pub const PROBE_STEPS: [&str; 11] = [
    "unshare",
    "idmap",
    "netns",
    "ipv6",
    "listeners",
    "nft-load",
    "nft-verify",
    "fallback",
    "bwrap-run",
    "bwrap-proc",
    "bwrap-seccomp",
];

/// Bound on each nested bwrap launch (the parent's whole probe is bounded
/// separately; see `host::facts::PROBE_TIMEOUT`).
pub const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The probe's JSON output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub version: u32,
    pub steps: Vec<ProbeStep>,
}

/// One probe step outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeStep {
    pub step: String,
    pub status: StepStatus,
    pub errno: Option<i32>,
    pub reason: Option<String>,
}

/// Step status on the probe wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Ok,
    Fail,
    Skip,
}

/// How a nested bwrap child ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BwrapExit {
    Code(i32),
    Signal(i32),
    TimedOut,
    SpawnFailed(String),
}

/// CLI seam for `sbx __init --probe` (dispatched by `crate::cli`). Same
/// prologue as [`super::run_init`]: signal mask reset, silenced panic hook
/// with `catch_unwind`, parent-death signal armed. Rc 0 with one JSON line
/// whenever the probe ran (whatever the step outcomes); rc 1 with
/// `sbx __init: internal error: …` on a caught panic or a failed prologue.
pub fn run_probe(bwrap: Option<PathBuf>, test_break_rules: bool) -> ExitCode {
    super::reset_signal_mask();
    if let Err(err) = super::arm_parent_death(None) {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        probe_pipeline(bwrap.as_deref(), test_break_rules)
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(line) => {
                println!("{line}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("sbx __init: internal error: probe report: {err}");
                ExitCode::FAILURE
            }
        },
        Err(payload) => {
            eprintln!(
                "sbx __init: internal error: {}",
                super::panic_message(&payload)
            );
            ExitCode::FAILURE
        }
    }
}

/// Accumulates the steps in order.
#[derive(Default)]
struct Steps(Vec<ProbeStep>);

impl Steps {
    fn push(&mut self, name: &str, status: StepStatus, errno: Option<i32>, reason: Option<String>) {
        self.0.push(ProbeStep {
            step: name.to_owned(),
            status,
            errno,
            reason,
        });
    }

    fn ok(&mut self, name: &str) {
        self.push(name, StepStatus::Ok, None, None);
    }

    fn fail(&mut self, name: &str, err: &InitError) {
        self.push(
            name,
            StepStatus::Fail,
            err.errno(),
            Some(truncate_reason(err.reason()).to_owned()),
        );
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.push(name, StepStatus::Skip, None, Some(reason.to_owned()));
    }

    /// Skip every step not recorded yet (the cascade's tail).
    fn skip_rest(&mut self, reason: &str) {
        for name in PROBE_STEPS.iter().skip(self.0.len()) {
            self.skip(name, reason);
        }
    }

    fn finish(self) -> ProbeReport {
        debug_assert_eq!(self.0.len(), PROBE_STEPS.len());
        ProbeReport {
            version: PROBE_VERSION,
            steps: self.0,
        }
    }
}

/// The probe pipeline. Pure sequencing over the real stage functions; the
/// only externally visible effects are the namespaces and the nft ruleset of
/// THIS process (which exits right after).
pub(crate) fn probe_pipeline(bwrap: Option<&Path>, test_break_rules: bool) -> ProbeReport {
    let mut steps = Steps::default();

    let ids = match netns::unshare_namespaces() {
        Ok(ids) => {
            steps.ok("unshare");
            ids
        }
        Err(err) => {
            steps.fail("unshare", &err);
            steps.skip_rest("skipped: unshare failed");
            return steps.finish();
        }
    };
    if let Err(err) = netns::write_id_maps(ids) {
        steps.fail("idmap", &err);
        steps.skip_rest("skipped: idmap failed");
        return steps.finish();
    }
    steps.ok("idmap");

    match netns::configure_netns() {
        Ok(()) => {
            steps.ok("netns");
            match netns::disable_ipv6() {
                Ok(()) => steps.ok("ipv6"),
                Err(err) => steps.fail("ipv6", &err),
            }
            match super::listeners::bind_all() {
                Ok(listeners) => {
                    drop(listeners);
                    steps.ok("listeners");
                }
                Err(err) => steps.fail("listeners", &err),
            }
            let mut sock = NetlinkSocket::new();
            match rules::load(&mut sock, test_break_rules) {
                Ok(_) => {
                    steps.ok("nft-load");
                    match rules::verify_dump(&mut sock) {
                        Ok(()) => steps.ok("nft-verify"),
                        Err(err) => steps.fail("nft-verify", &err),
                    }
                }
                Err(err) => {
                    steps.fail("nft-load", &err);
                    steps.skip("nft-verify", "skipped: nft-load failed");
                }
            }
            match netns::remove_default_route() {
                Ok(()) => steps.ok("fallback"),
                Err(err) => steps.fail("fallback", &err),
            }
        }
        Err(err) => {
            steps.fail("netns", &err);
            steps.skip("ipv6", "skipped: netns failed");
            steps.skip("listeners", "skipped: netns failed");
            steps.skip("nft-load", "skipped: netns failed");
            steps.skip("nft-verify", "skipped: netns failed");
            steps.skip("fallback", "skipped: netns failed");
        }
    }

    bwrap_steps(&mut steps, bwrap);
    steps.finish()
}

/// The two nested bwrap launches (control without `--proc`, then `--proc`),
/// run from inside the probe's namespaces exactly as production runs them.
fn bwrap_steps(steps: &mut Steps, bwrap: Option<&Path>) {
    let Some(bwrap) = bwrap else {
        steps.skip("bwrap-run", "skipped: no usable bwrap");
        steps.skip("bwrap-proc", "skipped: no usable bwrap");
        steps.skip("bwrap-seccomp", "skipped: no usable bwrap");
        return;
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            steps.push(
                "bwrap-run",
                StepStatus::Fail,
                None,
                Some(format!("cannot locate the sbx binary: {err}")),
            );
            steps.skip("bwrap-proc", "skipped: bwrap-run failed");
            steps.skip("bwrap-seccomp", "skipped: bwrap-run failed");
            return;
        }
    };
    let (exit, stderr) = run_bwrap_child(bwrap, &exe, false, None);
    let run = bwrap_step("bwrap-run", exit, &stderr);
    let run_ok = run.status == StepStatus::Ok;
    steps.0.push(run);
    if !run_ok {
        steps.skip("bwrap-proc", "skipped: bwrap-run failed");
        steps.skip("bwrap-seccomp", "skipped: bwrap-run failed");
        return;
    }
    let (exit, stderr) = run_bwrap_child(bwrap, &exe, true, None);
    steps.0.push(bwrap_step("bwrap-proc", exit, &stderr));
    steps.0.push(seccomp_step(bwrap, &exe));
}

/// Issue #34: the `bwrap-seccomp` step — a nested launch with `--seccomp N`
/// (the sealed program memfd `run` uses), proving bwrap installs sbx's
/// socket-family filter in this host's namespaces and outer policy. The
/// memfd is created here (the same constructor `run` uses) and made
/// inheritable for the one child only; the parent closes it right after the
/// spawn. A failure to create it is a FAIL with its reason (e.g. an arch
/// without a program), not a skip.
fn seccomp_step(bwrap: &Path, exe: &Path) -> ProbeStep {
    let memfd = match crate::bwrap::seccomp::program_memfd() {
        Ok(fd) => fd,
        Err(err) => {
            return ProbeStep {
                step: "bwrap-seccomp".to_owned(),
                status: StepStatus::Fail,
                errno: err.raw_os_error(),
                reason: Some(
                    truncate_reason(&format!("cannot prepare the seccomp filter: {err}"))
                        .to_owned(),
                ),
            };
        }
    };
    let (exit, stderr) = run_bwrap_child(bwrap, exe, false, Some(memfd.as_raw_fd()));
    drop(memfd);
    bwrap_step("bwrap-seccomp", exit, &stderr)
}

/// Pure: a bwrap child outcome → a probe step. `ok` iff it exited 0. Any
/// other outcome is `fail` with errno None; the reason is the first
/// non-empty stderr line (bounded), else the exit description.
pub(crate) fn bwrap_step(name: &'static str, exit: BwrapExit, stderr: &[u8]) -> ProbeStep {
    let first_line = || {
        String::from_utf8_lossy(stderr)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(|line| truncate_reason(line).to_owned())
    };
    let (status, reason) = match exit {
        BwrapExit::Code(0) => (StepStatus::Ok, None),
        BwrapExit::Code(code) => (
            StepStatus::Fail,
            Some(first_line().unwrap_or_else(|| format!("exited with status {code}"))),
        ),
        BwrapExit::Signal(sig) => (
            StepStatus::Fail,
            Some(first_line().unwrap_or_else(|| format!("killed by signal {sig}"))),
        ),
        BwrapExit::TimedOut => (
            StepStatus::Fail,
            Some(format!(
                "timed out after {}s",
                BWRAP_PROBE_TIMEOUT.as_secs()
            )),
        ),
        BwrapExit::SpawnFailed(error) => (
            StepStatus::Fail,
            Some(truncate_reason(&format!("cannot start bwrap: {error}")).to_owned()),
        ),
    };
    ProbeStep {
        step: name.to_owned(),
        status,
        errno: None,
        reason,
    }
}

/// Spawn one nested bwrap launch of the probe payload (this binary,
/// `--version`) and wait for it, bounded. `seccomp_fd` (issue #34) is the
/// program memfd the child inherits: its CLOEXEC is cleared here, so it
/// survives into bwrap only. Returns the outcome and the child's stderr
/// (empty when it did not exit on its own).
fn run_bwrap_child(
    bwrap: &Path,
    exe: &Path,
    with_proc: bool,
    seccomp_fd: Option<RawFd>,
) -> (BwrapExit, Vec<u8>) {
    let argv: Vec<OsString> = crate::bwrap::probe_argv(bwrap, exe, with_proc, seccomp_fd);
    if let Some(fd) = seccomp_fd {
        // SAFETY: F_SETFD on the memfd the caller owns; it is closed by the
        // caller after this spawn returns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return (
                BwrapExit::SpawnFailed(std::io::Error::last_os_error().to_string()),
                Vec::new(),
            );
        }
    }
    let spawned = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => return (BwrapExit::SpawnFailed(err.to_string()), Vec::new()),
    };
    wait_bounded(&mut child, BWRAP_PROBE_TIMEOUT)
}

/// Poll `try_wait` every 1 ms up to `timeout`; on expiry kill and reap.
fn wait_bounded(child: &mut Child, timeout: Duration) -> (BwrapExit, Vec<u8>) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_end(&mut stderr);
                }
                return (exit_of(status), stderr);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (BwrapExit::TimedOut, Vec::new());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return (BwrapExit::SpawnFailed(err.to_string()), Vec::new());
            }
        }
    }
}

fn exit_of(status: ExitStatus) -> BwrapExit {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => BwrapExit::Code(code),
        None => BwrapExit::Signal(status.signal().unwrap_or(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::consts::MAX_REASON_BYTES;

    #[test]
    fn probe_steps_pinned() {
        assert_eq!(
            PROBE_STEPS,
            [
                "unshare",
                "idmap",
                "netns",
                "ipv6",
                "listeners",
                "nft-load",
                "nft-verify",
                "fallback",
                "bwrap-run",
                "bwrap-proc",
                "bwrap-seccomp"
            ]
        );
        assert_eq!(PROBE_VERSION, 2);
        assert_eq!(BWRAP_PROBE_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn bwrap_step_table() {
        let ok = bwrap_step("bwrap-run", BwrapExit::Code(0), b"");
        assert_eq!(ok.status, StepStatus::Ok);
        assert_eq!(ok.reason, None);

        let fail = bwrap_step(
            "bwrap-proc",
            BwrapExit::Code(1),
            b"\n  bwrap: Can't mount proc\nmore\n",
        );
        assert_eq!(fail.status, StepStatus::Fail);
        assert_eq!(fail.reason.as_deref(), Some("bwrap: Can't mount proc"));

        let silent = bwrap_step("bwrap-run", BwrapExit::Code(1), b"");
        assert_eq!(silent.reason.as_deref(), Some("exited with status 1"));

        let sig = bwrap_step("bwrap-run", BwrapExit::Signal(9), b"");
        assert_eq!(sig.reason.as_deref(), Some("killed by signal 9"));

        let timeout = bwrap_step("bwrap-run", BwrapExit::TimedOut, b"ignored");
        assert_eq!(timeout.reason.as_deref(), Some("timed out after 5s"));

        let spawn = bwrap_step("bwrap-run", BwrapExit::SpawnFailed("ENOENT".into()), b"");
        assert_eq!(spawn.reason.as_deref(), Some("cannot start bwrap: ENOENT"));
        assert_eq!(spawn.errno, None);
    }

    #[test]
    fn bwrap_step_bounds_long_lines() {
        let long = "x".repeat(500);
        let step = bwrap_step("bwrap-run", BwrapExit::Code(1), long.as_bytes());
        let reason = step.reason.expect("a reason");
        assert_eq!(reason.len(), 500);
        assert!(reason.len() <= MAX_REASON_BYTES);
        let huge = "y".repeat(2000);
        let step = bwrap_step("bwrap-run", BwrapExit::Code(1), huge.as_bytes());
        assert!(step.reason.expect("a reason").len() <= MAX_REASON_BYTES);
    }

    #[test]
    fn probe_report_json_golden() {
        let report = ProbeReport {
            version: PROBE_VERSION,
            steps: vec![
                ProbeStep {
                    step: "unshare".into(),
                    status: StepStatus::Ok,
                    errno: None,
                    reason: None,
                },
                ProbeStep {
                    step: "bwrap-proc".into(),
                    status: StepStatus::Skip,
                    errno: None,
                    reason: Some("skipped: no usable bwrap".into()),
                },
            ],
        };
        assert_eq!(
            serde_json::to_string(&report).expect("serialises"),
            r#"{"version":2,"steps":[{"step":"unshare","status":"ok","errno":null,"reason":null},{"step":"bwrap-proc","status":"skip","errno":null,"reason":"skipped: no usable bwrap"}]}"#
        );
        let back: ProbeReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn steps_cascade_skip_rest() {
        let mut steps = Steps::default();
        steps.ok("unshare");
        steps.skip_rest("skipped: unshare failed");
        let report = steps.finish();
        assert_eq!(report.steps.len(), PROBE_STEPS.len());
        assert_eq!(report.steps[1].status, StepStatus::Skip);
        assert_eq!(report.steps[9].step, "bwrap-proc");
        assert_eq!(report.steps[10].step, "bwrap-seccomp");
    }
}
