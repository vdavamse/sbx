//! Impure host facts for `sbx check` (issue #11, T4) and the run-side reads
//! of the refusal path. Everything here is a read or a bounded child process;
//! the interpretation lives in the pure [`super::classify`].
//!
//! Cost (E10): `check` = one `bwrap --version`, one `__init --probe` (the
//! namespace stages plus two nested bwrap launches). `run` adds nothing on a
//! healthy host: [`RunFacts::read`] runs only on a staged failure.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::bwrap::version::{BwrapStatus, classify_version_output, find_bwrap};
use crate::init::probe::{PROBE_STEPS, ProbeReport};

/// The `--version` bound (`bwrap --version` is instant; this only bounds a
/// wedged binary).
pub const BWRAP_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The probe bound: above two nested bwrap launches (5 s each) plus setup.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// `landlock_create_ruleset` flag that returns the ABI version (`<linux/landlock.h>`;
/// not exported by the libc crate, E7).
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_long = 1;

const SYSCTL_APPARMOR_USERNS: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
const SYSCTL_USERNS_CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";
const SYSCTL_MAX_USERNS: &str = "/proc/sys/user/max_user_namespaces";
const SYSCTL_MAX_NETNS: &str = "/proc/sys/user/max_net_namespaces";

/// The three sysctls the classifier reads. `None` = absent, unreadable or
/// unparseable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sysctls {
    pub apparmor_restrict_userns: Option<i64>,
    pub unprivileged_userns_clone: Option<i64>,
    pub max_user_namespaces: Option<i64>,
    /// `user.max_net_namespaces`: a zero here makes unshare(CLONE_NEWNET) fail
    /// with ENOSPC even when user namespaces are allowed (review #1).
    pub max_net_namespaces: Option<i64>,
}

impl Sysctls {
    /// Read the sysctls the classifier uses.
    pub fn read() -> Self {
        let get = |path: &str| fs::read_to_string(path).ok().and_then(|t| parse_sysctl(&t));
        Self {
            apparmor_restrict_userns: get(SYSCTL_APPARMOR_USERNS),
            unprivileged_userns_clone: get(SYSCTL_USERNS_CLONE),
            max_user_namespaces: get(SYSCTL_MAX_USERNS),
            max_net_namespaces: get(SYSCTL_MAX_NETNS),
        }
    }
}

/// Pure: a sysctl's text (trimmed) as an integer; anything else is `None`.
pub(crate) fn parse_sysctl(text: &str) -> Option<i64> {
    text.trim().parse().ok()
}

/// Pure: the `Seccomp:` mode from a `/proc/self/status` text (0 disabled,
/// 1 strict, 2 filter).
pub(crate) fn parse_seccomp(status: &str) -> Option<u8> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp:"))
        .and_then(|value| value.trim().parse().ok())
}

/// What `run`'s refusal needs: read ONLY on a staged failure (reads, no spawn).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunFacts {
    pub sysctl: Sysctls,
    pub seccomp: Option<u8>,
}

impl RunFacts {
    /// Read the sysctls and this process's seccomp mode.
    pub fn read() -> Self {
        Self {
            sysctl: Sysctls::read(),
            seccomp: fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| parse_seccomp(&s)),
        }
    }
}

/// The Landlock probe outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landlock {
    /// The ABI version the kernel reports.
    Abi(u32),
    /// The errno of the failed probe (ENOSYS = not built, EOPNOTSUPP = built
    /// but disabled at boot).
    Errno(i32),
}

/// Probe Landlock: `landlock_create_ruleset(NULL, 0, VERSION)` returns the ABI
/// version (report-only, #19 consumes it later).
pub fn landlock() -> Landlock {
    // SAFETY: a plain syscall with a NULL attr pointer and size 0, which the
    // flag makes the documented version query; no memory is written.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0 as libc::c_long,
            0 as libc::c_long,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    landlock_from_return(rc, errno)
}

/// Pure: the raw syscall return (and errno, read right after it) → [`Landlock`].
pub(crate) fn landlock_from_return(rc: libc::c_long, errno: i32) -> Landlock {
    if rc >= 0 {
        Landlock::Abi(rc as u32)
    } else {
        Landlock::Errno(errno)
    }
}

/// The probe's outcome: the parsed report, or why it could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ran(ProbeReport),
    Failed(String),
}

/// Everything `check` gathers, before classification.
pub struct HostFacts {
    pub kernel: String,
    pub run: RunFacts,
    pub landlock: Landlock,
    pub bwrap: BwrapStatus,
    pub probe: ProbeOutcome,
}

/// Gathering options (CLI hidden flag, Q6 precedent).
pub struct GatherOptions {
    pub test_break_rules: bool,
}

/// Gather every input of the report, in order: uname, run facts, Landlock,
/// bwrap discovery and gate, then the probe with the usable bwrap (if any).
pub fn gather(opts: &GatherOptions) -> HostFacts {
    let kernel = uname_release();
    let run = RunFacts::read();
    let landlock = landlock();
    let bwrap = match find_bwrap() {
        Some(path) => bwrap_status(&path),
        None => BwrapStatus::NotFound,
    };
    let probe = run_probe(bwrap.usable_path(), opts.test_break_rules);
    HostFacts {
        kernel,
        run,
        landlock,
        bwrap,
        probe,
    }
}

fn uname_release() -> String {
    // SAFETY: `utsname` is plain data; uname fills it or fails (then empty).
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return String::from("unknown");
    }
    // SAFETY: uname NUL-terminates `release` on success.
    unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// `bwrap --version` with a bounded wait; the result is classified purely.
pub(crate) fn bwrap_status(path: &Path) -> BwrapStatus {
    let mut child = match Command::new(path)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return BwrapStatus::SpawnFailed {
                path: path.to_path_buf(),
                error: err.to_string(),
            };
        }
    };
    let deadline = Instant::now() + BWRAP_VERSION_TIMEOUT;
    let status = match wait_bounded(&mut child, deadline) {
        Some(status) => status,
        None => {
            return BwrapStatus::SpawnFailed {
                path: path.to_path_buf(),
                error: format!("timed out after {}s", BWRAP_VERSION_TIMEOUT.as_secs()),
            };
        }
    };
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    classify_version_output(path, status.success(), status.code(), &stdout)
}

/// Poll `try_wait` until `deadline`; on expiry kill and reap, returning `None`.
fn wait_bounded(child: &mut std::process::Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Run `sbx __init --probe` (same binary, `env_clear`, bounded) and parse its
/// one JSON line.
pub(crate) fn run_probe(bwrap: Option<&Path>, test_break_rules: bool) -> ProbeOutcome {
    // m6: the same binary through the procfs link (the `run` invariant: the
    // exec target is this process's own image even if the file was replaced).
    let exe = PathBuf::from("/proc/self/exe");
    let mut args: Vec<std::ffi::OsString> = vec!["__init".into(), "--probe".into()];
    if let Some(path) = bwrap {
        args.push("--bwrap".into());
        args.push(path.as_os_str().to_os_string());
    }
    if test_break_rules {
        args.push("--test-break-rules".into());
    }
    let mut child = match Command::new(&exe)
        .args(&args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return ProbeOutcome::Failed(format!("cannot spawn the probe: {err}")),
    };
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let Some(status) = wait_bounded(&mut child, deadline) else {
        return ProbeOutcome::Failed(format!("timed out after {}s", PROBE_TIMEOUT.as_secs()));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    parse_probe_output(status.code(), &stdout, &stderr)
}

/// Pure: the probe's exit code, stdout and stderr → the outcome. Non-zero exit
/// → the first non-empty stderr line; a malformed or mis-versioned report, or
/// one whose steps are not exactly [`PROBE_STEPS`] in order, is a failure.
pub(crate) fn parse_probe_output(exit: Option<i32>, stdout: &str, stderr: &str) -> ProbeOutcome {
    if exit != Some(0) {
        let first = stderr.lines().map(str::trim).find(|l| !l.is_empty());
        return ProbeOutcome::Failed(match (first, exit) {
            (Some(line), _) => line.to_owned(),
            (None, Some(code)) => format!("exited with status {code}"),
            (None, None) => "killed by a signal".to_owned(),
        });
    }
    let report: ProbeReport = match serde_json::from_str(stdout.trim()) {
        Ok(report) => report,
        Err(_) => return ProbeOutcome::Failed("unparseable probe output".to_owned()),
    };
    if report.version != 1 {
        return ProbeOutcome::Failed(format!(
            "probe protocol version {}, expected 1",
            report.version
        ));
    }
    let names_match = report.steps.len() == PROBE_STEPS.len()
        && report
            .steps
            .iter()
            .zip(PROBE_STEPS)
            .all(|(step, name)| step.step == name);
    if !names_match {
        return ProbeOutcome::Failed("unexpected probe steps".to_owned());
    }
    ProbeOutcome::Ran(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sysctl_table() {
        assert_eq!(parse_sysctl("1\n"), Some(1));
        assert_eq!(parse_sysctl("  0 "), Some(0));
        assert_eq!(parse_sysctl("2147483647\n"), Some(2147483647));
        assert_eq!(parse_sysctl(""), None);
        assert_eq!(parse_sysctl("junk"), None);
    }

    #[test]
    fn parse_seccomp_table() {
        let status = "Name:\tsbx\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert_eq!(parse_seccomp(status), Some(2));
        assert_eq!(parse_seccomp("Name:\tsbx\n"), None);
        assert_eq!(parse_seccomp("Seccomp:\tx\n"), None);
        assert_eq!(parse_seccomp("Seccomp:\t0\n"), Some(0));
    }

    #[test]
    fn landlock_errno_mapping() {
        assert_eq!(landlock_from_return(7, 0), Landlock::Abi(7));
        assert_eq!(
            landlock_from_return(-1, libc::ENOSYS),
            Landlock::Errno(libc::ENOSYS)
        );
        assert_eq!(
            landlock_from_return(-1, libc::EOPNOTSUPP),
            Landlock::Errno(libc::EOPNOTSUPP)
        );
    }

    fn report_json(version: u32, names: &[&str]) -> String {
        let steps: Vec<String> = names
            .iter()
            .map(|n| format!(r#"{{"step":"{n}","status":"ok","errno":null,"reason":null}}"#))
            .collect();
        format!(r#"{{"version":{version},"steps":[{}]}}"#, steps.join(","))
    }

    #[test]
    fn parse_probe_output_table() {
        let good = report_json(1, &PROBE_STEPS);
        assert!(matches!(
            parse_probe_output(Some(0), &good, ""),
            ProbeOutcome::Ran(_)
        ));
        assert_eq!(
            parse_probe_output(Some(1), "", "sbx __init: internal error: boom\n"),
            ProbeOutcome::Failed("sbx __init: internal error: boom".into())
        );
        assert_eq!(
            parse_probe_output(Some(3), "", ""),
            ProbeOutcome::Failed("exited with status 3".into())
        );
        assert_eq!(
            parse_probe_output(Some(0), "garbage", ""),
            ProbeOutcome::Failed("unparseable probe output".into())
        );
        assert_eq!(
            parse_probe_output(Some(0), &report_json(2, &PROBE_STEPS), ""),
            ProbeOutcome::Failed("probe protocol version 2, expected 1".into())
        );
        let mut swapped = PROBE_STEPS;
        swapped.swap(0, 1);
        assert_eq!(
            parse_probe_output(Some(0), &report_json(1, &swapped), ""),
            ProbeOutcome::Failed("unexpected probe steps".into())
        );
    }
}
