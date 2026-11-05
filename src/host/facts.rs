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
use crate::init::probe::{PROBE_STEPS, PROBE_VERSION, ProbeReport};

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
    if report.version != PROBE_VERSION {
        return ProbeOutcome::Failed(format!(
            "probe protocol version {}, expected {PROBE_VERSION}",
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

/// Entry bound of [`socket_scan`] (issue #35): the default policy's `/usr`
/// is ~70k entries, so this leaves an order of magnitude of headroom while
/// bounding a policy that binds a huge tree.
pub const SOCKET_SCAN_MAX_ENTRIES: usize = 500_000;

/// Depth bound of [`socket_scan`] below each root.
pub const SOCKET_SCAN_MAX_DEPTH: usize = 32;

/// What [`socket_scan`] saw: the socket files (sorted, deduped) and whether a
/// bound cut the walk short (then `found` is not exhaustive).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketScan {
    pub found: Vec<PathBuf>,
    pub truncated: bool,
}

/// Walk `roots` (the policy `ro`/`rw` binds) for unix socket files the payload
/// can reach (issue #35): a read-only bind does not block `connect()`.
/// Production entry point of [`socket_scan_bounded`] with the sandbox's
/// shadowed destinations ([`crate::bwrap::shadowed_dests`]) and the
/// [`SOCKET_SCAN_MAX_ENTRIES`]/[`SOCKET_SCAN_MAX_DEPTH`] bounds.
pub fn socket_scan(roots: &[&Path], skip: &[&Path]) -> SocketScan {
    let shadows = crate::bwrap::shadowed_dests();
    let shadows: Vec<&Path> = shadows.iter().map(Path::new).collect();
    socket_scan_bounded(
        roots,
        skip,
        &shadows,
        SOCKET_SCAN_MAX_ENTRIES,
        SOCKET_SCAN_MAX_DEPTH,
    )
}

/// The bounded walk behind [`socket_scan`].
///
/// - `skip` (the deny masks) hides every path at or under it, roots
///   included: bwrap's deny `--tmpfs` mounts come after every bind.
/// - `shadow` (destinations sbx mounts over AFTER the policy binds: the
///   session leaves and `/proc`, `/dev`) hides what is at or under it in a
///   root's walk, unless the root lies strictly below that shadow. Such a
///   root is its own bind, which sorts and mounts after the shadow.
/// - Roots follow symlinks (bwrap's bind does). Entries below them are
///   `lstat`ed and not followed: inside the sandbox a link resolves against
///   the sandbox view, which only holds other binds, walked as their own
///   roots.
/// - Unreadable directories are skipped. They are unreadable to the payload
///   too (same uid).
/// - `truncated` is set when `max_entries` stops the walk (`found` is then
///   partial) or a directory sits at `max_depth`.
pub fn socket_scan_bounded(
    roots: &[&Path],
    skip: &[&Path],
    shadow: &[&Path],
    max_entries: usize,
    max_depth: usize,
) -> SocketScan {
    use std::os::unix::fs::FileTypeExt;

    // The shadows that apply to the walk of `root`.
    let shadows_for = |root: &Path| -> Vec<&Path> {
        shadow
            .iter()
            .copied()
            .filter(|s| !(root.starts_with(s) && root != *s))
            .collect()
    };
    let hidden = |p: &Path, shadows: &[&Path]| {
        skip.iter().any(|s| p.starts_with(s)) || shadows.iter().any(|s| p.starts_with(s))
    };

    let mut sorted: Vec<&Path> = roots.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut kept: Vec<&Path> = Vec::new();
    for root in sorted {
        // A root under an earlier root is walked as part of it, unless that
        // walk hides it (a shadow over it that the earlier root does not
        // escape): then it is its own bind and walked separately.
        let covered = kept
            .iter()
            .any(|k| root.starts_with(k) && !hidden(root, &shadows_for(k)));
        if !covered {
            kept.push(root);
        }
    }

    let mut scan = SocketScan::default();
    let mut visited = 0usize;
    'roots: for root in kept {
        let shadows = shadows_for(root);
        if hidden(root, &shadows) {
            continue;
        }
        let Ok(meta) = fs::metadata(root) else {
            continue;
        };
        if meta.file_type().is_socket() {
            scan.found.push(root.to_path_buf());
            continue;
        }
        if !meta.is_dir() {
            continue;
        }
        let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                visited += 1;
                if visited > max_entries {
                    scan.truncated = true;
                    break 'roots;
                }
                let path = entry.path();
                if hidden(&path, &shadows) {
                    continue;
                }
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_socket() {
                    scan.found.push(path);
                } else if kind.is_dir() {
                    if depth + 1 < max_depth {
                        stack.push((path, depth + 1));
                    } else {
                        scan.truncated = true;
                    }
                }
            }
        }
    }
    scan.found.sort();
    scan.found.dedup();
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #35: sockets under a root are found, deny-masked subtrees and
    /// symlinks are not followed, overlapping roots are walked once.
    #[test]
    fn socket_scan_finds_sockets_and_honours_skip() {
        let base = std::env::temp_dir().join(format!("sbx-socket-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("run/user")).expect("mkdir");
        fs::create_dir_all(base.join("denied")).expect("mkdir");
        let a = base.join("run/docker.sock");
        let b = base.join("run/user/agent.sock");
        let hidden = base.join("denied/x.sock");
        let _l1 = std::os::unix::net::UnixListener::bind(&a).expect("bind");
        let _l2 = std::os::unix::net::UnixListener::bind(&b).expect("bind");
        let _l3 = std::os::unix::net::UnixListener::bind(&hidden).expect("bind");
        std::os::unix::fs::symlink(&a, base.join("link.sock")).expect("symlink");
        fs::write(base.join("plain"), b"x").expect("write");

        let run = base.join("run");
        let denied = base.join("denied");
        let scan = socket_scan(&[base.as_path(), run.as_path()], &[denied.as_path()]);
        assert_eq!(scan.found, vec![a.clone(), b.clone()]);
        assert!(!scan.truncated);

        // A root that is itself a socket is reported; a missing root is not.
        let scan = socket_scan(&[a.as_path(), Path::new("/nonexistent/sbx-scan")], &[]);
        assert_eq!(scan.found, vec![a.clone()]);

        // A skipped root is not walked at all.
        let scan = socket_scan(&[run.as_path()], &[run.as_path()]);
        assert!(scan.found.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    fn scratch(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("sbx-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("mkdir");
        base
    }

    /// Review of #48: a root equal to a shadow (session tmp over `/tmp`) is
    /// hidden; a root strictly below it is its own bind and walked; a
    /// shadow inside a root hides that subtree only.
    #[test]
    fn socket_scan_honours_shadows() {
        let base = scratch("socket-scan-shadow");
        let tmp = base.join("tmp");
        let x = tmp.join("x");
        fs::create_dir_all(&x).expect("mkdir");
        let top = tmp.join("X0");
        let below = x.join("agent.sock");
        let outside = base.join("run.sock");
        let _l1 = std::os::unix::net::UnixListener::bind(&top).expect("bind");
        let _l2 = std::os::unix::net::UnixListener::bind(&below).expect("bind");
        let _l3 = std::os::unix::net::UnixListener::bind(&outside).expect("bind");
        let shadow = [tmp.as_path()];

        let scan = socket_scan_bounded(&[tmp.as_path()], &[], &shadow, 1000, 8);
        assert!(scan.found.is_empty(), "{scan:?}");
        let scan = socket_scan_bounded(&[tmp.as_path(), x.as_path()], &[], &shadow, 1000, 8);
        assert_eq!(scan.found, vec![below.clone()]);
        // base covers tmp, but tmp is shadowed inside base's walk: only x
        // (its own root) and the socket outside the shadow are reachable.
        let scan = socket_scan_bounded(&[base.as_path(), x.as_path()], &[], &shadow, 1000, 8);
        assert_eq!(scan.found, vec![outside.clone(), below.clone()]);
        let scan = socket_scan_bounded(&[base.as_path()], &[], &shadow, 1000, 8);
        assert_eq!(scan.found, vec![outside.clone()]);

        let _ = fs::remove_dir_all(&base);
    }

    /// Review of #48: both bounds set `truncated`, and a directory symlink
    /// below a root is not followed.
    #[test]
    fn socket_scan_bounds_and_dir_symlinks() {
        let base = scratch("socket-scan-bounds");
        let deep = base.join("a/b");
        fs::create_dir_all(&deep).expect("mkdir");
        let sock = deep.join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        std::os::unix::fs::symlink(base.join("a"), base.join("dirlink")).expect("symlink");

        let scan = socket_scan_bounded(&[base.as_path()], &[], &[], 1000, 8);
        assert_eq!(
            scan.found,
            vec![sock.clone()],
            "dirlink must not be followed"
        );
        assert!(!scan.truncated);

        let scan = socket_scan_bounded(&[base.as_path()], &[], &[], 1000, 2);
        assert!(scan.found.is_empty());
        assert!(scan.truncated, "a directory at max_depth truncates");

        let scan = socket_scan_bounded(&[base.as_path()], &[], &[], 2, 8);
        assert!(scan.truncated, "max_entries truncates");

        let _ = fs::remove_dir_all(&base);
    }

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
        let good = report_json(PROBE_VERSION, &PROBE_STEPS);
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
            parse_probe_output(Some(0), &report_json(1, &PROBE_STEPS), ""),
            ProbeOutcome::Failed(format!(
                "probe protocol version 1, expected {PROBE_VERSION}"
            ))
        );
        let mut swapped = PROBE_STEPS;
        swapped.swap(0, 1);
        assert_eq!(
            parse_probe_output(Some(0), &report_json(PROBE_VERSION, &swapped), ""),
            ProbeOutcome::Failed("unexpected probe steps".into())
        );
    }
}
