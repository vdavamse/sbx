//! Spawning `sbx __init` and learning the sandbox's pid 1 (issue #10, T4, Q13).
//!
//! `__init` execs bwrap (same pid). bwrap writes `{"child-pid": H, …}` to the
//! `--info-fd` pipe right after clone; `H` is the HOST pid of the sandbox's
//! pid 1. Proof of identity before any signal is sent: `/proc/H/status` must
//! show `PPid == bwrap` and `NSpid`'s last entry `== 1` (E4). The fallback is
//! `/proc/<bwrap>/task/<bwrap>/children` with exactly one entry.

use std::ffi::OsString;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::RunError;
use super::sys::Signals;
use super::sys::{self, pollfd, ready};
use crate::bwrap::Launch;
use crate::init::fdpass::{AchievedMode, ListenerFds, SetupMsg, StagedFailure, recv_setup};
use crate::policy::NetworkMode;

/// The re-exec argv after the program:
/// `__init --fd C --keep-fd I --parent-pid P --min-mode M [--test-break-rules] -- <argv…>`
/// (issue #11: `M` is the policy's mode — the weakest mode `__init` may fall
/// back to).
pub(crate) fn init_argv(
    control_fd: RawFd,
    info_fd: RawFd,
    parent_pid: u32,
    min_mode: NetworkMode,
    test_break_rules: bool,
    launch: &Launch,
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        "__init".into(),
        "--fd".into(),
        control_fd.to_string().into(),
        "--keep-fd".into(),
        info_fd.to_string().into(),
        "--parent-pid".into(),
        parent_pid.to_string().into(),
        "--min-mode".into(),
        mode_word(min_mode).into(),
    ];
    if test_break_rules {
        argv.push("--test-break-rules".into());
    }
    argv.push("--".into());
    argv.extend(launch.argv().iter().cloned());
    argv
}

/// The `--min-mode` spelling of a policy mode (the `parse_network_mode` set).
fn mode_word(mode: NetworkMode) -> &'static str {
    match mode {
        NetworkMode::Transparent => "transparent",
        NetworkMode::Explicit => "explicit",
        NetworkMode::None => "none",
    }
}

/// `/proc/self/exe` (the same-binary invariant even if the file is replaced
/// mid-run), `env_clear()` (the second and last env-encoding site), stdout and
/// stderr piped for the pumps, and its own process group.
pub(crate) fn init_command(
    control_fd: RawFd,
    info_fd: RawFd,
    min_mode: NetworkMode,
    test_break_rules: bool,
    launch: &Launch,
    stdin: Stdio,
) -> Command {
    let mut cmd = Command::new("/proc/self/exe");
    // m6: __init arms PDEATHSIG and verifies this pid as its parent.
    cmd.args(init_argv(
        control_fd,
        info_fd,
        std::process::id(),
        min_mode,
        test_break_rules,
        launch,
    ))
    .env_clear()
    .stdin(stdin)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .process_group(0);
    cmd
}

#[derive(Deserialize)]
struct InfoFd {
    #[serde(rename = "child-pid")]
    child_pid: i32,
}

/// The `child-pid` of bwrap's info JSON. Unknown keys are ignored (the
/// 6-key production form and the 3-key 0.9 form both parse). Some iff > 1.
pub(crate) fn parse_info(bytes: &[u8]) -> Option<libc::pid_t> {
    let info: InfoFd = serde_json::from_slice(bytes).ok()?;
    (info.child_pid > 1).then_some(info.child_pid)
}

/// `(PPid, last NSpid)` from a `/proc/<pid>/status` text.
pub(crate) fn parse_status(text: &str) -> Option<(libc::pid_t, libc::pid_t)> {
    let mut ppid = None;
    let mut last_nspid = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("NSpid:") {
            last_nspid = rest.split_whitespace().last().and_then(|t| t.parse().ok());
        }
    }
    Some((ppid?, last_nspid?))
}

/// The pids listed in `/proc/<pid>/task/<tid>/children`.
pub(crate) fn parse_children(text: &str) -> Vec<libc::pid_t> {
    text.split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect()
}

/// Opens a pidfd for `pid` and verifies it is the sandbox's pid 1: its parent
/// is `bwrap_pid` and its innermost pid namespace id is 1. Sound because bwrap
/// is not yet reaped, so `bwrap_pid` cannot be recycled, and a recycled `pid`
/// can never have `PPid == bwrap_pid`.
pub(crate) fn open_pid1(pid: libc::pid_t, bwrap_pid: libc::pid_t) -> Option<OwnedFd> {
    let pidfd = sys::pidfd_open(pid).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let (ppid, last_nspid) = parse_status(&status)?;
    (ppid == bwrap_pid && last_nspid == 1).then_some(pidfd)
}

/// Fallback (Q13): exactly one child of bwrap ⇒ that child, verified.
pub(crate) fn pid1_from_children(bwrap_pid: libc::pid_t) -> Option<OwnedFd> {
    let text =
        std::fs::read_to_string(format!("/proc/{bwrap_pid}/task/{bwrap_pid}/children")).ok()?;
    let children = parse_children(&text);
    match children.as_slice() {
        [only] => open_pid1(*only, bwrap_pid),
        _ => None,
    }
}

/// How the setup wait ended.
pub(crate) enum SetupEnd {
    /// `__init` reached `send-fds`: the listener fds and the mode it achieved.
    Ready {
        fds: ListenerFds,
        mode: AchievedMode,
    },
    /// `__init` reported a staged failure (`'E'`) and is exiting.
    Refused(StagedFailure),
    Signal(i32),
    /// The run deadline (`--timeout`) passed first.
    TimedOut,
    /// The 30 s setup budget passed first.
    SetupTimedOut,
    /// `__init` exited before handing over its fds (status is collected by the caller).
    ChildExited,
    Failed(RunError),
}

/// Waits for `__init`'s listener fds. Priority within one wakeup: signal, then
/// ctrl, then child exit, then the deadline. A readable ctrl means that
/// `recv_listener_fds` will not block.
pub(crate) fn wait_for_fds(
    ctrl: BorrowedFd<'_>,
    child: BorrowedFd<'_>,
    signals: &Signals,
    run_deadline: Instant,
    setup_deadline: Instant,
) -> SetupEnd {
    use std::os::fd::AsRawFd;
    let deadline = run_deadline.min(setup_deadline);
    loop {
        let mut fds = [
            pollfd(signals.fd().as_raw_fd(), libc::POLLIN),
            pollfd(ctrl.as_raw_fd(), libc::POLLIN),
            pollfd(child.as_raw_fd(), libc::POLLIN),
        ];
        let n = match sys::poll_fds(&mut fds, Some(deadline)) {
            Ok(n) => n,
            Err(err) => {
                return SetupEnd::Failed(RunError::new(format!("sandbox setup failed: {err}")));
            }
        };
        if n == 0 {
            return if run_deadline <= setup_deadline {
                SetupEnd::TimedOut
            } else {
                SetupEnd::SetupTimedOut
            };
        }
        if ready(fds[0].revents) {
            if let Some(sig) = signals.read() {
                return SetupEnd::Signal(sig);
            }
        }
        if ready(fds[1].revents) {
            return match recv_setup(ctrl.as_raw_fd()) {
                Ok(SetupMsg::Ready { fds, mode }) => SetupEnd::Ready { fds, mode },
                Ok(SetupMsg::Failed(failure)) => SetupEnd::Refused(failure),
                Err(err) => {
                    // m1: a dying __init hangs up ctrl AND readies its pidfd; the ctrl
                    // error can win the race. Give the pidfd a moment: if __init is gone,
                    // report its exit (the pinned message), else the receive error.
                    if sys::wait_readable(child, Duration::from_millis(100)).unwrap_or(false) {
                        return SetupEnd::ChildExited;
                    }
                    SetupEnd::Failed(RunError::new(format!("sandbox setup failed: {err}")))
                }
            };
        }
        if ready(fds[2].revents) {
            return SetupEnd::ChildExited;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn wait_for_fds_reports_refusal() {
        // Issue #11: a staged failure ('E') is a successful receive: the wait
        // returns Refused with the stage, errno and reason, while __init is
        // still alive (the run then waits for its stderr line).
        use crate::init::InitError;
        use crate::init::Stage;
        use crate::init::fdpass::{control_socketpair, send_failure};
        let (parent_end, child_end) = control_socketpair().expect("socketpair");
        let err = InitError::new(Stage::NftLoad, "batch failed").with_errno(Some(2));
        use std::os::fd::AsRawFd;
        send_failure(child_end.as_raw_fd(), &err);
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn");
        let pidfd = sys::pidfd_open(child.id() as libc::pid_t).expect("pidfd");
        let signals = sys::Signals::install().expect("signals");
        let now = Instant::now();
        let end = wait_for_fds(
            parent_end.as_fd(),
            pidfd.as_fd(),
            &signals,
            now + Duration::from_secs(10),
            now + Duration::from_secs(10),
        );
        match end {
            SetupEnd::Refused(failure) => {
                assert_eq!(failure.stage, Stage::NftLoad);
                assert_eq!(failure.errno, Some(2));
                assert_eq!(failure.reason, "batch failed");
            }
            _ => panic!("expected Refused"),
        }
        let _ = child.kill();
        child.wait().expect("reap");
    }

    #[test]
    fn dead_init_with_hung_up_ctrl_reports_its_exit() {
        // m1: ctrl hangs up (receive error) and __init has already exited: the
        // setup wait must report ChildExited, not the receive error.
        let (ctrl_a, ctrl_b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        drop(ctrl_b);
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn");
        let pidfd = sys::pidfd_open(child.id() as libc::pid_t).expect("pidfd");
        // Let it exit (pidfd becomes readable) without reaping it.
        assert!(sys::wait_readable(pidfd.as_fd(), Duration::from_secs(10)).expect("poll"));
        let signals = sys::Signals::install().expect("signals");
        let now = Instant::now();
        let end = wait_for_fds(
            ctrl_a.as_fd(),
            pidfd.as_fd(),
            &signals,
            now + Duration::from_secs(10),
            now + Duration::from_secs(10),
        );
        assert!(matches!(end, SetupEnd::ChildExited), "wrong setup end");
        child.wait().expect("reap");
    }

    #[test]
    fn parse_info_bwrap_090_three_keys() {
        let bytes = b"{\n    \"child-pid\": 199130,\n    \"mnt-namespace\": 4026532368,\n    \"pid-namespace\": 4026532369\n}\n";
        assert_eq!(parse_info(bytes), Some(199130));
    }

    #[test]
    fn parse_info_bwrap_090_six_keys() {
        let bytes = b"{\n    \"child-pid\": 4242,\n    \"mnt-namespace\": 1,\n    \"pid-namespace\": 2,\n    \"cgroup-namespace\": 3,\n    \"ipc-namespace\": 4,\n    \"uts-namespace\": 5\n}\n";
        assert_eq!(parse_info(bytes), Some(4242));
    }

    #[test]
    fn parse_info_rejects_table() {
        for bad in [
            &b""[..],
            b"garbage",
            b"{\"child-pid\":0}",
            b"{\"child-pid\":1}",
            b"{\"child-pid\":-5}",
            b"{\"mnt-namespace\":1}",
            b"{\"child-pid\":\"123\"}",
        ] {
            assert_eq!(parse_info(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn parse_status_table() {
        let text = "Name:\tbwrap\nPPid:\t199129\nNSpid:\t199130\t1\n";
        assert_eq!(parse_status(text), Some((199129, 1)));
        // No NSpid line (old kernel) ⇒ cannot prove identity.
        assert_eq!(parse_status("PPid:\t5\n"), None);
        // No PPid line ⇒ None.
        assert_eq!(parse_status("NSpid:\t7\t1\n"), None);
    }

    #[test]
    fn parse_children_table() {
        assert_eq!(parse_children("199130 \n"), vec![199130]);
        assert_eq!(parse_children(""), Vec::<libc::pid_t>::new());
        assert_eq!(parse_children("12 13\n"), vec![12, 13]);
    }

    #[test]
    fn init_argv_shape() {
        let launch = crate::bwrap::build(&crate::bwrap::Build {
            policy: &crate::policy::Policy::from_json_str(
                r#"{"version":1,"filesystem":{"ro":[],"rw":[],"deny":[]},"network":{"mode":"none","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#,
            )
            .expect("policy"),
            session_dir: std::path::Path::new("/var/lib/sbx-test/s1"),
            bwrap_path: std::path::Path::new("/usr/bin/bwrap"),
            command: &["/bin/true".into()],
            cwd: None,
            passed_env: &Default::default(),
            info_fd: Some(9),
        })
        .expect("builds");
        let argv = init_argv(7, 9, 4242, NetworkMode::Explicit, false, &launch);
        assert_eq!(
            &argv[..10],
            [
                "__init",
                "--fd",
                "7",
                "--keep-fd",
                "9",
                "--parent-pid",
                "4242",
                "--min-mode",
                "explicit",
                "--",
            ]
            .map(OsString::from)
        );
        assert_eq!(&argv[10..], launch.argv());
        let with_break = init_argv(7, 9, 4242, NetworkMode::Transparent, true, &launch);
        assert_eq!(
            with_break[8..11],
            ["transparent", "--test-break-rules", "--"].map(OsString::from)
        );
    }
}
