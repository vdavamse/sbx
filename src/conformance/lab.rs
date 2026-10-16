//! The conformance lab (issue #13, PR2): an unprivileged nested user, network
//! and mount namespace in which `sbx run` is exercised against local
//! fixtures on `9.9.9.9` and a lab DNS that never forwards.
//!
//! Two sides:
//! * **child** (`sbx __conformance lab`, [`run`]): unshares first (it must be
//!   single-threaded for `CLONE_NEWUSER`), binds the lab's `resolv.conf` and
//!   `nsswitch.conf` over the host's (never `/etc/hosts`), configures `lo`,
//!   starts the fixtures, runs the L scenarios, and prints one JSON line per
//!   check. Setup failures print `{"lab":"unavailable",...}` and nothing else.
//! * **parent** ([`spawn_tier`]): spawns the child with a process group, a
//!   60 s bound, and parses its lines. A timeout SIGKILLs the group.

use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::report::CheckResult;
use super::scenarios::Env;
use super::{fixtures, lab_tier};
use crate::init::{OuterIds, configure_lab_lo, write_id_maps};

/// The parent's bound on the whole lab child.
pub const LAB_BOUND: Duration = Duration::from_secs(60);

/// What the parent learned from the child.
pub enum LabOutcome {
    /// The lab ran; one result per selected L check (catalog order not guaranteed).
    Ran(Vec<CheckResult>),
    /// Setup failed at `stage`; every L check is a capability skip.
    Unavailable { stage: String, reason: String },
    /// The child did not finish within [`LAB_BOUND`] (its group was killed).
    TimedOut,
    /// The child could not be spawned or its output was unreadable.
    Broken(String),
}

/// The child's state after a successful setup: the scenario environment, the
/// fixture logs and the trap accept counts recorded by the control.
type LabSetup = (Env, Arc<fixtures::Logs>, Vec<(Ipv4Addr, u64)>);

/// A setup failure inside the child.
struct SetupErr {
    stage: &'static str,
    reason: String,
    errno: Option<i32>,
}

impl SetupErr {
    fn new(stage: &'static str, e: impl std::fmt::Display, errno: Option<i32>) -> Self {
        SetupErr {
            stage,
            reason: e.to_string(),
            errno,
        }
    }

    fn io(stage: &'static str, e: &io::Error) -> Self {
        SetupErr::new(stage, e, e.raw_os_error())
    }
}

/// The child's entry point (`sbx __conformance lab`). `base` is the suite's
/// temp base (holds the probe copy `sbx`); `only` filters the L checks.
pub fn run(base: &Path, nonce: &str, only: &[String]) -> ExitCode {
    // FIRST: capture the outer ids, then unshare. Nothing before this line
    // may start a thread (CLONE_NEWUSER needs a single-threaded process).
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    let outer = unsafe {
        OuterIds {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    };
    // SAFETY: unshare(2) with namespace flags only; no pointers passed.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) };
    if rc != 0 {
        return unavailable(&SetupErr::io("unshare", &io::Error::last_os_error()));
    }
    let (env, logs, traps) = match setup(base, nonce, outer) {
        Ok(v) => v,
        Err(e) => return unavailable(&e),
    };
    emit(&serde_json::json!({"lab": "ok"}));
    let results = lab_tier::run_all(&env, &logs, &traps, only);
    for r in &results {
        emit(r);
    }
    emit(&serde_json::json!({"done": true}));
    ExitCode::SUCCESS
}

fn emit(v: &impl serde::Serialize) {
    if let Ok(line) = serde_json::to_string(v) {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

fn unavailable(e: &SetupErr) -> ExitCode {
    emit(&serde_json::json!({
        "lab": "unavailable",
        "stage": e.stage,
        "reason": e.reason,
        "errno": e.errno,
    }));
    ExitCode::SUCCESS
}

/// Staged setup; the first failure aborts. Returns the scenario environment,
/// the fixture logs and the trap accept counts recorded by the control.
fn setup(base: &Path, nonce: &str, outer: OuterIds) -> Result<LabSetup, SetupErr> {
    write_id_maps(outer).map_err(|e| SetupErr::new("idmap", e, None))?;
    // SAFETY: mount(2) with a NULL source and fstype: a propagation change only.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(SetupErr::io("mount-private", &io::Error::last_os_error()));
    }
    let lab_dir = base.join("lab");
    fs::create_dir_all(&lab_dir).map_err(|e| SetupErr::io("lab-dir", &e))?;
    bind_over(
        &lab_dir.join("resolv.conf"),
        "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
        "/etc/resolv.conf",
        "bind-resolv",
    )?;
    bind_over(
        &lab_dir.join("nsswitch.conf"),
        "hosts: files dns\n",
        "/etc/nsswitch.conf",
        "bind-nsswitch",
    )?;
    configure_lab_lo(&[
        fixtures::LAB_IP,
        fixtures::TRAP_PRIVATE,
        fixtures::TRAP_META,
    ])
    .map_err(|e| SetupErr::new("lo", e, None))?;

    let dns = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))
        .map_err(|e| SetupErr::io("bind-fixtures", &e))?;
    let tls = std::net::TcpListener::bind((fixtures::LAB_IP, 443))
        .map_err(|e| SetupErr::io("bind-fixtures", &e))?;
    let http = std::net::TcpListener::bind((fixtures::LAB_IP, 80))
        .map_err(|e| SetupErr::io("bind-fixtures", &e))?;
    let mut traps = Vec::new();
    for ip in [
        fixtures::TRAP_LOOPBACK,
        fixtures::TRAP_PRIVATE,
        fixtures::TRAP_META,
    ] {
        let l = std::net::TcpListener::bind((ip, 443))
            .map_err(|e| SetupErr::io("bind-fixtures", &e))?;
        traps.push((ip, l));
    }
    let logs = Arc::new(fixtures::Logs::default());
    fixtures::spawn(
        &logs,
        fixtures::Listeners {
            dns,
            tls,
            http,
            traps,
        },
    );

    // The A12 control: each trap accepts exactly one connection from the lab.
    let mut control = Vec::new();
    for ip in [
        fixtures::TRAP_LOOPBACK,
        fixtures::TRAP_PRIVATE,
        fixtures::TRAP_META,
    ] {
        TcpStream::connect_timeout(&(ip, 443).into(), Duration::from_secs(2))
            .map_err(|e| SetupErr::io("traps-control", &e))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while logs.trap_accepts(ip) < 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let n = logs.trap_accepts(ip);
        if n != 1 {
            return Err(SetupErr::new(
                "traps-control",
                format!("trap {ip}:443 saw {n} accepts for one control connect"),
                None,
            ));
        }
        control.push((ip, n));
    }
    let exe = base.join("sbx");
    let exe_text = exe
        .to_str()
        .ok_or_else(|| SetupErr::new("setup", "the temp base is not UTF-8", None))?
        .to_owned();
    let env = Env {
        exe: PathBuf::from(&exe_text),
        exe_text,
        base: lab_dir,
        secret: format!("sec-{nonce}"),
        passed: format!("pas-{nonce}"),
        nonce: nonce.to_owned(),
    };
    Ok((env, logs, control))
}

/// Bind `contents` (written to `src`) over `target` when `target` exists.
fn bind_over(
    src: &Path,
    contents: &str,
    target: &str,
    stage: &'static str,
) -> Result<(), SetupErr> {
    if !Path::new(target).exists() {
        return Ok(());
    }
    fs::write(src, contents).map_err(|e| SetupErr::io(stage, &e))?;
    let c_src =
        CString::new(src.as_os_str().as_bytes()).map_err(|e| SetupErr::new(stage, e, None))?;
    let c_target = CString::new(target).map_err(|e| SetupErr::new(stage, e, None))?;
    // SAFETY: both paths are valid NUL-terminated strings; MS_BIND ignores fstype and data.
    let rc = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(SetupErr::io(stage, &io::Error::last_os_error()));
    }
    Ok(())
}

/// Parent side: run the lab child for the selected L checks.
///
/// `bound` is the lab's wall-clock allowance (the lesser of [`LAB_BOUND`] and
/// what the suite's global budget has left).
pub fn spawn_tier(env: &Env, only: &[String], nonce: &str, bound: Duration) -> LabOutcome {
    // `env.base` is the suite's temp base; the child creates `<base>/lab`.
    let base = env.base.clone();
    let stderr = match fs::File::create(base.join(format!("lab-{nonce}.stderr"))) {
        Ok(f) => f,
        Err(e) => return LabOutcome::Broken(format!("cannot create the lab stderr file: {e}")),
    };
    let mut cmd = Command::new(&env.exe);
    cmd.args(["__conformance", "lab", "--base"])
        .arg(&base)
        .args(["--nonce", nonce]);
    if !only.is_empty() {
        cmd.arg("--only").arg(only.join(","));
    }
    cmd.process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr);
    // The child dies with the suite: PR_SET_PDEATHSIG(SIGKILL), and a parent
    // that already died before the prctl (getppid changed) makes it exit at once.
    // SAFETY: the closure only calls async-signal-safe libc functions.
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return LabOutcome::Broken(format!("cannot spawn the lab child: {e}")),
    };
    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        return LabOutcome::Broken("the lab child has no stdout".to_owned());
    };
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + bound;
    let mut lines = Vec::new();
    let mut timed_out = false;
    loop {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        match rx.recv_timeout(left) {
            Ok(line) => {
                let done = line.contains("\"done\":true");
                lines.push(line);
                if done {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if timed_out {
        // SAFETY: kill(2) on the child's own process group (set by process_group(0)).
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.wait();
    if timed_out {
        return LabOutcome::TimedOut;
    }
    interpret(&lines)
}

/// Turn the child's stdout lines into an outcome.
fn interpret(lines: &[String]) -> LabOutcome {
    let Some(first) = lines.first() else {
        return LabOutcome::Broken("the lab child printed nothing".to_owned());
    };
    let head: serde_json::Value = match serde_json::from_str(first) {
        Ok(v) => v,
        Err(e) => return LabOutcome::Broken(format!("unreadable lab banner: {e}")),
    };
    match head["lab"].as_str() {
        Some("unavailable") => LabOutcome::Unavailable {
            stage: head["stage"].as_str().unwrap_or("?").to_owned(),
            reason: head["reason"].as_str().unwrap_or("?").to_owned(),
        },
        Some("ok") => {
            let mut results = Vec::new();
            for line in &lines[1..] {
                if line.contains("\"done\"") {
                    continue;
                }
                match serde_json::from_str::<CheckResult>(line) {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        return LabOutcome::Broken(format!("unreadable lab result: {e}"));
                    }
                }
            }
            if !lines.iter().any(|l| l.contains("\"done\":true")) {
                return LabOutcome::Broken(
                    "the lab child did not finish (no done line)".to_owned(),
                );
            }
            LabOutcome::Ran(results)
        }
        _ => LabOutcome::Broken(format!("unexpected lab banner: {first}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_ip_passes_the_guard() {
        // The lab upstream must not be denied by the production guard: a
        // future guard table that denies 9.9.9.9 fails here first.
        assert!(crate::egress::guard(fixtures::LAB_IP.into()).is_ok());
        assert!(!fixtures::LAB_IP.is_private());
    }

    #[test]
    fn interpret_maps_unavailable_and_broken() {
        let u = vec![
            r#"{"lab":"unavailable","stage":"unshare","reason":"EPERM","errno":1}"#.to_owned(),
        ];
        assert!(matches!(
            interpret(&u),
            LabOutcome::Unavailable { ref stage, .. } if stage == "unshare"
        ));
        assert!(matches!(interpret(&[]), LabOutcome::Broken(_)));
        let no_done = vec![r#"{"lab":"ok"}"#.to_owned()];
        assert!(matches!(interpret(&no_done), LabOutcome::Broken(_)));
    }
}
