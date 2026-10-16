//! The init tier: F03 (issue #13, §9). The production `sbx __init` is
//! spawned directly with the control socketpair, the parent receives the
//! three listener fds, and the probe runs inside the namespace twice:
//!
//! 1. control: the fds are kept and one connection to 203.0.113.7:443 must be
//!    accepted on the transparent listener (the redirect really reaches it);
//! 2. gone: the fds are dropped before the go byte, so every egress path must
//!    be refused.

use std::io::Read;
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::probe::{Op, Ops, ProbeOutput, ReadSpec, SendSpec, Step, Target};
use super::report::CheckResult;
use crate::host::Status;
use crate::init::fdpass;

/// What the gone run observed, or why it could not run.
struct InitRun {
    stdout: Vec<String>,
    stderr: String,
    rc: Option<i32>,
    accepts: u32,
}

fn init_ops(gone: bool) -> Vec<Op> {
    let mut ops = vec![Op::Hello {
        id: "f03.hello".into(),
    }];
    if gone {
        ops.push(Op::Tcp {
            id: "f03.tcp1111".into(),
            target: Target::Addr {
                addr: "1.1.1.1:443".into(),
            },
            steps: vec![],
            connect_timeout_ms: 2000,
        });
        ops.push(Op::Tcp {
            id: "f03.tcp15001".into(),
            target: Target::Addr {
                addr: "127.0.0.1:15001".into(),
            },
            steps: vec![],
            connect_timeout_ms: 2000,
        });
        ops.push(Op::Tcp {
            id: "f03.tcp3128".into(),
            target: Target::Addr {
                addr: "127.0.0.1:3128".into(),
            },
            steps: vec![],
            connect_timeout_ms: 2000,
        });
        ops.push(Op::Udp {
            id: "f03.udp53".into(),
            addr: "8.8.8.8:53".into(),
            text: "Q".into(),
            attempts: 5,
            recv_timeout_ms: 300,
        });
        ops.push(Op::Udp {
            id: "f03.udp123".into(),
            addr: "8.8.8.8:123".into(),
            text: "Q".into(),
            attempts: 2,
            recv_timeout_ms: 300,
        });
        ops.push(Op::Links {
            id: "f03.links".into(),
        });
    } else {
        ops.push(Op::Tcp {
            id: "f03.control".into(),
            target: Target::Addr {
                addr: "203.0.113.7:443".into(),
            },
            steps: vec![
                Step::Send(SendSpec::Text { text: "x".into() }),
                Step::Read(ReadSpec {
                    until: None,
                    max: 64,
                    timeout_ms: 1000,
                }),
            ],
            connect_timeout_ms: 2000,
        });
    }
    ops
}

/// Spawn `sbx __init` with the probe as its payload. Returns the child and the
/// parent end of the control socketpair.
fn spawn_init(exe: &Path, exe_text: &str, gone: bool) -> std::io::Result<(Child, OwnedFd)> {
    let (parent_end, child_end) = fdpass::control_socketpair()?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd())?;
    let memfd = crate::bwrap::seccomp::program_memfd()?;
    let mraw = memfd.as_raw_fd();
    // SAFETY: fcntl on our own memfd; the seccomp fd must reach __init.
    unsafe { libc::fcntl(mraw, libc::F_SETFD, 0) };
    let json = serde_json::to_string(&Ops::new(init_ops(gone))).unwrap_or_else(|_| "{}".to_owned());
    let mut cmd = Command::new(exe);
    cmd.arg("__init")
        .arg("--fd")
        .arg(child_fd.to_string())
        .arg("--seccomp-fd")
        .arg(mraw.to_string())
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .arg("--min-mode")
        .arg("transparent")
        .arg("--")
        .arg(exe_text)
        .arg("__conformance")
        .arg("probe")
        .arg(json)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = cmd.spawn()?;
    drop(child_end);
    drop(memfd);
    Ok((child, parent_end))
}

fn wait_pollin(fd: i32, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: poll on one descriptor we own.
    unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
}

/// Owns the `__init` child and its process group: any early return kills and
/// reaps it (review item 4). `disarm` hands the child to the normal wait.
struct InitChild {
    child: Option<Child>,
    pid: i32,
}

impl InitChild {
    fn disarm(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for InitChild {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // SAFETY: kill the process group this module created.
            unsafe { libc::kill(-self.pid, libc::SIGKILL) };
            let _ = c.wait();
        }
    }
}

fn run_one(exe: &Path, exe_text: &str, gone: bool) -> Result<InitRun, String> {
    let (child, parent) =
        spawn_init(exe, exe_text, gone).map_err(|e| format!("cannot spawn sbx __init: {e}"))?;
    let pid = child.id() as i32;
    let mut guard = InitChild {
        child: Some(child),
        pid,
    };
    let stdout_handle = guard.child.as_mut().and_then(|c| c.stdout.take());
    let stderr_handle = guard.child.as_mut().and_then(|c| c.stderr.take());
    let out_thread = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut o) = stdout_handle {
            let _ = o.read_to_string(&mut s);
        }
        s
    });
    let err_thread = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut e) = stderr_handle {
            let _ = e.read_to_string(&mut s);
        }
        s
    });
    if !wait_pollin(parent.as_raw_fd(), Duration::from_secs(10)) {
        return Err("sbx __init did not hand over its listeners within 10 s".to_owned());
    }
    let fds = fdpass::recv_listener_fds(parent.as_raw_fd())
        .map_err(|e| format!("receiving listener fds: {e}"))?;
    let accepts = if gone {
        drop(fds);
        0
    } else {
        let t = fds.transparent;
        t.set_nonblocking(true)
            .map_err(|e| format!("listener mode: {e}"))?;
        // Early exit (review item 3): stop at the first accepted connection plus a
        // short grace for a second one; the control expects exactly one.
        let count = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            let mut n = 0u32;
            let mut first: Option<Instant> = None;
            while Instant::now() < until {
                match t.accept() {
                    Ok((s, _)) => {
                        n += 1;
                        first.get_or_insert_with(Instant::now);
                        let _ = s.shutdown(Shutdown::Both);
                    }
                    Err(_) => {
                        if first.is_some_and(|f| f.elapsed() > Duration::from_millis(300)) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
            n
        });
        fdpass::send_go(parent.as_raw_fd()).map_err(|e| format!("sending go: {e}"))?;
        let n = count.join().unwrap_or(0);
        let mut child = guard.disarm().ok_or("child already taken")?;
        return finish(&mut child, out_thread, err_thread, pid, n);
    };
    fdpass::send_go(parent.as_raw_fd()).map_err(|e| format!("sending go: {e}"))?;
    let mut child = guard.disarm().ok_or("child already taken")?;
    finish(&mut child, out_thread, err_thread, pid, accepts)
}

fn finish(
    child: &mut Child,
    out: std::thread::JoinHandle<String>,
    err: std::thread::JoinHandle<String>,
    pid: i32,
    accepts: u32,
) -> Result<InitRun, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            // SAFETY: kill the group we created.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout_text = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    Ok(InitRun {
        stdout: stdout_text.lines().map(str::to_owned).collect(),
        stderr,
        rc: status.and_then(|s| s.code()),
        accepts,
    })
}

/// F03 as one check result.
pub fn f03(exe: &Path, exe_text: &str) -> CheckResult {
    let id = "F03";
    let control = match run_one(exe, exe_text, false) {
        Ok(r) => r,
        Err(e) => return CheckResult::skip(id, super::report::SkipKind::Capability, e),
    };
    let control_probe = ProbeOutput::parse(&control.stdout, false);
    let control_ok = match &control_probe {
        Ok(p) => p
            .get("f03.control")
            .is_some_and(|r| r.data["connected"] == true),
        Err(_) => false,
    };
    if control.accepts != 1 || !control_ok {
        let why = format!(
            "control failed: the transparent listener accepted {} connections, probe connected={}",
            control.accepts, control_ok
        );
        return CheckResult::new(id, Status::Fail, why);
    }
    let gone = match run_one(exe, exe_text, true) {
        Ok(r) => r,
        Err(e) => return CheckResult::skip(id, super::report::SkipKind::Capability, e),
    };
    let probe = match ProbeOutput::parse(&gone.stdout, false) {
        Ok(p) => p,
        Err(e) => {
            return CheckResult::new(
                id,
                Status::Fail,
                format!(
                    "the gone run's probe did not complete: {e} (rc {:?}, stderr {:?})",
                    gone.rc,
                    gone.stderr.lines().next().unwrap_or("")
                ),
            );
        }
    };
    let get = |k: &str| probe.get(k).cloned();
    let mut bad: Vec<String> = Vec::new();
    for k in ["f03.tcp1111", "f03.tcp15001", "f03.tcp3128"] {
        match get(k) {
            Some(r) if !r.ok && r.errno == Some(libc::ECONNREFUSED) => {}
            Some(r) => bad.push(format!("{k}: expected ECONNREFUSED, got {:?}", r.errno)),
            None => bad.push(format!("{k}: missing")),
        }
    }
    match get("f03.udp53") {
        Some(r) if r.data["recv_errno"] == libc::ECONNREFUSED => {}
        Some(r) => bad.push(format!("f03.udp53: expected ECONNREFUSED, got {}", r.data)),
        None => bad.push("f03.udp53: missing".to_owned()),
    }
    match get("f03.udp123") {
        Some(r) if r.data["send_errno"] == libc::EPERM => {}
        Some(r) => bad.push(format!("f03.udp123: expected EPERM, got {}", r.data)),
        None => bad.push("f03.udp123: missing".to_owned()),
    }
    match get("f03.links") {
        Some(r) if r.data["names"] == serde_json::json!(["lo"]) => {}
        Some(r) => bad.push(format!("links: expected [\"lo\"], got {}", r.data["names"])),
        None => bad.push("f03.links: missing".to_owned()),
    }
    if let Some(first) = bad.first().cloned() {
        return CheckResult::new(id, Status::Fail, first).with_evidence(bad.into_iter().skip(1));
    }
    CheckResult::new(
        id,
        Status::Ok,
        "with the proxy gone every egress path is refused (control accepted 1 connection)",
    )
}
