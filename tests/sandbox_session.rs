//! Persistent-session integration tests (issue #18): `sbx run --keep-alive`,
//! `sbx attach` and `sbx stop`, driven through the real binary.
//!
//! These tests run the sbx lifecycle (holder, control socket, attach handshake,
//! namespace join with nftables re-verification, call exit rows, stop, idle and
//! max-lifetime ends, holder SIGKILL) with `SBX_BWRAP` pointed at a small shell
//! shim that `exec`s the command after `--` instead of starting a bwrap
//! sandbox. They therefore prove the session machinery, not the isolation: the
//! pid-namespace and foreign-uid properties need the real bwrap and are checked
//! by the CI tier (`sbx check --conformance` on a bwrap host), not here.
//!
//! Each test SKIPs with a message when unprivileged user namespaces are not
//! available (the namespace join and the `__init` pipeline need them).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const SBX: &str = env!("CARGO_BIN_EXE_sbx");

/// Unique scratch directory for one test (no symlinks, mode 0700).
fn scratch(tag: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sbx-session-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("scratch dir");
    dir
}

/// The shim that stands in for bwrap: `--version` reports 0.9.0, and everything
/// after `--` is `exec`ed in place (no namespaces of its own).
fn write_shim(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let shim = dir.join("bwrap-shim");
    fs::write(
        &shim,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then echo \"bubblewrap 0.9.0\"; exit 0; fi\n\
         while [ $# -gt 0 ]; do\n\
           if [ \"$1\" = \"--\" ]; then shift; exec \"$@\"; fi\n\
           shift\n\
         done\n\
         exit 2\n",
    )
    .expect("write shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod shim");
    shim
}

/// Skips (returns false) when this host cannot create user namespaces.
fn namespaces_available() -> bool {
    let ok = Command::new("unshare")
        .args(["-Urn", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: unprivileged user namespaces are unavailable on this host");
    }
    ok
}

fn policy_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/default.json")
}

/// An sbx command with the shim as its bwrap.
fn sbx(shim: &Path) -> Command {
    let mut cmd = Command::new(SBX);
    cmd.env("SBX_BWRAP", shim);
    cmd
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

/// Starts a holder and waits for the launcher's readiness (rc 0).
fn keep_alive(shim: &Path, session: &Path, extra: &[&str], resident: &[&str]) -> Output {
    let mut cmd = sbx(shim);
    cmd.args(["run", "--keep-alive", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(session)
        .args(extra)
        .arg("--")
        .args(resident);
    cmd.output().expect("run sbx --keep-alive")
}

/// `sbx attach` with the default policy and the given command.
fn attach(shim: &Path, session: &Path, extra: &[&str], cmd_args: &[&str]) -> Output {
    let mut cmd = sbx(shim);
    cmd.args(["attach", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(session)
        .args(extra)
        .arg("--")
        .args(cmd_args);
    cmd.output().expect("run sbx attach")
}

fn stop(shim: &Path, session: &Path) -> Output {
    sbx(shim)
        .args(["stop", "--session-dir"])
        .arg(session)
        .output()
        .expect("run sbx stop")
}

/// Polls `check` until it is true or `limit` passes.
fn wait_until(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}

/// Whether `pid` is alive (a zombie counts as gone).
fn alive(pid: i32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            // The state is the first field after the parenthesised command name.
            let after = stat.rsplit(')').next().unwrap_or("").trim_start();
            !after.starts_with('Z')
        }
        Err(_) => false,
    }
}

fn read_pid(path: &Path) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Waits for the holder's control socket to disappear (the session has ended).
fn session_ended(session: &Path, limit: Duration) -> bool {
    wait_until(limit, || !session.join("sbx.ctl").exists())
}

fn skip_or(shim_dir: &Path, name: &str) -> Option<PathBuf> {
    if !namespaces_available() {
        let _ = fs::remove_dir_all(shim_dir);
        eprintln!("SKIP {name}");
        return None;
    }
    Some(write_shim(shim_dir))
}

#[test]
fn attach_runs_in_the_resident_network_namespace_and_passes_rc() {
    let dir = scratch("join");
    let Some(shim) = skip_or(&dir, "attach-joins-resident-netns") else {
        return;
    };
    let session = dir.join("s");
    let resident_ns = dir.join("resident-ns");
    let call_ns = dir.join("call-ns");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &[
            "sh",
            "-c",
            &format!(
                "readlink /proc/self/ns/net > {}; exec sleep 300",
                resident_ns.display()
            ),
        ],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(wait_until(Duration::from_secs(5), || resident_ns.exists()));

    let out = attach(
        &shim,
        &session,
        &[],
        &[
            "sh",
            "-c",
            &format!("readlink /proc/self/ns/net > {}; exit 7", call_ns.display()),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "the call's own rc: {}",
        text(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(&resident_ns).unwrap(),
        fs::read_to_string(&call_ns).unwrap(),
        "the call shares the resident's network namespace"
    );
    assert!(stop(&shim, &session).status.success());
    assert!(session_ended(&session, Duration::from_secs(10)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attach_with_a_different_policy_is_refused_rc_125() {
    let dir = scratch("mismatch");
    let Some(shim) = skip_or(&dir, "attach-policy-mismatch-125") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));

    let other = dir.join("other.json");
    let mut bytes = fs::read(policy_path()).unwrap();
    bytes.push(b'\n'); // one byte of difference: the pin is exact bytes
    fs::write(&other, bytes).unwrap();
    let out = sbx(&shim)
        .args(["attach", "--policy"])
        .arg(&other)
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("policy differs from the session's policy"),
        "{}",
        text(&out.stderr)
    );
    assert!(stop(&shim, &session).status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attach_without_a_session_is_refused_rc_125() {
    let dir = scratch("nosession");
    let Some(shim) = skip_or(&dir, "attach-no-session-125") else {
        return;
    };
    let out = attach(&shim, &dir.join("missing"), &[], &["true"]);
    assert_eq!(out.status.code(), Some(125));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stop_is_idempotent_and_removes_the_control_socket() {
    let dir = scratch("stop");
    let Some(shim) = skip_or(&dir, "stop-idempotent") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(stop(&shim, &session).status.success(), "first stop");
    assert!(
        !session.join("sbx.ctl").exists(),
        "the control socket is gone at stop's return"
    );
    assert!(
        stop(&shim, &session).status.success(),
        "second stop is rc 0"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attached_call_is_killed_by_its_timeout_with_rc_124() {
    let dir = scratch("timeout");
    let Some(shim) = skip_or(&dir, "attach-timeout-124") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    let started = Instant::now();
    let out = attach(&shim, &session, &["--timeout", "1s"], &["sleep", "300"]);
    assert_eq!(out.status.code(), Some(124), "{}", text(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(30));
    assert!(stop(&shim, &session).status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn holder_sigkill_kills_the_resident_and_the_attached_call() {
    let dir = scratch("sigkill");
    let Some(shim) = skip_or(&dir, "holder-sigkill-kills-all") else {
        return;
    };
    let session = dir.join("s");
    let resident_pid = dir.join("resident-pid");
    let holder_pid = dir.join("holder-pid");
    let call_pid = dir.join("call-pid");
    // $PPID of the resident's shell is the holder (the chain execs in place).
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &[
            "sh",
            "-c",
            &format!(
                "echo $$ > {}; echo $PPID > {}; exec sleep 300",
                resident_pid.display(),
                holder_pid.display()
            ),
        ],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(wait_until(Duration::from_secs(5), || holder_pid.exists()));

    let mut attach_child = sbx(&shim)
        .args(["attach", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "sh", "-c"])
        .arg(format!("echo $$ > {}; exec sleep 300", call_pid.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn attach");
    assert!(wait_until(Duration::from_secs(10), || call_pid.exists()));
    let res = read_pid(&resident_pid).expect("resident pid");
    let holder = read_pid(&holder_pid).expect("holder pid");
    let call = read_pid(&call_pid).expect("call pid");
    assert!(alive(res) && alive(call));

    unsafe {
        libc::kill(holder, libc::SIGKILL);
    }
    assert!(
        wait_until(Duration::from_secs(10), || !alive(res)),
        "the resident died with the holder"
    );
    assert!(
        wait_until(Duration::from_secs(10), || !alive(call)),
        "the attached call died with the holder"
    );
    let status = attach_child.wait().expect("attach exits");
    assert_eq!(status.code(), Some(125), "attach reports the holder's exit");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn idle_timeout_ends_the_session() {
    let dir = scratch("idle");
    let Some(shim) = skip_or(&dir, "idle-timeout-ends-session") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "2s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(
        session_ended(&session, Duration::from_secs(15)),
        "idle end removes sbx.ctl"
    );
    let log = fs::read_to_string(session.join("holder.log")).unwrap_or_default();
    assert!(log.contains("timed out after 2s"), "{log}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn max_lifetime_ends_the_session_even_with_activity() {
    let dir = scratch("maxlife");
    let Some(shim) = skip_or(&dir, "max-lifetime-ends-session") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s", "--max-lifetime", "2s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(
        session_ended(&session, Duration::from_secs(15)),
        "max lifetime removes sbx.ctl"
    );
    let log = fs::read_to_string(session.join("holder.log")).unwrap_or_default();
    assert!(log.contains("timed out after 2s"), "{log}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resident_exit_ends_the_session() {
    let dir = scratch("resident-exit");
    let Some(shim) = skip_or(&dir, "resident-exit-ends-session") else {
        return;
    };
    let session = dir.join("s");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &["sh", "-c", "exit 0"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    assert!(session_ended(&session, Duration::from_secs(15)));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn max_lifetime_above_24h_is_a_usage_error() {
    let dir = scratch("cap");
    let Some(shim) = skip_or(&dir, "max-lifetime-cap-rc2") else {
        return;
    };
    let out = sbx(&shim)
        .args(["run", "--keep-alive", "--max-lifetime", "25h", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(dir.join("s"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(!dir.join("s").join("sbx.ctl").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn audit_rows_carry_call_ids() {
    let dir = scratch("audit");
    let Some(shim) = skip_or(&dir, "audit-call-ids") else {
        return;
    };
    let session = dir.join("s");
    let audit = dir.join("audit.jsonl");
    let out = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s", "--audit", audit.to_str().unwrap()],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    let out = attach(&shim, &session, &[], &["sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    assert!(stop(&shim, &session).status.success());
    assert!(session_ended(&session, Duration::from_secs(10)));

    let rows: Vec<serde_json::Value> = fs::read_to_string(&audit)
        .expect("audit file")
        .lines()
        .map(|l| serde_json::from_str(l).expect("row is JSON"))
        .collect();
    let exits: Vec<&serde_json::Value> = rows.iter().filter(|r| r["event"] == "exit").collect();
    assert_eq!(
        exits.len(),
        2,
        "one exit row per call and one for the resident: {rows:?}"
    );
    let call = exits
        .iter()
        .find(|r| r["call_id"] == 1)
        .expect("call 1 row");
    assert_eq!(call["code"], 7);
    assert_eq!(call["outcome"], "exited");
    let resident = exits
        .iter()
        .find(|r| r["call_id"] == 0)
        .expect("resident row");
    assert_eq!(
        resident["outcome"], "terminated",
        "stop ends the resident as terminated"
    );
    assert!(
        exits.last().is_some_and(|r| r["call_id"] == 0),
        "the resident exit row is last"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn keep_alive_refuses_a_non_transparent_policy_at_startup_rc125() {
    // No bwrap is needed: the refusal happens before anything is spawned.
    let dir = scratch("explicit");
    let policy = dir.join("explicit.json");
    let body = fs::read_to_string(policy_path())
        .unwrap()
        .replace("\"transparent\"", "\"explicit\"");
    fs::write(&policy, body).unwrap();
    let session = dir.join("s");
    let out = Command::new(SBX)
        .args(["run", "--keep-alive", "--policy"])
        .arg(&policy)
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("--keep-alive needs network mode transparent"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        !session.join("sbx.ctl").exists(),
        "no control socket for a refused session"
    );
    let _ = fs::remove_dir_all(&dir);
}
