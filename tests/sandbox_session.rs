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

/// More than 256 `--landlock-bind-tcp` ports with `--keep-alive` is refused at
/// argument validation: rc 2, the limit named, and no session directory made.
/// Nothing runs, so this needs no user namespace and no shim.
#[test]
fn keep_alive_refuses_more_than_256_bind_ports_rc2() {
    let dir = scratch("bind-cap");
    let mut cmd = Command::new(SBX);
    cmd.args([
        "run",
        "--keep-alive",
        "--landlock",
        "best-effort",
        "--policy",
    ])
    .arg(policy_path())
    .arg("--session-dir")
    .arg(dir.join("s"));
    for port in 1..=257u32 {
        cmd.arg("--landlock-bind-tcp").arg(port.to_string());
    }
    let out = cmd.args(["--", "true"]).output().expect("run sbx");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(
            "--keep-alive takes at most 256 --landlock-bind-tcp ports (this run names 257)"
        ),
        "{stderr}"
    );
    assert!(!dir.join("s").exists(), "no session directory is made");
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
    assert_eq!(
        call["output_truncated"], false,
        "the call's truncation flag reaches the row"
    );
    assert!(
        call["reason"].is_string(),
        "the call's reason reaches the row: {call}"
    );
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

#[test]
fn stop_returns_after_the_exit_row_is_written_and_the_lock_released() {
    // Review 2: `sbx stop` is answered only after the resident's exit row is in the
    // audit file and the session directory is free. Both are checked with no wait.
    let dir = scratch("stop-order");
    let Some(shim) = skip_or(&dir, "stop-returns-after-exit-row") else {
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
    assert!(stop(&shim, &session).status.success());

    let rows = fs::read_to_string(&audit).expect("audit file");
    let last: serde_json::Value =
        serde_json::from_str(rows.lines().last().expect("a row")).expect("JSON");
    assert_eq!(
        last["event"], "exit",
        "the exit row is already written: {rows}"
    );
    assert_eq!(
        last["call_id"], 0,
        "the resident's exit row carries call_id 0"
    );

    // The lock is free and the socket is gone: a new holder starts at once.
    let again = keep_alive(
        &shim,
        &session,
        &["--idle-timeout", "60s"],
        &["sleep", "300"],
    );
    assert!(
        again.status.success(),
        "a new session on the same dir: {}",
        text(&again.stderr)
    );
    assert!(stop(&shim, &session).status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attach_refuses_a_call_after_a_symlink_is_planted_under_a_writable_bind() {
    // S8a on every attach call: a payload can plant a link in a writable tree
    // after the resident started. The attach's guard refuses the call (rc 125)
    // instead of building its bwrap argv from the planted link.
    let dir = scratch("plant");
    let Some(shim) = skip_or(&dir, "attach-guard-after-planted-link") else {
        return;
    };
    let tree = dir.join("tree");
    let deny = tree.join("sub");
    fs::create_dir_all(&deny).unwrap();
    fs::create_dir_all(tree.join("other")).unwrap();
    let policy = dir.join("policy.json");
    fs::write(
        &policy,
        format!(
            "{{\"version\":1,\"filesystem\":{{\"ro\":[\"/usr\"],\"rw\":[{:?}],\"deny\":[{:?}]}},\"network\":{{\"mode\":\"transparent\",\"allow\":[\"pypi.org\"],\"ports\":[443,80]}},\"env\":{{\"pass\":[],\"set\":{{}}}},\"limits\":{{\"timeout\":\"30s\",\"output_bytes\":1048576}}}}",
            tree.display().to_string(),
            deny.display().to_string()
        ),
    )
    .unwrap();
    let session = dir.join("s");
    let out = sbx(&shim)
        .args(["run", "--keep-alive", "--idle-timeout", "60s", "--policy"])
        .arg(&policy)
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "sleep", "300"])
        .output()
        .unwrap();
    assert!(out.status.success(), "launch: {}", text(&out.stderr));

    // The planted link: the denied subdirectory becomes a symlink to a sibling.
    fs::remove_dir(&deny).unwrap();
    std::os::unix::fs::symlink(tree.join("other"), &deny).unwrap();

    // The same policy file as the session's, so the attach is admitted; only the guard refuses.
    let out = sbx(&shim)
        .args(["attach", "--policy"])
        .arg(&policy)
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "true"])
        .output()
        .unwrap();
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(125), "{err}");
    assert!(err.contains("sbx attach:"), "{err}");
    assert!(
        err.contains("unsafe filesystem path") && err.contains("symbolic link"),
        "{err}"
    );
    assert!(stop(&shim, &session).status.success());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_holder_does_not_keep_descriptors_inherited_from_its_caller() {
    // Review 9: the caller's descriptors above stdio are not the session's to keep.
    // A descriptor planted at 900 is not in the holder's table after the launch.
    let dir = scratch("inherit");
    let Some(shim) = skip_or(&dir, "holder-closes-inherited-fds") else {
        return;
    };
    use std::os::unix::process::CommandExt;
    let session = dir.join("s");
    let null = std::fs::File::open("/dev/null").unwrap();
    let src = std::os::fd::AsRawFd::as_raw_fd(&null);
    let mut cmd = sbx(&shim);
    cmd.args(["run", "--keep-alive", "--idle-timeout", "60s", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "sleep", "300"]);
    // SAFETY: dup2 is async-signal-safe; it runs in the child before exec.
    unsafe {
        cmd.pre_exec(move || {
            libc::dup2(src, 900);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    let want = session.to_string_lossy().into_owned();
    let holder =
        wait_for(Duration::from_secs(5), || holder_of(&want)).expect("the holder is running");
    assert!(
        !Path::new(&format!("/proc/{holder}/fd/900")).exists(),
        "the holder kept the caller's descriptor 900"
    );
    assert!(stop(&shim, &session).status.success());
    let _ = fs::remove_dir_all(&dir);
}

/// The `run --keep-alive` process that names `session` (the holder, not the launcher).
fn holder_of(session: &str) -> Option<i32> {
    fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .find(|pid| {
            fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| {
                let args: Vec<&[u8]> = c.split(|b| *b == 0).collect();
                args.iter().any(|a| *a == b"--keep-alive") && args.contains(&session.as_bytes())
            })
        })
}

/// Polls `f` until it yields a value or `limit` passes.
fn wait_for<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let until = Instant::now() + limit;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn attached_call_runs_under_the_session_landlock_layer() {
    // The session's Landlock layer (issue #56 with #18) applies to every call,
    // not only to the resident. Its signal scope lets a sandboxed process signal
    // only processes in its own domain, so a call cannot signal the resident
    // (another domain). The control is the same session without the layer, where
    // the same signal goes through. Needs Landlock ABI 6 (Linux 6.12+); skips
    // elsewhere.
    if !landlock_abi_six() {
        eprintln!("SKIP attach-landlock-signal-scope: the kernel lacks Landlock ABI 6");
        return;
    }
    let dir = scratch("landlock");
    let Some(shim) = skip_or(&dir, "attach-landlock-signal-scope") else {
        return;
    };
    let kill_probe = |pid: &Path, session: &Path, landlock: &[&str]| -> Option<i32> {
        let mut cmd = sbx(&shim);
        cmd.args(["run", "--keep-alive", "--idle-timeout", "60s"]);
        cmd.args(landlock);
        cmd.args(["--policy"])
            .arg(policy_path())
            .arg("--session-dir")
            .arg(session)
            .args(["--", "sh", "-c"])
            .arg(format!("echo $$ > {}; exec sleep 300", pid.display()));
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "launch: {}", text(&out.stderr));
        assert!(wait_until(Duration::from_secs(5), || pid.exists()));
        let resident = read_pid(pid).expect("resident pid");
        let probe = attach(
            &shim,
            session,
            &[],
            &[
                "sh",
                "-c",
                &format!("kill -0 {resident} 2>/dev/null; echo $?"),
            ],
        );
        assert_eq!(
            probe.status.code(),
            Some(0),
            "the probe ran: {}",
            text(&probe.stderr)
        );
        let rc = text(&probe.stdout).trim().parse::<i32>().ok();
        assert!(stop(&shim, session).status.success());
        rc
    };
    let plain = kill_probe(&dir.join("plain-pid"), &dir.join("plain"), &[]);
    assert_eq!(
        plain,
        Some(0),
        "control: without the layer the call signals the resident"
    );
    let scoped = kill_probe(
        &dir.join("scoped-pid"),
        &dir.join("scoped"),
        &["--landlock", "require"],
    );
    assert_ne!(
        scoped,
        Some(0),
        "under the session's signal scope the call cannot signal the resident"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attach_has_no_landlock_flags_of_its_own() {
    // A call takes the session's Landlock settings; it cannot ask for its own, so
    // attach refuses the flag (a usage error, rc 2) rather than weakening anything.
    let dir = scratch("attach-flag");
    let Some(shim) = skip_or(&dir, "attach-rejects-landlock-flags") else {
        return;
    };
    let out = sbx(&shim)
        .args(["attach", "--landlock", "off", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(dir.join("s"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let _ = fs::remove_dir_all(&dir);
}

/// Whether the running kernel reports Landlock ABI 6 or later (`sbx check`'s own probe).
fn landlock_abi_six() -> bool {
    let out = Command::new(SBX).args(["check", "--json"]).output();
    let Ok(out) = out else {
        return false;
    };
    let v: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v["checks"].as_array().into_iter().flatten().any(|c| {
        c["id"] == "landlock"
            && c["status"] == "ok"
            && c["detail"].as_str().is_some_and(|d| d.contains("ABI"))
    }) && landlock_ge_6(&v)
}

fn landlock_ge_6(v: &serde_json::Value) -> bool {
    v["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["id"] == "landlock")
        .filter_map(|c| c["detail"].as_str())
        .filter_map(|d| {
            d.split("ABI ")
                .nth(1)?
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse::<u32>()
                .ok()
        })
        .any(|abi| abi >= 6)
}

#[test]
fn holder_kill_paths_work_under_the_session_landlock_layer() {
    // Review item of #18 with #56: the signal scope confines the sandboxed
    // processes, not the holder or the attach (which sit outside every domain). So
    // the holder still ends an attached call on stop (SIGTERM through the attach's
    // pidfd) and a holder SIGKILL still ends the resident and the call. Needs ABI 6.
    if !landlock_abi_six() {
        eprintln!("SKIP holder-kill-under-landlock: the kernel lacks Landlock ABI 6");
        return;
    }
    let dir = scratch("landlock-kill");
    let Some(shim) = skip_or(&dir, "holder-kill-under-landlock") else {
        return;
    };
    // Stop with a call in flight: the call ends by the holder's teardown (143).
    let session = dir.join("stop");
    let mut cmd = sbx(&shim);
    cmd.args([
        "run",
        "--keep-alive",
        "--idle-timeout",
        "60s",
        "--landlock",
        "require",
        "--policy",
    ])
    .arg(policy_path())
    .arg("--session-dir")
    .arg(&session)
    .args(["--", "sleep", "300"]);
    assert!(cmd.output().unwrap().status.success());
    let mut call = sbx(&shim)
        .args(["attach", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "sleep", "300"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(stop(&shim, &session).status.success());
    let rc = call.wait().unwrap().code();
    assert_eq!(
        rc,
        Some(143),
        "the holder's stop ended the call under the layer"
    );

    // Holder SIGKILL: the resident and the call both die.
    let session = dir.join("kill");
    let resident = dir.join("kill-resident-pid");
    let holder = dir.join("kill-holder-pid");
    let mut cmd = sbx(&shim);
    cmd.args([
        "run",
        "--keep-alive",
        "--idle-timeout",
        "60s",
        "--landlock",
        "require",
        "--policy",
    ])
    .arg(policy_path())
    .arg("--session-dir")
    .arg(&session)
    .args(["--", "sh", "-c"])
    .arg(format!(
        "echo $$ > {}; echo $PPID > {}; exec sleep 300",
        resident.display(),
        holder.display()
    ));
    assert!(cmd.output().unwrap().status.success());
    assert!(wait_until(Duration::from_secs(5), || holder.exists()));
    let mut call = sbx(&shim)
        .args(["attach", "--policy"])
        .arg(policy_path())
        .arg("--session-dir")
        .arg(&session)
        .args(["--", "sleep", "300"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let res = read_pid(&resident).expect("resident pid");
    let hold = read_pid(&holder).expect("holder pid");
    unsafe {
        libc::kill(hold, libc::SIGKILL);
    }
    assert!(
        wait_until(Duration::from_secs(10), || !alive(res)),
        "the resident died with the holder"
    );
    let call_rc = call.wait().unwrap().code();
    assert_eq!(
        call_rc,
        Some(125),
        "the attach reports the holder's death under the layer"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Issue #73: the resident's `filesystem.protect` placeholders live as long as
/// the session. An attached call binds the holder's saved list and creates or
/// removes nothing; `sbx stop` returns after the placeholders, the placeholder
/// list and the saved list are gone. (The shim runs no bwrap, so this pins the
/// lifecycle, not the read-only binds: `tests/sandbox_run.rs`
/// `protect-attach-blocked` covers those for attach calls.)
#[test]
fn protect_placeholders_live_with_the_session() {
    let dir = scratch("protect");
    let Some(shim) = skip_or(&dir, "protect-placeholders-session") else {
        return;
    };
    let proj = dir.join("proj");
    fs::create_dir_all(proj.join(".git/hooks")).expect("proj");
    let policy = dir.join("policy.json");
    fs::write(
        &policy,
        format!(
            r#"{{"version":1,"filesystem":{{"ro":["/usr"],"rw":[{:?}],"deny":[]}},"network":{{"mode":"transparent","allow":[],"ports":[443]}},"env":{{"pass":[],"set":{{}}}},"limits":{{"timeout":"60s","output_bytes":65536}}}}"#,
            proj.display().to_string()
        ),
    )
    .expect("policy");
    let session = dir.join("s");
    let with_policy = |sub: &str, extra: &[&str], cmd: &[&str]| {
        let mut c = sbx(&shim);
        c.arg(sub)
            .arg("--policy")
            .arg(&policy)
            .arg("--session-dir")
            .arg(&session)
            .args(extra)
            .arg("--")
            .args(cmd);
        c.output().expect("run sbx")
    };
    let out = with_policy(
        "run",
        &["--keep-alive", "--idle-timeout", "60s"],
        &["sleep", "300"],
    );
    assert!(out.status.success(), "launch: {}", text(&out.stderr));
    let placeholder = proj.join(".bashrc");
    assert!(
        placeholder.is_dir(),
        "the resident created the placeholders"
    );
    assert!(session.join("protect.list").exists(), "and listed them");
    assert!(
        session.join("protect.paths").exists(),
        "the holder saved its protected paths for attach calls"
    );
    let call = with_policy("attach", &[], &["true"]);
    assert!(call.status.success(), "attach: {}", text(&call.stderr));
    assert!(
        placeholder.is_dir(),
        "an attached call leaves the resident's placeholders in place"
    );
    assert!(stop(&shim, &session).status.success(), "stop");
    assert!(!placeholder.exists(), "stop removed the placeholders");
    assert!(!proj.join(".vscode").exists());
    assert!(!session.join("protect.list").exists());
    assert!(!session.join("protect.paths").exists());
    let names: Vec<String> = fs::read_dir(&proj)
        .expect("read proj")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [".git"], "nothing else is left in the rw tree");
    let _ = fs::remove_dir_all(&dir);
}
