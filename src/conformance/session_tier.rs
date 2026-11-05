//! Group I, the persistent-session checks (issue #18, design point 9).
//!
//! Each scenario drives the real `sbx` binary (`run --keep-alive`, `attach`,
//! `stop`) with the host's bwrap. Nothing is shimmed: a check that needs bwrap
//! is gated like every other host check, so on a host without bwrap the group
//! is a capability skip, never a pass.
//!
//! Rules that follow the host tier:
//! * Controls come first in every evaluator. A control records that the
//!   observed thing was really there before the assertion ran (the resident
//!   and the call were alive, the attach was admitted, the session was up). A
//!   missing control is a control failure, never a pass.
//! * Process identity is exact: a process is found by its full argv, so the
//!   bwrap parent, the holder and the attach are never mistaken for the
//!   resident or the call.
//! * I04 (foreign-uid refusal) cannot run without a second uid. An
//!   unprivileged user namespace maps one uid, so the connection cannot come
//!   from another uid. It is an opt-in skip (rc 0), not a pass.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::host_tier::{F, R, Scns, ctl_fail, fail, sc};
use super::policies::{self, Builtin};
use super::report::{CheckResult, SkipKind};
use super::scenarios::{Env, Scn};
use crate::host::Status;

/// The scenario names of the group (each is one evidence bundle).
pub const SCENARIOS: [&str; 5] = ["SS-pid", "SS-kill", "SS-policy", "SS-idle", "SS-life"];

/// The group's check ids, in catalog order.
pub const IDS: [&str; 6] = ["I01", "I02", "I03", "I04", "I05", "I06"];

/// Whether this module evaluates `id`.
pub fn handles(id: &str) -> bool {
    IDS.contains(&id)
}

/// The scenario set an id reads (empty for I04, which is never run).
pub fn scenarios_of(id: &str) -> &'static [&'static str] {
    match id {
        "I01" => &["SS-pid"],
        "I02" => &["SS-kill"],
        "I03" => &["SS-policy"],
        "I05" => &["SS-idle"],
        "I06" => &["SS-life"],
        _ => &[],
    }
}

/// I04's result, produced without any scenario (see the module docs).
pub fn foreign_uid_skip() -> CheckResult {
    CheckResult::skip(
        "I04",
        SkipKind::OptIn,
        "needs a second uid on the host: an unprivileged user namespace maps one uid, so a connection from another uid cannot be made here (threat model S18)",
    )
}

/// The five scenarios, in one pass (the group is memoised by the runner).
pub fn run(env: &Env) -> Vec<Scn> {
    let base = env.base.join("session");
    if let Err(e) = fs::create_dir_all(&base) {
        return SCENARIOS
            .iter()
            .map(|n| Scn::unavailable(n, format!("cannot create the session base: {e}")))
            .collect();
    }
    let policy = match policies::write_policy(
        &base,
        "policy",
        &policies::policy_json(Builtin::Transparent, &env.exe_text, None),
    ) {
        Ok(p) => p,
        Err(e) => {
            return SCENARIOS
                .iter()
                .map(|n| Scn::unavailable(n, format!("cannot write policy: {e}")))
                .collect();
        }
    };
    let ctx = Ctx {
        exe: env.exe.clone(),
        base,
        policy,
    };
    vec![
        ctx.scenario("SS-pid", pid_isolation),
        ctx.scenario("SS-kill", holder_kill),
        ctx.scenario("SS-policy", policy_refusal),
        ctx.scenario("SS-idle", idle_end),
        ctx.scenario("SS-life", max_lifetime_end),
    ]
}

struct Ctx {
    exe: PathBuf,
    base: PathBuf,
    policy: PathBuf,
}

impl Ctx {
    fn scenario(&self, name: &'static str, body: fn(&Ctx, &'static str) -> Scn) -> Scn {
        let started = Instant::now();
        let mut scn = body(self, name);
        scn.ms = started.elapsed().as_millis() as u64;
        scn.name = name;
        scn
    }

    fn session(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    /// Starts a holder whose resident is `resident` (a session of `idle` idle).
    fn holder(&self, session: &Path, extra: &[&str], resident: &[&str]) -> Result<(), String> {
        let out = Command::new(&self.exe)
            .args(["run", "--keep-alive", "--policy"])
            .arg(&self.policy)
            .arg("--session-dir")
            .arg(session)
            .args(extra)
            .arg("--")
            .args(resident)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot spawn sbx run --keep-alive: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "sbx run --keep-alive rc {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Spawns an attach with a bounded call timeout (no call can outlive the check).
    fn attach_spawn(&self, session: &Path, policy: &Path, argv: &[&str]) -> Result<Child, String> {
        Command::new(&self.exe)
            .args(["attach", "--timeout", "60s", "--policy"])
            .arg(policy)
            .arg("--session-dir")
            .arg(session)
            .arg("--")
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot spawn sbx attach: {e}"))
    }

    fn attach_output(
        &self,
        session: &Path,
        policy: &Path,
        argv: &[&str],
    ) -> Result<Output, String> {
        Command::new(&self.exe)
            .args(["attach", "--timeout", "60s", "--policy"])
            .arg(policy)
            .arg("--session-dir")
            .arg(session)
            .arg("--")
            .args(argv)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run sbx attach: {e}"))
    }

    /// Ends a session and kills anything still running from it (best effort).
    fn cleanup(&self, session: &Path, pids: &[u32]) {
        let _ = Command::new(&self.exe)
            .args(["stop", "--session-dir"])
            .arg(session)
            .stdin(Stdio::null())
            .output();
        for p in pids {
            kill(*p, libc::SIGKILL);
        }
    }
}

/// Records one control result (`Ok` when it held).
fn note(scn: &mut Scn, key: &'static str, held: bool, why: &str) {
    scn.ctl
        .insert(key, if held { Ok(()) } else { Err(why.to_owned()) });
}

fn kill(pid: u32, sig: i32) {
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
}

/// Whether `pid` is alive (a zombie is gone).
fn alive(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let after = stat.rsplit(')').next().unwrap_or("").trim_start();
            !after.starts_with('Z')
        }
        Err(_) => false,
    }
}

fn cmdline(pid: u32) -> Option<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        bytes
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
    )
}

fn numeric_pids() -> Vec<u32> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// The pid whose full argv is exactly `argv` (polled for up to 10 s).
fn exact_pid(argv: &[&str]) -> Option<u32> {
    let want: Vec<&str> = argv.to_vec();
    poll(Duration::from_secs(10), || {
        numeric_pids().into_iter().find(|p| {
            cmdline(*p).is_some_and(|a| a.iter().map(String::as_str).eq(want.iter().copied()))
        })
    })
}

/// The holder of `session`: the `run --keep-alive` process naming that directory.
fn holder_pid(session: &Path) -> Option<u32> {
    let dir = session.to_string_lossy().into_owned();
    poll(Duration::from_secs(10), || {
        numeric_pids().into_iter().find(|p| {
            cmdline(*p).is_some_and(|a| a.iter().any(|x| x == "--keep-alive") && a.contains(&dir))
        })
    })
}

/// Polls `f` until it yields a value or `limit` passes.
fn poll<T>(limit: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
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

/// Waits until `cond` holds or `limit` passes; returns whether it held.
fn wait(limit: Duration, cond: impl Fn() -> bool) -> bool {
    poll(limit, || cond().then_some(())).is_some()
}

/// The child's exit within `limit`, else `None` (the child is then killed).
fn reap(child: &mut Child, limit: Duration) -> Option<i32> {
    let until = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().or(Some(128)),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn record_pid(scn: &mut Scn, key: &'static str, pid: Option<u32>) {
    if let Some(p) = pid {
        scn.nums.insert(key, p as u64);
    }
}

/// I01: a call cannot see or signal the resident or another call.
fn pid_isolation(ctx: &Ctx, name: &'static str) -> Scn {
    let mut scn = Scn::named(name);
    let session = ctx.session("pid");
    let res_argv = ["sleep", "3141592"];
    let b_argv = ["sleep", "2718281"];
    if let Err(e) = ctx.holder(&session, &["--idle-timeout", "120s"], &res_argv) {
        return Scn::unavailable(name, e);
    }
    let holder = holder_pid(&session);
    let res = exact_pid(&res_argv);
    let mut b_child = match ctx.attach_spawn(&session, &ctx.policy, &b_argv) {
        Ok(c) => c,
        Err(e) => {
            ctx.cleanup(&session, &[]);
            return Scn::unavailable(name, e);
        }
    };
    let b = exact_pid(&b_argv);
    record_pid(&mut scn, "resident", res);
    record_pid(&mut scn, "holder", holder);
    record_pid(&mut scn, "callb", b);
    note(
        &mut scn,
        "resident_alive",
        res.is_some_and(alive),
        "the resident was not running",
    );
    note(
        &mut scn,
        "callb_alive",
        b.is_some_and(alive),
        "the second call was not running",
    );

    // Call A: inside its own pid namespace it can see only its own processes.
    // The host pids of the resident and of call B are passed as numbers; a
    // number that names nothing in the call's namespace fails `kill -0`.
    let res_s = res.map(|p| p.to_string()).unwrap_or_else(|| "0".into());
    let b_s = b.map(|p| p.to_string()).unwrap_or_else(|| "0".into());
    let script = format!(
        "kill -0 $$ 2>/dev/null && echo SELF_SEEN; \
         n=0; for p in /proc/[0-9]*; do n=$((n+1)); done; echo PIDCOUNT=$n; \
         kill -0 {res_s} 2>/dev/null; echo RES_RC=$?; \
         kill -0 {b_s} 2>/dev/null; echo B_RC=$?"
    );
    let out = ctx.attach_output(&session, &ctx.policy, &["sh", "-c", &script]);
    let text = match &out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => String::new(),
    };
    scn.notes.insert("call_a", text.clone());
    if let Ok(o) = &out {
        scn.nums
            .insert("call_a_rc", o.status.code().unwrap_or(128) as u64);
    }
    let pidcount = text
        .lines()
        .find_map(|l| l.strip_prefix("PIDCOUNT=")?.parse::<u64>().ok());
    if let Some(n) = pidcount {
        scn.nums.insert("pidcount", n);
    }
    note(
        &mut scn,
        "call_a_ran",
        text.contains("SELF_SEEN"),
        "call A did not run its probe (SELF_SEEN missing)",
    );
    let _ = b_child.kill();
    let _ = b_child.wait();
    let pids: Vec<u32> = [holder, res, b].into_iter().flatten().collect();
    ctx.cleanup(&session, &pids);
    scn
}

/// I02: a SIGKILL of the holder kills the resident and the attached call.
fn holder_kill(ctx: &Ctx, name: &'static str) -> Scn {
    let mut scn = Scn::named(name);
    let session = ctx.session("kill");
    let res_argv = ["sleep", "3141593"];
    let b_argv = ["sleep", "2718282"];
    if let Err(e) = ctx.holder(&session, &["--idle-timeout", "120s"], &res_argv) {
        return Scn::unavailable(name, e);
    }
    let holder = holder_pid(&session);
    let res = exact_pid(&res_argv);
    let mut b_child = match ctx.attach_spawn(&session, &ctx.policy, &b_argv) {
        Ok(c) => c,
        Err(e) => {
            ctx.cleanup(&session, &[]);
            return Scn::unavailable(name, e);
        }
    };
    let b = exact_pid(&b_argv);
    let all_alive = holder.is_some_and(alive) && res.is_some_and(alive) && b.is_some_and(alive);
    note(
        &mut scn,
        "all_alive_before",
        all_alive,
        "holder, resident and call were not all running before the kill",
    );
    if let Some(h) = holder {
        kill(h, libc::SIGKILL);
    }
    let res_gone = res.is_some_and(|p| wait(Duration::from_secs(15), || !alive(p)));
    let b_gone = b.is_some_and(|p| wait(Duration::from_secs(15), || !alive(p)));
    scn.nums.insert("res_gone", u64::from(res_gone));
    scn.nums.insert("callb_gone", u64::from(b_gone));
    let attach_rc = reap(&mut b_child, Duration::from_secs(15));
    if let Some(rc) = attach_rc {
        scn.nums.insert("callb_attach_rc", rc as u64);
    }
    scn.nums.insert("resident_gone", u64::from(res_gone));
    let pids: Vec<u32> = [holder, res, b].into_iter().flatten().collect();
    ctx.cleanup(&session, &pids);
    scn
}

/// I03: attach with a different policy is refused (rc 125); the same policy is admitted.
fn policy_refusal(ctx: &Ctx, name: &'static str) -> Scn {
    let mut scn = Scn::named(name);
    let session = ctx.session("policy");
    if let Err(e) = ctx.holder(&session, &["--idle-timeout", "120s"], &["sleep", "3141594"]) {
        return Scn::unavailable(name, e);
    }
    let other = ctx.base.join("policy-other.json");
    let text = fs::read_to_string(&ctx.policy).unwrap_or_default();
    if fs::write(&other, format!("{text}\n")).is_err() {
        ctx.cleanup(&session, &[]);
        return Scn::unavailable(name, "cannot write the altered policy".to_owned());
    }
    let same = ctx.attach_output(&session, &ctx.policy, &["true"]);
    let diff = ctx.attach_output(&session, &other, &["true"]);
    match same {
        Ok(o) => {
            scn.nums
                .insert("same_rc", o.status.code().unwrap_or(128) as u64);
        }
        Err(e) => {
            ctx.cleanup(&session, &[]);
            return Scn::unavailable(name, e);
        }
    }
    if let Ok(o) = &diff {
        scn.nums
            .insert("diff_rc", o.status.code().unwrap_or(128) as u64);
        scn.notes.insert(
            "diff_stderr",
            String::from_utf8_lossy(&o.stderr).into_owned(),
        );
    }
    let holder = holder_pid(&session);
    ctx.cleanup(&session, &holder.into_iter().collect::<Vec<_>>());
    scn
}

/// I05: the idle timeout ends the session, and a running call holds it open.
fn idle_end(ctx: &Ctx, name: &'static str) -> Scn {
    let mut scn = Scn::named(name);
    let session = ctx.session("idle");
    if let Err(e) = ctx.holder(&session, &["--idle-timeout", "3s"], &["sleep", "3141595"]) {
        return Scn::unavailable(name, e);
    }
    let holder = holder_pid(&session);
    // A unique argv, so the call's host pid is found exactly.
    let call_argv = ["sleep", "5.00017"];
    let mut call = match ctx.attach_spawn(&session, &ctx.policy, &call_argv) {
        Ok(c) => c,
        Err(e) => {
            ctx.cleanup(&session, &holder.into_iter().collect::<Vec<_>>());
            return Scn::unavailable(name, e);
        }
    };
    let call_pid = exact_pid(&call_argv);
    record_pid(&mut scn, "call", call_pid);
    // Past the 3 s idle limit while the call runs: the call and the holder must
    // both still be up (the idle clock is suspended by the running call).
    std::thread::sleep(Duration::from_secs(4));
    note(
        &mut scn,
        "call_alive_while_idle_limit_passed",
        call_pid.is_some_and(alive),
        "the call was not running past the idle limit",
    );
    note(
        &mut scn,
        "held_while_call_runs",
        holder.is_some_and(alive),
        "the session ended while a call was running",
    );
    let attach_rc = reap(&mut call, Duration::from_secs(20));
    if let Some(rc) = attach_rc {
        scn.nums.insert("attach_rc", rc as u64);
    }
    let ended = wait(Duration::from_secs(15), || {
        !session.join("sbx.ctl").exists()
    });
    let gone = holder.is_some_and(|h| wait(Duration::from_secs(10), || !alive(h)));
    let call_gone = call_pid.is_some_and(|p| wait(Duration::from_secs(10), || !alive(p)));
    scn.nums.insert("ended", u64::from(ended));
    scn.nums.insert("holder_gone", u64::from(gone));
    scn.nums.insert("call_gone", u64::from(call_gone));
    ctx.cleanup(&session, &holder.into_iter().collect::<Vec<_>>());
    scn
}

/// I06: the max lifetime ends the session even while a call runs.
fn max_lifetime_end(ctx: &Ctx, name: &'static str) -> Scn {
    let mut scn = Scn::named(name);
    let session = ctx.session("life");
    if let Err(e) = ctx.holder(
        &session,
        &["--idle-timeout", "120s", "--max-lifetime", "3s"],
        &["sleep", "3141596"],
    ) {
        return Scn::unavailable(name, e);
    }
    let holder = holder_pid(&session);
    let call_argv = ["sleep", "60.00006"];
    let mut call = match ctx.attach_spawn(&session, &ctx.policy, &call_argv) {
        Ok(c) => c,
        Err(e) => {
            ctx.cleanup(&session, &holder.into_iter().collect::<Vec<_>>());
            return Scn::unavailable(name, e);
        }
    };
    let call_pid = exact_pid(&call_argv);
    record_pid(&mut scn, "call", call_pid);
    std::thread::sleep(Duration::from_millis(1500));
    note(
        &mut scn,
        "alive_before_max",
        holder.is_some_and(alive),
        "the session was not up before its max lifetime",
    );
    note(
        &mut scn,
        "call_alive_before_max",
        call_pid.is_some_and(alive),
        "the call was not running before the max lifetime",
    );
    let ended = wait(Duration::from_secs(15), || {
        !session.join("sbx.ctl").exists()
    });
    let gone = holder.is_some_and(|h| wait(Duration::from_secs(10), || !alive(h)));
    let call_gone = call_pid.is_some_and(|p| wait(Duration::from_secs(10), || !alive(p)));
    let attach_rc = reap(&mut call, Duration::from_secs(15));
    if let Some(rc) = attach_rc {
        scn.nums.insert("attach_rc", rc as u64);
    }
    scn.nums.insert("ended", u64::from(ended));
    scn.nums.insert("holder_gone", u64::from(gone));
    scn.nums.insert("call_gone", u64::from(call_gone));
    ctx.cleanup(&session, &holder.into_iter().collect::<Vec<_>>());
    scn
}

fn ctl_held(scn: &Scn, key: &'static str) -> Result<(), F> {
    match scn.ctl.get(key) {
        Some(Ok(())) => Ok(()),
        Some(Err(why)) => Err(ctl_fail(why.clone())),
        None => Err(ctl_fail(format!("{key} was not recorded"))),
    }
}

fn num(scn: &Scn, key: &'static str) -> Option<u64> {
    scn.nums.get(key).copied()
}

fn i01(s: &Scns) -> R {
    let scn = sc(s, "SS-pid")?;
    ctl_held(scn, "resident_alive")?;
    ctl_held(scn, "callb_alive")?;
    let call_a = scn.notes.get("call_a").cloned().unwrap_or_default();
    if !call_a.contains("SELF_SEEN") {
        return Err(ctl_fail("call A did not run its own probe"));
    }
    let pidcount =
        num(scn, "pidcount").ok_or_else(|| ctl_fail("call A did not report its process count"))?;
    if pidcount > 16 {
        return Err(fail(format!(
            "call A sees {pidcount} processes: its pid namespace is not its own"
        )));
    }
    let res_rc = call_a
        .lines()
        .find_map(|l| l.strip_prefix("RES_RC=")?.parse::<i32>().ok());
    let b_rc = call_a
        .lines()
        .find_map(|l| l.strip_prefix("B_RC=")?.parse::<i32>().ok());
    if res_rc == Some(0) {
        return Err(fail("call A signalled the resident's host pid"));
    }
    if b_rc == Some(0) {
        return Err(fail("call A signalled the other call's host pid"));
    }
    if res_rc.is_none() || b_rc.is_none() {
        return Err(ctl_fail("call A did not report its signal results"));
    }
    Ok(format!(
        "a call sees {pidcount} processes (its own namespace); it cannot signal the resident or the other call"
    ))
}

fn i02(s: &Scns) -> R {
    let scn = sc(s, "SS-kill")?;
    ctl_held(scn, "all_alive_before")?;
    if num(scn, "res_gone") != Some(1) {
        return Err(fail("the resident survived the holder's SIGKILL"));
    }
    if num(scn, "callb_gone") != Some(1) {
        return Err(fail("the attached call survived the holder's SIGKILL"));
    }
    // The attach watches the holder's pidfd and reports the holder's death as rc 125.
    if num(scn, "callb_attach_rc") != Some(125) {
        return Err(fail(format!(
            "the attach did not report the holder's death: rc {:?}, expected 125",
            num(scn, "callb_attach_rc")
        )));
    }
    Ok("SIGKILL of the holder took down the resident and the attached call".to_owned())
}

fn i03(s: &Scns) -> R {
    let scn = sc(s, "SS-policy")?;
    if num(scn, "same_rc") != Some(0) {
        return Err(ctl_fail(
            "an attach with the session's own policy was not admitted",
        ));
    }
    if num(scn, "diff_rc") != Some(125) {
        return Err(fail(format!(
            "an attach with a different policy returned rc {:?}, expected 125",
            num(scn, "diff_rc")
        )));
    }
    let err = scn.notes.get("diff_stderr").cloned().unwrap_or_default();
    if !err.contains("policy differs from the session's policy") {
        return Err(fail(format!(
            "the refusal text is not the pinned one: {err}"
        )));
    }
    Ok("an attach with a different policy is refused with rc 125".to_owned())
}

fn i05(s: &Scns) -> R {
    let scn = sc(s, "SS-idle")?;
    ctl_held(scn, "call_alive_while_idle_limit_passed")?;
    ctl_held(scn, "held_while_call_runs")?;
    if num(scn, "attach_rc") != Some(0) {
        return Err(fail(format!(
            "the call did not run to completion (attach rc {:?}); the idle timeout is not what ended it",
            num(scn, "attach_rc")
        )));
    }
    if num(scn, "ended") != Some(1) || num(scn, "holder_gone") != Some(1) {
        return Err(fail(
            "the idle timeout did not end the session after the call ended",
        ));
    }
    if num(scn, "call_gone") != Some(1) {
        return Err(fail("the call outlived the session it ran in"));
    }
    Ok("a running call holds the session; the idle timeout ends it after the call".to_owned())
}

fn i06(s: &Scns) -> R {
    let scn = sc(s, "SS-life")?;
    ctl_held(scn, "alive_before_max")?;
    ctl_held(scn, "call_alive_before_max")?;
    if num(scn, "ended") != Some(1) || num(scn, "holder_gone") != Some(1) {
        return Err(fail(
            "the max lifetime did not end the session while a call ran",
        ));
    }
    if num(scn, "call_gone") != Some(1) {
        return Err(fail("the running call outlived the session"));
    }
    // The call ends by the holder's teardown (SIGTERM, rc 143), not by an
    // immediate handshake refusal (rc 125) or by its own exit.
    if num(scn, "attach_rc") != Some(143) {
        return Err(fail(format!(
            "the attach did not end by the holder's teardown: rc {:?}, expected 143",
            num(scn, "attach_rc")
        )));
    }
    Ok("the max lifetime ends the session and its running call (teardown, rc 143)".to_owned())
}

/// Evaluates one group-I check into a result.
pub fn evaluate(id: &str, s: &Scns) -> CheckResult {
    let outcome: R = match id {
        "I01" => i01(s),
        "I02" => i02(s),
        "I03" => i03(s),
        "I05" => i05(s),
        "I06" => i06(s),
        _ => Err(fail(format!("no evaluator for {id}"))),
    };
    match outcome {
        Ok(text) => CheckResult::new(id, Status::Ok, text),
        Err(f) => CheckResult::new(id, Status::Fail, f.msg).with_evidence(f.ev),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_uid_check_is_an_opt_in_skip_never_a_pass() {
        let r = foreign_uid_skip();
        assert_eq!(r.id, "I04");
        assert_eq!(r.status, Status::Skip);
        assert_eq!(r.skip_kind, Some(SkipKind::OptIn));
    }

    #[test]
    fn a_missing_control_is_a_control_failure_not_a_pass() {
        // Empty evidence: every group-I evaluator must fail with a control, never pass.
        let empty: Scns = SCENARIOS.iter().map(|n| (*n, Scn::named(n))).collect();
        for id in ["I01", "I02", "I03", "I05", "I06"] {
            let r = evaluate(id, &empty);
            assert_eq!(r.status, Status::Fail, "{id} passed with no evidence");
        }
    }

    #[test]
    fn ids_and_scenarios_are_consistent() {
        for id in IDS {
            assert!(handles(id));
            if id != "I04" {
                assert!(!scenarios_of(id).is_empty(), "{id} has no scenario");
            }
        }
        for name in SCENARIOS {
            assert!(
                IDS.iter().any(|id| scenarios_of(id).contains(&name)),
                "{name} unused"
            );
        }
    }
}
