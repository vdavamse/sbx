//! Integration suite for `sbx __init` (issue #5) — spawns the real binary
//! inside real user+network namespaces and proves every acceptance
//! criterion end-to-end.
//!
//! Why `harness = false` (Cargo.toml): libtest runs tests on parallel
//! threads, but `unshare(CLONE_NEWUSER)` requires a single-threaded process
//! (and a *successful* unshare inside a test thread would capture the whole
//! test binary's namespaces — design D12/R20). This file hand-rolls its
//! runner instead: `main()` dispatches the `SBX_IT_ROLE` child roles FIRST —
//! before any thread is spawned — and the parent side runs the scenarios
//! sequentially with bounded waits.
//!
//! Per-scenario mechanics: `control_socketpair` → `prepare_child_end` →
//! spawn `sbx __init --fd N [--test-break-rules] -- <payload>` (piped
//! stdio + reader threads) → drop the child-end copy IMMEDIATELY (R6) →
//! `recv_listener_fds` → scenario-specific serve/go/close → `wait_bounded`
//! (5 s; `try_wait` polled at 10 ms; kill + FAIL on expiry) → join ALL
//! threads before the next scenario's spawn window (R6: keeps the
//! clear→spawn race free even in the harness) → assert rc + stdout markers
//! and stderr prefixes. No fixed sleeps anywhere — deadline retry-loops
//! only (R12).
//!
//! Gating (design D19): the preflight `probe-userns` child role SKIPs the
//! namespace scenarios with a clear message where unprivileged userns is
//! unavailable (AppArmor); `bwrap --version` SKIPs the bwrap tier. SKIPs
//! exit 0 (graceful on restricted hosts; the CI prep step guarantees a full
//! run in CI); any FAIL exits 1. Scenarios `fail-bad-fd`,
//! `fail-nonsocket-fd` and `usage-contract` need no userns at all (the
//! control stage precedes unshare by design), so the suite degrades to a
//! still-meaningful 3-scenario run instead of a blank SKIP.
//!
//! Payloads are this same test binary re-exec'd through `__init` with
//! `SBX_IT_ROLE=<role>`; every payload line is `SBX-IT-MARKER`-prefixed on
//! stdout, and the "payload never started" assertions check for the
//! marker's ABSENCE. Test addresses: the one AC literal `1.1.1.1:443`
//! (Q6(a)) plus TEST-NET-3 `203.0.113.7` for everything else — neither can
//! leave the sandbox netns (lo is the only interface, probe-proven).

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sbx::init::consts::{DNS_UDP_PORT, EXPLICIT_TCP_PORT, TRANSPARENT_TCP_PORT};
use sbx::init::fdpass;

/// Env var selecting the child role (single parameter; targets are
/// hard-coded per role).
const ROLE_ENV: &str = "SBX_IT_ROLE";
/// Prefix of every payload marker line on stdout.
const MARKER: &str = "SBX-IT-MARKER";
/// Every wait in this suite is bounded by this deadline (design: 5 s).
const BOUND: Duration = Duration::from_secs(5);
/// TEST-NET-3 (RFC 5737) — never routable, the bulk test address (Q6(a)).
const TEST3: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
/// The one acceptance-criteria literal address (Q6(a)).
const AC_LITERAL: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// Non-53 UDP port for the drop-policy scenario.
const DROP_PORT: u16 = 9999;

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // Role dispatch FIRST — before any thread is spawned: child roles must
    // be single-threaded (the unshare invariant, D12/R20).
    if let Ok(role) = std::env::var(ROLE_ENV) {
        return child_main(&role);
    }

    let userns_ok = preflight_userns();
    let bwrap_ok = which_bwrap();
    let (mut passed, mut failed, mut skipped) = (0u32, 0u32, 0u32);
    for sc in scenarios() {
        if !sc.gate.satisfied(userns_ok, bwrap_ok) {
            println!("SKIP {}: {}", sc.name, sc.gate.skip_reason(userns_ok));
            skipped += 1;
            continue;
        }
        match (sc.run)() {
            Ok(()) => {
                println!("PASS {}", sc.name);
                passed += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", sc.name);
                failed += 1;
            }
        }
    }
    println!("sandbox_init: {passed} passed, {failed} failed, {skipped} skipped");
    // SKIPs exit 0 (D19); any FAIL exits 1.
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What a scenario needs to run at all.
#[derive(Clone, Copy)]
enum Gate {
    /// No environment requirement (control stage precedes unshare / clap
    /// precedes everything).
    Always,
    /// Unprivileged user+net namespaces must work.
    Userns,
    /// Userns AND the bwrap binary (CI installs bubblewrap; local hosts may
    /// lack it → SKIP with a message).
    Bwrap,
}

impl Gate {
    fn satisfied(self, userns_ok: bool, bwrap_ok: bool) -> bool {
        match self {
            Gate::Always => true,
            Gate::Userns => userns_ok,
            Gate::Bwrap => userns_ok && bwrap_ok,
        }
    }

    fn skip_reason(self, userns_ok: bool) -> &'static str {
        match self {
            Gate::Always => "",
            Gate::Userns => USERNS_SKIP,
            Gate::Bwrap if !userns_ok => USERNS_SKIP,
            Gate::Bwrap => BWRAP_SKIP,
        }
    }
}

const USERNS_SKIP: &str = "unprivileged userns unavailable (AppArmor? CI: sysctl kernel.apparmor_restrict_unprivileged_userns=0)";
const BWRAP_SKIP: &str = "bwrap not installed (CI: apt-get install bubblewrap)";

struct Scenario {
    name: &'static str,
    gate: Gate,
    run: fn() -> Result<(), String>,
}

/// The 16 scenarios: the design's 15 AC-mapped ones plus `sigpipe-default`
/// (added post-design — pins `exec_payload`'s SIGPIPE restore end-to-end).
fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "only-lo",
            gate: Gate::Userns,
            run: scenario_only_lo,
        },
        Scenario {
            name: "sigpipe-default",
            gate: Gate::Userns,
            run: scenario_sigpipe_default,
        },
        Scenario {
            name: "tcp-redirect",
            gate: Gate::Userns,
            run: scenario_tcp_redirect,
        },
        Scenario {
            name: "explicit-3128",
            gate: Gate::Userns,
            run: scenario_explicit_3128,
        },
        Scenario {
            name: "udp53-roundtrip",
            gate: Gate::Userns,
            run: scenario_udp53_roundtrip,
        },
        Scenario {
            name: "udp-drop-eperm",
            gate: Gate::Userns,
            run: scenario_udp_drop_eperm,
        },
        Scenario {
            name: "proxy-gone",
            gate: Gate::Userns,
            run: scenario_proxy_gone,
        },
        Scenario {
            name: "mutation-eperm-degraded",
            gate: Gate::Userns,
            run: scenario_mutation_degraded,
        },
        Scenario {
            name: "mutation-eperm-bwrap",
            gate: Gate::Bwrap,
            run: scenario_mutation_bwrap,
        },
        Scenario {
            name: "fail-bad-fd",
            gate: Gate::Always,
            run: scenario_fail_bad_fd,
        },
        Scenario {
            name: "fail-nonsocket-fd",
            gate: Gate::Always,
            run: scenario_fail_nonsocket_fd,
        },
        Scenario {
            name: "fail-eof-before-go",
            gate: Gate::Userns,
            run: scenario_fail_eof_before_go,
        },
        Scenario {
            name: "fail-eof-after-fds",
            gate: Gate::Userns,
            run: scenario_fail_eof_after_fds,
        },
        Scenario {
            name: "fail-exec",
            gate: Gate::Userns,
            run: scenario_fail_exec,
        },
        Scenario {
            name: "fail-break-rules",
            gate: Gate::Userns,
            run: scenario_fail_break_rules,
        },
        Scenario {
            name: "usage-contract",
            gate: Gate::Always,
            run: scenario_usage_contract,
        },
    ]
}

/// Preflight: can THIS host do unprivileged userns+netns at all? Spawns the
/// `probe-userns` role (a fresh single-threaded process) and gates every
/// namespace scenario on its rc.
fn preflight_userns() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Ok(mut child) = Command::new(exe)
        .env(ROLE_ENV, "probe-userns")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    match wait_bounded(&mut child, "probe-userns preflight") {
        Ok(status) => status.code() == Some(0),
        Err(_) => false,
    }
}

/// Is the bwrap binary present and runnable (noble ships 0.9.0 ⇒
/// `--disable-userns` available)?
fn which_bwrap() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

// ---------------------------------------------------------------------------
// parent-side helpers
// ---------------------------------------------------------------------------

/// A spawned `sbx __init` with its drained stdio and (usually) the parent's
/// control-socket end.
struct Spawned {
    child: Child,
    /// `None` for the spawns that deliberately get no usable control socket
    /// (fail-bad-fd, fail-nonsocket-fd, fail-eof-before-go); `take()`-able
    /// so a scenario can close it mid-flight (fail-eof-after-fds).
    parent_end: Option<OwnedFd>,
    /// The child was spawned as its OWN process-group leader
    /// (`process_group(0)` ⇒ pgid == pid): on a wait timeout the kill must
    /// target the whole group (m4 — a bwrap payload's grandchildren inherit
    /// the stdio pipes, and a child-only kill would leave the reader-thread
    /// joins waiting for an EOF that never arrives). Only the bwrap tier
    /// sets this; every other scenario keeps the child-only kill.
    own_group: bool,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

/// A reaped scenario child: rc + fully drained stdio.
struct Outcome {
    rc: i32,
    stdout: String,
    stderr: String,
}

/// The core spawn: `sbx __init --fd <fd> [init_args] -- <payload>` with the
/// role env and piped stdio. Reader threads start immediately and are
/// bounded by construction: their pipes hit EOF once the child (and its
/// exec'd payload) exits or is killed.
fn spawn_argv(
    role: &str,
    init_args: &[&str],
    payload: &[OsString],
    fd: RawFd,
) -> Result<Spawned, String> {
    spawn_core(role, init_args, payload, fd, false)
}

/// [`spawn_argv`] with the process-group option (m4). `own_group` puts the
/// child in its own process group via std's
/// [`std::os::unix::process::CommandExt::process_group`]`(0)` — stable since
/// 1.64, so MSRV-safe, and NOT a `pre_exec`: this is the HARNESS's spawn of
/// `sbx`, nowhere near `__init`'s own no-pre_exec fd-inheritance design.
/// setpgid does not touch fd inheritance, so the R6/R14 CLOEXEC-cleared
/// control fd survives exactly as before.
fn spawn_core(
    role: &str,
    init_args: &[&str],
    payload: &[OsString],
    fd: RawFd,
    own_group: bool,
) -> Result<Spawned, String> {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.arg("__init").arg("--fd").arg(fd.to_string());
    cmd.args(init_args);
    cmd.arg("--");
    cmd.args(payload);
    cmd.env(ROLE_ENV, role);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if own_group {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn sbx __init: {e}"))?;
    let stdout = reader_thread(child.stdout.take().expect("stdout is piped"));
    let stderr = reader_thread(child.stderr.take().expect("stderr is piped"));
    Ok(Spawned {
        child,
        parent_end: None,
        own_group,
        stdout,
        stderr,
    })
}

/// The standard happy-path spawn: real control socketpair, child end
/// CLOEXEC-cleared in the spawn window and dropped immediately after (R6),
/// parent end kept for the protocol.
fn spawn_init(role: &str, init_args: &[&str], payload: &[OsString]) -> Result<Spawned, String> {
    spawn_init_core(role, init_args, payload, false)
}

/// [`spawn_init`] with the child as its own process-group leader — the m4
/// hardening, scoped strictly to the bwrap tier (see [`Spawned::own_group`]).
fn spawn_init_group(
    role: &str,
    init_args: &[&str],
    payload: &[OsString],
) -> Result<Spawned, String> {
    spawn_init_core(role, init_args, payload, true)
}

fn spawn_init_core(
    role: &str,
    init_args: &[&str],
    payload: &[OsString],
    own_group: bool,
) -> Result<Spawned, String> {
    let (parent_end, child_end) =
        fdpass::control_socketpair().map_err(|e| format!("control_socketpair: {e}"))?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd())
        .map_err(|e| format!("prepare_child_end: {e}"))?;
    let mut spawned = spawn_core(role, init_args, payload, child_fd, own_group)?;
    // R6: drop the parent's copy of the child end IMMEDIATELY after spawn —
    // the parent keeps ONLY its own end, so its close is a real EOF.
    drop(child_end);
    spawned.parent_end = Some(parent_end);
    Ok(spawned)
}

/// Spawn the role binary as the payload: `__init -- <current_exe>` with
/// `SBX_IT_ROLE` selecting the checks (env survives the exec chain).
fn payload_self() -> Result<Vec<OsString>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    Ok(vec![exe.into()])
}

fn reader_thread<R: Read + Send + 'static>(mut src: R) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = String::new();
        // Bounded: EOF arrives once every write end (child + exec'd
        // payload) is closed — i.e. after reap or kill.
        let _ = src.read_to_string(&mut buf);
        buf
    })
}

/// `try_wait` polled at 10 ms; on deadline expiry kill + reap + Err (FAIL).
fn wait_bounded(child: &mut Child, what: &str) -> Result<ExitStatus, String> {
    wait_bounded_core(child, what, false)
}

/// [`wait_bounded`] with the m4 group-kill: when `kill_group`, the timeout
/// SIGKILLs the WHOLE process group (the child leads it — pgid == pid via
/// `process_group(0)`) BEFORE the child-only kill+reap, so grandchildren
/// holding the stdio pipes die too and the reader-thread joins below can
/// never block on a missing EOF.
fn wait_bounded_core(
    child: &mut Child,
    what: &str,
    kill_group: bool,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + BOUND;
    loop {
        match child
            .try_wait()
            .map_err(|e| format!("try_wait {what}: {e}"))?
        {
            Some(status) => return Ok(status),
            None => {
                if Instant::now() >= deadline {
                    if kill_group {
                        // SAFETY: kill(2) with the negative pid of the group
                        // THIS harness spawned the child to lead
                        // (process_group(0) ⇒ pgid == child.id()); ESRCH is
                        // fine (the group may already be gone) and the
                        // child-only kill+wait below reaps regardless.
                        unsafe {
                            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{what} timed out after 5s (killed)"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Reap the child and join the reader threads — ALWAYS, even when the wait
/// failed (the kill closed the pipes, so the joins are bounded). No thread
/// survives into the next scenario's spawn window (R6 harness discipline).
fn finish(mut sp: Spawned, what: &str) -> Result<Outcome, String> {
    let wait = wait_bounded_core(&mut sp.child, what, sp.own_group);
    let stdout = sp
        .stdout
        .join()
        .map_err(|_| format!("{what}: stdout reader panicked"))?;
    let stderr = sp
        .stderr
        .join()
        .map_err(|_| format!("{what}: stderr reader panicked"))?;
    let status = wait?;
    Ok(Outcome {
        rc: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

fn recv_fds(sp: &Spawned) -> Result<fdpass::ListenerFds, String> {
    let parent_end = sp
        .parent_end
        .as_ref()
        .ok_or("spawn has no parent control end")?;
    fdpass::recv_listener_fds(parent_end.as_raw_fd()).map_err(|e| format!("recv_listener_fds: {e}"))
}

fn send_go(sp: &Spawned) -> Result<(), String> {
    let parent_end = sp
        .parent_end
        .as_ref()
        .ok_or("spawn has no parent control end")?;
    fdpass::send_go(parent_end.as_raw_fd()).map_err(|e| format!("send_go: {e}"))
}

/// Every payload marker line the scenario expects, in any order.
fn assert_markers(out: &Outcome, markers: &[&str]) -> Result<(), String> {
    for m in markers {
        let line = format!("{MARKER} {m}");
        if !out.stdout.contains(&line) {
            return Err(format!(
                "missing marker {line:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                out.stdout, out.stderr
            ));
        }
    }
    Ok(())
}

/// The fail-scenario shape: rc 1, stderr starting with the staged prefix,
/// and the payload marker ABSENT (the command never started).
fn assert_staged_failure(out: &Outcome, prefix: &str) -> Result<(), String> {
    if out.rc != 1 {
        return Err(format!(
            "rc {} (expected 1)\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.rc, out.stdout, out.stderr
        ));
    }
    if !out.stderr.starts_with(prefix) {
        return Err(format!(
            "stderr does not start with {prefix:?}: {:?}",
            out.stderr
        ));
    }
    if out.stdout.contains(MARKER) {
        return Err(format!(
            "payload marker PRESENT — the command must never start:\n{}",
            out.stdout
        ));
    }
    Ok(())
}

/// `SO_ORIGINAL_DST` from the PARENT (host netns) on an accepted stream of
/// a socket that lives in the CHILD's netns — the core cross-netns fd
/// claim, and #7's production lookup.
fn original_dst(stream: &TcpStream) -> Result<String, String> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            sbx::init::consts::SOL_IP,
            sbx::init::consts::SO_ORIGINAL_DST,
            (&mut sa as *mut libc::sockaddr_in).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!("SO_ORIGINAL_DST: {}", io::Error::last_os_error()));
    }
    if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
        return Err("SO_ORIGINAL_DST returned a truncated sockaddr".to_owned());
    }
    let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
    let port = u16::from_be(sa.sin_port);
    Ok(format!("{ip}:{port}"))
}

/// Serve `count` accepts on a received listener, each getting one line
/// `OK original_dst=<ip:port> tag=<tag>`. Bounded: non-blocking accept
/// polled at 10 ms against the 5 s deadline, so a child that never
/// connects fails the scenario instead of hanging the join.
fn serve_tcp(listener: &TcpListener, count: usize, tag: &str) -> Result<(), String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking({tag}): {e}"))?;
    let deadline = Instant::now() + BOUND;
    let mut served = 0usize;
    while served < count {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let od = original_dst(&stream)?;
                let mut w = &stream;
                writeln!(w, "OK original_dst={od} tag={tag}")
                    .map_err(|e| format!("serve write ({tag}): {e}"))?;
                served += 1;
                // drop(stream) closes the connection; the payload's
                // read_to_string sees the line then EOF.
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "serve_tcp({tag}): timed out after {served}/{count} accepts"
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("serve_tcp({tag}) accept: {e}")),
        }
    }
    Ok(())
}

/// Payload rc + markers for a success scenario.
fn assert_success(out: &Outcome, markers: &[&str]) -> Result<(), String> {
    if out.rc != 0 {
        return Err(format!(
            "payload rc {} (expected 0)\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.rc, out.stdout, out.stderr
        ));
    }
    assert_markers(out, markers)
}

// ---------------------------------------------------------------------------
// scenarios 1–9: the sandbox works
// ---------------------------------------------------------------------------

/// AC: inside the sandbox, `lo` is the only interface, IPv6 is off, the
/// default route points into the sandbox — and after the exec, only stdio
/// fds remain (the fd-hygiene end-to-end proof, D13).
fn scenario_only_lo() -> Result<(), String> {
    let sp = spawn_init("check-net", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?;
    send_go(&sp)?;
    let out = finish(sp, "check-net payload")?;
    // Hold the listener fds until the payload is reaped ("hold fds"), then
    // assert. Success is silent (D6): stderr must be empty.
    drop(fds);
    if !out.stderr.trim().is_empty() {
        return Err(format!(
            "stderr must be silent on success: {:?}",
            out.stderr
        ));
    }
    assert_success(
        &out,
        &[
            "ifaces=lo",
            "if_inet6=empty",
            "default-route=lo",
            "fds=0,1,2",
        ],
    )
}

/// Exec hygiene (module docs point 6): std ignores SIGPIPE at startup and
/// ignored dispositions survive `execve`, so `exec_payload` restores
/// `SIG_DFL` right before the exec — the payload must NOT inherit broken
/// `cmd | head`-style pipe semantics (writers dying silently by signal
/// instead of erroring with EPIPE).
///
/// The payload is `/bin/sh`, NOT the test binary: a Rust payload cannot
/// pin this (its own std startup re-ignores SIGPIPE before `main` runs),
/// while a POSIX shell leaves inherited dispositions untouched (ignored
/// on entry stay ignored, defaults stay defaults). The shell prints its
/// `SigIgn` mask from `/proc/self/status`; the harness asserts the SIGPIPE
/// bit (signal 13 ⇒ bit 12) is CLEAR. Pure shell builtins — no awk/grep
/// dependency. bwrap is not in this chain (the suite execs payloads
/// directly) and upstream `bubblewrap.c` restores only SIGCHLD, so the
/// production `run` → `__init` → bwrap → payload chain relies on exactly
/// this restore.
fn scenario_sigpipe_default() -> Result<(), String> {
    // Marker-prefixed like every payload line (suite convention).
    let script = format!(
        "while read -r name value; do \
         case $name in SigIgn:) echo \"{MARKER} SigIgn=$value\";; esac; \
         done < /proc/self/status"
    );
    let payload: Vec<OsString> = ["/bin/sh", "-c", &script]
        .iter()
        .map(OsString::from)
        .collect();
    let sp = spawn_init("sigpipe-default", &[], &payload)?;
    let fds = recv_fds(&sp)?;
    send_go(&sp)?;
    let out = finish(sp, "sigpipe-default payload")?;
    // Hold the listener fds until the payload is reaped ("hold fds").
    drop(fds);
    if out.rc != 0 {
        return Err(format!(
            "payload rc {} (expected 0)\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.rc, out.stdout, out.stderr
        ));
    }
    if !out.stderr.trim().is_empty() {
        return Err(format!(
            "stderr must be silent on success: {:?}",
            out.stderr
        ));
    }
    let mask_hex = out
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{MARKER} SigIgn=")))
        .ok_or_else(|| format!("no SigIgn marker line in payload stdout:\n{}", out.stdout))?;
    let mask = u64::from_str_radix(mask_hex.trim(), 16)
        .map_err(|e| format!("SigIgn mask {mask_hex:?} is not hex: {e}"))?;
    let sigpipe_bit = 1u64 << (libc::SIGPIPE - 1);
    if mask & sigpipe_bit != 0 {
        return Err(format!(
            "SIGPIPE still ignored after exec (SigIgn={mask:016x}) — \
             exec_payload must restore SIG_DFL before execvp"
        ));
    }
    Ok(())
}

/// AC: a direct connect to 1.1.1.1:443 (the acceptance literal, Q6(a)) and
/// its TEST-NET-3 twin are redirected to the parent-held listener, and the
/// parent — in the HOST netns — sees the pre-DNAT original destination via
/// SO_ORIGINAL_DST.
fn scenario_tcp_redirect() -> Result<(), String> {
    let sp = spawn_init("check-tcp", &[], &payload_self()?)?;
    let fdpass::ListenerFds {
        transparent,
        explicit,
        dns,
    } = recv_fds(&sp)?;
    // Serving is set up BEFORE go (the go guarantee): the thread polls
    // accepts from here on; the sockets were listening (backlog) since the
    // child bound them.
    let server = std::thread::spawn(move || serve_tcp(&transparent, 2, "transparent"));
    send_go(&sp)?;
    let served = server
        .join()
        .map_err(|_| "serve thread panicked".to_owned())?;
    let out = finish(sp, "check-tcp payload")?;
    served?;
    // explicit + dns stayed bound (dropped here, after the reap) — no
    // listener-gone races while the payload runs.
    drop((explicit, dns));
    assert_success(
        &out,
        &["original_dst=1.1.1.1:443", "original_dst=203.0.113.7:443"],
    )
}

/// AC: the explicit-proxy port is directly reachable, and F8 (own-address
/// semantics: SO_ORIGINAL_DST on a non-NATed connection returns the
/// connection's own local address) holds through the fd hand-off.
fn scenario_explicit_3128() -> Result<(), String> {
    let sp = spawn_init("check-explicit", &[], &payload_self()?)?;
    let fdpass::ListenerFds {
        transparent,
        explicit,
        dns,
    } = recv_fds(&sp)?;
    let server = std::thread::spawn(move || serve_tcp(&explicit, 1, "explicit"));
    send_go(&sp)?;
    let served = server
        .join()
        .map_err(|_| "serve thread panicked".to_owned())?;
    let out = finish(sp, "check-explicit payload")?;
    served?;
    drop((transparent, dns));
    assert_success(&out, &["original_dst=127.0.0.1:3128 tag=explicit"])
}

/// AC: udp/53 to an external address round-trips through the redirected,
/// parent-held DNS fd (bare `redir` preserves the port).
fn scenario_udp53_roundtrip() -> Result<(), String> {
    let sp = spawn_init("check-udp", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?;
    send_go(&sp)?;
    // Serve one DNS round-trip on the received fd (bounded: 5 s read
    // timeout — a killed child can never hang this).
    fds.dns
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("dns set_read_timeout: {e}"))?;
    let mut buf = [0u8; 256];
    let (n, peer) = fds
        .dns
        .recv_from(&mut buf)
        .map_err(|e| format!("dns recv_from: {e}"))?;
    let query = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
    fds.dns
        .send_to(b"PONG\n", peer)
        .map_err(|e| format!("dns send_to: {e}"))?;
    let out = finish(sp, "check-udp payload")?;
    drop(fds);
    if query != "QUERY" {
        return Err(format!("expected QUERY, got {query:?}"));
    }
    assert_success(&out, &["udp53 PONG"])
}

/// AC (F3): non-53 UDP hits the filter chain's drop policy — `send()`
/// fails SYNCHRONOUSLY with EPERM (deterministic; no timeouts involved).
/// The OutDiscards delta is captured informationally only (kernel
/// variance, R21).
fn scenario_udp_drop_eperm() -> Result<(), String> {
    let sp = spawn_init("check-udp-drop", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?; // hold, no serving
    send_go(&sp)?;
    let out = finish(sp, "check-udp-drop payload")?;
    drop(fds);
    assert_success(&out, &["udp-drop EPERM"])
}

/// AC: with the proxy gone (the parent dropped all three fds), every
/// connect fails — redirected, direct and explicit TCP refuse, and UDP
/// surfaces ECONNREFUSED via the ICMP from the redirect-to-unbound-:53.
fn scenario_proxy_gone() -> Result<(), String> {
    let sp = spawn_init("check-gone", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?;
    // The coordination is race-free by construction: drop-all-three THEN
    // go — by the time the payload runs, the sockets are already gone and
    // refusal is immediate (no fixed sleeps needed).
    drop(fds);
    send_go(&sp)?;
    let out = finish(sp, "check-gone payload")?;
    assert_success(
        &out,
        &[
            "refused redirect 1.1.1.1:443",
            "refused direct 127.0.0.1:15001",
            "refused explicit 127.0.0.1:3128",
            "refused udp 203.0.113.7:53",
        ],
    )
}

/// AC (degraded tier, Q5(a)/D15): after a nested unshare(CLONE_NEWUSER)
/// the payload has no capabilities over the sandbox netns — raw-netlink
/// route mutation AND the whole nfnetlink-nftables subsys answer EPERM.
/// Models exactly what `--cap-drop ALL` provides in the bwrap tier.
fn scenario_mutation_degraded() -> Result<(), String> {
    let sp = spawn_init("check-mutation", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?; // hold
    send_go(&sp)?;
    let out = finish(sp, "check-mutation payload")?;
    drop(fds);
    assert_success(
        &out,
        &["mutation tier=degraded route=EPERM nft=EPERM nested_userns=ok"],
    )
}

/// AC (CI tier): under `bwrap --unshare-user --cap-drop ALL
/// --disable-userns`, route + nft mutation answer EPERM AND creating a new
/// userns from inside is blocked — the `--disable-userns` proof (bwrap ≥
/// 0.8; noble ships 0.9.0). bwrap implements `--disable-userns` by setting
/// `user.max_user_namespaces` to 0 inside the sandbox userns, so the
/// kernel rejects nested `unshare(CLONE_NEWUSER)` with **ENOSPC** (observed
/// on the GitHub runner); EPERM is also accepted (other blocking
/// mechanisms/versions). The role prints the actual errno.
fn scenario_mutation_bwrap() -> Result<(), String> {
    // Env passes through bwrap by default, so SBX_IT_ROLE reaches the
    // payload. Fallback argv if `--ro-bind / /` ever proves fragile on
    // runners (R19): restricted binds (/usr /bin /lib /lib64 /etc + the
    // exe's tree) + --dev --proc.
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut payload: Vec<OsString> = [
        "bwrap",
        "--unshare-user",
        "--unshare-pid",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--",
    ]
    .iter()
    .map(|s| OsString::from(*s))
    .collect();
    payload.push(exe.into());

    // m4 hardening (bwrap tier ONLY): spawn in its own process group so a
    // wait timeout SIGKILLs the whole tree. The payload here is
    // sbx→bwrap→test-exe: if anything in that chain wedges, a child-only
    // kill could leave a grandchild holding the stdout pipe — the reader
    // join would then block forever. Other scenarios' payloads are the
    // single exec'd test binary (no grandchildren), so they keep the
    // plain spawn/kill path unchanged.
    let sp = spawn_init_group("check-mutation-bwrap", &[], &payload)?;
    let fds = recv_fds(&sp)?; // hold
    send_go(&sp)?;
    let out = finish(sp, "check-mutation-bwrap payload")?;
    drop(fds);
    assert_success(
        &out,
        &["mutation tier=bwrap route=EPERM nft=EPERM userns=blocked"],
    )
}

// ---------------------------------------------------------------------------
// scenarios 10–16: the failure paths
// ---------------------------------------------------------------------------

/// AC: `--fd 999` (nothing open there) fails at the CONTROL stage — before
/// unshare, hence gate Always — rc 1, staged prefix, payload never starts.
fn scenario_fail_bad_fd() -> Result<(), String> {
    let sp = spawn_argv("marker", &[], &payload_self()?, 999)?;
    let out = finish(sp, "fail-bad-fd child")?;
    assert_staged_failure(&out, "sbx __init: control:")
}

/// AC: a valid fd that is not a socket (/dev/null, inherited WITHOUT
/// CLOEXEC — std's File would set it and hide the fd from the child) fails
/// at the control stage: rc 1, staged prefix, payload never starts.
fn scenario_fail_nonsocket_fd() -> Result<(), String> {
    // SAFETY: open/close of a literal path; the fd number is passed to the
    // spawn and the parent's copy is closed immediately afterwards.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(format!("open /dev/null: {}", io::Error::last_os_error()));
    }
    let spawned = spawn_argv("marker", &[], &payload_self()?, fd);
    // Close the parent's copy whatever the spawn did (the child has its
    // own inherited reference by now).
    unsafe {
        libc::close(fd);
    }
    let out = finish(spawned?, "fail-nonsocket-fd child")?;
    assert_staged_failure(&out, "sbx __init: control:")
}

/// AC (probe-verified race 1): the parent dies BEFORE the fds arrive —
/// sendmsg sees EPIPE (std keeps SIGPIPE ignored), the child aborts staged
/// send-fds rc 1, and the payload never starts.
fn scenario_fail_eof_before_go() -> Result<(), String> {
    let (parent_end, child_end) =
        fdpass::control_socketpair().map_err(|e| format!("control_socketpair: {e}"))?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd())
        .map_err(|e| format!("prepare_child_end: {e}"))?;
    let sp = spawn_argv("marker", &[], &payload_self()?, child_fd)?;
    // Drop BOTH parent ends immediately: by the time the child finishes
    // its ~sub-second setup and sends, the peer is long gone ⇒ EPIPE.
    drop(child_end);
    drop(parent_end);
    let out = finish(sp, "fail-eof-before-go child")?;
    assert_staged_failure(&out, "sbx __init: send-fds:")
}

/// AC (probe-verified race 2): the fds hand-off SUCCEEDED (D18: prove all
/// three sockets are live via local_addr first), but the control socket
/// closes without a go byte ⇒ staged wait-go rc 1, payload never starts.
fn scenario_fail_eof_after_fds() -> Result<(), String> {
    let mut sp = spawn_init("marker", &[], &payload_self()?)?;
    let fds = recv_fds(&sp)?;
    // D18: the hand-off itself worked — all three sockets answer local_addr
    // from the host netns, on the protocol ports (also pins wire order).
    let t = fds
        .transparent
        .local_addr()
        .map_err(|e| format!("transparent local_addr: {e}"))?;
    let x = fds
        .explicit
        .local_addr()
        .map_err(|e| format!("explicit local_addr: {e}"))?;
    let d = fds
        .dns
        .local_addr()
        .map_err(|e| format!("dns local_addr: {e}"))?;
    if t.port() != TRANSPARENT_TCP_PORT || x.port() != EXPLICIT_TCP_PORT || d.port() != DNS_UDP_PORT
    {
        return Err(format!("unexpected listener ports: {t} {x} {d}"));
    }
    drop(fds);
    // Close the control socket WITHOUT sending go ⇒ the child's wait-go
    // sees EOF and aborts before exec.
    drop(sp.parent_end.take());
    let out = finish(sp, "fail-eof-after-fds child")?;
    assert_staged_failure(&out, "sbx __init: wait-go:")
}

/// AC: a payload path that does not exist fails at the EXEC stage — rc 1,
/// reason "not found", after a completely successful setup + hand-off +
/// go (the fds were real; only the exec failed).
fn scenario_fail_exec() -> Result<(), String> {
    let missing = OsString::from("/nonexistent/sbx-it-payload-404");
    let sp = spawn_init("marker", &[], &[missing])?;
    let fds = recv_fds(&sp)?;
    send_go(&sp)?;
    let out = finish(sp, "fail-exec child")?;
    drop(fds);
    assert_staged_failure(&out, "sbx __init: exec:")?;
    if !out.stderr.contains("not found") {
        return Err(format!(
            "exec reason must say 'not found': {:?}",
            out.stderr
        ));
    }
    Ok(())
}

/// AC (Q4(a)): the hidden --test-break-rules flag makes the kernel reject
/// the batch (ENOENT on the nonexistent chain) and roll everything back
/// (F6) — staged nft-load rc 1, payload never starts. The fresh netns dies
/// with the child, so nothing persists to check.
fn scenario_fail_break_rules() -> Result<(), String> {
    let sp = spawn_init("marker", &["--test-break-rules"], &payload_self()?)?;
    // The child dies at nft-load, BEFORE send-fds: do not recv (that would
    // block) — just reap.
    let out = finish(sp, "fail-break-rules child")?;
    assert_staged_failure(&out, "sbx __init: nft-load:")
}

/// AC: the usage contract — bare `__init`, non-numeric `--fd`, negative
/// `--fd` and a missing command are ALL clap rc 2 (no staged prefix, no
/// payload); rc 1 stays exclusively for staged setup failures (D7/D8).
fn scenario_usage_contract() -> Result<(), String> {
    let cases: [Vec<&str>; 4] = [
        vec!["__init"],
        vec!["__init", "--fd", "abc", "--", "/bin/true"],
        vec!["__init", "--fd=-1", "--", "/bin/true"],
        vec!["__init", "--fd", "3"],
    ];
    for args in cases {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(&args)
            .output()
            .map_err(|e| format!("spawn {args:?}: {e}"))?;
        let rc = out.status.code().unwrap_or(-1);
        if rc != 2 {
            return Err(format!(
                "{args:?}: rc {rc} (expected 2)\nstderr: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        if String::from_utf8_lossy(&out.stdout).contains(MARKER) {
            return Err(format!("{args:?}: payload marker on stdout"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// child side: role dispatch + roles
// ---------------------------------------------------------------------------

fn child_main(role: &str) -> ExitCode {
    let result = match role {
        "probe-userns" => role_probe_userns(),
        "marker" => role_marker(),
        "check-net" => role_check_net(),
        "check-tcp" => role_check_tcp(),
        "check-explicit" => role_check_explicit(),
        "check-udp" => role_check_udp(),
        "check-udp-drop" => role_check_udp_drop(),
        "check-gone" => role_check_gone(),
        "check-mutation" => role_check_mutation(false),
        "check-mutation-bwrap" => role_check_mutation(true),
        other => Err(format!("unknown {ROLE_ENV} {other:?}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("SBX-IT-FAIL role={role}: {err}");
            ExitCode::FAILURE
        }
    }
}

fn marker(line: &str) {
    println!("{MARKER} {line}");
}

/// Preflight role: prove unprivileged userns+netns works in a fresh
/// single-threaded process. rc IS the signal (no markers).
fn role_probe_userns() -> Result<(), String> {
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(format!(
            "unshare(CLONE_NEWUSER|CLONE_NEWNET): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Inert payload for the fail scenarios: its marker's ABSENCE is the
/// assertion that the command never started.
fn role_marker() -> Result<(), String> {
    marker("");
    Ok(())
}

/// only-lo: interface set, IPv6-off, default route, and the end-to-end fd
/// hygiene proof (D13): after the control-fd close + /proc scan + CLOEXEC
/// deaths at exec, ONLY stdio remains open.
fn role_check_net() -> Result<(), String> {
    // AC: lo is the only interface.
    let dev =
        std::fs::read_to_string("/proc/net/dev").map_err(|e| format!("read /proc/net/dev: {e}"))?;
    let ifaces: Vec<&str> = dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .collect();
    if ifaces != ["lo"] {
        return Err(format!("expected only lo, got {ifaces:?}"));
    }
    marker("ifaces=lo");

    // AC: IPv6 off (a missing if_inet6 is the CONFIG_IPV6=n case — empty).
    let v6 = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(format!("read /proc/net/if_inet6: {err}")),
    };
    if !v6.trim().is_empty() {
        return Err(format!("if_inet6 not empty: {v6:?}"));
    }
    marker("if_inet6=empty");

    // AC: the default route exists and points via lo.
    let route = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| format!("read /proc/net/route: {e}"))?;
    let default_via_lo = route.lines().skip(1).any(|l| {
        let mut f = l.split_whitespace();
        matches!((f.next(), f.next()), (Some("lo"), Some("00000000")))
    });
    if !default_via_lo {
        return Err(format!("no default route via lo:\n{route}"));
    }
    marker("default-route=lo");

    // fd hygiene end-to-end (D13): probe fds 3..1024 with fcntl(F_GETFD) —
    // EBADF everywhere. (Not a /proc/self/fd listing: the directory
    // handle's own dirfd would appear in its own listing; the fcntl probe
    // has no such self-inclusion and needs no /proc.)
    let leaked: Vec<RawFd> = (3..1024)
        .filter(|fd| {
            // SAFETY: F_GETFD on a candidate fd; -1/EBADF means closed.
            (unsafe { libc::fcntl(*fd, libc::F_GETFD) }) != -1
        })
        .collect();
    if !leaked.is_empty() {
        return Err(format!("fds still open after exec: {leaked:?}"));
    }
    marker("fds=0,1,2");
    Ok(())
}

/// tcp-redirect: connect to the AC literal AND the TEST-NET-3 twin; both
/// must land on the parent-held transparent listener, which serves the
/// pre-DNAT original destination.
fn role_check_tcp() -> Result<(), String> {
    for target in [AC_LITERAL, TEST3] {
        let addr = SocketAddr::V4(SocketAddrV4::new(target, 443));
        let mut stream =
            TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_read_timeout(Some(BOUND))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        let mut line = String::new();
        stream
            .read_to_string(&mut line)
            .map_err(|e| format!("read from {addr}: {e}"))?;
        let want = format!("original_dst={target}:443");
        if !line.contains(&want) {
            return Err(format!("served line for {addr} lacks {want:?}: {line:?}"));
        }
        marker(&format!("original_dst={target}:443"));
    }
    Ok(())
}

/// explicit-3128: direct connect to the explicit listener; F8 semantics —
/// SO_ORIGINAL_DST on a non-NATed connection reports its own local address.
fn role_check_explicit() -> Result<(), String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, EXPLICIT_TCP_PORT));
    let mut stream =
        TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let mut line = String::new();
    stream
        .read_to_string(&mut line)
        .map_err(|e| format!("read from {addr}: {e}"))?;
    let want = format!("original_dst=127.0.0.1:{EXPLICIT_TCP_PORT}");
    if !line.contains(&want) || !line.contains("tag=explicit") {
        return Err(format!("served line lacks {want:?}/tag=explicit: {line:?}"));
    }
    marker(&format!("{want} tag=explicit"));
    Ok(())
}

/// udp53-roundtrip: a connected UDP socket to TEST-NET-3:53 is redirected
/// (bare redir keeps the port) to the parent-held dns fd; QUERY → PONG.
fn role_check_udp() -> Result<(), String> {
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("udp bind: {e}"))?;
    s.connect(SocketAddrV4::new(TEST3, DNS_UDP_PORT))
        .map_err(|e| format!("udp connect: {e}"))?;
    s.set_read_timeout(Some(BOUND))
        .map_err(|e| format!("udp set_read_timeout: {e}"))?;
    s.send(b"QUERY\n").map_err(|e| format!("udp send: {e}"))?;
    let mut buf = [0u8; 64];
    let n = s.recv(&mut buf).map_err(|e| format!("udp recv: {e}"))?;
    let reply = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
    if reply != "PONG" {
        return Err(format!("expected PONG, got {reply:?}"));
    }
    marker("udp53 PONG");
    Ok(())
}

/// udp-drop-eperm: non-53 UDP hits filter_out's drop policy ⇒ `send()`
/// fails SYNCHRONOUSLY with EPERM (F3 — deterministic, no timeouts). The
/// OutDiscards delta is printed informationally (kernel variance, R21) and
/// never asserted.
fn role_check_udp_drop() -> Result<(), String> {
    let before = ip_out_discards();
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("udp bind: {e}"))?;
    s.connect(SocketAddrV4::new(TEST3, DROP_PORT))
        .map_err(|e| format!("udp connect: {e}"))?;
    match s.send(b"X") {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
        other => {
            return Err(format!(
                "expected synchronous EPERM from send(), got {other:?}"
            ));
        }
    }
    marker("udp-drop EPERM");
    marker(&format!(
        "outdiscards_delta={}",
        ip_out_discards().saturating_sub(before)
    ));
    Ok(())
}

/// `/proc/net/snmp` Ip OutDiscards — informational (0 on any parse miss).
fn ip_out_discards() -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/net/snmp") else {
        return 0;
    };
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("Ip:")).collect();
    if lines.len() < 2 {
        return 0;
    }
    let header: Vec<&str> = lines[0].split_whitespace().collect();
    let values: Vec<&str> = lines[1].split_whitespace().collect();
    let Some(idx) = header.iter().position(|f| *f == "OutDiscards") else {
        return 0;
    };
    values.get(idx).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// proxy-gone: with the parent's fds dropped, EVERY connect must refuse —
/// the redirected literal, the direct transparent port, the explicit port,
/// and UDP via the ICMP from the redirect-to-unbound-:53 (R22). Deadline
/// retry-loops; refusal is immediate in practice (the parent dropped the
/// fds before go).
fn role_check_gone() -> Result<(), String> {
    let deadline = Instant::now() + BOUND;
    let tcp_targets = [
        (
            "redirect 1.1.1.1:443",
            SocketAddr::V4(SocketAddrV4::new(AC_LITERAL, 443)),
        ),
        (
            "direct 127.0.0.1:15001",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, TRANSPARENT_TCP_PORT)),
        ),
        (
            "explicit 127.0.0.1:3128",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, EXPLICIT_TCP_PORT)),
        ),
    ];
    for (label, addr) in tcp_targets {
        await_tcp_refused(addr, deadline).map_err(|e| format!("{label}: {e}"))?;
        marker(&format!("refused {label}"));
    }
    let udp_addr = SocketAddrV4::new(TEST3, DNS_UDP_PORT);
    await_udp_refused(udp_addr, deadline).map_err(|e| format!("udp {udp_addr}: {e}"))?;
    marker(&format!("refused udp {TEST3}:{DNS_UDP_PORT}"));
    Ok(())
}

fn await_tcp_refused(addr: SocketAddr, deadline: Instant) -> Result<(), String> {
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(()),
            // An ACCEPTED connect with the proxy gone is a fail-closed
            // violation — hard error, no retry.
            Ok(_) => return Err(format!("connect {addr} was ACCEPTED with the proxy gone")),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("no ConnectionRefused by the deadline (last: {e})"));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn await_udp_refused(addr: SocketAddrV4, deadline: Instant) -> Result<(), String> {
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("bind: {e}"))?;
    s.connect(addr).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    loop {
        // The FIRST send succeeds (nothing has hit the ICMP path yet);
        // once the port-unreachable from the redirect-to-unbound-:53
        // arrives, the next send/recv surfaces ECONNREFUSED. Transient
        // send errors retry until the deadline; an actual reply with the
        // proxy gone is a fail-closed violation.
        match s.send(b"Q") {
            Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => return Ok(()),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("no ECONNREFUSED by the deadline (last send: {e})"));
                }
            }
            Ok(_) => {}
        }
        match s.recv(&mut [0u8; 16]) {
            Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("no ECONNREFUSED by the deadline (last recv: {e})"));
                }
            }
            Ok(_) => return Err("unexpected UDP reply with the proxy gone".to_owned()),
        }
        if Instant::now() >= deadline {
            return Err("no UDP ECONNREFUSED by the deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// mutation tiers: raw-netlink route + nftables mutations must be EPERM
/// once capabilities over the sandbox netns are gone. `bwrap_tier`
/// additionally proves `--disable-userns` (nested unshare ⇒ blocked:
/// bwrap zeroes `user.max_user_namespaces` inside the sandbox userns, so
/// the kernel answers ENOSPC — EPERM also accepted); the degraded tier
/// proves the nested-userns capability boundary instead (nested unshare
/// ⇒ ok, then everything is EPERM).
fn role_check_mutation(bwrap_tier: bool) -> Result<(), String> {
    let mut userns_errno = 0i32;
    if bwrap_tier {
        // bwrap --unshare-user --cap-drop ALL already stripped us;
        // --disable-userns (bwrap ≥ 0.8) must ALSO block creating a new
        // userns from inside. Its mechanism is
        // `/proc/sys/user/max_user_namespaces = 0` in the sandbox userns,
        // and the kernel's create_user_ns() returns ENOSPC when that
        // limit is hit (empirically verified on the GitHub runner,
        // bubblewrap 0.9.0); EPERM is what a capability-based block would
        // return. Either errno proves the block — anything else (or
        // success) does not.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if rc == 0 {
            return Err("unshare(CLONE_NEWUSER) SUCCEEDED despite --disable-userns".to_owned());
        }
        let err = io::Error::last_os_error();
        userns_errno = err.raw_os_error().unwrap_or(0);
        if userns_errno != libc::EPERM && userns_errno != libc::ENOSPC {
            return Err(format!(
                "expected EPERM or ENOSPC from unshare under --disable-userns, got {err}"
            ));
        }
    } else {
        // Degraded tier (Q5(a)): a nested unshare(CLONE_NEWUSER) (N7:
        // verified working inside our userns) leaves us uid 65534 with NO
        // capabilities over the sandbox netns — exactly the capability
        // boundary --cap-drop ALL provides in the bwrap tier. Safe here:
        // this process is single-threaded (role dispatch precedes any
        // thread spawn).
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if rc != 0 {
            return Err(format!(
                "nested unshare(CLONE_NEWUSER): {}",
                io::Error::last_os_error()
            ));
        }
    }

    // (a) rtnetlink RTM_NEWROUTE must be EPERM — raw netlink via the same
    //     crates __init uses; no ip/nft tooling needed inside.
    let route_errno = netlink_route_add_errno()?;
    if route_errno != libc::EPERM {
        return Err(format!(
            "RTM_NEWROUTE: expected EPERM ({}), got errno {route_errno}",
            libc::EPERM
        ));
    }
    // (b) NETLINK_NETFILTER GETGEN must be EPERM: the whole
    //     nfnetlink-nftables subsys is CAP_NET_ADMIN-gated, so every
    //     mutation path fails identically (D15).
    let nft_errno = netlink_nft_getgen_errno()?;
    if nft_errno != libc::EPERM {
        return Err(format!(
            "NF GETGEN: expected EPERM ({}), got errno {nft_errno}",
            libc::EPERM
        ));
    }

    if bwrap_tier {
        marker(&format!(
            "mutation tier=bwrap route=EPERM nft=EPERM userns=blocked(errno={userns_errno})"
        ));
    } else {
        marker("mutation tier=degraded route=EPERM nft=EPERM nested_userns=ok");
    }
    Ok(())
}

/// Attempt a default-route-shaped RTM_NEWROUTE; Ok(errno) when the kernel
/// rejected it (the expected outcome inside the sandbox), Err only if it
/// unexpectedly SUCCEEDED (a real sandbox breach) or the transport broke.
fn netlink_route_add_errno() -> Result<i32, String> {
    use netlink_bindings::rt_route;
    use netlink_socket2::NetlinkSocket;

    // Lazy socket: opened here, AFTER the capability state is final —
    // netlink binds the netns open at socket(2) time (same netns either
    // way; the permission check runs at request time).
    let mut sock = NetlinkSocket::new();
    let mut req = rt_route::Request::new()
        .set_create()
        .set_excl()
        .op_newroute_do(&rt_route::Rtmsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 254,  // RT_TABLE_MAIN
            rtm_protocol: 3, // RTPROT_BOOT
            rtm_scope: 253,  // RT_SCOPE_LINK
            rtm_type: 1,     // RTN_UNICAST
            rtm_flags: 0,
        });
    req.encode().push_oif(1); // lo
    // as_io_error() borrows (ReplyError outlives the call) — extract the
    // raw errno directly; a transport error without an errno maps to -1
    // (never EPERM, so the assertion still fails loudly).
    let outcome: Result<(), i32> = match sock.request(&req) {
        Ok(mut reply) => reply
            .recv_ack()
            .map_err(|e| e.as_io_error().raw_os_error().unwrap_or(-1)),
        Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
    };
    match outcome {
        Ok(()) => Err(
            "RTM_NEWROUTE unexpectedly SUCCEEDED — route mutation is not capability-gated!"
                .to_owned(),
        ),
        Err(errno) => Ok(errno),
    }
}

/// Attempt an nftables GETGEN over NETLINK_NETFILTER; same contract as
/// [`netlink_route_add_errno`].
fn netlink_nft_getgen_errno() -> Result<i32, String> {
    use netlink_bindings::nftables::{self, Nfgenmsg};
    use netlink_socket2::NetlinkSocket;

    let mut sock = NetlinkSocket::new();
    let req = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
    let outcome: Result<(), i32> = match sock.request(&req) {
        Ok(mut reply) => reply
            .recv_one()
            .map(|_| ())
            .map_err(|e| e.as_io_error().raw_os_error().unwrap_or(-1)),
        Err(e) => Err(e.raw_os_error().unwrap_or(-1)),
    };
    match outcome {
        Ok(()) => Err(
            "nftables GETGEN unexpectedly SUCCEEDED — the nft subsys is not capability-gated!"
                .to_owned(),
        ),
        Err(errno) => Ok(errno),
    }
}
