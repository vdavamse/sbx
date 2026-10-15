//! Integration suite for the transparent egress proxy (issue #7) — serves
//! the REAL handed-off transparent listener fd and proves every acceptance
//! criterion end-to-end.
//!
//! Why `harness = false` (Cargo.toml): the same single-threaded-process
//! rationale as sandbox_init.rs — the `probe-userns` child role is this
//! test binary re-exec'd and `unshare(CLONE_NEWUSER)` requires a
//! single-threaded process, so `main()` dispatches the `SBX_PT_ROLE` child
//! roles FIRST, before any thread is spawned, and the parent side runs the
//! scenarios sequentially with bounded waits (deadline retry-loops only,
//! no fixed sleeps — R12; all threads joined before the next spawn
//! window — R6).
//!
//! Three tiers (the design's gate split):
//!
//! * `Gate::Always` — the `origdst-probe` preflight canary only.
//! * `Gate::OrigDst` — host-netns scenarios on ephemeral 127.0.0.1
//!   listeners, exploiting the F8 own-address fallback (`SO_ORIGINAL_DST`
//!   on a non-NATed connection returns its own destination — the fact
//!   sandbox_init's `explicit-3128` scenario pinned). No netns needed.
//! * `Gate::Userns` — the full chain: spawn the real `sbx __init` (user +
//!   net namespaces, nftables REDIRECT, SCM_RIGHTS fd hand-off), start
//!   [`sbx::proxy::serve`] on the received transparent fd BEFORE the go
//!   byte (the fdpass go guarantee), and run payload roles that dial
//!   TEST-NET-3 (`203.0.113.7`, unmapped twin `203.0.113.9`) under the
//!   real redirect. Teardown is the pinned `shutdown(SHUT_RDWR)` →
//!   accept-EINVAL path with bounded joins.
//!
//! Payload lines are `SBX-PT-MARKER`-prefixed on stdout; denial roles
//! share an `expect_close` helper accepting a clean EOF OR `ECONNRESET`
//! (the kernel RSTs when the proxy closes with an unread receive queue —
//! both mean "closed with zero application bytes relayed"). The echo
//! server is half-duplex (read-to-end, write-back, close) which is
//! deterministic because roles `shutdown(Write)` after writing; the
//! second-hello teardown scenario uses the immediate-echo variant
//! (chunk-by-chunk write-back) whose CH1 echo is the role's signal that
//! the relay phase is live (R12: signal-driven, no fixed sleeps).
//!
//! SKIPs exit 0 (graceful on restricted hosts; CI runs everything); any
//! FAIL exits 1.

use std::collections::HashMap;
use std::ffi::OsString;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::pin::Pin;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sbx::init::fdpass;
use sbx::policy::{self, Domain};
use sbx::proxy::hello::build_client_hello;
use sbx::proxy::{
    ConnectError, Connected, Connector, Decision, DecisionSink, DialFn, DnsMap, GuardedConnector,
    Limits, Proxy, Rejected, ResolveFn, Verdict,
};

/// Env var selecting the child role (single parameter; targets are
/// hard-coded per role).
const ROLE_ENV: &str = "SBX_PT_ROLE";
/// Prefix of every payload marker line on stdout.
const MARKER: &str = "SBX-PT-MARKER";
/// Every wait in this suite is bounded by this deadline (design: 5 s).
const BOUND: Duration = Duration::from_secs(5);
/// TEST-NET-3 (RFC 5737) — the mapped fake IP the payload roles dial.
const TEST3: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
/// The unmapped TEST-NET-3 twin (unknown-fake-IP scenarios).
const TEST3_UNMAPPED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
/// The allowed name every relay scenario uses.
const ALLOWED: &str = "allowed.test";
/// The mapped-but-not-allowed name (AC: notallowed vs allowed).
const NOTALLOWED: &str = "notallowed.test";
/// The SNI the mismatch role sends.
const EVIL: &str = "evil.test";

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // Role dispatch FIRST — before any thread is spawned: child roles must
    // be single-threaded (the unshare invariant, sandbox_init D12/R20).
    if let Ok(role) = std::env::var(ROLE_ENV) {
        return child_main(&role);
    }

    let userns_ok = preflight_userns();
    let origdst_ok = preflight_origdst();
    let (mut passed, mut failed, mut skipped) = (0u32, 0u32, 0u32);
    // The F8 canary runs first and is the ONE scenario that reports its
    // own SKIP: where the conntrack lookup is unavailable it prints the
    // guidance line instead of failing (the host-netns tier then skips by
    // gate). PASS/SKIP here never affects the exit code.
    match probe_origdst() {
        Ok(()) => {
            println!("PASS origdst-probe");
            passed += 1;
        }
        Err(err) => {
            println!("SKIP origdst-probe: {ORIGDST_SKIP} ({err})");
            skipped += 1;
        }
    }
    for sc in scenarios() {
        if !sc.gate.satisfied(userns_ok, origdst_ok) {
            println!("SKIP {}: {}", sc.name, sc.gate.skip_reason());
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
    println!("sandbox_proxy: {passed} passed, {failed} failed, {skipped} skipped");
    // SKIPs exit 0; any FAIL exits 1.
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What a scenario needs to run at all. (The design's third gate,
/// `Always`, folded into the runner itself: the only Always-gated
/// scenario is the `origdst-probe` canary, which the runner executes
/// inline so it can print its SKIP-guidance outcome.)
#[derive(Clone, Copy)]
enum Gate {
    /// The host must support the `SO_ORIGINAL_DST` conntrack lookup (the
    /// F8 host-netns tier).
    OrigDst,
    /// Unprivileged user+net namespaces must work (the full-chain tier).
    Userns,
}

impl Gate {
    fn satisfied(self, userns_ok: bool, origdst_ok: bool) -> bool {
        match self {
            Gate::OrigDst => origdst_ok,
            Gate::Userns => userns_ok,
        }
    }

    fn skip_reason(self) -> &'static str {
        match self {
            Gate::OrigDst => ORIGDST_SKIP,
            Gate::Userns => USERNS_SKIP,
        }
    }
}

/// VERBATIM the sandbox_init.rs pin (same cause, same words).
const USERNS_SKIP: &str = "unprivileged userns unavailable (AppArmor? CI: sysctl kernel.apparmor_restrict_unprivileged_userns=0)";
const ORIGDST_SKIP: &str = "SO_ORIGINAL_DST unavailable on this host (nf_conntrack?)";

struct Scenario {
    name: &'static str,
    gate: Gate,
    run: fn() -> Result<(), String>,
}

/// The 16 gated scenarios (the design's table minus the origdst-probe
/// canary, which the runner handles inline): the six host-netns F8-tier
/// ones and the ten full-chain userns ones.
fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "hostnet-unknown-fake-ip",
            gate: Gate::OrigDst,
            run: scenario_hostnet_unknown_fake_ip,
        },
        Scenario {
            name: "hostnet-port-denied",
            gate: Gate::OrigDst,
            run: scenario_hostnet_port_denied,
        },
        Scenario {
            name: "hostnet-not-allowed",
            gate: Gate::OrigDst,
            run: scenario_hostnet_not_allowed,
        },
        Scenario {
            name: "hostnet-no-inspector",
            gate: Gate::OrigDst,
            run: scenario_hostnet_no_inspector,
        },
        Scenario {
            name: "hostnet-exactly-one-decision",
            gate: Gate::OrigDst,
            run: scenario_hostnet_exactly_one_decision,
        },
        Scenario {
            name: "hostnet-serve-stop",
            gate: Gate::OrigDst,
            run: scenario_hostnet_serve_stop,
        },
        Scenario {
            name: "tls-allowed-relay-443",
            gate: Gate::Userns,
            run: scenario_tls_allowed_relay_443,
        },
        Scenario {
            name: "tls-second-hello-torn-down",
            gate: Gate::Userns,
            run: scenario_tls_second_hello_torn_down,
        },
        Scenario {
            name: "http-allowed-relay-80",
            gate: Gate::Userns,
            run: scenario_http_allowed_relay_80,
        },
        Scenario {
            name: "sni-mismatch-denied",
            gate: Gate::Userns,
            run: scenario_sni_mismatch_denied,
        },
        Scenario {
            name: "missing-sni-denied",
            gate: Gate::Userns,
            run: scenario_missing_sni_denied,
        },
        Scenario {
            name: "plaintext-on-443-denied",
            gate: Gate::Userns,
            run: scenario_plaintext_on_443_denied,
        },
        Scenario {
            name: "notallowed-host-denied",
            gate: Gate::Userns,
            run: scenario_notallowed_host_denied,
        },
        Scenario {
            name: "unknown-fake-ip-netns",
            gate: Gate::Userns,
            run: scenario_unknown_fake_ip_netns,
        },
        Scenario {
            name: "rebinding-denied-netns",
            gate: Gate::Userns,
            run: scenario_rebinding_denied_netns,
        },
        Scenario {
            name: "port-not-in-policy-netns",
            gate: Gate::Userns,
            run: scenario_port_not_in_policy_netns,
        },
    ]
}

/// Preflight: can THIS host do unprivileged userns+netns at all? Spawns
/// the `probe-userns` role (a fresh single-threaded process) and gates the
/// full-chain tier on its rc (sandbox_init's exact mechanism).
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

/// Preflight: does `SO_ORIGINAL_DST` work on this host (the F8
/// own-address fallback the host-netns tier exploits)?
fn preflight_origdst() -> bool {
    probe_origdst().is_ok()
}

/// The F8 canary body: loopback connect ⇒ the lookup on the ACCEPTED
/// socket returns the connection's own destination. Byte pattern copied
/// from sandbox_init's pinned `original_dst()`.
fn probe_origdst() -> Result<(), String> {
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let _client = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let (accepted, _peer) = listener.accept().map_err(|e| e.to_string())?;
    let got = orig_dst_of(&accepted)?;
    if got != SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port()) {
        return Err(format!(
            "F8 own-address mismatch: got {got}, want 127.0.0.1:{}",
            addr.port()
        ));
    }
    Ok(())
}

/// `SO_ORIGINAL_DST` on an accepted stream — the suite-side twin of the
/// production [`sbx::proxy`] lookup (same byte pattern: `s_addr` octets
/// as-is, `sin_port` big-endian).
fn orig_dst_of(stream: &TcpStream) -> Result<SocketAddrV4, String> {
    // SAFETY: zeroed sockaddr_in written only by the kernel through the
    // getsockopt out-pointer.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: plain getsockopt call with the out-buffer above.
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
    Ok(SocketAddrV4::new(ip, port))
}

// ---------------------------------------------------------------------------
// parent-side spawn machinery (sandbox_init.rs shape, minus the bwrap tier)
// ---------------------------------------------------------------------------

/// A spawned `sbx __init` with its drained stdio and the parent's
/// control-socket end.
struct Spawned {
    child: Child,
    parent_end: Option<OwnedFd>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

/// A reaped scenario child: rc + fully drained stdio.
struct PayloadOutcome {
    rc: i32,
    stdout: String,
    stderr: String,
}

/// The standard spawn: `sbx __init --fd <fd> -- <payload>` with the role
/// env and piped stdio. The child end is CLOEXEC-cleared only in the spawn
/// window and the parent's copy is dropped IMMEDIATELY after (R6).
fn spawn_init(role: &str, payload: &[OsString]) -> Result<Spawned, String> {
    let (parent_end, child_end) =
        fdpass::control_socketpair().map_err(|e| format!("control_socketpair: {e}"))?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd())
        .map_err(|e| format!("prepare_child_end: {e}"))?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.arg("__init").arg("--fd").arg(child_fd.to_string());
    cmd.arg("--");
    cmd.args(payload);
    cmd.env(ROLE_ENV, role);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("spawn sbx __init: {e}"))?;
    let stdout = reader_thread(child.stdout.take().expect("stdout is piped"));
    let stderr = reader_thread(child.stderr.take().expect("stderr is piped"));
    // R6: drop the parent's copy of the child end IMMEDIATELY after spawn.
    drop(child_end);
    Ok(Spawned {
        child,
        parent_end: Some(parent_end),
        stdout,
        stderr,
    })
}

/// Spawn the role binary as the payload: `__init -- <current_exe>` with
/// `SBX_PT_ROLE` selecting the checks (env survives the exec chain).
fn payload_self() -> Result<Vec<OsString>, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    Ok(vec![exe.into()])
}

fn reader_thread<R: Read + Send + 'static>(mut src: R) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = String::new();
        // Bounded: EOF arrives once every write end is closed — i.e.
        // after reap or kill.
        let _ = src.read_to_string(&mut buf);
        buf
    })
}

/// `try_wait` polled at 10 ms; on deadline expiry kill + reap + Err (FAIL).
fn wait_bounded(child: &mut Child, what: &str) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + BOUND;
    loop {
        match child
            .try_wait()
            .map_err(|e| format!("try_wait {what}: {e}"))?
        {
            Some(status) => return Ok(status),
            None => {
                if Instant::now() >= deadline {
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
fn finish(mut sp: Spawned, what: &str) -> Result<PayloadOutcome, String> {
    let wait = wait_bounded(&mut sp.child, what);
    let stdout = sp
        .stdout
        .join()
        .map_err(|_| format!("{what}: stdout reader panicked"))?;
    let stderr = sp
        .stderr
        .join()
        .map_err(|_| format!("{what}: stderr reader panicked"))?;
    let status = wait?;
    Ok(PayloadOutcome {
        rc: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// RAII orphan guard (m3): EVERY exit path between spawning `sbx __init`
/// and [`finish`]'s normal reap — an `?` early return or a panic unwind —
/// must kill + reap the child and drain its reader threads. An orphaned
/// `__init` would linger for its full GO_TIMEOUT (30 s) holding its netns
/// alive and then zombie; unjoined reader threads would violate the R6
/// spawn-window discipline. Disarmed by [`SpawnedGuard::take`] on the
/// normal path (`finish` performs the same kill-on-timeout + joins itself).
struct SpawnedGuard(Option<Spawned>);

impl SpawnedGuard {
    fn new(spawned: Spawned) -> Self {
        Self(Some(spawned))
    }

    /// Borrow for the protocol steps (recv_fds / send_go) while armed.
    fn borrow(&self) -> &Spawned {
        self.0.as_ref().expect("spawned guard used after disarm")
    }

    /// Disarm and hand ownership to [`finish`] (the normal reap path).
    fn take(&mut self) -> Spawned {
        self.0.take().expect("spawned guard used after disarm")
    }
}

impl Drop for SpawnedGuard {
    fn drop(&mut self) {
        if let Some(mut sp) = self.0.take() {
            // Kill FIRST: the reader threads' pipes hit EOF only once the
            // child (and any exec'd payload) dies, which bounds the joins.
            let _ = sp.child.kill();
            let _ = sp.child.wait();
            let _ = sp.stdout.join();
            let _ = sp.stderr.join();
        }
    }
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

/// Payload rc + marker assertions (sandbox_init's `assert_success` shape).
fn assert_payload_success(out: &PayloadOutcome, markers: &[&str]) -> Result<(), String> {
    if out.rc != 0 {
        return Err(format!(
            "payload rc {} (expected 0)\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.rc, out.stdout, out.stderr
        ));
    }
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

/// The pinned teardown: `shutdown(SHUT_RDWR)` on a held `try_clone` of the
/// listener (std's TcpListener has no shutdown method — the raw sockopt on
/// the shared socket is the call) ⇒ accept EINVAL ⇒ `serve` exits.
fn shutdown_listener(listener: &TcpListener) -> Result<(), String> {
    // SAFETY: shutdown(2) on the listener's own valid fd; affecting the
    // shared socket is the point.
    let rc = unsafe { libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR) };
    if rc != 0 {
        return Err(format!("shutdown listener: {}", io::Error::last_os_error()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// test doubles for the three seams (the suite cannot see cfg(test) items)
// ---------------------------------------------------------------------------

struct StaticMap(HashMap<Ipv4Addr, Domain>);

impl StaticMap {
    fn new(pairs: &[(Ipv4Addr, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(ip, name)| (*ip, Domain::parse(name).expect("fixture name must parse")))
                .collect(),
        )
    }
}

impl DnsMap for StaticMap {
    fn name_for(&self, ip: Ipv4Addr) -> Option<Domain> {
        self.0.get(&ip).cloned()
    }
}

#[derive(Default)]
struct RecordingSink {
    decisions: Mutex<Vec<Decision>>,
    teardowns: Mutex<Vec<String>>,
}

impl RecordingSink {
    fn recorded(&self) -> Vec<Decision> {
        self.decisions.lock().expect("sink lock").clone()
    }
    fn teardowns(&self) -> Vec<String> {
        self.teardowns.lock().expect("sink lock").clone()
    }
}

impl DecisionSink for RecordingSink {
    fn record(&self, decision: &Decision) {
        self.decisions
            .lock()
            .expect("sink lock")
            .push(decision.clone());
    }
    fn teardown(&self, _decision: &Decision, detail: &str) {
        self.teardowns
            .lock()
            .expect("sink lock")
            .push(detail.to_owned());
    }
}

/// The pinned relay teardown detail for a second ClientHello
/// (`sbx::proxy::relay`'s `TORN_DOWN_SECOND_HELLO` — pub(crate) there, so
/// the literal is duplicated here under the same contract as the exact
/// deny-reason strings; the unit tier pins the constant itself).
const TORN_DOWN_SECOND_HELLO_DETAIL: &str =
    "relay torn down: second TLS ClientHello after the inspected handshake";

type ConnectorLog = Arc<Mutex<Vec<String>>>;

fn connector_log() -> ConnectorLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn log_of(log: &ConnectorLog) -> Vec<String> {
    log.lock().expect("connector log").clone()
}

/// The relay-scenario connector double: records `"{name}:{port}"` requests
/// and dials the parent-side echo server. The guard is DELIBERATELY
/// bypassed in this double — the echo target is loopback (guard-denied by
/// design) and the guard logic is unit-pinned (`private_rebinding_denied_
/// at_resolve`, `guard_applies_to_every_resolved_address`,
/// `peer_addr_recheck_is_the_rebinding_backstop`).
struct EchoConnector {
    target: SocketAddr,
    log: ConnectorLog,
}

impl Connector for EchoConnector {
    fn connect(
        &self,
        name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
        // Computed OUTSIDE the async block: the returned future borrows
        // only `&self` (the trait's `'_`), never the shorter-lived `name`.
        let request = format!("{}:{port}", name.as_str());
        Box::pin(async move {
            self.log.lock().expect("connector log").push(request);
            let stream = tokio::net::TcpStream::connect(self.target)
                .await
                .map_err(|e| ConnectError::Connect {
                    detail: e.to_string(),
                })?;
            let _ = stream.set_nodelay(true);
            let peer = stream.peer_addr().map_err(|e| ConnectError::Connect {
                detail: e.to_string(),
            })?;
            Ok(Connected {
                stream: Box::new(stream),
                peer,
            })
        })
    }
}

/// The denial-scenario connector double: any call is a scenario bug —
/// recorded (for the assertion message) and failed.
struct NeverConnector {
    log: ConnectorLog,
}

impl Connector for NeverConnector {
    fn connect(
        &self,
        name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
        // Computed OUTSIDE the async block (same lifetime reason as
        // EchoConnector).
        let request = format!("{}:{port}", name.as_str());
        Box::pin(async move {
            self.log.lock().expect("connector log").push(request);
            Err(ConnectError::Connect {
                detail: "connector must not be called".to_owned(),
            })
        })
    }
}

/// Echo server on 127.0.0.1:0 — accept ONE connection, read-to-end,
/// report the exact bytes received. In [`EchoMode::OnEof`] the write-back
/// happens after read-to-end (deterministic because the roles
/// `shutdown(Write)` after writing); in [`EchoMode::Immediate`] every chunk
/// is echoed as it arrives (best-effort — the teardown scenarios' proof is
/// the RECEIVED bytes). Bounded by construction: non-blocking accept
/// polled at 10 ms against `BOUND`, a stop flag for expect-miss scenarios,
/// socket timeouts on the served stream.
#[derive(Debug)]
enum EchoOutcome {
    /// Served one connection; carries the exact bytes received (the
    /// replay-correctness proof).
    Hit(Vec<u8>),
    /// The stop flag was set and no connection ever arrived (the final
    /// accept sweep ran first, so this is race-free).
    StoppedClean,
    /// No connection within BOUND.
    Deadline,
    Failed(String),
}

struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<EchoOutcome>>,
}

impl EchoServer {
    /// The bounded outcome collection: the stop flag is set FIRST for
    /// expect-miss scenarios (the thread's accept attempt doubles as the
    /// final sweep, so a connection racing the flag is still served), then
    /// the thread is joined.
    fn into_outcome(mut self, expect_miss: bool) -> Result<EchoOutcome, String> {
        if expect_miss {
            self.stop.store(true, Ordering::SeqCst);
        }
        self.handle
            .take()
            .expect("echo handle is taken exactly once")
            .join()
            .map_err(|_| "echo thread panicked".to_owned())
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        // Bounded hygiene on EVERY still-owned path (an error early-return
        // before the normal teardown): set the stop flag and join, so no
        // echo thread survives into the next scenario's spawn window (R6).
        // The poll loop exits within one 10 ms tick.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_echo_server(mode: EchoMode) -> Result<EchoServer, String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("echo bind: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("echo set_nonblocking: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("echo local_addr: {e}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + BOUND;
        loop {
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    let served = (|| -> Result<Vec<u8>, String> {
                        stream
                            .set_read_timeout(Some(BOUND))
                            .map_err(|e| format!("echo set_read_timeout: {e}"))?;
                        let mut buf = Vec::new();
                        match mode {
                            EchoMode::OnEof => {
                                stream
                                    .read_to_end(&mut buf)
                                    .map_err(|e| format!("echo read_to_end: {e}"))?;
                                stream
                                    .write_all(&buf)
                                    .map_err(|e| format!("echo write_all: {e}"))?;
                            }
                            EchoMode::Immediate => {
                                let mut chunk = [0u8; 4096];
                                loop {
                                    match stream.read(&mut chunk) {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            buf.extend_from_slice(&chunk[..n]);
                                            // Best-effort: the teardown
                                            // scenarios' proxy may already
                                            // have dropped the socket — the
                                            // RECEIVED bytes are the proof
                                            // (EchoMode::Immediate docs).
                                            if stream.write_all(&chunk[..n]).is_err() {
                                                break;
                                            }
                                        }
                                        Err(err) => {
                                            return Err(format!("echo read: {err}"));
                                        }
                                    }
                                }
                            }
                        }
                        Ok(buf)
                    })();
                    return match served {
                        Ok(buf) => EchoOutcome::Hit(buf),
                        Err(err) => EchoOutcome::Failed(err),
                    };
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // The accept attempt above IS the final sweep: stop is
                    // checked only after an accept came up empty, so a
                    // connection racing the stop flag is still served.
                    if stop_flag.load(Ordering::SeqCst) {
                        return EchoOutcome::StoppedClean;
                    }
                    if Instant::now() >= deadline {
                        return EchoOutcome::Deadline;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return EchoOutcome::Failed(format!("echo accept: {err}")),
            }
        }
    });
    Ok(EchoServer {
        addr,
        stop,
        handle: Some(handle),
    })
}

fn policy_network(allow: &[&str], ports: &[u16]) -> policy::Network {
    policy::Network {
        mode: policy::NetworkMode::Transparent,
        allow: allow
            .iter()
            .map(|name| Domain::parse(name).expect("fixture name must parse"))
            .collect(),
        ports: ports.to_vec(),
    }
}

/// Which connector double the scenario runs with.
#[derive(Clone, Copy)]
enum ConnectorSpec {
    /// [`EchoConnector`] to the spawned echo server (relay scenarios).
    Echo,
    /// [`NeverConnector`] — any call fails the scenario.
    Never,
    /// The REAL [`GuardedConnector`] with a scripted resolve →
    /// `10.0.0.1:443` and a dial that must never run (the rebinding AC).
    Rebinding,
}

/// Whether an echo server is spawned and what its absence/presence proves.
#[derive(Clone, Copy)]
enum EchoSpec {
    None,
    ExpectHit,
    ExpectMiss,
    /// Like `ExpectHit`, but the server echoes every chunk IMMEDIATELY
    /// (not after read-to-end) — the second-hello role needs the CH1 echo
    /// back as its signal that the relay phase is live (R12: signal-driven,
    /// no fixed sleeps).
    ExpectHitEchoing,
}

/// The echo server's write-back discipline.
#[derive(Clone, Copy)]
enum EchoMode {
    /// Read-to-end, then write everything back (the half-duplex contract
    /// the relay roles' `shutdown(Write)` makes deterministic).
    OnEof,
    /// Echo every chunk as it arrives; the write-back is best-effort (a
    /// teardown scenario's proxy has already dropped the socket — the
    /// RECEIVED bytes are the proof there, and the role side asserts the
    /// echoed prefix independently).
    Immediate,
}

/// One serve thread on its own current-thread runtime; the result travels
/// over a channel so every wait is bounded.
struct ServeHandle {
    thread: JoinHandle<()>,
    rx: Receiver<io::Result<()>>,
    stopper: TcpListener,
}

impl ServeHandle {
    /// The pinned teardown path (bounded).
    fn stop(self) -> Result<io::Result<()>, String> {
        shutdown_listener(&self.stopper)?;
        let result = self
            .rx
            .recv_timeout(BOUND)
            .map_err(|e| format!("serve thread did not exit after shutdown: {e}"))?;
        self.thread.join().map_err(|_| "serve thread panicked")?;
        Ok(result)
    }
}

/// Start [`sbx::proxy::serve`] on a dedicated thread — the listener moves
/// in; the returned handle tears down via the pinned shutdown path.
fn spawn_serve(listener: TcpListener, proxy: Arc<Proxy>) -> Result<ServeHandle, String> {
    let stopper = listener
        .try_clone()
        .map_err(|e| format!("try_clone: {e}"))?;
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let result = runtime
            .block_on(sbx::proxy::serve(listener, proxy))
            .map(|never| match never {});
        let _ = tx.send(result);
    });
    Ok(ServeHandle {
        thread,
        rx,
        stopper,
    })
}

// ---------------------------------------------------------------------------
// the userns full-chain harness
// ---------------------------------------------------------------------------

/// Everything a full-chain scenario asserts on, collected AFTER a complete
/// spawn → serve → go → payload → teardown cycle (teardown runs even when
/// the payload failed, so a wedged scenario never leaks the serve thread).
struct NetnsRun {
    payload: PayloadOutcome,
    decisions: Vec<Decision>,
    teardowns: Vec<String>,
    connector_log: Vec<String>,
    dial_ran: bool,
    echo_addr: Option<SocketAddr>,
    echo: Option<EchoOutcome>,
}

fn run_netns(
    role: &str,
    map: &[(Ipv4Addr, &str)],
    allow: &[&str],
    ports: &[u16],
    connector: ConnectorSpec,
    echo: EchoSpec,
) -> Result<NetnsRun, String> {
    let echo_server = match echo {
        EchoSpec::None => None,
        EchoSpec::ExpectHit | EchoSpec::ExpectMiss => Some(spawn_echo_server(EchoMode::OnEof)?),
        EchoSpec::ExpectHitEchoing => Some(spawn_echo_server(EchoMode::Immediate)?),
    };
    // Captured up front: the echo server itself moves into the teardown
    // join below, but the relay scenarios assert `upstream == echo addr`.
    let echo_addr = echo_server.as_ref().map(|srv| srv.addr);
    let sp = spawn_init(role, &payload_self()?)?;
    // m3: from here on, EVERY exit (error return or panic unwind) reaps
    // the child — the guard kills + waits + joins the readers unless
    // disarmed by take() into finish() below.
    let mut sp_guard = SpawnedGuard::new(sp);
    let fdpass::ListenerFds {
        transparent,
        explicit,
        dns,
    } = recv_fds(sp_guard.borrow())?;

    let sink = Arc::new(RecordingSink::default());
    let log = connector_log();
    let dial_ran = Arc::new(AtomicBool::new(false));
    let connector_arc: Arc<dyn Connector> = match connector {
        ConnectorSpec::Echo => Arc::new(EchoConnector {
            target: echo_server
                .as_ref()
                .expect("ConnectorSpec::Echo implies EchoSpec::Hit")
                .addr,
            log: Arc::clone(&log),
        }),
        ConnectorSpec::Never => Arc::new(NeverConnector {
            log: Arc::clone(&log),
        }),
        ConnectorSpec::Rebinding => {
            // The REAL GuardedConnector with the AC's scripted rebinding
            // answer: resolve → 10.0.0.1:443 (RFC 1918) and a dial that
            // must NEVER run (flag + fail).
            let resolve: ResolveFn = Arc::new(|_name: &str, _port: u16| {
                Box::pin(async {
                    Ok(vec![SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(10, 0, 0, 1),
                        443,
                    ))])
                })
            });
            let flag = Arc::clone(&dial_ran);
            let dial: DialFn = Arc::new(move |_name: &str, _port: u16| {
                let flag = Arc::clone(&flag);
                Box::pin(async move {
                    flag.store(true, Ordering::SeqCst);
                    Err(io::Error::other(
                        "the dial must never run past the resolve guard",
                    ))
                })
            });
            Arc::new(GuardedConnector::new(
                resolve,
                dial,
                Duration::from_secs(10),
            ))
        }
    };
    let network = policy_network(allow, ports);
    let proxy = Proxy::new(
        &network,
        Arc::new(StaticMap::new(map)),
        sink.clone(),
        connector_arc,
        Limits::default(),
    );

    // THE go guarantee (fdpass): serving starts BEFORE the go byte.
    let serve = spawn_serve(transparent, proxy)?;
    let go = send_go(sp_guard.borrow());
    // finish() disarms the guard on the normal path; a go-byte failure
    // leaves it armed, so the drop below kills the still-waiting child.
    let payload = go.and_then(|()| finish(sp_guard.take(), role));

    // Teardown ALWAYS runs (a failed payload must not leak the serve
    // thread into the next scenario's spawn window — R6).
    let serve_stop = serve.stop();
    let echo_outcome = echo_server
        .map(|srv| srv.into_outcome(matches!(echo, EchoSpec::ExpectMiss)))
        .transpose();
    // The explicit + dns fds are held until the payload is reaped, then
    // dropped here (no listener-gone races while the payload runs).
    drop((explicit, dns));

    let payload = payload?;
    // serve must exit with the shutdown error (the exact EINVAL errno is
    // pinned by the unit tier and hostnet-serve-stop; Ok is impossible —
    // serve returns Infallible on the loop path).
    match serve_stop? {
        Err(_) => {}
        Ok(()) => return Err("serve returned Ok — impossible (Infallible)".to_owned()),
    }
    Ok(NetnsRun {
        payload,
        decisions: sink.recorded(),
        teardowns: sink.teardowns(),
        connector_log: log_of(&log),
        dial_ran: dial_ran.load(Ordering::SeqCst),
        echo_addr,
        echo: echo_outcome?,
    })
}

/// The single-decision assertion with the exact reason (every denial
/// scenario pins the #10 audit text byte-exactly).
fn assert_single_decision(
    decisions: &[Decision],
    expected: &Verdict,
    expected_reason: &str,
) -> Result<(), String> {
    if decisions.len() != 1 {
        return Err(format!(
            "expected exactly ONE recorded decision, got {}: {decisions:?}",
            decisions.len()
        ));
    }
    let decision = &decisions[0];
    if decision.verdict != *expected {
        return Err(format!(
            "verdict mismatch:\n  got:  {:?} ({})\n  want: {expected:?} ({expected_reason})",
            decision.verdict,
            decision.reason()
        ));
    }
    if decision.reason() != expected_reason {
        return Err(format!(
            "reason mismatch:\n  got:  {:?}\n  want: {expected_reason:?}",
            decision.reason()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// scenarios: the host-netns F8 tier
// ---------------------------------------------------------------------------

/// What the host-netns client does.
enum HostnetClient {
    /// No connection at all (serve-stop).
    Absent,
    /// Connect and send nothing (denials that precede any read).
    Silent,
    /// Connect, send these bytes, then read (denial with client data —
    /// the write may hit EPIPE/reset, which is tolerated: the denial can
    /// legitimately close the socket before reading).
    Send(Vec<u8>),
}

struct HostnetRun {
    port: u16,
    decisions: Vec<Decision>,
    received: Vec<u8>,
    serve_result: io::Result<()>,
}

/// Serve [`sbx::proxy::serve`] on an ephemeral 127.0.0.1 listener in the
/// HOST netns: F8 makes `SO_ORIGINAL_DST` report `127.0.0.1:{port}` (the
/// connection's own destination), which is exactly the unknown/denied
/// shapes these scenarios assert — and a built-in ordering canary (if the
/// guard ever ran before the map, 127.0.0.1 would surface as a Loopback
/// DialDenied instead of the pinned verdicts).
fn run_hostnet(
    allow: &[&str],
    map: &[(Ipv4Addr, &str)],
    ports_fn: impl FnOnce(u16) -> Vec<u16>,
    client: HostnetClient,
) -> Result<HostnetRun, String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let port = addr.port();
    if port == 443 || port == 80 {
        // Ephemeral allocation must never collide with an inspected port
        // (practically impossible; the no-inspector scenario depends on it).
        return Err(format!(
            "ephemeral port {port} collides with an inspector port"
        ));
    }
    let sink = Arc::new(RecordingSink::default());
    let log = connector_log();
    let network = policy_network(allow, &ports_fn(port));
    let proxy = Proxy::new(
        &network,
        Arc::new(StaticMap::new(map)),
        sink.clone(),
        Arc::new(NeverConnector {
            log: Arc::clone(&log),
        }),
        Limits::default(),
    );
    // Stays BLOCKING on purpose — serve flips it (the fdpass contract;
    // pinned by the unit tier's serve_flips_nonblocking_itself).
    let serve = spawn_serve(listener, proxy)?;

    let connects = !matches!(client, HostnetClient::Absent);
    let mut received = Vec::new();
    if let HostnetClient::Silent | HostnetClient::Send(_) = &client {
        let mut stream =
            TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_read_timeout(Some(BOUND))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        if let HostnetClient::Send(bytes) = &client {
            let _ = stream.write_all(bytes);
            let _ = stream.shutdown(Shutdown::Write);
        }
        // Read to EOF-or-reset; ANY relayed byte fails the scenario
        // (every host-netns shape is a denial).
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(format!("client read: {e}")),
            }
        }
    }

    // Bounded wait for the decision (recorded before the close the client
    // just observed, so this exits on the first poll in practice).
    let deadline = Instant::now() + BOUND;
    while connects && sink.recorded().is_empty() {
        if Instant::now() >= deadline {
            break; // let the scenario assertion report the emptiness
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let serve_result = serve.stop()?;
    if !log_of(&log).is_empty() {
        return Err(format!(
            "the connector must never be called in the host-netns tier: {:?}",
            log_of(&log)
        ));
    }
    Ok(HostnetRun {
        port,
        decisions: sink.recorded(),
        received,
        serve_result,
    })
}

/// AC unknown-fake-IP (host-netns shape): 127.0.0.1 has no map entry ⇒
/// deny with the exact reason, zero bytes relayed, orig-dst = the F8 own
/// address.
fn scenario_hostnet_unknown_fake_ip() -> Result<(), String> {
    let run = run_hostnet(&[], &[], |port| vec![port], HostnetClient::Silent)?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::UnknownFakeIp {
            ip: Ipv4Addr::LOCALHOST,
        }),
        "unknown fake IP 127.0.0.1 (no DNS-map entry)",
    )?;
    if !run.received.is_empty() {
        return Err(format!(
            "denied connection received bytes: {:?}",
            run.received
        ));
    }
    let orig = run.decisions[0].orig_dst;
    if orig != Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, run.port)) {
        return Err(format!(
            "F8 own-address orig_dst: got {orig:?}, want 127.0.0.1:{}",
            run.port
        ));
    }
    if run.serve_result.is_ok() {
        return Err("serve must exit with the shutdown error".to_owned());
    }
    Ok(())
}

/// AC port policy: an empty `network.ports` denies BEFORE the map (the
/// first pipeline step).
fn scenario_hostnet_port_denied() -> Result<(), String> {
    let run = run_hostnet(&[], &[], |_| vec![], HostnetClient::Silent)?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::PortNotAllowed { port: run.port }),
        &format!("port {} is not in the policy port list", run.port),
    )?;
    if !run.received.is_empty() {
        return Err(format!(
            "denied connection received bytes: {:?}",
            run.received
        ));
    }
    Ok(())
}

/// AC non-allowed host: mapped to notallowed.test, allow-listed
/// allowed.test ⇒ NotAllowed — and the denial happens BEFORE any read (the
/// client sends nothing).
fn scenario_hostnet_not_allowed() -> Result<(), String> {
    let run = run_hostnet(
        &[ALLOWED],
        &[(Ipv4Addr::LOCALHOST, NOTALLOWED)],
        |port| vec![port],
        HostnetClient::Silent,
    )?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::NotAllowed {
            name: Domain::parse(NOTALLOWED).expect("fixture"),
        }),
        "notallowed.test is not in the policy allow list",
    )?;
    Ok(())
}

/// Q1 end-to-end: an allowed name on a policy-listed port with no v1
/// inspector (the ephemeral port ∉ {443, 80}) denies.
fn scenario_hostnet_no_inspector() -> Result<(), String> {
    let run = run_hostnet(
        &[ALLOWED],
        &[(Ipv4Addr::LOCALHOST, ALLOWED)],
        |port| vec![port],
        HostnetClient::Silent,
    )?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::NoInspector { port: run.port }),
        &format!("no protocol inspector for port {} in v1", run.port),
    )?;
    Ok(())
}

/// Exactly one recorded decision over a full serve → deny → close cycle,
/// even with client bytes in flight.
fn scenario_hostnet_exactly_one_decision() -> Result<(), String> {
    let run = run_hostnet(
        &[],
        &[],
        |port| vec![port],
        HostnetClient::Send(b"PING".to_vec()),
    )?;
    if run.decisions.len() != 1 {
        return Err(format!(
            "expected exactly ONE decision, got {}: {:?}",
            run.decisions.len(),
            run.decisions
        ));
    }
    if !run.received.is_empty() {
        return Err(format!(
            "denied connection received bytes: {:?}",
            run.received
        ));
    }
    Ok(())
}

/// The teardown contract: with no client at all, `shutdown` ends `serve`
/// bounded and with the pinned EINVAL error (the #10/suite stop mechanism).
fn scenario_hostnet_serve_stop() -> Result<(), String> {
    let run = run_hostnet(&[], &[], |_| vec![], HostnetClient::Absent)?;
    if !run.decisions.is_empty() {
        return Err(format!("no connection ⇒ no decisions: {:?}", run.decisions));
    }
    let err = run
        .serve_result
        .expect_err("shutdown must end serve with an error");
    if err.raw_os_error() != Some(libc::EINVAL) {
        return Err(format!(
            "expected the pinned EINVAL teardown path, got {err}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// scenarios: the userns full-chain tier
// ---------------------------------------------------------------------------

/// The exact bytes the pt-tls-ok role sends (parent side needs them for
/// the echo-equality assertion — one builder, both sides).
fn tls_relay_payload() -> Vec<u8> {
    let mut bytes = build_client_hello(Some(ALLOWED), &[]);
    bytes.extend_from_slice(b"PING");
    bytes
}

/// The exact bytes the pt-http-ok role sends.
fn http_relay_payload() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\nbody".to_vec()
}

/// The exact bytes the proxy replays upstream for [`http_relay_payload`]:
/// the validated head with `Connection: close` inserted before the final
/// CRLF (http.rs module docs point 6 — the name binding's
/// connection-lifetime enforcement), the body byte-identical.
fn http_relay_expected() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\nbody".to_vec()
}

/// AC allowed host works (443): the ClientHello + pipelined bytes pass
/// through the real REDIRECT, are replayed verbatim to the echo upstream,
/// and the echo comes back — with exactly one Allowed decision, the
/// connector dialed BY NAME, and the fake IP never appearing.
fn scenario_tls_allowed_relay_443() -> Result<(), String> {
    let run = run_netns(
        "pt-tls-ok",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Echo,
        EchoSpec::ExpectHit,
    )?;
    assert_payload_success(&run.payload, &["relay ok"])?;
    let expected = tls_relay_payload();
    match run.echo {
        Some(EchoOutcome::Hit(ref bytes)) if *bytes == expected => {}
        Some(EchoOutcome::Failed(ref err)) => {
            return Err(format!("the echo server failed: {err}"));
        }
        ref other => {
            return Err(format!(
                "the echo server must receive the EXACT payload (proves the replay \
                 carried the hello + pipelined bytes): {other:?}"
            ));
        }
    }
    let upstream = run.echo_addr.expect("echo server was spawned");
    assert_single_decision(
        &run.decisions,
        &Verdict::Allowed {
            name: Domain::parse(ALLOWED).expect("fixture"),
            upstream,
        },
        &format!("allowed {ALLOWED} via {upstream}"),
    )?;
    if run.decisions[0].orig_dst != Some(SocketAddrV4::new(TEST3, 443)) {
        return Err(format!(
            "orig_dst must be the real pre-DNAT destination: {:?}",
            run.decisions[0].orig_dst
        ));
    }
    if !run.teardowns.is_empty() {
        return Err(format!(
            "a clean relay must never trip the teardown hook: {:?}",
            run.teardowns
        ));
    }
    if run.connector_log != [format!("{ALLOWED}:443")] {
        return Err(format!(
            "the connector must see exactly one by-name request: {:?}",
            run.connector_log
        ));
    }
    Ok(())
}

/// Review-fix pin (the second-hello defense, proxy module docs point 12):
/// after the Allowed decision and the byte-exact CH1 replay, a SECOND
/// ClientHello on the wire (the post-HRR CH2 shape, sent only once the
/// CH1 echo proves the relay phase is live) tears the relay down — the
/// upstream sees EXACTLY the first hello and never one byte of the
/// second, the single Allowed decision stays the only `record` (the
/// teardown is normal relay lifecycle), the teardown hook carries the
/// pinned second-hello detail (round-2 review fix — a blocked attack is
/// not audit-invisible), and the payload observes the close.
fn scenario_tls_second_hello_torn_down() -> Result<(), String> {
    let run = run_netns(
        "pt-tls-second-hello",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Echo,
        EchoSpec::ExpectHitEchoing,
    )?;
    assert_payload_success(&run.payload, &["second hello torn down"])?;
    let expected = build_client_hello(Some(ALLOWED), &[]);
    match run.echo {
        Some(EchoOutcome::Hit(ref bytes)) if *bytes == expected => {}
        Some(EchoOutcome::Failed(ref err)) => {
            return Err(format!("the echo server failed: {err}"));
        }
        ref other => {
            return Err(format!(
                "the upstream must see EXACTLY the first hello (the second must be \
                 withheld byte-for-byte): {other:?}"
            ));
        }
    }
    let upstream = run.echo_addr.expect("echo server was spawned");
    assert_single_decision(
        &run.decisions,
        &Verdict::Allowed {
            name: Domain::parse(ALLOWED).expect("fixture"),
            upstream,
        },
        &format!("allowed {ALLOWED} via {upstream}"),
    )?;
    // The teardown hook pin (round-2 review fix): exactly one teardown,
    // with the pinned second-hello detail — and NOT a second decision.
    if run.teardowns != [TORN_DOWN_SECOND_HELLO_DETAIL.to_owned()] {
        return Err(format!(
            "the blocked attack must surface on the sink's teardown hook with the pinned \
             detail: {:?}",
            run.teardowns
        ));
    }
    if run.connector_log != [format!("{ALLOWED}:443")] {
        return Err(format!(
            "the connector must see exactly one by-name request: {:?}",
            run.connector_log
        ));
    }
    Ok(())
}

/// AC allowed host works (80): the HTTP head + pipelined body relay
/// end-to-end with one Allowed decision — the upstream sees the head with
/// the inserted `Connection: close` (http.rs module docs point 6) and the
/// body byte-identical.
fn scenario_http_allowed_relay_80() -> Result<(), String> {
    let run = run_netns(
        "pt-http-ok",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Echo,
        EchoSpec::ExpectHit,
    )?;
    assert_payload_success(&run.payload, &["relay ok"])?;
    let expected = http_relay_expected();
    match run.echo {
        Some(EchoOutcome::Hit(ref bytes)) if *bytes == expected => {}
        Some(EchoOutcome::Failed(ref err)) => {
            return Err(format!("the echo server failed: {err}"));
        }
        ref other => {
            return Err(format!(
                "the echo server must receive the EXACT rewritten head + body: {other:?}"
            ));
        }
    }
    if !run.teardowns.is_empty() {
        return Err(format!(
            "a clean relay must never trip the teardown hook: {:?}",
            run.teardowns
        ));
    }
    let upstream = run.echo_addr.expect("echo server was spawned");
    assert_single_decision(
        &run.decisions,
        &Verdict::Allowed {
            name: Domain::parse(ALLOWED).expect("fixture"),
            upstream,
        },
        &format!("allowed {ALLOWED} via {upstream}"),
    )?;
    if run.decisions[0].orig_dst != Some(SocketAddrV4::new(TEST3, 80)) {
        return Err(format!(
            "orig_dst must be the real pre-DNAT destination: {:?}",
            run.decisions[0].orig_dst
        ));
    }
    if run.connector_log != [format!("{ALLOWED}:80")] {
        return Err(format!(
            "the connector must see exactly one by-name request: {:?}",
            run.connector_log
        ));
    }
    Ok(())
}

/// AC SNI ≠ name: denied, zero application bytes to the payload, exact
/// reason, connector never called.
fn scenario_sni_mismatch_denied() -> Result<(), String> {
    let run = run_netns(
        "pt-tls-sni-mismatch",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::SniMismatch {
            sni: Domain::parse(EVIL).expect("fixture"),
            name: Domain::parse(ALLOWED).expect("fixture"),
        }),
        "SNI evil.test does not match the DNS-map name allowed.test",
    )?;
    if !run.connector_log.is_empty() {
        return Err(format!(
            "connector must not be called: {:?}",
            run.connector_log
        ));
    }
    Ok(())
}

/// AC missing SNI.
fn scenario_missing_sni_denied() -> Result<(), String> {
    let run = run_netns(
        "pt-tls-no-sni",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::SniMissing),
        "missing or invalid SNI in the TLS ClientHello",
    )?;
    Ok(())
}

/// AC plaintext on 443: HTTP bytes to the TLS port ⇒ NotTls carrying the
/// first byte ('G' = 0x47).
fn scenario_plaintext_on_443_denied() -> Result<(), String> {
    let run = run_netns(
        "pt-plaintext",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::NotTls { first_byte: b'G' }),
        "non-TLS traffic on port 443 (first byte 0x47)",
    )?;
    Ok(())
}

/// AC non-allowed host denied+logged (full chain): the map says
/// notallowed.test, the policy allows allowed.test ⇒ NotAllowed, and the
/// echo server is NEVER hit.
fn scenario_notallowed_host_denied() -> Result<(), String> {
    let run = run_netns(
        "pt-denied-notallowed",
        &[(TEST3, NOTALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::ExpectMiss,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::NotAllowed {
            name: Domain::parse(NOTALLOWED).expect("fixture"),
        }),
        "notallowed.test is not in the policy allow list",
    )?;
    match run.echo {
        Some(EchoOutcome::StoppedClean) | Some(EchoOutcome::Deadline) => {}
        ref other => {
            return Err(format!("the echo server must NEVER be hit: {other:?}"));
        }
    }
    if !run.connector_log.is_empty() {
        return Err(format!(
            "connector must not be called: {:?}",
            run.connector_log
        ));
    }
    Ok(())
}

/// AC unknown fake IP under the real REDIRECT: the unmapped TEST-NET-3
/// twin denies with the exact reason.
fn scenario_unknown_fake_ip_netns() -> Result<(), String> {
    let run = run_netns(
        "pt-denied-unknown",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::UnknownFakeIp { ip: TEST3_UNMAPPED }),
        "unknown fake IP 203.0.113.9 (no DNS-map entry)",
    )?;
    if run.decisions[0].orig_dst != Some(SocketAddrV4::new(TEST3_UNMAPPED, 443)) {
        return Err(format!(
            "orig_dst must be the dialed unmapped twin: {:?}",
            run.decisions[0].orig_dst
        ));
    }
    Ok(())
}

/// AC private-address rebinding: the REAL GuardedConnector resolves to
/// 10.0.0.1 ⇒ the guard denies with the issue's exact string and the dial
/// never runs.
fn scenario_rebinding_denied_netns() -> Result<(), String> {
    let run = run_netns(
        "pt-denied-rebinding",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Rebinding,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::DialDenied {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443)),
            denied: sbx::egress::Denied::PrivateNetwork,
        }),
        // The acceptance-criteria string, byte-exact.
        "denied dial to 10.0.0.1:443: private-use address (RFC 1918)",
    )?;
    if run.dial_ran {
        return Err("the dial must never run — the resolve guard denied first".to_owned());
    }
    Ok(())
}

/// AC port policy under the real REDIRECT: the nftables redirect is
/// port-agnostic (rules.rs rule 1), so a TEST3:443 dial with ports=[80]
/// lands on the proxy and denies at the FIRST pipeline step.
fn scenario_port_not_in_policy_netns() -> Result<(), String> {
    let run = run_netns(
        "pt-denied-port",
        &[(TEST3, ALLOWED)],
        &[ALLOWED],
        &[80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["closed without application bytes"])?;
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::PortNotAllowed { port: 443 }),
        "port 443 is not in the policy port list",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// child side: role dispatch + roles
// ---------------------------------------------------------------------------

fn child_main(role: &str) -> ExitCode {
    let result = match role {
        "probe-userns" => role_probe_userns(),
        "pt-tls-ok" => {
            let payload = tls_relay_payload();
            role_relay(&payload, &payload, TEST3, 443)
        }
        "pt-tls-second-hello" => role_second_hello(),
        "pt-http-ok" => role_relay(&http_relay_payload(), &http_relay_expected(), TEST3, 80),
        "pt-tls-sni-mismatch" => {
            let hello = build_client_hello(Some(EVIL), &[]);
            role_expect_close(TEST3, 443, Some(&hello))
        }
        "pt-tls-no-sni" => {
            let hello = build_client_hello(None, &[]);
            role_expect_close(TEST3, 443, Some(&hello))
        }
        "pt-plaintext" => role_expect_close(
            TEST3,
            443,
            Some(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"),
        ),
        // Denials that precede any read: connect, observe the close.
        "pt-denied-notallowed" => role_expect_close(TEST3, 443, None),
        "pt-denied-unknown" => role_expect_close(TEST3_UNMAPPED, 443, None),
        // The rebinding denial happens at CONNECT time — the pipeline must
        // first pass the TLS inspection, so the role sends a valid hello.
        "pt-denied-rebinding" => {
            let hello = build_client_hello(Some(ALLOWED), &[]);
            role_expect_close(TEST3, 443, Some(&hello))
        }
        "pt-denied-port" => role_expect_close(TEST3, 443, None),
        other => Err(format!("unknown {ROLE_ENV} {other:?}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("SBX-PT-FAIL role={role}: {err}");
            ExitCode::FAILURE
        }
    }
}

fn marker(line: &str) {
    println!("{MARKER} {line}");
}

/// Preflight role: prove unprivileged userns+netns works in a fresh
/// single-threaded process (sandbox_init's exact probe). rc IS the signal.
fn role_probe_userns() -> Result<(), String> {
    // SAFETY: no-argument unshare in the single-threaded role process
    // (role dispatch precedes any thread spawn).
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(format!(
            "unshare(CLONE_NEWUSER|CLONE_NEWNET): {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The relay roles: connect under the real REDIRECT, write the payload,
/// `shutdown(Write)` (the half-duplex echo contract), then require the
/// echo back byte-for-byte — proving the replay carried every byte.
fn role_relay(payload: &[u8], expected_echo: &[u8], ip: Ipv4Addr, port: u16) -> Result<(), String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .write_all(payload)
        .map_err(|e| format!("write to {addr}: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown(Write): {e}"))?;
    let mut echoed = Vec::new();
    stream
        .read_to_end(&mut echoed)
        .map_err(|e| format!("read from {addr}: {e}"))?;
    // `expected_echo` differs from `payload` exactly on the HTTP path:
    // the proxy replays the validated head with Connection: close
    // inserted (http.rs module docs point 6).
    if echoed != expected_echo {
        return Err(format!(
            "echo mismatch on {addr}: sent {} bytes, expected {} back, got {} ({echoed:?})",
            payload.len(),
            expected_echo.len(),
            echoed.len()
        ));
    }
    marker(&format!("relay ok {} bytes on {addr}", payload.len()));
    Ok(())
}

/// The second-hello role (review-fix pin, proxy module docs point 12): a
/// valid CH1 with the allowed SNI under the real REDIRECT, then — once the
/// CH1 echo proves the decision/replay/relay are all live (signal-driven,
/// no fixed sleeps — R12) — a SECOND ClientHello with a different SNI (the
/// post-HRR CH2 attack shape). Teardown proof: zero application bytes
/// beyond the CH1 echo, then a clean EOF or the kernel RST.
fn role_second_hello() -> Result<(), String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(TEST3, 443));
    let mut stream =
        TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let ch1 = build_client_hello(Some(ALLOWED), &[]);
    stream
        .write_all(&ch1)
        .map_err(|e| format!("write CH1 to {addr}: {e}"))?;
    // The bounded signal wait: the immediate-echo upstream returns CH1 the
    // moment the proxy replays it, so its arrival proves the relay phase
    // is live and the second hello will be a distinct relay-phase record
    // (never pipelined into the inspection read — that shape is pinned
    // separately by inspect_tls_pipelined_second_hello_denied).
    let mut echoed = Vec::new();
    let mut chunk = [0u8; 4096];
    while echoed.len() < ch1.len() {
        match stream.read(&mut chunk) {
            Ok(0) => return Err("the connection closed before the CH1 echo".to_owned()),
            Ok(n) => echoed.extend_from_slice(&chunk[..n]),
            Err(err) => return Err(format!("waiting for the CH1 echo: {err}")),
        }
    }
    if echoed != ch1 {
        return Err(format!(
            "the CH1 echo mismatched: sent {} bytes, got back {}",
            ch1.len(),
            echoed.len()
        ));
    }
    // The post-HRR CH2 shape: a second ClientHello with a different SNI.
    // The teardown may race the write: EPIPE/reset is an acceptable
    // "closed" (the deny-side proof is the read below + the parent-side
    // upstream-bytes assertion).
    let _ = stream.write_all(&build_client_hello(Some(EVIL), &[]));
    // Teardown proof: zero application bytes beyond the CH1 echo, then a
    // clean EOF or the kernel RST (the expect_close family's contract).
    let mut got = Vec::new();
    match stream.read_to_end(&mut got) {
        Ok(_) if got.is_empty() => {}
        Ok(_) => {
            return Err(format!(
                "the torn-down relay returned {} extra application bytes",
                got.len()
            ));
        }
        Err(err)
            if got.is_empty()
                && matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                ) => {}
        Err(err) => return Err(format!("read after the second hello: {err}")),
    }
    marker("second hello torn down");
    Ok(())
}

/// The denial roles: connect (bounded), optionally write the role's bytes
/// (tolerating EPIPE/reset — the denial may close the socket before any
/// read), then require ZERO application bytes and EOF-or-reset.
fn role_expect_close(ip: Ipv4Addr, port: u16, payload: Option<&[u8]>) -> Result<(), String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, BOUND).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    if let Some(bytes) = payload {
        // The proxy may already have closed (denials that precede reads):
        // a failed write is an acceptable "closed", a succeeded one just
        // means the RST/EOF comes on the read side.
        let _ = stream.write_all(bytes);
        let _ = stream.shutdown(Shutdown::Write);
    }
    // One read decides it: zero application bytes is the ONLY acceptable
    // outcome of a denied connection (clean EOF or the kernel RST when
    // the proxy closed with our write unread).
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        // Clean EOF: closed with zero application bytes.
        Ok(0) => {}
        Ok(n) => {
            return Err(format!(
                "proxy relayed {n} application bytes on a DENIED connection to {addr}"
            ));
        }
        // The kernel RSTs when the proxy closes with an unread receive
        // queue — equally "closed with zero application bytes".
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
        Err(e) => return Err(format!("read from {addr}: {e}")),
    }
    marker(&format!("closed without application bytes on {addr}"));
    Ok(())
}
