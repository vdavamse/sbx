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
use std::io::{self, BufRead, Read, Write};
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
    ConnectError, Connected, Connector, Decision, DecisionSink, DialFn, DnsMap, ExplicitKind,
    GuardedConnector, Limits, NameSource, Proxy, Rejected, ResolveFn, Verdict, Via,
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
    /// Runs everywhere (the explicit proxy needs no kernel feature).
    Always,
    /// Opt-in real-network tier: `SBX_PT_NETWORK=1`.
    Network,
    /// Host-netns tier that needs these tools on PATH.
    Tools(&'static [&'static str]),
    /// The host must support the `SO_ORIGINAL_DST` conntrack lookup (the
    /// F8 host-netns tier).
    OrigDst,
    /// Unprivileged user+net namespaces must work (the full-chain tier).
    Userns,
}

impl Gate {
    fn satisfied(self, userns_ok: bool, origdst_ok: bool) -> bool {
        match self {
            Gate::Always => true,
            Gate::Network => std::env::var("SBX_PT_NETWORK").as_deref() == Ok("1"),
            Gate::Tools(list) => missing_tools(list).is_empty(),
            Gate::OrigDst => origdst_ok,
            Gate::Userns => userns_ok,
        }
    }

    fn skip_reason(self) -> String {
        match self {
            Gate::Always => "always runs".to_owned(),
            Gate::Network => "set SBX_PT_NETWORK=1 to run the real-network tier".to_owned(),
            Gate::Tools(list) => {
                format!("tool(s) unavailable: {}", missing_tools(list).join(", "))
            }
            Gate::OrigDst => ORIGDST_SKIP.to_owned(),
            Gate::Userns => USERNS_SKIP.to_owned(),
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
            name: "explicit-connect-443-relay",
            gate: Gate::Always,
            run: scenario_explicit_connect_443_relay,
        },
        Scenario {
            name: "explicit-connect-pipelined-hello",
            gate: Gate::Always,
            run: scenario_explicit_connect_pipelined_hello,
        },
        Scenario {
            name: "explicit-connect-second-hello-torn-down",
            gate: Gate::Always,
            run: scenario_explicit_second_hello_torn_down,
        },
        Scenario {
            name: "explicit-connect-80-http-inspected",
            gate: Gate::Always,
            run: scenario_explicit_connect_80_inspected,
        },
        Scenario {
            name: "explicit-forward-get-rewritten",
            gate: Gate::Always,
            run: scenario_explicit_forward_get_rewritten,
        },
        Scenario {
            name: "explicit-upstream-eof-closes",
            gate: Gate::Always,
            run: scenario_explicit_upstream_eof_closes,
        },
        Scenario {
            name: "explicit-resolve-fail-502",
            gate: Gate::Always,
            run: scenario_explicit_resolve_fail_502,
        },
        Scenario {
            name: "tool-curl-connect-https",
            gate: Gate::Tools(&["curl", "python3"]),
            run: scenario_tool_curl_connect_https,
        },
        Scenario {
            name: "tool-curl-absolute-form",
            gate: Gate::Tools(&["curl", "python3"]),
            run: scenario_tool_curl_absolute_form,
        },
        Scenario {
            name: "tool-git-https-clone",
            gate: Gate::Tools(&["git", "python3", "openssl"]),
            run: scenario_tool_git_https_clone,
        },
        Scenario {
            name: "tool-pip-connect",
            gate: Gate::Tools(&["pip", "python3", "openssl"]),
            run: scenario_tool_pip_connect,
        },
        Scenario {
            name: "tool-npm-connect",
            gate: Gate::Tools(&["npm", "python3", "openssl"]),
            run: scenario_tool_npm_connect,
        },
        Scenario {
            name: "tool-openssl-servername-other-denied",
            gate: Gate::Tools(&["openssl", "python3"]),
            run: scenario_tool_openssl_other_denied,
        },
        Scenario {
            name: "tool-openssl-servername-match-allowed",
            gate: Gate::Tools(&["openssl", "python3"]),
            run: scenario_tool_openssl_match_allowed,
        },
        Scenario {
            name: "netns-explicit-connect-relay",
            gate: Gate::Userns,
            run: scenario_netns_explicit_connect_relay,
        },
        Scenario {
            name: "netns-explicit-sni-mismatch",
            gate: Gate::Userns,
            run: scenario_netns_explicit_sni_mismatch,
        },
        Scenario {
            name: "network-curl-pypi",
            gate: Gate::Network,
            run: scenario_network_curl_pypi,
        },
        Scenario {
            name: "network-git-clone-hello-world",
            gate: Gate::Network,
            run: scenario_network_git_clone,
        },
        Scenario {
            name: "network-pip-download-six",
            gate: Gate::Network,
            run: scenario_network_pip_download,
        },
        Scenario {
            name: "network-npm-view-left-pad",
            gate: Gate::Network,
            run: scenario_network_npm_view,
        },
        Scenario {
            name: "network-openssl-servername-other-denied",
            gate: Gate::Network,
            run: scenario_network_openssl_other_denied,
        },
        Scenario {
            name: "explicit-connect-not-allowed-403",
            gate: Gate::Always,
            run: scenario_explicit_connect_not_allowed,
        },
        Scenario {
            name: "explicit-connect-ip-literal-400",
            gate: Gate::Always,
            run: scenario_explicit_connect_ip_literal,
        },
        Scenario {
            name: "explicit-connect-sni-mismatch-silent",
            gate: Gate::Always,
            run: scenario_explicit_connect_sni_mismatch,
        },
        Scenario {
            name: "explicit-forward-host-mismatch-403",
            gate: Gate::Always,
            run: scenario_explicit_forward_host_mismatch,
        },
        Scenario {
            name: "explicit-forward-https-400",
            gate: Gate::Always,
            run: scenario_explicit_forward_https,
        },
        Scenario {
            name: "explicit-port-not-in-policy-403",
            gate: Gate::Always,
            run: scenario_explicit_port_denied,
        },
        Scenario {
            name: "explicit-serve-stop",
            gate: Gate::Always,
            run: scenario_explicit_serve_stop,
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
    spawn_serve_kind(listener, proxy, false)
}

/// `explicit = true` serves the explicit listener (issue #8) instead.
fn spawn_serve_kind(
    listener: TcpListener,
    proxy: Arc<Proxy>,
    explicit: bool,
) -> Result<ServeHandle, String> {
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
            .block_on(async {
                if explicit {
                    sbx::proxy::serve_explicit(listener, proxy).await
                } else {
                    sbx::proxy::serve(listener, proxy).await
                }
            })
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
    // Explicit roles (issue #8) reach the explicit listener, which is served
    // BEFORE the go byte alongside the transparent one (Q9 shape).
    let explicit_role = role.starts_with("explicit-");

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
    let explicit_serve = if explicit_role {
        Some(spawn_serve_kind(explicit, Arc::clone(&proxy), true)?)
    } else {
        drop(explicit);
        None
    };
    let serve = spawn_serve(transparent, proxy)?;
    let go = send_go(sp_guard.borrow());
    // finish() disarms the guard on the normal path; a go-byte failure
    // leaves it armed, so the drop below kills the still-waiting child.
    let payload = go.and_then(|()| finish(sp_guard.take(), role));

    // Teardown ALWAYS runs (a failed payload must not leak the serve
    // thread into the next scenario's spawn window — R6).
    let serve_stop = serve.stop();
    let explicit_stop = explicit_serve.map(ServeHandle::stop).transpose();
    let echo_outcome = echo_server
        .map(|srv| srv.into_outcome(matches!(echo, EchoSpec::ExpectMiss)))
        .transpose();
    // The explicit + dns fds are held until the payload is reaped, then
    // dropped here (no listener-gone races while the payload runs).
    drop(dns);

    let payload = payload?;
    match explicit_stop? {
        Some(Err(_)) | None => {}
        Some(Ok(())) => return Err("explicit serve returned Ok — impossible".to_owned()),
    }
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
    run_hostnet_mode(false, allow, map, ports_fn, client)
}

/// [`run_hostnet`] over either listener: `explicit = true` serves
/// `serve_explicit` (issue #8) — no `SO_ORIGINAL_DST`, the DNS map is
/// never consulted, and the request target alone names the destination.
fn run_hostnet_mode(
    explicit: bool,
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
    let serve = spawn_serve_kind(listener, proxy, explicit)?;

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
    let orig = run.decisions[0].orig_dst();
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
/// The pinned explicit wire bytes (issue #8, Q5), written as literals: the
/// crate's constants are `pub(crate)` and not visible to this suite.
const EXPLICIT_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const EXPLICIT_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const EXPLICIT_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// One explicit deny-tier exchange: the client sends `request`, reads to
/// EOF-or-reset, and the single decision is returned in `run.decisions`.
fn explicit_exchange(allow: &[&str], request: Vec<u8>) -> Result<HostnetRun, String> {
    run_hostnet_mode(
        true,
        allow,
        &[],
        |_| vec![443, 80, 8080],
        HostnetClient::Send(request),
    )
}

fn connect_head(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
}

/// A policy-denied CONNECT (name not on the allow list): 403 before any
/// tunnel, zero bytes of the 200, the connector never called.
fn scenario_explicit_connect_not_allowed() -> Result<(), String> {
    let run = explicit_exchange(&[ALLOWED], connect_head("notallowed.test:443"))?;
    if run.received != EXPLICIT_403 {
        return Err(format!(
            "the client must see exactly the pinned 403: {:?}",
            String::from_utf8_lossy(&run.received)
        ));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::NotAllowed {
            name: Domain::parse(NOTALLOWED).expect("fixture"),
        }),
        "notallowed.test is not in the policy allow list",
    )?;
    if run.decisions[0].via
        != (Via::Explicit {
            kind: ExplicitKind::Connect,
            port: Some(443),
        })
    {
        return Err(format!(
            "via must be explicit-connect: {:?}",
            run.decisions[0].via
        ));
    }
    Ok(())
}

/// An IP-literal CONNECT target: 400, the reason carries the redacted
/// target and the pinned detail.
fn scenario_explicit_connect_ip_literal() -> Result<(), String> {
    let run = explicit_exchange(&[ALLOWED], connect_head("93.184.216.34:443"))?;
    if run.received != EXPLICIT_400 {
        return Err(format!("expected the pinned 400: {:?}", run.received));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::ConnectTargetInvalid {
            target: "93.184.216.34:443".to_owned(),
            detail: "IP literals are not allowed; use a domain name",
        }),
        "CONNECT target \"93.184.216.34:443\" is invalid: IP literals are not allowed; use a domain name",
    )
}

/// SNI differs from the CONNECT target after an allowed CONNECT: the
/// client sees the 200 and nothing else (post-200 silence, Q5), and the
/// inspect-before-connect lock means the connector is never called.
fn scenario_explicit_connect_sni_mismatch() -> Result<(), String> {
    let mut request = connect_head("allowed.test:443");
    request.extend_from_slice(&build_client_hello(Some("other.test"), &[]));
    let run = explicit_exchange(&[ALLOWED], request)?;
    if run.received != EXPLICIT_200 {
        return Err(format!(
            "after the 200 a post-tunnel denial must be a bare close: {:?}",
            String::from_utf8_lossy(&run.received)
        ));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::SniMismatch {
            sni: Domain::parse("other.test").expect("fixture"),
            name: Domain::parse(ALLOWED).expect("fixture"),
            source: NameSource::ConnectTarget,
        }),
        "SNI other.test does not match the CONNECT target name allowed.test",
    )
}

/// Absolute-form Host mismatch: 403, the reason names the request-target.
fn scenario_explicit_forward_host_mismatch() -> Result<(), String> {
    let run = explicit_exchange(
        &[ALLOWED],
        b"GET http://allowed.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n".to_vec(),
    )?;
    if run.received != EXPLICIT_403 {
        return Err(format!("expected the pinned 403: {:?}", run.received));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::HostMismatch {
            host: Domain::parse("evil.test").expect("fixture"),
            name: Domain::parse(ALLOWED).expect("fixture"),
            source: NameSource::RequestTarget,
        }),
        "HTTP Host evil.test does not match the request-target name allowed.test",
    )
}

/// `https://` absolute-form: 400, TLS belongs on CONNECT.
fn scenario_explicit_forward_https() -> Result<(), String> {
    let run = explicit_exchange(
        &[ALLOWED],
        b"GET https://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_vec(),
    )?;
    if run.received != EXPLICIT_400 {
        return Err(format!("expected the pinned 400: {:?}", run.received));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::TargetSchemeUnsupported {
            scheme: "https".to_owned(),
        }),
        "absolute-form request target scheme \"https\" is not supported (http:// only; use CONNECT for TLS)",
    )
}

/// A CONNECT to a port outside `network.ports`: 403 with the port reason.
fn scenario_explicit_port_denied() -> Result<(), String> {
    let run = run_hostnet_mode(
        true,
        &[ALLOWED],
        &[],
        |_| vec![443, 80],
        HostnetClient::Send(connect_head("allowed.test:22")),
    )?;
    if run.received != EXPLICIT_403 {
        return Err(format!("expected the pinned 403: {:?}", run.received));
    }
    assert_single_decision(
        &run.decisions,
        &Verdict::Denied(Rejected::PortNotAllowed { port: 22 }),
        "port 22 is not in the policy port list",
    )
}

/// `serve_explicit` shares the accept loop: a shutdown ends it with the
/// same pinned EINVAL teardown as the transparent listener.
fn scenario_explicit_serve_stop() -> Result<(), String> {
    let run = run_hostnet_mode(true, &[], &[], |_| vec![], HostnetClient::Absent)?;
    if !run.decisions.is_empty() {
        return Err(format!("no connection ⇒ no decisions: {:?}", run.decisions));
    }
    let err = run
        .serve_result
        .expect_err("shutdown must end serve_explicit with an error");
    if err.raw_os_error() != Some(libc::EINVAL) {
        return Err(format!(
            "expected the pinned EINVAL teardown path, got {err}"
        ));
    }
    Ok(())
}

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
    if run.decisions[0].orig_dst() != Some(SocketAddrV4::new(TEST3, 443)) {
        return Err(format!(
            "orig_dst must be the real pre-DNAT destination: {:?}",
            run.decisions[0].orig_dst()
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
    if run.decisions[0].orig_dst() != Some(SocketAddrV4::new(TEST3, 80)) {
        return Err(format!(
            "orig_dst must be the real pre-DNAT destination: {:?}",
            run.decisions[0].orig_dst()
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
            source: NameSource::DnsMap,
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
    if run.decisions[0].orig_dst() != Some(SocketAddrV4::new(TEST3_UNMAPPED, 443)) {
        return Err(format!(
            "orig_dst must be the dialed unmapped twin: {:?}",
            run.decisions[0].orig_dst()
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
        "explicit-connect-relay" => role_explicit_exact(
            &[
                connect_head("allowed.test:443"),
                build_client_hello(Some(ALLOWED), &[]),
            ]
            .concat(),
            &[EXPLICIT_200, &build_client_hello(Some(ALLOWED), &[])].concat(),
        ),
        "explicit-sni-mismatch" => role_explicit_exact(
            &[
                connect_head("allowed.test:443"),
                build_client_hello(Some(EVIL), &[]),
            ]
            .concat(),
            EXPLICIT_200,
        ),
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

// ============================================================================
// Issue #8 — explicit proxy: allowed-path, tools, userns and network tiers.
// ============================================================================

const EXPLICIT_PORT: u16 = 3128;
const TOOL_BOUND: Duration = Duration::from_secs(30);

/// Missing tools from `list` (empty = all present). A tool is present when
/// `<tool> --version` (openssl: `openssl version`) runs and exits 0.
fn missing_tools(list: &'static [&'static str]) -> Vec<&'static str> {
    list.iter()
        .copied()
        .filter(|tool| {
            // Probe the way the suite runs each tool: openssl has no
            // `--version`; pip runs as `python3 -m pip`.
            let mut probe = match *tool {
                "pip" => {
                    let mut cmd = Command::new("python3");
                    cmd.args(["-m", "pip", "--version"]);
                    cmd
                }
                "openssl" => {
                    let mut cmd = Command::new("openssl");
                    cmd.arg("version");
                    cmd
                }
                other => {
                    let mut cmd = Command::new(other);
                    cmd.arg("--version");
                    cmd
                }
            };
            probe
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| !status.success())
                .unwrap_or(true)
        })
        .collect()
}

/// A temporary directory removed on drop.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Result<Self, String> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("sbx-pt-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The upstream fixture child: a python3 TLS server (allowed.test cert)
/// and a plain HTTP server over one docroot, logging `REQ <requestline>`.
const UPSTREAM_PY: &str = r#"
import http.server, os, socketserver, ssl, sys, threading
d = sys.argv[1]
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=d, **k)
    def log_message(self, fmt, *args):
        sys.stderr.write("REQ " + self.requestline + "\n")
        sys.stderr.flush()
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
tls = S(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(d, "cert.pem"), os.path.join(d, "key.pem"))
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
plain = S(("127.0.0.1", 0), H)
sys.stdout.write("PORTS %d %d\n" % (tls.server_address[1], plain.server_address[1]))
sys.stdout.flush()
threading.Thread(target=tls.serve_forever, daemon=True).start()
plain.serve_forever()
"#;

const SIMPLE_INDEX: &str = "<a href=\"/simple/sbx-probe/\">sbx-probe</a>";
const PROBE_NPM: &str = "{\"name\":\"sbx-probe\",\"dist-tags\":{\"latest\":\"0.1.0\"},\"versions\":{\"0.1.0\":{\"name\":\"sbx-probe\",\"version\":\"0.1.0\"}}}";

/// Run `cmd` with a deadline, collecting stdout and stderr.
struct ToolOut {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run_bounded(mut cmd: Command, what: &str, limit: Duration) -> Result<ToolOut, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("{what}: spawn: {e}"))?;
    let out = reader_thread(child.stdout.take().expect("piped stdout"));
    let err = reader_thread(child.stderr.take().expect("piped stderr"));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{what}: exceeded {limit:?}"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("{what}: wait: {e}")),
        }
    };
    Ok(ToolOut {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// The tool env isolation (design §5): nothing from the user's config.
/// Everything is cleared, then re-added: PATH, a fresh HOME/XDG cache, git
/// with no system or global config, pip with no config file, and no proxy
/// variables except the ones a scenario sets. PYENV_ROOT is passed through
/// deliberately: the `python3` on PATH is a pyenv shim that resolves its
/// interpreter from the REAL pyenv root (`$HOME/.pyenv`), which the
/// isolated HOME would otherwise hide.
fn isolated(cmd: &mut Command, home: &std::path::Path) {
    let real_home = std::env::var_os("HOME").unwrap_or_default();
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home)
        .env(
            "PYENV_ROOT",
            std::path::Path::new(&real_home).join(".pyenv"),
        )
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "sbx")
        .env("GIT_AUTHOR_EMAIL", "sbx@example.test")
        .env("GIT_COMMITTER_NAME", "sbx")
        .env("GIT_COMMITTER_EMAIL", "sbx@example.test")
        .env("PIP_CONFIG_FILE", "/dev/null")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
}

/// The python upstream fixture plus its docroot (cert, repo, index files).
struct Upstreams {
    dir: Scratch,
    child: Option<Child>,
    logs: Option<JoinHandle<String>>,
    tls: u16,
    plain: u16,
}

impl Upstreams {
    fn start() -> Result<Self, String> {
        let dir = Scratch::new("up")?;
        make_docroot(&dir.0)?;
        let mut child = Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(UPSTREAM_PY)
            .arg(&dir.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn python3 upstream: {e}"))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = io::BufReader::new(stdout);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let _ = tx.send(line);
            // Drain to EOF so the child never blocks on stdout.
            let _ = io::copy(&mut reader, &mut io::sink());
        });
        let line = rx
            .recv_timeout(BOUND * 2)
            .map_err(|_| "python3 upstream printed no PORTS line".to_owned())?;
        let mut parts = line.split_whitespace();
        let (Some("PORTS"), Some(tls), Some(plain)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("bad PORTS line {line:?}"));
        };
        let tls = tls.parse().map_err(|e| format!("tls port: {e}"))?;
        let plain = plain.parse().map_err(|e| format!("plain port: {e}"))?;
        let logs = child.stderr.take().map(reader_thread);
        Ok(Self {
            dir,
            child: Some(child),
            logs,
            tls,
            plain,
        })
    }

    fn cert(&self) -> std::path::PathBuf {
        self.dir.0.join("cert.pem")
    }

    /// Kill the fixture and return its request log.
    fn finish(mut self) -> String {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.logs
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default()
    }

    fn routing(&self) -> Arc<dyn Connector> {
        Arc::new(Routing(vec![(443, addr(self.tls)), (80, addr(self.plain))]))
    }
}

impl Drop for Upstreams {
    /// Early-error paths must not leak the python fixture (RAII kill+wait).
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn make_docroot(dir: &std::path::Path) -> Result<(), String> {
    let run = |args: &[&str], cwd: &std::path::Path| -> Result<(), String> {
        let status = Command::new(args[0])
            .args(&args[1..])
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("{}: {e}", args[0]))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{:?} failed: {status}", args))
        }
    };
    run(
        &[
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-days",
            "1",
            "-subj",
            "/CN=allowed.test",
            "-addext",
            "subjectAltName=DNS:allowed.test",
        ],
        dir,
    )?;
    std::fs::write(dir.join("index.html"), "sbx-explicit-ok\n").map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("simple/sbx-probe")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("simple/sbx-probe/index.html"), SIMPLE_INDEX)
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("sbx-probe"), PROBE_NPM).map_err(|e| e.to_string())?;
    // A dumb-HTTP git repo with one commit.
    let src = dir.join("src");
    std::fs::create_dir_all(&src).map_err(|e| e.to_string())?;
    std::fs::write(src.join("README"), "sbx-git-ok\n").map_err(|e| e.to_string())?;
    run(&["git", "init", "-q"], &src)?;
    run(&["git", "add", "README"], &src)?;
    run(
        &[
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "probe",
        ],
        &src,
    )?;
    run(&["git", "clone", "-q", "--bare", ".", "../repo.git"], &src)?;
    run(&["git", "-C", "../repo.git", "update-server-info"], &src)?;
    Ok(())
}

/// Routes CONNECT/forward dials to fixture or echo listeners by port.
struct Routing(Vec<(u16, SocketAddr)>);

impl Connector for Routing {
    fn connect(
        &self,
        _name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
        let target = self.0.iter().find(|(p, _)| *p == port).map(|(_, a)| *a);
        Box::pin(async move {
            let Some(target) = target else {
                return Err(ConnectError::Connect {
                    detail: format!("no route for port {port}"),
                });
            };
            let stream = tokio::net::TcpStream::connect(target).await.map_err(|e| {
                ConnectError::Connect {
                    detail: e.to_string(),
                }
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

/// Records `name:port` for every dial, then delegates.
struct Logged {
    inner: Arc<dyn Connector>,
    log: ConnectorLog,
}

impl Connector for Logged {
    fn connect(
        &self,
        name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
        self.log
            .lock()
            .expect("connector log")
            .push(format!("{}:{port}", name.as_str()));
        self.inner.connect(name, port)
    }
}

/// A serving explicit listener on 127.0.0.1:0 (host netns).
struct Explicit {
    addr: SocketAddr,
    sink: Arc<RecordingSink>,
    log: ConnectorLog,
    serve: ServeHandle,
}

fn start_explicit(
    allow: &[&str],
    ports: &[u16],
    connector: Arc<dyn Connector>,
) -> Result<Explicit, String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let sink = Arc::new(RecordingSink::default());
    let log = connector_log();
    let network = policy_network(allow, ports);
    let proxy = Proxy::new(
        &network,
        Arc::new(StaticMap::new(&[])),
        sink.clone(),
        Arc::new(Logged {
            inner: connector,
            log: Arc::clone(&log),
        }),
        Limits::default(),
    );
    let serve = spawn_serve_kind(listener, proxy, true)?;
    Ok(Explicit {
        addr,
        sink,
        log,
        serve,
    })
}

struct Finished {
    decisions: Vec<Decision>,
    teardowns: Vec<String>,
    dials: Vec<String>,
}

impl Explicit {
    fn finish(self) -> Result<Finished, String> {
        let serve_result = self.serve.stop()?;
        match serve_result {
            Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {}
            other => return Err(format!("serve_explicit teardown: {other:?}")),
        }
        Ok(Finished {
            decisions: self.sink.recorded(),
            teardowns: self.sink.teardowns(),
            dials: log_of(&self.log),
        })
    }
}

fn client_to(target: SocketAddr) -> Result<TcpStream, String> {
    let stream = TcpStream::connect_timeout(&target, BOUND).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    Ok(stream)
}

/// Read to EOF; a reset is a normal end (the proxy may drop the socket).
fn read_to_eof(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    match stream.read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(out),
        Err(e) => Err(format!("client read: {e}")),
    }
}

fn expect_echo(echo: Option<EchoOutcome>) -> Result<Vec<u8>, String> {
    match echo {
        Some(EchoOutcome::Hit(bytes)) => Ok(bytes),
        other => Err(format!("the echo server must be hit: {other:?}")),
    }
}

fn allowed_decision(decisions: &[Decision], via: Via, upstream: SocketAddr) -> Result<(), String> {
    let want = Verdict::Allowed {
        name: Domain::parse(ALLOWED).expect("fixture"),
        upstream,
    };
    if decisions.len() != 1 {
        return Err(format!("exactly one decision: {decisions:?}"));
    }
    if decisions[0].verdict != want {
        return Err(format!("verdict: {:?}", decisions[0].verdict));
    }
    if decisions[0].via != via {
        return Err(format!("via: {:?}", decisions[0].via));
    }
    Ok(())
}

/// Start an echo upstream and a routed explicit proxy around it.
fn echo_explicit(
    mode: EchoMode,
    ports: &[u16],
) -> Result<(EchoServer, Explicit, SocketAddr), String> {
    let echo = spawn_echo_server(mode)?;
    let target = echo.addr;
    let routes = Arc::new(Routing(ports.iter().map(|p| (*p, target)).collect()));
    let explicit = start_explicit(&[ALLOWED], ports, routes)?;
    Ok((echo, explicit, target))
}

/// The DIRECT CONNECT-443 relay (design 1): the upstream receives exactly
/// the ClientHello (the CONNECT head is consumed), echoes it back through
/// the tunnel after the `200`.
fn scenario_explicit_connect_443_relay() -> Result<(), String> {
    let hello = build_client_hello(Some(ALLOWED), &[]);
    let (echo, explicit, target) = echo_explicit(EchoMode::OnEof, &[443, 80])?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(&[connect_head("allowed.test:443"), hello.clone()].concat())
        .map_err(|e| format!("write: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    let upstream = expect_echo(Some(echo.into_outcome(false)?))?;
    let finished = explicit.finish()?;
    if upstream != hello {
        return Err(format!(
            "upstream must see exactly the hello: {} bytes",
            upstream.len()
        ));
    }
    if received != [EXPLICIT_200, hello.as_slice()].concat() {
        return Err(format!(
            "client bytes: {} (want 200 + hello)",
            received.len()
        ));
    }
    allowed_decision(
        &finished.decisions,
        Via::Explicit {
            kind: ExplicitKind::Connect,
            port: Some(443),
        },
        target,
    )?;
    if finished.dials != [format!("{ALLOWED}:443")] {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// Pipelined bytes after the ClientHello reach the upstream in order
/// (design 2): the replay is hello ++ tail, relayed verbatim.
fn scenario_explicit_connect_pipelined_hello() -> Result<(), String> {
    let hello = build_client_hello(Some(ALLOWED), &[]);
    let tail = b"PIPELINED-TAIL".to_vec();
    let (echo, explicit, _) = echo_explicit(EchoMode::OnEof, &[443, 80])?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(
            &[
                connect_head("allowed.test:443"),
                hello.clone(),
                tail.clone(),
            ]
            .concat(),
        )
        .map_err(|e| format!("write: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    let upstream = expect_echo(Some(echo.into_outcome(false)?))?;
    explicit.finish()?;
    let want = [hello.as_slice(), tail.as_slice()].concat();
    if upstream != want {
        return Err(format!(
            "the upstream must see hello ++ tail: {} bytes",
            upstream.len()
        ));
    }
    if received != [EXPLICIT_200, want.as_slice()].concat() {
        return Err("client bytes must be 200 ++ echo of hello ++ tail".to_owned());
    }
    Ok(())
}

/// A second ClientHello on the relay (design 3, the second-hello defense):
/// the upstream sees exactly the first hello, the teardown hook reports the
/// pinned detail, and the single Allowed decision stays the only record.
fn scenario_explicit_second_hello_torn_down() -> Result<(), String> {
    let hello1 = build_client_hello(Some(ALLOWED), &[]);
    let hello2 = build_client_hello(Some("other.test"), &[]);
    let (echo, explicit, target) = echo_explicit(EchoMode::Immediate, &[443, 80])?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(&[connect_head("allowed.test:443"), hello1.clone()].concat())
        .map_err(|e| format!("write: {e}"))?;
    // Signal-driven (no fixed sleep): CH1's echo proves the relay is live.
    let want_echo = [EXPLICIT_200, hello1.as_slice()].concat();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    while seen.len() < want_echo.len() {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read CH1 echo: {e}"))?;
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&chunk[..n]);
    }
    if seen != want_echo {
        return Err("CH1 echo must arrive before the second hello".to_owned());
    }
    stream
        .write_all(&hello2)
        .map_err(|e| format!("write CH2: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let _ = read_to_eof(&mut stream)?;
    let upstream = expect_echo(Some(echo.into_outcome(false)?))?;
    let finished = explicit.finish()?;
    if upstream != hello1 {
        return Err(format!(
            "upstream saw {} bytes, must be exactly CH1",
            upstream.len()
        ));
    }
    if finished.teardowns != [TORN_DOWN_SECOND_HELLO_DETAIL.to_owned()] {
        return Err(format!("teardown hook: {:?}", finished.teardowns));
    }
    allowed_decision(
        &finished.decisions,
        Via::Explicit {
            kind: ExplicitKind::Connect,
            port: Some(443),
        },
        target,
    )
}

/// CONNECT :80 — the tunnelled HTTP head is inspected and forwarded with
/// `Connection: close` (design 7).
fn scenario_explicit_connect_80_inspected() -> Result<(), String> {
    let (echo, explicit, _) = echo_explicit(EchoMode::OnEof, &[443, 80])?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(
            &[
                connect_head("allowed.test:80"),
                b"GET /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_vec(),
            ]
            .concat(),
        )
        .map_err(|e| format!("write: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    let upstream = expect_echo(Some(echo.into_outcome(false)?))?;
    let finished = explicit.finish()?;
    let text = String::from_utf8_lossy(&upstream).into_owned();
    if !text.starts_with("GET /x HTTP/1.1\r\nHost: allowed.test\r\n")
        || !text.contains("Connection: close\r\n")
    {
        return Err(format!("upstream request: {text:?}"));
    }
    if received.len() < EXPLICIT_200.len() || &received[..EXPLICIT_200.len()] != EXPLICIT_200 {
        return Err("the client must see the 200 first".to_owned());
    }
    if received[EXPLICIT_200.len()..] != upstream[..] {
        return Err("the client must receive the echo after the 200".to_owned());
    }
    if finished.dials != [format!("{ALLOWED}:80")] {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// Absolute-form GET: the upstream receives the rebuilt origin-form head
/// with `Connection: close` and no `Proxy-*` (design 8, exact bytes).
fn scenario_explicit_forward_get_rewritten() -> Result<(), String> {
    let (echo, explicit, target) = echo_explicit(EchoMode::OnEof, &[443, 80])?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(
            b"GET http://allowed.test/p?q#f HTTP/1.1\r\nHost: allowed.test\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .map_err(|e| format!("write: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    let upstream = expect_echo(Some(echo.into_outcome(false)?))?;
    let finished = explicit.finish()?;
    let want = b"GET /p?q HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
    if upstream != want {
        return Err(format!(
            "upstream bytes: {:?}",
            String::from_utf8_lossy(&upstream)
        ));
    }
    if received != want {
        return Err(
            "forward responses carry no CONNECT 200: the client sees the echo only".to_owned(),
        );
    }
    allowed_decision(
        &finished.decisions,
        Via::Explicit {
            kind: ExplicitKind::Forward,
            port: Some(80),
        },
        target,
    )
}

/// The upstream answers then closes WITHOUT the client half-closing: the
/// upstream EOF ends the exchange and the client sees EOF (design 13).
fn scenario_explicit_upstream_eof_closes() -> Result<(), String> {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("bind: {e}"))?;
    let upstream_addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let server = std::thread::spawn(move || -> Result<(), String> {
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking: {e}"))?;
        let deadline = Instant::now() + BOUND;
        let (mut conn, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("the upstream was never dialed".to_owned());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("accept: {e}")),
            }
        };
        conn.set_nonblocking(false).map_err(|e| e.to_string())?;
        conn.set_read_timeout(Some(BOUND))
            .map_err(|e| e.to_string())?;
        let mut head = Vec::new();
        let mut chunk = [0u8; 512];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn
                .read(&mut chunk)
                .map_err(|e| format!("upstream read: {e}"))?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..n]);
        }
        conn.write_all(response)
            .map_err(|e| format!("upstream write: {e}"))?;
        Ok(())
    });
    let explicit = start_explicit(
        &[ALLOWED],
        &[80],
        Arc::new(Routing(vec![(80, upstream_addr)])),
    )?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    server
        .join()
        .map_err(|_| "upstream thread panicked".to_owned())??;
    explicit.finish()?;
    if received != response {
        return Err(format!(
            "client bytes: {:?}",
            String::from_utf8_lossy(&received)
        ));
    }
    Ok(())
}

/// Resolution failure on an ALLOWED name, forward path: 502 with the
/// pinned empty-body shape, and the connector never dials (design 14).
fn scenario_explicit_resolve_fail_502() -> Result<(), String> {
    let resolve: ResolveFn = Arc::new(|_name: &str, _port: u16| {
        Box::pin(async { Err(io::Error::other("scripted resolve failure")) })
    });
    let dial: DialFn = Arc::new(|_name: &str, _port: u16| {
        Box::pin(async { Err(io::Error::other("the dial must not run")) })
    });
    let connector: Arc<dyn Connector> = Arc::new(GuardedConnector::new(
        resolve,
        dial,
        Limits::default().connect_timeout,
    ));
    let explicit = start_explicit(&[ALLOWED], &[80], connector)?;
    let mut stream = client_to(explicit.addr)?;
    stream
        .write_all(b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    let received = read_to_eof(&mut stream)?;
    let finished = explicit.finish()?;
    if received != EXPLICIT_502 {
        return Err(format!(
            "client bytes: {:?}",
            String::from_utf8_lossy(&received)
        ));
    }
    if finished.decisions.len() != 1 {
        return Err(format!("one decision: {:?}", finished.decisions));
    }
    if finished.decisions[0].reason()
        != "DNS resolution failed for allowed.test: scripted resolve failure"
    {
        return Err(format!("reason: {}", finished.decisions[0].reason()));
    }
    Ok(())
}

const EXPLICIT_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

// ---- tools tier ------------------------------------------------------------

/// curl over CONNECT: the upstream is reached only through the proxy.
fn scenario_tool_curl_connect_https() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--cacert"]).arg(up.cert()).args([
        "-x",
        &format!("http://127.0.0.1:{}", explicit.addr.port()),
        "https://allowed.test/",
    ]);
    isolated(&mut cmd, &up.dir.0);
    let out = run_bounded(cmd, "curl CONNECT", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    let logs = up.finish();
    if !out.status.success() || out.stdout != "sbx-explicit-ok\n" {
        return Err(format!("curl: {:?} stderr={}", out.status, out.stderr));
    }
    if finished.dials != [format!("{ALLOWED}:443")] {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    if !logs.contains("REQ GET / HTTP/1.1") {
        return Err(format!("upstream never saw the request: {logs}"));
    }
    if finished.decisions.len() != 1
        || !matches!(finished.decisions[0].verdict, Verdict::Allowed { .. })
    {
        return Err(format!("decisions: {:?}", finished.decisions));
    }
    Ok(())
}

/// curl absolute-form to port 80: the upstream sees origin-form, never the
/// absolute URL (design 17).
fn scenario_tool_curl_absolute_form() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "-x"])
        .arg(format!("http://127.0.0.1:{}", explicit.addr.port()))
        .arg("http://allowed.test/");
    isolated(&mut cmd, &up.dir.0);
    let out = run_bounded(cmd, "curl absolute-form", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    let logs = up.finish();
    if !out.status.success() || out.stdout != "sbx-explicit-ok\n" {
        return Err(format!("curl: {:?} stderr={}", out.status, out.stderr));
    }
    if !logs.contains("REQ GET / HTTP/1.1") || logs.contains("GET http://") {
        return Err(format!("the upstream must see origin-form only: {logs}"));
    }
    if finished.dials != [format!("{ALLOWED}:80")] {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// git over HTTPS through the proxy: a real dumb-HTTP clone.
fn scenario_tool_git_https_clone() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let clone_dir = up.dir.0.join("clone");
    let mut cmd = Command::new("git");
    cmd.args(["clone", "https://allowed.test/repo.git"])
        .arg(&clone_dir);
    isolated(&mut cmd, &up.dir.0);
    cmd.env(
        "HTTPS_PROXY",
        format!("http://127.0.0.1:{}", explicit.addr.port()),
    )
    .env("GIT_SSL_CAINFO", up.cert());
    let out = run_bounded(cmd, "git clone", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if !out.status.success() {
        up.finish();
        return Err(format!("git clone: {:?} stderr={}", out.status, out.stderr));
    }
    // Read BEFORE finish(): dropping the fixture removes its scratch dir.
    let readme = std::fs::read_to_string(clone_dir.join("README")).map_err(|e| {
        format!(
            "{e}; status={:?}; clone dir {:?}; stderr={}; stdout={}",
            out.status,
            clone_dir.display(),
            out.stderr,
            out.stdout
        )
    })?;
    if readme != "sbx-git-ok\n" {
        return Err(format!("cloned README: {readme:?}"));
    }
    if finished
        .dials
        .iter()
        .all(|d| d != &format!("{ALLOWED}:443"))
    {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// pip against an HTTPS index through the proxy. Criterion: the index page
/// request reaches the upstream through a CONNECT tunnel (the fixture index
/// links to no wheel, so pip's own exit status is NOT the success signal).
fn scenario_tool_pip_connect() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("python3");
    cmd.args([
        "-m",
        "pip",
        "download",
        "--no-deps",
        "--disable-pip-version-check",
        "--index-url",
    ])
    .arg("https://allowed.test/simple/")
    .arg("--cert")
    .arg(up.cert())
    .arg("--proxy")
    .arg(format!("http://127.0.0.1:{}", explicit.addr.port()))
    .args(["-d"])
    .arg(up.dir.0.join("pipout"))
    .arg("sbx-probe");
    isolated(&mut cmd, &up.dir.0);
    let _out = run_bounded(cmd, "pip download", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    let logs = up.finish();
    if !logs.contains("REQ GET /simple/sbx-probe/ HTTP/1.1") {
        return Err(format!(
            "pip never reached the index through the proxy: {logs}"
        ));
    }
    if finished
        .dials
        .iter()
        .all(|d| d != &format!("{ALLOWED}:443"))
    {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// npm view over HTTPS through the proxy (registry JSON from the fixture).
fn scenario_tool_npm_connect() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("npm");
    cmd.args([
        "view",
        "sbx-probe",
        "version",
        "--userconfig",
        "/dev/null",
        "--cache",
    ])
    .arg(up.dir.0.join("npm-cache"))
    .arg("--registry")
    .arg("https://allowed.test/");
    isolated(&mut cmd, &up.dir.0);
    cmd.env(
        "HTTPS_PROXY",
        format!("http://127.0.0.1:{}", explicit.addr.port()),
    )
    .env("NODE_EXTRA_CA_CERTS", up.cert());
    let out = run_bounded(cmd, "npm view", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    let logs = up.finish();
    if !out.status.success() || !out.stdout.contains("0.1.0") {
        return Err(format!(
            "npm view: {:?} stdout={} stderr={}",
            out.status, out.stdout, out.stderr
        ));
    }
    if !logs.contains("REQ GET /sbx-probe HTTP/1.1") {
        return Err(format!(
            "the registry fetch must go through the proxy: {logs}"
        ));
    }
    if finished
        .dials
        .iter()
        .all(|d| d != &format!("{ALLOWED}:443"))
    {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    Ok(())
}

/// THE AC, verbatim (issue #8): `openssl s_client -proxy … -servername
/// other.com` is denied with the exact SNI-mismatch reason, and the
/// connector is never called.
fn scenario_tool_openssl_other_denied() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("openssl");
    cmd.args(["s_client", "-proxy"])
        .arg(format!("127.0.0.1:{}", explicit.addr.port()))
        .args([
            "-connect",
            "allowed.test:443",
            "-servername",
            "other.com",
            "-CAfile",
        ])
        .arg(up.cert());
    isolated(&mut cmd, &up.dir.0);
    let out = run_bounded(cmd, "openssl s_client other.com", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    up.finish();
    if out.status.success() {
        return Err("a mismatched SNI must not complete a handshake".to_owned());
    }
    if finished.decisions.len() != 1 {
        return Err(format!("exactly one decision: {:?}", finished.decisions));
    }
    let want = Verdict::Denied(Rejected::SniMismatch {
        sni: Domain::parse("other.com").expect("fixture"),
        name: Domain::parse(ALLOWED).expect("fixture"),
        source: NameSource::ConnectTarget,
    });
    if finished.decisions[0].verdict != want {
        return Err(format!("verdict: {:?}", finished.decisions[0].verdict));
    }
    if finished.decisions[0].reason()
        != "SNI other.com does not match the CONNECT target name allowed.test"
    {
        return Err(format!("reason: {}", finished.decisions[0].reason()));
    }
    if !finished.dials.is_empty() {
        return Err(format!(
            "the connector must never be called: {:?}",
            finished.dials
        ));
    }
    Ok(())
}

/// The matching SNI completes the handshake through the proxy (AC's pair).
fn scenario_tool_openssl_match_allowed() -> Result<(), String> {
    let up = Upstreams::start()?;
    let explicit = start_explicit(&[ALLOWED], &[443, 80], up.routing())?;
    let mut cmd = Command::new("openssl");
    cmd.args(["s_client", "-proxy"])
        .arg(format!("127.0.0.1:{}", explicit.addr.port()))
        .args([
            "-connect",
            "allowed.test:443",
            "-servername",
            "allowed.test",
            "-verify_return_error",
            "-CAfile",
        ])
        .arg(up.cert());
    isolated(&mut cmd, &up.dir.0);
    let out = run_bounded(cmd, "openssl s_client allowed", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    up.finish();
    let text = format!("{}{}", out.stdout, out.stderr);
    if !text.contains("Verify return code: 0 (ok)") {
        return Err(format!("the handshake must verify: {text}"));
    }
    if finished.dials != [format!("{ALLOWED}:443")] {
        return Err(format!("connector log: {:?}", finished.dials));
    }
    if finished.decisions.len() != 1 {
        return Err(format!("exactly one decision: {:?}", finished.decisions));
    }
    match &finished.decisions[0].verdict {
        Verdict::Allowed { name, .. } if name.as_str() == ALLOWED => {}
        other => return Err(format!("verdict: {other:?}")),
    }
    if finished.decisions[0].via
        != (Via::Explicit {
            kind: ExplicitKind::Connect,
            port: Some(443),
        })
    {
        return Err(format!("via: {:?}", finished.decisions[0].via));
    }
    Ok(())
}

// ---- userns tier -----------------------------------------------------------

/// Both fds served before the go byte; the explicit CONNECT relays to the
/// echo upstream and the transparent sink records nothing (design 23).
fn scenario_netns_explicit_connect_relay() -> Result<(), String> {
    let run = run_netns(
        "explicit-connect-relay",
        &[],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Echo,
        EchoSpec::ExpectHit,
    )?;
    assert_payload_success(&run.payload, &["relay ok"])?;
    if run
        .decisions
        .iter()
        .any(|d| matches!(d.via, Via::Transparent { .. }))
    {
        return Err(format!(
            "the transparent sink must record zero: {:?}",
            run.decisions
        ));
    }
    let hello = build_client_hello(Some(ALLOWED), &[]);
    match run.echo {
        Some(EchoOutcome::Hit(ref bytes)) if *bytes == hello => {}
        ref other => {
            return Err(format!(
                "the echo must receive exactly the hello: {other:?}"
            ));
        }
    }
    let upstream = run.echo_addr.expect("echo spawned");
    allowed_decision(
        &run.decisions,
        Via::Explicit {
            kind: ExplicitKind::Connect,
            port: Some(443),
        },
        upstream,
    )
}

/// SNI mismatch inside the netns: `200` then a bare close, zero dials.
fn scenario_netns_explicit_sni_mismatch() -> Result<(), String> {
    let run = run_netns(
        "explicit-sni-mismatch",
        &[],
        &[ALLOWED],
        &[443, 80],
        ConnectorSpec::Never,
        EchoSpec::None,
    )?;
    assert_payload_success(&run.payload, &["relay ok"])?;
    if run
        .decisions
        .iter()
        .any(|d| matches!(d.via, Via::Transparent { .. }))
    {
        return Err(format!(
            "the transparent sink must record zero: {:?}",
            run.decisions
        ));
    }
    if run.dial_ran || !run.connector_log.is_empty() {
        return Err(format!(
            "the connector must never run: {:?}",
            run.connector_log
        ));
    }
    if run.decisions.len() != 1 {
        return Err(format!("exactly one decision: {:?}", run.decisions));
    }
    Ok(())
}

// ---- network tier (opt-in: SBX_PT_NETWORK=1) -------------------------------

fn network_proxy(allow: &[&str]) -> Result<Explicit, String> {
    let system: Arc<dyn Connector> =
        Arc::new(GuardedConnector::system(Limits::default().connect_timeout));
    start_explicit(allow, &[443], system)
}

fn scenario_network_curl_pypi() -> Result<(), String> {
    let explicit = network_proxy(&["pypi.org"])?;
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "-o", "/dev/null", "-w", "%{http_code}", "-x"])
        .arg(format!("http://127.0.0.1:{}", explicit.addr.port()))
        .arg("https://pypi.org/simple/six/");
    let home = Scratch::new("net-curl")?;
    isolated(&mut cmd, &home.0);
    let out = run_bounded(cmd, "network curl", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if out.stdout.trim() != "200" {
        return Err(format!(
            "curl status: {:?} stdout={} stderr={}",
            out.status, out.stdout, out.stderr
        ));
    }
    if finished.decisions.len() != 1
        || !matches!(finished.decisions[0].verdict, Verdict::Allowed { .. })
    {
        return Err(format!("decisions: {:?}", finished.decisions));
    }
    Ok(())
}

fn scenario_network_git_clone() -> Result<(), String> {
    let explicit = network_proxy(&["github.com"])?;
    let home = Scratch::new("net-git")?;
    let mut cmd = Command::new("git");
    cmd.args([
        "clone",
        "-q",
        "--depth",
        "1",
        "https://github.com/octocat/Hello-World.git",
    ])
    .arg(home.0.join("hello"));
    isolated(&mut cmd, &home.0);
    cmd.env(
        "HTTPS_PROXY",
        format!("http://127.0.0.1:{}", explicit.addr.port()),
    );
    let out = run_bounded(cmd, "network git clone", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if !out.status.success() {
        return Err(format!("git clone: {:?} stderr={}", out.status, out.stderr));
    }
    if finished
        .decisions
        .iter()
        .all(|d| !matches!(d.verdict, Verdict::Allowed { .. }))
    {
        return Err(format!("no allowed decision: {:?}", finished.decisions));
    }
    Ok(())
}

fn scenario_network_pip_download() -> Result<(), String> {
    let explicit = network_proxy(&["pypi.org", "files.pythonhosted.org"])?;
    let home = Scratch::new("net-pip")?;
    let mut cmd = Command::new("python3");
    cmd.args([
        "-m",
        "pip",
        "download",
        "--no-deps",
        "--disable-pip-version-check",
        "six==1.16.0",
        "-d",
    ])
    .arg(home.0.join("wheels"))
    .arg("--proxy")
    .arg(format!("http://127.0.0.1:{}", explicit.addr.port()));
    isolated(&mut cmd, &home.0);
    let out = run_bounded(cmd, "network pip", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if !out.status.success() {
        return Err(format!("pip: {:?} stderr={}", out.status, out.stderr));
    }
    if finished
        .decisions
        .iter()
        .all(|d| !matches!(d.verdict, Verdict::Allowed { .. }))
    {
        return Err(format!("no allowed decision: {:?}", finished.decisions));
    }
    Ok(())
}

fn scenario_network_npm_view() -> Result<(), String> {
    let explicit = network_proxy(&["registry.npmjs.org"])?;
    let home = Scratch::new("net-npm")?;
    let mut cmd = Command::new("npm");
    cmd.args([
        "view",
        "left-pad",
        "version",
        "--userconfig",
        "/dev/null",
        "--cache",
    ])
    .arg(home.0.join("cache"))
    .args(["--registry", "https://registry.npmjs.org/"]);
    isolated(&mut cmd, &home.0);
    cmd.env(
        "HTTPS_PROXY",
        format!("http://127.0.0.1:{}", explicit.addr.port()),
    );
    let out = run_bounded(cmd, "network npm view", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if !out.status.success() || out.stdout.trim().is_empty() {
        return Err(format!("npm view: {:?} stderr={}", out.status, out.stderr));
    }
    if finished
        .decisions
        .iter()
        .all(|d| !matches!(d.verdict, Verdict::Allowed { .. }))
    {
        return Err(format!("no allowed decision: {:?}", finished.decisions));
    }
    Ok(())
}

fn scenario_network_openssl_other_denied() -> Result<(), String> {
    let explicit = network_proxy(&["pypi.org"])?;
    let home = Scratch::new("net-ossl")?;
    let mut cmd = Command::new("openssl");
    cmd.args(["s_client", "-proxy"])
        .arg(format!("127.0.0.1:{}", explicit.addr.port()))
        .args(["-connect", "pypi.org:443", "-servername", "other.com"]);
    isolated(&mut cmd, &home.0);
    let out = run_bounded(cmd, "network openssl other", TOOL_BOUND)?;
    let finished = explicit.finish()?;
    if out.status.success() {
        return Err("mismatched SNI must not complete".to_owned());
    }
    let want = "SNI other.com does not match the CONNECT target name pypi.org";
    if finished.decisions.len() != 1 || finished.decisions[0].reason() != want {
        return Err(format!("decisions: {:?}", finished.decisions));
    }
    if !finished.dials.is_empty() {
        return Err(format!("the dial must never run: {:?}", finished.dials));
    }
    Ok(())
}

/// Child side of the explicit userns roles (issue #8): connect to the
/// explicit listener inside the netns, send `request`, half-close, and
/// require the exact `expected` bytes back.
fn role_explicit_exact(request: &[u8], expected: &[u8]) -> Result<(), String> {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, EXPLICIT_PORT));
    let mut stream =
        TcpStream::connect_timeout(&target, BOUND).map_err(|e| format!("connect {target}: {e}"))?;
    stream
        .set_read_timeout(Some(BOUND))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .write_all(request)
        .map_err(|e| format!("write: {e}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("shutdown(Write): {e}"))?;
    let mut got = Vec::new();
    stream
        .read_to_end(&mut got)
        .map_err(|e| format!("read: {e}"))?;
    if got != expected {
        return Err(format!(
            "explicit bytes mismatch: got {} bytes, want {}",
            got.len(),
            expected.len()
        ));
    }
    marker("relay ok explicit");
    Ok(())
}
