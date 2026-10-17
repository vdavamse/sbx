//! Integration suite for `sbx run` (issue #10): the real binary, the real bwrap
//! sandbox, the real proxies and resolver, end to end.
//!
//! Why `harness = false`: the payload is THIS test binary re-exec'd as a role
//! (`SBX_RUN_ROLE` set through the policy's `env.set`), and `main()` dispatches
//! the role FIRST, before any thread exists. The parent side runs scenarios
//! sequentially, with bounded waits only (deadline polls, no fixed sleeps; a
//! 10 s BOUND per wait; every child reaped before the next scenario).
//!
//! Gates: scenarios marked `Gate::Always` run everywhere (policy, audit and
//! session refusals happen before any spawn). `Gate::Bwrap` scenarios SKIP
//! (exit 0 with a message) when no bwrap is discoverable or unprivileged user
//! namespaces are unavailable; CI installs bubblewrap, so they always run there.
//! Any FAIL exits 1.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "SBX_RUN_ROLE";
const BOUND: Duration = Duration::from_secs(10);
const SBX: &str = env!("CARGO_BIN_EXE_sbx");

// ---- payload roles ---------------------------------------------------------

fn main() -> ExitCode {
    // Role dispatch FIRST: the payload is this binary, with no threads yet.
    if let Ok(role) = std::env::var(ROLE_ENV) {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        return ExitCode::from(run_role(&role, &args));
    }
    let filter: Option<String> = std::env::args().nth(1);
    let bwrap_ok = bwrap_available();
    let mut failed = 0u32;
    let mut passed = 0u32;
    let mut skipped = 0u32;
    for sc in scenarios() {
        if let Some(f) = &filter {
            if !sc.name.contains(f.as_str()) {
                continue;
            }
        }
        if sc.gate == Gate::Bwrap && !bwrap_ok {
            println!("SKIP {}: {}", sc.name, SKIP_REASON);
            skipped += 1;
            continue;
        }
        let started = Instant::now();
        match (sc.run)() {
            Ok(()) => {
                println!("PASS {} ({:?})", sc.name, started.elapsed());
                passed += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", sc.name);
                failed += 1;
            }
        }
    }
    println!("sandbox_run: {passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

const SKIP_REASON: &str =
    "bwrap or unprivileged user namespaces unavailable (CI: apt-get install bubblewrap)";

/// Payload roles. Output lines are plain ASCII; arbitrary bytes are hex-coded.
fn run_role(role: &str, args: &[OsString]) -> u8 {
    let arg = |i: usize| {
        args.get(i)
            .and_then(|a| a.to_str())
            .unwrap_or("")
            .to_owned()
    };
    match role {
        "exit" => arg(0).parse::<u8>().unwrap_or(1),
        // #34: raw socket-family and io_uring probes (see `sockets_role`).
        "sockets" => sockets_role(),
        // #34: this process's and pid 1's Seccomp mode, and its fd set.
        "seccomp-status" => seccomp_status_role(),
        // #34: an x32-ABI syscall, which the filter kills (SIGSYS, rc 159).
        "x32-syscall" => x32_syscall_role(),
        // #34: an i386 compat syscall through `int 0x80`, which the arch gate kills.
        "int80-syscall" => int80_role(),
        // #12: writes a marker into the session's work dir (/work).
        "mark" => match fs::write("/work/marker", b"marked") {
            Ok(()) => 0,
            Err(_) => 1,
        },
        // #12: a hostile tree in /work (see `hostile_tree`).
        "hostile-tree" => hostile_tree(&arg(0)),
        "argv" => {
            for a in args {
                println!("ARG {}", hex(a.as_bytes()));
            }
            print_env();
            0
        }
        "env" => {
            print_env();
            0
        }
        "self-signal" => {
            let sig: i32 = arg(0).parse().unwrap_or(15);
            // SAFETY: raising a signal on ourselves; the default action applies.
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
            3
        }
        "ready-sleep" => {
            let secs: u64 = arg(0).parse().unwrap_or(60);
            println!("READY");
            let _ = std::io::stdout().flush();
            thread::sleep(Duration::from_secs(secs));
            0
        }
        "orphan" => {
            // Spawn a grandchild that outlives its parent (setsid, no stdio), then
            // stay alive so the parent can observe it from the host.
            spawn_orphan(&arg(0));
            println!("ORPHAN-UP");
            let _ = std::io::stdout().flush();
            thread::sleep(Duration::from_secs(60));
            0
        }
        "orphan-exit" => {
            spawn_orphan(&arg(0));
            println!("ORPHAN-UP");
            let _ = std::io::stdout().flush();
            0
        }
        "orphan-sleeper" => {
            thread::sleep(Duration::from_secs(60));
            0
        }
        "flood" => {
            // N bytes to stdout and N to stderr; N == 0 means forever (until EPIPE).
            let n: u64 = arg(0).parse().unwrap_or(0);
            let chunk = vec![b'x'; 4096];
            let mut out = std::io::stdout().lock();
            let mut err = std::io::stderr().lock();
            // The Rust runtime ignores SIGPIPE; a C payload would die of it.
            // Restore the default so a closed reader ends us like any pipeline writer.
            let die_on_epipe = || -> u8 {
                // SAFETY: restoring the default disposition and raising it on self.
                unsafe {
                    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                    libc::raise(libc::SIGPIPE);
                }
                9
            };
            if n == 0 {
                loop {
                    if out.write_all(&chunk).is_err() {
                        return die_on_epipe();
                    }
                }
            }
            let mut left = n;
            while left > 0 {
                let k = left.min(chunk.len() as u64) as usize;
                if out.write_all(&chunk[..k]).is_err() || err.write_all(&chunk[..k]).is_err() {
                    return die_on_epipe();
                }
                left -= k as u64;
            }
            0
        }
        "stdin-echo" => {
            let mut buf = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut buf);
            let _ = std::io::stdout().write_all(&buf);
            0
        }
        "stderr-marker" => {
            eprintln!("ERRLINE");
            println!("OUTLINE");
            0
        }
        "tty-report" => {
            // SAFETY: isatty on the standard fds; access on a fixed path.
            let (t0, t1, t2) = unsafe { (libc::isatty(0), libc::isatty(1), libc::isatty(2)) };
            let console = std::path::Path::new("/dev/console").exists();
            let report = format!("isatty {t0} {t1} {t2} console {console}\n");
            let _ = fs::write("/work/report", &report);
            print!("{report}");
            0
        }
        "sigmask-report" => {
            let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
            let line = |k: &str| {
                status
                    .lines()
                    .find(|l| l.starts_with(k))
                    .unwrap_or("")
                    .to_owned()
            };
            println!("{}", line("SigBlk"));
            println!("{}", line("SigIgn"));
            0
        }
        "dns" => {
            for name in args.iter().filter_map(|a| a.to_str()) {
                let (rcode, ip) = dns_ask(name);
                println!(
                    "DNS {name} rcode={rcode} ip={}",
                    ip.map(|i| i.to_string()).unwrap_or("-".into())
                );
            }
            0
        }
        "dns-flood" => {
            let n: u32 = arg(0).parse().unwrap_or(1);
            for i in 0..n {
                let _ = dns_ask(&format!("flood{i}.example"));
            }
            println!("FLOOD-DONE");
            0
        }
        "dns-flood-hang" => {
            // Flood the audited resolver, then hang: the run must end by audit failure.
            let n: u32 = arg(0).parse().unwrap_or(1);
            for i in 0..n {
                let _ = dns_ask(&format!("flood{i}.example"));
            }
            println!("FLOOD-DONE");
            let _ = std::io::stdout().flush();
            thread::sleep(Duration::from_secs(60));
            0
        }
        "net-checks" => {
            // allowed name → fake IP; then SNI mismatch on it; port denial on it;
            // a denied name; an unmapped fake IP.
            let (rcode, ip) = dns_ask("allowed.test");
            println!(
                "DNS allowed.test rcode={rcode} ip={}",
                ip.map(|i| i.to_string()).unwrap_or("-".into())
            );
            let fake = ip.unwrap_or(Ipv4Addr::new(198, 18, 0, 1));
            println!(
                "DIAL {}",
                dial(SocketAddr::from((fake, 443)), Some("evil.test"))
            );
            println!(
                "DIAL {}",
                dial(SocketAddr::from((fake, 8080)), Some("allowed.test"))
            );
            let (rcode, _) = dns_ask("notallowed.test");
            println!("DNS notallowed.test rcode={rcode}");
            println!(
                "DIAL {}",
                dial(SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)), None)
            );
            0
        }
        "dial" => {
            let ip: Ipv4Addr = arg(0).parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
            let port: u16 = arg(1).parse().unwrap_or(443);
            let sni = arg(2);
            let sni = if sni == "-" { None } else { Some(sni.as_str()) };
            println!("DIAL {}", dial(SocketAddr::from((ip, port)), sni));
            0
        }
        "noroute-checks" => {
            // Issue #11: the explicit fallback removed the default route, so a
            // direct connect fails fast with ENETUNREACH; the explicit proxy
            // still answers (the CONNECT below is denied by policy: 403).
            let t0 = Instant::now();
            match TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443)),
                BOUND,
            ) {
                Ok(_) => println!("DIRECT tcp connected"),
                Err(e) => println!(
                    "DIRECT tcp errno={:?} ms={}",
                    e.raw_os_error(),
                    t0.elapsed().as_millis()
                ),
            }
            // IPv6 is disabled in the sandbox netns: the direct connect fails with
            // EADDRNOTAVAIL (review suggestion; measured).
            let t6 = TcpStream::connect_timeout(
                &SocketAddr::from((
                    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7),
                    443,
                )),
                BOUND,
            );
            match t6 {
                Ok(_) => println!("DIRECT tcp6 connected"),
                Err(e) => println!("DIRECT tcp6 errno={:?}", e.raw_os_error()),
            }
            explicit_connect_print();
            0
        }
        "explicit-connect" => {
            explicit_connect_print();
            0
        }
        "concurrent" => {
            // concurrent NONCE NAME EXIT: write the nonce to /work/out, resolve NAME, exit EXIT.
            let nonce = arg(0);
            let name = arg(1);
            let code: u8 = arg(2).parse().unwrap_or(1);
            let _ = fs::write("/work/out", nonce.as_bytes());
            let (rcode, ip) = dns_ask(&name);
            println!(
                "{nonce} {name} rcode={rcode} ip={}",
                ip.map(|i| i.to_string()).unwrap_or("-".into())
            );
            code
        }
        "cwd" => {
            println!(
                "CWD {}",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
            0
        }
        other => {
            eprintln!("unknown role {other:?}");
            2
        }
    }
}

/// Every environment variable as `ENV KEY=<hex value>`, sorted.
/// #34: raw socket-family probes through the `syscall` entry point, so the
/// family argument reaches the kernel untruncated (the high-word cases). One
/// `SOCK <label> <ok|errno=N>` line per probe; `ok` closes the fd at once.
fn sockets_role() -> u8 {
    use libc::{c_int, c_long};
    const STREAM: c_long = 1;
    const RAW: c_long = 3;
    let report = |label: &str, ret: c_long| {
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            println!("SOCK {label} errno={errno}");
        } else {
            println!("SOCK {label} ok");
            // SAFETY: the kernel returned a new fd we own.
            unsafe { libc::close(ret as c_int) };
        }
    };
    let sock = |family: c_long, ty: c_long, proto: c_long| -> c_long {
        // SAFETY: a plain socket(2) through syscall(2) with integer arguments.
        unsafe { libc::syscall(libc::SYS_socket, family, ty, proto) as c_long }
    };
    // Families that must fail with EAFNOSUPPORT (97).
    let denied: [(&str, c_long); 8] = [
        ("vsock", 40),
        ("packet", 17),
        ("xdp", 44),
        ("alg", 38),
        ("bluetooth", 31),
        ("unspec", 0),
        ("above-max", 255),
        ("vsock-hiword", (1 << 32) | 40),
    ];
    for (label, family) in denied {
        report(label, sock(family, STREAM, 0));
    }
    // #34 (review s1): the syscall NUMBER with high bits set, family VSOCK.
    // The filter reads the 32-bit `nr` field, so this is socket(2) to it and
    // is refused before the kernel decides what the number means.
    // SAFETY: a syscall with integer arguments.
    report("vsock-hiword-nr", unsafe {
        libc::syscall(
            ((1 << 32) | libc::SYS_socket) as c_long,
            40 as c_long,
            STREAM,
            0 as c_long,
        ) as c_long
    });
    // Families that must keep working.
    let allowed: [(&str, c_long, c_long, c_long); 5] = [
        ("unix", 1, STREAM, 0),
        ("inet", 2, STREAM, 0),
        ("inet6", 10, STREAM, 0),
        ("netlink-route", 16, RAW, 0),
        ("unix-hiword", (1 << 32) | 1, STREAM, 0),
    ];
    for (label, family, ty, proto) in allowed {
        report(label, sock(family, ty, proto));
    }
    // socketpair(2) shares the family check.
    for (label, family) in [("socketpair-vsock", 40), ("socketpair-unix", 1)] {
        let mut pair = [0 as c_int; 2];
        // SAFETY: socketpair(2) into a two-element array we own.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_socketpair,
                family,
                STREAM,
                0 as c_long,
                pair.as_mut_ptr() as c_long,
            ) as c_long
        };
        if ret == 0 {
            println!("SOCK {label} ok");
            // SAFETY: the kernel returned two new fds we own.
            unsafe {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
        } else {
            report(label, ret);
        }
    }
    // io_uring: the three syscalls answer ENOSYS (the filter runs before the
    // kernel reads any argument, so NULL pointers are fine here).
    // SAFETY: syscall(2) with integer and NULL arguments.
    unsafe {
        report(
            "uring-setup",
            libc::syscall(libc::SYS_io_uring_setup, 1 as c_long, 0 as c_long) as c_long,
        );
        report(
            "uring-enter",
            libc::syscall(
                libc::SYS_io_uring_enter,
                0 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            ) as c_long,
        );
        report(
            "uring-register",
            libc::syscall(
                libc::SYS_io_uring_register,
                0 as c_long,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            ) as c_long,
        );
    }
    0
}

/// #34: `Seccomp:` for this process and pid 1, and the open fd numbers (the
/// fd this role's own directory read holds is excluded). The seccomp memfd
/// must not leak into the payload: bwrap closes it, so only 0–2 remain.
fn seccomp_status_role() -> u8 {
    for pid in ["self", "1"] {
        let text = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let mode = text
            .lines()
            .find_map(|line| line.strip_prefix("Seccomp:"))
            .map_or("missing", str::trim);
        println!("STATUS {pid} {mode}");
    }
    let own_dir = PathBuf::from(format!("/proc/{}/fd", std::process::id()));
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return 1;
    };
    let mut fds: Vec<i32> = Vec::new();
    for entry in entries.flatten() {
        if fs::read_link(entry.path()).ok().as_deref() == Some(own_dir.as_path()) {
            continue;
        }
        if let Some(n) = entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            fds.push(n);
        }
    }
    fds.sort_unstable();
    for fd in fds {
        println!("FD {fd}");
    }
    0
}

/// #34: an x32 syscall (bit 30 set). The filter kills the process.
#[cfg(target_arch = "x86_64")]
fn x32_syscall_role() -> u8 {
    // SAFETY: a syscall with the x32 bit; the filter kills before the kernel
    // acts on it, so no state is touched.
    unsafe { libc::syscall((0x4000_0000u32 | 39) as libc::c_long) };
    3
}

#[cfg(not(target_arch = "x86_64"))]
fn x32_syscall_role() -> u8 {
    3
}

/// #34: a 32-bit compat getpid through `int 0x80`. The arch gate kills.
#[cfg(target_arch = "x86_64")]
fn int80_role() -> u8 {
    // SAFETY: the i386 compat gate with eax = 20 (getpid); the filter kills
    // the process on the wrong audit arch before the kernel acts on it.
    unsafe {
        std::arch::asm!("int 0x80", inout("eax") 20i32 => _);
    }
    3
}

#[cfg(not(target_arch = "x86_64"))]
fn int80_role() -> u8 {
    3
}

fn print_env() {
    let mut vars: Vec<(String, Vec<u8>)> = std::env::vars_os()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.into_vec()))
        .collect();
    vars.sort();
    for (k, v) in vars {
        println!("ENV {k}={}", hex(&v));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn spawn_orphan(token: &str) {
    let exe = std::env::current_exe().expect("current exe");
    let mut cmd = Command::new(exe);
    cmd.arg("orphan-sleeper")
        .arg(token)
        .env(ROLE_ENV, "orphan-sleeper")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid in the child between fork and exec; async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let _ = cmd.spawn();
}

/// A minimal DNS A query over UDP to the sandbox's resolver (127.0.0.1:53).
fn dns_ask(name: &str) -> (u8, Option<Ipv4Addr>) {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return (255, None);
    };
    let _ = sock.set_read_timeout(Some(BOUND));
    if sock.send_to(&q, "127.0.0.1:53").is_err() {
        return (255, None);
    }
    let mut buf = [0u8; 512];
    let Ok((n, _)) = sock.recv_from(&mut buf) else {
        return (254, None);
    };
    let rcode = buf[3] & 0x0f;
    let answers = u16::from_be_bytes([buf[6], buf[7]]);
    if answers == 0 || n < 12 {
        return (rcode, None);
    }
    // Skip the question: labels then QTYPE/QCLASS.
    let mut i = 12;
    while i < n && buf[i] != 0 {
        i += buf[i] as usize + 1;
    }
    i += 5;
    // First answer: name (pointer or labels), type, class, ttl, rdlength, rdata.
    if i < n && buf[i] & 0xc0 == 0xc0 {
        i += 2;
    } else {
        while i < n && buf[i] != 0 {
            i += buf[i] as usize + 1;
        }
        i += 1;
    }
    if i + 10 + 4 <= n {
        let rdata = &buf[i + 10..i + 14];
        return (
            rcode,
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
        );
    }
    (rcode, None)
}

/// Dials and sends a ClientHello (with SNI if given); reports what came back.
/// Sends a CONNECT for a denied name through the explicit proxy and prints the
/// status line (`EXPLICIT …`).
fn explicit_connect_print() {
    let proxy = std::env::var("HTTPS_PROXY").unwrap_or_default();
    let addr = proxy.trim_start_matches("http://").to_owned();
    let mut s = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            println!("EXPLICIT connect-error {e}");
            return;
        }
    };
    let _ = s.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n");
    let _ = s.set_read_timeout(Some(BOUND));
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    println!("EXPLICIT {}", text.lines().next().unwrap_or(""));
}

fn dial(addr: SocketAddr, sni: Option<&str>) -> String {
    let mut s = match TcpStream::connect_timeout(&addr, BOUND) {
        Ok(s) => s,
        Err(e) => return format!("{addr} connect-error {}", e.kind()),
    };
    let _ = s.set_read_timeout(Some(BOUND));
    let hello = sbx::proxy::hello::build_client_hello(sni, &[]);
    if s.write_all(&hello).is_err() {
        return format!("{addr} closed");
    }
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(0) => format!("{addr} closed"),
        Ok(_) => format!("{addr} data"),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => format!("{addr} reset"),
        Err(_) => format!("{addr} closed"),
    }
}

// ---- parent-side helpers ---------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy)]
enum Gate {
    Always,
    Bwrap,
}

struct Scenario {
    name: &'static str,
    gate: Gate,
    run: fn() -> Result<(), String>,
}

fn scenarios() -> Vec<Scenario> {
    use Gate::{Always, Bwrap};
    vec![
        Scenario {
            name: "policy-missing-125",
            gate: Always,
            run: policy_missing_125,
        },
        Scenario {
            name: "policy-invalid-125",
            gate: Always,
            run: policy_invalid_125,
        },
        Scenario {
            name: "audit-inside-session-125",
            gate: Always,
            run: audit_inside_session_125,
        },
        Scenario {
            name: "audit-not-regular-125",
            gate: Always,
            run: audit_not_regular_125,
        },
        Scenario {
            name: "session-in-use-125",
            gate: Always,
            run: session_in_use_125,
        },
        Scenario {
            name: "bwrap-missing-125",
            gate: Always,
            run: bwrap_missing_125,
        },
        Scenario {
            name: "seccomp-vsock-eafnosupport",
            gate: Bwrap,
            run: seccomp_vsock_eafnosupport,
        },
        Scenario {
            name: "seccomp-allowed-families",
            gate: Bwrap,
            run: seccomp_allowed_families,
        },
        Scenario {
            name: "seccomp-io-uring-enosys",
            gate: Bwrap,
            run: seccomp_io_uring_enosys,
        },
        Scenario {
            name: "seccomp-status",
            gate: Bwrap,
            run: seccomp_status,
        },
        Scenario {
            name: "seccomp-x32-killed-159",
            gate: Bwrap,
            run: seccomp_x32_killed_159,
        },
        Scenario {
            name: "seccomp-int80-killed-159",
            gate: Bwrap,
            run: seccomp_int80_killed_159,
        },
        Scenario {
            name: "exit-code-passthrough",
            gate: Bwrap,
            run: exit_code_passthrough,
        },
        Scenario {
            name: "signalled-payload-128",
            gate: Bwrap,
            run: signalled_payload_128,
        },
        Scenario {
            name: "argv-verbatim-env-clean",
            gate: Bwrap,
            run: argv_verbatim_env_clean,
        },
        Scenario {
            name: "cwd-flag",
            gate: Bwrap,
            run: cwd_flag,
        },
        Scenario {
            name: "timeout-124",
            gate: Bwrap,
            run: timeout_124,
        },
        Scenario {
            name: "policy-timeout-min",
            gate: Bwrap,
            run: policy_timeout_min,
        },
        Scenario {
            name: "sigterm-143",
            gate: Bwrap,
            run: signal_scenario_term,
        },
        Scenario {
            name: "sigint-130",
            gate: Bwrap,
            run: signal_scenario_int,
        },
        Scenario {
            name: "sighup-129",
            gate: Bwrap,
            run: signal_scenario_hup,
        },
        Scenario {
            name: "sigquit-131",
            gate: Bwrap,
            run: signal_scenario_quit,
        },
        Scenario {
            name: "caller-ignored-sigint",
            gate: Bwrap,
            run: caller_ignored_sigint,
        },
        Scenario {
            name: "orphans-gone-natural",
            gate: Bwrap,
            run: orphans_gone_natural,
        },
        Scenario {
            name: "orphans-gone-after-timeout",
            gate: Bwrap,
            run: orphans_gone_after_timeout,
        },
        Scenario {
            name: "orphans-gone-after-sigterm",
            gate: Bwrap,
            run: orphans_gone_after_sigterm,
        },
        Scenario {
            name: "concurrent-10",
            gate: Bwrap,
            run: concurrent_10,
        },
        Scenario {
            name: "concurrent-same-session",
            gate: Bwrap,
            run: concurrent_same_session,
        },
        Scenario {
            name: "stdin-passthrough",
            gate: Bwrap,
            run: stdin_passthrough,
        },
        Scenario {
            name: "stderr-separate",
            gate: Bwrap,
            run: stderr_separate,
        },
        Scenario {
            name: "tty-never-inherited",
            gate: Bwrap,
            run: tty_never_inherited,
        },
        Scenario {
            name: "output-cap",
            gate: Bwrap,
            run: output_cap,
        },
        Scenario {
            name: "audit-under-policy-rw-125",
            gate: Always,
            run: audit_under_policy_rw_125,
        },
        Scenario {
            name: "policy-fifo-125",
            gate: Always,
            run: policy_fifo_125,
        },
        Scenario {
            name: "closed-stderr-rc-125",
            gate: Always,
            run: closed_stderr_rc_125,
        },
        Scenario {
            name: "closed-stderr-rc-124",
            gate: Bwrap,
            run: closed_stderr_rc_124,
        },
        Scenario {
            name: "shared-audit-two-writers",
            gate: Bwrap,
            run: shared_audit_two_writers,
        },
        Scenario {
            name: "audit-under-policy-ro-125",
            gate: Always,
            run: audit_under_policy_ro_125,
        },
        Scenario {
            name: "audit-lock-held-fails-closed",
            gate: Bwrap,
            run: audit_lock_held_fails_closed,
        },
        Scenario {
            name: "partial-stderr-framing-merged",
            gate: Bwrap,
            run: partial_stderr_framing_merged,
        },
        Scenario {
            name: "output-cap-merged",
            gate: Bwrap,
            run: output_cap_merged,
        },
        Scenario {
            name: "partial-stderr-framing",
            gate: Bwrap,
            run: partial_stderr_framing,
        },
        Scenario {
            name: "output-epipe",
            gate: Bwrap,
            run: output_epipe,
        },
        Scenario {
            name: "sigmask-clean",
            gate: Bwrap,
            run: sigmask_clean,
        },
        Scenario {
            name: "audit-rows",
            gate: Bwrap,
            run: audit_rows_check,
        },
        Scenario {
            name: "mode-none-clamped",
            gate: Bwrap,
            run: mode_none_clamped,
        },
        Scenario {
            name: "proxy-env-explicit",
            gate: Bwrap,
            run: proxy_env_explicit,
        },
        Scenario {
            name: "audit-write-fail-closed",
            gate: Bwrap,
            run: audit_write_fail_closed,
        },
        Scenario {
            name: "payload-not-found-rc1",
            gate: Bwrap,
            run: payload_not_found_rc1,
        },
        Scenario {
            name: "audit-write-fail-after-main-loop-125",
            gate: Bwrap,
            run: audit_write_fail_after_main_loop_125,
        },
        Scenario {
            name: "audit-symlinked-parent-125",
            gate: Always,
            run: audit_symlinked_parent_125,
        },
        Scenario {
            name: "bwrap-version-timeout-124",
            gate: Always,
            run: bwrap_version_timeout_124,
        },
        Scenario {
            name: "prelaunch-deny-chain-symlink-125",
            gate: Bwrap,
            run: prelaunch_deny_chain_symlink_125,
        },
        Scenario {
            name: "prelaunch-deny-leaf-symlink-125",
            gate: Bwrap,
            run: prelaunch_deny_leaf_symlink_125,
        },
        Scenario {
            name: "prelaunch-deny-missing-125",
            gate: Bwrap,
            run: prelaunch_deny_missing_125,
        },
        Scenario {
            name: "prelaunch-deny-is-file-125",
            gate: Bwrap,
            run: prelaunch_deny_is_file_125,
        },
        Scenario {
            name: "prelaunch-nested-ro-chain-symlink-125",
            gate: Bwrap,
            run: prelaunch_nested_ro_chain_symlink_125,
        },
        Scenario {
            name: "prelaunch-nested-ro-leaf-symlink-125",
            gate: Bwrap,
            run: prelaunch_nested_ro_leaf_symlink_125,
        },
        Scenario {
            name: "prelaunch-nested-ro-relative-leaf-125",
            gate: Bwrap,
            run: prelaunch_nested_ro_relative_leaf_125,
        },
        Scenario {
            name: "c1-nested-rw-parent-rename-ebusy",
            gate: Bwrap,
            run: c1_nested_rw_parent_rename_ebusy,
        },
        Scenario {
            name: "c1-nested-ro-write-through-renamed-parent",
            gate: Bwrap,
            run: c1_nested_ro_write_through_renamed_parent,
        },
        Scenario {
            name: "prelaunch-planted-under-ro-cover-125",
            gate: Bwrap,
            run: prelaunch_planted_under_ro_cover_125,
        },
        Scenario {
            name: "prelaunch-deny-under-plain-ro-125",
            gate: Bwrap,
            run: prelaunch_deny_under_plain_ro_125,
        },
        Scenario {
            name: "c1-concurrent-source-swap-no-escape",
            gate: Bwrap,
            run: c1_concurrent_source_swap_no_escape,
        },
        Scenario {
            name: "prelaunch-bind-containing-deny-via-link-125",
            gate: Bwrap,
            run: prelaunch_bind_containing_deny_via_link_125,
        },
        Scenario {
            name: "nested-deny-under-deny-runs",
            gate: Bwrap,
            run: nested_deny_under_deny_runs,
        },
        Scenario {
            name: "prelaunch-n19-host-alias-ro-125",
            gate: Bwrap,
            run: prelaunch_n19_host_alias_ro_125,
        },
        Scenario {
            name: "prelaunch-n19-host-alias-rw-125",
            gate: Bwrap,
            run: prelaunch_n19_host_alias_rw_125,
        },
        Scenario {
            name: "prelaunch-alias-of-deny-125",
            gate: Bwrap,
            run: prelaunch_alias_of_deny_125,
        },
        Scenario {
            name: "prelaunch-reused-session-leaf-symlink-125",
            gate: Bwrap,
            run: prelaunch_reused_session_leaf_symlink_125,
        },
        Scenario {
            name: "pin-rename-of-deny-chain-ebusy",
            gate: Bwrap,
            run: pin_rename_of_deny_chain_ebusy,
        },
        Scenario {
            name: "pin-rename-of-nested-ro-ebusy",
            gate: Bwrap,
            run: pin_rename_of_nested_ro_ebusy,
        },
        Scenario {
            name: "pin-legit-deny-depth2-fresh-and-reused",
            gate: Bwrap,
            run: pin_legit_deny_depth2_fresh_and_reused,
        },
        Scenario {
            name: "pin-cross-pin-rename-is-exdev",
            gate: Bwrap,
            run: pin_cross_pin_rename_is_exdev,
        },
        Scenario {
            name: "session-leaf-deny-fresh-and-reused",
            gate: Bwrap,
            run: session_leaf_deny_fresh_and_reused,
        },
        Scenario {
            name: "bwrap-version-signal-143",
            gate: Always,
            run: bwrap_version_signal_143,
        },
        Scenario {
            name: "init-sigmask-reset",
            gate: Bwrap,
            run: init_sigmask_reset,
        },
        Scenario {
            name: "session-mtime-touched",
            gate: Bwrap,
            run: session_mtime_touched,
        },
        Scenario {
            name: "startup-overhead-report",
            gate: Bwrap,
            run: startup_overhead_report,
        },
        Scenario {
            name: "explicit-fallback-break-rules",
            gate: Bwrap,
            run: explicit_fallback_break_rules,
        },
        Scenario {
            name: "none-fallback-break-rules",
            gate: Bwrap,
            run: none_fallback_break_rules,
        },
        Scenario {
            name: "transparent-refused-break-rules-125",
            gate: Bwrap,
            run: transparent_refused_break_rules_125,
        },
        Scenario {
            name: "refused-no-userns-125",
            gate: Bwrap,
            run: refused_no_userns_125,
        },
        Scenario {
            name: "refused-ro-proc-sys-125",
            gate: Bwrap,
            run: refused_ro_proc_sys_125,
        },
        Scenario {
            name: "gc-skips-live-run",
            gate: Bwrap,
            run: gc_skips_live_run,
        },
        Scenario {
            name: "gc-hostile-payload-tree",
            gate: Bwrap,
            run: gc_hostile_payload_tree,
        },
        Scenario {
            name: "run-vs-gc-race",
            gate: Bwrap,
            run: run_vs_gc_race,
        },
    ]
}

/// A private scratch area per scenario (unique, under the system temp dir).
fn scratch(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sbx-run-it-{}-{}-{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn payload_exe() -> PathBuf {
    std::env::current_exe()
        .expect("current exe")
        .canonicalize()
        .expect("canonical exe")
}

/// The policy text. `role` (when given) rides in `env.set` as the payload role.
#[derive(Clone)]
struct Pol {
    mode: &'static str,
    allow: Vec<String>,
    ports: Vec<u16>,
    timeout: &'static str,
    output_bytes: u64,
    rw: Vec<String>,
    ro_extra: Vec<String>,
    deny: Vec<String>,
    role: Option<String>,
    env_set: Vec<(String, String)>,
    env_pass: Vec<String>,
}

impl Pol {
    fn new(role: &str) -> Self {
        Self {
            mode: "transparent",
            allow: Vec::new(),
            ports: Vec::new(),
            timeout: "30s",
            output_bytes: 1 << 20,
            rw: Vec::new(),
            ro_extra: Vec::new(),
            deny: Vec::new(),
            role: Some(role.to_owned()),
            env_set: Vec::new(),
            env_pass: Vec::new(),
        }
    }

    fn json(&self) -> String {
        let exe_dir = payload_exe().parent().expect("exe dir").to_path_buf();
        let mut env_set: Vec<(String, String)> = self.env_set.clone();
        if let Some(role) = &self.role {
            env_set.push((ROLE_ENV.to_owned(), role.clone()));
        }
        let set = env_set
            .iter()
            .map(|(k, v)| format!("{k:?}:{v:?}"))
            .collect::<Vec<_>>()
            .join(",");
        let pass = self
            .env_pass
            .iter()
            .map(|k| format!("{k:?}"))
            .collect::<Vec<_>>()
            .join(",");
        let allow = self
            .allow
            .iter()
            .map(|d| format!("{d:?}"))
            .collect::<Vec<_>>()
            .join(",");
        let ports = self
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"version":1,"filesystem":{{"ro":["/usr",{exe_dir:?}{ro_extra}],"rw":[{rw}],"deny":[{deny}]}},"network":{{"mode":"{mode}","allow":[{allow}],"ports":[{ports}]}},"env":{{"pass":[{pass}],"set":{{{set}}}}},"limits":{{"timeout":"{timeout}","output_bytes":{out}}}}}"#,
            mode = self.mode,
            ro_extra = self
                .ro_extra
                .iter()
                .map(|p| format!(",{p:?}"))
                .collect::<Vec<_>>()
                .join(""),
            rw = self
                .rw
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(","),
            deny = self
                .deny
                .iter()
                .map(|p| format!("{p:?}"))
                .collect::<Vec<_>>()
                .join(","),
            timeout = self.timeout,
            out = self.output_bytes,
        )
    }

    /// Writes the policy into `dir` and returns its path.
    fn write(&self, dir: &Path) -> PathBuf {
        let path = dir.join("policy.json");
        fs::write(&path, self.json()).expect("write policy");
        path
    }
}

/// The payload argv for a role with arguments: `[this exe, args...]`.
fn payload(args: &[&str]) -> Vec<OsString> {
    let mut cmd = vec![payload_exe().into_os_string()];
    cmd.extend(args.iter().map(OsString::from));
    cmd
}

/// Builds the sbx argv: `run --policy P --session-dir S <extra> -- CMD…`.
fn sbx_args(policy: &Path, session: &Path, extra: &[&str], cmd: &[OsString]) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "run".into(),
        "--policy".into(),
        policy.into(),
        "--session-dir".into(),
        session.into(),
    ];
    args.extend(extra.iter().map(OsString::from));
    args.push("--".into());
    args.extend(cmd.iter().cloned());
    args
}

/// A running sbx with its output collected by reader threads.
struct Proc {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    out: Arc<Mutex<Vec<u8>>>,
    err: Arc<Mutex<Vec<u8>>>,
    readers: Vec<JoinHandle<()>>,
}

struct Done {
    rc: i32,
    stdout: String,
    stderr: String,
}

fn collect(
    src: Option<impl Read + Send + 'static>,
) -> (Arc<Mutex<Vec<u8>>>, Option<JoinHandle<()>>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let Some(mut src) = src else {
        return (buf, None);
    };
    let sink = buf.clone();
    let handle = thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match src.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink.lock().expect("buf").extend_from_slice(&chunk[..n]),
            }
        }
    });
    (buf, Some(handle))
}

impl Proc {
    fn spawn(args: &[OsString], configure: impl FnOnce(&mut Command)) -> Result<Proc, String> {
        let mut cmd = Command::new(SBX);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Reset the signals these scenarios send to their defaults: sbx keeps
        // whatever the caller ignores (Q5), and the harness's own parent (cargo)
        // may ignore some of them. Registered BEFORE `configure`, so a scenario
        // that sets SIG_IGN itself still wins.
        // SAFETY: only signal(2) runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP, libc::SIGTERM] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                Ok(())
            });
        }
        configure(&mut cmd);
        let mut child = cmd.spawn().map_err(|e| format!("spawn sbx: {e}"))?;
        let stdin = child.stdin.take();
        let (out, h1) = collect(child.stdout.take());
        let (err, h2) = collect(child.stderr.take());
        Ok(Proc {
            child,
            stdin,
            out,
            err,
            readers: h1.into_iter().chain(h2).collect(),
        })
    }

    fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().expect("out")).into_owned()
    }

    /// Waits until stdout contains `needle` (bounded).
    fn wait_stdout(&self, needle: &str) -> Result<(), String> {
        let until = Instant::now() + BOUND;
        loop {
            if self.stdout_text().contains(needle) {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(format!(
                    "stdout never contained {needle:?}; got {:?}",
                    self.stdout_text()
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Waits for exit (bounded by `limit`), killing sbx on overrun.
    fn finish(mut self, limit: Duration) -> Result<Done, String> {
        drop(self.stdin.take());
        let until = Instant::now() + limit;
        let status: ExitStatus = loop {
            match self.child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(e) => return Err(format!("wait sbx: {e}")),
            }
            if Instant::now() >= until {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err(format!("sbx did not exit within {limit:?}"));
            }
            thread::sleep(Duration::from_millis(5));
        };
        for h in self.readers.drain(..) {
            let _ = h.join();
        }
        let rc = match status.code() {
            Some(code) => code,
            None => return Err(format!("sbx killed by a signal: {status:?}")),
        };
        Ok(Done {
            rc,
            stdout: String::from_utf8_lossy(&self.out.lock().expect("out")).into_owned(),
            stderr: String::from_utf8_lossy(&self.err.lock().expect("err")).into_owned(),
        })
    }
}

/// One complete sbx run.
fn run_sbx(args: &[OsString]) -> Result<Done, String> {
    Proc::spawn(args, |_| {})?.finish(Duration::from_secs(60))
}

/// Parses every line of a JSON-lines audit file.
fn read_audit(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read audit {path:?}: {e}"))?;
    text.lines()
        .map(|l| serde_json::from_str(l).map_err(|e| format!("bad audit line {l:?}: {e}")))
        .collect()
}

fn expect_rc(done: &Done, want: i32) -> Result<(), String> {
    if done.rc == want {
        Ok(())
    } else {
        Err(format!(
            "rc {} (want {want})\nstdout: {:?}\nstderr: {:?}",
            done.rc, done.stdout, done.stderr
        ))
    }
}

fn expect_stderr(done: &Done, needle: &str) -> Result<(), String> {
    if done.stderr.contains(needle) {
        Ok(())
    } else {
        Err(format!("stderr lacks {needle:?}: {:?}", done.stderr))
    }
}

/// A 125 refusal before any spawn: rc 125, the `sbx run: ` prefix, and the text.
fn expect_refusal(args: &[OsString], needle: &str) -> Result<(), String> {
    let done = run_sbx(args)?;
    expect_rc(&done, 125)?;
    if !done.stderr.starts_with("sbx run: ") {
        return Err(format!(
            "stderr lacks the sbx run: prefix: {:?}",
            done.stderr
        ));
    }
    expect_stderr(&done, needle)
}

fn bwrap_available() -> bool {
    // Probe with the real binary: a trivial run must succeed.
    let dir = scratch("probe");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let ok = matches!(run_sbx(&args), Ok(d) if d.rc == 0);
    let _ = fs::remove_dir_all(&dir);
    ok
}

// ---- Always-gated scenarios ------------------------------------------------

fn policy_missing_125() -> Result<(), String> {
    let dir = scratch("pmiss");
    let args = sbx_args(
        &dir.join("nope.json"),
        &dir.join("s"),
        &[],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "cannot read");
    let _ = fs::remove_dir_all(&dir);
    r
}

fn policy_invalid_125() -> Result<(), String> {
    let dir = scratch("pinv");
    let policy = dir.join("bad.json");
    fs::write(&policy, r#"{"version":2}"#).expect("write");
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let r = expect_refusal(&args, "missing field");
    let _ = fs::remove_dir_all(&dir);
    r
}

fn audit_inside_session_125() -> Result<(), String> {
    let dir = scratch("ains");
    let session = dir.join("s");
    let policy = Pol::new("exit").write(&dir);
    let audit = session.join("work").join("..").join("a.jsonl");
    let args = sbx_args(
        &policy,
        &session,
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "--audit must not be inside the session directory");
    let _ = fs::remove_dir_all(&dir);
    r
}

fn audit_not_regular_125() -> Result<(), String> {
    let dir = scratch("anreg");
    let policy = Pol::new("exit").write(&dir);
    // A directory.
    let as_dir = dir.join("adir");
    fs::create_dir_all(&as_dir).expect("mkdir");
    let args = sbx_args(
        &policy,
        &dir.join("s1"),
        &["--audit", as_dir.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    expect_refusal(&args, "cannot open audit log")?;
    // A symlink (O_NOFOLLOW).
    let target = dir.join("target.jsonl");
    fs::write(&target, b"").expect("write");
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let args = sbx_args(
        &policy,
        &dir.join("s2"),
        &["--audit", link.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "cannot open audit log");
    let _ = fs::remove_dir_all(&dir);
    r
}

fn session_in_use_125() -> Result<(), String> {
    let dir = scratch("inuse");
    let session = dir.join("s");
    fs::create_dir_all(&session).expect("mkdir");
    let lock = fs::File::create(session.join("sbx.lock")).expect("lock file");
    // SAFETY: flock on a file this test owns; held until `lock` drops.
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err("test could not take the flock".into());
    }
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(&policy, &session, &[], &payload(&["0"]));
    let r = expect_refusal(&args, "session directory is in use");
    drop(lock);
    let _ = fs::remove_dir_all(&dir);
    r
}

fn bwrap_missing_125() -> Result<(), String> {
    let dir = scratch("nobw");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let done = Proc::spawn(&args, |cmd| {
        cmd.env("SBX_BWRAP", "/nonexistent/bwrap");
    })?
    .finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(&done, "sbx run: ")
}

// ---- Bwrap-gated scenarios -------------------------------------------------

/// Runs one payload role under a fresh policy and session. Returns the done record.
fn run_role_case(
    tag: &str,
    role: &str,
    role_args: &[&str],
    tweak: impl FnOnce(&mut Pol),
    extra: &[&str],
) -> Result<(Done, PathBuf), String> {
    let dir = scratch(tag);
    let mut pol = Pol::new(role);
    tweak(&mut pol);
    let policy = pol.write(&dir);
    let session = dir.join("s");
    let args = sbx_args(&policy, &session, extra, &payload(role_args));
    let done = run_sbx(&args)?;
    Ok((done, dir))
}

/// #34: the `SOCK` lines of one `sockets` run, label → value.
fn seccomp_sockets() -> Result<std::collections::BTreeMap<String, String>, String> {
    let (done, dir) = run_role_case("seccomp-sockets", "sockets", &[], |_| {}, &[])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    let mut map = std::collections::BTreeMap::new();
    for line in done.stdout.lines() {
        if let Some(rest) = line.strip_prefix("SOCK ") {
            let (label, value) = rest
                .split_once(' ')
                .ok_or_else(|| format!("malformed SOCK line {line:?}"))?;
            map.insert(label.to_owned(), value.to_owned());
        }
    }
    Ok(map)
}

fn expect_socket(
    map: &std::collections::BTreeMap<String, String>,
    label: &str,
    want: &str,
) -> Result<(), String> {
    match map.get(label) {
        Some(got) if got == want => Ok(()),
        other => Err(format!("socket probe {label}: want {want}, got {other:?}")),
    }
}

/// #34 AC1: every family outside the allow-list, reached by any route the
/// probes cover, fails with EAFNOSUPPORT (97) — AF_VSOCK included, and the
/// high-word spelling of it.
fn seccomp_vsock_eafnosupport() -> Result<(), String> {
    // Host baseline, outside any filter: does socket(AF_VSOCK) work here? If
    // it does, the sandbox's errno 97 below is discriminating; if the host
    // also refuses (no vsock module), the scenario still asserts 97 but says
    // so instead of implying the filter was proven by it.
    // SAFETY: a plain socket(2) with integer arguments, closed at once.
    let host = unsafe {
        libc::syscall(
            libc::SYS_socket,
            40 as libc::c_long,
            1 as libc::c_long,
            0 as libc::c_long,
        ) as libc::c_long
    };
    let host_vsock = if host >= 0 {
        // SAFETY: the kernel returned a fresh fd this process owns.
        unsafe { libc::close(host as i32) };
        "ok".to_owned()
    } else {
        format!(
            "errno {}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )
    };
    if host_vsock == "ok" {
        println!("host vsock baseline (unfiltered): ok — the sandbox errno 97 is discriminating");
    } else {
        println!(
            "host vsock baseline (unfiltered): {host_vsock} — vsock unavailable on this host; the 97 below does not prove the filter by itself"
        );
    }
    let map = seccomp_sockets()?;
    for label in [
        "vsock",
        "packet",
        "xdp",
        "alg",
        "bluetooth",
        "unspec",
        "above-max",
        "vsock-hiword",
        "vsock-hiword-nr",
        "socketpair-vsock",
    ] {
        expect_socket(&map, label, "errno=97")?;
    }
    Ok(())
}

/// #34 AC2: the allow-listed families keep working (AF_INET6 is allowed by
/// design; it fails later on the disabled IPv6 stack, not here).
fn seccomp_allowed_families() -> Result<(), String> {
    let map = seccomp_sockets()?;
    for label in [
        "unix",
        "inet",
        "inet6",
        "netlink-route",
        "unix-hiword",
        "socketpair-unix",
    ] {
        expect_socket(&map, label, "ok")?;
    }
    Ok(())
}

/// #34: io_uring setup, enter and register answer ENOSYS (38), so libuv and
/// liburing fall back instead of creating sockets through IORING_OP_SOCKET.
fn seccomp_io_uring_enosys() -> Result<(), String> {
    let map = seccomp_sockets()?;
    for label in ["uring-setup", "uring-enter", "uring-register"] {
        expect_socket(&map, label, "errno=38")?;
    }
    Ok(())
}

/// #34: bwrap installed the filter in pid 1 and in the payload (`Seccomp: 2`
/// is SECCOMP_MODE_FILTER), and the memfd did not leak (fds are exactly 0–2).
fn seccomp_status() -> Result<(), String> {
    let (done, dir) = run_role_case("seccomp-status", "seccomp-status", &[], |_| {}, &[])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    for want in ["STATUS self 2", "STATUS 1 2"] {
        if !done.stdout.lines().any(|line| line == want) {
            return Err(format!("missing {want:?}\nstdout: {:?}", done.stdout));
        }
    }
    let fds: Vec<&str> = done
        .stdout
        .lines()
        .filter_map(|line| line.strip_prefix("FD "))
        .collect();
    if fds != ["0", "1", "2"] {
        return Err(format!("payload fds must be exactly 0-2, got {fds:?}"));
    }
    Ok(())
}

/// #34: an x32 syscall is killed by the filter: SIGSYS, so rc 128+31 = 159.
fn seccomp_x32_killed_159() -> Result<(), String> {
    if !cfg!(target_arch = "x86_64") {
        println!("SKIP seccomp-x32-killed-159: the x32 ABI is x86_64-only");
        return Ok(());
    }
    let (done, dir) = run_role_case("seccomp-x32", "x32-syscall", &[], |_| {}, &[])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 159)
}

/// #34: the i386 `int 0x80` compat entry is killed by the arch gate (rc 159).
/// Baseline first: the same role run directly, outside sbx. On a kernel
/// without IA32 emulation the unfiltered `int 0x80` faults (SIGSEGV), so
/// there is no compat path to close and the scenario reports SKIP; with
/// emulation the filter must turn the call into SIGSYS (rc 159).
fn seccomp_int80_killed_159() -> Result<(), String> {
    if !cfg!(target_arch = "x86_64") {
        println!("SKIP seccomp-int80-killed-159: the int 0x80 compat entry is x86_64-only");
        return Ok(());
    }
    let baseline = Command::new(payload_exe())
        .env(ROLE_ENV, "int80-syscall")
        .status()
        .map_err(|e| format!("spawn int80 baseline: {e}"))?;
    if baseline.code() != Some(3) {
        println!(
            "SKIP seccomp-int80-killed-159: unfiltered int 0x80 does not complete here ({baseline})"
        );
        return Ok(());
    }
    let (done, dir) = run_role_case("seccomp-int80", "int80-syscall", &[], |_| {}, &[])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 159)
}

fn exit_code_passthrough() -> Result<(), String> {
    for code in ["0", "3", "255"] {
        let (done, dir) = run_role_case("exit", "exit", &[code], |_| {}, &[])?;
        let _ = fs::remove_dir_all(&dir);
        expect_rc(&done, code.parse::<i32>().expect("number"))?;
    }
    Ok(())
}

fn signalled_payload_128() -> Result<(), String> {
    for (sig, want) in [("15", 143), ("11", 139)] {
        let (done, dir) = run_role_case("sigpay", "self-signal", &[sig], |_| {}, &[])?;
        let _ = fs::remove_dir_all(&dir);
        expect_rc(&done, want)?;
    }
    Ok(())
}

fn argv_verbatim_env_clean() -> Result<(), String> {
    let dir = scratch("argv");
    let mut pol = Pol::new("argv");
    pol.env_set.push(("FOO".into(), "bar".into()));
    pol.env_pass.push("PASS_ME".into());
    let policy = pol.write(&dir);
    // A non-UTF-8 argument, hyphenated arguments, and an empty one.
    let weird = OsString::from_vec(vec![b'a', 0xff, 0xfe, b'z']);
    let mut cmd = payload(&["-x", "--weird=1", "", "tail"]);
    cmd.push(weird.clone());
    let args = sbx_args(&policy, &dir.join("s"), &[], &cmd);
    let done = Proc::spawn(&args, |c| {
        c.env("PASS_ME", "pass-value")
            .env("HOST_SECRET", "must-not-leak");
    })?
    .finish(Duration::from_secs(60))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    let got: Vec<Vec<u8>> = done
        .stdout
        .lines()
        .filter_map(|l| l.strip_prefix("ARG "))
        .map(unhex)
        .collect();
    let want: Vec<Vec<u8>> = [&b"-x"[..], b"--weird=1", b"", b"tail", weird.as_bytes()]
        .iter()
        .map(|b| b.to_vec())
        .collect();
    // The payload's argv[0] is the exe; ARG lines are its arguments after the role.
    let role_args: Vec<Vec<u8>> = got.into_iter().collect();
    if role_args != want {
        return Err(format!("argv not verbatim: got {role_args:?}"));
    }
    if done.stdout.contains("HOST_SECRET") {
        return Err("host secret leaked into the payload environment".into());
    }
    if !done.stdout.contains("ENV PASS_ME=")
        || !done
            .stdout
            .contains(&format!("ENV PASS_ME={}", hex(b"pass-value")))
    {
        return Err(format!("env.pass value missing: {}", done.stdout));
    }
    if !done.stdout.contains(&format!("ENV FOO={}", hex(b"bar"))) {
        return Err("env.set value missing".into());
    }
    Ok(())
}

fn cwd_flag() -> Result<(), String> {
    let (done, dir) = run_role_case("cwd", "cwd", &[], |_| {}, &["--cwd", "/tmp"])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if done.stdout.contains("CWD /tmp") {
        Ok(())
    } else {
        Err(format!("payload cwd not /tmp: {:?}", done.stdout))
    }
}

fn timeout_124() -> Result<(), String> {
    let dir = scratch("to124");
    let policy = Pol::new("ready-sleep").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--timeout", "1s"],
        &payload(&["30"]),
    );
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 124)?;
    expect_stderr(&done, "sbx run: timed out after 1s")
}

fn policy_timeout_min() -> Result<(), String> {
    let dir = scratch("tomin");
    let mut pol = Pol::new("ready-sleep");
    pol.timeout = "1s";
    let policy = pol.write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--timeout", "60s"],
        &payload(&["30"]),
    );
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 124)
}

/// Starts a ready-sleep payload, waits for READY, sends `sig`, expects `want`.
fn signal_case(sig: libc::c_int, want: i32, name: &str) -> Result<(), String> {
    let dir = scratch(name);
    let policy = Pol::new("ready-sleep").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["30"]));
    let proc_ = Proc::spawn(&args, |_| {})?;
    proc_.wait_stdout("READY")?;
    let pid = proc_.child.id();
    let before = proc_masks(pid);
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(pid as libc::pid_t, sig) };
    let done = match proc_.finish(Duration::from_secs(30)) {
        Ok(done) => done,
        Err(err) => return Err(format!("{err}; sbx masks before the signal: {before}")),
    };
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, want)
}

/// The SigIgn/SigBlk lines of a live process (diagnostics for flaky signal tests).
fn proc_masks(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("SigIgn") || l.starts_with("SigBlk"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn signal_scenario_term() -> Result<(), String> {
    signal_case(libc::SIGTERM, 143, "sigterm")
}
fn signal_scenario_int() -> Result<(), String> {
    signal_case(libc::SIGINT, 130, "sigint")
}
fn signal_scenario_hup() -> Result<(), String> {
    signal_case(libc::SIGHUP, 129, "sighup")
}
fn signal_scenario_quit() -> Result<(), String> {
    signal_case(libc::SIGQUIT, 131, "sigquit")
}

fn caller_ignored_sigint() -> Result<(), String> {
    let dir = scratch("ignint");
    let policy = Pol::new("ready-sleep").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["1"]));
    let proc_ = Proc::spawn(&args, |cmd| {
        // SAFETY: only signal(2) runs between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                Ok(())
            });
        }
    })?;
    proc_.wait_stdout("READY")?;
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(proc_.child.id() as libc::pid_t, libc::SIGINT) };
    let done = proc_.finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)
}

/// M3: is the GRANDCHILD (`orphan-sleeper TOKEN`, a unique argv pair) alive on the
/// host? Matching the bare token is vacuous: sbx, bwrap and the `orphan` payload carry
/// it in their argv too. The needle is the exact NUL-separated argv pair.
fn host_has_token(token: &str) -> bool {
    let needle = format!("orphan-sleeper\0{token}\0");
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    entries.filter_map(|e| e.ok()).any(|e| {
        let name = e.file_name();
        if !name.as_bytes().iter().all(u8::is_ascii_digit) {
            return false;
        }
        fs::read(e.path().join("cmdline"))
            .map(|c| c.windows(needle.len()).any(|w| w == needle.as_bytes()))
            .unwrap_or(false)
    })
}

fn orphan_case(name: &str, token: &str, how: &str) -> Result<(), String> {
    let dir = scratch(name);
    let policy = Pol::new("orphan").write(&dir);
    let cmd = payload(&[token]);
    let extra: &[&str] = if how == "timeout" {
        &["--timeout", "2s"]
    } else {
        &[]
    };
    let args = sbx_args(&policy, &dir.join("s"), extra, &cmd);
    let proc_ = Proc::spawn(&args, |_| {})?;
    proc_.wait_stdout("ORPHAN-UP")?;
    // Non-vacuous: the grandchild is alive on the host while sbx runs.
    if !host_has_token(token) {
        return Err("orphan not visible on the host while sbx runs (vacuous check)".into());
    }
    if how == "sigterm" {
        // SAFETY: signalling our own child process by pid.
        unsafe { libc::kill(proc_.child.id() as libc::pid_t, libc::SIGTERM) };
    }
    let done = proc_.finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    if host_has_token(token) {
        return Err("orphan survived sbx".into());
    }
    expect_rc(
        &done,
        if how == "sigterm" {
            143
        } else if how == "timeout" {
            124
        } else {
            0
        },
    )
}

fn orphans_gone_natural() -> Result<(), String> {
    // The payload exits on its own right after spawning the grandchild.
    let dir = scratch("orphan-nat");
    let policy = Pol::new("orphan-exit").write(&dir);
    let token = "SBXORPHANNAT";
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&[token]));
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if host_has_token(token) {
        return Err("orphan survived a natural exit".into());
    }
    Ok(())
}

fn orphans_gone_after_timeout() -> Result<(), String> {
    orphan_case("orphan-to", "SBXORPHANTO", "timeout")
}

fn orphans_gone_after_sigterm() -> Result<(), String> {
    orphan_case("orphan-term", "SBXORPHANTERM", "sigterm")
}

fn concurrent_10() -> Result<(), String> {
    let root = scratch("conc");
    let mut runs = Vec::new();
    for i in 0..10u8 {
        let dir = root.join(format!("r{i}"));
        fs::create_dir_all(&dir).expect("mkdir");
        let name = format!("n{i}.example");
        let nonce = format!("NONCE{i:02}");
        let mut pol = Pol::new("concurrent");
        pol.allow.push(name.clone());
        let policy = pol.write(&dir);
        let session = dir.join("s");
        let audit = dir.join("a.jsonl");
        let code = i.to_string();
        let args = sbx_args(
            &policy,
            &session,
            &["--audit", audit.to_str().expect("utf8")],
            &payload(&[&nonce, &name, &code]),
        );
        runs.push((Proc::spawn(&args, |_| {})?, dir, name, nonce, i));
    }
    let mut problems = Vec::new();
    for (proc_, dir, name, nonce, i) in runs {
        let done = proc_.finish(Duration::from_secs(60))?;
        if done.rc != i as i32 {
            problems.push(format!(
                "run {i}: rc {} (stderr {:?})",
                done.rc, done.stderr
            ));
        }
        if !done.stdout.contains(&nonce) || done.stdout.matches("NONCE").count() != 1 {
            problems.push(format!(
                "run {i}: stdout not its own nonce: {:?}",
                done.stdout
            ));
        }
        let out = fs::read_to_string(dir.join("s").join("work").join("out")).unwrap_or_default();
        if out != nonce {
            problems.push(format!("run {i}: work/out is {out:?}"));
        }
        match read_audit(&dir.join("a.jsonl")) {
            Ok(rows) => {
                let want = format!("answered {name} A 198.18.0.1");
                let has = rows
                    .iter()
                    .any(|r| r["event"] == "dns" && r["reason"].as_str() == Some(want.as_str()));
                let exit_ok = rows
                    .last()
                    .map(|r| r["event"] == "exit" && r["code"] == i as i64)
                    .unwrap_or(false);
                if !has {
                    problems.push(format!("run {i}: no `{want}` row"));
                }
                if !exit_ok {
                    problems.push(format!("run {i}: last row is not exit code {i}"));
                }
            }
            Err(e) => problems.push(format!("run {i}: {e}")),
        }
        let _ = fs::remove_dir_all(&dir);
    }
    let _ = fs::remove_dir_all(&root);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn concurrent_same_session() -> Result<(), String> {
    let dir = scratch("same");
    let policy = Pol::new("ready-sleep").write(&dir);
    let session = dir.join("s");
    let a = Proc::spawn(&sbx_args(&policy, &session, &[], &payload(&["30"])), |_| {})?;
    a.wait_stdout("READY")?;
    let b = run_sbx(&sbx_args(&policy, &session, &[], &payload(&["0"])))?;
    expect_rc(&b, 125)?;
    expect_stderr(&b, "session directory is in use")?;
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(a.child.id() as libc::pid_t, libc::SIGTERM) };
    let done = a.finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 143)
}

fn stdin_passthrough() -> Result<(), String> {
    let dir = scratch("stdin");
    let policy = Pol::new("stdin-echo").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&[]));
    let mut proc_ = Proc::spawn(&args, |_| {})?;
    if let Some(mut stdin) = proc_.stdin.take() {
        let _ = stdin.write_all(b"hello-stdin\n");
    }
    let done = proc_.finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if done.stdout.contains("hello-stdin") {
        Ok(())
    } else {
        Err(format!("stdin not echoed: {:?}", done.stdout))
    }
}

fn stderr_separate() -> Result<(), String> {
    let (done, dir) = run_role_case("stderr", "stderr-marker", &[], |_| {}, &[])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if done.stdout.contains("ERRLINE")
        || !done.stderr.contains("ERRLINE")
        || !done.stdout.contains("OUTLINE")
    {
        return Err(format!(
            "streams mixed: out {:?} err {:?}",
            done.stdout, done.stderr
        ));
    }
    Ok(())
}

/// Opens a pseudo-terminal pair; returns (master, slave).
fn open_pty() -> Result<(OwnedFd, OwnedFd), String> {
    // SAFETY: standard pty allocation sequence; each fd is owned once.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return Err("posix_openpt failed".into());
        }
        let master = OwnedFd::from_raw_fd(master);
        if libc::grantpt(master.as_raw_fd()) != 0 || libc::unlockpt(master.as_raw_fd()) != 0 {
            return Err("grantpt/unlockpt failed".into());
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(master.as_raw_fd(), name.as_mut_ptr(), name.len()) != 0 {
            return Err("ptsname_r failed".into());
        }
        let path = std::ffi::CStr::from_ptr(name.as_ptr());
        let slave = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            return Err("open slave failed".into());
        }
        Ok((master, OwnedFd::from_raw_fd(slave)))
    }
}

fn tty_never_inherited() -> Result<(), String> {
    let dir = scratch("tty");
    let policy = Pol::new("tty-report").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&[]));
    let (_master, slave) = open_pty()?;
    let s1 = slave.try_clone().map_err(|e| e.to_string())?;
    let s2 = slave.try_clone().map_err(|e| e.to_string())?;
    let status = Command::new(SBX)
        .args(&args)
        .stdin(Stdio::from(slave))
        .stdout(Stdio::from(s1))
        .stderr(Stdio::from(s2))
        .status()
        .map_err(|e| format!("spawn sbx on pty: {e}"))?;
    let report = fs::read_to_string(dir.join("s").join("work").join("report")).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    if status.code() != Some(0) {
        return Err(format!("rc {:?}", status.code()));
    }
    if report.trim() != "isatty 0 0 0 console false" {
        return Err(format!("payload saw a tty or /dev/console: {report:?}"));
    }
    Ok(())
}

/// The flood payload writes only `x` bytes (no newlines), so every `x` on stdout or
/// stderr is a payload byte, and sbx's own lines (framing newline, notice) are not.
fn payload_x_bytes(done: &Done) -> usize {
    // sbx's own `sbx run: …` line contains an `x` ("sbx"): strip it first.
    let stderr = match done.stderr.find("sbx run: ") {
        Some(at) if at == 0 || done.stderr.as_bytes()[at - 1] == b'\n' => &done.stderr[..at],
        _ => done.stderr.as_str(),
    };
    done.stdout
        .bytes()
        .chain(stderr.bytes())
        .filter(|b| *b == b'x')
        .count()
}

fn output_cap() -> Result<(), String> {
    let dir = scratch("cap");
    let mut pol = Pol::new("flood");
    pol.output_bytes = 1000;
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["10000"]),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    let x = payload_x_bytes(&done);
    if x != 1000 {
        return Err(format!("forwarded {x} payload bytes, want 1000"));
    }
    // The notice is sbx's own final line, on its own line (review 3).
    let notice = "sbx run: output truncated at 1000 bytes (limits.output_bytes)\n";
    if !done.stderr.ends_with(notice) {
        return Err(format!("truncation notice missing: {:?}", done.stderr));
    }
    let head = &done.stderr[..done.stderr.len() - notice.len()];
    if !head.is_empty() && !head.ends_with('\n') {
        return Err(format!("notice glued to a payload line: {:?}", done.stderr));
    }
    let exit = rows.last().ok_or("no audit rows")?;
    if exit["output_truncated"] != true {
        return Err(format!("exit row output_truncated: {exit}"));
    }
    Ok(())
}

/// Review 3 (the CI failure): a payload that stops mid-line on stderr must not have
/// sbx's diagnostic glued onto that line. sbx starts its own line.
fn partial_stderr_framing() -> Result<(), String> {
    let dir = scratch("framing2");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--timeout", "1s"],
        &[
            OsString::from("/usr/bin/bash"),
            OsString::from("-c"),
            OsString::from("printf partial >&2; sleep 30"),
        ],
    );
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 124)?;
    if !done
        .stderr
        .starts_with("partial\nsbx run: timed out after 1s\n")
    {
        return Err(format!(
            "diagnostic glued to the partial line: {:?}",
            done.stderr
        ));
    }
    Ok(())
}

fn output_epipe() -> Result<(), String> {
    let dir = scratch("epipe");
    let policy = Pol::new("flood").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let mut child = Command::new(SBX)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn sbx: {e}"))?;
    // Read a little, then close the reader: the payload must die with SIGPIPE.
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let mut first = [0u8; 16];
    let _ = stdout.read(&mut first);
    drop(stdout);
    let status = wait_status(&mut child, Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    let rc = status.code().ok_or("sbx killed by a signal")?;
    if rc == 141 {
        Ok(())
    } else {
        Err(format!("rc {rc}, want 141 (payload SIGPIPE)"))
    }
}

fn wait_status(child: &mut std::process::Child, limit: Duration) -> Result<ExitStatus, String> {
    let until = Instant::now() + limit;
    loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(st);
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sbx did not exit".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn sigmask_clean() -> Result<(), String> {
    // A non-Rust payload (grep): the Rust runtime itself ignores SIGPIPE, so the
    // mask and the dispositions are only observable through a plain executable.
    let dir = scratch("mask");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &[],
        &[
            OsString::from("/usr/bin/grep"),
            OsString::from("-E"),
            OsString::from("^Sig(Blk|Ign)"),
            OsString::from("/proc/self/status"),
        ],
    );
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    let mut lines = done.stdout.lines();
    let blk = lines.next().unwrap_or("");
    let ign = lines.next().unwrap_or("");
    if blk != "SigBlk:\t0000000000000000" {
        return Err(format!("payload signal mask not empty: {blk:?}"));
    }
    let ign_bits = u64::from_str_radix(ign.trim_start_matches("SigIgn:").trim(), 16).unwrap_or(0);
    if ign_bits & (1 << 12) != 0 {
        return Err("SIGPIPE is ignored in the payload".into());
    }
    Ok(())
}

fn audit_rows_scenario(
    tag: &str,
    role: &str,
    role_args: &[&str],
    allow: &[&str],
) -> Result<(Vec<serde_json::Value>, Done, PathBuf), String> {
    let dir = scratch(tag);
    let mut pol = Pol::new(role);
    pol.allow = allow.iter().map(|s| s.to_string()).collect();
    pol.ports = vec![443];
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(role_args),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit)?;
    Ok((rows, done, dir))
}

fn audit_rows_check() -> Result<(), String> {
    let (rows, done, dir) = audit_rows_scenario("arows", "net-checks", &[], &["allowed.test"])?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    // Issue #11 (Q5): a transparent host records the achieved mode and never
    // prints the explicit-fallback notice.
    let exit = rows.last().ok_or("no rows")?;
    if exit["net_mode"] != "transparent" {
        return Err(format!("exit row net_mode: {exit}"));
    }
    if done.stderr.contains("notice:") {
        return Err(format!(
            "unexpected notice on a transparent run: {:?}",
            done.stderr
        ));
    }
    let has = |pred: &dyn Fn(&serde_json::Value) -> bool| rows.iter().any(pred);
    if !has(&|r| r["event"] == "dns" && r["host"] == "allowed.test" && r["verdict"] == "answered") {
        return Err("no answered DNS row for allowed.test".into());
    }
    if !has(&|r| {
        r["event"] == "dns"
            && r["host"] == "notallowed.test"
            && r["verdict"] == "denied"
            && r["rcode"] == 3
    }) {
        return Err("no denied NXDOMAIN row for notallowed.test".into());
    }
    if !has(&|r| {
        r["event"] == "deny"
            && r["verdict"] == "denied"
            && r["reason"].as_str().unwrap_or("").contains("SNI evil.test")
    }) {
        return Err("no SNI-mismatch deny row".into());
    }
    if !has(&|r| r["event"] == "deny" && r["port"] == 8080) {
        return Err("no port-denial row for 8080".into());
    }
    if !has(&|r| {
        r["event"] == "deny"
            && r["reason"]
                .as_str()
                .unwrap_or("")
                .contains("unknown fake IP 203.0.113.7")
    }) {
        return Err("no unknown-fake-IP deny row".into());
    }
    let last = rows.last().ok_or("no rows")?;
    if last["event"] != "exit" {
        return Err(format!("last row is not exit: {last}"));
    }
    Ok(())
}

fn mode_none_clamped() -> Result<(), String> {
    let dir = scratch("mnone");
    let mut pol = Pol::new("dns");
    pol.mode = "none";
    pol.allow = vec!["a.example".into()];
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["a.example"]),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if !rows
        .iter()
        .any(|r| r["event"] == "dns" && r["host"] == "a.example" && r["verdict"] == "denied")
    {
        return Err("mode none must clamp the allow list: no denied DNS row".into());
    }
    Ok(())
}

fn proxy_env_explicit() -> Result<(), String> {
    let dir = scratch("pxenv");
    let mut pol = Pol::new("env");
    pol.mode = "explicit";
    pol.allow = vec!["evil.example".into()];
    pol.env_set.push(("UNUSED".into(), "x".into()));
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&[]),
    );
    let done = run_sbx(&args)?;
    expect_rc(&done, 0)?;
    if !done.stdout.contains(&format!(
        "ENV HTTPS_PROXY={}",
        hex(b"http://127.0.0.1:3128")
    )) {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!("HTTPS_PROXY not visible: {}", done.stdout));
    }
    // Explicit CONNECT through the proxy: a 403 for a non-allowed name.
    let mut pol2 = Pol::new("explicit-connect");
    pol2.mode = "explicit";
    pol2.allow = vec!["allowed.test".into()];
    let policy2 = pol2.write(&dir);
    let args2 = sbx_args(
        &policy2,
        &dir.join("s2"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&[]),
    );
    let done2 = run_sbx(&args2)?;
    let rows = read_audit(&audit).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done2, 0)?;
    if !done2.stdout.contains("EXPLICIT HTTP/1.1 403") {
        return Err(format!(
            "explicit CONNECT not refused with 403: {}",
            done2.stdout
        ));
    }
    if !rows
        .iter()
        .any(|r| r["event"] == "deny" && r["via"] == "explicit-connect")
    {
        return Err("no explicit-connect deny audit row".into());
    }
    Ok(())
}

fn audit_write_fail_closed() -> Result<(), String> {
    let dir = scratch("awfail");
    let policy = Pol::new("dns-flood-hang").write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["60"]),
    );
    let proc_ = Proc::spawn(&args, |cmd| {
        // SAFETY: setrlimit and signal(3) only, between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &lim);
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                Ok(())
            });
        }
    })?;
    let done = proc_.finish(Duration::from_secs(30))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(&done, "sbx run: audit log write failed:")
}

fn payload_not_found_rc1() -> Result<(), String> {
    let dir = scratch("nf");
    let policy = Pol::new("exit").write(&dir);
    let cmd = vec![OsString::from("/nonexistent")];
    let args = sbx_args(&policy, &dir.join("s"), &[], &cmd);
    let done = run_sbx(&args)?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 1)?;
    expect_stderr(&done, "bwrap: execvp /nonexistent")
}

fn session_mtime_touched() -> Result<(), String> {
    let dir = scratch("mtime");
    let session = dir.join("s");
    fs::create_dir_all(&session).expect("mkdir");
    let times = [
        libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    ];
    let c = std::ffi::CString::new(session.as_os_str().as_bytes()).expect("cstr");
    // SAFETY: valid NUL-terminated path and a two-element timespec array.
    unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    let policy = Pol::new("exit").write(&dir);
    let done = run_sbx(&sbx_args(&policy, &session, &[], &payload(&["0"])))?;
    let mtime = fs::metadata(&session)
        .map_err(|e| e.to_string())?
        .modified()
        .map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 0)?;
    if mtime > std::time::UNIX_EPOCH + Duration::from_secs(1) {
        Ok(())
    } else {
        Err("session mtime was not touched by the run".into())
    }
}

/// AC3, report-only: never FAILs; prints the measured overhead.
fn startup_overhead_report() -> Result<(), String> {
    let bash = Path::new("/usr/bin/bash");
    if !bash.exists() {
        println!("INFO startup overhead: /usr/bin/bash missing; not measured");
        return Ok(());
    }
    let dir = scratch("overhead");
    let policy = Pol::new("exit").write(&dir);
    let mut sbx_times = Vec::new();
    let mut host_times = Vec::new();
    for i in 0..30 {
        let t = Instant::now();
        let _ = Command::new(bash).args(["-c", "true"]).status();
        if i >= 5 {
            host_times.push(t.elapsed());
        }
        let session = dir.join(format!("s{i}"));
        let args = sbx_args(
            &policy,
            &session,
            &[],
            &[
                OsString::from(bash),
                OsString::from("-c"),
                OsString::from("true"),
            ],
        );
        let t = Instant::now();
        let _ = Command::new(SBX)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if i >= 5 {
            sbx_times.push(t.elapsed());
        }
    }
    let _ = fs::remove_dir_all(&dir);
    let stat = |v: &mut Vec<Duration>| {
        v.sort();
        let median = v[v.len() / 2];
        let p90 = v[(v.len() * 9) / 10];
        (median, p90)
    };
    let (sm, sp) = stat(&mut sbx_times);
    let (hm, _) = stat(&mut host_times);
    let overhead = sm.as_secs_f64() * 1e3 - hm.as_secs_f64() * 1e3;
    println!(
        "INFO startup overhead (debug build): median {:.1} ms, p90 {:.1} ms (bash -c true median {:.1} ms, overhead {overhead:.1} ms); target < 25 ms (release: see CI step summary)",
        sm.as_secs_f64() * 1e3,
        sp.as_secs_f64() * 1e3,
        hm.as_secs_f64() * 1e3,
    );
    Ok(())
}

/// M1 probe: the exit row cannot be appended (RLIMIT_FSIZE, the file prefilled close
/// to the limit). The failure happens AFTER the main loop, so it must still end the
/// run as a failure (125), and the prefilled bytes must survive unchanged (no torn row).
fn audit_write_fail_after_main_loop_125() -> Result<(), String> {
    let dir = scratch("m1probe");
    let policy = Pol::new("exit").write(&dir);
    let audit = dir.join("a.jsonl");
    let prefill = vec![b'x'; 1000];
    fs::write(&audit, &prefill).expect("prefill");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let proc_ = Proc::spawn(&args, |cmd| {
        // SAFETY: setrlimit and signal(3) only, between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &lim);
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                Ok(())
            });
        }
    })?;
    let done = proc_.finish(Duration::from_secs(30))?;
    let after = fs::read(&audit).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(&done, "sbx run: audit log write failed:")?;
    if after != prefill {
        return Err(format!(
            "audit file changed: {} bytes, want {}",
            after.len(),
            prefill.len()
        ));
    }
    Ok(())
}

/// M2: an audit path whose PARENT is a symlink into the session directory is refused
/// (the lexical prefilter alone accepts it), and nothing is created in the session.
fn audit_symlinked_parent_125() -> Result<(), String> {
    let dir = scratch("m2link");
    let session = dir.join("s");
    fs::create_dir_all(&session).expect("mkdir");
    let alias = dir.join("alias");
    std::os::unix::fs::symlink(&session, &alias).expect("symlink");
    let policy = Pol::new("exit").write(&dir);
    let audit = alias.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &session,
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "--audit must not be inside the session directory");
    let created = session.join("a.jsonl").exists();
    let _ = fs::remove_dir_all(&dir);
    r?;
    if created {
        return Err("a file was created inside the session directory".into());
    }
    Ok(())
}

/// Writes an executable stand-in for bwrap (`body` after the shebang).
fn bwrap_stand_in(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("slow-bwrap");
    fs::write(&script, format!("#!/bin/sh\n{body}\n")).expect("write");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    script
}

/// m2: a `bwrap --version` that never returns is bounded by `--timeout` (124); the
/// child is killed rather than waited for.
fn bwrap_version_timeout_124() -> Result<(), String> {
    let dir = scratch("bwslow");
    let script = bwrap_stand_in(&dir, "sleep 30");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(
        &dir.join("s")
            .as_path()
            .to_path_buf()
            .as_path()
            .to_str()
            .map(|_| policy.clone())
            .unwrap_or(policy.clone()),
        &dir.join("s"),
        &["--timeout", "1s"],
        &payload(&["0"]),
    );
    let started = Instant::now();
    let proc_ = Proc::spawn(&args, |cmd| {
        cmd.env("SBX_BWRAP", &script);
    })?;
    let done = proc_.finish(Duration::from_secs(20))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 124)?;
    expect_stderr(&done, "sbx run: timed out after 1s")?;
    if started.elapsed() > Duration::from_secs(15) {
        return Err(format!(
            "bounded version check took {:?}",
            started.elapsed()
        ));
    }
    Ok(())
}

/// m2: a signal during a slow `bwrap --version` ends the run with 128+N (143).
fn bwrap_version_signal_143() -> Result<(), String> {
    let dir = scratch("bwsig");
    let mark = dir.join("started");
    let script = bwrap_stand_in(&dir, &format!("touch '{}'\nsleep 30", mark.display()));
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let proc_ = Proc::spawn(&args, |cmd| {
        cmd.env("SBX_BWRAP", &script);
    })?;
    // The marker proves the version check is running (signals already installed).
    let until = Instant::now() + BOUND;
    while !mark.exists() {
        if Instant::now() >= until {
            return Err("the bwrap stand-in never started".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(proc_.child.id() as libc::pid_t, libc::SIGTERM) };
    let done = proc_.finish(Duration::from_secs(20))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 143)?;
    expect_stderr(&done, "sbx run: terminated by SIGTERM")
}

/// m9: `__init` resets its own signal mask before anything else. Checked on the REAL
/// `__init` process while it waits for the go byte, with SIGTERM/SIGINT/SIGHUP/SIGQUIT
/// blocked on entry, so a removed reset would show up as a non-empty SigBlk.
fn init_sigmask_reset() -> Result<(), String> {
    use sbx::init::fdpass;
    use std::os::fd::{AsFd, AsRawFd};
    let dir = scratch("initmask");
    let (parent_end, child_end) = fdpass::control_socketpair().map_err(|e| e.to_string())?;
    let child_fd = fdpass::prepare_child_end(child_end.as_fd()).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(SBX);
    cmd.args([
        "__init",
        "--fd",
        &child_fd.to_string(),
        "--parent-pid",
        &std::process::id().to_string(),
        "--",
        "/usr/bin/grep",
        "-E",
        "^Sig(Blk|Ign)",
        "/proc/self/status",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // SAFETY: sigprocmask(2) only, between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
                libc::sigaddset(&mut set, sig);
            }
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("spawn __init: {e}"))?;
    drop(child_end); // the spawn window is over: the parent closes its copy
    // __init sends its listener fds, then blocks in the go wait: sample it there.
    let listeners =
        fdpass::recv_listener_fds(parent_end.as_raw_fd()).map_err(|e| format!("recv fds: {e}"))?;
    drop(listeners);
    let status =
        fs::read_to_string(format!("/proc/{}/status", child.id())).map_err(|e| e.to_string())?;
    let blk = status
        .lines()
        .find(|l| l.starts_with("SigBlk"))
        .unwrap_or("")
        .to_owned();
    fdpass::send_go(parent_end.as_raw_fd()).map_err(|e| format!("send go: {e}"))?;
    drop(parent_end);
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&dir);
    if blk != "SigBlk:\t0000000000000000" {
        return Err(format!(
            "__init kept a blocked mask while waiting for go: {blk:?}"
        ));
    }
    if out.status.code() != Some(0) {
        return Err(format!(
            "__init payload rc {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Review 1: `--audit` under a policy `rw` path is refused (the payload can write
/// there), before anything is spawned.
fn audit_under_policy_rw_125() -> Result<(), String> {
    let dir = scratch("rwaudit");
    let rw = dir.join("rw");
    fs::create_dir_all(&rw).expect("mkdir");
    let mut pol = Pol::new("exit");
    pol.rw = vec![rw.to_str().expect("utf8").to_owned()];
    let policy = pol.write(&dir);
    let audit = rw.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "--audit must not be inside a writable policy path");
    let created = audit.exists();
    let _ = fs::remove_dir_all(&dir);
    r?;
    if created {
        return Err("the audit file was created under the rw path".into());
    }
    Ok(())
}

/// Review 5: a FIFO policy is refused promptly (no blocking open with signals masked).
fn policy_fifo_125() -> Result<(), String> {
    let dir = scratch("fifo");
    let fifo = dir.join("policy.json");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("cstr");
    // SAFETY: mkfifo on a path in our scratch directory.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let args = sbx_args(&fifo, &dir.join("s"), &[], &payload(&["0"]));
    let proc_ = Proc::spawn(&args, |_| {})?;
    let done = proc_.finish(Duration::from_secs(10))?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(&done, "is a FIFO; expected a regular file")
}

/// Runs sbx with its stderr pipe's read end already closed (what `2>&1 | true` does).
fn run_with_closed_stderr(args: &[OsString]) -> Result<ExitStatus, String> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two fds into the array; the read end is closed at once.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("pipe2 failed".into());
    }
    // SAFETY: fresh fds from pipe2; the read end is closed immediately (EPIPE on write).
    unsafe { libc::close(fds[0]) };
    // SAFETY: the write end is ours; OwnedFd closes it when the Stdio is consumed.
    let stderr = Stdio::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) });
    Command::new(SBX)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .status()
        .map_err(|e| format!("spawn sbx: {e}"))
}

/// Review 4: a closed stderr must not panic the run (101) — the 125 is kept.
fn closed_stderr_rc_125() -> Result<(), String> {
    let dir = scratch("cs125");
    let policy = dir.join("missing.json");
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let status = run_with_closed_stderr(&args)?;
    let _ = fs::remove_dir_all(&dir);
    if status.code() == Some(125) {
        Ok(())
    } else {
        Err(format!("rc {:?}, want 125", status.code()))
    }
}

/// Review 4: a closed stderr must not panic the run — the timeout's 124 is kept.
fn closed_stderr_rc_124() -> Result<(), String> {
    let dir = scratch("cs124");
    let policy = Pol::new("ready-sleep").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--timeout", "1s"],
        &payload(&["30"]),
    );
    let status = run_with_closed_stderr(&args)?;
    let _ = fs::remove_dir_all(&dir);
    if status.code() == Some(124) {
        Ok(())
    } else {
        Err(format!("rc {:?}, want 124", status.code()))
    }
}

/// Review 2: two runs share one `--audit` file. Run A is started first (its pre-write
/// size snapshot is taken at open), run B appends its rows, then A's exit-row write
/// fails under RLIMIT_FSIZE. A's truncate-back must only remove A's own bytes: B's
/// rows must survive, and the file must not be shorter than it was before A's write.
fn shared_audit_two_writers() -> Result<(), String> {
    let dir = scratch("shared");
    let audit = dir.join("shared.jsonl");
    let prefill = vec![b'\n'; 900];
    fs::write(&audit, &prefill).expect("prefill");
    let audit_str = audit.to_str().expect("utf8").to_owned();
    // Run A: waits, and its exit row cannot be written (the file is past the limit).
    fs::create_dir_all(dir.join("a")).expect("mkdir");
    let a_policy = Pol::new("ready-sleep").write(&dir.join("a"));
    let a_args = sbx_args(
        &a_policy,
        &dir.join("a").join("s"),
        &["--audit", &audit_str],
        &payload(&["30"]),
    );
    let a = Proc::spawn(&a_args, |cmd| {
        // SAFETY: setrlimit and signal(3) only, between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                let lim = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 1024,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &lim);
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                Ok(())
            });
        }
    })?;
    a.wait_stdout("READY")?;
    // Run B: unlimited, completes, appends its exit row to the same file.
    fs::create_dir_all(dir.join("b")).expect("mkdir");
    let b_policy = Pol::new("exit").write(&dir.join("b"));
    let b_args = sbx_args(
        &b_policy,
        &dir.join("b").join("s"),
        &["--audit", &audit_str],
        &payload(&["0"]),
    );
    let b = run_sbx(&b_args)?;
    expect_rc(&b, 0)?;
    // Now A ends: its exit row write fails, and must not erase B's row.
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(a.child.id() as libc::pid_t, libc::SIGTERM) };
    let a_done = a.finish(Duration::from_secs(30))?;
    let content = fs::read_to_string(&audit).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&a_done, 125)?;
    let b_rows = content
        .lines()
        .filter(|l| l.contains("\"event\":\"exit\"") && l.contains("\"code\":0"))
        .count();
    if b_rows != 1 {
        return Err(format!("run B's exit row was erased or torn: {content:?}"));
    }
    Ok(())
}

/// Round 2 (1b): `--audit` under a policy `ro` path is refused too: the payload can see it.
fn audit_under_policy_ro_125() -> Result<(), String> {
    let dir = scratch("roaudit");
    let ro = dir.join("ro");
    fs::create_dir_all(&ro).expect("mkdir");
    let mut pol = Pol::new("exit");
    pol.ro_extra = vec![ro.to_str().expect("utf8").to_owned()];
    let policy = pol.write(&dir);
    let audit = ro.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["0"]),
    );
    let r = expect_refusal(&args, "--audit must not be inside a policy filesystem path");
    let created = audit.exists();
    let _ = fs::remove_dir_all(&dir);
    r?;
    if created {
        return Err("the audit file was created under the ro path".into());
    }
    Ok(())
}

/// Round 2 (1a): another process holds `flock` on the shared audit file. The run must not
/// stall: after the bounded wait it fails closed (125), and it still answers SIGTERM.
fn audit_lock_held_fails_closed() -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let dir = scratch("lockheld");
    let audit = dir.join("shared.jsonl");
    let holder = fs::File::create(&audit).expect("create");
    // SAFETY: flock on a file this test owns; held until `holder` drops.
    if unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("test could not take the flock".into());
    }
    let policy = Pol::new("ready-sleep").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--audit", audit.to_str().expect("utf8")],
        &payload(&["30"]),
    );
    let proc_ = Proc::spawn(&args, |_| {})?;
    proc_.wait_stdout("READY")?;
    let started = Instant::now();
    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(proc_.child.id() as libc::pid_t, libc::SIGTERM) };
    let done = proc_.finish(Duration::from_secs(10))?;
    let took = started.elapsed();
    drop(holder);
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(&done, "audit log write failed:")?;
    expect_stderr(&done, "locked by another process")?;
    if took > Duration::from_secs(5) {
        return Err(format!("the held lock stalled the teardown for {took:?}"));
    }
    Ok(())
}

/// Result of a run whose stdout and stderr are ONE pipe (`2>&1`).
struct Merged {
    rc: Option<i32>,
    text: String,
}

fn run_merged(args: &[OsString]) -> Result<Merged, String> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two fds into the array; each is owned exactly once below.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err("pipe2 failed".into());
    }
    // SAFETY: fresh fds from pipe2.
    let (read, write) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    };
    let write2 = write.try_clone().map_err(|e| e.to_string())?;
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = fs::File::from(read).read_to_end(&mut buf);
        buf
    });
    let status = Command::new(SBX)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(write))
        .stderr(Stdio::from(write2))
        .status()
        .map_err(|e| format!("spawn sbx: {e}"))?;
    let buf = reader.join().map_err(|_| "reader panicked".to_owned())?;
    Ok(Merged {
        rc: status.code(),
        text: String::from_utf8_lossy(&buf).into_owned(),
    })
}

/// Round 2 (2): `2>&1` — the partial payload stdout line must not be glued to sbx's line.
fn partial_stderr_framing_merged() -> Result<(), String> {
    let dir = scratch("mergedframe");
    let policy = Pol::new("exit").write(&dir);
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &["--timeout", "1s"],
        &[
            OsString::from("/usr/bin/bash"),
            OsString::from("-c"),
            OsString::from("printf progress; sleep 30"),
        ],
    );
    let m = run_merged(&args)?;
    let _ = fs::remove_dir_all(&dir);
    if m.rc != Some(124) {
        return Err(format!("rc {:?}, want 124", m.rc));
    }
    if m.text != "progress\nsbx run: timed out after 1s\n" {
        return Err(format!(
            "merged diagnostic glued to the payload: {:?}",
            m.text
        ));
    }
    Ok(())
}

/// Counts payload `x` bytes in text that may end with sbx's own lines.
fn x_before_diagnostics(text: &str) -> usize {
    // sbx's `sbx run: …` line contains an `x` ("sbx"): it is never counted.
    let body = match text.find("sbx run: ") {
        Some(at) if at == 0 || text.as_bytes()[at - 1] == b'\n' => &text[..at],
        _ => text,
    };
    body.bytes().filter(|b| *b == b'x').count()
}

/// Round 2 (2): the output cap with `2>&1`: payload bytes counted on the merged stream.
fn output_cap_merged() -> Result<(), String> {
    let dir = scratch("capmerged");
    let mut pol = Pol::new("flood");
    pol.output_bytes = 1000;
    let policy = pol.write(&dir);
    let args = sbx_args(&policy, &dir.join("s"), &[], &payload(&["10000"]));
    let m = run_merged(&args)?;
    let _ = fs::remove_dir_all(&dir);
    if m.rc != Some(0) {
        return Err(format!("rc {:?}, want 0", m.rc));
    }
    let x = x_before_diagnostics(&m.text);
    if x != 1000 {
        return Err(format!("forwarded {x} payload bytes, want 1000"));
    }
    let notice = "sbx run: output truncated at 1000 bytes (limits.output_bytes)\n";
    if !m.text.ends_with(notice) {
        return Err(format!(
            "truncation notice missing: {:?}",
            &m.text[m.text.len().saturating_sub(120)..]
        ));
    }
    let head = &m.text[..m.text.len() - notice.len()];
    if !head.is_empty() && !head.ends_with('\n') {
        return Err("notice glued to a payload line on the merged stream".into());
    }
    Ok(())
}

// ---- issue #11: the explicit fallback and the refusal ------------------------

const FALLBACK_NOTICE: &str = "sbx run: notice: running in network mode explicit because the nftables NAT redirect is unavailable (nft-load: batch failed";

/// AC (issue #11, Q1): an explicit policy with a refused nft batch still runs
/// (`--test-break-rules` is the hidden fail-only driver). Direct connects fail
/// with ENETUNREACH in well under a second, the explicit proxy still answers,
/// the notice is printed, and the exit row records `net_mode: explicit`.
fn explicit_fallback_break_rules() -> Result<(), String> {
    let dir = scratch("fbexp");
    let mut pol = Pol::new("noroute-checks");
    pol.mode = "explicit";
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &[
            "--audit",
            audit.to_str().expect("utf8"),
            "--test-break-rules",
        ],
        &payload(&[]),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit);
    let _ = fs::remove_dir_all(&dir);
    let rows = rows?;
    expect_rc(&done, 0)?;
    if !done.stdout.contains("DIRECT tcp errno=Some(101)") {
        return Err(format!(
            "direct connect was not ENETUNREACH: {:?}",
            done.stdout
        ));
    }
    let ms = done
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("DIRECT tcp errno=Some(101) ms="))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or("no timing on the direct connect line")?;
    if ms >= 1000 {
        return Err(format!("ENETUNREACH took {ms} ms (expected < 1000)"));
    }
    if !done.stdout.contains("DIRECT tcp6 errno=Some(99)") {
        return Err(format!(
            "direct IPv6 connect was not EADDRNOTAVAIL: {:?}",
            done.stdout
        ));
    }
    if !done.stdout.contains("EXPLICIT HTTP/1.1 403") {
        return Err(format!("explicit proxy did not answer: {:?}", done.stdout));
    }
    expect_stderr(&done, FALLBACK_NOTICE)?;
    let exit = rows.last().ok_or("no rows")?;
    if exit["event"] != "exit" || exit["net_mode"] != "explicit" {
        return Err(format!("exit row: {exit}"));
    }
    Ok(())
}

/// AC (issue #11): `none` policies run on the explicit variant too.
fn none_fallback_break_rules() -> Result<(), String> {
    let dir = scratch("fbnone");
    let mut pol = Pol::new("exit");
    pol.mode = "none";
    let policy = pol.write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &[
            "--audit",
            audit.to_str().expect("utf8"),
            "--test-break-rules",
        ],
        &payload(&["0"]),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit);
    let _ = fs::remove_dir_all(&dir);
    let rows = rows?;
    expect_rc(&done, 0)?;
    expect_stderr(
        &done,
        "sbx run: notice: running in network mode explicit (policy mode none) because the nftables NAT redirect is unavailable (nft-load: batch failed",
    )?;
    let exit = rows.last().ok_or("no rows")?;
    if exit["net_mode"] != "explicit" {
        return Err(format!("exit row: {exit}"));
    }
    Ok(())
}

/// AC (issue #11, Q1): a transparent policy is refused (rc 125) when the host
/// cannot provide it. The refusal names the stage, the reason and the fix,
/// points at `sbx check`, and the exit row records a failed run with a null
/// `net_mode`. `__init`'s own staged line comes first.
fn transparent_refused_break_rules_125() -> Result<(), String> {
    let dir = scratch("refuse");
    let policy = Pol::new("exit").write(&dir);
    let audit = dir.join("a.jsonl");
    let args = sbx_args(
        &policy,
        &dir.join("s"),
        &[
            "--audit",
            audit.to_str().expect("utf8"),
            "--test-break-rules",
        ],
        &payload(&["0"]),
    );
    let done = run_sbx(&args)?;
    let rows = read_audit(&audit);
    let _ = fs::remove_dir_all(&dir);
    let rows = rows?;
    expect_rc(&done, 125)?;
    let staged = done
        .stderr
        .find("sbx __init: nft-load:")
        .ok_or("no staged line")?;
    let refusal = done
        .stderr
        .find("sbx run: policy requires network mode transparent but this host provides only explicit: nftables NAT redirect is unavailable")
        .ok_or_else(|| format!("no refusal line: {:?}", done.stderr))?;
    if refusal < staged {
        return Err("the refusal must follow __init's staged line".into());
    }
    if !done
        .stderr
        .contains("run `sbx check` for a full host report")
    {
        return Err(format!("no sbx check hint: {:?}", done.stderr));
    }
    let exit = rows.last().ok_or("no rows")?;
    if exit["outcome"] != "failed" || !exit["net_mode"].is_null() {
        return Err(format!("exit row: {exit}"));
    }
    Ok(())
}

/// Runs `sbx run` inside a bwrap tier and returns the `Done` record.
fn run_inside_bwrap(bwrap_args: &[&str], sbx_run: &[OsString]) -> Result<Done, String> {
    let bwrap = sbx::bwrap::version::find_bwrap().ok_or("bwrap disappeared")?;
    let mut cmd = Command::new(&bwrap);
    cmd.args(bwrap_args);
    cmd.arg("--");
    cmd.arg(SBX);
    cmd.args(sbx_run);
    cmd.env("SBX_BWRAP", &bwrap);
    let out = cmd.output().map_err(|e| format!("spawn bwrap tier: {e}"))?;
    Ok(Done {
        rc: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// AC (issue #11, Q4/T6): a host where user namespaces cannot be nested (the
/// `bwrap --disable-userns` tier, E3) refuses `run` with rc 125 and the
/// ENOSPC explanation.
fn refused_no_userns_125() -> Result<(), String> {
    let dir = scratch("nonest");
    let policy = Pol::new("exit").write(&dir);
    let sbx_run = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let done = run_inside_bwrap(
        &["--unshare-user", "--disable-userns", "--dev-bind", "/", "/"],
        &sbx_run,
    )?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(
        &done,
        "this host cannot run sandboxes: no user namespace can be created here",
    )
}

/// AC (issue #11, E4): a read-only `/proc/sys` (Docker-style) refuses `run`
/// with the IPv6 EROFS explanation, rc 125.
fn refused_ro_proc_sys_125() -> Result<(), String> {
    let dir = scratch("roproc");
    let policy = Pol::new("exit").write(&dir);
    let sbx_run = sbx_args(&policy, &dir.join("s"), &[], &payload(&["0"]));
    let done = run_inside_bwrap(
        &[
            "--unshare-user",
            "--unshare-pid",
            "--dev-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--ro-bind",
            "/proc/sys",
            "/proc/sys",
        ],
        &sbx_run,
    )?;
    let _ = fs::remove_dir_all(&dir);
    expect_rc(&done, 125)?;
    expect_stderr(
        &done,
        "cannot disable IPv6 in the sandbox network namespace: /proc/sys is read-only (EROFS",
    )
}

// ---- #12: `sbx gc` against live and hostile sessions ----------------------------

/// Sets a directory's mtime to `ago` in the past (the session activity signal).
fn backdate_dir(p: &Path, ago: Duration) -> Result<(), String> {
    let when = std::time::SystemTime::now() - ago;
    fs::File::open(p)
        .and_then(|f| f.set_times(fs::FileTimes::new().set_modified(when)))
        .map_err(|e| format!("backdate {p:?}: {e}"))
}

/// `sbx gc --older-than 1s <root>`, optionally with a lowered RLIMIT_NOFILE.
fn gc_proc(root: &Path, rlimit: Option<u64>) -> Result<Proc, String> {
    let args: Vec<OsString> = vec![
        "gc".into(),
        "--older-than".into(),
        "1s".into(),
        root.as_os_str().to_owned(),
    ];
    Proc::spawn(&args, move |cmd| {
        if let Some(n) = rlimit {
            // SAFETY: the closure only calls setrlimit (async-signal-safe).
            unsafe {
                cmd.pre_exec(move || {
                    let lim = libc::rlimit {
                        rlim_cur: n,
                        rlim_max: n,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    })
}

/// A live `run` holds its session's lock: gc must skip it silently, keep it
/// intact, and collect it once the run has ended and the session is old.
fn gc_skips_live_run() -> Result<(), String> {
    let dir = scratch("gclive");
    let root = dir.join("root");
    fs::create_dir_all(&root).expect("mkdir root");
    let session = root.join("s");
    let policy = Pol::new("ready-sleep").write(&dir);
    let run = Proc::spawn(&sbx_args(&policy, &session, &[], &payload(&["60"])), |_| {})?;
    run.wait_stdout("READY")?;
    backdate_dir(&session, Duration::from_secs(86_400))?;

    let gc1 = gc_proc(&root, None)?.finish(Duration::from_secs(30))?;
    expect_rc(&gc1, 0)?;
    if !(gc1.stdout.is_empty() && gc1.stderr.is_empty()) {
        return Err(format!(
            "gc must be silent on a live session: {:?} {:?}",
            gc1.stdout, gc1.stderr
        ));
    }
    if !session.join("sbx.lock").exists() {
        return Err("gc touched a live session".into());
    }

    // SAFETY: signalling our own child process by pid.
    unsafe { libc::kill(run.child.id() as libc::pid_t, libc::SIGTERM) };
    let done = run.finish(Duration::from_secs(30))?;
    expect_rc(&done, 143)?;
    // The run touched the directory on exit: make it old again.
    backdate_dir(&session, Duration::from_secs(86_400))?;

    let gc2 = gc_proc(&root, None)?.finish(Duration::from_secs(30))?;
    expect_rc(&gc2, 0)?;
    let want = format!("removed {:?}\n", session);
    if gc2.stdout != want {
        return Err(format!("gc stdout {:?} (want {want:?})", gc2.stdout));
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// Builds a hostile tree under /work, all from inside the sandbox: nested
/// modes 000/100/500, a 1500-deep chain, a FIFO, a non-UTF-8 name, symlinks to
/// a host canary and to `/`, a hard link, and decoy `sbx.lock` and
/// `.sbx-gc-hoist.1` names. Returns 0 after printing TREE-DONE.
fn hostile_tree(canary: &str) -> u8 {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let w = Path::new("/work");
    let step = || -> std::io::Result<()> {
        let c = w.join("h/a/b/c");
        fs::create_dir_all(c.join("leaf"))?;
        fs::write(c.join("leaf/file"), b"x")?;
        // Deepest first: each chmod still has search permission on its path.
        fs::set_permissions(&c, fs::Permissions::from_mode(0o500))?;
        fs::set_permissions(w.join("h/a/b"), fs::Permissions::from_mode(0o100))?;
        fs::set_permissions(w.join("h/a"), fs::Permissions::from_mode(0o000))?;
        let mut deep = w.join("deep");
        fs::create_dir(&deep)?;
        for _ in 0..1500 {
            deep.push("d");
            fs::create_dir(&deep)?;
        }
        fs::write(deep.join("file"), b"x")?;
        let fifo = std::ffi::CString::new(w.join("fifo").as_os_str().as_bytes())
            .expect("no NUL in the fifo path");
        // SAFETY: mkfifo with a valid NUL-terminated path.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        fs::write(w.join(OsStr::from_bytes(b"n\xff")), b"x")?;
        symlink(canary, w.join("escape"))?;
        symlink("/", w.join("rootlink"))?;
        fs::write(w.join("orig"), b"x")?;
        fs::hard_link(w.join("orig"), w.join("hl"))?;
        fs::create_dir(w.join("decoy"))?;
        fs::write(w.join("decoy/sbx.lock"), b"")?;
        fs::write(w.join("decoy/.sbx-gc-hoist.1"), b"")?;
        Ok(())
    };
    match step() {
        Ok(()) => {
            println!("TREE-DONE");
            let _ = std::io::stdout().flush();
            0
        }
        Err(err) => {
            eprintln!("hostile-tree: {err}");
            1
        }
    }
}

/// A hostile payload tree (escaping symlinks, mode 000 dirs, a 1500-deep
/// chain) is removed by gc with RLIMIT_NOFILE=32, and nothing outside the
/// session is touched.
fn gc_hostile_payload_tree() -> Result<(), String> {
    let dir = scratch("hostile");
    let canary_dir = dir.join("canary");
    fs::create_dir_all(&canary_dir).expect("canary dir");
    fs::write(canary_dir.join("keep"), b"keep").expect("canary file");
    let root = dir.join("root");
    fs::create_dir_all(&root).expect("mkdir root");
    let session = root.join("s");
    let policy = Pol::new("hostile-tree").write(&dir);
    let canary = canary_dir.to_string_lossy().into_owned();
    let run = run_sbx(&sbx_args(&policy, &session, &[], &payload(&[&canary])))?;
    expect_rc(&run, 0)?;
    if !run.stdout.contains("TREE-DONE") {
        return Err(format!("payload did not finish the tree: {:?}", run.stdout));
    }
    backdate_dir(&session, Duration::from_secs(86_400))?;

    let gc = gc_proc(&root, Some(32))?.finish(Duration::from_secs(60))?;
    expect_rc(&gc, 0)?;
    let want = format!("removed {:?}\n", session);
    if gc.stdout != want {
        return Err(format!(
            "gc stdout {:?} (want {want:?}); stderr {:?}",
            gc.stdout, gc.stderr
        ));
    }
    if fs::read(canary_dir.join("keep")).map_err(|e| e.to_string())? != b"keep" {
        return Err("the canary outside the session was modified".into());
    }
    let left: Vec<String> = fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if left.iter().any(|n| n == "s" || n.starts_with(".sbx-gc.")) {
        return Err(format!("ROOT still holds {left:?}"));
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// `run` and `gc` race on one old session, 20 times, in both orders: even
/// iterations start gc first (it removes the old session before `run` gets
/// there), odd ones start `run` first (gc sees a young, locked session, or
/// runs after the run ended). The start gap sweeps 0 to ~5 ms. Invariants:
/// a refused run is 125 with a lock or binding message; a run that succeeded
/// left its marker; gc is 0, or 1 only with the Q13 line; and a final gc
/// leaves no tombstone behind. The outcome counts are printed and must show
/// that gc removed a session while a run was starting, and that runs
/// succeeded.
fn run_vs_gc_race() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("race");
    let root = dir.join("root");
    fs::create_dir_all(&root).expect("mkdir root");
    let session = root.join("s");
    let policy = Pol::new("mark").write(&dir);
    let (mut run_ok, mut run_refused, mut gc_removed, mut gc_skipped, mut gc_recreated) =
        (0u32, 0u32, 0u32, 0u32, 0u32);
    for iter in 0..20u32 {
        let _ = fs::remove_dir_all(&session);
        fs::create_dir(&session).map_err(|e| e.to_string())?;
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        fs::write(session.join("sbx.lock"), b"").map_err(|e| e.to_string())?;
        backdate_dir(&session, Duration::from_secs(86_400))?;

        let gap = Duration::from_micros(250 * u64::from(iter));
        let run_args = sbx_args(&policy, &session, &[], &payload(&[]));
        let (run, gc) = if iter % 2 == 0 {
            let gc = gc_proc(&root, None)?;
            std::thread::sleep(gap);
            (Proc::spawn(&run_args, |_| {})?, gc)
        } else {
            let run = Proc::spawn(&run_args, |_| {})?;
            std::thread::sleep(gap);
            (run, gc_proc(&root, None)?)
        };
        let run = run.finish(Duration::from_secs(60))?;
        let gc = gc.finish(Duration::from_secs(60))?;

        match run.rc {
            0 => {
                run_ok += 1;
                if !session.join("work/marker").exists() {
                    return Err(format!("iter {iter}: run succeeded but left no marker"));
                }
            }
            125 => {
                let known = run.stderr.contains("session directory is in use")
                    || run
                        .stderr
                        .contains("was removed or replaced while it was being locked");
                if !known {
                    return Err(format!(
                        "iter {iter}: unexpected 125 stderr {:?}",
                        run.stderr
                    ));
                }
                run_refused += 1;
            }
            other => return Err(format!("iter {iter}: run rc {other}: {:?}", run.stderr)),
        }
        match gc.rc {
            0 if gc.stdout.contains("removed ") => gc_removed += 1,
            0 => gc_skipped += 1,
            1 if gc
                .stderr
                .contains("a concurrent sbx run recreated entries during removal") =>
            {
                gc_recreated += 1;
            }
            other => return Err(format!("iter {iter}: gc rc {other}: {:?}", gc.stderr)),
        }
    }
    println!(
        "  run-vs-gc-race outcomes: run ok {run_ok}, run refused {run_refused}, gc removed {gc_removed}, gc skipped {gc_skipped}, gc recreated {gc_recreated}"
    );
    if gc_removed == 0 {
        return Err("gc never removed a session while a run was starting".into());
    }
    if run_ok == 0 {
        return Err("no run ever succeeded".into());
    }
    let done = gc_proc(&root, None)?.finish(Duration::from_secs(60))?;
    expect_rc(&done, 0)?;
    let left: Vec<String> = fs::read_dir(&root)
        .map_err(|e| e.to_string())?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    if left.iter().any(|n| n.starts_with(".sbx-gc.")) {
        return Err(format!("tombstones survived the final gc: {left:?}"));
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---- Pre-launch path verification and pins (#39 / #40) ---------------------

/// A host tree for the #39/#40 scenarios: `proj` is the writable tree, and
/// `outside` is a host directory the payload must never be able to reach
/// (it holds one file, `key`). Removed on drop.
struct Tree {
    dir: PathBuf,
    proj: PathBuf,
    outside: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Self {
        let dir = scratch(tag);
        let proj = dir.join("proj");
        let outside = dir.join("outside");
        fs::create_dir_all(&proj).expect("proj");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("key"), b"HOSTKEY\n").expect("key");
        Self { dir, proj, outside }
    }

    fn session(&self) -> PathBuf {
        self.dir.join("s")
    }

    /// The CVE form of a host path: bwrap 0.9 resolves it from `/oldroot`.
    fn oldroot(path: &Path) -> PathBuf {
        PathBuf::from(format!("/oldroot{}", path.display()))
    }

    /// Fails unless the host outside directory holds exactly its key file.
    fn outside_untouched(&self) -> Result<(), String> {
        let names = entries(&self.outside)?;
        if names == ["key"] {
            Ok(())
        } else {
            Err(format!("host outside directory changed: {names:?}"))
        }
    }

    fn policy(&self, rw: &[&Path], ro: &[&Path], deny: &[&Path]) -> Pol {
        let mut pol = Pol::new("exit");
        pol.rw = rw.iter().map(|p| p.display().to_string()).collect();
        pol.ro_extra = ro.iter().map(|p| p.display().to_string()).collect();
        pol.deny = deny.iter().map(|p| p.display().to_string()).collect();
        pol
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Sorted entry names of a host directory.
fn entries(dir: &Path) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map_err(|e| format!("read {dir:?}: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

/// A `/bin/sh -c` payload.
fn sh(script: &str) -> Vec<OsString> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
}

/// Writes the policy into `t.dir` and runs `script` in `session`.
fn run_script(t: &Tree, pol: &Pol, session: &Path, script: &str) -> Result<Done, String> {
    let policy = pol.write(&t.dir);
    run_sbx(&sbx_args(&policy, session, &[], &sh(script)))
}

/// A planted symlink must refuse before spawn (rc 125, pinned text), and the
/// host target must stay untouched.
fn expect_planted_refusal(t: &Tree, args: &[OsString], needle: &str) -> Result<(), String> {
    expect_refusal(args, needle)?;
    t.outside_untouched()
}

fn prelaunch_deny_chain_symlink_125() -> Result<(), String> {
    // #39 / CVE-2026-87766 shape: a payload turned the deny's parent into a
    // symlink to a host path, and the CVE form is an /oldroot path.
    let t = Tree::new("pl-chain");
    symlink(Tree::oldroot(&t.outside), t.proj.join("a")).map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/secrets")]);
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")?;
    if t.proj.join("a").symlink_metadata().is_err() {
        return Err("the planted symlink disappeared".into());
    }
    Ok(())
}

fn prelaunch_deny_leaf_symlink_125() -> Result<(), String> {
    let t = Tree::new("pl-leaf");
    fs::create_dir_all(t.proj.join("a")).map_err(|e| e.to_string())?;
    symlink(Tree::oldroot(&t.outside), t.proj.join("a/secrets")).map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/secrets")]);
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

fn prelaunch_deny_missing_125() -> Result<(), String> {
    // Q1: a missing deny under a writable bind is refused (bwrap would
    // otherwise create it, and its parents, on the host).
    let t = Tree::new("pl-miss");
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/secrets")]);
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "does not exist")?;
    if t.proj.join("a").exists() {
        return Err("the host parent of the missing deny was created".into());
    }
    Ok(())
}

fn prelaunch_deny_is_file_125() -> Result<(), String> {
    let t = Tree::new("pl-file");
    fs::create_dir_all(t.proj.join("a")).map_err(|e| e.to_string())?;
    fs::write(t.proj.join("a/secrets"), b"x").map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/secrets")]);
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "is not a directory")
}

fn prelaunch_nested_ro_chain_symlink_125() -> Result<(), String> {
    let t = Tree::new("pl-nro");
    fs::create_dir_all(t.proj.join("a2/ro")).map_err(|e| e.to_string())?;
    symlink(Tree::oldroot(&t.outside), t.proj.join("a")).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&t.proj], &[], &[]);
    pol.ro_extra = vec![t.proj.join("a/ro").display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

fn prelaunch_nested_ro_leaf_symlink_125() -> Result<(), String> {
    // The nested-bind SOURCE swap (F): the ro leaf is a symlink to a host dir.
    let t = Tree::new("pl-nrl");
    fs::create_dir_all(t.proj.join("a")).map_err(|e| e.to_string())?;
    symlink(&t.outside, t.proj.join("a/ro")).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&t.proj], &[], &[]);
    pol.ro_extra = vec![t.proj.join("a/ro").display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

fn prelaunch_nested_ro_relative_leaf_125() -> Result<(), String> {
    // F, as a payload writes it: a RELATIVE symlink that climbs out of the
    // rw tree to a host directory holding a secret. bwrap 0.9 resolves bind
    // sources through host symlinks, so the walk must refuse it.
    let t = Tree::new("pl-rel");
    let secret = t.dir.join("hostsecret");
    fs::create_dir_all(&secret).map_err(|e| e.to_string())?;
    fs::write(secret.join("key"), b"HOSTKEY\n").map_err(|e| e.to_string())?;
    fs::create_dir_all(t.proj.join("a")).map_err(|e| e.to_string())?;
    let depth = t.proj.join("a").components().count() - 1;
    let up: String = "../".repeat(depth);
    let target = format!(
        "{up}{}",
        secret.strip_prefix("/").unwrap_or(&secret).display()
    );
    symlink(target, t.proj.join("a/ro")).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&t.proj], &[], &[]);
    pol.ro_extra = vec![t.proj.join("a/ro").display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "it is a symbolic link")?;
    if fs::read_dir(&secret).map_err(|e| e.to_string())?.count() != 1 {
        return Err("the host secret directory changed".into());
    }
    Ok(())
}

fn prelaunch_alias_of_deny_125() -> Result<(), String> {
    // Q5: a read-only bind through a host symlink exposes the deny's inode
    // at another path, so the mask would not cover it. Refused at run time.
    let t = Tree::new("pl-alias");
    fs::create_dir_all(t.proj.join("secrets")).map_err(|e| e.to_string())?;
    let alias = t.dir.join("alias");
    symlink(&t.proj, &alias).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[], &[], &[&t.proj.join("secrets")]);
    pol.ro_extra = vec![alias.display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "reachable on the host")
}

fn prelaunch_reused_session_leaf_symlink_125() -> Result<(), String> {
    // E: a reused session's home leaf is payload-writable across runs. Run 1
    // creates `/root/.cache` in the leaf; the harness then plants a symlink
    // there, as a payload would.
    let t = Tree::new("pl-reuse");
    let pol = t.policy(&[], &[], &[Path::new("/root/.cache/x")]);
    let session = t.session();
    let first = run_script(&t, &pol, &session, "true")?;
    expect_rc(&first, 0)?;
    let cache = session.join("home/.cache");
    if cache.symlink_metadata().is_err() {
        return Err(format!("run 1 did not create {cache:?}"));
    }
    fs::remove_dir_all(&cache).map_err(|e| e.to_string())?;
    symlink(Tree::oldroot(&t.outside), &cache).map_err(|e| e.to_string())?;
    let args = sbx_args(&pol.write(&t.dir), &session, &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

fn pin_rename_of_deny_chain_ebusy() -> Result<(), String> {
    // A: the payload renames the deny's parent. The pin makes the rename
    // EBUSY, so the mask still hides the file on the next run.
    let t = Tree::new("pin-a");
    fs::create_dir_all(t.proj.join("a/secrets")).map_err(|e| e.to_string())?;
    fs::write(t.proj.join("a/secrets/key"), b"TOKEN\n").map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/secrets")]);
    let session = t.session();
    let p = t.proj.display();
    let script = format!(
        "if mv {p}/a {p}/a2 2>/dev/null; then echo RENAMED; else echo BLOCKED; fi; \
         if test -e {p}/a2/secrets/key; then echo LEAK; fi"
    );
    let first = run_script(&t, &pol, &session, &script)?;
    expect_rc(&first, 0)?;
    if !first.stdout.contains("BLOCKED") || first.stdout.contains("RENAMED") {
        return Err(format!("the rename was not blocked: {:?}", first.stdout));
    }
    if t.proj.join("a2").exists() || !t.proj.join("a/secrets/key").exists() {
        return Err("host tree changed under the pinned rename".into());
    }
    let second = run_script(
        &t,
        &pol,
        &session,
        &format!("cat {p}/a/secrets/key; echo done"),
    )?;
    expect_rc(&second, 0)?;
    if second.stdout.contains("TOKEN") {
        return Err(format!(
            "the deny mask leaked on run 2: {:?}",
            second.stdout
        ));
    }
    Ok(())
}

fn pin_rename_of_nested_ro_ebusy() -> Result<(), String> {
    // C: a rename of the parent of a nested ro bind would have let run 2
    // write through the renamed-away path. Blocked by the pin; the ro bind
    // stays read-only.
    let t = Tree::new("pin-c");
    fs::create_dir_all(t.proj.join("a/ro")).map_err(|e| e.to_string())?;
    fs::write(t.proj.join("a/ro/f"), b"orig\n").map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&t.proj], &[], &[]);
    pol.ro_extra = vec![t.proj.join("a/ro").display().to_string()];
    let session = t.session();
    let p = t.proj.display();
    let script = format!(
        "if mv {p}/a {p}/a2 2>/dev/null; then echo RENAMED; else echo BLOCKED; fi; \
         if echo X > {p}/a/ro/f 2>/dev/null; then echo WROTE; else echo RO_OK; fi"
    );
    let first = run_script(&t, &pol, &session, &script)?;
    expect_rc(&first, 0)?;
    if !first.stdout.contains("BLOCKED") || !first.stdout.contains("RO_OK") {
        return Err(format!("nested ro was not protected: {:?}", first.stdout));
    }
    if fs::read(t.proj.join("a/ro/f")).map_err(|e| e.to_string())? != b"orig\n" {
        return Err("the host ro file changed".into());
    }
    Ok(())
}

fn pin_legit_deny_depth2_fresh_and_reused() -> Result<(), String> {
    // A legitimate depth-2 deny with an ro sibling and a writable tree still
    // runs, on a fresh session and again on the reused one.
    let t = Tree::new("pin-ok");
    fs::create_dir_all(t.proj.join("a/b/secrets")).map_err(|e| e.to_string())?;
    fs::create_dir_all(t.proj.join("a/ro")).map_err(|e| e.to_string())?;
    fs::create_dir_all(t.proj.join("x")).map_err(|e| e.to_string())?;
    fs::write(t.proj.join("a/b/secrets/key"), b"TOKEN\n").map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/b/secrets")]);
    pol.ro_extra = vec![t.proj.join("a/ro").display().to_string()];
    let p = t.proj.display();
    let script =
        format!("test ! -e {p}/a/b/secrets/key && touch {p}/x/new && test -f {p}/x/new && echo OK");
    for _ in 0..2 {
        let done = run_script(&t, &pol, &t.session(), &script)?;
        expect_rc(&done, 0)?;
        if !done.stdout.contains("OK") {
            return Err(format!("legit payload failed: {:?}", done.stdout));
        }
    }
    if !t.proj.join("x/new").exists() {
        return Err("the payload's write did not reach the host".into());
    }
    Ok(())
}

fn pin_cross_pin_rename_is_exdev() -> Result<(), String> {
    // Documents the semantics (Risks in the design): a rename across a pinned
    // directory boundary fails with EXDEV. `mv` falls back to copy and
    // succeeds; a raw rename would not.
    let t = Tree::new("pin-exdev");
    fs::create_dir_all(t.proj.join("a/b/s")).map_err(|e| e.to_string())?;
    fs::create_dir_all(t.proj.join("c")).map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a/b/s")]);
    let p = t.proj.display();
    let script =
        format!("echo x > {p}/a/f && mv {p}/a/f {p}/a/g && mv {p}/a/g {p}/c/g && echo MOVED");
    let done = run_script(&t, &pol, &t.session(), &script)?;
    expect_rc(&done, 0)?;
    if fs::read(t.proj.join("c/g")).map_err(|e| e.to_string())? != b"x\n" {
        return Err("the cross-pin move did not reach the host".into());
    }
    Ok(())
}

fn session_leaf_deny_fresh_and_reused() -> Result<(), String> {
    // A deny under a session leaf (/root, /tmp) is created by bwrap inside
    // the leaf, which is allowed (the leaf is exclusively ours).
    let t = Tree::new("leaf-ok");
    let pol = t.policy(
        &[],
        &[],
        &[Path::new("/root/.cache/x"), Path::new("/tmp/deep/er")],
    );
    let script = "test -d /root/.cache/x && test -d /tmp/deep/er && echo OK";
    for _ in 0..2 {
        let done = run_script(&t, &pol, &t.session(), script)?;
        expect_rc(&done, 0)?;
        if !done.stdout.contains("OK") {
            return Err(format!("session-leaf deny missing: {:?}", done.stdout));
        }
    }
    Ok(())
}

// ---- Reviewer findings on #39/#40 (C1, M1, M2, m1) ---------------------------

/// C1 (a1): a writable parent of a nested writable bind is renamed by the
/// payload. The parent is pinned, so the rename is EBUSY and the deny mask
/// keeps hiding the secret on the next run.
fn c1_nested_rw_parent_rename_ebusy() -> Result<(), String> {
    let t = Tree::new("c1-a1");
    let x = t.proj.clone();
    let qp = x.join("q/p");
    fs::create_dir_all(qp.join("a/s")).map_err(|e| e.to_string())?;
    fs::write(qp.join("a/s/key"), b"SECRET\n").map_err(|e| e.to_string())?;
    let pol = t.policy(&[&x, &qp], &[], &[&qp.join("a/s")]);
    let session = t.session();
    let (xs, qs) = (x.display(), qp.display());
    let script =
        format!("if mv {xs}/q {xs}/q2 2>/dev/null; then echo RENAMED; else echo BLOCKED; fi");
    let first = run_script(&t, &pol, &session, &script)?;
    expect_rc(&first, 0)?;
    if !first.stdout.contains("BLOCKED") || first.stdout.contains("RENAMED") {
        return Err(format!(
            "the nested rw parent was renamed: {:?}",
            first.stdout
        ));
    }
    let second = run_script(
        &t,
        &pol,
        &session,
        &format!("cat {xs}/q2/p/a/s/key 2>/dev/null; cat {qs}/a/s/key 2>/dev/null; echo done"),
    )?;
    expect_rc(&second, 0)?;
    if second.stdout.contains("SECRET") {
        return Err(format!("the secret leaked on run 2: {:?}", second.stdout));
    }
    if !t.proj.join("q/p/a/s/key").exists() {
        return Err("the host tree changed".into());
    }
    Ok(())
}

/// C1 (a2): the payload renames the parent of a nested read-only bind and
/// then writes through the renamed path. Neither works: the rename is EBUSY
/// and the ro bind stays read-only.
fn c1_nested_ro_write_through_renamed_parent() -> Result<(), String> {
    let t = Tree::new("c1-a2");
    let x = t.proj.clone();
    let qp = x.join("q/p");
    let ro = qp.join("a/r");
    fs::create_dir_all(&ro).map_err(|e| e.to_string())?;
    fs::write(ro.join("f"), b"ORIG\n").map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&x, &qp], &[], &[]);
    pol.ro_extra = vec![ro.display().to_string()];
    let session = t.session();
    let (xs, qs) = (x.display(), qp.display());
    let script = format!(
        "if mv {xs}/q {xs}/q2 2>/dev/null; then echo RENAMED; else echo BLOCKED; fi; \
         if echo PWNED > {qs}/a/r/f 2>/dev/null; then echo WROTE; else echo RO_OK; fi"
    );
    let first = run_script(&t, &pol, &session, &script)?;
    expect_rc(&first, 0)?;
    if !first.stdout.contains("BLOCKED") || !first.stdout.contains("RO_OK") {
        return Err(format!("nested ro was writable: {:?}", first.stdout));
    }
    let second = run_script(
        &t,
        &pol,
        &session,
        &format!("echo PWNED > {xs}/q2/p/a/r/f 2>/dev/null && echo WROTE2; echo done"),
    )?;
    expect_rc(&second, 0)?;
    if second.stdout.contains("WROTE2") {
        return Err("run 2 wrote through a renamed parent".into());
    }
    if fs::read(ro.join("f")).map_err(|e| e.to_string())? != b"ORIG\n" {
        return Err("the host ro file changed".into());
    }
    Ok(())
}

/// M1 (a3): a deny under a read-only bind, with a symlink planted in the
/// read-only tree (by a different policy's writer). bwrap's setup-time mkdir
/// would follow it to the host, so the run is refused before the spawn.
fn prelaunch_planted_under_ro_cover_125() -> Result<(), String> {
    let t = Tree::new("pl-a3");
    let y = t.proj.clone();
    let r = y.join("r");
    fs::create_dir_all(r.join("a2/s")).map_err(|e| e.to_string())?;
    symlink(Tree::oldroot(&t.outside), r.join("a")).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[&y], &[], &[&r.join("a/s")]);
    pol.ro_extra = vec![r.display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

/// M1 (a3b): a deny under a plain read-only bind, planted symlink.
fn prelaunch_deny_under_plain_ro_125() -> Result<(), String> {
    let t = Tree::new("pl-a3b");
    let z = t.proj.join("z");
    fs::create_dir_all(&z).map_err(|e| e.to_string())?;
    symlink(Tree::oldroot(&t.outside), z.join("a")).map_err(|e| e.to_string())?;
    let mut pol = Pol::new("exit");
    pol.ro_extra = vec![z.display().to_string()];
    pol.deny = vec![z.join("a/s").display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_planted_refusal(&t, &args, "it is a symbolic link")
}

/// C1 (a4): a payload flips a nested-bind parent between a real directory and
/// a relative link to a host directory while other same-policy runs start. No
/// run may read the host key or write into the host directory. The flipping
/// payload runs for the whole loop, and at least 200 probe runs are made.
fn c1_concurrent_source_swap_no_escape() -> Result<(), String> {
    let t = Tree::new("c1-a4");
    let x = t.proj.clone();
    let qp = x.join("q/p");
    fs::create_dir_all(&qp).map_err(|e| e.to_string())?;
    let hs = t.dir.join("hs/p");
    fs::create_dir_all(&hs).map_err(|e| e.to_string())?;
    fs::write(hs.join("HOSTKEY"), b"HOSTKEY\n").map_err(|e| e.to_string())?;
    let pol = t.policy(&[&x, &qp], &[], &[]);
    let policy = pol.write(&t.dir);
    let (xs, qs) = (x.display(), qp.display());
    let flip = format!(
        "cd {xs}; end=$(( $(date +%s) + 6 )); while [ $(date +%s) -lt $end ]; do mv q qr; ln -s ../hs q; sleep 0.002; rm -f q; mv qr q; sleep 0.002; done"
    );
    let flipper = Proc::spawn(
        &sbx_args(&policy, &t.dir.join("sess-flip"), &[], &sh(&flip)),
        |_| {},
    )?;
    std::thread::sleep(Duration::from_millis(500));
    let mut leaks = 0u32;
    let mut runs = 0u32;
    let mut refused = 0u32;
    for i in 0..200 {
        let script = format!(
            "cat {qs}/HOSTKEY 2>/dev/null; cat {xs}/qr/p/HOSTKEY 2>/dev/null; touch {qs}/WRITTEN{i} 2>/dev/null; touch {xs}/qr/p/WRITTEN{i} 2>/dev/null; true"
        );
        let done = run_sbx(&sbx_args(
            &policy,
            &t.dir.join(format!("sess-{i}")),
            &[],
            &sh(&script),
        ))?;
        runs += 1;
        if done.rc == 125 {
            refused += 1;
        }
        if done.stdout.contains("HOSTKEY") {
            leaks += 1;
        }
    }
    let _ = flipper.finish(Duration::from_secs(30));
    let written = entries(&hs)?.into_iter().filter(|n| n != "HOSTKEY").count();
    if runs < 200 {
        return Err(format!("only {runs} probe runs"));
    }
    if leaks != 0 {
        return Err(format!(
            "{leaks} of {runs} runs read the host key ({refused} refused)"
        ));
    }
    if written != 0 {
        return Err(format!(
            "{written} files were written into the host directory"
        ));
    }
    Ok(())
}

/// M2 (a5 T6): a read-only bind whose host source is a link into a deny path
/// exposes the masked directory at another path. Refused before launch.
fn prelaunch_bind_containing_deny_via_link_125() -> Result<(), String> {
    let t = Tree::new("pl-a5");
    let secrets = t.proj.join("secrets/sub");
    fs::create_dir_all(&secrets).map_err(|e| e.to_string())?;
    fs::write(secrets.join("key"), b"TOPSECRET\n").map_err(|e| e.to_string())?;
    let lnk = t.dir.join("lnk");
    symlink(&secrets, &lnk).map_err(|e| e.to_string())?;
    let mut pol = t.policy(&[], &[], &[&t.proj.join("secrets")]);
    pol.ro_extra = vec![lnk.display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "reached through a host symbolic link")
}

/// m1 (a5 T2): a deny nested under another deny whose directory does not
/// exist. The outer mask hides it inside the tmpfs, so the run starts; the
/// nested one is not refused, and nothing is created on the host.
fn nested_deny_under_deny_runs() -> Result<(), String> {
    let t = Tree::new("nd");
    fs::create_dir_all(t.proj.join("a")).map_err(|e| e.to_string())?;
    fs::write(t.proj.join("a/k"), b"K").map_err(|e| e.to_string())?;
    let pol = t.policy(&[&t.proj], &[], &[&t.proj.join("a"), &t.proj.join("a/b/s")]);
    let p = t.proj.display();
    let done = run_script(&t, &pol, &t.session(), &format!("ls -A {p}/a; echo done"))?;
    expect_rc(&done, 0)?;
    if !done.stdout.contains("done") || done.stdout.contains("k") {
        return Err(format!("unexpected listing: {:?}", done.stdout));
    }
    if t.proj.join("a/b").exists() {
        return Err("the nested deny's parent was created on the host".into());
    }
    Ok(())
}

/// N19 (PR #47): `lnk -> real`, a read-only bind of `lnk/p` next to the
/// writable `real`. The bind is nested only through the host alias, so no pin
/// or walk on its lexical chain could hold. Refused before the spawn, with
/// nothing changed on the host.
fn n19_tree(tag: &str) -> Result<(Tree, PathBuf, PathBuf), String> {
    let t = Tree::new(tag);
    let real = t.dir.join("real");
    fs::create_dir_all(real.join("p")).map_err(|e| e.to_string())?;
    let lnk = t.dir.join("lnk");
    symlink(&real, &lnk).map_err(|e| e.to_string())?;
    Ok((t, real, lnk))
}

fn prelaunch_n19_host_alias_ro_125() -> Result<(), String> {
    let (t, real, lnk) = n19_tree("n19-ro")?;
    let mut pol = t.policy(&[&real], &[], &[]);
    pol.ro_extra = vec![lnk.join("p").display().to_string()];
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "through a host symbolic link")?;
    if !real.join("p").is_dir() {
        return Err("the host directory changed".into());
    }
    Ok(())
}

fn prelaunch_n19_host_alias_rw_125() -> Result<(), String> {
    let (t, real, lnk) = n19_tree("n19-rw")?;
    let pol = t.policy(&[&real, &lnk.join("p")], &[], &[]);
    let args = sbx_args(&pol.write(&t.dir), &t.session(), &[], &sh("true"));
    expect_refusal(&args, "through a host symbolic link")?;
    if real.join("p").join("WRITTEN").exists() {
        return Err("a payload file reached the host".into());
    }
    Ok(())
}
