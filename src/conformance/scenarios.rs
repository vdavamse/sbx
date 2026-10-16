//! Host-tier scenarios S1–S12 (issue #13, §8.3): each one is one or more
//! `sbx run` invocations whose probe output, audit rows, controls and exit
//! status are the evidence the evaluators in [`super::host_tier`] judge.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::policies::{self, Builtin};
use super::probe::{
    HelloSpec, Op, Ops, ProbeOutput, ReadSpec, ReadToEndSpec, SendSpec, Step, Target,
};
use super::spawn::{
    Finished, Running, SbxRun, kill_pids, netns_of, pids_in_netns, poll_gone, proc_scan,
};

/// Run-wide inputs shared by every scenario.
pub struct Env {
    pub exe: PathBuf,
    pub exe_text: String,
    pub base: PathBuf,
    /// Two nonces: `secret` (must not reach the payload) and `passed`
    /// (allowed through `env.pass`).
    pub secret: String,
    pub passed: String,
    pub nonce: String,
}

/// One scenario's evidence.
#[derive(Debug, Clone, Default)]
pub struct Scn {
    pub name: &'static str,
    /// A capability skip reason: every check on this scenario skips with it.
    pub skip: Option<String>,
    pub fin: Option<Finished>,
    pub probe: Option<ProbeOutput>,
    pub probe_err: Option<String>,
    pub audit: Vec<Value>,
    /// Control results: `Ok(())` when the control held.
    pub ctl: BTreeMap<&'static str, Result<(), String>>,
    /// Numbers (counters, sizes).
    pub nums: BTreeMap<&'static str, u64>,
    /// Strings (tokens, addresses, inode texts, ...).
    pub notes: BTreeMap<&'static str, String>,
    pub ms: u64,
}

impl Scn {
    pub(super) fn named(name: &'static str) -> Self {
        Scn {
            name,
            ..Default::default()
        }
    }

    /// A scenario that could not run: every check on it skips with `why`.
    pub fn unavailable(name: &'static str, why: String) -> Self {
        Scn {
            name,
            skip: Some(why),
            ..Default::default()
        }
    }
}

/// Wait for the token and netns to empty, recording the evidence BEFORE any
/// cleanup: `netns-after-exit` is the netns membership at the moment the poll
/// ends (G05 reads it), and `key` is the lifecycle assertion. Survivors are
/// then SIGKILLed; the kill is reported in the assertion's evidence.
fn gone_check(scn: &mut Scn, key: &'static str, token: &str, netns: Option<&str>) {
    let polled = poll_gone(token, netns, Duration::from_secs(5));
    if let Some(n) = netns {
        let left = pids_in_netns(n);
        let verdict = if left.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "netns members after exit (before cleanup): pids {left:?}"
            ))
        };
        scn.ctl.insert("netns-after-exit", verdict);
    }
    let outcome = match &polled {
        Ok(()) => Ok(()),
        Err(pids) => {
            kill_pids(pids);
            Err(format!(
                "survivors after exit: pids {pids:?} (SIGKILLed after recording)"
            ))
        }
    };
    scn.ctl.insert(key, outcome);
}

/// Which scenario group produces these names.
pub fn group_of(name: &str) -> &'static str {
    match name {
        "S12" => "S12",
        "S1" => "S1",
        "S13" => "S13",
        "S2" | "S3" => "S2",
        "S4" => "S4",
        "S5" => "S5",
        "S6" | "S6b" => "S6",
        "S7" => "S7",
        "S8a" | "S8b" | "S8c" => "S8",
        "S9" => "S9",
        "S10" => "S10",
        "S11a" | "S11b" => "S11",
        _ => "?",
    }
}

/// Run one scenario group, returning every scenario it produced.
pub fn run_group(env: &Env, group: &str) -> Vec<Scn> {
    match group {
        "S12" => s12(env),
        "S1" => vec![s1(env)],
        "S13" => vec![s13(env)],
        "S2" => s2(env),
        "S4" => vec![s4(env)],
        "S5" => vec![s5(env)],
        "S6" => s6(env),
        "S7" => vec![s7(env)],
        "S8" => s8(env),
        "S9" => vec![s9(env)],
        "S10" => vec![s10(env)],
        "S11" => s11(env),
        _ => vec![],
    }
}

fn tok(env: &Env, tag: &str) -> String {
    format!("tok-{tag}-{}", env.nonce)
}

fn expect_token_line(id: &str) -> impl Fn(&str) -> bool + '_ {
    move |l: &str| l.contains(&format!("\"id\":\"{id}\""))
}

/// The probe-ops JSON for one `sbx run` payload.
pub(super) fn payload(ops: Vec<Op>, exe_text: &str) -> Vec<String> {
    let json = serde_json::to_string(&Ops::new(ops)).unwrap_or_else(|_| "{}".to_owned());
    vec![
        exe_text.to_owned(),
        "__conformance".to_owned(),
        "probe".to_owned(),
        json,
    ]
}

/// Parse the audit JSON-lines file (missing file: no rows).
pub fn read_audit(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// Derive the Scn fields from a finished run.
pub(super) fn finish_scn(scn: &mut Scn, fin: Finished, audit: &Path, allow_no_done: bool) {
    scn.ms = fin.elapsed_ms;
    scn.audit = read_audit(audit);
    match parse_probe(&fin.stdout, allow_no_done) {
        Ok(p) => scn.probe = Some(p),
        Err(e) => scn.probe_err = Some(e),
    }
    scn.skip = classify_skip(&fin);
    if std::env::var_os("SBX_CONFORMANCE_TRACE").is_some() {
        trace_ops(scn);
    }
    scn.fin = Some(fin);
}

/// `SBX_CONFORMANCE_TRACE=1`: one stderr line per probe op with its wall time
/// since the previous op (the per-op timing used to size scenario bounds).
fn trace_ops(scn: &Scn) {
    if let Some(b) = scn.nums.get("budget_ms") {
        eprintln!("trace {} op budget {} ms (bound adds 10 s)", scn.name, b);
    }
    let Some(p) = &scn.probe else { return };
    let mut rows: Vec<&super::probe::OpResult> = p.results.values().collect();
    rows.sort_by_key(|r| r.t_ms);
    let mut prev: Option<u64> = None;
    for r in rows {
        let dt = prev.map_or(0, |t| r.t_ms.saturating_sub(t));
        eprintln!("trace {} {:<18} {:>6} ms (ok={})", scn.name, r.id, dt, r.ok);
        prev = Some(r.t_ms);
    }
}

fn parse_probe(lines: &[String], allow_no_done: bool) -> Result<ProbeOutput, String> {
    ProbeOutput::parse(lines, allow_no_done)
}

/// Capability classification of an `sbx run` outcome (§8.2 step 1 and 2).
pub fn classify_skip(fin: &Finished) -> Option<String> {
    let first = fin.stderr.lines().next().unwrap_or("").to_owned();
    if fin.rc == Some(125)
        && (fin.stderr.contains("this host cannot run sandboxes")
            || fin.stderr.contains("policy requires network mode"))
    {
        return Some(first);
    }
    if fin.rc == Some(1) && fin.stderr.starts_with("bwrap: execvp") {
        return Some("the sbx binary cannot run inside the sandbox (a dynamically linked build on a host whose libraries are outside /usr? use the static release build)".to_owned());
    }
    None
}

/// Options for one plain scenario.
#[derive(Default)]
pub(super) struct Opts {
    break_rules: bool,
    timeout: Option<&'static str>,
    fsize: Option<u64>,
    extra_env: Vec<(String, String)>,
    secret_fd: Option<String>,
    allow_no_done: bool,
    /// Ignore a `Finished` refusal (F05 expects it): do not classify.
    expect_refusal: bool,
    /// Observe the token's survivors after the run's exit and before the
    /// cleanup kill, recording the lifecycle assertion under this key.
    observe_gone: Option<(&'static str, String)>,
}

/// One scenario from start to finish: policy, session, ops, and the bounded wait.
/// A scenario's wall-clock bound: its ops' worst-case budget plus 10 s of slack.
pub fn budget_bound(ops: &[Op]) -> Duration {
    Duration::from_millis(ops.iter().map(Op::budget_ms).sum::<u64>()) + Duration::from_secs(10)
}

pub(super) fn plain(
    env: &Env,
    name: &'static str,
    which: Builtin,
    ops: Vec<Op>,
    opts: Opts,
) -> Scn {
    let bound = budget_bound(&ops);
    let budget = ops.iter().map(Op::budget_ms).sum::<u64>();
    let mut scn = Scn::named(name);
    scn.nums.insert("budget_ms", budget);
    let text = policies::policy_json(which, &env.exe_text, None);
    let policy = match policies::write_policy(&env.base, &format!("p-{name}-{which:?}"), &text) {
        Ok(p) => p,
        Err(e) => return Scn::unavailable(name, format!("cannot write policy: {e}")),
    };
    let session = env.base.join(format!("s-{name}"));
    let audit = env.base.join(format!("a-{name}.jsonl"));
    let mut run =
        SbxRun::new(&env.exe, &policy, &session, payload(ops, &env.exe_text)).audit(&audit);
    if opts.break_rules {
        run = run.break_rules();
    }
    if let Some(t) = opts.timeout {
        run = run.timeout(t);
    }
    if let Some(f) = opts.fsize {
        run = run.fsize(f);
    }
    for (k, v) in &opts.extra_env {
        run = run.env(k, v);
    }
    let started = Instant::now();
    let mut r = match spawn_with_secret(run, opts.secret_fd.as_deref(), &env.base, &mut scn) {
        Ok(r) => r,
        Err(e) => return Scn::unavailable(name, format!("cannot spawn sbx run: {e}")),
    };
    r.wait_exit(started + bound);
    if let Some((key, token)) = &opts.observe_gone {
        gone_check(&mut scn, key, token, None);
    }
    let fin = r.finish();
    if opts.expect_refusal {
        let mut s = scn.clone();
        s.ms = fin.elapsed_ms;
        s.audit = read_audit(&audit);
        s.probe_err = Some("refused before the probe ran".to_owned());
        s.fin = Some(fin);
        return s;
    }
    finish_scn(&mut scn, fin, &audit, opts.allow_no_done);
    scn
}

/// Spawn with the H05 secret descriptor: CLOEXEC cleared just before the spawn
/// and closed right after it (the main-thread, sequential R6 rule).
fn spawn_with_secret(
    run: SbxRun,
    secret: Option<&str>,
    base: &Path,
    scn: &mut Scn,
) -> std::io::Result<Running> {
    let Some(text) = secret else {
        return run.spawn();
    };
    let path = base.join("secret-fd");
    let mut f = File::create(&path)?;
    f.write_all(text.as_bytes())?;
    drop(f);
    let f = File::open(&path)?;
    let fd = f.as_raw_fd();
    // SAFETY: fcntl on a descriptor we own.
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let cleared = flags >= 0 && flags & libc::FD_CLOEXEC == 0;
    scn.ctl.insert(
        "fd-cloexec-cleared",
        if cleared {
            Ok(())
        } else {
            Err("FD_CLOEXEC still set on the secret descriptor".to_owned())
        },
    );
    let spawned = run.spawn();
    drop(f);
    let _ = fs::remove_file(&path);
    spawned
}

fn hello(id: &str) -> Op {
    Op::Hello { id: id.to_owned() }
}

fn dns(id: &str, name: &str) -> Op {
    Op::Dns {
        id: id.to_owned(),
        name: name.to_owned(),
        qtype: "A".to_owned(),
        server: "127.0.0.1:53".to_owned(),
        tcp: false,
        timeout_ms: 1000,
    }
}

fn dns_q(id: &str, name: &str, qtype: &str, server: &str, tcp: bool) -> Op {
    Op::Dns {
        id: id.to_owned(),
        name: name.to_owned(),
        qtype: qtype.to_owned(),
        server: server.to_owned(),
        tcp,
        timeout_ms: 1000,
    }
}

fn tcp_addr(id: &str, addr: &str, steps: Vec<Step>) -> Op {
    Op::Tcp {
        id: id.to_owned(),
        target: Target::Addr {
            addr: addr.to_owned(),
        },
        steps,
        connect_timeout_ms: 1000,
    }
}

fn tcp_name(id: &str, name: &str, port: u16, steps: Vec<Step>) -> Op {
    Op::Tcp {
        id: id.to_owned(),
        target: Target::Name {
            name: name.to_owned(),
            port,
        },
        steps,
        connect_timeout_ms: 1000,
    }
}

fn text(s: &str) -> Step {
    Step::Send(SendSpec::Text { text: s.to_owned() })
}

fn send_hello(sni: Option<&str>) -> Step {
    Step::Send(SendSpec::Hello {
        hello: HelloSpec {
            sni: sni.map(str::to_owned),
            ech: false,
        },
    })
}

fn read_head() -> Step {
    Step::Read(ReadSpec {
        until: Some("\r\n\r\n".to_owned()),
        max: 65536,
        timeout_ms: 1000,
    })
}

fn to_end() -> Step {
    Step::ReadToEnd(ReadToEndSpec {
        max: 65536,
        timeout_ms: 1000,
    })
}

/// A length-prefixed DNS A query for `name`, as ASCII-only text (every wire
/// byte is below 0x80 for these names).
fn dns_tcp_query(name: &str) -> String {
    let mut m = hickory_proto::op::Message::new();
    m.set_id(0x5c13)
        .set_recursion_desired(true)
        .add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii(name).unwrap_or_default(),
            hickory_proto::rr::RecordType::A,
        ));
    let bytes = m.to_vec().unwrap_or_default();
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend(bytes);
    framed.iter().map(|b| char::from(*b)).collect()
}

fn connect_req(target: &str) -> String {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
}

/// The runner's own TCP listener, accept-counting (the host-side controls).
pub struct Counter {
    pub port: u16,
    pub accepts: Arc<AtomicU64>,
}

fn counting_listener(addr: &str) -> std::io::Result<Counter> {
    let l = TcpListener::bind(addr)?;
    let port = l.local_addr()?.port();
    let accepts = Arc::new(AtomicU64::new(0));
    let a2 = accepts.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            match s {
                Ok(s) => {
                    a2.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                }
                Err(_) => break,
            }
        }
    });
    Ok(Counter { port, accepts })
}

/// Connect to a counting listener once (the control) and wait for the accept.
fn control_connect(c: &Counter) -> Result<(), String> {
    TcpStream::connect(("127.0.0.1", c.port))
        .map_err(|e| format!("runner control connect failed: {e}"))?;
    for _ in 0..100 {
        if c.accepts.load(Ordering::SeqCst) >= 1 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("runner control accept not observed".to_owned())
}

fn s1(env: &Env) -> Scn {
    let listener = counting_listener("127.0.0.1:0").ok();
    let lport = listener.as_ref().map(|c| c.port).unwrap_or(1);
    let abstract_name = format!("sbx-conf-{}", env.nonce);
    // A short dedicated path: sun_path is 108 bytes, and TMPDIR may be long.
    let host_sock = PathBuf::from(format!("/tmp/sbxc-{}.s", &env.nonce[..8]));
    let _ = fs::remove_file(&host_sock);
    let unix_bind = UnixListener::bind(&host_sock);
    let unix_bind_err = unix_bind.as_ref().err().map(|e| e.to_string());
    let unix_listener = unix_bind.ok();
    let abs_listener = {
        use std::os::linux::net::SocketAddrExt;
        std::os::unix::net::SocketAddr::from_abstract_name(&abstract_name)
            .and_then(|a| UnixListener::bind_addr(&a))
            .ok()
    };
    let mut ops: Vec<Op> = vec![
        hello("s1.hello"),
        dns("a01.a", "allowed.conformance.test"),
        dns_q(
            "a01.aaaa",
            "allowed.conformance.test",
            "AAAA",
            "127.0.0.1:53",
            false,
        ),
        dns("a07.dns", "other.conformance.test"),
        dns("a08.dns", "notpypi.org"),
        dns("a08.pypi", "pypi.org"),
        dns("a09.evil", "pypi.org.evil.com"),
        dns("a09.idn", "xn--pyp-lhd.org"),
        dns("d02.dns", "localhost"),
        dns_q(
            "c06.a8",
            "allowed.conformance.test",
            "A",
            "8.8.8.8:53",
            false,
        ),
        dns_q(
            "c06.other8",
            "other.conformance.test",
            "A",
            "8.8.8.8:53",
            false,
        ),
        dns_q(
            "c06.a1",
            "allowed.conformance.test",
            "A",
            "1.1.1.1:53",
            false,
        ),
        Op::Udp {
            id: "c05.u123".into(),
            addr: "8.8.8.8:123".into(),
            text: "Q".into(),
            attempts: 3,
            recv_timeout_ms: 100,
        },
        Op::Udp {
            id: "c05.u443".into(),
            addr: "9.9.9.9:443".into(),
            text: "Q".into(),
            attempts: 3,
            recv_timeout_ms: 100,
        },
        tcp_addr("c09.v6", "[2606:4700:4700::1111]:443", vec![]),
        tcp_addr("c09.v6lo", "[::1]:80", vec![]),
        Op::Links {
            id: "c01.links".into(),
        },
        Op::Socket {
            id: "c10.raw4".into(),
            family: "inet".into(),
            ty: "raw".into(),
            protocol: 1,
        },
        Op::Socket {
            id: "c10.raw6".into(),
            family: "inet6".into(),
            ty: "raw".into(),
            protocol: 58,
        },
        Op::Socket {
            id: "c11.packet".into(),
            family: "packet".into(),
            ty: "raw".into(),
            protocol: 0,
        },
        Op::Socket {
            id: "c11.xdp".into(),
            family: "xdp".into(),
            ty: "raw".into(),
            protocol: 0,
        },
        Op::Socket {
            id: "c12.icmp".into(),
            family: "inet".into(),
            ty: "dgram".into(),
            protocol: 1,
        },
        Op::Socket {
            id: "c14.vs_stream".into(),
            family: "vsock".into(),
            ty: "stream".into(),
            protocol: 0,
        },
        Op::Socket {
            id: "c14.vs_seq".into(),
            family: "vsock".into(),
            ty: "seqpacket".into(),
            protocol: 0,
        },
        Op::Netlink {
            id: "c13.lo_down".into(),
            action: "lo_down".into(),
        },
        Op::Netlink {
            id: "c13.addr".into(),
            action: "addr_add".into(),
        },
        Op::Netlink {
            id: "c13.route".into(),
            action: "route_del_default".into(),
        },
        Op::Netlink {
            id: "c13.dump".into(),
            action: "dump_links".into(),
        },
        tcp_addr("d01.tcp", &format!("127.0.0.1:{lport}"), vec![]),
        Op::UnixConnect {
            id: "d03.abs".into(),
            path: None,
            abstract_name: Some(abstract_name.clone()),
        },
        Op::UnixConnect {
            id: "d04.path".into(),
            path: Some(host_sock.to_string_lossy().into_owned()),
            abstract_name: None,
        },
        tcp_addr(
            "a10.hello",
            "1.1.1.1:443",
            vec![send_hello(Some("allowed.conformance.test")), to_end()],
        ),
        tcp_addr(
            "c03.tcp",
            "203.0.113.7:22",
            vec![text("SSH-2.0-x\r\n"), to_end()],
        ),
        tcp_addr(
            "c08.tcp853",
            "1.1.1.1:853",
            vec![send_hello(Some("allowed.conformance.test")), to_end()],
        ),
        tcp_name(
            "a08.hello",
            "pypi.org",
            443,
            vec![send_hello(Some("notpypi.org")), to_end()],
        ),
        tcp_name(
            "a09.hello",
            "pypi.org",
            443,
            vec![send_hello(Some("pypi.org.evil.com")), to_end()],
        ),
        tcp_name(
            "a09.idnhello",
            "pypi.org",
            443,
            vec![send_hello(Some("xn--pyp-lhd.org")), to_end()],
        ),
        tcp_name(
            "a11.hello",
            "allowed.conformance.test",
            8443,
            vec![send_hello(Some("allowed.conformance.test")), to_end()],
        ),
        tcp_name(
            "d02.hello",
            "localhost",
            443,
            vec![send_hello(Some("localhost")), to_end()],
        ),
        // DNS over TCP/53: a length-prefixed wire query sent as a plain TCP leg,
        // so the denied connection is pinned by its local address like any leg.
        tcp_addr(
            "c08.dns_tcp",
            "8.8.8.8:53",
            vec![text(&dns_tcp_query("allowed.conformance.test")), to_end()],
        ),
    ];
    let proxy = "127.0.0.1:3128";
    let connects: [(&str, &str); 6] = [
        ("a07.connect", "other.conformance.test:443"),
        ("a08.connect", "notpypi.org:443"),
        ("a09.connect", "pypi.org.evil.com:443"),
        ("a09.idnconnect", "xn--pyp-lhd.org:443"),
        ("a10.connect", "9.9.9.9:443"),
        ("a11.connect", "allowed.conformance.test:8443"),
    ];
    for (id, target) in connects {
        ops.push(tcp_addr(
            id,
            proxy,
            vec![text(&connect_req(target)), read_head()],
        ));
    }
    ops.push(tcp_addr("b10.abs", proxy, vec![text("GET http://allowed.conformance.test/ HTTP/1.1\r\nHost: other.conformance.test\r\nConnection: close\r\n\r\n"), read_head()]));
    ops.push(tcp_addr("b10.rev", proxy, vec![text("GET http://other.conformance.test/ HTTP/1.1\r\nHost: allowed.conformance.test\r\nConnection: close\r\n\r\n"), read_head()]));
    ops.push(tcp_addr("b10.https", proxy, vec![text("GET https://allowed.conformance.test/ HTTP/1.1\r\nHost: allowed.conformance.test\r\nConnection: close\r\n\r\n"), read_head()]));
    ops.push(tcp_addr(
        "a10.abs",
        proxy,
        vec![
            text("GET http://9.9.9.9/ HTTP/1.1\r\nHost: 9.9.9.9\r\nConnection: close\r\n\r\n"),
            read_head(),
        ],
    ));
    ops.push(tcp_addr(
        "d02.connect",
        proxy,
        vec![
            text(&connect_req(&format!("127.0.0.1:{lport}"))),
            read_head(),
        ],
    ));
    ops.push(tcp_addr(
        "d02.cnlo",
        proxy,
        vec![
            text(&connect_req("localhost:443")),
            read_head(),
            send_hello(Some("localhost")),
            to_end(),
        ],
    ));
    let _ = (&unix_listener, &abs_listener);
    // The control first: one runner-side connect is accepted (the baseline).
    let d01_control = listener.as_ref().map(control_connect);
    let d04_ctl: Result<(), String> = match (&unix_listener, &unix_bind_err) {
        (Some(_), _) => std::os::unix::net::UnixStream::connect(&host_sock)
            .map(|_| ())
            .map_err(|e| format!("runner control connect failed: {e}")),
        (None, Some(e)) => Err(format!(
            "runner pathname listener not bound (sun_path {}): {e}",
            host_sock.display()
        )),
        (None, None) => Err("runner pathname listener not bound".to_owned()),
    };
    let d03_ctl: Result<(), String> = match &abs_listener {
        Some(_) => {
            use std::os::linux::net::SocketAddrExt;
            std::os::unix::net::SocketAddr::from_abstract_name(&abstract_name)
                .and_then(|a| std::os::unix::net::UnixStream::connect_addr(&a))
                .map(|_| ())
                .map_err(|e| format!("runner control connect failed: {e}"))
        }
        None => Err("runner abstract listener not bound".to_owned()),
    };
    let before = listener
        .as_ref()
        .map(|l| l.accepts.load(Ordering::SeqCst))
        .unwrap_or(0);
    let mut scn = plain(
        env,
        "S1",
        Builtin::Transparent,
        ops,
        Opts {
            allow_no_done: false,
            ..Default::default()
        },
    );
    if let Some(l) = &listener {
        scn.nums.insert("d01.before", before);
        scn.nums
            .insert("d01.after", l.accepts.load(Ordering::SeqCst));
    }
    if let Some(c) = d01_control {
        scn.ctl.insert("d01.own", c);
    }
    scn.notes.insert("lport", lport.to_string());
    scn.notes.insert("abstract", abstract_name.clone());
    scn.notes
        .insert("host_sock", host_sock.to_string_lossy().into_owned());
    scn.ctl.insert("d03.own", d03_ctl);
    scn.ctl.insert("d04.own", d04_ctl);
    let _ = fs::remove_file(&host_sock);
    scn
}

/// S13: the D05 socket walk over the sandbox's whole view, under its own
/// wall-clock budget. A walk cut short by the budget is a WARN, not a pass.
fn s13(env: &Env) -> Scn {
    let ops = vec![
        hello("s13.hello"),
        Op::SocketsWalk {
            id: "d05.walk".into(),
            roots: vec!["/".into()],
            skip: vec!["/proc".into(), "/dev".into(), "/sys".into()],
            max_entries: 400000,
            max_depth: 16,
            budget_ms: 8000,
        },
    ];
    let mut s = plain(env, "S13", Builtin::Transparent, ops, Opts::default());
    s.name = "S13";
    s
}

fn s2(env: &Env) -> Vec<Scn> {
    let ops = vec![
        hello("s2.hello"),
        tcp_addr("c04.tcp", "203.0.113.7:443", vec![]),
        tcp_addr(
            "c04.connect",
            "127.0.0.1:3128",
            vec![
                text(&connect_req("other.conformance.test:443")),
                read_head(),
            ],
        ),
    ];
    let s2 = plain(
        env,
        "S2",
        Builtin::Explicit,
        ops,
        Opts {
            break_rules: true,
            ..Default::default()
        },
    );
    let s3 = plain(
        env,
        "S3",
        Builtin::NoNetwork,
        vec![
            hello("s3.hello"),
            dns("a01.none", "allowed.conformance.test"),
        ],
        Opts::default(),
    );
    let mut s3 = s3;
    s3.name = "S3";
    let mut s2 = s2;
    s2.name = "S2";
    vec![s2, s3]
}

fn s4(env: &Env) -> Scn {
    let mut s = plain(
        env,
        "S4",
        Builtin::Transparent,
        vec![hello("s4.hello")],
        Opts {
            break_rules: true,
            expect_refusal: true,
            ..Default::default()
        },
    );
    s.name = "S4";
    s
}

fn s5(env: &Env) -> Scn {
    let token = tok(env, "f06");
    let ops = vec![
        hello("s5.hello"),
        Op::SpawnBg {
            id: "f06.bg".into(),
            token: token.clone(),
            stdio: "null".into(),
            ignore_signals: true,
        },
        Op::DnsFlood {
            id: "f06.flood".into(),
            prefix: "f06".into(),
            count: 2000,
            server: "127.0.0.1:53".into(),
        },
    ];
    let mut s = plain(
        env,
        "S5",
        Builtin::Explicit,
        ops,
        Opts {
            fsize: Some(16384),
            allow_no_done: true,
            // Survivors: rc 125 kills the group; the bg must be gone within 5 s.
            observe_gone: Some(("f06.gone", token.clone())),
            ..Default::default()
        },
    );
    s.name = "S5";
    let audit_len = fs::metadata(env.base.join("a-S5.jsonl"))
        .map(|m| m.len())
        .unwrap_or(0);
    s.nums.insert("audit_bytes", audit_len);
    s.notes.insert("token", token.clone());
    s
}

fn s6(env: &Env) -> Vec<Scn> {
    let token = tok(env, "g01");
    let ops = vec![
        hello("s6.hello"),
        Op::SpawnBg {
            id: "g01.bg".into(),
            token: token.clone(),
            stdio: "null".into(),
            ignore_signals: true,
        },
        Op::WaitStdin {
            id: "g01.wait".into(),
            timeout_ms: 20000,
        },
    ];
    let text_pol = policies::policy_json(Builtin::Explicit, &env.exe_text, None);
    let policy = policies::write_policy(&env.base, "p-S6", &text_pol).ok();
    let mut out = Vec::new();
    let mut s6 = Scn::named("S6");
    let session = env.base.join("s-S6");
    let audit = env.base.join("a-S6.jsonl");
    let Some(pol) = policy else {
        return vec![Scn::unavailable("S6", "cannot write policy".to_owned())];
    };
    let mut r = match SbxRun::new(&env.exe, &pol, &session, payload(ops, &env.exe_text))
        .audit(&audit)
        .stdin_pipe()
        .spawn()
    {
        Ok(r) => r,
        Err(e) => return vec![Scn::unavailable("S6", format!("cannot spawn sbx run: {e}"))],
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let bg_line = r.wait_line(expect_token_line("g01.bg"), deadline);
    let pids = proc_scan(&token);
    let netns = pids.first().and_then(|p| netns_of(*p));
    s6.ctl.insert(
        "g01.seen",
        if !pids.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "token not alive before stdin close (bg line: {})",
                bg_line.is_some()
            ))
        },
    );
    if let Some(n) = &netns {
        s6.notes.insert("netns", n.clone());
    }
    s6.notes.insert("token", token.clone());
    r.close_stdin();
    r.wait_exit(Instant::now() + Duration::from_secs(10));
    gone_check(&mut s6, "g01.gone", &token, netns.as_deref());
    let fin = r.finish();
    finish_scn(&mut s6, fin, &audit, false);
    out.push(s6);
    // S6b: the same session dir is reusable.
    let mut s6b = Scn::named("S6b");
    let audit_b = env.base.join("a-S6b.jsonl");
    let sb = SbxRun::new(
        &env.exe,
        &pol,
        &session,
        payload(vec![hello("s6b.hello")], &env.exe_text),
    )
    .audit(&audit_b)
    .spawn();
    if let Ok(mut r) = sb {
        let fin = r.wait_bounded(Instant::now() + Duration::from_secs(10));
        finish_scn(&mut s6b, fin, &audit_b, false);
    } else {
        s6b.skip = Some("cannot spawn sbx run".to_owned());
    }
    out.push(s6b);
    out
}

fn s7(env: &Env) -> Scn {
    let token = tok(env, "g02");
    let ops = vec![
        hello("s7.hello"),
        Op::SpawnBg {
            id: "g02.bg".into(),
            token: token.clone(),
            stdio: "null".into(),
            ignore_signals: true,
        },
        Op::Sleep {
            id: "g02.sleep".into(),
            ms: 30000,
        },
    ];
    let text_pol = policies::policy_json(Builtin::Explicit, &env.exe_text, None);
    let mut s = Scn::named("S7");
    let Ok(pol) = policies::write_policy(&env.base, "p-S7", &text_pol) else {
        return Scn::unavailable("S7", "cannot write policy".to_owned());
    };
    let session = env.base.join("s-S7");
    let audit = env.base.join("a-S7.jsonl");
    let mut r = match SbxRun::new(&env.exe, &pol, &session, payload(ops, &env.exe_text))
        .audit(&audit)
        .timeout("1s")
        .spawn()
    {
        Ok(r) => r,
        Err(e) => return Scn::unavailable("S7", format!("cannot spawn sbx run: {e}")),
    };
    let _ = r.wait_line(
        expect_token_line("g02.bg"),
        Instant::now() + Duration::from_secs(10),
    );
    let seen = !proc_scan(&token).is_empty();
    s.ctl.insert(
        "g02.seen",
        if seen {
            Ok(())
        } else {
            Err("token not alive before the timeout".to_owned())
        },
    );
    r.wait_exit(Instant::now() + Duration::from_secs(10));
    gone_check(&mut s, "g02.gone", &token, None);
    let fin = r.finish();
    finish_scn(&mut s, fin, &audit, true);
    s.notes.insert("token", token);
    s
}

fn s8(env: &Env) -> Vec<Scn> {
    let mut out = Vec::new();
    let text_pol = policies::policy_json(Builtin::Explicit, &env.exe_text, None);
    let Ok(pol) = policies::write_policy(&env.base, "p-S8", &text_pol) else {
        return vec![Scn::unavailable("S8a", "cannot write policy".to_owned())];
    };
    for (name, sig) in [
        ("S8a", libc::SIGTERM),
        ("S8b", libc::SIGINT),
        ("S8c", libc::SIGHUP),
    ] {
        let token = tok(env, &format!("g03{}", &name[2..]));
        let ops = vec![
            hello(&format!("{name}.hello")),
            Op::SpawnBg {
                id: format!("{name}.bg"),
                token: token.clone(),
                stdio: "null".into(),
                ignore_signals: true,
            },
            Op::WaitStdin {
                id: format!("{name}.wait"),
                timeout_ms: 20000,
            },
        ];
        let session = env.base.join(format!("s-{name}"));
        let audit = env.base.join(format!("a-{name}.jsonl"));
        let mut s = Scn::named(name);
        let mut r = match SbxRun::new(&env.exe, &pol, &session, payload(ops, &env.exe_text))
            .audit(&audit)
            .stdin_pipe()
            .spawn()
        {
            Ok(r) => r,
            Err(e) => {
                out.push(Scn::unavailable(name, format!("cannot spawn sbx run: {e}")));
                continue;
            }
        };
        let _ = r.wait_line(
            expect_token_line(&format!("{name}.bg")),
            Instant::now() + Duration::from_secs(10),
        );
        let seen = !proc_scan(&token).is_empty();
        s.ctl.insert(
            "g03.seen",
            if seen {
                Ok(())
            } else {
                Err("token not alive before the signal".to_owned())
            },
        );
        r.signal(sig);
        r.wait_exit(Instant::now() + Duration::from_secs(10));
        gone_check(&mut s, "g03.gone", &token, None);
        let fin = r.finish();
        finish_scn(&mut s, fin, &audit, true);
        s.nums.insert("signal", sig as u64);
        s.notes.insert("token", token);
        out.push(s);
    }
    out
}

fn s9(env: &Env) -> Scn {
    let token = tok(env, "g04");
    let ops = vec![
        hello("s9.hello"),
        Op::SpawnBg {
            id: "g04.bg".into(),
            token: token.clone(),
            stdio: "inherit".into(),
            ignore_signals: true,
        },
        // Keeps the probe alive briefly so the runner can observe the background
        // process before the probe exits (the exit itself is what G04 tests).
        Op::Sleep {
            id: "g04.sleep".into(),
            ms: 500,
        },
    ];
    let text_pol = policies::policy_json(Builtin::Explicit, &env.exe_text, None);
    let mut s = Scn::named("S9");
    let Ok(pol) = policies::write_policy(&env.base, "p-S9", &text_pol) else {
        return Scn::unavailable("S9", "cannot write policy".to_owned());
    };
    let session = env.base.join("s-S9");
    let audit = env.base.join("a-S9.jsonl");
    let mut r = match SbxRun::new(&env.exe, &pol, &session, payload(ops, &env.exe_text))
        .audit(&audit)
        .spawn()
    {
        Ok(r) => r,
        Err(e) => return Scn::unavailable("S9", format!("cannot spawn sbx run: {e}")),
    };
    let _ = r.wait_line(
        expect_token_line("g04.bg"),
        Instant::now() + Duration::from_secs(10),
    );
    let seen = !proc_scan(&token).is_empty();
    s.ctl.insert(
        "g04.seen",
        if seen {
            Ok(())
        } else {
            Err("token not alive when the background process was spawned".to_owned())
        },
    );
    r.wait_exit(Instant::now() + Duration::from_secs(10));
    gone_check(&mut s, "g04.gone", &token, None);
    let fin = r.finish();
    finish_scn(&mut s, fin, &audit, true);
    s.notes.insert("token", token);
    s
}

fn s10(env: &Env) -> Scn {
    let token = tok(env, "f01");
    let ops = vec![
        hello("s10.hello"),
        Op::SpawnBg {
            id: "f01.bg".into(),
            token: token.clone(),
            stdio: "null".into(),
            ignore_signals: true,
        },
        Op::WaitStdin {
            id: "f01.wait".into(),
            timeout_ms: 20000,
        },
    ];
    let text_pol = policies::policy_json(Builtin::Explicit, &env.exe_text, None);
    let mut s = Scn::named("S10");
    let Ok(pol) = policies::write_policy(&env.base, "p-S10", &text_pol) else {
        return Scn::unavailable("S10", "cannot write policy".to_owned());
    };
    let session = env.base.join("s-S10");
    let audit = env.base.join("a-S10.jsonl");
    let mut r = match SbxRun::new(&env.exe, &pol, &session, payload(ops, &env.exe_text))
        .audit(&audit)
        .stdin_pipe()
        .spawn()
    {
        Ok(r) => r,
        Err(e) => return Scn::unavailable("S10", format!("cannot spawn sbx run: {e}")),
    };
    let _ = r.wait_line(
        expect_token_line("f01.bg"),
        Instant::now() + Duration::from_secs(10),
    );
    let pids = proc_scan(&token);
    let netns = pids.first().and_then(|p| netns_of(*p));
    s.ctl.insert(
        "f01.seen",
        if !pids.is_empty() && netns.is_some() {
            Ok(())
        } else {
            Err("token or netns not observed before the kill".to_owned())
        },
    );
    if let Some(n) = &netns {
        s.notes.insert("netns", n.clone());
        s.nums
            .insert("netns_members_before", pids_in_netns(n).len() as u64);
    }
    r.sigkill();
    r.wait_exit(Instant::now() + Duration::from_secs(10));
    gone_check(&mut s, "f01.gone", &token, netns.as_deref());
    let fin = r.finish();
    finish_scn(&mut s, fin, &audit, true);
    s.notes.insert("token", token);
    s
}

fn op_value(line: &Option<String>, key: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(line.as_deref()?).ok()?;
    if v.get("id").and_then(Value::as_str) == Some(key) {
        Some(v["data"].clone())
    } else {
        None
    }
}

fn s11(env: &Env) -> Vec<Scn> {
    let secret = format!("sec-{}", env.nonce);
    let abs = format!("sbx-conf-a-{}", env.nonce);
    let ops_a = vec![
        hello("d.hello"),
        Op::ListenTcp {
            id: "d.listen".into(),
            addr: "127.0.0.1:0".into(),
        },
        Op::ListenAbstract {
            id: "d.abs".into(),
            name: abs.clone(),
        },
        Op::Write {
            id: "d.write".into(),
            path: "/work/a-secret".into(),
            text: secret.clone(),
        },
        Op::Read {
            id: "d.read".into(),
            path: "/work/a-secret".into(),
            needles: vec![secret.clone()],
            max: 4096,
        },
        tcp_addr("d.own", "127.0.0.1:$listen", vec![]),
        Op::UnixConnect {
            id: "d.ownabs".into(),
            path: None,
            abstract_name: Some(abs.clone()),
        },
        dns("d.dns", "a-only.allowed.conformance.test"),
        Op::WaitStdin {
            id: "d.wait".into(),
            timeout_ms: 20000,
        },
    ];
    let text_pol = policies::policy_json(Builtin::Transparent, &env.exe_text, None);
    let mut a = Scn::named("S11a");
    let mut b = Scn::named("S11b");
    let Ok(pol) = policies::write_policy(&env.base, "p-S11", &text_pol) else {
        return vec![
            Scn::unavailable("S11a", "cannot write policy".to_owned()),
            Scn::unavailable("S11b", "cannot write policy".to_owned()),
        ];
    };
    let a_session = env.base.join("s-S11a");
    // The host path of A's secret, from the same layout code the sandbox uses.
    let a_secret_host = crate::bwrap::etc::session_layout(&a_session)
        .work
        .join("a-secret");
    let a_audit = env.base.join("a-S11a.jsonl");
    let mut ra = match SbxRun::new(&env.exe, &pol, &a_session, payload(ops_a, &env.exe_text))
        .audit(&a_audit)
        .stdin_pipe()
        .spawn()
    {
        Ok(r) => r,
        Err(e) => {
            return vec![
                Scn::unavailable("S11a", format!("cannot spawn sbx run: {e}")),
                Scn::unavailable("S11b", "A did not start".to_owned()),
            ];
        }
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let listen = ra.wait_line(expect_token_line("d.listen"), deadline);
    let dns_line = ra.wait_line(expect_token_line("d.dns"), deadline);
    let _ = ra.wait_line(expect_token_line("d.ownabs"), deadline);
    let listen_data = op_value(&listen, "d.listen");
    let dns_data = op_value(&dns_line, "d.dns");
    let a_port = listen_data
        .as_ref()
        .and_then(|d| d["port"].as_u64())
        .unwrap_or(0);
    let a_ip = dns_data
        .as_ref()
        .and_then(|d| d["a"][0].as_str().map(str::to_owned))
        .unwrap_or_default();
    let a_dns_local = dns_data
        .as_ref()
        .and_then(|d| d["local_addr"].as_str().map(str::to_owned))
        .unwrap_or_default();
    a.notes.insert("port", a_port.to_string());
    a.notes.insert("ip", a_ip.clone());
    a.notes.insert("dns_local", a_dns_local);
    a.notes.insert("secret", secret.clone());
    a.notes
        .insert("session", a_session.to_string_lossy().into_owned());
    let b_session = env.base.join("s-S11b");
    let b_audit = env.base.join("a-S11b.jsonl");
    let mut b_fin = None;
    if a_port == 0 || a_ip.is_empty() {
        b.probe_err = Some("A did not report its listener port and fake IP; B not run".to_owned());
    } else {
        let b_ops = vec![
            hello("d.bhello"),
            tcp_addr("d.btcp", &format!("127.0.0.1:{a_port}"), vec![]),
            Op::UnixConnect {
                id: "d.babs".into(),
                path: None,
                abstract_name: Some(abs.clone()),
            },
            Op::Stat {
                id: "d.bstat1".into(),
                path: a_secret_host.to_string_lossy().into_owned(),
            },
            Op::Stat {
                id: "d.bstat2".into(),
                path: "/work/a-secret".into(),
            },
            tcp_addr(
                "d.bfake",
                &format!("{a_ip}:443"),
                vec![
                    send_hello(Some("a-only.allowed.conformance.test")),
                    to_end(),
                ],
            ),
        ];
        if let Ok(mut rb) = SbxRun::new(&env.exe, &pol, &b_session, payload(b_ops, &env.exe_text))
            .audit(&b_audit)
            .spawn()
        {
            b_fin = Some(rb.wait_bounded(Instant::now() + Duration::from_secs(10)));
        } else {
            b.probe_err = Some("cannot spawn sbx run for B".to_owned());
        }
    }
    ra.close_stdin();
    let a_fin = ra.wait_bounded(Instant::now() + Duration::from_secs(10));
    finish_scn(&mut a, a_fin, &a_audit, false);
    // Control for D08: the file really is at the host path B stats (the layout).
    let host_file = if a_secret_host.is_file() {
        Ok(())
    } else {
        Err(format!(
            "A's secret is not at {} on the host",
            a_secret_host.display()
        ))
    };
    a.ctl.insert("d.host-file", host_file);
    if let Some(fin) = b_fin {
        finish_scn(&mut b, fin, &b_audit, false);
    }
    b.notes.insert("a_port", a_port.to_string());
    b.notes.insert("a_ip", a_ip);
    b.notes.insert("abstract", abs);
    b.notes
        .insert("a_session", a_session.to_string_lossy().into_owned());
    vec![a, b]
}

/// The proxy variables an explicit-mode payload receives (H04).
pub const PROXY_VARS: [&str; 8] = [
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

fn s12(env: &Env) -> Vec<Scn> {
    let mut show: Vec<String> = vec![
        "HOME".into(),
        "PATH".into(),
        "TMPDIR".into(),
        "SBX_CONFORMANCE_PASSED".into(),
        "SBX_CONFORMANCE_SET".into(),
    ];
    show.extend(PROXY_VARS.iter().map(|s| (*s).to_owned()));
    let host_home = std::env::var("HOME").unwrap_or_default();
    let mut ops = vec![
        hello("s12.hello"),
        Op::Env {
            id: "h01.env".into(),
            needles: vec![env.secret.clone(), env.passed.clone()],
            show,
        },
        Op::Read {
            id: "h02.environ".into(),
            path: "/proc/1/environ".into(),
            needles: vec![],
            max: 65536,
        },
        Op::Read {
            id: "h02.self".into(),
            path: "/proc/self/environ".into(),
            needles: vec![],
            max: 65536,
        },
        Op::ProcEnvironScan {
            id: "h03.scan".into(),
            needles: vec![env.secret.clone()],
        },
        Op::Fds {
            id: "h05.fds".into(),
        },
        Op::Procs {
            id: "d10.procs".into(),
        },
        Op::Unshare {
            id: "d10.unshare".into(),
            flags: "user".into(),
        },
        Op::Caps {
            id: "d10.caps".into(),
        },
        Op::Read {
            id: "d10.cmdline".into(),
            path: format!("/proc/{}/cmdline", std::process::id()),
            needles: vec!["--conformance".into()],
            max: 65536,
        },
    ];
    let home_ok = !host_home.is_empty()
        && host_home != "/"
        && !["/root", "/work", "/tmp", "/usr", "/etc", "/proc", "/dev"]
            .iter()
            .any(|p| host_home == *p || host_home.starts_with(&format!("{p}/")));
    if home_ok {
        ops.push(Op::Stat {
            id: "h06.home".into(),
            path: host_home.clone(),
        });
        ops.push(Op::Stat {
            id: "h06.ssh".into(),
            path: format!("{host_home}/.ssh"),
        });
    }
    let secret = env.secret.clone();
    let passed = env.passed.clone();
    let mut s = plain(
        env,
        "S12",
        Builtin::Explicit,
        ops,
        Opts {
            extra_env: vec![
                ("SBX_CONFORMANCE_SECRET".into(), secret),
                ("SBX_CONFORMANCE_PASSED".into(), passed),
            ],
            secret_fd: Some(env.secret.clone()),
            ..Default::default()
        },
    );
    s.name = "S12";
    s.notes.insert("home_applicable", home_ok.to_string());
    s.notes.insert("host_home", host_home);
    vec![s]
}
