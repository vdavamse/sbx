//! The in-sandbox probe (issue #13, §7): `sbx __conformance probe [--tag T] OPS`.
//!
//! The probe runs INSIDE a sandbox with only payload privileges and executes a
//! JSON list of operations, printing one JSON line per result. It never judges:
//! evaluators decide pass or fail from the recorded results. This module is
//! both the in-sandbox side (`run_probe`) and the runner-side parser
//! (`ProbeOutput::parse`), so the wire format lives in one place.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{SocketAddr as UnixSockAddr, UnixListener, UnixStream};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use netlink_bindings::{rt_addr, rt_link, rt_route};
use netlink_socket2::NetlinkSocket;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The probe document version.
pub const PROBE_VERSION: u32 = 1;
/// The maximum OPS document size the runner emits.
pub const MAX_OPS_BYTES: usize = 64 * 1024;

const DNS_ID: u16 = 0x5c13;

/// The whole OPS document.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ops {
    pub v: u32,
    pub ops: Vec<Op>,
}

impl Ops {
    /// A document with the given ops (version 1).
    pub fn new(ops: Vec<Op>) -> Self {
        Ops {
            v: PROBE_VERSION,
            ops,
        }
    }
}

fn t2000() -> u64 {
    2000
}
fn t3000() -> u64 {
    3000
}
fn t300() -> u64 {
    300
}
fn q_a() -> String {
    "A".to_owned()
}
fn server_53() -> String {
    "127.0.0.1:53".to_owned()
}
fn default_true() -> bool {
    true
}
fn n5() -> u32 {
    5
}
fn q_text() -> String {
    "Q".to_owned()
}
fn show_default() -> Vec<String> {
    vec!["HOME".into(), "PATH".into(), "TMPDIR".into()]
}
fn max_64k() -> usize {
    65536
}
fn roots_default() -> Vec<String> {
    vec!["/".into()]
}
fn skip_default() -> Vec<String> {
    vec!["/proc".into(), "/dev".into(), "/sys".into()]
}
fn n50000() -> usize {
    50000
}
fn walk_budget_default() -> u64 {
    8000
}
fn n12() -> usize {
    12
}
fn n20000() -> u64 {
    20000
}
fn listen_default() -> String {
    "127.0.0.1:0".to_owned()
}
fn null_stdio() -> String {
    "null".to_owned()
}

/// One operation. Every op has an `id` that names its result.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Hello {
        id: String,
    },
    Dns {
        id: String,
        name: String,
        #[serde(default = "q_a")]
        qtype: String,
        #[serde(default = "server_53")]
        server: String,
        #[serde(default)]
        tcp: bool,
        #[serde(default = "t2000")]
        timeout_ms: u64,
    },
    Tcp {
        id: String,
        target: Target,
        #[serde(default)]
        steps: Vec<Step>,
        #[serde(default = "t2000")]
        connect_timeout_ms: u64,
    },
    Udp {
        id: String,
        addr: String,
        #[serde(default = "q_text")]
        text: String,
        #[serde(default = "n5")]
        attempts: u32,
        #[serde(default = "t300")]
        recv_timeout_ms: u64,
    },
    Socket {
        id: String,
        family: String,
        ty: String,
        #[serde(default)]
        protocol: i32,
    },
    UnixConnect {
        id: String,
        path: Option<String>,
        abstract_name: Option<String>,
    },
    Netlink {
        id: String,
        action: String,
    },
    Links {
        id: String,
    },
    Env {
        id: String,
        #[serde(default)]
        needles: Vec<String>,
        #[serde(default = "show_default")]
        show: Vec<String>,
    },
    Read {
        id: String,
        path: String,
        #[serde(default)]
        needles: Vec<String>,
        #[serde(default = "max_64k")]
        max: usize,
    },
    ProcEnvironScan {
        id: String,
        needles: Vec<String>,
    },
    Fds {
        id: String,
    },
    Stat {
        id: String,
        path: String,
    },
    SocketsWalk {
        id: String,
        #[serde(default = "roots_default")]
        roots: Vec<String>,
        #[serde(default = "skip_default")]
        skip: Vec<String>,
        #[serde(default = "n50000")]
        max_entries: usize,
        #[serde(default = "n12")]
        max_depth: usize,
        /// Wall-clock budget: the walk stops (truncated) when it runs out.
        #[serde(default = "walk_budget_default")]
        budget_ms: u64,
    },
    /// Capability sets of the probe process (`/proc/self/status`).
    Caps {
        id: String,
    },
    Procs {
        id: String,
    },
    Unshare {
        id: String,
        flags: String,
    },
    SpawnBg {
        id: String,
        token: String,
        #[serde(default = "null_stdio")]
        stdio: String,
        #[serde(default = "default_true")]
        ignore_signals: bool,
    },
    Detach {
        id: String,
        #[serde(default = "default_true")]
        ignore_signals: bool,
    },
    Sleep {
        id: String,
        ms: u64,
    },
    WaitStdin {
        id: String,
        #[serde(default = "n20000")]
        timeout_ms: u64,
    },
    ListenTcp {
        id: String,
        #[serde(default = "listen_default")]
        addr: String,
    },
    ListenAbstract {
        id: String,
        name: String,
    },
    Write {
        id: String,
        path: String,
        text: String,
    },
    DnsFlood {
        id: String,
        prefix: String,
        count: u32,
        #[serde(default = "server_53")]
        server: String,
    },
    /// Repeated connect + ClientHello + one-line read (PR2, issue #13). Every
    /// attempt appends `<mono_ms> ok:<line>` or `<mono_ms> err:<kind>` to `log`
    /// (`mono_ms` is CLOCK_MONOTONIC, see [`mono_ms`]).
    /// With `hold_first`, the first successful socket stays open for the loop;
    /// `hold_token` (when set) is sent on it as one TLS application-data record,
    /// so the fixture can pin its record to exactly this connection.
    TcpLoop {
        id: String,
        target: Target,
        sni: String,
        #[serde(default = "tl_interval")]
        interval_ms: u64,
        duration_ms: u64,
        #[serde(default = "t300")]
        attempt_timeout_ms: u64,
        log: String,
        #[serde(default)]
        hold_first: bool,
        #[serde(default)]
        hold_token: String,
    },
}

fn tl_interval() -> u64 {
    100
}

impl Op {
    /// The result id.
    pub fn id(&self) -> &str {
        match self {
            Op::Hello { id }
            | Op::Dns { id, .. }
            | Op::Tcp { id, .. }
            | Op::Udp { id, .. }
            | Op::Socket { id, .. }
            | Op::UnixConnect { id, .. }
            | Op::Netlink { id, .. }
            | Op::Links { id }
            | Op::Env { id, .. }
            | Op::Read { id, .. }
            | Op::ProcEnvironScan { id, .. }
            | Op::Fds { id }
            | Op::Stat { id, .. }
            | Op::SocketsWalk { id, .. }
            | Op::Caps { id }
            | Op::Procs { id }
            | Op::Unshare { id, .. }
            | Op::SpawnBg { id, .. }
            | Op::Detach { id, .. }
            | Op::Sleep { id, .. }
            | Op::WaitStdin { id, .. }
            | Op::ListenTcp { id, .. }
            | Op::ListenAbstract { id, .. }
            | Op::Write { id, .. }
            | Op::DnsFlood { id, .. }
            | Op::TcpLoop { id, .. } => id,
        }
    }

    /// The op name (the `op` field's spelling).
    pub fn name(&self) -> &'static str {
        match self {
            Op::Hello { .. } => "hello",
            Op::Dns { .. } => "dns",
            Op::Tcp { .. } => "tcp",
            Op::Udp { .. } => "udp",
            Op::Socket { .. } => "socket",
            Op::UnixConnect { .. } => "unix_connect",
            Op::Netlink { .. } => "netlink",
            Op::Links { .. } => "links",
            Op::Env { .. } => "env",
            Op::Read { .. } => "read",
            Op::ProcEnvironScan { .. } => "proc_environ_scan",
            Op::Fds { .. } => "fds",
            Op::Stat { .. } => "stat",
            Op::SocketsWalk { .. } => "sockets_walk",
            Op::Caps { .. } => "caps",
            Op::Procs { .. } => "procs",
            Op::Unshare { .. } => "unshare",
            Op::SpawnBg { .. } => "spawn_bg",
            Op::Detach { .. } => "detach",
            Op::Sleep { .. } => "sleep",
            Op::WaitStdin { .. } => "wait_stdin",
            Op::ListenTcp { .. } => "listen_tcp",
            Op::ListenAbstract { .. } => "listen_abstract",
            Op::Write { .. } => "write",
            Op::DnsFlood { .. } => "dns_flood",
            Op::TcpLoop { .. } => "tcp_loop",
        }
    }
}

/// A `tcp` target.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Target {
    /// `{"addr":"ip:port"}`; `$listen` is replaced by the last listen port.
    Addr { addr: String },
    /// `{"name":N,"port":P}`: an A lookup through 127.0.0.1:53.
    Name { name: String, port: u16 },
    /// `{"env_proxy":"HTTPS_PROXY"}`: parse `http://host:port`.
    EnvProxy { env_proxy: String },
}

/// One `tcp` step.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Send(SendSpec),
    Read(ReadSpec),
    ReadHttp(ReadHttpSpec),
    ReadToEnd(ReadToEndSpec),
    SleepMs(u64),
}

/// `send`: literal text or a ClientHello.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SendSpec {
    Hello { hello: HelloSpec },
    Text { text: String },
}

/// A ClientHello to send.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HelloSpec {
    pub sni: Option<String>,
    #[serde(default)]
    pub ech: bool,
}

/// `read`: up to a delimiter (or one read when `until` is null).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadSpec {
    pub until: Option<String>,
    #[serde(default = "max_64k")]
    pub max: usize,
    #[serde(default = "t3000")]
    pub timeout_ms: u64,
}

/// `read_http`: a head plus its Content-Length body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadHttpSpec {
    #[serde(default = "t3000")]
    pub timeout_ms: u64,
}

/// `read_to_end`: until EOF, the cap or the timeout.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadToEndSpec {
    #[serde(default = "max_64k")]
    pub max: usize,
    #[serde(default = "t3000")]
    pub timeout_ms: u64,
}

/// One result line (`OpResult`), in the probe's own output.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct OpResult {
    pub id: String,
    pub op: String,
    pub t_ms: u64,
    pub ok: bool,
    pub errno: Option<i32>,
    pub detail: String,
    pub data: Value,
}

/// The mutable state of one probe run.
#[derive(Default)]
struct State {
    listen_port: Option<u16>,
    tcp_listeners: Vec<TcpListener>,
    unix_listeners: Vec<UnixListener>,
    /// Stdin read state for `wait_stdin` (kept for the probe's lifetime).
    stdin_eof: bool,
}

/// Monotonic milliseconds (`CLOCK_MONOTONIC`). Every timing comparison in the
/// lab uses this clock: it is shared by every process on the host (bwrap runs
/// no time namespace) and it never jumps backwards, unlike `CLOCK_REALTIME`.
pub fn mono_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into the valid, local timespec only.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// Unix time in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// First source port of the per-run allocator. The range sits below Linux's
/// default ephemeral range (32768-60999), so the kernel never picks one of
/// these for an unbound socket.
const SRC_PORT_BASE: u16 = 20_000;
const SRC_PORT_LAST: u16 = 32_000;
static NEXT_SRC_PORT: std::sync::atomic::AtomicU16 =
    std::sync::atomic::AtomicU16::new(SRC_PORT_BASE);

/// Connect with a source port unique to this probe process (issue #13 review).
///
/// Why: in transparent mode every leg of one `sbx run` reaches the proxy from
/// the same sandbox address to the same listener. When two legs reuse an
/// ephemeral port, conntrack rewrites the later leg's source port on the reply
/// tuple collision, so the audit row carries a port the probe never had. A
/// unique port per leg means no two reply tuples can collide.
///
/// IPv4 only (the audit rows the checks pin are IPv4); other families use a
/// plain connect. A bind collision (`EADDRINUSE`) retries with the next port.
pub(crate) fn dial(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let SocketAddr::V4(v4) = addr else {
        return TcpStream::connect_timeout(&addr, timeout);
    };
    let mut last = io::Error::new(io::ErrorKind::AddrInUse, "no free source port");
    for _ in 0..16 {
        let port = NEXT_SRC_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if port > SRC_PORT_LAST {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "the probe ran out of source ports",
            ));
        }
        match dial_from(v4, port, timeout) {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => last = e,
            other => return other,
        }
    }
    Err(last)
}

fn dial_from(dst: std::net::SocketAddrV4, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: plain socket(2)/bind(2)/setsockopt(2)/connect(2) on a fresh fd we
    // own (wrapped in OwnedFd straight away); every sockaddr is a local,
    // fully-initialised struct whose size is passed along.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let mut src: libc::sockaddr_in = std::mem::zeroed();
        src.sin_family = libc::AF_INET as libc::sa_family_t;
        src.sin_port = port.to_be();
        if libc::bind(
            fd,
            &src as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let mut dst_sa: libc::sockaddr_in = std::mem::zeroed();
        dst_sa.sin_family = libc::AF_INET as libc::sa_family_t;
        dst_sa.sin_port = dst.port().to_be();
        dst_sa.sin_addr.s_addr = u32::from_ne_bytes(dst.ip().octets());
        if libc::connect(
            fd,
            &dst_sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(TcpStream::from(owned))
    }
}

fn errno_of(e: &io::Error) -> Option<i32> {
    e.raw_os_error()
}

fn ok_result(
    id: &str,
    op: &str,
    ok: bool,
    errno: Option<i32>,
    detail: String,
    data: Value,
) -> OpResult {
    OpResult {
        id: id.to_owned(),
        op: op.to_owned(),
        t_ms: now_ms(),
        ok,
        errno,
        detail,
        data,
    }
}

/// `sbx __conformance probe [--tag TAG] OPS` (rc 0; rc 3 on a bad document).
pub fn run_probe(tag: Option<&str>, ops_json: &str) -> ExitCode {
    let _ = tag; // present only so the argv carries an exact token for /proc scans
    let doc: Ops = match serde_json::from_str(ops_json) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", json!({"error": format!("bad OPS document: {e}")}));
            return ExitCode::from(3);
        }
    };
    if doc.ops.iter().any(destructive) && !inside_sandbox() {
        println!(
            "{}",
            json!({"error": "refused: network-changing or file-writing ops run only inside an sbx sandbox"})
        );
        return ExitCode::from(4);
    }
    if doc.v != PROBE_VERSION {
        println!(
            "{}",
            json!({"error": format!("unsupported OPS version {}", doc.v)})
        );
        return ExitCode::from(3);
    }
    let stdout = io::stdout();
    let emit = |value: Value| {
        let mut out = stdout.lock();
        let _ = writeln!(out, "{value}");
        let _ = out.flush();
    };
    emit(
        json!({"probe": PROBE_VERSION, "sbx_version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(), "t_ms": now_ms()}),
    );
    let mut st = State::default();
    for op in &doc.ops {
        let res = execute(op, &mut st);
        emit(serde_json::to_value(&res).unwrap_or(Value::Null));
    }
    emit(json!({"done": true, "t_ms": now_ms()}));
    ExitCode::SUCCESS
}

/// Ops that change the network namespace or write files.
fn destructive(op: &Op) -> bool {
    match op {
        Op::Netlink { action, .. } => action != "dump_links",
        Op::Write { .. } => true,
        _ => false,
    }
}

/// True inside an sbx sandbox: the network namespace holds only `lo`, and the
/// user namespace is not the initial one (its uid_map is not the identity map).
/// A host, or any process outside a user namespace, is never inside.
pub fn inside_sandbox() -> bool {
    let map = fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let fields: Vec<&str> = map.split_whitespace().collect();
    let identity = fields == ["0", "0", "4294967295"];
    !fields.is_empty() && !identity && link_names() == ["lo"]
}

fn execute(op: &Op, st: &mut State) -> OpResult {
    let id = op.id().to_owned();
    let name = op.name();
    match op {
        Op::Hello { .. } => ok_result(
            &id,
            name,
            true,
            None,
            "probe alive".into(),
            json!({"version": env!("CARGO_PKG_VERSION")}),
        ),
        Op::Dns {
            name: qname,
            qtype,
            server,
            tcp,
            timeout_ms,
            ..
        } => {
            match dns_query_at(
                qname,
                qtype,
                server,
                *tcp,
                Duration::from_millis(*timeout_ms),
            ) {
                Ok((msg, local)) => {
                    let rcode = u16::from(msg.response_code());
                    let a: Vec<String> = msg
                        .answers()
                        .iter()
                        .filter_map(|r| match r.data() {
                            RData::A(a) => Some(a.0.to_string()),
                            _ => None,
                        })
                        .collect();
                    let n = msg.answers().len();
                    ok_result(
                        &id,
                        name,
                        true,
                        None,
                        format!("rcode {rcode}, {n} answers"),
                        json!({"rcode": rcode, "a": a, "answers": n, "local_addr": local}),
                    )
                }
                Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
            }
        }
        Op::Tcp {
            target,
            steps,
            connect_timeout_ms,
            ..
        } => run_tcp(&id, target, steps, *connect_timeout_ms, st),
        Op::Udp {
            addr,
            text,
            attempts,
            recv_timeout_ms,
            ..
        } => run_udp(&id, addr, text, *attempts, *recv_timeout_ms),
        Op::Socket {
            family,
            ty,
            protocol,
            ..
        } => socket_op(&id, family, ty, *protocol),
        Op::UnixConnect {
            path,
            abstract_name,
            ..
        } => {
            let r = match (path, abstract_name) {
                (Some(p), _) => UnixStream::connect(p).map(|_| ()),
                (None, Some(n)) => match UnixSockAddr::from_abstract_name(n) {
                    Ok(a) => UnixStream::connect_addr(&a).map(|_| ()),
                    Err(e) => Err(e),
                },
                (None, None) => Err(io::Error::from_raw_os_error(libc::EINVAL)),
            };
            match r {
                Ok(()) => ok_result(&id, name, true, None, "connected".into(), json!({})),
                Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
            }
        }
        Op::Netlink { action, .. } => netlink_op(&id, action),
        Op::Links { .. } => {
            let names = link_names();
            let dis = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
                .ok()
                .map(|s| s.trim().to_owned());
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{} links", names.len()),
                json!({"names": names, "disable_ipv6": dis}),
            )
        }
        Op::Env { needles, show, .. } => {
            let mut names: Vec<String> = Vec::new();
            let mut values: BTreeMap<String, String> = BTreeMap::new();
            let mut matched: Vec<usize> = Vec::new();
            let vars: Vec<(String, String)> = std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
                .collect();
            for (k, v) in &vars {
                names.push(k.clone());
                if show.iter().any(|s| s == k) {
                    values.insert(k.clone(), v.clone());
                }
            }
            names.sort();
            for (i, needle) in needles.iter().enumerate() {
                if vars
                    .iter()
                    .any(|(_, v)| !needle.is_empty() && v.contains(needle.as_str()))
                {
                    matched.push(i);
                }
            }
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{} variables", names.len()),
                json!({"names": names, "matched": matched, "values": values}),
            )
        }
        Op::Read {
            path, needles, max, ..
        } => match read_capped(path, *max) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let matched: Vec<usize> = needles
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| !n.is_empty() && text.contains(n.as_str()))
                    .map(|(i, _)| i)
                    .collect();
                ok_result(
                    &id,
                    name,
                    true,
                    None,
                    format!("read {} bytes", bytes.len()),
                    json!({"len": bytes.len(), "matched": matched}),
                )
            }
            Err(e) => ok_result(
                &id,
                name,
                false,
                errno_of(&e),
                e.to_string(),
                json!({"len": 0, "matched": []}),
            ),
        },
        Op::ProcEnvironScan { needles, .. } => {
            let (mut readable, mut unreadable) = (0u64, 0u64);
            let mut matched_pids: Vec<u32> = Vec::new();
            if let Ok(dir) = fs::read_dir("/proc") {
                for e in dir.flatten() {
                    let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    match fs::read(format!("/proc/{pid}/environ")) {
                        Ok(bytes) => {
                            readable += 1;
                            let text = String::from_utf8_lossy(&bytes);
                            if needles
                                .iter()
                                .any(|n| !n.is_empty() && text.contains(n.as_str()))
                            {
                                matched_pids.push(pid);
                            }
                        }
                        Err(_) => unreadable += 1,
                    }
                }
            }
            matched_pids.sort();
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{readable} readable"),
                json!({"readable": readable, "unreadable": unreadable, "matched_pids": matched_pids}),
            )
        }
        Op::Fds { .. } => {
            let own = format!("/proc/{}/fd", std::process::id());
            let mut fds: Vec<i32> = Vec::new();
            if let Ok(dir) = fs::read_dir("/proc/self/fd") {
                for e in dir.flatten() {
                    let target = fs::read_link(e.path())
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if target == own {
                        continue; // the directory handle read_dir itself holds
                    }
                    if let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
                        fds.push(n);
                    }
                }
            }
            fds.sort();
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{} fds", fds.len()),
                json!({"fds": fds}),
            )
        }
        Op::Stat { path, .. } => match fs::symlink_metadata(path) {
            Ok(m) => {
                let ft = m.file_type();
                let kind = if ft.is_symlink() {
                    "symlink"
                } else if ft.is_socket() {
                    "socket"
                } else if ft.is_dir() {
                    "dir"
                } else if ft.is_file() {
                    "file"
                } else {
                    "other"
                };
                ok_result(
                    &id,
                    name,
                    true,
                    None,
                    format!("kind {kind}"),
                    json!({"kind": kind}),
                )
            }
            Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
        },
        Op::SocketsWalk {
            roots,
            skip,
            max_entries,
            max_depth,
            budget_ms,
            ..
        } => {
            let (found, visited, truncated) = sockets_walk(
                roots,
                skip,
                *max_entries,
                *max_depth,
                Duration::from_millis(*budget_ms),
            );
            let shown: Vec<String> = found.iter().take(20).cloned().collect();
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{} socket files, {visited} entries visited", found.len()),
                json!({"found": shown, "visited": visited, "truncated": truncated}),
            )
        }
        Op::Caps { .. } => {
            let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
            let cap = |key: &str| -> String {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned()))
                    .unwrap_or_default()
            };
            let (eff, prm, bnd) = (cap("CapEff:"), cap("CapPrm:"), cap("CapBnd:"));
            ok_result(
                &id,
                name,
                !eff.is_empty(),
                None,
                format!("CapEff {eff} CapPrm {prm} CapBnd {bnd}"),
                json!({"eff": eff, "prm": prm, "bnd": bnd}),
            )
        }
        Op::Procs { .. } => {
            let mut pids: Vec<u32> = fs::read_dir("/proc")
                .map(|d| {
                    d.flatten()
                        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
                        .collect()
                })
                .unwrap_or_default();
            pids.sort();
            let pid1 = fs::read_to_string("/proc/1/comm")
                .map(|s| s.trim().to_owned())
                .unwrap_or_default();
            ok_result(
                &id,
                name,
                true,
                None,
                format!("{} pids", pids.len()),
                json!({"pids": pids, "pid1_comm": pid1, "self_pid": std::process::id()}),
            )
        }
        Op::Unshare { flags, .. } => {
            let flag = match flags.as_str() {
                "user" => libc::CLONE_NEWUSER,
                _ => libc::CLONE_NEWUSER,
            };
            let rc = unsafe { libc::unshare(flag) };
            if rc == 0 {
                ok_result(&id, name, true, None, "unshare succeeded".into(), json!({}))
            } else {
                let e = io::Error::last_os_error();
                ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({}))
            }
        }
        Op::SpawnBg {
            token,
            stdio,
            ignore_signals,
            ..
        } => {
            let ops = json!({"v": 1, "ops": [
                {"op": "detach", "id": "d", "ignore_signals": ignore_signals},
                {"op": "sleep", "id": "s", "ms": 600000}
            ]});
            let mut cmd = Command::new("/proc/self/exe");
            cmd.arg("__conformance")
                .arg("probe")
                .arg("--tag")
                .arg(token)
                .arg(ops.to_string())
                .stdin(Stdio::null());
            if stdio == "inherit" {
                cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            } else {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id();
                    drop(child); // never waited: the background process outlives this probe
                    ok_result(
                        &id,
                        name,
                        true,
                        None,
                        format!("spawned pid {pid}"),
                        json!({"pid": pid}),
                    )
                }
                Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
            }
        }
        Op::Detach { ignore_signals, .. } => {
            let sid = unsafe { libc::setsid() };
            if *ignore_signals {
                for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT, libc::SIGQUIT] {
                    unsafe { libc::signal(sig, libc::SIG_IGN) };
                }
            }
            ok_result(
                &id,
                name,
                sid > 0,
                None,
                format!("setsid {sid}"),
                json!({"sid": sid}),
            )
        }
        Op::Sleep { ms, .. } => {
            std::thread::sleep(Duration::from_millis(*ms));
            ok_result(&id, name, true, None, format!("slept {ms} ms"), json!({}))
        }
        Op::WaitStdin { timeout_ms, .. } => {
            let eof = wait_stdin_eof(Duration::from_millis(*timeout_ms));
            st.stdin_eof = eof;
            ok_result(
                &id,
                name,
                eof,
                None,
                if eof {
                    "stdin closed".into()
                } else {
                    "timeout".into()
                },
                json!({"eof": eof}),
            )
        }
        Op::ListenTcp { addr, .. } => match TcpListener::bind(addr.as_str()) {
            Ok(l) => {
                let port = l.local_addr().map(|a| a.port()).unwrap_or(0);
                st.listen_port = Some(port);
                st.tcp_listeners.push(l);
                ok_result(
                    &id,
                    name,
                    true,
                    None,
                    format!("listening on port {port}"),
                    json!({"port": port}),
                )
            }
            Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
        },
        Op::ListenAbstract { name: n, .. } => {
            let r = UnixSockAddr::from_abstract_name(n).and_then(|a| UnixListener::bind_addr(&a));
            match r {
                Ok(l) => {
                    st.unix_listeners.push(l);
                    ok_result(&id, name, true, None, "listening".into(), json!({}))
                }
                Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
            }
        }
        Op::Write { path, text, .. } => match fs::write(path, text) {
            Ok(()) => ok_result(&id, name, true, None, "written".into(), json!({})),
            Err(e) => ok_result(&id, name, false, errno_of(&e), e.to_string(), json!({})),
        },
        Op::TcpLoop {
            target,
            sni,
            interval_ms,
            duration_ms,
            attempt_timeout_ms,
            log,
            hold_first,
            hold_token,
            ..
        } => run_tcp_loop(
            &id,
            &LoopSpec {
                target,
                sni,
                interval_ms: *interval_ms,
                duration_ms: *duration_ms,
                attempt_timeout_ms: *attempt_timeout_ms,
                log,
                hold_first: *hold_first,
                hold_token: hold_token.clone(),
            },
            st,
        ),
        Op::DnsFlood {
            prefix,
            count,
            server,
            ..
        } => {
            let mut sent = 0u32;
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = sock.connect(server.as_str());
                let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
                for i in 0..*count {
                    let qname = format!("{prefix}-{i}.other.conformance.test");
                    let Ok(name_v) = Name::from_ascii(&qname) else {
                        continue;
                    };
                    let mut m = Message::new();
                    m.set_id(DNS_ID)
                        .set_recursion_desired(true)
                        .add_query(Query::query(name_v, RecordType::A));
                    if let Ok(bytes) = m.to_vec() {
                        if sock.send(&bytes).is_ok() {
                            sent += 1;
                        }
                    }
                    let mut buf = [0u8; 512];
                    let _ = sock.recv(&mut buf);
                }
            }
            ok_result(
                &id,
                name,
                true,
                None,
                format!("sent {sent} queries"),
                json!({"sent": sent}),
            )
        }
    }
}

/// One DNS query over UDP or TCP to `server`.
fn dns_query(
    qname: &str,
    qtype: &str,
    server: &str,
    tcp: bool,
    timeout: Duration,
) -> io::Result<Message> {
    dns_query_at(qname, qtype, server, tcp, timeout).map(|(m, _)| m)
}

/// One DNS query, also reporting the local source address (the audit `client`).
fn dns_query_at(
    qname: &str,
    qtype: &str,
    server: &str,
    tcp: bool,
    timeout: Duration,
) -> io::Result<(Message, String)> {
    let name = Name::from_ascii(qname)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let rtype = match qtype {
        "AAAA" => RecordType::AAAA,
        "TXT" => RecordType::TXT,
        "MX" => RecordType::MX,
        _ => RecordType::A,
    };
    let mut m = Message::new();
    m.set_id(DNS_ID)
        .set_recursion_desired(true)
        .add_query(Query::query(name, rtype));
    let bytes = m
        .to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let decode = |raw: &[u8]| {
        Message::from_vec(raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    };
    if tcp {
        let addr: SocketAddr = server.parse().map_err(|e: std::net::AddrParseError| {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;
        let mut s = dial(addr, timeout)?;
        let local = s.local_addr().map(|a| a.to_string()).unwrap_or_default();
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        s.write_all(&framed)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len)?;
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut body)?;
        decode(&body).map(|m| (m, local))
    } else {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(timeout))?;
        sock.connect(server)?;
        let local = sock.local_addr().map(|a| a.to_string()).unwrap_or_default();
        sock.send(&bytes)?;
        let mut buf = vec![0u8; 4096];
        let n = sock.recv(&mut buf)?;
        decode(&buf[..n]).map(|m| (m, local))
    }
}

/// Resolve an A record through the local fake DNS (127.0.0.1:53).
pub fn resolve_a(name: &str) -> io::Result<Ipv4Addr> {
    let msg = dns_query(name, "A", "127.0.0.1:53", false, Duration::from_secs(2))?;
    msg.answers()
        .iter()
        .find_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no A record for {name}")))
}

/// The fields of one `tcp_loop` op (keeps `run_tcp_loop` within clippy's arity).
struct LoopSpec<'a> {
    target: &'a Target,
    sni: &'a str,
    interval_ms: u64,
    duration_ms: u64,
    attempt_timeout_ms: u64,
    log: &'a str,
    hold_first: bool,
    hold_token: String,
}

/// `tcp_loop`: attempts until the duration ends (see [`Op::TcpLoop`]).
fn run_tcp_loop(id: &str, spec: &LoopSpec<'_>, st: &State) -> OpResult {
    let fail = |e: io::Error, what: String| {
        ok_result(
            id,
            "tcp_loop",
            false,
            errno_of(&e),
            what,
            json!({"attempts": 0, "ok": 0}),
        )
    };
    let addr = match resolve_target(spec.target, st) {
        Ok(a) => a,
        Err(e) => {
            let what = e.to_string();
            return fail(e, what);
        }
    };
    let mut log = match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(spec.log)
    {
        Ok(f) => f,
        Err(e) => {
            let what = format!("open {}: {e}", spec.log);
            return fail(e, what);
        }
    };
    let hello = crate::proxy::hello::build_client_hello(Some(spec.sni), &[]);
    let timeout = Duration::from_millis(spec.attempt_timeout_ms);
    let end = Instant::now() + Duration::from_millis(spec.duration_ms);
    let (mut attempts, mut oks) = (0u64, 0u64);
    let mut held: Option<TcpStream> = None;
    while Instant::now() < end {
        attempts += 1;
        let keep = spec.hold_first && held.is_none();
        let (status, kept) = loop_attempt(addr, &hello, timeout, keep, spec.hold_token.as_bytes());
        if status.starts_with("ok:") {
            oks += 1;
        }
        if held.is_none() {
            held = kept;
        }
        let _ = log.write_all(format!("{} {status}\n", mono_ms()).as_bytes());
        std::thread::sleep(Duration::from_millis(spec.interval_ms));
    }
    ok_result(
        id,
        "tcp_loop",
        attempts > 0,
        None,
        format!("{attempts} attempts, {oks} ok"),
        json!({"attempts": attempts, "ok": oks}),
    )
}

/// One `tcp_loop` attempt: connect, ClientHello, one line back. The socket is
/// returned only when `keep` is set and the attempt succeeded.
fn loop_attempt(
    addr: SocketAddr,
    hello: &[u8],
    timeout: Duration,
    keep: bool,
    hold_token: &[u8],
) -> (String, Option<TcpStream>) {
    let mut s = match dial(addr, timeout) {
        Ok(s) => s,
        Err(e) => return (format!("err:{:?}", e.kind()), None),
    };
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    if let Err(e) = s.write_all(hello) {
        return (format!("err:{:?}", e.kind()), None);
    }
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > 512 {
                    break;
                }
            }
            Err(e) => return (format!("err:{:?}", e.kind()), None),
        }
    }
    if line.is_empty() {
        return ("err:eof".to_owned(), None);
    }
    let text = String::from_utf8_lossy(&line).trim_end().to_owned();
    if keep && !hold_token.is_empty() {
        // The held connection's own marker: a valid TLS application-data record.
        if s.write_all(&tls_app_record(hold_token)).is_err() {
            return ("err:hold-token".to_owned(), None);
        }
    }
    let kept = keep.then_some(s);
    (format!("ok:{text}"), kept)
}

/// One TLS application-data record (version 3.3) carrying `payload`.
fn tls_app_record(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x17, 0x03, 0x03];
    v.extend((payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// The address a `tcp` or `tcp_loop` target names (a name is resolved through
/// the sandbox's own fake DNS, as the `dns` op does).
fn resolve_target(target: &Target, st: &State) -> io::Result<SocketAddr> {
    match target {
        Target::Addr { addr } => {
            let text = subst_listen(addr, st.listen_port);
            text.parse::<SocketAddr>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
        }
        Target::Name { name, port } => {
            resolve_a(name).map(|ip| SocketAddr::new(IpAddr::V4(ip), *port))
        }
        Target::EnvProxy { env_proxy } => std::env::var(env_proxy)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("{env_proxy}: {e}")))
            .and_then(|v| {
                let hostport = v
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_owned();
                hostport
                    .parse::<SocketAddr>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
            }),
    }
}

fn run_tcp(
    id: &str,
    target: &Target,
    steps: &[Step],
    connect_timeout_ms: u64,
    st: &State,
) -> OpResult {
    let resolved = resolve_target(target, st);
    let addr = match resolved {
        Ok(a) => a,
        Err(e) => {
            return ok_result(
                id,
                "tcp",
                false,
                errno_of(&e),
                e.to_string(),
                json!({"connected": false, "resolved": null, "reads": [], "write_errno": null}),
            );
        }
    };
    let mut stream = match dial(addr, Duration::from_millis(connect_timeout_ms)) {
        Ok(s) => s,
        Err(e) => {
            let detail = format!("connect {addr}: {e}");
            return ok_result(
                id,
                "tcp",
                false,
                errno_of(&e),
                detail,
                json!({"connected": false, "resolved": addr.to_string(), "reads": [], "write_errno": null}),
            );
        }
    };
    let local = stream
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let mut reads: Vec<Value> = Vec::new();
    let mut write_errno: Option<i32> = None;
    for step in steps {
        match step {
            Step::Send(SendSpec::Text { text }) => {
                if let Err(e) = stream.write_all(text.as_bytes()) {
                    write_errno = errno_of(&e);
                    break;
                }
            }
            Step::Send(SendSpec::Hello { hello }) => {
                let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
                if hello.ech {
                    exts.push((0xfe0d, ECH_GREASE.to_vec()));
                }
                let bytes = crate::proxy::hello::build_client_hello(hello.sni.as_deref(), &exts);
                if let Err(e) = stream.write_all(&bytes) {
                    write_errno = errno_of(&e);
                    break;
                }
            }
            Step::Read(spec) => reads.push(read_until(&mut stream, spec)),
            Step::ReadHttp(spec) => reads.push(read_http(&mut stream, spec.timeout_ms)),
            Step::ReadToEnd(spec) => {
                reads.push(read_to_end(&mut stream, spec.max, spec.timeout_ms))
            }
            Step::SleepMs(ms) => std::thread::sleep(Duration::from_millis(*ms)),
        }
    }
    let ok = true;
    let detail = format!("connected {addr}, {} reads", reads.len());
    ok_result(
        id,
        "tcp",
        ok,
        None,
        detail,
        json!({"connected": true, "resolved": addr.to_string(), "local_addr": local, "reads": reads, "write_errno": write_errno}),
    )
}

/// The pinned 41-byte GREASE ECH payload (a fixed, non-secret blob).
/// The GREASE-ECH extension body the B08 check offers: a well-formed outer
/// ECHClientHello (type 0, HKDF-SHA256/AES-128-GCM, config id 1, a 32-byte
/// enc, a 16-byte payload). The PR1 filler (41 bytes of 0x5c) is not a
/// well-formed ECH body: the proxy's parser then rejects the whole hello as
/// malformed, and B08 would no longer test the "offers ECH" rule.
pub const ECH_GREASE: [u8; 58] = {
    let mut b = [0x22u8; 58];
    b[0] = 0x00; // ECHClientHelloType: outer
    b[1] = 0x00;
    b[2] = 0x01; // kdf: HKDF-SHA256
    b[3] = 0x00;
    b[4] = 0x01; // aead: AES-128-GCM
    b[5] = 0x01; // config_id
    b[6] = 0x00;
    b[7] = 0x20; // enc length 32
    let mut k = 8;
    while k < 40 {
        b[k] = 0x11;
        k += 1;
    }
    b[40] = 0x00;
    b[41] = 0x10; // payload length 16
    b
};

fn lossy(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.chars().count() > 512 {
        s.chars().take(512).collect()
    } else {
        s.into_owned()
    }
}

fn read_capped(path: &str, max: usize) -> io::Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::new();
    Read::take(&mut f, max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_end_kind(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => "reset",
        _ => "error",
    }
}

fn read_until(stream: &mut TcpStream, spec: &ReadSpec) -> Value {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(spec.timeout_ms)));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let end: &str = loop {
        if let Some(delim) = &spec.until {
            if !delim.is_empty() && String::from_utf8_lossy(&buf).contains(delim.as_str()) {
                break "data";
            }
        }
        if buf.len() >= spec.max {
            break "data";
        }
        match stream.read(&mut chunk) {
            Ok(0) => break if buf.is_empty() { "eof" } else { "data" },
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if spec.until.is_none() {
                    break "data";
                }
            }
            Err(e) => {
                break if buf.is_empty() {
                    read_end_kind(&e)
                } else {
                    "data"
                };
            }
        }
    };
    json!({"len": buf.len(), "text": lossy(&buf), "end": end})
}

fn read_http(stream: &mut TcpStream, timeout_ms: u64) -> Value {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    let mut end = "data";
    // Head: up to the blank line.
    while !buf.ends_with(b"\r\n\r\n") && buf.len() < 65536 {
        match stream.read(&mut byte) {
            Ok(0) => {
                end = "eof";
                break;
            }
            Ok(_) => buf.push(byte[0]),
            Err(e) => {
                end = read_end_kind(&e);
                break;
            }
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let clen: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = vec![0u8; clen.min(65536)];
    let mut got = 0;
    while got < body.len() {
        match stream.read(&mut body[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => break,
        }
    }
    buf.extend_from_slice(&body[..got]);
    json!({"len": buf.len(), "text": lossy(&buf), "end": end})
}

fn read_to_end(stream: &mut TcpStream, max: usize, timeout_ms: u64) -> Value {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if buf.len() >= max {
            break "data";
        }
        match stream.read(&mut chunk) {
            Ok(0) => break "eof",
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                break if buf.is_empty() {
                    read_end_kind(&e)
                } else {
                    "data"
                };
            }
        }
    };
    json!({"len": buf.len(), "text": lossy(&buf), "end": end})
}

fn run_udp(id: &str, addr: &str, text: &str, attempts: u32, recv_timeout_ms: u64) -> OpResult {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => return ok_result(id, "udp", false, errno_of(&e), e.to_string(), json!({})),
    };
    if let Err(e) = sock.connect(addr) {
        return ok_result(id, "udp", false, errno_of(&e), e.to_string(), json!({}));
    }
    let _ = sock.set_read_timeout(Some(Duration::from_millis(recv_timeout_ms)));
    let (mut send_errno, mut recv_errno, mut reply_len) = (None, None, None);
    for _ in 0..attempts {
        if let Err(e) = sock.send(text.as_bytes()) {
            send_errno = errno_of(&e);
            break;
        }
        let mut buf = [0u8; 2048];
        match sock.recv(&mut buf) {
            Ok(n) => {
                reply_len = Some(n);
                break;
            }
            Err(e) => {
                recv_errno = errno_of(&e);
                if recv_errno == Some(libc::ECONNREFUSED) {
                    break;
                }
            }
        }
    }
    let ok = send_errno.is_none();
    ok_result(
        id,
        "udp",
        ok,
        send_errno,
        format!("send {send_errno:?} recv {recv_errno:?}"),
        json!({"send_errno": send_errno, "recv_errno": recv_errno, "reply_len": reply_len}),
    )
}

fn socket_op(id: &str, family: &str, ty: &str, protocol: i32) -> OpResult {
    let fam = match family {
        "inet" => libc::AF_INET,
        "inet6" => libc::AF_INET6,
        "unix" => libc::AF_UNIX,
        "netlink" => libc::AF_NETLINK,
        "packet" => libc::AF_PACKET,
        "xdp" => 44,
        "vsock" => 40,
        _ => libc::AF_UNSPEC,
    };
    let kind = match ty {
        "stream" => libc::SOCK_STREAM,
        "dgram" => libc::SOCK_DGRAM,
        "raw" => libc::SOCK_RAW,
        "seqpacket" => libc::SOCK_SEQPACKET,
        _ => 0,
    };
    let fd = unsafe { libc::socket(fam, kind, protocol) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        ok_result(
            id,
            "socket",
            true,
            None,
            "created".into(),
            json!({"created": true}),
        )
    } else {
        let e = io::Error::last_os_error();
        ok_result(
            id,
            "socket",
            false,
            errno_of(&e),
            e.to_string(),
            json!({"created": false}),
        )
    }
}

fn if_index(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const IFF_UP_FLAG: u32 = libc::IFF_UP as u32;

fn netlink_op(id: &str, action: &str) -> OpResult {
    let lo = if_index("lo").unwrap_or(1);
    let mut sock = NetlinkSocket::new();
    let errno: Option<i32> = match action {
        "lo_down" => {
            let req = rt_link::Request::new().op_newlink_do(&rt_link::Ifinfomsg {
                ifi_index: lo as i32,
                ifi_flags: 0,
                ifi_change: IFF_UP_FLAG,
                ..Default::default()
            });
            match sock.request(&req) {
                Err(e) => e.raw_os_error(),
                Ok(mut r) => match r.recv_ack() {
                    Ok(()) => None,
                    Err(e) => e.as_io_error().raw_os_error(),
                },
            }
        }
        "addr_add" => {
            let ip = Ipv4Addr::new(10, 9, 9, 9);
            let mut req = rt_addr::Request::new()
                .set_create()
                .set_excl()
                .op_newaddr_do(&rt_addr::Ifaddrmsg {
                    ifa_family: libc::AF_INET as u8,
                    ifa_prefixlen: 32,
                    ifa_flags: 0,
                    ifa_scope: RT_SCOPE_UNIVERSE,
                    ifa_index: lo,
                });
            req.encode()
                .push_address(IpAddr::V4(ip))
                .push_local(IpAddr::V4(ip));
            match sock.request(&req) {
                Err(e) => e.raw_os_error(),
                Ok(mut r) => match r.recv_ack() {
                    Ok(()) => None,
                    Err(e) => e.as_io_error().raw_os_error(),
                },
            }
        }
        "route_del_default" => {
            let mut req = rt_route::Request::new().op_delroute_do(&rt_route::Rtmsg {
                rtm_family: libc::AF_INET as u8,
                rtm_dst_len: 0,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: RT_TABLE_MAIN,
                rtm_protocol: RTPROT_BOOT,
                rtm_scope: RT_SCOPE_LINK,
                rtm_type: RTN_UNICAST,
                rtm_flags: 0,
            });
            req.encode().push_oif(lo);
            match sock.request(&req) {
                Err(e) => e.raw_os_error(),
                Ok(mut r) => match r.recv_ack() {
                    Ok(()) => None,
                    Err(e) => e.as_io_error().raw_os_error(),
                },
            }
        }
        _ => {
            // dump_links: a real RTM_GETLINK dump; the names prove the socket works.
            let req = rt_link::Request::new().op_getlink_dump(&rt_link::Ifinfomsg::default());
            let mut names: Vec<String> = Vec::new();
            let res: Result<(), i32> = match sock.request(&req) {
                Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
                Ok(mut iter) => {
                    let mut out = Ok(());
                    while let Some(item) = iter.recv() {
                        match item {
                            Ok((_hdr, attrs)) => {
                                if let Ok(n) = attrs.get_ifname() {
                                    names.push(n.to_string_lossy().into_owned());
                                }
                            }
                            Err(e) => {
                                out = Err(e.as_io_error().raw_os_error().unwrap_or(libc::EIO));
                                break;
                            }
                        }
                    }
                    out
                }
            };
            return match res {
                Ok(()) => ok_result(
                    id,
                    "netlink",
                    true,
                    None,
                    format!("links {names:?}"),
                    json!({"names": names}),
                ),
                Err(code) => ok_result(
                    id,
                    "netlink",
                    false,
                    Some(code),
                    format!("dump errno {code}"),
                    json!({"names": []}),
                ),
            };
        }
    };
    let ok = errno.is_none();
    ok_result(
        id,
        "netlink",
        ok,
        errno,
        format!("{action}: {errno:?}"),
        json!({}),
    )
}

fn link_names() -> Vec<String> {
    let text = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    text.lines()
        .skip(2)
        .filter_map(|l| l.split(':').next().map(|s| s.trim().to_owned()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn wait_stdin_eof(timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    let fd = io::stdin().as_raw_fd();
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let left = (deadline - now).as_millis().min(1000) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, left) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if rc == 0 {
            continue;
        }
        match io::stdin().lock().read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

/// The directory walk: never follows symlinks, crosses mounts, bounded.
fn sockets_walk(
    roots: &[String],
    skip: &[String],
    max_entries: usize,
    max_depth: usize,
    budget: Duration,
) -> (Vec<String>, usize, bool) {
    let started = std::time::Instant::now();
    let mut found: Vec<String> = Vec::new();
    let mut visited = 0usize;
    let mut truncated = false;
    let mut stack: Vec<(std::path::PathBuf, usize)> = roots
        .iter()
        .map(|r| (std::path::PathBuf::from(r), 0))
        .collect();
    while let Some((dir, depth)) = stack.pop() {
        if visited >= max_entries || started.elapsed() > budget {
            truncated = true;
            break;
        }
        if skip.iter().any(|s| dir.starts_with(s)) {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            visited += 1;
            if visited >= max_entries {
                truncated = true;
                break;
            }
            let path = entry.path();
            if skip.iter().any(|s| path.starts_with(s)) {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_socket() {
                found.push(path.to_string_lossy().into_owned());
            } else if ft.is_dir() && depth < max_depth {
                stack.push((path, depth + 1));
            }
        }
    }
    (found, visited, truncated)
}

/// The runner-side view of one probe's output.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutput {
    /// The probe's pid as it sees itself (its sandbox pid namespace).
    pub pid: u64,
    pub results: BTreeMap<String, OpResult>,
    pub done: bool,
}

impl ProbeOutput {
    /// Parse stdout lines. Rejects a missing or mismatched banner, duplicate
    /// ids, and a missing `done` line unless `allow_no_done` (kill scenarios).
    /// Later banners and `done` lines (from background probes that inherited
    /// stdout) are ignored.
    pub fn parse(lines: &[String], allow_no_done: bool) -> Result<Self, String> {
        let first = lines
            .first()
            .ok_or_else(|| "probe printed nothing".to_owned())?;
        let banner: Value =
            serde_json::from_str(first).map_err(|e| format!("bad probe banner: {e}"))?;
        if banner.get("probe").and_then(Value::as_u64) != Some(u64::from(PROBE_VERSION)) {
            return Err(format!("probe banner mismatch: {first}"));
        }
        let pid = banner.get("pid").and_then(Value::as_u64).unwrap_or(0);
        let mut results: BTreeMap<String, OpResult> = BTreeMap::new();
        let mut done = false;
        for line in &lines[1..] {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if v.get("done").is_some() {
                done = true;
                continue;
            }
            if v.get("probe").is_some() {
                continue;
            }
            if v.get("op").is_some() {
                let r: OpResult =
                    serde_json::from_value(v).map_err(|e| format!("bad op result: {e}"))?;
                if results.contains_key(&r.id) {
                    return Err(format!("duplicate probe result id `{}`", r.id));
                }
                results.insert(r.id.clone(), r);
            }
        }
        if !done && !allow_no_done {
            // Name the last op that completed: a timeout is then diagnosable.
            let last = results.values().max_by_key(|r| r.t_ms);
            let at = match last {
                Some(r) => format!(
                    "; last completed op {} ({}) at +{} ms after the banner",
                    r.id,
                    r.op,
                    r.t_ms
                        .saturating_sub(banner["t_ms"].as_u64().unwrap_or(r.t_ms))
                ),
                None => "; no op completed".to_owned(),
            };
            return Err(format!("probe output has no done line{at}"));
        }
        Ok(ProbeOutput { pid, results, done })
    }

    /// The result of op `id`.
    pub fn get(&self, id: &str) -> Option<&OpResult> {
        self.results.get(id)
    }
}

impl Op {
    /// The worst-case wall time this op can take (its timeouts summed). The
    /// runner sizes a scenario's bound from the sum over its ops.
    pub fn budget_ms(&self) -> u64 {
        match self {
            Op::Dns { timeout_ms, .. } => *timeout_ms,
            Op::Tcp {
                steps,
                connect_timeout_ms,
                ..
            } => {
                connect_timeout_ms
                    + steps
                        .iter()
                        .map(|st| match st {
                            Step::Send(_) => 0,
                            Step::Read(r) => r.timeout_ms,
                            Step::ReadHttp(r) => r.timeout_ms,
                            Step::ReadToEnd(r) => r.timeout_ms,
                            Step::SleepMs(ms) => *ms,
                        })
                        .sum::<u64>()
            }
            Op::Udp {
                attempts,
                recv_timeout_ms,
                ..
            } => u64::from(*attempts) * recv_timeout_ms,
            Op::SocketsWalk { budget_ms, .. } => *budget_ms,
            Op::Sleep { ms, .. } => *ms,
            Op::WaitStdin { timeout_ms, .. } => *timeout_ms,
            Op::DnsFlood { count, .. } => u64::from(*count) * 50,
            Op::TcpLoop {
                duration_ms,
                attempt_timeout_ms,
                ..
            } => duration_ms + attempt_timeout_ms + 2000,
            _ => 0,
        }
    }
}

impl Ops {
    /// The sum of the per-op budgets.
    pub fn budget_ms(&self) -> u64 {
        self.ops.iter().map(Op::budget_ms).sum()
    }
}

/// The `$listen` placeholder rule: replaced by the last `listen_tcp` port.
pub fn subst_listen(addr: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => addr.replace("$listen", &p.to_string()),
        None => addr.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip_every_variant() {
        let ops = Ops::new(vec![
            Op::Hello { id: "h".into() },
            Op::Dns {
                id: "d".into(),
                name: "a.test".into(),
                qtype: "AAAA".into(),
                server: "8.8.8.8:53".into(),
                tcp: true,
                timeout_ms: 5,
            },
            Op::Tcp {
                id: "t".into(),
                target: Target::Addr {
                    addr: "127.0.0.1:$listen".into(),
                },
                steps: vec![
                    Step::Send(SendSpec::Text { text: "x".into() }),
                    Step::Send(SendSpec::Hello {
                        hello: HelloSpec {
                            sni: None,
                            ech: true,
                        },
                    }),
                    Step::Read(ReadSpec {
                        until: Some("\n".into()),
                        max: 10,
                        timeout_ms: 1,
                    }),
                    Step::ReadHttp(ReadHttpSpec { timeout_ms: 1 }),
                    Step::ReadToEnd(ReadToEndSpec {
                        max: 10,
                        timeout_ms: 1,
                    }),
                    Step::SleepMs(1),
                ],
                connect_timeout_ms: 1,
            },
            Op::Udp {
                id: "u".into(),
                addr: "8.8.8.8:123".into(),
                text: "Q".into(),
                attempts: 2,
                recv_timeout_ms: 1,
            },
            Op::Socket {
                id: "s".into(),
                family: "vsock".into(),
                ty: "stream".into(),
                protocol: 0,
            },
            Op::UnixConnect {
                id: "x".into(),
                path: None,
                abstract_name: Some("n".into()),
            },
            Op::Netlink {
                id: "n".into(),
                action: "lo_down".into(),
            },
            Op::Links { id: "l".into() },
            Op::Env {
                id: "e".into(),
                needles: vec!["n".into()],
                show: vec!["HOME".into()],
            },
            Op::Read {
                id: "r".into(),
                path: "/p".into(),
                needles: vec![],
                max: 1,
            },
            Op::ProcEnvironScan {
                id: "p".into(),
                needles: vec!["n".into()],
            },
            Op::Fds { id: "f".into() },
            Op::Stat {
                id: "st".into(),
                path: "/".into(),
            },
            Op::SocketsWalk {
                id: "w".into(),
                roots: vec!["/".into()],
                skip: vec![],
                max_entries: 1,
                max_depth: 1,
                budget_ms: 1,
            },
            Op::Procs { id: "pr".into() },
            Op::Unshare {
                id: "un".into(),
                flags: "user".into(),
            },
            Op::SpawnBg {
                id: "b".into(),
                token: "t".into(),
                stdio: "null".into(),
                ignore_signals: true,
            },
            Op::Detach {
                id: "d2".into(),
                ignore_signals: false,
            },
            Op::Sleep {
                id: "sl".into(),
                ms: 1,
            },
            Op::WaitStdin {
                id: "ws".into(),
                timeout_ms: 1,
            },
            Op::ListenTcp {
                id: "lt".into(),
                addr: "127.0.0.1:0".into(),
            },
            Op::ListenAbstract {
                id: "la".into(),
                name: "n".into(),
            },
            Op::Write {
                id: "wr".into(),
                path: "/p".into(),
                text: "t".into(),
            },
            Op::DnsFlood {
                id: "df".into(),
                prefix: "p".into(),
                count: 1,
                server: "127.0.0.1:53".into(),
            },
        ]);
        let text = serde_json::to_string(&ops).unwrap();
        let back: Ops = serde_json::from_str(&text).unwrap();
        assert_eq!(back.ops.len(), 24);
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
        assert_eq!(back.ops[0].name(), "hello");
        assert_eq!(back.ops[23].id(), "df");
    }

    #[test]
    fn listen_placeholder_substitution() {
        assert_eq!(
            subst_listen("127.0.0.1:$listen", Some(4242)),
            "127.0.0.1:4242"
        );
        assert_eq!(subst_listen("127.0.0.1:$listen", None), "127.0.0.1:$listen");
    }

    #[test]
    fn parse_accepts_a_full_probe_output() {
        let lines = vec![
            r#"{"probe":1,"sbx_version":"0.1.0","pid":7,"t_ms":1}"#.to_owned(),
            r#"{"id":"h","op":"hello","t_ms":2,"ok":true,"errno":null,"detail":"alive","data":{}}"#
                .to_owned(),
            r#"{"done":true,"t_ms":3}"#.to_owned(),
        ];
        let p = ProbeOutput::parse(&lines, false).unwrap();
        assert_eq!(p.pid, 7);
        assert!(p.done);
        assert!(p.get("h").unwrap().ok);
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        let banner = r#"{"probe":1,"pid":1}"#.to_owned();
        let done = r#"{"done":true}"#.to_owned();
        assert!(ProbeOutput::parse(&[], false).is_err());
        assert!(ProbeOutput::parse(&[r#"{"probe":2}"#.to_owned()], false).is_err());
        assert!(ProbeOutput::parse(std::slice::from_ref(&banner), false).is_err());
        assert!(ProbeOutput::parse(std::slice::from_ref(&banner), true).is_ok());
        let dup =
            r#"{"id":"a","op":"hello","t_ms":1,"ok":true,"errno":null,"detail":"","data":{}}"#
                .to_owned();
        assert!(ProbeOutput::parse(&[banner, dup.clone(), dup, done], false).is_err());
    }

    #[test]
    fn env_op_never_emits_unshown_values() {
        let mut st = State::default();
        let r = execute(
            &Op::Env {
                id: "e".into(),
                needles: vec![],
                show: vec!["HOME".into()],
            },
            &mut st,
        );
        let values = r.data["values"].as_object().unwrap();
        assert!(values.keys().all(|k| k == "HOME"));
    }

    #[test]
    fn fds_excludes_the_dir_handle() {
        let mut st = State::default();
        let r = execute(&Op::Fds { id: "f".into() }, &mut st);
        let fds: Vec<i64> = r.data["fds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_i64)
            .collect();
        assert!(fds.contains(&0) && fds.contains(&1) && fds.contains(&2));
        let own = format!("/proc/{}/fd", std::process::id());
        for fd in fds {
            let target = fs::read_link(format!("/proc/self/fd/{fd}")).ok();
            assert_ne!(
                target.map(|p| p.to_string_lossy().into_owned()),
                Some(own.clone())
            );
        }
    }

    #[test]
    fn dns_query_encodes_and_decodes_against_the_wire_codec() {
        let mut m = Message::new();
        m.set_id(DNS_ID)
            .set_recursion_desired(true)
            .add_query(Query::query(
                Name::from_ascii("a.test").unwrap(),
                RecordType::A,
            ));
        let bytes = m.to_vec().unwrap();
        let back = Message::from_vec(&bytes).unwrap();
        assert_eq!(back.id(), DNS_ID);
        assert!(back.recursion_desired());
    }
}
