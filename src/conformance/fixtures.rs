//! The conformance lab's local upstreams (issue #13, PR2): the TLS and HTTP
//! fixtures on `9.9.9.9`, the lab DNS server on `127.0.0.1:53`, and trap
//! listeners on the private, loopback and metadata addresses. Every listener
//! logs what it saw; the checks read those logs as their evidence.
//!
//! Runs only inside the lab child (`lab.rs`), in its own network namespace.
//! Nothing here touches the real network: the lab DNS never forwards.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde::{Deserialize, Serialize};

use super::probe::mono_ms;
use crate::proxy::hello;

/// The lab upstream: every `*.conformance.test` name resolves here.
pub const LAB_IP: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
/// The address of the lab's trap listeners on port 443 (besides 127.0.0.1).
pub const TRAP_PRIVATE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// The metadata address (cloud IMDS range).
pub const TRAP_META: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// The loopback trap address (`127.0.0.1:443`).
pub const TRAP_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// The three rebinding names and the address each resolves to (A only).
pub const REBIND: [(&str, Ipv4Addr); 3] = [
    ("rebind-lo.allowed.conformance.test", TRAP_LOOPBACK),
    ("rebind-private.allowed.conformance.test", TRAP_PRIVATE),
    ("rebind-meta.allowed.conformance.test", TRAP_META),
];

/// One TLS fixture connection (the first record and what followed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsRec {
    pub conn: u64,
    pub accept_ms: u64,
    /// The first record's SNI; `None` when absent or not a hello.
    pub sni: Option<String>,
    /// The first byte of the connection (0x16 for a handshake record).
    pub first_byte: u8,
    /// Complete handshake records after the first one.
    pub extra_handshake: u32,
    /// When the fixture saw EOF or a reset (`None`: still open).
    pub close_ms: Option<u64>,
}

/// One HTTP fixture request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpRec {
    pub conn: u64,
    pub accept_ms: u64,
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub connection_close: bool,
    /// How many Host header lines the request carried (B05b counts them).
    pub host_headers: usize,
}

/// One query the lab DNS received (lowercase name, no root dot).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRec {
    pub t_ms: u64,
    pub name: String,
    pub qtype: String,
}

/// Every log the fixtures keep. Shared between the listener threads and the
/// evaluators; entries are only ever appended (or a close time filled in).
#[derive(Default)]
pub struct Logs {
    pub tls: Mutex<Vec<TlsRec>>,
    pub http: Mutex<Vec<HttpRec>>,
    pub dns: Mutex<Vec<DnsRec>>,
    /// Accepts per trap address (`ip:443`).
    pub traps: Mutex<BTreeMap<String, u64>>,
}

/// The DNS log is capped: a flood cannot grow the lab without bound.
const DNS_LOG_CAP: usize = 10_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Logs {
    pub fn tls_snapshot(&self) -> Vec<TlsRec> {
        lock(&self.tls).clone()
    }

    pub fn http_snapshot(&self) -> Vec<HttpRec> {
        lock(&self.http).clone()
    }

    pub fn dns_snapshot(&self) -> Vec<DnsRec> {
        lock(&self.dns).clone()
    }

    /// Accepts seen by the trap at `ip:443`.
    pub fn trap_accepts(&self, ip: Ipv4Addr) -> u64 {
        lock(&self.traps)
            .get(&format!("{ip}:443"))
            .copied()
            .unwrap_or(0)
    }
}

/// What the lab DNS answers for one query (the pure table, unit-tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabAnswer {
    /// One A record.
    A(Ipv4Addr),
    /// The name exists, but there is no record of this type.
    NoData,
    /// The name is outside the lab.
    NxDomain,
}

/// The lab DNS table: the rebinding names, then every `*.conformance.test`
/// name (and the apex) to [`LAB_IP`], and everything else NXDOMAIN.
pub fn lab_answer(name: &str, qtype: RecordType) -> LabAnswer {
    if let Some((_, ip)) = REBIND.iter().find(|(n, _)| *n == name) {
        return if qtype == RecordType::A {
            LabAnswer::A(*ip)
        } else {
            LabAnswer::NoData
        };
    }
    if name == "conformance.test" || name.ends_with(".conformance.test") {
        return if qtype == RecordType::A {
            LabAnswer::A(LAB_IP)
        } else {
            LabAnswer::NoData
        };
    }
    LabAnswer::NxDomain
}

/// Start every fixture thread. The sockets are already bound (the lab child
/// binds them in its setup stage, so a bind failure is a setup failure).
pub struct Listeners {
    pub dns: UdpSocket,
    pub tls: TcpListener,
    pub http: TcpListener,
    pub traps: Vec<(Ipv4Addr, TcpListener)>,
}

/// Serve every listener on its own thread.
pub fn spawn(logs: &Arc<Logs>, l: Listeners) {
    let dns_logs = Arc::clone(logs);
    std::thread::spawn(move || serve_dns(&dns_logs, &l.dns));
    let tls_logs = Arc::clone(logs);
    std::thread::spawn(move || accept_loop(&l.tls, move |s, conn| serve_tls(&tls_logs, s, conn)));
    let http_logs = Arc::clone(logs);
    std::thread::spawn(move || {
        accept_loop(&l.http, move |s, conn| serve_http(&http_logs, s, conn));
    });
    for (ip, listener) in l.traps {
        let trap_logs = Arc::clone(logs);
        std::thread::spawn(move || {
            accept_loop(&listener, move |s, _| {
                *lock(&trap_logs.traps)
                    .entry(format!("{ip}:443"))
                    .or_insert(0) += 1;
                drop(s);
            });
        });
    }
}

static CONN_IDS: AtomicU64 = AtomicU64::new(1);

/// Accept forever; every connection is served on its own thread (a held
/// connection must not block the listener).
fn accept_loop(listener: &TcpListener, handle: impl Fn(TcpStream, u64) + Send + Sync + 'static) {
    let handle = Arc::new(handle);
    loop {
        match listener.accept() {
            Ok((s, _)) => {
                let conn = CONN_IDS.fetch_add(1, Ordering::Relaxed);
                let h = Arc::clone(&handle);
                std::thread::spawn(move || h(s, conn));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Read until one complete first record is buffered (or the caller's bound).
fn read_first_record(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<usize> {
    let mut chunk = [0u8; 4096];
    loop {
        if buf.first().is_some_and(|b| *b != 0x16) {
            return None;
        }
        if let Some(n) = hello::first_record_end(buf) {
            return Some(n);
        }
        if buf.len() > 16 * 1024 {
            return None;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(k) => buf.extend_from_slice(&chunk[..k]),
        }
    }
}

/// The TLS fixture: log the first ClientHello, answer with the SNI, count the
/// handshake records that follow, and log when the peer closes.
fn serve_tls(logs: &Logs, mut s: TcpStream, conn: u64) {
    let accept_ms = mono_ms();
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let mut buf: Vec<u8> = Vec::new();
    let first_byte = {
        let mut one = [0u8; 1];
        match s.read(&mut one) {
            Ok(1) => {
                buf.push(one[0]);
                one[0]
            }
            _ => 0,
        }
    };
    let sni = if first_byte == 0x16 {
        let mut probe = s.try_clone().ok();
        let mut sni = None;
        if let Some(p) = probe.as_mut() {
            // The first byte is already consumed: read the rest of the record.
            if let Some(n) = read_first_record(p, &mut buf) {
                sni = hello::sni_of(&buf[..n]).flatten();
                let _ = s.write_all(
                    format!("FIXTURE-TLS {}\n", sni.as_deref().unwrap_or("none")).as_bytes(),
                );
            }
        }
        sni
    } else {
        None
    };
    let rec = TlsRec {
        conn,
        accept_ms,
        sni,
        first_byte,
        extra_handshake: 0,
        close_ms: None,
    };
    lock(&logs.tls).push(rec);
    if first_byte != 0x16 {
        mark_closed(logs, conn);
        return;
    }
    // Count the records after the first one until the peer goes away.
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    let mut off = hello::first_record_end(&buf).unwrap_or(buf.len());
    let mut extra = 0u32;
    let mut chunk = [0u8; 4096];
    loop {
        while buf.len() >= off + 5 {
            let rlen = usize::from(u16::from_be_bytes([buf[off + 3], buf[off + 4]]));
            if buf.len() < off + 5 + rlen {
                break;
            }
            if buf[off] == 0x16 {
                extra += 1;
            }
            off += 5 + rlen;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(k) => buf.extend_from_slice(&chunk[..k]),
        }
    }
    if let Some(r) = lock(&logs.tls).iter_mut().rev().find(|r| r.conn == conn) {
        r.extra_handshake = extra;
    }
    mark_closed(logs, conn);
}

fn mark_closed(logs: &Logs, conn: u64) {
    if let Some(r) = lock(&logs.tls).iter_mut().rev().find(|r| r.conn == conn) {
        r.close_ms = Some(mono_ms());
    }
}

/// The HTTP fixture: parse request heads (keep-alive loop), log each request,
/// answer with the Host name. A `Connection: close` request ends the socket.
fn serve_http(logs: &Logs, mut s: TcpStream, conn: u64) {
    let accept_ms = mono_ms();
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match parse_head(&buf) {
            Some((n, rec_fields)) => {
                let (method, target, host, close, host_headers) = rec_fields;
                lock(&logs.http).push(HttpRec {
                    conn,
                    accept_ms,
                    method,
                    target,
                    host: host.clone(),
                    connection_close: close,
                    host_headers,
                });
                let body = format!("FIXTURE-HTTP {}", host.as_deref().unwrap_or("none"));
                let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n", body.len());
                if close {
                    resp.push_str("Connection: close\r\n");
                }
                resp.push_str("\r\n");
                resp.push_str(&body);
                if s.write_all(resp.as_bytes()).is_err() {
                    return;
                }
                buf.drain(..n);
                if close {
                    return;
                }
            }
            None => {
                if buf.len() > 64 * 1024 {
                    return;
                }
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(k) => buf.extend_from_slice(&chunk[..k]),
                }
            }
        }
    }
}

/// One complete request head: its length and (method, target, Host, close, Host lines).
type Head = (usize, (String, String, Option<String>, bool, usize));

/// Parse the first complete request head in `buf`, if there is one.
fn parse_head(buf: &[u8]) -> Option<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            let method = req.method.unwrap_or("").to_owned();
            let target = req.path.unwrap_or("").to_owned();
            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .map(|h| String::from_utf8_lossy(h.value).into_owned());
            // A Connection header is a comma-separated token list; `closed`
            // or `x-close` must not count as `close`.
            let close = req.headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("connection")
                    && String::from_utf8_lossy(h.value)
                        .split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case("close"))
            });
            let host_headers = req
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("host"))
                .count();
            Some((n, (method, target, host, close, host_headers)))
        }
        _ => None,
    }
}

/// The lab DNS: answer A/AAAA/TXT per [`lab_answer`] and log every query.
fn serve_dns(logs: &Logs, sock: &UdpSocket) {
    let mut buf = [0u8; 4096];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf) else {
            return;
        };
        let Ok(query) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        let Some(q) = query.queries().first().cloned() else {
            continue;
        };
        let name = q
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let qtype = q.query_type();
        {
            let mut log = lock(&logs.dns);
            if log.len() < DNS_LOG_CAP {
                log.push(DnsRec {
                    t_ms: mono_ms(),
                    name: name.clone(),
                    qtype: format!("{qtype:?}"),
                });
            }
        }
        let mut resp = Message::new();
        resp.set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(query.recursion_desired())
            .set_recursion_available(true)
            .add_query(q.clone());
        match lab_answer(&name, qtype) {
            LabAnswer::A(ip) => {
                resp.set_response_code(ResponseCode::NoError);
                if let Ok(owner) = Name::from_ascii(&name) {
                    resp.add_answer(Record::from_rdata(owner, 5, RData::A(A(ip))));
                }
            }
            LabAnswer::NoData => {
                resp.set_response_code(ResponseCode::NoError);
            }
            LabAnswer::NxDomain => {
                resp.set_response_code(ResponseCode::NXDomain);
            }
        }
        if let Ok(bytes) = resp.to_vec() {
            let _ = sock.send_to(&bytes, peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_dns_table() {
        assert_eq!(
            lab_answer("a02.allowed.conformance.test", RecordType::A),
            LabAnswer::A(LAB_IP)
        );
        assert_eq!(
            lab_answer("conformance.test", RecordType::A),
            LabAnswer::A(LAB_IP)
        );
        assert_eq!(
            lab_answer("allowed.conformance.test", RecordType::TXT),
            LabAnswer::NoData
        );
        assert_eq!(
            lab_answer("rebind-lo.allowed.conformance.test", RecordType::A),
            LabAnswer::A(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            lab_answer("rebind-meta.allowed.conformance.test", RecordType::A),
            LabAnswer::A(TRAP_META)
        );
        assert_eq!(
            lab_answer("rebind-private.allowed.conformance.test", RecordType::AAAA),
            LabAnswer::NoData
        );
        assert_eq!(lab_answer("pypi.org", RecordType::A), LabAnswer::NxDomain);
        assert_eq!(
            lab_answer("conformance.test.evil.com", RecordType::A),
            LabAnswer::NxDomain
        );
    }

    #[test]
    fn head_parser_reports_close_and_host() {
        let keep = b"GET /a HTTP/1.1\r\nHost: x.allowed.conformance.test\r\n\r\n";
        let (n, (m, t, h, c, hosts)) = parse_head(keep).expect("complete head");
        assert_eq!(hosts, 1);
        assert_eq!(n, keep.len());
        assert_eq!((m.as_str(), t.as_str()), ("GET", "/a"));
        assert_eq!(h.as_deref(), Some("x.allowed.conformance.test"));
        assert!(!c);
        let close = b"GET / HTTP/1.1\r\nHost: y\r\nConnection: close\r\n\r\n";
        assert!(parse_head(close).expect("complete").1.3);
        // `closed` and `x-close` are not `close`; a token list is.
        assert!(
            !parse_head(b"GET / HTTP/1.1\r\nHost: y\r\nConnection: closed\r\n\r\n")
                .expect("complete")
                .1
                .3
        );
        assert!(
            parse_head(b"GET / HTTP/1.1\r\nHost: y\r\nConnection: keep-alive, Close\r\n\r\n")
                .expect("complete")
                .1
                .3
        );
        assert_eq!(
            parse_head(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n")
                .expect("complete")
                .1
                .4,
            2
        );
        assert!(parse_head(b"GET / HTTP/1.1\r\nHost: y\r\n").is_none());
        let none = b"GET / HTTP/1.0\r\n\r\n";
        assert_eq!(parse_head(none).expect("complete").1.2, None);
    }
}
