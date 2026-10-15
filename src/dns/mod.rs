//! The fake-IP DNS resolver (issue #9).
//!
//! The sandbox's `resolv.conf` points at `127.0.0.1`, and nftables redirects
//! every UDP/53 packet to the resolver the parent serves on the fd `__init`
//! handed over. Numbered like [`crate::proxy`]:
//!
//! 1. **Contract.** `ListenerFds.dns` arrives BLOCKING and is flipped
//!    non-blocking by [`serve_dns`]. The task runs until a fatal socket error
//!    (a provably dead fd) and is stopped by ABORT (point 7). #10 spawns it
//!    before the go byte, next to the transparent proxy.
//! 2. **Never forwards.** There is no upstream resolver, no resolver code and
//!    no TCP DNS. TCP to `127.0.0.1:53` (the `resolv.conf` target, i.e. the
//!    usual stub fallback) is local, so the nft REDIRECT skips it and the
//!    connect is refused with no audit record. TCP/53 to any other address
//!    reaches the transparent proxy: `PortNotAllowed` unless a policy lists
//!    port 53; then `UnknownFakeIp` for a non-fake address (the map lookup
//!    runs first) and `NoInspector` for an allocated fake IP.
//! 3. **Pipeline (per datagram, [`DnsServer::handle_datagram`]).** The raw-byte
//!    header gate runs before the protocol library, so an attacker-chosen
//!    section count never reaches the decoder. Then: decode, EDNS version,
//!    class, name (raw labels, then [`crate::proxy::canonicalize_host`]),
//!    allow-list ([`crate::egress::allowed`]), qtype, allocation. The map
//!    insert happens BEFORE the reply is built, so a client that gets an
//!    address can always be mapped back.
//! 4. **Answers.** Allowed names: A gets one fake IP at TTL [`FAKE_TTL`];
//!    every other qtype gets NODATA (NOERROR, empty), Q2. Any other name, any
//!    class other than IN (REFUSED), any opcode other than QUERY (NOTIMP) and
//!    any malformed query get the error rcodes returned by
//!    [`DnsVerdict::rcode`] (pinned in the tests). TC is never set (replies stay far under 512
//!    bytes). A PTR for a fake IP is NXDOMAIN (Q14, D6). CD is cleared and AD
//!    is never set: the resolver is not DNSSEC-aware (RFC 1035 Z rule). Negative
//!    answers carry no SOA, unlike RFC 2308 suggests; that is intentional, the
//!    mapping is per run and there is no zone to cache negative answers from.
//! 5. **The map.** [`FakeIpMap`] is the run's one allocation table, shared
//!    as the same `Arc` the proxy reads through [`crate::proxy::DnsMap`]. Names
//!    are canonical (lowercase, punycode), no expiry within a run (Q6), and
//!    exhaustion refuses NEW names only (Q4).
//! 6. **Vocabulary.** Every reason string is built in exactly one `reason()`
//!    match; the pinned table is in the tests. One [`DnsDecision`] per
//!    received datagram, drops included, goes to the [`DnsSink`] seam (#10)
//!    after the reply is encoded and before it is sent.
//! 7. **Errors and teardown (D3, D4).** Recv: `EBADF`/`EINVAL`/`ENOTSOCK` are
//!    fatal; anything else backs off and retries. Send: only `EBADF`/`ENOTSOCK`
//!    are fatal, so a per-datagram condition (`EINVAL` for a zero port, for
//!    example) cannot kill the resolver. On Linux, `shutdown(2)` on an
//!    unconnected UDP socket returns `ENOTCONN` and never wakes recv, so there
//!    is no deliberate stop path: the owner stops the task by abort.
//! 8. **Panic containment (D5).** Each datagram runs under `catch_unwind`. A
//!    panic in the decoder yields a decision with `Error(Internal)` and no
//!    reply. A panicking sink DROPS that datagram's reply, so no answer leaves
//!    without its audit record.
//! 9. **Residuals for #14.** (a) A client can exfiltrate data by encoding it
//!    into labels under an allowed suffix (`<data>.<allowed suffix>`). The
//!    resolver never forwards, but a connect to such a name later makes the
//!    host resolve it. (b) Host `/etc/hosts` entries bound into the sandbox
//!    resolve names to REAL addresses, so the proxy denies them with
//!    `UnknownFakeIp` (fail closed). (c) A policy that binds the nscd or
//!    systemd-resolved socket (`/run`, `/var/run`) bypasses this resolver. (d)
//!    Unique subdomains exhaust the pool and flood the audit sink.
//! 10. **Why hickory.** The wire codec is `hickory-proto` 0.25.2 with no
//!     features (`wire.rs` docs and `Cargo.toml`). The header gate and the
//!     deny.toml entries record the advisory reasoning. Re-evaluate at MSRV 1.88.
//! 11. **Test tiers.** Unit tests here drive [`DnsServer::handle_datagram`] with
//!     no sockets. The socket tier runs `serve_dns` on a current-thread runtime
//!     against a real UDP client. `tests/sandbox_proxy.rs` covers the namespace
//!     and `getent` path.

pub mod map;
pub(crate) mod wire;

pub use map::{AllocError, FAKE_POOL_FIRST, FAKE_POOL_LAST, FAKE_POOL_SIZE, FakeIpMap};

use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::Name;

use crate::egress;
use crate::policy::{self, Domain};
use crate::proxy::{AUDIT_TEXT_CAP, canonicalize_host};
use wire::{Gate, HeaderOnly, Parsed};

/// TTL on every fake-IP answer (Q6). Mappings never expire within a run.
pub const FAKE_TTL: u32 = 60;
/// Receive buffer. A UDP/IPv4 payload is at most 65 507 bytes, so nothing is
/// ever truncated.
pub const DNS_RECV_BUF: usize = 64 * 1024;
// A UDP/IPv4 payload is at most 65 507 bytes; the buffer must hold one.
const _: () = assert!(DNS_RECV_BUF >= 65_507);
const RECV_BACKOFF_START: Duration = Duration::from_millis(1);
const RECV_BACKOFF_MAX: Duration = Duration::from_millis(100);

/// Per-run resource limits. The default is the full pool (Q5); tests shrink it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsLimits {
    /// Most distinct names a run may allocate before new names are refused.
    pub max_names: u32,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            max_names: FAKE_POOL_SIZE,
        }
    }
}

/// The audit form of a question. The name is as received (case kept), escaped
/// and capped by [`dns_name_for_audit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// The one record a received datagram produces (Q10).
#[derive(Debug, Clone, PartialEq)]
pub struct DnsDecision {
    /// The `recv_from` peer.
    pub client: SocketAddr,
    /// `Some` iff the question decoded.
    pub question: Option<DnsQuestion>,
    pub verdict: DnsVerdict,
}

impl DnsDecision {
    /// The pinned human-readable reason (see [`DnsVerdict::reason`]).
    pub fn reason(&self) -> String {
        self.verdict.reason()
    }
}

/// What the resolver decided. `rcode()` says what was SENT.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsVerdict {
    /// A for an allowed name: NOERROR with one fake IP.
    Answered { name: Domain, ip: Ipv4Addr },
    /// An allowed name with a non-A qtype: NOERROR, empty (Q2).
    NoData { name: Domain, qtype: u16 },
    /// A reply went out with an error rcode.
    Denied(DnsRejected),
    /// No reply (Q3).
    Dropped(DnsDropped),
    /// An infrastructure failure: REFUSED, or no reply.
    Error(DnsFailed),
}

impl DnsVerdict {
    /// The stable short label for the audit row.
    pub fn label(&self) -> &'static str {
        match self {
            DnsVerdict::Answered { .. } => "answered",
            DnsVerdict::NoData { .. } => "nodata",
            DnsVerdict::Denied(_) => "denied",
            DnsVerdict::Dropped(_) => "dropped",
            DnsVerdict::Error(_) => "error",
        }
    }

    /// The pinned reason text (byte-exact; the tests carry the table).
    pub fn reason(&self) -> String {
        match self {
            DnsVerdict::Answered { name, ip } => {
                format!("answered {} A {ip}", name.as_str())
            }
            DnsVerdict::NoData { name, qtype } => {
                format!("NODATA for {} type {qtype} (A only)", name.as_str())
            }
            DnsVerdict::Denied(rejected) => rejected.reason(),
            DnsVerdict::Dropped(dropped) => dropped.reason(),
            DnsVerdict::Error(failed) => failed.reason(),
        }
    }

    /// The rcode SENT, or `None` when nothing was sent.
    pub fn rcode(&self) -> Option<u16> {
        match self {
            DnsVerdict::Answered { .. } | DnsVerdict::NoData { .. } => Some(0),
            DnsVerdict::Denied(rejected) => Some(rejected.rcode()),
            DnsVerdict::Dropped(_) => None,
            DnsVerdict::Error(failed) => failed.rcode(),
        }
    }
}

/// Queries answered with an error rcode (a reply was sent).
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRejected {
    /// Opcode other than QUERY: NOTIMP.
    NotImplemented { opcode: u8 },
    /// Section counts other than `qd=1 an=0 ns=0 ar<=1`: FORMERR.
    BadCounts { qd: u16, an: u16, ns: u16, ar: u16 },
    /// hickory could not decode the message: FORMERR.
    Malformed { detail: String },
    /// A compression pointer in the question name (D1): FORMERR.
    CompressedQuestion,
    /// An additional record other than one OPT (D2): FORMERR.
    UnexpectedAdditional { rtype: u16 },
    /// Bytes after the last record (D2): FORMERR.
    TrailingBytes { extra: usize },
    /// EDNS version above 0: BADVERS.
    BadEdnsVersion { version: u8 },
    /// A class other than IN: REFUSED.
    NotInClass { qclass: u16 },
    /// The name is not a valid hostname: NXDOMAIN.
    InvalidName { qname: String },
    /// A valid name outside the allow-list: NXDOMAIN.
    NotAllowed { name: Domain },
}

impl DnsRejected {
    /// The pinned reason text.
    pub fn reason(&self) -> String {
        match self {
            DnsRejected::NotImplemented { opcode } => {
                format!("DNS opcode {opcode} is not implemented (QUERY only)")
            }
            DnsRejected::BadCounts { qd, an, ns, ar } => format!(
                "malformed DNS query: section counts qd={qd} an={an} ns={ns} ar={ar} \
                 (want qd=1 an=0 ns=0 ar<=1)"
            ),
            DnsRejected::Malformed { detail } => format!("malformed DNS query: {detail}"),
            DnsRejected::CompressedQuestion => {
                "malformed DNS query: compression pointer in the question name".to_owned()
            }
            DnsRejected::UnexpectedAdditional { rtype } => format!(
                "malformed DNS query: additional record of type {rtype} (only one OPT is accepted)"
            ),
            DnsRejected::TrailingBytes { extra } => {
                format!("malformed DNS query: {extra} trailing byte(s) after the last record")
            }
            DnsRejected::BadEdnsVersion { version } => {
                format!("unsupported EDNS version {version} (EDNS0 only)")
            }
            DnsRejected::NotInClass { qclass } => format!("DNS class {qclass} is not IN"),
            DnsRejected::InvalidName { qname } => {
                format!("query name {qname} is not a valid hostname")
            }
            DnsRejected::NotAllowed { name } => {
                format!("{} is not in the policy allow list", name.as_str())
            }
        }
    }

    /// The rcode sent for this rejection.
    pub fn rcode(&self) -> u16 {
        match self {
            DnsRejected::NotImplemented { .. } => 4,
            DnsRejected::BadCounts { .. }
            | DnsRejected::Malformed { .. }
            | DnsRejected::CompressedQuestion
            | DnsRejected::UnexpectedAdditional { .. }
            | DnsRejected::TrailingBytes { .. } => 1,
            DnsRejected::BadEdnsVersion { .. } => 16,
            DnsRejected::NotInClass { .. } => 5,
            DnsRejected::InvalidName { .. } | DnsRejected::NotAllowed { .. } => 3,
        }
    }
}

/// Datagrams answered with no reply (Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDropped {
    /// Shorter than a DNS header.
    Short { len: usize },
    /// A response (QR=1) on the resolver socket.
    NotAQuery,
}

impl DnsDropped {
    /// The pinned reason text.
    pub fn reason(&self) -> String {
        match self {
            DnsDropped::Short { len } => {
                format!("datagram of {len} byte(s) is shorter than a DNS header")
            }
            DnsDropped::NotAQuery => {
                "DNS response (QR=1) received on the resolver socket".to_owned()
            }
        }
    }
}

/// Infrastructure failures.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsFailed {
    /// The pool is full: REFUSED for a new name (Q4).
    PoolExhausted,
    /// The map's lock is poisoned: REFUSED (Q11).
    MapUnavailable,
    /// The reply could not be encoded: no reply.
    Encode { detail: String },
    /// A panic was caught while handling the datagram (D5): no reply.
    Internal,
}

impl DnsFailed {
    /// The pinned reason text.
    pub fn reason(&self) -> String {
        match self {
            DnsFailed::PoolExhausted => "fake-IP pool 198.18.0.0/15 exhausted".to_owned(),
            DnsFailed::MapUnavailable => "fake-IP map unavailable (lock poisoned)".to_owned(),
            DnsFailed::Encode { detail } => format!("DNS response encoding failed: {detail}"),
            DnsFailed::Internal => {
                "internal error while handling the DNS datagram (panic caught)".to_owned()
            }
        }
    }

    /// The rcode sent for this failure, `None` when no reply goes out.
    pub fn rcode(&self) -> Option<u16> {
        match self {
            DnsFailed::PoolExhausted | DnsFailed::MapUnavailable => Some(5),
            DnsFailed::Encode { .. } | DnsFailed::Internal => None,
        }
    }
}

/// The audit seam (#10 plugs in the JSONL log). Exactly one call per received
/// datagram, drops included, AFTER the reply is encoded and BEFORE it is sent.
/// SYNC, CHEAP, NON-BLOCKING, and it must not panic: a panic drops that
/// datagram's reply (D5).
pub trait DnsSink: Send + Sync + 'static {
    /// Record one decision.
    fn record(&self, decision: &DnsDecision);
}

/// The resolver's shared state: the allow-list, the run's map, the sink.
pub struct DnsServer {
    /// Cloned from `policy.network.allow`.
    pub allow: Vec<Domain>,
    /// The SAME `Arc` the proxy reads through [`crate::proxy::DnsMap`].
    pub map: Arc<FakeIpMap>,
    /// Audit seam.
    pub sink: Arc<dyn DnsSink>,
}

impl DnsServer {
    /// Build the resolver for one run.
    pub fn new(
        network: &policy::Network,
        map: Arc<FakeIpMap>,
        sink: Arc<dyn DnsSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            allow: network.allow.clone(),
            map,
            sink,
        })
    }

    /// Answer one datagram: the pure pipeline (module docs point 3). Returns
    /// the decision and, when there is one, the encoded reply.
    pub(crate) fn handle_datagram(
        &self,
        client: SocketAddr,
        datagram: &[u8],
    ) -> (DnsDecision, Option<Vec<u8>>) {
        let (question, verdict, reply) = self.respond(datagram);
        (
            DnsDecision {
                client,
                question,
                verdict,
            },
            reply,
        )
    }

    fn respond(&self, datagram: &[u8]) -> (Option<DnsQuestion>, DnsVerdict, Option<Vec<u8>>) {
        let (id, rd) = match wire::gate(datagram) {
            Gate::Drop(dropped) => return (None, DnsVerdict::Dropped(dropped), None),
            Gate::Reject { reply, rejected } => {
                let encoded = wire::encode_header_only(&reply);
                return settle(None, DnsVerdict::Denied(rejected), encoded);
            }
            Gate::Pass { id, rd } => (id, rd),
        };

        let parsed = match wire::decode(datagram) {
            Ok(parsed) => parsed,
            Err(err) => {
                let question = err.query.as_ref().map(question_of);
                let reply = HeaderOnly {
                    id,
                    opcode: 0,
                    rd,
                    rcode: ResponseCode::FormErr,
                };
                let encoded = wire::encode_header_only(&reply);
                return settle(question, DnsVerdict::Denied(err.rejected), encoded);
            }
        };

        let question = question_of(&parsed.query);
        let (verdict, rcode, answer) = self.decide(&parsed, &question);
        let encoded = wire::encode_response(&parsed, rcode, answer);
        settle(Some(question), verdict, encoded)
    }

    /// Steps 3 to 8 of the pipeline: the verdict, the rcode to send, and the
    /// A answer if there is one.
    fn decide(
        &self,
        parsed: &Parsed,
        question: &DnsQuestion,
    ) -> (DnsVerdict, ResponseCode, Option<Ipv4Addr>) {
        if let Some(edns) = &parsed.edns {
            if edns.version() > 0 {
                let version = edns.version();
                return (
                    DnsVerdict::Denied(DnsRejected::BadEdnsVersion { version }),
                    ResponseCode::BADVERS,
                    None,
                );
            }
        }
        if !wire::is_in_class(&parsed.query) {
            return (
                DnsVerdict::Denied(DnsRejected::NotInClass {
                    qclass: question.qclass,
                }),
                ResponseCode::Refused,
                None,
            );
        }
        let name = match wire::query_host(parsed.query.name()).and_then(|h| canonicalize_host(&h)) {
            Some(name) => name,
            None => {
                return (
                    DnsVerdict::Denied(DnsRejected::InvalidName {
                        qname: question.name.clone(),
                    }),
                    ResponseCode::NXDomain,
                    None,
                );
            }
        };
        if egress::allowed(name.as_str(), &self.allow).is_none() {
            return (
                DnsVerdict::Denied(DnsRejected::NotAllowed { name }),
                ResponseCode::NXDomain,
                None,
            );
        }
        if !wire::is_a_query(&parsed.query) {
            let qtype = question.qtype;
            return (
                DnsVerdict::NoData { name, qtype },
                ResponseCode::NoError,
                None,
            );
        }
        match self.map.allocate(&name) {
            Ok(ip) => (
                DnsVerdict::Answered { name, ip },
                ResponseCode::NoError,
                Some(ip),
            ),
            Err(AllocError::Exhausted) => (
                DnsVerdict::Error(DnsFailed::PoolExhausted),
                ResponseCode::Refused,
                None,
            ),
            Err(AllocError::Unavailable) => (
                DnsVerdict::Error(DnsFailed::MapUnavailable),
                ResponseCode::Refused,
                None,
            ),
        }
    }
}

/// Attach the encoded reply to a verdict, or replace the verdict with an
/// encode failure and send nothing.
fn settle(
    question: Option<DnsQuestion>,
    verdict: DnsVerdict,
    encoded: Result<Vec<u8>, String>,
) -> (Option<DnsQuestion>, DnsVerdict, Option<Vec<u8>>) {
    match encoded {
        Ok(reply) => (question, verdict, Some(reply)),
        Err(detail) => (
            question,
            DnsVerdict::Error(DnsFailed::Encode {
                detail: sanitize_detail(&detail),
            }),
            None,
        ),
    }
}

fn question_of(query: &Query) -> DnsQuestion {
    DnsQuestion {
        name: dns_name_for_audit(query.name()),
        qtype: wire::qtype_of(query),
        qclass: wire::qclass_of(query),
    }
}

/// Serve the resolver on `socket` until a fatal socket error (module docs
/// points 1 and 7). Strictly sequential: one datagram at a time, so a slow
/// sink stalls DNS (the sink contract, point 6). It never returns `Ok`; stop
/// it by aborting the task.
pub async fn serve_dns(
    socket: std::net::UdpSocket,
    server: Arc<DnsServer>,
) -> io::Result<Infallible> {
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    let mut buf = vec![0u8; DNS_RECV_BUF];
    let mut backoff = RECV_BACKOFF_START;
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(got) => {
                backoff = RECV_BACKOFF_START;
                got
            }
            Err(err) if recv_error_is_fatal(&err) => return Err(err),
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(RECV_BACKOFF_MAX);
                continue;
            }
        };
        let datagram = &buf[..len];
        let (decision, reply) =
            match catch_unwind(AssertUnwindSafe(|| server.handle_datagram(peer, datagram))) {
                Ok(pair) => pair,
                Err(_) => (
                    DnsDecision {
                        client: peer,
                        question: None,
                        verdict: DnsVerdict::Error(DnsFailed::Internal),
                    },
                    None,
                ),
            };
        if catch_unwind(AssertUnwindSafe(|| server.sink.record(&decision))).is_err() {
            // D5: no reply leaves without its audit record.
            continue;
        }
        if let Some(reply) = reply {
            if let Err(err) = socket.send_to(&reply, peer).await {
                if send_error_is_fatal(&err) {
                    return Err(err);
                }
            }
        }
    }
}

/// The audit form of a question name (module docs point 6): ASCII LDH and `_`
/// verbatim, `.` as `\.`, `\` as `\\`, any other byte as `\DDD` (RFC 1035
/// master-file style), labels joined by `.`, capped at [`AUDIT_TEXT_CAP`].
pub(crate) fn dns_name_for_audit(name: &Name) -> String {
    let mut out = String::new();
    let mut labels = 0usize;
    for label in name.iter() {
        if labels > 0 {
            out.push('.');
        }
        labels += 1;
        for &byte in label {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' => out.push(char::from(byte)),
                b'.' => out.push_str("\\."),
                b'\\' => out.push_str("\\\\"),
                _ => out.push_str(&format!("\\{byte:03}")),
            }
        }
    }
    if labels == 0 {
        return ".".to_owned();
    }
    if out.len() > AUDIT_TEXT_CAP {
        // Everything pushed above is ASCII, so byte 253 is a char boundary.
        out.truncate(AUDIT_TEXT_CAP - 3);
        out.push_str("...");
    }
    out
}

/// Free text from a decoder error, made printable and capped: bytes outside
/// `' '..='~'` become `?`, and anything over [`AUDIT_TEXT_CAP`] is cut to
/// 253 bytes plus `...`.
fn sanitize_detail(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect();
    if out.len() > AUDIT_TEXT_CAP {
        out.truncate(AUDIT_TEXT_CAP - 3);
        out.push_str("...");
    }
    out
}

/// Recv errors that end the task (EBADF, EINVAL, ENOTSOCK). Everything else
/// backs off and retries.
fn recv_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::EINVAL) | Some(libc::ENOTSOCK)
    )
}

/// Send errors that end the task (EBADF, ENOTSOCK). Everything else, EINVAL
/// included, is per datagram (D3).
fn send_error_is_fatal(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EBADF) | Some(libc::ENOTSOCK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn dom(raw: &str) -> Domain {
        Domain::parse(raw).expect("test domain parses")
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:40000".parse().expect("addr")
    }

    /// The name's raw labels as a wire-form byte vector (no compression).
    fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(u8::try_from(label.len()).expect("label fits"));
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    /// A dotted name's wire form ("" = root).
    fn dotted(name: &str) -> Vec<u8> {
        let labels: Vec<&[u8]> = name
            .split('.')
            .filter(|l| !l.is_empty())
            .map(str::as_bytes)
            .collect();
        wire_name(&labels)
    }

    /// A query over raw name bytes, with optional EDNS `(version, DO)`.
    fn query(id: u16, name: &[u8], qtype: u16, qclass: u16, edns: Option<(u8, bool)>) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        if edns.is_some() {
            v[10..12].copy_from_slice(&1u16.to_be_bytes());
        }
        v.extend_from_slice(name);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        if let Some((version, do_bit)) = edns {
            v.extend_from_slice(&[
                0,
                0,
                41,
                0x10,
                0x00,
                0,
                version,
                if do_bit { 0x80 } else { 0 },
                0,
                0,
                0,
            ]);
        }
        v
    }

    fn a_query(id: u16, name: &str) -> Vec<u8> {
        query(id, &dotted(name), 1, 1, None)
    }

    fn server_with(
        allow: &[&str],
        limits: DnsLimits,
    ) -> (Arc<DnsServer>, Arc<FakeIpMap>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let map = Arc::new(FakeIpMap::new(&limits));
        let network = policy::Network {
            mode: policy::NetworkMode::Transparent,
            allow: allow.iter().map(|s| dom(s)).collect(),
            ports: vec![443],
        };
        let server = DnsServer::new(&network, Arc::clone(&map), sink.clone());
        (server, map, sink)
    }

    fn handle(server: &DnsServer, datagram: &[u8]) -> (DnsDecision, Option<Vec<u8>>) {
        server.handle_datagram(peer(), datagram)
    }

    /// The rcode of an encoded reply (header byte 3, low nibble; the extended
    /// bits are read from the OPT when present, which the pinned tests cover).
    fn rcode_of(reply: &[u8]) -> u8 {
        reply[3] & 0x0f
    }

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<DnsDecision>>);

    impl RecordingSink {
        fn take(&self) -> Vec<DnsDecision> {
            std::mem::take(&mut *self.0.lock().expect("sink lock"))
        }
    }

    impl DnsSink for RecordingSink {
        fn record(&self, decision: &DnsDecision) {
            self.0.lock().expect("sink lock").push(decision.clone());
        }
    }

    // ---- pinned vocabulary -------------------------------------------------

    #[test]
    fn dns_rejected_reasons_pinned() {
        let cases: Vec<(DnsRejected, &str, u16)> = vec![
            (
                DnsRejected::NotImplemented { opcode: 5 },
                "DNS opcode 5 is not implemented (QUERY only)",
                4,
            ),
            (
                DnsRejected::BadCounts {
                    qd: 0,
                    an: 0,
                    ns: 0,
                    ar: 0,
                },
                "malformed DNS query: section counts qd=0 an=0 ns=0 ar=0 \
                 (want qd=1 an=0 ns=0 ar<=1)",
                1,
            ),
            (
                DnsRejected::Malformed {
                    detail: "unexpected end of input reached".to_owned(),
                },
                "malformed DNS query: unexpected end of input reached",
                1,
            ),
            (
                DnsRejected::CompressedQuestion,
                "malformed DNS query: compression pointer in the question name",
                1,
            ),
            (
                DnsRejected::UnexpectedAdditional { rtype: 1 },
                "malformed DNS query: additional record of type 1 (only one OPT is accepted)",
                1,
            ),
            (
                DnsRejected::TrailingBytes { extra: 3 },
                "malformed DNS query: 3 trailing byte(s) after the last record",
                1,
            ),
            (
                DnsRejected::BadEdnsVersion { version: 1 },
                "unsupported EDNS version 1 (EDNS0 only)",
                16,
            ),
            (
                DnsRejected::NotInClass { qclass: 3 },
                "DNS class 3 is not IN",
                5,
            ),
            (
                DnsRejected::InvalidName {
                    qname: "a\\032b.test".to_owned(),
                },
                "query name a\\032b.test is not a valid hostname",
                3,
            ),
            (
                DnsRejected::NotAllowed {
                    name: dom("example.com"),
                },
                "example.com is not in the policy allow list",
                3,
            ),
        ];
        for (rejected, reason, rcode) in cases {
            assert_eq!(rejected.reason(), reason);
            assert_eq!(rejected.rcode(), rcode, "{rejected:?}");
        }
    }

    #[test]
    fn dns_failed_reasons_pinned() {
        assert_eq!(
            DnsFailed::PoolExhausted.reason(),
            "fake-IP pool 198.18.0.0/15 exhausted"
        );
        assert_eq!(DnsFailed::PoolExhausted.rcode(), Some(5));
        assert_eq!(
            DnsFailed::MapUnavailable.reason(),
            "fake-IP map unavailable (lock poisoned)"
        );
        assert_eq!(DnsFailed::MapUnavailable.rcode(), Some(5));
        let encode = DnsFailed::Encode {
            detail: "boom".to_owned(),
        };
        assert_eq!(encode.reason(), "DNS response encoding failed: boom");
        assert_eq!(encode.rcode(), None);
        assert_eq!(
            DnsFailed::Internal.reason(),
            "internal error while handling the DNS datagram (panic caught)"
        );
        assert_eq!(DnsFailed::Internal.rcode(), None);
    }

    #[test]
    fn dns_dropped_reasons_pinned() {
        assert_eq!(
            DnsDropped::Short { len: 5 }.reason(),
            "datagram of 5 byte(s) is shorter than a DNS header"
        );
        assert_eq!(
            DnsDropped::NotAQuery.reason(),
            "DNS response (QR=1) received on the resolver socket"
        );
    }

    #[test]
    fn verdict_labels_pinned() {
        let name = dom("allowed.test");
        assert_eq!(
            DnsVerdict::Answered {
                name: name.clone(),
                ip: Ipv4Addr::LOCALHOST
            }
            .label(),
            "answered"
        );
        assert_eq!(DnsVerdict::NoData { name, qtype: 28 }.label(), "nodata");
        assert_eq!(
            DnsVerdict::Denied(DnsRejected::CompressedQuestion).label(),
            "denied"
        );
        assert_eq!(
            DnsVerdict::Dropped(DnsDropped::NotAQuery).label(),
            "dropped"
        );
        assert_eq!(DnsVerdict::Error(DnsFailed::Internal).label(), "error");
    }

    #[test]
    fn verdict_rcodes_pinned() {
        let name = dom("allowed.test");
        assert_eq!(
            DnsVerdict::Answered {
                name: name.clone(),
                ip: Ipv4Addr::LOCALHOST
            }
            .rcode(),
            Some(0)
        );
        assert_eq!(DnsVerdict::NoData { name, qtype: 28 }.rcode(), Some(0));
        assert_eq!(
            DnsVerdict::Denied(DnsRejected::BadEdnsVersion { version: 2 }).rcode(),
            Some(16)
        );
        assert_eq!(DnsVerdict::Dropped(DnsDropped::NotAQuery).rcode(), None);
        assert_eq!(DnsVerdict::Error(DnsFailed::PoolExhausted).rcode(), Some(5));
        assert_eq!(DnsVerdict::Error(DnsFailed::Internal).rcode(), None);
    }

    #[test]
    fn answered_nodata_reasons_pinned() {
        let answered = DnsVerdict::Answered {
            name: dom("pypi.org"),
            ip: Ipv4Addr::new(198, 18, 0, 1),
        };
        assert_eq!(answered.reason(), "answered pypi.org A 198.18.0.1");
        let nodata = DnsVerdict::NoData {
            name: dom("pypi.org"),
            qtype: 28,
        };
        assert_eq!(nodata.reason(), "NODATA for pypi.org type 28 (A only)");
    }

    #[test]
    fn audit_escaper_table() {
        let escape = |labels: &[&[u8]]| {
            dns_name_for_audit(&Name::from_labels(labels.iter().copied()).expect("name"))
        };
        assert_eq!(escape(&[b"PyPI", b"org"]), "PyPI.org");
        assert_eq!(dns_name_for_audit(&Name::root()), ".");
        assert_eq!(escape(&[b"a.\xff"]), "a\\.\\255");
        assert_eq!(escape(&[b"a b", b"test"]), "a\\032b.test");
        assert_eq!(escape(&[b"a\\b"]), "a\\\\b");
        // Three 63-byte labels of 0xff: 193 wire bytes, but 758 audit bytes
        // (each byte escapes to \DDD), so the cap applies.
        let escaped_big = Name::from_labels([vec![0xffu8; 63], vec![0xffu8; 63], vec![0xffu8; 63]])
            .expect("name fits 255 wire bytes");
        let audit = dns_name_for_audit(&escaped_big);
        assert_eq!(audit.len(), AUDIT_TEXT_CAP);
        assert!(audit.ends_with("..."));
        assert!(audit.starts_with("\\255\\255"));
    }

    #[test]
    fn sanitize_detail_table() {
        assert_eq!(sanitize_detail("ok text"), "ok text");
        assert_eq!(sanitize_detail("tab\there\x7f"), "tab?here?");
        assert_eq!(sanitize_detail("é"), "?");
        let capped = sanitize_detail(&"x".repeat(300));
        assert_eq!(capped.len(), AUDIT_TEXT_CAP);
        assert!(capped.ends_with("..."));
    }

    // ---- pipeline (no sockets) ----------------------------------------------

    #[test]
    fn a_allowed_answers_and_maps_before_return() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let (decision, reply) = handle(&server, &a_query(0x1111, "allowed.test"));
        let expected = Ipv4Addr::new(198, 18, 0, 1);
        assert_eq!(
            decision.verdict,
            DnsVerdict::Answered {
                name: dom("allowed.test"),
                ip: expected
            }
        );
        assert_eq!(
            map.ip_for(&dom("allowed.test")),
            Some(expected),
            "mapped before the reply returns"
        );
        let reply = reply.expect("a reply");
        assert_eq!(rcode_of(&reply), 0);
        assert_eq!(&reply[reply.len() - 4..], &[198, 18, 0, 1]);
        assert_eq!(decision.question.as_ref().map(|q| q.qtype), Some(1));
    }

    #[test]
    fn suffix_subdomain_allowed() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let (decision, _) = handle(&server, &a_query(1, "sub.allowed.test"));
        assert!(
            matches!(decision.verdict, DnsVerdict::Answered { .. }),
            "{:?}",
            decision.verdict
        );
    }

    #[test]
    fn bare_suffix_not_allowed() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let (decision, reply) = handle(&server, &a_query(2, "evilallowed.test"));
        assert!(matches!(
            decision.verdict,
            DnsVerdict::Denied(DnsRejected::NotAllowed { .. })
        ));
        assert_eq!(rcode_of(&reply.expect("reply")), 3);
        assert!(map.is_empty());
    }

    #[test]
    fn case_folds_to_one_ip() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let (upper, _) = handle(&server, &a_query(3, "ALLOWED.test"));
        let (lower, _) = handle(&server, &a_query(4, "allowed.test"));
        let ip_of = |d: &DnsDecision| match &d.verdict {
            DnsVerdict::Answered { ip, .. } => *ip,
            other => panic!("{other:?}"),
        };
        assert_eq!(ip_of(&upper), ip_of(&lower));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn aaaa_nodata_no_allocation() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let (decision, reply) = handle(&server, &query(5, &dotted("allowed.test"), 28, 1, None));
        assert!(matches!(
            decision.verdict,
            DnsVerdict::NoData { qtype: 28, .. }
        ));
        let reply = reply.expect("reply");
        assert_eq!(rcode_of(&reply), 0);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0, "no answers");
        assert!(map.is_empty(), "NODATA allocates nothing");
    }

    #[test]
    fn other_qtypes_nodata() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        for qtype in [16u16, 255, 12, 65280] {
            let (decision, reply) =
                handle(&server, &query(6, &dotted("allowed.test"), qtype, 1, None));
            assert!(
                matches!(decision.verdict, DnsVerdict::NoData { .. }),
                "qtype {qtype}"
            );
            assert_eq!(rcode_of(&reply.expect("reply")), 0);
        }
        assert!(map.is_empty());
    }

    #[test]
    fn not_allowed_nxdomain_any_qtype() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        for qtype in [1u16, 28, 16] {
            let (decision, reply) = handle(
                &server,
                &query(7, &dotted("notallowed.test"), qtype, 1, None),
            );
            assert!(matches!(
                decision.verdict,
                DnsVerdict::Denied(DnsRejected::NotAllowed { .. })
            ));
            assert_eq!(rcode_of(&reply.expect("reply")), 3);
        }
    }

    #[test]
    fn invalid_names_nxdomain() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let names: Vec<Vec<u8>> = vec![
            wire_name(&[b"a b", b"test"]),
            wire_name(&[b"*", b"test"]),
            wire_name(&[b"\xff", b"test"]),
            wire_name(&[b"a.b", b"test"]),
            wire_name(&[b"1", b"2", b"3", b"4"]),
            wire_name(&[b"xn--zz", b"test"]),
            vec![0],
        ];
        for name in names {
            let (decision, reply) = handle(&server, &query(8, &name, 1, 1, None));
            assert!(
                matches!(
                    decision.verdict,
                    DnsVerdict::Denied(DnsRejected::InvalidName { .. })
                ),
                "{:?}",
                decision.verdict
            );
            assert_eq!(rcode_of(&reply.expect("reply")), 3);
        }
    }

    #[test]
    fn class_not_in_refused() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        for class in [3u16, 255] {
            let (decision, reply) =
                handle(&server, &query(9, &dotted("allowed.test"), 1, class, None));
            assert_eq!(decision.verdict.rcode(), Some(5));
            assert_eq!(decision.reason(), format!("DNS class {class} is not IN"));
            assert_eq!(rcode_of(&reply.expect("reply")), 5);
        }
    }

    #[test]
    fn edns_echo_minimal() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        // AAAA with an OPT (version 0, DO set): NODATA, OPT echoed minimal.
        let q = query(10, &dotted("allowed.test"), 28, 1, Some((0, true)));
        let (_decision, reply) = handle(&server, &q);
        let reply = reply.expect("reply");
        // OPT starts with root name 0x00, type 41, class (payload) 1232 = 0x04d0.
        let opt_at = reply.len() - 11;
        assert_eq!(&reply[opt_at..opt_at + 5], &[0x00, 0x00, 41, 0x04, 0xd0]);
        assert_eq!(reply[opt_at + 6], 0x00, "EDNS version 0");
        assert_eq!(reply[opt_at + 7] & 0x80, 0, "DO clear");
    }

    #[test]
    fn edns_badvers() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let q = query(11, &dotted("allowed.test"), 1, 1, Some((1, false)));
        let (decision, reply) = handle(&server, &q);
        assert_eq!(decision.reason(), "unsupported EDNS version 1 (EDNS0 only)");
        let reply = reply.expect("reply");
        // Extended rcode lives in the OPT TTL's first byte: 1 << 4 = 16 (BADVERS).
        let opt_at = reply.len() - 11;
        assert_eq!(reply[opt_at + 5], 0x01);
    }

    #[test]
    fn ptr_for_fake_ip_nxdomain() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let ip = map.allocate(&dom("allowed.test")).expect("alloc");
        let [a, b, c, d] = ip.octets();
        let ptr = wire_name(&[
            d.to_string().as_bytes(),
            c.to_string().as_bytes(),
            b.to_string().as_bytes(),
            a.to_string().as_bytes(),
            b"in-addr",
            b"arpa",
        ]);
        let (decision, reply) = handle(&server, &query(12, &ptr, 12, 1, None));
        assert!(matches!(
            decision.verdict,
            DnsVerdict::Denied(DnsRejected::NotAllowed { .. })
        ));
        assert_eq!(rcode_of(&reply.expect("reply")), 3);
    }

    #[test]
    fn exhaustion_refused_pinned_reason_existing_keep_answering() {
        let limits = DnsLimits { max_names: 2 };
        let (server, _map, _sink) = server_with(&["allowed.test"], limits);
        let names = ["a.allowed.test", "b.allowed.test", "c.allowed.test"];
        let (a, _) = handle(&server, &a_query(20, names[0]));
        let (b, _) = handle(&server, &a_query(21, names[1]));
        let (c, reply) = handle(&server, &a_query(22, names[2]));
        assert_eq!(c.verdict, DnsVerdict::Error(DnsFailed::PoolExhausted));
        assert_eq!(c.reason(), "fake-IP pool 198.18.0.0/15 exhausted");
        assert_eq!(rcode_of(&reply.expect("reply")), 5);
        let (again, _) = handle(&server, &a_query(23, names[0]));
        assert_eq!(again.verdict, a.verdict, "existing mapping keeps answering");
        assert!(matches!(b.verdict, DnsVerdict::Answered { .. }));
    }

    #[test]
    fn poisoned_map_refused() {
        let (server, map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        map.poison_for_test();
        let (decision, reply) = handle(&server, &a_query(24, "allowed.test"));
        assert_eq!(
            decision.verdict,
            DnsVerdict::Error(DnsFailed::MapUnavailable)
        );
        assert_eq!(rcode_of(&reply.expect("reply")), 5);
    }

    #[test]
    fn drops_formerr_notimp_decisions() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());

        let (short, reply) = handle(&server, &[1, 2, 3, 4, 5]);
        assert_eq!(
            short.verdict,
            DnsVerdict::Dropped(DnsDropped::Short { len: 5 })
        );
        assert!(short.question.is_none() && reply.is_none());

        let mut response = a_query(1, "allowed.test");
        response[2] |= 0x80;
        let (qr, reply) = handle(&server, &response);
        assert_eq!(qr.verdict, DnsVerdict::Dropped(DnsDropped::NotAQuery));
        assert!(reply.is_none());

        let mut opcode5 = a_query(3, "allowed.test");
        opcode5[2] |= 0x28;
        let (notimp, reply) = handle(&server, &opcode5);
        assert_eq!(notimp.verdict.rcode(), Some(4));
        assert!(
            notimp.question.is_none(),
            "the gate answers before any decode"
        );
        assert_eq!(rcode_of(&reply.expect("reply")), 4);

        let mut counts = a_query(4, "allowed.test");
        counts[5] = 2;
        let (formerr, reply) = handle(&server, &counts);
        assert!(matches!(
            formerr.verdict,
            DnsVerdict::Denied(DnsRejected::BadCounts { .. })
        ));
        assert!(formerr.question.is_none());
        assert_eq!(rcode_of(&reply.expect("reply")), 1);

        let mut trailing = a_query(5, "allowed.test");
        trailing.push(0);
        let (extra, _) = handle(&server, &trailing);
        assert_eq!(
            extra.verdict,
            DnsVerdict::Denied(DnsRejected::TrailingBytes { extra: 1 })
        );
        assert!(
            extra.question.is_some(),
            "the question decoded, so it is audited"
        );
    }

    #[test]
    fn pipeline_order_canaries() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());

        // opcode 5 AND bad counts: the opcode check comes first.
        let mut both = a_query(30, "notallowed.test");
        both[2] |= 0x28;
        both[5] = 2;
        assert_eq!(handle(&server, &both).0.verdict.rcode(), Some(4));

        // QR AND bad counts: the QR drop comes first.
        let mut qr = a_query(31, "notallowed.test");
        qr[2] |= 0x80;
        qr[5] = 2;
        assert!(matches!(
            handle(&server, &qr).0.verdict,
            DnsVerdict::Dropped(_)
        ));

        // EDNS v1 AND a not-allowed name: BADVERS, not NXDOMAIN.
        let v1 = query(32, &dotted("notallowed.test"), 1, 1, Some((1, false)));
        assert_eq!(handle(&server, &v1).0.verdict.rcode(), Some(16));

        // Class CH AND a not-allowed name: REFUSED, not NXDOMAIN.
        let ch = query(33, &dotted("notallowed.test"), 1, 3, None);
        assert_eq!(handle(&server, &ch).0.verdict.rcode(), Some(5));

        // Invalid labels on a non-A qtype: NXDOMAIN, not NODATA.
        let bad = wire_name(&[b"a b", b"test"]);
        assert_eq!(
            handle(&server, &query(34, &bad, 28, 1, None))
                .0
                .verdict
                .rcode(),
            Some(3)
        );
    }

    // ---- socket tier ----------------------------------------------------------

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Bind a loopback resolver socket and spawn `serve_dns` on the runtime.
    fn spawn_server(
        server: Arc<DnsServer>,
    ) -> (SocketAddr, tokio::task::JoinHandle<io::Result<Infallible>>) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = socket.local_addr().expect("addr");
        (addr, tokio::spawn(serve_dns(socket, server)))
    }

    async fn exchange(
        client: &tokio::net::UdpSocket,
        server: SocketAddr,
        datagram: &[u8],
    ) -> Option<Vec<u8>> {
        client.send_to(datagram, server).await.expect("send");
        let mut buf = vec![0u8; 65_535];
        match tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf)).await {
            Ok(got) => {
                let (n, _) = got.expect("recv");
                Some(buf[..n].to_vec())
            }
            Err(_) => None,
        }
    }

    #[test]
    fn serve_dns_answers_over_udp() {
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let rt = runtime();
        rt.block_on(async {
            let (addr, task) = spawn_server(Arc::clone(&server));
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client");
            let reply = exchange(&client, addr, &a_query(0x4242, "allowed.test"))
                .await
                .expect("reply");
            assert_eq!(&reply[..2], &[0x42, 0x42]);
            assert_eq!(rcode_of(&reply), 0);
            assert_eq!(&reply[reply.len() - 4..], &[198, 18, 0, 1]);
            task.abort();
            assert!(task.await.expect_err("aborted").is_cancelled());
        });
    }

    #[test]
    fn serve_dns_records_drops_in_order() {
        let (server, _map, sink) = server_with(&["allowed.test"], DnsLimits::default());
        let rt = runtime();
        rt.block_on(async {
            let (addr, task) = spawn_server(Arc::clone(&server));
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client");
            client.send_to(&[1, 2, 3, 4, 5], addr).await.expect("send");
            let reply = exchange(&client, addr, &a_query(7, "allowed.test"))
                .await
                .expect("reply");
            assert_eq!(&reply[..2], &[0, 7], "the short datagram got no reply");
            let recorded = sink.take();
            assert_eq!(recorded.len(), 2);
            assert_eq!(
                recorded[0].verdict,
                DnsVerdict::Dropped(DnsDropped::Short { len: 5 })
            );
            assert!(matches!(recorded[1].verdict, DnsVerdict::Answered { .. }));
            task.abort();
            let _ = task.await;
        });
    }

    #[derive(Default)]
    struct PanicOnceSink {
        panicked: std::sync::atomic::AtomicBool,
        seen: Mutex<Vec<DnsVerdict>>,
    }

    impl DnsSink for PanicOnceSink {
        fn record(&self, decision: &DnsDecision) {
            if !self
                .panicked
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                panic!("sink panics on the first record on purpose");
            }
            self.seen
                .lock()
                .expect("lock")
                .push(decision.verdict.clone());
        }
    }

    #[test]
    fn serve_dns_sink_panic_drops_reply_then_recovers() {
        let sink = Arc::new(PanicOnceSink::default());
        let network = policy::Network {
            mode: policy::NetworkMode::Transparent,
            allow: vec![dom("allowed.test")],
            ports: vec![443],
        };
        let server = DnsServer::new(
            &network,
            Arc::new(FakeIpMap::new(&DnsLimits::default())),
            sink.clone(),
        );
        let rt = runtime();
        rt.block_on(async {
            let (addr, task) = spawn_server(server);
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client");
            client
                .send_to(&a_query(1, "allowed.test"), addr)
                .await
                .expect("send");
            client
                .send_to(&a_query(2, "allowed.test"), addr)
                .await
                .expect("send");
            let mut buf = vec![0u8; 512];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .expect("a reply arrives")
                .expect("recv");
            assert_eq!(
                &buf[..2],
                &[0, 2],
                "the first reply was dropped, the second arrives"
            );
            assert!(n > 0);
            task.abort();
            let _ = task.await;
            assert_eq!(sink.seen.lock().expect("lock").len(), 1);
        });
    }

    #[test]
    fn serve_dns_large_datagram_not_truncated() {
        let (server, _map, sink) = server_with(&["allowed.test"], DnsLimits::default());
        let rt = runtime();
        rt.block_on(async {
            let (addr, task) = spawn_server(Arc::clone(&server));
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("client");
            let mut big = a_query(9, "allowed.test");
            // Just under the 64 KiB receive buffer: nothing may be truncated.
            big.resize(65_000, 0);
            let reply = exchange(&client, addr, &big).await.expect("reply");
            assert_eq!(rcode_of(&reply), 1, "FORMERR");
            let recorded = sink.take();
            assert_eq!(
                recorded[0].verdict,
                // The question ends at byte 30 (12 header + 14 name + 4), so 64_970 trail.
                DnsVerdict::Denied(DnsRejected::TrailingBytes { extra: 64_970 }),
            );
            task.abort();
            let _ = task.await;
        });
    }

    #[test]
    fn serve_dns_exits_on_enotsock() {
        use std::os::fd::{FromRawFd, OwnedFd};
        let mut fds = [0i32; 2];
        // SAFETY: pipe(2) writes two fds into the array; both are owned below.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SAFETY: fresh fds from pipe(2), owned by nothing else.
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: as above.
        let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        // SAFETY: writing one byte to the pipe we own.
        let n = unsafe {
            libc::write(
                std::os::fd::AsRawFd::as_raw_fd(&write_end),
                b"x".as_ptr().cast(),
                1,
            )
        };
        assert_eq!(n, 1);
        let socket = std::net::UdpSocket::from(read_end);
        let (server, _map, _sink) = server_with(&["allowed.test"], DnsLimits::default());
        let rt = runtime();
        let err = rt.block_on(async {
            let outcome = tokio::time::timeout(Duration::from_secs(5), serve_dns(socket, server))
                .await
                .expect("serve_dns exits");
            outcome.expect_err("a non-socket fd is fatal")
        });
        assert_eq!(err.raw_os_error(), Some(libc::ENOTSOCK));
        drop(write_end);
    }

    #[test]
    fn io_error_tables_pinned() {
        let os = io::Error::from_raw_os_error;
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            assert!(recv_error_is_fatal(&os(code)), "recv {code} is fatal");
        }
        for code in [
            libc::EAGAIN,
            libc::EINTR,
            libc::ENOMEM,
            libc::ENOBUFS,
            libc::ECONNREFUSED,
        ] {
            assert!(!recv_error_is_fatal(&os(code)), "recv {code} is transient");
        }
        assert!(!recv_error_is_fatal(&io::Error::other("not an OS error")));
        for code in [libc::EBADF, libc::ENOTSOCK] {
            assert!(send_error_is_fatal(&os(code)), "send {code} is fatal");
        }
        for code in [
            libc::EINVAL,
            libc::EPERM,
            libc::ENOBUFS,
            libc::EHOSTUNREACH,
            libc::ECONNREFUSED,
            libc::EMSGSIZE,
        ] {
            assert!(!send_error_is_fatal(&os(code)), "send {code} is transient");
        }
    }

    #[test]
    fn dns_recv_buf_pinned() {
        assert_eq!(DNS_RECV_BUF, 64 * 1024);
        assert_eq!(FAKE_TTL, 60);
    }
}
