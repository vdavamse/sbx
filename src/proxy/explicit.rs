//! The explicit HTTP forward proxy (issue #8): `CONNECT host:port` and
//! absolute-form `http://` requests, served on the listener fd #10 hands
//! over as `ListenerFds::explicit` (127.0.0.1:3128).
//!
//! 1. **Scope** — the same policy and inspectors as the transparent path
//!    (module docs of [`crate::proxy`] point 13), reached by an explicit
//!    request instead of `SO_ORIGINAL_DST`. The name comes from the request
//!    target, never from a DNS map, so [`crate::proxy::DnsMap`] is never
//!    consulted on this path.
//! 2. **Ports** — `CONNECT :443` → TLS inspector (SNI must equal the CONNECT
//!    host); `CONNECT :80` → HTTP inspector INSIDE the tunnel; absolute-form
//!    is port 80 only; any other policy-listed port → `NoInspector` (403).
//! 3. **Target grammar** — authority-form `host:port` for CONNECT: a domain
//!    name only; IP literals (bracketed, zoned, dotted, inet_aton shapes),
//!    userinfo, non-ASCII, and missing/invalid ports are denied. Absolute-
//!    form: `http://` only, same authority rules, port defaults to 80.
//! 4. **Host** — exactly one `Host` header (D1: an HTTP/1.0 CONNECT may omit
//!    it — the CONNECT target is the sole authority); its name and port
//!    suffix must match the target (Q2).
//! 5. **Framing** — CONNECT carries no body (D6: at most one
//!    `Content-Length: 0`); the strict table (Q8) denies CL+TE, duplicate or
//!    malformed CL, and non-final-chunked TE on every explicit request.
//! 6. **Order (Q7)** — scope A (under `decision_timeout`): read head → parse
//!    → port → inspector → allow list → head checks → (CONNECT) write
//!    `200` → inspect the tunnel's first bytes. Scope B (after A closes):
//!    dial via [`crate::proxy::connect_upstream`]. The inspection-before-
//!    connect order is the lock: no upstream socket exists before the SNI
//!    (or the tunnelled HTTP head) has passed.
//! 7. **Responses (Q5)** — exactly one table, [`explicit_response`]. Before
//!    the `200`: 400 malformed, 403 policy, 502/504 for forward-only
//!    infrastructure failures, silence for timeouts and EOF. After the `200`
//!    there is no HTTP status to send, so every post-tunnel denial is a
//!    silent close. Every deny response is `Content-Length: 0` +
//!    `Connection: close`, followed by [`crate::proxy::relay::linger_close`]
//!    (D5).
//! 8. **Forward rewrite (Q6/D7)** — the forward head is REBUILT from the
//!    validated parse, not patched: origin-form target, fragment dropped,
//!    `Proxy-*` and `Connection`/`Keep-Alive`/`Upgrade` dropped, one
//!    `Connection: close` added. Fields named by a `Connection` token are
//!    kept. Known residual, documented not denied: a target such as
//!    `//host/path` is origin-form (no scheme) and is forwarded as-is.
//! 9. **Tunnel residuals** — bytes pipelined after the CONNECT head are
//!    chained into the inspector ([`finish_residual`] appends whatever the
//!    inspector did not reach). What the upstream receives: on 443 the
//!    client's bytes verbatim (CH1 plus any pipelined tail, in order); on 80
//!    the inspected request head with the `Connection: close` rewrite
//!    (module docs point 6 of `http`), then the rest verbatim; on forward
//!    requests the REBUILT head (point 8) followed by the verbatim body.
//! 10. **Residuals (documented, not fixed in #8)** — (a) a CONNECT dial failure
//!     after the `200` is a silent close; (b) body framing beyond the strict
//!     table is deferred (F3); (c) pipelined second requests on a kept-alive
//!     connection are not inspected: on 80 the `Connection: close` rewrite
//!     covers only the first request, so a second request with a foreign
//!     `Host` could reach a shared vhost (the h2/vhost-confusion class, #14);
//!     (d) fields named by a `Connection` token are forwarded.
//! 11. **Audit (Q10)** — one [`Decision`] per connection, recorded before
//!     any relay byte or deny response. Client-derived text in reasons is
//!     [`crate::proxy::redact_for_audit`]ed: authority only, no path, query,
//!     or headers, capped at 256 bytes. (The post-`200` dial-failure
//!     residual is listed once, in point 10.)

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Chain};
use tokio::net::TcpStream;

use super::http::{self, Framing, HeadCheck};
use super::relay::linger_close;
use super::{
    Connected, Decision, ExplicitKind, Failed, Limits, NameSource, Proxy, Rejected, RelayMode,
    Verdict, Via, connect_upstream, hello, redact_for_audit,
};
use crate::egress;
use crate::policy::Domain;

/// The CONNECT success line (proxy-to-client, before the tunnel opens).
pub(crate) const RESPONSE_CONNECT_ESTABLISHED: &[u8] =
    b"HTTP/1.1 200 Connection established\r\n\r\n";
/// Malformed or unsupported request (before the tunnel opens).
pub(crate) const RESPONSE_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// Policy denial (before the tunnel opens).
pub(crate) const RESPONSE_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// Forward-only upstream failure (resolve, empty answer, refused dial).
pub(crate) const RESPONSE_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// Forward-only upstream timeout.
pub(crate) const RESPONSE_504: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Pinned fragments for [`Rejected::ConnectTargetInvalid`] and
/// [`Rejected::RequestTargetInvalid`] (the `detail` fields).
pub(crate) const TARGET_NOT_ASCII: &str = "non-ASCII bytes in the target";
pub(crate) const TARGET_NOT_AUTHORITY: &str = "not authority-form host:port";
pub(crate) const TARGET_USERINFO: &str = "userinfo is not allowed";
pub(crate) const TARGET_IP_LITERAL: &str = "IP literals are not allowed; use a domain name";
pub(crate) const TARGET_MISSING_PORT: &str = "missing :port";
pub(crate) const TARGET_BAD_PORT: &str = "port must be 1-65535 in canonical decimal";
pub(crate) const TARGET_BAD_HOST: &str = "host is not a valid domain name";

/// The response table (issue #8, Q5 / module docs point 7). `None` = send
/// nothing (silent close). Exhaustive on purpose: a new [`Rejected`] or
/// [`Failed`] variant must pick a status here.
pub(crate) fn explicit_response(verdict: &Verdict, tunnel_open: bool) -> Option<&'static [u8]> {
    if tunnel_open {
        // The client already saw `200`: there is no HTTP status left to send.
        return None;
    }
    match verdict {
        Verdict::Allowed { .. } => None,
        Verdict::Denied(rejected) => match rejected {
            Rejected::PortNotAllowed { .. }
            | Rejected::NoInspector { .. }
            | Rejected::UnknownFakeIp { .. }
            | Rejected::NotAllowed { .. }
            | Rejected::SniMismatch { .. }
            | Rejected::SniMissing
            | Rejected::EchOffered
            | Rejected::HostMismatch { .. }
            | Rejected::HostPortMismatch { .. }
            | Rejected::TargetMismatch { .. }
            | Rejected::DialDenied { .. } => Some(RESPONSE_403),
            Rejected::HeadTooLarge { .. }
            | Rejected::HttpMalformed { .. }
            | Rejected::Http2Preface
            | Rejected::ConnectMethod
            | Rejected::HostMissing
            | Rejected::HostMultiple
            | Rejected::HostNotUtf8
            | Rejected::HostInvalid { .. }
            | Rejected::NotProxyRequest
            | Rejected::ConnectTargetInvalid { .. }
            | Rejected::RequestTargetInvalid { .. }
            | Rejected::TargetSchemeUnsupported { .. }
            | Rejected::ConnectHasBody
            | Rejected::AmbiguousFraming { .. }
            | Rejected::NotTls { .. }
            | Rejected::HelloTooLarge { .. }
            | Rejected::HelloMalformed { .. } => Some(RESPONSE_400),
            Rejected::OriginalDst { .. } | Rejected::Eof | Rejected::DecisionTimeout { .. } => None,
        },
        Verdict::Error(failed) => match failed {
            Failed::Resolve { .. } | Failed::EmptyResolve { .. } | Failed::Connect { .. } => {
                Some(RESPONSE_502)
            }
            Failed::ConnectTimeout { .. } => Some(RESPONSE_504),
        },
    }
}

/// A parsed explicit request head (issue #8, T3).
pub(crate) struct ProxyRequest {
    pub kind: ExplicitKind,
    /// The request method exactly as the client sent it.
    pub method: String,
    pub host: Domain,
    pub port: u16,
    /// The HTTP/1.x minor version (0 or 1). Absent ⇒ treated as 1.
    pub minor_version: u8,
    /// Absolute-form only: the origin-form request-target to send upstream.
    pub origin_form: Option<String>,
}

/// Absolute-form only when `://` comes before any path, query, or fragment
/// delimiter (issue #8, m6): `GET /x?u=http://evil` is origin-form, so it
/// is NotProxyRequest, never a forward to a host in the query.
fn is_absolute_form(target: &str) -> bool {
    match (target.find("://"), target.find(['/', '?', '#'])) {
        (Some(scheme), Some(delim)) => scheme < delim,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// A parse failure with the request shape known so far.
#[derive(Debug)]
pub(crate) struct ParseFail {
    pub kind: ExplicitKind,
    pub rejected: Rejected,
}

fn fail(kind: ExplicitKind, rejected: Rejected) -> ParseFail {
    ParseFail { kind, rejected }
}

/// Parse one explicit request head (issue #8, T3). Pure: no I/O, no policy.
pub(crate) fn parse_proxy_request(
    buf: &[u8],
    head_end: usize,
    max_headers: usize,
) -> Result<ProxyRequest, ParseFail> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(buf) {
        Err(err) => {
            let rejected = if buf.starts_with(b"PRI * HTTP/2.0") {
                Rejected::Http2Preface
            } else {
                Rejected::HttpMalformed {
                    detail: err.to_string(),
                }
            };
            return Err(fail(ExplicitKind::Unknown, rejected));
        }
        Ok(httparse::Status::Partial) => {
            return Err(fail(
                ExplicitKind::Unknown,
                Rejected::HttpMalformed {
                    detail: "incomplete request head".to_owned(),
                },
            ));
        }
        Ok(httparse::Status::Complete(consumed)) => consumed,
    };
    if consumed != head_end {
        return Err(fail(
            ExplicitKind::Unknown,
            Rejected::HttpMalformed {
                detail: http::HEAD_TERMINATOR_MISMATCH.to_owned(),
            },
        ));
    }
    let minor_version = request.version.unwrap_or(1);
    let (Some(method), Some(target)) = (request.method, request.path) else {
        return Err(fail(
            ExplicitKind::Unknown,
            Rejected::HttpMalformed {
                detail: "missing method or request-target".to_owned(),
            },
        ));
    };
    if method == "CONNECT" {
        return match parse_authority(target, None, true) {
            Ok((host, port)) => Ok(ProxyRequest {
                kind: ExplicitKind::Connect,
                method: method.to_owned(),
                host,
                port,
                minor_version,
                origin_form: None,
            }),
            Err(detail) => Err(fail(
                ExplicitKind::Connect,
                Rejected::ConnectTargetInvalid {
                    target: redact_for_audit(target),
                    detail,
                },
            )),
        };
    }
    if is_absolute_form(target) {
        return match parse_absolute_target(target, method) {
            Ok((host, port, origin_form)) => Ok(ProxyRequest {
                kind: ExplicitKind::Forward,
                method: method.to_owned(),
                host,
                port,
                minor_version,
                origin_form: Some(origin_form),
            }),
            Err(rejected) => Err(fail(ExplicitKind::Forward, rejected)),
        };
    }
    Err(fail(ExplicitKind::Unknown, Rejected::NotProxyRequest))
}

/// Authority-form (`host:port`, CONNECT) or the authority of an absolute-
/// form target (`default_port` = 80). Returns the canonical name and port,
/// or a pinned detail fragment (issue #8, T3 order is load-bearing).
pub(crate) fn parse_authority(
    auth: &str,
    default_port: Option<u16>,
    connect: bool,
) -> Result<(Domain, u16), &'static str> {
    if !auth.is_ascii() {
        return Err(TARGET_NOT_ASCII);
    }
    if connect && auth.contains(['/', '?', '#']) {
        return Err(TARGET_NOT_AUTHORITY);
    }
    if auth.contains('@') {
        return Err(TARGET_USERINFO);
    }
    if auth.starts_with('[') || auth.parse::<std::net::IpAddr>().is_ok() {
        return Err(TARGET_IP_LITERAL);
    }
    let (host_raw, port) = match auth.rsplit_once(':') {
        Some((host, digits)) => {
            let well_formed = !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|b| b.is_ascii_digit())
                && !digits.starts_with('0');
            let port = if well_formed {
                digits.parse::<u16>().ok().filter(|p| *p != 0)
            } else {
                None
            };
            match port {
                Some(port) => (host, port),
                None => return Err(TARGET_BAD_PORT),
            }
        }
        None => match default_port {
            Some(port) => (auth, port),
            None => return Err(TARGET_MISSING_PORT),
        },
    };
    if host_raw.parse::<std::net::IpAddr>().is_ok() {
        return Err(TARGET_IP_LITERAL);
    }
    // inet_aton shapes ("127.1", "123", "0x7f.1"): a numeric final label
    // is an address in disguise — deny before any name canonicalization.
    let last_label = host_raw.strip_suffix('.').unwrap_or(host_raw);
    let last_label = last_label.rsplit('.').next().unwrap_or(last_label);
    if !last_label.is_empty() && last_label.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TARGET_IP_LITERAL);
    }
    match super::canonicalize_host(host_raw) {
        Some(host) => Ok((host, port)),
        None => Err(TARGET_BAD_HOST),
    }
}

/// Absolute-form `http://authority/path` (issue #8, T3): http only, the
/// authority rules above with port 80 as the default. Returns the name, the
/// port, and the origin-form request-target (fragment dropped; `*`/`/`
/// when empty).
pub(crate) fn parse_absolute_target(
    target: &str,
    method: &str,
) -> Result<(Domain, u16, String), Rejected> {
    let invalid = |detail: &'static str| Rejected::RequestTargetInvalid {
        target: redact_for_audit(target),
        detail,
    };
    if !target.is_ascii() {
        return Err(invalid(TARGET_NOT_ASCII));
    }
    let Some((scheme, rest)) = target.split_once("://") else {
        return Err(Rejected::NotProxyRequest);
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(Rejected::TargetSchemeUnsupported {
            scheme: redact_for_audit(scheme),
        });
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (host, port) = parse_authority(&rest[..auth_end], Some(80), false).map_err(invalid)?;
    let remainder = rest[auth_end..].split('#').next().unwrap_or("");
    let origin = if remainder.is_empty() {
        if method == "OPTIONS" { "*" } else { "/" }.to_owned()
    } else if remainder.starts_with('?') {
        format!("/{remainder}")
    } else {
        remainder.to_owned()
    };
    Ok((host, port, origin))
}

/// Head-level checks for an explicit request (issue #8, T4): the Host
/// rules (D1 relaxes only the HTTP/1.0 CONNECT case), the strict framing
/// table, and the CONNECT no-body rule (D6).
pub(crate) fn check_proxy_head(
    head: &[u8],
    req: &ProxyRequest,
    max_headers: usize,
) -> Result<(), Rejected> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let request = reparse_head(head, &mut headers)?;
    let (source, require) = match req.kind {
        ExplicitKind::Connect => (
            NameSource::ConnectTarget,
            // D1: HTTP/1.0 CONNECT may omit Host; 1.1 must carry one.
            req.minor_version != 0,
        ),
        _ => (NameSource::RequestTarget, true),
    };
    http::check_host(request.headers, &req.host, req.port, source, require)?;
    if req.kind == ExplicitKind::Connect {
        let has_te = request
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
        if has_te {
            return Err(Rejected::ConnectHasBody);
        }
        if let Framing::Length(n) = http::check_framing(request.headers, req.minor_version)? {
            if n > 0 {
                return Err(Rejected::ConnectHasBody);
            }
        }
        return Ok(());
    }
    http::check_framing(request.headers, req.minor_version)?;
    Ok(())
}

/// Rebuild the absolute-form head as origin-form (issue #8, T4 / D7): the
/// method, the origin-form target, the HTTP version, every header that is
/// not hop-by-hop, and one `Connection: close`. The caller appends the
/// pipelined remainder verbatim.
pub(crate) fn rewrite_forward_head(
    head: &[u8],
    req: &ProxyRequest,
    max_headers: usize,
) -> Result<Vec<u8>, Rejected> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    // Fail closed: the head was validated already, so a re-parse failure
    // is a bug, but it must never be rebuilt with an invented method.
    let request = reparse_head(head, &mut headers)?;
    let origin = req.origin_form.as_deref().unwrap_or("/");
    let mut out = format!("{} {origin} HTTP/1.{}\r\n", req.method, req.minor_version).into_bytes();
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let hop_by_hop = name.starts_with("proxy-")
            || matches!(name.as_str(), "connection" | "keep-alive" | "upgrade");
        if hop_by_hop {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(out)
}

/// Re-parse a head that must be exactly one complete request: httparse
/// `Complete(n)` with `n == head.len()`. Anything else (`Partial`, trailing
/// bytes, an error) fails closed as HttpMalformed. httparse leaves the
/// header slice untouched on `Partial`, so reading it would silently skip
/// the Host and framing checks.
fn reparse_head<'h, 'b>(
    head: &'b [u8],
    headers: &'h mut [httparse::Header<'b>],
) -> Result<httparse::Request<'h, 'b>, Rejected> {
    let mut request = httparse::Request::new(headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => Ok(request),
        _ => Err(Rejected::HttpMalformed {
            detail: "request head re-parse failed".to_owned(),
        }),
    }
}

/// What [`decide_explicit`] hands back to the connection handler.
pub(crate) struct ExplicitDecided {
    pub decision: Decision,
    /// The CONNECT tunnel was opened (`200` written): deny silently.
    pub tunnel_open: bool,
    /// Present only on the allowed path.
    pub relay: Option<ExplicitRelay>,
}

/// The allowed path's relay state.
pub(crate) struct ExplicitRelay {
    pub replay: Vec<u8>,
    pub connected: Connected,
    pub mode: RelayMode,
}

/// Progress of one explicit connection, for the audit row.
struct Progress {
    kind: ExplicitKind,
    port: Option<u16>,
    name: Option<Domain>,
    tunnel_open: bool,
}

impl Progress {
    fn deny(&self, client: SocketAddr, rejected: Rejected) -> ExplicitDecided {
        ExplicitDecided {
            decision: self.decision(client, Verdict::Denied(rejected)),
            tunnel_open: self.tunnel_open,
            relay: None,
        }
    }

    fn decision(&self, client: SocketAddr, verdict: Verdict) -> Decision {
        Decision {
            client,
            via: Via::Explicit {
                kind: self.kind,
                port: self.port,
            },
            name: self.name.clone(),
            verdict,
        }
    }
}

/// Scope A (issue #8, Q7): everything before the upstream dial. Runs under
/// `decision_timeout` in the caller. Returns the replay buffer and the
/// relay mode on success.
async fn pre_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    proxy: &Proxy,
    st: &mut Progress,
) -> Result<(Vec<u8>, RelayMode), Rejected> {
    let limits: &Limits = &proxy.limits;
    let mut head = http::read_head(client, limits).await?;
    let req = match parse_proxy_request(&head.buf, head.head_end, limits.max_http_headers) {
        Ok(req) => req,
        Err(ParseFail { kind, rejected }) => {
            st.kind = kind;
            return Err(rejected);
        }
    };
    st.kind = req.kind;
    st.port = Some(req.port);
    st.name = Some(req.host.clone());
    // 1. Port policy.
    if !proxy.ports.contains(&req.port) {
        return Err(Rejected::PortNotAllowed { port: req.port });
    }
    // 2. Inspector (Q1): 443 and CONNECT 80 / forward 80 only.
    let inspectable = matches!(
        (req.kind, req.port),
        (ExplicitKind::Connect, 443) | (ExplicitKind::Connect, 80) | (ExplicitKind::Forward, 80)
    );
    if !inspectable {
        return Err(Rejected::NoInspector { port: req.port });
    }
    // 3. Allow list — the request-target name, never the DNS map. The
    //    RuleMatch is synchronous and dropped before any await.
    if egress::allowed(req.host.as_str(), &proxy.allow).is_none() {
        return Err(Rejected::NotAllowed {
            name: req.host.clone(),
        });
    }
    // 4. Head checks (Host, framing, CONNECT body).
    check_proxy_head(&head.buf[..head.head_end], &req, limits.max_http_headers)?;

    match req.kind {
        ExplicitKind::Forward => {
            let mut replay =
                rewrite_forward_head(&head.buf[..head.head_end], &req, limits.max_http_headers)?;
            replay.extend_from_slice(&head.buf[head.head_end..]);
            Ok((replay, RelayMode::CloseOnUpstreamEof))
        }
        // Fail closed BEFORE any `200`: parse_proxy_request never yields
        // Unknown on success, so this arm is only a backstop.
        ExplicitKind::Unknown => Err(Rejected::NotProxyRequest),
        ExplicitKind::Connect => {
            // 5. Open the tunnel. The flag is set BEFORE the write: a write
            //    failure after a partial 200 must also be silent.
            st.tunnel_open = true;
            client
                .write_all(RESPONSE_CONNECT_ESTABLISHED)
                .await
                .map_err(|_| Rejected::Eof)?;
            client.flush().await.map_err(|_| Rejected::Eof)?;
            // 6. Inspect the tunnel's first bytes; the pipelined residual
            //    is chained in front of the client stream.
            let residual = head.buf.split_off(head.head_end);
            let mut chained = (&residual[..]).chain(&mut *client);
            let (inspected, mode) = if req.port == 443 {
                let replay = hello::inspect_tls_from(
                    &mut chained,
                    &req.host,
                    NameSource::ConnectTarget,
                    limits,
                )
                .await?;
                let scan_from =
                    hello::first_record_end(&replay).ok_or_else(|| Rejected::HelloMalformed {
                        detail: hello::RECORD_END_LOST_DETAIL.to_owned(),
                    })?;
                (replay, RelayMode::Scanned { scan_from })
            } else {
                let check = HeadCheck {
                    expected: &req.host,
                    port: 80,
                    source: NameSource::ConnectTarget,
                    strict_framing: true,
                };
                let replay = http::inspect_http_with(&mut chained, &check, limits).await?;
                (replay, RelayMode::CloseOnUpstreamEof)
            };
            Ok((finish_residual(inspected, chained), mode))
        }
    }
}

/// The tunnel-residual step (issue #8, module docs point 9). `chained`
/// yielded the pipelined residual first and the client stream after it;
/// `inspected` is what the inspector consumed. The residual bytes the
/// inspector did not reach are appended here, so the replay is an in-order
/// prefix of the client's byte stream. LOAD-BEARING: without this append a
/// residual larger than one read chunk is silently dropped.
fn finish_residual<S: AsyncRead + Unpin>(
    mut inspected: Vec<u8>,
    chained: Chain<&[u8], &mut S>,
) -> Vec<u8> {
    let (rest, _client) = chained.into_inner();
    inspected.extend_from_slice(rest);
    inspected
}

/// The explicit pipeline (issue #8, Q7): scope A, then scope B (the dial).
/// Generic over the client stream so unit tests drive it over duplex.
pub(crate) async fn decide_explicit<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    client_addr: SocketAddr,
    proxy: &Proxy,
) -> ExplicitDecided {
    let mut st = Progress {
        kind: ExplicitKind::Unknown,
        port: None,
        name: None,
        tunnel_open: false,
    };
    let budget = proxy.limits.decision_timeout;
    let pre = match tokio::time::timeout(budget, pre_connect(client, proxy, &mut st)).await {
        Ok(Ok(pre)) => pre,
        Ok(Err(rejected)) => return st.deny(client_addr, rejected),
        Err(_elapsed) => {
            return st.deny(
                client_addr,
                Rejected::DecisionTimeout {
                    secs: budget.as_secs(),
                },
            );
        }
    };
    let (replay, mode) = pre;
    let (Some(name), Some(port)) = (st.name.clone(), st.port) else {
        // Unreachable: pre_connect sets both before any success return.
        return st.deny(client_addr, Rejected::NotProxyRequest);
    };
    // Scope B — the dial, outside scope A's timeout (the scopes never nest).
    match connect_upstream(proxy, &name, port).await {
        Ok(connected) => ExplicitDecided {
            decision: st.decision(
                client_addr,
                Verdict::Allowed {
                    name: name.clone(),
                    upstream: connected.peer,
                },
            ),
            tunnel_open: st.tunnel_open,
            relay: Some(ExplicitRelay {
                replay,
                connected,
                mode,
            }),
        },
        Err(verdict) => ExplicitDecided {
            decision: st.decision(client_addr, verdict),
            tunnel_open: st.tunnel_open,
            relay: None,
        },
    }
}

/// One accepted explicit connection: decide → record exactly once → relay
/// or answer. The `200` is a proxy response, not a relay byte, so the
/// record may follow it (Q7).
pub(crate) async fn handle_explicit_connection(
    mut client: TcpStream,
    client_addr: SocketAddr,
    proxy: Arc<Proxy>,
) {
    // Proxy-standard; failure ignored (same policy as the transparent path).
    let _ = client.set_nodelay(true);
    let ExplicitDecided {
        decision,
        tunnel_open,
        relay,
    } = decide_explicit(&mut client, client_addr, &proxy).await;
    proxy.sink.record(&decision);
    match relay {
        Some(ExplicitRelay {
            replay,
            mut connected,
            mode,
        }) => {
            super::relay_tail(
                &proxy,
                &decision,
                client,
                &replay,
                mode,
                &mut connected.stream,
            )
            .await;
        }
        None => {
            if let Some(bytes) = explicit_response(&decision.verdict, tunnel_open) {
                // Errors ignored: the socket is closed either way (D5).
                let _ = client.write_all(bytes).await;
                let _ = client.flush().await;
                linger_close(&mut client).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::AsyncRead;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::policy;
    use crate::proxy::AUDIT_TEXT_CAP;
    use crate::proxy::hello::{build_client_hello, first_record_end};
    use crate::proxy::{
        Connector, DecisionSink, DialFn, DnsMap, GuardedConnector, ResolveFn, Upstream,
    };

    const CLIENT: &str = "127.0.0.1:40000";
    const PUBLIC: &str = "93.184.216.34:443";

    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    fn dom(s: &str) -> Domain {
        Domain::parse(s).expect("test domain parses")
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("test socket addr parses")
    }

    /// The explicit path must never consult the DNS map (issue #8).
    struct NoDns;

    impl DnsMap for NoDns {
        fn name_for(&self, _ip: Ipv4Addr) -> Option<Domain> {
            panic!("DnsMap must not be consulted on the explicit path")
        }
    }

    #[derive(Default)]
    struct Sink(Mutex<Vec<Decision>>);

    impl DecisionSink for Sink {
        fn record(&self, decision: &Decision) {
            self.0.lock().expect("sink lock").push(decision.clone());
        }
    }

    /// A proxy whose dial counts calls and returns a duplex upstream.
    fn proxy(decision_timeout: Duration) -> (Arc<Proxy>, Arc<AtomicUsize>) {
        let dials = Arc::new(AtomicUsize::new(0));
        let resolve: ResolveFn =
            Arc::new(|_name: &str, _port: u16| Box::pin(async { Ok(vec![sock(PUBLIC)]) }));
        let counter = Arc::clone(&dials);
        let dial: DialFn = Arc::new(move |_name: &str, _port: u16| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let (near, _far) = duplex(1024);
                Ok((Box::new(near) as Upstream, sock(PUBLIC)))
            })
        });
        let limits = Limits {
            decision_timeout,
            ..Limits::default()
        };
        let connector: Arc<dyn Connector> =
            Arc::new(GuardedConnector::new(resolve, dial, limits.connect_timeout));
        let network = policy::Network {
            mode: policy::NetworkMode::Transparent,
            allow: vec![dom("allowed.test")],
            ports: vec![443, 80, 8080, 22],
        };
        let sink: Arc<dyn DecisionSink> = Arc::new(Sink::default());
        let proxy = Proxy::new(&network, Arc::new(NoDns), sink, connector, limits);
        (proxy, dials)
    }

    /// Feed `bytes` to the proxy as the client, return the decision and
    /// everything the proxy wrote back.
    async fn drive(proxy: &Proxy, bytes: &[u8]) -> (ExplicitDecided, Vec<u8>) {
        let (mut client, mut peer): (DuplexStream, DuplexStream) = duplex(64 * 1024);
        peer.write_all(bytes).await.expect("client write");
        let decided = decide_explicit(&mut client, sock(CLIENT), proxy).await;
        drop(client);
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.expect("client read");
        (decided, out)
    }

    fn connect(target: &str) -> Vec<u8> {
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
    }

    fn hello(sni: &str) -> Vec<u8> {
        build_client_hello(Some(sni), &[])
    }

    fn denied(decided: &ExplicitDecided) -> &Rejected {
        match &decided.decision.verdict {
            Verdict::Denied(rejected) => rejected,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn explicit_response_table_bytes_pinned() {
        assert_eq!(
            RESPONSE_CONNECT_ESTABLISHED,
            b"HTTP/1.1 200 Connection established\r\n\r\n"
        );
        assert_eq!(
            RESPONSE_400,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            RESPONSE_403,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            RESPONSE_502,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            RESPONSE_504,
            b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn explicit_response_mapping_rows() {
        let policy = Verdict::Denied(Rejected::NotAllowed {
            name: dom("x.test"),
        });
        assert_eq!(explicit_response(&policy, false), Some(RESPONSE_403));
        assert_eq!(explicit_response(&policy, true), None, "post-200 is silent");
        let malformed = Verdict::Denied(Rejected::ConnectHasBody);
        assert_eq!(explicit_response(&malformed, false), Some(RESPONSE_400));
        let timeout = Verdict::Denied(Rejected::DecisionTimeout { secs: 5 });
        assert_eq!(explicit_response(&timeout, false), None);
        let eof = Verdict::Denied(Rejected::Eof);
        assert_eq!(explicit_response(&eof, false), None);
        let resolve = Verdict::Error(Failed::Resolve {
            name: dom("x.test"),
            detail: String::new(),
        });
        assert_eq!(explicit_response(&resolve, false), Some(RESPONSE_502));
        let dial_timeout = Verdict::Error(Failed::ConnectTimeout {
            name: dom("x.test"),
            secs: 5,
        });
        assert_eq!(explicit_response(&dial_timeout, false), Some(RESPONSE_504));
        let allowed = Verdict::Allowed {
            name: dom("x.test"),
            upstream: sock(PUBLIC),
        };
        assert_eq!(explicit_response(&allowed, false), None);
    }

    #[test]
    fn parse_authority_table() {
        let ok = [
            ("allowed.test:443", Some(443u16)),
            ("ALLOWED.test:443", Some(443)),
            ("allowed.test.:443", Some(443)),
        ];
        for (raw, port) in ok {
            let (host, got) = parse_authority(raw, None, true)
                .unwrap_or_else(|e| panic!("{raw} should parse: {e}"));
            assert_eq!(host.as_str(), "allowed.test");
            assert_eq!(Some(got), port);
        }
        let denied = [
            "1.2.3.4:443",
            "[::1]:443",
            "[fe80::1%25eth0]:443",
            "::1:443",
            "127.1:443",
            "0x7f.1:443",
            "123:443",
            "*.a.test:443",
            ":443",
            "allowed.test",
            "allowed.test:",
            ":0",
            ":65536",
            ":+443",
            ":0443",
            "u:p@allowed.test:443",
            "allowed.test:443/x",
            "аllowed.test:443",
        ];
        for raw in denied {
            assert!(
                parse_authority(raw, None, true).is_err(),
                "{raw} must be denied"
            );
        }
        assert_eq!(
            parse_authority("1.2.3.4:443", None, true),
            Err(TARGET_IP_LITERAL)
        );
        assert_eq!(
            parse_authority("allowed.test", None, true),
            Err(TARGET_MISSING_PORT)
        );
        assert_eq!(
            parse_authority("u:p@allowed.test:443", None, true),
            Err(TARGET_USERINFO)
        );
        assert_eq!(
            parse_authority("allowed.test:443", Some(80), false).map(|(_, p)| p),
            Ok(443)
        );
        assert_eq!(
            parse_authority("allowed.test", Some(80), false).map(|(_, p)| p),
            Ok(80)
        );
    }

    #[test]
    fn parse_absolute_target_table() {
        let (host, port, origin) =
            parse_absolute_target("http://allowed.test/p?q#f", "GET").expect("parses");
        assert_eq!(
            (host.as_str(), port, origin.as_str()),
            ("allowed.test", 80, "/p?q")
        );
        let (_, _, origin) = parse_absolute_target("http://allowed.test", "GET").expect("parses");
        assert_eq!(origin, "/");
        let (_, _, origin) =
            parse_absolute_target("http://allowed.test?x=1", "GET").expect("parses");
        assert_eq!(origin, "/?x=1");
        let (_, _, origin) =
            parse_absolute_target("http://allowed.test", "OPTIONS").expect("parses");
        assert_eq!(origin, "*");
        let scheme = parse_absolute_target("https://allowed.test/", "GET").unwrap_err();
        assert_eq!(
            scheme,
            Rejected::TargetSchemeUnsupported {
                scheme: "https".to_owned()
            }
        );
        let userinfo = parse_absolute_target("http://u:p@allowed.test/", "GET").unwrap_err();
        assert_eq!(
            userinfo.reason(),
            "absolute-form request target \"<redacted>@allowed.test\" is invalid: userinfo is not allowed"
        );
    }

    #[test]
    fn parse_proxy_request_classification() {
        let head = |raw: &str| {
            let bytes = raw.as_bytes();
            let end = bytes
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| i + 4);
            (bytes.to_vec(), end.unwrap_or(bytes.len()))
        };
        let (buf, end) =
            head("CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n");
        let req = parse_proxy_request(&buf, end, 64).expect("connect parses");
        assert_eq!(req.kind, ExplicitKind::Connect);
        assert_eq!((req.host.as_str(), req.port), ("allowed.test", 443));
        let (buf, end) = head("GET /origin HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
        let fail = parse_proxy_request(&buf, end, 64)
            .err()
            .expect("origin-form denied");
        assert_eq!(fail.rejected, Rejected::NotProxyRequest);
        assert_eq!(fail.kind, ExplicitKind::Unknown);
        // m6: `://` must come before any path/query/fragment delimiter.
        let (buf, end) = head("GET /x?u=http://evil HTTP/1.1\r\nHost: x\r\n\r\n");
        let fail = parse_proxy_request(&buf, end, 64)
            .err()
            .expect("origin-form with a URL in the query is not a proxy request");
        assert_eq!(fail.rejected, Rejected::NotProxyRequest);
        let (buf, end) = head("GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
        let forward = parse_proxy_request(&buf, end, 64).expect("absolute-form parses");
        assert_eq!(forward.kind, ExplicitKind::Forward);
        assert_eq!(forward.method, "GET");
        let (buf, end) = head("PRI * HTTP/2.0\r\n\r\n");
        let fail = parse_proxy_request(&buf, end, 64)
            .err()
            .expect("h2 preface denied");
        assert_eq!(fail.rejected, Rejected::Http2Preface);
        let (buf, end) = head("CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n");
        let fail = parse_proxy_request(&buf, end, 64)
            .err()
            .expect("ip literal denied");
        assert_eq!(fail.kind, ExplicitKind::Connect);
        assert_eq!(
            fail.rejected.reason(),
            "CONNECT target \"1.2.3.4:443\" is invalid: IP literals are not allowed; use a domain name"
        );
    }

    #[test]
    fn check_proxy_head_table() {
        let parsed = |raw: &str| {
            let bytes = raw.as_bytes().to_vec();
            let end = bytes
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("terminated")
                + 4;
            let req = parse_proxy_request(&bytes, end, 64).expect("parses");
            (bytes, req)
        };
        // D1: HTTP/1.0 CONNECT may omit Host; HTTP/1.1 must carry one.
        let (buf, req) = parsed("CONNECT allowed.test:443 HTTP/1.0\r\n\r\n");
        assert_eq!(check_proxy_head(&buf[..], &req, 64), Ok(()));
        let (buf, req) = parsed("CONNECT allowed.test:443 HTTP/1.1\r\n\r\n");
        assert_eq!(
            check_proxy_head(&buf[..], &req, 64),
            Err(Rejected::HostMissing)
        );
        // D6: exactly one Content-Length: 0 is fine; any body is not.
        let (buf, req) = parsed(
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(check_proxy_head(&buf[..], &req, 64), Ok(()));
        let (buf, req) = parsed(
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 5\r\n\r\n",
        );
        assert_eq!(
            check_proxy_head(&buf[..], &req, 64),
            Err(Rejected::ConnectHasBody)
        );
        let (buf, req) = parsed(
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(
            check_proxy_head(&buf[..], &req, 64),
            Err(Rejected::ConnectHasBody)
        );
        // Q8: CL + TE is ambiguous on every explicit request.
        let (buf, req) = parsed(
            "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(
            check_proxy_head(&buf[..], &req, 64),
            Err(Rejected::AmbiguousFraming {
                detail: "both Content-Length and Transfer-Encoding are present"
            })
        );
        // Host mismatch on the CONNECT target carries the CONNECT source.
        let (buf, req) = parsed("CONNECT allowed.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n");
        assert_eq!(
            check_proxy_head(&buf[..], &req, 64).map_err(|e| e.reason()),
            Err(
                "HTTP Host evil.test does not match the CONNECT target name allowed.test"
                    .to_owned()
            )
        );
    }

    #[test]
    fn rewrite_forward_head_pinned() {
        let raw = b"GET http://allowed.test/p?q#f HTTP/1.1\r\nHost: allowed.test\r\nProxy-Authorization: Basic eA==\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Foo\r\nX-A: 1\r\n\r\n";
        let end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("terminated")
            + 4;
        let req = parse_proxy_request(raw, end, 64).expect("parses");
        let out = rewrite_forward_head(&raw[..end], &req, 64).expect("rebuilds");
        assert_eq!(
            out,
            b"GET /p?q HTTP/1.1\r\nHost: allowed.test\r\nX-A: 1\r\nConnection: close\r\n\r\n"
                .to_vec()
        );
    }

    #[test]
    fn decide_explicit_connect_443_allowed_relay_state() {
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_secs(5));
            let hello_bytes = hello("allowed.test");
            let mut bytes = connect("allowed.test:443");
            bytes.extend_from_slice(&hello_bytes);
            let (decided, out) = drive(&proxy, &bytes).await;
            assert_eq!(out, RESPONSE_CONNECT_ESTABLISHED.to_vec());
            assert_eq!(dials.load(Ordering::SeqCst), 1);
            assert_eq!(
                decided.decision.verdict,
                Verdict::Allowed {
                    name: dom("allowed.test"),
                    upstream: sock(PUBLIC),
                }
            );
            assert_eq!(
                decided.decision.via,
                Via::Explicit {
                    kind: ExplicitKind::Connect,
                    port: Some(443),
                }
            );
            let relay = decided.relay.expect("allowed path carries relay state");
            assert_eq!(relay.replay, hello_bytes);
            let RelayMode::Scanned { scan_from } = relay.mode else {
                panic!("443 must be scanned");
            };
            assert_eq!(first_record_end(&relay.replay), Some(scan_from));
        });
    }

    #[test]
    fn decide_explicit_connect_443_pipelined_bytes_stay_in_order() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let hello_bytes = hello("allowed.test");
            let extra = vec![b'A'; 6000];
            let mut bytes = connect("allowed.test:443");
            bytes.extend_from_slice(&hello_bytes);
            bytes.extend_from_slice(&extra);
            let (decided, _out) = drive(&proxy, &bytes).await;
            let relay = decided.relay.expect("allowed");
            let mut expected = hello_bytes.clone();
            expected.extend_from_slice(&extra);
            // The replay is an in-order PREFIX of the pipelined stream: the
            // unread remainder stays on the client socket and is relayed
            // after it (never reordered, never dropped).
            assert!(expected.starts_with(&relay.replay));
            assert!(relay.replay.len() > hello_bytes.len());
        });
    }

    #[test]
    fn decide_explicit_connect_443_sni_mismatch_silent_after_200_never_dials() {
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_secs(5));
            let mut bytes = connect("allowed.test:443");
            bytes.extend_from_slice(&hello("other.com"));
            let (decided, out) = drive(&proxy, &bytes).await;
            assert_eq!(
                out,
                RESPONSE_CONNECT_ESTABLISHED.to_vec(),
                "tunnel opened first"
            );
            assert!(decided.tunnel_open);
            assert_eq!(
                dials.load(Ordering::SeqCst),
                0,
                "inspect-before-connect lock"
            );
            assert_eq!(
                denied(&decided),
                &Rejected::SniMismatch {
                    sni: dom("other.com"),
                    name: dom("allowed.test"),
                    source: NameSource::ConnectTarget,
                }
            );
            assert_eq!(
                decided.decision.reason(),
                "SNI other.com does not match the CONNECT target name allowed.test"
            );
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                None
            );
        });
    }

    #[test]
    fn decide_explicit_connect_denied_before_200_answers_403() {
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_secs(5));
            let (decided, out) = drive(&proxy, &connect("evil.test:443")).await;
            assert!(out.is_empty(), "the handler, not decide, writes deny bytes");
            assert!(!decided.tunnel_open);
            assert_eq!(dials.load(Ordering::SeqCst), 0);
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_403)
            );
            assert_eq!(
                denied(&decided),
                &Rejected::NotAllowed {
                    name: dom("evil.test")
                }
            );
        });
    }

    #[test]
    fn decide_explicit_connect_ip_literal_400_and_no_inspector_403() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let (decided, _) = drive(&proxy, &connect("1.2.3.4:443")).await;
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_400)
            );
            let (decided, _) = drive(&proxy, &connect("allowed.test:22")).await;
            assert_eq!(denied(&decided), &Rejected::NoInspector { port: 22 });
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_403)
            );
        });
    }

    #[test]
    fn decide_explicit_connect_http_1_0_without_host_is_allowed() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let mut bytes = b"CONNECT allowed.test:443 HTTP/1.0\r\n\r\n".to_vec();
            bytes.extend_from_slice(&hello("allowed.test"));
            let (decided, _) = drive(&proxy, &bytes).await;
            assert!(matches!(decided.decision.verdict, Verdict::Allowed { .. }));
        });
    }

    #[test]
    fn decide_explicit_connect_http_1_1_without_host_is_400() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let (decided, _) = drive(&proxy, b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n").await;
            assert_eq!(denied(&decided), &Rejected::HostMissing);
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_400)
            );
        });
    }

    #[test]
    fn decide_explicit_connect_80_tunnel_host_mismatch_uses_connect_source() {
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_secs(5));
            let mut bytes = connect("allowed.test:80");
            bytes.extend_from_slice(b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n");
            let (decided, _) = drive(&proxy, &bytes).await;
            assert!(decided.tunnel_open);
            assert_eq!(dials.load(Ordering::SeqCst), 0);
            assert_eq!(
                decided.decision.reason(),
                "HTTP Host evil.test does not match the CONNECT target name allowed.test"
            );
        });
    }

    #[test]
    fn decide_explicit_connect_80_tunnel_forwards_with_connection_close() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let mut bytes = connect("allowed.test:80");
            bytes.extend_from_slice(b"GET /p HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
            let (decided, _) = drive(&proxy, &bytes).await;
            let relay = decided.relay.expect("allowed");
            assert_eq!(relay.mode, RelayMode::CloseOnUpstreamEof);
            let text = String::from_utf8(relay.replay).expect("ascii head");
            assert!(text.starts_with("GET /p HTTP/1.1\r\n"));
            assert!(text.contains("Connection: close\r\n"));
        });
    }

    #[test]
    fn decide_explicit_forward_allowed_rewrites_head() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let raw = b"GET http://allowed.test/p?q#f HTTP/1.1\r\nHost: allowed.test\r\nProxy-Connection: keep-alive\r\n\r\n";
            let (decided, out) = drive(&proxy, raw).await;
            assert!(out.is_empty(), "forward requests get no 200");
            assert_eq!(
                decided.decision.via,
                Via::Explicit {
                    kind: ExplicitKind::Forward,
                    port: Some(80),
                }
            );
            let relay = decided.relay.expect("allowed");
            assert_eq!(relay.mode, RelayMode::CloseOnUpstreamEof);
            assert_eq!(
                relay.replay,
                b"GET /p?q HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n".to_vec()
            );
        });
    }

    #[test]
    fn decide_explicit_forward_denials_pinned() {
        block_on(async {
            let (proxy, _dials) = proxy(Duration::from_secs(5));
            let (decided, _) = drive(
                &proxy,
                b"GET http://allowed.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            )
            .await;
            assert_eq!(
                decided.decision.reason(),
                "HTTP Host evil.test does not match the request-target name allowed.test"
            );
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_403)
            );
            let (decided, _) = drive(
                &proxy,
                b"GET https://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            )
            .await;
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_400)
            );
            let (decided, _) = drive(
                &proxy,
                b"GET http://allowed.test:8080/ HTTP/1.1\r\nHost: allowed.test:8080\r\n\r\n",
            )
            .await;
            assert_eq!(denied(&decided), &Rejected::NoInspector { port: 8080 });
        });
    }

    #[test]
    fn decide_explicit_decision_timeout_is_silent() {
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_millis(50));
            let (decided, out) = drive(&proxy, b"").await;
            assert!(out.is_empty());
            assert_eq!(dials.load(Ordering::SeqCst), 0);
            assert_eq!(denied(&decided), &Rejected::DecisionTimeout { secs: 0 });
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                None
            );
        });
    }

    #[test]
    fn decide_explicit_via_label_pinned_per_kind() {
        let via = |kind| Via::Explicit { kind, port: None };
        assert_eq!(via(ExplicitKind::Connect).label(), "explicit-connect");
        assert_eq!(via(ExplicitKind::Forward).label(), "explicit-forward");
        assert_eq!(via(ExplicitKind::Unknown).label(), "explicit");
        assert_eq!(Via::Transparent { orig_dst: None }.label(), "transparent");
    }

    #[test]
    fn explicit_reasons_pinned() {
        let cases: Vec<(Rejected, &str)> = vec![
            (
                Rejected::NotProxyRequest,
                "not a proxy request: expected CONNECT host:port or an absolute-form http:// target",
            ),
            (
                Rejected::ConnectTargetInvalid {
                    target: "93.184.216.34:443".to_owned(),
                    detail: TARGET_IP_LITERAL,
                },
                "CONNECT target \"93.184.216.34:443\" is invalid: IP literals are not allowed; use a domain name",
            ),
            (
                Rejected::RequestTargetInvalid {
                    target: "<redacted>@allowed.test".to_owned(),
                    detail: TARGET_USERINFO,
                },
                "absolute-form request target \"<redacted>@allowed.test\" is invalid: userinfo is not allowed",
            ),
            (
                Rejected::TargetSchemeUnsupported {
                    scheme: "https".to_owned(),
                },
                "absolute-form request target scheme \"https\" is not supported (http:// only; use CONNECT for TLS)",
            ),
            (
                Rejected::ConnectHasBody,
                "CONNECT request declares a body (Content-Length > 0 or Transfer-Encoding)",
            ),
            (
                Rejected::AmbiguousFraming {
                    detail: http::FRAMING_DUPLICATE_CL,
                },
                "ambiguous HTTP request framing: multiple Content-Length headers",
            ),
        ];
        for (rejected, text) in cases {
            assert_eq!(rejected.reason(), text);
        }
    }

    #[test]
    fn name_source_rendering_pinned() {
        let host = |source| Rejected::HostPortMismatch {
            got: 8080,
            want: 443,
            source,
        };
        assert_eq!(
            host(NameSource::DnsMap).reason(),
            "Host port suffix :8080 does not match the original destination port 443"
        );
        assert_eq!(
            host(NameSource::ConnectTarget).reason(),
            "Host port suffix :8080 does not match the CONNECT target port 443"
        );
        assert_eq!(
            host(NameSource::RequestTarget).reason(),
            "Host port suffix :8080 does not match the request-target port 443"
        );
        let target = |source| Rejected::TargetMismatch {
            target: "evil.test".to_owned(),
            name: dom("allowed.test"),
            source,
        };
        assert_eq!(
            target(NameSource::ConnectTarget).reason(),
            "absolute-form request target \"evil.test\" does not match the CONNECT target name allowed.test"
        );
    }

    #[test]
    fn redact_for_audit_pinned() {
        assert_eq!(
            redact_for_audit("http://u:p@evil.test:80/x?y#z"),
            "<redacted>@evil.test:80"
        );
        assert_eq!(redact_for_audit("a@b@host:443"), "<redacted>@host:443");
        assert_eq!(redact_for_audit("evil.test:443"), "evil.test:443");
        let long = "a".repeat(300);
        let capped = redact_for_audit(&long);
        assert_eq!(capped.len(), AUDIT_TEXT_CAP);
        assert!(capped.ends_with("..."));
        // A multi-byte char straddling the cut must not panic or split.
        let multibyte = format!("{}é", "a".repeat(252));
        assert!(redact_for_audit(&multibyte).len() <= AUDIT_TEXT_CAP);
    }

    #[test]
    fn strict_framing_table() {
        let check = |raw: &str| -> Result<http::Framing, Rejected> {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut request = httparse::Request::new(&mut headers);
            request.parse(raw.as_bytes()).expect("parses");
            http::check_framing(request.headers, request.version.unwrap_or(1))
        };
        assert_eq!(check("GET / HTTP/1.1\r\n\r\n"), Ok(http::Framing::None));
        assert_eq!(
            check("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\n"),
            Ok(http::Framing::Length(5))
        );
        assert_eq!(
            check("GET / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
            Ok(http::Framing::Chunked)
        );
        assert_eq!(
            check("GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"),
            Err(Rejected::AmbiguousFraming {
                detail: http::FRAMING_DUPLICATE_CL
            })
        );
        assert_eq!(
            check("GET / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n"),
            Err(Rejected::AmbiguousFraming {
                detail: http::FRAMING_INVALID_CL
            })
        );
        assert_eq!(
            check("GET / HTTP/1.1\r\nContent-Length: +5\r\n\r\n"),
            Err(Rejected::AmbiguousFraming {
                detail: http::FRAMING_INVALID_CL
            })
        );
        assert_eq!(
            check("GET / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
            Err(Rejected::AmbiguousFraming {
                detail: http::FRAMING_TE_NOT_CHUNKED
            })
        );
        assert_eq!(
            check("GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(Rejected::AmbiguousFraming {
                detail: http::FRAMING_TE_HTTP10
            })
        );
    }

    #[test]
    fn linger_close_is_bounded() {
        block_on(async {
            let (mut near, _far) = duplex(1024);
            let started = std::time::Instant::now();
            crate::proxy::relay::linger_close(&mut near).await;
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "linger must be bounded"
            );
        });
    }

    #[test]
    fn decide_explicit_connect_dial_failure_after_200_is_silent() {
        // A refused dial after the tunnel opened: the 200 already went out,
        // so the verdict is an Error and the handler closes silently.
        block_on(async {
            let dial: DialFn = Arc::new(|_name: &str, _port: u16| {
                Box::pin(async { Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")) })
            });
            let connector: Arc<dyn Connector> = Arc::new(GuardedConnector::new(
                public_resolve(),
                dial,
                Duration::from_secs(5),
            ));
            let proxy = proxy_with_connector(connector, Duration::from_secs(5));
            let mut bytes = connect("allowed.test:443");
            bytes.extend_from_slice(&hello("allowed.test"));
            let (decided, out) = drive(&proxy, &bytes).await;
            assert_eq!(out, RESPONSE_CONNECT_ESTABLISHED.to_vec());
            assert!(decided.tunnel_open);
            assert!(matches!(
                decided.decision.verdict,
                Verdict::Error(Failed::Connect { .. })
            ));
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                None
            );
        });
    }

    #[test]
    fn reparse_requires_exactly_one_complete_head() {
        // Partial, trailing bytes, and a clean head: only the last parses.
        let mut headers = vec![httparse::EMPTY_HEADER; 8];
        assert!(reparse_head(b"GET / HTTP/1.1\r\nHost: a", &mut headers).is_err());
        let with_tail = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nPIPELINED";
        assert!(reparse_head(with_tail, &mut headers).is_err());
        let exact = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert!(reparse_head(exact, &mut headers).is_ok());
        // The explicit callers inherit it: a partial head is never checked.
        let connect = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n";
        let parsed = parse_proxy_request(connect, connect.len(), 8).expect("parses");
        assert_eq!(
            check_proxy_head(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: al", &parsed, 8),
            Err(Rejected::HttpMalformed {
                detail: "request head re-parse failed".to_owned()
            })
        );
    }

    #[test]
    fn relay_until_upstream_eof_replays_then_closes_on_upstream_eof() {
        block_on(async {
            let (client, mut client_peer) = duplex(4096);
            let (mut upstream, mut up_peer) = duplex(4096);
            // The upstream answers, then half-closes: its EOF ends the exchange.
            up_peer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("upstream write");
            up_peer.shutdown().await.expect("upstream shutdown");
            let replay = b"GET /p HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
            let ended =
                crate::proxy::relay::relay_until_upstream_eof(client, replay, &mut upstream)
                    .await
                    .expect("relay");
            assert!(matches!(ended, crate::proxy::relay::RelayEnd::Finished));
            // The replay reached the upstream intact (first bytes it read).
            let mut seen = vec![0u8; replay.len()];
            up_peer.read_exact(&mut seen).await.expect("replay bytes");
            assert_eq!(seen, replay.to_vec());
            // The response reached the client, and the client saw a clean EOF.
            let mut response = Vec::new();
            client_peer
                .read_to_end(&mut response)
                .await
                .expect("client read");
            assert_eq!(
                response,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()
            );
        });
    }

    #[test]
    fn no_credentials_in_any_explicit_reason() {
        let corpus = [
            "CONNECT user:s3cret@allowed.test:443 HTTP/1.1\r\nHost: x\r\n\r\n",
            "CONNECT allowed.test:443/user:s3cret@x HTTP/1.1\r\nHost: x\r\n\r\n",
            "GET http://user:s3cret@allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            "GET http://allowed.test/ HTTP/1.1\r\nHost: user:s3cret@evil.test\r\n\r\n",
            "GET ftp://user:s3cret@allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            "CONNECT 1.2.3.4:443?user:s3cret HTTP/1.1\r\nHost: x\r\n\r\n",
        ];
        for raw in corpus {
            let bytes = raw.as_bytes();
            let end = bytes
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("terminated")
                + 4;
            let reason = match parse_proxy_request(bytes, end, 64) {
                Ok(req) => {
                    let mut buf = bytes.to_vec();
                    buf.truncate(end);
                    match check_proxy_head(&buf, &req, 64) {
                        Ok(()) => continue,
                        Err(rejected) => rejected.reason(),
                    }
                }
                Err(fail) => fail.rejected.reason(),
            };
            assert!(
                !reason.contains("s3cret"),
                "credential leaked in {reason:?}"
            );
        }
    }

    const FORWARD_GET: &[u8] = b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n";

    /// A proxy whose connector is supplied by the test (failure mapping).
    fn proxy_with_connector(
        connector: Arc<dyn Connector>,
        decision_timeout: Duration,
    ) -> Arc<Proxy> {
        let limits = Limits {
            decision_timeout,
            ..Limits::default()
        };
        let network = policy::Network {
            mode: policy::NetworkMode::Transparent,
            allow: vec![dom("allowed.test")],
            ports: vec![443, 80, 8080, 22],
        };
        let sink: Arc<dyn DecisionSink> = Arc::new(Sink::default());
        Proxy::new(&network, Arc::new(NoDns), sink, connector, limits)
    }

    fn public_resolve() -> ResolveFn {
        Arc::new(|_name: &str, _port: u16| Box::pin(async { Ok(vec![sock(PUBLIC)]) }))
    }

    #[test]
    fn decide_explicit_slowloris_after_200_is_silent_timeout() {
        // M1(a): the CONNECT head arrives, then silence. The 200 is already
        // out, so the decision timeout is a silent close, never dialed.
        block_on(async {
            let (proxy, dials) = proxy(Duration::from_millis(100));
            let (decided, out) = drive(
                &proxy,
                b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n",
            )
            .await;
            assert_eq!(out, RESPONSE_CONNECT_ESTABLISHED.to_vec());
            assert!(decided.tunnel_open);
            assert_eq!(dials.load(Ordering::SeqCst), 0);
            assert_eq!(denied(&decided), &Rejected::DecisionTimeout { secs: 0 });
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                None
            );
        });
    }

    #[test]
    fn decide_explicit_forward_connect_timeout_is_504() {
        // M1(c): a stalled dial hits the connector's own bound.
        block_on(async {
            let dial: DialFn = Arc::new(|_name: &str, _port: u16| Box::pin(std::future::pending()));
            let connector: Arc<dyn Connector> = Arc::new(GuardedConnector::new(
                public_resolve(),
                dial,
                Duration::from_millis(50),
            ));
            let proxy = proxy_with_connector(connector, Duration::from_secs(5));
            let (decided, _) = drive(&proxy, FORWARD_GET).await;
            assert!(matches!(
                decided.decision.verdict,
                Verdict::Error(Failed::ConnectTimeout { .. })
            ));
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_504)
            );
        });
    }

    #[test]
    fn decide_explicit_forward_dial_denied_is_403() {
        // M1(c): the resolver answers a loopback address; the guard denies it
        // before any dial.
        block_on(async {
            let resolve: ResolveFn = Arc::new(|_name: &str, _port: u16| {
                Box::pin(async { Ok(vec![sock("127.0.0.1:80")]) })
            });
            let dial: DialFn = Arc::new(|_name: &str, _port: u16| {
                Box::pin(async { Err(io::Error::other("the dial must not run")) })
            });
            let connector: Arc<dyn Connector> =
                Arc::new(GuardedConnector::new(resolve, dial, Duration::from_secs(5)));
            let proxy = proxy_with_connector(connector, Duration::from_secs(5));
            let (decided, _) = drive(&proxy, FORWARD_GET).await;
            assert!(matches!(
                decided.decision.verdict,
                Verdict::Denied(Rejected::DialDenied { .. })
            ));
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_403)
            );
        });
    }

    #[test]
    fn decide_explicit_forward_connect_refused_is_502() {
        // M1(c): the dial itself is refused — an infrastructure error.
        block_on(async {
            let dial: DialFn = Arc::new(|_name: &str, _port: u16| {
                Box::pin(async { Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")) })
            });
            let connector: Arc<dyn Connector> = Arc::new(GuardedConnector::new(
                public_resolve(),
                dial,
                Duration::from_secs(5),
            ));
            let proxy = proxy_with_connector(connector, Duration::from_secs(5));
            let (decided, _) = drive(&proxy, FORWARD_GET).await;
            assert!(matches!(
                decided.decision.verdict,
                Verdict::Error(Failed::Connect { .. })
            ));
            assert_eq!(
                explicit_response(&decided.decision.verdict, decided.tunnel_open),
                Some(RESPONSE_502)
            );
        });
    }

    #[test]
    fn loopback_deny_with_unread_body_delivers_403_without_reset() {
        // M1(b) — proves D5 (linger_close): the proxy denies after the head,
        // the 64 KiB body is never read by the decision, and the client must
        // still read exactly the 403 and then a clean EOF (no ECONNRESET).
        let (proxy, _dials) = proxy(Duration::from_secs(5));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = std::thread::spawn(move || -> Result<Vec<u8>, String> {
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(addr).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|e| e.to_string())?;
            let mut request =
                b"CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n".to_vec();
            request.extend(std::iter::repeat_n(b'x', 64 * 1024));
            stream
                .write_all(&request)
                .map_err(|e| format!("client write: {e}"))?;
            let mut got = Vec::new();
            match stream.read_to_end(&mut got) {
                Ok(_) => Ok(got),
                Err(e) => Err(format!("client read: {e} after {} bytes", got.len())),
            }
        });
        runtime.block_on(async {
            let (server, peer) = listener.accept().await.expect("accept");
            handle_explicit_connection(server, peer, proxy).await;
        });
        let got = client
            .join()
            .expect("client thread")
            .expect("a clean read, not a reset");
        assert_eq!(got, RESPONSE_403.to_vec());
    }

    #[test]
    fn relay_until_upstream_eof_half_closes_upstream_on_client_eof() {
        // M1(d): the client half-closes; the upstream must see EOF on its read
        // side (the replay + the client's bytes, then the EOF), and its reply
        // must still reach the client before the relay ends.
        block_on(async {
            let (client, mut client_peer) = duplex(4096);
            let (mut upstream, up_peer) = duplex(4096);
            client_peer.write_all(b"PING").await.expect("client write");
            client_peer.shutdown().await.expect("client half-close");
            let server = tokio::spawn(async move {
                let mut up_peer = up_peer;
                let mut seen = Vec::new();
                up_peer
                    .read_to_end(&mut seen)
                    .await
                    .expect("upstream read to EOF");
                up_peer.write_all(b"PONG").await.expect("upstream reply");
                up_peer.shutdown().await.expect("upstream half-close");
                seen
            });
            let ended =
                crate::proxy::relay::relay_until_upstream_eof(client, b"REPLAY", &mut upstream)
                    .await
                    .expect("relay");
            assert!(matches!(ended, crate::proxy::relay::RelayEnd::Finished));
            let seen = server.await.expect("server task");
            assert_eq!(
                seen,
                b"REPLAYPING".to_vec(),
                "upstream saw EOF after the client bytes"
            );
            let mut got = Vec::new();
            client_peer
                .read_to_end(&mut got)
                .await
                .expect("client read");
            assert_eq!(got, b"PONG".to_vec());
        });
    }

    /// Yields at most one byte per read (the m1 reader).
    struct OneByte<S>(S);

    impl<S: AsyncRead + Unpin> AsyncRead for OneByte<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut one = [0u8; 1];
            let mut view = tokio::io::ReadBuf::new(&mut one);
            match Pin::new(&mut self.0).poll_read(cx, &mut view) {
                Poll::Ready(Ok(())) => {
                    buf.put_slice(view.filled());
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    #[test]
    fn finish_residual_restores_bytes_past_one_read_chunk() {
        // m1: the residual is larger than one 4096-byte read chunk, so the
        // inspector stops short of it. finish_residual must append the rest;
        // deleting that append makes the replay shorter than the residual.
        block_on(async {
            let mut residual = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_vec();
            residual.extend(std::iter::repeat_n(b'b', 9000));
            let (client, _peer) = duplex(64);
            let mut client = OneByte(client);
            let limits = Limits::default();
            let mut chained = (&residual[..]).chain(&mut client);
            let head = http::read_head(&mut chained, &limits).await.expect("head");
            assert!(
                head.buf.len() < residual.len(),
                "the first chunk must not hold the whole residual"
            );
            let replay = finish_residual(head.buf, chained);
            assert_eq!(replay, residual, "the replay is the residual, in order");
        });
    }
}
