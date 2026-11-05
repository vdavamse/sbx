//! HTTP/1 request-head inspection for port 80 (issue #7) — request line +
//! `Host` check WITHOUT proxying semantics (CONNECT belongs to #8's
//! explicit proxy).
//!
//! 1. **Read loop** — read to the first `\r\n\r\n` with an incremental
//!    search (3-byte overlap across reads, so a terminator straddling two
//!    chunks is never missed), bounded by [`Limits::max_head_bytes`] ⇒
//!    [`Rejected::HeadTooLarge`] and EOF ⇒ [`Rejected::Eof`] (a transport
//!    error is the same fail-closed family — the client is gone either
//!    way). The decision timeout is applied by the CALLER
//!    ([`crate::proxy::decide`]). Everything read is the replay buffer:
//!    head AND any pipelined body bytes (`inspect_http_replays_pipelined_body`).
//!    The parsed extent must EQUAL the located terminator: httparse also
//!    tolerates bare-LF line endings the search does not, so a differential
//!    — two parsers seeing two different requests in the same bytes, the
//!    request-smuggling shape — is denied
//!    (`request head terminator mismatch`), never relayed.
//! 2. **Pure parser** — [`parse_head`] over httparse (`Request` +
//!    [`Limits::max_http_headers`] slots; `TooHeaders` lands in
//!    [`Rejected::HttpMalformed`] — fail-closed, never a silent header
//!    drop). The HTTP/2 connection preface fails httparse's version check
//!    and is denied AS the malformed family with its own pinned row
//!    ([`Rejected::Http2Preface`], Phase 1 lock). `Status::Partial` after a
//!    seen terminator is impossible but pinned to [`Rejected::HttpMalformed`]
//!    anyway.
//! 3. **Denial order** — CONNECT ⇒ [`Rejected::ConnectMethod`] (that is
//!    #8) → request-target rules → `Host` rules → the strict framing table
//!    ([`check_framing`] ⇒ [`Rejected::AmbiguousFraming`], issue #29 F2).
//!    NO verb/path filtering in
//!    v1 (#17 owns those): any non-CONNECT method passes if the names
//!    verify; HTTP/0.9 (no version) fails in httparse ⇒ HttpMalformed (no
//!    Host ⇒ unverifiable ⇒ fail-closed).
//! 4. **Request-target** — origin-form (`/…`) or `*` is accepted as-is;
//!    absolute-form must use `http://` (any other scheme ⇒ HttpMalformed)
//!    and its authority — host after canonicalization, optional `:port`
//!    equal to the ORIGINAL destination port — must equal the DNS-map name,
//!    else [`Rejected::TargetMismatch`] (the single variant covering every
//!    absolute-form mismatch shape). An unrecognizable target form (no
//!    leading `/`, no `://`) is HttpMalformed — unverifiable ⇒ fail-closed.
//! 5. **Host rules, in order** — exactly one `Host` header (0 ⇒
//!    [`Rejected::HostMissing`], >1 ⇒ [`Rejected::HostMultiple`]); its
//!    value must be valid UTF-8 — NEVER `from_utf8_lossy` (egress.rs point
//!    5: a lossy conversion could *create* a match) ⇒
//!    [`Rejected::HostNotUtf8`]; ASCII-OWS trimmed; ONE optional `:port`
//!    suffix (non-empty all-ASCII-digit, `rsplit_once`) — u16 overflow ⇒
//!    [`Rejected::HostInvalid`], mismatch with the original destination
//!    port ⇒ [`Rejected::HostPortMismatch`] (Q5); the port-stripped value
//!    must canonicalize ([`crate::proxy::canonicalize_host`]) ⇒ else
//!    [`Rejected::HostInvalid`] (scheme/userinfo/brackets/IP-literal junk
//!    all land here — the bare-hostname contract, egress.rs point 5) and
//!    equal the DNS-map name ⇒ else [`Rejected::HostMismatch`].
//! 6. **The connection lifetime is enforced per request (issue #29, F3)** —
//!    the name binding above covers request 1 in the decision phase. Every
//!    later request on the same connection is inspected by the relay
//!    ([`crate::proxy::relay::relay_http`]) with the same functions (point 7),
//!    so a follow-up request with a foreign `Host` is denied before any of its
//!    bytes is forwarded. The validated head of a LAST request
//!    ([`crate::proxy::h1::RequestMeta::is_last`]: HTTP/1.0, `close`,
//!    `Upgrade`, or a body) is rewritten by [`upstream_head`] to carry
//!    `Connection: close`, inserted immediately before the final CRLF; the
//!    request line, every client header and every body byte stay
//!    byte-identical. A pre-existing client `Connection` header is kept
//!    verbatim: RFC 9110 combines the field's values as a list, and the
//!    `close` token in it is decisive — RFC 9112 §9.6 obliges a conforming
//!    server to close after responding and to NOT process further requests on
//!    the connection. Nothing after a last request is ever forwarded. A
//!    bodyless HTTP/1.1 request is not last and keeps its head byte-identical
//!    (point 8). The no-keep-alive cost of the original design is gone for
//!    these requests; an `Upgrade` request is still last, so no 101 switch
//!    reaches an uninspected tunnel on port 80 (RFC 6455 §4.1 and h2c are
//!    therefore not honored on port 80). The 443 twin no rewrite can reach —
//!    h2 `:authority` vhost confusion after an SNI-checked handshake (ALPN
//!    rides through uninspected; inherent to any non-terminating proxy; #14's
//!    threat model). Recorded residuals (mod.rs point 12): a NON-conforming
//!    server that mis-frames a body-bearing request (CL.0, a chunk
//!    differential) and also ignores `Connection: close`.
//! 7. **Per-request checks (requests 2+)** — [`inspect_head`] runs, in order:
//!    the head cap and the head deadline ([`crate::proxy::h1::HeadAccumulator`],
//!    the deadline measured from the head's first byte), httparse with
//!    [`Limits::max_http_headers`] slots and the terminator differential
//!    (`consumed == head.len()`), the CONNECT denial, the request-target (origin
//!    form or `*`, or absolute-form equal to the bound name and port), exactly
//!    one `Host` equal to the bound name, the strict framing table, and the
//!    last-request computation (no denial). Port, DNS map, allow list and dial
//!    are connection-invariant on transparent :80 and CONNECT-80: the name and
//!    port are fixed when the connection is decided, and the policy is immutable
//!    for the run. They are NOT re-run, and that is by design, not an omission.
//! 8. **Keep-alive rules** — on the transparent and CONNECT-80 paths the
//!    client's `Connection` header is never stripped. A non-last request's head
//!    is forwarded byte-identical, which removes point 9's deviation for
//!    keep-alive requests (the deviation remains for last requests only).
//!    `Expect: 100-continue` is forwarded verbatim and the proxy never generates
//!    `100`. HTTP/1.0 is always last, even with `Connection: keep-alive`
//!    (RFC 9112 App. C.2.2 keep-alive is not supported). The explicit forward
//!    path is always one request per connection (explicit module docs point 12).
use tokio::io::{AsyncRead, AsyncReadExt};

use super::h1::{HeadAccumulator, RequestMeta};
use super::{Limits, NameSource, Rejected, canonicalize_host, redact_for_audit, redact_opaque};
use crate::policy::Domain;

/// The pinned denial detail when httparse's consumed extent disagrees
/// with the located `\r\n\r\n` terminator (module docs point 1): a bare-LF
/// head plus CRLF junk is two different requests to two different parsers
/// — the request-smuggling differential, denied fail-closed. Single source
/// shared by [`inspect_http`] and its pin test.
pub(crate) const HEAD_TERMINATOR_MISMATCH: &str = "request head terminator mismatch";

/// The HTTP/2 client connection preface's request-line shape (RFC 7540
/// §3.5) — denied with its own pinned row (module docs point 2).
const H2_PREFACE_PREFIX: &[u8] = b"PRI * HTTP/2.0";

/// The header line inserted into every validated head (module docs point 6
/// — the name binding's connection-lifetime enforcement).
const CONNECTION_CLOSE_HEADER: &[u8] = b"Connection: close\r\n";

/// Per-read chunk size for the inspection loop (the cap, not this, bounds
/// the buffer).
const READ_CHUNK: usize = 4096;

/// The buffered request head: every byte read so far (head + any pipelined
/// bytes) and the offset where the head terminator ends.
pub(crate) struct Head {
    pub buf: Vec<u8>,
    pub head_end: usize,
}

/// Read until the head terminator (issue #8 seam): the byte cap and EOF
/// bound the loop; the caller owns the decision timeout. The search and the
/// cap are [`HeadAccumulator`]'s, shared with request 2+ (issue #29, F3).
pub(crate) async fn read_head<S: AsyncRead + Unpin>(
    client: &mut S,
    limits: &Limits,
) -> Result<Head, Rejected> {
    let mut acc = HeadAccumulator::new(limits.max_head_bytes);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match client.read(&mut chunk).await {
            Ok(0) => return Err(Rejected::Eof),
            Ok(n) => {
                if let Some((mut buf, used)) = acc.push(&chunk[..n])? {
                    // The head is everything up to the terminator; the bytes of
                    // this read past it are pipelined and kept in the replay.
                    let head_end = buf.len();
                    buf.extend_from_slice(&chunk[used..n]);
                    return Ok(Head { buf, head_end });
                }
            }
            // Transport failure = the client is gone before a complete
            // preamble — the same fail-closed family as a clean EOF (same
            // documented choice as hello.rs).
            Err(_err) => return Err(Rejected::Eof),
        }
    }
}

/// The head bytes sent upstream (module docs point 6, FLAG-3): a LAST
/// request gets [`CONNECTION_CLOSE_HEADER`] inserted immediately before its
/// final CRLF — the request line, the client headers and any body stay
/// byte-identical; every other head is returned unchanged.
pub(crate) fn upstream_head(mut head: Vec<u8>, meta: &RequestMeta) -> Vec<u8> {
    if meta.is_last() {
        let at = head.len().saturating_sub(2);
        head.splice(at..at, CONNECTION_CLOSE_HEADER.iter().copied());
    }
    head
}

/// The per-request check inputs (issue #8, Q4): the name to match, the
/// port and the [`NameSource`] for wording. The strict framing table
/// ([`check_framing`]) applies on every path, transparent :80 included
/// (issue #29, F2).
pub(crate) struct HeadCheck<'a> {
    pub expected: &'a Domain,
    pub port: u16,
    pub source: NameSource,
}

/// What request 1's inspection hands the relay (issue #29, F3): the head
/// exactly as the client sent it, the client bytes read past its terminator
/// (`pending`, in order), and the request's facts. The upstream bytes are
/// `upstream_head(head, &meta)`.
#[derive(Debug, PartialEq)]
pub(crate) struct Inspected {
    pub head: Vec<u8>,
    pub pending: Vec<u8>,
    pub meta: RequestMeta,
}

/// Read + inspect the HTTP request head on 80 (module docs point 1). This is
/// [`inspect_http_with`] for the transparent path (#7 behaviour, pinned).
pub(crate) async fn inspect_http<S: AsyncRead + Unpin>(
    client: &mut S,
    expected: &Domain,
    orig_port: u16,
    limits: &Limits,
) -> Result<Inspected, Rejected> {
    let check = HeadCheck {
        expected,
        port: orig_port,
        source: NameSource::DnsMap,
    };
    inspect_http_with(client, &check, limits).await
}

/// Read and inspect request 1's head (issue #8 seam; #7's `inspect_http` is the
/// DnsMap wrapper). The head is returned verbatim; the rewrite is
/// [`upstream_head`]'s job, applied by the relay.
pub(crate) async fn inspect_http_with<S: AsyncRead + Unpin>(
    client: &mut S,
    check: &HeadCheck<'_>,
    limits: &Limits,
) -> Result<Inspected, Rejected> {
    let Head { mut buf, head_end } = read_head(client, limits).await?;
    // parse_head_with reports the consumed head length; the bytes past it are
    // the pipelined residue.
    let parsed = parse_head_with(&buf, check, limits.max_http_headers)?;
    // The parser and the terminator search MUST agree on where the head
    // ends (module docs point 1): httparse tolerates bare-LF line endings,
    // the search does not, and a differential means two parsers see two
    // different requests in the same bytes — the smuggling shape, denied
    // fail-closed, never relayed.
    if parsed.consumed != head_end {
        return Err(Rejected::HttpMalformed {
            detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
        });
    }
    let pending = buf.split_off(head_end);
    Ok(Inspected {
        head: buf,
        pending,
        meta: parsed.meta,
    })
}

/// Inspect ONE complete request head on a connection's second or later
/// request (module docs point 7). `head` is exactly the head bytes, through
/// its terminator; a head whose parse does not consume all of it is the
/// terminator differential and is denied.
pub(crate) fn inspect_head(
    head: &[u8],
    check: &HeadCheck<'_>,
    max_headers: usize,
) -> Result<RequestMeta, Rejected> {
    let parsed = parse_head_with(head, check, max_headers)?;
    if parsed.consumed != head.len() {
        return Err(Rejected::HttpMalformed {
            detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
        });
    }
    Ok(parsed.meta)
}

/// The #7 entry point (DnsMap wording) — kept as a thin
/// wrapper so the #7 head pins are unchanged. Test-only: production goes
/// through [`inspect_http_with`].
#[cfg(test)]
pub(crate) fn parse_head(
    head: &[u8],
    expected: &Domain,
    orig_port: u16,
    max_headers: usize,
) -> Result<usize, Rejected> {
    let check = HeadCheck {
        expected,
        port: orig_port,
        source: NameSource::DnsMap,
    };
    parse_head_with(head, &check, max_headers).map(|parsed| parsed.consumed)
}

/// What a validated head yields: the consumed head length (the terminator
/// differential's input) and the request's facts for the stream.
#[derive(Debug, PartialEq)]
pub(crate) struct ParsedHead {
    pub consumed: usize,
    pub meta: RequestMeta,
}

/// The PURE head parser (module docs points 2-5; `parse_head_table` drives
/// it over byte slices directly). `head` may carry pipelined bytes past
/// the terminator — httparse reports the consumed head length, which this
/// returns on success.
pub(crate) fn parse_head_with(
    head: &[u8],
    check: &HeadCheck<'_>,
    max_headers: usize,
) -> Result<ParsedHead, Rejected> {
    // A bare LF inside the head is denied before httparse runs: httparse
    // accepts it mid-head, and the differential check below sees it only at
    // the end of the head (issue #29 review, item 6).
    if head_has_bare_lf(head) {
        return Err(Rejected::AmbiguousFraming {
            detail: FRAMING_BARE_LF,
        });
    }
    // httparse's Header is Copy; a runtime-sized slot count needs the Vec
    // (the array form the design sketch shows cannot take a runtime len).
    // Exceeding it yields TooHeaders ⇒ HttpMalformed — fail-closed, never a
    // silent header drop.
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(head) {
        Err(err) => {
            // The h2 preface fails httparse's version check (HTTP/2.0 is
            // not HTTP/1.x) — its own pinned row (module docs point 2).
            if head.starts_with(H2_PREFACE_PREFIX) {
                return Err(Rejected::Http2Preface);
            }
            return Err(Rejected::HttpMalformed {
                detail: err.to_string(),
            });
        }
        // Impossible after a seen \r\n\r\n; pinned fail-closed anyway.
        Ok(httparse::Status::Partial) => {
            return Err(Rejected::HttpMalformed {
                detail: "incomplete request head".to_owned(),
            });
        }
        Ok(httparse::Status::Complete(consumed)) => consumed,
    };
    // Complete guarantees both; the fail-closed arms keep the unwraps out.
    let Some(method) = request.method else {
        return Err(Rejected::HttpMalformed {
            detail: "missing method".to_owned(),
        });
    };
    if method == "CONNECT" {
        // That is #8's job — never the transparent port (and never inside
        // an explicit tunnel: the tunnel carries one origin request).
        return Err(Rejected::ConnectMethod);
    }
    let Some(target) = request.path else {
        return Err(Rejected::HttpMalformed {
            detail: "missing request-target".to_owned(),
        });
    };
    check_target(target, check.expected, check.port, check.source)?;
    check_host(
        request.headers,
        check.expected,
        check.port,
        check.source,
        true,
    )?;
    let minor_version = request.version.unwrap_or(1);
    let framing = check_framing(request.headers, minor_version)?;
    let (close, upgrade) = connection_semantics(request.headers);
    Ok(ParsedHead {
        consumed,
        meta: RequestMeta {
            framing,
            minor_version,
            close,
            upgrade,
        },
    })
}

/// `(close, upgrade)` for a request's header list (module docs point 8): a
/// `close` token in `Connection` or `Proxy-Connection`; an `Upgrade` field, or
/// an `upgrade` token in `Connection`. Tokens are comma-separated, OWS-trimmed,
/// and compared ASCII-case-insensitively.
pub(crate) fn connection_semantics(headers: &[httparse::Header<'_>]) -> (bool, bool) {
    let mut close = false;
    let mut upgrade = false;
    for header in headers {
        if header.name.eq_ignore_ascii_case("upgrade") {
            upgrade = true;
        }
        let is_connection = header.name.eq_ignore_ascii_case("connection");
        if !is_connection && !header.name.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        for token in header.value.split(|b| *b == b',') {
            let token = trim_ows(token);
            if token.eq_ignore_ascii_case(b"close") {
                close = true;
            }
            if is_connection && token.eq_ignore_ascii_case(b"upgrade") {
                upgrade = true;
            }
        }
    }
    (close, upgrade)
}

pub(crate) fn check_target(
    target: &str,
    expected: &Domain,
    port: u16,
    source: NameSource,
) -> Result<(), Rejected> {
    // Origin-form or asterisk-form: accepted as-is — NO URL/path rules in
    // v1 (#17 owns verb/path filtering).
    if target == "*" || target.starts_with('/') {
        return Ok(());
    }
    let mismatch = || Rejected::TargetMismatch {
        target: redact_for_audit(target),
        name: expected.clone(),
        source,
    };
    let Some((scheme, rest)) = target.split_once("://") else {
        // Neither origin-form, asterisk, nor absolute-form: unverifiable
        // ⇒ fail-closed.
        return Err(Rejected::HttpMalformed {
            detail: format!(
                "unrecognized request-target form {:?}",
                redact_opaque(target)
            ),
        });
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(Rejected::HttpMalformed {
            detail: "absolute-form request target must use http:// on port 80".to_owned(),
        });
    }
    // The authority is everything before the first path/query/fragment
    // delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // The optional :port must equal the destination port (Q5's rule for the
    // target side); every mismatch shape — wrong port, non-digit suffix,
    // junk host — is the single TargetMismatch variant.
    let host_part = match authority.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            let port_matches = digits.parse::<u16>().is_ok_and(|p| p == port);
            if !port_matches {
                return Err(mismatch());
            }
            host
        }
        _ => authority,
    };
    match canonicalize_host(host_part) {
        Some(host) if host == *expected => Ok(()),
        _ => Err(mismatch()),
    }
}

/// Exactly one `Host` header (or none, when `require` is false — the D1
/// HTTP/1.0 CONNECT case only), its optional port suffix equal to `port`,
/// and its name equal to `expected`.
pub(crate) fn check_host(
    headers: &[httparse::Header<'_>],
    expected: &Domain,
    port: u16,
    source: NameSource,
    require: bool,
) -> Result<(), Rejected> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value);
    let Some(raw) = values.next() else {
        return if require {
            Err(Rejected::HostMissing)
        } else {
            Ok(())
        };
    };
    if values.next().is_some() {
        return Err(Rejected::HostMultiple);
    }
    // NEVER from_utf8_lossy (egress.rs point 5).
    let Ok(value) = std::str::from_utf8(raw) else {
        return Err(Rejected::HostNotUtf8);
    };
    let value = value.trim_matches(|c: char| c == ' ' || c == '\t');
    // Q5: strip exactly ONE optional :<digits> suffix; it must equal the
    // port. A non-digit suffix ("[::1]", "8x") is left to Domain::parse ⇒
    // HostInvalid.
    let host_part = match value.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            let Ok(got) = digits.parse::<u16>() else {
                // Overflow (e.g. ":99999"): the full value is not a bare
                // hostname either — fail-closed.
                return Err(Rejected::HostInvalid {
                    value: redact_opaque(value),
                });
            };
            if got != port {
                return Err(Rejected::HostPortMismatch {
                    got,
                    want: port,
                    source,
                });
            }
            host
        }
        _ => value,
    };
    let Some(host) = canonicalize_host(host_part) else {
        return Err(Rejected::HostInvalid {
            value: redact_opaque(host_part),
        });
    };
    if host != *expected {
        return Err(Rejected::HostMismatch {
            host,
            name: expected.clone(),
            source,
        });
    }
    Ok(())
}

/// The framing a request declares (issue #8 on the explicit paths; issue
/// #29 F2 applies the same table on transparent :80).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No body.
    None,
    /// A `Content-Length` body of this many bytes.
    Length(u64),
    /// A `chunked` body (must be the final coding).
    Chunked,
}

pub(crate) const FRAMING_CL_AND_TE: &str = "both Content-Length and Transfer-Encoding are present";
pub(crate) const FRAMING_DUPLICATE_CL: &str = "multiple Content-Length headers";
pub(crate) const FRAMING_INVALID_CL: &str = "Content-Length is not a single decimal length";
pub(crate) const FRAMING_TE_NOT_CHUNKED: &str =
    "Transfer-Encoding does not end in a single final chunked coding";
pub(crate) const FRAMING_TE_HTTP10: &str = "Transfer-Encoding in an HTTP/1.0 request";
/// A `\n` not preceded by `\r` inside the request head (issue #29 review,
/// item 6): httparse accepts it, so the head is denied before parsing.
pub(crate) const FRAMING_BARE_LF: &str = "bare LF line ending in the request head";
/// A framing header name spelled with `_` (for example `Content_Length`): some
/// servers normalise `_` to `-` and read the body the proxy never saw (R8).
pub(crate) const FRAMING_UNDERSCORE_NAME: &str =
    "a framing header name uses an underscore (Content_Length or Transfer_Encoding)";
pub(crate) const FRAMING_CHUNK_SIZE: &str = "invalid chunk-size line";
pub(crate) const FRAMING_CHUNK_LINE_TOO_LONG: &str = "chunk-size line exceeds the 4096-byte cap";
pub(crate) const FRAMING_CHUNK_DATA_CRLF: &str = "chunk data is not followed by CRLF";
pub(crate) const FRAMING_TRAILER_INVALID: &str = "invalid chunked trailer section";
pub(crate) const FRAMING_TRAILER_TOO_LARGE: &str = "chunked trailer section exceeds the head caps";
pub(crate) const FRAMING_TRAILER_FORBIDDEN: &str =
    "chunked trailer names Host, Content-Length or Transfer-Encoding";

/// The strict framing table (issue #8, Q8): deny every shape whose body
/// boundary two parsers could disagree on. Checked in this pinned order.
pub(crate) fn check_framing(
    headers: &[httparse::Header<'_>],
    minor_version: u8,
) -> Result<Framing, Rejected> {
    // Issue #29 review, item 7: a framing name with `_` is denied. It is not
    // the framing header the table below reads, but a server that normalises
    // `_` to `-` would read a body the proxy never saw.
    for header in headers {
        if header.name.contains('_') {
            let normalised = header.name.replace('_', "-");
            if normalised.eq_ignore_ascii_case("content-length")
                || normalised.eq_ignore_ascii_case("transfer-encoding")
            {
                return Err(Rejected::AmbiguousFraming {
                    detail: FRAMING_UNDERSCORE_NAME,
                });
            }
        }
    }
    let mut cl = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"));
    let cl_first = cl.next();
    let cl_count = usize::from(cl_first.is_some()) + cl.count();
    let te: Vec<&[u8]> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|h| h.value)
        .collect();
    let ambiguous = |detail: &'static str| Rejected::AmbiguousFraming { detail };
    // (1) more than one Content-Length header.
    if cl_count > 1 {
        return Err(ambiguous(FRAMING_DUPLICATE_CL));
    }
    // (2) the one Content-Length must be 1–20 ASCII digits (OWS-trimmed)
    //     and fit a u64 — rejects "5, 5", "+5", "-5", overflow.
    let length = match cl_first {
        Some(header) => {
            let raw = trim_ows(header.value);
            let well_formed =
                !raw.is_empty() && raw.len() <= 20 && raw.iter().all(|b| b.is_ascii_digit());
            let parsed = if well_formed {
                std::str::from_utf8(raw)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };
            match parsed {
                Some(n) => Some(n),
                None => return Err(ambiguous(FRAMING_INVALID_CL)),
            }
        }
        None => None,
    };
    // (3) both Content-Length and Transfer-Encoding.
    if length.is_some() && !te.is_empty() {
        return Err(ambiguous(FRAMING_CL_AND_TE));
    }
    // (4) Transfer-Encoding in an HTTP/1.0 request.
    if !te.is_empty() && minor_version == 0 {
        return Err(ambiguous(FRAMING_TE_HTTP10));
    }
    // (5) every TE token across all TE headers: the list must end in
    //     `chunked`, exactly once.
    if !te.is_empty() {
        let mut tokens: Vec<&[u8]> = Vec::new();
        for value in &te {
            for token in value.split(|b| *b == b',') {
                tokens.push(trim_ows(token));
            }
        }
        let is_chunked = |t: &[u8]| t.eq_ignore_ascii_case(b"chunked");
        let ends_chunked = tokens.last().is_some_and(|t| is_chunked(t));
        let chunked_count = tokens.iter().filter(|t| is_chunked(t)).count();
        if !ends_chunked || chunked_count != 1 {
            return Err(ambiguous(FRAMING_TE_NOT_CHUNKED));
        }
        return Ok(Framing::Chunked);
    }
    Ok(match length {
        Some(n) => Framing::Length(n),
        None => Framing::None,
    })
}

/// True when the request head (through its first CRLFCRLF, or the whole
/// buffer when none) holds a `\n` that is not preceded by `\r` (issue #29
/// review, item 6). One pass. Bytes past the head's terminator are not part of
/// the head and are not scanned.
pub(crate) fn head_has_bare_lf(buf: &[u8]) -> bool {
    let end = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(buf.len(), |at| at + 2);
    let head = &buf[..end];
    head.iter()
        .enumerate()
        .any(|(at, byte)| *byte == b'\n' && (at == 0 || head[at - 1] != b'\r'))
}

/// Trim optional whitespace (SP / HTAB) from both ends of a header value.
pub(crate) fn trim_ows(raw: &[u8]) -> &[u8] {
    let start = raw
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map_or(start, |i| i + 1);
    &raw[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    /// The `read_head` extent is the head terminator the parser must agree
    /// with (issue #8, T1 seam): for every shape, `read_head`'s `head_end`
    /// equals `parse_head`'s consumed length, and the pipelined tail survives
    /// in the buffer.
    #[test]
    fn read_head_extent_matches_inspect_http() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let expected = Domain::parse("allowed.test").expect("fixture");
            let limits = Limits::default();
            let shapes: [&[u8]; 3] = [
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\nPIPELINED",
                b"GET /a HTTP/1.1\r\nHost: allowed.test\r\nX: y\r\n\r\n",
            ];
            for raw in shapes {
                let (mut near, mut far) = duplex(4096);
                far.write_all(raw).await.expect("write");
                let head = read_head(&mut near, &limits).await.expect("head read");
                let terminator = raw
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .expect("terminated")
                    + 4;
                assert_eq!(head.head_end, terminator, "read_head extent");
                let consumed =
                    parse_head(&head.buf, &expected, 80, limits.max_http_headers).expect("parses");
                assert_eq!(consumed, head.head_end, "parser agrees with the search");
                assert!(head.buf.len() >= head.head_end);
            }
        });
    }

    /// Hand-rolled current-thread block_on (the tokio `macros` feature is
    /// deliberately NOT enabled — proxy module docs point 8).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    fn dom(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    /// The default expected name / original port every parse_head test
    /// uses: `allowed.test`, port 80, 64 header slots.
    fn parse(bytes: &[u8]) -> Result<usize, Rejected> {
        parse_head(bytes, &dom("allowed.test"), 80, 64)
    }

    /// A request head with the given raw `Host` value bytes (no other
    /// headers).
    fn request_with_host(host_value: &[u8]) -> Vec<u8> {
        let mut head = Vec::from(b"GET / HTTP/1.1\r\nHost: ".as_slice());
        head.extend_from_slice(host_value);
        head.extend_from_slice(b"\r\n\r\n");
        head
    }

    /// A request head with the given request line (plus a valid Host).
    fn request_with_line(line: &str) -> Vec<u8> {
        format!("{line}\r\nHost: allowed.test\r\n\r\n").into_bytes()
    }

    // ---- Host semantics --------------------------------------------------

    #[test]
    fn host_bare_name_matches() {
        let head = request_with_host(b"allowed.test");
        assert_eq!(parse(&head), Ok(head.len()));
    }

    #[test]
    fn host_uppercase_matches() {
        let head = request_with_host(b"ALLOWED.TEST");
        assert_eq!(parse(&head), Ok(head.len()));
    }

    #[test]
    fn host_root_dot_stripped() {
        // Exactly one trailing dot (canonicalize_host); a second one fails
        // closed.
        let head = request_with_host(b"allowed.test.");
        assert_eq!(parse(&head), Ok(head.len()));
        let double = request_with_host(b"allowed.test..");
        assert!(matches!(parse(&double), Err(Rejected::HostInvalid { .. })));
    }

    #[test]
    fn host_port_suffix_equal_to_orig_port_matches() {
        // Q5: the suffix must equal the ORIGINAL destination port (80 here).
        let head = request_with_host(b"allowed.test:80");
        assert_eq!(parse(&head), Ok(head.len()));
    }

    #[test]
    fn host_port_suffix_mismatch_denied() {
        let head = request_with_host(b"allowed.test:8080");
        assert_eq!(
            parse(&head),
            Err(Rejected::HostPortMismatch {
                got: 8080,
                want: 80,
                source: NameSource::DnsMap,
            })
        );
    }

    #[test]
    fn host_port_suffix_non_digit_denied() {
        // "[::1]" splits at the last colon into a non-all-digit suffix ⇒
        // the WHOLE value goes to Domain::parse ⇒ HostInvalid (never an
        // accidental IPv6-host acceptance). The mixed form too.
        for (value, expected) in [
            (
                "[::1]".as_bytes(),
                Rejected::HostInvalid {
                    value: "[::1]".to_owned(),
                },
            ),
            (
                b"allowed.test:8x".as_slice(),
                Rejected::HostInvalid {
                    value: "allowed.test:8x".to_owned(),
                },
            ),
            (
                b"allowed.test:99999".as_slice(),
                // u16 overflow ⇒ HostInvalid over the FULL value.
                Rejected::HostInvalid {
                    value: "allowed.test:99999".to_owned(),
                },
            ),
        ] {
            let head = request_with_host(value);
            assert_eq!(parse(&head), Err(expected), "{value:?}");
        }
    }

    #[test]
    fn host_missing_denied() {
        // And with it HTTP/0.9-shape requests: httparse fails them before
        // this rule (no version ⇒ HttpMalformed) — no Host ⇒ unverifiable
        // ⇒ fail-closed either way.
        let head = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(parse(head), Err(Rejected::HostMissing));
    }

    #[test]
    fn host_multiple_denied() {
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: allowed.test\r\n\r\n";
        assert_eq!(parse(head), Err(Rejected::HostMultiple));
    }

    #[test]
    fn host_non_utf8_denied() {
        // NEVER lossy: a 0xff byte is HostNotUtf8, not a mismatch — a lossy
        // conversion could *create* a match (egress.rs point 5).
        let head = request_with_host(b"allowed.\xff.test");
        assert_eq!(parse(&head), Err(Rejected::HostNotUtf8));
    }

    #[test]
    fn host_with_scheme_or_userinfo_or_brackets_denied() {
        // The bare-hostname contract (egress.rs point 5): Domain::parse
        // rejects every decorated shape ⇒ HostInvalid.
        for value in [
            "http://allowed.test",
            "https://allowed.test",
            "user@allowed.test",
            "[allowed.test]",
            "allowed.test/x",
            "1.2.3.4",
        ] {
            let head = request_with_host(value.as_bytes());
            let err = parse(&head).expect_err(&format!("{value:?} must be denied"));
            assert!(
                matches!(err, Rejected::HostInvalid { .. }),
                "{value:?}: {err:?}"
            );
        }
    }

    // ---- method / preface -------------------------------------------------

    #[test]
    fn connect_method_denied() {
        // That is #8's job — the reason points there.
        let head = b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n";
        let err = parse(head).expect_err("CONNECT must be denied");
        assert_eq!(err, Rejected::ConnectMethod);
        assert_eq!(
            err.reason(),
            "CONNECT is served on the explicit proxy port only (issue #8)"
        );
    }

    #[test]
    fn h2_preface_denied_as_malformed() {
        // The full RFC 7540 §3.5 preface ⇒ Http2Preface (its own pinned
        // row inside the malformed family).
        let head = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let err = parse(head).expect_err("the h2 preface must be denied");
        assert_eq!(err, Rejected::Http2Preface);
        assert_eq!(
            err.reason(),
            "malformed HTTP request: HTTP/2 connection preface on port 80"
        );
    }

    // ---- absolute-form targets --------------------------------------------

    #[test]
    fn absolute_form_matching_host_allowed() {
        // With and without the matching :port, with path/query, uppercase
        // scheme.
        for line in [
            "GET http://allowed.test/ HTTP/1.1",
            "GET http://allowed.test:80/ HTTP/1.1",
            "GET http://allowed.test/a/b?c=d HTTP/1.1",
            "GET HTTP://ALLOWED.TEST/ HTTP/1.1",
        ] {
            let head = request_with_line(line);
            assert_eq!(parse(&head), Ok(head.len()), "{line:?}");
        }
    }

    #[test]
    fn absolute_form_mismatch_denied() {
        for line in [
            "GET http://evil.test/ HTTP/1.1",
            "GET http://notallowed.test/ HTTP/1.1",
            "GET http://allowed.test.evil/ HTTP/1.1",
        ] {
            let head = request_with_line(line);
            let err = parse(&head).expect_err(&format!("{line:?} must be denied"));
            assert_eq!(
                err,
                Rejected::TargetMismatch {
                    // Redacted to the authority on the transparent path too
                    // (issue #29, F1).
                    target: line
                        .strip_prefix("GET http://")
                        .and_then(|rest| rest.split('/').next())
                        .expect("line shape")
                        .to_owned(),
                    name: dom("allowed.test"),
                    source: NameSource::DnsMap,
                },
                "{line:?}"
            );
        }
    }

    #[test]
    fn absolute_form_wrong_port_denied() {
        // Q5's rule on the target side: the authority port must equal the
        // ORIGINAL destination port — mismatch is TargetMismatch (the
        // single absolute-form denial variant).
        let head = request_with_line("GET http://allowed.test:8080/ HTTP/1.1");
        assert_eq!(
            parse(&head),
            Err(Rejected::TargetMismatch {
                target: "allowed.test:8080".to_owned(),
                name: dom("allowed.test"),
                source: NameSource::DnsMap,
            })
        );
    }

    /// Issue #29, F1: client strings in transparent-path reasons are
    /// redacted like the explicit path's — no userinfo, path or query.
    #[test]
    fn transparent_reasons_redacted() {
        let head = request_with_line("GET http://user:secret@evil.test/p?token=x HTTP/1.1");
        let err = parse(&head).expect_err("mismatch must be denied");
        assert_eq!(
            err,
            Rejected::TargetMismatch {
                target: "<redacted>@evil.test".to_owned(),
                name: dom("allowed.test"),
                source: NameSource::DnsMap,
            }
        );
        assert!(!err.reason().contains("secret"), "{}", err.reason());

        let head = request_with_line("GET user:secret@x?token=y HTTP/1.1");
        let err = parse(&head).expect_err("unrecognized form must be denied");
        assert_eq!(
            err,
            Rejected::HttpMalformed {
                detail: "unrecognized request-target form \"<redacted>@x?<redacted>\"".to_owned(),
            }
        );
        assert!(!err.reason().contains("token"), "{}", err.reason());

        let head = b"GET / HTTP/1.1\r\nHost: u:pw@allowed.test\r\n\r\n";
        let err = parse(head).expect_err("userinfo in Host must be denied");
        assert_eq!(
            err,
            Rejected::HostInvalid {
                value: "<redacted>@allowed.test".to_owned(),
            }
        );
        assert!(!err.reason().contains("pw"), "{}", err.reason());

        // Review of #53: a Host value keeps its shape, so a scheme or a path
        // never logs as the bare, allowed name.
        for (host, logged) in [
            ("http://allowed.test", "http://allowed.test"),
            ("allowed.test/evil", "allowed.test/<redacted>"),
            (
                "http://u:pw@allowed.test/p?k=v",
                "http://<redacted>@allowed.test/<redacted>",
            ),
            // Review of #61: a `://` that is not a leading scheme separator
            // must not move the boundary past what it protects.
            ("allowed.test/p?k=v://x", "allowed.test/<redacted>"),
            ("u:pw@h/x://y", "<redacted>@h/<redacted>"),
            ("1http://u:pw@h", "1http:/<redacted>"),
        ] {
            let head = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let err = parse(head.as_bytes()).expect_err("decorated Host must be denied");
            assert_eq!(
                err,
                Rejected::HostInvalid {
                    value: logged.to_owned(),
                },
                "{host}"
            );
            assert!(!err.reason().contains("pw") && !err.reason().contains("k=v"));
        }
        let head = request_with_line("GET ?x HTTP/1.1");
        assert_eq!(
            parse(&head).expect_err("query-only target"),
            Rejected::HttpMalformed {
                detail: "unrecognized request-target form \"?<redacted>\"".to_owned(),
            }
        );
    }

    /// Issue #29, F2: the strict framing table applies on transparent :80.
    #[test]
    fn transparent_strict_framing() {
        let rows: [(&[u8], &str); 5] = [
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                FRAMING_CL_AND_TE,
            ),
            (
                b"POST / HTTP/1.0\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n",
                FRAMING_TE_HTTP10,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                FRAMING_DUPLICATE_CL,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: +1\r\n\r\n",
                FRAMING_INVALID_CL,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
                FRAMING_TE_NOT_CHUNKED,
            ),
        ];
        for (head, detail) in rows {
            assert_eq!(
                parse(head),
                Err(Rejected::AmbiguousFraming { detail }),
                "{head:?}"
            );
        }
        // Accept rows (review of #53): the regression guard against
        // rejecting legitimate requests on :80.
        let ok = b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse(ok), Ok(ok.len() - 3));
        let accepted: [&[u8]; 3] = [
            b"POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: allowed.test\r\n\r\n",
        ];
        for head in accepted {
            assert_eq!(parse(head), Ok(head.len()), "{head:?}");
        }
    }

    /// Review of #53: the production async entry applies the framing table.
    #[test]
    fn inspect_http_denies_cl_and_te() {
        let head = b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx";
        assert_eq!(
            inspect_with(head, Limits::default(), false),
            Err(Rejected::AmbiguousFraming {
                detail: FRAMING_CL_AND_TE
            })
        );
    }

    #[test]
    fn absolute_form_https_scheme_denied() {
        // A non-http scheme on port 80 is malformed, not a mismatch.
        let head = request_with_line("GET https://allowed.test/ HTTP/1.1");
        let err = parse(&head).expect_err("https:// must be denied");
        assert_eq!(
            err,
            Rejected::HttpMalformed {
                detail: "absolute-form request target must use http:// on port 80".to_owned(),
            }
        );
    }

    // ---- parser failures ---------------------------------------------------

    #[test]
    fn malformed_request_line_denied() {
        for head in [
            b"GET /\r\nHost: allowed.test\r\n\r\n".as_slice(), // no version
            b"GARBAGE\r\n\r\n".as_slice(),
            b"\x01\x02\x03\r\n\r\n".as_slice(),
            b"GET /path with spaces HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
        ] {
            let err = parse(head).expect_err("must be denied");
            assert!(
                matches!(err, Rejected::HttpMalformed { .. }),
                "{head:?}: {err:?}"
            );
            assert!(err.reason().starts_with("malformed HTTP request: "));
        }
    }

    #[test]
    fn too_many_headers_denied() {
        // TooHeaders lands in HttpMalformed — fail-closed, never a silent
        // header drop (a dropped duplicate Host would defeat HostMultiple).
        let mut head = Vec::from(b"GET / HTTP/1.1\r\n".as_slice());
        for i in 0..5 {
            head.extend_from_slice(format!("X-Pad{i}: v\r\n").as_bytes());
        }
        head.extend_from_slice(b"Host: allowed.test\r\n\r\n");
        let err = parse_head(&head, &dom("allowed.test"), 80, 4).expect_err("must be denied");
        assert!(matches!(err, Rejected::HttpMalformed { .. }), "{err:?}");
    }

    // ---- inspect_http over duplex streams -----------------------------------

    #[test]
    fn oversized_head_denied() {
        // The shrunk cap bounds a terminator-less flood ⇒ HeadTooLarge.
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        let limits = Limits {
            max_head_bytes: 32,
            ..Limits::default()
        };
        let result = block_on(async {
            peer.write_all(&[b'X'; 4096]).await.expect("write");
            inspect_http(&mut client, &expected, 80, &limits).await
        });
        assert_eq!(
            result.expect_err("must deny"),
            Rejected::HeadTooLarge { cap: 32 }
        );
    }

    #[test]
    fn inspect_http_replays_pipelined_body() {
        // The pipelined bytes past request 1's terminator are returned as
        // `pending`, in order; the head is verbatim (a bodyless HTTP/1.1
        // request without close is not last, module docs point 8).
        let mut bytes = Vec::from(b"POST /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice());
        let head_end = bytes.len();
        bytes.extend_from_slice(b"body-bytes");
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        let limits = Limits::default();
        let result = block_on(async {
            peer.write_all(&bytes).await.expect("write");
            inspect_http(&mut client, &expected, 80, &limits).await
        });
        let inspected = result.expect("must pass");
        assert_eq!(inspected.head, bytes[..head_end].to_vec());
        assert_eq!(inspected.pending, b"body-bytes".to_vec());
        assert!(!inspected.meta.is_last());
    }

    #[test]
    fn inspect_http_straddling_reads_still_find_terminator() {
        // The 3-byte overlap contract: a tiny duplex capacity forces the
        // head to arrive in many small reads, so the \r\n\r\n terminator
        // straddles chunk boundaries — the incremental search must still
        // find it and the replay buffer must accumulate every byte
        // exactly, whatever the split points are (plus the point-6
        // rewrite, which is chunking-independent by construction).
        let head: &[u8] = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        let (mut client, peer) = duplex(8);
        let expected = dom("allowed.test");
        let limits = Limits::default();
        let result = block_on(async {
            let writer = tokio::spawn(async move {
                let mut peer = peer;
                peer.write_all(head).await.expect("write");
                peer.shutdown().await.expect("shutdown");
            });
            let outcome = inspect_http(&mut client, &expected, 80, &limits).await;
            writer.await.expect("writer task");
            outcome
        });
        assert_eq!(result.expect("must pass").head, head.to_vec());
    }

    #[test]
    fn inspect_http_eof_denied() {
        // A head without the terminator, then close ⇒ Eof.
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        let limits = Limits::default();
        let result = block_on(async {
            peer.write_all(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n")
                .await
                .expect("write");
            peer.shutdown().await.expect("shutdown");
            inspect_http(&mut client, &expected, 80, &limits).await
        });
        assert_eq!(result.expect_err("must deny"), Rejected::Eof);
    }

    /// Run [`inspect_http`] over a duplex pre-fed `bytes` (expected name
    /// `allowed.test`, orig port 80); `close_after` shuts the writer down
    /// first (EOF after the buffered bytes).
    fn inspect_with(
        bytes: &[u8],
        limits: Limits,
        close_after: bool,
    ) -> Result<Inspected, Rejected> {
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        block_on(async {
            peer.write_all(bytes).await.expect("write");
            if close_after {
                peer.shutdown().await.expect("shutdown");
            }
            inspect_http(&mut client, &expected, 80, &limits).await
        })
    }

    /// The upstream bytes for an inspected request 1 (what the relay writes).
    fn upstream_of(bytes: &[u8]) -> Vec<u8> {
        let inspected = inspect_with(bytes, Limits::default(), false).expect("must pass");
        upstream_head(inspected.head, &inspected.meta)
    }

    #[test]
    fn inspect_http_forces_close_only_on_last_requests() {
        // Module docs points 6 and 8 (issue #29, F3): a bodyless HTTP/1.1
        // keep-alive request is forwarded byte-identical; a request with a
        // body, HTTP/1.0 and an explicit close are LAST and get the close
        // token inserted immediately before the final CRLF.
        let keep_alive = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        assert_eq!(upstream_of(keep_alive), keep_alive.to_vec());
        let rows: &[(&[u8], &[u8])] = &[
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\r\n\r\n",
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            ),
            (
                b"GET / HTTP/1.0\r\nHost: allowed.test\r\n\r\n",
                b"GET / HTTP/1.0\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\nConnection: close\r\n\r\n",
            ),
        ];
        for (input, want) in rows {
            assert_eq!(upstream_of(input), want.to_vec(), "{input:?}");
        }
    }

    #[test]
    fn existing_connection_headers_do_not_defeat_close() {
        // A client-supplied Connection header is kept VERBATIM (the rewrite is
        // a single insertion — the differential check and the body bytes rely
        // on that), and the inserted close token still rides the combined
        // field list: RFC 9112 §9.6 makes `close` decisive for a conforming
        // server. A keep-alive token next to a last-request marker changes
        // nothing: the request is last, so the close is inserted.
        let head = b"GET / HTTP/1.0\r\nHost: allowed.test\r\nConnection: keep-alive\r\n\r\n";
        let got = upstream_of(head);
        assert_eq!(
            got,
            b"GET / HTTP/1.0\r\nHost: allowed.test\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n"
        );
        assert!(
            got.windows(CONNECTION_CLOSE_HEADER.len())
                .any(|window| window == CONNECTION_CLOSE_HEADER),
            "the close token must ride the upstream head: {got:?}"
        );
        // Keep-alive on a 1.1 bodyless request is NOT last: verbatim.
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(upstream_of(head), head.to_vec());
        // Explicit close on 1.1: last, close inserted (a harmless duplicate).
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
        assert_eq!(
            upstream_of(head),
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn inspect_http_bare_lf_differential_denied() {
        // m1 pin: httparse terminates lines at a bare LF too; the read
        // loop stops only at \r\n\r\n. A bare-LF head followed by junk
        // containing a real \r\n\r\n parses to a SHORTER extent than the
        // located terminator — two parsers see two different requests in
        // the same bytes (the request-smuggling shape) ⇒ denied, never
        // relayed (and never rewritten — the enforcement runs only for a
        // validated head).
        let mut bytes = Vec::from(b"GET / HTTP/1.1\nHost: allowed.test\n\n".as_slice());
        bytes.extend_from_slice(b"POST /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
        let result = inspect_with(&bytes, Limits::default(), false);
        // Issue #29 review, item 6: the bare LF is caught before httparse, so the
        // pinned reason is the bare-LF one (the differential check still backs
        // it up for shapes the scan does not see).
        assert_eq!(
            result.expect_err("the parser differential must deny"),
            Rejected::AmbiguousFraming {
                detail: FRAMING_BARE_LF,
            }
        );
        // The accepted side: a normal CRLF head parses to exactly the
        // terminator, so the equality check is invisible to well-formed
        // traffic (with and without a pipelined body).
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        assert_eq!(
            inspect_with(head, Limits::default(), false)
                .expect("CRLF head must pass")
                .head,
            head.to_vec()
        );
        let mut with_body = head.to_vec();
        with_body.extend_from_slice(b"body");
        let inspected =
            inspect_with(&with_body, Limits::default(), false).expect("CRLF head + body must pass");
        assert_eq!(inspected.head, head.to_vec());
        assert_eq!(inspected.pending, b"body".to_vec());
    }

    #[test]
    fn inspect_http_cap_boundary_pinned() {
        // Boundary pin (m4, the LENIENT side — the deliberate asymmetry
        // with hello.rs's strict inspect_tls_hello_cap_boundary_pinned,
        // documented on Limits): the head cap bounds the SEARCH — it fires
        // only on a strict overrun while the terminator is still unseen —
        // and an already-complete head in the buffer wins over the cap
        // check (worst-case buffering: cap + one read chunk).
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        // A complete head at exactly the cap: accepted.
        let at_cap = Limits {
            max_head_bytes: head.len(),
            ..Limits::default()
        };
        assert_eq!(
            inspect_with(head, at_cap, false)
                .expect("len == cap must pass")
                .head,
            head.to_vec()
        );
        // A complete head ONE BYTE OVER a shrunk cap, arriving in one
        // chunk: STILL accepted — the terminator is found before the cap
        // check runs (this is the leniency being pinned; do not "fix" it
        // without re-reading the Limits docs).
        let under = Limits {
            max_head_bytes: head.len() - 1,
            ..Limits::default()
        };
        assert_eq!(
            inspect_with(head, under, false)
                .expect("a complete head beats the shrunk cap (terminator-first)")
                .head,
            head.to_vec()
        );
        // Terminator-less bytes: exactly cap → the search ends at Eof on
        // the client's close (the cap is NOT exceeded — strict `>`);
        // cap + 1 → HeadTooLarge.
        let limits = Limits {
            max_head_bytes: 32,
            ..Limits::default()
        };
        assert_eq!(
            inspect_with(&[b'X'; 32], limits.clone(), true).expect_err("must deny"),
            Rejected::Eof
        );
        assert_eq!(
            inspect_with(&[b'X'; 33], limits, false).expect_err("must deny"),
            Rejected::HeadTooLarge { cap: 32 }
        );
    }

    // ---- per-request inspection (issue #29, F3) -----------------------------

    /// The request-2+ check for `allowed.test` on port 80 (DnsMap wording).
    fn check_allowed(expected: &Domain) -> HeadCheck<'_> {
        HeadCheck {
            expected,
            port: 80,
            source: NameSource::DnsMap,
        }
    }

    #[test]
    fn inspect_head_table() {
        // Every row is one complete head (through its terminator); the Ok rows
        // pin the last-request computation, the Err rows pin the denial shape.
        let expected = dom("allowed.test");
        let check = check_allowed(&expected);
        let ok_rows: &[(&[u8], bool)] = &[
            (b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n", false),
            (
                b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                false,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 2\r\n\r\n",
                true,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
                true,
            ),
            (b"GET / HTTP/1.0\r\nHost: allowed.test\r\n\r\n", true),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nUpgrade: h2c\r\n\r\n",
                true,
            ),
        ];
        for (head, last) in ok_rows {
            let meta = inspect_head(head, &check, 64).expect("must pass");
            assert_eq!(meta.is_last(), *last, "{head:?}");
        }
        let err_rows: Vec<(&[u8], Rejected)> = vec![
            (
                b"CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                Rejected::ConnectMethod,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
                Rejected::HostMismatch {
                    host: dom("evil.test"),
                    name: dom("allowed.test"),
                    source: NameSource::DnsMap,
                },
            ),
            (
                b"GET http://evil.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                Rejected::TargetMismatch {
                    target: "evil.test".to_owned(),
                    name: dom("allowed.test"),
                    source: NameSource::DnsMap,
                },
            ),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                Rejected::AmbiguousFraming {
                    detail: FRAMING_CL_AND_TE,
                },
            ),
            (
                // The terminator differential on the head alone: bytes past the
                // terminator are not part of THIS head.
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\nGET /",
                Rejected::HttpMalformed {
                    detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
                },
            ),
        ];
        for (head, expected_err) in err_rows {
            assert_eq!(
                inspect_head(head, &check, 64),
                Err(expected_err),
                "{head:?}"
            );
        }
    }

    #[test]
    fn connection_semantics_table() {
        // (header lines, (close, upgrade)). Tokens are case-insensitive and
        // comma-separated; `closed` is not `close`; Keep-Alive is not a
        // Connection token list.
        let rows: &[(&str, (bool, bool))] = &[
            ("", (false, false)),
            ("Connection: close\r\n", (true, false)),
            ("Connection: keep-alive, Close\r\n", (true, false)),
            ("Connection:  CLOSE \r\n", (true, false)),
            ("Connection: closed\r\n", (false, false)),
            ("Proxy-Connection: close\r\n", (true, false)),
            ("Connection: upgrade\r\n", (false, true)),
            ("Connection: Upgrade, keep-alive\r\n", (false, true)),
            ("Upgrade: h2c\r\n", (false, true)),
            ("Keep-Alive: close\r\n", (false, false)),
        ];
        for (lines, want) in rows {
            let head = format!("GET / HTTP/1.1\r\nHost: allowed.test\r\n{lines}\r\n");
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut request = httparse::Request::new(&mut headers);
            request.parse(head.as_bytes()).expect("parses");
            assert_eq!(connection_semantics(request.headers), *want, "{lines:?}");
        }
    }

    /// The chunked-framing details are pinned text (module docs point 3); the
    /// `MAX_CHUNK_LINE` agreement is pinned in h1's tests.
    #[test]
    fn chunked_framing_details_pinned() {
        assert_eq!(FRAMING_CHUNK_SIZE, "invalid chunk-size line");
        assert_eq!(
            FRAMING_CHUNK_LINE_TOO_LONG,
            "chunk-size line exceeds the 4096-byte cap"
        );
        assert_eq!(
            FRAMING_CHUNK_DATA_CRLF,
            "chunk data is not followed by CRLF"
        );
        assert_eq!(FRAMING_TRAILER_INVALID, "invalid chunked trailer section");
        assert_eq!(
            FRAMING_TRAILER_TOO_LARGE,
            "chunked trailer section exceeds the head caps"
        );
        assert_eq!(
            FRAMING_TRAILER_FORBIDDEN,
            "chunked trailer names Host, Content-Length or Transfer-Encoding"
        );
        let denial = Rejected::AmbiguousFraming {
            detail: FRAMING_CHUNK_SIZE,
        };
        assert_eq!(
            denial.reason(),
            "ambiguous HTTP request framing: invalid chunk-size line"
        );
    }

    /// The drift alarm for the head-agreement assumption (module docs of the
    /// stream, point 1): httparse must keep rejecting obs-fold and whitespace
    /// before the colon in REQUESTS. If a httparse upgrade starts accepting
    /// either, the terminator and framing reasoning must be re-read.
    #[test]
    fn httparse_rejects_obs_fold_and_ws_before_colon() {
        let rows: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A: b\r\n c\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nX-A : b\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : allowed.test\r\n\r\n",
        ];
        for head in rows {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut request = httparse::Request::new(&mut headers);
            assert!(request.parse(head).is_err(), "{head:?} must not parse");
        }
    }

    /// Issue #29 review, item 6: a bare LF anywhere in the request head is
    /// denied with `FRAMING_BARE_LF`, on request 1 (the decision-phase parse)
    /// and on requests 2+ (`inspect_head`). Bytes past the terminator are not
    /// part of the head and never trigger it.
    #[test]
    fn bare_lf_in_the_head_is_denied_before_parsing() {
        let rows: &[&[u8]] = &[
            b"GET / HTTP/1.1\nHost: allowed.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: allowed.test\nX: y\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\n\r\n",
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nX: a\n b\r\n\r\n",
        ];
        let expected = Rejected::AmbiguousFraming {
            detail: FRAMING_BARE_LF,
        };
        let check_expected = dom("allowed.test");
        let check = check_allowed(&check_expected);
        for head in rows {
            assert_eq!(parse(head), Err(expected.clone()), "parse {head:?}");
            assert_eq!(
                inspect_head(head, &check, 64),
                Err(expected.clone()),
                "inspect_head {head:?}"
            );
        }
        // A bare LF AFTER the head (in the pipelined bytes) is not part of it.
        let mut pipelined = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_vec();
        let head_len = pipelined.len();
        pipelined.extend_from_slice(b"GET /b HTTP/1.1\nHost: x\n\n");
        assert_eq!(parse(&pipelined), Ok(head_len));
        assert!(!head_has_bare_lf(&pipelined));
    }

    /// Issue #29 review, item 7: a framing header whose name spells `_` is
    /// denied (`Content_Length` is read by some servers as `Content-Length`).
    /// Names that merely contain the framing words are not affected.
    #[test]
    fn underscore_framing_names_are_denied() {
        let denied: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: allowed.test\r\nContent_Length: 5\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: allowed.test\r\ncontent_length: 5\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: allowed.test\r\nTransfer_Encoding: chunked\r\n\r\n",
        ];
        for head in denied {
            assert_eq!(
                parse(head),
                Err(Rejected::AmbiguousFraming {
                    detail: FRAMING_UNDERSCORE_NAME,
                }),
                "{head:?}"
            );
        }
        // Neighbouring names are untouched, and so is a plain Content-Length.
        let ok = b"POST / HTTP/1.1\r\nHost: allowed.test\r\nX_Content-Length: 5\r\nContent-Length: 0\r\n\r\n";
        assert!(parse(ok).is_ok(), "{ok:?}");
        assert_eq!(FRAMING_BARE_LF, "bare LF line ending in the request head");
        assert_eq!(
            FRAMING_UNDERSCORE_NAME,
            "a framing header name uses an underscore (Content_Length or Transfer_Encoding)"
        );
    }

    // ---- the pure-parser table ----------------------------------------------

    #[test]
    fn parse_head_table() {
        // Every rule above, both outcomes, consumed-length asserted on the
        // Ok rows — over byte slices directly (module docs point 2).
        let ok_rows: &[&[u8]] = &[
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: allowed.test\r\n\r\n",
            b"HEAD /a HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            b"POST /p HTTP/1.1\r\nHost: allowed.test:80\r\nContent-Length: 0\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            b"GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            // The header NAME is case-insensitive; the value's OWS is
            // trimmed; one root dot is stripped.
            b"GET / HTTP/1.1\r\nhost: allowed.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost:allowed.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: \t allowed.test \t\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: allowed.test.\r\n\r\n",
        ];
        for head in ok_rows {
            assert_eq!(parse(head), Ok(head.len()), "{head:?}");
        }
        // Pipelined bytes past the terminator stay in the buffer but are
        // NOT consumed.
        let with_body = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\nBODY";
        assert_eq!(
            parse(with_body),
            Ok("GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n".len())
        );
        let err_rows: Vec<(&[u8], Rejected)> = vec![
            (
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
                Rejected::Http2Preface,
            ),
            (
                b"CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
                Rejected::ConnectMethod,
            ),
            (b"GET / HTTP/1.1\r\n\r\n".as_slice(), Rejected::HostMissing),
            (
                b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n".as_slice(),
                Rejected::HostMultiple,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: notallowed.test\r\n\r\n".as_slice(),
                Rejected::HostMismatch {
                    host: dom("notallowed.test"),
                    name: dom("allowed.test"),
                    source: NameSource::DnsMap,
                },
            ),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n".as_slice(),
                Rejected::HostPortMismatch {
                    got: 443,
                    want: 80,
                    source: NameSource::DnsMap,
                },
            ),
            (
                b"GET http://evil.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
                Rejected::TargetMismatch {
                    target: "evil.test".to_owned(),
                    name: dom("allowed.test"),
                    source: NameSource::DnsMap,
                },
            ),
            (
                b"GET ftp://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
                Rejected::HttpMalformed {
                    detail: "absolute-form request target must use http:// on port 80".to_owned(),
                },
            ),
            (
                b"GET allowed.test HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
                Rejected::HttpMalformed {
                    detail: "unrecognized request-target form \"allowed.test\"".to_owned(),
                },
            ),
        ];
        for (head, expected) in err_rows {
            assert_eq!(parse(head), Err(expected), "{head:?}");
        }
    }
}
