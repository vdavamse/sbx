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
//!    #8) → request-target rules → `Host` rules. NO verb/path filtering in
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
//! 6. **The connection lifetime is enforced (round-2 review fix)** — the
//!    name binding above covers the FIRST head only; HTTP/1.1 defaults to
//!    keep-alive, so a subsequent request with a foreign `Host` would ride
//!    the unscanned relay to a vhost-routing server (CDN edges co-host
//!    thousands of names per IP — an allow-list bypass needing NO server
//!    quirk at all, since vhost routing by `Host` is the intended behavior
//!    of fully compliant servers). [`inspect_http`] therefore REWRITES the
//!    validated head to carry `Connection: close` before it is replayed —
//!    inserted immediately before the final CRLF; the request line, every
//!    client header, and every body byte stay byte-identical (POST/PUT
//!    untouched). A pre-existing client `Connection` header is kept
//!    verbatim: RFC 9110 combines the field's values as a list, and the
//!    `close` token in it is decisive — RFC 9112 §9.6 obliges a conforming
//!    server to close after responding and to NOT process further requests
//!    on the connection. Deliberate costs: no keep-alive for sandbox HTTP
//!    clients (every request is re-inspected and re-audited on its own
//!    connection — fail-closed by construction), no protocol upgrades on
//!    port 80 (the inserted `close` rides the combined `Connection` list —
//!    RFC 9110 §7.6.1 — and §9.6's close-after-response obligation is
//!    irreconcilable with a 101 switch, RFC 9110 §7.8, so conforming
//!    servers will not honor `ws://` WebSocket — RFC 6455 §4.1 — or `h2c`
//!    upgrade handshakes), and the ONE documented deviation from "the
//!    upstream sees the client's byte stream verbatim" (mod.rs point 9).
//!    Recorded residuals (mod.rs point 12): a NON-conforming server
//!    ignoring `Connection: close` (one that also honors an upgrade opens
//!    an uninspectable tunnel, not merely follow-up requests), and the
//!    443 twin no rewrite can reach — h2 `:authority` vhost confusion after an
//!    SNI-checked handshake (ALPN rides through uninspected; inherent to
//!    any non-terminating proxy; #14's threat model). A full per-request
//!    relay scanner (this module's [`crate::proxy::relay::RelayScanner`]
//!    analogue) remains the shape for lifting the no-keep-alive cost.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{Limits, NameSource, Rejected, canonicalize_host, redact_for_audit};
use crate::policy::Domain;

/// The head terminator — the read loop stops after the first occurrence.
const HEAD_TERMINATOR: [u8; 4] = *b"\r\n\r\n";

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
/// bound the loop; the caller owns the decision timeout.
pub(crate) async fn read_head<S: AsyncRead + Unpin>(
    client: &mut S,
    limits: &Limits,
) -> Result<Head, Rejected> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    // Bytes already ruled out as a terminator start; the search resumes
    // 3 bytes earlier so a terminator straddling two reads is found.
    let mut scanned = 0usize;
    loop {
        if let Some(head_end) = find_terminator(&buf, &mut scanned) {
            return Ok(Head { buf, head_end });
        }
        if buf.len() > limits.max_head_bytes {
            return Err(Rejected::HeadTooLarge {
                cap: limits.max_head_bytes,
            });
        }
        match client.read(&mut chunk).await {
            Ok(0) => return Err(Rejected::Eof),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // Transport failure = the client is gone before a complete
            // preamble — the same fail-closed family as a clean EOF (same
            // documented choice as hello.rs).
            Err(_err) => return Err(Rejected::Eof),
        }
    }
}

/// Locate the `\r\n\r\n` terminator in `buf`, returning the offset just
/// past it. `scanned` records how far the buffer was already ruled out, so
/// the next call resumes 3 bytes earlier (a terminator straddling two
/// reads is still found) instead of rescanning from the start.
fn find_terminator(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    let from = scanned.saturating_sub(3);
    if let Some(rel) = buf
        .get(from..)?
        .windows(4)
        .position(|window| window == HEAD_TERMINATOR)
    {
        return Some(from + rel + HEAD_TERMINATOR.len());
    }
    *scanned = buf.len();
    None
}

/// Insert [`CONNECTION_CLOSE_HEADER`] before the head's final CRLF
/// (module docs point 6). `head_end` is the index just past the located
/// `\r\n\r\n` — always ≥ the 4-byte terminator — so the insertion point is
/// `head_end - 2`; everything else (request line, client headers,
/// pipelined body bytes) stays byte-identical.
fn force_connection_close(buf: &mut Vec<u8>, head_end: usize) {
    let at = head_end - 2;
    buf.splice(at..at, CONNECTION_CLOSE_HEADER.iter().copied());
}

/// The per-request check inputs (issue #8, Q4): the name to match, the
/// port, the [`NameSource`] for wording and redaction, and whether the
/// strict framing rules apply (explicit paths only — transparent :80 keeps
/// the #7 behaviour, follow-up F2).
pub(crate) struct HeadCheck<'a> {
    pub expected: &'a Domain,
    pub port: u16,
    pub source: NameSource,
    pub strict_framing: bool,
}

/// Read + inspect the HTTP request head on 80 (module docs point 1).
/// Returns the FULL replay buffer (head + any pipelined body bytes) on
/// success. This is [`inspect_http_with`] for the transparent path (#7
/// behaviour, pinned).
pub(crate) async fn inspect_http<S: AsyncRead + Unpin>(
    client: &mut S,
    expected: &Domain,
    orig_port: u16,
    limits: &Limits,
) -> Result<Vec<u8>, Rejected> {
    let check = HeadCheck {
        expected,
        port: orig_port,
        source: NameSource::DnsMap,
        strict_framing: false,
    };
    inspect_http_with(client, &check, limits).await
}

/// Read, validate and frame-check one request head, then force
/// `Connection: close` (issue #8 seam; #7's `inspect_http` is the DnsMap
/// wrapper). Returns the FULL buffer (head + pipelined bytes) to replay.
pub(crate) async fn inspect_http_with<S: AsyncRead + Unpin>(
    client: &mut S,
    check: &HeadCheck<'_>,
    limits: &Limits,
) -> Result<Vec<u8>, Rejected> {
    let Head { mut buf, head_end } = read_head(client, limits).await?;
    // parse_head_with returns the consumed head length; the FULL buffer
    // (head + pipelined body) is the replay.
    let consumed = parse_head_with(&buf, check, limits.max_http_headers)?;
    // The parser and the terminator search MUST agree on where the head
    // ends (module docs point 1): httparse tolerates bare-LF line endings,
    // the search does not, and a differential means two parsers see two
    // different requests in the same bytes — the smuggling shape, denied
    // fail-closed, never relayed.
    if consumed != head_end {
        return Err(Rejected::HttpMalformed {
            detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
        });
    }
    // The connection-lifetime enforcement (module docs point 6): the
    // validated head is rewritten to carry Connection: close BEFORE it is
    // replayed. Runs AFTER the differential check above; the rewrite never
    // feeds back into parse_head_with.
    force_connection_close(&mut buf, head_end);
    Ok(buf)
}

/// The #7 entry point (DnsMap wording, lenient framing) — kept as a thin
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
        strict_framing: false,
    };
    parse_head_with(head, &check, max_headers)
}

/// The PURE head parser (module docs points 2-5; `parse_head_table` drives
/// it over byte slices directly). `head` may carry pipelined bytes past
/// the terminator — httparse reports the consumed head length, which this
/// returns on success.
pub(crate) fn parse_head_with(
    head: &[u8],
    check: &HeadCheck<'_>,
    max_headers: usize,
) -> Result<usize, Rejected> {
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
    if check.strict_framing {
        check_framing(request.headers, request.version.unwrap_or(1))?;
    }
    Ok(consumed)
}

/// Client text in a non-DnsMap reason goes through [`redact_for_audit`]
/// (issue #8, D4); DnsMap rows keep #7's verbatim wording.
pub(crate) fn for_source(source: NameSource, raw: &str) -> String {
    match source {
        NameSource::DnsMap => raw.to_owned(),
        NameSource::ConnectTarget | NameSource::RequestTarget => redact_for_audit(raw),
    }
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
        target: for_source(source, target),
        name: expected.clone(),
        source,
    };
    let Some((scheme, rest)) = target.split_once("://") else {
        // Neither origin-form, asterisk, nor absolute-form: unverifiable
        // ⇒ fail-closed.
        return Err(Rejected::HttpMalformed {
            detail: format!(
                "unrecognized request-target form {:?}",
                for_source(source, target)
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
                    value: for_source(source, value),
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
            value: for_source(source, host_part),
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

/// The framing a request declares (issue #8, explicit paths).
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

/// The strict framing table (issue #8, Q8): deny every shape whose body
/// boundary two parsers could disagree on. Checked in this pinned order.
pub(crate) fn check_framing(
    headers: &[httparse::Header<'_>],
    minor_version: u8,
) -> Result<Framing, Rejected> {
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
                    target: line
                        .strip_prefix("GET ")
                        .and_then(|rest| rest.split(' ').next())
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
                target: "http://allowed.test:8080/".to_owned(),
                name: dom("allowed.test"),
                source: NameSource::DnsMap,
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
        // The replay buffer carries the head AND the pipelined body bytes
        // — the head with the inserted Connection: close (module docs
        // point 6), the body byte-identical.
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
        assert_eq!(result.expect("must pass"), closed_at(&bytes, head_end));
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
        assert_eq!(result.expect("must pass"), closed_at(head, head.len()));
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
    fn inspect_with(bytes: &[u8], limits: Limits, close_after: bool) -> Result<Vec<u8>, Rejected> {
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

    /// The expected replay for a validated head: `Connection: close`
    /// inserted before the final CRLF of the head ending at `head_end`
    /// (module docs point 6); every other byte — including any pipelined
    /// body — identical.
    fn closed_at(input: &[u8], head_end: usize) -> Vec<u8> {
        let mut out = input[..head_end - 2].to_vec();
        out.extend_from_slice(CONNECTION_CLOSE_HEADER);
        out.extend_from_slice(&input[head_end - 2..]);
        out
    }

    #[test]
    fn inspect_http_forces_connection_close() {
        // The name binding must outlive the first head (module docs point
        // 6, round-2 review fix): HTTP/1.1 keep-alive would let a
        // foreign-Host follow-up request ride the unscanned relay to a
        // vhost-routing server. The validated head is therefore rewritten
        // to carry Connection: close — byte-exact, immediately before the
        // final CRLF — while the request line, the client headers, and the
        // pipelined body bytes stay untouched (POST/PUT unaffected).
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        let result = inspect_with(head, Limits::default(), false).expect("must pass");
        assert_eq!(
            result,
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
        );
        let mut with_body = Vec::from(head.as_slice());
        with_body.extend_from_slice(b"body");
        let result = inspect_with(&with_body, Limits::default(), false).expect("must pass");
        assert_eq!(result, closed_at(&with_body, head.len()));
    }

    #[test]
    fn existing_connection_headers_do_not_defeat_close() {
        // A client-supplied Connection header is kept VERBATIM (the
        // rewrite is a single insertion — the differential check and the
        // body bytes rely on that), and the inserted close token still
        // rides the combined field list: RFC 9112 §9.6 makes `close`
        // decisive for a conforming server even next to keep-alive. An
        // already-present close is a harmless duplicate.
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: keep-alive\r\n\r\n";
        let result = inspect_with(head, Limits::default(), false).expect("must pass");
        assert_eq!(result, closed_at(head, head.len()));
        assert!(
            result
                .windows(CONNECTION_CLOSE_HEADER.len())
                .any(|window| window == CONNECTION_CLOSE_HEADER),
            "the close token must ride the replay: {result:?}"
        );
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
        let result = inspect_with(head, Limits::default(), false).expect("must pass");
        assert_eq!(result, closed_at(head, head.len()));
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
        assert_eq!(
            result.expect_err("the parser differential must deny"),
            Rejected::HttpMalformed {
                detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
            }
        );
        // The accepted side: a normal CRLF head parses to exactly the
        // terminator, so the equality check is invisible to well-formed
        // traffic (with and without a pipelined body).
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        assert_eq!(
            inspect_with(head, Limits::default(), false).expect("CRLF head must pass"),
            closed_at(head, head.len())
        );
        let mut with_body = head.to_vec();
        with_body.extend_from_slice(b"body");
        assert_eq!(
            inspect_with(&with_body, Limits::default(), false).expect("CRLF head + body must pass"),
            closed_at(&with_body, head.len())
        );
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
            inspect_with(head, at_cap, false).expect("len == cap must pass"),
            closed_at(head, head.len())
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
                .expect("a complete head beats the shrunk cap (terminator-first)"),
            closed_at(head, head.len())
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
                    target: "http://evil.test/".to_owned(),
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
