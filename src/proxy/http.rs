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

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{Limits, Rejected, canonicalize_host};
use crate::policy::Domain;

/// The head terminator — the read loop stops after the first occurrence.
const HEAD_TERMINATOR: [u8; 4] = *b"\r\n\r\n";

/// The pinned denial detail when httparse's consumed extent disagrees
/// with the located `\r\n\r\n` terminator (module docs point 1): a bare-LF
/// head plus CRLF junk is two different requests to two different parsers
/// — the request-smuggling differential, denied fail-closed. Single source
/// shared by [`inspect_http`] and its pin test.
const HEAD_TERMINATOR_MISMATCH: &str = "request head terminator mismatch";

/// The HTTP/2 client connection preface's request-line shape (RFC 7540
/// §3.5) — denied with its own pinned row (module docs point 2).
const H2_PREFACE_PREFIX: &[u8] = b"PRI * HTTP/2.0";

/// Per-read chunk size for the inspection loop (the cap, not this, bounds
/// the buffer).
const READ_CHUNK: usize = 4096;

/// Read + inspect the HTTP request head on 80 (module docs point 1).
/// Returns the FULL replay buffer (head + any pipelined body bytes) on
/// success.
pub(crate) async fn inspect_http<S: AsyncRead + Unpin>(
    client: &mut S,
    expected: &Domain,
    orig_port: u16,
    limits: &Limits,
) -> Result<Vec<u8>, Rejected> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    // Bytes already ruled out as a terminator start; the search resumes
    // 3 bytes earlier so a terminator straddling two reads is found.
    let mut scanned = 0usize;
    loop {
        if let Some(head_end) = find_terminator(&buf, &mut scanned) {
            // parse_head returns the consumed head length; the FULL buffer
            // (head + pipelined body) is the replay.
            let consumed = parse_head(&buf, expected, orig_port, limits.max_http_headers)?;
            // The parser and the terminator search MUST agree on where the
            // head ends (module docs point 1): httparse tolerates bare-LF
            // line endings, the search does not, and a differential means
            // two parsers see two different requests in the same bytes —
            // the smuggling shape, denied fail-closed, never relayed.
            if consumed != head_end {
                return Err(Rejected::HttpMalformed {
                    detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
                });
            }
            return Ok(buf);
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

/// The index just past the first `\r\n\r\n` in `buf`, with an incremental
/// search: `scanned` tracks the frontier already ruled out and is rewound
/// by the 3-byte overlap on every call.
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

/// The PURE head parser (module docs points 2-5; `parse_head_table` drives
/// it over byte slices directly). `head` may carry pipelined bytes past
/// the terminator — httparse reports the consumed head length, which this
/// returns on success.
pub(crate) fn parse_head(
    head: &[u8],
    expected: &Domain,
    orig_port: u16,
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
        // That is #8's job — never the transparent port.
        return Err(Rejected::ConnectMethod);
    }
    let Some(target) = request.path else {
        return Err(Rejected::HttpMalformed {
            detail: "missing request-target".to_owned(),
        });
    };
    check_target(target, expected, orig_port)?;
    check_host(request.headers, expected, orig_port)?;
    Ok(consumed)
}

/// The request-target rules (module docs point 4).
fn check_target(target: &str, expected: &Domain, orig_port: u16) -> Result<(), Rejected> {
    // Origin-form or asterisk-form: accepted as-is — NO URL/path rules in
    // v1 (#17 owns verb/path filtering).
    if target == "*" || target.starts_with('/') {
        return Ok(());
    }
    let mismatch = || Rejected::TargetMismatch {
        target: target.to_owned(),
        name: expected.clone(),
    };
    let Some((scheme, rest)) = target.split_once("://") else {
        // Neither origin-form, asterisk, nor absolute-form: unverifiable
        // ⇒ fail-closed.
        return Err(Rejected::HttpMalformed {
            detail: format!("unrecognized request-target form {target:?}"),
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
    // The optional :port must equal the original destination port (Q5's
    // rule for the target side); every mismatch shape — wrong port,
    // non-digit suffix, junk host — is the single TargetMismatch variant.
    let host_part = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let port_matches = port.parse::<u16>().is_ok_and(|p| p == orig_port);
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

/// The `Host` header rules, in the pinned order (module docs point 5).
fn check_host(
    headers: &[httparse::Header<'_>],
    expected: &Domain,
    orig_port: u16,
) -> Result<(), Rejected> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value);
    let Some(raw) = values.next() else {
        return Err(Rejected::HostMissing);
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
    // ORIGINAL destination port. A non-digit suffix ("[::1]", "8x") is
    // left to Domain::parse ⇒ HostInvalid.
    let host_part = match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let Ok(port) = port.parse::<u16>() else {
                // Overflow (e.g. ":99999"): the full value is not a bare
                // hostname either — fail-closed.
                return Err(Rejected::HostInvalid {
                    value: value.to_owned(),
                });
            };
            if port != orig_port {
                return Err(Rejected::HostPortMismatch {
                    got: port,
                    want: orig_port,
                });
            }
            host
        }
        _ => value,
    };
    let Some(host) = canonicalize_host(host_part) else {
        return Err(Rejected::HostInvalid {
            value: host_part.to_owned(),
        });
    };
    if host != *expected {
        return Err(Rejected::HostMismatch {
            host,
            name: expected.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

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
        // The replay buffer carries the head AND the pipelined body bytes.
        let mut bytes = Vec::from(b"POST /x HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice());
        bytes.extend_from_slice(b"body-bytes");
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        let limits = Limits::default();
        let result = block_on(async {
            peer.write_all(&bytes).await.expect("write");
            inspect_http(&mut client, &expected, 80, &limits).await
        });
        assert_eq!(result.expect("must pass"), bytes);
    }

    #[test]
    fn inspect_http_straddling_reads_still_find_terminator() {
        // The 3-byte overlap contract: a tiny duplex capacity forces the
        // head to arrive in many small reads, so the \r\n\r\n terminator
        // straddles chunk boundaries — the incremental search must still
        // find it and the replay buffer must accumulate every byte
        // exactly, whatever the split points are.
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
        assert_eq!(result.expect("must pass"), head.to_vec());
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

    #[test]
    fn inspect_http_bare_lf_differential_denied() {
        // m1 pin: httparse terminates lines at a bare LF too; the read
        // loop stops only at \r\n\r\n. A bare-LF head followed by junk
        // containing a real \r\n\r\n parses to a SHORTER extent than the
        // located terminator — two parsers see two different requests in
        // the same bytes (the request-smuggling shape) ⇒ denied, never
        // relayed.
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
            head.to_vec()
        );
        let mut with_body = head.to_vec();
        with_body.extend_from_slice(b"body");
        assert_eq!(
            inspect_with(&with_body, Limits::default(), false).expect("CRLF head + body must pass"),
            with_body
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
                .expect("a complete head beats the shrunk cap (terminator-first)"),
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
                },
            ),
            (
                b"GET / HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n".as_slice(),
                Rejected::HostPortMismatch { got: 443, want: 80 },
            ),
            (
                b"GET http://evil.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
                Rejected::TargetMismatch {
                    target: "http://evil.test/".to_owned(),
                    name: dom("allowed.test"),
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
