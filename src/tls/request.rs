//! The request-head checks on a terminated connection (issue #17, D5).
//!
//! 1. **One request, strictly checked.** The terminated connection carries
//!    exactly one HTTP/1.1 request. [`check_request`] parses it with httparse
//!    (the same parser and terminator agreement as the port-80 path) and
//!    denies everything v1 does not carry, in this order: CONNECT, a
//!    non-origin-form target (absolute-form, `*`), a missing or wrong `Host`
//!    (exactly one, equal to the SNI name, optional `:443`), any upgrade, any
//!    URL-override header (`X-Original-URL` and kin), any
//!    `Transfer-Encoding` (chunked uploads are unsupported), an ambiguous
//!    framing shape, and finally a path no `network.paths` rule of that host
//!    permits. The HTTP/2 preface is denied as malformed.
//! 2. **No path text in a reason.** [`Rejected::PathNotAllowed`] names the
//!    host only; the target itself is never copied into the audit row.
//! 3. **Host is the R1 check.** The sandbox cannot route to a different
//!    virtual host over the same verified connection: after termination the
//!    `Host` must equal the SNI the client was verified against.

use httparse::Header;

use crate::policy::{Domain, UrlPrefix};
use crate::proxy::NameSource;
use crate::proxy::Rejected;
use crate::proxy::TLS_PORT;
use crate::proxy::http::{
    FRAMING_BARE_LF, Framing, HEAD_TERMINATOR_MISMATCH, check_framing, check_host,
    head_has_bare_lf, trim_ows,
};

/// The HTTP/2 client connection preface's request line (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0";

/// Request fields that re-route a request on some upstreams, denied on a
/// terminated connection because the path rule checks only the request target.
const URL_OVERRIDE_FIELDS: [&str; 4] = [
    "x-original-url",
    "x-rewrite-url",
    "x-original-uri",
    "x-override-url",
];

/// The pinned detail for any `Transfer-Encoding` on a terminated request.
pub(crate) const CHUNKED_DETAIL: &str =
    "Transfer-Encoding request bodies (chunked uploads) are not supported";

/// Validate one request head (`head` = exactly the bytes through the
/// terminator) against the SNI name and the policy's path rules. Returns the
/// framing so the caller knows how much body to forward.
pub(crate) fn check_request(
    head: &[u8],
    name: &Domain,
    paths: &[UrlPrefix],
    max_headers: usize,
) -> Result<Framing, Rejected> {
    // A bare LF inside the head is denied before httparse runs, as on every
    // other path (issue #29: httparse accepts it mid-head).
    if head_has_bare_lf(head) {
        return Err(Rejected::AmbiguousFraming {
            detail: FRAMING_BARE_LF,
        });
    }
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(head) {
        Err(err) => {
            if head.starts_with(H2_PREFACE) {
                return Err(Rejected::Http2Preface);
            }
            return Err(Rejected::HttpMalformed {
                detail: err.to_string(),
            });
        }
        Ok(httparse::Status::Partial) => {
            return Err(Rejected::HttpMalformed {
                detail: "incomplete request head".to_owned(),
            });
        }
        Ok(httparse::Status::Complete(consumed)) => consumed,
    };
    // The parser and the terminator search must agree on the head's extent
    // (the smuggling differential; see http.rs point 1).
    if consumed != head.len() {
        return Err(Rejected::HttpMalformed {
            detail: HEAD_TERMINATOR_MISMATCH.to_owned(),
        });
    }
    let Some(method) = request.method else {
        return Err(Rejected::HttpMalformed {
            detail: "missing method".to_owned(),
        });
    };
    if method == "CONNECT" {
        return Err(Rejected::UnsupportedRequest { detail: "CONNECT" });
    }
    let Some(target) = request.path else {
        return Err(Rejected::HttpMalformed {
            detail: "missing request-target".to_owned(),
        });
    };
    if !target.starts_with('/') {
        return Err(Rejected::UnsupportedRequest {
            detail: "the request target is not origin-form",
        });
    }
    check_host(request.headers, name, TLS_PORT, NameSource::Sni, true)?;
    let fields: &[Header<'_>] = request.headers;
    if fields.iter().any(|field| {
        field.name.eq_ignore_ascii_case("upgrade")
            || (field.name.eq_ignore_ascii_case("connection")
                && connection_lists_upgrade(field.value))
    }) {
        return Err(Rejected::UnsupportedRequest { detail: "Upgrade" });
    }
    // PR #64 review m3: headers some servers and frameworks honor to re-route
    // a request (IIS URL Rewrite, older Symfony) would bypass the path rule.
    // `_` is compared as `-`: CGI/FastCGI stacks map both spellings to the same
    // `HTTP_X_ORIGINAL_URL` variable.
    if fields.iter().any(|field| {
        let name = field.name.replace('_', "-");
        URL_OVERRIDE_FIELDS
            .iter()
            .any(|known| name.eq_ignore_ascii_case(known))
    }) {
        return Err(Rejected::UnsupportedRequest {
            detail: "URL-override header",
        });
    }
    if fields
        .iter()
        .any(|field| field.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(Rejected::UnsupportedRequest {
            detail: CHUNKED_DETAIL,
        });
    }
    let framing = check_framing(fields, request.version.unwrap_or(1))?;
    let permitted = paths
        .iter()
        .filter(|rule| rule.host() == name)
        .any(|rule| rule.permits_target(target));
    if !permitted {
        return Err(Rejected::PathNotAllowed { host: name.clone() });
    }
    Ok(framing)
}

/// Whether a `Connection` field's token list names `upgrade` (RFC 9110
/// §7.6.1): the token is decisive even without an `Upgrade` field.
fn connection_lists_upgrade(value: &[u8]) -> bool {
    value
        .split(|byte| *byte == b',')
        .any(|token| trim_ows(token).eq_ignore_ascii_case(b"upgrade"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name() -> Domain {
        Domain::parse("api.example.com").expect("fixture name")
    }

    fn rules() -> Vec<UrlPrefix> {
        vec![UrlPrefix::parse("https://api.example.com/v1/").expect("fixture rule")]
    }

    /// A head exactly as the terminator passes it: through the terminator.
    fn head(lines: &str) -> Vec<u8> {
        format!("{lines}\r\n\r\n").into_bytes()
    }

    fn check(lines: &str) -> Result<Framing, Rejected> {
        check_request(&head(lines), &name(), &rules(), 64)
    }

    #[test]
    fn a_bare_lf_in_the_head_is_denied() {
        // Issue #29: the terminated path refuses a bare LF like every other.
        assert_eq!(
            check("GET /v1/items HTTP/1.1\nHost: api.example.com"),
            Err(Rejected::AmbiguousFraming {
                detail: FRAMING_BARE_LF
            })
        );
    }

    #[test]
    fn allowed_requests_return_their_framing() {
        assert_eq!(
            check("GET /v1/items HTTP/1.1\r\nHost: api.example.com"),
            Ok(Framing::None)
        );
        assert_eq!(
            check("POST /v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5"),
            Ok(Framing::Length(5))
        );
        // The optional TLS-port suffix on Host is accepted (RFC 9110 §7.2).
        assert_eq!(
            check("GET /v1/x HTTP/1.1\r\nHost: api.example.com:443"),
            Ok(Framing::None)
        );
    }

    #[test]
    fn host_must_equal_the_sni_name() {
        match check("GET /v1/x HTTP/1.1\r\nHost: evil.example.com") {
            Err(Rejected::HostMismatch { source, .. }) => assert_eq!(source, NameSource::Sni),
            other => panic!("expected HostMismatch, got {other:?}"),
        }
        assert!(matches!(
            check("GET /v1/x HTTP/1.1"),
            Err(Rejected::HostMissing)
        ));
        assert!(matches!(
            check("GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\nHost: api.example.com"),
            Err(Rejected::HostMultiple)
        ));
        assert!(matches!(
            check("GET /v1/x HTTP/1.1\r\nHost: api.example.com:8443"),
            Err(Rejected::HostPortMismatch {
                got: 8443,
                want: 443,
                ..
            })
        ));
    }

    #[test]
    fn absolute_form_and_connect_are_unsupported() {
        assert!(matches!(
            check("GET http://api.example.com/v1/x HTTP/1.1\r\nHost: api.example.com"),
            Err(Rejected::UnsupportedRequest { .. })
        ));
        assert!(matches!(
            check("OPTIONS * HTTP/1.1\r\nHost: api.example.com"),
            Err(Rejected::UnsupportedRequest { .. })
        ));
        assert_eq!(
            check("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com"),
            Err(Rejected::UnsupportedRequest { detail: "CONNECT" })
        );
    }

    #[test]
    fn upgrades_and_transfer_encoding_are_unsupported() {
        for lines in [
            "GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket",
            "GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\nConnection: keep-alive, Upgrade",
        ] {
            assert_eq!(
                check(lines),
                Err(Rejected::UnsupportedRequest { detail: "Upgrade" }),
                "{lines}"
            );
        }
        assert_eq!(
            check("POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked"),
            Err(Rejected::UnsupportedRequest {
                detail: CHUNKED_DETAIL
            })
        );
        // CL + TE is unsupported before the framing table would call it ambiguous.
        assert!(matches!(
            check(
                "POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked"
            ),
            Err(Rejected::UnsupportedRequest { .. })
        ));
    }

    #[test]
    fn url_override_headers_are_unsupported() {
        for field in [
            "X-Original-URL",
            "x-rewrite-url",
            "X-Original-URI",
            "X-Override-URL",
            "X_Original_URL",
        ] {
            let lines = format!("GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\n{field}: /admin");
            assert_eq!(
                check(&lines),
                Err(Rejected::UnsupportedRequest {
                    detail: "URL-override header"
                }),
                "{field}"
            );
        }
    }

    #[test]
    fn non_ascii_targets_are_denied() {
        assert!(matches!(
            check_request(
                "GET /v1/\u{ff0e}\u{ff0e}/admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
                    .as_bytes(),
                &name(),
                &rules(),
                64
            ),
            Err(Rejected::PathNotAllowed { .. } | Rejected::HttpMalformed { .. })
        ));
    }

    #[test]
    fn ambiguous_framing_is_denied() {
        assert!(matches!(
            check(
                "POST /v1/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\nContent-Length: 1"
            ),
            Err(Rejected::AmbiguousFraming { .. })
        ));
    }

    #[test]
    fn path_outside_the_rules_is_denied_without_path_text() {
        match check("GET /admin/secret HTTP/1.1\r\nHost: api.example.com") {
            Err(Rejected::PathNotAllowed { host }) => {
                assert_eq!(host, name());
                let reason = Rejected::PathNotAllowed { host }.reason();
                assert!(!reason.contains("admin"), "path text leaked: {reason}");
                assert!(reason.contains("api.example.com"));
            }
            other => panic!("expected PathNotAllowed, got {other:?}"),
        }
        // Dot segments and percent-encoding never reach the rule.
        for lines in [
            "GET /v1/../admin HTTP/1.1\r\nHost: api.example.com",
            "GET /v1/%2e%2e/admin HTTP/1.1\r\nHost: api.example.com",
        ] {
            assert!(
                matches!(check(lines), Err(Rejected::PathNotAllowed { .. })),
                "{lines}"
            );
        }
    }

    #[test]
    fn http2_preface_and_garbage_are_malformed() {
        assert_eq!(
            check_request(b"PRI * HTTP/2.0\r\n\r\n", &name(), &rules(), 64),
            Err(Rejected::Http2Preface)
        );
        assert!(matches!(
            check_request(b"\x16\x03\x01\r\n\r\n", &name(), &rules(), 64),
            Err(Rejected::HttpMalformed { .. })
        ));
    }

    #[test]
    fn the_head_must_be_exactly_the_parsed_extent() {
        // Pipelined bytes after the terminator are not part of the head: the
        // head check sees only what the terminator located.
        let mut extra = head("GET /v1/x HTTP/1.1\r\nHost: api.example.com");
        extra.extend_from_slice(b"GET /v1/y HTTP/1.1\r\n");
        assert!(matches!(
            check_request(&extra, &name(), &rules(), 64),
            Err(Rejected::HttpMalformed { .. })
        ));
    }
}
