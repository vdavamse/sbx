//! The egress decision core — the two pure predicates every egress
//! decision calls (issue #4).
//!
//! 1. **Ownership** — [`allowed`] decides the name side, `guard()` the
//!    address side; no I/O, no state, no allocation beyond one
//!    normalization `String` per [`allowed`] call. Consumers: #7 (TLS SNI
//!    match + dial-time address guard), #8 (CONNECT/absolute-form host),
//!    #9 (the fake-IP resolver's queried name); #10 logs [`RuleMatch`] and
//!    `Denied`.
//! 2. **Fail-closed** — every path that is not an explicit allow denies:
//!    normalization failure ⇒ `None`; empty allow list ⇒ `None`;
//!    `guard()` denies the full IANA special-purpose registries (fetched
//!    2025-10-09) plus multicast and the deprecated-but-delisted ranges.
//!    Outside the tables is dialable *by design*: the allow list decides
//!    names, the guard decides addresses.
//! 3. **Normalization seam** — strip exactly one trailing ASCII root dot,
//!    then [`Domain::parse`]: the same single pipeline as policy time. The
//!    asymmetry is deliberate — policy authors write dot-less names and are
//!    *rejected* for a root dot; runtime input is adversarial and may carry
//!    the dot a resolver appended.
//! 4. **Match rule** — exact match or dot-boundaried suffix, never a bare
//!    suffix (the eBPF bug class: allowing `github.com` must not allow
//!    `evilgithub.com`; pinned by `bare_suffix_check_is_the_bug_class`).
//!    First match wins in list order; the verdict is identical whichever
//!    entry matched — only the audit line differs.
//! 5. **Caller contract (host shape)** — a bare UTF-8 hostname: no port,
//!    scheme, brackets or userinfo; callers strip/reject first. #7 passes
//!    rustls-validated SNI; #8 must reject non-UTF-8 httparse bytes
//!    *before* calling (never `from_utf8_lossy` — a lossy conversion could
//!    *create* a match); #9 passes the queried name.
//! 6. **TOCTOU** — `guard()` is a predicate over an address, not a pin.
//!    Callers must guard the exact address they dial: connect to the
//!    guarded address, or re-check `guard()` against the connected socket's
//!    `peer_addr()` before forwarding any bytes (#7's DNS-rebinding
//!    backstop; "Dial by name, never the client-chosen IP").
//! 7. **Fake-IP interplay** — `198.18.0.0/15` is denied here *and*
//!    allocated by #9, deliberately: it makes the fake-IP namespace
//!    unspoofable from outside (a hostile resolver cannot smuggle an answer
//!    into the proxy's own map space). Unknown-fake-IP checks belong to
//!    #9's run map, not `guard()`.
//! 8. **Name/address split** — [`allowed`] is name-based (a policy entry
//!    like `localhost` can match); `guard()` is the address-based backstop.
//!    Always apply both layers: a hostile authoritative server resolving an
//!    allowed name to `127.0.0.1`/`169.254.169.254` is still denied at
//!    dial time.
//! 9. **Denial taxonomy** — `Denied` variants carry pinned `reason()`
//!    strings built in exactly one place; recursed embedded forms (mapped,
//!    NAT64 WKP) report the INNER reason; the Transition ranges (Teredo,
//!    6to4, local-use NAT64) are blanket-denied because their embedded
//!    addresses are obfuscated (Teredo XOR) or explicitly undefined
//!    (RFC 8215 §5), and all three mechanisms are deprecated or local-use.
//! 10. **MSRV rationale + underscore carry-over** — the guard tables are
//!     hand-rolled because std alone is insufficient on Rust 1.85
//!     (`Ipv4Addr::is_shared`/`is_benchmarking` unstable; `is_loopback()`
//!     misses `::ffff:127.0.0.1`; `to_canonical()` unwraps only mapped —
//!     all pinned by meta-tests). Underscore hosts follow policy-time
//!     acceptance (#3 handoff: URL deny-list, not STD3); revisit if
//!     real-world SNIs ever demand it. Perf: linear scan + one small
//!     `String` per call — microseconds at proxy decision rates; no
//!     caching in v1.

use crate::policy::Domain;

/// The allow-list entry that accepted a runtime host.
///
/// Borrows from the allow slice passed to [`allowed`] — zero-copy; the
/// policy outlives every decision (#7/#8/#9 decide-and-log synchronously,
/// so the borrow never crosses an await).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMatch<'a> {
    domain: &'a Domain,
}

impl<'a> RuleMatch<'a> {
    /// The matched policy entry in canonical stored form — the audit
    /// trail's "which rule allowed this" (#10 logs `as_str()`).
    pub fn domain(&self) -> &'a Domain {
        self.domain
    }
}

/// Decide whether a runtime host may be reached, per the allow list.
///
/// Normalizes `host` (exactly one trailing ASCII root dot stripped, then
/// the policy-time pipeline via [`Domain::parse`]) and matches it against
/// `allow` by exact match or dot-boundaried suffix — never a bare suffix.
/// Fail-closed: normalization failure, an empty allow list, and no match
/// all return `None`; this seam carries no diagnostics — callers wanting
/// the rejection reason call [`Domain::parse`] themselves. `host` must be
/// a bare UTF-8 hostname (module docs point 5).
pub fn allowed<'a>(host: &str, allow: &'a [Domain]) -> Option<RuleMatch<'a>> {
    // Strip exactly ONE trailing ASCII root dot (resolvers/SNI may carry
    // it; policy entries never do). "github.com.." leaves "github.com.",
    // which Domain::parse rejects — fail-closed. Fullwidth '。' is NOT
    // stripped: UTS-46 maps it to '.', producing a root dot that
    // normalization rejects — same fail-closed outcome.
    let bare = host.strip_suffix('.').unwrap_or(host);
    // Single normalization pipeline shared with policy time — Domain::parse
    // is the only normalization entry point in the crate, so the runtime
    // and policy acceptance rules can never drift. Any parse error ⇒ None:
    // fail-closed, no diagnostics at this seam.
    let parsed = Domain::parse(bare).ok()?;
    let host = parsed.as_str();
    // Linear scan, first match wins (list order is deterministic; the
    // verdict is identical whichever entry matched — only the audit line
    // differs). Dot-boundaried suffix, never a bare suffix: the char
    // immediately before the matched suffix must be '.'. (No length guard
    // needed: Domain::parse rejects empty labels, so a parsed host can
    // never contain ".." or start with '.', and host == rule is the first
    // arm.)
    allow
        .iter()
        .find(|rule| {
            let rule = rule.as_str();
            host == rule
                || host
                    .strip_suffix(rule)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
        .map(|domain| RuleMatch { domain })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use std::path::Path;

    // ---- fixtures / helpers ------------------------------------------------

    /// Parse a policy-side domain; fixtures must be canonical spellings.
    fn dom(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    /// An allow list built from canonical fixture spellings.
    fn allow(list: &[&str]) -> Vec<Domain> {
        list.iter().map(|s| dom(s)).collect()
    }

    // ---- allowed(): the issue's acceptance criteria -------------------------

    #[test]
    fn acceptance_criteria_table() {
        // Issue #4's acceptance criteria, verbatim: a policy allowing
        // github.com allows github.com and api.github.com, and denies
        // evilgithub.com, github.com.evil.tld and GITHUB.COM.evil.
        // (GITHUB.COM.evil normalizes fine and fails on *matching*, not
        // normalization — this row pins the match rule, not the parser.)
        let entries = allow(&["github.com"]);
        for host in ["github.com", "api.github.com"] {
            let rule =
                allowed(host, &entries).unwrap_or_else(|| panic!("{host:?} must be allowed"));
            assert_eq!(rule.domain().as_str(), "github.com", "{host:?}");
        }
        for host in ["evilgithub.com", "github.com.evil.tld", "GITHUB.COM.evil"] {
            assert!(allowed(host, &entries).is_none(), "{host:?} must be denied");
        }
    }

    // ---- allowed(): normalization -------------------------------------------

    #[test]
    fn case_insensitive_match() {
        let entries = allow(&["github.com"]);
        for host in ["GITHUB.COM", "GiThUb.CoM", "API.GITHUB.COM"] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
    }

    #[test]
    fn single_trailing_root_dot_stripped() {
        // Runtime hosts may carry the root dot a resolver appended; exactly
        // ONE ASCII dot is stripped. The asymmetry with policy time is
        // deliberate: policy *rejects* "example.com." (pinned by
        // domain_parse_rejects_with_pinned_messages), runtime strips one.
        let entries = allow(&["github.com"]);
        for host in ["github.com.", "api.github.com.", "GITHUB.COM."] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
        // "github.com.." keeps one dot after the single strip ⇒ parse
        // rejects; ".github.com" has an empty first label ⇒ parse rejects.
        for host in ["github.com..", ".github.com"] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    #[test]
    fn fullwidth_forms_normalized() {
        // NFKC folds fullwidth letters to ASCII before matching — the same
        // fold any resolver's IDNA layer applies (the trailing dot below is
        // ASCII: the fullwidth '．' spelling is deliberately NOT tested as
        // accepted, since only ASCII dots are stripped).
        let entries = allow(&["github.com"]);
        for host in [
            "ｇｉｔｈｕｂ.ｃｏｍ",
            "ＧＩＴＨＵＢ.ＣＯＭ",
            "ｇｉｔｈｕｂ.ｃｏｍ.",
        ] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
        assert!(allowed("ｅｖｉｌｇｉｔｈｕｂ.ｃｏｍ", &entries).is_none());
    }

    #[test]
    fn homoglyph_dotless_i_is_a_distinct_domain() {
        // DEVIATION from design §3.2 test 5 (recorded in notes): the design
        // assumed UTS-46 maps the dotless 'ı' (U+0131) to ASCII 'i', so
        // "gıthub.com" would fold onto "github.com". It does NOT under the
        // pinned config (AsciiDenyList::URL): U+0131 is disallowed_STD3_
        // valid, so ToASCII punycode-encodes it — "gıthub.com" canonicalizes
        // to "xn--gthub-n4a.com" (verified empirically, and identical to
        // idna::domain_to_ascii / what a resolver would query). The real
        // behavior is the SAFE one: the homoglyph is a *distinct* domain and
        // cannot smuggle into a "github.com" allow entry (fail-closed), yet
        // it does match its own canonical punycode entry.
        assert_eq!(dom("gıthub.com").as_str(), "xn--gthub-n4a.com");
        let legit = allow(&["github.com"]);
        assert!(
            allowed("gıthub.com", &legit).is_none(),
            "a homoglyph must not match the legitimate github.com entry"
        );
        let own = allow(&["xn--gthub-n4a.com"]);
        assert!(
            allowed("gıthub.com", &own).is_some(),
            "the homoglyph matches its own canonical punycode form"
        );
    }

    #[test]
    fn invisible_chars_fold_like_a_resolver() {
        // UTS-46 "ignored" chars (ZWSP U+200B, BOM U+FEFF, WJ U+2060, SHY
        // U+00AD, CGJ U+034F) are stripped — the fold any compliant resolver
        // applies, so matches stay resolver-consistent; folding can never
        // manufacture a dot boundary (evil case below). "deviation" chars
        // (ZWNJ U+200C, ZWJ U+200D) are rejected in Latin context under the
        // pinned config — fail-closed. The stance is non-transitional: ß and
        // final σ punycode rather than fold (strae-oqa, not strasse),
        // matching libidn2/WHATWG defaults. If this test ever fails, the idna
        // crate's mapping-table handling changed — re-audit before adjusting.
        let entries = allow(&["github.com"]);
        for host in [
            "git\u{200b}hub.com",
            "\u{feff}github.com",
            "github\u{2060}.com",
            "git\u{ad}hub.com",
            "git\u{34f}hub.com",
            "github.com\u{200b}",
        ] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
        for host in [
            "evil\u{200b}github.com", // folding cannot create a boundary
            "\u{200b}.github.com",    // empty label after folding
            "git\u{200c}hub.com",     // deviation: rejected, fail-closed
            "git\u{200d}hub.com",
        ] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    #[test]
    fn idn_punycode_equivalence_both_directions() {
        // Policy stores punycode; runtime hosts may arrive as Unicode or as
        // fullwidth punycode — all spellings converge on the stored form.
        let entries = allow(&["xn--r8jz45g.jp"]);
        for host in ["例え.jp", "ＸＮ--Ｒ８ＪＺ４５Ｇ.ＪＰ", "xn--r8jz45g.jp"] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
    }

    // ---- allowed(): rejections (fail-closed) ---------------------------------

    #[test]
    fn ip_literals_and_inet_aton_forms_denied() {
        // Host-libc evidence (Phase 1, this machine): glibc inet_aton
        // accepts EVERY issue-named form — 16843009 → 1.1.1.1,
        // 0x01010101 → 1.1.1.1, 1.1 → 1.0.0.1, 0177.0.0.1 → 127.0.0.1,
        // 0x7f.0.0.1 → 127.0.0.1 — while getaddrinfo's stricter numeric
        // fast path resolves the decimal/octal forms but not hex:
        // acceptance varies by libc AND by entry point within the same
        // libc, and two spellings land on loopback. Wholesale rejection of
        // every inet_aton form is the only libc-independent rule.
        let entries = allow(&["github.com"]);
        for host in [
            // issue-named legacy forms
            "16843009",
            "0x01010101",
            "1.1",
            // strict IP literals
            "1.2.3.4",
            "127.0.0.1",
            "::1",
            // policy-pinned inet_aton spellings
            "123",
            "0001.2.3.4",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            // fullwidth digits NFKC-fold to ASCII before the check
            "１.２.３.４",
            "１６８４３００９",
            // bracketed forms are not bare hosts
            "[::1]",
        ] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    #[test]
    fn wildcards_denied() {
        // ASCII and fullwidth (NFKC-folded) wildcards, both positions.
        let entries = allow(&["github.com"]);
        for host in ["*.github.com", "＊.github.com", "github.*", "*"] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    #[test]
    fn junk_host_shapes_denied() {
        // The caller contract says bare hostnames; junk still fails closed
        // at this seam (defense in depth for the #7/#8/#9 call sites).
        let entries = allow(&["github.com"]);
        let overlong = format!("{}.com", "a".repeat(64));
        for host in [
            "",
            " ",
            "github.com:443",
            "https://github.com/",
            "github.com/x",
            "user@github.com",
            "[github.com]",
            "github .com",
            "-github.com",
            "github-.com",
            overlong.as_str(),
            "ex..com",
            // Ideographic dot U+3002: UTS-46 maps it to '.', producing a
            // root dot that normalization rejects — only ONE ASCII dot is
            // ever stripped, and this one is not ASCII.
            "github.com。",
        ] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    #[test]
    fn empty_allow_list_denies_everything() {
        // The examples/locked-down.json shape: mode "none", allow [].
        let entries: Vec<Domain> = Vec::new();
        for host in ["github.com", "127.0.0.1", ""] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
    }

    // ---- allowed(): match semantics ------------------------------------------

    #[test]
    fn subdomain_depth_unbounded() {
        let entries = allow(&["github.com"]);
        for host in ["a.b.c.github.com", "x.a.b.c.github.com"] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
    }

    #[test]
    fn near_miss_suffixes_denied() {
        let entries = allow(&["github.com"]);
        for host in [
            "xgithub.com",
            "notgithub.com",
            "agithub.com",
            "github.comx",
            "github.com.evil",
            "github.community", // a real TLD: ".community" is not ".com" + boundary
        ] {
            assert!(allowed(host, &entries).is_none(), "{host:?}");
        }
        // No cross-direction suffixing: the entry matches hosts AT or BELOW
        // itself — "github.com" is a prefix of "github.community", not a
        // subdomain of it.
        let community = allow(&["github.community"]);
        assert!(allowed("github.com", &community).is_none());
    }

    #[test]
    fn underscore_hosts_match_underscore_policy() {
        // #3 handoff: policy accepts underscores (URL deny-list, not STD3)
        // and flagged "revisit for SNI-matchability". #4 stays consistent
        // with policy-time acceptance — a host matches iff its
        // normalization matches an entry's; no second grammar. Real TLS
        // clients never send underscore SNIs; the revisit note lives in
        // module-docs point 10.
        let entries = allow(&["ex_ample.com"]);
        for host in ["ex_ample.com", "EX_AMPLE.COM"] {
            assert!(allowed(host, &entries).is_some(), "{host:?}");
        }
    }

    #[test]
    fn policy_examples_reflexive() {
        // Every shipped example's allow entries match themselves
        // (reflexivity), their root-dot form, and any subdomain — through
        // the real policy pipeline, exactly as #7/#8/#9 will consume it.
        // No count pin: shipped_examples_validate (policy.rs) owns that.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
        for entry in std::fs::read_dir(&dir).expect("examples/ must exist") {
            let path = entry.expect("readable dir entry").path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let policy = Policy::from_file(&path).expect("shipped examples must be valid");
                for domain in &policy.network.allow {
                    for host in [
                        domain.as_str().to_owned(),
                        format!("{}.", domain.as_str()),
                        format!("sub.{}", domain.as_str()),
                    ] {
                        assert!(
                            allowed(&host, &policy.network.allow).is_some(),
                            "{}: {host:?} must match its own policy entry",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rule_match_reports_first_matching_entry() {
        // First-match-wins determinism (module-docs point 4): overlapping
        // entries produce the same verdict either way; only the audit line
        // (which rule matched) differs — pinned in both list orders.
        let broad_first = allow(&["github.com", "api.github.com"]);
        assert_eq!(
            allowed("api.github.com", &broad_first)
                .expect("must match")
                .domain()
                .as_str(),
            "github.com"
        );
        let narrow_first = allow(&["api.github.com", "github.com"]);
        assert_eq!(
            allowed("api.github.com", &narrow_first)
                .expect("must match")
                .domain()
                .as_str(),
            "api.github.com"
        );
    }

    // ---- meta ------------------------------------------------------------------

    #[test]
    fn bare_suffix_check_is_the_bug_class() {
        // Meta-test: the exact failure mode of the evaluated eBPF firewall
        // (tracking issue #20, "Key decisions: No eBPF … had a
        // suffix-match bypass") — a BARE ends_with check let
        // evilgithub.com through any github.com allow entry. The
        // dot-boundary rule makes the bug class structurally impossible;
        // this test keeps it that way forever.
        assert!("evilgithub.com".ends_with("github.com"));
        let entries = allow(&["github.com"]);
        assert!(allowed("evilgithub.com", &entries).is_none());
    }
}
