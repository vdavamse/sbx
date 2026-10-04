//! The egress decision core — the two pure predicates every egress
//! decision calls (issue #4).
//!
//! 1. **Ownership** — [`allowed`] decides the name side, [`guard`] the
//!    address side; no I/O, no state, no allocation beyond one
//!    normalization `String` per [`allowed`] call. Consumers: #7 (TLS SNI
//!    match + dial-time address guard), #8 (CONNECT/absolute-form host),
//!    #9 (the fake-IP resolver's queried name); #10 logs [`RuleMatch`] and
//!    [`Denied`].
//! 2. **Fail-closed** — every path that is not an explicit allow denies:
//!    normalization failure ⇒ `None`; empty allow list ⇒ `None`;
//!    [`guard`] denies the full IANA special-purpose registries (fetched
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
//! 6. **TOCTOU** — [`guard`] is a predicate over an address, not a pin.
//!    Callers must guard the exact address they dial: connect to the
//!    guarded address, or re-check [`guard`] against the connected socket's
//!    `peer_addr()` before forwarding any bytes (#7's DNS-rebinding
//!    backstop; "Dial by name, never the client-chosen IP").
//! 7. **Fake-IP interplay** — `198.18.0.0/15` is denied here *and*
//!    allocated by #9, deliberately: it makes the fake-IP namespace
//!    unspoofable from outside (a hostile resolver cannot smuggle an answer
//!    into the proxy's own map space). Unknown-fake-IP checks belong to
//!    #9's run map, not [`guard`].
//! 8. **Name/address split** — [`allowed`] is name-based (a policy entry
//!    like `localhost` can match); [`guard`] is the address-based backstop.
//!    Always apply both layers: a hostile authoritative server resolving an
//!    allowed name to `127.0.0.1`/`169.254.169.254` is still denied at
//!    dial time.
//! 9. **Denial taxonomy** — [`Denied`] variants carry pinned `reason()`
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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Why [`guard`] denied an address — the audit taxonomy (#10 logs
/// `reason()` verbatim; #7/#8 compose "denied dial to {addr}: {denied}").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    Unspecified,        // 0.0.0.0/8 "this network" (incl. 0.0.0.0/32), ::/128
    Loopback,           // 127.0.0.0/8, ::1/128
    PrivateNetwork,     // RFC 1918: 10/8, 172.16/12, 192.168/16
    UniqueLocal,        // fc00::/7 (RFC 4193)
    SharedAddressSpace, // 100.64.0.0/10 CGNAT (RFC 6598)
    LinkLocal,          // 169.254.0.0/16 (incl. 169.254.169.254), fe80::/10
    Multicast,          // 224.0.0.0/4, ff00::/8
    Benchmarking,       // 198.18.0.0/15 (RFC 2544 — #9's fake-IP space), 2001:2::/48
    Documentation,      // TEST-NET-1/2/3, 2001:db8::/32, 3fff::/20
    DiscardOnly,        // 100::/64 (RFC 6666), 100:0:0:1::/64 (RFC 9780 dummy)
    Transition, // Teredo 2001::/32, 6to4 2002::/16, local-use NAT64 64:ff9b:1::/48 — blanket
    Deprecated, // 192.88.99.0/24, ::/96 compatible, fec0::/10, ORCHID 2001:10::/28
    Reserved, // 240/4 (incl. limited broadcast), 192.0.0.0/24, AS112/AMT/DDAS112/SRv6, 2001::/23 umbrella
}

impl Denied {
    /// The pinned reason text — built in exactly one place (repo
    /// convention). The exhaustive match means a new variant without a
    /// pinned message fails to compile.
    pub fn reason(&self) -> &'static str {
        match self {
            Denied::Unspecified => "unspecified or 'this network' address (0.0.0.0/8, ::/128)",
            Denied::Loopback => "loopback address (127.0.0.0/8, ::1/128)",
            Denied::PrivateNetwork => "private-use address (RFC 1918)",
            Denied::UniqueLocal => "unique-local address (RFC 4193)",
            Denied::SharedAddressSpace => "shared address space / CGNAT (RFC 6598)",
            Denied::LinkLocal => "link-local address (incl. cloud metadata 169.254.169.254)",
            Denied::Multicast => "multicast address",
            Denied::Benchmarking => "network-benchmarking range (198.18.0.0/15, 2001:2::/48)",
            Denied::Documentation => {
                "documentation range (TEST-NET-1/2/3, 2001:db8::/32, 3fff::/20)"
            }
            Denied::DiscardOnly => "discard-only or dummy address block (RFC 6666, RFC 9780)",
            Denied::Transition => {
                "address in an IPv6 transition range (Teredo, 6to4, or local-use NAT64)"
            }
            Denied::Deprecated => {
                "deprecated special-purpose address (IPv4-compatible, site-local, ORCHID, or 6to4 relay anycast)"
            }
            Denied::Reserved => "reserved special-purpose address (IANA registry)",
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Denied {}

/// The resolved-address guard: deny every IANA special-purpose range.
///
/// `Ok(())` means the address is in no tabled special-purpose range —
/// dialable per this guard's deny-list contract (module docs point 2);
/// unallocated space also returns `Ok`. `Err(Denied)` carries the pinned
/// reason (#10 logs [`Denied::reason`]; #7/#8 compose "denied dial to
/// {addr}: {denied}" through `Display`). The tables cover the full IANA IPv4/IPv6
/// special-purpose registries (both "Last Updated 2025-10-09") plus
/// multicast and the deprecated-but-delisted ranges. Embedded-IPv4 forms
/// whose layout an RFC *guarantees* (mapped `::ffff:0:0/96`, NAT64 WKP
/// `64:ff9b::/96`) unwrap and recurse, so the denial reports the INNER
/// reason and a public embedded address stays dialable on
/// translation-only hosts; the Transition ranges (Teredo, 6to4, local-use
/// NAT64) are blanket-denied instead (module docs point 9).
///
/// A predicate over an address, not a pin — callers guard the exact
/// address they dial (module docs point 6, TOCTOU).
pub fn guard(addr: IpAddr) -> Result<(), Denied> {
    match addr {
        IpAddr::V4(v4) => {
            let bits = v4.to_bits();
            for row in V4_TABLE {
                // First match wins: the table invariants (descending mask
                // length + equal-length rows disjoint) make the first hit
                // the most specific reason.
                if bits >> (32 - row.mask) == row.prefix >> (32 - row.mask) {
                    return Err(row.denied);
                }
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            let bits = v6.to_bits();
            // Embedded-IPv4 families whose layout is GUARANTEED (mapped
            // RFC 4291; NAT64 WKP RFC 6052 — a /96 prefix fixes the
            // low-32-bit layout): unwrap and recurse so the denial reports
            // the INNER reason and a public embedded address stays
            // dialable on translation-only hosts. Depth ≤ 2: the recursive
            // call is always V4 and the V4 arm never recurses.
            if let Some(inner) = embedded_v4(bits) {
                return guard(IpAddr::V4(inner));
            }
            for row in V6_TABLE {
                if bits >> (128 - row.mask) == row.prefix >> (128 - row.mask) {
                    return Err(row.denied);
                }
            }
            Ok(())
        }
    }
}

// The embedded-IPv4 families with an RFC-guaranteed layout: mapped
// ::ffff:0:0/96 (RFC 4291) and the NAT64 well-known prefix 64:ff9b::/96
// (RFC 6052 — for a /96, the low-32-bit layout is fixed).
// 64:ff9b:1::/48 deliberately does NOT recurse: RFC 8215 §5 forbids nodes
// to assume anything about an embedded address's existence or location —
// it is a blanket Transition row in V6_TABLE instead (design refinement
// R2).
// Watch-item (#14 re-audit): RFC 8215 §4.2's unallocated gap inside
// 64:ff9b::/31 — 64:ff9b::1:0:0 through 64:ff9b:0:ffff:… — returns Ok
// BY DESIGN: it lies outside the /96 WKP (no recursion) and outside
// every table row; guard_v6_boundary_matrix pins it. If IANA ever
// reserves the gap, extend V6_TABLE in the same change.
fn embedded_v4(bits: u128) -> Option<Ipv4Addr> {
    // Top-96-bit keys: ::ffff:0:0/96 ⇒ 0xffff; 64:ff9b::/96 ⇒
    // 0x0064_ff9b followed by 64 zero bits.
    const MAPPED_HI96: u128 = 0xffff;
    const WKP_HI96: u128 = 0x0064_ff9b_0000_0000_0000_0000;
    match bits >> 32 {
        MAPPED_HI96 | WKP_HI96 => Some(Ipv4Addr::from((bits & 0xffff_ffff) as u32)),
        _ => None,
    }
}

// A deny-table row: hit iff bits >> (width - mask) == prefix >>
// (width - mask), where width is 32 (V4) or 128 (V6). Mask lengths are
// ≥ 4 everywhere, so the hit-test shifts can never overflow.
struct V4Row {
    prefix: u32,
    mask: u32,
    denied: Denied,
}

struct V6Row {
    prefix: u128,
    mask: u32,
    denied: Denied,
}

// Const-fn row builders over the std address constructors for readable
// table rows (Ipv4Addr::new/Ipv6Addr::new and both to_bits are const well
// before MSRV 1.85).
const fn v4(prefix: Ipv4Addr, mask: u32, denied: Denied) -> V4Row {
    V4Row {
        prefix: prefix.to_bits(),
        mask,
        denied,
    }
}

const fn v6(prefix: Ipv6Addr, mask: u32, denied: Denied) -> V6Row {
    V6Row {
        prefix: prefix.to_bits(),
        mask,
        denied,
    }
}

// The IPv4 deny table: the full IANA IPv4 special-purpose registry —
// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// "Last Updated 2025-10-09"; transcribed from the live registry at design
// time 2026-10-04 and re-fetched + diffed at implementation time (no
// drift). The multicast block is issue-mandatory but lives in the
// separate multicast registry (RFC 5771) — cited on its row.
//
// Maintenance rule: re-fetch and diff the registry when touching this
// table; `iana_registry_entries_all_denied` is the drift alarm.
//
// Invariants (pinned by `tables_sorted_most_specific_first`): rows sorted
// by DESCENDING mask length; equal-length rows pairwise disjoint ⇒
// first-match-wins always yields the most specific reason.
static V4_TABLE: &[V4Row] = &[
    // IETF Protocol Assignments, RFC 6890 §2.1 — folds the registry's
    // more specific /24 sub-entries (verdict-identical): 192.0.0.0/29
    // IPv4 Service Continuity Prefix (RFC 7335), 192.0.0.8/32 dummy
    // (RFC 7600), 192.0.0.9/32 PCP anycast (RFC 7723), 192.0.0.10/32
    // TURN anycast (RFC 8155), 192.0.0.170–171/32 NAT64/DNS64 discovery
    // (RFC 8880, RFC 7050 §2.2).
    v4(Ipv4Addr::new(192, 0, 0, 0), 24, Denied::Reserved),
    // Documentation (TEST-NET-1), RFC 5737.
    v4(Ipv4Addr::new(192, 0, 2, 0), 24, Denied::Documentation),
    // AS112-v4, RFC 7535. Denied despite the registry's "Globally
    // Reachable: True" — sbx's question is "could an untrusted sandboxed
    // command legitimately dial this", which is no for every
    // special-purpose range (module docs point 2).
    v4(Ipv4Addr::new(192, 31, 196, 0), 24, Denied::Reserved),
    // AMT, RFC 7450 (same rationale as AS112-v4).
    v4(Ipv4Addr::new(192, 52, 193, 0), 24, Denied::Reserved),
    // Deprecated 6to4 relay anycast, RFC 7526 (terminated 2015-03);
    // folds 192.88.99.2/32 6a44-relay anycast (RFC 6751).
    v4(Ipv4Addr::new(192, 88, 99, 0), 24, Denied::Deprecated),
    // Direct Delegation AS112 Service (DDAS112), RFC 7534.
    v4(Ipv4Addr::new(192, 175, 48, 0), 24, Denied::Reserved),
    // Documentation (TEST-NET-2), RFC 5737.
    v4(Ipv4Addr::new(198, 51, 100, 0), 24, Denied::Documentation),
    // Documentation (TEST-NET-3), RFC 5737.
    v4(Ipv4Addr::new(203, 0, 113, 0), 24, Denied::Documentation),
    // Link Local, RFC 3927 — includes the cloud-metadata endpoint
    // 169.254.169.254 the issue names explicitly.
    v4(Ipv4Addr::new(169, 254, 0, 0), 16, Denied::LinkLocal),
    // Private-Use, RFC 1918.
    v4(Ipv4Addr::new(192, 168, 0, 0), 16, Denied::PrivateNetwork),
    // Benchmarking, RFC 2544 — the issue's 198.18.0.0/15; #9 allocates
    // its fake IPs from exactly this range (module docs point 7).
    v4(Ipv4Addr::new(198, 18, 0, 0), 15, Denied::Benchmarking),
    // Private-Use, RFC 1918.
    v4(Ipv4Addr::new(172, 16, 0, 0), 12, Denied::PrivateNetwork),
    // Shared Address Space (CGNAT), RFC 6598.
    v4(Ipv4Addr::new(100, 64, 0, 0), 10, Denied::SharedAddressSpace),
    // "This network", RFC 791 §3.2; folds 0.0.0.0/32 "this host on this
    // network" (RFC 1122 §3.2.1.3). Denied outright rather than trusted
    // to routing: per-kernel behavior of 0/8 varies (mainstream Linux
    // treats it as local; WSL2's NAT routes it via the gateway).
    v4(Ipv4Addr::new(0, 0, 0, 0), 8, Denied::Unspecified),
    // Private-Use, RFC 1918.
    v4(Ipv4Addr::new(10, 0, 0, 0), 8, Denied::PrivateNetwork),
    // Loopback, RFC 1122 §3.2.1.3.
    v4(Ipv4Addr::new(127, 0, 0, 0), 8, Denied::Loopback),
    // Multicast, RFC 5771 (multicast registry, not special-purpose —
    // issue-mandatory).
    v4(Ipv4Addr::new(224, 0, 0, 0), 4, Denied::Multicast),
    // Reserved for future use, RFC 1112 §4; folds 255.255.255.255/32
    // limited broadcast (RFC 8190, RFC 919 §7).
    v4(Ipv4Addr::new(240, 0, 0, 0), 4, Denied::Reserved),
];

// The IPv6 deny table — same registry rules as V4_TABLE:
// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
// "Last Updated 2025-10-09"; transcribed 2026-10-04 (design) and
// re-fetched + diffed at implementation time (no drift). Maintenance
// rule: re-fetch and diff when touching; the reconciliation test is the
// drift alarm. The mapped (::ffff:0:0/96) and NAT64-WKP (64:ff9b::/96)
// registry entries are NOT rows — embedded_v4() unwraps them before the
// table is consulted, so their denials report the inner reason.
// Multicast ff00::/8 is issue-mandatory (RFC 4291, multicast registry);
// ::/96 (IPv4-compatible) and fec0::/10 (site-local) are DELISTED from
// the registry (deprecated by RFC 4291 / RFC 3879) but kept fail-closed.
// Same sort + disjointness invariants as V4_TABLE.
static V6_TABLE: &[V6Row] = &[
    // Loopback Address, RFC 4291. MUST precede the ::/96 blanket row
    // (::1 ⊂ ::/96) — the sort invariant is what makes ::1 report
    // Loopback, not Deprecated.
    v6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128, Denied::Loopback),
    // Unspecified Address, RFC 4291. Precedes ::/96 for the same reason.
    v6(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        128,
        Denied::Unspecified,
    ),
    // IPv4-compatible ::/96, RFC 4291 (deprecated; delisted from the
    // registry — kept fail-closed). Blanket, NO recursion: ::127.0.0.1
    // reports Deprecated, not Loopback (pinned by
    // deprecated_ranges_denied_with_table_precedence).
    v6(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        96,
        Denied::Deprecated,
    ),
    // Discard-Only Address Block, RFC 6666.
    v6(
        Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0),
        64,
        Denied::DiscardOnly,
    ),
    // Dummy IPv6 Prefix, RFC 9780 (allocated 2025-04). Disjoint from
    // 100::/64 (fourth group 1 vs 0).
    v6(
        Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 0),
        64,
        Denied::DiscardOnly,
    ),
    // Benchmarking, RFC 5180 (+ Errata 1752). More specific than the
    // 2001::/23 umbrella below.
    v6(
        Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0),
        48,
        Denied::Benchmarking,
    ),
    // Direct Delegation AS112 Service (DDAS112-v6), RFC 7534.
    v6(
        Ipv6Addr::new(0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0),
        48,
        Denied::Reserved,
    ),
    // Local-use NAT64, RFC 8215 — BLANKET-deny, no recursion (design
    // refinement R2): RFC 8215 §5 forbids nodes to "make any assumptions
    // regarding the syntax or properties of those addresses (e.g., the
    // existence and location of embedded IPv4 addresses)" — recursing on
    // the low 32 bits would assume exactly that. Local-use prefix, so
    // blanket denial costs nothing realistic.
    v6(
        Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0),
        48,
        Denied::Transition,
    ),
    // TEREDO, RFC 4380 / RFC 8190 — BLANKET-deny: the client IPv4 is
    // XOR-obfuscated with the server IPv4 in octets 12..16, so extraction
    // is subtle and a hostile resolver could smuggle a "public" payload;
    // the mechanism is deprecated. More specific than the /23 umbrella.
    v6(
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        32,
        Denied::Transition,
    ),
    // Documentation, RFC 3849. Outside 2001::/23 (bits 17–23 of 0x0db8
    // are 0000110, not the umbrella's 0000000).
    v6(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        32,
        Denied::Documentation,
    ),
    // Deprecated ORCHID, RFC 4843 (terminated 2014-03). More specific
    // than the /23 umbrella.
    v6(
        Ipv6Addr::new(0x2001, 0x10, 0, 0, 0, 0, 0, 0),
        28,
        Denied::Deprecated,
    ),
    // IETF Protocol Assignments umbrella, RFC 2928. Folds every registry
    // sub-allocation without a sharper audit reason of its own:
    // 2001:1::1/2/3 anycasts (RFC 7723/8155/9665), 2001:3::/32 AMT
    // (RFC 7450), 2001:4:112::/48 AS112-v6 (RFC 7535), 2001:20::/28
    // ORCHIDv2 (RFC 7343), 2001:30::/28 Drone DETs (RFC 9374) — and any
    // future sub-allocation. The more specific rows above refine the
    // reason first.
    v6(
        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        23,
        Denied::Reserved,
    ),
    // Documentation, RFC 9637 (2024): 3fff:0000:: – 3fff:0fff:… (the
    // prefix's own bits define the /20 mask).
    v6(
        Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        20,
        Denied::Documentation,
    ),
    // 6to4, RFC 3056 — BLANKET-deny (design refinement R1): deprecated
    // (RFC 7526 terminated the relay anycast; RFC 6343 advises against
    // 6to4); recursing would let a hostile resolver smuggle a "public"
    // embedded payload into a tunnel format with unclear modern routing.
    // 2002:808:808:: (embedded 8.8.8.8) stays denied — pinned.
    v6(
        Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0),
        16,
        Denied::Transition,
    ),
    // Segment Routing (SRv6) SIDs, RFC 9602 (2024).
    v6(
        Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0),
        16,
        Denied::Reserved,
    ),
    // Link-Local Unicast, RFC 4291: fe80:: – febf:…
    v6(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
        Denied::LinkLocal,
    ),
    // Site-local, RFC 3879 (deprecated; delisted from the registry — kept
    // fail-closed): fec0:: – feff:… Adjacent to fe80::/10, disjoint
    // (bits 9–10 differ).
    v6(
        Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
        10,
        Denied::Deprecated,
    ),
    // Multicast, RFC 4291 (multicast registry — issue-mandatory).
    v6(
        Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        8,
        Denied::Multicast,
    ),
    // Unique-Local, RFC 4193 / RFC 8190: fc00:: – fdff:… Disjoint from
    // the three rows above.
    v6(
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        7,
        Denied::UniqueLocal,
    ),
];

#[cfg(test)]
mod tests {
    // Deep property runs: PROPTEST_CASES=10000 cargo test --locked egress
    // (the default — and CI — runs 256 cases per property).
    use super::*;
    use crate::policy::Policy;
    use proptest::prelude::*;
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

    /// Parse an address fixture (must succeed).
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|err| panic!("{s:?}: {err}"))
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

    // ---- guard(): the issue's families --------------------------------------

    #[test]
    fn guard_denies_issue_families_with_exact_variants() {
        // One named representative per issue-mandated family, asserting the
        // exact variant — the #10 audit taxonomy, pinned.
        let cases = [
            ("127.0.0.1", Denied::Loopback),
            ("::1", Denied::Loopback),
            ("10.1.2.3", Denied::PrivateNetwork),
            ("172.16.0.1", Denied::PrivateNetwork),
            ("192.168.1.1", Denied::PrivateNetwork),
            ("100.64.0.1", Denied::SharedAddressSpace),
            ("169.254.1.1", Denied::LinkLocal),
            // The cloud-metadata endpoint the issue names explicitly.
            ("169.254.169.254", Denied::LinkLocal),
            ("fe80::1", Denied::LinkLocal),
            ("fc00::1", Denied::UniqueLocal),
            ("fd12::3456", Denied::UniqueLocal),
            ("224.0.0.1", Denied::Multicast),
            ("239.255.255.250", Denied::Multicast),
            ("ff02::1", Denied::Multicast),
            ("0.0.0.0", Denied::Unspecified),
            ("::", Denied::Unspecified),
            ("198.18.0.1", Denied::Benchmarking),
            ("198.19.255.255", Denied::Benchmarking),
        ];
        for (addr, expected) in cases {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
    }

    // ---- guard(): boundary matrices ------------------------------------------

    #[test]
    fn guard_v4_boundary_matrix() {
        // Per denied range: network address, network+1, last address — and
        // the tight ±1-outside controls that bound every table edge.
        let deny = [
            ("0.0.0.0", Denied::Unspecified),
            ("0.0.0.1", Denied::Unspecified),
            ("0.255.255.255", Denied::Unspecified),
            ("10.0.0.0", Denied::PrivateNetwork),
            ("10.255.255.255", Denied::PrivateNetwork),
            ("127.0.0.0", Denied::Loopback),
            ("127.255.255.255", Denied::Loopback),
            ("100.64.0.0", Denied::SharedAddressSpace),
            ("100.127.255.255", Denied::SharedAddressSpace),
            ("169.254.0.0", Denied::LinkLocal),
            ("169.254.169.254", Denied::LinkLocal),
            ("169.254.255.255", Denied::LinkLocal),
            ("172.16.0.0", Denied::PrivateNetwork),
            ("172.31.255.255", Denied::PrivateNetwork),
            ("192.0.0.0", Denied::Reserved),
            ("192.0.0.8", Denied::Reserved),
            ("192.0.0.9", Denied::Reserved),
            ("192.0.0.10", Denied::Reserved),
            ("192.0.0.170", Denied::Reserved),
            ("192.0.0.171", Denied::Reserved),
            ("192.0.0.255", Denied::Reserved),
            ("192.0.2.0", Denied::Documentation),
            ("192.0.2.255", Denied::Documentation),
            ("192.31.196.0", Denied::Reserved),
            ("192.31.196.255", Denied::Reserved),
            ("192.52.193.0", Denied::Reserved),
            ("192.52.193.255", Denied::Reserved),
            ("192.88.99.0", Denied::Deprecated),
            ("192.88.99.1", Denied::Deprecated),
            ("192.88.99.2", Denied::Deprecated),
            ("192.88.99.255", Denied::Deprecated),
            ("192.168.0.0", Denied::PrivateNetwork),
            ("192.168.255.255", Denied::PrivateNetwork),
            ("192.175.48.0", Denied::Reserved),
            ("192.175.48.255", Denied::Reserved),
            ("198.18.0.0", Denied::Benchmarking),
            ("198.18.0.1", Denied::Benchmarking),
            ("198.19.255.254", Denied::Benchmarking),
            ("198.19.255.255", Denied::Benchmarking),
            ("198.51.100.0", Denied::Documentation),
            ("198.51.100.1", Denied::Documentation),
            ("198.51.100.255", Denied::Documentation),
            ("203.0.113.0", Denied::Documentation),
            ("203.0.113.1", Denied::Documentation),
            ("203.0.113.255", Denied::Documentation),
            ("224.0.0.0", Denied::Multicast),
            ("224.0.0.1", Denied::Multicast),
            ("239.255.255.255", Denied::Multicast),
            ("240.0.0.0", Denied::Reserved),
            ("240.0.0.1", Denied::Reserved),
            ("255.255.255.254", Denied::Reserved),
            ("255.255.255.255", Denied::Reserved),
        ];
        for (addr, expected) in deny {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
        // Tight allow controls: one address either side of every denied
        // range, plus ordinary public space.
        let allow_addrs = [
            "1.0.0.0",
            "1.1.1.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.255.255.255", // last before 10/8
            "11.0.0.0",      // first after 10/8
            "93.184.216.34",
            "100.63.255.255", // last before CGNAT
            "100.128.0.0",    // first after CGNAT
            "126.255.255.255",
            "128.0.0.0",
            "140.82.112.3",
            "169.253.255.255", // last before link-local
            "169.255.0.0",     // first after link-local
            "172.15.255.255",  // last before 172.16/12
            "172.32.0.0",      // first after 172.16/12
            "192.0.1.0",
            "192.0.1.255",
            "192.0.3.0",
            "192.31.195.255",
            "192.31.197.0",
            "192.52.192.255",
            "192.52.194.0",
            "192.88.98.255",
            "192.88.100.0",
            "192.169.0.0", // first after 192.168/16
            "192.175.47.255",
            "192.175.49.0",
            "198.17.255.255", // last before 198.18/15
            "198.20.0.0",     // first after 198.18/15
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "208.67.222.222",
            "223.255.255.255", // last before 224/4
        ];
        for addr in allow_addrs {
            assert_eq!(guard(ip(addr)), Ok(()), "{addr}");
        }
    }

    #[test]
    fn guard_v6_boundary_matrix() {
        // Per denied range: network address, network+1, last address —
        // including the precedence pins (::1 → Loopback NOT Deprecated;
        // ::7f00:1 → Deprecated NOT Loopback, since ::/96 is a blanket row
        // with no recursion) and the CIDR-math pins (3fff::/20, 2001::/23).
        let deny = [
            ("::", Denied::Unspecified),
            ("::1", Denied::Loopback),
            ("::2", Denied::Deprecated), // compat blanket starts past ::1
            ("::7f00:1", Denied::Deprecated),
            ("::ffff:0:0", Denied::Unspecified), // mapped → 0.0.0.0
            ("100::", Denied::DiscardOnly),
            ("100::1", Denied::DiscardOnly),
            ("100:0:0:1::", Denied::DiscardOnly),
            ("100:0:0:1::1", Denied::DiscardOnly),
            ("2001::", Denied::Transition),
            ("2001::1", Denied::Transition),
            ("2001:1::1", Denied::Reserved), // umbrella (anycasts folded)
            ("2001:2::", Denied::Benchmarking),
            ("2001:2::1", Denied::Benchmarking),
            ("2001:3::1", Denied::Reserved),     // AMT, umbrella
            ("2001:4:112::1", Denied::Reserved), // AS112-v6, umbrella
            ("2001:10::", Denied::Deprecated),
            ("2001:10::1", Denied::Deprecated),
            ("2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", Denied::Deprecated), // ORCHID last
            ("2001:20::1", Denied::Reserved),                              // ORCHIDv2, umbrella
            ("2001:30::1", Denied::Reserved),                              // Drone DETs, umbrella
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", Denied::Reserved),  // /23 last
            ("2001:db8::", Denied::Documentation),
            ("2001:db8::1", Denied::Documentation),
            ("2002::", Denied::Transition),
            ("2002:7f00:1::", Denied::Transition),
            (
                "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                Denied::Transition,
            ), // 6to4 last
            ("2620:4f:8000::", Denied::Reserved),
            ("2620:4f:8000::1", Denied::Reserved),
            // DDAS112-v6 last address
            ("2620:4f:8000:ffff:ffff:ffff:ffff:ffff", Denied::Reserved),
            ("3fff::", Denied::Documentation),
            ("3fff::1", Denied::Documentation),
            (
                "3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff",
                Denied::Documentation,
            ), // /20 last
            ("5f00::", Denied::Reserved),
            ("5f00::1", Denied::Reserved),
            ("5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Denied::Reserved), // /16 last
            ("fc00::", Denied::UniqueLocal),
            ("fd12::3456", Denied::UniqueLocal),
            (
                "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                Denied::UniqueLocal,
            ), // /7 last
            ("fe80::", Denied::LinkLocal),
            ("fe80::1", Denied::LinkLocal),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Denied::LinkLocal), // /10 last
            ("fec0::", Denied::Deprecated),
            ("fec0::1", Denied::Deprecated),
            (
                "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                Denied::Deprecated,
            ), // site-local last
            ("ff00::", Denied::Multicast),
            ("ff02::1", Denied::Multicast),
            ("ff0e::1", Denied::Multicast),
        ];
        for (addr, expected) in deny {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
        let allow_addrs = [
            "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // ULA lower edge
            "fe00::1",                                 // unassigned gap
            "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // LL lower edge
            "2001:200::",                              // first after /23
            "2001:db7::1",
            "2001:4860:4860::8888",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2620:4f:7fff:ffff:ffff:ffff:ffff:ffff", // last before DDAS112-v6
            "2620:4f:8001::",                        // first after DDAS112-v6
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // last before 3fff::/20
            "3fff:1000::",                           // first after /20 — pins the CIDR math
            "4000::",
            "5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", // last before 5f00::/16
            "5f01::",                                  // first after /16
            "2003::1",
            "64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", // last before the WKP /96
            "64:ff9b::1:0:0", // RFC 8215 §4.2's unallocated gap — outside the WKP /96
            "64:ff9c::",      // first after the WKP /96 block
            "100:0:0:2::",    // first past the dummy /64
        ];
        for addr in allow_addrs {
            assert_eq!(guard(ip(addr)), Ok(()), "{addr}");
        }
    }

    // ---- guard(): registry reconciliation -------------------------------------

    #[test]
    fn iana_registry_entries_all_denied() {
        // Reconciliation against the source registries — the drift alarm:
        //
        //   https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
        //   https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
        //
        // Both "Last Updated 2025-10-09"; fetched at design time
        // 2026-10-04 and re-fetched at implementation time (identical —
        // no drift). One representative address per registry entry,
        // INCLUDING every entry folded into a wider table row, plus the
        // multicast blocks (separate registries, issue-mandatory) and the
        // two deprecated-but-delisted ranges kept fail-closed (::/96
        // compatible, fec0::/10 site-local). Maintenance rule: re-fetch
        // and diff the registries when touching the tables; if IANA adds
        // an entry, this test gains a representative in the same change.
        for addr in [
            // ---- IPv4 registry ----
            "0.0.0.0", //   /32 "this host" (RFC 1122), folded into 0.0.0.0/8
            "0.0.0.1", //   0.0.0.0/8 "this network" (RFC 791 §3.2)
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",   //   IETF Protocol Assignments (RFC 6890) + /29 (RFC 7335)
            "192.0.0.8",   //   IPv4 dummy address (RFC 7600)
            "192.0.0.9",   //   PCP anycast (RFC 7723)
            "192.0.0.10",  //  TURN anycast (RFC 8155)
            "192.0.0.170", // NAT64/DNS64 discovery (RFC 8880)
            "192.0.0.171", // … (RFC 7050 §2.2)
            "192.0.2.1",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.88.99.2", // 6a44-relay anycast (RFC 6751)
            "192.168.0.1",
            "192.175.48.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "255.255.255.255", // limited broadcast (RFC 8190/919)
            "224.0.0.1",       //       multicast registry (RFC 5771)
            // ---- IPv6 registry ----
            "::1",
            "::",
            "::ffff:0:1",   // mapped (RFC 4291) — recurses onto 0.0.0.1
            "64:ff9b::1",   // NAT64 WKP (RFC 6052) — recurses onto 0.0.0.1
            "64:ff9b:1::1", // local-use NAT64 (RFC 8215) — blanket
            "100::1",
            "100:0:0:1::1",
            "2001::1",   // TEREDO (RFC 4380) — blanket
            "2001:1::1", // PCP anycast (RFC 7723), under the /23 umbrella
            "2001:1::2", // TURN anycast (RFC 8155)
            "2001:1::3", // DNS-SD SRP anycast (RFC 9665)
            "2001:2::1",
            "2001:3::1",     // AMT (RFC 7450)
            "2001:4:112::1", // AS112-v6 (RFC 7535)
            "2001:10::1",    // deprecated ORCHID (RFC 4843)
            "2001:20::1",    // ORCHIDv2 (RFC 7343)
            "2001:30::1",    // Drone DETs (RFC 9374)
            "2001:db8::1",
            "2002::1", //         6to4 (RFC 3056) — blanket
            "2620:4f:8000::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fe80::1",
            "ff00::1", // multicast registry (RFC 4291)
            // ---- delisted from the registry, kept fail-closed ----
            "::7f00:1", // IPv4-compatible ::/96 (RFC 4291, deprecated)
            "fec0::1",  // site-local (RFC 3879, deprecated)
        ] {
            assert!(guard(ip(addr)).is_err(), "{addr} must be denied");
        }
    }

    // ---- guard(): embedded IPv4 forms ------------------------------------------

    #[test]
    fn mapped_v4_recursion_reports_inner_reason() {
        // ::ffff:0:0/96 (RFC 4291): unwrap-and-recurse — the denial
        // reports the INNER address's reason (audit-accurate), and public
        // embedded addresses stay dialable on translation-only hosts.
        let cases = [
            ("::ffff:127.0.0.1", Denied::Loopback),
            ("::ffff:10.0.0.1", Denied::PrivateNetwork),
            ("::ffff:169.254.169.254", Denied::LinkLocal),
            ("::ffff:198.18.0.1", Denied::Benchmarking),
            ("::ffff:224.0.0.1", Denied::Multicast),
            ("::ffff:ffff:ffff", Denied::Reserved), // 255.255.255.255
        ];
        for (addr, expected) in cases {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
        for addr in ["::ffff:8.8.8.8", "::ffff:93.184.216.34"] {
            assert_eq!(guard(ip(addr)), Ok(()), "{addr}");
        }
    }

    #[test]
    fn nat64_wkp_recursion_reports_inner_reason() {
        // 64:ff9b::/96 (RFC 6052 WKP): for a /96 prefix the RFC
        // GUARANTEES the low-32-bit embedded-IPv4 layout, so recursion is
        // sound here — and keeps NAT64-only hosts working.
        let cases = [
            ("64:ff9b::7f00:1", Denied::Loopback),      // 127.0.0.1
            ("64:ff9b::a00:1", Denied::PrivateNetwork), // 10.0.0.1
            ("64:ff9b::a9fe:a9fe", Denied::LinkLocal),  // 169.254.169.254
            ("64:ff9b::c612:1", Denied::Benchmarking),  // 198.18.0.1
        ];
        for (addr, expected) in cases {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
        for addr in ["64:ff9b::808:808", "64:ff9b::5db8:d822"] {
            // 8.8.8.8 and 93.184.216.34 — public embedded addresses stay
            // dialable.
            assert_eq!(guard(ip(addr)), Ok(()), "{addr}");
        }
    }

    #[test]
    fn transition_ranges_blanket_denied() {
        // The blanket decisions (design refinements R1/R2), pinned so any
        // reversal is a deliberate, reviewable act:
        // - Teredo 2001::/32: the client IPv4 is XOR-obfuscated with the
        //   server IPv4 in octets 12..16 — extraction is subtle and
        //   smuggleable; RFC 4380 is deprecated.
        // - 6to4 2002::/16 (R1): deprecated (RFC 7526/6343); recursing
        //   would let a hostile resolver smuggle a "public" payload into a
        //   tunnel format with unclear modern routing.
        // - Local-use NAT64 64:ff9b:1::/48 (R2): RFC 8215 §5 forbids
        //   assuming ANY embedded-IPv4 location, so the low bits are never
        //   treated as an address.
        for addr in [
            // Teredo — including a "public" payload
            "2001::1",
            "2001:0:0:0:0:0:808:808",
            // 6to4 — 2002:808:808:: embeds 8.8.8.8 and is STILL denied (R1)
            "2002::",
            "2002:7f00:1::",
            "2002:808:808::",
            // local-use NAT64 — 64:ff9b:1::808:808 embeds 8.8.8.8, STILL
            // denied (R2); nonzero middle bits change nothing
            "64:ff9b:1::1",
            "64:ff9b:1::808:808",
            "64:ff9b:1:1234::7f00:1",
        ] {
            assert_eq!(guard(ip(addr)), Err(Denied::Transition), "{addr}");
        }
    }

    #[test]
    fn deprecated_ranges_denied_with_table_precedence() {
        // Precedence pins: the /128 rows precede the ::/96 blanket, so ::1
        // reports Loopback and :: reports Unspecified — NOT Deprecated;
        // the ::/96 blanket itself does NOT recurse, so ::127.0.0.1
        // reports Deprecated, not Loopback.
        let cases = [
            ("::1", Denied::Loopback),
            ("::", Denied::Unspecified),
            ("::2", Denied::Deprecated),
            ("::7f00:1", Denied::Deprecated), // ::127.0.0.1 — blanket, no recursion
            ("fec0::1", Denied::Deprecated),
            ("feff::1", Denied::Deprecated),
            ("192.88.99.1", Denied::Deprecated),
            ("2001:10::1", Denied::Deprecated), // ORCHID refines the /23 umbrella
        ];
        for (addr, expected) in cases {
            assert_eq!(guard(ip(addr)), Err(expected), "{addr}");
        }
    }

    // ---- guard(): public space ---------------------------------------------------

    #[test]
    fn public_controls_allowed() {
        // Ordinary globally-routed space stays dialable — the guard is a
        // deny-list, and these controls bound the whole design (issue #7
        // dials by name; these are the kinds of addresses it must reach).
        for addr in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "140.82.112.3",
            "208.67.222.222",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",   // mapped public — recursion keeps it dialable
            "64:ff9b::808:808", // NAT64 WKP → 8.8.8.8
        ] {
            assert_eq!(guard(ip(addr)), Ok(()), "{addr}");
        }
    }

    // ---- guard(): taxonomy + table invariants -------------------------------------

    #[test]
    fn denied_reasons_pinned() {
        // Compile-time witness: Denied is a std Error (callers can Box it;
        // #7/#8 compose denial logs through Display).
        fn assert_error<T: std::error::Error>() {}
        assert_error::<Denied>();

        // All 13 variants' pinned reason() strings — exhaustive. The
        // exhaustive match in reason() means a new variant without a
        // pinned message fails to COMPILE; this table means a changed
        // message fails the test.
        let cases = [
            (
                Denied::Unspecified,
                "unspecified or 'this network' address (0.0.0.0/8, ::/128)",
            ),
            (Denied::Loopback, "loopback address (127.0.0.0/8, ::1/128)"),
            (Denied::PrivateNetwork, "private-use address (RFC 1918)"),
            (Denied::UniqueLocal, "unique-local address (RFC 4193)"),
            (
                Denied::SharedAddressSpace,
                "shared address space / CGNAT (RFC 6598)",
            ),
            (
                Denied::LinkLocal,
                "link-local address (incl. cloud metadata 169.254.169.254)",
            ),
            (Denied::Multicast, "multicast address"),
            (
                Denied::Benchmarking,
                "network-benchmarking range (198.18.0.0/15, 2001:2::/48)",
            ),
            (
                Denied::Documentation,
                "documentation range (TEST-NET-1/2/3, 2001:db8::/32, 3fff::/20)",
            ),
            (
                Denied::DiscardOnly,
                "discard-only or dummy address block (RFC 6666, RFC 9780)",
            ),
            (
                Denied::Transition,
                "address in an IPv6 transition range (Teredo, 6to4, or local-use NAT64)",
            ),
            (
                Denied::Deprecated,
                "deprecated special-purpose address (IPv4-compatible, site-local, ORCHID, or 6to4 relay anycast)",
            ),
            (
                Denied::Reserved,
                "reserved special-purpose address (IANA registry)",
            ),
        ];
        assert_eq!(cases.len(), 13, "Denied has exactly 13 variants");
        for (variant, expected) in cases {
            assert_eq!(variant.reason(), expected, "{variant:?}");
            assert_eq!(
                variant.to_string(),
                expected,
                "{variant:?}: Display must equal reason()"
            );
        }
    }

    #[test]
    fn tables_sorted_most_specific_first() {
        // The invariant first-match-wins correctness rests on: rows sorted
        // by DESCENDING mask length, and equal-length rows pairwise
        // disjoint (equal-length prefixes overlap iff their masked values
        // are identical). This is what makes ::1 report Loopback (not the
        // ::/96 blanket Deprecated) and 2001::1 report Transition (not the
        // 2001::/23 umbrella Reserved).
        let v4: Vec<(u128, u32)> = V4_TABLE
            .iter()
            .map(|row| (u128::from(row.prefix), row.mask))
            .collect();
        let v6: Vec<(u128, u32)> = V6_TABLE.iter().map(|row| (row.prefix, row.mask)).collect();
        for (family, rows, width) in [("V4", &v4, 32u32), ("V6", &v6, 128u32)] {
            for (i, &(prefix, mask)) in rows.iter().enumerate() {
                assert!(
                    mask > 0 && mask <= width,
                    "{family} row {i}: bad mask {mask}"
                );
                if i > 0 {
                    let prev = rows[i - 1].1;
                    assert!(
                        mask <= prev,
                        "{family} row {i} (/{mask}) follows a shorter mask (/{prev}) — rows must be sorted by descending mask length"
                    );
                }
                for &(other, other_mask) in rows.iter().take(i) {
                    if other_mask == mask {
                        assert_ne!(
                            prefix >> (width - mask),
                            other >> (width - mask),
                            "{family}: two /{mask} rows overlap ({prefix:#x} vs {other:#x})"
                        );
                    }
                }
            }
        }
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

    #[test]
    fn std_is_loopback_misses_ipv4_mapped() {
        // Meta-test: std's IpAddr::is_loopback() is FALSE for the mapped
        // form ::ffff:127.0.0.1 (verified on rustc 1.85.0 and current
        // stable) — a guard leaning on std alone would wave a
        // DNS-rebinding answer of ::ffff:127.0.0.1 straight through to a
        // host-side dial. The hand-rolled mapped-unwrap recursion denies
        // it. If this assertion ever fails, std fixed the gap — the
        // hand-rolled table stays correct regardless; update this test's
        // comment in the same change.
        let mapped = IpAddr::from([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
        assert!(!mapped.is_loopback());
        assert_eq!(guard(mapped), Err(Denied::Loopback));
    }

    #[test]
    fn to_canonical_only_unwraps_mapped() {
        // Meta-test: to_canonical() unwraps ONLY the mapped ::ffff:0:0/96
        // — the compatible form ::127.0.0.1, 6to4 2002:7f00:1:: and NAT64
        // 64:ff9b::7f00:1 all stay V6 (verified). A guard built on
        // to_canonical() alone would miss every other embedded family,
        // which is why the table handles each family explicitly. If this
        // ever fails, std changed — the table remains correct regardless;
        // update the test in the same change.
        assert_eq!(
            ip("::ffff:7f00:1").to_canonical(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        for addr in ["::7f00:1", "2002:7f00:1::", "64:ff9b::7f00:1"] {
            assert!(
                matches!(ip(addr).to_canonical(), IpAddr::V6(_)),
                "{addr}: to_canonical() must leave this form untouched"
            );
        }
    }

    // ---- property tests (proptest) ------------------------------------------
    //
    // Oracle soundness: the generators emit only SELF-CANONICAL
    // lowercase-ASCII names — asserted inside every property, so generator
    // drift fails loudly instead of silently vacuating the oracle. Given
    // canonicity, the raw-string `in_set_oracle` (concat + ends_with — a
    // different data path from the implementation's normalize-then-
    // strip_suffix rule, sharing no code with it) is an independent judge.
    // The guard oracles use inclusive-interval membership transcribed from
    // the RFC endpoints — interval arithmetic vs the implementation's
    // prefix/shift arithmetic: two representations cross-checking.

    // label: [a-z][a-z0-9]{0,9} — never hyphenated, never starts with a
    // digit (⇒ never all-numeric, never a "0x" hex form), ≤10 chars.
    fn prop_label() -> impl Strategy<Value = String> {
        (
            proptest::char::range('a', 'z'),
            proptest::collection::vec(prop_lower_alnum_char(), 0..=9),
        )
            .prop_map(|(first, rest)| std::iter::once(first).chain(rest).collect())
    }

    // [a-z0-9] via core strategies only (proptest 1.11 has no char_in;
    // char::range's `ranges` fully define the output set — the default
    // special/preferred biases never escape them, and shrinking never
    // crosses them, so self-canonicity holds for shrunk values too).
    fn prop_lower_alnum_char() -> impl Strategy<Value = char> {
        prop_oneof![
            proptest::char::range('a', 'z'),
            proptest::char::range('0', '9'),
        ]
    }

    // tld: [a-z]{2,6} — alphabetic ⇒ never inet_aton-form, never an
    // all-numeric TLD.
    fn prop_tld() -> impl Strategy<Value = String> {
        proptest::collection::vec(proptest::char::range('a', 'z'), 2..=6)
            .prop_map(|chars| chars.into_iter().collect())
    }

    // domain: 2–3 labels ending in the tld (allow-entry shape).
    fn prop_domain() -> impl Strategy<Value = String> {
        (proptest::collection::vec(prop_label(), 1..=2), prop_tld()).prop_map(
            |(mut labels, tld)| {
                labels.push(tld);
                labels.join(".")
            },
        )
    }

    // host: 1–5 labels ending in the tld (runtime-host shape).
    fn prop_host() -> impl Strategy<Value = String> {
        (proptest::collection::vec(prop_label(), 0..=4), prop_tld()).prop_map(
            |(mut labels, tld)| {
                labels.push(tld);
                labels.join(".")
            },
        )
    }

    // The raw-string oracle: `∃d ∈ allow: h == d || h.ends_with("." + d)`
    // — the issue's own rule, implemented independently of the matcher.
    // Sound over self-canonical inputs (asserted in every property).
    fn in_set_oracle(host: &str, allow: &[String]) -> bool {
        allow
            .iter()
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    }

    // The v4 guard oracle: INCLUSIVE intervals transcribed from the RFC
    // endpoints of the V4_TABLE rows. Pairwise disjoint, so scan order is
    // irrelevant for the verdict — unlike the implementation, which relies
    // on its sort invariant.
    const V4_INTERVALS: &[(u32, u32, Denied)] = &[
        (0x0000_0000, 0x00ff_ffff, Denied::Unspecified), // 0.0.0.0/8
        (0x0a00_0000, 0x0aff_ffff, Denied::PrivateNetwork), // 10.0.0.0/8
        (0x6440_0000, 0x647f_ffff, Denied::SharedAddressSpace), // 100.64.0.0/10
        (0x7f00_0000, 0x7fff_ffff, Denied::Loopback),    // 127.0.0.0/8
        (0xa9fe_0000, 0xa9fe_ffff, Denied::LinkLocal),   // 169.254.0.0/16
        (0xac10_0000, 0xac1f_ffff, Denied::PrivateNetwork), // 172.16.0.0/12
        (0xc000_0000, 0xc000_00ff, Denied::Reserved),    // 192.0.0.0/24
        (0xc000_0200, 0xc000_02ff, Denied::Documentation), // 192.0.2.0/24
        (0xc01f_c400, 0xc01f_c4ff, Denied::Reserved),    // 192.31.196.0/24
        (0xc034_c100, 0xc034_c1ff, Denied::Reserved),    // 192.52.193.0/24
        (0xc058_6300, 0xc058_63ff, Denied::Deprecated),  // 192.88.99.0/24
        (0xc0a8_0000, 0xc0a8_ffff, Denied::PrivateNetwork), // 192.168.0.0/16
        (0xc0af_3000, 0xc0af_30ff, Denied::Reserved),    // 192.175.48.0/24
        (0xc612_0000, 0xc613_ffff, Denied::Benchmarking), // 198.18.0.0/15
        (0xc633_6400, 0xc633_64ff, Denied::Documentation), // 198.51.100.0/24
        (0xcb00_7100, 0xcb00_71ff, Denied::Documentation), // 203.0.113.0/24
        (0xe000_0000, 0xefff_ffff, Denied::Multicast),   // 224.0.0.0/4
        (0xf000_0000, 0xffff_ffff, Denied::Reserved),    // 240.0.0.0/4
    ];

    fn v4_oracle(bits: u32) -> Option<Denied> {
        V4_INTERVALS
            .iter()
            .find(|(lo, hi, _)| (*lo..=*hi).contains(&bits))
            .map(|(_, _, denied)| *denied)
    }

    // The v6 guard oracle: same transcription, ordered most-specific-first
    // (mirroring the table's invariants: ::1/:: before the ::/96 blanket;
    // the /48, /32 and /28 refinements before the 2001::/23 umbrella), so
    // first-match is the most specific reason. Containments beyond those
    // are impossible: every other interval is pairwise disjoint.
    const V6_INTERVALS: &[(u128, u128, Denied)] = &[
        (
            0x0000_0000_0000_0000_0000_0000_0000_0001,
            0x0000_0000_0000_0000_0000_0000_0000_0001,
            Denied::Loopback,
        ), // ::1/128
        (0, 0, Denied::Unspecified), // ::/128
        (
            0,
            0x0000_0000_0000_0000_0000_0000_ffff_ffff,
            Denied::Deprecated,
        ), // ::/96 compatible — blanket, no recursion
        (
            0x0100_0000_0000_0000_0000_0000_0000_0000,
            0x0100_0000_0000_0000_ffff_ffff_ffff_ffff,
            Denied::DiscardOnly,
        ), // 100::/64
        (
            0x0100_0000_0000_0001_0000_0000_0000_0000,
            0x0100_0000_0000_0001_ffff_ffff_ffff_ffff,
            Denied::DiscardOnly,
        ), // 100:0:0:1::/64
        (
            0x2001_0002_0000_0000_0000_0000_0000_0000,
            0x2001_0002_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Benchmarking,
        ), // 2001:2::/48
        (
            0x2620_004f_8000_0000_0000_0000_0000_0000,
            0x2620_004f_8000_ffff_ffff_ffff_ffff_ffff,
            Denied::Reserved,
        ), // 2620:4f:8000::/48
        (
            0x0064_ff9b_0001_0000_0000_0000_0000_0000,
            0x0064_ff9b_0001_ffff_ffff_ffff_ffff_ffff,
            Denied::Transition,
        ), // 64:ff9b:1::/48
        (
            0x2001_0000_0000_0000_0000_0000_0000_0000,
            0x2001_0000_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Transition,
        ), // 2001::/32 Teredo
        (
            0x2001_0db8_0000_0000_0000_0000_0000_0000,
            0x2001_0db8_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Documentation,
        ), // 2001:db8::/32
        (
            0x2001_0010_0000_0000_0000_0000_0000_0000,
            0x2001_001f_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Deprecated,
        ), // 2001:10::/28 ORCHID
        (
            0x2001_0000_0000_0000_0000_0000_0000_0000,
            0x2001_01ff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Reserved,
        ), // 2001::/23 umbrella
        (
            0x3fff_0000_0000_0000_0000_0000_0000_0000,
            0x3fff_0fff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Documentation,
        ), // 3fff::/20
        (
            0x2002_0000_0000_0000_0000_0000_0000_0000,
            0x2002_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Transition,
        ), // 2002::/16 6to4
        (
            0x5f00_0000_0000_0000_0000_0000_0000_0000,
            0x5f00_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Reserved,
        ), // 5f00::/16
        (
            0xfe80_0000_0000_0000_0000_0000_0000_0000,
            0xfebf_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::LinkLocal,
        ), // fe80::/10
        (
            0xfec0_0000_0000_0000_0000_0000_0000_0000,
            0xfeff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Deprecated,
        ), // fec0::/10
        (
            0xff00_0000_0000_0000_0000_0000_0000_0000,
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::Multicast,
        ), // ff00::/8
        (
            0xfc00_0000_0000_0000_0000_0000_0000_0000,
            0xfdff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
            Denied::UniqueLocal,
        ), // fc00::/7
    ];

    fn v6_oracle(bits: u128) -> Option<Denied> {
        // The embedded families with an RFC-guaranteed layout FIRST:
        // mapped ::ffff:0:0/96 and NAT64 WKP 64:ff9b::/96 delegate to the
        // v4 oracle on the low 32 bits (the inner reason propagates).
        // Expressed as inclusive intervals — deliberately NOT the
        // implementation's bits >> 32 + hi-96-constant shape, so the
        // oracle stays an independent representation end to end.
        const EMBEDDED_V4_INTERVALS: &[(u128, u128)] = &[
            // ::ffff:0:0/96 (mapped)
            (0xffff_0000_0000, 0xffff_ffff_ffff),
            // 64:ff9b::/96 (NAT64 WKP)
            (
                0x0064_ff9b_0000_0000_0000_0000,
                0x0064_ff9b_0000_0000_ffff_ffff,
            ),
        ];
        if EMBEDDED_V4_INTERVALS
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&bits))
        {
            return v4_oracle(bits as u32);
        }
        V6_INTERVALS
            .iter()
            .find(|(lo, hi, _)| (*lo..=*hi).contains(&bits))
            .map(|(_, _, denied)| *denied)
    }

    proptest! {
        #[test]
        fn prop_out_of_set_hosts_never_allowed(
            allow_names in proptest::collection::vec(prop_domain(), 1..=4),
            host in prop_host(),
        ) {
            // THE acceptance criterion: "no host outside the allow set is
            // ever accepted" — the !oracle ⇒ None direction is the
            // security-critical half; the equality also catches
            // over-denial. Self-canonical inputs make the oracle sound.
            for name in allow_names.iter().chain([&host]) {
                prop_assert!(
                    Domain::parse(name).is_ok_and(|p| p.as_str() == name.as_str()),
                    "generated name {name:?} must be self-canonical"
                );
            }
            let entries: Vec<Domain> = allow_names.iter().map(|s| dom(s)).collect();
            prop_assert_eq!(
                allowed(&host, &entries).is_some(),
                in_set_oracle(&host, &allow_names)
            );
        }

        #[test]
        fn prop_subdomains_of_allowed_always_allowed(
            allow_names in proptest::collection::vec(prop_domain(), 1..=4),
            prefixes in proptest::collection::vec(prop_label(), 0..=2),
            pick in any::<proptest::sample::Index>(),
        ) {
            // A host built by prepending 0–2 random labels to a random
            // allow entry is in-set by definition ⇒ always Some.
            let entry = pick.get(&allow_names);
            let host = prefixes
                .iter()
                .chain([entry])
                .cloned()
                .collect::<Vec<_>>()
                .join(".");
            prop_assert!(
                Domain::parse(&host).is_ok_and(|p| p.as_str() == host.as_str()),
                "generated host {host:?} must be self-canonical"
            );
            let entries: Vec<Domain> = allow_names.iter().map(|s| dom(s)).collect();
            prop_assert!(allowed(&host, &entries).is_some());
        }

        #[test]
        fn prop_semantics_preserving_mutations_still_allowed(
            allow_names in proptest::collection::vec(prop_domain(), 1..=4),
            pick in any::<proptest::sample::Index>(),
            mutation in 0..3u8,
        ) {
            let entry = pick.get(&allow_names);
            // Mutations whose canonical form is the entry itself: case
            // flip, a single trailing root dot, fullwidth fold (each ASCII
            // char → its U+FF01-range equivalent). Canonical ⇒ in-set ⇒
            // Some; no oracle needed.
            let host = match mutation {
                0 => entry.to_uppercase(),
                1 => format!("{entry}."),
                _ => entry
                    .chars()
                    .map(|c| {
                        char::from_u32(u32::from(c) - 0x21 + 0xFF01).expect("fullwidth char")
                    })
                    .collect(),
            };
            // Canonical-form identity through the runtime pipeline: strip
            // one ASCII dot, then parse (mirrors allowed()'s own steps).
            let bare = host.strip_suffix('.').unwrap_or(&host);
            prop_assert!(Domain::parse(bare).is_ok_and(|p| p.as_str() == entry.as_str()));
            let entries: Vec<Domain> = allow_names.iter().map(|s| dom(s)).collect();
            prop_assert!(allowed(&host, &entries).is_some());
        }

        #[test]
        fn prop_adversarial_mutations_match_oracle(
            allow_names in proptest::collection::vec(prop_domain(), 1..=4),
            pick in any::<proptest::sample::Index>(),
            mutation in 0..2u8,
        ) {
            let entry = pick.get(&allow_names);
            // Boundary-breaking mutations: bare-prefix glue (the eBPF bug
            // class) and suffix escape. Both stay self-canonical, so the
            // raw-string oracle decides — never a hardcoded None:
            // accidental collisions with OTHER generated entries (allow
            // can itself contain "evil<entry>" or "<label>.evil.tld") must
            // be handled correctly, and the oracle does that by design.
            let host = match mutation {
                0 => format!("evil{entry}"),
                _ => format!("{entry}.evil.tld"),
            };
            prop_assert!(
                Domain::parse(&host).is_ok_and(|p| p.as_str() == host.as_str()),
                "mutation {host:?} must be self-canonical"
            );
            let entries: Vec<Domain> = allow_names.iter().map(|s| dom(s)).collect();
            prop_assert_eq!(
                allowed(&host, &entries).is_some(),
                in_set_oracle(&host, &allow_names)
            );
        }

        #[test]
        fn prop_arbitrary_unicode_never_panics_and_matches_oracle(
            allow_names in proptest::collection::vec(prop_domain(), 0..=3),
            host in any::<String>(),
        ) {
            for name in &allow_names {
                prop_assert!(
                    Domain::parse(name).is_ok_and(|p| p.as_str() == name.as_str()),
                    "generated name {name:?} must be self-canonical"
                );
            }
            // Fuzz-lite: arbitrary Unicode hosts must never panic (the
            // fork+timeout features turn aborts/hangs into ordinary
            // failures too), and the verdict must equal the contract:
            // normalize (one ASCII dot stripped, single pipeline) —
            // Err ⇒ None; Ok ⇒ the raw-string oracle over the canonical
            // form.
            let bare = host.strip_suffix('.').unwrap_or(&host);
            let expected = match Domain::parse(bare) {
                Ok(parsed) => in_set_oracle(parsed.as_str(), &allow_names),
                Err(_) => false,
            };
            let entries: Vec<Domain> = allow_names.iter().map(|s| dom(s)).collect();
            prop_assert_eq!(allowed(&host, &entries).is_some(), expected);
        }

        #[test]
        fn prop_guard_v4_matches_interval_oracle(bits in any::<u32>()) {
            // Verdict AND variant equality over the whole v4 space:
            // interval-membership arithmetic vs prefix/shift arithmetic.
            let expected = match v4_oracle(bits) {
                Some(denied) => Err(denied),
                None => Ok(()),
            };
            prop_assert_eq!(guard(IpAddr::V4(Ipv4Addr::from(bits))), expected);
        }

        #[test]
        fn prop_guard_v6_matches_interval_oracle(bits in any::<u128>()) {
            let expected = match v6_oracle(bits) {
                Some(denied) => Err(denied),
                None => Ok(()),
            };
            prop_assert_eq!(guard(IpAddr::V6(Ipv6Addr::from(bits))), expected);
        }

        #[test]
        fn prop_mapped_and_nat64_equivalence(bits in any::<u32>()) {
            // Full Result equality (inner variants included): the
            // guaranteed-layout embedded forms are verdict-identical to
            // the bare IPv4 they carry — over the WHOLE v4 space, not
            // just the denied ranges.
            let v4 = IpAddr::V4(Ipv4Addr::from(bits));
            let payload = u128::from(bits);
            let mapped = IpAddr::V6(Ipv6Addr::from(
                0x0000_0000_0000_0000_0000_ffff_0000_0000u128 | payload,
            ));
            let wkp = IpAddr::V6(Ipv6Addr::from(
                0x0064_ff9b_0000_0000_0000_0000_0000_0000u128 | payload,
            ));
            prop_assert_eq!(guard(mapped), guard(v4));
            prop_assert_eq!(guard(wkp), guard(v4));
        }

        #[test]
        fn prop_transition_payloads_always_denied(payload in any::<u128>()) {
            // The blanket decisions (R1/R2) at property scale: whatever
            // the payload — a "public" IPv4, loopback, anything — the
            // three Transition ranges deny with Transition. The masks
            // keep each address inside its range, so no more-specific row
            // can fire (Teredo's second group stays 0x0000, excluding the
            // 2001:2::/48 and 2001:10::/28 refinements) and no
            // embedded-v4 recursion triggers (the local-NAT64 third group
            // stays 0x0001 ≠ the WKP's 0x0000).
            const MASK96: u128 = 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff;
            const MASK112: u128 = 0x0000_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
            const MASK80: u128 = 0x0000_0000_0000_ffff_ffff_ffff_ffff_ffff;
            let cases = [
                0x2001_0000_0000_0000_0000_0000_0000_0000u128 | (payload & MASK96),
                0x2002_0000_0000_0000_0000_0000_0000_0000u128 | (payload & MASK112),
                0x0064_ff9b_0001_0000_0000_0000_0000_0000u128 | (payload & MASK80),
            ];
            for bits in cases {
                prop_assert_eq!(
                    guard(IpAddr::V6(Ipv6Addr::from(bits))),
                    Err(Denied::Transition)
                );
            }
        }
    }
}
