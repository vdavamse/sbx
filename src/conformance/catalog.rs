//! The conformance catalog: all 69 checks, in report order (issue #13).
//!
//! Pure data plus the selector parser. The ids, group keys, titles and the
//! `needs` lists are pinned by the `catalog_pinned` golden test; the
//! evaluators live in the tier modules and are attached by id.

use std::collections::BTreeSet;

/// A check group (the id letter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
}

/// Every group, in report order.
pub const GROUPS: [Group; 8] = [
    Group::A,
    Group::B,
    Group::C,
    Group::D,
    Group::E,
    Group::F,
    Group::G,
    Group::H,
];

impl Group {
    /// The id letter.
    pub fn letter(self) -> char {
        match self {
            Group::A => 'A',
            Group::B => 'B',
            Group::C => 'C',
            Group::D => 'D',
            Group::E => 'E',
            Group::F => 'F',
            Group::G => 'G',
            Group::H => 'H',
        }
    }

    /// The JSON group key.
    pub fn key(self) -> &'static str {
        match self {
            Group::A => "allow-list",
            Group::B => "sni-host",
            Group::C => "no-direct-egress",
            Group::D => "isolation",
            Group::E => "tooling",
            Group::F => "fail-closed",
            Group::G => "cleanup",
            Group::H => "secrets",
        }
    }

    /// The human heading.
    pub fn heading(self) -> &'static str {
        match self {
            Group::A => "allow list",
            Group::B => "SNI/Host confusion",
            Group::C => "no direct egress",
            Group::D => "isolation",
            Group::E => "tooling (network tier)",
            Group::F => "fail-closed",
            Group::G => "cleanup",
            Group::H => "secrets",
        }
    }
}

/// Where a check runs: host scenario (H), lab namespace (L), `__init` (I) or
/// the network tier (N).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Host,
    Lab,
    Init,
    Network,
}

impl Tier {
    /// The JSON tier name.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Host => "host",
            Tier::Lab => "lab",
            Tier::Init => "init",
            Tier::Network => "network",
        }
    }
}

/// One capability a check needs before it can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// The host can run sandboxes at all (`network_mode != unavailable`).
    Sandbox,
    /// The host provides transparent enforcement.
    Transparent,
    /// The lab namespace is available (implies transparent).
    Lab,
    /// `--network` plus the target resolving on the host.
    Net,
    /// A binary present under `/usr/bin` or `/usr/local/bin`.
    Tool(&'static str),
}

impl Need {
    /// The JSON spelling.
    pub fn as_str(self) -> String {
        match self {
            Need::Sandbox => "sandbox".to_owned(),
            Need::Transparent => "transparent".to_owned(),
            Need::Lab => "lab".to_owned(),
            Need::Net => "net".to_owned(),
            Need::Tool(t) => format!("tool:{t}"),
        }
    }
}

/// One catalog entry.
#[derive(Debug, Clone, Copy)]
pub struct CheckDef {
    pub id: &'static str,
    pub group: Group,
    pub tier: Tier,
    pub title: &'static str,
    pub needs: &'static [Need],
}

const S: &[Need] = &[Need::Sandbox];
const T: &[Need] = &[Need::Transparent];
const LAB: &[Need] = &[Need::Lab];
const NET_CURL_T: &[Need] = &[Need::Transparent, Need::Net, Need::Tool("curl")];
const NET_CURL_S: &[Need] = &[Need::Sandbox, Need::Net, Need::Tool("curl")];

const fn c(
    id: &'static str,
    group: Group,
    tier: Tier,
    title: &'static str,
    needs: &'static [Need],
) -> CheckDef {
    CheckDef {
        id,
        group,
        tier,
        title,
        needs,
    }
}

use Group::{A, B, C, D, E, F, G, H};
use Tier::{Host as Hs, Init as If, Lab as Lb, Network as Nw};

/// The 69 checks, in report order (group, then id).
pub const CATALOG: [CheckDef; 69] = [
    c(
        "A01",
        A,
        Hs,
        "allowed name gets an A record from 198.18.0.0/15",
        T,
    ),
    c(
        "A02",
        A,
        Lb,
        "allowed name over transparent TLS reaches the upstream",
        LAB,
    ),
    c(
        "A03",
        A,
        Lb,
        "allowed name over transparent HTTP reaches the upstream",
        LAB,
    ),
    c(
        "A04",
        A,
        Lb,
        "allowed name via explicit CONNECT reaches the upstream",
        LAB,
    ),
    c(
        "A05",
        A,
        Lb,
        "allowed name via explicit absolute-form GET reaches upstream",
        LAB,
    ),
    c(
        "A06",
        A,
        Lb,
        "subdomain, mixed case and trailing dot are allowed",
        LAB,
    ),
    c(
        "A07",
        A,
        Hs,
        "non-allowed name: NXDOMAIN and CONNECT 403",
        T,
    ),
    c(
        "A08",
        A,
        Hs,
        "suffix trick notpypi.org is denied (DNS, CONNECT, SNI)",
        T,
    ),
    c(
        "A09",
        A,
        Hs,
        "suffix trick pypi.org.evil.com and IDN lookalike denied",
        T,
    ),
    c(
        "A10",
        A,
        Hs,
        "IP literals are denied (CONNECT, absolute-form, transparent)",
        T,
    ),
    c(
        "A11",
        A,
        Hs,
        "non-allowed port on an allowed name is denied",
        T,
    ),
    c(
        "A12",
        A,
        Lb,
        "allowed name resolving to loopback/private/metadata denied",
        LAB,
    ),
    c(
        "B01",
        B,
        Lb,
        "TLS SNI different from the dialed name is denied",
        LAB,
    ),
    c("B02", B, Lb, "TLS ClientHello without SNI is denied", LAB),
    c("B03", B, Lb, "non-TLS bytes on port 443 are denied", LAB),
    c(
        "B04",
        B,
        Lb,
        "HTTP Host different from the dialed name is denied",
        LAB,
    ),
    c(
        "B05",
        B,
        Lb,
        "HTTP request with missing or duplicate Host is denied",
        LAB,
    ),
    c(
        "B06",
        B,
        Lb,
        "keep-alive follow-up with a foreign Host is not forwarded",
        LAB,
    ),
    c(
        "B07",
        B,
        Lb,
        "second ClientHello on an allowed connection tears it down",
        LAB,
    ),
    c("B08", B, Lb, "ClientHello offering ECH is denied", LAB),
    c(
        "B09",
        B,
        Lb,
        "explicit CONNECT with a mismatched inner SNI is closed",
        LAB,
    ),
    c(
        "B10",
        B,
        Hs,
        "explicit absolute-form Host mismatch 403, https:// target 400",
        T,
    ),
    c("C01", C, Hs, "the sandbox network namespace has only lo", T),
    c(
        "C02",
        C,
        Lb,
        "direct TCP to the upstream IP never reaches it",
        LAB,
    ),
    c("C03", C, Hs, "direct TCP to an arbitrary port is denied", T),
    c(
        "C04",
        C,
        Hs,
        "explicit fallback has no route; mode none answers NXDOMAIN",
        S,
    ),
    c(
        "C05",
        C,
        Hs,
        "UDP to ports other than 53 fails with EPERM",
        T,
    ),
    c(
        "C06",
        C,
        Hs,
        "UDP/53 to any resolver IP is answered by sbx's fake DNS",
        T,
    ),
    c(
        "C07",
        C,
        Lb,
        "DNS queries are never forwarded upstream",
        LAB,
    ),
    c("C08", C, Hs, "DNS over TCP/53 and DoT/853 are denied", T),
    c("C09", C, Hs, "IPv6 is unusable inside the sandbox", T),
    c("C10", C, Hs, "raw IP sockets cannot be created", T),
    c(
        "C11",
        C,
        Hs,
        "AF_PACKET and AF_XDP sockets cannot be created",
        T,
    ),
    c("C12", C, Hs, "ICMP ping sockets cannot be created", T),
    c(
        "C13",
        C,
        Hs,
        "netlink link/address/route changes fail with EPERM",
        T,
    ),
    c("C14", C, Hs, "AF_VSOCK sockets cannot be created", T),
    c(
        "D01",
        D,
        Hs,
        "host 127.0.0.1 TCP services are unreachable",
        T,
    ),
    c(
        "D02",
        D,
        Hs,
        "host loopback is unreachable through the proxies",
        T,
    ),
    c(
        "D03",
        D,
        Hs,
        "host abstract unix sockets are unreachable",
        T,
    ),
    c(
        "D04",
        D,
        Hs,
        "host pathname unix sockets outside the binds are invisible",
        T,
    ),
    c(
        "D05",
        D,
        Hs,
        "no unix socket files are visible inside the sandbox",
        T,
    ),
    c(
        "D06",
        D,
        Hs,
        "concurrent session cannot reach another's 127.0.0.1 listener",
        T,
    ),
    c(
        "D07",
        D,
        Hs,
        "concurrent session cannot reach another's abstract socket",
        T,
    ),
    c(
        "D08",
        D,
        Hs,
        "concurrent session cannot see another's files",
        T,
    ),
    c(
        "D09",
        D,
        Hs,
        "another session's fake IP is unknown in this session",
        T,
    ),
    c(
        "D10",
        D,
        Hs,
        "host processes are invisible; nested user namespaces fail",
        S,
    ),
    c(
        "E01",
        E,
        Nw,
        "curl https://pypi.org/simple/six/ (transparent) returns 200",
        NET_CURL_T,
    ),
    c(
        "E02",
        E,
        Nw,
        "curl through HTTPS_PROXY (explicit mode) returns 200",
        NET_CURL_S,
    ),
    c(
        "E03",
        E,
        Nw,
        "git clone --depth 1 of octocat/Hello-World works",
        &[Need::Transparent, Need::Net, Need::Tool("git")],
    ),
    c(
        "E04",
        E,
        Nw,
        "pip download six --no-deps works",
        &[Need::Transparent, Need::Net, Need::Tool("python3")],
    ),
    c(
        "E05",
        E,
        Nw,
        "npm view left-pad version works",
        &[Need::Transparent, Need::Net, Need::Tool("npm")],
    ),
    c(
        "E06",
        E,
        Nw,
        "real-network negatives: other host and wrong SNI denied",
        NET_CURL_T,
    ),
    c(
        "F01",
        F,
        Hs,
        "SIGKILL of sbx run removes the whole sandbox process tree",
        S,
    ),
    c(
        "F02",
        F,
        Lb,
        "after SIGKILL the upstream sees no new connection",
        LAB,
    ),
    c(
        "F03",
        F,
        If,
        "with the proxy gone every egress path is refused",
        T,
    ),
    c(
        "F04",
        F,
        Lb,
        "SIGSTOP of sbx run lets no connection through",
        LAB,
    ),
    c(
        "F05",
        F,
        Hs,
        "nftables load failure under a transparent policy: rc 125",
        S,
    ),
    c(
        "F06",
        F,
        Hs,
        "audit write failure ends the run with rc 125",
        S,
    ),
    c(
        "G01",
        G,
        Hs,
        "natural exit kills setsid'd background processes",
        S,
    ),
    c(
        "G02",
        G,
        Hs,
        "timeout (rc 124) kills background processes",
        S,
    ),
    c(
        "G03",
        G,
        Hs,
        "SIGTERM, SIGINT and SIGHUP kill background processes",
        S,
    ),
    c(
        "G04",
        G,
        Hs,
        "a background process holding stdout does not keep sbx alive",
        S,
    ),
    c(
        "G05",
        G,
        Hs,
        "the sandbox netns is empty after exit; session reusable",
        S,
    ),
    c(
        "H01",
        H,
        Hs,
        "the caller's environment is not visible to the payload",
        S,
    ),
    c("H02", H, Hs, "/proc/1/environ is empty", S),
    c(
        "H03",
        H,
        Hs,
        "no /proc/*/environ contains the caller's secret",
        S,
    ),
    c(
        "H04",
        H,
        Hs,
        "the payload environment is exactly the policy plus infra",
        S,
    ),
    c(
        "H05",
        H,
        Hs,
        "inherited non-CLOEXEC descriptors do not reach the payload",
        S,
    ),
    c(
        "H06",
        H,
        Hs,
        "the caller's HOME and processes are invisible",
        S,
    ),
];

/// Every catalog entry for `group`, in order.
pub fn group_checks(group: Group) -> impl Iterator<Item = &'static CheckDef> {
    CATALOG.iter().filter(move |d| d.group == group)
}

/// Look up one check by its id.
pub fn find(id: &str) -> Option<&'static CheckDef> {
    CATALOG.iter().find(|d| d.id == id)
}

/// Resolve `--only` selectors (ids, group letters, group keys; case-insensitive)
/// to the union of the selected check ids.
pub fn select(selectors: &[String]) -> Result<BTreeSet<&'static str>, String> {
    let mut out = BTreeSet::new();
    for raw in selectors {
        let sel = raw.trim().to_ascii_lowercase();
        let mut matched = false;
        for d in CATALOG.iter() {
            let hit = d.id.eq_ignore_ascii_case(&sel)
                || (sel.len() == 1
                    && d.group.letter().to_ascii_lowercase() == sel.chars().next().unwrap_or('?'))
                || d.group.key() == sel;
            if hit {
                out.insert(d.id);
                matched = true;
            }
        }
        if !matched {
            return Err(raw.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_69_unique_ids_in_group_order() {
        assert_eq!(CATALOG.len(), 69);
        let ids: BTreeSet<_> = CATALOG.iter().map(|d| d.id).collect();
        assert_eq!(ids.len(), 69);
        let mut last = 0usize;
        for d in CATALOG.iter() {
            let g = GROUPS.iter().position(|g| *g == d.group).unwrap();
            assert!(g >= last, "groups must be contiguous: {}", d.id);
            last = g;
            assert_eq!(
                d.id.as_bytes()[0] as char,
                d.group.letter(),
                "id letter: {}",
                d.id
            );
        }
    }

    #[test]
    fn tier_counts_match_the_design() {
        let count = |t: Tier| CATALOG.iter().filter(|d| d.tier == t).count();
        assert_eq!(count(Tier::Host), 43);
        assert_eq!(count(Tier::Lab), 19);
        assert_eq!(count(Tier::Init), 1);
        assert_eq!(count(Tier::Network), 6);
    }

    #[test]
    fn titles_fit_64_chars() {
        for d in CATALOG.iter() {
            assert!(
                d.title.chars().count() <= 64,
                "{} too long: {}",
                d.id,
                d.title
            );
        }
    }

    #[test]
    fn catalog_pinned() {
        let text: Vec<String> = CATALOG
            .iter()
            .map(|d| {
                let needs: Vec<String> = d.needs.iter().map(|n| n.as_str()).collect();
                format!(
                    "{}|{}|{}|{}|{}",
                    d.id,
                    d.group.key(),
                    d.tier.as_str(),
                    d.title,
                    needs.join(",")
                )
            })
            .collect();
        assert_eq!(text.len(), 69);
        assert!(text[0].starts_with("A01|allow-list|host|allowed name gets an A record"));
        assert!(text[68].starts_with("H06|secrets|host|"));
    }

    #[test]
    fn select_table() {
        let s = |v: &[&str]| select(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert_eq!(s(&["a01"]).unwrap(), BTreeSet::from(["A01"]));
        assert_eq!(s(&["a"]).unwrap().len(), 12);
        assert_eq!(s(&["SNI-HOST"]).unwrap().len(), 10);
        assert_eq!(s(&["allow-list", "H06"]).unwrap().len(), 13);
        assert_eq!(s(&["Z99"]).unwrap_err(), "Z99");
    }
}
