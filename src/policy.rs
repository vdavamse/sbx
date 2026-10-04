//! The versioned sandbox-policy contract — schema version 1 (issue #3).
//!
//! 1. This module owns the whole v1 policy contract: the serde types that
//!    mirror the documented JSON shape, semantic validation, and the
//!    published JSON Schema ([`schema_json`]).
//! 2. A policy states the *minimum* sbx must enforce. Comparing that minimum
//!    against what the host can actually provide is issue #11; enforcement
//!    itself is #6/#7/#8/#10. Nothing here negotiates or enforces.
//! 3. The session directory never comes from the policy — `sbx run` always
//!    takes it via `--session-dir`. `deny_unknown_fields` rejects attempts to
//!    sneak one in.
//! 4. Parsing is fail-fast: serde reports only the first problem, with
//!    `line N column M` context. Collecting every error in one pass is
//!    deliberately out of scope for v1.
//! 5. [`Policy::from_json_str`] and [`Policy::from_file`] are the only entry
//!    points that enforce the policy-wide validation rules (version, ports,
//!    environment-variable names). Deserializing [`Policy`] directly with
//!    serde_json enforces only the value-level rules baked into the types.
//!    The asymmetry is deliberate in v1, pinned by the
//!    `direct_deserialization_skips_policy_wide_rules` test, and slated to
//!    become a type-level invariant before #6 consumes [`Policy`].
//! 6. `///` doc comments on policy types are author-facing: schemars renders
//!    them as JSON Schema descriptions. Rust-internal rationale lives in `//`
//!    comments (same convention as cli.rs).
//! 7. Downstream consumers: #4 consumes [`Domain`]'s canonical form and
//!    [`Domain::parse`] (the public seam over the normalization pipeline —
//!    `egress::allowed` normalizes runtime hosts through it), #6 consumes
//!    [`AbsolutePath`]/[`Env`], #10 consumes [`Limits`], #11 consumes
//!    [`NetworkMode`]. Reuse the types — none of their logic lives here.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema, schema_for};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The policy schema version this sbx build accepts.
///
/// The JSON Schema deliberately renders `version` as a loose integer so the
/// schema stays forward-compatible; the exact check happens at runtime in
/// [`Policy::from_json_str`]/[`Policy::from_file`] with an actionable error.
pub const SUPPORTED_VERSION: u32 = 1;

/// Why a policy file was rejected — a parse, value, or validation problem.
///
/// The message is complete and user-facing (`sbx check` prints it verbatim);
/// serde value errors carry `line N column M` context.
#[derive(Debug)]
pub struct PolicyError(String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

impl From<serde_json::Error> for PolicyError {
    fn from(err: serde_json::Error) -> Self {
        PolicyError(err.to_string())
    }
}

/// The network isolation level a policy demands.
///
/// The policy states the *minimum* it accepts; sbx refuses to run a policy
/// under a weaker mode than the host can provide (capability comparison is
/// issue #11). Spellings are exactly `transparent`, `explicit`, `none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Egress is filtered transparently: the sandboxed command connects
    /// normally and sbx's proxy filters allowed destinations in the network
    /// namespace, without the command's cooperation.
    Transparent,
    /// The sandboxed command must connect through an explicitly configured
    /// proxy; sbx does not redirect traffic transparently.
    Explicit,
    /// No network access at all.
    None,
}

/// An absolute, lexically canonical filesystem path from a policy.
///
/// The stored string is exactly what was written in the policy and exactly
/// what a bind mount will see — no normalization happens downstream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AbsolutePath(String);

impl AbsolutePath {
    /// The path text, as written in the policy.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The same path as a [`Path`] — the seam for bwrap argv assembly (#6).
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

// Value-level rules, enforced at deserialization so rejections carry serde's
// line/column context. Deep normalization (resolving symlinks, collapsing
// `..` against the real filesystem) is deliberately out of scope: the rule is
// "stored string == lexically canonical == what bwrap will see".
fn check_path(s: &str) -> Result<(), String> {
    if !s.starts_with('/') {
        return Err(format!("must be an absolute path (got {s:?})"));
    }
    // NUL cannot cross any C-string interface. Rust's own spawn path is
    // fail-closed (std::process::Command rejects a NUL in argv/env with
    // InvalidInput before the kernel ever sees it), but #6 may assemble
    // bwrap argv via raw byte buffers, where the kernel would truncate at
    // the NUL and the *validated* path would silently differ from the
    // *mounted* one — so we reject here, at the contract boundary, instead
    // of relying on each downstream caller to fail closed. What we validate
    // must be what the kernel sees. (Domain already rejects NUL implicitly
    // via ToASCII.)
    if s.contains('\0') {
        return Err(format!("must not contain NUL bytes (got {s:?})"));
    }
    if s == "/" {
        return Err("the host root '/' is never allowed in a policy path".to_owned());
    }
    // skip(1): the segment before the first '/' is always empty in an
    // absolute path; every real segment must be non-empty and not "."/"..".
    if s.split('/')
        .skip(1)
        .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(format!(
            "must be lexically canonical: no '.', '..' or empty ('//'/trailing-slash) segments (got {s:?})"
        ));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for AbsolutePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        match check_path(&raw) {
            Ok(()) => Ok(Self(raw)),
            Err(message) => Err(serde::de::Error::custom(message)),
        }
    }
}

impl JsonSchema for AbsolutePath {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("AbsolutePath")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        // The pattern is deliberately coarse (JSON Schema regex cannot
        // express "segment is not '.' or '..'"); the description carries the
        // full rule, and `sbx check` is the authority — the schema is
        // documentation and editor support, not the enforcement point.
        json_schema!({
            "type": "string",
            "description": "An absolute, lexically canonical filesystem path (no '.', '..' or empty segments, no trailing slash, no NUL bytes). The host root '/' is never allowed: the filesystem sections are allow-lists of bind mounts.",
            "pattern": "^/([^/]+/)*[^/]+$"
        })
    }
}

/// A domain name from a policy, normalized to lowercase punycode.
///
/// The stored form is canonical — ASCII, lowercase, no root dot, with
/// wildcards and IP literals rejected. "IP literals" includes the legacy
/// inet_aton numeric forms (a bare `123`, `0001.2.3.4`, `0x7f.0.0.1`),
/// which getaddrinfo resolves to addresses without DNS. Policy-side
/// matching never re-normalizes the stored form; runtime hosts normalize
/// through [`Domain::parse`] (#4's `egress::allowed` strips exactly one
/// trailing root dot, then parses — one pipeline, both directions).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Domain(String);

/// Why [`Domain::parse`] rejected a string.
///
/// The message is one of the pinned rejection strings — byte-identical to
/// what policy deserialization reports for the same input (single pipeline,
/// single source; `parse_equals_deserialize` pins the equivalence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError(String);

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DomainError {}

impl Domain {
    /// Parse a domain string into its canonical stored form.
    ///
    /// The single normalization pipeline behind both policy deserialization
    /// and runtime-host matching (#4's [`crate::egress::allowed`]): UTS #46
    /// ToASCII (URL deny-list, hyphen first/last checks, DNS-length
    /// verification) with wildcard, IP-literal and legacy inet_aton
    /// rejection applied to the raw input AND to the normalized output.
    ///
    /// Does **not** strip a trailing root dot — policy entries are written
    /// dot-less (`example.com.` is rejected); `egress::allowed` strips
    /// exactly one ASCII dot from runtime hosts before calling.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        normalize_domain(raw).map(Self).map_err(DomainError)
    }

    /// The normalized domain: lowercase punycode ASCII, no root dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Pinned rejection messages, built in exactly one place each so the strings
// the tests pin can never drift between call sites.
fn wildcard_rejection(raw: &str) -> String {
    format!("wildcard domains are not allowed (got {raw:?})")
}

fn ip_rejection(raw: &str) -> String {
    format!("IP literals are not allowed; use a domain name (got {raw:?})")
}

// Legacy inet_aton numeric forms: every label is all-ASCII-digits ("123",
// "0001.2.3.4") or a "0x" hex literal ("0x7f.0.0.1"). getaddrinfo resolves
// these to IP addresses via the numeric fast path without ever consulting
// DNS — glibc and musl alike implement the full inet_aton grammar
// (decimal/octal/hex, 1-4 parts; musl: __lookup_ipliteral → __inet_aton,
// strtoul base 0, since its 2014 resolver overhaul) — so they are IP
// literals to any caller even though Rust's strict IpAddr parser rejects
// them, and rejecting them is libc-independent (sandboxed commands link
// the host libc, typically glibc). All-numeric TLDs are forbidden, so an
// all-numeric-label name has no legitimate DNS use — rejected in v1 with
// the same message as strict IP literals. A single non-numeric label
// ("123.com", "0xdead.beef") means real DNS resolution and stays legal.
// Applied to the NORMALIZED form: ToASCII NFKC-folds fullwidth digits
// ("１２３" → "123") and lowercases ("0X7F" → "0x7f"), so one
// post-normalization check covers every spelling.
fn is_inet_aton_form(ascii: &str) -> bool {
    ascii.split('.').all(|label| {
        !label.is_empty()
            && (label.bytes().all(|b| b.is_ascii_digit())
                || label.strip_prefix("0x").is_some_and(|rest| {
                    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit())
                }))
    })
}

// The normalization pipeline: wildcard + IP-literal pre-checks on the RAW
// input, UTS #46 ToASCII, then BOTH checks repeated on the NORMALIZED
// output.
fn normalize_domain(raw: &str) -> Result<String, String> {
    // The raw-input wildcard check exists for message quality in the common
    // ASCII case. It is NOT sufficient alone: NFKC maps fullwidth '＊'
    // (U+FF0A) to ASCII '*', and ToASCII under the URL deny-list accepts
    // the result — so the check repeats on the normalized output below
    // (pinned by fullwidth_wildcard_rejected + idna_alone_passes_wildcards).
    if raw.contains('*') {
        return Err(wildcard_rejection(raw));
    }
    // Textual IP literals get their dedicated message before UTS #46 sees
    // them: IPv4 passes ToASCII unchanged, and IPv6 (colons are disallowed
    // characters) would otherwise be rejected with the generic "not a valid
    // domain name" message.
    if raw.parse::<IpAddr>().is_ok() {
        return Err(ip_rejection(raw));
    }
    let ascii = idna::uts46::Uts46::new()
        .to_ascii(
            raw.as_bytes(),
            idna::uts46::AsciiDenyList::URL,
            idna::uts46::Hyphens::CheckFirstLast,
            idna::uts46::DnsLength::Verify,
        )
        // idna's Errors is an opaque bitmask without human-readable text, so
        // sbx writes its own message. This rejects: the empty string, empty
        // labels ("ex..com"), a trailing root dot ("example.com."), 64-char
        // labels, and leading/trailing hyphens ("-bad.com", "bad-.com").
        .map_err(|_| format!("not a valid domain name (got {raw:?})"))?;
    // Both checks repeat on the normalized output because NFKC folding can
    // introduce characters the raw input did not contain: '＊' becomes '*'
    // and "１.２.３.４" becomes "1.2.3.4". The IP rule additionally covers
    // legacy inet_aton forms Rust's strict parser misses (bare "123",
    // "0001.2.3.4", "0x7f.0.0.1" — getaddrinfo resolves all of them
    // without DNS). Rejecting them here is v1 input validation, not #4
    // matching logic; #4's resolved-address guard remains the runtime
    // backstop. The meta-tests pin that idna alone passes both wildcards
    // and IP literals.
    if ascii.contains('*') {
        return Err(wildcard_rejection(raw));
    }
    if ascii.parse::<IpAddr>().is_ok() || is_inet_aton_form(&ascii) {
        return Err(ip_rejection(raw));
    }
    Ok(ascii.into_owned())
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        // DomainError's Display is the pinned message, so custom() carries
        // it byte-identically — one pipeline for both entry points.
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Domain {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Domain")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "hostname",
            "description": "A domain name, normalized to lowercase punycode (IDNA / UTS #46). Wildcards ('*.example.com') and IP literals — including legacy numeric forms such as '0x7f.0.0.1' or a bare '123' — are rejected; write the name a resolver would return."
        })
    }
}

/// A sandbox policy: the versioned contract between a policy author and sbx.
///
/// Every section is required — for a security artifact, explicit beats
/// implicit. The policy states the *minimum* sbx must enforce; the session
/// directory never comes from the policy (always `--session-dir`). See
/// `examples/` for the canonical shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Policy schema version; this sbx build accepts version 1.
    pub version: u32,

    /// Filesystem bind-mount allow-lists.
    pub filesystem: Filesystem,

    /// Network egress policy.
    pub network: Network,

    /// Environment variables visible inside the sandbox.
    pub env: Env,

    /// Resource limits for the sandboxed command.
    pub limits: Limits,
}

/// Filesystem bind-mount allow-lists.
///
/// The sandbox's filesystem is built exclusively from what is listed here —
/// the host root is never mounted wholesale. Paths in `deny` take precedence:
/// they must never be visible, even inside an `ro` or `rw` mount.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    /// Paths mounted read-only into the sandbox.
    pub ro: Vec<AbsolutePath>,

    /// Paths mounted read-write into the sandbox.
    pub rw: Vec<AbsolutePath>,

    /// Paths that must never be visible, even inside an `ro`/`rw` mount.
    pub deny: Vec<AbsolutePath>,
}

/// Network egress policy.
///
/// `mode` states the minimum isolation this policy accepts; `allow` and
/// `ports` form the egress allow-list — destinations and ports that are not
/// listed are blocked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Minimum network isolation this policy accepts.
    pub mode: NetworkMode,

    /// Domain names the sandbox may reach. Normalized to lowercase punycode;
    /// wildcards and IP literals are rejected.
    pub allow: Vec<Domain>,

    /// Destination ports the sandbox may use. Port 0 is not a valid
    /// destination port and is rejected.
    pub ports: Vec<u16>,
}

/// Environment variables visible inside the sandbox.
///
/// The sandbox environment starts empty: only names listed in `pass` are
/// inherited from the host (with their host values), and only the pairs in
/// `set` are given fixed values. Names must be valid POSIX environment
/// variable names (`^[A-Za-z_][A-Za-z0-9_]*$`); values are unrestricted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Env {
    /// Variable names inherited from the host environment.
    pub pass: Vec<String>,

    /// Variables set to fixed values inside the sandbox. Duplicate keys are
    /// rejected rather than silently resolved last-wins: a hand-edited
    /// policy with a botched merge must not pass `sbx check`.
    #[serde(deserialize_with = "de_env_set")]
    pub set: BTreeMap<String, String>,
}

// serde derive rejects duplicate *struct* keys, but plain BTreeMap
// deserialization keeps only the last of duplicate dynamic keys. For a
// hand-edited security policy that silently drops an assignment (botched
// merge, copy-paste), so env.set rejects repeats instead — with serde's
// line/column context. The declared field type is unchanged, so the
// generated JSON Schema is identical to a plain BTreeMap<String, String>.
fn de_env_set<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct EnvSetVisitor;

    impl<'de> serde::de::Visitor<'de> for EnvSetVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map of environment variable names to values")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if entries.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate key {key:?} in env.set"
                    )));
                }
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_map(EnvSetVisitor)
}

/// Resource limits for the sandboxed command.
///
/// `sbx run` enforces these (issue #10); this schema only defines and
/// validates the values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Kill the command after this long. Human format (`120s`, `2m`, `7d`),
    /// greater than zero.
    #[serde(deserialize_with = "de_duration", serialize_with = "ser_duration")]
    #[schemars(with = "String", extend("format" = "duration-string", "examples" = ["120s"]))]
    pub timeout: Duration,

    /// How many bytes of command output to capture; 0 means "capture none".
    pub output_bytes: u64,
}

// One duration contract for CLI flags and policy files: reuse
// crate::cli::parse_duration (humantime grammar + zero rejection), so
// "120s" means exactly the same thing in both places.
fn de_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    let text = String::deserialize(deserializer)?;
    crate::cli::parse_duration(&text).map_err(serde::de::Error::custom)
}

// humantime's formatter is value-stable but not text-stable: "120s"
// serializes back as the equal "2m". Round-trips compare values, not text.
fn ser_duration<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&humantime::format_duration(*duration).to_string())
}

impl Policy {
    /// Parse and validate a policy from its JSON text.
    pub fn from_json_str(text: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_json::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Read, parse, and validate a policy file.
    ///
    /// An unreadable file is a [`PolicyError`] naming the path — same rc-1
    /// class as an invalid policy, never a panic. A file whose bytes are
    /// not UTF-8 gets its own accurate message (it *was* read; *decoding*
    /// it failed).
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            // read_to_string reports InvalidData when the bytes are not
            // valid UTF-8; every other failure is a genuine read error.
            if err.kind() == std::io::ErrorKind::InvalidData {
                PolicyError(format!("{} is not valid UTF-8", path.display()))
            } else {
                PolicyError(format!("cannot read {}: {err}", path.display()))
            }
        })?;
        Self::from_json_str(&text)
    }

    // Policy-wide rules (D3): value-level invariants live in the newtypes'
    // Deserialize impls so they carry line/column context; these run after a
    // successful parse and are reachable only via from_json_str/from_file —
    // direct serde_json deserialization of `Policy` skips them (module doc
    // point 5; pinned by direct_deserialization_skips_policy_wide_rules).
    // TODO(#6): make "`Policy` exists ⇒ `Policy` is valid" a type-level
    // invariant — e.g. a private raw mirror with #[serde(try_from)], or
    // Port/EnvName validating newtypes (which would also restore
    // line/column context for these errors) — before enforcement
    // consumers (#6/#10) start constructing `Policy` outside this module.
    // #6 should also revisit NUL in env.set *values* (deliberately
    // unrestricted here; keys/pass-names are POSIX-validated hence
    // NUL-free): Rust's Command::env fails closed, but the same
    // "validated == what the kernel sees" rationale resurfaces once #6
    // assembles `bwrap --setenv`.
    fn validate(&self) -> Result<(), PolicyError> {
        if self.version != SUPPORTED_VERSION {
            return Err(PolicyError(format!(
                "unsupported policy version {}; this sbx supports version {}",
                self.version, SUPPORTED_VERSION
            )));
        }
        for (index, port) in self.network.ports.iter().enumerate() {
            if *port == 0 {
                return Err(PolicyError(format!(
                    "network.ports[{index}] is 0; port 0 is not a valid destination port"
                )));
            }
        }
        for (index, name) in self.env.pass.iter().enumerate() {
            if !valid_env_name(name) {
                return Err(env_name_error(&format!("env.pass[{index}]"), name));
            }
        }
        for name in self.env.set.keys() {
            if !valid_env_name(name) {
                return Err(env_name_error("env.set key", name));
            }
        }
        Ok(())
    }
}

// POSIX portable filename charset for environment names — hand-rolled to
// avoid a regex dependency (D8). Values are unrestricted.
fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn env_name_error(where_: &str, name: &str) -> PolicyError {
    PolicyError(format!(
        "{where_}: {name:?} is not a valid environment variable name (expected ^[A-Za-z_][A-Za-z0-9_]*$)"
    ))
}

/// Render the policy JSON Schema (draft 2020-12) as pretty JSON.
///
/// Deterministic for a pinned dependency set: no trailing newline (the
/// caller adds one when writing to stdout).
pub fn schema_json() -> String {
    serde_json::to_string_pretty(&schema_for!(Policy))
        .expect("serializing a generated schema to JSON cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- fixtures ------------------------------------------------------

    /// The issue #3 draft policy, verbatim (== examples/default.json, minus
    /// the file's trailing newline).
    const DRAFT: &str = r#"{
  "version": 1,
  "filesystem": { "ro": ["/usr", "/etc/ssl"], "rw": [], "deny": [] },
  "network": { "mode": "transparent", "allow": ["github.com", "pypi.org"], "ports": [443, 80] },
  "env": { "pass": ["LANG"], "set": { "GIT_TERMINAL_PROMPT": "0" } },
  "limits": { "timeout": "120s", "output_bytes": 10485760 }
}"#;

    /// Replace `from` with `to` in [`DRAFT`]; panics if the fixture does not
    /// contain `from` (a silent no-op would make tests vacuous).
    fn draft_with(from: &str, to: &str) -> String {
        assert!(DRAFT.contains(from), "fixture lacks {from:?}");
        DRAFT.replace(from, to)
    }

    /// Parse-and-validate `json`, which must be rejected; return the error
    /// text (the surface `sbx check` prints).
    fn err_of(json: &str) -> String {
        Policy::from_json_str(json)
            .expect_err("must be rejected")
            .to_string()
    }

    /// Quote `value` as a JSON string (handles backslashes, unicode, ...).
    fn json_str(value: &str) -> String {
        serde_json::Value::String(value.to_owned()).to_string()
    }

    /// [`DRAFT`] with `filesystem.ro` replaced by the single path `value`.
    fn with_ro(value: &str) -> String {
        draft_with(
            r#""ro": ["/usr", "/etc/ssl"]"#,
            &format!(r#""ro": [{}]"#, json_str(value)),
        )
    }

    /// [`DRAFT`] with `network.allow` replaced by the single domain `value`.
    fn with_allow(value: &str) -> String {
        draft_with(
            r#""allow": ["github.com", "pypi.org"]"#,
            &format!(r#""allow": [{}]"#, json_str(value)),
        )
    }

    /// [`DRAFT`] with a top-level key removed.
    fn without_key(json: &str, key: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(json).expect("fixture is valid");
        value
            .as_object_mut()
            .expect("fixture is an object")
            .remove(key)
            .unwrap_or_else(|| panic!("fixture lacks key {key:?}"));
        serde_json::to_string(&value).expect("re-serializable")
    }

    /// Parse `json`, which must be accepted.
    fn policy_of(json: &str) -> Policy {
        Policy::from_json_str(json).unwrap_or_else(|err| panic!("must parse: {err}"))
    }

    // ---- valid policies / round-trip ------------------------------------

    #[test]
    fn issue_draft_parses_with_typed_values() {
        let policy = policy_of(DRAFT);
        assert_eq!(policy.version, SUPPORTED_VERSION);
        assert_eq!(
            policy
                .filesystem
                .ro
                .iter()
                .map(AbsolutePath::as_str)
                .collect::<Vec<_>>(),
            ["/usr", "/etc/ssl"]
        );
        assert!(policy.filesystem.rw.is_empty());
        assert!(policy.filesystem.deny.is_empty());
        assert_eq!(policy.network.mode, NetworkMode::Transparent);
        assert_eq!(
            policy
                .network
                .allow
                .iter()
                .map(Domain::as_str)
                .collect::<Vec<_>>(),
            ["github.com", "pypi.org"]
        );
        assert_eq!(policy.network.ports, [443, 80]);
        assert_eq!(policy.env.pass, ["LANG"]);
        assert_eq!(
            policy
                .env
                .set
                .get("GIT_TERMINAL_PROMPT")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(policy.limits.timeout, Duration::from_secs(120));
        assert_eq!(policy.limits.output_bytes, 10_485_760);
    }

    #[test]
    fn roundtrip_is_value_stable() {
        let policy = policy_of(DRAFT);
        let text = serde_json::to_string_pretty(&policy).expect("policy must serialize");
        // Pins the humantime asymmetry: "120s" comes back as the equal "2m".
        assert!(text.contains(r#""timeout": "2m""#), "{text}");
        let reparsed = policy_of(&text);
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn shipped_examples_validate() {
        // Drift guard: every examples/*.json must satisfy the current
        // validation rules — the CI smoke exercises them through the real
        // static binary too.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
        let mut count = 0;
        for entry in std::fs::read_dir(&dir).expect("examples/ must exist") {
            let path = entry.expect("readable dir entry").path();
            if path.extension().is_some_and(|ext| ext == "json") {
                Policy::from_file(&path).unwrap_or_else(|err| {
                    panic!("{} must be a valid policy: {err}", path.display())
                });
                count += 1;
            }
        }
        assert_eq!(count, 2, "exactly default.json + locked-down.json ship");
    }

    #[test]
    fn default_example_matches_issue_draft() {
        // The shipped default IS the issue #3 draft, byte-for-byte (modulo
        // the file's trailing newline) — and therefore value-equal to the
        // test fixture. The committed file is LF; the `replace` tolerates
        // CRLF *working copies* (core.autocrlf=true checkouts): rustc
        // normalizes CRLF to LF inside string literals, so DRAFT is LF
        // regardless of how policy.rs itself was checked out, while the
        // file is read from disk verbatim.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/default.json");
        let text = std::fs::read_to_string(&path).expect("default.json must be readable");
        assert_eq!(text.trim_end().replace("\r\n", "\n"), DRAFT);
        assert_eq!(
            Policy::from_file(&path).expect("default.json must be valid"),
            policy_of(DRAFT)
        );
    }

    #[test]
    fn minimal_empty_policy_valid() {
        // Q(ii)=A: all sections required, but every list may be empty —
        // the minimal valid policy is the full draft shape with no entries.
        let json = r#"{
          "version": 1,
          "filesystem": { "ro": [], "rw": [], "deny": [] },
          "network": { "mode": "none", "allow": [], "ports": [] },
          "env": { "pass": [], "set": {} },
          "limits": { "timeout": "1s", "output_bytes": 0 }
        }"#;
        let policy = policy_of(json);
        assert_eq!(policy.network.mode, NetworkMode::None);
        assert!(policy.network.allow.is_empty());
        assert_eq!(policy.limits.output_bytes, 0);
    }

    // ---- unknown / missing fields ---------------------------------------

    #[test]
    fn unknown_field_rejected_at_every_level() {
        // deny_unknown_fields must sit on every struct (top level + all four
        // sections), or unknown keys slip through at that level.
        let cases = [
            draft_with(r#""version": 1,"#, r#""version": 1, "surprise": 1,"#),
            draft_with(
                r#""ro": ["/usr", "/etc/ssl"]"#,
                r#""surprise": [], "ro": ["/usr", "/etc/ssl"]"#,
            ),
            draft_with(
                r#""mode": "transparent""#,
                r#""mode": "transparent", "surprise": 1"#,
            ),
            draft_with(r#""pass": ["LANG"]"#, r#""pass": ["LANG"], "surprise": []"#),
            draft_with(
                r#""timeout": "120s""#,
                r#""timeout": "120s", "surprise": 1"#,
            ),
        ];
        for json in cases {
            let err = err_of(&json);
            assert!(err.contains("unknown field"), "{err}");
            assert!(err.contains("surprise"), "{err}");
        }
    }

    #[test]
    fn session_dir_in_policy_rejected() {
        // Issue rule: the session directory never comes from the policy —
        // deny_unknown_fields rejects attempts to smuggle one in.
        let json = draft_with(
            r#""version": 1,"#,
            r#""version": 1, "session_dir": "/tmp/s","#,
        );
        let err = err_of(&json);
        assert!(err.contains("unknown field"), "{err}");
        assert!(err.contains("session_dir"), "{err}");
    }

    #[test]
    fn missing_section_rejected() {
        // Q(ii)=A: every section is required, including version.
        for key in ["version", "filesystem", "network", "env", "limits"] {
            let err = err_of(&without_key(DRAFT, key));
            assert!(err.contains("missing field"), "{key}: {err}");
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    #[test]
    fn missing_inner_field_rejected() {
        let mut value: serde_json::Value = serde_json::from_str(DRAFT).expect("fixture is valid");
        value["filesystem"]
            .as_object_mut()
            .expect("filesystem is an object")
            .remove("deny");
        let err = err_of(&serde_json::to_string(&value).expect("re-serializable"));
        assert!(err.contains("missing field"), "{err}");
        assert!(err.contains("deny"), "{err}");
    }

    // ---- AbsolutePath rules ---------------------------------------------

    #[test]
    fn relative_paths_rejected() {
        for path in ["usr", "./usr", "", "C:\\tmp"] {
            let err = err_of(&with_ro(path));
            assert!(err.contains("absolute path"), "{path:?}: {err}");
        }
    }

    #[test]
    fn root_path_rejected() {
        // D2: the host root is never a policy path (no wholesale mounts).
        let err = err_of(&with_ro("/"));
        assert!(err.contains("host root"), "{err}");
    }

    #[test]
    fn non_canonical_paths_rejected() {
        // D2: no '.', '..' or empty segments — the stored string is exactly
        // what bwrap will see (#6 does zero normalization).
        for path in ["//usr", "/usr/", "/usr/../etc", "/./x", "/a//b"] {
            let err = err_of(&with_ro(path));
            assert!(err.contains("canonical"), "{path:?}: {err}");
        }
    }

    #[test]
    fn nul_byte_paths_rejected() {
        // NUL is the one byte that cannot survive any C-string interface:
        // what `check` validates must be what the kernel would mount (#5/#6).
        for path in ["/usr\0etc", "/\0", "/a\0b/c"] {
            let err = err_of(&with_ro(path));
            assert!(err.contains("NUL"), "{path:?}: {err}");
        }
    }

    #[test]
    fn unusual_but_canonical_paths_accepted() {
        for path in ["/usr/lib/x86_64-linux-gnu", "/tmp/a b", "/日本語"] {
            let policy = policy_of(&with_ro(path));
            assert_eq!(policy.filesystem.ro[0].as_str(), path);
        }
    }

    // ---- Domain rules ----------------------------------------------------

    #[test]
    fn wildcard_domains_rejected() {
        for domain in ["*.example.com", "*", "example.*", "a.*.b.com"] {
            let err = err_of(&with_allow(domain));
            assert!(err.contains("wildcard"), "{domain:?}: {err}");
        }
    }

    #[test]
    fn ip_literals_rejected() {
        for ip in ["1.2.3.4", "0.0.0.0", "127.0.0.1", "::1", "2001:db8::1"] {
            let err = err_of(&with_allow(ip));
            assert!(err.contains("IP literals"), "{ip:?}: {err}");
        }
    }

    #[test]
    fn fullwidth_ip_literal_rejected() {
        // NFKC maps "１.２.３.４" to "1.2.3.4" — which is why the IP check
        // runs on the normalized output, not the raw input.
        let err = err_of(&with_allow("１.２.３.４"));
        assert!(err.contains("IP literals"), "{err}");
    }

    #[test]
    fn idna_alone_passes_ip_literals() {
        // Meta-test: documents why the explicit IpAddr pre-check is
        // load-bearing — IDNA ToASCII itself happily converts IP literals.
        assert!(idna::domain_to_ascii("1.2.3.4").is_ok());
    }

    #[test]
    fn fullwidth_wildcard_rejected() {
        // NFKC maps '＊' (U+FF0A) to ASCII '*' and ToASCII accepts the
        // result — which is why the wildcard check repeats on the
        // normalized output, not just the raw input.
        for domain in ["＊.example.com", "a＊b.com"] {
            let err = err_of(&with_allow(domain));
            assert!(err.contains("wildcard"), "{domain:?}: {err}");
        }
    }

    #[test]
    fn idna_alone_passes_wildcards() {
        // Meta-test: documents why the wildcard check is load-bearing —
        // ToASCII under the PRODUCTION config accepts ASCII wildcards (and
        // NFKC-folds the fullwidth '＊' into them).
        assert!(
            idna::uts46::Uts46::new()
                .to_ascii(
                    "*.example.com".as_bytes(),
                    idna::uts46::AsciiDenyList::URL,
                    idna::uts46::Hyphens::CheckFirstLast,
                    idna::uts46::DnsLength::Verify,
                )
                .is_ok()
        );
    }

    #[test]
    fn legacy_numeric_ip_forms_rejected() {
        // inet_aton forms resolve to IPs via getaddrinfo's digits-and-dots
        // fast path without DNS, so they ARE IP literals to any caller —
        // rejected with the same pinned message. Fullwidth digits are
        // NFKC-folded to ASCII by ToASCII first, so the post-normalization
        // check covers them too.
        for name in [
            "123",
            "2130706433",
            "0001.2.3.4",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f000001",
            "１２３",
        ] {
            let err = err_of(&with_allow(name));
            assert!(err.contains("IP literals"), "{name:?}: {err}");
        }
    }

    #[test]
    fn numeric_lookalikes_with_dns_resolution_accepted() {
        // Pins the inet_aton rule's boundary: one non-numeric label means
        // real DNS resolution, so these stay legal.
        for name in ["123.com", "1.2.3.4.com", "0xdead.beef"] {
            let policy = policy_of(&with_allow(name));
            assert_eq!(policy.network.allow[0].as_str(), name);
        }
    }

    #[test]
    fn domains_normalized() {
        let cases = [
            ("EXAMPLE.COM", "example.com"),
            ("例え.jp", "xn--r8jz45g.jp"),
            ("XN--R8JZ45G.JP", "xn--r8jz45g.jp"),
            ("ｅｘａｍｐｌｅ.ｃｏｍ", "example.com"),
        ];
        for (input, expected) in cases {
            let policy = policy_of(&with_allow(input));
            assert_eq!(policy.network.allow[0].as_str(), expected, "{input:?}");
        }
    }

    #[test]
    fn domain_edge_rules_pinned() {
        // Pins the D1 idna configuration (URL deny-list + CheckFirstLast +
        // Verify) so later issues cannot drift the acceptance rules
        // silently. Accepted:
        let label63 = "a".repeat(63);
        for ok in [
            "localhost",
            label63.as_str(),
            "a--b.com",
            "r1---sn-abc.googlevideo.com",
            "ex_ample.com", // URL deny-list, not STD3: underscores allowed
        ] {
            policy_of(&with_allow(ok));
        }
        // Rejected:
        let label64 = "a".repeat(64);
        for bad in [
            "example.com.", // root dot (DnsLength::Verify)
            "ex..com",      // empty label
            label64.as_str(),
            "-bad.com", // leading hyphen (CheckFirstLast)
            "bad-.com", // trailing hyphen (CheckFirstLast)
            "",
        ] {
            let err = err_of(&with_allow(bad));
            assert!(err.contains("not a valid domain name"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn domain_parse_accepts_and_normalizes() {
        // The constructor is the runtime-host normalization seam (#4): the
        // same pipeline and the same canonical output as deserialization.
        let label63 = "a".repeat(63);
        let cases = [
            ("EXAMPLE.COM", "example.com"),
            ("例え.jp", "xn--r8jz45g.jp"),
            ("ＸＮ--Ｒ８ＪＺ４５Ｇ.ＪＰ", "xn--r8jz45g.jp"),
            ("ｅｘａｍｐｌｅ.ｃｏｍ", "example.com"),
            ("localhost", "localhost"),
            (label63.as_str(), label63.as_str()),
            ("ex_ample.com", "ex_ample.com"),
            ("123.com", "123.com"),
        ];
        for (input, expected) in cases {
            let parsed = Domain::parse(input).unwrap_or_else(|err| panic!("{input:?}: {err}"));
            assert_eq!(parsed.as_str(), expected, "{input:?}");
        }
    }

    #[test]
    fn domain_parse_rejects_with_pinned_messages() {
        // Exact-message pins per rejection family — the constructor reports
        // the identical strings deserialization does (single source).
        let not_valid = |raw: &str| format!("not a valid domain name (got {raw:?})");
        let wildcard = |raw: &str| format!("wildcard domains are not allowed (got {raw:?})");
        let ip =
            |raw: &str| format!("IP literals are not allowed; use a domain name (got {raw:?})");
        let label64 = "a".repeat(64);
        let cases = [
            ("example.com.", not_valid("example.com.")),
            ("", not_valid("")),
            ("ex..com", not_valid("ex..com")),
            (label64.as_str(), not_valid(&label64)),
            ("-bad.com", not_valid("-bad.com")),
            ("bad-.com", not_valid("bad-.com")),
            ("*.example.com", wildcard("*.example.com")),
            ("＊.example.com", wildcard("＊.example.com")),
            ("1.2.3.4", ip("1.2.3.4")),
            ("::1", ip("::1")),
            ("123", ip("123")),
            ("0x7f.0.0.1", ip("0x7f.0.0.1")),
            ("0177.0.0.1", ip("0177.0.0.1")),
            ("１.２.３.４", ip("１.２.３.４")),
        ];
        for (input, expected) in cases {
            let err = Domain::parse(input).unwrap_err();
            assert_eq!(err.to_string(), expected, "{input:?}");
        }
    }

    #[test]
    fn parse_equals_deserialize() {
        // Meta/equivalence: the public constructor and the serde path share
        // one pipeline, so they can never drift — same accepts, same
        // canonical form, same rejection text (serde adds only its line/
        // column position context around the identical custom message).
        let label63 = "a".repeat(63);
        let label64 = "a".repeat(64);
        let matrix = [
            // accepted: canonical, case-folded, IDN, fullwidth, underscore,
            // numeric look-alikes, hyphen rules, long label
            "example.com",
            "EXAMPLE.COM",
            "localhost",
            "ex_ample.com",
            "123.com",
            "0xdead.beef",
            "1.2.3.4.com",
            "a--b.com",
            "r1---sn-abc.googlevideo.com",
            label63.as_str(),
            "例え.jp",
            "xn--r8jz45g.jp",
            "ＸＮ--Ｒ８ＪＺ４５Ｇ.ＪＰ",
            "ｅｘａｍｐｌｅ.ｃｏｍ",
            // rejected: root dot, empty string/label, overlong label, edge
            // hyphens, wildcards (ASCII + fullwidth), IP literals (strict +
            // inet_aton spellings + fullwidth digits)
            "example.com.",
            "",
            "ex..com",
            label64.as_str(),
            "-bad.com",
            "bad-.com",
            "*.example.com",
            "*",
            "example.*",
            "＊.example.com",
            "1.2.3.4",
            "::1",
            "2001:db8::1",
            "123",
            "2130706433",
            "0001.2.3.4",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f000001",
            "１２３",
            "１.２.３.４",
        ];
        for input in matrix {
            match (
                Domain::parse(input),
                serde_json::from_str::<Domain>(&json_str(input)),
            ) {
                (Ok(parsed), Ok(deserialized)) => {
                    assert_eq!(parsed, deserialized, "{input:?}");
                }
                (Err(parse_err), Err(deserialize_err)) => {
                    let text = deserialize_err.to_string();
                    assert!(
                        text.starts_with(&parse_err.to_string()),
                        "{input:?}: {text:?} does not carry {parse_err:?}"
                    );
                }
                (Ok(parsed), Err(err)) => {
                    panic!("{input:?}: parse accepted {parsed:?} but deserialize failed: {err}")
                }
                (Err(err), Ok(deserialized)) => {
                    panic!(
                        "{input:?}: parse rejected ({err}) but deserialize accepted {deserialized:?}"
                    )
                }
            }
        }
    }

    // ---- ports -----------------------------------------------------------

    #[test]
    fn port_out_of_u16_range_rejected() {
        for ports in ["[65536]", "[-1]"] {
            let err = err_of(&draft_with(
                r#""ports": [443, 80]"#,
                &format!(r#""ports": {ports}"#),
            ));
            assert!(err.contains("invalid value"), "{ports}: {err}");
        }
    }

    #[test]
    fn port_zero_rejected() {
        // Q(vii)=A: u16 gives the range; port 0 is a validation rule.
        let err = err_of(&draft_with(r#""ports": [443, 80]"#, r#""ports": [443, 0]"#));
        assert!(err.contains("network.ports[1]"), "{err}");
        assert!(err.contains("port 0"), "{err}");
    }

    #[test]
    fn port_bounds_and_empty_accepted() {
        let policy = policy_of(&draft_with(r#""ports": [443, 80]"#, r#""ports": [65535]"#));
        assert_eq!(policy.network.ports, [65535]);
        let policy = policy_of(&draft_with(r#""ports": [443, 80]"#, r#""ports": []"#));
        assert!(policy.network.ports.is_empty());
    }

    // ---- version -----------------------------------------------------------

    #[test]
    fn version_must_be_one() {
        // Q(vi)=A: runtime validation with an actionable message, exact text.
        for version in [0u32, 2, 99] {
            let json = draft_with(r#""version": 1,"#, &format!(r#""version": {version},"#));
            assert_eq!(
                err_of(&json),
                format!("unsupported policy version {version}; this sbx supports version 1")
            );
        }
    }

    #[test]
    fn version_type_errors() {
        let err = err_of(&draft_with(r#""version": 1,"#, r#""version": "1","#));
        assert!(err.contains("invalid type"), "{err}");
        let err = err_of(&draft_with(r#""version": 1,"#, r#""version": -1,"#));
        assert!(err.contains("invalid value"), "{err}");
    }

    // ---- timeout -----------------------------------------------------------

    #[test]
    fn timeout_valid_spellings() {
        let cases = [
            ("120s", Duration::from_secs(120)),
            ("2m", Duration::from_secs(120)),
            ("500ms", Duration::from_millis(500)),
            ("1h30m", Duration::from_secs(90 * 60)),
            ("7d", Duration::from_secs(7 * 24 * 3600)),
        ];
        for (text, expected) in cases {
            let json = draft_with(r#""timeout": "120s""#, &format!(r#""timeout": "{text}""#));
            assert_eq!(policy_of(&json).limits.timeout, expected, "{text:?}");
        }
    }

    #[test]
    fn timeout_zero_rejected() {
        for text in ["0s", "0", "0ms"] {
            let json = draft_with(r#""timeout": "120s""#, &format!(r#""timeout": "{text}""#));
            let err = err_of(&json);
            assert!(err.contains("greater than zero"), "{text:?}: {err}");
        }
    }

    #[test]
    fn timeout_garbage_rejected() {
        for text in ["abc", "", "-5s"] {
            let json = draft_with(r#""timeout": "120s""#, &format!(r#""timeout": "{text}""#));
            err_of(&json); // rejection is the assertion (err_of panics otherwise)
        }
        // A JSON number is the wrong type — the contract is a human-format
        // string (same grammar as the CLI's --timeout).
        let err = err_of(&draft_with(r#""timeout": "120s""#, r#""timeout": 120"#));
        assert!(err.contains("invalid type"), "{err}");
    }

    // ---- output_bytes --------------------------------------------------------

    #[test]
    fn output_bytes_rules() {
        let policy = policy_of(&draft_with(
            r#""output_bytes": 10485760"#,
            &format!(r#""output_bytes": {}"#, u64::MAX),
        ));
        assert_eq!(policy.limits.output_bytes, u64::MAX);
        // D9: 0 is legal and means "capture none" — the strictest valid
        // policy (examples/locked-down.json) relies on it.
        let policy = policy_of(&draft_with(
            r#""output_bytes": 10485760"#,
            r#""output_bytes": 0"#,
        ));
        assert_eq!(policy.limits.output_bytes, 0);
        for bad in ["-1", "1.5", "18446744073709551616"] {
            // 18446744073709551616 == 2^64, one past u64::MAX.
            let json = draft_with(
                r#""output_bytes": 10485760"#,
                &format!(r#""output_bytes": {bad}"#),
            );
            let err = err_of(&json);
            assert!(err.contains("invalid"), "{bad}: {err}");
        }
    }

    // ---- env -----------------------------------------------------------------

    #[test]
    fn env_names_posix_only() {
        // Q(viii)=A: ^[A-Za-z_][A-Za-z0-9_]*$ for names in pass AND set keys.
        for ok in ["LANG", "_X", "A1_B2"] {
            let json = draft_with(
                r#""pass": ["LANG"]"#,
                &format!(r#""pass": [{}]"#, json_str(ok)),
            );
            policy_of(&json);
            // `{{`/`}}` escape the JSON object braces for format!.
            let json = draft_with(
                r#""set": { "GIT_TERMINAL_PROMPT": "0" }"#,
                &format!(r#""set": {{ {}: "v" }}"#, json_str(ok)),
            );
            policy_of(&json);
        }
        for bad in ["1BAD", "A-B", "", "ÜNICODE"] {
            let json = draft_with(
                r#""pass": ["LANG"]"#,
                &format!(r#""pass": [{}]"#, json_str(bad)),
            );
            let err = err_of(&json);
            assert!(err.contains("env.pass[0]"), "{bad:?}: {err}");
            assert!(
                err.contains("is not a valid environment variable name"),
                "{bad:?}: {err}"
            );
            let json = draft_with(
                r#""set": { "GIT_TERMINAL_PROMPT": "0" }"#,
                &format!(r#""set": {{ {}: "v" }}"#, json_str(bad)),
            );
            let err = err_of(&json);
            assert!(err.contains("env.set key"), "{bad:?}: {err}");
            assert!(
                err.contains("is not a valid environment variable name"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn env_values_unrestricted() {
        // Only *names* are constrained; values are arbitrary strings (#6
        // passes them through bwrap --setenv).
        let json = draft_with(
            r#""set": { "GIT_TERMINAL_PROMPT": "0" }"#,
            r#""set": { "WEIRD": "any value: spaces, ünïcode, 1BAD, ''" }"#,
        );
        let policy = policy_of(&json);
        assert_eq!(
            policy.env.set["WEIRD"],
            "any value: spaces, ünïcode, 1BAD, ''"
        );
    }

    #[test]
    fn env_set_keys_are_sorted() {
        // BTreeMap: deterministic ordering regardless of file order —
        // serialization and #6's argv assembly are stable.
        let json = draft_with(
            r#""set": { "GIT_TERMINAL_PROMPT": "0" }"#,
            r#""set": { "Z": "1", "A": "2", "M": "3" }"#,
        );
        let policy = policy_of(&json);
        let keys: Vec<&String> = policy.env.set.keys().collect();
        assert_eq!(keys, ["A", "M", "Z"]);
    }

    #[test]
    fn duplicate_env_set_keys_rejected() {
        // Plain BTreeMap deserialization would silently keep only the last
        // duplicate (last-win), dropping an assignment from a hand-edited
        // security policy; env.set rejects repeats instead, with serde's
        // line/column context.
        let json = draft_with(
            r#""set": { "GIT_TERMINAL_PROMPT": "0" }"#,
            r#""set": { "A": "1", "A": "2" }"#,
        );
        let err = err_of(&json);
        assert!(err.contains("duplicate key"), "{err}");
        assert!(err.contains(r#""A""#), "{err}");
        assert!(err.contains("env.set"), "{err}");
        assert!(err.contains("line"), "{err}"); // serde position context
    }

    // ---- network mode --------------------------------------------------------

    #[test]
    fn network_mode_spellings() {
        let cases = [
            ("transparent", NetworkMode::Transparent),
            ("explicit", NetworkMode::Explicit),
            ("none", NetworkMode::None),
        ];
        for (text, expected) in cases {
            let json = draft_with(r#""mode": "transparent""#, &format!(r#""mode": "{text}""#));
            assert_eq!(policy_of(&json).network.mode, expected, "{text:?}");
        }
        for bad in ["Transparent", "TRANSPARENT", "proxy", "off", ""] {
            let json = draft_with(r#""mode": "transparent""#, &format!(r#""mode": "{bad}""#));
            let err = err_of(&json);
            assert!(err.contains("unknown variant"), "{bad:?}: {err}");
        }
    }

    // ---- JSON Schema -----------------------------------------------------------

    #[test]
    fn schema_is_draft_2020_12_json() {
        let json = schema_json();
        let schema: serde_json::Value = serde_json::from_str(&json).expect("schema must be JSON");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }

    #[test]
    fn schema_pins_structure() {
        // Structural assertions, no golden file (D10): pin every
        // contract-relevant keyword; byte-determinism has its own test.
        let json = schema_json();
        let schema: serde_json::Value = serde_json::from_str(&json).expect("schema must be JSON");
        let defs = schema["$defs"].as_object().expect("$defs");

        // Root: object, all five fields required in declaration order,
        // author-facing description present.
        assert_eq!(schema["type"], "object");
        assert_eq!(
            schema["required"],
            serde_json::json!(["version", "filesystem", "network", "env", "limits"])
        );
        assert!(
            schema["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "root description must be non-empty"
        );

        // deny_unknown_fields on Policy + all four sections: exactly five.
        assert_eq!(
            json.matches(r#""additionalProperties": false"#).count(),
            5,
            "additionalProperties:false must appear on the root + 4 sections"
        );
        for name in ["Filesystem", "Network", "Env", "Limits"] {
            assert_eq!(
                defs[name]["additionalProperties"],
                serde_json::json!(false),
                "{name}"
            );
        }

        // Section required arrays in field-declaration order.
        for (name, required) in [
            ("Filesystem", serde_json::json!(["ro", "rw", "deny"])),
            ("Network", serde_json::json!(["mode", "allow", "ports"])),
            ("Env", serde_json::json!(["pass", "set"])),
            ("Limits", serde_json::json!(["timeout", "output_bytes"])),
        ] {
            assert_eq!(defs[name]["required"], required, "{name}");
        }

        // Validated newtypes: named $defs with their manual schemas.
        assert_eq!(defs["AbsolutePath"]["type"], "string");
        assert_eq!(defs["AbsolutePath"]["pattern"], "^/([^/]+/)*[^/]+$");
        assert_eq!(defs["Domain"]["type"], "string");
        assert_eq!(defs["Domain"]["format"], "hostname");

        // u16 ports: range lands in the schema for free.
        let ports = &defs["Network"]["properties"]["ports"]["items"];
        assert_eq!(ports["type"], "integer");
        assert_eq!(ports["format"], "uint16");
        assert_eq!(ports["minimum"], serde_json::json!(0));
        assert_eq!(ports["maximum"], serde_json::json!(65535));

        // NetworkMode: oneOf string consts with the exact lowercase spellings.
        let consts: Vec<&str> = defs["NetworkMode"]["oneOf"]
            .as_array()
            .expect("NetworkMode oneOf")
            .iter()
            .map(|variant| variant["const"].as_str().expect("const string"))
            .collect();
        assert_eq!(consts, ["transparent", "explicit", "none"]);

        // Version: loose integer (runtime enforces == 1, Q(vi)=A).
        assert_eq!(schema["properties"]["version"]["type"], "integer");

        // Timeout: human-format string, not an integer — with the extend
        // keywords pinned.
        let timeout = &defs["Limits"]["properties"]["timeout"];
        assert_eq!(timeout["type"], "string");
        assert_eq!(timeout["format"], "duration-string");
        assert_eq!(timeout["examples"], serde_json::json!(["120s"]));
    }

    #[test]
    fn schema_generation_is_deterministic() {
        assert_eq!(schema_json(), schema_json());
    }

    #[test]
    fn schema_has_no_session_dir_field() {
        // Issue rule: the session directory never comes from the policy, so
        // no object in the schema may grow such a field.
        let schema: serde_json::Value =
            serde_json::from_str(&schema_json()).expect("schema must be JSON");
        let objects =
            std::iter::once(&schema).chain(schema["$defs"].as_object().expect("$defs").values());
        for object in objects {
            if let Some(properties) = object["properties"].as_object() {
                for key in properties.keys() {
                    assert!(
                        !key.contains("session"),
                        "schema must have no session-directory field (got {key:?})"
                    );
                }
            }
        }
    }

    // ---- validation entry points ------------------------------------------

    #[test]
    fn direct_deserialization_skips_policy_wide_rules() {
        // Pins the module-doc point-5 asymmetry: raw serde_json
        // deserialization enforces only the value-level rules baked into the
        // types; version/port-0/env-name checks run in validate(), which
        // only from_json_str/from_file call. Future consumers (#6, #10)
        // must load policies through those entry points. If this test ever
        // fails, the asymmetry changed (e.g. the TODO(#6) type-level
        // invariant landed): update the module docs, this test, and the
        // handoff notes in the same change.
        for json in [
            draft_with(r#""version": 1,"#, r#""version": 2,"#),
            draft_with(r#""ports": [443, 80]"#, r#""ports": [443, 0]"#),
            draft_with(r#""pass": ["LANG"]"#, r#""pass": ["1BAD"]"#),
        ] {
            serde_json::from_str::<Policy>(&json)
                .expect("raw deserialization must skip validate()");
            err_of(&json); // the same text IS rejected via from_json_str
        }
    }

    // ---- files -----------------------------------------------------------------

    #[test]
    fn from_file_reports_unreadable() {
        let err = Policy::from_file(Path::new("/nonexistent/sbx-test-dir/policy.json"))
            .expect_err("a missing file must be an error")
            .to_string();
        assert!(err.contains("cannot read"), "{err}");
    }

    #[test]
    fn from_file_reports_non_utf8() {
        // "cannot read" means an I/O failure; a byte-level decode failure
        // gets its own accurate message (both stay rc 1 via `sbx check`).
        let dir = std::env::temp_dir().join(format!("sbx-policy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir must be creatable");
        let path = dir.join("invalid-utf8.json");
        std::fs::write(&path, b"{ \"version\": 1, \xff\xfe }").expect("temp file must be writable");
        let err = Policy::from_file(&path)
            .expect_err("non-UTF-8 must be rejected")
            .to_string();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(err.contains("not valid UTF-8"), "{err}");
        assert!(err.contains("invalid-utf8.json"), "{err}");
        assert!(!err.contains("cannot read"), "{err}");
    }
}
