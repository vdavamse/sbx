//! The transparent egress proxy — TLS passthrough with an SNI check,
//! served on the listener fd `sbx __init` hands to the parent (issue #7).
//!
//! 1. **Contract** — [`serve`] takes [`crate::init::fdpass::ListenerFds`]'s
//!    `transparent` socket (blocking + CLOEXEC), flips it non-blocking
//!    ITSELF (the fdpass contract — a missing flip would block the whole
//!    single-threaded runtime inside `accept(2)`: deadlock, not error), and
//!    serves it until the fd provably dies or the caller shuts the listener
//!    down. Per connection: `SO_ORIGINAL_DST` recovers the fake IP the
//!    sandbox dialed, the [`DnsMap`] seam (#9) maps it back to a name, the
//!    port + name must pass the policy, the protocol preamble is inspected
//!    WITHOUT termination (443 → TLS ClientHello SNI via rustls's
//!    `Acceptor`, never a completed handshake; 80 → httparse request line +
//!    `Host`), the name is resolved and dialed under
//!    [`crate::egress::guard`], the buffered bytes are replayed, and the
//!    connection is relayed with `copy_bidirectional`. Every connection ends
//!    in exactly ONE [`Decision`] recorded to the [`DecisionSink`] seam
//!    (#10) BEFORE any relay byte flows.
//! 2. **Pipeline order is load-bearing** — port → DNS map → allow list →
//!    protocol inspection → connect. The map lookup runs BEFORE any guard
//!    call and the fake IP is NEVER guarded: production fakes live in
//!    198.18.0.0/15 and test fakes in TEST-NET-3, both guard-denied BY
//!    DESIGN (egress.rs module docs point 7) — guarding the original
//!    destination would deny everything. The ordering canary is
//!    `map_lookup_precedes_guard_ordering`; the host-netns test tier is a
//!    second canary (its orig-dst is 127.0.0.1, Loopback-denied if the
//!    order ever flips).
//! 3. **Three seams** — [`DnsMap`] (#9 plugs in the run's live fake-IP
//!    allocation map), [`DecisionSink`] (#10 plugs in the JSONL audit log),
//!    and [`serve`] itself (#10 spawns it as a task BEFORE the go byte —
//!    the fdpass go guarantee — and tears down via task abort or listener
//!    shutdown). Both trait seams run on the single runtime thread: they
//!    must be sync, cheap, non-blocking, and must not panic (a panicking
//!    sink aborts that connection task with the decision unrecorded).
//! 4. **Fail-closed everywhere** — every path that is not an explicit
//!    allow denies: `SO_ORIGINAL_DST` failure (no verifiable destination ⇒
//!    no traffic), unknown fake IP, unlisted port, unlisted name, a
//!    policy-listed port with no v1 inspector (Q1), byte caps, timeouts,
//!    malformed or adversarial preambles, ECH offers (Q4's GREASE-ECH
//!    trade-off accepted), a guard failure on ANY resolved address (the
//!    first failure denies the whole connection), and a guard failure on
//!    the connected `peer_addr()` — the DNS-rebinding backstop; the dial is
//!    BY NAME, never the client-chosen IP. Deny-side TLS alerts are
//!    DROPPED, never written back (Q2 — an alert would leak policy
//!    internals into the sandbox).
//! 5. **Single-site vocabulary** — [`Rejected::reason`] and
//!    [`Failed::reason`] are the ONLY build sites of the pinned deny/error
//!    text (exhaustive matches, so a new variant without a pinned message
//!    fails to compile; #10 logs [`Decision::reason`] verbatim). The
//!    denied-vs-error split (Q6): adversarial input and policy predicates
//!    are [`Verdict::Denied`]; infrastructure failures against an
//!    already-allowed name (resolve, refused connect, connect timeout) are
//!    [`Verdict::Error`] — keeping #10's JSONL semantics clean.
//! 6. **Caps and timeouts** — 32 KiB ClientHello, 16 KiB HTTP head, 64
//!    headers, a 10 s decision phase (accept → protocol verdict; elapsed ⇒
//!    the inspection future is dropped mid-read and the buffered bytes are
//!    discarded — fail-closed), a 10 s connect phase (resolve + dial, owned
//!    by [`GuardedConnector`]), and a 1 ms→100 ms bounded accept backoff.
//!    The two timeout scopes never nest, so the pinned reasons never
//!    compete. No relay idle timeout and no concurrency cap in v1 (Q7 —
//!    revisit with #10 via [`Limits`]).
//! 7. **v1 limitations (deliberate)** — only 443/80 have inspectors; any
//!    other policy-listed port denies because unverifiable-name traffic
//!    must not pass (Q1). TLS is PASSED THROUGH, never terminated (no CA in
//!    the sandbox): `Accepted::into_connection` is NEVER called — which is
//!    why rustls ships with NO crypto provider (the Acceptor parse path
//!    needs none, and the aarch64 static-musl leg requires a pure-Rust
//!    tree). ECH is denied outright, GREASE-ECH false positives accepted
//!    (Q4 — sandbox clients are CLI tools; user docs land with #10).
//!    IPv4-only by construction (#5: IPv6 disabled, 127.0.0.1 listeners,
//!    AF_INET nft — an AF_INET6 `SO_ORIGINAL_DST` answer is denied).
//! 8. **Runtime model** — one current-thread runtime with the IO and time
//!    drivers enabled (#10 hosts it). `tokio::spawn` requires `Send` even
//!    on a current-thread runtime, so every seam is
//!    `Arc<dyn … + Send + Sync>` and [`Upstream`] carries `Send`.
//!    [`GuardedConnector::system`] resolves via `tokio::net::lookup_host`
//!    (getaddrinfo on the blocking pool — legal and non-starving on a
//!    single-threaded runtime). Static-musl resolution reads the HOST's
//!    `/etc/resolv.conf`/`/etc/hosts` at call time, which is correct: the
//!    parent runs in the host netns and the sandbox itself never resolves
//!    (#9's fake-IP design). musl returns A+AAAA; `egress::guard` covers
//!    the IPv6 special-purpose tables identically.
//! 9. **Replay correctness** — the socket is read into a scratch chunk
//!    which is appended to the replay buffer FIRST; rustls only ever sees a
//!    COPY of exactly the newly-read bytes (Cursor-fed), never a byte
//!    twice, and the acceptor is dropped after inspection. Post-ClientHello
//!    pipelined bytes the acceptor internally buffers therefore survive in
//!    the replay buffer (`inspect_tls_replays_pipelined_bytes` pins it),
//!    and the upstream sees the client's byte stream verbatim.
//! 10. **Accept-loop resilience** — proxy death = sandbox death (fdpass),
//!     so transient accept errors (EMFILE/ENFILE/ECONNABORTED/ENOBUFS/
//!     ENOMEM …) get bounded exponential backoff and NEVER an exit; only a
//!     provably dead fd (EBADF/EINVAL/ENOTSOCK) exits [`serve`] — and
//!     EINVAL-on-shutdown is exactly the deliberate teardown signal (#10 /
//!     the integration suite). EINTR is retried inside tokio. The loop
//!     never panics.
//! 11. **Test tiers** — the unit tests below drive the full pipeline over
//!     `tokio::io::duplex` with scripted seams (no sockets, shrunk
//!     [`Limits`] keep timeout tests at ~50 ms); the `Gate::OrigDst`
//!     host-netns tier exploits the F8 own-address fallback
//!     (`SO_ORIGINAL_DST` on a non-NATed connection returns its own
//!     destination) on ephemeral 127.0.0.1 listeners; the `Gate::Userns`
//!     tier in `tests/sandbox_proxy.rs` runs the real chain — `sbx __init`
//!     netns + nft REDIRECT + fd hand-off + [`serve`] + payload roles
//!     dialing TEST-NET-3.

pub mod hello;
pub(crate) mod http;

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use crate::egress;
use crate::init::consts;
use crate::policy::{self, Domain};

/// The ports with a v1 protocol inspector (module docs point 7): 443 is
/// inspected as TLS ([`hello`]), 80 as HTTP/1 ([`http`]). Any other
/// policy-listed port denies with [`Rejected::NoInspector`] (Q1).
const TLS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

/// The initial accept-backoff delay (doubles to
/// [`Limits::accept_backoff_max`], resets on every successful accept).
const ACCEPT_BACKOFF_START: Duration = Duration::from_millis(1);

/// Caps and timeouts bounding every pre-relay path (module docs point 6).
///
/// The [`Default`] values are the pinned v1 contract; the struct is a
/// [`Proxy`] field so tests shrink the timeouts/caps and #10 can tune them.
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// Byte cap on the buffered TLS ClientHello (including any pipelined
    /// bytes read alongside it) — a truncated hello can never grow the
    /// buffer past this. Ordering note (deliberate, m4): the hello cap is
    /// checked after EVERY append and BEFORE feeding the acceptor —
    /// strict: a completing chunk that crosses the cap denies even though
    /// the hello inside is valid, because a truncated hello can otherwise
    /// park the acceptor in `Ok(None)` forever. [`Self::max_head_bytes`]
    /// is the lenient twin (a complete head beats its cap check); do NOT
    /// "harmonize" the two without re-pinning
    /// `inspect_tls_hello_cap_boundary_pinned` /
    /// `inspect_http_cap_boundary_pinned`.
    pub max_hello_bytes: usize,
    /// Byte cap on the buffered HTTP request head. It bounds the SEARCH
    /// for `\r\n\r\n` only — firing on a strict overrun while the
    /// terminator is still unseen (worst-case buffering: cap + one read
    /// chunk) — and an already-complete head in the buffer wins over the
    /// cap check (lenient; the strict twin and rationale:
    /// [`Self::max_hello_bytes`]).
    pub max_head_bytes: usize,
    /// httparse header-array size; exceeding it yields `TooHeaders` ⇒
    /// [`Rejected::HttpMalformed`] (fail-closed, never a silent drop).
    pub max_http_headers: usize,
    /// Accept → protocol verdict. Elapsed ⇒ [`Rejected::DecisionTimeout`]:
    /// the inspection future is dropped mid-read and the buffered bytes are
    /// discarded (fail-closed).
    pub decision_timeout: Duration,
    /// Resolve + dial budget, owned by [`GuardedConnector`].
    pub connect_timeout: Duration,
    /// Upper bound of the transient-accept-error backoff (1 ms doubling).
    pub accept_backoff_max: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_hello_bytes: 32 * 1024,
            max_head_bytes: 16 * 1024,
            max_http_headers: 64,
            decision_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            accept_backoff_max: Duration::from_millis(100),
        }
    }
}

/// The terminal outcome of one connection's decision pipeline.
///
/// Exactly one per connection, recorded to the [`DecisionSink`] BEFORE any
/// relay byte flows. The denied/error split is Q6 (module docs point 5).
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The name passed every check and the upstream connected: `upstream`
    /// is the guarded `peer_addr` actually connected.
    Allowed { name: Domain, upstream: SocketAddr },
    /// A policy, protocol, or adversarial-input failure — fail-closed.
    Denied(Rejected),
    /// An infrastructure failure against an ALLOWED name (Q6).
    Error(Failed),
}

impl Verdict {
    /// The audit-log label — #10's JSONL `verdict` field.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Allowed { .. } => "allowed",
            Verdict::Denied(_) => "denied",
            Verdict::Error(_) => "error",
        }
    }
}

/// Why a connection was denied — the pinned deny taxonomy.
///
/// Every variant's user-visible text is built in exactly ONE place
/// ([`Rejected::reason`], house rule); `rejected_reasons_pinned` asserts
/// every row byte-exact (the #10 contract).
#[derive(Debug, Clone, PartialEq)]
pub enum Rejected {
    /// `getsockopt(SO_ORIGINAL_DST)` failed, truncated, or answered a
    /// non-AF_INET family: no verifiable destination ⇒ no traffic.
    OriginalDst { detail: String },
    /// The original destination port is not in `network.ports`.
    PortNotAllowed { port: u16 },
    /// The port IS policy-listed but has no v1 inspector (Q1) — neither
    /// 443 nor 80.
    NoInspector { port: u16 },
    /// The fake IP has no [`DnsMap`] entry (#9's run map is the authority).
    UnknownFakeIp { ip: Ipv4Addr },
    /// The mapped name failed [`crate::egress::allowed`].
    NotAllowed { name: Domain },
    /// The first byte on 443 was not a TLS handshake record (0x16).
    NotTls { first_byte: u8 },
    /// The buffered ClientHello outgrew [`Limits::max_hello_bytes`].
    HelloTooLarge { cap: usize },
    /// rustls rejected the ClientHello; the `AcceptedAlert` is DROPPED
    /// (Q2 — never written back).
    HelloMalformed { detail: String },
    /// The 0xfe0d walker found an `encrypted_client_hello` extension
    /// (GREASE-ECH included — Q4).
    EchOffered,
    /// rustls saw no SNI (absent OR an IP literal — indistinguishable), or
    /// the SNI failed canonicalization.
    SniMissing,
    /// The canonicalized SNI differs from the DNS-map name.
    SniMismatch { sni: Domain, name: Domain },
    /// The buffered HTTP head outgrew [`Limits::max_head_bytes`].
    HeadTooLarge { cap: usize },
    /// httparse rejected the request (detail = its error text;
    /// `TooHeaders` lands here too — fail-closed).
    HttpMalformed { detail: String },
    /// The HTTP/2 connection preface (`PRI * HTTP/2.0`) on port 80 —
    /// denied AS the malformed family (Phase 1 lock).
    Http2Preface,
    /// CONNECT belongs to the explicit proxy (#8), never the transparent
    /// port.
    ConnectMethod,
    /// The request has no `Host` header (HTTP/0.9 included — no Host ⇒
    /// unverifiable ⇒ fail-closed).
    HostMissing,
    /// The request has more than one `Host` header.
    HostMultiple,
    /// The `Host` value is not valid UTF-8 — NEVER `from_utf8_lossy`
    /// (egress.rs point 5: a lossy conversion could *create* a match).
    HostNotUtf8,
    /// The `Host` port suffix exists but differs from the original
    /// destination port (Q5).
    HostPortMismatch { got: u16, want: u16 },
    /// The (port-stripped) `Host` value is not a bare hostname
    /// ([`Domain::parse`] rejected it: scheme, userinfo, brackets, IP
    /// literal, junk).
    HostInvalid { value: String },
    /// The canonicalized `Host` differs from the DNS-map name.
    HostMismatch { host: Domain, name: Domain },
    /// The absolute-form request-target's authority differs from the
    /// DNS-map name (or carries a foreign port/scheme shape).
    TargetMismatch { target: String, name: Domain },
    /// [`crate::egress::guard`] denied a resolved address or the connected
    /// peer: composition per egress.rs — `denied dial to {addr}: {denied}`
    /// (Q3: `{addr}` is the SocketAddr).
    DialDenied {
        addr: SocketAddr,
        denied: egress::Denied,
    },
    /// The client closed (or the transport failed) before a complete
    /// preamble.
    Eof,
    /// No complete preamble within [`Limits::decision_timeout`].
    DecisionTimeout { secs: u64 },
}

impl Rejected {
    /// The pinned reason text — THE single exhaustive-match build site
    /// (house rule; #10 logs it verbatim via [`Decision::reason`]).
    pub fn reason(&self) -> String {
        match self {
            Rejected::OriginalDst { detail } => {
                format!("SO_ORIGINAL_DST lookup failed: {detail}")
            }
            Rejected::PortNotAllowed { port } => {
                format!("port {port} is not in the policy port list")
            }
            Rejected::NoInspector { port } => {
                format!("no protocol inspector for port {port} in v1")
            }
            Rejected::UnknownFakeIp { ip } => {
                format!("unknown fake IP {ip} (no DNS-map entry)")
            }
            Rejected::NotAllowed { name } => {
                format!("{} is not in the policy allow list", name.as_str())
            }
            Rejected::NotTls { first_byte } => {
                format!("non-TLS traffic on port 443 (first byte {first_byte:#04x})")
            }
            Rejected::HelloTooLarge { cap } => {
                format!("TLS ClientHello exceeds the {cap}-byte cap")
            }
            Rejected::HelloMalformed { detail } => {
                format!("malformed TLS ClientHello: {detail}")
            }
            Rejected::EchOffered => {
                "TLS ClientHello offers encrypted_client_hello (ECH); denied in v1".to_owned()
            }
            Rejected::SniMissing => "missing or invalid SNI in the TLS ClientHello".to_owned(),
            Rejected::SniMismatch { sni, name } => format!(
                "SNI {} does not match the DNS-map name {}",
                sni.as_str(),
                name.as_str()
            ),
            Rejected::HeadTooLarge { cap } => {
                format!("HTTP request head exceeds the {cap}-byte cap")
            }
            Rejected::HttpMalformed { detail } => format!("malformed HTTP request: {detail}"),
            Rejected::Http2Preface => {
                "malformed HTTP request: HTTP/2 connection preface on port 80".to_owned()
            }
            Rejected::ConnectMethod => {
                "CONNECT is served on the explicit proxy port only (issue #8)".to_owned()
            }
            Rejected::HostMissing => "HTTP request has no Host header".to_owned(),
            Rejected::HostMultiple => "HTTP request has multiple Host headers".to_owned(),
            Rejected::HostNotUtf8 => "Host header is not valid UTF-8".to_owned(),
            Rejected::HostPortMismatch { got, want } => format!(
                "Host port suffix :{got} does not match the original destination port {want}"
            ),
            Rejected::HostInvalid { value } => {
                format!("Host header {value:?} is not a bare hostname")
            }
            Rejected::HostMismatch { host, name } => format!(
                "HTTP Host {} does not match the DNS-map name {}",
                host.as_str(),
                name.as_str()
            ),
            Rejected::TargetMismatch { target, name } => format!(
                "absolute-form request target {target:?} does not match the DNS-map name {}",
                name.as_str()
            ),
            Rejected::DialDenied { addr, denied } => format!("denied dial to {addr}: {denied}"),
            Rejected::Eof => "connection closed before a complete protocol preamble".to_owned(),
            Rejected::DecisionTimeout { secs } => {
                format!("decision-phase timeout: no complete protocol preamble within {secs}s")
            }
        }
    }
}

/// Why an allowed connection failed for infrastructure reasons (Q6) —
/// logged, but NOT a policy denial.
#[derive(Debug, Clone, PartialEq)]
pub enum Failed {
    /// Resolution errored (NXDOMAIN, SERVFAIL, transport …).
    Resolve { name: Domain, detail: String },
    /// Resolution returned zero addresses.
    EmptyResolve { name: Domain },
    /// The dial failed (refused, unreachable, …).
    Connect { name: Domain, detail: String },
    /// Resolve + dial together outgrew the connect timeout. The bound is
    /// owned by the [`Connector`] implementation (the trait's boundedness
    /// contract requires [`Limits::connect_timeout`] to equal it); `secs`
    /// is that limit, reported verbatim by [`decide`]'s single mapping
    /// site.
    ConnectTimeout { name: Domain, secs: u64 },
}

impl Failed {
    /// The pinned reason text — the second (and last) build site.
    pub fn reason(&self) -> String {
        match self {
            Failed::Resolve { name, detail } => {
                format!("DNS resolution failed for {}: {detail}", name.as_str())
            }
            Failed::EmptyResolve { name } => {
                format!("DNS resolution returned no addresses for {}", name.as_str())
            }
            Failed::Connect { name, detail } => {
                format!("connect to {} failed: {detail}", name.as_str())
            }
            Failed::ConnectTimeout { name, secs } => {
                format!("connect to {} timed out after {secs}s", name.as_str())
            }
        }
    }
}

/// One connection's terminal audit record — #10's JSONL row.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// The accepted sandbox-side peer.
    pub client: SocketAddr,
    /// The `SO_ORIGINAL_DST` result; `None` iff the lookup itself failed.
    pub orig_dst: Option<SocketAddrV4>,
    /// The DNS-map result; `None` for pre-map denials.
    pub name: Option<Domain>,
    /// The terminal outcome.
    pub verdict: Verdict,
}

impl Decision {
    /// THE audit-text composition site — #10 logs this verbatim.
    pub fn reason(&self) -> String {
        match &self.verdict {
            Verdict::Allowed { name, upstream } => {
                format!("allowed {} via {upstream}", name.as_str())
            }
            Verdict::Denied(rejected) => rejected.reason(),
            Verdict::Error(failed) => failed.reason(),
        }
    }
}

/// Seam (a): fake IP → canonical policy name. #9 plugs in the run's live
/// allocation map.
pub trait DnsMap: Send + Sync + 'static {
    /// Fake IP → canonical policy name. SYNC + CHEAP + NON-BLOCKING (called
    /// on the runtime thread); `None` = unknown fake IP ⇒ deny. #9: back
    /// with the run's live allocation map; production keys are always
    /// 198.18.0.0/15 (unspoofable-by-design interplay with
    /// [`egress::Denied::Benchmarking`], egress.rs point 7).
    fn name_for(&self, ip: Ipv4Addr) -> Option<Domain>;
}

/// Seam (b): the audit sink. #10 plugs in the JSONL log.
pub trait DecisionSink: Send + Sync + 'static {
    /// Exactly one call per connection, at its terminal decision point,
    /// BEFORE any relay bytes flow (Allowed) or the socket is dropped
    /// (Denied/Error). SYNC + CHEAP + NON-BLOCKING + must-not-panic (a
    /// panic aborts the connection task with the decision unrecorded). #10:
    /// buffer JSONL, flush best-effort.
    fn record(&self, decision: &Decision);
}

/// A bidirectional byte stream usable as an upstream (relay endpoint).
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug> ByteStream for T {}

/// The boxed upstream stream. `Box<T: AsyncRead + ?Sized>`'s blanket impls
/// make `copy_bidirectional` work through the box.
pub type Upstream = Box<dyn ByteStream>;

/// A connected, guard-rechecked upstream.
#[derive(Debug)]
pub struct Connected {
    /// The upstream byte stream.
    pub stream: Upstream,
    /// The connected peer — already re-checked against [`egress::guard`]
    /// by [`GuardedConnector`] (the rebinding backstop).
    pub peer: SocketAddr,
}

/// Upstream plumbing failures — mapped to [`Verdict`]s at exactly one site
/// in [`decide`] (Q6 split: only `DialDenied` is a policy denial).
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectError {
    /// A resolved address or the connected peer failed [`egress::guard`].
    DialDenied {
        addr: SocketAddr,
        denied: egress::Denied,
    },
    /// Resolution errored.
    Resolve { detail: String },
    /// Resolution returned zero addresses.
    EmptyResolve,
    /// The dial failed.
    Connect { detail: String },
    /// Resolve or dial outgrew the connect timeout.
    Timeout,
}

/// Injectable resolution (see [`GuardedConnector::new`]). The returned
/// future must be `Send` and `'static` — the name is copied in, never
/// borrowed.
// The hand-rolled boxed-future shape (no async-trait dep) trips
// clippy::type_complexity; the alias name IS the documentation.
#[allow(clippy::type_complexity)]
pub type ResolveFn = Arc<
    dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>
        + Send
        + Sync,
>;

/// Injectable dial (see [`GuardedConnector::new`]). Same `Send` +
/// `'static` contract as [`ResolveFn`]; the future yields the stream and
/// its connected `peer_addr`.
#[allow(clippy::type_complexity)]
pub type DialFn = Arc<
    dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = io::Result<(Upstream, SocketAddr)>> + Send>>
        + Send
        + Sync,
>;

/// Seam (c-adjacent): dial `name:port` with every address guard applied.
///
/// Boundedness contract (m2): implementations MUST bound `connect()`
/// internally — a hung dial would wedge the connection task with no audit
/// line ever recorded — and [`Limits::connect_timeout`] must equal that
/// bound: [`decide`] applies no nested timeout of its own (module docs
/// point 6's non-nesting rule) and reports the limit verbatim as
/// [`Failed::ConnectTimeout`]'s `secs`. [`GuardedConnector`] owns the
/// bound (one timeout around the resolve, one around the dial).
pub trait Connector: Send + Sync + 'static {
    /// Hand-rolled boxed future (no async-trait dep). The future MUST be
    /// `Send` (tokio::spawn on any runtime).
    fn connect(
        &self,
        name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>>;
}

/// The production [`Connector`]: resolve → guard EVERY address → dial BY
/// NAME → re-guard the connected `peer_addr` (module docs points 2/4;
/// egress.rs point 6 sanctions exactly this pattern).
pub struct GuardedConnector {
    resolve: ResolveFn,
    dial: DialFn,
    connect_timeout: Duration,
}

impl GuardedConnector {
    /// Production shape for #10: `resolve` = [`tokio::net::lookup_host`]
    /// (getaddrinfo on the blocking pool — fine on a single-threaded
    /// runtime), `dial` = `TcpStream::connect((name, port))` BY NAME +
    /// `set_nodelay(true)` + `peer_addr()`.
    pub fn system(connect_timeout: Duration) -> Self {
        let resolve: ResolveFn = Arc::new(|name: &str, port: u16| {
            let name = name.to_owned();
            Box::pin(async move {
                tokio::net::lookup_host((name.as_str(), port))
                    .await
                    .map(|addrs| addrs.collect())
            })
        });
        let dial: DialFn = Arc::new(|name: &str, port: u16| {
            let name = name.to_owned();
            Box::pin(async move {
                // Dial BY NAME — never the client-chosen IP (egress.rs
                // point 6). A second getaddrinfo inside this call can
                // return different addresses than the guarded resolution
                // above: the peer_addr recheck in `inner` is the backstop.
                let stream = TcpStream::connect((name.as_str(), port)).await?;
                // Proxy-standard; a failure is not worth denying an
                // otherwise guarded connection (same policy as the
                // client-side flip in handle_connection).
                let _ = stream.set_nodelay(true);
                let peer = stream.peer_addr()?;
                Ok((Box::new(stream) as Upstream, peer))
            })
        });
        Self {
            resolve,
            dial,
            connect_timeout,
        }
    }

    /// Injectable fakes (unit tests + integration suite): hermetic
    /// resolve/dial with the SAME guard discipline around them.
    pub fn new(resolve: ResolveFn, dial: DialFn, connect_timeout: Duration) -> Self {
        Self {
            resolve,
            dial,
            connect_timeout,
        }
    }

    // The guarded flow (the single ConnectError→Verdict mapping site lives
    // in decide(), NOT here):
    //   1. resolve, bounded          → Err ⇒ Timeout / Resolve
    //   2. empty answer              ⇒ EmptyResolve
    //   3. guard EVERY resolved addr ⇒ DialDenied (first failure denies
    //      the WHOLE connection)
    //   4. dial by name, bounded     → Err ⇒ Timeout / Connect
    //   5. guard(peer_addr)          ⇒ DialDenied (rebinding backstop,
    //      BEFORE any byte is forwarded)
    async fn inner(&self, name: Domain, port: u16) -> Result<Connected, ConnectError> {
        let addrs =
            match tokio::time::timeout(self.connect_timeout, (self.resolve)(name.as_str(), port))
                .await
            {
                Ok(Ok(addrs)) => addrs,
                Ok(Err(err)) => {
                    return Err(ConnectError::Resolve {
                        detail: err.to_string(),
                    });
                }
                Err(_elapsed) => return Err(ConnectError::Timeout),
            };
        if addrs.is_empty() {
            return Err(ConnectError::EmptyResolve);
        }
        for addr in &addrs {
            if let Err(denied) = egress::guard(addr.ip()) {
                return Err(ConnectError::DialDenied {
                    addr: *addr,
                    denied,
                });
            }
        }
        let (stream, peer) = match tokio::time::timeout(
            self.connect_timeout,
            (self.dial)(name.as_str(), port),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                return Err(ConnectError::Connect {
                    detail: err.to_string(),
                });
            }
            Err(_elapsed) => return Err(ConnectError::Timeout),
        };
        if let Err(denied) = egress::guard(peer.ip()) {
            return Err(ConnectError::DialDenied { addr: peer, denied });
        }
        Ok(Connected { stream, peer })
    }
}

impl Connector for GuardedConnector {
    fn connect(
        &self,
        name: &Domain,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
        Box::pin(self.inner(name.clone(), port))
    }
}

/// The shared per-connection state bundle — one `Arc<Proxy>` across every
/// spawned connection task.
pub struct Proxy {
    /// Cloned from `policy.network.allow`.
    pub allow: Vec<Domain>,
    /// Cloned from `policy.network.ports`.
    pub ports: Vec<u16>,
    /// Seam (a) — #9 plugs in.
    pub dns_map: Arc<dyn DnsMap>,
    /// Seam (b) — #10 plugs in.
    pub sink: Arc<dyn DecisionSink>,
    /// Upstream dialer (production: [`GuardedConnector::system`]).
    pub connector: Arc<dyn Connector>,
    /// Caps + timeouts (module docs point 6).
    pub limits: Limits,
}

impl Proxy {
    /// Production shape for #10: [`GuardedConnector::system`] with default
    /// limits, built from a validated policy's network section.
    pub fn system(
        network: &policy::Network,
        dns_map: Arc<dyn DnsMap>,
        sink: Arc<dyn DecisionSink>,
    ) -> Arc<Self> {
        let limits = Limits::default();
        let connector = Arc::new(GuardedConnector::system(limits.connect_timeout));
        Self::new(network, dns_map, sink, connector, limits)
    }

    /// Full control (tests, #10 tuning).
    pub fn new(
        network: &policy::Network,
        dns_map: Arc<dyn DnsMap>,
        sink: Arc<dyn DecisionSink>,
        connector: Arc<dyn Connector>,
        limits: Limits,
    ) -> Arc<Self> {
        Arc::new(Self {
            allow: network.allow.clone(),
            ports: network.ports.clone(),
            dns_map,
            sink,
            connector,
            limits,
        })
    }
}

/// Seam (c): the serve entry point #10 spawns BEFORE the go byte.
///
/// Takes the BLOCKING std listener from `fdpass::ListenerFds::transparent`
/// and flips `set_nonblocking(true)` ITSELF (the fdpass contract) before
/// `TcpListener::from_std`. Returns `Err` ONLY on startup
/// (set_nonblocking/from_std) or a dead listener fd — a fatal accept error
/// or a caller `shutdown(Both)`, which surfaces as EINVAL and is the
/// deliberate teardown signal. The accept loop itself never exits on
/// transient errors (module docs point 10) and never panics. Must run on a
/// runtime with the IO + time drivers enabled.
pub async fn serve(listener: std::net::TcpListener, proxy: Arc<Proxy>) -> io::Result<Infallible> {
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let mut backoff = ACCEPT_BACKOFF_START;
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                backoff = ACCEPT_BACKOFF_START;
                tokio::spawn(handle_connection(stream, client_addr, Arc::clone(&proxy)));
            }
            Err(err) if accept_error_is_fatal(&err) => return Err(err),
            Err(_err) => {
                // Proxy death = sandbox death: bounded exponential backoff
                // (1 ms doubling → accept_backoff_max, reset on success),
                // never an exit. EINTR is retried inside tokio.
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(proxy.limits.accept_backoff_max);
            }
        }
    }
}

/// The accepted connection's fixed context (the pipeline's inputs).
pub(crate) struct ConnCtx {
    pub client_addr: SocketAddr,
    pub orig_dst: SocketAddrV4,
}

/// The relay hand-off state returned by [`decide`] on the allowed path:
/// the client stream, the FULL replay buffer (preamble + any pipelined
/// bytes), and the guarded upstream.
pub(crate) struct RelayStart<S> {
    pub client: S,
    pub replay: Vec<u8>,
    pub connected: Connected,
}

/// One accepted connection: decide → record (exactly once) → replay →
/// relay. Relay errors are normal lifecycle (EOF/RST) and swallowed; there
/// is no idle timeout in v1 (module docs point 6). Drop closes both
/// sockets.
pub(crate) async fn handle_connection(
    client: TcpStream,
    client_addr: SocketAddr,
    proxy: Arc<Proxy>,
) {
    // Proxy-standard; failure ignored (same policy as the upstream flip).
    let _ = client.set_nodelay(true);
    let (decision, relay) = match original_dst(client.as_raw_fd()) {
        Ok(orig_dst) => {
            decide(
                client,
                ConnCtx {
                    client_addr,
                    orig_dst,
                },
                &proxy,
            )
            .await
        }
        // Fail-closed: no verifiable destination ⇒ no traffic. `client` is
        // NOT moved in this arm — it is dropped at scope end (FIN/RST).
        Err(err) => (
            Decision {
                client: client_addr,
                orig_dst: None,
                name: None,
                verdict: Verdict::Denied(Rejected::OriginalDst {
                    detail: err.to_string(),
                }),
            },
            None,
        ),
    };
    // EXACTLY ONE record per connection, before any relay byte
    // (`exactly_one_decision_per_connection` pins it).
    proxy.sink.record(&decision);
    if let Some(RelayStart {
        mut client,
        replay,
        mut connected,
    }) = relay
    {
        // Replay the FULL buffer (preamble + pipelined bytes) to the
        // UPSTREAM: the inspection consumed those bytes FROM THE CLIENT,
        // so forwarding them upstream is what makes the upstream see the
        // client's byte stream verbatim (module docs point 9). Writing
        // them back to the client instead would echo the client's own
        // preamble at it and send the upstream nothing (the design
        // sketch's `client.write_all` was a typo — deviation recorded in
        // the issue notes; the suite's echo-equality assertions pin the
        // direction). Then relay; relay errors are normal lifecycle
        // (EOF/RST) — swallowed. Drop closes both sockets.
        if connected.stream.write_all(&replay).await.is_ok() {
            let _ = copy_bidirectional(&mut client, &mut connected.stream).await;
        }
    }
}

/// `getsockopt(SO_ORIGINAL_DST)` on an ACCEPTED socket of the redirected
/// transparent listener — the pre-DNAT destination the sandbox dialed
/// (conntrack's own-address fallback on non-NATed connections is the F8
/// test-tier fact).
///
/// Parsing follows the pattern sandbox_init's pinned `original_dst()`
/// proved: `sin_addr.s_addr` is a network-order `__be32`, so the octets are
/// taken as-is (`to_ne_bytes`) and `sin_port` is big-endian. Truncation
/// (`len < size_of::<sockaddr_in>()`) and a non-AF_INET family are errors —
/// the sandbox is IPv4-only by construction (module docs point 7). ANY
/// failure becomes a [`Rejected::OriginalDst`] deny at the call site.
pub(crate) fn original_dst(fd: RawFd) -> io::Result<SocketAddrV4> {
    // SAFETY: zeroed sockaddr_in written only by the kernel through the
    // getsockopt out-pointer; the length is passed and re-read per the
    // sockopt contract.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: plain getsockopt call with the out-buffer above.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            consts::SOL_IP,
            consts::SO_ORIGINAL_DST,
            (&mut sa as *mut libc::sockaddr_in).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SO_ORIGINAL_DST returned a truncated sockaddr ({len} bytes)"),
        ));
    }
    if sa.sin_family != libc::AF_INET as libc::sa_family_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SO_ORIGINAL_DST returned family {} (not AF_INET)",
                sa.sin_family
            ),
        ));
    }
    let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
    let port = u16::from_be(sa.sin_port);
    Ok(SocketAddrV4::new(ip, port))
}

/// The locked per-connection pipeline (module docs point 2). Returns the
/// terminal [`Decision`] plus, on the allowed path only, the [`RelayStart`]
/// hand-off state. Generic over the client stream so unit tests drive it
/// over `tokio::io::duplex` without sockets.
pub(crate) async fn decide<S: AsyncRead + Unpin>(
    mut client: S,
    ctx: ConnCtx,
    proxy: &Proxy,
) -> (Decision, Option<RelayStart<S>>) {
    // 1. Port policy — the original destination port must be listed.
    let port = ctx.orig_dst.port();
    if !proxy.ports.contains(&port) {
        return (
            decision(
                &ctx,
                None,
                Verdict::Denied(Rejected::PortNotAllowed { port }),
            ),
            None,
        );
    }
    // 2. DNS map FIRST — the fake IP is NEVER guarded (module docs point
    //    2): 198.18/15 + TEST-NET-3 are guard-denied BY DESIGN.
    let ip = *ctx.orig_dst.ip();
    let Some(name) = proxy.dns_map.name_for(ip) else {
        return (
            decision(&ctx, None, Verdict::Denied(Rejected::UnknownFakeIp { ip })),
            None,
        );
    };
    // 3. Allow list. The RuleMatch borrows the allow slice; it is used
    //    synchronously and dropped before any await (egress.rs borrow note).
    if egress::allowed(name.as_str(), &proxy.allow).is_none() {
        return (
            decision(
                &ctx,
                Some(name.clone()),
                Verdict::Denied(Rejected::NotAllowed { name }),
            ),
            None,
        );
    }
    // 4. Protocol branch under the decision timeout — ONE scope around the
    //    whole inspection (elapsed ⇒ future dropped mid-read, buffered
    //    bytes discarded — fail-closed; module docs point 6).
    let inspected = match port {
        TLS_PORT => {
            tokio::time::timeout(
                proxy.limits.decision_timeout,
                hello::inspect_tls(&mut client, &name, &proxy.limits),
            )
            .await
        }
        HTTP_PORT => {
            tokio::time::timeout(
                proxy.limits.decision_timeout,
                http::inspect_http(&mut client, &name, port, &proxy.limits),
            )
            .await
        }
        // Q1: policy-listed but uninspectable ⇒ deny, immediate (no
        // timeout needed — nothing is read).
        other => {
            return (
                decision(
                    &ctx,
                    Some(name),
                    Verdict::Denied(Rejected::NoInspector { port: other }),
                ),
                None,
            );
        }
    };
    let replay = match inspected {
        Ok(Ok(replay)) => replay,
        Ok(Err(rejected)) => {
            return (decision(&ctx, Some(name), Verdict::Denied(rejected)), None);
        }
        Err(_elapsed) => {
            return (
                decision(
                    &ctx,
                    Some(name),
                    Verdict::Denied(Rejected::DecisionTimeout {
                        secs: proxy.limits.decision_timeout.as_secs(),
                    }),
                ),
                None,
            );
        }
    };
    // 5. Connect (GuardedConnector owns the connect timeout internally —
    //    the scopes never nest).
    let connected = match proxy.connector.connect(&name, port).await {
        Ok(connected) => connected,
        // THE single exhaustive ConnectError→verdict mapping site (Q6):
        // DialDenied is a policy denial; the rest are infrastructure
        // failures against an already-allowed name.
        Err(err) => {
            let verdict = match err {
                ConnectError::DialDenied { addr, denied } => {
                    Verdict::Denied(Rejected::DialDenied { addr, denied })
                }
                ConnectError::Resolve { detail } => Verdict::Error(Failed::Resolve {
                    name: name.clone(),
                    detail,
                }),
                ConnectError::EmptyResolve => {
                    Verdict::Error(Failed::EmptyResolve { name: name.clone() })
                }
                ConnectError::Connect { detail } => Verdict::Error(Failed::Connect {
                    name: name.clone(),
                    detail,
                }),
                ConnectError::Timeout => Verdict::Error(Failed::ConnectTimeout {
                    name: name.clone(),
                    secs: proxy.limits.connect_timeout.as_secs(),
                }),
            };
            return (decision(&ctx, Some(name), verdict), None);
        }
    };
    // 6. Allowed — the decision carries the guarded peer actually
    //    connected; the relay state carries the FULL replay buffer.
    (
        decision(
            &ctx,
            Some(name.clone()),
            Verdict::Allowed {
                name,
                upstream: connected.peer,
            },
        ),
        Some(RelayStart {
            client,
            replay,
            connected,
        }),
    )
}

/// The [`Decision`] field bundle shared by every pipeline exit.
fn decision(ctx: &ConnCtx, name: Option<Domain>, verdict: Verdict) -> Decision {
    Decision {
        client: ctx.client_addr,
        orig_dst: Some(ctx.orig_dst),
        name,
        verdict,
    }
}

/// The runtime-host normalization shared by the SNI, `Host`, and
/// absolute-form-target checks: strip exactly ONE trailing ASCII root dot
/// (resolvers/SNI may carry it; the map's names never do), then
/// [`Domain::parse`] — the [`crate::egress::allowed`] pipeline (egress.rs
/// module docs point 3).
pub(crate) fn canonicalize_host(raw: &str) -> Option<Domain> {
    Domain::parse(raw.strip_suffix('.').unwrap_or(raw)).ok()
}

/// The fatal-accept-error classifier (module docs point 10): only a
/// provably dead fd exits [`serve`]; EVERYTHING else (EMFILE/ENFILE/
/// ECONNABORTED/ENOBUFS/ENOMEM, and non-OS errors) is transient and gets
/// bounded backoff. `accept_error_classification_pinned` pins the table.
fn accept_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::EINVAL) | Some(libc::ENOTSOCK)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    /// Every wait in these tests is bounded by this deadline.
    const BOUND: Duration = Duration::from_secs(5);
    /// The sandbox-side client address fixtures (the netns `lo` address
    /// #5 assigns — realistic but never asserted against a real socket
    /// here).
    const SANDBOX_CLIENT: &str = "10.255.255.1:40000";
    /// The TEST-NET-3 fake IP the integration tier uses.
    const FAKE_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    /// A public address `egress::guard` passes.
    const PUBLIC: &str = "93.184.216.34:443";

    /// Hand-rolled current-thread block_on (the tokio `macros` feature is
    /// deliberately NOT enabled — module docs point 8).
    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    fn dom(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse()
            .unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse()
            .unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    // ---- fakes (the three seams + the connector plumbing) ---------------

    #[derive(Default)]
    struct StaticMap(HashMap<Ipv4Addr, Domain>);

    impl StaticMap {
        fn new(pairs: &[(Ipv4Addr, &str)]) -> Self {
            Self(pairs.iter().map(|(ip, s)| (*ip, dom(s))).collect())
        }
    }

    impl DnsMap for StaticMap {
        fn name_for(&self, ip: Ipv4Addr) -> Option<Domain> {
            self.0.get(&ip).cloned()
        }
    }

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<Decision>>);

    impl RecordingSink {
        fn recorded(&self) -> Vec<Decision> {
            self.0.lock().expect("sink lock").clone()
        }
    }

    impl DecisionSink for RecordingSink {
        fn record(&self, decision: &Decision) {
            self.0.lock().expect("sink lock").push(decision.clone());
        }
    }

    /// A connector that must never be called: it counts attempts and
    /// fails, so an unexpected connect surfaces as a verdict mismatch AND
    /// a counter assertion.
    struct NeverConnector(Arc<AtomicUsize>);

    impl Connector for NeverConnector {
        fn connect(
            &self,
            _name: &Domain,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(ConnectError::Connect {
                    detail: "connector must not be called".to_owned(),
                })
            })
        }
    }

    fn never_connector() -> (Arc<dyn Connector>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (Arc::new(NeverConnector(Arc::clone(&calls))), calls)
    }

    /// A connector returning a scripted result exactly once (the
    /// ConnectError→verdict mapping table driver).
    struct ScriptedConnector(Mutex<Option<Result<Connected, ConnectError>>>);

    impl ScriptedConnector {
        fn returning(result: Result<Connected, ConnectError>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(Some(result))))
        }
    }

    impl Connector for ScriptedConnector {
        fn connect(
            &self,
            _name: &Domain,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Connected, ConnectError>> + Send + '_>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .expect("script lock")
                    .take()
                    .expect("scripted connector called twice")
            })
        }
    }

    /// The scripted resolve/dial call log: `(name, port)` per call.
    type CallLog = Arc<Mutex<Vec<(String, u16)>>>;

    fn call_log() -> CallLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn log_of(log: &CallLog) -> Vec<(String, u16)> {
        log.lock().expect("log lock").clone()
    }

    fn resolve_addrs(addrs: Vec<SocketAddr>) -> ResolveFn {
        Arc::new(move |_name: &str, _port: u16| {
            let addrs = addrs.clone();
            Box::pin(async move { Ok(addrs) })
        })
    }

    fn resolve_recording(addrs: Vec<SocketAddr>, log: CallLog) -> ResolveFn {
        Arc::new(move |name: &str, port: u16| {
            let addrs = addrs.clone();
            let log = Arc::clone(&log);
            let name = name.to_owned();
            Box::pin(async move {
                log.lock().expect("log lock").push((name, port));
                Ok(addrs)
            })
        })
    }

    fn resolve_fail(detail: &'static str) -> ResolveFn {
        Arc::new(move |_name: &str, _port: u16| {
            Box::pin(async move { Err(io::Error::other(detail)) })
        })
    }

    /// A dial returning one half of a duplex as the upstream plus a
    /// scripted `peer_addr` (the guard-recheck target).
    fn dial_duplex(peer: SocketAddr, log: CallLog) -> DialFn {
        Arc::new(move |name: &str, port: u16| {
            let log = Arc::clone(&log);
            let name = name.to_owned();
            Box::pin(async move {
                log.lock().expect("log lock").push((name, port));
                let (near, _far) = duplex(1024);
                Ok((Box::new(near) as Upstream, peer))
            })
        })
    }

    fn dial_fail(kind: io::ErrorKind, detail: &'static str) -> DialFn {
        Arc::new(move |_name: &str, _port: u16| {
            Box::pin(async move { Err(io::Error::new(kind, detail)) })
        })
    }

    fn dial_slow(delay: Duration) -> DialFn {
        Arc::new(move |_name: &str, _port: u16| {
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                let (near, _far) = duplex(1024);
                Ok((Box::new(near) as Upstream, sock(PUBLIC)))
            })
        })
    }

    fn guarded(resolve: ResolveFn, dial: DialFn, connect_timeout: Duration) -> Arc<dyn Connector> {
        Arc::new(GuardedConnector::new(resolve, dial, connect_timeout))
    }

    fn proxy_with(
        allow: &[&str],
        ports: &[u16],
        map: StaticMap,
        connector: Arc<dyn Connector>,
        limits: Limits,
    ) -> (Arc<Proxy>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let network = policy::Network {
            mode: policy::NetworkMode::Transparent,
            allow: allow.iter().map(|s| dom(s)).collect(),
            ports: ports.to_vec(),
        };
        let proxy = Proxy::new(&network, Arc::new(map), sink.clone(), connector, limits);
        (proxy, sink)
    }

    /// The standard allow-list + DNS-map shape most pipeline tests use.
    fn allowed_proxy(connector: Arc<dyn Connector>, limits: Limits) -> Arc<Proxy> {
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT, HTTP_PORT],
            StaticMap::new(&[(FAKE_IP, "allowed.test")]),
            connector,
            limits,
        );
        proxy
    }

    fn ctx(orig_dst: &str) -> ConnCtx {
        ConnCtx {
            client_addr: sock(SANDBOX_CLIENT),
            orig_dst: v4(orig_dst),
        }
    }

    /// Drive [`decide`] over a duplex pre-fed `client_bytes` (empty ⇒ a
    /// silent client whose peer stays ALIVE for the whole decision — the
    /// timeout tests rely on that).
    fn run_decide(
        proxy: &Proxy,
        orig_dst: &str,
        client_bytes: &[u8],
    ) -> (Decision, Option<RelayStart<DuplexStream>>) {
        let (client, mut peer) = duplex(64 * 1024);
        block_on(async {
            if !client_bytes.is_empty() {
                peer.write_all(client_bytes)
                    .await
                    .expect("fixture write fits the duplex buffer");
            }
            let outcome = decide(client, ctx(orig_dst), proxy).await;
            drop(peer);
            outcome
        })
    }

    fn tls_hello(name: &str) -> Vec<u8> {
        hello::build_client_hello(Some(name), &[])
    }

    // ---- the pinned vocabularies (the #10 contract) ----------------------

    #[test]
    fn rejected_reasons_pinned() {
        // EVERY vocabulary row, byte-exact — the #10 audit-log contract.
        let cases: Vec<(Rejected, &str)> = vec![
            (
                Rejected::OriginalDst {
                    detail: "no conntrack".to_owned(),
                },
                "SO_ORIGINAL_DST lookup failed: no conntrack",
            ),
            (
                Rejected::PortNotAllowed { port: 8080 },
                "port 8080 is not in the policy port list",
            ),
            (
                Rejected::NoInspector { port: 8443 },
                "no protocol inspector for port 8443 in v1",
            ),
            (
                Rejected::UnknownFakeIp {
                    ip: Ipv4Addr::new(198, 18, 0, 7),
                },
                "unknown fake IP 198.18.0.7 (no DNS-map entry)",
            ),
            (
                Rejected::NotAllowed {
                    name: dom("notallowed.test"),
                },
                "notallowed.test is not in the policy allow list",
            ),
            (
                Rejected::NotTls { first_byte: b'G' },
                "non-TLS traffic on port 443 (first byte 0x47)",
            ),
            (
                Rejected::HelloTooLarge { cap: 32768 },
                "TLS ClientHello exceeds the 32768-byte cap",
            ),
            (
                Rejected::HelloMalformed {
                    detail: "bogus".to_owned(),
                },
                "malformed TLS ClientHello: bogus",
            ),
            (
                Rejected::EchOffered,
                "TLS ClientHello offers encrypted_client_hello (ECH); denied in v1",
            ),
            (
                Rejected::SniMissing,
                "missing or invalid SNI in the TLS ClientHello",
            ),
            (
                Rejected::SniMismatch {
                    sni: dom("evil.test"),
                    name: dom("allowed.test"),
                },
                "SNI evil.test does not match the DNS-map name allowed.test",
            ),
            (
                Rejected::HeadTooLarge { cap: 16384 },
                "HTTP request head exceeds the 16384-byte cap",
            ),
            (
                Rejected::HttpMalformed {
                    detail: "bogus".to_owned(),
                },
                "malformed HTTP request: bogus",
            ),
            (
                Rejected::Http2Preface,
                "malformed HTTP request: HTTP/2 connection preface on port 80",
            ),
            (
                Rejected::ConnectMethod,
                "CONNECT is served on the explicit proxy port only (issue #8)",
            ),
            (Rejected::HostMissing, "HTTP request has no Host header"),
            (
                Rejected::HostMultiple,
                "HTTP request has multiple Host headers",
            ),
            (Rejected::HostNotUtf8, "Host header is not valid UTF-8"),
            (
                Rejected::HostPortMismatch {
                    got: 8080,
                    want: 80,
                },
                "Host port suffix :8080 does not match the original destination port 80",
            ),
            (
                Rejected::HostInvalid {
                    value: "user@allowed.test".to_owned(),
                },
                "Host header \"user@allowed.test\" is not a bare hostname",
            ),
            (
                Rejected::HostMismatch {
                    host: dom("evil.test"),
                    name: dom("allowed.test"),
                },
                "HTTP Host evil.test does not match the DNS-map name allowed.test",
            ),
            (
                Rejected::TargetMismatch {
                    target: "http://evil.test/".to_owned(),
                    name: dom("allowed.test"),
                },
                "absolute-form request target \"http://evil.test/\" does not match the DNS-map name allowed.test",
            ),
            (
                Rejected::DialDenied {
                    addr: sock("10.0.0.1:443"),
                    denied: egress::Denied::PrivateNetwork,
                },
                "denied dial to 10.0.0.1:443: private-use address (RFC 1918)",
            ),
            (
                Rejected::Eof,
                "connection closed before a complete protocol preamble",
            ),
            (
                Rejected::DecisionTimeout { secs: 10 },
                "decision-phase timeout: no complete protocol preamble within 10s",
            ),
        ];
        assert_eq!(cases.len(), 25, "every Rejected variant is pinned");
        for (rejected, expected) in cases {
            assert_eq!(rejected.reason(), expected);
        }
    }

    #[test]
    fn failed_reasons_pinned() {
        let name = dom("allowed.test");
        let cases: Vec<(Failed, &str)> = vec![
            (
                Failed::Resolve {
                    name: name.clone(),
                    detail: "servfail".to_owned(),
                },
                "DNS resolution failed for allowed.test: servfail",
            ),
            (
                Failed::EmptyResolve { name: name.clone() },
                "DNS resolution returned no addresses for allowed.test",
            ),
            (
                Failed::Connect {
                    name: name.clone(),
                    detail: "refused".to_owned(),
                },
                "connect to allowed.test failed: refused",
            ),
            (
                Failed::ConnectTimeout {
                    name: name.clone(),
                    secs: 10,
                },
                "connect to allowed.test timed out after 10s",
            ),
        ];
        assert_eq!(cases.len(), 4, "every Failed variant is pinned");
        for (failed, expected) in cases {
            assert_eq!(failed.reason(), expected);
        }
    }

    #[test]
    fn decision_reason_allowed_pinned() {
        // The allowed composition ("allowed {name} via {upstream}") and
        // the three labels (#10's JSONL field).
        let decision = Decision {
            client: sock(SANDBOX_CLIENT),
            orig_dst: Some(v4("203.0.113.7:443")),
            name: Some(dom("allowed.test")),
            verdict: Verdict::Allowed {
                name: dom("allowed.test"),
                upstream: sock(PUBLIC),
            },
        };
        assert_eq!(
            decision.reason(),
            "allowed allowed.test via 93.184.216.34:443"
        );
        assert_eq!(decision.verdict.label(), "allowed");
        let denied = Verdict::Denied(Rejected::SniMissing);
        assert_eq!(denied.label(), "denied");
        let error = Verdict::Error(Failed::EmptyResolve {
            name: dom("allowed.test"),
        });
        assert_eq!(error.label(), "error");
        // Denied/Error decisions delegate to the pinned sub-vocabularies.
        let d = Decision {
            client: sock(SANDBOX_CLIENT),
            orig_dst: None,
            name: None,
            verdict: denied,
        };
        assert_eq!(d.reason(), Rejected::SniMissing.reason());
    }

    #[test]
    fn dial_denied_composes_guard_reason() {
        // Q3's composition — the issue's acceptance-criteria string,
        // byte-exact (egress.rs: "denied dial to {addr}: {denied}"; #8
        // copies this shape).
        let rejected = Rejected::DialDenied {
            addr: sock("10.0.0.1:443"),
            denied: egress::Denied::PrivateNetwork,
        };
        assert_eq!(
            rejected.reason(),
            "denied dial to 10.0.0.1:443: private-use address (RFC 1918)"
        );
    }

    #[test]
    fn limits_defaults_pinned() {
        // The v1 caps/timeouts contract (module docs point 6).
        let limits = Limits::default();
        assert_eq!(limits.max_hello_bytes, 32 * 1024);
        assert_eq!(limits.max_head_bytes, 16 * 1024);
        assert_eq!(limits.max_http_headers, 64);
        assert_eq!(limits.decision_timeout, Duration::from_secs(10));
        assert_eq!(limits.connect_timeout, Duration::from_secs(10));
        assert_eq!(limits.accept_backoff_max, Duration::from_millis(100));
    }

    // ---- the pipeline order + AC denials ----------------------------------

    #[test]
    fn map_lookup_precedes_guard_ordering() {
        // CANARY (module docs point 2): the fake IP 198.18.0.1 is
        // Benchmarking — egress::guard WOULD deny it — yet the map keys it
        // to an allowed name and the connector resolves a public address,
        // so the outcome must be Allowed. If the guard ever moved before
        // the map lookup, this flips to DialDenied.
        assert!(
            egress::guard(std::net::IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))).is_err(),
            "precondition: 198.18.0.1 is guard-denied"
        );
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock(PUBLIC)]),
            dial_duplex(sock(PUBLIC), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT],
            StaticMap::new(&[(Ipv4Addr::new(198, 18, 0, 1), "allowed.test")]),
            connector,
            Limits::default(),
        );
        let hello = tls_hello("allowed.test");
        let (decision, relay) = run_decide(&proxy, "198.18.0.1:443", &hello);
        assert_eq!(
            decision.verdict,
            Verdict::Allowed {
                name: dom("allowed.test"),
                upstream: sock(PUBLIC),
            }
        );
        let RelayStart { replay, .. } = relay.expect("the allowed path returns the relay state");
        assert_eq!(replay, hello);
        assert_eq!(log_of(&log), [("allowed.test".to_owned(), TLS_PORT)]);
    }

    #[test]
    fn unknown_fake_ip_denied() {
        // AC unknown-fake-IP: no map entry ⇒ deny BEFORE any read, with
        // the full decision fields.
        let (connector, calls) = never_connector();
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT],
            StaticMap::default(),
            connector,
            Limits::default(),
        );
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &[]);
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::UnknownFakeIp { ip: FAKE_IP })
        );
        assert_eq!(
            decision.reason(),
            "unknown fake IP 203.0.113.7 (no DNS-map entry)"
        );
        assert_eq!(decision.name, None);
        assert_eq!(decision.orig_dst, Some(v4("203.0.113.7:443")));
        assert_eq!(decision.client, sock(SANDBOX_CLIENT));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "never connects");
    }

    #[test]
    fn port_not_in_policy_denied() {
        // AC: the port must be in network.ports — checked FIRST, before
        // the map (an unmapped fake IP on an unlisted port reports the
        // PORT denial).
        let (connector, calls) = never_connector();
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[HTTP_PORT],
            StaticMap::new(&[(FAKE_IP, "allowed.test")]),
            connector,
            Limits::default(),
        );
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &[]);
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::PortNotAllowed { port: 443 })
        );
        assert_eq!(decision.reason(), "port 443 is not in the policy port list");
        assert_eq!(decision.name, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn non_allowed_host_denied_when_allowed_listed() {
        // AC notallowed.com-when-allowed.com-listed at the pipeline level:
        // the map says notallowed.test, the allow list says allowed.test
        // ⇒ NotAllowed (egress's bare-suffix bug class is pinned there).
        let (connector, calls) = never_connector();
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT],
            StaticMap::new(&[(FAKE_IP, "notallowed.test")]),
            connector,
            Limits::default(),
        );
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &[]);
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::NotAllowed {
                name: dom("notallowed.test"),
            })
        );
        assert_eq!(
            decision.reason(),
            "notallowed.test is not in the policy allow list"
        );
        assert_eq!(decision.name, Some(dom("notallowed.test")));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn no_inspector_for_uninspected_policy_port() {
        // Q1: a policy-listed port without a v1 inspector DENIES (before
        // any read — fail-closed; unverifiable-name traffic must not pass).
        let (connector, calls) = never_connector();
        let (proxy, _sink) = proxy_with(
            &["allowed.test"],
            &[8443],
            StaticMap::new(&[(FAKE_IP, "allowed.test")]),
            connector,
            Limits::default(),
        );
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:8443", &[]);
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::NoInspector { port: 8443 })
        );
        assert_eq!(
            decision.reason(),
            "no protocol inspector for port 8443 in v1"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn allowed_tls_path_returns_relay_state() {
        // AC allowed-host at the decide level, 443: Allowed{name,
        // upstream} + the replay buffer is the exact fixture bytes + the
        // decision fields.
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock(PUBLIC)]),
            dial_duplex(sock(PUBLIC), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let hello = tls_hello("allowed.test");
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &hello);
        assert_eq!(
            decision.verdict,
            Verdict::Allowed {
                name: dom("allowed.test"),
                upstream: sock(PUBLIC),
            }
        );
        assert_eq!(decision.name, Some(dom("allowed.test")));
        assert_eq!(decision.orig_dst, Some(v4("203.0.113.7:443")));
        assert_eq!(
            decision.reason(),
            "allowed allowed.test via 93.184.216.34:443"
        );
        let RelayStart {
            replay, connected, ..
        } = relay.expect("the allowed path returns the relay state");
        assert_eq!(replay, hello);
        assert_eq!(connected.peer, sock(PUBLIC));
        assert_eq!(log_of(&log), [("allowed.test".to_owned(), TLS_PORT)]);
    }

    #[test]
    fn allowed_http_path_returns_relay_state() {
        // AC allowed-host at the decide level, 80.
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock("93.184.216.34:80")]),
            dial_duplex(sock("93.184.216.34:80"), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let head = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:80", head);
        assert_eq!(
            decision.verdict,
            Verdict::Allowed {
                name: dom("allowed.test"),
                upstream: sock("93.184.216.34:80"),
            }
        );
        let RelayStart { replay, .. } = relay.expect("the allowed path returns the relay state");
        assert_eq!(replay, head);
        assert_eq!(log_of(&log), [("allowed.test".to_owned(), HTTP_PORT)]);
    }

    // ---- the Q6 error taxonomy + guard layers ------------------------------

    #[test]
    fn resolve_failure_is_verdict_error() {
        // Q6: infrastructure failure against an ALLOWED name ⇒ Error, not
        // Denied.
        let connector = guarded(
            resolve_fail("servfail"),
            dial_duplex(sock(PUBLIC), call_log()),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Error(Failed::Resolve {
                name: dom("allowed.test"),
                detail: "servfail".to_owned(),
            })
        );
        assert_eq!(
            decision.reason(),
            "DNS resolution failed for allowed.test: servfail"
        );
        assert_eq!(decision.verdict.label(), "error");
    }

    #[test]
    fn empty_resolve_is_verdict_error() {
        let connector = guarded(
            resolve_addrs(vec![]),
            dial_duplex(sock(PUBLIC), call_log()),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Error(Failed::EmptyResolve {
                name: dom("allowed.test"),
            })
        );
        assert_eq!(
            decision.reason(),
            "DNS resolution returned no addresses for allowed.test"
        );
    }

    #[test]
    fn connect_refused_is_verdict_error() {
        let connector = guarded(
            resolve_addrs(vec![sock(PUBLIC)]),
            dial_fail(io::ErrorKind::ConnectionRefused, "refused"),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Error(Failed::Connect {
                name: dom("allowed.test"),
                detail: "refused".to_owned(),
            })
        );
        assert_eq!(decision.reason(), "connect to allowed.test failed: refused");
    }

    #[test]
    fn connect_timeout_is_verdict_error() {
        // The shrunk connect timeout bounds the dial (50 ms, not the 30 s
        // the scripted dial would take).
        let connect_timeout = Duration::from_millis(50);
        let connector = guarded(
            resolve_addrs(vec![sock(PUBLIC)]),
            dial_slow(Duration::from_secs(30)),
            connect_timeout,
        );
        let limits = Limits {
            connect_timeout,
            ..Limits::default()
        };
        let proxy = allowed_proxy(connector, limits);
        let started = Instant::now();
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        let elapsed = started.elapsed();
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Error(Failed::ConnectTimeout {
                name: dom("allowed.test"),
                secs: 0,
            })
        );
        assert_eq!(
            decision.reason(),
            "connect to allowed.test timed out after 0s"
        );
        assert!(elapsed >= connect_timeout, "too fast: {elapsed:?}");
        assert!(
            elapsed < BOUND,
            "the timeout must bound the dial: {elapsed:?}"
        );
    }

    #[test]
    fn private_rebinding_denied_at_resolve() {
        // AC private-address rebinding: the scripted resolve answers a
        // private address ⇒ the guard denies with the issue's exact
        // string, and the dial NEVER runs.
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock("10.0.0.1:443")]),
            dial_duplex(sock("10.0.0.1:443"), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::DialDenied {
                addr: sock("10.0.0.1:443"),
                denied: egress::Denied::PrivateNetwork,
            })
        );
        assert_eq!(
            decision.reason(),
            "denied dial to 10.0.0.1:443: private-use address (RFC 1918)"
        );
        assert!(log_of(&log).is_empty(), "the dial must never run");
    }

    #[test]
    fn guard_applies_to_every_resolved_address() {
        // EVERY resolved address is guarded, not just the first/dialed
        // one: the loopback in second position still denies the whole
        // connection (and the dial never runs).
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock("1.1.1.1:443"), sock("127.0.0.1:443")]),
            dial_duplex(sock("1.1.1.1:443"), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::DialDenied {
                addr: sock("127.0.0.1:443"),
                denied: egress::Denied::Loopback,
            })
        );
        assert!(log_of(&log).is_empty(), "the dial must never run");
    }

    #[test]
    fn peer_addr_recheck_is_the_rebinding_backstop() {
        // TOCTOU backstop (egress.rs point 6): the resolve passed the
        // guard, but the CONNECTED peer is the cloud-metadata endpoint ⇒
        // denied on the peer re-check, before any byte is forwarded.
        let log = call_log();
        let connector = guarded(
            resolve_addrs(vec![sock(PUBLIC)]),
            dial_duplex(sock("169.254.169.254:443"), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::DialDenied {
                addr: sock("169.254.169.254:443"),
                denied: egress::Denied::LinkLocal,
            })
        );
        assert_eq!(
            decision.reason(),
            "denied dial to 169.254.169.254:443: link-local address (incl. cloud metadata 169.254.169.254)"
        );
        assert_eq!(
            log_of(&log),
            [("allowed.test".to_owned(), TLS_PORT)],
            "the dial DID run — the recheck is what caught it"
        );
    }

    #[test]
    fn dial_is_by_name_never_the_client_ip() {
        // Both injectables receive the MAPPED NAME — the fake IP
        // (203.0.113.7) must never reach the resolver or the dialer
        // ("Dial by name, never the client-chosen IP").
        let log = call_log();
        let connector = guarded(
            resolve_recording(vec![sock(PUBLIC)], Arc::clone(&log)),
            dial_duplex(sock(PUBLIC), Arc::clone(&log)),
            Duration::from_secs(10),
        );
        let proxy = allowed_proxy(connector, Limits::default());
        let (decision, _relay) = run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
        assert!(
            matches!(decision.verdict, Verdict::Allowed { .. }),
            "{decision:?}"
        );
        assert_eq!(
            log_of(&log),
            [
                ("allowed.test".to_owned(), TLS_PORT),
                ("allowed.test".to_owned(), TLS_PORT),
            ],
            "resolve then dial, both by name"
        );
        for (name, _port) in log_of(&log) {
            assert!(!name.contains("203.0.113"), "the fake IP leaked: {name}");
        }
    }

    #[test]
    fn connect_error_mapping_is_exhaustive_and_single_site() {
        // Each ConnectError variant maps to exactly the one verdict/reason
        // at decide()'s single mapping site (Q6 split: DialDenied denies,
        // the rest are Errors against the allowed name).
        let name = dom("allowed.test");
        let cases: Vec<(ConnectError, Verdict, &str)> = vec![
            (
                ConnectError::DialDenied {
                    addr: sock("10.0.0.1:443"),
                    denied: egress::Denied::PrivateNetwork,
                },
                Verdict::Denied(Rejected::DialDenied {
                    addr: sock("10.0.0.1:443"),
                    denied: egress::Denied::PrivateNetwork,
                }),
                "denied dial to 10.0.0.1:443: private-use address (RFC 1918)",
            ),
            (
                ConnectError::Resolve {
                    detail: "boom".to_owned(),
                },
                Verdict::Error(Failed::Resolve {
                    name: name.clone(),
                    detail: "boom".to_owned(),
                }),
                "DNS resolution failed for allowed.test: boom",
            ),
            (
                ConnectError::EmptyResolve,
                Verdict::Error(Failed::EmptyResolve { name: name.clone() }),
                "DNS resolution returned no addresses for allowed.test",
            ),
            (
                ConnectError::Connect {
                    detail: "refused".to_owned(),
                },
                Verdict::Error(Failed::Connect {
                    name: name.clone(),
                    detail: "refused".to_owned(),
                }),
                "connect to allowed.test failed: refused",
            ),
            (
                ConnectError::Timeout,
                Verdict::Error(Failed::ConnectTimeout {
                    name: name.clone(),
                    secs: 10,
                }),
                "connect to allowed.test timed out after 10s",
            ),
        ];
        for (scripted, expected_verdict, expected_reason) in cases {
            let proxy = allowed_proxy(
                ScriptedConnector::returning(Err(scripted.clone())),
                Limits::default(),
            );
            let (decision, relay) =
                run_decide(&proxy, "203.0.113.7:443", &tls_hello("allowed.test"));
            assert!(relay.is_none(), "{scripted:?}");
            assert_eq!(decision.verdict, expected_verdict, "{scripted:?}");
            assert_eq!(decision.reason(), expected_reason, "{scripted:?}");
            assert_eq!(decision.name, Some(name.clone()), "{scripted:?}");
        }
    }

    #[test]
    fn decision_timeout_denies_slow_client() {
        // The silent client: the decision timeout (shrunk to ~50 ms)
        // bounds the inspection phase; elapsed ⇒ the future is dropped
        // mid-read and the denial is DecisionTimeout.
        let limits = Limits {
            decision_timeout: Duration::from_millis(50),
            ..Limits::default()
        };
        let (connector, calls) = never_connector();
        let proxy = allowed_proxy(connector, limits);
        let started = Instant::now();
        let (decision, relay) = run_decide(&proxy, "203.0.113.7:443", &[]);
        let elapsed = started.elapsed();
        assert!(relay.is_none());
        assert_eq!(
            decision.verdict,
            Verdict::Denied(Rejected::DecisionTimeout { secs: 0 })
        );
        assert_eq!(
            decision.reason(),
            "decision-phase timeout: no complete protocol preamble within 0s"
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "too fast: {elapsed:?}"
        );
        assert!(
            elapsed < BOUND,
            "the timeout must bound the wait: {elapsed:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "never connects");
    }

    // ---- handle_connection / original_dst / serve ---------------------------

    /// The F8 probe: `SO_ORIGINAL_DST` on an accepted socket of a
    /// non-NATed loopback connection — `Ok` (the connection's OWN
    /// destination) where the host has the conntrack lookup, `Err` where
    /// it does not.
    fn probe_origdst() -> io::Result<SocketAddrV4> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let _client = std::net::TcpStream::connect(addr)?;
        let (accepted, _peer) = listener.accept()?;
        original_dst(accepted.as_raw_fd())
    }

    #[test]
    fn exactly_one_decision_per_connection() {
        // Over a real loopback TcpStream pair through handle_connection:
        // WHATEVER single decision results, the sink records exactly one.
        // On hosts WITHOUT the conntrack lookup the orig-dst failure is
        // itself the recorded deny; where the F8 probe passes, the
        // expected variant is PortNotAllowed (the ephemeral port is not
        // in the policy).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let listen_addr = listener.local_addr().expect("local_addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking for tokio accept");
        let (connector, calls) = never_connector();
        let (proxy, sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT],
            StaticMap::new(&[(Ipv4Addr::LOCALHOST, "allowed.test")]),
            connector,
            Limits::default(),
        );
        let client_thread = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(listen_addr).expect("connect");
            stream
                .set_read_timeout(Some(BOUND))
                .expect("set_read_timeout");
            let mut received = Vec::new();
            let _ = stream.read_to_end(&mut received); // EOF when the proxy drops
            received
        });
        block_on(async {
            let listener = TcpListener::from_std(listener).expect("from_std");
            let (stream, peer) = listener.accept().await.expect("accept");
            handle_connection(stream, peer, Arc::clone(&proxy)).await;
        });
        let received = client_thread.join().expect("client thread");
        assert!(
            received.is_empty(),
            "a denied connection must receive no bytes: {received:?}"
        );
        let decisions = sink.recorded();
        assert_eq!(
            decisions.len(),
            1,
            "EXACTLY one decision per connection: {decisions:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let f8 = probe_origdst().is_ok();
        match &decisions[0].verdict {
            Verdict::Denied(Rejected::PortNotAllowed { port }) if f8 => {
                assert_eq!(*port, listen_addr.port());
                assert_eq!(
                    decisions[0].orig_dst.map(|o| o.port()),
                    Some(listen_addr.port())
                );
            }
            Verdict::Denied(Rejected::OriginalDst { .. }) if !f8 => {
                assert_eq!(decisions[0].orig_dst, None);
            }
            other => panic!("unexpected verdict: {other:?} (f8={f8})"),
        }
        assert_eq!(
            decisions[0].client.ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn original_dst_parses_sockaddr_in() {
        // F8-probed (SKIP-with-message where the getsockopt is
        // unsupported): a loopback connect ⇒ the lookup returns the
        // connection's OWN destination. The byte pattern
        // (s_addr.to_ne_bytes + u16::from_be(sin_port)) is the one
        // sandbox_init's pinned original_dst() proved.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _client = std::net::TcpStream::connect(addr).expect("connect");
        let (accepted, _peer) = listener.accept().expect("accept");
        match original_dst(accepted.as_raw_fd()) {
            Ok(got) => {
                assert_eq!(
                    got,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port()),
                    "F8: a non-NATed connection reports its own destination"
                );
            }
            Err(err) => {
                eprintln!(
                    "SKIP original_dst_parses_sockaddr_in: SO_ORIGINAL_DST unavailable on this host (nf_conntrack?): {err}"
                );
            }
        }
    }

    #[test]
    fn accept_error_classification_pinned() {
        // Transient: bounded backoff, never an exit (proxy death =
        // sandbox death — fdpass).
        for errno in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ECONNABORTED,
            libc::ENOBUFS,
            libc::ENOMEM,
        ] {
            assert!(
                !accept_error_is_fatal(&io::Error::from_raw_os_error(errno)),
                "errno {errno} must classify transient"
            );
        }
        // Fatal: a provably dead fd — and shutdown(Both)'s EINVAL is the
        // deliberate teardown signal.
        for errno in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            assert!(
                accept_error_is_fatal(&io::Error::from_raw_os_error(errno)),
                "errno {errno} must classify fatal"
            );
        }
        // Non-OS errors stay transient (fail-safe: backoff, not exit).
        assert!(!accept_error_is_fatal(&io::Error::other("custom")));
    }

    /// [`serve`] on its own thread + current-thread runtime; the result
    /// travels over a channel so every wait is bounded (no unbounded
    /// joins).
    struct ServeHandle {
        thread: std::thread::JoinHandle<()>,
        rx: Receiver<io::Result<()>>,
        stopper: std::net::TcpListener,
    }

    impl ServeHandle {
        /// The pinned teardown path: `shutdown(SHUT_RDWR)` on a held
        /// `try_clone` of the listener (std's TcpListener has no shutdown
        /// method — the raw sockopt on the shared socket is the call) ⇒
        /// accept EINVAL ⇒ [`serve`] returns Err, bounded.
        fn stop(self) -> io::Result<()> {
            // SAFETY: shutdown(2) on the stopper's own valid listener fd;
            // the call affects the shared socket, which is the point.
            let rc = unsafe { libc::shutdown(self.stopper.as_raw_fd(), libc::SHUT_RDWR) };
            assert_eq!(rc, 0, "shutdown: {}", io::Error::last_os_error());
            let result = self
                .rx
                .recv_timeout(BOUND)
                .expect("serve must exit after the listener shutdown");
            self.thread.join().expect("serve thread");
            result
        }
    }

    fn spawn_serve(listener: std::net::TcpListener, proxy: Arc<Proxy>) -> ServeHandle {
        let stopper = listener.try_clone().expect("try_clone for teardown");
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let result = runtime
                .block_on(serve(listener, proxy))
                .map(|never| match never {});
            let _ = tx.send(result);
        });
        ServeHandle {
            thread,
            rx,
            stopper,
        }
    }

    #[test]
    fn serve_flips_nonblocking_itself() {
        // The fdpass contract: the listener arrives BLOCKING and serve
        // flips it — a missing flip would block the runtime thread inside
        // accept(2); the bounded sink wait makes that a failure, not a
        // hang. One client ⇒ exactly one recorded decision.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (connector, _calls) = never_connector();
        let (proxy, sink) = proxy_with(
            &["allowed.test"],
            &[TLS_PORT],
            StaticMap::new(&[(Ipv4Addr::LOCALHOST, "allowed.test")]),
            connector,
            Limits::default(),
        );
        let handle = spawn_serve(listener, proxy);
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let deadline = Instant::now() + BOUND;
        let mut decided = false;
        while Instant::now() < deadline {
            if !sink.recorded().is_empty() {
                decided = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = handle.stop();
        assert!(
            decided,
            "serve accepted+decided nothing within {BOUND:?} — the nonblocking flip is missing?"
        );
        assert_eq!(sink.recorded().len(), 1, "exactly one decision");
        assert!(result.is_err(), "shutdown must end serve with an error");
        drop(client);
    }

    #[test]
    fn serve_exits_on_listener_shutdown() {
        // The suite/#10 teardown mechanism: shutdown(Both) ⇒ EINVAL ⇒
        // serve returns Err through the fatal classifier, bounded.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let (connector, _calls) = never_connector();
        let (proxy, _sink) =
            proxy_with(&[], &[], StaticMap::default(), connector, Limits::default());
        let handle = spawn_serve(listener, proxy);
        let err = handle
            .stop()
            .expect_err("shutdown must end serve with an error");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EINVAL),
            "the pinned EINVAL teardown path: {err}"
        );
    }

    // ---- canonicalization ----------------------------------------------------

    #[test]
    fn canonicalize_host_strips_one_root_dot() {
        // Exactly ONE trailing ASCII dot — the egress::allowed pipeline
        // shared by SNI, Host, and absolute-form targets.
        assert_eq!(canonicalize_host("a.test"), Some(dom("a.test")));
        assert_eq!(canonicalize_host("a.test."), Some(dom("a.test")));
        assert_eq!(canonicalize_host("a.test.."), None);
        assert_eq!(canonicalize_host(".a.test"), None);
        assert_eq!(canonicalize_host("1.2.3.4"), None);
    }
}
