//! The relay phase — `copy_bidirectional` with a client→upstream TLS
//! scanner on 443 (issue #7, review fix: the second-hello defense).
//!
//! 1. **Why a scanner** — the SNI/ECH verdict covers the FIRST ClientHello
//!    only. A TLS 1.3 HelloRetryRequest lets the sandbox send a SECOND
//!    hello (CH2) that the remote server completes the handshake with — and
//!    RFC 8446 §4.1.4's "the SNI MUST NOT change on retry" is only as good
//!    as the remote stack enforcing it. This module's bar is proxy-local
//!    fail-closed (proxy module docs point 12), so the client→upstream
//!    direction keeps being watched AFTER the replay: [`RelayScanner`]
//!    tracks TLS record + handshake-message framing and tears the
//!    connection down on any new ClientHello. The upstream→client direction
//!    is passed through unscanned (the server's flights carry no
//!    client-hello; scanning them would only add a parse surface).
//! 2. **Plaintext phase (pre-CCS)** — a ClientHello is denied on its TYPE
//!    BYTE (handshake type 0x01) before its length is even known:
//!    fragmentation across records cannot hide it. Any framing that cannot
//!    be a legal continuation (a non-handshake record while a handshake
//!    message is open — a mid-fragment CCS included) tears down too —
//!    fail-closed. This covers the sequential post-HRR CH2, a plaintext
//!    TLS 1.2 renegotiation hello, and every pipelined shape
//!    [`crate::proxy::hello::inspect_tls`] lets through (a trailing 0x16
//!    record AND a same-record [CH1‖CH2] coalescing are denied at
//!    inspection itself; a CH2 hidden behind a legitimate middlebox-CCS or
//!    early-data record tail reaches the pre-feed below).
//! 3. **Post-CCS phase** — after the client's ChangeCipherSpec (the
//!    exactly-one-byte [0x01] record servers accept — a malformed "CCS"
//!    does NOT relax the scanner) the payloads MAY be ciphertext (TLS 1.2):
//!    an encrypted record body is indistinguishable from garbage framing,
//!    so the parser becomes best-effort, under THREE rules (round-3 review
//!    fix — the round-2 length-plausibility gate was proven bypassable and
//!    is gone):
//!    - **Completion deny** — a ClientHello tears down when its message
//!      COMPLETES inside a single record (the CCS-masked CH2 in any record
//!      order, an insecure-renegotiation hello): a real second hello must
//!      complete for any server to act on it, and the tripping chunk is
//!      withheld, so it never does.
//!    - **Continuation deny** — post-CCS, a handshake record arriving
//!      while a message is still open tears down (hello-shaped state ⇒
//!      second-hello detail, anything else ⇒ framing detail). No
//!      legitimate post-CCS client flight contains a FRAGMENTED handshake
//!      message: the TLS 1.2 client's encrypted Finished fits one record
//!      (~36 B — records hold 16 KiB), a TLS 1.3 client's protected
//!      handshake messages (Finished, KeyUpdate) all ride OUTER 0x17
//!      records the scanner never message-parses (RFC 8446 §5.2 — the real
//!      type is sealed inside `TLSInnerPlaintext`), and TLS 1.2
//!      renegotiation is practically extinct (its ClientHello is
//!      single-record too — and a plaintext post-CCS hello tears down
//!      regardless). A continuation
//!      therefore can only be (i) an attacker tiling a MASKED split hello
//!      toward completion — withholding the continuation chunk means the
//!      server's deframer never completes it, at ANY server reassembly
//!      bound (this is why no length gate is needed or possible: OpenSSL
//!      reassembles handshake messages up to INT_MAX−4 ≈ 2 GiB —
//!      statem_lib.c `tls_get_message_header` — so every finite
//!      plausibility threshold is bypassable by padding; rustls caps at
//!      0xffff and Go at 65536, but the bar is proxy-local, not
//!      stack-specific), or (ii) a plaintext hello arriving while a
//!      CIPHERTEXT phantom is open — the scanner would swallow it as
//!      phantom body while the server's deframer (clean: it DECRYPTED the
//!      real flight) parses it fresh. The TLS 1.2 GCM shape needs no luck:
//!      the 8-byte explicit nonce is client-chosen, so the phantom's type
//!      byte and claimed length are attacker-controlled. Fail-closed both
//!      ways.
//!    - **Mask retention** — a non-handshake, non-CCS record interrupting
//!      an open message PASSES (the record itself is inert) while a
//!      HELLO-SHAPED open message is RETAINED — never wiped: servers
//!      ignore several record classes mid-reassembly and KEEP the
//!      fragment across them (warning `user_canceled` alerts: rustls
//!      0.23.45 tolerates up to 4 in TLS 1.3 and notes some stacks send
//!      them routinely — its JDK-8323517 comment; rejected-0-RTT early
//!      data: RFC 8446 §4.2.10 servers MUST skip, rustls via
//!      `ExpectAndSkipRejectedEarlyData`; OpenSSL `ssl3_read_bytes`
//!      `goto start` for both), and a wipe is what let the round-2
//!      alert-masked split CH2 re-emerge as "fresh" messages and complete
//!      upstream. A provably NON-hello phantom IS wiped (resync at the
//!      record boundary): a kept non-hello fragment can never become a
//!      ClientHello server-side — both endpoints parsed the same non-0x01
//!      type byte, and after the wipe scanner and server are re-aligned
//!      at fresh-message boundaries.
//!
//!    A CCS record NEVER interrupts message tracking: a mid-fragment CCS
//!    tears down in BOTH phases (review fix C1) — no legitimate client
//!    emits one (the TLS 1.3 middlebox CCS follows a CLOSED flight; the
//!    TLS 1.2 CCS follows the closed Cert/CKX/CV flight), and OpenSSL
//!    treats it as fatal too (CCS_RECEIVED_EARLY). The trade-off remains
//!    deliberate: deny-on-artifact would break EVERY TLS 1.2 connection at
//!    its encrypted Finished, and a tear-down-at-mask would false-kill
//!    ~1/256 of TLS 1.2 connections (TLS 1.2 only — its encrypted
//!    Finished keeps the real content type outside; a TLS 1.3 client's
//!    protected records ALL ride outer 0x17 with the real type sealed
//!    inside `TLSInnerPlaintext` — RFC 8446 §5.2, rustls
//!    `Tls13MessageEncrypter::encrypt` — so no ciphertext phantom ever
//!    arms in TLS 1.3) whose first ciphertext byte is 0x01, at their
//!    first application-data record. Under these rules that phantom
//!    RETAINS across its app-data interrupts and the connection lives
//!    (`ccs_then_ciphertext_shapes_pass` pins it); pass-through costs at
//!    most an invisible ENCRYPTED renegotiation hello — which no
//!    non-terminating proxy can see (documented residual, proxy module
//!    docs point 12). Recorded
//!    residuals of the deferred policy (Q4 family): (a) an encrypted TLS
//!    1.2 renegotiation whose CCS arrives while a phantom
//!    ciphertext-parsed message is open tears the connection down
//!    (renegotiation with zero intervening application-data records —
//!    practically extinct); and (b) the symmetric false-teardown family of
//!    a 0x01-leading TLS 1.2 encrypted Finished (~1/256 of TLS 1.2
//!    connections): it arms a deferred hello that fires if its random
//!    24-bit length drains exactly across consecutive client 0x16 records
//!    (~2^-19 — a random 24-bit length landing under a ~40-byte record
//!    remainder), and ANY later client 0x16 while the phantom is open
//!    trips the continuation deny — only TLS 1.2 renegotiation (extinct,
//!    and plaintext post-CCS hellos tear down anyway). TLS 1.3 clients
//!    are fully supported with OR without the middlebox-compat CCS (RFC
//!    8446 App-D.4 makes it a MAY): every post-CH1 record is outer
//!    0x14/0x15/0x17 and passes inertly (`tls13_no_ccs_client_passes`,
//!    `tls13_compat_ccs_client_passes`), while a plaintext CH2 (outer
//!    0x16) still tears down in both phases
//!    (`tls13_plaintext_second_hello_after_protected_flight_tears_down`).
//!    The only wire that parses a ciphertext-shaped 0x16 in the strict
//!    pre-CCS phase is a protocol-violating TLS 1.2 client skipping its
//!    mandatory CCS (fatal server-side anyway) — denied fail-closed,
//!    pinned by `protocol_violating_no_ccs_ciphertext_tears_down`.
//! 4. **Record framing is the trust anchor** — the record layer (5-byte
//!    header, big-endian length) is plaintext in EVERY TLS version, and
//!    both endpoints parse it identically: bytes this scanner passes inside
//!    a record body can never be re-interpreted as a record header by the
//!    server. The divergences policed explicitly (round-2/3 review fixes):
//!    servers IGNORE several record classes mid-reassembly and KEEP an
//!    open handshake message across them — warning `user_canceled`
//!    alerts, rejected-0-RTT early data (point 3) — so the scanner NEVER
//!    wipes hello-shaped message state (masks pass with the state
//!    RETAINED) and NEVER lets a post-CCS open message receive
//!    continuation bytes (the continuation deny): the masked split CH2
//!    dies at its first continuation chunk — withheld from the server —
//!    at ANY server reassembly bound. A mid-message CCS tears down
//!    (review fix C1, point 3). Oversized or bogus lengths are passed
//!    through — the server's own record-layer limits and decryption checks
//!    reject them; the scanner's job is only the ClientHello deny.
//! 5. **Teardown semantics** — a teardown is an `io::Error` surfaced
//!    through [`Scanned`] (the client-side `AsyncRead` wrapper): the chunk
//!    that tripped it is NEVER forwarded, and [`relay`] answers
//!    `Ok(`[`RelayEnd::TornDown`]`)` carrying the pinned detail (round-2
//!    review fix: callers never string-match an `io::Error` — transport
//!    failures are the Result's `Err`, teardowns are the typed arm). The
//!    caller (`handle_connection`) reports the detail to the
//!    [`crate::proxy::DecisionSink::teardown`] hook — default no-op, #10
//!    logs it alongside the JSONL row — so a blocked attack is not
//!    audit-invisible, and otherwise treats the teardown as normal relay
//!    lifecycle: both sockets drop (FIN/RST). The single
//!    [`crate::proxy::Decision`] was already recorded (Allowed) BEFORE the
//!    first relay byte; there is NO second record
//!    (`exactly_one_decision_per_connection` stays true — the teardown
//!    hook is not `record`). The two pinned detail strings below are the
//!    test-visible identity of the two teardown classes.
//!
//! Byte counting (issue #10, T9): [`Counted`] wraps the upstream side and
//! counts the bytes it accepts (`up`, replay buffer included) and the bytes it
//! reads (`down`) for the close audit row. A scanner-withheld chunk is never
//! written upstream, so it is never counted.
//!
//! 6. **Pre-feed** — pipelined bytes already inside the replay buffer are
//!    future client→upstream bytes, so [`relay`] scans
//!    `replay[hello_end..]` BEFORE writing anything upstream: a teardown
//!    there means the upstream never sees a single byte (pinned by
//!    `relay_prefeed_tears_down_before_any_upstream_byte`). `hello_end` is
//!    [`crate::proxy::hello::first_record_end`] — the inspected ClientHello
//!    is exactly ONE record (a multi-record hello is denied as unwalkable
//!    at inspection), so the scanner always starts at a record boundary.
//! 7. **Cost** — slice-at-a-time state machine (no per-byte hot loop
//!    outside the ≤4-byte message-header accumulation; non-handshake
//!    record bodies are skipped in one `min()` step). Only port-443 relays
//!    are scanned. The HTTP/1 paths (port 80, CONNECT-80, absolute-form forward) run
//!    [`relay_http`] instead (issue #29, F3): the per-request relay, whose client
//!    side is framed by `h1::RequestStream` and inspected per request (proxy
//!    module docs point 14).
//! 8. **Idle watchdog (issue #29, C4)** — every relay (443 scanned, port 80,
//!    CONNECT-443, CONNECT-80 and forward) runs under [`until_idle`]. [`Activity`]
//!    records the time of the last payload byte moved in EITHER direction, stamped
//!    by [`Watched`] on each read or write that moves at least one byte (TCP
//!    keepalives do not count). When no byte has moved for
//!    [`crate::proxy::Limits::relay_idle_timeout`] the relay future is dropped,
//!    which drops both sockets with no linger, and the `close` row carries
//!    `reason: "idle_timeout"`. The decision phase is not covered: it has
//!    [`crate::proxy::Limits::decision_timeout`]. Deadlines use checked arithmetic.
//! 9. **Teardown vocabulary (issue #29)** — [`Teardown`] is the single build site of
//!    the relay-phase denial details: `SecondHello` and `TlsFraming` (the two pinned
//!    scanner strings), and `Request { index, rejected }`, rendered as
//!    `relay torn down: HTTP request N denied: <reason>`, where request 1 is the
//!    decision phase's and N counts up from there. [`relay_http`] writes every
//!    validated byte before a request's outcome is acted on, so a denied element
//!    never reaches the upstream and the bytes before it do. Upstream EOF ends the
//!    segment (client half-close, then linger). A last request's framed end, or a
//!    client EOF, half-closes the upstream write half.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};

use super::h1::{H1Limits, RequestMeta, RequestStream, Step};
use super::http::{HeadCheck, inspect_head, upstream_head};
use super::{Limits, NameSource, Rejected};
use crate::policy::Domain;

/// The pinned teardown detail: a ClientHello (handshake type 0x01) after
/// the inspected one — plaintext-phase (immediate, on the type byte), or
/// post-CCS (on message completion inside one record, or at the first
/// continuation record into hello-shaped open state — module docs point
/// 3).
pub(crate) const TORN_DOWN_SECOND_HELLO: &str =
    "relay torn down: second TLS ClientHello after the inspected handshake";

/// The pinned teardown detail: plaintext-phase framing that cannot be a
/// legal continuation (a non-handshake record while a handshake message is
/// open) — fail-closed (module docs point 2).
pub(crate) const TORN_DOWN_FRAMING: &str =
    "relay torn down: TLS record framing violation after the inspected handshake";

/// TLS record content types the scanner distinguishes. Every other type
/// (0x15 alert, 0x17 application_data, 0x18 heartbeat, …) is passed
/// through by record framing alone (module docs point 4).
const RECORD_CCS: u8 = 0x14;
const RECORD_HANDSHAKE: u8 = 0x16;

/// The only legal ChangeCipherSpec body byte (RFC 5246 §6.1) — a "CCS"
/// record with any other body does NOT relax the scanner (review fix).
const CCS_BODY_BYTE: u8 = 0x01;

/// The handshake message type of a ClientHello — the ONLY type that tears
/// down (module docs points 2/3).
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// The relay-phase TLS scanner state machine (module docs points 2–4).
///
/// Fed every client→upstream byte AFTER the inspected ClientHello record
/// (starting with the replay buffer's pipelined tail). Deterministic and
/// chunk-boundary invariant: the verdict depends only on the byte stream,
/// never on how it is split across reads (`chunk_split_invariance` pins it
/// over teardown AND pass scenarios). Never panics on any input
/// (`scanner_never_panics_on_garbage` pins it over a truncation/mutation
/// corpus).
pub(crate) struct RelayScanner {
    /// Client ChangeCipherSpec seen: from there on, 0x16 record bodies may
    /// be ciphertext — the ClientHello deny becomes completion-deferred,
    /// continuations into an open message tear down, and non-hello framing
    /// artifacts pass instead of tearing down (module docs point 3).
    ccs: bool,
    /// Partial record header (type, version(2), length(2)).
    hdr: [u8; 5],
    hdr_len: usize,
    /// Remaining body bytes of the open record.
    body_left: usize,
    /// The open record is a handshake record (0x16) being message-parsed.
    body_hs: bool,
    /// The open record is a CCS record (0x14) — flips [`Self::ccs`] once
    /// its body is drained.
    body_ccs: bool,
    /// Partial handshake message header (type, length(3)) — a message
    /// header may itself be fragmented across records.
    msg_hdr: [u8; 4],
    msg_hdr_len: usize,
    /// Remaining body bytes of the open handshake message (>0 = a
    /// fragmented message continues in the NEXT handshake record — legal
    /// pre-CCS only; post-CCS a continuation tears down, module docs
    /// point 3).
    msg_left: usize,
    /// Post-CCS deferred teardown: the open message's type byte was 0x01 —
    /// fires when the message completes inside one record, and drives the
    /// mask-retention + continuation-deny gates meanwhile (module docs
    /// point 3).
    deferred_hello: bool,
    /// The pinned detail of the teardown this scanner fired (set at EVERY
    /// `scan` Err site; read by [`relay`] to surface [`RelayEnd::TornDown`]
    /// without string-matching the `io::Error` — module docs point 5).
    torn_down: Option<&'static str>,
}

impl RelayScanner {
    pub(crate) fn new() -> Self {
        Self {
            ccs: false,
            hdr: [0; 5],
            hdr_len: 0,
            body_left: 0,
            body_hs: false,
            body_ccs: false,
            msg_hdr: [0; 4],
            msg_hdr_len: 0,
            msg_left: 0,
            deferred_hello: false,
            torn_down: None,
        }
    }

    /// The pinned teardown detail this scanner fired (`None` until
    /// [`Self::scan`] returns `Err` — every Err site sets it; module docs
    /// point 5).
    pub(crate) fn torn_down(&self) -> Option<&'static str> {
        self.torn_down
    }

    /// A handshake message is mid-parse (header partially accumulated, or
    /// body bytes still owed): the next record MUST be a handshake record
    /// (a legal fragmentation continuation) — anything else is a framing
    /// violation.
    fn msg_open(&self) -> bool {
        self.msg_hdr_len > 0 || self.msg_left > 0
    }

    /// The retention gate (module docs point 3, round-2/3 review fixes):
    /// the open message COULD be a ClientHello that a server keeps
    /// reassembling across a record it ignores — an armed deferred hello,
    /// or a partial header whose first byte is the ClientHello type (the
    /// claimed length is not known yet ⇒ same answer). NO length
    /// plausibility gate: OpenSSL reassembles handshake messages up to
    /// INT_MAX−4, so any finite threshold is bypassable by padding
    /// (round-3 F1) — hello-shaped state is RETAINED at every length and
    /// continuations deny.
    fn hello_shaped_open_message(&self) -> bool {
        self.deferred_hello || (self.msg_hdr_len > 0 && self.msg_hdr[0] == HANDSHAKE_CLIENT_HELLO)
    }

    /// Feed one read chunk. `Ok(())` = pass (every byte may be forwarded);
    /// `Err` = tear down (the pinned detail says which class) and withhold
    /// THIS chunk — the caller never forwards it (module docs point 5).
    pub(crate) fn scan(&mut self, mut data: &[u8]) -> Result<(), io::Error> {
        while !data.is_empty() {
            if self.hdr_len < 5 {
                // Record-header accumulation (headers may split across
                // chunks; the length is only trusted once complete).
                let take = (5 - self.hdr_len).min(data.len());
                self.hdr[self.hdr_len..self.hdr_len + take].copy_from_slice(&data[..take]);
                self.hdr_len += take;
                data = &data[take..];
                if self.hdr_len == 5 {
                    let ty = self.hdr[0];
                    if self.msg_open() && ty != RECORD_HANDSHAKE {
                        // A record boundary inside an open handshake
                        // message is only legal as another handshake
                        // continuation. Servers IGNORE warning
                        // `user_canceled` alerts and rejected-0-RTT early
                        // data mid-reassembly and KEEP the fragment
                        // across them (rustls-verified; module docs
                        // points 3–4) — so WIPING message state at such
                        // a record is how a split CH2 smuggles through
                        // (round-2 review fix). The shapes, post-CCS: a
                        // mid-message CCS tears down unconditionally in
                        // BOTH phases (review fix C1 — the one mask class
                        // no legitimate client emits mid-fragment, and
                        // OpenSSL fatals on it: BAD_CHANGE_CIPHER_SPEC /
                        // CCS_RECEIVED_EARLY — hence teardown, not
                        // retention); any OTHER
                        // non-handshake record PASSES (inert) with a
                        // HELLO-SHAPED open message RETAINED — never
                        // wiped, at any claimed length (round-3 review
                        // fix: a length gate cannot be fail-closed —
                        // OpenSSL reassembles to INT_MAX−4 — and the
                        // continuation deny below is what actually
                        // closes the masked split CH2); a provably
                        // NON-hello phantom IS wiped (resync at this
                        // record boundary — a kept non-hello fragment
                        // can never become a ClientHello server-side).
                        if self.ccs && ty != RECORD_CCS {
                            if !self.hello_shaped_open_message() {
                                // Ciphertext-parse artifact (module docs
                                // point 3): drop the bogus message state
                                // and pass this record — resync at its
                                // boundary.
                                self.msg_hdr_len = 0;
                                self.msg_left = 0;
                                self.deferred_hello = false;
                            }
                            // Hello-shaped: retain the state, pass the
                            // record — the mask itself is inert; the
                            // attacker's payoff requires a continuation.
                        } else {
                            self.torn_down = Some(TORN_DOWN_FRAMING);
                            return Err(io::Error::other(TORN_DOWN_FRAMING));
                        }
                    } else if self.ccs && self.msg_open() {
                        // The continuation deny (module docs point 3,
                        // round-3 review fix): post-CCS, a handshake
                        // record arriving while a message is still open.
                        // No legitimate post-CCS client flight fragments
                        // a handshake message (the Finished fits one
                        // record in every stack; TLS 1.3 has no
                        // fragmenting post-handshake client message; TLS
                        // 1.2 renegotiation is extinct and single-record
                        // — and plaintext post-CCS hellos tear down
                        // anyway). So this is either an attacker tiling
                        // a MASKED split hello toward completion
                        // (withholding this chunk means the server's
                        // deframer never completes it — at ANY server
                        // reassembly bound) or a plaintext hello riding
                        // into a CIPHERTEXT phantom the server already
                        // decrypted past (its deframer is clean and
                        // would parse the hello fresh — the TLS 1.2 GCM
                        // explicit-nonce shape makes the phantom
                        // attacker-controlled). Fail-closed both ways;
                        // pre-CCS continuations stay legal (fragmented
                        // client-certificate flights are real).
                        let detail = if self.hello_shaped_open_message() {
                            TORN_DOWN_SECOND_HELLO
                        } else {
                            TORN_DOWN_FRAMING
                        };
                        self.torn_down = Some(detail);
                        return Err(io::Error::other(detail));
                    }
                    self.body_left = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
                    self.body_hs = ty == RECORD_HANDSHAKE;
                    // A CCS only counts when it is the exactly-one-byte
                    // record servers accept; the [0x01] body byte itself is
                    // confirmed when the body drains (review fix: a
                    // malformed "CCS" must not relax the scanner — staying
                    // strict only tears down MORE, fail-closed).
                    self.body_ccs = ty == RECORD_CCS && self.body_left == 1;
                }
                continue;
            }
            if self.body_left == 0 {
                // Record drained: close it (a zero-length body closes
                // immediately). Message state SURVIVES the boundary —
                // fragmented handshake messages continue in the next
                // handshake record.
                if self.body_ccs {
                    self.ccs = true;
                }
                self.hdr_len = 0;
                continue;
            }
            if !self.body_hs {
                // Non-handshake record body: skip in one step (module docs
                // point 4 — framing, not content, is the trust anchor).
                let take = self.body_left.min(data.len());
                // The strict CCS confirmation (review fix): only the
                // [0x01] body flips the phase at the record close. A
                // malformed CCS gains an attacker nothing (servers reject
                // it) and staying strict only tears down MORE.
                if self.body_ccs && data[0] != CCS_BODY_BYTE {
                    self.body_ccs = false;
                }
                self.body_left -= take;
                data = &data[take..];
                continue;
            }
            // Handshake record body: message framing.
            if self.msg_left > 0 {
                // Inside a message body (possibly a cross-record
                // continuation): consume, never re-parse.
                let take = self.msg_left.min(self.body_left).min(data.len());
                self.msg_left -= take;
                self.body_left -= take;
                data = &data[take..];
                if self.msg_left == 0 && self.deferred_hello {
                    // A post-CCS ClientHello just completed — even
                    // fragmented across records. No server can act on an
                    // INCOMPLETE hello, so withholding from here on is
                    // sufficient (module docs point 3).
                    self.torn_down = Some(TORN_DOWN_SECOND_HELLO);
                    return Err(io::Error::other(TORN_DOWN_SECOND_HELLO));
                }
                continue;
            }
            // Message-header accumulation (a header may span records).
            debug_assert!(self.msg_hdr_len < 4);
            let take = (4 - self.msg_hdr_len).min(self.body_left).min(data.len());
            self.msg_hdr[self.msg_hdr_len..self.msg_hdr_len + take].copy_from_slice(&data[..take]);
            self.msg_hdr_len += take;
            self.body_left -= take;
            data = &data[take..];
            if !self.ccs && self.msg_hdr[0] == HANDSHAKE_CLIENT_HELLO {
                // Plaintext-phase second hello: denied on the TYPE BYTE —
                // fragmentation cannot hide it (module docs point 2).
                // (msg_hdr[0] is always this message's first byte: the
                // accumulation above starts at index 0 for a fresh header.)
                self.torn_down = Some(TORN_DOWN_SECOND_HELLO);
                return Err(io::Error::other(TORN_DOWN_SECOND_HELLO));
            }
            if self.msg_hdr_len == 4 {
                let len = ((self.msg_hdr[1] as usize) << 16)
                    | ((self.msg_hdr[2] as usize) << 8)
                    | (self.msg_hdr[3] as usize);
                self.msg_left = len;
                self.msg_hdr_len = 0;
                // Post-CCS only: the deferred teardown arms on the type
                // byte and fires at completion inside one record; while
                // the message stays open it drives the mask-retention
                // and continuation-deny gates (module docs point 3). The
                // pre-CCS deny above already fired for plaintext hellos.
                self.deferred_hello = self.ccs && self.msg_hdr[0] == HANDSHAKE_CLIENT_HELLO;
                if self.msg_left == 0 && self.deferred_hello {
                    // A zero-length "ClientHello" is nonsense either way —
                    // fail closed on the completed type byte.
                    self.torn_down = Some(TORN_DOWN_SECOND_HELLO);
                    return Err(io::Error::other(TORN_DOWN_SECOND_HELLO));
                }
            }
        }
        Ok(())
    }
}

/// The client-side `AsyncRead` wrapper that runs every read chunk through
/// the scanner BEFORE `copy_bidirectional` can forward it (module docs
/// point 5). Writes (the upstream→client direction) pass through
/// unscanned — including `poll_shutdown`, so the copy's half-close
/// semantics are unchanged.
pub(crate) struct Scanned<C> {
    inner: C,
    scanner: RelayScanner,
}

impl<C: AsyncRead + Unpin> AsyncRead for Scanned<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Scan ONLY the delta (review fix C3): `ReadBuf::filled()` is
        // cumulative, and tokio's `CopyBuffer` re-enters `poll_read` with
        // the stale tail of its buffer pre-marked filled
        // (`buf.set_filled(me.cap)`, tokio io/util/copy.rs) after a
        // partial-write Pending cycle. Re-ingesting bytes the scanner
        // already consumed would desync its framing (spurious teardowns
        // under backpressure; missed detections). `AsyncRead` impls only
        // ever append, so `filled()[before..]` is exactly the new bytes.
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => match this.scanner.scan(&buf.filled()[before..]) {
                Ok(()) => Poll::Ready(Ok(())),
                // The tripping chunk is withheld: an Err return discards
                // whatever the read produced (module docs point 5). The
                // stale prefix was already scanned-and-forwarded in an
                // earlier cycle — same semantics as a fragmented hello.
                Err(err) => Poll::Ready(Err(err)),
            },
            other => other,
        }
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for Scanned<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// How the relay phase ended (module docs point 5; round-2 review fix —
/// the caller never string-matches an `io::Error`). Transport failures
/// (replay-write, copy) return as the `io::Result`'s `Err` instead: normal
/// relay lifecycle, swallowed by the caller.
#[derive(Debug)]
pub(crate) enum RelayEnd {
    /// Both directions ended cleanly (normal lifecycle).
    Finished,
    /// The scanner tripped: the teardown class (module docs point 9); the
    /// caller reports its detail to [`crate::proxy::DecisionSink::teardown`]
    /// — a blocked attack must not be audit-invisible behind its `allowed …`
    /// line.
    TornDown(Teardown),
}

/// The relay phase: write the FULL replay buffer upstream (proxy module
/// docs point 9 — inspection consumed those bytes FROM the client), then
/// copy bidirectionally. On 443 (`scan_from: Some`) the client→upstream
/// direction runs through [`RelayScanner`], starting with the replay
/// buffer's pipelined tail (`replay[hello_end..]` — scanned BEFORE any
/// write, module docs point 6); on 80 (`None`) the plain
/// `copy_bidirectional` shape is kept.
///
/// Every outcome returns here: a scanner teardown as
/// `Ok(`[`RelayEnd::TornDown`]`)` with the pinned detail, a clean end as
/// `Ok(RelayEnd::Finished)`, and a transport failure (replay-write, copy)
/// as `Err`. The caller (`handle_connection`) reports `TornDown` to the
/// sink's teardown hook and swallows the rest as normal relay lifecycle,
/// letting the drop close both sockets.
pub(crate) async fn relay<C, U>(
    client: C,
    replay: &[u8],
    scan_from: Option<usize>,
    upstream: &mut U,
) -> io::Result<RelayEnd>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let scanner = match scan_from {
        Some(hello_end) => {
            let mut scanner = RelayScanner::new();
            // The clamp is belt-and-braces: `hello_end` comes from
            // first_record_end, which only answers Some(end) when the
            // record is fully present (end <= replay.len()).
            if scanner
                .scan(&replay[hello_end.min(replay.len())..])
                .is_err()
            {
                // The pre-feed tripped BEFORE write_all: zero bytes ever
                // reach the upstream (module docs point 6). Every scan
                // Err site sets `torn_down`; the fallback keeps the
                // unreachable arm panic-free (house rule).
                return Ok(RelayEnd::TornDown(Teardown::from_scanner(
                    scanner.torn_down().unwrap_or(TORN_DOWN_FRAMING),
                )));
            }
            Some(scanner)
        }
        None => None,
    };
    upstream.write_all(replay).await?;
    match scanner {
        Some(scanner) => {
            let mut scanned = Scanned {
                inner: client,
                scanner,
            };
            let copied = copy_bidirectional(&mut scanned, upstream).await;
            // A tripped teardown surfaces as the copy's read error; the
            // scanner's pinned detail is the identity — never
            // string-match the io error (module docs point 5).
            if let Some(detail) = scanned.scanner.torn_down() {
                return Ok(RelayEnd::TornDown(Teardown::from_scanner(detail)));
            }
            copied?;
            Ok(RelayEnd::Finished)
        }
        None => {
            let mut client = client;
            copy_bidirectional(&mut client, upstream).await?;
            Ok(RelayEnd::Finished)
        }
    }
}

/// The wall-clock budget for the post-deny drain (issue #8, D5): the
/// client gets this long to finish its own write before we hang up.
pub(crate) const LINGER_TIMEOUT: Duration = Duration::from_secs(1);

/// The drain byte cap for [`linger_close`] (issue #8, D5).
pub(crate) const LINGER_MAX_BYTES: usize = 64 * 1024;

/// Close a socket after writing a deny response without an RST eating the
/// response (issue #8, D5): shut the write side, then read and discard
/// until EOF, [`LINGER_MAX_BYTES`], or [`LINGER_TIMEOUT`]. Errors are
/// ignored — the caller drops the socket either way.
pub(crate) async fn linger_close<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    let _ = stream.shutdown().await;
    let drain = async {
        let mut sink = [0u8; 4096];
        let mut total = 0usize;
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    if total >= LINGER_MAX_BYTES {
                        break;
                    }
                }
            }
        }
    };
    let _ = tokio::time::timeout(LINGER_TIMEOUT, drain).await;
}

/// Why a relay tore down before its natural end (module docs point 9): the
/// pinned detail is the test-visible identity of each class.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Teardown {
    /// A second ClientHello after the inspected one (443 scanner).
    SecondHello,
    /// Plaintext-phase TLS framing that cannot be a legal continuation (443).
    TlsFraming,
    /// An HTTP request on the connection was denied; `index` is its 1-based
    /// number, `rejected` the check that failed (port 80 and CONNECT-80).
    Request { index: u32, rejected: Rejected },
}

impl Teardown {
    fn from_scanner(detail: &'static str) -> Self {
        if detail == TORN_DOWN_SECOND_HELLO {
            Teardown::SecondHello
        } else {
            Teardown::TlsFraming
        }
    }

    /// The pinned audit detail (module docs point 9; the single build site).
    pub(crate) fn detail(&self) -> String {
        match self {
            Teardown::SecondHello => TORN_DOWN_SECOND_HELLO.to_owned(),
            Teardown::TlsFraming => TORN_DOWN_FRAMING.to_owned(),
            Teardown::Request { index, rejected } => format!(
                "relay torn down: HTTP request {index} denied: {}",
                rejected.reason()
            ),
        }
    }
}

/// The per-connection relay activity clock (module docs point 8): the time of
/// the last payload byte moved in EITHER direction, shared by every wrapper of
/// one relay. `Send` (atomic), so `tokio::spawn` accepts the relay.
#[derive(Debug, Clone)]
pub(crate) struct Activity {
    base: Instant,
    last_nanos: Arc<AtomicU64>,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            last_nanos: Arc::new(AtomicU64::new(0)),
        }
    }

    fn touch(&self) {
        let nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_nanos.store(nanos, Ordering::Relaxed);
    }

    fn last_nanos(&self) -> u64 {
        self.last_nanos.load(Ordering::Relaxed)
    }

    /// The instant a recorded activity stamp denotes (saturating).
    fn at(&self, nanos: u64) -> Instant {
        self.base
            .checked_add(Duration::from_nanos(nanos))
            .unwrap_or(self.base)
    }
}

/// Wraps one side of a relay and stamps [`Activity`] on every read that
/// returns at least one byte and every write that accepts at least one byte.
/// TCP keepalives and empty polls do not count.
pub(crate) struct Watched<S> {
    inner: S,
    act: Activity,
}

impl<S> Watched<S> {
    pub(crate) fn new(inner: S, act: Activity) -> Self {
        Self { inner, act }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            if buf.filled().len() > before {
                this.act.touch();
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                this.act.touch();
            }
        }
        res
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                this.act.touch();
            }
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The inactivity watchdog (module docs point 8): completes once no payload
/// byte has moved for `idle`. A deadline that overflows `Instant` never
/// fires (checked arithmetic, house rule).
pub(crate) async fn idle_watchdog(act: Activity, idle: Duration) {
    loop {
        let seen = act.last_nanos();
        let Some(deadline) = act.at(seen).checked_add(idle) else {
            std::future::pending::<()>().await;
            return;
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        if act.last_nanos() == seen {
            return;
        }
    }
}

/// Race `fut` against the idle watchdog: `Some(output)` when the future
/// finished first, `None` once the relay has been idle for `idle` — `fut` is
/// dropped then, which drops both sockets without a linger (module docs
/// point 8).
pub(crate) async fn until_idle<F: Future>(
    act: &Activity,
    idle: Duration,
    fut: F,
) -> Option<F::Output> {
    let mut fut = Box::pin(fut);
    let mut watchdog = Box::pin(idle_watchdog(act.clone(), idle));
    poll_fn(|cx| {
        if let Poll::Ready(output) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(output));
        }
        if watchdog.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}

/// Which request path a per-request relay serves (module docs point 4): the
/// name source for every head check follows from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpFlavor {
    /// Transparent :80 — the name is the DNS-map name.
    Transparent,
    /// CONNECT-80 — the name is the CONNECT target host.
    ConnectTunnel,
    /// Absolute-form forward — one request only (explicit module docs point
    /// 12); its name is the request-target host.
    Forward,
}

impl HttpFlavor {
    fn source(self) -> NameSource {
        match self {
            HttpFlavor::Transparent => NameSource::DnsMap,
            HttpFlavor::ConnectTunnel => NameSource::ConnectTarget,
            HttpFlavor::Forward => NameSource::RequestTarget,
        }
    }
}

/// The name a per-request relay binds every later request to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HttpBinding {
    pub name: Domain,
    pub port: u16,
    pub flavor: HttpFlavor,
}

/// Everything request 1's decision phase hands the relay: the binding, the
/// request's facts, and the client bytes already read past its head.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HttpStart {
    pub binding: HttpBinding,
    pub first: RequestMeta,
    pub pending: Vec<u8>,
}

/// How a per-request relay ended (module docs point 4).
#[derive(Debug)]
pub(crate) enum HttpEnd {
    /// Upstream EOF ended the relay (normal lifecycle).
    Finished,
    /// A later request was denied (module docs point 4): silent teardown.
    TornDown(Teardown),
}

/// The read chunk for the client side (the head cap bounds what a chunk can
/// add to the accumulator).
const READ_CHUNK: usize = 4096;

/// The outcome of feeding client bytes through the request stream.
#[derive(Debug)]
enum Flow {
    /// More client bytes may follow.
    Continue,
    /// The last request's framed end passed: stop reading the client.
    AfterLast,
    /// The client half-closed (EOF) before the stream ended.
    Eof,
    /// A request was denied.
    Torn(Teardown),
}

/// Race outcome of [`relay_http`]'s two directions.
enum Race {
    Down(io::Result<u64>),
    Up(io::Result<Flow>),
}

/// Feed `input` through the request stream and forward every validated
/// byte (module docs points 4 and 6). Heads are inspected and admitted one
/// at a time, so a denied head is never written.
async fn forward_input<W: AsyncWrite + Unpin>(
    stream: &mut RequestStream,
    binding: &HttpBinding,
    max_headers: usize,
    up_w: &mut W,
    input: &[u8],
) -> io::Result<Flow> {
    let mut pos = 0usize;
    while pos < input.len() {
        if stream.after_last() {
            return Ok(Flow::AfterLast);
        }
        let mut out = Vec::new();
        let result = stream.feed(&input[pos..], &mut out);
        // Validated bytes go upstream before the outcome is acted on: a
        // denied element's predecessors are exactly what the stream emitted.
        if !out.is_empty() {
            up_w.write_all(&out).await?;
        }
        let step = match result {
            Ok(step) => step,
            Err(rejected) => {
                return Ok(Flow::Torn(Teardown::Request {
                    index: stream.index(),
                    rejected,
                }));
            }
        };
        match step {
            Step::Progress { consumed } => {
                if consumed == 0 {
                    return Err(io::Error::other("request stream made no progress"));
                }
                pos += consumed;
            }
            Step::AfterLast { .. } => return Ok(Flow::AfterLast),
            Step::Head { consumed, head } => {
                pos += consumed;
                let index = stream.index();
                let meta = match admit_next(binding, &head, max_headers) {
                    Ok(meta) => meta,
                    Err(rejected) => {
                        return Ok(Flow::Torn(Teardown::Request { index, rejected }));
                    }
                };
                up_w.write_all(&upstream_head(head, &meta)).await?;
                stream.admit(&meta);
            }
        }
    }
    Ok(if stream.after_last() {
        Flow::AfterLast
    } else {
        Flow::Continue
    })
}

/// The client→upstream side's exit: a last request's framed end (or a client
/// EOF) half-closes the upstream write half, so the server sees the end of
/// the request stream. Nothing else is ever sent after it. A denial is
/// returned as is: the caller drops the sockets.
async fn finish_up<W: AsyncWrite + Unpin>(up_w: &mut W, flow: Flow) -> io::Result<Flow> {
    if matches!(flow, Flow::AfterLast) {
        up_w.shutdown().await?;
    }
    Ok(flow)
}

/// Inspect one later request head (module docs point 7). Forward never
/// reaches here: its only request is LAST, so the stream never yields a
/// second head (the arm is a fail-closed backstop).
fn admit_next(
    binding: &HttpBinding,
    head: &[u8],
    max_headers: usize,
) -> Result<RequestMeta, Rejected> {
    match binding.flavor {
        HttpFlavor::Transparent | HttpFlavor::ConnectTunnel => {
            let check = HeadCheck {
                expected: &binding.name,
                port: binding.port,
                source: binding.flavor.source(),
            };
            inspect_head(head, &check, max_headers)
        }
        HttpFlavor::Forward => Err(Rejected::NotProxyRequest),
    }
}

/// The per-request relay (issue #29, F3; module docs point 4): writes the
/// request-1 head, then pumps the client's bytes through the request stream,
/// inspecting and admitting every later head before its bytes are written.
/// Upstream bytes flow back unparsed (`copy`). Upstream EOF ends the relay
/// (client half-closed, linger as before); a client EOF shuts the upstream
/// write half; a last request's end stops reading the client. Every outcome
/// is returned, never swallowed.
pub(crate) async fn relay_http<C, U>(
    client: C,
    head: &[u8],
    start: HttpStart,
    upstream: &mut U,
    limits: &Limits,
) -> io::Result<HttpEnd>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let HttpStart {
        binding,
        first,
        pending,
    } = start;
    let max_headers = limits.max_http_headers;
    let decision_timeout = limits.decision_timeout;
    let mut stream = RequestStream::after_first(&first, H1Limits::from_limits(limits));
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut up_r, mut up_w) = tokio::io::split(&mut *upstream);

    // The request-1 head and the pending bytes go upstream BEFORE the race
    // starts: the downstream copy may finish first (an upstream that is
    // already closed), and the head must never be skipped.
    up_w.write_all(head).await?;
    let first = forward_input(&mut stream, &binding, max_headers, &mut up_w, &pending).await?;
    if let Flow::Torn(teardown) = first {
        return Ok(HttpEnd::TornDown(teardown));
    }
    let up = async {
        if !matches!(first, Flow::Continue) {
            return finish_up(&mut up_w, first).await;
        }
        let mut chunk = [0u8; READ_CHUNK];
        // (request number, instant the head's first byte was seen): the
        // per-head deadline restarts for every head (module docs point 7).
        let mut head_started: Option<(u32, Instant)> = None;
        loop {
            let deadline = if stream.head_in_progress() {
                let index = stream.index();
                let started = match head_started {
                    Some((seen, at)) if seen == index => at,
                    _ => {
                        let at = Instant::now();
                        head_started = Some((index, at));
                        at
                    }
                };
                started.checked_add(decision_timeout)
            } else {
                head_started = None;
                None
            };
            let read = match deadline {
                Some(at) => match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(at),
                    client_r.read(&mut chunk),
                )
                .await
                {
                    Ok(read) => read?,
                    Err(_elapsed) => {
                        return Ok(Flow::Torn(Teardown::Request {
                            index: stream.index(),
                            rejected: Rejected::DecisionTimeout {
                                secs: decision_timeout.as_secs(),
                            },
                        }));
                    }
                },
                None => client_r.read(&mut chunk).await?,
            };
            if read == 0 {
                // Client EOF: a partial head is dropped, never forwarded.
                up_w.shutdown().await?;
                return Ok(Flow::Eof);
            }
            let flow = forward_input(
                &mut stream,
                &binding,
                max_headers,
                &mut up_w,
                &chunk[..read],
            )
            .await?;
            if !matches!(flow, Flow::Continue) {
                return finish_up(&mut up_w, flow).await;
            }
        }
    };
    let down = async { tokio::io::copy(&mut up_r, &mut client_w).await };
    let mut up = Box::pin(up);
    let mut down = Box::pin(down);
    let mut up_done = false;
    let race = poll_fn(|cx| {
        if let Poll::Ready(result) = down.as_mut().poll(cx) {
            return Poll::Ready(Race::Down(result));
        }
        if !up_done {
            if let Poll::Ready(result) = up.as_mut().poll(cx) {
                up_done = true;
                match &result {
                    // A denial or a transport error ends the relay now; the
                    // other outcomes keep the downstream copy running until
                    // upstream EOF.
                    Ok(Flow::Torn(_)) | Err(_) => return Poll::Ready(Race::Up(result)),
                    Ok(_) => {}
                }
            }
        }
        Poll::Pending
    })
    .await;
    drop(up);
    drop(down);
    match race {
        Race::Down(Ok(_)) => {
            // Upstream EOF ends the segment (module docs point 4): half-close
            // the client, then linger as relay_until_upstream_eof did.
            let _ = client_w.shutdown().await;
            let mut client = client_r.unsplit(client_w);
            linger_close(&mut client).await;
            Ok(HttpEnd::Finished)
        }
        Race::Down(Err(err)) => Err(err),
        Race::Up(Ok(Flow::Torn(teardown))) => Ok(HttpEnd::TornDown(teardown)),
        Race::Up(Err(err)) => Err(err),
        // Only Torn/Err reach the race's Up arm (see above).
        Race::Up(Ok(_)) => Ok(HttpEnd::Finished),
    }
}

/// Upstream byte counter for the close audit row (issue #10, T9). `up` counts
/// bytes the upstream ACCEPTED (replay buffer included); `down` counts bytes
/// read from the upstream. A scanner-withheld chunk is never written upstream,
/// so it is never counted.
pub(crate) struct Counted<U> {
    inner: U,
    up: u64,
    down: u64,
}

impl<U> Counted<U> {
    pub(crate) fn new(inner: U) -> Self {
        Self {
            inner,
            up: 0,
            down: 0,
        }
    }

    pub(crate) fn up(&self) -> u64 {
        self.up
    }

    pub(crate) fn down(&self) -> u64 {
        self.down
    }
}

impl<U: AsyncRead + Unpin> AsyncRead for Counted<U> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len().saturating_sub(before) as u64;
        this.down = this.down.saturating_add(read);
        res
    }
}

impl<U: AsyncWrite + Unpin> AsyncWrite for Counted<U> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            this.up = this.up.saturating_add(*n as u64);
        }
        res
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &res {
            this.up = this.up.saturating_add(*n as u64);
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::hello::{build_client_hello, first_record_end};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Hand-rolled current-thread block_on (the tokio `macros` feature is
    /// deliberately NOT enabled — proxy module docs point 8).
    #[test]
    fn counted_counts_reads_and_writes() {
        block_on(async {
            let (mut far, near) = tokio::io::duplex(4096);
            let mut counted = Counted::new(near);
            far.write_all(b"hello world").await.expect("far write");
            let mut buf = [0u8; 5];
            counted.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello");
            // Only the 5 bytes actually delivered by read_exact count; the
            // duplex may have buffered the rest, which is not "down" traffic.
            assert_eq!(counted.down(), 5);
            counted.write_all(b"abc").await.expect("write");
            assert_eq!(counted.up(), 3);
            let mut echoed = [0u8; 3];
            far.read_exact(&mut echoed).await.expect("far read");
            assert_eq!(&echoed, b"abc");
        });
    }

    #[test]
    fn counted_counts_vectored_writes() {
        block_on(async {
            let (mut far, near) = tokio::io::duplex(4096);
            let mut counted = Counted::new(near);
            let bufs = [std::io::IoSlice::new(b"ab"), std::io::IoSlice::new(b"cde")];
            let n = counted.write_vectored(&bufs).await.expect("vectored");
            counted.flush().await.expect("flush");
            assert_eq!(counted.up(), n as u64);
            assert!(counted.up() >= 2);
            let mut got = vec![0u8; n];
            far.read_exact(&mut got).await.expect("far read");
        });
    }

    #[test]
    fn relay_counts_replay_as_up() {
        block_on(async {
            // The request-1 head is written upstream first; a counted relay must
            // report it as `up` (issue #10, T9). Upstream EOF ends the relay.
            let (mut far, near) = tokio::io::duplex(4096);
            let (client, _client_far) = tokio::io::duplex(4096);
            let mut counted = Counted::new(near);
            let head = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
            let far_task = tokio::spawn(async move {
                let mut got = vec![0u8; b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".len()];
                far.read_exact(&mut got).await.expect("far read");
                far.shutdown().await.expect("far shutdown");
            });
            let start = HttpStart {
                binding: HttpBinding {
                    name: Domain::parse("a.test").expect("name"),
                    port: 80,
                    flavor: HttpFlavor::Transparent,
                },
                first: RequestMeta {
                    framing: super::super::http::Framing::None,
                    minor_version: 1,
                    close: true,
                    upgrade: false,
                },
                pending: Vec::new(),
            };
            let r = relay_http(client, head, start, &mut counted, &Limits::default()).await;
            far_task.await.expect("far task");
            assert!(matches!(r, Ok(HttpEnd::Finished)), "{r:?}");
            assert_eq!(counted.up(), head.len() as u64);
        });
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    // ---- wire helpers -----------------------------------------------------

    /// A TLS record: type + legacy version + big-endian length + body.
    fn rec(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![ty, 0x03, 0x03];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A handshake message: type + 24-bit length + body.
    fn hs(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![ty];
        let l = body.len() as u32;
        out.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, (l & 0xff) as u8]);
        out.extend_from_slice(body);
        out
    }

    /// One handshake record carrying the concatenated messages.
    fn hs_rec(msgs: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for m in msgs {
            body.extend_from_slice(m);
        }
        rec(RECORD_HANDSHAKE, &body)
    }

    /// The CCS record (one 0x01 byte — the only legal body).
    fn ccs_rec() -> Vec<u8> {
        rec(RECORD_CCS, &[0x01])
    }

    /// A ClientHello-shaped handshake message (the type byte is all the
    /// scanner keys on; the body is fixture filler).
    fn hello_msg() -> Vec<u8> {
        hs(
            HANDSHAKE_CLIENT_HELLO,
            &[0x03, 0x03, 0xAA, 0xBB, 0xCC, 0xDD],
        )
    }

    fn scan_all(bytes: &[u8]) -> Result<(), io::Error> {
        RelayScanner::new().scan(bytes)
    }

    fn torn_down(err: &io::Error, want: &str) {
        assert_eq!(err.to_string(), want, "teardown detail mismatch");
    }

    // ---- plaintext phase (module docs point 2) ----------------------------

    #[test]
    fn second_hello_in_plaintext_phase_tears_down() {
        // THE review-fix scenario: the post-HRR CH2 as its own record.
        let err = scan_all(&hs_rec(&[&hello_msg()])).expect_err("a second hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn plaintext_client_flight_passes() {
        // The legitimate TLS 1.2 plaintext flight: Certificate (0x0b) +
        // ClientKeyExchange (0x10) + CertificateVerify (0x0f), coalesced
        // into one record — none of them a ClientHello.
        let wire = hs_rec(&[
            &hs(0x0b, &[0x00, 0x02, 0x11, 0x22]),
            &hs(0x10, &[0x21]),
            &hs(0x0f, &[0x04, 0x03, 0x99, 0x88]),
        ]);
        scan_all(&wire).expect("a legitimate plaintext flight must pass");
    }

    #[test]
    fn plaintext_hello_tears_down_when_fragmented_across_records() {
        // The type byte cannot be hidden: the first fragment's leading
        // 0x01 tears down before the message (or even its header)
        // completes.
        let msg = hello_msg();
        let split = 6; // mid-body
        let r1 = rec(RECORD_HANDSHAKE, &msg[..split]);
        let err = scan_all(&r1).expect_err("the type byte alone must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn plaintext_hello_header_split_across_records_still_tears_down() {
        // Even a message HEADER fragmented across records cannot hide the
        // type byte: record 1 carries [0x01, 0x00] — the deny fires on the
        // accumulated first byte, i.e. within record 1.
        let msg = hello_msg();
        let r1 = rec(RECORD_HANDSHAKE, &msg[..2]);
        let err = scan_all(&r1).expect_err("a split header must tear down on its type byte");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn pre_ccs_fragmented_flight_continuation_passes() {
        // The continuation deny is POST-CCS only (module docs point 3):
        // pre-CCS, a fragmented plaintext flight is legitimate — a large
        // client Certificate spans records in real TLS 1.2 client-cert
        // flows. The continuation record is consumed into the open
        // message, never re-parsed.
        let msg = hs(0x0b, &[0x00, 0x03, 0x11, 0x22, 0x33, 0x44]);
        let split = 6;
        let mut wire = rec(RECORD_HANDSHAKE, &msg[..split]);
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[split..]));
        scan_all(&wire).expect("a pre-CCS fragmented flight must pass");
    }

    #[test]
    fn non_handshake_record_mid_message_tears_down_pre_ccs() {
        // Framing violation (fail-closed, module docs point 2): a
        // Certificate message claims more bytes than the record carries,
        // then an application-data record follows instead of the legal
        // handshake continuation.
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &hs(0x0b, &[0xAA; 8])[..8]));
        wire.extend_from_slice(&rec(0x17, b"smuggled"));
        let err = scan_all(&wire).expect_err("lost framing must tear down pre-CCS");
        torn_down(&err, TORN_DOWN_FRAMING);
    }

    #[test]
    fn early_data_alerts_and_heartbeats_pass() {
        // 0-RTT early data (0x17) may legitimately pipeline behind the
        // hello; plaintext alerts (0x15) and any other record type pass —
        // the server's own state machine judges them (module docs point 4).
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(0x17, b"early data"));
        wire.extend_from_slice(&rec(0x15, &[0x01, 0x00]));
        wire.extend_from_slice(&rec(0x18, &[0x00]));
        scan_all(&wire).expect("non-handshake records must pass");
    }

    #[test]
    fn zero_length_records_pass() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &[]));
        wire.extend_from_slice(&rec(0x17, &[]));
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &hs(0x0b, &[])));
        scan_all(&wire).expect("zero-length bodies are the server's problem");
    }

    // ---- post-CCS phase (module docs point 3) ------------------------------

    #[test]
    fn ccs_then_ciphertext_shapes_pass() {
        // The TLS 1.2 survival case — and the round-3 AVAILABILITY pin:
        // after the client CCS, the encrypted Finished (0x16 with a
        // ciphertext body — TLS 1.2 only; TLS 1.3 protected records ride
        // outer 0x17, RFC 8446 §5.2) and everything after it must pass. The
        // "ciphertext" bytes are deliberately shaped to misparse (a
        // leading 0x01 = the ~1/256 random type-byte hit, a bogus 24-bit
        // length overshooting the record): the phantom arms a deferred
        // hello, the app-data record interrupts it, and the mask-retention
        // rule RETAINS the state and passes the record. A
        // deny-on-artifact scanner would break every TLS 1.2 connection
        // here; a tear-down-at-mask scanner (the round-3 rejected option)
        // would false-kill ~1/256 of TLS 1.2 connections here.
        let mut wire = Vec::new();
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0x01, 0xFF, 0xFF, 0x00, 0x77, 0x88],
        ));
        wire.extend_from_slice(&rec(0x17, b"app data"));
        wire.extend_from_slice(&rec(0x17, b"more app data"));
        scan_all(&wire).expect("post-CCS ciphertext artifacts must pass");
    }

    #[test]
    fn ccs_masked_second_hello_tears_down_on_completion() {
        // The CCS-mask bypass attempt: a middlebox CCS (ignored by TLS 1.3
        // servers) then a well-formed plaintext CH2 completing INSIDE its
        // single record ⇒ the completion deny fires — bytes withheld.
        let mut wire = Vec::new();
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&hs_rec(&[&hello_msg()]));
        let err = scan_all(&wire).expect_err("a completed post-CCS hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn ccs_masked_fragmented_hello_tears_down_at_its_continuation() {
        // The fragmented CCS-mask shape: record 1 = header + partial body
        // (no verdict yet — ciphertext ambiguity), record 2 is a
        // CONTINUATION into the open deferred hello ⇒ the round-3
        // continuation deny fires at its record header. The completion
        // chunk is withheld, so the server can never reassemble the full
        // hello — at ANY server reassembly bound.
        let msg = hello_msg();
        let split = 6;
        let mut s = RelayScanner::new();
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
        s.scan(&wire)
            .expect("an incomplete message must not tear down yet");
        let r2 = rec(RECORD_HANDSHAKE, &msg[split..]);
        let err = s.scan(&r2).expect_err("the continuation must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn post_ccs_framing_artifacts_resync_and_pass() {
        // Ciphertext garbage leaves a bogus open message; the next
        // application-data record is a "violation" that post-CCS policy
        // passes with a resync — resync is only for PROVABLY NON-HELLO
        // phantoms (round-2 review fix: the 0x0b artifact is one) — and a
        // LATER clean record parses normally (still catching a real
        // post-CCS hello).
        let mut wire = Vec::new();
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0x0b, 0x10, 0x00, 0x00, 0x40, 0x11],
        ));
        wire.extend_from_slice(&rec(0x17, b"data"));
        wire.extend_from_slice(&hs_rec(&[&hs(0x0b, &[0x01, 0x02])]));
        scan_all(&wire).expect("artifact → resync → pass");
        // The resynced scanner still denies a real completed hello:
        let mut tail = wire;
        tail.extend_from_slice(&hs_rec(&[&hello_msg()]));
        let err = scan_all(&tail).expect_err("post-resync hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    /// The C1 attack wire (review fix pin): CCS₁, a CH2 FRAGMENT (header +
    /// partial body — arms the deferred hello and leaves the message open),
    /// CCS₂ injected MID-FRAGMENT (a record class servers ignore
    /// mid-reassembly — and one OpenSSL treats as fatal,
    /// CCS_RECEIVED_EARLY — resyncing there would wipe the deferred state
    /// and let the completion record smuggle the hello upstream), then the
    /// completion.
    fn ccs_mid_fragment_attack() -> Vec<u8> {
        let msg = hello_msg();
        let split = 6;
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[split..]));
        wire
    }

    #[test]
    fn ccs_mid_fragment_does_not_mask_second_hello() {
        // C1 pin: a mid-fragment CCS tears down (framing violation) in
        // BOTH feed shapes — the deferred hello tracking is never wiped by
        // a CCS record.
        let wire = ccs_mid_fragment_attack();
        let err = scan_all(&wire).expect_err("a mid-fragment CCS must tear down");
        torn_down(&err, TORN_DOWN_FRAMING);
        let mut s = RelayScanner::new();
        let mut bytewise = Ok(());
        for chunk in wire.chunks(1) {
            if let Err(err) = s.scan(chunk) {
                bytewise = Err(err);
                break;
            }
        }
        let err = bytewise.expect_err("byte-fed must tear down identically");
        torn_down(&err, TORN_DOWN_FRAMING);
        // The header-split variant: CCS₁, a record carrying ONLY the CH2
        // type byte + 1 length byte, CCS₂. Post-CCS the type byte alone
        // does not fire (ciphertext ambiguity) — the mid-message CCS₂ is
        // the deny.
        let mut wire2 = ccs_rec();
        wire2.extend_from_slice(&rec(RECORD_HANDSHAKE, &[0x01, 0x00]));
        wire2.extend_from_slice(&ccs_rec());
        let err = scan_all(&wire2).expect_err("header-split variant must tear down");
        torn_down(&err, TORN_DOWN_FRAMING);
    }

    /// The round-2 alert-mask attack wire (review-fix pin): CCS₁, a CH2
    /// FRAGMENT (header + partial body — arms the deferred hello and
    /// leaves the message open), a warning `user_canceled` alert (a record
    /// class servers IGNORE mid-reassembly and KEEP the fragment across —
    /// WIPING the state there would let the completion record smuggle the
    /// hello upstream), then the completion. Under the round-3 rules the
    /// mask passes with the state RETAINED and the completion record dies
    /// at the continuation deny.
    fn alert_masked_split_hello_attack() -> Vec<u8> {
        let msg = hello_msg();
        let split = 6;
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
        wire.extend_from_slice(&rec(0x15, &[0x01, 0x5a])); // warning user_canceled
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[split..]));
        wire
    }

    #[test]
    fn alert_masked_split_hello_tears_down() {
        // Round-2 C1 pin (round-3 shape): the mask record itself is inert
        // and PASSES with the hello-shaped state retained — never wiped —
        // and the completion record dies at the continuation deny, its
        // chunk withheld, so the server's deframer never completes the
        // CH2. Whole-fed, stepped, and byte-fed identical.
        let wire = alert_masked_split_hello_attack();
        let err = scan_all(&wire).expect_err("an alert-masked split hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
        // Stepped: fragment + mask pass (state retained), continuation
        // denies.
        let msg = hello_msg();
        let mut mask_part = ccs_rec();
        mask_part.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..6]));
        mask_part.extend_from_slice(&rec(0x15, &[0x01, 0x5a]));
        let mut s = RelayScanner::new();
        s.scan(&mask_part)
            .expect("the mask passes with the state retained");
        let err = s
            .scan(&rec(RECORD_HANDSHAKE, &msg[6..]))
            .expect_err("the continuation must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
        let mut s = RelayScanner::new();
        let mut bytewise = Ok(());
        for chunk in wire.chunks(1) {
            if let Err(err) = s.scan(chunk) {
                bytewise = Err(err);
                break;
            }
        }
        let err = bytewise.expect_err("byte-fed must tear down identically");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn early_data_masked_split_hello_tears_down() {
        // The 0x17-mask variant (round-2 review fix): rejected-0-RTT
        // early-data records are the other ignore-and-reassemble class
        // (RFC 8446 §4.2.10 — servers MUST skip them, rustls via
        // ExpectAndSkipRejectedEarlyData). Retention and the continuation
        // deny are record-type AGNOSTIC — one mechanism closes the 0x15
        // and 0x17 masks together.
        let msg = hello_msg();
        let split = 6;
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
        wire.extend_from_slice(&rec(0x17, b"rejected early data"));
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[split..]));
        let err = scan_all(&wire).expect_err("an early-data-masked split hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn partial_hello_header_mask_tears_down() {
        // The partial-header shape (round-2 review fix): the interrupting
        // record arrives while only [0x01, 0x00] of the message header is
        // accumulated — the claimed length is not known yet, so retention
        // treats the state as hello-shaped (fail closed), and the
        // continuation record denies.
        let msg = hello_msg();
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..2]));
        wire.extend_from_slice(&rec(0x15, &[0x01, 0x5a]));
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[2..]));
        let err = scan_all(&wire).expect_err("a partial hello header mask must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    /// Round-3 F1/F2 pin: a masked split hello with ANY claimed length
    /// dies at its FIRST continuation record. The retention gate has no
    /// length threshold — OpenSSL reassembles handshake messages up to
    /// INT_MAX−4 (~2 GiB, statem_lib.c `tls_get_message_header`), so no
    /// finite plausibility bound is fail-closed. No length gate was ever
    /// landed: a 64 KiB plausibility threshold proposed during the round-2
    /// fix cycle was proven bypassable by padding (a padded CH2 claiming
    /// 81920 bytes; PoC executed) before it shipped — and the continuation
    /// deny closes the attack at ANY server reassembly bound: the server's
    /// deframer only ever completes the split hello through a 0x16
    /// continuation, and that chunk is withheld. Lengths span the PROPOSED
    /// gate's boundary on both sides (65536/65537), the PoC's 81920, and
    /// the single-record scale (6).
    #[test]
    fn masked_split_hello_of_any_claimed_length_tears_down() {
        for claimed in [6usize, 65536, 65537, 81920] {
            // Fragment: message header + filler < claimed ⇒ the message
            // stays open across the mask.
            let filler = vec![0x5a; claimed / 2];
            let mut fragment_body = vec![HANDSHAKE_CLIENT_HELLO];
            fragment_body.extend_from_slice(&[
                (claimed >> 16) as u8,
                (claimed >> 8) as u8,
                (claimed & 0xff) as u8,
            ]);
            fragment_body.extend_from_slice(&filler);
            let mut mask_part = ccs_rec();
            mask_part.extend_from_slice(&rec(RECORD_HANDSHAKE, &fragment_body));
            mask_part.extend_from_slice(&rec(0x15, &[0x01, 0x5a])); // warning user_canceled
            let continuation = rec(RECORD_HANDSHAKE, &[0x5a; 64]);
            // Stepped: the fragment + mask PASS (the mask record is inert;
            // the hello-shaped state is RETAINED, never wiped) ...
            let mut s = RelayScanner::new();
            s.scan(&mask_part)
                .expect("the fragment + mask must pass with the state retained");
            // ... and the FIRST continuation record is the deny.
            let err = s
                .scan(&continuation)
                .expect_err("a post-CCS continuation must tear down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
            // Whole-fed and byte-fed agree (chunk-boundary invariance).
            let mut full = mask_part;
            full.extend_from_slice(&continuation);
            let err = scan_all(&full).expect_err("whole feed must tear down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
            let mut s = RelayScanner::new();
            let mut bytewise = Ok(());
            for chunk in full.chunks(1) {
                if let Err(err) = s.scan(chunk) {
                    bytewise = Err(err);
                    break;
                }
            }
            let err = bytewise.expect_err("byte feed must tear down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
        }
    }

    #[test]
    fn chosen_nonce_phantom_cannot_swallow_a_plaintext_hello() {
        // The TLS 1.2 GCM shape (round-3 review fix): the 8-byte explicit
        // nonce is CLIENT-CHOSEN, so a "Finished" record can arm a
        // deferred-hello phantom with an attacker-chosen type byte (0x01)
        // and claimed length — no 1/256 luck, no grinding. The server
        // DECRYPTS the real Finished (its deframer stays CLEAN), so a
        // subsequent plaintext CH2 record would be parsed FRESH by the
        // server while the pre-round-3 scanner consumed it as phantom
        // body — the swallow bypass. The continuation deny closes it: any
        // post-CCS 0x16 arriving into the open phantom tears down, chunk
        // withheld, at any claimed length.
        let mut phantom_body = vec![HANDSHAKE_CLIENT_HELLO, 0xff, 0xff, 0xff];
        phantom_body.extend_from_slice(&[0x11; 32]); // nonce tail + "ciphertext"
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &phantom_body));
        let mut s = RelayScanner::new();
        s.scan(&wire)
            .expect("the phantom-arming Finished record passes");
        let ch2 = hs_rec(&[&hello_msg()]);
        let err = s
            .scan(&ch2)
            .expect_err("the plaintext hello must NOT be swallowed by the phantom");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn post_ccs_continuation_into_nonhello_phantom_tears_down_framing() {
        // The continuation deny's other arm: a post-CCS 0x16 arriving
        // while a NON-hello phantom is open. The server's deframer may be
        // clean (it decrypted the real flight the phantom was parsed
        // from) and would parse this record FRESH — a divergence the
        // scanner cannot resolve, so it fails closed on the framing
        // detail. Legitimate cost: none — no post-CCS client flight
        // fragments a handshake message (module docs point 3).
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0x0b, 0x10, 0x00, 0x00, 0x40, 0x11],
        ));
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &[0x5a; 8]));
        let err = scan_all(&wire).expect_err("a post-CCS continuation must tear down");
        torn_down(&err, TORN_DOWN_FRAMING);
    }

    #[test]
    fn protocol_violating_no_ccs_ciphertext_tears_down() {
        // Fail-closed deny pin for a wire NO real TLS 1.3 client emits
        // (module docs point 3; TLS 1.3 protected records ride outer 0x17
        // — see the tls13_* pins below): a ciphertext-shaped 0x16 record
        // with no preceding CCS — a protocol-violating TLS 1.2 client
        // skipping its mandatory CCS, fatal server-side anyway. It parses
        // as a plaintext phantom in the STRICT pre-CCS phase: random first
        // byte ≠ 0x01 with a 24-bit length overshooting the record, then
        // an application-data record ⇒ TORN_DOWN_FRAMING at the 0x17; a
        // 0x01 first byte ⇒ the plaintext type-byte deny fires at the
        // record itself ⇒ TORN_DOWN_SECOND_HELLO.
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0xC1, 0x4F, 0x00, 0x10, 0x9A, 0x3E],
        ));
        wire.extend_from_slice(&rec(0x17, b"app data"));
        let err =
            scan_all(&wire).expect_err("a no-CCS 0x16 phantom must tear down at its first 0x17");
        torn_down(&err, TORN_DOWN_FRAMING);
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0x01, 0x4F, 0x00, 0x10, 0x9A, 0x3E],
        ));
        wire.extend_from_slice(&rec(0x17, b"app data"));
        let err = scan_all(&wire).expect_err("the 0x01-leading variant tears down at the record");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    /// The real TLS 1.3 client wires (module docs point 3): every
    /// protected record — encrypted flight incl. Finished, application
    /// data, KeyUpdate — rides OUTER 0x17 (RFC 8446 §5.2), so the scanner
    /// never message-parses it. Bodies are shaped to misparse were they
    /// ever parsed (a leading 0x01, a bogus overshooting 24-bit length).
    fn tls13_protected(body: &[u8]) -> Vec<u8> {
        rec(0x17, body)
    }

    #[test]
    fn tls13_no_ccs_client_passes() {
        // Compat mode OFF (RFC 8446 App-D.4 MAY): no CCS ever arrives —
        // the scanner stays in the strict phase and must still pass.
        let mut wire = tls13_protected(&[0x01, 0xFF, 0xFF, 0x00, 0x77, 0x88]);
        wire.extend_from_slice(&tls13_protected(b"app data"));
        wire.extend_from_slice(&tls13_protected(b"more app data"));
        scan_all(&wire).expect("a no-CCS TLS 1.3 client must pass");
    }

    #[test]
    fn tls13_compat_ccs_client_passes() {
        // Compat mode ON: the middlebox CCS, then the protected flight,
        // app data, and a KeyUpdate-shaped protected record.
        let mut wire = ccs_rec();
        wire.extend_from_slice(&tls13_protected(&[0x01, 0xFF, 0xFF, 0x00, 0x77, 0x88]));
        wire.extend_from_slice(&tls13_protected(b"app data"));
        wire.extend_from_slice(&tls13_protected(&[
            0x18, 0x00, 0x00, 0x01, 0x00, 0x17, 0, 0,
        ]));
        scan_all(&wire).expect("a compat-CCS TLS 1.3 client must pass");
    }

    #[test]
    fn tls13_plaintext_second_hello_after_protected_flight_tears_down() {
        // The protected flight being inert must not open a hole: a
        // plaintext CH2 (outer 0x16) after it tears down in BOTH phases.
        for lead in [Vec::new(), ccs_rec()] {
            let mut wire = lead;
            wire.extend_from_slice(&tls13_protected(&[0x01, 0xFF, 0xFF, 0x00, 0x77, 0x88]));
            wire.extend_from_slice(&tls13_protected(b"app data"));
            wire.extend_from_slice(&hs_rec(&[&hello_msg()]));
            let err = scan_all(&wire).expect_err("a plaintext CH2 must tear down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
        }
    }

    /// The round-2 alert-mask attack PIPELINED into the replay tail
    /// (inspect_tls passes a trailing 0x14 — only 0x16 tails deny): the
    /// pre-feed runs the same state machine, so the attack dies before a
    /// single upstream byte — no timing race.
    #[test]
    fn relay_prefeed_stops_alert_masked_split_hello() {
        let ch1 = build_client_hello(Some("allowed.test"), &[]);
        let hello_end = first_record_end(&ch1).expect("fixture is one complete record");
        let mut replay = ch1;
        replay.extend_from_slice(&alert_masked_split_hello_attack());
        let (client, _client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        block_on(async {
            let mut up = upstream;
            let relay_end = relay(client, &replay, Some(hello_end), &mut up).await;
            drop(up);
            let mut received = Vec::new();
            let _ = upstream_peer.read_to_end(&mut received).await;
            match relay_end.expect("a teardown is not a transport error") {
                RelayEnd::TornDown(detail) => assert_eq!(detail, Teardown::SecondHello),
                other => panic!("the pre-feed must tear down on the alert mask: {other:?}"),
            }
            assert!(received.is_empty(), "the pre-feed runs BEFORE write_all");
        });
    }

    #[test]
    fn relay_reports_transport_errors_as_err() {
        // The RelayEnd taxonomy's Err arm (round-2 review fix): a
        // transport failure is NOT a teardown — the caller swallows it as
        // normal lifecycle and the sink's teardown hook stays silent.
        let (client, _client_peer) = duplex(64 * 1024);
        let (upstream, upstream_peer) = duplex(64 * 1024);
        drop(upstream_peer); // the replay write fails
        block_on(async {
            let mut up = upstream;
            let relay_end = relay(client, b"payload", None, &mut up).await;
            assert!(
                relay_end.is_err(),
                "a dead upstream must surface as Err: {relay_end:?}"
            );
        });
    }

    #[test]
    fn malformed_ccs_does_not_relax_the_scanner() {
        // The CCS flip is strict: only the exactly-one-byte [0x01] record
        // servers accept moves the scanner into the deferred phase. After a
        // malformed "CCS" the strict plaintext policy stays armed — the
        // phantom-message artifact that a valid CCS would pass tears down
        // instead (fail-closed; a malformed CCS kills the server session
        // anyway).
        let artifact = rec(RECORD_HANDSHAKE, &[0x0b, 0x10, 0x00, 0x00, 0x40, 0x11]);
        // Wrong body byte:
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(RECORD_CCS, &[0x02]));
        wire.extend_from_slice(&artifact);
        wire.extend_from_slice(&rec(0x17, b"data"));
        let err = scan_all(&wire).expect_err("strict phase must survive a malformed CCS");
        torn_down(&err, TORN_DOWN_FRAMING);
        // Zero-length body:
        let mut wire = Vec::new();
        wire.extend_from_slice(&rec(RECORD_CCS, &[]));
        wire.extend_from_slice(&artifact);
        wire.extend_from_slice(&rec(0x17, b"data"));
        let err = scan_all(&wire).expect_err("a zero-length CCS must not relax either");
        torn_down(&err, TORN_DOWN_FRAMING);
        // The contrast pin: the SAME tail after a valid CCS passes.
        let mut ok_wire = ccs_rec();
        ok_wire.extend_from_slice(&artifact);
        ok_wire.extend_from_slice(&rec(0x17, b"data"));
        scan_all(&ok_wire).expect("a valid CCS relaxes to the deferred phase");
    }

    #[test]
    fn scanned_wrapper_only_scans_the_read_delta() {
        // The C3 pin (review fix): tokio's CopyBuffer re-enters poll_read
        // with the stale tail of its buffer pre-marked filled
        // (`set_filled(cap)`) after a partial-write Pending cycle. The
        // wrapper must scan ONLY the delta. Reproduction: a previous cycle
        // left a partial record header scanned-and-forwarded; the fresh
        // bytes complete it into a zero-length ClientHello (type byte ⇒
        // teardown). Re-ingesting the stale prefix instead desyncs the
        // header (length 0x1603) and SWALLOWS the hello — the missed
        // detection this pin fails on.
        let stale = [RECORD_HANDSHAKE, 0x03, 0x03]; // partial record header
        let fresh = [0x00, 0x04, HANDSHAKE_CLIENT_HELLO, 0x00, 0x00, 0x00];
        let (inner, mut peer) = duplex(64 * 1024);
        block_on(async {
            peer.write_all(&fresh).await.expect("peer write");
            let mut scanner = RelayScanner::new();
            scanner.scan(&stale).expect("the previous cycle passed");
            let mut scanned = Scanned { inner, scanner };
            let mut raw = vec![0u8; 64];
            raw[..stale.len()].copy_from_slice(&stale);
            let mut rb = ReadBuf::new(&mut raw);
            rb.set_filled(stale.len());
            let res =
                std::future::poll_fn(|cx| Pin::new(&mut scanned).poll_read(cx, &mut rb)).await;
            let err = res.expect_err("the delta completes a ClientHello header ⇒ teardown");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
            // The stale prefix stays untouched (only the delta moved).
            assert_eq!(&raw[..stale.len()], &stale[..]);
        });
    }

    // ---- invariants --------------------------------------------------------

    #[test]
    fn chunk_split_invariance() {
        // The verdict depends only on the byte stream, never on chunking:
        // every scenario fed whole, byte-at-a-time, and in two halves must
        // agree (same Ok/Err and the same pinned detail).
        let hello_flight = hs_rec(&[&hello_msg()]);
        let cert_flight = hs_rec(&[&hs(0x0b, &[0x01, 0x02, 0x03])]);
        let mut ccs_masked = Vec::new();
        ccs_masked.extend_from_slice(&ccs_rec());
        ccs_masked.extend_from_slice(&hs_rec(&[&hello_msg()]));
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&ccs_rec());
        ciphertext.extend_from_slice(&rec(RECORD_HANDSHAKE, &[0x01, 0xFF, 0xFF, 0x00, 0x77]));
        ciphertext.extend_from_slice(&rec(0x17, b"x"));
        let ccs_mid_fragment = ccs_mid_fragment_attack();
        let alert_masked = alert_masked_split_hello_attack();
        // The partial-header mask ([0x01, 0x00] + alert + rest).
        let partial_mask = {
            let msg = hello_msg();
            let mut w = ccs_rec();
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..2]));
            w.extend_from_slice(&rec(0x15, &[0x01, 0x5a]));
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[2..]));
            w
        };
        // The 0x17-mask variant.
        let early_data_mask = {
            let msg = hello_msg();
            let split = 6;
            let mut w = ccs_rec();
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
            w.extend_from_slice(&rec(0x17, b"rejected early data"));
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[split..]));
            w
        };
        // The retained mask: a 0x01-leading phantom survives its app-data
        // interrupts (retention — the round-3 availability side).
        let retained_mask = {
            let mut w = ccs_rec();
            w.extend_from_slice(&rec(
                RECORD_HANDSHAKE,
                &[0x01, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB],
            ));
            w.extend_from_slice(&rec(0x15, &[0x01, 0x5a]));
            w.extend_from_slice(&rec(0x17, b"app data"));
            w
        };
        // The continuation into the retained mask (the round-3 deny).
        let retained_mask_continuation = {
            let mut w = retained_mask.clone();
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &[0x5a; 8]));
            w
        };
        // The chosen-nonce phantom + swallowed-hello shape (round-3).
        let chosen_nonce = {
            let mut phantom_body = vec![HANDSHAKE_CLIENT_HELLO, 0xff, 0xff, 0xff];
            phantom_body.extend_from_slice(&[0x11; 32]);
            let mut w = ccs_rec();
            w.extend_from_slice(&rec(RECORD_HANDSHAKE, &phantom_body));
            w.extend_from_slice(&hs_rec(&[&hello_msg()]));
            w
        };
        // The protocol-violating no-CCS ciphertext-0x16 wire.
        let no_ccs = {
            let mut w = rec(RECORD_HANDSHAKE, &[0xC1, 0x4F, 0x00, 0x10, 0x9A, 0x3E]);
            w.extend_from_slice(&rec(0x17, b"app data"));
            w
        };
        for wire in [
            &hello_flight[..],
            &cert_flight[..],
            &ccs_masked[..],
            &ciphertext[..],
            &ccs_mid_fragment[..],
            &alert_masked[..],
            &partial_mask[..],
            &early_data_mask[..],
            &retained_mask[..],
            &retained_mask_continuation[..],
            &chosen_nonce[..],
            &no_ccs[..],
        ] {
            let whole = scan_all(wire);
            // Byte-at-a-time.
            let mut s = RelayScanner::new();
            let mut bytewise = Ok(());
            for chunk in wire.chunks(1) {
                if let Err(err) = s.scan(chunk) {
                    bytewise = Err(err);
                    break;
                }
            }
            // Two halves (the teardown may fire in either).
            let mid = wire.len() / 2;
            let mut s = RelayScanner::new();
            let halved = s.scan(&wire[..mid]).and_then(|()| s.scan(&wire[mid..]));
            for (label, got) in [("bytewise", bytewise), ("halved", halved)] {
                match (&whole, &got) {
                    (Ok(()), Ok(())) => {}
                    (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "{label}"),
                    _ => panic!("{label} disagrees with the whole feed: {whole:?} vs {got:?}"),
                }
            }
        }
    }

    #[test]
    fn scanner_never_panics_on_garbage() {
        // The never-panics pin (house rule, the ECH walker's shape): every
        // truncation of a handshake-bearing wire, single-byte mutations at
        // EVERY offset, and a garbage corpus — whole-fed AND byte-fed.
        let mut base = Vec::new();
        base.extend_from_slice(&hs_rec(&[&hello_msg()]));
        base.extend_from_slice(&ccs_rec());
        base.extend_from_slice(&hs_rec(&[&hs(0x0b, &[0xDE, 0xAD])]));
        base.extend_from_slice(&rec(0x17, b"tail"));
        base.extend_from_slice(&ccs_mid_fragment_attack());
        base.extend_from_slice(&alert_masked_split_hello_attack());
        let corpus: Vec<Vec<u8>> = {
            let mut v = Vec::new();
            for cut in 0..=base.len() {
                v.push(base[..cut].to_vec());
            }
            for pos in 0..base.len() {
                for byte in [0x00u8, 0xff, RECORD_HANDSHAKE, RECORD_CCS] {
                    let mut m = base.clone();
                    m[pos] = byte;
                    v.push(m);
                }
            }
            v.push(vec![0xff; 64]);
            v.push(vec![RECORD_HANDSHAKE, 0x03, 0x03, 0xff, 0xff]);
            v.push(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n".to_vec());
            v
        };
        for wire in &corpus {
            let _ = scan_all(wire);
            let mut s = RelayScanner::new();
            for chunk in wire.chunks(1) {
                if s.scan(chunk).is_err() {
                    break;
                }
            }
        }
    }

    // ---- the relay() level (module docs points 5/6) ------------------------

    /// The second-hello relay pin: CH1 is replayed upstream verbatim, the
    /// sequential CH2 (the post-HRR attack shape) trips the scanner — the
    /// upstream NEVER sees it and the relay ends with the pinned teardown.
    /// (The peers run as spawned tasks — the tokio `macros` feature, and
    /// with it `join!`, is deliberately NOT enabled; `rt` is.)
    #[test]
    fn relay_tears_down_on_sequential_second_hello() {
        let ch1 = build_client_hello(Some("allowed.test"), &[]);
        let hello_end = first_record_end(&ch1).expect("fixture is one complete record");
        let ch2 = build_client_hello(Some("evil.test"), &[]);
        let (client, mut client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        block_on(async {
            let peer_task = tokio::spawn(async move {
                client_peer.write_all(&ch2).await.expect("peer write");
                let mut back = Vec::new();
                let _ = client_peer.read_to_end(&mut back).await; // EOF on teardown
                back
            });
            let upstream_task = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = upstream_peer.read_to_end(&mut got).await; // EOF when relay drops
                got
            });
            // The inline relay OWNS both streams and drops them when the
            // teardown returns — that drop is the EOF the two peer readers
            // wait for (mirrors handle_connection's scope-end drop).
            let mut up = upstream;
            let relay_end = relay(client, &ch1, Some(hello_end), &mut up).await;
            drop(up);
            let back = peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            match relay_end.expect("a teardown is not a transport error") {
                RelayEnd::TornDown(detail) => assert_eq!(detail, Teardown::SecondHello),
                other => panic!("the scanner must tear the relay down: {other:?}"),
            }
            assert_eq!(
                received, ch1,
                "the upstream must see EXACTLY the first hello"
            );
            assert!(back.is_empty(), "no bytes may come back after a teardown");
        });
    }

    /// The pre-feed pin (module docs point 6): a CH2 hidden behind a
    /// legitimate pipelined CCS record (inspect_tls passes that tail) trips
    /// the pre-feed scan — the upstream sees NOTHING, not even the replay.
    #[test]
    fn relay_prefeed_tears_down_before_any_upstream_byte() {
        let ch1 = build_client_hello(Some("allowed.test"), &[]);
        let hello_end = first_record_end(&ch1).expect("fixture is one complete record");
        let mut replay = ch1;
        replay.extend_from_slice(&ccs_rec());
        replay.extend_from_slice(&hs_rec(&[&hello_msg()]));
        let (client, _client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        block_on(async {
            let mut up = upstream;
            // The pre-feed errors synchronously, before write_all: nothing
            // ever reaches the upstream.
            let relay_end = relay(client, &replay, Some(hello_end), &mut up).await;
            drop(up);
            let mut received = Vec::new();
            let _ = upstream_peer.read_to_end(&mut received).await;
            match relay_end.expect("a teardown is not a transport error") {
                RelayEnd::TornDown(detail) => assert_eq!(detail, Teardown::SecondHello),
                other => panic!("the pre-feed must tear down: {other:?}"),
            }
            assert!(received.is_empty(), "the pre-feed runs BEFORE write_all");
        });
    }

    /// The C1 pre-feed pin: the mid-fragment-CCS attack PIPELINED into the
    /// replay tail (inspect_tls passes a trailing 0x14 — only 0x16 tails
    /// deny) dies in the pre-feed: zero upstream bytes.
    #[test]
    fn relay_prefeed_stops_ccs_mid_fragment_masking() {
        let ch1 = build_client_hello(Some("allowed.test"), &[]);
        let hello_end = first_record_end(&ch1).expect("fixture is one complete record");
        let mut replay = ch1;
        replay.extend_from_slice(&ccs_mid_fragment_attack());
        let (client, _client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        block_on(async {
            let mut up = upstream;
            let relay_end = relay(client, &replay, Some(hello_end), &mut up).await;
            drop(up);
            let mut received = Vec::new();
            let _ = upstream_peer.read_to_end(&mut received).await;
            match relay_end.expect("a teardown is not a transport error") {
                RelayEnd::TornDown(detail) => assert_eq!(detail, Teardown::TlsFraming),
                other => panic!("the pre-feed must tear down on the mid-fragment CCS: {other:?}"),
            }
            assert!(received.is_empty(), "the pre-feed runs BEFORE write_all");
        });
    }

    /// The HTTP-path pin: `scan_from: None` keeps the plain relay shape —
    /// arbitrary bytes (which would be framing violations on 443) flow.
    #[test]
    fn relay_without_scan_from_is_unscanned() {
        let payload = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\nbody";
        let (client, mut client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        block_on(async {
            let peer_task = tokio::spawn(async move {
                client_peer.shutdown().await.expect("shutdown"); // ends the client→upstream copy
            });
            let upstream_task = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = upstream_peer.read_to_end(&mut got).await; // EOF via the copy's shutdown
                // shutdown is the upstream→client EOF.
                upstream_peer.shutdown().await.expect("shutdown");
                got
            });
            let mut up = upstream;
            let relay_end = relay(client, payload, None, &mut up).await;
            drop(up);
            peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            assert!(
                matches!(relay_end, Ok(RelayEnd::Finished)),
                "the unscanned relay must succeed: {relay_end:?}"
            );
            assert_eq!(received, payload);
        });
    }

    /// The pass-through pin: a legitimate TLS 1.2 client tail after the
    /// hello (Certificate/CKX/CertVerify, CCS, encrypted Finished, app
    /// data) relays WITHOUT a teardown, byte-exact.
    #[test]
    fn relay_passes_a_legitimate_tls12_tail() {
        let ch1 = build_client_hello(Some("allowed.test"), &[]);
        let hello_end = first_record_end(&ch1).expect("fixture is one complete record");
        let mut tail = Vec::new();
        tail.extend_from_slice(&hs_rec(&[
            &hs(0x0b, &[0x00, 0x01, 0x55]),
            &hs(0x10, &[0x21]),
            &hs(0x0f, &[0x04, 0x03, 0x77, 0x66]),
        ]));
        tail.extend_from_slice(&ccs_rec());
        // "Encrypted Finished": ciphertext-shaped (random first byte, a
        // 24-bit length that never tiles) — must pass, not tear down.
        tail.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0xC1, 0x4F, 0x00, 0x10, 0x9A, 0x3E],
        ));
        tail.extend_from_slice(&rec(0x17, b"GET / HTTP/1.1\r\n\r\n"));
        let (client, mut client_peer) = duplex(64 * 1024);
        let (upstream, mut upstream_peer) = duplex(64 * 1024);
        // The peer task owns the wire copy; `expected` keeps the assertion
        // copy (byte-equality is the whole point of this pin).
        let wire_tail = tail.clone();
        block_on(async {
            let peer_task = tokio::spawn(async move {
                client_peer.write_all(&wire_tail).await.expect("peer write");
                client_peer.shutdown().await.expect("shutdown");
            });
            let upstream_task = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = upstream_peer.read_to_end(&mut got).await;
                // The copy returns only once BOTH directions end: this
                // shutdown is the upstream→client EOF.
                upstream_peer.shutdown().await.expect("shutdown");
                got
            });
            let mut up = upstream;
            let relay_end = relay(client, &ch1, Some(hello_end), &mut up).await;
            drop(up);
            peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            assert!(
                matches!(relay_end, Ok(RelayEnd::Finished)),
                "a legitimate tail must not tear down: {relay_end:?}"
            );
            let mut expected = ch1;
            expected.extend_from_slice(&tail);
            assert_eq!(received, expected, "every byte must reach the upstream");
        });
    }

    // ---- the per-request relay (issue #29, F3) -----------------------------

    /// What one [`run_http`] exchange observed.
    struct Harness {
        /// Every byte the upstream received before its quiet deadline.
        upstream_received: Vec<u8>,
        /// Every byte the client received (until the relay closed it).
        client_received: Vec<u8>,
        end: io::Result<HttpEnd>,
    }

    /// A keep-alive-capable request-1 meta (HTTP/1.1, no body, no close).
    fn keep_alive() -> RequestMeta {
        RequestMeta {
            framing: super::super::http::Framing::None,
            minor_version: 1,
            close: false,
            upgrade: false,
        }
    }

    /// Drive `relay_http` over duplex pairs. The client writes `steps` (each
    /// after its delay in ms), then half-closes when `half_close`. The upstream
    /// collects bytes until 400 ms of quiet, then answers a 200 and closes.
    async fn run_http(
        head: &[u8],
        first: RequestMeta,
        pending: &[u8],
        steps: Vec<(u64, Vec<u8>)>,
        half_close: bool,
        limits: Limits,
    ) -> Harness {
        let (server_side, mut client_peer) = tokio::io::duplex(64 * 1024);
        let (mut upstream, mut up_peer) = tokio::io::duplex(64 * 1024);
        let up_task = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                // Longer than small_limits' decision timeout, so a stalled head
                // is torn down by the relay before the upstream's EOF arrives.
                let quiet = Duration::from_millis(400);
                match tokio::time::timeout(quiet, up_peer.read(&mut chunk)).await {
                    Ok(Ok(n)) if n > 0 => seen.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            let _ = up_peer
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = up_peer.shutdown().await;
            seen
        });
        let head = head.to_vec();
        let pending = pending.to_vec();
        let relay_task = tokio::spawn(async move {
            let start = HttpStart {
                binding: HttpBinding {
                    name: Domain::parse("allowed.test").expect("name"),
                    port: 80,
                    flavor: HttpFlavor::Transparent,
                },
                first,
                pending,
            };
            relay_http(server_side, &head, start, &mut upstream, &limits).await
        });
        let client_task = tokio::spawn(async move {
            for (delay_ms, bytes) in steps {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                if client_peer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            if half_close {
                let _ = client_peer.shutdown().await;
            }
            let mut got = Vec::new();
            let _ = client_peer.read_to_end(&mut got).await;
            got
        });
        let end = relay_task.await.expect("relay task");
        let upstream_received = up_task.await.expect("upstream task");
        let client_received = client_task.await.expect("client task");
        Harness {
            upstream_received,
            client_received,
            end,
        }
    }

    fn small_limits() -> Limits {
        Limits {
            decision_timeout: Duration::from_millis(200),
            ..Limits::default()
        }
    }

    const GET1: &[u8] = b"GET /a HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
    const GET2: &[u8] = b"GET /b HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
    const GET3: &[u8] = b"GET /c HTTP/1.1\r\nHost: allowed.test\r\n\r\n";

    fn torn(end: &io::Result<HttpEnd>) -> Teardown {
        match end {
            Ok(HttpEnd::TornDown(teardown)) => teardown.clone(),
            other => panic!("expected a teardown: {other:?}"),
        }
    }

    #[test]
    fn http_keepalive_two_gets_forwarded_verbatim() {
        block_on(async {
            // Request 2 in its own write: forwarded byte-identical, no close
            // inserted on either keep-alive request.
            let got = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, GET2.to_vec())],
                true,
                small_limits(),
            )
            .await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(GET2);
            assert_eq!(got.upstream_received, want);
            assert!(matches!(got.end, Ok(HttpEnd::Finished)), "{:?}", got.end);
            assert!(got.client_received.starts_with(b"HTTP/1.1 200 OK"));
        });
    }

    #[test]
    fn http_pipelined_gets_in_one_write() {
        block_on(async {
            // Requests 2 and 3 already sit in the pending bytes of request 1's read.
            let mut pending = GET2.to_vec();
            pending.extend_from_slice(GET3);
            let got = run_http(GET1, keep_alive(), &pending, vec![], true, small_limits()).await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(&pending);
            assert_eq!(got.upstream_received, want);
        });
    }

    #[test]
    fn http_foreign_host_second_request_torn_down() {
        block_on(async {
            let evil: &[u8] = b"GET /b HTTP/1.1\r\nHost: evil.test\r\n\r\n";
            let got = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, evil.to_vec())],
                true,
                small_limits(),
            )
            .await;
            // The upstream saw request 1 only; the denied head never left.
            assert_eq!(got.upstream_received, GET1.to_vec());
            assert_eq!(
                torn(&got.end).detail(),
                "relay torn down: HTTP request 2 denied: HTTP Host evil.test does not match the DNS-map name allowed.test"
            );
        });
    }

    #[test]
    fn http_post_body_last_then_after_last_not_forwarded() {
        block_on(async {
            // Request 2 is a POST with a body: it is LAST, so the close token
            // goes in, the body is forwarded, and the pipelined request 3 after
            // the body is never forwarded (module docs point 7 of h1.rs).
            let post_head = b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\r\n\r\n";
            let mut tail = post_head.to_vec();
            tail.extend_from_slice(b"body");
            tail.extend_from_slice(GET3);
            let got = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, tail)],
                true,
                small_limits(),
            )
            .await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
            assert_eq!(got.upstream_received, want);
            assert!(matches!(got.end, Ok(HttpEnd::Finished)), "{:?}", got.end);
        });
    }

    #[test]
    fn http_chunked_body_then_after_last_not_forwarded() {
        block_on(async {
            let chunked_head =
                b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n";
            let mut tail = chunked_head.to_vec();
            tail.extend_from_slice(b"3\r\nabc\r\n0\r\n\r\n");
            tail.extend_from_slice(GET3);
            let got = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, tail)],
                true,
                small_limits(),
            )
            .await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
            assert_eq!(got.upstream_received, want);
        });
    }

    #[test]
    fn http_bad_chunk_line_torn_down_before_forwarding() {
        block_on(async {
            // Request 2's first chunk is valid, the second size line is not:
            // the valid chunk and the head are forwarded, the bad line never is.
            let mut bad =
                b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .to_vec();
            bad.extend_from_slice(b"3\r\nabc\r\nzz\r\n");
            let got = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, bad)],
                true,
                small_limits(),
            )
            .await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(b"POST /p HTTP/1.1\r\nHost: allowed.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n");
            assert_eq!(got.upstream_received, want);
            assert_eq!(
                torn(&got.end).detail(),
                "relay torn down: HTTP request 2 denied: ambiguous HTTP request framing: invalid chunk-size line"
            );
        });
    }

    #[test]
    fn http_second_head_too_large() {
        block_on(async {
            let limits = Limits {
                max_head_bytes: 64,
                ..small_limits()
            };
            let mut flood = b"GET /".to_vec();
            flood.extend(std::iter::repeat_n(b'X', 200));
            let got = run_http(GET1, keep_alive(), b"", vec![(0, flood)], true, limits).await;
            assert_eq!(got.upstream_received, GET1.to_vec());
            assert_eq!(
                torn(&got.end).detail(),
                "relay torn down: HTTP request 2 denied: HTTP request head exceeds the 64-byte cap"
            );
        });
    }

    #[test]
    fn http_second_head_timeout_starts_at_first_byte() {
        block_on(async {
            // A partial second head that stalls past the decision timeout is
            // torn down ...
            let stalled = run_http(
                GET1,
                keep_alive(),
                b"",
                vec![(0, b"GET /b HTTP/1.1\r\n".to_vec())],
                false,
                small_limits(),
            )
            .await;
            assert!(
                torn(&stalled.end)
                    .detail()
                    .starts_with("relay torn down: HTTP request 2 denied: decision-phase timeout"),
                "{:?}",
                stalled.end
            );
            // ... but a PAUSE between requests longer than the timeout is
            // allowed: the deadline starts at the second head's first byte.
            let paused = run_http(
                GET1,
                keep_alive(),
                b"",
                // 300 ms: longer than the 200 ms decision timeout, shorter than the
                // upstream's 400 ms quiet window.
                vec![(300, GET2.to_vec())],
                true,
                small_limits(),
            )
            .await;
            let mut want = GET1.to_vec();
            want.extend_from_slice(GET2);
            assert_eq!(paused.upstream_received, want);
            assert!(
                matches!(paused.end, Ok(HttpEnd::Finished)),
                "{:?}",
                paused.end
            );
        });
    }

    #[test]
    fn http_client_eof_shuts_upstream_and_upstream_eof_ends_segment() {
        block_on(async {
            // Client half-close: the upstream sees EOF after the head, answers,
            // and the relay ends with the client's clean EOF after the reply.
            let got = run_http(GET1, keep_alive(), b"", vec![], true, small_limits()).await;
            assert_eq!(got.upstream_received, GET1.to_vec());
            assert!(matches!(got.end, Ok(HttpEnd::Finished)), "{:?}", got.end);
            assert_eq!(
                got.client_received,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
            );
        });
    }

    #[test]
    fn after_last_request_forwards_nothing_more() {
        block_on(async {
            // A `close` request is last: the pipelined GET after it is discarded.
            let close = RequestMeta {
                close: true,
                ..keep_alive()
            };
            let close_head = b"GET /a HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
            let got = run_http(close_head, close, GET2, vec![], false, small_limits()).await;
            assert_eq!(got.upstream_received, close_head.to_vec());
            assert!(matches!(got.end, Ok(HttpEnd::Finished)), "{:?}", got.end);
        });
    }

    #[test]
    fn forward_pipelined_second_request_never_forwarded() {
        // Explicit forward is one request per connection (explicit module docs
        // point 12): any pipelined follow-up is dropped, whatever its authority.
        block_on(async {
            let forward = RequestMeta {
                close: true,
                ..keep_alive()
            };
            let rewritten = b"GET /a HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n";
            let other = b"GET /b HTTP/1.1\r\nHost: other.test\r\n\r\n";
            let got = run_http(rewritten, forward, other, vec![], false, small_limits()).await;
            assert_eq!(got.upstream_received, rewritten.to_vec());
        });
    }

    #[test]
    fn teardown_detail_pinned() {
        // Module docs point 9: the three arms, byte-exact.
        assert_eq!(Teardown::SecondHello.detail(), TORN_DOWN_SECOND_HELLO);
        assert_eq!(Teardown::TlsFraming.detail(), TORN_DOWN_FRAMING);
        let request = Teardown::Request {
            index: 2,
            rejected: Rejected::HostMismatch {
                host: Domain::parse("evil.test").expect("host"),
                name: Domain::parse("allowed.test").expect("name"),
                source: NameSource::DnsMap,
            },
        };
        assert_eq!(
            request.detail(),
            "relay torn down: HTTP request 2 denied: HTTP Host evil.test does not match the DNS-map name allowed.test"
        );
    }

    #[test]
    fn activity_in_either_direction_resets_idle() {
        // Payload in EITHER direction keeps the relay alive; only silence ends it.
        block_on(async {
            let act = Activity::new();
            let (mut far, near) = tokio::io::duplex(4096);
            let mut watched = Watched::new(near, act.clone());
            let writer = tokio::spawn(async move {
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    far.write_all(b"x").await.expect("far write");
                }
                far.shutdown().await.expect("far shutdown");
            });
            let mut seen = 0usize;
            let relayed = until_idle(&act, Duration::from_millis(80), async {
                let mut one = [0u8; 1];
                while let Ok(1) = watched.read(&mut one).await {
                    seen += 1;
                }
            })
            .await;
            writer.await.expect("writer");
            assert!(
                relayed.is_some(),
                "payload every 20 ms must not trip an 80 ms idle bound"
            );
            assert_eq!(seen, 10);
        });
    }

    #[test]
    fn idle_watchdog_fires_without_activity() {
        block_on(async {
            let act = Activity::new();
            let (_far, near) = tokio::io::duplex(4096);
            let mut watched = Watched::new(near, act.clone());
            let relayed = until_idle(&act, Duration::from_millis(30), async {
                let mut one = [0u8; 1];
                let _ = watched.read(&mut one).await;
            })
            .await;
            assert!(relayed.is_none(), "silence must trip the watchdog");
        });
    }
}
