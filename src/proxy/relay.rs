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
//!    so the parser becomes best-effort — a ClientHello tears down only
//!    when its message COMPLETES (a real second hello must complete for any
//!    server to act on it, including one reassembling a fragmented
//!    handshake message), while framing artifacts pass and resync at the
//!    next record boundary. The trade-off is deliberate: deny-on-artifact
//!    would break EVERY TLS 1.2 connection at its encrypted Finished;
//!    pass-through costs at most an invisible ENCRYPTED renegotiation hello
//!    — which no non-terminating proxy can see (documented residual, proxy
//!    module docs point 12). Plaintext post-CCS ClientHellos (the
//!    CCS-masked CH2 in ANY record order, and insecure-renegotiation
//!    shapes) still complete and still tear down. A CCS record NEVER
//!    interrupts message tracking: a mid-fragment CCS tears down in BOTH
//!    phases (review fix C1) — CCS is the one record type real servers
//!    ignore and reassemble across (RFC 8446 §5; rustls's middlebox budget
//!    is 2 and its deframer spans survive; OpenSSL likewise), so resyncing
//!    there would let a split CH2 complete upstream. Recorded residuals of
//!    the deferred policy (Q4 family): an encrypted TLS 1.2 renegotiation
//!    whose CCS arrives while a phantom ciphertext-parsed message is open
//!    tears the connection down (renegotiation with zero intervening
//!    application-data records — practically extinct), and the symmetric
//!    false-teardown: an encrypted Finished whose first ciphertext byte is
//!    0x01 (~1/256) arms a deferred hello that fires only if its random
//!    24-bit length drains exactly across consecutive client 0x16 records
//!    (~2^-24 combined) — recorded for honesty, not mitigated.
//! 4. **Record framing is the trust anchor** — the record layer (5-byte
//!    header, big-endian length) is plaintext in EVERY TLS version, and
//!    both endpoints parse it identically: bytes this scanner passes inside
//!    a record body can never be re-interpreted as a record header by the
//!    server. ONE divergence is policed explicitly: servers IGNORE a CCS
//!    record and keep reassembling an open handshake message across it, so
//!    the scanner tears down on a mid-message CCS instead of resyncing
//!    (review fix C1, point 3). Oversized or bogus lengths are passed
//!    through — the server's own record-layer limits and decryption checks
//!    reject them; the scanner's job is only the ClientHello deny.
//! 5. **Teardown semantics** — a teardown is an `io::Error` surfaced
//!    through [`Scanned`] (the client-side `AsyncRead` wrapper): the chunk
//!    that tripped it is NEVER forwarded, [`relay`] returns the error, and
//!    the caller (`handle_connection`) treats it as normal relay lifecycle
//!    — both sockets drop (FIN/RST). The single [`crate::proxy::Decision`]
//!    was already recorded (Allowed) BEFORE the first relay byte; there is
//!    NO second record (`exactly_one_decision_per_connection` stays true).
//!    The two pinned detail strings below are the test-visible identity of
//!    the two teardown classes.
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
//!    are scanned; the HTTP path passes `scan_from: None` and keeps the
//!    plain `copy_bidirectional` shape.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};

/// The pinned teardown detail: a ClientHello (handshake type 0x01) after
/// the inspected one — plaintext-phase (immediate, on the type byte) or
/// post-CCS (on message completion).
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
    /// be ciphertext — the ClientHello deny becomes completion-deferred and
    /// framing artifacts pass instead of tearing down (module docs point 3).
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
    /// fragmented message continues in the NEXT handshake record).
    msg_left: usize,
    /// Post-CCS deferred teardown: the open message's type byte was 0x01 —
    /// fires when the message completes (module docs point 3).
    deferred_hello: bool,
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
        }
    }

    /// A handshake message is mid-parse (header partially accumulated, or
    /// body bytes still owed): the next record MUST be a handshake record
    /// (a legal fragmentation continuation) — anything else is a framing
    /// violation.
    fn msg_open(&self) -> bool {
        self.msg_hdr_len > 0 || self.msg_left > 0
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
                        // continuation — with ONE type policed
                        // separately: a CCS record is the ONE record type
                        // real servers IGNORE mid-reassembly and keep the
                        // fragment across (RFC 8446 §5 middlebox compat;
                        // rustls allows 2 and its deframer spans survive;
                        // OpenSSL's s3.tmp.buf likewise), so resyncing
                        // here would wipe a deferred/fragmented
                        // ClientHello and let it complete upstream
                        // (review fix C1). A mid-message CCS therefore
                        // tears down in BOTH phases — no legitimate client
                        // emits one (the TLS 1.3 middlebox CCS follows a
                        // CLOSED flight; the TLS 1.2 CCS follows the closed
                        // Cert/CKX/CV flight).
                        if self.ccs && ty != RECORD_CCS {
                            // Ciphertext-parse artifact (module docs point
                            // 3): drop the bogus message state and pass
                            // this record — resync at its boundary.
                            self.msg_hdr_len = 0;
                            self.msg_left = 0;
                            self.deferred_hello = false;
                        } else {
                            return Err(io::Error::other(TORN_DOWN_FRAMING));
                        }
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
                return Err(io::Error::other(TORN_DOWN_SECOND_HELLO));
            }
            if self.msg_hdr_len == 4 {
                let len = ((self.msg_hdr[1] as usize) << 16)
                    | ((self.msg_hdr[2] as usize) << 8)
                    | (self.msg_hdr[3] as usize);
                self.msg_left = len;
                self.msg_hdr_len = 0;
                // Post-CCS only: the deferred teardown arms on the type
                // byte and fires at completion (the pre-CCS deny above
                // already fired for plaintext hellos).
                self.deferred_hello = self.ccs && self.msg_hdr[0] == HANDSHAKE_CLIENT_HELLO;
                if self.msg_left == 0 && self.deferred_hello {
                    // A zero-length "ClientHello" is nonsense either way —
                    // fail closed on the completed type byte.
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

/// The relay phase: write the FULL replay buffer upstream (proxy module
/// docs point 9 — inspection consumed those bytes FROM the client), then
/// copy bidirectionally. On 443 (`scan_from: Some`) the client→upstream
/// direction runs through [`RelayScanner`], starting with the replay
/// buffer's pipelined tail (`replay[hello_end..]` — scanned BEFORE any
/// write, module docs point 6); on 80 (`None`) the plain
/// `copy_bidirectional` shape is kept.
///
/// Every error — write failure, copy failure, scanner teardown — returns
/// here; the caller (`handle_connection`) swallows it as normal relay
/// lifecycle and lets the drop close both sockets.
pub(crate) async fn relay<C, U>(
    client: C,
    replay: &[u8],
    scan_from: Option<usize>,
    upstream: &mut U,
) -> io::Result<()>
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
            scanner.scan(&replay[hello_end.min(replay.len())..])?;
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
            copy_bidirectional(&mut scanned, upstream).await?;
        }
        None => {
            let mut client = client;
            copy_bidirectional(&mut client, upstream).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::hello::{build_client_hello, first_record_end};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Hand-rolled current-thread block_on (the tokio `macros` feature is
    /// deliberately NOT enabled — proxy module docs point 8).
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
        // The TLS 1.2 survival case: after the client CCS, the encrypted
        // Finished (0x16 with a ciphertext body) and everything after it
        // must pass — a deny-on-artifact scanner would break every TLS 1.2
        // connection here. The "ciphertext" bytes are deliberately shaped
        // to misparse (a leading 0x01 = the random type-byte hit, a bogus
        // 24-bit length overshooting the record).
        let mut wire = Vec::new();
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&rec(
            RECORD_HANDSHAKE,
            &[0x01, 0xFF, 0xFF, 0x00, 0x77, 0x88],
        ));
        wire.extend_from_slice(&rec(0x17, b"app data"));
        scan_all(&wire).expect("post-CCS ciphertext artifacts must pass");
    }

    #[test]
    fn ccs_masked_second_hello_tears_down_on_completion() {
        // The CCS-mask bypass attempt: a middlebox CCS (ignored by TLS 1.3
        // servers) then a well-formed plaintext CH2. It parses cleanly and
        // completes inside its record ⇒ teardown — bytes withheld.
        let mut wire = Vec::new();
        wire.extend_from_slice(&ccs_rec());
        wire.extend_from_slice(&hs_rec(&[&hello_msg()]));
        let err = scan_all(&wire).expect_err("a completed post-CCS hello must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn ccs_masked_fragmented_hello_tears_down_at_completion() {
        // The fragmented CCS-mask shape: record 1 = header + partial body
        // (no verdict yet — ciphertext ambiguity), record 2 completes the
        // message ⇒ teardown. The completion chunk is withheld, so the
        // server can never reassemble the full hello.
        let msg = hello_msg();
        let split = 6;
        let mut s = RelayScanner::new();
        let mut wire = ccs_rec();
        wire.extend_from_slice(&rec(RECORD_HANDSHAKE, &msg[..split]));
        s.scan(&wire)
            .expect("an incomplete message must not tear down yet");
        let r2 = rec(RECORD_HANDSHAKE, &msg[split..]);
        let err = s.scan(&r2).expect_err("completion must tear down");
        torn_down(&err, TORN_DOWN_SECOND_HELLO);
    }

    #[test]
    fn post_ccs_framing_artifacts_resync_and_pass() {
        // Ciphertext garbage leaves a bogus open message; the next
        // application-data record is a "violation" that post-CCS policy
        // passes with a resync — and a LATER clean record parses normally
        // (still catching a real post-CCS hello).
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
    /// CCS₂ injected MID-FRAGMENT (the one record type servers ignore and
    /// reassemble across — resyncing there would wipe the deferred state
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
        for wire in [
            &hello_flight[..],
            &cert_flight[..],
            &ccs_masked[..],
            &ciphertext[..],
            &ccs_mid_fragment[..],
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
            let relay_res = relay(client, &ch1, Some(hello_end), &mut up).await;
            drop(up);
            let back = peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            let err = relay_res.expect_err("the scanner must tear the relay down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
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
            let relay_res = relay(client, &replay, Some(hello_end), &mut up).await;
            drop(up);
            let mut received = Vec::new();
            let _ = upstream_peer.read_to_end(&mut received).await;
            let err = relay_res.expect_err("the pre-feed must tear down");
            torn_down(&err, TORN_DOWN_SECOND_HELLO);
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
            let relay_res = relay(client, &replay, Some(hello_end), &mut up).await;
            drop(up);
            let mut received = Vec::new();
            let _ = upstream_peer.read_to_end(&mut received).await;
            let err = relay_res.expect_err("the pre-feed must tear down on the mid-fragment CCS");
            torn_down(&err, TORN_DOWN_FRAMING);
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
            let relay_res = relay(client, payload, None, &mut up).await;
            drop(up);
            peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            relay_res.expect("the unscanned relay must succeed");
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
            let relay_res = relay(client, &ch1, Some(hello_end), &mut up).await;
            drop(up);
            peer_task.await.expect("peer task");
            let received = upstream_task.await.expect("upstream task");
            relay_res.expect("a legitimate tail must not tear down");
            let mut expected = ch1;
            expected.extend_from_slice(&tail);
            assert_eq!(received, expected, "every byte must reach the upstream");
        });
    }
}
