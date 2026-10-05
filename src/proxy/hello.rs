//! TLS ClientHello inspection for port 443 (issue #7) — SNI check WITHOUT
//! terminating TLS, plus the ECH walker and the test-fixture wire builder.
//!
//! 1. **Parse, never handshake** — rustls's `server::Acceptor` structurally
//!    validates the ClientHello and extracts the rustls-validated SNI
//!    (lowercased, trailing root dot PRESERVED, IP literals → `None`).
//!    `Accepted::into_connection` is NEVER called — no crypto provider is
//!    installed (proxy module docs point 7), and the `AcceptedAlert` of a
//!    rejected hello is DROPPED, never written back (Q2: alerts would leak
//!    policy internals into the sandbox).
//! 2. **The read loop** — bounded by [`Limits::max_hello_bytes`] and (at the
//!    caller, [`crate::proxy::decide`]) by the decision timeout: a
//!    truncated hello can otherwise hold a connection open forever
//!    (`Ok(None)` on every feed). Each read chunk is appended to the replay
//!    buffer FIRST, then a COPY of exactly the new bytes is fed to the
//!    acceptor via `Cursor` — no byte is ever fed twice, and post-hello
//!    pipelined bytes survive in the buffer (proxy module docs point 9).
//!    `accept()` runs after every feed; acting only on `Ok(Some)` (the full
//!    hello buffered) is the incremental contract `fixture_split_feed_accepts`
//!    pins.
//! 3. **Denial order (pinned)** — [`Rejected::NotTls`] (first byte ≠ 0x16,
//!    checked once the buffer is non-empty: the cleaner "plaintext on 443"
//!    reason instead of rustls's InvalidContentType) → [`Rejected::Eof`]
//!    (read 0, or a transport error — the client is gone either way) →
//!    [`Rejected::HelloTooLarge`] (cap) → [`Rejected::HelloMalformed`]
//!    (rustls `Err`) → [`Rejected::EchOffered`] (walker) →
//!    [`Rejected::SniMissing`] / [`Rejected::SniMismatch`].
//! 4. **ECH is hand-walked** — rustls 0.23 exposes no raw-extension
//!    accessor, so [`offers_ech`] is a bounds-checked walker over the raw
//!    buffered record looking for extension type 0xfe0d. It runs on bytes
//!    rustls already accepted and BEFORE we act on the SNI verdict (a
//!    well-formed ECH hello parses fine in rustls — the walker is the
//!    load-bearing deny layer; a malformed one rustls rejects anyway ⇒
//!    fail-closed both ways). GREASE types (0x?a?a) are provably disjoint
//!    from 0xfe0d; the false-positive trade-off is Q4 (accepted).
//! 5. **Fixture wire** — [`build_client_hello`] is `pub` because
//!    `tests/sandbox_proxy.rs` (an external crate) must emit real
//!    ClientHello bytes over raw sockets from its payload roles. It is
//!    test-fixture wire only: no secrets, no behavior, byte-identical to
//!    the Phase-1 spike-verified builder. `signature_algorithms` is
//!    MANDATORY — rustls rejects a hello without it (PeerIncompatible),
//!    pinned by `fixture_without_sigalgs_is_rejected`.

use std::io::Cursor;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{Limits, Rejected, canonicalize_host};
use crate::policy::Domain;

/// The TLS record content type of a handshake message — the first byte of
/// every ClientHello record (the [`Rejected::NotTls`] pre-check).
const RECORD_HANDSHAKE: u8 = 0x16;

/// The `encrypted_client_hello` extension type (draft-ECH; the GREASE form
/// uses the same codepoint). Provably disjoint from every GREASE value
/// (0x?a?a): the high byte 0xfe has a low nibble of 0xe ≠ 0xa. ECH's
/// companion `encrypted_client_hello_outer_extensions` (0xfd00) is
/// deliberately NOT walked: it only appears in the INNER (encrypted)
/// hello, which never reaches us because every 0xfe0d outer is denied —
/// and a bare plaintext 0xfd00 is inert, with the SNI still visible and
/// checked.
const ECH_EXTENSION_TYPE: u16 = 0xfe0d;

/// The pinned denial detail when the raw buffer is not walkable as a
/// single-record ClientHello, so ECH presence cannot be PROVEN absent —
/// denied fail-closed (module docs point 4's scope note; the multi-record
/// shape is deviation #4's documented denial). Single source shared by
/// [`inspect_tls`] and its pin test.
const WALK_FAILED_DETAIL: &str = "ClientHello extension walk failed (ECH presence unverifiable)";

/// Per-read chunk size for the inspection loop (the caps, not this, bound
/// the buffer).
const READ_CHUNK: usize = 4096;

/// Build a minimal but rustls-acceptable TLS ClientHello record — TEST
/// FIXTURE WIRE (module docs point 5), shipped `pub` for the integration
/// suite's payload roles.
///
/// Shape: record header (0x16 0x03 0x01, then the record length) →
/// handshake header (0x01, then the 24-bit body length) → legacy_version
/// 0x0303 → 32-byte random → empty session_id → ONE cipher suite (0x1301)
/// → null compression → extensions: optional `server_name` (0x0000),
/// MANDATORY `signature_algorithms` (0x000d — rustls rejects without it),
/// then `extra_exts` verbatim (ECH injection: `(0xfe0d, data)`).
pub fn build_client_hello(sni: Option<&str>, extra_exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    build_client_hello_with(sni, extra_exts, true)
}

/// [`build_client_hello`] with the `signature_algorithms` extension
/// optional — private; only `fixture_without_sigalgs_is_rejected` passes
/// `false` (it pins WHY the fixture carries the extension).
fn build_client_hello_with(
    sni: Option<&str>,
    extra_exts: &[(u16, Vec<u8>)],
    sigalgs: bool,
) -> Vec<u8> {
    fn ext(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ty.to_be_bytes());
        // Test-fixture wire: extension payloads are tiny and caller-built;
        // a >64 KiB extension would truncate, which no fixture does.
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }
    fn sni_ext(name: &str) -> Vec<u8> {
        let nb = name.as_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&((3 + nb.len()) as u16).to_be_bytes());
        data.push(0x00); // NameType host_name
        data.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        data.extend_from_slice(nb);
        ext(0x0000, &data)
    }
    fn sigalgs_ext() -> Vec<u8> {
        let schemes: [u16; 3] = [0x0403, 0x0804, 0x0401];
        let mut data = Vec::new();
        data.extend_from_slice(&((2 * schemes.len()) as u16).to_be_bytes());
        for s in schemes {
            data.extend_from_slice(&s.to_be_bytes());
        }
        ext(0x000d, &data)
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS1.2 legacy version
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one TLS1.3 suite
    body.extend_from_slice(&[0x01, 0x00]); // null compression

    let mut exts = Vec::new();
    if let Some(name) = sni {
        exts.extend_from_slice(&sni_ext(name));
    }
    if sigalgs {
        exts.extend_from_slice(&sigalgs_ext());
    }
    for (ty, data) in extra_exts {
        exts.extend_from_slice(&ext(*ty, data));
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![0x01];
    let l = body.len() as u32;
    hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, (l & 0xff) as u8]);
    hs.extend_from_slice(&body);

    let mut rec = vec![RECORD_HANDSHAKE, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// The 0xfe0d walker (module docs point 4; spike-verified algorithm).
///
/// `Some(true)` = the extension is present ⇒ DENY; `Some(false)` = the full
/// extension block was walked and 0xfe0d is PROVABLY absent; `None` = the
/// raw bytes are not a walkable single-record ClientHello shape (the caller
/// fails closed). Bounds-checked via `.get()` and checked arithmetic at
/// every offset — NEVER panics (`ech_walker_never_panics_on_garbage` pins
/// it over every truncation + a garbage corpus).
///
/// Scope note: the walker assumes the ClientHello occupies ONE TLS record
/// (hellos that span records are legal but vanishingly rare — a hello
/// larger than 16 KiB; rustls would accept one, the walker answers `None`,
/// and the connection is denied fail-closed as
/// unverifiable-ECH-absence).
pub(crate) fn offers_ech(raw: &[u8]) -> Option<bool> {
    // Record header: type(1) version(2) length(2).
    if raw.len() < 5 || raw[0] != RECORD_HANDSHAKE {
        return None;
    }
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let hs = raw.get(5..5 + rec_len)?;
    // Handshake header: type(1) length(3) — ClientHello is type 0x01.
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let m = hs.get(4..4 + hs_len)?;
    // Body: version(2) + random(32) = 34, then session_id(1+n),
    // cipher_suites(2+n), compression(1+n), extensions(2+n).
    let mut off = 34usize;
    off = off.checked_add(*m.get(off)? as usize)?.checked_add(1)?;
    let suites_len = u16::from_be_bytes([*m.get(off)?, *m.get(off + 1)?]) as usize;
    off = off.checked_add(suites_len)?.checked_add(2)?;
    off = off.checked_add(*m.get(off)? as usize)?.checked_add(1)?;
    let ext_total = u16::from_be_bytes([*m.get(off)?, *m.get(off + 1)?]) as usize;
    let start = off.checked_add(2)?;
    let exts = m.get(start..start.checked_add(ext_total)?)?;
    // Walk extension entries: type(2) length(2) data(length).
    let mut eoff = 0usize;
    while eoff + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[eoff], exts[eoff + 1]]);
        if ty == ECH_EXTENSION_TYPE {
            return Some(true);
        }
        let elen = u16::from_be_bytes([exts[eoff + 2], exts[eoff + 3]]) as usize;
        // checked: a garbage length near u16::MAX can never wrap the walk.
        eoff = eoff.checked_add(elen)?.checked_add(4)?;
    }
    // Some(false) ONLY on an exact walk: a trailing truncated entry means
    // the block is not fully walkable ⇒ not PROVABLY absent ⇒ None
    // (fail-closed at the caller).
    if eoff == exts.len() {
        Some(false)
    } else {
        None
    }
}

/// Read + inspect the ClientHello on 443 (module docs points 2/3). Returns
/// the FULL replay buffer (hello record + any pipelined bytes) on success.
/// The decision timeout is applied by the CALLER ([`crate::proxy::decide`])
/// — this loop is bounded only by the byte cap and EOF.
pub(crate) async fn inspect_tls<S: AsyncRead + Unpin>(
    client: &mut S,
    expected: &Domain,
    limits: &Limits,
) -> Result<Vec<u8>, Rejected> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        let n = match client.read(&mut chunk).await {
            Ok(0) => return Err(Rejected::Eof),
            Ok(n) => n,
            // A transport failure means the client is gone before a
            // complete preamble — the same fail-closed family as a clean
            // EOF (a "malformed hello" label would misreport the audit).
            Err(_err) => return Err(Rejected::Eof),
        };
        // The replay buffer gets every byte FIRST (module docs point 2):
        // the acceptor only ever sees a copy of exactly this chunk.
        let is_first_chunk = buf.is_empty();
        buf.extend_from_slice(&chunk[..n]);
        if is_first_chunk && buf[0] != RECORD_HANDSHAKE {
            return Err(Rejected::NotTls { first_byte: buf[0] });
        }
        if buf.len() > limits.max_hello_bytes {
            return Err(Rejected::HelloTooLarge {
                cap: limits.max_hello_bytes,
            });
        }
        // Feed a COPY of exactly the newly-read bytes (a Cursor over the
        // chunk slice — never the buffer, never a byte twice). Cursor reads
        // cannot fail; the fail-closed arm exists so no io path is ignored.
        if acceptor.read_tls(&mut Cursor::new(&chunk[..n])).is_err() {
            return Err(Rejected::HelloMalformed {
                detail: "internal read_tls failure".to_owned(),
            });
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let hello = accepted.client_hello();
                // ECH walker BEFORE acting on the SNI verdict (module docs
                // point 4 — a well-formed ECH hello parses fine in rustls).
                match offers_ech(&buf) {
                    Some(true) => return Err(Rejected::EchOffered),
                    Some(false) => {}
                    None => {
                        return Err(Rejected::HelloMalformed {
                            detail: WALK_FAILED_DETAIL.to_owned(),
                        });
                    }
                }
                // rustls-validated SNI: lowercased, root dot preserved,
                // IP literals → None (indistinguishable from absent ⇒ the
                // single pinned SniMissing denial). Canonicalization
                // failure (junk rustls would never produce) is the same
                // denial — fail-closed.
                let Some(raw_sni) = hello.server_name() else {
                    return Err(Rejected::SniMissing);
                };
                let Some(sni) = canonicalize_host(raw_sni) else {
                    return Err(Rejected::SniMissing);
                };
                if sni != *expected {
                    return Err(Rejected::SniMismatch {
                        sni,
                        name: expected.clone(),
                    });
                }
                return Ok(buf);
            }
            // Incomplete hello: read more (the cap + the caller's timeout
            // bound the loop).
            Ok(None) => continue,
            Err((err, alert)) => {
                // Q2: the alert is DROPPED, never written back — it would
                // leak policy internals into the sandbox.
                drop(alert);
                return Err(Rejected::HelloMalformed {
                    detail: err.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn dom(s: &str) -> Domain {
        Domain::parse(s).unwrap_or_else(|err| panic!("{s:?} must parse: {err}"))
    }

    /// Feed `raw` to a fresh Acceptor in one shot. The outer `Option` is
    /// the accept state (`None` = incomplete), the inner one the
    /// `server_name()` result.
    fn accept_once(raw: &[u8]) -> Result<Option<Option<String>>, rustls::Error> {
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor
            .read_tls(&mut Cursor::new(raw))
            .expect("Cursor reads cannot fail");
        match acceptor.accept() {
            Ok(Some(accepted)) => Ok(Some(
                accepted.client_hello().server_name().map(str::to_owned),
            )),
            Ok(None) => Ok(None),
            Err((err, _alert)) => Err(err),
        }
    }

    // GREASE-ECH per the draft: cipher_suite = KEM(2) KDF(2) AEAD(2),
    // maximum_name_length(2), then filler (the probe3 corpus).
    fn ech_grease_payload() -> Vec<u8> {
        [0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0x11, 32))
            .collect()
    }

    /// A minimal 8-byte ECH extension body (suite + max_name_len only).
    fn ech_min_payload() -> Vec<u8> {
        vec![0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]
    }

    /// An outer-ECH shape: cipher_suite(8) + config_id(1) + enc(2+n) +
    /// payload(2+n) (the probe3 corpus).
    fn ech_outer_payload() -> Vec<u8> {
        let mut outer = vec![0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x07];
        outer.extend_from_slice(&[0xAA; 32]);
        let enc_len = 32u16;
        outer.splice(9..9, enc_len.to_be_bytes());
        outer.extend_from_slice(&[0x00, 0x10]);
        outer.extend_from_slice(&[0xBB; 16]);
        outer
    }

    // ---- fixture self-checks (the rustls-0.23.x drift alarms) ----------

    #[test]
    fn fixture_hello_is_accepted_by_rustls() {
        // THE drift alarm: if a rustls 0.23.x update changes Acceptor
        // behavior or the SNI accessor, this fails — a test breaks, not
        // production.
        let raw = build_client_hello(Some("allowed.com"), &[]);
        assert_eq!(
            accept_once(&raw).expect("rustls must accept the fixture"),
            Some(Some("allowed.com".to_owned()))
        );
    }

    #[test]
    fn fixture_without_sigalgs_is_rejected() {
        // WHY the fixture carries signature_algorithms: rustls rejects a
        // hello without it (PeerIncompatible) — a fixture missing it would
        // make every inspect_tls test vacuously a HelloMalformed.
        let raw = build_client_hello_with(Some("allowed.com"), &[], false);
        let err = accept_once(&raw).expect_err("rustls must reject a no-sigalgs hello");
        assert!(
            matches!(err, rustls::Error::PeerIncompatible(_)),
            "unexpected rejection: {err:?}"
        );
    }

    #[test]
    fn fixture_split_feed_accepts() {
        // The incremental read-loop contract: two chunks → Ok(None) then
        // Ok(Some). Feeding the same bytes twice would corrupt the parse —
        // the replay-buffer-first + copy-fed design (module docs point 2)
        // relies on this shape.
        let raw = build_client_hello(Some("allowed.com"), &[]);
        let split = raw.len() / 2;
        let mut acceptor = rustls::server::Acceptor::default();
        acceptor
            .read_tls(&mut Cursor::new(&raw[..split]))
            .expect("feed 1");
        assert!(
            matches!(acceptor.accept(), Ok(None)),
            "a half hello must be incomplete"
        );
        acceptor
            .read_tls(&mut Cursor::new(&raw[split..]))
            .expect("feed 2");
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                assert_eq!(accepted.client_hello().server_name(), Some("allowed.com"));
            }
            Ok(None) => panic!("the full hello must accept after the second feed"),
            Err((err, _)) => panic!("split feed must accept: {err:?}"),
        }
    }

    // ---- rustls SNI facts the compare layer relies on -------------------

    #[test]
    fn uppercase_sni_is_lowercased() {
        let raw = build_client_hello(Some("ALLOWED.COM"), &[]);
        assert_eq!(
            accept_once(&raw).expect("must accept"),
            Some(Some("allowed.com".to_owned()))
        );
    }

    #[test]
    fn root_dot_sni_preserved() {
        // rustls does NOT strip the root dot — canonicalize_host strips
        // exactly one before the compare (inspect_tls_root_dot_sni_matches).
        let raw = build_client_hello(Some("allowed.com."), &[]);
        assert_eq!(
            accept_once(&raw).expect("must accept"),
            Some(Some("allowed.com.".to_owned()))
        );
    }

    #[test]
    fn ip_literal_sni_yields_none() {
        // Indistinguishable from a missing SNI ⇒ the single pinned
        // SniMissing denial (Rejected::SniMissing docs).
        let raw = build_client_hello(Some("1.2.3.4"), &[]);
        assert_eq!(
            accept_once(&raw).expect("must accept structurally"),
            Some(None)
        );
    }

    // ---- the ECH walker --------------------------------------------------

    #[test]
    fn ech_walker_finds_fe0d_in_all_shapes() {
        // The probe3 corpus: GREASE-32B, minimal-8B, outer-ECH.
        for (label, payload) in [
            ("grease-32B", ech_grease_payload()),
            ("ech-8B", ech_min_payload()),
            ("outer-ech", ech_outer_payload()),
        ] {
            let raw = build_client_hello(Some("allowed.com"), &[(ECH_EXTENSION_TYPE, payload)]);
            assert_eq!(offers_ech(&raw), Some(true), "{label}");
        }
    }

    #[test]
    fn ech_walker_grease_types_are_disjoint() {
        // Q4 pin: all 16 GREASE extension types (0x?a?a) are provably NOT
        // 0xfe0d — a GREASE-only hello is walkable and ECH-free.
        for high in 0..=0xfu16 {
            let grease = (high << 12) | 0x0a0a | (high << 4);
            assert_ne!(grease, ECH_EXTENSION_TYPE, "GREASE must never be 0xfe0d");
            let raw = build_client_hello(Some("allowed.com"), &[(grease, vec![0x00; 4])]);
            assert_eq!(offers_ech(&raw), Some(false), "GREASE {grease:#06x}");
        }
    }

    #[test]
    fn ech_walker_never_panics_on_garbage() {
        // Every truncation of a fixture hello (all offsets, including an
        // ECH-carrying one), every 1-byte mutation at EVERY offset (record
        // and handshake headers, the session-id / cipher-suites /
        // compression length fields and the extension block — where the
        // walk arithmetic lives), and a garbage corpus — no panic, result
        // ∈ {None, Some(_)}.
        let with_ech = build_client_hello(Some("allowed.com"), &[(ECH_EXTENSION_TYPE, vec![0; 9])]);
        let plain = build_client_hello(Some("allowed.com"), &[]);
        for raw in [&plain, &with_ech] {
            for cut in 0..=raw.len() {
                let _ = offers_ech(&raw[..cut]);
            }
        }
        for pos in 0..plain.len() {
            for byte in [0x00u8, 0xff] {
                let mut mutated = plain.clone();
                mutated[pos] = byte;
                let _ = offers_ech(&mutated);
            }
        }
        let garbage: [&[u8]; 6] = [
            &[],
            &[0x16],
            &[0x16, 0x03, 0x01, 0xff, 0xff],
            &[0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff],
            &[0xff; 64],
            b"GET / HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
        ];
        for raw in garbage {
            let _ = offers_ech(raw);
        }
        // A trailing extension whose claimed length overshoots the block is
        // NOT provably absent ⇒ None (fail-closed at the caller).
        let mut cut = build_client_hello(Some("allowed.com"), &[(0x0017, vec![0x00; 4])]);
        // The trailing extension is the record's last 8 bytes: type(2)
        // length(2) data(4) — corrupt its length field to overshoot.
        let len_pos = cut.len() - 8 + 2;
        cut[len_pos] = 0xff;
        cut[len_pos + 1] = 0xff;
        assert_eq!(offers_ech(&cut), None);
    }

    // ---- inspect_tls over duplex streams --------------------------------

    /// Run `inspect_tls` with the client side pre-fed `bytes`. The write
    /// half stays ALIVE for the whole inspection unless `close_after` —
    /// then it is shut down first, giving the inspector EOF after the
    /// buffered bytes.
    fn inspect_with(
        bytes: &[u8],
        expected: &str,
        limits: Limits,
        close_after: bool,
    ) -> Result<Vec<u8>, Rejected> {
        let (mut client, mut peer) = duplex(64 * 1024);
        block_on(peer.write_all(bytes)).expect("fixture write fits the duplex buffer");
        if close_after {
            block_on(peer.shutdown()).expect("shutdown");
        }
        let expected = dom(expected);
        block_on(inspect_tls(&mut client, &expected, &limits))
    }

    #[test]
    fn inspect_tls_allowed_sni_returns_replay() {
        // AC-adjacent: the replay buffer is byte-exact the hello.
        let hello = build_client_hello(Some("allowed.test"), &[]);
        let result = inspect_with(&hello, "allowed.test", Limits::default(), false);
        assert_eq!(result.expect("matching SNI must pass"), hello);
    }

    #[test]
    fn inspect_tls_replays_pipelined_bytes() {
        // The replay-correctness lock (module docs point 9): hello +
        // pipelined application bytes in one write ⇒ replay == both.
        let mut bytes = build_client_hello(Some("allowed.test"), &[]);
        bytes.extend_from_slice(b"pipelined");
        let result = inspect_with(&bytes, "allowed.test", Limits::default(), false);
        assert_eq!(result.expect("must pass"), bytes);
    }

    #[test]
    fn inspect_tls_missing_sni_denied() {
        // AC missing-SNI (and the IP-literal shape is indistinguishable —
        // ip_literal_sni_yields_none pins the rustls side).
        let hello = build_client_hello(None, &[]);
        let result = inspect_with(&hello, "allowed.test", Limits::default(), false);
        assert_eq!(result.expect_err("must deny"), Rejected::SniMissing);
    }

    #[test]
    fn inspect_tls_sni_mismatch_denied() {
        // AC SNI≠name.
        let hello = build_client_hello(Some("evil.test"), &[]);
        let result = inspect_with(&hello, "allowed.test", Limits::default(), false);
        assert_eq!(
            result.expect_err("must deny"),
            Rejected::SniMismatch {
                sni: dom("evil.test"),
                name: dom("allowed.test"),
            }
        );
    }

    #[test]
    fn inspect_tls_root_dot_sni_matches() {
        // Canonicalization: rustls preserves the root dot; exactly one is
        // stripped before the compare.
        let hello = build_client_hello(Some("allowed.test."), &[]);
        let result = inspect_with(&hello, "allowed.test", Limits::default(), false);
        assert_eq!(result.expect("root-dot SNI must match"), hello);
    }

    /// Re-wrap the fixture hello's handshake message into TWO TLS records
    /// split at `first_len` — the legal multi-record fragmentation shape
    /// (rustls reassembles it; the single-record walker answers `None`).
    fn fragment_across_two_records(raw: &[u8], first_len: usize) -> Vec<u8> {
        let hs = &raw[5..]; // strip the fixture's record header
        assert!(
            first_len > 0 && first_len < hs.len(),
            "the split must be interior"
        );
        let mut out = Vec::new();
        for part in [&hs[..first_len], &hs[first_len..]] {
            out.extend_from_slice(&[RECORD_HANDSHAKE, 0x03, 0x01]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// draft-18 §5 `ECHClientHello` "inner" type: the type byte 0x01 with
    /// NO payload — the extension shape a real ECH inner ClientHello
    /// carries, and the minimal form rustls 0.23.45 structurally accepts.
    fn ech_inner_payload() -> Vec<u8> {
        vec![0x01]
    }

    /// draft-18 §5 `ECHClientHello` "outer" type: 0x00 + the HPKE
    /// cipher suite (kdf 0x0001 HKDF-SHA256, aead 0x0001 AES-128-GCM —
    /// rustls validates the codepoints) + config_id + empty enc + a
    /// NON-EMPTY payload — a structurally valid outer rustls accepts.
    fn ech_outer_valid_payload() -> Vec<u8> {
        vec![
            0x00, // ECHClientHelloType::ClientHelloOuter
            0x00, 0x01, // kdf_id: HKDF-SHA256
            0x00, 0x01, // aead_id: AES-128-GCM
            0x07, // config_id
            0x00, 0x00, // enc: empty (the HRR-response shape)
            0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, // payload: non-empty
        ]
    }

    #[test]
    fn inspect_tls_ech_with_valid_sni_denied() {
        // The precedence pin (module docs point 4): the walker runs BEFORE
        // the SNI verdict is acted on — a hello whose SNI matches
        // perfectly AND which rustls parses fine is STILL denied
        // EchOffered when it carries a 0xfe0d extension. The payloads are
        // the draft-18 inner shape + a structurally valid outer: rustls
        // 0.23.45 ACCEPTS both (probe3's GREASE-filler shapes are rejected
        // by rustls itself first — still fail-closed, but as
        // HelloMalformed, the path inspect_tls_malformed_hello_denied
        // pins), so here the walker is the load-bearing deny layer exactly
        // where the design requires it (Q4's trade-off included).
        for payload in [ech_inner_payload(), ech_outer_valid_payload()] {
            let hello = build_client_hello(
                Some("allowed.test"),
                &[(ECH_EXTENSION_TYPE, payload.clone())],
            );
            // Precondition: rustls accepts — the walker, not rustls, must
            // be the layer that denies this hello.
            assert!(
                matches!(accept_once(&hello), Ok(Some(_))),
                "rustls must accept the ECH shape {payload:?}"
            );
            assert_eq!(offers_ech(&hello), Some(true), "{payload:?}");
            let result = inspect_with(&hello, "allowed.test", Limits::default(), false);
            assert_eq!(
                result.expect_err("ECH must deny despite a valid SNI"),
                Rejected::EchOffered,
                "{payload:?}"
            );
        }
    }

    #[test]
    fn inspect_tls_multirecord_hello_denied_as_unwalkable() {
        // Deviation #4's pin (was prose-only): a ClientHello fragmented
        // across TWO TLS records is legal wire format and rustls
        // REASSEMBLES AND ACCEPTS it — but the single-record ECH walker
        // cannot prove 0xfe0d absent (`None`), so the connection is denied
        // fail-closed with the pinned walk-failed detail instead of
        // passing the SNI check with ECH presence unverified.
        let hello = build_client_hello(Some("allowed.test"), &[]);
        let fragmented = fragment_across_two_records(&hello, 40);
        // Precondition 1: rustls accepts the fragmented shape — this is the
        // interesting case (a parser disagreement, not a malformed hello).
        assert!(
            matches!(accept_once(&fragmented), Ok(Some(_))),
            "rustls must reassemble a record-spanning hello"
        );
        // Precondition 2: the walker answers None (not provably absent).
        assert_eq!(offers_ech(&fragmented), None);
        let result = inspect_with(&fragmented, "allowed.test", Limits::default(), false);
        assert_eq!(
            result.expect_err("must deny fail-closed"),
            Rejected::HelloMalformed {
                detail: WALK_FAILED_DETAIL.to_owned(),
            }
        );
    }

    #[test]
    fn inspect_tls_plaintext_first_byte_denied() {
        // AC plaintext-on-443: the 0x16 pre-check gives the cleaner pinned
        // reason carrying the first byte's hex.
        let plaintext = b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n";
        let result = inspect_with(plaintext, "allowed.test", Limits::default(), false);
        let rejected = result.expect_err("must deny");
        assert_eq!(rejected, Rejected::NotTls { first_byte: b'G' });
        assert_eq!(
            rejected.reason(),
            "non-TLS traffic on port 443 (first byte 0x47)"
        );
    }

    #[test]
    fn inspect_tls_malformed_hello_denied() {
        // 0x16-prefixed but structurally rejected by rustls (the
        // no-sigalgs fixture: PeerIncompatible) ⇒ HelloMalformed, and the
        // AcceptedAlert is NEVER written back (Q2): the peer sees zero
        // bytes before the close.
        let raw = build_client_hello_with(Some("allowed.test"), &[], false);
        let (mut client, mut peer) = duplex(64 * 1024);
        let expected = dom("allowed.test");
        let limits = Limits::default();
        let (outcome, echoed) = block_on(async {
            peer.write_all(&raw).await.expect("write");
            let outcome = inspect_tls(&mut client, &expected, &limits).await;
            drop(client);
            // Anything the inspector wrote back would show up here; Q2
            // says the alert is dropped, so this must be empty-then-EOF.
            let mut echoed = Vec::new();
            peer.read_to_end(&mut echoed).await.expect("read");
            (outcome, echoed)
        });
        let rejected = outcome.expect_err("must deny");
        assert!(
            matches!(rejected, Rejected::HelloMalformed { .. }),
            "unexpected denial: {rejected:?}"
        );
        assert!(
            echoed.is_empty(),
            "the AcceptedAlert must be dropped, never written: {echoed:?}"
        );
    }

    #[test]
    fn inspect_tls_truncated_hello_hits_cap() {
        // The truncated-hello DoS bound: a shrunk cap denies a hello that
        // would otherwise keep the acceptor in Ok(None) forever.
        let hello = build_client_hello(Some("allowed.test"), &[]);
        let limits = Limits {
            max_hello_bytes: 16,
            ..Limits::default()
        };
        let result = inspect_with(&hello, "allowed.test", limits, false);
        assert_eq!(
            result.expect_err("must deny"),
            Rejected::HelloTooLarge { cap: 16 }
        );
    }

    #[test]
    fn inspect_tls_hello_cap_boundary_pinned() {
        // Boundary pin (m4, the STRICT side): the cap is checked after
        // every append and BEFORE feeding the acceptor — a hello of
        // exactly cap bytes passes; one byte over denies EVEN THOUGH the
        // buffered hello is complete and valid (a completing chunk that
        // crosses the cap is never parsed). The deliberate asymmetry with
        // HTTP's lenient terminator-first ordering is documented on
        // Limits; HTTP's twin: inspect_http_cap_boundary_pinned.
        let hello = build_client_hello(Some("allowed.test"), &[]);
        let exact = Limits {
            max_hello_bytes: hello.len(),
            ..Limits::default()
        };
        let result = inspect_with(&hello, "allowed.test", exact, false);
        assert_eq!(result.expect("len == cap must pass"), hello);
        let shrunk = Limits {
            max_hello_bytes: hello.len() - 1,
            ..Limits::default()
        };
        let result = inspect_with(&hello, "allowed.test", shrunk, false);
        assert_eq!(
            result.expect_err("cap + 1 must deny even though complete"),
            Rejected::HelloTooLarge {
                cap: hello.len() - 1,
            }
        );
    }

    #[test]
    fn inspect_tls_eof_denied() {
        // A partial hello then close ⇒ Eof (bounded, never a hang).
        let hello = build_client_hello(Some("allowed.test"), &[]);
        let result = inspect_with(
            &hello[..hello.len() / 2],
            "allowed.test",
            Limits::default(),
            true,
        );
        assert_eq!(result.expect_err("must deny"), Rejected::Eof);
    }
}
