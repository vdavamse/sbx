//! The DNS wire codec (issue #9, T3). `pub(crate)`: no hickory type escapes
//! this module, so a later hickory bump cannot change the public API (D7).
//!
//! Two layers, in this order for every datagram:
//!
//! 1. [`gate`] reads the raw header bytes ONLY. It drops short datagrams and
//!    responses, answers non-QUERY opcodes NOTIMP and any count shape other
//!    than `qd=1 an=0 ns=0 ar<=1` FORMERR, all WITHOUT calling the decoder. The
//!    decoder never sees an attacker-chosen section count.
//! 2. [`decode`] runs hickory's [`Query`]/[`Message`] readers on the gated bytes.
//!    It refuses compression pointers in the question name (D1), any additional
//!    record other than one OPT (D2), and trailing bytes (D2).
//!
//! Encoding goes through hickory as well, so the reply bytes are the protocol
//! library's, not ours. The golden vectors in the tests below were produced by
//! hickory-proto 0.25.2 (the exact pin in Cargo.toml) and are pinned here
//! byte-exact: a hickory bump that changes any of them must fail the tests.

use std::net::Ipv4Addr;

use hickory_proto::op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

use super::{DnsDropped, DnsRejected, FAKE_TTL, sanitize_detail};

/// The fixed DNS header length (RFC 1035 section 4.1.1).
pub(crate) const HEADER_LEN: usize = 12;
/// The EDNS0 payload size we advertise in every OPT we send (Q7).
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// A header-only reply (no question, no answers, no OPT): the FORMERR and
/// NOTIMP family (D2). `id` and `rd` are echoed, `RA` is set.
pub(crate) struct HeaderOnly {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub rcode: ResponseCode,
}

/// What the raw-header gate decided.
pub(crate) enum Gate {
    /// No reply, and the datagram is recorded as dropped (Q3).
    Drop(DnsDropped),
    /// Send `reply` (header-only) and record `rejected`.
    Reject {
        reply: HeaderOnly,
        rejected: DnsRejected,
    },
    /// The header is plausible: hand the bytes to [`decode`].
    Pass { id: u16, rd: bool },
}

/// The header gate (module docs point 1). Reads bytes 0..12 directly.
pub(crate) fn gate(dg: &[u8]) -> Gate {
    if dg.len() < HEADER_LEN {
        return Gate::Drop(DnsDropped::Short { len: dg.len() });
    }
    let id = be16(dg, 0);
    let flags = dg[2];
    if flags & 0x80 != 0 {
        return Gate::Drop(DnsDropped::NotAQuery);
    }
    let opcode = (flags >> 3) & 0x0f;
    let rd = flags & 0x01 != 0;
    if opcode != 0 {
        return Gate::Reject {
            reply: HeaderOnly {
                id,
                opcode,
                rd,
                rcode: ResponseCode::NotImp,
            },
            rejected: DnsRejected::NotImplemented { opcode },
        };
    }
    let (qd, an, ns, ar) = (be16(dg, 4), be16(dg, 6), be16(dg, 8), be16(dg, 10));
    if qd != 1 || an != 0 || ns != 0 || ar > 1 {
        return Gate::Reject {
            reply: HeaderOnly {
                id,
                opcode: 0,
                rd,
                rcode: ResponseCode::FormErr,
            },
            rejected: DnsRejected::BadCounts { qd, an, ns, ar },
        };
    }
    Gate::Pass { id, rd }
}

/// A successfully decoded query.
pub(crate) struct Parsed {
    pub header: Header,
    pub query: Query,
    /// The OPT record, when the client sent one.
    pub edns: Option<Edns>,
}

/// A decode failure. `query` is `Some` when the question itself decoded, so
/// the audit record can still name what was asked.
pub(crate) struct DecodeError {
    pub rejected: DnsRejected,
    pub query: Option<Query>,
}

/// Decode a gated datagram (module docs point 2).
pub(crate) fn decode(dg: &[u8]) -> Result<Parsed, DecodeError> {
    let malformed = |detail: String, query: Option<Query>| DecodeError {
        rejected: DnsRejected::Malformed {
            detail: sanitize_detail(&detail),
        },
        query,
    };
    let mut dec = BinDecoder::new(dg);
    let header = Header::read(&mut dec).map_err(|e| malformed(e.to_string(), None))?;
    let query = Query::read(&mut dec).map_err(|e| malformed(e.to_string(), None))?;

    // A compressed question name consumes fewer bytes than its uncompressed
    // wire form. Equal length proves the name was written out in full.
    let wire_name: usize = query
        .name()
        .iter()
        .map(|label| label.len() + 1)
        .sum::<usize>()
        + 1;
    if dec.index() != HEADER_LEN + wire_name + 4 {
        return Err(DecodeError {
            rejected: DnsRejected::CompressedQuestion,
            query: Some(query),
        });
    }

    let (others, edns, sigs) =
        match Message::read_records(&mut dec, usize::from(header.additional_count()), true) {
            Ok(parts) => parts,
            Err(e) => return Err(malformed(e.to_string(), Some(query))),
        };
    if let Some(first) = others.first().or_else(|| sigs.first()) {
        return Err(DecodeError {
            rejected: DnsRejected::UnexpectedAdditional {
                rtype: u16::from(first.record_type()),
            },
            query: Some(query),
        });
    }
    if !dec.is_empty() {
        return Err(DecodeError {
            rejected: DnsRejected::TrailingBytes { extra: dec.len() },
            query: Some(query),
        });
    }
    Ok(Parsed {
        header,
        query,
        edns,
    })
}

/// The query name as a raw-label hostname (Q9): ASCII LDH plus `_` only, no
/// trailing dot, labels joined by `.`. `None` for the root name or any other
/// byte. The caller canonicalizes the result through the proxy pipeline.
pub(crate) fn query_host(name: &Name) -> Option<String> {
    let mut host = String::new();
    let mut count = 0usize;
    for label in name.iter() {
        let ok = !label.is_empty()
            && label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
        if !ok {
            return None;
        }
        if count > 0 {
            host.push('.');
        }
        // ASCII checked above, so this is always valid UTF-8.
        host.push_str(std::str::from_utf8(label).ok()?);
        count += 1;
    }
    (count > 0).then_some(host)
}

/// Encode a header-only reply (FORMERR / NOTIMP family, D2).
pub(crate) fn encode_header_only(h: &HeaderOnly) -> Result<Vec<u8>, String> {
    let mut m = Message::error_msg(h.id, OpCode::from_u8(h.opcode), h.rcode);
    m.set_recursion_desired(h.rd).set_recursion_available(true);
    m.to_vec().map_err(|e| e.to_string())
}

/// Encode a reply to a decoded query: the question echoed verbatim (Q8),
/// an optional single A answer at [`FAKE_TTL`], and a minimal OPT when the
/// client sent one (Q7: payload 1232, version 0, DO clear, no options).
pub(crate) fn encode_response(
    p: &Parsed,
    rcode: ResponseCode,
    answer: Option<Ipv4Addr>,
) -> Result<Vec<u8>, String> {
    let mut m = Message::new();
    m.set_id(p.header.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(p.header.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(rcode);
    m.add_query(p.query.clone());
    if let Some(ip) = answer {
        m.add_answer(Record::from_rdata(
            p.query.name().clone(),
            FAKE_TTL,
            RData::A(A::from(ip)),
        ));
    }
    if p.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD)
            .set_version(0)
            .set_dnssec_ok(false);
        m.set_edns(edns);
    }
    m.to_vec().map_err(|e| e.to_string())
}

/// The DNS class of a decoded question, as the raw `u16`.
pub(crate) fn qclass_of(query: &Query) -> u16 {
    u16::from(query.query_class())
}

/// The question type of a decoded question, as the raw `u16`.
pub(crate) fn qtype_of(query: &Query) -> u16 {
    u16::from(query.query_type())
}

/// `true` when the class is IN (the only class the resolver serves).
pub(crate) fn is_in_class(query: &Query) -> bool {
    query.query_class() == DNSClass::IN
}

/// `true` when the question asks for an A record.
pub(crate) fn is_a_query(query: &Query) -> bool {
    query.query_type() == RecordType::A
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the design's hex notation ("12 34 81 80 ...") into bytes.
    fn hx(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The uncompressed wire form of a dotted name ("" = root).
    fn name_wire(dotted: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in dotted.split('.').filter(|l| !l.is_empty()) {
            out.push(u8::try_from(label.len()).expect("label fits"));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A header (id, flags, counts) followed by the body bytes.
    fn msg(id: u16, flags: [u8; 2], counts: [u16; 4], body: &[u8]) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend_from_slice(&flags);
        for c in counts {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    /// One question, no additional records.
    fn question(id: u16, rd: bool, name: &[u8], qtype: u16, qclass: u16) -> Vec<u8> {
        let flags = [if rd { 0x01 } else { 0x00 }, 0x00];
        let mut body = name.to_vec();
        body.extend_from_slice(&qtype.to_be_bytes());
        body.extend_from_slice(&qclass.to_be_bytes());
        msg(id, flags, [1, 0, 0, 0], &body)
    }

    /// The OPT record bytes (root name, type 41) with the given payload,
    /// version, DO bit and raw option bytes.
    fn opt(payload: u16, version: u8, do_bit: bool, options: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, 0x00, 41];
        v.extend_from_slice(&payload.to_be_bytes());
        v.extend_from_slice(&[0x00, version, if do_bit { 0x80 } else { 0x00 }, 0x00]);
        v.extend_from_slice(&u16::try_from(options.len()).expect("fits").to_be_bytes());
        v.extend_from_slice(options);
        v
    }

    fn pass(dg: &[u8]) {
        match gate(dg) {
            Gate::Pass { .. } => {}
            _ => panic!("expected the gate to pass {}", hex(dg)),
        }
    }

    fn expect_decode(dg: &[u8]) -> Parsed {
        pass(dg);
        match decode(dg) {
            Ok(p) => p,
            Err(e) => panic!("decode failed: {:?}", e.rejected),
        }
    }

    fn expect_decode_err(dg: &[u8]) -> DecodeError {
        pass(dg);
        match decode(dg) {
            Ok(_) => panic!("expected a decode error for {}", hex(dg)),
            Err(e) => e,
        }
    }

    #[test]
    fn gate_short_dropped() {
        let full = hx("12 34 01 00 00 01 00 00 00 00 00 00");
        for len in 0..=11 {
            match gate(&full[..len]) {
                Gate::Drop(DnsDropped::Short { len: got }) => assert_eq!(got, len),
                _ => panic!("length {len} must drop"),
            }
        }
    }

    #[test]
    fn gate_qr_dropped() {
        let response = hx("12 34 81 80 00 01 00 00 00 00 00 00");
        assert!(matches!(gate(&response), Gate::Drop(DnsDropped::NotAQuery)));
    }

    #[test]
    fn gate_opcode_notimp_golden() {
        // Opcode 5 (UPDATE), RD set, one question so the counts are otherwise fine.
        let q = question(3, true, &name_wire("pypi.org"), 1, 1);
        let mut dg = q.clone();
        dg[2] = 0x29;
        match gate(&dg) {
            Gate::Reject { reply, rejected } => {
                assert_eq!(rejected, DnsRejected::NotImplemented { opcode: 5 });
                assert_eq!(
                    hex(&encode_header_only(&reply).unwrap()),
                    "00 03 a9 84 00 00 00 00 00 00 00 00"
                );
            }
            _ => panic!("opcode 5 must be NOTIMP"),
        }
    }

    #[test]
    fn gate_bad_counts_formerr() {
        // Rows: (qd, an, ns, ar).
        let rows = [
            (0u16, 0u16, 0u16, 0u16),
            (2, 0, 0, 0),
            (1, 1, 0, 0),
            (1, 0, 1, 0),
            (1, 0, 0, 2),
        ];
        for (qd, an, ns, ar) in rows {
            let dg = msg(0x0102, [0x01, 0x00], [qd, an, ns, ar], &[]);
            match gate(&dg) {
                Gate::Reject { reply, rejected } => {
                    assert_eq!(
                        rejected,
                        DnsRejected::BadCounts { qd, an, ns, ar },
                        "row {qd}/{an}/{ns}/{ar}"
                    );
                    assert_eq!(u16::from(reply.rcode), 1, "FORMERR");
                }
                _ => panic!("row {qd}/{an}/{ns}/{ar} must be FORMERR"),
            }
        }
        // Golden for one row: qd=0 with RD clear, id 4.
        let dg = msg(4, [0x00, 0x00], [0, 0, 0, 0], &[]);
        match gate(&dg) {
            Gate::Reject { reply, .. } => assert_eq!(
                hex(&encode_header_only(&reply).unwrap()),
                "00 04 80 81 00 00 00 00 00 00 00 00"
            ),
            _ => panic!("expected FORMERR"),
        }
    }

    #[test]
    fn gate_precedes_decoder() {
        // Garbage body with a hostile QDCOUNT: the gate answers without the decoder,
        // so the reason is the count shape, never a decoder message.
        let dg = msg(9, [0x00, 0x00], [0xffff, 0, 0, 0], &[0xc0, 0x0c, 0xff]);
        match gate(&dg) {
            Gate::Reject { rejected, .. } => {
                assert_eq!(
                    rejected,
                    DnsRejected::BadCounts {
                        qd: 0xffff,
                        an: 0,
                        ns: 0,
                        ar: 0
                    }
                );
            }
            _ => panic!("hostile counts must be rejected by the gate"),
        }
    }

    #[test]
    fn decode_ok_fields() {
        let q = question(0x1234, true, &name_wire("PyPI.org"), 1, 1);
        let p = expect_decode(&q);
        assert_eq!(p.header.id(), 0x1234);
        assert!(p.header.recursion_desired());
        assert_eq!(qtype_of(&p.query), 1);
        assert_eq!(qclass_of(&p.query), 1);
        assert_eq!(p.query.name().to_ascii(), "PyPI.org.");
        assert!(p.edns.is_none());
    }

    #[test]
    fn decode_truncated_question_malformed() {
        let q = question(8, true, &name_wire("pypi.org"), 1, 1);
        let e = expect_decode_err(&q[..q.len() - 2]);
        match e.rejected {
            DnsRejected::Malformed { detail } => {
                assert!(detail.contains("unexpected end of input"), "{detail}")
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
        assert!(e.query.is_none());
    }

    #[test]
    fn decode_self_pointer_malformed() {
        // Label "a" then a pointer to offset 12: the name points at itself.
        let body = [1, b'a', 0xc0, 0x0c, 0, 1, 0, 1];
        let dg = msg(5, [0x01, 0x00], [1, 0, 0, 0], &body);
        match expect_decode_err(&dg).rejected {
            DnsRejected::Malformed { detail } => {
                assert!(
                    detail.contains("label points to data not prior"),
                    "{detail}"
                )
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn decode_header_pointer_is_compressed_question() {
        // The pointer lands inside the header; the decoded name is short of its
        // wire length, so the compression check fires (D1).
        let mut dg = msg(6, [0x01, 0x00], [1, 0, 0, 0], &[]);
        dg.extend_from_slice(&[1, b'a', 0xc0, 0x06, 0, 1, 0, 1]);
        let e = expect_decode_err(&dg);
        assert_eq!(e.rejected, DnsRejected::CompressedQuestion);
        assert!(e.query.is_some(), "the question decoded, so it is audited");
    }

    #[test]
    fn decode_trailing_bytes() {
        let mut q = question(7, true, &name_wire("pypi.org"), 1, 1);
        q.push(0);
        let e = expect_decode_err(&q);
        assert_eq!(e.rejected, DnsRejected::TrailingBytes { extra: 1 });
        assert!(e.query.is_some());
    }

    #[test]
    fn decode_non_opt_additional() {
        // ARCOUNT 1 with an A record in the additional section.
        let mut body = name_wire("pypi.org");
        body.extend_from_slice(&[0, 1, 0, 1]);
        body.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
        let dg = msg(9, [0x01, 0x00], [1, 0, 0, 1], &body);
        let e = expect_decode_err(&dg);
        assert_eq!(e.rejected, DnsRejected::UnexpectedAdditional { rtype: 1 });
    }

    #[test]
    fn decode_opt_extracted() {
        let mut body = name_wire("pypi.org");
        body.extend_from_slice(&[0, 28, 0, 1]);
        body.extend_from_slice(&opt(4096, 0, true, &[]));
        let dg = msg(0xbeef, [0x01, 0x00], [1, 0, 0, 1], &body);
        let p = expect_decode(&dg);
        let edns = p.edns.expect("OPT present");
        assert_eq!(edns.max_payload(), 4096);
        assert_eq!(edns.version(), 0);
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn decode_opt_small_payload_reads_as_512() {
        // hickory clamps advertised payloads below 512 up to 512.
        let mut body = name_wire("pypi.org");
        body.extend_from_slice(&[0, 1, 0, 1]);
        body.extend_from_slice(&opt(16, 0, false, &[]));
        let p = expect_decode(&msg(0x000f, [0x01, 0x00], [1, 0, 0, 1], &body));
        assert_eq!(p.edns.expect("OPT").max_payload(), 512);
    }

    #[test]
    fn decode_name_over_255_malformed() {
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        let q = question(0x000b, true, &name_wire(&long), 1, 1);
        match expect_decode_err(&q).rejected {
            DnsRejected::Malformed { detail } => {
                assert!(detail.contains("exceed 255"), "{detail}")
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn decode_extended_label_malformed() {
        // Label-type bits 01 are reserved: byte 0x41 is not a plain label length.
        let mut name = vec![0x41u8];
        name.extend_from_slice(&[0u8; 0x41]);
        name.push(0);
        let q = question(0x000c, true, &name, 1, 1);
        match expect_decode_err(&q).rejected {
            DnsRejected::Malformed { detail } => {
                assert!(detail.contains("unrecognized label code"), "{detail}")
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn query_host_table() {
        let ok = |wire: &[u8]| {
            // Decode a real question so the Name carries exactly the wire labels.
            let mut dg = msg(1, [0x01, 0x00], [1, 0, 0, 0], &[]);
            dg.extend_from_slice(wire);
            dg.extend_from_slice(&[0, 1, 0, 1]);
            decode(&dg).ok().map(|p| p.query.name().clone())
        };
        let host = |dotted: &str| ok(&name_wire(dotted)).and_then(|n| query_host(&n));
        assert_eq!(host("a_b.test").as_deref(), Some("a_b.test"));
        assert_eq!(host("PyPI.org").as_deref(), Some("PyPI.org"));
        assert_eq!(host("a-b.test").as_deref(), Some("a-b.test"));
        assert_eq!(host("a b.test"), None);
        assert_eq!(host("*.test"), None);
        assert_eq!(host("[a . 0xff]"), None);
        // Root name has zero labels.
        assert_eq!(ok(&[0]).and_then(|n| query_host(&n)), None);
        // A non-ASCII byte inside a label.
        let raw = [3u8, b'a', 0xc3, b'b', 0];
        assert_eq!(ok(&raw).and_then(|n| query_host(&n)), None);
    }

    #[test]
    fn encode_answer_golden() {
        // A PyPI.org, RD + CD; the reply clears CD and sets RA, echoes case.
        let q = hx("12 34 01 10 00 01 00 00 00 00 00 00 04 50 79 50 49 03 6f 72 67 00 00 01 00 01");
        let p = expect_decode(&q);
        let r = encode_response(
            &p,
            ResponseCode::NoError,
            Some(Ipv4Addr::new(198, 18, 0, 1)),
        )
        .unwrap();
        assert_eq!(
            hex(&r),
            "12 34 81 80 00 01 00 01 00 00 00 00 04 50 79 50 49 03 6f 72 67 00 00 01 00 01 \
             c0 0c 00 01 00 01 00 00 00 3c 00 04 c6 12 00 01"
        );
    }

    #[test]
    fn encode_question_echoed_verbatim() {
        let q = question(0x7777, true, &name_wire("PyPI.org"), 1, 1);
        let p = expect_decode(&q);
        let r = encode_response(
            &p,
            ResponseCode::NoError,
            Some(Ipv4Addr::new(198, 18, 0, 1)),
        )
        .unwrap();
        assert_eq!(
            &r[12..q.len()],
            &q[12..],
            "question bytes are echoed unchanged (D1)"
        );
    }

    #[test]
    fn encode_nodata_edns_golden() {
        // AAAA pypi.org, client OPT 4096 + DO + a COOKIE option: the reply drops
        // the options, advertises 1232, and clears DO.
        let q = hx(
            "be ef 01 00 00 01 00 00 00 00 00 01 04 70 79 70 69 03 6f 72 67 00 00 1c 00 01 \
             00 00 29 10 00 00 00 80 00 00 0c 00 0a 00 08 01 02 03 04 05 06 07 08",
        );
        let p = expect_decode(&q);
        let r = encode_response(&p, ResponseCode::NoError, None).unwrap();
        assert_eq!(
            hex(&r),
            "be ef 81 80 00 01 00 00 00 00 00 01 04 70 79 70 69 03 6f 72 67 00 00 1c 00 01 \
             00 00 29 04 d0 00 00 00 00 00 00"
        );
    }

    #[test]
    fn encode_badvers_golden() {
        let q = hx(
            "00 01 00 00 00 01 00 00 00 00 00 01 04 70 79 70 69 03 6f 72 67 \
             00 00 01 00 01 00 00 29 04 d0 00 01 00 00 00 00",
        );
        let p = expect_decode(&q);
        assert_eq!(p.edns.as_ref().map(|e| e.version()), Some(1));
        let r = encode_response(&p, ResponseCode::BADVERS, None).unwrap();
        assert_eq!(
            hex(&r),
            "00 01 80 80 00 01 00 00 00 00 00 01 04 70 79 70 69 03 6f 72 67 00 00 01 00 01 \
             00 00 29 04 d0 01 00 00 00 00 00"
        );
    }

    #[test]
    fn encode_nxdomain_golden() {
        let q = hx(
            "00 02 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 \
             03 63 6f 6d 00 00 01 00 01",
        );
        let p = expect_decode(&q);
        let r = encode_response(&p, ResponseCode::NXDomain, None).unwrap();
        assert_eq!(
            hex(&r),
            "00 02 81 83 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
        );
    }

    #[test]
    fn encode_refused_class_golden() {
        let q = hx("00 0e 01 00 00 01 00 00 00 00 00 00 04 70 79 70 69 03 6f 72 67 00 00 01 00 03");
        let p = expect_decode(&q);
        assert_eq!(qclass_of(&p.query), 3);
        let r = encode_response(&p, ResponseCode::Refused, None).unwrap();
        assert_eq!(
            hex(&r),
            "00 0e 81 85 00 01 00 00 00 00 00 00 04 70 79 70 69 03 6f 72 67 00 00 01 00 03"
        );
    }

    #[test]
    fn encode_formerr_header_only_golden() {
        let h = HeaderOnly {
            id: 4,
            opcode: 0,
            rd: false,
            rcode: ResponseCode::FormErr,
        };
        assert_eq!(
            hex(&encode_header_only(&h).unwrap()),
            "00 04 80 81 00 00 00 00 00 00 00 00"
        );
    }

    #[test]
    fn rd_clear_echoed() {
        let q = question(0x0042, false, &name_wire("pypi.org"), 1, 1);
        let p = expect_decode(&q);
        let r = encode_response(&p, ResponseCode::NoError, None).unwrap();
        assert_eq!(
            r[2] & 0x01,
            0,
            "RD clear in the query stays clear in the reply"
        );
        assert_eq!(r[3] & 0x80, 0x80, "RA is always set");
    }

    #[test]
    fn max_name_response_fits_512() {
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let mut body = name_wire(&long);
        body.extend_from_slice(&[0, 1, 0, 1]);
        body.extend_from_slice(&opt(1232, 0, false, &[]));
        let q = msg(0x000a, [0x01, 0x00], [1, 0, 0, 1], &body);
        let p = expect_decode(&q);
        let r = encode_response(
            &p,
            ResponseCode::NoError,
            Some(Ipv4Addr::new(198, 19, 255, 254)),
        )
        .unwrap();
        assert!(r.len() <= 512, "response is {} bytes", r.len());
    }
}
