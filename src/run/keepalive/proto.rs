//! The control protocol on `sbx.ctl` (issue #18, design point 6).
//!
//! 1. **Framing.** Every message is one frame: a one-byte opcode, a 4-byte
//!    big-endian payload length, then the payload. The length is checked against
//!    [`MAX_FRAME`] before the payload is allocated, so a peer cannot make the
//!    holder reserve more than that. A clean close before the first byte is
//!    [`ProtoError::Eof`]; any other short read is an I/O error.
//! 2. **Strict decoding (fail closed).** Every opcode has one exact payload
//!    shape. An unknown opcode, a wrong length, a non-UTF-8 field or an outcome
//!    outside the pinned vocabulary is [`ProtoError::Malformed`], and the caller
//!    drops the connection without answering. Nothing is guessed.
//! 3. **Requests.** `A` attach (the policy bytes), `E` call end (the call id, rc,
//!    duration and outcome), `S` stop. **Replies.** `K` accepted (the call id),
//!    `D` done, `R` refused (a reason, cut to [`MAX_REASON`]).
//! 4. **Outcome vocabulary.** A call's outcome is one of [`OUTCOMES`], the same
//!    words the audit exit row uses (`run` module docs point 7), so the holder
//!    writes them verbatim.

use std::io;

use super::pin::MAX_POLICY_BYTES;

/// The largest payload any frame may carry (the policy cap; the other
/// messages are far smaller).
pub(crate) const MAX_FRAME: usize = MAX_POLICY_BYTES;
/// The longest refusal reason sent (longer reasons are cut at a char boundary).
pub(crate) const MAX_REASON: usize = 512;
/// The call outcomes a `CallEnd` may carry (the audit exit-row vocabulary).
pub(crate) const OUTCOMES: [&str; 5] = ["exited", "signaled", "timeout", "terminated", "failed"];

const OP_ATTACH: u8 = b'A';
const OP_CALL_END: u8 = b'E';
const OP_STOP: u8 = b'S';
const OP_ACCEPTED: u8 = b'K';
const OP_DONE: u8 = b'D';
const OP_REFUSED: u8 = b'R';

/// A protocol failure. `Eof` is a clean close; the rest drop the connection.
#[derive(Debug)]
pub(crate) enum ProtoError {
    /// The peer closed before sending a frame.
    Eof,
    /// The stream failed or ended inside a frame.
    Io(io::Error),
    /// The declared payload exceeds [`MAX_FRAME`].
    TooLarge(usize),
    /// The frame does not match its opcode's shape.
    Malformed(&'static str),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Eof => f.write_str("the peer closed the connection"),
            ProtoError::Io(err) => write!(f, "control I/O failed: {err}"),
            ProtoError::TooLarge(n) => {
                write!(f, "frame of {n} bytes exceeds the {MAX_FRAME}-byte cap")
            }
            ProtoError::Malformed(why) => write!(f, "malformed control message: {why}"),
        }
    }
}

impl From<io::Error> for ProtoError {
    fn from(err: io::Error) -> Self {
        ProtoError::Io(err)
    }
}

/// One framed message before decoding.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) op: u8,
    pub(crate) payload: Vec<u8>,
}

/// The end of one attached call, as the attach process reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallEnd {
    pub(crate) call_id: u32,
    pub(crate) rc: i32,
    pub(crate) duration_ms: u64,
    /// One of [`OUTCOMES`].
    pub(crate) outcome: &'static str,
}

/// A request from an attach process or `sbx stop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// The attach's policy bytes; the holder pins-checks them and admits a call.
    Attach(Vec<u8>),
    /// An admitted call ended.
    CallEnd(CallEnd),
    /// End the session.
    Stop,
}

/// The holder's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    /// An attach was admitted under this call id (resident = 0 is never issued
    /// to an attach).
    Accepted(u32),
    /// The request was applied.
    Done,
    /// The request was refused; the text is the reason.
    Refused(String),
}

impl Request {
    /// The opcode and payload of this request.
    pub(crate) fn encode(&self) -> (u8, Vec<u8>) {
        match self {
            Request::Attach(policy) => (OP_ATTACH, policy.clone()),
            Request::CallEnd(end) => {
                let mut p = Vec::with_capacity(4 + 4 + 8 + end.outcome.len());
                p.extend_from_slice(&end.call_id.to_be_bytes());
                p.extend_from_slice(&end.rc.to_be_bytes());
                p.extend_from_slice(&end.duration_ms.to_be_bytes());
                p.extend_from_slice(end.outcome.as_bytes());
                (OP_CALL_END, p)
            }
            Request::Stop => (OP_STOP, Vec::new()),
        }
    }

    /// Decodes a frame as a request (rule 2).
    pub(crate) fn decode(frame: Frame) -> Result<Self, ProtoError> {
        match frame.op {
            OP_ATTACH => Ok(Request::Attach(frame.payload)),
            OP_CALL_END => {
                let p = &frame.payload;
                if p.len() < 16 {
                    return Err(ProtoError::Malformed(
                        "call end is shorter than its fixed fields",
                    ));
                }
                let call_id = u32::from_be_bytes(p[0..4].try_into().expect("4 bytes"));
                let rc = i32::from_be_bytes(p[4..8].try_into().expect("4 bytes"));
                let duration_ms = u64::from_be_bytes(p[8..16].try_into().expect("8 bytes"));
                let text = std::str::from_utf8(&p[16..])
                    .map_err(|_| ProtoError::Malformed("call outcome is not UTF-8"))?;
                let outcome = OUTCOMES
                    .iter()
                    .copied()
                    .find(|known| *known == text)
                    .ok_or(ProtoError::Malformed(
                        "call outcome is not in the vocabulary",
                    ))?;
                Ok(Request::CallEnd(CallEnd {
                    call_id,
                    rc,
                    duration_ms,
                    outcome,
                }))
            }
            OP_STOP => {
                if !frame.payload.is_empty() {
                    return Err(ProtoError::Malformed("stop takes no payload"));
                }
                Ok(Request::Stop)
            }
            _ => Err(ProtoError::Malformed("unknown request opcode")),
        }
    }
}

impl Reply {
    /// The opcode and payload of this reply. A refusal reason is cut to
    /// [`MAX_REASON`] at a character boundary.
    pub(crate) fn encode(&self) -> (u8, Vec<u8>) {
        match self {
            Reply::Accepted(call_id) => (OP_ACCEPTED, call_id.to_be_bytes().to_vec()),
            Reply::Done => (OP_DONE, Vec::new()),
            Reply::Refused(reason) => {
                let mut end = reason.len().min(MAX_REASON);
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                (OP_REFUSED, reason.as_bytes()[..end].to_vec())
            }
        }
    }

    /// Decodes a frame as a reply (rule 2).
    pub(crate) fn decode(frame: Frame) -> Result<Self, ProtoError> {
        match frame.op {
            OP_ACCEPTED => {
                let bytes: [u8; 4] = frame
                    .payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| ProtoError::Malformed("accepted reply is not 4 bytes"))?;
                Ok(Reply::Accepted(u32::from_be_bytes(bytes)))
            }
            OP_DONE => {
                if !frame.payload.is_empty() {
                    return Err(ProtoError::Malformed("done takes no payload"));
                }
                Ok(Reply::Done)
            }
            OP_REFUSED => {
                let text = String::from_utf8(frame.payload)
                    .map_err(|_| ProtoError::Malformed("refusal reason is not UTF-8"))?;
                Ok(Reply::Refused(text))
            }
            _ => Err(ProtoError::Malformed("unknown reply opcode")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::keepalive::ctl::{recv_frame, send_frame};
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    /// The frames travel over a real socket pair, through the same send and
    /// receive functions the holder and attach use.
    fn round_trip_request(req: Request) -> Request {
        let (a, b) = UnixStream::pair().expect("pair");
        let (op, payload) = req.encode();
        send_frame(&a, op, &payload, &[]).expect("send");
        let (frame, fds) = recv_frame(&b).expect("recv");
        assert!(fds.is_empty());
        Request::decode(frame).expect("decode")
    }

    #[test]
    fn requests_round_trip() {
        let attach = Request::Attach(b"{\"version\":1}".to_vec());
        assert_eq!(round_trip_request(attach.clone()), attach);
        assert_eq!(round_trip_request(Request::Stop), Request::Stop);
        let end = Request::CallEnd(CallEnd {
            call_id: 7,
            rc: -1,
            duration_ms: 1234,
            outcome: "timeout",
        });
        assert_eq!(round_trip_request(end.clone()), end);
    }

    #[test]
    fn call_end_wire_layout_is_pinned() {
        let end = Request::CallEnd(CallEnd {
            call_id: 1,
            rc: 2,
            duration_ms: 3,
            outcome: "exited",
        });
        let (op, payload) = end.encode();
        assert_eq!(op, b'E');
        let mut want = vec![0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3];
        want.extend_from_slice(b"exited");
        assert_eq!(payload, want);
    }

    #[test]
    fn replies_round_trip() {
        for reply in [
            Reply::Accepted(42),
            Reply::Done,
            Reply::Refused("policy differs from the session's policy".into()),
        ] {
            let (a, b) = UnixStream::pair().unwrap();
            let (op, payload) = reply.encode();
            send_frame(&a, op, &payload, &[]).unwrap();
            let (frame, _) = recv_frame(&b).unwrap();
            assert_eq!(Reply::decode(frame).unwrap(), reply);
        }
    }

    #[test]
    fn oversized_declared_length_is_refused_before_reading_the_payload() {
        // Only the header arrives: a receiver that tried to read the payload
        // would block or fail with I/O instead of reporting TooLarge.
        let (mut a, b) = UnixStream::pair().unwrap();
        let mut wire = vec![b'A'];
        wire.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        a.write_all(&wire).unwrap();
        match recv_frame(&b) {
            Err(ProtoError::TooLarge(n)) => assert_eq!(n, MAX_FRAME + 1),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn clean_close_is_eof_and_a_cut_frame_is_io() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(a);
        assert!(matches!(recv_frame(&b), Err(ProtoError::Eof)));

        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&[b'A', 0, 0, 0, 9, 1, 2]).unwrap();
        drop(a);
        assert!(matches!(recv_frame(&b), Err(ProtoError::Io(_))));
    }

    #[test]
    fn send_refuses_oversized_payloads_before_writing() {
        let (a, b) = UnixStream::pair().unwrap();
        let big = vec![0u8; MAX_FRAME + 1];
        assert!(matches!(
            send_frame(&a, b'A', &big, &[]),
            Err(ProtoError::TooLarge(_))
        ));
        drop(a);
        assert!(
            matches!(recv_frame(&b), Err(ProtoError::Eof)),
            "nothing was written"
        );
    }

    #[test]
    fn unknown_opcodes_and_bad_shapes_are_malformed() {
        let f = |op: u8, payload: &[u8]| Frame {
            op,
            payload: payload.to_vec(),
        };
        assert!(matches!(
            Request::decode(f(b'Z', &[])),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Request::decode(f(b'S', b"x")),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Request::decode(f(b'E', &[0; 15])),
            Err(ProtoError::Malformed(_))
        ));
        let mut bad_outcome = vec![0u8; 16];
        bad_outcome.extend_from_slice(b"exploded");
        assert!(matches!(
            Request::decode(f(b'E', &bad_outcome)),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Reply::decode(f(b'K', &[0; 3])),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Reply::decode(f(b'D', b"x")),
            Err(ProtoError::Malformed(_))
        ));
        assert!(matches!(
            Reply::decode(f(b'?', &[])),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn every_vocabulary_outcome_is_accepted() {
        for outcome in OUTCOMES {
            let end = Request::CallEnd(CallEnd {
                call_id: 1,
                rc: 0,
                duration_ms: 0,
                outcome,
            });
            assert_eq!(round_trip_request(end.clone()), end);
        }
    }

    #[test]
    fn refusal_reason_is_cut_at_a_char_boundary() {
        // 'é' is two bytes; a cut at 512 would split it, so it backs off to 511.
        let reason = format!("{}é", "a".repeat(511));
        let (_, payload) = Reply::Refused(reason).encode();
        assert_eq!(payload.len(), 511);
        assert!(std::str::from_utf8(&payload).is_ok());
    }
}
