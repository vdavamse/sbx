//! The HTTP/1 request stream (issue #29, F3): the pure, sans-IO splitter
//! that cuts a client's byte stream into request heads and framed bodies.
//! No I/O, no policy: [`super::http`] inspects each head and the relay
//! driver ([`super::relay::relay_http`]) moves the bytes.
//!
//! 1. **Heads** — [`HeadAccumulator`] collects bytes up to the first
//!    `\r\n\r\n` (3-byte overlap across pushes, so a terminator straddling two
//!    reads is never missed). It is capped by [`H1Limits::max_head_bytes`] with
//!    the lenient rule of `http::read_head` (a complete head beats its cap; the
//!    worst case is cap + one read chunk). Request 1 is read by that same code
//!    in the decision phase, so request 1 and requests 2+ share one accumulator.
//!    The accumulator does not look at line endings: a bare LF inside a head is
//!    denied by `http::parse_head_with` (and `explicit::parse_proxy_request`)
//!    before httparse runs, with `FRAMING_BARE_LF` (issue #29 review, item 6).
//!    That is the head's "no bare LF" rule; the chunk and trailer rules below
//!    are this module's own.
//! 2. **Content-Length** — [`BodyFramer::Length`] streams exactly `n` bytes.
//!    `Length(0)` never enters a body.
//! 3. **Chunked (RFC 9112 §7.1, strict profile)** — [`BodyFramer::Chunked`]:
//!    - a chunk-size line is `HEXDIG{1,16}` followed by CRLF, or by `;` and one
//!      or more bytes from HTAB, SP, 0x21–0x7E and 0x80–0xFF, then CRLF. No
//!      whitespace before `;` (RFC 9110 §5.6.3: senders must not generate it).
//!      A bare LF, a CR that is not followed by LF, NUL and every other control
//!      byte are denied. The line is capped at [`MAX_CHUNK_LINE`] bytes including
//!      CRLF. Leading zeros count toward the 16 digits, so `u64` cannot overflow.
//!    - chunk data is streamed, and the CRLF after it must be exactly `\r\n`
//!      (possibly split across reads).
//!    - the trailer section (after the last-chunk line) is buffered whole and
//!      forwarded only once the empty line ends it. Each field is
//!      `token ":" OWS value OWS CRLF`, with no obs-fold (a line starting with SP
//!      or HTAB), no bare LF, and no CTL in the value. The section is capped by
//!      the head caps (bytes and fields). Fields naming `Host`, `Content-Length`
//!      or `Transfer-Encoding` are denied.
//! 4. **Ordering guarantee** — `out` only ever receives bytes that have already
//!    passed validation. A denied element therefore never reaches the upstream,
//!    and the bytes forwarded before it are exactly the bytes before it. A
//!    denied trailer section forwards none of its own bytes.
//! 5. **Bodies are streamed, never buffered** — beyond the head accumulator, the
//!    4 KiB size line and the trailer section (both bounded), a body byte is
//!    appended to `out` as soon as it arrives, bounded by the input chunk.
//! 6. **Bytes after a body** — `feed` never consumes past a body's end. The
//!    caller loops over the rest of the same read, so pipelined bytes go into
//!    the next head or, after a last request, are discarded (`AfterLast`).
//! 7. **Last request (FLAG-3)** — [`RequestMeta::is_last`] is true for HTTP/1.0,
//!    `close`, `Upgrade`, and every request with a body. A request with a body
//!    is always the last request on its upstream connection, so nothing after
//!    its body is forwarded by the proxy. That is the proxy's half of the
//!    defence. A server that disagrees with the proxy about where the body ends
//!    (CL.0, the chunk differentials) still reads a smuggled request INSIDE the
//!    forwarded body. What stops it is the server honouring the inserted
//!    `Connection: close` (threat model R8(a)); the proxy cannot enforce that.
//!    Bodyless HTTP/1.1 requests keep the connection alive.
//! 8. **Request numbering** — [`RequestStream::index`] is the 1-based number of
//!    the request whose head is being inspected, or whose body is being framed.
//!    Teardown reasons quote it (`relay torn down: HTTP request 2 denied: …`).

use super::Limits;
use super::Rejected;
use super::http::{
    FRAMING_CHUNK_DATA_CRLF, FRAMING_CHUNK_LINE_TOO_LONG, FRAMING_CHUNK_SIZE,
    FRAMING_CHUNK_SIZE_OVERFLOW, FRAMING_TRAILER_FORBIDDEN, FRAMING_TRAILER_INVALID,
    FRAMING_TRAILER_TOO_LARGE, Framing,
};

/// The head terminator — the accumulator stops after its first occurrence.
pub(crate) const HEAD_TERMINATOR: [u8; 4] = *b"\r\n\r\n";

/// Cap on one chunk-size line, CRLF included (Go's `maxLineLength`; module
/// docs point 3). `FRAMING_CHUNK_LINE_TOO_LONG` names it, and a test pins the
/// agreement.
pub(crate) const MAX_CHUNK_LINE: usize = 4096;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const HTAB: u8 = b'\t';
const SP: u8 = b' ';

/// The per-request caps the stream enforces (copied from [`Limits`] so the
/// state machine stays pure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct H1Limits {
    /// Head byte cap (the lenient search cap) and the trailer-section byte cap.
    pub max_head_bytes: usize,
    /// Header slots for the head parser and the trailer field cap.
    pub max_http_headers: usize,
}

impl H1Limits {
    pub(crate) fn from_limits(limits: &Limits) -> Self {
        Self {
            max_head_bytes: limits.max_head_bytes,
            max_http_headers: limits.max_http_headers,
        }
    }
}

/// Locate the `\r\n\r\n` terminator in `buf`, returning the offset just past
/// it. `scanned` records how far the buffer was already ruled out, so the next
/// call resumes 3 bytes earlier (a terminator straddling two reads is still
/// found) instead of rescanning from the start.
pub(crate) fn find_terminator(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    let from = scanned.saturating_sub(3);
    if let Some(rel) = buf
        .get(from..)?
        .windows(4)
        .position(|window| window == HEAD_TERMINATOR)
    {
        return Some(from + rel + HEAD_TERMINATOR.len());
    }
    *scanned = buf.len();
    None
}

/// Collects one request head across pushes (module docs point 1). Bytes past
/// the terminator are reported back as unconsumed, never stored.
#[derive(Debug)]
pub(crate) struct HeadAccumulator {
    buf: Vec<u8>,
    scanned: usize,
    cap: usize,
}

impl HeadAccumulator {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            cap,
        }
    }

    /// Bytes of a head have arrived but its terminator has not (the per-head
    /// deadline runs while this holds).
    pub(crate) fn in_progress(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Append `input`. `Ok(Some((head, used)))` when the terminator completed:
    /// `head` is the whole head (every byte since the previous head) and `used`
    /// is how many bytes of THIS `input` belong to it. `Ok(None)` when the
    /// terminator is still unseen. `Err(HeadTooLarge)` when the buffer strictly
    /// exceeds the cap with no terminator in it.
    pub(crate) fn push(&mut self, input: &[u8]) -> Result<Option<(Vec<u8>, usize)>, Rejected> {
        self.buf.extend_from_slice(input);
        if let Some(head_end) = find_terminator(&self.buf, &mut self.scanned) {
            // The terminator cannot lie wholly inside the bytes already
            // buffered (they were ruled out on the previous push), so the tail
            // is a suffix of `input`.
            let tail_len = self.buf.len() - head_end;
            let mut head = std::mem::take(&mut self.buf);
            head.truncate(head_end);
            self.scanned = 0;
            return Ok(Some((head, input.len().saturating_sub(tail_len))));
        }
        if self.buf.len() > self.cap {
            return Err(Rejected::HeadTooLarge { cap: self.cap });
        }
        Ok(None)
    }
}

/// A body framer for one request (module docs points 2–3).
#[derive(Debug)]
pub(crate) enum BodyFramer {
    /// `Content-Length`: this many body bytes remain.
    Length { remaining: u64 },
    /// `chunked`: the chunked state machine.
    Chunked(ChunkedBody),
}

impl BodyFramer {
    /// The framer for a request's framing, or `None` when the request has no
    /// body (`None` or `Content-Length: 0`).
    pub(crate) fn new(framing: Framing, limits: H1Limits) -> Option<Self> {
        match framing {
            Framing::None | Framing::Length(0) => None,
            Framing::Length(remaining) => Some(BodyFramer::Length { remaining }),
            Framing::Chunked => Some(BodyFramer::Chunked(ChunkedBody {
                state: ChunkState::Size { line: Vec::new() },
                limits,
            })),
        }
    }

    /// Feed input. Appends the bytes that are safe to forward to `out` and
    /// returns `(consumed, done)`: `consumed` never runs past the body's end,
    /// and `done` is true once the body is complete.
    pub(crate) fn feed(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), Rejected> {
        match self {
            BodyFramer::Length { remaining } => {
                let take = usize::try_from((*remaining).min(input.len() as u64)).unwrap_or(0);
                out.extend_from_slice(&input[..take]);
                *remaining -= take as u64;
                Ok((take, *remaining == 0))
            }
            BodyFramer::Chunked(body) => body.feed(input, out),
        }
    }
}

/// The chunked decoder's state (module docs point 3).
#[derive(Debug)]
pub(crate) struct ChunkedBody {
    state: ChunkState,
    limits: H1Limits,
}

#[derive(Debug)]
enum ChunkState {
    /// Accumulating a chunk-size line (CRLF included); forwarded once valid.
    Size { line: Vec<u8> },
    /// Chunk data: `remaining` bytes are owed, forwarded as they arrive.
    Data { remaining: u64 },
    /// The CRLF after chunk data; `cr_seen` once its CR arrived.
    DataCrlf { cr_seen: bool },
    /// The trailer section: `section` holds every byte since the last-chunk
    /// line (fields and the final empty line), `line_start` the offset of the
    /// current line, `fields` the validated field count. Forwarded at the end.
    Trailers {
        section: Vec<u8>,
        line_start: usize,
        fields: usize,
    },
    /// The body is complete.
    Done,
}

fn chunk_err(detail: &'static str) -> Rejected {
    Rejected::AmbiguousFraming { detail }
}

impl ChunkedBody {
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(usize, bool), Rejected> {
        let mut pos = 0usize;
        while pos < input.len() {
            match &mut self.state {
                ChunkState::Done => return Ok((pos, true)),
                ChunkState::Data { remaining } => {
                    let avail = (input.len() - pos) as u64;
                    let take = usize::try_from((*remaining).min(avail)).unwrap_or(0);
                    out.extend_from_slice(&input[pos..pos + take]);
                    pos += take;
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.state = ChunkState::DataCrlf { cr_seen: false };
                    }
                }
                ChunkState::DataCrlf { cr_seen } => {
                    let byte = input[pos];
                    pos += 1;
                    if *cr_seen {
                        if byte != LF {
                            return Err(chunk_err(FRAMING_CHUNK_DATA_CRLF));
                        }
                        out.extend_from_slice(b"\r\n");
                        self.state = ChunkState::Size { line: Vec::new() };
                    } else if byte == CR {
                        *cr_seen = true;
                    } else {
                        return Err(chunk_err(FRAMING_CHUNK_DATA_CRLF));
                    }
                }
                ChunkState::Size { line } => {
                    let byte = input[pos];
                    pos += 1;
                    if line.len() + 1 > MAX_CHUNK_LINE {
                        return Err(chunk_err(FRAMING_CHUNK_LINE_TOO_LONG));
                    }
                    if line.last() == Some(&CR) {
                        // A CR must be followed by LF — anything else is a
                        // CR-only terminator, the differential shape.
                        if byte != LF {
                            return Err(chunk_err(FRAMING_CHUNK_SIZE));
                        }
                        line.push(LF);
                        let size = parse_chunk_size(&line[..line.len() - 2])?;
                        let line = std::mem::take(line);
                        out.extend_from_slice(&line);
                        self.state = if size == 0 {
                            ChunkState::Trailers {
                                section: Vec::new(),
                                line_start: 0,
                                fields: 0,
                            }
                        } else {
                            ChunkState::Data { remaining: size }
                        };
                    } else if byte == LF {
                        // A bare LF terminates the line for some parsers only.
                        return Err(chunk_err(FRAMING_CHUNK_SIZE));
                    } else {
                        line.push(byte);
                    }
                }
                ChunkState::Trailers {
                    section,
                    line_start,
                    fields,
                } => {
                    let byte = input[pos];
                    pos += 1;
                    if section.last() == Some(&CR) {
                        if byte != LF {
                            return Err(chunk_err(FRAMING_TRAILER_INVALID));
                        }
                        section.push(LF);
                        let end = section.len() - 2;
                        if *line_start == end {
                            // The empty line: the section (and the body) ends.
                            out.extend_from_slice(section);
                            self.state = ChunkState::Done;
                            return Ok((pos, true));
                        }
                        validate_trailer_field(
                            &section[*line_start..end],
                            fields,
                            self.limits.max_http_headers,
                        )?;
                        *line_start = section.len();
                    } else if byte == LF {
                        return Err(chunk_err(FRAMING_TRAILER_INVALID));
                    } else {
                        section.push(byte);
                    }
                    if section.len() > self.limits.max_head_bytes {
                        return Err(chunk_err(FRAMING_TRAILER_TOO_LARGE));
                    }
                }
            }
        }
        Ok((pos, matches!(self.state, ChunkState::Done)))
    }
}

/// Parse a chunk-size line WITHOUT its CRLF (module docs point 3). Every
/// rejection is `FRAMING_CHUNK_SIZE`.
pub(crate) fn parse_chunk_size(line: &[u8]) -> Result<u64, Rejected> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return Err(chunk_err(FRAMING_CHUNK_SIZE));
    }
    match line.get(digits..) {
        None | Some([]) => {}
        Some([b';', ext @ ..]) => {
            if ext.is_empty() || !ext.iter().all(|b| is_chunk_ext_byte(*b)) {
                return Err(chunk_err(FRAMING_CHUNK_SIZE));
            }
        }
        Some(_) => return Err(chunk_err(FRAMING_CHUNK_SIZE)),
    }
    let mut size = 0u64;
    for digit in &line[..digits] {
        let value = match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            _ => digit - b'A' + 10,
        };
        size = (size << 4) | u64::from(value);
    }
    // Issue #29 review, item 6: a size above i64::MAX is refused, never
    // truncated (7fffffffffffffff is the largest accepted).
    if size > i64::MAX as u64 {
        return Err(chunk_err(FRAMING_CHUNK_SIZE_OVERFLOW));
    }
    Ok(size)
}

/// Chunk-extension bytes: HTAB, SP, VCHAR and obs-text.
fn is_chunk_ext_byte(byte: u8) -> bool {
    byte == HTAB || byte == SP || (0x21..=0x7e).contains(&byte) || byte >= 0x80
}

/// RFC 9110 `tchar`.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Validate one trailer field line (CRLF excluded, non-empty): the
/// obs-fold, `token ":"`, forbidden-name, value and field-count rules of
/// module docs point 3.
fn validate_trailer_field(
    line: &[u8],
    fields: &mut usize,
    max_fields: usize,
) -> Result<(), Rejected> {
    if matches!(line.first(), Some(&SP) | Some(&HTAB)) {
        return Err(chunk_err(FRAMING_TRAILER_INVALID));
    }
    let Some(colon) = line.iter().position(|b| *b == b':') else {
        return Err(chunk_err(FRAMING_TRAILER_INVALID));
    };
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|b| is_tchar(*b)) {
        return Err(chunk_err(FRAMING_TRAILER_INVALID));
    }
    // Issue #29 review, item 7: `_` is folded to `-` before the forbidden-name
    // comparison, so `Content_Length` cannot slip past it.
    let folded: Vec<u8> = name
        .iter()
        .map(|b| if *b == b'_' { b'-' } else { *b })
        .collect();
    if ["host", "content-length", "transfer-encoding"]
        .iter()
        .any(|forbidden| folded.eq_ignore_ascii_case(forbidden.as_bytes()))
    {
        return Err(chunk_err(FRAMING_TRAILER_FORBIDDEN));
    }
    let value = trim_ows(&line[colon + 1..]);
    let value_ok = value
        .iter()
        .all(|b| *b == HTAB || *b == SP || (0x21..=0x7e).contains(b) || *b >= 0x80);
    if !value_ok {
        return Err(chunk_err(FRAMING_TRAILER_INVALID));
    }
    *fields += 1;
    if *fields > max_fields {
        return Err(chunk_err(FRAMING_TRAILER_TOO_LARGE));
    }
    Ok(())
}

/// Trim SP and HTAB from both ends (OWS).
fn trim_ows(raw: &[u8]) -> &[u8] {
    super::http::trim_ows(raw)
}

/// The per-request facts the stream and the relay need (built by
/// [`super::http::inspect_head`] from the parsed head).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestMeta {
    /// The body framing `check_framing` accepted.
    pub framing: Framing,
    /// HTTP/1.x minor version (0 or 1).
    pub minor_version: u8,
    /// A `close` token in `Connection` or `Proxy-Connection`.
    pub close: bool,
    /// An `Upgrade` field, or an `upgrade` token in `Connection`.
    pub upgrade: bool,
}

impl RequestMeta {
    /// The request carries a body (`Content-Length` > 0 or chunked).
    pub(crate) fn has_body(&self) -> bool {
        match self.framing {
            Framing::Chunked => true,
            Framing::Length(n) => n > 0,
            Framing::None => false,
        }
    }

    /// FLAG-3 (module docs point 7): the last request forwarded on its
    /// upstream connection. HTTP/1.0 is never kept alive (RFC 9112 App. C.2.2
    /// keep-alive is not supported).
    pub(crate) fn is_last(&self) -> bool {
        self.minor_version == 0 || self.close || self.upgrade || self.has_body()
    }
}

/// One result of [`RequestStream::feed`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// `consumed` input bytes were taken. Bytes in `out` (if any) are
    /// forwardable.
    Progress { consumed: usize },
    /// A head completed. `consumed` input bytes belong to it. The caller must
    /// inspect `head`, then call [`RequestStream::admit`] (or deny).
    Head { consumed: usize, head: Vec<u8> },
    /// The last request's framed end passed. `consumed` bytes were taken and
    /// everything after them is never forwarded.
    AfterLast { consumed: usize },
}

#[derive(Debug)]
enum State {
    Head(HeadAccumulator),
    Body(BodyFramer),
    AfterLast,
}

/// The request-stream state machine (module docs points 6–8).
#[derive(Debug)]
pub(crate) struct RequestStream {
    state: State,
    /// Heads admitted so far (request 1 counts: the decision phase admits it).
    admitted: u32,
    limits: H1Limits,
}

impl RequestStream {
    /// The stream after request 1 was inspected in the decision phase: its
    /// body (if any) is framed next, otherwise the stream waits for request 2's
    /// head (keep-alive) or is already past its last request.
    pub(crate) fn after_first(first: &RequestMeta, limits: H1Limits) -> Self {
        Self {
            state: Self::enter(first, limits),
            admitted: 1,
            limits,
        }
    }

    fn enter(meta: &RequestMeta, limits: H1Limits) -> State {
        match BodyFramer::new(meta.framing, limits) {
            Some(framer) => State::Body(framer),
            None if meta.is_last() => State::AfterLast,
            None => State::Head(HeadAccumulator::new(limits.max_head_bytes)),
        }
    }

    /// Feed input bytes. Forwardable bytes are appended to `out` (before the
    /// returned [`Step`] is acted on). A framing or cap error is returned as
    /// `Err`, and the caller tears the connection down.
    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Step, Rejected> {
        match &mut self.state {
            State::Head(acc) => Ok(match acc.push(input)? {
                None => Step::Progress {
                    consumed: input.len(),
                },
                Some((head, used)) => Step::Head {
                    consumed: used,
                    head,
                },
            }),
            State::Body(framer) => {
                let (consumed, done) = framer.feed(input, out)?;
                if done {
                    self.state = State::AfterLast;
                    Ok(Step::AfterLast { consumed })
                } else {
                    Ok(Step::Progress { consumed })
                }
            }
            State::AfterLast => Ok(Step::AfterLast {
                consumed: input.len(),
            }),
        }
    }

    /// Admit the head returned by [`Step::Head`]: frame its body, or wait for
    /// the next head, or stop after it.
    pub(crate) fn admit(&mut self, meta: &RequestMeta) {
        self.admitted = self.admitted.saturating_add(1);
        self.state = Self::enter(meta, self.limits);
    }

    /// The last request's framed end passed: nothing more may be read or
    /// forwarded from the client.
    pub(crate) fn after_last(&self) -> bool {
        matches!(self.state, State::AfterLast)
    }

    /// A head has started and not finished (the per-head deadline runs).
    pub(crate) fn head_in_progress(&self) -> bool {
        matches!(&self.state, State::Head(acc) if acc.in_progress())
    }

    /// The 1-based request number (module docs point 8).
    pub(crate) fn index(&self) -> u32 {
        match self.state {
            State::Head(_) => self.admitted.saturating_add(1),
            State::Body(_) | State::AfterLast => self.admitted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const LIMITS: H1Limits = H1Limits {
        max_head_bytes: 16 * 1024,
        max_http_headers: 64,
    };

    /// Feed `bytes` in one piece through a fresh framer. Returns everything
    /// forwarded (even on error) and the outcome.
    fn feed_all(framing: Framing, bytes: &[u8]) -> (Vec<u8>, Result<(usize, bool), Rejected>) {
        let Some(mut framer) = BodyFramer::new(framing, LIMITS) else {
            return (Vec::new(), Ok((0, true)));
        };
        let mut out = Vec::new();
        let result = framer.feed(bytes, &mut out);
        (out, result)
    }

    /// Feed `pieces` in order, looping each piece until it is consumed or the
    /// body is done (bytes past the end are never consumed).
    fn feed_pieces(framing: Framing, pieces: &[&[u8]]) -> Result<(Vec<u8>, usize, bool), Rejected> {
        let Some(mut framer) = BodyFramer::new(framing, LIMITS) else {
            return Ok((Vec::new(), 0, true));
        };
        let mut out = Vec::new();
        let mut consumed = 0usize;
        let mut done = false;
        for piece in pieces {
            let mut at = 0usize;
            while at < piece.len() && !done {
                let (taken, now_done) = framer.feed(&piece[at..], &mut out)?;
                at += taken;
                done = now_done;
                if taken == 0 && !now_done {
                    break;
                }
            }
            consumed += at;
            if done {
                break;
            }
        }
        Ok((out, consumed, done))
    }

    fn one_shot(framing: Framing, bytes: &[u8]) -> Result<(Vec<u8>, usize, bool), Rejected> {
        feed_pieces(framing, &[bytes])
    }

    /// The reject-row helper: the error must be exactly `detail`.
    fn assert_chunked_denied(bytes: &[u8], detail: &'static str) {
        assert_eq!(
            one_shot(Framing::Chunked, bytes),
            Err(Rejected::AmbiguousFraming { detail }),
            "{bytes:?}"
        );
    }

    // ---- Content-Length ----------------------------------------------------

    #[test]
    fn content_length_table() {
        // (length, input, forwarded, consumed, done)
        type Row<'a> = (u64, &'a [u8], &'a [u8], usize, bool);
        let rows: &[Row<'_>] = &[
            (4, b"body", b"body", 4, true),
            // Bytes past the body are not consumed: the next head's bytes stay
            // with the caller.
            (4, b"bodyGET / HTTP/1.1", b"body", 4, true),
            (4, b"bo", b"bo", 2, false),
            (1, b"x", b"x", 1, true),
            (3, b"", b"", 0, false),
        ];
        for (n, input, forwarded, consumed, done) in rows {
            let got = one_shot(Framing::Length(*n), input).expect("valid");
            assert_eq!(
                got,
                (forwarded.to_vec(), *consumed, *done),
                "cl={n} {input:?}"
            );
        }
    }

    #[test]
    fn content_length_split_across_feeds() {
        // The body boundary falls inside the third piece: the leftover bytes of
        // that piece are not consumed.
        let got = feed_pieces(Framing::Length(6), &[b"ab", b"cd", b"efGET"]).expect("valid");
        assert_eq!(got, (b"abcdef".to_vec(), 6, true));
    }

    #[test]
    fn length_zero_and_none_have_no_body() {
        assert!(BodyFramer::new(Framing::Length(0), LIMITS).is_none());
        assert!(BodyFramer::new(Framing::None, LIMITS).is_none());
        assert!(BodyFramer::new(Framing::Length(1), LIMITS).is_some());
        assert!(BodyFramer::new(Framing::Chunked, LIMITS).is_some());
    }

    // ---- chunked: valid rows ----------------------------------------------

    /// A valid chunked body is forwarded verbatim (the decoder never
    /// rewrites), so every valid row pins `out == input`.
    #[test]
    fn chunked_valid_table() {
        let rows: &[&[u8]] = &[
            b"0\r\n\r\n",
            b"3\r\nabc\r\n0\r\n\r\n",
            b"a\r\n0123456789\r\n0\r\n\r\n",
            b"A\r\n0123456789\r\n0\r\n\r\n",
            b"0000000000000003\r\nabc\r\n0\r\n\r\n",
            b"3;a\r\nabc\r\n0\r\n\r\n",
            b"3;a=b\r\nabc\r\n0\r\n\r\n",
            b"3;a=\"q v\"\r\nabc\r\n0\r\n\r\n",
            b"3;a\t=\x80\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabc\r\n0;last=1\r\n\r\n",
            b"3\r\nabc\r\n0\r\nX-A: b\r\n\r\n",
            b"3\r\nabc\r\n0\r\nX-A:\tb \t\r\nX-B:c\r\n\r\n",
            b"3\r\nabc\r\n0\r\nX-Empty:\r\n\r\n",
            b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n",
            b"3\r\n\r\nx\r\n0\r\n\r\n",
        ];
        for bytes in rows {
            let (out, consumed, done) = one_shot(Framing::Chunked, bytes).expect("valid");
            assert_eq!(out, bytes.to_vec(), "{bytes:?}");
            assert_eq!(consumed, bytes.len(), "{bytes:?}");
            assert!(done, "{bytes:?}");
        }
    }

    #[test]
    fn chunked_leftover_after_final_crlf_is_not_consumed() {
        let body = b"3\r\nabc\r\n0\r\n\r\n";
        let mut bytes = body.to_vec();
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let (out, consumed, done) = one_shot(Framing::Chunked, &bytes).expect("valid");
        assert_eq!(out, body.to_vec());
        assert_eq!(consumed, body.len());
        assert!(done);
    }

    #[test]
    fn chunk_size_line_cap_boundary() {
        // Exactly MAX_CHUNK_LINE bytes including CRLF is legal: "0;" + filler
        // + CRLF, then the empty trailer line.
        let mut ok = b"0;".to_vec();
        ok.extend(std::iter::repeat_n(b'e', MAX_CHUNK_LINE - 4));
        ok.extend_from_slice(b"\r\n\r\n");
        let (out, consumed, done) = one_shot(Framing::Chunked, &ok).expect("at the cap");
        assert_eq!((out.len(), consumed, done), (ok.len(), ok.len(), true));

        // One byte more is denied, whatever the filler.
        let mut over = b"0;".to_vec();
        over.extend(std::iter::repeat_n(b'e', MAX_CHUNK_LINE - 3));
        over.extend_from_slice(b"\r\n\r\n");
        assert_chunked_denied(&over, FRAMING_CHUNK_LINE_TOO_LONG);
    }

    #[test]
    fn chunk_line_too_long_detail_names_the_cap() {
        assert!(FRAMING_CHUNK_LINE_TOO_LONG.contains(&MAX_CHUNK_LINE.to_string()));
    }

    // ---- chunked: rejected rows (each pins its FRAMING_* detail) ----------

    #[test]
    fn chunked_reject_table() {
        let rows: &[(&[u8], &str)] = &[
            // Size-line grammar.
            (b"11111111111111111\r\nx\r\n", FRAMING_CHUNK_SIZE), // 17 hex digits
            (b"zz\r\n", FRAMING_CHUNK_SIZE),                     // non-hex size
            (b"\r\n", FRAMING_CHUNK_SIZE),                       // empty size
            (b"3 ;a\r\nabc\r\n", FRAMING_CHUNK_SIZE),            // BWS before ';'
            (b"3\n", FRAMING_CHUNK_SIZE),                        // bare LF
            (b"3\rX", FRAMING_CHUNK_SIZE),                       // CR without LF
            (b"3;a\x00\r\n", FRAMING_CHUNK_SIZE),                // NUL in an extension
            (b"3;a\x01\r\n", FRAMING_CHUNK_SIZE),                // CTL in an extension
            (b"3;\r\n", FRAMING_CHUNK_SIZE),                     // ';' with no extension
            (b"3x\r\n", FRAMING_CHUNK_SIZE),                     // junk after the digits
            // Chunk-data terminator.
            (b"3\r\nabc\nXX", FRAMING_CHUNK_DATA_CRLF), // LF where the CR goes
            (b"3\r\nabcXX", FRAMING_CHUNK_DATA_CRLF),   // no CRLF at all
            (b"3\r\nabc\rX", FRAMING_CHUNK_DATA_CRLF),  // CR, then not LF
            // Trailer section.
            (b"0\r\nX-A: b\nX-B: c\r\n\r\n", FRAMING_TRAILER_INVALID), // bare LF
            (b"0\r\nX-A: b\r\n c\r\n\r\n", FRAMING_TRAILER_INVALID),   // obs-fold
            (b"0\r\n X-A: b\r\n\r\n", FRAMING_TRAILER_INVALID),        // leading SP
            (b"0\r\nX A: b\r\n\r\n", FRAMING_TRAILER_INVALID),         // space in name
            (b"0\r\n: b\r\n\r\n", FRAMING_TRAILER_INVALID),            // empty name
            (b"0\r\nX-A b\r\n\r\n", FRAMING_TRAILER_INVALID),          // no colon
            (b"0\r\nX-A: b\x01\r\n\r\n", FRAMING_TRAILER_INVALID),     // CTL in value
            (b"0\r\nX-A: \x7f\r\n\r\n", FRAMING_TRAILER_INVALID),      // DEL in value
            (b"0\r\nX-A\x01: b\r\n\r\n", FRAMING_TRAILER_INVALID),     // CTL in name
            (b"0\r\nHost: a.test\r\n\r\n", FRAMING_TRAILER_FORBIDDEN),
            (b"0\r\nhost: a.test\r\n\r\n", FRAMING_TRAILER_FORBIDDEN),
            (b"0\r\nContent-Length: 0\r\n\r\n", FRAMING_TRAILER_FORBIDDEN),
            (
                b"0\r\nTransfer-Encoding: chunked\r\n\r\n",
                FRAMING_TRAILER_FORBIDDEN,
            ),
        ];
        for (bytes, detail) in rows {
            assert_chunked_denied(bytes, detail);
        }
    }

    #[test]
    fn trailer_section_caps() {
        // Over the byte cap: one long field line.
        let limits = H1Limits {
            max_head_bytes: 64,
            max_http_headers: 64,
        };
        let mut long = b"0\r\nX-Pad: ".to_vec();
        long.extend(std::iter::repeat_n(b'p', 64));
        long.extend_from_slice(b"\r\n\r\n");
        let mut framer = BodyFramer::new(Framing::Chunked, limits).expect("chunked");
        let mut out = Vec::new();
        assert_eq!(
            framer.feed(&long, &mut out),
            Err(Rejected::AmbiguousFraming {
                detail: FRAMING_TRAILER_TOO_LARGE
            })
        );
        assert_eq!(out, b"0\r\n".to_vec(), "no trailer byte is forwarded");

        // Over the field cap: 3 fields with max 2.
        let limits = H1Limits {
            max_head_bytes: 1024,
            max_http_headers: 2,
        };
        let three = b"0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        let mut framer = BodyFramer::new(Framing::Chunked, limits).expect("chunked");
        let mut out = Vec::new();
        assert_eq!(
            framer.feed(three, &mut out),
            Err(Rejected::AmbiguousFraming {
                detail: FRAMING_TRAILER_TOO_LARGE
            })
        );
        // Exactly the cap is fine.
        let two = b"0\r\nA: 1\r\nB: 2\r\n\r\n";
        let mut framer = BodyFramer::new(Framing::Chunked, limits).expect("chunked");
        let mut out = Vec::new();
        assert_eq!(framer.feed(two, &mut out), Ok((two.len(), true)));
    }

    /// Module docs point 4: an invalid element never reaches `out`; the bytes
    /// forwarded before it are exactly the bytes before it. A trailer section
    /// forwards nothing of its own on any denial.
    #[test]
    fn nothing_invalid_is_forwarded() {
        let rows: &[(&[u8], &[u8])] = &[
            (b"3 ;a\r\nabc\r\n", b""),
            (b"3\r\nabc\nXX", b"3\r\nabc"),
            (b"3\r\nabcXX", b"3\r\nabc"),
            (b"3\r\nabc\r\nzz\r\n", b"3\r\nabc\r\n"),
            (b"0\r\nX-A: b\nX-B: c\r\n\r\n", b"0\r\n"),
            (b"0\r\nHost: a.test\r\n\r\n", b"0\r\n"),
        ];
        for (bytes, expected) in rows {
            let (out, result) = feed_all(Framing::Chunked, bytes);
            assert!(result.is_err(), "{bytes:?} must be denied");
            assert_eq!(out, expected.to_vec(), "{bytes:?}");
            assert!(bytes.starts_with(&out), "{bytes:?}");
        }
    }

    /// Issue #29 review, item 6: a chunk size above i64::MAX is refused. The
    /// largest accepted is 7fffffffffffffff; the first refused is 8000000000000000.
    #[test]
    fn chunk_size_i64_limit_table() {
        assert_eq!(parse_chunk_size(b"7fffffffffffffff"), Ok(i64::MAX as u64));
        assert_eq!(parse_chunk_size(b"0000000000000003"), Ok(3));
        for line in [&b"8000000000000000"[..], b"ffffffffffffffff"] {
            assert_eq!(
                parse_chunk_size(line),
                Err(Rejected::AmbiguousFraming {
                    detail: FRAMING_CHUNK_SIZE_OVERFLOW,
                }),
                "{line:?}"
            );
        }
        // The stream accepts the largest size line and waits for its data.
        let line: &[u8] = b"7fffffffffffffff\r\n";
        assert_eq!(
            feed_pieces(Framing::Chunked, &[line]),
            Ok((line.to_vec(), line.len(), false))
        );
    }

    /// Issue #29 review, item 7: a trailer name is folded (`_` to `-`) before the
    /// forbidden-name comparison.
    #[test]
    fn trailer_names_fold_underscores_before_the_forbidden_check() {
        let rows: &[&[u8]] = &[
            b"0\r\nContent_Length: 0\r\n\r\n",
            b"0\r\ncontent_length: 0\r\n\r\n",
            b"0\r\nTransfer_Encoding: chunked\r\n\r\n",
            b"0\r\nHost_: a.test\r\n\r\n",
        ];
        for (index, bytes) in rows.iter().enumerate() {
            let want = if index == 3 {
                // `Host_` folds to `host-`, which is not Host: a plain field.
                None
            } else {
                Some(FRAMING_TRAILER_FORBIDDEN)
            };
            match want {
                Some(detail) => assert_chunked_denied(bytes, detail),
                None => assert!(one_shot(Framing::Chunked, bytes).is_ok(), "{bytes:?}"),
            }
        }
    }

    // ---- RequestMeta::is_last (module docs point 7) -----------------------

    #[test]
    fn is_last_table() {
        let meta = |minor, close, upgrade, framing| RequestMeta {
            framing,
            minor_version: minor,
            close,
            upgrade,
        };
        let rows: &[(RequestMeta, bool)] = &[
            (meta(0, false, false, Framing::None), true), // HTTP/1.0
            (meta(1, false, false, Framing::None), false), // 1.1 bodyless
            (meta(1, false, false, Framing::Length(0)), false), // CL 0
            (meta(1, false, false, Framing::Length(5)), true), // CL 5
            (meta(1, false, false, Framing::Chunked), true), // chunked
            (meta(1, true, false, Framing::None), true),  // close token
            (meta(1, false, true, Framing::None), true),  // Upgrade
            (meta(0, false, false, Framing::Length(0)), true), // 1.0 CL 0
        ];
        for (request, last) in rows {
            assert_eq!(request.is_last(), *last, "{request:?}");
        }
    }

    // ---- HeadAccumulator ---------------------------------------------------

    #[test]
    fn head_accumulator_cap_and_terminator() {
        // A terminator-less push of exactly the cap is fine; one byte over is
        // HeadTooLarge (the same strict-overrun rule as read_head).
        let mut acc = HeadAccumulator::new(8);
        assert!(acc.push(b"XXXXXXXX").expect("at the cap").is_none());
        assert!(acc.in_progress());
        assert_eq!(acc.push(b"X"), Err(Rejected::HeadTooLarge { cap: 8 }));

        // The terminator straddling two pushes is found, and `used` counts only
        // the bytes of the second push that belong to the head.
        let mut acc = HeadAccumulator::new(1024);
        assert!(
            acc.push(b"GET / HTTP/1.1\r\n\r")
                .expect("partial")
                .is_none()
        );
        let (head, used) = acc.push(b"\nPIPELINED").expect("ok").expect("complete");
        assert_eq!(head, b"GET / HTTP/1.1\r\n\r\n".to_vec());
        assert_eq!(used, 1);
        assert!(
            !acc.in_progress(),
            "the accumulator is reset for the next head"
        );
    }

    #[test]
    fn head_accumulator_complete_head_beats_its_cap() {
        // The lenient rule (module docs point 1): a head complete in the same
        // push wins over the cap check.
        let head = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let mut acc = HeadAccumulator::new(head.len() - 1);
        let (got, used) = acc.push(head).expect("ok").expect("complete");
        assert_eq!((got.as_slice(), used), (&head[..], head.len()));
    }

    // ---- RequestStream -----------------------------------------------------

    const KEEP_ALIVE: RequestMeta = RequestMeta {
        framing: Framing::None,
        minor_version: 1,
        close: false,
        upgrade: false,
    };

    fn post(len: u64) -> RequestMeta {
        RequestMeta {
            framing: Framing::Length(len),
            ..KEEP_ALIVE
        }
    }

    /// One event of the request-stream protocol, as the driver sees it.
    #[derive(Debug, PartialEq)]
    enum Ev {
        Out(Vec<u8>),
        Head(Vec<u8>, u32),
        AfterLast,
        Denied(u32, Rejected),
    }

    /// Mini driver (the relay's loop, minus I/O): `heads` maps each head's
    /// start to the meta the inspector would return. Splits `bytes` at `cuts`.
    fn drive(first: RequestMeta, bytes: &[u8], cuts: &[usize]) -> Vec<Ev> {
        let limits = LIMITS;
        let mut stream = RequestStream::after_first(&first, limits);
        let mut events: Vec<Ev> = Vec::new();
        let mut pieces: Vec<&[u8]> = Vec::new();
        let mut at = 0usize;
        let mut cuts: Vec<usize> = cuts.iter().map(|c| (*c).min(bytes.len())).collect();
        cuts.sort_unstable();
        for cut in cuts.into_iter().chain(std::iter::once(bytes.len())) {
            if cut >= at {
                pieces.push(&bytes[at..cut]);
                at = cut;
            }
        }
        'pieces: for piece in pieces {
            let mut pos = 0usize;
            while pos < piece.len() {
                if stream.after_last() {
                    events.push(Ev::AfterLast);
                    break 'pieces;
                }
                let mut out = Vec::new();
                let result = stream.feed(&piece[pos..], &mut out);
                // Validated bytes are forwarded before the outcome is acted on
                // (the relay writes `out` first, then tears down on Err).
                if !out.is_empty() {
                    push_out(&mut events, out);
                }
                let step = match result {
                    Ok(step) => step,
                    Err(rejected) => {
                        events.push(Ev::Denied(stream.index(), rejected));
                        break 'pieces;
                    }
                };
                match step {
                    Step::Progress { consumed } => {
                        assert!(consumed > 0, "progress must consume");
                        pos += consumed;
                    }
                    Step::AfterLast { .. } => {
                        events.push(Ev::AfterLast);
                        break 'pieces;
                    }
                    Step::Head { consumed, head } => {
                        pos += consumed;
                        let meta = if head.starts_with(b"POST ") {
                            post(4)
                        } else {
                            KEEP_ALIVE
                        };
                        events.push(Ev::Head(head.clone(), stream.index()));
                        stream.admit(&meta);
                    }
                }
            }
        }
        events
    }

    fn push_out(events: &mut Vec<Ev>, out: Vec<u8>) {
        if let Some(Ev::Out(last)) = events.last_mut() {
            last.extend_from_slice(&out);
        } else {
            events.push(Ev::Out(out));
        }
    }

    const PIPELINE: &[u8] = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n\
        GET /b HTTP/1.1\r\nHost: x\r\n\r\n\
        POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nbody\
        GET /d HTTP/1.1\r\nHost: x\r\n\r\n";

    #[test]
    fn request_stream_pipeline_table() {
        let events = drive(KEEP_ALIVE, PIPELINE, &[]);
        let head_a = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let head_b = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let head_c = b"POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n".to_vec();
        // Request 1 was admitted by the decision phase, so the next head is 2.
        assert_eq!(
            events,
            vec![
                Ev::Head(head_a, 2),
                Ev::Head(head_b, 3),
                Ev::Head(head_c, 4),
                Ev::Out(b"body".to_vec()),
                Ev::AfterLast,
            ]
        );
    }

    /// The same pipeline under every single split point, and under a
    /// one-byte-at-a-time feed: the event sequence never changes.
    #[test]
    fn request_stream_split_invariance_table() {
        let expected = drive(KEEP_ALIVE, PIPELINE, &[]);
        for cut in 0..=PIPELINE.len() {
            assert_eq!(drive(KEEP_ALIVE, PIPELINE, &[cut]), expected, "cut {cut}");
        }
        let everywhere: Vec<usize> = (0..=PIPELINE.len()).collect();
        assert_eq!(drive(KEEP_ALIVE, PIPELINE, &everywhere), expected);
    }

    #[test]
    fn request_stream_after_last_forwards_nothing_more() {
        // A close request: its head is the last admitted; the bytes after it
        // are never forwarded.
        let close = RequestMeta {
            close: true,
            ..KEEP_ALIVE
        };
        let bytes = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\nGET /c HTTP/1.1\r\nHost: x\r\n\r\n";
        let events = drive(close, bytes, &[]);
        assert_eq!(events, vec![Ev::AfterLast]);
        let mut stream = RequestStream::after_first(&close, LIMITS);
        assert!(stream.after_last());
        let mut out = Vec::new();
        assert_eq!(
            stream.feed(b"GET /z HTTP/1.1\r\n", &mut out),
            Ok(Step::AfterLast { consumed: 17 })
        );
        assert!(out.is_empty());
    }

    #[test]
    fn request_stream_denies_bad_chunk_before_forwarding_it() {
        // Request 1 carries the chunked body (the decision phase admitted it).
        let chunked = RequestMeta {
            framing: Framing::Chunked,
            ..KEEP_ALIVE
        };
        let bytes = b"3\r\nabc\r\nzz\r\nGET / HTTP/1.1\r\n";
        let events = drive(chunked, bytes, &[]);
        assert_eq!(
            events,
            vec![
                Ev::Out(b"3\r\nabc\r\n".to_vec()),
                Ev::Denied(
                    1,
                    Rejected::AmbiguousFraming {
                        detail: FRAMING_CHUNK_SIZE
                    }
                ),
            ]
        );
    }

    #[test]
    fn request_stream_index_and_head_in_progress() {
        let mut stream = RequestStream::after_first(&KEEP_ALIVE, LIMITS);
        assert_eq!(stream.index(), 2, "request 1 is admitted; 2 is next");
        assert!(!stream.head_in_progress());
        let mut out = Vec::new();
        assert_eq!(
            stream.feed(b"GET /b HT", &mut out),
            Ok(Step::Progress { consumed: 9 })
        );
        assert!(stream.head_in_progress());
        assert_eq!(stream.index(), 2);
    }

    // ---- property tests ----------------------------------------------------

    /// Split `len` bytes at the given cut points (clamped, sorted).
    fn pieces_of<'a>(bytes: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
        let mut cuts: Vec<usize> = cuts.iter().map(|c| (*c).min(bytes.len())).collect();
        cuts.sort_unstable();
        let mut pieces = Vec::new();
        let mut at = 0usize;
        for cut in cuts.into_iter().chain(std::iter::once(bytes.len())) {
            pieces.push(&bytes[at..cut]);
            at = cut;
        }
        pieces
    }

    /// A valid chunked body: `chunks` (data + an optional extension), a
    /// last-chunk line (optional extension), trailers, and the final CRLF.
    /// Returns (encoded body, payload).
    fn encode_chunked(
        chunks: &[(Vec<u8>, bool)],
        trailers: &[(String, String)],
        last_ext: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut encoded = Vec::new();
        let mut payload = Vec::new();
        for (data, ext) in chunks {
            encoded.extend_from_slice(format!("{:x}", data.len()).as_bytes());
            if *ext {
                encoded.extend_from_slice(b";ext=\"q v\"");
            }
            encoded.extend_from_slice(b"\r\n");
            encoded.extend_from_slice(data);
            encoded.extend_from_slice(b"\r\n");
            payload.extend_from_slice(data);
        }
        encoded.extend_from_slice(b"0");
        if last_ext {
            encoded.extend_from_slice(b";last");
        }
        encoded.extend_from_slice(b"\r\n");
        for (name, value) in trailers {
            encoded.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        encoded.extend_from_slice(b"\r\n");
        (encoded, payload)
    }

    /// A reference decoder for the round-trip check: the payload of a valid
    /// chunked body (ignores extensions and trailers, which the valid rows pin).
    fn decode_payload(encoded: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut at = 0usize;
        loop {
            let line_end = at
                + encoded[at..]
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .expect("line");
            let size_text = std::str::from_utf8(&encoded[at..line_end]).expect("ascii");
            let size_hex = size_text.split(';').next().expect("size");
            let size = usize::from_str_radix(size_hex, 16).expect("hex");
            at = line_end + 2;
            if size == 0 {
                return payload;
            }
            payload.extend_from_slice(&encoded[at..at + size]);
            at += size + 2;
        }
    }

    fn prop_chunks() -> impl Strategy<Value = Vec<(Vec<u8>, bool)>> {
        proptest::collection::vec(
            (
                proptest::collection::vec(any::<u8>(), 1..=24),
                any::<bool>(),
            ),
            0..=4,
        )
    }

    fn prop_trailers() -> impl Strategy<Value = Vec<(String, String)>> {
        proptest::collection::vec(
            (
                prop_oneof![Just("X-A"), Just("x-b"), Just("Trace-Id")].prop_map(str::to_owned),
                "[ -~]{0,12}",
            ),
            0..=3,
        )
    }

    proptest! {
        /// The round trip: a valid chunked body with random trailers and
        /// extensions, followed by pipelined bytes, is forwarded verbatim, its
        /// decoded payload is the original data, and the framer stops at the
        /// body's end whatever the split.
        #[test]
        fn chunked_round_trip(
            chunks in prop_chunks(),
            trailers in prop_trailers(),
            last_ext in any::<bool>(),
            tail in proptest::collection::vec(any::<u8>(), 0..=16),
            cuts in proptest::collection::vec(0usize..=400, 0..=6),
        ) {
            let (encoded, payload) = encode_chunked(&chunks, &trailers, last_ext);
            prop_assert_eq!(decode_payload(&encoded), payload);
            let mut bytes = encoded.clone();
            bytes.extend_from_slice(&tail);
            let pieces = pieces_of(&bytes, &cuts);
            let got = feed_pieces(Framing::Chunked, &pieces).expect("valid body");
            prop_assert_eq!(got, (encoded.clone(), encoded.len(), true));
        }

        /// Split invariance for Content-Length bodies: any split gives the same
        /// forwarded bytes, consumed count and done flag as a one-shot feed.
        #[test]
        fn framer_split_invariance_length(
            body in proptest::collection::vec(any::<u8>(), 1..=64),
            extra in 0usize..=8,
            tail in proptest::collection::vec(any::<u8>(), 0..=16),
            cuts in proptest::collection::vec(0usize..=96, 0..=6),
        ) {
            let mut bytes = body.clone();
            bytes.extend_from_slice(&tail);
            let framing = Framing::Length(body.len() as u64 - extra.min(body.len() - 1) as u64);
            let one = one_shot(framing, &bytes);
            let split = feed_pieces(framing, &pieces_of(&bytes, &cuts));
            prop_assert_eq!(split, one);
        }

        /// Split invariance for chunked bodies, valid or not: the same forwarded
        /// bytes and the same accept/deny outcome under any split.
        #[test]
        fn framer_split_invariance_chunked(
            bytes in proptest::collection::vec(
                prop_oneof![
                    Just(b'0'), Just(b'3'), Just(b'a'), Just(b'\r'), Just(b'\n'),
                    Just(b';'), Just(b'X'), Just(b':'), Just(b' '), any::<u8>(),
                ],
                0..=200,
            ),
            cuts in proptest::collection::vec(0usize..=200, 0..=8),
        ) {
            let one = one_shot(Framing::Chunked, &bytes);
            let split = feed_pieces(Framing::Chunked, &pieces_of(&bytes, &cuts));
            prop_assert_eq!(split, one);
        }

        /// Garbage in, only Ok/Err out: no panic, and never more bytes forwarded
        /// than were fed.
        #[test]
        fn framer_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..=300),
            chunked in any::<bool>(),
            cuts in proptest::collection::vec(0usize..=300, 0..=8),
        ) {
            let framing = if chunked { Framing::Chunked } else { Framing::Length(200) };
            let Some(mut framer) = BodyFramer::new(framing, LIMITS) else {
                return Ok(());
            };
            let mut out = Vec::new();
            let mut fed = 0usize;
            for piece in pieces_of(&bytes, &cuts) {
                fed += piece.len();
                if framer.feed(piece, &mut out).is_err() {
                    break;
                }
            }
            prop_assert!(out.len() <= fed);
            prop_assert!(out.len() <= bytes.len());
        }

        /// The request stream under random splits: the pipelined
        /// [GET, GET, POST+body, GET] yields the same events as a one-shot feed.
        #[test]
        fn request_stream_split_invariance_prop(
            cuts in proptest::collection::vec(0usize..=PIPELINE.len(), 0..=12),
        ) {
            let expected = drive(KEEP_ALIVE, PIPELINE, &[]);
            prop_assert_eq!(drive(KEEP_ALIVE, PIPELINE, &cuts), expected);
        }
    }
}
