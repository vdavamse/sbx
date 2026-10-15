//! The JSONL audit log (issue #10, T2, Q6–Q8). Schema: notes §5. One row per
//! event, written with one `write_all` under the log mutex; keys are emitted in
//! a fixed order; exit-only keys appear on the `exit` row alone.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use super::Outcome;
use super::RunError;
use super::plan::{exit_reason, outcome_label, outcome_signal};
use super::serve::{Fault, FaultLatch};
use crate::dns::{DnsDecision, DnsSink};
use crate::proxy::{Decision, DecisionSink, Verdict, Via};

#[derive(Serialize)]
pub(crate) struct Bytes {
    up: u64,
    down: u64,
}

#[derive(Serialize)]
pub(crate) struct ExitFields {
    code: i32,
    outcome: &'static str,
    signal: Option<i32>,
    duration_ms: u64,
    output_truncated: bool,
    dns_poisoned: bool,
}

/// One audit row. Field order IS the schema (§5 rows 1–12, then the exit-only
/// tail flattened in when present).
#[derive(Serialize)]
pub(crate) struct Row {
    ts: String,
    event: &'static str,
    host: Option<String>,
    sni: Option<String>,
    port: Option<u16>,
    bytes: Option<Bytes>,
    reason: Option<String>,
    via: Option<&'static str>,
    verdict: Option<&'static str>,
    rcode: Option<u16>,
    qtype: Option<u16>,
    client: Option<String>,
    #[serde(flatten)]
    exit: Option<ExitFields>,
}

impl Row {
    fn blank(ts: String, event: &'static str) -> Self {
        Self {
            ts,
            event,
            host: None,
            sni: None,
            port: None,
            bytes: None,
            reason: None,
            via: None,
            verdict: None,
            rcode: None,
            qtype: None,
            client: None,
            exit: None,
        }
    }
}

/// RFC 3339, UTC, millisecond precision, `Z`.
pub(crate) fn ts(t: SystemTime) -> String {
    humantime::format_rfc3339_millis(t).to_string()
}

fn port_of(via: &Via) -> Option<u16> {
    match via {
        Via::Transparent { orig_dst } => orig_dst.map(|a| a.port()),
        Via::Explicit { port, .. } => *port,
    }
}

/// `sni` is the host iff the verdict is Allowed AND the port is 443 (the SNI
/// was verified equal to the mapped name); anything else is null.
fn sni_of(d: &Decision, port: Option<u16>) -> Option<String> {
    match (&d.verdict, port) {
        (Verdict::Allowed { name, .. }, Some(443)) => Some(name.as_str().to_owned()),
        _ => None,
    }
}

fn proxy_base(ts: String, event: &'static str, d: &Decision) -> Row {
    let port = port_of(&d.via);
    let mut row = Row::blank(ts, event);
    row.host = d.name.as_ref().map(|n| n.as_str().to_owned());
    row.sni = sni_of(d, port);
    row.port = port;
    row.via = Some(d.via.label());
    row.client = Some(d.client.to_string());
    row
}

/// connect (Allowed) or deny/denied|error (Denied|Error) at decision time.
pub(crate) fn decision_row(ts: String, d: &Decision) -> Row {
    match &d.verdict {
        Verdict::Allowed { .. } => {
            let mut row = proxy_base(ts, "connect", d);
            row.reason = Some(d.reason());
            row.verdict = Some("allowed");
            row
        }
        Verdict::Denied(_) => {
            let mut row = proxy_base(ts, "deny", d);
            row.reason = Some(d.reason());
            row.verdict = Some("denied");
            row
        }
        Verdict::Error(_) => {
            let mut row = proxy_base(ts, "deny", d);
            row.reason = Some(d.reason());
            row.verdict = Some("error");
            row
        }
    }
}

/// deny/teardown: the relay's pinned teardown detail is the reason.
pub(crate) fn teardown_row(ts: String, d: &Decision, detail: &str) -> Row {
    let mut row = proxy_base(ts, "deny", d);
    row.reason = Some(detail.to_owned());
    row.verdict = Some("teardown");
    row
}

/// close: the relay ended; byte counts from the upstream wrapper.
pub(crate) fn close_row(ts: String, d: &Decision, up: u64, down: u64) -> Row {
    let mut row = proxy_base(ts, "close", d);
    row.bytes = Some(Bytes { up, down });
    row.verdict = Some("allowed");
    row
}

/// dns: one row per datagram; the outcome is `verdict`.
pub(crate) fn dns_row(ts: String, d: &DnsDecision) -> Row {
    let mut row = Row::blank(ts, "dns");
    row.host = d.question.as_ref().map(|q| q.name.clone());
    row.reason = Some(d.reason());
    row.verdict = Some(d.verdict.label());
    row.rcode = d.verdict.rcode();
    row.qtype = d.question.as_ref().map(|q| q.qtype);
    row.client = Some(d.client.to_string());
    row
}

/// exit: always the last row of a run.
pub(crate) fn exit_row(
    ts: String,
    o: &Outcome,
    duration: Duration,
    truncated: bool,
    poisoned: bool,
) -> Row {
    let mut row = Row::blank(ts, "exit");
    row.reason = Some(exit_reason(o));
    row.exit = Some(ExitFields {
        code: super::plan::exit_code(o),
        outcome: outcome_label(o),
        signal: outcome_signal(o),
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        output_truncated: truncated,
        dns_poisoned: poisoned,
    });
    row
}

/// One JSON object + `\n`. Serialisation of these types cannot fail; the
/// fallback keeps the no-panic contract anyway.
pub(crate) fn line(row: &Row) -> Vec<u8> {
    let mut out = serde_json::to_vec(row)
        .unwrap_or_else(|_| br#"{"event":"error","reason":"row serialisation failed"}"#.to_vec());
    out.push(b'\n');
    out
}

/// `O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, mode 0600.
/// O_NONBLOCK makes a planted FIFO fail instantly (ENXIO) instead of hanging;
/// it is cleared again once the file is known to be a regular file.
pub(crate) fn open_audit(path: &Path) -> Result<File, RunError> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| RunError::new(format!("cannot open audit log {path:?}: {err}")))?;
    let meta = file
        .metadata()
        .map_err(|err| RunError::new(format!("cannot open audit log {path:?}: {err}")))?;
    if !meta.file_type().is_file() {
        return Err(RunError::new(format!(
            "audit log {path:?} is not a regular file"
        )));
    }
    // M2: never append to a file another user owns, or one with other hard
    // links (a link could alias it into a place the lexical checks cannot see).
    // SAFETY: geteuid has no preconditions and cannot fail.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(RunError::new(format!(
            "audit log {path:?} is not owned by the current user"
        )));
    }
    if meta.nlink() != 1 {
        return Err(RunError::new(format!(
            "audit log {path:?} has more than one hard link"
        )));
    }
    // SAFETY: F_GETFL/F_SETFL on the fd we just opened; clearing O_NONBLOCK
    // restores blocking writes for the rest of the run.
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0
        {
            return Err(RunError::new(format!(
                "cannot configure audit log {path:?}: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(file)
}

struct AuditState {
    file: File,
    /// The first write failure, verbatim (M1: fail closed, reported by the caller).
    failure: Option<String>,
    finished: bool,
}

/// The run's audit sink (both the proxy and the DNS side write through it).
pub(crate) struct AuditLog {
    inner: Option<Mutex<AuditState>>,
    latch: Arc<FaultLatch>,
}

impl AuditLog {
    /// `None` = no `--audit` (Q8): every write is a no-op.
    pub(crate) fn new(file: Option<File>, latch: Arc<FaultLatch>) -> Arc<Self> {
        Arc::new(Self {
            inner: file.map(|file| {
                Mutex::new(AuditState {
                    file,
                    failure: None,
                    finished: false,
                })
            }),
            latch,
        })
    }

    fn lock(&self) -> Option<std::sync::MutexGuard<'_, AuditState>> {
        self.inner
            .as_ref()
            .map(|m| m.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Appends one row with ONE write(2) under an advisory `flock(LOCK_EX)` on the
    /// shared file. The pre-write offset is the REAL end of file (fstat under the
    /// lock), never a snapshot: several runs may share one `--audit` file, and a
    /// failed write must only remove this write's own bytes (review 2). A short write
    /// or an error truncates the file back to that offset, so no torn row is left.
    fn append(file: &File, bytes: &[u8]) -> Result<(), String> {
        let fd = file.as_raw_fd();
        // SAFETY: flock on the fd this log owns; LOCK_EX waits for other writers.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let result = (|| {
            let pre = file.metadata().map_err(|err| err.to_string())?.len();
            // O_APPEND: this write lands at the real EOF, which the lock keeps stable.
            let failure = match (&*file).write(bytes) {
                Ok(n) if n == bytes.len() => return Ok(()),
                Ok(n) => format!("short write: {n} of {} bytes", bytes.len()),
                Err(err) => err.to_string(),
            };
            // SAFETY: ftruncate on the fd this log owns, back to the pre-write EOF.
            unsafe {
                libc::ftruncate(fd, pre as libc::off_t);
            }
            Err(failure)
        })();
        // SAFETY: releasing the lock taken above on the same fd.
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
        result
    }

    /// Fail closed (Q7): the first write error latches a fault; later rows are
    /// dropped and the failure is reported at the end of the run.
    fn write(&self, row: &Row) {
        let Some(mut state) = self.lock() else { return };
        if state.failure.is_some() || state.finished {
            return;
        }
        if let Err(text) = Self::append(&state.file, &line(row)) {
            self.latch.trip(Fault::Audit(text.clone()));
            state.failure = Some(text);
        }
    }

    /// Writes the exit row (unless the log already failed) and closes the log for
    /// further rows. The exit row is therefore always the last one.
    pub(crate) fn finish(&self, row: &Row) {
        let Some(mut state) = self.lock() else { return };
        if state.failure.is_none() {
            if let Err(text) = Self::append(&state.file, &line(row)) {
                self.latch.trip(Fault::Audit(text.clone()));
                state.failure = Some(text);
            }
        }
        state.finished = true;
    }

    /// The first audit write failure of the run, if any (M1).
    pub(crate) fn failure(&self) -> Option<String> {
        self.lock().and_then(|s| s.failure.clone())
    }
}

impl DecisionSink for AuditLog {
    fn record(&self, decision: &Decision) {
        self.write(&decision_row(ts(SystemTime::now()), decision));
    }

    fn teardown(&self, decision: &Decision, detail: &str) {
        self.write(&teardown_row(ts(SystemTime::now()), decision, detail));
    }

    fn closed(&self, decision: &Decision, up: u64, down: u64) {
        self.write(&close_row(ts(SystemTime::now()), decision, up, down));
    }
}

impl DnsSink for AuditLog {
    fn record(&self, decision: &DnsDecision) {
        self.write(&dns_row(ts(SystemTime::now()), decision));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsDecision, DnsDropped, DnsQuestion, DnsRejected, DnsVerdict};
    use crate::policy::Domain;
    use crate::proxy::{ExplicitKind, NameSource, Rejected, Verdict, Via};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    const TS: &str = "2026-10-15T18:23:01.123Z";

    fn sock(s: &str) -> SocketAddr {
        s.parse().expect("socket addr")
    }

    fn dom(s: &str) -> Domain {
        Domain::parse(s).expect("domain")
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().expect("v4 addr")
    }

    fn transparent(orig: &str) -> Via {
        Via::Transparent {
            orig_dst: Some(v4(orig)),
        }
    }

    fn decision(client: &str, via: Via, name: Option<&str>, verdict: Verdict) -> Decision {
        Decision {
            client: sock(client),
            via,
            name: name.map(dom),
            verdict,
        }
    }

    fn allowed(name: &str, upstream: &str) -> Verdict {
        Verdict::Allowed {
            name: dom(name),
            upstream: sock(upstream),
        }
    }

    fn json(row: &Row) -> String {
        String::from_utf8(line(row)).expect("utf8")
    }

    #[test]
    fn ts_rfc3339_millis_utc() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_781_547_781_123);
        let text = ts(t);
        assert!(text.ends_with('Z'), "{text}");
        assert_eq!(text.len(), "2026-10-15T18:23:01.123Z".len(), "{text}");
        assert_eq!(&text[19..20], ".", "{text}");
    }

    #[test]
    fn golden_rows_byte_exact() {
        // (1) dns answered
        let dns_ok = DnsDecision {
            client: sock("10.255.255.1:41000"),
            question: Some(DnsQuestion {
                name: "github.com".into(),
                qtype: 1,
                qclass: 1,
            }),
            verdict: DnsVerdict::Answered {
                name: dom("github.com"),
                ip: Ipv4Addr::new(198, 18, 0, 1),
            },
        };
        assert_eq!(
            json(&dns_row(TS.into(), &dns_ok)),
            "{\"ts\":\"2026-10-15T18:23:01.123Z\",\"event\":\"dns\",\"host\":\"github.com\",\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"answered github.com A 198.18.0.1\",\"via\":null,\"verdict\":\"answered\",\"rcode\":0,\"qtype\":1,\"client\":\"10.255.255.1:41000\"}\n"
        );
        // (2) dns denied
        let dns_denied = DnsDecision {
            client: sock("10.255.255.1:41001"),
            question: Some(DnsQuestion {
                name: "evil.example".into(),
                qtype: 1,
                qclass: 1,
            }),
            verdict: DnsVerdict::Denied(DnsRejected::NotAllowed {
                name: dom("evil.example"),
            }),
        };
        let row = dns_row(TS.into(), &dns_denied);
        assert_eq!(row.verdict, Some("denied"));
        assert_eq!(
            json(&row),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"dns\",\"host\":\"evil.example\",\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"{}\",\"via\":null,\"verdict\":\"denied\",\"rcode\":3,\"qtype\":1,\"client\":\"10.255.255.1:41001\"}}\n",
                dns_denied.reason()
            )
        );
        // (3) dns dropped (no question, no rcode)
        let dns_dropped = DnsDecision {
            client: sock("10.255.255.1:41002"),
            question: None,
            verdict: DnsVerdict::Dropped(DnsDropped::Short { len: 5 }),
        };
        assert_eq!(
            json(&dns_row(TS.into(), &dns_dropped)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"dns\",\"host\":null,\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"{}\",\"via\":null,\"verdict\":\"dropped\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:41002\"}}\n",
                dns_dropped.reason()
            )
        );
        // (4) connect allowed
        let connect = decision(
            "10.255.255.1:40000",
            transparent("140.82.121.4:443"),
            Some("github.com"),
            allowed("github.com", "140.82.121.4:443"),
        );
        assert_eq!(
            json(&decision_row(TS.into(), &connect)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"connect\",\"host\":\"github.com\",\"sni\":\"github.com\",\"port\":443,\"bytes\":null,\"reason\":\"allowed github.com via 140.82.121.4:443\",\"via\":\"transparent\",\"verdict\":\"allowed\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40000\"}}\n"
            )
        );
        // (5) deny: SNI mismatch on a mapped fake IP
        let sni_deny = decision(
            "10.255.255.1:40001",
            transparent("198.18.0.1:443"),
            Some("github.com"),
            Verdict::Denied(Rejected::SniMismatch {
                sni: dom("evil.example"),
                name: dom("github.com"),
                source: NameSource::DnsMap,
            }),
        );
        assert_eq!(
            json(&decision_row(TS.into(), &sni_deny)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"deny\",\"host\":\"github.com\",\"sni\":null,\"port\":443,\"bytes\":null,\"reason\":\"{}\",\"via\":\"transparent\",\"verdict\":\"denied\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40001\"}}\n",
                sni_deny.reason()
            )
        );
        // (6) deny: unknown fake IP (no name)
        let unknown = decision(
            "10.255.255.1:40002",
            transparent("203.0.113.7:443"),
            None,
            Verdict::Denied(Rejected::UnknownFakeIp {
                ip: Ipv4Addr::new(203, 0, 113, 7),
            }),
        );
        assert_eq!(
            json(&decision_row(TS.into(), &unknown)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"deny\",\"host\":null,\"sni\":null,\"port\":443,\"bytes\":null,\"reason\":\"unknown fake IP 203.0.113.7 (no DNS-map entry)\",\"via\":\"transparent\",\"verdict\":\"denied\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40002\"}}\n"
            )
        );
        // (7) deny: explicit CONNECT not allowed
        let explicit = decision(
            "10.255.255.1:40003",
            Via::Explicit {
                kind: ExplicitKind::Connect,
                port: Some(443),
            },
            Some("evil.example"),
            Verdict::Denied(Rejected::NotAllowed {
                name: dom("evil.example"),
            }),
        );
        assert_eq!(
            json(&decision_row(TS.into(), &explicit)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"deny\",\"host\":\"evil.example\",\"sni\":null,\"port\":443,\"bytes\":null,\"reason\":\"evil.example is not in the policy allow list\",\"via\":\"explicit-connect\",\"verdict\":\"denied\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40003\"}}\n"
            )
        );
        // (8) deny: upstream error
        let error = decision(
            "10.255.255.1:40004",
            transparent("140.82.121.4:443"),
            Some("github.com"),
            Verdict::Error(crate::proxy::Failed::ConnectTimeout {
                name: dom("github.com"),
                secs: 10,
            }),
        );
        assert_eq!(
            json(&decision_row(TS.into(), &error)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"deny\",\"host\":\"github.com\",\"sni\":null,\"port\":443,\"bytes\":null,\"reason\":\"connect to github.com timed out after 10s\",\"via\":\"transparent\",\"verdict\":\"error\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40004\"}}\n"
            )
        );
        // (9) teardown
        let tear = decision(
            "10.255.255.1:40000",
            transparent("140.82.121.4:443"),
            Some("github.com"),
            allowed("github.com", "140.82.121.4:443"),
        );
        assert_eq!(
            json(&teardown_row(
                TS.into(),
                &tear,
                "relay torn down: second TLS ClientHello after the inspected handshake"
            )),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"deny\",\"host\":\"github.com\",\"sni\":\"github.com\",\"port\":443,\"bytes\":null,\"reason\":\"relay torn down: second TLS ClientHello after the inspected handshake\",\"via\":\"transparent\",\"verdict\":\"teardown\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40000\"}}\n"
            )
        );
        // (10) close
        assert_eq!(
            json(&close_row(TS.into(), &tear, 517, 5120)),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"close\",\"host\":\"github.com\",\"sni\":\"github.com\",\"port\":443,\"bytes\":{{\"up\":517,\"down\":5120}},\"reason\":null,\"via\":\"transparent\",\"verdict\":\"allowed\",\"rcode\":null,\"qtype\":null,\"client\":\"10.255.255.1:40000\"}}\n"
            )
        );
        // (11)–(14) exit rows
        let d = Duration::from_millis;
        assert_eq!(
            json(&exit_row(
                TS.into(),
                &Outcome::Exited(0),
                d(1234),
                false,
                false
            )),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"exit\",\"host\":null,\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"command exited with status 0\",\"via\":null,\"verdict\":null,\"rcode\":null,\"qtype\":null,\"client\":null,\"code\":0,\"outcome\":\"exited\",\"signal\":null,\"duration_ms\":1234,\"output_truncated\":false,\"dns_poisoned\":false}}\n"
            )
        );
        assert_eq!(
            json(&exit_row(
                TS.into(),
                &Outcome::TimedOut(Duration::from_secs(120)),
                d(120_004),
                false,
                false
            )),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"exit\",\"host\":null,\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"timed out after 2m\",\"via\":null,\"verdict\":null,\"rcode\":null,\"qtype\":null,\"client\":null,\"code\":124,\"outcome\":\"timeout\",\"signal\":null,\"duration_ms\":120004,\"output_truncated\":false,\"dns_poisoned\":false}}\n"
            )
        );
        assert_eq!(
            json(&exit_row(
                TS.into(),
                &Outcome::Terminated(15),
                d(5000),
                true,
                false
            )),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"exit\",\"host\":null,\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"terminated by SIGTERM\",\"via\":null,\"verdict\":null,\"rcode\":null,\"qtype\":null,\"client\":null,\"code\":143,\"outcome\":\"terminated\",\"signal\":15,\"duration_ms\":5000,\"output_truncated\":true,\"dns_poisoned\":false}}\n"
            )
        );
        assert_eq!(
            json(&exit_row(
                TS.into(),
                &Outcome::Failed("network service failed: transparent proxy panicked: boom".into()),
                d(17),
                false,
                false
            )),
            format!(
                "{{\"ts\":\"{TS}\",\"event\":\"exit\",\"host\":null,\"sni\":null,\"port\":null,\"bytes\":null,\"reason\":\"network service failed: transparent proxy panicked: boom\",\"via\":null,\"verdict\":null,\"rcode\":null,\"qtype\":null,\"client\":null,\"code\":125,\"outcome\":\"failed\",\"signal\":null,\"duration_ms\":17,\"output_truncated\":false,\"dns_poisoned\":false}}\n"
            )
        );
    }

    #[test]
    fn decision_event_mapping() {
        let ok = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            Some("a.example"),
            allowed("a.example", "1.2.3.4:80"),
        );
        assert_eq!(decision_row(TS.into(), &ok).event, "connect");
        let denied = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            None,
            Verdict::Denied(Rejected::PortNotAllowed { port: 22 }),
        );
        let row = decision_row(TS.into(), &denied);
        assert_eq!((row.event, row.verdict), ("deny", Some("denied")));
        let err = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            None,
            Verdict::Error(crate::proxy::Failed::Connect {
                name: dom("a.example"),
                detail: "refused".into(),
            }),
        );
        let row = decision_row(TS.into(), &err);
        assert_eq!((row.event, row.verdict), ("deny", Some("error")));
    }

    #[test]
    fn sni_only_for_allowed_443() {
        let on_80 = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            Some("a.example"),
            allowed("a.example", "1.2.3.4:80"),
        );
        assert_eq!(decision_row(TS.into(), &on_80).sni, None);
        let on_443 = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:443"),
            Some("a.example"),
            allowed("a.example", "1.2.3.4:443"),
        );
        assert_eq!(
            decision_row(TS.into(), &on_443).sni.as_deref(),
            Some("a.example")
        );
        let denied_443 = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:443"),
            Some("a.example"),
            Verdict::Denied(Rejected::PortNotAllowed { port: 443 }),
        );
        assert_eq!(decision_row(TS.into(), &denied_443).sni, None);
    }

    #[test]
    fn port_from_via_table() {
        assert_eq!(port_of(&transparent("1.2.3.4:8080")), Some(8080));
        assert_eq!(port_of(&Via::Transparent { orig_dst: None }), None);
        assert_eq!(
            port_of(&Via::Explicit {
                kind: ExplicitKind::Forward,
                port: Some(80)
            }),
            Some(80)
        );
        assert_eq!(
            port_of(&Via::Explicit {
                kind: ExplicitKind::Unknown,
                port: None
            }),
            None
        );
    }

    #[test]
    fn open_audit_creates_0600_and_appends() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-a", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("a.jsonl");
        std::fs::remove_file(&path).ok();
        {
            let mut f = open_audit(&path).expect("open");
            f.write_all(b"one\n").expect("write");
        }
        {
            let mut f = open_audit(&path).expect("reopen");
            f.write_all(b"two\n").expect("write");
        }
        let mut text = String::new();
        std::fs::File::open(&path)
            .expect("read")
            .read_to_string(&mut text)
            .expect("utf8");
        assert_eq!(text, "one\ntwo\n");
        assert_eq!(
            std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_audit_rejects_symlink() {
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-l", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let target = dir.join("target");
        std::fs::write(&target, b"").expect("touch");
        let link = dir.join("link.jsonl");
        std::fs::remove_file(&link).ok();
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = open_audit(&link).expect_err("symlink must be refused");
        assert!(
            err.reason().starts_with("cannot open audit log"),
            "{}",
            err.reason()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_audit_rejects_directory() {
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-d", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let err = open_audit(&dir).expect_err("directory must be refused");
        assert!(err.reason().contains("audit log"), "{}", err.reason());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_audit_refuses_hard_links() {
        // M2: a second hard link could alias the log outside the lexical checks.
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-h", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("a.jsonl");
        let other = dir.join("b.jsonl");
        std::fs::write(&path, b"").expect("write");
        std::fs::hard_link(&path, &other).expect("link");
        let err = open_audit(&path).expect_err("hard-linked log must be refused");
        assert!(
            err.reason().contains("more than one hard link"),
            "{}",
            err.reason()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_audit_rejects_fifo_without_hanging() {
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-f", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fifo = dir.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("cstr");
        // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // No reader exists: a blocking open would hang forever. O_NONBLOCK → ENXIO.
        let err = open_audit(&fifo).expect_err("fifo must be refused");
        assert!(
            err.reason().starts_with("cannot open audit log"),
            "{}",
            err.reason()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_failure_trips_latch_and_drops_later_rows() {
        let latch = FaultLatch::new().expect("latch");
        // Read-only handle: the first write fails with EBADF.
        let ro = std::fs::File::open("/dev/null").expect("open ro");
        let log = AuditLog::new(Some(ro), latch.clone());
        log.write(&exit_row(
            TS.into(),
            &Outcome::Exited(0),
            Duration::ZERO,
            false,
            false,
        ));
        assert!(log.failure().is_some());
        assert!(matches!(latch.take(), Some(Fault::Audit(_))));
        // Later writes are silently dropped (fail closed, no second fault).
        log.write(&exit_row(
            TS.into(),
            &Outcome::Exited(0),
            Duration::ZERO,
            false,
            false,
        ));
        assert!(latch.take().is_none());
    }

    #[test]
    fn finish_makes_exit_row_last() {
        let dir = std::env::temp_dir().join(format!("sbx-run-audit-{}-z", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("order.jsonl");
        std::fs::remove_file(&path).ok();
        let latch = FaultLatch::new().expect("latch");
        let log = AuditLog::new(Some(open_audit(&path).expect("open")), latch);
        let c = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            Some("a.example"),
            allowed("a.example", "1.2.3.4:80"),
        );
        DecisionSink::record(&*log, &c);
        log.finish(&exit_row(
            TS.into(),
            &Outcome::Exited(0),
            Duration::ZERO,
            false,
            false,
        ));
        // A row racing in after finish is dropped.
        DecisionSink::record(&*log, &c);
        let text = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[1].contains("\"event\":\"exit\""), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_audit_is_noop() {
        let latch = FaultLatch::new().expect("latch");
        let log = AuditLog::new(None, latch.clone());
        let c = decision(
            "10.0.0.1:1",
            transparent("1.2.3.4:80"),
            None,
            Verdict::Denied(Rejected::PortNotAllowed { port: 22 }),
        );
        DecisionSink::record(&*log, &c);
        log.finish(&exit_row(
            TS.into(),
            &Outcome::Exited(0),
            Duration::ZERO,
            false,
            false,
        ));
        assert!(log.failure().is_none());
        assert!(latch.take().is_none());
    }
}
