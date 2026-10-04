//! Traffic self-tests (design D4; AC mapping in the note's test matrix).
//!
//! Run sequentially on the main thread; listener events arrive over the mpsc
//! channel and are asserted per test. Flake controls: explicit timeouts
//! everywhere, no sleeps in assertion paths (except the t6 quiet-period
//! drain), deterministic signals (EPERM + SNMP counter for the drop test,
//! round-trip for UDP-53).
//!
//! | test | proves |
//! |------|--------|
//! | t1  | TCP redirect + SO_ORIGINAL_DST == original (F1) |
//! | t2  | direct loopback connect not redirected; SO_ORIGINAL_DST == own addr (F8) |
//! | t2b | direct sandbox-addr connect lands on canary, main untouched (D2) |
//! | t3  | UDP/53 redirect via round-trip on connected socket (F4-corrected) |
//! | t4  | positive control: local UDP allowed, ECONNREFUSED (F10) |
//! | t5  | UDP non-53 dropped: send() EPERM + Ip OutDiscards delta (F3) |
//! | t6  | canaries quiet, no leftover events |

use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::consts::{
    DNS_PORT, OP_TIMEOUT_SECS, SANDBOX_ADDR, TCP_PORT, TEST_ADDR, TEST_TCP_PORT, TEST_UDP_DROP_PORT,
};
use crate::listeners::ServerEvent;
use crate::report::TestResult;

pub fn run(mut rx: Receiver<ServerEvent>) -> Vec<TestResult> {
    vec![
        t1_tcp_redirect(&mut rx),
        t2_direct_loopback(&mut rx),
        t2b_canary_direct(&mut rx),
        t3_udp53_roundtrip(&mut rx),
        t4_control_econnrefused(),
        t5_udp_drop(),
        t6_canaries_quiet(&mut rx),
    ]
}

fn to() -> Duration {
    Duration::from_secs(OP_TIMEOUT_SECS)
}

fn next_event(rx: &mut Receiver<ServerEvent>, what: &str) -> Result<ServerEvent, String> {
    match rx.recv_timeout(to()) {
        Ok(ev) => Ok(ev),
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "timed out ({OP_TIMEOUT_SECS}s) waiting for {what} event"
        )),
        Err(e) => Err(format!("waiting for {what} event: {e}")),
    }
}

/// Read the single line the TCP server speaks first.
fn read_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match stream.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                out.push(b[0]);
                if b[0] == b'\n' || out.len() >= 4096 {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read server line: {e}")),
        }
    }
    if out.is_empty() {
        return Err("server closed without speaking first".into());
    }
    Ok(String::from_utf8_lossy(&out).trim_end().to_string())
}

fn connect_tcp(ip: Ipv4Addr, port: u16) -> Result<(TcpStream, String), String> {
    let target = SocketAddrV4::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(target), to())
        .map_err(|e| format!("connect {target}: {e}"))?;
    stream
        .set_read_timeout(Some(to()))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let line = read_line(&mut stream)?;
    Ok((stream, line))
}

/// t1 — AC: TCP connect to 203.0.113.7:443 must be accepted by the listener
/// on 127.0.0.1:15001, SO_ORIGINAL_DST must report 203.0.113.7:443, and the
/// server must see the client's sandbox source address (F1).
fn t1_tcp_redirect(rx: &mut Receiver<ServerEvent>) -> TestResult {
    TestResult::from_result("t1-tcp-redirect", t1_run(rx))
}

fn t1_run(rx: &mut Receiver<ServerEvent>) -> Result<String, String> {
    let target = SocketAddrV4::new(Ipv4Addr::from(TEST_ADDR), TEST_TCP_PORT);
    let (stream, line) = connect_tcp(*target.ip(), target.port())?;
    let peer = stream.peer_addr().map_err(|e| format!("peer_addr: {e}"))?;
    let local = stream
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    // DNAT is transparent to the client socket: peer stays the original.
    if peer != SocketAddr::V4(target) {
        return Err(format!(
            "client peer {peer} != {target} (expected transparent DNAT)"
        ));
    }
    // Source address comes from the default route's prefsrc.
    if local.ip() != Ipv4Addr::from(SANDBOX_ADDR) {
        return Err(format!("client source {local} != prefsrc 10.255.255.1"));
    }
    let expect_od = format!("{}:{}", Ipv4Addr::from(TEST_ADDR), TEST_TCP_PORT);
    let expect_on = format!("{}:{}", Ipv4Addr::LOCALHOST, TCP_PORT);
    if !line.contains(&format!("original_dst={expect_od}"))
        || !line.contains(&format!("accepted_on={expect_on}"))
    {
        return Err(format!("unexpected server line: {line:?}"));
    }
    match next_event(rx, "tcp-accept")? {
        ServerEvent::TcpAccepted {
            canary: false,
            ref on,
            ref peer,
            original_dst: Ok(ref od),
        } if on == &expect_on && od == &expect_od && peer.starts_with("10.255.255.1:") => {}
        ref other => return Err(format!("unexpected server event: {other:?}")),
    }
    Ok(format!(
        "line={line:?} client peer={peer} local={local} \
         SO_ORIGINAL_DST={expect_od} on={expect_on}"
    ))
}

/// t2 — direct loopback connect must NOT be redirected, and SO_ORIGINAL_DST
/// on a non-NATed connection returns the connection's own local address (F8).
fn t2_direct_loopback(rx: &mut Receiver<ServerEvent>) -> TestResult {
    TestResult::from_result("t2-direct-loopback", t2_run(rx))
}

fn t2_run(rx: &mut Receiver<ServerEvent>) -> Result<String, String> {
    let (_stream, line) = connect_tcp(Ipv4Addr::LOCALHOST, TCP_PORT)?;
    let expect_own = format!("{}:{}", Ipv4Addr::LOCALHOST, TCP_PORT);
    match next_event(rx, "tcp-accept")? {
        ServerEvent::TcpAccepted {
            canary: false,
            ref on,
            ref peer,
            original_dst: Ok(ref od),
        } if on == &expect_own && od == &expect_own && peer.starts_with("127.0.0.1:") => {}
        ref other => return Err(format!("unexpected server event: {other:?}")),
    }
    Ok(format!(
        "direct connect unredirected; SO_ORIGINAL_DST == own addr {expect_own} (F8); line={line:?}"
    ))
}

/// t2b — direct connect to the sandbox address lands on the CANARY listener
/// (the fib rules only match non-local destinations, D2); the main listener
/// must not see it (asserted via the event's canary flag + t6 drain).
fn t2b_canary_direct(rx: &mut Receiver<ServerEvent>) -> TestResult {
    TestResult::from_result("t2b-canary-direct", t2b_run(rx))
}

fn t2b_run(rx: &mut Receiver<ServerEvent>) -> Result<String, String> {
    let sandbox = Ipv4Addr::from(SANDBOX_ADDR);
    let (_stream, line) = connect_tcp(sandbox, TCP_PORT)?;
    let expect_on = format!("{sandbox}:{TCP_PORT}");
    match next_event(rx, "canary tcp-accept")? {
        ServerEvent::TcpAccepted {
            canary: true,
            ref on,
            ref original_dst,
            ..
        } if on == &expect_on => Ok(format!(
            "canary accepted direct connect on {expect_on}; \
             original_dst={original_dst:?} (informational, F8-analog); line={line:?}"
        )),
        ref other => Err(format!("expected CANARY accept, got: {other:?}")),
    }
}

/// t3 — UDP/53 redirect proof is the ROUND-TRIP on a socket connected to
/// 203.0.113.7:53 (F4 correction: IP_RECVORIGDSTADDR reports the post-DNAT
/// address, so the cmsg is logged as informational, not asserted).
fn t3_udp53_roundtrip(rx: &mut Receiver<ServerEvent>) -> TestResult {
    TestResult::from_result("t3-udp53-roundtrip", t3_run(rx))
}

fn t3_run(rx: &mut Receiver<ServerEvent>) -> Result<String, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    let dst = SocketAddrV4::new(Ipv4Addr::from(TEST_ADDR), DNS_PORT);
    sock.connect(dst)
        .map_err(|e| format!("connect {dst}: {e}"))?;
    sock.set_read_timeout(Some(to()))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let local = sock.local_addr().map_err(|e| format!("local_addr: {e}"))?;
    if local.ip() != Ipv4Addr::from(SANDBOX_ADDR) {
        return Err(format!("client source {local} != prefsrc 10.255.255.1"));
    }
    sock.send(b"QUERY\n").map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 256];
    let n = sock
        .recv(&mut buf)
        .map_err(|e| format!("recv (round-trip): {e}"))?;
    let reply = String::from_utf8_lossy(&buf[..n]).into_owned();
    if !reply.starts_with("PONG ") {
        return Err(format!("unexpected reply {reply:?}"));
    }
    let ev = next_event(rx, "udp-receive")?;
    let cmsg = match &ev {
        ServerEvent::UdpReceived {
            canary: false,
            on,
            peer,
            origdst_cmsg,
            payload,
        } if on == "127.0.0.1:53" && peer.starts_with("10.255.255.1:") && payload == "QUERY\n" => {
            origdst_cmsg.clone()
        }
        other => return Err(format!("unexpected server event: {other:?}")),
    };
    // Informational (F4): the cmsg carries the POST-DNAT destination.
    eprintln!("[status] t3: IP_RECVORIGDSTADDR cmsg = {cmsg:?} (post-DNAT per F4, informational)");
    Ok(format!(
        "round-trip {reply:?} via 127.0.0.1:53; client local={local}; cmsg={cmsg:?}"
    ))
}

/// t4 — positive control (F10): UDP to 127.0.0.1:9999 is allowed by the
/// filter chain; with no listener the kernel answers ICMP port-unreachable,
/// surfacing as ECONNREFUSED. Proves the EPERM in t5 is drop-specific.
fn t4_control_econnrefused() -> TestResult {
    TestResult::from_result("t4-control-econnrefused", t4_run())
}

fn t4_run() -> Result<String, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, TEST_UDP_DROP_PORT);
    sock.connect(dst)
        .map_err(|e| format!("connect {dst}: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let mut buf = [0u8; 64];
    let mut refused_at = None;
    for attempt in 1..=3u32 {
        match sock.send(b"X") {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                refused_at = Some(format!("send (attempt {attempt})"));
                break;
            }
            Err(e) => return Err(format!("control send: {e}")),
        }
        match sock.recv(&mut buf) {
            Ok(n) => return Err(format!("control port unexpectedly replied ({n} bytes)")),
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                refused_at = Some(format!("recv (attempt {attempt})"));
                break;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue
            }
            Err(e) => return Err(format!("control recv: {e}")),
        }
    }
    match refused_at {
        Some(where_) => Ok(format!(
            "ECONNREFUSED on {where_} — local UDP passed the filter, no listener (F10)"
        )),
        None => Err("no ECONNREFUSED after 3 send/recv attempts".into()),
    }
}

/// t5 — UDP to a non-53 external port must be dropped by the filter chain's
/// policy. Deterministic proof (F3): send() fails synchronously with EPERM
/// and `/proc/net/snmp` Ip OutDiscards increases. No timeouts involved.
fn t5_udp_drop() -> TestResult {
    TestResult::from_result("t5-udp-drop-eperm", t5_run())
}

fn t5_run() -> Result<String, String> {
    let before = snmp_out_discards()?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    let dst = SocketAddrV4::new(Ipv4Addr::from(TEST_ADDR), TEST_UDP_DROP_PORT);
    sock.connect(dst)
        .map_err(|e| format!("connect {dst}: {e}"))?;
    match sock.send(b"DROP") {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
        Ok(_) => {
            return Err(
                "send() to non-53 external UDP SUCCEEDED — filter policy drop not enforced \
                 (F3 expects synchronous EPERM)"
                    .into(),
            )
        }
        Err(e) => return Err(format!("send failed with {e} — expected EPERM (F3)")),
    }
    let after = snmp_out_discards()?;
    let delta = after.saturating_sub(before);
    if delta < 1 {
        return Err(format!(
            "Ip OutDiscards did not increase ({before} -> {after})"
        ));
    }
    Ok(format!(
        "send()=EPERM synchronously; Ip OutDiscards {before}->{after} (+{delta}) (F3)"
    ))
}

/// Parse `Ip: OutDiscards` from /proc/net/snmp content.
pub fn snmp_out_discards_from(content: &str) -> Result<u64, String> {
    let mut header: Option<Vec<&str>> = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("Ip:") {
            continue;
        }
        let vals: Vec<&str> = parts.collect();
        match header.take() {
            None => header = Some(vals),
            Some(h) => {
                let idx = h
                    .iter()
                    .position(|k| *k == "OutDiscards")
                    .ok_or("Ip: header lacks OutDiscards")?;
                let v = vals.get(idx).ok_or("Ip: values row shorter than header")?;
                return v
                    .parse::<u64>()
                    .map_err(|e| format!("OutDiscards={v:?}: {e}"));
            }
        }
    }
    Err("no complete Ip: section in /proc/net/snmp".into())
}

fn snmp_out_discards() -> Result<u64, String> {
    let content = std::fs::read_to_string("/proc/net/snmp")
        .map_err(|e| format!("read /proc/net/snmp: {e}"))?;
    snmp_out_discards_from(&content)
}

/// t6 — after a 200ms quiet period the event channel must be empty: the
/// canaries never saw redirected traffic and nothing else leaked.
fn t6_canaries_quiet(rx: &mut Receiver<ServerEvent>) -> TestResult {
    TestResult::from_result("t6-canaries-quiet", t6_run(rx))
}

fn t6_run(rx: &mut Receiver<ServerEvent>) -> Result<String, String> {
    thread::sleep(Duration::from_millis(200));
    let mut leftover = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        leftover.push(format!("{ev:?}"));
    }
    if leftover.is_empty() {
        Ok("canaries quiet; no leftover events after 200ms drain".into())
    } else {
        Err(format!(
            "{} unexpected event(s): {}",
            leftover.len(),
            leftover.join(" | ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snmp_parse_extracts_out_discards() {
        let content = "\
Icmp: InMsgs InErrors OutMsgs
Icmp: 0 0 0
Ip: Forwarding DefaultTTL InReceives OutDiscards OutRequests
Ip: 1 64 12 7 13
Tcp: RtoAlgorithm
Tcp: 1
";
        assert_eq!(snmp_out_discards_from(content), Ok(7));
    }

    #[test]
    fn snmp_parse_missing_section() {
        assert!(snmp_out_discards_from("Tcp: a b\nTcp: 1 2\n").is_err());
    }
}
