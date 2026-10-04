//! Listener + canary sockets (design D4).
//!
//! Bound AFTER netns setup and BEFORE the rules are loaded, so there is no
//! window where a redirect is live without a listener behind it.
//!
//! Protocol — the server speaks first:
//! * TCP: on accept, query `SO_ORIGINAL_DST` (conntrack's pre-DNAT
//!   destination), write one line
//!   `OK original_dst=<ip:port|errno=N> accepted_on=<bind> peer=<peer>\n`,
//!   then close.
//! * UDP: `recvmsg` with `IP_RECVORIGDSTADDR` ancillary data (which reports
//!   the POST-DNAT destination — empirical fact F4), reply `PONG <origdst>\n`
//!   to the peer so a connected client round-trip succeeds.
//!
//! Every accept/receive is also pushed to the main thread over an mpsc
//! channel; the self-tests assert on those events (including that the
//! canaries bound to 10.255.255.1 stay quiet for redirected traffic).

use std::io::{self, Write};
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::consts::{
    DNS_PORT, EXIT_LISTEN, IP_RECVORIGDSTADDR, SANDBOX_ADDR, SOL_IP, SO_ORIGINAL_DST, TCP_PORT,
};
use crate::Fail;

/// One observed server-side event, pushed to the self-test thread.
#[derive(Debug, Clone)]
pub enum ServerEvent {
    TcpAccepted {
        canary: bool,
        /// Bind address the connection was accepted on ("ip:port").
        on: String,
        /// Peer as seen by the listener ("ip:port").
        peer: String,
        /// `SO_ORIGINAL_DST` result: Ok("ip:port") or Err(errno).
        original_dst: Result<String, i32>,
    },
    UdpReceived {
        canary: bool,
        on: String,
        peer: String,
        /// `IP_RECVORIGDSTADDR` cmsg (post-DNAT destination — F4).
        origdst_cmsg: Option<String>,
        payload: String,
    },
}

pub struct Listeners {
    /// Event stream consumed by the self-tests.
    pub rx: Receiver<ServerEvent>,
}

fn listen_fail(op: String, e: io::Error) -> Fail {
    Fail::new(EXIT_LISTEN, format!("listeners: {op}: {e}"))
}

/// Bind all four sockets (main TCP/UDP on 127.0.0.1, canary TCP/UDP on
/// 10.255.255.1) and spawn their server threads. Bind errors are fatal
/// (exit 6) — without listeners the redirect self-tests are meaningless.
pub fn start(verbose: bool) -> Result<Listeners, Fail> {
    let (tx, rx) = mpsc::channel();
    let sandbox = Ipv4Addr::from(SANDBOX_ADDR);
    spawn_tcp(tx.clone(), Ipv4Addr::LOCALHOST, false, verbose)?;
    spawn_udp(tx.clone(), Ipv4Addr::LOCALHOST, false, verbose)?;
    // Canaries: redirected traffic must never land here; direct connections
    // to the sandbox address must (t2b). This invariant is TCP-only: rule 1
    // carries a `fib daddr type != local` guard (D2), but rule 2 redirects
    // ALL udp/53 regardless of destination locality, so the UDP canary is
    // unreachable by construction and its silence in t6 is not evidence of
    // UDP rule scoping — there is no UDP analogue of t2b. NOTE(#5): revisit
    // if the production ruleset ever intends UDP scoping (adding a fib guard
    // to rule 2 would deviate from the documented ground truth, so the spike
    // keeps the rule and corrects this comment instead).
    spawn_tcp(tx.clone(), sandbox, true, verbose)?;
    spawn_udp(tx, sandbox, true, verbose)?;
    Ok(Listeners { rx })
}

fn spawn_tcp(
    tx: Sender<ServerEvent>,
    ip: Ipv4Addr,
    canary: bool,
    verbose: bool,
) -> Result<(), Fail> {
    let addr = SocketAddrV4::new(ip, TCP_PORT);
    let listener = TcpListener::bind(addr)
        .map_err(|e| listen_fail(format!("bind TCP {addr} (canary={canary})"), e))?;
    thread::spawn(move || {
        let on = addr.to_string();
        if verbose {
            eprintln!("[listener] TCP {on} ready (canary={canary})");
        }
        for conn in listener.incoming() {
            let Ok(stream) = conn else {
                continue;
            };
            let peer = match stream.peer_addr() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let original_dst = get_original_dst(&stream);
            let _ = tx.send(ServerEvent::TcpAccepted {
                canary,
                on: on.clone(),
                peer: peer.to_string(),
                original_dst: original_dst.clone(),
            });
            // Server speaks first: one line with everything the client asserts on.
            let od = match &original_dst {
                Ok(s) => s.clone(),
                Err(errno) => format!("errno={errno}"),
            };
            let line = format!("OK original_dst={od} accepted_on={on} peer={peer}\n");
            // NOTE(#5): the production listener needs SO_SNDTIMEO (or
            // non-blocking writes) here — this accept loop is serial, so one
            // peer that advertises a zero window against a full send buffer
            // would block it indefinitely and halt ALL redirects. Safe for
            // the spike: one ~100-byte line per connection, then close.
            let _ = (&stream).write_all(line.as_bytes());
            // drop(stream) closes the connection.
        }
    });
    Ok(())
}

fn spawn_udp(
    tx: Sender<ServerEvent>,
    ip: Ipv4Addr,
    canary: bool,
    verbose: bool,
) -> Result<(), Fail> {
    let addr = SocketAddrV4::new(ip, DNS_PORT);
    let sock = UdpSocket::bind(addr)
        .map_err(|e| listen_fail(format!("bind UDP {addr} (canary={canary})"), e))?;
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            SOL_IP,
            IP_RECVORIGDSTADDR,
            (&one as *const libc::c_int).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(listen_fail(
            format!("setsockopt IP_RECVORIGDSTADDR on UDP {addr}"),
            io::Error::last_os_error(),
        ));
    }
    // Poll timeout keeps the loop from blocking forever; process exit reaps
    // the thread either way.
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| listen_fail("set_read_timeout".into(), e))?;
    thread::spawn(move || {
        let on = addr.to_string();
        if verbose {
            eprintln!("[listener] UDP {on} ready (canary={canary}, IP_RECVORIGDSTADDR)");
        }
        let mut buf = [0u8; 1024];
        // Control buffer for one sockaddr_in cmsg. On x86_64 Linux both
        // CMSG_LEN(16) and CMSG_SPACE(16) evaluate to 32 (sizeof(cmsghdr)==16
        // + 4-byte-aligned payload; verified via python3 socket.CMSG_SPACE).
        // 64 bytes keeps headroom on any platform; CtrlBuf guarantees the
        // align-8 the cmsg casts in recvmsg_origdst require.
        let mut ctrl = CtrlBuf([0; 64]);
        loop {
            match recvmsg_origdst(&sock, &mut buf, &mut ctrl.0) {
                Ok((n, peer, origdst)) => {
                    let payload = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let _ = tx.send(ServerEvent::UdpReceived {
                        canary,
                        on: on.clone(),
                        peer: peer.to_string(),
                        origdst_cmsg: origdst.clone(),
                        payload,
                    });
                    // Reply so the connected client's round-trip succeeds
                    // (the round-trip itself is the UDP-53 proof — F4).
                    let reply = format!("PONG {}\n", origdst.unwrap_or_else(|| "?".into()));
                    let _ = sock.send_to(reply.as_bytes(), peer);
                }
                // Timeout / transient error: keep serving.
                Err(_) => continue,
            }
        }
    });
    Ok(())
}

/// `getsockopt(SO_ORIGINAL_DST)` on an accepted (redirected) TCP connection.
/// Returns the pre-DNAT destination by consulting conntrack; on a direct
/// (non-NATed) connection it succeeds and returns the connection's own local
/// address (empirical fact F8).
fn get_original_dst(stream: &TcpStream) -> Result<String, i32> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_IP,
            SO_ORIGINAL_DST,
            (&mut sa as *mut libc::sockaddr_in).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
    }
    if (len as usize) < size_of::<libc::sockaddr_in>() {
        return Err(libc::EINVAL);
    }
    format_sockaddr_in(&sa).ok_or(libc::EAFNOSUPPORT)
}

/// Validate + render a raw 16-byte `sockaddr_in`: `sin_port` and `sin_addr`
/// are stored in network byte order ([2..4] and [4..8] of the raw struct).
/// Returns `None` if the family is not AF_INET.
fn format_sockaddr_in(sa: &libc::sockaddr_in) -> Option<String> {
    if sa.sin_family != libc::AF_INET as libc::sa_family_t {
        return None;
    }
    // to_ne_bytes() yields the octets in memory order == network order.
    let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
    let port = u16::from_be(sa.sin_port);
    Some(format!("{ip}:{port}"))
}

/// Align-8 control buffer for `recvmsg` cmsg data. A plain `[u8; 64]` is
/// only align-1, but [`recvmsg_origdst`] casts it to `*cmsghdr` (contains
/// u64 members on x86_64 → required alignment 8) and `*sockaddr_in`;
/// creating references to under-aligned structs is UB by Rust's rules, even
/// though rustc usually happens to place stack arrays 8-aligned.
#[repr(align(8))]
struct CtrlBuf([u8; 64]);

/// `recvmsg` with ancillary data; extracts the `IP_RECVORIGDSTADDR` cmsg
/// (original destination as seen by the kernel — post-DNAT per F4).
///
/// `ctrl` must be suitably aligned for `cmsghdr`/`sockaddr_in` (see
/// [`CtrlBuf`]).
fn recvmsg_origdst(
    sock: &UdpSocket,
    buf: &mut [u8],
    ctrl: &mut [u8],
) -> io::Result<(usize, SocketAddrV4, Option<String>)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        let mut src: libc::sockaddr_in = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut src as *mut libc::sockaddr_in).cast::<libc::c_void>();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = ctrl.len() as _;

        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // The kernel truncated the control data: the cmsg chain is
        // incomplete and its last header may advertise bytes past the end of
        // `ctrl`. Treat as a transient error (the caller's loop moves on to
        // the next datagram) rather than parse a malformed chain.
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }

        let mut origdst = None;
        let ctrl_end = ctrl.as_ptr() as usize + ctrl.len();
        let mut cmh = libc::CMSG_FIRSTHDR(&msg);
        while !cmh.is_null() {
            let min_len = libc::CMSG_LEN(size_of::<libc::sockaddr_in>() as libc::c_uint) as usize;
            // Bounds invariant (defense in depth on top of the MSG_CTRUNC
            // check): the advertised length must cover at least the header
            // and stay inside the control buffer before CMSG_DATA is read.
            // Written overflow-free (cmh <= ctrl_end always holds): a garbage
            // cmsg_len near usize::MAX must not wrap the addition.
            let claimed = (*cmh).cmsg_len as usize;
            if claimed < size_of::<libc::cmsghdr>() || claimed > ctrl_end - cmh as usize {
                break;
            }
            if (*cmh).cmsg_level == SOL_IP
                && (*cmh).cmsg_type == IP_RECVORIGDSTADDR
                && claimed >= min_len
            {
                let sa = libc::CMSG_DATA(cmh).cast::<libc::sockaddr_in>();
                // None (non-AF_INET) leaves origdst unset — informational.
                origdst = format_sockaddr_in(&*sa);
            }
            cmh = libc::CMSG_NXTHDR(&msg, cmh);
        }

        // The kernel rewrites msg_namelen to the actual source-address size;
        // refuse to parse a truncated sockaddr (symmetric to the getsockopt
        // length check in get_original_dst).
        if (msg.msg_namelen as usize) < size_of::<libc::sockaddr_in>() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if src.sin_family != libc::AF_INET as libc::sa_family_t {
            return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
        }
        let peer = SocketAddrV4::new(
            Ipv4Addr::from(src.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(src.sin_port),
        );
        Ok((n as usize, peer, origdst))
    }
}
