//! The three bare listener binds (issue #5) — binding only, never serving.
//!
//! 1. **No threads, no serving** (F5): `__init` binds and hands the fds to
//!    the parent over SCM_RIGHTS; serving is the PARENT's job (#7
//!    transparent, #8 explicit, #9 DNS) — both because the child must stay
//!    single-threaded until exec (the unshare invariant) and because the
//!    parent lives in the host netns where the audit log and policy are.
//! 2. **Order: listeners BEFORE rules** (N5, spike guidance): a
//!    bound-but-unaccepted socket completes TCP handshakes into its
//!    backlog, so from the instant the redirect rule goes live there is
//!    neither a redirect-without-listener window nor an RST window.
//! 3. **Privileged :53 works unprivileged-on-host**: inside the sandbox
//!    `__init` is ns-root with CAP_NET_BIND_SERVICE over the OWNED netns
//!    (probe-verified) — no host capability is ever needed.
//! 4. **CLOEXEC discipline** (R5): std binds with CLOEXEC by default, so
//!    these sockets die at exec even if [`super`] 's fd hygiene ever missed
//!    one — the parent's SCM_RIGHTS-dup'd copies live on. Blocking mode is
//!    deliberate: #7 flips `transparent` non-blocking itself before handing
//!    it to tokio.
//! 5. Partial binds clean up via RAII: if bind N fails, binds 0..N-1 drop
//!    (close) as the error propagates — the staged [`Stage::Listeners`]
//!    failure leaves nothing behind, and the fresh netns dies with the
//!    process anyway.

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};

use super::consts::{DNS_UDP_PORT, EXPLICIT_TCP_PORT, TRANSPARENT_TCP_PORT};
use super::fdpass::ListenerFds;
use super::{InitError, Stage};

/// Bind the three sandbox listeners in wire order (transparent, explicit,
/// dns — the order [`ListenerFds`] pins for the SCM_RIGHTS hand-off) and
/// hand them back ready for [`super::fdpass::send_listener_fds`].
///
/// Bind failures are staged [`Stage::Listeners`] errors naming the exact
/// address/protocol — fail closed, the payload never starts (F9–F13).
pub fn bind_all() -> Result<ListenerFds, InitError> {
    bind(TRANSPARENT_TCP_PORT, EXPLICIT_TCP_PORT, DNS_UDP_PORT)
}

/// The shared bind sequence over explicit ports; [`bind_all`] passes the
/// protocol ports, [`bind_test`] passes zeros (ephemeral).
fn bind(tcp_redir: u16, tcp_explicit: u16, udp_dns: u16) -> Result<ListenerFds, InitError> {
    let transparent = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp_redir))
        .map_err(|e| {
            InitError::new(
                Stage::Listeners,
                format!("bind 127.0.0.1:{tcp_redir}/tcp: {e}"),
            )
        })?;
    let explicit = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, tcp_explicit))
        .map_err(|e| {
            InitError::new(
                Stage::Listeners,
                format!("bind 127.0.0.1:{tcp_explicit}/tcp: {e}"),
            )
        })?;
    let dns = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, udp_dns)).map_err(|e| {
        InitError::new(
            Stage::Listeners,
            format!("bind 127.0.0.1:{udp_dns}/udp: {e}"),
        )
    })?;
    Ok(ListenerFds::new(transparent, explicit, dns))
}

/// [`bind_all`] over three EPHEMERAL loopback ports: lets cargo test
/// (non-root, HOST netns) exercise the wire ordering and the CLOEXEC
/// property without the privileged :53 bind or collisions with live host
/// services on 15001/3128.
#[cfg(test)]
fn bind_test() -> Result<ListenerFds, InitError> {
    bind(0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn bind_test_orders_fds_per_protocol() {
        // The wire order both directions share (D11): fd index 0 is the
        // transparent TCP listener, 1 the explicit TCP listener, 2 the DNS
        // socket — pinned through as_raw_fds, the exact array
        // send_listener_fds puts on the wire.
        let l = bind_test().expect("ephemeral loopback binds must succeed");
        let fds = l.as_raw_fds();
        assert_eq!(fds[0], l.transparent.as_raw_fd(), "index 0 = transparent");
        assert_eq!(fds[1], l.explicit.as_raw_fd(), "index 1 = explicit");
        assert_eq!(fds[2], l.dns.as_raw_fd(), "index 2 = dns");
        // Three DISTINCT sockets (an aliasing bug would collapse them).
        assert_ne!(fds[0], fds[1]);
        assert_ne!(fds[1], fds[2]);
        assert_ne!(fds[0], fds[2]);
    }

    #[test]
    fn bound_sockets_are_cloexec() {
        // R5: std's CLOEXEC default is load-bearing — if the fd-hygiene
        // scan ever missed one, exec would still not leak a listener into
        // the untrusted payload. Pin the default explicitly.
        let l = bind_test().expect("ephemeral loopback binds must succeed");
        for fd in l.as_raw_fds() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD: {}", std::io::Error::last_os_error());
            assert!(
                flags & libc::FD_CLOEXEC != 0,
                "listener fd {fd} must be CLOEXEC"
            );
        }
    }

    #[test]
    fn bind_all_fails_staged_as_non_root() {
        // On the HOST netns a normal user cannot bind :53/udp
        // (CAP_NET_BIND_SERVICE is missing outside the sandbox), so the
        // production bind_all must fail with a staged Listeners error —
        // never a panic, never an unstyled io::Error. Asserts the STAGE
        // only: a host port collision on 15001/3128 would fail at an
        // earlier bind but the same stage, keeping the test robust (R21).
        // Guarded: as root the privileged bind would legitimately succeed.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let err = bind_all().expect_err("host-netns bind_all must fail for non-root");
        assert_eq!(err.stage(), Stage::Listeners);
        assert!(!err.reason().is_empty());
        assert!(
            err.to_string().starts_with("sbx __init: listeners:"),
            "{err}"
        );
    }
}
