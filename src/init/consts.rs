//! Sandbox-network and wire-protocol constants (issue #5).
//!
//! Several constants are not exported by the `libc` crate; they are defined
//! here from the kernel uAPI headers (stable ABI, source noted per constant).
//! Visibility is deliberately two-tier (design D10): the `pub` tier is the
//! cross-issue surface (#6 documents the proxy ports in the bwrap argv, #7
//! consumes [`SO_ORIGINAL_DST`], #9 [`IP_RECVORIGDSTADDR`], #10 the wire
//! bytes and [`GO_TIMEOUT`] budget); kernel-plumbing constants shared by
//! exactly the init modules are `pub(crate)` and land with their consumers.
//!
//! Test-only addresses (TEST-NET-3 `203.0.113.7`, drop port 9999, ...) live
//! in `tests/sandbox_init.rs`, never here: production constants only ship in
//! the binary.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Sandbox IP assigned to `lo` inside the private netns (spike fact F7:
/// the address must exist before the default route references it as
/// `prefsrc`, or the kernel rejects the route with EADDRNOTAVAIL). Only
/// meaningful inside the namespace — never routable outside.
pub const SANDBOX_ADDR: Ipv4Addr = Ipv4Addr::new(10, 255, 255, 1);

/// Transparent-proxy TCP listener port (127.0.0.1): non-local TCP is
/// redirected here by the nftables ruleset. #6 documents it, #7 serves it.
pub const TRANSPARENT_TCP_PORT: u16 = 15001;

/// Explicit-proxy TCP listener port (127.0.0.1): #6 sets
/// `HTTP(S)_PROXY=http://127.0.0.1:3128` in the sandbox environment, #8
/// serves it.
pub const EXPLICIT_TCP_PORT: u16 = 3128;

/// DNS UDP listener port (127.0.0.1): udp/53 is redirected here (port
/// preserved by the bare `redir`), #9 serves it. Privileged port — the
/// bind works because `__init` is ns-root with `CAP_NET_BIND_SERVICE`
/// over the owned netns.
pub const DNS_UDP_PORT: u16 = 53;

/// Number of listener fds handed to the parent in one SCM_RIGHTS message
/// (wire order: transparent, explicit, dns — pinned by
/// [`super::fdpass::ListenerFds`]).
pub const LISTENER_FD_COUNT: usize = 3;

/// Data payload of the child→parent fds message: marker and version in one
/// byte. Strict-checked (design D4): parent and child are always the same
/// binary, so any other byte is a protocol violation, not a negotiation.
pub const FDS_PAYLOAD_BYTE: u8 = b'F';

/// Data payload of the parent→child go message — releasing the payload exec.
/// Strict-checked like [`FDS_PAYLOAD_BYTE`].
pub const GO_BYTE: u8 = b'G';

/// `SO_RCVTIMEO` the child installs before blocking on the go byte: a stuck
/// parent aborts the sandbox with a staged `wait-go` error instead of
/// hanging forever (#10's startup budget consumes the same constant).
pub const GO_TIMEOUT: Duration = Duration::from_secs(30);

/// `SOL_IP` == `IPPROTO_IP` (`<linux/in.h>`). Alias kept so that
/// getsockopt/setsockopt call sites read symmetrically.
pub const SOL_IP: i32 = libc::IPPROTO_IP;

/// `SO_ORIGINAL_DST` from `<linux/netfilter_ipv4.h>` — NOT in the libc
/// crate. Conntrack-based DNAT lookup on a redirected TCP connection
/// (returns the pre-redirect destination as a raw `sockaddr_in`). #7's
/// production consumer; issue #5's integration tests consume it now. Stable
/// uAPI since 2.6.x.
pub const SO_ORIGINAL_DST: i32 = 80;

/// `IP_RECVORIGDSTADDR` (== `IP_ORIGDSTADDR`) from `<uapi/linux/in.h>` —
/// NOT in the libc crate. Enables the ancillary message carrying the
/// original destination `sockaddr_in` on UDP `recvmsg`. #9's consumer —
/// with the spike's F4 caveat: it reports the POST-DNAT `127.0.0.1:53`, so
/// it is informational only (replies go via `recv_from`'s peer address).
pub const IP_RECVORIGDSTADDR: i32 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_and_port_consts_pinned() {
        // The cross-issue surface, pinned: any change here is a wire-protocol
        // or deployment change (#6/#7/#8/#9/#10 consume these), never a
        // drive-by edit.
        assert_eq!(SANDBOX_ADDR.octets(), [10, 255, 255, 1]);
        assert_eq!(TRANSPARENT_TCP_PORT, 15001);
        assert_eq!(EXPLICIT_TCP_PORT, 3128);
        assert_eq!(DNS_UDP_PORT, 53);
        assert_eq!(LISTENER_FD_COUNT, 3);
        assert_eq!(FDS_PAYLOAD_BYTE, b'F');
        assert_eq!(GO_BYTE, b'G');
        assert_eq!(GO_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn uapi_sockopt_consts_pinned() {
        // Values transcribed from the kernel uAPI headers (sources in the
        // const docs); libc does not export them, so the transcription is
        // pinned here.
        assert_eq!(SO_ORIGINAL_DST, 80);
        assert_eq!(IP_RECVORIGDSTADDR, 20);
        assert_eq!(SOL_IP, libc::IPPROTO_IP);
    }
}
