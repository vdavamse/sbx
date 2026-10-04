//! uAPI constants and sandbox configuration.
//!
//! Several constants are not exported by the `libc` crate; they are defined
//! here from the kernel uAPI headers (stable ABI, source noted per constant).

/// Process exit codes (see README.md).
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 1;
pub const EXIT_NETNS: i32 = 2;
pub const EXIT_RULES: i32 = 3;
pub const EXIT_VERIFY: i32 = 4;
pub const EXIT_SELFTEST: i32 = 5;
pub const EXIT_LISTEN: i32 = 6;
pub const EXIT_BREAK_ACCEPTED: i32 = 7;

/// `SOL_IP` == `IPPROTO_IP` (`<linux/in.h>`). Alias kept so that
/// getsockopt/setsockopt call sites read symmetrically.
pub const SOL_IP: i32 = libc::IPPROTO_IP;

/// `SO_ORIGINAL_DST` from `<linux/netfilter_ipv4.h>` — NOT in the libc crate.
/// Conntrack-based DNAT lookup on a redirected TCP connection (returns the
/// pre-redirect destination as a raw `sockaddr_in`). Stable uAPI since 2.6.x.
pub const SO_ORIGINAL_DST: i32 = 80;

/// `IP_RECVORIGDSTADDR` (== `IP_ORIGDSTADDR`) from `<uapi/linux/in.h>` —
/// NOT in the libc crate. Enables the ancillary message carrying the original
/// destination `sockaddr_in` on UDP `recvmsg`.
pub const IP_RECVORIGDSTADDR: i32 = 20;

/// `ERESTART` from `<asm-generic/errno.h>` — kernel-internal errno returned
/// by nfnetlink batch processing when the ruleset generation id changed
/// between GETGEN and batch commit. NOT exported by the libc crate.
pub const ERESTART: i32 = 85;

/// `IFF_UP` from `<net/if.h>`; `ifinfomsg` fields are `u32`.
pub const IFF_UP: u32 = libc::IFF_UP as u32;

/// Sandbox IP assigned to `lo` inside the private netns (empirical fact F7).
/// Only meaningful inside the namespace — never routable outside.
pub const SANDBOX_ADDR: [u8; 4] = [10, 255, 255, 1];

/// Local TCP listener port; non-loopback TCP is redirected here.
pub const TCP_PORT: u16 = 15001;
/// Local UDP listener port; DNS (udp/53) is redirected here (port preserved).
pub const DNS_PORT: u16 = 53;

/// External test address: TEST-NET-3 (RFC 5737) — never routable on the
/// Internet, safe to use as a fake external destination.
pub const TEST_ADDR: [u8; 4] = [203, 0, 113, 7];
/// TCP port the self-test connects to (gets redirected to [`TCP_PORT`]).
pub const TEST_TCP_PORT: u16 = 443;
/// Non-53 UDP port used for the drop test (and loopback control).
pub const TEST_UDP_DROP_PORT: u16 = 9999;

/// Per-operation timeout (seconds) used across self-tests and listeners.
pub const OP_TIMEOUT_SECS: u64 = 5;
