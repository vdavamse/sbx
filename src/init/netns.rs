//! Namespace + network setup for `sbx __init` (issue #5) — the spike/probe
//! port behind the production error vocabulary.
//!
//! 1. **Order is load-bearing** (pipeline stages `unshare → idmap → netns →
//!    ipv6`): `unshare(CLONE_NEWUSER|CLONE_NEWNET)` →
//!    `/proc/self/setgroups` = "deny" (required before gid_map) →
//!    uid_map/gid_map = `"0 <outer id> 1"` → `lo` UP (RTM_NEWLINK, IFF_UP in
//!    flags AND change mask) → addr `10.255.255.1/32` on lo (RTM_NEWADDR,
//!    scope universe) → default route via lo (RTM_NEWROUTE) → read-back
//!    asserts → IPv6 off. The addr MUST precede the route: the kernel
//!    rejects a non-local `RTA_PREFSRC` with EADDRNOTAVAIL (spike fact
//!    Q1/F7).
//! 2. **No unit test ever calls `unshare`** (design D12/R20): the cargo-test
//!    process is multithreaded, where `unshare(CLONE_NEWUSER)` fails EPERM —
//!    and a *successful* unshare would capture the whole test binary's
//!    namespaces. Every syscall path here is exercised by the spawned
//!    single-threaded children of `tests/sandbox_init.rs`; only the pure
//!    mappers are unit-tested.
//! 3. The netlink socket is created AFTER unshare — netlink sockets bind to
//!    the network namespace open at `socket(2)` time, so a pre-unshare
//!    socket would configure the HOST netns.
//! 4. **Read-back verification is fail-closed**: any mismatch is a hard
//!    [`Stage::Netns`] error — the sandbox must never proceed to
//!    rules/exec on a half-configured netns. The asserts include the
//!    kernel-auto-added `127.0.0.1/8` (spike fact F7: it appears when lo
//!    comes up); its absence means lo did not come up properly.
//! 5. **IPv6 (design D14)**: write `all/disable_ipv6` then
//!    `default/disable_ipv6`; a NotFound sysctl ⇒ the kernel is built
//!    without IPv6 ⇒ structurally disabled ⇒ OK; any other write error is
//!    fatal (fail closed — probe-verified writable as ns-root). Then verify
//!    `/proc/net/if_inet6` is EMPTY — non-empty after the disable is fatal.
//!    IPv6 additionally fails closed structurally: the rules are `ip`-family
//!    only and a fresh netns has no v6 route ⇒ ENETUNREACH.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use netlink_bindings::{rt_addr, rt_link, rt_route};
use netlink_socket2::NetlinkSocket;

use super::consts::{IFA_F_PERMANENT, IFF_UP, SANDBOX_ADDR};
use super::{InitError, Stage};

// rtnetlink constants not needed as types by the generated bindings
// (module-private per design D10 — kernel plumbing for exactly this file).
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

/// The sysctl knobs [`disable_ipv6`] writes, in order: `all` first (covers
/// every existing interface), then `default` (covers interfaces created
/// later — bwrap's, if #6 ever unshares more).
pub(crate) const IPV6_DISABLE_PATHS: [&str; 2] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
];

/// The interface-address table [`disable_ipv6`] verifies is empty.
const IF_INET6_PATH: &str = "/proc/net/if_inet6";

/// The OUTER (pre-unshare) uid/gid, captured by [`unshare_namespaces`] and
/// consumed by [`write_id_maps`]: inside the fresh userns `getuid()` reports
/// the overflow id (65534) until the maps are written, so the ids cannot be
/// re-read after the fact — they must be carried across the stage boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterIds {
    /// The outer uid that becomes ns-root (map line "0 {uid} 1").
    pub uid: u32,
    /// The outer gid that becomes ns-root (map line "0 {gid} 1").
    pub gid: u32,
}

fn netns_fail(reason: impl Into<String>) -> InitError {
    InitError::new(Stage::Netns, reason)
}

/// `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in the current (single-threaded!)
/// process; returns the outer ids [`write_id_maps`] needs.
///
/// EPERM gets the AppArmor hint (Ubuntu 24.04+ restricts unprivileged user
/// namespaces by default — including GitHub runners before the CI sysctl);
/// the mapping lives in the pure `unshare_error` fn (unit-tested; no test
/// ever calls unshare itself — module docs point 2).
pub fn unshare_namespaces() -> Result<OuterIds, InitError> {
    // Capture the outer ids BEFORE unshare: inside the fresh userns
    // getuid()/getgid() report the overflow id (65534) until the maps are
    // written.
    let ids = OuterIds {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(unshare_error(io::Error::last_os_error()));
    }
    Ok(ids)
}

/// Pure errno → staged-error mapper for [`unshare_namespaces`] (design D12:
/// the syscall itself is never unit-tested; its error vocabulary is).
fn unshare_error(err: io::Error) -> InitError {
    if err.raw_os_error() == Some(libc::EPERM) {
        InitError::new(
            Stage::Unshare,
            format!(
                "unshare(CLONE_NEWUSER|CLONE_NEWNET) failed with EPERM ({err}). \
                 On Ubuntu 24.04+ (incl. GitHub runners) AppArmor may restrict \
                 unprivileged user namespaces: check \
                 `sysctl kernel.apparmor_restrict_unprivileged_userns`."
            ),
        )
    } else {
        InitError::new(Stage::Unshare, format!("unshare failed: {err}"))
    }
}

/// Write the id maps of the fresh userns: ns-root (0) mapped to the single
/// outer id, ONE id wide. Order is load-bearing (module docs point 1):
/// `setgroups` must be denied before `gid_map` in an unprivileged userns.
pub fn write_id_maps(ids: OuterIds) -> Result<(), InitError> {
    write_proc("/proc/self/setgroups", "deny")?;
    write_proc("/proc/self/uid_map", &map_line(ids.uid))?;
    write_proc("/proc/self/gid_map", &map_line(ids.gid))?;
    Ok(())
}

/// Pure one-id map line: `"0 <outer> 1"` — inside the namespace, uid/gid 0
/// (ns-root, holding CAP_NET_ADMIN/CAP_NET_BIND_SERVICE over the owned
/// netns) maps to exactly one outer id.
fn map_line(outer: u32) -> String {
    format!("0 {outer} 1")
}

fn write_proc(path: &str, value: &str) -> Result<(), InitError> {
    fs::write(path, value)
        .map_err(|e| InitError::new(Stage::Idmap, format!("write {path} = {value:?}: {e}")))
}

/// Configure the fresh netns: `lo` UP → `10.255.255.1/32` → default route
/// via `lo` → read-back asserts (module docs points 1, 3, 4). Every failure
/// is a hard [`Stage::Netns`] error.
pub fn configure_netns() -> Result<(), InitError> {
    // The netlink socket must be created AFTER unshare — netlink sockets
    // bind to the network namespace open at socket(2) time (module docs
    // point 3). SOCK_CLOEXEC is the crate default, so it dies at exec.
    let mut sock = NetlinkSocket::new();

    let lo = lo_ifindex()?;
    link_up(&mut sock, lo)?;
    add_sandbox_addr(&mut sock, lo)?;
    add_default_route(&mut sock, lo)?;
    verify_readback(&mut sock, lo)
}

fn lo_ifindex() -> Result<u32, InitError> {
    let idx = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    if idx == 0 {
        return Err(netns_fail(format!(
            "if_nametoindex(lo): {}",
            io::Error::last_os_error()
        )));
    }
    Ok(idx)
}

/// `ip link set lo up` equivalent: RTM_NEWLINK with IFF_UP in the flags and
/// the change mask (spike fact F7).
fn link_up(sock: &mut NetlinkSocket, lo: u32) -> Result<(), InitError> {
    let req = rt_link::Request::new().op_newlink_do(&rt_link::Ifinfomsg {
        ifi_index: lo as i32,
        ifi_flags: IFF_UP,
        ifi_change: IFF_UP,
        ..Default::default()
    });
    sock.request(&req)
        .map_err(|e| netns_fail(format!("lo up request: {e}")))?
        .recv_ack()
        .map_err(|e| netns_fail(format!("lo up: {e}")))
}

/// `ip addr add 10.255.255.1/32 dev lo` equivalent (F7): scope universe,
/// permanent flag, CREATE|EXCL. Must run BEFORE the default route (module
/// docs point 1: EADDRNOTAVAIL otherwise).
fn add_sandbox_addr(sock: &mut NetlinkSocket, lo: u32) -> Result<(), InitError> {
    let mut req = rt_addr::Request::new()
        .set_create()
        .set_excl()
        .op_newaddr_do(&rt_addr::Ifaddrmsg {
            ifa_family: libc::AF_INET as u8,
            ifa_prefixlen: 32,
            ifa_flags: IFA_F_PERMANENT,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: lo,
        });
    req.encode()
        .push_address(SANDBOX_ADDR.into())
        .push_local(SANDBOX_ADDR.into());
    sock.request(&req)
        .map_err(|e| netns_fail(format!("addr request: {e}")))?
        .recv_ack()
        .map_err(|e| netns_fail(format!("addr add {SANDBOX_ADDR}/32: {e}")))
}

/// `ip route add default dev lo src 10.255.255.1` equivalent (F7): table
/// main, protocol boot, scope link, type unicast, dst_len 0, CREATE|EXCL.
/// Every packet the sandbox sends takes this route — into the nat chain.
fn add_default_route(sock: &mut NetlinkSocket, lo: u32) -> Result<(), InitError> {
    let mut req = rt_route::Request::new()
        .set_create()
        .set_excl()
        .op_newroute_do(&rt_route::Rtmsg {
            rtm_family: libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RT_TABLE_MAIN,
            rtm_protocol: RTPROT_BOOT,
            rtm_scope: RT_SCOPE_LINK,
            rtm_type: RTN_UNICAST,
            rtm_flags: 0,
        });
    req.encode().push_oif(lo).push_prefsrc(SANDBOX_ADDR.into());
    sock.request(&req)
        .map_err(|e| netns_fail(format!("route request: {e}")))?
        .recv_ack()
        .map_err(|e| netns_fail(format!("route add default: {e}")))
}

/// Dump-based read-back verification (module docs point 4): lo UP, both
/// addresses present (ours AND the kernel-auto-added 127.0.0.1/8), and the
/// default route via lo with prefsrc = the sandbox address. Any mismatch is
/// a hard error — never trust a write the kernel did not confirm.
fn verify_readback(sock: &mut NetlinkSocket, lo: u32) -> Result<(), InitError> {
    // 1) lo must be UP.
    let req = rt_link::Request::new().op_getlink_dump(&rt_link::Ifinfomsg::default());
    let mut iter = sock
        .request(&req)
        .map_err(|e| netns_fail(format!("getlink dump: {e}")))?;
    let mut lo_up: Option<bool> = None;
    while let Some(res) = iter.recv() {
        let (hdr, attrs) = res.map_err(|e| netns_fail(format!("getlink dump: {e}")))?;
        if attrs.get_ifname().is_ok_and(|n| n == c"lo") {
            lo_up = Some(hdr.ifi_flags & IFF_UP != 0);
        }
    }
    match lo_up {
        Some(true) => {}
        Some(false) => return Err(netns_fail("read-back: lo is not UP")),
        None => return Err(netns_fail("read-back: lo missing from getlink dump")),
    }

    // 2) addresses: 10.255.255.1/32 (ours) and 127.0.0.1/8 (auto-added by
    //    the kernel when lo comes up — F7).
    let req = rt_addr::Request::new().op_getaddr_dump(&rt_addr::Ifaddrmsg {
        ifa_family: libc::AF_INET as u8,
        ..Default::default()
    });
    let mut iter = sock
        .request(&req)
        .map_err(|e| netns_fail(format!("getaddr dump: {e}")))?;
    let (mut have_sandbox, mut have_loopback4) = (false, false);
    while let Some(res) = iter.recv() {
        let (hdr, attrs) = res.map_err(|e| netns_fail(format!("getaddr dump: {e}")))?;
        let ip = attrs
            .get_local()
            .or_else(|_| attrs.get_address())
            .map_err(|e| netns_fail(format!("getaddr parse: {e}")))?;
        let IpAddr::V4(ip) = ip else { continue };
        if ip == SANDBOX_ADDR && hdr.ifa_prefixlen == 32 {
            have_sandbox = true;
        }
        if ip == Ipv4Addr::LOCALHOST && hdr.ifa_prefixlen == 8 {
            have_loopback4 = true;
        }
    }
    if !have_sandbox || !have_loopback4 {
        return Err(netns_fail(format!(
            "read-back: expected {SANDBOX_ADDR}/32 and 127.0.0.1/8 \
             (found sandbox={have_sandbox} loopback={have_loopback4})"
        )));
    }

    // 3) default route via lo with prefsrc = the sandbox address.
    let req = rt_route::Request::new().op_getroute_dump(&rt_route::Rtmsg {
        rtm_family: libc::AF_INET as u8,
        rtm_table: RT_TABLE_MAIN,
        ..Default::default()
    });
    let mut iter = sock
        .request(&req)
        .map_err(|e| netns_fail(format!("getroute dump: {e}")))?;
    let mut have_default = false;
    while let Some(res) = iter.recv() {
        let (hdr, attrs) = res.map_err(|e| netns_fail(format!("getroute dump: {e}")))?;
        if hdr.rtm_dst_len != 0 {
            continue;
        }
        let oif_ok = attrs.get_oif().is_ok_and(|oif| oif == lo);
        let src_ok = attrs
            .get_prefsrc()
            .is_ok_and(|src| src == IpAddr::V4(SANDBOX_ADDR));
        if oif_ok && src_ok {
            have_default = true;
        }
    }
    if !have_default {
        return Err(netns_fail(format!(
            "read-back: default route via lo src {SANDBOX_ADDR} not found"
        )));
    }
    Ok(())
}

/// Disable IPv6 fail-closed (module docs point 5, design D14): write the
/// sysctls (NotFound ⇒ no IPv6 in the kernel ⇒ OK), then verify
/// `/proc/net/if_inet6` is empty — a non-empty table after the disable is
/// fatal, never a warning (the probe's warning-only fallback is upgraded:
/// "any setup failure means the command never starts").
pub fn disable_ipv6() -> Result<(), InitError> {
    for path in IPV6_DISABLE_PATHS {
        if let Err(err) = fs::write(path, "1") {
            classify_disable_write(&err)?;
        }
    }
    interpret_if_inet6(fs::read_to_string(IF_INET6_PATH))
}

/// Pure decision fn: NotFound on a disable_ipv6 sysctl means the kernel is
/// built without IPv6 (CONFIG_IPV6=n) — structurally disabled, OK. Every
/// other write error is fatal (fail closed; probe-verified writable as
/// ns-root, so an error here is a real anomaly).
fn classify_disable_write(err: &io::Error) -> Result<(), InitError> {
    if err.kind() == io::ErrorKind::NotFound {
        return Ok(());
    }
    Err(InitError::new(
        Stage::Ipv6,
        format!("write disable_ipv6 failed: {err}"),
    ))
}

/// Pure decision fn for the post-disable verification read: a missing
/// `/proc/net/if_inet6` is the CONFIG_IPV6=n case (OK); an empty (or
/// whitespace-only) table is success; ANY address left is fatal — the
/// sandbox would have a reachable IPv6 stack the ip-family ruleset does not
/// filter.
fn interpret_if_inet6(contents: io::Result<String>) -> Result<(), InitError> {
    match contents {
        Ok(text) if text.trim().is_empty() => Ok(()),
        Ok(text) => Err(InitError::new(
            Stage::Ipv6,
            format!("IPv6 addresses still present after disable: {text:?}"),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(InitError::new(
            Stage::Ipv6,
            format!("read {IF_INET6_PATH}: {err}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NO test in this module (or anywhere in the unit suite) calls
    // unshare/configure_netns/disable_ipv6 for real — module docs point 2
    // (D12/R20). Only the pure mappers are exercised; the syscall paths are
    // covered end-to-end by tests/sandbox_init.rs's spawned children.

    #[test]
    fn unshare_error_maps_eperm_to_apparmor_hint() {
        // EPERM is the AppArmor-restriction signature on Ubuntu 24.04+ —
        // the hint must name the exact sysctl so the failure is actionable
        // (spike text, adapted to the staged shape).
        let err = unshare_error(io::Error::from_raw_os_error(libc::EPERM));
        assert_eq!(err.stage(), Stage::Unshare);
        let reason = err.reason();
        assert!(reason.contains("EPERM"), "{reason}");
        assert!(reason.contains("AppArmor"), "{reason}");
        assert!(
            reason.contains("apparmor_restrict_unprivileged_userns"),
            "{reason}"
        );
        assert!(
            reason.contains("unshare(CLONE_NEWUSER|CLONE_NEWNET)"),
            "{reason}"
        );
    }

    #[test]
    fn unshare_error_passes_other_errnos_through() {
        let err = unshare_error(io::Error::from_raw_os_error(libc::EINVAL));
        assert_eq!(err.stage(), Stage::Unshare);
        assert!(err.reason().starts_with("unshare failed:"), "{}", err);
        assert!(!err.reason().contains("AppArmor"), "{}", err);
    }

    #[test]
    fn map_line_formats_single_id_map() {
        // "0 <outer> 1": ns-root mapped to exactly ONE outer id — no wider
        // map is ever written (the sandbox must not own a uid range).
        assert_eq!(map_line(1000), "0 1000 1");
        assert_eq!(map_line(0), "0 0 1");
        assert_eq!(map_line(u32::MAX), "0 4294967295 1");
    }

    #[test]
    fn disable_write_classification() {
        // NotFound ⇒ CONFIG_IPV6=n ⇒ structurally disabled ⇒ OK (D14).
        assert!(classify_disable_write(&io::Error::from(io::ErrorKind::NotFound)).is_ok());
        // Every other write error is fatal — fail closed, never a warning.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Other,
        ] {
            let err = classify_disable_write(&io::Error::from(kind))
                .expect_err("non-NotFound write errors must be fatal");
            assert_eq!(err.stage(), Stage::Ipv6, "{kind:?}");
            assert!(err.reason().contains("disable_ipv6"), "{err}");
        }
    }

    #[test]
    fn if_inet6_interpretation() {
        // Empty (or whitespace-only) table ⇒ success.
        assert!(interpret_if_inet6(Ok(String::new())).is_ok());
        assert!(interpret_if_inet6(Ok("  \n".to_owned())).is_ok());
        // ANY address left ⇒ fatal, message carries the contents.
        let row = "fe800000000000006c8a5e0000000001 02 40 20 80 10 eth0\n";
        let err = interpret_if_inet6(Ok(row.to_owned())).expect_err("non-empty must be fatal");
        assert_eq!(err.stage(), Stage::Ipv6);
        assert!(err.reason().contains("still present"), "{err}");
        assert!(err.reason().contains("eth0"), "contents quoted: {err}");
        // Missing file ⇒ CONFIG_IPV6=n ⇒ OK; unreadable file ⇒ fatal.
        assert!(interpret_if_inet6(Err(io::Error::from(io::ErrorKind::NotFound))).is_ok());
        let err = interpret_if_inet6(Err(io::Error::from(io::ErrorKind::PermissionDenied)))
            .expect_err("an unreadable if_inet6 must be fatal");
        assert_eq!(err.stage(), Stage::Ipv6);
        assert!(err.reason().contains("/proc/net/if_inet6"), "{err}");
    }

    #[test]
    fn ipv6_disable_paths_pinned() {
        // D14: all FIRST (covers existing interfaces), then default (covers
        // later-created ones). The order and the exact paths are pinned.
        assert_eq!(
            IPV6_DISABLE_PATHS,
            [
                "/proc/sys/net/ipv6/conf/all/disable_ipv6",
                "/proc/sys/net/ipv6/conf/default/disable_ipv6",
            ]
        );
    }
}
