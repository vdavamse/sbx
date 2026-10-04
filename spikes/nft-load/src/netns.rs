//! Namespace + network setup (design D3; sequence per empirical fact F7).
//!
//! ORDER IS LOAD-BEARING:
//!   1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`
//!   2. `/proc/self/setgroups` = "deny"  (required before gid_map)
//!   3. `/proc/self/uid_map` / `gid_map` = "0 <outer uid|gid> 1"
//!   4. `lo` UP via RTM_NEWLINK (IFF_UP in both flags and change mask)
//!   5. addr `10.255.255.1/32` on `lo`, scope universe (RTM_NEWADDR) —
//!      must precede the route: the kernel rejects a non-local RTA_PREFSRC
//!      with EADDRNOTAVAIL (clarification Q1)
//!   6. route `default dev lo src 10.255.255.1` (RTM_NEWROUTE: table main,
//!      protocol boot, scope link, type unicast, dst_len 0)
//!   7. Read back all three via rtnetlink dumps and assert.
//!
//! Failures map to exit 1 (unshare EPERM → AppArmor hint) or exit 2
//! (everything else in this module).

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use netlink_bindings::{rt_addr, rt_link, rt_route};
use netlink_socket2::NetlinkSocket;

use crate::consts::{EXIT_NETNS, EXIT_USAGE, IFF_UP, SANDBOX_ADDR};
use crate::Fail;

// rtnetlink constants not needed as types by the generated bindings.
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

fn netns_fail(msg: String) -> Fail {
    Fail::new(EXIT_NETNS, format!("netns: {msg}"))
}

/// Set up the sandbox netns in the current process. On success this process
/// lives in a fresh user+net namespace with `lo` up, `10.255.255.1/32`
/// assigned and a default route via `lo`.
pub fn setup(verbose: bool) -> Result<(), Fail> {
    // Capture outer ids BEFORE unshare: inside the fresh userns getuid()
    // returns the overflow id (65534) until the maps are written.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err(Fail::new(
                EXIT_USAGE,
                format!(
                    "unshare(CLONE_NEWUSER|CLONE_NEWNET) failed with EPERM ({err}). \
                     On Ubuntu 24.04+ (incl. GitHub runners) AppArmor may restrict \
                     unprivileged user namespaces: check \
                     `sysctl kernel.apparmor_restrict_unprivileged_userns` and see README.md."
                ),
            ));
        }
        return Err(netns_fail(format!("unshare failed: {err}")));
    }
    status(verbose, "unshared user+net namespace");

    // setgroups must be denied before gid_map in an unprivileged userns.
    write_proc("/proc/self/setgroups", "deny")?;
    write_proc("/proc/self/uid_map", &format!("0 {uid} 1"))?;
    write_proc("/proc/self/gid_map", &format!("0 {gid} 1"))?;
    status(
        verbose,
        &format!("uid/gid maps written (ns root -> outer {uid}:{gid})"),
    );

    // The netlink socket must be created AFTER unshare — netlink sockets
    // bind to the network namespace open at socket(2) time.
    let mut sock = NetlinkSocket::new();

    let lo = lo_ifindex()?;
    link_up(&mut sock, lo)?;
    status(verbose, &format!("lo (ifindex {lo}) is UP"));
    add_sandbox_addr(&mut sock, lo)?;
    status(verbose, "assigned 10.255.255.1/32 to lo");
    add_default_route(&mut sock, lo)?;
    status(verbose, "added route: default dev lo src 10.255.255.1");

    verify_readback(&mut sock, lo, verbose)?;
    status(
        verbose,
        "read-back verified: lo UP, 10.255.255.1/32 + 127.0.0.1/8 present, default route via lo",
    );
    Ok(())
}

fn status(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("[netns] {msg}");
    }
}

fn write_proc(path: &str, value: &str) -> Result<(), Fail> {
    fs::write(path, value).map_err(|e| netns_fail(format!("write {path} = {value:?}: {e}")))
}

fn lo_ifindex() -> Result<u32, Fail> {
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
/// the change mask (F7).
fn link_up(sock: &mut NetlinkSocket, lo: u32) -> Result<(), Fail> {
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
/// CREATE|EXCL. Must run BEFORE the default route (Q1: the kernel rejects a
/// non-local RTA_PREFSRC with EADDRNOTAVAIL).
fn add_sandbox_addr(sock: &mut NetlinkSocket, lo: u32) -> Result<(), Fail> {
    let mut req = rt_addr::Request::new()
        .set_create()
        .set_excl()
        .op_newaddr_do(&rt_addr::Ifaddrmsg {
            ifa_family: libc::AF_INET as u8,
            ifa_prefixlen: 32,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: lo,
        });
    let ip = Ipv4Addr::from(SANDBOX_ADDR);
    req.encode().push_address(ip.into()).push_local(ip.into());
    sock.request(&req)
        .map_err(|e| netns_fail(format!("addr request: {e}")))?
        .recv_ack()
        .map_err(|e| netns_fail(format!("addr add 10.255.255.1/32: {e}")))
}

/// `ip route add default dev lo src 10.255.255.1` equivalent (F7).
fn add_default_route(sock: &mut NetlinkSocket, lo: u32) -> Result<(), Fail> {
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
    req.encode()
        .push_oif(lo)
        .push_prefsrc(Ipv4Addr::from(SANDBOX_ADDR).into());
    sock.request(&req)
        .map_err(|e| netns_fail(format!("route request: {e}")))?
        .recv_ack()
        .map_err(|e| netns_fail(format!("route add default: {e}")))
}

/// Dump-based read-back verification. Any mismatch is a hard failure
/// (exit 2) — the self-tests must never run on a misconfigured netns.
fn verify_readback(sock: &mut NetlinkSocket, lo: u32, verbose: bool) -> Result<(), Fail> {
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
        Some(true) => status(verbose, "read-back: lo is UP"),
        Some(false) => return Err(netns_fail("read-back: lo is not UP".into())),
        None => return Err(netns_fail("read-back: lo missing from getlink dump".into())),
    }

    // 2) addresses: 10.255.255.1/32 (ours) and 127.0.0.1/8 (auto-added by
    //    the kernel when lo comes up).
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
        if ip == Ipv4Addr::from(SANDBOX_ADDR) && hdr.ifa_prefixlen == 32 {
            have_sandbox = true;
        }
        if ip == Ipv4Addr::LOCALHOST && hdr.ifa_prefixlen == 8 {
            have_loopback4 = true;
        }
    }
    if !have_sandbox || !have_loopback4 {
        return Err(netns_fail(format!(
            "read-back: expected 10.255.255.1/32 and 127.0.0.1/8 (found sandbox={have_sandbox} loopback={have_loopback4})"
        )));
    }
    status(
        verbose,
        "read-back: addresses 10.255.255.1/32 + 127.0.0.1/8 present",
    );

    // 3) default route via lo with prefsrc 10.255.255.1.
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
            .is_ok_and(|src| src == IpAddr::V4(Ipv4Addr::from(SANDBOX_ADDR)));
        if oif_ok && src_ok {
            have_default = true;
        }
    }
    if !have_default {
        return Err(netns_fail(
            "read-back: default route via lo src 10.255.255.1 not found".into(),
        ));
    }
    status(
        verbose,
        "read-back: default route via lo src 10.255.255.1 present",
    );
    Ok(())
}
