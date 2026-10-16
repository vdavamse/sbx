//! The host tier's 43 checks (issue #13, §4 groups A, B, C, D, F05/F06, G, H):
//! the scenario plan and the pure evaluators over scenario evidence.
//!
//! Evaluation rules (review fixes):
//! * Controls come FIRST in every evaluator. A control reads probe evidence
//!   (`ok`, `connected`, `errno`, data fields, audit rows); missing or
//!   unreadable evidence is a control failure, never a silent pass.
//! * Audit rows are pinned to a leg: a deny row must match the leg's probe
//!   `local_addr` (the audit `client`), its `via` (`transparent` for TCP/TLS
//!   legs, `explicit-connect` for CONNECT legs) and its reason text. A row
//!   produced by the other leg does not satisfy the assertion.
//! * Scenario-lifecycle assertions (`*.gone` keys, rc, elapsed) are plain
//!   assertions; the `*.seen` keys are controls.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde_json::Value;

use super::probe::OpResult;
use super::report::{CheckResult, SkipKind};
use super::scenarios::Scn;
use crate::host::Status;

/// The evaluator result: the pass text, or the first failed assertion.
pub type R = Result<String, F>;

/// A failed assertion (`control` marks a broken control).
#[derive(Debug, Clone)]
pub struct F {
    pub msg: String,
    pub ev: Vec<String>,
    pub control: bool,
}

fn fail(msg: impl Into<String>) -> F {
    F {
        msg: msg.into(),
        ev: Vec::new(),
        control: false,
    }
}

fn ctl_fail(msg: impl Into<String>) -> F {
    F {
        msg: format!("control failed: {}", msg.into()),
        ev: Vec::new(),
        control: true,
    }
}

fn need(cond: bool, msg: impl Into<String>) -> Result<(), F> {
    if cond { Ok(()) } else { Err(fail(msg)) }
}

fn ctl(cond: bool, msg: impl Into<String>) -> Result<(), F> {
    if cond { Ok(()) } else { Err(ctl_fail(msg)) }
}

/// Turn any evidence-read failure inside a control into a control failure.
fn as_ctl(f: F) -> F {
    ctl_fail(f.msg)
}

/// The scenario-set map handed to evaluators.
pub type Scns = BTreeMap<&'static str, Scn>;

/// The scenario names a check's evidence comes from.
pub fn scenarios_of(id: &str) -> &'static [&'static str] {
    match id {
        "A01" | "A07" | "A08" | "A09" | "A10" | "A11" | "B10" | "C01" | "C03" | "C05" | "C06"
        | "C08" | "C09" | "C10" | "C11" | "C12" | "C13" | "C14" | "D01" | "D02" | "D03" | "D04" => {
            &["S1"]
        }
        "D05" => &["S13"],
        "C04" => &["S2", "S3"],
        "D06" | "D07" | "D08" | "D09" => &["S11a", "S11b"],
        "D10" | "H01" | "H02" | "H03" | "H04" | "H05" | "H06" => &["S12"],
        "F01" => &["S10"],
        "F05" => &["S4"],
        "F06" => &["S5"],
        "G01" => &["S6"],
        "G05" => &["S6", "S6b"],
        "G02" => &["S7"],
        "G03" => &["S8a", "S8b", "S8c"],
        "G04" => &["S9"],
        _ => &[],
    }
}

/// Whether `id` is implemented by this module.
pub fn implemented(id: &str) -> bool {
    !scenarios_of(id).is_empty()
}

fn sc<'a>(s: &'a Scns, name: &str) -> Result<&'a Scn, F> {
    let scn = s
        .get(name)
        .ok_or_else(|| fail(format!("scenario {name} was not run")))?;
    if let Some(why) = &scn.skip {
        return Err(fail(format!("scenario {name} unavailable: {why}")));
    }
    Ok(scn)
}

fn op<'a>(s: &'a Scn, id: &str) -> Result<&'a OpResult, F> {
    if let Some(e) = &s.probe_err {
        return Err(fail(format!("probe did not run in {}: {e}", s.name)));
    }
    let p = s
        .probe
        .as_ref()
        .ok_or_else(|| fail(format!("probe did not run in {}", s.name)))?;
    p.get(id)
        .ok_or_else(|| fail(format!("missing probe result {id} in {}", s.name)))
}

/// The leg's local address (the audit `client` for that connection).
fn local(r: &OpResult) -> Result<String, F> {
    r.data["local_addr"]
        .as_str()
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("probe result {} reports no local_addr", r.id)))
}

fn rcode(r: &OpResult) -> i64 {
    r.data["rcode"].as_i64().unwrap_or(-1)
}

fn a_ips(r: &OpResult) -> Vec<Ipv4Addr> {
    r.data["a"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()?.parse().ok()).collect())
        .unwrap_or_default()
}

fn answers(r: &OpResult) -> i64 {
    r.data["answers"].as_i64().unwrap_or(-1)
}

fn errno(r: &OpResult) -> Option<i32> {
    r.errno
}

fn errno_name(e: Option<i32>) -> String {
    match e {
        None => "no errno".to_owned(),
        Some(n) => format!(
            "errno {n} ({})",
            std::io::Error::from_raw_os_error(n)
                .to_string()
                .split(" (os error")
                .next()
                .unwrap_or("")
        ),
    }
}

fn in_fake_range(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] & 0xFE) == 18
}

fn connected(r: &OpResult) -> bool {
    r.data["connected"].as_bool().unwrap_or(false)
}

fn read_len(r: &OpResult) -> u64 {
    r.data["reads"]
        .as_array()
        .map(|a| a.iter().map(|x| x["len"].as_u64().unwrap_or(0)).sum())
        .unwrap_or(0)
}

fn reads_text(r: &OpResult) -> String {
    r.data["reads"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x["text"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

fn status_code(r: &OpResult) -> String {
    reads_text(r)
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_owned()
}

fn first_line(r: &OpResult) -> String {
    reads_text(r).lines().next().unwrap_or("").to_owned()
}

/// Whether the audit has a deny row for this leg: client, via and reason.
fn denied(s: &Scn, client: &str, via: &str, reason: &str) -> bool {
    s.audit.iter().any(|r| {
        r["event"] == "deny"
            && r["client"].as_str() == Some(client)
            && r["via"].as_str() == Some(via)
            && r["reason"].as_str().is_some_and(|x| x.contains(reason))
    })
}

/// Whether the audit has a dns row for this client with the given verdict,
/// and reason text containing `reason` (empty = any).
fn dns_row(s: &Scn, client: &str, verdict: &str, reason: &str) -> bool {
    s.audit.iter().any(|r| {
        r["event"] == "dns"
            && r["client"].as_str() == Some(client)
            && r["verdict"].as_str() == Some(verdict)
            && r["reason"].as_str().is_some_and(|x| x.contains(reason))
    })
}

/// A probe-leg assertion: no bytes came back on the leg.
fn leg_no_bytes(s: &Scn, id: &str) -> Result<(), F> {
    let r = op(s, id)?;
    need(
        read_len(r) == 0,
        format!("{id}: expected no bytes, got {}", read_len(r)),
    )
}

/// A probe-leg assertion: the audit has a deny row for this leg's client,
/// through `via`, with `reason`.
fn leg_denied(s: &Scn, id: &str, via: &str, reason: &str) -> Result<(), F> {
    leg_denied_any(s, id, via, &[reason.to_owned()])
}

/// The audit rows the probe leg `id` produced (matched by its client address),
/// for failure diagnostics: a "no row" failure shows what the audit actually says.
fn rows_for_client(s: &Scn, client: &str) -> Vec<String> {
    s.audit
        .iter()
        .filter(|r| r["client"].as_str() == Some(client))
        .map(|r| {
            format!(
                "audit: via={} event={} verdict={} reason={}",
                r["via"].as_str().unwrap_or("-"),
                r["event"].as_str().unwrap_or("-"),
                r["verdict"].as_str().unwrap_or("-"),
                r["reason"].as_str().unwrap_or("-")
            )
        })
        .collect()
}

/// A leg's deny row must carry one of `reasons` (exact product texts), through
/// `via`, for the leg's own client address. A failure lists the rows that the
/// audit has for that client.
fn leg_denied_any(s: &Scn, id: &str, via: &str, reasons: &[String]) -> Result<(), F> {
    let r = op(s, id)?;
    let l = local(r)?;
    if reasons.iter().any(|reason| denied(s, &l, via, reason)) {
        return Ok(());
    }
    Err(F {
        msg: format!("no audit deny row for {id} ({l}) via {via} with any of {reasons:?}"),
        ev: rows_for_client(s, &l),
        control: false,
    })
}

/// A control: the named dns query was answered with one fake IP.
fn answered_ctl(s: &Scn, id: &str) -> Result<(), F> {
    let r = op(s, id).map_err(as_ctl)?;
    ctl(
        rcode(r) == 0 && a_ips(r).len() == 1 && in_fake_range(a_ips(r)[0]),
        format!("dns query {id} was not answered with a fake IP"),
    )
}

/// A control on a probe result: the op must have succeeded.
fn ctl_ok(s: &Scn, id: &str) -> Result<(), F> {
    let r = op(s, id).map_err(as_ctl)?;
    ctl(r.ok, format!("{id} did not succeed"))
}

/// A scenario control recorded by the runner (`ctl` map): must be `Ok`.
fn ctl_key(s: &Scn, key: &str) -> Result<(), F> {
    match s.ctl.get(key) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(ctl_fail(format!("{key}: {e}"))),
        None => Err(ctl_fail(format!("{key}: control not recorded"))),
    }
}

/// A scenario lifecycle assertion (`ctl` map entry): must be `Ok`.
fn assert_key(s: &Scn, key: &str) -> Result<(), F> {
    match s.ctl.get(key) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(fail(format!("{key}: {e}"))),
        None => Err(fail(format!("{key}: not recorded"))),
    }
}

fn fin_of(s: &Scn) -> Result<&super::spawn::Finished, F> {
    s.fin
        .as_ref()
        .ok_or_else(|| fail(format!("sbx run did not run in {}", s.name)))
}

fn rc_is(s: &Scn, want: i32) -> Result<(), F> {
    let fin = fin_of(s)?;
    need(
        fin.rc == Some(want),
        format!("{}: expected rc {want}, got {:?}", s.name, fin.rc),
    )
}

fn socket_fails(s: &Scn, id: &str, expect: Option<i32>) -> Result<(), F> {
    let r = op(s, id)?;
    need(
        !r.data["created"].as_bool().unwrap_or(true),
        format!("socket {id}: expected failure, got a socket"),
    )?;
    need(
        errno(r).is_some(),
        format!("socket {id}: failed without an errno"),
    )?;
    if let Some(e) = expect {
        need(
            errno(r) == Some(e),
            format!(
                "socket {id}: expected errno {e}, got {}",
                errno_name(errno(r))
            ),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------- group A

fn a01(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let a = op(s1, "a01.a")?;
    let ips = a_ips(a);
    need(
        rcode(a) == 0 && ips.len() == 1 && in_fake_range(ips[0]),
        format!(
            "dns A allowed.conformance.test: expected rcode 0 with one A in 198.18.0.0/15, got rcode {} {ips:?}",
            rcode(a)
        ),
    )?;
    let aaaa = op(s1, "a01.aaaa")?;
    need(
        rcode(aaaa) == 0 && answers(aaaa) == 0,
        format!(
            "dns AAAA allowed.conformance.test: expected rcode 0 with 0 answers, got rcode {} {} answers",
            rcode(aaaa),
            answers(aaaa)
        ),
    )?;
    let l = local(a)?;
    if !dns_row(s1, &l, "answered", "") {
        return Err(F {
            msg: format!("no audit dns answered row for the A query's client ({l})"),
            ev: rows_for_client(s1, &l),
            control: false,
        });
    }
    Ok(format!("allowed name answered with {}", ips[0]))
}

fn a07(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    answered_ctl(s1, "a01.a")?;
    let d = op(s1, "a07.dns")?;
    need(
        rcode(d) == 3,
        format!(
            "dns other.conformance.test: expected rcode 3, got {}",
            rcode(d)
        ),
    )?;
    let l = local(d)?;
    if !dns_row(
        s1,
        &l,
        "denied",
        "other.conformance.test is not in the policy allow list",
    ) {
        return Err(F {
            msg: format!("no audit dns denied row for the other.conformance.test query ({l})"),
            ev: rows_for_client(s1, &l),
            control: false,
        });
    }
    let c = op(s1, "a07.connect")?;
    need(
        status_code(c) == "403",
        format!(
            "CONNECT other.conformance.test:443: expected 403, got {:?}",
            first_line(c)
        ),
    )?;
    leg_denied(
        s1,
        "a07.connect",
        "explicit-connect",
        "other.conformance.test is not in the policy allow list",
    )?;
    Ok("non-allowed name: NXDOMAIN and CONNECT 403".to_owned())
}

fn a08(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    answered_ctl(s1, "a08.pypi")?;
    let d = op(s1, "a08.dns")?;
    need(
        rcode(d) == 3,
        format!("dns notpypi.org: expected rcode 3, got {}", rcode(d)),
    )?;
    let c = op(s1, "a08.connect")?;
    need(
        status_code(c) == "403",
        format!(
            "CONNECT notpypi.org:443: expected 403, got {:?}",
            first_line(c)
        ),
    )?;
    leg_no_bytes(s1, "a08.hello")?;
    leg_denied(
        s1,
        "a08.hello",
        "transparent",
        "SNI notpypi.org does not match the DNS-map name pypi.org",
    )?;
    Ok("notpypi.org denied on DNS, CONNECT and SNI".to_owned())
}

fn a09(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    answered_ctl(s1, "a08.pypi")?;
    for (dns_id, connect_id, hello_id, name) in [
        ("a09.evil", "a09.connect", "a09.hello", "pypi.org.evil.com"),
        (
            "a09.idn",
            "a09.idnconnect",
            "a09.idnhello",
            "xn--pyp-lhd.org",
        ),
    ] {
        let d = op(s1, dns_id)?;
        need(
            rcode(d) == 3,
            format!("dns {name}: expected rcode 3, got {}", rcode(d)),
        )?;
        let c = op(s1, connect_id)?;
        need(
            status_code(c) == "403",
            format!("CONNECT {name}:443: expected 403, got {:?}", first_line(c)),
        )?;
        leg_no_bytes(s1, hello_id)?;
        leg_denied(
            s1,
            hello_id,
            "transparent",
            &format!("SNI {name} does not match the DNS-map name pypi.org"),
        )?;
    }
    Ok("pypi.org.evil.com and the IDN lookalike denied on DNS, CONNECT and SNI".to_owned())
}

fn a10(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let c = op(s1, "a10.connect")?;
    need(
        status_code(c) == "400",
        format!("CONNECT 9.9.9.9:443: expected 400, got {:?}", first_line(c)),
    )?;
    let g = op(s1, "a10.abs")?;
    need(
        status_code(g) == "400",
        format!("GET http://9.9.9.9/: expected 400, got {:?}", first_line(g)),
    )?;
    leg_no_bytes(s1, "a10.hello")?;
    leg_denied(
        s1,
        "a10.hello",
        "transparent",
        "unknown fake IP 1.1.1.1 (no DNS-map entry)",
    )?;
    Ok("IP literals denied on CONNECT, absolute-form and transparent paths".to_owned())
}

fn a11(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    answered_ctl(s1, "a01.a")?;
    leg_no_bytes(s1, "a11.hello")?;
    leg_denied(
        s1,
        "a11.hello",
        "transparent",
        "port 8443 is not in the policy port list",
    )?;
    let c = op(s1, "a11.connect")?;
    need(
        status_code(c) == "403",
        format!(
            "CONNECT allowed:8443: expected 403, got {:?}",
            first_line(c)
        ),
    )?;
    leg_denied(
        s1,
        "a11.connect",
        "explicit-connect",
        "port 8443 is not in the policy port list",
    )?;
    Ok("non-allowed port on an allowed name denied on both legs".to_owned())
}

fn b10(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let a10 = op(s1, "a10.abs").map_err(as_ctl)?;
    ctl(
        status_code(a10) == "400",
        "the forward-path control (A10 absolute-form) did not answer 400",
    )?;
    let abs = op(s1, "b10.abs")?;
    leg_denied(
        s1,
        "b10.abs",
        "explicit-forward",
        "HTTP Host other.conformance.test does not match the request-target name allowed.conformance.test",
    )?;
    need(
        status_code(abs) == "403",
        format!(
            "GET http://allowed + Host other: expected 403, got {:?}",
            first_line(abs)
        ),
    )?;
    let https = op(s1, "b10.https")?;
    need(
        status_code(https) == "400",
        format!(
            "GET https://allowed: expected 400, got {:?}",
            first_line(https)
        ),
    )?;
    let rev = op(s1, "b10.rev")?;
    need(
        status_code(rev) == "403",
        format!(
            "GET http://other + Host allowed: expected 403, got {:?}",
            first_line(rev)
        ),
    )?;
    leg_denied(
        s1,
        "b10.rev",
        "explicit-forward",
        "other.conformance.test is not in the policy allow list",
    )?;
    Ok("absolute-form Host mismatch 403 in both directions, with pinned reasons; https:// target 400".to_owned())
}

// ---------------------------------------------------------------- group C

fn c01(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let l = op(s1, "c01.links")?;
    let names: Vec<String> = l.data["names"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    need(
        names == ["lo"],
        format!("network links: expected [\"lo\"], got {names:?}"),
    )?;
    Ok("only lo in the sandbox network namespace".to_owned())
}

fn c03(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    leg_no_bytes(s1, "c03.tcp")?;
    leg_denied(
        s1,
        "c03.tcp",
        "transparent",
        "port 22 is not in the policy port list",
    )?;
    Ok("direct TCP to port 22 denied".to_owned())
}

fn c04(s: &Scns) -> R {
    let s2 = sc(s, "S2").map_err(as_ctl)?;
    let c = op(s2, "c04.connect").map_err(as_ctl)?;
    ctl(
        status_code(c) == "403",
        "the explicit proxy is not up in the fallback run",
    )?;
    let s3 = sc(s, "S3")?;
    let t = op(s2, "c04.tcp")?;
    need(
        errno(t) == Some(libc::ENETUNREACH),
        format!(
            "explicit fallback TCP 203.0.113.7:443: expected ENETUNREACH, got {}",
            errno_name(errno(t))
        ),
    )?;
    let d = op(s3, "a01.none")?;
    need(
        rcode(d) == 3,
        format!(
            "mode none dns allowed.conformance.test: expected rcode 3, got {}",
            rcode(d)
        ),
    )?;
    Ok("explicit fallback has no route; mode none answers NXDOMAIN".to_owned())
}

fn c05(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    for id in ["c05.u123", "c05.u443"] {
        let u = op(s1, id)?;
        need(
            u.errno == Some(libc::EPERM),
            format!(
                "UDP {id}: expected EPERM on send, got {}",
                errno_name(u.errno)
            ),
        )?;
    }
    Ok("UDP to ports other than 53 fails with EPERM".to_owned())
}

fn c06(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let a8 = op(s1, "c06.a8")?;
    need(
        rcode(a8) == 0 && a_ips(a8).len() == 1 && in_fake_range(a_ips(a8)[0]),
        format!(
            "UDP/53 via 8.8.8.8: allowed name expected a fake IP, got rcode {}",
            rcode(a8)
        ),
    )?;
    let o8 = op(s1, "c06.other8")?;
    need(
        rcode(o8) == 3,
        format!(
            "UDP/53 via 8.8.8.8: other name expected rcode 3, got {}",
            rcode(o8)
        ),
    )?;
    let a1 = op(s1, "c06.a1")?;
    need(
        rcode(a1) == 0 && a_ips(a1).len() == 1 && in_fake_range(a_ips(a1)[0]),
        format!(
            "UDP/53 via 1.1.1.1: allowed name expected a fake IP, got rcode {}",
            rcode(a1)
        ),
    )?;
    Ok("UDP/53 to any resolver answered by the fake DNS".to_owned())
}

fn c08(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    leg_no_bytes(s1, "c08.dns_tcp")?;
    leg_denied(
        s1,
        "c08.dns_tcp",
        "transparent",
        "port 53 is not in the policy port list",
    )?;
    leg_no_bytes(s1, "c08.tcp853")?;
    leg_denied(
        s1,
        "c08.tcp853",
        "transparent",
        "port 853 is not in the policy port list",
    )?;
    Ok("DNS over TCP/53 and DoT/853 denied".to_owned())
}

fn c09(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    for id in ["c09.v6", "c09.v6lo"] {
        let r = op(s1, id)?;
        need(
            !connected(r) && errno(r).is_some() && errno(r) != Some(libc::ETIMEDOUT),
            format!(
                "{id}: expected a non-timeout refusal with an errno, got connected={} {}",
                connected(r),
                errno_name(errno(r))
            ),
        )?;
    }
    let links = op(s1, "c01.links")?;
    let dis = links.data["disable_ipv6"].as_str();
    need(
        dis.is_none() || dis == Some("1"),
        format!("disable_ipv6: expected 1 or absent, got {dis:?}"),
    )?;
    Ok("IPv6 unusable inside the sandbox".to_owned())
}

fn c10(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    socket_fails(s1, "c10.raw4", None)?;
    socket_fails(s1, "c10.raw6", None)?;
    Ok("raw IP sockets cannot be created".to_owned())
}

fn c11(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    socket_fails(s1, "c11.packet", Some(libc::EAFNOSUPPORT))?;
    socket_fails(s1, "c11.xdp", Some(libc::EAFNOSUPPORT))?;
    Ok("AF_PACKET and AF_XDP sockets cannot be created".to_owned())
}

fn c12(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    socket_fails(s1, "c12.icmp", None)?;
    Ok("ICMP ping sockets cannot be created".to_owned())
}

fn c13(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    let d = op(s1, "c13.dump").map_err(as_ctl)?;
    let names: Vec<String> = d.data["names"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ctl(
        d.ok && names.iter().any(|n| n == "lo"),
        "netlink dump_links did not list lo",
    )?;
    for id in ["c13.lo_down", "c13.addr", "c13.route"] {
        let r = op(s1, id)?;
        need(
            errno(r) == Some(libc::EPERM),
            format!("netlink {id}: expected EPERM, got {}", errno_name(errno(r))),
        )?;
    }
    Ok("netlink link, address and route changes fail with EPERM".to_owned())
}

fn c14(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    socket_fails(s1, "c14.vs_stream", Some(libc::EAFNOSUPPORT))?;
    socket_fails(s1, "c14.vs_seq", Some(libc::EAFNOSUPPORT))?;
    Ok("AF_VSOCK sockets cannot be created".to_owned())
}

// ---------------------------------------------------------------- group D

fn d01(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    ctl_key(s1, "d01.own").map_err(|f| ctl_fail(f.msg))?;
    let before = s1
        .nums
        .get("d01.before")
        .copied()
        .ok_or_else(|| ctl_fail("no accept baseline recorded"))?;
    let after = s1
        .nums
        .get("d01.after")
        .copied()
        .ok_or_else(|| ctl_fail("no accept count recorded"))?;
    let t = op(s1, "d01.tcp")?;
    need(
        errno(t) == Some(libc::ECONNREFUSED) && !connected(t),
        format!(
            "TCP 127.0.0.1:P: expected ECONNREFUSED, got {}",
            errno_name(errno(t))
        ),
    )?;
    need(
        after == before,
        format!(
            "runner listener saw {} accepts from the sandbox",
            after.saturating_sub(before)
        ),
    )?;
    Ok("host 127.0.0.1 TCP services unreachable".to_owned())
}

/// The loopback denial texts for the given resolved addresses: one per address
/// the egress guard refuses as loopback, built by the product's own builders
/// (`proxy::Rejected::DialDenied` over `egress::guard`), so no text is retyped.
pub fn loopback_reasons(addrs: &[std::net::SocketAddr]) -> Vec<String> {
    use crate::egress::{Denied, guard};
    use crate::proxy::Rejected;
    addrs
        .iter()
        .filter_map(|a| match guard(a.ip()) {
            Err(denied) if denied == Denied::Loopback => {
                Some(Rejected::DialDenied { addr: *a, denied }.reason())
            }
            _ => None,
        })
        .collect()
}

/// What `localhost:443` resolves to on this host, in resolver order.
pub fn localhost_addrs() -> Vec<std::net::SocketAddr> {
    std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 443))
        .map(|it| it.collect())
        .unwrap_or_default()
}

fn d02(s: &Scns) -> R {
    d02_with(s, &localhost_addrs())
}

/// D02 given the host's resolution of `localhost`. Any address that the guard
/// refuses as loopback is an accepted denial text: the proxy resolves the name
/// itself, and on a host whose /etc/hosts lists `::1 localhost` first the
/// denial names `[::1]:443` (review: the CI runner's /etc/hosts is that shape).
fn d02_with(s: &Scns, resolved: &[std::net::SocketAddr]) -> R {
    let s1 = sc(s, "S1")?;
    let reasons = loopback_reasons(resolved);
    ctl(
        !reasons.is_empty(),
        "localhost does not resolve to a loopback address on this host",
    )?;
    let c = op(s1, "d02.connect")?;
    need(
        status_code(c) == "400",
        format!("CONNECT 127.0.0.1:P: expected 400, got {:?}", first_line(c)),
    )?;
    let cl = op(s1, "d02.cnlo")?;
    need(
        status_code(cl) == "200",
        format!(
            "CONNECT localhost:443: expected 200, got {:?}",
            first_line(cl)
        ),
    )?;
    leg_denied_any(s1, "d02.cnlo", "explicit-connect", &reasons)?;
    let dns = op(s1, "d02.dns")?;
    need(
        rcode(dns) == 0 && a_ips(dns).len() == 1 && in_fake_range(a_ips(dns)[0]),
        format!(
            "dns localhost: expected a fake IP, got rcode {}",
            rcode(dns)
        ),
    )?;
    leg_no_bytes(s1, "d02.hello")?;
    leg_denied_any(s1, "d02.hello", "transparent", &reasons)?;
    Ok("host loopback unreachable through both proxies".to_owned())
}

fn d03(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    ctl_key(s1, "d03.own").map_err(|f| ctl_fail(f.msg))?;
    let r = op(s1, "d03.abs")?;
    need(
        errno(r) == Some(libc::ECONNREFUSED),
        format!(
            "abstract sbx-conf socket: expected ECONNREFUSED, got {}",
            errno_name(errno(r))
        ),
    )?;
    Ok("host abstract unix sockets unreachable".to_owned())
}

fn d04(s: &Scns) -> R {
    let s1 = sc(s, "S1")?;
    ctl_key(s1, "d04.own").map_err(|f| ctl_fail(f.msg))?;
    let r = op(s1, "d04.path")?;
    need(
        errno(r) == Some(libc::ENOENT),
        format!(
            "host pathname socket: expected ENOENT, got {}",
            errno_name(errno(r))
        ),
    )?;
    Ok("host pathname unix sockets outside the binds invisible".to_owned())
}

/// D05: `Ok(pass)`, `Ok(Err(warn))` for visible or non-exhaustive, `Err` for a broken control.
fn d05(s: &Scns) -> Result<R, F> {
    let s13 = sc(s, "S13")?;
    let w = op(s13, "d05.walk").map_err(as_ctl)?;
    let visited = w.data["visited"].as_u64().unwrap_or(0);
    ctl(
        visited > 100,
        format!("the socket walk visited only {visited} entries"),
    )?;
    let found: Vec<String> = w.data["found"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if !found.is_empty() {
        return Ok(Err(F {
            msg: format!(
                "{} socket file{} visible: {}",
                found.len(),
                if found.len() == 1 { "" } else { "s" },
                found.join(", ")
            ),
            ev: found,
            control: false,
        }));
    }
    if w.data["truncated"] == true {
        return Ok(Err(F {
            msg: format!(
                "the walk stopped at {visited} entries; no socket file found so far (not exhaustive)"
            ),
            ev: Vec::new(),
            control: false,
        }));
    }
    Ok(Ok(
        "no unix socket files visible inside the sandbox".to_owned()
    ))
}

fn d06(s: &Scns) -> R {
    let a = sc(s, "S11a")?;
    let b = sc(s, "S11b")?;
    let listen = op(a, "d.listen").map_err(as_ctl)?;
    let port = listen.data["port"].as_u64().unwrap_or(0);
    ctl(
        listen.ok && port != 0,
        "A did not report a bound listener port",
    )?;
    ctl_ok(a, "d.own")?;
    ctl(
        connected(op(a, "d.own").map_err(as_ctl)?),
        "A's own TCP connect to its listener did not connect",
    )?;
    let r = op(b, "d.btcp")?;
    need(
        r.data["resolved"].as_str() == Some(&format!("127.0.0.1:{port}")),
        format!(
            "B targeted {:?}, expected 127.0.0.1:{port}",
            r.data["resolved"]
        ),
    )?;
    need(
        errno(r) == Some(libc::ECONNREFUSED) && !connected(r),
        format!(
            "B TCP 127.0.0.1:{port} (A's listener): expected ECONNREFUSED, got {}",
            errno_name(errno(r))
        ),
    )?;
    Ok("concurrent session cannot reach another's 127.0.0.1 listener".to_owned())
}

fn d07(s: &Scns) -> R {
    let a = sc(s, "S11a")?;
    let b = sc(s, "S11b")?;
    ctl_ok(a, "d.abs").map_err(|f| ctl_fail(f.msg))?;
    ctl_ok(a, "d.ownabs").map_err(|f| ctl_fail(f.msg))?;
    let r = op(b, "d.babs")?;
    need(
        errno(r) == Some(libc::ECONNREFUSED),
        format!(
            "B abstract socket of A: expected ECONNREFUSED, got {}",
            errno_name(errno(r))
        ),
    )?;
    Ok("concurrent session cannot reach another's abstract socket".to_owned())
}

fn d08(s: &Scns) -> R {
    let a = sc(s, "S11a")?;
    let b = sc(s, "S11b")?;
    ctl_ok(a, "d.write").map_err(|f| ctl_fail(f.msg))?;
    ctl_key(a, "d.host-file")?;
    let read = op(a, "d.read").map_err(as_ctl)?;
    ctl(
        read.data["matched"]
            .as_array()
            .is_some_and(|m| !m.is_empty()),
        "A cannot read its own secret file",
    )?;
    let s1 = op(b, "d.bstat1")?;
    need(
        errno(s1) == Some(libc::ENOENT),
        format!(
            "B stat of A's session file: expected ENOENT, got {}",
            errno_name(errno(s1))
        ),
    )?;
    let s2 = op(b, "d.bstat2")?;
    need(
        errno(s2) == Some(libc::ENOENT),
        format!(
            "B stat of /work/a-secret: expected ENOENT, got {}",
            errno_name(errno(s2))
        ),
    )?;
    Ok("concurrent session cannot see another's files".to_owned())
}

fn d09(s: &Scns) -> R {
    let a = sc(s, "S11a")?;
    let b = sc(s, "S11b")?;
    let ip = a
        .notes
        .get("ip")
        .cloned()
        .ok_or_else(|| ctl_fail("A's fake IP was not recorded"))?;
    let dns = op(a, "d.dns").map_err(as_ctl)?;
    ctl(
        rcode(dns) == 0 && a_ips(dns).iter().any(|x| x.to_string() == ip),
        "A did not resolve a-only.allowed.conformance.test to its recorded fake IP",
    )?;
    let l = local(dns).map_err(as_ctl)?;
    ctl(
        dns_row(a, &l, "answered", "a-only.allowed.conformance.test"),
        "A has no audit answered row for its own query",
    )?;
    leg_no_bytes(b, "d.bfake")?;
    let bl = local(op(b, "d.bfake")?)?;
    if !denied(b, &bl, "transparent", &format!("unknown fake IP {ip}")) {
        return Err(F {
            msg: format!("B audit has no `unknown fake IP {ip}` row for its leg ({bl})"),
            ev: rows_for_client(b, &bl),
            control: false,
        });
    }
    Ok("another session's fake IP is unknown here".to_owned())
}

// ---------------------------------------------------------------- F, G

fn f01(s: &Scns) -> R {
    let s10 = sc(s, "S10")?;
    ctl_key(s10, "f01.seen")?;
    let fin = fin_of(s10)?;
    need(
        fin.signal == Some(libc::SIGKILL),
        format!(
            "sbx run exit: expected SIGKILL, got signal {:?}",
            fin.signal
        ),
    )?;
    assert_key(s10, "f01.gone")?;
    Ok("SIGKILL removes the whole sandbox process tree".to_owned())
}

fn f05(s: &Scns) -> R {
    let s4 = sc(s, "S4")?;
    let fin = fin_of(s4)?;
    need(
        fin.rc == Some(125),
        format!(
            "transparent policy with --test-break-rules: expected rc 125, got {:?}",
            fin.rc
        ),
    )?;
    need(
        fin.stderr.contains(
            "policy requires network mode transparent but this host provides only explicit",
        ),
        format!(
            "stderr lacks the refusal text: {:?}",
            fin.stderr.lines().next().unwrap_or("")
        ),
    )?;
    need(
        !fin.stdout.iter().any(|l| l.contains("\"id\":\"s4.hello\"")),
        "the probe ran despite the refusal",
    )?;
    Ok("nftables load failure under a transparent policy: rc 125".to_owned())
}

fn f06(s: &Scns) -> R {
    let s5 = sc(s, "S5")?;
    ctl(
        s5.nums.get("audit_bytes").copied().unwrap_or(0) >= 15000,
        "the audit file did not grow before the failure",
    )?;
    let fin = fin_of(s5)?;
    need(
        fin.rc == Some(125),
        format!("audit write failure: expected rc 125, got {:?}", fin.rc),
    )?;
    need(
        fin.stderr.contains("sbx run: audit log write failed:"),
        format!(
            "stderr lacks the audit failure: {:?}",
            fin.stderr.lines().next().unwrap_or("")
        ),
    )?;
    assert_key(s5, "f06.gone")?;
    Ok("audit write failure ends the run with rc 125".to_owned())
}

fn g01(s: &Scns) -> R {
    let s6 = sc(s, "S6")?;
    ctl_key(s6, "g01.seen")?;
    rc_is(s6, 0)?;
    assert_key(s6, "g01.gone")?;
    Ok("natural exit kills setsid'd background processes".to_owned())
}

fn g02(s: &Scns) -> R {
    let s7 = sc(s, "S7")?;
    ctl_key(s7, "g02.seen")?;
    rc_is(s7, 124)?;
    let fin = fin_of(s7)?;
    need(
        fin.elapsed_ms <= 5000,
        format!("timeout: sbx run took {} ms (bound 5000)", fin.elapsed_ms),
    )?;
    assert_key(s7, "g02.gone")?;
    Ok("timeout (rc 124) kills background processes".to_owned())
}

fn g03(s: &Scns) -> R {
    for (name, rc) in [("S8a", 143), ("S8b", 130), ("S8c", 129)] {
        let scn = sc(s, name)?;
        ctl_key(scn, "g03.seen")?;
        rc_is(scn, rc)?;
        assert_key(scn, "g03.gone")?;
    }
    Ok("SIGTERM, SIGINT and SIGHUP kill background processes".to_owned())
}

fn g04(s: &Scns) -> R {
    let s9 = sc(s, "S9")?;
    ctl_key(s9, "g04.seen")?;
    rc_is(s9, 0)?;
    let fin = fin_of(s9)?;
    need(
        fin.elapsed_ms <= 5000,
        format!(
            "stdout holder: sbx run took {} ms (bound 5000)",
            fin.elapsed_ms
        ),
    )?;
    assert_key(s9, "g04.gone")?;
    Ok("a background process holding stdout does not keep sbx alive".to_owned())
}

fn g05(s: &Scns) -> R {
    let s6 = sc(s, "S6")?;
    let s6b = sc(s, "S6b")?;
    // The netns inode is a control: without it the membership check has no subject.
    s6.notes
        .get("netns")
        .ok_or_else(|| ctl_fail("the sandbox netns inode was not recorded while alive"))?;
    // Evidence recorded before cleanup (a kill before this check hid the members).
    assert_key(s6, "netns-after-exit")?;
    rc_is(s6b, 0)?;
    Ok("the sandbox netns is empty after exit; the session is reusable".to_owned())
}

// ---------------------------------------------------------------- H, D10

fn env_matched(s12: &Scn) -> Result<(&OpResult, Vec<i64>), F> {
    let r = op(s12, "h01.env")?;
    let matched: Vec<i64> = r.data["matched"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default();
    Ok((r, matched))
}

fn h01(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let (_, matched) = env_matched(s12).map_err(as_ctl)?;
    ctl(
        matched.contains(&1),
        "the passed SBX_CONFORMANCE_PASSED value did not reach the payload",
    )?;
    need(
        !matched.contains(&0),
        "the caller's SBX_CONFORMANCE_SECRET reached the payload environment",
    )?;
    Ok("the caller's environment is not visible to the payload".to_owned())
}

fn h02(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let me = op(s12, "h02.self").map_err(as_ctl)?;
    ctl(
        me.data["len"].as_u64().unwrap_or(0) > 0,
        "control: /proc/self/environ is empty",
    )?;
    let pid1 = op(s12, "h02.environ")?;
    need(
        pid1.data["len"].as_u64() == Some(0) || pid1.errno.is_some(),
        format!(
            "/proc/1/environ: expected empty, got {} bytes",
            pid1.data["len"]
        ),
    )?;
    Ok("/proc/1/environ is empty".to_owned())
}

fn h03(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let r = op(s12, "h03.scan").map_err(as_ctl)?;
    ctl(
        r.data["readable"].as_u64().unwrap_or(0) >= 2,
        "fewer than two /proc/*/environ files were readable",
    )?;
    let matched = r.data["matched_pids"].as_array().map(Vec::len).unwrap_or(0);
    need(
        matched == 0,
        format!("{matched} /proc/*/environ files contain the caller's secret"),
    )?;
    Ok("no /proc/*/environ contains the caller's secret".to_owned())
}

fn h04(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let (r, _) = env_matched(s12)?;
    let names: Vec<String> = r.data["names"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    // PWD: bubblewrap 0.9.0 sets it for the working directory (bwrap/mod.rs point 4).
    let mut want: Vec<String> = [
        "HOME",
        "PATH",
        "TMPDIR",
        "PWD",
        "SBX_CONFORMANCE_PASSED",
        "SBX_CONFORMANCE_SET",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    want.extend(super::scenarios::PROXY_VARS.iter().map(|s| (*s).to_owned()));
    want.sort();
    let mut got = names.clone();
    got.sort();
    need(
        got == want,
        format!("payload environment: expected {want:?}, got {got:?}"),
    )?;
    let path = r.data["values"]["PATH"].as_str().unwrap_or("");
    need(
        path == crate::bwrap::infra_path(),
        format!("PATH: expected the pinned infra PATH, got {path:?}"),
    )?;
    let home = r.data["values"]["HOME"].as_str().unwrap_or("");
    need(
        home == "/root",
        format!("HOME: expected /root, got {home:?}"),
    )?;
    let tmp = r.data["values"]["TMPDIR"].as_str().unwrap_or("");
    need(tmp == "/tmp", format!("TMPDIR: expected /tmp, got {tmp:?}"))?;
    Ok("the payload environment is the policy plus infra".to_owned())
}

fn h05(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    ctl_key(s12, "fd-cloexec-cleared")?;
    let r = op(s12, "h05.fds")?;
    let fds: Vec<i64> = r.data["fds"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default();
    need(
        fds == [0, 1, 2],
        format!("payload descriptors: expected [0, 1, 2], got {fds:?}"),
    )?;
    Ok("inherited non-CLOEXEC descriptors do not reach the payload".to_owned())
}

fn h06(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let home = s12.notes.get("host_home").cloned().unwrap_or_default();
    let host = std::fs::symlink_metadata(&home).is_ok();
    ctl(host, format!("the host cannot stat its own HOME {home}"))?;
    let a = op(s12, "h06.home")?;
    need(
        errno(a) == Some(libc::ENOENT),
        format!("stat $HOME: expected ENOENT, got {}", errno_name(errno(a))),
    )?;
    let b = op(s12, "h06.ssh")?;
    need(
        errno(b) == Some(libc::ENOENT),
        format!(
            "stat $HOME/.ssh: expected ENOENT, got {}",
            errno_name(errno(b))
        ),
    )?;
    let cmd = op(s12, "d10.cmdline")?;
    let matched = cmd.data["matched"].as_array().map(Vec::len).unwrap_or(0);
    need(
        matched == 0,
        "the runner's command line (--conformance) is readable from the sandbox",
    )?;
    Ok("the caller's HOME and processes are invisible".to_owned())
}

fn d10(s: &Scns) -> R {
    let s12 = sc(s, "S12")?;
    let p = op(s12, "d10.procs")?;
    let pids = p.data["pids"].as_array().map(Vec::len).unwrap_or(99);
    need(pids <= 8, format!("{pids} processes visible (bound 8)"))?;
    let comm = p.data["pid1_comm"].as_str().unwrap_or("");
    need(
        comm == "bwrap",
        format!("pid 1 comm: expected bwrap, got {comm:?}"),
    )?;
    let caps = op(s12, "d10.caps")?;
    for (key, label) in [("eff", "Eff"), ("prm", "Prm"), ("bnd", "Bnd")] {
        let v = caps.data[key].as_str().unwrap_or("?");
        need(
            v == "0000000000000000",
            format!("payload Cap{label} is {v}: expected no capabilities (--cap-drop ALL)"),
        )?;
    }
    let un = op(s12, "d10.unshare")?;
    need(
        errno(un) == Some(libc::ENOSPC) || errno(un) == Some(libc::EPERM),
        format!(
            "unshare user: expected ENOSPC or EPERM, got {}",
            errno_name(errno(un))
        ),
    )?;
    Ok("host processes invisible; nested user namespaces fail".to_owned())
}

/// Evaluate one host-tier check into a result.
pub fn evaluate(id: &str, s: &Scns) -> CheckResult {
    if id == "H06"
        && s.get("S12")
            .and_then(|x| x.notes.get("home_applicable"))
            .map(String::as_str)
            == Some("false")
    {
        // Not a pass and not an opt-in: H06 could not be set up on this host.
        return CheckResult::skip(
            id,
            SkipKind::Capability,
            "cannot test: HOME is unset or lies under /root, /work, /tmp, /usr, /etc, /proc or /dev; run with HOME outside those",
        );
    }
    let outcome: Result<R, F> = match id {
        "D05" => d05(s),
        _ => Ok(eval_plain(id, s)),
    };
    match outcome {
        Ok(Ok(text)) => CheckResult::new(id, Status::Ok, text),
        Ok(Err(f)) if id == "D05" => {
            let mut r = CheckResult::new(id, Status::Warn, f.msg).with_evidence(f.ev);
            r.fix = Some("socket files under ro/rw binds stay connectable (MS_RDONLY does not block connect); keep /run, /var/run and /tmp out of policies (#35)".to_owned());
            r
        }
        Ok(Err(f)) => fail_result(id, f),
        Err(f) => fail_result(id, f),
    }
}

fn fail_result(id: &str, f: F) -> CheckResult {
    CheckResult::new(id, Status::Fail, f.msg).with_evidence(f.ev)
}

fn eval_plain(id: &str, s: &Scns) -> R {
    match id {
        "A01" => a01(s),
        "A07" => a07(s),
        "A08" => a08(s),
        "A09" => a09(s),
        "A10" => a10(s),
        "A11" => a11(s),
        "B10" => b10(s),
        "C01" => c01(s),
        "C03" => c03(s),
        "C04" => c04(s),
        "C05" => c05(s),
        "C06" => c06(s),
        "C08" => c08(s),
        "C09" => c09(s),
        "C10" => c10(s),
        "C11" => c11(s),
        "C12" => c12(s),
        "C13" => c13(s),
        "C14" => c14(s),
        "D01" => d01(s),
        "D02" => d02(s),
        "D03" => d03(s),
        "D04" => d04(s),
        "D06" => d06(s),
        "D07" => d07(s),
        "D08" => d08(s),
        "D09" => d09(s),
        "D10" => d10(s),
        "F01" => f01(s),
        "F05" => f05(s),
        "F06" => f06(s),
        "G01" => g01(s),
        "G02" => g02(s),
        "G03" => g03(s),
        "G04" => g04(s),
        "G05" => g05(s),
        "H01" => h01(s),
        "H02" => h02(s),
        "H03" => h03(s),
        "H04" => h04(s),
        "H05" => h05(s),
        "H06" => h06(s),
        _ => Err(fail(format!("no evaluator for {id}"))),
    }
}

#[cfg(test)]
mod tests;
