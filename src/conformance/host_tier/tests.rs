//! Table-driven evaluator tests (review M3): for every implemented host check,
//! the good evidence passes, a broken assertion FAILs, and a broken control
//! FAILs as `control failed`. Audit legs are pinned: a row that exists only for
//! the other leg must not satisfy the check.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Scns, evaluate};
use crate::conformance::probe::{OpResult, ProbeOutput};
use crate::conformance::scenarios::Scn;
use crate::conformance::spawn::Finished;
use crate::host::Status;

const TRANS: &str = "10.255.255.1";

fn op(id: &str, ok: bool, errno: Option<i32>, data: Value) -> OpResult {
    OpResult {
        id: id.to_owned(),
        op: "x".into(),
        t_ms: 0,
        ok,
        errno,
        detail: String::new(),
        data,
    }
}

fn tcp(id: &str, local: &str, connected: bool, reads: Value) -> OpResult {
    op(
        id,
        connected,
        None,
        json!({"connected": connected, "resolved": null, "local_addr": local, "reads": reads, "write_errno": null}),
    )
}

fn none_read() -> Value {
    json!([{"len": 0, "text": "", "end": "eof"}])
}

fn reply(text: &str) -> Value {
    json!([{"len": text.len(), "text": text, "end": "data"}])
}

fn dns(id: &str, local: &str, rcode: i64, a: &[&str]) -> OpResult {
    op(
        id,
        true,
        None,
        json!({"rcode": rcode, "a": a, "answers": a.len(), "local_addr": local}),
    )
}

fn deny(client: &str, via: &str, reason: &str) -> Value {
    json!({"event": "deny", "client": client, "via": via, "reason": reason, "verdict": "denied"})
}

fn answered(client: &str, host: &str) -> Value {
    json!({"event": "dns", "client": client, "host": host, "verdict": "answered", "reason": format!("answered {host} A")})
}

fn denied_dns(client: &str, reason: &str) -> Value {
    json!({"event": "dns", "client": client, "verdict": "denied", "reason": reason})
}

fn scn(name: &'static str, ops: Vec<OpResult>, audit: Vec<Value>) -> Scn {
    let results: BTreeMap<String, OpResult> = ops.into_iter().map(|r| (r.id.clone(), r)).collect();
    Scn {
        name,
        probe: Some(ProbeOutput {
            pid: 1,
            results,
            done: true,
        }),
        audit,
        ..Default::default()
    }
}

fn fin(rc: Option<i32>, stderr: &str, stdout: Vec<String>, ms: u64) -> Finished {
    Finished {
        rc,
        signal: None,
        stdout,
        stderr: stderr.to_owned(),
        elapsed_ms: ms,
    }
}

/// Passing S1 evidence (transparent) with one client port per leg.
fn s1() -> Scn {
    let x = |n: u32| format!("127.0.0.1:{}", 50000 + n);
    let t = |n: u32| format!("{TRANS}:{}", 50000 + n);
    let ops = vec![
        dns("a01.a", &x(1), 0, &["198.18.0.1"]),
        dns("a01.aaaa", &x(2), 0, &[]),
        dns("a07.dns", &x(30), 3, &[]),
        tcp(
            "a07.connect",
            &x(3),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        dns("a08.dns", &x(31), 3, &[]),
        dns("a08.pypi", &x(32), 0, &["198.18.0.2"]),
        tcp(
            "a08.connect",
            &x(4),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        tcp("a08.hello", &t(5), true, none_read()),
        dns("a09.evil", &x(33), 3, &[]),
        dns("a09.idn", &x(34), 3, &[]),
        tcp(
            "a09.connect",
            &x(6),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        tcp(
            "a09.idnconnect",
            &x(7),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        tcp("a09.hello", &t(8), true, none_read()),
        tcp("a09.idnhello", &t(9), true, none_read()),
        tcp(
            "a10.connect",
            &x(10),
            true,
            reply("HTTP/1.1 400 Bad Request\r\n\r\n"),
        ),
        tcp(
            "a10.abs",
            &x(11),
            true,
            reply("HTTP/1.1 400 Bad Request\r\n\r\n"),
        ),
        tcp("a10.hello", &t(12), true, none_read()),
        tcp("a11.hello", &t(13), true, none_read()),
        tcp(
            "a11.connect",
            &x(14),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        tcp(
            "b10.abs",
            &x(15),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        tcp(
            "b10.https",
            &x(16),
            true,
            reply("HTTP/1.1 400 Bad Request\r\n\r\n"),
        ),
        tcp(
            "b10.rev",
            &x(18),
            true,
            reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
        ),
        op(
            "c01.links",
            true,
            None,
            json!({"names": ["lo"], "disable_ipv6": "1"}),
        ),
        tcp("c03.tcp", &t(17), true, none_read()),
        op(
            "c05.u123",
            false,
            Some(libc::EPERM),
            json!({"send_errno": libc::EPERM}),
        ),
        op(
            "c05.u443",
            false,
            Some(libc::EPERM),
            json!({"send_errno": libc::EPERM}),
        ),
        dns("c06.a8", &x(40), 0, &["198.18.0.3"]),
        dns("c06.other8", &x(41), 3, &[]),
        dns("c06.a1", &x(42), 0, &["198.18.0.4"]),
        tcp("c08.dns_tcp", &t(18), true, none_read()),
        tcp("c08.tcp853", &t(19), true, none_read()),
        op(
            "c09.v6",
            false,
            Some(libc::ENETUNREACH),
            json!({"connected": false, "local_addr": null, "reads": []}),
        ),
        op(
            "c09.v6lo",
            false,
            Some(libc::ENETUNREACH),
            json!({"connected": false, "local_addr": null, "reads": []}),
        ),
        op(
            "c10.raw4",
            false,
            Some(libc::EPERM),
            json!({"created": false}),
        ),
        op(
            "c10.raw6",
            false,
            Some(libc::EPERM),
            json!({"created": false}),
        ),
        op(
            "c11.packet",
            false,
            Some(libc::EAFNOSUPPORT),
            json!({"created": false}),
        ),
        op(
            "c11.xdp",
            false,
            Some(libc::EAFNOSUPPORT),
            json!({"created": false}),
        ),
        op(
            "c12.icmp",
            false,
            Some(libc::EPERM),
            json!({"created": false}),
        ),
        op("c13.lo_down", false, Some(libc::EPERM), json!({})),
        op("c13.addr", false, Some(libc::EPERM), json!({})),
        op("c13.route", false, Some(libc::EPERM), json!({})),
        op("c13.dump", true, None, json!({"names": ["lo"]})),
        op(
            "c14.vs_stream",
            false,
            Some(libc::EAFNOSUPPORT),
            json!({"created": false}),
        ),
        op(
            "c14.vs_seq",
            false,
            Some(libc::EAFNOSUPPORT),
            json!({"created": false}),
        ),
        op(
            "d01.tcp",
            false,
            Some(libc::ECONNREFUSED),
            json!({"connected": false}),
        ),
        dns("d02.dns", &x(50), 0, &["198.18.0.5"]),
        tcp(
            "d02.connect",
            &x(51),
            true,
            reply("HTTP/1.1 400 Bad Request\r\n\r\n"),
        ),
        tcp(
            "d02.cnlo",
            &x(52),
            true,
            reply("HTTP/1.1 200 Connection established\r\n\r\n"),
        ),
        tcp("d02.hello", &t(53), true, none_read()),
        op("d03.abs", false, Some(libc::ECONNREFUSED), json!({})),
        op("d04.path", false, Some(libc::ENOENT), json!({})),
        op("d.listen", true, None, json!({"port": 40000})),
    ];
    let mut s = scn(
        "S1",
        ops,
        vec![
            answered("127.0.0.1:50001", "allowed.conformance.test"),
            deny(
                "127.0.0.1:50015",
                "explicit-forward",
                "HTTP Host other.conformance.test does not match the request-target name allowed.conformance.test",
            ),
            deny(
                "127.0.0.1:50018",
                "explicit-forward",
                "other.conformance.test is not in the policy allow list",
            ),
            denied_dns(
                "127.0.0.1:50030",
                "other.conformance.test is not in the policy allow list",
            ),
            deny(
                "127.0.0.1:50003",
                "explicit-connect",
                "other.conformance.test is not in the policy allow list",
            ),
            deny(
                "127.0.0.1:50004",
                "explicit-connect",
                "notpypi.org is not in the policy allow list",
            ),
            deny(
                &format!("{TRANS}:50005"),
                "transparent",
                "SNI notpypi.org does not match the DNS-map name pypi.org",
            ),
            deny(
                &format!("{TRANS}:50008"),
                "transparent",
                "SNI pypi.org.evil.com does not match the DNS-map name pypi.org",
            ),
            deny(
                &format!("{TRANS}:50009"),
                "transparent",
                "SNI xn--pyp-lhd.org does not match the DNS-map name pypi.org",
            ),
            deny(
                "127.0.0.1:50006",
                "explicit-connect",
                "pypi.org.evil.com is not in the policy allow list",
            ),
            deny(
                "127.0.0.1:50007",
                "explicit-connect",
                "xn--pyp-lhd.org is not in the policy allow list",
            ),
            deny(
                &format!("{TRANS}:50012"),
                "transparent",
                "unknown fake IP 1.1.1.1 (no DNS-map entry)",
            ),
            deny(
                &format!("{TRANS}:50013"),
                "transparent",
                "port 8443 is not in the policy port list",
            ),
            deny(
                "127.0.0.1:50014",
                "explicit-connect",
                "port 8443 is not in the policy port list",
            ),
            deny(
                &format!("{TRANS}:50017"),
                "transparent",
                "port 22 is not in the policy port list",
            ),
            deny(
                &format!("{TRANS}:50018"),
                "transparent",
                "port 53 is not in the policy port list",
            ),
            deny(
                &format!("{TRANS}:50019"),
                "transparent",
                "port 853 is not in the policy port list",
            ),
            deny("127.0.0.1:50052", "explicit-connect", &d02_reason()),
            deny(&format!("{TRANS}:50053"), "transparent", &d02_reason()),
        ],
    );
    s.ctl.insert("d01.own", Ok(()));
    s.ctl.insert("d03.own", Ok(()));
    s.ctl.insert("d04.own", Ok(()));
    s.nums.insert("d01.before", 1);
    s.nums.insert("d01.after", 1);
    s
}

fn s13() -> Scn {
    let mut s = scn(
        "S13",
        vec![op(
            "d05.walk",
            true,
            None,
            json!({"found": [], "visited": 500, "truncated": false}),
        )],
        vec![],
    );
    s.name = "S13";
    s
}

fn s2() -> Scn {
    let mut s = scn(
        "S2",
        vec![
            op("s2.hello", true, None, json!({})),
            op(
                "c04.tcp",
                false,
                Some(libc::ENETUNREACH),
                json!({"connected": false}),
            ),
            tcp(
                "c04.connect",
                "127.0.0.1:60",
                true,
                reply("HTTP/1.1 403 Forbidden\r\n\r\n"),
            ),
        ],
        vec![],
    );
    s.name = "S2";
    s
}

fn s3() -> Scn {
    scn("S3", vec![dns("a01.none", "127.0.0.1:61", 3, &[])], vec![])
}

fn s4() -> Scn {
    let mut s = scn("S4", vec![], vec![]);
    s.name = "S4";
    s.fin = Some(fin(
        Some(125),
        "sbx run: policy requires network mode transparent but this host provides only explicit: x",
        vec![],
        20,
    ));
    s
}

fn s5() -> Scn {
    let mut s = scn("S5", vec![], vec![]);
    s.name = "S5";
    s.nums.insert("audit_bytes", 20000);
    s.ctl.insert("f06.gone", Ok(()));
    s.fin = Some(fin(
        Some(125),
        "sbx run: audit log write failed: No space left",
        vec![],
        80,
    ));
    s
}

fn s6(name: &'static str) -> Scn {
    let mut s = scn(name, vec![], vec![]);
    s.name = name;
    if name == "S6" {
        s.ctl.insert("g01.seen", Ok(()));
        s.ctl.insert("g01.gone", Ok(()));
        s.ctl.insert("netns-after-exit", Ok(()));
        s.notes.insert("netns", "net:[4026532309]".to_owned());
    }
    s.fin = Some(fin(Some(0), "", vec![], 30));
    s
}

fn timed(name: &'static str, rc: i32, ms: u64, key: &str) -> Scn {
    let mut s = scn(name, vec![], vec![]);
    s.name = name;
    s.ctl.insert(
        match key {
            "g02" => "g02.seen",
            "g04" => "g04.seen",
            "f01" => "f01.seen",
            _ => "g03.seen",
        },
        Ok(()),
    );
    s.ctl.insert(
        match key {
            "g02" => "g02.gone",
            "g04" => "g04.gone",
            "f01" => "f01.gone",
            _ => "g03.gone",
        },
        Ok(()),
    );
    s.fin = Some(fin(Some(rc), "", vec![], ms));
    s
}

fn s10() -> Scn {
    let mut s = scn("S10", vec![], vec![]);
    s.name = "S10";
    s.ctl.insert("f01.seen", Ok(()));
    s.ctl.insert("f01.gone", Ok(()));
    s.notes.insert("netns", "net:[4026532309]".to_owned());
    s.fin = Some(Finished {
        rc: None,
        signal: Some(libc::SIGKILL),
        stdout: vec![],
        stderr: String::new(),
        elapsed_ms: 40,
    });
    s
}

fn s11a() -> Scn {
    let mut a = scn(
        "S11a",
        vec![
            op("d.listen", true, None, json!({"port": 40000})),
            op("d.abs", true, None, json!({})),
            op("d.write", true, None, json!({})),
            op("d.read", true, None, json!({"len": 20, "matched": [0]})),
            tcp("d.own", "127.0.0.1:40001", true, json!([])),
            op("d.ownabs", true, None, json!({})),
            dns("d.dns", "127.0.0.1:40100", 0, &["198.18.0.5"]),
        ],
        vec![answered(
            "127.0.0.1:40100",
            "a-only.allowed.conformance.test",
        )],
    );
    a.notes.insert("ip", "198.18.0.5".to_owned());
    a.ctl.insert("d.host-file", Ok(()));
    a.notes.insert("port", "40000".to_owned());
    a
}

fn s11b() -> Scn {
    let mut b = scn(
        "S11b",
        vec![
            op(
                "d.btcp",
                false,
                Some(libc::ECONNREFUSED),
                json!({"connected": false, "resolved": "127.0.0.1:40000", "local_addr": null, "reads": []}),
            ),
            op("d.babs", false, Some(libc::ECONNREFUSED), json!({})),
            op("d.bstat1", false, Some(libc::ENOENT), json!({})),
            op("d.bstat2", false, Some(libc::ENOENT), json!({})),
            tcp("d.bfake", &format!("{TRANS}:40200"), true, none_read()),
        ],
        vec![deny(
            &format!("{TRANS}:40200"),
            "transparent",
            "unknown fake IP 198.18.0.5 (no DNS-map entry)",
        )],
    );
    b.name = "S11b";
    b
}

fn s12() -> Scn {
    let names = [
        "HOME",
        "PATH",
        "TMPDIR",
        "PWD",
        "SBX_CONFORMANCE_PASSED",
        "SBX_CONFORMANCE_SET",
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ];
    let values = json!({"PATH": crate::bwrap::infra_path(), "HOME": "/root", "TMPDIR": "/tmp"});
    let mut s = scn(
        "S12",
        vec![
            op(
                "h01.env",
                true,
                None,
                json!({"names": names, "matched": [1], "values": values}),
            ),
            op("h02.environ", true, None, json!({"len": 0})),
            op("h02.self", true, None, json!({"len": 120})),
            op(
                "h03.scan",
                true,
                None,
                json!({"readable": 3, "unreadable": 0, "matched_pids": []}),
            ),
            op("h05.fds", true, None, json!({"fds": [0, 1, 2]})),
            op("h06.home", false, Some(libc::ENOENT), json!({})),
            op("h06.ssh", false, Some(libc::ENOENT), json!({})),
            op(
                "d10.cmdline",
                false,
                Some(libc::ENOENT),
                json!({"len": 0, "matched": []}),
            ),
            op(
                "d10.procs",
                true,
                None,
                json!({"pids": [1, 2, 3], "pid1_comm": "bwrap", "self_pid": 3}),
            ),
            op("d10.unshare", false, Some(libc::ENOSPC), json!({})),
            op(
                "d10.caps",
                true,
                None,
                json!({"eff": "0000000000000000", "prm": "0000000000000000", "bnd": "0000000000000000"}),
            ),
        ],
        vec![],
    );
    s.name = "S12";
    s.ctl.insert("fd-cloexec-cleared", Ok(()));
    s.notes.insert("home_applicable", "true".to_owned());
    // The host HOME must exist for the control: /usr is a stand-in.
    s.notes.insert("host_home", "/usr".to_owned());
    s
}

/// A complete, passing evidence set for every host scenario.
pub fn good() -> Scns {
    let mut m: Scns = BTreeMap::new();
    m.insert("S1", s1());
    m.insert("S2", s2());
    m.insert("S3", s3());
    m.insert("S4", s4());
    m.insert("S5", s5());
    m.insert("S6", s6("S6"));
    m.insert("S6b", s6("S6b"));
    m.insert("S7", timed("S7", 124, 1200, "g02"));
    m.insert("S8a", timed("S8a", 143, 40, "g03"));
    m.insert("S8b", timed("S8b", 130, 40, "g03"));
    m.insert("S8c", timed("S8c", 129, 40, "g03"));
    m.insert("S9", timed("S9", 0, 600, "g04"));
    m.insert("S10", s10());
    m.insert("S11a", s11a());
    m.insert("S11b", s11b());
    m.insert("S12", s12());
    m.insert("S13", s13());
    m
}

fn s1_of(m: &mut Scns) -> &mut Scn {
    m.get_mut("S1").unwrap()
}

/// Break one thing: `control` breaks the check's control, otherwise its assertion.
fn bad(id: &str, control: bool) -> Option<Scns> {
    let mut m = good();
    macro_rules! edit {
        ($scn:expr, $id:expr, $f:expr) => {{
            let p = $scn.probe.as_mut().unwrap();
            let r = p.results.get_mut($id).unwrap();
            $f(r);
        }};
    }
    match (id, control) {
        ("A01", false) => edit!(s1_of(&mut m), "a01.a", |r: &mut OpResult| r.data["a"] =
            json!(["93.184.216.34"])),
        ("A01", _) => return None,
        ("A07", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != "127.0.0.1:50030"),
        ("A07", true) => edit!(s1_of(&mut m), "a01.a", |r: &mut OpResult| r.data["rcode"] =
            json!(3)),
        ("A08", false) => edit!(
            s1_of(&mut m),
            "a08.hello",
            |r: &mut OpResult| r.data["reads"] = reply("HELLO")
        ),
        ("A08", true) => edit!(
            s1_of(&mut m),
            "a08.pypi",
            |r: &mut OpResult| r.data["rcode"] = json!(3)
        ),
        ("A09", false) => s1_of(&mut m).audit.retain(|r| {
            r["reason"] != "SNI xn--pyp-lhd.org does not match the DNS-map name pypi.org"
        }),
        ("A09", true) => edit!(
            s1_of(&mut m),
            "a08.pypi",
            |r: &mut OpResult| r.data["rcode"] = json!(3)
        ),
        ("A10", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != format!("{TRANS}:50012")),
        ("A11", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != format!("{TRANS}:50013")),
        ("A11", true) => edit!(s1_of(&mut m), "a01.a", |r: &mut OpResult| r.data["rcode"] =
            json!(3)),
        ("B10", false) => edit!(
            s1_of(&mut m),
            "b10.abs",
            |r: &mut OpResult| r.data["reads"] = reply("HTTP/1.1 200 OK\r\n\r\n")
        ),
        ("B10", true) => edit!(
            s1_of(&mut m),
            "a10.abs",
            |r: &mut OpResult| r.data["reads"] = reply("HTTP/1.1 200 OK\r\n\r\n")
        ),
        ("C01", false) => edit!(
            s1_of(&mut m),
            "c01.links",
            |r: &mut OpResult| r.data["names"] = json!(["lo", "eth0"])
        ),
        ("C03", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != format!("{TRANS}:50017")),
        ("C04", false) => edit!(m.get_mut("S2").unwrap(), "c04.tcp", |r: &mut OpResult| r
            .errno =
            None),
        ("C04", true) => edit!(
            m.get_mut("S2").unwrap(),
            "c04.connect",
            |r: &mut OpResult| r.data["reads"] = reply("HTTP/1.1 200 OK\r\n\r\n")
        ),
        ("C05", false) => edit!(s1_of(&mut m), "c05.u123", |r: &mut OpResult| r.errno = None),
        ("C06", false) => edit!(
            s1_of(&mut m),
            "c06.a8",
            |r: &mut OpResult| r.data["rcode"] = json!(3)
        ),
        ("C08", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != format!("{TRANS}:50018")),
        ("C09", false) => edit!(s1_of(&mut m), "c09.v6", |r: &mut OpResult| r.errno = None),
        ("C10", false) => edit!(
            s1_of(&mut m),
            "c10.raw4",
            |r: &mut OpResult| r.data["created"] = json!(true)
        ),
        ("C11", false) => edit!(s1_of(&mut m), "c11.packet", |r: &mut OpResult| r.errno =
            Some(libc::EPERM)),
        ("C12", false) => edit!(
            s1_of(&mut m),
            "c12.icmp",
            |r: &mut OpResult| r.data["created"] = json!(true)
        ),
        ("C13", false) => edit!(s1_of(&mut m), "c13.lo_down", |r: &mut OpResult| r.errno =
            None),
        ("C13", true) => edit!(
            s1_of(&mut m),
            "c13.dump",
            |r: &mut OpResult| r.data["names"] = json!([])
        ),
        ("C14", false) => edit!(s1_of(&mut m), "c14.vs_stream", |r: &mut OpResult| r.data
            ["created"] =
            json!(true)),
        ("D01", false) => edit!(
            s1_of(&mut m),
            "d01.tcp",
            |r: &mut OpResult| r.data["connected"] = json!(true)
        ),
        ("D01", true) => {
            m.get_mut("S1").unwrap().nums.remove("d01.before");
        }
        ("D02", false) => s1_of(&mut m)
            .audit
            .retain(|r| r["client"] != format!("{TRANS}:50053")),
        ("D02", true) => edit!(
            s1_of(&mut m),
            "d02.cnlo",
            |r: &mut OpResult| r.data["reads"] = reply("HTTP/1.1 403 Forbidden\r\n\r\n")
        ),
        ("D03", false) => edit!(s1_of(&mut m), "d03.abs", |r: &mut OpResult| r.errno = None),
        ("D03", true) => {
            m.get_mut("S1")
                .unwrap()
                .ctl
                .insert("d03.own", Err("x".into()));
        }
        ("D04", false) => edit!(s1_of(&mut m), "d04.path", |r: &mut OpResult| r.errno = None),
        ("D04", true) => {
            m.get_mut("S1")
                .unwrap()
                .ctl
                .insert("d04.own", Err("sun_path too long".into()));
        }
        ("D05", false) => edit!(m.get_mut("S13").unwrap(), "d05.walk", |r: &mut OpResult| {
            r.data["found"] = json!(["/usr/lib/x/agent.sock"])
        }),
        ("D05", true) => edit!(m.get_mut("S13").unwrap(), "d05.walk", |r: &mut OpResult| {
            r.data["visited"] = json!(3)
        }),
        ("D06", false) => edit!(m.get_mut("S11b").unwrap(), "d.btcp", |r: &mut OpResult| {
            r.errno = None;
            r.data["connected"] = json!(true)
        }),
        ("D06", true) => edit!(
            m.get_mut("S11a").unwrap(),
            "d.listen",
            |r: &mut OpResult| r.data["port"] = json!(0)
        ),
        ("D07", false) => edit!(m.get_mut("S11b").unwrap(), "d.babs", |r: &mut OpResult| r
            .errno =
            None),
        ("D07", true) => edit!(m.get_mut("S11a").unwrap(), "d.abs", |r: &mut OpResult| r
            .ok =
            false),
        ("D08", false) => edit!(
            m.get_mut("S11b").unwrap(),
            "d.bstat1",
            |r: &mut OpResult| r.errno = None
        ),
        ("D08", true) => edit!(m.get_mut("S11a").unwrap(), "d.read", |r: &mut OpResult| r
            .data["matched"] =
            json!([])),
        ("D09", false) => m.get_mut("S11b").unwrap().audit.clear(),
        ("D09", true) => edit!(m.get_mut("S11a").unwrap(), "d.dns", |r: &mut OpResult| r
            .data["rcode"] =
            json!(3)),
        ("D10", false) => edit!(
            m.get_mut("S12").unwrap(),
            "d10.procs",
            |r: &mut OpResult| r.data["pids"] = json!((0..20).collect::<Vec<i32>>())
        ),
        ("F01", false) => {
            m.get_mut("S10")
                .unwrap()
                .ctl
                .insert("f01.gone", Err("survived".into()));
        }
        ("F01", true) => {
            m.get_mut("S10")
                .unwrap()
                .ctl
                .insert("f01.seen", Err("no token".into()));
        }
        ("F05", false) => m.get_mut("S4").unwrap().fin.as_mut().unwrap().rc = Some(0),
        ("F06", false) => m.get_mut("S5").unwrap().fin.as_mut().unwrap().rc = Some(0),
        ("F06", true) => {
            m.get_mut("S5").unwrap().nums.insert("audit_bytes", 10);
        }
        ("G01", false) => m.get_mut("S6").unwrap().fin.as_mut().unwrap().rc = Some(1),
        ("G01", true) => {
            m.get_mut("S6")
                .unwrap()
                .ctl
                .insert("g01.seen", Err("no token".into()));
        }
        ("G02", false) => m.get_mut("S7").unwrap().fin.as_mut().unwrap().rc = Some(0),
        ("G02", true) => {
            m.get_mut("S7")
                .unwrap()
                .ctl
                .insert("g02.seen", Err("no token".into()));
        }
        ("G03", false) => m.get_mut("S8b").unwrap().fin.as_mut().unwrap().rc = Some(0),
        ("G03", true) => {
            m.get_mut("S8a")
                .unwrap()
                .ctl
                .insert("g03.seen", Err("no token".into()));
        }
        ("G04", false) => m.get_mut("S9").unwrap().fin.as_mut().unwrap().elapsed_ms = 9000,
        ("G04", true) => {
            m.get_mut("S9")
                .unwrap()
                .ctl
                .insert("g04.seen", Err("no token".into()));
        }
        ("G05", false) => m.get_mut("S6b").unwrap().fin.as_mut().unwrap().rc = Some(1),
        ("G05", true) => {
            m.get_mut("S6").unwrap().notes.remove("netns");
        }
        ("H01", false) => edit!(m.get_mut("S12").unwrap(), "h01.env", |r: &mut OpResult| r
            .data["matched"] =
            json!([0, 1])),
        ("H01", true) => edit!(m.get_mut("S12").unwrap(), "h01.env", |r: &mut OpResult| r
            .data["matched"] =
            json!([])),
        ("H02", false) => edit!(
            m.get_mut("S12").unwrap(),
            "h02.environ",
            |r: &mut OpResult| r.data["len"] = json!(10)
        ),
        ("H02", true) => edit!(m.get_mut("S12").unwrap(), "h02.self", |r: &mut OpResult| {
            r.data["len"] = json!(0)
        }),
        ("H03", false) => edit!(m.get_mut("S12").unwrap(), "h03.scan", |r: &mut OpResult| {
            r.data["matched_pids"] = json!([5])
        }),
        ("H03", true) => edit!(m.get_mut("S12").unwrap(), "h03.scan", |r: &mut OpResult| {
            r.data["readable"] = json!(1)
        }),
        ("H04", false) => edit!(m.get_mut("S12").unwrap(), "h01.env", |r: &mut OpResult| {
            let mut n = r.data["names"].as_array().unwrap().clone();
            n.push(json!("LEAK"));
            r.data["names"] = Value::Array(n);
        }),
        ("H05", false) => edit!(m.get_mut("S12").unwrap(), "h05.fds", |r: &mut OpResult| r
            .data["fds"] =
            json!([0, 1, 2, 3])),
        ("H05", true) => {
            m.get_mut("S12")
                .unwrap()
                .ctl
                .insert("fd-cloexec-cleared", Err("FD_CLOEXEC still set".into()));
        }
        ("H06", false) => edit!(m.get_mut("S12").unwrap(), "h06.home", |r: &mut OpResult| {
            r.errno = None
        }),
        ("H06", true) => {
            m.get_mut("S12")
                .unwrap()
                .notes
                .insert("host_home", "/nonexistent-conformance-home".into());
        }
        _ => return None,
    }
    Some(m)
}

fn status_of(id: &str, m: &Scns) -> (Status, String, bool) {
    let r = evaluate(id, m);
    (
        r.status,
        r.detail.clone(),
        r.detail.starts_with("control failed:"),
    )
}

fn host_ids() -> Vec<&'static str> {
    crate::conformance::catalog::CATALOG
        .iter()
        .filter(|d| d.tier == crate::conformance::catalog::Tier::Host && super::implemented(d.id))
        .map(|d| d.id)
        .collect()
}

#[test]
fn every_implemented_host_check_passes_on_good_evidence() {
    let g = good();
    for id in host_ids() {
        let (st, detail, _) = status_of(id, &g);
        assert!(
            st == Status::Ok || (id == "D05" && st == Status::Ok),
            "{id} on good evidence: {st:?} {detail}"
        );
    }
}

#[test]
fn every_host_check_fails_on_its_assertion_mutation() {
    for id in host_ids() {
        let Some(m) = bad(id, false) else {
            panic!("no assertion mutation for {id}")
        };
        let (st, detail, control) = status_of(id, &m);
        let want = if id == "D05" {
            Status::Warn
        } else {
            Status::Fail
        };
        assert_eq!(st, want, "{id} assertion mutation: {detail}");
        assert!(
            !control,
            "{id} assertion mutation reported as control: {detail}"
        );
    }
}

#[test]
fn every_host_check_with_a_control_fails_as_control_when_the_control_breaks() {
    let with_control = [
        "A07", "A08", "A09", "A11", "B10", "C04", "C13", "D01", "D03", "D04", "D05", "D06", "D07",
        "D08", "D09", "F01", "F06", "G01", "G02", "G03", "G04", "G05", "H01", "H02", "H03", "H05",
        "H06",
    ];
    for id in with_control {
        let Some(m) = bad(id, true) else {
            panic!("no control mutation for {id}")
        };
        let (st, detail, control) = status_of(id, &m);
        assert!(
            st != Status::Ok,
            "{id} passed with a broken control: {detail}"
        );
        assert!(
            control,
            "{id} control break is not a control failure: {detail}"
        );
    }
}

#[test]
fn a11_row_only_on_the_other_leg_is_a_fail() {
    // The CONNECT leg's row exists but the transparent leg's row does not: the
    // transparent assertion must fail, not pass on the explicit row.
    let mut m = good();
    m.get_mut("S1")
        .unwrap()
        .audit
        .retain(|r| r["via"] != "transparent" || r["client"] != format!("{TRANS}:50013"));
    let (st, detail, control) = status_of("A11", &m);
    assert_eq!(st, Status::Fail, "{detail}");
    assert!(!control);
    assert!(detail.contains("transparent"), "{detail}");
}

#[test]
fn d02_loopback_row_on_the_wrong_via_is_a_fail() {
    let mut m = good();
    let s1 = m.get_mut("S1").unwrap();
    for r in s1.audit.iter_mut() {
        if r["client"] == format!("{TRANS}:50053") {
            r["via"] = json!("explicit-connect");
        }
    }
    let (st, detail, _) = status_of("D02", &m);
    assert_eq!(st, Status::Fail, "{detail}");
}

#[test]
fn d06_without_the_probe_port_is_a_control_failure() {
    let mut m = good();
    m.get_mut("S11a")
        .unwrap()
        .probe
        .as_mut()
        .unwrap()
        .results
        .remove("d.listen");
    let (st, detail, control) = status_of("D06", &m);
    assert_eq!(st, Status::Fail);
    assert!(control, "{detail}");
}

#[test]
fn missing_probe_evidence_is_never_a_pass() {
    let mut m = good();
    m.get_mut("S1")
        .unwrap()
        .probe
        .as_mut()
        .unwrap()
        .results
        .remove("c03.tcp");
    assert_eq!(status_of("C03", &m).0, Status::Fail);
    let mut n = good();
    n.get_mut("S1").unwrap().probe = None;
    n.get_mut("S1").unwrap().probe_err = Some("probe printed nothing".into());
    assert_eq!(status_of("C01", &n).0, Status::Fail);
}

#[test]
fn unavailable_scenario_is_not_a_pass() {
    let mut m = good();
    m.insert("S1", Scn::unavailable("S1", "boom".into()));
    assert_eq!(status_of("A01", &m).0, Status::Fail);
}

#[test]
fn g05_survivors_recorded_before_cleanup_are_a_fail() {
    // Review (CRITICAL): the netns members must be judged from the evidence
    // recorded before the cleanup kill, never from a re-check after it.
    let mut m = good();
    m.get_mut("S6").unwrap().ctl.insert(
        "netns-after-exit",
        Err("netns members after exit (before cleanup): pids [7]".into()),
    );
    let (st, detail, control) = status_of("G05", &m);
    assert_eq!(st, Status::Fail, "{detail}");
    assert!(!control, "{detail}");
    assert!(detail.contains("netns-after-exit"), "{detail}");
}

#[test]
fn d08_host_path_control_breaks_when_the_layout_moves() {
    let mut m = good();
    m.get_mut("S11a").unwrap().ctl.insert(
        "d.host-file",
        Err("A's secret is not at /x/wk/a-secret on the host".into()),
    );
    let (st, detail, control) = status_of("D08", &m);
    assert_eq!(st, Status::Fail, "{detail}");
    assert!(control, "{detail}");
}

#[test]
fn d10_any_capability_fails() {
    for key in ["eff", "prm", "bnd"] {
        let mut m = good();
        let r = m
            .get_mut("S12")
            .unwrap()
            .probe
            .as_mut()
            .unwrap()
            .results
            .get_mut("d10.caps")
            .unwrap();
        r.data[key] = json!("000001ffffffffff");
        let (st, detail, control) = status_of("D10", &m);
        assert_eq!(st, Status::Fail, "{key}: {detail}");
        assert!(!control, "{key}: {detail}");
    }
}

#[test]
fn b10_pins_the_forward_leg_and_both_reasons() {
    // Only the reverse-direction row exists: the absolute-form Host mismatch leg
    // must not pass on it.
    let mut m = good();
    m.get_mut("S1")
        .unwrap()
        .audit
        .retain(|r| r["reason"] != "HTTP Host other.conformance.test does not match the request-target name allowed.conformance.test");
    let (st, detail, _) = status_of("B10", &m);
    assert_eq!(st, Status::Fail, "{detail}");
    assert!(detail.contains("explicit-forward"), "{detail}");
}

#[test]
fn h06_that_cannot_run_is_a_capability_skip_not_a_pass() {
    let mut m = good();
    m.get_mut("S12")
        .unwrap()
        .notes
        .insert("home_applicable", "false".into());
    let r = evaluate("H06", &m);
    assert_eq!(r.status, Status::Skip);
    assert_eq!(
        r.skip_kind,
        Some(crate::conformance::report::SkipKind::Capability)
    );
}

#[test]
fn s13_walk_truncated_by_its_budget_is_a_warn() {
    let mut m = good();
    let w = m
        .get_mut("S13")
        .unwrap()
        .probe
        .as_mut()
        .unwrap()
        .results
        .get_mut("d05.walk")
        .unwrap();
    w.data["truncated"] = json!(true);
    let r = evaluate("D05", &m);
    assert_eq!(r.status, Status::Warn, "{r:?}");
}

#[test]
fn d02_accepts_the_ipv6_first_resolution_of_localhost() {
    // Review: the CI runner's /etc/hosts lists `::1 localhost` first, so the
    // guard's denial names [::1]:443. The check must accept it, pinned to the
    // leg and the client.
    let v6: std::net::SocketAddr = "[::1]:443".parse().unwrap();
    let v4: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
    let reasons = super::loopback_reasons(&[v6, v4]);
    assert_eq!(reasons.len(), 2);
    assert!(
        reasons[0].starts_with("denied dial to [::1]:443: loopback"),
        "{reasons:?}"
    );
    let mut m = good();
    let s1 = m.get_mut("S1").unwrap();
    for r in s1.audit.iter_mut() {
        let client = r["client"].as_str().unwrap_or("").to_owned();
        if client == format!("{TRANS}:50053") || client == "127.0.0.1:50052" {
            r["reason"] = json!(reasons[0].clone());
        }
    }
    let r = super::d02_with(&m, &[v6, v4]);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn d02_rejects_a_denial_for_some_other_address_and_lists_the_rows() {
    let v6: std::net::SocketAddr = "[::1]:443".parse().unwrap();
    let mut m = good();
    let s1 = m.get_mut("S1").unwrap();
    for r in s1.audit.iter_mut() {
        if r["client"] == "127.0.0.1:50052" {
            r["reason"] = json!("denied dial to 10.0.0.1:443: private-use address (RFC 1918)");
        }
    }
    let err = super::d02_with(&m, &[v6]).expect_err("the explicit leg has no loopback row");
    assert!(err.msg.contains("127.0.0.1:50052"), "{}", err.msg);
    assert!(
        err.ev.iter().any(|e| e.contains("10.0.0.1")),
        "evidence must show the actual rows: {:?}",
        err.ev
    );
}

/// The loopback denial text for `localhost` as this host resolves it (first
/// loopback address in resolver order), built by the product's builders.
fn d02_reason() -> String {
    super::loopback_reasons(&super::localhost_addrs())
        .into_iter()
        .next()
        .expect("localhost resolves to a loopback address on the test host")
}
