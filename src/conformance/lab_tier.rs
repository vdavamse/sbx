//! The lab tier's 19 checks (issue #13, PR2, §10): scenarios L1–L4 run inside
//! the lab child, and the pure evaluators over their evidence.
//!
//! Every L check uses its own `xNN.allowed.conformance.test` name, so fixture
//! and DNS evidence attributes to exactly one check. Controls come first in
//! each evaluator (a broken probe or fixture is a `control failed`, never a
//! vacuous pass).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::fixtures::{DnsRec, HttpRec, LAB_IP, Logs, REBIND, TlsRec};
use super::host_tier::{
    F, R, Scns, a_ips, as_ctl, ctl, ctl_fail, denied, fail, in_fake_range, leg_denied,
    leg_no_bytes, local, need, op, rcode, read_len, sc,
};
use super::policies::{self, Builtin};
use super::probe::Op;
use super::probe::{OpResult, mono_ms};
use super::report::{CheckResult, SkipKind};
use super::scenarios::{Env, Opts, Scn, plain};
use super::spawn::{SbxRun, poll_gone};
use crate::host::Status;
use crate::proxy::relay::TORN_DOWN_SECOND_HELLO;

/// The 19 lab checks, in catalog order.
pub const LAB_IDS: [&str; 19] = [
    "A02", "A03", "A04", "A05", "A06", "A12", "B01", "B02", "B03", "B04", "B05", "B06", "B07",
    "B08", "B09", "C02", "C07", "F02", "F04",
];

/// The evaluator inputs: the scenario results plus the fixture logs at the
/// time of evaluation.
pub struct Ev<'a> {
    pub s: &'a Scns,
    /// The run's nonce (names the probe's unique DNS queries).
    pub nonce: String,
    pub tls: Vec<TlsRec>,
    pub http: Vec<HttpRec>,
    pub dns: Vec<DnsRec>,
    /// Trap accept counts: the control value and the value now.
    pub traps: Vec<(Ipv4Addr, u64, u64)>,
}

/// The lab tier entry point (the child calls this after setup): run the
/// scenarios that feed the selected checks, evaluate, return the results.
pub fn run_all(
    env: &Env,
    logs: &Arc<Logs>,
    trap_control: &[(Ipv4Addr, u64)],
    only: &[String],
) -> Vec<CheckResult> {
    let selected: Vec<&str> = LAB_IDS
        .iter()
        .copied()
        .filter(|id| only.is_empty() || only.iter().any(|o| o.eq_ignore_ascii_case(id)))
        .collect();
    let want = |ids: &[&str]| selected.iter().any(|s| ids.contains(s));
    let mut scns: Scns = BTreeMap::new();
    if want(&[
        "A02", "A03", "A06", "A12", "B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "C02",
        "C07",
    ]) {
        let s = l1(env);
        scns.insert(s.name, s);
    }
    if want(&["A04", "A05", "B09"]) {
        let s = l2(env);
        scns.insert(s.name, s);
    }
    if want(&["F02"]) {
        let s = fail_closed(env, logs, FailMode::Sigkill);
        scns.insert(s.name, s);
    }
    if want(&["F04"]) {
        let s = fail_closed(env, logs, FailMode::Sigstop);
        scns.insert(s.name, s);
    }
    let ev = Ev {
        s: &scns,
        nonce: env.nonce.clone(),
        tls: logs.tls_snapshot(),
        http: logs.http_snapshot(),
        dns: logs.dns_snapshot(),
        traps: trap_control
            .iter()
            .map(|(ip, n)| (*ip, *n, logs.trap_accepts(*ip)))
            .collect(),
    };
    selected
        .iter()
        .map(|id| {
            let needed = scenario_of(id);
            if let Some(why) = scns.get(needed).and_then(|s| s.skip.clone()) {
                return CheckResult::skip(
                    id,
                    SkipKind::Capability,
                    format!("lab scenario {needed}: {why}"),
                );
            }
            match evaluate(id, &ev) {
                Ok(text) => CheckResult::new(id, Status::Ok, text),
                Err(f) => {
                    let mut lines = f.ev.clone();
                    lines.extend(scn_evidence(&scns, needed));
                    CheckResult::new(id, Status::Fail, f.msg).with_evidence(lines)
                }
            }
        })
        .collect()
}

/// The numbers and control results of the scenario a failed check read (the
/// lab evidence a reviewer needs: signal times, attempts, control outcomes).
fn scn_evidence(scns: &Scns, name: &str) -> Vec<String> {
    let Some(s) = scns.get(name) else {
        return Vec::new();
    };
    let mut out: Vec<String> = s
        .nums
        .iter()
        .map(|(k, v)| format!("{name}: {k}={v}"))
        .collect();
    out.extend(s.ctl.iter().map(|(k, v)| {
        format!(
            "{name}: {k}={}",
            v.as_ref().map_or_else(|e| e.clone(), |()| "ok".to_owned())
        )
    }));
    out
}

/// The scenario whose evidence a lab check reads (for capability skips).
fn scenario_of(id: &str) -> &'static str {
    match id {
        "A04" | "A05" | "B09" => "L2",
        "F02" => "F02",
        "F04" => "F04",
        _ => "L1",
    }
}

// ---------------------------------------------------------------- scenarios

/// The ops of L1 (transparent). One probe run; each check has its own name.
fn l1_ops(nonce: &str) -> Vec<Op> {
    let tls_name = |n: &str| format!("{n}.allowed.conformance.test");
    let mut v = vec![
        dns("c07a", &format!("c07-{nonce}.conformance.test"), "A"),
        dns("c07b", "allowed.conformance.test", "TXT"),
        dns(
            "c07c",
            &format!("x{nonce}.c07.allowed.conformance.test"),
            "A",
        ),
        dns("c07d", "c07.allowed.conformance.test", "AAAA"),
        dns("a06dns", "A06.Allowed.Conformance.Test.", "A"),
        tcp_name(
            "a02",
            &tls_name("a02"),
            443,
            vec![hello(&tls_name("a02")), read_line()],
        ),
        tcp_name(
            "a03",
            &tls_name("a03"),
            80,
            vec![
                text(&format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
                    tls_name("a03")
                )),
                read_http(),
            ],
        ),
        tcp_name(
            "a06",
            "A06.Allowed.Conformance.Test.",
            443,
            vec![hello(&tls_name("a06")), read_line()],
        ),
    ];
    for (i, (name, _)) in REBIND.iter().enumerate() {
        let id = format!("a12{}", ["lo", "private", "meta"][i]);
        v.push(dns(&format!("{id}dns"), name, "A"));
        v.push(tcp_name(&id, name, 443, vec![hello(name), read_to_end()]));
    }
    let b = |n: &str| tls_name(n);
    v.push(tcp_name(
        "b01",
        &b("b01"),
        443,
        vec![hello("other-b01.conformance.test"), read_to_end()],
    ));
    v.push(tcp_name(
        "b02",
        &b("b02"),
        443,
        vec![hello_none(), read_to_end()],
    ));
    v.push(tcp_name(
        "b03",
        &b("b03"),
        443,
        vec![
            text(&format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", b("b03"))),
            read_to_end(),
        ],
    ));
    v.push(tcp_name(
        "b04",
        &b("b04"),
        80,
        vec![
            text("GET / HTTP/1.1\r\nHost: other-b04.conformance.test\r\n\r\n"),
            read_to_end(),
        ],
    ));
    v.push(tcp_name(
        "b05a",
        &b("b05a"),
        80,
        vec![text("GET / HTTP/1.0\r\n\r\n"), read_to_end()],
    ));
    v.push(tcp_name(
        "b05b",
        &b("b05b"),
        80,
        vec![
            text(&format!(
                "GET / HTTP/1.1\r\nHost: {0}\r\nHost: {0}\r\n\r\n",
                b("b05b")
            )),
            read_to_end(),
        ],
    ));
    v.push(tcp_name(
        "b06",
        &b("b06"),
        80,
        vec![
            text(&format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", b("b06"))),
            read_http(),
            text("GET / HTTP/1.1\r\nHost: other-b06.conformance.test\r\n\r\n"),
            read_to_end(),
        ],
    ));
    v.push(tcp_name(
        "b07",
        &b("b07"),
        443,
        vec![
            hello(&b("b07")),
            read_line(),
            hello(&b("b07")),
            read_to_end(),
        ],
    ));
    v.push(tcp_name(
        "b08",
        &b("b08"),
        443,
        vec![hello_ech(&b("b08")), read_to_end()],
    ));
    v.push(tcp_addr(
        "c02",
        &format!("{LAB_IP}:443"),
        vec![hello(&b("c02")), read_to_end()],
    ));
    v
}

/// L1 (`lab-transparent`).
fn l1(env: &Env) -> Scn {
    let ops = l1_ops(&env.nonce);
    plain(env, "L1", Builtin::LabTransparent, ops, Opts::default())
}

/// L2 (`lab-explicit`): the explicit CONNECT and absolute-form paths.
fn l2(env: &Env) -> Scn {
    let a = |n: &str| format!("{n}.allowed.conformance.test");
    let connect = |n: &str| {
        text(&format!(
            "CONNECT {0}:443 HTTP/1.1\r\nHost: {0}:443\r\n\r\n",
            a(n)
        ))
    };
    let ops = vec![
        tcp_env(
            "a04",
            vec![
                connect("a04"),
                read_until("\r\n\r\n"),
                hello(&a("a04")),
                read_line(),
            ],
        ),
        tcp_env(
            "a05",
            vec![
                text(&format!(
                    "GET http://{0}/x HTTP/1.1\r\nHost: {0}\r\n\r\n",
                    a("a05")
                )),
                read_http(),
            ],
        ),
        tcp_env(
            "b09",
            vec![
                connect("b09"),
                read_until("\r\n\r\n"),
                hello("other-b09.conformance.test"),
                read_to_end(),
            ],
        ),
    ];
    plain(env, "L2", Builtin::Explicit, ops, Opts::default())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailMode {
    Sigkill,
    Sigstop,
}

/// F02 (SIGKILL) and F04 (SIGSTOP) of `sbx run` mid-stream. The probe loops
/// connections to a fixture; the evidence is the fixture's accept log and,
/// for F04, the probe's own attempt log in the session's `/work`.
fn fail_closed(env: &Env, logs: &Arc<Logs>, mode: FailMode) -> Scn {
    let (name, tag, log) = match mode {
        FailMode::Sigkill => ("F02", "f02", "/work/f02.log"),
        FailMode::Sigstop => ("F04", "f04", "/work/f04.log"),
    };
    let mut scn = Scn::named(name);
    let sni = format!("{tag}.allowed.conformance.test");
    let text_policy = policies::policy_json(Builtin::LabTransparent, &env.exe_text, None);
    let policy = match policies::write_policy(&env.base, &format!("p-{name}"), &text_policy) {
        Ok(p) => p,
        Err(e) => return Scn::unavailable(name, format!("cannot write policy: {e}")),
    };
    let session = env.base.join(format!("s-{name}"));
    let audit = env.base.join(format!("a-{name}.jsonl"));
    let token = format!("tok-{tag}-{}", env.nonce);
    // F04's window is one second: a 150 ms attempt bound gives >= 3 attempts in it.
    let attempt_ms = if mode == FailMode::Sigkill { 300 } else { 150 };
    let ops = vec![op_from(json!({
        "op": "tcp_loop",
        "id": tag,
        "target": {"name": sni, "port": 443},
        "sni": sni,
        "duration_ms": 20_000,
        "attempt_timeout_ms": attempt_ms,
        "log": log,
        "hold_first": mode == FailMode::Sigkill,
        "hold_token": if mode == FailMode::Sigkill { "HOLD-f02" } else { "" },
    }))];
    let mut cmd = vec![
        env.exe_text.clone(),
        "__conformance".to_owned(),
        "probe".to_owned(),
        "--tag".to_owned(),
        token.clone(),
    ];
    cmd.push(serde_json::to_string(&super::probe::Ops::new(ops)).unwrap_or_default());
    let mut running = match SbxRun::new(&env.exe, &policy, &session, cmd)
        .audit(&audit)
        .spawn()
    {
        Ok(r) => r,
        Err(e) => return Scn::unavailable(name, format!("cannot spawn sbx run: {e}")),
    };
    // Control: the loop reached the fixture at least three times.
    let before = wait_accepts(logs, &sni, 3, Duration::from_secs(8));
    scn.ctl.insert(
        "seen",
        if before >= 3 {
            Ok(())
        } else {
            Err(format!("only {before} accepts before the signal"))
        },
    );
    // All lab timestamps are CLOCK_MONOTONIC (shared by every process here).
    // t_signal is taken before the signal, t_kill after the SIGKILL returns.
    let t_sig = mono_ms();
    scn.nums.insert("t_signal", t_sig);
    scn.nums.insert("accepts_before", before as u64);
    match mode {
        FailMode::Sigkill => running.sigkill(),
        FailMode::Sigstop => {
            running.signal(libc::SIGSTOP);
            std::thread::sleep(Duration::from_millis(1000));
            running.sigkill();
        }
    }
    let t_kill = mono_ms();
    scn.nums.insert("t_kill", t_kill);
    if mode == FailMode::Sigstop {
        let inside = work_log_times(&session.join("work").join("f04.log"))
            .iter()
            .filter(|t| **t > t_sig && **t < t_kill)
            .count();
        scn.nums.insert("stop_attempts", inside as u64);
    }
    // The observation window runs from the SIGKILL. F02 observes at +2 s and
    // requires the held connection to close within 1.5 s: a close the window
    // never sees (the cleanup below would cause it) cannot pass.
    let window = match mode {
        FailMode::Sigkill => Duration::from_secs(2),
        FailMode::Sigstop => Duration::from_millis(500),
    };
    std::thread::sleep(window);
    // OBSERVE before any cleanup: the fixture's state now, the chain's liveness
    // now. The reap and the group kill come only after this.
    observe_fail_closed(&mut scn, logs, mode, tag, t_sig, t_kill);
    let gone = poll_gone(&token, None, Duration::from_secs(5));
    scn.ctl
        .insert("gone", gone.map_err(|pids| format!("survivors {pids:?}")));
    running.wait_exit(Instant::now() + Duration::from_secs(5));
    let _fin = running.finish();
    scn
}

/// The fail-closed evidence, read from the fixture at observation time (before
/// cleanup): late accepts after the kill and, for F02, the held connection's
/// accept and close times (`u64::MAX` close = still open when observed).
fn observe_fail_closed(
    scn: &mut Scn,
    logs: &Logs,
    mode: FailMode,
    tag: &str,
    t_sig: u64,
    t_kill: u64,
) {
    let snap = logs.tls_snapshot();
    let sni = format!("{tag}.allowed.conformance.test");
    let cutoff = match mode {
        FailMode::Sigkill => t_kill + 50,
        FailMode::Sigstop => t_sig + 50,
    };
    let late = snap
        .iter()
        .filter(|r| r.sni.as_deref() == Some(sni.as_str()) && r.accept_ms > cutoff)
        .count();
    scn.nums.insert("late_accepts", late as u64);
    if mode == FailMode::Sigkill {
        let held: Vec<&TlsRec> = snap
            .iter()
            .filter(|r| r.tokens.iter().any(|t| t == "HOLD-f02"))
            .collect();
        scn.nums.insert("held_count", held.len() as u64);
        if let Some(h) = held.first() {
            scn.nums.insert("held_accept", h.accept_ms);
            scn.nums
                .insert("held_close", h.close_ms.unwrap_or(u64::MAX));
        }
    }
}

/// Poll the fixture's TLS log until `n` connections with `sni` were accepted.
fn wait_accepts(logs: &Logs, sni: &str, n: usize, bound: Duration) -> usize {
    let deadline = Instant::now() + bound;
    loop {
        let count = logs
            .tls_snapshot()
            .iter()
            .filter(|r| r.sni.as_deref() == Some(sni))
            .count();
        if count >= n || Instant::now() > deadline {
            return count;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The probe's `tcp_loop` log: the CLOCK_MONOTONIC (`mono_ms`) timestamp of each attempt line.
fn work_log_times(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next()?.parse::<u64>().ok())
        .collect()
}

// ---------------------------------------------------------------- op builders

fn dns(id: &str, name: &str, qtype: &str) -> Op {
    op_from(json!({"op": "dns", "id": id, "name": name, "qtype": qtype}))
}

fn tcp_name(id: &str, name: &str, port: u16, steps: Vec<Value>) -> Op {
    op_from(json!({"op": "tcp", "id": id, "target": {"name": name, "port": port}, "steps": steps}))
}

fn tcp_addr(id: &str, addr: &str, steps: Vec<Value>) -> Op {
    op_from(json!({"op": "tcp", "id": id, "target": {"addr": addr}, "steps": steps}))
}

fn tcp_env(id: &str, steps: Vec<Value>) -> Op {
    op_from(json!({"op": "tcp", "id": id, "target": {"env_proxy": "HTTPS_PROXY"}, "steps": steps}))
}

/// Build an op from its JSON; the shapes are pinned by `lab_ops_parse`.
fn op_from(v: Value) -> Op {
    serde_json::from_value(v).unwrap_or_else(|e| {
        // A malformed lab op is a bug in this file; the missing result then
        // surfaces as a FAIL ("missing probe result") rather than a panic.
        eprintln!("internal: malformed lab op: {e}");
        Op::Sleep {
            id: "malformed".to_owned(),
            ms: 0,
        }
    })
}

fn text(t: &str) -> Value {
    json!({"send": {"text": t}})
}

fn hello(sni: &str) -> Value {
    json!({"send": {"hello": {"sni": sni, "ech": false}}})
}

fn hello_none() -> Value {
    json!({"send": {"hello": {"sni": null, "ech": false}}})
}

fn hello_ech(sni: &str) -> Value {
    json!({"send": {"hello": {"sni": sni, "ech": true}}})
}

fn read_line() -> Value {
    json!({"read": {"until": "\n", "max": 4096, "timeout_ms": 3000}})
}

fn read_until(delim: &str) -> Value {
    json!({"read": {"until": delim, "max": 4096, "timeout_ms": 3000}})
}

fn read_http() -> Value {
    json!({"read_http": {"timeout_ms": 3000}})
}

fn read_to_end() -> Value {
    json!({"read_to_end": {"max": 65536, "timeout_ms": 3000}})
}

// ---------------------------------------------------------------- evaluators

/// The evaluator for one L check (controls first, see the module docs).
fn evaluate(id: &str, ev: &Ev<'_>) -> R {
    match id {
        "A02" => a02(ev),
        "A03" => a03(ev),
        "A04" => a04(ev),
        "A05" => a05(ev),
        "A06" => a06(ev),
        "A12" => a12(ev),
        "B01" => b01(ev),
        "B02" => b02(ev),
        "B03" => b03(ev),
        "B04" => b04(ev),
        "B05" => b05(ev),
        "B06" => b06(ev),
        "B07" => b07(ev),
        "B08" => b08(ev),
        "B09" => b09(ev),
        "C02" => c02(ev),
        "C07" => c07(ev),
        "F02" => f02(ev),
        "F04" => f04(ev),
        _ => Err(fail(format!("no evaluator for {id}"))),
    }
}

/// The reply text of read `i` of an op (`""` when absent).
fn read_text(r: &OpResult, i: usize) -> String {
    r.data["reads"][i]["text"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

fn read_end(r: &OpResult, i: usize) -> String {
    r.data["reads"][i]["end"].as_str().unwrap_or("").to_owned()
}

/// Read the op result by id from a scenario.
fn res<'a>(s: &'a Scn, id: &str) -> Result<&'a OpResult, F> {
    op(s, id)
}

fn l1_scn<'a>(ev: &Ev<'a>) -> Result<&'a Scn, F> {
    sc(ev.s, "L1")
}

fn l2_scn<'a>(ev: &Ev<'a>) -> Result<&'a Scn, F> {
    sc(ev.s, "L2")
}

fn name(prefix: &str) -> String {
    format!("{prefix}.allowed.conformance.test")
}

/// A control on the L1 `a02` path: the fixture was reached through the proxy.
fn a02_control(ev: &Ev<'_>) -> Result<(), F> {
    let s = l1_scn(ev).map_err(as_ctl)?;
    let r = res(s, "a02").map_err(as_ctl)?;
    ctl(
        r.ok && read_text(r, 0) == format!("FIXTURE-TLS {}", name("a02")),
        "the A02 reference path did not reach the fixture",
    )
}

/// A TLS fixture connection with `sni`, counted.
fn tls_with<'b>(ev: &'b Ev<'_>, sni: &str) -> Vec<&'b TlsRec> {
    ev.tls
        .iter()
        .filter(|r| r.sni.as_deref() == Some(sni))
        .collect()
}

/// Audit connect rows for `host` through `via`.
fn connect_row(s: &Scn, host: &str, via: &str) -> bool {
    s.audit.iter().any(|r| {
        r["event"] == "connect"
            && r["host"].as_str() == Some(host)
            && r["via"].as_str() == Some(via)
    })
}

/// Audit close rows for `host` through `via`.
fn close_row(s: &Scn, host: &str, via: &str) -> bool {
    s.audit.iter().any(|r| {
        r["event"] == "close" && r["host"].as_str() == Some(host) && r["via"].as_str() == Some(via)
    })
}

fn a02(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "a02")?;
    let n = name("a02");
    need(r.ok && read_len(r) > 0, "a02: no bytes from the upstream")?;
    need(
        read_text(r, 0) == format!("FIXTURE-TLS {n}"),
        format!("a02: expected FIXTURE-TLS {n}, got {:?}", read_text(r, 0)),
    )?;
    let conns = tls_with(ev, &n);
    need(
        conns.len() == 1,
        format!(
            "a02: fixture saw {} connections with SNI {n}, expected 1",
            conns.len()
        ),
    )?;
    need(
        connect_row(s, &n, "transparent"),
        format!("a02: no audit connect row for {n} via transparent"),
    )?;
    need(
        close_row(s, &n, "transparent"),
        format!("a02: no audit close row for {n}"),
    )?;
    lab_dns_row(ev, &n)?;
    Ok(format!(
        "allowed name over transparent TLS reaches the upstream ({n})"
    ))
}

fn a03(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "a03")?;
    let n = name("a03");
    need(
        reads_all(r).contains(&format!("FIXTURE-HTTP {n}")),
        format!(
            "a03: expected body FIXTURE-HTTP {n}, got {:?}",
            reads_all(r)
        ),
    )?;
    let reqs: Vec<&HttpRec> = ev
        .http
        .iter()
        .filter(|h| h.host.as_deref() == Some(n.as_str()))
        .collect();
    need(
        !reqs.is_empty(),
        format!("a03: fixture saw no request with Host {n}"),
    )?;
    need(
        reqs.iter().any(|h| h.connection_close),
        "a03: fixture request lacks Connection: close",
    )?;
    need(
        connect_row(s, &n, "transparent"),
        format!("a03: no audit connect row for {n} via transparent"),
    )?;
    lab_dns_row(ev, &n)?;
    Ok(format!(
        "allowed name over transparent HTTP reaches the upstream ({n})"
    ))
}

/// The probe's reads, joined (diagnostics).
fn reads_all(r: &OpResult) -> String {
    (0..4)
        .map(|i| read_text(r, i))
        .collect::<Vec<_>>()
        .join("|")
}

fn a04(ev: &Ev<'_>) -> R {
    let s = l2_scn(ev)?;
    let r = res(s, "a04")?;
    let n = name("a04");
    need(r.ok, "a04: the proxy path did not connect")?;
    need(
        read_text(r, 0).starts_with("HTTP/1.1 200"),
        format!("a04: CONNECT did not return 200, got {:?}", read_text(r, 0)),
    )?;
    need(
        read_text(r, 1) == format!("FIXTURE-TLS {n}"),
        format!(
            "a04: expected FIXTURE-TLS {n} after CONNECT, got {:?}",
            read_text(r, 1)
        ),
    )?;
    need(
        connect_row(s, &n, "explicit-connect"),
        format!("a04: no audit connect row for {n} via explicit-connect"),
    )?;
    lab_dns_row(ev, &n)?;
    Ok(format!(
        "allowed name via explicit CONNECT reaches the upstream ({n})"
    ))
}

fn a05(ev: &Ev<'_>) -> R {
    let s = l2_scn(ev)?;
    let r = res(s, "a05")?;
    let n = name("a05");
    need(
        reads_all(r).contains(&format!("FIXTURE-HTTP {n}")),
        format!("a05: expected FIXTURE-HTTP {n}, got {:?}", reads_all(r)),
    )?;
    let saw = ev.http.iter().any(|h| {
        h.host.as_deref() == Some(n.as_str())
            && h.method == "GET"
            && h.target == "/x"
            && h.connection_close
    });
    need(
        saw,
        format!("a05: fixture did not see origin-form GET /x with Host {n} and Connection: close"),
    )?;
    need(
        connect_row(s, &n, "explicit-forward"),
        format!("a05: no audit row for {n} via explicit-forward"),
    )?;
    lab_dns_row(ev, &n)?;
    Ok(format!(
        "allowed name via explicit absolute-form GET reaches the upstream ({n})"
    ))
}

fn a06(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    let d = res(s, "a06dns")?;
    need(
        rcode(d) == 0 && a_ips(d).len() == 1 && in_fake_range(a_ips(d)[0]),
        "a06: mixed-case dns did not return one fake IP",
    )?;
    let answered = a_ips(d)[0];
    // The probe dials the MIXED-CASE name; the SNI stays lowercase (the
    // normalized name the proxy must match).
    let r = res(s, "a06")?;
    let n = name("a06");
    need(
        r.data["resolved"].as_str() == Some(format!("{answered}:443").as_str()),
        format!(
            "a06: the mixed-case dial went to {} instead of the answered {answered}:443",
            r.data["resolved"]
        ),
    )?;
    need(
        read_text(r, 0) == format!("FIXTURE-TLS {n}"),
        format!("a06: expected FIXTURE-TLS {n}, got {:?}", read_text(r, 0)),
    )?;
    need(
        !tls_with(ev, &n).is_empty(),
        format!("a06: fixture saw no SNI {n}"),
    )?;
    lab_dns_row(ev, &n)?;
    Ok("subdomain, mixed case and trailing dot are normalized and allowed".to_owned())
}

/// The proxy's own upstream resolution asked the lab DNS for `name` (an A
/// query). A proxy that dials some other name fails here, whatever the
/// fixture then echoes.
fn lab_dns_row(ev: &Ev<'_>, name: &str) -> Result<(), F> {
    need(
        ev.dns.iter().any(|d| d.name == name && d.qtype == "A"),
        format!(
            "the lab DNS never saw an A query for {name} (the upstream dial used another name)"
        ),
    )
}

/// The denial reason for a dial to `ip:443`, as the egress guard words it.
fn dial_reason(ip: Ipv4Addr) -> String {
    let why = crate::egress::guard(ip.into())
        .err()
        .map_or("", |d| d.reason());
    format!("denied dial to {ip}:443: {why}")
}

fn a12(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    // Control: each trap accepted exactly its one control connection.
    for (ip, control, _) in &ev.traps {
        if *control != 1 {
            return Err(ctl_fail(format!("trap {ip}:443 control count {control}")));
        }
    }
    for (i, (dns_name, _)) in REBIND.iter().enumerate() {
        let id = format!("a12{}", ["lo", "private", "meta"][i]);
        let d = res(s, &format!("{id}dns"))?;
        need(
            rcode(d) == 0 && a_ips(d).len() == 1 && in_fake_range(a_ips(d)[0]),
            format!("a12: {dns_name} did not resolve to a fake IP"),
        )?;
        leg_no_bytes(s, &id)?;
        let ip = REBIND[i].1;
        leg_denied(s, &id, "transparent", &dial_reason(ip))?;
    }
    for (ip, control, now) in &ev.traps {
        need(
            control == now,
            format!(
                "trap {ip}:443 accepted {} connections after the control, expected none",
                now - control
            ),
        )?;
    }
    Ok("allowed name resolving to loopback/private/metadata is denied".to_owned())
}

fn b01(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    leg_no_bytes(s, "b01")?;
    let r = res(s, "b01")?;
    let l = local(r)?;
    let want = format!(
        "SNI other-b01.conformance.test does not match the DNS-map name {}",
        name("b01")
    );
    need(
        denied(s, &l, "transparent", &want),
        format!("b01: no audit deny row: {want}"),
    )?;
    need(
        tls_with(ev, "other-b01.conformance.test").is_empty(),
        "b01: the fixture saw SNI other-b01",
    )?;
    Ok("TLS SNI different from the dialed name is denied".to_owned())
}

fn b02(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    leg_no_bytes(s, "b02")?;
    let l = local(res(s, "b02")?)?;
    need(
        denied(
            s,
            &l,
            "transparent",
            "missing or invalid SNI in the TLS ClientHello",
        ),
        "b02: no audit deny row for a missing SNI",
    )?;
    need(
        !ev.tls
            .iter()
            .any(|r| r.sni.is_none() && r.first_byte == 0x16),
        "b02: the fixture saw a ClientHello without SNI",
    )?;
    Ok("TLS ClientHello without SNI is denied".to_owned())
}

fn b03(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    leg_no_bytes(s, "b03")?;
    let l = local(res(s, "b03")?)?;
    need(
        denied(
            s,
            &l,
            "transparent",
            "non-TLS traffic on port 443 (first byte 0x47)",
        ),
        "b03: no audit deny row for non-TLS bytes",
    )?;
    need(
        !ev.tls
            .iter()
            .any(|r| r.first_byte != 0x16 && r.first_byte != 0),
        "b03: the fixture saw non-TLS bytes",
    )?;
    Ok("non-TLS bytes on port 443 are denied".to_owned())
}

fn b04(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "a03")?;
    ctl(
        reads_all(r).contains(&format!("FIXTURE-HTTP {}", name("a03"))),
        "the A03 HTTP path did not reach the fixture",
    )?;
    leg_no_bytes(s, "b04")?;
    let l = local(res(s, "b04")?)?;
    let want = format!(
        "HTTP Host other-b04.conformance.test does not match the DNS-map name {}",
        name("b04")
    );
    need(
        denied(s, &l, "transparent", &want),
        format!("b04: no audit deny row: {want}"),
    )?;
    need(
        !ev.http
            .iter()
            .any(|h| h.host.as_deref() == Some("other-b04.conformance.test")),
        "b04: the fixture saw Host other-b04",
    )?;
    Ok("HTTP Host different from the dialed name is denied".to_owned())
}

fn b05(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "a03")?;
    ctl(
        reads_all(r).contains(&format!("FIXTURE-HTTP {}", name("a03"))),
        "the A03 HTTP path did not reach the fixture",
    )?;
    leg_no_bytes(s, "b05a")?;
    leg_no_bytes(s, "b05b")?;
    let la = local(res(s, "b05a")?)?;
    let lb = local(res(s, "b05b")?)?;
    need(
        denied(s, &la, "transparent", "HTTP request has no Host header"),
        "b05a: no audit deny row for a missing Host",
    )?;
    need(
        denied(
            s,
            &lb,
            "transparent",
            "HTTP request has multiple Host headers",
        ),
        "b05b: no audit deny row for duplicate Host",
    )?;
    need(
        !ev.http.iter().any(|h| h.host.is_none()),
        "b05a: the fixture saw a request without Host",
    )?;
    need(
        !ev.http
            .iter()
            .any(|h| h.host_headers > 1 || h.host.as_deref() == Some(name("b05b").as_str())),
        "b05b: the fixture saw the duplicate-Host request",
    )?;
    Ok("HTTP request with missing or duplicate Host is denied".to_owned())
}

fn b06(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "b06")?;
    let n = name("b06");
    ctl(
        read_text(r, 0).starts_with("HTTP/1.1 200"),
        format!("the first response did not arrive ({:?})", read_text(r, 0)),
    )?;
    let second = r.data["reads"][1]["len"].as_u64().unwrap_or(0);
    need(
        second == 0,
        format!("b06: {second} bytes came back for the foreign Host"),
    )?;
    let on_conn: Vec<&HttpRec> = ev
        .http
        .iter()
        .filter(|h| h.host.as_deref() == Some(n.as_str()))
        .collect();
    need(
        on_conn.len() == 1 && on_conn[0].connection_close,
        format!(
            "b06: fixture saw {} requests for {n}, expected exactly 1 with Connection: close",
            on_conn.len()
        ),
    )?;
    need(
        !ev.http
            .iter()
            .any(|h| h.host.as_deref() == Some("other-b06.conformance.test")),
        "b06: the fixture saw the foreign Host",
    )?;
    Ok("keep-alive follow-up with a foreign Host is not forwarded".to_owned())
}

fn b07(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    let r = res(s, "b07")?;
    let n = name("b07");
    ctl(
        read_text(r, 0) == format!("FIXTURE-TLS {n}"),
        format!("the first hello was not answered ({:?})", read_text(r, 0)),
    )?;
    need(
        matches!(read_end(r, 1).as_str(), "eof" | "reset") || r.data["write_errno"].is_number(),
        format!(
            "b07: the second hello was not torn down (second read {:?})",
            read_end(r, 1)
        ),
    )?;
    let conns = tls_with(ev, &n);
    need(
        conns.len() == 1,
        format!(
            "b07: fixture saw {} connections with SNI {n}, expected 1",
            conns.len()
        ),
    )?;
    need(
        conns[0].extra_handshake == 0,
        format!(
            "b07: fixture saw {} extra handshake records",
            conns[0].extra_handshake
        ),
    )?;
    let l = local(r)?;
    need(
        s.audit.iter().any(|x| {
            x["event"] == "deny"
                && x["client"].as_str() == Some(l.as_str())
                && x["verdict"] == "teardown"
                && x["reason"]
                    .as_str()
                    .is_some_and(|t| t.contains(TORN_DOWN_SECOND_HELLO))
        }),
        "b07: no audit teardown row for the second ClientHello",
    )?;
    Ok("second ClientHello on an allowed connection tears it down".to_owned())
}

fn b08(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    leg_no_bytes(s, "b08")?;
    let l = local(res(s, "b08")?)?;
    need(
        denied(
            s,
            &l,
            "transparent",
            "TLS ClientHello offers encrypted_client_hello (ECH); denied in v1",
        ),
        "b08: no audit deny row for ECH",
    )?;
    need(
        tls_with(ev, &name("b08")).is_empty(),
        "b08: the fixture saw the ECH hello",
    )?;
    Ok("ClientHello offering ECH is denied".to_owned())
}

fn b09(ev: &Ev<'_>) -> R {
    let s = l2_scn(ev)?;
    let r = res(s, "b09")?;
    ctl(
        read_text(r, 0).starts_with("HTTP/1.1 200"),
        format!("CONNECT did not return 200 ({:?})", read_text(r, 0)),
    )?;
    need(
        r.data["reads"][1]["len"].as_u64().unwrap_or(0) == 0,
        "b09: bytes came back for a mismatched SNI",
    )?;
    let l = local(r)?;
    let want = format!(
        "SNI other-b09.conformance.test does not match the CONNECT target name {}",
        name("b09")
    );
    need(
        denied(s, &l, "explicit-connect", &want),
        format!("b09: no audit deny row: {want}"),
    )?;
    need(
        tls_with(ev, "other-b09.conformance.test").is_empty(),
        "b09: the fixture saw SNI other-b09",
    )?;
    Ok("explicit CONNECT with a mismatched inner SNI is closed".to_owned())
}

fn c02(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    leg_no_bytes(s, "c02")?;
    let l = local(res(s, "c02")?)?;
    need(
        denied(
            s,
            &l,
            "transparent",
            &format!("unknown fake IP {LAB_IP} (no DNS-map entry)"),
        ),
        "c02: no audit deny row for the raw upstream IP",
    )?;
    need(
        tls_with(ev, &name("c02")).is_empty(),
        "c02: the fixture saw the direct hello",
    )?;
    Ok("direct TCP to the upstream IP never reaches it".to_owned())
}

fn c07(ev: &Ev<'_>) -> R {
    let s = l1_scn(ev)?;
    a02_control(ev)?;
    for id in ["c07a", "c07b", "c07c", "c07d"] {
        need(
            res(s, id)?.ok,
            format!("c07: probe query {id} did not complete"),
        )?;
    }
    // The probe's queries for these (name, qtype) pairs were answered by the
    // fake DNS; none may have reached the lab DNS.
    let forbidden = [
        (format!("c07-{}.conformance.test", ev.nonce), "A"),
        ("allowed.conformance.test".to_owned(), "TXT"),
        (format!("x{}.c07.allowed.conformance.test", ev.nonce), "A"),
        ("c07.allowed.conformance.test".to_owned(), "AAAA"),
    ];
    for (n, t) in &forbidden {
        let hit = ev.dns.iter().any(|d| &d.name == n && d.qtype == *t);
        need(
            !hit,
            format!("c07: the lab DNS received {t} {n} (a forwarded query)"),
        )?;
    }
    // Control: the proxy's own dial did reach the lab DNS.
    let control = ev
        .dns
        .iter()
        .any(|d| d.name == name("a02") && d.qtype == "A");
    ctl(
        control,
        "the lab DNS log has no A query for a02 (the dial's own resolution)",
    )?;
    Ok("DNS queries are never forwarded upstream".to_owned())
}

/// The `seen` control of a signal scenario: the loop reached the fixture.
fn seen_control(s: &Scn) -> Result<(), F> {
    match s.ctl.get("seen") {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(ctl_fail(e.clone())),
        None => Err(ctl_fail("seen not recorded")),
    }
}

/// A recorded number of a scenario (missing is a control failure).
fn num(s: &Scn, key: &'static str) -> Result<u64, F> {
    s.nums
        .get(key)
        .copied()
        .ok_or_else(|| ctl_fail(format!("{key} not recorded")))
}

/// Timestamps must not run backwards (the monotonic clock is the evidence clock).
fn clock_control(t_sig: u64, t_kill: u64) -> Result<(), F> {
    ctl(
        t_kill >= t_sig,
        format!("clock went backwards: t_kill {t_kill} < t_signal {t_sig}"),
    )
}

fn f02(ev: &Ev<'_>) -> R {
    let s = sc(ev.s, "F02")?;
    seen_control(s)?;
    let t_sig = num(s, "t_signal")?;
    let t_kill = num(s, "t_kill")?;
    clock_control(t_sig, t_kill)?;
    // Everything below was read at observation time, before cleanup.
    let held_count = num(s, "held_count")?;
    ctl(
        held_count == 1,
        format!("expected one connection carrying HOLD-f02 at observation, found {held_count}"),
    )?;
    let held_accept = num(s, "held_accept")?;
    let held_close = num(s, "held_close")?;
    ctl(
        held_accept <= t_sig,
        format!("held connection accepted after the signal ({held_accept} > {t_sig})"),
    )?;
    ctl(
        held_close == u64::MAX || held_close >= t_sig,
        format!("held connection closed before the signal ({held_close} < {t_sig})"),
    )?;
    let late = num(s, "late_accepts")?;
    need(
        late == 0,
        format!("f02: {late} new upstream connections after the SIGKILL"),
    )?;
    need(
        held_close != u64::MAX && held_close <= t_kill + 1500,
        "f02: the held upstream connection was still open 1.5 s after the SIGKILL (observed at +2 s, before cleanup)",
    )?;
    s.ctl
        .get("gone")
        .cloned()
        .unwrap_or(Err("gone not recorded".to_owned()))
        .map_err(fail)?;
    Ok("after SIGKILL the upstream sees no new connection, held one EOFs".to_owned())
}

fn f04(ev: &Ev<'_>) -> R {
    let s = sc(ev.s, "F04")?;
    seen_control(s)?;
    let t_stop = num(s, "t_signal")?;
    let t_kill = num(s, "t_kill")?;
    clock_control(t_stop, t_kill)?;
    let attempts = num(s, "stop_attempts")?;
    ctl(
        attempts >= 3,
        format!("only {attempts} probe attempts logged inside the stop window"),
    )?;
    let during = num(s, "late_accepts")?;
    need(
        during == 0,
        format!("f04: {during} upstream connections while sbx run was stopped or after the kill"),
    )?;
    s.ctl
        .get("gone")
        .cloned()
        .unwrap_or(Err("gone not recorded".to_owned()))
        .map_err(fail)?;
    Ok("SIGSTOP of sbx run lets no connection through".to_owned())
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{TRAP_META, TRAP_PRIVATE};
    use super::*;

    #[test]
    fn lab_ids_are_the_nineteen() {
        assert_eq!(LAB_IDS.len(), 19);
        let mut sorted = LAB_IDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 19);
    }

    #[test]
    fn lab_ops_parse() {
        // Every op the lab scenarios build must parse (a silently dropped op
        // would only surface later as a missing result).
        let ops = l1_ops("0123abcd");
        assert!(ops.len() >= 20);
        assert!(
            ops.iter()
                .all(|o| !matches!(o, Op::Sleep { id, .. } if id == "malformed"))
        );
    }

    #[test]
    fn dial_reason_uses_the_guard_text() {
        assert_eq!(
            dial_reason(Ipv4Addr::LOCALHOST),
            "denied dial to 127.0.0.1:443: loopback address (127.0.0.0/8, ::1/128)"
        );
        assert!(dial_reason(TRAP_PRIVATE).starts_with("denied dial to 10.0.0.1:443: "));
        assert!(dial_reason(TRAP_META).starts_with("denied dial to 169.254.169.254:443: "));
    }
}
