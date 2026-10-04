//! Atomic nftables ruleset load + post-load dump verification.
//!
//! Batch layout (design D5; one `writev`, all-or-nothing kernel transaction,
//! empirical fact F6):
//!
//! ```text
//! BATCH_BEGIN(+genid) NEWTABLE sbx NEWCHAIN nat_out NEWCHAIN filter_out
//! NEWRULE x3 (CREATE|APPEND) BATCH_END
//! ```
//!
//! Byte-exact ground truth (captured from `nft` 1.0.9 via raw netlink dumps)
//! lives in `../rules/ground-truth.md`. Deviations from the typed API:
//!
//! * `redir` has NO generated binding — the bundled kernel YAML spec contains
//!   zero `redir` occurrences. It is hand-encoded through the public
//!   [`netlink_bindings::traits::Pusher`] escape hatch: `push_name(c"redir")`
//!   plus a manual `NFTA_EXPR_DATA(2)` nest with big-endian u32 attributes
//!   `REG_PROTO_MIN(1)`, `REG_PROTO_MAX(2)`, `FLAGS(3)`.
//! * `fib` RESULT is pushed as raw `3` — the generated `FibResult` enum is
//!   off by one vs the kernel (empirical fact F11: the spec omits
//!   `NFT_FIB_RESULT_UNSPEC=0`, so `FibResult::Addrtype == 2` while the
//!   kernel stores addrtype as 3).

use std::ffi::CStr;

use netlink_bindings::nftables::{self, ExprOps, Nfgenmsg, Registers};
use netlink_bindings::traits::Pusher;
use netlink_bindings::utils;
use netlink_socket2::NetlinkSocket;

use crate::consts::{ERESTART, EXIT_BREAK_ACCEPTED, EXIT_RULES, EXIT_VERIFY};
use crate::report::TestResult;
use crate::Fail;

const TABLE: &CStr = c"sbx";
const CHAIN_NAT: &CStr = c"nat_out";
const CHAIN_FILTER: &CStr = c"filter_out";
/// Only used with `--break-rules`: a rule targeting this nonexistent chain
/// makes the kernel reject the whole batch with ENOENT (fact F6).
const CHAIN_MISSING: &CStr = c"sbx_no_such_chain";

const NF_INET_LOCAL_OUT: u32 = 3;
const PRIO_DSTNAT: i32 = -100; // `priority dstnat`; must run before filter (F2)
const PRIO_FILTER: i32 = 0; // `priority filter`
const POLICY_ACCEPT: u32 = 1; // NF_ACCEPT
const POLICY_DROP: u32 = 0; // NF_DROP

/// Raw kernel value of `NFT_FIB_RESULT_ADDRTYPE`. NEVER use the generated
/// `FibResult::Addrtype` (== 2) on the wire — see module docs (F11).
const FIB_RESULT_ADDRTYPE_RAW: u32 = 3;
/// `NFT_FIB_F_DADDR` — look up by destination address.
const FIB_FLAGS_DADDR: u32 = 2;

const IP_PROTO_TCP: [u8; 1] = [0x06];
const IP_PROTO_UDP: [u8; 1] = [0x11];
/// `fib daddr type` result register holds a 4-byte route type; nft pads the
/// compare value to register width (ground-truth.md): `RTN_LOCAL` = 2.
const RTN_LOCAL: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
/// 15001 in big-endian (network order), as stored by `immediate`.
const PORT_15001_BE: [u8; 2] = [0x3a, 0x99];
/// 53 in big-endian.
const PORT_53_BE: [u8; 2] = [0x00, 0x35];
/// `oifname "lo"` compare value: 16 bytes, NUL-padded.
const OIFNAME_LO: [u8; 16] = [b'l', b'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// `NF_NAT_RANGE_PROTO_SPECIFIED` — redir uses the registers for the port.
const REDIR_FLAGS_PROTO_SPECIFIED: u32 = 2;

/// genid/ERESTART retry budget (design D5).
const MAX_BATCH_ATTEMPTS: u32 = 5;

/// Outcome of a successful [`load`].
pub struct LoadStats {
    pub genid: u32,
    pub attempts: u32,
}

fn rules_fail(msg: String) -> Fail {
    Fail::new(EXIT_RULES, format!("rules: {msg}"))
}

fn verify_fail(msg: String) -> Fail {
    Fail::new(EXIT_VERIFY, format!("verify-dump: {msg}"))
}

fn msg_header() -> Nfgenmsg {
    Nfgenmsg {
        nfgen_family: libc::AF_INET as u8,
        ..Default::default()
    }
}

fn batch_header() -> Nfgenmsg {
    let mut h = Nfgenmsg::new();
    h.set_res_id(10); // NFNL_SUBSYS_NFTABLES
    h
}

/// Latest ruleset generation id (used to detect concurrent modification).
fn get_genid(sock: &mut NetlinkSocket) -> Result<u32, Fail> {
    let req = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
    let mut iter = sock
        .request(&req)
        .map_err(|e| rules_fail(format!("getgen request: {e}")))?;
    let (_, attrs) = iter
        .recv_one()
        .map_err(|e| rules_fail(format!("getgen reply: {e}")))?;
    attrs
        .get_id()
        .map_err(|e| rules_fail(format!("getgen id: {e}")))
}

/// Build the full transaction buffer. `break_rules` appends a rule targeting
/// a nonexistent chain, which the kernel must reject (ENOENT) while rolling
/// back everything else in the same batch (F6).
fn build_batch(seq: u32, genid: u32, break_rules: bool) -> nftables::ChainedFinal<'static> {
    let mut c = nftables::Chained::new(seq);

    c.request()
        .op_batch_begin_do(&batch_header())
        .encode()
        .push_genid(genid);

    c.request()
        .op_newtable_do(&msg_header())
        .encode()
        .push_name(TABLE);

    // nat_out: type nat hook output priority dstnat(-100), policy accept.
    // Priority -100 < 0 is load-bearing: the nat chain must run BEFORE the
    // filter chain (policy drop) — empirical fact F2.
    c.request()
        .op_newchain_do(&msg_header())
        .encode()
        .push_table(TABLE)
        .push_name(CHAIN_NAT)
        .nested_hook()
        .push_num(NF_INET_LOCAL_OUT)
        .push_priority(PRIO_DSTNAT)
        .end_nested()
        .push_policy(POLICY_ACCEPT)
        .push_type(c"nat");

    // filter_out: type filter hook output priority filter(0), policy DROP.
    // The drop policy is the fail-closed default; rule 3 is the only accept.
    c.request()
        .op_newchain_do(&msg_header())
        .encode()
        .push_table(TABLE)
        .push_name(CHAIN_FILTER)
        .nested_hook()
        .push_num(NF_INET_LOCAL_OUT)
        .push_priority(PRIO_FILTER)
        .end_nested()
        .push_policy(POLICY_DROP)
        .push_type(c"filter");

    // Rule 1 (nat_out): meta l4proto == tcp && fib daddr type != local
    //   => reg1 = 15001 (BE) => redir proto_min=proto_max=reg1.
    let mut r = c
        .request()
        .set_create()
        .set_append()
        .op_newrule_do(&msg_header());
    let list = r
        .encode()
        .push_table(TABLE)
        .push_chain(CHAIN_NAT)
        .nested_expressions();
    let list = list
        .nested_elem()
        .nested_data_meta()
        .push_dreg(Registers::Reg1 as u32)
        .push_key(nftables::MetaKeys::L4Proto as u32)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Eq as u32)
        .nested_data()
        .push_value(&IP_PROTO_TCP)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_fib()
        .push_dreg(Registers::Reg1 as u32)
        // F11: raw kernel value 3 (addrtype). The generated FibResult enum
        // says Addrtype == 2 because the YAML spec lacks UNSPEC — do NOT use
        // `FibResult::Addrtype as u32` here.
        .push_result(FIB_RESULT_ADDRTYPE_RAW)
        .push_flags(FIB_FLAGS_DADDR)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Neq as u32)
        .nested_data()
        .push_value(&RTN_LOCAL)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(Registers::Reg1 as u32)
        .nested_data()
        .push_value(&PORT_15001_BE)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = push_redir(list, false);
    let _ = list.end_nested(); // NFTA_RULE_EXPRESSIONS

    // Rule 2 (nat_out): meta l4proto == udp && payload th dport == 53
    //   => bare redir (empty data nest — destination port preserved).
    let mut r = c
        .request()
        .set_create()
        .set_append()
        .op_newrule_do(&msg_header());
    let list = r
        .encode()
        .push_table(TABLE)
        .push_chain(CHAIN_NAT)
        .nested_expressions();
    let list = list
        .nested_elem()
        .nested_data_meta()
        .push_dreg(Registers::Reg1 as u32)
        .push_key(nftables::MetaKeys::L4Proto as u32)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Eq as u32)
        .nested_data()
        .push_value(&IP_PROTO_UDP)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_payload()
        .push_dreg(Registers::Reg1 as u32)
        .push_base(nftables::PayloadBase::TransportHeader as u32)
        .push_offset(2) // UDP dport
        .push_len(2)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Eq as u32)
        .nested_data()
        .push_value(&PORT_53_BE)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = push_redir(list, true);
    let _ = list.end_nested(); // NFTA_RULE_EXPRESSIONS

    // Rule 3 (filter_out): oifname "lo" && fib daddr type local => accept.
    // Exact complement of the nat redirect condition (design D2): everything
    // else hits the chain's drop policy.
    let mut r = c
        .request()
        .set_create()
        .set_append()
        .op_newrule_do(&msg_header());
    let list = r
        .encode()
        .push_table(TABLE)
        .push_chain(CHAIN_FILTER)
        .nested_expressions();
    let list = list
        .nested_elem()
        .nested_data_meta()
        .push_dreg(Registers::Reg1 as u32)
        .push_key(nftables::MetaKeys::Oifname as u32)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Eq as u32)
        .nested_data()
        .push_value(&OIFNAME_LO)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_fib()
        .push_dreg(Registers::Reg1 as u32)
        .push_result(FIB_RESULT_ADDRTYPE_RAW) // F11: raw 3, see rule 1.
        .push_flags(FIB_FLAGS_DADDR)
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_cmp()
        .push_sreg(Registers::Reg1 as u32)
        .push_op(nftables::CmpOps::Eq as u32)
        .nested_data()
        .push_value(&RTN_LOCAL)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = list
        .nested_elem()
        .nested_data_immediate()
        .push_dreg(Registers::RegVerdict as u32)
        .nested_data()
        .nested_verdict()
        .push_code(nftables::VerdictCode::Accept as u32)
        .end_nested()
        .end_nested()
        .end_nested()
        .end_nested();
    let _ = list.end_nested(); // NFTA_RULE_EXPRESSIONS

    if break_rules {
        // Deliberately broken rule: target chain does not exist and is not
        // created by this batch => kernel rejects with ENOENT and rolls the
        // whole batch back (F6).
        let mut r = c
            .request()
            .set_create()
            .set_append()
            .op_newrule_do(&msg_header());
        let list = r
            .encode()
            .push_table(TABLE)
            .push_chain(CHAIN_MISSING)
            .nested_expressions();
        let list = list
            .nested_elem()
            .nested_data_immediate()
            .push_dreg(Registers::RegVerdict as u32)
            .nested_data()
            .nested_verdict()
            .push_code(nftables::VerdictCode::Accept as u32)
            .end_nested()
            .end_nested()
            .end_nested()
            .end_nested();
        let _ = list.end_nested();
    }

    c.request().op_batch_end_do(&batch_header());

    c.finalize()
}

/// Hand-encode the `redir` expression into an open `NFTA_RULE_EXPRESSIONS`
/// list. The kernel-stored bytes are identical to the `nft` 1.0.9-loaded
/// reference (raw GETRULE dump in rules/ground-truth.md §5; intra-nest
/// attribute order in the request direction may differ and is irrelevant —
/// the kernel parses by type):
///
/// ```text
/// NFTA_LIST_ELEM(1) nest {
///   NFTA_EXPR_NAME(1) = "redir\0"
///   NFTA_EXPR_DATA(2) nest {                 # bare=true: EMPTY nest
///     NFTA_REDIR_REG_PROTO_MIN(1) = 1 (BE)   # Reg1
///     NFTA_REDIR_REG_PROTO_MAX(2) = 1 (BE)   # Reg1
///     NFTA_REDIR_FLAGS(3)         = 2 (BE)   # NF_NAT_RANGE_PROTO_SPECIFIED
///   }
/// }
/// ```
fn push_redir<Prev: Pusher>(
    list: nftables::PushExprListAttrs<Prev>,
    bare: bool,
) -> nftables::PushExprListAttrs<Prev> {
    let mut expr = list.nested_elem().push_name(c"redir");
    {
        // Public escape hatch: Pusher::as_vec_mut + utils header helpers.
        let buf = expr.as_vec_mut();
        let data_off = utils::push_nested_header(buf, 2); // NFTA_EXPR_DATA
        if !bare {
            push_attr_be_u32(buf, 1, Registers::Reg1 as u32); // REG_PROTO_MIN
            push_attr_be_u32(buf, 2, Registers::Reg1 as u32); // REG_PROTO_MAX
            push_attr_be_u32(buf, 3, REDIR_FLAGS_PROTO_SPECIFIED); // FLAGS
        }
        utils::finalize_nested_header(buf, data_off);
    }
    expr.end_nested()
}

fn push_attr_be_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    utils::push_header(buf, attr_type, 4);
    buf.extend_from_slice(&value.to_be_bytes());
}

/// Send one chained batch; map the outcome to `(errno, display)`.
fn send_batch(
    sock: &mut NetlinkSocket,
    batch: &nftables::ChainedFinal<'static>,
) -> Result<(), (Option<i32>, String)> {
    let mut reply = sock
        .request_chained(batch)
        .map_err(|e| (e.raw_os_error(), e.to_string()))?;
    reply
        .recv_all()
        .map_err(|e| (e.as_io_error().raw_os_error(), e.to_string()))
}

/// Load the sandbox ruleset atomically. Retries up to [`MAX_BATCH_ATTEMPTS`]
/// times on ERESTART (genid raced with another ruleset modification); any
/// other failure => exit 3 (fail closed, design D5).
pub fn load(sock: &mut NetlinkSocket, verbose: bool) -> Result<LoadStats, Fail> {
    for attempt in 1..=MAX_BATCH_ATTEMPTS {
        let genid = get_genid(sock)?;
        let batch = build_batch(sock.reserve_seq(256), genid, false);
        match send_batch(sock, &batch) {
            Ok(()) => {
                if verbose {
                    eprintln!("[rules] batch committed (genid {genid}, attempt {attempt})");
                }
                return Ok(LoadStats {
                    genid,
                    attempts: attempt,
                });
            }
            Err((errno, msg)) => {
                if errno == Some(ERESTART) {
                    if attempt < MAX_BATCH_ATTEMPTS {
                        eprintln!(
                            "[status] batch rejected with ERESTART (genid race), retrying \
                             ({attempt}/{MAX_BATCH_ATTEMPTS}): {msg}"
                        );
                        continue;
                    }
                    // Budget exhausted: dedicated error (not the generic one).
                    return Err(rules_fail(format!(
                        "batch still rejected with ERESTART after {MAX_BATCH_ATTEMPTS} attempts \
                         (ruleset keeps changing underneath us; last genid {genid}): {msg}"
                    )));
                }
                return Err(rules_fail(format!(
                    "batch failed (attempt {attempt}/{MAX_BATCH_ATTEMPTS}, genid {genid}): {msg}"
                )));
            }
        }
    }
    unreachable!("every path in the loop returns or retries on the final attempt");
}

/// `--break-rules`: load a deliberately broken batch, require the kernel to
/// reject it with the ADJUDICATED error (ENOENT on the missing chain — F6)
/// AND roll back the whole transaction. Returns the process exit code plus
/// a report entry:
/// * rejected with ENOENT + nothing committed => print
///   `FAIL-CLOSED-VERIFIED: <err>` on stderr, exit 3 (the expected, passing
///   outcome for this mode);
/// * rejected with an unexpected errno (incl. exhausted ERESTART — the batch
///   was never adjudicated) => exit 3 WITHOUT the marker
///   (`FAIL-CLOSED-NOT-VERIFIED`), so CI marker greps stay meaningful;
/// * batch accepted, or rejected but tables survived => fail-closed violated
///   => exit 7.
pub fn prove_fail_closed(sock: &mut NetlinkSocket, verbose: bool) -> (i32, TestResult) {
    for attempt in 1..=MAX_BATCH_ATTEMPTS {
        let genid = match get_genid(sock) {
            Ok(g) => g,
            Err(f) => return (f.code, TestResult::failed("fail-closed", f.msg)),
        };
        let batch = build_batch(sock.reserve_seq(256), genid, true);
        if verbose {
            eprintln!(
                "[rules] sending broken batch (rule -> {CHAIN_MISSING:?}), \
                 genid {genid}, attempt {attempt}"
            );
        }
        match send_batch(sock, &batch) {
            Ok(()) => {
                return (
                    EXIT_BREAK_ACCEPTED,
                    TestResult::failed(
                        "fail-closed",
                        "broken batch was ACCEPTED by the kernel — fail-closed NOT verified",
                    ),
                );
            }
            Err((errno, err)) => {
                if errno == Some(ERESTART) {
                    // ERESTART means the batch was never adjudicated (genid
                    // race) — retry instead of treating it as proof.
                    if attempt < MAX_BATCH_ATTEMPTS {
                        eprintln!(
                            "[status] broken batch hit ERESTART (not adjudicated), \
                             retrying ({attempt}/{MAX_BATCH_ATTEMPTS})"
                        );
                        continue;
                    }
                    let msg = format!(
                        "FAIL-CLOSED-NOT-VERIFIED: broken batch still hit ERESTART after \
                         {MAX_BATCH_ATTEMPTS} attempts — never adjudicated: {err}"
                    );
                    eprintln!("{msg}");
                    return (EXIT_RULES, TestResult::failed("fail-closed", msg));
                }
                if errno != Some(libc::ENOENT) {
                    // F6's expected rejection is ENOENT (rule -> nonexistent
                    // chain). Any other errno means the proof did not exercise
                    // the intended failure path — do NOT print the marker.
                    let msg = format!(
                        "FAIL-CLOSED-NOT-VERIFIED: broken batch rejected with unexpected \
                         errno {errno:?} (expected ENOENT={}): {err}",
                        libc::ENOENT
                    );
                    eprintln!("{msg}");
                    return (EXIT_RULES, TestResult::failed("fail-closed", msg));
                }
                return match table_names(sock) {
                    Ok(names) if names.is_empty() => {
                        eprintln!("FAIL-CLOSED-VERIFIED: batch rejected and rolled back: {err}");
                        (
                            EXIT_RULES,
                            TestResult::passed(
                                "fail-closed",
                                format!(
                                    "FAIL-CLOSED-VERIFIED: batch rejected and rolled back: {err}"
                                ),
                            ),
                        )
                    }
                    Ok(names) => (
                        // Rejected, but objects from the same batch survived:
                        // the all-or-nothing property (F6) does not hold —
                        // treat like an unexpected acceptance (fail-closed
                        // violated).
                        EXIT_BREAK_ACCEPTED,
                        TestResult::failed(
                            "fail-closed",
                            format!(
                                "batch rejected ({err}) but tables survived rollback: {names:?}"
                            ),
                        ),
                    ),
                    Err(f) => (
                        EXIT_BREAK_ACCEPTED,
                        TestResult::failed(
                            "fail-closed",
                            format!(
                                "batch rejected ({err}) but rollback check failed: {}",
                                f.msg
                            ),
                        ),
                    ),
                };
            }
        }
    }
    unreachable!("every path in the loop returns or retries on the final attempt");
}

/// GETTABLE dump => names of all ip-family tables.
fn table_names(sock: &mut NetlinkSocket) -> Result<Vec<String>, Fail> {
    let req = nftables::Request::new().op_gettable_dump(&msg_header());
    let mut iter = sock
        .request(&req)
        .map_err(|e| rules_fail(format!("gettable dump: {e}")))?;
    let mut names = Vec::new();
    while let Some(res) = iter.recv() {
        let (_, attrs) = res.map_err(|e| rules_fail(format!("gettable dump: {e}")))?;
        names.push(
            attrs
                .get_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unparsable>".into()),
        );
    }
    Ok(names)
}

// ---------------------------------------------------------------------------
// Post-load dump verification (exit 4 on any mismatch)
// ---------------------------------------------------------------------------

/// One decoded expression: `(name, canonical detail string)`. The detail
/// format is fixed so that rules compare byte-exactly against the expected
/// tables derived from rules/ground-truth.md.
type DecodedExpr = (String, String);

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Verify the loaded ruleset via GETCHAIN + GETRULE dumps. Collects
/// human-readable lines; with `dump_rules` they are printed to stderr
/// (stdout is reserved for the report / JSON object).
pub fn verify_dump(sock: &mut NetlinkSocket, dump_rules: bool, verbose: bool) -> Result<(), Fail> {
    let mut lines: Vec<String> = Vec::new();
    verify_chains(sock, &mut lines, verbose)?;
    verify_rules(sock, &mut lines)?;
    if dump_rules {
        for l in &lines {
            eprintln!("[dump] {l}");
        }
    }
    Ok(())
}

fn verify_chains(
    sock: &mut NetlinkSocket,
    lines: &mut Vec<String>,
    verbose: bool,
) -> Result<(), Fail> {
    let mut req = nftables::Request::new().op_getchain_dump(&msg_header());
    req.encode().push_table(TABLE);
    let mut iter = sock
        .request(&req)
        .map_err(|e| verify_fail(format!("getchain dump: {e}")))?;

    let mut seen = 0u32;
    while let Some(res) = iter.recv() {
        let (_, attrs) = res.map_err(|e| verify_fail(format!("getchain dump: {e}")))?;
        let name = attrs
            .get_name()
            .map_err(|e| verify_fail(format!("chain name: {e}")))?
            .to_string_lossy()
            .into_owned();
        let hook = attrs
            .get_hook()
            .map_err(|e| verify_fail(format!("chain {name}: hook: {e}")))?;
        let num = hook
            .get_num()
            .map_err(|e| verify_fail(format!("chain {name}: hook num: {e}")))?;
        let prio = hook
            .get_priority()
            .map_err(|e| verify_fail(format!("chain {name}: hook priority: {e}")))?;
        let policy = attrs
            .get_policy()
            .map_err(|e| verify_fail(format!("chain {name}: policy: {e}")))?;
        let ctype = attrs
            .get_type()
            .map_err(|e| verify_fail(format!("chain {name}: type: {e}")))?
            .to_string_lossy()
            .into_owned();

        // Chain counters are opportunistic only (F5: presence varies by
        // kernel; WSL2 6.18 dumps none). Log, never assert.
        match attrs.get_counters() {
            Ok(c) => {
                let packets = c.get_packets().unwrap_or(0);
                let bytes = c.get_bytes().unwrap_or(0);
                if verbose {
                    eprintln!("[verify] chain {name} counters: packets={packets} bytes={bytes}");
                }
            }
            Err(_) => {
                if verbose {
                    eprintln!("[verify] chain {name}: no counters attribute (F5, informational)");
                }
            }
        }

        lines.push(format!(
            "chain {name}: hook num={num} priority={prio} policy={policy} type={ctype:?}"
        ));

        let expected = match name.as_str() {
            "nat_out" => (NF_INET_LOCAL_OUT, PRIO_DSTNAT, POLICY_ACCEPT, "nat"),
            "filter_out" => (NF_INET_LOCAL_OUT, PRIO_FILTER, POLICY_DROP, "filter"),
            other => {
                return Err(verify_fail(format!("unexpected chain {other:?} in dump")));
            }
        };
        let (e_num, e_prio, e_policy, e_type) = expected;
        if (num, prio, policy, ctype.as_str()) != (e_num, e_prio, e_policy, e_type) {
            return Err(verify_fail(format!(
                "chain {name}: got hook num={num} priority={prio} policy={policy} type={ctype:?}, \
                 expected num={e_num} priority={e_prio} policy={e_policy} type={e_type:?}"
            )));
        }
        seen += 1;
    }
    if seen != 2 {
        return Err(verify_fail(format!(
            "expected 2 chains, dump returned {seen}"
        )));
    }
    Ok(())
}

fn verify_rules(sock: &mut NetlinkSocket, lines: &mut Vec<String>) -> Result<(), Fail> {
    let mut req = nftables::Request::new().op_getrule_dump(&msg_header());
    req.encode().push_table(TABLE);
    let mut iter = sock
        .request(&req)
        .map_err(|e| verify_fail(format!("getrule dump: {e}")))?;

    let mut nat: Vec<Vec<DecodedExpr>> = Vec::new();
    let mut filter: Vec<Vec<DecodedExpr>> = Vec::new();
    while let Some(res) = iter.recv() {
        let (_, attrs) = res.map_err(|e| verify_fail(format!("getrule dump: {e}")))?;
        let chain = attrs
            .get_chain()
            .map_err(|e| verify_fail(format!("rule chain: {e}")))?
            .to_string_lossy()
            .into_owned();
        let handle = attrs
            .get_handle()
            .map_err(|e| verify_fail(format!("rule handle: {e}")))?;
        let exprs = decode_rule(&attrs)?;
        lines.push(format!(
            "rule {chain} (handle {handle}): {}",
            exprs
                .iter()
                .map(|(n, d)| format!("{n}{{{d}}}"))
                .collect::<Vec<_>>()
                .join(" -> ")
        ));
        match chain.as_str() {
            "nat_out" => nat.push(exprs),
            "filter_out" => filter.push(exprs),
            other => return Err(verify_fail(format!("rule in unexpected chain {other:?}"))),
        }
    }

    // Dump order is handle order == append order.
    if nat.len() != 2 {
        return Err(verify_fail(format!(
            "nat_out: expected 2 rules, got {}",
            nat.len()
        )));
    }
    if filter.len() != 1 {
        return Err(verify_fail(format!(
            "filter_out: expected 1 rule, got {}",
            filter.len()
        )));
    }

    // Expected expression trees — byte-exact values from
    // rules/ground-truth.md §5 (kernel dump of the nft-loaded reference).
    expect_exprs(
        "nat_out rule 1 (tcp redirect :15001)",
        &nat[0],
        &[
            ("meta", "dreg=1 key=16"),
            ("cmp", "sreg=1 op=0 value=[06]"),
            ("fib", "dreg=1 result=3 flags=2"), // F11: raw result 3
            ("cmp", "sreg=1 op=1 value=[02 00 00 00]"),
            ("immediate", "dreg=1 value=[3a 99]"),
            ("redir", "data{1=1 2=1 3=2}"),
        ],
    )?;
    expect_exprs(
        "nat_out rule 2 (udp/53 redirect)",
        &nat[1],
        &[
            ("meta", "dreg=1 key=16"),
            ("cmp", "sreg=1 op=0 value=[11]"),
            ("payload", "dreg=1 base=2 offset=2 len=2"),
            ("cmp", "sreg=1 op=0 value=[00 35]"),
            ("redir", "data{}"), // bare redirect: EMPTY data nest
        ],
    )?;
    expect_exprs(
        "filter_out rule 1 (accept lo->local)",
        &filter[0],
        &[
            ("meta", "dreg=1 key=7"),
            (
                "cmp",
                "sreg=1 op=0 value=[6c 6f 00 00 00 00 00 00 00 00 00 00 00 00 00 00]",
            ),
            ("fib", "dreg=1 result=3 flags=2"),
            ("cmp", "sreg=1 op=0 value=[02 00 00 00]"),
            ("immediate", "dreg=0 verdict.code=1"),
        ],
    )?;
    Ok(())
}

fn expect_exprs(what: &str, got: &[DecodedExpr], want: &[(&str, &str)]) -> Result<(), Fail> {
    if got.len() != want.len() {
        return Err(verify_fail(format!(
            "{what}: expected {} expressions, got {} ({got:?})",
            want.len(),
            got.len()
        )));
    }
    for (i, ((gn, gd), (wn, wd))) in got.iter().zip(want).enumerate() {
        if gn != wn || gd != wd {
            return Err(verify_fail(format!(
                "{what}: expr {i} mismatch: got {gn}{{{gd}}}, expected {wn}{{{wd}}}"
            )));
        }
    }
    Ok(())
}

/// Decode one rule's expression list into canonical `(name, detail)` pairs.
/// `redir` has no typed binding: its data nest is decoded manually from raw
/// bytes (same values the encoder wrote).
fn decode_rule(attrs: &nftables::IterableRuleAttrs<'_>) -> Result<Vec<DecodedExpr>, Fail> {
    let list = attrs
        .get_expressions()
        .map_err(|e| verify_fail(format!("expressions: {e}")))?;
    let mut out = Vec::new();
    for expr in list.get_elem() {
        let name = expr
            .get_name()
            .map_err(|e| verify_fail(format!("expr name: {e}")))?
            .to_string_lossy()
            .into_owned();
        let detail = match expr.get_data() {
            Ok(ExprOps::Meta(m)) => {
                let dreg = m
                    .get_dreg()
                    .map_err(|e| verify_fail(format!("meta dreg: {e}")))?;
                let key = m
                    .get_key()
                    .map_err(|e| verify_fail(format!("meta key: {e}")))?;
                format!("dreg={dreg} key={key}")
            }
            Ok(ExprOps::Cmp(m)) => {
                let sreg = m
                    .get_sreg()
                    .map_err(|e| verify_fail(format!("cmp sreg: {e}")))?;
                let op = m
                    .get_op()
                    .map_err(|e| verify_fail(format!("cmp op: {e}")))?;
                let data = m
                    .get_data()
                    .map_err(|e| verify_fail(format!("cmp data: {e}")))?;
                let value = data
                    .get_value()
                    .map_err(|e| verify_fail(format!("cmp value: {e}")))?;
                format!("sreg={sreg} op={op} value=[{}]", hex_bytes(value))
            }
            Ok(ExprOps::Fib(m)) => {
                let dreg = m
                    .get_dreg()
                    .map_err(|e| verify_fail(format!("fib dreg: {e}")))?;
                let result = m
                    .get_result()
                    .map_err(|e| verify_fail(format!("fib result: {e}")))?;
                let flags = m
                    .get_flags()
                    .map_err(|e| verify_fail(format!("fib flags: {e}")))?;
                // Assert the RAW kernel value (F11): addrtype == 3.
                format!("dreg={dreg} result={result} flags={flags}")
            }
            Ok(ExprOps::Payload(m)) => {
                let dreg = m
                    .get_dreg()
                    .map_err(|e| verify_fail(format!("payload dreg: {e}")))?;
                let base = m
                    .get_base()
                    .map_err(|e| verify_fail(format!("payload base: {e}")))?;
                let offset = m
                    .get_offset()
                    .map_err(|e| verify_fail(format!("payload offset: {e}")))?;
                let len = m
                    .get_len()
                    .map_err(|e| verify_fail(format!("payload len: {e}")))?;
                format!("dreg={dreg} base={base} offset={offset} len={len}")
            }
            Ok(ExprOps::Immediate(m)) => {
                let dreg = m
                    .get_dreg()
                    .map_err(|e| verify_fail(format!("immediate dreg: {e}")))?;
                let data = m
                    .get_data()
                    .map_err(|e| verify_fail(format!("immediate data: {e}")))?;
                match data.get_verdict() {
                    Ok(v) => {
                        let code = v
                            .get_code()
                            .map_err(|e| verify_fail(format!("verdict code: {e}")))?;
                        format!("dreg={dreg} verdict.code={code}")
                    }
                    Err(_) => {
                        let value = data
                            .get_value()
                            .map_err(|e| verify_fail(format!("immediate value: {e}")))?;
                        format!("dreg={dreg} value=[{}]", hex_bytes(value))
                    }
                }
            }
            // `redir` is not in the generated spec: get_data() fails; decode
            // the raw NFTA_EXPR_DATA nest by hand.
            Err(_) if name == "redir" => decode_redir_raw(expr.get_buf())?,
            Ok(other) => {
                return Err(verify_fail(format!(
                    "unexpected typed expression {name}: {other:?}"
                )))
            }
            Err(e) => return Err(verify_fail(format!("expr {name}: undecodable data: {e}"))),
        };
        out.push((name, detail));
    }
    Ok(out)
}

/// Manual decode of a redir expression's raw bytes: find NFTA_EXPR_DATA(2)
/// and render its u32be children as `data{<type>=<value> ...}` (empty nest
/// renders as `data{}`).
fn decode_redir_raw(buf: &[u8]) -> Result<String, Fail> {
    for (hdr, data) in utils::IterableChunks::new(buf) {
        if hdr.r#type != 2 {
            continue;
        }
        let mut parts = Vec::new();
        for (ihdr, idata) in utils::IterableChunks::new(data) {
            let value = u32::from_be_bytes(idata.try_into().map_err(|_| {
                verify_fail(format!(
                    "redir attr {}: expected 4 bytes, got {}",
                    ihdr.r#type,
                    idata.len()
                ))
            })?);
            parts.push(format!("{}={value}", ihdr.r#type));
        }
        return Ok(format!("data{{{}}}", parts.join(" ")));
    }
    Err(verify_fail("redir: no NFTA_EXPR_DATA nest".into()))
}
