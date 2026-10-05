//! Atomic nftables ruleset load + post-load dump verification (issue #5).
//!
//! Ported from the issue #1 spike (`spikes/nft-load/src/rules.rs`) behind the
//! production error vocabulary: staged [`InitError`]s replace the spike's
//! exit codes 3/4, and the report/selftest plumbing is gone — the runtime
//! proof is [`verify_dump`], the byte-level proof is the golden unit tests
//! below, and the end-to-end proof is `tests/sandbox_init.rs`.
//!
//! Batch layout (one `writev`, all-or-nothing kernel transaction — spike
//! empirical fact F6):
//!
//! ```text
//! BATCH_BEGIN(+genid) NEWTABLE sbx NEWCHAIN nat_out NEWCHAIN filter_out
//! NEWRULE x3 (CREATE|APPEND) BATCH_END
//! ```
//!
//! Byte-exact ground truth (captured from `nft` 1.0.9 via raw netlink dumps)
//! lives in `spikes/nft-load/rules/ground-truth.md`. Deviations from the
//! crate's typed API (both spike-proven, both test-enforced here):
//!
//! * `redir` has NO generated binding — the bundled kernel YAML spec contains
//!   zero `redir` occurrences. It is hand-encoded through the public
//!   [`netlink_bindings::traits::Pusher`] escape hatch: `push_name(c"redir")`
//!   plus a manual `NFTA_EXPR_DATA(2)` nest with big-endian u32 attributes
//!   `REG_PROTO_MIN(1)`, `REG_PROTO_MAX(2)`, `FLAGS(3)`.
//! * `fib` RESULT is pushed as raw `3` — the generated `FibResult` enum is
//!   off by one vs the kernel (spike empirical fact F11: the spec omits
//!   `NFT_FIB_RESULT_UNSPEC=0`, so `FibResult::Addrtype == 2` while the
//!   kernel stores addrtype as 3). `fib_result_raw_pin` is the meta-test
//!   that fails loudly if the crate ever fixes the spec.
//!
//! Encoding note pinned by the golden tests (risk R15): request nests carry
//! the `NLA_F_NESTED` (0x8000) bit that kernel-stored dumps in
//! ground-truth.md show stripped, and intra-nest attribute order may differ
//! from nft's (the kernel parses by type). The unit tests therefore pin
//! OUR request encoding byte-for-byte ([`build_batch`] is pure, and
//! `request_chained` writes exactly `ChainedFinal::buf()` in one writev —
//! the goldens ARE the bytes the kernel sees); ground-truth.md remains the
//! semantic reference and [`verify_dump`] remains the runtime kernel-side
//! proof.

use std::ffi::CStr;

use netlink_bindings::nftables::{self, ExprOps, Nfgenmsg, Registers};
use netlink_bindings::traits::Pusher;
use netlink_bindings::utils;
use netlink_socket2::NetlinkSocket;

use super::consts::{DNS_UDP_PORT, ERESTART, TRANSPARENT_TCP_PORT};
use super::{InitError, Stage};

const TABLE: &CStr = c"sbx";
const CHAIN_NAT: &CStr = c"nat_out";
const CHAIN_FILTER: &CStr = c"filter_out";
/// Only used with `--test-break-rules`: a rule targeting this nonexistent
/// chain makes the kernel reject the whole batch with ENOENT and roll
/// everything back (spike fact F6) — the only way to inject a rules-load
/// failure into a fresh netns from the outside (design Q4(a)).
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
/// `oifname "lo"` compare value: 16 bytes, NUL-padded.
const OIFNAME_LO: [u8; 16] = [b'l', b'o', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// `NF_NAT_RANGE_PROTO_SPECIFIED` — redir uses the registers for the port.
const REDIR_FLAGS_PROTO_SPECIFIED: u32 = 2;

/// The redirect target port in big-endian (network order), as `immediate`
/// stores it — DERIVED from the protocol constant so the wire bytes and
/// [`TRANSPARENT_TCP_PORT`] can never drift (single source of truth;
/// `port_be_consts_derive_from_ports` pins the bytes).
const PORT_REDIR_BE: [u8; 2] = TRANSPARENT_TCP_PORT.to_be_bytes();
/// The DNS port in big-endian — derived like [`PORT_REDIR_BE`].
const PORT_DNS_BE: [u8; 2] = DNS_UDP_PORT.to_be_bytes();

/// genid/ERESTART retry budget (spike design D5).
const MAX_BATCH_ATTEMPTS: u32 = 5;

/// Outcome of a successful [`load`] — retained (design D20) for #10's
/// startup/audit notes: the committed generation id and how many attempts
/// the ERESTART retry loop needed.
pub struct LoadStats {
    /// The ruleset generation id the committed batch carried.
    pub genid: u32,
    /// Which attempt committed (1 = no ERESTART race).
    pub attempts: u32,
}

fn load_fail(reason: impl Into<String>) -> InitError {
    InitError::new(Stage::NftLoad, reason)
}

fn verify_fail(reason: impl Into<String>) -> InitError {
    InitError::new(Stage::NftVerify, reason)
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
fn get_genid(sock: &mut NetlinkSocket) -> Result<u32, InitError> {
    let req = nftables::Request::new().op_getgen_do(&Nfgenmsg::new());
    let mut iter = sock
        .request(&req)
        .map_err(|e| load_fail(format!("getgen request: {e}")))?;
    let (_, attrs) = iter
        .recv_one()
        .map_err(|e| load_fail(format!("getgen reply: {e}")))?;
    attrs
        .get_id()
        .map_err(|e| load_fail(format!("getgen id: {e}")))
}

/// ERESTART classification, pure for the unit test: nfnetlink rejects a
/// batch with the kernel-internal errno 85 when the ruleset generation id
/// changed between GETGEN and commit — retryable, unlike every other error.
fn is_erestart(errno: Option<i32>) -> bool {
    errno == Some(ERESTART)
}

/// Build the FULL transaction buffer — a pure function of
/// `(seq, genid, break_rules)`, no I/O, byte-level unit-testable via the
/// public `ChainedFinal::buf()` (which `request_chained` writes verbatim in
/// one writev, so the goldens pin what the kernel sees).
///
/// `break_rules` (only reachable via the hidden test-only
/// `__init --test-break-rules` flag — fail-only by construction, it can make
/// setup fail but never weaken it) appends one NEWRULE targeting
/// `CHAIN_MISSING`: the kernel rejects the batch with ENOENT and rolls
/// everything back (F6).
pub fn build_batch(seq: u32, genid: u32, break_rules: bool) -> nftables::ChainedFinal<'static> {
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
    // filter chain (policy drop) — spike fact F2.
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
        .push_value(&PORT_REDIR_BE)
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
        .push_value(&PORT_DNS_BE)
        .end_nested()
        .end_nested()
        .end_nested();
    let list = push_redir(list, true);
    let _ = list.end_nested(); // NFTA_RULE_EXPRESSIONS

    // Rule 3 (filter_out): oifname "lo" && fib daddr type local => accept.
    // Exact complement of the nat redirect condition (spike design D2):
    // everything else hits the chain's drop policy.
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
/// list (spike-verbatim; the kernel-stored bytes are identical to the
/// `nft` 1.0.9-loaded reference — raw GETRULE dump in ground-truth.md §5):
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

/// Load the sandbox ruleset atomically, staged [`Stage::NftLoad`].
///
/// Retries up to `MAX_BATCH_ATTEMPTS` (5) times on ERESTART (the genid
/// raced with another ruleset modification — re-read, rebuild, resend);
/// every other failure is fatal (fail closed, spike design D5). The kernel
/// batch is all-or-nothing (F6): a rejected batch leaves no partial
/// ruleset.
pub fn load(sock: &mut NetlinkSocket, break_rules: bool) -> Result<LoadStats, InitError> {
    let mut last_genid = 0u32;
    let mut last_msg = String::from("no attempt reached the kernel");
    for attempt in 1..=MAX_BATCH_ATTEMPTS {
        let genid = get_genid(sock)?;
        let batch = build_batch(sock.reserve_seq(256), genid, break_rules);
        match send_batch(sock, &batch) {
            Ok(()) => {
                return Ok(LoadStats {
                    genid,
                    attempts: attempt,
                });
            }
            Err((errno, msg)) => {
                if !is_erestart(errno) {
                    return Err(load_fail(format!(
                        "batch failed (attempt {attempt}/{MAX_BATCH_ATTEMPTS}, genid {genid}): {msg}"
                    )));
                }
                // ERESTART: silent retry — success stays silent (D6), and a
                // retry that eventually commits is success.
                last_genid = genid;
                last_msg = msg;
            }
        }
    }
    // Budget exhausted: dedicated reason (not the generic per-attempt one).
    Err(load_fail(format!(
        "batch still rejected with ERESTART after {MAX_BATCH_ATTEMPTS} attempts \
         (ruleset keeps changing underneath us; last genid {last_genid}): {last_msg}"
    )))
}

// ---------------------------------------------------------------------------
// Post-load dump verification (Stage::NftVerify on any mismatch)
// ---------------------------------------------------------------------------

/// One decoded expression: `(name, canonical detail string)`. The detail
/// format is fixed so rules compare byte-exactly against the expected
/// tables derived from ground-truth.md §5.
type DecodedExpr = (String, String);

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Verify the loaded ruleset via GETCHAIN + GETRULE dumps, staged
/// [`Stage::NftVerify`] — production ALWAYS verifies (design Q7(a)): the
/// young crate's encoder is never trusted blindly, and the dumps are the
/// kernel's own view of what was committed (sub-ms cost).
///
/// Chain counters are deliberately never asserted (spike fact F5: their
/// presence varies by kernel — WSL2 6.18 dumps none — so any counter
/// expectation would be a flake source, not a safety check).
pub fn verify_dump(sock: &mut NetlinkSocket) -> Result<(), InitError> {
    verify_chains(sock)?;
    verify_rules(sock)
}

fn verify_chains(sock: &mut NetlinkSocket) -> Result<(), InitError> {
    let mut req = nftables::Request::new().op_getchain_dump(&msg_header());
    req.encode().push_table(TABLE);
    let mut iter = sock
        .request(&req)
        .map_err(|e| verify_fail(format!("getchain dump: {e}")))?;

    let (mut seen_nat, mut seen_filter) = (false, false);
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

        // Per-name presence flags: a bare count would accept [nat_out,
        // nat_out] — a duplicate plus a MISSING policy-drop chain. This is
        // the fail-closed verifier for a security boundary; reject
        // duplicates and assert both chains are present.
        let (e_num, e_prio, e_policy, e_type) = match name.as_str() {
            "nat_out" => {
                if seen_nat {
                    return Err(verify_fail("duplicate nat_out in chain dump"));
                }
                seen_nat = true;
                (NF_INET_LOCAL_OUT, PRIO_DSTNAT, POLICY_ACCEPT, "nat")
            }
            "filter_out" => {
                if seen_filter {
                    return Err(verify_fail("duplicate filter_out in chain dump"));
                }
                seen_filter = true;
                (NF_INET_LOCAL_OUT, PRIO_FILTER, POLICY_DROP, "filter")
            }
            other => {
                return Err(verify_fail(format!("unexpected chain {other:?} in dump")));
            }
        };
        if (num, prio, policy, ctype.as_str()) != (e_num, e_prio, e_policy, e_type) {
            return Err(verify_fail(format!(
                "chain {name}: got hook num={num} priority={prio} policy={policy} type={ctype:?}, \
                 expected num={e_num} priority={e_prio} policy={e_policy} type={e_type:?}"
            )));
        }
    }
    if !seen_nat || !seen_filter {
        return Err(verify_fail(format!(
            "expected chains nat_out + filter_out \
             (found nat_out={seen_nat} filter_out={seen_filter})"
        )));
    }
    Ok(())
}

fn verify_rules(sock: &mut NetlinkSocket) -> Result<(), InitError> {
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
        let exprs = decode_rule(&attrs)?;
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

    // Expected expression trees. The `value=[…]` byte literals are DERIVED
    // from the same consts `build_batch` encodes (IP_PROTO_TCP/UDP,
    // RTN_LOCAL, OIFNAME_LO, and PORT_REDIR_BE/PORT_DNS_BE ← consts.rs's
    // cross-issue port surface): a transcribed hex literal would silently
    // strand if a const ever changed — fail-closed (every sandbox would die
    // at nft-verify, rc 1), but deriving removes the drift class. The
    // absolute ground-truth pin lives in the byte-golden unit tests vs the
    // captured envelope. Structural renderings (dreg/sreg/key/op, the FIB
    // raw result 3 F11 pins, the verdict code, the redir data nest) stay
    // literal — the captured kernel dump is their source of truth
    // (ground-truth.md §5).
    let want_tcp = format!("sreg=1 op=0 value=[{}]", hex_bytes(&IP_PROTO_TCP));
    let want_udp = format!("sreg=1 op=0 value=[{}]", hex_bytes(&IP_PROTO_UDP));
    let want_not_local = format!("sreg=1 op=1 value=[{}]", hex_bytes(&RTN_LOCAL));
    let want_local = format!("sreg=1 op=0 value=[{}]", hex_bytes(&RTN_LOCAL));
    let want_redir_port = format!("dreg=1 value=[{}]", hex_bytes(&PORT_REDIR_BE));
    let want_dns_port = format!("sreg=1 op=0 value=[{}]", hex_bytes(&PORT_DNS_BE));
    let want_oif_lo = format!("sreg=1 op=0 value=[{}]", hex_bytes(&OIFNAME_LO));
    expect_exprs(
        "nat_out rule 1 (tcp redirect :15001)",
        &nat[0],
        &[
            ("meta", "dreg=1 key=16"),
            ("cmp", want_tcp.as_str()),
            ("fib", "dreg=1 result=3 flags=2"), // F11: raw result 3
            ("cmp", want_not_local.as_str()),
            ("immediate", want_redir_port.as_str()),
            ("redir", "data{1=1 2=1 3=2}"),
        ],
    )?;
    expect_exprs(
        "nat_out rule 2 (udp/53 redirect)",
        &nat[1],
        &[
            ("meta", "dreg=1 key=16"),
            ("cmp", want_udp.as_str()),
            ("payload", "dreg=1 base=2 offset=2 len=2"),
            ("cmp", want_dns_port.as_str()),
            ("redir", "data{}"), // bare redirect: EMPTY data nest
        ],
    )?;
    expect_exprs(
        "filter_out rule 1 (accept lo->local)",
        &filter[0],
        &[
            ("meta", "dreg=1 key=7"),
            ("cmp", want_oif_lo.as_str()),
            ("fib", "dreg=1 result=3 flags=2"),
            ("cmp", want_local.as_str()),
            ("immediate", "dreg=0 verdict.code=1"),
        ],
    )?;
    Ok(())
}

fn expect_exprs(what: &str, got: &[DecodedExpr], want: &[(&str, &str)]) -> Result<(), InitError> {
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
fn decode_rule(attrs: &nftables::IterableRuleAttrs<'_>) -> Result<Vec<DecodedExpr>, InitError> {
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
                // The detail carries the RAW kernel value (F11): the
                // expected tables assert result=3 (addrtype).
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
                )));
            }
            Err(e) => return Err(verify_fail(format!("expr {name}: undecodable data: {e}"))),
        };
        out.push((name, detail));
    }
    Ok(out)
}

/// Manual decode of a redir expression's raw bytes: find NFTA_EXPR_DATA(2)
/// and render its u32be children as `data{<type>=<value> ...}` (an empty
/// nest renders as `data{}`).
fn decode_redir_raw(buf: &[u8]) -> Result<String, InitError> {
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
    Err(verify_fail("redir: no NFTA_EXPR_DATA nest"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_bindings::builtin::Nlmsghdr;

    // ---- golden capture ----------------------------------------------------
    //
    // Captured from the working end-to-end prototype (`build_batch(7, 42,
    // false)` — the identical encoder this module ships): 8 messages, 1044
    // bytes total, cross-checked against spikes/nft-load/rules/ground-truth.md
    // §3–§5. Envelope pinned per the design: types
    // [0x0010, 0x0a00, 0x0a03, 0x0a03, 0x0a06 x3, 0x0011], flags
    // [0x0005 x4, 0x0c05 x3, 0x0005], contiguous seq. The break batch is
    // 9 messages / 1148 bytes (+104), first 8 byte-identical.
    //
    // These tests pin OUR request encoding (R15): request nests carry the
    // NLA_F_NESTED (0x8000) bit the kernel-stored ground-truth dumps show
    // stripped, and intra-nest attribute order may differ from nft's (the
    // kernel parses by type). ground-truth.md stays the semantic reference;
    // verify_dump stays the runtime kernel-side proof.

    const GOLDEN_SEQ: u32 = 7;
    const GOLDEN_GENID: u32 = 42;
    const GOLDEN_TOTAL_LEN: usize = 1044;
    const GOLDEN_MSG_LENS: [u32; 8] = [28, 28, 76, 84, 296, 240, 272, 20];
    const GOLDEN_TYPES: [u16; 8] = [
        0x0010, // NFNL_MSG_BATCH_BEGIN
        0x0a00, // NFT_MSG_NEWTABLE
        0x0a03, // NFT_MSG_NEWCHAIN (nat_out)
        0x0a03, // NFT_MSG_NEWCHAIN (filter_out)
        0x0a06, // NFT_MSG_NEWRULE (tcp redirect)
        0x0a06, // NFT_MSG_NEWRULE (udp/53 redirect)
        0x0a06, // NFT_MSG_NEWRULE (filter accept)
        0x0011, // NFNL_MSG_BATCH_END
    ];
    const GOLDEN_FLAGS: [u16; 8] = [
        0x0005, // REQUEST | ACK
        0x0005, 0x0005, 0x0005, 0x0c05, // REQUEST | ACK | CREATE | APPEND
        0x0c05, 0x0c05, 0x0005,
    ];

    const GOLDEN_BEGIN_ATTRS: &str = "080001000000002a";
    const GOLDEN_TABLE_ATTRS: &str = "0800010073627800";
    const GOLDEN_CHAIN_NAT_ATTRS: &str = "08000100736278000c0003006e61745f6f757400140004800800010000000003080002\
         00ffffff9c0800050000000001080007006e617400";
    const GOLDEN_CHAIN_FILTER_ATTRS: &str = "08000100736278000f00030066696c7465725f6f757400001400048008000100000000\
         03080002000000000008000500000000000b00070066696c7465720000";
    const GOLDEN_RULE1_ATTRS: &str = "08000100736278000c0002006e61745f6f7574000001048024000180090001006d6574\
         610000000014000280080001000000000108000200000000102c00018008000100636d\
         700020000280080001000000000108000200000000000c000380050001000600000028\
         00018008000100666962001c0002800800010000000001080002000000000308000300\
         000000022c00018008000100636d700020000280080001000000000108000200000000\
         010c00038008000100020000002c0001800e000100696d6d6564696174650000001800\
         028008000100000000010c000280060001003a9900002c0001800a0001007265646972\
         0000001c000280080001000000000108000200000000010800030000000002";
    const GOLDEN_RULE2_ATTRS: &str = "08000100736278000c0002006e61745f6f757400c800048024000180090001006d6574\
         610000000014000280080001000000000108000200000000102c00018008000100636d\
         700020000280080001000000000108000200000000000c000380050001001100000034\
         0001800c0001007061796c6f6164002400028008000100000000010800020000000002\
         080003000000000208000400000000022c00018008000100636d70002000028008000100\
         0000000108000200000000000c0003800600010000350000140001800a00010072656469\
         7200000004000280";
    const GOLDEN_RULE3_ATTRS: &str = "08000100736278000f00020066696c7465725f6f75740000e400048024000180090001\
         006d65746100000000140002800800010000000001080002000000000738000180080001\
         00636d70002c0002800800010000000001080002000000000018000380140001006c6f00\
         000000000000000000000000002800018008000100666962001c00028008000100000000\
         01080002000000000308000300000000022c00018008000100636d700020000280080001\
         000000000108000200000000000c0003800800010002000000300001800e000100696d6d\
         6564696174650000001c0002800800010000000000100002800c00028008000100000000\
         01";

    /// The redir LIST_ELEM of rule 1 (proto_min=proto_max=Reg1, flags=2).
    const GOLDEN_RULE1_REDIR_ELEM: &str = "2c0001800a00010072656469720000001c000280080001000000000108000200000000\
         010800030000000002";
    /// The bare redir LIST_ELEM of rule 2 — its empty `04000280` DATA nest is
    /// ground truth's `04 00 02 00` plus the NLA_F_NESTED request bit (R15).
    const GOLDEN_RULE2_BARE_REDIR_ELEM: &str = "140001800a000100726564697200000004000280";
    /// The immediate/verdict LIST_ELEM of rule 3 (dreg=0=RegVerdict,
    /// DATA{ VERDICT{ CODE=1 } } — the design's golden
    /// `1c000280 0800010000000000 10000280 0c000280 0800010000000001` is the
    /// element minus its own LIST_ELEM/NAME wrapper).
    const GOLDEN_RULE3_VERDICT_ELEM: &str = "300001800e000100696d6d6564696174650000001c0002800800010000000000100002\
         800c0002800800010000000001";

    /// One parsed batch message: envelope fields + nfgenmsg + attr bytes.
    struct Msg {
        len: u32,
        mtype: u16,
        flags: u16,
        seq: u32,
        pid: u32,
        nfgen: [u8; 4],
        attrs: Vec<u8>,
    }

    /// Split a batch buffer into its messages via the crate's always-public
    /// `builtin::Nlmsghdr` (nlmsg_len is trusted only after bounds-checking
    /// it against the buffer).
    fn messages(buf: &[u8]) -> Vec<Msg> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < buf.len() {
            assert!(off + 16 <= buf.len(), "truncated nlmsghdr at offset {off}");
            let hdr = Nlmsghdr::new_from_slice(&buf[off..off + 16]).expect("16-byte header");
            let len = hdr.len as usize;
            assert!(len >= 16, "nlmsg_len {len} below the 16-byte header size");
            assert!(
                off + len <= buf.len(),
                "nlmsg_len {len} past the buffer end at offset {off}"
            );
            let body = &buf[off + 16..off + len];
            assert!(body.len() >= 4, "message at {off} lacks an nfgenmsg");
            let mut nfgen = [0u8; 4];
            nfgen.copy_from_slice(&body[..4]);
            out.push(Msg {
                len: hdr.len,
                mtype: hdr.r#type,
                flags: hdr.flags,
                seq: hdr.seq,
                pid: hdr.pid,
                nfgen,
                attrs: body[4..].to_vec(),
            });
            off += (len + 3) & !3; // NLMSG_ALIGN
        }
        out
    }

    /// Compact lowercase hex (the goldens' spelling).
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The golden clean batch.
    fn golden_batch() -> Vec<u8> {
        build_batch(GOLDEN_SEQ, GOLDEN_GENID, false).buf().clone()
    }

    /// `find_attr` result as a BE u32.
    fn attr_be_u32(buf: &[u8], attr: u16) -> u32 {
        let bytes = utils::find_attr(buf, attr)
            .unwrap_or_else(|| panic!("attr {attr} missing from {}", hex(buf)));
        assert_eq!(bytes.len(), 4, "attr {attr} is not 4 bytes wide");
        u32::from_be_bytes(bytes.try_into().expect("4 bytes"))
    }

    // ---- envelope -----------------------------------------------------------

    #[test]
    fn batch_message_envelope_table() {
        // The captured golden envelope: 8 messages, 1044 bytes, exact
        // per-message lengths/types/flags, contiguous seq from first_seq,
        // pid 0, and every nlmsg_len equal to the message's actual span.
        let buf = golden_batch();
        assert_eq!(buf.len(), GOLDEN_TOTAL_LEN);
        let msgs = messages(&buf);
        assert_eq!(msgs.len(), 8);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(m.len, GOLDEN_MSG_LENS[i], "msg {i} nlmsg_len");
            assert_eq!(m.mtype, GOLDEN_TYPES[i], "msg {i} type");
            assert_eq!(m.flags, GOLDEN_FLAGS[i], "msg {i} flags");
            assert_eq!(m.seq, GOLDEN_SEQ + i as u32, "msg {i} seq (contiguous)");
            assert_eq!(m.pid, 0, "msg {i} pid");
        }
        // The spans tile the buffer exactly (all lens are 4-aligned, so no
        // inter-message padding hides anywhere).
        assert_eq!(
            GOLDEN_MSG_LENS.iter().sum::<u32>() as usize,
            GOLDEN_TOTAL_LEN
        );
    }

    #[test]
    fn nfgenmsg_headers_pinned() {
        // ground-truth §3: BEGIN/END carry family 0 + res_id BE 10
        // (NFNL_SUBSYS_NFTABLES); every per-op message carries family 2
        // (AF_INET — the ruleset is `ip`-family) + res_id 0; version 0
        // (NFNETLINK_V0) everywhere.
        let buf = golden_batch();
        let msgs = messages(&buf);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(m.nfgen[1], 0, "msg {i} nfgen version");
            if i == 0 || i == 7 {
                assert_eq!(m.nfgen[0], 0, "msg {i} nfgen family (batch)");
                assert_eq!(&m.nfgen[2..4], &[0x00, 0x0a], "msg {i} res_id BE 10");
            } else {
                assert_eq!(m.nfgen[0], 2, "msg {i} nfgen family (AF_INET)");
                assert_eq!(&m.nfgen[2..4], &[0x00, 0x00], "msg {i} res_id 0");
            }
        }
    }

    #[test]
    fn batch_begin_carries_genid_be() {
        // BEGIN's single attribute is NFTA_GEN_ID(1), big-endian — the
        // kernel's commit-race detection value.
        let buf = golden_batch();
        let msgs = messages(&buf);
        assert_eq!(hex(&msgs[0].attrs), GOLDEN_BEGIN_ATTRS);
        let genid = utils::find_attr(&msgs[0].attrs, 1).expect("GENID attr");
        assert_eq!(genid, GOLDEN_GENID.to_be_bytes());
        // A different genid re-encodes in place (same length, new BE bytes).
        let buf2 = build_batch(GOLDEN_SEQ, 0xDEAD_BEEF, false);
        let msgs2 = messages(buf2.buf());
        let genid2 = utils::find_attr(&msgs2[0].attrs, 1).expect("GENID attr");
        assert_eq!(genid2, 0xDEAD_BEEFu32.to_be_bytes());
    }

    // ---- chains -------------------------------------------------------------

    #[test]
    fn chain_messages_match_ground_truth() {
        // Full-attr goldens PLUS the structured ground-truth §4 values
        // (names, hook num 3, priorities -100/0, policies accept/drop, types
        // nat/filter) — bytes and semantics pinned in one place.
        let buf = golden_batch();
        let msgs = messages(&buf);
        assert_eq!(hex(&msgs[2].attrs), GOLDEN_CHAIN_NAT_ATTRS.replace(' ', ""));
        assert_eq!(
            hex(&msgs[3].attrs),
            GOLDEN_CHAIN_FILTER_ATTRS.replace(' ', "")
        );
        assert_eq!(hex(&msgs[1].attrs), GOLDEN_TABLE_ATTRS); // NEWTABLE "sbx\0"

        for (m, name, prio, policy, ctype) in [
            (
                &msgs[2],
                &b"nat_out\0"[..],
                PRIO_DSTNAT,
                POLICY_ACCEPT,
                &b"nat\0"[..],
            ),
            (
                &msgs[3],
                &b"filter_out\0"[..],
                PRIO_FILTER,
                POLICY_DROP,
                &b"filter\0"[..],
            ),
        ] {
            let attrs = &m.attrs;
            assert_eq!(
                utils::find_attr(attrs, 1).expect("TABLE"),
                b"sbx\0",
                "{name:?}"
            );
            assert_eq!(utils::find_attr(attrs, 3).expect("NAME"), name);
            let hook = utils::find_attr(attrs, 4).expect("HOOK nest");
            assert_eq!(attr_be_u32(hook, 1), NF_INET_LOCAL_OUT, "hook num");
            assert_eq!(
                attr_be_u32(hook, 2) as i32,
                prio,
                "hook priority ({name:?})"
            );
            assert_eq!(attr_be_u32(attrs, 5), policy, "policy ({name:?})");
            assert_eq!(utils::find_attr(attrs, 7).expect("TYPE"), ctype);
        }
    }

    // ---- rules --------------------------------------------------------------

    #[test]
    fn rule1_tcp_redirect_exprs_byte_exact() {
        // meta l4proto(16)→reg1, cmp eq [06], fib daddr result=3 RAW (F11),
        // cmp neq RTN_LOCAL [02 00 00 00], immediate reg1=[3a 99] (15001
        // BE), redir {min=1 max=1 flags=2}.
        let buf = golden_batch();
        let msgs = messages(&buf);
        assert_eq!(hex(&msgs[4].attrs), GOLDEN_RULE1_ATTRS.replace(' ', ""));
        let h = hex(&msgs[4].attrs);
        assert!(
            h.contains(GOLDEN_RULE1_REDIR_ELEM),
            "rule 1 must carry the full redir element golden"
        );
        assert!(h.contains("0c000380050001000600"), "cmp [06] (tcp)");
        assert!(h.contains("0800020000000003"), "fib RESULT=3 raw (F11)");
        assert!(h.contains("0c0003800800010002000000"), "cmp RTN_LOCAL");
        assert!(h.contains("0c000280060001003a990000"), "immediate [3a 99]");
    }

    #[test]
    fn rule2_udp53_exprs_byte_exact() {
        // meta l4proto→reg1, cmp eq [11], payload th+2 len 2→reg1, cmp eq
        // [00 35] (53 BE), BARE redir (empty DATA nest = keep dport).
        let buf = golden_batch();
        let msgs = messages(&buf);
        assert_eq!(hex(&msgs[5].attrs), GOLDEN_RULE2_ATTRS.replace(' ', ""));
        let h = hex(&msgs[5].attrs);
        assert!(
            h.contains(GOLDEN_RULE2_BARE_REDIR_ELEM),
            "rule 2 must carry the bare-redir element golden (empty DATA nest)"
        );
        assert!(h.contains("0c000380050001001100"), "cmp [11] (udp)");
        // payload expr: dreg=1, base=2 (transport header), offset=2, len=2.
        assert!(
            h.contains("240002800800010000000001080002000000000208000300000000020800040000000002"),
            "payload dreg/base/offset/len"
        );
        assert!(
            h.contains("0c0003800600010000350000"),
            "cmp [00 35] (53 BE)"
        );
    }

    #[test]
    fn rule3_filter_accept_exprs_byte_exact() {
        // meta oifname(7)→reg1, cmp eq 16-byte "lo" pad, fib daddr result=3
        // raw, cmp eq RTN_LOCAL, immediate reg0 (verdict) accept(1).
        let buf = golden_batch();
        let msgs = messages(&buf);
        assert_eq!(hex(&msgs[6].attrs), GOLDEN_RULE3_ATTRS.replace(' ', ""));
        let h = hex(&msgs[6].attrs);
        assert!(
            h.contains(GOLDEN_RULE3_VERDICT_ELEM),
            "rule 3 must carry the immediate/verdict element golden"
        );
        assert!(
            h.contains("18000380140001006c6f0000000000000000000000000000"),
            "oifname cmp: 16-byte NUL-padded \"lo\""
        );
        assert!(h.contains("0800020000000003"), "fib RESULT=3 raw (F11)");
    }

    // ---- break-rules variant --------------------------------------------------

    #[test]
    fn break_rules_batch_appends_missing_chain_rule() {
        // Q4(a)'s injection: exactly one extra NEWRULE (9 messages, +104
        // bytes) targeting the nonexistent chain, inserted BEFORE the END
        // message — END shifts from message 8 to message 9, so the
        // byte-identical clean prefix is the first 7 messages (1024 bytes),
        // and the kernel rejects-then-rolls-back the whole thing (F6).
        // (The design digest's "first 8 messages identical" is corrected by
        // the empirical capture: message 8 IS the injected NEWRULE.)
        let clean = golden_batch();
        let broken = build_batch(GOLDEN_SEQ, GOLDEN_GENID, true).buf().clone();
        assert_eq!(broken.len(), 1148);
        assert_eq!(broken.len() - clean.len(), 104);
        let prefix_len: usize = GOLDEN_MSG_LENS[..7].iter().map(|l| *l as usize).sum();
        assert_eq!(prefix_len, 1024, "the 7 clean messages tile 1024 bytes");
        assert_eq!(
            &broken[..prefix_len],
            &clean[..prefix_len],
            "the first 7 messages (everything before END/the injected rule) are byte-identical"
        );

        let msgs = messages(&broken);
        assert_eq!(msgs.len(), 9);
        let extra = &msgs[7];
        assert_eq!(extra.mtype, 0x0a06, "message 8 is a NEWRULE");
        assert_eq!(extra.flags, 0x0c05, "CREATE|APPEND like the real rules");
        assert_eq!(extra.seq, GOLDEN_SEQ + 7, "seq stays contiguous");
        assert_eq!(
            utils::find_attr(&extra.attrs, 2).expect("CHAIN attr"),
            b"sbx_no_such_chain\0",
            "the rule must target the nonexistent chain"
        );
        assert_eq!(msgs[8].mtype, 0x0011, "message 9 is BATCH_END");
        assert_eq!(msgs[8].seq, GOLDEN_SEQ + 8, "END keeps the seq contiguous");
    }

    // ---- meta / purity pins ----------------------------------------------------

    #[test]
    fn fib_result_raw_pin() {
        // F11 meta-test: the generated enum is off by one vs the kernel (the
        // bundled YAML spec lacks NFT_FIB_RESULT_UNSPEC=0). The encoder must
        // push the RAW 3; if the crate ever fixes the spec, this fails
        // loudly so the raw constant can be re-evaluated (candidate upstream
        // bug report tracked by the spike's FINDINGS.md).
        assert_eq!(nftables::FibResult::Addrtype as u32, 2, "generated enum");
        assert_eq!(FIB_RESULT_ADDRTYPE_RAW, 3, "kernel wire value");
        assert_ne!(
            nftables::FibResult::Addrtype as u32,
            FIB_RESULT_ADDRTYPE_RAW,
            "the trap is still live: never encode FibResult::Addrtype"
        );
    }

    #[test]
    fn build_batch_is_deterministic() {
        // Purity: identical inputs ⇒ identical bytes; the genid is always
        // 4 BE bytes, so the total length is genid-independent; the seq
        // only shifts the envelope numbers.
        let a = build_batch(GOLDEN_SEQ, GOLDEN_GENID, false);
        let b = build_batch(GOLDEN_SEQ, GOLDEN_GENID, false);
        assert_eq!(a.buf(), b.buf(), "same inputs ⇒ identical bytes");
        assert_eq!(
            build_batch(GOLDEN_SEQ, 0xDEAD_BEEF, false).buf().len(),
            GOLDEN_TOTAL_LEN,
            "length invariant under the genid value"
        );
        assert_eq!(
            build_batch(1234, GOLDEN_GENID, false).buf().len(),
            GOLDEN_TOTAL_LEN,
            "length invariant under the seq base"
        );
        let shifted = messages(build_batch(1234, GOLDEN_GENID, false).buf());
        assert_eq!(shifted[0].seq, 1234);
        assert_eq!(shifted[7].seq, 1234 + 7);
    }

    #[test]
    fn erestart_classification_pinned() {
        // The retry predicate: ONLY the kernel-internal ERESTART(85) is
        // retryable — 0 (success) and every other errno are fatal.
        assert!(is_erestart(Some(ERESTART)));
        assert!(is_erestart(Some(85)));
        assert!(!is_erestart(Some(0)));
        assert!(!is_erestart(Some(libc::EEXIST)));
        assert!(!is_erestart(Some(libc::ENOENT)));
        assert!(!is_erestart(None));
    }

    #[test]
    fn port_be_consts_derive_from_ports() {
        // Single source of truth: the wire bytes are const-derived from the
        // protocol constants (consts.rs), pinned here against the
        // ground-truth spelling ([3a 99] = 15001, [00 35] = 53).
        assert_eq!(PORT_REDIR_BE, [0x3a, 0x99]);
        assert_eq!(PORT_DNS_BE, [0x00, 0x35]);
        assert_eq!(PORT_REDIR_BE, TRANSPARENT_TCP_PORT.to_be_bytes());
        assert_eq!(PORT_DNS_BE, DNS_UDP_PORT.to_be_bytes());
    }
}
