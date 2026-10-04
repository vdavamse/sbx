//! nft-load-spike — entry point / orchestration (design D4).
//!
//! Sequence: netns setup -> bind listeners+canaries -> atomic nftables batch
//! -> dump verification -> traffic self-tests -> report -> exit code.
//!
//! Exit codes:
//!   0 all checks passed
//!   1 usage error / environment (unshare EPERM -> AppArmor hint)
//!   2 netns setup or read-back verification failed
//!   3 nftables batch load failed (fail closed) — also the *verified*
//!     `--break-rules` outcome (FAIL-CLOSED-VERIFIED on stderr)
//!   4 post-load dump verification mismatch
//!   5 self-test failure
//!   6 listener bind failure
//!   7 broken batch unexpectedly accepted (`--break-rules`)

mod consts;
mod listeners;
mod netns;
mod report;
mod rules;
mod selftest;

use std::process;
use std::thread;
use std::time::Duration;

use netlink_socket2::NetlinkSocket;

use crate::consts::{EXIT_OK, EXIT_SELFTEST, EXIT_USAGE};
use crate::report::TestResult;

/// Uniform failure carrier: exit code + message. Modules map their errors
/// into this; `main` prints the message on stderr and exits with the code.
pub struct Fail {
    pub code: i32,
    pub msg: String,
}

impl Fail {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
        }
    }
}

const USAGE: &str = "\
nft-load-spike — prove unprivileged nftables sandbox loading (sbx issue #1)

Creates a fresh user+net namespace, configures lo (10.255.255.1/32 + default
route via lo), loads the sandbox nftables ruleset atomically in ONE netlink
batch, verifies it via netlink dumps, then runs traffic self-tests (TCP
redirect + SO_ORIGINAL_DST, UDP/53 redirect, UDP-non-53 drop, fail-closed
controls). Everything happens inside the private netns; process exit destroys
the sandbox.

USAGE:
    nft-load-spike [FLAGS]

FLAGS:
    --break-rules      Load a deliberately broken batch (rule -> nonexistent
                       chain) and verify the kernel rejects it and rolls
                       everything back. Prints FAIL-CLOSED-VERIFIED on stderr
                       and exits 3 when verified; exits 7 if the broken batch
                       was unexpectedly accepted.
    --json             Emit a single JSON report object on stdout instead of
                       the PASS/FAIL table.
    --skip-selftests   Skip traffic self-tests (netns + rule load + dump
                       verification still run).
    --dump-rules       Print the decoded post-load netlink dump (stderr).
    --keep-alive N     After the report, print READY pid=<pid> on stderr and
                       sleep N seconds before exiting (lets an external
                       observer enter the netns, e.g. nsenter + nft list).
    --verbose          Extra status/diagnostic lines on stderr.
    --help, -h         Show this help.

EXIT CODES:
    0  all checks passed
    1  usage error / environment (unshare EPERM -> see AppArmor hint)
    2  netns setup or read-back verification failed
    3  nftables batch load failed (fail closed); also verified --break-rules
    4  post-load dump verification mismatch
    5  self-test failure
    6  listener bind failure
    7  broken batch unexpectedly accepted (--break-rules)
";

#[derive(Default)]
struct Args {
    break_rules: bool,
    json: bool,
    skip_selftests: bool,
    dump_rules: bool,
    keep_alive: u64,
    verbose: bool,
    help: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--keep-alive" {
            i += 1;
            let v = argv
                .get(i)
                .ok_or("--keep-alive requires a value (seconds)")?;
            a.keep_alive = v
                .parse()
                .map_err(|_| format!("--keep-alive: invalid seconds {v:?}"))?;
        } else if let Some(v) = arg.strip_prefix("--keep-alive=") {
            a.keep_alive = v
                .parse()
                .map_err(|_| format!("--keep-alive: invalid seconds {v:?}"))?;
        } else {
            match arg {
                "--break-rules" => a.break_rules = true,
                "--json" => a.json = true,
                "--skip-selftests" => a.skip_selftests = true,
                "--dump-rules" => a.dump_rules = true,
                "--verbose" => a.verbose = true,
                "--help" | "-h" => a.help = true,
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        i += 1;
    }
    Ok(a)
}

struct Outcome {
    code: i32,
    tests: Vec<TestResult>,
    genid: u32,
    attempts: u32,
}

fn fatal(f: Fail) -> Outcome {
    eprintln!("ERROR: {}", f.msg);
    Outcome {
        code: f.code,
        tests: vec![TestResult::failed("fatal", f.msg)],
        genid: 0,
        attempts: 0,
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprint!("{USAGE}");
            process::exit(EXIT_USAGE);
        }
    };
    if args.help {
        print!("{USAGE}");
        process::exit(EXIT_OK);
    }

    let out = run(&args);

    if args.json {
        report::emit_json(
            out.code == EXIT_OK,
            out.code,
            &out.tests,
            out.genid,
            out.attempts,
        );
    } else {
        report::emit_table(&out.tests);
    }

    if args.keep_alive > 0 {
        // Marker for external cross-checks: CI runs
        // `nsenter -t <pid> -n nft list ruleset` during this window.
        eprintln!("READY pid={}", process::id());
        thread::sleep(Duration::from_secs(args.keep_alive));
    }

    process::exit(out.code);
}

fn run(args: &Args) -> Outcome {
    eprintln!("[status] creating user+net namespace and sandbox network");
    if let Err(f) = netns::setup(args.verbose) {
        return fatal(f);
    }

    // MUST be created after unshare: netlink sockets bind to the netns that
    // is current at socket(2) time. Used for all nftables interactions.
    let mut sock = NetlinkSocket::new();

    eprintln!("[status] binding listeners + canaries (before rules: no redirect-live-without-listener window)");
    let listeners = match listeners::start(args.verbose) {
        Ok(l) => l,
        Err(f) => return fatal(f),
    };

    if args.break_rules {
        eprintln!("[status] --break-rules: sending deliberately broken batch");
        let fc = rules::prove_fail_closed(&mut sock, args.verbose);
        return Outcome {
            code: fc.code,
            tests: vec![fc.result],
            genid: fc.genid,
            attempts: fc.attempts,
        };
    }

    eprintln!("[status] loading nftables ruleset (single-write batch, genid + ERESTART retry)");
    let stats = match rules::load(&mut sock, args.verbose) {
        Ok(s) => s,
        Err(f) => return fatal(f),
    };
    eprintln!(
        "[status] batch committed: genid={} attempt(s)={}",
        stats.genid, stats.attempts
    );

    eprintln!("[status] verifying loaded ruleset via netlink dump");
    if let Err(f) = rules::verify_dump(&mut sock, args.dump_rules, args.verbose) {
        eprintln!("ERROR: {}", f.msg);
        return Outcome {
            code: f.code,
            tests: vec![TestResult::failed("verify-dump", f.msg)],
            genid: stats.genid,
            attempts: stats.attempts,
        };
    }
    eprintln!("[status] dump verification passed");

    let tests = if args.skip_selftests {
        eprintln!("[status] --skip-selftests: skipping traffic self-tests");
        Vec::new()
    } else {
        eprintln!("[status] running traffic self-tests");
        selftest::run(listeners.rx)
    };

    let code = if tests.iter().all(|t| t.pass) {
        EXIT_OK
    } else {
        EXIT_SELFTEST
    };
    Outcome {
        code,
        tests,
        genid: stats.genid,
        attempts: stats.attempts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults() {
        let a = parse_args(&argv(&[])).unwrap();
        assert!(!a.json && !a.break_rules && a.keep_alive == 0);
    }

    #[test]
    fn parse_args_all_flags() {
        let a = parse_args(&argv(&[
            "--break-rules",
            "--json",
            "--skip-selftests",
            "--dump-rules",
            "--verbose",
        ]))
        .unwrap();
        assert!(a.break_rules && a.json && a.skip_selftests && a.dump_rules && a.verbose);
    }

    #[test]
    fn parse_args_keep_alive_forms() {
        assert_eq!(
            parse_args(&argv(&["--keep-alive", "42"]))
                .unwrap()
                .keep_alive,
            42
        );
        assert_eq!(
            parse_args(&argv(&["--keep-alive=7"])).unwrap().keep_alive,
            7
        );
    }

    #[test]
    fn parse_args_rejects_bad_input() {
        assert!(parse_args(&argv(&["--nope"])).is_err());
        assert!(parse_args(&argv(&["--keep-alive"])).is_err());
        assert!(parse_args(&argv(&["--keep-alive", "x"])).is_err());
    }
}
