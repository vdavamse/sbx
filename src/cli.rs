//! Command-line interface for `sbx`.
//!
//! Issue #2 froze the documented flag surface; issue #3 replaced the
//! `check` stub; issue #5 made `__init` real; issue #10 made `run` real;
//! issue #12 made `gc` real. Every subcommand is real:
//!
//! - `run`    — sandbox lifecycle, egress proxy, audit log (real since #10)
//! - `check`  — host capability report (issue #11), policy validation and
//!   JSON Schema (real since #3)
//! - `gc`     — session-directory garbage collection (real since #12)
//! - `check --conformance` — the executable conformance suite (issue #13;
//!   the hidden `__conformance probe` is its in-sandbox side)
//! - `__init` — re-exec'd namespace helper (real since #5; hidden — #10's
//!   `run` is its only production caller)
//!
//! Exit-code contract: 0 = success, 1 = runtime failure
//! ([`ExitCode::FAILURE`]) — for `check`, an invalid or unreadable policy
//! file; for `__init`, a staged setup failure (`sbx __init: <stage>: <reason>`,
//! the payload never started); for `gc`, a refused ROOT or any per-session
//! failure — 2 = usage error (clap's own convention). For `run` (issue #10):
//! the command's own code; 124 timeout; 125 sbx failure; 128+N terminated by
//! signal N; 2 usage. See the `run` module docs, point 4. For `gc` (issue #12):
//! 0 = every eligible session handled, 1 = ROOT refused or any per-session
//! failure, 2 = usage.

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand};

use crate::policy::NetworkMode;

/// Parse a positive human-readable duration (`120s`, `7d`, `500ms`, ...) for clap.
///
/// Wraps [`humantime::parse_duration`] and additionally rejects zero: a zero
/// `--timeout` is ambiguous (kill immediately vs. never), and a zero
/// `--older-than` cutoff would match every session (destructive). humantime
/// already rejects negatives, empty input, and overflow. The error is mapped
/// to [`String`] so clap reports it as an invalid-value usage error (exit 2).
/// Public for reuse: the policy module's `limits.timeout` shares this exact
/// contract, as do later issues (#5, #10, #12) and unit tests.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let d = humantime::parse_duration(s).map_err(|e| e.to_string())?;
    if d.is_zero() {
        return Err("duration must be greater than zero".to_owned());
    }
    Ok(d)
}

/// Parse the `__init --fd` value for clap: a base-10 file-descriptor number
/// in `0..=i32::MAX`.
///
/// Rejects anything that cannot be a valid fd number — non-integers,
/// negatives and out-of-range values all become clap `ValueValidation`
/// errors (exit 2), keeping rc 1 exclusively for staged setup failures
/// (design D8). Probe-verified: BOTH `--fd -1` and `--fd=-1` spellings
/// reach this parser (clap 4.6 hands the hyphenated token to the value
/// parser of a value-expecting option), so one range check covers every
/// spelling. Private: unlike [`parse_duration`], no policy schema shares
/// this contract.
fn parse_control_fd(s: &str) -> Result<RawFd, String> {
    // i64 (not i32) so out-of-range values report the range message
    // instead of clap's generic integer-overflow text.
    let parsed: i64 = s
        .parse()
        .map_err(|_| format!("`{s}` is not a file descriptor number"))?;
    if !(0..=i64::from(i32::MAX)).contains(&parsed) {
        return Err(format!(
            "file descriptor `{s}` is out of range (0..={})",
            i32::MAX
        ));
    }
    Ok(parsed as RawFd) // range-checked above
}

/// Parsed command-line interface for `sbx`.
#[derive(Debug, Parser)]
#[command(name = "sbx", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

/// The `sbx` subcommands.
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run a command inside the sandbox.
    Run {
        /// Sandbox policy file (JSON).
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,

        /// Session directory for sandbox state and audit files.
        #[arg(long, value_name = "DIR")]
        session_dir: PathBuf,

        /// Working directory for the command inside the sandbox.
        #[arg(long, value_name = "PATH")]
        cwd: Option<PathBuf>,

        /// Kill the command after this long (e.g. 90s, 2h); default and upper
        /// bound: the policy's limits.timeout.
        #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
        timeout: Option<Duration>,

        /// Audit log file (JSON Lines).
        #[arg(long, value_name = "FILE")]
        audit: Option<PathBuf>,

        /// Command to run, verbatim — everything after `--`.
        //
        // `OsString`, not `String`: Linux argv is arbitrary bytes, and the
        // verbatim pass-through contract must survive non-UTF-8 arguments
        // (a `String` parser rejects them with exit 2). Downstream consumers
        // (`std::process::Command::args`, bwrap) take `OsStr` anyway. The
        // rationale is a `//` comment, not `///`: clap derive renders doc
        // comments as user-facing long help, where Rust type names have no
        // place.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..,
            required = true
        )]
        cmd: Vec<OsString>,

        /// (hidden) Test-only, fail-only: load a deliberately broken nftables
        /// batch in the sandbox setup (forwarded to `__init`; issue #11, Q6).
        #[arg(long, hide = true)]
        test_break_rules: bool,
    },

    /// Report what this host can run, or validate a policy file.
    Check {
        /// Sandbox policy file (JSON): validated, or — with --host — compared
        /// against this host.
        #[arg(long, value_name = "PATH", conflicts_with = "print_schema")]
        policy: Option<PathBuf>,

        /// Print the policy JSON Schema (draft 2020-12) to stdout and exit.
        #[arg(long, conflicts_with_all = ["policy", "host", "json", "test_break_rules", "conformance"])]
        print_schema: bool,

        /// With --policy: also check that this host can run the policy.
        #[arg(long, requires = "policy")]
        host: bool,

        /// Print the host report as JSON (report version 1).
        #[arg(long)]
        json: bool,

        /// (hidden) Test-only, fail-only: make the probe's nftables load fail
        /// (issue #11, Q6 precedent).
        #[arg(long, hide = true)]
        test_break_rules: bool,
        /// Run the conformance suite: every security guarantee as an executable check.
        #[arg(long, conflicts_with_all = ["policy", "print_schema", "host", "test_break_rules"])]
        conformance: bool,
        /// With --conformance: also run the network tier (needs internet access).
        #[arg(long, requires = "conformance", conflicts_with = "list")]
        network: bool,
        /// With --conformance: run only these checks or groups (A01, A, allow-list; comma-separated or repeated).
        #[arg(
            long,
            value_name = "ID|GROUP",
            value_delimiter = ',',
            requires = "conformance",
            conflicts_with = "list"
        )]
        only: Vec<String>,
        /// With --conformance: list the checks without running them.
        #[arg(long, requires = "conformance")]
        list: bool,
    },

    /// Delete session directories older than a cutoff.
    Gc {
        /// Age cutoff (e.g. 12h, 7d); older sessions are deleted.
        #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
        older_than: Duration,

        /// Print what would be removed without removing anything.
        #[arg(long)]
        dry_run: bool,

        /// Session root directory to scan.
        #[arg(value_name = "ROOT")]
        root: PathBuf,
    },

    /// Internal conformance roles (hidden; issue #13).
    #[command(name = "__conformance", hide = true)]
    Conformance {
        #[command(subcommand)]
        role: ConformanceRole,
    },
    /// Internal namespace helper, re-exec'd by `run` (hidden; real since #5).
    #[command(name = "__init", hide = true)]
    Init {
        /// Inherited control socketpair end (SOCK_SEQPACKET).
        //
        // The number `run` passes after clearing CLOEXEC on exactly this end
        // in the spawn window (fdpass::prepare_child_end — the R6 bug-class
        // discipline). Validated in the pipeline's `control` stage BEFORE
        // any namespace work, so a bad fd fails fast and deterministically.
        // `//` rationale, not `///`: clap renders doc comments as help text.
        #[arg(long, value_name = "FD", value_parser = parse_control_fd, required_unless_present = "probe")]
        fd: Option<RawFd>,

        /// (hidden) The bwrap `--info-fd` pipe write end `run` hands through.
        //
        // Issue #10 (Q13): `run` passes its bwrap info pipe here so the fd
        // survives fd_hygiene for exactly one hop. Validated in the control
        // stage (init::validate_keep_fd) before any namespace work.
        #[arg(long, value_name = "FD", hide = true, value_parser = parse_control_fd)]
        keep_fd: Option<RawFd>,

        /// (hidden) The sealed memfd holding sbx's seccomp program, handed to bwrap
        /// as `--seccomp` (issue #34).
        //
        // Validated in the control stage (init::validate_seccomp_fd): a sealed
        // memfd whose bytes equal this binary's own program. Optional so direct
        // `__init` callers (the integration suites) keep working; `run` always
        // passes it.
        #[arg(long, value_name = "FD", hide = true, value_parser = parse_control_fd)]
        seccomp_fd: Option<RawFd>,

        /// (hidden) The pid of the `run` process that spawned us (m6): __init sets
        /// PR_SET_PDEATHSIG and refuses to continue if its parent is not this pid.
        //
        // Optional so direct `__init` callers (the integration suites) keep working;
        // `run` always passes it.
        #[arg(long, value_name = "PID", hide = true, value_parser = parse_control_fd)]
        parent_pid: Option<i32>,

        /// (hidden) Test-only: load a deliberately broken ruleset batch.
        //
        // Fail-only by construction (Q4(a)): it can make setup FAIL (the
        // kernel rejects the batch with ENOENT and rolls everything back,
        // spike fact F6) but can never WEAKEN the sandbox — the only way to
        // integration-test the nft-load failure path in a fresh netns.
        #[arg(long, hide = true)]
        test_break_rules: bool,

        /// (hidden) The weakest network mode the caller accepts — `run` passes
        /// its policy's mode. Defaults to transparent (no explicit fallback).
        //
        // Issue #11 (Q1): with explicit or none, a refused nft batch falls
        // back to the explicit mode (default route removed and verified).
        #[arg(long, value_name = "MODE", hide = true, value_parser = parse_network_mode)]
        min_mode: Option<NetworkMode>,

        /// (hidden) Host capability probe for `sbx check`: run the setup stages
        /// and the nested bwrap launches, print one JSON line, exit 0.
        //
        // Issue #11 (T3/T4). Conflicts with every pipeline argument.
        #[arg(long, hide = true, conflicts_with_all = ["fd", "keep_fd", "seccomp_fd", "parent_pid", "min_mode", "cmd"])]
        probe: bool,

        /// (hidden, with --probe) The bwrap binary the probe launches.
        #[arg(long, value_name = "PATH", hide = true, requires = "probe")]
        bwrap: Option<PathBuf>,

        /// Command to exec, verbatim — everything after `--`.
        //
        // Same contract as `run`'s trailing command (OsString-clean,
        // hyphens preserved): `required = true` (design D7) — an `__init`
        // with nothing to exec has no runtime meaning, and the
        // MissingRequiredArgument rc 2 keeps rc 1 exclusively for staged
        // setup failures.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..,
            required_unless_present = "probe"
        )]
        cmd: Vec<OsString>,
    },
}

/// Roles of the hidden `__conformance` subcommand (issue #13).
#[derive(Debug, Subcommand)]
pub enum ConformanceRole {
    /// In-sandbox probe: run the ops, print one JSON line per op.
    Probe {
        /// An exact token for /proc scans; otherwise ignored.
        #[arg(long, value_name = "TOKEN")]
        tag: Option<String>,
        /// The OPS document (JSON).
        #[arg(value_name = "OPS")]
        ops: String,
    },
}

/// Parse `--min-mode` / the policy's network mode spelling for clap: exactly
/// `transparent`, `explicit` or `none` (issue #11).
pub fn parse_network_mode(s: &str) -> Result<NetworkMode, String> {
    match s {
        "transparent" => Ok(NetworkMode::Transparent),
        "explicit" => Ok(NetworkMode::Explicit),
        "none" => Ok(NetworkMode::None),
        other => Err(format!(
            "`{other}` is not a network mode (transparent, explicit, none)"
        )),
    }
}

/// Cross-argument rules clap cannot express alone (issue #11). Returns the
/// usage error to report (rc 2). `check --policy P` without `--host` is the
/// validate-only form, which must stay probe-free, so `--json` and
/// `--test-break-rules` need a host report.
pub fn validate(cli: &Cli) -> Result<(), clap::Error> {
    if let Cmd::Check {
        conformance: true,
        only,
        ..
    } = &cli.command
    {
        if !only.is_empty() {
            if let Err(bad) = crate::conformance::catalog::select(only) {
                return Err(Cli::command().error(
                    clap::error::ErrorKind::InvalidValue,
                    format!(
                        "unknown conformance check or group `{bad}` (ids A01..H06, groups A..H or names such as allow-list; see --list)"
                    ),
                ));
            }
        }
    }
    if let Cmd::Check {
        policy: Some(_),
        host: false,
        json,
        test_break_rules,
        ..
    } = &cli.command
    {
        if *json || *test_break_rules {
            return Err(Cli::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--json and --test-break-rules need a host report: add --host or drop --policy",
            ));
        }
    }
    Ok(())
}

/// Binary entry point: parse `argv` and dispatch to the subcommand.
///
/// `check` contract (issues #3 and #11): bare or `--json` prints the host
/// capability report (exit 0 when the host can run at least the explicit
/// mode, 1 otherwise); `--policy P --host` adds the policy comparison;
/// `--policy PATH` alone validates the file, probe-free —
/// silent rc 0 on success, rc 1 with `sbx check: <reason>` on stderr for
/// an invalid *or* unreadable policy — and `--print-schema` prints the
/// policy JSON Schema to stdout with rc 0. The two flags are mutually
/// exclusive and exactly one is required; anything else is clap's rc 2.
///
/// `__init` contract (issue #5): `--fd N [--test-break-rules] -- CMD
/// ARGS…` runs the namespace pipeline ([`crate::init`]) and `exec`s CMD —
/// success is silent and the exit code is the payload's own (via `exec`);
/// ANY setup failure is rc 1 with `sbx __init: <stage>: <reason>` on
/// stderr and the payload never starts; usage errors stay clap's rc 2.
///
/// `gc` contract (issue #12): `gc --older-than D [--dry-run] ROOT` removes
/// expired session directories under ROOT and reports one line per entry on
/// stdout (`removed "<path>"` or `would remove "<path>"`). A refused ROOT or any
/// per-session failure is rc 1 with `sbx gc: <path>: <reason>` on stderr. The
/// zero duration and other usage errors are rc 2 (clap). See [`crate::gc`].
pub fn run() -> ExitCode {
    // Catches invalid clap configuration (bad defaults, duplicate names,
    // conflicting attributes) at startup. Despite the name, this is NOT
    // gated on cfg(debug_assertions): it runs in every profile — tests,
    // debug, and release alike — at negligible cost (once per process).
    Cli::command().debug_assert();

    let cli = Cli::parse();
    if let Err(err) = validate(&cli) {
        err.exit();
    }
    match cli.command {
        Cmd::Check {
            conformance: true,
            network,
            only,
            list,
            json,
            ..
        } => crate::conformance::check(crate::conformance::ConformanceArgs {
            network,
            only,
            list,
            json,
        }),
        Cmd::Conformance {
            role: ConformanceRole::Probe { tag, ops },
        } => crate::conformance::probe::run_probe(tag.as_deref(), &ops),
        Cmd::Run {
            policy,
            session_dir,
            cwd,
            timeout,
            audit,
            cmd,
            test_break_rules,
        } => crate::run::run(crate::run::RunArgs {
            policy,
            session_dir,
            cwd,
            timeout,
            audit,
            cmd,
            test_break_rules,
        }),
        Cmd::Check {
            print_schema: true, ..
        } => check_print_schema(),
        Cmd::Check {
            policy: Some(path),
            host: false,
            ..
        } => check(path),
        Cmd::Check {
            policy,
            host,
            json,
            test_break_rules,
            ..
        } => crate::host::check(crate::host::CheckArgs {
            policy,
            host,
            json,
            test_break_rules,
        }),
        Cmd::Gc {
            older_than,
            dry_run,
            root,
        } => crate::gc::gc(crate::gc::GcArgs {
            root,
            older_than,
            dry_run,
        }),
        Cmd::Init {
            fd,
            keep_fd,
            seccomp_fd,
            parent_pid,
            min_mode,
            test_break_rules,
            probe,
            bwrap,
            cmd,
        } => {
            if probe {
                return crate::init::probe::run_probe(bwrap, test_break_rules);
            }
            let Some(fd) = fd else {
                unreachable!("clap enforces --fd unless --probe")
            };
            crate::init::run_init(crate::init::InitArgs {
                fd,
                keep_fd,
                seccomp_fd,
                parent_pid,
                min_mode: min_mode.unwrap_or(NetworkMode::Transparent),
                test_break_rules,
                cmd,
            })
        }
    }
}

/// `check` dispatch: print the JSON Schema, or validate a policy file.
///
/// Success is silent — scripting callers rely on the exit code alone. Both
/// an invalid policy and an unreadable file are runtime failures (rc 1 with
/// the reason on stderr), never usage errors: rc 2 stays clap's. A closed
/// stdout (broken pipe, e.g. `check --print-schema | true`) is not an sbx
/// failure either: Unix convention, silent rc 0 — `println!` would panic
/// (rc 101) because Rust ignores SIGPIPE.
fn check_print_schema() -> ExitCode {
    use std::io::Write;
    let mut out = std::io::stdout();
    match writeln!(out, "{}", crate::policy::schema_json()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sbx check: cannot write schema to stdout: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `check --policy P` (validate-only, probe-free): silent rc 0 on success.
fn check(path: PathBuf) -> ExitCode {
    match crate::policy::Policy::from_file(&path) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sbx check: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use std::path::Path;

    // ---- happy paths -------------------------------------------------

    #[test]
    fn run_parses_full_documented_interface() {
        let cli = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
            "--cwd",
            "/w",
            "--timeout",
            "90s",
            "--audit",
            "a.jsonl",
            "--",
            "/bin/echo",
            "--help",
            "--not-a-flag",
        ])
        .expect("full run invocation must parse");
        match cli.command {
            Cmd::Run {
                policy,
                session_dir,
                cwd,
                timeout,
                audit,
                cmd,
                test_break_rules,
            } => {
                assert!(!test_break_rules);
                assert_eq!(policy, Path::new("p.json"));
                assert_eq!(session_dir, Path::new("/tmp/s"));
                assert_eq!(cwd.as_deref(), Some(Path::new("/w")));
                assert_eq!(timeout, Some(Duration::from_secs(90)));
                assert_eq!(audit.as_deref(), Some(Path::new("a.jsonl")));
                // Hyphenated args survive verbatim; the `--` separator itself
                // is consumed by clap and never reaches cmd.
                assert_eq!(cmd, ["/bin/echo", "--help", "--not-a-flag"]);
            }
            other => panic!("expected Cmd::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_timeout_absent_is_none() {
        let cli = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
            "--",
            "true",
        ])
        .expect("minimal run invocation must parse");
        match cli.command {
            Cmd::Run {
                cwd,
                timeout,
                audit,
                cmd,
                ..
            } => {
                assert_eq!(timeout, None);
                assert_eq!(cwd, None);
                assert_eq!(audit, None);
                assert_eq!(cmd, ["true"]);
            }
            other => panic!("expected Cmd::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_without_double_dash_still_preserves_hyphens() {
        // `allow_hyphen_values` + `trailing_var_arg`: once the first
        // positional is seen, the rest of argv (hyphenated or not) is the
        // command. `--` is the documented form but not strictly required.
        let cli = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
            "/bin/echo",
            "--help",
        ])
        .expect("run without -- must parse");
        match cli.command {
            Cmd::Run { cmd, .. } => assert_eq!(cmd, ["/bin/echo", "--help"]),
            other => panic!("expected Cmd::Run, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_preserves_non_utf8_args() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        // Linux argv is arbitrary bytes: the verbatim contract must survive
        // arguments that are not valid UTF-8 (a `String` value parser would
        // reject these with InvalidUtf8, exit 2).
        let bad = OsString::from_vec(b"/bin/\xff-cmd".to_vec());
        let cli = Cli::try_parse_from(
            [
                "sbx",
                "run",
                "--policy",
                "p.json",
                "--session-dir",
                "/tmp/s",
                "--",
            ]
            .into_iter()
            .map(OsString::from)
            .chain([bad.clone()]),
        )
        .expect("non-UTF-8 trailing args must survive verbatim");
        match cli.command {
            Cmd::Run { cmd, .. } => {
                assert_eq!(cmd, [bad]);
                assert_eq!(cmd[0].as_bytes(), b"/bin/\xff-cmd");
            }
            other => panic!("expected Cmd::Run, got {other:?}"),
        }
    }

    #[test]
    fn check_parses() {
        let cli = Cli::try_parse_from(["sbx", "check", "--policy", "p.json"])
            .expect("check invocation must parse");
        match cli.command {
            Cmd::Check {
                policy,
                print_schema,
                ..
            } => {
                assert_eq!(policy.as_deref(), Some(Path::new("p.json")));
                assert!(!print_schema);
            }
            other => panic!("expected Cmd::Check, got {other:?}"),
        }
    }

    #[test]
    fn check_print_schema_parses() {
        let cli = Cli::try_parse_from(["sbx", "check", "--print-schema"])
            .expect("check --print-schema must parse");
        match cli.command {
            Cmd::Check {
                policy,
                print_schema,
                ..
            } => {
                assert_eq!(policy, None);
                assert!(print_schema);
            }
            other => panic!("expected Cmd::Check, got {other:?}"),
        }
    }

    #[test]
    fn gc_parses_duration_and_root() {
        let cli = Cli::try_parse_from(["sbx", "gc", "--older-than", "7d", "/var/tmp/root"])
            .expect("gc invocation must parse");
        match cli.command {
            Cmd::Gc {
                older_than,
                root,
                dry_run,
            } => {
                assert_eq!(older_than, Duration::from_secs(7 * 24 * 3600));
                assert_eq!(root, Path::new("/var/tmp/root"));
                assert!(!dry_run);
            }
            other => panic!("expected Cmd::Gc, got {other:?}"),
        }
    }

    #[test]
    fn gc_parses_dry_run() {
        let cli = Cli::try_parse_from(["sbx", "gc", "--dry-run", "--older-than", "1h", "/r"])
            .expect("gc --dry-run must parse");
        match cli.command {
            Cmd::Gc { dry_run, root, .. } => {
                assert!(dry_run);
                assert_eq!(root, Path::new("/r"));
            }
            other => panic!("expected Cmd::Gc, got {other:?}"),
        }
    }

    #[test]
    fn gc_help_lists_dry_run() {
        let mut cmd = Cli::command();
        let gc = cmd.find_subcommand_mut("gc").expect("gc subcommand exists");
        let help = gc.render_help().to_string();
        assert!(
            help.contains("--dry-run"),
            "gc help must list --dry-run:\n{help}"
        );
    }

    // ---- error paths -------------------------------------------------

    #[test]
    fn run_requires_policy() {
        let err = Cli::try_parse_from(["sbx", "run", "--session-dir", "/tmp/s", "--", "true"])
            .expect_err("run without --policy must fail");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_requires_trailing_command() {
        let err = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
        ])
        .expect_err("run without a trailing command must fail");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn gc_rejects_bad_duration() {
        let err = Cli::try_parse_from(["sbx", "gc", "--older-than", "abc", "/tmp/root"])
            .expect_err("gc with a bad duration must fail");
        // clap reports custom value_parser failures as ValueValidation
        // (InvalidValue is for possible-values violations).
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn gc_rejects_zero_duration() {
        // The zero cutoff through the full clap seam: a destructive-by-typo
        // `gc --older-than 0s` must be a usage error (exit 2), never a parse
        // success that matches every session directory.
        let err = Cli::try_parse_from(["sbx", "gc", "--older-than", "0s", "/tmp/root"])
            .expect_err("gc with a zero cutoff must fail");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn run_rejects_bad_duration() {
        let err = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
            "--timeout",
            "abc",
            "--",
            "true",
        ])
        .expect_err("run with a bad --timeout must fail");
        // Same ValueValidation contract as gc's --older-than: the humantime
        // parser rejects "abc" (the binary reports `invalid value 'abc' for
        // '--timeout <DURATION>'` and exits 2).
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn run_rejects_zero_timeout() {
        // Symmetric with gc_rejects_zero_duration: `--timeout 0s` is
        // semantically undefined (kill immediately vs. never) and must be a
        // usage error (exit 2), never a silently accepted sentinel.
        let err = Cli::try_parse_from([
            "sbx",
            "run",
            "--policy",
            "p.json",
            "--session-dir",
            "/tmp/s",
            "--timeout",
            "0s",
            "--",
            "true",
        ])
        .expect_err("run with a zero --timeout must fail");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn check_bare_parses() {
        // Issue #11: a bare `check` is the host report (no longer a usage error).
        let cli = Cli::try_parse_from(["sbx", "check"]).expect("bare check must parse");
        validate(&cli).expect("bare check is valid");
        match cli.command {
            Cmd::Check {
                policy,
                print_schema,
                host,
                json,
                test_break_rules,
                conformance,
                ..
            } => {
                assert_eq!(
                    (
                        policy,
                        print_schema,
                        host,
                        json,
                        test_break_rules,
                        conformance
                    ),
                    (None, false, false, false, false, false)
                );
            }
            other => panic!("expected Cmd::Check, got {other:?}"),
        }
    }

    #[test]
    fn check_json_and_host_forms_parse() {
        for argv in [
            &["sbx", "check", "--json"][..],
            &["sbx", "check", "--policy", "p.json", "--host"][..],
            &["sbx", "check", "--policy", "p.json", "--host", "--json"][..],
        ] {
            let cli = Cli::try_parse_from(argv).expect("must parse");
            validate(&cli).expect("valid");
        }
    }

    #[test]
    fn check_host_requires_policy() {
        let err = Cli::try_parse_from(["sbx", "check", "--host"]).expect_err("--host alone");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn check_validate_only_rejects_json_and_break_rules() {
        let cli = Cli::try_parse_from(["sbx", "check", "--policy", "p.json", "--json"])
            .expect("parses; validate rejects");
        let err = validate(&cli).expect_err("--json needs --host");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        let cli = Cli::try_parse_from(["sbx", "check", "--policy", "p.json", "--test-break-rules"])
            .expect("parses");
        assert!(validate(&cli).is_err());
    }

    #[test]
    fn check_print_schema_conflicts_with_host_and_json() {
        for argv in [
            &["sbx", "check", "--print-schema", "--json"][..],
            &["sbx", "check", "--print-schema", "--host"][..],
        ] {
            let err = Cli::try_parse_from(argv).expect_err("must conflict");
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn check_hidden_flags_absent_from_help() {
        let mut check = Cli::command();
        let help = check
            .find_subcommand_mut("check")
            .expect("check exists")
            .render_long_help()
            .to_string();
        assert!(!help.contains("test-break-rules"), "{help}");
        assert!(help.contains("--json"), "{help}");
        let run = Cli::command()
            .find_subcommand_mut("run")
            .expect("run exists")
            .render_long_help()
            .to_string();
        assert!(!run.contains("test-break-rules"), "{run}");
    }

    #[test]
    fn init_probe_parses_without_fd() {
        let cli = Cli::try_parse_from(["sbx", "__init", "--probe", "--bwrap", "/usr/bin/bwrap"])
            .expect("probe must parse");
        match cli.command {
            Cmd::Init {
                probe,
                bwrap,
                fd,
                cmd,
                ..
            } => {
                assert!(probe);
                assert_eq!(bwrap.as_deref(), Some(Path::new("/usr/bin/bwrap")));
                assert_eq!(fd, None);
                assert!(cmd.is_empty());
            }
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_probe_conflicts_with_pipeline_args() {
        let err = Cli::try_parse_from(["sbx", "__init", "--probe", "--fd", "3"])
            .expect_err("--probe with --fd");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        let err = Cli::try_parse_from(["sbx", "__init", "--probe", "--", "/bin/true"])
            .expect_err("--probe with a command");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn init_requires_fd_without_probe() {
        let err = Cli::try_parse_from(["sbx", "__init", "--", "/bin/true"])
            .expect_err("no --fd and no --probe");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn init_min_mode_parses_and_rejects_bogus() {
        let cli = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "3",
            "--min-mode",
            "explicit",
            "--",
            "/bin/true",
        ])
        .expect("min-mode parses");
        match cli.command {
            Cmd::Init { min_mode, .. } => assert_eq!(min_mode, Some(NetworkMode::Explicit)),
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
        let err = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "3",
            "--min-mode",
            "bogus",
            "--",
            "/bin/true",
        ])
        .expect_err("bogus mode");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn parse_network_mode_table() {
        assert_eq!(
            parse_network_mode("transparent"),
            Ok(NetworkMode::Transparent)
        );
        assert_eq!(parse_network_mode("explicit"), Ok(NetworkMode::Explicit));
        assert_eq!(parse_network_mode("none"), Ok(NetworkMode::None));
        assert_eq!(
            parse_network_mode("Explicit"),
            Err("`Explicit` is not a network mode (transparent, explicit, none)".to_owned())
        );
    }

    #[test]
    fn check_rejects_policy_with_print_schema() {
        // `conflicts_with`: printing the schema ignores the policy file, so
        // combining the flags is a usage error (exit 2), never a silent
        // print-and-ignore.
        let err = Cli::try_parse_from(["sbx", "check", "--policy", "p.json", "--print-schema"])
            .expect_err("--policy with --print-schema must fail");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        let err = Cli::try_parse_from(["sbx", "nope"]).expect_err("unknown subcommand must fail");
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn bare_invocation_reports_missing_subcommand() {
        // Freezes the no-subcommand UX: bare `sbx` must yield clap's
        // help-on-missing-subcommand error (binary: exit 2 + help text),
        // never a silent success or a stub message.
        let err = Cli::try_parse_from(["sbx"]).expect_err("bare sbx must fail");
        assert_eq!(
            err.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    // ---- hidden __init contract --------------------------------------

    // Helper: parse an __init invocation that must succeed and destructure
    // the three fields.
    fn init_of(args: &[&str]) -> (RawFd, bool, Vec<OsString>) {
        let cli = Cli::try_parse_from(["sbx", "__init"].into_iter().chain(args.iter().copied()))
            .expect("__init invocation must parse");
        match cli.command {
            Cmd::Init {
                fd,
                test_break_rules,
                cmd,
                ..
            } => (fd.expect("--fd given"), test_break_rules, cmd),
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_parses_keep_fd() {
        let cli = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "7",
            "--keep-fd",
            "9",
            "--",
            "/bin/true",
        ])
        .expect("--keep-fd must parse");
        match cli.command {
            Cmd::Init { keep_fd, .. } => assert_eq!(keep_fd, Some(9)),
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_parses_seccomp_fd() {
        let cli = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "7",
            "--seccomp-fd",
            "11",
            "--",
            "/bin/true",
        ])
        .expect("--seccomp-fd must parse");
        match cli.command {
            Cmd::Init { seccomp_fd, .. } => assert_eq!(seccomp_fd, Some(11)),
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_seccomp_fd_hidden_in_help() {
        let help = <Cli as clap::CommandFactory>::command()
            .find_subcommand("__init")
            .expect("__init subcommand")
            .clone()
            .render_long_help()
            .to_string();
        assert!(!help.contains("--seccomp-fd"), "{help}");
    }

    #[test]
    fn init_probe_conflicts_with_seccomp_fd() {
        let err = Cli::try_parse_from(["sbx", "__init", "--probe", "--seccomp-fd", "11"])
            .expect_err("--probe must conflict with --seccomp-fd");
        assert!(
            err.to_string().contains("--seccomp-fd") || err.to_string().contains("cannot be used"),
            "{err}"
        );
    }

    #[test]
    fn init_rejects_negative_seccomp_fd() {
        assert!(
            Cli::try_parse_from([
                "sbx",
                "__init",
                "--fd",
                "7",
                "--seccomp-fd",
                "-1",
                "--",
                "/bin/true"
            ])
            .is_err()
        );
    }

    #[test]
    fn init_parses_parent_pid() {
        let cli = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "7",
            "--parent-pid",
            "4242",
            "--",
            "/bin/true",
        ])
        .expect("--parent-pid must parse");
        match cli.command {
            Cmd::Init { parent_pid, .. } => assert_eq!(parent_pid, Some(4242)),
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_keep_fd_hidden_in_help() {
        let help = <Cli as clap::CommandFactory>::command()
            .find_subcommand("__init")
            .expect("__init subcommand")
            .clone()
            .render_long_help()
            .to_string();
        assert!(!help.contains("--keep-fd"), "{help}");
    }

    #[test]
    fn init_rejects_negative_keep_fd() {
        let err = Cli::try_parse_from([
            "sbx",
            "__init",
            "--fd",
            "7",
            "--keep-fd",
            "-1",
            "--",
            "/bin/true",
        ])
        .expect_err("negative --keep-fd must be rejected");
        assert!(
            err.to_string().contains("-1") || err.to_string().contains("keep-fd"),
            "{err}"
        );
    }

    #[test]
    fn init_parses_full_form() {
        let (fd, tbr, cmd) = init_of(&["--fd", "7", "--", "/bin/echo", "--help", "-x"]);
        assert_eq!(fd, 7);
        assert!(!tbr);
        // Hyphenated args survive verbatim; the `--` separator itself is
        // consumed by clap and never reaches cmd (same contract as `run`).
        assert_eq!(cmd, ["/bin/echo", "--help", "-x"]);
    }

    #[test]
    fn init_parses_equals_form_fd() {
        let (fd, _, cmd) = init_of(&["--fd=7", "--", "/bin/true"]);
        assert_eq!(fd, 7);
        assert_eq!(cmd, ["/bin/true"]);
    }

    #[cfg(unix)]
    #[test]
    fn init_preserves_non_utf8_cmd() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        // Linux argv is arbitrary bytes: the verbatim contract must survive
        // non-UTF-8 payload arguments (a `String` parser would reject them
        // with exit 2) — exec_payload consumes them as OsStr bytes.
        let bad = OsString::from_vec(b"/bin/\xff-payload".to_vec());
        let cli = Cli::try_parse_from(
            ["sbx", "__init", "--fd", "3", "--"]
                .into_iter()
                .map(OsString::from)
                .chain([bad.clone()]),
        )
        .expect("non-UTF-8 payload args must survive verbatim");
        match cli.command {
            Cmd::Init { cmd, .. } => {
                assert_eq!(cmd, [bad]);
                assert_eq!(cmd[0].as_bytes(), b"/bin/\xff-payload");
            }
            other => panic!("expected Cmd::Init, got {other:?}"),
        }
    }

    #[test]
    fn init_requires_fd() {
        // REPLACES the old hidden_init_parses: a bare `__init` is now a
        // usage error (rc 2), never a parse success.
        let err =
            Cli::try_parse_from(["sbx", "__init", "--", "/bin/true"]).expect_err("--fd required");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn init_requires_command() {
        // D7: `cmd` is required — an `__init` with nothing to exec has no
        // runtime meaning, and rc 2 keeps rc 1 exclusively for staged
        // setup failures.
        let err = Cli::try_parse_from(["sbx", "__init", "--fd", "3"])
            .expect_err("a trailing command must be required");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn init_rejects_negative_fd() {
        // D8, probe-verified: BOTH spellings hand the hyphenated token to
        // the value parser (not to clap's flag matcher), so one range check
        // covers `--fd -1` and `--fd=-1`.
        for args in [
            vec!["--fd", "-1", "--", "/bin/true"],
            vec!["--fd=-1", "--", "/bin/true"],
        ] {
            let err = Cli::try_parse_from(["sbx", "__init"].into_iter().chain(args))
                .expect_err("negative fd must be a usage error");
            assert_eq!(err.kind(), ErrorKind::ValueValidation, "{err}");
        }
    }

    #[test]
    fn init_rejects_non_numeric_fd() {
        let err = Cli::try_parse_from(["sbx", "__init", "--fd", "abc", "--", "/bin/true"])
            .expect_err("non-numeric fd must be a usage error");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn init_rejects_out_of_range_fd() {
        // 2^32 — parses as an integer but is not a valid RawFd; the parser
        // reports the range, not clap's generic overflow text.
        let err = Cli::try_parse_from(["sbx", "__init", "--fd", "4294967296", "--", "/bin/true"])
            .expect_err("out-of-range fd must be a usage error");
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn init_test_break_rules_parses_and_is_hidden() {
        let (fd, tbr, cmd) = init_of(&["--fd", "3", "--test-break-rules", "--", "/bin/true"]);
        assert_eq!(fd, 3);
        assert!(tbr);
        assert_eq!(cmd, ["/bin/true"]);
        // The flag is fail-only test surface (Q4(a)): it must never render
        // in the (already hidden) __init help.
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("__init")
            .expect("hidden subcommands stay findable")
            .render_help()
            .to_string();
        assert!(
            !help.contains("test-break-rules"),
            "hidden flag must not render:\n{help}"
        );
    }

    #[test]
    fn help_lists_public_subcommands_and_hides_init() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("run"), "help must list run:\n{help}");
        assert!(help.contains("check"), "help must list check:\n{help}");
        assert!(help.contains("gc"), "help must list gc:\n{help}");
        assert!(!help.contains("__init"), "help must hide __init:\n{help}");
    }

    #[test]
    fn check_help_lists_both_flags() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("check")
            .expect("check subcommand must exist")
            .render_help()
            .to_string();
        assert!(
            help.contains("--policy"),
            "help must list --policy:\n{help}"
        );
        assert!(
            help.contains("--print-schema"),
            "help must list --print-schema:\n{help}"
        );
    }

    // ---- duration parser ---------------------------------------------

    #[test]
    fn parse_duration_table() {
        assert_eq!(parse_duration("120s").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn parse_duration_rejects_zero() {
        // Pins the positive-duration contract: every zero spelling humantime
        // accepts must be rejected, so `gc --older-than 0s` (a cutoff of
        // *now* — matches every session, destructive typo) and the ambiguous
        // `--timeout 0s` (kill immediately vs. never) are usage errors.
        for s in ["0", "0s", "0ms", "0d", "00s"] {
            assert!(parse_duration(s).is_err(), "{s:?} must be rejected");
        }
    }

    // ---- control-fd parser ----------------------------------------------

    #[test]
    fn parse_control_fd_table() {
        // The full acceptance table (D8): valid fd numbers pass through;
        // negatives, non-integers, the empty string and anything past
        // i32::MAX are Strings (clap renders them as ValueValidation, rc 2).
        assert_eq!(parse_control_fd("0"), Ok(0));
        assert_eq!(parse_control_fd("7"), Ok(7));
        assert_eq!(parse_control_fd("2147483647"), Ok(i32::MAX));
        for bad in ["-1", "abc", "", "4294967296", "7.0", " 7", "0x7"] {
            assert!(parse_control_fd(bad).is_err(), "{bad:?} must be rejected");
        }
        // "-0" parses as the integer 0 (Rust's FromStr accepts it) — a
        // harmless spelling of stdin's fd number, accepted like "0".
        assert_eq!(parse_control_fd("-0"), Ok(0));
    }

    // ---- clap configuration validity ----------------------------------

    #[test]
    fn clap_config_is_valid() {
        Cli::command().debug_assert();
    }

    // ---- issue #13: `check --conformance` and the hidden `__conformance`.

    fn kind_of(args: &[&str]) -> Option<ErrorKind> {
        let mut full = vec!["sbx"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).err().map(|e| e.kind())
    }

    #[test]
    fn check_conformance_parses() {
        let cli = Cli::try_parse_from([
            "sbx",
            "check",
            "--conformance",
            "--only",
            "a01,B",
            "--network",
        ])
        .expect("parses");
        match cli.command {
            Cmd::Check {
                conformance,
                network,
                only,
                list,
                ..
            } => {
                assert!(conformance && network && !list);
                assert_eq!(only, ["a01", "B"]);
            }
            other => panic!("expected Cmd::Check, got {other:?}"),
        }
    }

    #[test]
    fn conformance_conflicts_with_policy_host_print_schema_and_break_rules() {
        for extra in [
            vec!["--policy", "p.json"],
            vec!["--host"],
            vec!["--print-schema"],
            vec!["--test-break-rules"],
        ] {
            let mut args = vec!["check", "--conformance"];
            args.extend(extra.iter().copied());
            assert_eq!(
                kind_of(&args),
                Some(ErrorKind::ArgumentConflict),
                "{args:?}"
            );
        }
    }

    #[test]
    fn conformance_only_flags_need_conformance() {
        assert_eq!(
            kind_of(&["check", "--network"]),
            Some(ErrorKind::MissingRequiredArgument)
        );
        assert_eq!(
            kind_of(&["check", "--only", "A01"]),
            Some(ErrorKind::MissingRequiredArgument)
        );
        assert_eq!(
            kind_of(&["check", "--list"]),
            Some(ErrorKind::MissingRequiredArgument)
        );
    }

    #[test]
    fn list_conflicts_with_only() {
        assert_eq!(
            kind_of(&["check", "--conformance", "--list", "--only", "A01"]),
            Some(ErrorKind::ArgumentConflict)
        );
    }

    #[test]
    fn list_conflicts_with_network() {
        assert_eq!(
            kind_of(&["check", "--conformance", "--list", "--network"]),
            Some(ErrorKind::ArgumentConflict)
        );
    }

    #[test]
    fn only_unknown_selector_is_a_validate_error() {
        let cli = Cli::try_parse_from(["sbx", "check", "--conformance", "--only", "Z99"])
            .expect("parses");
        let err = validate(&cli).expect_err("Z99 is unknown");
        assert_eq!(err.kind(), ErrorKind::InvalidValue);
        let ok = Cli::try_parse_from(["sbx", "check", "--conformance", "--only", "a01,B"])
            .expect("parses");
        assert!(validate(&ok).is_ok());
    }

    #[test]
    fn hidden_conformance_subcommand_is_not_in_help() {
        let mut cmd = Cli::command();
        let help = cmd.render_help().to_string();
        assert!(!help.contains("__conformance"), "{help}");
        let check = Cli::command()
            .find_subcommand_mut("check")
            .expect("check")
            .render_help()
            .to_string();
        assert!(check.contains("--conformance"));
    }

    #[test]
    fn conformance_probe_parses_tag_and_ops() {
        let cli = Cli::try_parse_from(["sbx", "__conformance", "probe", "--tag", "t", "{}"])
            .expect("parses");
        match cli.command {
            Cmd::Conformance {
                role: ConformanceRole::Probe { tag, ops },
            } => {
                assert_eq!(tag.as_deref(), Some("t"));
                assert_eq!(ops, "{}");
            }
            other => panic!("expected the probe role, got {other:?}"),
        }
    }
}
