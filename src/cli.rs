//! Command-line interface for `sbx`.
//!
//! Issue #2 freezes the documented flag surface: every subcommand parses its
//! full interface, then reports `not implemented yet` and exits 1. Later
//! issues replace the stub bodies behind [`run`] without CLI churn:
//!
//! - `run`    — sandbox lifecycle, egress proxy, audit log (#10, #7, #8)
//! - `check`  — policy validation (#3)
//! - `gc`     — session-directory garbage collection (#12)
//! - `__init` — re-exec'd namespace helper (#5 defines its real interface)
//!
//! Exit-code contract: 0 = success, 1 = stub/runtime failure
//! ([`ExitCode::FAILURE`]), 2 = usage error (clap's own convention).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand};

/// Parse a human-readable duration (`120s`, `7d`, `500ms`, ...) for clap.
///
/// Thin wrapper around [`humantime::parse_duration`]; the error is mapped to
/// [`String`] so clap reports it as an invalid-value usage error (exit 2).
/// Public for reuse by later issues (#5, #10, #12) and unit tests.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| e.to_string())
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

        /// Kill the command after this long (e.g. 90s, 2h, 7d).
        #[arg(
            long,
            value_name = "DURATION",
            default_value = "120s",
            value_parser = parse_duration
        )]
        timeout: Duration,

        /// Audit log file (JSON Lines).
        #[arg(long, value_name = "FILE")]
        audit: Option<PathBuf>,

        /// Command to run, verbatim — everything after `--`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            num_args = 1..,
            required = true
        )]
        cmd: Vec<String>,
    },

    /// Validate a policy file without running anything.
    Check {
        /// Sandbox policy file (JSON) to validate.
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,
    },

    /// Delete session directories older than a cutoff.
    Gc {
        /// Age cutoff (e.g. 12h, 7d); older sessions are deleted.
        #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
        older_than: Duration,

        /// Session root directory to scan.
        #[arg(value_name = "ROOT")]
        root: PathBuf,
    },

    /// Internal namespace helper, re-exec'd by `run` (hidden; #5 defines it).
    #[command(name = "__init", hide = true)]
    Init,
}

/// Binary entry point: parse `argv` and dispatch to the (stub) subcommand.
///
/// Stub contract (issue #2): a successfully parsed subcommand prints
/// `sbx <sub>: not implemented yet` to stderr and returns
/// [`ExitCode::FAILURE`] (1) — deliberately distinct from clap's exit 2 for
/// usage errors, and without the exit-101 + backtrace a panic would produce.
pub fn run() -> ExitCode {
    // Catches invalid clap configuration (bad defaults, duplicate names,
    // conflicting attributes) at startup. Despite the name, this is NOT
    // gated on cfg(debug_assertions): it runs in every profile — tests,
    // debug, and release alike — at negligible cost (once per process).
    Cli::command().debug_assert();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Run { .. } => not_implemented("run"),
        Cmd::Check { .. } => not_implemented("check"),
        Cmd::Gc { .. } => not_implemented("gc"),
        Cmd::Init => not_implemented("__init"),
    }
}

/// Uniform stub behavior: message on stderr, exit code 1.
fn not_implemented(sub: &str) -> ExitCode {
    eprintln!("sbx {sub}: not implemented yet");
    ExitCode::FAILURE
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
            } => {
                assert_eq!(policy, Path::new("p.json"));
                assert_eq!(session_dir, Path::new("/tmp/s"));
                assert_eq!(cwd.as_deref(), Some(Path::new("/w")));
                assert_eq!(timeout, Duration::from_secs(90));
                assert_eq!(audit.as_deref(), Some(Path::new("a.jsonl")));
                // Hyphenated args survive verbatim; the `--` separator itself
                // is consumed by clap and never reaches cmd.
                assert_eq!(cmd, ["/bin/echo", "--help", "--not-a-flag"]);
            }
            other => panic!("expected Cmd::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_defaults_timeout_to_120s() {
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
                assert_eq!(timeout, Duration::from_secs(120));
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

    #[test]
    fn check_parses() {
        let cli = Cli::try_parse_from(["sbx", "check", "--policy", "p.json"])
            .expect("check invocation must parse");
        match cli.command {
            Cmd::Check { policy } => assert_eq!(policy, Path::new("p.json")),
            other => panic!("expected Cmd::Check, got {other:?}"),
        }
    }

    #[test]
    fn gc_parses_duration_and_root() {
        let cli = Cli::try_parse_from(["sbx", "gc", "--older-than", "7d", "/var/tmp/root"])
            .expect("gc invocation must parse");
        match cli.command {
            Cmd::Gc { older_than, root } => {
                assert_eq!(older_than, Duration::from_secs(7 * 24 * 3600));
                assert_eq!(root, Path::new("/var/tmp/root"));
            }
            other => panic!("expected Cmd::Gc, got {other:?}"),
        }
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

    #[test]
    fn hidden_init_parses() {
        let cli = Cli::try_parse_from(["sbx", "__init"]).expect("__init must parse");
        assert!(matches!(cli.command, Cmd::Init));
    }

    #[test]
    fn help_lists_public_subcommands_and_hides_init() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("run"), "help must list run:\n{help}");
        assert!(help.contains("check"), "help must list check:\n{help}");
        assert!(help.contains("gc"), "help must list gc:\n{help}");
        assert!(!help.contains("__init"), "help must hide __init:\n{help}");
    }

    // ---- duration parser ---------------------------------------------

    #[test]
    fn parse_duration_table() {
        assert_eq!(parse_duration("120s").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert!(parse_duration("abc").is_err());
    }

    // ---- clap configuration validity ----------------------------------

    #[test]
    fn clap_config_is_valid() {
        Cli::command().debug_assert();
    }
}
