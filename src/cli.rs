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
    // conflicting attributes) in tests and debug builds; cheap no-op-ish
    // check in release.
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
