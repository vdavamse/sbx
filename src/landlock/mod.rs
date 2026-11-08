//! The optional Landlock layer (issue #19, `sbx run --landlock`).
//!
//! 1. **Where it runs (D1).** The ruleset is applied by an exec shim INSIDE
//!    the sandbox. `run` makes bwrap's command `/proc/self/fd/N __landlock …
//!    -- CMD`; the shim applies the ruleset and `execvp`s `CMD`. It is not
//!    applied in `__init`: Landlock's filesystem rules forbid the mount and
//!    `pivot_root` operations that bwrap performs for the restricted thread,
//!    so a ruleset applied before bwrap would break bwrap's own setup. The
//!    filesystem, TCP-bind and signal-scope rules all go in the shim, so the
//!    layer is one mechanism.
//! 2. **Opt-in (D3).** `--landlock off`, the default, adds nothing: the bwrap
//!    argv is byte-identical to a run without the layer, and every existing
//!    golden is unchanged. The layer is a `run` flag rather than a policy
//!    field, because the policy schema is a pinned v1 contract whose sections
//!    are all required.
//! 3. **Modes (D4).** `best-effort` uses the crate's BestEffort compatibility:
//!    a kernel without Landlock, or with an older ABI, runs with the subset it
//!    supports, silently. `require` uses HardRequirement on the full set
//!    (filesystem, TCP bind at ABI 4, signal scope at ABI 6, so Linux 6.12 or
//!    later). `sbx run` checks the ABI host-side ([`require_refusal`], rc 125
//!    before anything is spawned), and the shim enforces again. A shim failure
//!    of any other kind also fails closed: rc 125 with `sbx __landlock:
//!    <reason>` on stderr and in the status pipe (point 9), and the payload
//!    never runs. A payload the shim cannot exec is not a shim failure (issue
//!    #74): the shim exits 127 (not found) or 126 (not executable), as a shell
//!    would, and reports `exec-failed RC REASON` ([`EXEC_FAILED_PREFIX`]).
//! 4. **Rules mirror the mount list (D5).** [`PathRule`]s are derived from the
//!    same merged mount list `bwrap::build` emits (`bwrap::argv`), and they name
//!    the paths the payload SEES, the sandbox-side destinations, because the
//!    shim runs in the sandbox's mount namespace. Read-only mounts get
//!    [`Grant::Read`] (read, execute and list). Read-write mounts, `/proc` and
//!    `/dev` get [`Grant::All`]. `/` gets [`Grant::ReadDir`], so `ls /` works
//!    and creating an entry at `/` does not. Deny masks (`--tmpfs`) get no
//!    rule of their own. A rule whose path cannot be opened grants nothing
//!    (`path_beneath_rules` skips it), which is the fail-closed direction.
//! 5. **What is handled (D6, D7).** Filesystem: every right up to ABI 6
//!    ([`REQUESTED_ABI`]). TCP bind: `AccessNet::BindTcp`, with one `NetPort`
//!    rule per `--landlock-bind-tcp` port (0 is the kernel's ephemeral range).
//!    Signal scope: `Scope::Signal`, so the payload cannot signal processes
//!    outside its domain (bwrap's pid 1, and anything else on the host).
//!    `connect_tcp` is NOT handled: egress stays with the netns and the
//!    proxies, which is the issue's scope. Abstract-socket scope and
//!    `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (threat model R6) are not handled.
//! 6. **Descriptors (D2).** `run` opens its own executable (`/proc/self/exe`,
//!    the same file `__init` re-execs), clears CLOEXEC in the spawn window and
//!    passes it as `--exe-fd`. `__init` validates it and keeps it through fd
//!    hygiene, and bwrap does not close it. The shim closes it, and every
//!    other descriptor above stdio except the status pipe, before it applies
//!    the ruleset. The status write end is close-on-exec from just before the
//!    exec, so the payload has exactly fds 0, 1 and 2. An unreadable
//!    `/proc/self/fd` is a shim failure (rc 125), not a silent continue.
//! 9. **Status pipe (issue #19 round 2, M1; start marker, round 3 item 2).**
//!    `run` creates a pipe with the
//!    write end passed as `--status-fd` (validated by `__init`, kept through
//!    hygiene, inherited by bwrap). On any shim failure the reason is written
//!    there before rc 125, so the run can tell a shim failure from the payload's
//!    own exit 125: the audit outcome is `failed` and the run prints `sbx run:
//!    landlock: <reason>`. The first thing the shim writes is [`STATUS_MARKER`],
//!    before any argument parsing ([`announce_start`]), so a failure before
//!    [`shim`] runs (a clap error, bwrap's exec of the shim failing, the dynamic
//!    loader failing) leaves a pipe with no marker, which `run` reports as "the
//!    shim did not start". On success the exec closes the write end, and the pipe
//!    holds the marker only. An exec failure of the payload adds
//!    [`EXEC_FAILED_PREFIX`], the rc and the reason after the marker, and `run`
//!    reports it as the outcome `exec_failed` (issue #74).
//! 10. **Host ABI check (round 2, m1).** `--host-abi` is the ABI `run` saw
//!     ([`host_abi`]). A best-effort ruleset that the kernel reports as NOT
//!     enforced while the host has Landlock fails closed ([`enforcement_failure`]),
//!     so an outer profile that refuses Landlock cannot pass as "no Landlock".
//! 7. **Irreversibility (test rule).** `restrict_self` is irreversible for the
//!    calling thread. Unit tests that apply a ruleset do it in a forked child
//!    and build the ruleset in the parent first (see [`prepare`]).
//! 8. **Dynamic binaries (D9).** The static musl release needs nothing from the
//!    sandbox to run the shim. A dynamically linked `sbx` build needs its shared
//!    libraries visible inside the sandbox when `--landlock` is on. This is
//!    documented, not pre-checked.

use std::ffi::{CString, OsStr, OsString};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ::landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope, path_beneath_rules,
};

use crate::host::facts::{Landlock as Probe, landlock as probe};

/// The ABI whose rights the rules request (module docs point 5). Every handled
/// right is at most this ABI's, so a kernel that supports it enforces all of
/// the requested set.
pub const REQUESTED_ABI: ABI = ABI::V6;

/// The lowest kernel ABI that `--landlock require` accepts: ABI 6 covers the
/// filesystem rules, TCP bind (ABI 4) and signal scope (ABI 6).
pub const REQUIRED_ABI: u32 = 6;

/// The `--landlock` setting. `Off` (the default) adds no layer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    BestEffort,
    Require,
}

impl Mode {
    /// The spelling the CLI and the shim argv both use.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::BestEffort => "best-effort",
            Mode::Require => "require",
        }
    }
}

/// Parse `--landlock` / `__landlock --mode` for clap: exactly `off`,
/// `best-effort` or `require`.
pub fn parse_mode(s: &str) -> Result<Mode, String> {
    match s {
        "off" => Ok(Mode::Off),
        "best-effort" => Ok(Mode::BestEffort),
        "require" => Ok(Mode::Require),
        other => Err(format!(
            "`{other}` is not a Landlock mode (off, best-effort, require)"
        )),
    }
}

/// What a rule grants on its path (module docs point 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grant {
    /// Read, execute and list: the read-only mounts.
    Read,
    /// List the directory only: `/`, so `ls /` works and nothing can be created there.
    ReadDir,
    /// Every filesystem right up to [`REQUESTED_ABI`]: read-write mounts, `/proc`, `/dev`.
    All,
}

impl Grant {
    /// The spelling used in the shim argv (`read`, `readdir`, `all`).
    pub fn as_str(self) -> &'static str {
        match self {
            Grant::Read => "read",
            Grant::ReadDir => "readdir",
            Grant::All => "all",
        }
    }

    fn parse(s: &str) -> Option<Grant> {
        match s {
            "read" => Some(Grant::Read),
            "readdir" => Some(Grant::ReadDir),
            "all" => Some(Grant::All),
            _ => None,
        }
    }
}

/// One filesystem rule: a sandbox-side absolute path and what it grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathRule {
    pub path: String,
    pub grant: Grant,
}

impl PathRule {
    pub fn new(path: &str, grant: Grant) -> Self {
        Self {
            path: path.to_owned(),
            grant,
        }
    }

    /// The shim argv spelling: `GRANT:PATH`. The grant has no colon, so the
    /// first colon splits it, and the path may contain any other byte.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.grant.as_str(), self.path)
    }

    /// Inverse of [`PathRule::encode`]. The path must be absolute and NUL-free
    /// (the same vocabulary the policy uses for every path).
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "`{text}` is not a Landlock rule (read|readdir|all, then `:` and an absolute path)"
            )
        };
        let (grant, path) = text.split_once(':').ok_or_else(bad)?;
        let grant = Grant::parse(grant).ok_or_else(bad)?;
        if !path.starts_with('/') || path.contains('\0') {
            return Err(bad());
        }
        Ok(Self {
            path: path.to_owned(),
            grant,
        })
    }
}

/// The layer as `build` receives it (module docs points 6, 9 and 10): the mode,
/// the TCP bind ports, sbx's own executable's fd, the status pipe's write end
/// and the host's Landlock ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub mode: Mode,
    /// `--landlock-bind-tcp` ports, in command-line order (0 = ephemeral range).
    pub bind_tcp: Vec<u16>,
    /// The sbx executable's fd (`--exe-fd`, module docs point 6).
    pub exe_fd: RawFd,
    /// The status pipe's write end (`--status-fd`, module docs point 9).
    pub status_fd: RawFd,
    /// The host's Landlock ABI as `run` saw it ([`host_abi`]; module docs point 10).
    pub host_abi: u32,
}

/// The shim argv elements from the `/proc/self/fd/N` program up to, but not
/// including, the `--` that separates the shim's flags from the payload:
/// `/proc/self/fd/N __landlock --exe-fd N --status-fd S --mode M --host-abi A
/// [--bind-tcp P]… [--rule R]…`. The rules come from [`PathRule`]s the caller
/// derived from the mount list.
pub fn shim_head(layer: &Layer, rules: &[PathRule]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = [
        format!("/proc/self/fd/{}", layer.exe_fd),
        "__landlock".to_owned(),
        "--exe-fd".to_owned(),
        layer.exe_fd.to_string(),
        "--status-fd".to_owned(),
        layer.status_fd.to_string(),
        "--mode".to_owned(),
        layer.mode.as_str().to_owned(),
        "--host-abi".to_owned(),
        layer.host_abi.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for port in &layer.bind_tcp {
        argv.push(OsString::from("--bind-tcp"));
        argv.push(OsString::from(port.to_string()));
    }
    for rule in rules {
        argv.push(OsString::from("--rule"));
        argv.push(OsString::from(rule.encode()));
    }
    argv
}

/// The kernel's Landlock ABI as `sbx` sees it: 0 when Landlock is missing or
/// disabled. Reuses the `sbx check` probe, so the two never disagree.
pub fn kernel_abi() -> u32 {
    match probe() {
        Probe::Abi(n) => n,
        Probe::Errno(_) => 0,
    }
}

/// The ABI the shim is told the host has (`--host-abi`, module docs point 10).
/// A probe refused with ENOSYS or EOPNOTSUPP means no Landlock (0). Any other
/// errno means Landlock is present but refused, for example by an outer
/// seccomp profile, so the value is 1: the shim must then enforce at least
/// the filesystem rules or fail closed.
pub fn host_abi() -> u32 {
    match probe() {
        Probe::Abi(n) => n,
        Probe::Errno(errno) if errno == libc::ENOSYS || errno == libc::EOPNOTSUPP => 0,
        Probe::Errno(_) => 1,
    }
}

/// The host-side refusal for `--landlock require` on a kernel below
/// [`REQUIRED_ABI`] (rc 125 before any spawn). `None` when the kernel is new
/// enough. The text is pinned by the unit tests and the `landlock-require`
/// integration scenario.
pub fn require_refusal(abi: u32) -> Option<String> {
    if abi >= REQUIRED_ABI {
        return None;
    }
    Some(if abi == 0 {
        format!(
            "landlock require: Landlock is not available on this kernel (ABI {REQUIRED_ABI}, Linux 6.12 or later, is required)"
        )
    } else {
        format!(
            "landlock require: the kernel's Landlock ABI is {abi}; ABI {REQUIRED_ABI} (Linux 6.12 or later) is required for the filesystem, TCP-bind and signal-scope rules"
        )
    })
}

/// Build the ruleset without applying it. Everything that can fail is done
/// here, so a test can prepare in the parent and apply in a forked child.
pub fn prepare(
    mode: Mode,
    bind_tcp: &[u16],
    rules: &[PathRule],
) -> Result<RulesetCreated, RulesetError> {
    let compat = match mode {
        Mode::Require => CompatLevel::HardRequirement,
        Mode::Off | Mode::BestEffort => CompatLevel::BestEffort,
    };
    let mut created = Ruleset::default()
        .set_compatibility(compat)
        .handle_access(AccessFs::from_all(REQUESTED_ABI))?
        .handle_access(AccessNet::BindTcp)?
        .scope(Scope::Signal)?
        .create()?;
    for rule in rules {
        created = match rule.grant {
            Grant::Read => created.add_rules(path_beneath_rules(
                [&rule.path],
                AccessFs::from_read(REQUESTED_ABI),
            ))?,
            Grant::ReadDir => {
                created.add_rules(path_beneath_rules([&rule.path], AccessFs::ReadDir))?
            }
            Grant::All => created.add_rules(path_beneath_rules(
                [&rule.path],
                AccessFs::from_all(REQUESTED_ABI),
            ))?,
        };
    }
    for port in bind_tcp {
        created = created.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
    }
    Ok(created)
}

/// Apply the ruleset to the calling thread (irreversible; module docs point 7)
/// and report what the kernel enforced.
pub fn apply(
    mode: Mode,
    bind_tcp: &[u16],
    rules: &[PathRule],
) -> Result<RulesetStatus, RulesetError> {
    Ok(prepare(mode, bind_tcp, rules)?.restrict_self()?.ruleset)
}

/// Module docs point 10: `Some(reason)` when the host has Landlock (ABI 1 or
/// later, see [`host_abi`]) but the ruleset was not enforced at all. That is
/// the outer-profile case, which best-effort must not mistake for "no Landlock".
pub fn enforcement_failure(host_abi: u32, status: RulesetStatus) -> Option<String> {
    (host_abi >= 1 && status == RulesetStatus::NotEnforced).then(|| {
        format!("Landlock is present (host ABI {host_abi}) but the ruleset was not enforced")
    })
}

/// The shim's parsed argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimArgs {
    pub exe_fd: RawFd,
    pub status_fd: RawFd,
    pub mode: Mode,
    pub host_abi: u32,
    pub bind_tcp: Vec<u16>,
    pub rules: Vec<PathRule>,
    pub cmd: Vec<OsString>,
}

/// The shim's own checks, before any descriptor is touched. An `--exe-fd` or
/// `--status-fd` at or below 2 would make the shim close or write stdio, so both
/// are refused, and they must differ.
pub fn check_shim_args(args: &ShimArgs) -> Result<(), String> {
    if args.exe_fd <= 2 {
        return Err(format!("--exe-fd {} must be greater than 2", args.exe_fd));
    }
    if args.status_fd <= 2 {
        return Err(format!(
            "--status-fd {} must be greater than 2",
            args.status_fd
        ));
    }
    if args.status_fd == args.exe_fd {
        return Err(format!(
            "--status-fd {} must differ from --exe-fd",
            args.status_fd
        ));
    }
    if args.cmd.is_empty() {
        return Err("no payload command given".to_owned());
    }
    Ok(())
}

/// Longest reason written to the status pipe (module docs point 9).
const STATUS_MAX_BYTES: usize = 512;

/// The shim's failure path (module docs points 3 and 9): the reason goes to
/// stderr and to the status pipe, then rc 125. Best effort on both: a closed
/// stderr or pipe must not panic (rc 101) or change the rc. The status write end
/// is written only when it is above stdio.
fn report_failure(status_fd: RawFd, reason: &str) -> ExitCode {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "sbx __landlock: {reason}");
    write_status(status_fd, reason.as_bytes());
    ExitCode::from(crate::run::EXIT_FAILURE as u8)
}

/// The payload could not be executed (issue #74): the reason goes to stderr and,
/// after [`EXEC_FAILED_PREFIX`] and the rc, to the status pipe, and the shim
/// exits with that rc (127 or 126), as a shell would.
fn report_exec_failure(status_fd: RawFd, code: i32, reason: &str) -> ExitCode {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "sbx __landlock: {reason}");
    write_status(
        status_fd,
        format!("{EXEC_FAILED_PREFIX}{code} {reason}").as_bytes(),
    );
    ExitCode::from(code as u8)
}

/// The status-pipe prefix of an exec failure (issue #74): `exec-failed RC
/// REASON` after the marker. [`decode_status`] reads it as
/// [`StatusReport::ExecFailed`].
pub const EXEC_FAILED_PREFIX: &str = "exec-failed ";

/// The first bytes the shim writes to its status pipe (issue #19 round 3, item 2),
/// before anything else. They prove the shim started, so a failure before
/// [`shim`] runs (a clap error, bwrap's own exec of the shim failing, a dynamic
/// loader failing) is told apart from a shim that started and failed.
pub const STATUS_MARKER: &str = "sbx-shim: started\n";

/// What the status pipe says, as `run` reads it (module docs point 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReport {
    /// No marker: the shim never started (or the pipe holds something else).
    NotStarted,
    /// The marker and nothing after it: the shim started and reported no failure.
    Started,
    /// The marker, then the shim's failure reason.
    Failed(String),
    /// The marker, then [`EXEC_FAILED_PREFIX`]: the shim could not exec the
    /// payload (issue #74). `code` is 127 or 126, the shim's own rc.
    ExecFailed { code: i32, reason: String },
}

/// Decodes the status pipe's bytes (module docs point 9). Pure: empty bytes and
/// bytes without the marker are `NotStarted`, so only a shim that wrote its
/// marker can report a clean start or a reason.
pub fn decode_status(bytes: &[u8]) -> StatusReport {
    let text = String::from_utf8_lossy(bytes);
    match text.strip_prefix(STATUS_MARKER) {
        None => StatusReport::NotStarted,
        Some(rest) => {
            let rest = rest.trim();
            if rest.is_empty() {
                StatusReport::Started
            } else if let Some((code, reason)) = rest
                .strip_prefix(EXEC_FAILED_PREFIX)
                .and_then(|r| r.split_once(' '))
                .and_then(|(code, reason)| Some((code.parse::<i32>().ok()?, reason)))
                .filter(|(code, _)| matches!(code, 126 | 127))
            {
                StatusReport::ExecFailed {
                    code,
                    reason: reason.to_owned(),
                }
            } else {
                StatusReport::Failed(rest.to_owned())
            }
        }
    }
}

/// `--status-fd S` from the shim's RAW argv: a minimal scan that needs no clap, so
/// it works even when clap would reject the arguments. Only the shim's own argv
/// counts (`argv[1]` is `__landlock`), and only a flag before the shim's `--`.
/// `None` unless the value is a descriptor above stdio.
pub fn status_fd_in_argv(argv: &[OsString]) -> Option<RawFd> {
    if argv.get(1).and_then(|a| a.to_str()) != Some("__landlock") {
        return None;
    }
    let mut i = 2;
    while let Some(word) = argv.get(i).and_then(|a| a.to_str()) {
        if word == "--" {
            return None;
        }
        if word == "--status-fd" {
            let fd: RawFd = argv.get(i + 1)?.to_str()?.parse().ok()?;
            return (fd > 2).then_some(fd);
        }
        i += 1;
    }
    None
}

/// Writes `bytes` to the status pipe, best effort: nothing is written unless the
/// descriptor is above stdio, and errors (a closed pipe) are ignored.
fn write_status(status_fd: RawFd, bytes: &[u8]) {
    if status_fd > 2 {
        let bytes = &bytes[..bytes.len().min(STATUS_MAX_BYTES)];
        // SAFETY: a write from a live buffer to the status descriptor, which this
        // process keeps open for exactly this purpose; errors are ignored.
        unsafe {
            libc::write(status_fd, bytes.as_ptr().cast(), bytes.len());
        }
    }
}

/// The shim's first act (issue #19 round 3, item 2), run before any argument
/// parsing: writes [`STATUS_MARKER`] to the status pipe when the raw argv names
/// one. A shim that never gets this far leaves the pipe empty, which `run` reads
/// as "the shim did not start".
pub fn announce_start(argv: &[OsString]) {
    if let Some(fd) = status_fd_in_argv(argv) {
        write_status(fd, STATUS_MARKER.as_bytes());
    }
}

/// A clap parse error in the shim's argv (issue #19 round 3, item 2): the message
/// goes to stderr and, after the marker `announce_start` already wrote, to the
/// status pipe. rc 125, never clap's 2.
pub fn parse_failure(argv: &[OsString], message: &str) -> ExitCode {
    report_failure(status_fd_in_argv(argv).unwrap_or(0), message)
}

/// The shim (module docs points 5, 6, 9 and 10). It closes the executable fd and
/// every other descriptor above stdio except the status pipe, applies the
/// ruleset (unless `off`) and checks enforcement against the host ABI, then
/// `execvp`s the payload with SIGPIPE restored, the same as `__init`'s exec. The
/// status write end is close-on-exec from just before the exec, so a successful
/// exec closes it and the payload never holds it. Returns only on failure, with
/// rc 125, the reason on stderr and in the status pipe.
pub fn shim(args: ShimArgs) -> ExitCode {
    if let Err(reason) = check_shim_args(&args) {
        return report_failure(args.status_fd, &reason);
    }
    if let Err(reason) = close_inherited_fds(args.exe_fd, args.status_fd) {
        return report_failure(args.status_fd, &reason);
    }
    if args.mode != Mode::Off {
        match apply(args.mode, &args.bind_tcp, &args.rules) {
            Err(err) => {
                return report_failure(
                    args.status_fd,
                    &format!("cannot apply Landlock rules: {err}"),
                );
            }
            Ok(status) => {
                if let Some(reason) = enforcement_failure(args.host_abi, status) {
                    return report_failure(args.status_fd, &reason);
                }
            }
        }
    }
    // SAFETY: fcntl on the status descriptor the shim holds; a successful exec
    // then closes it (CLOEXEC), and a failed exec still leaves it for the report.
    unsafe {
        libc::fcntl(args.status_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    match exec_command(&args.cmd) {
        Ok(never) => match never {},
        Err(ExecError::Exec { code, reason }) => report_exec_failure(args.status_fd, code, &reason),
        Err(ExecError::Other(reason)) => report_failure(args.status_fd, &reason),
    }
}

/// Closes the shim's executable fd, then every other descriptor above stdio
/// except `status_fd` (collect-then-close, the `__init` hygiene pattern). The
/// shim is single-threaded, so no other thread can reuse a number in between.
/// A `/proc/self/fd` that cannot be listed is an error (module docs point 6): the
/// shim does not continue with descriptors it could not account for.
fn close_inherited_fds(exe_fd: RawFd, status_fd: RawFd) -> Result<(), String> {
    // SAFETY: closing a descriptor this process inherited for the shim; EBADF
    // (already closed) is ignored by design.
    unsafe {
        libc::close(exe_fd);
    }
    let fds = crate::init::scan_fds_above_stdio()
        .ok_or_else(|| "cannot list the open descriptors (/proc/self/fd)".to_owned())?;
    for fd in crate::init::fds_to_close(fds, &[status_fd]) {
        // SAFETY: the number came from this process's own /proc/self/fd scan.
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

/// The file `execvp` would run for `name`: a name with a slash is itself, a bare
/// name is looked up on `PATH` (the shim's environment, which bwrap set to the
/// infra PATH for the payload). `None` when no executable file is found.
fn resolve_program(name: &OsStr) -> Option<PathBuf> {
    if name.as_bytes().contains(&b'/') {
        return Some(PathBuf::from(name));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: access(2) on a NUL-terminated path; the result is only read.
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
        && unsafe { libc::access(c_path.as_ptr(), libc::X_OK) } == 0
}

/// Why [`exec_command`] returned.
#[derive(Debug)]
enum ExecError {
    /// `execvp` itself failed (issue #74): the rc (127 not found, 126 not
    /// executable) and the reason, as `run::exec_status::exec_failure` words them.
    Exec { code: i32, reason: String },
    /// The argv could not be prepared for `execvp`.
    Other(String),
}

/// The `strerror` text of an OS error, without std's ` (os error N)` suffix.
fn errno_text(err: &std::io::Error) -> String {
    let text = err.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_owned(),
        None => text,
    }
}

/// `execvp` the payload argv (PATH search, like `__init`'s exec). Returns only
/// on failure.
///
/// m3: glibc's `execvp` runs a file that has no shebang and is not a binary
/// through `/bin/sh` (ENOEXEC fallback); musl's does not. The fallback is added
/// here so both libcs behave alike: on ENOEXEC the shim execs `/bin/sh <path>
/// <args…>`. The fallback lives in this exec path only.
fn exec_command(cmd: &[OsString]) -> Result<std::convert::Infallible, ExecError> {
    let argv0 = cmd
        .first()
        .ok_or_else(|| ExecError::Other("no payload command given".to_owned()))?;
    let c_argv: Vec<CString> = cmd
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            ExecError::Other(format!(
                "cannot exec {argv0:?}: a payload argument contains an interior NUL byte"
            ))
        })?;
    let ptrs: Vec<*const libc::c_char> = c_argv
        .iter()
        .map(|s| s.as_ptr())
        .chain([std::ptr::null()])
        .collect();
    // SAFETY: SIGPIPE is set to its default disposition. std ignores SIGPIPE at
    // startup, and bwrap does not reset it, so the payload would otherwise
    // inherit the ignore (the `__init` exec_payload rationale).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // SAFETY: a NULL-terminated argv of valid C strings; the buffers outlive
    // the call, which returns only on failure.
    unsafe { libc::execvp(ptrs[0], ptrs.as_ptr()) };
    let mut err = std::io::Error::last_os_error();
    // The first exec decides "not found": a failed `/bin/sh` fallback below is
    // still a command that was found.
    let not_found = err.raw_os_error() == Some(libc::ENOENT);
    if err.raw_os_error() == Some(libc::ENOEXEC) {
        if let Some(program) = resolve_program(argv0) {
            // `/bin/sh <path> <args…>`: the same arguments the payload gets, with
            // the program's path as the script.
            let sh = CString::new("/bin/sh").expect("no NUL in a literal");
            let script = CString::new(program.as_os_str().as_bytes()).map_err(|_| {
                ExecError::Other(format!("cannot exec {argv0:?}: interior NUL byte"))
            })?;
            let mut sh_argv: Vec<*const libc::c_char> = vec![sh.as_ptr(), script.as_ptr()];
            sh_argv.extend(c_argv.iter().skip(1).map(|s| s.as_ptr()));
            sh_argv.push(std::ptr::null());
            // SAFETY: NULL-terminated argv built from the live CStrings above.
            unsafe { libc::execv(sh.as_ptr(), sh_argv.as_ptr()) };
            err = std::io::Error::last_os_error();
        }
    }
    let (code, reason) = crate::run::exec_status::exec_failure(argv0, not_found, &errno_text(&err));
    Err(ExecError::Exec { code, reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse_table() {
        assert_eq!(parse_mode("off"), Ok(Mode::Off));
        assert_eq!(parse_mode("best-effort"), Ok(Mode::BestEffort));
        assert_eq!(parse_mode("require"), Ok(Mode::Require));
        assert_eq!(
            parse_mode("Require"),
            Err("`Require` is not a Landlock mode (off, best-effort, require)".to_owned())
        );
        for mode in [Mode::Off, Mode::BestEffort, Mode::Require] {
            assert_eq!(parse_mode(mode.as_str()), Ok(mode));
        }
    }

    #[test]
    fn rule_encode_parse_round_trip() {
        for rule in [
            PathRule::new("/", Grant::ReadDir),
            PathRule::new("/usr", Grant::Read),
            PathRule::new("/tmp/a:b c", Grant::All),
        ] {
            assert_eq!(PathRule::parse(&rule.encode()), Ok(rule));
        }
        assert_eq!(PathRule::new("/work", Grant::All).encode(), "all:/work");
    }

    #[test]
    fn rule_parse_rejects_bad_text() {
        for bad in [
            "",
            "read",
            "write:/x",
            "read:relative",
            "read:",
            "all:/x\0y",
        ] {
            assert!(PathRule::parse(bad).is_err(), "{bad:?} must be rejected");
        }
        let err = PathRule::parse("write:/x").expect_err("unknown grant");
        assert!(
            err.starts_with("`write:/x` is not a Landlock rule"),
            "{err}"
        );
    }

    #[test]
    fn require_refusal_table() {
        assert_eq!(require_refusal(6), None);
        assert_eq!(require_refusal(9), None);
        assert_eq!(
            require_refusal(5).as_deref(),
            Some(
                "landlock require: the kernel's Landlock ABI is 5; ABI 6 (Linux 6.12 or later) is required for the filesystem, TCP-bind and signal-scope rules"
            )
        );
        assert_eq!(
            require_refusal(0).as_deref(),
            Some(
                "landlock require: Landlock is not available on this kernel (ABI 6, Linux 6.12 or later, is required)"
            )
        );
    }

    #[test]
    fn shim_head_golden() {
        // The shim argv is part of the launch contract: pin it byte-exact.
        let layer = Layer {
            mode: Mode::Require,
            bind_tcp: vec![8080, 0],
            exe_fd: 9,
            status_fd: 8,
            host_abi: 6,
        };
        let rules = [
            PathRule::new("/", Grant::ReadDir),
            PathRule::new("/usr", Grant::Read),
            PathRule::new("/work", Grant::All),
        ];
        let text: Vec<String> = shim_head(&layer, &rules)
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            text.join(" "),
            "/proc/self/fd/9 __landlock --exe-fd 9 --status-fd 8 --mode require --host-abi 6 --bind-tcp 8080 --bind-tcp 0 --rule readdir:/ --rule read:/usr --rule all:/work"
        );
    }

    #[test]
    fn shim_args_checks() {
        let mut args = ShimArgs {
            exe_fd: 9,
            status_fd: 8,
            mode: Mode::BestEffort,
            host_abi: 6,
            bind_tcp: Vec::new(),
            rules: Vec::new(),
            cmd: vec![OsString::from("/bin/true")],
        };
        assert_eq!(check_shim_args(&args), Ok(()));
        args.exe_fd = 2;
        assert_eq!(
            check_shim_args(&args),
            Err("--exe-fd 2 must be greater than 2".to_owned())
        );
        args.exe_fd = 9;
        args.status_fd = 1;
        assert_eq!(
            check_shim_args(&args),
            Err("--status-fd 1 must be greater than 2".to_owned())
        );
        args.status_fd = 9;
        assert_eq!(
            check_shim_args(&args),
            Err("--status-fd 9 must differ from --exe-fd".to_owned())
        );
        args.status_fd = 8;
        args.cmd.clear();
        assert_eq!(
            check_shim_args(&args),
            Err("no payload command given".to_owned())
        );
    }

    /// A fresh scratch directory under the system temp dir (unit-test helper).
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sbx-landlock-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Runs `f` in a forked child and returns its exit code. The ruleset is
    /// applied only in the child (irreversible; module docs point 7).
    fn in_child(f: impl FnOnce() -> i32) -> i32 {
        // SAFETY: fork; the child runs only `f` and then `_exit`s, never
        // returning into the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let rc = f();
            // SAFETY: terminate the child without running atexit handlers.
            unsafe { libc::_exit(rc) };
        }
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid on our own child with a valid status pointer.
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(got, pid, "waitpid");
        assert!(
            libc::WIFEXITED(status),
            "child must exit normally: {status}"
        );
        libc::WEXITSTATUS(status)
    }

    #[test]
    fn filesystem_rules_grant_and_deny_in_child() {
        if kernel_abi() < 1 {
            eprintln!("skipped: the kernel has no Landlock");
            return;
        }
        let dir = scratch("fs");
        let ro = dir.join("ro");
        let rw = dir.join("rw");
        std::fs::create_dir_all(&ro).expect("ro dir");
        std::fs::create_dir_all(&rw).expect("rw dir");
        std::fs::write(ro.join("present"), b"x").expect("seed file");
        let rules = [
            PathRule::new(ro.to_str().expect("utf8"), Grant::Read),
            PathRule::new(rw.to_str().expect("utf8"), Grant::All),
        ];
        let created = prepare(Mode::BestEffort, &[], &rules).expect("prepare");
        let ro_new = CString::new(ro.join("new").as_os_str().as_bytes()).expect("cstring");
        let rw_new = CString::new(rw.join("new").as_os_str().as_bytes()).expect("cstring");
        let ro_file = CString::new(ro.join("present").as_os_str().as_bytes()).expect("cstring");
        let rc = in_child(move || {
            if created.restrict_self().is_err() {
                return 90;
            }
            // SAFETY: plain syscalls on prepared, NUL-terminated paths.
            let mut code = 0;
            if unsafe { libc::open(ro_file.as_ptr(), libc::O_RDONLY) } < 0 {
                code |= 1; // the read grant must allow reading
            }
            if unsafe { libc::mkdir(ro_new.as_ptr(), 0o700) } == 0 {
                code |= 2; // no write grant under ro
            }
            if unsafe { libc::mkdir(rw_new.as_ptr(), 0o700) } != 0 {
                code |= 4; // the all grant must allow creating a directory
            }
            code
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            rc, 0,
            "filesystem grants: bit 1 read, bit 2 ro write, bit 4 rw create"
        );
    }

    #[test]
    fn bind_tcp_needs_a_port_rule_in_child() {
        if kernel_abi() < 4 {
            eprintln!("skipped: TCP bind rules need Landlock ABI 4");
            return;
        }
        // Port 0 is the ephemeral range: a rule for it allows any ephemeral bind.
        let denied = prepare(Mode::BestEffort, &[], &[]).expect("prepare");
        let rc = in_child(move || {
            if denied.restrict_self().is_err() {
                return 90;
            }
            match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(_) => 1,
                Err(_) => 0,
            }
        });
        assert_eq!(rc, 0, "a bind without a port rule must be denied");
        let allowed = prepare(Mode::BestEffort, &[0], &[]).expect("prepare");
        let rc = in_child(move || {
            if allowed.restrict_self().is_err() {
                return 90;
            }
            match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(_) => 0,
                Err(_) => 1,
            }
        });
        assert_eq!(rc, 0, "a bind under a port-0 rule must be allowed");
    }

    #[test]
    fn signal_scope_hides_the_parent_in_child() {
        if kernel_abi() < 6 {
            eprintln!("skipped: signal scope needs Landlock ABI 6");
            return;
        }
        // The child is in its own domain; its parent (this process) is outside it.
        let parent = std::process::id() as libc::pid_t;
        let created = prepare(Mode::BestEffort, &[], &[]).expect("prepare");
        let rc = in_child(move || {
            if created.restrict_self().is_err() {
                return 90;
            }
            // SAFETY: kill with signal 0 only probes permission; no signal is sent.
            let rc = unsafe { libc::kill(parent, 0) };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                0
            } else {
                1
            }
        });
        assert_eq!(rc, 0, "kill(parent, 0) must be EPERM under signal scope");
    }

    #[test]
    fn rule_paths_that_do_not_exist_grant_nothing() {
        // `path_beneath_rules` skips a path it cannot open, so the ruleset holds
        // no grant for it: a `mkdir` under the scratch directory (which the
        // missing path would have granted, had it existed) must be EACCES.
        if kernel_abi() < 1 {
            eprintln!("skipped: the kernel has no Landlock");
            return;
        }
        let dir = scratch("nothing");
        let target = CString::new(dir.join("new").as_os_str().as_bytes()).expect("cstring");
        let rules = [PathRule::new(
            "/sbx-no-such-path-for-landlock-test",
            Grant::All,
        )];
        let created = prepare(Mode::BestEffort, &[], &rules).expect("prepare");
        let rc = in_child(move || {
            if created.restrict_self().is_err() {
                return 90;
            }
            // SAFETY: mkdir on a prepared, NUL-terminated path; no syscall state is touched.
            let made = unsafe { libc::mkdir(target.as_ptr(), 0o700) };
            if made == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
                0
            } else {
                1
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rc, 0, "a rule for a missing path must grant nothing");
    }

    #[test]
    fn decode_status_table() {
        // Round 3 item 2: empty, marker, marker+reason, garbage. Only a marker
        // proves the shim started; the reason is what follows it.
        assert_eq!(decode_status(b""), StatusReport::NotStarted);
        assert_eq!(
            decode_status(STATUS_MARKER.as_bytes()),
            StatusReport::Started
        );
        assert_eq!(
            decode_status(format!("{STATUS_MARKER}cannot exec \"/x\": not found\n").as_bytes()),
            StatusReport::Failed("cannot exec \"/x\": not found".to_owned())
        );
        // A reason with the marker but no trailing newline still decodes.
        assert_eq!(
            decode_status(
                format!(
                    "{STATUS_MARKER}{EXEC_FAILED_PREFIX}127 command not found in the sandbox: rg\n"
                )
                .as_bytes()
            ),
            StatusReport::ExecFailed {
                code: 127,
                reason: "command not found in the sandbox: rg".to_owned()
            }
        );
        // Issue #74: only 126 and 127 are exec failures; anything else is a reason.
        assert_eq!(
            decode_status(format!("{STATUS_MARKER}{EXEC_FAILED_PREFIX}1 x").as_bytes()),
            StatusReport::Failed(format!("{EXEC_FAILED_PREFIX}1 x"))
        );
        assert_eq!(
            decode_status(format!("{STATUS_MARKER}{EXEC_FAILED_PREFIX}127").as_bytes()),
            StatusReport::Failed(format!("{EXEC_FAILED_PREFIX}127"))
        );
        assert_eq!(
            decode_status(format!("{STATUS_MARKER}boom").as_bytes()),
            StatusReport::Failed("boom".to_owned())
        );
        // Garbage, a partial marker, or a reason without the marker: not started.
        assert_eq!(
            decode_status(b"garbage without marker"),
            StatusReport::NotStarted
        );
        assert_eq!(
            decode_status(&STATUS_MARKER.as_bytes()[..5]),
            StatusReport::NotStarted
        );
        assert_eq!(
            decode_status(b"cannot exec: not found"),
            StatusReport::NotStarted
        );
    }

    #[test]
    fn status_fd_in_argv_scans_only_the_shim_head() {
        // Round 3 item 2: the minimal raw-argv scan that runs before clap.
        let words = |w: &[&str]| w.iter().map(OsString::from).collect::<Vec<_>>();
        let shim = words(&[
            "sbx",
            "__landlock",
            "--exe-fd",
            "9",
            "--status-fd",
            "13",
            "--mode",
            "off",
            "--",
            "/bin/true",
        ]);
        assert_eq!(status_fd_in_argv(&shim), Some(13));
        // Not the shim: another subcommand, or no argv[1].
        assert_eq!(
            status_fd_in_argv(&words(&["sbx", "run", "--status-fd", "13"])),
            None
        );
        assert_eq!(status_fd_in_argv(&words(&["sbx"])), None);
        // A `--status-fd` after the shim's own `--` is the payload's, not the shim's.
        let payload = words(&[
            "sbx",
            "__landlock",
            "--exe-fd",
            "9",
            "--",
            "/bin/true",
            "--status-fd",
            "13",
        ]);
        assert_eq!(status_fd_in_argv(&payload), None);
        // Values that are not a descriptor above stdio.
        assert_eq!(
            status_fd_in_argv(&words(&["sbx", "__landlock", "--status-fd", "2"])),
            None
        );
        assert_eq!(
            status_fd_in_argv(&words(&["sbx", "__landlock", "--status-fd", "x"])),
            None
        );
        assert_eq!(
            status_fd_in_argv(&words(&["sbx", "__landlock", "--status-fd"])),
            None
        );
    }

    #[test]
    fn enforcement_failure_table() {
        // m1: "not enforced" with no host Landlock (ABI 0) is the normal no-Landlock
        // case; with Landlock present it must fail closed.
        assert_eq!(enforcement_failure(0, RulesetStatus::NotEnforced), None);
        assert_eq!(enforcement_failure(6, RulesetStatus::FullyEnforced), None);
        assert_eq!(
            enforcement_failure(1, RulesetStatus::PartiallyEnforced),
            None
        );
        assert_eq!(
            enforcement_failure(1, RulesetStatus::NotEnforced).as_deref(),
            Some("Landlock is present (host ABI 1) but the ruleset was not enforced")
        );
    }

    #[test]
    fn resolve_program_finds_bare_names_on_path() {
        // m3: a bare name resolves through PATH; a name with a slash is itself;
        // a missing name resolves to nothing.
        assert_eq!(
            resolve_program(OsStr::new("/bin/sh")),
            Some(PathBuf::from("/bin/sh"))
        );
        let found = resolve_program(OsStr::new("sh")).expect("sh is on PATH");
        assert!(found.ends_with("sh") && found.is_file(), "{found:?}");
        assert_eq!(resolve_program(OsStr::new("sbx-no-such-program-xyz")), None);
    }

    #[test]
    fn exec_falls_back_to_sh_for_a_file_without_a_shebang() {
        // m3: a file with the execute bit and no shebang runs through `/bin/sh`
        // with the same arguments. glibc's execvp does this itself; musl's does
        // not, and the shim's ENOEXEC step makes the two agree. The script's exit
        // status proves that the shell ran it. The child reports 99 if exec fails.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("enoexec");
        let script = dir.join("script");
        std::fs::write(&script, "exit 7\n").expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script");
        let cmd = vec![OsString::from(script.as_os_str())];
        let rc = in_child(move || match exec_command(&cmd) {
            Ok(never) => match never {},
            Err(_) => 99,
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rc, 7, "the script must have run under the shell");
    }

    #[test]
    fn exec_failure_is_127_or_126() {
        // Issue #74: a missing payload is 127, a directory (EACCES) is 126. The
        // child reports 99 if the failure is not an exec failure.
        for (name, want) in [("/sbx-no-such-payload-for-shim-test", 127), ("/", 126)] {
            let cmd = vec![OsString::from(name)];
            let rc = in_child(move || match exec_command(&cmd) {
                Ok(never) => match never {},
                Err(ExecError::Exec { code, .. }) => code,
                Err(ExecError::Other(_)) => 99,
            });
            assert_eq!(rc, want, "{name}");
        }
    }

    #[test]
    fn errno_text_drops_the_os_error_suffix() {
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(errno_text(&err), "Permission denied");
    }
}
