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
//!    <reason>` on stderr, and the payload never runs.
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
//!    other descriptor above stdio, before it applies the ruleset, so the
//!    payload has exactly fds 0, 1 and 2.
//! 7. **Irreversibility (test rule).** `restrict_self` is irreversible for the
//!    calling thread. Unit tests that apply a ruleset do it in a forked child
//!    and build the ruleset in the parent first (see [`prepare`]).
//! 8. **Dynamic binaries (D9).** The static musl release needs nothing from the
//!    sandbox to run the shim. A dynamically linked `sbx` build needs its shared
//!    libraries visible inside the sandbox when `--landlock` is on. This is
//!    documented, not pre-checked.

use std::ffi::{CString, OsString};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use ::landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope, path_beneath_rules,
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

/// The layer as `build` receives it: the mode, the TCP bind ports and the
/// descriptor of sbx's own executable that the shim is exec'd through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub mode: Mode,
    /// `--landlock-bind-tcp` ports, in command-line order (0 = ephemeral range).
    pub bind_tcp: Vec<u16>,
    /// The sbx executable's fd (`--exe-fd`, module docs point 6).
    pub exe_fd: RawFd,
}

/// The shim argv elements from the `/proc/self/fd/N` program up to, but not
/// including, the `--` that separates the shim's flags from the payload:
/// `/proc/self/fd/N __landlock --exe-fd N --mode M [--bind-tcp P]… [--rule R]…`.
/// The rules come from [`PathRule`]s the caller derived from the mount list.
pub fn shim_head(layer: &Layer, rules: &[PathRule]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        OsString::from(format!("/proc/self/fd/{}", layer.exe_fd)),
        OsString::from("__landlock"),
        OsString::from("--exe-fd"),
        OsString::from(layer.exe_fd.to_string()),
        OsString::from("--mode"),
        OsString::from(layer.mode.as_str()),
    ];
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

/// Apply the ruleset to the calling thread (irreversible; module docs point 7).
pub fn apply(mode: Mode, bind_tcp: &[u16], rules: &[PathRule]) -> Result<(), RulesetError> {
    prepare(mode, bind_tcp, rules)?.restrict_self()?;
    Ok(())
}

/// The shim's parsed argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimArgs {
    pub exe_fd: RawFd,
    pub mode: Mode,
    pub bind_tcp: Vec<u16>,
    pub rules: Vec<PathRule>,
    pub cmd: Vec<OsString>,
}

/// The shim's own checks, before any descriptor is touched. An `--exe-fd` at or
/// below 2 would make the shim close stdio, so it is refused.
pub fn check_shim_args(args: &ShimArgs) -> Result<(), String> {
    if args.exe_fd <= 2 {
        return Err(format!("--exe-fd {} must be greater than 2", args.exe_fd));
    }
    if args.cmd.is_empty() {
        return Err("no payload command given".to_owned());
    }
    Ok(())
}

/// The shim (module docs points 5 and 6). It closes the executable fd and
/// every other descriptor above stdio, applies the ruleset (unless `off`), then
/// `execvp`s the payload with SIGPIPE restored, the same as `__init`'s exec.
/// Returns only on failure, with rc 125 and `sbx __landlock: <reason>`.
pub fn shim(args: ShimArgs) -> ExitCode {
    // Best effort, like `run`'s diagnostics: a closed stderr must not panic (rc 101)
    // and must not change the rc.
    let fail = |reason: String| {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "sbx __landlock: {reason}");
        ExitCode::from(crate::run::EXIT_FAILURE as u8)
    };
    if let Err(reason) = check_shim_args(&args) {
        return fail(reason);
    }
    close_inherited_fds(args.exe_fd);
    if args.mode != Mode::Off {
        if let Err(err) = apply(args.mode, &args.bind_tcp, &args.rules) {
            return fail(format!("cannot apply Landlock rules: {err}"));
        }
    }
    match exec_command(&args.cmd) {
        Ok(never) => match never {},
        Err(reason) => fail(reason),
    }
}

/// Closes the shim's executable fd, then every other descriptor above stdio
/// (collect-then-close, the `__init` hygiene pattern). The shim is
/// single-threaded, so no other thread can reuse a number in between.
fn close_inherited_fds(exe_fd: RawFd) {
    // SAFETY: closing a descriptor this process inherited for the shim; EBADF
    // (already closed) is ignored by design.
    unsafe {
        libc::close(exe_fd);
    }
    let Some(fds) = crate::init::scan_fds_above_stdio() else {
        return;
    };
    for fd in crate::init::fds_to_close(fds, &[]) {
        // SAFETY: the number came from this process's own /proc/self/fd scan.
        unsafe {
            libc::close(fd);
        }
    }
}

/// `execvp` the payload argv (PATH search, like `__init`'s exec). Returns only
/// on failure, as the reason text.
fn exec_command(cmd: &[OsString]) -> Result<std::convert::Infallible, String> {
    let argv0 = cmd
        .first()
        .ok_or_else(|| "no payload command given".to_owned())?;
    let c_argv: Vec<CString> = cmd
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            format!("cannot exec {argv0:?}: a payload argument contains an interior NUL byte")
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
    let err = std::io::Error::last_os_error();
    Err(match err.raw_os_error() {
        Some(libc::ENOENT) => format!("cannot exec {argv0:?}: not found"),
        Some(libc::EACCES) => format!("cannot exec {argv0:?}: permission denied"),
        _ => format!("cannot exec {argv0:?}: {err}"),
    })
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
            "/proc/self/fd/9 __landlock --exe-fd 9 --mode require --bind-tcp 8080 --bind-tcp 0 --rule readdir:/ --rule read:/usr --rule all:/work"
        );
    }

    #[test]
    fn shim_args_checks() {
        let mut args = ShimArgs {
            exe_fd: 9,
            mode: Mode::BestEffort,
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
    fn best_effort_rule_paths_that_do_not_exist_grant_nothing() {
        // path_beneath_rules skips a path it cannot open; the grant is absent,
        // which is the fail-closed direction. Preparing must still succeed.
        let rules = [PathRule::new(
            "/sbx-no-such-path-for-landlock-test",
            Grant::All,
        )];
        assert!(prepare(Mode::BestEffort, &[], &rules).is_ok());
    }
}
