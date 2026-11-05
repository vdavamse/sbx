//! Per-sandbox resource limits (issue #43): the policy's optional `limits`
//! fields, applied by `__init` as `RLIMIT_*` values right before it execs bwrap.
//!
//! 1. **Where.** `__init` sets them AFTER `unshare(CLONE_NEWUSER)`. Since Linux
//!    5.14, `RLIMIT_NPROC` is counted per user namespace (ucounts), and a new
//!    user namespace records its creator's limit as the cap for the parent
//!    level. Set before the unshare, a small `processes` value would be compared
//!    with every process the host uid owns; set after it, only the sandbox's own
//!    processes count. Kernel floor: before 5.14 the count is per real uid,
//!    host-wide; on 5.14–5.16 a process whose kuid is 0 is exempt
//!    (`real_cred->user == INIT_USER`), so a root-run sbx gets no process
//!    limit there. Since 5.17 ("ucounts: Only except the root user in
//!    init_user_ns from RLIMIT_NPROC") only init-namespace root is exempt, and
//!    every process in the sandbox's namespaces is limited, even when sbx
//!    itself runs as root.
//! 2. **soft = hard.** Both limits get the policy value, so the payload cannot
//!    raise its soft limit back. Lowering a hard limit needs no privilege; a
//!    value above the caller's current hard limit fails (`EPERM`) and the
//!    setup fails closed instead of running with a weaker limit.
//! 3. **Headroom.** bwrap runs under these limits too: very small values
//!    (`processes` below 3, a few `open_files`, a few MiB of address space)
//!    make bwrap itself fail. That still fails closed, but the error comes
//!    from bwrap, not from this module.
//! 4. **Wire form.** `run` passes `--rlimit NAME=VALUE` (hidden); NAME is one of
//!    [`Resource::name`].

use std::fmt;

use crate::policy::Limits;

/// One of the resources a policy may limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// `limits.processes` → `RLIMIT_NPROC`.
    Nproc,
    /// `limits.open_files` → `RLIMIT_NOFILE`.
    Nofile,
    /// `limits.file_bytes` → `RLIMIT_FSIZE`.
    Fsize,
    /// `limits.address_space_bytes` → `RLIMIT_AS`.
    As,
}

impl Resource {
    /// Every resource, in the fixed `--rlimit` emission order.
    pub const ALL: [Resource; 4] = [
        Resource::Nproc,
        Resource::Nofile,
        Resource::Fsize,
        Resource::As,
    ];

    /// The `--rlimit` wire name.
    pub fn name(self) -> &'static str {
        match self {
            Resource::Nproc => "nproc",
            Resource::Nofile => "nofile",
            Resource::Fsize => "fsize",
            Resource::As => "as",
        }
    }

    /// The policy field the value comes from (for error messages).
    pub fn policy_field(self) -> &'static str {
        match self {
            Resource::Nproc => "limits.processes",
            Resource::Nofile => "limits.open_files",
            Resource::Fsize => "limits.file_bytes",
            Resource::As => "limits.address_space_bytes",
        }
    }

    /// `setrlimit(2)` for this resource. One call per arm: the resource
    /// constant's type differs between glibc and musl.
    fn set(self, rl: &libc::rlimit) -> libc::c_int {
        // SAFETY: setrlimit reads one valid, initialised struct.
        unsafe {
            match self {
                Resource::Nproc => libc::setrlimit(libc::RLIMIT_NPROC, rl),
                Resource::Nofile => libc::setrlimit(libc::RLIMIT_NOFILE, rl),
                Resource::Fsize => libc::setrlimit(libc::RLIMIT_FSIZE, rl),
                Resource::As => libc::setrlimit(libc::RLIMIT_AS, rl),
            }
        }
    }

    fn value_in(self, limits: &Limits) -> Option<u64> {
        match self {
            Resource::Nproc => limits.processes,
            Resource::Nofile => limits.open_files,
            Resource::Fsize => limits.file_bytes,
            Resource::As => limits.address_space_bytes,
        }
        .map(|v| v.get())
    }
}

/// One limit to apply: soft = hard = `value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    /// Which resource.
    pub resource: Resource,
    /// The limit (never 0: the policy type is `NonZeroU64`).
    pub value: u64,
}

impl fmt::Display for Rlimit {
    /// The `--rlimit` wire form, `NAME=VALUE`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.resource.name(), self.value)
    }
}

/// The limits a policy asks for, in [`Resource::ALL`] order.
pub fn from_limits(limits: &Limits) -> Vec<Rlimit> {
    Resource::ALL
        .into_iter()
        .filter_map(|resource| {
            resource
                .value_in(limits)
                .map(|value| Rlimit { resource, value })
        })
        .collect()
}

/// Parses one `--rlimit NAME=VALUE` (clap value parser).
pub fn parse(s: &str) -> Result<Rlimit, String> {
    let (name, value) = s
        .split_once('=')
        .ok_or_else(|| format!("`{s}` is not NAME=VALUE"))?;
    let resource = Resource::ALL
        .into_iter()
        .find(|r| r.name() == name)
        .ok_or_else(|| format!("`{name}` is not a resource (nproc, nofile, fsize, as)"))?;
    let value: u64 = value
        .parse()
        .map_err(|_| format!("`{value}` is not a positive integer"))?;
    if value == 0 {
        return Err(format!("`{name}` must be greater than zero"));
    }
    if to_rlim(value).is_none() {
        return Err(format!("`{value}` is too large (it would mean no limit)"));
    }
    Ok(Rlimit { resource, value })
}

/// `value` as a finite `rlim_t`: `None` when it does not fit, or equals
/// `RLIM_INFINITY` (which would mean "no limit" — fail closed instead).
fn to_rlim(value: u64) -> Option<libc::rlim_t> {
    libc::rlim_t::try_from(value)
        .ok()
        .filter(|v| *v != libc::RLIM_INFINITY)
}

/// Applies every limit (soft = hard). The first failure is returned as a
/// complete, user-facing reason; limits applied before it stay applied, which
/// is harmless because the caller fails setup and never execs the payload.
pub fn apply(limits: &[Rlimit]) -> Result<(), String> {
    for limit in limits {
        let Some(value) = to_rlim(limit.value) else {
            return Err(format!(
                "cannot set {} to {}: the value is too large (it would mean no limit)",
                limit.resource.policy_field(),
                limit.value
            ));
        };
        let rl = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if limit.resource.set(&rl) != 0 {
            let err = std::io::Error::last_os_error();
            let why = match (err.raw_os_error(), limit.resource) {
                // NOFILE has a second, system-wide ceiling that binds even root.
                (Some(libc::EPERM), Resource::Nofile) => {
                    "it exceeds the caller's hard limit or fs.nr_open".to_owned()
                }
                (Some(libc::EPERM), _) => "it exceeds the caller's hard limit".to_owned(),
                _ => err.to_string(),
            };
            return Err(format!(
                "cannot set {} to {}: {why}",
                limit.resource.policy_field(),
                limit.value
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::time::Duration;

    fn limits() -> Limits {
        Limits {
            timeout: Duration::from_secs(1),
            output_bytes: 0,
            processes: None,
            open_files: None,
            file_bytes: None,
            address_space_bytes: None,
        }
    }

    #[test]
    fn from_limits_is_empty_when_nothing_is_set() {
        assert!(from_limits(&limits()).is_empty());
    }

    #[test]
    fn from_limits_keeps_the_fixed_order() {
        let l = Limits {
            address_space_bytes: NonZeroU64::new(1 << 30),
            processes: NonZeroU64::new(64),
            file_bytes: NonZeroU64::new(1 << 20),
            open_files: NonZeroU64::new(256),
            ..limits()
        };
        let wire: Vec<String> = from_limits(&l).iter().map(ToString::to_string).collect();
        assert_eq!(
            wire,
            ["nproc=64", "nofile=256", "fsize=1048576", "as=1073741824"]
        );
    }

    #[test]
    fn parse_round_trips_the_wire_form() {
        for r in Resource::ALL {
            let limit = Rlimit {
                resource: r,
                value: 7,
            };
            assert_eq!(parse(&limit.to_string()), Ok(limit));
        }
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse("nproc").is_err());
        assert!(parse("cpu=1").is_err());
        assert!(parse("nproc=0").is_err());
        assert!(parse("nproc=-1").is_err());
        assert!(parse("nproc=x").is_err());
        assert!(parse("=5").is_err());
        // u64::MAX is RLIM_INFINITY on 64-bit: "no limit" must never sneak in.
        assert!(parse(&format!("as={}", u64::MAX)).is_err());
    }

    #[test]
    fn apply_lowers_soft_and_hard_in_a_child() {
        // A forked child, so the test process keeps its own limits. The parent
        // is the multithreaded harness, so the child must not allocate: it
        // calls the allocation-free `Resource::set` (the syscall `apply` makes)
        // instead of `apply`, whose error path formats a String.
        let rl = libc::rlimit {
            rlim_cur: 4096,
            rlim_max: 4096,
        };
        // SAFETY: the child only calls async-signal-safe functions
        // (setrlimit, getrlimit, _exit).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let ok = Resource::Fsize.set(&rl) == 0;
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes one struct we own.
            let got = unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut rl) } == 0;
            let code = i32::from(!(ok && got && rl.rlim_cur == 4096 && rl.rlim_max == 4096));
            // SAFETY: _exit never returns; no destructors run in the child.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waits for the child we just forked.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    /// CAP_SYS_RESOURCE (bit 24) in this process's effective set.
    fn has_cap_sys_resource() -> bool {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            // Unknown: assume capable, so the test skips instead of risking it.
            .is_none_or(|caps| caps & (1 << 24) != 0)
    }

    #[test]
    fn apply_above_the_hard_limit_fails_closed() {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one struct we own.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) }, 0);
        if rl.rlim_max == libc::RLIM_INFINITY || has_cap_sys_resource() {
            // Nothing above the hard limit to ask for, or this process may
            // raise it (the call would succeed and change the harness).
            return;
        }
        // Raising past the hard limit fails without changing anything, so the
        // test process is safe to call it directly.
        let err = apply(&[Rlimit {
            resource: Resource::Nofile,
            value: rl.rlim_max + 1,
        }])
        .unwrap_err();
        assert!(err.starts_with("cannot set limits.open_files to "), "{err}");
        assert!(
            err.ends_with("it exceeds the caller's hard limit or fs.nr_open"),
            "{err}"
        );
    }

    #[test]
    fn apply_refuses_infinity_instead_of_lifting_the_limit() {
        // Fails before any setrlimit call, so the test process is unaffected.
        let err = apply(&[Rlimit {
            resource: Resource::As,
            value: u64::MAX,
        }])
        .unwrap_err();
        assert!(err.contains("too large"), "{err}");
    }
}
