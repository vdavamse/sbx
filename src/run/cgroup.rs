//! cgroup v2 limits for the whole sandbox (issue #43): `limits.memory_bytes`
//! → `memory.max`, `limits.pids` → `pids.max`, on a child cgroup that holds
//! `__init`, bwrap and every payload process.
//!
//! 1. **Only with a delegated cgroup.** sbx never asks for privileges: it
//!    uses the cgroup it already runs in (`/proc/self/cgroup`, the `0::`
//!    line) when that cgroup is writable and offers the controllers, e.g.
//!    under `systemd-run --user --scope -p Delegate=yes`, or a container
//!    with a private, writable cgroup namespace.
//! 2. **No internal processes.** cgroup v2 refuses to enable a controller
//!    for the children of a cgroup that holds processes (the namespace root
//!    excepted). When the needed controllers are not yet enabled, sbx enables
//!    them only if it is the ONLY process in its cgroup: it first moves
//!    itself into a leaf child `sbx-supervisor`, then writes
//!    `+memory`/`+pids` to `cgroup.subtree_control`. Another process in the
//!    cgroup (a shell, a sibling) makes the limit unavailable.
//! 3. **Fail closed.** With a limit set and no usable cgroup, `sbx run`
//!    refuses with 125 and the reason; the limit is never silently dropped.
//!    Without a limit nothing here runs.
//! 4. **Attach before go.** `sbx run` writes `__init`'s pid to the child's
//!    `cgroup.procs` after the spawn and before the go byte; `__init` forks
//!    nothing before go, so bwrap and the payload start inside the child.
//! 5. **Cleanup.** The child (`sbx-sandbox-<pid>`) is removed after the run
//!    (best effort: it must be empty). The supervisor leaf stays until sbx
//!    exits, and goes with the delegated cgroup (a systemd scope is removed
//!    when its last process exits).

use std::fs;
use std::io;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

/// The cgroup v2 mount point.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The leaf sbx moves itself into before enabling controllers (point 2).
pub const SUPERVISOR_LEAF: &str = "sbx-supervisor";

/// The limits that need a cgroup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupLimits {
    pub memory_bytes: Option<NonZeroU64>,
    pub pids: Option<NonZeroU64>,
}

impl CgroupLimits {
    /// The policy's cgroup limits.
    pub fn of(limits: &crate::policy::Limits) -> Self {
        Self {
            memory_bytes: limits.memory_bytes,
            pids: limits.pids,
        }
    }

    /// Whether any cgroup limit is set.
    pub fn any(&self) -> bool {
        self.memory_bytes.is_some() || self.pids.is_some()
    }

    /// The controllers the limits need, in `cgroup.subtree_control` order.
    fn controllers(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.memory_bytes.is_some() {
            out.push("memory");
        }
        if self.pids.is_some() {
            out.push("pids");
        }
        out
    }
}

/// Why the limits cannot be applied. Display is the reason only; `sbx run`
/// prefixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupError(pub String);

impl std::fmt::Display for CgroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The fix appended to every refusal.
const FIX: &str = "run sbx in its own delegated cgroup v2 (for example `systemd-run --user --scope -p Delegate=yes sbx run …`), or remove limits.memory_bytes and limits.pids";

fn refuse(why: impl std::fmt::Display) -> CgroupError {
    CgroupError(format!(
        "limits.memory_bytes/limits.pids need a delegated cgroup v2: {why}; {FIX}"
    ))
}

/// Pure: the cgroup v2 path from a `/proc/self/cgroup` text (the `0::` line).
pub fn v2_path(proc_self_cgroup: &str) -> Option<&str> {
    proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|p| p.starts_with('/'))
}

/// The child cgroup holding the sandbox.
#[derive(Debug)]
pub struct SandboxCgroup {
    dir: PathBuf,
    /// Where sbx itself lives after [`setup`] (its cgroup, or the supervisor
    /// leaf it moved into): [`SandboxCgroup::spawn_inside`] returns here.
    home: PathBuf,
}

impl SandboxCgroup {
    /// The child's directory.
    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Spawn with sbx itself inside the child, so the new process starts
    /// there (no window in which it could fork outside), then move sbx back
    /// home. For `--keep-alive` calls, whose `__init` execs bwrap at once
    /// (there is no go byte to attach before). Returns the spawn result and
    /// the move-back result; on a move-back error the caller must kill the
    /// child. Memory already charged stays where it was (cgroup v2 does not
    /// move charges), and `pids.max` applies to the fork, so sbx's own
    /// threads count against it for that instant.
    pub fn spawn_inside<T>(
        &self,
        spawn: impl FnOnce() -> io::Result<T>,
    ) -> Result<(io::Result<T>, Result<(), CgroupError>), CgroupError> {
        let me = std::process::id().to_string();
        fs::write(self.dir.join("cgroup.procs"), &me)
            .map_err(|e| refuse(format!("cannot enter {}: {e}", self.dir.display())))?;
        let out = spawn();
        let back = fs::write(self.home.join("cgroup.procs"), &me)
            .map_err(|e| refuse(format!("cannot return to {}: {e}", self.home.display())));
        Ok((out, back))
    }

    /// Move `pid` (and its threads) into the child.
    pub fn attach(&self, pid: u32) -> Result<(), CgroupError> {
        fs::write(self.dir.join("cgroup.procs"), pid.to_string()).map_err(|e| {
            refuse(format!(
                "cannot move sbx __init into {}: {e}",
                self.dir.display()
            ))
        })
    }

    /// Remove the child (best effort, it must be empty: retried briefly while
    /// the kernel finishes reaping).
    pub fn remove(self) {
        for _ in 0..50 {
            match fs::remove_dir(&self.dir) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }
}

/// Create the sandbox's child cgroup with the limits, under `root` (the
/// cgroup2 mount) and this process's cgroup (`proc_self_cgroup`). `self_pid`
/// is sbx's pid. See the module docs for the rules.
pub fn setup(
    root: &Path,
    proc_self_cgroup: &str,
    self_pid: u32,
    limits: CgroupLimits,
) -> Result<SandboxCgroup, CgroupError> {
    let rel = v2_path(proc_self_cgroup).ok_or_else(|| {
        refuse("this host has no cgroup v2 hierarchy (no `0::` line in /proc/self/cgroup)")
    })?;
    let group = root.join(rel.trim_start_matches('/'));
    let read = |name: &str| {
        fs::read_to_string(group.join(name))
            .map_err(|e| refuse(format!("cannot read {}: {e}", group.join(name).display())))
    };
    let wanted = limits.controllers();
    let available = read("cgroup.controllers")?;
    let available: Vec<&str> = available.split_whitespace().collect();
    if let Some(missing) = wanted.iter().find(|c| !available.contains(c)) {
        return Err(refuse(format!(
            "the {missing} controller is not delegated to {}",
            group.display()
        )));
    }
    let mut home = group.clone();
    let enabled = read("cgroup.subtree_control")?;
    let enabled: Vec<&str> = enabled.split_whitespace().collect();
    let to_enable: Vec<&str> = wanted
        .iter()
        .copied()
        .filter(|c| !enabled.contains(c))
        .collect();
    if !to_enable.is_empty() {
        // Point 2: only when sbx is alone in its cgroup.
        let procs = read("cgroup.procs")?;
        let pids: Vec<&str> = procs.split_whitespace().collect();
        if pids != [self_pid.to_string().as_str()] {
            return Err(refuse(format!(
                "{} holds other processes ({}), so controllers cannot be enabled for its children",
                group.display(),
                pids.len().saturating_sub(1)
            )));
        }
        let leaf = group.join(SUPERVISOR_LEAF);
        match fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(refuse(format!("cannot create {}: {e}", leaf.display())));
            }
        }
        fs::write(leaf.join("cgroup.procs"), self_pid.to_string())
            .map_err(|e| refuse(format!("cannot move sbx into {}: {e}", leaf.display())))?;
        home = leaf;
        let line = to_enable
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        fs::write(group.join("cgroup.subtree_control"), &line).map_err(|e| {
            refuse(format!(
                "cannot enable {line} in {}: {e}",
                group.join("cgroup.subtree_control").display()
            ))
        })?;
    }
    let dir = group.join(format!("sbx-sandbox-{self_pid}"));
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(refuse(format!("cannot create {}: {e}", dir.display()))),
    }
    let cg = SandboxCgroup { dir, home };
    let set = |file: &str, value: NonZeroU64| {
        fs::write(cg.dir.join(file), value.get().to_string())
            .map_err(|e| refuse(format!("cannot set {}: {e}", cg.dir.join(file).display())))
    };
    let applied = (|| {
        if let Some(v) = limits.memory_bytes {
            set("memory.max", v)?;
            // memory_bytes bounds memory, not memory plus swap: without this
            // a payload over memory.max is swapped out instead of OOM-killed.
            // The file exists only with swap accounting (no swap: nothing to
            // bound); when it exists, failing to set it refuses the run.
            let swap = cg.dir.join("memory.swap.max");
            if swap.exists() {
                fs::write(&swap, "0")
                    .map_err(|e| refuse(format!("cannot set {}: {e}", swap.display())))?;
            }
        }
        if let Some(v) = limits.pids {
            set("pids.max", v)?;
        }
        Ok(())
    })();
    if let Err(e) = applied {
        let _ = fs::remove_dir(&cg.dir);
        return Err(e);
    }
    Ok(cg)
}

/// [`setup`] against the live system.
pub fn setup_live(limits: CgroupLimits) -> Result<SandboxCgroup, CgroupError> {
    let text = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| refuse(format!("cannot read /proc/self/cgroup: {e}")))?;
    setup(Path::new(CGROUP_ROOT), &text, std::process::id(), limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake cgroupfs: plain files, so these tests pin sbx's decisions
    /// and writes, not kernel semantics (the CI smoke covers those).
    fn fake(name: &str, controllers: &str, subtree: &str, procs: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sbx-cg-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let g = root.join("user.slice/run.scope");
        fs::create_dir_all(&g).unwrap();
        fs::write(g.join("cgroup.controllers"), controllers).unwrap();
        fs::write(g.join("cgroup.subtree_control"), subtree).unwrap();
        fs::write(g.join("cgroup.procs"), procs).unwrap();
        root
    }

    const SELF_CG: &str = "0::/user.slice/run.scope\n";

    fn both() -> CgroupLimits {
        CgroupLimits {
            memory_bytes: NonZeroU64::new(64 << 20),
            pids: NonZeroU64::new(128),
        }
    }

    #[test]
    fn v2_path_parsing() {
        assert_eq!(v2_path("0::/a/b\n"), Some("/a/b"));
        assert_eq!(v2_path("12:pids:/x\n0::/\n"), Some("/"));
        assert_eq!(v2_path("12:pids:/x\n1:name=systemd:/y\n"), None);
        assert_eq!(v2_path(""), None);
    }

    #[test]
    fn alone_in_cgroup_enables_controllers_and_sets_limits() {
        let root = fake("alone", "cpu memory pids io", "", "4242\n");
        let cg = setup(&root, SELF_CG, 4242, both()).expect("setup");
        let g = root.join("user.slice/run.scope");
        assert_eq!(
            fs::read_to_string(g.join("cgroup.subtree_control")).unwrap(),
            "+memory +pids"
        );
        assert_eq!(
            fs::read_to_string(g.join(SUPERVISOR_LEAF).join("cgroup.procs")).unwrap(),
            "4242"
        );
        assert_eq!(cg.dir(), g.join("sbx-sandbox-4242"));
        assert_eq!(
            fs::read_to_string(cg.dir().join("memory.max")).unwrap(),
            "67108864"
        );
        assert_eq!(
            fs::read_to_string(cg.dir().join("pids.max")).unwrap(),
            "128"
        );
        cg.attach(4243).unwrap();
        assert_eq!(
            fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap(),
            "4243"
        );
        // spawn_inside: sbx enters the child for the spawn, then returns home
        // (the supervisor leaf).
        let me = std::process::id().to_string();
        let (out, back) = cg
            .spawn_inside(|| {
                assert_eq!(
                    fs::read_to_string(cg.dir().join("cgroup.procs")).unwrap(),
                    me
                );
                Ok(7)
            })
            .unwrap();
        assert_eq!((out.unwrap(), back), (7, Ok(())));
        assert_eq!(
            fs::read_to_string(g.join(SUPERVISOR_LEAF).join("cgroup.procs")).unwrap(),
            me
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// With swap accounting (memory.swap.max present), memory_bytes also
    /// pins swap to 0; without it nothing is written.
    #[test]
    fn swap_is_pinned_to_zero_when_accounted() {
        let root = fake("swap", "memory pids", "memory pids", "1\n");
        let g = root.join("user.slice/run.scope");
        let dir = g.join("sbx-sandbox-9");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("memory.swap.max"), "max").unwrap();
        let cg = setup(&root, SELF_CG, 9, both()).expect("setup");
        assert_eq!(
            fs::read_to_string(cg.dir().join("memory.swap.max")).unwrap(),
            "0"
        );
        let _ = fs::remove_dir_all(&root);
        let root = fake("noswap", "memory pids", "memory pids", "1\n");
        let cg = setup(&root, SELF_CG, 9, both()).expect("setup");
        assert!(!cg.dir().join("memory.swap.max").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn already_enabled_controllers_need_no_move() {
        let root = fake("enabled", "memory pids", "memory pids", "1 2 3\n");
        let cg = setup(&root, SELF_CG, 4242, both()).expect("setup");
        let g = root.join("user.slice/run.scope");
        assert!(!g.join(SUPERVISOR_LEAF).exists(), "no self-move needed");
        assert_eq!(
            fs::read_to_string(g.join("cgroup.subtree_control")).unwrap(),
            "memory pids"
        );
        assert!(cg.dir().join("memory.max").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn only_the_needed_controller_is_required() {
        let root = fake("pidsonly", "pids", "", "7\n");
        let limits = CgroupLimits {
            memory_bytes: None,
            pids: NonZeroU64::new(10),
        };
        let cg = setup(&root, SELF_CG, 7, limits).expect("setup");
        assert!(!cg.dir().join("memory.max").exists());
        assert_eq!(fs::read_to_string(cg.dir().join("pids.max")).unwrap(), "10");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn refusals_name_the_cause() {
        let cases = [
            (
                "nomem",
                "pids",
                "",
                "7\n",
                "the memory controller is not delegated",
            ),
            (
                "shared",
                "memory pids",
                "",
                "7 8\n",
                "holds other processes (1)",
            ),
        ];
        for (name, ctl, sub, procs, want) in cases {
            let root = fake(name, ctl, sub, procs);
            let err = setup(&root, SELF_CG, 7, both()).expect_err(name);
            assert!(err.0.contains(want), "{name}: {err}");
            assert!(
                err.0
                    .starts_with("limits.memory_bytes/limits.pids need a delegated cgroup v2: ")
            );
            assert!(err.0.ends_with(FIX), "{name}: {err}");
            let _ = fs::remove_dir_all(&root);
        }
        let root = fake("v1", "memory pids", "", "7\n");
        let err = setup(&root, "1:name=systemd:/x\n", 7, both()).expect_err("v1");
        assert!(err.0.contains("no cgroup v2 hierarchy"), "{err}");
        let err = setup(&root, "0::/missing/group\n", 7, both()).expect_err("missing");
        assert!(err.0.contains("cannot read"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn limits_of_policy_and_any() {
        assert!(!CgroupLimits::default().any());
        assert!(both().any());
        assert_eq!(both().controllers(), ["memory", "pids"]);
    }
}
