//! Joining a persistent session's namespaces (issue #18, design point 4).
//!
//! 1. **Which namespaces.** A session is one user namespace (the one `__init`
//!    created, owned by the caller's uid) and one network namespace inside it
//!    (the nftables rules and the listeners live there). An attached call joins
//!    exactly those two; bwrap then creates the call's own mount and pid
//!    namespaces as in a normal run.
//! 2. **Captured while parked.** The holder opens `/proc/<init>/ns/user` and
//!    `/ns/net` (see [`capture_namespaces`]) after `__init` reports ready and
//!    before the go byte. At that point `__init` is parked in its own namespaces
//!    and cannot exec bwrap, so the descriptors name the session's namespaces
//!    and not a bwrap child's nested ones.
//! 3. **Order.** The user namespace is joined first: `setns(CLONE_NEWUSER)`
//!    gives the caller capabilities inside it, and only then can
//!    `setns(CLONE_NEWNET)` into the network namespace that user namespace owns.
//!    The kernel refuses the user step in a multithreaded process, so
//!    [`join_namespaces`] is only called from a freshly forked child before exec.
//! 4. **Who may join.** The kernel allows a process in the parent user namespace
//!    whose effective uid owns the target user namespace. An attach is the same
//!    uid as the holder, so the join is unprivileged. The test below shows it
//!    works here; nothing in sbx relies on a privilege.

use std::fs::File;
use std::io;
use std::os::fd::{OwnedFd, RawFd};

/// Joins the user namespace `user`, then the network namespace `net` (rule 3).
/// Call it only in a single-threaded child, between `fork` and `exec`.
pub(crate) fn join_namespaces(user: RawFd, net: RawFd) -> io::Result<()> {
    if unsafe { libc::setns(user, libc::CLONE_NEWUSER) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setns(net, libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Opens the user and network namespace descriptors of process `pid` (rule 2).
pub(crate) fn capture_namespaces(pid: libc::pid_t) -> io::Result<(OwnedFd, OwnedFd)> {
    let open = |kind: &str| -> io::Result<OwnedFd> {
        let file = File::open(format!("/proc/{pid}/ns/{kind}"))?;
        Ok(OwnedFd::from(file))
    };
    Ok((open("user")?, open("net")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// `unshare -Urn true` succeeds here, so the namespace test can run.
    fn unprivileged_userns_available() -> bool {
        Command::new("unshare")
            .args(["-Urn", "true"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn ns_link(pid: &str, kind: &str) -> String {
        std::fs::read_link(format!("/proc/{pid}/ns/{kind}"))
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    #[test]
    fn join_validates_its_descriptors() {
        // A closed descriptor is refused, not silently ignored.
        let err = join_namespaces(-1, -1).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    /// The open question of issue #18: an unprivileged same-uid process can join
    /// a user and network namespace that another process of its uid created.
    #[test]
    fn unprivileged_join_enters_the_holders_namespaces() {
        if !unprivileged_userns_available() {
            eprintln!("SKIP: unprivileged user namespaces are unavailable on this host");
            return;
        }
        let mut holder = Command::new("unshare")
            .args(["-Urn", "sleep", "30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holder");
        let pid = holder.id() as libc::pid_t;
        let pid_s = pid.to_string();

        // Wait until the holder has unshared (its namespaces differ from ours).
        let mine_net = ns_link("self", "net");
        let deadline = Instant::now() + Duration::from_secs(5);
        while ns_link(&pid_s, "net") == mine_net && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let (user_fd, net_fd) = capture_namespaces(pid).expect("capture the holder's namespaces");
        let (user_raw, net_raw) = (user_fd.as_raw_fd(), net_fd.as_raw_fd());

        let mut cmd = Command::new("/bin/sh");
        cmd.args([
            "-c",
            "readlink /proc/self/ns/user; readlink /proc/self/ns/net",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null());
        // SAFETY: the closure only calls setns, which is async-signal-safe, on
        // descriptors this process still holds across fork.
        unsafe {
            cmd.pre_exec(move || join_namespaces(user_raw, net_raw));
        }
        let want_user = ns_link(&pid_s, "user");
        let want_net = ns_link(&pid_s, "net");
        let out = cmd.output().expect("run the joined shell");
        let _ = holder.kill();
        let _ = holder.wait();

        assert!(out.status.success(), "join or exec failed: {out:?}");
        assert!(
            !want_user.is_empty() && !want_net.is_empty(),
            "holder links were readable"
        );
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some(want_user.as_str()),
            "the joined user namespace is the holder's"
        );
        assert_eq!(
            lines.next(),
            Some(want_net.as_str()),
            "the joined network namespace is the holder's"
        );
        assert_ne!(
            want_net, mine_net,
            "the holder's network namespace is not ours"
        );
    }
}
