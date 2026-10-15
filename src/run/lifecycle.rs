//! The sandbox lifecycle after the spawn (issue #10, T7, notes §7.2–7.3): the
//! poll loop over the child's pidfd, the signalfd, the fault latch and the bwrap
//! info pipe; and the single teardown path that kills pid 1 and reaps bwrap.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use super::serve::{Fault, FaultLatch};
use super::spawn::{open_pid1, parse_info, pid1_from_children};
use super::stdio::{PumpEnd, Pumps};
use super::sys::{self, Signals, pollfd, ready};
use super::{INFO_MAX_BYTES, Outcome, PUMP_DRAIN_TIMEOUT, RunError, TEARDOWN_TIMEOUT};

/// The sandbox's pid 1, learned from bwrap's info pipe.
pub(crate) enum Pid1 {
    /// bwrap has not reported yet; `buf` holds what was read so far.
    Pending { info: OwnedFd, buf: Vec<u8> },
    /// Verified (PPid == bwrap, NSpid last == 1) and held by pidfd.
    Known(OwnedFd),
    /// bwrap reported nothing usable (it died early, or the proof failed).
    Gone,
}

/// Everything the teardown needs about the launched sandbox.
pub(crate) struct Sandbox {
    pub(crate) child: Child,
    pub(crate) child_pidfd: OwnedFd,
    pub(crate) bwrap_pid: libc::pid_t,
    pub(crate) pid1: Pid1,
    pub(crate) go_sent: bool,
}

impl Drop for Sandbox {
    /// Panic backstop: SIGKILL whatever is still alive. Idempotent (ESRCH is Ok).
    fn drop(&mut self) {
        if let Pid1::Known(fd) = &self.pid1 {
            let _ = sys::pidfd_kill(fd.as_fd());
        }
        let _ = sys::pidfd_kill(self.child_pidfd.as_fd());
    }
}

/// Why the run ends. Input to [`outcome_of`].
pub(crate) enum Cause {
    Fault(Fault),
    Signal(i32),
    ChildExited,
    Timeout(Duration),
    Setup(RunError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CauseKind {
    Fault,
    Signal,
    ChildExited,
    Timeout,
}

/// Pure priority rule for one wakeup: fault > signal > child exit > timeout.
pub(crate) fn pick_cause(
    fault: bool,
    signal: Option<i32>,
    child: bool,
    timed_out: bool,
) -> Option<CauseKind> {
    if fault {
        Some(CauseKind::Fault)
    } else if signal.is_some() {
        Some(CauseKind::Signal)
    } else if child {
        Some(CauseKind::ChildExited)
    } else if timed_out {
        Some(CauseKind::Timeout)
    } else {
        None
    }
}

/// Maps a cause (and bwrap's status, when it exited on its own) to the outcome.
pub(crate) fn outcome_of(cause: Cause, status: Option<ExitStatus>) -> Outcome {
    match cause {
        Cause::Fault(Fault::Net(text)) => {
            Outcome::Failed(format!("network service failed: {text}"))
        }
        Cause::Fault(Fault::Audit(text)) => {
            Outcome::Failed(format!("audit log write failed: {text}"))
        }
        Cause::Setup(err) => Outcome::Failed(err.reason().to_owned()),
        Cause::Timeout(limit) => Outcome::TimedOut(limit),
        Cause::Signal(sig) => Outcome::Terminated(sig),
        Cause::ChildExited => match status {
            Some(st) => match (st.code(), st.signal()) {
                (Some(code), _) => Outcome::Exited(code),
                (None, Some(sig)) => Outcome::Signaled(sig),
                (None, None) => Outcome::Failed("sandbox ended in an unknown state".into()),
            },
            None => Outcome::Failed("cannot collect the sandbox exit status".into()),
        },
    }
}

fn kind_to_cause(
    kind: CauseKind,
    fault: Option<Fault>,
    signal: Option<i32>,
    limit: Duration,
) -> Option<Cause> {
    match kind {
        CauseKind::Fault => fault.map(Cause::Fault),
        CauseKind::Signal => signal.map(Cause::Signal),
        CauseKind::ChildExited => Some(Cause::ChildExited),
        CauseKind::Timeout => Some(Cause::Timeout(limit)),
    }
}

/// Reads whatever bwrap wrote so far (non-blocking). Returns true at EOF.
fn drain_info(info: &OwnedFd, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 512];
    loop {
        // SAFETY: reads at most chunk.len() bytes into a live buffer from an fd we own.
        let n = unsafe { libc::read(info.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if n == 0 {
            return true;
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // EAGAIN: no more data for now. Anything else: treat as EOF.
            return err.kind() != io::ErrorKind::WouldBlock;
        }
        let room = (INFO_MAX_BYTES + 1).saturating_sub(buf.len());
        buf.extend_from_slice(&chunk[..(n as usize).min(room)]);
    }
}

/// Resolves pid 1 once bwrap's info pipe reached EOF (or never will).
fn resolve_pid1(buf: &[u8], bwrap_pid: libc::pid_t) -> Pid1 {
    let from_info = if buf.len() <= INFO_MAX_BYTES {
        parse_info(buf).and_then(|pid| open_pid1(pid, bwrap_pid))
    } else {
        None // oversized info ⇒ unparseable (INFO_MAX_BYTES)
    };
    match from_info.or_else(|| pid1_from_children(bwrap_pid)) {
        Some(fd) => Pid1::Known(fd),
        None => Pid1::Gone,
    }
}

/// The supervisor loop. The first cause observed wins (see [`pick_cause`]).
pub(crate) fn main_loop(
    sb: &mut Sandbox,
    signals: &Signals,
    latch: &FaultLatch,
    deadline: Instant,
    timeout: Duration,
) -> Cause {
    loop {
        let mut fds = vec![
            pollfd(sb.child_pidfd.as_raw_fd(), libc::POLLIN),
            pollfd(signals.fd().as_raw_fd(), libc::POLLIN),
            pollfd(latch.fd().as_raw_fd(), libc::POLLIN),
        ];
        let info_index = match &sb.pid1 {
            Pid1::Pending { info, .. } => {
                fds.push(pollfd(info.as_raw_fd(), libc::POLLIN));
                Some(fds.len() - 1)
            }
            _ => None,
        };
        if let Err(err) = sys::poll_fds(&mut fds, Some(deadline)) {
            return Cause::Setup(RunError::new(format!("internal error: poll failed: {err}")));
        }
        if let Some(index) = info_index {
            if ready(fds[index].revents) {
                if let Pid1::Pending { info, buf } = &mut sb.pid1 {
                    if drain_info(info, buf) {
                        let buf = std::mem::take(buf);
                        sb.pid1 = resolve_pid1(&buf, sb.bwrap_pid);
                    }
                }
            }
        }
        let fault = if ready(fds[2].revents) {
            latch.take()
        } else {
            None
        };
        let signal = if ready(fds[1].revents) {
            signals.read()
        } else {
            None
        };
        let child = ready(fds[0].revents);
        let timed_out = Instant::now() >= deadline;
        if let Some(kind) = pick_cause(fault.is_some(), signal, child, timed_out) {
            if let Some(cause) = kind_to_cause(kind, fault, signal, timeout) {
                return cause;
            }
        }
    }
}

/// Teardown (§7.3): kill pid 1 through its pidfd, wait for it (the whole pid
/// namespace is then gone), reap bwrap, drain the pumps. Returns
/// `(outcome, output_truncated, stragglers)`.
pub(crate) fn teardown(
    mut sb: Sandbox,
    cause: Cause,
    pumps: Option<Pumps>,
) -> (Outcome, PumpEnd, bool) {
    let mut stragglers = false;
    if sb.go_sent {
        // T2: pid 1 may still be unknown; give bwrap a short grace to report.
        if let Pid1::Pending { info, buf } = &mut sb.pid1 {
            let until = Instant::now() + super::INFO_GRACE;
            loop {
                let remaining = until.saturating_duration_since(Instant::now());
                match sys::wait_readable(info.as_fd(), remaining) {
                    Ok(true) => {
                        if drain_info(info, buf) {
                            break;
                        }
                    }
                    _ => break,
                }
                if Instant::now() >= until {
                    break;
                }
            }
            let buf = std::mem::take(buf);
            sb.pid1 = resolve_pid1(&buf, sb.bwrap_pid);
        }
        // T3: kill pid 1; readable ⇔ it exited ⇔ the namespace is reaped.
        if let Pid1::Known(fd) = &sb.pid1 {
            let _ = sys::pidfd_kill(fd.as_fd());
            if !matches!(sys::wait_readable(fd.as_fd(), TEARDOWN_TIMEOUT), Ok(true)) {
                stragglers = true;
            }
        }
    } else {
        // Before the go byte the child is __init, which has no sandbox to kill.
        let _ = sys::pidfd_kill(sb.child_pidfd.as_fd());
    }
    // T4: bwrap exits on its own once pid 1 is gone; make sure it does.
    if !matches!(
        sys::wait_readable(sb.child_pidfd.as_fd(), Duration::ZERO),
        Ok(true)
    ) {
        let _ = sys::pidfd_kill(sb.child_pidfd.as_fd());
        if !matches!(
            sys::wait_readable(sb.child_pidfd.as_fd(), TEARDOWN_TIMEOUT),
            Ok(true)
        ) {
            stragglers = true;
        }
    }
    // T5: reap (never earlier — keeps the PPid proof sound).
    let status = sb.child.wait().ok();
    // T6: pumps see EOF once every write end died with the namespace.
    let outcome = outcome_of(cause, status);
    let end = pumps
        .map(|p| p.finish(Instant::now() + PUMP_DRAIN_TIMEOUT))
        .unwrap_or_default();
    (outcome, end, stragglers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_cause_priority_table() {
        use CauseKind::*;
        type Case = (bool, Option<i32>, bool, bool, Option<CauseKind>);
        let cases: [Case; 8] = [
            (false, None, false, false, None),
            (false, None, false, true, Some(Timeout)),
            (false, None, true, true, Some(ChildExited)),
            (false, Some(15), true, true, Some(Signal)),
            (true, Some(15), true, true, Some(Fault)),
            (true, None, false, false, Some(Fault)),
            (false, None, true, false, Some(ChildExited)),
            (false, Some(2), false, true, Some(Signal)),
        ];
        for (fault, signal, child, timed, want) in cases {
            assert_eq!(pick_cause(fault, signal, child, timed), want);
        }
    }

    #[test]
    fn outcome_of_table() {
        let exit = |code: i32| ExitStatus::from_raw(code << 8);
        let sig = |s: i32| ExitStatus::from_raw(s);
        assert_eq!(
            outcome_of(Cause::ChildExited, Some(exit(0))),
            Outcome::Exited(0)
        );
        assert_eq!(
            outcome_of(Cause::ChildExited, Some(exit(3))),
            Outcome::Exited(3)
        );
        assert_eq!(
            outcome_of(Cause::ChildExited, Some(sig(9))),
            Outcome::Signaled(9)
        );
        assert_eq!(
            outcome_of(Cause::Timeout(Duration::from_secs(1)), Some(sig(9))),
            Outcome::TimedOut(Duration::from_secs(1))
        );
        assert_eq!(
            outcome_of(Cause::Signal(15), Some(sig(9))),
            Outcome::Terminated(15)
        );
        assert_eq!(
            outcome_of(Cause::Fault(Fault::Net("x".into())), None),
            Outcome::Failed("network service failed: x".into())
        );
        assert_eq!(
            outcome_of(Cause::Fault(Fault::Audit("disk".into())), None),
            Outcome::Failed("audit log write failed: disk".into())
        );
        assert_eq!(
            outcome_of(Cause::Setup(RunError::new("bwrap not found")), None),
            Outcome::Failed("bwrap not found".into())
        );
        assert_eq!(
            outcome_of(Cause::ChildExited, None),
            Outcome::Failed("cannot collect the sandbox exit status".into())
        );
    }

    #[test]
    fn resolve_pid1_falls_back_to_gone() {
        // Unparseable info and a bwrap pid that does not exist ⇒ Gone.
        assert!(matches!(
            resolve_pid1(b"nonsense", 2_000_000_000),
            Pid1::Gone
        ));
        // Oversized info is never parsed.
        let big = vec![b' '; INFO_MAX_BYTES + 10];
        assert!(matches!(resolve_pid1(&big, 2_000_000_000), Pid1::Gone));
    }
}
