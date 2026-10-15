//! Stdio pumps and the output cap (issue #10, T6, Q3/Q4, notes §8).
//!
//! The payload's stdout and stderr are always pipes; sbx forwards up to
//! `limits.output_bytes` combined, then drains and discards (never kills). A
//! write error on the caller's side closes the payload's pipe (plain-pipe
//! semantics: `sbx run … | head -1` ends the payload with EPIPE/SIGPIPE).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, TryLockError, mpsc};
use std::thread;
use std::time::Instant;

pub(crate) const PUMP_BUF: usize = 64 * 1024;

/// The combined output budget shared by the stdout and stderr pumps.
pub(crate) struct OutputBudget {
    remaining: AtomicU64,
    truncated: AtomicBool,
    /// Set when `Pumps::finish` returns: no pump may forward anything after that (m8).
    closed: AtomicBool,
    /// stdout and stderr are one open file (`2>&1`, the same pipe): one sink.
    shared: AtomicBool,
    /// The last byte written to the diagnostic sink (stderr, or the shared sink).
    /// Writes to a shared sink are serialised under this lock, so it is exact.
    tail: Mutex<Option<u8>>,
}

impl OutputBudget {
    pub(crate) fn new(cap: u64) -> Arc<Self> {
        Arc::new(Self {
            remaining: AtomicU64::new(cap),
            truncated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            shared: AtomicBool::new(false),
            tail: Mutex::new(None),
        })
    }

    /// Grants up to `n` bytes; a grant smaller than `n` marks the run truncated.
    pub(crate) fn take(&self, n: u64) -> u64 {
        let mut current = self.remaining.load(Ordering::SeqCst);
        loop {
            let granted = current.min(n);
            match self.remaining.compare_exchange_weak(
                current,
                current - granted,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    if granted < n {
                        self.truncated.store(true, Ordering::SeqCst);
                    }
                    return granted;
                }
                Err(actual) => current = actual,
            }
        }
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated.load(Ordering::SeqCst)
    }

    /// Writes forwarded payload bytes to `dst`. Stderr writes always record the tail
    /// (diagnostics go there); when stdout and stderr are one sink, every write does,
    /// under the tail lock, so the tail is the true end of the shared stream.
    pub(crate) fn forward(&self, dst: RawFd, data: &[u8]) -> io::Result<()> {
        if dst != 2 && !self.shared.load(Ordering::SeqCst) {
            return write_all_fd(dst, data);
        }
        let mut tail = self.tail.lock().unwrap_or_else(PoisonError::into_inner);
        write_all_fd(dst, data)?;
        *tail = data.last().copied();
        Ok(())
    }

    /// The diagnostic sink ends mid-line: sbx must start its own line with a newline.
    ///
    /// Never blocks: a pump stuck in `forward` holds the tail lock for an unbounded
    /// write, and teardown must stay bounded by the drain deadline. A busy lock means
    /// a write is in flight, so assume mid-line (an extra newline is harmless).
    pub(crate) fn sink_partial(&self) -> bool {
        let tail = match self.tail.try_lock() {
            Ok(tail) => tail,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return true,
        };
        matches!(*tail, Some(last) if last != b'\n')
    }

    pub(crate) fn set_shared(&self) {
        self.shared.store(true, Ordering::SeqCst);
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: reads at most buf.len() bytes into a live buffer from an fd we own.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Whether two fds are one open file (`2>&1`, one pipe, one log file).
fn same_sink(a: RawFd, b: RawFd) -> bool {
    // SAFETY: fstat on fds we were handed; the stat buffers are zero-initialised.
    unsafe {
        let mut sa: libc::stat = std::mem::zeroed();
        let mut sb: libc::stat = std::mem::zeroed();
        libc::fstat(a, &mut sa) == 0
            && libc::fstat(b, &mut sb) == 0
            && sa.st_dev == sb.st_dev
            && sa.st_ino == sb.st_ino
    }
}

/// Writes all of `data`, waiting for POLLOUT on EAGAIN (the caller may have left
/// its stdout non-blocking).
fn write_all_fd(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // SAFETY: writes from a live slice to an fd we borrow.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n >= 0 {
            data = &data[n as usize..];
            continue;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => {
                let mut fds = [super::sys::pollfd(fd, libc::POLLOUT)];
                super::sys::poll_fds(&mut fds, None)?;
            }
            _ => return Err(err),
        }
    }
    Ok(())
}

/// Copies `src` to `dst` through the budget. Keeps draining after the cap. Any
/// write error stops forwarding AND drops `src`. Sends `()` on `done` at exit.
pub(crate) fn pump(src: OwnedFd, dst: RawFd, budget: Arc<OutputBudget>, done: mpsc::Sender<()>) {
    let mut buf = vec![0u8; PUMP_BUF];
    loop {
        let n = match read_fd(src.as_raw_fd(), &mut buf) {
            Ok(0) | Err(_) => break, // EOF (or unreadable): done
            Ok(n) => n,
        };
        if budget.is_closed() {
            break; // the run is concluding: forward nothing more (m8)
        }
        let grant = budget.take(n as u64) as usize;
        // Caller side gone: stop and drop the read end, so the payload sees EPIPE.
        if grant > 0 && budget.forward(dst, &buf[..grant]).is_err() {
            break;
        }
    }
    drop(src);
    let _ = done.send(());
}

/// Stdin copy for the tty-foreground case: fd 0 → the payload's stdin, EOF closes it.
fn pump_stdin(dst: OwnedFd) {
    let mut buf = vec![0u8; PUMP_BUF];
    loop {
        match read_fd(0, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if write_all_fd(dst.as_raw_fd(), &buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// What the pumps forwarded, as the end of the run needs it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PumpEnd {
    /// The output cap was hit.
    pub truncated: bool,
    /// The forwarded stderr ends mid-line.
    pub stderr_partial: bool,
}

/// The running pumps. The stdin pump is never joined (it may sit in read(0)).
pub(crate) struct Pumps {
    done: mpsc::Receiver<()>,
    outputs: usize,
    budget: Arc<OutputBudget>,
}

impl Pumps {
    /// stdout → fd 1, stderr → fd 2 (raw write(2): std's stdout would delay
    /// partial lines). When `stdin_piped`, fd 0 is copied into the child's stdin.
    pub(crate) fn start(
        child: &mut Child,
        budget: Arc<OutputBudget>,
        stdin_piped: bool,
    ) -> io::Result<Self> {
        if same_sink(1, 2) {
            budget.set_shared();
        }
        let (tx, rx) = mpsc::channel();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("child stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("child stderr was not piped"))?;
        {
            let (budget, tx) = (budget.clone(), tx.clone());
            thread::Builder::new()
                .name("sbx-out".into())
                .spawn(move || pump(OwnedFd::from(stdout), 1, budget, tx))?;
        }
        {
            let (budget, tx) = (budget.clone(), tx.clone());
            thread::Builder::new()
                .name("sbx-err".into())
                .spawn(move || pump(OwnedFd::from(stderr), 2, budget, tx))?;
        }
        if stdin_piped {
            if let Some(stdin) = child.stdin.take() {
                thread::Builder::new()
                    .name("sbx-in".into())
                    .spawn(move || pump_stdin(OwnedFd::from(stdin)))?;
            }
        }
        Ok(Self {
            done: rx,
            outputs: 2,
            budget,
        })
    }

    /// Waits for both OUTPUT pumps to reach EOF or exit, until `deadline`.
    pub(crate) fn finish(self, deadline: Instant) -> PumpEnd {
        for _ in 0..self.outputs {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if self.done.recv_timeout(remaining).is_err() {
                break;
            }
        }
        // Close the gate before the diagnostics are written (m8): a pump that is
        // still reading drains without forwarding from here on.
        self.budget.close();
        PumpEnd {
            truncated: self.budget.truncated(),
            stderr_partial: self.budget.sink_partial(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sink_partial_never_blocks_on_a_stuck_forward() {
        let budget = super::OutputBudget::new(10);
        let held = budget.tail.lock().unwrap();
        // A forward stuck mid-write holds the lock; teardown must not wait for it.
        assert!(budget.sink_partial());
        drop(held);
        assert!(!budget.sink_partial());
    }

    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::time::Duration;

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe2 writes two fds into the array; both are owned below.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: fresh fds returned by pipe2.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn budget_exact_cap_split() {
        let b = OutputBudget::new(10);
        assert_eq!(b.take(4), 4);
        assert!(!b.truncated());
        assert_eq!(b.take(4), 4);
        assert_eq!(b.take(4), 2); // partial grant
        assert!(b.truncated());
        assert_eq!(b.take(4), 0);
    }

    #[test]
    fn closed_budget_forwards_nothing() {
        // m8: after finish() closes the gate, a pump writes nothing more.
        let (src_r, src_w) = pipe();
        let (dst_r, dst_w) = pipe();
        let budget = OutputBudget::new(1_000);
        budget.close();
        let mut writer = std::fs::File::from(src_w);
        writer.write_all(b"late output").expect("write");
        drop(writer);
        let (tx, rx) = mpsc::channel();
        let dst_fd = dst_w.as_raw_fd();
        let handle = thread::spawn(move || pump(src_r, dst_fd, budget, tx));
        rx.recv_timeout(Duration::from_secs(5)).expect("pump done");
        handle.join().expect("join");
        drop(dst_w);
        let mut out = Vec::new();
        std::fs::File::from(dst_r)
            .read_to_end(&mut out)
            .expect("read");
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn budget_zero_cap() {
        let b = OutputBudget::new(0);
        assert_eq!(b.take(1), 0);
        assert!(b.truncated());
    }

    #[test]
    fn budget_concurrent_never_exceeds() {
        let b = OutputBudget::new(1_000);
        let total = Arc::new(AtomicU64::new(0));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (b, total) = (b.clone(), total.clone());
                thread::spawn(move || {
                    for _ in 0..10_000 {
                        total.fetch_add(b.take(1), Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        assert_eq!(total.load(Ordering::SeqCst), 1_000);
        assert!(b.truncated());
    }

    #[test]
    fn pump_forwards_then_truncates_then_drains() {
        let (src_r, src_w) = pipe();
        let (dst_r, dst_w) = pipe();
        let budget = OutputBudget::new(5);
        let (tx, rx) = mpsc::channel();
        let dst_fd = dst_w.as_raw_fd();
        let handle = thread::spawn(move || pump(src_r, dst_fd, budget, tx));
        let mut writer = std::fs::File::from(src_w);
        writer.write_all(b"abcdefghij").expect("write");
        drop(writer); // EOF
        rx.recv_timeout(Duration::from_secs(5)).expect("pump done");
        handle.join().expect("join");
        drop(dst_w);
        let mut out = String::new();
        std::fs::File::from(dst_r)
            .read_to_string(&mut out)
            .expect("read");
        assert_eq!(out, "abcde");
    }

    #[test]
    fn pump_dest_epipe_closes_source() {
        let (src_r, src_w) = pipe();
        let (dst_r, dst_w) = pipe();
        drop(dst_r); // the caller has gone: every write to dst fails with EPIPE
        let budget = OutputBudget::new(1_000);
        let (tx, rx) = mpsc::channel();
        let dst_fd = dst_w.as_raw_fd();
        let handle = thread::spawn(move || pump(src_r, dst_fd, budget, tx));
        let mut writer = std::fs::File::from(src_w);
        // SIGPIPE is ignored by the test harness (std), so the writer sees EPIPE.
        let _ = writer.write_all(b"x");
        rx.recv_timeout(Duration::from_secs(5)).expect("pump done");
        handle.join().expect("join");
        let err = (|| -> io::Result<()> {
            // Once the pump dropped its read end, the next write must fail.
            for _ in 0..100 {
                writer.write_all(&[b'y'; 4096])?;
            }
            Ok(())
        })()
        .expect_err("writer must observe EPIPE");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        drop(dst_w);
    }
}
