//! Runner-side process mechanics (issue #13, §8.2): `sbx run` spawns with a
//! stdout line channel, bounded waits, group kills, and the `/proc` survivor
//! scans. All spawns happen on the main thread (the CLOEXEC rule of H05/F03).

use std::io::{self, BufRead, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Everything a finished `sbx run` left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    pub rc: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<String>,
    pub stderr: String,
    pub elapsed_ms: u64,
}

/// Builder for one `sbx run` invocation.
pub struct SbxRun {
    exe: PathBuf,
    policy: PathBuf,
    session: PathBuf,
    audit: Option<PathBuf>,
    timeout: Option<String>,
    test_break_rules: bool,
    stdin_pipe: bool,
    fsize_limit: Option<u64>,
    env: Vec<(String, String)>,
    cmd: Vec<String>,
}

impl SbxRun {
    /// A run of `exe` with the policy and session directory.
    pub fn new(exe: &Path, policy: &Path, session: &Path, cmd: Vec<String>) -> Self {
        SbxRun {
            exe: exe.to_path_buf(),
            policy: policy.to_path_buf(),
            session: session.to_path_buf(),
            audit: None,
            timeout: None,
            test_break_rules: false,
            stdin_pipe: false,
            fsize_limit: None,
            env: Vec::new(),
            cmd,
        }
    }

    /// `--audit FILE`.
    pub fn audit(mut self, file: &Path) -> Self {
        self.audit = Some(file.to_path_buf());
        self
    }

    /// `--timeout D`.
    pub fn timeout(mut self, d: &str) -> Self {
        self.timeout = Some(d.to_owned());
        self
    }

    /// `--test-break-rules`.
    pub fn break_rules(mut self) -> Self {
        self.test_break_rules = true;
        self
    }

    /// Pipe stdin (the runner closes it to release `wait_stdin`).
    pub fn stdin_pipe(mut self) -> Self {
        self.stdin_pipe = true;
        self
    }

    /// Lower RLIMIT_FSIZE in the child and ignore SIGXFSZ (F06).
    pub fn fsize(mut self, bytes: u64) -> Self {
        self.fsize_limit = Some(bytes);
        self
    }

    /// An extra environment variable for `sbx run` (inherited otherwise).
    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.to_owned(), v.to_owned()));
        self
    }

    /// Spawn it; the returned handle owns the child group.
    pub fn spawn(self) -> io::Result<Running> {
        let mut cmd = Command::new(&self.exe);
        cmd.arg("run")
            .arg("--policy")
            .arg(&self.policy)
            .arg("--session-dir")
            .arg(&self.session);
        if let Some(a) = &self.audit {
            cmd.arg("--audit").arg(a);
        }
        if let Some(t) = &self.timeout {
            cmd.arg("--timeout").arg(t);
        }
        if self.test_break_rules {
            cmd.arg("--test-break-rules");
        }
        cmd.arg("--");
        cmd.args(&self.cmd);
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        cmd.process_group(0);
        cmd.stdin(if self.stdin_pipe {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let fsize = self.fsize_limit;
        // SAFETY: only async-signal-safe calls (setrlimit, signal) run between
        // fork and exec. Every child starts with default signal dispositions: an
        // inherited SIG_IGN (a background job in a non-interactive shell) would
        // make `sbx run` ignore the very signals G03 sends it.
        unsafe {
            cmd.pre_exec(move || {
                for sig in [libc::SIGINT, libc::SIGHUP, libc::SIGTERM, libc::SIGQUIT] {
                    libc::signal(sig, libc::SIG_DFL);
                }
                if let Some(limit) = fsize {
                    let rl = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &rl) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                }
                Ok(())
            });
        }
        let t0 = Instant::now();
        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout pipe"))?;
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        let (tx, rx) = mpsc::channel::<String>();
        let out_thread = std::thread::spawn(move || {
            for line in io::BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let err_thread = stderr.map(|e| {
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = io::Read::read_to_string(&mut io::BufReader::new(e), &mut s);
                s
            })
        });
        Ok(Running {
            child,
            rx,
            collected: Vec::new(),
            out_thread: Some(out_thread),
            err_thread,
            stdin,
            t0,
            finished: false,
        })
    }
}

/// A spawned `sbx run`. Dropping it kills its process group.
pub struct Running {
    child: Child,
    rx: Receiver<String>,
    collected: Vec<String>,
    out_thread: Option<JoinHandle<()>>,
    err_thread: Option<JoinHandle<String>>,
    stdin: Option<ChildStdin>,
    t0: Instant,
    finished: bool,
}

impl Running {
    /// The child's pid (also its process group id: `process_group(0)`).
    pub fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    /// Wait until a stdout line satisfies `pred`, or `deadline` passes.
    pub fn wait_line(&mut self, pred: impl Fn(&str) -> bool, deadline: Instant) -> Option<String> {
        if let Some(found) = self.collected.iter().find(|l| pred(l)) {
            return Some(found.clone());
        }
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            match self.rx.recv_timeout(deadline - now) {
                Ok(line) => {
                    let hit = pred(&line);
                    self.collected.push(line.clone());
                    if hit {
                        return Some(line);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Write to the stdin pipe (a `wait_stdin` release is `close_stdin`).
    pub fn write_stdin(&mut self, text: &str) {
        if let Some(s) = self.stdin.as_mut() {
            let _ = s.write_all(text.as_bytes());
        }
    }

    /// Close the stdin pipe (EOF for `wait_stdin`).
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Send `sig` to the `sbx run` process itself.
    pub fn signal(&self, sig: i32) {
        // SAFETY: plain kill(2) on our own child's pid.
        unsafe { libc::kill(self.pid(), sig) };
    }

    /// SIGKILL `sbx run` (not the group): the test of F01.
    pub fn sigkill(&self) {
        self.signal(libc::SIGKILL);
    }

    /// Poll for the exit until `deadline`; on expiry kill the group and reap.
    pub fn wait_bounded(&mut self, deadline: Instant) -> Finished {
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {}
                Err(_) => break None,
            }
            if Instant::now() >= deadline {
                self.kill_group();
                break self.child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        self.finished = true;
        // Leftover descendants (for example a setsid'd background probe that
        // held stdout) are killed as a group; the pipes close, then we drain.
        self.kill_group();
        let stdout = self.drain_stdout();
        let stderr = self
            .err_thread
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        Finished {
            rc: status.and_then(|s| s.code()),
            signal: status.and_then(|s| s.signal()),
            stdout,
            stderr,
            elapsed_ms: self.t0.elapsed().as_millis() as u64,
        }
    }

    fn drain_stdout(&mut self) -> Vec<String> {
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            match self.rx.recv_timeout(Duration::from_millis(20)) {
                Ok(l) => self.collected.push(l),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.out_thread.as_ref().is_none_or(|h| h.is_finished()) {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        while let Ok(l) = self.rx.try_recv() {
            self.collected.push(l);
        }
        std::mem::take(&mut self.collected)
    }

    /// SIGKILL the whole process group (also reaps nothing: the caller waits).
    pub fn kill_group(&self) {
        // SAFETY: kill(2) on our own process group.
        unsafe { libc::kill(-self.pid(), libc::SIGKILL) };
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.finished {
            self.kill_group();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Host pids whose argv contains `token` as one exact NUL-separated argument.
pub fn proc_scan(token: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(bytes) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            if bytes.split(|b| *b == 0).any(|arg| arg == token.as_bytes()) {
                pids.push(pid);
            }
        }
    }
    pids.sort();
    pids
}

/// The `net` namespace link text of `pid` (`net:[inode]`), if readable.
pub fn netns_of(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Every readable pid whose netns link equals `netns`.
pub fn pids_in_netns(netns: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if netns_of(pid).as_deref() == Some(netns) {
            pids.push(pid);
        }
    }
    pids
}

/// Poll until no process carries `token` (and none is in `netns`). On timeout
/// every survivor is SIGKILLed and reported (pids are the evidence).
pub fn wait_gone(token: &str, netns: Option<&str>, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let alive =
            !proc_scan(token).is_empty() || netns.is_some_and(|n| !pids_in_netns(n).is_empty());
        if !alive {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let mut pids = proc_scan(token);
            if let Some(n) = netns {
                pids.extend(pids_in_netns(n));
            }
            pids.sort();
            pids.dedup();
            for p in &pids {
                kill_pid(*p, libc::SIGKILL);
            }
            return Err(format!(
                "survived the {}s bound: pids {pids:?} (SIGKILLed)",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send `sig` to a host pid (best effort).
pub fn kill_pid(pid: u32, sig: i32) {
    // SAFETY: kill(2) on a pid we found under /proc.
    unsafe { libc::kill(pid as i32, sig) };
}
