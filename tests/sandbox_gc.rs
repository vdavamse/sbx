//! Integration suite for `sbx gc` (issue #12): the real binary on real temp
//! ROOTs, plus mount-crossing scenarios inside a user+mount namespace.
//!
//! Why `harness = false`: the mount scenarios unshare `USER|NS` in a child
//! role, and `unshare(CLONE_NEWUSER)` needs a single-threaded process. The
//! parent stays sequential with bounded waits, like `sandbox_run` and
//! `sandbox_init`. Role dispatch (`SBX_GC_ROLE`) runs first, before any thread.
//!
//! Gates (SKIP-with-message, exit 0; any FAIL exits 1):
//! * `Always`: no environment requirement.
//! * `Userns`: unprivileged user+mount namespaces are available (probed by
//!   re-executing this binary with the `probe-userns` role).

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

const ROLE_ENV: &str = "SBX_GC_ROLE";
const SBX: &str = env!("CARGO_BIN_EXE_sbx");
const BOUND: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(86_400);
const USERNS_SKIP: &str = "unprivileged user+mount namespaces unavailable (CI: sysctl kernel.apparmor_restrict_unprivileged_userns=0)";

fn main() -> ExitCode {
    // Role dispatch FIRST: the mount roles unshare, which needs one thread.
    if let Ok(role) = std::env::var(ROLE_ENV) {
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        return run_role(&role, &args);
    }
    let filter: Option<String> = std::env::args().nth(1);
    let userns_ok = userns_available();
    let (mut passed, mut failed, mut skipped) = (0u32, 0u32, 0u32);
    for sc in scenarios() {
        if let Some(f) = &filter {
            if !sc.name.contains(f.as_str()) {
                continue;
            }
        }
        if sc.gate == Gate::Userns && !userns_ok {
            println!("SKIP {}: {USERNS_SKIP}", sc.name);
            skipped += 1;
            continue;
        }
        let started = Instant::now();
        match (sc.run)() {
            Ok(()) => {
                println!("PASS {} ({:?})", sc.name, started.elapsed());
                passed += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", sc.name);
                failed += 1;
            }
        }
    }
    println!("sandbox_gc: {passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    Always,
    Userns,
}

struct Scenario {
    name: &'static str,
    gate: Gate,
    run: fn() -> Result<(), String>,
}

fn scenarios() -> Vec<Scenario> {
    use Gate::{Always, Userns};
    vec![
        Scenario {
            name: "ac1-symlinks-not-followed",
            gate: Always,
            run: ac1_symlinks_not_followed,
        },
        Scenario {
            name: "ac2-locked-session-kept",
            gate: Always,
            run: ac2_locked_session_kept,
        },
        Scenario {
            name: "ac3-old-new-mix-dry-run",
            gate: Always,
            run: ac3_old_new_mix_dry_run,
        },
        Scenario {
            name: "partial-failure-continues",
            gate: Always,
            run: partial_failure_continues,
        },
        Scenario {
            name: "leftover-tombstone-collected",
            gate: Always,
            run: leftover_tombstone_collected,
        },
        Scenario {
            name: "deep-tree-rlimit-32",
            gate: Always,
            run: deep_tree_rlimit_32,
        },
        Scenario {
            name: "non-utf8-session-name",
            gate: Always,
            run: non_utf8_session_name,
        },
        Scenario {
            name: "root-refusals",
            gate: Always,
            run: root_refusals,
        },
        Scenario {
            name: "parallel-gc-lockless-tombstone",
            gate: Always,
            run: parallel_gc_lockless_tombstone,
        },
        Scenario {
            name: "mount-point-inside-session",
            gate: Userns,
            run: mount_point_inside_session,
        },
        Scenario {
            name: "mount-point-fallback-mount-id",
            gate: Userns,
            run: mount_point_fallback_mount_id,
        },
        Scenario {
            name: "session-dir-is-mount-point",
            gate: Userns,
            run: session_dir_is_mount_point,
        },
    ]
}

// ---- roles (re-exec'd children) ----------------------------------------------

fn run_role(role: &str, args: &[OsString]) -> ExitCode {
    match role {
        "probe-userns" => {
            // SAFETY: unshare takes flags by value; no pointers.
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
            ExitCode::from(u8::from(rc != 0))
        }
        "mountns" => mountns_role(args),
        other => {
            eprintln!("sandbox_gc: unknown role {other:?}");
            ExitCode::from(2)
        }
    }
}

fn arg_str(args: &[OsString], i: usize) -> String {
    args.get(i)
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `mountns <mode> <root> <outside>`: unshare USER|NS, map the caller to root,
/// make `/` private, build the mount layout for `mode`, then run `sbx gc` on
/// `root` inside it. The role exits with gc's rc, and its stdio is the
/// caller's.
fn mountns_role(args: &[OsString]) -> ExitCode {
    let mode = arg_str(args, 0);
    // `inproc-<layout>`: the same layout, but gc runs in this process with the
    // name_to_handle_at fallback forced on (kernels < 5.8 behaviour).
    let (mode, inproc) = match mode.strip_prefix("inproc-") {
        Some(rest) => (rest.to_owned(), true),
        None => (mode, false),
    };
    let root = args.get(1).map(PathBuf::from).unwrap_or_default();
    let outside = args.get(2).map(PathBuf::from).unwrap_or_default();
    // SAFETY: getuid/getgid have no preconditions and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // SAFETY: unshare takes flags by value; no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        eprintln!("unshare: {}", io::Error::last_os_error());
        return ExitCode::from(3);
    }
    let maps = fs::write("/proc/self/setgroups", "deny")
        .and_then(|()| fs::write("/proc/self/uid_map", format!("0 {uid} 1")))
        .and_then(|()| fs::write("/proc/self/gid_map", format!("0 {gid} 1")));
    if let Err(err) = maps {
        eprintln!("id maps: {err}");
        return ExitCode::from(3);
    }
    if let Err(err) = mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE) {
        eprintln!("make / private: {err}");
        return ExitCode::from(3);
    }
    let layout = match mode.as_str() {
        "cross" => build_cross(&root, &outside),
        "session" => build_session_mount(&root),
        other => Err(format!("unknown mode {other:?}")),
    };
    if let Err(err) = layout {
        eprintln!("{err}");
        return ExitCode::from(3);
    }
    if inproc {
        sbx::gc::force_mount_id_fallback(true);
        return sbx::gc::gc(sbx::gc::GcArgs {
            root,
            older_than: DAY,
            dry_run: false,
        });
    }
    match Command::new(SBX)
        .args(["gc", "--older-than", "1d"])
        .arg(&root)
        .status()
    {
        Ok(status) => ExitCode::from(u8::try_from(status.code().unwrap_or(3)).unwrap_or(3)),
        Err(err) => {
            eprintln!("spawn sbx gc: {err}");
            ExitCode::from(3)
        }
    }
}

/// s1/work/b is a bind mount of `outside` (same filesystem, so only the
/// mount id can tell). s2/work/t is a tmpfs with a file in it.
fn build_cross(root: &Path, outside: &Path) -> Result<(), String> {
    let b = root.join("s1/work/b");
    mount(Some(outside), &b, None, libc::MS_BIND).map_err(|e| format!("bind {b:?}: {e}"))?;
    let t = root.join("s2/work/t");
    mount(None, &t, Some(c"tmpfs"), 0).map_err(|e| format!("tmpfs {t:?}: {e}"))?;
    fs::write(t.join("inside"), b"x").map_err(|e| format!("write in tmpfs: {e}"))
}

/// A tmpfs mounted over the session directory, with its own lock. The mount
/// root is backdated, so only the mount check can refuse it. The tmpfs root
/// starts as 1777, so it is chmod'ed to 0700 first (Q14 runs before the
/// mount check).
fn build_session_mount(root: &Path) -> Result<(), String> {
    let s = root.join("s");
    mount(None, &s, Some(c"tmpfs"), 0).map_err(|e| format!("tmpfs {s:?}: {e}"))?;
    fs::set_permissions(&s, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod: {e}"))?;
    create_lock(&s).map_err(|e| format!("lock in tmpfs: {e}"))?;
    backdate(&s, DAY * 2).map_err(|e| format!("backdate: {e}"))
}

fn cstr(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("no NUL in test paths")
}

/// `mount(2)` with optional source and path-based target. `fstype` is set for
/// tmpfs; `MS_BIND` takes the source as a path.
fn mount(
    src: Option<&Path>,
    target: &Path,
    fstype: Option<&CStr>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let src = src.map(cstr);
    let target = cstr(target);
    let src_ptr = src.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    let fs_ptr = fstype.map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: mount(2) with NUL-terminated paths, or NULL where the flags allow
    // it (the root remount and tmpfs take no source; a bind takes no fstype).
    let rc = unsafe { libc::mount(src_ptr, target.as_ptr(), fs_ptr, flags, std::ptr::null()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- helpers ------------------------------------------------------------------

/// A unique scratch directory, made traversable and removed on drop (the
/// walker can leave modes behind that a plain remove cannot cross).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "sbx-gc-it-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("scratch dir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod scratch");
        Self(p)
    }

    /// A fresh ROOT inside the scratch directory.
    fn root(&self) -> PathBuf {
        let r = self.0.join("root");
        fs::create_dir_all(&r).expect("mkdir root");
        fs::set_permissions(&r, fs::Permissions::from_mode(0o700)).expect("chmod root");
        r
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fn traversable(p: &Path) {
            if let Ok(md) = fs::symlink_metadata(p) {
                if md.is_dir() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o700));
                    if let Ok(rd) = fs::read_dir(p) {
                        for e in rd.flatten() {
                            traversable(&e.path());
                        }
                    }
                }
            }
        }
        traversable(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_lock(dir: &Path) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("sbx.lock"))
        .map(drop)
}

/// Sets the directory's mtime to `now - age`. Must be the last change made to
/// the directory: adding or removing entries moves the mtime.
fn backdate(p: &Path, age: Duration) -> io::Result<()> {
    File::open(p)?.set_times(FileTimes::new().set_modified(SystemTime::now() - age))
}

/// A session: a 0700 directory with an `sbx.lock`, backdated by `age`.
fn session(root: &Path, name: &OsStr, age: Duration) -> PathBuf {
    let p = root.join(name);
    fs::create_dir(&p).expect("mkdir session");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod session");
    create_lock(&p).expect("create sbx.lock");
    backdate(&p, age).expect("backdate session");
    p
}

/// Holds an exclusive flock on `p` for the life of the returned file.
fn hold(p: &Path) -> File {
    let f = File::open(p).expect("open lock to hold");
    // SAFETY: flock on an fd we own; no pointers.
    assert_eq!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "hold flock on {p:?}"
    );
    f
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// `mkdir -p`-style helper for test trees (mode 0700 at each level).
fn mkdirs(p: &Path) {
    fs::create_dir_all(p).expect("mkdir -p");
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).expect("chmod");
}

struct Done {
    rc: i32,
    stdout: String,
    stderr: String,
}

/// Runs `sbx <args>` with stdout and stderr in files, polling with a bound.
/// `rlimit_nofile` sets soft and hard RLIMIT_NOFILE in the child before exec.
fn sbx(args: &[OsString], rlimit_nofile: Option<u64>) -> Result<Done, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let id = N.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("sbx-gc-io-{}-{id}", std::process::id()));
    let (out_p, err_p) = (base.with_extension("out"), base.with_extension("err"));
    let mut cmd = Command::new(SBX);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(File::create(&out_p).expect("out file")))
        .stderr(Stdio::from(File::create(&err_p).expect("err file")));
    if let Some(n) = rlimit_nofile {
        // SAFETY: the closure only calls setrlimit, which is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                let lim = libc::rlimit {
                    rlim_cur: n,
                    rlim_max: n,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn().map_err(|e| format!("spawn sbx: {e}"))?;
    let started = Instant::now();
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > BOUND => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("sbx {args:?} exceeded {BOUND:?}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("wait sbx: {e}")),
        }
    };
    let stdout = fs::read_to_string(&out_p).unwrap_or_default();
    let stderr = fs::read_to_string(&err_p).unwrap_or_default();
    let _ = fs::remove_file(&out_p);
    let _ = fs::remove_file(&err_p);
    Ok(Done {
        rc: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// `sbx gc --older-than <older> [--dry-run] <root>`.
fn gc(root: &Path, older: &str, dry_run: bool) -> Result<Done, String> {
    let mut args: Vec<OsString> = vec!["gc".into(), "--older-than".into(), older.into()];
    if dry_run {
        args.push("--dry-run".into());
    }
    args.push(root.as_os_str().to_owned());
    sbx(&args, None)
}

/// `sbx gc --older-than 1d <root>`: the common real run.
fn gc_1d(root: &Path) -> Result<Done, String> {
    gc(root, "1d", false)
}

fn expect_rc(done: &Done, want: i32) -> Result<(), String> {
    if done.rc == want {
        Ok(())
    } else {
        Err(format!(
            "rc {} (want {want})\nstdout: {:?}\nstderr: {:?}",
            done.rc, done.stdout, done.stderr
        ))
    }
}

fn expect_stdout(done: &Done, want: &str) -> Result<(), String> {
    if done.stdout == want {
        Ok(())
    } else {
        Err(format!("stdout {:?} (want {want:?})", done.stdout))
    }
}

fn expect_stderr(done: &Done, want: &str) -> Result<(), String> {
    if done.stderr == want {
        Ok(())
    } else {
        Err(format!("stderr {:?} (want {want:?})", done.stderr))
    }
}

/// The Debug form of a path, as gc prints it (`removed "<path>"`).
fn quoted(p: &Path) -> String {
    format!("{p:?}")
}

fn userns_available() -> bool {
    let mut cmd = Command::new(std::env::current_exe().expect("current exe"));
    cmd.env(ROLE_ENV, "probe-userns")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    matches!(cmd.status(), Ok(st) if st.success())
}

// ---- scenarios ------------------------------------------------------------------

/// AC1: symlinks inside a session and a symlink in ROOT are never followed.
fn ac1_symlinks_not_followed() -> Result<(), String> {
    let s = Scratch::new("ac1");
    let root = s.root();
    let outside = s.0.join("outside");
    mkdirs(&outside);
    fs::write(outside.join("canary"), b"keep").map_err(|e| e.to_string())?;
    let sess = session(&root, OsStr::new("s"), DAY * 2);
    let work = sess.join("work");
    mkdirs(&work);
    symlink(&outside, work.join("l")).map_err(|e| e.to_string())?;
    symlink("/", work.join("root")).map_err(|e| e.to_string())?;
    backdate(&sess, DAY * 2).map_err(|e| e.to_string())?;
    let outside2 = s.0.join("outside2");
    mkdirs(&outside2);
    create_lock(&outside2).map_err(|e| e.to_string())?;
    backdate(&outside2, DAY * 9).map_err(|e| e.to_string())?;
    symlink(&outside2, root.join("evil")).map_err(|e| e.to_string())?;

    let done = gc_1d(&root)?;
    expect_rc(&done, 0)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&root.join("s"))))?;
    if fs::read(outside.join("canary")).map_err(|e| e.to_string())? != b"keep" {
        return Err("canary behind a symlink was modified".into());
    }
    if !outside2.join("sbx.lock").exists() {
        return Err("a symlinked ROOT entry was followed".into());
    }
    Ok(())
}

/// AC2: a session whose lock a live run holds is kept, silently; after the
/// release the next gc removes it.
fn ac2_locked_session_kept() -> Result<(), String> {
    let s = Scratch::new("ac2");
    let root = s.root();
    let sess = session(&root, OsStr::new("s"), DAY * 2);
    let held = hold(&sess.join("sbx.lock"));
    let done = gc_1d(&root)?;
    expect_rc(&done, 0)?;
    if !(done.stdout.is_empty() && done.stderr.is_empty()) {
        return Err(format!(
            "locked session must be silent: stdout {:?} stderr {:?}",
            done.stdout, done.stderr
        ));
    }
    if !sess.join("sbx.lock").exists() {
        return Err("locked session was touched".into());
    }
    drop(held);
    let done = gc_1d(&root)?;
    expect_rc(&done, 0)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&root.join("s"))))
}

/// AC3: old and young sessions, a lockless old directory and a file. Dry run
/// names the three old sessions and changes nothing; the real run removes
/// exactly those and leaves no tombstone.
fn ac3_old_new_mix_dry_run() -> Result<(), String> {
    let s = Scratch::new("ac3");
    let root = s.root();
    for name in ["a", "b", "c"] {
        session(&root, OsStr::new(name), DAY * 3);
    }
    for name in ["d", "e"] {
        session(&root, OsStr::new(name), Duration::from_secs(3600));
    }
    let lockless = root.join("f");
    mkdirs(&lockless);
    backdate(&lockless, DAY * 3).map_err(|e| e.to_string())?;
    fs::write(root.join("g"), b"x").map_err(|e| e.to_string())?;

    let dry = gc(&root, "1d", true)?;
    expect_rc(&dry, 0)?;
    let want_dry: String = ["a", "b", "c"]
        .iter()
        .map(|n| format!("would remove {}\n", quoted(&root.join(n))))
        .collect();
    expect_stdout(&dry, &want_dry)?;
    if names_in(&root) != ["a", "b", "c", "d", "e", "f", "g"] {
        return Err(format!("dry run changed ROOT: {:?}", names_in(&root)));
    }

    let real = gc_1d(&root)?;
    expect_rc(&real, 0)?;
    let want_real: String = ["a", "b", "c"]
        .iter()
        .map(|n| format!("removed {}\n", quoted(&root.join(n))))
        .collect();
    expect_stdout(&real, &want_real)?;
    let left = names_in(&root);
    if left != ["d", "e", "f", "g"] {
        return Err(format!("after the real run ROOT holds {left:?}"));
    }
    if lockless.join("sbx.lock").exists() {
        return Err("gc created a lock in a lockless directory".into());
    }
    Ok(())
}

/// A failing session (Q14: group-writable) is reported and left, and the
/// sessions after it are still removed (Q8).
fn partial_failure_continues() -> Result<(), String> {
    let s = Scratch::new("partial");
    let root = s.root();
    let a = session(&root, OsStr::new("a"), DAY * 2);
    fs::set_permissions(&a, fs::Permissions::from_mode(0o770)).map_err(|e| e.to_string())?;
    backdate(&a, DAY * 2).map_err(|e| e.to_string())?;
    session(&root, OsStr::new("b"), DAY * 2);

    let done = gc_1d(&root)?;
    expect_rc(&done, 1)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&root.join("b"))))?;
    expect_stderr(
        &done,
        &format!(
            "sbx gc: {}: session directory is group- or world-writable (mode 770); left in place\n",
            quoted(&root.join("a"))
        ),
    )?;
    if !a.join("sbx.lock").exists() {
        return Err("the group-writable session was touched".into());
    }
    Ok(())
}

/// A tombstone left by an interrupted gc is collected on the next run, even
/// though it is young (Q5).
fn leftover_tombstone_collected() -> Result<(), String> {
    let s = Scratch::new("tomb");
    let root = s.root();
    let tomb = root.join(".sbx-gc.42.00000000deadbeef");
    mkdirs(&tomb.join("inner"));
    fs::write(tomb.join("inner/file"), b"x").map_err(|e| e.to_string())?;
    let done = gc_1d(&root)?;
    expect_rc(&done, 0)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&tomb)))?;
    if tomb.exists() {
        return Err("the tombstone survived".into());
    }
    Ok(())
}

/// A 3000-deep chain plus mode-000 directories, with RLIMIT_NOFILE=32: the
/// walker hoists instead of running out of fds.
fn deep_tree_rlimit_32() -> Result<(), String> {
    let s = Scratch::new("deep");
    let root = s.root();
    let sess = session(&root, OsStr::new("s"), DAY * 2);
    build_chain(&sess, 3000)?;
    // z/y is built first, so both chmods have search permission on their path.
    let z = sess.join("z");
    mkdirs(&z.join("y"));
    fs::write(z.join("y/file"), b"x").map_err(|e| e.to_string())?;
    fs::set_permissions(z.join("y"), fs::Permissions::from_mode(0o000))
        .map_err(|e| e.to_string())?;
    fs::set_permissions(&z, fs::Permissions::from_mode(0o000)).map_err(|e| e.to_string())?;
    backdate(&sess, DAY * 2).map_err(|e| e.to_string())?;

    let args: Vec<OsString> = vec![
        "gc".into(),
        "--older-than".into(),
        "1d".into(),
        root.as_os_str().to_owned(),
    ];
    let done = sbx(&args, Some(32))?;
    expect_rc(&done, 0)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&root.join("s"))))?;
    if names_in(&root) != Vec::<String>::new() {
        return Err(format!("ROOT is not empty: {:?}", names_in(&root)));
    }
    Ok(())
}

/// Builds `depth` nested `d` directories below `top` with `openat`, so the
/// path never exceeds PATH_MAX. A file every 500 levels.
fn build_chain(top: &Path, depth: usize) -> Result<(), String> {
    use std::os::fd::IntoRawFd;
    let c = cstr(top);
    // SAFETY: open of a NUL-terminated path; the fd is owned from here on.
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!("open {top:?}: {}", io::Error::last_os_error()));
    }
    let mut cur = unsafe { OwnedFd::from_raw_fd(raw) };
    for level in 0..depth {
        // SAFETY: mkdirat/openat on an fd we own with a static NUL-terminated name.
        let rc = unsafe { libc::mkdirat(cur.as_raw_fd(), c"d".as_ptr(), 0o700) };
        if rc != 0 {
            return Err(format!(
                "mkdirat at level {level}: {}",
                io::Error::last_os_error()
            ));
        }
        let next = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c"d".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(format!(
                "openat at level {level}: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: `next` is a fresh descriptor nothing else owns.
        cur = unsafe { OwnedFd::from_raw_fd(next) };
        if level % 500 == 0 {
            let f = unsafe {
                libc::openat(
                    cur.as_raw_fd(),
                    c"file".as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                )
            };
            if f < 0 {
                return Err(format!(
                    "file at level {level}: {}",
                    io::Error::last_os_error()
                ));
            }
            // SAFETY: `f` is a fresh descriptor; closing it here is its only owner.
            drop(unsafe { OwnedFd::from_raw_fd(f) });
        }
    }
    let _ = cur.into_raw_fd();
    Ok(())
}

/// A session name that is not UTF-8 is reported with the Debug form.
fn non_utf8_session_name() -> Result<(), String> {
    let s = Scratch::new("nonutf8");
    let root = s.root();
    let name = OsStr::from_bytes(b"s\xff");
    session(&root, name, DAY * 2);
    let done = gc_1d(&root)?;
    expect_rc(&done, 0)?;
    expect_stdout(&done, &format!("removed {}\n", quoted(&root.join(name))))?;
    if !names_in(&root).is_empty() {
        return Err(format!("ROOT not empty: {:?}", names_in(&root)));
    }
    Ok(())
}

/// Each refused ROOT is rc 1 with the pinned reason and no stdout; a zero
/// duration is a usage error (rc 2).
fn root_refusals() -> Result<(), String> {
    let s = Scratch::new("refuse");
    let base = s.0.clone();
    let check = |p: &Path, reason: &str| -> Result<(), String> {
        let done = gc_1d(p)?;
        expect_rc(&done, 1)?;
        if !done.stdout.is_empty() {
            return Err(format!("refused ROOT printed stdout: {:?}", done.stdout));
        }
        expect_stderr(&done, &format!("sbx gc: {}: {reason}\n", quoted(p)))
    };

    check(&base.join("missing"), "does not exist")?;

    let file = base.join("file");
    fs::write(&file, b"x").map_err(|e| e.to_string())?;
    check(&file, "is not a directory")?;

    let real = base.join("real");
    mkdirs(&real);
    let link = base.join("link");
    symlink(&real, &link).map_err(|e| e.to_string())?;
    check(&link, "is a symbolic link")?;
    check(
        &PathBuf::from(format!("{}/", link.display())),
        "is a symbolic link",
    )?;
    check(
        &PathBuf::from(format!("{}/.", link.display())),
        "is a symbolic link",
    )?;

    for host in ["/", "//", "/."] {
        check(Path::new(host), "refusing to collect the host root")?;
    }

    let wide = base.join("wide");
    mkdirs(&wide);
    fs::set_permissions(&wide, fs::Permissions::from_mode(0o777)).map_err(|e| e.to_string())?;
    check(
        &wide,
        "is group- or world-writable without the sticky bit (mode 777)",
    )?;

    let usage = sbx(
        &[
            "gc".into(),
            "--older-than".into(),
            "0s".into(),
            real.as_os_str().to_owned(),
        ],
        None,
    )?;
    expect_rc(&usage, 2)
}

/// Runs `mountns <mode> <root> <outside>` and returns its result.
fn mountns(mode: &str, root: &Path, outside: &Path) -> Result<Done, String> {
    let args: Vec<OsString> = vec![
        mode.into(),
        root.as_os_str().to_owned(),
        outside.as_os_str().to_owned(),
    ];
    let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.env(ROLE_ENV, "mountns").args(&args);
    run_child(cmd)
}

/// Runs a prepared role command with its output in files, bounded.
fn run_child(mut cmd: Command) -> Result<Done, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let id = N.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("sbx-gc-role-{}-{id}", std::process::id()));
    let (out_p, err_p) = (base.with_extension("out"), base.with_extension("err"));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(
            File::create(&out_p).map_err(|e| e.to_string())?,
        ))
        .stderr(Stdio::from(
            File::create(&err_p).map_err(|e| e.to_string())?,
        ));
    let mut child = cmd.spawn().map_err(|e| format!("spawn role: {e}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > BOUND => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("role exceeded its bound".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(format!("wait role: {e}")),
        }
    };
    let stdout = fs::read_to_string(&out_p).unwrap_or_default();
    let stderr = fs::read_to_string(&err_p).unwrap_or_default();
    let _ = fs::remove_file(&out_p);
    let _ = fs::remove_file(&err_p);
    Ok(Done {
        rc: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

/// Inside a user+mount namespace: a bind mount of an outside directory at
/// s1/work/b and a tmpfs at s2/work/t. gc refuses to descend into either, leaves
/// both tombstones, and the canary survives. After the namespace is gone,
/// a plain gc collects both tombstones.
fn mount_point_inside_session() -> Result<(), String> {
    mount_point_case("cross")
}

/// The same layout, gc run in-process with the name_to_handle_at fallback
/// forced (kernels < 5.8): the bind mount is still detected, by mount id.
fn mount_point_fallback_mount_id() -> Result<(), String> {
    mount_point_case("inproc-cross")
}

fn mount_point_case(mode: &str) -> Result<(), String> {
    let s = Scratch::new("mountx");
    let root = s.root();
    let outside = s.0.join("outside");
    mkdirs(&outside);
    fs::write(outside.join("canary"), b"keep").map_err(|e| e.to_string())?;
    for name in ["s1", "s2"] {
        let sess = session(&root, OsStr::new(name), DAY * 2);
        mkdirs(&sess.join("work"));
        mkdirs(&sess.join("work").join(if name == "s1" { "b" } else { "t" }));
        backdate(&sess, DAY * 2).map_err(|e| e.to_string())?;
    }
    let inside = mountns(mode, &root, &outside)?;
    expect_rc(&inside, 1)?;
    if !inside.stdout.is_empty() {
        return Err(format!("unexpected stdout: {:?}", inside.stdout));
    }
    let tomb_prefix = format!("{}/.sbx-gc.", root.display());
    for (name, at) in [("s1", "work/b"), ("s2", "work/t")] {
        let want = format!(
            "sbx gc: {}: mount point at {:?}; not descending; remainder left at \"{tomb_prefix}",
            quoted(&root.join(name)),
            at
        );
        if !inside.stderr.contains(&want) {
            return Err(format!("stderr lacks {want:?}: {:?}", inside.stderr));
        }
    }
    if fs::read(outside.join("canary")).map_err(|e| e.to_string())? != b"keep" {
        return Err("the bind-mounted outside tree was modified".into());
    }
    let tombs = names_in(&root);
    if tombs.len() != 2 || !tombs.iter().all(|n| n.starts_with(".sbx-gc.")) {
        return Err(format!("expected two tombstones, found {tombs:?}"));
    }

    let after = gc_1d(&root)?;
    expect_rc(&after, 0)?;
    let removed: Vec<&str> = after.stdout.lines().collect();
    if removed.len() != 2
        || !removed
            .iter()
            .all(|l| l.starts_with("removed \"") && l.contains("/.sbx-gc."))
    {
        return Err(format!("plain gc output: {:?}", after.stdout));
    }
    if !names_in(&root).is_empty() {
        return Err(format!("ROOT not empty: {:?}", names_in(&root)));
    }
    Ok(())
}

/// A tmpfs mounted over the session directory, with a backdated lock inside:
/// the mount root is refused (rc 1, pinned reason).
fn session_dir_is_mount_point() -> Result<(), String> {
    let s = Scratch::new("mountroot");
    let root = s.root();
    mkdirs(&root.join("s"));
    let done = mountns("session", &root, &s.0)?;
    expect_rc(&done, 1)?;
    expect_stderr(
        &done,
        &format!(
            "sbx gc: {}: session directory is a mount point; left in place\n",
            quoted(&root.join("s"))
        ),
    )?;
    if !done.stdout.is_empty() {
        return Err(format!("unexpected stdout: {:?}", done.stdout));
    }
    Ok(())
}

/// m1: eight gc processes at once on the same lockless tombstone. Exactly one
/// may report the removal, every process exits 0 silently otherwise, and the
/// tombstone is gone afterwards. Repeated for several rounds.
fn parallel_gc_lockless_tombstone() -> Result<(), String> {
    let s = Scratch::new("parallel");
    let root = s.root();
    for round in 0..5u32 {
        let tomb = root.join(format!(".sbx-gc.{}.0123456789abcdef", 100 + round));
        mkdirs(&tomb.join("a/b"));
        fs::write(tomb.join("a/b/file"), b"x").map_err(|e| e.to_string())?;
        fs::write(tomb.join("top"), b"x").map_err(|e| e.to_string())?;
        let mut children = Vec::new();
        for _ in 0..8 {
            children.push(
                Command::new(SBX)
                    .args(["gc", "--older-than", "1d"])
                    .arg(&root)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| format!("spawn gc: {e}"))?,
            );
        }
        let mut removed_lines = Vec::new();
        for child in children {
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            if out.status.code() != Some(0) {
                return Err(format!(
                    "round {round}: a parallel gc exited {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            if !out.stderr.is_empty() {
                return Err(format!(
                    "round {round}: parallel gc stderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            removed_lines.extend(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(str::to_owned),
            );
        }
        let want = format!("removed {}", quoted(&tomb));
        if removed_lines != [want.clone()] {
            return Err(format!(
                "round {round}: expected exactly one `{want}`, got {removed_lines:?}"
            ));
        }
        if tomb.exists() {
            return Err(format!("round {round}: the tombstone survived"));
        }
    }
    if !names_in(&root).is_empty() {
        return Err(format!("ROOT not empty: {:?}", names_in(&root)));
    }
    Ok(())
}
