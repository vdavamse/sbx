//! Telling "bwrap could not exec the command" apart from "the command exited 1"
//! (issue #74).
//!
//! 1. **The problem.** bwrap `execvp`s the command itself. When that fails it
//!    prints `bwrap: execvp CMD: <strerror>` and exits 1 (`die_with_error`), so
//!    by rc alone a missing command reads like a command that ran and exited 1.
//! 2. **The signal (every supported version, ≥ 0.8).** `run` and
//!    every attach pass a pipe as `--json-status-fd`. bwrap's monitor writes
//!    `{ "child-pid": … }` there after clone, and `{ "exit-code": N }` at exit
//!    only when its exec of the command succeeded: pid 2 writes one byte to an
//!    `O_CLOEXEC` pipe right before `execvp` and a second one when `execvp`
//!    fails, and the monitor reports the exit code only when it reads exactly
//!    one (`report_child_exit_status`, bubblewrap.c v0.8.0 through v0.13.1). A
//!    command that runs always gets its `exit-code` line, whatever it prints or
//!    returns, so the payload cannot fake an exec failure.
//! 3. **What the signal does not say.** bwrap also omits `exit-code` when its
//!    own setup fails before the exec (a missing bind source, a bad `--chdir`),
//!    and it never reports the errno. Both come from bwrap's diagnostic: the
//!    last stderr line must be exactly `bwrap: execvp <argv0>: <message>`.
//!    bwrap runs with an empty environment and never calls `setlocale`, so the
//!    message is the C locale's `strerror` text. `No such file or directory`
//!    (ENOENT) is 127; any other message (EACCES for a directory or a file
//!    without the execute bit, ENOEXEC, ENOTDIR…) is 126, the POSIX shell
//!    convention.
//! 4. **Degrading.** Every condition must hold: the outcome is `Exited(1)`,
//!    the status pipe shows bwrap started the sandbox and reported no exit
//!    code, and the stderr line matches. Otherwise the outcome is unchanged,
//!    so an unexpected bwrap (other wording, no status) keeps the old rc 1 and
//!    `exited`, never a wrong 126 or 127.
//! 5. **With `--landlock`** bwrap execs the shim, and the shim execs the
//!    command and reports its errno through its own status pipe
//!    ([`crate::landlock`] module docs point 9); this module is not used.

use std::ffi::OsStr;
use std::os::fd::OwnedFd;

use super::Outcome;

/// The most of bwrap's stderr the pumps keep for [`classify`]: bwrap's
/// diagnostic is one line with the command name in it.
pub(crate) const STDERR_TAIL_BYTES: usize = 4096;

/// The most of the status pipe that is read: two short JSON objects.
const STATUS_MAX_BYTES: usize = 4096;

/// bwrap's `strerror(ENOENT)` in the C locale.
const ENOENT_TEXT: &str = "No such file or directory";

/// The exit code POSIX shells use for a command that is not found.
pub(crate) const EXIT_NOT_FOUND: i32 = 127;
/// The exit code POSIX shells use for a command found but not executable.
pub(crate) const EXIT_NOT_EXECUTABLE: i32 = 126;

/// What the status pipe says (module docs point 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Status {
    /// bwrap reported a `child-pid`: it got as far as cloning the sandbox.
    pub(crate) started: bool,
    /// bwrap reported an `exit-code`: its exec of the command succeeded.
    pub(crate) exit_reported: bool,
}

/// Decodes the status pipe's bytes: a stream of JSON objects. Pure. Anything
/// that is not an object, or does not parse, ends the scan with what was seen.
pub(crate) fn decode(bytes: &[u8]) -> Status {
    let mut status = Status {
        started: false,
        exit_reported: false,
    };
    for value in serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>() {
        let Ok(serde_json::Value::Object(map)) = value else {
            break;
        };
        status.started |= map.contains_key("child-pid");
        status.exit_reported |= map.contains_key("exit-code");
    }
    status
}

/// Reads the status pipe after teardown. bwrap is reaped by then, so the read
/// ends at EOF; a pipe something still holds ends at EAGAIN (the read end is
/// non-blocking) with what is there.
pub(crate) fn read(fd: &OwnedFd) -> Status {
    use std::io::Read;
    let mut bytes = Vec::new();
    if let Ok(clone) = fd.try_clone() {
        let mut file = std::fs::File::from(clone);
        let mut chunk = [0u8; 512];
        while bytes.len() < STATUS_MAX_BYTES {
            match file.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
        }
    }
    decode(&bytes)
}

/// The outcome after the exec status is known (module docs points 2 to 4).
/// `argv0` is the command bwrap exec'd (`None` when bwrap exec'd something
/// else, the Landlock shim); `stderr_tail` is the end of bwrap's stderr.
pub(crate) fn classify(
    outcome: Outcome,
    status: Option<Status>,
    stderr_tail: &[u8],
    argv0: Option<&OsStr>,
) -> Outcome {
    let (Outcome::Exited(1), Some(status), Some(argv0)) = (&outcome, status, argv0) else {
        return outcome;
    };
    if !status.started || status.exit_reported {
        return outcome;
    }
    let Some(message) = execvp_message(stderr_tail, argv0) else {
        return outcome;
    };
    let (code, reason) = exec_failure(argv0, message == ENOENT_TEXT, &message);
    Outcome::ExecFailed { code, reason }
}

/// The rc and reason of a command that could not be executed, shared with the
/// Landlock shim: 127 and `command not found in the sandbox: NAME` when it was
/// not found (ENOENT), otherwise 126 and `command not executable in the
/// sandbox: NAME (MESSAGE)`.
pub(crate) fn exec_failure(argv0: &OsStr, not_found: bool, message: &str) -> (i32, String) {
    let name = argv0.to_string_lossy();
    if not_found {
        (
            EXIT_NOT_FOUND,
            format!("command not found in the sandbox: {name}"),
        )
    } else {
        (
            EXIT_NOT_EXECUTABLE,
            format!("command not executable in the sandbox: {name} ({message})"),
        )
    }
}

/// The `<message>` when the stderr tail ends with the line
/// `bwrap: execvp <argv0>: <message>\n` (at the start of the tail or after a
/// newline), or `None`. The message is one line; the name is matched as bytes,
/// so a name with a newline in it still matches.
fn execvp_message(stderr_tail: &[u8], argv0: &OsStr) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let text = stderr_tail.strip_suffix(b"\n")?;
    let mut head = b"bwrap: execvp ".to_vec();
    head.extend_from_slice(argv0.as_bytes());
    head.extend_from_slice(b": ");
    // The line starts at the tail's start or after a newline, and only the
    // message after the head must be free of newlines.
    let begin = text.len().checked_sub(head.len())?;
    let start = (0..=begin)
        .rev()
        .find(|&at| text[at..].starts_with(&head) && (at == 0 || text[at - 1] == b'\n'))?;
    let message = &text[start + head.len()..];
    if message.is_empty() || message.contains(&b'\n') {
        return None;
    }
    std::str::from_utf8(message).ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    const STARTED: Status = Status {
        started: true,
        exit_reported: false,
    };

    fn argv0(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn decode_reads_bwrap_status_streams() {
        // bwrap 0.9.0's real output for a failed exec and for a command that ran.
        let failed = b"{ \"child-pid\": 1888740, \"cgroup-namespace\": 4026532375, \"ipc-namespace\": 4026532373, \"mnt-namespace\": 4026532371, \"pid-namespace\": 4026532374, \"uts-namespace\": 4026532372 }\n";
        assert_eq!(decode(failed), STARTED);
        let ran = b"{ \"child-pid\": 1888758 }\n{ \"exit-code\": 1 }\n";
        assert_eq!(
            decode(ran),
            Status {
                started: true,
                exit_reported: true
            }
        );
        assert_eq!(
            decode(b""),
            Status {
                started: false,
                exit_reported: false
            }
        );
        // A torn stream keeps what parsed before the tear.
        assert_eq!(decode(b"{ \"child-pid\": 5 }\n{ \"exit-co"), STARTED);
        assert!(!decode(b"[1]{\"exit-code\":1}").started);
    }

    #[test]
    fn missing_command_is_127() {
        let out = classify(
            Outcome::Exited(1),
            Some(STARTED),
            b"bwrap: execvp no-such-cmd: No such file or directory\n",
            Some(&argv0("no-such-cmd")),
        );
        assert_eq!(
            out,
            Outcome::ExecFailed {
                code: 127,
                reason: "command not found in the sandbox: no-such-cmd".into()
            }
        );
    }

    #[test]
    fn non_executable_command_is_126() {
        let out = classify(
            Outcome::Exited(1),
            Some(STARTED),
            b"earlier output\nbwrap: execvp /work: Permission denied\n",
            Some(&argv0("/work")),
        );
        assert_eq!(
            out,
            Outcome::ExecFailed {
                code: 126,
                reason: "command not executable in the sandbox: /work (Permission denied)".into()
            }
        );
    }

    #[test]
    fn anything_short_of_every_condition_keeps_the_outcome() {
        let line: &[u8] = b"bwrap: execvp x: No such file or directory\n";
        let x = argv0("x");
        let reported = Status {
            started: true,
            exit_reported: true,
        };
        let not_started = Status {
            started: false,
            exit_reported: false,
        };
        type Case<'a> = (Outcome, Option<Status>, &'a [u8], Option<&'a OsStr>);
        let cases: [Case<'_>; 10] = [
            // The command ran: bwrap reported its exit code (a payload that
            // prints bwrap's line and exits 1 is not an exec failure).
            (Outcome::Exited(1), Some(reported), line, Some(&x)),
            // No status at all, or bwrap died before cloning.
            (Outcome::Exited(1), None, line, Some(&x)),
            (Outcome::Exited(1), Some(not_started), line, Some(&x)),
            // Another rc or outcome.
            (Outcome::Exited(127), Some(STARTED), line, Some(&x)),
            (
                Outcome::Failed("boom".into()),
                Some(STARTED),
                line,
                Some(&x),
            ),
            // The Landlock shim was exec'd, not the command.
            (Outcome::Exited(1), Some(STARTED), line, None),
            // A setup failure (no execvp line), another name, a torn line.
            (
                Outcome::Exited(1),
                Some(STARTED),
                b"bwrap: Can't chdir to /nope: No such file or directory\n",
                Some(&x),
            ),
            (Outcome::Exited(1), Some(STARTED), line, Some(&argv0("y"))),
            (
                Outcome::Exited(1),
                Some(STARTED),
                b"bwrap: execvp x: No such file or directory",
                Some(&x),
            ),
            // The execvp line is not the last one.
            (
                Outcome::Exited(1),
                Some(STARTED),
                b"bwrap: execvp x: No such file or directory\nmore\n",
                Some(&x),
            ),
        ];
        for (outcome, status, tail, name) in cases {
            let want = outcome.clone();
            assert_eq!(classify(outcome, status, tail, name), want, "{tail:?}");
        }
    }

    #[test]
    fn execvp_message_is_what_follows_the_exact_name() {
        // The name is matched as given, so a name with `: ` in it splits right.
        assert_eq!(
            execvp_message(b"bwrap: execvp x: y: Permission denied\n", OsStr::new("x")),
            Some("y: Permission denied".to_owned())
        );
        assert_eq!(
            execvp_message(
                b"bwrap: execvp x: y: Permission denied\n",
                OsStr::new("x: y")
            ),
            Some("Permission denied".to_owned())
        );
        assert_eq!(
            execvp_message(b"bwrap: execvp x: \n", OsStr::new("x")),
            None
        );
        // A name with a newline (review of #74): still the exact line.
        assert_eq!(
            execvp_message(
                b"out\nbwrap: execvp no\nsuch: No such file or directory\n",
                OsStr::new("no\nsuch")
            ),
            Some("No such file or directory".to_owned())
        );
        assert_eq!(
            execvp_message(b"bwrap: execvp x: a\nb\n", OsStr::new("x")),
            None
        );
    }
}
