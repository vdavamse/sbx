//! Pure decisions of `sbx run` (issue #10, T1): timeout, env pass-through,
//! path normalisation, exit codes, signal names and the pinned reason texts.
//! Nothing here touches the process, the filesystem or the clock.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use super::{EXIT_FAILURE, EXIT_TIMEOUT, Outcome, RunError};
use crate::policy::Policy;

/// Q2: the effective timeout is the minimum of the CLI value and the policy's
/// `limits.timeout`; with no CLI value the policy value applies.
pub(crate) fn effective_timeout(cli: Option<Duration>, policy: Duration) -> Duration {
    match cli {
        Some(cli) => cli.min(policy),
        None => policy,
    }
}

/// Only `env.pass` names are forwarded; absent names are omitted; values keep
/// their exact bytes (non-UTF-8 included).
pub(crate) fn passed_env(
    policy: &Policy,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> BTreeMap<String, OsString> {
    policy
        .env
        .pass
        .iter()
        .filter_map(|name| lookup(name).map(|value| (name.clone(), value)))
        .collect()
}

/// Absolute spelling of `p` relative to the caller's cwd (no symlink
/// resolution; `std::path::absolute`, MSRV 1.79).
pub(crate) fn absolutize(p: &Path) -> Result<PathBuf, RunError> {
    std::path::absolute(p).map_err(|err| RunError::new(format!("cannot resolve path {p:?}: {err}")))
}

/// Lexical normalisation: drop `.`, pop on `..` (never above `/`). Symlinks
/// are NOT resolved — this is the documented lexical contract (Q8).
pub(crate) fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop a normal segment; at the root `..` stays at the root.
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            Component::Normal(name) => out.push(name),
        }
    }
    out
}

/// Q8: the audit file must not live inside the session directory. Component-
/// wise comparison after normalisation (so `/s1` is not inside `/s10`).
pub(crate) fn audit_inside_session(audit_abs: &Path, session_abs: &Path) -> bool {
    lexical_normalize(audit_abs).starts_with(lexical_normalize(session_abs))
}

/// The process exit code for an outcome (§6). A signalled payload already
/// arrives as 128+N from bwrap (E6); sbx's own signal exits follow the same
/// convention.
pub(crate) fn exit_code(o: &Outcome) -> i32 {
    match o {
        Outcome::Exited(code) => *code,
        Outcome::Signaled(sig) | Outcome::Terminated(sig) => 128 + sig,
        Outcome::TimedOut(_) => EXIT_TIMEOUT,
        Outcome::Failed(_) => EXIT_FAILURE,
    }
}

/// Symbolic names for the signals `sbx run` can report (§6 / Q5 set plus the
/// fatal signals bwrap can relay).
pub(crate) fn signal_name(sig: i32) -> Option<&'static str> {
    Some(match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        7 => "SIGBUS",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => return None,
    })
}

fn named_signal(sig: i32) -> String {
    match signal_name(sig) {
        Some(name) => name.to_owned(),
        None => format!("signal {sig}"),
    }
}

/// The exit-row `reason` and the stderr diagnostic text (pinned, §6).
pub(crate) fn exit_reason(o: &Outcome) -> String {
    match o {
        Outcome::Exited(code) => format!("command exited with status {code}"),
        Outcome::Signaled(sig) => {
            let name = signal_name(*sig)
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            format!("sandbox killed by signal {sig}{name}")
        }
        Outcome::TimedOut(limit) => {
            format!("timed out after {}", humantime::format_duration(*limit))
        }
        Outcome::Terminated(sig) => format!("terminated by {}", named_signal(*sig)),
        Outcome::Failed(reason) => reason.clone(),
    }
}

/// The `sbx run: …` stderr line; `None` for a command that exited normally
/// (sbx stays silent so the caller sees only the command's own output).
pub(crate) fn sbx_diagnostic(o: &Outcome) -> Option<String> {
    match o {
        Outcome::Exited(_) => None,
        other => Some(format!("sbx run: {}", exit_reason(other))),
    }
}

/// The audit `outcome` label.
pub(crate) fn outcome_label(o: &Outcome) -> &'static str {
    match o {
        Outcome::Exited(_) => "exited",
        Outcome::Signaled(_) => "signaled",
        Outcome::TimedOut(_) => "timeout",
        Outcome::Terminated(_) => "terminated",
        Outcome::Failed(_) => "failed",
    }
}

/// The audit `signal` field: the signal number for signalled/terminated runs.
pub(crate) fn outcome_signal(o: &Outcome) -> Option<i32> {
    match o {
        Outcome::Signaled(sig) | Outcome::Terminated(sig) => Some(*sig),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_timeout_policy_only() {
        assert_eq!(
            effective_timeout(None, Duration::from_secs(120)),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn effective_timeout_takes_minimum() {
        let a = Duration::from_secs(60);
        let b = Duration::from_secs(1);
        assert_eq!(effective_timeout(Some(a), b), b); // policy smaller
        assert_eq!(effective_timeout(Some(b), a), b); // CLI smaller
        assert_eq!(effective_timeout(Some(a), a), a); // equal
    }

    #[test]
    fn passed_env_only_policy_names_absent_omitted_bytes_verbatim() {
        use std::os::unix::ffi::OsStringExt;
        let policy = Policy::from_json_str(
            r#"{"version":1,"filesystem":{"ro":[],"rw":[],"deny":[]},
                "network":{"mode":"none","allow":[],"ports":[]},
                "env":{"pass":["KEEP","ABSENT","RAW"],"set":{}},
                "limits":{"timeout":"1s","output_bytes":1000}}"#,
        )
        .expect("policy parses");
        let raw = OsString::from_vec(b"v\xffal".to_vec());
        let env = passed_env(&policy, |name| match name {
            "KEEP" => Some(OsString::from("yes")),
            "RAW" => Some(raw.clone()),
            "NOT_IN_POLICY" => Some(OsString::from("leak")),
            _ => None,
        });
        let mut expected = BTreeMap::new();
        expected.insert("KEEP".to_owned(), OsString::from("yes"));
        expected.insert("RAW".to_owned(), raw);
        assert_eq!(env, expected);
    }

    #[test]
    fn lexical_normalize_table() {
        let cases = [
            ("/a/b/../c", "/a/c"),
            ("/a/./b", "/a/b"),
            ("/../x", "/x"),
            ("/", "/"),
            ("/a/b/..", "/a"),
            ("/a//b/", "/a/b"),
        ];
        for (input, want) in cases {
            assert_eq!(
                lexical_normalize(Path::new(input)),
                Path::new(want),
                "{input}"
            );
        }
    }

    #[test]
    fn audit_inside_session_table() {
        let s = Path::new("/var/lib/sbx/s1");
        assert!(!audit_inside_session(Path::new("/var/lib/sbx/a.jsonl"), s));
        assert!(audit_inside_session(
            Path::new("/var/lib/sbx/s1/a.jsonl"),
            s
        ));
        assert!(audit_inside_session(Path::new("/var/lib/sbx/s1"), s)); // equal
        assert!(audit_inside_session(
            Path::new("/var/lib/sbx/s1/work/../a.jsonl"),
            s
        ));
        assert!(!audit_inside_session(
            Path::new("/var/lib/sbx/s1/../s10/a"),
            s
        ));
        assert!(!audit_inside_session(Path::new("/var/lib/sbx/s10/a"), s)); // /s1 vs /s10
        assert!(audit_inside_session(Path::new("/var/lib/sbx/./s1/./a"), s));
    }

    #[test]
    fn exit_code_table() {
        assert_eq!(exit_code(&Outcome::Exited(0)), 0);
        assert_eq!(exit_code(&Outcome::Exited(3)), 3);
        assert_eq!(exit_code(&Outcome::Exited(255)), 255);
        assert_eq!(exit_code(&Outcome::Signaled(9)), 137);
        assert_eq!(exit_code(&Outcome::TimedOut(Duration::from_secs(1))), 124);
        assert_eq!(exit_code(&Outcome::Terminated(2)), 130);
        assert_eq!(exit_code(&Outcome::Terminated(1)), 129);
        assert_eq!(exit_code(&Outcome::Terminated(3)), 131);
        assert_eq!(exit_code(&Outcome::Terminated(15)), 143);
        assert_eq!(exit_code(&Outcome::Failed("x".into())), 125);
    }

    #[test]
    fn signal_name_table() {
        assert_eq!(signal_name(1), Some("SIGHUP"));
        assert_eq!(signal_name(2), Some("SIGINT"));
        assert_eq!(signal_name(3), Some("SIGQUIT"));
        assert_eq!(signal_name(6), Some("SIGABRT"));
        assert_eq!(signal_name(7), Some("SIGBUS"));
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(11), Some("SIGSEGV"));
        assert_eq!(signal_name(13), Some("SIGPIPE"));
        assert_eq!(signal_name(15), Some("SIGTERM"));
        assert_eq!(signal_name(10), None);
    }

    #[test]
    fn exit_reason_pinned() {
        assert_eq!(
            exit_reason(&Outcome::Exited(0)),
            "command exited with status 0"
        );
        assert_eq!(
            exit_reason(&Outcome::Signaled(9)),
            "sandbox killed by signal 9 (SIGKILL)"
        );
        assert_eq!(
            exit_reason(&Outcome::Signaled(40)),
            "sandbox killed by signal 40"
        );
        assert_eq!(
            exit_reason(&Outcome::TimedOut(Duration::from_secs(120))),
            "timed out after 2m"
        );
        assert_eq!(
            exit_reason(&Outcome::Terminated(15)),
            "terminated by SIGTERM"
        );
        assert_eq!(
            exit_reason(&Outcome::Failed("network service failed: boom".into())),
            "network service failed: boom"
        );
    }

    #[test]
    fn sbx_diagnostic_pinned() {
        assert_eq!(sbx_diagnostic(&Outcome::Exited(7)), None);
        assert_eq!(
            sbx_diagnostic(&Outcome::TimedOut(Duration::from_secs(2))).as_deref(),
            Some("sbx run: timed out after 2s")
        );
        assert_eq!(
            sbx_diagnostic(&Outcome::Terminated(15)).as_deref(),
            Some("sbx run: terminated by SIGTERM")
        );
        assert_eq!(
            sbx_diagnostic(&Outcome::Failed("bwrap not found".into())).as_deref(),
            Some("sbx run: bwrap not found")
        );
    }

    #[test]
    fn outcome_label_and_signal_table() {
        assert_eq!(outcome_label(&Outcome::Exited(0)), "exited");
        assert_eq!(outcome_label(&Outcome::Signaled(9)), "signaled");
        assert_eq!(outcome_label(&Outcome::TimedOut(Duration::ZERO)), "timeout");
        assert_eq!(outcome_label(&Outcome::Terminated(2)), "terminated");
        assert_eq!(outcome_label(&Outcome::Failed(String::new())), "failed");
        assert_eq!(outcome_signal(&Outcome::Terminated(15)), Some(15));
        assert_eq!(outcome_signal(&Outcome::Signaled(9)), Some(9));
        assert_eq!(outcome_signal(&Outcome::Exited(1)), None);
        assert_eq!(outcome_signal(&Outcome::Failed(String::new())), None);
    }
}
