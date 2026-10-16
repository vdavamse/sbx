//! Renderers and exit code for the host report (issue #11, T1): the human
//! layout, the JSON document (version 1), the stderr reason lines and the rc.

use std::fmt::Write as _;

use super::{EffectiveMode, Report, Status};

/// Continuation indent of the item rows: 2 + 4 (status) + 2 + 10 (id) + 2.
const ROW_INDENT: usize = 20;
/// Continuation indent of the policy rows (id column 12 wide).
const POLICY_INDENT: usize = 22;

/// The human report (the default `sbx check` output).
pub fn render_human(r: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "sbx {} host check (kernel {})",
        r.sbx_version, r.kernel
    );
    out.push('\n');
    for cap in &r.capabilities {
        let _ = writeln!(
            out,
            "  {:<4}  {:<10}  {}",
            cap.status.label(),
            cap.id.as_str(),
            cap.detail
        );
        if matches!(cap.status, Status::Fail | Status::Warn) {
            if let Some(evidence) = &cap.evidence {
                let _ = writeln!(
                    out,
                    "{:indent$}evidence: {evidence}",
                    "",
                    indent = ROW_INDENT
                );
            }
            if let Some(fix) = &cap.fix {
                let _ = writeln!(out, "{:indent$}fix: {fix}", "", indent = ROW_INDENT);
            }
        }
    }
    out.push('\n');
    let _ = writeln!(out, "{}", mode_line(r.network_mode));
    if let Some(err) = &r.probe_error {
        let _ = writeln!(out, "probe error: {err}");
    }
    if let Some(policy) = &r.policy {
        out.push('\n');
        let _ = writeln!(
            out,
            "policy {} (requires {}):",
            policy.path,
            policy_mode_word(policy.required)
        );
        for item in &policy.checks {
            let _ = writeln!(
                out,
                "  {:<4}  {:<12}  {}",
                item.status.label(),
                item.id,
                item.detail
            );
            if item.status == Status::Fail {
                if let Some(fix) = &item.fix {
                    let _ = writeln!(out, "{:indent$}fix: {fix}", "", indent = POLICY_INDENT);
                }
            }
        }
        out.push('\n');
        let _ = writeln!(
            out,
            "policy: {}",
            if policy.runnable {
                "can run on this host"
            } else {
                "cannot run on this host"
            }
        );
    }
    out
}

fn policy_mode_word(mode: crate::policy::NetworkMode) -> &'static str {
    match mode {
        crate::policy::NetworkMode::Transparent => "transparent",
        crate::policy::NetworkMode::Explicit => "explicit",
        crate::policy::NetworkMode::None => "none",
    }
}

/// The pinned mode line of the human report.
fn mode_line(mode: EffectiveMode) -> &'static str {
    match mode {
        EffectiveMode::Transparent => {
            "network mode: transparent (policies with network mode transparent, explicit or none can run)"
        }
        EffectiveMode::Explicit => {
            "network mode: explicit (policies with network mode explicit or none can run; transparent needs the nft item fixed)"
        }
        EffectiveMode::Unavailable => {
            "network mode: unavailable (no policy can run until the failed items are fixed)"
        }
    }
}

/// The JSON report: pretty-printed, trailing newline.
pub fn render_json(r: &Report) -> String {
    let mut text = serde_json::to_string_pretty(r).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

/// The stderr reason lines, in order (pinned): the probe failure; the
/// unavailable line listing the failed items with unavailable impact (only
/// without a probe error); then one `sbx check: <detail>` per failing policy
/// item. An explicit-only host prints nothing.
pub fn stderr_lines(r: &Report) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(err) = &r.probe_error {
        lines.push(format!("sbx check: the namespace probe failed: {err}"));
    } else if r.network_mode == EffectiveMode::Unavailable {
        let ids: Vec<&str> = r
            .capabilities
            .iter()
            .filter(|c| c.status == Status::Fail && c.impact == Some(EffectiveMode::Unavailable))
            .map(|c| c.id.as_str())
            .collect();
        lines.push(format!(
            "sbx check: this host cannot run sandboxes ({} failed)",
            ids.join(", ")
        ));
    }
    if let Some(policy) = &r.policy {
        for item in policy.checks.iter().filter(|c| c.status == Status::Fail) {
            lines.push(format!("sbx check: {}", item.detail));
        }
    }
    lines
}

/// The exit code of the probing forms: 1 when the host is unavailable, the
/// probe failed, or a checked policy does not run here; otherwise 0.
pub fn exit_code(r: &Report) -> u8 {
    let policy_bad = r.policy.as_ref().is_some_and(|p| !p.runnable);
    if r.probe_error.is_some() || r.network_mode == EffectiveMode::Unavailable || policy_bad {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::classify::assemble;
    use crate::host::facts::{ProbeOutcome, RunFacts};
    use crate::host::test_support::*;
    use crate::host::{CapId, EffectiveMode};
    use crate::init::probe::StepStatus;

    const H1: &str = r#"sbx 0.1.0 host check (kernel 6.8.0-test)

  ok    userns      unprivileged user + network namespaces work
  ok    netns       sandbox loopback network configured
  ok    netns-ipv6  IPv6 disabled inside the sandbox network namespace
  ok    nft         nftables NAT redirect loaded and verified
  ok    fallback    default route removable for explicit mode
  ok    bwrap       bubblewrap 0.9.0 at /usr/bin/bwrap
  ok    bwrap-run   bwrap starts a sandbox inside the sbx namespaces
  ok    bwrap-proc  bwrap mounts a fresh /proc
  ok    seccomp     bwrap installs sbx's socket-family filter (installation only; denials not probed)
  ok    landlock    Landlock ABI 4 (report-only)

network mode: transparent (policies with network mode transparent, explicit or none can run)
"#;
    const H3: &str = r#"sbx 0.1.0 host check (kernel 6.8.0-test)

  FAIL  userns      no user namespace can be created here: the limit is exhausted or nesting is forbidden (ENOSPC; for example inside bwrap --disable-userns)
                    evidence: unshare: unshare failed: No space left on device (os error 28)
                    fix: run sbx outside sandboxes that forbid nested user namespaces, or raise user.max_user_namespaces
  skip  netns       not probed: user namespaces are unavailable
  skip  netns-ipv6  not probed: user namespaces are unavailable
  skip  nft         not probed: user namespaces are unavailable
  skip  fallback    not probed: user namespaces are unavailable
  ok    bwrap       bubblewrap 0.9.0 at /usr/bin/bwrap
  skip  bwrap-run   not probed: user namespaces are unavailable
  skip  bwrap-proc  not probed: user namespaces are unavailable
  skip  seccomp     not probed: user namespaces are unavailable
  ok    landlock    Landlock ABI 4 (report-only)

network mode: unavailable (no policy can run until the failed items are fixed)
"#;
    const H2_ROW: &str = r#"  FAIL  nft         nftables NAT redirect is unavailable (transparent mode needs it; explicit and none do not)
                    evidence: nft-load: batch failed (attempt 1/5, genid 1): No such file or directory (os error 2)
                    fix: load the nftables modules (sudo modprobe -a nf_tables nf_nat nft_chain_nat nft_redir nft_fib nft_fib_ipv4) or use network mode explicit
"#;
    const H2_MODE: &str = "network mode: explicit (policies with network mode explicit or none can run; transparent needs the nft item fixed)
";
    const J1: &str = r#"{
  "version": 1,
  "sbx_version": "0.1.0",
  "kernel": "6.8.0-test",
  "network_mode": "transparent",
  "runnable_modes": [
    "transparent",
    "explicit",
    "none"
  ],
  "probe_error": null,
  "capabilities": [
    {
      "id": "userns",
      "status": "ok",
      "detail": "unprivileged user + network namespaces work",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "netns",
      "status": "ok",
      "detail": "sandbox loopback network configured",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "netns-ipv6",
      "status": "ok",
      "detail": "IPv6 disabled inside the sandbox network namespace",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "nft",
      "status": "ok",
      "detail": "nftables NAT redirect loaded and verified",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "fallback",
      "status": "ok",
      "detail": "default route removable for explicit mode",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "bwrap",
      "status": "ok",
      "detail": "bubblewrap 0.9.0 at /usr/bin/bwrap",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "bwrap-run",
      "status": "ok",
      "detail": "bwrap starts a sandbox inside the sbx namespaces",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "bwrap-proc",
      "status": "ok",
      "detail": "bwrap mounts a fresh /proc",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "seccomp",
      "status": "ok",
      "detail": "bwrap installs sbx's socket-family filter (installation only; denials not probed)",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    },
    {
      "id": "landlock",
      "status": "ok",
      "detail": "Landlock ABI 4 (report-only)",
      "evidence": null,
      "errno": null,
      "impact": null,
      "fix": null
    }
  ],
  "policy": null
}
"#;

    #[test]
    fn golden_h1_all_ok() {
        let r = assemble(&ok_host());
        assert_eq!(render_human(&r), H1);
        assert_eq!(stderr_lines(&r), Vec::<String>::new());
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn golden_h2_nft_load_failed() {
        let probe = ProbeOutcome::Ran(with_step(
            with_step(
                ok_steps(),
                "nft-load",
                StepStatus::Fail,
                Some(2),
                Some("batch failed (attempt 1/5, genid 1): No such file or directory (os error 2)"),
            ),
            "nft-verify",
            StepStatus::Skip,
            None,
            Some("skipped: nft-load failed"),
        ));
        let r = assemble(&host(probe, bwrap_ok(), RunFacts::default()));
        let text = render_human(&r);
        assert!(text.contains(H2_ROW), "{text}");
        assert!(text.ends_with(&format!("\n{H2_MODE}")), "{text}");
        assert_eq!(stderr_lines(&r), Vec::<String>::new());
        assert_eq!(exit_code(&r), 0, "explicit-only hosts exit 0");
    }

    #[test]
    fn golden_h3_nested_no_userns() {
        let mut steps = ok_steps();
        steps.steps[0].status = StepStatus::Fail;
        steps.steps[0].errno = Some(28);
        steps.steps[0].reason =
            Some("unshare failed: No space left on device (os error 28)".into());
        for step in steps.steps.iter_mut().skip(1) {
            step.status = StepStatus::Skip;
            step.reason = Some("skipped: unshare failed".into());
        }
        let run = RunFacts {
            sysctl: crate::host::facts::Sysctls {
                max_user_namespaces: Some(2147483647),
                ..Default::default()
            },
            seccomp: None,
        };
        let r = assemble(&host(ProbeOutcome::Ran(steps), bwrap_ok(), run));
        assert_eq!(render_human(&r), H3);
        assert_eq!(
            stderr_lines(&r),
            vec!["sbx check: this host cannot run sandboxes (userns failed)".to_owned()]
        );
        assert_eq!(exit_code(&r), 1);
        assert_eq!(r.network_mode, EffectiveMode::Unavailable);
    }

    #[test]
    fn golden_j1_json() {
        let r = assemble(&ok_host());
        assert_eq!(render_json(&r), J1);
    }

    #[test]
    fn policy_section_golden() {
        let mut r = assemble(&ok_host());
        let policy = crate::policy::Policy::from_json_str(
            r#"{"version":1,"filesystem":{"ro":["/usr"],"rw":[],"deny":[]},"network":{"mode":"transparent","allow":[],"ports":[]},"env":{"pass":[],"set":{}},"limits":{"timeout":"1s","output_bytes":1000}}"#,
        )
        .expect("policy");
        r.policy = Some(crate::host::classify::policy_check(
            "examples/p.json",
            &policy,
            EffectiveMode::Explicit,
            &|_| false,
            &|_| false,
        ));
        let text = render_human(&r);
        assert!(
            text.contains("\npolicy examples/p.json (requires transparent):\n"),
            "{text}"
        );
        assert!(text.contains("  FAIL  network-mode  policy requires network mode transparent but this host provides only explicit\n"), "{text}");
        assert!(
            text.ends_with("policy: cannot run on this host\n"),
            "{text}"
        );
        let json: serde_json::Value = serde_json::from_str(&render_json(&r)).expect("json");
        assert_eq!(json["policy"]["runnable"], serde_json::Value::Bool(false));
        assert_eq!(json["policy"]["required"], "transparent");
        assert_eq!(json["policy"]["checks"][0]["id"], "network-mode");
        assert_eq!(json["policy"]["checks"][3]["id"], "deny-paths");
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn stderr_lines_table() {
        let mut r = assemble(&ok_host());
        assert!(stderr_lines(&r).is_empty());
        r.probe_error = Some("timed out after 20s".into());
        r.network_mode = EffectiveMode::Unavailable;
        assert_eq!(
            stderr_lines(&r),
            vec!["sbx check: the namespace probe failed: timed out after 20s".to_owned()]
        );
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn exit_code_table() {
        let ok = assemble(&ok_host());
        assert_eq!(exit_code(&ok), 0);
        let mut unavailable = ok.clone();
        unavailable.network_mode = EffectiveMode::Unavailable;
        assert_eq!(exit_code(&unavailable), 1);
        let mut policy_bad = ok.clone();
        policy_bad.policy = Some(crate::host::PolicyCheck {
            path: "p".into(),
            required: crate::policy::NetworkMode::Transparent,
            runnable: false,
            checks: vec![],
        });
        assert_eq!(exit_code(&policy_bad), 1);
        let _ = CapId::ALL;
    }
}
