//! The conformance report model, renderers and exit code (issue #13, §5).
//!
//! Human layout, JSON version 1, the result line, the stderr reason lines and
//! the rc contract. Pinned by golden tests on a synthetic report.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::catalog::{self, CATALOG, CheckDef, GROUPS};
use crate::host::{EffectiveMode, Status};

/// Why a skip happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipKind {
    /// The host cannot provide what the check needs (counts toward rc 1).
    Capability,
    /// Opt-in: `--network` absent, a tool missing, or not selected (rc 0).
    OptIn,
    /// The check is not implemented in this build (counts toward rc 1).
    NotImplemented,
}

impl SkipKind {
    /// The reason-line prefix in the human layout.
    pub fn prefix(self) -> &'static str {
        match self {
            SkipKind::Capability => "capability: ",
            SkipKind::OptIn => "opt-in: ",
            SkipKind::NotImplemented => "not implemented: ",
        }
    }
}

/// Evidence lines are capped at this many lines of this many chars.
pub const EVIDENCE_LINES: usize = 8;
pub const EVIDENCE_CHARS: usize = 300;

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub status: Status,
    pub skip_kind: Option<SkipKind>,
    /// One line: the pass text, or the first failed assertion (no prefix).
    pub detail: String,
    pub evidence: Vec<String>,
    /// Remedy text; set for warn rows.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fix: Option<String>,
    pub scenario: Option<String>,
    pub scenario_ms: Option<u64>,
}

impl CheckResult {
    /// A result with the evidence capped to the pinned size.
    pub fn new(id: &str, status: Status, detail: impl Into<String>) -> Self {
        CheckResult {
            id: id.to_owned(),
            status,
            skip_kind: None,
            detail: one_line(&detail.into()),
            evidence: Vec::new(),
            fix: None,
            scenario: None,
            scenario_ms: None,
        }
    }

    /// A skip of `kind` with `detail`.
    pub fn skip(id: &str, kind: SkipKind, detail: impl Into<String>) -> Self {
        let mut r = CheckResult::new(id, Status::Skip, detail);
        r.skip_kind = Some(kind);
        r
    }

    /// Attach evidence, capped to [`EVIDENCE_LINES`] x [`EVIDENCE_CHARS`].
    pub fn with_evidence(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.evidence = lines
            .into_iter()
            .take(EVIDENCE_LINES)
            .map(|l| truncate(&one_line(&l), EVIDENCE_CHARS))
            .collect();
        self
    }
}

/// Collapse a detail to one line.
pub fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let kept: String = text.chars().take(max.saturating_sub(3)).collect();
    format!("{kept}...")
}

/// The lab tier's status in the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabStatus {
    /// `ok`, `unavailable` or `not-run`.
    pub status: &'static str,
    pub detail: Option<String>,
}

/// One check in the JSON document: catalog metadata plus the result.
#[derive(Serialize)]
pub struct ReportCheck<'a> {
    pub id: &'static str,
    pub group: &'static str,
    pub tier: &'static str,
    pub title: &'static str,
    #[serde(flatten)]
    pub result: &'a CheckResult,
}

/// Totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub total: usize,
    pub ok: usize,
    pub fail: usize,
    pub warn: usize,
    pub skip: usize,
    pub capability_skips: usize,
    pub opt_in_skips: usize,
    pub not_implemented: usize,
    pub not_selected: usize,
    pub conformant: bool,
    pub duration_ms: u64,
}

/// The whole conformance report (JSON version 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub sbx_version: &'static str,
    pub kernel: String,
    pub network_mode: EffectiveMode,
    pub lab: LabStatus,
    pub network_requested: bool,
    pub only: Option<Vec<String>>,
    /// One entry per catalog check, in catalog order.
    pub results: Vec<CheckResult>,
    pub duration_ms: u64,
}

/// The JSON report version.
pub const REPORT_VERSION: u32 = 1;

impl Report {
    /// Totals over the catalog.
    pub fn summary(&self) -> Summary {
        let mut s = Summary {
            total: self.results.len(),
            ok: 0,
            fail: 0,
            warn: 0,
            skip: 0,
            capability_skips: 0,
            opt_in_skips: 0,
            not_implemented: 0,
            not_selected: 0,
            conformant: false,
            duration_ms: self.duration_ms,
        };
        for r in &self.results {
            match r.status {
                Status::Ok => s.ok += 1,
                Status::Fail => s.fail += 1,
                Status::Warn => s.warn += 1,
                Status::Skip => {
                    s.skip += 1;
                    match r.skip_kind {
                        Some(SkipKind::Capability) => s.capability_skips += 1,
                        Some(SkipKind::NotImplemented) => s.not_implemented += 1,
                        _ => s.opt_in_skips += 1,
                    }
                }
            }
            if r.detail == NOT_SELECTED {
                s.not_selected += 1;
            }
        }
        s.conformant =
            s.fail == 0 && s.capability_skips == 0 && s.not_implemented == 0 && !self.nothing_ran();
        s
    }

    /// `--only` selected checks, and none of them could run (the opt-in E
    /// checks without `--network`): nothing was verified, which is not conformance.
    pub fn nothing_ran(&self) -> bool {
        self.only.is_some()
            && self.results.iter().any(|r| r.detail != NOT_SELECTED)
            && self
                .results
                .iter()
                .filter(|r| r.detail != NOT_SELECTED)
                .all(|r| r.status == Status::Skip && r.skip_kind == Some(SkipKind::OptIn))
    }

    /// The `result:` line (the first matching case wins).
    pub fn result_line(&self) -> String {
        let s = self.summary();
        if self.nothing_ran() {
            "result: nothing selected was runnable (add --network for E checks)".to_owned()
        } else if s.fail > 0 {
            format!("result: NOT conformant ({} FAIL)", s.fail)
        } else if s.capability_skips + s.not_implemented > 0 {
            format!(
                "result: incomplete ({} checks skipped: {} capability, {} not implemented)",
                s.capability_skips + s.not_implemented,
                s.capability_skips,
                s.not_implemented
            )
        } else if s.opt_in_skips > s.not_selected_count() {
            "result: conformant (opt-in skips only)".to_owned()
        } else {
            "result: conformant".to_owned()
        }
    }
}

impl Summary {
    fn not_selected_count(&self) -> usize {
        self.not_selected
    }
}

/// The detail of a check left out by `--only`.
pub const NOT_SELECTED: &str = "not selected (--only)";

/// The human report.
pub fn render_human(r: &Report) -> String {
    let s = r.summary();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "sbx {} conformance (kernel {}, network mode {}, lab {})",
        r.sbx_version,
        r.kernel,
        r.network_mode.as_str(),
        r.lab.status.replace("not-run", "not run")
    );
    let find = |id: &str| r.results.iter().find(|x| x.id == id);
    for group in GROUPS {
        let defs: Vec<&CheckDef> = catalog::group_checks(group).collect();
        let shown: Vec<&CheckDef> = defs
            .into_iter()
            .filter(|d| find(d.id).is_some_and(|x| x.detail != NOT_SELECTED))
            .collect();
        if shown.is_empty() {
            continue;
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "{}  {}", group.letter(), group.heading());
        for d in shown {
            let res = find(d.id).expect("catalog result");
            let label = res.status.label();
            let _ = writeln!(out, "  {label:<4}  {}  {}", d.id, d.title);
            let mut reason = res.detail.clone();
            if res.status == Status::Skip {
                if let Some(kind) = res.skip_kind {
                    reason = format!("{}{}", kind.prefix(), res.detail);
                }
            }
            if res.status != Status::Ok {
                let _ = writeln!(out, "             reason: {reason}");
            }
            if matches!(res.status, Status::Fail | Status::Warn) {
                for line in res.evidence.iter().take(3) {
                    let _ = writeln!(out, "             evidence: {line}");
                }
            }
            if res.status == Status::Warn {
                if let Some(fix) = &res.fix {
                    let _ = writeln!(out, "             fix: {fix}");
                }
            }
        }
    }
    let _ = writeln!(out);
    let selected = s.total - s.not_selected;
    let head = if s.not_selected > 0 {
        format!("{selected} checks ({} not selected)", s.not_selected)
    } else {
        format!("{} checks", s.total)
    };
    let skips = format!(
        "{} skip ({} opt-in, {} capability, {} not implemented)",
        s.skip, s.opt_in_skips, s.capability_skips, s.not_implemented
    );
    let _ = writeln!(
        out,
        "{head}: {} ok, {} FAIL, {} warn, {skips} in {:.1} s",
        s.ok,
        s.fail,
        s.warn,
        r.duration_ms as f64 / 1000.0
    );
    let _ = writeln!(out, "{}", r.result_line());
    out
}

/// The JSON report (`serde_json` pretty, final newline).
pub fn render_json(r: &Report) -> String {
    #[derive(Serialize)]
    struct Doc<'a> {
        kind: &'static str,
        version: u32,
        sbx_version: &'static str,
        kernel: &'a str,
        network_mode: EffectiveMode,
        lab: &'a LabStatus,
        network_requested: bool,
        only: &'a Option<Vec<String>>,
        checks: Vec<ReportCheck<'a>>,
        summary: Summary,
    }
    let checks: Vec<ReportCheck<'_>> = CATALOG
        .iter()
        .zip(r.results.iter())
        .map(|(d, res)| ReportCheck {
            id: d.id,
            group: d.group.key(),
            tier: d.tier.as_str(),
            title: d.title,
            result: res,
        })
        .collect();
    let doc = Doc {
        kind: "conformance",
        version: REPORT_VERSION,
        sbx_version: r.sbx_version,
        kernel: &r.kernel,
        network_mode: r.network_mode,
        lab: &r.lab,
        network_requested: r.network_requested,
        only: &r.only,
        checks,
        summary: r.summary(),
    };
    let mut text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

/// The stderr lines: one per FAIL, then the incomplete line when capability
/// or not-implemented skips exist.
pub fn stderr_lines(r: &Report) -> Vec<String> {
    let mut lines: Vec<String> = r
        .results
        .iter()
        .filter(|x| x.status == Status::Fail)
        .map(|x| format!("sbx check: conformance {} failed: {}", x.id, x.detail))
        .collect();
    let s = r.summary();
    if r.nothing_ran() {
        lines.push(
            "sbx check: conformance: no selected check was runnable (E checks need --network)"
                .to_owned(),
        );
    }
    if s.fail == 0 && (s.capability_skips + s.not_implemented) > 0 {
        let first = r
            .results
            .iter()
            .find(|x| x.status == Status::Skip && x.skip_kind != Some(SkipKind::OptIn))
            .map(|x| format!("{}: {}", x.id, x.detail))
            .unwrap_or_default();
        lines.push(format!(
            "sbx check: conformance incomplete: {} checks skipped for missing host capabilities, {} not implemented in this build (first: {first})",
            s.capability_skips, s.not_implemented
        ));
    }
    lines
}

/// The exit code: 1 on any FAIL or any capability/not-implemented skip, else 0.
pub fn exit_code(r: &Report) -> u8 {
    let s = r.summary();
    if s.fail > 0 || s.capability_skips + s.not_implemented > 0 || r.nothing_ran() {
        1
    } else {
        0
    }
}

/// `--list` (human): one line per check under the group headings.
pub fn render_list() -> String {
    let mut out = String::new();
    for group in GROUPS {
        let _ = writeln!(out, "{}  {}", group.letter(), group.heading());
        for d in catalog::group_checks(group) {
            let _ = writeln!(out, "  {}  {:<7}  {}", d.id, d.tier.as_str(), d.title);
        }
    }
    out
}

/// `--list --json`.
pub fn render_list_json() -> String {
    #[derive(Serialize)]
    struct Entry {
        id: &'static str,
        group: &'static str,
        tier: &'static str,
        title: &'static str,
        needs: Vec<String>,
    }
    #[derive(Serialize)]
    struct Doc {
        kind: &'static str,
        version: u32,
        checks: Vec<Entry>,
    }
    let doc = Doc {
        kind: "conformance-catalog",
        version: REPORT_VERSION,
        checks: CATALOG
            .iter()
            .map(|d| Entry {
                id: d.id,
                group: d.group.key(),
                tier: d.tier.as_str(),
                title: d.title,
                needs: d.needs.iter().map(|n| n.as_str()).collect(),
            })
            .collect(),
    };
    let mut text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(id: &str, status: Status) -> CheckResult {
        CheckResult::new(id, status, "pass text")
    }

    /// Synthetic 6-row golden used by the human-layout test.
    pub(crate) fn synthetic() -> Report {
        let mut results: Vec<CheckResult> = CATALOG
            .iter()
            .map(|d| CheckResult::skip(d.id, SkipKind::OptIn, NOT_SELECTED))
            .collect();
        let set = |results: &mut Vec<CheckResult>, r: CheckResult| {
            let i = results.iter().position(|x| x.id == r.id).unwrap();
            results[i] = r;
        };
        set(&mut results, res("A01", Status::Ok));
        set(
            &mut results,
            CheckResult::new(
                "A07",
                Status::Fail,
                "CONNECT other.conformance.test:443: expected 403, got 200",
            )
            .with_evidence(vec![
                "audit: {\"event\":\"connect\",\"host\":\"other.conformance.test\",...}".to_owned(),
            ]),
        );
        set(
            &mut results,
            CheckResult {
                fix: Some("socket files under ro/rw binds stay connectable (MS_RDONLY does not block connect); keep /run, /var/run and /tmp out of policies (#35)".to_owned()),
                ..CheckResult::new("D05", Status::Warn, "1 socket file visible: /usr/lib/x/agent.sock").with_evidence(vec![])
            },
        );
        set(
            &mut results,
            CheckResult::skip(
                "E01",
                SkipKind::OptIn,
                "network tier not requested (add --network)",
            ),
        );
        set(
            &mut results,
            CheckResult::skip(
                "F02",
                SkipKind::Capability,
                "lab unavailable: unshare: Operation not permitted (os error 1)",
            ),
        );
        set(
            &mut results,
            CheckResult::skip(
                "F03",
                SkipKind::NotImplemented,
                "lab tier lands in the second #13 PR",
            ),
        );
        Report {
            sbx_version: "0.1.0",
            kernel: "6.8.0-test".to_owned(),
            network_mode: EffectiveMode::Transparent,
            lab: LabStatus {
                status: "ok",
                detail: None,
            },
            network_requested: false,
            only: None,
            results,
            duration_ms: 4200,
        }
    }

    #[test]
    fn human_layout_golden() {
        let mut r = synthetic();
        r.results
            .retain(|x| x.detail != NOT_SELECTED || x.id == "A01");
        let expect = "\
sbx 0.1.0 conformance (kernel 6.8.0-test, network mode transparent, lab ok)

A  allow list
  ok    A01  allowed name gets an A record from 198.18.0.0/15
  FAIL  A07  non-allowed name: NXDOMAIN and CONNECT 403
             reason: CONNECT other.conformance.test:443: expected 403, got 200
             evidence: audit: {\"event\":\"connect\",\"host\":\"other.conformance.test\",...}

D  isolation
  warn  D05  no unix socket files are visible inside the sandbox
             reason: 1 socket file visible: /usr/lib/x/agent.sock
             fix: socket files under ro/rw binds stay connectable (MS_RDONLY does not block connect); keep /run, /var/run and /tmp out of policies (#35)

E  tooling (network tier)
  skip  E01  curl https://pypi.org/simple/six/ (transparent) returns 200
             reason: opt-in: network tier not requested (add --network)

F  fail-closed
  skip  F02  after SIGKILL the upstream sees no new connection
             reason: capability: lab unavailable: unshare: Operation not permitted (os error 1)
  skip  F03  with the proxy gone every egress path is refused
             reason: not implemented: lab tier lands in the second #13 PR

6 checks: 1 ok, 1 FAIL, 1 warn, 3 skip (1 opt-in, 1 capability, 1 not implemented) in 4.2 s
result: NOT conformant (1 FAIL)
";
        assert_eq!(render_human(&r), expect);
    }

    #[test]
    fn result_line_table() {
        let mut r = synthetic();
        assert_eq!(r.result_line(), "result: NOT conformant (1 FAIL)");
        r.results.retain(|x| x.status != Status::Fail);
        r.results
            .iter_mut()
            .filter(|x| x.status == Status::Fail)
            .for_each(|_| {});
        for x in r.results.iter_mut() {
            if x.status == Status::Warn {
                x.status = Status::Ok;
            }
        }
        assert_eq!(
            r.result_line(),
            "result: incomplete (2 checks skipped: 1 capability, 1 not implemented)"
        );
        let mut ok = synthetic();
        for x in ok.results.iter_mut() {
            if x.status != Status::Ok {
                *x = CheckResult::skip(&x.id.clone(), SkipKind::OptIn, NOT_SELECTED);
            }
        }
        assert_eq!(ok.result_line(), "result: conformant");
        ok.results[0] = CheckResult::skip("A01", SkipKind::OptIn, "network tier not requested");
        assert_eq!(ok.result_line(), "result: conformant (opt-in skips only)");
    }

    #[test]
    fn exit_code_table() {
        let mut r = synthetic();
        assert_eq!(exit_code(&r), 1);
        let mut only_opt = synthetic();
        only_opt.results.iter_mut().for_each(|x| {
            if x.status != Status::Ok {
                *x = CheckResult::skip(&x.id.clone(), SkipKind::OptIn, NOT_SELECTED);
            }
        });
        assert_eq!(exit_code(&only_opt), 0);
        r.results.retain(|x| x.id != "A07");
        assert_eq!(exit_code(&r), 1);
        let warn_only = {
            let mut w = synthetic();
            w.results
                .iter_mut()
                .filter(|x| x.status == Status::Fail || x.status == Status::Skip)
                .for_each(|x| {
                    *x = if x.id == "D05" {
                        x.clone()
                    } else {
                        CheckResult::skip(&x.id.clone(), SkipKind::OptIn, NOT_SELECTED)
                    };
                });
            w
        };
        assert_eq!(exit_code(&warn_only), 0, "warn does not fail");
    }

    #[test]
    fn stderr_lines_for_fail_and_incomplete() {
        let r = synthetic();
        let lines = stderr_lines(&r);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("sbx check: conformance A07 failed: CONNECT"));
    }

    #[test]
    fn list_json_has_69_rows() {
        let v: serde_json::Value = serde_json::from_str(&render_list_json()).unwrap();
        assert_eq!(v["checks"].as_array().unwrap().len(), 69);
        assert_eq!(v["kind"], "conformance-catalog");
    }

    #[test]
    fn json_top_keys_are_stable() {
        let r = synthetic();
        let v: serde_json::Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(v["kind"], "conformance");
        assert_eq!(v["version"], 1);
        assert_eq!(v["checks"].as_array().unwrap().len(), 69);
        assert_eq!(v["checks"][0]["id"], "A01");
        assert!(v["summary"]["conformant"] == false);
    }
}
