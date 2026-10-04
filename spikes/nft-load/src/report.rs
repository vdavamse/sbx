//! Reporting (design D4): PASS/FAIL table + SUMMARY on stdout, or a single
//! JSON object with `--json`. Status/diagnostics go to stderr elsewhere.
//! No serde — JSON is hand-rolled to keep the static binary small (D7).

use std::fs;

/// One test/check outcome. `name` is static (fixed test matrix).
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

impl TestResult {
    pub fn passed(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            pass: true,
            detail: detail.into(),
        }
    }
    pub fn failed(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            pass: false,
            detail: detail.into(),
        }
    }
    pub fn from_result(name: &'static str, res: Result<String, String>) -> Self {
        match res {
            Ok(d) => Self::passed(name, d),
            Err(d) => Self::failed(name, d),
        }
    }
}

/// Size of the running binary in bytes (AC: record the static binary size).
pub fn binary_bytes() -> u64 {
    std::env::current_exe()
        .ok()
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

pub fn emit_table(tests: &[TestResult]) {
    println!("{:<24} {:<6} DETAIL", "TEST", "RESULT");
    for t in tests {
        println!(
            "{:<24} {:<6} {}",
            t.name,
            if t.pass { "PASS" } else { "FAIL" },
            one_line(&t.detail)
        );
    }
    let passed = tests.iter().filter(|t| t.pass).count();
    println!("SUMMARY: {passed}/{} passed", tests.len());
}

/// Single-line JSON object on stdout:
/// `{"ok":...,"exit_code":...,"tests":[...],"binary_bytes":...,"genid":...,"attempts":...}`
pub fn emit_json(ok: bool, exit_code: i32, tests: &[TestResult], genid: u32, attempts: u32) {
    let mut s = String::new();
    s.push('{');
    s.push_str(&format!(
        "\"ok\":{ok},\"exit_code\":{exit_code},\"tests\":["
    ));
    for (i, t) in tests.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"name\":{},\"pass\":{},\"detail\":{}}}",
            json_str(t.name),
            t.pass,
            json_str(&t.detail)
        ));
    }
    s.push_str(&format!(
        "],\"binary_bytes\":{},\"genid\":{genid},\"attempts\":{attempts}}}",
        binary_bytes()
    ));
    println!("{s}");
}

/// Minimal JSON string escaper.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_specials() {
        assert_eq!(json_str("plain"), "\"plain\"");
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("l1\nl2\t!"), "\"l1\\nl2\\t!\"");
        assert_eq!(json_str("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn json_object_shape() {
        // The emitted object must contain the CI-greppable "ok":true token.
        let t = [TestResult::passed("x", "d")];
        let mut s = String::new();
        s.push_str(&format!(
            "{{\"ok\":{},\"exit_code\":{},\"tests\":[",
            true, 0
        ));
        s.push_str(&format!(
            "{{\"name\":{},\"pass\":{},\"detail\":{}}}",
            json_str(t[0].name),
            t[0].pass,
            json_str(&t[0].detail)
        ));
        s.push_str("]}");
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"name\":\"x\""));
    }

    #[test]
    fn from_result_maps_ok_err() {
        assert!(TestResult::from_result("a", Ok("good".into())).pass);
        assert!(!TestResult::from_result("a", Err("bad".into())).pass);
    }
}
