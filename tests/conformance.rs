//! Integration suite for `sbx check --conformance` (issue #13) — the real
//! binary, the real host tier, the real probe.
//!
//! Why `harness = false`: the suite spawns `sbx run` inside real namespaces
//! and waits on process groups with bounded polls; libtest's threads would
//! make the wait bookkeeping (and the nested `unshare` of the probe's negative
//! controls) harder to reason about. The same reasoning as `sandbox_check`.
//!
//! Gates (SKIP-with-message, exit 0; any assertion failure exits 1):
//! * the report is produced and parsed (`kind`, `version`, 69 checks in
//!   catalog order, matching `--list --json`);
//! * no check FAILs; the rc matches `summary.conformant`;
//! * PR1 state: exactly the 19 lab checks are `not-implemented`; the E checks
//!   are `opt-in` (or `not-implemented` with `SBX_CONFORMANCE_NETWORK=1`);
//! * when the host cannot run sandboxes at all, the suite prints
//!   `SKIP conformance: host cannot run sandboxes` and exits 0.
//!
//! Plus fast CLI scenarios (`--list`, `--only`, usage errors, the hidden
//! probe on the host).

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const SBX: &str = env!("CARGO_BIN_EXE_sbx");
const PR1_NOT_IMPLEMENTED: [&str; 19] = [
    "A02", "A03", "A04", "A05", "A06", "A12", "B01", "B02", "B03", "B04", "B05", "B06", "B07",
    "B08", "B09", "C02", "C07", "F02", "F04",
];
const E_IDS: [&str; 6] = ["E01", "E02", "E03", "E04", "E05", "E06"];
const CATALOG_BOUND: Duration = Duration::from_secs(240);

fn main() -> std::process::ExitCode {
    let mut failures: Vec<String> = Vec::new();
    let mut run = |name: &str, res: Result<(), String>| match res {
        Ok(()) => println!("PASS {name}"),
        Err(e) => {
            println!("FAIL {name}: {e}");
            failures.push(name.to_owned());
        }
    };
    run("list", list_scenario());
    run("only-single-id", only_scenario());
    run("only-unknown-selector-rc2", only_unknown_scenario());
    run("policy-conflict-rc2", conflict_scenario());
    run("help-hides-hidden-subcommand", help_scenario());
    run("hidden-probe-on-host", probe_scenario());
    run("hidden-probe-malformed-rc3", probe_malformed_scenario());
    run(
        "hidden-probe-destructive-refused-outside-sandbox",
        probe_destructive_scenario(),
    );
    match full_report_scenario() {
        Ok(Some(msg)) => println!("SKIP conformance: {msg}"),
        Ok(None) => println!("PASS full-report"),
        Err(e) => {
            println!("FAIL full-report: {e}");
            failures.push("full-report".to_owned());
        }
    }
    if failures.is_empty() {
        println!("conformance: all scenarios passed");
        std::process::ExitCode::SUCCESS
    } else {
        println!("conformance: {} scenario(s) failed", failures.len());
        std::process::ExitCode::FAILURE
    }
}

/// Run `sbx` with `args`, bounded, returning stdout/stderr/rc.
fn sbx(args: &[&str]) -> Result<Output, String> {
    let mut child = Command::new(SBX)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot spawn sbx: {e}"))?;
    let deadline = Instant::now() + CATALOG_BOUND;
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                return Err(format!("sbx {args:?} exceeded {CATALOG_BOUND:?}"));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    child.wait_with_output().map_err(|e| e.to_string())
}

fn rc(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn list_scenario() -> Result<(), String> {
    let out = sbx(&["check", "--conformance", "--list"])?;
    if rc(&out) != 0 {
        return Err(format!("--list rc {}", rc(&out)));
    }
    let rows = text(&out)
        .lines()
        .filter(|l| l.starts_with("  ") && l.len() > 6)
        .count();
    if rows != 69 {
        return Err(format!("--list printed {rows} rows, expected 69"));
    }
    let json = sbx(&["check", "--conformance", "--list", "--json"])?;
    let v: serde_json::Value =
        serde_json::from_str(&text(&json)).map_err(|e| format!("--list --json: {e}"))?;
    if v["kind"] != "conformance-catalog" || v["checks"].as_array().map(Vec::len) != Some(69) {
        return Err("--list --json: wrong shape".to_owned());
    }
    Ok(())
}

fn only_scenario() -> Result<(), String> {
    let probe = sbx(&["check", "--json"])?;
    let mode = serde_json::from_str::<serde_json::Value>(&text(&probe))
        .ok()
        .and_then(|v| v["network_mode"].as_str().map(str::to_owned));
    if mode.as_deref() != Some("transparent") {
        println!("SKIP only-single-id: needs network mode transparent (host provides {mode:?})");
        return Ok(());
    }
    let out = sbx(&["check", "--conformance", "--only", "A01", "--json"])?;
    let v: serde_json::Value =
        serde_json::from_str(&text(&out)).map_err(|e| format!("--only A01 --json: {e}"))?;
    let checks = v["checks"].as_array().ok_or("no checks array")?;
    let a01 = checks
        .iter()
        .find(|c| c["id"] == "A01")
        .ok_or("A01 missing")?;
    if a01["status"] != "ok" {
        return Err(format!(
            "A01 status {} (detail {})",
            a01["status"], a01["detail"]
        ));
    }
    for c in checks.iter().filter(|c| c["id"] != "A01") {
        if c["skip_kind"] != "not-selected" {
            return Err(format!("{} was not marked not selected", c["id"]));
        }
    }
    if rc(&out) != 0 {
        return Err(format!("--only A01 rc {}", rc(&out)));
    }
    Ok(())
}

fn only_unknown_scenario() -> Result<(), String> {
    let out = sbx(&["check", "--conformance", "--only", "Z99"])?;
    if rc(&out) != 2 {
        return Err(format!("--only Z99 rc {}, expected 2", rc(&out)));
    }
    Ok(())
}

fn conflict_scenario() -> Result<(), String> {
    let out = sbx(&["check", "--conformance", "--policy", "x.json"])?;
    if rc(&out) != 2 {
        return Err(format!(
            "--conformance --policy rc {}, expected 2",
            rc(&out)
        ));
    }
    Ok(())
}

fn help_scenario() -> Result<(), String> {
    let top = sbx(&["--help"])?;
    if text(&top).contains("__conformance") {
        return Err("--help lists the hidden __conformance subcommand".to_owned());
    }
    let check = sbx(&["check", "--help"])?;
    if !text(&check).contains("--conformance") {
        return Err("check --help lacks --conformance".to_owned());
    }
    Ok(())
}

fn probe_scenario() -> Result<(), String> {
    let out = sbx(&[
        "__conformance",
        "probe",
        r#"{"v":1,"ops":[{"op":"hello","id":"h"}]}"#,
    ])?;
    if rc(&out) != 0 {
        return Err(format!(
            "probe rc {} ({})",
            rc(&out),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let lines: Vec<String> = text(&out).lines().map(str::to_owned).collect();
    if lines.len() != 3 {
        return Err(format!(
            "probe printed {} lines, expected banner, result, done",
            lines.len()
        ));
    }
    let banner: serde_json::Value = serde_json::from_str(&lines[0]).map_err(|e| e.to_string())?;
    if banner["probe"] != 1 {
        return Err("probe banner missing".to_owned());
    }
    Ok(())
}

/// The destructive ops (netlink changes, writes) are refused unless the probe runs
/// inside an sbx sandbox. On the host (identity uid_map) they must be refused with rc 4.
fn probe_destructive_scenario() -> Result<(), String> {
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    if uid_map.split_whitespace().collect::<Vec<_>>() != ["0", "0", "4294967295"] {
        println!("SKIP probe-destructive: not running on the initial user namespace");
        return Ok(());
    }
    let out = sbx(&[
        "__conformance",
        "probe",
        r#"{"v":1,"ops":[{"op":"netlink","id":"x","action":"lo_down"}]}"#,
    ])?;
    if rc(&out) != 4 {
        return Err(format!(
            "destructive probe op outside a sandbox: rc {}, expected 4",
            rc(&out)
        ));
    }
    if !text(&out).contains("refused") {
        return Err("refusal text missing".to_owned());
    }
    Ok(())
}

fn probe_malformed_scenario() -> Result<(), String> {
    let out = sbx(&["__conformance", "probe", "{not json"])?;
    if rc(&out) != 3 {
        return Err(format!("malformed OPS rc {}, expected 3", rc(&out)));
    }
    let _ = std::io::stdout().flush();
    Ok(())
}

/// The full catalog run (offline tiers; `--network` when requested). Returns
/// `Some(reason)` when the host cannot run sandboxes at all (a graceful skip).
fn full_report_scenario() -> Result<Option<String>, String> {
    let mut args = vec!["check", "--conformance", "--json"];
    let network = std::env::var("SBX_CONFORMANCE_NETWORK").is_ok_and(|v| v == "1");
    if network {
        args.push("--network");
    }
    let out = sbx(&args)?;
    let v: serde_json::Value =
        serde_json::from_str(&text(&out)).map_err(|e| format!("report JSON: {e}"))?;
    if v["kind"] != "conformance" || v["version"] != 1 {
        return Err("report kind/version".to_owned());
    }
    let checks = v["checks"].as_array().ok_or("no checks")?;
    let listed = sbx(&["check", "--conformance", "--list", "--json"])?;
    let catalog: serde_json::Value =
        serde_json::from_str(&text(&listed)).map_err(|e| e.to_string())?;
    let want: Vec<&str> = catalog["checks"]
        .as_array()
        .ok_or("no catalog")?
        .iter()
        .map(|c| c["id"].as_str().unwrap_or(""))
        .collect();
    let got: Vec<&str> = checks
        .iter()
        .map(|c| c["id"].as_str().unwrap_or(""))
        .collect();
    if got != want || got.len() != 69 {
        return Err(format!(
            "report ids differ from the catalog: {} entries",
            got.len()
        ));
    }
    let summary = &v["summary"];
    let mode = v["network_mode"].as_str().unwrap_or("");
    // Only the offline tiers can be capability-skipped by a host that cannot
    // run sandboxes; the E (network) checks stay opt-in and are excluded.
    let offline: Vec<&serde_json::Value> = checks
        .iter()
        .filter(|c| matches!(c["tier"].as_str(), Some("host" | "lab" | "init")))
        .collect();
    let all_capability = !offline.is_empty()
        && offline
            .iter()
            .all(|c| c["status"] == "skip" && c["skip_kind"] == "capability");
    if mode == "unavailable" && all_capability {
        return Ok(Some("host cannot run sandboxes".to_owned()));
    }
    if let Some(c) = checks.iter().find(|c| c["status"] == "fail") {
        return Err(format!("{} FAILed: {}", c["id"], c["detail"]));
    }
    for c in checks {
        let id = c["id"].as_str().unwrap_or("");
        let kind = c["skip_kind"].as_str();
        let is_e = E_IDS.contains(&id);
        let want_lab = PR1_NOT_IMPLEMENTED.contains(&id);
        if want_lab {
            if c["status"] != "skip" || kind != Some("not-implemented") {
                return Err(format!(
                    "{id}: expected a not-implemented skip, got {} {:?}",
                    c["status"], kind
                ));
            }
        } else if is_e {
            let ok = (c["status"] == "skip"
                && kind == Some(if network { "not-implemented" } else { "opt-in" }))
                || (network && c["status"] == "ok");
            if !ok {
                return Err(format!(
                    "{id}: unexpected tooling state {} {:?}",
                    c["status"], kind
                ));
            }
        } else if c["status"] != "ok" && c["status"] != "warn" {
            return Err(format!(
                "{id}: expected ok, got {} ({})",
                c["status"], c["detail"]
            ));
        }
    }
    let conformant = summary["conformant"] == true;
    if (rc(&out) == 0) != conformant {
        return Err(format!(
            "rc {} disagrees with summary.conformant {conformant}",
            rc(&out)
        ));
    }
    Ok(None)
}
