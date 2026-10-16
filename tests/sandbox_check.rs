//! Integration suite for `sbx check` (issue #11) — the real binary, the real
//! probe, the real nested bwrap tiers.
//!
//! Why `harness = false`: the nested tiers run `sbx check` inside `bwrap
//! --unshare-user …`, and the probe itself unshares; the parent side stays
//! sequential with bounded waits, the same reasoning as `sandbox_init` and
//! `sandbox_run`. There are no child roles: every scenario runs the real
//! binary and checks its report.
//!
//! Gates (SKIP-with-message, exit 0; any FAIL exits 1):
//! * `Always` — no environment requirement (the report is produced on every
//!   host; the rc is whatever the host says, so the scenarios assert shape).
//! * `Userns` — the probe's own userns item reads `ok` on this host.
//! * `Bwrap` — a usable bwrap is discoverable (`SBX_BWRAP`, `PATH`, fixed
//!   fallbacks), so the nested tiers can run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sbx::bwrap::version::find_bwrap;
use sbx::host::CapId;

const SBX: &str = env!("CARGO_BIN_EXE_sbx");

fn main() -> std::process::ExitCode {
    let bwrap = find_bwrap();
    let userns_ok = host_userns_ok();
    let mut failed = 0u32;
    let mut passed = 0u32;
    let mut skipped = 0u32;
    for sc in scenarios() {
        let satisfied = match sc.gate {
            Gate::Always => true,
            Gate::Userns => userns_ok,
            Gate::Bwrap => bwrap.is_some() && userns_ok,
        };
        if !satisfied {
            let why = match sc.gate {
                Gate::Bwrap if !userns_ok => USERNS_SKIP,
                Gate::Bwrap => BWRAP_SKIP,
                _ => USERNS_SKIP,
            };
            println!("SKIP {}: {why}", sc.name);
            skipped += 1;
            continue;
        }
        match (sc.run)() {
            Ok(()) => {
                println!("PASS {}", sc.name);
                passed += 1;
            }
            Err(err) => {
                println!("FAIL {}: {err}", sc.name);
                failed += 1;
            }
        }
    }
    println!("sandbox_check: {passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

#[derive(Clone, Copy)]
enum Gate {
    Always,
    Userns,
    Bwrap,
}

const USERNS_SKIP: &str = "unprivileged userns unavailable (AppArmor? CI: sysctl kernel.apparmor_restrict_unprivileged_userns=0)";
const BWRAP_SKIP: &str = "bwrap not installed (CI: apt-get install bubblewrap)";

struct Scenario {
    name: &'static str,
    gate: Gate,
    run: fn() -> Result<(), String>,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "print-schema-unchanged",
            gate: Gate::Always,
            run: print_schema_unchanged,
        },
        Scenario {
            name: "validate-only-probe-free",
            gate: Gate::Always,
            run: validate_only_probe_free,
        },
        Scenario {
            name: "usage-contract",
            gate: Gate::Always,
            run: usage_contract,
        },
        Scenario {
            name: "json-shape",
            gate: Gate::Always,
            run: json_shape,
        },
        Scenario {
            name: "seccomp-item-ok",
            gate: Gate::Bwrap,
            run: seccomp_item_ok,
        },
        Scenario {
            name: "bwrap-missing",
            gate: Gate::Userns,
            run: bwrap_missing,
        },
        Scenario {
            name: "invalid-policy-host",
            gate: Gate::Always,
            run: invalid_policy_host,
        },
        Scenario {
            name: "break-rules-explicit",
            gate: Gate::Userns,
            run: break_rules_explicit,
        },
        Scenario {
            name: "policy-host-mode",
            gate: Gate::Userns,
            run: policy_host_mode,
        },
        Scenario {
            name: "human-shape",
            gate: Gate::Bwrap,
            run: human_shape,
        },
        Scenario {
            name: "nested-no-userns",
            gate: Gate::Bwrap,
            run: nested_no_userns,
        },
        Scenario {
            name: "ro-proc-sys",
            gate: Gate::Bwrap,
            run: ro_proc_sys,
        },
        Scenario {
            name: "policy-host-deny-file",
            gate: Gate::Bwrap,
            run: policy_host_deny_file,
        },
    ]
}

// ---- helpers ---------------------------------------------------------------

/// The probe's own verdict on unprivileged namespaces (the same stages `run`
/// depends on). Any failure to read it reads as "unavailable".
fn host_userns_ok() -> bool {
    match sbx_json(&["check", "--json"]) {
        Ok((_, report)) => report
            .get("capabilities")
            .and_then(|c| c.as_array())
            .and_then(|items| items.iter().find(|c| c["id"] == "userns"))
            .is_some_and(|c| c["status"] == "ok"),
        Err(_) => false,
    }
}

/// Runs `sbx` with `args` and returns `(rc, parsed stdout JSON)`.
fn sbx_json(args: &[&str]) -> Result<(i32, serde_json::Value), String> {
    let out = run(Command::new(SBX).args(args))?;
    let report = serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "stdout is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    })?;
    Ok((rc(&out), report))
}

fn run(cmd: &mut Command) -> Result<Output, String> {
    cmd.output().map_err(|e| format!("spawn: {e}"))
}

fn rc(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn text(out: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sbx-check-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The `SBX_BWRAP` the nested tiers and the override tests use.
fn bwrap_path() -> Result<PathBuf, String> {
    find_bwrap().ok_or_else(|| "bwrap not found".to_owned())
}

/// A transparent-mode policy with `/usr` read-only (every infra path exists on
/// a normal host).
fn policy_text(mode: &str, deny: &[&str]) -> String {
    let deny = deny
        .iter()
        .map(|d| format!("{d:?}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"version":1,"filesystem":{{"ro":["/usr"],"rw":[],"deny":[{deny}]}},"network":{{"mode":"{mode}","allow":[],"ports":[]}},"env":{{"pass":[],"set":{{}}}},"limits":{{"timeout":"5s","output_bytes":1000}}}}"#
    )
}

fn item<'a>(report: &'a serde_json::Value, id: &str) -> Result<&'a serde_json::Value, String> {
    report["capabilities"]
        .as_array()
        .and_then(|items| items.iter().find(|c| c["id"] == id))
        .ok_or_else(|| format!("no capability {id} in {report}"))
}

// ---- Always ----------------------------------------------------------------

/// `--print-schema` is unchanged: rc 0, the schema plus one newline, nothing on
/// stderr.
fn print_schema_unchanged() -> Result<(), String> {
    let out = run(Command::new(SBX).args(["check", "--print-schema"]))?;
    let (stdout, stderr) = text(&out);
    if rc(&out) != 0 || !stderr.is_empty() {
        return Err(format!("rc {} stderr {stderr:?}", rc(&out)));
    }
    let want = format!("{}\n", sbx::policy::schema_json());
    if stdout != want {
        return Err("schema output changed".into());
    }
    Ok(())
}

/// The validate-only form stays probe-free: with a bwrap override pointing
/// nowhere and an empty PATH, `check --policy` still exits 0 silently.
fn validate_only_probe_free() -> Result<(), String> {
    let policy = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/default.json");
    let out = run(Command::new(SBX)
        .args(["check", "--policy"])
        .arg(&policy)
        .env_clear()
        .env("SBX_BWRAP", "/nonexistent")
        .env("PATH", ""))?;
    let (stdout, stderr) = text(&out);
    if rc(&out) != 0 || !stdout.is_empty() || !stderr.is_empty() {
        return Err(format!(
            "rc {} stdout {stdout:?} stderr {stderr:?}",
            rc(&out)
        ));
    }
    Ok(())
}

/// Usage errors are rc 2: `--host` alone, `--json` with a validate-only
/// policy, and the `--print-schema` conflicts.
fn usage_contract() -> Result<(), String> {
    let cases: [&[&str]; 4] = [
        &["check", "--host"],
        &["check", "--policy", "p.json", "--json"],
        &["check", "--print-schema", "--json"],
        &["check", "--print-schema", "--host"],
    ];
    for args in cases {
        let out = run(Command::new(SBX).args(args))?;
        if rc(&out) != 2 {
            return Err(format!("{args:?}: rc {} (expected 2)", rc(&out)));
        }
    }
    Ok(())
}

/// The JSON report's shape holds on every host: version 1, the ids in
/// report order, rc 1 exactly when the network mode is unavailable, and every
/// failing item carries a fix.
fn json_shape() -> Result<(), String> {
    let (code, report) = sbx_json(&["check", "--json"])?;
    if report["version"] != 1 {
        return Err(format!("version {}", report["version"]));
    }
    let ids: Vec<String> = report["capabilities"]
        .as_array()
        .ok_or("no capabilities")?
        .iter()
        .map(|c| c["id"].as_str().unwrap_or("").to_owned())
        .collect();
    let want: Vec<&str> = CapId::ALL.iter().map(|id| id.as_str()).collect();
    if ids != want {
        return Err(format!("ids {ids:?}"));
    }
    let mode = report["network_mode"].as_str().unwrap_or("");
    if (code == 0) != (mode != "unavailable") || (code != 0 && code != 1) {
        return Err(format!("rc {code} with network_mode {mode:?}"));
    }
    for cap in report["capabilities"].as_array().into_iter().flatten() {
        if (cap["status"] == "fail" || cap["status"] == "warn") && cap["fix"].is_null() {
            return Err(format!("no fix on {cap}"));
        }
    }
    Ok(())
}

/// Issue #34: where bwrap runs, the `seccomp` item is ok — the nested launch
/// with sbx's socket-family filter (`bwrap-seccomp`) starts, so `run` can.
fn seccomp_item_ok() -> Result<(), String> {
    // No program for this architecture: the item is a documented FAIL there.
    if sbx::bwrap::seccomp::Arch::native().is_none() {
        return Ok(());
    }
    let bwrap = bwrap_path()?;
    let out = run(Command::new(SBX)
        .args(["check", "--json"])
        .env("SBX_BWRAP", &bwrap))?;
    let (stdout, stderr) = text(&out);
    let report: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("json: {e} (stdout {stdout:?}, stderr {stderr:?})"))?;
    let seccomp = item(&report, "seccomp")?;
    if seccomp["status"] != "ok" {
        return Err(format!("seccomp item: {seccomp}"));
    }
    Ok(())
}

/// A missing bwrap is a failure item with the spawn detail, the two bwrap
/// steps are reported as not probed, and the host is unavailable (rc 1).
fn bwrap_missing() -> Result<(), String> {
    let out = run(Command::new(SBX)
        .args(["check", "--json"])
        .env("SBX_BWRAP", "/nonexistent/bwrap"))?;
    let (stdout, stderr) = text(&out);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("json: {e}"))?;
    if rc(&out) != 1 {
        return Err(format!("rc {} (expected 1)", rc(&out)));
    }
    let bwrap = item(&report, "bwrap")?;
    if bwrap["status"] != "fail"
        || !bwrap["detail"]
            .as_str()
            .unwrap_or("")
            .starts_with("cannot run /nonexistent/bwrap --version:")
    {
        return Err(format!("bwrap item: {bwrap}"));
    }
    for id in ["bwrap-run", "bwrap-proc", "seccomp"] {
        if item(&report, id)?["detail"] != "not probed: bwrap is unavailable" {
            return Err(format!("{id}: {}", item(&report, id)?));
        }
    }
    if !stderr.starts_with("sbx check: this host cannot run sandboxes (") {
        return Err(format!("stderr: {stderr:?}"));
    }
    Ok(())
}

/// An unreadable policy with `--host` still prints the host report (stdout),
/// names the problem on stderr, and exits 1.
fn invalid_policy_host() -> Result<(), String> {
    let out =
        run(Command::new(SBX).args(["check", "--policy", "/nonexistent/policy.json", "--host"]))?;
    let (stdout, stderr) = text(&out);
    if rc(&out) != 1 {
        return Err(format!("rc {} (expected 1)", rc(&out)));
    }
    if !stdout.contains("network mode:") {
        return Err(format!("no host report on stdout: {stdout:?}"));
    }
    if !stderr.starts_with("sbx check: ") {
        return Err(format!("stderr: {stderr:?}"));
    }
    Ok(())
}

// ---- Userns ----------------------------------------------------------------

/// With the nft batch refused (`--test-break-rules`), the nft item carries the
/// explicit impact, the fallback works, and the host is explicit (rc 0).
fn break_rules_explicit() -> Result<(), String> {
    let (code, report) = sbx_json(&["check", "--json", "--test-break-rules"])?;
    if code != 0 {
        return Err(format!("rc {code} (expected 0)"));
    }
    if report["network_mode"] != "explicit" {
        return Err(format!("network_mode {}", report["network_mode"]));
    }
    let nft = item(&report, "nft")?;
    if nft["status"] != "fail" || nft["impact"] != "explicit" {
        return Err(format!("nft item: {nft}"));
    }
    if item(&report, "fallback")?["status"] != "ok" {
        return Err(format!("fallback: {}", item(&report, "fallback")?));
    }
    Ok(())
}

/// The policy comparison: a transparent policy cannot run on an explicit-only
/// host (rc 1 with the pinned line); an explicit policy can (rc 0).
fn policy_host_mode() -> Result<(), String> {
    let dir = scratch("hostmode");
    let transparent = dir.join("transparent.json");
    let explicit = dir.join("explicit.json");
    fs::write(&transparent, policy_text("transparent", &[])).map_err(|e| e.to_string())?;
    fs::write(&explicit, policy_text("explicit", &[])).map_err(|e| e.to_string())?;
    let out = run(Command::new(SBX)
        .args(["check", "--policy"])
        .arg(&transparent)
        .args(["--host", "--test-break-rules"]))?;
    let (_, stderr) = text(&out);
    if rc(&out) != 1 {
        return Err(format!("transparent: rc {} (expected 1)", rc(&out)));
    }
    if !stderr.contains(
        "sbx check: policy requires network mode transparent but this host provides only explicit",
    ) {
        return Err(format!("transparent: stderr {stderr:?}"));
    }
    let out = run(Command::new(SBX)
        .args(["check", "--policy"])
        .arg(&explicit)
        .args(["--host", "--test-break-rules"]))?;
    if rc(&out) != 0 {
        return Err(format!(
            "explicit: rc {} (expected 0)\n{}",
            rc(&out),
            text(&out).1
        ));
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---- Bwrap -----------------------------------------------------------------

/// The human layout: the header, one row per item (ten since #34), and the
/// network mode line.
fn human_shape() -> Result<(), String> {
    let out = run(Command::new(SBX).arg("check"))?;
    let (stdout, _) = text(&out);
    let lines: Vec<&str> = stdout.lines().collect();
    if !lines
        .first()
        .is_some_and(|l| l.starts_with("sbx ") && l.contains(" host check (kernel "))
    {
        return Err(format!("header: {stdout:?}"));
    }
    let rows = lines
        .iter()
        .filter(|l| {
            CapId::ALL
                .iter()
                .any(|id| l.contains(&format!("  {}", id.as_str())))
        })
        .count();
    if rows < CapId::ALL.len() {
        return Err(format!(
            "expected {} rows, saw {rows}: {stdout:?}",
            CapId::ALL.len()
        ));
    }
    if !stdout.contains("\nnetwork mode: ") {
        return Err(format!("no mode line: {stdout:?}"));
    }
    Ok(())
}

/// Nested in `bwrap --unshare-user --disable-userns` (E3): the probe's
/// unshare fails with ENOSPC, the userns item is explained, the rest is not
/// probed, and the host is unavailable (rc 1).
fn nested_no_userns() -> Result<(), String> {
    let bwrap = bwrap_path()?;
    let out = run(Command::new(&bwrap)
        .args([
            "--unshare-user",
            "--disable-userns",
            "--dev-bind",
            "/",
            "/",
            "--",
        ])
        .arg(SBX)
        .args(["check", "--json"])
        .env("SBX_BWRAP", &bwrap))?;
    let (stdout, _) = text(&out);
    if rc(&out) != 1 {
        return Err(format!("rc {} (expected 1): {stdout}", rc(&out)));
    }
    let report: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("json: {e}"))?;
    let userns = item(&report, "userns")?;
    if userns["status"] != "fail" || userns["errno"] != 28 {
        return Err(format!("userns: {userns}"));
    }
    if !userns["detail"]
        .as_str()
        .unwrap_or("")
        .starts_with("no user namespace can be created here")
    {
        return Err(format!("userns detail: {userns}"));
    }
    let skipped = report["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] == "skip")
        .count();
    // Seven since #34: the `seccomp` item is skipped too (its probe step
    // needs bwrap-run, which cannot start without user namespaces).
    if skipped != 7 {
        return Err(format!("expected 7 skipped items, saw {skipped}"));
    }
    if report["network_mode"] != "unavailable" {
        return Err(format!("network_mode {}", report["network_mode"]));
    }
    Ok(())
}

/// Nested with a read-only `/proc/sys` (E4/E5, Docker-style): the IPv6 stage
/// reports EROFS, the nested bwrap control launch reports the read-only
/// filesystem, and the host is unavailable (rc 1).
fn ro_proc_sys() -> Result<(), String> {
    let bwrap = bwrap_path()?;
    let out = run(Command::new(&bwrap)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--dev-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--ro-bind",
            "/proc/sys",
            "/proc/sys",
            "--",
        ])
        .arg(SBX)
        .args(["check", "--json"])
        .env("SBX_BWRAP", &bwrap))?;
    let (stdout, _) = text(&out);
    if rc(&out) != 1 {
        return Err(format!("rc {} (expected 1): {stdout}", rc(&out)));
    }
    let report: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("json: {e}"))?;
    let v6 = item(&report, "netns-ipv6")?;
    if v6["status"] != "fail"
        || v6["errno"] != 30
        || !v6["detail"].as_str().unwrap_or("").contains("EROFS")
    {
        return Err(format!("netns-ipv6: {v6}"));
    }
    let run_item = item(&report, "bwrap-run")?;
    if run_item["status"] != "fail"
        || !run_item["detail"]
            .as_str()
            .unwrap_or("")
            .contains("read-only")
    {
        return Err(format!("bwrap-run: {run_item}"));
    }
    if report["network_mode"] != "unavailable" {
        return Err(format!("network_mode {}", report["network_mode"]));
    }
    Ok(())
}

/// `--policy P --host` with a file in a deny list (E11): the deny-paths item
/// fails and the policy cannot run (rc 1).
fn policy_host_deny_file() -> Result<(), String> {
    let dir = scratch("denyfile");
    let policy = dir.join("deny.json");
    fs::write(&policy, policy_text("transparent", &["/etc/passwd"])).map_err(|e| e.to_string())?;
    let bwrap = bwrap_path()?;
    let out = run(Command::new(SBX)
        .args(["check", "--policy"])
        .arg(&policy)
        .args(["--host", "--json"])
        .env("SBX_BWRAP", &bwrap))?;
    let (stdout, _) = text(&out);
    let _ = fs::remove_dir_all(&dir);
    if rc(&out) != 1 {
        return Err(format!("rc {} (expected 1): {stdout}", rc(&out)));
    }
    let report: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|e| format!("json: {e}"))?;
    let deny = report["policy"]["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["id"] == "deny-paths"))
        .ok_or("no deny-paths item")?;
    if deny["status"] != "fail"
        || !deny["detail"]
            .as_str()
            .unwrap_or("")
            .contains("/etc/passwd")
    {
        return Err(format!("deny-paths: {deny}"));
    }
    if report["policy"]["runnable"] != false {
        return Err("policy must not be runnable".into());
    }
    Ok(())
}
