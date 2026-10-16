//! The network tier (issue #13, PR2, §11): E01–E06 run real tools through
//! `sbx run` against the real internet. Opt-in: `--network` or
//! `--network` (the CLI flag; `tests/conformance.rs` honours
//! `SBX_CONFORMANCE_NETWORK=1` by passing it). Each check is one `sbx run`.
//!
//! Gating, in order: no `--network` → opt-in skip; a needed tool missing →
//! opt-in skip; the host cannot resolve the check's first name → capability
//! skip; the host's network mode lacks what the check needs → capability skip.

use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::probe::now_ms;
use super::report::{CheckResult, SkipKind};
use super::scenarios::Env;
use super::spawn::{Finished, SbxRun};
use crate::host::{EffectiveMode, Status};

/// The network tier's total allowance, measured from its first check.
pub const NETWORK_BOUND: Duration = Duration::from_secs(300);

/// One network check's definition (§11 table).
struct Net {
    id: &'static str,
    title: &'static str,
    /// `transparent` or `explicit`.
    mode: &'static str,
    allow: &'static [&'static str],
    /// The tool that must exist (its first existing path is used).
    tool: &'static str,
    /// Extra environment for the payload (`env.set`).
    env_set: &'static [(&'static str, &'static str)],
}

const NET: [Net; 6] = [
    Net {
        id: "E01",
        title: "curl https://pypi.org/simple/six/ (transparent) returns 200",
        mode: "transparent",
        allow: &["pypi.org"],
        tool: "curl",
        env_set: &[],
    },
    Net {
        id: "E02",
        title: "curl through HTTPS_PROXY (explicit mode) returns 200",
        mode: "explicit",
        allow: &["pypi.org"],
        tool: "curl",
        env_set: &[],
    },
    Net {
        id: "E03",
        title: "git clone --depth 1 of github.com/octocat/Hello-World works",
        mode: "transparent",
        allow: &["github.com"],
        tool: "git",
        env_set: &[],
    },
    Net {
        id: "E04",
        title: "pip download six --no-deps works",
        mode: "transparent",
        allow: &["pypi.org", "files.pythonhosted.org"],
        tool: "python3",
        env_set: &[
            ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
            ("PIP_NO_INPUT", "1"),
        ],
    },
    Net {
        id: "E05",
        title: "npm view left-pad version works",
        mode: "transparent",
        allow: &["registry.npmjs.org"],
        tool: "npm",
        env_set: &[("npm_config_update_notifier", "false")],
    },
    Net {
        id: "E06",
        title: "real-network negatives: other host and wrong SNI are denied",
        mode: "transparent",
        allow: &["pypi.org"],
        tool: "curl",
        env_set: &[],
    },
];

/// The check table entry for `id`.
fn def(id: &str) -> Option<&'static Net> {
    NET.iter().find(|n| n.id == id)
}

/// The first existing `/usr/bin/<tool>` or `/usr/local/bin/<tool>`.
fn tool_path(tool: &str) -> Option<PathBuf> {
    ["/usr/bin", "/usr/local/bin"]
        .iter()
        .map(|d| Path::new(d).join(tool))
        .find(|p| p.is_file())
}

/// Run one check. `network` is the `--network` flag; `mode` the host's mode.
pub fn run(
    id: &str,
    env: &Env,
    mode: EffectiveMode,
    network: bool,
    deadline: Instant,
) -> CheckResult {
    let Some(d) = def(id) else {
        return CheckResult::new(id, Status::Fail, "no network-tier definition");
    };
    if !network {
        return CheckResult::skip(
            id,
            SkipKind::OptIn,
            "network tier not requested (add --network)",
        );
    }
    if Instant::now() > deadline {
        return CheckResult::skip(
            id,
            SkipKind::Capability,
            "network tier budget (300 s) exhausted",
        );
    }
    let Some(tool) = tool_path(d.tool) else {
        return CheckResult::skip(
            id,
            SkipKind::OptIn,
            format!("tool {} not found under /usr/bin or /usr/local/bin", d.tool),
        );
    };
    if id == "E04" && !pip_works() {
        return CheckResult::skip(
            id,
            SkipKind::OptIn,
            "tool python3 -m pip not found (python3 -m pip --version failed)",
        );
    }
    let transparent = d.mode == "transparent";
    if transparent && mode == EffectiveMode::Explicit {
        return CheckResult::skip(
            id,
            SkipKind::Capability,
            "needs network mode transparent; this host provides explicit (run `sbx check`)",
        );
    }
    if mode == EffectiveMode::Unavailable {
        return CheckResult::skip(
            id,
            SkipKind::Capability,
            "the host cannot run sandboxes (run `sbx check`)",
        );
    }
    let host = d.allow[0];
    if !resolves(host) {
        return CheckResult::skip(
            id,
            SkipKind::Capability,
            format!("no network: cannot resolve {host} on this host"),
        );
    }
    let started = Instant::now();
    let outcome = match id {
        "E06" => e06(env, &tool),
        _ => one(env, d, &command_for(id, &tool)),
    };
    let ms = started.elapsed().as_millis() as u64;
    let mut r = match outcome {
        Ok(r) => r,
        Err(why) => CheckResult::new(id, Status::Fail, why),
    };
    r.scenario = Some(id.to_owned());
    r.scenario_ms = Some(ms);
    r
}

/// `python3 -m pip --version` exits 0 on the host (bound 10 s).
fn pip_works() -> bool {
    let Some(py) = tool_path("python3") else {
        return false;
    };
    // Output is discarded: the probe's stdout is the report (JSON mode).
    let spawned = Command::new(py)
        .args(["-m", "pip", "--version"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// The host resolves `name` (bound 5 s, on a helper thread).
fn resolves(name: &str) -> bool {
    let (tx, rx) = mpsc::channel();
    let target = format!("{name}:443");
    std::thread::spawn(move || {
        let ok = target
            .to_socket_addrs()
            .is_ok_and(|mut it| it.next().is_some());
        let _ = tx.send(ok);
    });
    rx.recv_timeout(Duration::from_secs(5)).unwrap_or(false)
}

/// The argv of E01–E05 (absolute tool paths; no PATH reliance).
fn command_for(id: &str, tool: &Path) -> Vec<String> {
    let t = tool.to_string_lossy().into_owned();
    let v: Vec<&str> = match id {
        "E01" => vec![
            &t,
            "-fsS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://pypi.org/simple/six/",
        ],
        "E02" => vec![
            &t,
            "-fsS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "https://pypi.org/simple/six/",
        ],
        "E03" => vec![
            &t,
            "clone",
            "--depth",
            "1",
            "https://github.com/octocat/Hello-World",
            "/work/hw",
        ],
        "E04" => vec![
            &t,
            "-m",
            "pip",
            "download",
            "six",
            "--no-deps",
            "--dest",
            "/work/dl",
        ],
        "E05" => vec![&t, "view", "left-pad", "version"],
        _ => vec![&t],
    };
    v.into_iter().map(str::to_owned).collect()
}

/// The policy text for one run.
fn policy(mode: &str, allow: &[&str], env_set: &[(&str, &str)]) -> String {
    let mut set = serde_json::Map::new();
    set.insert("SBX_CONFORMANCE_SET".to_owned(), json!("1"));
    for (k, v) in env_set {
        set.insert((*k).to_owned(), json!(v));
    }
    let doc: Value = json!({
        "version": 1,
        "filesystem": {"ro": ["/usr"], "rw": [], "deny": []},
        "network": {"mode": mode, "allow": allow, "ports": [443, 80]},
        "env": {"pass": [], "set": set},
        "limits": {"timeout": "60s", "output_bytes": 1048576}
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// One `sbx run` of `argv` under the check's policy.
fn exec(
    env: &Env,
    d: &Net,
    tag: &str,
    argv: Vec<String>,
    allow: &[&str],
) -> Result<(Finished, Vec<Value>, PathBuf), String> {
    // The policy's own timeout (60 s) fires first, so a hung run reports rc 124;
    // the wait bound (90 s) only backstops a run that ignores its timeout.
    let text = policy(d.mode, allow, d.env_set);
    let policy_path = env.base.join(format!("p-{tag}.json"));
    std::fs::write(&policy_path, text).map_err(|e| format!("cannot write the policy: {e}"))?;
    let session = env.base.join(format!("s-{tag}"));
    let audit = env.base.join(format!("a-{tag}.jsonl"));
    let mut running = SbxRun::new(&env.exe, &policy_path, &session, argv)
        .audit(&audit)
        .timeout("60s")
        .spawn()
        .map_err(|e| format!("cannot spawn sbx run: {e}"))?;
    let fin = running.wait_bounded(Instant::now() + Duration::from_secs(90));
    Ok((fin, super::scenarios::read_audit(&audit), session))
}

/// The common path: one run, rc 0, and the check's own evidence.
fn one(env: &Env, d: &Net, argv: &[String]) -> Result<CheckResult, String> {
    let tag = format!("net-{}-{}", d.id, now_ms());
    let (fin, audit, session) = exec(env, d, &tag, argv.to_vec(), d.allow)?;
    let evidence = vec![
        format!("rc {:?} stdout {:?}", fin.rc, fin.stdout.last()),
        format!("stderr: {}", fin.stderr.lines().last().unwrap_or("")),
    ];
    let mut r = match d.id {
        "E01" | "E02" => {
            let via = if d.id == "E01" {
                "transparent"
            } else {
                "explicit-connect"
            };
            if fin.rc != Some(0) {
                return Err(format!("{}: sbx run rc {:?}", d.id, fin.rc));
            }
            if fin.stdout.last().map(String::as_str) != Some("200") {
                return Err(format!(
                    "{}: expected HTTP 200, got {:?}",
                    d.id,
                    fin.stdout.last()
                ));
            }
            if !connect_row(&audit, "pypi.org", via) {
                return Err(format!(
                    "{}: no audit connect row for pypi.org via {via}",
                    d.id
                ));
            }
            CheckResult::new(d.id, Status::Ok, d.title)
        }
        "E03" => {
            if fin.rc != Some(0) {
                return Err(format!("E03: git clone rc {:?}", fin.rc));
            }
            let readme = session.join("work").join("hw").join("README");
            if !readme.is_file() {
                return Err(format!("E03: {} is missing on the host", readme.display()));
            }
            CheckResult::new(d.id, Status::Ok, d.title)
        }
        "E04" => {
            if fin.rc != Some(0) {
                return Err(format!("E04: pip download rc {:?}", fin.rc));
            }
            let dir = session.join("work").join("dl");
            let found = std::fs::read_dir(&dir)
                .map(|it| {
                    it.filter_map(Result::ok).any(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.starts_with("six-") && n.ends_with(".whl")
                    })
                })
                .unwrap_or(false);
            if !found {
                return Err(format!("E04: no six-*.whl under {}", dir.display()));
            }
            CheckResult::new(d.id, Status::Ok, d.title)
        }
        "E05" => {
            if fin.rc != Some(0) {
                return Err(format!("E05: npm view rc {:?}", fin.rc));
            }
            let out = fin.stdout.join("\n");
            if !is_semver_line(&out) {
                return Err(format!("E05: stdout is not a version: {out:?}"));
            }
            CheckResult::new(d.id, Status::Ok, d.title)
        }
        _ => return Err(format!("{}: no evaluator", d.id)),
    };
    r.evidence = evidence;
    Ok(r)
}

/// `^\d+\.\d+\.\d+\n?$` without a regex dependency.
fn is_semver_line(text: &str) -> bool {
    let t = text.strip_suffix('\n').unwrap_or(text);
    let parts: Vec<&str> = t.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn connect_row(audit: &[Value], host: &str, via: &str) -> bool {
    audit.iter().any(|r| {
        r["event"] == "connect"
            && r["host"].as_str() == Some(host)
            && r["via"].as_str() == Some(via)
    })
}

/// E06: `curl https://example.com/` is denied at DNS; `openssl s_client` to
/// pypi.org with a foreign `-servername` is denied on the SNI. The curl half
/// alone decides; a missing openssl is a note.
fn e06(env: &Env, curl: &Path) -> Result<CheckResult, String> {
    let d = def("E06").ok_or("E06 missing")?;
    let stamp = now_ms();
    // Positive control: the same policy and tool reach the allowed host, so a
    // broken probe or policy cannot make the negatives pass vacuously.
    let ok_argv = vec![
        curl.to_string_lossy().into_owned(),
        "-fsS".to_owned(),
        "-o".to_owned(),
        "/dev/null".to_owned(),
        "-w".to_owned(),
        "%{http_code}".to_owned(),
        "https://pypi.org/simple/six/".to_owned(),
    ];
    let (ok_fin, _, _) = exec(env, d, &format!("net-E06c-{stamp}"), ok_argv, d.allow)?;
    if ok_fin.rc != Some(0) || ok_fin.stdout.last().map(String::as_str) != Some("200") {
        return Err(format!(
            "E06: positive control failed (curl pypi.org rc {:?}, stdout {:?})",
            ok_fin.rc,
            ok_fin.stdout.last()
        ));
    }
    let argv = vec![
        curl.to_string_lossy().into_owned(),
        "-fsS".to_owned(),
        "https://example.com/".to_owned(),
    ];
    let (fin, audit, _) = exec(env, d, &format!("net-E06a-{stamp}"), argv, d.allow)?;
    if fin.rc == Some(0) {
        return Err("E06: curl to example.com succeeded (it must be denied)".to_owned());
    }
    let dns_denied = audit.iter().any(|r| {
        r["event"] == "dns" && r["verdict"] == "denied" && r["host"].as_str() == Some("example.com")
    });
    if !dns_denied {
        return Err("E06: no audit dns denied row for example.com".to_owned());
    }
    let mut evidence = vec![
        "control: curl pypi.org 200 under the same policy".to_owned(),
        format!("curl example.com rc {:?} (denied)", fin.rc),
    ];
    match tool_path("openssl") {
        None => evidence.push("note: openssl not found; the SNI half was not run".to_owned()),
        Some(ossl) => {
            let argv = vec![
                ossl.to_string_lossy().into_owned(),
                "s_client".to_owned(),
                "-connect".to_owned(),
                "pypi.org:443".to_owned(),
                "-servername".to_owned(),
                "example.com".to_owned(),
            ];
            let (_fin2, audit2, _) = exec(env, d, &format!("net-E06b-{stamp}"), argv, d.allow)?;
            let want = "SNI example.com does not match the DNS-map name pypi.org";
            let sni_denied = audit2.iter().any(|r| {
                r["event"] == "deny" && r["reason"].as_str().is_some_and(|t| t.contains(want))
            });
            if !sni_denied {
                return Err(format!("E06: no audit deny row: {want}"));
            }
            evidence.push("openssl -servername example.com to pypi.org: SNI denied".to_owned());
        }
    }
    let mut r = CheckResult::new("E06", Status::Ok, d.title);
    r.evidence = evidence;
    Ok(r)
}
