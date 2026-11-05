//! Drives the group-I scenarios (issue #18) and their evaluators end to end, with
//! `SBX_BWRAP` pointed at the shell shim that `exec`s in place (no bwrap).
//!
//! This is a control, not a pass of the group: the shim gives no pid namespace,
//! so I01 (a call cannot see or signal the resident or another call) must FAIL
//! here, and the rest (holder SIGKILL, policy refusal, idle and max-lifetime
//! ends) must hold, because they do not depend on bwrap's isolation. The
//! conformance gate never runs group I on a host without bwrap; this test only
//! proves that the scenarios and evaluators can tell a broken isolation from a
//! working one.
//!
//! Harness: this binary is separate from every other test, so it may set
//! `SBX_BWRAP` for its own process. The single test SKIPs when unprivileged user
//! namespaces are unavailable.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sbx::conformance::scenarios::{Env, Scn};
use sbx::conformance::session_tier;
use sbx::host::Status;

fn write_shim(dir: &std::path::Path) -> PathBuf {
    let shim = dir.join("bwrap-shim");
    std::fs::write(
        &shim,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then echo \"bubblewrap 0.9.0\"; exit 0; fi\n\
         while [ $# -gt 0 ]; do\n\
           if [ \"$1\" = \"--\" ]; then shift; exec \"$@\"; fi\n\
           shift\n\
         done\n\
         exit 2\n",
    )
    .expect("write shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    shim
}

fn namespaces_available() -> bool {
    std::process::Command::new("unshare")
        .args(["-Urn", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn group_i_evaluators_separate_broken_isolation_from_working_lifecycle() {
    if !namespaces_available() {
        eprintln!("SKIP: unprivileged user namespaces are unavailable on this host");
        return;
    }
    let base = std::env::temp_dir().join(format!("sbx-session-conf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("base");
    let shim = write_shim(&base);
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_sbx"));
    // SAFETY: this test binary runs only this one test, so nothing else reads the
    // environment concurrently.
    unsafe {
        std::env::set_var("SBX_BWRAP", &shim);
    }
    let env = Env {
        exe: exe.clone(),
        exe_text: exe.to_string_lossy().into_owned(),
        base: base.clone(),
        secret: "unused".into(),
        passed: "unused".into(),
        nonce: "session".into(),
    };

    let scns: BTreeMap<&'static str, Scn> = session_tier::run(&env)
        .into_iter()
        .map(|s| (s.name, s))
        .collect();
    for name in session_tier::SCENARIOS {
        let scn = scns
            .get(name)
            .unwrap_or_else(|| panic!("scenario {name} missing"));
        assert!(
            scn.skip.is_none(),
            "scenario {name} did not run: {:?}",
            scn.skip
        );
    }

    let verdict = |id: &str| session_tier::evaluate(id, &scns);

    // Without bwrap's pid namespace, the call sees the host's processes: I01 fails.
    let i01 = verdict("I01");
    assert_eq!(
        i01.status,
        Status::Fail,
        "I01 must not pass without pid isolation: {}",
        i01.detail
    );
    assert!(i01.detail.contains("not its own"), "{}", i01.detail);

    // The lifecycle checks do not depend on bwrap's isolation: they hold here.
    for id in ["I02", "I03", "I05", "I06"] {
        let r = verdict(id);
        assert_eq!(r.status, Status::Ok, "{id}: {} {:?}", r.detail, r.evidence);
    }

    let _ = std::fs::remove_dir_all(&base);
}
